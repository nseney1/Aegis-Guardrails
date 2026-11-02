#!/usr/bin/env python3
"""ROOT handoff tooling: launch checks, lane health and the shared write helpers.

Every launch and rotation on 2026-11-02 was typed as an ad hoc heredoc, and each one hit
a defect that one tested command would have caught: launcher code read from inherited
stdin into first prompts, lanes stuck on a dialog nobody could see, torn transcript
lines aborting writes, a full disk swallowing writes (C2 design note F1-F9;
investigation F-A, F-B; ROOT C5 F1, F2, F5).

Every subcommand prints one JSON object. Exit codes:
  0  ok
  2  a critical check failed; nothing was written
  3  the target exists and differs, or the session name is already live
  4  IO or disk error, including free space below --min-free-mb (checked before any write)
  5  a human-answerable dialog is pending (the record is still written)

These tools never stop, attach to or answer a session: a host may refuse a stop, so a
stop stays a visible, explicit command (T27, T13). Where one is needed the tool prints
it and can verify the outcome afterwards. No deletes, no network.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True

EXIT_OK, EXIT_CRITICAL, EXIT_CONFLICT, EXIT_IO, EXIT_DIALOG = 0, 2, 3, 4, 5
HEAD_CHARS = 120


class Failure(Exception):
    """A refusal with its exit code; detail fields are merged into the printed JSON."""

    def __init__(self, code, message, **detail):
        super().__init__(message)
        self.code = code
        self.detail = detail


def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def read_jsonl(path, tolerate_torn_tail=True):
    """Return ([(line_number, record)], torn_tail).

    A live transcript's last line can be half written while the session runs, so an
    unparsable last line is skipped and reported (F1). An unparsable earlier line is
    corruption and fails.
    """
    with open(path, "rb") as stream:
        lines = stream.read().split(b"\n")
    last = max((index for index, line in enumerate(lines) if line.strip()), default=-1)
    rows, torn = [], False
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            if index == last and tolerate_torn_tail:
                torn = True
                continue
            raise Failure(EXIT_CRITICAL, "unparsable JSON at line %d of %s" % (index + 1, path)) from None
        rows.append((index + 1, record))
    return rows, torn


def record_text(record):
    """The text a user record carries: a string, or the concatenated text blocks."""
    message = record.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(block.get("text", "") for block in content
                       if isinstance(block, dict) and block.get("type") == "text")
    return None


def first_user_record(rows):
    for line, record in rows:
        if isinstance(record, dict) and record.get("type") == "user":
            where = {"line": line, "uuid": record.get("uuid"), "timestamp": record.get("timestamp")}
            return where, record_text(record)
    return None, None


def first_prompt_check(transcript, prompt, expected_sha256):
    """Compare a session's first prompt with the recorded prompt file (F-A).

    Launchers that inherited stdin appended their own source to every first prompt, so
    the check reports how many characters follow the recorded prompt and how they start.
    """
    raw = Path(prompt).read_bytes()
    recorded = raw.decode("utf-8")
    rows, torn = read_jsonl(transcript)
    where, content = first_user_record(rows)
    result = {"transcript": str(transcript), "prompt": str(prompt), "prompt_sha256": sha256_bytes(raw),
              "expected_sha256": expected_sha256, "first_user_record": where, "torn_tail": torn,
              "prompt_chars": len(recorded), "first_prompt_chars": None if content is None else len(content),
              "equals_recorded": content == recorded}
    result["prompt_sha256_ok"] = result["prompt_sha256"] == expected_sha256
    if content is not None and content.startswith(recorded):
        extra = content[len(recorded):]
        result.update(prefix_matches=True, extra_chars=len(extra), extra_head=extra[:HEAD_CHARS])
    else:
        result.update(prefix_matches=False, extra_chars=None,
                      extra_head=None if content is None else content[:HEAD_CHARS])
    result["ok"] = result["prompt_sha256_ok"] and result["equals_recorded"]
    return result


def cmd_first_prompt_check(args):
    result = first_prompt_check(args.transcript, args.prompt, args.prompt_sha256)
    return (EXIT_OK if result["ok"] else EXIT_CRITICAL), result


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("first-prompt-check", help="Compare a transcript's first prompt with the recorded prompt")
    check.add_argument("--transcript", required=True)
    check.add_argument("--prompt", required=True)
    check.add_argument("--prompt-sha256", required=True)
    check.set_defaults(handler=cmd_first_prompt_check)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        code, result = args.handler(args)
    except Failure as exc:
        code, result = exc.code, {"ok": False, "error": str(exc), **exc.detail}
    except (ValueError, UnicodeError) as exc:
        code, result = EXIT_CRITICAL, {"ok": False, "error": str(exc)}
    except OSError as exc:
        code, result = EXIT_IO, {"ok": False, "error": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
