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
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import fields, read_json, require, text  # noqa: E402

EXIT_OK, EXIT_CRITICAL, EXIT_CONFLICT, EXIT_IO, EXIT_DIALOG = 0, 2, 3, 4, 5
HEAD_CHARS = 120
EFFORTS = ("low", "medium", "high", "xhigh", "max")
DIALOG_PHRASE = "Do you want to proceed?"
DIALOG_LIMIT_BYTES = 4096
CLAUDE_TIMEOUT_S = 120
# `claude --bg` prints this line first; the id is the session id's first 8 characters.
BACKGROUNDED = re.compile(r"^backgrounded · (\S+) · (.+)$", re.MULTILINE)
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class Failure(Exception):
    """A refusal with its exit code; detail fields are merged into the printed JSON."""

    def __init__(self, code, message, **detail):
        super().__init__(message)
        self.code = code
        self.detail = detail


def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_utc(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None


def encode_json(obj):
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def check_free_space(paths, min_free_mb, statvfs=os.statvfs):
    """Refuse before any write when a target's filesystem is nearly full.

    With / at 0 bytes free, writes and here-doc temp files failed silently and an ACK
    vanished four times (C2 F5), so the check runs before the first byte is written.
    """
    for path in paths:
        folder = Path(path).parent
        while not folder.exists() and folder != folder.parent:
            folder = folder.parent
        stats = statvfs(folder)
        free = stats.f_bavail * stats.f_frsize
        if free < min_free_mb * 1024 * 1024:
            raise Failure(EXIT_IO, "free space below --min-free-mb at %s: %d MB free, %d MB required"
                          % (folder, free // (1024 * 1024), min_free_mb), free_bytes=free, path=str(path))


def _fsync_folder(folder):
    fd = os.open(folder, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _temp_beside(path, raw):
    temp = path.parent / (".%s.%s.tmp" % (path.name, uuid.uuid4().hex))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return temp


def atomic_write_json(path, obj, expect_absent=True):
    """Write JSON through an O_EXCL temp, fsync and an atomic rename.

    An identical existing target counts as success, so a rerun is idempotent; a
    differing one is a conflict (exit 3, C2 F9). With expect_absent the rename is
    os.link, which never replaces a file another writer created after the check; the
    tool's own temp name is then removed, the only unlink it ever makes.
    """
    path = Path(path)
    raw = encode_json(obj)
    if expect_absent and path.exists():
        if path.read_bytes() == raw:
            return {"path": str(path), "written": False, "identical": True, "sha256": sha256_bytes(raw)}
        raise Failure(EXIT_CONFLICT, "target exists and differs: %s" % path, path=str(path))
    temp = _temp_beside(path, raw)
    try:
        if expect_absent:
            try:
                os.link(temp, path)
            except FileExistsError:
                if path.read_bytes() == raw:
                    return {"path": str(path), "written": False, "identical": True, "sha256": sha256_bytes(raw)}
                raise Failure(EXIT_CONFLICT, "target exists and differs: %s" % path, path=str(path)) from None
        else:
            os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()
    _fsync_folder(path.parent)
    return {"path": str(path), "written": True, "identical": False, "sha256": sha256_bytes(raw)}


def claude_env():
    """The launcher's own CLAUDE_* identity must not leak into a session it starts."""
    return {key: value for key, value in os.environ.items() if not key.startswith("CLAUDE_")}


def run_claude(argv, cwd=None, timeout=CLAUDE_TIMEOUT_S):
    """Run claude with stdin closed: an inherited stdin became part of the first prompt (F-A)."""
    try:
        proc = subprocess.run(["claude", *argv], cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True,
                              env=claude_env(), timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        out = exc.output or b""
        return {"exit": None, "timed_out": True, "stdout": out.decode("utf-8", "replace"), "stderr": ""}
    return {"exit": proc.returncode, "timed_out": False, "stdout": proc.stdout.decode("utf-8", "replace"),
            "stderr": proc.stderr.decode("utf-8", "replace")}


def agents_rows():
    result = run_claude(["agents", "--json"], timeout=30)
    if result["exit"] != 0:
        raise Failure(EXIT_CRITICAL, "claude agents --json failed", agents=result)
    try:
        rows = json.loads(result["stdout"])
    except ValueError:
        raise Failure(EXIT_CRITICAL, "claude agents --json printed no JSON list") from None
    require(isinstance(rows, list), "claude agents --json printed no JSON list")
    return [row for row in rows if isinstance(row, dict)]


def agent_row(rows, session):
    for row in rows:
        if session and (row.get("sessionId") == session or row.get("id") == session[:8]):
            return row
    return None


def strip_ansi(screen):
    return CONTROL.sub("", ANSI.sub("", screen))


def dialog_excerpt(screen, require_phrase=True):
    """The ANSI-stripped screen around the last permission question, at most 4 KB."""
    plain = strip_ansi(screen)
    index = plain.rfind(DIALOG_PHRASE)
    if index < 0:
        if require_phrase:
            return None
        end = len(plain)
    else:
        end = min(len(plain), index + len(DIALOG_PHRASE) + 256)
    return plain[:end].encode("utf-8")[-DIALOG_LIMIT_BYTES:].decode("utf-8", "ignore")


def find_transcript(projects_dir, session):
    """A transcript lives at <projects>/<cwd slug>/<session id>.jsonl; a short id is a prefix."""
    projects = Path(projects_dir)
    exact = sorted(projects.glob("*/%s.jsonl" % session))
    found = exact or sorted(projects.glob("*/%s*.jsonl" % session))
    return found[0] if len(found) == 1 else None


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


SESSION_ID = re.compile(r"[0-9a-f][0-9a-f-]{3,63}")


def read_launch_spec(path):
    spec = read_json(path)
    fields(spec, {"name", "model", "effort", "cwd", "add_dirs", "prompt", "uses_enter_worktree", "record_out"})
    text(spec["name"], "name", 256)
    text(spec["model"], "model", 128)
    require(spec["effort"] in EFFORTS, "effort must be one of " + ", ".join(EFFORTS))
    for key in ("cwd", "record_out"):
        require(Path(text(spec[key], key)).is_absolute(), key + " must be an absolute path")
    require(isinstance(spec["add_dirs"], list) and len(spec["add_dirs"]) <= 32, "add_dirs must be a list")
    for folder in spec["add_dirs"]:
        require(Path(text(folder, "add_dirs entry")).is_absolute(), "add_dirs entries must be absolute paths")
    fields(spec["prompt"], {"path", "sha256"})
    text(spec["prompt"]["path"], "prompt path")
    text(spec["prompt"]["sha256"], "prompt sha256", 64)
    require(type(spec["uses_enter_worktree"]) is bool, "uses_enter_worktree must be a boolean")
    return spec


def observe_launch(record, spec, args, started):
    """Fill the first-prompt check and the dialog detector into a launch record.

    A session stopped at a permission dialog leaves no assistant record (the turn holding
    the tool call is not written yet), so "no record yet" plus agents state blocked plus
    the dialog question on its screen is what tells a dialog from a long first request.
    """
    short = record["id"]
    transcript = check = assistant = None
    while True:
        transcript = transcript or find_transcript(args.projects_dir, short)
        if transcript is not None and first_user_record(read_jsonl(transcript)[0])[0] is not None:
            check = first_prompt_check(transcript, spec["prompt"]["path"], spec["prompt"]["sha256"])
            break
        if time.monotonic() - started >= args.wait_s:
            break
        time.sleep(args.poll_s)
    record["transcript"] = None if transcript is None else str(transcript)
    record["first_prompt_check"] = check
    while transcript is not None:
        assistant = next((line for line, row in read_jsonl(transcript)[0]
                          if isinstance(row, dict) and row.get("type") == "assistant"), None)
        if assistant is not None or time.monotonic() - started >= args.dialog_wait_s:
            break
        time.sleep(args.poll_s)
    record["first_assistant_line"] = assistant
    row = agent_row(agents_rows(), transcript.stem if transcript is not None else short)
    record["agents_row"] = row
    record["session"] = transcript.stem if transcript is not None else (row or {}).get("sessionId")
    if assistant is None and row is not None and row.get("state") == "blocked":
        screen = run_claude(["logs", short], timeout=30)
        excerpt = dialog_excerpt(screen["stdout"])
        if excerpt is None and "permission" in str(row.get("waitingFor", "")):
            excerpt = dialog_excerpt(screen["stdout"], require_phrase=False)
        if excerpt is not None:
            record["dialog"] = {"detected_at": utc_now(), "text": excerpt, "waiting_for": row.get("waitingFor")}


def cmd_launch(args):
    spec = read_launch_spec(args.spec)
    raw = Path(spec["prompt"]["path"]).read_bytes()
    if sha256_bytes(raw) != spec["prompt"]["sha256"]:
        raise Failure(EXIT_CRITICAL, "prompt does not re-hash to its recorded sha256",
                      prompt_sha256=sha256_bytes(raw))
    argv = ["--bg", "--agent", "claude", "--permission-mode", "auto", "--model", spec["model"],
            "--effort", spec["effort"]]
    for folder in spec["add_dirs"]:
        argv += ["--add-dir", folder]
    argv += ["-n", spec["name"], raw.decode("utf-8")]
    shown = ["claude", *argv[:-1], "<prompt>"]
    record_out = Path(spec["record_out"])
    if args.plan:
        return EXIT_OK, {"ok": True, "plan": True, "writes": [str(record_out)], "argv": shown, "cwd": spec["cwd"],
                         "target_exists": record_out.exists()}
    if record_out.exists():
        raise Failure(EXIT_CONFLICT, "launch record already exists: %s" % record_out, path=str(record_out))
    check_free_space([record_out], args.min_free_mb)
    live = [row.get("sessionId") for row in agents_rows() if row.get("name") == spec["name"]]
    if live:
        raise Failure(EXIT_CONFLICT, "a live session already has this name", name=spec["name"], live_sessions=live)
    started = time.monotonic()
    record = {"schema": "aegis.hierarchy-launch-record/v1", "at": utc_now(), "name": spec["name"], "argv": shown,
              "cwd": spec["cwd"], "stdin": "DEVNULL", "env": "CLAUDE_* unset",
              "prompt": {**spec["prompt"], "chars": len(raw.decode("utf-8"))},
              "uses_enter_worktree": spec["uses_enter_worktree"], "id": None, "session": None, "transcript": None,
              "first_prompt_check": None, "first_assistant_line": None, "agents_row": None, "dialog": None}
    result = run_claude(argv, cwd=spec["cwd"])
    record.update(exit=result["exit"], stdout=result["stdout"], stderr=result["stderr"])
    match = BACKGROUNDED.search(result["stdout"])
    if result["exit"] == 0 and match and SESSION_ID.fullmatch(match.group(1)):
        record["id"] = match.group(1)
        try:
            observe_launch(record, spec, args, started)
        except (Failure, OSError, ValueError) as exc:
            record["observe_error"] = str(exc)
    if record["id"] is None:
        code, verdict = EXIT_CRITICAL, "launch failed"
    elif not (record["first_prompt_check"] or {}).get("ok"):
        code, verdict = EXIT_CRITICAL, "first prompt unverified or different from the recorded prompt"
    elif record["dialog"] is not None:
        code, verdict = EXIT_DIALOG, "waiting on a human: a permission dialog is pending"
    else:
        code, verdict = EXIT_OK, "launched"
    record["verdict"] = verdict
    if record["id"] is not None and code != EXIT_OK:
        # Printed, never run: a stop may be refused and must stay a visible human or ROOT action.
        record["attach_command"] = "claude attach " + record["id"]
        record["stop_command"] = "claude stop " + record["id"]
    written = atomic_write_json(record_out, record)
    return code, {"ok": code == EXIT_OK, "verdict": verdict, "record_out": str(record_out), "written": written,
                  "record": record}


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("first-prompt-check", help="Compare a transcript's first prompt with the recorded prompt")
    check.add_argument("--transcript", required=True)
    check.add_argument("--prompt", required=True)
    check.add_argument("--prompt-sha256", required=True)
    check.set_defaults(handler=cmd_first_prompt_check)

    launch = commands.add_parser("launch", help="Start one claude --bg session from a spec and verify its start")
    launch.add_argument("--spec", required=True, help="Absolute path to a strict JSON launch spec")
    launch.add_argument("--plan", action="store_true", help="Print the paths and argv a run would use; write nothing")
    launch.add_argument("--projects-dir", default=str(Path.home() / ".claude" / "projects"))
    launch.add_argument("--wait-s", type=float, default=30.0, help="How long to wait for the first prompt")
    launch.add_argument("--dialog-wait-s", type=float, default=90.0, help="How long to wait for a first answer")
    launch.add_argument("--poll-s", type=float, default=2.0)
    launch.add_argument("--min-free-mb", type=int, default=512)
    launch.set_defaults(handler=cmd_launch)
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
