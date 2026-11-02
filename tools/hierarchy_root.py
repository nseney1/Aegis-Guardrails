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
import hierarchy_handoff  # noqa: E402
from hierarchy_mailbox import (  # noqa: E402
    SHA256, Mailbox, fields, matching, read_bytes, read_json, require, safe_path, text, writer_lock)

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


def cas_update_json(path, expect_sha256, mutate):
    """Replace a shared JSON file (custody, rendezvous) only if it still has the bytes read.

    mutate receives the parsed object and returns the new one (or edits it in place and
    returns None). The file is re-hashed just before os.replace; a change in between
    exits 2 and leaves the other writer's bytes untouched (C2 F6). Without a lock a
    window of one rename remains; the tool narrows it, it cannot close it.
    """
    path = Path(path)
    raw = path.read_bytes()
    if sha256_bytes(raw) != expect_sha256:
        raise Failure(EXIT_CRITICAL, "%s changed before the update" % path, expected_sha256=expect_sha256,
                      actual_sha256=sha256_bytes(raw))
    current = json.loads(raw)
    changed = mutate(current)
    updated = encode_json(current if changed is None else changed)
    temp = _temp_beside(path, updated)
    try:
        now = sha256_bytes(path.read_bytes())
        if now != expect_sha256:
            raise Failure(EXIT_CRITICAL, "%s changed during the update" % path, expected_sha256=expect_sha256,
                          actual_sha256=now)
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()
    _fsync_folder(path.parent)
    return {"path": str(path), "previous_sha256": expect_sha256, "sha256": sha256_bytes(updated)}


def verify_briefs(spec_briefs, checkpoint_briefs):
    """Every checkpoint brief re-hashes, and the spec's briefs are a subset of the checkpoint's.

    Requiring equality aborted a rotation whose checkpoint carried 3 briefs against the
    spec's 1 (C2 F2); a checkpoint may legitimately carry more.
    """
    for brief in [*spec_briefs, *checkpoint_briefs]:
        fields(brief, {"path", "sha256"})
        matching(brief["sha256"], SHA256, "brief sha256")
    rehash = []
    for brief in checkpoint_briefs:
        row = {"path": brief["path"], "sha256": brief["sha256"], "actual_sha256": None}
        try:
            row["actual_sha256"] = sha256_bytes(read_bytes(safe_path(text(brief["path"], "brief path"))))
        except (ValueError, OSError) as exc:
            row["error"] = str(exc)
        row["ok"] = row["actual_sha256"] == brief["sha256"]
        rehash.append(row)
    held = {brief["sha256"] for brief in checkpoint_briefs}
    missing = [brief["sha256"] for brief in spec_briefs if brief["sha256"] not in held]
    return {"ok": not missing and all(row["ok"] for row in rehash), "missing_from_checkpoint": missing,
            "rehash": rehash}


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


def matching_rows(rows, session):
    """Rows whose sessionId starts with session (a full id or a prefix of one).

    Real rows carry name, pid, sessionId, state and status but no id, so matching an id
    field never fired and a short id found nothing: a live session read as gone (P2-2).
    """
    return [row for row in rows if session and isinstance(row.get("sessionId"), str)
            and row["sessionId"].startswith(session)]


def agent_row(rows, session):
    """The one row for session; a prefix shared by several sessions is refused (exit 2)."""
    found = matching_rows(rows, session)
    sessions = sorted({row["sessionId"] for row in found})
    if len(sessions) > 1:
        raise Failure(EXIT_CRITICAL, "ambiguous session prefix %s: %d sessions match" % (session, len(sessions)),
                      matching_sessions=sessions)
    return found[0] if found else None


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
FULL_SESSION_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def full_session(value, label):
    """Steps that record a stop or move custody take only a full id: a prefix fails open (P2-2)."""
    require(isinstance(value, str) and FULL_SESSION_ID.fullmatch(value) is not None,
            "%s must be a full 36-character session id, not a prefix" % label)
    return value


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


def transcript_activity(rows):
    """Last record time, the last main-thread request and whether it was answered, pending notices."""
    last_ts = last_request = None
    answered = False
    pending = []
    for _line, record in rows:
        if not isinstance(record, dict):
            continue
        when = parse_utc(record.get("timestamp"))
        if when is not None and (last_ts is None or when >= last_ts[0]):
            last_ts = (when, record["timestamp"])
        kind = record.get("type")
        if kind == "api-request":
            last_request, answered = record, False
        elif kind == "assistant" and last_request is not None:
            answered = True
        elif kind == "queue-operation":
            operation, content = record.get("operation"), record.get("content")
            if operation == "enqueue":
                pending.append({"timestamp": record.get("timestamp"), "content": content})
            elif operation in ("dequeue", "remove") and pending:
                match = next((item for item in pending if content is not None and item["content"] == content), None)
                pending.remove(match if match is not None else pending[0])
    notices = [{"timestamp": item["timestamp"],
                "head": (item["content"] if isinstance(item["content"], str)
                         else json.dumps(item["content"]))[:HEAD_CHARS]} for item in pending]
    return last_ts, last_request, answered, notices


def lane_health(session, label, agents, args, now):
    """One session's liveness verdict (F-B).

    A request open past the effort's normal ceiling is "stalled"; it cannot read messages,
    so only a relaunch recovers it. A blocked agents state with the last request
    unanswered is a session parked on a dialog: only a human can answer it (T10).
    """
    entry = {"session": session, "label": label, "transcript": None, "torn_tail": False, "last_record_ts": None,
             "silent_s": None, "open_request_s": None, "open_request_id": None, "effort": None,
             "enqueued_notices": [], "agents_state": None, "stalled": False, "silent": False,
             "waiting_on_human": False, "dialog": None, "agents_error": None}
    if agents is not None:
        try:
            row = agent_row(agents, session)
        except Failure as exc:
            row, entry["agents_error"] = None, str(exc)
        if row is not None:
            entry["agents_state"] = {key: row.get(key) for key in ("id", "name", "pid", "status", "state", "waitingFor")}
    transcript = find_transcript(args.projects_dir, session)
    if transcript is None:
        entry["error"] = "transcript not found under " + str(args.projects_dir)
        return entry
    entry["transcript"] = str(transcript)
    try:
        rows, entry["torn_tail"] = read_jsonl(transcript)
    except (Failure, OSError) as exc:
        entry["error"] = str(exc)
        return entry
    last_ts, request, answered, entry["enqueued_notices"] = transcript_activity(rows)
    if last_ts is not None:
        entry["last_record_ts"] = last_ts[1]
        entry["silent_s"] = round((now - last_ts[0]).total_seconds(), 3)
        entry["silent"] = entry["silent_s"] > args.silent_s
    if request is not None:
        params = request.get("params") if isinstance(request.get("params"), dict) else {}
        config = params.get("output_config") if isinstance(params.get("output_config"), dict) else {}
        entry["effort"] = config.get("effort")
        opened = parse_utc(request.get("timestamp"))
        if not answered and opened is not None:
            entry["open_request_s"] = round((now - opened).total_seconds(), 3)
            entry["open_request_id"] = request.get("id")
            limit = args.stall_max_s if entry["effort"] == "max" else args.stall_s
            entry["stalled"] = entry["open_request_s"] > limit
    state = entry["agents_state"]
    if state is not None and state.get("state") == "blocked" and entry["open_request_s"] is not None:
        entry["waiting_on_human"] = True
        screen = run_claude(["logs", state.get("id") or session[:8]], timeout=30)
        excerpt = dialog_excerpt(screen["stdout"])
        if excerpt is not None:
            entry["dialog"] = {"text": excerpt}
    return entry


def session_argument(value):
    session, _, label = value.partition("=")
    require(SESSION_ID.fullmatch(session) is not None, "invalid session id: " + session[:80])
    return session, label or session


def cmd_lanes_health(args):
    now = parse_utc(args.now) if args.now else datetime.now(timezone.utc)
    require(now is not None, "--now must be a UTC timestamp ending in Z")
    sessions = [session_argument(value) for value in args.session]
    result = {"ok": True, "now": now.isoformat().replace("+00:00", "Z"),
              "thresholds": {"stall_s": args.stall_s, "stall_max_s": args.stall_max_s, "silent_s": args.silent_s}}
    try:
        agents = agents_rows()
    except (Failure, OSError) as exc:
        agents, result["agents_error"] = None, str(exc)
    result["sessions"] = [lane_health(session, label, agents, args, now) for session, label in sessions]
    return EXIT_OK, result


INBOX_PAGE = 20  # the mailbox caps a page at 100; 500 fails with "invalid inbox limit" (C5 F3)
MAX_INBOX_PAGES = 1000


def ack_request_path(ack_dir, endpoint, generation):
    return Path(ack_dir) / ("ack-%s-g%d.json" % (endpoint.replace("/", "-"), generation))


def read_whole_inbox(mailbox, endpoint):
    """Follow next_after until remaining is 0: one default page hid 4 of 24 messages (T15, T28)."""
    after, messages, pages = None, [], 0
    while True:
        page = mailbox.inbox(endpoint, include_briefs=True, limit=INBOX_PAGE, after=after)
        pages += 1
        messages += page["messages"]
        if page["remaining"] == 0:
            return page, messages, pages
        require(page["next_after"] is not None and pages < MAX_INBOX_PAGES, "inbox paging did not reach remaining 0")
        after = page["next_after"]


def rebind_entry(spec, entry, row, ack_dir):
    endpoint = entry["endpoint"]
    out = {"root": entry["root"], "endpoint": endpoint, "ready": False}
    if not row.get("ok"):
        out["error"] = row.get("error", "handoff failed")
        return out
    page, messages, pages = read_whole_inbox(Mailbox(entry["root"]), endpoint)
    binding = page["binding"]
    out.update(generation=binding["generation"], checkpoint_sha256=binding["checkpoint_sha256"], pages=pages,
               messages_read=len(messages), remaining=page["remaining"])
    expected = {"host": spec["host"], "session": spec["session"], "generation": row["generation"],
                "checkpoint_sha256": row["checkpoint_sha256"]}
    differing = sorted(key for key, value in expected.items() if binding.get(key) != value)
    if differing:
        out["error"] = "binding differs from the handoff result: " + ", ".join(differing)
        return out
    out["briefs"] = verify_briefs(entry.get("briefs", []), (binding["checkpoint"] or {}).get("briefs", []))
    if not out["briefs"]["ok"]:
        out["error"] = "brief check failed: spec briefs must be in the checkpoint and every brief must re-hash"
        return out
    request = row["acknowledge"]
    if request is None:
        out["ready"] = binding["ready"]
        return out
    path = ack_request_path(ack_dir, endpoint, request["generation"])
    atomic_write_json(path, request)
    out["ack_request"] = str(path)
    if binding["ready"]:
        out.update(ready=True, already_acknowledged=True)
        return out
    with writer_lock(safe_path(entry["root"])):
        out["ready"] = Mailbox(entry["root"]).acknowledge_handoff(request)["ready"]
    return out


def planned_generation(spec, entry):
    current = Mailbox(entry["root"]).bindings(entry["endpoint"])[-1]
    same = current["host"] == spec["host"] and current["session"] == spec["session"]
    return current["generation"] if same else current["generation"] + 1


def cmd_rebind(args):
    """Bind every spec endpoint to this session, read each inbox to the end, check, acknowledge.

    The incoming session runs this through its own connection; it replaces the three-step
    loop each ROOT typed by hand (C2 section 3).
    """
    spec = read_json(args.spec)
    fields(spec, {"schema", "host", "session", "outgoing_stopped", "entries"})
    require(spec["schema"] == hierarchy_handoff.SPEC_SCHEMA, "unsupported handoff spec schema")
    require(isinstance(spec["entries"], list) and spec["entries"], "handoff spec requires entries")
    for entry in spec["entries"]:
        require(isinstance(entry, dict) and {"root", "endpoint"} <= entry.keys(), "entries need root and endpoint")
    result_out = Path(args.result_out)
    if args.plan:
        acks = [str(ack_request_path(args.ack_dir, entry["endpoint"], planned_generation(spec, entry)))
                for entry in spec["entries"]]
        return EXIT_OK, {"ok": True, "plan": True, "writes": [str(result_out), *acks],
                         "mailbox_roots": [entry["root"] for entry in spec["entries"]]}
    if result_out.exists():
        raise Failure(EXIT_CONFLICT, "result already exists: %s" % result_out, path=str(result_out))
    check_free_space([result_out, Path(args.ack_dir) / "ack.json"], args.min_free_mb)
    handoff = hierarchy_handoff.run(args.spec)
    rows = []
    for entry, row in zip(spec["entries"], handoff["entries"]):
        try:
            rows.append(rebind_entry(spec, entry, row, args.ack_dir))
        except (Failure, ValueError, OSError, UnicodeError) as exc:
            rows.append({"root": entry["root"], "endpoint": entry["endpoint"], "ready": False, "error": str(exc)})
    result = {"schema": "aegis.hierarchy-rebind-result/v1", "host": spec["host"], "session": spec["session"],
              "ok": all(row["ready"] for row in rows), "handoff": handoff, "entries": rows}
    atomic_write_json(result_out, result)
    return (EXIT_OK if result["ok"] else EXIT_CRITICAL), result


def process_state(pid):
    """(alive, start_ticks). A zombie is gone; start ticks are field 22 of /proc/<pid>/stat,
    read after the last ")" because the command name may itself contain one."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False, None
    except PermissionError:
        pass
    try:
        stat = Path("/proc/%d/stat" % pid).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return True, None
    after = stat[stat.rfind(")") + 2:].split()
    if after and after[0] == "Z":
        return False, None
    return True, int(after[19]) if len(after) > 19 and after[19].isdigit() else None


def cmd_verify_retired(args):
    """Check an outgoing session is really gone before anyone records it as stopped (F5).

    Retired means its PID is gone (or reused, when --start-ticks is given) and claude agents
    no longer lists it. While it is not, this prints the stop command for a human or ROOT
    to run and exits 2: the tool never stops a session itself (T27, T13).
    """
    session = full_session(args.session, "--session")
    require((args.custody is None) == (args.expect_custody_sha256 is None),
            "--custody and --expect-custody-sha256 go together")
    alive, ticks = process_state(args.pid)
    if alive and args.start_ticks is not None and ticks is not None and ticks != args.start_ticks:
        alive = False
    listed = matching_rows(agents_rows(), session)
    result = {"session": session, "pid": args.pid, "pid_alive": alive, "pid_start_ticks": ticks,
              "agents_listed": bool(listed), "agents_rows": listed, "retired": not alive and not listed}
    result["verdict"] = ("retired" if result["retired"] else "alive" if alive else "listed_but_pid_gone")
    if not result["retired"]:
        result["stop_command"] = "claude stop " + session[:8]
        result["ok"] = False
        return EXIT_CRITICAL, result
    if args.custody is not None:
        check_free_space([args.custody], args.min_free_mb)
        stopped = {"verified_at": utc_now(), "pid": args.pid, "start_ticks": args.start_ticks,
                   "evidence": {"pid_alive": False, "agents_listed": False},
                   "by": "hierarchy_root.py verify-retired"}

        def record(custody):
            history = custody.get("custody_history") if isinstance(custody, dict) else None
            entries = [entry for entry in history or [] if isinstance(entry, dict)
                       and entry.get("outgoing_root") == session]
            require(bool(entries), "custody_history has no entry for outgoing root " + session)
            entries[-1]["outgoing_stopped"] = stopped
            return custody

        result["custody_update"] = cas_update_json(args.custody, args.expect_custody_sha256, record)
    result["ok"] = True
    return EXIT_OK, result


def file_ref(path):
    path = Path(path)
    return {"path": str(path), "sha256": sha256_bytes(path.read_bytes())}


ACK_SCHEMA = "aegis.claude-root-startup-ack/v1"


def ack_problems(ack, facts):
    """Why a startup ACK does not vouch for this transfer; empty when it does (P2-1).

    Finding the incoming session's bytes in the file accepted an ACK left from an earlier
    attempt, or one about a packet regenerated after it was written, so custody could move
    to a ROOT that never verified the packet the facts name. The ACK has to be about these
    two sessions and this packet, and every critical check it ran has to have passed; a
    hand-written ACK without critical_checks is refused, not assumed fine.
    """
    if not isinstance(ack, dict):
        return ["the ACK is not a JSON object"]

    def at(*keys):
        value = ack
        for key in keys:
            value = value.get(key) if isinstance(value, dict) else None
        return value

    problems = [] if ack.get("schema") == ACK_SCHEMA else ["schema is not " + ACK_SCHEMA]
    for side in ("incoming", "outgoing"):
        if at(side, "session") != facts[side]["session"]:
            problems.append("%s.session is not the facts' %s session" % (side, side))
    if at("observed", "handoff", "sha256") != facts["handoff"]["sha256"]:
        problems.append("observed.handoff.sha256 is not the facts' handoff sha256")
    checks = ack.get("critical_checks")
    if not isinstance(checks, list) or not checks:
        problems.append("critical_checks is missing or empty")
    else:
        failed = [check.get("name") if isinstance(check, dict) else check for check in checks
                  if not (isinstance(check, dict) and check.get("ok") is True)]
        if failed:
            problems.append("critical checks not ok: " + json.dumps(failed)[:200])
    return problems


def read_transfer_facts(path):
    facts = read_json(path)
    fields(facts, {"outgoing", "incoming", "handoff", "authority"}, {"goal", "invariants", "transferred_at"})
    fields(facts["outgoing"], {"host", "session", "pid", "start_ticks", "label"})
    fields(facts["incoming"], {"host", "session", "label"}, {"pid", "start_ticks", "job_dir"})
    fields(facts["handoff"], {"path", "sha256"})
    for side in ("outgoing", "incoming"):
        full_session(text(facts[side]["session"], side + " session"), side + " session")
        require(re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,15}", text(facts[side]["label"], side + " label")) is not None,
                "invalid %s label" % side)
    return facts


def cmd_transfer(args):
    """Outgoing ROOT: write the next root spec and the transfer, then move custody by CAS.

    After C1's transfer custody named C2 in active_native_root but still C1 in
    active_root_session (C2 F3); all three active_* fields move together here. The
    outgoing session is not stopped by the tool: it prints the stop command, and
    verify-retired records the stop once the incoming side has acknowledged (F5).
    """
    facts = read_transfer_facts(args.facts)
    out, inc = facts["outgoing"], facts["incoming"]
    ack_raw = Path(args.ack).read_bytes()
    if sha256_bytes(ack_raw) != args.ack_sha256:
        raise Failure(EXIT_CRITICAL, "startup ACK does not re-hash to --ack-sha256", ack_sha256=sha256_bytes(ack_raw))
    try:
        ack = json.loads(ack_raw)
    except ValueError:
        ack = None
    problems = ack_problems(ack, facts)
    if problems:
        raise Failure(EXIT_CRITICAL, "startup ACK does not vouch for this transfer: " + "; ".join(problems),
                      problems=problems)
    if sha256_bytes(Path(facts["handoff"]["path"]).read_bytes()) != facts["handoff"]["sha256"]:
        raise Failure(EXIT_CRITICAL, "handoff packet does not re-hash to its recorded sha256")
    custody_raw = Path(args.custody).read_bytes()
    if sha256_bytes(custody_raw) != args.expect_custody_sha256:
        raise Failure(EXIT_CRITICAL, "custody changed: it does not re-hash to --expect-custody-sha256",
                      actual_sha256=sha256_bytes(custody_raw))
    custody = json.loads(custody_raw)
    require(custody.get("active_root_session") == out["session"], "custody does not name the outgoing root")
    prev = read_json(args.prev_spec)
    fields(prev, {"schema", "host", "session", "outgoing_stopped", "entries"})
    require(prev["schema"] == hierarchy_handoff.SPEC_SCHEMA, "unsupported previous spec schema")
    writes = [str(args.spec_out), str(args.transfer_out), str(args.custody)]
    if args.plan:
        return EXIT_OK, {"ok": True, "plan": True, "writes": writes}
    check_free_space(writes, args.min_free_mb)
    at = facts.get("transferred_at") or utc_now()
    ack_sha, delta = sha256_bytes(ack_raw), file_ref(args.final_delta)
    stop_command = "claude stop " + out["session"][:8]
    checks = [
        "Outgoing %s ROOT %s %s retires with this transfer and takes no further root action; per owner rule F5 it "
        "is then stopped (%s) and verify-retired records the stop." % (out["host"], out["label"], out["session"],
                                                                       stop_command),
        "Incoming %s ROOT %s %s startup ACK verified (sha %s)." % (inc["host"], inc["label"], inc["session"], ack_sha),
        "Final delta %s sha %s." % (delta["path"], delta["sha256"]),
    ]
    spec = {"schema": prev["schema"], "host": inc["host"], "session": inc["session"], "outgoing_stopped": True,
            "entries": [{**entry, "completed_checks": checks} for entry in prev["entries"]]}
    atomic_write_json(args.spec_out, spec)
    record = {"schema": "aegis.claude-to-claude-root-transfer/v1", "state": "TRANSFERRED", "at": at,
              "outgoing": {key: out[key] for key in ("host", "session", "pid", "start_ticks")},
              "incoming": {**{key: inc[key] for key in ("host", "session", "pid", "start_ticks", "job_dir") if key in inc},
                           "startup_ack": {"path": str(args.ack), "sha256": ack_sha}},
              "handoff": facts["handoff"], "final_delta": delta, "root_spec": file_ref(args.spec_out),
              "authority": facts["authority"], "goal": facts.get("goal"), "invariants": facts.get("invariants")}
    record["outgoing"]["scope"] = "retired: no further root action; stop pending verify-retired"
    atomic_write_json(args.transfer_out, record)
    transfer_ref = file_ref(args.transfer_out)
    key = "claude_%s_to_%s_handoff" % (out["label"].lower(), inc["label"].lower())

    def move(custody):
        require(custody.get("active_root_session") == out["session"], "custody does not name the outgoing root")
        custody.update(active_native_root=inc["session"], active_root_session=inc["session"],
                       active_root_host=inc["host"],
                       current_root_dispatch_state="Sole Claude ROOT %s %s ACTIVE after transfer; %s retired."
                       % (inc["label"], inc["session"], out["label"]))
        history = custody.setdefault("custody_history", [])
        require(isinstance(history, list), "custody_history must be a list")
        history.append({"outgoing_host": out["host"], "outgoing_root": out["session"], "incoming_host": inc["host"],
                        "incoming_root": inc["session"], "transferred_at": at,
                        "handoff_path": facts["handoff"]["path"], "handoff_sha256": facts["handoff"]["sha256"],
                        "startup_ack_sha256": ack_sha, "transfer": transfer_ref, "final_delta": delta})
        handoff = custody.setdefault(key, {})
        require(isinstance(handoff, dict), key + " must be an object")
        handoff.update(state="TRANSFERRED_%s_EXECUTES_ROOT_SPEC" % inc["label"].upper(), transferred_at=at,
                       incoming_host=inc["host"], incoming_session=inc["session"], transfer=transfer_ref,
                       final_delta=delta, startup_ack={"path": str(args.ack), "sha256": ack_sha})
        return custody

    update = cas_update_json(args.custody, args.expect_custody_sha256, move)
    return EXIT_OK, {"ok": True, "spec_out": file_ref(args.spec_out), "transfer_out": transfer_ref,
                     "custody_update": update, "stop_command": stop_command,
                     "next": ("After the incoming ROOT acknowledges every endpoint, a human or ROOT runs `%s`, then "
                              "hierarchy_root.py verify-retired --session %s --pid %d --custody %s "
                              "--expect-custody-sha256 %s" % (stop_command, out["session"], out["pid"], args.custody,
                                                             update["sha256"]))}


GOAL_MARKERS = ("<command-name>/goal</command-name>", "Goal set:")


def goal_records(rows):
    """User records whose own text sets a goal, each cited by its own line (F8).

    record_text reads only string content and text blocks, so a tool result that merely
    quotes "Goal set:" is not a goal record.
    """
    found = []
    for line, record in rows:
        if isinstance(record, dict) and record.get("type") == "user":
            body = record_text(record)
            if body and any(marker in body for marker in GOAL_MARKERS):
                found.append({"line": line, "timestamp": record.get("timestamp"), "uuid": record.get("uuid"),
                              "head": body[:HEAD_CHARS]})
    return found


def session_identity(projects_dir):
    """Who is running this tool: env, live host process and the transcript that names it."""
    session = os.environ.get("CLAUDE_CODE_SESSION_ID") or os.environ.get("CODEX_THREAD_ID")
    pid_text = os.environ.get("CLAUDE_PID", "")
    pid = int(pid_text) if pid_text.isdigit() else None
    alive, ticks = process_state(pid) if pid else (False, None)
    proof = {"runtime_env": sorted(key for key in os.environ if key.startswith("CLAUDE_")
                                   and "TOKEN" not in key and "SOCKET" not in key),
             "host_process": {"pid": pid, "alive": alive, "start_ticks": ticks},
             "job_dir": os.environ.get("CLAUDE_JOB_DIR"), "transcript": None, "transcript_line1": None,
             "transcript_first_user_record": None}
    rows, torn = [], False
    transcript = find_transcript(projects_dir, session) if session and SESSION_ID.fullmatch(session) else None
    if transcript is not None:
        rows, torn = read_jsonl(transcript)
        proof["transcript"] = str(transcript)
        if rows and isinstance(rows[0][1], dict):
            proof["transcript_line1"] = {"line": rows[0][0], "sessionId": rows[0][1].get("sessionId")}
        proof["transcript_first_user_record"] = first_user_record(rows)[0]
    ok = bool(session) and alive and (proof["transcript_line1"] or {}).get("sessionId") == session
    return session, proof, ok, rows, torn


def git_state(path, ignored=False):
    def git(*arguments):
        result = subprocess.run(["git", "--no-optional-locks", "-c", "core.fsmonitor=false", *arguments], cwd=path,
                                capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
        require(result.returncode == 0, "git %s failed in %s" % (arguments[0], path))
        return result.stdout
    status = git("status", "--porcelain=v1", "-z", "--untracked-files=all", *(["--ignored"] if ignored else []))
    entries = len([token for token in status.split(b"\0") if token[2:3] == b" "])
    return {"path": str(path), "commit": git("rev-parse", "HEAD").decode().strip(),
            "tree": git("rev-parse", "HEAD^{tree}").decode().strip(), "porcelain_entries": entries,
            "clean": entries == 0}


def source_observation(path):
    """Observed, never fatal: a deleted checkout is recorded, not a reason to abort (C2 F6)."""
    if not Path(path).exists():
        return {"path": path, "present": False}
    try:
        from hierarchy_jobs import uncommitted_content
        state = git_state(path)
        digest, count = uncommitted_content(path)
        return {"path": path, "present": True, "commit": state["commit"], "tree": state["tree"],
                "dirty_content_sha256": digest, "dirty_entries": count}
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        return {"path": path, "present": True, "error": str(exc)}


def cmd_startup_ack(args):
    """Incoming ROOT: build the startup ACK from live facts (C2 section 3).

    Critical checks exit 2 and write nothing. Everything else is observed and recorded,
    so a deleted source or a changed lease no longer aborts an ACK after every critical
    check has passed (F1, F6).
    """
    out = Path(args.out)
    if args.plan:
        return EXIT_OK, {"ok": True, "plan": True, "writes": [str(out)]}
    checks = []

    def critical(name, ok, **detail):
        checks.append({"name": name, "ok": bool(ok), **detail})

    packet_raw = Path(args.packet).read_bytes()
    critical("packet_sha256", sha256_bytes(packet_raw) == args.packet_sha256, actual=sha256_bytes(packet_raw))
    rendezvous_raw = Path(args.rendezvous).read_bytes()
    rendezvous = json.loads(rendezvous_raw)
    require(isinstance(rendezvous, dict), "the rendezvous file is not a JSON object")
    # --packet and --packet-sha256 come from the operator; the rendezvous says which packet
    # the outgoing ROOT means, so a stale or regenerated packet is refused here (P2-1).
    named = rendezvous.get("handoff") if isinstance(rendezvous.get("handoff"), dict) else {}
    critical("rendezvous_names_packet", named.get("sha256") == sha256_bytes(packet_raw)
             and isinstance(named.get("path"), str) and Path(named["path"]).resolve() == Path(args.packet).resolve(),
             rendezvous_handoff=named or None)
    session, proof, identity_ok, rows, torn = session_identity(args.projects_dir)
    critical("own_identity", identity_ok, session=session)
    waiting = (str(rendezvous.get("state", "")).startswith("WAITING") and rendezvous.get("incoming_host") == args.host
               and rendezvous.get("incoming_session") in (None, session)
               and sha256_bytes(rendezvous_raw) == args.rendezvous_sha256)
    critical("rendezvous_awaits_this_host", waiting, state=rendezvous.get("state"))
    custody_raw = Path(args.custody).read_bytes()
    custody = json.loads(custody_raw)
    outgoing = rendezvous.get("outgoing_session")
    critical("custody_names_outgoing_root", outgoing is not None and custody.get("active_root_session") == outgoing,
             active_root_session=custody.get("active_root_session"))
    try:
        pin = git_state(args.tools_pin, ignored=True)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        pin = {"path": str(args.tools_pin), "clean": False, "error": str(exc)}
    critical("tools_pin_clean", pin["clean"], porcelain_entries=pin.get("porcelain_entries"))
    if not all(check["ok"] for check in checks):
        return EXIT_CRITICAL, {"ok": False, "error": "a critical startup check failed; nothing was written",
                               "critical_checks": checks}
    check_free_space([out], args.min_free_mb)
    stats = os.statvfs(out.parent)
    sources = [source_observation(path) for path in (read_json(args.sources) if args.sources else [])]
    observations = ["source missing: " + s["path"] for s in sources if not s["present"]]
    if torn:
        observations.append("own transcript has a torn last line (skipped)")
    ack = {"schema": ACK_SCHEMA, "startup_only": True, "custody_transfer": False,
           "at": utc_now(),
           "incoming": {"role": args.role, "host": args.host, "session": session, "identity_proof": proof},
           "outgoing": {"host": rendezvous.get("outgoing_host"), "session": outgoing},
           "observed": {"handoff": {"path": str(args.packet), "sha256": sha256_bytes(packet_raw)},
                        "rendezvous": {"path": str(args.rendezvous), "sha256": sha256_bytes(rendezvous_raw),
                                       "state": rendezvous.get("state"),
                                       "incoming_session": rendezvous.get("incoming_session")},
                        "custody": {"path": str(args.custody), "sha256": sha256_bytes(custody_raw),
                                    "active_root_session": custody.get("active_root_session"),
                                    "active_native_root": custody.get("active_native_root")},
                        "tools_pin": pin, "sources_readonly": sources,
                        "disk": {"free_mb": stats.f_bavail * stats.f_frsize // (1024 * 1024)}},
           "goal_records": goal_records(rows), "torn_tail": torn, "critical_checks": checks,
           "observations": observations}
    written = atomic_write_json(out, ack)
    return EXIT_OK, {"ok": True, "out": str(out), "written": written, "ack": ack}


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

    health = commands.add_parser("lanes-health", help="Report stalled, silent or dialog-blocked sessions; always exit 0")
    health.add_argument("--session", action="append", required=True, metavar="ID[=LABEL]")
    health.add_argument("--projects-dir", default=str(Path.home() / ".claude" / "projects"))
    health.add_argument("--stall-s", type=float, default=1200.0, help="Open request ceiling at xhigh or below")
    health.add_argument("--stall-max-s", type=float, default=1500.0, help="Open request ceiling at max effort")
    health.add_argument("--silent-s", type=float, default=900.0, help="No-record ceiling")
    health.add_argument("--now", help="UTC timestamp to measure ages from (default: the clock)")
    health.set_defaults(handler=cmd_lanes_health)

    rebind = commands.add_parser("rebind", help="Bind, read every inbox page, check briefs and acknowledge")
    rebind.add_argument("--spec", required=True, help="Absolute path to an aegis.hierarchy-handoff/v1 spec")
    rebind.add_argument("--result-out", required=True)
    rebind.add_argument("--ack-dir", required=True, help="Folder for the acknowledgment requests")
    rebind.add_argument("--plan", action="store_true", help="Print the paths a run would write; write nothing")
    rebind.add_argument("--min-free-mb", type=int, default=512)
    rebind.set_defaults(handler=cmd_rebind)

    retired = commands.add_parser("verify-retired", help="Verify an outgoing session is gone; record it via CAS")
    retired.add_argument("--session", required=True)
    retired.add_argument("--pid", type=int, required=True)
    retired.add_argument("--start-ticks", type=int, help="Expected /proc start ticks; a different value is a reused PID")
    retired.add_argument("--custody", help="Custody file whose custody_history entry receives outgoing_stopped")
    retired.add_argument("--expect-custody-sha256")
    retired.add_argument("--min-free-mb", type=int, default=512)
    retired.set_defaults(handler=cmd_verify_retired)

    move = commands.add_parser("transfer", help="Outgoing ROOT: write spec and transfer, move custody by CAS")
    move.add_argument("--facts", required=True, help="JSON: outgoing, incoming, handoff, authority")
    move.add_argument("--ack", required=True)
    move.add_argument("--ack-sha256", required=True)
    move.add_argument("--final-delta", required=True)
    move.add_argument("--prev-spec", required=True)
    move.add_argument("--spec-out", required=True)
    move.add_argument("--transfer-out", required=True)
    move.add_argument("--custody", required=True)
    move.add_argument("--expect-custody-sha256", required=True)
    move.add_argument("--plan", action="store_true", help="Print the paths a run would write; write nothing")
    move.add_argument("--min-free-mb", type=int, default=512)
    move.set_defaults(handler=cmd_transfer)

    ack = commands.add_parser("startup-ack", help="Incoming ROOT: build the startup ACK from live facts")
    ack.add_argument("--packet", required=True)
    ack.add_argument("--packet-sha256", required=True)
    ack.add_argument("--rendezvous", required=True)
    ack.add_argument("--rendezvous-sha256", required=True, help="The rendezvous must still have these bytes")
    ack.add_argument("--custody", required=True)
    ack.add_argument("--tools-pin", required=True, help="Pinned tools checkout; must be clean, ignored files included")
    ack.add_argument("--sources", help="JSON list of absolute source checkouts to observe read-only")
    ack.add_argument("--role", required=True)
    ack.add_argument("--host", default="claude-code")
    ack.add_argument("--out", required=True)
    ack.add_argument("--projects-dir", default=str(Path.home() / ".claude" / "projects"))
    ack.add_argument("--plan", action="store_true", help="Print the paths a run would write; write nothing")
    ack.add_argument("--min-free-mb", type=int, default=512)
    ack.set_defaults(handler=cmd_startup_ack)
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
