#!/usr/bin/env python3
"""Meter a session's active time from its host transcript, for the owner's rotation limits.

Root rotates after 90 active minutes and every other session after 60.

Session age is the wrong measure: an idle session uses no budget. This sums finished turns from
the transcript itself. A turn with no recorded end stays unknown instead of getting an invented
end, because a missing end can mean a running turn or a killed one. Unknown time never counts as
active, but if it could reach the limit the state warns. Time spent waiting inside a turn counts,
which errs toward rotating early.

Reads only. A transcript is a host's own record, not proof of what a session did.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import hierarchy_hosts  # noqa: E402
from hierarchy_hosts import SESSION  # noqa: E402

CLAUDE_HOSTS = {kind for kind in hierarchy_hosts.HOST_KINDS if hierarchy_hosts.family(kind) == "claude"}
CODEX_HOSTS = {kind for kind in hierarchy_hosts.HOST_KINDS if hierarchy_hosts.family(kind) == "codex"}
SESSION_LIMIT_SECONDS = 3600
ROOT_LIMIT_SECONDS = 5400
WARN_FRACTION = 0.8
CODEX_ENDS = {"task_complete", "turn_aborted"}


def moment(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def read_records(path):
    records, malformed = [], 0
    with open(path, encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError:
                malformed += 1
                continue
            if isinstance(record, dict) and isinstance(record.get("timestamp"), str):
                try:
                    moment(record["timestamp"])
                except ValueError:
                    malformed += 1
                    continue
                records.append(record)
    return records, malformed


def span(start, end):
    return max(0.0, (moment(end) - moment(start)).total_seconds())


def codex_turns(records):
    active, turns, unknown = 0.0, 0, []
    started = None
    last = None
    for record in records:
        payload = record.get("payload") if record.get("type") == "event_msg" else None
        kind = payload.get("type") if isinstance(payload, dict) else None
        if kind == "task_started":
            if started is not None:
                unknown.append({"started_at": started, "last_record_at": last})
            started = record["timestamp"]
        elif kind in CODEX_ENDS and started is not None:
            active += span(started, record["timestamp"])
            turns += 1
            started = None
        last = record["timestamp"]
    open_turn = started is not None
    if open_turn:
        unknown.append({"started_at": started, "last_record_at": last})
    return active, turns, unknown, open_turn


def claude_prompt(record):
    if record.get("type") != "user" or record.get("isMeta"):
        return False
    message = record.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        return True
    return isinstance(content, list) and any(isinstance(part, dict) and part.get("type") == "text" for part in content)


def claude_turns(records):
    """A turn ends at its last reply or tool result. Other records can carry later timestamps from
    the idle gap before the next prompt, such as queue operations, attachments and summaries."""
    active, turns, unknown = 0.0, 0, []
    started = last = None
    replied = False
    open_turn = False
    for record in records + [None]:
        if record is None or claude_prompt(record):
            if started is not None:
                if replied:
                    active += span(started, last)
                    turns += 1
                else:
                    unknown.append({"started_at": started, "last_record_at": last})
                    open_turn = record is None
            if record is not None:
                started, last, replied = record["timestamp"], record["timestamp"], False
            continue
        if started is not None and record.get("type") in ("assistant", "user"):
            last = record["timestamp"]
            replied = replied or record.get("type") == "assistant"
    return active, turns, unknown, open_turn


def find_transcript(host, session):
    if (not isinstance(host, str) or host not in CLAUDE_HOSTS | CODEX_HOSTS
            or not isinstance(session, str) or SESSION.fullmatch(session) is None):
        return None
    spec = hierarchy_hosts.entry(host)["home"]
    home = os.environ.get(spec["variable"]) or Path.home() / spec["owner_folder"]
    # Archived rollouts were invisible to the meter and evidence collection without the registry.
    found = hierarchy_hosts.transcripts(host, home, session)
    return max(found, key=lambda path: path.stat().st_mtime) if found else None


def measure(host, session, transcript=None, limit=SESSION_LIMIT_SECONDS):
    if host not in CLAUDE_HOSTS | CODEX_HOSTS:
        raise ValueError("unsupported host: " + str(host))
    if not isinstance(session, str) or SESSION.fullmatch(session) is None:
        raise ValueError("invalid session")
    if type(limit) is not int or not 0 < limit <= 86400:
        raise ValueError("invalid limit")
    answer = {"host": host, "session": session, "limit": limit, "active_seconds": None, "turns": 0, "open_turn": False,
              "unknown_intervals": [], "malformed_lines": 0, "transcript": None, "state": "no_transcript"}
    path = Path(transcript) if transcript is not None else find_transcript(host, session)
    if path is None:
        return answer
    try:
        records, malformed = read_records(path)
    except OSError as exc:
        raise ValueError("transcript unavailable: " + str(path)) from exc
    active, turns, unknown, open_turn = (claude_turns if host in CLAUDE_HOSTS else codex_turns)(records)
    possible = active + sum(span(row["started_at"], row["last_record_at"]) for row in unknown)
    if active >= limit:
        state = "rotate_now"
    elif active >= limit * WARN_FRACTION or possible >= limit:
        state = "rotate_soon"
    else:
        state = "ok"
    return {**answer, "active_seconds": round(active, 3), "turns": turns, "open_turn": open_turn,
            "unknown_intervals": unknown, "malformed_lines": malformed, "transcript": str(path), "state": state}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--transcript", default=None, help="Read this file instead of the host's usual location")
    parser.add_argument("--role", choices=("session", "root"), default="session", help="Which rotation limit applies")
    parser.add_argument("--limit", type=int, default=None, help="Seconds, replacing the role's limit")
    args = parser.parse_args(argv)
    limit = args.limit if args.limit is not None else ROOT_LIMIT_SECONDS if args.role == "root" else SESSION_LIMIT_SECONDS
    try:
        result = measure(args.host, args.session, args.transcript, limit)
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 3 if result["state"] == "rotate_now" else 0


if __name__ == "__main__":
    sys.exit(main())
