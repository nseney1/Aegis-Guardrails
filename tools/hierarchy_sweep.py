#!/usr/bin/env python3
"""Wake every session with unread mail across the registered initiatives, then report what happened.

A published message reaches nobody until a turn starts, and starting each turn by hand made root a
bottleneck. Root runs this at task boundaries. It goes through active initiatives in the owner's
priority order, wakes each endpoint that has unread mail and a current profile, and can repeat so a
conversation continues without anyone starting each turn.

It stops rather than guesses. A session past 60 active minutes, or one with no transcript to measure, is not woken. A
session that ignored its mail is not retried in the same sweep. Root's own queue and its time against
its 90 minutes are only reported, because jobs go through `tools/hierarchy_jobs.py` and only root can
rotate itself. This runs nothing on its own schedule, and a read here means what `delivery` says it
means: the adapter returned the message.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import Mailbox, endpoint_parts, read_json, require, safe_path  # noqa: E402
from hierarchy_meter import ROOT_LIMIT_SECONDS, measure  # noqa: E402
from hierarchy_wake import wake  # noqa: E402
from hierarchy_workspace import Store  # noqa: E402


MAX_ROUNDS = 100
NATIVE_HOST = "codex"
ERRORS = (ValueError, OSError, UnicodeError, RecursionError)


def profile_for(mailbox_root, endpoint, binding):
    stem = endpoint.replace("/", "%2F") + "-g%d.wake.json" % binding["generation"]
    path = Path(mailbox_root).parent / "profiles" / stem
    if not path.is_file():
        return None
    profile = read_json(path)
    return path if profile.get("session") == binding["session"] and profile.get("host") == binding["host"] else None


def wake_endpoint(initiative, name, summary, dry_run):
    binding = summary["binding"]
    row = {"initiative": initiative["id"], "endpoint": name}
    if binding is None:
        return {**row, "state": "no_profile", "unread_count": summary["unread_count"]}
    try:
        meter = measure(binding["host"], binding["session"])
    except ERRORS as exc:
        # Waking could carry a session past the active limit, and there is no way to tell here.
        return {**row, "state": "meter_error", "error": str(exc)[:512]}
    if meter["state"] == "rotate_now":
        return {**row, "state": "rotate_needed", "session": binding["session"], "active_seconds": meter["active_seconds"]}
    if binding["host"] == NATIVE_HOST:
        # Its app server hosts it, so a second process resuming it could race that. Root messages it instead.
        return {**row, "state": "message_thread", "session": binding["session"], "unread_count": summary["unread_count"],
                "meter_before": meter["state"], "active_seconds_before": meter["active_seconds"]}
    path = profile_for(initiative["mailbox_root"], name, binding)
    if path is None:
        return {**row, "state": "no_profile", "unread_count": summary["unread_count"]}
    if meter["state"] == "no_transcript":
        # Without a transcript its active time is unknown, so a wake could carry it past its limit.
        return {**row, "state": "time_unknown", "session": binding["session"], "unread_count": summary["unread_count"]}
    if dry_run:
        return {**row, "state": "would_wake", "unread": summary["unread"]}
    try:
        code, result = wake(Path(initiative["mailbox_root"]), initiative["delivery_dir"], name, str(path))
    except ERRORS + (subprocess.SubprocessError,) as exc:
        return {**row, "state": "refused", "error": str(exc)[:512]}
    return {**row, "wake_exit": code, "meter_before": meter["state"], "active_seconds_before": meter["active_seconds"],
            # A background wake can stop a session (the idle one before it, or its own turn), and the row is
            # what ROOT reads, so that stop and how the turn ended are carried too.
            **{key: result[key] for key in ("state", "wake_id", "read", "still_unread", "exit_code", "timed_out", "error",
                                            "background", "stopped_idle")
               if key in result}}


def summaries(initiative):
    mailbox = Mailbox(initiative["mailbox_root"])
    records = mailbox.messages()
    return ({name: mailbox.endpoint_delivery(initiative["delivery_dir"], name, records)[1]
             for name in sorted(mailbox.manifest["endpoints"])}, mailbox.open_job_requests(records))


def is_root(endpoint):
    return endpoint_parts(endpoint)[1] == "root"


def sweep_round(initiatives, rows, tried, broken, dry_run):
    """One pass in priority order. Returns how many turns it started."""
    woken = 0
    for initiative in initiatives:
        try:
            found, _ = summaries(initiative)
        except ERRORS as exc:
            if initiative["id"] not in broken:
                broken.add(initiative["id"])
                rows.append({"initiative": initiative["id"], "state": "mailbox_error", "error": str(exc)[:512]})
            continue
        for name, summary in found.items():
            # The attempt is keyed on the exact unread set: a session that left this mail unread
            # gets no second turn for it, while new mail is a new reason to wake.
            attempt = (initiative["id"], name, tuple(summary["unread"]))
            if not summary["unread_count"] or is_root(name) or attempt in tried:
                continue
            tried.add(attempt)
            row = wake_endpoint(initiative, name, summary, dry_run)
            rows.append(row)
            woken += "wake_exit" in row
    return woken


def root_time(binding):
    row = {"session": binding["session"], "host": binding["host"]}
    try:
        meter = measure(binding["host"], binding["session"], limit=ROOT_LIMIT_SECONDS)
    except ERRORS as exc:
        return {**row, "state": "meter_error", "error": str(exc)[:512]}
    return {**row, "state": meter["state"], "active_seconds": meter["active_seconds"], "limit": meter["limit"]}


def remaining(initiatives):
    """Described from the mailboxes as they are now, because a round's own view goes stale as turns publish."""
    still_unread, root_queue, root_sessions = [], [], {}
    for initiative in initiatives:
        try:
            found, jobs = summaries(initiative)
        except ERRORS:
            continue  # Already reported as a mailbox_error row.
        for name, summary in found.items():
            entry = {"initiative": initiative["id"], "endpoint": name, "unread_count": summary["unread_count"]}
            if is_root(name):
                opened = sum(1 for job in jobs if job["to"] == name)
                if opened or summary["unread_count"]:
                    root_queue.append({**entry, "open_jobs": opened})
                if summary["binding"]:
                    root_sessions[summary["binding"]["host"], summary["binding"]["session"]] = summary["binding"]
            elif summary["unread_count"]:
                still_unread.append(entry)
    return still_unread, root_queue, [root_time(binding) for binding in root_sessions.values()]


def run(store_path, rounds, chosen, dry_run):
    require(type(rounds) is int and 0 < rounds <= MAX_ROUNDS, "invalid rounds")
    ledger = Store(store_path).load()
    for identifier in chosen:
        ledger.initiative(identifier)
    initiatives = sorted((i for i in ledger.initiatives.values() if i["state"] == "active" and "mailbox_root" in i
                          and "delivery_dir" in i and (not chosen or i["id"] in chosen)),
                         key=lambda i: (i["priority"], i["id"]))
    rows, tried, broken = [], set(), set()
    completed = 0
    while completed < rounds and sweep_round(initiatives, rows, tried, broken, dry_run):
        completed += 1
    still_unread, root_queue, root_times = remaining(initiatives)
    rotate = [{key: row[key] for key in ("initiative", "endpoint", "session")}
              for row in rows if row["state"] == "rotate_needed"]
    quiet = not still_unread and not root_queue and not broken
    return (0 if quiet else 3), {"rounds": completed, "quiet": quiet, "rows": rows, "still_unread": still_unread,
                                 "root_queue": root_queue, "root_time": root_times, "rotate_needed": rotate}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--store", required=True, help="Absolute path to the workspace store")
    parser.add_argument("--rounds", type=int, default=1, help="Repeat while sessions are still being woken")
    parser.add_argument("--initiative", action="append", default=[], help="Only sweep this initiative; can repeat")
    parser.add_argument("--dry-run", action="store_true", help="Report what would happen; write and launch nothing")
    args = parser.parse_args(argv)
    try:
        safe_path(args.store)
        code, result = run(args.store, args.rounds, args.initiative, args.dry_run)
    except ERRORS as exc:
        code, result = 2, {"error": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
