#!/usr/bin/env python3
"""Wake every session with unread mail across the registered initiatives, then report what happened.

A published message reaches nobody until a turn starts, and starting each turn by hand made root a
bottleneck. Root runs this at task boundaries. It goes through active initiatives in the owner's
priority order, wakes each endpoint that has unread mail and a current profile, and can repeat so a
conversation continues without anyone starting each turn.

It stops rather than guesses. A session past 60 active minutes, or one with no transcript to measure, is not woken. A
session that ignored its mail is not retried in the same sweep, nor, with --durable, by a later one. Root's own queue and its time against
its 90 minutes are only reported, because jobs go through `tools/hierarchy_jobs.py` and only root can
rotate itself. An endpoint named with --skip is reported with its unread count and never woken. This runs nothing on its own schedule, and a read here means what `delivery` says it
means: the adapter returned the message.

Two more reports are judged from the mailbox's own files, with nothing kept between sweeps. `silent_roles`: an
orchestrator, lane or decider whose completed turn read work it owes an answer to and that has published nothing
since that turn began. Later receipt-only turns do not clear earlier unanswered work. `stalled_dispatches`: a lane that accepted a dispatch, has answered none of it, and has
no unread mail and no running turn, even when a manually started turn left no wake receipts, so no wake will come.
Neither changes `quiet`, which stays about mail.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import (MAX_DELIVERY_IDS, Mailbox, endpoint_parts, parse_time, read_json, require,  # noqa: E402
                               safe_path)
from hierarchy_meter import ROOT_LIMIT_SECONDS, measure  # noqa: E402
from hierarchy_wake import wake  # noqa: E402
from hierarchy_workspace import Store  # noqa: E402
from hierarchy_lifecycle import Lifecycle  # noqa: E402


MAX_ROUNDS = 100
NATIVE_HOST = "codex"
ERRORS = (ValueError, OSError, UnicodeError, RecursionError)
# Durable mode caps failed starts per generation, which also keeps a broken profile from filling the
# wake receipt ledger (MAX_RECORDS) with one failure per pass.
FAILED_START_LIMIT = 3
START_BACKOFF = timedelta(seconds=300)
# What each role owes an answer to: (sender role in its own team, message type). The Router acts through its own
# tool and publishes nothing by design, so it is absent, like every role not listed.
OWED = {"orchestrator": {("router", "info"), ("front-door", "info"), ("lane", "result"), ("lane", "review")},
        "lane": {("orchestrator", "dispatch")},
        "decider": {("orchestrator", "info")}}
FINISHED = {"exited", "timed_out"}


def profile_for(mailbox_root, endpoint, binding):
    stem = endpoint.replace("/", "%2F") + "-g%d.wake.json" % binding["generation"]
    path = Path(mailbox_root).parent / "profiles" / stem
    if not path.is_file():
        return None
    profile = read_json(path)
    return path if profile.get("session") == binding["session"] and profile.get("host") == binding["host"] else None


def covered(wake, pending):
    """The unread IDs a wake receipt stands for.

    wake() records only the oldest MAX_DELIVERY_IDS unread IDs. A capped receipt therefore also stands for every
    message still unread now that was published before the receipt: it was unread then too, because reads are
    never withdrawn, so that turn had it in its inbox. Without this, mail past the cap is never "given" and
    new mail behind 100 ignored messages could not be told apart from the old."""
    named = set(wake["message_ids"])
    if len(named) < MAX_DELIVERY_IDS:
        return named
    at = parse_time(wake["at"])
    return named | {identifier for identifier, published in pending.items() if parse_time(published) <= at}


def durable_hold(summary, now):
    """Why a durable sweep must not start a turn now, judged only from the mailbox's own wake receipts and marker."""
    generation = summary["binding"]["generation"]
    held = {"session": summary["binding"]["session"], "generation": generation, "unread_count": summary["unread_count"]}
    if summary["marker"].exists():
        # A turn may still be running, or one died holding it; only the owner or ROOT may clear it.
        return {"state": "wake_marker_held", "marker": str(summary["marker"]), **held}
    # The full unread set, not the capped summary list, so mail past the first 100 IDs is judged too.
    pending = summary["pending"]
    unread = set(pending)
    if not unread:
        # Read since the snapshot; wake() itself reports nothing_unread, and an empty set must not match old failures.
        return None
    current = [wake for wake in summary["wakes"] if wake["generation"] == generation]
    # A failure counts only for the exact mail now unread: new mail resets the cap and the backoff, and a failure
    # whose mail has since been read no longer holds anything.
    failures = [wake for wake in current if wake["state"] == "failed_to_start" and unread <= covered(wake, pending)]
    if failures:
        last = max(failures, key=lambda wake: parse_time(wake["at"]))["at"]
        counts = {"failed_starts": len(failures), "last_failed_at": last}
        if len(failures) >= FAILED_START_LIMIT:
            return {"state": "start_failed", **held, **counts}
        if now - parse_time(last) < START_BACKOFF:
            return {"state": "start_backoff", **held, **counts}
    # Only turns this binding was given count, so a successor gets one turn for the mail it inherited.
    failed = {wake["wake_id"] for wake in current if wake["state"] == "failed_to_start"}
    given = set()
    for wake in current:
        if wake["state"] == "started" and wake["wake_id"] not in failed:
            given |= covered(wake, pending)
    if unread <= given:
        return {"state": "ignored_mail", **held}
    return None


def wake_endpoint(initiative, name, summary, dry_run, durable=False):
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
    if durable:
        # Judged on receipts read now, not on the round's opening snapshot: an earlier endpoint's turn can run for
        # minutes, and another sweep may give this endpoint its turn meanwhile. A window remains between this
        # read and wake() claiming its marker, because wake() is pinned and does not apply the ignored-mail rule
        # under its own lock; this narrows the window to milliseconds instead of a whole round.
        try:
            summary = fresh_summary(initiative, name)
        except ERRORS as exc:
            return {**row, "state": "mailbox_error", "error": str(exc)[:512]}
        if summary["binding"] is None:
            return {**row, "state": "no_profile", "unread_count": summary["unread_count"]}
        fresh = summary["binding"]
        if (fresh["session"], fresh["generation"]) != (binding["session"], binding["generation"]):
            # A handoff landed after the snapshot: the meter, host and profile above were judged for the old
            # binding, so waking now would resume the wrong session. The next pass judges the new one.
            return {**row, "state": "binding_changed", "unread_count": summary["unread_count"]}
        held = durable_hold(summary, datetime.now(timezone.utc))
        if held is not None:
            return {**row, **held}
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


def endpoint_summary(mailbox, initiative, name, records, durable):
    summary = mailbox.endpoint_delivery(initiative["delivery_dir"], name, records)[1]
    if not durable:
        return summary
    # The summary has no generation on woken_unread and caps its IDs, so durable mode reads the receipts it came
    # from and the full unread set, each unread ID with when it was published.
    directory = initiative["delivery_dir"]
    reads = mailbox.delivery_receipts(directory, "reads", name, records)
    read = {identifier for receipt in reads for identifier in receipt["message_ids"]}
    pending = {record["message"]["message_id"]: record["message"]["created_at"] for record in records.values()
               if record["message"]["to"] == name and record["message"]["message_id"] not in read}
    return {**summary, "marker": mailbox.wake_marker(name), "pending": pending, "reads": reads,
            "wakes": mailbox.delivery_receipts(directory, "wakes", name, records)}


def summaries(initiative, durable=False):
    mailbox = Mailbox(initiative["mailbox_root"])
    records = mailbox.messages()
    found = {name: endpoint_summary(mailbox, initiative, name, records, durable)
             for name in sorted(mailbox.manifest["endpoints"])}
    return found, mailbox.open_job_requests(records), records


def fresh_summary(initiative, name):
    mailbox = Mailbox(initiative["mailbox_root"])
    return endpoint_summary(mailbox, initiative, name, mailbox.messages(), True)


def is_root(endpoint):
    return endpoint_parts(endpoint)[1] == "root"


def by_time(receipts):
    """Oldest first; the stable sort keeps write order between receipts stamped in the same instant."""
    return sorted(receipts, key=lambda receipt: parse_time(receipt["at"]))


def silent_role(name, summary, records):
    """Retain work read in completed turns until the endpoint publishes an answer.

    Later receipt-only turns cannot erase an earlier owed read. While the latest turn is unfinished, or its
    marker exists, the endpoint can still answer, so no silent hold is raised. Read windows retain the background
    launch rule: reads after the previous finish and up to this finish belong to this turn, even before its start
    receipt. Only a publication at or after an owed read answers that read; an earlier publication cannot answer
    work that the endpoint has not read yet.
    """
    owed = OWED.get(endpoint_parts(name)[1])
    binding = summary["binding"]
    if owed is None or binding is None or summary["marker"].exists():
        return None
    current = [wake for wake in summary["wakes"]
               if (wake["generation"], wake["session"]) == (binding["generation"], binding["session"])]
    started = by_time([wake for wake in current if wake["state"] == "started"])
    finished = {wake["wake_id"]: wake for wake in current if wake["state"] in FINISHED}
    if not started or started[-1]["wake_id"] not in finished:
        return None
    publications = [parse_time(record["message"]["created_at"]) for record in records.values()
                    if record["message"]["from"] == name]
    published = max(publications) if publications else None
    for start in started:
        finish = finished.get(start["wake_id"])
        if finish is None:
            continue
        opened, closed = parse_time(start["at"]), parse_time(finish["at"])
        earlier = [parse_time(wake["at"]) for wake in current
                   if wake["state"] in FINISHED and wake["wake_id"] != start["wake_id"] and parse_time(wake["at"]) <= opened]
        after = max(earlier) if earlier else None
        team = endpoint_parts(name)[0]
        work, first_read = [], None
        for receipt in summary["reads"]:
            at = parse_time(receipt["at"])
            if (receipt["session"], receipt["generation"]) != (start["session"], start["generation"]) or at > closed \
                    or (after is not None and at <= after) or (published is not None and at <= published):
                continue
            for identifier in receipt["message_ids"]:
                message = records[identifier]["message"]
                sender = endpoint_parts(message["from"])
                if sender[0] == team and (sender[1], message["type"]) in owed:
                    first_read = at if first_read is None else min(first_read, at)
                    work.append({"message_id": identifier, "type": message["type"], "from": message["from"]})
        # A refused publish writes nothing, so a role whose every answer was refused remains silent.
        if not work:
            continue
        return {"endpoint": name, "wake_id": start["wake_id"], "started_at": start["at"], "finished_at": finish["at"],
                "ended": finish["state"], "exit_code": finish.get("exit_code"), "read": work,
                "silent_since": first_read.isoformat(timespec="microseconds").replace("+00:00", "Z")}
    return None


def stalled_dispatch(name, summary, records):
    """The lane accepted a dispatch it has not answered, and nothing will wake it: no unread mail, no turn running,
    including turns started manually with no sweep receipt. A session that died after accepting gets no further
    wakes, so this cannot wait on a wake count. A result clears it; a running wake suspends it."""
    if endpoint_parts(name)[1] != "lane" or summary["unread_count"] or summary["marker"].exists():
        return None
    finished = by_time([wake for wake in summary["wakes"] if wake["state"] in FINISHED])
    last = finished[-1] if finished else None
    # The mailbox's own closed set: a result, a review or a completed ack answers a dispatch.
    closed, accepted = Mailbox.dispatch_history(records)
    waiting = sorted((ack for ack in accepted if ack["from"] == name and ack["in_reply_to"] not in closed),
                     key=lambda ack: (ack["created_at"], ack["message_id"]))
    if not waiting:
        return None
    return {"endpoint": name, "wake_id": last["wake_id"] if last else None,
            "finished_at": last["at"] if last else None,
            "dispatches": [{"dispatch": ack["in_reply_to"], "accepted": ack["message_id"],
                            "accepted_at": ack["created_at"]} for ack in waiting]}


def sweep_round(initiatives, rows, tried, broken, dry_run, durable=False, skip=frozenset()):
    """One pass in priority order. Returns how many turns it started."""
    woken = 0
    for initiative in initiatives:
        try:
            found = summaries(initiative, durable)[0]
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
            if name in skip:
                # The caller holds this endpoint (the loop does after repeated unrecorded start failures), so it
                # is reported with its mail and never woken, in any mode.
                rows.append({"initiative": initiative["id"], "endpoint": name, "state": "skipped",
                             "unread_count": summary["unread_count"]})
                continue
            row = wake_endpoint(initiative, name, summary, dry_run, durable)
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


def remaining(initiatives, broken=None, rows=None):
    """Described from the mailboxes as they are now, because a round's own view goes stale as turns publish."""
    still_unread, root_queue, root_sessions, silent, stalled = [], [], {}, [], []
    for initiative in initiatives:
        try:
            # Durable summaries carry the receipts and marker the silent and stalled checks read.
            found, jobs, records = summaries(initiative, durable=True)
            judged = {name: (silent_role(name, summary, records), stalled_dispatch(name, summary, records))
                      for name, summary in found.items()}
        except ERRORS as exc:
            if rows is not None and (broken is None or initiative["id"] not in broken):
                rows.append({"initiative": initiative["id"], "state": "mailbox_error", "error": str(exc)[:512]})
            if broken is not None:
                broken.add(initiative["id"])
            continue
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
            for held, into in zip(judged[name], (silent, stalled)):
                if held is not None:
                    into.append({"initiative": initiative["id"], **held})
    return still_unread, root_queue, [root_time(binding) for binding in root_sessions.values()], silent, stalled


def run(store_path, rounds, chosen, dry_run, lifecycle_path=None, *, durable=False, skip=()):
    require(type(rounds) is int and 0 < rounds <= MAX_ROUNDS, "invalid rounds")
    for endpoint in skip:
        endpoint_parts(endpoint)
    skip = frozenset(skip)
    ledger = Store(store_path).load()
    for identifier in chosen:
        ledger.initiative(identifier)
    initiatives = sorted((i for i in ledger.initiatives.values() if i["state"] == "active" and "mailbox_root" in i
                          and "delivery_dir" in i and (not chosen or i["id"] in chosen)),
                         key=lambda i: (i["priority"], i["id"]))
    rows, tried, broken = [], set(), set()
    lifecycle = {"state": "untracked", "work_complete": False, "coverage": "untracked", "execution_enabled": False}
    if lifecycle_path is not None:
        try:
            lifecycle = Lifecycle(lifecycle_path).status()
        except ERRORS + (TypeError, KeyError) as exc:
            lifecycle = {"state": "hold", "work_complete": False, "execution_enabled": False, "error": str(exc)}
            still_unread, root_queue, root_times, silent, stalled = remaining(initiatives, broken, rows)
            return 3, {"rounds": 0, "quiet": False, "mail_quiet": not still_unread and not root_queue and not broken,
                       "work_complete": False, "lifecycle": lifecycle, "rows": rows, "still_unread": still_unread,
                       "root_queue": root_queue, "root_time": root_times, "rotate_needed": [],
                       "silent_roles": silent, "stalled_dispatches": stalled}
    completed = 0
    while completed < rounds and sweep_round(initiatives, rows, tried, broken, dry_run, durable, skip):
        completed += 1
    still_unread, root_queue, root_times, silent, stalled = remaining(initiatives, broken, rows)
    rotate = [{key: row[key] for key in ("initiative", "endpoint", "session")}
              for row in rows if row["state"] == "rotate_needed"]
    mail_quiet = not still_unread and not root_queue and not broken
    if lifecycle_path is not None:
        try:
            lifecycle = Lifecycle(lifecycle_path).status()
        except ERRORS + (TypeError, KeyError) as exc:
            lifecycle = {"state": "hold", "work_complete": False, "execution_enabled": False, "error": str(exc)}
    quiet = mail_quiet and (lifecycle_path is None or lifecycle["work_complete"])
    return (0 if quiet else 3), {"rounds": completed, "quiet": quiet, "mail_quiet": mail_quiet,
                                 "work_complete": lifecycle["work_complete"], "lifecycle": lifecycle,
                                 "rows": rows, "still_unread": still_unread,
                                 "root_queue": root_queue, "root_time": root_times, "rotate_needed": rotate,
                                 "silent_roles": silent, "stalled_dispatches": stalled}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--store", required=True, help="Absolute path to the workspace store")
    parser.add_argument("--rounds", type=int, default=1, help="Repeat while sessions are still being woken")
    parser.add_argument("--initiative", action="append", default=[], help="Only sweep this initiative; can repeat")
    parser.add_argument("--dry-run", action="store_true", help="Report what would happen; write and launch nothing")
    parser.add_argument("--lifecycle", help="Read-only evidence ledger; its obligations remain distinct from mail quiet")
    parser.add_argument("--durable", action="store_true",
                        help="Across sweeps: no second turn for mail this generation ignored, never past a held wake "
                             "marker, and stop after 3 failed starts for the same unread mail with 300 s between "
                             "them")
    parser.add_argument("--skip", action="append", default=[], metavar="ENDPOINT",
                        help="Report this endpoint as skipped with its unread count and never wake it; can repeat")
    args = parser.parse_args(argv)
    try:
        safe_path(args.store)
        code, result = run(args.store, args.rounds, args.initiative, args.dry_run, args.lifecycle, durable=args.durable,
                           skip=args.skip)
    except ERRORS as exc:
        code, result = 2, {"error": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
