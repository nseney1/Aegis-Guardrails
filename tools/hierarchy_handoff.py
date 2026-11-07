#!/usr/bin/env python3
"""Hand off one or more endpoints to a new session with one command.

One front door can hold an endpoint in several mailbox roots, and rotating them by
hand took a checkpoint per root. This drafts each checkpoint from the record and
binds it. After the stop preflight, a failure on one entry is reported without
hiding or blocking the others. Running the same spec again leaves finished entries alone.

For launcher-managed bindings, every entry's stop record, wake marker and session
process census are checked before any entry is processed. Other sessions retain
the caller's outgoing_stopped assertion. Binding grants no sender authority: each
successor must still read its checkpoint and acknowledge it through its own
connection, so acknowledgments are not batched here.

A mailbox root beside a team run's host plan binds only a successor on the host
the plan assigns, and refuses the entry when the plan is not that root's own. The
successor's session record comes from the add-role that builds its connection and
profile. Roots without a host plan keep today's unchecked host choice.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import (Mailbox, cli_path, fields, parse_time, read_bytes, read_json, require,  # noqa: E402
                               safe_path, strict_json, text, writer_lock)
import hierarchy_hosts  # noqa: E402
import hierarchy_launcher  # noqa: E402
import hierarchy_roles  # noqa: E402


SPEC_SCHEMA = "aegis.hierarchy-handoff/v1"
MAX_ENTRIES = 256


def acknowledgment(binding):
    if binding["generation"] < 2:
        return None
    return {"endpoint": binding["endpoint"], "session": binding["session"], "generation": binding["generation"],
            "checkpoint_sha256": binding["checkpoint_sha256"]}


def host_plan(root):
    """The host plan this root's handoffs answer to, or None when its base has none."""
    base = root.parent
    path = base / hierarchy_hosts.PLAN_FILE
    if not path.exists() and not path.is_symlink():
        return None
    record = base / "provision.json"
    setup = read_json(record) if record.is_file() else None
    mailbox_root = setup.get("mailbox_root") if isinstance(setup, dict) else None
    # A plan sits here, so it is never ignored: either the base's provision speaks for this root, or the entry is
    # refused. samefile, because two spellings of one folder must not count as two mailboxes.
    require(isinstance(mailbox_root, str) and os.path.isdir(mailbox_root) and os.path.samefile(mailbox_root, root),
            "host plan %s does not cover mailbox %s: its base's provision.json does not name that mailbox" % (path, root))
    return hierarchy_hosts.base_plan(base, setup.get("initiative"))


def check_successor(plan, mailbox, endpoint, spec):
    """Before binding, so a refusal leaves the entry unbound."""
    kind = mailbox.endpoint(endpoint).get("kind")
    hierarchy_hosts.require_binding(plan, endpoint, spec["host"],
                                    hierarchy_roles.writer(hierarchy_roles.role(endpoint, kind)))


def check_successor_record(base, endpoint, generation, spec):
    """A record already on file for the generation this handoff binds must be this successor's, or add-role would later
    find the binding and its record disagreeing."""
    path = hierarchy_hosts.session_record_path(base, endpoint, generation)
    if not path.exists() and not path.is_symlink():
        return
    found = read_json(path)
    require(isinstance(found, dict) and found.get("session") == spec["session"] and found.get("host_kind") == spec["host"],
            "session record for %s generation %d belongs to another session or host" % (endpoint, generation))


def stop_evidence(mailbox, current):
    """Read the launcher's records and matching processes; never stop or reconcile anything here."""
    base, endpoint = mailbox.root.parent, current["endpoint"]
    command = shlex.join(["hierarchy_launcher.py", "--base", str(base), "stop", "--endpoint", endpoint])
    try:
        folder = safe_path(base / "launches" / hierarchy_launcher.quoted(endpoint))
        if not folder.exists():
            return "caller_asserted"
        launches = hierarchy_launcher.Launches(str(base))
        require(os.path.samefile(launches.mailbox.root, mailbox.root),
                "launch records do not cover this mailbox")
        paths = launches.paths(endpoint)
        require(len(paths) <= hierarchy_launcher.MAX_RECORDS, "launch history exceeds record limit")
        records = []
        for path in paths:
            # Hash the exact bytes parsed, so the evidence cannot describe a different read of the file.
            raw = read_bytes(path)
            record = strict_json(raw.decode("utf-8"))
            require(isinstance(record, dict) and record.get("schema") == hierarchy_launcher.SCHEMA,
                    "invalid launch record: " + str(path))
            if all(record.get(key) == current[key] for key in ("endpoint", "session", "generation")):
                records.append((path, record, hashlib.sha256(raw).hexdigest()))
        starts = [row for row in records if row[1].get("action") == "start"]
        if not starts:
            return "caller_asserted"
        # The launcher orders its immutable records by their timestamp-prefixed filenames, including status().
        launch_path, launch, launch_hash = starts[-1]
        status_path, status, status_hash = records[-1]
        require(status_path > launch_path, "missing stop record after the latest launch")
        require(status.get("action") == "stop" and status.get("state") in ("stopped", "not_running"),
                "latest launch status is %s (%s); a stopped or not_running stop record is required"
                % (status.get("state"), status.get("action")))
        require(parse_time(status.get("at")) > parse_time(launch.get("at")),
                "stop record must be recorded after the latest launch")
        marker = mailbox.wake_marker(endpoint)
        require(not marker.exists() and not marker.is_symlink(), "wake marker is held: " + str(marker))
        # Unlike stop(), we signal nothing, so exclude no ancestors that could still be the outgoing writer.
        found = hierarchy_launcher.session_processes(current["session"], set())
        require(not found, "live process remains for session %s: %s"
                % (current["session"], ", ".join(str(pid) for pid, _ in found)))
        return {"launch": str(launch_path), "launch_sha256": launch_hash,
                "status": str(status_path), "status_sha256": status_hash, "state": status["state"]}
    except (ValueError, OSError, TypeError, KeyError, UnicodeError, RecursionError, subprocess.SubprocessError) as exc:
        raise ValueError("stop evidence for %s: %s; obtain evidence with: %s" % (endpoint, exc, command)) from exc


def preflight_stops(spec):
    """A missing launcher stop refuses the whole spec before locks, drafts or bindings are written."""
    for entry in spec["entries"]:
        if not isinstance(entry, dict) or not {"root", "endpoint"} <= entry.keys():
            continue
        try:
            root = safe_path(text(entry["root"], "root"))
            mailbox = Mailbox(root)
            history = mailbox.bindings(entry["endpoint"])
        except (ValueError, OSError, TypeError, UnicodeError, RecursionError):
            # Invalid entries still get their existing per-entry errors; they cannot bind a replacement.
            continue
        if history:
            current = history[-1]
            if current["host"] != spec["host"] or current["session"] != spec["session"]:
                stop_evidence(mailbox, current)


def hand_off(spec, entry):
    fields(entry, {"root", "endpoint"}, {"completed_checks", "briefs", "evidence_dir", "delivery_dir", "kind"})
    root = safe_path(text(entry["root"], "root"))
    plan = host_plan(root)
    with writer_lock(root):
        mailbox = Mailbox(root)
        mailbox.endpoint(entry["endpoint"])
        if "kind" in entry:
            mailbox.require_kind(entry["endpoint"], entry["kind"])
        history = mailbox.bindings(entry["endpoint"])
        require(bool(history), "endpoint has no binding to replace: " + entry["endpoint"])
        current = history[-1]
        # A re-run is checked too, so it reports a binding the plan does not allow even if an unchecked path made it.
        if plan is not None:
            check_successor(plan, mailbox, entry["endpoint"], spec)
        if current["host"] == spec["host"] and current["session"] == spec["session"]:
            return {"already_bound": True, "generation": current["generation"], "ready": mailbox.ready(current),
                    "checkpoint_sha256": current["checkpoint_sha256"], "acknowledge": acknowledgment(current),
                    "stop_evidence": "caller_asserted"}
        # Recheck under the bind/wake writer lock as well as in the whole-spec preflight.
        evidence = stop_evidence(mailbox, current)
        if plan is not None:
            # host_plan has shown the base's provision names this root, so its records sit beside it.
            check_successor_record(root.parent, entry["endpoint"], current["generation"] + 1, spec)
        optional = {key: entry[key] for key in ("completed_checks", "briefs", "evidence_dir", "delivery_dir")
                    if key in entry}
        binding = mailbox.bind(mailbox.draft_handoff({
            "endpoint": entry["endpoint"], "host": spec["host"], "session": spec["session"],
            "outgoing_stopped": spec["outgoing_stopped"], **optional}))
    return {"generation": binding["generation"], "ready": binding["ready"],
            "checkpoint_sha256": binding["checkpoint_sha256"], "acknowledge": acknowledgment(binding),
            "stop_evidence": evidence}


def run(path):
    spec = read_json(path)
    fields(spec, {"schema", "host", "session", "outgoing_stopped", "entries"})
    require(spec["schema"] == SPEC_SCHEMA, "unsupported handoff spec schema")
    require(spec["outgoing_stopped"] is True, "outgoing session must be stopped before replacement")
    text(spec["host"], "host", 128)
    text(spec["session"], "session", 256)
    require(isinstance(spec["entries"], list) and 0 < len(spec["entries"]) <= MAX_ENTRIES,
            "handoff spec requires entries")
    preflight_stops(spec)
    rows = []
    for entry in spec["entries"]:
        labels = {key: entry.get(key) for key in ("root", "endpoint")} if isinstance(entry, dict) else {}
        try:
            rows.append({**labels, "ok": True, **hand_off(spec, entry)})
        except (ValueError, OSError, TypeError, UnicodeError, RecursionError) as exc:
            rows.append({**labels, "ok": False, "error": str(exc)})
    return {"schema": "aegis.hierarchy-handoff-result/v1", "host": spec["host"], "session": spec["session"],
            "ok": all(row["ok"] for row in rows), "entries": rows,
            "next": "Each successor must read its checkpoint and acknowledge it through its own connection."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--spec", required=True, help="Absolute path to a strict JSON handoff spec")
    args = parser.parse_args(argv)
    try:
        result = run(cli_path(args.spec, "--spec"))
    except (ValueError, OSError, UnicodeError, RecursionError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 3


if __name__ == "__main__":
    sys.exit(main())
