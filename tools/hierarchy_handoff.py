#!/usr/bin/env python3
"""Hand off one or more endpoints to a new session with one command.

One front door can hold an endpoint in several mailbox roots, and rotating them by
hand took a checkpoint per root. This drafts each checkpoint from the record and
binds it. A failure on one entry is reported without hiding or blocking the others,
and running the same spec again leaves finished entries alone.

The caller asserts outgoing_stopped after verifying that the old session has really
stopped. That stays a claim, as it is for a hand-written checkpoint. Binding grants
no sender authority: each successor must still read its checkpoint and acknowledge
it through its own connection, so acknowledgments are not batched here.

A mailbox root inside a provisioned base whose team run wrote a host plan binds
only a successor on the host the plan assigns, and records the successor's session
beside the binding. Any other root keeps today's unchecked handoff.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import (Mailbox, cli_path, encoded, fields, publish_file, read_json, require, safe_path,  # noqa: E402
                               text, writer_lock)
import hierarchy_hosts  # noqa: E402
import hierarchy_roles  # noqa: E402


SPEC_SCHEMA = "aegis.hierarchy-handoff/v1"
MAX_ENTRIES = 256


def acknowledgment(binding):
    if binding["generation"] < 2:
        return None
    return {"endpoint": binding["endpoint"], "session": binding["session"], "generation": binding["generation"],
            "checkpoint_sha256": binding["checkpoint_sha256"]}


def host_plan(root):
    """(base, plan) when this root is the mailbox of a provisioned base, else (None, None)."""
    base = root.parent
    if not (base / "provision.json").is_file():
        return None, None
    setup = read_json(base / "provision.json")
    mailbox_root = setup.get("mailbox_root") if isinstance(setup, dict) else None
    # A copied or moved mailbox is not the base's own, so the base's plan does not speak for it.
    if not isinstance(mailbox_root, str) or os.path.realpath(mailbox_root) != os.path.realpath(root):
        return None, None
    return base, hierarchy_hosts.read_plan(base)


def planned_session(base, plan, mailbox, endpoint, spec, generation):
    """(path, record, already recorded) for the successor under the plan, or None when the plan does not cover it.

    Checked before binding, so a refusal leaves the entry unbound.
    """
    kind = mailbox.endpoint(endpoint).get("kind")
    scope = hierarchy_hosts.require_binding(plan, endpoint, spec["host"],
                                            hierarchy_roles.writer(hierarchy_roles.role(endpoint, kind)))
    if scope is None:
        return None
    stand_in = hierarchy_hosts.plan_host(plan, endpoint)[1]
    # A spec carries no start options, and add-role refuses background for a team run's Claude roles, so the start
    # mode is the host's team start (print or exec). add-role computes the same record when it profiles the successor.
    record = hierarchy_hosts.session_record(
        endpoint, hierarchy_roles.role_name(endpoint, kind), spec["host"],
        hierarchy_hosts.team_start_mode(spec["host"], stand_in), spec["session"], generation, stand_in, scope)
    path = hierarchy_hosts.session_record_path(base, endpoint, generation)
    return path, record, hierarchy_hosts.session_recorded(path, record)


def keep_record(planned):
    if planned is not None and not planned[2]:
        publish_file(planned[0], encoded(planned[1]) + b"\n")


def hand_off(spec, entry):
    fields(entry, {"root", "endpoint"}, {"completed_checks", "briefs", "evidence_dir", "delivery_dir", "kind"})
    root = safe_path(text(entry["root"], "root"))
    base, plan = host_plan(root)
    with writer_lock(root):
        mailbox = Mailbox(root)
        mailbox.endpoint(entry["endpoint"])
        if "kind" in entry:
            mailbox.require_kind(entry["endpoint"], entry["kind"])
        history = mailbox.bindings(entry["endpoint"])
        require(bool(history), "endpoint has no binding to replace: " + entry["endpoint"])
        current = history[-1]
        if current["host"] == spec["host"] and current["session"] == spec["session"]:
            # A re-run also finishes a record that an earlier run stopped before writing.
            if plan is not None:
                keep_record(planned_session(base, plan, mailbox, entry["endpoint"], spec, current["generation"]))
            return {"already_bound": True, "generation": current["generation"], "ready": mailbox.ready(current),
                    "checkpoint_sha256": current["checkpoint_sha256"], "acknowledge": acknowledgment(current)}
        planned = None
        if plan is not None:
            planned = planned_session(base, plan, mailbox, entry["endpoint"], spec, current["generation"] + 1)
        optional = {key: entry[key] for key in ("completed_checks", "briefs", "evidence_dir", "delivery_dir")
                    if key in entry}
        binding = mailbox.bind(mailbox.draft_handoff({
            "endpoint": entry["endpoint"], "host": spec["host"], "session": spec["session"],
            "outgoing_stopped": spec["outgoing_stopped"], **optional}))
        keep_record(planned)
    return {"generation": binding["generation"], "ready": binding["ready"],
            "checkpoint_sha256": binding["checkpoint_sha256"], "acknowledge": acknowledgment(binding)}


def run(path):
    spec = read_json(path)
    fields(spec, {"schema", "host", "session", "outgoing_stopped", "entries"})
    require(spec["schema"] == SPEC_SCHEMA, "unsupported handoff spec schema")
    require(spec["outgoing_stopped"] is True, "outgoing session must be stopped before replacement")
    text(spec["host"], "host", 128)
    text(spec["session"], "session", 256)
    require(isinstance(spec["entries"], list) and 0 < len(spec["entries"]) <= MAX_ENTRIES,
            "handoff spec requires entries")
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
