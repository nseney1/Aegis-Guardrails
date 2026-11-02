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
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import Mailbox, fields, read_json, require, safe_path, text, writer_lock  # noqa: E402


SPEC_SCHEMA = "aegis.hierarchy-handoff/v1"
MAX_ENTRIES = 256


def acknowledgment(binding):
    if binding["generation"] < 2:
        return None
    return {"endpoint": binding["endpoint"], "session": binding["session"], "generation": binding["generation"],
            "checkpoint_sha256": binding["checkpoint_sha256"]}


def hand_off(spec, entry):
    fields(entry, {"root", "endpoint"}, {"completed_checks", "briefs", "evidence_dir", "delivery_dir"})
    root = safe_path(text(entry["root"], "root"))
    with writer_lock(root):
        mailbox = Mailbox(root)
        mailbox.endpoint(entry["endpoint"])
        history = mailbox.bindings(entry["endpoint"])
        require(bool(history), "endpoint has no binding to replace: " + entry["endpoint"])
        current = history[-1]
        if current["host"] == spec["host"] and current["session"] == spec["session"]:
            return {"already_bound": True, "generation": current["generation"], "ready": mailbox.ready(current),
                    "checkpoint_sha256": current["checkpoint_sha256"], "acknowledge": acknowledgment(current)}
        optional = {key: entry[key] for key in ("completed_checks", "briefs", "evidence_dir", "delivery_dir")
                    if key in entry}
        binding = mailbox.bind(mailbox.draft_handoff({
            "endpoint": entry["endpoint"], "host": spec["host"], "session": spec["session"],
            "outgoing_stopped": spec["outgoing_stopped"], **optional}))
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
        result = run(args.spec)
    except (ValueError, OSError, UnicodeError, RecursionError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 3


if __name__ == "__main__":
    sys.exit(main())
