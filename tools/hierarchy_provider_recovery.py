#!/usr/bin/env python3
"""Read existing provider and workspace-job evidence without joining their identities."""
from __future__ import annotations

import argparse
from collections import OrderedDict
import json
import os
from pathlib import Path
import sys
from threading import Lock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_jobs import JOB_ID, recovery_status  # noqa: E402
from hierarchy_lifecycle import Lifecycle, provider_handle  # noqa: E402
from hierarchy_mailbox_index import MailboxIndex  # noqa: E402
from hierarchy_mailbox import Mailbox, SHA256, SLUG, matching, require  # noqa: E402
from hierarchy_workspace import Store  # noqa: E402


class _MailboxReader:
    """Keep binding and locking inside public read callables."""
    def __init__(self, mailbox):
        read_lock = Lock()
        with read_lock:
            index = MailboxIndex(mailbox, mode="shadow")

        def read_messages():
            with read_lock:
                return index.messages()

        def read_message(message_id):
            with read_lock:
                return index.get(message_id)

        def read_mode():
            with read_lock:
                return index.mode

        def read_divergence():
            with read_lock:
                return index.last_divergence

        def read_reconciliation():
            with read_lock:
                return index.last_reconciliation

        def read_changes():
            with read_lock:
                return index.content_changed

        self.read_messages = read_messages
        self.read_message = read_message
        self.read_mode = read_mode
        self.read_divergence = read_divergence
        self.read_reconciliation = read_reconciliation
        self.read_changes = read_changes

    def messages(self):
        return self.read_messages()

    def get(self, message_id):
        return self.read_message(message_id)

    @property
    def mode(self):
        return self.read_mode()

    @property
    def last_divergence(self):
        return self.read_divergence()

    @property
    def last_reconciliation(self):
        return self.read_reconciliation()

    @property
    def content_changed(self):
        return self.read_changes()


_MAILBOX_READERS = OrderedDict()
_MAILBOX_READERS_LOCK = Lock()


def mailbox_reader(mailbox):
    """Reuse locked shadow state only for this exact Mailbox authority."""
    # The retained index owns mailbox, keeping its identity live until eviction.
    key = (mailbox.root, os.getpid(), id(mailbox))
    with _MAILBOX_READERS_LOCK:
        reader = _MAILBOX_READERS.get(key)
        if reader is None:
            if len(_MAILBOX_READERS) >= 16:
                _MAILBOX_READERS.popitem(last=False)
            reader = _MailboxReader(mailbox)
            _MAILBOX_READERS[key] = reader
        _MAILBOX_READERS.move_to_end(key)
        return reader


PROVIDER_SCHEMA = "aegis.provider-recovery/v1"
JOB_SCHEMA = "aegis.workspace-job-recovery/v1"


def provider_status(lifecycle_root, request_id, request_sha256):
    """Project immutable canonical history; provider identities cannot name jobs."""
    matching(request_id, SLUG, "request id")
    matching(request_sha256, SHA256, "request sha256")
    _, state = Lifecycle(lifecycle_root).load()
    row = state["requests"].get(request_id)
    require(row is not None, "unknown canonical request: " + request_id)
    require(row["raw"]["sha256"] == request_sha256, "canonical request sha256 mismatch")
    association = row.get("association")
    original = None
    if association is not None:
        value = association["value"]
        original = {key: value[key] for key in ("original_actor", "original_generation", "original_cap_seconds",
                                                "authority_expires_at", "deadline")}
        association = {"value": value, "sha256": association["sha256"]}
    observations = row.get("observations", [])
    return {"schema": PROVIDER_SCHEMA, "read_only": True, "native_qualified": False,
            "request_id": request_id, "request_sha256": request_sha256,
            "owner": row["request"]["owner"], "source": row["request"]["source"],
            "original": original, "intent": row["intent"], "association": association,
            "provider_handle": provider_handle(row), "observation": observations[-1] if observations else None,
            "cancellation": row.get("cancellation"), "terminal": row["terminal"],
            "mapping": {"state": "unavailable",
                        "reason": "original provider-to-job admission binding is not available"},
            "next_action": "Retain the original intent; reconcile original job admission before correlation or settlement."}


def job_status(store_path, job_id, recipes_path=None):
    """Keep the existing job inventory distinct from external payload knowledge."""
    require(isinstance(job_id, str) and JOB_ID.fullmatch(job_id) is not None,
            "invalid job: " + str(job_id)[:128])
    initiative_id, message_id = job_id.split("/")
    _, inventory = recovery_status(store_path, chosen=(initiative_id,), recipes_path=recipes_path)
    row = next((item for item in inventory["jobs"] if item["job"] == job_id), None)
    require(row is not None, "unknown workspace job: " + job_id)

    # These are separate read observations, not an atomic cross-store snapshot.
    # The public recovery inventory owns orphan discovery; no request is fabricated here.
    initiative = Store(store_path).load().initiative(initiative_id)
    original_request = False
    if "mailbox_root" in initiative:
        try:
            record = mailbox_reader(Mailbox(initiative["mailbox_root"])).get(message_id)
            original_request = record is not None and record["message"]["type"] == "job_request"
        except (ValueError, OSError, UnicodeError):
            # Missing mailbox visibility remains explicit orphan/unknown evidence.
            # The original recovery row and its errors remain untouched below.
            original_request = False
    correlation = ({"state": "unbound", "reason": "no canonical provider binding was supplied by an accepted producer"}
                   if original_request else
                   {"state": "orphan", "reason": "original mailbox job_request is unavailable"})
    return {"schema": JOB_SCHEMA, "read_only": True, "native_qualified": False,
            "job": job_id, "workspace_seq": inventory["seq"], "capacity": inventory["capacity"],
            "capacity_scope": "ledger_only", "projection": row,
            "projection_scope": "existing_workspace_job_inventory", "payload_effect": "unknown",
            "correlation": correlation,
            "next_action": "Preserve original reservations and evidence; reconcile the original admission with its owner."}


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def main(argv=None):
    parser = JsonArgumentParser(description=__doc__)
    parser.add_argument("--lifecycle")
    parser.add_argument("--store")
    parser.add_argument("--recipes", help="Absolute path to root's trusted job recipe file")
    commands = parser.add_subparsers(dest="command", required=True)
    provider = commands.add_parser("provider")
    provider.add_argument("--request-id", required=True)
    provider.add_argument("--request-sha256", required=True)
    job = commands.add_parser("job")
    job.add_argument("--job", required=True)
    job.add_argument("--recipes", default=argparse.SUPPRESS, help="Absolute path to root's trusted job recipe file")
    try:
        args = parser.parse_args(argv)
        if args.command == "provider":
            require(args.lifecycle is not None, "--lifecycle is required")
            result = provider_status(args.lifecycle, args.request_id, args.request_sha256)
        else:
            require(args.store is not None, "--store is required")
            result = job_status(args.store, args.job, recipes_path=args.recipes)
        code = 0
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, RecursionError) as exc:
        code, result = 2, {"error": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
