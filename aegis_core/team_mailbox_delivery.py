"""Delivery directories, receipts and evidence paths for Mailbox.

Mailbox inherits these methods, so the public names, refusal codes and return
values stay on the mailbox object. The confined store owns every descriptor.
This module never imports tools or launches processes.
"""
from __future__ import annotations

import re
import uuid

from aegis_core.team_mailbox_primitives import (
    render_mailbox_refusal,
    DELIVERY_MEANING, DELIVERY_RECEIPT, MAX_BYTES, MAX_DELIVERY_IDS, MAX_HISTORY_BYTES,
    MAX_RECORDS, SLUG, WAKE_STATES, MailboxRefusal, encoded, fields, integer, matching,
    operation, parse_time, record_types, require, safe_path, strict_json, strings, text,
)

__all__ = ["MailboxDelivery"]


class MailboxDelivery:
    """Delivery method family moved off Mailbox to restore module headroom."""

    @operation(write=False)
    def outside_mailbox(self, directory, label):
        """Derived files must never reach mailbox history, so overlap is refused in both directions.

        A directory above the root is unsafe too: a derived folder name can equal the root's own name.
        """
        text(label, "directory label")
        directory = safe_path(directory)
        require(directory != self.root and self.root not in directory.parents,
                label + " must be outside the mailbox root")
        require(directory not in self.root.parents, label + " must not contain the mailbox root")
        return directory

    @operation(write=False)
    def delivery_directory(self, directory):
        directory = self.outside_mailbox(directory, "delivery directory")
        with self.store.directory(directory, verification={}):
            require(not self.delivery_roots or directory in self.delivery_roots)
        return directory

    @operation(evidence=True)
    def evidence_directory(self, directory):
        directory = self.outside_mailbox(directory, "evidence directory")
        text(str(directory / ("0" * 64 + ".status")), "dirty evidence")
        require(bool(self.delivery_roots), reason="delivery_context_required")
        for delivery in self.delivery_roots:
            self.store.disjoint_directories(delivery, directory)
        with self.store.directory(directory.parent):
            pass
        return directory

    @staticmethod
    def _delivery_receipt(receipt, kind, endpoint, history, records):
        extra = {"wake_id", "state", "exit_code", "timed_out"} if kind == "wakes" else set()
        fields(receipt, {"schema", "endpoint", "host", "session", "generation", "at", "message_ids"}, extra)
        require(receipt["schema"] == DELIVERY_RECEIPT and receipt["endpoint"] == endpoint,
                "wrong receipt schema or endpoint")
        integer(receipt["generation"], "receipt generation")
        require(receipt["generation"] <= len(history) and all(
            history[receipt["generation"] - 1][key] == receipt[key] for key in ("host", "session")),
                "receipt does not match binding history")
        parse_time(receipt["at"])
        strings(receipt["message_ids"], "receipt message ids")
        for identifier in receipt["message_ids"]:
            record = records.get(identifier)
            require(record is not None and record["message"]["to"] == endpoint,
                    "receipt names a message not addressed to this endpoint")
        if kind == "wakes":
            matching(receipt.get("wake_id"), SLUG, "wake id")
            require(type(receipt.get("state")) is str and receipt["state"] in WAKE_STATES, "invalid wake state")
            require(receipt.get("exit_code") is None or type(receipt["exit_code"]) is int)
            if "timed_out" in receipt:
                require(type(receipt["timed_out"]) is bool)
        return receipt

    @operation(write=False)
    def delivery_receipts(self, directory, kind, endpoint, records):
        require(kind in ("reads", "wakes"))
        record_types(records)
        self.endpoint(endpoint)
        folder = safe_path(self.delivery_directory(directory) / kind / endpoint)
        self.calls.history_bytes[folder] = 0
        if not self.store.exists(folder):
            return []
        history = self.bindings(endpoint)
        receipts, total_bytes = [], 0
        for path in self.store.entries(folder):
            safe_path(path)
            if path.name.startswith("."):
                require(path.name == ".write.lock" or re.fullmatch(r"\.pending-[0-9a-f]{32}", path.name))
                continue
            require(path.suffix == ".json")
            require(len(receipts) < MAX_RECORDS, "delivery receipt history exceeds record limit")
            try:
                raw = self.store.read(path, limit=min(MAX_BYTES, MAX_HISTORY_BYTES - total_bytes))
                total_bytes += len(raw)
                receipts.append(self._delivery_receipt(strict_json(raw), kind, endpoint, history, records))
            except MailboxRefusal as error:
                render_mailbox_refusal(error, reraise=True)
            except (ValueError, KeyError, UnicodeError):
                raise MailboxRefusal("invalid_record") from None
        self.calls.history_bytes[folder] = total_bytes
        return receipts

    @operation(write=False)
    def require_receipt_room(self, directory, kind, endpoint, needed=1):
        require(kind in ("reads", "wakes"))
        integer(needed, "needed receipts", minimum=0, maximum=MAX_RECORDS)
        self.endpoint(endpoint)
        folder = safe_path(self.delivery_directory(directory) / kind / endpoint)
        self.store.require_room(folder, needed)

    @operation(write=True)
    def write_delivery_receipt(self, directory, kind, receipt):
        require(kind in ("reads", "wakes"))
        extra = {"wake_id", "state", "exit_code", "timed_out"} if kind == "wakes" else set()
        fields(receipt, {"endpoint", "host", "session", "generation", "message_ids"}, extra)
        self.endpoint(receipt["endpoint"])
        records = self.messages()
        self._delivery_receipt({**receipt, "schema": DELIVERY_RECEIPT, "at": self.timestamp()},
                               kind, receipt["endpoint"], self.bindings(receipt["endpoint"]), records)
        self.delivery_receipts(directory, kind, receipt["endpoint"], records)
        folder = safe_path(self.delivery_directory(directory) / kind / receipt["endpoint"])
        # record_read holds mailbox exclusion before this ledger lock. Past the limit the reader
        # would refuse the whole ledger, so a full one refuses here instead.
        with self.store.creation("delivery-ledger"), self.store.lock(folder, create=True):
            self.require_receipt_room(directory, kind, receipt["endpoint"])
            name = self.now().strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex + ".json"
            raw = encoded({"schema": DELIVERY_RECEIPT, "at": self.timestamp(), **receipt}) + b"\n"
            self.store.admit(folder / name, raw, self.calls.history_bytes[folder], MAX_HISTORY_BYTES)
            self.store.publish(folder / name, raw)

    @operation(write=True)
    def record_read(self, directory, sender, message_ids):
        """Record what the adapter returned to this connection, never what the session did with it."""
        # The delivered page's binding can retire during stdout flush. Fence it before even
        # deduplicating receipts, and retain exclusion through publication; historical receipts
        # remain valid, but cannot authorize a new receipt for a retired connection.
        # Only staleness is fenced here. A receipt records what was returned to the current binding, which an
        # unacknowledged successor is too; it authors nothing.
        with self.store.lock(self.root):
            strings(message_ids, "message ids")
            self.fence(sender, ready=False)
            endpoint = sender["from"]
            records = self.messages()
            seen = {identifier for receipt in self.delivery_receipts(directory, "reads", endpoint, records)
                    if receipt["generation"] == sender["binding_generation"] for identifier in receipt["message_ids"]}
            fresh = [identifier for identifier in message_ids if identifier not in seen]
            if fresh:
                self.write_delivery_receipt(directory, "reads", {
                    "endpoint": endpoint, "host": sender["host"], "session": sender["session"],
                    "generation": sender["binding_generation"], "message_ids": fresh})

    @operation(write=False)
    def endpoint_delivery(self, directory, endpoint, records):
        """Per-message rows and an endpoint summary; published, woken and read stay separate."""
        reads = self.delivery_receipts(directory, "reads", endpoint, records)
        wakes = self.delivery_receipts(directory, "wakes", endpoint, records)
        failed = {wake["wake_id"] for wake in wakes if wake["state"] == "failed_to_start"}
        read_at, read_by, woken_at = {}, {}, {}
        for receipt in reads:
            for identifier in receipt["message_ids"]:
                if identifier not in read_at:
                    read_at[identifier] = receipt["at"]
                    read_by[identifier] = {key: receipt[key] for key in ("host", "session", "generation")}
        for wake in wakes:
            if wake["state"] == "started" and wake["wake_id"] not in failed:
                for identifier in wake["message_ids"]:
                    woken_at.setdefault(identifier, wake["at"])
        incoming = sorted((r["message"] for r in records.values() if r["message"]["to"] == endpoint),
                          key=lambda message: (message["created_at"], message["message_id"]))
        rows = {}
        for message in incoming:
            identifier = message["message_id"]
            state = "read" if identifier in read_at else "woken" if identifier in woken_at else "published"
            rows[identifier] = {"message_id": identifier, "to": endpoint, "state": state,
                                "published_at": message["created_at"], "woken_at": woken_at.get(identifier),
                                "read_at": read_at.get(identifier), "read_by": read_by.get(identifier)}
        unread = [message["message_id"] for message in incoming if message["message_id"] not in read_at]
        history = self.bindings(endpoint)
        binding = None
        if history:
            binding = {"host": history[-1]["host"], "session": history[-1]["session"],
                       "generation": history[-1]["generation"], "ready": self.ready(history[-1])}
        last_wake = None
        if wakes:
            last_wake = {key: wakes[-1].get(key) for key in ("wake_id", "state", "at", "exit_code", "timed_out")}
        return rows, {"binding": binding, "published": len(incoming), "read": len(incoming) - len(unread),
                      "unread_count": len(unread), "unread": unread[:MAX_DELIVERY_IDS],
                      "woken_unread": [i for i in unread if i in woken_at][:MAX_DELIVERY_IDS],
                      "oldest_unread_at": rows[unread[0]]["published_at"] if unread else None,
                      "last_read_at": reads[-1]["at"] if reads else None, "last_wake": last_wake}

    @operation(write=False, envelope=True)
    def delivery(self, directory, endpoint=None, message_id=None):
        self.delivery_directory(directory)
        records = self.messages()
        answer = {"schema": "aegis.hierarchy-delivery/v1", "meaning": DELIVERY_MEANING}
        if message_id is not None:
            matching(message_id, SLUG, "message id")
            require(message_id in records, "unknown message: " + message_id)
            rows, _ = self.endpoint_delivery(directory, records[message_id]["message"]["to"], records)
            return {**answer, "message": rows[message_id]}
        if endpoint is not None:
            self.endpoint(endpoint)
        names = [endpoint] if endpoint is not None else sorted(self.manifest["endpoints"])
        return {**answer, "endpoints": {name: self.endpoint_delivery(directory, name, records)[1] for name in names}}
