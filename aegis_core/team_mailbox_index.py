"""Read-only mailbox index over the injected TA-1a mailbox and store.

The shadow default compares against the product mailbox, never a tools import.
This service registers no adapter and changes no legacy host-plan behavior.
Each instance serializes memo publication; separate instances share no cache.
"""
from copy import deepcopy
import hashlib
import json
from threading import RLock

from aegis_core.team_mailbox import Mailbox
from aegis_core.team_mailbox_primitives import (
    SLUG, matching, operation, require,
)
from aegis_core.team_mailbox_index_scan import Evidence, scan_history

__all__ = ["Index", "compare"]


class _InboxView:
    def __init__(self, mailbox, read):
        self.mailbox, self.read = mailbox, read

    def __getattr__(self, name):
        return getattr(self.mailbox, name)

    def messages(self):
        return self.read()


class Index:
    """Hash current store bytes before parsed reuse; return independent values.

    Unlike the keyed metadata optimization in the legacy tool, every core scan
    reads every record through the held store root. No path-stat observation is
    treated as authority. The retained parsed history is capped by the store's
    count and aggregate byte ceilings. Evidence has a separate bounded budget.
    """
    def __init__(self, mailbox, *, mode="shadow"):
        require(isinstance(mailbox, Mailbox))
        require(type(mode) is str and mode in ("shadow", "indexed"))
        self.mailbox, self._mode = mailbox, mode
        self._memo, self._evidence, self._guard = {}, Evidence(), RLock()
        self.content_changed, self.last_divergence = [], []
        self.last_reconciliation = None
        # A later matching scan cannot witness an earlier canonical read's
        # original bytes. Coalesce gaps until a successful verify reports them.
        self._coverage_loss = None

    @property
    def mode(self):
        return self._mode

    @property
    def calls(self):
        return self.mailbox.calls

    @property
    def store(self):
        return self.mailbox.store

    def __getattr__(self, name):
        return getattr(self.mailbox, name)

    def _scan(self, *, force=False):
        records, candidate = scan_history(self.mailbox, self._memo, self._evidence, force=force)
        self._memo = candidate
        self.content_changed = self._evidence.changes()
        return records

    def _read(self, read, canonical):
        value = read()
        self.last_divergence = []
        if self.mode == "shadow":
            expected = canonical()
            self.last_divergence = _differences(value, expected)
            if self.last_divergence:
                self.last_reconciliation = {"reason": "canonical_reconciliation", "baseline_unavailable": True}
                self._coverage_loss = {"kind": "verification_unavailable", "reason": "baseline_unavailable",
                                       "scope": "all_returned_records"}
                return deepcopy(expected)
        self.last_reconciliation = None
        return deepcopy(value)

    @operation(write=False)
    def messages(self):
        with self._guard:
            return self._read(self._scan, self.mailbox.messages)

    @operation(write=False)
    def get(self, message_id):
        matching(message_id, SLUG, "message id")
        records = self.messages()
        require(message_id in records)
        return records[message_id]

    @operation(write=False, envelope=True)
    def inbox(self, endpoint, *, include_briefs=False, limit=20, after=None):
        require(type(include_briefs) is bool)
        with self._guard:
            options = dict(include_briefs=include_briefs, limit=limit, after=after)
            view = _InboxView(self.mailbox, self._scan)
            return self._read(lambda: Mailbox.inbox(view, endpoint, **options),
                              lambda: self.mailbox.inbox(endpoint, **options))

    @operation(write=False)
    def verify(self):
        with self._guard:
            self._read(lambda: self._scan(force=True), self.mailbox.messages)
            changes = self._evidence.changes()
            if self._coverage_loss is not None:
                changes.append(deepcopy(self._coverage_loss))
            self.content_changed = deepcopy([row for row in changes if row["kind"] == "content_changed"])
            # Construct the report before acknowledging evidence. If this
            # verify reconciled again, it still lacks a current byte baseline.
            if self.last_reconciliation is None:
                self._evidence.acknowledge_all(self._memo)
                self._coverage_loss = None
            return changes

    def evidence_stats(self):
        with self._guard:
            return self._evidence.stats()


def _differences(left, right):
    result = []
    if left != right:
        result.append({"kind": "mailbox_index_divergence", "index_sha256": _fingerprint(left),
                       "pinned_sha256": _fingerprint(right)})
    if not _same_order(left, right):
        result.append({"kind": "mailbox_index_key_order"})
    return result


def _fingerprint(value):
    # Histories exceed the single-record encoder budget. Stream a digest rather
    # than allocating one aggregate serialization of already validated records.
    digest = hashlib.sha256()
    for chunk in json.JSONEncoder(sort_keys=True, ensure_ascii=True, allow_nan=False).iterencode(value):
        digest.update(chunk.encode("ascii"))
    return digest.hexdigest()


def _same_order(left, right):
    if type(left) is dict and type(right) is dict:
        return list(left) == list(right) and all(_same_order(left[key], right[key]) for key in left)
    if type(left) is list and type(right) is list:
        return len(left) == len(right) and all(_same_order(a, b) for a, b in zip(left, right))
    return type(left) not in (dict, list) and type(right) not in (dict, list)


def compare(mailbox, index):
    """Compare public read results; differences contain only fixed kinds/hashes."""
    require(isinstance(index, Index) and mailbox is index.mailbox)
    with index._guard:
        current = index.messages()
        differences = deepcopy(index.last_divergence)
        for item in _differences(current, mailbox.messages()):
            if item not in differences:
                differences.append(item)
        index.last_divergence = differences
        return deepcopy(index.last_divergence)
