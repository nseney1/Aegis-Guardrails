"""Exact-tree queue with durable issuance and authenticated restart state (Git ADR D9).

The owner-only port authenticates bounded state and durably CASes checkpoints and
archives. prepare observes scheduling; revalidate checkpoints exact pin intent,
creates/observes its shared ref, then issues a receipt for a separate publisher.
Unacknowledged intents abort through durable cleanup. Revision health is sticky;
unresolved results, receipts, cleanup and storage faults block publication.
Restart requires target authentication. Completed history uses indexed archives.
One service owns each repository/target. Native wiring/activation remain separate.
No direct filesystem writer or exemption carrier is used here. Ancestry reads
shared full OIDs. Reviews carry through GM-6 equivalence or the queue's clean merge.

Precondition: repair, parents, deadline, reviewer sessions and hosted attempts are
trusted caller input, authenticated by the owner-side adapter. Passing
model-controlled values here is a defect in that caller: repair=True bypasses
the target-red pause; parents control dependency eligibility; deadline controls
expiry; reviewer sessions establish independence; hosted attempts order health.
The queue validates their shape, not their provenance.
"""
from __future__ import annotations

from dataclasses import replace
from functools import wraps
from hashlib import sha256
import re
from threading import RLock
import time

from aegis_core import gitsafe, human_gate, team_git, team_qualify
from aegis_core.errors import AegisError
from aegis_core.merge_queue_types import (
    Completion, HostedResult, IssuedRecord, Landing, QueueEntry, QueueState, QueueStorage, Review,
)
from aegis_core.primitives import sanitize_display
from aegis_core.redaction import redact_command_secrets

__all__ = ["MergeQueue", "QueueEntry", "Review", "Landing", "QueueRefused", "REFUSALS",
           "REQUIRED_LEGS", "descriptor_supported", "QueueStorage", "QueueState",
           "HostedResult", "IssuedRecord", "Completion"]

REQUIRED_LEGS = ("linux-3.12", "linux-3.9")
MAX_ENTRIES = 1024
MAX_RESULTS = 32
MAX_STATE_BYTES = 32 * 1024 * 1024
MAX_REPLAY_RESULTS = MAX_STATE_BYTES // 64
MAX_REVIEWS = 32
MAX_PARENTS = 32
MAX_COMMIT_BYTES = 128 * 1024
REFUSALS = {
    "state_unavailable": "durable queue state is unavailable; reload before any effect",
    "state_capacity": "bounded queue state capacity reached; reconcile retained observations",
    "state_conflict": "authenticated queue observations conflict; reconcile without publishing",
    "issued_unresolved": "an issued publication needs settled reconciliation before any new effect",
    "target_red": "target is RED; only a qualified repair may publish",
    "policy_refused": "effective target policy refuses ordinary publication",
    "deadline_passed": "issued lane deadline passed; reconcile without publication",
    "invalid_request": "merge queue request is malformed or oversized",
    "unsupported_platform": "merge queue requires descriptor-relative custody support",
    "store_mismatch": "merge queue belongs to a different trusted repository",
    "not_reviewed": "lane requires two independent helpers-off ACCEPTs on its exact commit and tree",
    "not_qualified": "lane head tree lacks its required entry PASS",
    "request_conflict": "lane already has a different immutable queue entry",
    "queue_full": "merge queue capacity reached",
    "parent_cycle": "stack parents form a dependency cycle",
    "observation_failed": "trusted target or policy observation is unavailable or invalid",
    "git_failed": "merge queue Git operation failed",
    "tip_moved": "target moved during planning; rebuild and requalify the landing tree",
    "stale_candidate": "candidate no longer matches the serial queue head and target",
    "landing_unconfirmed": "exact candidate landing is unconfirmed; observe without retrying the effect",
    "already_integrated": "lane head is already an ancestor of the target; use a fresh pick lane to re-land reverted work",
}
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_LANE = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")


class QueueRefused(ValueError):
    """Fixed input-free diagnostic; no transport or hostile text is echoed."""

    def __init__(self, code):
        super().__init__(REFUSALS[code])
        self.code = code
        self.next_action = {"actor": "custodian", "command": REFUSALS[code]}


def descriptor_supported():
    return team_git.descriptor_support() and team_qualify.descriptor_supported()


def _oid(value):
    return type(value) is str and len(value) in (40, 64) and _OID.fullmatch(value) is not None


def _text(value, pattern, limit):
    if type(value) is not str or not 1 <= len(value) <= limit or not pattern.fullmatch(value):
        return False
    canonical = sanitize_display(value, max_len=None)
    return canonical == value and redact_command_secrets(canonical) == canonical


def _lane(value):
    return _text(value, _LANE, 63)


def _ready(value):
    return (type(value) is Landing and type(value.status) is str and value.status == "ready"
            and _lane(value.lane) and _oid(value.tip) and _oid(value.commit) and _oid(value.tree)
            and len(value.tip) == len(value.commit) == len(value.tree)
            and type(value.issuance) is int and 0 <= value.issuance < 2**63
            and type(value.missing_legs) is tuple and len(value.missing_legs) == 0)


def _legs(values):
    if type(values) is not tuple or not 1 <= len(values) <= team_qualify.MAX_LEGS:
        raise QueueRefused("invalid_request")
    for leg in values:
        team_qualify.qualification_ref("0" * 40, leg)
    if len(set(values)) != len(values):
        raise QueueRefused("invalid_request")
    return values


def _entry(item):
    if (type(item) is not QueueEntry or not _lane(item.lane)
            or not _text(item.author, _LABEL, 128) or not _oid(item.head)
            or type(item.repair) is not bool or type(item.parents) is not tuple
            or len(item.parents) > MAX_PARENTS
            or any(not _lane(parent) or parent == item.lane for parent in item.parents)
            or len(set(item.parents)) != len(item.parents)
            or (item.deadline is not None and (type(item.deadline) is not int
                or not 0 <= item.deadline <= 2**63 - 1))):
        raise QueueRefused("invalid_request")
    if type(item.reviews) is not tuple or not 2 <= len(item.reviews) <= MAX_REVIEWS:
        raise QueueRefused("not_reviewed")
    for review in item.reviews:
        if (type(review) is not Review or not _text(review.session, _LABEL, 128)
                or review.session == item.author or review.helpers_off is not True
                or type(review.verdict) is not str or review.verdict != "ACCEPT"
                or not _oid(review.commit) or not _oid(review.tree)):
            raise QueueRefused("not_reviewed")
    if len({review.session for review in item.reviews}) != len(item.reviews):
        raise QueueRefused("not_reviewed")


def _tree(store, commit):
    raw = store.object(commit, "commit", max_bytes=MAX_COMMIT_BYTES)
    if type(raw) is not bytes or len(raw) > MAX_COMMIT_BYTES:
        raise QueueRefused("git_failed")
    header, separator, _ = raw.partition(b"\n\n")
    trees = [line[5:] for line in header.split(b"\n") if line.startswith(b"tree ")]
    if not separator or len(trees) != 1:
        raise QueueRefused("git_failed")
    tree = trees[0].decode("ascii")
    if not _oid(tree) or len(tree) != len(commit):
        raise QueueRefused("git_failed")
    store.object(tree, "tree")
    return tree


def _ancestor(store, tip, head):
    # Public bounded ancestry reads only shared commits.
    with gitsafe.custody(scratch=store.scratch, stdout_limit=4096, stderr_limit=4096,
                         strict_lane=True, worktree_root=store.repo):
        result = gitsafe.run(["merge-base", "--is-ancestor", tip, head], store.repo)
    if result.returncode not in (0, 1):
        raise QueueRefused("git_failed")
    return result.returncode == 0


def _read(callback, *args):
    try:
        if not callable(callback):
            raise QueueRefused("observation_failed")
        return callback(*args)
    except Exception:
        # Adapter boundary: no exception payload crosses into the broker.
        raise QueueRefused("observation_failed") from None



def _result(value):
    return (type(value) is HostedResult and _oid(value.commit) and type(value.passed) is bool
            and type(value.attempt) is int and 0 <= value.attempt < 2**63)


def _merged_result(old, new):
    if old is None or new.attempt > old.attempt:
        return new
    if old.attempt > new.attempt or old.passed is False:
        return old
    return new


def _storage_call(function, *args):
    try:
        return function(*args)
    except Exception:
        # This is the external authenticated storage boundary, not a retry.
        raise QueueRefused("state_unavailable") from None


def _completion(value, target):
    if value is None:
        return None
    if (type(value) is not Completion or type(value.target) is not str or value.target != target
            or not _ready(value.landing) or value.landing.issuance == 0
            or type(value.entry) is not QueueEntry or value.entry.lane != value.landing.lane
            or (value.result is not None and
                (not _result(value.result) or value.result.commit != value.landing.commit))):
        raise QueueRefused("state_unavailable")
    try:
        _entry(value.entry)
    except ValueError:
        raise QueueRefused("state_unavailable") from None
    return value


def _pin_ref(target, candidate):
    target = sha256(target.encode("utf-8")).hexdigest()
    return "refs/aegis/merge-queue/%s/%d-%s" % (target, candidate.issuance, candidate.commit)


def _record(value, target):
    if (type(value) is not IssuedRecord or type(value.ref) is not str or len(value.ref) > 240
            or not _oid(value.expected)):
        raise QueueRefused("state_unavailable")
    row = _completion(Completion(target, value.entry, value.landing, value.result), target)
    if value.ref != _pin_ref(target, row.landing) or value.expected != row.landing.commit:
        raise QueueRefused("state_unavailable")
    return row


def _validate_state(state, target, required, entry_legs, capacity):
    if (type(state) is not QueueState or type(state.target) is not str or state.target != target
            or type(state.required_legs) is not tuple or state.required_legs != required
            or type(state.entry_legs) is not tuple or state.entry_legs != entry_legs
            or type(state.entries) is not tuple or len(state.entries) > capacity
            or type(state.results) is not tuple
            or type(state.red) is not bool or type(state.reconciliation_required) is not bool):
        raise QueueRefused("state_unavailable")
    # Hard recovery bounds precede validation sets/dicts; nominal admission
    # capacity must never make authenticated recovery checkpoints unloadable.
    if len(state.results) > MAX_REPLAY_RESULTS:
        raise QueueRefused("state_capacity")
    numbers = (state.health_order, state.red_order, state.green_order, state.serial, state.generation)
    if any(type(n) is not int or not 0 <= n < 2**63 for n in numbers):
        raise QueueRefused("state_unavailable")
    if max(numbers[:3]) > state.serial:
        raise QueueRefused("state_unavailable")
    if state.red_order > state.green_order and not state.red:
        raise QueueRefused("state_unavailable")
    try:
        for item in state.entries:
            _entry(item)
    except ValueError:
        raise QueueRefused("state_unavailable") from None
    if len({item.lane for item in state.entries}) != len(state.entries):
        raise QueueRefused("state_unavailable")
    if (any(not _result(item) for item in state.results)
            or len({item.commit for item in state.results}) != len(state.results)):
        raise QueueRefused("state_unavailable")
    if state.health_commit is not None and not _oid(state.health_commit):
        raise QueueRefused("state_unavailable")
    if state.health_result is not None and (
            not _result(state.health_result) or state.health_result.commit != state.health_commit):
        raise QueueRefused("state_unavailable")
    if (state.health_commit is not None and state.health_order == 0
            or state.health_result is not None and not state.health_result.passed
            and state.health_order >= state.green_order and not state.red):
        raise QueueRefused("state_unavailable")
    for record, cleanup in ((state.issued, False), (state.cleanup, True)):
        if record is None:
            continue
        row = _record(record, target)
        if row.landing.issuance > state.serial:
            raise QueueRefused("state_unavailable")
        if not cleanup and (record.resolution is not None or row.entry not in state.entries):
            raise QueueRefused("state_unavailable")
        if cleanup and (state.issued is not None or type(record.resolution) is not str
                or record.resolution not in ("issuing", "aborted", "done", "not_applied", "released")):
            raise QueueRefused("state_unavailable")
    return replace(state, reconciliation_required=True) if len(state.results) > MAX_RESULTS else state


def _apply_result(state, result, order):
    red, bad, good = state.red, state.red_order, state.green_order
    health = state.health_result
    if state.health_commit == result.commit:
        health = _merged_result(health, result)
        result = health
    if result.passed and state.health_commit == result.commit:
        good = max(good, order)
        red, bad = False, min(bad, good)
    elif not result.passed and order >= good:
        bad, red = max(bad, order), True
    if health is not None and not health.passed:
        red = True
    return replace(state, red=red, red_order=bad, green_order=good, health_result=health)


def _operation(function):
    @wraps(function)
    def wrapped(self, store, *args, **kwargs):
        if not descriptor_supported():
            raise QueueRefused("unsupported_platform")
        with self._lock:
            self._available()
            if type(store) is not team_git.GitStore:
                raise QueueRefused("git_failed")
            if self._repo is not None and store.repo != self._repo:
                raise QueueRefused("store_mismatch")
            try:
                return function(self, store, *args, **kwargs)
            except (AegisError, OSError, ValueError, RuntimeError) as exc:
                if self._guarded:
                    self._faulted = True
                if isinstance(exc, QueueRefused):
                    raise
                raise QueueRefused("git_failed") from None
    return wrapped


class MergeQueue:
    """Serial planning and durable issuance; publication remains a separate service."""

    def __init__(self, target, *, required_legs=REQUIRED_LEGS,
                 entry_legs=("linux-3.12",), capacity=MAX_ENTRIES, storage=None):
        if (type(target) is not str or not 1 <= len(target) <= 255
                or not human_gate.is_branch_name(target)
                or redact_command_secrets(sanitize_display(target, max_len=None)) != target
                or type(capacity) is not int or not 1 <= capacity <= MAX_ENTRIES):
            raise QueueRefused("invalid_request")
        try:
            self.required_legs, self.entry_legs = _legs(required_legs), _legs(entry_legs)
        except ValueError:
            raise QueueRefused("invalid_request") from None
        if not set(REQUIRED_LEGS) <= set(required_legs) or not set(entry_legs) <= set(required_legs):
            raise QueueRefused("invalid_request")
        if storage is not None and (type(storage) is not QueueStorage or
                any(not callable(f) for f in (storage.load, storage.save, storage.lane,
                                              storage.commit, storage.begin, storage.health))):
            raise QueueRefused("state_unavailable")
        self.target, self.capacity, self._storage = target, capacity, storage
        self._lock = RLock()
        self._repo = self._candidate = self._uncertain = None
        self._faulted = False
        self._guarded = False
        self._target_checked = False
        self._state = QueueState(target, required_legs, entry_legs)
        if storage is not None:
            saved = _storage_call(storage.load, target)
            if saved is not None:
                self._state = _validate_state(saved, target, required_legs, entry_legs, capacity)
                for item in self._state.entries:
                    if self._lane_done(item.lane) is not None:
                        raise QueueRefused("state_unavailable")

    @property
    def issued(self):
        """Read-only reconciliation record; never permission to repeat publication."""
        with self._lock:
            record = self._state.issued or self._state.cleanup
            if record is None and self._uncertain is not None:
                record = self._uncertain.issued or self._uncertain.cleanup
            return record.landing if record is not None else None

    def _save(self, state, completion=None):
        try:
            if self._state.generation >= 2**63 - 1 or state.serial >= 2**63:
                raise QueueRefused("state_capacity")
            state = replace(state, generation=self._state.generation + 1)
            self._begin()
            saved = _storage_call(self._storage.save, self.target, self._state.generation,
                                  state, completion)
            if saved is not True:
                raise QueueRefused("state_unavailable")
        except QueueRefused:
            self._uncertain, self._faulted = state, True
            raise
        self._state = state
        self._guarded, self._candidate = False, None

    def _begin(self, observation=None):
        if self._guarded:
            return
        self._candidate = None
        try:
            if _storage_call(self._storage.begin, self.target, self._state.generation,
                             observation, self._state.reconciliation_required) is not True:
                raise QueueRefused("state_unavailable")
        except QueueRefused:
            self._faulted = True
            raise
        self._guarded = True

    def _archive(self, function, key, kind, observation=None):
        try:
            row = _completion(_storage_call(function, self.target, key), self.target)
            if row is not None and key != (row.entry.lane if kind == "lane" else row.landing.commit):
                raise QueueRefused("state_unavailable")
            return row
        except QueueRefused:
            self._begin(observation)
            self._faulted = True
            raise

    def _lane_done(self, lane):
        return self._archive(self._storage.lane, lane, "lane")

    def _commit_done(self, commit, observation=None):
        return self._archive(self._storage.commit, commit, "commit", observation)

    def _retained(self, commit, observation=None, done=None):
        try:
            result = _storage_call(self._storage.health, self.target, commit)
            if result is not None and (not _result(result) or result.commit != commit):
                raise QueueRefused("state_unavailable")
            sources = [observation, done.result if done is not None else None]
            if self._state.health_commit == commit:
                sources.append(self._state.health_result)
            if self._state.issued is not None and self._state.issued.landing.commit == commit:
                sources.append(self._state.issued.result)
            if self._state.cleanup is not None and self._state.cleanup.landing.commit == commit:
                sources.append(self._state.cleanup.result)
            sources.extend(row for row in self._state.results if row.commit == commit)
            for source in sources:
                if source is not None:
                    result = _merged_result(result, source)
            return result
        except QueueRefused:
            self._begin()
            self._faulted = True
            raise

    def _entries(self):
        return {item.lane: item for item in self._state.entries}

    def _observed_health(self, state, tip):
        result = self._retained(tip)
        if state.health_commit != tip:
            state = replace(state, health_commit=tip, health_order=state.serial + 1,
                            serial=state.serial + 1)
        state = replace(state, health_result=result,
                        reconciliation_required=len(state.results) > MAX_RESULTS)
        return _apply_result(state, result, state.health_order) if result is not None else state

    def _candidate_red(self, commit):
        result = self._retained(commit, done=self._commit_done(commit))
        return result is not None and not result.passed

    def _result_capacity(self, commit):
        state = self._state
        if (len(state.results) >= MAX_RESULTS and commit != state.health_commit
                and (state.issued is None or commit != state.issued.landing.commit)
                and (state.cleanup is None or commit != state.cleanup.landing.commit)
                and not any(row.commit == commit for row in state.results)):
            raise QueueRefused("state_capacity")

    def _retire(self, store, state, record, resolution, completion=None):
        self._save(replace(state, issued=None, cleanup=replace(record, resolution=resolution)), completion)
        self._finish_cleanup(store)

    @_operation
    def _abort_intent(self, store):
        record = self._state.cleanup
        if record is not None and record.resolution in ("issuing", "aborted"):
            record = replace(record, result=self._retained(record.landing.commit))
            self._retire(store, self._state, record, "aborted")

    @_operation
    def _finish_cleanup(self, store):
        record = self._state.cleanup
        self._begin()
        # The exact persisted identity owns deletion across lost replies and
        # failed checkpoints; observation never needs candidate object bytes.
        with gitsafe.custody(scratch=store.scratch, stdout_limit=4096, stderr_limit=4096,
                             worktree_root=store.repo):
            ref = record.ref
            current = gitsafe.read_ref(store.repo, ref)
            if current is not None:
                if current != record.expected:
                    raise QueueRefused("state_conflict")
                gitsafe.update_ref(store.repo, ref, None, current, single_attempt=True)
        remaining = tuple(row for row in self._state.results if row.commit != record.expected)
        self._save(replace(self._state, cleanup=None, results=remaining,
                           reconciliation_required=len(remaining) > MAX_RESULTS))

    @_operation
    def enqueue(self, store, item):
        """Admit bounded pending work; archived IDs remain immutable and reserved."""
        _entry(item)
        entries = self._entries()
        done = self._lane_done(item.lane)
        previous = entries.get(item.lane) or (done.entry if done is not None else None)
        if previous is not None:
            if previous != item:
                raise QueueRefused("request_conflict")
            return "already"
        if len(entries) >= self.capacity:
            raise QueueRefused("queue_full")
        self._acyclic(item, entries)
        tree = _tree(store, item.head)
        equivalent = {item.head}
        for review in item.reviews:
            if review.tree != tree:
                raise QueueRefused("not_reviewed")
            if review.commit not in equivalent:
                if not team_qualify.approval_equivalent(store, review.commit, item.head, self.entry_legs):
                    raise QueueRefused("not_reviewed")
                equivalent.add(review.commit)
        if not team_qualify.qualified(store, tree, self.entry_legs):
            raise QueueRefused("not_qualified")
        entries[item.lane] = item
        self._save(replace(self._state, entries=tuple(entries.values())))
        self._repo, self._candidate = store.repo, None
        return "queued"

    def _acyclic(self, item, entries):
        pending, visited = list(item.parents), set()
        while pending:
            lane = pending.pop()
            if lane == item.lane:
                raise QueueRefused("parent_cycle")
            if lane not in visited:
                visited.add(lane)
                if lane in entries:
                    pending.extend(entries[lane].parents)

    def withdraw(self, lane, *, expected_head, store=None, read_target=None, read_outcome=None):
        """Issued work needs settled non-publication proof and an ancestry check."""
        if not _lane(lane) or not _oid(expected_head):
            raise QueueRefused("invalid_request")
        with self._lock:
            self._available()
            cleanup = self._state.cleanup
            if cleanup is not None and cleanup.entry.lane == lane:
                if cleanup.entry.head != expected_head:
                    raise QueueRefused("request_conflict")
                if store is None:
                    raise QueueRefused("issued_unresolved")
                if cleanup.resolution in ("issuing", "aborted"):
                    self._abort_intent(store)
                else:
                    if cleanup.resolution != "released":
                        raise QueueRefused("request_conflict")
                    self._finish_cleanup(store)
                    return "released"
            if self._state.issued is not None and self._state.issued.entry.lane == lane:
                if store is None or read_target is None or read_outcome is None:
                    raise QueueRefused("issued_unresolved")
                return self._withdraw_issued(store, expected_head, read_target, read_outcome)
            if self._lane_done(lane) is not None:
                raise QueueRefused("request_conflict")
            entries = self._entries()
            item = entries.get(lane)
            if item is None:
                return "already"
            if item.head != expected_head:
                raise QueueRefused("request_conflict")
            del entries[lane]
            self._save(replace(self._state, entries=tuple(entries.values())))
            return "released"

    @_operation
    def _withdraw_issued(self, store, expected_head, read_target, read_outcome):
        record = self._state.issued
        if record.entry.head != expected_head:
            raise QueueRefused("request_conflict")
        tip = self._tip(read_target)
        if (_read(read_outcome, record.landing) != "not_applied"
                or _ancestor(store, record.landing.commit, tip)):
            raise QueueRefused("landing_unconfirmed")
        entries = tuple(item for item in self._state.entries if item.lane != record.entry.lane)
        self._retire(store, replace(self._state, entries=entries), record, "released")
        self._candidate, self._target_checked = None, False
        return "released"

    def _available(self):
        if self._storage is None or self._faulted:
            raise QueueRefused("state_unavailable")

    def _head(self):
        known = {}
        for item in self._state.entries:
            if self._state.red and not item.repair:
                continue
            for parent in item.parents:
                if parent not in known:
                    known[parent] = self._lane_done(parent) is not None
            if all(known[parent] for parent in item.parents):
                return item
        return None

    def _tip(self, callback):
        tip = _read(callback, self.target)
        if not _oid(tip):
            raise QueueRefused("observation_failed")
        return tip

    def _mode(self, callback, tip, head):
        mode = _read(callback, self.target, tip, head)
        if type(mode) is not str or mode not in ("none", "review", "signature"):
            raise QueueRefused("observation_failed")
        return mode

    def _plan(self, store, item, tip, identity):
        if item.head == tip:
            raise QueueRefused("already_integrated")
        if _ancestor(store, tip, item.head):
            return Landing("pending", item.lane, tip, item.head, _tree(store, item.head))
        if _ancestor(store, item.head, tip):
            raise QueueRefused("already_integrated")
        merged = team_git.plan_merge(store, tip, item.head)
        if merged.status == "conflict":
            return Landing("conflict", item.lane, tip)
        if merged.status != "clean" or not _oid(merged.tree):
            raise QueueRefused("git_failed")
        commit = team_git.commit_tested(store, merged.tree, (tip, item.head),
                                       "Merge qualified queue lane\n", identity)
        return Landing("pending", item.lane, tip, commit, merged.tree)

    @_operation
    def prepare(self, store, *, read_target, read_mode, identity, now=None):
        """Scheduling observations cannot erase issued records or grant another effect."""
        self._candidate = None
        state = self._state
        if state.issued is not None or state.cleanup is not None:
            record = state.issued or state.cleanup
            return replace(record.landing, status="reconciliation-required")
        if state.results:
            return Landing("unapplied-results")
        if state.reconciliation_required:
            return Landing("target-unobserved")
        if state.health_commit is None:
            return Landing("target-unobserved")
        if not state.entries:
            return Landing("empty")
        item = self._head()
        if item is None:
            return Landing("target-red" if state.red else "blocked-by-parent")
        if not self._target_checked:
            return Landing("target-unobserved", item.lane)
        now = time.time() if now is None else now
        if type(now) not in (int, float) or not 0 <= now <= 2**63 - 1:
            raise QueueRefused("invalid_request")
        if item.deadline is not None and now >= item.deadline:
            return Landing("deadline-passed", item.lane)
        tip = self._tip(read_target)
        mode = self._mode(read_mode, tip, item.head)
        if mode != "none":
            return Landing("awaiting-owner-" + mode, item.lane, tip)
        if tip != state.health_commit:
            return Landing("target-unobserved", item.lane, tip)
        candidate = self._plan(store, item, tip, identity)
        if candidate.status == "conflict":
            return candidate
        if self._commit_done(candidate.commit) is not None:
            raise QueueRefused("already_integrated")
        if self._candidate_red(candidate.commit):
            return replace(candidate, status="target-red")
        missing = tuple(leg for leg in self.required_legs
                        if not team_qualify.qualified(store, candidate.tree, (leg,)))
        if self._tip(read_target) != tip:
            raise QueueRefused("tip_moved")
        mode = self._mode(read_mode, tip, candidate.commit)
        if mode != "none":
            return Landing("awaiting-owner-" + mode, item.lane, tip)
        candidate = replace(candidate, status="pending" if missing else "ready", missing_legs=missing)
        self._candidate = candidate
        return candidate

    @_operation
    def revalidate(self, store, candidate, *, read_target, read_mode, identity, now=None):
        """Checkpoint pin intent, create/observe once, then issue for a separate publisher.

        Unknown replies require recovery; native publisher journal/custody is separate.
        """
        if self._state.issued is not None or self._state.cleanup is not None:
            raise QueueRefused("issued_unresolved")
        if not _ready(candidate) or candidate.issuance != 0:
            raise QueueRefused("stale_candidate")
        if self._candidate_red(candidate.commit):
            raise QueueRefused("target_red")
        if candidate != self._candidate:
            raise QueueRefused("stale_candidate")
        fresh = self.prepare(store, read_target=read_target, read_mode=read_mode, identity=identity, now=now)
        if fresh != candidate:
            raise QueueRefused("stale_candidate")
        if self._state.serial >= 2**63 - 1 or self._state.generation >= 2**63 - 2:
            raise QueueRefused("state_capacity")
        issued = replace(candidate, issuance=self._state.serial + 1)
        item = self._entries()[candidate.lane]
        record = IssuedRecord(item, issued, resolution="issuing",
                              ref=_pin_ref(self.target, issued), expected=issued.commit)
        self._save(replace(self._state, cleanup=record, serial=issued.issuance))
        self._begin()
        team_git.cas_fast_forward(store, record.ref, None, record.expected)
        if team_git.ref_oid(store, record.ref) != record.expected:
            raise QueueRefused("state_conflict")
        self._save(replace(self._state, cleanup=None, issued=replace(record, resolution=None)))
        return issued

    @_operation
    def check_issued(self, store, candidate, *, read_target, read_mode, now=None):
        """Read-only gate; native one-use journal/custody remains mandatory.

        True never authorizes retrying a pending/unknown publication intent.
        """
        record, state = self._state.issued, self._state
        if not _ready(candidate) or record is None or record.landing != candidate:
            raise QueueRefused("stale_candidate")
        try:
            checkpoint = _validate_state(_storage_call(self._storage.load, self.target), self.target,
                                         self.required_legs, self.entry_legs, self.capacity)
        except QueueRefused:
            self._begin()
            self._faulted = True
            raise
        if checkpoint.generation != state.generation or checkpoint.reconciliation_required:
            raise QueueRefused("issued_unresolved")
        if state.results or record.result is not None:
            raise QueueRefused("issued_unresolved")
        if self._candidate_red(candidate.commit):
            raise QueueRefused("target_red")
        if state.reconciliation_required or not self._target_checked or state.health_commit != candidate.tip:
            raise QueueRefused("observation_failed")
        if state.red and not record.entry.repair:
            raise QueueRefused("target_red")
        now = time.time() if now is None else now
        if type(now) not in (int, float) or not 0 <= now <= 2**63 - 1:
            raise QueueRefused("invalid_request")
        if record.entry.deadline is not None and now >= record.entry.deadline:
            raise QueueRefused("deadline_passed")
        if self._tip(read_target) != candidate.tip:
            raise QueueRefused("tip_moved")
        if self._mode(read_mode, candidate.tip, candidate.commit) != "none":
            raise QueueRefused("policy_refused")
        if not team_qualify.qualified(store, candidate.tree, self.required_legs):
            raise QueueRefused("not_qualified")
        if self._tip(read_target) != candidate.tip:
            raise QueueRefused("tip_moved")
        if self._mode(read_mode, candidate.tip, candidate.commit) != "none":
            raise QueueRefused("policy_refused")
        return True

    @_operation
    def observe_landed(self, store, candidate, *, read_target):
        """Reconcile a receipt; scheduling then needs fresh target authentication."""
        if not _ready(candidate) or candidate.issuance == 0:
            raise QueueRefused("stale_candidate")
        if self._state.cleanup is not None and self._state.cleanup.landing == candidate:
            if self._state.cleanup.resolution != "done":
                raise QueueRefused("stale_candidate")
            self._finish_cleanup(store)
            self._target_checked = False
            return "already"
        done = self._lane_done(candidate.lane)
        if done is not None:
            if done.landing != candidate:
                raise QueueRefused("stale_candidate")
            if self._state.reconciliation_required:
                tip = self._tip(read_target)
                if tip != candidate.commit and not _ancestor(store, candidate.commit, tip):
                    raise QueueRefused("landing_unconfirmed")
                self._save(self._observed_health(self._state, tip))
            self._target_checked = False
            return "already"
        record = self._state.issued
        if record is None or record.landing != candidate:
            raise QueueRefused("stale_candidate")
        tip = self._tip(read_target)
        if tip != candidate.commit and not _ancestor(store, candidate.commit, tip):
            raise QueueRefused("landing_unconfirmed")
        if _tree(store, candidate.commit) != candidate.tree:
            raise QueueRefused("landing_unconfirmed")
        result = self._retained(candidate.commit)
        entries = self._entries()
        del entries[candidate.lane]
        state = replace(self._state, entries=tuple(entries.values()), issued=None)
        state = self._observed_health(state, tip)
        if result is not None:
            state = _apply_result(state, result, candidate.issuance)
        self._target_checked = False
        self._retire(store, state, record, "done", Completion(self.target, record.entry, candidate, result))
        return "done"

    @_operation
    def reconcile_not_landed(self, store, candidate, *, read_target, read_outcome):
        """Require the publisher's authenticated settled not-applied result, never tip alone."""
        if not _ready(candidate) or candidate.issuance == 0:
            raise QueueRefused("stale_candidate")
        if self._state.cleanup is not None and self._state.cleanup.landing == candidate:
            if self._state.cleanup.resolution in ("issuing", "aborted"):
                if _read(read_outcome, candidate) != "not_applied":
                    raise QueueRefused("landing_unconfirmed")
                self._abort_intent(store)
                return "not_applied"
            if self._state.cleanup.resolution != "not_applied":
                raise QueueRefused("stale_candidate")
            self._finish_cleanup(store)
            return "not_applied"
        record = self._state.issued
        if record is None or record.landing != candidate:
            raise QueueRefused("stale_candidate")
        tip = self._tip(read_target)
        if (_read(read_outcome, candidate) != "not_applied"
                or _ancestor(store, candidate.commit, tip)):
            raise QueueRefused("landing_unconfirmed")
        if record.result is not None:
            raise QueueRefused("state_conflict")
        self._retire(store, self._state, record, "not_applied")
        if tip != candidate.tip:
            self._target_checked = False
        return "not_applied"

    def hosted_result(self, commit, *, passed, attempt=0):
        """Retain authenticated results in either order; same-attempt RED wins.

        Only higher-attempt same-revision GREEN clears RED. Unknown subjects block.
        """
        result = HostedResult(commit, passed, attempt)
        if not _result(result):
            raise QueueRefused("invalid_request")
        with self._lock:
            self._available()
            done = self._commit_done(commit, result)
            if done is None:
                self._result_capacity(commit)
            self._begin(result)
            state = self._state
            chosen = self._retained(commit, result, done)
            state = replace(state, results=tuple(row for row in state.results if row.commit != commit))
            record = state.issued or state.cleanup
            if record is not None and record.landing.commit == commit:
                field = "issued" if state.issued is not None else "cleanup"
                state = replace(state, **{field: replace(record, result=chosen)})
                if state.health_commit == commit:
                    state = _apply_result(state, chosen, state.health_order)
                self._save(state, replace(done, result=chosen) if done is not None else None)
                return "pending"
            if done is not None:
                state = _apply_result(state, chosen, done.landing.issuance)
                self._save(state, replace(done, result=chosen))
                if (not self._state.red and commit != self._state.health_commit
                        and done.landing.issuance < self._state.green_order):
                    return "stale"
            elif state.health_commit == commit:
                self._save(_apply_result(state, chosen, state.health_order))
            else:
                pending = {row.commit: row for row in state.results}
                pending[commit] = chosen
                self._save(replace(state, results=tuple(pending.values())))
                return "unapplied"
            return "target-red" if self._state.red else "green"

    @_operation
    def restore_target(self, store, observation, *, read_target):
        """Restore the authenticated actual target; fresh queues start unobserved."""
        if not _result(observation):
            raise QueueRefused("invalid_request")
        try:
            tip = self._tip(read_target)
        except QueueRefused:
            self._begin(observation)
            raise
        if tip != observation.commit:
            self._result_capacity(observation.commit)
            self._begin(observation)
            raise QueueRefused("observation_failed")
        self._begin(observation)
        state, commit = self._state, observation.commit
        done = self._commit_done(commit)
        chosen = self._retained(commit, observation, done)
        if done is not None:
            order = done.landing.issuance
        elif state.issued is not None and state.issued.landing.commit == commit:
            order = state.issued.landing.issuance
        elif state.health_commit == commit:
            order = state.health_order
        else:
            order = state.serial + 1
        remaining = []
        for result in state.results:
            if result.commit == commit:
                chosen = _merged_result(chosen, result)
            elif not _ancestor(store, result.commit, commit):
                remaining.append(result)
        issued = state.issued
        if issued is not None and issued.landing.commit == commit:
            issued = replace(issued, result=chosen)
        state = replace(state, issued=issued, results=tuple(remaining), health_commit=commit,
                        health_result=chosen, health_order=order, serial=max(state.serial, order),
                        reconciliation_required=len(remaining) > MAX_RESULTS)
        state = _apply_result(state, chosen, order)
        self._save(state, replace(done, result=chosen) if done is not None else None)
        self._abort_intent(store)
        self._target_checked = True
        self._repo, self._candidate = store.repo, None
        return "target-red" if state.red else "green"

    @_operation
    def reconcile_result(self, store, commit, *, read_outcome, read_target):
        """Resolve an unrelated result only with authenticated settled non-publication proof."""
        if not _oid(commit):
            raise QueueRefused("invalid_request")
        rows = {row.commit: row for row in self._state.results}
        if commit not in rows:
            return "already"
        if _read(read_outcome, rows[commit]) != "not_applied":
            raise QueueRefused("landing_unconfirmed")
        tip = self._tip(read_target)
        if tip == commit or _ancestor(store, commit, tip):
            raise QueueRefused("landing_unconfirmed")
        del rows[commit]
        self._save(replace(self._state, results=tuple(rows.values())))
        return "not_applied"
