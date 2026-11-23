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
from threading import RLock
import time

from aegis_core import gitsafe, merge_queue_model as model, team_git, team_qualify
from aegis_core.errors import AegisError
from aegis_core.merge_queue_model import (
    MAX_ENTRIES,
    MAX_PARENTS as MAX_PARENTS,
    MAX_REPLAY_RESULTS as MAX_REPLAY_RESULTS,
    MAX_RESULTS,
    MAX_REVIEWS as MAX_REVIEWS,
    MAX_STATE_BYTES as MAX_STATE_BYTES,
    REFUSALS, REQUIRED_LEGS, Completion, HostedResult, IssuedRecord, Landing, QueueEntry,
    QueueRefused, QueueState, QueueStorage, Review,
)

__all__ = ["MergeQueue", "QueueEntry", "Review", "Landing", "QueueRefused", "REFUSALS",
           "REQUIRED_LEGS", "descriptor_supported", "QueueStorage", "QueueState",
           "HostedResult", "IssuedRecord", "Completion"]

MAX_COMMIT_BYTES = 128 * 1024

# One handler per declared cleanup resolution, in declaration order. Recovery
# looks this table up and refuses state_unavailable for every other value,
# including a resolution that never passed validate_state.
_CLEANUP_RECOVERY = {
    "issuing": "abort",
    "aborted": "abort",
    "done": "acknowledge",
    "not_applied": "settle",
    "released": "release",
}


def _cleanup_handler(resolution):
    """Return the one recovery handler for a declared cleanup resolution."""
    if tuple(_CLEANUP_RECOVERY) != model.CLEANUP_RESOLUTIONS:
        raise QueueRefused("state_unavailable")
    if type(resolution) is not str:
        raise QueueRefused("state_unavailable")
    handler = _CLEANUP_RECOVERY.get(resolution)
    if type(handler) is not str:
        raise QueueRefused("state_unavailable")
    return handler


def descriptor_supported():
    return team_git.descriptor_support() and team_qualify.descriptor_supported()


def _tree(store, commit):
    raw = store.object(commit, "commit", max_bytes=MAX_COMMIT_BYTES)
    if type(raw) is not bytes or len(raw) > MAX_COMMIT_BYTES:
        raise QueueRefused("git_failed")
    header, separator, _ = raw.partition(b"\n\n")
    trees = [line[5:] for line in header.split(b"\n") if line.startswith(b"tree ")]
    if not separator or len(trees) != 1:
        raise QueueRefused("git_failed")
    tree = trees[0].decode("ascii")
    if not model.valid_oid(tree) or len(tree) != len(commit):
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


def _storage_call(function, *args):
    try:
        return function(*args)
    except Exception:
        # This is the external authenticated storage boundary, not a retry.
        raise QueueRefused("state_unavailable") from None


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
        self.required_legs, self.entry_legs = model.validate_configuration(
            target, required_legs, entry_legs, capacity, MAX_ENTRIES, storage)
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
                self._state = model.validate_state(saved, target, required_legs, entry_legs, capacity)
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
            row = model.validate_completion(_storage_call(function, self.target, key), self.target)
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
            return model.retained_result(self._state, commit, result, observation, done)
        except QueueRefused:
            self._begin()
            self._faulted = True
            raise

    def _entries(self):
        return {item.lane: item for item in self._state.entries}

    def _observed_health(self, state, tip):
        return model.apply_observed_health(state, tip, self._retained(tip))

    def _candidate_red(self, commit):
        result = self._retained(commit, done=self._commit_done(commit))
        return result is not None and not result.passed

    def _retire(self, store, state, record, resolution, completion=None):
        self._save(replace(state, issued=None, cleanup=replace(record, resolution=resolution)), completion)
        self._finish_cleanup(store)

    @_operation
    def _abort_intent(self, store):
        record = self._state.cleanup
        if record is None:
            return
        if _cleanup_handler(record.resolution) != "abort":
            return
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
        model.validate_entry(item)
        entries = self._entries()
        done = self._lane_done(item.lane)
        previous = entries.get(item.lane) or (done.entry if done is not None else None)
        if previous is not None:
            if previous != item:
                raise QueueRefused("request_conflict")
            return "already"
        if len(entries) >= self.capacity:
            raise QueueRefused("queue_full")
        model.check_acyclic(item, entries)
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

    def withdraw(self, lane, *, expected_head, store=None, read_target=None, read_outcome=None):
        """Issued work needs settled non-publication proof and an ancestry check."""
        if not model.valid_lane(lane) or not model.valid_oid(expected_head):
            raise QueueRefused("invalid_request")
        with self._lock:
            self._available()
            cleanup = self._state.cleanup
            if cleanup is not None and cleanup.entry.lane == lane:
                if cleanup.entry.head != expected_head:
                    raise QueueRefused("request_conflict")
                if store is None:
                    raise QueueRefused("issued_unresolved")
                handler = _cleanup_handler(cleanup.resolution)
                if handler == "abort":
                    self._abort_intent(store)
                elif handler == "release":
                    self._finish_cleanup(store)
                    return "released"
                else:
                    raise QueueRefused("request_conflict")
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
        if not model.valid_oid(tip):
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
        if merged.status != "clean" or not model.valid_oid(merged.tree):
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
        # One authenticated completion for this preparation. Revalidation and
        # issuance read the index again; this miss is only for the health check.
        done = self._commit_done(candidate.commit)
        if done is not None:
            # Withdraw this pending entry. The archived row is not the operand.
            raise QueueRefused("archived_completion", item)
        result = self._retained(candidate.commit, done=done)
        if result is not None and not result.passed:
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
        if not model.ready_landing(candidate) or candidate.issuance != 0:
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
                              ref=model.pin_ref(self.target, issued), expected=issued.commit)
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
        if not model.ready_landing(candidate) or record is None or record.landing != candidate:
            raise QueueRefused("stale_candidate")
        try:
            checkpoint = model.validate_state(
                _storage_call(self._storage.load, self.target), self.target,
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
        if not model.ready_landing(candidate) or candidate.issuance == 0:
            raise QueueRefused("stale_candidate")
        if self._state.cleanup is not None and self._state.cleanup.landing == candidate:
            if _cleanup_handler(self._state.cleanup.resolution) == "acknowledge":
                self._finish_cleanup(store)
                self._target_checked = False
                return "already"
            raise QueueRefused("stale_candidate")
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
            state = model.apply_result(state, result, candidate.issuance)
        self._target_checked = False
        self._retire(store, state, record, "done", Completion(self.target, record.entry, candidate, result))
        return "done"

    @_operation
    def reconcile_not_landed(self, store, candidate, *, read_target, read_outcome):
        """Require the publisher's authenticated settled not-applied result, never tip alone."""
        if not model.ready_landing(candidate) or candidate.issuance == 0:
            raise QueueRefused("stale_candidate")
        if self._state.cleanup is not None and self._state.cleanup.landing == candidate:
            handler = _cleanup_handler(self._state.cleanup.resolution)
            if handler == "abort":
                if _read(read_outcome, candidate) != "not_applied":
                    raise QueueRefused("landing_unconfirmed")
                self._abort_intent(store)
                return "not_applied"
            if handler == "settle":
                self._finish_cleanup(store)
                return "not_applied"
            raise QueueRefused("stale_candidate")
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
        if not model.valid_result(result):
            raise QueueRefused("invalid_request")
        with self._lock:
            self._available()
            done = self._commit_done(commit, result)
            if done is None:
                model.check_result_capacity(self._state, commit)
            self._begin(result)
            state = self._state
            chosen = self._retained(commit, result, done)
            state = replace(state, results=tuple(row for row in state.results if row.commit != commit))
            record = state.issued or state.cleanup
            if record is not None and record.landing.commit == commit:
                field = "issued" if state.issued is not None else "cleanup"
                state = replace(state, **{field: replace(record, result=chosen)})
                if state.health_commit == commit:
                    state = model.apply_result(state, chosen, state.health_order)
                self._save(state, replace(done, result=chosen) if done is not None else None)
                return "pending"
            if done is not None:
                state = model.apply_result(state, chosen, done.landing.issuance)
                self._save(state, replace(done, result=chosen))
                if (not self._state.red and commit != self._state.health_commit
                        and done.landing.issuance < self._state.green_order):
                    return "stale"
            elif state.health_commit == commit:
                self._save(model.apply_result(state, chosen, state.health_order))
            else:
                pending = {row.commit: row for row in state.results}
                pending[commit] = chosen
                self._save(replace(state, results=tuple(pending.values())))
                return "unapplied"
            return "target-red" if self._state.red else "green"

    @_operation
    def restore_target(self, store, observation, *, read_target):
        """Restore the authenticated actual target; fresh queues start unobserved."""
        if not model.valid_result(observation):
            raise QueueRefused("invalid_request")
        # Refuse an undeclared cleanup resolution before this restore writes health.
        if self._state.cleanup is not None:
            _cleanup_handler(self._state.cleanup.resolution)
        try:
            tip = self._tip(read_target)
        except QueueRefused:
            self._begin(observation)
            raise
        if tip != observation.commit:
            model.check_result_capacity(self._state, observation.commit)
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
                chosen = model.merge_result(chosen, result)
            elif not _ancestor(store, result.commit, commit):
                remaining.append(result)
        issued = state.issued
        if issued is not None and issued.landing.commit == commit:
            issued = replace(issued, result=chosen)
        state = replace(state, issued=issued, results=tuple(remaining), health_commit=commit,
                        health_result=chosen, health_order=order, serial=max(state.serial, order),
                        reconciliation_required=len(remaining) > MAX_RESULTS)
        state = model.apply_result(state, chosen, order)
        self._save(state, replace(done, result=chosen) if done is not None else None)
        self._abort_intent(store)
        self._target_checked = True
        self._repo, self._candidate = store.repo, None
        return "target-red" if state.red else "green"

    @_operation
    def reconcile_result(self, store, commit, *, read_outcome, read_target):
        """Resolve an unrelated result only with authenticated settled non-publication proof."""
        if not model.valid_oid(commit):
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
