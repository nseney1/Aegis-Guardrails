"""Merge queue records, validation and pure state transitions.

Records retain their defining module for existing checkpoints. Transitions
consume the validated records and observations supplied by the queue service.
"""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import re

from aegis_core import human_gate, team_qualify
from aegis_core.merge_queue_types import (
    Completion, HostedResult, IssuedRecord, Landing, QueueEntry, QueueState, QueueStorage, Review,
)
from aegis_core.primitives import sanitize_display
from aegis_core.redaction import redact_command_secrets

__all__ = [
    "Completion", "HostedResult", "IssuedRecord", "Landing", "QueueEntry", "QueueState",
    "QueueStorage", "Review", "QueueRefused", "REFUSALS", "REQUIRED_LEGS", "MAX_ENTRIES",
    "MAX_RESULTS", "MAX_STATE_BYTES", "MAX_REPLAY_RESULTS", "MAX_REVIEWS", "MAX_PARENTS",
    "valid_oid", "valid_lane", "ready_landing", "validate_configuration", "validate_entry",
    "check_acyclic", "valid_result", "merge_result", "retained_result", "check_result_capacity",
    "validate_completion", "pin_ref", "validate_state", "apply_result", "apply_observed_health",
]

REQUIRED_LEGS = ("linux-3.12", "linux-3.9")
MAX_ENTRIES = 1024
MAX_RESULTS = 32
MAX_STATE_BYTES = 32 * 1024 * 1024
MAX_REPLAY_RESULTS = MAX_STATE_BYTES // 64
MAX_REVIEWS = 32
MAX_PARENTS = 32
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
    "archived_completion": "archived completion already records this commit; withdraw the pending entry with its expected head",
}
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_LANE = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")


class QueueRefused(ValueError):
    """Fixed input-free diagnostic; no transport or hostile text is echoed."""

    # Keep the qualified name used by callers of the original queue module.
    __module__ = "aegis_core.merge_queue"

    def __init__(self, code):
        super().__init__(REFUSALS[code])
        self.code = code
        self.next_action = {"actor": "custodian", "command": REFUSALS[code]}


def valid_oid(value):
    return type(value) is str and len(value) in (40, 64) and _OID.fullmatch(value) is not None


def _text(value, pattern, limit):
    if type(value) is not str or not 1 <= len(value) <= limit or not pattern.fullmatch(value):
        return False
    canonical = sanitize_display(value, max_len=None)
    return canonical == value and redact_command_secrets(canonical) == canonical


def valid_lane(value):
    return _text(value, _LANE, 63)


def ready_landing(value):
    return (type(value) is Landing and type(value.status) is str and value.status == "ready"
            and valid_lane(value.lane)
            and valid_oid(value.tip) and valid_oid(value.commit) and valid_oid(value.tree)
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


def validate_configuration(target, required_legs, entry_legs, capacity, max_entries, storage):
    if (type(target) is not str or not 1 <= len(target) <= 255
            or not human_gate.is_branch_name(target)
            or redact_command_secrets(sanitize_display(target, max_len=None)) != target
            or type(capacity) is not int or not 1 <= capacity <= max_entries):
        raise QueueRefused("invalid_request")
    try:
        required_legs, entry_legs = _legs(required_legs), _legs(entry_legs)
    except ValueError:
        raise QueueRefused("invalid_request") from None
    if not set(REQUIRED_LEGS) <= set(required_legs) or not set(entry_legs) <= set(required_legs):
        raise QueueRefused("invalid_request")
    if storage is not None and (type(storage) is not QueueStorage or
            any(not callable(f) for f in (storage.load, storage.save, storage.lane,
                                         storage.commit, storage.begin, storage.health))):
        raise QueueRefused("state_unavailable")
    return required_legs, entry_legs


def validate_entry(item):
    if (type(item) is not QueueEntry or not valid_lane(item.lane)
            or not _text(item.author, _LABEL, 128) or not valid_oid(item.head)
            or type(item.repair) is not bool or type(item.parents) is not tuple
            or len(item.parents) > MAX_PARENTS
            or any(not valid_lane(parent) or parent == item.lane for parent in item.parents)
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
                or not valid_oid(review.commit) or not valid_oid(review.tree)):
            raise QueueRefused("not_reviewed")
    if len({review.session for review in item.reviews}) != len(item.reviews):
        raise QueueRefused("not_reviewed")


def check_acyclic(item, entries):
    pending, visited = list(item.parents), set()
    while pending:
        lane = pending.pop()
        if lane == item.lane:
            raise QueueRefused("parent_cycle")
        if lane not in visited:
            visited.add(lane)
            if lane in entries:
                pending.extend(entries[lane].parents)


def valid_result(value):
    return (type(value) is HostedResult and valid_oid(value.commit) and type(value.passed) is bool
            and type(value.attempt) is int and 0 <= value.attempt < 2**63)


def merge_result(old, new):
    if old is None or new.attempt > old.attempt:
        return new
    if old.attempt > new.attempt or old.passed is False:
        return old
    return new


def retained_result(state, commit, result, observation, done):
    if result is not None and (not valid_result(result) or result.commit != commit):
        raise QueueRefused("state_unavailable")
    sources = [observation, done.result if done is not None else None]
    if state.health_commit == commit:
        sources.append(state.health_result)
    if state.issued is not None and state.issued.landing.commit == commit:
        sources.append(state.issued.result)
    if state.cleanup is not None and state.cleanup.landing.commit == commit:
        sources.append(state.cleanup.result)
    sources.extend(row for row in state.results if row.commit == commit)
    for source in sources:
        if source is not None:
            result = merge_result(result, source)
    return result


def check_result_capacity(state, commit):
    if (len(state.results) >= MAX_RESULTS and commit != state.health_commit
            and (state.issued is None or commit != state.issued.landing.commit)
            and (state.cleanup is None or commit != state.cleanup.landing.commit)
            and not any(row.commit == commit for row in state.results)):
        raise QueueRefused("state_capacity")


def validate_completion(value, target):
    if value is None:
        return None
    if (type(value) is not Completion or type(value.target) is not str or value.target != target
            or not ready_landing(value.landing) or value.landing.issuance == 0
            or type(value.entry) is not QueueEntry or value.entry.lane != value.landing.lane
            or (value.result is not None and
                (not valid_result(value.result) or value.result.commit != value.landing.commit))):
        raise QueueRefused("state_unavailable")
    try:
        validate_entry(value.entry)
    except ValueError:
        raise QueueRefused("state_unavailable") from None
    return value


def pin_ref(target, candidate):
    target = sha256(target.encode("utf-8")).hexdigest()
    return "refs/aegis/merge-queue/%s/%d-%s" % (target, candidate.issuance, candidate.commit)


def _record(value, target):
    if (type(value) is not IssuedRecord or type(value.ref) is not str or len(value.ref) > 240
            or not valid_oid(value.expected)):
        raise QueueRefused("state_unavailable")
    row = validate_completion(Completion(target, value.entry, value.landing, value.result), target)
    if value.ref != pin_ref(target, row.landing) or value.expected != row.landing.commit:
        raise QueueRefused("state_unavailable")
    return row


def validate_state(state, target, required, entry_legs, capacity):
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
            validate_entry(item)
    except ValueError:
        raise QueueRefused("state_unavailable") from None
    if len({item.lane for item in state.entries}) != len(state.entries):
        raise QueueRefused("state_unavailable")
    if (any(not valid_result(item) for item in state.results)
            or len({item.commit for item in state.results}) != len(state.results)):
        raise QueueRefused("state_unavailable")
    if state.health_commit is not None and not valid_oid(state.health_commit):
        raise QueueRefused("state_unavailable")
    if state.health_result is not None and (
            not valid_result(state.health_result) or state.health_result.commit != state.health_commit):
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


def apply_result(state, result, order):
    red, bad, good = state.red, state.red_order, state.green_order
    health = state.health_result
    if state.health_commit == result.commit:
        health = merge_result(health, result)
        result = health
    if result.passed and state.health_commit == result.commit:
        good = max(good, order)
        red, bad = False, min(bad, good)
    elif not result.passed and order >= good:
        bad, red = max(bad, order), True
    if health is not None and not health.passed:
        red = True
    return replace(state, red=red, red_order=bad, green_order=good, health_result=health)


def apply_observed_health(state, tip, result):
    if state.health_commit != tip:
        state = replace(state, health_commit=tip, health_order=state.serial + 1,
                        serial=state.serial + 1)
    state = replace(state, health_result=result,
                    reconciliation_required=len(state.results) > MAX_RESULTS)
    return apply_result(state, result, state.health_order) if result is not None else state
