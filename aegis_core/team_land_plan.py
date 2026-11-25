"""Read-only order of supplied ready attempts for a landing plan.

The caller supplies typed attempt records and the resolved landing policy.
This module selects the newest attempt per lane, flags ambiguous supersession,
orders eligible guard lanes first, and keeps FIFO within each class. It does
not take a publication lease, issue a landing, or write a receipt.

Invariant: a newer attempt that is ineligible is not replaced by an older one.
A refusal raises a fixed code or returns a finding; storage is untouched
because nothing is written. Untrusted text is not echoed. A single-line field
that contains a line break is refused rather than joined.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from types import MappingProxyType

from aegis_core.primitives import sanitize_display
from aegis_core.redaction import redact_command_secrets

__all__ = [
    "SCHEMA", "REFUSALS", "MAX_RECORDS", "MAX_EVIDENCE", "ReadyAttempt", "Finding",
    "LandOrder", "LandPlanRefused", "order_ready",
]

SCHEMA = "aegis.team.land.plan/v1"
MAX_RECORDS = 256
MAX_EVIDENCE = 32
_MAX_POLICY_KEYS = 64
_MAX_ATTEMPT = 2**63
_STRATEGIES = ("combined-full", "batch", "direct")
_FIELDS = frozenset(("lane", "attempt", "ready_at", "target", "guard", "evidence", "head"))
_LINE_BREAKS = "\n\r\x00\v\f\u2028\u2029"
_LANE = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
_BRANCH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/-]{0,254}")
_OID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_RAISED = frozenset(("invalid_request", "policy_unavailable"))
_FINDING_REFUSALS = frozenset(("missing_evidence", "changed_target", "ambiguous_supersession"))
REFUSALS = MappingProxyType({
    "invalid_request": "landing plan request is malformed or oversized",
    "policy_unavailable": "landing plan requires a resolved landing policy",
    "missing_evidence": "ready attempt has no landing evidence",
    "changed_target": "ready attempt target does not match the landing policy",
    "ambiguous_supersession": "lane has no single newest ready attempt",
    "superseded": "older ready attempt is not the newest attempt for its lane",
})


class LandPlanRefused(ValueError):
    """Fixed refusal. The message and next action contain no supplied text."""

    def __init__(self, code):
        if code not in _RAISED:
            code = "invalid_request"
        reason = REFUSALS[code]
        super().__init__(reason)
        self.code = code
        self.refused = True
        self.reason = reason
        self.exit_code = 1
        self.next_action = {"actor": "owner", "command": reason}


def _shape_line(value, limit, pattern):
    """Reject before display work. Line breaks stay intact and are not joined."""
    if type(value) is not str or not 1 <= len(value) <= limit:
        return False
    if any(char in value for char in _LINE_BREAKS):
        return False
    return pattern.fullmatch(value) is not None


def _branch_shape(value):
    """Check the literal short local target spelling."""
    if not _shape_line(value, 255, _BRANCH):
        return False
    if value == "HEAD" or value.startswith("refs/"):
        return False
    if ".." in value or "//" in value or "/." in value or ".lock/" in value:
        return False
    return not value.endswith(("/", ".", ".lock"))


def _confirm_line(value, code):
    """Confirm that each transform leaves the bounded input intact."""
    canonical = sanitize_display(value, max_len=None)
    if type(canonical) is not str or canonical != value:
        raise LandPlanRefused(code)
    redacted = redact_command_secrets(canonical)
    if type(redacted) is not str or redacted != value:
        raise LandPlanRefused(code)


def _confirm_attempt(attempt):
    evidence = attempt.evidence
    if (type(evidence) is not list and type(evidence) is not tuple) or len(evidence) > MAX_EVIDENCE:
        raise LandPlanRefused("invalid_request")
    if (not _shape_line(attempt.lane, 63, _LANE) or not _branch_shape(attempt.target)
            or not _shape_line(attempt.head, 64, _OID)):
        raise LandPlanRefused("invalid_request")
    if (type(attempt.attempt) is not int or type(attempt.ready_at) is not int
            or not 0 <= attempt.attempt < _MAX_ATTEMPT or not 0 <= attempt.ready_at < _MAX_ATTEMPT
            or type(attempt.guard) is not bool):
        raise LandPlanRefused("invalid_request")
    evidence = tuple(evidence)
    for token in evidence:
        if not _shape_line(token, 128, _TOKEN):
            raise LandPlanRefused("invalid_request")
    _confirm_line(attempt.lane, "invalid_request")
    _confirm_line(attempt.target, "invalid_request")
    _confirm_line(attempt.head, "invalid_request")
    for token in evidence:
        _confirm_line(token, "invalid_request")
    return evidence


@dataclass(frozen=True)
class ReadyAttempt:
    """One supplied ready attempt. Construction rechecks every closed field."""

    lane: str
    attempt: int
    ready_at: int
    target: str
    guard: bool
    evidence: tuple
    head: str

    def __post_init__(self):
        object.__setattr__(self, "evidence", _confirm_attempt(self))


@dataclass(frozen=True)
class Finding:
    """A per-attempt flag. Lane and attempt were already closed single-line values."""

    code: str
    lane: str
    attempt: int

    @property
    def refused(self):
        return self.code in _FINDING_REFUSALS

    @property
    def reason(self):
        return REFUSALS[self.code]

    @property
    def next_action(self):
        return {"actor": "owner", "command": REFUSALS[self.code], "lane": self.lane,
                "attempt": self.attempt}


@dataclass(frozen=True)
class LandOrder:
    """Eligible attempts, guards first, FIFO by ready time then input order."""

    schema: str
    target: str
    strategy: str
    batch_max: int
    order: tuple
    findings: tuple

    @property
    def ambiguous_lanes(self):
        return tuple(dict.fromkeys(
            item.lane for item in self.findings if item.code == "ambiguous_supersession"))


def _shaped_policy(policy):
    if type(policy) is not dict or len(policy) > _MAX_POLICY_KEYS:
        raise LandPlanRefused("policy_unavailable")
    if any(type(key) is not str for key in policy) or "target_branch" not in policy:
        raise LandPlanRefused("policy_unavailable")
    target = policy["target_branch"]
    if not _branch_shape(target):
        raise LandPlanRefused("policy_unavailable")
    strategy = policy.get("strategy", "combined-full")
    if type(strategy) is not str or strategy not in _STRATEGIES:
        raise LandPlanRefused("policy_unavailable")
    batch = policy.get("batch_max", 1)
    if type(batch) is not int or isinstance(batch, bool) or not 1 <= batch <= 1000000:
        raise LandPlanRefused("policy_unavailable")
    return target, strategy, batch


def _shaped_records(records):
    if type(records) is not list and type(records) is not tuple:
        raise LandPlanRefused("invalid_request")
    if len(records) > MAX_RECORDS:
        raise LandPlanRefused("invalid_request")
    shaped = []
    for record in records:
        if type(record) is ReadyAttempt:
            shaped.append(record)
            continue
        if type(record) is not dict or len(record) > 16:
            raise LandPlanRefused("invalid_request")
        if any(type(key) is not str for key in record) or set(record) != _FIELDS:
            raise LandPlanRefused("invalid_request")
        evidence = record["evidence"]
        if (type(evidence) is not list and type(evidence) is not tuple) or len(evidence) > MAX_EVIDENCE:
            raise LandPlanRefused("invalid_request")
        shaped.append(record)
    return tuple(shaped)


def _materialize(record):
    if type(record) is ReadyAttempt:
        if type(record.evidence) is not tuple:
            raise LandPlanRefused("invalid_request")
        _confirm_attempt(record)
        return record
    return ReadyAttempt(
        lane=record["lane"], attempt=record["attempt"], ready_at=record["ready_at"],
        target=record["target"], guard=record["guard"], evidence=record["evidence"],
        head=record["head"])


def _identity(attempt):
    return (attempt.attempt, attempt.ready_at, attempt.target, attempt.guard,
            attempt.evidence, attempt.head)


def _select(attempts, target):
    """Newest attempt only. An ineligible newest does not revive an older one."""
    grouped = {}
    for index, attempt in enumerate(attempts):
        grouped.setdefault(attempt.lane, []).append((index, attempt))
    chosen = []
    findings = set()
    for lane, group in grouped.items():
        newest_id = max(attempt.attempt for _, attempt in group)
        newest = [pair for pair in group if pair[1].attempt == newest_id]
        for _, attempt in group:
            if attempt.attempt != newest_id:
                findings.add(Finding("superseded", lane, attempt.attempt))
        if len({_identity(attempt) for _, attempt in newest}) > 1:
            findings.add(Finding("ambiguous_supersession", lane, newest_id))
            continue
        pick_index, pick = newest[0]
        if len(pick.evidence) == 0:
            findings.add(Finding("missing_evidence", lane, newest_id))
            continue
        if pick.target != target:
            findings.add(Finding("changed_target", lane, newest_id))
            continue
        chosen.append((pick_index, pick))
    return chosen, findings


def _ordered(chosen):
    ranked = sorted(chosen, key=lambda item: (0 if item[1].guard else 1, item[1].ready_at, item[0]))
    return tuple(item[1] for item in ranked)


def order_ready(records, policy):
    """Return the eligible order for one resolved landing policy.

    ``records`` is a list or tuple of closed attempt mappings. ``policy`` is the
    resolved ``policy.landing`` object. Guards that lack evidence or name a
    different target are not eligible and do not move ahead of other lanes.
    ``batch_max`` is reported for the issuer and does not drop lanes.
    """
    shaped = _shaped_records(records)
    target, strategy, batch = _shaped_policy(policy)
    _confirm_line(target, "policy_unavailable")
    attempts = tuple(_materialize(record) for record in shaped)
    chosen, findings = _select(attempts, target)
    reported = tuple(sorted(findings, key=lambda item: (item.lane, item.attempt, item.code)))
    return LandOrder(SCHEMA, target, strategy, batch, _ordered(chosen), reported)
