"""Bind immutable review evidence and reduce the current checked votes."""
from __future__ import annotations

import hashlib
import json
import re
import threading
from copy import deepcopy
from dataclasses import dataclass, replace
from types import MappingProxyType

from aegis_core.diagnostic_messages import receipt_value
from aegis_core.primitives import envelope

__all__ = [
    "DEFAULT_POLICY",
    "EXIT_CODES",
    "GATE_NEXT",
    "NEXT",
    "REFUSALS",
    "ReviewLedger",
    "authorize_vote",
    "authorize_waiver",
    "bind_report",
    "notify_waiter",
    "release_hold",
    "repair_copy",
    "review_record",
    "served_identity",
]

_RECORD_SCHEMA = "aegis.team.review.record/v1"
_MAX_OBJECTS = 128
_MAX_ROUNDS = 32
_MAX_EVENTS = 4 * _MAX_ROUNDS
_MAX_SITES = 64
_MAX_FINDINGS = 64
_MAX_CONTROL_INCARNATION = 320
_MAX_ITEMS = 32
_MAX_KNOWN = 64
_MAX_UNCHANGED = 10000
_MAX_RULING = 200
_LENSES = frozenset(("gating", "advisory", "second_family"))
_LAUNCH_KEYS = ("family", "model", "host", "fallback", "lens", "state", "brief_seen")
_STATES = frozenset(("completed", "error", "timeout", "content_filter", "unavailable"))
_FALLBACK_REASONS = frozenset(("capacity", "content_filter", "timeout", "provider_refusal", "declared"))
_COVERS = frozenset(("cross_family", "cap", "both"))
_BREAKS = "\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029"
_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
# Match the served receipt grammar in model_served, including model punctuation.
_SERVED_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SERVED_MODEL = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_TREE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_CANONICAL_DISPOSITIONS = {
    b"VERDICT: ACCEPT": "accept",
    b"VERDICT: ACCEPT\n": "accept",
    b"VERDICT: REQUEST CHANGES": "request_changes",
    b"VERDICT: REQUEST CHANGES\n": "request_changes",
    b"VERDICT: FIX FIRST": "fix_first",
    b"VERDICT: FIX FIRST\n": "fix_first",
}
_REPORT_BREAK = re.compile(r"\r\n|[\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029]")
_MARKDOWN = re.compile(r"^(?:#{1,6}[ \t]+|[-+*][ \t]+|[0-9]{1,6}[.)][ \t]+)")
_CLAIM_LINE = re.compile(
    r'(?i)(?P<mark>\*{1,3}|_{1,3}|`{1,3}|")?(?P<label>verdict|checked-site)'
    r"(?(mark)(?:(?P=mark)\s*:|\s*:(?P=mark))|\s*:)\s*(?P<value>.*)\Z"
)
_VERDICT_LABEL = re.compile(r"(?i)(?<![^\W_])verdict(?![^\W_])")
_VERDICT_TERM = r"(?<![^\W_])(?:ACCEPT|INCOMPLETE|(?i:request[\W_]+changes|fix[\W_]+first))(?![^\W_])"
_BARE_VERDICT = re.compile(_VERDICT_TERM)
_VERDICT_WORDS = re.compile(_VERDICT_TERM, re.IGNORECASE)
_FIELD_VALUE = re.compile(r"(?:^|[:=：])(?:[^\w:=：]|_)*" + _VERDICT_TERM, re.IGNORECASE)
_CONTEXT_TERM = r"(?<![^\W_])(?:decision|outcome|recommendation)(?![^\W_])"
_CONTEXT_LABEL = re.compile(_CONTEXT_TERM, re.IGNORECASE)
_CONTEXT_FIELD = re.compile(
    r"^[\W_]*" + _CONTEXT_TERM + r"[\W_]*\Z|" + _CONTEXT_TERM + r"[\W_]*[:=：–—]",
    re.IGNORECASE,
)
_CONTEXT_VALUE = re.compile(_CONTEXT_TERM + r"\s+(?:is|was)\s+" + _VERDICT_TERM, re.IGNORECASE)
_VERDICT_VALUES = {
    "accept": "accept", "request changes": "request_changes", "fix first": "request_changes",
    "incomplete": "incomplete",
}
_REJECTION = re.compile(r"(?i)(?:request changes|fix first)(?:\Z|[ \t]*[.:;–—]|[ \t]+-[ \t]+)")
_SOURCE_LOCATION = re.compile(r"(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_-]+\.[A-Za-z0-9]+:[1-9][0-9]*")
_TABLE_HEADER = re.compile(r"(?i)\|\s*(?:field\s*\|\s*value|:?-+:?\s*\|\s*:?-+:?)\s*\|")
_FINDING = re.compile(r"(?i)^[*_]*\[?(p[0-3])\b[\]*_ \t]*(?:line[ \t]+([1-9][0-9]{0,6})(?![0-9]))?")

DEFAULT_POLICY = MappingProxyType({
    "max_report_bytes": 262144,
    "window_lines": 200,
    "require_cross_family": False,
    "review_cap": None,
    "mode": "full",
    "advisory_prereview": False,
    "second_family_reviewer": False,
    "content_filter_retries": 1,
})
REFUSALS = MappingProxyType({
    "invalid_input": "review input is missing or the wrong type",
    "malformed_report": "review report is not bounded text",
    "stale_report": "review report does not match the current tree, round or ruling",
    "limit_exceeded": "review report exceeds the configured bound",
    "unauthorized_waiver": "review observations do not authorize waivers",
    "multiline_signed_value": "a signed review value must be a single line",
    "not_provenance_bound": "a completed observation requires served family and model",
    "incomplete_evidence": "the current observation lacks complete checked evidence",
    "hold_mismatch": "this request has no matching waiter or round owner",
    "unknown_review": "no review record is bound to that object",
})
NEXT = MappingProxyType({
    "invalid_input": "submit the launch, tree, report bytes and round",
    "malformed_report": "submit a bounded text report",
    "stale_report": "bind the report that matches the current tree and ruling",
    "limit_exceeded": "submit a report inside the profile limit",
    "unauthorized_waiver": "ask the coordinator to review the waiver request",
    "multiline_signed_value": "submit the signed value as a single line",
    "not_provenance_bound": "submit the served family and model for the completed review",
    "incomplete_evidence": "obtain a checked receipt for the current report and all declared sites",
    "hold_mismatch": "ask the coordinator to review the round and owner",
    "unknown_review": "bind a review for that object before reading it",
})
GATE_NEXT = MappingProxyType({
    "evidence_only": "ask the coordinator to review the recorded observation",
    "refuse": "ask the coordinator to review the observed refusal",
    "ambiguous": "ask the coordinator for an unambiguous verdict",
    "integrity": "ask the coordinator to verify the review copy",
    "peer_refusal": "ask the coordinator to resolve the current round's refusal",
    "policy_stop": "ask the coordinator for an authorized disposition of the policy stop",
    "check_incomplete": "ask the coordinator for a complete checked receipt",
    "cross_family": "ask the coordinator for a checked vote from another served family",
    "pass": "use the checked votes for the current review round",
    "superseded": "read the current review round",
})
_USAGE = frozenset(("invalid_input", "limit_exceeded", "multiline_signed_value", "not_provenance_bound"))
EXIT_CODES = MappingProxyType({code: (2 if code in _USAGE else 1) for code in REFUSALS})

class _Refuse(Exception):
    def __init__(self, code, verb="bind"):
        self.code = code
        self.verb = verb

def _require(condition, code="invalid_input", verb="bind"):
    if not condition:
        raise _Refuse(code, verb)

def _identifier(value, verb="bind"):
    _require(type(value) is str and len(value) <= 64 and _IDENT.fullmatch(value) is not None, verb=verb)
    _require(receipt_value(value, limit=64, identifier=True) == value, verb=verb)
    return value

def _site_set(value, verb):
    _require(type(value) in (tuple, list), verb=verb)
    _require(len(value) <= _MAX_SITES, "limit_exceeded", verb)
    submitted = value[:_MAX_SITES + 1]
    _require(len(submitted) <= _MAX_SITES, "limit_exceeded", verb)
    sites = {_identifier(site, verb) for site in submitted}
    _require(len(sites) == len(submitted), verb=verb)
    return tuple(sorted(sites))

def _served_token(value, pattern=_SERVED_TOKEN):
    _require(type(value) is str and len(value) <= 128 and pattern.fullmatch(value) is not None)
    _require(receipt_value(value, limit=128, identifier=True) == value)
    return value

def _tree_oid(value, verb="bind"):
    _require(type(value) is str and len(value) in (40, 64) and _TREE.fullmatch(value) is not None, verb=verb)
    return value

def _sha(value, verb="bind"):
    _require(type(value) is str and len(value) == 64 and _SHA.fullmatch(value) is not None, verb=verb)
    return value

def _closed(value, keys, verb="bind"):
    _require(type(value) is dict and len(value) == len(keys), verb=verb)
    _require(all(type(key) is str for key in value) and value.keys() == set(keys), verb=verb)
    return value

def _flag(value, verb="bind"):
    _require(type(value) is bool, verb=verb)
    return value

def _whole(value, low, high, verb="bind"):
    _require(type(value) is int and low <= value <= high, verb=verb)
    return value

def _label(value, allowed, verb="bind"):
    _require(type(value) is str and len(value) <= max(map(len, allowed)) and value in allowed, verb=verb)

def _policy_value(value):
    if value is None or value is DEFAULT_POLICY:
        value = dict(DEFAULT_POLICY)
    base = _closed(value, DEFAULT_POLICY)
    policy = {
        "max_report_bytes": _whole(base["max_report_bytes"], 1, 1048576),
        "window_lines": _whole(base["window_lines"], 1, 1000),
        "require_cross_family": _flag(base["require_cross_family"]),
        "review_cap": None if base["review_cap"] is None else _whole(base["review_cap"], 1, 1000000),
        "mode": base["mode"],
        "advisory_prereview": _flag(base["advisory_prereview"]),
        "second_family_reviewer": _flag(base["second_family_reviewer"]),
        "content_filter_retries": _whole(base["content_filter_retries"], 0, 1),
    }
    _label(policy["mode"], ("full", "delta"))
    return policy

def _fallback_value(value):
    if value is None:
        return None
    body = _closed(value, ("family", "model", "reason"))
    reason = body["reason"]
    _label(reason, _FALLBACK_REASONS)
    return {
        "family": _served_token(body["family"]),
        "model": _served_token(body["model"], _SERVED_MODEL),
        "reason": reason,
    }

def _launch_value(value):
    _require(type(value) is dict and len(value) <= len(_LAUNCH_KEYS))
    _require(all(type(key) is str for key in value))
    state = value.get("state")
    _label(state, _STATES)
    if state == "completed":
        value = {"family": None, "model": None, **value}
    body = _closed(value, _LAUNCH_KEYS)
    lens = body["lens"]
    _label(lens, _LENSES)
    family = None if body["family"] is None else _served_token(body["family"])
    model = None if body["model"] is None else _served_token(body["model"], _SERVED_MODEL)
    launch = {
        "family": family,
        "model": model,
        "host": _served_token(body["host"]),
        "fallback": _fallback_value(body["fallback"]),
        "lens": lens,
        "state": state,
        "brief_seen": _flag(body["brief_seen"]),
    }
    _require(state == "completed" or family is not None)
    return launch

def _round_value(value):
    body = _closed(value, ("review_object", "round_id", "owner", "number", "expected_generation"))
    return {
        "review_object": _identifier(body["review_object"]),
        "round_id": _identifier(body["round_id"]),
        "owner": _identifier(body["owner"]),
        "number": _whole(body["number"], 1, 1000000),
        "expected_generation": _whole(body["expected_generation"], 0, 1000000000),
    }

def _copy_value(value):
    if value is None:
        return None
    body = _closed(value, ("ok", "tree", "manifest_sha256"))
    return {"ok": _flag(body["ok"]), "tree": _tree_oid(body["tree"]), "manifest_sha256": _sha(body["manifest_sha256"])}

def _verified_value(value):
    if value is None:
        return None
    body = _closed(value, ("tree", "verified"))
    return {"tree": _tree_oid(body["tree"]), "verified": _flag(body["verified"])}

def _unchanged_value(value):
    if value is None:
        return ()
    _require(type(value) in (list, tuple))
    _require(len(value) <= _MAX_UNCHANGED, "limit_exceeded")
    submitted = value[:_MAX_UNCHANGED + 1]
    _require(len(submitted) <= _MAX_UNCHANGED, "limit_exceeded")
    lines = tuple(_whole(item, 1, 10000000) for item in submitted)
    if not lines:
        return ()
    # Keep the exact verification scope in the version without retaining every line in the journal.
    raw = json.dumps(lines, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(raw).hexdigest()

def _qualification_value(value):
    if value is None:
        return None
    body = _closed(value, ("tree", "review_object", "lens", "qualified"))
    lens = body["lens"]
    _label(lens, _LENSES)
    return {
        "tree": _tree_oid(body["tree"]),
        "review_object": _identifier(body["review_object"]),
        "lens": lens,
        "qualified": _flag(body["qualified"]),
    }

def _decode(report):
    try:
        text = report.decode("utf-8")
    except UnicodeError:
        raise _Refuse("malformed_report") from None
    _require("\x00" not in text, "malformed_report")
    return text

def _report_lines(text, limit):
    start = int(text.startswith("\ufeff"))
    for _ in range(limit):
        if start >= len(text):
            return
        boundary = _REPORT_BREAK.search(text, start)
        if boundary is None:
            yield text[start:]
            return
        yield text[start:boundary.start()]
        start = boundary.end()
    if start < len(text):
        yield None


def _unemphasize(value):
    for mark in ('***', '___', '```', '**', '__', '``', '*', '_', '`', '"'):
        if len(value) > 2 * len(mark) and value.startswith(mark) and value.endswith(mark):
            return value[len(mark):-len(mark)].strip()
    return value


def _claim_on(line):
    if line.startswith("|"):
        name, _, remainder = line[1:].partition("|")
        value, end, tail = remainder.partition("|")
        if end and not tail.strip():
            name = name.strip()
            if name.endswith(":"):
                name = _unemphasize(name[:-1].rstrip())
            else:
                name = _unemphasize(name).removesuffix(":").rstrip()
            name = name.lower()
            if name in ("verdict", "checked-site"):
                return name, _unemphasize(value.strip())
    match = _CLAIM_LINE.fullmatch(line)
    if match is None:
        match = _CLAIM_LINE.fullmatch(_unemphasize(line))
        if match is not None and match["mark"] is not None:
            return None, line
    if match is None:
        return None, line
    return match["label"].lower(), _unemphasize(match["value"].strip())


def _has_verdict_claim(line):
    # These cues preserve ambiguity in the read record.
    if _VERDICT_LABEL.search(line) or _BARE_VERDICT.search(line) or _FIELD_VALUE.search(line):
        return True
    if "|" in line:
        return _CONTEXT_LABEL.search(line) is not None or _VERDICT_WORDS.search(line) is not None
    return _CONTEXT_FIELD.search(line) is not None or _CONTEXT_VALUE.search(line) is not None


def _verdict_value(value):
    observed = _VERDICT_VALUES.get(value.lower())
    if observed is not None:
        return observed
    refusal = _REJECTION.match(value)
    if refusal is not None and not _has_verdict_claim(value[refusal.end():]):
        return "request_changes"
    return "ambiguous"


def _parse_report(text, limit):
    """Collect bounded diagnostic observations and indicate unread text."""
    verdicts, findings = set(), []
    overflow = False
    for raw in _report_lines(text, limit):
        if raw is None:
            overflow = True
            break
        line = _MARKDOWN.sub("", raw.strip(), count=1)
        if not line or _TABLE_HEADER.fullmatch(line):
            continue
        label, value = _claim_on(line)
        if label == "verdict":
            verdicts.add(_verdict_value(value))
            continue
        if label == "checked-site":
            continue
        if not line.startswith(">") and not _SOURCE_LOCATION.fullmatch(line) and _has_verdict_claim(line):
            verdicts.add("ambiguous")
        finding = _FINDING.match(line)
        if finding is not None and finding[2] is not None and len(findings) < _MAX_FINDINGS:
            findings.append((finding[1].lower(), int(finding[2])))
    if "ambiguous" in verdicts or len(verdicts) > 1:
        note = "unparsed_block" if "ambiguous" in verdicts else "conflict"
        return "ambiguous", note, tuple(findings), overflow
    if not verdicts:
        note = "window_exceeded" if overflow else "no_verdict" if text else "empty"
        return "incomplete", note, (), overflow
    verdict, = verdicts
    if overflow and verdict == "accept":
        return verdict, "window_exceeded", tuple(findings), overflow
    return verdict, "unanimous", tuple(findings), overflow


def _version(payload, previous, operation):
    versioned = payload if previous is None else {**payload, "previous": previous, "operation": operation}
    raw = json.dumps(versioned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class _Observation:
    origin: int
    bound_origin: int
    payload: dict
    version: str
    parsed_verdict: str
    note: str
    disposition: str
    findings: tuple
    overflow: bool
    previous: str = None
    operation: str = "bound"

    @property
    def round_id(self):
        return self.payload["round_id"]

    @property
    def number(self):
        return self.payload["number"]

    @property
    def family(self):
        return self.payload["launch"]["family"]

    @property
    def expected_sites(self):
        return self.payload.get("expected_sites", ())

    @property
    def refuses(self):
        return self.disposition in ("request_changes", "fix_first")

    @property
    def voting(self):
        lens = self.payload["launch"]["lens"]
        return lens == "gating" or (lens == "second_family" and self.payload["policy"]["second_family_reviewer"])

    @property
    def gating(self):
        return self.payload["launch"]["lens"] == "gating"


@dataclass(frozen=True)
class _Vote:
    origin: int
    version: str
    sites: tuple

def _prepare(launch, tree, report, review_round, policy, copy_evidence, verified, unchanged_lines, qualification,
             previous, expected_sites):
    launch = _launch_value(launch)
    tree = _tree_oid(tree)
    identity = _round_value(review_round)
    expected = identity.pop("expected_generation")
    policy = _policy_value(policy)
    _require(type(report) is bytes)
    _require(len(report) <= policy["max_report_bytes"], "limit_exceeded")
    copy = _copy_value(copy_evidence)
    verification = _verified_value(verified)
    unchanged = _unchanged_value(unchanged_lines)
    qualification = _qualification_value(qualification)
    sites = () if expected_sites is None else _site_set(expected_sites, "bind")
    if previous is not None:
        _sha(previous)

    state = launch["state"]
    if state == "completed":
        _require(launch["family"] is not None and launch["model"] is not None, "not_provenance_bound")
    text = _decode(report)
    if state != "completed":
        disposition = "unavailable" if state == "error" else state
        parsed, note, findings, overflow = disposition, "not_scored", (), False
    elif not launch["brief_seen"]:
        disposition = "incomplete"
        parsed, note, findings, overflow = disposition, "brief_unseen", (), False
    else:
        disposition = _CANONICAL_DISPOSITIONS.get(report, "incomplete")
        parsed, note, findings, overflow = _parse_report(text, policy["window_lines"])
    for witness in (copy, verification):
        _require(witness is None or witness["tree"] == tree, "stale_report")

    digest = hashlib.sha256(report).hexdigest()
    payload = {
        **identity, "launch": launch, "tree": tree, "report_sha256": digest, "policy": policy, "copy": copy,
        "verified": verification, "unchanged": unchanged, "qualification": qualification,
    }
    if sites:
        payload["expected_sites"] = sites
    operation = "bound" if previous is None else "corrected"
    return _Observation(expected, expected, payload, _version(payload, previous, operation), parsed, note,
                        disposition, findings, overflow, previous, operation)


def _row(observation, reason, *, counted=False, obsolete=False):
    payload = observation.payload
    launch, copy, tree = payload["launch"], payload["copy"], payload["tree"]
    qualification = payload["qualification"]
    qualified = (qualification is not None and qualification["qualified"] and qualification["tree"] == tree
                 and qualification["review_object"] == payload["review_object"] and qualification["lens"] == launch["lens"])
    return {
        **{key: payload[key] for key in ("review_object", "round_id", "owner", "number", "tree", "report_sha256")},
        "launch": deepcopy(launch), "evidence_version": observation.version,
        "parsed_verdict": observation.parsed_verdict, "parse_note": observation.note,
        "effective_gate": reason if reason in ("pass", "refuse") else "hold", "gate_reason": reason,
        "authorized_waiver": None, "waiver_history": [], "follow_ups": [],
        "findings": [{"severity": severity, "line": line} for severity, line in observation.findings],
        "counted": counted, "eligible_retry": False, "preferred_independent": False, "obsolete": obsolete,
        "copy_ok": copy["ok"] if copy is not None else None, "copy_evidence": deepcopy(copy),
        "qualification_retained": qualified,
    }

class _ReviewState:
    def __init__(self, events):
        self.generation = len(events)
        self.observations = {event.version: event for event in events if isinstance(event, _Observation)}
        self.authorizations = {event.version: event for event in events if isinstance(event, _Vote)}
        self.rounds = {event.round_id: event for event in self.observations.values()}
        self.latest = max(self.rounds.values(), key=lambda row: (row.number, row.bound_origin), default=None)
        self.number = self.latest.number if self.latest is not None else 0
        self.active = sorted((row for row in self.rounds.values() if row.number == self.number and row.voting),
                             key=lambda row: row.bound_origin)
        self.families = {row.family: row for row in self.active}
        current = [row for row in self.observations.values() if row.number == self.number and row.voting]
        self.refusals = self._unresolved(row for row in current if row.refuses)
        self.unread = self._unresolved((row for row in current if row.overflow), refusal_disposes=True)
        # A new round on identical bytes cannot stand in for disposition of a policy stop.
        self.policy_stop = self.latest is not None and any(
            row.voting and row.disposition == "content_filter" and row.payload["tree"] == self.latest.payload["tree"]
            for row in self.observations.values()
        )
        self.counted = {
            row.version for row in self.families.values()
            if row.version in self.authorizations and self._can_count(row)
        }
        self.accept_reason = self._accept_reason(current)

    def _unresolved(self, history, *, refusal_disposes=False):
        pending = {row.round_id for row in history}
        return {
            row.round_id for row in self.active if row.round_id in pending
            and not (refusal_disposes and row.refuses)
            and not (row.disposition == "accept" and row.version in self.authorizations)
        }

    def _can_count(self, row):
        return row.disposition == "request_changes" or not (self.refusals or self.policy_stop)

    def _needs_independent_gating(self, current, counted_gating):
        successful = [row for row in current if row.disposition == "accept" and row.version in self.authorizations]
        failures = (row for row in self.active if row.gating and row.disposition in ("unavailable", "timeout"))
        for failed in failures:
            # Authorization, repair and correction may arrive after the failure.
            prior = {row.family for row in successful if row.bound_origin < failed.bound_origin}
            prior.add(failed.family)
            if not any(row.bound_origin > failed.bound_origin and row.family not in prior for row in counted_gating):
                return True
        return False

    def _accept_reason(self, current):
        if self.refusals:
            return "peer_refusal"
        if self.policy_stop:
            return "policy_stop"
        if self.unread or any(row.payload["launch"]["state"] == "completed" and row.version not in self.authorizations
                              for row in self.active):
            return "check_incomplete"
        counted_gating = [row for row in self.families.values() if row.gating and row.version in self.counted]
        if not counted_gating or self._needs_independent_gating(current, counted_gating):
            return "check_incomplete"
        policy = self.latest.payload["policy"]
        if policy["require_cross_family"] and len(self.counted) < 2:
            return "cross_family"
        return "pass"

    def row(self, row):
        counted = row.version in self.counted
        obsolete = row.number != self.number
        copy = row.payload["copy"]
        if row.refuses or (row.number == self.number and row.round_id in self.refusals):
            reason = "refuse"
        elif row.disposition == "content_filter":
            reason = "policy_stop"
        elif obsolete:
            reason = "superseded"
        elif row.voting and self.policy_stop:
            reason = "policy_stop"
        elif row.version in self.authorizations and self.families.get(row.family) is row:
            reason = self.accept_reason
        elif copy is not None and not copy["ok"] and row.expected_sites:
            reason = "integrity"
        else:
            reason = "evidence_only"
        return _row(row, reason, counted=counted, obsolete=obsolete)

    def record(self, review_object):
        rounds = sorted(self.rounds.values(), key=lambda row: (row.number, row.round_id))
        attempts = [_attempt(row) for row in rounds if row.payload["launch"]["state"] != "completed"]
        votes = [
            _vote_record(row, self.authorizations[row.version]) for row in rounds if row.version in self.counted
        ]
        return {
            "schema": _RECORD_SCHEMA, "review_object": review_object, "generation": self.generation,
            "manual_flag": False, "qualification_voided": False, "rounds": [self.row(row) for row in rounds],
            "history": self.history(), "holds": [], "votes": votes, "attempts": attempts,
        }

    def history(self):
        events = []
        for row in self.observations.values():
            if self.rounds[row.round_id] is not row:
                reason = "refuse" if row.refuses else "superseded"
                body = _row(row, reason, obsolete=True)
            elif row.previous is not None:
                body = {key: row.payload[key] for key in ("review_object", "round_id", "owner", "tree")}
                body["evidence_version"] = row.version
            else:
                continue
            events.append(dict(body, generation=row.origin + 1, operation=row.operation, previous=row.previous))
        events.extend(
            dict(_vote_record(self.observations[version], vote, counted=False), operation="authorized")
            for version, vote in self.authorizations.items() if version not in self.counted
        )
        return sorted(events, key=lambda event: event["generation"])


def _attempt(row):
    launch = row.payload["launch"]
    return {
        "family": launch["family"], "model": launch["model"], "round_id": row.round_id,
        "tree": row.payload["tree"], "lens": launch["lens"], "state": row.disposition,
    }


def _vote_record(row, vote, *, counted=True):
    return {
        **_identity(row, counted), "number": row.number, "owner": row.payload["owner"],
        "tree": row.payload["tree"], "report_sha256": row.payload["report_sha256"],
        "evidence_version": row.version, "generation": vote.origin + 1, "verdict": row.disposition,
        "checked_sites": list(vote.sites),
    }


def _success(verb, effect, review_object, state, round_id):
    record = state.record(review_object)
    affected = next(row for row in record["rounds"] if row["round_id"] == round_id)
    payload = envelope("aegis team review " + verb, {"review_object": review_object},
                       schema="aegis.team.review." + verb + "/v1")
    payload.update(refused=False, reason="", next_action=GATE_NEXT[affected["gate_reason"]], exit_code=0,
                   effect=effect, record=record, round=affected)
    return payload

def _refusal(verb, code):
    payload = envelope("aegis team review " + verb, {}, schema="aegis.team.review." + verb + "/v1")
    payload.update(refused=True, reason=code, next_action=NEXT[code], exit_code=EXIT_CODES[code],
                   effect="refused", record=None, round=None)
    return payload

class ReviewLedger:
    """An in-memory append-only ledger of review observations."""

    def __init__(self):
        self._lock = threading.Lock()
        self._objects = {}

    def _append(self, verb, effect, review_object, round_id, events, event):
        _require(len(events) < _MAX_EVENTS, "limit_exceeded", verb)
        proposed = (*events, event)
        result = _success(verb, effect, review_object, _ReviewState(proposed), round_id)
        self._objects[review_object] = proposed
        return result

    def _bind(self, row):
        supplied = row.payload
        review_object, owner = supplied["review_object"], supplied["owner"]
        with self._lock:
            events = self._objects.get(review_object)
            if events is None:
                _require(len(self._objects) < _MAX_OBJECTS, "limit_exceeded")
                events = ()
            state = _ReviewState(events)
            current = state.rounds.get(row.round_id)
            if current is not None:
                _require(current.payload["owner"] == owner, "hold_mismatch")
                _require(current.number == row.number == state.number, "stale_report")
                if row.operation == "corrected" and current.voting:
                    _require(state.families.get(current.family) is current, "stale_report")
                if current.version == row.version:
                    _require((current.operation, current.previous, current.payload)
                             == (row.operation, row.previous, row.payload)
                             and row.origin in (current.origin, state.generation), "stale_report")
                    return _success("bind", "already", review_object, state, row.round_id)
                _check_correction(current, row)
                row = replace(row, bound_origin=current.bound_origin)
            else:
                _require(row.previous is None and row.number >= state.number, "stale_report")
                if row.number == state.number:
                    reference = state.latest.payload
                    _require(supplied["tree"] == reference["tree"] and supplied["policy"] == reference["policy"],
                             "stale_report")
                _require(len(state.rounds) < _MAX_ROUNDS, "limit_exceeded")
            _require(row.origin == state.generation, "stale_report")
            return self._append("bind", row.operation, review_object, row.round_id, events, row)

    def _target(self, review_object, round_id, owner, verb):
        events = self._objects.get(review_object)
        _require(events is not None, "unknown_review", verb)
        state = _ReviewState(events)
        current = state.rounds.get(round_id)
        _require(current is not None, "stale_report", verb)
        _require(current.payload["owner"] == owner, "hold_mismatch", verb)
        return events, state, current

    def _authorize(self, review_object, round_id, owner, vote):
        verb = "vote"
        with self._lock:
            events, state, current = self._target(review_object, round_id, owner, verb)
            _require(current.version == vote.version and current.number == state.number, "stale_report", verb)
            _require(current.voting, "incomplete_evidence", verb)
            _require(state.families.get(current.family) is current, "stale_report", verb)
            previous = state.authorizations.get(vote.version)
            if previous is not None:
                _require(previous.sites == vote.sites and vote.origin in (previous.origin, state.generation),
                         "stale_report", verb)
                return _success(verb, "already", review_object, state, round_id)
            _require(vote.origin == state.generation, "stale_report", verb)
            verification, copy = current.payload["verified"], current.payload["copy"]
            _require(current.disposition in ("accept", "request_changes") and current.expected_sites
                     and current.expected_sites == vote.sites
                     and verification is not None and verification["verified"] and (copy is None or copy["ok"]),
                     "incomplete_evidence", verb)
            return self._append(verb, "authorized", review_object, round_id, events, vote)

    def _repair(self, review_object, round_id, owner, previous, expected, copy):
        verb = "repair"
        with self._lock:
            events, state, current = self._target(review_object, round_id, owner, verb)
            old_copy = current.payload["copy"]
            if current.operation == "repaired" and current.previous == previous and copy == old_copy:
                _require(expected in (current.origin, state.generation), "stale_report", verb)
                return _success(verb, "already", review_object, state, round_id)
            _require(expected == state.generation and current.version == previous, "stale_report", verb)
            _require(old_copy is not None and not old_copy["ok"] and copy == {**old_copy, "ok": True},
                     "stale_report", verb)
            payload = {**current.payload, "copy": copy}
            repaired = replace(current, origin=expected, payload=payload, version=_version(payload, previous, "repaired"),
                               previous=previous, operation="repaired")
            return self._append(verb, "repaired", review_object, round_id, events, repaired)

    def read(self, review_object):
        try:
            _identifier(review_object, "read")
        except _Refuse as refused:
            return _refusal(refused.verb, refused.code)
        with self._lock:
            events = self._objects.get(review_object)
            if events is None:
                return _refusal("read", "unknown_review")
            state = _ReviewState(events)
            return _success("read", "read", review_object, state, state.latest.round_id)

    def identities(self, tree):
        try:
            _tree_oid(tree, "read")
        except _Refuse as refused:
            return _refusal(refused.verb, refused.code)
        with self._lock:
            states = (_ReviewState(events) for events in self._objects.values())
            rows = [_identity(row, row.version in state.counted) for state in states for row in state.rounds.values()
                    if row.payload["tree"] == tree]
        rows.sort(key=lambda item: (item["review_object"], item["round_id"]))
        payload = envelope("aegis team review read", {"tree": tree}, schema="aegis.team.review.read/v1")
        payload.update(refused=False, reason="", next_action="", exit_code=0, effect="read",
                       record=None, round=None, tree=tree, identities=rows)
        return payload

def _check_correction(current, replacement):
    _require(replacement.previous == current.version and current.payload["launch"]["state"] == "completed",
             "stale_report")
    _require(replacement.payload != current.payload and all(
        replacement.payload[key] == value for key, value in current.payload.items()
        if key not in ("report_sha256", "verified", "expected_sites")
    ), "stale_report")


def _identity(row, counted):
    launch = row.payload["launch"]
    return {
        "family": launch["family"], "model": launch["model"], "host": launch["host"],
        "fallback": deepcopy(launch["fallback"]), "round_id": row.round_id,
        "review_object": row.payload["review_object"], "lens": launch["lens"], "counted": counted,
    }


def bind_report(ledger, launch, tree, report, review_round, policy=None, copy_evidence=None,
                verified=None, unchanged_lines=None, qualification=None, *, replaces=None, expected_sites=None):
    """Bind a report or append a correction naming the current evidence version.

    The trusted caller supplies expected sites for this version independently
    of the report text. A missing or empty sequence binds observation only.
    """
    if type(ledger) is not ReviewLedger:
        return _refusal("bind", "invalid_input")
    try:
        return ledger._bind(_prepare(
            launch, tree, report, review_round, policy, copy_evidence, verified, unchanged_lines, qualification,
            replaces, expected_sites))
    except _Refuse as refused:
        return _refusal(refused.verb, refused.code)

def _validate_ruling(value, verb):
    _require(type(value) is str, verb=verb)
    _require(len(value) <= _MAX_RULING, "limit_exceeded", verb)
    _require(value != "" and not any(char in value for char in _BREAKS), "multiline_signed_value", verb)
    _require(receipt_value(value, limit=_MAX_RULING) == value, verb=verb)

def _validate_items(deferred_items, known_items, verb):
    _require(type(deferred_items) in (list, tuple) and type(known_items) in (list, tuple), verb=verb)
    _require(len(deferred_items) <= _MAX_ITEMS and len(known_items) <= _MAX_KNOWN, "limit_exceeded", verb)
    items = {_identifier(item, verb) for item in deferred_items}
    _require(len(items) == len(deferred_items), verb=verb)
    for item in known_items:
        _identifier(item, verb)

def _validate_control(ledger, review_object, round_id, owner, generation, verb):
    _require(type(ledger) is ReviewLedger, verb=verb)
    _identifier(review_object, verb)
    _identifier(round_id, verb)
    _identifier(owner, verb)
    _whole(generation, 0, 1000000000, verb)


def authorize_vote(ledger, review_object, round_id, owner, evidence_version, expected_generation, checked_sites):
    """Record the trusted caller's checks for the exact current observation.

    The checked sites must equal the trusted set bound for a canonical verdict.
    A later receipt requires a fresh authorization.
    """
    verb = "vote"
    try:
        _validate_control(ledger, review_object, round_id, owner, expected_generation, verb)
        _sha(evidence_version, verb)
        vote = _Vote(expected_generation, evidence_version, _site_set(checked_sites, verb))
        return ledger._authorize(review_object, round_id, owner, vote)
    except _Refuse as refused:
        return _refusal(verb, refused.code)


def repair_copy(ledger, review_object, round_id, owner, evidence_version, expected_generation, copy_evidence):
    """Bind a verified copy of the same manifest to the selected failed receipt."""
    verb = "repair"
    try:
        _validate_control(ledger, review_object, round_id, owner, expected_generation, verb)
        _sha(evidence_version, verb)
        copy = _copy_value(copy_evidence)
        _require(copy is not None and copy["ok"], verb=verb)
        return ledger._repair(review_object, round_id, owner, evidence_version, expected_generation, copy)
    except _Refuse as refused:
        return _refusal(verb, refused.code)


def authorize_waiver(ledger, review_object, round_id, owner, report_sha256, tree, ruling,
                     deferred_items, known_items, covers, expected_generation, *, evidence_version=None):
    """Validate a waiver request for compatibility and decline authorization."""
    verb = "waive"
    try:
        _validate_control(ledger, review_object, round_id, owner, expected_generation, verb)
        _sha(report_sha256, verb)
        _tree_oid(tree, verb)
        if evidence_version is not None:
            _sha(evidence_version, verb)
        _label(covers, _COVERS, verb)
        _validate_ruling(ruling, verb)
        _validate_items(deferred_items, known_items, verb)
    except _Refuse as refused:
        return _refusal(refused.verb, refused.code)
    return _refusal(verb, "unauthorized_waiver")

def _decline_waiter(ledger, verb, review_object, round_id, owner, expected_generation, incarnation):
    try:
        _validate_control(ledger, review_object, round_id, owner, expected_generation, verb)
        if incarnation is not None:
            _whole(incarnation, 1, _MAX_CONTROL_INCARNATION, verb)
    except _Refuse as refused:
        return _refusal(refused.verb, refused.code)
    return _refusal(verb, "hold_mismatch")

def notify_waiter(ledger, review_object, round_id, owner, expected_generation, *, incarnation=None):
    """Decline notification for the evidence-only ledger."""
    return _decline_waiter(ledger, "notify", review_object, round_id, owner, expected_generation, incarnation)

def release_hold(ledger, review_object, round_id, owner, expected_generation, *, incarnation=None):
    """Decline release for the evidence-only ledger."""
    return _decline_waiter(ledger, "release", review_object, round_id, owner, expected_generation, incarnation)

def review_record(ledger, review_object):
    """Read the observations for one review object."""
    if type(ledger) is not ReviewLedger:
        return _refusal("read", "invalid_input")
    return ledger.read(review_object)

def served_identity(ledger, tree):
    """Read the observed served identities for one tree."""
    if type(ledger) is not ReviewLedger:
        return _refusal("read", "invalid_input")
    return ledger.identities(tree)
