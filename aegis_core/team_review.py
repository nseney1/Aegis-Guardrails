"""Record bounded, immutable review observations for coordinator inspection."""
from __future__ import annotations

import hashlib
import json
import re
import threading
from copy import deepcopy
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
    "authorize_waiver",
    "bind_report",
    "notify_waiter",
    "release_hold",
    "review_record",
    "served_identity",
]

_RECORD_SCHEMA = "aegis.team.review.record/v1"
_MAX_OBJECTS = 128
_MAX_ROUNDS = 32
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
_VERDICTS = MappingProxyType({
    "VERDICT: ACCEPT": "accept",
    "VERDICT: REQUEST CHANGES": "request_changes",
    "VERDICT: FIX FIRST": "request_changes",
    "VERDICT: INCOMPLETE": "incomplete",
})

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
    "hold_mismatch": "ask the coordinator to review the round and owner",
    "unknown_review": "bind a review for that object before reading it",
})
GATE_NEXT = MappingProxyType({
    "evidence_only": "ask the coordinator to review the recorded observation",
    "refuse": "ask the coordinator to review the observed refusal",
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
    return tuple(_whole(item, 1, 10000000) for item in value)

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

def _observed_verdict(text, launch):
    state = launch["state"]
    if state != "completed":
        return ("unavailable" if state == "error" else state), "not_scored"
    if not launch["brief_seen"]:
        return "incomplete", "brief_unseen"
    verdict = _VERDICTS.get(text.removesuffix("\n"))
    if verdict is None:
        return "incomplete", "no_verdict" if text else "empty"
    return verdict, "unanimous"

def _prepare(launch, tree, report, review_round, policy, copy_evidence, verified, unchanged_lines, qualification):
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

    if launch["state"] == "completed":
        _require(launch["family"] is not None and launch["model"] is not None, "not_provenance_bound")
    verdict, note = _observed_verdict(_decode(report), launch)
    for witness in (copy, verification):
        _require(witness is None or witness["tree"] == tree, "stale_report")

    digest = hashlib.sha256(report).hexdigest()
    payload = {
        **identity, "launch": launch, "tree": tree, "report_sha256": digest, "policy": policy, "copy": copy,
        "verified": verification, "unchanged": unchanged, "qualification": qualification,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    refused = verdict == "request_changes"
    qualified = (qualification is not None and qualification["qualified"] and qualification["tree"] == tree
                 and qualification["review_object"] == identity["review_object"] and qualification["lens"] == launch["lens"])
    row = {
        **identity, "launch": launch, "tree": tree, "report_sha256": digest,
        "evidence_version": hashlib.sha256(raw).hexdigest(),
        "parsed_verdict": verdict, "parse_note": note,
        "effective_gate": "refuse" if refused else "hold", "gate_reason": "refuse" if refused else "evidence_only",
        "authorized_waiver": None, "waiver_history": [], "findings": [], "follow_ups": [],
        "counted": False, "eligible_retry": False, "preferred_independent": False, "obsolete": False,
        "copy_ok": copy["ok"] if copy is not None else None, "copy_evidence": copy, "qualification_retained": qualified,
    }
    return row, expected

def _view(review_object, rounds):
    # Responses own their nested structures, including launch and copy metadata.
    ordered = sorted((row for _, row in rounds.values()), key=lambda row: (row["number"], row["round_id"]))
    attempts = []
    for round_id in sorted(rounds):
        _, row = rounds[round_id]
        launch = row["launch"]
        if launch["state"] != "completed":
            attempts.append({
                "family": launch["family"], "model": launch["model"], "round_id": round_id,
                "tree": row["tree"], "lens": launch["lens"], "state": row["parsed_verdict"],
            })
    return {
        "schema": _RECORD_SCHEMA, "review_object": review_object, "generation": len(rounds),
        "manual_flag": False, "qualification_voided": False, "rounds": deepcopy(ordered),
        "history": [], "holds": [], "votes": [], "attempts": attempts,
    }

def _success(verb, effect, review_object, rounds, round_id):
    record = _view(review_object, rounds)
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

    def _bind(self, row, expected):
        review_object, round_id = row["review_object"], row["round_id"]
        with self._lock:
            rounds = self._objects.get(review_object)
            if rounds is None:
                _require(len(self._objects) < _MAX_OBJECTS, "limit_exceeded")
                rounds = {}
            generation = len(rounds)
            latest = next(reversed(rounds.values()), None)
            current_number = latest[1]["number"] if latest is not None else 0
            binding = rounds.get(round_id)
            if binding is not None:
                origin, current = binding
                _require(current["owner"] == row["owner"], "hold_mismatch")
                _require(current["number"] == row["number"] == current_number
                         and current["evidence_version"] == row["evidence_version"]
                         and expected in (origin, generation), "stale_report")
                return _success("bind", "already", review_object, rounds, round_id)
            _require(expected == generation and row["number"] >= current_number, "stale_report")
            _require(generation < _MAX_ROUNDS, "limit_exceeded")
            rounds[round_id] = (generation, row)
            self._objects[review_object] = rounds
            return _success("bind", "bound", review_object, rounds, round_id)

    def read(self, review_object):
        try:
            _identifier(review_object, "read")
        except _Refuse as refused:
            return _refusal(refused.verb, refused.code)
        with self._lock:
            rounds = self._objects.get(review_object)
            if rounds is None:
                return _refusal("read", "unknown_review")
            return _success("read", "read", review_object, rounds, next(reversed(rounds)))

    def identities(self, tree):
        try:
            _tree_oid(tree, "read")
        except _Refuse as refused:
            return _refusal(refused.verb, refused.code)
        with self._lock:
            rows = [
                _identity(row)
                for rounds in self._objects.values()
                for _, row in rounds.values()
                if row["tree"] == tree
            ]
        rows.sort(key=lambda item: (item["review_object"], item["round_id"]))
        payload = envelope("aegis team review read", {"tree": tree}, schema="aegis.team.review.read/v1")
        payload.update(refused=False, reason="", next_action="", exit_code=0, effect="read",
                       record=None, round=None, tree=tree, identities=rows)
        return payload

def _identity(row):
    launch = row["launch"]
    return {
        "family": launch["family"], "model": launch["model"], "host": launch["host"],
        "fallback": deepcopy(launch["fallback"]), "round_id": row["round_id"],
        "review_object": row["review_object"], "lens": launch["lens"], "counted": False,
    }

def bind_report(ledger, launch, tree, report, review_round, policy=None, copy_evidence=None,
                verified=None, unchanged_lines=None, qualification=None):
    """Append one observation or replay identical evidence for a current round."""
    if type(ledger) is not ReviewLedger:
        return _refusal("bind", "invalid_input")
    try:
        return ledger._bind(*_prepare(
            launch, tree, report, review_round, policy, copy_evidence, verified, unchanged_lines, qualification))
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
