"""Fixed repair text for rule-lint loader and paper-gate findings.

lint_rule and lint_workspace share this classifier. An empty reason list is
acceptance. Every repair sentence is a constant: exception text, keys read
from a file, and commands are never copied into it.
"""
from __future__ import annotations

__all__ = [
    "LOADER_MESSAGE",
    "LOADER_REPAIRS",
    "PAPER_GATE_MESSAGE",
    "PAPER_GATE_REPAIRS",
    "loader_message",
    "loader_reason_ids",
    "paper_gate_message",
]

LOADER_MESSAGE = "final accepted bytes or destination fail the rule loader"
_LOADER_REASON_ORDER = (
    ("expired", "clear expired_at so an expired rule can be accepted"),
    ("legacy_keys", "remove derived or retired keys before acceptance"),
    ("id_mismatch", "set id to the file name without .md"),
    ("type_mismatch", "set type to the canonical rule type for the directory"),
)
LOADER_REPAIRS = tuple(text for _reason, text in _LOADER_REASON_ORDER)
_SPECIFIC_REASONS = frozenset(reason for reason, _text in _LOADER_REASON_ORDER)

PAPER_GATE_MESSAGE = "gate requires a valid non-empty forbid_ast specification"
PAPER_GATE_REPAIRS = (
    "add a non-empty forbid_ast specification",
    "add at least one imports, calls or decorators pattern",
    "replace forbid_ast with a valid non-empty specification of imports, calls or decorators",
)
_SPEC_KEYS = frozenset(("imports", "calls", "decorators"))


def _with_repairs(base, repairs):
    """Append single-line allowlisted repairs. Multi-line text is not joined."""
    if not repairs or any(type(item) is not str or "\n" in item or "\r" in item for item in repairs):
        return base
    return base + ": " + "; ".join(repairs)


def loader_reason_ids(rule, destination):
    """Allowlisted reason ids. Empty means the loaded rule is accepted."""
    if rule is None or destination is None:
        return ("refused",)
    reasons = []
    if getattr(rule, "expired", False):
        reasons.append("expired")
    if getattr(rule, "legacy_keys", ()):
        reasons.append("legacy_keys")
    meta = getattr(rule, "meta", None)
    ok = bool(getattr(rule, "ok", False))
    if type(meta) is dict:
        if meta.get("id") != destination.id and (ok or "id" in meta):
            reasons.append("id_mismatch")
        if meta.get("type") != destination.type and (ok or "type" in meta):
            reasons.append("type_mismatch")
    if type(meta) is not dict or (not ok and not any(item in _SPECIFIC_REASONS for item in reasons)):
        reasons.append("refused")
    return tuple(reasons)


def loader_message(rule, destination):
    """Fixed loader text. Specific repairs are appended only from the allowlist."""
    found = set(loader_reason_ids(rule, destination))
    repairs = tuple(text for reason, text in _LOADER_REASON_ORDER if reason in found)
    return _with_repairs(LOADER_MESSAGE, repairs)


def _spec_repair(spec):
    """Classify a present forbid_ast value without reading pattern text."""
    if type(spec) is not dict or len(spec) > len(_SPEC_KEYS):
        return PAPER_GATE_REPAIRS[2]
    if not spec:
        return PAPER_GATE_REPAIRS[1]
    empty = True
    for key, value in spec.items():
        if type(key) is not str or key not in _SPEC_KEYS or type(value) is not list:
            return PAPER_GATE_REPAIRS[2]
        if value:
            empty = False
    return PAPER_GATE_REPAIRS[1] if empty else PAPER_GATE_REPAIRS[2]


def paper_gate_message(rule):
    """Fixed paper-gate text naming a missing, empty, or unusable forbid_ast."""
    meta = getattr(rule, "meta", None)
    if type(meta) is not dict or "forbid_ast" not in meta:
        repair = PAPER_GATE_REPAIRS[0]
    else:
        repair = _spec_repair(meta.get("forbid_ast"))
    return _with_repairs(PAPER_GATE_MESSAGE, (repair,))
