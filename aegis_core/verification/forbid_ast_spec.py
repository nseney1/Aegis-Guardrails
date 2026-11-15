"""Pure forbid_ast specification grammar shared by lint and verification.

The grammar and diagnostic strings are moved unchanged from verification.runner.
No paths are opened and no repository code is executed.
"""
from __future__ import annotations

import re
from typing import Optional

__all__ = ["CALL_SPEC_KEYS", "forbid_ast_spec_error"]


_FORBID_AST_KEYS = ("imports", "calls", "decorators")
_CALL_SPEC_KEYS = frozenset({"name", "where", "builtin"})
_SCALARS = (str, int, float, bool, type(None))


def _condition_error(cond: object) -> Optional[str]:
    """Why a where condition is outside the spec grammar: a scalar, {in: [scalars]}, {not: condition}, {absent: bool}."""
    while isinstance(cond, dict) and list(cond) == ["not"]:
        cond = cond["not"]
    if isinstance(cond, _SCALARS):
        return None
    op, target = next(iter(cond.items())) if isinstance(cond, dict) and len(cond) == 1 else (None, None)
    if op == "in":
        ok = isinstance(target, (list, tuple)) and bool(target) and all(isinstance(t, _SCALARS) for t in target)
        return None if ok else "in needs a non-empty list of scalars"
    if op == "absent":
        return None if isinstance(target, bool) else "absent needs true or false"
    return f"unknown operator {op} (allowed: in, not, absent)" if op is not None else "a condition is a scalar or one operator: in, not, absent"


def _call_spec_error(at: str, entry: dict) -> Optional[str]:
    extra = sorted(str(key) for key in entry if key not in _CALL_SPEC_KEYS)
    if extra:
        return f"{at}: unknown key {extra[0]!r} (allowed: {', '.join(sorted(_CALL_SPEC_KEYS))})"
    if not (isinstance(entry.get("name"), str) and entry["name"].strip()) or not isinstance(entry.get("builtin", False), bool):
        return f"{at}: name must be a non-empty string and builtin true or false"
    where = entry.get("where")
    if "where" in entry and (not isinstance(where, dict) or not where):
        return f"{at}.where must map argument names to conditions"
    for arg, cond in (where or {}).items():
        named = isinstance(arg, str) and all(n.strip().isidentifier() or re.fullmatch(r"\s*#[0-9]+\s*", n) for n in arg.split("|"))
        reason = _condition_error(cond) if named else "argument names are identifiers or #N, joined by |"
        if reason:
            return f"{at}.where.{arg}: {reason}"
    return None


def forbid_ast_spec_error(spec: object) -> Optional[str]:
    """Why a declared ``forbid_ast`` would enforce nothing as written; None when it is well-formed.

    evaluate_forbid_ast ignores what it cannot use (a list, a string where a list belongs,
    a misspelt key, an operator outside the where grammar), so a gate rule in such a shape
    would pass every file.
    """
    if not isinstance(spec, dict):
        return f"forbid_ast must map imports/calls/decorators to lists, not {type(spec).__name__}"
    unknown = sorted(str(key) for key in spec if key not in _FORBID_AST_KEYS)
    if unknown:
        listed = ", ".join(repr(key) for key in unknown)
        return f"unknown forbid_ast key {listed} (allowed: {', '.join(_FORBID_AST_KEYS)})"
    patterns = 0
    for key, value in spec.items():
        mapped = (lambda p: key == "calls" and isinstance(p, dict))
        if not isinstance(value, list) or not all(mapped(p) or (isinstance(p, str) and p.strip()) for p in value):
            return f"forbid_ast.{key} must be a list of non-empty strings, not {type(value).__name__}"
        errors = (_call_spec_error(f"forbid_ast.calls[{i}]", p) for i, p in enumerate(value) if mapped(p))
        error = next((e for e in errors if e), None)
        if error:
            return error
        patterns += len(value)
    return None if patterns else "forbid_ast declares no patterns"


# Public compatibility data; runner retains its historical private spelling.
CALL_SPEC_KEYS = _CALL_SPEC_KEYS

