"""Typed comparisons of driver-rendered literals, without evaluating source expressions."""
from __future__ import annotations

import ast
import math
from typing import Any, Optional

_UNKNOWN = object()


def _reference(value: str) -> bool:
    return all(part.replace("$", "_").isidentifier() for part in value.split("."))


def literal_value(value: Any) -> Any:
    """Decode supported Python-rendered scalars; unsupported kinds remain unknown."""
    if not isinstance(value, str) or value == "<expr>":
        return _UNKNOWN
    try:
        decoded = ast.literal_eval(value)
    except (ValueError, SyntaxError, RecursionError, OverflowError):
        return _UNKNOWN
    if type(decoded) not in (str, int, float, bool, type(None)):
        return _UNKNOWN
    if type(decoded) is float and not math.isfinite(decoded):
        return _UNKNOWN
    return decoded


def compare_literal(value: Any, condition: Any) -> Optional[bool]:
    """Scalar equality with distinct bool/string/number types and legacy symbolic names."""
    decoded = literal_value(value)
    if decoded is _UNKNOWN:
        if isinstance(value, str) and isinstance(condition, str) and _reference(value):
            return True if value == condition or value.endswith(f".{condition}") else None
        return None
    if type(decoded) in (int, float) and type(condition) in (int, float):
        return decoded == condition
    return type(decoded) is type(condition) and decoded == condition


def compare_options(value: Any, options: Any) -> Optional[bool]:
    """Three-valued membership using the same typed scalar comparison."""
    results = [compare_literal(value, option) for option in options]
    if any(result is True for result in results):
        return True
    if not any(result is None for result in results):
        return False
    # Existing enum-like references are known alternatives when their final name is capitalized.
    if isinstance(value, str) and _reference(value) and value.rpartition(".")[2][:1].isupper():
        return False
    return None
