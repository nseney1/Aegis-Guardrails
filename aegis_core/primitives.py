"""The primitives every layer shares, one home each (layer 0, standard library only): path
containment, strict JSON and UTC timestamps. Copies of these disagreed at their edges (a looped
path inside or outside, ``1e999`` read as infinity, a naive datetime read as local time or UTC).
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import os
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from aegis_core._version import __version__

__all__ = [
    "DuplicateKeyError",
    "TS_FORMAT",
    "envelope",
    "is_within",
    "key_within",
    "parse_utc",
    "real_key",
    "real_path",
    "safe_parts",
    "strict_loads",
    "utc_stamp",
]

_EXTENDED = "\\\\?\\"
_EXTENDED_UNC = "\\\\?\\UNC\\"

PathArg = Union[str, "os.PathLike[str]"]


# ── Paths ────────────────────────────────────────────────────────────────────

def real_path(path: PathArg) -> str:
    """``path`` with every link resolved and without the Windows extended-length prefix.

    realpath, not Path.resolve(): it never raises on a loop (3.9's resolve does) and it resolves
    Windows junctions. Windows realpath answers ``\\\\?\\C:\\...`` when the path appears or
    disappears while it resolves; that prefix is dropped (``\\\\?\\UNC\\x`` becomes ``\\\\x``).
    """
    real = os.path.realpath(path)
    if real.startswith(_EXTENDED_UNC):
        return "\\\\" + real[len(_EXTENDED_UNC):]
    if real.startswith(_EXTENDED):
        return real[len(_EXTENDED):]
    return real


def real_key(path: PathArg) -> Optional[str]:
    """``path`` resolved in one spelling per location (normcase folds the case Windows ignores), or
    None when it cannot be resolved: a NUL byte, an OS error, or a final component that is still a
    link after realpath (a loop: realpath hands the loop back and no file sits there)."""
    try:
        text = os.fsdecode(path)
        # Checked here: Windows realpath on 3.12+ returns a NUL path unchanged (gh-106242).
        if "\0" in text:
            return None
        real = real_path(text)
        if os.path.islink(real):
            return None
        return os.path.normcase(real)
    except (OSError, ValueError, RuntimeError):
        return None


def key_within(key: str, root_key: str) -> bool:
    """Whether the key ``key`` is ``root_key`` or below it (both from ``real_key``)."""
    return key == root_key or key.startswith(root_key.rstrip(os.sep) + os.sep)


def is_within(path: PathArg, root: PathArg, *, unresolvable: bool) -> bool:
    """Whether ``path`` resolves to ``root`` or below it. When either side cannot be resolved the
    answer is ``unresolvable``, which has no default: pass False where the caller requires the path
    inside (refusing on False) and True where it requires the path outside (refusing on True)."""
    key, base = real_key(path), real_key(root)
    if key is None or base is None:
        return unresolvable
    return key_within(key, base)


def safe_parts(rel: object, *, windows: bool = os.name == "nt") -> Optional[Tuple[str, ...]]:
    """The parts of a relative POSIX path that stays below wherever it is joined, or None: not a
    string, empty, a leading ``/``, or an empty, ``.`` or ``..`` part. With ``windows`` also None
    for a backslash or a ``:`` anywhere (a drive prefix ``D:x`` or a stream); POSIX keeps
    ``a:b.py`` and ``a\\b.py``, which are plain file names there."""
    if not isinstance(rel, str) or not rel or rel.startswith("/"):
        return None
    if windows and ("\\" in rel or ":" in rel):
        return None
    parts = tuple(rel.split("/"))
    if any(part in ("", ".", "..") for part in parts):
        return None
    return parts


# ── Strict JSON ──────────────────────────────────────────────────────────────

class DuplicateKeyError(ValueError):
    """A JSON object names one key twice: a second value would let one reader see one value
    and another reader the other."""


def _unique_object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    found: Dict[str, Any] = {}
    for key, value in pairs:
        if key in found:
            raise DuplicateKeyError(f"duplicate key {key!r}")
        found[key] = value
    return found


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not allowed")


def _finite(literal: str) -> float:
    value = float(literal)
    if not math.isfinite(value):
        # Cut: a refusal that echoes this message must not echo a megabyte of digits.
        raise ValueError(f"{literal[:40]} is not allowed")
    return value


def strict_loads(text: Union[str, bytes]) -> Any:
    """``json.loads`` that refuses a duplicate key (DuplicateKeyError), NaN and Infinity, and a
    number that overflows to infinity (``1e999``, which json reads as inf without calling
    parse_constant and which nothing can write back as JSON). The messages are fixed
    (``duplicate key 'k'``, ``NaN is not allowed``): readers echo them in their refusals.
    RecursionError passes through."""
    return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_no_constant, parse_float=_finite)


# ── UTC timestamps ───────────────────────────────────────────────────────────

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_CANONICAL_TS = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z", re.ASCII)


def utc_stamp(moment: Union[None, datetime, int, float] = None) -> str:
    """``moment`` in TS_FORMAT: None is now, a naive datetime is read as UTC, an aware one is
    converted, an int or float is a POSIX time. Anything else (a bool included) is a TypeError."""
    if moment is None:
        when = datetime.now(timezone.utc)
    elif isinstance(moment, datetime):
        when = moment.replace(tzinfo=timezone.utc) if moment.utcoffset() is None else moment.astimezone(timezone.utc)
    elif isinstance(moment, (int, float)) and not isinstance(moment, bool):
        when = datetime.fromtimestamp(moment, timezone.utc)
    else:
        raise TypeError(f"a timestamp is a datetime or a POSIX time, not {type(moment).__name__}")
    return when.strftime(TS_FORMAT)


def parse_utc(value: object, *, lenient: bool = False) -> Optional[datetime]:
    """``value`` as an aware UTC datetime, or None.

    Strict reads exactly what ``datetime.strptime(value, TS_FORMAT)`` reads. That includes a
    lower-case ``z`` or ``t`` and any Unicode decimal digit: pinned on purpose, because every
    copy this replaced read stamps that way and tightening it would drop rows that count today.
    The writers' own spelling is read without strptime, whose first call imports ``_strptime``
    and builds locale tables (the pre-tool hook reads stamps on every run).

    Lenient is ``datetime.fromisoformat`` with ``Z`` read as ``+00:00`` and a naive value read
    as UTC; what it accepts depends on the Python version (before 3.11, fractions of 3 or 6
    digits only).
    """
    if not isinstance(value, str) or not value:
        return None
    if lenient:
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
        except ValueError:
            return None
        return parsed.replace(tzinfo=timezone.utc) if parsed.utcoffset() is None else parsed.astimezone(timezone.utc)
    found = _CANONICAL_TS.fullmatch(value)
    if found:
        try:
            return datetime(*map(int, found.groups()), tzinfo=timezone.utc)
        except ValueError:
            return None
    try:
        return datetime.strptime(value, TS_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def envelope(source: str, scope: Dict[str, Any], *, schema: Optional[str] = None,
             now: Union[None, int, float, datetime] = None,
             checked_at: Optional[str] = None) -> Dict[str, Any]:
    """The machine-readable head, keeping a caller's already captured stamp verbatim."""
    if now is not None and checked_at is not None:
        raise TypeError("give now or checked_at, not both")
    # A stored stamp is not a request to read the clock again or to reinterpret its text.
    head = {} if schema is None else {"schema": schema}
    head.update(source=source, aegis_version=__version__,
                checked_at=utc_stamp(now) if checked_at is None else checked_at, scope=scope)
    return head
