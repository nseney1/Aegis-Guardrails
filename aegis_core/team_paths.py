"""Lease path parsing and conservative overlap decisions.

New leases never contain whitespace globs. Legacy space-joined globs retain their
stored spelling, and protect the conservative union of that spelling and its parts.
Only boundary parsers validate paths; overlap consumes their immutable parsed sets.

Raw leading slashes reach this parser intact. They retain the historical unanchored
meaning here; a future root-anchor decision belongs in this module.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import List, Optional, Tuple

from aegis_core import match
from aegis_core.config import MAX_CONFIG_BYTES

__all__ = ["LeasePathError", "PathSet", "glob_problem", "claim_paths", "stored_paths", "overlap",
           "legacy_recovery"]

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_TOO_LARGE = f"paths: the lease would be larger than {MAX_CONFIG_BYTES // 1024} KiB"
_RECOVERY = "give each path as its own entry (use ? for a space inside a name)"


class LeasePathError(ValueError):
    """Invalid lease paths; messages contain only trusted text and ordinals."""


@dataclass(frozen=True)
class PathSet:
    """Boundary-parsed paths: lossless stored values and conservative overlap globs."""

    raw: Tuple[str, ...]
    matching: Tuple[str, ...]
    legacy: bool = False


def glob_problem(glob: object) -> Optional[str]:
    """The shared non-lease validator, preserving lane-gate/partition semantics."""
    if not isinstance(glob, str):
        return "not_text"
    if _CONTROL.search(glob):
        return "control"
    return _shape_problem(glob)


def _shape_problem(glob: str) -> Optional[str]:
    clean = match.normalize_path(glob)
    if not clean:
        return "empty"
    if ".." in clean.split("/"):
        return "climbs"
    return None


def _lease_problem(glob: object, stored: bool = False) -> Optional[str]:
    # Bound input before normalization allocates a replacement string or components.
    if not isinstance(glob, str):
        return "not_text"
    if len(glob) > MAX_CONFIG_BYTES:
        return "too_large"
    if _CONTROL.search(glob) and (not stored or any(
            _CONTROL.match(ch) and not ch.isspace() for ch in glob)):
        return "control"
    if not stored and any(ch.isspace() for ch in glob):
        return "whitespace"
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in glob):
        return "utf8"
    return _shape_problem(glob)


def claim_paths(paths: object) -> PathSet:
    """Validate and normalize a new claim's list/tuple, without splitting any glob."""
    if not isinstance(paths, (list, tuple)):
        raise LeasePathError("paths: give a list of globs")
    if not paths:
        raise LeasePathError("paths: give at least one glob")
    out: List[str] = []
    seen = set()
    size = 0
    for ordinal, glob in enumerate(paths, 1):
        problem = _lease_problem(glob)
        if problem == "too_large":
            raise LeasePathError(_TOO_LARGE)
        if problem:
            message = {"not_text": "is not text", "control": "has a control character",
                       "empty": "is empty", "climbs": "climbs out of the workspace with '..'",
                       "whitespace": "has whitespace", "utf8": "is not UTF-8 text"}[problem]
            recovery = "; " + _RECOVERY if isinstance(glob, str) and any(ch.isspace() for ch in glob) else ""
            raise LeasePathError(f"paths: glob {ordinal} {message}{recovery}")
        clean = match.normalize_path(glob)
        if clean not in seen:
            size += len(clean)
            if size > MAX_CONFIG_BYTES:
                raise LeasePathError(_TOO_LARGE)
            seen.add(clean)
            out.append(clean)
    parsed = tuple(out)
    return PathSet(parsed, parsed)


def stored_paths(paths: object) -> PathSet:
    """Read v1 paths losslessly; ambiguous whitespace protects raw and split globs."""
    error = "paths is not a non-empty list of globs"
    if not isinstance(paths, (list, tuple)) or not paths:
        raise LeasePathError(error)
    size = 0
    matching: List[str] = []
    legacy = False
    for glob in paths:
        if _lease_problem(glob, stored=True):
            raise LeasePathError(error)
        size += len(glob)
        if size > MAX_CONFIG_BYTES:  # before split/result allocation
            raise LeasePathError(error)
        matching.append(glob)
        if any(ch.isspace() for ch in glob):
            legacy = True
            matching.extend(glob.split())
    return PathSet(tuple(paths), tuple(dict.fromkeys(matching)), legacy)


def overlap(first: PathSet, second: PathSet) -> bool:
    """Conservative overlap of boundary-parsed sets, with no repeated validation."""
    return match.sets_overlap(first.matching, second.matching)


def legacy_recovery(paths: PathSet, lane: str, oid: str) -> str:
    """Fixed recovery text; lane and OID come from the validated lease/ref."""
    return (f"; release {lane} --expect {oid}, then claim each path as its own entry"
            if paths.legacy else "")
