"""Lease path parsing and conservative overlap decisions.

New leases never contain whitespace globs. Legacy space-joined globs retain their
stored spelling, and protect the conservative union of that spelling and its parts.
Only boundary parsers validate paths; overlap consumes their immutable parsed sets.

Leading slashes anchor leases to the workspace root. Slashless globs keep their
historical any-depth meaning; rule targeting in match is unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import List, Optional, Tuple

from aegis_core import gitsafe, match, storage
from aegis_core.config import MAX_CONFIG_BYTES
from aegis_core.primitives import sanitize_display
from aegis_core.redaction import redact_command_secrets

__all__ = ["LeaseGlob", "LeasePathError", "PathSet", "glob_problem", "claim_paths", "stored_paths", "overlap",
           "legacy_recovery", "anchor_next_action", "first_match", "STORED_PATH_ERROR"]

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_WILDCARD = re.compile(r"[*?\[]")
_TOO_LARGE = f"paths: the lease would be larger than {MAX_CONFIG_BYTES // 1024} KiB"
_RECOVERY = "give each path as its own entry (use ? for a space inside a name)"
STORED_PATH_ERROR = "paths is not a non-empty list of globs"
LeaseGlob = match.LeaseGlob


class LeasePathError(ValueError):
    """Invalid lease paths; messages contain only trusted text and ordinals."""


@dataclass(frozen=True)
class PathSet:
    """Boundary-parsed paths: lossless stored values and conservative overlap globs."""

    raw: Tuple[LeaseGlob, ...]
    matching: Tuple[LeaseGlob, ...]
    legacy: bool = False

    def __post_init__(self) -> None:
        # Every boundary and direct PathSet construction retains provenance.
        for field in ("raw", "matching"):
            object.__setattr__(self, field, tuple(
                glob if isinstance(glob, LeaseGlob) else LeaseGlob(glob)
                for glob in getattr(self, field)))


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
    problem = _shape_problem(glob)
    return problem or ("empty" if _normalize(glob) == "/" else None)


def _normalize(glob: str) -> str:
    """Normalize separators and dot prefixes while retaining a root anchor."""
    text = glob.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    if not text.startswith("/"):
        return text
    # Equivalent anchored spellings must protect the same root-relative prefix.
    parts = [part for part in text.split("/") if part not in ("", ".")]
    suffix = "/" if parts and text.endswith("/") else ""
    return "/" + "/".join(parts) + suffix


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
        clean = _normalize(glob)
        if clean not in seen:
            size += len(clean)
            if size > MAX_CONFIG_BYTES:
                raise LeasePathError(_TOO_LARGE)
            seen.add(clean)
            out.append(clean)
    parsed = tuple(out)
    return PathSet(parsed, parsed)


def _old_reading(glob: str) -> str:
    """Preserve old scope without reinterpreting a revealed slash as an anchor."""
    clean = match.normalize_path(glob)
    # Old slash stripping can expose another ./ prefix. Removing residual dot
    # prefixes widens conservatively and leaves no new anchor for later readers.
    while clean.startswith("./"):
        clean = match.normalize_path(clean)
    return clean


def stored_paths(paths: object) -> PathSet:
    """Read v1 paths losslessly; ambiguous whitespace protects raw and split globs."""
    error = STORED_PATH_ERROR
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
        # The old writer stripped every leading slash; only the new writer can
        # store that explicit anchor marker. Raw old spellings remain lossless.
        matching.append(glob if glob.startswith("/") else _old_reading(glob))
        if any(ch.isspace() for ch in glob):
            components = glob.split()
            if not components or any(_lease_problem(component) for component in components):
                raise LeasePathError(error)
            legacy = True
            matching.extend(components)
    if legacy:
        # Whitespace cannot be newly claimed: this entire lease predates anchors.
        # Keep every legacy entry and split part at least as wide as its old reader.
        matching = [_old_reading(glob) for glob in matching]
    return PathSet(tuple(paths), tuple(dict.fromkeys(matching)), legacy)


def overlap(first: PathSet, second: PathSet) -> bool:
    """Conservative overlap of boundary-parsed sets, with no repeated validation."""
    others = tuple(_literal_prefix(glob) for glob in second.matching)
    return any(a.startswith(b) or b.startswith(a)
               for a in (_literal_prefix(glob) for glob in first.matching) for b in others)


def _literal_prefix(glob: str) -> str:
    """Anchors constrain the root prefix; unanchored basenames protect every depth."""
    pattern = _normalize(glob)
    anchored = pattern.startswith("/")
    pattern = pattern.lstrip("/")
    if not anchored and "/" not in pattern:
        return ""
    found = _WILDCARD.search(pattern)
    return (pattern if found is None else pattern[:found.start()]).casefold()


def first_match(paths: PathSet, path: str) -> Optional[str]:
    """First parsed lease glob containing a workspace file; None for invalid files.

    A fixed directory component disables the rule matcher's basename fallback for
    anchored patterns. Its wildcard semantics stay shared with the rule matcher.
    Only anchored trailing slashes declare a directory prefix.
    """
    if not isinstance(path, str) or not path or len(path) > MAX_CONFIG_BYTES:
        return None
    relative = match.normalize_path(path)
    if not relative or ".." in relative.split("/"):
        return None
    for glob in paths.matching:
        pattern = _normalize(glob)
        if pattern.startswith("/"):
            pattern = pattern[1:] + ("**" if pattern.endswith("/") else "")
            contained = match.matches("lease-root/" + pattern, "lease-root/" + relative)
        else:
            contained = match.matches(pattern, relative)
        if contained:
            return glob
    return None


def _root_file(root, name: str) -> bool:
    """Probe a regular root file without reading its content or following links."""
    try:
        # The storage boundary requires exact str components, not subclasses.
        # This I/O spelling never flows back into lease or rule matching.
        with storage.confined_file(root.absolute(), (str(name),)) as handle:
            handle.read_bytes(0)
        return True
    except storage.ConfinedFileError as exc:
        # A zero-byte cap refuses nonempty regular files before reading them.
        return exc.reason == "too_large"
    except OSError:
        return False  # A relative trusted root can lose its cwd before absolute().


def anchor_next_action(root, paths: PathSet, found, lane: str, now: int) -> str:
    """Suggest anchors only when they remove every live conflict in this snapshot.

    This is advisory: claims still re-read leases on retry and run the real overlap
    guard. Missing/unsafe files and unsupported platforms keep the original refusal.
    """
    live = [lease for lease in found.leases if not lease.expired(now)]
    if found.unreadable or any(lease.lane == lane for lease in live):
        return ""
    try:
        top = gitsafe.toplevel(root)
    except (OSError, gitsafe.GitError):
        return ""
    if top is None:
        return ""
    anchored = []
    alternatives = []
    for path in paths.raw:
        if "/" not in path and _WILDCARD.search(path) is None and _root_file(top, path):
            path = "/" + path
            anchored.append(path)
        alternatives.append(path)
    if not anchored or any(overlap(PathSet(tuple(alternatives), tuple(alternatives)), lease.path_set)
                           for lease in live):
        return ""
    text = "Retry with root-anchored lease paths: " + ", ".join(anchored) + "; slashless paths cover every depth."
    canonical = sanitize_display(text, max_len=None)
    return sanitize_display(redact_command_secrets(canonical), max_len=512)


def legacy_recovery(paths: PathSet, lane: str, oid: str) -> str:
    """Fixed recovery text; lane and OID come from the validated lease/ref."""
    return (f"; release {lane} --expect {oid}, then claim each path as its own entry"
            if paths.legacy else "")
