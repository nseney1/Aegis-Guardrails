"""CODEOWNERS parsing and coverage of the canonical governance paths (L1)."""
from __future__ import annotations

import fnmatch
import re
from typing import List, Optional, Sequence, Tuple

from aegis_core import governance

__all__ = ["CODEOWNERS_LOCATIONS", "COVERAGE_SAMPLES", "codeowners_coverage", "codeowners_lines", "parse_codeowners"]

CODEOWNERS_LOCATIONS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
COVERAGE_SAMPLES: Tuple[str, ...] = tuple(dict.fromkeys(governance.coverage_samples() + CODEOWNERS_LOCATIONS))
_OWNER = re.compile(r"\A(?:@[A-Za-z0-9][A-Za-z0-9-]*(?:/[A-Za-z0-9._-]+)?|[^@\s]+@[^@\s]+\.[^@\s]+)\Z")
_MAX_CODEOWNERS_LINES = 5000
_MAX_PATTERN = 300


def parse_codeowners(text: str, *, org_login: Optional[str] = None) -> List[Tuple[str, Tuple[str, ...]]]:
    # GitHub ignores the bare handle of the organization that owns the repository (it takes a user,
    # @org/team or an email), so that owner is dropped when the caller knows the owner is one.
    org_handle = f"@{org_login}".lower() if org_login else None
    entries: List[Tuple[str, Tuple[str, ...]]] = []
    for line in text.splitlines()[:_MAX_CODEOWNERS_LINES]:
        tokens = line.strip().split()
        if not tokens or tokens[0].startswith("#"):
            continue
        owners: List[str] = []
        for token in tokens[1:]:
            if token.startswith("#"):
                break
            if _OWNER.match(token) and token.lower() != org_handle:
                owners.append(token)
        entries.append((tokens[0], tuple(owners)))
    return entries


def _segment_match(pattern: str, text: str) -> bool:
    return fnmatch.fnmatchcase(text, pattern.replace("**", "*"))


def _prefix_ends(segments: List[str], parts: List[str], start: int) -> List[int]:
    ends = {start} if not segments else set()
    reach = {(0, start)}
    seen = set()
    while reach:
        si, pi = reach.pop()
        if (si, pi) in seen:
            continue
        seen.add((si, pi))
        if si == len(segments):
            ends.add(pi)
            continue
        seg = segments[si]
        if seg == "**":
            for end in range(pi, len(parts) + 1):
                reach.add((si + 1, end))
        elif pi < len(parts) and _segment_match(seg, parts[pi]):
            reach.add((si + 1, pi + 1))
    return sorted(ends)


def _codeowners_match(pattern: str, path: str) -> bool:
    # A bracket or a backslash never gets here: codeowners_coverage reads such a file as unsupported.
    if not pattern or len(pattern) > _MAX_PATTERN or pattern[0] == "!":
        return False
    directory = pattern.endswith("/")
    core = pattern.strip("/")
    if not core:
        return False
    anchored = pattern.startswith("/") or "/" in core
    segments = core.split("/")
    parts = path.split("/")
    starts = [0] if anchored else range(len(parts))
    for start in starts:
        for end in _prefix_ends(segments, parts, start):
            if (end == len(parts) and not directory) or (end > start and directory):
                return True
    return False


def codeowners_coverage(
    text: str,
    location: str = "CODEOWNERS",
    *,
    repo_paths: Sequence[str] = (),
    org_login: Optional[str] = None,
) -> Tuple[List[str], List[str]]:
    entries = parse_codeowners(text, org_login=org_login)
    covered: List[str] = []
    uncovered: List[str] = []
    unsupported = any(any(c in pat for c in "[]\\") for pat, _ in entries)
    targets = dict.fromkeys(
        (
            *COVERAGE_SAMPLES,
            location.lstrip("/"),
            *(p.lstrip("/") for p in repo_paths if p and p.lstrip("/")),
        )
    )
    for path in targets:
        owners: Tuple[str, ...] = ()
        if not unsupported:
            for pattern, found in entries:
                if pattern.startswith("!"):
                    if not pattern[1:] or _codeowners_match(pattern[1:], path):
                        owners = ()
                elif _codeowners_match(pattern, path):
                    owners = found
        if owners:
            covered.append(path)
        else:
            uncovered.append(path)
    return covered, uncovered


codeowners_lines = governance.codeowners_lines
