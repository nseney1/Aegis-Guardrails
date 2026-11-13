"""Lease event counts and merge outcomes, shared by the team public surface."""
from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Set

from aegis_core import events, gitsafe
from aegis_core.errors import AegisValidationError

__all__ = ["TeamUsageError", "event_counts", "merge_metrics", "repository_root"]

_SYNTHETIC_MERGE = re.compile(r"\Arefs/(?:remotes/)?pull/[^/]+/merge\Z")


class TeamUsageError(AegisValidationError):
    """A lane name, glob, ttl, label, expected object id or base that cannot be used;
    nothing was written."""

    # Keep historical exception names and pickle payloads valid through team.
    __module__ = "aegis_core.team"


def repository_root(root: Any) -> Path:
    path = Path(os.fspath(root))
    if gitsafe.common_dir(path) is None:
        raise TeamUsageError("not in a git repository: aegis team keeps leases in git refs")
    return path


# ── Metrics ──────────────────────────────────────────────────────────────────

_CLAIMS = ("claimed", "taken_over")


def event_counts(root: Any) -> Dict[str, Any]:
    """Lease events from the log: ``claims`` (claimed or taken over), ``denials`` and
    their ``denials_by_reason``, every change ``by_result``, the distinct
    ``lanes_claimed``, the ``first`` and ``last`` row times, and ``unusable_rows``
    (torn, unparseable, another version, malformed). Reads only."""
    found = events.read(root, ("lease_claimed", "lease_denied"))
    by_result: Dict[str, int] = {}
    by_reason: Dict[str, int] = {}
    lanes: Set[str] = set()
    stamps: List[str] = []
    claims = denials = 0
    for row in found.rows:
        detail = row["detail"]
        if detail.get("queue") is True:
            continue
        stamps.append(row["ts"])
        if row["event"] == "lease_denied":
            denials += 1
            reason = detail.get("reason")
            key = reason if isinstance(reason, str) else "unknown"
            by_reason[key] = by_reason.get(key, 0) + 1
            continue
        result = row["result"]
        by_result[result] = by_result.get(result, 0) + 1
        if result in _CLAIMS:
            claims += 1
            if isinstance(detail.get("lane"), str):
                lanes.add(detail["lane"])
    return {
        "claims": claims,
        "denials": denials,
        "denials_by_reason": dict(sorted(by_reason.items())),
        "by_result": dict(sorted(by_result.items())),
        "lanes_claimed": len(lanes),
        "first": min(stamps) if stamps else None,
        "last": max(stamps) if stamps else None,
        "unusable_rows": found.skipped + int(found.torn_tail) + found.unknown_version + found.malformed,
        "error": found.error,
    }


def _synthetic_merges(root: Path) -> Set[str]:
    """Commits GitHub's ``refs/pull/<n>/merge`` (or actions/checkout's
    ``refs/remotes/pull/<n>/merge``) name: trial merges, never part of a branch."""
    found: Set[str] = set()
    for prefix in ("refs/pull", "refs/remotes/pull"):
        found.update(oid for name, oid in gitsafe.list_refs(root, prefix) if _SYNTHETIC_MERGE.match(name))
    return found


def _rev_list(root: Path, args: Sequence[str]) -> List[List[str]]:
    res = gitsafe.run(["rev-list", *args], root)
    if res.returncode != 0:
        raise gitsafe.GitError(f"git rev-list failed in {root}")
    return [line.split() for line in os.fsdecode(res.stdout).splitlines() if line.strip()]


def _changed_paths(root: Path, base: str, side: str) -> Set[str]:
    return {entry[3] for entry in gitsafe.diff_entries(root, base, side)}


def _both_sides_changed(root: Path, parents: Sequence[str]) -> Optional[bool]:
    """Whether the first parent and another parent both changed a path since their merge
    base; None when they share no history."""
    first = parents[0]
    for other in parents[1:]:
        base = gitsafe.merge_base(root, first, other)
        if base is None:
            return None
        ours = _changed_paths(root, base, first)
        if ours and ours & _changed_paths(root, base, other):
            return True
    return False


def merge_metrics(root: Any, base: Optional[str] = None) -> Dict[str, Any]:
    """Per first-parent merge on the current branch since ``base``, oldest first:
    ``overlapping`` (both sides changed a common path since the merge base) and
    ``conflicting`` (``git merge-tree --write-tree`` reports a conflict; None and
    ``conflicting_merge: "unavailable"`` when git cannot say, as before 2.38). A merge
    of unrelated histories has neither answer (both None) and counts in neither.

    Without ``base`` the branch base is resolved as ``aegis check --lane`` resolves it
    (``gitsafe.resolve_base_ref``); with none found, the whole first-parent history
    counts. A HEAD that is GitHub's synthetic pull-request merge is replaced by the pull
    request's head, and synthetic merges are never counted. Reads refs only (the trial
    merges store unreferenced objects). Raises TeamUsageError for a base that names no
    commit, GitError when git fails."""
    repo = repository_root(root)
    if base is None:
        base = gitsafe.resolve_base_ref(repo)
    base_commit = None
    if base is not None:
        base_commit = gitsafe.resolve_commit(repo, base) if isinstance(base, str) else None
        if not base_commit:
            raise TeamUsageError(f"cannot resolve --base {base!r} to a commit")
    head = gitsafe.head_commit(repo)
    synthetic = _synthetic_merges(repo) if head is not None else set()
    tip, synthetic_head, excluded = head, False, 0
    if head is not None and head in synthetic:
        parents = _rev_list(repo, ["--no-walk", "--parents", head])[0][1:]
        if len(parents) >= 2:
            tip, synthetic_head, excluded = parents[1], True, 1
    merges: List[Dict[str, Any]] = []
    unavailable: Optional[str] = None
    if tip is not None:
        args = ["--first-parent", "--merges", "--parents", "--reverse", tip]
        if base_commit:
            args.append(f"^{base_commit}")
        for commit, *parents in _rev_list(repo, [*args, "--"]):
            if commit in synthetic:
                excluded += 1
                continue
            overlapping = _both_sides_changed(repo, parents)
            conflicting: Optional[bool] = None
            # Unrelated histories have no merge base, and merge-tree refuses to merge them.
            if unavailable is None and overlapping is not None:
                try:
                    conflicting = any(gitsafe.merge_tree_conflicted(repo, parents[0], p) for p in parents[1:])
                except gitsafe.MergeTreeUnavailable as exc:
                    unavailable = str(exc)
            merges.append({"commit": commit, "parents": parents, "overlapping": overlapping,
                           "conflicting": conflicting})
    if unavailable is not None:
        for merge in merges:
            merge["conflicting"] = None
    return {
        "range": {"base": base, "base_commit": base_commit, "head": head, "tip": tip,
                  "synthetic_head": synthetic_head},
        "count": len(merges),
        "overlapping_merge": sum(1 for m in merges if m["overlapping"] is True),
        "conflicting_merge": "unavailable" if unavailable is not None else sum(
            1 for m in merges if m["conflicting"] is True),
        "conflicting_unavailable": unavailable,
        "excluded_synthetic": excluded,
        "merges": merges,
    }
