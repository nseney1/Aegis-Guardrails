"""Read-only repository lane status, with optional checks of captured branch tips.

Lease expiry and missing branches describe stale declarations, never actor liveness.
The report keeps unreadable leases visible and never writes refs, events or worktrees.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from aegis_core import gitsafe, lane_gate, team

__all__ = ["status", "supervisor_health"]


def _branch(root: Path, name: Optional[str]) -> Tuple[Optional[str], str]:
    if name is None:
        return None, "unrecorded"
    # A lease branch is a display label, not a revision expression or a tag.
    ref = name if name.startswith("refs/") else "refs/heads/" + name
    if not ref.startswith(("refs/heads/", "refs/remotes/")):
        return None, "missing"
    try:
        oid = gitsafe.read_ref(root, ref)
    except gitsafe.RefNameError:
        return None, "missing"
    if oid is None:
        return None, "missing"
    if gitsafe.resolve_commit(root, oid) != oid:
        raise gitsafe.GitError(f"branch {ref!r} does not name a readable commit")
    return oid, "available"


def _distance(root: Path, base: str, tip: str) -> Tuple[int, int]:
    shallow = gitsafe.run_checked(["rev-parse", "--is-shallow-repository"], root).stdout.strip()
    if shallow != b"false":
        raise gitsafe.GitError("ahead/behind requires complete history; repository is shallow or unreadable")
    counts = gitsafe.run_checked(["rev-list", "--left-right", "--count", base + "..." + tip, "--"], root)
    parts = counts.stdout.split()
    if len(parts) != 2 or not all(value.isdigit() for value in parts):
        raise gitsafe.GitError("git rev-list returned invalid ahead/behind counts")
    behind, ahead = (int(value) for value in parts)
    return ahead, behind


def _check(root: Path, row: Dict[str, Any], base: Optional[str], now: int) -> Dict[str, Any]:
    reason = row.get("error")
    if reason is None and row["state"] != "live":
        reason = "the lease is expired"
    if reason is None and row["tip"] is None:
        reason = "the lease has no readable recorded branch"
    if reason is None and base is None:
        reason = "no base branch is available; pass --base"
    if reason is not None:
        return lane_gate.error_report(root, row["lane"], reason, now)
    try:
        result = lane_gate.check_lane(root, row["lane"], base=base, paths=row["paths"], now=now,
                                      tip=row["tip"], record=False)
        provenance = "lease@" + row["oid"]
        changes = tuple(replace(change, source=provenance) if change.source == "cli" else change
                        for change in result.changes)
        return replace(result, paths_source=provenance, changes=changes).as_dict()
    except (lane_gate.LaneGateError, lane_gate.LaneGateUsage, team.TeamFileError, gitsafe.GitError) as exc:
        return lane_gate.error_report(root, row["lane"], str(exc), now)


@gitsafe.scrubbed()
def status(root: Path, now: int, base: Optional[str] = None, check: bool = False) -> Dict[str, Any]:
    """One observation of every lease, pinned branch OIDs and their optional tip verdicts.

    Missing default base or per-lane evidence remains visible. An explicitly invalid
    base is a usage error. No report, including ``check=True``, records an event.
    """
    found = team.describe(root, now)
    ref = base if base is not None else gitsafe.resolve_base_ref(root)
    base_commit = gitsafe.resolve_commit(root, ref) if ref is not None else None
    if base is not None and base_commit is None:
        raise team.TeamUsageError(f"cannot resolve --base {base!r} to a commit")
    rows = []
    unknown = sorted(row["lane"] for row in found["unreadable"] if team.valid_lane(row["lane"]))
    for lease in found["leases"]:
        row = {**lease, "state": "expired" if lease["expired"] else "live", "stale": lease["expired"],
               "tip": None, "branch_state": "unreadable", "ahead": None, "behind": None,
               "unknown_overlaps": unknown, "error": None, "check": None}
        try:
            row["tip"], row["branch_state"] = _branch(root, lease["branch"])
            row["stale"] = row["stale"] or row["branch_state"] == "missing"
            if row["tip"] is not None and base_commit is not None:
                row["ahead"], row["behind"] = _distance(root, base_commit, row["tip"])
            elif base_commit is None:
                row["error"] = "no base branch is available; pass --base"
        except gitsafe.GitError as exc:
            row["error"] = str(exc)
        rows.append(row)
    rows.extend({**bad, "state": "unreadable", "stale": None, "owner": None, "role": None,
                 "expires_at": None, "branch": None, "paths": None, "tip": None,
                 "branch_state": "unreadable", "ahead": None, "behind": None,
                 "overlaps": [], "unknown_overlaps": [], "check": None} for bad in found["unreadable"])
    rows.sort(key=lambda row: row["lane"])
    if check:
        for row in rows:
            row["check"] = _check(root, row, base_commit, now)
    return {"base": ref, "base_commit": base_commit, "lanes": rows, "check_requested": check,
            "checks_passed": all(row["check"]["status"] == "pass" for row in rows) if check else None}


def supervisor_health(root, now, user_root=None):
    """One supervisor health projection. Lease status is a different report and is not changed."""
    from aegis_core import team_profile
    from aegis_core.team_supervisor import report
    def checked_load(root, **kwargs):
        loaded = team_profile.load(root, **kwargs)
        team_profile.validate_resolved(loaded, root)
        return loaded

    return report(checked_load, root, now, user_root, team_profile.ProfileError)
