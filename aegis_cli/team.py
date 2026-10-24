"""aegis team — lane leases for parallel agents (v4.1 spec §1, ADR 0005 AD-7).

The dispatcher runs these; there is no MCP tool for them. ``claim``, ``renew`` and
``transfer`` print the lane's new lease oid alone on stdout, so a script can pass it to
the next ``--expect``. With ``--json`` stdout carries one document with ``source``,
``aegis_version``, ``checked_at`` (UTC) and ``scope``, refusals and errors included.

Exit codes: 0 done; 1 refused (taken, overlap, stale, absent, expired, unreadable) or
git failed; 2 usage (an invalid lane name, glob, ttl, label or ``--expect``, a base
that names no commit, no git repository). ``list`` and ``metrics`` change nothing.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from aegis_cli import sanitize_display
from aegis_cli.base import AegisCommand, CommandCategory
from aegis_core import gitsafe, team
from aegis_core._version import __version__
from aegis_core.primitives import utc_stamp

__all__ = ["TeamCommand", "run_team"]

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
ACTIONS = ("claim", "renew", "transfer", "release", "gc", "list", "metrics")


def _envelope(action: str, root: Path, now: int, **scope: Any) -> Dict[str, Any]:
    return {
        "source": f"aegis team {action}",
        "aegis_version": __version__,
        "checked_at": utc_stamp(now),
        "scope": {"workspace": str(root), **scope},
    }


def _emit(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2))


def _text(value: object) -> str:
    """Repository-chosen text (labels, globs, git's messages) without terminal controls."""
    text = str(value)
    return sanitize_display(text, max_len=len(text))  # stripped text is never longer: no cut


def _warn(warnings: List[str]) -> None:
    for line in warnings:
        print(f"Warning: {_text(line)}", file=sys.stderr)


def _view(root: Path, now: int, oid: Optional[str]) -> Optional[Dict[str, Any]]:
    """The list view (current overlaps included) of the lease blob ``oid``, or None when
    no lane holds it now (released, replaced since, or unreadable)."""
    if oid is not None:
        for entry in team.describe(root, now)["leases"]:
            if entry["oid"] == oid:
                return entry
    return None


def _lease_lines(lease: Optional[Dict[str, Any]]) -> List[str]:
    if lease is None:
        return []
    state = "expired" if lease["expired"] else "live"
    skew = " (writer clock ahead)" if lease["clock_skew"] else ""
    lines = [
        f"  {lease['lane']}  {state}  owner {_text(lease['owner'])}  role {_text(lease['role'])}  "
        f"gen {lease['gen']}  expires {lease['expires_at']}{skew}",
        f"    paths: {_text(', '.join(lease['paths']))}",
        f"    oid: {lease['oid']}" + (f"  branch: {_text(lease['branch'])}" if lease["branch"] else ""),
    ]
    if lease["overlaps"]:
        lines.append(f"    overlaps live: {', '.join(lease['overlaps'])}")
    return lines


# ── Lease changes ────────────────────────────────────────────────────────────

def _changed(args: argparse.Namespace, root: Path, now: int, change: team.LeaseChange) -> int:
    if args.json:
        payload = _envelope(args.team_action, root, now, refs=team.LANES_REF, lane=change.lane)
        payload.update({
            "status": change.action,
            "oid": change.oid,
            "previous": change.previous,
            "lease": _view(root, now, change.oid),
            "caller": change.caller,
            "warnings": list(change.warnings),
        })
        _emit(payload)
        return EXIT_OK
    _warn(list(change.warnings))
    print(change.oid if change.oid is not None else f"released {change.lane}")
    return EXIT_OK


def _claim(args: argparse.Namespace, root: Path, now: int) -> int:
    change = team.claim(root, args.lane, args.paths, role=args.role, owner=args.owner, ttl_s=args.ttl,
                        branch=args.branch, now=now)
    return _changed(args, root, now, change)


def _renew(args: argparse.Namespace, root: Path, now: int) -> int:
    return _changed(args, root, now, team.renew(root, args.lane, args.expect, ttl_s=args.ttl, now=now))


def _transfer(args: argparse.Namespace, root: Path, now: int) -> int:
    change = team.transfer(root, args.lane, args.expect, owner=args.owner, role=args.role, now=now)
    return _changed(args, root, now, change)


def _release(args: argparse.Namespace, root: Path, now: int) -> int:
    return _changed(args, root, now, team.release(root, args.lane, args.expect))


def _gc(args: argparse.Namespace, root: Path, now: int) -> int:
    result = team.gc(root, now=now)
    warnings = [line for change in result.collected for line in change.warnings]
    if args.json:
        payload = _envelope("gc", root, now, refs=team.LANES_REF)
        payload.update({
            "status": "collected" if result.collected else "nothing to collect",
            "collected": [{"lane": c.lane, "previous": c.previous, "caller": c.caller} for c in result.collected],
            "kept": [{"lane": lane, "reason": reason} for lane, reason in result.kept],
            "warnings": warnings,
        })
        _emit(payload)
        return EXIT_OK
    _warn(warnings)
    for change in result.collected:
        print(f"collected {change.lane}")
    if not result.collected:
        print("nothing to collect")
    for lane, reason in result.kept:
        print(f"kept {_text(lane)}: {reason}", file=sys.stderr)
    return EXIT_OK


# ── Reading ──────────────────────────────────────────────────────────────────

def _list(args: argparse.Namespace, root: Path, now: int) -> int:
    found = team.describe(root, now)
    if args.json:
        payload = _envelope("list", root, now, refs=team.LANES_REF)
        payload.update({"note": team.LEASE_NOTE, **found})
        _emit(payload)
        return EXIT_OK
    if not found["leases"] and not found["unreadable"]:
        print(f"There are no leases under {team.LANES_REF}.")
    else:
        print(f"Leases under {team.LANES_REF} (checked {utc_stamp(now)}):")
    for lease in found["leases"]:
        for line in _lease_lines(lease):
            print(line)
    for bad in found["unreadable"]:
        print(f"  {_text(bad['lane'])}  unreadable  oid {bad['oid']}: {_text(bad['error'])}")
    print(team.LEASE_NOTE)
    return EXIT_OK


def _metrics(args: argparse.Namespace, root: Path, now: int) -> int:
    merges = team.merge_metrics(root, base=args.base)
    counts = team.event_counts(root)
    span = merges.pop("range")
    if args.json:
        payload = _envelope("metrics", root, now, **span)
        payload.update({"events": counts, "merges": merges})
        _emit(payload)
        return EXIT_OK
    reasons = ", ".join(f"{reason} {n}" for reason, n in counts["denials_by_reason"].items())
    print(f"Lease events: {counts['claims']} claims, {counts['denials']} denials"
          + (f" ({reasons})" if reasons else "") + f"; {counts['lanes_claimed']} lanes claimed")
    if counts["error"]:
        print(f"  events log unreadable: {_text(counts['error'])}")
    since = span["base"] if span["base"] is not None else "the first commit"
    tip = span["tip"][:12] if span["tip"] else "an unborn branch"
    print(f"First-parent merges on {tip} since {_text(since)}: {merges['count']}")
    print(f"  overlapping (both sides changed a common path): {merges['overlapping_merge']}")
    conflicting = merges["conflicting_merge"]
    if conflicting == "unavailable":
        conflicting = f"unavailable ({_text(merges['conflicting_unavailable'])})"
    print(f"  conflicting (git merge-tree): {conflicting}")
    if merges["excluded_synthetic"]:
        print(f"  excluded synthetic pull-request merges: {merges['excluded_synthetic']}")
    return EXIT_OK


_HANDLERS: Dict[str, Callable[[argparse.Namespace, Path, int], int]] = {
    "claim": _claim,
    "renew": _renew,
    "transfer": _transfer,
    "release": _release,
    "gc": _gc,
    "list": _list,
    "metrics": _metrics,
}


# ── Failures ─────────────────────────────────────────────────────────────────

def _failed(args: argparse.Namespace, root: Path, now: int, message: str, code: int) -> int:
    if args.json:
        payload = _envelope(args.team_action, root, now)
        payload.update({"status": "error", "error": message})
        _emit(payload)
    else:
        print(f"Error: {_text(message)}", file=sys.stderr)
    return code


def _refused(args: argparse.Namespace, root: Path, now: int, exc: team.LeaseRefused) -> int:
    lease = _view(root, now, exc.current)
    if args.json:
        payload = _envelope(args.team_action, root, now, refs=team.LANES_REF, lane=exc.lane)
        payload.update({
            "status": "refused",
            "reason": exc.reason,
            "message": str(exc),
            "current": exc.current,
            "lanes": list(exc.lanes),
            "lease": lease,
            "warnings": list(exc.warnings),
        })
        _emit(payload)
        return EXIT_REFUSED
    _warn(list(exc.warnings))
    print(_text(str(exc)), file=sys.stderr)
    for line in _lease_lines(lease):
        print(line, file=sys.stderr)
    return EXIT_REFUSED


def run_team(args: argparse.Namespace) -> int:
    action = getattr(args, "team_action", None)
    if action not in _HANDLERS:
        print(f"usage: aegis team {{{','.join(ACTIONS)}}} ...", file=sys.stderr)
        print("aegis team --help describes each action.", file=sys.stderr)
        return EXIT_USAGE
    root = Path(args.ws.root) if getattr(args, "ws", None) is not None else Path(args.workspace)
    now = int(time.time())
    try:
        return _HANDLERS[action](args, root, now)
    except team.LeaseRefused as exc:
        return _refused(args, root, now, exc)
    except team.TeamUsageError as exc:
        return _failed(args, root, now, str(exc), EXIT_USAGE)
    except gitsafe.GitError as exc:
        return _failed(args, root, now, str(exc), EXIT_REFUSED)


class TeamCommand(AegisCommand):
    """Lane leases: cooperative conflict input for parallel agents."""

    name = "team"
    category = CommandCategory.WORKFLOW
    help = "Lease lane paths for parallel agents (claim, renew, transfer, release, gc, list, metrics)"
    description = (
        "Leases under refs/aegis/lanes/<lane> declare which paths a lane works on. A lease is "
        "cooperative conflict input, not a lock, not an identity and not proof that an agent is "
        "alive: claims of different lanes can race, and owner and role are display labels. The "
        "backstops are the post-lane gate (aegis check --lane) and aegis team metrics."
    )

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        common = argparse.ArgumentParser(add_help=False)
        common.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                            help="Emit machine-readable JSON output")
        common.add_argument("--plain", action="store_true", default=argparse.SUPPRESS,
                            help="Strip ANSI styling and emoji")
        common.add_argument("--workspace", type=str, default=argparse.SUPPRESS, help="Target workspace root")
        sub = parser.add_subparsers(dest="team_action", metavar="ACTION")
        lane_help = f"Lane name: {team.LANE_GRAMMAR}"
        expect_help = "The lease oid the lane must hold now (printed by claim, renew, transfer and list)"

        claim = sub.add_parser(
            "claim", parents=[common], help="Lease a lane's paths; prints the lease oid",
            description=(
                "Refuse when a live lease of another lane may overlap the paths; otherwise create the "
                "lane's lease, or take over its expired lease. Prints the new lease oid."
            ),
        )
        claim.add_argument("lane", metavar="LANE", help=lane_help)
        claim.add_argument("--paths", nargs="+", required=True, metavar="GLOB",
                           help="Globs the lane will change (the conflict scope)")
        claim.add_argument("--role", default=None, help=f"Display label (default: {team.DEFAULT_ROLE})")
        claim.add_argument("--owner", default=None, help="Display label (default: <user>@<hostname>)")
        claim.add_argument("--ttl", type=int, default=team.DEFAULT_TTL_S, metavar="SECONDS",
                           help=f"Seconds until the lease expires, at most {team.MAX_TTL_S}")
        claim.add_argument("--branch", default=None, help="The lane's branch, recorded for display")

        renew = sub.add_parser(
            "renew", parents=[common], help="Extend a lease; prints the new lease oid",
            description="Renew by compare-and-swap; an expired lease is re-claimed, overlap check included.",
        )
        renew.add_argument("lane", metavar="LANE", help=lane_help)
        renew.add_argument("--expect", required=True, metavar="OID", help=expect_help)
        renew.add_argument("--ttl", type=int, default=None, metavar="SECONDS",
                           help=f"New lifetime in seconds, at most {team.MAX_TTL_S} (default: keep it)")

        transfer = sub.add_parser("transfer", parents=[common], help="Give a live lease to another owner",
                                  description="Change a live lease's owner (and role) by compare-and-swap.")
        transfer.add_argument("lane", metavar="LANE", help=lane_help)
        transfer.add_argument("--expect", required=True, metavar="OID", help=expect_help)
        transfer.add_argument("--owner", required=True, help="The new owner label")
        transfer.add_argument("--role", default=None, help="The new role label (default: keep it)")

        release = sub.add_parser(
            "release", parents=[common], help="Delete a lease",
            description="Delete a lease by compare-and-swap. Anyone may release; the events log records the caller.",
        )
        release.add_argument("lane", metavar="LANE", help=lane_help)
        release.add_argument("--expect", required=True, metavar="OID", help=expect_help)

        sub.add_parser("gc", parents=[common], help="Delete expired leases",
                       description="Delete every expired lease by compare-and-swap; unreadable leases are kept.")
        sub.add_parser("list", parents=[common], help="Show leases (conflict input, not liveness proof)",
                       description=team.LEASE_NOTE)
        metrics = sub.add_parser(
            "metrics", parents=[common], help="Lease events and merge outcomes",
            description=(
                "Claims and denials from the events log, and for each first-parent merge since --base: "
                "whether both sides changed a common path and whether git merge-tree reports a conflict "
                "(unavailable before git 2.38). GitHub's synthetic refs/pull/*/merge commits are excluded."
            ),
        )
        metrics.add_argument("--base", default=None, metavar="REF",
                             help="Count merges since this commit (default: the branch base, as for "
                                  "aegis check --lane: origin/$GITHUB_BASE_REF, the branch origin/HEAD names, then main, "
                                  "develop or master; "
                                  "with none, the whole first-parent history)")

    def execute(self, args: argparse.Namespace) -> int:
        return run_team(args)
