"""aegis team — lane leases for parallel agents (v4.1 spec §1, ADR 0005 AD-7).

The dispatcher runs these; there is no MCP tool for them. ``claim``, ``renew`` and
``transfer`` print the lane's new lease oid alone on stdout, so a script can pass it to
the next ``--expect``. With ``--json`` stdout carries one document with ``source``,
``aegis_version``, ``checked_at`` (UTC) and ``scope``, refusals and errors included.

Host capacity check exits: 0 go, 3 hold, 4 fallback, 5 skip; 1 refused, 2 usage.
Other exit codes: 0 done; 1 refused (taken, overlap, stale, absent, expired, unreadable) or
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

from aegis_core import primitives
from aegis_cli import sanitize_display
from aegis_cli.base import AegisCommand, CommandCategory
from aegis_core import gitsafe, team
from aegis_core.primitives import utc_stamp
from aegis_core.team_profile import display_profile as display_profile

__all__ = ["TeamCommand", "run_team"]

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
ACTIONS = ("claim", "renew", "transfer", "release", "gc", "list", "status", "metrics")


def _team_payload(action: str, root: Path, now: int, **scope: Any) -> Dict[str, Any]:
    return {**primitives.envelope(f"aegis team {action}", {"workspace": str(root), **scope}, now=now),
            "schema": f"aegis.team.{action}/v1"}


def _emit(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2))


def _warn(warnings: List[str]) -> None:
    for line in warnings:
        print(f"Warning: {sanitize_display(line, max_len=None)}", file=sys.stderr)


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
        f"  {lease['lane']}  {state}  owner {sanitize_display(lease['owner'], max_len=None)}  role {sanitize_display(lease['role'], max_len=None)}  "
        f"gen {lease['gen']}  expires {lease['expires_at']}{skew}",
        f"    paths: {sanitize_display(', '.join(lease['paths']), max_len=None)}",
        f"    oid: {lease['oid']}" + (f"  branch: {sanitize_display(lease['branch'], max_len=None)}" if lease["branch"] else ""),
    ]
    if lease["overlaps"]:
        lines.append(f"    overlaps live: {', '.join(lease['overlaps'])}")
    return lines


# ── Lease changes ────────────────────────────────────────────────────────────

def _changed(args: argparse.Namespace, root: Path, now: int, change: team.LeaseChange) -> int:
    if args.json:
        payload = _team_payload(args.team_action, root, now, refs=team.LANES_REF, lane=change.lane)
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
        payload = _team_payload("gc", root, now, refs=team.LANES_REF)
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
        print(f"kept {sanitize_display(lane, max_len=None)}: {reason}", file=sys.stderr)
    return EXIT_OK


# ── Reading ──────────────────────────────────────────────────────────────────

def _list(args: argparse.Namespace, root: Path, now: int) -> int:
    found = team.describe(root, now)
    if args.json:
        payload = _team_payload("list", root, now, refs=team.LANES_REF)
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
        print(f"  {sanitize_display(bad['lane'], max_len=None)}  unreadable  oid {bad['oid']}: {sanitize_display(bad['error'], max_len=None)}")
    print(team.LEASE_NOTE)
    return EXIT_OK


def _status(args: argparse.Namespace, root: Path, now: int) -> int:
    from aegis_cli.formatters.text import render_team_status
    from aegis_core.team_status import status

    found = status(root, now, base=args.base, check=args.check)
    payload = _team_payload("status", root, now, refs=team.LANES_REF,
                            base=found.pop("base"), base_commit=found.pop("base_commit"))
    payload.update(note=team.LEASE_NOTE, **found)
    if args.json:
        _emit(payload)
    else:
        for line in render_team_status(payload):
            print(sanitize_display(line, max_len=None))
    return EXIT_REFUSED if found["checks_passed"] is False else EXIT_OK


def _metrics(args: argparse.Namespace, root: Path, now: int) -> int:
    merges = team.merge_metrics(root, base=args.base)
    counts = team.event_counts(root)
    span = merges.pop("range")
    if args.json:
        payload = _team_payload("metrics", root, now, **span)
        payload.update({"events": counts, "merges": merges})
        _emit(payload)
        return EXIT_OK
    reasons = ", ".join(f"{reason} {n}" for reason, n in counts["denials_by_reason"].items())
    print(f"Lease events: {counts['claims']} claims, {counts['denials']} denials"
          + (f" ({reasons})" if reasons else "") + f"; {counts['lanes_claimed']} lanes claimed")
    if counts["error"]:
        print(f"  events log unreadable: {sanitize_display(counts['error'], max_len=None)}")
    since = span["base"] if span["base"] is not None else "the first commit"
    tip = span["tip"][:12] if span["tip"] else "an unborn branch"
    print(f"First-parent merges on {tip} since {sanitize_display(since, max_len=None)}: {merges['count']}")
    print(f"  overlapping (both sides changed a common path): {merges['overlapping_merge']}")
    conflicting = merges["conflicting_merge"]
    if conflicting == "unavailable":
        conflicting = f"unavailable ({sanitize_display(merges['conflicting_unavailable'], max_len=None)})"
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
    "status": _status,
    "metrics": _metrics,
}


def _profile_command(args: argparse.Namespace, root: Path, now: int) -> int:
    """Configuration has its own envelope; lease payloads remain unchanged."""
    from aegis_core import team_profile

    noun = args.team_action
    verb = getattr(args, "config_action", None) if noun == "config" else getattr(args, "hosts_action", None)
    if noun == "hosts" and verb not in ("status", "check", "usage"):
        verb = None
    command = noun + (" " + verb if verb else "")
    schema = "aegis.team." + command.replace(" ", ".") + "/v1"
    payload = primitives.envelope("aegis team " + command, {"workspace": str(root)}, now=now)
    payload.update(schema=schema, schema_family="aegis.team." + noun + "/v1",
                   governance=team_profile.governance_status())
    code = EXIT_OK
    try:
        if noun == "config" and verb is None:
            payload.update(status="refused", reason="a config verb is required", layer="flags", file="<command-line>",
                           next_action="Run aegis team config show|presets|init --help.")
            code = EXIT_USAGE
        elif verb == "presets":
            payload.update(status="done", presets=list(team_profile.PRESET_DATA["presets"]),
                           host_kinds=team_profile.PRESET_DATA["hosts"],
                           next_action="Run aegis team config init --preset NAME --json.")
        elif verb == "init":
            document = team_profile.initialize(root, args.preset, host=args.host, force=args.force)
            payload.update(status="done", profile=team_profile.resolve(repo=document)["profile"],
                           next_action="Review the profile diff and use aegis approve; hosted aegis-governance gates approval before merge. Run aegis team doctor --json.")
        else:
            resolved = team_profile.load(root)
            if noun == "hosts":
                code = _hosts_result(args, resolved, payload)
            elif noun == "doctor":
                found = team_profile.doctor(resolved, root=root)
                _doctor_capacity(resolved, found)
                payload.update(found)
                if found["healthy"]:
                    payload.update(status="done", next_action="Review the resolved profile with aegis team config show --json.")
                else:
                    current = resolved["profile"]["preset"]
                    binding = next((item for item in found["runnable_bindings"] if item["preset"] == current), None)
                    missing = sorted({host["cli"] for host in found["hosts"] if not host["found"]})
                    action = "Install the missing declared CLI: " + ", ".join(missing) + "; rerun aegis team doctor --json."
                    if binding is not None and resolved.get("repository_profile_exists") is False:
                        command = "aegis team config init --preset " + current
                        if binding["host"] is not None:
                            command += " --host " + binding["host"]
                        action += " An available binding of the current preset is " + command + "; review any repository change through aegis approve before merge."
                    payload.update(status="refused", reason="a declared host CLI is missing from PATH",
                                   layer="repo", file=str(root.joinpath(*team_profile.REPO_PATH)),
                                   next_action=action)
                    code = EXIT_REFUSED
            else:
                payload.update(status="done", **resolved,
                               next_action="Run aegis team doctor --json before starting a run.")
    except team_profile.ProfileError as exc:
        payload.update(status="refused", reason=str(exc), layer=exc.layer, file=exc.file,
                       next_action="Correct the indicated file or command-line layer, then retry. Run aegis team config presets --json for preset and host choices; repository policy changes need aegis approve before merge.")
        code = exc.exit_code
    except (OSError, ValueError, RuntimeError):
        payload.update(status="refused", reason="profile operation unavailable", layer="filesystem",
                       file=str(root.joinpath(*team_profile.REPO_PATH)),
                       next_action="Check the trusted workspace and home directories and retry on a platform with anchored file operations.")
        code = EXIT_REFUSED
    payload = display_profile(payload, capacity=True)
    if args.json:
        _emit(payload)
    elif payload["status"] == "refused":
        print("refused: " + payload["reason"] + "\nnext_action: " + payload["next_action"], file=sys.stderr)
    else:
        # Preserve provenance and actionable instructions in the human view too.
        print(json.dumps(payload, indent=2))
    return code


def _doctor_capacity(resolved, found):
    """Compose health and capacity views without a profile/service cycle."""
    from aegis_core.team_hosts import HostCapacity

    capacity = {row["host"]: row for row in HostCapacity(resolved).status()}
    found["hosts"] = [{**host, **{key: value for key, value in capacity[host["name"]].items() if key != "host"}}
                      for host in found["hosts"]]
    found["write_scope"] = _capacity_write_scope(found["hosts"])


def _capacity_write_scope(rows):
    return list(dict.fromkeys(scope for row in rows for decision in row["decisions"]
                              for scope in decision.get("write_scope", [])))


def _hosts_result(args, resolved, payload):
    """Thin host view; all policy and advice live in the shared service."""
    from aegis_core import team_hosts, team_profile

    verb = args.hosts_action
    host, kind = args.host, args.kind
    if (verb not in ("status", "check", "usage") or
            (verb == "check" and (host is None or kind is None)) or
            (verb != "check" and (host is not None or kind is not None))):
        raise team_profile.ProfileError("use hosts status|usage or hosts check HOST KIND", layer="flags",
                                        file="<command-line>", exit_code=2)
    service = team_hosts.HostCapacity(resolved)
    payload.update(status="done", exit_codes=team_hosts.EXIT_CODES,
                   write_scope=resolved["write_scope"],
                   next_action="Run aegis team hosts status --json to choose a declared host and kind, then aegis team hosts check HOST KIND --json.")
    if verb == "check":
        result = service.check(host, kind)
        payload.update(result)
        return result["exit_code"]
    payload["hosts"] = service.status() if verb == "status" else service.usage()
    if verb == "status":
        payload["write_scope"] = _capacity_write_scope(payload["hosts"])
    return EXIT_OK


# ── Failures ─────────────────────────────────────────────────────────────────

def _failed(args: argparse.Namespace, root: Path, now: int, message: str, code: int) -> int:
    if args.json:
        payload = _team_payload(args.team_action, root, now)
        payload.update({"status": "error", "error": message})
        _emit(payload)
    else:
        print(f"Error: {sanitize_display(message, max_len=None)}", file=sys.stderr)
    return code


def _refused(args: argparse.Namespace, root: Path, now: int, exc: team.LeaseRefused) -> int:
    lease = _view(root, now, exc.current)
    if args.json:
        payload = _team_payload(args.team_action, root, now, refs=team.LANES_REF, lane=exc.lane)
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
    print(sanitize_display(str(exc), max_len=None), file=sys.stderr)
    for line in _lease_lines(lease):
        print(line, file=sys.stderr)
    return EXIT_REFUSED


def run_team(args: argparse.Namespace) -> int:
    action = getattr(args, "team_action", None)
    if action in ("config", "doctor", "hosts"):
        root = Path(args.ws.root) if getattr(args, "ws", None) is not None else Path(args.workspace)
        return _profile_command(args, root, int(time.time()))
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
    help = "Lease lane paths for parallel agents (claim, renew, transfer, release, gc, list, status, metrics)"
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
        config = sub.add_parser("config", parents=[common], help="Inspect or initialize a layered team profile")
        config_sub = config.add_subparsers(dest="config_action")
        config_sub.add_parser("show", parents=[common], help="Show every resolved value and its layer")
        config_sub.add_parser("presets", parents=[common], help="List built-in team presets")
        config_init = config_sub.add_parser("init", parents=[common], help="Write the repository team profile")
        config_init.add_argument("--preset", required=True, help="Preset name from config presets")
        config_init.add_argument("--host", default=None, metavar="KIND", help="Bind the preset host kind at initialization; see config presets --json")
        config_init.add_argument("--force", action="store_true", help="Replace an existing valid profile")
        sub.add_parser("doctor", parents=[common], help="Check profile completeness and host CLIs on PATH")
        hosts = sub.add_parser("hosts", parents=[common], help="Read host capacity and per-host usage",
                               description="Read capacity advice: status | usage | check HOST KIND. "
                               "KIND: writer, review, extra-review, doc, research, a declared role or lens. "
                               "check exits 0 go / 3 hold / 4 fallback / 5 skip; 1 refused / 2 usage. "
                               "Real usage readers are adapter extension points; credentials are never read.")
        hosts.add_argument("hosts_action", nargs="?", metavar="VERB", help="status, check or usage")
        hosts.add_argument("host", nargs="?", metavar="HOST", help="Declared host alias (see status --json)")
        hosts.add_argument("kind", nargs="?", metavar="KIND", help="Job kind or declared role/lens")
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
        status = sub.add_parser("status", parents=[common], help="Inspect every lane, branch and optional tip verdict",
                                description=team.LEASE_NOTE + " Inspection changes no leases, worktrees or events.")
        status.add_argument("--base", default=None, metavar="REF",
                            help="Compare branch tips to this commit (default: the base resolved by check --lane)")
        status.add_argument("--check", action="store_true",
                            help="Check each live lane's captured branch tip; exit 1 for failed or unavailable verdicts")
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
