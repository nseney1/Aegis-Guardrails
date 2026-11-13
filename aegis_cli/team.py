"""aegis team — lane leases for parallel agents (v4.1 spec §1, ADR 0005 AD-7).

The dispatcher runs these; there is no MCP tool for them. ``claim``, ``renew`` and
``transfer`` print the lane's new lease oid alone on stdout, so a script can pass it to
the next ``--expect``. With ``--json`` stdout carries one document with ``source``,
``aegis_version``, ``checked_at`` (UTC) and ``scope``, refusals and errors included.

Host capacity check exits: 0 go, 3 hold, 4 fallback, 5 skip; 1 refused, 2 usage.
Other exit codes: 0 done; 1 refused (taken, overlap, stale, absent, expired, unreadable) or
git failed; 2 usage (an invalid lane name, glob, ttl, label or ``--expect``, a base
that names no commit, no git repository). ``list`` and ``metrics`` change nothing.
``model`` uses the public model-selection core and always emits JSON, exiting 2
on refusal. Its MCP counterpart shares the core; neither launches a host.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from functools import partial
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

MODEL_REQUIRED = ("bindings", "policy", "history", "task_kind", "role_kind", "subject", "host_kinds")
MODEL_OPTIONAL = ("intent", "author_family", "lane_family", "review_stage", "record")


def _model_output_safe(value):
    """Refuse any changed field; successful operational values stay lossless."""
    from aegis_core.redaction import redact_command_secrets

    if isinstance(value, dict):
        return all(_model_output_safe(key) and _model_output_safe(item) for key, item in value.items())
    if isinstance(value, list):
        return all(_model_output_safe(item) for item in value)
    if isinstance(value, str):
        return value == sanitize_display(redact_command_secrets(sanitize_display(value, max_len=None)), max_len=512)
    return True


def model_argument_refusal(arguments):
    """Validate shape, types and bounds before workspace or path operations."""
    from aegis_core.model_select import MAX_INPUT_BYTES

    if (type(arguments) is not dict or
            not set(MODEL_REQUIRED) <= arguments.keys() or
            any(key not in MODEL_REQUIRED + MODEL_OPTIONAL for key in arguments)):
        return {"error": "invalid_model_arguments"}
    args = dict(arguments)
    for key in MODEL_REQUIRED + MODEL_OPTIONAL:
        if key in ("host_kinds", "record") or key not in args:
            continue
        value = args[key]
        if (value is None and key in MODEL_OPTIONAL):
            continue
        if type(value) is not str or len(value) > MAX_INPUT_BYTES:
            return {"error": "invalid_model_arguments"}
    hosts = args["host_kinds"]
    if (type(hosts) is not list or not 1 <= len(hosts) <= 256 or
            any(type(host) is not str or len(host) > 128 for host in hosts) or
            type(args.get("record", False)) is not bool):
        return {"error": "invalid_model_arguments"}
    return None


def model_result(arguments, root=None):
    """CLI/MCP adapter over the public selector; no adapter-owned file opens."""
    from aegis_core import model_select
    from aegis_core.config import env_workspace
    from aegis_core.storage import LockTimeoutError
    from aegis_core.errors import PathTraversalError
    from aegis_core.workspace import confine_path
    from aegis_core.workspace.base import Workspace
    from aegis_core.workspace.binding import resolve_cli_root
    from aegis_core.workspace.layout import has_rules_dir

    refusal = model_argument_refusal(arguments)
    if refusal is not None:
        return refusal
    args = dict(arguments)
    hosts = args["host_kinds"]
    try:
        if isinstance(root, Workspace):
            root = root.root
        if root is not None:
            if not isinstance(root, (str, Path)):
                return {"error": "model_workspace_unavailable"}
            root = str(root)
            if len(root) > model_select.MAX_INPUT_BYTES or root.count("/") + root.count("\\") > 256:
                return {"error": "model_workspace_unavailable"}
        workspace = Workspace(root=resolve_cli_root(explicit=root, pin=env_workspace()))
        if not has_rules_dir(workspace.root):
            return {"error": "model_workspace_unavailable"}
    except (OSError, ValueError, RuntimeError):
        return {"error": "model_workspace_unavailable"}
    try:
        # Bound raw path text before pathlib allocation. The core owns no-follow
        # descriptor walks, file byte caps and strict JSON validation.
        for key in ("bindings", "policy", "history"):
            value = args[key]
            if value.count("/") + value.count("\\") > 256:
                return {"error": "invalid_model_arguments"}
            path = Path(value)
            if path.is_absolute() or ".." in path.parts:
                return {"error": "invalid_model_arguments"}
            confine_path(value, workspace)
            # Keep the original spelling so the core no-follow walk still rejects
            # symlinks introduced before or after the confinement check.
            args[key] = str(workspace.root / path)
        requested = {key: args[key] for key in MODEL_REQUIRED + MODEL_OPTIONAL
                     if key in args and key not in ("bindings", "policy", "history", "record")}
        if not _model_output_safe(requested):
            return {"error": "model_output_needs_redaction"}
        options = {key: args[key] for key in ("subject", "intent", "author_family", "lane_family", "review_stage")
                   if key in args and args[key] is not None}
        if args.get("record", False):
            choice, record = model_select.select_and_append(
                args["history"], args["bindings"], args["policy"], args["task_kind"], args["role_kind"],
                host_kinds=hosts, **options)
        else:
            history = model_select.read_decisions(args["history"])
            try:
                choice, record = model_select.select_model(
                    args["bindings"], args["policy"], args["task_kind"], args["role_kind"], history,
                    host_kinds=hosts, **options)
            finally:
                history.close()
        result = {"choice": choice, "record": record}
        return result if _model_output_safe(result) else {"error": "model_output_needs_redaction"}
    except PathTraversalError:
        return {"error": "invalid_model_arguments"}
    except model_select.ModelSelectionError as exc:
        error = str(exc)
        return {"error": error if _model_output_safe(error) else "model_output_needs_redaction"}
    except LockTimeoutError:
        return {"error": "model_lock_timeout"}
    except (OSError, ValueError, RuntimeError):
        return {"error": "model_io_unavailable"}


class ModelArgumentError(ValueError):
    """Parser signal without the parser's input-reflecting diagnostic."""


class ModelHostKinds(argparse.Action):
    """Bound repeated registry values before growing their retained list."""

    def __call__(self, parser, namespace, value, option_string=None):
        previous = getattr(namespace, self.dest, None) or []
        if len(previous) >= 256 or len(value) > 128:
            raise ModelArgumentError()
        setattr(namespace, self.dest, previous + [value])


class _SilentModelOutput:
    """Discard incidental text without retaining or parsing untrusted output."""

    def write(self, text):
        return len(text)

    def flush(self):
        pass

    def isatty(self):
        return False


class ModelErrorPolicy:
    """Own the complete raw model invocation and publish one structured result."""

    def __init__(self, fallback=None, *, argv=()):
        self.fallback = fallback
        self.payload = None
        self.queue_payload = None
        self.model_ready = False
        # Preserve the raw-token policy until a successful parse establishes
        # that model is queue data rather than a model-policy invocation.
        self.model_invocation = False
        seen_team = False
        for token in argv:
            if token == "--":
                break
            if token == "model" and seen_team:
                self.model_invocation = True
                break
            if token == "team":
                seen_team = True
        self.model_errors = self.model_invocation

    def run(self, operation):
        if not self.model_invocation:
            return operation()
        with redirect_stdout(_SilentModelOutput()), redirect_stderr(_SilentModelOutput()):
            try:
                code = operation()
            except (SystemExit, ModelArgumentError):
                code = self.output({"error": "invalid_model_arguments"})
            except (KeyboardInterrupt, Exception):
                code = self.operation_error()
        if self.queue_payload is not None:
            _emit(self.queue_payload)
            return code
        payload = self.payload
        if (payload is None or
                (code == EXIT_OK and (not self.model_ready or "error" in payload)) or
                (code != EXIT_OK and "error" not in payload)):
            payload, code = {"error": "invalid_model_arguments"}, EXIT_USAGE
        _emit(payload)
        return EXIT_OK if code == EXIT_OK else EXIT_USAGE

    def queue_output(self, payload):
        self.queue_payload = payload
        return payload["exit_code"]

    def output(self, payload):
        if self.model_invocation:
            self.payload = payload
        else:
            _emit(payload)
        return EXIT_USAGE if "error" in payload else EXIT_OK

    def select_parser(self, model_errors):
        self.model_errors = self.model_invocation or model_errors

    def __call__(self):
        if self.model_errors or self.fallback is None:
            raise ModelArgumentError()
        self.fallback()

    def removed_pointer(self, argv, lookup):
        if self.model_invocation:
            return None
        return self.fallback.removed_pointer(argv, lookup) if self.fallback is not None else None

    def parse(self, parser, argv):
        from aegis_core.model_select import MAX_INPUT_BYTES

        try:
            args = self.fallback.parse(parser, argv) if self.fallback is not None else parser.parse_args(argv)
            if isinstance(args, int):
                return args
            if args.command == "team" and getattr(args, "team_action", None) == "queue":
                self.model_invocation = False
                self.model_errors = False
                args._queue_output_policy = self
                return args
            is_model = args.command == "team" and getattr(args, "team_action", None) == "model"
            if self.model_invocation and not is_model:
                raise ModelArgumentError()
            if not is_model:
                return args
            values = {key: getattr(args, key) for key in MODEL_REQUIRED + MODEL_OPTIONAL}
            if model_argument_refusal(values) is not None:
                raise ModelArgumentError()
            raw = args.workspace
            if raw is not None and (len(raw) > MAX_INPUT_BYTES or raw.count("/") + raw.count("\\") > 256):
                raise ModelArgumentError()
            # main attaches the workspace through the shared upward resolver;
            # model_result then checks that the resolved root is initialized.
            self.model_ready = True
            if self.model_invocation:
                args._model_error_policy = self
            return args
        except ModelArgumentError:
            return self.output({"error": "invalid_model_arguments"})

    def workspace_error(self, args, error):
        if not self.model_invocation and (args.command != "team" or getattr(args, "team_action", None) != "model"):
            return self.fallback.workspace_error(args, error) if self.fallback is not None else None
        return self.output({"error": "model_workspace_unavailable"})

    def operation_error(self):
        return self.output({"error": "model_io_unavailable"})


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
        if exc.next_action:
            payload["next_action"] = exc.next_action
        _emit(payload)
        return EXIT_REFUSED
    _warn(list(exc.warnings))
    print(sanitize_display(str(exc), max_len=None), file=sys.stderr)
    if exc.next_action:
        print(sanitize_display(exc.next_action, max_len=None), file=sys.stderr)
    for line in _lease_lines(lease):
        print(line, file=sys.stderr)
    return EXIT_REFUSED


def _queue_command(args):
    """Thin adapter: core owns item parsing, scheduling, storage and refusals."""
    from aegis_core import team_queue

    verb = getattr(args, "queue_action", None)
    root = args.ws.root if getattr(args, "ws", None) is not None else getattr(args, "workspace", None)
    if verb == "add":
        parsed = team_queue.parse_item(args.item)
        result = (team_queue.refusal(parsed["reason"], verb=verb) if parsed["refused"]
                  else team_queue.add(root, parsed["item"]))
    elif verb == "list":
        result = team_queue.list(root, capabilities=args.capabilities, include_done=args.include_done)
    elif verb in ("audit", "compact"):
        result = getattr(team_queue, verb)(root)
    elif verb == "claim":
        result = team_queue.claim(root, args.item_id, expect=args.expect, lane=args.lane,
                                  capabilities=args.capabilities or [], ttl_s=args.ttl, branch=args.branch)
    elif verb in ("release", "done"):
        result = getattr(team_queue, verb)(root, args.item_id, expect=args.expect, lane=args.lane)
    else:
        result = team_queue.refusal("invalid_arguments")
    return _queue_output(args, result)


def _queue_privacy_scoped(argv):
    """Conservatively cover team followed by queue anywhere in argv.

    Options, their values and -- deliberately receive no interpretation.
    Only argparse's successful namespace can establish a policy exemption.
    """
    seen_team = False
    for token in argv:
        if seen_team and token == "queue":
            return True
        if token == "team":
            seen_team = True
    return False


def _queue_removed_pointer(original, argv, lookup):
    # Let the scoped parser own refusals before any removed-command shortcut
    # can print a different diagnostic or bypass the queue envelope.
    return None if _queue_privacy_scoped(argv) else original(argv, lookup)


def _parse_queue_or_default(original, parser, argv, *, output=None):
    if not _queue_privacy_scoped(argv):
        return original(parser, argv)
    from aegis_core import team_queue
    from aegis_cli.msg import MsgArgumentError

    # Own the complete parse, including both ancestors. Diagnostics are
    # suppressed before argparse can echo an untrusted option or value.
    try:
        with redirect_stderr(_SilentModelOutput()):
            args = parser.parse_args(argv)
            raw = args.workspace
            if raw is not None and not team_queue.valid_workspace_spelling(raw):
                raise ModelArgumentError()
            return args
    except SystemExit as error:
        if error.code == 0:
            return EXIT_OK
    except (ModelArgumentError, MsgArgumentError):
        pass
    result = team_queue.refusal("invalid_arguments")
    if output is not None:
        return output(result)
    _emit(result)
    return result["exit_code"]


def _configure_queue_parser(sub, common, parent):
    """Scope non-echoing parser/workspace errors to this new command only."""
    from aegis_core import team_queue

    # The shared policy is invocation-local. Wrapping its parse boundary also
    # covers errors raised before argparse reaches the queue child parser.
    policy = getattr(parent, "_error_policy", None)
    if policy is not None:
        # Model policy must still validate the successful namespace. Wrap its
        # underlying parser boundary, rather than bypassing that validation.
        target = policy.fallback if isinstance(policy, ModelErrorPolicy) else policy
        output = policy.queue_output if isinstance(policy, ModelErrorPolicy) else None
        target.parse = partial(_parse_queue_or_default, target.parse, output=output)
        target.removed_pointer = partial(_queue_removed_pointer, target.removed_pointer)

    class QueueParser(type(parent)):
        def error(self, message):
            if getattr(self, "_error_policy", None) is not None:
                raise ModelArgumentError()
            _emit(team_queue.refusal("invalid_arguments"))
            self.exit(EXIT_USAGE)

        def parse_known_args(self, args=None, namespace=None):
            values, extras = super().parse_known_args(args, namespace)
            if extras:
                self.error("")
            raw = getattr(values, "workspace", None)
            if raw is not None and not team_queue.valid_workspace_spelling(raw):
                self.error("")
            # Each invocation owns this policy instance. Preserve the shared
            # resolver while replacing its input-reflecting diagnostic only
            # after the parser has selected queue.
            policy = getattr(self, "_error_policy", None)
            if policy is not None:
                policy.workspace_error = _queue_workspace_error
            return values, extras

    class Capabilities(argparse.Action):
        def __call__(self, parser, namespace, value, option_string=None):
            previous = getattr(namespace, self.dest, None) or []
            if len(previous) >= 128 or len(value) > 64:
                parser.error("")
            setattr(namespace, self.dest, previous + [value])

    factory = sub._parser_class
    keywords = {"error_policy": parent._error_policy} if hasattr(parent, "_error_policy") else {}
    sub._parser_class = partial(QueueParser, **keywords)
    try:
        parser = sub.add_parser("queue", parents=[common], help="Manage queued team work with CAS leases",
                                description="Queue add, list, claim, release, done, audit and compact; all results are JSON.",
                                allow_abbrev=False)
    finally:
        sub._parser_class = factory
    verbs = parser.add_subparsers(dest="queue_action", metavar="VERB")
    add = verbs.add_parser("add", parents=[common], help="Enqueue a bounded inline JSON item", allow_abbrev=False)
    add.add_argument("--item", required=True, metavar="JSON", help="Queue item object; no file paths are opened")
    view = verbs.add_parser("list", parents=[common], help="List items, blockers and lane labels", allow_abbrev=False)
    view.add_argument("--capability", dest="capabilities", action=Capabilities, default=None,
                      help="Filter by a team capability label; repeat for each label")
    view.add_argument("--include-done", action="store_true", help="Include completed items hidden by default")
    claim = verbs.add_parser("claim", parents=[common], help="Claim a current item revision with a lease", allow_abbrev=False)
    claim.add_argument("item_id", metavar="ITEM", help="Stable queue item id")
    claim.add_argument("--expect", required=True, metavar="REVISION", help="Current revision returned by add or list")
    claim.add_argument("--lane", required=True, help="Lane declared in .aegis/team.json")
    claim.add_argument("--branch", default=None, help="Lane's local branch; omitted means unknown branch evidence")
    claim.add_argument("--capability", dest="capabilities", action=Capabilities, default=None,
                       help="Team capability label; repeat for each label")
    claim.add_argument("--ttl", type=int, default=team.DEFAULT_TTL_S, metavar="SECONDS", help="Claim lifetime, at most one day")
    for verb in ("release", "done"):
        action = verbs.add_parser(verb, parents=[common], help="Release a claim" if verb == "release" else "Complete a live claim",
                                  allow_abbrev=False)
        action.add_argument("item_id", metavar="ITEM", help="Stable queue item id")
        action.add_argument("--expect", required=True, metavar="REVISION", help="Current revision returned by claim or list")
        action.add_argument("--lane", default=None, help="Current claim lane; required for a live claim")
    verbs.add_parser("audit", parents=[common], help="Report held work needing a decision", allow_abbrev=False)
    verbs.add_parser("compact", parents=[common], help="Remove completed items not needed by unfinished dependencies", allow_abbrev=False)


def _queue_workspace_error(args, error):
    from aegis_core import team_queue

    result = team_queue.refusal("queue_io_unavailable", verb=getattr(args, "queue_action", "usage"))
    return _queue_output(args, result)


def _queue_output(args, result):
    policy = getattr(args, "_queue_output_policy", None)
    if policy is not None:
        return policy.queue_output(result)
    _emit(result)
    return result["exit_code"]


def run_team(args: argparse.Namespace) -> int:
    action = getattr(args, "team_action", None)
    if action == "queue":
        return _queue_command(args)
    if action == "model":
        values = {key: getattr(args, key) for key in MODEL_REQUIRED + MODEL_OPTIONAL}
        root = args.ws.root if getattr(args, "ws", None) is not None else args.workspace
        result = model_result(values, root)
        policy = getattr(args, "_model_error_policy", None)
        if policy is not None:
            return policy.output(result)
        _emit(result)
        return EXIT_USAGE if "error" in result else EXIT_OK
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


def _configure_model_parser(sub, common):
    model = sub.add_parser("model", parents=[common], help="Select a model; optionally record the decision",
                           description="Preview model selection as JSON; --record atomically selects and appends. "
                           "Errors are JSON with exit 2. Paths must stay inside the workspace; absolute and parent paths refuse. "
                           "No model is launched; unprobed admission remains explicit.")
    model._model_errors = True
    for flag, help_text in (
        ("bindings", "Model bindings JSON file inside the workspace (bounded, regular, no symlinks)"),
        ("policy", "Team selection policy JSON file inside the workspace (bounded, regular, no symlinks)"),
        ("history", "Decision JSONL path inside the workspace in an existing owner-only directory; missing log means empty history"),
        ("task-kind", "Task kind T1 through T14, validated by the core"),
        ("role-kind", "Seat kind: orchestrator, decider, implementer, integrator or reviewer"),
        ("subject", "Single-line lane/endpoint/generation identifier for this decision"),
    ):
        model.add_argument("--" + flag, required=True, help=help_text)
    model.add_argument("--host-kind", dest="host_kinds", action=ModelHostKinds, required=True,
                       help="Host registry kind; repeat for each host (at most 256)")
    model.add_argument("--intent", help="Semantic intent: light, standard, deep, extended, max or ultra; default from policy/role band")
    model.add_argument("--author-family", help="Author family required for reviews; T7 binds it to its chosen family")
    model.add_argument("--lane-family", help="Lane family required for T3; writer lanes must match team_family")
    model.add_argument("--review-stage", default="primary", help="Review stage: primary, correctness, security, whole or second as allowed by the task")
    model.add_argument("--record", action="store_true", help="Atomically select and append under the history lock (60-second timeout); default preview")


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
        # Before a team action is recognized, malformed prefixes may target model.
        # Each recognized non-model child restores its normal error policy.
        parser._model_errors = True
        common = argparse.ArgumentParser(add_help=False)
        common.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                            help="Emit machine-readable JSON output")
        common.add_argument("--plain", action="store_true", default=argparse.SUPPRESS,
                            help="Strip ANSI styling and emoji")
        common.add_argument("--workspace", type=str, default=argparse.SUPPRESS, help="Target workspace root")
        sub = parser.add_subparsers(dest="team_action", metavar="ACTION")
        _configure_model_parser(sub, common)
        _configure_queue_parser(sub, common, parser)
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
