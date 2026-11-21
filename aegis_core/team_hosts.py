"""Read-only capacity advice from resolved policy and injected usage adapters.

Adapters return bounded Python snapshots, never paths or credential material.
Subscription snapshots use UTC RFC3339 resets_at and used_pct in [0, 100];
credits snapshots use nonnegative credits_left (zero holds). Optional tokens
and runs are per-host counters. No cross-host totals are calculated.

Check exit codes: 0 go, 3 hold, 4 fallback, 5 skip; profile refusals remain 1
and invalid host/KIND arguments remain 2. Advice does not authorize execution.
"""
from __future__ import annotations

from datetime import datetime
from importlib import import_module
import math

from aegis_core import hosts as host_registry, team_profile
from aegis_core.team_host_adapter import (
    HostAdapter as HostAdapter, HostAdapterError as HostAdapterError, copy_environment,
)
from aegis_core.team_profile import NEXT_ACTION_TEMPLATES as NEXT_ACTION_TEMPLATES


__all__ = [
    "EXIT_CODES",
    "FakeUsageAdapter",
    "HostCapacity",
    "HostAdapter",
    "HostAdapterError",
    "NEXT_ACTION_TEMPLATES",
    "UnconfiguredUsageAdapter",
    "normalize_usage",
    "usage_adapter",
    "host_adapter",
    "scrub_child_environment",
]


EXIT_CODES = {"go": 0, "hold": 3, "fallback": 4, "skip": 5, "refused": 1, "usage": 2}


def scrub_child_environment(environment):
    """Return a bounded private snapshot and a child free of all host controls.

    Both results are private process inputs, never display/evidence payloads.
    The adapter may deliberately re-add its selected credential and markers
    after this single registry-driven, case-insensitive scrub. Returning the
    snapshot separately permits that selection without importing this service
    from a lower-layer adapter or rereading a mutable caller Mapping.
    """
    snapshot = copy_environment(environment)
    names, prefixes = set(), []
    for spec in host_registry.all_hosts():
        names.update(name.upper() for name in (*spec.billing_variables, spec.session_variable,
                                               *spec.session_markers, *spec.environment_overrides) if name)
        prefixes.extend(prefix.upper() for prefix in spec.session_marker_prefixes)
    prefixes = tuple(prefixes)
    child = {key: value for key, value in snapshot.items()
             if key.upper() not in names and not key.upper().startswith(prefixes)}
    return snapshot, child


def host_adapter(host_kind):
    """Resolve an explicitly registered adapter; never select another provider."""
    action = "Select a registered host with a candidate adapter; no provider fallback is permitted."
    if type(host_kind) is not str or len(host_kind) > 128:
        raise HostAdapterError("host_adapter_unavailable", action, exit_code=2)
    try:
        spec = host_registry.get(host_registry.resolve(host_kind))
    except KeyError:
        raise HostAdapterError("host_adapter_unavailable", action, exit_code=2) from None
    if not spec.team_adapter:
        raise HostAdapterError("host_adapter_unavailable", action)
    # The module path is trusted registry data, never profile or model input.
    try:
        adapter = import_module(spec.team_adapter).Adapter(scrub_environment=scrub_child_environment)
    except (ImportError, AttributeError):
        raise HostAdapterError("host_adapter_unavailable", action) from None
    if not isinstance(adapter, HostAdapter):
        raise HostAdapterError("host_adapter_unavailable", action)
    return adapter


class UnconfiguredUsageAdapter:
    """Extension point for a qualified registry kind; performs no host I/O.

    A real adapter implements read(host_alias, usage_source) and bounds reads
    before parsing, using its own trusted descriptor-based storage boundary.
    """

    def read(self, host, usage_source):
        raise NotImplementedError("usage adapter not configured")


def usage_adapter(host_kind):
    """Reader extension point for every qualified host kind in the registry.

    Integrators supply a kind-specific adapter here or inject one into
    HostCapacity. This ships no credential readers and launches no processes.
    """
    return UnconfiguredUsageAdapter()


class FakeUsageAdapter:
    """Deterministic adapter with per-alias snapshots or injected exceptions."""

    def __init__(self, snapshots):
        self.snapshots = snapshots
        self.calls = []

    def read(self, host, usage_source):
        self.calls.append((host, usage_source))
        value = self.snapshots[host]
        if isinstance(value, Exception):
            raise value
        return value


def _number(value, maximum):
    if type(value) not in (int, float) or not 0 <= value <= maximum or not math.isfinite(value):
        raise ValueError("invalid usage number")
    return value


def normalize_usage(value, source):
    """Validate bounded shapes before copying or parsing adapter data."""
    if type(value) is not dict or len(value) > 3:
        raise ValueError("invalid usage snapshot")
    expected = "window" if source == "subscription-window" else "credits_left"
    if expected not in value or any(key not in (expected, "tokens", "runs") for key in value):
        raise ValueError("invalid usage fields")
    if source == "subscription-window":
        window = value["window"]
        if type(window) is not dict or len(window) != 2 or "used_pct" not in window or "resets_at" not in window:
            raise ValueError("invalid usage window")
        reset = window["resets_at"]
        if type(reset) is not str or len(reset) != 20:
            raise ValueError("invalid usage reset")
        # Refuse multiline and noncanonical reset values rather than joining.
        parsed = datetime.strptime(reset, "%Y-%m-%dT%H:%M:%SZ")
        if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != reset:
            raise ValueError("invalid usage reset")
        result = {"window": {"used_pct": _number(window["used_pct"], 100), "resets_at": reset}}
    elif source == "credits":
        result = {"credits_left": _number(value["credits_left"], 10**15)}
    else:
        raise ValueError("invalid usage source")
    for counter in ("tokens", "runs"):
        if counter in value:
            if type(value[counter]) is not int or not 0 <= value[counter] <= 10**15:
                raise ValueError("invalid usage counter")
            result[counter] = value[counter]
    return result


class HostCapacity:
    """One command's per-host snapshot cache; policy checks precede advice."""

    def __init__(self, resolved, *, adapter=None):
        team_profile.validate_resolved(resolved)
        self.profile = resolved["profile"]
        self.settings = self.profile["model_settings"]
        self.adapter = adapter
        self.snapshots = {}

    def _usage(self, host):
        if host in self.snapshots:
            return self.snapshots[host]
        binding = self.settings["hosts"][host]
        capacity = self.settings["capacity"].get(host, {})
        source = capacity.get("usage_source", "none")
        row = {"host": host, "host_kind": binding["kind"], "usage_source": source,
               "thresholds": team_profile.capacity_thresholds(capacity), "usage": {},
               "usage_status": "none", "reason": "usage tracking disabled by profile",
               "next_action": "Configure a usage source and its adapter to obtain capacity advice."}
        if source != "none":
            try:
                reader = self.adapter if self.adapter is not None else usage_adapter(binding["kind"])
                row["usage"] = normalize_usage(reader.read(host, source), source)
                row.update(usage_status="known", reason="per-host usage snapshot available",
                           next_action="Use aegis team hosts check HOST KIND --json before starting work.")
            except Exception:
                # Availability applies to this host's capacity observation only.
                # Exception text and partial snapshots never cross the boundary.
                row.update(usage_status="unknown", usage={}, reason="unknown: usage adapter unavailable or invalid snapshot",
                           next_action="Configure or repair this host kind's usage adapter; capacity advice alone does not block work.")
        self.snapshots[host] = row
        return row

    def _rule(self, host, kind, voting):
        row = self._usage(host)
        if row["usage_status"] != "known":
            return False, row["reason"], row["next_action"]
        usage = row["usage"]
        if "credits_left" in usage:
            held = usage["credits_left"] == 0
            return held, "credits exhausted" if held else "credits available", "Replenish this host's credits, then recheck."
        thresholds = row["thresholds"]
        threshold = thresholds["route_pct"] if voting else thresholds["flex_route_pct"]
        if kind == "writer":
            threshold = thresholds["hold_pct"]
        held = usage["window"]["used_pct"] >= threshold
        reason = "usage reaches capacity threshold" if held else "usage below capacity threshold"
        return held, reason, "Wait for the window reset at " + usage["window"]["resets_at"] + "; rerun this check."

    def check(self, host, kind):
        if type(host) is not str or len(host) > 64 or host not in self.settings["hosts"]:
            raise team_profile.ProfileError("unknown host; use hosts status for declared aliases", exit_code=2,
                                           layer="flags", file="<command-line>")
        plan = team_profile.plan(self.profile, kind, start_host=host)
        decision, reason, next_action, selected = self._decide(host, plan)
        result = {"host": host, "kind": plan["kind"], "decision": decision, "reason": reason,
                  "next_action": next_action, "selected_host": selected,
                  "exit_code": EXIT_CODES[decision.split(":", 1)[0]], "usage": self._usage(host)}
        if type(next_action) is list:
            result["next_action_parts"] = next_action
            result["next_action"] = "".join(part if type(part) is str else part["identifier"] for part in next_action)
        if plan["kind"] == "writer":
            binding = self.settings["hosts"][selected]
            boundary = team_profile.PRESET_DATA["hosts"][binding["kind"]]["boundary"]
            result.update(write_scope=["write scope: " + boundary],
                          write_boundary={"host": selected, "kind": binding["kind"], "boundary": boundary})
        return result

    def _decide(self, host, plan):
        held_reason, held_action = "", ""
        for entry in plan["entries"]:
            if "terminal" in entry:
                if entry["terminal"] == "skip":
                    return "skip", held_reason + "; declared non-voting skip", "Record this job as skipped; continue the remaining required jobs.", host
                break
            target = entry["host"]
            held, reason, next_action = self._rule(target, plan["kind"], plan["voting"])
            if not held:
                if target == host:
                    if self._usage(host)["usage_status"] == "known":
                        prefix, suffix = NEXT_ACTION_TEMPLATES["start"]
                        next_action = [prefix, {"identifier": host}, suffix]
                    return "go", reason, next_action, host
                prefix, separator, suffix = NEXT_ACTION_TEMPLATES["check"]
                action = [prefix, {"identifier": target}, separator, {"identifier": plan["kind"]}, suffix]
                return "fallback:" + target, held_reason + "; fallback " + reason, action, target
            if not held_reason:
                held_reason, held_action = reason, next_action
            if plan["pinned"]:
                return "hold", reason + "; pinned role or lens cannot fall back", next_action, host
        return "hold", held_reason + "; fallback chain exhausted or held", held_action, host

    def usage(self):
        """Per-host measurements, with no aggregation across host accounts."""
        return [dict(self._usage(host)) for host in self.settings["hosts"]]

    def status(self):
        """List the same effective role decisions exposed by direct checks."""
        kinds = [name for name, role in self.settings["roles"].items() if role["hosts"]]
        kinds += [lens["name"] for lens in self.profile["policy"]["review"]["lenses"]]
        plans = {kind: team_profile.plan(self.profile, kind) for kind in kinds}
        result = []
        for host in self.settings["hosts"]:
            jobs = [kind for kind, plan in plans.items()
                    if host in plan["admitted"]]
            decisions = [self.check(host, kind) for kind in [*jobs, "doc"]]
            result.append({**self._usage(host), "decisions": decisions})
        return result
