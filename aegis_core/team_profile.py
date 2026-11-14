"""Versioned team profiles: closed layers, provenance and confined local storage.

No process or network probes occur here. Host capabilities below mirror the
registry in tools/hierarchy_hosts.py; native app threads cannot bind run roles.
Confined reads and publication use the shared storage boundary. Windows
filesystem-backed operations currently refuse.
"""
from __future__ import annotations

from collections import deque
from contextlib import contextmanager
from copy import deepcopy
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from aegis_core import hosts as host_registry, pathlookup, storage, team_supervisor
from aegis_core.primitives import sanitize_display as sanitize_display
from aegis_core.team_profile_display import (
    NEXT_ACTION_TEMPLATES, TERMINAL_NAMES as _TERMINALS,
    closed_object as _object, reject_terminal_hosts as _reject_terminal_hosts,
    provenance_values as _display_values,
    render_profile as _render_profile,
)
from aegis_core.workspace.layout import AEGIS_DIRNAME, UserLayout

__all__ = [
    "CAPACITY_DEFAULTS", "CAPACITY_KINDS", "JSON_SCHEMA", "MAX_BYTES", "MAX_DEPTH", "MAX_ITEMS",
    "MAX_NODES", "MAX_STRING", "MAX_HOSTS", "MAX_FALLBACK_CHAIN", "MAX_LENSES", "MAX_FALLBACK_EDGES",
    "PRESET_DATA", "PROFILE_SCHEMA", "REPO_PATH", "USER_PATH", "USER_JSON_SCHEMA", "ProfileError",
    "capacity_thresholds", "descriptor_supported", "doctor", "plan", "governance_status", "initialize",
    "load", "resolve", "validate_resolved", "display_profile", "NEXT_ACTION_TEMPLATES",
]

MAX_BYTES = 131072
MAX_DEPTH = 16
MAX_NODES = 4096
MAX_STRING = 4096
MAX_ITEMS = 64
MAX_HOSTS = 16
MAX_FALLBACK_CHAIN = 8
MAX_LENSES = 16
MAX_FALLBACK_EDGES = 64
CAPACITY_KINDS = ("writer", "review", "extra-review", "doc", "research",
                  "reviewer.correctness", "reviewer.security", "lens.extra")
CAPACITY_DEFAULTS = {"hold_pct": 99, "route_pct": 95, "flex_route_pct": 80}
_CAPACITY_ALIASES = {"review": "reviewer.correctness", "extra-review": "lens.extra"}
# Bounds, declarations and required bindings precede these route-kind checks.
_ROUTE_REFUSAL_ORDER = {
    "review": ("cross_family", "admission", "pinned_family", "terminal"),
    "writer": ("admission", "terminal"),
    "other": ("admission",),
}
_IDENTIFIER_PATTERN = r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$"
PROFILE_SCHEMA = "aegis.team.profile/v1"
REPO_PATH = (AEGIS_DIRNAME, "team", "profile.json")
USER_PATH = (".config", "aegis", "team.json")

# Preset data is the only source of host/runner names. Qualification is registry
# data, never a profile-controlled boolean. TP-9 may add the optional third lens.
PRESET_DATA = {
    "hosts": {
        "codex-cli": {"cli": "codex", "family": "codex", "writer": True,
                      "boundary": "OS sandbox, qualification pending T2(b)"},
        "claude-code": {"cli": "claude", "family": "claude", "writer": True,
                        "boundary": "permission rules, not OS-enforced"},
        "codex": {"cli": "codex", "family": "codex", "writer": False, "boundary": None},
        **{spec.id: {"cli": spec.binaries[0], "family": spec.team_family,
                     "writer": False, "boundary": None}
           for spec in host_registry.all_hosts() if spec.team_adapter},
    },
    "defaults": {
        "version": 1, "preset": "solo",
        "policy": {
            "review": {"require_cross_family": False, "cap": None, "mode": "full",
                       "extra_lens_blocks_on": "confirmed", "lenses": []},
            "gates": [{"name": "full", "runner": "local", "selector": "whole", "must_pass": True,
                       "reuse_identical_tree": True}],
            "landing": {"target_branch": "main", "strategy": "combined-full", "batch_max": 1,
                        "signature_required_for": ["main"], "publish": {"remote": "origin", "app": ""}},
        },
        "model_settings": {
            "hosts": {}, "roles": {}, "capacity": {},
        },
        "run_config": {
            "runners": {"local": {"cpus": 1}},
            "autopilot": {"queue_full_on_ready": False, "claim_next": False,
                          "resume_writer": False, "rulings": "owner"},
            "limits": {"writers_max": 1, "votes_max": 2, "research_max": 1},
            "token_budgets": {},
        },
    },
    "presets": {
        "solo": {"model_settings": {
            "hosts": {"primary": {"kind": "codex-cli"}},
            "roles": {"writer": {"hosts": ["primary"]}, "reviewer.correctness": {"hosts": ["primary"]},
                      "reviewer.security": {"hosts": ["primary"]}, "research": {"hosts": ["primary"]}},
        }, "policy": {"review": {"require_cross_family": False}}},
        "pair": {"model_settings": {
            "hosts": {"primary": {"kind": "codex-cli"}, "review": {"kind": "claude-code"}},
            "roles": {"writer": {"hosts": ["primary"]}, "reviewer.correctness": {"hosts": ["review"]},
                      "reviewer.security": {"hosts": ["primary"], "pinned_family": True},
                      "research": {"hosts": ["primary", "review"]}},
        }, "policy": {"review": {"require_cross_family": True}}},
        "mixed": {"model_settings": {
            "hosts": {"primary": {"kind": "codex-cli"}, "review": {"kind": "claude-code"}},
            "roles": {"writer": {"hosts": ["primary"]}, "reviewer.correctness": {"hosts": ["review"]},
                      "reviewer.security": {"hosts": ["primary"], "pinned_family": True},
                      "lens.extra": {"hosts": [], "optional": True},
                      "research": {"hosts": ["primary", "review"]}},
        }, "policy": {"review": {"require_cross_family": True}, "landing": {"batch_max": 4}}},
        "ci-only": {},
    },
}


class ProfileError(ValueError):
    """Documented refusal; messages contain no file contents or OS error text."""

    def __init__(self, message, *, layer=None, file=None, path=None, related_paths=(), exit_code=1):
        super().__init__(message)
        self.layer = layer
        self.file = file
        self.path = path
        self.related_paths = related_paths
        self.exit_code = exit_code


def _map(items, limit=MAX_ITEMS, reserved=()):
    return {"type": "object", "patternProperties": {_IDENTIFIER_PATTERN: items},
            "additionalProperties": False, "maxProperties": limit,
            **({"propertyNames": {"not": {"enum": list(reserved)}}} if reserved else {})}


def _array(items, limit=MAX_ITEMS):
    return {"type": "array", "items": items, "maxItems": limit}


_TEXT = {"type": "string", "maxLength": MAX_STRING}
_IDENTIFIER = {"type": "string", "maxLength": 64, "pattern": _IDENTIFIER_PATTERN}
_BOOL = {"type": "boolean"}
_INT = {"type": "integer", "minimum": 1, "maximum": 1000000}
_USER_TEXT = {**_TEXT, "user_layer_only": True}
_HOST = _object({"kind": {"type": "string", "enum": list(PRESET_DATA["hosts"])},
                 "auth_mode": {"type": "string", "enum": ["sso", "api", "token"], "user_layer_only": True}})
_ROLE = _object({"hosts": _array(_IDENTIFIER, MAX_HOSTS), "model": _TEXT, "effort": _TEXT,
                 "optional": _BOOL, "pinned_family": _BOOL})
_CAPACITY = _object({"usage_source": {"type": "string", "enum": ["subscription-window", "credits", "none"]},
                     "thresholds": _object({name: {"type": "number", "minimum": 0, "maximum": 100}
                                            for name in ("hold_pct", "route_pct", "flex_route_pct")}),
                     "fallback": _object({kind: _array(_IDENTIFIER, MAX_FALLBACK_CHAIN) for kind in CAPACITY_KINDS})})
_RUNNER = _object({"cpus": _INT, "image": _TEXT, "provider": _TEXT,
                   "pool": _USER_TEXT, "credentials": _USER_TEXT,
                   "budget_usd_month": {"type": "number", "minimum": 0, "maximum": 1000000,
                                        "user_layer_only": True}})
JSON_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema", "$id": PROFILE_SCHEMA,
    "validation_order": ("version", "preset", "model_settings", "policy", "run_config", "supervisor"),
    **_object({
        "version": {"type": "integer", "enum": [1], "invalid_refusal": "unsupported profile version; upgrade aegis"},
        "preset": {"type": "string", "enum": list(PRESET_DATA["presets"])},
        "policy": _object({
            "review": _object({"require_cross_family": _BOOL, "cap": {"type": ["integer", "null"], "minimum": 1, "maximum": 1000000},
                               "mode": {"type": "string", "enum": ["full", "delta"]},
                               "extra_lens_blocks_on": {"type": "string", "enum": ["confirmed"]},
                               "lenses": _array(_object({"name": _IDENTIFIER, "host_pref": _array(_IDENTIFIER, MAX_HOSTS),
                                                         "voting": _BOOL, "pinned_family": _BOOL}), MAX_LENSES)}),
            "gates": _array(_object({"name": _TEXT, "runner": _IDENTIFIER,
                                     "selector": {"type": "string", "enum": ["impacted", "whole", "list"]},
                                     "tests": _array(_TEXT), "python": _TEXT, "must_pass": _BOOL,
                                     "reuse_identical_tree": _BOOL})),
            "landing": _object({"target_branch": _TEXT,
                                "strategy": {"type": "string", "enum": ["combined-full", "batch", "direct"]},
                                "batch_max": _INT, "signature_required_for": _array(_TEXT),
                                "publish": _object({"remote": _TEXT, "app": _TEXT})}),
        }),
        "model_settings": {"validation_order": ("hosts", "roles", "capacity"), **_object({
            "hosts": _map(_HOST, MAX_HOSTS, reserved=_TERMINALS), "roles": _object({
            name: _ROLE for name in ("writer", "reviewer.correctness", "reviewer.security", "lens.extra", "research")}),
            "capacity": _map(_CAPACITY, reserved=_TERMINALS)})},
        "run_config": _object({"runners": _map(_RUNNER),
            "autopilot": _object({"queue_full_on_ready": _BOOL, "claim_next": _BOOL, "resume_writer": _BOOL,
                                   "rulings": {"type": "string", "enum": ["owner", "coordinator"]}}),
            "limits": _object({"writers_max": _INT, "votes_max": _INT, "research_max": _INT}),
            "token_budgets": {**_map(_INT), "user_layer_only": True}}),
        "supervisor": team_supervisor.SUPERVISOR_SCHEMA,
    }),
}


_LAYER_FILES = {"repo": "/".join(REPO_PATH), "user": "~/" + "/".join(USER_PATH), "flags": "<command-line>"}
_USER_SETTINGS = {**JSON_SCHEMA["properties"]["model_settings"], "properties": {
    **JSON_SCHEMA["properties"]["model_settings"]["properties"],
    "hosts": _object({kind: _object({"auth_mode": _HOST["properties"]["auth_mode"]})
                      for kind in PRESET_DATA["hosts"]}),
    "capacity": _object({kind: _CAPACITY for kind in PRESET_DATA["hosts"]}),
}}
USER_JSON_SCHEMA = {**JSON_SCHEMA, "$id": "aegis.team.profile.user/v1",
                    "properties": {**JSON_SCHEMA["properties"], "model_settings": _USER_SETTINGS}}


def _context(error, layer, file=None):
    if error.layer is None:
        error.layer = layer
    if error.file is None:
        error.file = file or _LAYER_FILES.get(error.layer, "<built-in preset>")
    return error


def _validate(value, schema, path, layer, *, required=None, resolved=False):
    try:
        return team_supervisor.validate_input(value, schema, path, layer, required=required, resolved=resolved)
    except team_supervisor.SupervisorError as error:
        raise _context(ProfileError(str(error), path=error.path, layer=error.layer), layer) from None


def _merge(target, patch, origins, layer, prefix=()):
    for key, value in patch.items():
        path = (*prefix, key)
        if type(value) is dict:
            if layer == "user" and not any(type(child) is not dict for _, child in _leaves(value)):
                continue
            if key not in target:
                target[key] = {}
            _merge(target[key], value, origins, layer, path)
            if not value:
                origins.setdefault(path, layer)
        else:
            target[key] = deepcopy(value)
            origins[path] = layer


def _leaves(value, prefix=()):
    for key, child in value.items():
        path = (*prefix, key)
        if type(child) is dict and child:
            yield from _leaves(child, path)
        else:
            yield path, child


def capacity_thresholds(capacity):
    """Defaults fit a lower explicit hold/route threshold without changing it."""
    supplied = capacity.get("thresholds", {})
    hold = supplied.get("hold_pct", CAPACITY_DEFAULTS["hold_pct"])
    route = supplied.get("route_pct", min(hold, CAPACITY_DEFAULTS["route_pct"]))
    flex = supplied.get("flex_route_pct", min(route, CAPACITY_DEFAULTS["flex_route_pct"]))
    return {"hold_pct": hold, "route_pct": route, "flex_route_pct": flex}


def _capacity_complete(settings):
    hosts, edges = settings["hosts"], 0
    for name in sorted(settings["capacity"]):
        capacity = settings["capacity"][name]
        path = "model_settings.capacity." + name
        if name not in hosts:
            raise ProfileError("capacity references undeclared host", path=path)
        thresholds = capacity_thresholds(capacity)
        if not thresholds["flex_route_pct"] <= thresholds["route_pct"] <= thresholds["hold_pct"]:
            raise ProfileError("capacity thresholds must satisfy flex_route_pct <= route_pct <= hold_pct",
                               path=path + ".thresholds")
        fallbacks = capacity.get("fallback", {})
        for kind in sorted(fallbacks):
            chain = fallbacks[kind]
            if len(chain) > MAX_FALLBACK_CHAIN:
                raise ProfileError("profile fallback chain limit exceeded", path=path + ".fallback." + kind)
            edges += len(chain)
            if edges > MAX_FALLBACK_EDGES:
                raise ProfileError("profile fallback edge limit exceeded", path="model_settings.capacity")
            if any(target not in _TERMINALS and target not in hosts for target in chain):
                raise ProfileError("capacity references undeclared host", path=path + ".fallback." + kind)


def _capacity_job(profile, kind):
    if type(kind) is not str or len(kind) > 64 or re.fullmatch(_IDENTIFIER_PATTERN, kind) is None:
        raise ProfileError("unknown job kind; use aegis team hosts status --json", layer="flags",
                           file="<command-line>", exit_code=2)
    kind = _CAPACITY_ALIASES.get(kind, kind)
    roles = profile["model_settings"]["roles"]
    lens = next((item for item in profile["policy"]["review"]["lenses"] if item["name"] == kind), None)
    generic = "review" if kind.startswith("reviewer.") or lens else kind
    if kind == "lens.extra":
        generic = "extra-review"
    path = "policy.review.lenses" if lens else "model_settings.roles." + kind + ".hosts"
    role = lens if lens else roles.get(kind)
    if kind == "doc":
        binding = list(profile["model_settings"]["hosts"])
    elif role is None:
        raise ProfileError("job role or lens is not declared; use aegis team hosts status --json", path=path)
    else:
        binding = role.get("host_pref" if lens else "hosts", [])
    if not binding:
        raise ProfileError("job is disabled: no declared host binding", path=path)
    return {"kind": kind, "generic": generic, "binding": binding, "path": path,
            "pinned": role.get("pinned_family", False) if role else False,
            "voting": lens.get("voting", True) if lens else kind.startswith("reviewer.")}


def plan(profile, kind, *, start_host=None):
    """Plan from any bound or fallback-admitted host, retaining source paths.

    Canonical keys override generic keys, including explicit empty lists.
    Cycles terminate; the first terminal ends traversal. Bound restarts use
    their remaining binding; other admitted starts use their explicit routes.
    """
    try:
        job = _capacity_job(profile, kind)
    except ProfileError as error:
        raise _context(error, "repo") from None
    settings = profile["model_settings"]

    def traverse(roots):
        entries, reached, pending = [], set(), deque(roots)
        while pending:
            name, source = pending.popleft()
            if name in _TERMINALS or name not in settings["hosts"]:
                entries.append({"terminal": name, "path": source})
                break
            if name in reached:
                continue
            reached.add(name)
            entries.append({"host": name, "path": source})
            fallbacks = settings["capacity"].get(name, {}).get("fallback", {})
            keys = (job["kind"], job["generic"], "review") if job["kind"] == "lens.extra" else (job["kind"], job["generic"])
            key = next((key for key in keys if key in fallbacks), None)
            if key is not None:
                path = "model_settings.capacity." + name + ".fallback." + key
                pending.extendleft((target, path) for target in reversed(fallbacks[key]))
        return entries

    binding = [start_host] if job["kind"] == "doc" and start_host is not None else job["binding"]
    entries = traverse([(name, job["path"]) for name in binding])
    admitted = list(dict.fromkeys(binding + [entry["host"] for entry in entries if "host" in entry
                                           and (not job["pinned"] or entry["host"] in job["binding"])]))
    if start_host is not None:
        if start_host not in admitted:
            raise _context(ProfileError("host is not bound to this job; use its declared role hosts", path=job["path"]), "repo")
        roots = ([{"host": name, "path": job["path"]} for name in binding[binding.index(start_host):]]
                 if start_host in binding else [next(entry for entry in entries if entry.get("host") == start_host)])
        entries = traverse([(entry["host"], entry["path"]) for entry in roots])
    return {**job, "entries": entries, "admitted": admitted}


def _lens_identities(profile):
    lenses, names = profile["policy"]["review"]["lenses"], set()
    if len(lenses) + bool(profile["model_settings"]["roles"].get("lens.extra", {}).get("hosts")) > MAX_LENSES:
        raise ProfileError("profile lens limit exceeded", path="policy.review.lenses")
    for index, lens in enumerate(lenses):
        if not lens.get("name"):
            raise ProfileError("incomplete review lens: name required", path="policy.review.lenses")
        if lens["name"] in names:
            raise ProfileError("duplicate review lens name", path="policy.review.lenses")
        if lens["name"] in CAPACITY_KINDS:
            raise ProfileError("review lens name is reserved for a built-in job kind", path="policy.review.lenses")
        if not lens.get("host_pref"):
            raise ProfileError("incomplete review lens: host_pref required", path="policy.review.lenses")
        if len(lens["host_pref"]) > MAX_HOSTS:
            raise ProfileError("profile host binding limit exceeded", path="policy.review.lenses." + str(index) + ".host_pref")
        if any(host not in profile["model_settings"]["hosts"] for host in lens["host_pref"]):
            raise ProfileError("review route references undeclared host", path="policy.review.lenses")
        names.add(lens["name"])


def _review_routes(profile, families):
    roles, hosts = profile["model_settings"]["roles"], profile["model_settings"]["hosts"]
    kinds = [kind for kind in sorted(roles) if roles[kind]["hosts"]]
    kinds += [lens["name"] for lens in profile["policy"]["review"]["lenses"]]
    @lru_cache(maxsize=None)
    def planned(kind, start=None):
        return plan(profile, kind, start_host=start)

    bindings = {kind: planned(kind) for kind in kinds}
    starts = [(kind, host) for kind, binding in bindings.items()
              for host in dict.fromkeys([*binding["binding"], *binding["admitted"]])]
    starts += [("doc", host) for host in sorted(hosts)]
    # Cache every restarted plan before checking policy, preserving refusal order.
    for kind, host in starts:
        planned(kind, host)
    admitted = {kind: set(binding["admitted"]) for kind, binding in bindings.items()}
    writers = {entry["host"] for kind, host in starts if kind == "writer"
               for route in (planned(kind, host),)
               for entry in (route["entries"][:1] if route["pinned"] else route["entries"])
               if "host" in entry and entry["host"] in admitted["writer"]}
    writer_families = {families[host] for host in writers}
    checked = {kind: set() for kind in kinds}
    cross_family = profile["policy"]["review"]["require_cross_family"]
    if cross_family and (not writers or not roles.get("reviewer.correctness", {}).get("hosts")):
        raise ProfileError("cross-family review needs declared writer and reviewer hosts", path="policy.review.require_cross_family")

    def refuse(rule, route, entry, allowed, cross):
        name = entry.get("host")
        if rule == "terminal" and entry.get("terminal") == "skip" and (route["voting"] or route["kind"] == "writer"):
            raise ProfileError("skip is allowed only for non-voting jobs", path=entry["path"])
        if name is None:
            return
        if rule == "cross_family" and cross and route["voting"] and families[name] in writer_families:
            raise ProfileError("cross-family review route reaches the writer family", path=entry["path"],
                               related_paths=("model_settings.roles.writer.hosts", "model_settings.hosts." + name + ".kind"))
        if rule == "admission" and not route["pinned"] and name not in allowed:
            raise ProfileError("fallback destination is not admitted for this job", path=entry["path"])
        if rule == "pinned_family" and route["pinned"] and families[name] != families[route["binding"][0]]:
            raise ProfileError("pinned lens fallback changes family", path=entry["path"],
                               related_paths=("model_settings.hosts." + name + ".kind",))

    order, grouped = [], {}
    for kind, host in starts:
        route = planned(kind, host)
        review = kind.startswith("reviewer.") or kind == "lens.extra" or kind not in roles and kind != "doc"
        category = "review" if review else "writer" if kind == "writer" else "other"
        if category not in grouped:
            order.append(category)
            grouped[category] = []
        destinations = set() if kind == "doc" else checked[kind]
        allowed = set(route["admitted"]) if kind == "doc" else admitted[kind]
        cross = review and cross_family and (kind not in roles or kind == "reviewer.correctness" or
                                             (kind.startswith("reviewer.") and not route["pinned"]))
        for entry in route["entries"]:
            name = entry.get("host")
            if name in destinations:
                continue
            if name is not None:
                destinations.add(name)
            grouped[category].append((route, entry, allowed, cross))
    for category in order:
        for rule in _ROUTE_REFUSAL_ORDER[category]:
            for route, entry, allowed, cross in grouped[category]:
                refuse(rule, route, entry, allowed, cross)


def _complete(profile):
    settings = profile["model_settings"]
    hosts, roles = settings["hosts"], settings["roles"]
    if len(hosts) > MAX_HOSTS:
        raise ProfileError("profile host limit exceeded", path="model_settings.hosts")
    try:
        team_supervisor.validate_input(profile, {**JSON_SCHEMA, "error_path": "", "node_budget": 4 * MAX_NODES}, resolved=True)
    except team_supervisor.SupervisorError as error:
        raise ProfileError(str(error), path=error.path) from None
    _reject_terminal_hosts(hosts, ProfileError, "model_settings.hosts")
    for name in sorted(hosts):
        host = hosts[name]
        if "kind" not in host:
            raise ProfileError("incomplete host: kind required", path="model_settings.hosts." + name)
        if host["kind"] not in PRESET_DATA["hosts"] or not PRESET_DATA["hosts"][host["kind"]]["writer"]:
            raise ProfileError("host kind not qualified for team-run roles", path="model_settings.hosts." + name + ".kind")
    for name in sorted(roles):
        role = roles[name]
        path = "model_settings.roles." + name
        if "optional" in role and name != "lens.extra":
            raise ProfileError("optional is allowed only on lens.extra", path=path + ".optional")
        if "hosts" not in role or (not role["hosts"] and not role.get("optional", False)):
            raise ProfileError("incomplete role: declared hosts required", path=path + ".hosts")
        if len(role["hosts"]) > MAX_HOSTS:
            raise ProfileError("profile host binding limit exceeded", path=path + ".hosts")
        if any(host not in hosts for host in role["hosts"]):
            raise ProfileError("role references undeclared host", path=path + ".hosts")
    _capacity_complete(settings)
    _lens_identities(profile)

    families = {name: PRESET_DATA["hosts"][host["kind"]]["family"] for name, host in hosts.items()}

    for name in sorted(roles):
        role = roles[name]
        chain = role["hosts"]
        if role.get("pinned_family", False) and chain and any(families[host] != families[chain[0]] for host in chain):
            raise ProfileError("pinned role chain changes family", path="model_settings.roles." + name + ".hosts",
                               related_paths=("model_settings.roles." + name + ".pinned_family",
                                              *("model_settings.hosts." + host + ".kind" for host in chain)))

    _review_routes(profile, families)
    for gate in profile["policy"]["gates"]:
        if not {"name", "runner", "selector", "must_pass"} <= gate.keys():
            raise ProfileError("incomplete gate")
        if gate["runner"] not in profile["run_config"]["runners"]:
            raise ProfileError("gate references undeclared runner")


def _policy_layer(document, layer):
    if layer == "repo":
        return
    settings = document.get("model_settings", {})
    if layer == "flags" and any(any(key in value for key in ("optional", "pinned_family"))
                                for value in settings.get("roles", {}).values()):
        raise _context(ProfileError("optional/pinned-family settings are repository-only; use the approval-before-merge path"), layer)
    governed = ("policy" in document or any(key in document.get("run_config", {}) for key in ("autopilot", "limits"))
                or any(any(kind in value.get("fallback", {}) for kind in
                           (("review", "reviewer.correctness", "reviewer.security", "extra-review", "lens.extra")
                            if layer == "user" else CAPACITY_KINDS))
                       for value in settings.get("capacity", {}).values())
                or any((name.startswith("reviewer.") or name == "lens.extra") and
                       any(key in value for key in ("hosts", "optional", "pinned_family"))
                       for name, value in settings.get("roles", {}).items())
                or any("kind" in value for value in settings.get("hosts", {}).values()))
    if governed:
        raise _context(ProfileError("governance policy is repository-only; use the approval-before-merge path"), layer)


_ABSENT = object()


def _lookup(document, path):
    for component in path:
        if type(document) is not dict or component not in document:
            return _ABSENT
        document = document[component]
    return document


def _set_leaf(document, path, value):
    for component in path[:-1]:
        document = document.setdefault(component, {})
    document[path[-1]] = deepcopy(value)


def _user_threshold_hosts(repository, names, entry):
    compatible = []
    for name in names:
        prior = repository["model_settings"]["capacity"].get(name, {}).get("thresholds", {})
        thresholds = capacity_thresholds({"thresholds": {**prior, **entry.get("thresholds", {})}})
        if thresholds["flex_route_pct"] <= thresholds["route_pct"] <= thresholds["hold_pct"]:
            compatible.append(name)
    return compatible


def _user_layer(document, repository):
    """Bind preferences by components; record repetitions without merging them."""
    result, records, applied = deepcopy(document), {}, {}
    settings = result.pop("model_settings", {})
    hosts, roles = repository["model_settings"]["hosts"], repository["model_settings"]["roles"]

    def record(path, value, targets, reason):
        repeated = [target for target in targets if _lookup(repository, target) == value]
        if targets and len(repeated) == len(targets):
            reason = "repeats repository"
        records[("user", *path)] = {
            "value": value, "layer": "user", "frozen_at_run_start": path[0] in ("model_settings", "run_config"),
            "status": "applied" if targets else "ignored", "reason": reason,
            "applied_to": [".".join(target) for target in targets],
            "applied_paths": [list(target) for target in targets],
        }
        for target in targets:
            if target not in repeated:
                _set_leaf(applied, target, value)

    for section in ("hosts", "capacity"):
        for kind, entry in settings.get(section, {}).items():
            names = [name for name, host in hosts.items() if host.get("kind") == kind]
            threshold_hosts = _user_threshold_hosts(repository, names, entry) if section == "capacity" else names
            for field, value in list(_leaves(entry)) or [((), {})]:
                targets = [("model_settings", section, name, *field) for name in names if type(value) is not dict and
                           (field[:1] != ("thresholds",) or name in threshold_hosts) and
                           (field[0] != "fallback" or _lookup(repository, ("model_settings", section, name, *field)) == value)]
                reason = ("host kind is not declared by this repository" if not names else
                          "empty object has no effect" if type(value) is dict else
                          "threshold preferences conflict with repository" if field[:1] == ("thresholds",) and not targets else
                          "routing is declared by the repository" if not targets else "bound by registered host kind")
                record(("model_settings", section, kind, *field), value, targets, reason)
    for name, entry in settings.get("roles", {}).items():
        for field, value in list(_leaves(entry)) or [((), {})]:
            target = ("model_settings", "roles", name, *field)
            repository_only = field in (("optional",), ("pinned_family",))
            applies = (not repository_only and name in roles and type(value) is not dict and
                       (field in (("model",), ("effort",)) or _lookup(repository, target) == value))
            reason = ("repository-only" if repository_only else
                      "role is not declared by this repository" if name not in roles else
                      "empty object has no effect" if type(value) is dict else
                      "routing is declared by the repository" if not applies else "bound to declared repository role")
            record(target, value, [target] if applies else [], reason)
    for path, value in _leaves(result):
        if type(value) is dict:
            record(path, value, [], "empty object has no effect")
        elif _lookup(repository, path) == value:
            record(path, value, [path], "repeats repository")
        else:
            _set_leaf(applied, path, value)
    return applied, records


def resolve(*, preset=None, repo=None, user=None, flags=None, live_run=False):
    """Attribute intrinsic repository defects before evaluating the owner ceiling."""
    try:
        return _resolve(preset=preset, repo=repo, user=user, flags=flags, live_run=live_run)
    except ProfileError as error:
        try:
            _repository_intrinsic(preset, repo)
        except ProfileError as repository_error:
            raise _context(repository_error, "repo") from None
        try:
            _resolve(preset=preset, repo=repo, user=user)
        except ProfileError as user_error:
            # assemble identifies repository widening against the actual owner
            # ceiling. Other combined-prefix failures belong to the user.
            raise _context(user_error, "user") from None
        # Both earlier prefixes are valid. Only the added flags/live-run
        # restrictions can account for the final refusal.
        raise _context(error, "flags") from None


def _repository_intrinsic(preset, repo):
    """Check repository syntax and policy without comparing supervisor to defaults.

    A valid owner file may widen those defaults. Its absence during attribution
    must not manufacture a repository failure that hides an owner-file refusal.
    """
    try:
        prepared, _fragments = _split_supervisor([("repo", {} if repo is None else repo)])
        _resolve(preset=preset, repo=prepared[0][1])
    except ProfileError as error:
        raise _context(error, "repo") from None


def _split_supervisor(layers):
    """Validate each layer, then hold supervisor fragments out of the generic merge."""
    prepared, fragments = [], {}
    for layer, document in layers:
        try:
            _validate(document, USER_JSON_SCHEMA if layer == "user" else JSON_SCHEMA, "", layer)
            _policy_layer(document, layer)
        except ProfileError as error:
            raise _context(error, layer)
        if type(document) is dict and "supervisor" in document:
            fragments[layer] = document["supervisor"]
            document = {key: value for key, value in document.items() if key != "supervisor"}
        prepared.append((layer, document))
    return prepared, fragments


def _resolve(*, preset=None, repo=None, user=None, flags=None, live_run=False):
    """Validate partial layers before merging; return values and per-leaf origins.

    Repository policy changes go through the existing human gate before merge.
    User/flag layers cannot set policy. There is no runtime approval switch.
    """
    layers, fragments = _split_supervisor([
        ("repo", {} if repo is None else repo), ("user", {} if user is None else user),
        ("flags", {} if flags is None else flags),
    ])
    if preset is not None and (type(preset) is not str or preset not in PRESET_DATA["presets"]):
        raise ProfileError("unknown preset; use aegis team config presets --json", layer="flags", file="<command-line>", exit_code=2)
    selected = preset or PRESET_DATA["defaults"]["preset"]
    selected = layers[0][1].get("preset", selected)
    for layer, document in layers[1:]:
        candidate = document.get("preset", selected)
        if candidate != selected:
            raise _context(ProfileError("governance: select the preset in the repository profile"), layer)
    if type(selected) is not str or selected not in PRESET_DATA["presets"]:
        raise ProfileError("unknown preset; use aegis team config presets")
    result, origins = {}, {}
    _merge(result, PRESET_DATA["defaults"], origins, "defaults")
    _merge(result, PRESET_DATA["presets"][selected], origins, "preset:" + selected)
    result["preset"] = selected
    origins[("preset",)] = "preset:" + selected
    user_records = {}
    for layer, document in layers:
        if layer == "flags" and live_run and any(key in document for key in ("preset", "model_settings", "run_config")):
            raise _context(ProfileError("frozen_at_run_start values cannot change on a live run"), layer)
        if layer == "user":
            document, user_records = _user_layer(document, result)
        _merge(result, document, origins, layer)
    if "main" not in result["policy"]["landing"]["signature_required_for"]:
        raise _context(ProfileError("governance floor: signatures required for main"), "repo")
    if result["run_config"]["autopilot"]["rulings"] != "owner":
        raise _context(ProfileError("governance floor: rulings remain with owner"), "repo")
    _complete(result)
    try:
        supervisor, supervisor_origins = team_supervisor.assemble(fragments.get("user", {}), fragments.get("repo", {}))
    except team_supervisor.SupervisorError as error:
        raise _context(ProfileError(str(error), path=error.path, layer=error.layer), error.layer or "repo")
    result["supervisor"] = supervisor
    origins.update(supervisor_origins)
    values = {path: {"value": value, "layer": origins[path],
                     "frozen_at_run_start": path[0] in ("model_settings", "run_config", "supervisor")}
              for path, value in _leaves(result)}
    values.update(user_records)
    writer_hosts = result["model_settings"]["roles"].get("writer", {}).get("hosts", [])
    boundaries = ["write scope: " + PRESET_DATA["hosts"][result["model_settings"]["hosts"][host]["kind"]]["boundary"]
                  for host in writer_hosts]
    return {"profile": result, "values": _display_values(values), "write_scope": boundaries}


def governance_status():
    """Declare the merge boundary without claiming an approval was verified."""
    return {"path": "/".join(REPO_PATH), "status": "governance_path",
            "approval_required_before_merge": True, "approval": "not checked",
            "message": "Profile changes need approval before merge through aegis approve and hosted aegis-governance."}


def descriptor_supported():
    return storage.confined_descriptor_supported()


@contextmanager
def _profile_file(root, parts, create=False):
    if not descriptor_supported():
        raise ProfileError("unsupported platform: anchored profile operations unavailable")
    with storage.confined_file(root, parts, create_parents=create) as handle:
        yield handle


def _file_refusal(error):
    messages = {
        "unsupported": "unsupported platform: anchored profile operations unavailable",
        "invalid_path": "unsafe profile root; use an absolute trusted directory",
        "too_large": "profile size limit exceeded",
        "exists": "profile already exists; inspect it or use --force",
    }
    return ProfileError(messages.get(error.reason, "unsafe or unreadable profile path"))


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ProfileError("duplicate key in profile JSON")
        result[key] = value
    return result


def _parse(data):
    if len(data) > MAX_BYTES:
        raise ProfileError("profile size limit exceeded")
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        raise ProfileError("invalid profile JSON") from None
    # Preflight containers, strings, nesting and nodes before tree allocation.
    depth, nodes, chars, unicode_left = 0, 0, 0, 0
    quoted, escaped, atom = False, False, False
    containers = []  # [entry count, awaiting first token of the next entry]
    for char in text:
        if not quoted and containers and containers[-1][1] and char not in " \t\r\n]}":
            containers[-1][0] += 1
            containers[-1][1] = False
            if containers[-1][0] > MAX_ITEMS:
                raise ProfileError("profile container size limit exceeded")
        if quoted:
            if unicode_left:
                unicode_left -= 1
            elif escaped:
                escaped = False
                if char == "u":
                    unicode_left = 4
            elif char == "\\":
                escaped = True
                chars += 1
            elif char == '"':
                quoted = False
            else:
                chars += 1
            if chars > MAX_STRING:
                raise ProfileError("profile string size limit exceeded")
        elif char == '"':
            quoted = True
            chars, atom = 0, False
            nodes += 1
        elif char in "[{":
            nodes += 1
            atom = False
            depth += 1
            if depth > MAX_DEPTH:
                raise ProfileError("profile nesting limit exceeded")
            containers.append([0, True])
        elif char in "]}":
            depth -= 1
            atom = False
            if containers:
                containers.pop()
        elif char in " \t\r\n,:":
            atom = False
            if char == "," and containers:
                containers[-1][1] = True
        elif not atom:
            nodes += 1
            atom = True
        if nodes > MAX_NODES:
            raise ProfileError("profile node limit exceeded")
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ProfileError("invalid profile JSON")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, ProfileError):
            raise
        raise ProfileError("invalid profile JSON") from None
    if type(value) is not dict or "version" not in value:
        raise ProfileError("profile version required")
    return value


def _read(root, parts, layer):
    file = str(root.joinpath(*parts))
    try:
        with _profile_file(root, parts) as handle:
            if layer == "user":
                info = handle.parent_stat()
                if info.st_uid != os.getuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    raise ProfileError("user profile directory must be owned by the current user and not group/other-writable")
                data = team_supervisor.read_owned_leaf(
                    handle._parent, parts[-1], MAX_BYTES,
                    "user profile file must be owned by the current user and not group/other-writable")
                return {} if data is None else _parse(data)
            return _parse(handle.read_bytes(MAX_BYTES))
    except storage.ConfinedFileError as error:
        if error.reason == "missing":
            return {}
        raise _context(_file_refusal(error), layer, file) from None
    except ProfileError as error:
        raise _context(error, layer, file)
    except team_supervisor.SupervisorError as error:
        reason = str(error) if error.layer == "user" else "unsafe or unreadable profile path"
        raise _context(ProfileError(reason), layer, file) from None
    except OSError:
        raise _context(ProfileError("unsafe or unreadable profile path"), layer, file) from None


def _repository_root(root):
    return _validate(root, {"type": "root", "refusal": "unsafe profile root; use an absolute trusted directory"},
                     "root", "repo")


def _owner_config_root(user_root):
    """Resolve an absolute owner home before any anchored read."""
    message = "user profile root unavailable; configure a home directory"
    if user_root is None:
        layout = UserLayout.current()
        if layout is None:
            raise _context(ProfileError(message), "user")
        home = layout.home
    else:
        home = user_root
    try:
        # The owner-selected directory chain includes stow's folded aegis link.
        # Resolve an absolute home once, then verify its opened descriptor.
        resolved = team_supervisor.resolved_home(home)
        root = resolved.joinpath(*USER_PATH[:-1]).resolve()
        _validate(root, {"type": "root", "refusal": message}, "root", "user")
        return root
    except (team_supervisor.SupervisorError, OSError, RuntimeError, ValueError):
        raise _context(ProfileError(message), "user") from None


def load(root, *, user_root=None):
    root = _repository_root(root)
    config_root = _owner_config_root(user_root)
    try:
        repository = _read(root, REPO_PATH, "repo")
        try:
            user = _read(config_root, USER_PATH[-1:], "user")
        except ProfileError:
            # Parsing/refusal occurs before resolve sees the user document.
            # Check intrinsic repository policy without a fabricated default
            # supervisor ceiling when the owner file could not be read.
            _repository_intrinsic(None, repository)
            raise
        resolved = resolve(repo=repository, user=user)
        # A parsed on-disk profile always has version; only a missing anchored
        # read returns {}. Keep this observation with the resolved snapshot.
        resolved["repository_profile_exists"] = bool(repository)
        return resolved
    except ProfileError as error:
        if error.layer in ("repo", "user"):
            error.file = str(root.joinpath(*REPO_PATH) if error.layer == "repo" else config_root / USER_PATH[-1])
        raise


def _preset_document(preset, host=None):
    resolved = resolve(preset=preset)["profile"]
    document = {"version": 1, "preset": resolved["preset"]}
    if host is None:
        return document
    if type(host) is not str or host not in PRESET_DATA["hosts"] or not PRESET_DATA["hosts"][host]["writer"]:
        raise ProfileError("host kind is not qualified for a preset binding", layer="flags", file="<command-line>", exit_code=2)
    settings = resolved["model_settings"]
    writers = settings["roles"].get("writer", {}).get("hosts", [])
    if not writers:
        raise ProfileError("this preset has no model host to bind", layer="flags", file="<command-line>", exit_code=2)
    hosts = deepcopy(settings["hosts"])
    hosts[writers[0]]["kind"] = host
    pinned_roles = {}
    for name, role in settings["roles"].items():
        if role.get("pinned_family", False):
            chain = []
            for alias in role["hosts"]:
                if hosts[alias]["kind"] != settings["hosts"][alias]["kind"]:
                    pinned_alias = "pinned-" + alias
                    hosts[pinned_alias] = deepcopy(settings["hosts"][alias])
                    chain.append(pinned_alias)
                else:
                    chain.append(alias)
            if chain != role["hosts"]:
                pinned_roles[name] = {"hosts": chain}
    if resolved["policy"]["review"]["require_cross_family"]:
        alternatives = [kind for kind, data in PRESET_DATA["hosts"].items()
                        if data["writer"] and data["family"] != PRESET_DATA["hosts"][host]["family"]]
        if not alternatives:
            raise ProfileError("no qualified cross-family preset binding exists", layer="flags", file="<command-line>", exit_code=2)
        for name in settings["roles"]["reviewer.correctness"]["hosts"]:
            if PRESET_DATA["hosts"][hosts[name]["kind"]]["family"] == PRESET_DATA["hosts"][host]["family"]:
                hosts[name]["kind"] = alternatives[0]
    document["model_settings"] = {"hosts": hosts}
    if pinned_roles:
        document["model_settings"]["roles"] = pinned_roles
    resolve(repo=document)
    return document


def initialize(root, preset, *, host=None, force=False):
    document = _preset_document(preset, host)
    root = _repository_root(root)
    data = (json.dumps(document, indent=2) + "\n").encode("utf-8")
    try:
        with _profile_file(root, REPO_PATH, create=True) as handle:
            try:
                existing = _parse(handle.read_bytes(MAX_BYTES))
                if not force:
                    raise ProfileError("profile already exists; inspect it or use --force")
                # N/N-1: --force never authorizes misreading a future schema.
                resolve(repo=existing)
            except storage.ConfinedFileError as error:
                if error.reason != "missing":
                    raise
            handle.publish_bytes(data, replace=force)
    except storage.ConfinedFileError as error:
        raise _context(_file_refusal(error), "repo", str(root.joinpath(*REPO_PATH))) from None
    except ProfileError as error:
        error = _context(error, "repo")
        if error.layer == "repo":
            error.file = str(root.joinpath(*REPO_PATH))
        raise error
    return document


def validate_resolved(resolved, root=None):
    """Recheck route policy and supervisor bounds before consuming a resolved profile."""
    file = str(_repository_root(root).joinpath(*REPO_PATH)) if root is not None else None
    def complete(body):
        _complete(body)
        team_supervisor.require_resolved(body["supervisor"])

    try:
        envelope = {"validation_order": ("profile", "values", "write_scope", "repository_profile_exists"), **_object({
            "profile": {**JSON_SCHEMA, "error_path": "", "node_budget": 4 * MAX_NODES, "after": complete},
            "values": {"type": "provenance", "schema": JSON_SCHEMA, "user_schema": USER_JSON_SCHEMA},
            "write_scope": _array(_TEXT), "repository_profile_exists": _BOOL,
        })}
        _validate(resolved, envelope, "", "repo",
                  required={"profile": {**PRESET_DATA["defaults"], "supervisor": team_supervisor.assemble({}, {})[0]},
                            "values": {}, "write_scope": []}, resolved=True)
    except ProfileError as error:
        raise _context(error, "repo", file)
    except team_supervisor.SupervisorError as error:
        raise _context(ProfileError(str(error), path=error.path, layer=error.layer), "repo", file)


def doctor(resolved, root=None):
    validate_resolved(resolved, root)
    installed = {kind: pathlookup.which(data["cli"], outside=root) is not None for kind, data in PRESET_DATA["hosts"].items()}
    hosts = [{"name": name, "kind": host["kind"], "cli": PRESET_DATA["hosts"][host["kind"]]["cli"],
              "found": installed[host["kind"]]} for name, host in resolved["profile"]["model_settings"]["hosts"].items()]
    available, bindings = [], []
    for preset in PRESET_DATA["presets"]:
        kinds = [kind for kind, data in PRESET_DATA["hosts"].items() if data["writer"] and installed[kind]]
        for kind in [None] if preset == "ci-only" else kinds:
            candidate = resolve(repo=_preset_document(preset, kind))["profile"]["model_settings"]["hosts"]
            if all(installed[host["kind"]] for host in candidate.values()):
                bindings.append({"preset": preset, "host": kind,
                                 "hosts": {name: host["kind"] for name, host in candidate.items()}})
        current_runnable = (preset == resolved["profile"]["preset"] and all(host["found"] for host in hosts))
        if current_runnable or any(binding["preset"] == preset for binding in bindings):
            available.append(preset)
    families = {PRESET_DATA["hosts"][kind]["family"] for kind, found in installed.items()
                if found and PRESET_DATA["hosts"][kind]["writer"]}
    return {"hosts": hosts, "runnable_presets": available, "runnable_bindings": bindings,
            "suggested_presets": ["pair", "mixed"] if len(families) > 1 else [],
            "complete": True, "healthy": all(host["found"] for host in hosts),
            "checks": {"profile": "complete", "cli": "PATH only", "login": "not checked", "network": "not checked"},
            "write_scope": resolved["write_scope"]}


def display_profile(value: Any, *, capacity=False) -> Any:
    """Render through the shared policy; capacity views opt into typed actions."""
    value, snapshot = _validate(value, {"type": "display", "profile_keys": tuple(JSON_SCHEMA["properties"])}, "", "repo")
    if snapshot is not None:
        validate_resolved(snapshot)
    return _render_profile(value, capacity=capacity,
                           identifier_pattern=_IDENTIFIER_PATTERN, max_string=MAX_STRING)
