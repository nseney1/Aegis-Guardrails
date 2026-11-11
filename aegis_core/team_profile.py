"""Versioned team profiles: closed layers, provenance and confined local storage.

No process or network probes occur here. Host capabilities below mirror the
registry in tools/hierarchy_hosts.py; native app threads cannot bind run roles.
Anchored feature-owned I/O remains until STORE-API-1 supplies the shared boundary
and platform support. Windows filesystem-backed operations currently refuse.
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
import uuid
from typing import Any

from aegis_core import pathlookup
from aegis_core.primitives import sanitize_display
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
NEXT_ACTION_TEMPLATES = {
    "start": ("Start the job on ", "; capacity advice grants no execution authority."),
    "check": ("Run aegis team hosts check ", " ", " --json; use that declared host if admitted."),
}
_CAPACITY_ALIASES = {"review": "reviewer.correctness", "extra-review": "lens.extra"}
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


def _object(properties):
    return {"type": "object", "properties": properties, "additionalProperties": False}


def _map(items, limit=MAX_ITEMS):
    return {"type": "object", "patternProperties": {_IDENTIFIER_PATTERN: items},
            "additionalProperties": False, "maxProperties": limit}


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
    **_object({
        "version": {"type": "integer", "enum": [1]},
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
        "model_settings": _object({"hosts": _map(_HOST, MAX_HOSTS), "roles": _object({
            name: _ROLE for name in ("writer", "reviewer.correctness", "reviewer.security", "lens.extra", "research")}),
            "capacity": _map(_CAPACITY)}),
        "run_config": _object({"runners": _map(_RUNNER),
            "autopilot": _object({"queue_full_on_ready": _BOOL, "claim_next": _BOOL, "resume_writer": _BOOL,
                                   "rulings": {"type": "string", "enum": ["owner", "coordinator"]}}),
            "limits": _object({"writers_max": _INT, "votes_max": _INT, "research_max": _INT}),
            "token_budgets": {**_map(_INT), "user_layer_only": True}}),
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


def _bounded(value, depth=0, budget=None):
    if budget is None:
        budget = [MAX_NODES]
    budget[0] -= 1
    if depth > MAX_DEPTH or budget[0] < 0:
        raise ProfileError("profile nesting or node limit exceeded")
    if type(value) is str and len(value) > MAX_STRING:
        raise ProfileError("profile string size limit exceeded")
    if type(value) in (dict, list):
        if len(value) > MAX_NODES:
            raise ProfileError("profile node limit exceeded")
        for item in (value.items() if type(value) is dict else enumerate(value)):
            if type(value) is dict:
                _bounded(item[0], depth + 1, budget)
            _bounded(item[1], depth + 1, budget)


def _validate(value, schema, path, layer):
    try:
        _validate_value(value, schema, path, layer)
    except ProfileError as error:
        if error.path is None:
            error.path = path
        raise _context(error, layer)


def _validate_value(value, schema, path, layer):
    types = schema["type"]
    types = [types] if type(types) is str else types
    names = {dict: "object", list: "array", str: "string", bool: "boolean", int: "integer",
             float: "number", type(None): "null"}
    actual = names.get(type(value))
    if actual not in types and not (actual == "integer" and "number" in types):
        raise ProfileError("wrong type: " + (path or "profile"))
    if schema.get("user_layer_only") and layer != "user":
        raise ProfileError("user-only key: " + path)
    if "enum" in schema and value not in schema["enum"]:
        reason = "unregistered host kind" if path.endswith(".kind") else "invalid value"
        raise ProfileError(reason + ": " + path)
    if actual == "string" and "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
        raise ProfileError("invalid identifier: " + path)
    if type(value) in (int, float):
        if not schema.get("minimum", 0) <= value <= schema.get("maximum", 1000000):
            raise ProfileError("value out of range: " + path)
    if actual == "object":
        if len(value) > schema.get("maxProperties", MAX_ITEMS):
            raise ProfileError("profile object size limit exceeded")
        for key, child in value.items():
            if type(key) is not str:
                raise ProfileError("profile keys must be strings")
            child_schema = schema.get("properties", {}).get(key)
            if child_schema is None:
                child_schema = next((item for pattern, item in schema.get("patternProperties", {}).items()
                                     if re.fullmatch(pattern, key)), None)
            child_path = path + "." + key if path else key
            if child_schema is None:
                raise ProfileError("unknown key: " + child_path)
            _validate(child, child_schema, child_path, layer)
    elif actual == "array":
        if len(value) > schema["maxItems"]:
            raise ProfileError("profile array size limit exceeded: " + path)
        for index, child in enumerate(value):
            _validate(child, schema["items"], path + "." + str(index), layer)


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
    for name, capacity in settings["capacity"].items():
        path = "model_settings.capacity." + name
        if name not in hosts:
            raise ProfileError("capacity references undeclared host", path=path)
        thresholds = capacity_thresholds(capacity)
        if not thresholds["flex_route_pct"] <= thresholds["route_pct"] <= thresholds["hold_pct"]:
            raise ProfileError("capacity thresholds must satisfy flex_route_pct <= route_pct <= hold_pct",
                               path=path + ".thresholds")
        for kind, chain in capacity.get("fallback", {}).items():
            if len(chain) > MAX_FALLBACK_CHAIN:
                raise ProfileError("profile fallback chain limit exceeded", path=path + ".fallback." + kind)
            edges += len(chain)
            if edges > MAX_FALLBACK_EDGES:
                raise ProfileError("profile fallback edge limit exceeded", path="model_settings.capacity")
            if any(target not in hosts and target not in ("hold", "skip") for target in chain):
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
    Cycles terminate; the first terminal ends traversal. Restarting from an
    admitted host keeps explicit fallbacks to earlier hosts in the binding.
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
            if name not in settings["hosts"]:
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
        index = next((index for index, entry in enumerate(entries) if entry.get("host") == start_host), None)
        if start_host not in admitted:
            raise _context(ProfileError("host is not bound to this job; use its declared role hosts", path=job["path"]), "repo")
        roots = entries[index:] if index is not None else [{"host": name, "path": job["path"]}
                                                          for name in binding[binding.index(start_host):]]
        entries = traverse([(entry.get("host", entry.get("terminal")), entry["path"]) for entry in roots])
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
    kinds = [kind for kind, role in roles.items() if role["hosts"]]
    kinds += [lens["name"] for lens in profile["policy"]["review"]["lenses"]]
    @lru_cache(maxsize=None)
    def planned(kind, start=None):
        return plan(profile, kind, start_host=start)

    bindings = {kind: planned(kind) for kind in kinds}
    starts = [(kind, host) for kind, binding in bindings.items()
              for host in dict.fromkeys([*binding["binding"], *binding["admitted"]])]
    starts += [("doc", host) for host in hosts]
    # Cache every restarted plan before checking policy, preserving refusal order.
    for kind, host in starts:
        planned(kind, host)
    writers = {entry["host"] for kind, host in starts if kind == "writer"
               for route in (planned(kind, host),)
               for entry in (route["entries"][:1] if route["pinned"] else route["entries"]) if "host" in entry}
    writer_families = {families[host] for host in writers}
    admitted = {kind: set(binding["admitted"]) for kind, binding in bindings.items()}
    checked = {kind: set() for kind in kinds}
    cross_family = profile["policy"]["review"]["require_cross_family"]
    if cross_family and (not writers or not roles.get("reviewer.correctness", {}).get("hosts")):
        raise ProfileError("cross-family review needs declared writer and reviewer hosts", path="policy.review.require_cross_family")

    for kind, host in starts:
        route = planned(kind, host)
        # Role/lens facts apply across starts; doc admission is host-rooted.
        destinations = set() if kind == "doc" else checked[kind]
        allowed = set(route["admitted"]) if kind == "doc" else admitted[kind]
        review = kind.startswith("reviewer.") or kind == "lens.extra" or kind not in roles
        cross = cross_family and (kind not in roles or kind == "reviewer.correctness" or
                                  (kind.startswith("reviewer.") and not route["pinned"]))
        for entry in route["entries"]:
            if "terminal" in entry:
                if entry["terminal"] == "skip" and (route["voting"] or kind == "writer"):
                    raise ProfileError("skip is allowed only for non-voting jobs", path=entry["path"])
                continue
            name = entry["host"]
            if name in destinations:
                continue
            if review and route["pinned"] and families[name] != families[route["binding"][0]]:
                raise ProfileError("pinned lens fallback changes family", path=entry["path"],
                                   related_paths=("model_settings.hosts." + name + ".kind",))
            if cross and route["voting"] and families[name] in writer_families:
                raise ProfileError("cross-family review route reaches the writer family", path=entry["path"],
                                   related_paths=("model_settings.roles.writer.hosts", "model_settings.hosts." + name + ".kind"))
            if not route["pinned"] and name not in allowed:
                raise ProfileError("fallback destination is not admitted for this job", path=entry["path"])
            destinations.add(name)


def _complete(profile):
    settings = profile["model_settings"]
    hosts, roles = settings["hosts"], settings["roles"]
    if len(hosts) > MAX_HOSTS:
        raise ProfileError("profile host limit exceeded", path="model_settings.hosts")
    for name, host in hosts.items():
        if "kind" not in host:
            raise ProfileError("incomplete host: kind required", path="model_settings.hosts." + name)
        if host["kind"] not in PRESET_DATA["hosts"] or not PRESET_DATA["hosts"][host["kind"]]["writer"]:
            raise ProfileError("host kind not qualified for team-run roles", path="model_settings.hosts." + name + ".kind")
    for name, role in roles.items():
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

    for name, role in roles.items():
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


def _display_values(records):
    """Serialize component-keyed provenance; keep ambiguous labels lossless."""
    labels = {}
    for path in records:
        labels.setdefault(".".join(path), []).append(path)
    result = {}
    for label, paths in labels.items():
        for path in paths:
            key = label if len(paths) == 1 else json.dumps(path, separators=(",", ":"))
            result[key] = {**records[path], "path": list(path)}
    return result


def resolve(*, preset=None, repo=None, user=None, flags=None, live_run=False):
    """Attribute refusals by resolving again without the user, never by origins."""
    try:
        return _resolve(preset=preset, repo=repo, user=user, flags=flags, live_run=live_run)
    except ProfileError as error:
        try:
            _resolve(preset=preset, repo=repo)
        except ProfileError as repository_error:
            raise _context(repository_error, "repo") from None
        try:
            _resolve(preset=preset, repo=repo, user=user)
        except ProfileError as user_error:
            raise _context(user_error, "user") from None
        # Both earlier prefixes are valid. Only the added flags/live-run
        # restrictions can account for the final refusal.
        raise _context(error, "flags") from None


def _resolve(*, preset=None, repo=None, user=None, flags=None, live_run=False):
    """Validate partial layers before merging; return values and per-leaf origins.

    Repository policy changes go through the existing human gate before merge.
    User/flag layers cannot set policy. There is no runtime approval switch.
    """
    layers = [("repo", {} if repo is None else repo), ("user", {} if user is None else user),
              ("flags", {} if flags is None else flags)]
    for layer, document in layers:
        try:
            _bounded(document)
            if type(document) is dict and "version" in document and (type(document["version"]) is not int or document["version"] != 1):
                raise ProfileError("unsupported profile version; upgrade aegis")
            _validate(document, USER_JSON_SCHEMA if layer == "user" else JSON_SCHEMA, "", layer)
            _policy_layer(document, layer)
        except ProfileError as error:
            raise _context(error, layer)
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
    values = {path: {"value": value, "layer": origins[path],
                     "frozen_at_run_start": path[0] in ("model_settings", "run_config")}
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
    names = {function.__name__ for function in os.supports_dir_fd}
    return (os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
            and {"open", "mkdir", "link", "rename", "unlink"} <= names)


@contextmanager
def _directory(root, components=(), create=False):
    if not descriptor_supported():
        raise ProfileError("unsupported platform: anchored profile operations unavailable")
    given = Path(root)
    if not given.is_absolute() or ".." in given.parts:
        raise ProfileError("unsafe profile root; use an absolute trusted directory")
    fd = None
    try:
        fd = os.open(given.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        for index, component in enumerate((*given.parts[1:], *components)):
            if create and index >= len(given.parts) - 1:
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
            parent, fd = fd, child
            os.close(parent)
        yield fd
    finally:
        if fd is not None:
            os.close(fd)


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


def _read_at(parent, name):
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ProfileError("unsafe profile: regular file required")
        if info.st_size > MAX_BYTES:
            raise ProfileError("profile size limit exceeded")
        data = bytearray()
        while len(data) <= MAX_BYTES:
            chunk = os.read(fd, min(8192, MAX_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > MAX_BYTES:
            raise ProfileError("profile size limit exceeded")
        return _parse(data)
    finally:
        if fd is not None:
            os.close(fd)


def _read(root, parts, layer):
    file = str(Path(root).joinpath(*parts))
    try:
        with _directory(root, parts[:-1]) as parent:
            if layer == "user":
                info = os.fstat(parent)
                if info.st_uid != os.getuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    raise ProfileError("user profile directory must be owned by the current user and not group/other-writable")
            return _read_at(parent, parts[-1])
    except FileNotFoundError:
        return {}
    except ProfileError as error:
        raise _context(error, layer, file)
    except OSError:
        raise ProfileError("unsafe or unreadable profile path", layer=layer, file=file) from None


def load(root, *, user_root=None):
    try:
        if user_root is None:
            layout = UserLayout.current()
            if layout is None:
                raise _context(ProfileError("user profile root unavailable; configure a home directory"), "user")
            home = layout.home
        else:
            home = Path(user_root)
        # The owner-selected directory chain includes stow's folded aegis link.
        # Resolve once, then verify its opened descriptor; never resolve the leaf.
        home = home.resolve()
        config_root = home.joinpath(*USER_PATH[:-1]).resolve()
    except (OSError, RuntimeError):
        raise _context(ProfileError("user profile root unavailable; configure a home directory"), "user") from None
    try:
        repository = _read(root, REPO_PATH, "repo")
        try:
            user = _read(config_root, USER_PATH[-1:], "user")
        except ProfileError:
            # Parsing/refusal occurs before resolve sees the user document.
            # Apply the same repository-only counterfactual at this boundary.
            resolve(repo=repository)
            raise
        resolved = resolve(repo=repository, user=user)
        # A parsed on-disk profile always has version; only a missing anchored
        # read returns {}. Keep this observation with the resolved snapshot.
        resolved["repository_profile_exists"] = bool(repository)
        return resolved
    except ProfileError as error:
        if error.layer in ("repo", "user"):
            error.file = str(Path(root).joinpath(*REPO_PATH) if error.layer == "repo" else config_root / USER_PATH[-1])
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
    data = (json.dumps(document, indent=2) + "\n").encode("utf-8")
    fd = None
    temporary = ".profile-" + uuid.uuid4().hex
    try:
        with _directory(root, REPO_PATH[:-1], create=True) as parent:
            try:
                existing = _read_at(parent, REPO_PATH[-1])
                if not force:
                    raise ProfileError("profile already exists; inspect it or use --force")
                # N/N-1: --force never authorizes misreading a future schema.
                resolve(repo=existing)
            except FileNotFoundError:
                pass
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            try:
                view = memoryview(data)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise ProfileError("profile write failed")
                    view = view[count:]
                os.fsync(fd)
                os.close(fd)
                fd = None
                if force:
                    os.replace(temporary, REPO_PATH[-1], src_dir_fd=parent, dst_dir_fd=parent)
                else:
                    os.link(temporary, REPO_PATH[-1], src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                os.fsync(parent)
            finally:
                if fd is not None:
                    os.close(fd)
                    fd = None
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
    except FileExistsError:
        raise ProfileError("profile already exists; inspect it or use --force", layer="repo", file=str(Path(root).joinpath(*REPO_PATH))) from None
    except ProfileError as error:
        error = _context(error, "repo")
        if error.layer == "repo":
            error.file = str(Path(root).joinpath(*REPO_PATH))
        raise error
    except OSError:
        raise ProfileError("unsafe or unreadable profile path", layer="repo", file=str(Path(root).joinpath(*REPO_PATH))) from None
    return document


def validate_resolved(resolved, root=None):
    """Recheck route policy before consuming an already resolved profile."""
    try:
        _complete(resolved["profile"])
    except ProfileError as error:
        raise _context(error, "repo", str(Path(root).joinpath(*REPO_PATH)) if root is not None else None)


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


def _display_action_parts(parts, shown):
    """Render service template literals and separately validated identities."""
    if type(parts) is not list or not 0 < len(parts) <= 16:
        return None
    pattern = next(iter(JSON_SCHEMA["properties"]["model_settings"]["properties"]["hosts"]["patternProperties"]))
    literals = {part for template in NEXT_ACTION_TEMPLATES.values() for part in template}
    rendered, remaining = [], MAX_STRING
    for part in parts:
        marker = None
        if type(part) is dict and len(part) == 1:
            marker = next(iter(part))
            if marker not in ("identifier", "text"):
                return None
            part = part[marker]
        if type(part) is not str or len(part) > remaining:
            return None
        remaining -= len(part)
        if marker == "identifier":
            if len(part) > 64 or re.fullmatch(pattern, part) is None:
                return None
            rendered.append(shown(part, identifier=True))
        elif marker == "text":
            rendered.append(shown(part))
        else:
            rendered.append(sanitize_display(part, max_len=None) if part in literals else shown(part))
    return sanitize_display("".join(rendered), max_len=512)


def display_profile(value: Any, *, capacity=False) -> Any:
    """Canonicalize/redact/truncate; capacity views opt into typed actions.

    The default retains config-only redaction for the read-only MCP tool.
    """
    from aegis_core.redaction import redact_command_secrets

    def shown(text: str, identifier=False) -> str:
        canonical = sanitize_display(text, max_len=None)
        # Identifiers are schema references, not secret values. Pattern masking
        # would change their meaning; credential positions are masked below.
        redacted = canonical if identifier else redact_command_secrets(canonical)
        return sanitize_display(redacted, max_len=512)

    document = value.get("profile", value) if type(value) is dict else {}
    prefix = ("profile",) if type(value) is dict and "profile" in value else ()
    runners = document.get("run_config", {}).get("runners", {}) if type(document) is dict else {}
    secrets = set()
    for name, runner in runners.items():
        if "credentials" in runner:
            secrets.add((*prefix, "run_config", "runners", name, "credentials"))
    values = value.get("values", {}) if type(value) is dict else {}
    for label, record in values.items():
        components = tuple(record["path"])
        if len(components) == 4 and components[:2] == ("run_config", "runners") and components[-1] == "credentials":
            secrets.add(("values", label, "value"))
        if len(components) == 5 and components[:3] == ("user", "run_config", "runners") and components[-1] == "credentials":
            secrets.add(("values", label, "value"))

    def walk(item, path=(), identifier=False):
        if path in secrets:
            return "[REDACTED]"
        if type(item) is dict:
            result = {}
            action = (_display_action_parts(item["next_action_parts"], shown)
                      if capacity and "next_action" in item and "next_action_parts" in item else None)
            for key, child in item.items():
                reference = key in {"runner", "hosts", "host_pref", "applied_to", "applied_paths", "path"}
                reference = reference or (capacity and key in {"host", "host_kind", "selected_host", "kind", "decision"})
                reference = reference or (key == "next_action_parts" and action is not None)
                reference = reference or (capacity and key == "identifier" and identifier and path[-2:-1] == ("next_action_parts",))
                if key == "name":
                    # Doctor host aliases and review lens names are constrained
                    # identifiers. Gate names are free text and must be redacted,
                    # including the gate array copied into provenance values.
                    reference = (len(path) == 2 and path[0] == "hosts")
                    reference = reference or path[-4:-1] == ("policy", "review", "lenses")
                    reference = reference or (len(path) == 4 and path[0] == "values" and path[2] == "value" and
                                             tuple(values[path[1]]["path"]) == ("policy", "review", "lenses"))
                reference = reference or ((capacity or key in {"review", "doc"}) and path[-1:] == ("fallback",))
                if key == "value" and len(path) == 2 and path[0] == "values":
                    components = tuple(values[path[1]]["path"])
                    reference = components[-1:] in (("hosts",), ("host_pref",)) or components[-2:] in (("fallback", "review"), ("fallback", "doc"))
                    reference = reference or (capacity and components[-2:-1] == ("fallback",))
                result[shown(key, identifier=True)] = walk(child, (*path, key), reference)
            if action is not None:
                result["next_action"] = action
            return result
        if type(item) is list:
            return [walk(child, (*path, index), identifier and
                         (not capacity or path[-1:] != ("next_action_parts",) or type(child) is not str))
                    for index, child in enumerate(item)]
        return shown(item, identifier) if type(item) is str else item

    return walk(value)
