"""Pure supervisor policy: narrow limits, pauses, backoff and confined state.

No process is started and no host probe runs. Callers pass the clock and the
set of components they already observe. State bytes are read and replaced
through the confined-file boundary.

``resolved_home(home)`` returns one absolute resolved home. A relative path,
an empty string, a NUL, or a non-path raises ``SupervisorError`` with
``user profile root unavailable; configure a home directory`` and is not
resolved against the working directory.

``require_resolved(body)`` checks one fully resolved supervisor object
against the schema bounds. It raises ``SupervisorError`` and does not clamp.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import re
import stat

from aegis_core import storage_confined

__all__ = [
    "COMPONENTS", "PAUSES", "SCHEMA", "STATE_NAME", "SUPERVISOR_SCHEMA", "SupervisorError",
    "assemble", "descriptor_supported", "empty_state", "load_state", "note_failure",
    "note_success", "plan", "report", "require_resolved", "resolved_home", "screen",
    "store_state", "validate_input", "read_owned_leaf",
]

COMPONENTS = ("autopilot", "landing", "writer", "renew", "monitor")
PAUSES = ("owner", "capacity", "disk", "audit", "autopilot", "landing", "writer", "renew", "monitor")
SCHEMA = "aegis.team.supervisor/v1"
STATE_NAME = "supervisor-state.json"
STATE_MAX_BYTES = 131072
_CLOCK_MAX = 10 ** 12
_IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_LINE_BREAKS = re.compile(r"[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]")
_INTERVALS = {"autopilot": 30, "landing": 60, "writer": 60, "renew": 9000, "monitor": 20}
_HEALTH_DEFAULTS = {
    "writer_dead_s": 60, "disk_floor_mib": 4096, "capacity_interval_s": 120,
    "usage_interval_s": 120, "audit_interval_s": 600,
}
_AUDIT_HOLDS = ("autopilot", "landing", "writer", "renew")
_OBSERVATIONS = ("writer_dead", "disk", "capacity", "usage", "audit")
_STATE_REASON = "unsafe or unreadable supervisor state"
_FAILURE_CAP = 100
_ROOT_REASON = "user profile root unavailable; configure a home directory"
_NATIVE_PATH_TYPE = type(Path())
_RESTART_SPANS = {"initial_s": (1, 86400), "max_s": (1, 86400), "limit": (1, 100), "window_s": (1, 86400)}


def _object(properties):
    return {"type": "object", "properties": properties, "additionalProperties": False, "required_first": True}


def _span(low, high):
    return {"type": "integer", "minimum": low, "maximum": high}


_RESTART_SCHEMA = _object({
    "initial_s": _span(1, 86400), "max_s": _span(1, 86400),
    "limit": _span(1, 100), "window_s": _span(1, 86400),
})
_COMPONENT_SCHEMA = _object({
    "enabled": {"type": "boolean"}, "interval_s": _span(1, 86400), "restart": _RESTART_SCHEMA,
})
SUPERVISOR_SCHEMA = _object({
    "pauses": {"type": "array", "items": {"type": "string", "enum": list(PAUSES)}, "maxItems": len(PAUSES)},
    "components": _object({name: _COMPONENT_SCHEMA for name in COMPONENTS}),
    "health": _object({
        "writer_dead_s": _span(60, 86400), "disk_floor_mib": _span(4096, 1048576),
        "capacity_interval_s": _span(1, 86400), "usage_interval_s": _span(1, 86400),
        "audit_interval_s": _span(1, 86400),
    }),
})


class SupervisorError(ValueError):
    """Documented refusal. The message is a fixed reason or a closed schema path."""

    def __init__(self, reason, *, layer=None, path=None):
        super().__init__(reason)
        self.layer = layer
        self.path = path


_META_PATH = {"type": "array", "items": {"type": "string", "maxLength": 64}, "maxItems": 17}
_META_TEXT = {"type": "string", "maxLength": 4096}
_PROVENANCE_META = _object({
    "path": _META_PATH, "layer": _META_TEXT, "frozen_at_run_start": {"type": "boolean"},
    "status": _META_TEXT, "reason": _META_TEXT,
    "applied_to": {"type": "array", "items": _META_TEXT, "maxItems": 64},
    "applied_paths": {"type": "array", "items": _META_PATH, "maxItems": 64},
})


def _field_schema(schema, path):
    for part in path:
        child = schema.get("properties", {}).get(part)
        if child is None:
            patterns = schema.get("patternProperties", {})
            child = next((patterns[key] for key in sorted(patterns) if re.fullmatch(key, part)), None)
        if child is None:
            return None
        schema = child
    return schema


def _provenance_input(records, schema, layer):
    """Check bounded metadata and each copied value under its actual field schema."""
    def invalid():
        raise SupervisorError("invalid value: profile provenance", layer=layer, path="values")

    if type(records) is not dict or len(records) > 4096:
        invalid()
    if any(type(key) is not str or len(key) > 4096 for key in records):
        invalid()
    seen = set()
    for key in sorted(records):
        record = records[key]
        if type(record) is not dict or len(record) > 8 or "value" not in record or "path" not in record:
            invalid()
        if any(name != "value" and name not in _PROVENANCE_META["properties"] for name in record):
            invalid()
        meta = {name: value for name, value in record.items() if name != "value"}
        validate_input(meta, _PROVENANCE_META, "values", layer)
        path = meta["path"]
        if not path or tuple(path) in seen:
            invalid()
        seen.add(tuple(path))
        user = path[0] == "user"
        source_path = path[1:] if user else path
        if not source_path:
            invalid()
        field = _field_schema(schema["user_schema"] if user else schema["schema"], source_path)
        if field is None:
            invalid()
        # A copied leaf belongs to one bounded input document. Its metadata and
        # other copies do not consume that document's validation budget.
        validate_input(record["value"], field, ".".join(source_path), layer, resolved=True)


def _root_input(value, schema, path, layer):
    """Convert only exact strings/native paths; custom conversion hooks are not input."""
    reason = schema["refusal"]
    if type(value) not in (str, _NATIVE_PATH_TYPE):
        raise SupervisorError(reason, layer=layer, path=path)
    spelling = str(value) if type(value) is _NATIVE_PATH_TYPE else value
    if not 1 <= len(spelling) <= schema.get("maxLength", 32768) or "\x00" in spelling:
        raise SupervisorError(reason, layer=layer, path=path)
    try:
        os.fsencode(spelling)
        candidate = Path(spelling)
        if not candidate.is_absolute() or ".." in candidate.parts:
            raise SupervisorError(reason, layer=layer, path=path)
    except (OSError, RuntimeError, ValueError):
        raise SupervisorError(reason, layer=layer, path=path) from None
    return candidate


def _display_input(value, profile_keys):
    """Copy bounded native JSON and identify its optional strict profile projection."""
    budget = [1048576, 67108864]
    def refuse():
        raise SupervisorError("invalid value: profile display", path="display")
    def copy(item, depth=0):
        budget[0] -= 1
        if depth > 16 or budget[0] < 0: refuse()
        kind = type(item)
        if kind is dict:
            if len(item) > 4096 or 2 * len(item) > budget[0] or any(type(key) is not str for key in item): refuse()
            return {copy(key, depth + 1): copy(child, depth + 1) for key, child in item.items()}
        if kind is list:
            if len(item) > 4096 or len(item) > budget[0]: refuse()
            return [copy(child, depth + 1) for child in item]
        if kind is str:
            budget[1] -= len(item)
            if len(item) > 131072 or budget[1] < 0: refuse()
        elif kind is float:
            if not math.isfinite(item): refuse()
        elif kind is int:
            if item.bit_length() > 4096: refuse()
        elif kind is not bool and item is not None: refuse()
        return item
    shown = copy(value)
    data = shown if type(shown) is dict else {}
    schema = data.get("schema")
    if schema == "aegis.team.config.init/v1" and data.get("status") != "refused":
        if "values" in data or "write_scope" in data: refuse()
        snapshot = {"profile": data.get("profile"), "values": {}, "write_scope": []}
    elif schema == "aegis.team.config.show/v1" and data.get("status") != "refused":
        snapshot = {key: data[key] for key in ("profile", "values", "write_scope", "repository_profile_exists") if key in data}
    elif "profile" in data or "values" in data:
        snapshot = data
    elif any(key in data for key in profile_keys):
        snapshot = {"profile": data, "values": {}, "write_scope": []}
    else:
        snapshot = None
    return shown, snapshot


def validate_input(value, schema, path="", layer="repo", *, required=None, resolved=False):
    """The shared closed-schema gate for profile fragments, resolved values and roots.

    Required leaves use a trusted template; partial inputs omit it. Limits precede walks and allocation.
    Roots return a native Path; display returns a native copy. validation_order sets field priorities;
    remaining fields use identifier order, and error_path marks an embedded schema root.
    """
    from aegis_core.team_profile_display import reject_terminal_hosts
    budget = [4096]

    def refuse(reason, at):
        raise SupervisorError(reason, layer=layer, path=at)

    def check(item, spec, at, template, depth, remaining):
        if "error_path" in spec:
            remaining, depth = [spec.get("node_budget", 4096)], 0
        at = spec.get("error_path", at)
        remaining[0] -= 1
        if depth > 16 or remaining[0] < 0:
            refuse("profile nesting or node limit exceeded", at)
        if spec["type"] == "root":
            return _root_input(item, spec, at, layer)
        if spec["type"] == "provenance":
            return _provenance_input(item, spec, layer)
        if spec["type"] == "display":
            return _display_input(item, spec["profile_keys"])
        if at == "supervisor" and layer == "flags":
            refuse("supervisor settings are owner-file only", at)
        if "invalid_refusal" in spec and (type(item) is not int or item not in spec["enum"]):
            refuse(spec["invalid_refusal"], at)
        types = spec["type"]
        types = [types] if type(types) is str else types
        actual = {dict: "object", list: "array", str: "string", bool: "boolean", int: "integer",
                  float: "number", type(None): "null"}.get(type(item))
        if actual not in types and not (actual == "integer" and "number" in types):
            refuse("wrong type: " + (at or "profile"), at)
        if spec.get("user_layer_only") and layer != "user" and not resolved:
            refuse("user-only key: " + at, at)
        if actual == "string" and len(item) > spec.get("maxLength", 4096):
            refuse("profile string size limit exceeded", at)
        if "enum" in spec and item not in spec["enum"]:
            reason = "unregistered host kind" if at.endswith(".kind") else "invalid value"
            refuse(reason + ": " + at, at)
        if actual == "string" and "pattern" in spec and re.fullmatch(spec["pattern"], item) is None:
            refuse("invalid identifier: " + at, at)
        if type(item) in (int, float):
            if not spec.get("minimum", 0) <= item <= spec.get("maximum", 1000000):
                refuse("value out of range: " + at, at)
        if actual == "object":
            if len(item) > spec.get("maxProperties", 64):
                refuse("profile object size limit exceeded", at)
            if any(type(key) is not str for key in item):
                refuse("profile keys must be strings", at)
            if any(len(key) > 4096 for key in item):
                refuse("profile string size limit exceeded", at)
            priority = {key: index for index, key in enumerate(spec.get("validation_order", ()))}
            expected = template if type(template) is dict else {}
            keys = sorted(item.keys() | expected.keys(), key=lambda key: (priority.get(key, len(priority)), key))
            reject_terminal_hosts(keys, SupervisorError, at)
            if spec.get("required_first") and expected.keys() - item.keys():
                refuse("invalid value: " + (at or "profile"), at)
            if at == "supervisor" and _pause_clear(item):
                refuse("supervisor pause cannot be cleared by the repository layer", at)
            for key in keys:
                if key not in item:
                    refuse("invalid value: " + (at or key), at or key)
                child = item[key]
                child_spec = spec.get("properties", {}).get(key)
                if child_spec is None and spec.get("additionalProperties") is True:
                    child_spec = {"type": ["object", "array", "string", "boolean", "integer", "number", "null"],
                                  "additionalProperties": True, "maxItems": 64}
                    child_spec["items"] = child_spec
                if child_spec is None:
                    patterns = spec.get("patternProperties", {})
                    child_spec = next((patterns[pattern] for pattern in sorted(patterns)
                                       if re.fullmatch(pattern, key)), None)
                if child_spec is None:
                    # Only identifier-shaped unknown keys can extend a refusal path.
                    safe = _IDENT.fullmatch(key) is not None
                    child_at = (at + "." + key if at else key) if safe else (at or "profile")
                    refuse("unknown key: " + child_at, child_at)
                child_at = at + "." + key if at else key
                child_template = template.get(key) if type(template) is dict else None
                check(child, child_spec, child_at, child_template, depth + 1, remaining)
        elif actual == "array":
            if len(item) > spec["maxItems"]:
                refuse("profile array size limit exceeded: " + at, at)
            for index, child in enumerate(item):
                check(child, spec["items"], at + "." + str(index), None, depth + 1, remaining)
            if at == "supervisor.pauses" and len(set(item)) != len(item):
                refuse("invalid value: supervisor.pauses", at)
        if "after" in spec:
            spec["after"](item)

    try:
        return check(value, schema, path, required, 0, budget)
    except SupervisorError as error:
        if error.layer is None:
            error.layer = layer
        raise


def descriptor_supported():
    return storage_confined.descriptor_supported()


def _state_error():
    raise SupervisorError(_STATE_REASON, layer="state")


def _pause_clear(fragment):
    if any(name in fragment for name in ("clear", "unpause")) or fragment.get("paused") is False:
        return True
    if "pauses" in fragment:
        pauses = fragment["pauses"]
        if type(pauses) is dict or pauses is None or type(pauses) is bool:
            return True
        if type(pauses) is list and any(type(item) is bool for item in pauses):
            return True
    components = fragment.get("components")
    if type(components) is not dict:
        return False
    for spec in components.values():
        if type(spec) is not dict:
            continue
        if "clear" in spec or "unpause" in spec or spec.get("paused") is False:
            return True
        restart = spec.get("restart")
        if type(restart) is dict and ("clear" in restart or "unpause" in restart or restart.get("paused") is False):
            return True
    return False


def screen(fragment, layer):
    """Validate a standalone fragment through the shared ranked schema traversal."""
    validate_input(fragment, SUPERVISOR_SCHEMA, "supervisor", layer)


def _component(name):
    return {
        "enabled": False, "interval_s": _INTERVALS[name],
        "restart": {"initial_s": 30, "max_s": 300, "limit": 3, "window_s": 300},
    }


def _defaults():
    return {
        "pauses": [],
        "components": {name: _component(name) for name in COMPONENTS},
        "health": dict(_HEALTH_DEFAULTS),
    }


def _remember(origins, value, prefix):
    for key, child in value.items():
        path = prefix + (key,)
        if type(child) is dict and child:
            _remember(origins, child, path)
        else:
            origins[path] = "defaults"


def _apply(target, fragment, origins, layer):
    health = fragment.get("health")
    if type(health) is dict:
        for key, value in health.items():
            target["health"][key] = value
            origins[("supervisor", "health", key)] = layer
    components = fragment.get("components")
    if type(components) is not dict:
        return
    for name, spec in components.items():
        if type(spec) is not dict or name not in target["components"]:
            continue
        dest = target["components"][name]
        if "enabled" in spec:
            dest["enabled"] = spec["enabled"]
            origins[("supervisor", "components", name, "enabled")] = layer
        if "interval_s" in spec:
            dest["interval_s"] = spec["interval_s"]
            origins[("supervisor", "components", name, "interval_s")] = layer
        restart = spec.get("restart")
        if type(restart) is not dict:
            continue
        for key, value in restart.items():
            dest["restart"][key] = value
            origins[("supervisor", "components", name, "restart", key)] = layer


def _widens(ceiling, repo):
    health = repo.get("health")
    if type(health) is dict:
        for key, value in health.items():
            if type(value) is int and key in ceiling["health"] and value < ceiling["health"][key]:
                return True
    components = repo.get("components")
    if type(components) is not dict:
        return False
    for name, spec in components.items():
        if type(spec) is not dict or name not in ceiling["components"]:
            continue
        current = ceiling["components"][name]
        if spec.get("enabled") is True and current["enabled"] is False:
            return True
        interval = spec.get("interval_s")
        if type(interval) is int and interval < current["interval_s"]:
            return True
        restart = spec.get("restart")
        if type(restart) is not dict:
            continue
        limit = restart.get("limit")
        if type(limit) is int and limit > current["restart"]["limit"]:
            return True
        for key in ("initial_s", "max_s", "window_s"):
            value = restart.get(key)
            if type(value) is int and value < current["restart"][key]:
                return True
    return False


def _conflict(body):
    for name in COMPONENTS:
        spec = body["components"][name]
        restart = spec["restart"]
        if restart["initial_s"] > restart["max_s"]:
            return "supervisor.components." + name + ".restart.initial_s"
    return None


def _span_ok(value, bounds):
    low, high = bounds
    return type(value) is int and low <= value <= high


def _union(user, repo):
    names = list(user.get("pauses", []))
    contributed = False
    for name in repo.get("pauses", []):
        if name not in names:
            names.append(name)
            contributed = True
    names.sort(key=PAUSES.index)
    if contributed:
        return names, "repo"
    if "pauses" in user:
        return names, "user"
    return names, None


def assemble(user, repo):
    """Overlay owner settings, then refuse a repository value that widens them."""
    screen(user, "user")
    screen(repo, "repo")
    result = _defaults()
    origins = {}
    _remember(origins, result, ("supervisor",))
    _apply(result, user, origins, "user")
    conflict = _conflict(result)
    if conflict is not None:
        raise SupervisorError("value out of range: " + conflict, layer="user", path=conflict)
    if _widens(result, repo):
        raise SupervisorError("supervisor limit cannot be widened by the repository layer", layer="repo")
    _apply(result, repo, origins, "repo")
    conflict = _conflict(result)
    if conflict is not None:
        raise SupervisorError("value out of range: " + conflict, layer="repo", path=conflict)
    pauses, layer = _union(user, repo)
    result["pauses"] = pauses
    if layer is not None:
        origins[("supervisor", "pauses")] = layer
    return result, origins


def _delay(initial, maximum, count):
    delay = initial
    for _step in range(max(0, count - 1)):
        delay = min(delay * 2, maximum)
    return delay


def _in_window(failures, now, window):
    return [item for item in failures if type(item) is int and item <= now and now - item < window]


def _policy_fields(policy):
    names = ("initial_s", "max_s", "limit", "window_s")
    if type(policy) is not dict or set(policy) != set(names):
        raise SupervisorError("invalid value: restart", layer="state")
    if any(not _span_ok(policy[name], _RESTART_SPANS[name]) for name in names):
        raise SupervisorError("invalid value: restart", layer="state")
    initial, maximum, limit, window = (policy[name] for name in names)
    if initial > maximum:
        raise SupervisorError("invalid value: restart", layer="state")
    return initial, maximum, limit, window


def _event_deadlines(failures, restart):
    """Backoff deadlines and their event indices, derived solely from evidence."""
    return [(event + _delay(restart["initial_s"], restart["max_s"],
                            len(_in_window(failures, event, restart["window_s"]))), index)
            for index, event in enumerate(failures)]


def _retain(failures, now, policy):
    """Keep recent counts, future events and a sufficient outstanding-deadline witness."""
    # The normalized input contains at most 100 events; scratch has at most 101.
    candidates = [*failures, now]
    ordered = sorted(range(len(candidates)), key=lambda index: (candidates[index], index))
    window = policy["window_s"]
    recent = [index for index in ordered if 0 <= now - candidates[index] < window]
    keep = set(recent[-_FAILURE_CAP:])
    keep.update(index for index in ordered if candidates[index] > now)
    # The newest visible event dominates every older interval-only deadline,
    # even though this API receives restart policy without the component interval.
    keep.add(len(candidates) - 1)
    deadline, event_index = max(_event_deadlines(candidates, policy))
    if deadline > now:
        event = candidates[event_index]
        support = [index for index in ordered if 0 <= event - candidates[index] < window]
        needed, delay = 1, policy["initial_s"]
        while delay < deadline - event:
            delay = min(delay * 2, policy["max_s"])
            needed += 1
        # Once doubling saturates, extra predecessors add no deadline evidence.
        keep.update(support[-needed:])
    if len(keep) > _FAILURE_CAP:
        raise SupervisorError("supervisor failure history limit exceeded", layer="state")
    return [event for index, event in enumerate(candidates) if index in keep]


def note_failure(state, component, now, policy):
    """Return a new state with one failure appended. The input is unchanged.

    Keep the evidence for a pending deadline beyond window expiry. The bounded
    history preserves recent counts and refuses if required evidence cannot fit.
    """
    if type(now) is not int or not 0 <= now <= _CLOCK_MAX:
        raise SupervisorError("invalid value: now", layer="state")
    initial, maximum, _limit, window = _policy_fields(policy)
    if component not in COMPONENTS:
        raise SupervisorError("invalid value: components", layer="state")
    fresh = _normalize(state)
    slot = fresh["components"][component]
    slot["failures"] = _retain(slot["failures"], now, policy)
    visible = _in_window(slot["failures"], now, window)
    slot["delay_s"] = _delay(initial, maximum, len(visible))
    return fresh


def note_success(state, component, policy):
    """Return a new state whose delay is the policy initial and whose failures are empty."""
    initial, _maximum, _limit, _window = _policy_fields(policy)
    if component not in COMPONENTS:
        raise SupervisorError("invalid value: components", layer="state")
    fresh = _normalize(state)
    slot = fresh["components"][component]
    slot["failures"] = []
    slot["delay_s"] = initial
    return fresh


def _clock(now):
    if type(now) is not int or not 0 <= now <= _CLOCK_MAX:
        return None
    return now


def _running(running):
    if type(running) not in (list, tuple):
        return None
    seen = []
    for item in running:
        if type(item) is not str or item not in COMPONENTS or item in seen:
            return None
        seen.append(item)
    return seen


def _refused(reason, layer):
    return {"status": "refused", "reason": reason, "layer": layer, "starts_nothing": True, "start": []}


def _holding(name, pauses):
    table = {
        "owner": COMPONENTS, "capacity": COMPONENTS, "disk": COMPONENTS, "audit": _AUDIT_HOLDS,
        "autopilot": ("autopilot",), "landing": ("landing",), "writer": ("writer",),
        "renew": ("renew",), "monitor": ("monitor",),
    }
    return [pause for pause in PAUSES if pause in pauses and name in table[pause]]


def require_resolved(body):
    """Refuse a resolved supervisor object the schema bounds would reject."""
    validate_input(body, SUPERVISOR_SCHEMA, "supervisor", "repo", required=_defaults())
    conflict = _conflict(body)
    if conflict is not None:
        raise SupervisorError("value out of range: " + conflict, layer="repo", path=conflict)


def _next_eligible(spec, slot):
    """Keep recorded-event deadlines holding even when the observing clock rolls back."""
    failures = slot["failures"]
    if not failures:
        return None
    backoff = max(deadline for deadline, _index in _event_deadlines(failures, spec["restart"]))
    return max(backoff, max(failures) + spec["interval_s"])


def _component_row(name, body, state, running, now):
    spec = body["components"][name]
    restart = spec["restart"]
    slot = state["components"][name]
    counted = _in_window(slot["failures"], now, restart["window_s"])
    count = len(counted)
    delay = _delay(restart["initial_s"], restart["max_s"], count)
    exhausted = count >= restart["limit"]
    nxt = _next_eligible(spec, slot)
    holding = _holding(name, body["pauses"])
    if spec["enabled"] is not True:
        action = "disabled"
    elif holding:
        action = "paused"
    elif exhausted:
        action = "restart_exhausted"
    elif name in running:
        action = "already_running"
    elif nxt is not None and now < nxt:
        action = "waiting_backoff"
    else:
        action = "would_start"
    return {
        "id": name, "action": action, "pauses": holding, "enabled": spec["enabled"] is True,
        "interval_s": spec["interval_s"], "next_eligible_at": nxt,
        "restart": {"limit": restart["limit"], "delay_s": delay, "failures": count, "exhausted": exhausted},
    }


def plan(resolved, state, running, now):
    """Dry-run the start set. A refusal has no component array and writes nothing."""
    clock = _clock(now)
    if clock is None:
        return _refused("invalid value: now", "state")
    names = _running(running)
    if names is None:
        return _refused("invalid value: running", "state")
    try:
        checked = _normalize(state)
    except SupervisorError:
        return _refused(_STATE_REASON, "state")
    body = resolved.get("supervisor") if type(resolved) is dict else None
    try:
        require_resolved(body)
    except SupervisorError:
        return _refused("invalid value: supervisor", "repo")
    components = [_component_row(name, body, checked, names, clock) for name in COMPONENTS]
    start = [row["id"] for row in components if row["action"] == "would_start"]
    return {"status": "dry_run", "starts_nothing": not start, "start": start, "components": components}


def empty_state():
    components = {name: {"delay_s": 30, "failures": []} for name in COMPONENTS}
    return {"version": 1, "components": components}


def _pairs(items):
    result = {}
    for key, value in items:
        if type(key) is not str or key in result:
            _state_error()
        result[key] = value
    return result


def _bad_number(_value):
    _state_error()


def _measure(text, ceiling):
    """Count JSON nodes. Structural caps are applied before a tree is built."""
    depth, nodes, chars, unicode_left = 0, 0, 0, 0
    quoted, escaped, atom = False, False, False
    containers = []
    for char in text:
        if not quoted and containers and containers[-1][1] and char not in " \t\r\n]}":
            containers[-1][0] += 1
            containers[-1][1] = False
            if containers[-1][0] > _FAILURE_CAP:
                _state_error()
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
            if chars > 64:
                _state_error()
        elif char == '"':
            quoted = True
            chars, atom = 0, False
            nodes += 1
        elif char in "[{":
            nodes += 1
            atom = False
            depth += 1
            if depth > 8:
                _state_error()
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
        if ceiling is not None and nodes > ceiling:
            _state_error()
    return nodes


def _maximum_state_text():
    components = {name: {"delay_s": 1, "failures": list(range(_FAILURE_CAP))} for name in COMPONENTS}
    return json.dumps({"version": 1, "components": components}, sort_keys=True, separators=(",", ":"))


# The reader and the writer share this count: it is the scanner's own tally of the largest document _normalize accepts.
_STATE_MAX_NODES = _measure(_maximum_state_text(), None)


def _scan(text):
    """Reject oversized state text before json.loads allocates a tree."""
    _measure(text, _STATE_MAX_NODES)


def _normalize(value):
    if type(value) is not dict or set(value) - {"version", "components"}:
        _state_error()
    version = value.get("version")
    if type(version) is not int or version != 1:
        _state_error()
    raw = value.get("components", {})
    if type(raw) is not dict or set(raw) - set(COMPONENTS):
        _state_error()
    components = {}
    for name in COMPONENTS:
        if name not in raw:
            components[name] = {"delay_s": 30, "failures": []}
            continue
        spec = raw[name]
        if type(spec) is not dict or set(spec) != {"delay_s", "failures"}:
            _state_error()
        delay, failures = spec["delay_s"], spec["failures"]
        if type(delay) is not int or not 1 <= delay <= 86400 or type(failures) is not list or len(failures) > _FAILURE_CAP:
            _state_error()
        checked = []
        for item in failures:
            if type(item) is not int or not 0 <= item <= _CLOCK_MAX:
                _state_error()
            checked.append(item)
        components[name] = {"delay_s": delay, "failures": checked}
    return {"version": 1, "components": components}


def _parse_state(data):
    if type(data) is not bytes or len(data) > STATE_MAX_BYTES:
        _state_error()
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        raise SupervisorError(_STATE_REASON, layer="state") from None
    _scan(text)
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_bad_number)
    except SupervisorError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise SupervisorError(_STATE_REASON, layer="state") from None
    return _normalize(value)


def _reject_root():
    raise SupervisorError(_ROOT_REASON, layer="user")


def resolved_home(home):
    """Accept only a bounded absolute home, before resolving or opening any path."""
    schema = {"type": "root", "maxLength": 32768 - len("/.config/aegis"), "refusal": _ROOT_REASON}
    candidate = validate_input(home, schema, "root", "user")
    try:
        candidate = candidate.resolve()
    except (OSError, RuntimeError, ValueError):
        _reject_root()
    return validate_input(candidate, schema, "root", "user")


def _config_root(user_root):
    if user_root is None:
        from aegis_core.workspace.layout import UserLayout
        layout = UserLayout.current()
        if layout is None:
            _reject_root()
        home = layout.home
    else:
        home = user_root
    try:
        root = resolved_home(home).joinpath(".config", "aegis").resolve()
        validate_input(root, {"type": "root", "refusal": _ROOT_REASON}, "root", "user")
        return root
    except SupervisorError:
        raise
    except (OSError, RuntimeError, ValueError):
        _reject_root()


def _owned(info):
    return info.st_uid == os.getuid() and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def _open_leaf(parent, name, max_bytes=STATE_MAX_BYTES, owner_reason=None):
    """Open one leaf on the held parent descriptor and require an owner-only regular file."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
    except FileNotFoundError:
        return None
    except OSError:
        raise SupervisorError(_STATE_REASON, layer="state") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SupervisorError(_STATE_REASON, layer="state")
        if not _owned(info):
            raise SupervisorError(
                owner_reason or "supervisor state must be owned by the current user and not group/other-writable",
                layer="user")
        if info.st_size > max_bytes:
            raise storage_confined.ConfinedFileError("too_large")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_owned_leaf(parent, name, max_bytes=STATE_MAX_BYTES, owner_reason=None):
    """Read and inspect the same leaf descriptor below an already held parent."""
    fd = _open_leaf(parent, name, max_bytes, owner_reason)
    if fd is None:
        return None
    try:
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(fd, min(8192, max_bytes + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
        raise storage_confined.ConfinedFileError("too_large")
    finally:
        os.close(fd)


def _refuse_foreign_leaf(parent, name):
    fd = _open_leaf(parent, name)
    if fd is not None:
        os.close(fd)


def load_state(user_root=None):
    """Read the owner state file. A missing file or directory is empty state."""
    root = _config_root(user_root)
    if not descriptor_supported():
        raise SupervisorError("unsupported platform: anchored profile operations unavailable", layer="state")
    try:
        with storage_confined.confined_file(root, (STATE_NAME,)) as handle:
            if not _owned(handle.parent_stat()):
                raise SupervisorError(
                    "user profile directory must be owned by the current user and not group/other-writable",
                    layer="user")
            # Held parent descriptor: a path reopen would race a leaf swap.
            data = read_owned_leaf(handle._parent, STATE_NAME)
            if data is None:
                return empty_state()
            return _parse_state(data)
    except storage_confined.ConfinedFileError as error:
        if error.reason == "missing":
            return empty_state()
        raise SupervisorError(_STATE_REASON, layer="state") from None
    except OSError:
        raise SupervisorError(_STATE_REASON, layer="state") from None


def store_state(state, user_root=None):
    """Validate, then replace the state leaf. A missing directory is not created."""
    data = (json.dumps(_normalize(state), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > STATE_MAX_BYTES:
        _state_error()
    _scan(data.decode("utf-8"))
    root = _config_root(user_root)
    if not descriptor_supported():
        raise SupervisorError("unsupported platform: anchored profile operations unavailable", layer="state")
    try:
        with storage_confined.confined_file(root, (STATE_NAME,)) as handle:
            if not _owned(handle.parent_stat()):
                raise SupervisorError(
                    "user profile directory must be owned by the current user and not group/other-writable",
                    layer="user")
            _refuse_foreign_leaf(handle._parent, STATE_NAME)
            handle.publish_bytes(data, replace=True, mode=0o600)
    except (storage_confined.ConfinedFileError, OSError):
        raise SupervisorError(_STATE_REASON, layer="state") from None


def _single_line(text):
    return type(text) is str and _LINE_BREAKS.search(text) is None


def _public_text(text):
    if not _single_line(text):
        return "invalid value: supervisor"
    from aegis_core.primitives import sanitize_display
    from aegis_core.redaction import redact_command_secrets
    canonical = sanitize_display(text, max_len=None)
    return sanitize_display(redact_command_secrets(canonical), max_len=512)


def _health_row(row):
    return {
        "id": row["id"], "enabled": row["enabled"], "interval_s": row["interval_s"],
        "pauses": list(row["pauses"]), "delay_s": row["restart"]["delay_s"],
        "failures": row["restart"]["failures"], "exhausted": row["restart"]["exhausted"],
        "next_eligible_at": row["next_eligible_at"],
    }


def _health_refused(reason, layer, path, exists):
    shown = path if _single_line(path) else None
    layer = layer if type(layer) is str and layer in ("repo", "user", "flags", "state") else None
    return {
        "schema": SCHEMA, "profile": "refused", "reason": _public_text(reason), "layer": layer,
        "path": None if shown is None else _public_text(shown),
        "repository_profile_exists": bool(exists), "pauses": [], "starts_nothing": True, "start": [],
    }


def _exception_types(profile_error):
    if type(profile_error) is type and issubclass(profile_error, Exception):
        return (profile_error,)
    if type(profile_error) is not tuple or not profile_error:
        return ()
    if all(type(item) is type and issubclass(item, Exception) for item in profile_error):
        return profile_error
    return ()


def report(load, root, now, user_root=None, profile_error=()):
    """Project health from one profile load and one state snapshot. Nothing is started.

    The caller passes the profile refusal type. This module does not import the
    profile module, so the two stay acyclic.
    """
    try:
        loaded = load(root, user_root=user_root)
    except _exception_types(profile_error) as error:
        return _health_refused(
            str(error), getattr(error, "layer", None), getattr(error, "path", None), False)
    except OSError:
        return _health_refused("unsafe or unreadable profile path", "repo", None, False)
    exists = bool(loaded.get("repository_profile_exists")) if type(loaded) is dict else False
    try:
        state = load_state(user_root=user_root)
    except SupervisorError as error:
        return _health_refused(str(error), error.layer or "state", error.path, exists)
    except OSError:
        return _health_refused(_STATE_REASON, "state", None, exists)
    body = loaded.get("profile") if type(loaded) is dict else None
    planned = plan(body if type(body) is dict else {}, state, [], now)
    if planned["status"] != "dry_run":
        return _health_refused(planned["reason"], planned["layer"], None, exists)
    return {
        "schema": SCHEMA, "profile": "valid", "reason": None, "layer": None, "path": None,
        "repository_profile_exists": exists, "pauses": list(body["supervisor"]["pauses"]),
        "starts_nothing": True, "start": [],
        "components": [_health_row(row) for row in planned["components"]],
        "observations": {name: "not_run" for name in _OBSERVATIONS},
    }
