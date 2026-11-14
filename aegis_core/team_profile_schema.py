"""Shared bounded profile traversal, native roots and display/provenance copies.

Both profile resolution and supervisor policy consume this lower validation gate.
This module performs no filesystem I/O and imports neither consumer.
"""
from __future__ import annotations

import math
import os
from pathlib import Path
import re

__all__ = ["SupervisorError", "validate_input"]

_IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_NATIVE_PATH_TYPE = type(Path())


class SupervisorError(ValueError):
    """Documented refusal. The message is a fixed reason or a closed schema path."""

    def __init__(self, reason, *, layer=None, path=None):
        super().__init__(reason)
        self.layer = layer
        self.path = path


_META_PATH = {"type": "array", "items": {"type": "string", "maxLength": 64}, "maxItems": 17}
_META_TEXT = {"type": "string", "maxLength": 4096}
_PROVENANCE_META = {"type": "object", "additionalProperties": False, "required_first": True, "properties": {
    "path": _META_PATH, "layer": _META_TEXT, "frozen_at_run_start": {"type": "boolean"},
    "status": _META_TEXT, "reason": _META_TEXT,
    "applied_to": {"type": "array", "items": _META_TEXT, "maxItems": 64},
    "applied_paths": {"type": "array", "items": _META_PATH, "maxItems": 64},
}}


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
