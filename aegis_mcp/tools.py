"""Tool dispatch: argument check, one handler per tool, opt-in response projection."""
from __future__ import annotations

from typing import Any, Optional

from aegis_mcp.handlers.core import handle_scan
from aegis_mcp.handlers.governance import handle_create_rule, handle_list_rules
from aegis_mcp.handlers.telemetry import handle_capture_insight, handle_report_outcome
from aegis_mcp.projection import project_response
from aegis_mcp.registry import TOOL_ARGUMENTS, TOOL_DEFINITIONS

_TOOL_HANDLERS = {
    "aegis_scan": handle_scan,
    "aegis_report_outcome": handle_report_outcome,
    "aegis_create_rule": handle_create_rule,
    "aegis_list_rules": handle_list_rules,
    "aegis_capture_insight": handle_capture_insight,
}

# Set by the server (or passed by an in-process caller), never part of a tool schema.
SERVER_INJECTED = frozenset({
    "workspace", "_host", "_session", "_client_name", "_client_version", "_binding", "_unbound",
})


_PROPERTIES = {tool["name"]: tool["inputSchema"].get("properties", {}) for tool in TOOL_DEFINITIONS}
# Scalar schema types and the Python values that satisfy them. bool is an int in Python,
# so an integer argument rejects it explicitly.
_SCALAR_TYPES = {
    "string": ((str,), "a string"),
    "integer": ((int,), "an integer"),
    "boolean": ((bool,), "true or false"),
}


def is_known_tool(name: Any) -> bool:
    return isinstance(name, str) and name in _TOOL_HANDLERS


def _shown(value: Any) -> str:
    text = repr(value)
    return text if len(text) <= 60 else text[:57] + "..."


def _invalid_scalar(name: str, args: dict) -> Optional[str]:
    """The first scalar argument whose value breaks the tool's published inputSchema.

    Checked before the handler runs, so a bad value can never fail a call after its
    ledger row is written. A null is the same as an absent argument; list arguments
    are checked by their handlers.
    """
    for key, spec in _PROPERTIES[name].items():
        value = args.get(key)
        if value is None or spec.get("type") not in _SCALAR_TYPES:
            continue
        python_types, expected = _SCALAR_TYPES[spec["type"]]
        if not isinstance(value, python_types) or (spec["type"] == "integer" and isinstance(value, bool)):
            return f"Invalid {key!r}: {_shown(value)}. Expected {expected}."
        if "enum" in spec and value not in spec["enum"]:
            return f"Invalid {key!r}: {_shown(value)}. Expected one of {spec['enum']}."
        if "maxLength" in spec and len(value) > spec["maxLength"]:
            return f"Invalid {key!r}: {len(value)} characters. Expected at most {spec['maxLength']}."
    return None


def execute_tool(name: str, args: dict) -> Any:
    """Check the arguments against the schema, dispatch, and project the response if a view is asked for."""
    unknown = sorted(k for k in args if k not in TOOL_ARGUMENTS[name] and k not in SERVER_INJECTED)
    if unknown:
        return {"status": "FAIL", "error": f"Unknown argument(s) for {name}: {unknown}"}
    invalid = _invalid_scalar(name, args)
    if invalid:
        return {"status": "FAIL", "error": invalid}

    result = _TOOL_HANDLERS[name](args)  # handle_request answers an unknown name before dispatch
    view = args.get("view")
    if view:
        return project_response(result, view=view)
    return result


__all__ = ["execute_tool", "is_known_tool"]
