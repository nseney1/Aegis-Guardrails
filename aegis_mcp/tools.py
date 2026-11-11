"""Tool dispatch: argument check, one handler per tool, opt-in response projection."""
from __future__ import annotations

from typing import Any, Optional

from aegis_mcp.handlers.core import handle_scan
from aegis_mcp.handlers.governance import handle_create_rule, handle_list_rules
from aegis_mcp.handlers.telemetry import handle_capture_insight, handle_report_outcome
from aegis_mcp.handlers.msg import handle_msg_read, handle_msg_write
from aegis_mcp.projection import project_response
from aegis_mcp.registry import TOOL_ARGUMENTS, TOOL_DEFINITIONS


def _team_config_payload() -> dict:
    from aegis_core import primitives, team_profile

    payload = primitives.envelope("aegis team config show", {})
    payload.update(schema="aegis.team.config.show/v1", schema_family="aegis.team.config/v1",
                   governance=team_profile.governance_status())
    return payload


def _team_config_argument_refusal() -> dict:
    """The closed-input refusal, shared by raw-client and direct dispatch checks."""
    from aegis_core.team_profile import display_profile

    payload = _team_config_payload()
    payload.update(status="refused", reason="aegis_team_config accepts no arguments",
                   layer="flags", file="<command-line>",
                   next_action="Call aegis_team_config with an empty arguments object.")
    return display_profile(payload)


def _handle_team_config(args: dict) -> dict:
    """Read the CLI's resolved snapshot without exposing an initialization path."""
    from pathlib import Path

    from aegis_core import team_profile
    from aegis_core.config import env_workspace
    from aegis_core.team_profile import display_profile
    from aegis_core.workspace.base import Workspace
    from aegis_core.workspace.binding import resolve_cli_root

    if not isinstance(args, dict) or any(key not in SERVER_INJECTED for key in args):
        return _team_config_argument_refusal()
    payload = _team_config_payload()
    try:
        raw = args.get("workspace")
        if isinstance(raw, Workspace):
            root = raw.root
        elif isinstance(raw, (str, Path)):
            root = resolve_cli_root(explicit=raw, pin=env_workspace())
        elif raw is None:
            root = resolve_cli_root(pin=env_workspace())
        else:
            raise ValueError("workspace unavailable")
    except (OSError, ValueError, RuntimeError):
        payload.update(status="refused", reason="profile operation unavailable", layer="filesystem",
                       file="<workspace>",
                       next_action="Check the trusted workspace and home directories and retry on a platform with anchored file operations.")
        return display_profile(payload)
    payload["scope"] = {"workspace": str(root)}
    try:
        payload.update(status="done", **team_profile.load(root),
                       next_action="Run aegis team doctor --json before starting a run.")
    except team_profile.ProfileError as exc:
        payload.update(status="refused", reason=str(exc), layer=exc.layer, file=exc.file,
                       next_action="Correct the indicated file or command-line layer, then retry. Run aegis team config presets --json for preset and host choices; repository policy changes need aegis approve before merge.")
    except (OSError, ValueError, RuntimeError):
        payload.update(status="refused", reason="profile operation unavailable", layer="filesystem",
                       file=str(root.joinpath(*team_profile.REPO_PATH)),
                       next_action="Check the trusted workspace and home directories and retry on a platform with anchored file operations.")
    return display_profile(payload)


_TOOL_HANDLERS = {
    "aegis_scan": handle_scan,
    "aegis_report_outcome": handle_report_outcome,
    "aegis_create_rule": handle_create_rule,
    "aegis_list_rules": handle_list_rules,
    "aegis_capture_insight": handle_capture_insight,
    "aegis_msg_read": handle_msg_read,
    "aegis_msg_write": handle_msg_write,
    "aegis_team_config": _handle_team_config,
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


def execute_tool(name: str, args: dict, *, client_arguments: bool = False) -> Any:
    """Check the arguments against the schema, dispatch, and project the response if a view is asked for."""
    if name == "aegis_team_config":
        # This closed read surface owns non-echoing, CLI-shaped argument refusals.
        if client_arguments and (not isinstance(args, dict) or args):
            return _team_config_argument_refusal()
        return _handle_team_config(args)
    if name in ("aegis_msg_read", "aegis_msg_write"):
        # The codec owns fixed, non-echoing errors and bounds for this surface.
        from aegis_core.message_codec import CodecError

        if any(k not in TOOL_ARGUMENTS[name] and k not in SERVER_INJECTED for k in args):
            return CodecError("E_FORMAT").as_dict()
        return _TOOL_HANDLERS[name](args)
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
