"""Tool dispatch: argument check, one handler per tool, opt-in response projection."""
from __future__ import annotations

from typing import Any, Optional
from pathlib import Path

from aegis_core.primitives import sanitize_display

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


MODEL_REQUIRED = ("bindings", "policy", "history", "task_kind", "role_kind", "subject", "host_kinds")
MODEL_OPTIONAL = ("intent", "author_family", "lane_family", "review_stage", "record")


def queue_argument_refusal(arguments):
    from aegis_core import team_queue

    result = team_queue.list_argument_refusal(arguments)
    if result is not None:
        result["error"] = result["reason"]
    return result


def _handle_team_queue(args):
    """Read-only adapter: no client argument can select a queue mutation."""
    from aegis_core import team_queue
    from aegis_core.workspace.base import Workspace

    if (type(args) is not dict or len(args) > len(SERVER_INJECTED) + 2 or
            any(key not in ("capabilities", "include_done") and key not in SERVER_INJECTED for key in args)):
        return queue_argument_refusal(None)
    else:
        options = {key: args[key] for key in ("capabilities", "include_done") if key in args}
        invalid = queue_argument_refusal(options)
        if invalid is not None:
            return invalid
        root = args.get("workspace")
        root = root.root if isinstance(root, Workspace) else root
        result = team_queue.list(root, **options)
    if result["refused"]:
        # The generic MCP transport recognizes error; retain the core envelope
        # and add only this fixed reason for its isError flag.
        result["error"] = result["reason"]
    return result


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
    """MCP adapter over the public selector; parity is pinned through both transports."""
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


def _handle_team_model(args):
    if type(args) is not dict:
        return model_result(args)
    if any(key not in MODEL_REQUIRED + MODEL_OPTIONAL and key not in SERVER_INJECTED for key in args):
        return {"error": "invalid_model_arguments"}
    values = {key: value for key, value in args.items() if key not in SERVER_INJECTED}
    refusal = model_argument_refusal(values)
    if refusal is not None:
        return refusal
    return model_result(values, args.get("workspace"))


_TOOL_HANDLERS = {
    "aegis_scan": handle_scan,
    "aegis_report_outcome": handle_report_outcome,
    "aegis_create_rule": handle_create_rule,
    "aegis_list_rules": handle_list_rules,
    "aegis_capture_insight": handle_capture_insight,
    "aegis_msg_read": handle_msg_read,
    "aegis_msg_write": handle_msg_write,
    "aegis_team_config": _handle_team_config,
    "aegis_team_model": _handle_team_model,
    "aegis_team_queue": _handle_team_queue,
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
    return isinstance(name, str) and (name in _TOOL_HANDLERS or name == "aegis_team_queue_claim")


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


def execute_tool(name: str, args: dict, *, client_arguments: bool = False, queue_grant=None, queue_session=None) -> Any:
    """Check the arguments against the schema, dispatch, and project the response if a view is asked for."""
    if name == "aegis_team_queue_claim":
        from .queue_role import Grant, claim_argument_refusal, refusal

        invalid = claim_argument_refusal(args)
        if invalid is not None:
            return invalid
        if client_arguments or type(queue_grant) is not Grant:
            return refusal("role_missing")
        return queue_grant.claim(args, queue_session)
    if name == "aegis_team_queue":
        if client_arguments:
            invalid = queue_argument_refusal(args)
            if invalid is not None:
                return invalid
        return _handle_team_queue(args)
    if name == "aegis_team_model":
        if client_arguments and (type(args) is not dict or any(key in SERVER_INJECTED for key in args)):
            return {"error": "invalid_model_arguments"}
        return _handle_team_model(args)
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
