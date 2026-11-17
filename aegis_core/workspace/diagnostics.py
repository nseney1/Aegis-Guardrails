"""Pure workspace-binding display projection shared by CLI and MCP.

Canonical bindings stay private. Validate the whole collection before projecting
literal components, then compose fixed wording and bound the final sentence.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from aegis_core.guidance_projection import (
    MAX_GUIDANCE_CHARS, MAX_GUIDANCE_ITEMS, GuidanceProjectionError,
    project_diagnostic, project_error_name,
)
from aegis_core.workspace.binding import WorkspaceBinding

__all__ = ["project_binding"]

_INVALID = "guidance_projection_invalid_field"
_ALLOWED = {"pin", "target", "cwd", "cwd_root", "host_root", "registered_root", "host_roots", "candidates"}
_LISTS = {"host_roots", "candidates"}

_BINDING_MESSAGES = {
    "pin_conflicts_with_host_root": (
        "AEGIS_WORKSPACE pins {pin}, but the host reports the session in {host_roots}; "
        "fix the pin or open the pinned project", ("pin", "host_roots")),
    "pin_conflicts_with_registry": (
        "AEGIS_WORKSPACE pins {pin}, but the files belong to the registered workspace {registered_root}",
        ("pin", "registered_root")),
    "host_root_conflicts_with_registry": (
        "the host reports the session in {host_root}, but the files belong to the registered workspace "
        "{registered_root}", ("host_root", "registered_root")),
    "host_root_conflicts_with_registry_outside": (
        "the host reports the session outside any Aegis workspace, but the files belong to "
        "the registered workspace {registered_root}", ("registered_root",)),
    "ambiguous_host_roots": (
        "the host reports several Aegis workspaces and the call's files do not pick one; "
        "pass the files you plan to edit", ()),
    "cwd_conflicts_with_registry": (
        "the server runs in the workspace {cwd_root}, but the files exist only in the registered "
        "workspace(s) {candidates}; pass absolute paths", ("cwd_root", "candidates")),
    "ambiguous_registry_selection": ("the files exist in several registered workspaces; pass absolute paths", ()),
    "host_roots_not_governed": ("the host's workspace has no .aegis/", ()),
    "no_workspace": ("no Aegis workspace resolves for this call", ()),
    "pin_missing": ("AEGIS_WORKSPACE is set to {workspace}, which cannot be resolved", ()),
    "pin_missing_directory": ("AEGIS_WORKSPACE is set to {workspace}, which is not a directory", ()),
    "pin_not_a_workspace": ("AEGIS_WORKSPACE is set to {workspace}, which has no .aegis/ (run aegis init there)", ()),
    "pin_denied": ("AEGIS_WORKSPACE is set to {workspace}, which is the home directory", ()),
    "pin_denied_root": ("AEGIS_WORKSPACE is set to {workspace}, which is the filesystem root", ()),
}

_CLI_MESSAGES = {
    "pin_conflicts_with_target": (
        "--workspace {workspace} resolves to {target}, but AEGIS_WORKSPACE pins {pin}; "
        "unset the pin or drop --workspace", ("pin", "target")),
    "pin_conflicts_with_cwd": (
        "AEGIS_WORKSPACE pins {pin}, but the current directory {cwd} is in {cwd_root}; "
        "unset the pin, or run aegis from the pinned project", ("pin", "cwd", "cwd_root")),
    "pin_resolution": ("AEGIS_WORKSPACE {pin} cannot be resolved", ("pin",)),
    "target_resolution": ("--workspace {target} cannot be resolved", ("target",)),
    "home_directory": (
        "not an Aegis workspace ({target} is the home directory; ~/.aegis is the user rule layer); "
        "run aegis init in a project", ("target",)),
    "filesystem_root": (
        "not an Aegis workspace ({target} is the filesystem root); run aegis init in a project", ("target",)),
}
_CLI_MESSAGES.update({key: value for key, value in _BINDING_MESSAGES.items() if key.startswith("pin_")})


def _preflight(raw, details):
    refusal = None
    for value in raw.values():
        if value is not None:
            if not isinstance(value, str):
                refusal = _INVALID
                break
            if len(value) > MAX_GUIDANCE_CHARS:
                refusal = GuidanceProjectionError.code
                break
    if not isinstance(details, (tuple, list)):
        return refusal or _INVALID
    items = len(details)
    # Collection overflow has precedence over a malformed wrapper field.
    if items > MAX_GUIDANCE_ITEMS:
        return GuidanceProjectionError.code
    if refusal is not None:
        return refusal
    for entry in details:
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            return _INVALID
        key, value = entry
        if (not isinstance(key, str) or key not in _ALLOWED
                or not isinstance(value, list if key in _LISTS else str)):
            return _INVALID
        items += len(value) if isinstance(value, list) else 1
        if items > MAX_GUIDANCE_ITEMS:
            return GuidanceProjectionError.code
        for path in value if isinstance(value, list) else (value,):
            if not isinstance(path, str):
                return _INVALID
            if len(path) > MAX_GUIDANCE_CHARS:
                return GuidanceProjectionError.code
    return None


def _component(value):
    try:
        name = project_error_name(value)
    except GuidanceProjectionError as error:
        name = error.code
    return project_diagnostic(name, escaped=False)


def _message_key(binding, details):
    reason, kind = binding.reason, binding.kind
    if reason == "pin_missing" and kind == "not_a_directory":
        return "pin_missing_directory"
    if reason == "pin_denied" and kind == "filesystem_root":
        return "pin_denied_root"
    if kind in {"pin_resolution", "target_resolution"} or (
            reason == "no_workspace" and kind in {"home_directory", "filesystem_root"}):
        return kind
    if reason == "host_root_conflicts_with_registry" and "host_root" not in details:
        return "host_root_conflicts_with_registry_outside"
    return reason


def project_binding(binding: WorkspaceBinding, *, workspace: Optional[str] = None,
                    cli: bool = False) -> Dict[str, Any]:
    """Project once without reading message text or mutating the canonical record.

    CLI supplies the explicit target; MCP supplies the registration's pin.
    Their historical field insertion order is retained for byte compatibility.
    """
    raw = {"status": binding.status, "root": str(binding.root) if binding.root is not None else None,
           "source": binding.source, "confidence": binding.confidence, "reason": binding.reason,
           "_workspace": workspace, "_kind": binding.kind}
    refusal = _preflight(raw, binding.details)
    display = {key: None if value is None else _component(value) for key, value in raw.items() if key != "_kind"}
    supplied = display.pop("_workspace")
    details = {}
    if refusal is None:
        for key, value in binding.details:
            shown = [_component(path) for path in value] if isinstance(value, list) else _component(value)
            details[key] = shown
    key = _message_key(binding, details) if refusal is None else None
    template, required = (_CLI_MESSAGES if cli else _BINDING_MESSAGES).get(key, ("workspace binding refused", ()))
    if refusal is None and not all(name in details for name in required):
        refusal = _INVALID
    details = details if refusal is None else {}
    values = {name: ", ".join(value) if isinstance(value, list) else value for name, value in details.items()}
    if cli:
        values["workspace"] = supplied or values.get("target", "workspace")
        if refusal is None and binding.reason in {"pin_missing", "pin_denied", "pin_not_a_workspace"}:
            values["workspace"] = values.get("pin") or supplied or "workspace"
    else:
        values["workspace"] = supplied or values.get("pin") or display["root"] or "workspace"
    message = project_diagnostic(refusal or template.format(**values), escaped=False)
    if cli:
        display.update(message=message, details=details)
    else:
        display.update(details=details, message=message)
    return display
