"""Shared profile provenance and display rendering, without profile I/O."""
from __future__ import annotations

import json
import re
from typing import Any

from aegis_core.primitives import sanitize_display


__all__ = ["NEXT_ACTION_TEMPLATES", "TERMINAL_NAMES", "closed_object", "provenance_values",
           "reject_terminal_hosts", "render_profile"]


TERMINAL_NAMES = ("hold", "skip")


NEXT_ACTION_TEMPLATES = {
    "start": ("Start the job on ", "; capacity advice grants no execution authority."),
    "check": ("Run aegis team hosts check ", " ", " --json; use that declared host if admitted."),
}


def closed_object(properties):
    return {"type": "object", "properties": properties, "additionalProperties": False}


def reject_terminal_hosts(names, error_type, path):
    """Host and capacity keys use decoded, exact, case-sensitive identities."""
    if path in ("model_settings.hosts", "model_settings.capacity"):
        for name in names:
            if type(name) is str and name in TERMINAL_NAMES:
                raise error_type("host alias is reserved for a fallback terminal", path=path + "." + name)


def provenance_values(records):
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


def _display_action_parts(parts, shown, pattern, max_string):
    """Render service template literals and separately validated identities."""
    if type(parts) is not list or not 0 < len(parts) <= 16:
        return None
    literals = {part for template in NEXT_ACTION_TEMPLATES.values() for part in template}
    rendered, remaining = [], max_string
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


def render_profile(value: Any, *, identifier_pattern: str, max_string: int, capacity=False) -> Any:
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
            action = (_display_action_parts(item["next_action_parts"], shown, identifier_pattern, max_string)
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
