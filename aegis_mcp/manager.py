"""Separate manager-only MCP schemas and dispatch; repository contracts stay intact."""
from __future__ import annotations

import re
from typing import Any

from aegis_core.primitives import strict_loads

__all__ = ["INSTRUCTIONS", "TOOL_DEFINITIONS", "decode_frame", "execute", "validate_call"]

INSTRUCTIONS = ("Aegis manager audit prototype. Scan a management action before recording "
                "its outcome. Audit acknowledgement grants no fitness, approval, execution, "
                "delegation authority or native Teams enforcement. Scope and policy are "
                "fixed by this registration; repository implementation rules remain local.")
_ACTIONS = ["delegation", "ownership", "hierarchy", "resource_budget", "checkpoint", "handoff",
            "evidence_review", "escalation", "policy_change"]


def _string(limit=128):
    return {"type": "string", "minLength": 1, "maxLength": limit}


def _object(properties, required=()):
    return {"type": "object", "properties": properties, "required": list(required),
            "additionalProperties": False}


_CONTEXT = _object({key: _string(4096 if key == "summary" else 128) for key in
                    ("member_id", "worktree_id", "role", "phase", "risk", "summary")},
                   ("member_id", "worktree_id"))
_EVIDENCE = _object({key: _string(1024 if key == "reference" else 256) for key in
                     ("member_id", "worktree_id", "source_tree", "check", "rule_id", "rule_revision", "reference")},
                    ("member_id", "worktree_id", "source_tree", "check", "rule_id", "rule_revision", "reference"))
_SCHEMAS = {
    "aegis_scan": _object({"action": {"type": "string", "enum": _ACTIONS}, "context": _CONTEXT},
                          ("action", "context")),
    "aegis_list_rules": _object({}),
    "aegis_report_outcome": _object({
        "decision_ref": {**_string(64), "minLength": 64, "pattern": "[0-9a-f]{64}"},
        "rules_used": {"type": "array", "items": _string(64), "maxItems": 128},
        "outcome": {"type": "string", "enum": ["success", "partial", "failure", "pass", "fail", "tp", "fp"]},
        "evidence": {"type": "array", "items": _EVIDENCE, "maxItems": 20},
        "idempotency_key": _string(128), "tests_passed": {"type": "boolean"}},
        ("decision_ref", "rules_used", "outcome", "idempotency_key")),
}
_DESCRIPTIONS = {
    "aegis_scan": "Record a manager action and bounded context; return matching manager rules and an immutable decision reference.",
    "aegis_list_rules": "Inspect the activated manager policy only; no repository implementation rules or fitness exposure.",
    "aegis_report_outcome": "Record a claimed outcome for a served manager decision. Audit acknowledgement always earns zero fitness credit.",
}
TOOL_DEFINITIONS = [{"name": name, "description": _DESCRIPTIONS[name], "inputSchema": schema,
                     "annotations": {"readOnlyHint": name == "aegis_list_rules", "destructiveHint": False,
                                     "idempotentHint": name != "aegis_scan", "openWorldHint": False}}
                    for name, schema in _SCHEMAS.items()]


def _validate(value: Any, schema: dict, path: str) -> None:
    kind = schema["type"]
    valid = {"object": isinstance(value, dict), "array": isinstance(value, list),
             "string": isinstance(value, str), "boolean": isinstance(value, bool)}[kind]
    if not valid:
        raise ValueError(f"manager argument {path} must be {kind}")
    if kind == "object":
        extra = sorted(set(value) - set(schema["properties"]))
        if extra:
            raise ValueError(f"unexpected manager argument {path}.{extra[0]}")
        missing = [key for key in schema.get("required", ()) if key not in value]
        if missing:
            raise ValueError(f"missing manager argument {path}.{missing[0]}")
        for key, item in value.items():
            _validate(item, schema["properties"][key], f"{path}.{key}")
    elif kind == "array":
        if len(value) > schema["maxItems"]:
            raise ValueError(f"manager argument {path} exceeds item limit")
        for item in value:
            _validate(item, schema["items"], path + "[]")
    elif kind == "string":
        if not schema.get("minLength", 1) <= len(value) <= schema.get("maxLength", 4096):
            raise ValueError(f"manager argument {path} has invalid length")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise ValueError(f"manager argument {path} has invalid format")
        if "enum" in schema and value not in schema["enum"]:
            raise ValueError(f"manager argument {path} has unsupported value")


def validate_call(name: Any, arguments: Any) -> None:
    if not isinstance(name, str) or name not in _SCHEMAS:
        raise ValueError(f"Unknown tool: {name}")
    _validate(arguments, _SCHEMAS[name], "arguments")


def execute(config_path: str, config_digest: str, provenance: dict, name: str, arguments: dict):
    validate_call(name, arguments)
    from aegis_core.manager import ManagerService

    service = ManagerService(config_path, provenance=provenance, expected_config_digest=config_digest)
    if name == "aegis_scan":
        return service.scan(arguments["action"], arguments["context"])
    if name == "aegis_list_rules":
        return service.list_rules()
    return service.report(arguments["decision_ref"], arguments["rules_used"], arguments["outcome"],
                          arguments.get("evidence", []), arguments["idempotency_key"],
                          tests_passed=arguments.get("tests_passed"))


def decode_frame(line: str):
    """Manager transport rejects duplicate keys and non-finite JSON before dispatch."""
    if len(line.encode("utf-8")) > 262144:
        raise ValueError("manager frame exceeds 262144 bytes")

    return strict_loads(line)
