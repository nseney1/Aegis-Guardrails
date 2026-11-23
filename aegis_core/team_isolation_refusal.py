"""Stable, input-free isolation refusals for planning and capability checks.

Plan responses share one projection. Capability responses stay on refusal() and
finish() and do not carry a human reason or an input stage.
"""

__all__ = [
    "CAPABILITY_CODES", "DOCUMENT_CODES", "LAUNCHER_ENVIRONMENT_REASON", "PLAN_STAGES",
    "REFUSALS", "STAGED_PLAN_KEYS", "UNSTAGED_PLAN_KEYS", "IsolationRefusal",
    "finish", "plan_response", "plan_text", "refusal", "with_document_stage",
]

_CAPABILITY_REFUSALS = {
    "unknown_field": "isolation document contains an unknown field",
    "unknown_role": "isolation document role is not in the injected vocabulary",
    "unknown_host": "isolation document host is not in the injected host table",
    "oversized": "isolation document exceeds its size limit",
    "invalid_encoding": "isolation document is not valid UTF-8",
    "missing_vocabulary": "isolation capability report requires an injected role vocabulary",
    "missing_host_table": "isolation capability report requires an injected host table",
    "invalid_table": "injected role or host table is malformed",
    "invalid_document": "isolation document is malformed",
    "ambiguous": "isolation document is ambiguous",
    "invalid_host_mapping": "host capability mapping is malformed",
    "invalid_mcp_tools": "provisioned MCP tools are malformed",
    "invalid_file_tools": "provisioned file tools are malformed",
    "invalid_prohibited_call_tools": "prohibited-call mapping is malformed",
    "uncovered_prohibited_calls": "prohibited calls are not covered by the injected mapping",
    "prohibited_capability": "resolved capabilities include a prohibited call",
    "invalid_resolution": "capability resolution is malformed",
    "invalid_catalog": "served capability catalog is malformed",
    "incomplete_catalog": "served capability catalog is incomplete",
    "invalid_probe_plan": "capability probe plan is malformed",
    "invalid_observations": "capability probe observations are malformed",
    "incomplete_observations": "capability probe observations are incomplete",
    "inconclusive_observations": "capability probe observations are inconclusive",
    "internal": "Report an internal isolation check failure.",
}

CAPABILITY_CODES = frozenset(_CAPABILITY_REFUSALS)
REFUSALS = {
    **_CAPABILITY_REFUSALS,
    "container_required": "Verification requires a container-mode plan.",
    "docker_unqualified": "Set isolation.allow_unqualified to true if Docker use is intended.",
    "document_invalid": "Supply a valid bounded JSON document.",
    "document_read": "Supply an accessible regular JSON file without symlink components.",
    "document_size": "Reduce the isolation input to its documented size limits.",
    "engine_custody": "Select an owner-approved engine in an absolute, protected PATH directory.",
    "environment": "Supply only allowlisted environment values and keep the configured homes.",
    "expected_record": "Recompute the expected container record from validated observations.",
    "host_registry": "Supply a valid team host table with unique run homes.",
    "image_inspect": "Provide a successful image inspection for the configured digest.",
    "image_inspect_timeout": "Retry after the engine can inspect the configured digest within 30 seconds.",
    "image_tag": "Supply a nonempty image tag that does not start with a dash.",
    "invalid_arguments": "Use aegis team isolation check --help for the required options.",
    "isolation_command": "Supply a bounded nonempty command with a valid executable.",
    "isolation_cpus": "Set a CPU limit within the available CPU count.",
    "isolation_engine": "Select a supported container engine.",
    "isolation_fields": "Supply only fields allowed for the selected isolation mode.",
    "isolation_image": "Supply a valid image reference for the requested engine operation.",
    "isolation_memory": "Supply a positive memory limit with a k, m or g suffix.",
    "isolation_mode": "Select host or container isolation.",
    "isolation_object": "Supply isolation as a JSON object.",
    "isolation_pids": "Supply an integer PID limit of at least 64 and at most 2147483647.",
    "isolation_unqualified": "Supply a boolean allow_unqualified value.",
    "isolation_user": "Supply a valid numeric container UID and GID.",
    "mount_changed": "Retry with unchanged mount paths and access metadata.",
    "mount_metadata": "Supply complete trusted mount metadata and readable access ACLs.",
    "mount_overlap": "Use distinct mounts with no overlap between access domains.",
    "mount_rows": "Supply valid same-path mount rows within the mount limit.",
    "owner_homes": "Supply the trusted explicit, ambient and account home paths.",
    "python_bin": "Set recipes.python to an absolute path inside a bin directory.",
    "python_prefix": "Use an explicit python_prefix or an inferred prefix with a regular pyvenv.cfg.",
    "stop_timeout": "Supply a positive bounded integer stop timeout.",
    "team_run_fields": "Supply only supported team-run fields.",
    "team_run_recipes": "Supply the Python interpreter in a team-run recipes object.",
    "team_run_schema": "Use schema aegis.team-run/v2 when specifying isolation.",
    "unsafe_mount": "Select paths without protected, aliased or unsafe mount components.",
    "unsupported_platform": "Run this check where Linux descriptor-relative observations are available.",
}


# Closed document inputs. TA-6d agrees this additive plan field and these values.
DOCUMENT_CODES = frozenset(("document_invalid", "document_read", "document_size"))
PLAN_STAGES = frozenset(("config", "container-inspection", "image-inspection"))
UNSTAGED_PLAN_KEYS = frozenset(("status", "code", "reason", "next_action"))
STAGED_PLAN_KEYS = frozenset(("status", "code", "reason", "next_action", "stage"))
_LAUNCHER_ENVIRONMENT_NOTE = "launcher_environment"
LAUNCHER_ENVIRONMENT_REASON = "Retry from a clean launcher environment."


def _valid_stage(code, stage):
    return type(stage) is str and stage in PLAN_STAGES and code in DOCUMENT_CODES


class IsolationRefusal(ValueError):
    """Stable code string, fixed human message and structured next action."""

    status = "refused"
    exit_code = 1

    def __init__(self, code, *, stage=None, note=None):
        if type(code) is not str or code not in REFUSALS:
            code = "internal"
            stage = None
            note = None
        if code != "image_inspect" or type(note) is not str or note != _LAUNCHER_ENVIRONMENT_NOTE:
            note = None
        self.note = note
        self.message = LAUNCHER_ENVIRONMENT_REASON if note is not None else REFUSALS[code]
        self.code = self.reason = code
        self.stage = stage if _valid_stage(code, stage) else None
        if code == "invalid_arguments":
            self.exit_code = 2
        self.next_action = {"actor": "operator", "command": self.message}
        super().__init__(code)


def with_document_stage(error, stage):
    """Attribute a document refusal to the input handled by this boundary."""
    if isinstance(error, IsolationRefusal):
        code = getattr(error, "code", None)
        if type(code) is str and _valid_stage(code, stage):
            return IsolationRefusal(code, stage=stage)
    return error


def plan_response(error):
    """One projection for core, CLI and parser errors. Stage is present only for a document input."""
    if isinstance(error, IsolationRefusal):
        refusal = IsolationRefusal(getattr(error, "code", None),
                                   stage=getattr(error, "stage", None), note=getattr(error, "note", None))
    else:
        refusal = IsolationRefusal("internal")
    body = {"status": refusal.status, "code": refusal.code, "reason": refusal.message,
            "next_action": refusal.next_action}
    if refusal.stage is not None:
        body["stage"] = refusal.stage
    return body


def plan_text(body):
    """Render single-line operator text from the closed refusal catalog."""
    internal = "internal — " + REFUSALS["internal"]
    if type(body) is not dict:
        return internal
    code, reason = body.get("code"), body.get("reason")
    if type(code) is not str or code not in REFUSALS or type(reason) is not str:
        return internal
    if reason != REFUSALS[code] and (code != "image_inspect" or reason != LAUNCHER_ENVIRONMENT_REASON):
        return internal
    if "stage" not in body:
        return code + " — " + reason
    stage = body["stage"]
    if not _valid_stage(code, stage):
        return internal
    return code + " — " + reason + " (" + stage + ")"


_VERDICT_CODES = {
    "resolved": "resolved",
    "match": "equal_catalog",
    "exceeds": "extra_capabilities",
    "planned": "planned",
    "pass": "all_refused",
    "fail": "attempt_allowed",
}
_REFUSAL_DETAILS = ("prohibited_calls", "uncovered_calls", "extras", "missing", "attempts")


def refusal(code, *, details=None):
    error = IsolationRefusal(code)
    body = {"status": error.status, "code": error.code, "next_action": error.next_action}
    if error.code != "internal" and details is not None:
        body.update({key: details[key] for key in _REFUSAL_DETAILS if key in details})
    return body


def finish(result):
    """Allow only a declared verdict pair or render a registered refusal."""
    status, code = result.get("status"), result.get("code")
    if type(status) is str and status in _VERDICT_CODES:
        if type(code) is str and code == _VERDICT_CODES[status]:
            return result
        return refusal("internal")
    if type(code) is str and code == "invalid_role":
        code = "unknown_role"
    return refusal(code, details=result)
