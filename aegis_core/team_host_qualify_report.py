"""Structural acceptance for producer host-qualification reports.

A report is accepted when it is bounded and matches the producer shape:
completed, reported passing and non-fake. This module does not replay
steps, permissions, expectations, settings, recovery, multi-agent or ROOT.
It does not spawn, open paths or import aegis packages.
"""
from __future__ import annotations

import re


__all__ = [
    "FAKE_CLAIM",
    "MAX_RECORD_BYTES",
    "MAX_REPORT_BYTES",
    "PROBE_ROLES",
    "REAL_CLAIM",
    "REPORT_SCHEMA",
    "accept_report",
    "role_retained",
]

REPORT_SCHEMA = "aegis.native-probe-report/v1"
FAKE_CLAIM = "none: the codex on PATH is the test fake"
REAL_CLAIM = "this host and Codex version only; a model that declines shows NOT_ATTEMPTED, never REFUSED"
MAX_REPORT_BYTES = 512 * 1024
_MAX_DEPTH = 16
_MAX_STRING = 4096
# Probe contract role set (tools/hierarchy_native_probe.py ROLES). Membership, not a full cover.
_PROBE_ROLES = frozenset((
    "implementer", "integrator", "reviewer", "front-door", "orchestrator", "router", "decider",
))
# Closed-world producer report table. Hold turn_context is the boolean true witness.
_MISS = object()
_UNCONFIRMED = "unconfirmed against a real host"
_MARKS = frozenset(("written", "present"))
_CHECKS = frozenset(("checked", "unchecked", "mismatch"))
_TARGETS = frozenset(("worktree", "outside", "gitdir", "codex_home"))
_CHANNELS = frozenset(("shell", "apply_patch"))
_VERDICTS = frozenset(("REFUSED", "ALLOWED", "UNAVAILABLE"))
_EXPECTS = _VERDICTS | frozenset(("NOT_ATTEMPTED", "INCONCLUSIVE"))
_S, _TX, _N, _B = ("str",), ("text",), ("none",), ("bool",)
_I, _CODE = ("int", 0, 100000), ("int", 0, 255)
_OPT_S, _OPT_I, _OPT_B = ("alt", (_N, _S)), ("alt", (_N, ("int", -255, 255))), ("alt", (_N, _B))
_WITNESS = ("obj", (("path", _S), ("line", ("int", 1, 10000000)), ("sha256", ("sha",)), ("timestamp", _OPT_S)), (("call_id", _OPT_S), ("source", _S), ("exit_code", _OPT_I), ("status", _OPT_S), ("success", _B)))
_TURN = ("obj", (("path", _S), ("line", ("int", 1, 10000000)), ("sha256", ("sha",)), ("timestamp", _OPT_S)), ())
_SANDBOX_RO = ("obj", (("type", ("eq", "read-only")),), ())
_SANDBOX_WW = ("obj", (("type", ("eq", "workspace-write")), ("writable_roots", ("list", _S, 0, 32)), ("network_access", _B), ("exclude_slash_tmp", _B), ("exclude_tmpdir_env_var", _B)), ())
_SANDBOX = ("alt", (_SANDBOX_RO, _SANDBOX_WW))
# Producer observations are already byte-, depth- and item-bounded by JSON
# preflight. Keep their envelope without decoding raw permission policy.
_OBS = ("container", ("model", "effort", "cwd", "approval_policy", "approvals_reviewer",
                      "sandbox_policy", "permission_profile"))
_PERMS = ("obj", (("supported", ("eq", True)), ("network", ("eq", "restricted")),
                  ("entries", ("list", ("container", ()), 1, 64)), ("reasons", ("list", _S, 0, 8))), ())
_EVIDENCE = ("obj", (("nonce_file", _B), ("events", _I)), (("event", _WITNESS), ("output", _TX), ("untrusted_wrappers", _I), ("declined", _I), ("unavailable", _I), ("shape", ("alt", (_S, ("list", _S, 2, 8)))), ("strength", _S), ("note", _TX), ("contradiction", _TX)))
_ATTEMPT = ("obj", (("id", _S), ("target", ("in", _TARGETS)), ("channel", ("in", _CHANNELS)), ("path", _S), ("nonce", _S), ("expected", ("in", _EXPECTS)), ("verdict", ("in", _VERDICTS)), ("assessment", ("eq", "as_expected")), ("evidence", _EVIDENCE)), ())
_LOG = ("obj", (("stdout", _S), ("stderr", _S)), ())
_STOP = ("obj", (("state", _S), ("launcher_exit", _CODE)), (("pids", ("list", ("int", 0, 2147483647), 0, 64)), ("wake_marker_present", _B), ("grace_seconds", ("int", 0, 3600)), ("error", _TX), ("unresolved_groups", ("list", _S, 0, 64))))
_START = ("obj", (("state", ("eq", "bound")), ("launcher_exit", _CODE), ("exit_code", _OPT_I), ("session", _S)), (("error", _TX),))
_PROBE_STEP = ("obj", (("state", ("eq", "ran")), ("exit_code", _CODE), ("timed_out", _B), ("turn_id", _S), ("log", _LOG)), (("error", _TX),))
_HOLD = ("obj", (("state", ("eq", "stopped")), ("turn_context", ("eq", True)), ("stop", _STOP), ("exit_code", _OPT_I), ("turn_id", _S), ("turn_completed", _B), ("nonce", _S), ("marks", ("obj", (("done", ("in", _MARKS)), ("release", ("in", _MARKS))), ())), ("log", _LOG)), ())
_WAKE_BODY = ("obj", (("state", ("eq", "read")),), (("wake_id", _OPT_S), ("exit_code", _OPT_I), ("timed_out", _B)))
_RESUME = ("obj", (("state", ("eq", "resumed")), ("launcher_exit", _CODE), ("wake", _WAKE_BODY)), (("wake_exit_code", _OPT_I), ("error", _TX)))
_PUBLISH = ("obj", (("message_id", _S), ("exit_code", ("eq", 0))), (("error", _TX),))
_WAKE = ("obj", (("state", ("eq", "resumed")), ("publish", _PUBLISH), ("resume", _RESUME)), ())
_SETTINGS = ("obj", (("state", ("eq", "PROFILE_MATCH")), ("reasons", ("list", _S, 0, 32)), ("turn_id", _S), ("model", _S), ("model_check", ("in", _CHECKS)), ("effort", _S), ("effort_check", ("in", _CHECKS)), ("cwd", _S), ("approval_policy", _S), ("approvals_reviewer", _OPT_S), ("approvals_reviewer_expected", _S), ("sandbox_policy", _SANDBOX), ("requested_tier", _S), ("served_tier", _OPT_S), ("served_tier_source", _OPT_S), ("turn_record", _TURN)), ())
_AGENT = ("obj", (("state", ("eq", "MULTI_AGENT_OFF")), ("reasons", ("list", _S, 0, 32)), ("version", ("alt", (_N, _S, ("int", 0, 1000)))), ("agent_tools", ("list", _S, 0, 32)), ("turns", _I), ("tool_records", _I)), (("unknown_tools", ("list", _S, 1, 32)),))
_RECOVERY = ("obj", (("stopped_turn_id", _OPT_S), ("stopped_turn_completed", _OPT_B), ("resumed_turn_id", _OPT_S), ("resumed_turn_completed", _OPT_B), ("wake_read", _B), ("settings_kept", _B), ("sandbox_policy", ("alt", (_N, _SANDBOX))), ("recovered", ("eq", True))), ())
_ROLE_BODY = ("obj", (("role", ("role",)), ("endpoint", _S), ("initiative", _S), ("sandbox", _S), ("shell", _B), ("session", _S), ("rollout", _S), ("steps", ("obj", (("start", _START), ("probe", _PROBE_STEP), ("hold", _HOLD), ("wake", _WAKE)), ())), ("settings", ("obj", (("probe", _SETTINGS), ("wake", _SETTINGS)), ())), ("attempts", ("list", _ATTEMPT, 1, 64)), ("recovery", _RECOVERY), ("multi_agent", _AGENT)), ())
_LOGIN = ("alt", (("obj", (("mode", ("eq", "existing")), ("auth_file", _S), ("codex_login_called", ("eq", False)), ("auth_file_sha256_before", _OPT_S), ("cleanup", _S)), (("error", _TX),)), ("obj", (("argv", ("list", _S, 1, 8)), ("api_key_env", _S), ("exit_code", ("eq", 0))), ())))
_CUSTODY = ("obj", (("base", _OPT_S), ("endpoint", _OPT_S), ("reason", _TX)), ())
_CLEANUP = ("obj", (("worktree_removed", ("eq", True)), ("auth_removed", ("eq", True)), ("leftover_processes", ("list", ("alt", (_N, ("int", 0, 2147483647))), 0, 64)), ("found_running", ("list", _S, 0, 64)), ("command", ("list", _S, 1, 16))), (("error", _TX), ("auth_error", _TX), ("login_left", ("list", _S, 0, 64)), ("unresolved_custody", ("list", _CUSTODY, 0, 64))))
_FOLDER = ("obj", (("path", _S), ("before", _OPT_S), ("after", _OPT_S), ("errors", ("list", _S, 0, 32)), ("state", ("in", frozenset(("unchanged", "changed", "unknown"))))), ())
_HOME = ("obj", (("state", ("eq", "unchanged")), ("folders", ("list", _FOLDER, 0, 8))), ())
_SUMMARY = ("obj", (("passed", ("eq", True)), ("failures", ("list", _TX, 0, 0)), ("unexpected", ("list", _TX, 0, 0)), ("inconclusive", ("list", _TX, 0, 0))), ())
_SHAPES = ("obj", (("apply_patch response_item", ("eq", _UNCONFIRMED)),), ())
_BINARY = ("obj", (("path", _S), ("fake", ("eq", False))), ())
_ROOT = ("obj", (("rollout", _S), ("cid", _S), ("started_session", ("eq", False)), ("read_only", ("eq", True)), ("reasons", ("list", _S, 0, 32)), ("multi_agent", _AGENT), ("served_tier", _OPT_S), ("turn_record", _TURN), ("settings", _OBS), ("observed_permissions", _PERMS)), ())
_REPORT = ("obj", (("schema", ("eq", REPORT_SCHEMA)), ("probe_root", _S), ("probe_id", ("probe",)), ("started_at", ("ts",)), ("enforcement_claim", ("eq", REAL_CLAIM)), ("turn_cap", _I), ("login", ("alt", (_N, _LOGIN))), ("roles", ("list", _ROLE_BODY, 0, 64)), ("root", ("alt", (_N, _ROOT))), ("cleanup", _CLEANUP), ("shapes", _SHAPES), ("home_codex", _HOME), ("state", ("eq", "completed")), ("turns_used", _I), ("finished_at", ("ts",)), ("summary", _SUMMARY)), (("host", ("line",)), ("host_version", ("ver",))))
_ROLE = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
_PROBE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")

PROBE_ROLES = _PROBE_ROLES
_RECORD_ESCAPE = 6
_RECORD_ENVELOPE = 768
MAX_RECORD_BYTES = MAX_REPORT_BYTES * _RECORD_ESCAPE + _RECORD_ENVELOPE

def _same(value, expect):
    if type(expect) is bool:
        return value is expect
    if type(expect) is int:
        return type(value) is int and value == expect
    return type(expect) is str and type(value) is str and value == expect

def _text(value, kind):
    if type(value) is not str or "\x00" in value or len(value) > _MAX_STRING:
        return _MISS
    if kind == "text":
        return value
    if kind == "ver":
        return value if 1 <= len(value) <= 128 else _MISS
    if "\n" in value or "\r" in value or not value:
        return _MISS
    return value if kind != "line" or len(value) <= 128 else _MISS

def _scalar(rule, value):
    kind = rule[0]
    if kind in ("str", "text", "line", "ver"):
        return _text(value, kind)
    if kind == "bool":
        return value if type(value) is bool else _MISS
    if kind == "int":
        if type(value) is not int or isinstance(value, bool) or not rule[1] <= value <= rule[2]:
            return _MISS
        return value
    if kind == "eq":
        return value if _same(value, rule[1]) else _MISS
    if kind == "none":
        return None if value is None else _MISS
    if kind == "in":
        return value if type(value) is str and value in rule[1] else _MISS
    if kind == "sha":
        return value if type(value) is str and _SHA.fullmatch(value) is not None else _MISS
    if kind == "ts":
        return value if type(value) is str and _TS.fullmatch(value) is not None else _MISS
    if kind == "probe":
        return value if type(value) is str and _PROBE.fullmatch(value) is not None else _MISS
    if kind == "role":
        matched = type(value) is str and value in _PROBE_ROLES and _ROLE.fullmatch(value) is not None
        return value if matched else _MISS
    return _MISS

def _apply(rule, value, depth):
    if depth > _MAX_DEPTH:
        return _MISS
    kind = rule[0]
    if kind == "container":
        if type(value) is dict and len(value) <= 64 and all(key in value for key in rule[1]):
            return value
        return _MISS
    if kind == "alt":
        for option in rule[1]:
            got = _apply(option, value, depth + 1)
            if got is not _MISS:
                return got
        return _MISS
    if kind == "list":
        if type(value) is not list or not rule[2] <= len(value) <= rule[3]:
            return _MISS
        for item in value:
            if _apply(rule[1], item, depth + 1) is _MISS:
                return _MISS
        return value
    if kind != "obj":
        return _scalar(rule, value)
    if type(value) is not dict or len(value) > 64:
        return _MISS
    allowed = {key: child for key, child in rule[1]}
    allowed.update({key: child for key, child in rule[2]})
    if any(key not in value for key, _child in rule[1]):
        return _MISS
    for key, item in value.items():
        if type(key) is not str or key not in allowed:
            return _MISS
        if _apply(allowed[key], item, depth + 1) is _MISS:
            return _MISS
    return value


def accept_report(report, binary):
    """Role map from a structurally valid producer report, or None."""
    if type(report) is not dict or type(binary) is not str or not 1 <= len(report) <= 64:
        return None
    if any(type(key) is not str for key in report) or binary not in report:
        return None
    rest = {key: value for key, value in report.items() if key != binary}
    if _apply(_REPORT, rest, 0) is _MISS or _apply(_BINARY, report[binary], 0) is _MISS:
        return None
    has_roles = bool(rest["roles"])
    if has_roles != (rest["login"] is not None) or (not has_roles and rest["root"] is None):
        return None
    found = {}
    for role in rest["roles"]:
        name = role["role"]
        if name in found:
            return None
        found[name] = role
    return found


def role_retained(key, role):
    """True when one stored role still matches the producer role shape."""
    walked = _apply(_ROLE_BODY, role, 0)
    if walked is _MISS or walked.get("role") != key or _apply(("role",), key, 0) is _MISS:
        return False
    return True
