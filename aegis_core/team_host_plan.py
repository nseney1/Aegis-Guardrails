"""Host-plan and immutable session-record readers (TA-4a round 1b).

A trusted absolute base is opened without following any component symlink.
Retained parent descriptors anchor bounded reads across rename/replacement.
Legacy ValueError causes map to HostRefusal reasons; text is excluded from parity:
oversized -> too_large; JSON/UTF-8/duplicates/depth -> invalid_json; closed keys
-> plan_keys; schema -> plan_schema; host mismatch -> host_mismatch; all other
plan fields -> invalid_plan. Missing plans retain None. No function writes state.
MAX_BYTES=262144 bounds files before allocation/parsing; MAX_PATH_CHARS=32768
bounds path spelling before Path allocation. Oversized files refuse too_large,
and over-bound paths refuse unsafe_path, both with code 1.
"""
from __future__ import annotations

from pathlib import Path
import re

from aegis_core.storage import ConfinedFileError, confined_file
from aegis_core.storage import confined_descriptor_supported as descriptor_supported
from aegis_core.team_mailbox_primitives import (
    render_mailbox_refusal,
    MAX_BYTES, MailboxRefusal, RoleTables, bounded_tree, integer, strict_json, text,
)
from aegis_core.team_host_registry import (
    CLAUDE, HOST_KINDS, TEAM_HOSTS, HostRefusal, entry, guarded, qualify, require,
)

__all__ = [
    "HostRefusal", "MAX_BYTES", "descriptor_supported", "PLAN_SCHEMA", "PLAN_FILE", "PLAN_KEYS",
    "SESSION_SCHEMA", "STAND_IN_SCOPE", "START_MODES", "MAX_PATH_CHARS", "SHA256", "validate_plan",
    "plan_record", "read_plan", "base_plan", "governing_plan", "plan_host", "require_binding",
    "team_start_mode", "session_record", "session_record_path", "session_recorded", "absolute_path",
]

PLAN_SCHEMA = "aegis.hierarchy-host-plan/v1"
PLAN_FILE = "host-plan.json"
PLAN_KEYS = ("schema", "hierarchy", "root", "team", "stand_ins", "config_sha256")
SESSION_SCHEMA = "aegis.team-session/v1"
STAND_IN_SCOPE = {"boundary": "stand-in: runs no host"}
START_MODES = ("print", "background", "exec", None)
MAX_PATH_CHARS = 32768
SHA256 = re.compile(r"[0-9a-f]{64}")
_MISSING = object()
_ROLES = RoleTables()


def _endpoint(name):
    try:
        return _ROLES.endpoint_parts(name)
    except ValueError:
        return None


@guarded
def validate_plan(value):
    bounded_tree(value)
    require(type(value) is dict, reason="invalid_plan")
    require(value.keys() == set(PLAN_KEYS), reason="plan_keys")
    require(value["schema"] == PLAN_SCHEMA, reason="plan_schema")
    hierarchy = value["hierarchy"]
    require(type(hierarchy) is str and len(hierarchy) <= 80 and
            _endpoint(hierarchy + "/root") is not None, reason="invalid_plan")
    for key in ("root", "team"):
        require(type(value[key]) is str and value[key] in TEAM_HOSTS, reason="invalid_plan")
    stand_ins = value["stand_ins"]
    require(type(stand_ins) is dict, reason="invalid_plan")
    for name, kind in stand_ins.items():
        parts = _endpoint(name)
        require(parts is not None and parts[0] == hierarchy and parts[1] == "front-door",
                reason="invalid_plan")
        require(type(kind) is str and kind in HOST_KINDS, reason="invalid_plan")
    require(type(value["config_sha256"]) is str and SHA256.fullmatch(value["config_sha256"]) is not None,
            reason="invalid_plan")
    return value


@guarded
def plan_record(hierarchy, root, team, stand_ins, config_sha256):
    record = {"schema": PLAN_SCHEMA, "hierarchy": hierarchy, "root": root, "team": team,
              "stand_ins": stand_ins, "config_sha256": config_sha256}
    validate_plan(record)
    record["stand_ins"] = dict(stand_ins)
    return record


def _read_json(base, parts):
    require(descriptor_supported(), reason="unsupported_platform")
    try:
        with confined_file(base, parts) as handle:
            raw = handle.read_bytes(MAX_BYTES)
    except ConfinedFileError as error:
        if error.reason == "missing":
            return _MISSING
        reason = {"unsupported": "unsupported_platform", "too_large": "too_large",
                  "unsafe": "unsafe_path", "invalid_path": "unsafe_path"}.get(error.reason, "io")
        raise HostRefusal(reason) from None
    try:
        return strict_json(raw)
    except MailboxRefusal as error:
        raise HostRefusal("too_large" if render_mailbox_refusal(error)["reason"] == "too_large" else "invalid_json") from None


@guarded
def read_plan(base):
    value = _read_json(base, (PLAN_FILE,))
    return None if value is _MISSING else validate_plan(value)


@guarded
def base_plan(base, hierarchy):
    plan = read_plan(base)
    require(plan is None or plan["hierarchy"] == hierarchy, reason="hierarchy_mismatch")
    return plan


@guarded
def governing_plan(base, mailbox_root, hierarchy):
    base, home = absolute_path(base), absolute_path(mailbox_root).parent
    plan = base_plan(base, hierarchy)
    if base == home:
        return plan
    other = base_plan(home, hierarchy)
    require(plan is None or other is None or plan == other, reason="plan_mismatch")
    return plan if plan is not None else other


@guarded
def plan_host(plan, endpoint):
    if plan is None:
        return None, False
    validate_plan(plan)
    parts = _ROLES.endpoint_parts(endpoint)
    if parts[0] != plan["hierarchy"]:
        return None, False
    if endpoint in plan["stand_ins"]:
        return plan["stand_ins"][endpoint], True
    return (plan["root"] if parts[1] == "root" else plan["team"]), False


@guarded
def require_binding(plan, endpoint, host, writer):
    if plan is None:
        return None
    expected, stand_in = plan_host(plan, endpoint)
    require(expected is not None, reason="endpoint_mismatch")
    require(host == expected, reason="host_mismatch")
    if stand_in:
        require(type(writer) is bool and not writer)
        return dict(STAND_IN_SCOPE)
    return qualify(host, writer)


@guarded
def team_start_mode(host_kind, stand_in, background=False):
    team_start = entry(host_kind)["team_start"]
    if stand_in:
        return None
    if background:
        require(host_kind == CLAUDE)
        return "background"
    return team_start


@guarded
def session_record(endpoint, role_kind, host_kind, start_mode, session, generation, stand_in, write_scope):
    _ROLES.endpoint_parts(endpoint)
    text(role_kind, "role_kind", 64)
    entry(host_kind)
    require(start_mode is None or (isinstance(start_mode, str) and start_mode in START_MODES))
    text(session, "session", 256)
    integer(generation, "generation")
    require(type(stand_in) is bool)
    bounded_tree(write_scope)
    require(isinstance(write_scope, dict) and isinstance(write_scope.get("boundary"), str))
    roots = write_scope.get("roots", [])
    require(isinstance(roots, list) and all(isinstance(root, str) and root for root in roots))
    return {"schema": SESSION_SCHEMA, "endpoint": endpoint, "role_kind": role_kind, "host_kind": host_kind,
            "start_mode": start_mode, "session": session, "generation": generation, "stand_in": stand_in,
            "write_scope": dict(write_scope)}


def absolute_path(base, limit=MAX_PATH_CHARS):
    require(type(limit) is int and 0 < limit <= MAX_PATH_CHARS, reason="unsafe_path")
    spelling = str(base) if isinstance(base, Path) else base
    require(type(spelling) is str and 0 < len(spelling) <= limit, reason="unsafe_path")
    require("\x00" not in spelling, reason="unsafe_path")
    path = Path(spelling)
    require(path.is_absolute() and ".." not in path.parts, reason="unsafe_path")
    return path


@guarded
def session_record_path(base, endpoint, generation):
    _ROLES.endpoint_parts(endpoint)
    integer(generation, "generation")
    spelling = str(base) if isinstance(base, Path) else base
    require(type(spelling) is str and 0 < len(spelling) <= MAX_PATH_CHARS, reason="unsafe_path")
    return Path(spelling) / "sessions" / ("%s-g%d.json" % (endpoint.replace("/", "%2F"), generation))


@guarded
def session_recorded(path, record):
    path = absolute_path(path)
    bounded_tree(record)
    value = _read_json(path.parent, (path.name,))
    if value is _MISSING:
        return False
    require(value == record, reason="session_mismatch")
    return True

