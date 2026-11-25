"""Owner-only receipts for structurally valid producer host reports.

The native probe runner is not this module. A receipt stores a bounded report
digest, the complete reported roles, the owner timestamp and the host version
from an injected reader. It does not replay the report and it does not qualify
the host. This module never spawns a program.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from datetime import datetime

from aegis_core import hosts
from aegis_core.errors import LockTimeoutError, PathTraversalError
from aegis_core.primitives import is_within, json_preflight, strict_loads, utc_stamp
from aegis_core.storage import file_lock
from aegis_core.storage_confined import ConfinedFileError, confined_file, descriptor_supported as confined_supported
from aegis_core.workspace.layout import UserLayout

from aegis_core.team_host_qualify_report import (
    FAKE_CLAIM,
    MAX_RECORD_BYTES,
    MAX_REPORT_BYTES,
    PROBE_ROLES,
    REAL_CLAIM,
    REPORT_SCHEMA,
    accept_report,
    role_retained,
)


__all__ = [
    "REPORT_SCHEMA",
    "REAL_CLAIM",
    "FAKE_CLAIM",
    "REPORT_ONLY_CLAIM",
    "VERSION_NOTE",
    "REFUSALS",
    "NEXT_ACTIONS",
    "MAX_REPORT_BYTES",
    "HostUnqualified",
    "descriptor_supported",
    "default_state_root",
    "probe_runner_ids",
    "record_relative",
    "text_report",
    "show_report",
    "status",
    "record",
    "record_file",
    "require_qualified",
]

VERSION_NOTE = "an upgrade between probe and record is not detectable for this report"
REPORT_ONLY_CLAIM = "report-only"
_MAX_DEPTH = 16
_MAX_NODES = 8000
_MAX_ITEMS = 1024
_MAX_STRING = 4096
_MAX_CLOCK = 4_000_000_000
_RECORD_DIR = "host-qualification"
_LOCK_TIMEOUT = 5.0
_PROBE_ROLES = PROBE_ROLES
_ROLE = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
_PROBE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_BASE_KEYS = frozenset((
    "enforcement_claim", "fake", "host", "host_version", "passed", "probe_id",
    "recorded_at", "report_sha256", "roles", "schema", "v", "version_source",
))
_NOTE_KEYS = _BASE_KEYS | frozenset(("version_note",))
_UNQUALIFIED = frozenset((
    "missing_record", "version_changed", "version_unavailable", "version_multiline", "no_probe_runner",
    "receipt_recorded", "receipt_current",
))

REFUSALS = {
    "unqualified": "host is unqualified",
    "receipt_recorded": "host report receipt stored",
    "receipt_current": "host report receipt matches this host version",
    "missing_record": "no host qualification record is stored",
    "version_changed": "host version differs from the qualification record",
    "version_unavailable": "host version is unavailable",
    "version_multiline": "host version must be a single line",
    "no_probe_runner": "host has no probe runner",
    "unknown_host": "host is not in the registry",
    "unsupported_platform": "host qualification requires descriptor custody",
    "record_unsafe": "host qualification record failed custody checks",
    "record_invalid": "host qualification record is invalid",
    "record_busy": "host qualification record is busy",
    "record_exists": "host qualification record already exists",
    "record_inside_workspace": "host qualification record must stay outside the workspace",
    "host_mismatch": "host qualification record names another host",
    "report_rejected": "probe report cannot qualify a host",
    "report_malformed": "probe report is malformed",
    "report_unreadable": "probe report is unreadable",
    "report_missing": "probe report is missing",
    "state_unavailable": "host qualification state root is unavailable",
    "invalid_usage": "host qualification usage is invalid",
}
NEXT_ACTIONS = {
    "receipt_recorded": {"actor": "owner", "command": "aegis team qualify host KIND"},
    "receipt_current": {"actor": "owner", "command": "aegis team qualify host KIND"},
    "missing_record": {"actor": "owner", "command": "aegis team qualify host KIND --report PATH --record"},
    "version_changed": {"actor": "owner", "command": "aegis team qualify host KIND --report PATH --record"},
    "version_unavailable": {"actor": "owner", "command": "aegis team qualify host KIND --report PATH --record"},
    "version_multiline": {"actor": "owner", "command": "aegis team qualify host KIND --report PATH --record"},
    "no_probe_runner": {"actor": "owner", "command": "aegis team qualify host KIND"},
    "unknown_host": {"actor": "owner", "command": "aegis team qualify host KIND"},
    "unsupported_platform": {"actor": "owner", "command": "aegis team qualify host KIND"},
    "record_unsafe": {"actor": "owner", "command": "aegis team qualify host KIND --report PATH --record"},
    "record_invalid": {"actor": "owner", "command": "aegis team qualify host KIND --report PATH --record"},
    "record_busy": {"actor": "owner", "command": "aegis team qualify host KIND --report PATH --record"},
    "record_exists": {"actor": "owner", "command": "aegis team qualify host KIND"},
    "record_inside_workspace": {"actor": "owner", "command": "aegis team qualify host KIND"},
    "host_mismatch": {"actor": "owner", "command": "aegis team qualify host KIND --report PATH --record"},
    "report_rejected": {"actor": "owner", "command": "aegis team qualify host KIND --report PATH --record"},
    "report_malformed": {"actor": "owner", "command": "aegis team qualify host KIND --report PATH --record"},
    "report_unreadable": {"actor": "owner", "command": "aegis team qualify host KIND --report PATH --record"},
    "report_missing": {"actor": "owner", "command": "aegis team qualify host KIND --report PATH --record"},
    "state_unavailable": {"actor": "owner", "command": "aegis team qualify host KIND"},
    "invalid_usage": {"actor": "owner", "command": "aegis team qualify host KIND"},
    "unqualified": {"actor": "owner", "command": "aegis team qualify host KIND --report PATH --record"},
}


class HostUnqualified(ValueError):
    """One gate refusal. The message and next action never include caller input."""

    def __init__(self):
        super().__init__(REFUSALS["unqualified"])
        self.code = "unqualified"
        self.next_action = dict(NEXT_ACTIONS["unqualified"])


def descriptor_supported():
    return confined_supported()


def default_state_root():
    layout = UserLayout.current()
    if layout is None:
        return None
    return str(layout.aegis_dir)


def probe_runner_ids():
    """Host ids with a declared report producer and an active catalog entry."""
    return tuple(spec.id for spec in hosts.HOSTS if spec.team_report_producer and not spec.retired)


def record_relative(host_id):
    """Storage parts under the user state root, or None when the host is unknown."""
    if type(host_id) is not str:
        return None
    try:
        resolved = hosts.resolve(host_id)
    except KeyError:
        return None
    if not _component(resolved):
        return None
    return (_RECORD_DIR, resolved + ".json")


def text_report(report):
    """Closed-token rendering. Untrusted paths, claims and failure text are omitted."""
    if type(report) is not dict or _over_render_bound(report):
        return "refused\n"
    summary = report.get("summary")
    passed = type(summary) is dict and summary.get("passed") is True
    state = report.get("state")
    if state not in ("completed", "interrupted", "refused"):
        state = "other"
    roles = report.get("roles")
    count = len(roles) if type(roles) is list else 0
    fake = "yes" if _marked_fake(report) else "no"
    verdict = "PASSED" if passed else "NOT PASSED"
    return "probe %s\nfake %s\nstate %s\nroles %d\n" % (verdict, fake, state, count)


def show_report(probe_root):
    """Read probe_root/report.json. Exit 0 passed, 3 not passed, 2 refused."""
    parts = _absolute_parts(probe_root)
    if parts is None:
        return 2, _show_refusal()
    loaded = _read_confined(("/", parts + ("report.json",)), MAX_REPORT_BYTES, report=True)
    if loaded[0] is not None:
        return 2, _show_refusal()
    try:
        report = _parse(loaded[1], MAX_REPORT_BYTES)
    except ValueError:
        return 2, _show_refusal()
    if type(report) is not dict or report.get("schema") != REPORT_SCHEMA or _over_render_bound(report):
        return 2, _show_refusal()
    summary = report.get("summary")
    if type(summary) is not dict or type(summary.get("passed")) is not bool:
        return 2, _show_refusal()
    passed = summary.get("passed") is True
    state = report.get("state")
    if state not in ("completed", "interrupted", "refused"):
        state = "other"
    info = {"schema": REPORT_SCHEMA, "passed": passed, "state": state,
            "fake": _marked_fake(report)}
    return (0 if passed else 3), info


def status(state_root, host, *, version_reader, workspace=None):
    prepared = _prepare(state_root, host, workspace)
    if prepared[1] is not None:
        return prepared[1]
    resolved, relative = prepared[0]
    loaded = _read_confined((state_root, relative), MAX_RECORD_BYTES, report=False)
    if loaded[0] is not None:
        return _result(_class(loaded[0]), loaded[0], resolved)
    accepted = _accept_stored(loaded[1], resolved)
    if accepted[0] is not None:
        return _result(_class(accepted[0]), accepted[0], resolved)
    checked = _matches_reader(version_reader, accepted[1]["host_version"])
    if checked is not None:
        return _result(_class(checked), checked, resolved)
    return _result("unqualified", "receipt_current", resolved, accepted[1])


def record(state_root, host, report_bytes, *, version_reader, workspace=None, clock=None):
    prepared = _prepare(state_root, host, workspace)
    if prepared[1] is not None:
        return prepared[1]
    resolved, relative = prepared[0]
    accepted = _accept_report(report_bytes, resolved)
    if accepted[0] is not None:
        return _result(_class(accepted[0]), accepted[0], resolved)
    version = _version_for_record(version_reader, accepted[1])
    if version[0] is not None:
        return _result(_class(version[0]), version[0], resolved)
    stamped = _clock_stamp(clock)
    if stamped is None:
        return _result("refused", "state_unavailable", resolved)
    payload = _payload(resolved, accepted[1], report_bytes, version[1], version[2], stamped)
    if payload is None:
        return _result("refused", "record_invalid", resolved)
    published = _publish(state_root, relative, payload[0], resolved, version[1])
    if published is not None:
        return _result(_class(published), published, resolved)
    return _result("unqualified", "receipt_recorded", resolved, payload[1])


def record_file(state_root, host, report_path, *, version_reader, workspace=None, clock=None):
    prepared = _prepare(state_root, host, workspace)
    if prepared[1] is not None:
        return prepared[1]
    parts = _absolute_parts(report_path)
    if parts is None:
        return _result("refused", "report_unreadable", prepared[0][0])
    loaded = _read_confined(("/", parts), MAX_REPORT_BYTES, report=True)
    if loaded[0] is not None:
        return _result("refused", loaded[0], prepared[0][0])
    return record(state_root, host, loaded[1], version_reader=version_reader, workspace=workspace, clock=clock)


def require_qualified(state_root, host, *, version_reader, workspace=None):
    """Authorization is deferred. Keep the existing caller signature and refusal."""
    raise HostUnqualified()


def _result(kind, reason, host, record=None):
    body = {"status": kind, "reason": reason, "host": host, "next_action": dict(NEXT_ACTIONS[reason])}
    if record is not None and reason in ("receipt_recorded", "receipt_current"):
        body["record"] = record
    return body


def _class(reason):
    if reason in _UNQUALIFIED:
        return "unqualified"
    return "refused"


def _component(name):
    if type(name) is not str or not 1 <= len(name) <= 64:
        return False
    if name in (".", ".."):
        return False
    return not any(char in name for char in "/\\\x00")


def _marked_fake(report):
    seen = 0
    for value in report.values():
        seen += 1
        if seen > 64:
            return False
        if type(value) is dict and value.get("fake") is True:
            return True
    return False


def _over_render_bound(report):
    """True when a render would have to skip a top-level value or a role past the bound."""
    if len(report) > 64:
        return True
    roles = report.get("roles")
    return type(roles) is list and len(roles) > 64


def _record_overlaps_workspace(state_root, workspace, resolved):
    """Refuse when the state root or the record lies in the workspace, or the workspace lies in the record directory.

    An unresolvable path counts as inside. A non-path does too, and is not passed to is_within.
    """
    if workspace is None:
        return False
    if (not isinstance(state_root, (str, os.PathLike))
            or not isinstance(workspace, (str, os.PathLike))):
        return True
    if is_within(state_root, workspace, unresolvable=True):
        return True
    if not _component(resolved):
        return True
    root = os.fspath(state_root)
    place = os.fspath(workspace)
    record_dir = os.path.join(root, _RECORD_DIR)
    leaf = os.path.join(record_dir, resolved + ".json")
    if is_within(leaf, place, unresolvable=True):
        return True
    return is_within(place, record_dir, unresolvable=True)


def _show_refusal():
    return {"schema": REPORT_SCHEMA, "state": "refused"}


def _resolved(host):
    if type(host) is not str or not 1 <= len(host) <= 128:
        return None
    if any(char in host for char in "\x00\n\r"):
        return None
    try:
        return hosts.resolve(host)
    except KeyError:
        return None


def _root_reason(state_root):
    if type(state_root) is not str or not 1 <= len(state_root) <= 32768 or "\x00" in state_root:
        return "state_unavailable"
    if not os.path.isabs(state_root):
        return "state_unavailable"
    try:
        info = os.lstat(state_root)
    except FileNotFoundError:
        return "state_unavailable"
    except OSError:
        return "record_unsafe"
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        return "record_unsafe"
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
        return "record_unsafe"
    return None


def _prepare(state_root, host, workspace):
    if not descriptor_supported():
        return None, _result("refused", "unsupported_platform", None)
    resolved = _resolved(host)
    if resolved is None:
        return None, _result("refused", "unknown_host", None)
    if resolved not in probe_runner_ids():
        return None, _result("unqualified", "no_probe_runner", resolved)
    if _record_overlaps_workspace(state_root, workspace, resolved):
        return None, _result("refused", "record_inside_workspace", resolved)
    reason = _root_reason(state_root)
    if reason is not None:
        return None, _result("refused", reason, resolved)
    relative = record_relative(resolved)
    if relative is None:
        return None, _result("refused", "record_unsafe", resolved)
    return (resolved, relative), None


def _parse(raw, limit):
    if type(raw) is not bytes or len(raw) > limit:
        raise ValueError("size")
    try:
        text = json_preflight(raw, max_bytes=limit, max_depth=_MAX_DEPTH, max_nodes=_MAX_NODES,
                              max_items=_MAX_ITEMS, max_string=_MAX_STRING, max_atom=64)
        return strict_loads(text)
    except (ValueError, RecursionError, UnicodeError):
        raise ValueError("invalid") from None


def _absolute_parts(path):
    if type(path) is not str or not 1 <= len(path) <= 4096 or "\x00" in path or "\\" in path:
        return None
    if not path.startswith("/") or path.startswith("//"):
        return None
    parts = path.split("/")[1:]
    if not parts or any(part in ("", ".", "..") or len(part) > 255 for part in parts):
        return None
    return tuple(parts)


def _read_confined(place, limit, *, report):
    root, parts = place
    try:
        with confined_file(root, parts) as handle:
            if not report:
                custody = _custody(handle, parts[-1])
                if custody is None:
                    return "missing_record", None
                if custody is not True:
                    return "record_unsafe", None
            try:
                return None, handle.read_bytes(limit)
            except ConfinedFileError as error:
                return _confined_reason(error, report=report), None
    except ConfinedFileError as error:
        return _confined_reason(error, report=report), None


def _confined_reason(error, *, report):
    if error.reason == "unsupported":
        return "unsupported_platform"
    if report:
        if error.reason == "missing":
            return "report_missing"
        if error.reason == "too_large":
            return "report_malformed"
        return "report_unreadable"
    if error.reason == "missing":
        return "missing_record"
    if error.reason == "exists":
        return "record_exists"
    if error.reason == "too_large":
        return "record_invalid"
    return "record_unsafe"


def _custody(handle, name):
    """True for a private regular leaf, None when that leaf is absent, False when custody fails."""
    try:
        parent = handle.parent_stat()
    except ConfinedFileError:
        return False
    if parent.st_uid != os.getuid() or not stat.S_ISDIR(parent.st_mode):
        return False
    if stat.S_IMODE(parent.st_mode) & 0o022:
        return False
    try:
        info = os.stat(name, dir_fd=handle.parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        return False
    if info.st_uid == os.getuid() and stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600:
        return True
    return False


def _accept_report(raw, resolved):
    try:
        report = _parse(raw, MAX_REPORT_BYTES)
    except ValueError:
        return "report_malformed", None
    if type(report) is not dict or report.get("schema") != REPORT_SCHEMA:
        return "report_rejected", None
    probe_id = report.get("probe_id")
    if type(probe_id) is not str or _PROBE.fullmatch(probe_id) is None:
        return "report_rejected", None
    spec = hosts.get(resolved)
    if "host" in report and _resolved(report["host"]) != resolved:
        return "report_rejected", None
    roles = accept_report(report, spec.team_report_producer)
    if roles is None:
        return "report_rejected", None
    return None, {"probe_id": probe_id, "roles": roles, "supplied": report.get("host_version", None),
                  "has_version": "host_version" in report}


def _version_text(value):
    if type(value) is not str or not 1 <= len(value) <= 128:
        return "version_unavailable"
    if value.splitlines() != [value]:
        return "version_multiline"
    if value.strip() != value:
        return "version_unavailable"
    if any(ord(char) < 32 or ord(char) == 127 or 0xd800 <= ord(char) <= 0xdfff for char in value):
        return "version_unavailable"
    return None


def _call_reader(reader):
    if not callable(reader):
        return "version_unavailable", None
    try:
        value = reader()
    except (OSError, ValueError, RuntimeError):
        return "version_unavailable", None
    reason = _version_text(value)
    if reason is not None:
        return reason, None
    return None, value


def _version_for_record(reader, info):
    """The reader always answers. A supplied report version must equal it; an omission takes the reader."""
    reason, value = _call_reader(reader)
    if reason is not None:
        return reason, None, None
    if not info["has_version"]:
        return None, value, "reader_at_record"
    supplied = _version_text(info["supplied"])
    if supplied is not None:
        return supplied, None, None
    if info["supplied"] != value:
        return "version_changed", None, None
    return None, value, "report"


def _matches_reader(reader, expected):
    reason, value = _call_reader(reader)
    if reason is not None:
        return reason
    if value != expected:
        return "version_changed"
    return None


def _clock_stamp(clock):
    if clock is None:
        moment = int(time.time())
    elif not callable(clock):
        return None
    else:
        try:
            moment = clock()
        except (OSError, ValueError, RuntimeError):
            return None
    if type(moment) is not int or not 0 <= moment <= _MAX_CLOCK:
        return None
    try:
        return utc_stamp(moment)
    except (OSError, OverflowError, ValueError):
        return None


def _payload(resolved, info, raw, version, source, stamped):
    body = {
        "v": 2,
        "host": resolved,
        "probe_id": info["probe_id"],
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "schema": REPORT_SCHEMA,
        "passed": True,
        "fake": False,
        "enforcement_claim": REPORT_ONLY_CLAIM,
        "recorded_at": stamped,
        "roles": info["roles"],
        "host_version": version,
        "version_source": source,
    }
    if source == "reader_at_record":
        body["version_note"] = VERSION_NOTE
    if not info["roles"]:
        body["root_only"] = True
    try:
        encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        buffer = bytearray()
        for chunk in encoder.iterencode(body):
            if len(chunk) > MAX_RECORD_BYTES - len(buffer):
                return None
            buffer.extend(chunk.encode("ascii"))
        encoded = bytes(buffer)
        if _parse(encoded, MAX_RECORD_BYTES) != body:
            return None
    except (ValueError, UnicodeError):
        return None
    return encoded, body


def _stamp_ok(value):
    if type(value) is not str or _TS.fullmatch(value) is None:
        return False
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value


def _stored_host(stored, resolved):
    if type(stored) is not str:
        return "record_invalid"
    try:
        canonical = hosts.resolve(stored)
    except KeyError:
        return "record_invalid"
    if canonical != resolved:
        return "host_mismatch"
    if stored != resolved:
        return "record_invalid"
    return None


def _accept_stored(raw, resolved):
    try:
        body = _parse(raw, MAX_RECORD_BYTES)
    except ValueError:
        return "record_invalid", None
    if type(body) is not dict:
        return "record_invalid", None
    keys = set(body)
    if body.get("root_only") is True:
        keys.remove("root_only")
    source = body.get("version_source")
    if source == "reader_at_record":
        if keys != _NOTE_KEYS or body.get("version_note") != VERSION_NOTE:
            return "record_invalid", None
    elif source == "report":
        if keys != _BASE_KEYS:
            return "record_invalid", None
    else:
        return "record_invalid", None
    host_reason = _stored_host(body.get("host"), resolved)
    if host_reason is not None:
        return host_reason, None
    if not _stored_shape(body):
        return "record_invalid", None
    return None, body


def _stored_shape(body):
    roles = body.get("roles")
    if (type(body.get("v")) is not int or body["v"] != 2
            or body.get("passed") is not True or body.get("fake") is not False):
        return False
    if body.get("schema") != REPORT_SCHEMA or body.get("enforcement_claim") != REPORT_ONLY_CLAIM:
        return False
    if type(body.get("probe_id")) is not str or _PROBE.fullmatch(body.get("probe_id")) is None:
        return False
    if type(body.get("report_sha256")) is not str or _SHA.fullmatch(body.get("report_sha256")) is None:
        return False
    if not _stamp_ok(body.get("recorded_at")) or _version_text(body.get("host_version")) is not None:
        return False
    if type(roles) is not dict or len(roles) > 64:
        return False
    if body.get("root_only") is True:
        return not roles
    if not roles:
        return False
    for key, provenance in roles.items():
        if not role_retained(key, provenance):
            return False
    return True


def _publish(state_root, relative, payload, resolved, version):
    try:
        with confined_file(state_root, relative, create_parents=True) as handle:
            if not _parent_private(handle):
                return "record_unsafe"
            return _locked_decision(handle, relative[-1], payload, resolved, version)
    except ConfinedFileError as error:
        return _confined_reason(error, report=False)


def _lock_name(leaf):
    """Stable basename beside one receipt leaf, or None when that leaf is not one component."""
    if type(leaf) is not str or not leaf.endswith(".json") or len(leaf) <= len(".json"):
        return None
    name = leaf[:-len(".json")] + ".lock"
    if not 1 <= len(name) <= 255 or name in (".", "..", ".lock"):
        return None
    if any(char in name for char in "/\\\x00"):
        return None
    return name


def _directory_fd(handle):
    directory = handle.parent_fd
    if type(directory) is not int or directory < 0 or os.name != "posix":
        return None
    return directory


def _lock_timeout():
    timeout = _LOCK_TIMEOUT
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout < 0:
        return None
    return timeout


def _locked_decision(handle, leaf, payload, resolved, version):
    """One per-host lock from custody and version checks through publication and readback."""
    name = _lock_name(leaf)
    directory = _directory_fd(handle)
    timeout = _lock_timeout()
    if name is None or directory is None or timeout is None:
        return "record_unsafe"
    try:
        with file_lock(name, timeout=timeout, dir_fd=directory):
            return _decide(handle, leaf, payload, resolved, version)
    except LockTimeoutError:
        return "record_busy"
    except ConfinedFileError:
        raise
    except PathTraversalError:
        return "record_unsafe"
    except OSError:
        return "record_unsafe"
    except ValueError:
        return "record_unsafe"


def _decide(handle, leaf, payload, resolved, version):
    custody = _custody(handle, leaf)
    if custody is False:
        return "record_unsafe"
    if custody is None:
        return _create_record(handle, leaf, payload)
    return _renew_record(handle, leaf, payload, resolved, version)


def _create_record(handle, name, payload):
    """Exclusive first creation. The caller holds the host lock through readback."""
    try:
        handle.publish_bytes(payload, replace=False, mode=0o600)
    except ConfinedFileError as error:
        if error.reason == "exists":
            return "record_exists"
        return "record_unsafe"
    if _leaf_bytes(handle) != payload or _custody(handle, name) is not True:
        return "record_unsafe"
    return None


def _renew_record(handle, name, payload, resolved, version):
    """Replace only when the stored version differs. The caller holds the host lock."""
    snapshot = handle.read_bytes(MAX_RECORD_BYTES)
    reason, stored = _stored_version(snapshot, resolved)
    if reason is not None:
        return reason
    if stored == version:
        return "record_exists"
    if _leaf_bytes(handle) != snapshot:
        return "record_unsafe"
    try:
        handle.publish_bytes(payload, replace=True, mode=0o600)
    except ConfinedFileError:
        return "record_unsafe"
    if _leaf_bytes(handle) != payload or _custody(handle, name) is not True:
        return "record_unsafe"
    return None


def _leaf_bytes(handle):
    try:
        return handle.read_bytes(MAX_RECORD_BYTES)
    except ConfinedFileError:
        return None


def _stored_version(raw, resolved):
    accepted = _accept_stored(raw, resolved)
    if accepted[0] is not None:
        return accepted[0], None
    return None, accepted[1]["host_version"]


def _parent_private(handle):
    try:
        info = handle.parent_stat()
    except ConfinedFileError:
        return False
    return (info.st_uid == os.getuid() and stat.S_ISDIR(info.st_mode)
            and (stat.S_IMODE(info.st_mode) & 0o022) == 0)
