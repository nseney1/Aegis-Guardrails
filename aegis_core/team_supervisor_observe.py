"""Explicit, bounded supervisor observations; never changes policy or state.

Git reads use the central gitsafe transport. No component is started and no
observation writes state. Workspace descriptors are borrowed from confined
storage for the complete observation; executable resolution stays in transport.
Lease declarations never prove actor liveness (SUPERVISOR-WRITER-LIVENESS).
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path

from aegis_core import (
    gitsafe, storage_confined, team, team_hosts, team_profile, team_queue, team_writer_binding,
)
from aegis_core.primitives import sanitize_display
from aegis_core.redaction import redact_command_secrets

__all__ = ["SCHEMA", "MAX_LEASES", "MAX_FINDINGS", "descriptor_supported", "disk_supported", "observe"]

SCHEMA = "aegis.team.supervisor.observations/v1"
MAX_LEASES = 256
MAX_FINDINGS = 8 * team_queue.MAX_ITEMS
_ANCHOR = ("supervisor-observation",)
_REFUSALS = {
    "invalid_clock": "invalid observation clock",
    "invalid_profile": "invalid resolved observation profile",
}


def descriptor_supported():
    """The workspace must support the existing no-follow storage boundary."""
    return storage_confined.descriptor_supported()


def disk_supported():
    """statvfs must accept a held descriptor; no pathname fallback is used."""
    return os.name == "posix" and callable(getattr(os, "statvfs", None))


def _unknown(reason):
    return {"state": "unknown", "reason": reason}


def _writer(leases):
    return {"state": "unknown", "reason": "no_bound_liveness_source", "leases": leases}


def _refused(code):
    return {"schema": SCHEMA, "status": "refused", "code": code, "reason": _REFUSALS[code],
            "starts_nothing": True, "writes_nothing": True}


def _root(value):
    spelling = str(value) if isinstance(value, Path) else value
    if (type(spelling) is not str or not 0 < len(spelling) <= 32768
            or any(c in spelling for c in "\x00\r\n")
            or spelling.count("/") + spelling.count("\\") > 128):
        raise ValueError("workspace_unavailable")
    os.fsencode(spelling)
    path = Path(spelling)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("workspace_unavailable")
    return path


def _identity(info):
    return info.st_dev, info.st_ino


def _same_root(root, identity):
    # No exists/resolve/stat-by-path precheck. Every ancestor is checked by the
    # shared descriptor walker; the synthetic leaf is never opened or created.
    with storage_confined.confined_file(root, _ANCHOR) as current:
        if _identity(current.parent_stat()) != identity:
            raise ValueError("workspace_changed")


def _repository_call(root, identity, operation):
    _same_root(root, identity)
    value = operation(root)
    _same_root(root, identity)
    return value


def _lease_budget(root, identity):
    try:
        # Constant output avoids materializing ref names before checking the
        # count. The command emits at most MAX_LEASES + 1 two-byte records.
        result = _repository_call(root, identity, lambda path: gitsafe.run_checked(
            ["for-each-ref", "--count=" + str(MAX_LEASES + 1), "--format=x", team.LANES_REF + "/"],
            path, timeout=10))
        raw = result.stdout
        if type(raw) is not bytes or len(raw) > 2 * (MAX_LEASES + 1) or len(raw) % 2:
            return "leases_unavailable"
        count = len(raw) // 2
        if raw != b"x\n" * count:
            return "leases_unavailable"
        return "lease_limit" if count > MAX_LEASES else None
    except Exception:
        return "leases_unavailable"


def _disk(parent, floor):
    try:
        if not disk_supported():
            return _unknown("unsupported_platform")
        info = os.statvfs(parent)
        if (type(info.f_bavail) is not int or not 0 <= info.f_bavail < 2**63
                or type(info.f_frsize) is not int or not 0 < info.f_frsize <= 2**30):
            return _unknown("disk_unavailable")
        free = info.f_bavail * info.f_frsize
        return {"state": "healthy" if free >= floor * 1024 * 1024 else "below_floor",
                "free_bytes": free, "floor_mib": floor}
    except Exception:
        return _unknown("disk_unavailable")


def _leases(root, identity, now):
    try:
        found = _repository_call(root, identity, team.read_leases)
        if (not isinstance(found, team.LeaseSet) or type(found.leases) is not tuple
                or type(found.unreadable) is not tuple
                or len(found.leases) + len(found.unreadable) > MAX_LEASES):
            return _unknown("leases_unavailable"), None
        live = expired = 0
        for lease in found.leases:
            if not isinstance(lease, team.Lease):
                return _unknown("leases_unavailable"), None
            if lease.expired(now):
                expired += 1
            else:
                live += 1
        # No labels, paths, OIDs or diagnostics from a lease are displayed.
        summary = {"state": "unknown" if found.unreadable else "known", "live": live,
                   "expired": expired, "unreadable": len(found.unreadable)}
        return summary, found
    except Exception:
        return _unknown("leases_unavailable"), None


def _audit(root, identity, now):
    try:
        result = _repository_call(root, identity, lambda path: team_queue.audit(path, now=now))
        if (type(result) is not dict or len(result) > 16 or result.get("refused") is not False
                or result.get("status") != "done" or type(result.get("exit_code")) is not int
                or result["exit_code"] != 0):
            return _unknown("audit_unavailable")
        findings = result.get("findings")
        items = result.get("items")
        if (type(findings) is not list or len(findings) > MAX_FINDINGS
                or type(items) is not list or len(items) > team_queue.MAX_ITEMS):
            return _unknown("audit_unavailable")
        # Findings are counted, not copied, rendered or trusted as commands.
        return {"state": "findings" if findings else "clean", "findings": len(findings)}
    except Exception:
        return _unknown("audit_unavailable")


def _bound_writer(user_root, summary, found):
    """None keeps today's row. A judge failure stays unknown and keeps the lease counts."""
    if user_root is None or found is None:
        return _writer(summary)
    try:
        row = team_writer_binding.judge(user_root, found, summary)
    except Exception:
        row = None
    reason = row.get("reason") if type(row) is dict else None
    lanes = row.get("lanes") if type(row) is dict else None
    if (type(row) is not dict or row.get("leases") != summary or row.get("state") not in ("unknown", "dead")
            or type(reason) is not str or len(reason) > 80 or any(char in reason for char in "\r\n")
            or ("lanes" in row and (type(lanes) is not list or len(lanes) > MAX_LEASES))):
        fallback = _writer(summary)
        fallback["reason"] = "bindings_unavailable"
        return fallback
    return row


def _workspace_observations(root, now, floor, user_root=None):
    try:
        if not descriptor_supported():
            reason = "unsupported_platform"
            return _unknown(reason), _writer(_unknown(reason)), _unknown(reason)
        root = _root(root)
        with storage_confined.confined_file(root, _ANCHOR) as handle:
            identity = _identity(handle.parent_stat())
            disk = _disk(handle.parent_fd, floor)
            reason = _lease_budget(root, identity)
            if reason is not None:
                writer, audit = _writer(_unknown(reason)), _unknown(reason)
            else:
                summary, found = _leases(root, identity, now)
                writer = _bound_writer(user_root, summary, found)
                audit = _audit(root, identity, now)
        return disk, writer, audit
    except Exception:
        return (_unknown("workspace_unavailable"), _writer(_unknown("workspace_unavailable")),
                _unknown("workspace_unavailable"))


def _host_text(host):
    # Validated profile identifiers are bounded, single-line strings. Keep the
    # same canonicalize -> redact -> truncate ordering as supervisor health.
    canonical = sanitize_display(host, max_len=None)
    return sanitize_display(redact_command_secrets(canonical), max_len=64)


def _host_snapshot(measurement, host):
    row, capacity_state = measurement
    label = _host_text(host)
    unknown = {"host": label, **_unknown("usage_unavailable")}
    measured = {"host": label, "state": "known"} if row["usage_status"] == "known" else dict(unknown)
    if row["usage"]:
        measured.update(source=row["usage_source"], usage=row["usage"])
    limit = unknown if capacity_state == "unknown" else {"host": label, "state": capacity_state}
    return measured, limit


def _hosts(resolved, adapter, now):
    settings = resolved["profile"]["model_settings"]
    try:
        observed_at = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=now)
        service = team_hosts.HostCapacity(resolved, adapter=adapter, now=observed_at)
        rows = service.writer_capacity()
        if (type(rows) is not list or len(rows) > team_profile.MAX_HOSTS
                or len(rows) != len(settings["hosts"])):
            raise ValueError("usage_unavailable")
        usage, capacity = [], []
        for host, row in zip(settings["hosts"], rows):
            try:
                measured, limit = _host_snapshot(row, host)
            except Exception:
                measured = {"host": _host_text(host), **_unknown("usage_unavailable")}
                limit = dict(measured)
            usage.append(measured)
            capacity.append(limit)
        complete = bool(rows) and all(row["state"] == "known" for row in usage)
        capacity_state = "available" if complete else "unknown"
        if any(row["state"] == "at_limit" for row in capacity):
            capacity_state = "at_limit"
        return ({"state": "known" if complete else "unknown", "hosts": usage},
                {"state": capacity_state, "hosts": capacity})
    except Exception:
        return _unknown("usage_unavailable"), _unknown("capacity_unavailable")


def observe(resolved, *, workspace_root, now, usage_adapter=None, user_root=None):
    """Observe once from a validated resolved-profile envelope and trusted root.

    Invalid clocks/profiles return fixed refusals before any probe. Each source
    failure otherwise returns unknown without exception text, while independent
    observations remain visible. No observations are installed into pure health
    or planning, and no pause, lease, queue, profile or supervisor state is saved.
    """
    if type(now) is not int or not 0 <= now <= 4102444800:
        return _refused("invalid_clock")
    try:
        team_profile.validate_resolved(resolved)
        # Validate bounds before copying. Adapters must not be able to change
        # the caller's validated limits while independent sources are read.
        resolved = deepcopy(resolved)
        team_profile.validate_resolved(resolved)
    except Exception:
        return _refused("invalid_profile")
    usage, capacity = _hosts(resolved, usage_adapter, now)
    floor = resolved["profile"]["supervisor"]["health"]["disk_floor_mib"]
    disk, writer, audit = _workspace_observations(workspace_root, now, floor, user_root)
    return {"schema": SCHEMA, "status": "ok", "starts_nothing": True, "writes_nothing": True,
            "observations": {"writer_dead": writer, "disk": disk, "capacity": capacity,
                             "usage": usage, "audit": audit}}
