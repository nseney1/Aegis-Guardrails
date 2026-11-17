"""Owner-home writer identity for one lane claim. Leases are not liveness.

The leaf is ``<passwd home>/.config/aegis/writer-bindings.json``. ``bind`` re-reads
the current lease itself. ``observe`` reads without the lock and never writes.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import re
import stat

from aegis_core import gitsafe, kernel_identity, storage, storage_confined, team
from aegis_core.primitives import json_preflight, sanitize_display
from aegis_core.redaction import redact_command_secrets
from aegis_core.team_supervisor import read_owned_leaf
from aegis_core.workspace.layout import WorkspaceLayout

__all__ = [
    "NAME", "MAX_BYTES", "descriptor_supported", "process_identity", "bind", "load", "judge",
    "BindingLockRefused", "claim_exclusion",
]

NAME = "writer-bindings.json"
MAX_BYTES = 68379
_ANCHOR = ("writer-binding-workspace",)
_CLAIM_LOCK = "aegis-writer.lock"
_RECORD_KEYS = {"boot_id", "claim_id", "gen", "pid", "pid_namespace", "start_ticks"}
_BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_CLAIM = re.compile(r"[0-9a-f]{16}")
_NAMESPACE = re.compile(r"pid:\[[0-9]{1,20}\]")
_BREAKS = re.compile(r"[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]")
_REASONS = {
    "unsupported_platform": "unsupported platform: writer binding unavailable",
    "state_unavailable": "unsafe or unreadable writer binding",
    "state_locked": "writer binding is locked",
    "identity_unavailable": "writer process identity unavailable",
    "identity_ambiguous": "writer binding scope is ambiguous",
    "lease_unavailable": "writer lease is unavailable",
    "invalid_lane": "invalid writer lane",
}
_UNKNOWN_ORDER = ("identity_unavailable", "binding_scope_mismatch",
                  "no_bound_liveness_source", "writer_bound")


class _Refusal(ValueError):
    def __init__(self, code):
        super().__init__(_REASONS[code])
        self.code = code


class BindingLockRefused(ValueError):
    """Fixed state_locked or lease_unavailable failure acquiring claim exclusion."""

    def __init__(self, code):
        super().__init__(_REASONS[code])
        self.code = code


def _git_marker_above(workspace):
    """Prove absence up the bounded root spelling; unsafe probes are uncertain."""
    def present(root, name):
        try:
            with storage_confined.confined_file(root, (name,)) as handle:
                handle.read_bytes(0)
        except storage_confined.ConfinedFileError as error:
            if error.reason == "missing":
                return False
        return True
    for root in (workspace, *workspace.parents):
        if present(root, ".git") or (present(root, "HEAD") and present(root, "objects")):
            return True
    return False


@contextmanager
def claim_exclusion(workspace, *, validated_workspace=False):
    """Serialize bind/unclaim for Git refs shared by every linked worktree.

    Acquire after the workspace lock and retain through the whole mutation.
    The queue passes its validated root; binding callers retain their stricter
    path contract. A Git common directory is independent of workspace depth.
    Outside Git there is no real lease for bind to select or publish against.
    Only acquisition failures are translated; consumer refusals pass unchanged.
    """
    with ExitStack() as stack:
        try:
            if not validated_workspace:
                workspace = _root(workspace)
            common = gitsafe.common_dir(workspace)
            if common is None and _git_marker_above(workspace):
                # Layout discovery also returns None on some Git failures. A
                # marked repository must never bypass its shared exclusion.
                raise _Refusal("lease_unavailable")
            if common is not None:
                spelling = str(common)
                if (len(spelling) > (32768 if validated_workspace else 32740) or
                        (not validated_workspace and spelling.count("/") + spelling.count("\\") > 128)):
                    raise _Refusal("lease_unavailable")
                # common_dir can include a lexical '..' from a Git subdirectory;
                # normalize it without following any filesystem link.
                normalized = os.path.abspath(spelling)
                common = Path(normalized) if validated_workspace else _root(normalized)
                handle = stack.enter_context(storage_confined.confined_file(common, (_CLAIM_LOCK,)))
                stack.enter_context(storage.file_lock(common / _CLAIM_LOCK, timeout=0, dir_fd=handle._parent))
        except storage.LockTimeoutError:
            raise BindingLockRefused("state_locked") from None
        except Exception:
            raise BindingLockRefused("lease_unavailable") from None
        yield


def descriptor_supported():
    """Linux start ticks and no-follow directory descriptors; no PID-file fallback."""
    return kernel_identity.descriptor_supported()


def _refused(code):
    return {"status": "refused", "code": code, "reason": _REASONS[code]}


def _current_uid():
    return os.getuid()


def _confined_file(root, parts):
    return storage_confined.confined_file(root, parts)


def _selected_lease(workspace, lane):
    """The one lane ref. Other lane refs are not listed."""
    oid = gitsafe.read_ref(workspace, team.lane_ref(lane))
    if type(oid) is not str:
        raise _Refusal("lease_unavailable")
    return team.parse_lease(gitsafe.read_object(workspace, oid, team.MAX_LEASE_BYTES), lane, oid)


def _preflight(data):
    # 256 widest records: depth 3, 2051 nodes, 63-byte lane, 20-digit ticks.
    return json_preflight(data, max_bytes=MAX_BYTES, max_depth=3, max_nodes=4096,
                          max_items=256, max_string=63, string_units="escaped", max_atom=20)


def _json_loads(text):
    return json.loads(text, object_pairs_hook=_pairs)


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if type(key) is not str or key in value:
            raise _Refusal("state_unavailable")
        value[key] = item
    return value


def _root(value):
    if isinstance(value, Path):
        spelling = str(value)
    elif type(value) is str:
        spelling = value
    else:
        raise _Refusal("state_unavailable")
    if (not 1 <= len(spelling) <= 32740 or any(char in spelling for char in "\x00\r\n")
            or spelling.count("/") + spelling.count("\\") > 128):
        raise _Refusal("state_unavailable")
    try:
        os.fsencode(spelling)
        path = Path(spelling)
    except (OSError, ValueError, UnicodeError):
        raise _Refusal("state_unavailable") from None
    if not path.is_absolute() or ".." in path.parts:
        raise _Refusal("state_unavailable")
    return path


def _owned(info):
    return info.st_uid == _current_uid() and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def _identity(info):
    return info.st_dev, info.st_ino


def _record_ok(record):
    if type(record) is not dict or set(record) != _RECORD_KEYS:
        return False
    boot, claim, gen = record["boot_id"], record["claim_id"], record["gen"]
    pid, namespace, ticks = record["pid"], record["pid_namespace"], record["start_ticks"]
    return (type(boot) is str and _BOOT.fullmatch(boot) is not None
            and type(claim) is str and _CLAIM.fullmatch(claim) is not None
            and type(gen) is int and 1 <= gen <= 2 ** 53
            and type(pid) is int and 1 <= pid <= 2147483647
            and type(namespace) is str and len(namespace) <= 26 and _NAMESPACE.fullmatch(namespace) is not None
            and type(ticks) is int and 0 <= ticks < 10 ** 20)


def _schema(value):
    if (type(value) is not dict or set(value) != {"version", "bindings"}
            or type(value["version"]) is not int or value["version"] != 1
            or type(value["bindings"]) is not dict or len(value["bindings"]) > 256):
        raise _Refusal("state_unavailable")
    records = {}
    for lane, record in value["bindings"].items():
        if not team.valid_lane(lane) or not _record_ok(record):
            raise _Refusal("state_unavailable")
        records[lane] = {key: record[key] for key in _RECORD_KEYS}
    return records


def _decode(data):
    """Refuse before parsing when the byte cap is already exceeded."""
    if type(data) is not bytes or len(data) > MAX_BYTES:
        raise _Refusal("state_unavailable")
    try:
        value = _json_loads(_preflight(data))
    except _Refusal:
        raise
    except Exception:
        raise _Refusal("state_unavailable") from None
    return _schema(value)


def _read_map(directory):
    try:
        data = read_owned_leaf(directory, NAME, MAX_BYTES)
    except _Refusal:
        raise
    except Exception:
        raise _Refusal("state_unavailable") from None
    return {} if data is None else _decode(data)


def _dump(records):
    data = (json.dumps({"version": 1, "bindings": records}, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > MAX_BYTES:
        raise _Refusal("state_unavailable")
    return data


def _publish_leaf(directory, data):
    if type(data) is not bytes or len(data) > MAX_BYTES:
        raise _Refusal("state_unavailable")
    storage_confined.ConfinedFile(directory, NAME).publish_bytes(data, replace=True, mode=0o600)


@contextmanager
def _directory(home):
    try:
        with _confined_file(home, (".config", "aegis", NAME)) as handle:
            info = handle.parent_stat()
            if not stat.S_ISDIR(info.st_mode) or not _owned(info):
                raise _Refusal("state_unavailable")
            yield handle._parent
    except _Refusal:
        raise
    except Exception:
        raise _Refusal("state_unavailable") from None


@contextmanager
def _locked(directory):
    try:
        with kernel_identity.owner_directory_lock(directory):
            yield
    except kernel_identity.IdentityError as error:
        code = "state_locked" if error.reason == "locked" else "state_unavailable"
        raise _Refusal(code) from None


def process_identity(pid):
    """Kernel identity for one pid, retaining the binding refusal contract."""
    if not descriptor_supported():
        raise _Refusal("unsupported_platform")
    try:
        return kernel_identity.process_identity(pid, confined_file=_confined_file)
    except kernel_identity.IdentityError as error:
        code = "unsupported_platform" if error.reason == "unsupported" else "identity_unavailable"
        raise _Refusal(code) from None


def _scope():
    try:
        return kernel_identity.scope(confined_file=_confined_file, readlink=os.readlink)
    except kernel_identity.IdentityError:
        raise _Refusal("identity_unavailable") from None


def _lease_for(workspace, lane):
    try:
        with _confined_file(workspace, _ANCHOR) as handle:
            identity = _identity(handle.parent_stat())
            chosen = _selected_lease(workspace, lane)
            with _confined_file(workspace, _ANCHOR) as again:
                if _identity(again.parent_stat()) != identity:
                    raise _Refusal("lease_unavailable")
    except _Refusal:
        raise
    except Exception:
        raise _Refusal("lease_unavailable") from None
    if not isinstance(chosen, team.Lease):
        raise _Refusal("lease_unavailable")
    return chosen


def _decision(stored, record):
    """Return keep or publish. A different live pid in this scope is ambiguous."""
    if stored is None:
        return "publish"
    same_scope = stored["boot_id"] == record["boot_id"] and stored["pid_namespace"] == record["pid_namespace"]
    if not same_scope:
        return "publish"
    if stored["pid"] == record["pid"] and stored["start_ticks"] == record["start_ticks"]:
        same_claim = stored["claim_id"] == record["claim_id"] and stored["gen"] == record["gen"]
        return "keep" if same_claim else "publish"
    live = process_identity(stored["pid"])
    if live == {"pid": stored["pid"], "start_ticks": stored["start_ticks"]}:
        raise _Refusal("identity_ambiguous")
    if live is None or type(live) is dict:
        return "publish"
    raise _Refusal("identity_unavailable")


def _bind_locked(directory, workspace, lane, pid):
    current = _read_map(directory)
    identity = process_identity(pid)
    if identity is None:
        raise _Refusal("identity_unavailable")
    scope = _scope()
    chosen = _lease_for(workspace, lane)
    if _scope() != scope:
        raise _Refusal("identity_unavailable")
    record = {
        **scope, **identity, "claim_id": chosen.claim_id, "gen": chosen.gen,
    }
    if _decision(current.get(lane), record) == "keep":
        return {"status": "ok"}
    updated = dict(current)
    updated[lane] = record
    if len(updated) > 256:
        raise _Refusal("state_unavailable")
    _publish_leaf(directory, _dump(updated))
    return {"status": "ok"}


@contextmanager
def _workspace_locked(workspace):
    """Share unclaim's lock inode, opened through a held directory descriptor."""
    with ExitStack() as stack:
        try:
            target = WorkspaceLayout(workspace).lock_file
            handle = stack.enter_context(storage_confined.confined_file(
                workspace, target.relative_to(workspace).parts, create_parents=True))
            stack.enter_context(storage.file_lock(target, timeout=0, dir_fd=handle._parent))
        except storage.LockTimeoutError:
            raise _Refusal("state_locked") from None
        except Exception:
            raise _Refusal("lease_unavailable") from None
        yield


def bind(user_root, workspace_root, lane, pid):
    """Store this pid for the lane's current lease. The caller does not pass the triple."""
    try:
        if not descriptor_supported():
            return _refused("unsupported_platform")
        if not team.valid_lane(lane):
            return _refused("invalid_lane")
        if type(pid) is not int or not 1 <= pid <= 2147483647:
            return _refused("identity_unavailable")
        home, workspace = _root(user_root), _root(workspace_root)
        # Workspace first, then owner directory: selection and publication must
        # not straddle unclaim's judgement, release, or final queue publication.
        with _workspace_locked(workspace), claim_exclusion(workspace), _directory(home) as directory:
            with _locked(directory):
                return _bind_locked(directory, workspace, lane, pid)
    except (_Refusal, BindingLockRefused) as error:
        return _refused(error.code)
    except Exception:
        return _refused("state_unavailable")


def load(user_root):
    """Read the binding map. A missing file is empty. This does not lock or write."""
    if not descriptor_supported():
        raise _Refusal("unsupported_platform")
    with _directory(_root(user_root)) as directory:
        return _read_map(directory)


def _judge_one(records, scope, lease):
    record = records.get(lease.lane) if type(lease.lane) is str else None
    if record is None or record.get("claim_id") != lease.claim_id or record.get("gen") != lease.gen:
        return "unknown", "no_bound_liveness_source"
    if scope is None:
        return "unknown", "identity_unavailable"
    if record["boot_id"] != scope["boot_id"] or record["pid_namespace"] != scope["pid_namespace"]:
        return "unknown", "binding_scope_mismatch"
    try:
        witness = process_identity(os.getpid())
    except _Refusal:
        return "unknown", "identity_unavailable"
    if type(witness) is not dict or witness.get("pid") != os.getpid():
        return "unknown", "identity_unavailable"
    try:
        live = process_identity(record["pid"])
    except _Refusal:
        return "unknown", "identity_unavailable"
    if live is None:
        return "dead", "writer_absent"
    if (type(live) is not dict or live.get("pid") != record["pid"]
            or live.get("start_ticks") != record["start_ticks"]):
        return "dead", "writer_replaced"
    return "unknown", "writer_bound"


def _lane_text(lane):
    # A line break is refused before sanitize can strip it and join the sides.
    if type(lane) is not str or _BREAKS.search(lane) is not None:
        return None
    canonical = sanitize_display(lane, max_len=None)
    if type(canonical) is not str or _BREAKS.search(canonical) is not None:
        return None
    shown = sanitize_display(redact_command_secrets(canonical), max_len=63)
    if type(shown) is not str or _BREAKS.search(shown) is not None:
        return None
    return shown


def _top(rows, unreadable):
    visible = [{"lane": shown, "state": state, "reason": reason}
               for state, reason, shown in rows if shown is not None]
    if unreadable:
        return "unknown", "unreadable_lease", visible
    if not rows or not all(state == "dead" for state, reason, shown in rows):
        for reason in _UNKNOWN_ORDER:
            if any(item == reason for state, item, shown in rows):
                return "unknown", reason, visible
        return "unknown", "no_bound_liveness_source", visible
    reason = "writer_absent" if any(item == "writer_absent" for state, item, shown in rows) else "writer_replaced"
    return "dead", reason, visible


def _assemble(records, found, summary):
    try:
        scope = _scope()
    except _Refusal:
        scope = None
    rows = []
    ordered = sorted(found.leases, key=lambda item: item.lane if type(getattr(item, "lane", None)) is str else "")
    for lease in ordered:
        if not isinstance(lease, team.Lease):
            raise _Refusal("state_unavailable")
        state, reason = _judge_one(records, scope, lease)
        rows.append((state, reason, _lane_text(lease.lane)))
    state, reason, lanes = _top(rows, bool(found.unreadable))
    return {"state": state, "reason": reason, "leases": summary, "lanes": lanes}


def _unavailable(summary):
    return {"state": "unknown", "reason": "bindings_unavailable", "leases": summary}


def judge(user_root, found, summary):
    """Judge current leases against the binding file. Never writes and never raises."""
    try:
        if (type(summary) is not dict or not isinstance(found, team.LeaseSet)
                or type(found.leases) is not tuple or type(found.unreadable) is not tuple
                or len(found.leases) + len(found.unreadable) > 256 or not descriptor_supported()):
            return _unavailable(summary if type(summary) is dict else {})
        return _assemble(load(user_root), found, summary)
    except Exception:
        return _unavailable(summary if type(summary) is dict else {})
