"""Host-local enrollment capabilities, effect fences and protected readers.

The binding and invocation classes late-bind through team_native_keys. The
binding supplies the process check, external proof, canonical API and H lock.
Only a current, registered owner can use the local fences, and the canonical
writer retains its own exclusion and publication contract.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import sys
import threading
import time
import weakref
from contextlib import ExitStack, suppress
from pathlib import Path
from types import MappingProxyType

from aegis_core import kernel_identity, storage_confined
from aegis_core.primitives import json_preflight, strict_loads
from aegis_core.team_native_keys import (
    BOUND_INITIAL_KEY, GUARD_KEY, NATIVE_IDENTITIES as native_identities, RESERVATION_KEY,
)
from aegis_core.team_native_wire import (
    HostAuthorityError, MAX_DEPTH, MAX_FRAME_BYTES, MAX_WAIT_SECONDS,
)

__all__ = [
    "BoundInitialEnrollment", "ControlIO", "DecisionGuard", "HostAuthority", "HostAuthorityError",
    "InitialCreationGuard", "ReservedEnrollment", "ReservedGenesisGuard",
    "CONTROL_ERRORS", "CONTROL_SCHEMA", "LIVE_ERRORS", "LIVE_METHODS", "LIVE_SCHEMA", "ROLES",
    "decision_tool", "descriptor_supported", "digest", "fields", "json_bytes", "process_identity",
    "protected_bytes", "protected_path", "require", "same_data", "sha", "uint",
]

CONTROL_SCHEMA = "aegis.protected-initial-control/v1"
LIVE_SCHEMA = "aegis.protected-live-control/v1"
ROLES = frozenset({"root", "router", "coordinator", "operator", "reviewer"})
LIVE_ERRORS = MappingProxyType({
    "CONTROL_INVALID": "HOST_PROTOCOL_ERROR", "CONTROL_STALE": "STALE_INVOCATION",
    "DEADLINE_EXPIRED": "HOST_PROTOCOL_TIMEOUT", "PLAN_MISMATCH": "HOST_PROFILE_UNQUALIFIED",
    "RESERVATION_INVALID": "CANONICAL_CORRELATION_MISMATCH",
    "INITIAL_CORRELATION_MISMATCH": "CANONICAL_CORRELATION_MISMATCH",
    "ATTEMPT_ALREADY_BOUND": "HOST_CALL_CONFLICT", "START_ALREADY_ISSUED": "HOST_CALL_CONFLICT",
    "START_UNKNOWN": "PROVIDER_OUTCOME_UNKNOWN", "LIVE_NOT_ENROLLED": "STALE_INVOCATION",
    "CALL_NOT_PENDING": "STALE_INVOCATION", "CALL_CORRELATION_MISMATCH": "CANONICAL_CORRELATION_MISMATCH",
    "PERMISSION_PROFILE_MISMATCH": "HOST_PROFILE_UNQUALIFIED",
    "TOOL_FORBIDDEN": "ROLE_OPERATION_FORBIDDEN", "PUBLICATION_PENDING": "PROVIDER_OUTCOME_UNKNOWN",
})
LIVE_METHODS = ("describe", "reserve_initial", "bind_initial", "start_initial",
                "describe_live", "enroll_live", "pending_call", "retire_call")
CONTROL_ERRORS = frozenset({
    "CONTROL_INVALID", "CONTROL_STALE", "DEADLINE_EXPIRED", "PLAN_MISMATCH",
    "RESERVATION_INVALID", "INITIAL_CORRELATION_MISMATCH", "ATTEMPT_ALREADY_BOUND",
    "START_ALREADY_ISSUED", "START_UNKNOWN",
})
_UNPROTECTED = "unprotected host deployment"
_INVALID_FRAME = "invalid host protocol frame"
_CORRELATION = "CANONICAL_CORRELATION_MISMATCH"
_MAX_PROTECTED_BYTES = 64 * MAX_FRAME_BYTES
_PROC_STAT_MAX_BYTES = 4096
_ACLS = frozenset({"system.posix_acl_access", "system.posix_acl_default"})


def decision_tool():
    return [{"namespace": "functions", "name": "aegis_decision"}]


def digest(value, *, code="UNPROTECTED_DEPLOYMENT", reason=_UNPROTECTED):
    """Hash the legacy JSON encoding. Readers enforce input size and depth."""
    _check_digest_keys(value, code, reason)

    def reject_value(_value):
        raise HostAuthorityError(code, reason)

    raw = None
    with suppress(TypeError, ValueError, RecursionError):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False, default=reject_value).encode()
    require(raw is not None, code, reason)
    return hashlib.sha256(raw).hexdigest()


def _check_digest_keys(value, code, reason):
    """Refuse unsupported or incomparable object keys before encoder sorting."""
    end = object()
    pending = [iter((value,))]
    seen = set()
    while pending:
        item = next(pending[-1], end)
        if item is end:
            pending.pop()
        elif isinstance(item, (dict, list, tuple)) and id(item) not in seen:
            seen.add(id(item))
            if isinstance(item, dict):
                first = next(iter(item), None)
                if first is None:
                    require(len(item) <= 1, code, reason)
                else:
                    family = str if isinstance(first, str) else (int, float)
                    require(all(isinstance(key, family) for key in item), code, reason)
                pending.append(iter(item.values()))
            else:
                pending.append(iter(item))


def require(value, code="UNPROTECTED_DEPLOYMENT", reason=_UNPROTECTED):
    if not value:
        raise HostAuthorityError(code, reason)


def fields(value, names, code="UNPROTECTED_DEPLOYMENT"):
    require(type(value) is dict and value.keys() == names, code)


def uint(value, maximum=(1 << 64) - 1):
    return type(value) is int and 0 < value <= maximum


def sha(value):
    return (type(value) is str and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


def same_data(value, expected):
    if type(value) is not type(expected):
        return False
    if type(expected) is dict:
        return value.keys() == expected.keys() and all(
            same_data(value[key], item) for key, item in expected.items())
    if type(expected) is list:
        return len(value) == len(expected) and all(
            same_data(a, b) for a, b in zip(value, expected))
    return value == expected


def json_bytes(raw):
    """Parse bounded protected JSON, including pretty-printed documents."""
    require(type(raw) is bytes and len(raw) <= MAX_FRAME_BYTES)
    try:
        checked = json_preflight(
            raw, max_bytes=MAX_FRAME_BYTES, max_depth=MAX_DEPTH + 1,
            max_nodes=MAX_FRAME_BYTES, max_items=MAX_FRAME_BYTES,
            max_string=MAX_FRAME_BYTES,
        )
    except ValueError as error:
        if str(error) == "nesting":
            raise HostAuthorityError("HOST_PROTOCOL_ERROR", _INVALID_FRAME) from None
        raise HostAuthorityError("UNPROTECTED_DEPLOYMENT", _UNPROTECTED) from None
    _check_json_boundary(checked)
    try:
        return strict_loads(checked)
    except (json.JSONDecodeError, RecursionError):
        raise HostAuthorityError("UNPROTECTED_DEPLOYMENT", _UNPROTECTED) from None
    except ValueError:
        raise HostAuthorityError("HOST_PROTOCOL_ERROR", _INVALID_FRAME) from None


def _check_json_boundary(text):
    """At legacy value depth 32, a container may be present only if empty."""
    depth = 0
    quoted = escaped = False
    for index, char in enumerate(text):
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth == MAX_DEPTH + 1:
                close = "]" if char == "[" else "}"
                next_char = index + 1
                while next_char < len(text) and text[next_char] in " \t\r\n":
                    next_char += 1
                require(next_char < len(text) and text[next_char] == close,
                        "HOST_PROTOCOL_ERROR", _INVALID_FRAME)
        elif char in "]}":
            depth -= 1


def _node(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _identity(info):
    return (*_node(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def descriptor_supported():
    """Protected reads require Linux, descriptor-relative lookup and fd ACLs."""
    return (sys.platform == "linux" and kernel_identity.descriptor_supported()
            and hasattr(os, "O_PATH") and hasattr(os, "listxattr")
            and "readlink" in {operation.__name__ for operation in os.supports_dir_fd}
            and "stat" in {operation.__name__ for operation in os.supports_follow_symlinks})


def _require_descriptors():
    require(descriptor_supported(), "UNSUPPORTED_HOST", "protected control requires Linux")


def _absolute_parts(path):
    if isinstance(path, Path):
        path = str(path)
    require(type(path) is str and 0 < len(path) <= 4096 and "\x00" not in path
            and path.startswith("/") and not path.startswith("//"))
    parts = Path(path).parts[1:]
    require(".." not in parts)
    return parts


def _directory_chain(parts, stack):
    """Hold every directory edge from / until its caller finishes."""
    directory = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    stack.callback(os.close, directory)
    edges = []
    for part in parts:
        child = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=directory)
        stack.callback(os.close, child)
        edges.append((directory, part, child))
        directory = child
    return edges, directory


def _check_metadata(fd, kind, owners, model_uid):
    info = os.fstat(fd)
    require(kind(info.st_mode) and info.st_uid in owners and info.st_uid != model_uid
            and not info.st_mode & 0o022)
    # Linux cannot list attributes directly on O_PATH descriptors.
    # The proc descriptor alias names that held inode, never a supplied path.
    require(not _ACLS.intersection(os.listxattr(f"/proc/self/fd/{fd}")))
    return info


def _verify_directories(edges, directory, owners, model_uid):
    root = edges[0][0] if edges else directory
    _check_metadata(root, stat.S_ISDIR, owners, model_uid)
    for parent, name, child in edges:
        info = _check_metadata(child, stat.S_ISDIR, owners, model_uid)
        require(_node(os.stat(name, dir_fd=parent, follow_symlinks=False)) == _node(info))


def _protected_leaf(stack, directory, name, owners, model_uid, *, socket_path, read_bytes):
    kind = stat.S_ISSOCK if socket_path else stat.S_ISREG
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    require(kind(before.st_mode) and before.st_uid in owners and before.st_uid != model_uid
            and not before.st_mode & 0o022)
    if read_bytes:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=directory)
    else:
        fd = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    stack.callback(os.close, fd)
    info = _check_metadata(fd, kind, owners, model_uid)
    require(_identity(info) == _identity(before))
    return fd, info


def _read_bytes(fd, size, maximum):
    first = os.read(fd, size) if size else b""
    if size and not first:
        return first  # A read with a positive count already found EOF.
    probe = os.read(fd, 1)
    if not probe:
        return first

    # Short reads and files whose contents exceed their reported size still
    # use bounded chunks when the probe finds more data.
    length = len(first) + len(probe)
    require(length <= maximum)
    chunks = [first, probe]
    while True:
        chunk = os.read(fd, min(65536, maximum + 1 - length))
        if not chunk:
            return b"".join(chunks)
        length += len(chunk)
        require(length <= maximum)
        chunks.append(chunk)


def _inspect_protected(path, owners, model_uid, *, directory, socket_path, maximum=None):
    _require_descriptors()
    parts = _absolute_parts(path)
    require(not (directory and socket_path) and (directory or parts))
    require(type(owners) in (set, frozenset) and type(model_uid) is int)
    try:
        with ExitStack() as stack:
            edges, parent = _directory_chain(parts if directory else parts[:-1], stack)
            _verify_directories(edges, parent, owners, model_uid)
            if directory:
                return os.fstat(parent)
            fd, opened = _protected_leaf(stack, parent, parts[-1], owners, model_uid,
                                         socket_path=socket_path, read_bytes=maximum is not None)
            raw = None
            if maximum is not None:
                require(0 <= opened.st_size <= maximum)
                raw = _read_bytes(fd, opened.st_size, maximum)
            _verify_directories(edges, parent, owners, model_uid)
            require(_identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False))
                    == _identity(os.fstat(fd)) == _identity(opened))
            return opened if maximum is None else raw
    except (OSError, ValueError):
        raise HostAuthorityError("UNPROTECTED_DEPLOYMENT", _UNPROTECTED) from None


def protected_path(path, owners, model_uid, *, directory=False, socket_path=False):
    """Verify protection on the named directory, regular file or socket."""
    return _inspect_protected(path, owners, model_uid, directory=directory, socket_path=socket_path)


def protected_bytes(path, owners, model_uid, maximum=MAX_FRAME_BYTES):
    """Read bounded bytes from a held file and verify its named ancestry."""
    require(type(maximum) is int and 0 <= maximum <= _MAX_PROTECTED_BYTES)
    return _inspect_protected(path, owners, model_uid, directory=False, socket_path=False,
                              maximum=maximum)


def _process_namespace_inode(directory):
    target = os.readlink("pid", dir_fd=directory)
    require(7 <= len(target) <= 26 and target.startswith("pid:[") and target.endswith("]"))
    inode = target[5:-1]
    require(inode.isascii() and inode.isdecimal())
    return int(inode)


def _listed_process_ticks(handle, pid):
    raw = handle.read_bytes(_PROC_STAT_MAX_BYTES)
    # The command name may contain spaces or parentheses. Field 22 follows it.
    prefix, separator, tail = raw.rpartition(b") ")
    require(separator and prefix.startswith(f"{pid} (".encode("ascii")))
    fields = tail.split()
    require(len(fields) >= 20 and fields[0] in (b"Z", b"X", b"x")
            and 1 <= len(fields[19]) <= 20 and fields[19].isdigit())
    return int(fields[19])


def _dead_listed_process(pid, edges, namespace):
    # The storage reader holds the stat parent across both reads. Match it
    # to the PID directory already held by the namespace walk.
    with storage_confined.confined_file(Path("/proc"), (str(pid), "stat")) as handle:
        pid_directory = edges[-1][0]
        require(_node(handle.parent_stat()) == _node(os.fstat(pid_directory)))
        ticks = _listed_process_ticks(handle, pid)
        inode = _process_namespace_inode(namespace)
        require(_listed_process_ticks(handle, pid) == ticks)
        for parent, name, child in edges:
            require(_node(os.stat(name, dir_fd=parent, follow_symlinks=False)) == _node(os.fstat(child)))
    return inode, {"pid": pid, "start_ticks": ticks}


def process_identity(pid):
    _require_descriptors()
    require(uint(pid, 2147483647))
    try:
        boot = kernel_identity.boot_id()
        identity = kernel_identity.process_identity(pid)
        with ExitStack() as stack:
            edges, namespace = _directory_chain(("proc", str(pid), "ns"), stack)
            if identity is None:
                inode, identity = _dead_listed_process(pid, edges, namespace)
            else:
                inode = _process_namespace_inode(namespace)
                require(kernel_identity.process_identity(pid) == identity)
            return {"boot_id": boot, "pid_namespace": inode, **identity}
    except (OSError, kernel_identity.IdentityError, storage_confined.ConfinedFileError):
        raise HostAuthorityError("UNPROTECTED_DEPLOYMENT", _UNPROTECTED) from None


class ControlIO:
    """Check package control admission before refusing the borrow."""

    def __init__(self, owner):
        _require_descriptors()
        require(native_identities.is_instance("binding", owner),
                "ROLE_OPERATION_FORBIDDEN", "control requires an owned binding")
        owner.require_owner_process()
        require(not owner.fenced, "STALE_INVOCATION", "runtime binding is closed")
        raise HostAuthorityError("UNPROTECTED_DEPLOYMENT", _UNPROTECTED)


def _mapping(record, name):
    value = record.get(name)
    return value if type(value) is dict else {}


class ReservedEnrollment:
    """An owned reservation snapshot, never constructible from a witness dict."""

    __slots__ = ("_owner", "_witness", "stage", "bind_attempted")

    def __init__(self, key, owner, witness):
        require(type(self) is ReservedEnrollment and key is RESERVATION_KEY
                and native_identities.owns_binding(owner),
                "ROLE_OPERATION_FORBIDDEN", "reservation requires owned runtime")
        owner.require_owner_process()
        fields(witness, {"schema", "actor_cid", "role", "generation", "profile_sha256", "cap_seconds",
                         "channel_instance_sha256", "approved_plan_sha256", "reservation_sequence",
                         "expires_monotonic_ns"}, "CANONICAL_CORRELATION_MISMATCH")
        require(type(witness["actor_cid"]) is str and type(witness["role"]) is str
                and uint(witness["expires_monotonic_ns"]), "CANONICAL_CORRELATION_MISMATCH",
                "reservation conflicts with protected plan")
        digest(witness, code=_CORRELATION, reason="reservation conflicts with protected plan")
        self._owner = weakref.ref(owner)
        self._witness = copy.deepcopy(witness)
        self.stage = "reserved"  # Local issuance lifecycle, not a canonical ledger.
        self.bind_attempted = False

    @property
    def actor_cid(self):
        return self._witness["actor_cid"]

    @property
    def witness(self):
        return copy.deepcopy(self._witness)

    def belongs_to(self, owner):
        return self._owner() is owner

    @property
    def reservation_witness_sha256(self):
        return digest(self._witness)

    @property
    def owned_runtime(self):
        owner = self._owner()
        require(native_identities.owns_binding(owner), "STALE_INVOCATION", "runtime is no longer owned")
        owner.require_owner_process()
        return owner

    def __copy__(self):
        raise TypeError("owned reservations cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("owned reservations cannot be copied")

    def __reduce_ex__(self, protocol):
        raise TypeError("owned reservations cannot be serialized")


class BoundInitialEnrollment:
    """One host-local startup context; never a serialized runtime permit."""

    __slots__ = ("_owner", "reservation", "_initial", "deadline_ns", "epoch", "nonce", "stage")

    def __init__(self, key, owner, reservation, initial, deadline):
        require(type(self) is BoundInitialEnrollment and key is BOUND_INITIAL_KEY
                and native_identities.owns_binding(owner),
                "ROLE_OPERATION_FORBIDDEN", "bound context requires owned runtime")
        owner.require_owner_process()
        require(type(reservation) is ReservedEnrollment and reservation.belongs_to(owner)
                and any(reservation is row for row in owner.reservations),
                "ROLE_OPERATION_FORBIDDEN", "foreign owned reservation")
        require(uint(deadline), "ROLE_OPERATION_FORBIDDEN", "invalid original operation deadline")
        require(type(initial) is dict, _CORRELATION, "original INITIAL envelope changed")
        digest(initial, code=_CORRELATION, reason="original INITIAL envelope changed")
        self._owner, self.reservation = weakref.ref(owner), reservation
        self._initial, self.deadline_ns = copy.deepcopy(initial), deadline
        self.epoch, self.nonce, self.stage = owner.epoch, owner.nonce, "bound"

    @property
    def actor_cid(self):
        return self.reservation.actor_cid

    @property
    def initial(self):
        return copy.deepcopy(self._initial)

    def belongs_to(self, owner):
        return self._owner() is owner

    def __copy__(self):
        raise TypeError("bound initial contexts cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("bound initial contexts cannot be copied")

    def __reduce_ex__(self, protocol):
        raise TypeError("bound initial contexts cannot be serialized")


class HostAuthority:
    """Owned genesis/INITIAL fences, without a model or LIVE effect grant."""

    __slots__ = ("_owner",)

    def __init__(self, owned_runtime):
        require(type(self) is HostAuthority and native_identities.owns_binding(owned_runtime),
                "ROLE_OPERATION_FORBIDDEN", "authority requires owned runtime")
        owned_runtime.require_owner_process()
        self._owner = weakref.ref(owned_runtime)

    @property
    def owned_runtime(self):
        owner = self._owner()
        require(native_identities.owns_binding(owner), "STALE_INVOCATION", "runtime is no longer owned")
        owner.require_owner_process()
        return owner

    @property
    def canonical_root(self):
        return self.owned_runtime.canonical_root

    def bootstrap_fence(self, owned_runtime, approved_plan_ref, reserved_enrollments):
        require(type(self) is HostAuthority and self.owned_runtime is owned_runtime,
                 "ROLE_OPERATION_FORBIDDEN", "foreign host authority")
        return ReservedGenesisGuard(GUARD_KEY, owned_runtime, approved_plan_ref,
                                    reserved_enrollments)

    def initial_creation_fence(self, owned_runtime, approved_plan_ref, reserved_enrollment):
        require(type(self) is HostAuthority and self.owned_runtime is owned_runtime,
                 "ROLE_OPERATION_FORBIDDEN", "foreign host authority")
        return InitialCreationGuard(GUARD_KEY, owned_runtime, approved_plan_ref,
                                    reserved_enrollment)

    def effect_fence(self, invocation, operation):
        owner = self._owner()
        if (native_identities.is_instance("invocation", invocation) and owner is not None
                and invocation.owner is owner and invocation.scope_entered):
            # History wins over currentness: a call whose decision scope ever
            # entered stays unknown, even once it is stale or its owner closed.
            # History never resets, so this unlocked read cannot wrongly refuse;
            # DecisionGuard.__enter__ repeats the check under the lock.
            owner.decision_history_unknown()
        owner = self.owned_runtime
        require(type(self) is HostAuthority and self is owner.authority
                 and type(operation) is str and operation == "decision",
                 "ROLE_OPERATION_FORBIDDEN", "only decision effects are admitted")
        return DecisionGuard(GUARD_KEY, owner, invocation)

    def require_current(self, invocation, policy, state, request):
        owner = self.owned_runtime
        guard = owner.active_guard
        require(type(self) is HostAuthority and self is owner.authority
                 and type(guard) is DecisionGuard,
                 "STALE_INVOCATION", "decision fence is not active")
        return guard.require_current(invocation, policy, state, request)

    def require_decision_command(self, invocation, command):
        """Bind inert command data to this guard's actual received frame."""
        owner = self.owned_runtime
        guard = owner.active_guard
        require(type(self) is HostAuthority and self is owner.authority
                 and type(guard) is DecisionGuard,
                 "STALE_INVOCATION", "decision fence is not active")
        guard._local_current()
        require(invocation is guard._invocation,
                 "ROLE_OPERATION_FORBIDDEN", "foreign pending invocation")
        invocation.require_current()
        require(type(command) is dict and all(type(key) is str for key in command)
                 and command.keys() == {"event_id", "request_id", "request_sha256", "decision", "reason"}
                 and all(type(value) is str for value in command.values())
                 and same_data(command, invocation.arguments),
                 "STALE_INVOCATION", "decision arguments do not match owned call")


class _OwnedGuard:
    """One lexical local fence. External provenance is read before acquiring it."""

    def __init__(self, key, owner, plan_ref, *, deadline_ns=None):
        require(key is GUARD_KEY and native_identities.owns_binding(owner) and owner.policy_data is not None,
                 "ROLE_OPERATION_FORBIDDEN", "guard requires owned runtime")
        owner.require_owner_process()
        require(same_data(plan_ref, owner.plan_data), "CANONICAL_CORRELATION_MISMATCH",
                 "guard plan does not match owned runtime")
        self._owner = owner
        self._plan = copy.deepcopy(owner.plan_data)
        self._policy = copy.deepcopy(owner.policy_data)
        self._channel = copy.deepcopy(owner.channel_data)
        self._epoch, self._nonce = owner.epoch, owner.nonce
        self._entry_lock = threading.Lock()
        self._used, self._active = False, False
        self._thread, self._deadline = None, None
        require(deadline_ns is None or uint(deadline_ns), "ROLE_OPERATION_FORBIDDEN",
                 "invalid original operation deadline")
        self._deadline_limit = deadline_ns

    def __enter__(self):
        self._owner.require_owner_process()
        require(native_identities.owns_binding(self._owner) and not self._owner.closed,
                "STALE_INVOCATION", "host guard is no longer current")
        with self._entry_lock:
            require(not self._used, "ROLE_OPERATION_FORBIDDEN", "guard cannot be reentered")
            active = self._owner.active_guard
            require(active is None or active._thread != threading.get_ident(),
                    "ROLE_OPERATION_FORBIDDEN", "nested host fences are forbidden")
            self._used = True
        self._deadline = time.monotonic_ns() + MAX_WAIT_SECONDS * 1000000000
        if self._deadline_limit is not None:
            self._deadline = min(self._deadline, self._deadline_limit)
        # This is actual OS/runtime/source preflight, outside H/canonical locks.
        try:
            self._owner.prove_current()
        except HostAuthorityError:
            raise
        except (OSError, ValueError):
            raise HostAuthorityError("HOST_PROFILE_UNQUALIFIED",
                                     "host preflight is unavailable") from None
        left = max(0, (self._deadline - time.monotonic_ns()) / 1000000000)
        require(self._owner.lock.acquire(timeout=left), "HOST_PROTOCOL_TIMEOUT",
                 "host fence deadline expired")
        try:
            require(self._owner.active_guard is None, "ROLE_OPERATION_FORBIDDEN",
                     "nested host fences are forbidden")
            self._owner.active_guard = self
            self._thread, self._active = threading.get_ident(), True
            self._local_current()
            self._entry_current()
            return self
        except BaseException:
            self._active = False
            if self._owner.active_guard is self:
                self._owner.active_guard = None
            self._owner.lock.release()
            raise

    def _entry_current(self):
        raise NotImplementedError("a concrete guard purpose is required")

    def _local_current(self):
        owner = self._owner
        owner.require_owner_process()
        require(self._active and self._thread == threading.get_ident()
                 and native_identities.owns_binding(owner) and not owner.closed
                 and owner.active_guard is self and owner.epoch == self._epoch
                 and owner.nonce == self._nonce and time.monotonic_ns() < self._deadline,
                 "STALE_INVOCATION", "host guard is no longer current")
        require(same_data(owner.plan_data, self._plan)
                 and same_data(owner.policy_data, self._policy)
                 and same_data(owner.channel_data, self._channel),
                 "CANONICAL_CORRELATION_MISMATCH", "owned host inputs changed")

    def __exit__(self, exc_type, exc_value, traceback):
        self._owner.require_owner_process()
        require(self._active and self._thread == threading.get_ident(),
                 "ROLE_OPERATION_FORBIDDEN", "foreign guard exit")
        # N1 performs the final current check inside its publication try block.
        # Exit only retires the lexical guard: a later exception here must not
        # relabel an already published INITIAL result as a no-effect refusal.
        self._retire()
        return False

    def _retire(self):
        self._active = False
        self._owner.active_guard = None
        self._owner.lock.release()

    def __copy__(self):
        raise TypeError("host guards cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("host guards cannot be copied")

    def __reduce_ex__(self, protocol):
        raise TypeError("host guards cannot be serialized")


class _EnrollmentGuard(_OwnedGuard):
    def __init__(self, key, owner, plan_ref, *, deadline_ns=None, genesis=False, supplied=None):
        super().__init__(key, owner, plan_ref, deadline_ns=deadline_ns)
        timeout = MAX_WAIT_SECONDS
        if deadline_ns is not None:
            timeout = min(timeout, max(0, (deadline_ns - time.monotonic_ns()) / 1000000000))
        lock = owner.lock
        require(lock.acquire(timeout=timeout), "HOST_PROTOCOL_TIMEOUT", "host fence deadline expired")
        try:
            members = self._live_members()
            for member in members:
                self._require_owned_member(member)
            if genesis:
                require(type(supplied) is tuple and len(supplied) == len(members)
                        and all(row is member for row, member in zip(supplied, members)),
                        "ROLE_OPERATION_FORBIDDEN", "genesis requires the complete owned set")
            self._reservations = tuple((member, member.witness) for member in members)
        finally:
            lock.release()

    def _live_members(self):
        members = self._owner.reservations
        require(type(members) is tuple, "ROLE_OPERATION_FORBIDDEN", "invalid owned reservation set")
        return members

    def _require_owned_member(self, member):
        require(type(member) is ReservedEnrollment and member.belongs_to(self._owner),
                 "ROLE_OPERATION_FORBIDDEN", "foreign owned reservation")

    def _require_reservations_current(self, *, fresh_genesis=False):
        members = self._live_members()
        require(len(members) == len(self._reservations), _CORRELATION, "owned reservation set changed")
        for member, (original, witness) in zip(members, self._reservations):
            self._require_owned_member(member)
            require(member is original, _CORRELATION, "owned reservation set changed")
            require(same_data(member.witness, witness), _CORRELATION, "owned reservation changed")
            if fresh_genesis:
                require(witness["expires_monotonic_ns"] > time.monotonic_ns()
                         and member.stage == "reserved", "STALE_INVOCATION",
                         "genesis reservation is expired or already issued")


class ReservedGenesisGuard(_EnrollmentGuard):
    """Fresh full-set genesis authority, never a receipt-recovery fence."""

    def __init__(self, key, owner, plan_ref, reservations):
        super().__init__(key, owner, plan_ref, genesis=True, supplied=reservations)

    def _entry_current(self):
        self.require_reserved_genesis_current()

    def require_reserved_genesis_current(self):
        self._local_current()
        self._require_reservations_current(fresh_genesis=True)

    def reserved_genesis_rows(self):
        """Return detached witness rows in the order validated by this guard."""
        self.require_reserved_genesis_current()
        return [copy.deepcopy(witness) for _, witness in self._reservations]

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if exc_type is None:
                # N1 owns this complete lexical transaction and maps an exit
                # failure after exclusive root claim to publication UNKNOWN.
                self.require_reserved_genesis_current()
        finally:
            super().__exit__(exc_type, exc_value, traceback)
        return False


class InitialCreationGuard(_EnrollmentGuard):
    """Current owner identity, original receipt recovery, then NEW-only checks."""

    def __init__(self, key, owner, plan_ref, reservation, *, deadline_ns=None):
        super().__init__(key, owner, plan_ref, deadline_ns=deadline_ns)
        self._target = reservation
        self._target_witness = next((witness for member, witness in self._reservations
                                     if member is reservation), None)
        require(self._target_witness is not None, "ROLE_OPERATION_FORBIDDEN", "foreign owned reservation")

    def _entry_current(self):
        self.require_initial_identity_current(self._target)

    def require_initial_identity_current(self, reserved_enrollment):
        self._local_current()
        require(reserved_enrollment is self._target, "ROLE_OPERATION_FORBIDDEN",
                 "guard target does not match owned reservation")
        self._require_reservations_current()

    def _canonical_current(self, reservation, policy, state):
        self.require_initial_identity_current(reservation)
        require(same_data(policy, self._policy) and type(state) is dict,
                 "CANONICAL_CORRELATION_MISMATCH", "canonical policy does not match owned plan")
        bootstrap = state.get("initial_bootstrap")
        fields(bootstrap, {"genesis", "reservations", "creations"},
                "CANONICAL_CORRELATION_MISMATCH")
        fields(bootstrap["genesis"], {"envelope", "receipt"},
                "CANONICAL_CORRELATION_MISMATCH")
        witnesses = [witness for _, witness in self._reservations]
        envelope = {"schema": "aegis.initial-bootstrap-envelope/v1", "id": "initial-genesis",
                    "event": {"type": "initial_reservations", "approved_plan": self._plan,
                              "channel_witness": self._channel,
                              "reservations": witnesses}}
        receipt = {"event_id": "initial-genesis", "sequence": 1,
                   "event_sha256": digest(envelope), "execution_enabled": False}
        require(same_data(bootstrap["genesis"], {"envelope": envelope, "receipt": receipt})
                 and same_data(bootstrap["reservations"], witnesses)
                 and type(bootstrap["creations"]) is dict,
                 "CANONICAL_CORRELATION_MISMATCH", "original genesis correlation changed")
        return bootstrap

    def require_initial_creation_current(self, reserved_enrollment, policy, state, row_or_None):
        # policy/state/row are N1's actual public-read products under its writer
        # exclusion. They never come from model arguments or a callback. Check
        # their immutable owned-plan/original-row correlations, not a new ledger.
        bootstrap = self._canonical_current(reserved_enrollment, policy, state)
        if row_or_None is None:
            return  # Identity/correlation only; never NEW append permission.
        self._require_reservations_current()
        witness = self._target_witness
        original = bootstrap["creations"].get(reserved_enrollment.actor_cid)
        expected = original if original is not None else witness
        require(same_data(row_or_None, expected), "CANONICAL_CORRELATION_MISMATCH",
                 "INITIAL target is not its original canonical row")
        if original is not None:
            fields(original, {"actor_cid", "envelope", "receipt"},
                    "CANONICAL_CORRELATION_MISMATCH")
            require(original["actor_cid"] == reserved_enrollment.actor_cid,
                     "CANONICAL_CORRELATION_MISMATCH")
            envelope, receipt = original["envelope"], original["receipt"]
            fields(envelope, {"schema", "id", "event"}, "CANONICAL_CORRELATION_MISMATCH")
            event = envelope["event"]
            expected_fields = {name: witness[name] for name in (
                "actor_cid", "role", "generation", "profile_sha256", "cap_seconds",
                "channel_instance_sha256", "approved_plan_sha256")}
            expected_fields.update(type="initial_creation",
                                   genesis_event_sha256=bootstrap["genesis"]["receipt"]["event_sha256"],
                                   reservation_set_sha256=digest(bootstrap["reservations"]),
                                   reservation_witness_sha256=digest(witness))
            identifier = "initial-" + digest({"schema": "aegis.initial-creation-key/v1",
                                               "policy_sha256": digest(policy),
                                               "actor_cid": witness["actor_cid"]})[:40]
            require(envelope["schema"] == "aegis.initial-bootstrap-envelope/v1"
                     and envelope["id"] == identifier and same_data(event, expected_fields),
                     "CANONICAL_CORRELATION_MISMATCH", "original INITIAL envelope changed")
            fields(receipt, {"event_id", "sequence", "event_sha256", "execution_enabled"},
                    "CANONICAL_CORRELATION_MISMATCH")
            require(receipt["event_id"] == identifier and uint(receipt["sequence"])
                     and receipt["sequence"] >= 2 and receipt["event_sha256"] == digest(envelope)
                     and receipt["execution_enabled"] is False
                     and same_data(_mapping(state, "receipts").get(identifier), receipt),
                     "CANONICAL_CORRELATION_MISMATCH", "original INITIAL receipt changed")

    def require_initial_creation_new(self, reserved_enrollment, policy, state, actual_genesis_row):
        bootstrap = self._canonical_current(reserved_enrollment, policy, state)
        self._require_reservations_current()
        witness = self._target_witness
        require(same_data(actual_genesis_row, witness)
                 and reserved_enrollment.actor_cid not in bootstrap["creations"],
                 "CANONICAL_CORRELATION_MISMATCH", "INITIAL intent already has an original row")
        cid, role = witness["actor_cid"], witness["role"]
        require(cid in policy["current"].values() and _mapping(state, "current").get(role) == cid,
                 "ROLE_OPERATION_FORBIDDEN", "INITIAL requires its original current actor")
        require(witness["expires_monotonic_ns"] > time.monotonic_ns()
                 and reserved_enrollment.stage == "reserved", "STALE_INVOCATION",
                 "NEW INITIAL reservation is expired or already issued")


class DecisionGuard(_OwnedGuard):
    """Local identity and original-target checks under H then canonical exclusion."""

    def __init__(self, key, owner, invocation):
        require(native_identities.is_instance("invocation", invocation) and invocation.owner is owner,
                 "ROLE_OPERATION_FORBIDDEN", "decision requires a LIVE HostInvocation")
        invocation.require_current()
        self._invocation = invocation
        super().__init__(key, owner, owner.plan_data,
                         deadline_ns=invocation.deadline_ns)

    def _entry_current(self):
        if not self._invocation.scope_entered:
            self._invocation.require_current()

    def __enter__(self):
        super().__enter__()
        invocation = self._invocation
        if invocation.scope_entered:
            # Authoritative repeat of effect_fence's history check, for a call
            # that entered from another thread after this guard was built.
            invocation.stage = "unknown"
            self._retire()
            self._owner.decision_history_unknown()
        invocation.scope_entered = True
        invocation.scope_depth += 1
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        result = super().__exit__(exc_type, exc_value, traceback)
        self._invocation.scope_depth -= 1
        return result

    def require_current(self, invocation, policy, state, request):
        self._local_current()
        require(invocation is self._invocation, "ROLE_OPERATION_FORBIDDEN", "foreign pending invocation")
        invocation.require_current()
        session, cid = invocation.session, invocation.actor_cid
        require(same_data(policy, self._policy) and type(state) is dict,
                 "CANONICAL_CORRELATION_MISMATCH", "canonical policy differs from owned plan")
        actor = _mapping(policy, "actors").get(cid)
        role_reason = "decision requires current ROOT"
        require(type(actor) is dict and actor.get("role") == "root", "ROLE_OPERATION_FORBIDDEN", role_reason)
        live_actor = session.actor_data
        require(live_actor["role"] == "root", "ROLE_OPERATION_FORBIDDEN", role_reason)
        require(_mapping(state, "current").get("root") == cid
                 and actor.get("generation") == live_actor["generation"]
                 and digest(actor.get("profile"), code="STALE_INVOCATION",
                            reason="canonical generation or custody changed")
                 == live_actor["profile_sha256"],
                 "STALE_INVOCATION", "canonical generation or custody changed")
        initial = session.initial_data
        receipt = {"event_id": initial["initial_event_id"], "sequence": initial["initial_sequence"],
                   "event_sha256": initial["initial_event_sha256"], "execution_enabled": False}
        creation = _mapping(_mapping(state, "initial_bootstrap"), "creations").get(cid)
        require(type(creation) is dict and creation.get("actor_cid") == cid
                 and same_data(creation.get("receipt"), receipt)
                 and same_data(_mapping(state, "receipts").get(receipt["event_id"]), receipt)
                 and digest(creation.get("envelope"), code=_CORRELATION, reason="owned INITIAL receipt changed")
                 == receipt["event_sha256"],
                 "CANONICAL_CORRELATION_MISMATCH", "owned INITIAL receipt changed")
        if request is None:
            return  # Identity only; not NEW authority, expiry or canonical NEW cap.
        require(type(request) is dict and type(request.get("request")) is dict,
                 "CANONICAL_CORRELATION_MISMATCH", "canonical target row is invalid")
        identifier = request["request"].get("id")
        require(type(identifier) is str and _mapping(state, "requests").get(identifier) is request,
                _CORRELATION, "target is not the actual fresh canonical row")
        require("raw" in request, _CORRELATION, "canonical target row is invalid")
        try:
            actual = self._owner.canonical_api.validate_request(request["raw"])
        except HostAuthorityError:
            raise
        except (OSError, ValueError, KeyError):
            raise HostAuthorityError(_CORRELATION, "canonical target row is invalid") from None
        require(type(actual) is dict and same_data(actual, request["request"])
                and "source" in actual and same_data(actual["source"], policy.get("source")),
                _CORRELATION, "canonical target source binding changed")
