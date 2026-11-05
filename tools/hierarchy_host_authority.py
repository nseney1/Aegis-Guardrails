"""Bounded Codex stdio client leaf, without enrollment or native authority.

No process is launched here. The caller owns the external process and hands
ownership of its two binary pipe streams to ProtocolClient. Frame/handshake
success authenticates neither a host principal nor an Aegis role/generation.
"""
from __future__ import annotations

import hashlib
import copy
from contextlib import ExitStack
import json
import math
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import sys
import threading
import time
import weakref


MAX_FRAME_BYTES = 1024 * 1024
MAX_DEPTH = 32
MAX_CALLS = 32
MAX_WAIT_SECONDS = 5
# Longest a blocked wait goes without noticing revocation. Revocation never
# waits for a reply; this only bounds how soon a waiting operation sees it.
REVOCATION_POLL_SECONDS = 0.05
_REVOKED = object()
CODES = frozenset({
    "UNSUPPORTED_HOST", "UNPROTECTED_DEPLOYMENT", "HOST_PROFILE_UNQUALIFIED",
    "HOST_PROTOCOL_ERROR", "HOST_PROTOCOL_TIMEOUT", "HOST_CALL_CONFLICT",
    "STALE_INVOCATION", "ROLE_OPERATION_FORBIDDEN", "CANONICAL_CORRELATION_MISMATCH",
    "CANONICAL_API_UNAVAILABLE", "PROVIDER_OUTCOME_UNKNOWN", "PROVIDER_HANDLE_INVALID",
    "HISTORY_CURSOR_INVALID",
})


class HostAuthorityError(PermissionError):
    """Closed, bounded error data; an error object never grants authority."""

    def __init__(self, code, reason):
        if (type(code) is not str or code not in CODES or type(reason) is not str
                or not 0 < len(reason) <= 1024 or "\x00" in reason):
            raise ValueError("invalid host authority error")
        self._code = code
        self._reason = reason
        super().__init__(reason)

    @property
    def code(self):
        return self._code

    @property
    def reason(self):
        return self._reason


def _invalid():
    raise HostAuthorityError("HOST_PROTOCOL_ERROR", "invalid host protocol frame")


def _text(value, maximum=256):
    return type(value) is str and 0 < len(value) <= maximum and "\x00" not in value


def _rpc_key(value):
    # JSON numbers and strings with the same spelling are different RPC IDs.
    if type(value) is int and -(2 ** 63) <= value < 2 ** 63:
        return (int, value)
    if _text(value):
        return (str, value)
    _invalid()


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            _invalid()
        value[key] = item
    return value


def _constant(_value):
    _invalid()


def _bounded(value):
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_DEPTH:
            _invalid()
        if type(item) is dict:
            stack.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is float and not math.isfinite(item):
            _invalid()


def _decode(raw, maximum=MAX_FRAME_BYTES):
    if (type(raw) is not bytes or len(raw) > maximum or not raw.endswith(b"\n")
            or b"\n" in raw[:-1]):
        _invalid()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise HostAuthorityError("HOST_PROTOCOL_ERROR", "invalid host protocol frame") from exc
    _bounded(value)
    if type(value) is not dict:
        _invalid()
    return value


def _call(value):
    if (set(value) != {"id", "method", "params"}
            or value["method"] != "item/tool/call"):
        _invalid()
    _rpc_key(value["id"])
    params = value["params"]
    required = {"threadId", "turnId", "callId", "tool", "arguments"}
    if (type(params) is not dict or not required <= params.keys()
            or not params.keys() <= required | {"namespace"}):
        _invalid()
    if not all(_text(params[key]) for key in ("threadId", "turnId", "callId", "tool")):
        _invalid()
    if params.get("namespace") is not None and not _text(params["namespace"]):
        _invalid()
    return value


def decode_call_frame(raw):
    """Decode one bounded JSONL call. All arguments remain untrusted data."""
    return _call(_decode(raw))


def refuse_unowned_call(call):
    """This leaf has no enrollment constructor; even matching claims refuse."""
    _call(call)
    body = {"state": "refused", "effect": "none", "code": "STALE_INVOCATION",
            "reason": "host call has no trusted enrollment",
            "identity_authenticated": False, "native_qualified": False}
    return {"success": False, "contentItems": [
        {"type": "inputText", "text": json.dumps(body, separators=(",", ":"))}]}


class ProtocolClient:
    """Single-owner POSIX pipe client; no callbacks, process launch or grants.

    Reader/writer streams are closed on terminal protocol errors or close().
    The process owner must separately reap/stop its actual owned child. The
    bounded connection retains at most MAX_CALLS distinct call identities; it
    refuses rather than evicting replay history or treating an old call as new.

    Revocation (close) is a fence, not a drain: it takes the same gate as every
    read/write syscall, so no I/O can follow it on a descriptor number that
    another file may reuse. Bytes already written keep an unknown outcome.
    """

    def __init__(self, reader, writer, *, timeout_seconds=MAX_WAIT_SECONDS,
                 max_frame_bytes=MAX_FRAME_BYTES):
        if os.name != "posix":
            raise HostAuthorityError("UNSUPPORTED_HOST", "bounded pipe transport requires POSIX")
        if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
                or not 0 < timeout_seconds <= MAX_WAIT_SECONDS
                or type(max_frame_bytes) is not int or not 0 < max_frame_bytes <= MAX_FRAME_BYTES):
            raise ValueError("invalid host transport limits")
        self._gate = self._transport_gate()
        self._reader, self._writer = reader, writer
        self._closed = False
        self._initialized = False
        self._timeout = timeout_seconds
        self._maximum = max_frame_bytes
        self._buffer = b""
        self._calls = {}
        self._ids = {}
        try:
            self._read_fd, self._write_fd = reader.fileno(), writer.fileno()
            if self._read_fd == self._write_fd:
                _invalid()
            os.set_blocking(self._read_fd, False)
            os.set_blocking(self._write_fd, False)
        except (OSError, ValueError, AttributeError) as exc:
            self.close()
            raise HostAuthorityError("HOST_PROTOCOL_ERROR", "invalid host protocol frame") from exc

    @property
    def closed(self):
        return self._closed

    def _transport_gate(self):
        return threading.RLock()

    def _revoked(self):
        return self._closed

    def _guarded(self, operation, *args):
        """Run one non-blocking syscall on an owned descriptor, never after revocation."""
        with self._gate:
            if self._revoked():
                return _REVOKED
            return operation(*args)

    def close(self):
        """Close both owned streams; never signal a PID or infer quiescence."""
        error = None
        with self._gate:  # Waits at most for one in-progress non-blocking syscall.
            if self._closed:
                return
            self._closed = True
            for stream in (self._writer, self._reader):
                try:
                    stream.close()
                except OSError as exc:
                    error = exc if error is None else error
        if error is not None:
            raise error

    def _fail(self, code="HOST_PROTOCOL_ERROR", reason="invalid host protocol frame"):
        try:
            self.close()
        except OSError as exc:
            raise HostAuthorityError(code, reason) from exc
        raise HostAuthorityError(code, reason)

    def _live(self, *, initialized=True):
        if self._closed or (initialized and not self._initialized):
            self._fail()

    def _wait(self, fd, deadline, *, writing=False):
        while True:
            if self._revoked():
                self._fail()
            left = deadline - time.monotonic()
            if left <= 0:
                self._fail("HOST_PROTOCOL_TIMEOUT", "host protocol deadline expired")
            try:
                # Sliced so revocation is seen promptly: closing a descriptor
                # does not wake a select already sleeping on it.
                readable, writable, _ = select.select(
                    [] if writing else [fd], [fd] if writing else [], [],
                    min(left, REVOCATION_POLL_SECONDS))
            except InterruptedError:
                continue  # OS interruption, not a retransmitted protocol request.
            except (OSError, ValueError) as exc:
                try:
                    self._fail()
                except HostAuthorityError as error:
                    raise error from exc
            if readable or writable:
                return

    def _read(self, deadline):
        while True:
            end = self._buffer.find(b"\n")
            if end >= 0:
                raw, self._buffer = self._buffer[:end + 1], self._buffer[end + 1:]
                try:
                    return _decode(raw, self._maximum)
                except HostAuthorityError:
                    self._fail()
            if len(self._buffer) >= self._maximum:
                self._fail()
            self._wait(self._read_fd, deadline)
            try:
                chunk = self._guarded(os.read, self._read_fd,
                                      min(65536, self._maximum - len(self._buffer)))
            except (BlockingIOError, InterruptedError):
                continue
            except OSError as exc:
                try:
                    self._fail()
                except HostAuthorityError as error:
                    raise error from exc
            if chunk is _REVOKED or not chunk:
                self._fail()
            self._buffer += chunk

    def _write(self, value, deadline):
        try:
            _bounded(value)
            raw = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
        except (ValueError, TypeError, RecursionError):
            self._fail()
        if len(raw) > self._maximum:
            self._fail()
        offset = 0
        while offset < len(raw):
            self._wait(self._write_fd, deadline, writing=True)
            try:
                written = self._guarded(os.write, self._write_fd, raw[offset:])
            except (BlockingIOError, InterruptedError):
                continue
            except OSError as exc:
                try:
                    self._fail()
                except HostAuthorityError as error:
                    raise error from exc
            if written is _REVOKED or written <= 0:
                self._fail()
            offset += written

    def _operation_deadline(self):
        return time.monotonic() + self._timeout

    def initialize(self):
        self._live(initialized=False)
        if self._initialized:
            self._fail()
        deadline = self._operation_deadline()
        identifier = "aegis-initialize-1"
        self._write({"id": identifier, "method": "initialize", "params": {
            "clientInfo": {"name": "aegis_host_leaf", "version": "1"},
            "capabilities": {"experimentalApi": True}}}, deadline)
        response = self._read(deadline)
        fields = {"codexHome", "platformFamily", "platformOs", "userAgent"}
        if (set(response) != {"id", "result"} or response["id"] != identifier
                or type(response["id"]) is not str
                or type(response["result"]) is not dict
                or set(response["result"]) != fields
                or not all(_text(item, 4096) for item in response["result"].values())):
            self._fail()
        self._write({"method": "initialized"}, deadline)
        self._initialized = True

    def receive_call(self):
        self._live()
        deadline = self._operation_deadline()
        for _ in range(MAX_CALLS):
            try:
                value = _call(self._read(deadline))
            except HostAuthorityError as exc:
                if not self._closed:
                    self._fail(exc.code, exc.reason)
                raise
            params, rpc = value["params"], _rpc_key(value["id"])
            key = tuple(params.get(name) for name in ("threadId", "turnId", "callId"))
            fingerprint = hashlib.sha256(json.dumps(params, sort_keys=True,
                                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()
            if rpc in self._ids and self._ids[rpc] != key:
                self._fail("HOST_CALL_CONFLICT", "host call correlation conflicts")
            if rpc not in self._ids and len(self._ids) >= MAX_CALLS:
                self._fail("HOST_CALL_CONFLICT", "host call correlation capacity exhausted")
            previous = self._calls.get(key)
            if previous is not None:
                if previous["fingerprint"] != fingerprint:
                    self._fail("HOST_CALL_CONFLICT", "host call correlation conflicts")
                self._ids[rpc] = key
                if previous["result"] is not None:
                    self._write({"id": value["id"], "result": previous["result"]}, deadline)
                elif rpc not in previous["aliases"]:
                    previous["aliases"][rpc] = value["id"]
                continue  # Never return a duplicate for a second dispatch.
            if len(self._calls) >= MAX_CALLS or len(self._ids) >= MAX_CALLS:
                self._fail("HOST_CALL_CONFLICT", "host call correlation capacity exhausted")
            self._ids[rpc] = key
            self._calls[key] = {"fingerprint": fingerprint,
                                "aliases": {rpc: value["id"]}, "result": None}
            return value
        self._fail("HOST_CALL_CONFLICT", "host call correlation capacity exhausted")

    def reply(self, rpc_id, result):
        self._live()
        try:
            rpc = _rpc_key(rpc_id)
            key = self._ids.get(rpc)
            row = self._calls.get(key)
            if row is None or row["result"] is not None:
                self._fail("HOST_CALL_CONFLICT", "host reply has no pending call")
            if (type(result) is not dict or set(result) != {"success", "contentItems"}
                    or type(result["success"]) is not bool
                    or type(result["contentItems"]) is not list
                    or len(result["contentItems"]) > 64):
                self._fail()
            for item in result["contentItems"]:
                if (type(item) is not dict or set(item) != {"type", "text"}
                        or item["type"] != "inputText" or type(item["text"]) is not str):
                    self._fail()
            # Freeze the validated reply before I/O; later caller mutation cannot
            # rewrite a cached response or alias. No raw request is reserialized.
            frozen = json.loads(json.dumps(result, allow_nan=False))
            deadline = self._operation_deadline()
            for identifier in row["aliases"].values():
                self._write({"id": identifier, "result": frozen}, deadline)
            row["result"] = frozen
        except HostAuthorityError as exc:
            if not self._closed:
                self._fail(exc.code, exc.reason)
            raise


_CONTROL_SCHEMA = "aegis.protected-initial-control/v1"
_LIVE_SCHEMA = "aegis.protected-live-control/v1"
_ROLES = frozenset({"root", "router", "coordinator", "operator", "reviewer"})
_OWNED_BINDINGS = weakref.WeakSet()
_RESERVATION_KEY = object()
_GUARD_KEY = object()
_BOUND_INITIAL_KEY = object()
_LIVE_KEY = object()
_LIVE_ERRORS = {
    "CONTROL_INVALID": "HOST_PROTOCOL_ERROR", "CONTROL_STALE": "STALE_INVOCATION",
    "DEADLINE_EXPIRED": "HOST_PROTOCOL_TIMEOUT", "PLAN_MISMATCH": "HOST_PROFILE_UNQUALIFIED",
    "RESERVATION_INVALID": "CANONICAL_CORRELATION_MISMATCH",
    "INITIAL_CORRELATION_MISMATCH": "CANONICAL_CORRELATION_MISMATCH",
    "ATTEMPT_ALREADY_BOUND": "HOST_CALL_CONFLICT", "START_ALREADY_ISSUED": "HOST_CALL_CONFLICT",
    "START_UNKNOWN": "PROVIDER_OUTCOME_UNKNOWN", "LIVE_NOT_ENROLLED": "STALE_INVOCATION",
    "CALL_NOT_PENDING": "STALE_INVOCATION", "CALL_CORRELATION_MISMATCH": "CANONICAL_CORRELATION_MISMATCH",
    "PERMISSION_PROFILE_MISMATCH": "HOST_PROFILE_UNQUALIFIED",
    "TOOL_FORBIDDEN": "ROLE_OPERATION_FORBIDDEN", "PUBLICATION_PENDING": "PROVIDER_OUTCOME_UNKNOWN",
}
_LIVE_METHODS = ("describe", "reserve_initial", "bind_initial", "start_initial",
                 "describe_live", "enroll_live", "pending_call", "retire_call")
_DECISION_TOOL = [{"namespace": "functions", "name": "aegis_decision"}]
_CONTROL_ERRORS = frozenset({
    "CONTROL_INVALID", "CONTROL_STALE", "DEADLINE_EXPIRED", "PLAN_MISMATCH",
    "RESERVATION_INVALID", "INITIAL_CORRELATION_MISMATCH", "ATTEMPT_ALREADY_BOUND",
    "START_ALREADY_ISSUED", "START_UNKNOWN",
})


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _require(value, code="UNPROTECTED_DEPLOYMENT", reason="unprotected host deployment"):
    if not value:
        raise HostAuthorityError(code, reason)


def _fields(value, names, code="UNPROTECTED_DEPLOYMENT"):
    _require(type(value) is dict and set(value) == set(names), code)


def _uint(value, maximum=(1 << 64) - 1):
    return type(value) is int and 0 < value <= maximum


def _sha(value):
    return (type(value) is str and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


def _same_data(value, expected):
    if type(value) is not type(expected):
        return False
    if type(expected) is dict:
        return set(value) == set(expected) and all(
            _same_data(value[key], item) for key, item in expected.items())
    if type(expected) is list:
        return len(value) == len(expected) and all(
            _same_data(a, b) for a, b in zip(value, expected))
    return value == expected


def _json_bytes(raw):
    _require(len(raw) <= MAX_FRAME_BYTES)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                       parse_constant=_constant)
    _bounded(value)
    return value


def _identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns)


def _protected_path(path, owners, model_uid, *, directory=False, socket_path=False):
    path = Path(path)
    _require(path.is_absolute() and _text(str(path), 4096))
    for current in [*reversed(path.parents), path]:
        info = os.stat(current, follow_symlinks=False)
        _require(not stat.S_ISLNK(info.st_mode) and info.st_uid in owners
                 and info.st_uid != model_uid and not info.st_mode & 0o022)
        wanted = (stat.S_ISDIR if current != path or directory else
                  stat.S_ISSOCK if socket_path else stat.S_ISREG)
        _require(wanted(info.st_mode))
        _require(not {"system.posix_acl_access", "system.posix_acl_default"}.intersection(
            os.listxattr(current, follow_symlinks=False)))
    return info


def _protected_bytes(path, owners, model_uid, maximum=MAX_FRAME_BYTES):
    before = _protected_path(path, owners, model_uid)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        _require(_identity(opened) == _identity(before) and opened.st_size <= maximum)
        chunks, length = [], 0
        while True:
            chunk = os.read(fd, min(65536, maximum + 1 - length))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
            _require(length <= maximum)
        _require(_identity(os.fstat(fd)) == _identity(opened))
        _require(_identity(os.stat(path, follow_symlinks=False)) == _identity(opened))
        return b"".join(chunks)
    finally:
        os.close(fd)


def _process_identity(pid):
    _require(_uint(pid, 2147483647))
    root = Path("/proc") / str(pid)
    raw = (root / "stat").read_text()
    _require(raw.split(" ", 1)[0] == str(pid))
    tail = raw[raw.rfind(")") + 2:].split()
    _require(len(tail) >= 20)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    _require(len(boot) == 36 and all(c in "0123456789abcdef-" for c in boot))
    return {"boot_id": boot, "pid_namespace": os.stat(root / "ns/pid").st_ino,
            "pid": pid, "start_ticks": int(tail[19])}


class _ControlIO(ProtocolClient):
    """Reuse bounded framing/I/O, without the model app-server handshake."""

    def __init__(self, owner):
        self._owner = owner
        self._gate = owner._io_gate  # The binding's fence takes this same gate.
        self._read_fd = self._write_fd = owner._control.fileno()
        self._maximum, self._buffer = MAX_FRAME_BYTES, b""
        self._closed = False
        os.set_blocking(self._read_fd, False)

    def _revoked(self):
        return self._closed or self._owner._fenced

    def close(self):
        self._owner.close()


class ReservedEnrollment:
    """An owned reservation snapshot, never constructible from a witness dict."""

    __slots__ = ("_owner", "_witness", "_stage", "_bind_attempted")

    def __init__(self, key, owner, witness):
        _require(key is _RESERVATION_KEY and owner in _OWNED_BINDINGS,
                 "ROLE_OPERATION_FORBIDDEN", "reservation requires owned runtime")
        self._owner = weakref.ref(owner)
        self._witness = copy.deepcopy(witness)
        self._stage = "reserved"  # Local issuance lifecycle, not a canonical ledger.
        self._bind_attempted = False

    @property
    def actor_cid(self):
        return self._witness["actor_cid"]

    @property
    def witness(self):
        return copy.deepcopy(self._witness)

    @property
    def reservation_witness_sha256(self):
        return _digest(self._witness)

    @property
    def owned_runtime(self):
        owner = self._owner()
        _require(owner in _OWNED_BINDINGS, "STALE_INVOCATION", "runtime is no longer owned")
        owner._require_owner_process()
        return owner

    def __copy__(self):
        raise TypeError("owned reservations cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("owned reservations cannot be copied")

    def __reduce_ex__(self, protocol):
        raise TypeError("owned reservations cannot be serialized")


class BoundInitialEnrollment:
    """One host-local startup context; never a serialized runtime permit."""

    __slots__ = ("_owner", "_reservation", "_initial", "_deadline", "_epoch", "_nonce", "_stage")

    def __init__(self, key, owner, reservation, initial, deadline):
        _require(key is _BOUND_INITIAL_KEY and type(owner) is OwnedHostBinding
                 and owner in _OWNED_BINDINGS, "ROLE_OPERATION_FORBIDDEN",
                 "bound context requires owned runtime")
        owner._require_owner_process()
        self._owner, self._reservation = weakref.ref(owner), reservation
        self._initial, self._deadline = copy.deepcopy(initial), deadline
        self._epoch, self._nonce, self._stage = owner._epoch, owner._nonce, "bound"

    @property
    def actor_cid(self):
        return self._reservation.actor_cid

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
        _require(type(owned_runtime) is OwnedHostBinding and owned_runtime in _OWNED_BINDINGS,
                 "ROLE_OPERATION_FORBIDDEN", "authority requires owned runtime")
        self._owner = weakref.ref(owned_runtime)

    @property
    def owned_runtime(self):
        owner = self._owner()
        _require(owner in _OWNED_BINDINGS, "STALE_INVOCATION", "runtime is no longer owned")
        owner._require_owner_process()
        return owner

    @property
    def canonical_root(self):
        return self.owned_runtime.canonical_root

    def bootstrap_fence(self, owned_runtime, approved_plan_ref, reserved_enrollments):
        _require(type(self) is HostAuthority and self.owned_runtime is owned_runtime,
                 "ROLE_OPERATION_FORBIDDEN", "foreign host authority")
        return ReservedGenesisGuard(_GUARD_KEY, owned_runtime, approved_plan_ref,
                                    reserved_enrollments)

    def initial_creation_fence(self, owned_runtime, approved_plan_ref, reserved_enrollment):
        _require(type(self) is HostAuthority and self.owned_runtime is owned_runtime,
                 "ROLE_OPERATION_FORBIDDEN", "foreign host authority")
        return InitialCreationGuard(_GUARD_KEY, owned_runtime, approved_plan_ref,
                                    reserved_enrollment)

    def effect_fence(self, invocation, operation):
        owner = self._owner()
        if (type(invocation) is HostInvocation and owner is not None
                and invocation._session._owner is owner and invocation._scope_entered):
            # History wins over currentness: a call whose decision scope ever
            # entered stays unknown, even once it is stale or its owner closed.
            # History never resets, so this unlocked read cannot wrongly refuse;
            # DecisionGuard.__enter__ repeats the check under the lock.
            owner._decision_history_unknown()
        owner = self.owned_runtime
        _require(type(self) is HostAuthority and self is owner._authority
                 and operation == "decision" and type(operation) is str,
                 "ROLE_OPERATION_FORBIDDEN", "only decision effects are admitted")
        return DecisionGuard(_GUARD_KEY, owner, invocation)

    def require_current(self, invocation, policy, state, request):
        owner = self.owned_runtime
        guard = owner._active_guard
        _require(type(self) is HostAuthority and self is owner._authority
                 and type(guard) is DecisionGuard,
                 "STALE_INVOCATION", "decision fence is not active")
        return guard.require_current(invocation, policy, state, request)

    def require_decision_command(self, invocation, command):
        """Bind inert command data to this guard's actual received frame."""
        owner = self.owned_runtime
        guard = owner._active_guard
        _require(type(self) is HostAuthority and self is owner._authority
                 and type(guard) is DecisionGuard,
                 "STALE_INVOCATION", "decision fence is not active")
        guard._local_current()
        _require(invocation is guard._invocation,
                 "ROLE_OPERATION_FORBIDDEN", "foreign pending invocation")
        invocation._current()
        _require(type(command) is dict and all(type(key) is str for key in command)
                 and set(command) == {"event_id", "request_id", "request_sha256", "decision", "reason"}
                 and all(type(value) is str for value in command.values())
                 and _same_data(command, invocation._frame["params"]["arguments"]),
                 "STALE_INVOCATION", "decision arguments do not match owned call")


class _OwnedGuard:
    """One lexical local fence. External provenance is read before acquiring it."""

    def __init__(self, key, owner, plan_ref, *, deadline_ns=None):
        _require(key is _GUARD_KEY and type(owner) is OwnedHostBinding
                 and owner in _OWNED_BINDINGS and owner._policy is not None,
                 "ROLE_OPERATION_FORBIDDEN", "guard requires owned runtime")
        owner._require_owner_process()
        _require(_same_data(plan_ref, owner._plan), "CANONICAL_CORRELATION_MISMATCH",
                 "guard plan does not match owned runtime")
        self._owner = owner
        self._plan = copy.deepcopy(owner._plan)
        self._policy = copy.deepcopy(owner._policy)
        self._channel = copy.deepcopy(owner._channel)
        self._members = tuple(owner._reservations)
        self._witnesses = tuple(row.witness for row in self._members)
        self._epoch, self._nonce = owner._epoch, owner._nonce
        self._used, self._active = False, False
        self._thread, self._deadline = None, None
        _require(deadline_ns is None or _uint(deadline_ns), "ROLE_OPERATION_FORBIDDEN",
                 "invalid original operation deadline")
        self._deadline_limit = deadline_ns

    def __enter__(self):
        self._owner._require_owner_process()
        _require(not self._used, "ROLE_OPERATION_FORBIDDEN", "guard cannot be reentered")
        active = self._owner._active_guard
        _require(active is None or active._thread != threading.get_ident(),
                 "ROLE_OPERATION_FORBIDDEN", "nested host fences are forbidden")
        self._used = True
        self._deadline = time.monotonic_ns() + MAX_WAIT_SECONDS * 1000000000
        if self._deadline_limit is not None:
            self._deadline = min(self._deadline, self._deadline_limit)
        # This is actual OS/runtime/source preflight, outside H/canonical locks.
        try:
            self._owner._prove_current()
        except HostAuthorityError:
            raise
        except (OSError, ValueError) as exc:
            raise HostAuthorityError("HOST_PROFILE_UNQUALIFIED",
                                     "host preflight is unavailable") from exc
        left = max(0, (self._deadline - time.monotonic_ns()) / 1000000000)
        _require(self._owner._lock.acquire(timeout=left), "HOST_PROTOCOL_TIMEOUT",
                 "host fence deadline expired")
        try:
            _require(self._owner._active_guard is None, "ROLE_OPERATION_FORBIDDEN",
                     "nested host fences are forbidden")
            self._owner._active_guard = self
            self._thread, self._active = threading.get_ident(), True
            self._local_current()
            self._entry_current()
            return self
        except BaseException:
            self._active = False
            if self._owner._active_guard is self:
                self._owner._active_guard = None
            self._owner._lock.release()
            raise

    def _entry_current(self):
        raise NotImplementedError("a concrete guard purpose is required")

    def _local_current(self):
        owner = self._owner
        owner._require_owner_process()
        _require(self._active and self._thread == threading.get_ident()
                 and owner in _OWNED_BINDINGS and not owner._closed
                 and owner._active_guard is self and owner._epoch == self._epoch
                 and owner._nonce == self._nonce and time.monotonic_ns() < self._deadline,
                 "STALE_INVOCATION", "host guard is no longer current")
        _require(_same_data(owner._plan, self._plan)
                 and _same_data(owner._policy, self._policy)
                 and _same_data(owner._channel, self._channel),
                 "CANONICAL_CORRELATION_MISMATCH", "owned host inputs changed")

    def _member(self, reservation):
        _require(type(reservation) is ReservedEnrollment
                 and reservation._owner() is self._owner
                 and any(reservation is row for row in self._members),
                 "ROLE_OPERATION_FORBIDDEN", "foreign owned reservation")
        index = next(i for i, row in enumerate(self._members) if row is reservation)
        _require(_same_data(reservation.witness, self._witnesses[index]),
                 "CANONICAL_CORRELATION_MISMATCH", "owned reservation changed")
        return self._witnesses[index]

    def __exit__(self, exc_type, exc_value, traceback):
        self._owner._require_owner_process()
        _require(self._active and self._thread == threading.get_ident(),
                 "ROLE_OPERATION_FORBIDDEN", "foreign guard exit")
        # N1 performs the final current check inside its publication try block.
        # Exit only retires the lexical guard: a later exception here must not
        # relabel an already published INITIAL result as a no-effect refusal.
        self._active = False
        self._owner._active_guard = None
        self._owner._lock.release()
        return False

    def __copy__(self):
        raise TypeError("host guards cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("host guards cannot be copied")

    def __reduce_ex__(self, protocol):
        raise TypeError("host guards cannot be serialized")


class ReservedGenesisGuard(_OwnedGuard):
    """Fresh full-set genesis authority, never a receipt-recovery fence."""

    def __init__(self, key, owner, plan_ref, reservations):
        super().__init__(key, owner, plan_ref)
        _require(type(reservations) is tuple and len(reservations) == len(self._members)
                 and all(a is b for a, b in zip(reservations, self._members)),
                 "ROLE_OPERATION_FORBIDDEN", "genesis requires the complete owned set")

    def _entry_current(self):
        self.require_reserved_genesis_current()

    def require_reserved_genesis_current(self):
        self._local_current()
        for reservation in self._members:
            witness = self._member(reservation)
            _require(witness["expires_monotonic_ns"] > time.monotonic_ns()
                     and reservation._stage == "reserved", "STALE_INVOCATION",
                     "genesis reservation is expired or already issued")

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if exc_type is None:
                # N1 owns this complete lexical transaction and maps an exit
                # failure after exclusive root claim to publication UNKNOWN.
                self.require_reserved_genesis_current()
        finally:
            super().__exit__(exc_type, exc_value, traceback)
        return False


class InitialCreationGuard(_OwnedGuard):
    """Current owner identity, original receipt recovery, then NEW-only checks."""

    def __init__(self, key, owner, plan_ref, reservation, *, deadline_ns=None):
        super().__init__(key, owner, plan_ref, deadline_ns=deadline_ns)
        self._target = reservation
        self._member(reservation)

    def _entry_current(self):
        self.require_initial_identity_current(self._target)

    def require_initial_identity_current(self, reserved_enrollment):
        self._local_current()
        _require(reserved_enrollment is self._target, "ROLE_OPERATION_FORBIDDEN",
                 "guard target does not match owned reservation")
        self._member(reserved_enrollment)

    def _canonical_current(self, reservation, policy, state):
        self.require_initial_identity_current(reservation)
        _require(_same_data(policy, self._policy) and type(state) is dict,
                 "CANONICAL_CORRELATION_MISMATCH", "canonical policy does not match owned plan")
        bootstrap = state.get("initial_bootstrap")
        _fields(bootstrap, {"genesis", "reservations", "creations"},
                "CANONICAL_CORRELATION_MISMATCH")
        _fields(bootstrap["genesis"], {"envelope", "receipt"},
                "CANONICAL_CORRELATION_MISMATCH")
        envelope = {"schema": "aegis.initial-bootstrap-envelope/v1", "id": "initial-genesis",
                    "event": {"type": "initial_reservations", "approved_plan": self._plan,
                              "channel_witness": self._channel,
                              "reservations": list(self._witnesses)}}
        receipt = {"event_id": "initial-genesis", "sequence": 1,
                   "event_sha256": _digest(envelope), "execution_enabled": False}
        _require(_same_data(bootstrap["genesis"], {"envelope": envelope, "receipt": receipt})
                 and _same_data(bootstrap["reservations"], list(self._witnesses))
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
        witness = self._member(reserved_enrollment)
        original = bootstrap["creations"].get(reserved_enrollment.actor_cid)
        expected = original if original is not None else witness
        _require(_same_data(row_or_None, expected), "CANONICAL_CORRELATION_MISMATCH",
                 "INITIAL target is not its original canonical row")
        if original is not None:
            _fields(original, {"actor_cid", "envelope", "receipt"},
                    "CANONICAL_CORRELATION_MISMATCH")
            _require(original["actor_cid"] == reserved_enrollment.actor_cid,
                     "CANONICAL_CORRELATION_MISMATCH")
            envelope, receipt = original["envelope"], original["receipt"]
            _fields(envelope, {"schema", "id", "event"}, "CANONICAL_CORRELATION_MISMATCH")
            event = envelope["event"]
            expected_fields = {name: witness[name] for name in (
                "actor_cid", "role", "generation", "profile_sha256", "cap_seconds",
                "channel_instance_sha256", "approved_plan_sha256")}
            expected_fields.update(type="initial_creation",
                                   genesis_event_sha256=bootstrap["genesis"]["receipt"]["event_sha256"],
                                   reservation_set_sha256=_digest(bootstrap["reservations"]),
                                   reservation_witness_sha256=_digest(witness))
            identifier = "initial-" + _digest({"schema": "aegis.initial-creation-key/v1",
                                               "policy_sha256": _digest(policy),
                                               "actor_cid": witness["actor_cid"]})[:40]
            _require(envelope["schema"] == "aegis.initial-bootstrap-envelope/v1"
                     and envelope["id"] == identifier and _same_data(event, expected_fields),
                     "CANONICAL_CORRELATION_MISMATCH", "original INITIAL envelope changed")
            _fields(receipt, {"event_id", "sequence", "event_sha256", "execution_enabled"},
                    "CANONICAL_CORRELATION_MISMATCH")
            _require(receipt["event_id"] == identifier and _uint(receipt["sequence"])
                     and receipt["sequence"] >= 2 and receipt["event_sha256"] == _digest(envelope)
                     and receipt["execution_enabled"] is False
                     and _same_data(state.get("receipts", {}).get(identifier), receipt),
                     "CANONICAL_CORRELATION_MISMATCH", "original INITIAL receipt changed")

    def require_initial_creation_new(self, reserved_enrollment, policy, state, actual_genesis_row):
        bootstrap = self._canonical_current(reserved_enrollment, policy, state)
        witness = self._member(reserved_enrollment)
        _require(_same_data(actual_genesis_row, witness)
                 and reserved_enrollment.actor_cid not in bootstrap["creations"],
                 "CANONICAL_CORRELATION_MISMATCH", "INITIAL intent already has an original row")
        cid, role = witness["actor_cid"], witness["role"]
        _require(cid in policy["current"].values() and state.get("current", {}).get(role) == cid,
                 "ROLE_OPERATION_FORBIDDEN", "INITIAL requires its original current actor")
        _require(witness["expires_monotonic_ns"] > time.monotonic_ns()
                 and reserved_enrollment._stage == "reserved", "STALE_INVOCATION",
                 "NEW INITIAL reservation is expired or already issued")


class OwnedHostBinding:
    """Authenticate one private control connection and own its three resources.

    Witness JSON is checked against kernel/protected-file readback before a
    reservation is interned. This constructor does not make any actor LIVE.
    """

    def __init__(self):
        raise TypeError("use OwnedHostBinding.from_owned_channels")

    @classmethod
    def from_owned_channels(cls, runtime_control_socket, appserver_reader,
                            appserver_writer, protected_deployment_path):
        _require(cls is OwnedHostBinding, "ROLE_OPERATION_FORBIDDEN", "invalid binding factory")
        self = object.__new__(cls)
        self._host_pid = os.getpid()
        self._control, self._reader, self._writer = (
            runtime_control_socket, appserver_reader, appserver_writer)
        self._closed, self._reserved = False, False
        self._lock = threading.RLock()
        # Descriptor fence: every owned-descriptor syscall and close() take it.
        # It is held only for one non-blocking syscall, never while waiting on
        # _lock, so revocation cannot wait on an exchange holding _lock.
        self._io_gate = threading.RLock()
        self._fenced, self._retired = False, False
        self._active_guard = None
        self._files, self._reservations, self._policy, self._plan = {}, (), None, None
        self._canonical_api, self._bound_initials = None, set()
        self._started, self._live_sessions, self._live_attempts = {}, {}, set()
        self._appserver = None
        try:
            _require(sys.platform == "linux", "UNSUPPORTED_HOST", "protected control requires Linux")
            self._nonce, self._id, self._epoch = os.urandom(32).hex(), 0, 0
            _require(isinstance(self._control, socket.socket)
                     and self._control.family == socket.AF_UNIX
                     and self._control.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM)
            _require(isinstance(protected_deployment_path, (str, Path)),
                     "UNPROTECTED_DEPLOYMENT", "deployment path must be text or Path")
            self._deployment_path = Path(protected_deployment_path)
            # The host's own UID is a kernel fact; deployment bytes do not choose it.
            host_uid = os.geteuid()
            raw = _protected_bytes(self._deployment_path, {0, host_uid}, -1)
            deployment = _json_bytes(raw)
            _fields(deployment, {"schema", "runtime_uid", "host_uid", "model_uid",
                                 "runtime_executable", "host_source_closure", "canonical_root",
                                 "runtime_control_endpoint", "role_ceiling_ref"})
            _require(deployment["schema"] == "aegis.protected-host-deployment/v1"
                     and deployment["host_uid"] == host_uid)
            _require(all(type(deployment[k]) is int and 0 <= deployment[k] < 2 ** 32
                         for k in ("runtime_uid", "host_uid", "model_uid")))
            _require(deployment["model_uid"] not in {host_uid, deployment["runtime_uid"]})
            self._deployment = deployment
            self._owners = {0, host_uid, deployment["runtime_uid"]}
            self._model_uid = deployment["model_uid"]
            self._files[str(self._deployment_path)] = hashlib.sha256(raw).hexdigest()
            executable = self._reference(deployment["runtime_executable"], maximum=64 * MAX_FRAME_BYTES)
            ceiling = self._reference(deployment["role_ceiling_ref"])
            closure = deployment["host_source_closure"]
            _require(type(closure) is list and 0 < len(closure) <= 128)
            paths = []
            for ref in closure:
                self._reference(ref, maximum=64 * MAX_FRAME_BYTES)
                paths.append(ref["path"])
            _require(paths == sorted(set(paths)) and str(Path(__file__).resolve()) in paths)
            _require(_text(deployment["canonical_root"], 4096)
                     and _text(deployment["runtime_control_endpoint"], 4096))
            canonical = Path(deployment["canonical_root"])
            _protected_path(canonical if canonical.exists() else canonical.parent,
                            self._owners, self._model_uid, directory=True)
            _require(canonical.is_absolute())
            endpoint = deployment["runtime_control_endpoint"]
            _protected_path(endpoint, self._owners, self._model_uid, socket_path=True)
            _require(self._control.getpeername() == endpoint)
            _require(all(hasattr(stream, "fileno") and hasattr(stream, "close")
                         for stream in (self._reader, self._writer)))
            self._fds = (self._control.fileno(), self._reader.fileno(), self._writer.fileno())
            _require(all(type(fd) is int and fd >= 0 for fd in self._fds)
                     and len(set(self._fds)) == 3)
            import fcntl  # Linux constructor only; portable codec import is unaffected.
            for fd in self._fds:
                os.set_inheritable(fd, False)
            read_info, write_info = (os.fstat(fd) for fd in self._fds[1:])
            _require(stat.S_ISFIFO(read_info.st_mode) and stat.S_ISFIFO(write_info.st_mode)
                     and read_info.st_ino != write_info.st_ino
                     and fcntl.fcntl(self._fds[1], fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
                     and fcntl.fcntl(self._fds[2], fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY)
            pid, uid, _gid = struct.unpack("3i", self._control.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            _require(uid == deployment["runtime_uid"] and pid != os.getpid())
            self._peer_pid, self._peer_uid = pid, uid
            self._host_process = _process_identity(self._host_pid)
            self._process = _process_identity(pid)
            self._prove_current()
            self._expected_channel = {
                "schema": "aegis.host-channel-witness/v1",
                "runtime_instance": self._process, "appserver_instance": self._process,
                "control_peer_instance": self._process,
                "read_pipe_inode": read_info.st_ino, "write_pipe_inode": write_info.st_ino,
                "deployment_sha256": self._files[str(self._deployment_path)],
                "runtime_executable_sha256": executable["sha256"],
                "host_source_closure_sha256": _digest(closure),
                "role_ceiling_sha256": ceiling["sha256"]}
            self._wire = _ControlIO(self)
            result = self._exchange("describe", {})
            _fields(result, {"channel_witness"}, "HOST_PROTOCOL_ERROR")
            channel = result["channel_witness"]
            _fields(channel, set(self._expected_channel) | {"epoch"}, "HOST_PROTOCOL_ERROR")
            _require(type(channel["epoch"]) is int and channel["epoch"] == self._epoch
                     and all(_same_data(channel[k], v) for k, v in self._expected_channel.items()),
                     "CANONICAL_CORRELATION_MISMATCH", "host witness conflicts with readback")
            self._channel = copy.deepcopy(channel)
            _OWNED_BINDINGS.add(self)
            self._authority = HostAuthority(self)
            return self
        except HostAuthorityError:
            self.close()
            raise
        except (OSError, ValueError, UnicodeError) as exc:
            self.close()
            raise HostAuthorityError("UNPROTECTED_DEPLOYMENT", "unprotected host deployment") from exc

    def _reference(self, value, maximum=MAX_FRAME_BYTES):
        _fields(value, {"path", "sha256"})
        _require(_text(value["path"], 4096) and _sha(value["sha256"]))
        raw = _protected_bytes(value["path"], self._owners, self._model_uid, maximum)
        _require(hashlib.sha256(raw).hexdigest() == value["sha256"])
        self._files[value["path"]] = value["sha256"]
        return dict(value)

    def _require_owner_process(self):
        # getpid is local kernel identity, not procfs/source/transport readback.
        # Inherited Python objects, registries and locks confer no child grant.
        _require(os.getpid() == self._host_pid, "STALE_INVOCATION",
                 "runtime binding belongs to another host process")

    def _prove_current(self):
        self._require_owner_process()
        _require(not self._closed, "STALE_INVOCATION", "runtime binding is closed")
        _require(_process_identity(self._host_pid) == self._host_process,
                 "STALE_INVOCATION", "host process incarnation changed")
        _require(_process_identity(self._peer_pid) == self._process)
        # Descriptor readback runs under the fence gate, so close() cannot
        # release these numbers mid-check. A fenced binding refuses with a typed
        # error instead of reading a released, possibly reused, descriptor.
        with self._io_gate:
            _require(not self._fenced, "STALE_INVOCATION", "runtime binding is closed")
            pid, uid, _gid = struct.unpack("3i", self._control.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            _require(pid == self._peer_pid and uid == self._peer_uid)
            root = Path("/proc") / str(pid)
            status = (root / "status").read_text()
            uids = [line.split()[1:] for line in status.splitlines() if line.startswith("Uid:")]
            _require(len(uids) == 1 and all(int(value) == uid for value in uids[0]))
            _require(os.stat(root / "ns/time").st_ino == os.stat("/proc/self/ns/time").st_ino)
            _require(os.readlink(root / "exe") == self._deployment["runtime_executable"]["path"])
            for number, fd in ((0, self._fds[2]), (1, self._fds[1])):
                info = os.fstat(fd)
                _require(stat.S_ISFIFO(info.st_mode)
                         and os.readlink(root / ("fd/%s" % number)) == "pipe:[%s]" % info.st_ino)
        for path, expected in self._files.items():
            raw = _protected_bytes(path, self._owners, self._model_uid, 64 * MAX_FRAME_BYTES)
            _require(hashlib.sha256(raw).hexdigest() == expected)

    def _fail(self, code="HOST_PROTOCOL_ERROR", reason="invalid protected control frame"):
        try:
            self.close()
        except OSError as exc:
            raise HostAuthorityError(code, reason) from exc
        raise HostAuthorityError(code, reason)

    def _exchange(self, method, params, deadline=None, *, schema=_CONTROL_SCHEMA):
        self._require_owner_process()
        _require(self._active_guard is None, "ROLE_OPERATION_FORBIDDEN",
                 "control IPC is forbidden inside a host fence")
        if deadline is None:
            deadline = time.monotonic() + MAX_WAIT_SECONDS
        self._prove_current()
        acquired = self._lock.acquire(timeout=max(0, deadline - time.monotonic()))
        if not acquired:
            self._fail("HOST_PROTOCOL_TIMEOUT", "protected control deadline expired")
        try:
            if self._closed or self._id >= MAX_CALLS:
                self._fail("STALE_INVOCATION", "protected control is unavailable")
            self._id += 1
            self._wire._write({"schema": schema, "id": self._id,
                               "epoch": self._epoch, "nonce": self._nonce,
                               "method": method, "params": params}, deadline)
            reply = self._wire._read(deadline)
            if (set(reply) not in ({"schema", "id", "epoch", "nonce", "result"},
                                   {"schema", "id", "epoch", "nonce", "error"})
                    or reply["schema"] != schema
                    or type(reply["id"]) is not int or reply["id"] != self._id
                    or reply["nonce"] != self._nonce or not _uint(reply["epoch"])
                    or (self._epoch and reply["epoch"] != self._epoch)):
                self._fail()
            self._epoch = reply["epoch"]
            if "error" in reply:
                error = reply["error"]
                _fields(error, {"code", "effect"}, "HOST_PROTOCOL_ERROR")
                roster = _LIVE_ERRORS if schema == _LIVE_SCHEMA else _CONTROL_ERRORS
                if (type(error["code"]) is not str or type(error["effect"]) is not str
                        or error["code"] not in roster
                        or error["effect"] not in {"none", "possible"}):
                    self._fail()
                if schema == _LIVE_SCHEMA:
                    if (error["code"] in {"START_UNKNOWN", "PUBLICATION_PENDING"}
                            and error["effect"] != "possible"):
                        self._fail()
                    self._fail("PROVIDER_OUTCOME_UNKNOWN" if error["effect"] == "possible"
                               else _LIVE_ERRORS[error["code"]], "protected runtime refused operation")
                self._fail("PROVIDER_OUTCOME_UNKNOWN" if error["effect"] == "possible"
                           else "HOST_PROFILE_UNQUALIFIED", "protected runtime refused operation")
            self._prove_current()
            if time.monotonic() >= deadline:
                self._fail("HOST_PROTOCOL_TIMEOUT", "protected control deadline expired")
            return reply["result"]
        finally:
            self._lock.release()

    def reserve_initial(self, approved_plan_ref):
        """Reserve once from actual protected plan bytes and authenticated runtime."""
        self._require_owner_process()
        deadline = time.monotonic() + MAX_WAIT_SECONDS
        try:
            acquired = self._lock.acquire(timeout=max(0, deadline - time.monotonic()))
            _require(acquired, "HOST_PROTOCOL_TIMEOUT", "protected control deadline expired")
            try:
                _require(self in _OWNED_BINDINGS and not self._reserved,
                         "HOST_CALL_CONFLICT", "initial reservation was already attempted")
                self._reserved = True  # Lost replies never permit another attempt.
            finally:
                self._lock.release()
            self._reference(approved_plan_ref)
            raw = _protected_bytes(approved_plan_ref["path"], self._owners, self._model_uid)
            plan = _json_bytes(raw)
            _fields(plan, {"source", "actors", "current", "successors"})
            # Real public canonical validation; no affirmative authority callback.
            if __package__:
                from . import hierarchy_lifecycle as lifecycle
            else:
                import hierarchy_lifecycle as lifecycle
            _require(Path(lifecycle.__file__).resolve() == Path(__file__).with_name(
                "hierarchy_lifecycle.py").resolve(), "CANONICAL_API_UNAVAILABLE")
            policy = lifecycle.validate_policy({"schema": lifecycle.POLICY,
                                               "authority": [dict(approved_plan_ref)], **plan})
            result = self._exchange("reserve_initial", {"approved_plan": dict(approved_plan_ref)},
                                    deadline)
            _fields(result, {"reservations"}, "HOST_PROTOCOL_ERROR")
            rows = result["reservations"]
            _require(type(rows) is list and len(rows) == len(policy["actors"]),
                     "CANONICAL_CORRELATION_MISMATCH")
            seen, sequences = [], set()
            owned = []
            for row in rows:
                _fields(row, {"schema", "channel_instance_sha256", "approved_plan_sha256",
                              "actor_cid", "role", "generation", "profile_sha256", "cap_seconds",
                              "reservation_sequence", "expires_monotonic_ns"}, "HOST_PROTOCOL_ERROR")
                cid = row["actor_cid"]
                _require(type(cid) is str and cid in policy["actors"], "CANONICAL_CORRELATION_MISMATCH")
                actor = policy["actors"][cid]
                expected = {"schema": "aegis.host-reservation-witness/v1",
                            "channel_instance_sha256": _digest(self._channel),
                            "approved_plan_sha256": approved_plan_ref["sha256"],
                            "actor_cid": cid, "role": actor["role"], "generation": actor["generation"],
                            "profile_sha256": _digest(actor["profile"]), "cap_seconds": actor["cap_seconds"]}
                _require(all(type(row[k]) is type(v) and row[k] == v for k, v in expected.items())
                         and _uint(row["reservation_sequence"])
                         and row["reservation_sequence"] not in sequences
                         and _uint(row["expires_monotonic_ns"])
                         and row["expires_monotonic_ns"] > time.monotonic_ns(),
                         "CANONICAL_CORRELATION_MISMATCH", "reservation conflicts with protected plan")
                seen.append(cid)
                sequences.add(row["reservation_sequence"])
                owned.append(ReservedEnrollment(_RESERVATION_KEY, self, row))
            _require(seen == sorted(policy["actors"]), "CANONICAL_CORRELATION_MISMATCH")
            _require(time.monotonic() < deadline, "HOST_PROTOCOL_TIMEOUT",
                     "protected control deadline expired")
            acquired = self._lock.acquire(timeout=max(0, deadline - time.monotonic()))
            _require(acquired, "HOST_PROTOCOL_TIMEOUT", "protected control deadline expired")
            try:
                _require(self in _OWNED_BINDINGS and not self._closed,
                         "STALE_INVOCATION", "runtime binding is closed")
                self._reservations, self._policy, self._plan = (
                    tuple(owned), copy.deepcopy(policy), dict(approved_plan_ref))
                self._canonical_api = lifecycle  # Actual co-located public producer validated above.
                return self._reservations
            finally:
                self._lock.release()
        except HostAuthorityError:
            self.close()
            raise
        except (OSError, ValueError, UnicodeError) as exc:
            self.close()
            raise HostAuthorityError("UNPROTECTED_DEPLOYMENT", "invalid protected plan") from exc

    def _initial_owner_current(self):
        self._require_owner_process()
        _require(self in _OWNED_BINDINGS and not self._closed, "STALE_INVOCATION",
                 "runtime binding is closed")

    def _initial_reservation(self, reservation):
        _require(type(reservation) is ReservedEnrollment and reservation._owner() is self
                 and any(reservation is row for row in self._reservations),
                 "ROLE_OPERATION_FORBIDDEN", "foreign owned reservation")

    def _initial_lock(self, deadline):
        left = max(0, (deadline - time.monotonic_ns()) / 1000000000)
        _require(self._lock.acquire(timeout=left), "HOST_PROTOCOL_TIMEOUT",
                 "original initial deadline expired")

    def _initial_projection(self, guard, reservation, expected_receipt=None):
        # Only this actual binding's co-located N1 producer supplies these views.
        # Nothing here accepts caller-loaded state, a loader or a callback.
        lifecycle = self._canonical_api
        _require(lifecycle is not None, "CANONICAL_API_UNAVAILABLE",
                 "canonical producer is unavailable")
        with lifecycle.writer_lock(self.canonical_root):
            guard.require_initial_identity_current(reservation)
            reader = lifecycle.Lifecycle(self.canonical_root)
            policy, state = reader.load()
            guard.require_initial_creation_current(reservation, policy, state, None)
            snapshot = reader.initial_bootstrap()
            original = next((row for row in snapshot["creations"]
                             if row["actor_cid"] == reservation.actor_cid), None)
            _require(original is not None, "CANONICAL_CORRELATION_MISMATCH",
                     "original INITIAL row is unavailable")
            guard.require_initial_creation_current(reservation, policy, state, original)
            receipt, witness = original["receipt"], reservation.witness
            if expected_receipt is not None:
                _require(_same_data(receipt, expected_receipt), "CANONICAL_CORRELATION_MISMATCH",
                         "INITIAL receipt changed")
            _require(state["current"][witness["role"]] == reservation.actor_cid
                     and policy["current"][witness["role"]] == reservation.actor_cid,
                     "ROLE_OPERATION_FORBIDDEN", "INITIAL actor is no longer current")
            initial = {name: witness[name] for name in (
                "actor_cid", "role", "generation", "profile_sha256", "cap_seconds",
                "approved_plan_sha256", "channel_instance_sha256")}
            initial.update({"policy_sha256": _digest(policy),
                            "reservation_witness_sha256": _digest(witness),
                            "genesis_event_sha256": snapshot["genesis_receipt"]["event_sha256"],
                            "initial_event_id": receipt["event_id"],
                            "initial_sequence": receipt["sequence"],
                            "initial_event_sha256": receipt["event_sha256"]})
            guard.require_initial_identity_current(reservation)
            return initial

    def _initial_unknown(self, cause):
        try:
            self.close()
        except OSError as cleanup:
            raise HostAuthorityError("PROVIDER_OUTCOME_UNKNOWN",
                                     "initial control outcome is unknown") from cleanup
        raise HostAuthorityError("PROVIDER_OUTCOME_UNKNOWN",
                                 "initial control outcome is unknown") from cause

    def bind_initial(self, reservation):
        """Record a real INITIAL once, then bind it on the owned control channel."""
        self._initial_owner_current()
        self._initial_reservation(reservation)
        deadline = time.monotonic_ns() + MAX_WAIT_SECONDS * 1000000000
        self._initial_lock(deadline)
        try:
            self._initial_owner_current()
            _require(not reservation._bind_attempted, "HOST_CALL_CONFLICT",
                     "initial binding was already attempted")
            # Keep stage reserved until N1's NEW checks finish. This separate
            # local one-attempt bit cannot create a canonical receipt or grant.
            reservation._bind_attempted = True
        finally:
            self._lock.release()
        sent = False
        try:
            with InitialCreationGuard(_GUARD_KEY, self, self._plan, reservation,
                                      deadline_ns=deadline) as guard:
                answer = self._canonical_api.ProtectedCanonicalBootstrapWriter(
                    self.canonical_root).commit_initial_creation(guard, reservation)
                _fields(answer, {"schema", "state", "effect", "code", "reason", "actor_cid",
                                 "event_id", "receipt", "native_qualified"},
                        "CANONICAL_CORRELATION_MISMATCH")
                if answer["state"] == "unknown" or answer["effect"] == "possible":
                    raise HostAuthorityError("PROVIDER_OUTCOME_UNKNOWN",
                                             "INITIAL publication outcome is unknown")
                _require(answer["state"] == "recorded"
                         and answer["effect"] == "canonical_initial_creation"
                         and answer["native_qualified"] is False,
                         "ROLE_OPERATION_FORBIDDEN", "only a newly recorded INITIAL may bind")
                initial = self._initial_projection(guard, reservation, answer["receipt"])
                _require(answer["actor_cid"] == initial["actor_cid"]
                         and answer["event_id"] == initial["initial_event_id"],
                         "CANONICAL_CORRELATION_MISMATCH", "INITIAL result correlation changed")
                deadline = min(deadline, reservation.witness["expires_monotonic_ns"])
                reservation._stage = "binding"
            # Canonical exclusion and the active lexical H fence have exited.
            _require(time.monotonic_ns() < deadline, "HOST_PROTOCOL_TIMEOUT",
                     "original initial deadline expired")
            sent = True  # No later failure can imply a safe control retry.
            result = self._exchange("bind_initial", {
                "deadline_monotonic_ns": deadline, "initial": initial}, deadline / 1000000000)
            _fields(result, {"actor_cid", "state"}, "HOST_PROTOCOL_ERROR")
            _require(result["actor_cid"] == reservation.actor_cid and result["state"] == "bound",
                     "HOST_PROTOCOL_ERROR", "invalid initial binding reply")
            self._initial_lock(deadline)
            try:
                self._initial_owner_current()
                _require(time.monotonic_ns() < deadline, "HOST_PROTOCOL_TIMEOUT",
                         "original initial deadline expired")
                context = BoundInitialEnrollment(_BOUND_INITIAL_KEY, self, reservation, initial, deadline)
                self._bound_initials.add(context)
                reservation._stage = "bound"
                return context
            finally:
                self._lock.release()
        except HostAuthorityError as exc:
            reservation._stage = "unknown" if sent or exc.code == "PROVIDER_OUTCOME_UNKNOWN" else "refused"
            if sent or exc.code == "PROVIDER_OUTCOME_UNKNOWN":
                self._initial_unknown(exc)
            raise
        except (OSError, ValueError) as exc:
            reservation._stage = "unknown" if sent else "refused"
            if sent:
                self._initial_unknown(exc)
            raise HostAuthorityError("CANONICAL_API_UNAVAILABLE", "canonical producer is unavailable") from exc

    def start_initial(self, context):
        """Consume the exact local bound context once; never renew its deadline."""
        self._initial_owner_current()
        _require(type(context) is BoundInitialEnrollment and context._owner() is self
                 and context in self._bound_initials and context._epoch == self._epoch
                 and context._nonce == self._nonce,
                 "ROLE_OPERATION_FORBIDDEN", "foreign initial context")
        reservation, deadline = context._reservation, context._deadline
        self._initial_reservation(reservation)
        self._initial_lock(deadline)
        try:
            _require(context._stage == "bound", "HOST_CALL_CONFLICT", "initial start was already issued")
            context._stage = reservation._stage = "issued"  # Irrevocable, even on pre-send expiry.
            _require(time.monotonic_ns() < deadline, "HOST_PROTOCOL_TIMEOUT",
                     "original initial deadline expired")
        finally:
            self._lock.release()
        sent = False
        try:
            with InitialCreationGuard(_GUARD_KEY, self, self._plan, reservation,
                                      deadline_ns=deadline) as guard:
                initial = self._initial_projection(guard, reservation)
                _require(_same_data(initial, context._initial), "CANONICAL_CORRELATION_MISMATCH",
                         "bound INITIAL projection changed")
            _require(time.monotonic_ns() < deadline, "HOST_PROTOCOL_TIMEOUT",
                     "original initial deadline expired")
            sent = True
            start_before = time.monotonic_ns()
            result = self._exchange("start_initial", {
                "actor_cid": context.actor_cid,
                "initial_event_id": context._initial["initial_event_id"],
                "deadline_monotonic_ns": deadline}, deadline / 1000000000)
            _fields(result, {"actor_cid", "state"}, "HOST_PROTOCOL_ERROR")
            _require(result["actor_cid"] == context.actor_cid and result["state"] == "started",
                     "HOST_PROTOCOL_ERROR", "invalid initial start reply")
            _require(time.monotonic_ns() < deadline, "HOST_PROTOCOL_TIMEOUT",
                     "original initial deadline expired")
            self._started[context.actor_cid] = (context, start_before, time.monotonic_ns())
            return dict(result)  # Inert observation, never LIVE enrollment or an effect grant.
        except HostAuthorityError as exc:
            if sent:
                context._stage = reservation._stage = "unknown"
                self._initial_unknown(exc)
            raise
        except (OSError, ValueError) as exc:
            if sent:
                context._stage = reservation._stage = "unknown"
                self._initial_unknown(exc)
            raise HostAuthorityError("CANONICAL_API_UNAVAILABLE", "canonical producer is unavailable") from exc

    def open_live_session(self, actor_cid):
        """Enroll one actually started actor using fixed protected source/profile bytes."""
        self._initial_owner_current()
        _require(type(actor_cid) is str and actor_cid in self._started,
                 "ROLE_OPERATION_FORBIDDEN", "LIVE requires an observed owned start")
        _require(self._active_guard is None, "ROLE_OPERATION_FORBIDDEN",
                 "LIVE enrollment is forbidden inside a host fence")
        deadline = time.monotonic_ns() + MAX_WAIT_SECONDS * 10**9
        try:
            self._prove_current()
            context, lower, upper = self._started[actor_cid]
            actor = self._policy["actors"][actor_cid]
            raw = _protected_bytes(self._deployment["role_ceiling_ref"]["path"],
                                   self._owners, self._model_uid)
            mapping = _json_bytes(raw)
            _fields(mapping, {"schema", "profiles"}, "HOST_PROFILE_UNQUALIFIED")
            _require(mapping["schema"] == "aegis.protected-role-profiles/v1"
                     and type(mapping["profiles"]) is list
                     and 0 < len(mapping["profiles"]) <= 128, "HOST_PROFILE_UNQUALIFIED")
            selected, seen = [], set()
            for row in mapping["profiles"]:
                _fields(row, {"role", "canonical_profile_sha256", "runtime_profile_sha256",
                              "runtime_profile", "tool_ceiling"}, "HOST_PROFILE_UNQUALIFIED")
                _require(type(row["role"]) is str and row["role"] in _ROLES
                         and _sha(row["canonical_profile_sha256"])
                         and _sha(row["runtime_profile_sha256"]), "HOST_PROFILE_UNQUALIFIED")
                key = (row["role"], row["canonical_profile_sha256"])
                _require(key not in seen, "HOST_PROFILE_UNQUALIFIED", "ambiguous protected role map")
                seen.add(key)
                if key == (actor["role"], _digest(actor["profile"])):
                    selected.append(row)
            _require(len(selected) == 1, "HOST_PROFILE_UNQUALIFIED", "LIVE profile is not mapped")
            row = selected[0]
            _check_native_profile(row["runtime_profile"])
            _require(row["runtime_profile_sha256"] == _digest(row["runtime_profile"])
                     and _same_data(row["tool_ceiling"], _DECISION_TOOL), "HOST_PROFILE_UNQUALIFIED")
            # The canonical writer and its locking/publication helper are part of
            # the protected host closure, not trusted merely by a module name.
            for name in ("hierarchy_lifecycle.py", "hierarchy_mailbox.py"):
                _require(str(Path(__file__).with_name(name).resolve()) in self._files,
                         "HOST_PROFILE_UNQUALIFIED", "LIVE canonical source closure is incomplete")
            self._initial_lock(deadline)
            try:
                _require(actor_cid not in self._live_attempts, "HOST_CALL_CONFLICT",
                         "LIVE enrollment was already attempted")
                self._live_attempts.add(actor_cid)
            finally:
                self._lock.release()
            with InitialCreationGuard(_GUARD_KEY, self, self._plan, context._reservation,
                                      deadline_ns=deadline) as guard:
                initial = self._initial_projection(guard, context._reservation)
                _require(_same_data(initial, context._initial), "CANONICAL_CORRELATION_MISMATCH")
            result = self._exchange("describe_live", {"actor_cid": actor_cid},
                                    deadline / 10**9, schema=_LIVE_SCHEMA)
            projection = _check_live_description(self, actor_cid, result, row, lower, upper)
            deadline = min(deadline, projection["actor_deadline_monotonic_ns"])
            if self._appserver is None:
                self._appserver = _AppserverIO(self)
                self._appserver._bound_deadline = deadline / 10**9
                self._appserver.initialize()
            result = self._exchange("enroll_live", {
                "actor_cid": actor_cid, "generation": actor["generation"],
                "policy_sha256": initial["policy_sha256"],
                "initial_event_id": initial["initial_event_id"],
                "initial_event_sha256": initial["initial_event_sha256"],
                "runtime_profile_sha256": row["runtime_profile_sha256"],
                "deadline_monotonic_ns": deadline}, deadline / 10**9, schema=_LIVE_SCHEMA)
            _require(_same_data(result, {"actor_cid": actor_cid, "generation": actor["generation"],
                                         "state": "enrolled"}), "HOST_PROTOCOL_ERROR")
            _require(time.monotonic_ns() < deadline, "HOST_PROTOCOL_TIMEOUT",
                     "original LIVE enrollment deadline expired")
            session = HostSession(_LIVE_KEY, self, projection, initial)
            self._live_sessions[actor_cid] = session
            return session
        except BaseException:
            self.close()
            raise

    @property
    def owned_runtime(self):
        self._require_owner_process()
        return self

    @property
    def authority(self):
        self._require_owner_process()
        return self._authority

    @property
    def canonical_root(self):
        self._require_owner_process()
        return Path(self._deployment["canonical_root"])

    @property
    def channel_witness(self):
        self._require_owner_process()
        return copy.deepcopy(self._channel)

    @property
    def policy(self):
        self._require_owner_process()
        return copy.deepcopy(self._policy)

    @property
    def approved_plan(self):
        self._require_owner_process()
        return copy.deepcopy(self._plan)

    @property
    def approved_plan_ref(self):
        return self.approved_plan

    @property
    def accepted_plan(self):
        self._require_owner_process()
        if self._policy is None:
            return None
        return {key: copy.deepcopy(self._policy[key])
                for key in ("source", "actors", "current", "successors")}

    @property
    def reservations(self):
        self._require_owner_process()
        return self._reservations

    def close(self):
        """Revoke now: fence every owned descriptor, then retire local state.

        The fence never waits for a reply, only for one in-progress
        non-blocking syscall, so an in-flight exchange fails promptly and no
        I/O follows on a released descriptor number. Retiring state then waits
        only for a section that is already exiting, such as a guarded
        publication, so no guarded write completes after close returns.
        """
        self._require_owner_process()
        self._closed = True  # Every currentness check refuses from here on.
        try:
            self._fence()
        finally:
            with self._lock:
                if not self._retired:
                    self._retired = True
                    for session in self._live_sessions.values():
                        session._invalidate()
                    _OWNED_BINDINGS.discard(self)

    def _decision_history_unknown(self):
        """Refuse a repeat decision entry, because an earlier scope may have published.

        Same rule as dispatch_decision's history check: the outcome stays
        unknown, never a fresh write and never a no-effect refusal. Closing the
        owner retires the session, which marks the call unknown.
        """
        cause = None
        if os.getpid() == self._host_pid:
            try:
                self.close()
            except OSError as exc:
                cause = exc
        raise HostAuthorityError("PROVIDER_OUTCOME_UNKNOWN",
                                 "canonical decision outcome is unresolved") from cause

    def _fence(self):
        with self._io_gate:
            self._fenced = True
            for io in (getattr(self, "_wire", None), self._appserver):
                if io is not None:
                    io._closed = True
            with ExitStack() as cleanup:
                for stream in (self._control, self._reader, self._writer):
                    if hasattr(stream, "close"):
                        cleanup.callback(stream.close)


def _check_native_profile(profile):
    """Validate the closed projection before hashing or copying its values."""
    keys = {"model", "reasoning_effort", "service_tier", "approval_policy", "approvals_reviewer",
            "permission_profile", "effective_permission_profile", "file_system_sandbox_policy",
            "network_sandbox_policy", "workspace_roots", "allow_login_shell",
            "shell_environment_policy", "windows_sandbox_mode", "windows_sandbox_type",
            "tool_policy", "session_isolation", "provider_binding_sha256"}
    _fields(profile, keys, "HOST_PROFILE_UNQUALIFIED")
    env = profile["shell_environment_policy"]
    _fields(env, {"inherit", "ignore_default_excludes", "exclude", "set", "include_only", "use_profile"},
            "HOST_PROFILE_UNQUALIFIED")
    # Do not iterate, copy, hash, log or emit any nonempty set's values.
    _require(type(env["set"]) is dict and not env["set"], "HOST_PROFILE_UNQUALIFIED",
             "environment overrides are unsupported")
    _require(_same_data(env, {"inherit": "none", "ignore_default_excludes": False,
                              "exclude": [], "set": {}, "include_only": [], "use_profile": False}),
             "HOST_PROFILE_UNQUALIFIED", "environment policy is unsupported")
    for name in ("model", "reasoning_effort", "approval_policy", "approvals_reviewer",
                 "network_sandbox_policy", "windows_sandbox_type", "session_isolation"):
        _require(_text(profile[name]), "HOST_PROFILE_UNQUALIFIED")
    _require(profile["service_tier"] is None or _text(profile["service_tier"]),
             "HOST_PROFILE_UNQUALIFIED")
    _require(profile["windows_sandbox_mode"] is None or _text(profile["windows_sandbox_mode"]),
             "HOST_PROFILE_UNQUALIFIED")
    _require(type(profile["allow_login_shell"]) is bool
             and type(profile["workspace_roots"]) is list
             and all(_text(root, 4096) and Path(root).is_absolute() for root in profile["workspace_roots"])
             and _sha(profile["provider_binding_sha256"]), "HOST_PROFILE_UNQUALIFIED")
    for name in ("permission_profile", "effective_permission_profile", "file_system_sandbox_policy"):
        _require(type(profile[name]) is dict, "HOST_PROFILE_UNQUALIFIED")
    tool = profile["tool_policy"]
    _fields(tool, {"allowed_tools", "require_managed_sandbox", "require_unified_exec",
                   "expose_additional_permissions"}, "HOST_PROFILE_UNQUALIFIED")
    _require(_same_data(tool["allowed_tools"], _DECISION_TOOL)
             and all(type(tool[name]) is bool for name in (
                 "require_managed_sandbox", "require_unified_exec", "expose_additional_permissions")),
             "HOST_PROFILE_UNQUALIFIED")
    stack = [profile]
    while stack:
        value = stack.pop()
        _require(type(value) is not float, "HOST_PROFILE_UNQUALIFIED")
        if type(value) is dict:
            stack.extend(value.values())
        elif type(value) is list:
            stack.extend(value)


def _check_live_description(owner, cid, result, row, lower, upper):
    _fields(result, {"actor", "runtime_record"}, "HOST_PROTOCOL_ERROR")
    record, actor = result["runtime_record"], result["actor"]
    expected = {"schema": "aegis.protected-runtime-binding/v1",
                "runtime_instance": owner._process, "appserver_instance": owner._process,
                "channel": {key: owner._channel[key] for key in (
                    "read_pipe_inode", "write_pipe_inode", "epoch")},
                "runtime_source": {"commit": owner._policy["source"]["commit"],
                                   "tree": owner._policy["source"]["tree"],
                                   "executable_sha256": owner._deployment["runtime_executable"]["sha256"]},
                "tool_ceiling": row["tool_ceiling"]}
    _fields(record, set(expected) | {"control_methods"}, "HOST_PROTOCOL_ERROR")
    _require(all(_same_data(record[k], v) for k, v in expected.items()),
             "CANONICAL_CORRELATION_MISMATCH", "LIVE runtime source or channel changed")
    methods = record["control_methods"]
    _require(type(methods) is list and len(methods) == len(_LIVE_METHODS)
             and all(type(method) is str for method in methods)
             and set(methods) == set(_LIVE_METHODS), "HOST_PROFILE_UNQUALIFIED")
    _fields(actor, {"actor_cid", "role", "generation", "profile_sha256", "runtime_profile_sha256",
                    "runtime_profile", "actor_started_monotonic_ns", "actor_deadline_monotonic_ns"},
            "HOST_PROTOCOL_ERROR")
    canonical = owner._policy["actors"][cid]
    expected_actor = {"actor_cid": cid, "role": canonical["role"],
                      "generation": canonical["generation"], "profile_sha256": _digest(canonical["profile"]),
                      "runtime_profile_sha256": row["runtime_profile_sha256"]}
    _require(all(_same_data(actor[k], v) for k, v in expected_actor.items()),
             "CANONICAL_CORRELATION_MISMATCH", "LIVE actor does not match owned INITIAL")
    _check_native_profile(actor["runtime_profile"])
    _require(_same_data(actor["runtime_profile"], row["runtime_profile"])
             and _digest(actor["runtime_profile"]) == row["runtime_profile_sha256"],
             "HOST_PROFILE_UNQUALIFIED", "LIVE native profile does not match protected map")
    start, end = actor["actor_started_monotonic_ns"], actor["actor_deadline_monotonic_ns"]
    _require(_uint(start) and _uint(end) and lower <= start <= upper
             and end == start + canonical["cap_seconds"] * 10**9
             and time.monotonic_ns() < end, "STALE_INVOCATION", "original actor budget is unavailable")
    return copy.deepcopy(actor)


class _AppserverIO(ProtocolClient):
    def __init__(self, owner):
        self._owner, self._bound_deadline = owner, 0
        self._opening = True
        try:
            # A fence cannot interleave with descriptor setup on these pipes.
            with owner._io_gate:
                _require(not owner._fenced, "STALE_INVOCATION", "runtime binding is closed")
                super().__init__(owner._reader, owner._writer)
        finally:
            self._opening = False

    def _transport_gate(self):
        return self._owner._io_gate

    def _revoked(self):
        return self._closed or self._owner._fenced

    def _operation_deadline(self):
        return min(super()._operation_deadline(), self._bound_deadline)

    def close(self):
        if self._opening:
            # Never wait on the binding lock while holding its gate. The
            # constructor's caller closes the binding after this unwinds.
            self._closed = True
            return
        self._owner.close()


class _NonTransferable:
    def __copy__(self):
        raise TypeError("owned LIVE objects cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("owned LIVE objects cannot be copied")

    def __reduce_ex__(self, protocol):
        raise TypeError("owned LIVE objects cannot be serialized")


class HostInvocation(_NonTransferable):
    """One actual received frame, interned only after owned pending readback."""

    def __init__(self, key, session, frame, projection):
        _require(key is _LIVE_KEY and type(session) is HostSession,
                 "ROLE_OPERATION_FORBIDDEN", "invocation requires an owned pending call")
        self._session = session
        self._frame, self._projection = copy.deepcopy(frame), copy.deepcopy(projection)
        self._stage, self._dispatching, self._completion = "pending", False, None
        self._writer_entered, self._dispatch_returned = False, False
        self._dispatch_issued, self._reply_issued = False, False
        self._scope_depth = 0
        self._scope_entered = False

    @property
    def actor_cid(self):
        return self._session.actor_cid

    @property
    def rpc_id(self):
        return self._frame["id"]

    @property
    def event_id(self):
        return self._projection["event_id"]

    @property
    def decision_recovery_event_id(self):
        return self._projection["original_event_id"]

    def _current(self):
        self._session._current()
        _require(self in self._session._pending and self._stage == "pending"
                 and time.monotonic_ns() < self._projection["call_deadline_monotonic_ns"],
                 "STALE_INVOCATION", "pending invocation is no longer current")


class HostSession(_NonTransferable):
    """Process-local LIVE enrollment; arguments and results remain inert data."""

    def __init__(self, key, owner, actor, initial):
        _require(key is _LIVE_KEY and type(owner) is OwnedHostBinding and owner in _OWNED_BINDINGS,
                 "ROLE_OPERATION_FORBIDDEN", "session requires an owned LIVE enrollment")
        self._owner = owner
        self._actor, self._initial = copy.deepcopy(actor), copy.deepcopy(initial)
        self._epoch, self._nonce = owner._epoch, owner._nonce
        self._pending, self._writer = set(), None

    @property
    def actor_cid(self):
        return self._actor["actor_cid"]

    @property
    def owned_runtime(self):
        self._current()
        return self._owner

    @property
    def authority(self):
        self._current()
        return self._owner.authority

    def _current(self):
        owner = self._owner
        owner._initial_owner_current()
        _require(owner._live_sessions.get(self.actor_cid) is self
                 and owner._epoch == self._epoch and owner._nonce == self._nonce
                 and time.monotonic_ns() < self._actor["actor_deadline_monotonic_ns"],
                 "STALE_INVOCATION", "LIVE session is no longer current")

    def _invalidate(self):
        for invocation in self._pending:
            if (invocation._scope_entered or invocation._dispatching
                    or invocation._stage == "unknown"):
                invocation._stage = "unknown"  # Never quiescence or custody release.
            else:
                invocation._stage = "retired"

    def receive_invocation(self):
        owner = self._owner
        self._current()
        _require(owner._active_guard is None, "ROLE_OPERATION_FORBIDDEN",
                 "appserver IPC is forbidden inside a host fence")
        deadline = min(time.monotonic_ns() + MAX_WAIT_SECONDS * 10**9,
                       self._actor["actor_deadline_monotonic_ns"])
        try:
            owner._prove_current()
            owner._appserver._bound_deadline = deadline / 10**9
            frame = owner._appserver.receive_call()
            received = time.monotonic_ns()
            params = frame["params"]
            _require(params["threadId"] == self.actor_cid
                     and params.get("namespace") in (None, "", "functions")
                     and params["tool"] == "aegis_decision", "ROLE_OPERATION_FORBIDDEN",
                     "call is outside the enrolled decision ceiling")
            arguments = params["arguments"]
            _require(type(arguments) is dict and type(arguments.get("event_id")) is str
                     and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,79}", arguments["event_id"]) is not None,
                     "HOST_PROTOCOL_ERROR", "call has no bounded decision correlation")
            correlation = {"actor_cid": self.actor_cid, "rpc_id": frame["id"],
                           "thread_id": params["threadId"], "turn_id": params["turnId"],
                           "call_id": params["callId"], "namespace": params.get("namespace"),
                           "tool": params["tool"], "event_id": arguments["event_id"]}
            projection = owner._exchange("pending_call", {
                **correlation, "deadline_monotonic_ns": deadline}, deadline / 10**9, schema=_LIVE_SCHEMA)
            _fields(projection, set(correlation) | {
                "role", "generation", "profile_sha256", "runtime_profile_sha256", "epoch",
                "actor_started_monotonic_ns", "actor_deadline_monotonic_ns",
                "call_started_monotonic_ns", "call_deadline_monotonic_ns", "mode",
                "original_event_id", "recovery_of"}, "HOST_PROTOCOL_ERROR")
            expected = {**correlation, "epoch": self._epoch,
                        **{key: self._actor[key] for key in (
                            "role", "generation", "profile_sha256", "runtime_profile_sha256",
                            "actor_started_monotonic_ns", "actor_deadline_monotonic_ns")}}
            _require(all(_same_data(projection[key], value) for key, value in expected.items()),
                     "CANONICAL_CORRELATION_MISMATCH", "pending call does not match received frame")
            start, end = projection["call_started_monotonic_ns"], projection["call_deadline_monotonic_ns"]
            _require(_uint(start) and _uint(end)
                     and self._actor["actor_started_monotonic_ns"] <= start <= received
                     and time.monotonic_ns() < end <= min(
                         deadline, start + MAX_WAIT_SECONDS * 10**9,
                         self._actor["actor_deadline_monotonic_ns"]),
                     "STALE_INVOCATION", "original call budget is unavailable")
            if projection["mode"] == "normal":
                _require(projection["original_event_id"] is None and projection["recovery_of"] is None,
                         "CANONICAL_CORRELATION_MISMATCH")
            else:
                _require(projection["mode"] == "original_only"
                         and projection["original_event_id"] == correlation["event_id"],
                         "CANONICAL_CORRELATION_MISMATCH")
                originals = [old for old in self._pending if old._stage == "unknown"
                             and _same_data(projection["recovery_of"], {
                                 **{k: old._projection[k] for k in correlation}, "epoch": self._epoch})]
                _require(len(originals) == 1, "STALE_INVOCATION",
                         "recovery has no actual owned original unknown call")
            self._current()
            invocation = HostInvocation(_LIVE_KEY, self, frame, projection)
            self._pending.add(invocation)
            return invocation
        except BaseException:
            owner.close()
            raise

    def dispatch_decision(self, invocation, command):
        """Call the fixed real N1 writer; retain completion independently of returned data."""
        self._current()
        _require(type(invocation) is HostInvocation and invocation._session is self,
                 "ROLE_OPERATION_FORBIDDEN", "decision requires this session's invocation")
        invocation._current()
        _require(self._owner._active_guard is None and not invocation._dispatching,
                 "ROLE_OPERATION_FORBIDDEN", "decision dispatch is already active")
        self._owner._initial_lock(invocation._projection["call_deadline_monotonic_ns"])
        try:
            invocation._current()
            _require(self._owner._active_guard is None and not invocation._dispatch_issued,
                     "HOST_CALL_CONFLICT", "decision dispatch was already issued")
            invocation._dispatch_issued = True
            prior_scope_entered = invocation._scope_entered
            if prior_scope_entered:
                invocation._stage = "unknown"
        finally:
            self._owner._lock.release()
        if prior_scope_entered:
            self._owner.close()
            raise HostAuthorityError("PROVIDER_OUTCOME_UNKNOWN",
                                     "canonical decision outcome is unresolved")
        original = invocation._frame["params"]["arguments"]
        if (type(command) is not dict or not all(type(key) is str for key in command) or set(command) != {
                "event_id", "request_id", "request_sha256", "decision", "reason"}
                or not _same_data(command, original)):
            invocation._completion = _PreDispatchRefusal(_LIVE_KEY, invocation)
            invocation._stage = "complete"
            raise HostAuthorityError("STALE_INVOCATION", "decision arguments do not match owned call")
        api = self._owner._canonical_api
        if not hasattr(api, "ProtectedCanonicalDecisionWriter"):
            invocation._completion = _PreDispatchRefusal(_LIVE_KEY, invocation)
            invocation._stage = "complete"
            raise HostAuthorityError("CANONICAL_API_UNAVAILABLE", "canonical decision producer is unavailable")
        # Neither the constructor, root, authority nor dispatch callback is supplied
        # by D/model arguments. This source file and N1 are in the protected closure.
        if self._writer is None:
            self._writer = api.ProtectedCanonicalDecisionWriter(self._owner.canonical_root, self.authority)
        _require(type(self._writer) is api.ProtectedCanonicalDecisionWriter,
                 "CANONICAL_API_UNAVAILABLE", "canonical decision producer changed")
        invocation._dispatching, invocation._writer_entered = True, True
        try:
            result = self._writer.commit_decision(invocation, copy.deepcopy(original))
            invocation._dispatching = False
            _check_decision_result(result, original)
            _require(invocation._scope_depth == 0
                     and self._owner._active_guard is None,
                     "PROVIDER_OUTCOME_UNKNOWN", "decision scopes have not exited")
            invocation._dispatch_returned = True
            invocation._completion = _DecisionCompletion(_LIVE_KEY, invocation, result)
            invocation._stage = "unknown" if result["state"] == "unknown" else "complete"
            return copy.deepcopy(result)
        except BaseException as exc:
            invocation._dispatching = False
            invocation._stage = "unknown"
            self._owner.close()
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise HostAuthorityError("PROVIDER_OUTCOME_UNKNOWN",
                                     "canonical decision outcome is unresolved") from exc

    def reply(self, invocation, result):
        """Send data only after source-owned completion; a D result cannot mint proof."""
        self._current()
        owner = self._owner
        _require(owner._active_guard is None, "ROLE_OPERATION_FORBIDDEN",
                 "reply IPC is forbidden inside a host fence")
        _require(type(invocation) is HostInvocation and invocation._session is self
                 and invocation in self._pending
                 and invocation._stage in {"complete", "unknown"}
                 and type(invocation._completion) in {_DecisionCompletion, _PreDispatchRefusal}
                 and invocation._scope_depth == 0 and not invocation._dispatching,
                 "STALE_INVOCATION", "reply has no owned source completion")
        proof = invocation._completion
        deadline = invocation._projection["call_deadline_monotonic_ns"] / 10**9
        state = proof._result["state"] if type(proof) is _DecisionCompletion else None
        owner._initial_lock(invocation._projection["call_deadline_monotonic_ns"])
        try:
            _require(owner._active_guard is None and not invocation._reply_issued,
                     "HOST_CALL_CONFLICT", "decision reply was already issued")
            invocation._reply_issued = True
            invocation._stage = "unknown"  # Any subsequent I/O ambiguity retains R.
        finally:
            owner._lock.release()
        try:
            owner._prove_current()
            owner._appserver._bound_deadline = deadline
            owner._appserver.reply(invocation.rpc_id, result)
            projection = invocation._projection
            correlation = {key: projection[key] for key in (
                "actor_cid", "rpc_id", "thread_id", "turn_id", "call_id", "namespace", "tool", "event_id")}
            retired = owner._exchange("retire_call", {
                **correlation, "mode": projection["mode"], "recovery_of": projection["recovery_of"],
                "outcome": "unknown" if state == "unknown" else "replied", "canonical_state": state},
                deadline, schema=_LIVE_SCHEMA)
            _fields(retired, {"actor_cid", "rpc_id", "state"}, "HOST_PROTOCOL_ERROR")
            _require(retired["actor_cid"] == self.actor_cid
                     and _same_data(retired["rpc_id"], invocation.rpc_id)
                     and retired["state"] in {"awaiting_terminal", "retired", "publication_unknown"},
                     "HOST_PROTOCOL_ERROR", "invalid terminal observation")
            if state != "unknown" and retired["state"] != "publication_unknown":
                invocation._stage = "retired"
            # Do not clear old Unknown objects here. Runtime still owns actual
            # callback/Core terminal legs; this observation settles no resources.
            return copy.deepcopy(retired)
        except BaseException:
            owner.close()
            raise


class DecisionGuard(_OwnedGuard):
    """Local identity and original-target checks under H then canonical exclusion."""

    def __init__(self, key, owner, invocation):
        _require(type(invocation) is HostInvocation and invocation._session._owner is owner,
                 "ROLE_OPERATION_FORBIDDEN", "decision requires a LIVE HostInvocation")
        invocation._current()
        self._invocation = invocation
        super().__init__(key, owner, owner._plan,
                         deadline_ns=invocation._projection["call_deadline_monotonic_ns"])

    def _entry_current(self):
        self._invocation._current()

    def __enter__(self):
        super().__enter__()
        invocation = self._invocation
        if invocation._scope_entered:
            # Authoritative repeat of effect_fence's history check, for a call
            # that entered from another thread after this guard was built.
            invocation._stage = "unknown"
            self._active = False
            self._owner._active_guard = None
            self._owner._lock.release()
            self._owner._decision_history_unknown()
        invocation._scope_entered = True
        invocation._scope_depth += 1
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        result = super().__exit__(exc_type, exc_value, traceback)
        self._invocation._scope_depth -= 1
        return result

    def require_current(self, invocation, policy, state, request):
        self._local_current()
        _require(invocation is self._invocation, "ROLE_OPERATION_FORBIDDEN", "foreign pending invocation")
        invocation._current()
        session, cid = invocation._session, invocation.actor_cid
        _require(_same_data(policy, self._policy) and type(state) is dict,
                 "CANONICAL_CORRELATION_MISMATCH", "canonical policy differs from owned plan")
        actor = policy["actors"][cid]
        _require(actor["role"] == "root" and session._actor["role"] == "root",
                 "ROLE_OPERATION_FORBIDDEN", "decision requires current ROOT")
        _require(state.get("current", {}).get("root") == cid
                 and actor["generation"] == session._actor["generation"]
                 and _digest(actor["profile"]) == session._actor["profile_sha256"],
                 "STALE_INVOCATION", "canonical generation or custody changed")
        initial = session._initial
        receipt = {"event_id": initial["initial_event_id"], "sequence": initial["initial_sequence"],
                   "event_sha256": initial["initial_event_sha256"], "execution_enabled": False}
        creation = state.get("initial_bootstrap", {}).get("creations", {}).get(cid)
        _require(type(creation) is dict and creation.get("actor_cid") == cid
                 and _same_data(creation.get("receipt"), receipt)
                 and _same_data(state.get("receipts", {}).get(receipt["event_id"]), receipt)
                 and _digest(creation.get("envelope")) == receipt["event_sha256"],
                 "CANONICAL_CORRELATION_MISMATCH", "owned INITIAL receipt changed")
        if request is None:
            return  # Identity only; not NEW authority, expiry or canonical NEW cap.
        _require(type(request) is dict and type(request.get("request")) is dict,
                 "CANONICAL_CORRELATION_MISMATCH", "canonical target row is invalid")
        identifier = request["request"].get("id")
        _require(state.get("requests", {}).get(identifier) is request,
                 "CANONICAL_CORRELATION_MISMATCH", "target is not the actual fresh canonical row")
        actual = self._owner._canonical_api.validate_request(request["raw"])
        _require(_same_data(actual, request["request"])
                 and _same_data(actual["source"], policy["source"]),
                 "CANONICAL_CORRELATION_MISMATCH", "canonical target source binding changed")


class _PreDispatchRefusal(_NonTransferable):
    def __init__(self, key, invocation):
        _require(key is _LIVE_KEY and not invocation._writer_entered
                 and not invocation._scope_entered
                 and not invocation._dispatching and invocation._scope_depth == 0,
                 "ROLE_OPERATION_FORBIDDEN", "pre-dispatch proof is unavailable")
        self._invocation = invocation


class _DecisionCompletion(_NonTransferable):
    def __init__(self, key, invocation, result):
        _require(key is _LIVE_KEY and invocation._writer_entered and invocation._dispatch_returned
                 and not invocation._dispatching and invocation._scope_depth == 0,
                 "ROLE_OPERATION_FORBIDDEN", "decision completion is unavailable")
        self._invocation, self._result = invocation, copy.deepcopy(result)


def _check_decision_result(result, command):
    _fields(result, {"schema", "state", "effect", "code", "reason", "event_id", "request_id",
                     "request_sha256", "receipt", "native_qualified"}, "PROVIDER_OUTCOME_UNKNOWN")
    effects = {"recorded": "canonical_decision", "recovered": "none", "refused": "none", "unknown": "possible"}
    _require(type(result["state"]) is str and result["state"] in effects
             and result["effect"] == effects[result["state"]]
             and result["schema"] == "aegis.protected-decision-commit/v1"
             and result["native_qualified"] is False and _text(result["reason"], 1024)
             and all(_same_data(result[key], command[key]) for key in (
                 "event_id", "request_id", "request_sha256")), "PROVIDER_OUTCOME_UNKNOWN")
    if result["state"] in {"recorded", "recovered"}:
        receipt = result["receipt"]
        _fields(receipt, {"event_id", "sequence", "event_sha256", "execution_enabled"},
                "PROVIDER_OUTCOME_UNKNOWN")
        _require(result["code"] is None and receipt["event_id"] == command["event_id"]
                 and _uint(receipt["sequence"]) and _sha(receipt["event_sha256"])
                 and receipt["execution_enabled"] is False, "PROVIDER_OUTCOME_UNKNOWN")
    else:
        _require(result["receipt"] is None and _text(result["code"]), "PROVIDER_OUTCOME_UNKNOWN")
