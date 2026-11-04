"""Bounded Codex stdio client leaf, without enrollment or native authority.

No process is launched here. The caller owns the external process and hands
ownership of its two binary pipe streams to ProtocolClient. Frame/handshake
success authenticates neither a host principal nor an Aegis role/generation.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import select
import time


MAX_FRAME_BYTES = 1024 * 1024
MAX_DEPTH = 32
MAX_CALLS = 32
MAX_WAIT_SECONDS = 5
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
    """

    def __init__(self, reader, writer, *, timeout_seconds=MAX_WAIT_SECONDS,
                 max_frame_bytes=MAX_FRAME_BYTES):
        if os.name != "posix":
            raise HostAuthorityError("UNSUPPORTED_HOST", "bounded pipe transport requires POSIX")
        if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
                or not 0 < timeout_seconds <= MAX_WAIT_SECONDS
                or type(max_frame_bytes) is not int or not 0 < max_frame_bytes <= MAX_FRAME_BYTES):
            raise ValueError("invalid host transport limits")
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

    def close(self):
        """Close both owned streams; never signal a PID or infer quiescence."""
        if self._closed:
            return
        self._closed = True
        error = None
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
            left = deadline - time.monotonic()
            if left <= 0:
                self._fail("HOST_PROTOCOL_TIMEOUT", "host protocol deadline expired")
            try:
                readable, writable, _ = select.select(
                    [] if writing else [fd], [fd] if writing else [], [], left)
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
                chunk = os.read(self._read_fd, min(65536, self._maximum - len(self._buffer)))
            except (BlockingIOError, InterruptedError):
                continue
            except OSError as exc:
                try:
                    self._fail()
                except HostAuthorityError as error:
                    raise error from exc
            if not chunk:
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
                written = os.write(self._write_fd, raw[offset:])
            except (BlockingIOError, InterruptedError):
                continue
            except OSError as exc:
                try:
                    self._fail()
                except HostAuthorityError as error:
                    raise error from exc
            if written <= 0:
                self._fail()
            offset += written

    def initialize(self):
        self._live(initialized=False)
        if self._initialized:
            self._fail()
        deadline = time.monotonic() + self._timeout
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
        deadline = time.monotonic() + self._timeout
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
            deadline = time.monotonic() + self._timeout
            for identifier in row["aliases"].values():
                self._write({"id": identifier, "result": frozen}, deadline)
            row["result"] = frozen
        except HostAuthorityError as exc:
            if not self._closed:
                self._fail(exc.code, exc.reason)
            raise
