"""Bounded Codex stdio client leaf, without enrollment or native authority.

No process is launched here. The caller owns the external process and hands
ownership of its two binary pipe streams to ProtocolClient. Every frame,
handshake, or revocation anomaly is one HostAuthorityError with a fixed code,
reason, and next_action, and the client does not write after a refusal.
Frame length and container depth are refused before UTF-8 decoding or JSON
parsing. A completed frame authenticates neither a host principal nor a role.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import select
import threading
import time


MAX_FRAME_BYTES = 1024 * 1024
MAX_DEPTH = 32
MAX_CALLS = 32
MAX_WAIT_SECONDS = 5
# Longest a blocked wait goes without noticing revocation. Closing a
# descriptor does not wake a select already sleeping on it.
REVOCATION_POLL_SECONDS = 0.05
_REVOKED = object()
_AGAIN = object()
_OPEN = {0x7B: 0x7D, 0x5B: 0x5D}
_WHITESPACE = (0x20, 0x09, 0x0A, 0x0D)
_NEXT = {
    "UNSUPPORTED_HOST":
        "Retry on a POSIX host; the bounded pipe transport is unavailable here.",
    "UNPROTECTED_DEPLOYMENT":
        "Install the protected host deployment before retrying the host call.",
    "HOST_PROFILE_UNQUALIFIED":
        "Qualify the host profile before retrying the host call.",
    "HOST_PROTOCOL_ERROR":
        "Close the transport and retry with one bounded host protocol frame.",
    "HOST_PROTOCOL_TIMEOUT":
        "Close the transport and retry within the host protocol deadline.",
    "HOST_CALL_CONFLICT":
        "Close the transport and retry with a new call correlation.",
    "STALE_INVOCATION":
        "Retry only with a current enrolled invocation.",
    "ROLE_OPERATION_FORBIDDEN":
        "Retry with a role that is allowed to perform the operation.",
    "CANONICAL_CORRELATION_MISMATCH":
        "Retry with the canonical correlation for this invocation.",
    "CANONICAL_API_UNAVAILABLE":
        "Retry when the canonical host API is available.",
    "PROVIDER_OUTCOME_UNKNOWN":
        "Preserve the unknown provider outcome and do not retry the effect.",
    "PROVIDER_HANDLE_INVALID":
        "Retry with a valid provider handle.",
    "HISTORY_CURSOR_INVALID":
        "Retry with a valid history cursor.",
}
CODES = frozenset(_NEXT)

__all__ = [
    "CODES", "HostAuthorityError", "MAX_CALLS", "MAX_DEPTH", "MAX_FRAME_BYTES",
    "MAX_WAIT_SECONDS", "ProtocolClient", "REVOCATION_POLL_SECONDS",
]


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

    @property
    def next_action(self):
        return _NEXT[self._code]


def _invalid():
    raise HostAuthorityError("HOST_PROTOCOL_ERROR", "invalid host protocol frame")


def _text(value, maximum=256):
    return type(value) is str and 0 < len(value) <= maximum and "\x00" not in value


def _rpc_key(value):
    # JSON numbers and strings with the same spelling are different RPC ids.
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
    """Refuse a walk deeper than MAX_DEPTH, and any value JSON cannot encode."""
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_DEPTH:
            _invalid()
        kind = type(item)
        if kind is dict:
            for key, child in item.items():
                if type(key) is not str:
                    _invalid()
                stack.append((child, depth + 1))
        elif kind is list:
            stack.extend((child, depth + 1) for child in item)
        elif kind is float:
            if not math.isfinite(item):
                _invalid()
        elif kind is not str and kind is not int and kind is not bool and item is not None:
            _invalid()


def _container_has_child(raw, open_at):
    """True when the container just opened is not an empty {} or []."""
    close = _OPEN[raw[open_at]]
    index = open_at + 1
    length = len(raw)
    while index < length and raw[index] in _WHITESPACE:
        index += 1
    return index >= length or raw[index] != close


def _nesting_refused(raw):
    """Refuse before decode when a container would sit past the walk limit.

    The root container is scanner depth 1 and walk depth 0. Walk depth 32 is
    scanner depth 33: an empty container there is legal, and any child is not.
    Scanner depth 34 is walk depth 33 and is refused immediately. Braces
    inside strings do not count.
    """
    depth = 0
    in_string = False
    escaped = False
    limit = MAX_DEPTH + 1
    index = 0
    length = len(raw)
    while index < length:
        byte = raw[index]
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in _OPEN:
            depth += 1
            if depth > limit or (depth == limit and _container_has_child(raw, index)):
                return True
        elif byte in (0x7D, 0x5D) and depth:
            depth -= 1
        index += 1
    return False


def _frame_rejected(raw, maximum):
    if type(raw) is not bytes or not raw or len(raw) > maximum or raw[-1] != 10:
        return True
    return raw.find(10, 0, len(raw) - 1) != -1


def _decode(raw, maximum=MAX_FRAME_BYTES):
    if _frame_rejected(raw, maximum) or _nesting_refused(raw):
        _invalid()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=_constant)
    except HostAuthorityError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        # Parser text can quote the frame. Drop it; the refusal stays fixed.
        raise HostAuthorityError("HOST_PROTOCOL_ERROR", "invalid host protocol frame") from None
    _bounded(value)
    if type(value) is not dict:
        _invalid()
    return value


def _call(value):
    if set(value) != {"id", "method", "params"} or value["method"] != "item/tool/call":
        _invalid()
    _rpc_key(value["id"])
    params = value["params"]
    required = {"threadId", "turnId", "callId", "tool", "arguments"}
    if (type(params) is not dict or not required <= set(params)
            or not set(params) <= required | {"namespace"}):
        _invalid()
    if not all(_text(params[key]) for key in ("threadId", "turnId", "callId", "tool")):
        _invalid()
    if params.get("namespace") is not None and not _text(params["namespace"]):
        _invalid()
    return value


def _string_size(text, ceiling):
    """ASCII JSON string length, quotes included, without building the text."""
    total = 2
    for char in text:
        code = ord(char)
        if char in '"\\\b\f\n\r\t':
            total += 2
        elif code < 0x20 or code > 0x7E:
            total += 12 if code > 0xFFFF else 6
        else:
            total += 1
        if total > ceiling:
            return total
    return total


def _int_size(item, ceiling):
    """Decimal length. A value that cannot fit is refused before str()."""
    if item == 0:
        return 1
    # floor((bits - 1) * log10(2)) + 1 lower-bounds the digits; log10(2) > 0.30102.
    bits = item.bit_length()
    lower = (1 if item < 0 else 0) + ((bits - 1) * 30102) // 100000 + 1
    if lower > ceiling:
        return lower
    try:
        return len(str(item))
    except ValueError:
        _invalid()


def _json_size(value, maximum):
    """Compact ASCII JSON size. Stops once the size passes maximum.

    Depth is refused before this walk, so a hostile nest is never encoded.
    """
    _bounded(value)

    def walk(item):
        kind = type(item)
        if kind is dict:
            total = 2
            index = 0
            for key, child in item.items():
                if type(key) is not str:
                    _invalid()
                if index:
                    total += 1
                index += 1
                total += _string_size(key, maximum) + 1 + walk(child)
                if total > maximum:
                    return total
            return total
        if kind is list:
            total = 2
            for index, child in enumerate(item):
                if index:
                    total += 1
                total += walk(child)
                if total > maximum:
                    return total
            return total
        if kind is str:
            return _string_size(item, maximum)
        if kind is bool:
            return 4 if item else 5
        if kind is int:
            return _int_size(item, maximum)
        if item is None:
            return 4
        if kind is float:
            try:
                return len(json.dumps(item, allow_nan=False))
            except ValueError:
                _invalid()
        _invalid()

    return walk(value)


def _encode(value, maximum):
    # The trailing newline is part of the frame. Refuse before dumps builds it.
    if _json_size(value, maximum) + 1 > maximum:
        _invalid()
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
    if len(raw) > maximum:
        _invalid()
    return raw


def _fingerprint(params):
    body = json.dumps(params, sort_keys=True, ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _freeze_reply(result, maximum):
    if (type(result) is not dict or set(result) != {"success", "contentItems"}
            or type(result["success"]) is not bool
            or type(result["contentItems"]) is not list
            or len(result["contentItems"]) > 64):
        _invalid()
    for item in result["contentItems"]:
        if (type(item) is not dict or set(item) != {"type", "text"}
                or item["type"] != "inputText" or type(item["text"]) is not str):
            _invalid()
    if _json_size(result, maximum) > maximum:
        _invalid()
    return json.loads(json.dumps(
        result, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False))


class ProtocolClient:
    """Single-owner POSIX pipe client; no callbacks, process launch, or grants.

    Reader and writer streams are closed on a terminal protocol error or
    close(). The process owner reaps its own child. At most MAX_CALLS distinct
    call identities are retained; an old call is never treated as new.
    Revocation is a fence, not a drain: it takes the same gate as every
    read and write, so no later call uses a descriptor number another file
    may have reused. Bytes already written keep an unknown outcome.
    """

    def __init__(self, reader, writer, *, timeout_seconds=MAX_WAIT_SECONDS,
                 max_frame_bytes=MAX_FRAME_BYTES):
        # Platform refusal matches the legacy leaf and runs before any stream use.
        # Numeric limits are checked only once the host can own a pipe.
        if os.name != "posix":
            raise HostAuthorityError(
                "UNSUPPORTED_HOST", "bounded pipe transport requires POSIX")
        if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
                or not 0 < timeout_seconds <= MAX_WAIT_SECONDS
                or type(max_frame_bytes) is not int
                or not 0 < max_frame_bytes <= MAX_FRAME_BYTES):
            raise ValueError("invalid host transport limits")
        self._gate = self._transport_gate()
        self._reader = reader
        self._writer = writer
        self._closed = False
        self._initialized = False
        self._timeout = timeout_seconds
        self._maximum = max_frame_bytes
        self._buffer = b""
        self._calls = {}
        self._ids = {}
        try:
            self._adopt()
        except HostAuthorityError:
            self.close()
            raise
        except (OSError, ValueError, AttributeError) as exc:
            self.close()
            raise HostAuthorityError(
                "HOST_PROTOCOL_ERROR", "invalid host protocol frame") from exc

    @property
    def closed(self):
        return self._closed

    def _transport_gate(self):
        return threading.RLock()

    def _revoked(self):
        return self._closed

    def _adopt(self):
        self._read_fd = self._reader.fileno()
        self._write_fd = self._writer.fileno()
        if self._read_fd == self._write_fd:
            _invalid()
        os.set_blocking(self._read_fd, False)
        os.set_blocking(self._write_fd, False)

    def _guarded(self, operation, *args):
        """Run one non-blocking syscall on an owned descriptor, never after revocation."""
        with self._gate:
            if self._revoked():
                return _REVOKED
            return operation(*args)

    def close(self):
        """Close both owned streams. Never signal a process id."""
        error = None
        with self._gate:
            if self._closed:
                return
            self._closed = True
            for stream in (self._writer, self._reader):
                closer = getattr(stream, "close", None)
                if not callable(closer):
                    continue
                try:
                    closer()
                except OSError as exc:
                    if error is None:
                        error = exc
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
                readable, writable, _unused = select.select(
                    [] if writing else [fd], [fd] if writing else [], [],
                    min(left, REVOCATION_POLL_SECONDS))
            except InterruptedError:
                continue
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
                raw = self._buffer[:end + 1]
                self._buffer = self._buffer[end + 1:]
                try:
                    return _decode(raw, self._maximum)
                except HostAuthorityError:
                    self._fail()
            if len(self._buffer) >= self._maximum:
                self._fail()
            self._wait(self._read_fd, deadline)
            chunk = self._take()
            if chunk is _AGAIN:
                continue
            if chunk is _REVOKED or not chunk:
                self._fail()
            self._buffer += chunk

    def _take(self):
        try:
            return self._guarded(
                os.read, self._read_fd, min(65536, self._maximum - len(self._buffer)))
        except (BlockingIOError, InterruptedError):
            return _AGAIN
        except OSError as exc:
            try:
                self._fail()
            except HostAuthorityError as error:
                raise error from exc

    def _encode_frame(self, value):
        """One complete frame, including its newline. A refusal closes both streams.

        Every write goes through here. An encoding HostAuthorityError is terminal
        in this primitive, before any caller can leave it on an open transport.
        """
        try:
            return _encode(value, self._maximum)
        except HostAuthorityError as exc:
            self._fail(exc.code, exc.reason)
        except (ValueError, RecursionError, UnicodeError):
            self._fail()

    def _send_frame(self, raw, deadline):
        view = memoryview(raw)
        offset = 0
        while offset < len(raw):
            self._wait(self._write_fd, deadline, writing=True)
            written = self._send(view[offset:])
            if written is _AGAIN:
                continue
            if written is _REVOKED or written <= 0:
                self._fail()
            offset += written

    def _write(self, value, deadline):
        self._send_frame(self._encode_frame(value), deadline)

    def _send(self, payload):
        try:
            return self._guarded(os.write, self._write_fd, payload)
        except (BlockingIOError, InterruptedError):
            return _AGAIN
        except OSError as exc:
            try:
                self._fail()
            except HostAuthorityError as error:
                raise error from exc

    def _operation_deadline(self):
        return time.monotonic() + self._timeout

    def initialize(self):
        self._live(initialized=False)
        if self._initialized:
            self._fail()
        deadline = self._operation_deadline()
        identifier = "aegis-initialize-1"
        self._write({
            "id": identifier,
            "method": "initialize",
            "params": {
                "clientInfo": {"name": "aegis_host_leaf", "version": "1"},
                "capabilities": {"experimentalApi": True},
            },
        }, deadline)
        self._accept_handshake(self._read(deadline), identifier)
        self._write({"method": "initialized"}, deadline)
        self._initialized = True

    def _accept_handshake(self, response, identifier):
        fields = {"codexHome", "platformFamily", "platformOs", "userAgent"}
        result = response["result"] if type(response) is dict and "result" in response else None
        if (set(response) != {"id", "result"} or response["id"] != identifier
                or type(response["id"]) is not str or type(result) is not dict
                or set(result) != fields
                or not all(_text(item, 4096) for item in result.values())):
            self._fail()

    def receive_call(self):
        self._live()
        deadline = self._operation_deadline()
        for _ignored in range(MAX_CALLS):
            try:
                value = _call(self._read(deadline))
            except HostAuthorityError as exc:
                if not self._closed:
                    self._fail(exc.code, exc.reason)
                raise
            fresh = self._correlate(value, deadline)
            if fresh is not None:
                return fresh
        self._fail("HOST_CALL_CONFLICT", "host call correlation capacity exhausted")

    def _correlate(self, value, deadline):
        params = value["params"]
        rpc = _rpc_key(value["id"])
        key = (params.get("threadId"), params.get("turnId"), params.get("callId"))
        self._reject_correlation(rpc, key)
        previous = self._calls.get(key)
        if previous is not None:
            self._repeat(previous, rpc, key, _fingerprint(params), value, deadline)
            return None
        self._reserve(rpc, key, _fingerprint(params), value)
        return value

    def _reject_correlation(self, rpc, key):
        if rpc in self._ids and self._ids[rpc] != key:
            self._fail("HOST_CALL_CONFLICT", "host call correlation conflicts")
        if rpc not in self._ids and len(self._ids) >= MAX_CALLS:
            self._fail("HOST_CALL_CONFLICT", "host call correlation capacity exhausted")

    def _repeat(self, previous, rpc, key, fingerprint, value, deadline):
        if previous["fingerprint"] != fingerprint:
            self._fail("HOST_CALL_CONFLICT", "host call correlation conflicts")
        self._ids[rpc] = key
        if previous["result"] is not None:
            self._write({"id": value["id"], "result": previous["result"]}, deadline)
            return
        if rpc not in previous["aliases"]:
            previous["aliases"][rpc] = value["id"]

    def _reserve(self, rpc, key, fingerprint, value):
        if len(self._calls) >= MAX_CALLS or len(self._ids) >= MAX_CALLS:
            self._fail("HOST_CALL_CONFLICT", "host call correlation capacity exhausted")
        self._ids[rpc] = key
        self._calls[key] = {
            "fingerprint": fingerprint,
            "aliases": {rpc: value["id"]},
            "result": None,
        }

    def reply(self, rpc_id, result):
        self._live()
        try:
            self._reply(rpc_id, result)
        except HostAuthorityError as exc:
            if not self._closed:
                self._fail(exc.code, exc.reason)
            raise

    def _reply(self, rpc_id, result):
        rpc = _rpc_key(rpc_id)
        row = self._calls.get(self._ids.get(rpc))
        if row is None or row["result"] is not None:
            self._fail("HOST_CALL_CONFLICT", "host reply has no pending call")
        frozen = _freeze_reply(result, self._maximum)
        # Every alias envelope is a complete frame. Refuse before the first write.
        frames = []
        for identifier in row["aliases"].values():
            frames.append(self._encode_frame({"id": identifier, "result": frozen}))
        deadline = self._operation_deadline()
        for raw in frames:
            self._send_frame(raw, deadline)
        row["result"] = frozen
