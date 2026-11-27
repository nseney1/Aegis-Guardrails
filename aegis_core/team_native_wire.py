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
from json import encoder as json_encoder


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
_REPLY_PREFIX = b'{"id":'
_REPLY_SEPARATOR = b',"result":'
_REPLY_END = b"}\n"
_REPLY_OVERHEAD = len(_REPLY_PREFIX) + len(_REPLY_SEPARATOR) + len(_REPLY_END)
_REPLY_REPAIR = "Shorten the result to fit in one bounded host protocol frame."
_REPLY_RECONCILE = "Reconcile the original call before attempting another host call."
_STRING_CHUNK_CHARS = 8192
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
        self._next_action = _NEXT[code]
        super().__init__(reason)

    @property
    def code(self):
        return self._code

    @property
    def reason(self):
        return self._reason

    @property
    def next_action(self):
        return self._next_action


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
    """ASCII JSON string length, with bounded temporary encoder output."""
    length = len(text)
    total = 2
    if length + total > ceiling:
        return length + total
    start = 0
    while start < length and total <= ceiling:
        # One code point uses at most 12 bytes. Near the limit, encode at
        # least one so a short escape can still fit exactly.
        width = max(1, min(_STRING_CHUNK_CHARS, (ceiling - total) // 12))
        stop = min(start + width, length)
        encoded = json_encoder.encode_basestring_ascii(text[start:stop])
        total += len(encoded) - 2  # Ignore the temporary slice's quotes.
        start = stop
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

    def walk(item, ceiling):
        kind = type(item)
        if kind is dict:
            total = 2
            for index, (key, child) in enumerate(item.items()):
                total += 2 if index else 1  # Colon and optional comma.
                total += _string_size(key, ceiling - total)
                if total > ceiling:
                    return total
                total += walk(child, ceiling - total)
                if total > ceiling:
                    return total
            return total
        if kind is list:
            total = 2
            for index, child in enumerate(item):
                if index:
                    total += 1
                total += walk(child, ceiling - total)
                if total > ceiling:
                    return total
            return total
        if kind is str:
            return _string_size(item, ceiling)
        if kind is bool:
            return 4 if item else 5
        if kind is int:
            return _int_size(item, ceiling)
        if item is None:
            return 4
        if kind is float:
            try:
                return len(json.dumps(item, allow_nan=False))
            except ValueError:
                _invalid()
        _invalid()

    return walk(value, maximum)


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _encode(value, maximum):
    # The trailing newline is part of the frame. Refuse before dumps builds it.
    if _json_size(value, maximum) + 1 > maximum:
        _invalid()
    raw = _json_bytes(value) + b"\n"
    if len(raw) > maximum:
        _invalid()
    return raw


def _fingerprint(params):
    body = json.dumps(params, sort_keys=True, ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _reply_fields(value):
    if type(value) is not dict or len(value) != 2:
        _invalid()
    fields = {}
    try:
        for key, item in value.items():
            if len(fields) == 2 or type(key) is not str:
                _invalid()
            fields[key] = item
    except RuntimeError:
        _invalid()
    return fields


def _reply_snapshot(result):
    """Keep the validated strings for both sizing and canonical encoding."""
    result = _reply_fields(result)
    success, contents = result.get("success"), result.get("contentItems")
    if type(success) is not bool or type(contents) is not list or len(contents) > 64:
        _invalid()
    items = []
    for item in contents:
        if len(items) == 64:
            _invalid()
        fields = _reply_fields(item)
        kind, text = fields.get("type"), fields.get("text")
        if type(kind) is not str or kind != "inputText" or type(text) is not str:
            _invalid()
        items.append({"type": kind, "text": text})
    return {"success": success, "contentItems": items}


class FrameTransport:
    """Shared bounded frame encoding, readiness and descriptor I/O.

    Until a frame is consumed, the next search skips bytes already examined.
    After a frame is consumed, search starts at the buffered remainder.
    Bytes already written keep an unknown outcome.
    """

    def _deadline_left(self, deadline):
        if self._revoked():
            self._fail()
        left = deadline - time.monotonic()
        if left <= 0:
            self._fail("HOST_PROTOCOL_TIMEOUT", "host protocol deadline expired")
        return left

    def _prepare_frame(self, deadline):
        """Hook for a borrowed transport that bounds preparation."""

    def _guarded(self, operation, _deadline, *args):
        """Run one non-blocking syscall on a live descriptor."""
        with self._gate:
            if self._revoked():
                return _REVOKED
            return operation(*args)

    def _io_failure(self, cause):
        try:
            self._fail()
        except HostAuthorityError as error:
            raise error from cause

    def _wait(self, fd, deadline, *, writing=False):
        while True:
            left = self._deadline_left(deadline)
            try:
                readable, writable, _unused = select.select(
                    [] if writing else [fd], [fd] if writing else [], [],
                    min(left, REVOCATION_POLL_SECONDS))
            except InterruptedError:
                continue
            except (OSError, ValueError) as exc:
                self._io_failure(exc)
            if readable or writable:
                return

    def _read(self, deadline):
        searched = 0
        while True:
            self._prepare_frame(deadline)
            end = self._buffer.find(b"\n", searched)
            if end >= 0:
                with memoryview(self._buffer)[:end + 1] as frame:
                    raw = bytes(frame)
                return self._deliver(raw, end, deadline)
            searched = len(self._buffer)
            if searched >= self._maximum:
                self._fail()
            self._wait(self._read_fd, deadline)
            chunk = self._take(deadline)
            if chunk is _AGAIN:
                continue
            if chunk is _REVOKED or not chunk:
                self._fail()
            self._buffer.extend(chunk)

    def _deliver(self, raw, end, _deadline):
        del self._buffer[:end + 1]
        return self._decode_frame(raw)

    def _decode_frame(self, raw):
        try:
            return _decode(raw, self._maximum)
        except HostAuthorityError:
            self._fail()

    def _take(self, deadline):
        try:
            return self._guarded(
                os.read, deadline, self._read_fd,
                min(65536, self._maximum - len(self._buffer)))
        except HostAuthorityError:
            raise
        except (BlockingIOError, InterruptedError):
            return _AGAIN
        except OSError as exc:
            self._io_failure(exc)

    def _encode_frame(self, value):
        """Encode one generic frame, including its newline.

        Initialization and control writes use this encoder. An encoding refusal
        closes the transport before it reaches the caller.
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
            written = self._send(view[offset:], deadline)
            if written is _AGAIN:
                continue
            if written is _REVOKED or written <= 0:
                self._fail()
            offset += written

    def _write(self, value, deadline):
        self._prepare_frame(deadline)
        self._send_frame(self._encode_frame(value), deadline)

    def _send(self, payload, deadline):
        try:
            return self._guarded(os.write, deadline, self._write_fd, payload)
        except HostAuthorityError:
            raise
        except (BlockingIOError, InterruptedError):
            return _AGAIN
        except OSError as exc:
            self._io_failure(exc)


class ProtocolClient(FrameTransport):
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
        # Check the platform before touching either pipe.
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
        self._buffer = bytearray()
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

    def _operation_deadline(self):
        return time.monotonic() + self._timeout

    def _live(self, *, initialized=True):
        if self._closed or (initialized and not self._initialized):
            self._fail()

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
        identifier = value["id"]
        with self._gate:
            body = previous["result"]
            if body is None:
                previous["aliases"].setdefault(rpc, identifier)
                return
        self._check_reply_sizes((identifier,), len(body), replay=True)
        self._send_reply(identifier, body, deadline)

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
            if not self._revoked():
                self._fail(exc.code, exc.reason)
            raise

    def _reply(self, rpc_id, result):
        rpc = _rpc_key(rpc_id)
        row = self._calls.get(self._ids.get(rpc))
        if row is None or row["result"] is not None:
            self._fail("HOST_CALL_CONFLICT", "host reply has no pending call")
        snapshot = _reply_snapshot(result)
        body_size = _json_size(snapshot, self._maximum)
        with self._gate:
            aliases = tuple(row["aliases"].values())
        self._check_reply_sizes(aliases, body_size)
        body = _json_bytes(snapshot)
        # Encoding can overlap a receive. Include aliases added before the
        # fan-out starts, keeping checks and writes outside the descriptor gate.
        with self._gate:
            initial = tuple(row["aliases"].values())
        self._check_reply_sizes(initial[len(aliases):], body_size)
        deadline = self._operation_deadline()
        self._send_reply_batch(row, initial, body, deadline)

    def _send_reply_batch(self, row, aliases, body, deadline):
        sent = 0
        while True:
            for identifier in aliases:
                self._send_reply(identifier, body, deadline)
            sent += len(aliases)
            with self._gate:
                aliases = tuple(row["aliases"].values())[sent:]
                if not aliases:
                    row["result"] = body
                    return
            # A retry admitted during a write uses the already established body.
            self._check_reply_sizes(aliases, len(body), replay=True)

    def _check_reply_sizes(self, aliases, body_size, *, replay=False):
        remaining = self._maximum - body_size - _REPLY_OVERHEAD
        if remaining >= 0 and all(_json_size(identifier, remaining) <= remaining
                                  for identifier in aliases):
            return
        try:
            self._fail()
        except HostAuthorityError as exc:
            # Preserve the usual close or owner fence and the public error code.
            exc._next_action = _REPLY_RECONCILE if replay else _REPLY_REPAIR
            raise

    def _send_reply(self, identifier, body, deadline):
        raw = b"".join((_REPLY_PREFIX, _json_bytes(identifier), _REPLY_SEPARATOR,
                        body, _REPLY_END))
        self._send_frame(raw, deadline)
