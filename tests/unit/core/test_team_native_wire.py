"""Parity and refusal tests for the Codex stdio wire client leaf.

The legacy module is imported only here. Product code never imports tools/.
Pipe tests skip on non-POSIX hosts. Shared process modules are not patched;
replacements are installed on aegis_core.team_native_wire only.
"""
import ast
import importlib
import json
import math
import os
import select
import threading
from contextlib import ExitStack, closing, contextmanager
from types import SimpleNamespace

import pytest

import aegis_core.team_native_wire as wire
from aegis_core import team_native_keys, team_native_session


legacy = importlib.import_module("tools.hierarchy_host_authority")

HANDSHAKE = {
    "userAgent": "fake",
    "codexHome": "fixture-home",
    "platformFamily": "unix",
    "platformOs": "linux",
}
INIT_ID = "aegis-initialize-1"


def frame(value):
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


def _response_bytes(identifier, result):
    """One complete reply frame, envelope and newline, in the wire encoding."""
    payload = {"id": identifier, "result": result}
    return (json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def _close_stream(stream):
    if stream is None:
        return
    try:
        stream.close()
    except OSError:
        pass


def call(identifier=7, call_id="call-1", **changes):
    value = {"id": identifier, "method": "item/tool/call", "params": {
        "threadId": "thread-1", "turnId": "turn-1", "callId": call_id,
        "tool": "aegis_decide", "arguments": {"request_id": "r-1"}}}
    value.update(changes)
    return value


def _posix():
    if os.name != "posix":
        pytest.skip("bounded anonymous pipe transport is explicitly POSIX-only")


def _owned_stream(fd, mode):
    """Adopt fd. On fdopen failure the raw descriptor is closed exactly once."""
    try:
        return os.fdopen(fd, mode, buffering=0)
    except BaseException:
        os.close(fd)
        raise


def _pipe():
    read_fd, write_fd = os.pipe()
    try:
        reader = _owned_stream(read_fd, "rb")
    except BaseException:
        os.close(write_fd)
        raise
    try:
        writer = _owned_stream(write_fd, "wb")
    except BaseException:
        reader.close()
        raise
    return reader, writer


class _LineReader:
    def __init__(self, read):
        self.read = read
        self.buf = b""

    def line(self):
        while b"\n" not in self.buf:
            chunk = self.read(65536)
            if not chunk:
                data, self.buf = self.buf, b""
                return data
            self.buf += chunk
            if len(self.buf) > wire.MAX_FRAME_BYTES * 4:
                break
        end = self.buf.find(b"\n")
        if end < 0:
            data, self.buf = self.buf, b""
            return data
        raw, self.buf = self.buf[:end + 1], self.buf[end + 1:]
        return raw


class Link:
    """One client and the peer ends of its two anonymous pipes."""

    _DRAIN_TIMEOUT_SECONDS = 5

    def __init__(self, timeout=3, maximum=None, implementation=None):
        _posix()
        self.seen = []
        self.error = None
        self.to_client = None
        self.to_peer = None
        self._peer_reader = None
        self._client_reader = None
        self._client_writer = None
        self._thread = None
        self._abort_peer = threading.Event()
        self.client = None
        try:
            self._client_reader, self.to_client = _pipe()
            self._peer_reader, self._client_writer = _pipe()
            self.to_peer = self._peer_reader.fileno()
            os.set_inheritable(self.to_client.fileno(), False)
            os.set_inheritable(self.to_peer, False)
            self.peer = _LineReader(self._peer_reader.read)
            implementation = wire.ProtocolClient if implementation is None else implementation
            self.client = implementation(
                self._client_reader, self._client_writer, timeout_seconds=timeout,
                max_frame_bytes=wire.MAX_FRAME_BYTES if maximum is None else maximum)
        except BaseException:
            self.close()
            raise

    def start(self, frames=(), mode="ok", result=None):
        payload = HANDSHAKE if result is None else result
        incoming = list(frames)

        def run():
            try:
                self._serve(incoming, mode, payload)
            except (OSError, ValueError) as exc:
                # Close during a blocked write drops the peer's end. That is shutdown.
                self.error = exc

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self._thread = thread

    def _emit(self, payload):
        view = memoryview(payload)
        offset = 0
        while offset < len(payload) and not self._abort_peer.is_set():
            wrote = self.to_client.write(view[offset:])
            if wrote <= 0:
                break
            offset += wrote

    def _serve(self, incoming, mode, payload):
        first = self.peer.line()
        if first:
            self.seen.append(first)
        if mode == "hang" or not first:
            return
        ident = "other" if mode == "wrong-init" else INIT_ID
        body = dict(payload)
        if mode == "bad-init":
            body.pop("codexHome", None)
        if mode != "silent":
            self._emit(frame({"id": ident, "result": body}))
        if mode in ("wrong-init", "bad-init", "eof-after-result"):
            return
        second = self.peer.line()
        if second:
            self.seen.append(second)
        if mode == "torn":
            self._emit(b'{"id":7')
            self.to_client.close()
            return
        if mode == "eof":
            self.to_client.close()
            return
        for raw in incoming:
            self._emit(raw)
        while not self._abort_peer.is_set():
            more = self.peer.line()
            if not more:
                break
            self.seen.append(more)

    def close(self):
        """Close the client, then wait until the peer records end-of-stream.

        reply() returns only after os.write has accepted every byte. The peer
        thread is the observer. Closing its read end before it runs discards
        those bytes, so the read end stays open until the thread finishes.
        """
        thread = self._thread
        timed_out = False
        try:
            try:
                if self.client is not None:
                    self.client.close()
            except OSError:
                pass
        finally:
            try:
                if thread is not None and thread is not threading.current_thread():
                    thread.join(self._DRAIN_TIMEOUT_SECONDS)
                    timed_out = thread.is_alive()
                    if timed_out:
                        self._abort_peer.set()
            finally:
                # Closing the opposite pipe ends wakes blocked peer reads or writes.
                for stream in (self._client_writer, self._client_reader,
                               self.to_client, self._peer_reader):
                    _close_stream(stream)
            if timed_out:
                thread.join(5)
                raise AssertionError(
                    "peer did not reach end-of-stream within %s seconds; "
                    "observed %d frames; peer still alive after cleanup: %s"
                    % (self._DRAIN_TIMEOUT_SECONDS, len(self.seen), thread.is_alive()))

    def parsed(self):
        return [json.loads(raw) for raw in self.seen if raw.endswith(b"\n")]


@contextmanager
def link(timeout=3, maximum=None, frames=(), mode="ok", result=None, implementation=None):
    item = Link(timeout=timeout, maximum=maximum, implementation=implementation)
    try:
        item.start(frames=frames, mode=mode, result=result)
        yield item
    finally:
        item.close()
        if item._thread is not None:
            assert not item._thread.is_alive()


def _messages(item):
    item.close()
    return item.parsed()


class _GatedSelect:
    """Pause a proven unready descriptor before polling it again."""

    def __init__(self, fd, *, writing=False, poll=select.select):
        self.fd = fd
        self.writing = writing
        self.poll = poll
        self.entered = threading.Event()
        self.release = threading.Event()
        self.ready = False

    def select(self, readable, writable, exceptional, timeout=None):
        watched = writable if self.writing else readable
        if self.fd not in watched:
            return select.select(readable, writable, exceptional, timeout)
        if not self.entered.is_set():
            assert select.select(readable, writable, exceptional, 0) == ([], [], [])
            self.entered.set()
            assert self.release.wait(5), "test did not release the select gate"
        result = self.poll(readable, writable, exceptional, timeout)
        self.ready = self.fd in result[1 if self.writing else 0]
        return result


class _PollClock:
    def __init__(self):
        self.now = 0

    def monotonic(self):
        return self.now

    def poll(self, readable, writable, exceptional, timeout):
        self.now += timeout
        return [], [], []


@contextmanager
def _pending_initialize(client, watch):
    outcome = []

    def initialize():
        try:
            client.initialize()
        except wire.HostAuthorityError as exc:
            outcome.append(exc.code)
        else:
            outcome.append("initialized")

    worker = threading.Thread(target=initialize, daemon=True)
    worker.start()
    try:
        assert watch.entered.wait(5), "initialize did not reach the select gate"
        yield outcome
    finally:
        watch.release.set()
        worker.join(5)
        assert not worker.is_alive()


class _Once:
    def __init__(self, fault):
        self.fault = fault
        self.used = False

    def select(self, readable, writable, exceptional, timeout=None):
        if not self.used:
            self.used = True
            raise self.fault
        return select.select(readable, writable, exceptional, timeout)


class _OsName:
    name = "nt"


class _ReadFail:
    name = os.name

    def set_blocking(self, fd, blocking):
        os.set_blocking(fd, blocking)

    def read(self, fd, size):
        raise OSError("injected read failure")

    def write(self, fd, data):
        return os.write(fd, data)


class _WriteFail:
    name = os.name

    def set_blocking(self, fd, blocking):
        os.set_blocking(fd, blocking)

    def read(self, fd, size):
        return os.read(fd, size)

    def write(self, fd, data):
        raise OSError("injected write failure")


class _BlockFail:
    name = os.name

    def set_blocking(self, fd, blocking):
        raise OSError("injected pipe setup failure")


def test_frame_transport_stops_at_frames_and_protocol_client_keeps_the_session():
    """Invariant: handshake and call correlation stay on ProtocolClient."""
    assert issubclass(wire.ProtocolClient, wire.FrameTransport)
    for name in ("initialize", "receive_call", "reply"):
        assert hasattr(wire.ProtocolClient, name)
        assert not hasattr(wire.FrameTransport, name)


def test_public_surface_matches_the_legacy_constants_and_omits_dead_names():
    assert wire.CODES == legacy.CODES
    assert wire.MAX_FRAME_BYTES == legacy.MAX_FRAME_BYTES == 1024 * 1024
    assert wire.MAX_DEPTH == legacy.MAX_DEPTH == 32
    assert wire.MAX_CALLS == legacy.MAX_CALLS == 32
    assert wire.MAX_WAIT_SECONDS == legacy.MAX_WAIT_SECONDS == 5
    assert wire.REVOCATION_POLL_SECONDS == legacy.REVOCATION_POLL_SECONDS
    assert wire.__all__ == [
        "CODES", "HostAuthorityError", "MAX_CALLS", "MAX_DEPTH", "MAX_FRAME_BYTES",
        "MAX_WAIT_SECONDS", "ProtocolClient", "REVOCATION_POLL_SECONDS"]
    for name in wire.__all__:
        assert hasattr(wire, name)
    assert not hasattr(wire, "decode_call_frame")
    assert not hasattr(wire, "refuse_unowned_call")


def test_product_imports_only_the_standard_library_and_has_no_typeerror_handler():
    with open(wire.__file__, encoding="utf-8") as handle:
        source = handle.read()
    tree = ast.parse(source)
    modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.append((node.module or "").split(".")[0])
        elif isinstance(node, ast.ExceptHandler) and node.type is not None:
            assert "TypeError" not in ast.dump(node.type)
    assert "tools" not in modules
    assert "aegis_core" not in modules
    assert "TypeError" not in source


def test_error_fields_are_fixed_and_do_not_echo_the_rejected_value():
    reason = "not enrolled"
    error = wire.HostAuthorityError("STALE_INVOCATION", reason)
    assert isinstance(error, PermissionError)
    assert (error.code, error.reason, str(error)) == ("STALE_INVOCATION", reason, reason)
    assert error.next_action == wire.HostAuthorityError("STALE_INVOCATION", "other").next_action
    assert reason not in error.next_action
    assert "\n" not in error.next_action
    with pytest.raises(AttributeError):
        error.code = "made-up"
    with pytest.raises(AttributeError):
        error.reason = "changed"
    with pytest.raises(AttributeError):
        error.next_action = "changed"
    rejected = "made-up-code-value"
    with pytest.raises(ValueError) as caught:
        wire.HostAuthorityError(rejected, "no")
    assert str(caught.value) == "invalid host authority error"
    assert rejected not in str(caught.value)
    with pytest.raises(ValueError):
        wire.HostAuthorityError("HOST_PROTOCOL_ERROR", "")
    with pytest.raises(ValueError):
        wire.HostAuthorityError("HOST_PROTOCOL_ERROR", "bad\x00value")
    actions = {}
    for code in sorted(wire.CODES):
        item = wire.HostAuthorityError(code, "fixed reason")
        actions[code] = item.next_action
        assert item.next_action and "\n" not in item.next_action
        assert "fixed reason" not in item.next_action
    assert len(set(actions)) == len(actions)


@pytest.mark.parametrize("timeout,maximum", [
    (0, wire.MAX_FRAME_BYTES),
    (-1, wire.MAX_FRAME_BYTES),
    (wire.MAX_WAIT_SECONDS + 0.01, wire.MAX_FRAME_BYTES),
    (math.nan, wire.MAX_FRAME_BYTES),
    (True, wire.MAX_FRAME_BYTES),
    (1, 0),
    (1, wire.MAX_FRAME_BYTES + 1),
    (1, True),
])
def test_invalid_transport_limits_use_a_fixed_message(timeout, maximum):
    if os.name != "posix":
        with pytest.raises(wire.HostAuthorityError) as caught:
            wire.ProtocolClient(None, None, timeout_seconds=timeout, max_frame_bytes=maximum)
        assert caught.value.code == "UNSUPPORTED_HOST"
        assert str(caught.value) == "bounded pipe transport requires POSIX"
        assert "None" not in caught.value.next_action
        return
    with pytest.raises(ValueError) as caught:
        wire.ProtocolClient(None, None, timeout_seconds=timeout, max_frame_bytes=maximum)
    assert str(caught.value) == "invalid host transport limits"


def test_unsupported_host_is_a_typed_refusal_before_any_stream_use(monkeypatch):
    monkeypatch.setattr(wire, "os", _OsName())
    with pytest.raises(wire.HostAuthorityError) as caught:
        wire.ProtocolClient(None, None)
    assert caught.value.code == "UNSUPPORTED_HOST"
    assert str(caught.value) == "bounded pipe transport requires POSIX"
    assert caught.value.next_action
    assert "None" not in caught.value.next_action


def test_posix_constructor_refuses_missing_streams_without_a_raw_attribute_error():
    _posix()
    with pytest.raises(wire.HostAuthorityError) as caught:
        wire.ProtocolClient(None, None)
    assert caught.value.code == "HOST_PROTOCOL_ERROR"
    assert str(caught.value) == "invalid host protocol frame"


def test_same_descriptor_refuses_and_closes_both_wrappers():
    _posix()
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    first = second = None
    try:
        first = os.fdopen(read_fd, "rb", buffering=0, closefd=False)
        second = os.fdopen(read_fd, "rb", buffering=0, closefd=False)
        with pytest.raises(wire.HostAuthorityError) as caught:
            wire.ProtocolClient(first, second)
        assert caught.value.code == "HOST_PROTOCOL_ERROR"
        assert first.closed and second.closed
    finally:
        if first is not None and not first.closed:
            first.close()
        if second is not None and not second.closed:
            second.close()
        try:
            os.close(read_fd)
        except OSError:
            pass


def test_setup_failure_closes_streams_and_hides_the_injected_text(monkeypatch):
    _posix()
    monkeypatch.setattr(wire, "os", _BlockFail())
    reader, writer = _pipe()
    try:
        with pytest.raises(wire.HostAuthorityError) as caught:
            wire.ProtocolClient(reader, writer)
        assert caught.value.code == "HOST_PROTOCOL_ERROR"
        assert "injected" not in str(caught.value)
        assert "injected" not in caught.value.next_action
        assert reader.closed and writer.closed
    finally:
        reader.close()
        writer.close()


def test_link_closes_the_first_pipe_when_the_second_open_fails(monkeypatch):
    """A failure before the client exists still closes every pipe end."""
    _posix()
    real = _pipe
    state = {"n": 0, "reader": None}

    def flaky():
        state["n"] += 1
        pair = real()
        if state["n"] == 1:
            state["reader"] = pair[0]
            return pair
        pair[0].close()
        pair[1].close()
        raise OSError("second pipe refused")

    monkeypatch.setattr(
        "tests.unit.core.test_team_native_wire._pipe", flaky)
    with pytest.raises(OSError, match="^second pipe refused$"):
        Link()
    assert state["reader"] is not None and state["reader"].closed


def test_link_timeout_releases_the_peer_closes_streams_and_allows_a_fresh_exchange():
    entered = threading.Event()
    abort = threading.Event()

    class GatedLink(Link):
        _DRAIN_TIMEOUT_SECONDS = 0

        def _serve(self, incoming, mode, payload):
            entered.set()
            abort.wait(15)

    item = GatedLink()
    item._abort_peer = abort
    streams = (item._client_reader, item._client_writer, item.to_client, item._peer_reader)
    try:
        item.start()
        assert entered.wait(5)
        with pytest.raises(AssertionError, match="^peer did not reach end-of-stream"):
            item.close()
        assert abort.is_set()
        assert not item._thread.is_alive()
        assert all(stream.closed for stream in streams)
        item.close()
    finally:
        abort.set()
        if item._thread is not None:
            item._thread.join(5)
        item.close()

    answer = {"success": True, "contentItems": []}
    with link(frames=[frame(call())]) as fresh:
        fresh.client.initialize()
        value = fresh.client.receive_call()
        fresh.client.reply(value["id"], answer)
    assert fresh.parsed()[-1] == {"id": 7, "result": answer}


def test_fdopen_failure_closes_the_unused_end():
    _posix()
    state = {"closed": []}
    real_close = os.close

    def remembering(fd):
        state["closed"].append(fd)
        real_close(fd)

    read_fd, write_fd = os.pipe()

    def opener(fd, mode, buffering=0):
        if mode == "wb":
            raise OSError("fdopen rejected the write end")
        return os.fdopen(fd, mode, buffering=buffering)

    try:
        with pytest.raises(OSError, match="^fdopen rejected the write end$"):
            try:
                reader = opener(read_fd, "rb")
            except BaseException:
                remembering(read_fd)
                remembering(write_fd)
                raise
            try:
                opener(write_fd, "wb")
            except BaseException:
                reader.close()
                remembering(write_fd)
                raise
    finally:
        for fd in (read_fd, write_fd):
            try:
                os.close(fd)
            except OSError:
                pass
    assert write_fd in state["closed"]
    assert read_fd not in state["closed"]


def test_initialize_receive_and_reply_match_legacy_bytes():
    _posix()
    payload = call()
    with link(frames=[frame(payload)]) as item:
        item.client.initialize()
        value = item.client.receive_call()
        assert value == payload
        answer = {"success": False, "contentItems": [{"type": "inputText", "text": "refused"}]}
        item.client.reply(value["id"], answer)
        rows = _messages(item)
    legacy_rows = _legacy_exchange([frame(payload)], answer)
    assert rows == legacy_rows
    assert rows[0]["method"] == "initialize"
    assert rows[0]["params"]["capabilities"]["experimentalApi"] is True
    assert rows[1] == {"method": "initialized"}
    assert rows[2]["id"] == 7
    assert rows[2]["result"] == answer
    assert item.client.closed


def _legacy_exchange(frames, answer):
    """Run the frozen client on its own pipes and return the frames it wrote."""
    _posix()
    to_client_r, to_client_w = os.pipe()
    to_peer_r, to_peer_w = os.pipe()
    reader = writer = None
    worker = None
    try:
        reader = _owned_stream(to_client_r, "rb")
        writer = _owned_stream(to_peer_w, "wb")
        client = legacy.ProtocolClient(reader, writer, timeout_seconds=3)
        seen = []

        def serve():
            try:
                peer = _LineReader(lambda size: os.read(to_peer_r, size))
                first = peer.line()
                if first:
                    seen.append(first)
                os.write(to_client_w, frame({"id": INIT_ID, "result": HANDSHAKE}))
                second = peer.line()
                if second:
                    seen.append(second)
                for raw in frames:
                    os.write(to_client_w, raw)
                while True:
                    more = peer.line()
                    if not more:
                        break
                    seen.append(more)
            except (OSError, ValueError):
                return

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            client.initialize()
            value = client.receive_call()
            client.reply(value["id"], answer)
        finally:
            try:
                client.close()
            finally:
                worker.join(5)
        return [json.loads(raw) for raw in seen if raw.endswith(b"\n")]
    finally:
        for fd in (to_client_w, to_peer_r, to_peer_w):
            try:
                os.close(fd)
            except OSError:
                pass
        for stream in (reader, writer):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        if worker is not None and worker.is_alive():
            worker.join(1)


@pytest.mark.parametrize("raw", [
    b'{"id":1,"id":2,"method":"item/tool/call","params":{}}\n',
    b'{"id":true,"method":"item/tool/call","params":{}}\n',
    b'{"id":1,"method":"item/tool/call","params":{"arguments":NaN}}\n',
    b"\xff\n", b"{}\n", b"[]\n", b"{bad}\n",
    pytest.param(frame(call(extra="not-in-envelope")), id="extra-field"),
    pytest.param(frame(call(method="command/exec")), id="wrong-method"),
    pytest.param(frame(call(params={"threadId": "thread-1", "turnId": "turn-1",
                                    "callId": "call-1", "tool": "aegis_decide",
                                    "arguments": {}, "actor": "root"})),
                 id="actor-field"),
    b'{"id":1}\n{"id":2}\n',
    pytest.param(b"x" * (1024 * 1024 + 1), id="frame-over-1MiB"),
])
def test_rejected_frames_match_legacy_and_do_not_echo_or_write(raw):
    _posix()
    with pytest.raises(legacy.HostAuthorityError) as legacy_error:
        legacy.decode_call_frame(raw)
    with link(frames=[raw]) as item:
        item.client.initialize()
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.receive_call()
        assert (caught.value.code, str(caught.value)) == (
            legacy_error.value.code, str(legacy_error.value))
        assert caught.value.code == "HOST_PROTOCOL_ERROR"
        assert item.client.closed
        echoed = raw if len(raw) < 80 else b""
        if echoed:
            assert echoed.decode("utf-8", "replace") not in str(caught.value)
            assert echoed.decode("utf-8", "replace") not in caught.value.next_action
        rows = _messages(item)
    assert [row.get("method") for row in rows] == ["initialize", "initialized"]


def test_depth_limit_matches_legacy_before_a_reply_is_written():
    _posix()
    nested = {}
    for _ in range(40):
        nested = {"nested": nested}
    value = call()
    value["params"]["arguments"] = nested
    raw = frame(value)
    with pytest.raises(legacy.HostAuthorityError) as legacy_error:
        legacy.decode_call_frame(raw)
    with link(frames=[raw]) as item:
        item.client.initialize()
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.receive_call()
        assert (caught.value.code, str(caught.value)) == (
            legacy_error.value.code, "invalid host protocol frame")
        assert item.client.closed
        rows = _messages(item)
    assert all("result" not in row for row in rows)


def _wrapped(center, wraps):
    value = center
    for _index in range(wraps):
        value = {"k": value}
    return value


def test_depth_boundary_matches_legacy_including_strings_and_empty_containers():
    _posix()
    samples = [
        _wrapped({}, 30),
        _wrapped(1, 30),
        {"text": "{" * 80 + "}" * 80},
    ]
    for arguments in samples:
        body = call()
        body["params"]["arguments"] = arguments
        raw = frame(body)
        assert legacy.decode_call_frame(raw) == body
        with link(frames=[raw]) as item:
            item.client.initialize()
            assert item.client.receive_call() == body
    for arguments in (_wrapped({}, 31), _wrapped(1, 31)):
        body = call()
        body["params"]["arguments"] = arguments
        raw = frame(body)
        with pytest.raises(legacy.HostAuthorityError) as legacy_error:
            legacy.decode_call_frame(raw)
        with link(frames=[raw]) as item:
            item.client.initialize()
            with pytest.raises(wire.HostAuthorityError) as caught:
                item.client.receive_call()
            assert (caught.value.code, str(caught.value)) == (
                legacy_error.value.code, "invalid host protocol frame")
            assert item.client.closed
            rows = _messages(item)
        assert all("result" not in row for row in rows)


def test_accepted_call_shapes_match_legacy():
    _posix()
    samples = [call(), call(identifier="7"), call(identifier=0, call_id="integer-zero"),
               call(identifier="0", call_id="string-zero")]
    namespaced = call()
    namespaced["params"] = dict(namespaced["params"], namespace="functions")
    samples.append(namespaced)
    boundary = call()
    boundary["params"]["arguments"] = {"nested": {}}
    samples.append(boundary)
    for sample in samples:
        raw = frame(sample)
        assert legacy.decode_call_frame(raw) == sample
        with link(frames=[raw]) as item:
            item.client.initialize()
            assert item.client.receive_call() == sample


@pytest.mark.parametrize("mode,code,reason", [
    ("hang", "HOST_PROTOCOL_TIMEOUT", "host protocol deadline expired"),
    ("wrong-init", "HOST_PROTOCOL_ERROR", "invalid host protocol frame"),
    ("bad-init", "HOST_PROTOCOL_ERROR", "invalid host protocol frame"),
    ("torn", "HOST_PROTOCOL_ERROR", "invalid host protocol frame"),
    ("eof", "HOST_PROTOCOL_ERROR", "invalid host protocol frame"),
])
def test_handshake_failures_close_and_use_the_fixed_reason(mode, code, reason):
    timeout = 0.2 if mode == "hang" else 3
    with link(mode=mode, timeout=timeout) as item:
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.initialize()
            item.client.receive_call()
        assert (caught.value.code, str(caught.value)) == (code, reason)
        assert item.client.closed
        assert mode not in caught.value.next_action


def test_calls_cannot_arrive_before_initialization_and_init_is_once():
    with link() as item:
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.receive_call()
        assert caught.value.code == "HOST_PROTOCOL_ERROR"
        assert item.client.closed
    with link() as item:
        item.client.initialize()
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.initialize()
        assert caught.value.code == "HOST_PROTOCOL_ERROR"
        assert item.client.closed


def test_integer_and_string_ids_stay_distinct_including_zero():
    one, two = call(0, "integer-zero"), call("0", "string-zero")
    with link(frames=[frame(one), frame(two)]) as item:
        item.client.initialize()
        assert item.client.receive_call() == one
        assert item.client.receive_call() == two
        item.client.reply("0", {"success": True, "contentItems": [
            {"type": "inputText", "text": "string"}]})
        item.client.reply(0, {"success": False, "contentItems": [
            {"type": "inputText", "text": "integer"}]})
        rows = _messages(item)[2:]
    assert [(type(row["id"]), row["id"]) for row in rows] == [(str, "0"), (int, 0)]
    assert [row["result"]["success"] for row in rows] == [True, False]


def test_duplicate_completed_call_replays_without_a_second_dispatch_or_mutation():
    original, duplicate, later = call(7), call("retry"), call(8, "later")
    with link(frames=[frame(original), frame(duplicate), frame(later)]) as item:
        item.client.initialize()
        assert item.client.receive_call() == original
        answer = {"success": False, "contentItems": [{"type": "inputText", "text": "no"}]}
        item.client.reply(7, answer)
        answer["contentItems"][0]["text"] = "changed"
        assert item.client.receive_call() == later
        item.client.reply(8, {"success": False, "contentItems": [
            {"type": "inputText", "text": "no"}]})
        rows = _messages(item)[2:]
    assert [row["id"] for row in rows] == [7, "retry", 8]
    assert rows[0]["result"] == rows[1]["result"]
    assert rows[1]["result"]["contentItems"][0]["text"] == "no"


def test_pending_aliases_and_completed_replay_encode_the_body_once(monkeypatch):
    _posix()
    original = call(-(2 ** 63), "one")
    alias = call('a"\\é😀\n', "one")
    later = call(8, "two")
    replay = call("retry\ud800", "one")
    final = call(9, "three")
    marker = "immutable tool result"
    answer = {"success": False, "contentItems": [
        {"type": "inputText", "text": marker + ' "é😀\n\ud800'}]}
    expected = [_response_bytes(value["id"], answer) for value in (original, alias, replay)]
    encodings = []

    class CountBodyEncodes:
        loads = staticmethod(json.loads)

        @staticmethod
        def dumps(value, *args, **kwargs):
            raw = json.dumps(value, *args, **kwargs)
            if marker in raw:
                encodings.append(raw)
            return raw

    monkeypatch.setattr(wire, "json", CountBodyEncodes)
    with link(frames=map(frame, (original, alias, later, replay, final))) as item:
        item.client.initialize()
        assert item.client.receive_call() == original
        assert item.client.receive_call() == later
        item.client.reply(alias["id"], answer)
        answer["contentItems"][0]["text"] = "changed"
        assert item.client.receive_call() == final
    assert item.seen[2:] == expected
    assert len(encodings) == 1


@pytest.mark.parametrize("revoke", [False, True], ids=["write-error", "revoked"])
def test_reply_stops_between_aliases_after_a_transport_failure(monkeypatch, revoke):
    _posix()
    original, alias, later = call(7), call("alias"), call(8, "later")
    answer = {"success": True, "contentItems": []}
    expected = _response_bytes(7, answer)
    accepted = bytearray()
    attempts = []

    with link(frames=map(frame, (original, alias, later))) as item:
        item.client.initialize()
        assert item.client.receive_call() == original
        assert item.client.receive_call() == later

        class AliasIO:
            @staticmethod
            def select(readable, writable, exceptional, timeout):
                if revoke and writable and accepted == expected:
                    item.client.close()
                    return [], writable, []
                return select.select(readable, writable, exceptional, timeout)

            @staticmethod
            def write(fd, data):
                attempts.append(bytes(data))
                if len(attempts) == 1:
                    raise InterruptedError
                if len(attempts) == 2:
                    data = data[:3]
                if accepted == expected:
                    raise OSError("injected write failure")
                written = os.write(fd, data)
                accepted.extend(data[:written])
                return written

        monkeypatch.setattr(wire, "select", AliasIO)
        monkeypatch.setattr(wire, "os", AliasIO)
        for _attempt in range(2):
            with pytest.raises(wire.HostAuthorityError) as caught:
                item.client.reply(7, answer)
            assert (caught.value.code, caught.value.reason) == (
                "HOST_PROTOCOL_ERROR", "invalid host protocol frame")
            assert item.client.closed
        assert item._client_reader.closed and item._client_writer.closed
    assert attempts[:3] == [expected, expected, expected[3:]]
    assert attempts[3:] == ([] if revoke else [_response_bytes("alias", answer)])
    assert item.seen[2:] == [expected]


def test_changed_duplicate_and_unknown_reply_close_without_a_result_frame():
    changed = call(9)
    changed["params"]["arguments"] = {"request_id": "changed"}
    with link(frames=[frame(call()), frame(changed)]) as item:
        item.client.initialize()
        item.client.receive_call()
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.receive_call()
        assert caught.value.code == "HOST_CALL_CONFLICT"
        assert str(caught.value) == "host call correlation conflicts"
        assert item.client.closed
        rows = _messages(item)
    assert all("result" not in row for row in rows)
    with link() as item:
        item.client.initialize()
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.reply("not-pending", {"success": False, "contentItems": []})
        assert caught.value.code == "HOST_CALL_CONFLICT"
        assert str(caught.value) == "host reply has no pending call"
        assert item.client.closed
        rows = _messages(item)
    assert [row.get("method") for row in rows] == ["initialize", "initialized"]


def test_correlation_capacity_refuses_the_next_call_and_leaves_storage_unwritten():
    frames = [frame(call(identifier=index, call_id="c-%s" % index))
              for index in range(wire.MAX_CALLS + 1)]
    with link(frames=frames) as item:
        item.client.initialize()
        for index in range(wire.MAX_CALLS):
            value = item.client.receive_call()
            assert value["id"] == index
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.receive_call()
        assert caught.value.code == "HOST_CALL_CONFLICT"
        assert str(caught.value) == "host call correlation capacity exhausted"
        assert item.client.closed
        with pytest.raises(wire.HostAuthorityError):
            item.client.reply(0, {"success": False, "contentItems": []})
        rows = _messages(item)
    assert all("result" not in row for row in rows)


def test_reply_shape_is_closed_and_a_bad_reply_writes_nothing():
    with link(frames=[frame(call())]) as item:
        item.client.initialize()
        item.client.receive_call()
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.reply(7, {"success": False, "contentItems": [
                {"type": "inputText", "text": "x", "extra": "y"}]})
        assert caught.value.code == "HOST_PROTOCOL_ERROR"
        assert item.client.closed
        rows = _messages(item)
    assert all("result" not in row for row in rows)


def test_read_and_write_failures_are_typed_and_do_not_echo(monkeypatch):
    _posix()
    monkeypatch.setattr(wire, "os", _WriteFail())
    with link() as item:
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.initialize()
        assert caught.value.code == "HOST_PROTOCOL_ERROR"
        assert "injected" not in str(caught.value)
        assert "injected" not in caught.value.next_action
        assert item.client.closed
        rows = _messages(item)
    assert rows == []


def test_read_failure_after_a_frame_is_typed(monkeypatch):
    _posix()
    monkeypatch.setattr(wire, "os", _ReadFail())
    with link() as item:
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.initialize()
        assert str(caught.value) == "invalid host protocol frame"
        assert "injected" not in caught.value.next_action
        assert item.client.closed


def test_select_interruption_is_retried_and_select_failure_refuses(monkeypatch):
    monkeypatch.setattr(wire, "select", _Once(InterruptedError()))
    with link(frames=[frame(call())]) as item:
        item.client.initialize()
        assert item.client.receive_call()["id"] == 7

    class Boom:
        def select(self, readable, writable, exceptional, timeout=None):
            raise OSError("injected select failure")

    monkeypatch.setattr(wire, "select", Boom())
    with link() as item:
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.initialize()
        assert str(caught.value) == "invalid host protocol frame"
        assert "injected" not in caught.value.next_action
        assert isinstance(caught.value.__cause__, OSError)
        assert item.client.closed


def test_close_is_idempotent_and_a_fresh_client_can_retry():
    with link(frames=[frame(call())]) as item:
        item.client.initialize()
        item.client.close()
        item.client.close()
        with pytest.raises(wire.HostAuthorityError):
            item.client.receive_call()
    with link(frames=[frame(call())]) as item:
        item.client.initialize()
        assert item.client.receive_call()["id"] == 7


class _SearchBuffer(bytearray):
    """Record each newline search as (start, length) for the public receiver."""

    def __init__(self):
        super().__init__()
        self.spans = []

    def find(self, needle, start=0, end=None):
        self.spans.append((start, len(self)))
        if end is None:
            return bytearray.find(self, needle, start)
        return bytearray.find(self, needle, start, end)


def test_fragmented_read_reuses_its_prefix_and_keeps_coalesced_frames(monkeypatch):
    _posix()
    maximum = 512
    first, second, exact = call(7, "first"), call(8, "second"), call(9, "exact")
    exact["params"]["arguments"] = ""
    exact["params"]["arguments"] = "x" * (maximum - len(frame(exact)))
    incoming = frame(first) + frame(second)
    requested = []
    recopied = []

    class TrackedChunk(bytes):
        def __radd__(self, prefix):
            # The old immutable concatenation invokes this with the full prefix.
            if prefix:
                recopied.append(len(prefix))
            return prefix + bytes(self)

    class FragmentedReader:
        @staticmethod
        def read(fd, size):
            requested.append(size)
            if len(requested) == 1:
                size = 4
            elif len(requested) == 2:
                raise InterruptedError
            return TrackedChunk(os.read(fd, size))

    with closing(Link(maximum=maximum)) as item:
        item.to_client.write(frame({"id": INIT_ID, "result": HANDSHAKE}))
        item.client.initialize()
        observed = _SearchBuffer()
        item.client._buffer = observed
        monkeypatch.setattr(wire, "os", FragmentedReader)
        item.to_client.write(incoming)
        assert item.client.receive_call() == first
        during_fragments = list(observed.spans)
        assert item.client.receive_call() == second
        after_consume = observed.spans[len(during_fragments):]
        # A restart from zero on every fragment never records a positive start.
        assert any(start > 0 for start, _length in during_fragments)
        assert any(start == 4 and length >= 4 for start, length in during_fragments)
        # The buffered successor is searched from its own beginning.
        assert after_consume[0] == (0, len(frame(second)))
        assert requested == [maximum, maximum - 4, maximum - 4]
        item.to_client.write(frame(exact))
        assert item.client.receive_call() == exact
        assert requested[-1] == maximum
        item.to_client.write(b'{"id":7')
        item.to_client.close()
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.receive_call()
        assert (caught.value.code, caught.value.reason) == (
            "HOST_PROTOCOL_ERROR", "invalid host protocol frame")
        assert item.client.closed
        assert item._client_reader.closed and item._client_writer.closed
    assert recopied == []
    monkeypatch.setattr(wire, "os", os)
    with closing(Link()) as revoked:
        revoked.to_client.write(frame({"id": INIT_ID, "result": HANDSHAKE}))
        revoked.client.initialize()
        revoked.to_client.write(frame(call(7)) + frame(call(8, "later")))
        assert revoked.client.receive_call()["id"] == 7
        revoked.client.close()
        assert revoked.client.closed
        with pytest.raises(wire.HostAuthorityError) as caught:
            revoked.client.receive_call()
        assert (caught.value.code, caught.value.reason) == (
            "HOST_PROTOCOL_ERROR", "invalid host protocol frame")
        assert "later" not in caught.value.reason
        assert "later" not in caught.value.next_action


class _FrozenClock:
    def __init__(self, now):
        self.now = now

    def monotonic(self):
        return self.now


class _ExpireOnDecode:
    def __init__(self, clock):
        self.clock = clock
        self.armed = False

    def loads(self, *args, **kwargs):
        if self.armed:
            self.clock.now = 100
        return json.loads(*args, **kwargs)

    def dumps(self, *args, **kwargs):
        return json.dumps(*args, **kwargs)


def test_protocol_client_keeps_interrupted_coalesced_reads_and_the_cursor_bound(monkeypatch):
    """Ordinary ProtocolClient I/O stays on the shared transport.

    Handshake and correlation stay on ProtocolClient. An interrupted read
    retries, coalesced frames keep the cursor bound, and a buffered frame
    remains deliverable when its decode crosses the readiness deadline.
    """
    _posix()
    assert not any(hasattr(wire.FrameTransport, name)
                   for name in ("initialize", "receive_call", "reply"))
    clock = _FrozenClock(0)
    parser = _ExpireOnDecode(clock)
    monkeypatch.setattr(wire, "time", clock)
    monkeypatch.setattr(wire, "json", parser)
    maximum = 512
    first, second, third = call(7, "first"), call(8, "second"), call(9, "third")
    incoming = frame(first) + frame(second) + frame(third)
    requested = []

    class Fragmented:
        @staticmethod
        def read(fd, size):
            requested.append(size)
            if len(requested) == 1:
                return os.read(fd, 4)
            if len(requested) == 2:
                raise InterruptedError
            return os.read(fd, size)

        @staticmethod
        def write(fd, data):
            return os.write(fd, data)

        @staticmethod
        def set_blocking(fd, blocking):
            return os.set_blocking(fd, blocking)

    with closing(Link(timeout=3, maximum=maximum)) as item:
        item.to_client.write(frame({"id": INIT_ID, "result": HANDSHAKE}))
        item.client.initialize()
        observed = _SearchBuffer()
        item.client._buffer = observed
        monkeypatch.setattr(wire, "os", Fragmented)
        item.to_client.write(incoming)
        assert item.client.receive_call() == first
        during = list(observed.spans)
        assert item.client.receive_call() == second
        after = observed.spans[len(during):]
        assert any(start > 0 for start, _length in during)
        assert after[0] == (0, len(frame(second)) + len(frame(third)))
        assert requested == [maximum, maximum - 4, maximum - 4]
        parser.armed = True
        assert item.client.receive_call() == third
        assert not item.client.closed
        assert requested == [maximum, maximum - 4, maximum - 4]


@pytest.fixture(params=["standalone", "appserver"])
def timed_pipe(request, monkeypatch):
    clock = _FrozenClock(0)
    monkeypatch.setattr(wire, "time", clock)
    if request.param == "standalone":
        with closing(Link(timeout=3)) as item:
            yield clock, item
        return

    class Owner:
        def __init__(self, reader, writer):
            self.reader, self.writer = reader, writer
            self.io_gate = threading.RLock()
            self.fenced = False

        def require_owner_process(self):
            pass

        def close(self):
            with self.io_gate:
                self.fenced = True
                self.reader.close()
                self.writer.close()

    registry = team_native_keys.NativeIdentities()
    registry.bind_type("binding", Owner)
    monkeypatch.setattr(team_native_session, "native_identities", registry)
    monkeypatch.setattr(team_native_session, "time",
                        SimpleNamespace(monotonic_ns=lambda: clock.now * 10**9))

    def appserver(reader, writer, **_limits):
        owner = Owner(reader, writer)
        registry.register_binding(team_native_keys.LIVE_KEY, owner)
        return team_native_session.AppserverIO(owner)

    with closing(Link(implementation=appserver)) as item:
        with item.client.operation(3 * 10**9):
            yield clock, item


@pytest.mark.parametrize("operation", ["initialize", "receive", "reply", "replay"])
def test_pipe_client_preserves_timing_after_readiness(monkeypatch, timed_pipe, operation):
    clock, item = timed_pipe
    original, repeat, later = call(7, "one"), call(8, "one"), call(9, "two")
    answer = {"success": True, "contentItems": [{"type": "inputText", "text": "accepted"}]}
    late_writes = []

    class ReadyLate:
        @staticmethod
        def select(readable, writable, exceptional, timeout):
            ready = select.select(readable, writable, exceptional, timeout)
            if ready[1]:
                late_writes.append(ready[1])
                if operation != "initialize" or len(late_writes) == 2:
                    clock.now = 100
            return ready

    os.set_blocking(item.to_peer, False)
    item.to_client.write(frame({"id": INIT_ID, "result": HANDSHAKE}))
    if operation == "initialize":
        monkeypatch.setattr(wire, "select", ReadyLate)
    item.client.initialize()
    assert json.loads(item.peer.line())["method"] == "initialize"
    assert json.loads(item.peer.line()) == {"method": "initialized"}
    if operation == "initialize":
        assert len(late_writes) == 2
    else:
        item.to_client.write(frame(original) + frame(repeat) + frame(later))
        assert item.client.receive_call() == original
        if operation == "receive":
            parser = _ExpireOnDecode(clock)
            parser.armed = True
            monkeypatch.setattr(wire, "json", parser)
            # The duplicate is pending and the next distinct call is buffered.
            assert item.client.receive_call() == later
            assert clock.now == 100
        else:
            if operation == "reply":
                monkeypatch.setattr(wire, "select", ReadyLate)
            item.client.reply(original["id"], answer)
            assert json.loads(item.peer.line()) == {"id": 7, "result": answer}
            if operation == "replay":
                monkeypatch.setattr(wire, "select", ReadyLate)
                assert item.client.receive_call() == later
                assert json.loads(item.peer.line()) == {"id": 8, "result": answer}
            assert len(late_writes) == 1
    assert not item.client.closed


def test_close_during_blocked_write_does_not_write_a_reused_descriptor(tmp_path, monkeypatch):
    with closing(Link()) as item, ExitStack() as descriptors:
        write_fd = item._client_writer.fileno()
        queued = 0
        fill = b"x" * 65536
        while True:
            try:
                queued += os.write(write_fd, fill)
            except BlockingIOError:
                break
        victim_path = tmp_path / "unrelated-file"
        victim = os.open(str(victim_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        descriptors.callback(os.close, victim)
        watch = _GatedSelect(write_fd, writing=True)
        monkeypatch.setattr(wire, "select", watch)
        with _pending_initialize(item.client, watch) as errors:
            item.client.close()
            # The pending select now sees an unrelated, writable file at this number.
            os.dup2(victim, write_fd)
            descriptors.callback(os.close, write_fd)
        os.set_blocking(item.to_peer, False)
        while queued:
            chunk = os.read(item.to_peer, min(queued, len(fill)))
            if not chunk:
                break
            queued -= len(chunk)
        assert watch.ready
        assert queued == 0
        assert victim_path.read_bytes() == b""
        assert errors == ["HOST_PROTOCOL_ERROR"]


def test_close_during_blocked_read_does_not_read_a_reused_descriptor(monkeypatch):
    with closing(Link()) as item, ExitStack() as descriptors:
        read_fd = item._client_reader.fileno()
        forged = frame({"id": INIT_ID, "result": {
            "codexHome": "forged", "platformFamily": "unix", "platformOs": "linux",
            "userAgent": "forged"}})
        forged_reader, forged_writer = _pipe()
        descriptors.enter_context(forged_reader)
        descriptors.enter_context(forged_writer)
        forged_writer.write(forged)
        watch = _GatedSelect(read_fd)
        monkeypatch.setattr(wire, "select", watch)
        with _pending_initialize(item.client, watch) as outcome:
            item.client.close()
            os.dup2(forged_reader.fileno(), read_fd)
            descriptors.callback(os.close, read_fd)
        assert watch.ready
        assert outcome == ["HOST_PROTOCOL_ERROR"]
        os.set_blocking(read_fd, False)
        try:
            unread = os.read(read_fd, 65536)
        except BlockingIOError:
            unread = b""
        assert unread == forged


def test_close_interrupts_a_blocked_read_before_the_deadline(monkeypatch):
    timeout = 3
    clock = _PollClock()
    monkeypatch.setattr(wire, "time", clock)
    with closing(Link(timeout=timeout)) as item:
        watch = _GatedSelect(item._client_reader.fileno(), poll=clock.poll)
        monkeypatch.setattr(wire, "select", watch)
        with _pending_initialize(item.client, watch) as finished:
            item.client.close()
        assert finished == ["HOST_PROTOCOL_ERROR"]
        assert clock.monotonic() < timeout
        assert clock.monotonic() == wire.REVOCATION_POLL_SECONDS


def test_stream_close_error_is_raised_after_both_wrappers_are_closed():
    _posix()
    reader, writer = _pipe()

    class Boom:
        def __init__(self, stream):
            self.stream = stream

        def fileno(self):
            return self.stream.fileno()

        def close(self):
            self.stream.close()
            raise OSError("injected pipe close failure")

    client = wire.ProtocolClient(reader, Boom(writer))
    try:
        with pytest.raises(OSError, match="^injected pipe close failure$"):
            client.close()
        assert reader.closed
        assert client.closed
    finally:
        reader.close()
        writer.close()


def test_json_size_matches_the_compact_ascii_encoding():
    samples = [
        {}, [], "", "a", '"', "\\", "\n", "\x7f", "é", "😀", "\ud800",
        0, -1, 2 ** 20, True, False, None, -0.0, 1.5,
        {"b": 1, "a": [True, None, "x"]},
        {"k": "quote\"and\\slash\n"},
    ]
    for value in samples:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False)
        assert wire._json_size(value, 100000) == len(raw)


def _guard_json(monkeypatch, maximum):
    """Replace the wire JSON module. An encoded string past maximum fails the test."""

    class Guard:
        @staticmethod
        def loads(text, *args, **kwargs):
            raw = text.encode("utf-8") if isinstance(text, str) else text
            if len(raw) > maximum or raw.count(b"{") > 34:
                raise AssertionError("parser ran on a refused frame")
            return json.loads(text, *args, **kwargs)

        @staticmethod
        def dumps(value, *args, **kwargs):
            raw = json.dumps(value, *args, **kwargs)
            if len(raw.encode("utf-8")) > maximum:
                raise AssertionError("encoder built a value over the cap")
            return raw

    monkeypatch.setattr(wire, "json", Guard)


def test_deep_and_oversize_frames_never_reach_the_parser(monkeypatch):
    _posix()
    maximum = wire.MAX_FRAME_BYTES
    _guard_json(monkeypatch, maximum)
    nested = {}
    for _index in range(40):
        nested = {"nested": nested}
    body = call()
    body["params"]["arguments"] = nested
    raw = frame(body)
    assert len(raw) < maximum
    with pytest.raises(legacy.HostAuthorityError):
        legacy.decode_call_frame(raw)
    with link(frames=[raw]) as item:
        item.client.initialize()
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.receive_call()
        assert str(caught.value) == "invalid host protocol frame"
        assert item.client.closed
        rows = _messages(item)
    assert all("result" not in row for row in rows)
    with link(frames=[b"x" * (maximum + 8)]) as item:
        item.client.initialize()
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.receive_call()
        assert str(caught.value) == "invalid host protocol frame"
        assert "x" * 40 not in caught.value.next_action


def test_escaped_reply_over_the_cap_is_refused_before_encoding(monkeypatch):
    _posix()
    maximum = 180
    _guard_json(monkeypatch, maximum)
    short = {"success": False, "contentItems": [{"type": "inputText", "text": "ok"}]}
    wide = {"success": False, "contentItems": [{"type": "inputText", "text": '"' * 80}]}
    with link(frames=[frame(call(call_id="short"))], maximum=maximum) as item:
        item.client.initialize()
        value = item.client.receive_call()
        item.client.reply(value["id"], short)
        rows = _messages(item)
    assert rows[-1]["result"] == short
    with link(frames=[frame(call(call_id="wide"))], maximum=maximum) as item:
        item.client.initialize()
        value = item.client.receive_call()
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.reply(value["id"], wide)
        assert str(caught.value) == "invalid host protocol frame"
        assert '"' not in str(caught.value)
        assert item.client.closed
        rows = _messages(item)
    assert all("result" not in row for row in rows)


_REPAIR_REPLY = "Shorten the result to fit in one bounded host protocol frame."
_RECONCILE_REPLY = "Reconcile the original call before attempting another host call."


def _answer(text):
    return {"success": True, "contentItems": [{"type": "inputText", "text": text}]}


def _watch_reply_encoding(monkeypatch, encode_string, before_body=lambda: None):
    bodies = []

    def dumps(value, *args, **kwargs):
        if type(value) is dict and set(value) == {"success", "contentItems"}:
            before_body()
            raw = json.dumps(value, *args, **kwargs)
            bodies.append(raw.encode("ascii"))
            return raw
        return json.dumps(value, *args, **kwargs)

    monkeypatch.setattr(wire, "json", SimpleNamespace(loads=json.loads, dumps=dumps))
    monkeypatch.setattr(wire, "json_encoder", SimpleNamespace(encode_basestring_ascii=encode_string))
    return bodies


@pytest.mark.parametrize("extra", ["", "z"], ids=["exact", "over"])
def test_reply_text_frame_limit_matches_stdlib_bytes(monkeypatch, extra):
    text = ('a"\\\b\f\n\r\t\x00\x1f\x7fé\ud800😀' * 700) + "tail"
    expected = _response_bytes(7, _answer(text))
    chunks = []

    def encode_string(piece):
        if piece and piece in text + extra:
            chunks.append(piece)
        return json.encoder.encode_basestring_ascii(piece)

    bodies = _watch_reply_encoding(monkeypatch, encode_string)
    with link(frames=[frame(call())], maximum=len(expected)) as item:
        item.client.initialize()
        assert item.client.receive_call() == call()
        if extra:
            with pytest.raises(wire.HostAuthorityError) as caught:
                item.client.reply(7, _answer(text + extra))
            _assert_encoding_refusal_is_terminal(item, caught)
            assert caught.value.next_action == _REPAIR_REPLY
        else:
            item.client.reply(7, _answer(text))
    assert b"".join(item.seen[2:]) == (b"" if extra else expected)
    assert len(bodies) == (0 if extra else 1)
    if not extra:
        assert ascii("".join(chunks)) == ascii(text)
        assert len(chunks) > 1
        assert max(map(len, chunks)) <= 8192


def test_over_budget_escape_sizing_stops_before_the_text_tail(monkeypatch):
    maximum = 8192
    text = "😀" * 4000 + "unencoded tail"
    chunks = []

    def encode_string(piece):
        if piece and (piece[0] == "😀" or "tail" in piece):
            chunks.append(piece)
        return json.encoder.encode_basestring_ascii(piece)

    bodies = _watch_reply_encoding(monkeypatch, encode_string)
    with link(frames=[frame(call())], maximum=maximum) as item:
        item.client.initialize()
        item.client.receive_call()
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.reply(7, _answer(text))
        _assert_encoding_refusal_is_terminal(item, caught)
        assert caught.value.next_action == _REPAIR_REPLY
    assert chunks and 0 < sum(map(len, chunks)) < len(text)
    assert all("tail" not in piece for piece in chunks)
    assert bodies == []
    assert item.seen[2:] == []


@pytest.mark.parametrize("replay", [False, True], ids=["pending", "cached"])
@pytest.mark.parametrize("extra", ["", "z"], ids=["exact", "over"])
def test_escaped_alias_frame_limit_preserves_fanout_and_replay(monkeypatch, replay, extra):
    answer = _answer("private body " + "b" * 600)
    alias = 'private id "\\\n\x7f\ud800😀'
    expected_original = _response_bytes(7, answer)
    expected_alias = _response_bytes(alias, answer)
    original, duplicate, later = call(7), call(alias + extra), call(8, "later")
    bodies = _watch_reply_encoding(monkeypatch, json.encoder.encode_basestring_ascii)
    with link(frames=list(map(frame, (original, duplicate, later))),
              maximum=len(expected_alias)) as item:
        item.client.initialize()
        assert item.client.receive_call() == original
        if replay:
            item.client.reply(7, answer)
            answer["contentItems"][0]["text"] = "changed after first reply"
            operation = item.client.receive_call
        else:
            assert item.client.receive_call() == later

            def operation():
                item.client.reply(7, answer)

        if extra:
            with pytest.raises(wire.HostAuthorityError) as caught:
                operation()
            _assert_encoding_refusal_is_terminal(item, caught)
            assert caught.value.next_action == (_RECONCILE_REPLY if replay else _REPAIR_REPLY)
        else:
            assert operation() == (later if replay else None)
    expected = [expected_original] if replay or not extra else []
    if not extra:
        expected.append(expected_alias)
    assert item.seen[2:] == expected
    assert len(bodies) == (1 if expected else 0)


@pytest.mark.parametrize("arrival,extra", [
    ("encoding", "z"), ("writing", ""), ("writing", "z"),
], ids=["encoding-over", "writing-exact", "writing-over"])
def test_reply_preflights_aliases_admitted_during_fanout(monkeypatch, arrival, extra):
    answer = _answer("body " + "b" * 600)
    alias = "concurrent alias " + "😀" * 8
    expected_original = _response_bytes(7, answer)
    expected_alias = _response_bytes(alias, answer)
    later = call(8, "later")
    paused, resume = threading.Event(), threading.Event()
    errors = []

    def pause():
        paused.set()
        assert resume.wait(5)

    def select_before_write(readers, writers, exceptional, timeout):
        if writers and not paused.is_set():
            pause()
        return select.select(readers, writers, exceptional, timeout)

    with link(frames=[frame(call())], maximum=len(expected_alias)) as item:
        item.client.initialize()
        item.client.receive_call()
        if arrival == "encoding":
            _watch_reply_encoding(monkeypatch, json.encoder.encode_basestring_ascii, pause)
        else:
            monkeypatch.setattr(wire, "select", SimpleNamespace(select=select_before_write))

        def reply():
            try:
                item.client.reply(7, answer)
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=reply, daemon=True)
        worker.start()
        try:
            assert paused.wait(5)
            item.to_client.write(frame(call(alias + extra)) + frame(later))
            assert item.client.receive_call() == later
        finally:
            resume.set()
            worker.join(5)
        assert not worker.is_alive()
        if extra:
            assert len(errors) == 1
            assert type(errors[0]) is wire.HostAuthorityError
            assert errors[0].code == "HOST_PROTOCOL_ERROR"
            expected_action = _REPAIR_REPLY if arrival == "encoding" else _RECONCILE_REPLY
            assert errors[0].next_action == expected_action
            assert item.client.closed
        else:
            assert errors == []
    expected = [] if arrival == "encoding" else [expected_original]
    if not extra:
        expected.append(expected_alias)
    assert item.seen[2:] == expected


@pytest.mark.parametrize("revoke", [False, True], ids=["producer-mutation", "revocation"])
def test_reply_preflight_uses_owned_text_and_obeys_revocation(monkeypatch, revoke):
    text = "original " + "a" * 9000
    answer = _answer(text)
    expected = _response_bytes(7, answer)
    sizing = threading.Event()
    resume = threading.Event()
    errors = []

    def encode_string(piece):
        if piece.startswith("original "):
            sizing.set()
            assert resume.wait(5)
        return json.encoder.encode_basestring_ascii(piece)

    _watch_reply_encoding(monkeypatch, encode_string)
    with link(frames=[frame(call())], maximum=len(expected)) as item:
        item.client.initialize()
        item.client.receive_call()

        def reply():
            try:
                item.client.reply(7, answer)
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=reply, daemon=True)
        worker.start()
        try:
            assert sizing.wait(5), "reply did not enter the bounded encoder"
            if revoke:
                item.client.close()
            else:
                answer["contentItems"][0]["text"] = "outside the cap " + text
        finally:
            resume.set()
            worker.join(5)
        assert not worker.is_alive()
    if revoke:
        assert len(errors) == 1
        assert type(errors[0]) is wire.HostAuthorityError
        assert (errors[0].code, str(errors[0])) == (
            "HOST_PROTOCOL_ERROR", "invalid host protocol frame")
        assert item.seen[2:] == []
    else:
        assert errors == []
        assert item.seen[2:] == [expected]


def test_size_refusal_advice_survives_transport_fencing(timed_pipe):
    _clock, item = timed_pipe
    item.to_client.write(frame({"id": INIT_ID, "result": HANDSHAKE}))
    item.client.initialize()
    assert json.loads(item.peer.line())["method"] == "initialize"
    assert json.loads(item.peer.line()) == {"method": "initialized"}
    item.to_client.write(frame(call()))
    item.client.receive_call()
    with pytest.raises(wire.HostAuthorityError) as caught:
        item.client.reply(7, _answer("x" * (wire.MAX_FRAME_BYTES + 1)))
    assert caught.value.code == "HOST_PROTOCOL_ERROR"
    assert caught.value.next_action == _REPAIR_REPLY
    assert item._client_reader.closed and item._client_writer.closed
    assert item.peer.line() == b""


def test_malformed_inbound_frame_keeps_generic_recovery_advice():
    with link(frames=[b'{"private input":\n']) as item:
        item.client.initialize()
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.receive_call()
        _assert_encoding_refusal_is_terminal(item, caught)
        assert caught.value.next_action == (
            "Close the transport and retry with one bounded host protocol frame.")
    assert item.seen[2:] == []


def test_pending_duplicate_is_one_dispatch_and_one_reply_covers_both_ids():
    _posix()
    original, duplicate, later = call(7), call("retry"), call(8, "later")
    with link(frames=[frame(original), frame(duplicate), frame(later)]) as item:
        item.client.initialize()
        assert item.client.receive_call() == original
        assert item.client.receive_call() == later
        answer = {"success": False, "contentItems": [{"type": "inputText", "text": "no"}]}
        item.client.reply(7, answer)
        item.client.reply(8, {"success": True, "contentItems": [
            {"type": "inputText", "text": "later"}]})
        rows = _messages(item)[2:]
    assert [row["id"] for row in rows] == [7, "retry", 8]
    assert rows[0]["result"] == rows[1]["result"] == answer


def test_one_rpc_id_cannot_move_to_another_call():
    _posix()
    first, moved = call(7, "one"), call(7, "two")
    with link(frames=[frame(first), frame(moved)]) as item:
        item.client.initialize()
        assert item.client.receive_call() == first
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.receive_call()
        assert (caught.value.code, str(caught.value)) == (
            "HOST_CALL_CONFLICT", "host call correlation conflicts")
        assert "two" not in caught.value.next_action
        assert item.client.closed
        rows = _messages(item)
    assert all("result" not in row for row in rows)


@pytest.mark.parametrize("identifier", [False, True, 0.0, 1.5])
def test_boolean_and_float_ids_match_the_legacy_refusal(identifier):
    _posix()
    raw = frame(call(identifier))
    with pytest.raises(legacy.HostAuthorityError) as legacy_error:
        legacy.decode_call_frame(raw)
    with link(frames=[raw]) as item:
        item.client.initialize()
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.receive_call()
        assert (caught.value.code, str(caught.value)) == (
            legacy_error.value.code, "invalid host protocol frame")
        assert str(identifier) not in caught.value.next_action
        assert item.client.closed


def _frozen_reply(result):
    return json.loads(json.dumps(
        result, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False))


def _largest_fitting_alias(frozen, maximum):
    """Longest unescaped alias id whose complete frame still fits."""
    fitting = 0
    for length in range(1, 257):
        size = len(_response_bytes("a" * length, frozen))
        if size <= maximum:
            fitting = length
            continue
        break
    over = fitting + 1
    fit_size = len(_response_bytes("a" * fitting, frozen))
    over_size = len(_response_bytes("a" * over, frozen))
    if fitting < 1 or over > 256 or over_size != fit_size + 1 or over_size <= maximum:
        raise AssertionError("alias boundary is not one byte past the frame cap")
    return fitting


def test_oversize_alias_reply_writes_no_response_frame():
    """Reviewer scenario: id 7 fits, the 256-character alias envelope does not.

    The duplicate is admitted before reply, so both envelopes exist when the
    reply is validated. A refusal writes neither frame. A retry on the closed
    client writes nothing either.
    """
    _posix()
    maximum = 1024
    answer = {"success": True, "contentItems": [{"type": "inputText", "text": "x" * 800}]}
    frozen = _frozen_reply(answer)
    alias = "a" * 256
    original, duplicate, later = call(7, "one"), call(alias, "one"), call(8, "two")
    short = len(_response_bytes(7, frozen))
    wide = len(_response_bytes(alias, frozen))
    assert short <= maximum < wide
    with link(frames=[frame(original), frame(duplicate), frame(later)],
              maximum=maximum) as item:
        item.client.initialize()
        assert item.client.receive_call() == original
        assert item.client.receive_call() == later
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.reply(7, answer)
        assert (caught.value.code, str(caught.value)) == (
            "HOST_PROTOCOL_ERROR", "invalid host protocol frame")
        assert "x" * 40 not in str(caught.value)
        assert "x" * 40 not in caught.value.next_action
        assert "a" * 40 not in str(caught.value)
        assert "a" * 40 not in caught.value.next_action
        assert item.client.closed
        with pytest.raises(wire.HostAuthorityError) as retry:
            item.client.reply(7, answer)
        assert retry.value.code == "HOST_PROTOCOL_ERROR"
        rows = _messages(item)
    assert all("result" not in row for row in rows)


def test_alias_reply_boundary_writes_every_frame_or_none():
    """Largest fitting alias writes every frame; one byte more writes none."""
    _posix()
    maximum = 1024
    answer = {"success": True, "contentItems": [{"type": "inputText", "text": "x" * 800}]}
    frozen = _frozen_reply(answer)
    fitting = _largest_fitting_alias(frozen, maximum)
    assert len(_response_bytes(7, frozen)) <= maximum

    alias = "a" * fitting
    original, duplicate, later = call(7, "fit"), call(alias, "fit"), call(8, "after")
    with link(frames=[frame(original), frame(duplicate), frame(later)],
              maximum=maximum) as item:
        item.client.initialize()
        assert item.client.receive_call() == original
        assert item.client.receive_call() == later
        item.client.reply(7, answer)
        rows = _messages(item)
    replies = [row for row in rows if "result" in row]
    assert [row["id"] for row in replies] == [7, alias]
    assert replies[0]["result"] == replies[1]["result"] == answer
    assert [len(raw) for raw in item.seen if b'"result"' in raw] == [
        len(_response_bytes(7, frozen)), len(_response_bytes(alias, frozen))]

    alias = "a" * (fitting + 1)
    original, duplicate, later = call(7, "over"), call(alias, "over"), call(8, "after")
    with link(frames=[frame(original), frame(duplicate), frame(later)],
              maximum=maximum) as item:
        item.client.initialize()
        assert item.client.receive_call() == original
        assert item.client.receive_call() == later
        with pytest.raises(wire.HostAuthorityError) as caught:
            item.client.reply(7, answer)
        assert (caught.value.code, str(caught.value)) == (
            "HOST_PROTOCOL_ERROR", "invalid host protocol frame")
        assert alias not in str(caught.value)
        assert alias not in caught.value.next_action
        assert "x" * 40 not in caught.value.next_action
        assert item.client.closed
        with pytest.raises(wire.HostAuthorityError) as retry:
            item.client.reply(alias, answer)
        assert retry.value.code == "HOST_PROTOCOL_ERROR"
        rows = _messages(item)
    assert all("result" not in row for row in rows)


def _wide_answer():
    return {"success": True, "contentItems": [{"type": "inputText", "text": "x" * 800}]}


def _assert_encoding_refusal_is_terminal(item, caught):
    """Both descriptors are closed, and the refusal text is the fixed sentence."""
    assert (caught.value.code, str(caught.value)) == (
        "HOST_PROTOCOL_ERROR", "invalid host protocol frame")
    assert "x" * 40 not in str(caught.value)
    assert "a" * 40 not in str(caught.value)
    if type(caught.value) is wire.HostAuthorityError:
        assert "x" * 40 not in caught.value.next_action
        assert "a" * 40 not in caught.value.next_action
    assert item.client.closed
    assert item._client_reader.closed
    assert item._client_writer.closed
    later = {"success": False, "contentItems": [{"type": "inputText", "text": "AFTER"}]}
    for action in (
            item.client.initialize,
            item.client.receive_call,
            lambda: item.client.reply(7, later)):
        with pytest.raises(type(caught.value)) as follow:
            action()
        assert (follow.value.code, str(follow.value)) == (
            "HOST_PROTOCOL_ERROR", "invalid host protocol frame")
    item.client.close()
    assert item.client.closed
    assert item._client_reader.closed
    assert item._client_writer.closed


@pytest.mark.parametrize("implementation,error,path", [
    pytest.param(wire.ProtocolClient, wire.HostAuthorityError, "initialize", id="port-initialize"),
    pytest.param(legacy.ProtocolClient, legacy.HostAuthorityError, "initialize", id="legacy-initialize"),
    pytest.param(wire.ProtocolClient, wire.HostAuthorityError, "cached-replay", id="port-cached-replay"),
    pytest.param(legacy.ProtocolClient, legacy.HostAuthorityError, "cached-replay", id="legacy-cached-replay"),
    pytest.param(wire.ProtocolClient, wire.HostAuthorityError, "reply", id="port-reply"),
    pytest.param(wire.ProtocolClient, wire.HostAuthorityError, "alias-reply", id="port-alias-reply"),
])
def test_encoding_refusal_closes_both_descriptors(implementation, error, path):
    """An oversize frame closes the client before the exception leaves the public method.

    initialize and cached-replay are the reviewer's scenarios and match legacy.
    reply and alias-reply are the port's other encode paths. This leaf has no
    outgoing call method and no cancel write. The initialized notification is
    smaller than the initialize request, so a cap that refuses it refuses
    initialize first; both writes share _write.
    """
    _posix()
    answer = _wide_answer()
    alias = "a" * 256
    if path == "initialize":
        frames = ()
        maximum = 128
    elif path == "reply":
        frames = [frame(call(7, "one"))]
        maximum = len(_response_bytes(7, _frozen_reply(answer))) - 1
    else:
        original, duplicate, later = call(7, "one"), call(alias, "one"), call(8, "two")
        frames = [frame(original), frame(duplicate), frame(later)]
        maximum = 1024
    with link(maximum=maximum, frames=frames, implementation=implementation) as item:
        if path == "initialize":
            with pytest.raises(error) as caught:
                item.client.initialize()
        elif path == "cached-replay":
            item.client.initialize()
            assert item.client.receive_call()["id"] == 7
            item.client.reply(7, answer)
            with pytest.raises(error) as caught:
                item.client.receive_call()
        elif path == "reply":
            item.client.initialize()
            assert item.client.receive_call()["id"] == 7
            with pytest.raises(error) as caught:
                item.client.reply(7, answer)
        else:
            item.client.initialize()
            assert item.client.receive_call()["id"] == 7
            assert item.client.receive_call()["id"] == 8
            with pytest.raises(error) as caught:
                item.client.reply(7, answer)
        _assert_encoding_refusal_is_terminal(item, caught)
        observed = item
    raw = b"".join(observed.seen)
    assert b"AFTER" not in raw
    if path == "initialize":
        assert observed.seen == []
        assert b"aegis-initialize-1" not in raw
    elif path == "cached-replay":
        assert alias.encode("ascii") not in raw
        results = [row for row in observed.parsed() if "result" in row]
        assert [row["id"] for row in results] == [7]
        assert results[0]["result"] == answer
    else:
        assert all("result" not in row for row in observed.parsed())
