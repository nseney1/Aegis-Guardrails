"""Public pipe/codec leaf; fake host messages never establish native authority."""
import base64
from contextlib import contextmanager
import importlib
import json
import os
import subprocess
import sys

import pytest


@pytest.fixture
def api():
    return importlib.import_module("tools.hierarchy_host_authority")


def frame(value):
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


def call(identifier=7, call_id="call-1", **changes):
    value = {"id": identifier, "method": "item/tool/call", "params": {
        "threadId": "thread-1", "turnId": "turn-1", "callId": call_id,
        "tool": "aegis_decide", "arguments": {"request_id": "r-1"}}}
    value.update(changes)
    return value


HOST = r'''
import base64, json, sys
scenario = json.loads(sys.argv[1])
def note(value):
    with open(scenario["log"], "a", encoding="utf-8") as stream:
        stream.write(json.dumps(value) + "\n")
raw = sys.stdin.buffer.readline()
if not raw:
    sys.exit(0)
request = json.loads(raw)
note(request)
if scenario["mode"] == "hang":
    sys.stdin.buffer.read()
    sys.exit(0)
result_id = request["id"] if scenario["mode"] != "wrong-init" else "other"
result = {"userAgent": "fake", "codexHome": "/fixture/codex",
          "platformFamily": "unix", "platformOs": "linux"}
if scenario["mode"] == "bad-init":
    del result["codexHome"]
sys.stdout.buffer.write((json.dumps({"id": result_id, "result": result}) + "\n").encode())
sys.stdout.buffer.flush()
if scenario["mode"] in ("wrong-init", "bad-init"):
    sys.stdin.buffer.read()
    sys.exit(0)
note(json.loads(sys.stdin.buffer.readline()))
for raw in scenario["frames"]:
    sys.stdout.buffer.write(base64.b64decode(raw))
sys.stdout.buffer.flush()
if scenario["mode"] == "eof":
    sys.exit(0)
for line in sys.stdin.buffer:
    note(json.loads(line))
'''


@contextmanager
def host(api, tmp_path, frames=(), mode="normal", timeout=3, **options):
    if os.name != "posix":
        pytest.skip("bounded anonymous pipe transport is explicitly POSIX-only")
    log = tmp_path / "host-wire.jsonl"
    scenario = {"log": str(log), "mode": mode,
                "frames": [base64.b64encode(raw).decode() for raw in frames]}
    child = subprocess.Popen([sys.executable, "-I", "-B", "-c", HOST,
                              json.dumps(scenario)], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    client = None
    try:
        client = api.ProtocolClient(child.stdout, child.stdin, timeout_seconds=timeout,
                                    **options)
        yield client, log
    finally:
        try:
            if client is not None:
                client.close()
        finally:
            try:
                try:
                    if not child.stdin.closed:
                        child.stdin.close()
                finally:
                    if not child.stdout.closed:
                        child.stdout.close()
            finally:
                try:
                    try:
                        child.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        child.kill()  # Only this disposable host is owned here.
                        child.wait(timeout=2)
                    error = child.stderr.read()
                finally:
                    child.stderr.close()
                assert child.returncode == 0, error.decode(errors="replace")


def observed(log):
    return [json.loads(line) for line in log.read_text().splitlines()]


def test_initialize_receive_reply_over_actual_owned_pipes(api, tmp_path):
    with host(api, tmp_path, [frame(call())]) as (client, log):
        client.initialize()
        value = client.receive_call()
        assert value == call()
        client.reply(value["id"], {"success": False, "contentItems": [
            {"type": "inputText", "text": "refused"}]})
    rows = observed(log)
    assert rows[0]["method"] == "initialize"
    assert rows[0]["params"]["capabilities"]["experimentalApi"] is True
    assert rows[1] == {"method": "initialized"}
    assert rows[2] == {"id": 7, "result": {"success": False, "contentItems": [
        {"type": "inputText", "text": "refused"}]}}
    assert client.closed


@pytest.mark.parametrize("raw", [
    b'{"id":1,"id":2,"method":"item/tool/call","params":{}}\n',
    b'{"id":true,"method":"item/tool/call","params":{}}\n',
    b'{"id":1,"method":"item/tool/call","params":{"arguments":NaN}}\n',
    b'\xff\n', b'{}\n', b'[]\n', b'{bad}\n',
    frame(call(extra="not-in-envelope")),
    frame(call(method="command/exec")),
    frame(call(params={"threadId": "thread-1", "turnId": "turn-1",
                       "callId": "call-1", "tool": "aegis_decide",
                       "arguments": {}, "actor": "root"})),
])
def test_closed_call_codec_refuses_exact_protocol_error(api, raw):
    with pytest.raises(api.HostAuthorityError) as caught:
        api.decode_call_frame(raw)
    assert isinstance(caught.value, PermissionError)
    assert caught.value.code == "HOST_PROTOCOL_ERROR"
    assert str(caught.value) == "invalid host protocol frame"


def test_codec_preserves_model_fields_as_inert_arguments_and_rpc_id_type(api):
    value = call(identifier="7")
    value["params"]["arguments"] = {"threadId": "forged", "id": 900,
                                       "role": "root", "generation": 99}
    assert api.decode_call_frame(frame(value)) == value
    assert api.decode_call_frame(frame(value))["id"] == "7"


def test_frame_and_depth_limits_refuse_without_authority(api):
    with pytest.raises(api.HostAuthorityError, match="^invalid host protocol frame$") as caught:
        api.decode_call_frame(b"x" * (1024 * 1024 + 1))
    assert caught.value.code == "HOST_PROTOCOL_ERROR"
    value = call()
    nested = {}
    for _ in range(40):
        nested = {"nested": nested}
    value["params"]["arguments"] = nested
    with pytest.raises(api.HostAuthorityError) as caught:
        api.decode_call_frame(frame(value))
    assert caught.value.code == "HOST_PROTOCOL_ERROR"


@pytest.mark.parametrize("mode,frames,code,reason", [
    ("hang", (), "HOST_PROTOCOL_TIMEOUT", "host protocol deadline expired"),
    ("wrong-init", (), "HOST_PROTOCOL_ERROR", "invalid host protocol frame"),
    ("bad-init", (), "HOST_PROTOCOL_ERROR", "invalid host protocol frame"),
    ("eof", (b'{"id":7',), "HOST_PROTOCOL_ERROR", "invalid host protocol frame"),
    ("eof", (), "HOST_PROTOCOL_ERROR", "invalid host protocol frame"),
])
def test_missing_reply_wrong_id_torn_and_eof_close_transport(api, tmp_path, mode,
                                                           frames, code, reason):
    timeout = 0.2 if mode == "hang" else 3
    with host(api, tmp_path, frames, mode=mode, timeout=timeout) as (client, _):
        with pytest.raises(api.HostAuthorityError) as caught:
            client.initialize()
            client.receive_call()
        assert (caught.value.code, str(caught.value)) == (code, reason)
        assert client.closed


def test_calls_cannot_arrive_before_initialization_and_no_second_init(api, tmp_path):
    with host(api, tmp_path) as (client, _):
        with pytest.raises(api.HostAuthorityError) as caught:
            client.receive_call()
        assert caught.value.code == "HOST_PROTOCOL_ERROR"
    with host(api, tmp_path) as (client, _):
        client.initialize()
        with pytest.raises(api.HostAuthorityError) as caught:
            client.initialize()
        assert caught.value.code == "HOST_PROTOCOL_ERROR"


def test_out_of_order_replies_and_same_spelling_ids_remain_distinct(api, tmp_path):
    one, two = call(7, "a"), call("7", "b")
    with host(api, tmp_path, [frame(one), frame(two)]) as (client, log):
        client.initialize()
        assert client.receive_call() == one
        assert client.receive_call() == two
        client.reply("7", {"success": True, "contentItems": [{"type": "inputText", "text": "b"}]})
        client.reply(7, {"success": False, "contentItems": [{"type": "inputText", "text": "a"}]})
    assert [row["id"] for row in observed(log)[2:]] == ["7", 7]


def test_duplicate_completed_call_recovers_reply_without_second_dispatch(api, tmp_path):
    original, duplicate, later = call(7), call("retry"), call(8, "later")
    with host(api, tmp_path, [frame(original), frame(duplicate), frame(later)]) as (client, log):
        client.initialize()
        assert client.receive_call() == original
        answer = {"success": False, "contentItems": [{"type": "inputText", "text": "no"}]}
        client.reply(7, answer)
        assert client.receive_call() == later
        client.reply(8, answer)
    assert [row["id"] for row in observed(log)[2:]] == [7, "retry", 8]
    assert observed(log)[2]["result"] == observed(log)[3]["result"]


def test_changed_duplicate_and_unknown_reply_never_cross_dispatch(api, tmp_path):
    changed = call(9)
    changed["params"]["arguments"] = {"request_id": "changed"}
    with host(api, tmp_path, [frame(call()), frame(changed)]) as (client, _):
        client.initialize()
        client.receive_call()
        with pytest.raises(api.HostAuthorityError) as caught:
            client.receive_call()
        assert caught.value.code == "HOST_CALL_CONFLICT"
        assert client.closed
    with host(api, tmp_path) as (client, _):
        client.initialize()
        with pytest.raises(api.HostAuthorityError) as caught:
            client.reply("not-pending", {"success": False, "contentItems": []})
        assert caught.value.code == "HOST_CALL_CONFLICT"


def test_unowned_or_claimed_enrollment_can_only_refuse(api):
    for actor in ("unknown", "predecessor", "current-root"):
        value = call()
        value["params"]["arguments"] = {"actor": actor, "trusted": True,
                                           "generation": 1, "native_qualified": True}
        answer = api.refuse_unowned_call(api.decode_call_frame(frame(value)))
        body = json.loads(answer["contentItems"][0]["text"])
        assert answer["success"] is False
        assert body == {"state": "refused", "effect": "none", "code": "STALE_INVOCATION",
                        "reason": "host call has no trusted enrollment",
                        "identity_authenticated": False, "native_qualified": False}


def test_error_fields_are_readonly_closed_and_transport_is_explicitly_posix(api,
                                                                         monkeypatch):
    error = api.HostAuthorityError("STALE_INVOCATION", "not enrolled")
    with pytest.raises(AttributeError):
        error.code = "made-up"
    with pytest.raises(AttributeError):
        error.reason = "changed"
    with pytest.raises(ValueError):
        api.HostAuthorityError("made-up", "no")
    with monkeypatch.context() as patch:
        patch.setattr(os, "name", "nt")  # Actual OS boundary; restored before pytest I/O.
        with pytest.raises(api.HostAuthorityError) as caught:
            api.ProtocolClient(None, None)
    assert caught.value.code == "UNSUPPORTED_HOST"


def _reap_regression_child(child):
    """The regression itself must clean its real child even on expected RED."""
    for stream in (child.stdin, child.stdout):
        if not stream.closed:
            stream.close()
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=2)
    child.stderr.close()


def test_host_fixture_reaps_actual_child_when_pipe_setup_fails(api, tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("actual anonymous pipe cleanup is POSIX-only")
    actual_popen, children = subprocess.Popen, []

    def retain_child(*args, **kwargs):
        child = actual_popen(*args, **kwargs)
        children.append(child)
        return child

    def pipe_failure(_fd, _blocking):
        raise OSError("injected pipe setup failure")

    monkeypatch.setattr(subprocess, "Popen", retain_child)  # Real OS process boundary.
    monkeypatch.setattr(os, "set_blocking", pipe_failure)
    try:
        with pytest.raises(api.HostAuthorityError) as caught:
            with host(api, tmp_path):
                pytest.fail("broken pipe setup cannot enter the client body")
        assert caught.value.code == "HOST_PROTOCOL_ERROR"
        assert len(children) == 1
        assert children[0].returncode is not None, "host fixture did not reap its child"
        assert all(stream.closed for stream in
                   (children[0].stdin, children[0].stdout, children[0].stderr))
    finally:
        for child in children:
            _reap_regression_child(child)


def test_host_fixture_reaps_actual_child_when_pipe_close_fails(api, tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("actual anonymous pipe cleanup is POSIX-only")
    actual_popen, children = subprocess.Popen, []

    class FailingClosePipe:
        def __init__(self, stream):
            self.stream = stream
            self.failed = False

        def fileno(self):
            return self.stream.fileno()

        @property
        def closed(self):
            return self.stream.closed

        def close(self):
            self.stream.close()
            if not self.failed:
                self.failed = True
                raise OSError("injected pipe close failure")

    def retain_child(*args, **kwargs):
        child = actual_popen(*args, **kwargs)
        child.stdout = FailingClosePipe(child.stdout)  # Real pipe, actual close, OS error.
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", retain_child)
    try:
        with pytest.raises(OSError, match="^injected pipe close failure$"):
            with host(api, tmp_path) as (client, _):
                client.initialize()
        assert len(children) == 1
        assert children[0].returncode is not None, "host fixture did not reap its child"
        assert all(stream.closed for stream in
                   (children[0].stdin, children[0].stdout, children[0].stderr))
    finally:
        for child in children:
            _reap_regression_child(child)
