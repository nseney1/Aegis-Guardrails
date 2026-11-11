"""Public pipe/codec leaf; fake host messages never establish native authority."""
import base64
import copy
from contextlib import ExitStack, contextmanager
import hashlib
import importlib
import json
import os
import pickle
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

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


LIVE_ROLE_MAP_RAW = b'{\n  "schema": "aegis.protected-role-profiles/v1",\n  "profiles": [\n    {\n      "role": "root",\n      "canonical_profile_sha256": "3c6102e909a2b21d1d4c15c97176faac24db544da5ff6adeb7fac4a3c719d720",\n      "runtime_profile_sha256": "34b9b07d4fa988dd96b73a7aa9b1c968f2088d706144db6044c5e3850ed158d5",\n      "runtime_profile": {\n        "model": "gpt-6.1-sol",\n        "reasoning_effort": "ultra",\n        "service_tier": "default",\n        "approval_policy": "on-request",\n        "approvals_reviewer": "auto_review",\n        "permission_profile": {\n          "type": "managed",\n          "file_system": {\n            "type": "restricted",\n            "entries": [\n              {\n                "path": {\n                  "type": "special",\n                  "value": {\n                    "kind": "minimal"\n                  }\n                },\n                "access": "read"\n              }\n            ]\n          },\n          "network": "restricted"\n        },\n        "effective_permission_profile": {\n          "file_system": {\n            "entries": [\n              {\n                "access": "read",\n                "path": {\n                  "type": "special",\n                  "value": {\n                    "kind": "minimal"\n                  }\n                }\n              }\n            ],\n            "type": "restricted"\n          },\n          "network": "restricted",\n          "type": "managed"\n        },\n        "file_system_sandbox_policy": {\n          "kind": "restricted",\n          "entries": [\n            {\n              "path": {\n                "type": "special",\n                "value": {\n                  "kind": "minimal"\n                }\n              },\n              "access": "read"\n            }\n          ]\n        },\n        "network_sandbox_policy": "restricted",\n        "workspace_roots": [],\n        "allow_login_shell": false,\n        "shell_environment_policy": {\n          "inherit": "none",\n          "ignore_default_excludes": false,\n          "exclude": [],\n          "set": {},\n          "include_only": [],\n          "use_profile": false\n        },\n        "windows_sandbox_mode": null,\n        "windows_sandbox_type": "none",\n        "tool_policy": {\n          "allowed_tools": [\n            {\n              "namespace": "functions",\n              "name": "aegis_decision"\n            }\n          ],\n          "require_managed_sandbox": true,\n          "require_unified_exec": false,\n          "expose_additional_permissions": false\n        },\n        "session_isolation": "isolated",\n        "provider_binding_sha256": "de444870d44d3dac1e1dc4fe36a4aa0551e7d76627dec49e6eaf91a3abe33f77"\n      },\n      "tool_ceiling": [\n        {\n          "namespace": "functions",\n          "name": "aegis_decision"\n        }\n      ]\n    }\n  ]\n}\n'


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


def test_rpc_zero_keeps_integer_and_string_identity_on_real_pipes(api, tmp_path):
    integer_call, string_call = call(0, "integer-zero"), call("0", "string-zero")
    with host(api, tmp_path, [frame(integer_call), frame(string_call)]) as (client, log):
        client.initialize()
        assert client.receive_call() == integer_call
        assert client.receive_call() == string_call
        client.reply("0", {"success": True, "contentItems": [{"type": "inputText", "text": "string"}]})
        client.reply(0, {"success": False, "contentItems": [{"type": "inputText", "text": "integer"}]})
    replies = observed(log)[2:]
    assert [(type(row["id"]), row["id"]) for row in replies] == [(str, "0"), (int, 0)]
    assert [row["result"]["success"] for row in replies] == [True, False]


@pytest.mark.parametrize("identifier", [False, True, 0.0])
def test_rpc_zero_cannot_be_replaced_by_boolean_or_float(api, identifier):
    with pytest.raises(api.HostAuthorityError) as caught:
        api.decode_call_frame(frame(call(identifier)))
    assert caught.value.code == "HOST_PROTOCOL_ERROR"


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


@contextmanager
def raw_pipe_client(api, timeout=3):
    """A client on real anonymous pipes whose peer ends the test owns directly."""
    if os.name != "posix":
        pytest.skip("bounded anonymous pipe transport is explicitly POSIX-only")
    to_client_r, to_client_w = os.pipe()
    to_peer_r, to_peer_w = os.pipe()
    owned = {to_client_w, to_peer_r}
    client = api.ProtocolClient(os.fdopen(to_client_r, "rb", 0), os.fdopen(to_peer_w, "wb", 0),
                                timeout_seconds=timeout)
    try:
        yield client, to_client_r, to_peer_w, to_client_w, to_peer_r, owned
    finally:
        try:
            client.close()
        finally:
            for fd in owned:
                try:
                    os.close(fd)
                except OSError:
                    pass


def waiting_on(api, monkeypatch, fd, *, writing):
    """Signal once the client is actually waiting on fd; the wait itself stays real."""
    entered, actual = threading.Event(), select.select

    def observed(readable, writable, exceptional, timeout=None):
        if fd in (writable if writing else readable):
            entered.set()
        return actual(readable, writable, exceptional, timeout)

    monkeypatch.setattr(api.select, "select", observed)
    return entered


def test_close_during_blocked_write_never_writes_a_reused_descriptor(api, tmp_path, monkeypatch):
    with raw_pipe_client(api) as (client, _, client_write, _, peer_read, owned):
        queued = 0
        while True:  # Fill the outgoing pipe so the next frame must wait to be written.
            try:
                queued += os.write(client_write, b"x" * 65536)
            except BlockingIOError:
                break
        entered = waiting_on(api, monkeypatch, client_write, writing=True)
        errors = []

        def initialize():
            try:
                client.initialize()
            except api.HostAuthorityError as exc:
                errors.append(exc.code)

        worker = threading.Thread(target=initialize)
        worker.start()
        victim_path = tmp_path / "unrelated-file"
        # Opened before close so it cannot itself land on a released number.
        victim = os.open(victim_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        owned.add(victim)
        try:
            assert entered.wait(5)
            client.close()  # Revocation while the write is still pending.
            os.dup2(victim, client_write)  # The released number now names another file.
            owned.add(client_write)
            while queued:  # The old pipe drains, so a stale wait on it can wake.
                queued -= len(os.read(peer_read, queued))
        finally:
            worker.join(10)
        assert not worker.is_alive()
        assert victim_path.read_bytes() == b""
        assert errors == ["HOST_PROTOCOL_ERROR"]


def test_close_during_blocked_read_never_reads_a_reused_descriptor(api, monkeypatch):
    with raw_pipe_client(api) as (client, client_read, _, peer_write, _, owned):
        entered = waiting_on(api, monkeypatch, client_read, writing=False)
        outcome = []

        def initialize():
            try:
                client.initialize()
                outcome.append("initialized")
            except api.HostAuthorityError as exc:
                outcome.append(exc.code)

        worker = threading.Thread(target=initialize)
        worker.start()
        forged = frame({"id": "aegis-initialize-1", "result": {
            "codexHome": "/forged", "platformFamily": "unix", "platformOs": "linux",
            "userAgent": "forged"}})
        # Created before close so neither end can itself land on a released number.
        forged_read, forged_write = os.pipe()
        owned.update({forged_read, forged_write})
        os.write(forged_write, forged)
        # Keep the old pipe readable after close, so the wake-up write cannot EPIPE.
        owned.add(os.dup(client_read))
        try:
            assert entered.wait(5)  # The request is written; the reply is awaited.
            client.close()
            os.dup2(forged_read, client_read)  # The released number now names another pipe.
            owned.add(client_read)
            os.write(peer_write, b"\n")  # The old pipe becomes readable, so a stale wait can wake.
        finally:
            worker.join(10)
        assert not worker.is_alive()
        assert outcome == ["HOST_PROTOCOL_ERROR"]
        os.set_blocking(client_read, False)
        try:
            unread = os.read(client_read, 65536)
        except BlockingIOError:
            unread = b""  # The closed client consumed the other pipe's data.
        assert unread == forged


@pytest.mark.timing
def test_close_interrupts_a_blocked_read_long_before_its_deadline(api, monkeypatch):
    with raw_pipe_client(api, timeout=3) as (client, client_read, _, _, _, _):
        entered = waiting_on(api, monkeypatch, client_read, writing=False)
        finished = []

        def initialize():
            try:
                client.initialize()
            except api.HostAuthorityError as exc:
                finished.append((exc.code, time.monotonic()))

        worker = threading.Thread(target=initialize)
        worker.start()
        try:
            assert entered.wait(5)
            # entered fires just before the syscall; without this, a close that
            # wins the race fails fast even in the unfixed client.
            time.sleep(0.2)
            closed_at = time.monotonic()
            client.close()
        finally:
            worker.join(10)
        assert not worker.is_alive()
        assert [code for code, _ in finished] == ["HOST_PROTOCOL_ERROR"]
        assert finished[0][1] - closed_at < 1.0  # The 3 s read deadline is not waited out.


def _control_digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _file_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@contextmanager
def owned_runtime_boundary(api, tmp_path, monkeypatch, fault=None, *,
                           initialize_canonical=True, planned_successor=False,
                           initial_control=False, control_fault=None, live_control=False, live_fault=None):
    """Fake the external Rust/OS boundary, never an H authority or N1 loader.

    This fixture is authored during FULL-01, but must only execute in a later
    admitted pytest window. It owns actual sockets/pipes and no subprocess.
    """
    if sys.platform != "linux":
        pytest.skip("first protected constructor requires Linux peer/procfs readback")
    from tools import hierarchy_lifecycle as lifecycle

    assert Path(lifecycle.__file__).parent == Path(api.__file__).parent
    uid = os.geteuid()
    executable = Path(os.readlink("/proc/self/exe"))
    peer_pid = os.getpid() + 1000000  # Only the actual OS readback is mocked.
    actual_stat, actual_fstat, actual_listxattr = os.stat, os.fstat, os.listxattr
    actual_readlink = os.readlink
    actual_read_bytes, actual_read_text = Path.read_bytes, Path.read_text
    actual_getsockopt = socket.socket.getsockopt
    proc_stat = Path("/proc/self/stat").read_text()
    proc_tail = proc_stat[proc_stat.rfind(")") + 2:]
    start_ticks = int(proc_tail.split()[19])
    process = {"boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
               "pid_namespace": actual_stat("/proc/self/ns/pid").st_ino,
               "pid": peer_pid, "start_ticks": start_ticks}
    roles = ("root", "router", "coordinator", "operator", "reviewer")
    actors = {}
    for role in roles:
        actors["fixture-" + role] = {
            "role": role, "generation": 1, "cap_seconds": 60,
            "profile": {"model": "gpt-6.1-sol",
                        "effort": "medium" if role == "router" else "ultra",
                        "tier": "ultrafast" if role == "router" else "default",
                        "filesystem": "read-only" if role == "root" else "restricted",
                        "tools": ["read"]}}
    successors = {}
    if planned_successor:
        actors["fixture-operator-next"] = json.loads(json.dumps(actors["fixture-operator"]))
        actors["fixture-operator-next"]["generation"] = 2
        successors["fixture-operator"] = "fixture-operator-next"
    plan_body = {"source": {"commit": "c3471723d32706852a8c182de0eef8cce87e7465",
                            "tree": "69691322f217818108577f3bb54546e7ae7de5b1",
                            "dirty_sha256": "0" * 64},
                 "actors": actors, "current": {r: "fixture-" + r for r in roles},
                 "successors": successors}
    plan = tmp_path / "accepted-plan.json"
    plan.write_text(json.dumps(plan_body, sort_keys=True))
    plan_ref = {"path": str(plan), "sha256": _file_digest(plan)}
    policy = {"schema": lifecycle.POLICY, "authority": [plan_ref], **plan_body}
    canonical = tmp_path / "canonical"
    if initialize_canonical:
        lifecycle.initialize(canonical, policy)  # Real public temporary N1 source.
        loaded_policy, state = lifecycle.Lifecycle(canonical).load()
        assert loaded_policy == policy and state["sequence"] == 0
    # No protected genesis, INITIAL intent, activation or native grant is claimed.
    ceiling = tmp_path / "role-ceiling.json"
    ceiling.write_bytes(LIVE_ROLE_MAP_RAW) if live_control else ceiling.write_text(
        json.dumps({role: [] for role in roles}))
    endpoint_home = None
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client, peer, wire = None, None, None
    streams, thread, requests, errors = [], None, [], []
    app_thread = None
    enrolled, pending = threading.Event(), {}
    held = threading.Event()  # Releases a runtime reply held by a "held-*" control fault.
    peer_read, peer_write = None, None
    try:
        # sockaddr_un has a short byte limit; pytest's descriptive case path may
        # exceed it before any H API runs. This remains a real private pathname.
        endpoint_home = tempfile.TemporaryDirectory(prefix="hc-")
        endpoint = Path(endpoint_home.name) / "c"
        listener.bind(str(endpoint))
        os.chmod(endpoint, 0o600)
        listener.listen(1)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(endpoint))
        peer, _ = listener.accept()
        peer.settimeout(2)
        peer_read, host_write = os.pipe()
        host_read, peer_write = os.pipe()
        reader, writer = os.fdopen(host_read, "rb", 0), os.fdopen(host_write, "wb", 0)
        streams.extend((reader, writer))
        closure = [{"path": str(Path(api.__file__).resolve()),
                    "sha256": _file_digest(api.__file__)}]
        if live_control:
            closure.extend({"path": str(Path(api.__file__).with_name(name).resolve()),
                            "sha256": _file_digest(Path(api.__file__).with_name(name))}
                           for name in ("hierarchy_lifecycle.py", "hierarchy_mailbox.py"))
            closure.sort(key=lambda row: row["path"])
        deployment = tmp_path / "deployment.json"
        deployment.write_text(json.dumps({
            "schema": "aegis.protected-host-deployment/v1",
            "runtime_uid": uid, "host_uid": uid, "model_uid": uid + 1,
            "runtime_executable": {"path": str(executable),
                                   "sha256": _file_digest(executable)},
            "host_source_closure": closure, "canonical_root": str(canonical),
            "runtime_control_endpoint": str(endpoint),
            "role_ceiling_ref": {"path": str(ceiling), "sha256": _file_digest(ceiling)}}))
        channel = {"schema": "aegis.host-channel-witness/v1",
                   "runtime_instance": dict(process), "appserver_instance": dict(process),
                   "control_peer_instance": dict(process),
                   "read_pipe_inode": actual_fstat(peer_write).st_ino,
                   "write_pipe_inode": actual_fstat(peer_read).st_ino,
                   "epoch": 17, "deployment_sha256": _file_digest(deployment),
                   "runtime_executable_sha256": _file_digest(executable),
                   "host_source_closure_sha256": _control_digest(closure),
                   "role_ceiling_sha256": _file_digest(ceiling)}
        reservations = [{
            "schema": "aegis.host-reservation-witness/v1",
            "channel_instance_sha256": _control_digest(channel),
            "approved_plan_sha256": plan_ref["sha256"], "actor_cid": cid,
            "role": actor["role"], "generation": actor["generation"],
            "profile_sha256": _control_digest(actor["profile"]),
            "cap_seconds": actor["cap_seconds"], "reservation_sequence": index,
            "expires_monotonic_ns": time.monotonic_ns() + 5000000000}
            for index, (cid, actor) in enumerate(sorted(actors.items()), 1)]

        def protected_metadata(value):
            # Actual OS provenance is the mocked boundary; file contents are real.
            data = list(value)
            # The confined test user namespace maps host-root-owned ancestors
            # to overflow UID 65534. Model those protected fixture files as
            # owned by the declared host; preserve every other owner value.
            if value.st_uid == 65534:
                data[4] = uid
            if fault == "foreign-file-owner" and stat.S_ISREG(value.st_mode):
                data[4] = uid + 77
            if stat.S_ISDIR(value.st_mode) or stat.S_ISREG(value.st_mode):
                data[0] &= ~0o022
            return os.stat_result(data)

        def map_proc(path):
            text = os.fspath(path)
            prefix = "/proc/%s/" % peer_pid
            return "/proc/self/" + text[len(prefix):] if text.startswith(prefix) else text

        def kernel_stat(path, *args, **kwargs):
            if os.fspath(path) == "/proc/%s/fd/0" % peer_pid:
                return protected_metadata(actual_fstat(peer_read))
            if os.fspath(path) == "/proc/%s/fd/1" % peer_pid:
                return protected_metadata(actual_fstat(peer_write))
            return protected_metadata(actual_stat(map_proc(path), *args, **kwargs))

        def kernel_readlink(path, *args, **kwargs):
            value = os.fspath(path)
            if value == "/proc/%s/fd/0" % peer_pid:
                return "pipe:[%s]" % actual_fstat(peer_read).st_ino
            if value == "/proc/%s/fd/1" % peer_pid:
                return "pipe:[%s]" % actual_fstat(peer_write).st_ino
            return actual_readlink(map_proc(path), *args, **kwargs)

        def kernel_bytes(path):
            if str(path) == "/proc/%s/stat" % peer_pid:
                return ("%s (mock-rust) " % peer_pid + proc_tail).encode()
            return actual_read_bytes(Path(map_proc(path)))

        def kernel_text(path, *args, **kwargs):
            if str(path) == "/proc/%s/stat" % peer_pid:
                return "%s (mock-rust) " % peer_pid + proc_tail
            return actual_read_text(Path(map_proc(path)), *args, **kwargs)

        def peer_credentials(sock, level, option, *args):
            if level == socket.SOL_SOCKET and option == socket.SO_PEERCRED:
                peer_uid = uid + 77 if fault == "foreign-peer" else uid
                return struct.pack("3i", peer_pid, peer_uid, uid)
            return actual_getsockopt(sock, level, option, *args)

        with monkeypatch.context() as boundary:
            boundary.setattr(os, "stat", kernel_stat)
            boundary.setattr(os, "fstat", lambda fd: protected_metadata(actual_fstat(fd)))
            boundary.setattr(os, "readlink", kernel_readlink)
            # Like the 0o022 masking above: the host interpreter's install path may carry
            # POSIX ACLs (GitHub's hosted toolcache does), which is host provenance, not fixture state.
            boundary.setattr(os, "listxattr", lambda path, *args, **kwargs: [
                name for name in actual_listxattr(path, *args, **kwargs)
                if name not in ("system.posix_acl_access", "system.posix_acl_default")])
            boundary.setattr(Path, "read_bytes", kernel_bytes)
            boundary.setattr(Path, "read_text", kernel_text)
            boundary.setattr(socket.socket, "getsockopt", peer_credentials)
            wire = peer.makefile("rwb", buffering=0)

            def rust_control():
                bound, started = {}, {}  # External Rust permit/registry boundary.
                try:
                    for raw in wire:
                        request = json.loads(raw)
                        requests.append(request)
                        assert set(request) == {"schema", "id", "epoch", "nonce", "method", "params"}
                        assert request["schema"] == (
                            "aegis.protected-live-control/v1" if request["method"] in {
                                "describe_live", "enroll_live", "pending_call", "retire_call"}
                            else "aegis.protected-initial-control/v1")
                        assert len(request["nonce"]) == 64
                        assert request["id"] == len(requests)
                        if request["method"] == "describe":
                            assert request["id"] == 1 and request["epoch"] == 0
                            assert request["params"] == {}
                            result = {"channel_witness": channel}
                        elif request["method"] == "reserve_initial":
                            assert request["epoch"] == 17
                            assert request["params"] == {"approved_plan": plan_ref}
                            result = {"reservations": reservations}
                        elif request["method"] in {"describe_live", "enroll_live", "pending_call", "retire_call"}:
                            assert live_control and not (canonical / ".write.lock").exists()
                            params = request["params"]
                            cid = params["actor_cid"]
                            actor = actors[cid]
                            profile = json.loads(LIVE_ROLE_MAP_RAW)["profiles"][0]
                            projection = {
                                "actor_cid": cid, "role": actor["role"],
                                "generation": actor["generation"],
                                "profile_sha256": _control_digest(actor["profile"]),
                                "runtime_profile_sha256": profile["runtime_profile_sha256"],
                                "actor_started_monotonic_ns": started[cid],
                                "actor_deadline_monotonic_ns": started[cid] + actor["cap_seconds"] * 10**9}
                            if request["method"] == "describe_live":
                                projection["runtime_profile"] = copy.deepcopy(profile["runtime_profile"])
                                if live_fault == "profile":
                                    projection["runtime_profile"]["network_sandbox_policy"] = "enabled"
                                result = {"actor": projection, "runtime_record": {
                                    "schema": "aegis.protected-runtime-binding/v1",
                                    "runtime_instance": process, "appserver_instance": process,
                                    "channel": {key: channel[key] for key in (
                                        "read_pipe_inode", "write_pipe_inode", "epoch")},
                                    "runtime_source": {"commit": plan_body["source"]["commit"],
                                                       "tree": plan_body["source"]["tree"],
                                                       "executable_sha256": _file_digest(executable)},
                                    "tool_ceiling": profile["tool_ceiling"],
                                    "control_methods": ["describe", "reserve_initial", "bind_initial",
                                                        "start_initial", "describe_live", "enroll_live",
                                                        "pending_call", "retire_call"]}}
                            elif request["method"] == "enroll_live":
                                snapshot = lifecycle.Lifecycle(canonical).initial_bootstrap()
                                receipt = next(row["receipt"] for row in snapshot["creations"]
                                               if row["actor_cid"] == cid)
                                assert params == {
                                    "actor_cid": cid, "generation": actor["generation"],
                                    "policy_sha256": _control_digest(lifecycle.Lifecycle(canonical).load()[0]),
                                    "initial_event_id": receipt["event_id"],
                                    "initial_event_sha256": receipt["event_sha256"],
                                    "runtime_profile_sha256": profile["runtime_profile_sha256"],
                                    "deadline_monotonic_ns": params["deadline_monotonic_ns"]}
                                result = {"actor_cid": cid, "generation": actor["generation"],
                                          "state": "enrolled"}
                                enrolled.set()
                            elif request["method"] == "pending_call":
                                assert pending and params == {
                                    **pending["correlation"],
                                    "deadline_monotonic_ns": params["deadline_monotonic_ns"]}
                                result = {**pending["correlation"], **projection, "epoch": 17,
                                          "call_started_monotonic_ns": pending["start"],
                                          "call_deadline_monotonic_ns": min(
                                              projection["actor_deadline_monotonic_ns"],
                                              pending["start"] + 5 * 10**9,
                                              params["deadline_monotonic_ns"]),
                                          "mode": "normal", "original_event_id": None,
                                          "recovery_of": None}
                                if live_fault == "rpc":
                                    result["rpc_id"] = "0"
                            else:
                                assert all(params[key] == value
                                           and type(params[key]) is type(value)
                                           for key, value in pending["correlation"].items())
                                assert params["canonical_state"] is None
                                result = {"actor_cid": cid, "rpc_id": params["rpc_id"],
                                          "state": "awaiting_terminal"}
                        else:
                            assert initial_control
                            assert request["epoch"] == 17
                            assert not (canonical / ".write.lock").exists()
                            policy, state = lifecycle.Lifecycle(canonical).load()
                            snapshot = lifecycle.Lifecycle(canonical).initial_bootstrap()
                            params = request["params"]
                            if request["method"] == "bind_initial":
                                assert set(params) == {"deadline_monotonic_ns", "initial"}
                                initial = params["initial"]
                                cid = initial["actor_cid"]
                                witness = next(row for row in snapshot["reservations"]
                                               if row["actor_cid"] == cid)
                                creation = next(row for row in snapshot["creations"]
                                                if row["actor_cid"] == cid)
                                receipt = creation["receipt"]
                                expected = {key: witness[key] for key in (
                                    "actor_cid", "role", "generation", "profile_sha256",
                                    "cap_seconds", "approved_plan_sha256", "channel_instance_sha256")}
                                expected.update({
                                    "policy_sha256": _control_digest(policy),
                                    "reservation_witness_sha256": _control_digest(witness),
                                    "genesis_event_sha256": snapshot["genesis_receipt"]["event_sha256"],
                                    "initial_event_id": receipt["event_id"],
                                    "initial_sequence": receipt["sequence"],
                                    "initial_event_sha256": receipt["event_sha256"]})
                                assert initial == expected
                                assert state["current"][witness["role"]] == cid
                                assert cid not in bound
                                deadline = params["deadline_monotonic_ns"]
                                assert type(deadline) is int
                                assert time.monotonic_ns() < deadline <= witness["expires_monotonic_ns"]
                                assert deadline <= time.monotonic_ns() + 5000000000
                                bound[cid] = (receipt["event_id"], deadline)
                                result = {"actor_cid": cid, "state": "bound"}
                            else:
                                assert request["method"] == "start_initial"
                                assert set(params) == {"actor_cid", "initial_event_id",
                                                       "deadline_monotonic_ns"}
                                cid = params["actor_cid"]
                                identifier, deadline = bound[cid]
                                assert params["initial_event_id"] == identifier
                                assert time.monotonic_ns() < params["deadline_monotonic_ns"] <= deadline
                                assert cid not in started
                                started[cid] = time.monotonic_ns()  # Actual external StartIssued boundary.
                                result = {"actor_cid": cid, "state": "started"}
                            if control_fault == "lost-" + request["method"] + "-reply":
                                peer.shutdown(socket.SHUT_WR)
                                break
                            if control_fault == "wrong-bind-cid" and request["method"] == "bind_initial":
                                result["actor_cid"] = "foreign-cid"
                        if control_fault == "held-" + request["method"] + "-reply":
                            held.wait(10)  # The runtime keeps the request; teardown releases it.
                            break
                        nonce = "0" * 64 if fault == "wrong-nonce" else request["nonce"]
                        wire.write(frame({"schema": request["schema"], "id": request["id"],
                                          "epoch": 17, "nonce": nonce, "result": result}))
                except Exception as error:
                    errors.append(error)

            thread = threading.Thread(target=rust_control, daemon=True)
            thread.start()
            if live_control:
                def appserver():
                    try:
                        with os.fdopen(os.dup(peer_read), "rb", 0) as source:
                            raw = source.readline()
                            if not raw:
                                return
                            initialize = json.loads(raw)
                            assert initialize["method"] == "initialize"
                            os.write(peer_write, frame({"id": initialize["id"], "result": {
                                "userAgent": "source-fixture", "codexHome": "/fixture/codex",
                                "platformFamily": "unix", "platformOs": "linux"}}))
                            assert json.loads(source.readline()) == {"method": "initialized"}
                            if not enrolled.wait(3):
                                if writer.closed:
                                    return
                                raise AssertionError("actual LIVE enrollment was not observed")
                            state = lifecycle.Lifecycle(canonical).load()[1]
                            command = {"event_id": "live-decision-1", "request_id": "fixture-authority",
                                       "request_sha256": state["requests"]["fixture-authority"]["raw"]["sha256"],
                                       "decision": "approve", "reason": "reviewed"}
                            pending["correlation"] = {
                                "actor_cid": "fixture-root", "rpc_id": 0, "thread_id": "fixture-root",
                                "turn_id": "turn-live", "call_id": "call-live", "namespace": None,
                                "tool": "aegis_decision", "event_id": command["event_id"]}
                            pending["start"] = time.monotonic_ns()
                            os.write(peer_write, frame({"id": 0, "method": "item/tool/call", "params": {
                                "threadId": "fixture-root", "turnId": "turn-live", "callId": "call-live",
                                "namespace": None, "tool": "aegis_decision", "arguments": command}}))
                            while source.readline():
                                pass
                    except (BrokenPipeError, ConnectionResetError):
                        pass  # Owned transport closure is the external process boundary.
                    except Exception as error:
                        errors.append(error)
                app_thread = threading.Thread(target=appserver, daemon=True)
                app_thread.start()
            yield client, reader, writer, deployment, plan_ref, requests
    finally:
        # Every close/reap runs even if another cleanup operation raises.
        # LIFO closes H's ends, interrupts Rust's read, joins, then closes peers.
        with ExitStack() as cleanup:
            if endpoint_home is not None:
                cleanup.callback(endpoint_home.cleanup)
            for fd in (peer_read, peer_write):
                if fd is not None:
                    cleanup.callback(os.close, fd)
            cleanup.callback(listener.close)
            if peer is not None:
                cleanup.callback(peer.close)
            if wire is not None:
                cleanup.callback(wire.close)
            if thread is not None:
                cleanup.callback(thread.join, timeout=3)
                cleanup.callback(held.set)  # LIFO: release a held reply before the join.
            if app_thread is not None:
                cleanup.callback(app_thread.join, timeout=3)
            if peer is not None:
                cleanup.callback(peer.shutdown, socket.SHUT_RDWR)
            for stream in streams:
                cleanup.callback(stream.close)
            if client is not None:
                cleanup.callback(client.close)
        assert thread is None or not thread.is_alive(), "external Rust stand-in did not stop"
        assert app_thread is None or not app_thread.is_alive(), "external appserver stand-in did not stop"
        assert not errors, errors


def test_owned_constructor_and_reserve_use_authenticated_control(api, tmp_path, monkeypatch):
    factory = api.OwnedHostBinding.from_owned_channels  # Actual public FEATURE_ABSENT.
    with owned_runtime_boundary(api, tmp_path, monkeypatch) as inputs:
        control, reader, writer, deployment, plan_ref, requests = inputs
        binding = factory(control, reader, writer, deployment)
        try:
            reservations = binding.reserve_initial(plan_ref)
            assert tuple(row.actor_cid for row in reservations) == (
                "fixture-coordinator", "fixture-operator", "fixture-reviewer",
                "fixture-root", "fixture-router")
            with pytest.raises(AttributeError):
                reservations[0].actor_cid = "forged"
            assert [row["method"] for row in requests] == ["describe", "reserve_initial"]
            assert requests[1]["id"] > requests[0]["id"]
            assert requests[1]["nonce"] == requests[0]["nonce"]
        finally:
            binding.close()
        assert control.fileno() == -1 and reader.closed and writer.closed


@pytest.mark.timing
def test_close_revokes_an_in_flight_control_exchange_without_awaiting_its_reply(
        api, tmp_path, monkeypatch):
    with owned_runtime_boundary(api, tmp_path, monkeypatch,
                                control_fault="held-reserve_initial-reply") as inputs:
        control, reader, writer, deployment, plan_ref, requests = inputs
        binding = api.OwnedHostBinding.from_owned_channels(control, reader, writer, deployment)
        outcome = []

        def reserve():
            try:
                binding.reserve_initial(plan_ref)
                outcome.append(("reserved", time.monotonic()))
            except api.HostAuthorityError as exc:
                outcome.append((exc.code, time.monotonic()))

        worker = threading.Thread(target=reserve)
        worker.start()
        try:
            limit = time.monotonic() + 5
            while [row["method"] for row in requests] != ["describe", "reserve_initial"]:
                assert time.monotonic() < limit, "the runtime never received the request"
                time.sleep(0.01)
            started = time.monotonic()
            binding.close()  # The runtime still holds the request and has not replied.
            closed = time.monotonic()
        finally:
            worker.join(10)
        assert not worker.is_alive()
        assert closed - started < 1.0  # Revocation does not wait out the 5 s exchange.
        assert [code for code, _ in outcome] == ["HOST_PROTOCOL_ERROR"]
        assert outcome[0][1] - started < 1.0
        assert control.fileno() == -1 and reader.closed and writer.closed
        with pytest.raises(api.HostAuthorityError) as stale:
            binding.reserve_initial(plan_ref)
        assert stale.value.code == "HOST_CALL_CONFLICT"
        assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


@pytest.mark.parametrize("fault,code", [
    ("foreign-peer", "UNPROTECTED_DEPLOYMENT"),
    ("foreign-file-owner", "UNPROTECTED_DEPLOYMENT"),
    ("wrong-nonce", "HOST_PROTOCOL_ERROR"),
])
def test_owned_constructor_refuses_external_peer_or_nonce(api, tmp_path, monkeypatch,
                                                        fault, code):
    factory = api.OwnedHostBinding.from_owned_channels
    with owned_runtime_boundary(api, tmp_path, monkeypatch, fault) as inputs:
        control, reader, writer, deployment, _, requests = inputs
        with pytest.raises(api.HostAuthorityError) as caught:
            factory(control, reader, writer, deployment)
        assert caught.value.code == code
        if fault in {"foreign-peer", "foreign-file-owner"}:
            assert requests == [], "foreign owner must not reach control protocol"
        assert control.fileno() == -1 and reader.closed and writer.closed


def test_owned_constructor_missing_deployment_fails_before_protocol(api, tmp_path, monkeypatch):
    factory = api.OwnedHostBinding.from_owned_channels
    with owned_runtime_boundary(api, tmp_path, monkeypatch) as inputs:
        control, reader, writer, _, _, requests = inputs
        with pytest.raises(api.HostAuthorityError) as caught:
            factory(control, reader, writer, tmp_path / "missing-deployment.json")
        assert caught.value.code == "UNPROTECTED_DEPLOYMENT"
        assert requests == []
        assert control.fileno() == -1 and reader.closed and writer.closed


@contextmanager
def count_external_readback(monkeypatch):
    """Observe actual OS/persistence boundaries, without replacing H authority."""
    reads = []
    with monkeypatch.context() as patch:
        for owner, names in ((Path, ("read_text", "read_bytes")),
                             (os, ("stat", "fstat", "readlink", "listxattr", "open", "read")),
                             (socket.socket, ("getsockopt", "getpeername"))):
            for name in names:
                actual = getattr(owner, name)

                def observed(*args, _actual=actual, _name=name, **kwargs):
                    reads.append(_name)
                    return _actual(*args, **kwargs)

                patch.setattr(owner, name, observed)
        yield reads


def fork_public_result(action, monkeypatch):
    """Run one public action in a real fork and always reap that exact child."""
    read_fd, write_fd = os.pipe()
    pid, status = None, None
    try:
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                with count_external_readback(monkeypatch) as reads:
                    try:
                        action()
                    except Exception as error:
                        result = {"error_type": type(error).__name__,
                                  "code": getattr(error, "code", None)}
                    else:
                        result = {"error_type": None, "code": None}
                    result["external_reads"] = list(reads)
                os.write(write_fd, json.dumps(result).encode())
            finally:
                os._exit(0)  # Never unwind inherited fixture/thread ownership.
        os.close(write_fd)
        write_fd = None
        ready, _, _ = select.select([read_fd], [], [], 2)
        assert ready, "forked public authority check did not return"
        raw = os.read(read_fd, 65536)
        deadline = time.monotonic() + 2
        while status is None and time.monotonic() < deadline:
            finished, value = os.waitpid(pid, os.WNOHANG)
            if finished:
                status = value
            else:
                time.sleep(0.005)
        assert status is not None, "forked public authority check did not exit"
        assert os.waitstatus_to_exitcode(status) == 0
        return json.loads(raw)
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
        if pid not in (None, 0) and status is None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


# A real fork is required to verify that children cannot use their parent's guards.
@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded, use of fork:DeprecationWarning")
@pytest.mark.parametrize("purpose", ["genesis", "initial"])
@pytest.mark.parametrize("lifetime", ["active", "precreated", "new"])
def test_forked_process_cannot_use_owned_host_guards(api, tmp_path, monkeypatch,
                                                  purpose, lifetime):
    with owned_runtime_boundary(api, tmp_path, monkeypatch) as inputs:
        control, reader, writer, deployment, plan_ref, requests = inputs
        binding = api.OwnedHostBinding.from_owned_channels(control, reader, writer, deployment)
        try:
            reservations = binding.reserve_initial(plan_ref)
            target = reservations[0]
            canonical_before = {str(p.relative_to(binding.canonical_root)): p.read_bytes()
                                for p in binding.canonical_root.rglob("*") if p.is_file()}

            def make_guard():
                if purpose == "genesis":
                    return binding.authority.bootstrap_fence(binding, plan_ref, reservations)
                return binding.authority.initial_creation_fence(binding, plan_ref, target)

            def require_current(guard):
                if purpose == "genesis":
                    guard.require_reserved_genesis_current()
                else:
                    guard.require_initial_identity_current(target)

            if lifetime == "active":
                with make_guard() as guard:
                    result = fork_public_result(lambda: require_current(guard), monkeypatch)
                    require_current(guard)  # Child refusal does not revoke its real parent.
            else:
                guard = make_guard() if lifetime == "precreated" else None

                def enter_guard():
                    with (guard if guard is not None else make_guard()) as child_guard:
                        require_current(child_guard)

                result = fork_public_result(enter_guard, monkeypatch)
            assert result == {"error_type": "HostAuthorityError", "code": "STALE_INVOCATION",
                              "external_reads": []}
            assert {str(p.relative_to(binding.canonical_root)): p.read_bytes()
                    for p in binding.canonical_root.rglob("*") if p.is_file()} == canonical_before
            assert [row["method"] for row in requests] == ["describe", "reserve_initial"]
        finally:
            binding.close()


@pytest.mark.parametrize("outer_purpose", ["genesis", "initial"])
@pytest.mark.parametrize("inner_purpose", ["genesis", "initial"])
def test_nested_host_fence_refuses_before_external_readback_under_canonical_lock(
        api, tmp_path, monkeypatch, outer_purpose, inner_purpose):
    from tools import hierarchy_lifecycle as lifecycle

    with owned_runtime_boundary(api, tmp_path, monkeypatch) as inputs:
        control, reader, writer, deployment, plan_ref, requests = inputs
        binding = api.OwnedHostBinding.from_owned_channels(control, reader, writer, deployment)
        try:
            reservations = binding.reserve_initial(plan_ref)
            target = reservations[0]

            def make_guard(purpose):
                if purpose == "genesis":
                    return binding.authority.bootstrap_fence(binding, plan_ref, reservations)
                return binding.authority.initial_creation_fence(binding, plan_ref, target)

            # The real H guard and real N1 O_EXCL writer exclusion are both held.
            with make_guard(outer_purpose):
                with lifecycle.writer_lock(binding.canonical_root):
                    with count_external_readback(monkeypatch) as reads:
                        with pytest.raises(api.HostAuthorityError) as caught:
                            with make_guard(inner_purpose):
                                pytest.fail("nested H fence must never enter")
                    assert caught.value.code == "ROLE_OPERATION_FORBIDDEN"
                    assert reads == [], "nested refusal performed external reads under both fences"
            assert [row["method"] for row in requests] == ["describe", "reserve_initial"]
        finally:
            binding.close()


@pytest.mark.parametrize("fault", ["nonce", "none-path", "bytes-path", "integer-path"])
def test_owned_constructor_failure_closes_all_channels(api, tmp_path, monkeypatch, fault):
    with owned_runtime_boundary(api, tmp_path, monkeypatch) as inputs:
        control, reader, writer, deployment, _, requests = inputs
        invalid_paths = {"none-path": None, "bytes-path": b"deployment",
                         "integer-path": 7}
        error, unexpected_binding = None, None

        def unavailable_nonce(_size):
            raise OSError("injected owned nonce failure")

        try:
            with monkeypatch.context() as boundary:
                if fault == "nonce":
                    boundary.setattr(os, "urandom", unavailable_nonce)
                try:
                    unexpected_binding = api.OwnedHostBinding.from_owned_channels(
                        control, reader, writer, invalid_paths.get(fault, deployment))
                except Exception as caught:
                    error = caught
            assert error is not None, "invalid constructor unexpectedly returned a binding"
            assert control.fileno() == -1 and reader.closed and writer.closed, (
                "failed constructor leaked an owned channel")
            assert type(error) is api.HostAuthorityError
            assert error.code == "UNPROTECTED_DEPLOYMENT"
            assert requests == [], "constructor failure reached the private protocol"
        finally:
            if unexpected_binding is not None:
                unexpected_binding.close()


def test_owned_constructor_postreply_readback_keeps_original_deadline(
        api, tmp_path, monkeypatch):
    with owned_runtime_boundary(api, tmp_path, monkeypatch) as inputs:
        control, reader, writer, deployment, _, requests = inputs
        control_fd = control.fileno()
        actual_read, actual_text = os.read, Path.read_text
        actual_monotonic, actual_monotonic_ns = time.monotonic, time.monotonic_ns
        received, advanced = bytearray(), []
        clock_offset = [0]
        binding = None

        def observe_control_read(fd, length):
            raw = actual_read(fd, length)
            if fd == control_fd:
                received.extend(raw)
            return raw

        def delayed_os_readback(path, *args, **kwargs):
            value = actual_text(path, *args, **kwargs)
            if (not advanced and b"\n" in received
                    and str(path) == "/proc/%s/stat" % os.getpid()):
                # Actual valid describe reply has arrived. Only external OS
                # readback/clock boundaries change; H validation stays real.
                reply = json.loads(bytes(received).split(b"\n", 1)[0])
                assert "channel_witness" in reply["result"]
                advanced.append(str(path))
                clock_offset[0] = 6
            return value

        try:
            with monkeypatch.context() as boundary:
                boundary.setattr(os, "read", observe_control_read)
                boundary.setattr(Path, "read_text", delayed_os_readback)
                boundary.setattr(time, "monotonic",
                                 lambda: actual_monotonic() + clock_offset[0])
                boundary.setattr(time, "monotonic_ns",
                                 lambda: actual_monotonic_ns() + clock_offset[0] * 1000000000)
                with pytest.raises(api.HostAuthorityError) as caught:
                    binding = api.OwnedHostBinding.from_owned_channels(
                        control, reader, writer, deployment)
            assert caught.value.code == "HOST_PROTOCOL_TIMEOUT"
            assert advanced == ["/proc/%s/stat" % os.getpid()]
            assert binding is None, "expired describe must not return an owned binding"
            assert control.fileno() == -1 and reader.closed and writer.closed
            assert [row["method"] for row in requests] == ["describe"]
        finally:
            if binding is not None:
                binding.close()


@contextmanager
def initial_control_runtime(api, tmp_path, monkeypatch, control_fault=None):
    from tools import hierarchy_lifecycle as lifecycle

    with owned_runtime_boundary(api, tmp_path, monkeypatch, initialize_canonical=False,
                                planned_successor=True, initial_control=True,
                                control_fault=control_fault) as inputs:
        control, reader, writer, deployment, plan_ref, requests = inputs
        binding = api.OwnedHostBinding.from_owned_channels(control, reader, writer, deployment)
        try:
            reservations = binding.reserve_initial(plan_ref)
            lifecycle.ProtectedCanonicalEnrollmentWriter(
                binding.canonical_root, binding.authority).initialize_reserved_genesis(
                    binding, reservations, plan_ref)
            yield lifecycle, binding, reservations, plan_ref, requests
        finally:
            binding.close()


def test_bind_start_use_real_initial_and_one_owned_context(api, tmp_path, monkeypatch):
    with initial_control_runtime(api, tmp_path, monkeypatch) as values:
        lifecycle, binding, reservations, _, requests = values
        target = next(row for row in reservations if row.actor_cid == "fixture-operator")
        context = binding.bind_initial(target)  # Actual public FEATURE_ABSENT prerequisite.
        assert context.actor_cid == target.actor_cid
        with pytest.raises(AttributeError):
            context.actor_cid = "foreign"
        with pytest.raises(TypeError):
            copy.copy(context)
        with pytest.raises(TypeError):
            pickle.dumps(context)
        assert [row["method"] for row in requests] == ["describe", "reserve_initial", "bind_initial"]
        before = lifecycle.Lifecycle(binding.canonical_root).initial_bootstrap()
        assert before["creations"][0]["actor_cid"] == target.actor_cid
        assert before["creations"][0]["receipt"]["sequence"] == 2
        assert binding.start_initial(context) == {"actor_cid": target.actor_cid, "state": "started"}
        for attempt in (lambda: binding.bind_initial(target), lambda: binding.start_initial(context)):
            with pytest.raises(api.HostAuthorityError) as caught:
                attempt()
            assert caught.value.code == "HOST_CALL_CONFLICT"
        assert [row["method"] for row in requests] == [
            "describe", "reserve_initial", "bind_initial", "start_initial"]
        assert lifecycle.Lifecycle(binding.canonical_root).initial_bootstrap() == before


def test_recovered_initial_receipt_never_binds_again(api, tmp_path, monkeypatch):
    with initial_control_runtime(api, tmp_path, monkeypatch) as values:
        lifecycle, binding, reservations, plan_ref, requests = values
        target = next(row for row in reservations if row.actor_cid == "fixture-operator")
        with binding.authority.initial_creation_fence(binding, plan_ref, target) as guard:
            first = lifecycle.ProtectedCanonicalBootstrapWriter(
                binding.canonical_root).commit_initial_creation(guard, target)
        assert first["state"] == "recorded"
        before = lifecycle.Lifecycle(binding.canonical_root).initial_bootstrap()
        with pytest.raises(api.HostAuthorityError) as caught:
            binding.bind_initial(target)
        assert caught.value.code == "ROLE_OPERATION_FORBIDDEN"
        assert lifecycle.Lifecycle(binding.canonical_root).initial_bootstrap() == before
        assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


def test_initial_bind_rejects_witness_dict_and_planned_successor(api, tmp_path, monkeypatch):
    with initial_control_runtime(api, tmp_path, monkeypatch) as values:
        lifecycle, binding, reservations, _, requests = values
        successor = next(row for row in reservations if row.actor_cid == "fixture-operator-next")
        for target in (successor.witness, successor):
            with pytest.raises(api.HostAuthorityError) as caught:
                binding.bind_initial(target)
            assert caught.value.code == "ROLE_OPERATION_FORBIDDEN"
        assert lifecycle.Lifecycle(binding.canonical_root).load()[1]["sequence"] == 1
        assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


@pytest.mark.parametrize("fault,methods", [
    ("lost-bind_initial-reply", ["describe", "reserve_initial", "bind_initial"]),
    ("wrong-bind-cid", ["describe", "reserve_initial", "bind_initial"]),
    ("lost-start_initial-reply", ["describe", "reserve_initial", "bind_initial", "start_initial"]),
])
def test_possible_initial_control_retains_unknown_without_retry(api, tmp_path, monkeypatch,
                                                              fault, methods):
    with initial_control_runtime(api, tmp_path, monkeypatch, fault) as values:
        lifecycle, binding, reservations, _, requests = values
        target = next(row for row in reservations if row.actor_cid == "fixture-operator")
        context = None
        with pytest.raises(api.HostAuthorityError) as caught:
            context = binding.bind_initial(target)
            binding.start_initial(context)
        assert caught.value.code == "PROVIDER_OUTCOME_UNKNOWN"
        before = lifecycle.Lifecycle(binding.canonical_root).initial_bootstrap()
        assert before["creations"][0]["actor_cid"] == target.actor_cid
        assert before["creations"][0]["receipt"]["sequence"] == 2
        with pytest.raises(api.HostAuthorityError) as retry:
            if context is None:
                binding.bind_initial(target)
            else:
                binding.start_initial(context)
        assert retry.value.code == "STALE_INVOCATION"
        assert [row["method"] for row in requests] == methods
        assert lifecycle.Lifecycle(binding.canonical_root).initial_bootstrap() == before


def test_initial_start_cannot_renew_original_bound_deadline(api, tmp_path, monkeypatch):
    with initial_control_runtime(api, tmp_path, monkeypatch) as values:
        _, binding, reservations, _, requests = values
        target = next(row for row in reservations if row.actor_cid == "fixture-operator")
        context = binding.bind_initial(target)
        actual_monotonic, actual_monotonic_ns = time.monotonic, time.monotonic_ns
        with monkeypatch.context() as clock:
            clock.setattr(time, "monotonic", lambda: actual_monotonic() + 6)
            clock.setattr(time, "monotonic_ns", lambda: actual_monotonic_ns() + 6000000000)
            with pytest.raises(api.HostAuthorityError) as caught:
                binding.start_initial(context)
        assert caught.value.code == "HOST_PROTOCOL_TIMEOUT"
        with pytest.raises(api.HostAuthorityError) as spent:
            binding.start_initial(context)
        assert spent.value.code == "HOST_CALL_CONFLICT"
        assert [row["method"] for row in requests] == ["describe", "reserve_initial", "bind_initial"]


def test_owned_constructor_unsupported_host_closes_transferred_channels(
        api, tmp_path, monkeypatch):
    # This case deliberately avoids the Linux-only positive runtime fixture.
    # On non-Linux it measures the real platform refusal, without OS mocking.
    with ExitStack() as cleanup:
        control, peer = socket.socketpair()
        cleanup.callback(control.close)
        cleanup.callback(peer.close)
        peer.settimeout(1)
        incoming_read, incoming_write = os.pipe()
        reader = os.fdopen(incoming_read, "rb", buffering=0)
        cleanup.callback(reader.close)
        incoming = os.fdopen(incoming_write, "wb", buffering=0)
        cleanup.callback(incoming.close)
        observer = os.fdopen(os.dup(reader.fileno()), "rb", buffering=0)
        cleanup.callback(observer.close)
        outgoing_read, outgoing_write = os.pipe()
        outgoing = os.fdopen(outgoing_read, "rb", buffering=0)
        cleanup.callback(outgoing.close)
        writer = os.fdopen(outgoing_write, "wb", buffering=0)
        cleanup.callback(writer.close)
        pending = b"untouched appserver input"
        incoming.write(pending)
        incoming.close()  # Bound the observer read with actual EOF.
        deployment = tmp_path / "never-created" / "deployment.json"
        binding = None
        try:
            with monkeypatch.context() as platform:
                if sys.platform == "linux":
                    platform.setattr(sys, "platform", "win32")  # OS boundary only.
                with pytest.raises(api.HostAuthorityError) as caught:
                    binding = api.OwnedHostBinding.from_owned_channels(
                        control, reader, writer, deployment)
            assert caught.value.code == "UNSUPPORTED_HOST"
            assert caught.value.reason == "protected control requires Linux"
            assert binding is None
            assert control.fileno() == -1 and reader.closed and writer.closed
            assert peer.recv(1) == b"", "unsupported host emitted a control request"
            assert observer.read(len(pending)) == pending, "unsupported host consumed appserver input"
            assert outgoing.read(1) == b"", "unsupported host wrote to the appserver"
            assert not deployment.parent.exists(), "unsupported host created deployment or canonical state"
        finally:
            if binding is not None:
                binding.close()


@pytest.mark.parametrize("stage", ["reserved", "bound"])
def test_initial_context_without_start_cannot_open_live_session(
        api, tmp_path, monkeypatch, stage):
    with initial_control_runtime(api, tmp_path, monkeypatch) as values:
        lifecycle, binding, reservations, _, requests = values
        target = next(row for row in reservations if row.actor_cid == "fixture-root")
        if stage == "bound":
            binding.bind_initial(target)
        before = lifecycle.Lifecycle(binding.canonical_root).load()
        methods = [row["method"] for row in requests]
        with pytest.raises(api.HostAuthorityError) as caught:
            binding.open_live_session(target.actor_cid)
        assert caught.value.code == "ROLE_OPERATION_FORBIDDEN"
        assert lifecycle.Lifecycle(binding.canonical_root).load() == before
        assert [row["method"] for row in requests] == methods


def test_started_initial_with_legacy_role_ceiling_cannot_open_live_session(
        api, tmp_path, monkeypatch):
    with initial_control_runtime(api, tmp_path, monkeypatch) as values:
        lifecycle, binding, reservations, _, requests = values
        target = next(row for row in reservations if row.actor_cid == "fixture-root")
        context = binding.bind_initial(target)
        assert binding.start_initial(context) == {
            "actor_cid": target.actor_cid, "state": "started"}
        before = lifecycle.Lifecycle(binding.canonical_root).load()
        with pytest.raises(api.HostAuthorityError) as caught:
            binding.open_live_session(target.actor_cid)
        assert caught.value.code == "HOST_PROFILE_UNQUALIFIED"
        assert lifecycle.Lifecycle(binding.canonical_root).load() == before
        assert [row["method"] for row in requests] == [
            "describe", "reserve_initial", "bind_initial", "start_initial"]
        # The real INITIAL fixture uses the legacy role-list ceiling.
        # Its authenticated raw digest cannot substitute for a full LIVE map.


@contextmanager
def live_control_runtime(api, tmp_path, monkeypatch, fault=None):
    from tools import hierarchy_lifecycle as lifecycle

    with owned_runtime_boundary(api, tmp_path, monkeypatch, initialize_canonical=False,
                                initial_control=True, live_control=True, live_fault=fault) as inputs:
        control, reader, writer, deployment, plan_ref, requests = inputs
        binding = api.OwnedHostBinding.from_owned_channels(control, reader, writer, deployment)
        try:
            reservations = binding.reserve_initial(plan_ref)
            lifecycle.ProtectedCanonicalEnrollmentWriter(
                binding.canonical_root, binding.authority).initialize_reserved_genesis(
                    binding, reservations, plan_ref)
            policy, _ = lifecycle.Lifecycle(binding.canonical_root).load()
            request = {"schema": lifecycle.REQUEST, "id": "fixture-authority", "version": 1,
                       "team": "engine", "owner": "engine/coordinator", "next_decision": "review",
                       "phase": "validation", "operation": "targeted-tests", "source": policy["source"],
                       "paths": ["/fixture/tests"], "prerequisites": [], "authority": "fixture-authority",
                       "continuation": {"members": [], "max_starts": 1,
                                        "expires_at": "2099-01-01T00:00:00Z"}}
            raw = json.dumps(request, sort_keys=True) + "\n"
            lifecycle.Lifecycle(binding.canonical_root).record({
                "id": "publish-live-authority", "actor": "fixture-coordinator", "generation": 1,
                "custody": {"cid": "fixture-root", "generation": 1}, "event": {
                    "type": "publish", "request": {"raw": raw,
                                                   "sha256": hashlib.sha256(raw.encode()).hexdigest()}}})
            target = next(row for row in reservations if row.actor_cid == "fixture-root")
            context = binding.bind_initial(target)
            assert binding.start_initial(context) == {"actor_cid": target.actor_cid, "state": "started"}
            yield lifecycle, binding, requests
        finally:
            binding.close()


@pytest.mark.timing
def test_close_interrupts_a_live_session_waiting_for_its_next_call(api, tmp_path, monkeypatch):
    with live_control_runtime(api, tmp_path, monkeypatch) as (_, binding, requests):
        session = binding.open_live_session("fixture-root")
        session.receive_invocation()  # The app-server stand-in sends exactly one call.
        methods = [row["method"] for row in requests]
        entered, actual = threading.Event(), select.select

        def observed(readable, writable, exceptional, timeout=None):
            if threading.current_thread().name == "next-call" and readable:
                entered.set()  # The worker is really waiting on the app-server pipe.
            return actual(readable, writable, exceptional, timeout)

        monkeypatch.setattr(api.select, "select", observed)
        outcome = []

        def receive():
            try:
                session.receive_invocation()
                outcome.append(("received", time.monotonic()))
            except api.HostAuthorityError as exc:
                outcome.append((exc.code, time.monotonic()))

        worker = threading.Thread(target=receive, name="next-call")
        worker.start()
        try:
            assert entered.wait(5)
            time.sleep(0.2)  # Let the worker reach the kernel wait (see the leaf test).
            started = time.monotonic()
            binding.close()
        finally:
            worker.join(10)
        assert not worker.is_alive()
        assert [code for code, _ in outcome] == ["HOST_PROTOCOL_ERROR"]
        assert outcome[0][1] - started < 1.0  # Not the 5 s call-wait deadline.
        assert [row["method"] for row in requests] == methods


def test_close_during_post_reply_readback_refuses_with_a_typed_error(api, tmp_path, monkeypatch):
    with live_control_runtime(api, tmp_path, monkeypatch) as (_, binding, requests):
        session = binding.open_live_session("fixture-root")
        actual_identity, closers = api._process_identity, []

        def identity(pid):
            # The provenance readback that runs under the binding lock right
            # after pending_call's reply: revoke from another thread there.
            if (not closers and requests[-1]["method"] == "pending_call"
                    and binding._lock._is_owned()):
                closer = threading.Thread(target=binding.close)
                closers.append(closer)
                closer.start()
                limit = time.monotonic() + 5
                while not binding._fenced:  # close() fences, then waits for our lock.
                    assert time.monotonic() < limit, "close() never fenced"
                    time.sleep(0.001)
            return actual_identity(pid)

        monkeypatch.setattr(api, "_process_identity", identity)
        try:
            with pytest.raises(api.HostAuthorityError) as stale:
                session.receive_invocation()  # Never a raw OSError from a released descriptor.
        finally:
            for closer in closers:
                closer.join(5)
        assert stale.value.code == "STALE_INVOCATION"
        assert len(closers) == 1 and not closers[0].is_alive()


def test_real_initial_live_wire_creates_owned_invocation_and_both_fence_guard(
        api, tmp_path, monkeypatch):
    with live_control_runtime(api, tmp_path, monkeypatch) as (lifecycle, binding, requests):
        before = lifecycle.Lifecycle(binding.canonical_root).load()
        session = binding.open_live_session("fixture-root")
        assert type(session) is api.HostSession
        assert session.owned_runtime is binding and session.authority is binding.authority
        assert session.actor_cid == "fixture-root"
        invocation = session.receive_invocation()
        assert type(invocation) is api.HostInvocation
        assert invocation.actor_cid == "fixture-root" and invocation.rpc_id == 0
        assert type(invocation.rpc_id) is int
        assert invocation.event_id == "live-decision-1"
        assert invocation.decision_recovery_event_id is None
        for owned, attribute in ((session, "actor_cid"), (invocation, "rpc_id"),
                                 (invocation, "decision_recovery_event_id")):
            with pytest.raises(AttributeError):
                setattr(owned, attribute, "foreign")
            with pytest.raises(TypeError):
                copy.copy(owned)
            with pytest.raises(TypeError):
                pickle.dumps(owned)
        with session.authority.effect_fence(invocation, "decision") as guard:
            with lifecycle.writer_lock(binding.canonical_root):
                policy, state = lifecycle.Lifecycle(binding.canonical_root).load()
                assert session.authority.require_current(invocation, policy, state, None) is None
                assert session.authority.require_current(
                    invocation, policy, state, state["requests"]["fixture-authority"]) is None
                # IPC/readback under the actual H/canonical fences must refuse.
                with pytest.raises(api.HostAuthorityError) as caught:
                    session.receive_invocation()
                assert caught.value.code == "ROLE_OPERATION_FORBIDDEN"
        with pytest.raises(api.HostAuthorityError) as caught:
            guard.require_current(invocation, *before, None)
        assert caught.value.code == "STALE_INVOCATION"
        assert lifecycle.Lifecycle(binding.canonical_root).load() == before
        assert [row["method"] for row in requests] == [
            "describe", "reserve_initial", "bind_initial", "start_initial",
            "describe_live", "enroll_live", "pending_call"]


@pytest.mark.parametrize("fault,code", [
    ("profile", "HOST_PROFILE_UNQUALIFIED"), ("rpc", "CANONICAL_CORRELATION_MISMATCH")])
def test_live_runtime_projection_cannot_replace_owned_profile_or_rpc_variant(
        api, tmp_path, monkeypatch, fault, code):
    with live_control_runtime(api, tmp_path, monkeypatch, fault) as (lifecycle, binding, _):
        before = lifecycle.Lifecycle(binding.canonical_root).load()
        with pytest.raises(api.HostAuthorityError) as caught:
            session = binding.open_live_session("fixture-root")
            session.receive_invocation()
        assert caught.value.code == code
        assert lifecycle.Lifecycle(binding.canonical_root).load() == before


@pytest.mark.parametrize("field", ["event_id", "request_id", "request_sha256", "decision", "reason"])
def test_all_five_dispatch_fields_must_match_actual_owned_frame_before_canonical_access(
        api, tmp_path, monkeypatch, field):
    with live_control_runtime(api, tmp_path, monkeypatch) as (lifecycle, binding, requests):
        session = binding.open_live_session("fixture-root")
        invocation = session.receive_invocation()
        before = lifecycle.Lifecycle(binding.canonical_root).load()
        command = {"event_id": "live-decision-1", "request_id": "fixture-authority",
                   "request_sha256": before[1]["requests"]["fixture-authority"]["raw"]["sha256"],
                   "decision": "approve", "reason": "reviewed"}
        command[field] = {"event_id": "different-event", "request_id": "different-request",
                          "request_sha256": "b" * 64, "decision": "deny", "reason": "changed"}[field]
        with pytest.raises(api.HostAuthorityError) as caught:
            session.dispatch_decision(invocation, command)
        assert caught.value.code == "STALE_INVOCATION"
        assert caught.value.reason == "decision arguments do not match owned call"
        assert lifecycle.Lifecycle(binding.canonical_root).load() == before
        # The H-owned early branch proves only this new call never entered N1.
        # Returning arbitrary D data alone cannot make an invocation usable again.
        reply = session.reply(invocation, {"success": False, "contentItems": [
            {"type": "inputText", "text": "refused"}]})
        assert reply == {"actor_cid": "fixture-root", "rpc_id": 0, "state": "awaiting_terminal"}
        with pytest.raises(api.HostAuthorityError) as caught:
            session.authority.effect_fence(invocation, "decision")
        assert caught.value.code == "STALE_INVOCATION"
        assert requests[-1]["method"] == "retire_call"
        assert requests[-1]["params"]["canonical_state"] is None
        assert lifecycle.Lifecycle(binding.canonical_root).load() == before


@pytest.mark.parametrize("branch", ["changed-command", "exact-original-command"])
def test_public_prior_guard_history_with_present_producer_stays_unknown(
        api, tmp_path, monkeypatch, branch):
    with live_control_runtime(api, tmp_path, monkeypatch) as (lifecycle, binding, requests):
        # This candidate requires the real producer, not the standalone
        # producer-absent history fixture or a substituted authority object.
        assert callable(lifecycle.ProtectedCanonicalDecisionWriter.commit_decision)
        ledger = lifecycle.Lifecycle(binding.canonical_root)
        session = binding.open_live_session("fixture-root")
        invocation = session.receive_invocation()
        before = ledger.load()
        command = {"event_id": "live-decision-1", "request_id": "fixture-authority",
                   "request_sha256": before[1]["requests"]["fixture-authority"]["raw"]["sha256"],
                   "decision": "approve", "reason": "reviewed"}
        original_event_id = invocation.event_id
        assert original_event_id == command["event_id"]

        # Successful entry remains history after both actual scopes exit.
        # No decision is dispatched or appended by this setup.
        with session.authority.effect_fence(invocation, "decision"):
            with lifecycle.writer_lock(binding.canonical_root):
                policy, state = ledger.load()
                session.authority.require_current(invocation, policy, state, None)
                session.authority.require_current(
                    invocation, policy, state, state["requests"]["fixture-authority"])
        assert ledger.load() == before
        if branch == "changed-command":
            command["reason"] = "changed after original guard exit"

        with pytest.raises(api.HostAuthorityError) as caught:
            session.dispatch_decision(invocation, command)
        assert caught.value.code == "PROVIDER_OUTCOME_UNKNOWN"
        assert caught.value.reason == "canonical decision outcome is unresolved"
        assert invocation.event_id == original_event_id
        assert ledger.load() == before
        assert requests[-1]["method"] == "pending_call"
        assert not any(row["method"] == "retire_call" for row in requests)

        for attempt in (
                lambda: session.dispatch_decision(invocation, command),
                lambda: session.reply(invocation, {"success": False, "contentItems": [
                    {"type": "inputText", "text": "unresolved"}]}),
                session.receive_invocation):
            with pytest.raises(api.HostAuthorityError) as stale:
                attempt()
            assert stale.value.code == "STALE_INVOCATION"
        assert not any(row["method"] == "retire_call" for row in requests)
        assert ledger.load() == before
