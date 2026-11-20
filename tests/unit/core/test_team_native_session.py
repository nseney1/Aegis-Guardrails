"""Exercise the port at the owned binding, appserver and canonical API seams."""
import copy
import json
import os
import pickle
import select
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis_core import team_native_authority as authority
from aegis_core import team_lifecycle_writers as writers
from aegis_core import team_native_session as live
from aegis_core import team_native_wire as wire
from aegis_core.team_native_keys import LIVE_KEY, NativeIdentities
from tests.unit.core.test_team_native_wire import Link, frame
from tools import hierarchy_host_authority as legacy
from tools import hierarchy_lifecycle as legacy_writers


COMMAND = {"event_id": "decision-1", "request_id": "request-1",
           "request_sha256": "a" * 64, "decision": "approve", "reason": "reviewed"}
ANSWER = {"success": False, "contentItems": [{"type": "inputText", "text": "reviewed"}]}


def call(rpc=0, **changes):
    return {"id": rpc, "method": "item/tool/call", "params": {
        "namespace": "functions", "threadId": "root-1", "turnId": "turn-1",
        "callId": "call-" + str(rpc), "tool": "aegis_decision", "arguments": dict(COMMAND),
        **changes,
    }}


@contextmanager
def refusal(code, reason, error_type=wire.HostAuthorityError):
    with pytest.raises(error_type) as caught:
        yield
    error = caught.value
    assert (error.code, error.reason, str(error)) == (code, reason, reason)
    if error_type is wire.HostAuthorityError:
        assert error.next_action == wire.HostAuthorityError(code, reason).next_action


class AppserverPeer:
    def __init__(self):
        self.calls = deque([call()])
        self.replies = []
        self.admit = nullcontext

    @contextmanager
    def operation(self, deadline_ns):
        assert deadline_ns > time.monotonic_ns()
        with self.admit():
            yield

    def receive_call(self):
        return self.calls.popleft()

    def reply(self, rpc_id, result):
        self.replies.append((rpc_id, copy.deepcopy(result)))


class OwnerPort:
    def __init__(self, registry):
        self.registry = registry
        self.legacy_binding = None
        self.error_type = wire.HostAuthorityError
        self.epoch, self.nonce = 1, "nonce"
        self.active_guard = None
        self.fenced = False
        self.lock = threading.RLock()
        self.io_gate = threading.RLock()
        self.live_sessions = {}
        self.appserver = AppserverPeer()
        self.canonical_root = "canonical"
        self.canonical_api = None
        self.mailbox = object()
        self.plan_data, self.policy_data, self.channel_data, self.reservations = {}, {}, {}, ()
        self.reader = self.writer = None
        self.requests, self.commits, self.proofs = [], [], 0
        self.projection_patch = {}
        self.terminal = {"actor_cid": "root-1", "rpc_id": 0, "state": "awaiting_terminal"}
        self.before_prove = lambda: None
        self.before_retire = lambda: None
        self.before_close = lambda: None
        start = time.monotonic_ns()
        self.actor = {"actor_cid": "root-1", "role": "root", "generation": 1,
                      "profile_sha256": "b" * 64, "runtime_profile_sha256": "c" * 64,
                      "actor_started_monotonic_ns": start, "actor_deadline_monotonic_ns": start + 30 * 10**9}

    @property
    def closed(self):
        if self.legacy_binding is not None:
            return self.legacy_binding._closed
        return self.fenced

    def require_owner_process(self):
        pass

    def prove_current(self):
        self.proofs += 1
        self.before_prove()

    def exchange(self, method, params, deadline, *, schema):
        assert schema == "aegis.protected-live-control/v1"
        active = self.active_guard if self.legacy_binding is None else self.legacy_binding._active_guard
        if active is not None:
            raise self.error_type("ROLE_OPERATION_FORBIDDEN", "control IPC is forbidden inside a host fence")
        self.requests.append((method, copy.deepcopy(params)))
        if method == "pending_call":
            return {**{key: value for key, value in params.items() if key != "deadline_monotonic_ns"},
                    **self.actor, "epoch": self.epoch, "mode": "normal",
                    "call_started_monotonic_ns": self.actor["actor_started_monotonic_ns"],
                    "call_deadline_monotonic_ns": min(params["deadline_monotonic_ns"],
                                                     self.actor["actor_started_monotonic_ns"] + 5 * 10**9),
                    "original_event_id": None, "recovery_of": None, **self.projection_patch}
        assert method == "retire_call"
        self.before_retire()
        return self.terminal

    def close(self):
        self.before_close()
        with self.io_gate:
            self.fenced = True
            for stream in (self.reader, self.writer):
                if stream is not None:
                    stream.close()
        with self.lock:
            for session in self.live_sessions.values():
                session.invalidate()
            self.registry.discard_binding(LIVE_KEY, self)


class LegacyPort(OwnerPort):
    """Supply only the protected I/O and enrollment inputs to the frozen binding."""

    def __init__(self):
        super().__init__(None)
        self.error_type = legacy.HostAuthorityError
        self.canonical_root = Path("canonical")
        owner = object.__new__(legacy.OwnedHostBinding)
        self.legacy_binding = owner
        owner._host_pid, owner._deployment = os.getpid(), {"canonical_root": self.canonical_root}
        owner._epoch, owner._nonce = self.epoch, self.nonce
        owner._lock, owner._io_gate = self.lock, self.io_gate
        owner._closed = owner._fenced = owner._retired = False
        owner._active_guard, owner._live_sessions = None, self.live_sessions
        owner._control = owner._reader = owner._writer = None
        owner._plan, owner._policy, owner._channel, owner._reservations = {}, {}, {}, ()
        owner._appserver = self.appserver
        owner._prove_current = self.prove_current
        owner._exchange = self.exchange
        owner.close = self.close
        legacy._OWNED_BINDINGS.add(owner)
        self.authority = owner._authority = legacy.HostAuthority(owner)

    def prove_current(self):
        self.legacy_binding._initial_owner_current()
        super().prove_current()

    def enroll(self):
        session = legacy.HostSession(legacy._LIVE_KEY, self.legacy_binding, self.actor,
                                     {"initial_event_id": "initial"})
        self.live_sessions[session.actor_cid] = session
        return session

    def close(self):
        self.before_close()
        legacy.OwnedHostBinding.close(self.legacy_binding)
        self.fenced = self.legacy_binding._fenced


@pytest.fixture
def runtime(monkeypatch):
    registry = NativeIdentities()
    registry.bind_type("binding", OwnerPort)
    registry.bind_type("invocation", live.HostInvocation)
    monkeypatch.setattr(live, "native_identities", registry)
    monkeypatch.setattr(authority, "native_identities", registry)
    owner = OwnerPort(registry)
    registry.register_binding(LIVE_KEY, owner)
    owner.authority = authority.HostAuthority(owner)
    session = live.HostSession(LIVE_KEY, owner, owner.actor, {"initial_event_id": "initial"})
    owner.live_sessions[session.actor_cid] = session
    try:
        yield owner, session
    finally:
        owner.close()


@pytest.fixture(params=["core", "legacy"])
def parity_runtime(request):
    if request.param == "core":
        yield request.getfixturevalue("runtime")
        return
    owner = LegacyPort()
    try:
        yield owner, owner.enroll()
    finally:
        owner.close()


def install_writer(owner, *, state="recorded", edit=None, failure=None, entered=None, resume=None):
    class Writer:
        def __init__(self, root, bound_authority, *, host_authority=None, mailbox=None):
            assert root == owner.canonical_root and bound_authority is owner.authority
            if owner.legacy_binding is None:
                assert mailbox is owner.mailbox
                assert host_authority.HostInvocation is live.HostInvocation
                assert host_authority.HostAuthority is authority.HostAuthority
                assert host_authority.HostAuthorityError is wire.HostAuthorityError
        def commit_decision(self, invocation, command):
            owner.commits.append((invocation, command))
            if entered is not None:
                entered.set()
                assert resume.wait(3)
            if failure is not None:
                raise failure
            receipt = {"event_id": command["event_id"], "sequence": 1,
                       "event_sha256": "d" * 64, "execution_enabled": False}
            effect = {"recorded": "canonical_decision", "recovered": "none",
                      "refused": "none", "unknown": "possible"}[state]
            outcome = {"schema": "aegis.protected-decision-commit/v1", "state": state,
                       "effect": effect, "code": None, "reason": "fixed decision result",
                       "receipt": receipt, "native_qualified": False,
                       **{key: command[key] for key in ("event_id", "request_id", "request_sha256")}}
            if state in {"refused", "unknown"}:
                outcome.update(receipt=None, code="FIXED_REASON")
                if owner.legacy_binding is None:
                    outcome["next_action"] = "Reconcile original canonical evidence before retrying."
            return edit(outcome) if edit is not None else outcome

    owner.canonical_api = SimpleNamespace(ProtectedCanonicalDecisionWriter=Writer)
    if owner.legacy_binding is not None:
        owner.legacy_binding._canonical_api = owner.canonical_api


@pytest.mark.parametrize("name,reason", [
    ("HostInvocation", "invocation requires an owned pending call"),
    ("HostSession", "session requires an owned LIVE enrollment"),
])
def test_unowned_constructor_refusal_matches_legacy(name, reason):
    with pytest.raises(legacy.HostAuthorityError) as baseline:
        getattr(legacy, name)(object(), None, {}, {})
    assert (baseline.value.code, baseline.value.reason) == ("ROLE_OPERATION_FORBIDDEN", reason)
    with refusal(baseline.value.code, baseline.value.reason):
        getattr(live, name)(object(), None, {}, {})


@pytest.mark.parametrize("state", ["recorded", "recovered", "refused", "unknown"])
def test_source_completion_and_one_reply(runtime, state):
    owner, session = runtime
    install_writer(owner, state=state)
    invocation = session.receive_invocation()
    assert (invocation.actor_cid, invocation.event_id, invocation.rpc_id) == ("root-1", "decision-1", 0)
    assert invocation.decision_recovery_event_id is None
    assert session.owned_runtime is owner and session.authority is owner.authority
    for owned in (session, invocation):
        with pytest.raises(TypeError, match="owned LIVE objects cannot be copied"):
            copy.copy(owned)
        with pytest.raises(TypeError, match="owned LIVE objects cannot be copied"):
            copy.deepcopy(owned)
        with pytest.raises(TypeError, match="owned LIVE objects cannot be serialized"):
            pickle.dumps(owned)
    with refusal("STALE_INVOCATION", "reply has no owned source completion"):
        session.reply(invocation, ANSWER)
    result = session.dispatch_decision(invocation, dict(COMMAND))
    assert result["state"] == state
    result["state"] = "tampered"
    with refusal("STALE_INVOCATION", "pending invocation is no longer current"):
        session.dispatch_decision(invocation, COMMAND)
    assert session.reply(invocation, ANSWER) == owner.terminal
    assert owner.requests[-1][1]["canonical_state"] == state
    assert owner.requests[-1][1]["outcome"] == ("unknown" if state == "unknown" else "replied")
    if state == "unknown":
        with refusal("HOST_CALL_CONFLICT", "decision reply was already issued"):
            session.reply(invocation, ANSWER)
    else:
        with refusal("STALE_INVOCATION", "reply has no owned source completion"):
            session.reply(invocation, ANSWER)
    assert len(owner.commits) == len(owner.appserver.replies) == 1


@pytest.mark.parametrize("field", list(COMMAND))
def test_mismatched_command_refusal_leaves_only_reply_eligible(runtime, field):
    owner, session = runtime
    install_writer(owner)
    invocation = session.receive_invocation()
    with refusal("STALE_INVOCATION", "decision arguments do not match owned call"):
        session.dispatch_decision(invocation, dict(COMMAND, **{field: "different"}))
    with refusal("STALE_INVOCATION", "pending invocation is no longer current"):
        session.dispatch_decision(invocation, COMMAND)
    assert session.reply(invocation, ANSWER) == owner.terminal
    assert not owner.commits
    assert owner.requests[-1][1]["canonical_state"] is None


@pytest.mark.parametrize("field,value", [
    pytest.param("reason", "x" * 1025, id="overlong-reason"),
    pytest.param("decision", "allow", id="invalid-decision"),
    pytest.param("request_sha256", "A" * 64, id="uppercase-hash"),
    pytest.param("request_id", "INVALID", id="invalid-request-id"),
])
def test_matching_malformed_arguments_follow_legacy_writer_completion(parity_runtime, tmp_path, field, value):
    owner, session = parity_runtime
    owner.canonical_root = tmp_path.resolve() / "canonical"
    owner.mailbox = None
    if owner.legacy_binding is None:
        owner.canonical_api = writers
    else:
        owner.legacy_binding._deployment["canonical_root"] = owner.canonical_root
        owner.legacy_binding._canonical_api = legacy_writers

    command = dict(COMMAND, **{field: value})
    owner.appserver.calls = deque([call(arguments=command)])
    invocation = session.receive_invocation()
    if field in ("request_id", "request_sha256"):
        # The frozen writer clears invalid correlations. The session's
        # completion check rejects the resulting mismatch and fences.
        with refusal("PROVIDER_OUTCOME_UNKNOWN", "canonical decision outcome is unresolved", owner.error_type):
            session.dispatch_decision(invocation, command)
        assert owner.closed and not owner.canonical_root.exists() and not owner.appserver.replies
        assert [method for method, _ in owner.requests] == ["pending_call"]
        return
    outcome = session.dispatch_decision(invocation, command)
    assert (outcome["code"], outcome["state"], outcome["effect"], outcome["receipt"]) == (
        "INVALID_DECISION_INPUT", "refused", "none", None)
    assert not owner.canonical_root.exists() and not owner.closed
    assert session.reply(invocation, ANSWER) == owner.terminal
    assert owner.requests[-1][1]["canonical_state"] == "refused"


def test_existing_scope_history_wins_before_command_or_writer_access(runtime):
    owner, session = runtime
    invocation = session.receive_invocation()
    with session.authority.effect_fence(invocation, "decision"):
        with refusal("ROLE_OPERATION_FORBIDDEN", "appserver IPC is forbidden inside a host fence"):
            session.receive_invocation()
    with refusal("PROVIDER_OUTCOME_UNKNOWN", "canonical decision outcome is unresolved"):
        session.dispatch_decision(invocation, dict(COMMAND, reason="changed"))
    assert owner.closed and invocation.stage == "unknown"
    assert not owner.commits and not owner.appserver.replies
    with refusal("STALE_INVOCATION", "runtime binding is closed"):
        session.dispatch_decision(invocation, COMMAND)


def test_recovery_preserves_the_actual_original_unknown_call(runtime):
    owner, session = runtime
    install_writer(owner, state="unknown")
    original = session.receive_invocation()
    session.dispatch_decision(original, COMMAND)
    session.reply(original, ANSWER)
    correlation = dict(owner.requests[0][1], epoch=owner.epoch)
    correlation.pop("deadline_monotonic_ns")
    owner.projection_patch = {"mode": "original_only", "original_event_id": original.event_id,
                              "recovery_of": correlation}
    owner.appserver.calls.append(call(rpc="recovery"))
    recovered = session.receive_invocation()
    assert recovered.rpc_id == "recovery"
    assert recovered.decision_recovery_event_id == original.event_id
    assert original.stage == "unknown" and len(owner.commits) == 1


@pytest.mark.parametrize("projection,code,reason", [
    ({"rpc_id": False}, "CANONICAL_CORRELATION_MISMATCH", "pending call does not match received frame"),
    ({"call_deadline_monotonic_ns": 1}, "STALE_INVOCATION", "original call budget is unavailable"),
    ({"mode": "original_only", "original_event_id": "decision-1"},
     "STALE_INVOCATION", "recovery has no actual owned original unknown call"),
])
def test_bad_control_readback_closes_and_never_dispatches(runtime, projection, code, reason):
    owner, session = runtime
    owner.projection_patch = projection
    with refusal(code, reason):
        session.receive_invocation()
    with refusal("STALE_INVOCATION", "runtime binding is closed"):
        session.receive_invocation()
    assert owner.closed and not owner.commits and not owner.appserver.replies
    assert [method for method, _ in owner.requests] == ["pending_call"]


def test_retirement_shape_failure_is_typed_and_cannot_resend(runtime):
    owner, session = runtime
    install_writer(owner)
    invocation = session.receive_invocation()
    session.dispatch_decision(invocation, COMMAND)
    owner.terminal["state"] = []
    with refusal("HOST_PROTOCOL_ERROR", "invalid terminal observation"):
        session.reply(invocation, ANSWER)
    with refusal("STALE_INVOCATION", "runtime binding is closed"):
        session.reply(invocation, ANSWER)
    assert owner.appserver.replies == [(0, ANSWER)]


@pytest.mark.parametrize("effect_failure", ["exception", "malformed-result"])
def test_ambiguous_writer_outcome_closes_and_cannot_be_retried(runtime, effect_failure):
    owner, session = runtime
    if effect_failure == "exception":
        install_writer(owner, failure=RuntimeError("private producer detail"))
    else:
        install_writer(owner, edit=lambda result: dict(result, state=[]))
    invocation = session.receive_invocation()
    with refusal("PROVIDER_OUTCOME_UNKNOWN", "canonical decision outcome is unresolved"):
        session.dispatch_decision(invocation, COMMAND)
    assert invocation.stage == "unknown"
    with refusal("STALE_INVOCATION", "runtime binding is closed"):
        session.dispatch_decision(invocation, COMMAND)
    assert len(owner.commits) == 1 and not owner.appserver.replies


def test_concurrent_dispatch_enters_writer_once(runtime):
    owner, session = runtime
    entered, resume = threading.Event(), threading.Event()
    install_writer(owner, entered=entered, resume=resume)
    invocation = session.receive_invocation()
    with ThreadPoolExecutor(max_workers=1) as worker:
        pending = worker.submit(session.dispatch_decision, invocation, COMMAND)
        try:
            assert entered.wait(3)
            with refusal("ROLE_OPERATION_FORBIDDEN", "decision dispatch is already active"):
                session.dispatch_decision(invocation, COMMAND)
            with refusal("STALE_INVOCATION", "reply has no owned source completion"):
                session.reply(invocation, ANSWER)
        finally:
            resume.set()
        assert pending.result(timeout=3)["state"] == "recorded"
    assert len(owner.commits) == 1


def test_concurrent_reply_cannot_resend_while_terminal_readback_is_pending(runtime):
    owner, session = runtime
    install_writer(owner)
    invocation = session.receive_invocation()
    session.dispatch_decision(invocation, COMMAND)
    entered, resume = threading.Event(), threading.Event()

    def before_retire():
        entered.set()
        assert resume.wait(3)

    owner.before_retire = before_retire
    with ThreadPoolExecutor(max_workers=1) as worker:
        pending = worker.submit(session.reply, invocation, ANSWER)
        try:
            assert entered.wait(3)
            with refusal("HOST_CALL_CONFLICT", "decision reply was already issued"):
                session.reply(invocation, ANSWER)
        finally:
            resume.set()
        assert pending.result(timeout=3) == owner.terminal
    assert owner.appserver.replies == [(0, ANSWER)]
    assert [method for method, _ in owner.requests] == ["pending_call", "retire_call"]


@pytest.mark.skipif(os.name != "posix", reason="bounded anonymous pipes require POSIX")
def test_owned_appserver_preserves_legacy_wire_and_parent_close(runtime):
    owner, _ = runtime

    def implementation(reader, writer, **_options):
        owner.reader, owner.writer = reader, writer
        return live.AppserverIO(owner)

    with closing(Link(implementation=legacy.ProtocolClient)) as baseline, closing(
            Link(implementation=implementation)) as port:
        for link in (baseline, port):
            link.start([frame(call())])
        baseline.client.initialize()
        assert baseline.client.receive_call() == call()
        baseline.client.reply(0, ANSWER)
        deadline = time.monotonic_ns() + 4 * 10**9
        with port.client.operation(deadline):
            port.client.initialize()
            assert port.client.receive_call() == call()
            port.client.reply(0, ANSWER)
    assert port.parsed() == baseline.parsed()
    assert owner.fenced and owner.reader.closed and owner.writer.closed


def test_unsupported_appserver_refuses_before_stream_use(runtime, monkeypatch):
    owner, _ = runtime
    monkeypatch.setattr(wire, "os", SimpleNamespace(name="nt"))
    with refusal("UNSUPPORTED_HOST", "bounded pipe transport requires POSIX"):
        live.AppserverIO(owner)
    assert owner.closed


class ObservedAppserver(live.AppserverIO):
    def __init__(self, owner):
        super().__init__(owner)
        self.receiving = threading.Event()

    def receive_call(self):
        self.receiving.set()
        return super().receive_call()


class ObservedLegacyAppserver(legacy._AppserverIO):
    def __init__(self, owner):
        super().__init__(owner)
        self.receiving = threading.Event()

    def receive_call(self):
        self.receiving.set()
        return super().receive_call()


@contextmanager
def duplex(owner, *calls):
    def implementation(reader, writer, **_options):
        owner.reader, owner.writer = reader, writer
        if owner.legacy_binding is not None:
            owner.legacy_binding._reader, owner.legacy_binding._writer = reader, writer
            return ObservedLegacyAppserver(owner.legacy_binding)
        return ObservedAppserver(owner)

    with closing(Link(implementation=implementation)) as link:
        owner.appserver = link.client
        link.start([frame(value) for value in calls])
        deadline = time.monotonic_ns() + 4 * 10**9
        if owner.legacy_binding is not None:
            owner.legacy_binding._appserver = link.client
            link.client._bound_deadline = deadline / 10**9
            link.client.initialize()
        else:
            with link.client.operation(deadline):
                link.client.initialize()
        yield link


@pytest.mark.skipif(os.name != "posix", reason="bounded anonymous pipes require POSIX")
def test_idle_duplex_receive_does_not_block_the_reply(parity_runtime):
    owner, session = parity_runtime
    install_writer(owner)
    with duplex(owner, call()) as link, ThreadPoolExecutor(max_workers=2) as workers:
        first = session.receive_invocation()
        session.dispatch_decision(first, COMMAND)
        link.client.receiving.clear()
        receiving = workers.submit(session.receive_invocation)
        try:
            assert link.client.receiving.wait(3)
            replying = workers.submit(session.reply, first, ANSWER)
            assert replying.result(timeout=2) == owner.terminal
        finally:
            link.to_client.write(frame(call(rpc=1)))
        assert receiving.result(timeout=3).rpc_id == 1
        assert len(owner.commits) == 1
    assert [row["id"] for row in link.parsed() if "result" in row] == [0]


@pytest.mark.skipif(os.name != "posix", reason="bounded anonymous pipes require POSIX")
def test_duplex_read_progresses_while_a_reply_waits_for_writability(parity_runtime, monkeypatch):
    owner, session = parity_runtime
    install_writer(owner)
    sending, resume = threading.Event(), threading.Event()

    def pause_write(readers, writers, exceptional, timeout):
        if writers:
            sending.set()
            assert resume.wait(3)
        return select.select(readers, writers, exceptional, timeout)

    with duplex(owner, call()) as link, ThreadPoolExecutor(max_workers=2) as workers:
        first = session.receive_invocation()
        session.dispatch_decision(first, COMMAND)
        replacement = SimpleNamespace(select=pause_write)
        if owner.legacy_binding is None:
            monkeypatch.setattr(wire, "select", replacement)
        else:
            monkeypatch.setattr(legacy, "select", replacement)
        replying = workers.submit(session.reply, first, ANSWER)
        try:
            assert sending.wait(3)
            link.to_client.write(frame(call(rpc=1)))
            receiving = workers.submit(session.receive_invocation)
            assert receiving.result(timeout=2).rpc_id == 1
        finally:
            resume.set()
        assert replying.result(timeout=3) == owner.terminal
    assert [row["id"] for row in link.parsed() if "result" in row] == [0]


@pytest.mark.skipif(os.name != "posix", reason="bounded anonymous pipes require POSIX")
def test_cached_reply_and_fresh_receive_progress_during_another_retirement(parity_runtime):
    owner, session = parity_runtime
    install_writer(owner)
    retiring, release = threading.Event(), threading.Event()

    def pause_retirement():
        retiring.set()
        assert release.wait(3)

    with duplex(owner, call(), call(rpc=1)) as link, ThreadPoolExecutor(max_workers=2) as workers:
        first, second = session.receive_invocation(), session.receive_invocation()
        for invocation in (first, second):
            session.dispatch_decision(invocation, COMMAND)
        session.reply(first, ANSWER)
        owner.terminal["rpc_id"] = 1
        owner.before_retire = pause_retirement
        reply = workers.submit(session.reply, second, ANSWER)
        try:
            assert retiring.wait(3)
            link.to_client.write(frame(call(rpc=10, callId="call-0")) + frame(call(rpc=2)))
            receive = workers.submit(session.receive_invocation)
            assert receive.result(timeout=2).rpc_id == 2
        finally:
            release.set()
        assert reply.result(timeout=3) == owner.terminal
    assert [row["id"] for row in link.parsed() if "result" in row] == [0, 1, 10]


@pytest.mark.skipif(os.name != "posix", reason="bounded anonymous pipes require POSIX")
@pytest.mark.parametrize("pause_at", ["host-lock", "encoding"])
def test_fresh_receive_progresses_while_reply_is_prepared(parity_runtime, monkeypatch, pause_at):
    owner, session = parity_runtime
    install_writer(owner)
    preparing, release = threading.Event(), threading.Event()
    lock = owner.lock

    def pause():
        preparing.set()
        assert release.wait(3)

    def pause_reply_encoding(value, *args, **kwargs):
        if type(value) is dict and "contentItems" in value:
            pause()
        return json.dumps(value, *args, **kwargs)

    def pause_reply_claim(*, timeout):
        pause()
        return lock.acquire(timeout=timeout)

    with duplex(owner, call()) as link, ThreadPoolExecutor(max_workers=2) as workers:
        first = session.receive_invocation()
        session.dispatch_decision(first, COMMAND)
        if pause_at == "encoding":
            replacement = SimpleNamespace(dumps=pause_reply_encoding, loads=json.loads)
            if owner.legacy_binding is None:
                monkeypatch.setattr(wire, "json", replacement)
            else:
                monkeypatch.setattr(legacy, "json", replacement)
        else:
            owner.lock = SimpleNamespace(acquire=pause_reply_claim, release=lock.release)
            if owner.legacy_binding is not None:
                owner.legacy_binding._lock = owner.lock
        reply = workers.submit(session.reply, first, ANSWER)
        try:
            assert preparing.wait(3)
            link.to_client.write(frame(call(rpc=1)))
            assert workers.submit(session.receive_invocation).result(timeout=2).rpc_id == 1
        finally:
            release.set()
            owner.lock = lock
            if owner.legacy_binding is not None:
                owner.legacy_binding._lock = lock
        assert reply.result(timeout=3) == owner.terminal
    assert [row["id"] for row in link.parsed() if "result" in row] == [0]


@pytest.mark.skipif(os.name != "posix", reason="bounded anonymous pipes require POSIX")
@pytest.mark.parametrize("failure", ["invalid-event", "invalid-retirement"])
def test_terminal_failure_revokes_before_cleanup_allows_a_queued_reply(runtime, failure):
    owner, session = runtime
    install_writer(owner)
    is_receive = failure == "invalid-event"
    another = call(rpc=1, arguments=dict(COMMAND, event_id="INVALID")) if is_receive else call(rpc=1)
    cleanup_entered, resume_cleanup = threading.Event(), threading.Event()

    def pause_cleanup():
        if not cleanup_entered.is_set():
            cleanup_entered.set()
            assert resume_cleanup.wait(3)

    with duplex(owner, call(), another) as link, ThreadPoolExecutor(max_workers=2) as workers:
        first = session.receive_invocation()
        session.dispatch_decision(first, COMMAND)
        queued = first
        if not is_receive:
            queued = session.receive_invocation()
            session.dispatch_decision(queued, COMMAND)
            owner.terminal["state"] = []
        owner.before_close = pause_cleanup
        terminal = (workers.submit(session.receive_invocation) if is_receive else
                    workers.submit(session.reply, first, ANSWER))
        try:
            assert cleanup_entered.wait(3)
            with refusal("STALE_INVOCATION", "runtime binding is closed"):
                workers.submit(session.reply, queued, ANSWER).result(timeout=2)
        finally:
            resume_cleanup.set()
        reason = "call has no bounded decision correlation" if is_receive else "invalid terminal observation"
        with refusal("HOST_PROTOCOL_ERROR", reason):
            terminal.result(timeout=3)
    expected = [] if is_receive else [0]
    assert [row["id"] for row in link.parsed() if "result" in row] == expected


@pytest.mark.skipif(os.name != "posix", reason="bounded anonymous pipes require POSIX")
@pytest.mark.parametrize("failure,code,reason", [
    ("invalid-frame", "HOST_PROTOCOL_ERROR", "invalid host protocol frame"),
    ("conflicting-rpc", "HOST_CALL_CONFLICT", "host call correlation conflicts"),
    ("invalid-event", "HOST_PROTOCOL_ERROR", "call has no bounded decision correlation"),
    ("invalid-pending", "CANONICAL_CORRELATION_MISMATCH", "pending call does not match received frame"),
    ("invalid-retirement", "HOST_PROTOCOL_ERROR", "invalid terminal observation"),
])
def test_terminal_failure_fences_dispatch_and_guard_before_cleanup(parity_runtime, failure, code, reason):
    owner, session = parity_runtime
    install_writer(owner)
    cleanup_entered, release = threading.Event(), threading.Event()

    def pause_cleanup():
        if not cleanup_entered.is_set():
            cleanup_entered.set()
            assert release.wait(3)

    with duplex(owner, call(), call(rpc=1), call(rpc=2)) as link, ThreadPoolExecutor(max_workers=1) as worker:
        ready, pending, guarded = (session.receive_invocation() for _ in range(3))
        session.dispatch_decision(ready, COMMAND)
        queued_guard = owner.authority.effect_fence(guarded, "decision")
        owner.before_close = pause_cleanup
        if failure == "invalid-retirement":
            owner.terminal["rpc_id"] = 9
            terminal = worker.submit(session.reply, ready, ANSWER)
        else:
            incoming = {
                "invalid-frame": b"{\n",
                "conflicting-rpc": frame(call(rpc=0, callId="different")),
                "invalid-event": frame(call(rpc=3, arguments=dict(COMMAND, event_id="INVALID"))),
                "invalid-pending": frame(call(rpc=3)),
            }[failure]
            if failure == "invalid-pending":
                owner.projection_patch = {"rpc_id": 9}
            link.to_client.write(incoming)
            terminal = worker.submit(session.receive_invocation)
        try:
            assert cleanup_entered.wait(3)
            if owner.legacy_binding is None:
                with refusal("STALE_INVOCATION", "host guard is no longer current"):
                    with queued_guard:
                        pytest.fail("guard entered after terminal failure")
                with refusal("STALE_INVOCATION", "runtime binding is closed"):
                    session.dispatch_decision(pending, COMMAND)
                assert len(owner.commits) == 1
            else:
                # Frozen close() is the first place that records revocation.
                # The test seam pauses entry to it before any cleanup begins.
                with queued_guard:
                    assert owner.legacy_binding._active_guard is queued_guard
                assert session.dispatch_decision(pending, COMMAND)["state"] == "recorded"
                assert len(owner.commits) == 2
        finally:
            release.set()
        with refusal(code, reason, owner.error_type):
            terminal.result(timeout=3)
    assert owner.closed


@pytest.mark.parametrize("failure", ["guard", "timeout"])
@pytest.mark.parametrize("operation", ["receive", "reply"])
def test_admission_refusal_keeps_binding_and_reply_eligible(runtime, failure, operation):
    owner, session = runtime
    install_writer(owner)
    first = session.receive_invocation()
    session.dispatch_decision(first, COMMAND)
    owner.appserver.calls.append(call(rpc=1))
    guard_call = session.receive_invocation()
    owner.appserver.calls.append(call(rpc=2))

    @contextmanager
    def reject():
        if failure == "timeout":
            raise wire.HostAuthorityError("HOST_PROTOCOL_TIMEOUT", "original appserver deadline expired")
        with session.authority.effect_fence(guard_call, "decision"):
            yield

    owner.appserver.admit = reject
    code = "HOST_PROTOCOL_TIMEOUT" if failure == "timeout" else "ROLE_OPERATION_FORBIDDEN"
    reason = {
        "receive": "appserver IPC is forbidden inside a host fence",
        "reply": "reply IPC is forbidden inside a host fence",
    }[operation]
    if failure == "timeout":
        reason = "original appserver deadline expired"
    with refusal(code, reason):
        if operation == "receive":
            session.receive_invocation()
        else:
            session.reply(first, ANSWER)
    assert not owner.closed and not owner.appserver.replies
    owner.appserver.admit = nullcontext
    assert session.receive_invocation().rpc_id == 2
    assert session.reply(first, ANSWER) == owner.terminal


@pytest.mark.skipif(os.name != "posix", reason="bounded anonymous pipes require POSIX")
@pytest.mark.parametrize("failure", ["guard", "timeout"])
def test_reply_can_retry_after_guard_or_host_lock_admission_refusal(parity_runtime, failure):
    owner, session = parity_runtime
    install_writer(owner)
    with duplex(owner, call(), call(rpc=1)) as link:
        first, guard_call = session.receive_invocation(), session.receive_invocation()
        session.dispatch_decision(first, COMMAND)
        if failure == "guard":
            with owner.authority.effect_fence(guard_call, "decision"), refusal(
                    "ROLE_OPERATION_FORBIDDEN", "reply IPC is forbidden inside a host fence", owner.error_type):
                session.reply(first, ANSWER)
        else:
            lock = owner.lock
            owner.lock = SimpleNamespace(acquire=lambda *, timeout: False)
            if owner.legacy_binding is not None:
                owner.legacy_binding._lock = owner.lock
            try:
                with refusal("HOST_PROTOCOL_TIMEOUT", "original initial deadline expired", owner.error_type):
                    session.reply(first, ANSWER)
            finally:
                owner.lock = lock
                if owner.legacy_binding is not None:
                    owner.legacy_binding._lock = lock
        assert not owner.closed
        assert [method for method, _ in owner.requests] == ["pending_call", "pending_call"]
        assert session.reply(first, ANSWER) == owner.terminal
    assert [row["id"] for row in link.parsed() if "result" in row] == [0]


@pytest.mark.skipif(os.name != "posix", reason="bounded anonymous pipes require POSIX")
@pytest.mark.parametrize("operation", ["receive", "reply"])
def test_guard_entering_during_appserver_wait_is_observed_by_control(parity_runtime, operation, monkeypatch):
    owner, session = parity_runtime
    install_writer(owner)
    with duplex(owner, call(), call(rpc=1)) as link:
        first, guard_call = session.receive_invocation(), session.receive_invocation()
        session.dispatch_decision(first, COMMAND)
        guard = owner.authority.effect_fence(guard_call, "decision")
        enters = []

        def admit_guard(readers, writers, exceptional, timeout):
            if not enters:
                guard.__enter__()
                enters.append(True)
                if operation == "receive":
                    link.to_client.write(frame(call(rpc=2)))
            return select.select(readers, writers, exceptional, timeout)

        replacement = SimpleNamespace(select=admit_guard)
        if owner.legacy_binding is None:
            monkeypatch.setattr(wire, "select", replacement)
        else:
            monkeypatch.setattr(legacy, "select", replacement)
        try:
            # Frozen behavior: the appserver passes its original guard check,
            # but the protected control exchange sees the new active guard.
            with refusal("ROLE_OPERATION_FORBIDDEN", "control IPC is forbidden inside a host fence",
                         owner.error_type):
                if operation == "receive":
                    session.receive_invocation()
                else:
                    session.reply(first, ANSWER)
        finally:
            if enters:
                guard.__exit__(None, None, None)
        assert owner.closed
    assert [row["id"] for row in link.parsed() if "result" in row] == ([0] if operation == "reply" else [])


@pytest.mark.skipif(os.name != "posix", reason="bounded anonymous pipes require POSIX")
def test_cached_reply_writability_timeout_before_first_byte(parity_runtime, monkeypatch):
    owner, session = parity_runtime
    install_writer(owner)
    with duplex(owner, call()) as link:
        first = session.receive_invocation()
        session.dispatch_decision(first, COMMAND)
        session.reply(first, ANSWER)
        now = [time.monotonic()]

        def expire_cached_write(readers, writers, exceptional, timeout):
            if writers:
                now[0] += 60
                return [], [], []
            return select.select(readers, writers, exceptional, timeout)

        select_api = SimpleNamespace(select=expire_cached_write)
        time_api = SimpleNamespace(monotonic=lambda: now[0], monotonic_ns=time.monotonic_ns)
        if owner.legacy_binding is None:
            monkeypatch.setattr(wire, "select", select_api)
            monkeypatch.setattr(wire, "time", time_api)
        else:
            monkeypatch.setattr(legacy, "select", select_api)
            monkeypatch.setattr(legacy, "time", time_api)
        link.to_client.write(frame(call(rpc=10, callId="call-0")))
        with refusal("HOST_PROTOCOL_TIMEOUT", "host protocol deadline expired", owner.error_type):
            session.receive_invocation()
        # Frozen behavior: the alias has been reserved, even though no cached
        # reply bytes left this process and the binding cannot be retried.
        assert owner.closed
    assert [row["id"] for row in link.parsed() if "result" in row] == [0]


@pytest.fixture
def session_clock(monkeypatch):
    clock = SimpleNamespace(now=time.monotonic_ns(), monotonic=time.monotonic)
    clock.monotonic_ns = lambda: clock.now
    monkeypatch.setattr(live, "time", clock)
    return clock


def test_expiry_during_preparation_is_no_effect_stale(parity_runtime, session_clock, monkeypatch, tmp_path):
    owner, session = parity_runtime
    invocation = session.receive_invocation()
    initial_time = session_clock.now
    owner.canonical_root = tmp_path.resolve() / "canonical"
    owner.mailbox = None
    if owner.legacy_binding is None:
        producer = writers.ProtectedCanonicalDecisionWriter
        deadline = invocation.deadline_ns
    else:
        monkeypatch.setattr(legacy, "time", session_clock)
        owner.legacy_binding._deployment["canonical_root"] = owner.canonical_root
        producer = legacy_writers.ProtectedCanonicalDecisionWriter
        deadline = invocation._projection["call_deadline_monotonic_ns"]

    class ExpiringWriter(producer):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            session_clock.now = deadline

    owner.canonical_api = SimpleNamespace(ProtectedCanonicalDecisionWriter=ExpiringWriter)
    if owner.legacy_binding is not None:
        owner.legacy_binding._canonical_api = owner.canonical_api
    outcome = session.dispatch_decision(invocation, COMMAND)
    assert (outcome["code"], outcome["state"], outcome["effect"], outcome["receipt"]) == (
        "STALE_INVOCATION", "refused", "none", None)
    assert not owner.canonical_root.exists() and not owner.closed
    # Reset only the test clock to observe the retirement proof. A real expired
    # invocation cannot regain its original transport budget.
    session_clock.now = initial_time
    assert session.reply(invocation, ANSWER) == owner.terminal
    assert owner.requests[-1][1]["canonical_state"] == "refused"


@pytest.mark.parametrize("site", ["recorded", "refused", "retirement"])
@pytest.mark.parametrize("race", ["close", "state-lock"])
def test_validated_outcome_survives_close_or_state_lock_contention(
        parity_runtime, session_clock, site, race):
    owner, session = parity_runtime
    invocation = session.receive_invocation()
    ready, resume = threading.Event(), threading.Event()

    def race_after_effect(outcome=None):
        if race == "close":
            owner.close()
        else:
            ready.set()
            assert resume.wait(3)
        return outcome

    if site == "retirement":
        install_writer(owner)
        session.dispatch_decision(invocation, COMMAND)
        owner.before_retire = race_after_effect
        run = lambda: session.reply(invocation, ANSWER)
    else:
        install_writer(owner, state=site, edit=race_after_effect)
        run = lambda: session.dispatch_decision(invocation, COMMAND)

    with ThreadPoolExecutor(max_workers=1) as workers:
        result = workers.submit(run)
        try:
            if race == "state-lock":
                assert ready.wait(3)
                with owner.lock:
                    session_clock.now = (invocation.deadline_ns if owner.legacy_binding is None else
                                         invocation._projection["call_deadline_monotonic_ns"])
                    resume.set()
                    observed = result.result(timeout=2)
            else:
                observed = result.result(timeout=3)
        finally:
            resume.set()
    assert len(owner.commits) == 1
    if site == "retirement":
        assert observed == owner.terminal and owner.appserver.replies == [(0, ANSWER)]
    else:
        assert observed["state"] == site
        assert (observed["receipt"] is None) == (site == "refused")


@pytest.mark.parametrize("checkpoint", ["preflight", "retirement", "preflight-failure"])
def test_recovery_can_read_runtime_confirmed_unknown_during_retirement(parity_runtime, checkpoint):
    owner, session = parity_runtime
    install_writer(owner)
    original = session.receive_invocation()
    if checkpoint == "preflight-failure":
        with refusal("STALE_INVOCATION", "decision arguments do not match owned call", owner.error_type):
            session.dispatch_decision(original, dict(COMMAND, reason="different"))

        def reject_proof():
            raise owner.error_type("HOST_PROFILE_UNQUALIFIED", "host preflight is unavailable")

        owner.before_prove = reject_proof
        with refusal("HOST_PROFILE_UNQUALIFIED", "host preflight is unavailable", owner.error_type):
            session.reply(original, ANSWER)
        stage = original.stage if owner.legacy_binding is None else original._stage
        assert stage == "unknown" and owner.closed and not owner.commits and not owner.appserver.replies
        with refusal("STALE_INVOCATION", "runtime binding is closed", owner.error_type):
            session.reply(original, ANSWER)
        return
    result = session.dispatch_decision(original, COMMAND)
    correlation = dict(owner.requests[0][1], epoch=owner.epoch)
    correlation.pop("deadline_monotonic_ns")
    owner.terminal["state"] = "publication_unknown"
    owner.projection_patch = {"mode": "original_only", "original_event_id": original.event_id,
                              "recovery_of": correlation}
    owner.appserver.calls.append(call(rpc=1))
    retiring, release = threading.Event(), threading.Event()

    def pause_once():
        if not retiring.is_set():
            retiring.set()
            assert release.wait(3)

    if checkpoint == "preflight":
        owner.before_prove = pause_once
    else:
        owner.before_retire = pause_once
    with ThreadPoolExecutor(max_workers=2) as workers:
        reply = workers.submit(session.reply, original, ANSWER)
        try:
            assert retiring.wait(3)
            recovery = workers.submit(session.receive_invocation).result(timeout=2)
            assert recovery.decision_recovery_event_id == original.event_id
        finally:
            release.set()
        assert reply.result(timeout=3) == owner.terminal
    assert result["state"] == "recorded" and result["receipt"]["event_id"] == original.event_id
