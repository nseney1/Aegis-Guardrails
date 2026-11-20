"""Lifecycle port parity, fixed refusals, retries and confined publication."""
import ast
import copy
import errno
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import importlib
import inspect
import itertools
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import sys
from types import SimpleNamespace
from threading import Event

import pytest

from conftest import symlink_or_skip
from aegis_core import team_lifecycle as core_module
from aegis_core import team_lifecycle_writers as writers_module
from aegis_core import team_mailbox_store as store_module
from aegis_core.team_mailbox_primitives import BusyError, MailboxRefusal
from tests.unit.core.test_team_mailbox import make_store, mailbox, owner_plane
from tools import hierarchy_host_authority as host_module
from tools import hierarchy_lifecycle as legacy


NOW = "2026-11-17T15:00:00.000000Z"
SOURCE = {"commit": "a" * 40, "tree": "b" * 40, "dirty_sha256": "c" * 64}


def policy():
    actors = {}
    for role in ("root", "router", "coordinator", "operator", "reviewer"):
        actors[role + "-1"] = {"role": role, "generation": 1, "cap_seconds": 3600,
            "profile": {"model": "fixture-model", "effort": "medium" if role == "router" else "max",
                        "tier": "ultrafast", "filesystem": "read-only" if role == "root" else "workspace-write",
                        "tools": ["read", "decide"] if role == "root" else ["read", "write"]}}
    return {"schema": legacy.POLICY, "source": SOURCE,
            "authority": [{"path": (Path(__file__).resolve().parents[3] / "lifecycle-fixture" / "evidence").as_posix(), "sha256": "d" * 64}], "actors": actors,
            "current": {role: role + "-1" for role in legacy.ROLES - legacy.OPTIONAL_ROLES}, "successors": {}}


def request():
    return {"schema": legacy.REQUEST, "id": "work", "version": 1, "team": "alpha", "owner": "coordinator",
            "next_decision": "review", "phase": "validation", "operation": "targeted-tests", "source": SOURCE,
            "paths": [(Path(__file__).resolve().parents[3] / "lifecycle-fixture" / "tests").as_posix()], "prerequisites": [], "authority": "work",
            "continuation": {"members": [], "max_starts": 1, "expires_at": "2099-01-01T00:00:00Z"}}


def raw(value):
    body = json.dumps(value, sort_keys=True) + "\n"
    return {"raw": body, "sha256": hashlib.sha256(body.encode()).hexdigest()}


def event(kind, actor="coordinator-1", identifier=None, **payload):
    return {"id": identifier or kind, "actor": actor, "generation": 1,
            "custody": {"cid": "root-1", "generation": 1}, "event": {"type": kind, **payload}}


def target():
    return {"request_id": "work", "request_sha256": raw(request())["sha256"]}


@pytest.fixture
def core():
    return importlib.import_module("aegis_core.team_lifecycle")


def test_measure_legacy_refusal_set(tmp_path):
    """Initial cases were measured before porting; later cases extend the census."""
    p = policy()
    cases = [(legacy.validate_policy, ({},), ValueError),
             (legacy.validate_request, ({"raw": "{", "sha256": hashlib.sha256(b"{").hexdigest()},), ValueError),
             (legacy.validate_request, ({"raw": None, "sha256": "d" * 64},), ValueError),
             (legacy.reduce_event, (p, legacy.initial_state(p), event("unknown"), NOW), ValueError),
             (legacy.unknown_effect, ({},), KeyError),
             (legacy.validate_policy, ({**p, "current": {"root": []}},), ValueError)]
    for function, args, expected in cases:
        with pytest.raises(expected):
            function(*args)
    assert legacy.validate_policy(p) == p
    assert legacy.inspect_request(raw(request()))["classification"] == "full_planning_required"
    invalid = copy.deepcopy(p)
    invalid["actors"]["root-1"]["role"] = []
    with pytest.raises(TypeError):
        legacy.validate_policy(invalid)
    with pytest.raises(UnicodeEncodeError):
        legacy.raw_value({"raw": "\ud800", "sha256": "a" * 64})
    with pytest.raises(FileNotFoundError):
        legacy.load_json((tmp_path / "absent").as_posix())
    assert isinstance(legacy.CanonicalGenesisError("ROOT_ALREADY_EXISTS"), PermissionError)


def test_successful_reducer_parity_and_retry(core):
    p = policy()
    left, right = legacy.initial_state(p), core.initial_state(p)
    events = [event("publish", request=raw(request())),
              event("read", "router-1", **target()),
              event("decision", "root-1", decision="approve", reason="approved", **target()),
              event("admit", "operator-1", source=SOURCE,
                    gates={gate: p["authority"] for gate in legacy.GATES}, **target()),
              event("intent", "operator-1", intent_id="attempt-1", **target()),
              event("start", "operator-1", intent_id="attempt-1", **target()),
              event("terminal", "operator-1", result=raw({**target(), "intent_id": "attempt-1",
                    "outcome": "passed", "exit_code": 0, "source": SOURCE, "evidence": p["authority"]}), **target())]
    # Terminal result has its own closed schema, with no request_id.
    terminal = json.loads(events[-1]["event"]["result"]["raw"])
    terminal.pop("request_id")
    events[-1]["event"]["result"] = raw(terminal)
    for envelope in events:
        assert legacy.reduce_event(p, left, envelope, NOW) == core.reduce_event(p, right, envelope, NOW)
        assert left == right
        assert legacy.checkpoint(p, left) == core.checkpoint(p, right)
    assert core.unknown_effect(right["requests"]["work"]) is False


@pytest.mark.parametrize("field", ["schema", "source", "authority", "actors", "current", "successors"])
def test_policy_refusals_name_only_fixed_field(core, field):
    p = policy()
    p[field] = "secret-token\nnot-a-policy"
    with pytest.raises(core.LifecycleRefusal) as caught:
        core.validate_policy(p)
    result = caught.value.as_dict()
    assert result["code"] == "invalid_policy"
    assert result["field"] == field
    assert result["reason"] and result["next_action"]
    assert "secret-token" not in str(result)
    assert core.validate_policy(policy()) == policy()


def test_unknown_event_is_atomic_and_retry_succeeds(core):
    p = policy()
    state = core.initial_state(p)
    before = copy.deepcopy(state)
    with pytest.raises(core.LifecycleRefusal) as caught:
        core.reduce_event(p, state, event("unknown"), NOW)
    assert caught.value.code == "invalid_record"
    assert state == before
    core.reduce_event(p, state, event("publish", request=raw(request())), NOW)
    before = copy.deepcopy(state)
    bad = event("disposition", status="FINAL", resolution={"kind": "next", "request": raw(request()),
                                                          "evidence": p["authority"]}, **target())
    with pytest.raises(core.LifecycleRefusal):
        core.reduce_event(p, state, bad, NOW)
    assert state == before
    assert core.add_request(state, raw(request()), "coordinator-1") == state["requests"]["work"]


def test_boundary_checks_call_shape_without_inference_from_parameter_names(core):
    @core.boundary
    def accept(raw, root_fd, at, write):
        return raw, root_fd, at, write

    assert accept(b"payload", None, 0, "preview") == (b"payload", None, 0, "preview")
    for args, kwargs in [((b"payload",), {}), ((b"payload", None, 0, True), {"raw": b"extra"})]:
        with pytest.raises(core.LifecycleRefusal) as caught:
            accept(*args, **kwargs)
        assert caught.value.as_dict() == core.LifecycleRefusal().as_dict()


def test_public_reduction_shapes_each_input_once_on_publish_and_retry(core):
    p = policy()
    state = core.initial_state(p)
    publish = event("publish", request=raw(request()))

    def count_shapes(frame, action, arg):
        if action == "call" and frame.f_code.co_filename == core.__file__ and frame.f_code.co_name == "_shape":
            shapes.append(id(frame.f_locals["value"]))

    for _ in range(2):
        shapes = []
        previous = sys.getprofile()
        try:
            sys.setprofile(count_shapes)
            assert core.reduce_event(p, state, publish, NOW) is None
        finally:
            sys.setprofile(previous)
        assert shapes == [id(p), id(state), id(publish)]

    assert state["requests"]["work"]["raw"] == publish["event"]["request"]


def test_concurrent_reductions_keep_fixed_refusals_and_allow_retry(core):
    p = policy()
    publish = event("publish", request=raw(request()))
    bad_inputs = (
        ({**p, "actors": []}, publish, NOW, "invalid_record"),
        (p, {**publish, "event": "private-input\nsecond-line"}, NOW, "invalid_record"),
        (p, {**publish, "extra": "x" * core.MAX_BYTES}, NOW, "too_large"),
        (p, publish, 0, "invalid_record"),
    )

    def attempt(bad):
        state = core.initial_state(p)
        before = copy.deepcopy(state)
        bad_policy, bad_event, bad_at, code = bad
        with pytest.raises(core.LifecycleRefusal) as caught:
            core.reduce_event(bad_policy, state, bad_event, bad_at)
        assert caught.value.as_dict() == core.LifecycleRefusal(code).as_dict()
        assert state == before
        core.reduce_event(p, state, publish, NOW)
        return state

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(attempt, bad) for bad in bad_inputs]
        states = [future.result(timeout=10) for future in futures]
    assert states == [states[0]] * len(bad_inputs)


@pytest.fixture
def journal(tmp_path, core, owner_plane):
    root = make_store(tmp_path)
    with mailbox(root) as box:
        path = root.parent / "lifecycle"
        writers = importlib.import_module("aegis_core.team_lifecycle_writers")
        writers.initialize(path, policy(), mailbox=box)
        yield writers.Lifecycle(path, mailbox=box, clock=lambda: NOW), box


def test_journal_parity_idempotency_and_checkpoint(journal, core, monkeypatch):
    reader, box = journal
    monkeypatch.setattr(legacy, "timestamp", lambda: NOW)
    legacy_path = reader.root.parent / "legacy"
    legacy.initialize(legacy_path, policy())
    old = legacy.Lifecycle(legacy_path)
    envelope = event("publish", request=raw(request()))
    assert reader.record(envelope) == old.record(envelope)
    assert reader.record(envelope) == old.record(envelope)
    assert reader.load() == old.load()
    assert reader.status() == old.status()
    assert core.checkpoint(*reader.load()) == legacy.checkpoint(*old.load())


def test_refusal_has_no_persistent_change_and_valid_retry(journal, core):
    reader, box = journal
    before = reader.load()
    with pytest.raises(core.LifecycleRefusal):
        reader.record(event("unknown"))
    assert reader.load() == before
    reader.record(event("publish", request=raw(request())))
    assert reader.load()[1]["sequence"] == 1


def test_no_host_port_is_unqualified_without_io(core, tmp_path):
    writers = importlib.import_module("aegis_core.team_lifecycle_writers")
    root = tmp_path / "absent"
    with pytest.raises(core.LifecycleRefusal) as caught:
        writers.ProtectedCanonicalEnrollmentWriter(root.as_posix(), None).initialize_reserved_genesis(None, (), None)
    assert caught.value.code == "unqualified"
    assert writers.ProtectedCanonicalBootstrapWriter(root.as_posix()).commit_initial_creation(None, None)["code"] == "unqualified"
    command = {"event_id": "decision", **target(), "decision": "approve", "reason": "approved"}
    assert writers.ProtectedCanonicalDecisionWriter(root.as_posix(), None).commit_decision(None, command)["code"] == "unqualified"
    assert not root.exists()


def test_symlink_policy_refused_then_retry(journal, core):
    reader, box = journal
    original = reader.root / "policy.json"
    saved = reader.root / "saved.json"
    original.rename(saved)
    symlink_or_skip(saved, original)
    with pytest.raises(core.LifecycleRefusal) as caught:
        reader.load()
    assert caught.value.code == "unsafe_path"
    original.unlink()
    saved.rename(original)
    assert reader.load()[1]["sequence"] == 0


def test_oversized_policy_refused_before_parse(journal, core, monkeypatch):
    reader, box = journal
    (reader.root / "policy.json").write_bytes(b"x" * (core.MAX_BYTES + 1))
    def forbidden(*args):
        pytest.fail("oversized input reached parser")
    monkeypatch.setattr(core_module, "strict_json", forbidden)
    with pytest.raises(core.LifecycleRefusal) as caught:
        reader.load()
    assert caught.value.code == "too_large"


def test_pins_are_identical_to_claim():
    # Snapshot-safe: fixed hashes, no git history dependency.
    path = Path(__file__).resolve().parents[3] / "tools" / "hierarchy_lifecycle.py"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == "c941520a185de54a2e8e3419689220cd627aab5d80ea97ea36fb09f965d28ebf"


@pytest.fixture
def decision(journal):
    """Mock only the owner-injected host boundary; this grants no native authority."""
    reader, box = journal
    writers = importlib.import_module("aegis_core.team_lifecycle_writers")
    HostError = host_module.HostAuthorityError
    class Invocation:
        event_id, actor_cid, decision_recovery_event_id = "approval", "root-1", None
    class Authority:
        canonical_root = reader.root
        current_hooks = []
        @contextmanager
        def effect_fence(self, invocation, operation):
            yield
        def require_current(self, invocation, policy, state, row):
            if row is not None and state["requests"].get(row["request"]["id"]) is not row:
                raise HostError("CANONICAL_CORRELATION_MISMATCH", "fixture canonical row mismatch")
            for hook in self.current_hooks:
                hook(invocation, policy, state, row)
        def require_decision_command(self, *args):
            for hook in hooks:
                hook(*args)
    hooks = []
    authority = Authority()
    port = SimpleNamespace(HostAuthority=Authority, HostInvocation=Invocation, HostAuthorityError=HostError)
    writer = writers.ProtectedCanonicalDecisionWriter(reader.root, authority, mailbox=box,
                                                      host_authority=port, clock=lambda: NOW)
    reader.record(event("publish", request=raw(request())))
    command = {"event_id": "approval", **target(), "decision": "approve", "reason": "approved"}
    return reader, writer, Invocation(), command, hooks


def test_protected_decision_parity_and_recovery(decision, monkeypatch):
    reader, writer, invocation, command, hooks = decision
    first = writer.commit_decision(invocation, command)
    assert first["state"] == "recorded"
    recovered = writer.commit_decision(invocation, command)
    assert recovered["state"] == "recovered"
    assert recovered == legacy._decision_result(command, "recovered", receipt=first["receipt"])
    before = reader.load()
    result = writer.commit_decision(invocation, {**command, "reason": "changed"})
    assert result["code"] == "REPLAY_CONFLICT"
    assert result["reason"] and result["next_action"]
    assert reader.load() == before
    assert writer.commit_decision(invocation, command) == recovered


def test_protected_target_changed_preserves_records_and_retry(decision, core, monkeypatch):
    reader, writer, invocation, command, hooks = decision
    original = reader.root / "events"
    saved = reader.root / "saved-events"
    before = {p.name: p.read_bytes() for p in original.iterdir()}
    original_publish = writers_module.Lifecycle.publish
    def changed(self, record, root_fd, events_fd):
        original.rename(saved)
        original.mkdir(mode=0o700)
        try:
            return original_publish(self, record, root_fd, events_fd)
        finally:
            original.rmdir()
            saved.rename(original)
    monkeypatch.setattr(writers_module.Lifecycle, "publish", changed)
    result = writer.commit_decision(invocation, command)
    assert result["state"] == "refused"
    assert result["code"] == "target_changed"
    assert {p.name: p.read_bytes() for p in original.iterdir()} == before
    monkeypatch.setattr(writers_module.Lifecycle, "publish", original_publish)
    assert writer.commit_decision(invocation, command)["state"] == "recorded"


def test_policy_change_during_guard_refuses_publication(decision, monkeypatch):
    reader, writer, invocation, command, hooks = decision
    original = reader.root / "policy.json"
    saved = original.read_bytes()
    def changed(*args):
        original.write_text("{}")
    hooks.append(changed)
    result = writer.commit_decision(invocation, command)
    assert result["state"] == "refused"
    assert result["code"] == "target_changed"
    assert len(list((reader.root / "events").iterdir())) == 1
    original.write_bytes(saved)
    hooks.clear()
    assert writer.commit_decision(invocation, command)["state"] == "recorded"


def test_new_publication_exclusive_and_retry(journal, core, monkeypatch):
    reader, box = journal
    destination = reader.root / "events" / "000001.json"
    publish = store_module.Store.publish
    def occupied(self, path, raw, **options):
        if path == destination:
            destination.write_bytes(b"retained")
        return publish(self, path, raw, **options)
    monkeypatch.setattr(store_module.Store, "publish", occupied)
    with pytest.raises(core.LifecycleRefusal) as caught:
        reader.record(event("publish", request=raw(request())))
    assert caught.value.code == "exists"
    assert destination.read_bytes() == b"retained"
    destination.unlink()
    monkeypatch.setattr(store_module.Store, "publish", publish)
    assert reader.record(event("publish", request=raw(request())))["sequence"] == 1


def test_unsupported_platform_path(core, tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    with pytest.raises(MailboxRefusal) as caught:
        mailbox(tmp_path / "absent")
    assert type(caught.value) is MailboxRefusal
    assert caught.value.reason == "unsupported_platform"


@pytest.mark.parametrize("body", ["{", "{\"x\":1,\"x\":2}", "NaN", "1e999", "\"\\ud800\""])
def test_malformed_json_never_escapes_raw_exception(core, body):
    with pytest.raises(core.LifecycleRefusal) as caught:
        core.strict_json(body)
    assert caught.value.code == "invalid_record"
    assert caught.value.as_dict() == core.LifecycleRefusal().as_dict()


def test_unknown_request_effect_refuses_and_retries(core):
    state = core.initial_state(policy())
    before = copy.deepcopy(state)
    with pytest.raises(core.LifecycleRefusal):
        core.add_request(state, raw({**request(), "effect": "execute-arbitrary"}), "coordinator-1")
    assert state == before
    core.add_request(state, raw(request()), "coordinator-1")
    assert len(state["requests"]) == 1


def test_concurrent_writer_refuses_then_recovers_original(journal, core, monkeypatch):
    reader, box = journal
    entered, release = Event(), Event()
    publish = store_module.Store.publish
    def paused(self, path, body, **options):
        if path.parent == reader.root / "events":
            entered.set()
            assert release.wait(timeout=5), "writer release was not signalled"
        return publish(self, path, body, **options)
    monkeypatch.setattr(store_module.Store, "publish", paused)
    envelope = event("publish", request=raw(request()))
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(reader.record, envelope)
        try:
            assert entered.wait(timeout=5), "writer did not reach publication"
            with pytest.raises(core.LifecycleRefusal) as caught:
                reader.record(envelope)
            assert caught.value.code == "busy"
        finally:
            release.set()
        receipt = first.result(timeout=5)
    assert reader.record(envelope) == receipt
    assert reader.load()[1]["sequence"] == 1


def test_invalid_policy_creates_no_root_or_checkpoint(journal, core):
    reader, box = journal
    writers = importlib.import_module("aegis_core.team_lifecycle_writers")
    for field, value in policy().items():
        malformed = {**policy(), field: [] if type(value) is dict else {}}
        with pytest.raises(core.LifecycleRefusal) as expected:
            core.validate_policy(malformed)
        path = reader.root.parent / ("invalid-policy-" + field)
        with pytest.raises(core.LifecycleRefusal) as caught:
            writers.initialize(path, malformed, mailbox=box)
        assert caught.value.as_dict() == expected.value.as_dict()
        assert not path.exists()
        writers.initialize(path, policy(), mailbox=box)
        assert writers.Lifecycle(path, mailbox=box).load()[1]["sequence"] == 0


def test_failure_after_partial_reduction_is_atomic(core):
    p = policy()
    state = core.initial_state(p)
    core.reduce_event(p, state, event("publish", request=raw(request())), NOW)
    # A successor request is added before the legacy final disposition append.
    # Corrupt only that append target to exercise rollback after candidate work.
    state["requests"]["work"]["dispositions"] = None
    following = {**request(), "id": "following", "authority": "following"}
    before = copy.deepcopy(state)
    with pytest.raises(core.LifecycleRefusal):
        core.reduce_event(p, state, event("disposition", status="FINAL", resolution={"kind": "next",
            "request": raw(following), "evidence": p["authority"]}, **target()), NOW)
    assert state == before


@pytest.fixture
def bootstrap(journal, core):
    reader, box = journal
    p = policy()
    process = {"boot_id": "00000000-0000-0000-0000-000000000001", "pid_namespace": 1, "pid": 2, "start_ticks": 3}
    channel = {"schema": "aegis.host-channel-witness/v1", "runtime_instance": process,
               "appserver_instance": process, "control_peer_instance": process, "read_pipe_inode": 1,
               "write_pipe_inode": 2, "epoch": 1, "deployment_sha256": "a" * 64,
               "runtime_executable_sha256": "b" * 64, "host_source_closure_sha256": "c" * 64,
               "role_ceiling_sha256": "d" * 64}
    runtime = SimpleNamespace(canonical_root=reader.root.parent / "protected", approved_plan_ref=p["authority"][0],
                              accepted_plan={key: p[key] for key in ("source", "actors", "current", "successors")},
                              channel_witness=channel)
    HostError = host_module.HostAuthorityError
    class Reservation:
        def __init__(self, cid, sequence):
            self.actor_cid, self.owned_runtime = cid, runtime
            actor = p["actors"][cid]
            self.witness = {"schema": "aegis.host-reservation-witness/v1", "actor_cid": cid,
                "role": actor["role"], "generation": actor["generation"], "cap_seconds": actor["cap_seconds"],
                "profile_sha256": core.digest(actor["profile"]), "channel_instance_sha256": core.digest(channel),
                "approved_plan_sha256": runtime.approved_plan_ref["sha256"], "reservation_sequence": sequence,
                "expires_monotonic_ns": 1000000000}
    class Guard:
        def require_reserved_genesis_current(self):
            pass
        def require_initial_identity_current(self, *args):
            pass
        def require_initial_creation_current(self, *args):
            pass
        def require_initial_creation_new(self, *args):
            pass
    class Authority:
        owned_runtime = runtime
        @contextmanager
        def bootstrap_fence(self, *args):
            yield Guard()
    port = SimpleNamespace(HostAuthority=Authority, ReservedEnrollment=Reservation,
                           InitialCreationGuard=Guard, HostAuthorityError=HostError)
    reservations = tuple(Reservation(cid, i) for i, cid in enumerate(sorted(p["actors"]), 1))
    writers = importlib.import_module("aegis_core.team_lifecycle_writers")
    enrollment = writers.ProtectedCanonicalEnrollmentWriter(runtime.canonical_root, Authority(), mailbox=box,
                                                            host_authority=port, clock=lambda: NOW)
    return runtime, reservations, Guard(), port, enrollment, box


def test_protected_genesis_and_initial_recovery_parity(bootstrap, core, monkeypatch):
    runtime, reservations, guard, port, enrollment, box = bootstrap
    writers = importlib.import_module("aegis_core.team_lifecycle_writers")
    original_root = runtime.canonical_root
    actual = enrollment.initialize_reserved_genesis(runtime, reservations, runtime.approved_plan_ref)
    snapshot = legacy.Lifecycle(original_root).initial_bootstrap()
    assert actual["policy_sha256"] == snapshot["policy_sha256"]
    assert actual["checkpoint_sha256"] == snapshot["genesis_checkpoint"]["sha256"]
    reader = writers.Lifecycle(original_root, mailbox=box)
    assert reader.initial_bootstrap() == snapshot
    with pytest.raises(writers.CanonicalGenesisError) as caught:
        enrollment.initialize_reserved_genesis(runtime, reservations, runtime.approved_plan_ref)
    assert caught.value.code == "ROOT_ALREADY_EXISTS"
    assert caught.value.as_dict()["effect"] == "none"
    writer = writers.ProtectedCanonicalBootstrapWriter(original_root, mailbox=box, host_authority=port, clock=lambda: NOW)
    first = writer.commit_initial_creation(guard, reservations[0])
    assert first["state"] == "recorded"
    recovered = writer.commit_initial_creation(guard, reservations[0])
    assert recovered["state"] == "recovered"
    assert recovered == legacy._initial_result("recovered", cid=first["actor_cid"],
                                               event_id=first["event_id"], receipt=first["receipt"])


def test_bootstrap_missing_genesis_refuses_without_mutation(journal):
    reader, box = journal
    writers = importlib.import_module("aegis_core.team_lifecycle_writers")
    with pytest.raises(writers.InitialBootstrapMissing) as caught:
        reader.initial_bootstrap()
    assert caught.value.code == "initial_genesis_required"
    assert reader.load()[1]["sequence"] == 0


@pytest.fixture(params=["initial", "decision"])
def protected_refusal_case(request, pytest_request):
    if request.param == "decision":
        reader, writer, invocation, command, hooks = pytest_request.getfixturevalue("decision")
        old = legacy.ProtectedCanonicalDecisionWriter(reader.root, writer.authority)
        return SimpleNamespace(reader=reader, writer=writer, kind="decision", hooks=hooks,
                               after_hooks=writer.authority.current_hooks,
                               call=lambda: writer.commit_decision(invocation, command),
                               legacy_call=lambda: old.commit_decision(invocation, command),
                               busy="CANONICAL_WRITER_BUSY", unknown="PUBLICATION_UNKNOWN")
    runtime, reservations, guard, port, enrollment, box = pytest_request.getfixturevalue("bootstrap")
    enrollment.initialize_reserved_genesis(runtime, reservations, runtime.approved_plan_ref)
    hooks = []
    after_hooks = []

    class Guard(port.InitialCreationGuard):
        def require_initial_creation_current(self, *args):
            for hook in hooks:
                hook(*args)
        def require_initial_identity_current(self, *args):
            for hook in after_hooks:
                hook(*args)

    port = SimpleNamespace(**{**vars(port), "InitialCreationGuard": Guard})
    guard = Guard()
    writer = writers_module.ProtectedCanonicalBootstrapWriter(runtime.canonical_root, mailbox=box,
                                                               host_authority=port, clock=lambda: NOW)
    old = legacy.ProtectedCanonicalBootstrapWriter(runtime.canonical_root)
    return SimpleNamespace(reader=writers_module.Lifecycle(runtime.canonical_root, mailbox=box),
                           writer=writer, kind="initial", hooks=hooks, after_hooks=after_hooks,
                           call=lambda: writer.commit_initial_creation(guard, reservations[0]),
                           legacy_call=lambda: old.commit_initial_creation(guard, reservations[0]),
                           busy="CANONICAL_BUSY", unknown="INITIAL_CREATION_PUBLICATION_UNKNOWN")


def lifecycle_bytes(root):
    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}


def test_protected_busy_refusal_has_no_effect_and_retries(protected_refusal_case, monkeypatch):
    case = protected_refusal_case
    before = lifecycle_bytes(case.reader.root)
    entered, release = Event(), Event()

    def hold():
        # This holder does not acquire the owner evidence lock.
        with legacy.writer_lock(case.reader.root):
            entered.set()
            assert release.wait(timeout=10), "contender release was not signalled"

    canonical_attempts = []
    original = store_module.Store.lock

    @contextmanager
    def observed(self, directory, *args, **options):
        canonical_attempts.append(directory)
        with original(self, directory, *args, **options):
            yield

    # The calling thread already owns the evidence transaction, so each call
    # must reach the independently held canonical exclusion.
    with case.reader.store.evidence_transaction():
        monkeypatch.setattr(store_module.Store, "lock", observed)
        with ThreadPoolExecutor(max_workers=1) as pool:
            holder = pool.submit(hold)
            try:
                assert entered.wait(timeout=10), "contender did not acquire canonical lock"
                assert (case.reader.root / ".write.lock").is_file()
                for _ in range(2):
                    answer = case.call()
                    assert (answer["state"], answer["code"], answer["effect"]) == ("refused", case.busy, "none")
                assert canonical_attempts == [case.reader.root, case.reader.root]
            finally:
                release.set()
            holder.result(timeout=10)
        monkeypatch.setattr(store_module.Store, "lock", original)
    assert lifecycle_bytes(case.reader.root) == before
    assert case.call()["state"] == "recorded"
    assert case.call()["state"] == "recovered"


@pytest.mark.parametrize("failure", ["busy", "too_large", "invalid_record", "io"])
def test_protected_generator_body_refusals(protected_refusal_case, monkeypatch, failure):
    case = protected_refusal_case
    before = lifecycle_bytes(case.reader.root)
    original = store_module.Store.read

    def failed(self, path, **options):
        if path == case.reader.root / "policy.json":
            if failure == "busy":
                raise BusyError(path) from None
            if failure == "io":
                raise OSError(errno.EIO, "untrusted\ninput")
            raise MailboxRefusal(failure) from None
        return original(self, path, **options)

    monkeypatch.setattr(store_module.Store, "read", failed)
    answer = case.call()
    monkeypatch.setattr(store_module.Store, "read", original)
    expected = case.busy if failure == "busy" else (
        "too_large" if case.kind == "decision" and failure == "too_large" else
        case.unknown if case.kind == "decision" else "CANONICAL_INVALID")
    assert answer["code"] == expected
    assert answer["state"] == ("unknown" if expected == case.unknown else "refused")
    assert "untrusted" not in json.dumps(answer)
    assert lifecycle_bytes(case.reader.root) == before
    assert case.call()["state"] == "recorded"


@pytest.mark.parametrize("failure", ["busy", "too_large", "io"])
def test_initial_failure_after_publication_is_unknown(bootstrap, monkeypatch, failure):
    runtime, reservations, guard, port, enrollment, box = bootstrap
    enrollment.initialize_reserved_genesis(runtime, reservations, runtime.approved_plan_ref)
    writer = writers_module.ProtectedCanonicalBootstrapWriter(runtime.canonical_root, mailbox=box,
                                                               host_authority=port, clock=lambda: NOW)
    original = store_module.Store.lock
    depth = [0]

    @contextmanager
    def published_then_failed(self, path, *args, **options):
        depth[0] += 1
        try:
            with original(self, path, *args, **options):
                yield
        finally:
            depth[0] -= 1
        if depth[0]:
            return
        if failure == "busy":
            raise BusyError(path) from None
        if failure == "io":
            raise OSError(errno.EIO, "untrusted\ninput")
        raise core_module.LifecycleRefusal("too_large") from None

    monkeypatch.setattr(store_module.Store, "lock", published_then_failed)
    answer = writer.commit_initial_creation(guard, reservations[0])
    monkeypatch.setattr(store_module.Store, "lock", original)
    assert (answer["state"], answer["code"], answer["effect"]) == (
        "unknown", "INITIAL_CREATION_PUBLICATION_UNKNOWN", "possible")
    assert "untrusted" not in json.dumps(answer)
    assert writers_module.Lifecycle(runtime.canonical_root, mailbox=box).load()[1]["sequence"] == 2
    assert writer.commit_initial_creation(guard, reservations[0])["state"] == "recovered"


def test_genesis_policy_reason_matches_legacy():
    assert writers_module.CanonicalGenesisError("POLICY_INVALID").reason == legacy.CanonicalGenesisError("POLICY_INVALID").reason
    assert writers_module.CanonicalGenesisError("POLICY_INVALID").reason == "protected bootstrap evidence is invalid"


@pytest.mark.parametrize("entry", ["load", "initial_bootstrap", "record", "view", "transaction"])
@pytest.mark.parametrize("failure", ["busy", "too_large", "invalid_record", "io"])
def test_lifecycle_context_callers_translate_body_failures(bootstrap, core, monkeypatch, entry, failure):
    runtime, reservations, guard, port, enrollment, box = bootstrap
    enrollment.initialize_reserved_genesis(runtime, reservations, runtime.approved_plan_ref)
    reader = writers_module.Lifecycle(runtime.canonical_root, mailbox=box, clock=lambda: NOW)
    writer = writers_module.ProtectedCanonicalBootstrapWriter(reader.root, mailbox=box)
    original = store_module.Store.read
    before = lifecycle_bytes(reader.root)

    def failed(self, path, **options):
        if path == reader.root / "policy.json":
            if failure == "busy":
                raise BusyError(path) from None
            if failure == "io":
                if entry == "view":
                    # The real Store normalizes OS errors at its own boundary.
                    raise MailboxRefusal("io") from None
                raise OSError(errno.EIO, "untrusted\ninput")
            raise MailboxRefusal(failure) from None
        return original(self, path, **options)

    def call():
        if entry == "view":
            with reader.view(write=True) as (root_fd, events_fd):
                return reader.store.read(reader.root / "policy.json", parent=root_fd)
        if entry == "transaction":
            with writer.transaction() as active:
                return active.load()
        if entry == "record":
            return reader.record(event("publish", request=raw(request())))
        if entry == "load":
            return reader.load()
        return reader.initial_bootstrap()

    monkeypatch.setattr(store_module.Store, "read", failed)
    with pytest.raises(core.LifecycleRefusal) as caught:
        call()
    monkeypatch.setattr(store_module.Store, "read", original)
    assert caught.value.code == failure
    assert "untrusted" not in json.dumps(caught.value.as_dict())
    assert lifecycle_bytes(reader.root) == before
    assert call() is not None


@pytest.mark.parametrize("failure", ["busy", "too_large", "invalid_record", "io"])
def test_enrollment_transaction_failure_preserves_unknown_root(bootstrap, monkeypatch, failure):
    runtime, reservations, guard, port, enrollment, box = bootstrap
    original = store_module.Store.read

    def failed(self, path, **options):
        if path == runtime.canonical_root / "policy.json":
            if failure == "busy":
                raise BusyError(path) from None
            if failure == "io":
                raise OSError(errno.EIO, "untrusted\ninput")
            raise MailboxRefusal(failure) from None
        return original(self, path, **options)

    monkeypatch.setattr(store_module.Store, "read", failed)
    with pytest.raises(writers_module.CanonicalGenesisError) as caught:
        enrollment.initialize_reserved_genesis(runtime, reservations, runtime.approved_plan_ref)
    monkeypatch.setattr(store_module.Store, "read", original)
    assert (caught.value.code, caught.value.state, caught.value.effect) == (
        "GENESIS_PUBLICATION_UNKNOWN", "unknown", "possible")
    assert "untrusted" not in json.dumps(caught.value.as_dict())
    before = lifecycle_bytes(runtime.canonical_root)
    assert writers_module.Lifecycle(runtime.canonical_root, mailbox=box).load()[1]["sequence"] == 0
    with pytest.raises(writers_module.CanonicalGenesisError) as retry:
        enrollment.initialize_reserved_genesis(runtime, reservations, runtime.approved_plan_ref)
    assert retry.value.code == "ROOT_ALREADY_EXISTS"
    assert lifecycle_bytes(runtime.canonical_root) == before


@pytest.mark.parametrize("failure", ["busy", "too_large", "invalid_record", "io"])
def test_protected_mid_publication_failure_is_unknown(protected_refusal_case, monkeypatch, failure):
    case = protected_refusal_case
    before = lifecycle_bytes(case.reader.root)
    original = store_module.Store.publish

    def failed(self, path, body, **options):
        if failure == "busy":
            raise BusyError(path) from None
        if failure == "io":
            raise OSError(errno.EIO, "untrusted\ninput")
        raise MailboxRefusal(failure) from None

    monkeypatch.setattr(store_module.Store, "publish", failed)
    answer = case.call()
    monkeypatch.setattr(store_module.Store, "publish", original)
    # A store-level exception has no proof of where publication stopped.
    code = case.unknown
    assert answer["code"] == code
    assert answer["state"] == ("refused" if code == "too_large" else "unknown")
    assert lifecycle_bytes(case.reader.root) == before
    assert "untrusted" not in json.dumps(answer)
    assert case.call()["state"] == "recorded"


@pytest.mark.parametrize("failure", ["host", "unrelated_cause"])
def test_protected_host_failures_keep_identity(protected_refusal_case, monkeypatch, failure):
    case = protected_refusal_case
    before = lifecycle_bytes(case.reader.root)

    def failed(*args):
        if failure == "host":
            raise case.writer.host.HostAuthorityError("STALE_INVOCATION", "untrusted\ninput")
        raise ValueError("untrusted\ninput") from FileExistsError("untrusted")

    monkeypatch.setattr(host_module, "HostAuthority", case.writer.host.HostAuthority)
    if case.kind == "decision":
        monkeypatch.setattr(host_module, "HostInvocation", case.writer.host.HostInvocation)
    else:
        monkeypatch.setattr(host_module, "InitialCreationGuard", case.writer.host.InitialCreationGuard)
        monkeypatch.setattr(host_module, "ReservedEnrollment", case.writer.host.ReservedEnrollment)
    case.hooks.append(failed)
    old = case.legacy_call()
    answer = case.call()
    case.hooks.clear()
    expected = ("STALE_INVOCATION" if failure == "host" else case.unknown) if case.kind == "decision" else (
        "HOST_AUTHORITY_REFUSED" if failure == "host" else "CANONICAL_INVALID")
    assert answer["code"] == expected
    if failure == "host":
        assert {key: answer[key] for key in old} == old
    assert lifecycle_bytes(case.reader.root) == before
    assert "untrusted" not in json.dumps(answer)
    assert case.call()["state"] == "recorded"


@pytest.mark.parametrize("failure", ["busy", "too_large", "io"])
def test_protected_exit_failure_after_retained_publication(protected_refusal_case, monkeypatch, failure):
    case = protected_refusal_case
    before = case.reader.load()[1]["sequence"]
    original = store_module.Store.lock
    depth = [0]

    @contextmanager
    def published_then_failed(self, path, *args, **options):
        depth[0] += 1
        try:
            with original(self, path, *args, **options):
                yield
        finally:
            depth[0] -= 1
        if depth[0]:
            return
        assert case.reader.load()[1]["sequence"] == before + 1
        if failure == "busy":
            raise BusyError(path) from None
        raise MailboxRefusal(failure) from None

    monkeypatch.setattr(store_module.Store, "lock", published_then_failed)
    answer = case.call()
    monkeypatch.setattr(store_module.Store, "lock", original)
    assert (answer["state"], answer["code"], answer["effect"]) == ("unknown", case.unknown, "possible")
    assert case.reader.load()[1]["sequence"] == before + 1
    assert case.call()["state"] == "recovered"


@pytest.mark.parametrize("entry", ["read_view", "write_view", "transaction"])
def test_host_error_crosses_storage_contexts_unchanged(journal, entry):
    reader, box = journal
    before = lifecycle_bytes(reader.root)
    error = host_module.HostAuthorityError("STALE_INVOCATION", "untrusted\ninput")
    writer = writers_module.ProtectedCanonicalDecisionWriter(reader.root, mailbox=box)
    context = writer.transaction() if entry == "transaction" else reader.view(write=entry == "write_view")
    with pytest.raises(host_module.HostAuthorityError) as caught:
        with context:
            raise error
    assert caught.value is error
    assert lifecycle_bytes(reader.root) == before
    assert reader.record(event("publish", request=raw(request())))["sequence"] == 1


def test_decision_preflight_size_refusal_has_no_effect(decision, monkeypatch):
    reader, writer, invocation, command, hooks = decision
    before = lifecycle_bytes(reader.root)
    original = writers_module.Lifecycle.publish
    limit = core_module.MAX_BYTES
    entered = []

    def limited(self, record, root_fd, events_fd):
        entered.append(record["sequence"])
        monkeypatch.setattr(core_module, "MAX_BYTES", 1)
        try:
            return original(self, record, root_fd, events_fd)
        finally:
            monkeypatch.setattr(core_module, "MAX_BYTES", limit)

    monkeypatch.setattr(writers_module.Lifecycle, "publish", limited)
    answer = writer.commit_decision(invocation, command)
    monkeypatch.setattr(writers_module.Lifecycle, "publish", original)
    assert entered == [2]
    assert (answer["state"], answer["code"], answer["effect"]) == ("refused", "too_large", "none")
    assert lifecycle_bytes(reader.root) == before
    assert writer.commit_decision(invocation, command)["state"] == "recorded"


def test_protected_host_error_after_publication_matches_legacy(protected_refusal_case, monkeypatch):
    case = protected_refusal_case
    before = case.reader.load()[1]["sequence"]
    error = case.writer.host.HostAuthorityError("STALE_INVOCATION", "untrusted\ninput")

    def after_publication(*args):
        if case.reader.load()[1]["sequence"] == before + 1:
            raise error

    monkeypatch.setattr(host_module, "HostAuthority", case.writer.host.HostAuthority)
    if case.kind == "decision":
        monkeypatch.setattr(host_module, "HostInvocation", case.writer.host.HostInvocation)
    else:
        monkeypatch.setattr(host_module, "InitialCreationGuard", case.writer.host.InitialCreationGuard)
        monkeypatch.setattr(host_module, "ReservedEnrollment", case.writer.host.ReservedEnrollment)
    case.after_hooks.append(after_publication)
    old = case.legacy_call()
    assert (old["state"], old["code"], old["effect"]) == ("unknown", case.unknown, "possible")
    assert case.reader.load()[1]["sequence"] == before + 1
    # Restore this fixture's appended leaf so both implementations see the
    # same original canonical input. No tracked file or history is involved.
    (case.reader.root / "events" / ("%06d.json" % (before + 1))).unlink()
    answer = case.call()
    case.after_hooks.clear()
    assert {key: answer[key] for key in old} == old
    assert "untrusted" not in json.dumps(answer)
    assert case.reader.load()[1]["sequence"] == before + 1
    assert case.call()["state"] == "recovered"


def test_measure_legacy_policy_limit_delta(core):
    """MEASURE gate: source accepts this policy; bounded core refuses it."""
    value = policy()
    value["actors"]["operator-1"]["profile"]["tools"] = ["read"] * 10001
    assert legacy.validate_policy(value) == value
    assert len(legacy.encoded(value)) < legacy.MAX_BYTES
    with pytest.raises(core.LifecycleRefusal) as caught:
        core.validate_policy(value)
    assert caught.value.code == "invalid_policy"
    assert caught.value.field == "schema"


def test_initialize_directory_sync_failure_rolls_back_and_retries(journal, core, monkeypatch):
    reader, box = journal
    path = reader.root.parent / "durable-initialization"
    parent = path.parent.stat()
    def failed(fd):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (parent.st_dev, parent.st_ino):
            raise OSError(errno.EIO, "fixture directory sync failure")
        return os.fsync(fd)
    monkeypatch.setattr(writers_module, "os", SimpleNamespace(fstat=os.fstat, fsync=failed))
    with pytest.raises(core.LifecycleRefusal) as caught:
        writers_module.initialize(path, policy(), mailbox=box)
    assert caught.value.code == "io"
    assert not path.exists()
    monkeypatch.setattr(writers_module, "os", os)
    writers_module.initialize(path, policy(), mailbox=box)
    assert writers_module.Lifecycle(path, mailbox=box).load()[1]["sequence"] == 0


def test_small_change_approval_start_review_parity(core):
    p = policy()
    left, right = legacy.initial_state(p), core.initial_state(p)
    plan = {"schema": legacy.SMALL_CHANGE_PLAN, "request": raw(request()), "plan": {
        "request_sha256": raw(request())["sha256"], "projects": ["alpha"],
        "writing_lanes": [{"lane": "work", "writer": "operator-1"}], "path_scopes": [request()["paths"]],
        "checks": ["unit"], "reviewer": "reviewer-1", "shared_interface_change": False,
        "migration": False, "governance_change": False, "budget_expansion": False, "scope_certain": True}}
    proposal = raw(plan)
    participants = {"writer": {"cid": "operator-1", "generation": 1}, "reviewer": {"cid": "reviewer-1", "generation": 1}}
    def apply(envelope):
        assert legacy.reduce_event(p, left, envelope, NOW) == core.reduce_event(p, right, envelope, NOW)
        assert left == right
        assert legacy.checkpoint(p, left) == core.checkpoint(p, right)
    apply(event("publish", request=raw(request())))
    apply(event("small_change_plan", proposal=proposal, participants=participants, **target()))
    apply(event("small_change_decision", "root-1", plan_sha256=proposal["sha256"], decision="approve", reason="approved", **target()))
    decision_sha = legacy.digest(left["requests"]["work"]["small_change"]["decisions"][-1])
    apply(event("small_change_admit", "operator-1", plan_sha256=proposal["sha256"], decision_sha256=decision_sha,
        source=SOURCE, participants=participants, checks=[{"check": "unit", "recipe": "unit", "recipes_sha256": "f" * 64,
        "evidence": p["authority"]}], gates={name: p["authority"] for name in legacy.GATES | {"reviewer"}}, **target()))
    assert core.small_change_approval(right, right["requests"]["work"]) == legacy.small_change_approval(left, left["requests"]["work"])
    apply(event("intent", "operator-1", intent_id="attempt-1", **target()))
    apply(event("start", "operator-1", intent_id="attempt-1", **target()))
    apply(event("terminal", "operator-1", result=raw({"request_sha256": target()["request_sha256"], "intent_id": "attempt-1",
        "outcome": "passed", "exit_code": 0, "source": SOURCE, "evidence": p["authority"]}), **target()))
    assert core.small_change_review(p, right, right["requests"]["work"], "reviewer-1") is None
    result_sha = left["requests"]["work"]["terminal"]["sha256"]
    apply(event("review", "reviewer-1", result_sha256=result_sha, source=SOURCE, verdict="accept", evidence=p["authority"], **target()))
    apply(event("delivery", evidence=p["authority"], **target()))
    apply(event("disposition", status="FINAL", resolution={"kind": "complete", "evidence": p["authority"]}, **target()))


def test_loaded_transaction_requires_exclusion_and_preserves_state_on_failure(journal, core):
    reader, box = journal
    p, state = reader.load()
    before = copy.deepcopy(state)
    envelope = event("publish", request=raw(request()))
    with pytest.raises(core.LifecycleRefusal):
        reader.record_under_lock(envelope, p, state)
    assert state == before
    with reader.view(write=True) as fds:
        p, state, _ = reader.replay(*fds)
        before = copy.deepcopy(state)
        with pytest.raises(core.LifecycleRefusal):
            reader.record_under_lock(event("unknown"), p, state)
        assert state == before
        receipt = reader.record_under_lock(envelope, p, state)
        assert state["sequence"] == receipt["sequence"] == 1
    assert reader.record(envelope) == receipt


def public_entries():
    """Discover definitions and inherited product methods, never a named example list."""
    for module in (core_module, writers_module):
        for name, value in inspect.getmembers(module):
            if name.startswith("_") or getattr(value, "__module__", None) != module.__name__:
                continue
            if inspect.isfunction(value):
                yield module, None, name, value
            elif inspect.isclass(value):
                yield module, value, name, value
                for method, function in inspect.getmembers(value, inspect.isfunction):
                    if not method.startswith("_") and function.__module__ == module.__name__:
                        yield module, value, method, function


def test_public_exports_resolve_and_cover_definitions():
    for module in (core_module, writers_module):
        exported = module.__all__
        assert len(set(exported)) == len(exported)
        assert all(not name.startswith("_") and hasattr(module, name) for name in exported)
        definitions = {name for owner, cls, name, function in public_entries()
                       if owner is module and (cls is None or function is cls)}
        assert definitions <= set(exported)


def test_schema_labels_remain_valid_actor_and_request_identifiers(core):
    """Identifier-map keys are data, even when they spell schema field names."""
    labels = set(policy()) | set(request()) | set(policy()["actors"]["root-1"]) | set(legacy.initial_state(policy()))
    for label in sorted(labels):
        if legacy.SLUG.fullmatch(label) is None:
            continue
        p = policy()
        p["actors"][label] = p["actors"].pop("root-1")
        p["current"]["root"] = label
        left, right = legacy.initial_state(p), core.initial_state(p)
        assert left == right
        value = {**request(), "id": label, "authority": label}
        envelope = event("publish", request=raw(value))
        envelope["custody"]["cid"] = label
        assert legacy.reduce_event(p, left, envelope, NOW) == core.reduce_event(p, right, envelope, NOW)
        assert core.checkpoint(p, right) == legacy.checkpoint(p, left)


def test_finish_refusal_preserves_state_and_allows_retry(core):
    state = core.initial_state(policy())
    before = copy.deepcopy(state)
    with pytest.raises(core.LifecycleRefusal):
        writers_module.Lifecycle.finish(state, {"sequence": 1})
    assert state == before
    envelope = event("publish", request=raw(request()))
    record = {"sequence": 1, "envelope": envelope, "event_sha256": core.digest(envelope)}
    receipt = writers_module.Lifecycle.finish(state, record)
    assert state["sequence"] == receipt["sequence"] == 1


def test_empty_lane_shape_refuses_and_retry_succeeds(core):
    p = policy()
    state = core.initial_state(p)
    row = core.add_request(state, raw(request()), "coordinator-1")
    participants = {"writer": {"cid": "operator-1", "generation": 1},
                    "reviewer": {"cid": "reviewer-1", "generation": 1}}
    plan = {"writing_lanes": [], "reviewer": "reviewer-1"}
    with pytest.raises(core.LifecycleRefusal):
        core.small_change_participants(p, state, row, plan, participants)
    plan["writing_lanes"] = [{"lane": "work", "writer": "operator-1"}]
    assert core.small_change_participants(p, state, row, plan, participants) is None


def test_missing_reservation_shape_refuses_atomically_then_retries(bootstrap, core):
    runtime, reservations, guard, port, enrollment, box = bootstrap
    enrollment.initialize_reserved_genesis(runtime, reservations, runtime.approved_plan_ref)
    reader = writers_module.Lifecycle(runtime.canonical_root, mailbox=box)
    p, state = reader.load()
    witness, snapshot = reservations[0].witness, reader.initial_bootstrap()
    value = {key: witness[key] for key in ("actor_cid", "role", "generation", "profile_sha256",
        "cap_seconds", "channel_instance_sha256", "approved_plan_sha256")}
    value.update(type="initial_creation", genesis_event_sha256=snapshot["genesis_receipt"]["event_sha256"],
        reservation_set_sha256=core.digest(snapshot["reservations"]), reservation_witness_sha256=core.digest(witness))
    envelope = {"schema": core.INITIAL_ENVELOPE, "id": core.initial_key(p, witness["actor_cid"]), "event": value}
    retained = state["initial_bootstrap"]["reservations"]
    state["initial_bootstrap"]["reservations"] = []
    before = copy.deepcopy(state)
    with pytest.raises(core.LifecycleRefusal):
        core.reduce_event(p, state, envelope, NOW)
    assert state == before
    state["initial_bootstrap"]["reservations"] = retained
    assert core.reduce_event(p, state, envelope, NOW) is None


def test_decoded_terminal_outcome_types_refuse_atomically_and_retry(core):
    p, state = policy(), core.initial_state(policy())
    prefix = [event("publish", request=raw(request())),
        event("decision", "root-1", decision="approve", reason="approved", **target()),
        event("admit", "operator-1", source=SOURCE, gates={gate: p["authority"] for gate in legacy.GATES}, **target()),
        event("intent", "operator-1", intent_id="attempt-1", **target()),
        event("start", "operator-1", intent_id="attempt-1", **target())]
    for envelope in prefix:
        core.reduce_event(p, state, envelope, NOW)
    result = {"request_sha256": target()["request_sha256"], "intent_id": "attempt-1", "outcome": "passed",
              "exit_code": 0, "source": SOURCE, "evidence": p["authority"]}
    for outcome in ([], {}, None, 0, False):
        before = copy.deepcopy(state)
        with pytest.raises(core.LifecycleRefusal) as caught:
            core.reduce_event(p, state, event("terminal", "operator-1", result=raw({**result, "outcome": outcome}), **target()), NOW)
        assert caught.value.code == "invalid_record"
        assert state == before
    core.reduce_event(p, state, event("terminal", "operator-1", result=raw(result), **target()), NOW)
    assert state["requests"]["work"]["terminal"]["value"]["outcome"] == "passed"


def policy_wrong_shapes(value):
    """Mutate every populated JSON position to an incompatible JSON shape."""
    yield object()
    if isinstance(value, (dict, list)):
        yield None
        yield [] if isinstance(value, dict) else {}
        for key in value if isinstance(value, dict) else range(len(value)):
            item = value[key]
            replacements = ({}, []) if not isinstance(item, (dict, list)) else (None,)
            for replacement in replacements:
                changed = copy.deepcopy(value)
                changed[key] = replacement
                yield changed
            if isinstance(item, (dict, list)):
                for replacement in policy_wrong_shapes(item):
                    changed = copy.deepcopy(value)
                    changed[key] = replacement
                    yield changed


@pytest.fixture
def pytest_request(request):
    return request


@pytest.mark.parametrize("entry", list(public_entries()),
                         ids=lambda entry: entry[0].__name__ + "." +
                         ((entry[1].__name__ + ".") if entry[1] is not None else "") + entry[2])
def test_generated_public_wrong_types(entry, pytest_request, tmp_path):
    module, cls, name, function = entry
    p = policy()
    successor = copy.deepcopy(p["actors"]["root-1"])
    successor["generation"] = 2
    p["actors"]["root-2"], p["successors"]["root-1"] = successor, "root-2"
    state = core_module.initial_state(p)
    row = core_module.add_request(state, raw(request_value := request()), "coordinator-1")
    envelope = event("publish", request=raw(request_value))
    seeds = dict(policy=p, state=state, row=row, value=p if name == "validate_policy" else raw(request_value),
        raw=raw(request_value), envelope=envelope, event=envelope["event"], mark={"actor": "operator-1", "generation": 1, "at": NOW},
        cid="operator-1", publisher="coordinator-1", at=NOW, name="schema", role="operator", expected="operator-1",
        condition=True, message="", function=lambda: None, scope=request_value["paths"], path=request_value["paths"][0],
        binding={"cid": "operator-1", "generation": 1}, participants={"writer": {"cid": "operator-1", "generation": 1},
        "reviewer": {"cid": "reviewer-1", "generation": 1}}, resolution={"kind": "blocked", "evidence": p["authority"],
        "owner": "coordinator", "next_decision": "review", "condition": "blocked"}, code="ROOT_ALREADY_EXISTS" if cls is writers_module.CanonicalGenesisError else "invalid_record")
    signature = inspect.signature(function)
    if not signature.parameters:
        assert isinstance(function(), core_module.LifecycleRefusal)
        return
    values = {parameter: seeds.get(parameter, spec.default if spec.default is not inspect.Parameter.empty else None)
              for parameter, spec in signature.parameters.items()}
    if "self" in values:
        if cls is writers_module.Lifecycle:
            values["self"] = pytest_request.getfixturevalue("journal")[0]
        elif issubclass(cls, core_module.LifecycleRefusal):
            values["self"] = cls(seeds["code"])
        else:
            values["self"] = cls((tmp_path / "unqualified").as_posix())
    if "mailbox" in values or "store" in values:
        reader, box = pytest_request.getfixturevalue("journal")
        values.update({key: value for key, value in dict(mailbox=box, store=box.store,
                      root=reader.root, path=reader.root / "policy.json").items() if key in values})
    # Host objects are owner-injected capabilities; the native method's public
    # data/refusal boundary is tested with its absent-port context.
    opaque = {"authority", "host_authority", "clock"}
    for parameter in signature.parameters:
        if parameter in opaque:
            continue
        variants = list(policy_wrong_shapes(values[parameter])) if name == "validate_policy" else [object()]
        if not (name in {"encoded", "digest"} and parameter == "value"):
            for malformed in (None, [], {}, 0, False, "untrusted-input"):
                if type(malformed) is type(values[parameter]):
                    continue
                if malformed is None and signature.parameters[parameter].default is None:
                    continue
                if parameter in {"root", "path"} and isinstance(malformed, str):
                    continue
                variants.append(malformed)
        for malformed in variants:
            supplied = copy.copy(values)
            supplied[parameter] = malformed
            try:
                answer = function(**supplied)
                if hasattr(answer, "__enter__"):
                    with answer:
                        answer = None
            except (core_module.LifecycleRefusal, MailboxRefusal) as error:
                answer = error.as_dict()
            if isinstance(answer, core_module.LifecycleRefusal):
                answer = answer.as_dict()
            assert isinstance(answer, dict), (name, parameter)
            assert answer.get("state", answer.get("status")) in {"refused", "unknown"}, (name, parameter)
            assert answer.get("code") and answer.get("reason") and answer.get("next_action"), (name, parameter)
            json.dumps(answer, sort_keys=True)


def tree_nodes(value):
    if isinstance(value, dict):
        return 1 + sum(1 + tree_nodes(child) for child in value.values())
    if isinstance(value, list):
        return 1 + sum(map(tree_nodes, value))
    return 1


def capacity_envelopes(state, budget):
    """Generate actual node-limit crossings, including receipt-only growth."""
    for index, width in itertools.product(range(20), (255,)):
        value = {**request(), "id": "request-%d" % index, "authority": "request-%d" % index,
                 "paths": request()["paths"] * 256,
                 "prerequisites": ["prior-%d" % item for item in range(256)]}
        value["continuation"] = {**value["continuation"], "members": [
            {"id": "member-%d" % item, "sha256": "a" * 64, "phase": "validation", "operation": "tests"}
            for item in range(width)]}
        envelope = event("publish", identifier="insert-%d" % index, request=raw(value))
        projected = copy.deepcopy(state)
        legacy.reduce_event(policy(), projected, envelope, NOW)
        if budget == "receipts" and tree_nodes(projected) > 32768:
            value["paths"], value["prerequisites"] = request()["paths"], []
            value["continuation"]["members"] = []
            base = copy.deepcopy(state)
            legacy.reduce_event(policy(), base, event("publish", request=raw(value)), NOW)
            members, extras = divmod(32765 - tree_nodes(base), 9)
            assert 0 <= members <= 255 and 0 <= extras <= 256
            value["prerequisites"] = ["prior-%d" % item for item in range(extras)]
            value["continuation"]["members"] = [
                {"id": "member-%d" % item, "sha256": "a" * 64, "phase": "validation", "operation": "tests"}
                for item in range(members)]
            envelope["event"]["request"] = raw(value)
            projected = copy.deepcopy(state)
            legacy.reduce_event(policy(), projected, envelope, NOW)
            assert tree_nodes(projected) == 32765
        yield envelope


@pytest.mark.parametrize("budget", list(itertools.chain(("nodes", "receipts"), ("genesis",))))
def test_generated_state_sequences(decision, core, monkeypatch, budget, pytest_request):
    if budget == "genesis":
        runtime, reservations, guard, port, enrollment, box = pytest_request.getfixturevalue("bootstrap")
        original = copy.deepcopy(runtime.accepted_plan)
        witnesses = [copy.deepcopy(reservation.witness) for reservation in reservations]
        p = {"schema": core.POLICY, "authority": [runtime.approved_plan_ref], **runtime.accepted_plan}
        remaining = 32700 - tree_nodes(p)
        for actor in p["actors"].values():
            count = min(10000 - len(actor["profile"]["tools"]), remaining)
            actor["profile"]["tools"].extend(["read"] * count)
            remaining -= count
        assert remaining == 0 and core.validate_policy(p) == p
        for reservation in reservations:
            reservation.witness["profile_sha256"] = core.digest(p["actors"][reservation.actor_cid]["profile"])
        with pytest.raises(writers_module.CanonicalGenesisError) as caught:
            enrollment.initialize_reserved_genesis(runtime, reservations, runtime.approved_plan_ref)
        assert caught.value.code == "POLICY_INVALID" and not runtime.canonical_root.exists()
        runtime.accepted_plan = original
        for reservation, witness in zip(reservations, witnesses):
            reservation.witness = witness
        enrollment.initialize_reserved_genesis(runtime, reservations, runtime.approved_plan_ref)
        assert writers_module.Lifecycle(runtime.canonical_root, mailbox=box).load()[1]["sequence"] == 1
        return
    reader, writer, invocation, command, hooks = decision
    assert writer.commit_decision(invocation, command)["state"] == "recorded"
    with reader.view(write=True) as fds:
        p, state, _ = reader.replay(*fds)
        saved = copy.deepcopy(state)
        original_publish = store_module.Store.publish
        def failed_publication(self, *args, **kwargs):
            raise OSError(errno.EIO, "fixture publication failure")
        monkeypatch.setattr(store_module.Store, "publish", failed_publication)
        try:
            with pytest.raises(core.LifecycleRefusal) as caught:
                reader.record_under_lock(event("read", "router-1", identifier="io-retry", **target()), p, state)
        finally:
            monkeypatch.setattr(store_module.Store, "publish", original_publish)
        assert caught.value.code == "io" and state == saved
        assert store_module.Store.publish is original_publish
        reader.record_under_lock(event("read", "router-1", identifier="io-retry", **target()), p, state)
        for envelope in (event("admit", "operator-1", source=SOURCE,
                              gates={gate: p["authority"] for gate in legacy.GATES}, **target()),
                         event("intent", "operator-1", intent_id="attempt", **target()),
                         event("start", "operator-1", intent_id="attempt", **target()),
                         event("terminal", "operator-1", result=raw({"request_sha256": target()["request_sha256"],
                               "intent_id": "attempt", "outcome": "passed", "exit_code": 0,
                               "source": SOURCE, "evidence": p["authority"]}), **target())):
            receipt = reader.record_under_lock(envelope, p, state)
            assert state["sequence"] == receipt["sequence"]
        expected = copy.deepcopy(state)
        foreign = event("meter", "operator-1", identifier="foreign", subject="operator-1", active_seconds=0, open_since=None)
        record = {"schema": core.JOURNAL, "sequence": state["sequence"] + 1, "previous": state["head"],
                  "policy_sha256": core.digest(p), "at": NOW, "envelope": foreign, "event_sha256": core.digest(foreign)}
        path = reader.root / "events" / ("%06d.json" % record["sequence"])
        path.write_bytes(core.encoded(record) + b"\n")
        with pytest.raises(core.LifecycleRefusal) as caught:
            reader.record_under_lock(event("read", "router-1", identifier="retry", **target()), p, state)
        assert caught.value.code == "target_changed" and state == expected
    assert writers_module.Lifecycle(reader.root, mailbox=writer.mailbox).load()[1]["sequence"] == record["sequence"]
    reader.record(event("read", "router-1", identifier="retry", **target()))
    with reader.view(write=True) as fds:
        p, state, _ = reader.replay(*fds)
        values = capacity_envelopes(state, budget)
        refused = False
        for envelope in values:
            before = {path.name: path.read_bytes() for path in (reader.root / "events").iterdir()}
            saved = copy.deepcopy(state)
            try:
                reader.record_under_lock(envelope, p, state)
            except core.LifecycleRefusal as error:
                assert error.code == "too_large"
                assert state == saved
                assert {path.name: path.read_bytes() for path in (reader.root / "events").iterdir()} == before
                refused = True
                break
        assert refused, "generated sequence never crossed the retained budget"
        reader.record_under_lock(event("meter", "operator-1", identifier="valid-retry", subject="operator-1", active_seconds=0, open_since=None), p, state)
        expected = copy.deepcopy(state)
    assert writers_module.Lifecycle(reader.root, mailbox=writer.mailbox).load() == (p, expected)


@pytest.mark.parametrize("suffix", ["a\\b", "space name", "part/" * 129 + "leaf"])
def test_inert_path_references_keep_legacy_characters_with_bounds(core, tmp_path, suffix):
    if os.name == "nt":
        pytest.skip("POSIX inert-path spelling parity")
    path = (tmp_path / suffix).as_posix()
    p, value = policy(), request()
    p["authority"][0]["path"], value["paths"] = path, [path]
    assert legacy.validate_policy(p) == p
    assert legacy.validate_request(raw(value)) == value
    proposal = {"schema": legacy.SMALL_CHANGE_PLAN, "request": raw(value), "plan": {
        "request_sha256": raw(value)["sha256"], "projects": ["alpha"],
        "writing_lanes": [{"lane": "work", "writer": "operator-1"}], "path_scopes": [[path]],
        "checks": ["unit"], "reviewer": "reviewer-1", "shared_interface_change": False,
        "migration": False, "governance_change": False, "budget_expansion": False, "scope_certain": True}}
    expected = legacy.inspect_request(proposal)
    if suffix.startswith("part/"):
        # ROUND-1g retains resource bounds while restoring inert characters.
        for function, argument, code in ((core_module.validate_policy, p, "invalid_policy"),
                                         (core_module.validate_request, raw(value), "unsafe_path"),
                                         (core_module.inspect_request, proposal, "unsafe_path")):
            with pytest.raises(core.LifecycleRefusal) as caught:
                function(argument)
            assert caught.value.code == code
            assert path not in json.dumps(caught.value.as_dict())
        for cls in (writers_module.ProtectedCanonicalEnrollmentWriter, writers_module.ProtectedCanonicalBootstrapWriter,
                    writers_module.ProtectedCanonicalDecisionWriter):
            with pytest.raises(core.LifecycleRefusal) as caught:
                cls(path)
            assert caught.value.code == "unsafe_path"
            assert cls(tmp_path / "bounded-retry").root == tmp_path / "bounded-retry"
        return
    assert core.validate_policy(p) == p
    assert core.validate_request(raw(value)) == value
    assert core.inspect_request(proposal) == expected
    for cls in (writers_module.ProtectedCanonicalEnrollmentWriter, writers_module.ProtectedCanonicalBootstrapWriter,
                writers_module.ProtectedCanonicalDecisionWriter):
        assert cls(path).root == Path(path)


def test_inert_root_character_rules_apply_only_when_opened(journal, core):
    reader, box = journal
    if os.name == "nt":
        pytest.skip("POSIX inert-path spelling parity")
    root = reader.root.parent / "a\\b"
    assert legacy.Lifecycle(root).root == root
    inert = writers_module.Lifecycle(root, mailbox=box)
    assert inert.root == root
    with pytest.raises(core.LifecycleRefusal) as caught:
        inert.load()
    assert caught.value.code == "unsafe_path"
    with pytest.raises(core.LifecycleRefusal) as caught:
        writers_module.initialize(root, policy(), mailbox=box)
    assert caught.value.code == "unsafe_path" and not root.exists()
    retry = root.parent / "bounded-root-retry"
    writers_module.initialize(retry, policy(), mailbox=box)
    assert writers_module.Lifecycle(retry, mailbox=box).load()[1]["sequence"] == 0


def test_long_bounded_history_replays_and_publishes_like_legacy(journal, core, monkeypatch):
    reader, box = journal
    monkeypatch.setattr(legacy, "timestamp", lambda: NOW)
    old_root = reader.root.parent / "legacy-long-history"
    legacy.initialize(old_root, policy())
    old = legacy.Lifecycle(old_root)
    p, state = old.load()
    value = raw(request())
    assert core.validate_request(value) == legacy.validate_request(value)
    total = (old_root / "policy.json").stat().st_size
    former_limit = 64 * 1024 * 1024
    # Build bounded fixtures in one pass; public readers/writers below exercise
    # the real journal without quadratic fixture publication/replay work.
    for sequence in range(1, core.MAX_EVENTS):
        envelope = event("publish", identifier="history-%06d" % sequence, request=value)
        record = {"schema": core.JOURNAL, "sequence": sequence, "previous": state["head"],
                  "policy_sha256": legacy.digest(p), "at": NOW, "envelope": envelope,
                  "event_sha256": legacy.digest(envelope)}
        body = legacy.encoded(record) + b"\n"
        if total + len(body) > former_limit:
            break
        # JSON whitespace belongs to the wire record, not the resulting state.
        # Leave less than one canonical record before the old cap, so the next
        # ordinary append (without padding) must cross it.
        padding = min(800000, max(0, former_limit - total - len(body) - 100))
        body = body[:-1] + b" " * padding + b"\n"
        assert len(body) <= core.MAX_BYTES
        legacy.reduce_event(p, state, envelope, NOW)
        legacy.Lifecycle.finish(state, record)
        for root in (old_root, reader.root):
            (root / "events" / ("%06d.json" % sequence)).write_bytes(body)
        total += len(body)
    else:
        pytest.fail("bounded history did not reach the former cumulative limit")
    assert len(state["requests"]) == 1
    core.bounded_tree(state, limit=67108864, ascii_strings=True)
    with reader.view(write=True) as fds:
        loaded_policy, loaded_state, _ = reader.replay(*fds)
        assert (loaded_policy, loaded_state) == old.load() == (p, state)
        assert reader.record_under_lock(envelope, loaded_policy, loaded_state) == old.record(envelope)
    assert total + len(body) > former_limit
    restarted = writers_module.Lifecycle(reader.root, mailbox=box, clock=lambda: NOW)
    with restarted.view(write=True) as fds:
        p, state, _ = restarted.replay(*fds)
        assert (p, state) == old.load()
        # A malformed record still refuses atomically after the old cap.
        before = copy.deepcopy(state)
        with pytest.raises(core.LifecycleRefusal) as caught:
            restarted.record_under_lock(event("unknown", identifier="invalid-after-long-history"), p, state)
        assert caught.value.code == "invalid_record" and state == before
        assert not (reader.root / "events" / ("%06d.json" % (state["sequence"] + 1))).exists()
        retry = event("meter", "operator-1", identifier="retry-after-long-history",
                      subject="operator-1", active_seconds=0, open_since=None)
        assert restarted.record_under_lock(retry, p, state) == old.record(retry)
        assert (p, state) == old.load()


def test_replay_retains_only_bounded_state_and_history_fingerprints():
    """Structural memory check: no retained record bodies or aggregate cap."""
    tree = ast.parse(inspect.getsource(writers_module))
    lifecycle = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Lifecycle")
    replay = next(node for node in lifecycle.body if isinstance(node, ast.FunctionDef) and node.name == "replay")
    loop = next(node for node in replay.body if isinstance(node, ast.For))
    reads = [node for node in ast.walk(loop) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == "read"]
    assert len(reads) == 1
    limit = next(keyword.value for keyword in reads[0].keywords if keyword.arg == "limit")
    assert ast.dump(limit) == ast.dump(ast.parse("domain.MAX_BYTES", mode="eval").body)
    mutations = [node for node in ast.walk(loop) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr in {"append", "extend", "update"}]
    assert len(mutations) == 1
    assert ast.dump(mutations[0]) == ast.dump(ast.parse("snapshot.append((path.name, hashlib.sha256(raw).hexdigest()))", mode="eval").body)
    retained = [node.targets[0].attr for node in ast.walk(replay) if isinstance(node, ast.Assign)
                and len(node.targets) == 1 and isinstance(node.targets[0], ast.Attribute)]
    assert retained == ["snapshot"]
    assert not {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} & {"_MAX_HISTORY_BYTES", "retained_bytes", "remaining"}


class LifecyclePathLike(os.PathLike):
    def __init__(self, value):
        self.value = value

    def __fspath__(self):
        return self.value


def lifecycle_path_input(kind, spelling):
    if kind in {"str", "Path", "PurePosixPath", "bytes"}:
        return {"str": spelling, "Path": Path(spelling), "PurePosixPath": PurePosixPath(spelling),
                "bytes": os.fsencode(spelling)}[kind]
    binding, result = kind.split("-")
    value = {"str": spelling, "bytes": os.fsencode(spelling), "list": [], "none": None, "int": 1}[result]

    class StaticPathLike(os.PathLike):
        @staticmethod
        def __fspath__():
            return value

    class ClassPathLike(os.PathLike):
        @classmethod
        def __fspath__(cls):
            return value

    return {"pathlike": LifecyclePathLike(value), "static": StaticPathLike(), "class": ClassPathLike()}[binding]


PATHLIKE_KINDS = ("str", "Path", "PurePosixPath", "bytes", *(
    binding + "-" + result for binding, result in itertools.product(
        ("pathlike", "static", "class"), ("str", "bytes", "list", "none", "int"))))


def valid_pathlike_kind(kind):
    return kind in {"str", "Path", "PurePosixPath"} or kind.endswith("-str")


@pytest.mark.parametrize("kind,entry", itertools.product(
    PATHLIKE_KINDS,
    ("safe_path", "covered", *(name for module, cls, name, function in public_entries()
                    if module is writers_module and function is cls and "root" in inspect.signature(function).parameters))))
def test_generated_pathlike_inputs(core, tmp_path, kind, entry, pytest_request):
    spelling = (tmp_path / "pathlike-root").as_posix()
    value = lifecycle_path_input(kind, spelling)
    old = getattr(legacy, entry)
    new = getattr(core_module, entry) if entry in {"safe_path", "covered"} else getattr(writers_module, entry)
    old_options = {"authority": None} if "authority" in inspect.signature(old).parameters else {}
    new_options = {"mailbox": pytest_request.getfixturevalue("journal")[1]} if entry == "Lifecycle" else {}
    if entry == "covered":
        for left, right in (([value], spelling), ([spelling], value)):
            if valid_pathlike_kind(kind):
                assert new(left, right) is old(left, right)
            else:
                with pytest.raises(TypeError):
                    old(left, right)
                with pytest.raises(core.LifecycleRefusal) as caught:
                    new(left, right)
                assert caught.value.code == "invalid_record"
                assert spelling not in json.dumps(caught.value.as_dict())
                assert new([spelling], spelling) is True
        return
    if valid_pathlike_kind(kind):
        left, right = old(value, **old_options), new(value, **new_options)
        assert (left if entry == "safe_path" else left.root) == (right if entry == "safe_path" else right.root) == Path(spelling)
    else:
        with pytest.raises(TypeError):
            old(value, **old_options)
        with pytest.raises(core.LifecycleRefusal) as caught:
            new(value, **new_options)
        assert caught.value.code == "invalid_record"
        assert spelling not in json.dumps(caught.value.as_dict())
        retried = new(spelling, **new_options)
        assert (retried if entry == "safe_path" else retried.root) == Path(spelling)
    assert not Path(spelling).exists()


@pytest.mark.parametrize("kind,entry", itertools.product(
    PATHLIKE_KINDS,
    ("initialize", "load_json")))
def test_generated_opened_pathlike_inputs(journal, core, kind, entry):
    reader, box = journal
    if entry == "initialize":
        old_path, new_path = (reader.root.parent / name for name in ("legacy-pathlike", "core-pathlike"))
        old_args, new_args, options = (policy(),), (policy(),), {"mailbox": box}
    else:
        old_path = new_path = reader.root / "policy.json"
        old_args, new_args, options = (), (), {"store": box.store}
    old_value = lifecycle_path_input(kind, old_path.as_posix())
    new_value = lifecycle_path_input(kind, new_path.as_posix())
    new = getattr(writers_module, entry)
    def old(value):
        # The pinned initializer receives Path from its CLI/callers, whereas
        # pinned load_json and constructors perform their own Path conversion.
        return getattr(legacy, entry)(Path(value) if entry == "initialize" else value, *old_args)
    if valid_pathlike_kind(kind):
        assert new(new_value, *new_args, **options) == old(old_value)
    else:
        with pytest.raises(TypeError):
            old(old_value)
        with pytest.raises(core.LifecycleRefusal) as caught:
            new(new_value, *new_args, **options)
        assert caught.value.code == "invalid_record"
        assert str(new_path) not in json.dumps(caught.value.as_dict())
        if entry == "initialize":
            assert not new_path.exists() and not old_path.exists()
        assert new(str(new_path), *new_args, **options) == old(str(old_path))
    if entry == "initialize":
        assert writers_module.Lifecycle(new_path, mailbox=box).load() == legacy.Lifecycle(old_path).load()


def lifecycle_path_call(entry, value, reader, box):
    if entry == "safe_path":
        return core_module.safe_path(value)
    if entry == "covered_target":
        return core_module.covered([reader.root.as_posix()], value)
    if entry == "covered_scope":
        return core_module.covered([value], reader.root.as_posix())
    if entry == "load_json":
        return writers_module.load_json(value, store=box.store)
    if entry == "initialize":
        return writers_module.initialize(value, policy(), mailbox=box)
    return getattr(writers_module, entry)(value, mailbox=box)


@pytest.mark.parametrize("entry,kind,shape", itertools.product(
    ("safe_path", "covered_target", "covered_scope", "initialize", "load_json", *(
        name for module, cls, name, function in public_entries()
        if module is writers_module and function is cls and "root" in inspect.signature(function).parameters)),
    ("str", "pathlike-str", "static-str", "class-str"), ("components", "byte_length")))
def test_generated_deep_paths_refuse_before_ancestor_or_io(journal, core, monkeypatch, entry, kind, shape):
    reader, box = journal
    spelling = "/" + ("a/" * 50000 if shape == "components" else "a" * 32768)
    value = lifecycle_path_input(kind, spelling)
    observed = {"allow": False, "parents": 0, "io": 0}

    class ObservedPath(type(reader.root)):
        @property
        def parents(self):
            observed["parents"] += 1
            assert observed["allow"], "ancestor expansion preceded lexical bounds"
            return super().parents

        def is_symlink(self):
            observed["io"] += 1
            assert observed["allow"], "filesystem access preceded lexical bounds"
            return super().is_symlink()

    monkeypatch.setattr(core_module, "Path", ObservedPath)
    with pytest.raises(core.LifecycleRefusal) as caught:
        lifecycle_path_call(entry, value, reader, box)
    assert caught.value.code == "unsafe_path"
    assert observed["parents"] == observed["io"] == 0
    assert spelling not in json.dumps(caught.value.as_dict())
    assert not list((reader.root / "events").iterdir())

    def refuse_again(_):
        with pytest.raises(core.LifecycleRefusal) as error:
            lifecycle_path_call(entry, lifecycle_path_input(kind, spelling), reader, box)
        return error.value.code

    with box.store.evidence_transaction():
        with ThreadPoolExecutor(max_workers=3) as pool:
            assert list(pool.map(refuse_again, range(3))) == ["unsafe_path"] * 3
    assert observed["parents"] == observed["io"] == 0
    observed["allow"] = True
    retry = reader.root / "policy.json" if entry == "load_json" else reader.root.parent / "bounded-retry"
    result = lifecycle_path_call(entry, lifecycle_path_input(kind, retry.as_posix()), reader, box)
    if entry == "load_json":
        assert result == policy()
    elif entry == "initialize":
        assert writers_module.Lifecycle(retry, mailbox=box).load()[1]["sequence"] == 0
    elif entry.startswith("covered_"):
        assert result is False
    else:
        assert (result if entry == "safe_path" else result.root) == retry


def test_generated_pathlike_conversions_are_isolated_across_threads(journal, core):
    reader, box = journal
    entries = ("safe_path", "covered_target", "covered_scope", "load_json", *(
        name for module, cls, name, function in public_entries()
        if module is writers_module and function is cls and "root" in inspect.signature(function).parameters))
    cases = list(enumerate(itertools.product(("pathlike-str", "static-str", "class-str"), entries)))

    def convert(case):
        index, (kind, entry) = case
        path = reader.root / "policy.json" if entry == "load_json" else reader.root.parent / ("parallel-%d" % index)
        with pytest.raises(core.LifecycleRefusal) as caught:
            lifecycle_path_call(entry, lifecycle_path_input(kind.replace("-str", "-bytes"), path.as_posix()), reader, box)
        assert caught.value.code == "invalid_record"
        result = lifecycle_path_call(entry, lifecycle_path_input(kind, path.as_posix()), reader, box)
        if entry == "load_json":
            assert result == policy()
        elif entry.startswith("covered_"):
            assert result is False
        else:
            assert (result if entry == "safe_path" else result.root) == path
        return index

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(convert, cases)) == list(range(len(cases)))
    assert reader.load()[1]["sequence"] == 0


def round1g_input(kind, reference):
    base = reference.as_posix()

    class Misleading(str):
        def __str__(self):
            return base

    if kind == "backslash":
        return reference.parent.as_posix() + "/a\\b"
    if kind in {"str", "Path", "PurePosixPath", "pathlike-str", "static-str", "class-str"}:
        return lifecycle_path_input(kind, base)
    if kind in {"surrogate", "surrogate_path", "surrogate_windows"}:
        value = reference.parent.as_posix() + "/\udcffchild"
        return {"surrogate": value, "surrogate_path": Path(value), "surrogate_windows": PureWindowsPath(value)}[kind]
    if kind in {"absolute_reset", "windows_absolute_reset"}:
        cls = PurePosixPath if kind == "absolute_reset" else PureWindowsPath
        return cls("a" * 20000, "b" * 20000, base)
    if kind == "misleading_deep":
        return Misleading("/" + "a/" * 50000)
    if kind in {"pure_deep", "windows_deep"}:
        cls = PurePosixPath if kind == "pure_deep" else PureWindowsPath
        return cls("/" + "a/" * 50000, base)
    if kind == "windows_bounded":
        return PureWindowsPath(base)
    if "bytes" in kind:
        prefix = reference.parent.as_posix() + "/"
        remaining = 32768 - len(prefix.encode("utf-8"))
        tail = "z" * remaining if kind.startswith("ascii") else "é" * (remaining // 2) + "z" * (remaining % 2)
        return prefix + tail + ("x" if kind.endswith("over") else "")
    count = 128 - len(reference.parts) + int(kind.endswith("over"))
    value = reference.joinpath(*(["a"] * count))
    return PurePosixPath(value) if kind.startswith("pure_") else value.as_posix()


def round1g_call(entry, value, reader, box, *, old=False):
    wire = str.__str__(os.fspath(value))
    if entry in {"evidence", "validate_policy", "validate_request", "plan_paths", "replay"}:
        p, requested = policy(), request()
        if entry == "evidence":
            return legacy.evidence([{"path": wire, "sha256": "d" * 64}]) if old else core_module.evidence([{"path": wire, "sha256": "d" * 64}])
        if entry == "validate_policy":
            p["authority"][0]["path"] = wire
            return legacy.validate_policy(p) if old else core_module.validate_policy(p)
        if entry in {"validate_request", "replay"}:
            requested["paths"] = [wire]
        if entry == "validate_request":
            return legacy.validate_request(raw(requested)) if old else core_module.validate_request(raw(requested))
        if entry == "plan_paths":
            proposal = {"schema": legacy.SMALL_CHANGE_PLAN, "request": raw(requested), "plan": {
                "request_sha256": raw(requested)["sha256"], "projects": ["alpha"],
                "writing_lanes": [{"lane": "work", "writer": "operator-1"}], "path_scopes": [[wire]],
                "checks": ["unit"], "reviewer": "reviewer-1", "shared_interface_change": False,
                "migration": False, "governance_change": False, "budget_expansion": False, "scope_certain": True}}
            return legacy.inspect_request(proposal) if old else core_module.inspect_request(proposal)
        envelope = event("publish", request=raw(requested))
        record = {"schema": legacy.JOURNAL, "sequence": 1, "previous": "0" * 64,
                  "policy_sha256": legacy.digest(p), "at": NOW, "envelope": envelope,
                  "event_sha256": legacy.digest(envelope)}
        (reader.root / "events" / "000001.json").write_bytes(legacy.encoded(record) + b"\n")
        return legacy.Lifecycle(reader.root).load() if old else reader.load()
    if entry.startswith("covered_"):
        scope, target = ([reader.root.as_posix()], value) if entry == "covered_target" else ([value], reader.root.as_posix())
        return legacy.covered(scope, target) if old else core_module.covered(scope, target)
    if entry == "safe_path":
        return legacy.safe_path(value) if old else core_module.safe_path(value)
    if entry == "load_json":
        return legacy.load_json(value) if old else writers_module.load_json(value, store=box.store)
    if entry == "initialize":
        return legacy.initialize(Path(value), policy()) if old else writers_module.initialize(value, policy(), mailbox=box)
    cls = getattr(legacy, entry) if old else getattr(writers_module, entry)
    options = {"authority": None} if "authority" in inspect.signature(cls).parameters else {}
    if not old:
        options["mailbox"] = box
    return cls(value, **options).root


def round1g_over(value, *, posix=False):
    parsed = PurePosixPath(value) if posix else Path(value)
    return len(str(parsed).encode("utf-8", "surrogatepass")) > 32768 or len(parsed.parts) > 128


def round1g_observer(reader, observed):
    class ObservedPath(type(reader.root)):
        @property
        def parents(self):
            if round1g_over(self):
                observed["bad_walk"] += 1
                raise AssertionError("unbounded ancestor walk")
            return super().parents

        def is_symlink(self):
            if round1g_over(self):
                observed["bad_io"] += 1
                raise AssertionError("unbounded filesystem observation")
            observed["io"] += 1
            return False
    return ObservedPath


ROUND1G_ENTRIES = ("safe_path", "evidence", "validate_policy", "validate_request", "plan_paths",
                   "covered_target", "covered_scope", "load_json", "initialize", "replay", *(
    name for module, cls, name, function in public_entries()
    if module is writers_module and function is cls and "root" in inspect.signature(function).parameters))


@pytest.mark.parametrize("entry,kind", itertools.product(ROUND1G_ENTRIES, (
    "backslash", "misleading_deep", "pure_deep", "windows_deep", "windows_bounded",
    "ascii_bytes_at", "ascii_bytes_over", "unicode_bytes_at", "unicode_bytes_over",
    "components_at", "components_over", "pure_components_at", "pure_components_over",
    "str", "Path", "PurePosixPath", "pathlike-str", "static-str", "class-str",
    "surrogate", "surrogate_path", "surrogate_windows", "absolute_reset", "windows_absolute_reset")))
def test_generated_round1g_consumers_and_representations(journal, core, monkeypatch, entry, kind):
    reader, box = journal
    reference = reader.root / "policy.json" if entry == "load_json" else reader.root.parent / "round1g-target"
    value = round1g_input(kind, reference)
    observed = {"bad_walk": 0, "bad_io": 0, "io": 0}
    probe = round1g_observer(reader, observed)
    monkeypatch.setattr(core_module, "Path", probe)
    is_wire = entry in {"evidence", "validate_policy", "validate_request", "plan_paths", "replay"}
    candidate = str.__str__(os.fspath(value)) if is_wire else value
    parsed = None if round1g_over(candidate, posix=entry.startswith("covered_")) else (
        PurePosixPath(candidate) if entry.startswith("covered_") else Path(candidate))
    code = "unsafe_path" if parsed is None else None
    if is_wire and (len(candidate) > 4096 or any(0xD800 <= ord(c) <= 0xDFFF for c in candidate)):
        code = "invalid_record"
    elif parsed is not None and not entry.startswith("covered_") and not parsed.is_absolute():
        code = "invalid_record"
    if entry == "validate_policy" and code:
        code = "invalid_policy"
    if entry in {"load_json", "initialize"} and code is None:
        if kind == "backslash" or "bytes" in kind or kind.startswith("surrogate"):
            code = "unsafe_path"
        elif "components" in kind:
            code = "unsafe_path" if entry == "load_json" else "missing"
    if code:
        with pytest.raises(core.LifecycleRefusal) as caught:
            round1g_call(entry, value, reader, box)
        assert caught.value.code == code
        assert not any(observed[key] for key in ("bad_walk", "bad_io"))
        assert "a/" * 50000 not in json.dumps(caught.value.as_dict())
        if entry not in {"initialize", "replay"}:
            def refuse_again(_):
                with pytest.raises(core.LifecycleRefusal) as error:
                    round1g_call(entry, value, reader, box)
                return error.value.code
            with box.store.evidence_transaction():
                with ThreadPoolExecutor(max_workers=3) as pool:
                    assert list(pool.map(refuse_again, range(3))) == [code] * 3
            assert not any(observed[key] for key in ("bad_walk", "bad_io"))
    else:
        answer = round1g_call(entry, value, reader, box)
        if "bytes_at" in kind and entry not in {"covered_target", "covered_scope"}:
            # These lexical boundary values exceed kernel filename limits.
            # The module-owned observation seam isolates the converter gate.
            expected = Path(value)
        elif entry == "initialize":
            expected = {"policy_sha256": legacy.digest(policy()), "execution_enabled": False, "native_enforcement": "unqualified"}
        else:
            expected = round1g_call(entry, value, reader, box, old=True)
        assert answer == expected
    if entry == "replay":
        saved = (reader.root / "events" / "000001.json").read_bytes()
        if code:
            with pytest.raises(core.LifecycleRefusal):
                reader.load()
        assert (reader.root / "events" / "000001.json").read_bytes() == saved
        assert round1g_call(entry, reference.as_posix(), reader, box)[1]["sequence"] == 1
    elif code:
        retry = reader.root / "policy.json" if entry == "load_json" else reader.root.parent / "round1g-retry"
        round1g_call(entry, retry.as_posix(), reader, box)


def test_generated_cross_flavour_coverage_keeps_legacy_results(core):
    values = ("/tmp/reference", "C:/tmp/reference", PurePosixPath("/tmp/reference"),
              PureWindowsPath("/tmp/reference"), PureWindowsPath("C:/", "/tmp/reference"),
              PureWindowsPath("C:/base", "D:child"), "/tmp/\udcffreference", PurePosixPath("/tmp/\udcffreference"),
              PurePosixPath("a" * 20000, "b" * 20000, "/tmp/reference"),
              PureWindowsPath("a" * 20000, "b" * 20000, "/tmp/reference"))
    with ThreadPoolExecutor(max_workers=3) as pool:
        outcomes = list(pool.map(lambda pair: core_module.covered([pair[0]], pair[1]), itertools.product(values, repeat=2)))
    assert outcomes == [legacy.covered([left], right) for left, right in itertools.product(values, repeat=2)]


@pytest.mark.parametrize("entry,kind", itertools.product(
    ("safe_path", "covered_target", "covered_scope", "load_json", "initialize", *(
        name for module, cls, name, function in public_entries()
        if module is writers_module and function is cls and "root" in inspect.signature(function).parameters)),
    ("str", "Path", "PurePosixPath", "PureWindowsPath", "pathlike-str", "static-str", "class-str")))
def test_generated_deep_paths_use_linear_work_after_one_conversion(journal, core, monkeypatch, entry, kind):
    reader, box = journal
    spelling = "/" + "a/" * 16000
    value = PureWindowsPath(spelling) if kind == "PureWindowsPath" else lifecycle_path_input(kind, spelling)
    observed = {"parses": 0, "work": 0, "parents": 0, "io": 0}

    def counted(factory):
        class Counted(factory):
            def __new__(cls, *args):
                if args and (args[0] is value or isinstance(args[0], str) and args[0] == spelling):
                    observed["parses"] += 1
                return super().__new__(cls, *args)

            @property
            def parents(self):
                observed["parents"] += 1
                return super().parents

            def is_symlink(self):
                observed["io"] += 1
                return super().is_symlink()
        return Counted

    monkeypatch.setattr(core_module, "Path", counted(type(reader.root)))
    monkeypatch.setattr(core_module, "PurePosixPath", counted(PurePosixPath))

    def trace(frame, event, arg):
        if event == "line" and frame.f_code.co_filename == core_module.__file__:
            observed["work"] += 1
            assert observed["work"] <= 8 * len(spelling), "path conversion exceeded linear work budget"
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        with pytest.raises(core.LifecycleRefusal) as caught:
            lifecycle_path_call(entry, value, reader, box)
    finally:
        sys.settrace(previous)
    assert caught.value.code == "unsafe_path"
    assert observed["parses"] == 1
    assert observed["parents"] == observed["io"] == 0
    assert not list((reader.root / "events").iterdir())
    retry = reader.root / "policy.json" if entry == "load_json" else reader.root.parent / "linear-retry"
    lifecycle_path_call(entry, retry.as_posix(), reader, box)


def delegated_path_case(grant_path, target_path):
    parent = request()
    parent.update(id="grant", operation="delegate-merge", authority="grant", paths=[grant_path])
    value = {**request(), "operation": "merge", "paths": [target_path]}
    state = legacy.initial_state(policy())
    state["requests"] = {"grant": {"request": parent, "raw": {"sha256": "d" * 64}},
                         "work": {"request": value, "publisher": "coordinator-1"}}
    state["decisions"] = [{"request_id": "grant", "decision": "approve"}]
    decision = {"delegation_id": "grant", "delegation_sha256": "d" * 64, "decision": "approve",
                "commit": SOURCE["commit"], "review": policy()["authority"], "reason": "reviewed"}
    mark = {"actor": "decider-1", "at": NOW}
    return state, decision, mark


@pytest.mark.parametrize("entry,shape", itertools.product(("grant", "target"), ("bounded", "deep", "root", "surrogate")))
def test_generated_delegation_paths_bound_before_comparison_and_retry(core, tmp_path, monkeypatch, entry, shape):
    base = tmp_path.as_posix()
    path = {"bounded": base, "deep": "/" + "a/" * 16000, "root": "/", "surrogate": base + "/\udcffchild"}[shape]
    paths = (path, base) if entry == "grant" else (base, path)
    observed = {"unbounded_comparison": 0}

    class Parts(tuple):
        def __ne__(self, other):
            if len(self) > 128:
                observed["unbounded_comparison"] += 1
                raise AssertionError("delegation compared an unbounded path")
            return super().__ne__(other)

    class ComparedPath(PurePosixPath):
        @property
        def parts(self):
            return Parts(super().parts)

    monkeypatch.setattr(core_module, "PurePosixPath", ComparedPath)

    def apply(module, values):
        state, decision, mark = values
        module.delegated_decision(state, state["requests"]["work"], decision, mark)
        return state

    state, decision, mark = delegated_path_case(*paths)
    before = copy.deepcopy(state)
    if shape == "bounded":
        assert apply(core, (state, decision, mark)) == apply(legacy, delegated_path_case(*paths))
    else:
        with pytest.raises(core.LifecycleRefusal) as caught:
            apply(core, (state, decision, mark))
        assert caught.value.code == ("unsafe_path" if shape == "deep" else "invalid_record")
        assert state == before and path not in json.dumps(caught.value.as_dict())
    assert observed["unbounded_comparison"] == 0
    expected = apply(legacy, delegated_path_case(base, base))
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: apply(core, delegated_path_case(base, base)), range(3)))
    assert results == [expected] * 3
