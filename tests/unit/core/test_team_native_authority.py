"""Public host-authority checks and parity against the frozen adapter."""
import copy
import json
import os
import pickle
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import team_native_authority as authority
from aegis_core import team_native_keys as keys
from aegis_core.team_native_wire import HostAuthorityError, MAX_DEPTH, MAX_FRAME_BYTES
from tools import hierarchy_host_authority as legacy


@contextmanager
def refusal(code, reason):
    with pytest.raises(HostAuthorityError) as caught:
        yield caught
    assert (caught.value.code, caught.value.reason, str(caught.value)) == (code, reason, reason)
    assert caught.value.next_action == HostAuthorityError(code, reason).next_action


class Binding:
    def __init__(self):
        self.plan_data = {"approved": True}
        self.policy_data = {"current": {"root": "root-1"}, "actors": {}, "source": {}}
        self.channel_data = {"epoch": 1}
        self.reservations = ()
        self.epoch, self.nonce = 1, "nonce"
        self.lock = threading.RLock()
        self.active_guard = None
        self.closed = False
        self.canonical_root = "canonical"
        self.pid = os.getpid()
        self.proofs = 0
        self.prove = lambda: None

    def require_owner_process(self):
        if self.pid != os.getpid():
            raise HostAuthorityError("STALE_INVOCATION",
                                     "runtime binding belongs to another host process")

    def prove_current(self):
        self.proofs += 1
        self.prove()

    def decision_history_unknown(self):
        self.closed = True
        raise HostAuthorityError("PROVIDER_OUTCOME_UNKNOWN",
                                 "canonical decision outcome is unresolved")


class Invocation:
    def __init__(self, owner):
        self.owner = owner
        self.scope_entered = False
        self.scope_depth = 0
        self.stage = "pending"
        self.deadline_ns = time.monotonic_ns() + 4 * 10**9
        self.arguments = {"event_id": "event", "request_id": "request",
                          "request_sha256": "digest", "decision": "allow", "reason": "reviewed"}

    def require_current(self):
        self.owner.require_owner_process()

    @property
    def actor_cid(self):
        return "root-1"


@pytest.fixture
def runtime(monkeypatch):
    registry = keys.NativeIdentities()
    monkeypatch.setattr(authority, "native_identities", registry)
    registry.bind_type("binding", Binding)
    registry.bind_type("invocation", Invocation)
    owner = Binding()
    registry.register_binding(keys.LIVE_KEY, owner)
    owner.authority = authority.HostAuthority(owner)
    owner.reservations = (authority.ReservedEnrollment(keys.RESERVATION_KEY, owner, {
        "schema": "aegis.host-reservation-witness/v1", "actor_cid": "root-1", "role": "root",
        "generation": 1, "profile_sha256": "a" * 64, "cap_seconds": 60,
        "channel_instance_sha256": "b" * 64, "approved_plan_sha256": "c" * 64,
        "reservation_sequence": 1, "expires_monotonic_ns": time.monotonic_ns() + 10**11,
    }),)
    yield owner
    registry.discard_binding(keys.LIVE_KEY, owner)


def test_registry_is_exact_and_refuses_rebinding():
    registry = keys.NativeIdentities()
    assert not registry.is_instance("binding", None)
    registry.bind_type("binding", Binding)
    registry.bind_type("binding", Binding)
    with refusal("ROLE_OPERATION_FORBIDDEN", "native class identity is already bound"):
        registry.bind_type("binding", type("Other", (Binding,), {}))
    with refusal("ROLE_OPERATION_FORBIDDEN", "registration requires an owned binding"):
        registry.register_binding(object(), Binding())
    with refusal("ROLE_OPERATION_FORBIDDEN", "registration requires an owned binding"):
        registry.register_binding(keys.LIVE_KEY, type("Derived", (Binding,), {})())
    owner = Binding()
    registry.register_binding(keys.LIVE_KEY, owner)
    assert registry.owns_binding(owner)
    assert not registry.owns_binding(Binding())
    registry.discard_binding(keys.LIVE_KEY, owner)
    assert not registry.owns_binding(owner)


@pytest.mark.parametrize("name,args", [
    ("HostAuthority", ([],)),
    ("ReservedEnrollment", (None, None, {})),
    ("BoundInitialEnrollment", (None, None, None, {}, 1)),
    ("InitialCreationGuard", (None, None, {}, None)),
    ("ReservedGenesisGuard", (None, None, {}, ())),
    ("DecisionGuard", (None, None, None)),
], ids=["authority", "reservation", "bound", "initial-guard", "genesis-guard", "decision-guard"])
def test_constructor_refusals_match_legacy(name, args):
    with pytest.raises(legacy.HostAuthorityError) as expected:
        getattr(legacy, name)(*args)
    with refusal(expected.value.code, expected.value.reason):
        getattr(authority, name)(*args)


def test_capability_snapshots_are_nontransferable_and_process_local(runtime):
    reservation, = runtime.reservations
    witness = reservation.witness
    assert reservation.reservation_witness_sha256 == legacy._digest(witness)
    witness["actor_cid"] = "foreign"
    assert reservation.actor_cid == "root-1"
    context = authority.BoundInitialEnrollment(
        keys.BOUND_INITIAL_KEY, runtime, reservation, {}, time.monotonic_ns() + 10**9)
    assert context.actor_cid == reservation.actor_cid
    guard = runtime.authority.initial_creation_fence(runtime, runtime.plan_data, reservation)
    for capability in (reservation, context, guard):
        for transfer in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TypeError, match="cannot be"):
                transfer(capability)
    owner_pid, runtime.pid = runtime.pid, -1
    try:
        with refusal("STALE_INVOCATION", "runtime binding belongs to another host process"):
            reservation.owned_runtime
        with refusal("STALE_INVOCATION", "runtime binding belongs to another host process"):
            with guard:
                pytest.fail("guard admitted a foreign process")
    finally:
        runtime.pid = owner_pid
    assert runtime.proofs == 0


def test_genesis_rejects_nested_and_incomplete_guards(runtime):
    host = runtime.authority
    with refusal("ROLE_OPERATION_FORBIDDEN", "genesis requires the complete owned set"):
        host.bootstrap_fence(runtime, runtime.plan_data, ())
    with refusal("CANONICAL_CORRELATION_MISMATCH", "guard plan does not match owned runtime"):
        host.bootstrap_fence(runtime, {"approved": 1}, runtime.reservations)
    with host.bootstrap_fence(runtime, runtime.plan_data, runtime.reservations) as guard:
        guard.require_reserved_genesis_current()
        with refusal("ROLE_OPERATION_FORBIDDEN", "nested host fences are forbidden"):
            with host.bootstrap_fence(runtime, runtime.plan_data, runtime.reservations):
                pytest.fail("nested fence admitted")
    assert runtime.proofs == 1
    assert runtime.active_guard is None


def test_one_guard_entry_during_concurrent_preflight(runtime):
    started, finish = threading.Event(), threading.Event()

    def hold_preflight():
        started.set()
        assert finish.wait(3)

    runtime.prove = hold_preflight
    guard = runtime.authority.bootstrap_fence(runtime, runtime.plan_data, runtime.reservations)

    def enter():
        with guard:
            guard.require_reserved_genesis_current()

    with ThreadPoolExecutor(max_workers=1) as workers:
        result = workers.submit(enter)
        try:
            assert started.wait(3)
            with refusal("ROLE_OPERATION_FORBIDDEN", "guard cannot be reentered"):
                enter()
        finally:
            finish.set()
        result.result(timeout=3)
    assert runtime.proofs == 1
    assert runtime.active_guard is None


def test_failed_preflight_consumes_guard_without_blocking_fresh_guard(runtime):
    def failed():
        raise OSError("input diagnostic")

    runtime.prove = failed
    guard = runtime.authority.bootstrap_fence(runtime, runtime.plan_data, runtime.reservations)
    with refusal("HOST_PROFILE_UNQUALIFIED", "host preflight is unavailable") as error:
        with guard:
            pytest.fail("preflight failure admitted")
    assert error.value.__cause__ is None
    with refusal("ROLE_OPERATION_FORBIDDEN", "guard cannot be reentered"):
        with guard:
            pytest.fail("failed guard reused")
    runtime.prove = lambda: None
    with runtime.authority.bootstrap_fence(runtime, runtime.plan_data, runtime.reservations):
        pass


def test_initial_recovery_identity_and_new_checks(runtime):
    reservation, = runtime.reservations
    envelope = {"schema": "aegis.initial-bootstrap-envelope/v1", "id": "initial-genesis",
                "event": {"type": "initial_reservations", "approved_plan": runtime.plan_data,
                          "channel_witness": runtime.channel_data, "reservations": [reservation.witness]}}
    receipt = {"event_id": "initial-genesis", "sequence": 1,
               "event_sha256": legacy._digest(envelope), "execution_enabled": False}
    state = {"initial_bootstrap": {"genesis": {"envelope": envelope, "receipt": receipt},
                                   "reservations": [reservation.witness], "creations": {}},
             "current": {"root": reservation.actor_cid}}
    with runtime.authority.initial_creation_fence(runtime, runtime.plan_data, reservation) as guard:
        guard.require_initial_creation_current(reservation, runtime.policy_data, state, None)
        guard.require_initial_creation_new(reservation, runtime.policy_data, state, reservation.witness)
        state["current"] = ["malformed"]
        with refusal("ROLE_OPERATION_FORBIDDEN", "INITIAL requires its original current actor"):
            guard.require_initial_creation_new(reservation, runtime.policy_data, state, reservation.witness)
        assert state["initial_bootstrap"]["creations"] == {}


def test_decision_command_and_retry_of_prebuilt_guard(runtime):
    host = runtime.authority
    invocation = Invocation(runtime)
    first = host.effect_fence(invocation, "decision")
    second = host.effect_fence(invocation, "decision")
    with first:
        host.require_decision_command(invocation, dict(invocation.arguments))
        with refusal("STALE_INVOCATION", "decision arguments do not match owned call"):
            host.require_decision_command(invocation, dict(invocation.arguments, reason="changed"))
    assert invocation.scope_depth == 0
    with refusal("PROVIDER_OUTCOME_UNKNOWN", "canonical decision outcome is unresolved"):
        with second:
            pytest.fail("previously entered invocation readmitted")
    assert runtime.active_guard is None
    assert invocation.scope_depth == 0
    with refusal("PROVIDER_OUTCOME_UNKNOWN", "canonical decision outcome is unresolved"):
        host.effect_fence(invocation, "decision")


def test_decision_requires_actual_canonical_row(runtime):
    invocation = Invocation(runtime)
    profile = {"scope": "reviews"}
    runtime.policy_data["actors"]["root-1"] = {
        "role": "root", "generation": 1, "profile": profile,
    }
    envelope = {"event": "initial"}
    receipt = {"event_id": "initial", "sequence": 2,
               "event_sha256": legacy._digest(envelope), "execution_enabled": False}
    invocation.session = SimpleNamespace(
        actor_data={"role": "root", "generation": 1, "profile_sha256": legacy._digest(profile)},
        initial_data={"initial_event_id": "initial", "initial_sequence": 2,
                      "initial_event_sha256": receipt["event_sha256"]},
    )
    row = {"request": {"id": "review"}}
    state = {"current": {"root": "root-1"}, "receipts": {"initial": receipt},
             "initial_bootstrap": {"creations": {"root-1": {
                 "actor_cid": "root-1", "receipt": receipt, "envelope": envelope,
             }}}, "requests": {"review": row}}
    host = runtime.authority
    with host.effect_fence(invocation, "decision"):
        host.require_current(invocation, runtime.policy_data, state, None)
        with refusal("CANONICAL_CORRELATION_MISMATCH", "target is not the actual fresh canonical row"):
            host.require_current(invocation, runtime.policy_data, state, copy.deepcopy(row))
        with refusal("CANONICAL_CORRELATION_MISMATCH", "canonical target row is invalid"):
            host.require_current(invocation, runtime.policy_data, state, row)


@pytest.mark.parametrize("raw,code,reason", [
    (b"\xff", "UNPROTECTED_DEPLOYMENT", "unprotected host deployment"),
    (b"[" * (MAX_DEPTH + 2), "HOST_PROTOCOL_ERROR", "invalid host protocol frame"),
    (b"[" * (MAX_DEPTH + 1) + b"0" + b"]" * (MAX_DEPTH + 1),
     "HOST_PROTOCOL_ERROR", "invalid host protocol frame"),
    (b"1" * (MAX_FRAME_BYTES + 1), "UNPROTECTED_DEPLOYMENT", "unprotected host deployment"),
], ids=["encoding", "depth", "depth-at-scalar", "frame-size"])
def test_protected_json_refuses_before_parser(raw, code, reason, monkeypatch):
    def parser(_):
        pytest.fail("over-limit or invalid text reached the parser")

    monkeypatch.setattr(authority, "strict_loads", parser)
    with refusal(code, reason):
        authority.json_bytes(raw)


@pytest.mark.parametrize("raw", [b'{\n"x": [true, 10, "[]"]\n}', b"[]", b"true",
                                  b"[" * (MAX_DEPTH + 1) + b"]" * (MAX_DEPTH + 1)])
def test_protected_json_acceptance_matches_legacy(raw):
    assert authority.json_bytes(raw) == legacy._json_bytes(raw)


@pytest.mark.parametrize("raw", [b'{"duplicate":1,"duplicate":2}', b"[NaN]", b"[1e9999]"])
def test_protected_json_refusals_match_legacy(raw):
    with pytest.raises(legacy.HostAuthorityError) as expected:
        legacy._json_bytes(raw)
    with refusal(expected.value.code, expected.value.reason):
        authority.json_bytes(raw)


@pytest.mark.parametrize("raw", [
    b'{"n":18446744073709551616}',
    b"[" * (MAX_DEPTH + 1) + b"]" * (MAX_DEPTH + 1),
    b"[" * MAX_DEPTH + b"0" + b"]" * MAX_DEPTH,
    b"[" + b"0," * 10000 + b"0]",
    br'{"value":"\ud800"}',
], ids=["wide-integer", "empty-deepest-container", "depth-32-scalar", "long-list", "lone-surrogate"])
def test_digest_accepts_the_legacy_protected_json_domain(raw):
    value = authority.json_bytes(raw)
    assert authority.digest(value) == legacy._digest(value)


def test_digest_preserves_encoder_keys_and_refuses_invalid_inputs_then_allows_retry():
    value = {1: ("one",), 2.5: False}
    expected = legacy._digest(value)
    assert authority.digest(value) == expected
    cyclic = []
    cyclic.append(cyclic)
    for invalid in ({"n": float("nan")}, {"value": object()}, {"key": 0, 2: 0}, cyclic):
        with refusal("UNPROTECTED_DEPLOYMENT", "unprotected host deployment"):
            authority.digest(invalid)
    assert authority.digest(value) == expected


def test_digest_maps_encoder_typeerror_and_preserves_the_callers_refusal(monkeypatch):
    def unsupported(*args, **kwargs):
        raise TypeError("encoder details")

    monkeypatch.setattr(authority, "json", SimpleNamespace(dumps=unsupported))
    with refusal("UNPROTECTED_DEPLOYMENT", "unprotected host deployment"):
        authority.digest({"value": object()})
    with refusal("CANONICAL_CORRELATION_MISMATCH", "host receipt changed"):
        authority.digest({"value": object()}, code="CANONICAL_CORRELATION_MISMATCH",
                         reason="host receipt changed")


class OSBoundary:
    """Supply fixture-only metadata above the test directory and track our I/O."""

    def __init__(self, temporary):
        self.ancestors = {(info.st_dev, info.st_ino)
                          for info in (parent.stat() for parent in temporary.parents)}
        self.opened = set()
        self.open_flags = []
        self.after_read = lambda: None
        self.after_xattr = lambda info: None
        self.read_sizes = []
        self.socket_inode = None
        self.O_RDONLY = os.O_RDONLY
        self.O_DIRECTORY = os.O_DIRECTORY
        self.O_NOFOLLOW = os.O_NOFOLLOW
        self.O_CLOEXEC = os.O_CLOEXEC
        self.O_PATH = os.O_PATH
        self.O_NONBLOCK = os.O_NONBLOCK
        self.supports_dir_fd = os.supports_dir_fd
        self.supports_follow_symlinks = os.supports_follow_symlinks

    def open(self, path, flags, *, dir_fd=None):
        descriptor = os.open(path, flags, dir_fd=dir_fd)
        self.opened.add(descriptor)
        self.open_flags.append(flags)
        return descriptor

    def close(self, descriptor):
        os.close(descriptor)
        self.opened.remove(descriptor)

    def fstat(self, descriptor):
        return self._normalize(os.fstat(descriptor))

    def stat(self, *args, **kwargs):
        return self._normalize(os.stat(*args, **kwargs))

    def _normalize(self, info):
        identity = info.st_dev, info.st_ino
        socket_leaf = identity == self.socket_inode
        if identity not in self.ancestors and not socket_leaf:
            return info
        mode = stat.S_IFSOCK | stat.S_IMODE(info.st_mode) if socket_leaf else info.st_mode & ~0o022
        return SimpleNamespace(st_mode=mode, st_uid=os.getuid(), st_gid=info.st_gid,
                               st_dev=info.st_dev, st_ino=info.st_ino, st_size=info.st_size,
                               st_mtime_ns=info.st_mtime_ns, st_ctime_ns=info.st_ctime_ns)

    def listxattr(self, target, *, follow_symlinks=True):
        if isinstance(target, int):
            info = os.fstat(target)
        else:
            info = os.stat(target, follow_symlinks=follow_symlinks)
        attrs = ([] if (info.st_dev, info.st_ino) in self.ancestors else
                 os.listxattr(target, follow_symlinks=follow_symlinks))
        self.after_xattr(info)
        return attrs

    def read(self, descriptor, size):
        self.read_sizes.append(size)
        raw = os.read(descriptor, size)
        self.after_read()
        return raw


@pytest.fixture
def protected(tmp_path, monkeypatch):
    if os.name != "posix" or not authority.descriptor_supported():
        pytest.skip("Linux protected descriptor and ACL checks required")
    boundary = OSBoundary(tmp_path)
    monkeypatch.setattr(authority, "os", boundary)
    parent = tmp_path / "owned"
    parent.mkdir(mode=0o700)
    leaf = parent / "record"
    leaf.write_bytes(b"owned")
    yield leaf, boundary, {0, os.getuid()}
    assert not boundary.opened


def test_protected_reads_check_size_and_mode_before_read_and_allow_retry(protected):
    leaf, boundary, owners = protected
    with refusal("UNPROTECTED_DEPLOYMENT", "unprotected host deployment"):
        authority.protected_bytes(leaf, owners, -1, maximum=4)
    assert boundary.read_sizes == []
    leaf.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IWOTH)
    with refusal("UNPROTECTED_DEPLOYMENT", "unprotected host deployment"):
        authority.protected_bytes(leaf, owners, -1)
    assert boundary.read_sizes == []
    leaf.chmod(0o600)
    assert authority.protected_bytes(leaf, owners, -1, maximum=5) == b"owned"
    assert boundary.read_sizes[-1] == 1
    assert stat.S_ISDIR(authority.protected_path(leaf.parent, owners, -1, directory=True).st_mode)


@pytest.mark.parametrize("mode", [0o444, 0o400], ids=["read-only", "owner-read-only"])
def test_protected_metadata_and_reads_match_legacy_below_search_only_ancestor(protected, monkeypatch, mode):
    leaf, boundary, owners = protected
    leaf.parent.chmod(0o711)
    leaf.chmod(mode)
    monkeypatch.setattr(legacy, "os", boundary)

    for path, is_dir in ((leaf.parent, True), (leaf, False)):
        boundary.open_flags.clear()
        expected = legacy._protected_path(path, owners, -1, directory=is_dir)
        actual = authority.protected_path(path, owners, -1, directory=is_dir)
        assert actual == expected
        assert boundary.open_flags and all(flags & os.O_PATH for flags in boundary.open_flags)

    assert boundary.read_sizes == []
    boundary.open_flags.clear()
    assert authority.protected_bytes(leaf, owners, -1) == b"owned"
    assert [flags for flags in boundary.open_flags if not flags & os.O_PATH] == [
        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
    ]


def test_protected_metadata_refuses_replaced_leaf_and_allows_retry(protected):
    leaf, boundary, owners = protected
    inode = leaf.stat().st_ino
    saved = leaf.with_name("original")

    def replace(info):
        if info.st_ino == inode:
            boundary.after_xattr = lambda info: None
            leaf.rename(saved)
            leaf.write_bytes(b"replacement")

    boundary.after_xattr = replace
    with refusal("UNPROTECTED_DEPLOYMENT", "unprotected host deployment"):
        authority.protected_path(leaf, owners, -1)
    assert not boundary.opened
    assert not boundary.read_sizes
    assert authority.protected_path(leaf, owners, -1).st_ino == leaf.stat().st_ino


def test_protected_read_refuses_replaced_ancestor_and_allows_retry(protected):
    leaf, boundary, owners = protected
    moved = leaf.parent.with_name("moved")

    def move():
        boundary.after_read = lambda: None
        leaf.parent.rename(moved)
        symlink_or_skip(moved, leaf.parent, target_is_directory=True)

    boundary.after_read = move
    with refusal("UNPROTECTED_DEPLOYMENT", "unprotected host deployment"):
        authority.protected_bytes(leaf, owners, -1)
    assert not boundary.opened
    leaf.parent.unlink()
    moved.rename(leaf.parent)
    assert authority.protected_bytes(leaf, owners, -1) == b"owned"


def test_protected_read_refuses_growth_and_releases_the_chain(protected):
    leaf, boundary, owners = protected

    def grow():
        boundary.after_read = lambda: None
        with leaf.open("ab") as stream:
            stream.write(b"excess")

    boundary.after_read = grow
    with refusal("UNPROTECTED_DEPLOYMENT", "unprotected host deployment"):
        authority.protected_bytes(leaf, owners, -1, maximum=5)
    assert boundary.read_sizes == [6, 1]
    assert not boundary.opened
    assert authority.protected_bytes(leaf, owners, -1) == b"ownedexcess"


def test_socket_inspection_checks_kind_without_opening_a_connection(protected):
    leaf, boundary, owners = protected
    assert stat.S_ISREG(authority.protected_path(leaf, owners, -1).st_mode)
    with refusal("UNPROTECTED_DEPLOYMENT", "unprotected host deployment"):
        authority.protected_path(leaf, owners, -1, socket_path=True)
    # The syscall boundary supplies socket metadata. Lookup, O_PATH, ACL
    # inspection and closure still use the real descriptor and kernel.
    info = leaf.stat()
    boundary.socket_inode = info.st_dev, info.st_ino
    assert stat.S_ISSOCK(authority.protected_path(leaf, owners, -1, socket_path=True).st_mode)
    with refusal("UNPROTECTED_DEPLOYMENT", "unprotected host deployment"):
        authority.protected_bytes(leaf, owners, -1)
    assert not boundary.read_sizes


def _unexpected_control_resource(*_args, **_kwargs):
    pytest.fail("ControlIO admission touched an owner resource")


class ControlBinding:
    __slots__ = ("foreign", "_fenced", "checks", "__weakref__")

    def __init__(self, *, foreign=False, fenced=False):
        self.foreign = foreign
        self._fenced = fenced
        self.checks = []

    def require_owner_process(self):
        self.checks.append("process")
        if self.foreign:
            raise HostAuthorityError("STALE_INVOCATION",
                                     "runtime binding belongs to another host process")

    @property
    def fenced(self):
        self.checks.append("fenced")
        return self._fenced

    @property
    def io_gate(self):
        pytest.fail("ControlIO admission accessed the owner gate")

    @property
    def control_socket(self):
        pytest.fail("ControlIO admission accessed the owner socket")

    def close(self):
        pytest.fail("ControlIO admission closed the owner")


@pytest.fixture
def control_registry(monkeypatch):
    registry = keys.NativeIdentities()
    registry.bind_type("binding", ControlBinding)
    unexpected = _unexpected_control_resource
    monkeypatch.setattr(authority, "native_identities", registry)
    monkeypatch.setattr(authority, "descriptor_supported", lambda: True)
    monkeypatch.setattr(authority, "os", SimpleNamespace(
        set_blocking=unexpected, read=unexpected, write=unexpected, close=unexpected))
    monkeypatch.setattr(authority, "threading", SimpleNamespace(
        Thread=unexpected, Lock=unexpected, Event=unexpected))
    monkeypatch.setattr(authority, "weakref", SimpleNamespace(
        WeakValueDictionary=unexpected, finalize=unexpected))
    return registry


def test_control_constructor_checks_platform_before_identity(control_registry, monkeypatch):
    monkeypatch.setattr(authority, "descriptor_supported", lambda: False)
    with refusal("UNSUPPORTED_HOST", "protected control requires Linux"):
        authority.ControlIO(object())


def test_control_constructor_checks_exact_binding_identity_before_process(control_registry):
    class ForeignBinding(ControlBinding):
        pass

    owner = ForeignBinding(foreign=True, fenced=True)
    with refusal("ROLE_OPERATION_FORBIDDEN", "control requires an owned binding"):
        authority.ControlIO(owner)
    assert owner.checks == []


def test_control_constructor_checks_owner_process_before_staleness(control_registry):
    owner = ControlBinding(foreign=True, fenced=True)
    with refusal("STALE_INVOCATION", "runtime binding belongs to another host process"):
        authority.ControlIO(owner)
    assert owner.checks == ["process"]


def test_control_constructor_checks_staleness_before_deployment(control_registry):
    owner = ControlBinding(fenced=True)
    with refusal("STALE_INVOCATION", "runtime binding is closed"):
        authority.ControlIO(owner)
    assert owner.checks == ["process", "fenced"]
    assert owner._fenced is True


@pytest.mark.parametrize("registered", [False, True])
def test_control_constructor_repeatedly_refuses_without_owner_side_effects(control_registry, registered):
    first, fresh = ControlBinding(), ControlBinding()
    for owner in (first, fresh):
        if registered:
            control_registry.register_binding(keys.LIVE_KEY, owner)
        initial_checks = ["process"] if registered else []
        for _ in range(2):
            with refusal("UNPROTECTED_DEPLOYMENT", "unprotected host deployment") as error:
                authority.ControlIO(owner)
            assert error.value.__cause__ is None
            assert owner.foreign is False and owner._fenced is False
            assert control_registry.owns_binding(owner) is registered
        assert owner.checks == initial_checks + ["process", "fenced"] * 2


def test_missing_and_invalid_paths_refuse_without_diagnostics(protected):
    leaf, boundary, owners = protected
    for path in (leaf.with_name("not-present"), str(leaf) + "/../record", "x" * 4097, None):
        with refusal("UNPROTECTED_DEPLOYMENT", "unprotected host deployment") as error:
            authority.protected_bytes(path, owners, -1)
        assert error.value.__cause__ is None
        assert not boundary.opened
    assert boundary.read_sizes == []


def test_unsupported_host_refuses_before_any_filesystem_work(monkeypatch):
    monkeypatch.setattr(authority, "descriptor_supported", lambda: False)
    monkeypatch.setattr(authority, "os", object())
    with refusal("UNSUPPORTED_HOST", "protected control requires Linux"):
        authority.protected_bytes("/unread", {0}, -1)
    with refusal("UNSUPPORTED_HOST", "protected control requires Linux"):
        authority.protected_path("/unread", {0}, -1)
    with refusal("UNSUPPORTED_HOST", "protected control requires Linux"):
        authority.process_identity(1)
    with refusal("UNSUPPORTED_HOST", "protected control requires Linux"):
        authority.ControlIO(object())


def test_process_identity_matches_legacy_on_linux():
    if not authority.descriptor_supported():
        pytest.skip("Linux procfs and descriptor-relative reads required")
    pid = os.getpid()
    assert authority.process_identity(pid) == legacy._process_identity(pid)
    with refusal("UNPROTECTED_DEPLOYMENT", "unprotected host deployment"):
        authority.process_identity("not-a-pid")


class ProcBoundary(OSBoundary):
    def __init__(self, root):
        super().__init__(root)
        self.root = root
        self.unreadable = False
        self.after_namespace = lambda: None

    def open(self, path, flags, *, dir_fd=None):
        if self.unreadable and path == "proc":
            raise PermissionError("fixture proc details")
        return super().open(self.root if path == "/" else path, flags, dir_fd=dir_fd)

    def readlink(self, name, *, dir_fd):
        result = os.readlink(name, dir_fd=dir_fd)
        self.after_namespace()
        return result


@pytest.fixture
def listed_proc(tmp_path, monkeypatch):
    if os.name != "posix" or not authority.descriptor_supported():
        pytest.skip("Linux procfs and descriptor-relative reads required")
    pid = 4321
    boot = "00000000-0000-0000-0000-000000000001"
    proc = tmp_path / "proc"
    pid_dir = proc / str(pid)
    namespace = pid_dir / "ns"
    namespace.mkdir(parents=True)
    symlink_or_skip("pid:[71]", namespace / "pid")
    boundary = ProcBoundary(tmp_path)
    identity = authority.kernel_identity

    def proc_path(path):
        assert path == "/proc"
        return proc

    monkeypatch.setattr(authority, "os", boundary)
    monkeypatch.setattr(authority, "Path", proc_path)
    monkeypatch.setattr(authority, "kernel_identity", SimpleNamespace(
        descriptor_supported=identity.descriptor_supported, IdentityError=identity.IdentityError,
        boot_id=lambda: boot, process_identity=lambda pid: None,
    ))
    yield pid, pid_dir, boot, boundary
    assert not boundary.opened


def proc_stat(pid_dir, pid, state="Z", ticks=123):
    # The command name can itself contain a closing parenthesis or spaces.
    fields = " ".join([state] + ["0"] * 18 + [str(ticks), "0"])
    (pid_dir / "stat").write_bytes(f"{pid} (child ) name) {fields}\n".encode("ascii"))


@pytest.mark.parametrize("state", ["Z", "X", "x"], ids=["zombie", "dead-upper", "dead-lower"])
def test_process_identity_preserves_dead_listed_pid(listed_proc, state):
    pid, pid_dir, boot, _ = listed_proc
    proc_stat(pid_dir, pid, state)
    expected = {"pid": pid, "start_ticks": 123, "boot_id": boot, "pid_namespace": 71}
    assert authority.process_identity(pid) == expected


def test_process_identity_refuses_a_missing_pid(listed_proc):
    pid, pid_dir, _, _ = listed_proc
    pid_dir.rename(pid_dir.with_name("retired"))
    with refusal("UNPROTECTED_DEPLOYMENT", "unprotected host deployment"):
        authority.process_identity(pid)


def test_process_identity_refuses_unreadable_proc(listed_proc):
    pid, pid_dir, _, boundary = listed_proc
    proc_stat(pid_dir, pid)
    boundary.unreadable = True
    with refusal("UNPROTECTED_DEPLOYMENT", "unprotected host deployment") as error:
        authority.process_identity(pid)
    assert error.value.__cause__ is None
    assert not boundary.opened


@pytest.mark.parametrize("change", ["disappeared", "changed", "replaced"])
def test_process_identity_refuses_a_racing_pid_and_allows_retry(listed_proc, change):
    pid, pid_dir, boot, boundary = listed_proc
    proc_stat(pid_dir, pid)
    saved = pid_dir.with_name("retired")
    changes = []

    def replace():
        if change == "changed":
            proc_stat(pid_dir, pid, ticks=456)
        elif change == "disappeared":
            (pid_dir / "stat").unlink()
        else:
            pid_dir.rename(saved)
            (pid_dir / "ns").mkdir(parents=True)
            proc_stat(pid_dir, pid)
        changes.append(change)
        boundary.after_namespace = lambda: None

    boundary.after_namespace = replace
    with refusal("UNPROTECTED_DEPLOYMENT", "unprotected host deployment"):
        authority.process_identity(pid)
    assert changes == [change]
    assert not boundary.opened
    if change == "replaced":
        pid_dir.rename(pid_dir.with_name("other"))
        saved.rename(pid_dir)
    proc_stat(pid_dir, pid)
    assert authority.process_identity(pid) == {
        "pid": pid, "start_ticks": 123, "boot_id": boot, "pid_namespace": 71,
    }


@pytest.mark.parametrize("invalid", ["live", "wrong-pid", "oversized"])
def test_process_identity_refuses_unproven_dead_stat(listed_proc, invalid):
    pid, pid_dir, _, _ = listed_proc
    if invalid == "live":
        proc_stat(pid_dir, pid, state="S")
    elif invalid == "wrong-pid":
        proc_stat(pid_dir, pid + 1)
    else:
        (pid_dir / "stat").write_bytes(b"0" * 4097)
    with refusal("UNPROTECTED_DEPLOYMENT", "unprotected host deployment"):
        authority.process_identity(pid)
