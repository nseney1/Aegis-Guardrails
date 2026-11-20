"""Custody publication and contention through descriptor-confined public boundaries."""
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis_core import team_host_registry as hosts
from aegis_core.team_mailbox import RoleTables
from aegis_core import team_session_census as census
from aegis_core import team_session_custody as custody


class CustodyIO:
    """Test-owned reference facade; the shared os module is never modified."""
    O_RDONLY = os.O_RDONLY
    O_DIRECTORY = getattr(os, 'O_DIRECTORY', 0)
    O_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)
    open = staticmethod(os.open)
    close = staticmethod(os.close)
    mkdir = staticmethod(os.mkdir)
    fsync = staticmethod(os.fsync)
    fstat = staticmethod(os.fstat)
    stat = staticmethod(os.stat)
    fdopen = staticmethod(os.fdopen)


def make_runtime(tmp_path):
    core = custody.CustodyRuntime(hosts, roles=RoleTables())
    if not core.launch_descriptor_capable():
        pytest.skip("descriptor-relative custody unavailable")
    return core


def test_unsupported_platform_refuses_with_probe_monkeypatched(tmp_path, monkeypatch):
    monkeypatch.setattr(census, 'kernel_identity', SimpleNamespace(descriptor_supported=lambda: False))
    core = custody.CustodyRuntime(hosts, roles=RoleTables())
    with pytest.raises(census.SessionRefused) as caught:
        with core.directory_fence(tmp_path):
            pass
    assert caught.value.code == "unsupported_platform"


def test_custody_busy_is_one_typed_refusal_then_retry(tmp_path):
    core = make_runtime(tmp_path)
    binding = dict(host="codex-cli", session="session-a", generation=1)
    with core.stop_custody(tmp_path, "team/lane/worker", binding) as first:
        first.prepare()
        first.lock()
        with core.stop_custody(tmp_path, "team/lane/worker", binding) as second:
            second.prepare()
            with pytest.raises(census.SessionRefused) as caught:
                second.lock()
            assert caught.value.code == "custody_busy"
    with core.stop_custody(tmp_path, "team/lane/worker", binding) as retry:
        retry.prepare()
        assert retry.lock() is retry


def test_descriptor_stream_closes_when_fdopen_fails(tmp_path, monkeypatch):
    core = make_runtime(tmp_path)
    descriptor = os.open(tmp_path / "stream", os.O_WRONLY | os.O_CREAT, 0o600)
    class BrokenStreamOS(CustodyIO):
        def fdopen(self, *args, **kwargs):
            raise OSError("untrusted diagnostic")
    monkeypatch.setattr(custody, 'os', BrokenStreamOS())
    with pytest.raises(census.SessionRefused):
        with core.descriptor_stream(descriptor, "wb"):
            pass
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_invalid_resume_record_leaves_storage_untouched(tmp_path):
    core = make_runtime(tmp_path)
    launches = SimpleNamespace(base=tmp_path, folder=lambda endpoint: tmp_path / "launches" / "team%2Flane%2Fworker")
    identifier = "20261119T140000000000Z-" + "a" * 32
    before = list(tmp_path.iterdir())
    with pytest.raises(census.SessionRefused):
        core.write_resume_admission(launches, "team/lane/worker", identifier,
                                    dict(host="codex-cli", session="session-a", generation=-1),
                                    "2026-11-19T14:00:00.000000Z", True)
    assert list(tmp_path.iterdir()) == before


def test_resume_record_round_trip_retry(tmp_path):
    core = make_runtime(tmp_path)
    launches = SimpleNamespace(base=tmp_path, folder=lambda endpoint: tmp_path / "launches" / "team%2Flane%2Fworker")
    identifier = "20261119T140000000000Z-" + "a" * 32
    arguments = (launches, "team/lane/worker", identifier, dict(host="codex-cli", session="session-a", generation=1),
                 "2026-11-19T14:00:00.000000Z", True)
    record = core.write_resume_admission(*arguments)
    assert core.read_resume_admission(tmp_path, "team/lane/worker", identifier) == record
    assert core.write_resume_admission(*arguments) == record


def test_symlinked_ancestor_refuses_without_touching_target(tmp_path):
    from tests.conftest import symlink_or_skip
    core = make_runtime(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    alias = tmp_path / "alias"
    symlink_or_skip(target, alias, target_is_directory=True)
    with pytest.raises(census.SessionRefused):
        core.read_running_wake(alias, "team/lane/worker")
    assert list(target.iterdir()) == []


def test_fence_detects_concurrent_ancestor_rename(tmp_path):
    core = make_runtime(tmp_path)
    parent = tmp_path / "parent"
    child = parent / "child"
    child.mkdir(parents=True)
    with pytest.raises(census.SessionRefused):
        with core.directory_fence(child) as fence:
            parent.rename(tmp_path / "moved")
            child.mkdir(parents=True)
            fence.check()


def test_invalid_terminal_custody_is_refused_before_any_write(tmp_path):
    from aegis_core.team_session_stop import StopRuntime
    class Recorded(StopRuntime):
        def require_pid_namespace(self, *args):
            return dict(device=1, inode=2)
    core = Recorded(hosts, roles=RoleTables())
    if not core.launch_descriptor_capable():
        pytest.skip("descriptor-relative custody unavailable")
    namespace = dict(device=1, inode=2)
    state = dict(candidates={41: None}, initial_unavailable={41: {}}, blocked=set(), identity_lost=set(),
                 resolved={}, coverage=None, pid_namespace=namespace)
    with core.stop_custody(tmp_path, "team/lane/worker", dict(host="codex-cli", session="session-a", generation=1)) as store:
        with pytest.raises(census.SessionRefused):
            store.save(state, set(), active=False)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("value", [None, True, False, 12, "a\n\"\\\u00e9\U0001f600", {"entries": [1, "x"]}])
def test_serialized_size_measures_before_encoder(value):
    import json
    assert custody.serialized_size(value) == len(json.dumps(value, sort_keys=True).encode("ascii"))


def test_active_custody_round_trip_and_refused_terminal_retry(tmp_path):
    from aegis_core.team_session_stop import StopRuntime
    from tests.unit.core.test_team_session_census import row
    class Recorded(StopRuntime):
        def require_pid_namespace(self, *args):
            return dict(device=1, inode=2)
    core = Recorded(hosts, roles=RoleTables())
    if not core.launch_descriptor_capable():
        pytest.skip("descriptor-relative custody unavailable")
    binding = dict(host="codex-cli", session="session-a", generation=1)
    state = dict(candidates={41: row()}, initial_unavailable={}, blocked=set(), identity_lost=set(),
                 resolved={}, coverage=None, pid_namespace=dict(device=1, inode=2))
    with core.stop_custody(tmp_path, "team/lane/worker", binding) as store:
        store.save(state, set())
        before = store.path.read_bytes()
        saved, entries = store.read()
        assert saved["active"] is True and entries[0][1].pid == 41
        with pytest.raises(census.SessionRefused):
            store.save(state, set(), active=False)
        assert store.path.read_bytes() == before
        store.save(state, set())
        assert store.read()[0] == saved


def test_prepare_failure_closes_partial_chain_without_context_manager(tmp_path, monkeypatch):
    make_runtime(tmp_path)
    class FaultOS(CustodyIO):
        def __init__(self):
            self.opened, self.closed, self.calls = [], [], 0

        def open(self, *args, **kwargs):
            self.calls += 1
            if self.calls == 2:
                raise OSError("untrusted diagnostic")
            descriptor = super().open(*args, **kwargs)
            self.opened.append(descriptor)
            return descriptor

        def close(self, descriptor):
            self.closed.append(descriptor)
            return super().close(descriptor)
    system = FaultOS()
    monkeypatch.setattr(custody, 'os', system)
    core = custody.CustodyRuntime(hosts, roles=RoleTables())
    store = core.stop_custody(tmp_path, "team/lane/worker", None)
    with pytest.raises(census.SessionRefused):
        store.prepare()
    assert system.opened == system.closed and store.namespace == []


def test_terminal_custody_requires_physical_exit_and_can_be_retried(tmp_path):
    from aegis_core.team_session_stop import StopRuntime
    from tests.unit.core.test_team_session_census import row
    class Recorded(StopRuntime):
        current = census.ProcessObservation('PRESENT', 41, row())

        def require_pid_namespace(self, *args):
            return dict(device=1, inode=2)

        def read_process(self, pid):
            return self.current
    core = Recorded(hosts, roles=RoleTables())
    if not core.launch_descriptor_capable():
        pytest.skip('descriptor-relative custody unavailable')
    state = dict(candidates={41: row()}, initial_unavailable={}, blocked=set(), identity_lost=set(),
                 resolved={41: 'matching_birth_zombie'}, coverage=None, pid_namespace=dict(device=1, inode=2))
    binding = dict(host='codex-cli', session='session-a', generation=1)
    with core.stop_custody(tmp_path, 'team/lane/worker', binding) as store:
        store.save(state, set(), active=False)
        before = store.path.read_bytes()
        with pytest.raises(census.CustodyExitUnproven) as caught:
            store.read()
        assert caught.value.code == 'custody_exit_unproven'
        assert store.path.read_bytes() == before
        core.current = census.ProcessObservation('CONFIRMED_ABSENT', 41, proof='qualified_namespace_ESRCH')
        assert store.read()[0]['active'] is False


@pytest.mark.parametrize('missing', ['uid', 'euid', 'both'])
def test_partial_custody_exit_does_not_accept_missing_identity_fields(tmp_path, missing):
    from aegis_core.team_session_stop import StopRuntime
    from tests.unit.core.test_team_session_census import row
    class Recorded(StopRuntime):
        current = census.ProcessObservation('PRESENT', 41, row())

        def require_pid_namespace(self, *args):
            return dict(device=1, inode=2)

        def read_process(self, pid):
            return self.current
    core = Recorded(hosts, roles=RoleTables())
    if not core.launch_descriptor_capable():
        pytest.skip('descriptor-relative custody unavailable')
    state = dict(candidates={41: row()}, initial_unavailable={}, blocked=set(), identity_lost=set(),
                 resolved={41: 'matching_birth_zombie'}, coverage=None, pid_namespace=dict(device=1, inode=2))
    facts = dict(row()._asdict(), coherent_birth=True, exit_observed=True)
    for field in ['uid', 'euid'] if missing == 'both' else [missing]:
        facts.pop(field)
    core.current = census.ProcessObservation('UNAVAILABLE', 41, partial=facts, reason='missing UIDs')
    with core.stop_custody(tmp_path, 'team/lane/worker', dict(host='codex-cli', session='session-a', generation=1)) as store:
        store.save(state, set(), active=False)
        before = store.path.read_bytes()
        with pytest.raises(census.CustodyExitUnproven) as caught:
            store.read()
        assert caught.value.code == 'custody_exit_unproven' and caught.value.next_action
        assert store.path.read_bytes() == before
        core.current = census.ProcessObservation('CONFIRMED_ABSENT', 41, proof='qualified_namespace_ESRCH')
        assert store.read()[0]['active'] is False
