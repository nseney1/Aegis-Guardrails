"""Signal-time gates use owned OS facades; no test signals a real process."""
import errno
import os
from contextlib import contextmanager
from types import FunctionType
from types import SimpleNamespace

import pytest

from aegis_core import team_host_registry as hosts
from aegis_core.team_mailbox import RoleTables
from aegis_core import team_session_census as census
from aegis_core import team_session_stop as stopping
from tests.unit.core.test_team_session_census import row
from tests.unit.core.test_team_session_census import oversized_argv, unavailable_row


class RecordedStop(stopping.StopRuntime):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.observer = lambda pid, boundaries="proven": census.ProcessObservation("PRESENT", pid, row())
        self.namespace_failure = False
        self.checkpoint_failure = False

    def require_pid_namespace(self, *args):
        if self.namespace_failure:
            raise census.PidNamespaceUnavailable()
        return {"device": 1, "inode": 2}

    def read_process(self, *args):
        return self.observer(*args)

    def persist_custody(self, *args):
        if self.checkpoint_failure:
            raise census.CustodyUnavailable()

    def process_census(self, session):
        return census.ProcessCensus([], "proven")

    def ancestors(self):
        return set()


def scenario(opening=None):
    calls = []
    system = SimpleNamespace(geteuid=lambda: 1000, kill=lambda *args: calls.append(args), close=lambda fd: None)
    if opening is not None:
        system.pidfd_open = opening
    core = RecordedStop(hosts, roles=RoleTables(), system=system, signals=SimpleNamespace(pidfd_send_signal=lambda *args: calls.append(args)))
    expected = row()
    state = dict(argv_boundaries="proven", pid_namespace={"device": 1, "inode": 2}, candidates={41: expected},
                 blocked=set(), identity_lost=set(), handles={}, unresolved={}, initial_unavailable={}, resolved={},
                 custody=SimpleNamespace(check_namespace=lambda: None))
    return core, state, calls


@pytest.mark.parametrize("failure", ["missing", errno.ENOSYS, errno.EPERM])
def test_pidfd_unavailable_refuses_before_attempt_and_retry(failure):
    def opening(pid):
        raise OSError(failure, "untrusted diagnostic")
    core, state, calls = scenario(None if failure == "missing" else opening)
    attempted = set()
    with pytest.raises(census.PidfdUnavailable) as caught:
        core.signal_process([row()], 15, "proven", "session-a", "codex-cli", [], observed=state, attempted=attempted)
    assert caught.value.code == "pidfd_unavailable"
    assert caught.value.reason and caught.value.next_action
    assert "untrusted" not in str(caught.value)
    assert calls == [] and attempted == set() and not state.get("possible_attempts")
    core.os.pidfd_open = lambda pid: 77
    assert core.signal_process([row()], 15, "proven", "session-a", "codex-cli", [],
                               observed=state, attempted=attempted) == "sent"
    assert calls == [(77, 15)] and attempted == {41}


def test_changed_identity_sends_nothing_and_closes_opened_handle():
    core, state, calls = scenario(lambda pid: 77)
    closed = []
    core.os.close = closed.append
    core.observer = lambda *args: census.ProcessObservation("PRESENT", 41, row(birth="456"))
    attempted = set()
    assert core.signal_process([row()], 15, "proven", "session-a", "codex-cli", [],
                               observed=state, attempted=attempted) is False
    assert calls == [] and attempted == set() and closed == [77]
    assert 41 in state["identity_lost"]


def test_namespace_failure_sends_nothing():
    core, state, calls = scenario(lambda pid: 77)
    core.namespace_failure = True
    with pytest.raises(census.PidNamespaceUnavailable):
        core.signal_process([row()], 15, "proven", "session-a", "codex-cli", [], observed=state)
    assert calls == []


def test_change_during_endpoint_fence_recheck_prevents_delivery():
    core, state, calls = scenario(lambda pid: 77)
    reads = iter([row(), row(birth="456")])
    core.observer = lambda *args: census.ProcessObservation("PRESENT", 41, next(reads))
    state["endpoint_fence"] = SimpleNamespace(check=lambda: None)
    attempted = set()
    assert core.signal_process([row()], 15, "proven", "session-a", "codex-cli", [],
                               observed=state, attempted=attempted) is False
    assert calls == [] and attempted == set()
    for handle in state["handles"].values():
        core.os.close(handle["fd"])


def test_checkpoint_failure_prevents_signal_and_closes_pidfd():
    core, state, calls = scenario(lambda pid: 77)
    closed = []
    core.os.close = closed.append
    core.checkpoint_failure = True
    with pytest.raises(census.CustodyUnavailable):
        core.signal_process([row()], 15, "proven", "session-a", "codex-cli", [], observed=state)
    assert calls == [] and closed == [77]


def test_reparented_descendant_is_never_signaled():
    core, state, calls = scenario(lambda pid: 77)
    child = row(42, parent=41, group=41, argv=("worker",))
    state["candidates"][42] = child
    core.observer = lambda pid, *args: census.ProcessObservation(
        "PRESENT", pid, row() if pid == 41 else child._replace(ppid=99))
    assert core.signal_process([child, row()], 15, "proven", "session-a", "codex-cli", [], observed=state) is False
    assert calls == []


def test_stop_entrypoint_empty_scope_preserves_successful_outcome(tmp_path):
    class EmptyScopeOS(census.SystemCalls):
        def pidfd_open(self, pid):
            return 77
    core = RecordedStop(hosts, roles=RoleTables(), ports=stopping.StopPorts(
        bound_session=lambda *args: (dict(host="codex-cli", session="session-a", generation=1), None),
        profile_mode=lambda profile: None, native_host="codex"), system=EmptyScopeOS())
    if not core.launch_descriptor_capable():
        pytest.skip("descriptor-relative stop unavailable")
    mailbox_root = tmp_path / "mailbox"
    (mailbox_root / "bindings" / "team" / "lane" / "worker").mkdir(parents=True)
    binding = dict(host="codex-cli", session="session-a", generation=1)
    records = []
    def record(endpoint, identifier, action, state, **details):
        result = dict(endpoint=endpoint, action=action, state=state, **details)
        records.append(result)
        return result
    launches = SimpleNamespace(base=tmp_path, mailbox=SimpleNamespace(root=mailbox_root),
                               resolve=lambda endpoint: endpoint, new_id=lambda: "outcome",
                               binding=lambda endpoint: binding, record=record)
    # Model both pidfd capabilities; the empty scope opens and signals nothing.
    core.signal = SimpleNamespace(pidfd_send_signal=lambda *args: pytest.fail("empty scope signaled"))
    code, result = core.stop(launches, "team/lane/worker", 0)
    assert code == 0 and result["state"] == "not_running" and result["pids"] == []
    assert len(records) == 1 and not (tmp_path / "launches").exists()


@pytest.mark.parametrize('endpoint', [None, 'team/lane/worker'])
def test_status_without_descriptors_names_prerequisite_without_reading_history(tmp_path, monkeypatch, endpoint):
    class StatusProbe(stopping.StopRuntime):
        def __init__(self):
            super().__init__(hosts, roles=RoleTables())
            self.history_requests = []

        def status_endpoints(self, base):
            self.history_requests.append('endpoints')
            return ['team/lane/worker']

        def launch_record_paths(self, base, name):
            self.history_requests.append('paths')
            return []

    monkeypatch.setattr(census, 'kernel_identity', SimpleNamespace(descriptor_supported=lambda: False))
    core = StatusProbe()
    launches = SimpleNamespace(base=tmp_path, mailbox=SimpleNamespace(endpoint=lambda name: None),
                               binding=lambda name: None)
    code, result = core.status(launches, endpoint)
    assert core.history_requests == []
    assert code == 0 and result['schema'] == census.STATUS_SCHEMA
    unknown = result if endpoint is None else result['endpoints'][endpoint]
    assert unknown['state'] == 'unknown' and unknown['records'] is None
    assert 'last' not in unknown
    assert unknown['code'] == 'unsupported_platform'
    assert unknown['reason'] == 'descriptor support unavailable'
    assert unknown['next_action'] == {
        'actor': 'owner', 'command': 'use a host with descriptor support to inspect launch history'}
    monkeypatch.setattr(census, 'kernel_identity', SimpleNamespace(descriptor_supported=lambda: True))
    code, retried = core.status(launches, endpoint)
    assert code == 0 and retried['endpoints']['team/lane/worker']['records'] == 0
    assert 'state' not in retried['endpoints']['team/lane/worker']


class ScopeStop(stopping.StopRuntime):
    def __init__(self, snapshots, unavailable, **ports):
        super().__init__(hosts, roles=RoleTables(), **ports)
        self.snapshots, self.unavailable, self.exited = snapshots, unavailable, set()

    def require_pid_namespace(self, *args):
        return dict(device=1, inode=2)

    def ancestors(self):
        return set()

    def process_census(self, session):
        return census.ProcessCensus([entry for entry in self.snapshots if entry.pid not in self.exited],
                                    'proven', unavailable=self.unavailable)

    def read_process(self, pid, boundaries='proven'):
        if pid in self.exited:
            return census.ProcessObservation('CONFIRMED_ABSENT', pid, proof='qualified_namespace_ESRCH')
        return next(census.ProcessObservation('PRESENT', pid, entry) for entry in self.snapshots if entry.pid == pid)


class TimedScope(ScopeStop):
    census_calls = 0
    appearance = 1
    running = None

    def process_census(self, session):
        self.census_calls += 1
        rows = [entry for entry in self.snapshots if entry.pid not in self.exited
                and (entry.pid != 42 or self.census_calls >= self.appearance)]
        missing = self.unavailable if self.census_calls >= self.appearance else {}
        return census.ProcessCensus([entry for entry in rows if entry.pid not in missing], 'proven', unavailable=missing)

    def read_running_wake(self, base, endpoint):
        return self.running


@contextmanager
def stop_fixture(tmp_path, snapshots, missing=None, appearance=1, running=False, escalation=False):
    if not stopping.StopRuntime(hosts).launch_descriptor_capable():
        pytest.skip('descriptor-relative stop unavailable')
    signals, handles, records = [], {}, []
    def open_handle(pid):
        descriptor = os.dup(read_end)
        handles[descriptor] = pid
        return descriptor
    def close_handle(descriptor):
        del handles[descriptor]
        os.close(descriptor)
    def deliver(descriptor, number):
        pid = handles[descriptor]
        signals.append((pid, number))
        if number == 9 or not escalation:
            core.exited.add(pid)
    def group_exists(group, number):
        assert number == 0
        if not any(entry.pgid == group and entry.pid not in core.exited for entry in core.snapshots):
            raise ProcessLookupError(errno.ESRCH, 'recorded group absent')
    binding = dict(host='codex-cli', session='session-a', generation=1)
    ticks = iter(range(1000))
    core = TimedScope(snapshots, missing or {},
        system=SimpleNamespace(geteuid=lambda: 1000, pidfd_open=open_handle, close=close_handle, killpg=group_exists),
        signals=SimpleNamespace(SIGTERM=15, SIGKILL=9, pidfd_send_signal=deliver),
        clock=SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda seconds: None),
        ports=stopping.StopPorts(bound_session=lambda *args: (dict(binding), None),
                                 profile_mode=lambda profile: None, native_host='codex'))
    core.appearance = appearance
    if running:
        core.running = dict(binding=dict(binding), host_pid=42, snapshot=None, pid_namespace=dict(device=1, inode=2))
    mailbox_root = tmp_path / 'mailbox'
    (mailbox_root / 'bindings' / 'team' / 'lane' / 'worker').mkdir(parents=True)
    def record(endpoint, identifier, action, state, **details):
        result = dict(endpoint=endpoint, state=state, **details)
        records.append(result)
        return result
    def refuse(*args, **kwargs):
        pytest.fail('unexpected stop refusal')
    launches = SimpleNamespace(base=tmp_path, mailbox=SimpleNamespace(root=mailbox_root,
        wake_marker=lambda endpoint: SimpleNamespace(exists=lambda: False)),
        resolve=lambda endpoint: endpoint, new_id=lambda: 'record', binding=lambda endpoint: dict(binding),
        record=record, refuse=refuse)
    read_end, write_end = os.pipe()
    try:
        yield core, launches, signals, binding
        assert handles == {}
    finally:
        for descriptor in handles:
            os.close(descriptor)
        os.close(read_end)
        os.close(write_end)


def legacy_stop(core, launches):
    from tools import hierarchy_launcher as legacy
    class CustodyBoundary:
        encode = staticmethod(legacy.StopCustody.encode)
        decode = staticmethod(legacy.StopCustody.decode)

        def __new__(cls, *args, **kwargs):
            return core.stop_custody(*args, **kwargs)
    bindings = dict(vars(legacy))
    for name, function in vars(legacy).items():
        if isinstance(function, FunctionType) and function.__module__ == legacy.__name__:
            cloned = FunctionType(function.__code__, bindings, name, function.__defaults__, function.__closure__)
            bindings[name] = cloned
    # Only actual OS/storage/adapter boundaries are replaced; discovery, lineage,
    # delivery and stop algorithms execute the unbounded legacy implementation.
    bindings.update(require_pid_namespace=core.require_pid_namespace, process_census=core.process_census,
                    read_process=core.read_process, ancestors=core.ancestors,
                    recorded_endpoint_lock=core.recorded_endpoint_lock, read_running_wake=core.read_running_wake,
                    clear_running_wake=core.clear_running_wake, stop_checks=core.stop_checks,
                    os=core.os, signal=core.signal, time=core.time, StopCustody=CustodyBoundary)
    return bindings['stop'](launches, 'team/lane/worker', 0)


@pytest.mark.parametrize('shape', ['atoms', 'atom', 'total', 'script'])
@pytest.mark.parametrize('grandchild', [False, True])
def test_stop_oversize_plain_descendants_match_legacy(tmp_path, shape, grandchild):
    argv = ('python', '-c', 'x' * 40000) if shape == 'script' else oversized_argv(shape)
    snapshots = [row(), row(42, parent=41, argv=argv)]
    if grandchild:
        snapshots.append(row(44, parent=42, argv=('worker',)))
    outcomes = []
    for implementation in ['legacy', 'core']:
        with stop_fixture(tmp_path / implementation, snapshots) as (core, launches, signals, _):
            code, result = legacy_stop(core, launches) if implementation == 'legacy' else core.stop(launches, 'team/lane/worker', 0)
            outcomes.append((code, result['state'], result['pids'], signals))
    assert outcomes[0] == outcomes[1]
    expected = [(44, 15), (42, 15), (41, 15)] if grandchild else [(42, 15), (41, 15)]
    assert outcomes[1] == (0, 'stopped', sorted(pid for pid, _ in expected), expected)


@pytest.mark.parametrize('shape', ['atoms', 'atom', 'total'])
@pytest.mark.parametrize('availability', ['present', 'unavailable', 'running'])
@pytest.mark.parametrize('appearance', [1, 2, 3], ids=['discovery', 'refresh', 'escalation'])
def test_uncertainty_never_vetoes_proven_host_or_lends_ancestry(tmp_path, shape, availability, appearance):
    extra = row(42, parent=41, argv=('codex',) + oversized_argv(shape, 'session-a')[1:])
    child = row(44, parent=42, argv=('worker',))
    second = row(43, group=43, argv=('codex', 'exec', 'resume', 'session-b'))
    missing = {42: unavailable_row(extra)} if availability == 'unavailable' else {}
    traces = []
    for label, extras in [('baseline', []), ('uncertain', [extra, child, second])]:
        with stop_fixture(tmp_path / label, [row()] + extras, missing if extras else {},
                          appearance, availability == 'running' and bool(extras), escalation=True) as (core, launches, signals, binding):
            code, result = core.stop(launches, 'team/lane/worker', 0)
            traces.append(list(signals))
            if extras:
                assert code == 3 and result['state'] == 'stop_failed'
                assert {42, 44} <= set(result['unresolved_pids'])
                assert all(pid not in [42, 44] for pid, _ in signals)
                reason = next(entry['reason'] for entry in result['unresolved'] if entry['pid'] == 42)
                assert reason == 'host_grammar_oversize'
                # Same census, separate binding and endpoint: unresolved A cannot veto B.
                binding['session'] = 'session-b'
                core.running = None
                other = 'team/lane/other'
                (launches.mailbox.root / 'bindings' / other).mkdir(parents=True)
                other_code, other_result = core.stop(launches, other, 0)
                assert other_code == 0 and other_result['state'] == 'stopped' and other_result['pids'] == [43]
                # Remove the unresolved processes, then retry the retained original session.
                core.exited.update([42, 44])
                core.unavailable = {}
                binding['session'] = 'session-a'
                retry_code, retry_result = core.stop(launches, 'team/lane/worker', 0)
                assert retry_code == 0 and retry_result['state'] == 'stopped'
            else:
                assert code == 0 and result['state'] == 'stopped'
    assert traces[0] == traces[1] == [(41, 15), (41, 9)]


@pytest.mark.parametrize('transition', [1, 2], ids=['first_check', 'fence_recheck'])
@pytest.mark.parametrize('target', ['owner', 'ancestor', 'child'])
def test_delivery_rechecks_do_not_borrow_through_new_grammar_uncertainty(transition, target):
    core, state, calls = scenario(lambda pid: 77)
    ancestor = row(42, parent=41, argv=('worker',))
    child = row(44, parent=42, argv=('worker',))
    chain = [row()] if target == 'owner' else [child, ancestor, row()]
    uncertain_pid = {'owner': 41, 'ancestor': 42, 'child': 44}[target]
    expected = next(entry for entry in chain if entry.pid == uncertain_pid)
    uncertain = expected._replace(argv=('codex',) + oversized_argv('atoms', 'session-a')[1:])
    uncertain = uncertain._replace(cmdline=b'\0'.join(atom.encode() for atom in uncertain.argv) + b'\0')
    state['candidates'].update({entry.pid: entry for entry in chain})
    state['endpoint_fence'] = SimpleNamespace(check=lambda: None)
    reads = {}
    def observe(pid, boundaries='proven'):
        reads[pid] = reads.get(pid, 0) + 1
        entry = next(entry for entry in chain if entry.pid == pid)
        if pid == uncertain_pid and reads[pid] >= transition:
            entry = uncertain
        return census.ProcessObservation('PRESENT', pid, entry)
    core.observer = observe
    attempts = set()
    assert core.signal_process(chain, 15, 'proven', 'session-a', 'codex-cli', [],
                               observed=state, attempted=attempts) is False
    assert calls == [] and attempts == set() and state.get('possible_attempts', set()) == set()
    assert chain[0].pid in state['unresolved'] and state['blocked'] == set()
    # A separately proven host still receives its signal, and the uncertain row
    # may be retried once its complete grammar is available again.
    other = row(43, group=43)
    state['candidates'][43] = other
    core.observer = lambda pid, *args: census.ProcessObservation('PRESENT', pid, other if pid == 43 else next(entry for entry in chain if entry.pid == pid))
    assert core.signal_process([other], 15, 'proven', 'session-a', 'codex-cli', [], observed=state, attempted=attempts) == 'sent'
    assert core.signal_process(chain, 15, 'proven', 'session-a', 'codex-cli', [], observed=state, attempted=attempts) == 'sent'
    assert calls == [(77, 15), (77, 15)] and attempts == {43, chain[0].pid}
    for handle in state['handles'].values():
        core.os.close(handle['fd'])


@pytest.mark.parametrize('failure_call', [1, 2], ids=['discovery_clause', 'owned_clause'])
def test_diagnostic_program_failure_is_translated_before_stop_clause_and_retries(tmp_path, failure_call):
    import subprocess

    class DiagnosticStop(RecordedStop):
        census_calls = 0

        def process_census(self, session):
            self.census_calls += 1
            if self.census_calls == failure_call:
                return self.ps_census()
            return super().process_census(session)

    attempted, diagnostics, records, refusals = [], [], [], []

    class EmptyScopeOS(census.SystemCalls):
        def pidfd_open(self, pid):
            attempted.append(pid)
            pytest.fail('empty scope opened a pidfd')

    def process_rows(pid):
        diagnostics.append(pid)
        raise subprocess.SubprocessError('untrusted diagnostic program failure')

    binding = dict(host='codex-cli', session='session-a', generation=1)
    core = DiagnosticStop(hosts, roles=RoleTables(), system=EmptyScopeOS(),
        ports=stopping.StopPorts(bound_session=lambda *args: (dict(binding), None),
            profile_mode=lambda profile: None, native_host='codex', process_rows=process_rows),
        signals=SimpleNamespace(pidfd_send_signal=lambda *args: attempted.append(args)))
    if not core.launch_descriptor_capable():
        pytest.skip('descriptor-relative stop unavailable')
    mailbox_root = tmp_path / 'mailbox'
    (mailbox_root / 'bindings' / 'team' / 'lane' / 'worker').mkdir(parents=True)

    def record(endpoint, identifier, action, state, **details):
        result = dict(endpoint=endpoint, action=action, state=state, **details)
        records.append(result)
        return result

    def refuse(endpoint, identifier, action, error, **known):
        refusals.append(dict(endpoint=endpoint, identifier=identifier, action=action, error=error, **known))
        raise census.SessionRefused()

    launches = SimpleNamespace(base=tmp_path, mailbox=SimpleNamespace(root=mailbox_root),
        resolve=lambda endpoint: endpoint, new_id=lambda: 'outcome', binding=lambda endpoint: dict(binding),
        record=record, refuse=refuse)
    with pytest.raises(census.SessionRefused) as caught:
        core.stop(launches, 'team/lane/worker', 0)
    assert type(caught.value) is census.SessionRefused and caught.value.code == 'invalid_evidence'
    assert caught.value.next_action and 'untrusted' not in str(caught.value)
    assert refusals == [dict(endpoint='team/lane/worker', identifier='outcome', action='stop',
                             error=census.SessionRefused().reason, **binding)]
    assert diagnostics == [None] and core.census_calls == failure_call
    assert attempted == records == []
    code, retried = core.stop(launches, 'team/lane/worker', 0)
    assert code == 0 and retried['state'] == 'not_running' and retried['pids'] == []
    assert attempted == [] and records == [retried] and diagnostics == [None]


@pytest.mark.parametrize('raw', [b'worker\0' + b'y' * 100, b'worker\0session-a\0tail',
                               b'worker\0' + b'y' * (262144 - len(b'worker\0'))],
                         ids=['unread-tail', 'captured-session', 'reader-cap'])
@pytest.mark.parametrize('owner,appearance', [(True, 1), (True, 2), (True, 3), (False, 1), (False, 2)])
def test_partial_cmdline_remains_unresolved_without_vetoing_host(tmp_path, raw, owner, appearance):
    from tests.unit.core.test_team_session_census import partial_sample
    sample = partial_sample(raw)
    extra = row(42, parent=41, argv=('worker',))
    snapshots = ([row()] if owner else []) + [extra]
    with stop_fixture(tmp_path, snapshots, {42: sample}, appearance=appearance) as (core, launches, signals, _):
        code, result = core.stop(launches, 'team/lane/worker', 0)
        assert code == 3 and result['state'] == 'stop_failed' and 42 in result['unresolved_pids']
        assert signals == ([(41, 15)] if owner else [])
        reason = next(item['reason'] for item in result['unresolved'] if item['pid'] == 42)
        assert reason == 'cmdline_unavailable'
        core.exited.add(42)
        core.unavailable = {}
        retry_code, retry_result = core.stop(launches, 'team/lane/worker', 0)
        assert retry_code == 0 and retry_result['state'] == ('stopped' if owner else 'not_running')


def test_unstable_partial_uid_cannot_latch_identity_loss_and_prevent_retry():
    core, state, signals = scenario(lambda pid: 77)
    core.observer = lambda *args: census.ProcessObservation('UNAVAILABLE', 41,
        partial=dict(coherent_birth=False, uid=1001, euid=1001), reason='unstable birth evidence')
    assert core.signal_process([row()], 15, 'proven', 'session-a', 'codex-cli', [], observed=state) is False
    assert state['identity_lost'] == state['blocked'] == set() and signals == []
    core.observer = lambda *args: census.ProcessObservation('PRESENT', 41, row())
    assert core.signal_process([row()], 15, 'proven', 'session-a', 'codex-cli', [], observed=state) == 'sent'
    assert signals == [(77, 15)]
    for handle in state['handles'].values():
        core.os.close(handle['fd'])


@pytest.mark.parametrize('missing', ['uid', 'euid', 'both'])
def test_partial_exit_requires_complete_uid_evidence_before_resolving(missing):
    core, state, signals = scenario()
    facts = dict(row()._asdict(), coherent_birth=True, exit_observed=True)
    for field in ['uid', 'euid'] if missing == 'both' else [missing]:
        facts.pop(field)
    state.update(candidates={41: None}, initial_unavailable={41: dict(row()._asdict(), coherent_birth=True)},
                 excluded=set(), owned_groups=set())
    core.observer = lambda *args: census.ProcessObservation('UNAVAILABLE', 41, partial=facts, reason='missing UIDs')
    assert core.gone_within('session-a', set(), set(), 0, 'codex-cli', state, []) is False
    assert state['resolved'] == {} and 41 in state['unresolved'] and signals == []
    core.observer = lambda *args: census.ProcessObservation('CONFIRMED_ABSENT', 41, proof='qualified_namespace_ESRCH')
    assert core.gone_within('session-a', set(), set(), 0, 'codex-cli', state, []) is True


@pytest.mark.parametrize('unstable_side', ['current', 'original'])
def test_unstable_partial_uid_in_exit_poll_does_not_exclude_future_retry(unstable_side):
    core, state, signals = scenario()
    state.update(candidates={41: None}, initial_unavailable={41: dict(row()._asdict(), coherent_birth=True)},
                 excluded=set(), owned_groups=set())
    facts = dict(uid=1001, euid=1001, coherent_birth=False)
    if unstable_side == 'original':
        state['initial_unavailable'][41]['coherent_birth'] = False
        facts.update(start_time='456', coherent_birth=True)
    core.observer = lambda *args: census.ProcessObservation('UNAVAILABLE', 41,
        partial=facts, reason='unstable birth evidence')
    assert core.gone_within('session-a', set(), set(), 0, 'codex-cli', state, []) is False
    assert state['blocked'] == state['identity_lost'] == set() and signals == []


def test_census_uid_witness_cannot_replace_unknown_original_birth():
    class WitnessStop(RecordedStop):
        def process_census(self, session):
            foreign = row(birth='456')._replace(uid=1001, euid=1001)
            return census.ProcessCensus([foreign], 'proven')
    core = WitnessStop(hosts, roles=RoleTables(), system=SimpleNamespace(geteuid=lambda: 1000))
    _, state, _ = scenario()
    state.update(candidates={41: None}, initial_unavailable={41: dict(uid=1000, euid=1000, coherent_birth=False)},
                 excluded=set())
    assert core.refresh_stop_scope(state, 'session-a', 'codex-cli', []) == []
    assert state['identity_lost'] == state['blocked'] == set()
    assert state['candidates'][41] is None and state['resolved'] == {}


@pytest.mark.parametrize('owner', [True, False])
@pytest.mark.parametrize('shape', ['complete', 'foreign'])
def test_complete_irrelevant_and_foreign_partial_rows_do_not_hold_stop(tmp_path, owner, shape):
    from tests.unit.core.test_team_session_census import partial_sample
    sample = partial_sample(b'worker\0session-a' if shape == 'foreign' else b'worker\0other\0',
                            uid=1001 if shape == 'foreign' else 1000)
    extra = row(42, parent=1, group=42, argv=('worker', 'other'))
    if shape == 'complete':
        sample = unavailable_row(sample.snapshot)
    with stop_fixture(tmp_path, ([row()] if owner else []) + [extra], {42: sample}) as (core, launches, signals, _):
        code, result = core.stop(launches, 'team/lane/worker', 0)
        assert code == 0 and result['state'] == ('stopped' if owner else 'not_running')
        assert signals == ([(41, 15)] if owner else [])
        assert 42 not in result.get('unresolved_pids', [])
