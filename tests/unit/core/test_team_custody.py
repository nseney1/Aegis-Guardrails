"""Tested-byte commits through the custodian's public boundary."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import errno
import os
import time
from threading import Barrier, Event
from types import SimpleNamespace

import pytest

from aegis_core import gitsafe, storage, team, team_git, team_gitops, team_lease_custody, team_qualify
from aegis_core import team_custody as custody
from aegis_core.errors import LockTimeoutError
from tests.conftest import symlink_or_skip
from tests.helpers_team_git import IDENTITY, copied_rig, git, make_store, rig_template, state


@pytest.fixture
def rig(tmp_path, rig_template):
    # The shared module-scoped template is copied, never rebuilt per test.
    with copied_rig(rig_template, tmp_path) as candidate:
        candidate.journal = team_gitops.GitOpsJournal(candidate.repo / ".git")
        yield candidate


def run(rig, **changes):
    options = dict(rig.options, identity=IDENTITY, journal=rig.journal,
                   request_id="commit-1", actor="custodian", governance_check=lambda commit, tree: True)
    return custody.commit(rig.store, **{**options, **changes})


def results(rig):
    return [row for row in rig.journal.read().rows
            if row["op"] == "commit" and row["kind"] == "result"]


@pytest.fixture
def terminal_observation(rig, monkeypatch):
    """Successful concurrent recovery waits for durable completion, not host speed."""
    terminal, waiting = Event(), Event()
    clock = _ObservationClock()
    # One real watchdog covers every participant, including sequential waits.
    # Progress still depends on events; custody's observation clock is separate.
    deadline = time.monotonic() + 60.0
    def remaining():
        return max(0.0, deadline - time.monotonic())
    class TerminalJournal(team_gitops.GitOpsJournal):
        def reconcile(self, *args, **kwargs):
            rows = super().reconcile(*args, **kwargs)
            if any(row["op"] == "commit" and row["kind"] in ("result", "tombstone")
                   for row in (rows or self.read().rows)):
                terminal.set()
            return rows
    def wait_for_terminal(delay):
        waiting.set()
        assert terminal.wait(remaining()), "the binding owner did not publish a terminal record"
        clock.sleep(delay)
    rig.journal = TerminalJournal(rig.journal.common_dir)
    monkeypatch.setattr(custody, "team_gitops", SimpleNamespace(
        GitOpsJournal=TerminalJournal, GitOpsError=team_gitops.GitOpsError, Observation=team_gitops.Observation))
    # Only custody's observation clock is paused. Journal locks and Event waits
    # retain real bounded timeouts; timeout/refusal tests use their own clocks.
    monkeypatch.setattr(custody, "time", SimpleNamespace(
        monotonic=clock.monotonic, sleep=wait_for_terminal))
    return SimpleNamespace(waiting=waiting, remaining=remaining)


class _ObservationClock:
    """Monotonic seam: sleep advances this clock and does not call time.sleep."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, delay):
        if delay < 0:
            raise AssertionError("observation sleep must be non-negative")
        self.sleeps.append(delay)
        self.now += delay


def _expected_observation_sleeps():
    """Steps the named window must sleep: double from the initial poll, clip to the cap and deadline."""
    now, delay = 0.0, custody.OBSERVATION_POLL_SECONDS
    deadline = custody.OBSERVATION_SECONDS
    steps = []
    while now < deadline:
        step = min(delay, custody.OBSERVATION_POLL_MAX_SECONDS, deadline - now)
        if step <= 0:
            break
        steps.append(step)
        now += step
        delay = min(delay * 2.0, custody.OBSERVATION_POLL_MAX_SECONDS)
    return steps


def test_commit_exact_tested_bytes_and_retry_once(rig):
    index = (rig.repo / ".git/index").read_bytes()
    work = (rig.repo / "src/a.py").read_bytes()
    before = state(rig)
    calls = []
    def governance(commit, tree):
        assert state(rig) == before
        assert rig.store.object(commit, "commit").startswith(("tree " + tree + "\n").encode())
        calls.append((commit, tree))
        return True
    first = run(rig, governance_check=governance)
    assert first.status == "committed"
    assert first.tree == rig.options["tested_tree"]
    assert git(rig.repo, "rev-parse", "HEAD").decode().strip() == first.commit
    assert git(rig.repo, "rev-parse", "HEAD^{tree}").decode().strip() == first.tree
    assert git(rig.repo, "rev-parse", "HEAD^").decode().strip() == rig.options["expected_head"]
    assert (rig.repo / ".git/index").read_bytes() == index
    assert (rig.repo / "src/a.py").read_bytes() == work
    assert calls == [(first.commit, first.tree)]
    after = state(rig)
    retry = run(rig, governance_check=lambda commit, tree: pytest.fail("retry ran governance"))
    assert retry.status == "committed_recovered" and retry.commit == first.commit
    assert len(results(rig)) == 1 and results(rig)[0]["status"] == "done"
    assert state(rig) == after


def test_lease_custody_checks_open_parent_and_recovers_after_refusal(rig, monkeypatch):
    if not team_lease_custody.descriptor_supported():
        pytest.skip("requires parent-addressable lease descriptors")
    boundary = team_lease_custody.storage_confined
    closed, acquired = True, []

    @contextmanager
    def confined(*args, **kwargs):
        with boundary.confined_file(*args, **kwargs) as handle:
            fd = handle.parent_fd
            acquired.append(fd)
            assert not os.get_inheritable(fd)
            if not closed:
                yield SimpleNamespace(parent_fd=fd)
                return
        yield handle

    monkeypatch.setattr(team_lease_custody, "storage_confined", SimpleNamespace(
        **{**vars(boundary), "confined_file": confined}))
    with pytest.raises(gitsafe.GitError, match="^liveness_unknown$") as error:
        with team.lease_custody(rig.repo):
            pytest.fail("lease custody accepted a closed parent")
    assert error.value.code == "git_failed"

    closed = False
    with team.lease_custody(rig.repo):
        team.verify_lease_repository(rig.repo)
        head = gitsafe.run_checked(["rev-parse", "HEAD"], rig.repo).stdout.strip()
        assert head == rig.options["expected_head"].encode()
    assert acquired
    for fd in set(acquired):
        with pytest.raises(OSError) as error:
            os.fstat(fd)
        assert error.value.errno == errno.EBADF


@pytest.mark.parametrize("decision", [False, None, 1, "yes", "exception"])
def test_governance_requires_explicit_true_and_failure_is_retryable(rig, decision):
    before = state(rig)
    def governance(commit, tree):
        if decision == "exception":
            raise RuntimeError("untrusted failure detail")
        return decision
    with pytest.raises(custody.CommitRefused) as caught:
        run(rig, governance_check=governance)
    assert caught.value.code == "governance_refused"
    assert str(caught.value) == custody.REFUSALS["governance_refused"]
    assert caught.value.next_action == {
        "actor": "custodian",
        "command": "obtain governance approval for the tested bytes before retrying commit custody",
    }
    assert state(rig) == before
    assert run(rig).status == "committed"


@pytest.mark.parametrize("changes,code", [
    ({"owner": "other"}, "lease_not_live"),
    ({"read_branch": lambda: "other"}, "branch_mismatch"),
    ({"expected_head": "a" * 40}, "head_mismatch"),
    ({"tested_tree": "a" * 40}, "tree_mismatch"),
    ({"required_legs": ("missing",)}, "not_qualified"),
    ({"read_paths": lambda old, new: ("outside",)}, "path_outside_lease"),
    ({"message": "Aegis-Approve: forged\n"}, "invalid_message"),
])
def test_preconditions_refuse_before_governance_and_any_ref_move(rig, changes, code):
    before = state(rig)
    for _ in range(2):
        with pytest.raises(custody.CustodyRefused) as caught:
            run(rig, **changes, governance_check=lambda commit, tree: pytest.fail("governance ran"))
        assert caught.value.code == code
        assert state(rig) == before
    assert run(rig).status == "committed"


def test_unsupported_platform_refuses_without_git_or_journal(monkeypatch):
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(descriptor_support=lambda: False))
    with pytest.raises(custody.CommitRefused) as caught:
        custody.commit(None, lane=None, owner=None, expected_head=None, tested_tree=None,
                       required_legs=(), message=None, identity=None, journal=None, request_id=None,
                       actor=None, read_branch=None, read_head=None, read_paths=None, read_policy=None,
                       governance_check=None)
    assert caught.value.code == "unsupported_platform"
    assert str(caught.value) == custody.REFUSALS["unsupported_platform"]
    assert caught.value.next_action == {
        "actor": "custodian",
        "command": "use a host with descriptor-relative commit custody support",
    }


def test_governance_race_cannot_overwrite_concurrent_ref(rig):
    winner = team_git.commit_tested(rig.store, rig.options["tested_tree"],
                                    rig.options["expected_head"], "winner", IDENTITY)
    def governance(commit, tree):
        team_git.cas_fast_forward(rig.store, "refs/heads/lane/work", rig.options["expected_head"], winner)
        return True
    with pytest.raises(custody.CommitRefused) as caught:
        run(rig, governance_check=governance)
    assert caught.value.code == "cas_mismatch"
    assert caught.value.next_action == {
        "actor": "custodian",
        "command": "inspect the lane ref and terminal commit result; never repeat this request's effect",
    }
    assert git(rig.repo, "rev-parse", "HEAD").decode().strip() == winner
    assert len(results(rig)) == 1 and results(rig)[0]["status"] == "unknown"
    with pytest.raises(custody.CommitRefused) as caught:
        run(rig)
    assert caught.value.code == "request_closed"
    assert caught.value.next_action == {
        "actor": "custodian",
        "command": "inspect the terminal commit result; never retry this request's effect",
    }
    assert len(results(rig)) == 1


def test_crash_after_cas_recovers_without_second_effect(rig, monkeypatch):
    real = team_git.cas_fast_forward
    calls = []
    class Crash(BaseException):
        pass
    def lost_reply(*args, **kwargs):
        calls.append(1)
        real(*args, **kwargs)
        raise Crash()
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(**{**vars(team_git), "cas_fast_forward": lost_reply}))
    with pytest.raises(Crash):
        run(rig)
    assert not results(rig)
    assert run(rig).status == "committed_recovered"
    assert run(rig).status == "committed_recovered"
    assert calls == [1] and len(results(rig)) == 1


@pytest.mark.parametrize("code", (
    "ref_update_unknown", "git_cleanup_failed", "git_timeout", "git_output_limit"))
@pytest.mark.parametrize("applied", [False, True])
def test_unknown_transport_is_observed_never_repeated(rig, monkeypatch, applied, code):
    real = team_git.cas_fast_forward
    calls = []
    def unknown(*args, **kwargs):
        calls.append(1)
        if applied:
            real(*args, **kwargs)
        raise team_git.GitRefusal(code)
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(**{**vars(team_git), "cas_fast_forward": unknown}))
    with pytest.raises(custody.CommitRefused) as caught:
        run(rig)
    assert caught.value.code == "ref_update_unknown"
    assert str(caught.value) == custody.REFUSALS["ref_update_unknown"]
    assert code not in str(caught.value)
    assert caught.value.next_action == {
        "actor": "custodian",
        "command": "inspect the commit intent and reconcile by observation; never repeat its effect",
    }
    if applied:
        assert run(rig).status == "committed_recovered"
    else:
        with pytest.raises(custody.CommitRefused) as caught:
            run(rig)
        assert caught.value.code == "request_closed"
        assert str(caught.value) == custody.REFUSALS["request_closed"]
        assert code not in str(caught.value)
    assert calls == [1] and len(results(rig)) == 1


def test_two_callers_same_request_get_one_effect_and_one_result(rig, monkeypatch):
    entered, release = Event(), Event()
    real = team_git.cas_fast_forward
    calls = []
    def blocked(*args, **kwargs):
        calls.append(1)
        entered.set()
        assert release.wait(10)
        return real(*args, **kwargs)
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(**{**vars(team_git), "cas_fast_forward": blocked}))
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run, rig)
        try:
            assert entered.wait(10)
            with pytest.raises(custody.CommitRefused) as caught:
                pool.submit(run, rig).result(timeout=10)
            assert caught.value.code == "ref_update_unknown"
            assert caught.value.next_action == {
                "actor": "custodian",
                "command": "inspect the commit intent and reconcile by observation; never repeat its effect",
            }
            assert not results(rig)
        finally:
            release.set()
        assert first.result(timeout=15).status == "committed"
    assert run(rig).status == "committed_recovered"
    assert calls == [1] and len(results(rig)) == 1


def test_retry_changed_binding_refuses_without_effect(rig):
    run(rig)
    before = state(rig)
    with pytest.raises(custody.CommitRefused) as caught:
        run(rig, message="different")
    assert caught.value.code == "request_conflict"
    assert caught.value.next_action == {
        "actor": "custodian",
        "command": "inspect the recorded request binding and restore its original inputs; never repeat its effect",
    }
    assert state(rig) == before and len(results(rig)) == 1


@pytest.mark.parametrize("new", ["a" * 40, {"ref": "refs/heads/lane/work"},
                                 {"head": "a" * 40}], ids=["oid", "missing-head", "missing-ref"])
def test_other_commit_intent_shape_refuses_without_raw_exception(rig, new):
    with rig.journal.record_intent(op="commit", lane="work", request_id="commit-1",
                                  actor="custodian", expected_old=rig.options["expected_head"],
                                  expected_new=new):
        pass
    before = state(rig)
    for _ in range(2):
        with pytest.raises(custody.CommitRefused) as caught:
            run(rig)
        assert caught.value.code == "request_conflict"
    assert state(rig) == before and not results(rig)


@pytest.mark.parametrize("field,value", [("request_id", None), ("request_id", "x" * 129),
                                       ("request_id", "bad\nvalue"), ("actor", "bad\nvalue")])
def test_invalid_request_fields_refuse_before_store_access(monkeypatch, field, value):
    options = dict(lane=None, owner=None, expected_head=None, tested_tree=None, required_legs=(),
                   message=None, identity=None, journal=None, request_id="commit-1", actor="custodian",
                   read_branch=None, read_head=None, read_paths=None, read_policy=None, governance_check=None)
    options[field] = value
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(descriptor_support=lambda: True))
    monkeypatch.setattr(custody, "team_qualify", SimpleNamespace(descriptor_supported=lambda: True))
    for _ in range(2):
        with pytest.raises(custody.CommitRefused) as caught:
            custody.commit(None, **options)
        assert caught.value.code == "invalid_request"
        assert str(caught.value) == custody.REFUSALS["invalid_request"]
        assert caught.value.next_action == {
            "actor": "custodian",
            "command": "provide valid commit request and actor identifiers",
        }


@pytest.mark.parametrize("kind", ["wrong-type", "unreadable"])
def test_journal_gate_advice_precedes_store_access_and_is_repeatable(monkeypatch, kind):
    class UnreadableJournal:
        def read(self):
            raise team_gitops.GitOpsError("journal_io")
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(descriptor_support=lambda: True))
    monkeypatch.setattr(custody, "team_qualify", SimpleNamespace(descriptor_supported=lambda: True))
    monkeypatch.setattr(custody, "team_gitops", SimpleNamespace(
        GitOpsJournal=UnreadableJournal, GitOpsError=team_gitops.GitOpsError))
    journal = object() if kind == "wrong-type" else UnreadableJournal()
    for _ in range(2):
        with pytest.raises(custody.CommitRefused) as caught:
            custody.commit(None, lane=None, owner=None, expected_head=None, tested_tree=None,
                           required_legs=(), message=None, identity=None, journal=journal,
                           request_id="commit-1", actor="custodian", read_branch=None, read_head=None,
                           read_paths=None, read_policy=None, governance_check=None)
        assert caught.value.code == "journal_failed"
        assert str(caught.value) == custody.REFUSALS["journal_failed"]
        assert caught.value.next_action == {
            "actor": "custodian",
            "command": "restore journal access and reconcile by observation; never repeat an existing intent's effect",
        }


def test_failed_result_append_is_recovered_without_repeating_cas(rig, monkeypatch):
    class UnavailableJournal:
        common_dir = rig.journal.common_dir
        def admission(self):
            return rig.journal.admission()
        def read(self):
            return rig.journal.read()
        def record_intent(self, **kwargs):
            return rig.journal.record_intent(**kwargs)
        def reconcile(self, *args, **kwargs):
            raise team_gitops.GitOpsError("journal_io")
    facade = UnavailableJournal()
    monkeypatch.setattr(custody, "team_gitops", SimpleNamespace(
        GitOpsJournal=UnavailableJournal, GitOpsError=team_gitops.GitOpsError, Observation=team_gitops.Observation))
    with pytest.raises(custody.CommitRefused) as caught:
        run(rig, journal=facade)
    assert caught.value.code == "journal_failed"
    assert caught.value.next_action == {
        "actor": "custodian",
        "command": "restore journal access and reconcile by observation; never repeat an existing intent's effect",
    }
    assert not results(rig)
    monkeypatch.setattr(custody, "team_gitops", team_gitops)
    assert run(rig).status == "committed_recovered"
    assert len(results(rig)) == 1


def test_changed_worktree_and_expired_lease_do_not_obstruct_recovery(rig):
    first = run(rig)
    (rig.repo / "src/a.py").write_bytes(b"later untested bytes\n")
    retry = run(rig, now=1000)
    assert retry.status == "committed_recovered" and retry.commit == first.commit
    assert git(rig.repo, "show", "HEAD:src/a.py") == b"tested\n"
    assert len(results(rig)) == 1


def test_deleted_worktree_file_refuses_and_restored_bytes_retry(rig):
    (rig.repo / "src/a.py").unlink()
    with pytest.raises(custody.CustodyRefused) as caught:
        run(rig)
    assert caught.value.code == "tree_mismatch"
    assert not results(rig)
    (rig.repo / "src/a.py").write_bytes(b"tested\n")
    assert run(rig).status == "committed"


def test_returned_cas_with_live_holder_stays_unknown_until_holder_closes(rig, monkeypatch):
    real = team_git.cas_fast_forward
    held = []
    calls = []
    def retained(*args, **kwargs):
        calls.append(1)
        result = real(*args, **kwargs)
        held.append(os.dup(kwargs["effect_fds"][0]))
        return result
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(**{**vars(team_git), "cas_fast_forward": retained}))
    ticks = iter((0.0, custody.OBSERVATION_SECONDS + 1.0))
    def expired(delay):
        pytest.fail("a live holder made the observation window sleep")
    monkeypatch.setattr(custody, "time", SimpleNamespace(
        monotonic=lambda: next(ticks), sleep=expired))
    try:
        for _ in range(2):
            with pytest.raises(custody.CommitRefused) as caught:
                run(rig)
            assert caught.value.code == "ref_update_unknown"
            assert not results(rig)
    finally:
        for descriptor in held:
            os.close(descriptor)
    monkeypatch.setattr(custody, "time", time)
    assert run(rig).status == "committed_recovered"
    assert calls == [1] and len(results(rig)) == 1


@pytest.mark.parametrize("same_request", [True, False], ids=["same-request", "competing-requests"])
def test_simultaneous_governance_then_intent_race_preserves_cas_and_result_uniqueness(rig, same_request):
    gate = Barrier(2)
    def governance(commit, tree):
        gate.wait(timeout=10)
        return True
    options = dict(governance_check=governance)
    second_options = options if same_request else dict(options, request_id="commit-2", message="competing")
    # GitStore deliberately refuses simultaneous snapshots of one private index.
    # Independent callers own independent stores over the same repository.
    with make_store(rig.repo) as second_store, ThreadPoolExecutor(max_workers=2) as pool:
        other = SimpleNamespace(repo=rig.repo, store=second_store, options=rig.options, journal=rig.journal)
        pending = [pool.submit(run, candidate, **selected)
                   for candidate, selected in ((rig, options), (other, second_options))]
        statuses = []
        for future in pending:
            try:
                statuses.append(future.result(timeout=20).status)
            except custody.CommitRefused as exc:
                statuses.append(exc.code)
    if same_request:
        assert any(status in ("committed", "committed_recovered") for status in statuses)
        assert set(statuses) <= {"committed", "committed_recovered", "ref_update_unknown"}
        assert run(rig).status == "committed_recovered"
        assert len(results(rig)) == 1
    else:
        assert statuses.count("committed") == 1
        assert set(statuses) == {"committed", "cas_mismatch"}
        assert len(results(rig)) == 2
        assert sorted(row["status"] for row in results(rig)) == ["done", "unknown"]


def test_crash_before_cas_is_observed_not_retried(rig, monkeypatch):
    calls = []
    class Crash(BaseException):
        pass
    def crash(*args, **kwargs):
        calls.append(1)
        raise Crash()
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(**{**vars(team_git), "cas_fast_forward": crash}))
    with pytest.raises(Crash):
        run(rig)
    for _ in range(2):
        with pytest.raises(custody.CommitRefused) as caught:
            run(rig)
        assert caught.value.code == "request_closed"
    assert calls == [1] and len(results(rig)) == 1
    assert results(rig)[0]["status"] == "not_applied"
    assert git(rig.repo, "rev-parse", "HEAD").decode().strip() == rig.options["expected_head"]


def test_distinct_request_ids_for_identical_commit_share_one_operation(rig, monkeypatch,
                                                                     terminal_observation):
    remaining = terminal_observation.remaining
    gate = Barrier(2)
    calls = []
    real = team_git.cas_fast_forward
    def observed(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)
    def governance(commit, tree):
        gate.wait(timeout=remaining())
        return True
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(**{**vars(team_git), "cas_fast_forward": observed}))
    with make_store(rig.repo) as second_store, ThreadPoolExecutor(max_workers=2) as pool:
        other = SimpleNamespace(repo=rig.repo, store=second_store, options=rig.options, journal=rig.journal)
        pending = [pool.submit(run, candidate, request_id=request, governance_check=governance)
                   for candidate, request in ((rig, "commit-1"), (other, "commit-2"))]
        outcomes = [future.result(timeout=remaining()) for future in pending]
    rows = [row for row in rig.journal.read().rows if row["op"] == "commit"]
    assert [row["kind"] for row in rows] == ["intent", "result"]
    assert calls == [1]
    assert outcomes[0].commit == outcomes[1].commit
    assert outcomes[0].tree == outcomes[1].tree == rig.options["tested_tree"]
    assert sorted(item.status for item in outcomes) == ["committed", "committed_recovered"]
    for request in ("commit-1", "commit-2", "commit-3"):
        recovered = run(rig, request_id=request, governance_check=lambda commit, tree: pytest.fail("duplicate ran governance"))
        assert recovered.status == "committed_recovered" and recovered.commit == outcomes[0].commit
    assert len(results(rig)) == 1 and calls == [1]


@pytest.mark.parametrize("applied", [False, True])
def test_distinct_request_attaches_to_interrupted_binding_without_new_effect(rig, monkeypatch, applied):
    real = team_git.cas_fast_forward
    calls = []
    def unknown(*args, **kwargs):
        calls.append(1)
        if applied:
            real(*args, **kwargs)
        raise team_git.GitRefusal("ref_update_unknown")
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(**{**vars(team_git), "cas_fast_forward": unknown}))
    with pytest.raises(custody.CommitRefused) as caught:
        run(rig)
    assert caught.value.code == "ref_update_unknown"
    (rig.repo / "src/a.py").write_bytes(b"later untested bytes\n")
    for request in ("commit-2", "commit-3"):
        if applied:
            assert run(rig, request_id=request, now=1000).status == "committed_recovered"
        else:
            with pytest.raises(custody.CommitRefused) as caught:
                run(rig, request_id=request, now=1000)
            assert caught.value.code == "request_closed"
    rows = [row for row in rig.journal.read().rows if row["op"] == "commit"]
    assert [row["kind"] for row in rows] == ["intent", "result"]
    assert calls == [1]


@pytest.mark.parametrize("phase", ["open", "lock"])
def test_binding_lock_failures_close_descriptors_and_allow_clean_retry(rig, monkeypatch, phase):
    opened = []
    real_open = os.open
    def observed_open(*args, **kwargs):
        if phase == "open" and args[0] == "gitops.jsonl" and args[1] & os.O_RDWR:
            raise OSError("untrusted failure detail")
        descriptor = real_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor
    def failed_lock(*args, **kwargs):
        raise LockTimeoutError("untrusted failure detail")
    monkeypatch.setattr(team_gitops, "os", SimpleNamespace(**{**vars(os), "open": observed_open}))
    if phase == "lock":
        monkeypatch.setattr(team_gitops, "storage", SimpleNamespace(**{**vars(storage), "file_lock": failed_lock,
            "confined_descriptor_supported": storage.confined_descriptor_supported}))
    before = state(rig)
    with pytest.raises(custody.CommitRefused) as caught:
        run(rig)
    assert caught.value.code == "journal_failed"
    assert str(caught.value) == custody.REFUSALS["journal_failed"]
    assert opened and state(rig) == before and not results(rig)
    for descriptor in opened:
        with pytest.raises(OSError) as closed:
            os.fstat(descriptor)
        assert closed.value.errno == errno.EBADF
    monkeypatch.setattr(team_gitops, "os", os)
    monkeypatch.setattr(team_gitops, "storage", storage)
    assert run(rig).status == "committed"


def test_binding_lock_symlink_refuses_without_touching_target_and_retry_succeeds(rig):
    target = rig.repo.parent / "outside-lock"
    target.write_bytes(b"untouched\n")
    link = rig.repo / ".git/aegis/gitops.lock"
    link.unlink()  # The fixture's qualification created this existing lock.
    symlink_or_skip(target, link)
    for _ in range(2):
        with pytest.raises(custody.CommitRefused) as caught:
            run(rig)
        assert caught.value.code == "journal_failed"
        assert target.read_bytes() == b"untouched\n" and not results(rig)
    link.unlink()
    assert run(rig).status == "committed"


def test_binding_lock_stays_on_opened_directory_during_rename_and_symlink_swap(rig, monkeypatch):
    original = rig.repo / ".git"
    parked = rig.repo.parent / "parked-git"
    outside = rig.repo.parent / "outside"
    outside.mkdir()
    @contextmanager
    def swapped(lock_path, *, timeout, dir_fd):
        original.rename(parked)
        try:
            symlink_or_skip(outside, original, target_is_directory=True)
            with storage.file_lock(lock_path, timeout=timeout, dir_fd=dir_fd):
                assert (parked / "aegis/gitops.lock").is_file()
                assert list(outside.iterdir()) == []
                yield
        finally:
            if original.is_symlink():
                original.unlink()
            parked.rename(original)
    monkeypatch.setattr(team_gitops, "storage", SimpleNamespace(**{**vars(storage), "file_lock": swapped,
        "confined_descriptor_supported": storage.confined_descriptor_supported}))
    with pytest.raises(custody.CommitRefused) as caught:
        run(rig)
    assert caught.value.code == "journal_failed"
    assert list(outside.iterdir()) == [] and not results(rig)
    monkeypatch.setattr(team_gitops, "storage", storage)
    assert run(rig).status == "committed"


def test_already_acknowledgment_is_recovered_only_by_binding_owner(rig, monkeypatch):
    real = team_git.cas_fast_forward
    calls = []
    def already(*args, **kwargs):
        intents = [row for row in rig.journal.read().rows if row["op"] == "commit"]
        assert len(intents) == 1 and intents[0]["kind"] == "intent"
        calls.append(1)
        real(*args, **kwargs)
        return "already"
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(**{**vars(team_git), "cas_fast_forward": already}))
    original = run(rig)
    assert original.status == "committed_recovered"
    duplicate = run(rig, request_id="commit-2")
    assert duplicate == original and calls == [1] and len(results(rig)) == 1


def test_duplicate_branch_reader_failure_has_fixed_refusal_and_retry(rig):
    original = run(rig)
    before = state(rig)
    def failed_branch():
        raise OSError("untrusted failure detail")
    with pytest.raises(custody.CustodyRefused) as caught:
        run(rig, request_id="commit-2", read_branch=failed_branch)
    assert caught.value.code == "branch_mismatch"
    assert str(caught.value) == "worktree branch differs from the lane lease"
    assert state(rig) == before
    recovered = run(rig, request_id="commit-2")
    assert recovered.commit == original.commit and recovered.status == "committed_recovered"
    assert len(results(rig)) == 1


def test_foreign_journal_admission_race_preserves_request_conflict_and_retry(rig, monkeypatch):
    class CollisionJournal:
        common_dir = rig.journal.common_dir
        def admission(self):
            return rig.journal.admission()
        def read(self):
            return rig.journal.read()
        def record_intent(self, **kwargs):
            with rig.journal.record_intent(op="ref_update", lane="work", request_id=kwargs["request_id"],
                                          actor="other", expected_old=None,
                                          expected_new=rig.options["expected_head"]):
                pass
            return rig.journal.record_intent(**kwargs)
    monkeypatch.setattr(custody, "team_gitops", SimpleNamespace(
        GitOpsJournal=CollisionJournal, GitOpsError=team_gitops.GitOpsError, Observation=team_gitops.Observation))
    with pytest.raises(custody.CommitRefused) as caught:
        run(rig, journal=CollisionJournal())
    assert caught.value.code == "request_conflict"
    assert str(caught.value) == custody.REFUSALS["request_conflict"]
    assert not results(rig)
    assert git(rig.repo, "rev-parse", "HEAD").decode().strip() == rig.options["expected_head"]
    monkeypatch.setattr(custody, "team_gitops", team_gitops)
    with pytest.raises(custody.CommitRefused) as caught:
        run(rig)
    assert caught.value.code == "request_conflict"
    assert run(rig, request_id="commit-2").status == "committed"


def test_distinct_request_waits_for_active_binding_owner_then_recovers(rig, monkeypatch,
                                                                     terminal_observation):
    remaining = terminal_observation.remaining
    entered, release, alias_waiting = Event(), Event(), Event()
    calls = []
    real_cas = team_git.cas_fast_forward
    def blocked(*args, **kwargs):
        calls.append(1)
        entered.set()
        assert release.wait(remaining())
        return real_cas(*args, **kwargs)
    class ObservedJournal:
        @contextmanager
        def admission(self):
            with rig.journal.admission():
                if entered.is_set():
                    alias_waiting.set()
                yield self
        def read(self):
            return rig.journal.read()
        def record_intent(self, **kwargs):
            return rig.journal.record_intent(**kwargs)
        def reconcile(self, *args, **kwargs):
            return rig.journal.reconcile(*args, **kwargs)
    observed = ObservedJournal()
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(**{**vars(team_git), "cas_fast_forward": blocked}))
    monkeypatch.setattr(custody, "team_gitops", SimpleNamespace(
        GitOpsJournal=ObservedJournal, GitOpsError=team_gitops.GitOpsError, Observation=team_gitops.Observation))
    with make_store(rig.repo) as second_store, ThreadPoolExecutor(max_workers=2) as pool:
        other = SimpleNamespace(repo=rig.repo, store=second_store, options=rig.options, journal=rig.journal)
        first = pool.submit(run, rig, journal=observed)
        try:
            assert entered.wait(remaining())
            second = pool.submit(run, other, request_id="commit-2", journal=observed)
            assert alias_waiting.wait(remaining()), "the attached caller bypassed binding serialization"
            assert terminal_observation.waiting.wait(remaining()), "the attached caller did not observe the active binding"
        finally:
            release.set()
        original, recovered = first.result(timeout=remaining()), second.result(timeout=remaining())
    assert original.status == "committed" and recovered.status == "committed_recovered"
    assert recovered.commit == original.commit and recovered.tree == original.tree
    rows = [row for row in rig.journal.read().rows if row["op"] == "commit"]
    assert [row["kind"] for row in rows] == ["intent", "result"]
    assert calls == [1]
    assert run(rig, request_id="commit-2", journal=observed).status == "committed_recovered"
    assert calls == [1] and len(results(rig)) == 1


@pytest.mark.parametrize("missing", ["journal", "subreaper"])
def test_complete_platform_gate_refuses_before_any_git_or_journal_access(monkeypatch, missing):
    class NoAccessJournal:
        def read(self):
            pytest.fail("unsupported platform reached the journal")
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(descriptor_support=lambda: True))
    monkeypatch.setattr(custody, "team_gitops", SimpleNamespace(
        GitOpsJournal=NoAccessJournal, GitOpsError=team_gitops.GitOpsError))
    monkeypatch.setattr(team_qualify, "team_git", SimpleNamespace(descriptor_support=lambda: True))
    monkeypatch.setattr(team_qualify, "team_gitops", SimpleNamespace(descriptor_supported=lambda: missing != "journal"))
    monkeypatch.setattr(team_qualify, "gitops_fds", SimpleNamespace(descriptor_supported=lambda: missing != "subreaper"))
    with pytest.raises(custody.CommitRefused) as caught:
        custody.commit(None, lane="work", owner="team-1", expected_head=None, tested_tree=None,
                       required_legs=(), message=None, identity=None, journal=NoAccessJournal(),
                       request_id="commit-1", actor="custodian", read_branch=None, read_head=None,
                       read_paths=None, read_policy=None, governance_check=None)
    assert caught.value.code == "unsupported_platform"
    assert str(caught.value) == custody.REFUSALS["unsupported_platform"]


@pytest.mark.parametrize("changes", [
    {"lane": "../invalid"}, {"lane": "other"}, {"lane": None},
    {"expected_head": None}, {"expected_head": "a" * 40},
    {"actor": "other"}, {"actor": None}, {"actor": "bad\nvalue"},
], ids=["invalid-lane", "changed-lane", "missing-lane", "missing-parent", "changed-parent",
        "changed-actor", "missing-actor", "invalid-actor"])
def test_bound_input_conflict_precedes_any_recovery_git_work(rig, monkeypatch, changes):
    run(rig)
    before = state(rig)
    def forbidden(*args, **kwargs):
        pytest.fail("changed bound inputs reached recovery Git work")
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(**{**vars(team_git),
        "commit_tested": forbidden, "ref_oid": forbidden, "snapshot_tree": forbidden}))
    for _ in range(2):
        with pytest.raises(custody.CommitRefused) as caught:
            run(rig, **changes)
        assert caught.value.code == "request_conflict"
        assert str(caught.value) == custody.REFUSALS["request_conflict"]
    assert state(rig) == before and len(results(rig)) == 1
    monkeypatch.setattr(custody, "team_git", team_git)
    assert run(rig).status == "committed_recovered"


def test_public_journal_admission_nests_intent_and_releases_after_failure(rig):
    alternate = team_gitops.GitOpsJournal(rig.journal.common_dir)
    created = []
    def nested():
        with rig.journal.admission() as held, alternate.admission():
            assert held is rig.journal
            with alternate.record_intent(op="ref_update", lane="work", request_id="nested-admission",
                                         actor="custodian", expected_old=None,
                                         expected_new=rig.options["expected_head"]) as receipt:
                created.append(receipt.created)
                assert any(row["request_id"] == "nested-admission" for row in held.read().rows)
        return alternate.reconcile("work", lambda row: team_gitops.Observation(None),
                                   request_id="nested-admission")
    with ThreadPoolExecutor(max_workers=1) as pool:
        observed = pool.submit(nested).result(timeout=10)
    assert len(observed) == 1 and observed[0]["status"] == "not_applied"
    with pytest.raises(RuntimeError, match="^intentional caller failure$"):
        with rig.journal.admission():
            raise RuntimeError("intentional caller failure")
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(nested).result(timeout=10) == []
    assert created == [True, False]
    assert not (rig.repo / ".git/aegis-custody.lock").exists()


def test_admission_exit_failure_releases_receipt_without_running_effect(rig, monkeypatch):
    class FailingExitJournal:
        @contextmanager
        def admission(self):
            with rig.journal.admission():
                yield self
                raise team_gitops.GitOpsError("journal_io")
        def read(self):
            return rig.journal.read()
        def record_intent(self, **kwargs):
            return rig.journal.record_intent(**kwargs)
    def forbidden(*args, **kwargs):
        pytest.fail("admission exit failure permitted an effect")
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(**{**vars(team_git), "cas_fast_forward": forbidden}))
    monkeypatch.setattr(custody, "team_gitops", SimpleNamespace(
        GitOpsJournal=FailingExitJournal, GitOpsError=team_gitops.GitOpsError, Observation=team_gitops.Observation))
    with pytest.raises(custody.CommitRefused) as caught:
        run(rig, journal=FailingExitJournal())
    assert caught.value.code == "journal_failed"
    assert len(rig.journal.open_intents("work")) == 1
    assert rig.journal.in_flight("work") == []
    assert git(rig.repo, "rev-parse", "HEAD").decode().strip() == rig.options["expected_head"]
    monkeypatch.setattr(custody, "team_gitops", team_gitops)
    with pytest.raises(custody.CommitRefused) as caught:
        run(rig)
    assert caught.value.code == "request_closed"
    assert len(results(rig)) == 1 and results(rig)[0]["status"] == "not_applied"


def test_observation_window_backs_off_on_the_clock_seam(monkeypatch):
    """Waiting observation is immediate, then doubles until the named window, without process sleep."""
    clock = _ObservationClock()
    monkeypatch.setattr(custody, "time", clock)

    class Journal:
        def __init__(self, ready_at=None):
            self.ready_at = ready_at
            self.reads = 0

        def reconcile(self, lane, observe, request_id=None):
            self.reads += 1
            if self.ready_at is not None and clock.now >= self.ready_at:
                return [{"kind": "result", "request_id": request_id, "status": "done"}]
            return []

        def read(self):
            return SimpleNamespace(rows=[])

    expired = Journal()
    assert custody._terminal(None, expired, "work", "commit-1", "refs/heads/lane/work", wait=True) is None
    expected = _expected_observation_sleeps()
    assert clock.sleeps == expected
    assert expected[0] == custody.OBSERVATION_POLL_SECONDS
    assert expected[1] == custody.OBSERVATION_POLL_SECONDS * 2
    assert expected[2] == custody.OBSERVATION_POLL_SECONDS * 4
    assert expected[3] == custody.OBSERVATION_POLL_SECONDS * 8
    assert expected[4] == custody.OBSERVATION_POLL_MAX_SECONDS
    assert expected[-1] < custody.OBSERVATION_POLL_MAX_SECONDS
    assert clock.now == custody.OBSERVATION_SECONDS
    assert expired.reads == len(expected) + 1
    assert len(expected) < custody.OBSERVATION_SECONDS / custody.OBSERVATION_POLL_SECONDS
    slept = len(clock.sleeps)
    found = custody._terminal(None, Journal(ready_at=0.0), "work", "commit-1",
                              "refs/heads/lane/work", wait=True)
    assert found["status"] == "done" and len(clock.sleeps) == slept
    assert custody._terminal(None, Journal(), "work", "commit-1",
                             "refs/heads/lane/work", wait=False) is None
    assert len(clock.sleeps) == slept
    clock.now, clock.sleeps = 0.0, []
    raced = Journal(ready_at=custody.OBSERVATION_POLL_SECONDS)
    found = custody._terminal(None, raced, "work", "commit-2", "refs/heads/lane/work", wait=True)
    assert found == {"kind": "result", "request_id": "commit-2", "status": "done"}
    assert clock.sleeps == [custody.OBSERVATION_POLL_SECONDS]
    assert raced.reads == 2


def test_distinct_attachment_timeout_preserves_unknown_until_holder_exits(rig, monkeypatch):
    real = team_git.cas_fast_forward
    held, calls = [], []
    def unknown(*args, **kwargs):
        calls.append(1)
        real(*args, **kwargs)
        held.append(os.dup(kwargs["effect_fds"][0]))
        raise team_git.GitRefusal("ref_update_unknown")
    def forbidden_sleep(delay):
        pytest.fail("an expired observation deadline slept")
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(**{**vars(team_git), "cas_fast_forward": unknown}))
    try:
        with pytest.raises(custody.CommitRefused) as caught:
            run(rig)
        assert caught.value.code == "ref_update_unknown"
        ticks = iter((0.0, custody.OBSERVATION_SECONDS + 1.0))
        monkeypatch.setattr(custody, "time", SimpleNamespace(
            monotonic=lambda: next(ticks), sleep=forbidden_sleep))
        with pytest.raises(custody.CommitRefused) as caught:
            run(rig, request_id="commit-2")
        assert caught.value.code == "ref_update_unknown" and not results(rig)
    finally:
        for descriptor in held:
            os.close(descriptor)
    monkeypatch.setattr(custody, "time", time)
    assert run(rig, request_id="commit-2").status == "committed_recovered"
    assert calls == [1] and len(results(rig)) == 1


def test_public_journal_admission_unsupported_platform_does_not_open_state(tmp_path, monkeypatch):
    journal = team_gitops.GitOpsJournal(tmp_path)
    monkeypatch.setattr(team_gitops, "storage", SimpleNamespace(**{**vars(storage),
        "confined_descriptor_supported": lambda: False}))
    with pytest.raises(team_gitops.GitOpsError) as caught:
        with journal.admission():
            pytest.fail("unsupported admission entered its body")
    assert caught.value.code == "unsupported_platform"
    assert str(caught.value) == team_gitops.REFUSALS["unsupported_platform"]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("changes", [
    {"tested_tree": None}, {"tested_tree": "a" * 40},
    {"message": "\0"}, {"message": "different message"},
    {"message": "\ud800"}, {"message": "x" * (team_git.MAX_MESSAGE_BYTES + 1)},
    {"identity": None},
    {"identity": team_git.CommitIdentity("Other", IDENTITY.email, IDENTITY.date)},
    {"identity": team_git.CommitIdentity(None, IDENTITY.email, IDENTITY.date)},
], ids=["missing-tree", "changed-tree", "nul-message", "changed-message", "invalid-unicode-message",
        "oversized-message", "missing-identity", "changed-identity", "malformed-identity"])
def test_all_bound_commit_inputs_conflict_before_reconstruction(rig, monkeypatch, changes):
    run(rig)
    before = state(rig)
    def forbidden(*args, **kwargs):
        pytest.fail("different immutable input reached deterministic reconstruction")
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(**{**vars(team_git), "commit_tested": forbidden}))
    for _ in range(2):
        with pytest.raises(custody.CommitRefused) as caught:
            run(rig, **changes)
        assert caught.value.code == "request_conflict"
        assert str(caught.value) == custody.REFUSALS["request_conflict"]
    assert state(rig) == before and len(results(rig)) == 1
    monkeypatch.setattr(custody, "team_git", team_git)
    assert run(rig).status == "committed_recovered"


@pytest.mark.parametrize("matching,now,fail_refresh", [
    (True, 101, False), (True, 160, False), (False, 101, False), (True, 101, True),
], ids=["head-refusal", "lease-refusal", "nonmatching-commit", "journal-unavailable"])
def test_publication_after_initial_history_read_recovers_before_head_refusal(rig, monkeypatch,
                                                                          matching, now, fail_refresh):
    completed = []
    class InterleavedJournal:
        def __init__(self, stale=False, fail=False):
            self.stale = stale
            self.fail = fail
        def admission(self):
            if self.fail:
                raise team_gitops.GitOpsError("journal_io")
            return rig.journal.admission()
        def read(self):
            snapshot = rig.journal.read()
            if self.stale:
                self.stale = False
                completed.append(run(rig, journal=InterleavedJournal(), request_id="commit-A",
                    message=rig.options["message"] if matching else "another commit"))
            return snapshot
        def record_intent(self, **kwargs):
            return rig.journal.record_intent(**kwargs)
        def reconcile(self, *args, **kwargs):
            return rig.journal.reconcile(*args, **kwargs)
    monkeypatch.setattr(custody, "team_gitops", SimpleNamespace(
        GitOpsJournal=InterleavedJournal, GitOpsError=team_gitops.GitOpsError, Observation=team_gitops.Observation))
    if fail_refresh:
        with pytest.raises(custody.CommitRefused) as caught:
            run(rig, journal=InterleavedJournal(stale=True, fail=True), request_id="commit-B", now=now)
        assert caught.value.code == "journal_failed"
    elif not matching:
        with pytest.raises(custody.CustodyRefused) as caught:
            run(rig, journal=InterleavedJournal(stale=True), request_id="commit-B", now=now)
        assert caught.value.code == "head_mismatch"
        assert str(caught.value) == "worktree HEAD differs from the expected lane tip"
    else:
        recovered = run(rig, journal=InterleavedJournal(stale=True), request_id="commit-B", now=now)
        assert recovered.status == "committed_recovered"
        assert recovered.commit == completed[0].commit and recovered.tree == completed[0].tree
    assert len(completed) == 1 and completed[0].status == "committed"
    rows = [row for row in rig.journal.read().rows if row["op"] == "commit"]
    assert [row["kind"] for row in rows] == ["intent", "result"]
    if matching:
        retry = run(rig, journal=InterleavedJournal(), request_id="commit-B", now=now)
        assert retry.status == "committed_recovered" and retry.commit == completed[0].commit


def test_matching_bound_inputs_preserve_genuine_store_failure(rig):
    run(rig)
    before = state(rig)
    inactive = team_git.GitStore(rig.repo, rig.store.scratch)
    other = SimpleNamespace(repo=rig.repo, store=inactive, options=rig.options, journal=rig.journal)
    with pytest.raises(custody.CommitRefused) as caught:
        run(other)
    assert caught.value.code == "store_closed"
    assert str(caught.value) == custody.REFUSALS["store_closed"]
    assert caught.value.next_action == {
        "actor": "custodian",
        "command": "open an active private Git store and reconcile any existing intent by observation; never repeat its effect",
    }
    assert state(rig) == before and len(results(rig)) == 1
    assert run(rig).status == "committed_recovered"


def test_invalid_commit_identity_advice_allows_corrected_retry(rig):
    before = state(rig)
    for _ in range(2):
        with pytest.raises(custody.CommitRefused) as caught:
            run(rig, identity=team_git.CommitIdentity("bad\nvalue", IDENTITY.email, IDENTITY.date))
        assert caught.value.code == "invalid_identity"
        assert str(caught.value) == custody.REFUSALS["invalid_identity"]
        assert caught.value.next_action == {
            "actor": "custodian",
            "command": "provide a valid commit identity and reconcile any existing intent by observation; never repeat its effect",
        }
        assert state(rig) == before and not results(rig)
    assert run(rig).status == "committed"


@pytest.mark.parametrize("branch_state", ["unchanged", "switched", "detached", "reader-failed"])
def test_same_id_stale_history_recovers_recorded_ref_without_branch_discovery(rig, monkeypatch,
                                                                            branch_state):
    completed, published, branch_reads, effects = [], [], [], []
    real_cas = team_git.cas_fast_forward
    def observed_cas(*args, **kwargs):
        effects.append(1)
        return real_cas(*args, **kwargs)
    def read_branch():
        branch_reads.append(1)
        if branch_state == "reader-failed":
            raise OSError("untrusted failure detail")
        if branch_state == "detached":
            return None
        return rig.options["read_branch"]()
    class InterleavedJournal:
        def __init__(self, stale=False):
            self.stale = stale
            self.admitting = False
        @contextmanager
        def admission(self):
            with rig.journal.admission():
                self.admitting = True
                try:
                    yield self
                finally:
                    self.admitting = False
        def read(self):
            snapshot = rig.journal.read()
            if self.stale:
                self.stale = False
                completed.append(run(rig, journal=InterleavedJournal()))
                if branch_state == "switched":
                    git(rig.repo, "branch", "other", completed[0].commit)
                    git(rig.repo, "symbolic-ref", "HEAD", "refs/heads/other")
                elif branch_state == "detached":
                    git(rig.repo, "update-ref", "--no-deref", "HEAD", completed[0].commit)
                    assert (rig.repo / ".git/HEAD").read_text().strip() == completed[0].commit
                published.append(state(rig))
            return snapshot
        def record_intent(self, **kwargs):
            return rig.journal.record_intent(**kwargs)
        def reconcile(self, *args, **kwargs):
            assert not self.admitting, "recovery must release admission before observation"
            return rig.journal.reconcile(*args, **kwargs)
    monkeypatch.setattr(custody, "team_git", SimpleNamespace(**{**vars(team_git),
        "cas_fast_forward": observed_cas}))
    monkeypatch.setattr(custody, "team_gitops", SimpleNamespace(
        GitOpsJournal=InterleavedJournal, GitOpsError=team_gitops.GitOpsError, Observation=team_gitops.Observation))
    recovered = run(rig, journal=InterleavedJournal(stale=True), read_branch=read_branch,
                    governance_check=lambda commit, tree: pytest.fail("recovery ran governance"))
    assert len(completed) == 1 and completed[0].status == "committed"
    assert recovered.status == "committed_recovered"
    assert recovered.commit == completed[0].commit and recovered.tree == completed[0].tree
    assert branch_reads == [1] and effects == [1]
    rows = [row for row in rig.journal.read().rows if row["op"] == "commit"]
    assert [row["kind"] for row in rows] == ["intent", "result"]
    assert rows[1]["status"] == "done" and state(rig) == published[0]


def test_distinct_input_fingerprints_still_share_identical_commit_binding(rig, terminal_observation):
    remaining = terminal_observation.remaining
    gate = Barrier(2)
    def governance(commit, tree):
        gate.wait(timeout=remaining())
        return True
    with make_store(rig.repo) as second_store, ThreadPoolExecutor(max_workers=2) as pool:
        other = SimpleNamespace(repo=rig.repo, store=second_store, options=rig.options, journal=rig.journal)
        pending = [pool.submit(run, candidate, request_id=request, actor=actor, governance_check=governance)
                   for candidate, request, actor in ((rig, "commit-1", "custodian-1"),
                                                     (other, "commit-2", "custodian-2"))]
        outcomes = [future.result(timeout=remaining()) for future in pending]
    assert outcomes[0].commit == outcomes[1].commit
    assert sorted(item.status for item in outcomes) == ["committed", "committed_recovered"]
    rows = [row for row in rig.journal.read().rows if row["op"] == "commit"]
    assert [row["kind"] for row in rows] == ["intent", "result"]


def test_unknown_outcome_codes_are_one_shared_object():
    """Custody and lane Git classify indeterminate outcomes with one frozenset."""
    assert "UNKNOWN_OUTCOME_CODES" in team_git.__all__
    shared = getattr(team_git, "UNKNOWN_OUTCOME_CODES", None)
    assert shared is custody._UNKNOWN
    assert isinstance(shared, frozenset)
    assert shared == frozenset((
        "ref_update_unknown", "git_cleanup_failed", "git_timeout", "git_output_limit"))
    for determinate in ("git_failed", "ref_update_failed", "cas_mismatch", "git_missing"):
        assert determinate not in shared


def test_shared_unknown_codes_are_one_object_under_concurrent_reads():
    assert hasattr(team_git, "UNKNOWN_OUTCOME_CODES")
    shared = team_git.UNKNOWN_OUTCOME_CODES
    barrier = Barrier(4)

    def read():
        barrier.wait(5)
        return custody._UNKNOWN, team_git.UNKNOWN_OUTCOME_CODES

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(read) for _ in range(4)]
        seen = [future.result(timeout=5) for future in futures]
    assert seen == [(shared, shared)] * 4
    assert all(item is custody._UNKNOWN for pair in seen for item in pair)
