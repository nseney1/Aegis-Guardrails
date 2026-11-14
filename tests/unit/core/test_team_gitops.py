"""Git/forge journal public API: durable reservation, results and observation only."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, ExitStack
import ast
import errno
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
from threading import Barrier, Event, get_ident

import pytest

from aegis_core import team_gitops as gitops
from aegis_core import storage_confined
from tests.conftest import symlink_or_skip


OLD = "a" * 40
NEW = "b" * 40
OPS = ("worktree_add", "worktree_remove", "commit", "ref_update", "push", "pr_open",
       "pr_ready", "pr_close", "merge", "run_cancel", "lease_claim", "lease_renew",
       "lease_transfer", "lease_release")


@pytest.fixture(autouse=True)
def effect_resources():
    """Close test-owned live effect handles after all effect activity has ended."""
    yield
    owners = getattr(gitops, "_OWNERS", {})
    for key, owner in list(owners.items()):
        if owner[1] == os.getpid():
            os.close(owner[0])
            del owners[key]


@pytest.fixture
def make_store(tmp_path):
    if not gitops.descriptor_supported():
        pytest.skip("descriptor-relative journal needs POSIX no-follow operations")
    def make(name="common"):
        root = tmp_path / name
        root.mkdir()
        return gitops.GitOpsJournal(root)
    return make


def intent(store, request_id="request-1", **changes):
    fields = dict(op="push", lane="lane-1", request_id=request_id,
                  expected_old=OLD, expected_new=NEW, actor="session-1")
    fields.update(changes)
    return store.record_intent(**fields)


def orphan_intent(store, request_id="request-1", **changes):
    """A durable reservation whose real process owner has exited."""
    fields = dict(op="push", lane="lane-1", request_id=request_id,
                  expected_old=OLD, expected_new=NEW, actor="session-1")
    fields.update(changes)
    script = """
import json, sys
sys.path.insert(0, sys.argv[1])
from aegis_core.team_gitops import GitOpsJournal
receipt = GitOpsJournal(sys.argv[2]).record_intent(**json.loads(sys.argv[3]))
print(json.dumps({'row': receipt.row, 'created': receipt.created}))
"""
    child = subprocess.run([sys.executable, "-I", "-c", script,
                            str(Path(__file__).resolve().parents[3]), str(store.common_dir), json.dumps(fields)],
                           capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stderr
    return gitops.IntentReceipt(**json.loads(child.stdout))


def refusal(code, call):
    with pytest.raises(gitops.GitOpsError) as error:
        call()
    assert error.value.code == code
    assert str(error.value) == gitops.REFUSALS[code]


@pytest.mark.parametrize("op", OPS)
def test_every_operation_has_intent_then_result_and_retry_receipt(make_store, op):
    store = make_store()
    first = intent(store, op=op)
    assert first.created is True
    assert intent(store, op=op).created is False
    assert store.open_intents("lane-1") == [first.row]
    result = store.record_result("request-1", "done", NEW)
    assert result["kind"] == "result"
    assert result["op"] == op
    for key in ("lane", "request_id", "actor", "expected_old", "expected_new", "created_at"):
        assert result[key] == first.row[key]
    assert result["ts"] >= first.row["ts"]
    assert store.record_result("request-1", "done", NEW) == result
    assert intent(store, op=op).created is False
    assert store.open_intents("lane-1") == []
    assert [row["kind"] for row in store.read().rows] == ["intent", "result"]
    path = store.common_dir / "aegis" / "gitops.jsonl"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.with_name("gitops.lock").stat().st_mode) == 0o600


@pytest.mark.parametrize("state,status", [(NEW, "done"), (OLD, "not_applied"), ("c" * 40, "unknown")])
def test_kill_gap_reconciles_only_by_observation_and_never_retries(make_store, state, status):
    store = make_store()
    orphan_intent(store)
    calls = []
    def observe(row):
        calls.append(row["request_id"])
        return gitops.Observation(state)
    results = store.reconcile("lane-1", observe)
    assert results[0]["status"] == status
    assert store.reconcile("lane-1", observe) == []
    assert intent(store).created is False
    assert calls == ["request-1"]
    assert len(store.read().rows) == 2


@pytest.mark.parametrize("failure", [OSError("token=do-not-echo"), TimeoutError("secret"), ValueError("bad adapter")])
def test_observer_failure_is_sticky_unknown_without_exception_text(make_store, failure):
    store = make_store()
    row = orphan_intent(store).row
    def unavailable(row):
        raise failure
    assert store.reconcile("lane-1", unavailable) == []
    assert store.open_intents() == [row]
    # Preserve the original terminal-unknown assertions for an authoritative
    # foreign observation, following the round-2 transient-failure ruling.
    assert store.reconcile("lane-1", lambda row: gitops.Observation("c" * 40))[0]["status"] == "unknown"
    assert store.open_intents("lane-1") == []
    assert "do-not-echo" not in json.dumps(store.read().rows)
    refusal("result_conflict", lambda: store.record_result("request-1", "done", NEW))


def test_remote_and_lease_states_and_lane_filtering(make_store):
    store = make_store()
    before, after = {"state": "open", "number": 42}, {"state": "closed", "number": 42}
    orphan_intent(store, expected_old=before, expected_new=after)
    intent(store, "request-2", lane="lane-2")
    assert store.reconcile("lane-1", lambda row: gitops.Observation(after))[0]["status"] == "done"
    assert [row["request_id"] for row in store.open_intents()] == ["request-2"]
    assert store.open_intents("missing") == []


def test_request_and_result_conflicts_refuse_without_append(make_store):
    store = make_store()
    intent(store)
    refusal("request_conflict", lambda: intent(store, expected_new="c" * 40))
    refusal("missing_intent", lambda: store.record_result("absent", "done", NEW))
    refusal("invalid_result", lambda: store.record_result("request-1", "done", OLD))
    refusal("invalid_result", lambda: store.record_result("request-1", "not_applied", NEW))
    assert len(store.read().rows) == 1


@pytest.mark.parametrize("status,state", [("done", NEW), ("not_applied", OLD), ("unknown", "c" * 40)])
def test_durable_result_conflict_directs_owner_to_read_existing_result(make_store, status, state):
    store = make_store()
    receipt = intent(store)
    saved = store.record_result("request-1", status, state, receipt=receipt)
    path = store.common_dir / "aegis" / "gitops.jsonl"
    before = path.read_bytes()
    other_status, other_state = ("not_applied", OLD) if status == "done" else ("done", NEW)
    with pytest.raises(gitops.GitOpsError) as error:
        store.record_result("request-1", other_status, other_state)
    assert error.value.code == "result_conflict"
    assert str(error.value) == gitops.REFUSALS["result_conflict"]
    assert error.value.next_action == {"actor": "owner", "command": "read the durable result for this request; never retry the effect"}
    assert path.read_bytes() == before
    assert store.read().rows[-1] == saved
    assert store.record_result("request-1", status, state) == saved
    assert store.reconcile("lane-1", lambda row: pytest.fail("durable result observed")) == []


@pytest.mark.parametrize("changes", [
    {"op": "shell"}, {"lane": "bad\nAegis-Approve: forged"}, {"actor": "session\rsecond"},
    {"request_id": "x" * 129}, {"expected_old": "bad"}, {"expected_new": OLD},
    {"expected_new": {"GH_TOKEN": "do-not-store"}},
    {"expected_new": {"state": "token=do-not-store"}},
    {"expected_new": {"state": "ghp_" + "a" * 30}},
    {"expected_new": {"state": "x" * 1025}}, {"expected_new": {"state": ["nested"]}},
    {"expected_new": {"number": True}}, {"expected_new": {"state": "two\nlines"}},
])
def test_invalid_or_secret_fields_are_refused_before_any_write(make_store, changes):
    store = make_store()
    refusal("invalid_intent", lambda: intent(store, **changes))
    assert not (store.common_dir / "aegis").exists()


def test_unsupported_probe_has_documented_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(gitops, "descriptor_supported", lambda: False)
    store = gitops.GitOpsJournal(tmp_path)
    refusal("unsupported_platform", lambda: intent(store))
    refusal("unsupported_platform", store.read)
    refusal("unsupported_platform", lambda: store.reconcile("lane-1", lambda row: pytest.fail("unsupported observer")))
    assert not (tmp_path / "aegis").exists()


def test_malformed_torn_schema_and_oversized_lines_are_counted_and_preserved(make_store):
    store = make_store()
    intent(store)
    path = store.common_dir / "aegis" / "gitops.jsonl"
    with path.open("ab") as stream:
        stream.write(b'not-json\n{"v":99}\n' + b"x" * (gitops.MAX_ROW_BYTES + 1) + b'\n{"torn":')
    read = store.read()
    assert len(read.rows) == 1
    assert read.skipped == 4 and read.torn_tail is True
    intent(store, "request-2")
    assert store.read().skipped == 4
    assert store.read().torn_tail is False
    assert [row["request_id"] for row in store.open_intents()] == ["request-1", "request-2"]


def test_size_limit_refuses_before_parsing_or_append(make_store, monkeypatch):
    store = make_store()
    intent(store)
    path = store.common_dir / "aegis" / "gitops.jsonl"
    with path.open("r+b") as stream:
        stream.truncate(gitops.MAX_JOURNAL_BYTES + 1)
    def must_not_parse(*args, **kwargs):
        pytest.fail("oversized journal parsed")
    monkeypatch.setattr(gitops, "_parse", must_not_parse)
    refusal("journal_too_large", store.read)
    refusal("journal_too_large", lambda: intent(store, "request-2"))


def test_parallel_reservations_results_and_reconcile_are_once_only(make_store):
    store = make_store()
    with ThreadPoolExecutor(max_workers=3) as pool:
        receipts = list(pool.map(lambda _: orphan_intent(store), range(12)))
    assert sum(receipt.created for receipt in receipts) == 1
    calls = []
    def observe(row):
        calls.append(row["request_id"])
        return gitops.Observation(NEW)
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: store.reconcile("lane-1", observe), range(9)))
    assert sum(len(rows) for rows in results) == 1
    assert calls == ["request-1"]
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(lambda _: store.record_result("request-1", "done", NEW), range(9)))
    assert len(store.read().rows) == 2


@pytest.mark.parametrize("state,status", [(NEW, "done"), (OLD, "not_applied"), ("c" * 40, "unknown")])
@pytest.mark.parametrize("completion", ["reconcile", "receipt", "effect_fd"])
def test_delayed_reconcile_does_not_observe_a_completed_intent(make_store, monkeypatch, state, status, completion):
    store = make_store()
    receipt = orphan_intent(store) if completion == "reconcile" else intent(store)
    delayed = gitops.GitOpsJournal(store.common_dir)
    pending_read, resume = Event(), Event()
    original = gitops._try_effect
    calls = []

    def pause_before_acquire(directory, request_id):
        if not pending_read.is_set():
            pending_read.set()
            assert resume.wait(10), "delayed reconciler was not released"
        return original(directory, request_id)

    def observe(row):
        calls.append(row["request_id"])
        return gitops.Observation(state)

    monkeypatch.setattr(gitops, "_try_effect", pause_before_acquire)
    with ThreadPoolExecutor(max_workers=1) as pool:
        waiting = pool.submit(delayed.reconcile, "lane-1", observe)
        try:
            assert pending_read.wait(10), "delayed reconciler did not read pending intents"
            # A records its result and closes its effect descriptor before B
            # may acquire that lock using its now-stale pending snapshot.
            if completion == "reconcile":
                assert [row["status"] for row in store.reconcile("lane-1", observe)] == [status]
            elif completion == "receipt":
                assert store.record_result("request-1", status, state, receipt=receipt)["status"] == status
            else:
                script = """
import json, os, sys
sys.path.insert(0, sys.argv[1])
from aegis_core.team_gitops import GitOpsJournal
fd = int(sys.argv[3])
try:
    GitOpsJournal(sys.argv[2]).record_result('request-1', sys.argv[4], json.loads(sys.argv[5]), effect_fd=fd)
finally:
    os.close(fd)
"""
                try:
                    child = subprocess.run([sys.executable, "-I", "-c", script,
                                            str(Path(__file__).resolve().parents[3]), str(store.common_dir),
                                            str(receipt.inheritable_fds()[0]), status, json.dumps(state)],
                                           pass_fds=receipt.inheritable_fds(), capture_output=True, timeout=20)
                    assert child.returncode == 0, child.stderr
                finally:
                    receipt.close()
        finally:
            resume.set()
        assert waiting.result(timeout=15) == []

    expected_calls = ["request-1"] if completion == "reconcile" else []
    assert calls == expected_calls
    assert store.reconcile("lane-1", observe) == []
    assert calls == expected_calls
    assert intent(store).created is False
    assert len(store.read().rows) == 2
    assert store.read().rows[-1]["status"] == status


def test_reconcile_generation_failure_refuses_without_observing_and_releases_lock(make_store, monkeypatch):
    store = make_store()
    row = orphan_intent(store).row
    original_effect = gitops._try_effect
    original_os = gitops.os
    acquired, calls = [], []

    def track_effect(directory, request_id):
        fd = original_effect(directory, request_id)
        if fd is not None:
            acquired.append(fd)
        return fd

    def failed_stat(*args, **kwargs):
        raise OSError(errno.EIO, "token=private-generation-error")

    def observe(row):
        calls.append(row["request_id"])
        return gitops.Observation(NEW)

    monkeypatch.setattr(gitops, "_try_effect", track_effect)
    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "stat": failed_stat}))
    refusal("journal_io", lambda: store.reconcile("lane-1", observe))
    assert calls == []
    assert len(acquired) == 1
    for fd in acquired:
        with pytest.raises(OSError) as error:
            os.fstat(fd)
        assert error.value.errno == errno.EBADF

    monkeypatch.setattr(gitops, "os", original_os)
    assert store.open_intents() == [row]
    assert [result["status"] for result in store.reconcile("lane-1", observe)] == ["done"]
    assert calls == ["request-1"]
    assert intent(store).created is False


@pytest.mark.parametrize("failure,code", [("stat", "journal_io"), ("reread", "journal_busy")])
def test_reconcile_preflight_failure_observes_neither_pending_intent(make_store, monkeypatch, failure, code):
    store = make_store()
    # Reverse creation order also exercises the fixed request-id lock order.
    rows = [orphan_intent(store, request).row for request in ("request-2", "request-1")]
    activity = gitops.GitOpsJournal(store.common_dir)
    original_effect, original_os = gitops._try_effect, gitops.os
    original_transaction = gitops.GitOpsJournal._transaction
    acquired, calls = [], []

    def track_effect(directory, request_id, **kwargs):
        fd = original_effect(directory, request_id, **kwargs)
        if fd is not None and request_id in {row["request_id"] for row in rows}:
            acquired.append((request_id, fd))
            try:
                if len(acquired) == 2 and failure == "reread":
                    intent(activity, "other-request", lane="other-lane").close()
            except BaseException:
                os.close(fd)
                raise
        return fd

    def failed_stat(*args, **kwargs):
        if len(acquired) == 2 and failure == "stat":
            raise OSError(errno.EIO, "token=private-preflight-error")
        return original_os.stat(*args, **kwargs)

    @contextmanager
    def failed_transaction(self, write=False, **kwargs):
        if self is store and len(acquired) == 2 and failure == "reread":
            raise gitops.LockTimeoutError("token=private-preflight-error")
        with original_transaction(self, write=write, **kwargs) as transaction:
            yield transaction

    def observe(row):
        calls.append(row["request_id"])
        return gitops.Observation(NEW)

    monkeypatch.setattr(gitops, "_try_effect", track_effect)
    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "stat": failed_stat}))
    monkeypatch.setattr(gitops.GitOpsJournal, "_transaction", failed_transaction)
    refusal(code, lambda: store.reconcile("lane-1", observe))
    assert calls == []
    assert [request for request, _ in acquired] == ["request-1", "request-2"]
    for _, fd in acquired:
        with pytest.raises(OSError) as error:
            os.fstat(fd)
        assert error.value.errno == errno.EBADF

    monkeypatch.setattr(gitops, "_try_effect", original_effect)
    monkeypatch.setattr(gitops, "os", original_os)
    monkeypatch.setattr(gitops.GitOpsJournal, "_transaction", original_transaction)
    assert store.open_intents("lane-1") == rows
    assert len(store.reconcile("lane-1", observe)) == 2
    assert calls == ["request-1", "request-2"]
    assert store.reconcile("lane-1", observe) == []
    assert all(intent(store, row["request_id"]).created is False for row in rows)


@pytest.mark.parametrize("grow", [False, True])
def test_concurrent_reconcilers_check_generation_once_before_observing(make_store, monkeypatch, grow):
    activity = make_store()
    workers, per_lane = 3, 3
    stores = [gitops.GitOpsJournal(activity.common_dir) for _ in range(workers)]
    lanes = ["lane-" + str(index) for index in range(workers)]
    for lane in lanes:
        for index in reversed(range(per_lane)):
            intent(activity, lane + "-request-" + str(index), lane=lane).close()
    transactions = {store: 0 for store in stores}
    original_transaction, original_effect = gitops.GitOpsJournal._transaction, gitops._try_effect
    acquisitions, calls = [], []

    def other_lane_transaction():
        # A real same-mode chmod invalidates the old timestamp tuple at every
        # acquisition round, without changing any worker's pending intents.
        acquisitions.append(None)
        if grow and len(acquisitions) == per_lane:
            intent(activity, "unrelated-request", lane="unrelated").close()
        else:
            with original_transaction(activity, write=True):
                pass

    barrier = Barrier(workers, action=other_lane_transaction, timeout=15)
    observations_ready = Barrier(workers, timeout=15)

    def acquire_together(directory, request_id, **kwargs):
        fd = original_effect(directory, request_id, **kwargs)
        try:
            if request_id != "unrelated-request":
                barrier.wait()
        except BaseException:
            if fd is not None:
                os.close(fd)
            raise
        return fd

    @contextmanager
    def count_transactions(self, write=False, **kwargs):
        if write and self in transactions:
            transactions[self] += 1
        with original_transaction(self, write=write, **kwargs) as transaction:
            yield transaction

    def observe(row):
        observations_ready.wait()
        calls.append(row["request_id"])
        return gitops.Observation(NEW)

    monkeypatch.setattr(gitops, "_try_effect", acquire_together)
    monkeypatch.setattr(gitops.GitOpsJournal, "_transaction", count_transactions)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(store.reconcile, lane, observe) for store, lane in zip(stores, lanes)]
        results = [future.result(timeout=30) for future in futures]
    assert all(len(rows) == per_lane for rows in results)
    assert len(calls) == len(set(calls)) == workers * per_lane
    # Initial snapshot and final append; growth refreshes are read-only.
    assert set(transactions.values()) == {2}, transactions


@pytest.mark.parametrize("failure", ["journal_busy", "journal_io", "torn", "complete"])
@pytest.mark.parametrize("exhaust", [False, True])
def test_final_record_retry_keeps_waiting_reconciler_from_observing_twice(make_store, monkeypatch, failure, exhaust):
    store = make_store()
    intent(store).close()
    second = gitops.GitOpsJournal(store.common_dir)
    observed, waiting, finished = Event(), Event(), Event()
    original_effect = gitops._try_effect
    original_transaction = gitops.GitOpsJournal._transaction
    original_append = gitops._append
    journal_inode = (store.common_dir / "aegis" / "gitops.jsonl").stat().st_ino
    calls, attempts = [], []

    def delayed_claim(directory, request_id):
        if observed.is_set() and not waiting.is_set():
            waiting.set()
            assert finished.wait(15), "first reconciler did not finish"
        return original_effect(directory, request_id)

    @contextmanager
    def fail_transaction(self, write=False, **kwargs):
        if self is store and write and calls:
            attempts.append(None)
            if ((len(attempts) == 1 and failure in ("journal_busy", "journal_io"))
                    or (exhaust and len(attempts) > 1)):
                raise gitops.GitOpsError("journal_busy" if failure == "journal_busy" else "journal_io")
        with original_transaction(self, write=write, **kwargs) as transaction:
            yield transaction

    def fail_append(fd, row, size):
        if (failure in ("torn", "complete") and os.fstat(fd).st_ino == journal_inode
                and len(attempts) == 1):
            if failure == "complete":
                original_append(fd, row, size)
            else:
                os.lseek(fd, 0, os.SEEK_END)
                os.write(fd, b'{"torn":')
            raise OSError(errno.EIO, "token=private-final-append")
        return original_append(fd, row, size)

    def observe(row):
        calls.append(row["request_id"])
        observed.set()
        assert waiting.wait(10), "second reconciler did not reach the claim"
        return gitops.Observation(NEW)

    def first_pass():
        try:
            return store.reconcile("lane-1", observe)
        except gitops.GitOpsError as error:
            return error.code
        finally:
            finished.set()

    monkeypatch.setattr(gitops, "_try_effect", delayed_claim)
    monkeypatch.setattr(gitops.GitOpsJournal, "_transaction", fail_transaction)
    monkeypatch.setattr(gitops, "_append", fail_append)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(first_pass)
        assert observed.wait(10)
        following = pool.submit(second.reconcile, "lane-1", observe)
        first_result, second_result = first.result(timeout=20), following.result(timeout=20)
    assert calls == ["request-1"]
    if exhaust:
        assert first_result == ("journal_busy" if failure == "journal_busy" else "journal_io")
        assert [row["status"] for row in second_result] == ([] if failure == "complete" else ["done"])
        assert len(attempts) == 3
    else:
        assert [row["status"] for row in first_result] == ["done"]
        assert second_result == []
        assert len(attempts) == 2
    assert store.open_intents() == []
    assert len(store.read().rows) == 2


@pytest.mark.parametrize("failure", ["journal_busy", "journal_io", "torn"])
def test_exhausted_final_retries_recover_durably_without_observer(make_store, monkeypatch, failure):
    store = make_store()
    for request in ("request-2", "request-1"):
        intent(store, request).close()
    original_transaction = gitops.GitOpsJournal._transaction
    calls, attempts = [], []

    @contextmanager
    def fail_final(self, write=False, **kwargs):
        if self is store and write and len(calls) == 2:
            attempts.append(None)
            if failure == "torn":
                with original_transaction(self, write=write, **kwargs) as transaction:
                    os.lseek(transaction[0], 0, os.SEEK_END)
                    os.write(transaction[0], b'{"torn":')
                    raise OSError(errno.ENOSPC, "token=private-final-error")
            raise gitops.GitOpsError(failure)
        with original_transaction(self, write=write, **kwargs) as transaction:
            yield transaction

    def observe(row):
        calls.append(row["request_id"])
        return gitops.Observation(NEW)

    monkeypatch.setattr(gitops.GitOpsJournal, "_transaction", fail_final)
    refusal("journal_io" if failure == "torn" else failure,
            lambda: store.reconcile("lane-1", observe))
    assert len(attempts) == 3
    assert calls == ["request-1", "request-2"]
    monkeypatch.setattr(gitops.GitOpsJournal, "_transaction", original_transaction)
    # Recovery in another interpreter rules out an in-memory observation cache.
    script = """
import json, sys
sys.path.insert(0, sys.argv[1])
from aegis_core.team_gitops import GitOpsJournal
def forbidden(row):
    raise AssertionError('observer called during durable recovery')
store = GitOpsJournal(sys.argv[2])
print(json.dumps(store.reconcile('lane-1', forbidden)))
"""
    child = subprocess.run([sys.executable, "-I", "-c", script,
                            str(Path(__file__).resolve().parents[3]), str(store.common_dir)],
                           capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stderr
    assert [row["status"] for row in json.loads(child.stdout)] == ["done", "done"]
    assert store.reconcile("lane-1", observe) == []
    assert calls == ["request-1", "request-2"]


def test_reconcile_bounds_effect_descriptors_under_low_rlimit(make_store):
    store = make_store()
    if os.name != "posix":
        pytest.skip("RLIMIT_NOFILE is POSIX-only")
    pytest.importorskip("resource")
    for index in range(48):
        intent(store, "request-" + str(index)).close()
    script = """
import json, os, resource, sys
sys.path.insert(0, sys.argv[1])
from aegis_core.team_gitops import GitOpsJournal, Observation
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
limit = 32 if soft == resource.RLIM_INFINITY else min(32, soft)
resource.setrlimit(resource.RLIMIT_NOFILE, (limit, hard))
calls = []
def observe(row):
    calls.append(row['request_id'])
    return Observation('b'*40)
store = GitOpsJournal(sys.argv[2])
rows = store.reconcile('lane-1', observe)
assert len(rows) == len(calls) == len(set(calls)) == 48
assert store.reconcile('lane-1', observe) == []
print('bounded descriptors: 48 results at soft limit 32')
"""
    child = subprocess.run([sys.executable, "-I", "-c", script,
                            str(Path(__file__).resolve().parents[3]), str(store.common_dir)],
                           capture_output=True, text=True, timeout=30)
    assert child.returncode == 0, child.stderr
    assert store.open_intents() == []


@pytest.mark.parametrize("failure", ["before", "torn", "complete"])
def test_checkpoint_write_failure_never_allows_second_authoritative_observation(make_store, monkeypatch, failure):
    store = make_store()
    intent(store).close()
    original_append, original_effect = gitops._append, gitops._try_effect
    journal_inode = (store.common_dir / "aegis" / "gitops.jsonl").stat().st_ino
    calls, acquired = [], []

    def track_effect(*args):
        fd = original_effect(*args)
        if fd is not None:
            acquired.append(fd)
        return fd

    def fail_checkpoint(fd, row, size):
        if os.fstat(fd).st_ino != journal_inode:
            if failure == "complete":
                original_append(fd, row, size)
            elif failure == "torn":
                os.lseek(fd, 0, os.SEEK_END)
                os.write(fd, b'{"torn":')
            raise OSError(errno.ENOSPC, "token=private-checkpoint-error")
        return original_append(fd, row, size)

    def observe(row):
        calls.append(row["request_id"])
        return gitops.Observation(NEW)

    monkeypatch.setattr(gitops, "_append", fail_checkpoint)
    monkeypatch.setattr(gitops, "_try_effect", track_effect)
    refusal("journal_io" if failure == "complete" else "checkpoint_stuck",
            lambda: store.reconcile("lane-1", observe))
    monkeypatch.setattr(gitops, "_append", original_append)
    if failure == "complete":
        assert [row["status"] for row in store.reconcile("lane-1", observe)] == ["done"]
    else:
        for _ in range(2):
            refusal("checkpoint_stuck", lambda: store.reconcile("lane-1", observe))
        assert len(store.open_intents()) == 1
    assert calls == ["request-1"]
    for fd in acquired:
        with pytest.raises(OSError) as error:
            os.fstat(fd)
        assert error.value.errno == errno.EBADF


@pytest.mark.parametrize("corruption", ["marker", "torn", "malformed", "binding", "intent", "oversize"])
def test_checkpoint_corruption_refuses_without_observing_or_leaking_descriptors(make_store, monkeypatch, corruption):
    store = make_store()
    receipt = intent(store)
    row = receipt.row
    # Release the real receipt before simulating a damaged owner record.
    receipt.close()
    path = next((store.common_dir / "aegis").glob("gitops-effect-*.lock"))
    result = dict(row, kind="result", status="done", observed=NEW)
    if corruption == "binding":
        result["request_id"] = "other-request"
    if corruption == "intent":
        result = row
    payload = {"marker": b"!\n", "torn": b'!\n{"token=private":',
               "malformed": b'!\n{"token=private":true}\n'}.get(corruption)
    path.write_bytes(payload if payload is not None else b"!\n" + json.dumps(result).encode("ascii") + b"\n")
    if corruption == "oversize":
        with path.open("r+b") as stream:
            stream.truncate(gitops.MAX_ROW_BYTES + 4)
        checkpoint_inode, original_os = path.stat().st_ino, gitops.os

        def bounded_read(fd, count):
            assert os.fstat(fd).st_ino != checkpoint_inode, "oversized checkpoint read before refusal"
            return original_os.read(fd, count)

        monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "read": bounded_read}))
    original_effect = gitops._try_effect
    acquired, calls = [], []

    def track_effect(*args):
        fd = original_effect(*args)
        if fd is not None:
            acquired.append(fd)
        return fd

    monkeypatch.setattr(gitops, "_try_effect", track_effect)
    for _ in range(2):
        refusal("checkpoint_stuck", lambda: store.reconcile("lane-1", lambda row: calls.append(row)))
    assert calls == []
    assert store.open_intents() == [row]
    for fd in acquired:
        with pytest.raises(OSError) as error:
            os.fstat(fd)
        assert error.value.errno == errno.EBADF


def test_interrupted_observation_reservation_refuses_in_new_process(make_store):
    store = make_store()
    intent(store).close()
    script = """
import os, sys
sys.path.insert(0, sys.argv[1])
from aegis_core.team_gitops import GitOpsJournal
def interrupted(row):
    os._exit(17)
GitOpsJournal(sys.argv[2]).reconcile('lane-1', interrupted)
"""
    child = subprocess.run([sys.executable, "-I", "-c", script,
                            str(Path(__file__).resolve().parents[3]), str(store.common_dir)],
                           capture_output=True, timeout=20)
    assert child.returncode == 17, child.stderr
    calls = []
    for _ in range(2):
        refusal("checkpoint_stuck", lambda: store.reconcile("lane-1", lambda row: calls.append(row)))
    assert calls == []
    assert len(store.open_intents()) == 1


def test_partial_batch_result_retry_returns_each_result_once(make_store, monkeypatch):
    store = make_store()
    for request in ("request-1", "request-2"):
        intent(store, request).close()
    original_append = gitops._append
    journal_inode = (store.common_dir / "aegis" / "gitops.jsonl").stat().st_ino
    failed, calls = [], []

    def interrupted_second_row(fd, row, size):
        if row["request_id"] == "request-2" and os.fstat(fd).st_ino == journal_inode and not failed:
            failed.append(None)
            os.lseek(fd, 0, os.SEEK_END)
            os.write(fd, b'{"torn":')
            raise OSError(errno.EIO, "token=private-batch-error")
        return original_append(fd, row, size)

    def observe(row):
        calls.append(row["request_id"])
        return gitops.Observation(NEW)

    monkeypatch.setattr(gitops, "_append", interrupted_second_row)
    rows = store.reconcile("lane-1", observe)
    assert [row["request_id"] for row in rows] == calls == ["request-1", "request-2"]
    assert store.reconcile("lane-1", observe) == []
    assert len(store.read().rows) == 4
    assert store.read().skipped == 1


def test_later_batch_claim_failure_preserves_completed_batches_on_retry(make_store, monkeypatch):
    store = make_store()
    requests = ["request-" + str(index).zfill(2) for index in range(17)]
    for request in requests:
        intent(store, request).close()
    original_effect = gitops._try_effect
    calls, failed = [], []

    def failed_later_claim(directory, request_id):
        if request_id == "request-08" and not failed:
            failed.append(None)
            raise OSError(errno.EMFILE, "token=private-descriptor-error")
        return original_effect(directory, request_id)

    def observe(row):
        calls.append(row["request_id"])
        return gitops.Observation(NEW)

    monkeypatch.setattr(gitops, "_try_effect", failed_later_claim)
    refusal("journal_io", lambda: store.reconcile("lane-1", observe))
    assert calls == requests[:8]
    assert [row["request_id"] for row in store.open_intents()] == requests[8:]
    assert [row["request_id"] for row in store.reconcile("lane-1", observe)] == requests[8:]
    assert calls == requests
    assert store.reconcile("lane-1", observe) == []


@pytest.mark.parametrize("failure", ["write", "short", "fsync"])
def test_observation_reservation_failure_precedes_callback(make_store, monkeypatch, failure):
    store = make_store()
    intent(store).close()
    checkpoint = next((store.common_dir / "aegis").glob("gitops-effect-*.lock"))
    checkpoint_inode, original_os = checkpoint.stat().st_ino, gitops.os
    calls = []

    def failed_write(fd, payload):
        if os.fstat(fd).st_ino == checkpoint_inode:
            if failure == "write":
                raise OSError(errno.ENOSPC, "token=private-reservation-error")
            if failure == "short":
                return original_os.write(fd, payload[:1])
        return original_os.write(fd, payload)

    def failed_fsync(fd):
        if os.fstat(fd).st_ino == checkpoint_inode and failure == "fsync":
            raise OSError(errno.EIO, "token=private-reservation-error")
        return original_os.fsync(fd)

    def observe(row):
        calls.append(row["request_id"])
        return gitops.Observation(NEW)

    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "write": failed_write, "fsync": failed_fsync}))
    refusal("journal_io", lambda: store.reconcile("lane-1", observe))
    assert calls == []
    assert len(store.open_intents()) == 1
    assert checkpoint.read_bytes() == b""
    monkeypatch.setattr(gitops, "os", original_os)
    assert [row["status"] for row in store.reconcile("lane-1", observe)] == ["done"]
    assert calls == ["request-1"]


@pytest.fixture
def checkpointed_store(make_store, monkeypatch):
    """A real saved observation whose three final journal writes all failed."""
    def prepare(state=NEW):
        store = make_store()
        intent(store).close()
        journal_inode = (store.common_dir / "aegis" / "gitops.jsonl").stat().st_ino
        original_os = gitops.os

        def failed_final_write(fd, payload):
            if os.fstat(fd).st_ino == journal_inode:
                raise OSError(errno.ENOSPC, "token=private-final-error")
            return original_os.write(fd, payload)

        monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "write": failed_final_write}))
        try:
            refusal("journal_io", lambda: store.reconcile("lane-1", lambda row: gitops.Observation(state)))
        finally:
            monkeypatch.setattr(gitops, "os", original_os)
        return store
    return prepare


@pytest.mark.parametrize("ownership", ["receiptless", "receipt", "implicit", "effect_fd"])
@pytest.mark.parametrize("state,status", [(NEW, "done"), (OLD, "not_applied"), ("c" * 40, "unknown")])
@pytest.mark.parametrize("matching", [False, True])
def test_every_result_writer_honours_authoritative_checkpoint(make_store, checkpointed_store, ownership, state, status, matching):
    if ownership == "receiptless":
        store = checkpointed_store(state)
        path = next((store.common_dir / "aegis").glob("gitops-effect-*.lock"))
        saved = json.loads(path.read_bytes().splitlines()[1])
        kwargs = {}
    else:
        store = make_store()
        receipt = intent(store)
        saved = dict(receipt.row, kind="result", status=status, observed=state)
        path = next((store.common_dir / "aegis").glob("gitops-effect-*.lock"))
        # Test-owned owner record: exercise all ownership branches even though
        # a live effect would normally prevent a reconciler from checkpointing.
        path.write_bytes(b"!\n" + json.dumps(saved).encode("ascii") + b"\n")
        kwargs = {"receipt": receipt} if ownership == "receipt" else {}
    with ExitStack() as resources:
        if ownership == "effect_fd":
            inherited = os.dup(receipt.inheritable_fds()[0])
            resources.callback(os.close, inherited)
            kwargs = {"effect_fd": inherited}
        if not matching:
            other_state, other_status = (OLD, "not_applied") if status == "done" else (NEW, "done")
            with pytest.raises(gitops.GitOpsError) as error:
                store.record_result("request-1", other_status, other_state, **kwargs)
            assert error.value.code == "result_conflict"
            assert error.value.next_action["command"] == "reconcile the lane to publish the saved observation, then read its result"
            assert len(store.read().rows) == 1
        result = store.record_result("request-1", status, state, **kwargs)
        assert result == saved
        assert store.record_result("request-1", status, state, **kwargs) == saved
    assert store.open_intents() == []
    assert store.reconcile("lane-1", lambda row: pytest.fail("completed checkpoint observed")) == []
    assert len(store.read().rows) == 2


@pytest.mark.parametrize("healthy_count", [1, 17])
@pytest.mark.parametrize("corruption", [b"!\n", b'!\n{"torn":', b"x" * (gitops.MAX_ROW_BYTES + 4)],
                         ids=["reservation", "torn", "oversize"])
def test_stuck_checkpoint_finishes_healthy_intents_then_names_owner_recovery(make_store, healthy_count, corruption):
    store = make_store()
    stuck = intent(store, "request-05-stuck")
    stuck.close()
    path = next((store.common_dir / "aegis").glob("gitops-effect-*.lock"))
    path.write_bytes(corruption)
    healthy = ["request-" + str(index).zfill(2) for index in range(healthy_count)]
    for request in healthy:
        intent(store, request).close()
    calls = []

    def observe(row):
        calls.append(row["request_id"])
        return gitops.Observation(NEW)

    for _ in range(2):
        with pytest.raises(gitops.GitOpsError) as error:
            store.reconcile("lane-1", observe)
        assert calls == healthy
        assert store.open_intents() == [stuck.row]
        assert error.value.code == "checkpoint_stuck"
        assert str(error.value) == gitops.REFUSALS["checkpoint_stuck"]
        assert error.value.next_action["request_ids"] == ["request-05-stuck"]
        assert error.value.next_action["actor"] == "owner"
        assert "record_result" in error.value.next_action["command"]
    # The documented owner action resolves this reservation without asking
    # reconcile to observe it again and without granting an effect retry.
    assert store.record_result("request-05-stuck", "done", NEW)["status"] == "done"
    assert store.reconcile("lane-1", observe) == []
    assert calls == healthy


def test_new_intent_resets_checkpoint_after_archive_shaped_reset(checkpointed_store, monkeypatch):
    store = checkpointed_store()
    assert store.reconcile("lane-1", lambda row: pytest.fail("saved result re-observed"))[0]["status"] == "done"
    path = next((store.common_dir / "aegis").glob("gitops-effect-*.lock"))
    assert path.stat().st_size > 0
    # Simulate the owner's archived journal without depending on git history.
    (store.common_dir / "aegis" / "gitops.jsonl").write_bytes(b"")
    original_os, truncations = gitops.os, []

    def track_truncate(fd, size):
        truncations.append(size)
        return original_os.ftruncate(fd, size)

    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "ftruncate": track_truncate}))
    receipt = intent(store, expected_old=NEW, expected_new="c" * 40)
    assert receipt.created is True
    assert path.read_bytes() == b""
    assert truncations == [0]
    receipt.close()
    calls = []

    def observe(row):
        calls.append(row["expected_new"])
        return gitops.Observation("c" * 40)

    assert store.reconcile("lane-1", observe)[0]["observed"] == "c" * 40
    data = path.read_bytes()
    assert intent(store, expected_old=NEW, expected_new="c" * 40).created is False
    assert path.read_bytes() == data
    assert store.reconcile("lane-1", observe) == []
    assert calls == ["c" * 40]


@pytest.mark.parametrize("grow", [False, True])
def test_multibatch_final_records_carry_forward_matching_generation(make_store, monkeypatch, grow):
    store = make_store()
    activity = gitops.GitOpsJournal(store.common_dir)
    requests = ["request-" + str(index).zfill(2) for index in range(48)]
    for request in requests:
        intent(store, request).close()
    original_read, reads = gitops._read_fd, []
    original_effect, growth = gitops._try_effect, []

    def counted_read(fd):
        reads.append(fd)
        return original_read(fd)

    def grow_after_claim(directory, request_id, **kwargs):
        fd = original_effect(directory, request_id, **kwargs)
        try:
            if grow and request_id == "request-08" and not growth:
                growth.append(None)
                intent(activity, "unrelated-request", lane="other-lane").close()
        except BaseException:
            if fd is not None:
                os.close(fd)
            raise
        return fd

    monkeypatch.setattr(gitops, "_read_fd", counted_read)
    monkeypatch.setattr(gitops, "_try_effect", grow_after_claim)
    rows = store.reconcile("lane-1", lambda row: gitops.Observation(NEW))
    assert [row["request_id"] for row in rows] == requests
    # One initial snapshot and one final transaction for each batch of eight.
    # An unrelated writer adds its own read and exactly one worker refresh.
    assert len(reads) == 1 + (len(requests) + 7) // 8 + 2 * int(grow)


@pytest.mark.parametrize("outcome", ["completed", "unavailable", "invalid", "stuck"])
def test_multibatch_refresh_never_seeds_cache_without_final_records(make_store, monkeypatch, outcome):
    store = make_store()
    delayed = gitops.GitOpsJournal(store.common_dir)
    requests = ["request-" + str(index).zfill(2) for index in range(48)]
    for request in requests:
        intent(store, request).close()
    if outcome == "stuck":
        for path in (store.common_dir / "aegis").glob("gitops-effect-*.lock"):
            path.write_bytes(b"!\n")
    original_effect, original_read = gitops._try_effect, gitops._read_fd
    leader, reads, calls = get_ident(), [], []
    pending_read, resume = Event(), Event()

    def delayed_claim(directory, request_id, **kwargs):
        if get_ident() != leader and not pending_read.is_set():
            pending_read.set()
            assert resume.wait(15), "delayed reconciler not released"
        return original_effect(directory, request_id, **kwargs)

    def counted_read(fd):
        if get_ident() != leader:
            reads.append(fd)
        return original_read(fd)

    def observe(row):
        calls.append(row["request_id"])
        if outcome in ("completed", "stuck"):
            pytest.fail("retired or stuck intent observed")
        if outcome == "unavailable":
            raise OSError(errno.EIO, "token=private-observer-error")
        return object()

    monkeypatch.setattr(gitops, "_try_effect", delayed_claim)
    monkeypatch.setattr(gitops, "_read_fd", counted_read)
    with ThreadPoolExecutor(max_workers=1) as pool:
        following = pool.submit(delayed.reconcile, "lane-1", observe)
        try:
            assert pending_read.wait(10), "delayed reconciler did not read pending intents"
            if outcome == "completed":
                assert len(store.reconcile("lane-1", lambda row: gitops.Observation(NEW))) == len(requests)
            else:
                intent(store, "unrelated-request", lane="other-lane").close()
        finally:
            resume.set()
        if outcome == "stuck":
            refusal("checkpoint_stuck", lambda: following.result(timeout=20))
        else:
            assert following.result(timeout=20) == []
    assert calls == (requests if outcome in ("unavailable", "invalid") else [])
    # Only the initial locked snapshot seeds the cache; each changed batch reads.
    assert len(reads) == 1 + (len(requests) + gitops.RECONCILE_BATCH_SIZE - 1) // gitops.RECONCILE_BATCH_SIZE


def test_refresh_generation_never_covers_bytes_appended_after_its_read(make_store, monkeypatch):
    store = make_store()
    activity = gitops.GitOpsJournal(store.common_dir)
    requests = ["request-" + str(index).zfill(2) for index in range(16)]
    for request in requests:
        intent(store, request).close()
    original_effect, original_transaction = gitops._try_effect, gitops.GitOpsJournal._transaction
    growth, completed, calls = [], [], []

    def grow_after_claim(directory, request_id, **kwargs):
        fd = original_effect(directory, request_id, **kwargs)
        try:
            if request_id == requests[0] and not growth:
                growth.append(None)
                intent(activity, "unrelated-request", lane="other-lane").close()
        except BaseException:
            if fd is not None:
                os.close(fd)
            raise
        return fd

    @contextmanager
    def append_after_read(self, write=False, **kwargs):
        with original_transaction(self, write=write, **kwargs) as transaction:
            if self is store and not write and not completed:
                completed.append(activity.record_result(requests[8], "done", NEW))
            yield transaction

    def unavailable(row):
        calls.append(row["request_id"])
        return None

    monkeypatch.setattr(gitops, "_try_effect", grow_after_claim)
    monkeypatch.setattr(gitops.GitOpsJournal, "_transaction", append_after_read)
    assert store.reconcile("lane-1", unavailable) == []
    assert len(completed) == 1
    assert calls == requests[:8] + requests[9:]
    assert [row["request_id"] for row in store.open_intents("lane-1")] == calls


@pytest.mark.parametrize("extra_torn_bytes", [0, 1], ids=["same-size", "one-extra-byte"])
def test_torn_refresh_never_hides_later_batch_completion(make_store, monkeypatch, extra_torn_bytes):
    store = make_store()
    stamp = "2026-11-13T02:40:00Z"
    monkeypatch.setattr(gitops, "utc_stamp", lambda: stamp)
    requests = ["request-" + str(index).zfill(2) for index in range(16)]
    target = requests[12]
    for request in requests:
        receipt = intent(store, request)
        if request == target:
            held = receipt
        else:
            receipt.close()
    saved = dict(held.row, kind="result", status="done", observed=NEW, ts=stamp)
    result_bytes = json.dumps(saved, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
    path = store.common_dir / "aegis" / "gitops.jsonl"
    first_claimed, resume_first, next_batch, resume_second = Event(), Event(), Event(), Event()
    original_effect, original_read = gitops._try_effect, gitops._read_fd
    leader, calls, reads = get_ident(), [], []

    def delayed_claim(directory, request_id, **kwargs):
        fd = original_effect(directory, request_id, **kwargs)
        try:
            if get_ident() != leader:
                if request_id == requests[7]:
                    first_claimed.set()
                    assert resume_first.wait(15), "first batch was not released"
                elif request_id == requests[8]:
                    next_batch.set()
                    assert resume_second.wait(15), "second batch was not released"
        except BaseException:
            if fd is not None:
                os.close(fd)
            raise
        return fd

    def counted_read(fd):
        if get_ident() != leader:
            reads.append(fd)
        return original_read(fd)

    def unavailable(row):
        calls.append(row["request_id"])
        if row["request_id"] == target:
            return gitops.Observation(OLD)
        raise OSError(errno.EIO, "token=private-unavailable-observer")

    def reconcile():
        try:
            return store.reconcile("lane-1", unavailable)
        except gitops.GitOpsError as error:
            return error.code

    monkeypatch.setattr(gitops, "_try_effect", delayed_claim)
    monkeypatch.setattr(gitops, "_read_fd", counted_read)
    with ThreadPoolExecutor(max_workers=1) as pool:
        following = pool.submit(reconcile)
        try:
            assert first_claimed.wait(10), "first batch did not claim its requests"
            with path.open("ab") as stream:
                stream.write(b"x" * (len(result_bytes) + 2 + extra_torn_bytes))
            torn_size = path.stat().st_size
            resume_first.set()
            assert next_batch.wait(10), "second batch did not reach its claim"
            assert store.record_result(target, "done", NEW, receipt=held) == saved
            recovered_size = path.stat().st_size
        finally:
            resume_first.set()
            resume_second.set()
        result = following.result(timeout=20)
    assert (torn_size == recovered_size) is (extra_torn_bytes == 0)
    assert calls.count(target) == 0
    assert result == []
    assert len(reads) == 3  # Initial snapshot plus one refresh per batch.
    assert calls == requests[:12] + requests[13:]
    completed = store.reconcile("lane-1", lambda row: gitops.Observation(NEW))
    assert [row["request_id"] for row in completed] == calls
    assert store.open_intents() == []


def test_lock_free_refresh_cannot_assign_or_construct_cached_generation():
    tree = ast.parse(Path(gitops.__file__).read_text(encoding="utf-8"))
    journal = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "GitOpsJournal")
    reconcile = next(node for node in journal.body if isinstance(node, ast.FunctionDef) and node.name == "reconcile")

    def transaction_mode(expression):
        if (not isinstance(expression, ast.Call) or not isinstance(expression.func, ast.Attribute)
                or expression.func.attr != "_transaction"):
            return None
        return any(keyword.arg == "write" and isinstance(keyword.value, ast.Constant)
                   and keyword.value.value is True for keyword in expression.keywords)

    refreshes = [node for node in ast.walk(reconcile) if isinstance(node, ast.With)
                 and any(transaction_mode(item.context_expr) is False for item in node.items)]
    assert len(refreshes) == 1
    assigned = {node.id for node in ast.walk(refreshes[0])
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)}
    assert not assigned & {"cached", "generation", "next_cached", "next_generation"}
    parents = {child: node for node in ast.walk(reconcile) for child in ast.iter_child_nodes(node)}
    generations = [node for node in ast.walk(reconcile) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Name) and node.func.id == "_committed_generation"]
    assert generations
    for call in generations:
        ancestor = parents.get(call)
        while ancestor is not None:
            if (isinstance(ancestor, ast.With)
                    and any(transaction_mode(item.context_expr) is True for item in ancestor.items)):
                break
            ancestor = parents.get(ancestor)
        assert ancestor is not None, "cache generation constructed outside the journal writer lock"


def test_spliced_lock_free_refresh_is_never_cached_for_later_batches(make_store, monkeypatch):
    store = make_store()
    monkeypatch.setattr(gitops, "utc_stamp", lambda: "2026-11-13T03:22:00Z")
    requests = ["request-" + str(index).zfill(2) for index in range(29)]
    target = requests[-1]
    for index, request in enumerate(requests):
        receipt = intent(store, request, actor="session-1" + ("x" * 85 if index == 0 else ""))
        if request == target:
            held = receipt
        else:
            receipt.close()
    path = store.common_dir / "aegis" / "gitops.jsonl"
    prefix = path.read_bytes()
    assert len(prefix) == 8147
    journal_inode = path.stat().st_ino
    first_claimed, resume_claims, chunk_read, resume_read = Event(), Event(), Event(), Event()
    original_os, original_effect, original_read = gitops.os, gitops._try_effect, gitops._read_fd
    leader, calls, reads, refresh_bytes = get_ident(), [], [], []
    tearing, torn_write, refreshing = [False], [], [False]

    def delayed_claim(directory, request_id, **kwargs):
        fd = original_effect(directory, request_id, **kwargs)
        try:
            if get_ident() != leader and request_id == requests[7]:
                first_claimed.set()
                assert resume_claims.wait(15), "first batch was not released"
        except BaseException:
            if fd is not None:
                os.close(fd)
            raise
        return fd

    def failed_final_newline(fd, payload):
        if tearing[0] and os.fstat(fd).st_ino == journal_inode:
            if not torn_write:
                torn_write.append(None)
                return original_os.write(fd, payload[:-1])
            raise OSError(errno.EIO, "token=private-interrupted-result")
        return original_os.write(fd, payload)

    def latch_chunk(fd, count):
        data = original_os.read(fd, count)
        if get_ident() != leader and refreshing[0] and not chunk_read.is_set():
            assert len(data) == 8192
            chunk_read.set()
            assert resume_read.wait(15), "chunk reader was not released"
        return data

    def counted_read(fd):
        if get_ident() == leader:
            return original_read(fd)
        reads.append(fd)
        refreshing[0] = len(reads) == 2
        try:
            data = original_read(fd)
            if len(reads) == 2:
                refresh_bytes.append(data)
            return data
        finally:
            refreshing[0] = False

    def unavailable(row):
        calls.append(row["request_id"])
        if row["request_id"] == target:
            return gitops.Observation(OLD)
        raise OSError(errno.EIO, "token=private-unavailable-observer")

    def reconcile():
        try:
            return store.reconcile("lane-1", unavailable)
        except gitops.GitOpsError as error:
            return error.code

    monkeypatch.setattr(gitops, "_try_effect", delayed_claim)
    monkeypatch.setattr(gitops, "_read_fd", counted_read)
    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "read": latch_chunk, "write": failed_final_newline}))
    with ThreadPoolExecutor(max_workers=1) as pool:
        following = pool.submit(reconcile)
        try:
            assert first_claimed.wait(10), "first batch did not claim its requests"
            tearing[0] = True
            try:
                refusal("journal_io", lambda: store.record_result(target, "unknown", "c" * 40, receipt=held))
            finally:
                tearing[0] = False
            torn_size = path.stat().st_size
            assert torn_size - len(prefix) == 350
            resume_claims.set()
            assert chunk_read.wait(10), "lock-free refresh did not reach its first chunk"
            assert store.record_result(target, "done", NEW, receipt=held)["status"] == "done"
            assert path.stat().st_size == torn_size
        finally:
            resume_claims.set()
            resume_read.set()
        result = following.result(timeout=20)
    assert len(refresh_bytes) == 1
    assert refresh_bytes[0].endswith(b"\n")
    assert b'"lane":"lalane-1"' in refresh_bytes[0]
    assert calls.count(target) == 0
    assert result == []
    assert len(reads) == 1 + (len(requests) + gitops.RECONCILE_BATCH_SIZE - 1) // gitops.RECONCILE_BATCH_SIZE
    assert calls == requests[:-1]
    assert [row["request_id"] for row in store.reconcile("lane-1", lambda row: gitops.Observation(NEW))] == calls
    assert store.open_intents() == []


@pytest.mark.parametrize("boundary", ["before_stat", "before_open"])
def test_vanished_journal_during_refresh_refuses_io_and_closes_claims(make_store, monkeypatch, boundary):
    store = make_store()
    intent(store).close()
    activity = gitops.GitOpsJournal(store.common_dir)
    path = store.common_dir / "aegis" / "gitops.jsonl"
    archived = path.with_name("archived.jsonl")
    original_os, original_effect = gitops.os, gitops._try_effect
    growth, opened, calls = [], [], []

    def grow_after_claim(directory, request_id, **kwargs):
        fd = original_effect(directory, request_id, **kwargs)
        try:
            if request_id == "request-1" and not growth:
                growth.append(None)
                intent(activity, "unrelated-request", lane="other-lane").close()
        except BaseException:
            if fd is not None:
                os.close(fd)
            raise
        return fd

    def vanish_before_open(name, flags, *args, **kwargs):
        if boundary == "before_open" and name == "gitops.jsonl" and flags & os.O_ACCMODE == os.O_RDONLY:
            path.rename(archived)
        fd = original_os.open(name, flags, *args, **kwargs)
        opened.append(fd)
        return fd

    def vanish_before_stat(name, *args, **kwargs):
        if boundary == "before_stat" and name == "gitops.jsonl":
            path.rename(archived)
        return original_os.stat(name, *args, **kwargs)

    def observe(row):
        calls.append(row["request_id"])
        return gitops.Observation(NEW)

    monkeypatch.setattr(gitops, "_try_effect", grow_after_claim)
    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "open": vanish_before_open, "stat": vanish_before_stat}))
    try:
        with pytest.raises(gitops.GitOpsError) as error:
            store.reconcile("lane-1", observe)
        assert error.value.code == "journal_io"
        assert str(error.value) == gitops.REFUSALS["journal_io"]
        assert "storage" in error.value.next_action["command"]
        assert calls == []
    finally:
        monkeypatch.setattr(gitops, "os", original_os)
        monkeypatch.setattr(gitops, "_try_effect", original_effect)
        if archived.exists():
            archived.rename(path)
    for fd in opened:
        with pytest.raises(OSError) as closed:
            os.fstat(fd)
        assert closed.value.errno == errno.EBADF
    assert [row["request_id"] for row in store.open_intents("lane-1")] == ["request-1"]
    assert store.reconcile("lane-1", observe)[0]["status"] == "done"
    assert calls == ["request-1"]
    assert intent(store).created is False


def test_fresh_intent_skips_checkpoint_reset_and_uses_three_fsyncs(make_store, monkeypatch):
    store = make_store()
    original_os, opened, truncations, flushes = gitops.os, [], [], []

    def track_open(path, flags, *args, **kwargs):
        if str(path).startswith("gitops-effect-"):
            opened.append(flags & os.O_ACCMODE)
        return original_os.open(path, flags, *args, **kwargs)

    def track_truncate(fd, size):
        truncations.append(size)
        return original_os.ftruncate(fd, size)

    def track_fsync(fd):
        flushes.append(fd)
        return original_os.fsync(fd)

    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "open": track_open,
                                                       "ftruncate": track_truncate, "fsync": track_fsync}))
    with intent(store) as receipt:
        assert receipt.created is True
        assert truncations == []
        assert opened == [os.O_RDONLY]
        assert len(flushes) == 3


@pytest.mark.parametrize("lock_errno", [errno.EBADF, errno.ENOLCK])
def test_read_only_effect_flock_refuses_unsupported_filesystem(make_store, monkeypatch, lock_errno):
    store = make_store()
    original_fcntl, original_os = gitops.fcntl, gitops.os
    opened, locked = [], []

    def track_open(path, flags, *args, **kwargs):
        fd = original_os.open(path, flags, *args, **kwargs)
        if str(path).startswith("gitops-effect-"):
            opened.append((fd, flags & os.O_ACCMODE))
        return fd

    def unsupported_flock(fd, operation):
        locked.append(fd)
        assert operation == original_fcntl.LOCK_EX | original_fcntl.LOCK_NB
        assert original_fcntl.fcntl(fd, original_fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
        raise OSError(lock_errno, "token=private-flock-error")

    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "open": track_open}))
    monkeypatch.setattr(gitops, "fcntl", SimpleNamespace(**{**vars(original_fcntl), "flock": unsupported_flock}))
    with pytest.raises(gitops.GitOpsError) as error:
        intent(store)
    assert error.value.code == "unsupported_platform"
    assert str(error.value) == gitops.REFUSALS["unsupported_platform"]
    assert "local filesystem" in error.value.next_action["command"]
    assert "common dir" in error.value.next_action["command"]
    assert "private-flock-error" not in str(error.value.next_action)
    assert opened == [(locked[0], os.O_RDONLY)]
    assert len(locked) == 1
    with pytest.raises(OSError) as closed:
        os.fstat(locked[0])
    assert closed.value.errno == errno.EBADF
    assert store.read().rows == []
    monkeypatch.setattr(gitops, "fcntl", original_fcntl)
    with intent(store) as receipt:
        assert receipt.created is True


@pytest.mark.parametrize("caller", ["inherited", "receiptless", "reconcile"])
@pytest.mark.parametrize("lock_errno,code", [(errno.EBADF, "unsupported_platform"),
                                           (errno.ENOLCK, "unsupported_platform"),
                                           (errno.EIO, "journal_io")])
def test_effect_flock_refusal_covers_completion_and_reconcile(make_store, monkeypatch, caller, lock_errno, code):
    store = make_store()
    receipt = intent(store)
    original_os, original_fcntl = gitops.os, gitops.fcntl
    path = store.common_dir / "aegis" / "gitops.jsonl"
    before = path.read_bytes()
    temporary, locked, calls = [], [], []

    def track_open(*args, **kwargs):
        fd = original_os.open(*args, **kwargs)
        temporary.append(fd)
        return fd

    def track_dup(fd):
        duplicate = original_os.dup(fd)
        temporary.append(duplicate)
        return duplicate

    def unsupported_flock(fd, operation):
        locked.append(fd)
        mode = original_fcntl.fcntl(fd, original_fcntl.F_GETFL) & os.O_ACCMODE
        assert mode == (os.O_RDONLY if caller == "inherited" else os.O_RDWR)
        assert operation == original_fcntl.LOCK_EX | original_fcntl.LOCK_NB
        raise OSError(lock_errno, "token=private-flock-boundary-error")

    def observe(row):
        calls.append(row["request_id"])
        return gitops.Observation(NEW)

    with ExitStack() as resources:
        supplied = None
        if caller == "inherited":
            supplied = os.dup(receipt.inheritable_fds()[0])
            resources.callback(os.close, supplied)
        else:
            receipt.close()

        def attempt():
            if caller == "reconcile":
                return store.reconcile("lane-1", observe)
            return store.record_result("request-1", "done", NEW, effect_fd=supplied)

        monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "open": track_open, "dup": track_dup}))
        monkeypatch.setattr(gitops, "fcntl", SimpleNamespace(**{**vars(original_fcntl), "flock": unsupported_flock}))
        with pytest.raises(gitops.GitOpsError) as error:
            attempt()
        assert error.value.code == code
        assert str(error.value) == gitops.REFUSALS[code]
        if code == "unsupported_platform":
            assert "local filesystem" in error.value.next_action["command"]
            assert "common dir" in error.value.next_action["command"]
        else:
            assert "storage" in error.value.next_action["command"]
        assert "private-flock-boundary-error" not in str(error.value.next_action)
        assert len(locked) == 1
        assert calls == []
        assert path.read_bytes() == before
        assert store.open_intents("lane-1") == [receipt.row]
        if supplied is not None:
            os.fstat(supplied)  # Caller custody survives the refused temporary copies.
        monkeypatch.setattr(gitops, "fcntl", original_fcntl)
        monkeypatch.setattr(gitops, "os", original_os)
        for fd in temporary:
            with pytest.raises(OSError) as closed:
                os.fstat(fd)
            assert closed.value.errno == errno.EBADF
        result = attempt()
        assert (result[0] if caller == "reconcile" else result)["status"] == "done"
        assert calls == (["request-1"] if caller == "reconcile" else [])
    assert store.open_intents() == []


@pytest.mark.parametrize("stage", ["saved", "result"])
def test_checkpoint_fsync_refusal_preserves_storage_cause_and_saved_result(make_store, checkpointed_store, monkeypatch, stage):
    store = checkpointed_store() if stage == "saved" else make_store()
    if stage == "result":
        intent(store).close()
    path = next((store.common_dir / "aegis").glob("gitops-effect-*.lock"))
    checkpoint_inode, original_os = path.stat().st_ino, gitops.os
    intent(store, "request-2").close()
    calls = []

    def failed_checkpoint_fsync(fd):
        info = os.fstat(fd)
        if info.st_ino == checkpoint_inode and info.st_size > 2:
            raise OSError(errno.EIO, "token=private-fsync-error")
        return original_os.fsync(fd)

    def observe(row):
        calls.append(row["request_id"])
        return gitops.Observation(NEW)

    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "fsync": failed_checkpoint_fsync}))
    with pytest.raises(gitops.GitOpsError) as error:
        store.reconcile("lane-1", observe)
    assert error.value.code == "journal_io"
    assert str(error.value) == gitops.REFUSALS["journal_io"]
    assert "storage" in error.value.next_action["command"]
    assert "request_ids" not in error.value.next_action
    assert "private-fsync-error" not in str(error.value.next_action)
    assert calls == (["request-1", "request-2"] if stage == "result" else ["request-2"])
    assert [row["request_id"] for row in store.open_intents()] == ["request-1"]
    monkeypatch.setattr(gitops, "os", original_os)
    assert store.reconcile("lane-1", lambda row: pytest.fail("saved result re-observed"))[0]["status"] == "done"
    assert store.open_intents() == []


def test_stuck_checkpoint_refusal_caps_ids_and_exposes_remaining_recovery(make_store):
    store = make_store()
    requests = ["request-" + str(index).zfill(2) for index in range(19)]
    for request in requests:
        intent(store, request).close()
    for path in (store.common_dir / "aegis").glob("gitops-effect-*.lock"):
        path.write_bytes(b"!\n")
    for remaining in (requests, requests[16:]):
        with pytest.raises(gitops.GitOpsError) as error:
            store.reconcile("lane-1", lambda row: pytest.fail("stuck checkpoint observed"))
        assert error.value.code == "checkpoint_stuck"
        action = error.value.next_action
        assert action["request_ids"] == remaining[:16]
        assert action["request_ids_truncated"] is (len(remaining) > 16)
        assert "16" in action["command"]
        assert "reconcile again" in action["command"]
        for request in remaining[:16]:
            assert store.record_result(request, "done", NEW)["status"] == "done"
    assert store.reconcile("lane-1", lambda row: pytest.fail("completed intent observed")) == []


def test_inherited_effect_descriptor_is_read_only_and_preserves_completion(make_store):
    store = make_store()
    receipt = intent(store)
    fd, = receipt.inheritable_fds()
    script = """
import errno, fcntl, os, sys
sys.path.insert(0, sys.argv[1])
from aegis_core.team_gitops import GitOpsJournal
fd = int(sys.argv[3])
try:
    assert fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
    try:
        os.write(fd, b'forged-checkpoint')
    except OSError as error:
        assert error.errno == errno.EBADF
    else:
        raise AssertionError('inherited checkpoint descriptor is writable')
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert GitOpsJournal(sys.argv[2]).record_result('request-1', 'done', 'b'*40, effect_fd=fd)['status'] == 'done'
finally:
    os.close(fd)
"""
    child = subprocess.run([sys.executable, "-I", "-c", script,
                            str(Path(__file__).resolve().parents[3]), str(store.common_dir), str(fd)],
                           pass_fds=(fd,), capture_output=True, timeout=20)
    assert child.returncode == 0, child.stderr
    assert store.record_result("request-1", "done", NEW, receipt=receipt)["status"] == "done"


def test_failed_reservation_cleanup_stays_closed_until_owner_resolution(make_store, monkeypatch):
    store = make_store()
    intent(store).close()
    path = next((store.common_dir / "aegis").glob("gitops-effect-*.lock"))
    checkpoint_inode, original_os = path.stat().st_ino, gitops.os
    calls = []

    def short_write(fd, payload):
        if os.fstat(fd).st_ino == checkpoint_inode:
            return original_os.write(fd, payload[:1])
        return original_os.write(fd, payload)

    def failed_cleanup(fd, size):
        if os.fstat(fd).st_ino == checkpoint_inode:
            raise OSError(errno.ENOSPC, "token=private-cleanup-error")
        return original_os.ftruncate(fd, size)

    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "write": short_write, "ftruncate": failed_cleanup}))
    refusal("checkpoint_stuck", lambda: store.reconcile("lane-1", lambda row: calls.append(row)))
    assert path.read_bytes() == b"!"
    monkeypatch.setattr(gitops, "os", original_os)
    refusal("checkpoint_stuck", lambda: store.reconcile("lane-1", lambda row: calls.append(row)))
    assert calls == []
    assert store.record_result("request-1", "done", NEW)["status"] == "done"
    assert store.reconcile("lane-1", lambda row: calls.append(row)) == []
    assert calls == []


@pytest.mark.parametrize("phase", ["reservation", "result"])
def test_checkpoint_io_refusal_is_local_to_its_intent(make_store, monkeypatch, phase):
    store = make_store()
    intent(store).close()
    path = next((store.common_dir / "aegis").glob("gitops-effect-*.lock"))
    checkpoint_inode, original_os = path.stat().st_ino, gitops.os
    intent(store, "request-2").close()
    calls = []

    def failed_checkpoint_write(fd, payload):
        if os.fstat(fd).st_ino == checkpoint_inode and (phase == "reservation" or bytes(payload) != b"!\n"):
            raise OSError(errno.ENOSPC, "token=private-checkpoint-error")
        return original_os.write(fd, payload)

    def observe(row):
        calls.append(row["request_id"])
        return gitops.Observation(NEW)

    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "write": failed_checkpoint_write}))
    with pytest.raises(gitops.GitOpsError) as error:
        store.reconcile("lane-1", observe)
    code = "journal_io" if phase == "reservation" else "checkpoint_stuck"
    assert error.value.code == code
    if phase == "reservation":
        assert "storage" in error.value.next_action["command"]
        assert "request_ids" not in error.value.next_action
        assert path.read_bytes() == b""
    else:
        assert error.value.next_action["request_ids"] == ["request-1"]
    assert "private-checkpoint-error" not in str(error.value.next_action)
    assert [row["request_id"] for row in store.open_intents()] == ["request-1"]
    monkeypatch.setattr(gitops, "os", original_os)
    if phase == "reservation":
        assert calls == ["request-2"]
        assert store.reconcile("lane-1", observe)[0]["request_id"] == "request-1"
        assert calls == ["request-2", "request-1"]
    else:
        assert calls == ["request-1", "request-2"]
        refusal("checkpoint_stuck", lambda: store.reconcile("lane-1", observe))
        assert calls == ["request-1", "request-2"]
        store.record_result("request-1", "done", NEW)
    assert store.reconcile("lane-1", observe) == []


def test_failed_new_intent_checkpoint_reset_closes_descriptors_before_retry(checkpointed_store, monkeypatch):
    store = checkpointed_store()
    (store.common_dir / "aegis" / "gitops.jsonl").write_bytes(b"")
    original_os, opened = gitops.os, []

    def track_open(*args, **kwargs):
        fd = original_os.open(*args, **kwargs)
        opened.append(fd)
        return fd

    def failed_reset(fd, size):
        raise OSError(errno.ENOSPC, "token=private-reset-error")

    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "open": track_open, "ftruncate": failed_reset}))
    refusal("journal_io", lambda: intent(store, expected_old=NEW, expected_new="c" * 40))
    for fd in opened:
        with pytest.raises(OSError) as error:
            os.fstat(fd)
        assert error.value.errno == errno.EBADF
    monkeypatch.setattr(gitops, "os", original_os)
    assert store.read().rows == []
    receipt = intent(store, expected_old=NEW, expected_new="c" * 40)
    assert receipt.created is True
    assert store.record_result("request-1", "done", "c" * 40, receipt=receipt)["status"] == "done"


def test_stuck_checkpoint_refusal_redacts_each_request_identifier(make_store):
    store = make_store()
    secret_id = "ghp_" + "A" * 30
    for request in (secret_id, "other-stuck"):
        before = set((store.common_dir / "aegis").glob("gitops-effect-*.lock"))
        intent(store, request).close()
        path, = set((store.common_dir / "aegis").glob("gitops-effect-*.lock")) - before
        path.write_bytes(b"!\n")
    with pytest.raises(gitops.GitOpsError) as error:
        store.reconcile("lane-1", lambda row: pytest.fail("stuck checkpoint observed"))
    assert error.value.code == "checkpoint_stuck"
    shown = error.value.next_action["request_ids"]
    assert len(shown) == 2
    assert shown[1] == "other-stuck"
    assert secret_id not in str(error.value) + json.dumps(error.value.next_action)
    assert "REDACTED" in shown[0]
    assert all(value.isprintable() and len(value) <= gitops.DISPLAY_LIMIT for value in shown)


def test_delayed_reconciler_preserves_healthy_completion_beside_stuck_checkpoint(make_store, monkeypatch):
    store = make_store()
    intent(store, "request-2-stuck").close()
    path = next((store.common_dir / "aegis").glob("gitops-effect-*.lock"))
    path.write_bytes(b"!\n")
    intent(store).close()
    delayed = gitops.GitOpsJournal(store.common_dir)
    original_effect = gitops._try_effect
    pending_read, resume = Event(), Event()
    calls = []

    def delayed_claim(directory, request_id):
        if not pending_read.is_set():
            pending_read.set()
            assert resume.wait(15), "delayed reconciler not released"
        return original_effect(directory, request_id)

    def observe(row):
        calls.append(row["request_id"])
        return gitops.Observation(NEW)

    monkeypatch.setattr(gitops, "_try_effect", delayed_claim)
    with ThreadPoolExecutor(max_workers=1) as pool:
        following = pool.submit(delayed.reconcile, "lane-1", observe)
        try:
            assert pending_read.wait(10), "delayed reconciler did not read pending intents"
            refusal("checkpoint_stuck", lambda: store.reconcile("lane-1", observe))
        finally:
            resume.set()
        refusal("checkpoint_stuck", lambda: following.result(timeout=20))
    assert calls == ["request-1"]
    assert [row["request_id"] for row in store.open_intents()] == ["request-2-stuck"]


@pytest.mark.parametrize("component", ["ancestor", "aegis", "gitops.jsonl", "gitops.lock"])
def test_symlink_components_are_refused_without_touching_victim(make_store, tmp_path, component):
    store = make_store()
    victim = tmp_path / "victim"
    victim.mkdir()
    marker = victim / "marker"
    marker.write_bytes(b"unchanged")
    if component == "ancestor":
        link = tmp_path / "alias"
        symlink_or_skip(victim, link, target_is_directory=True)
        store = gitops.GitOpsJournal(link / "nested")
    elif component == "aegis":
        symlink_or_skip(victim, store.common_dir / "aegis", target_is_directory=True)
    else:
        (store.common_dir / "aegis").mkdir()
        symlink_or_skip(marker, store.common_dir / "aegis" / component)
    refusal("unsafe_journal", lambda: intent(store))
    assert marker.read_bytes() == b"unchanged"
    assert sorted(p.name for p in victim.iterdir()) == ["marker"]


def test_concurrent_ancestor_rename_keeps_io_on_anchored_directory(make_store, monkeypatch, tmp_path):
    store = make_store()
    intent(store)
    original = gitops.storage.file_lock
    moved = tmp_path / "moved"
    victim = tmp_path / "victim"
    victim.mkdir()
    @contextmanager
    def move_after_anchor(*args, **kwargs):
        with original(*args, **kwargs):
            store.common_dir.rename(moved)
            symlink_or_skip(victim, store.common_dir, target_is_directory=True)
            yield
    # Replace this module's reference, never the shared storage module global.
    monkeypatch.setattr(gitops, "storage", SimpleNamespace(file_lock=move_after_anchor,
                       confined_descriptor_supported=gitops.storage.confined_descriptor_supported))
    intent(store, "request-2")
    assert list(victim.iterdir()) == []
    assert b"request-2" in (moved / "aegis" / "gitops.jsonl").read_bytes()


def test_lock_failure_has_fixed_refusal_and_no_result(make_store, monkeypatch):
    store = make_store()
    intent(store)
    @contextmanager
    def timeout(*args, **kwargs):
        raise gitops.LockTimeoutError("sensitive OS diagnostic")
        yield
    monkeypatch.setattr(gitops, "storage", SimpleNamespace(file_lock=timeout,
                       confined_descriptor_supported=gitops.storage.confined_descriptor_supported))
    refusal("journal_busy", lambda: store.record_result("request-1", "done", NEW))


def test_failed_append_keeps_request_reserved_and_closes_descriptors(make_store, monkeypatch):
    store = make_store()
    intent(store)
    opened = []
    real_open = os.open
    def tracking_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd
    def failed_write(*args):
        raise OSError(errno.ENOSPC, "token=secret")
    local_os = SimpleNamespace(**{**vars(os), "open": tracking_open, "write": failed_write})
    monkeypatch.setattr(gitops, "os", local_os)
    refusal("journal_io", lambda: store.record_result("request-1", "done", NEW))
    for fd in opened:
        with pytest.raises(OSError) as error:
            os.fstat(fd)
        assert error.value.errno == errno.EBADF
    assert intent(store).created is False
    assert len(store.open_intents()) == 1


def test_display_canonicalizes_then_redacts_then_truncates_every_string_field():
    secret = "ghp_" + "A" * 30
    hostile = "\x1b[31mgh\x1b[0mp_" + "A" * 30
    shown = gitops.display_row({hostile: {"actor": hostile, "state": "x" * 500 + " token=" + secret}})
    encoded = json.dumps(shown)
    assert secret not in encoded and "\u001b" not in encoded
    assert "ghp_REDACTED" in encoded
    assert len(shown["ghp_REDACTED"]["state"]) <= gitops.DISPLAY_LIMIT


@pytest.mark.parametrize("root", ["relative", "null\x00root", "bad\ud800root"])
def test_invalid_root_has_documented_refusal(tmp_path, root):
    path = root if root == "relative" else str(tmp_path / root)
    refusal("unsafe_journal", lambda: gitops.GitOpsJournal(path).read())


def test_fresh_process_after_effect_without_receipt_observes_once(make_store, tmp_path):
    store = make_store()
    marker = tmp_path / "effect-count"
    script = """
import os, sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from aegis_core.team_gitops import GitOpsJournal
store = GitOpsJournal(sys.argv[2])
receipt = store.record_intent(op='ref_update', lane='lane-1', request_id='crash-1',
                            expected_old='a'*40, expected_new='b'*40, actor='session-1')
if receipt.created:
    Path(sys.argv[3]).write_bytes(b'one effect')
os._exit(0)
"""
    result = subprocess.run([sys.executable, "-I", "-c", script,
                             str(Path(__file__).resolve().parents[3]), str(store.common_dir), str(marker)],
                            capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    restarted = gitops.GitOpsJournal(store.common_dir)
    rows = restarted.reconcile("lane-1", lambda row: gitops.Observation(NEW if marker.exists() else OLD))
    assert [row["status"] for row in rows] == ["done"]
    assert intent(restarted, "crash-1", op="ref_update").created is False
    assert marker.read_bytes() == b"one effect"
    assert len(restarted.read().rows) == 2


def test_partial_write_and_durability_failure_never_grant_retry(make_store, monkeypatch):
    store = make_store()
    real_write = os.write
    local_os = SimpleNamespace(**{**vars(os), "write": lambda fd, data: real_write(fd, data[:7])})
    monkeypatch.setattr(gitops, "os", local_os)
    assert intent(store).created is True
    assert len(store.read().rows) == 1
    real_fsync = os.fsync
    def fail_file_fsync(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "secret file error")
        real_fsync(fd)
    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "fsync": fail_file_fsync}))
    refusal("journal_io", lambda: store.record_result("request-1", "done", NEW))
    monkeypatch.setattr(gitops, "os", local_os)
    assert intent(store).created is False
    assert len(store.read().rows) == 2


@pytest.mark.parametrize("kind", ["hardlink", "fifo"])
def test_nonprivate_journal_files_refuse_before_read(make_store, tmp_path, kind):
    store = make_store()
    directory = store.common_dir / "aegis"
    directory.mkdir()
    path = directory / "gitops.jsonl"
    if kind == "hardlink":
        victim = tmp_path / "victim"
        victim.write_bytes(b"unchanged")
        os.link(victim, path)
    else:
        os.mkfifo(path)
    refusal("unsafe_journal", store.read)


def test_malformed_result_cannot_close_intent_or_expose_fields(make_store):
    store = make_store()
    row = intent(store).row
    path = store.common_dir / "aegis" / "gitops.jsonl"
    bad = dict(row, kind="result", status="done", observed=OLD)
    with path.open("ab") as stream:
        stream.write(json.dumps(bad).encode() + b"\n")
        stream.write(b'{"v":1,"v":2}\n')
        stream.write(b"[" * 2000 + b"]" * 2000 + b"\n")
    assert store.read().skipped == 3
    assert store.open_intents() == [row]


def test_clock_rollback_does_not_lose_terminal_result(make_store, monkeypatch):
    store = make_store()
    monkeypatch.setattr(gitops, "utc_stamp", lambda: "2026-11-12T10:00:00Z")
    intent(store)
    monkeypatch.setattr(gitops, "utc_stamp", lambda: "2026-11-12T09:59:00Z")
    store.record_result("request-1", "done", NEW)
    assert store.open_intents() == []
    assert len(store.read().rows) == 2


def test_observer_cannot_mutate_the_journal_binding(make_store):
    store = make_store()
    first = orphan_intent(store)
    def observe(row):
        row["actor"] = "other-session"
        row["expected_new"] = OLD
        return gitops.Observation(NEW)
    result = store.reconcile("lane-1", observe)[0]
    assert result["status"] == "done"
    assert result["actor"] == first.row["actor"]
    assert result["expected_new"] == NEW


def test_reconcile_skips_live_effect_and_accepts_owners_result(make_store):
    owner = make_store()
    observer = gitops.GitOpsJournal(owner.common_dir)
    receipt = intent(owner)
    assert receipt.created is True
    calls = []
    assert observer.reconcile("lane-1", lambda row: calls.append(row) or gitops.Observation(OLD)) == []
    assert calls == []
    assert observer.open_intents() == [receipt.row]
    # A fresh object in this process is still the owner when it presents the
    # receipt. A distinct process must continue to refuse the live effect.
    script = """
import sys
sys.path.insert(0, sys.argv[1])
from aegis_core.team_gitops import GitOpsJournal, GitOpsError
try:
    GitOpsJournal(sys.argv[2]).record_result('request-1', 'not_applied', 'a'*40)
except GitOpsError as error:
    print(error.code)
"""
    other = subprocess.run([sys.executable, "-I", "-c", script,
                            str(Path(__file__).resolve().parents[3]), str(owner.common_dir)],
                           capture_output=True, text=True, timeout=20)
    assert other.returncode == 0, other.stderr
    assert other.stdout.strip() == "effect_busy"
    assert observer.record_result("request-1", "done", NEW, receipt=receipt)["status"] == "done"
    assert observer.record_result("request-1", "done", NEW)["status"] == "done"
    assert observer.open_intents() == []


def test_sigkill_releases_effect_ownership_for_observation(make_store):
    store = make_store()
    script = """
import os, signal, sys
sys.path.insert(0, sys.argv[1])
from aegis_core.team_gitops import GitOpsJournal
GitOpsJournal(sys.argv[2]).record_intent(op='push', lane='lane-1', request_id='killed',
    expected_old='a'*40, expected_new='b'*40, actor='session-1')
os.kill(os.getpid(), signal.SIGKILL)
"""
    child = subprocess.run([sys.executable, "-I", "-c", script,
                            str(Path(__file__).resolve().parents[3]), str(store.common_dir)],
                           capture_output=True, timeout=20)
    assert child.returncode == -signal.SIGKILL
    assert store.reconcile("lane-1", lambda row: gitops.Observation(NEW))[0]["status"] == "done"
    assert store.reconcile("lane-1", lambda row: pytest.fail("second observation")) == []
    assert intent(store, "killed").created is False


def test_existing_directory_flush_is_required_before_receipt(make_store, monkeypatch):
    store = make_store()
    (store.common_dir / "aegis").mkdir(mode=0o700)
    parent = store.common_dir.stat()
    flushed = []
    original = storage_confined._flush
    def record_flush(fd):
        info = os.fstat(fd)
        flushed.append((info.st_dev, info.st_ino))
        original(fd)
    monkeypatch.setattr(storage_confined, "_flush", record_flush)
    assert intent(store).created is True
    assert (parent.st_dev, parent.st_ino) in flushed
    store.record_result("request-1", "done", NEW)


def test_parent_flush_failure_refuses_then_can_retry(make_store, monkeypatch):
    store = make_store()
    original = storage_confined._flush
    def failed_flush(fd):
        raise storage_confined.ConfinedFileError("durability")
    monkeypatch.setattr(storage_confined, "_flush", failed_flush)
    refusal("journal_io", lambda: intent(store))
    monkeypatch.setattr(storage_confined, "_flush", original)
    assert intent(store).created is True
    store.record_result("request-1", "done", NEW)


@pytest.mark.parametrize("kind", ["intent", "result"])
def test_complete_uncommitted_tail_is_permanently_quarantined(make_store, kind):
    store = make_store()
    old = orphan_intent(store).row
    path = store.common_dir / "aegis" / "gitops.jsonl"
    if kind == "intent":
        path.write_bytes(json.dumps(old).encode())
        receipt = intent(store, expected_new="c" * 40)
        assert receipt.created is True
        assert store.read().rows == [receipt.row]
        store.record_result("request-1", "done", "c" * 40)
    else:
        tail = dict(old, kind="result", status="done", observed=NEW)
        with path.open("ab") as stream:
            stream.write(json.dumps(tail).encode())
        result = store.record_result("request-1", "not_applied", OLD)
        assert store.read().rows == [old, result]
    assert store.read().skipped == 1
    assert store.read().torn_tail is False
    assert store.open_intents() == []


def test_reads_use_only_readonly_descriptors_without_a_lock(make_store, monkeypatch):
    store = make_store()
    row = intent(store).row
    original_open = os.open
    calls = []
    def readonly_open(path, flags, *args, **kwargs):
        calls.append(flags)
        assert flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT) == 0
        return original_open(path, flags, *args, **kwargs)
    @contextmanager
    def forbidden_lock(*args, **kwargs):
        pytest.fail("reader took an exclusive lock")
        yield
    monkeypatch.setattr(gitops, "storage", SimpleNamespace(file_lock=forbidden_lock,
                       confined_descriptor_supported=gitops.storage.confined_descriptor_supported))
    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "open": readonly_open}))
    assert store.read().rows == [row]
    assert store.open_intents() == [row]
    assert len(calls) >= 2


def test_reads_in_readonly_journal_directory(make_store):
    store = make_store()
    row = intent(store).row
    directory = store.common_dir / "aegis"
    before = stat.S_IMODE(directory.stat().st_mode)
    files = list(directory.iterdir())
    for path in files:
        path.chmod(0o400)
    directory.chmod(0o500)
    try:
        probe = directory / "write-probe"
        try:
            probe.write_bytes(b"probe")
        except PermissionError:
            pass
        else:
            probe.unlink()
            pytest.skip("platform/user cannot express a read-only directory")
        assert store.read().rows == [row]
        assert store.open_intents() == [row]
    finally:
        directory.chmod(before)
        for path in files:
            path.chmod(0o600)


def test_admission_reserves_every_outstanding_result_and_names_next_action(make_store, monkeypatch):
    store = make_store()
    monkeypatch.setattr(gitops, "MAX_JOURNAL_BYTES", 2 * (gitops.MAX_ROW_BYTES + 3) + 2048)
    assert intent(store).created is True
    assert intent(store, "request-2").created is True
    refusal("journal_capacity", lambda: intent(store, "request-3"))
    assert intent(store).created is False
    assert store.record_result("request-1", "done", NEW)["status"] == "done"
    assert store.record_result("request-2", "not_applied", OLD)["status"] == "not_applied"
    assert "reconcile" in gitops.REFUSALS["journal_capacity"]
    assert intent(store, "request-3").created is True
    store.record_result("request-3", "done", NEW)


def test_reserved_results_fit_when_reconciling_large_observations(make_store, monkeypatch):
    store = make_store()
    orphan_intent(store)
    orphan_intent(store, "request-2")
    monkeypatch.setattr(gitops, "MAX_JOURNAL_BYTES", 2 * (gitops.MAX_ROW_BYTES + 3) + 2048)
    refusal("journal_capacity", lambda: intent(store, "request-3"))
    state = {key: "x" * 1024 for key in ("path", "state", "branch", "ref")}
    rows = store.reconcile("lane-1", lambda row: gitops.Observation(state))
    assert [row["status"] for row in rows] == ["unknown", "unknown"]
    assert store.open_intents() == []


def test_grammar_valid_identifiers_and_branch_text_are_accepted(make_store):
    store = make_store()
    lane = "teams-t2a-gm-4-gitops-journal"
    receipt = intent(store, "01ARZ3NDEKTSV4RRFFQ69G5FAV", lane=lane,
                     actor="claude-019c6e27-e55b-73d1-87d8-4e01f1f75043",
                     expected_old={"branch": "lane/" + lane}, expected_new={"branch": "lane/next"})
    assert receipt.created is True
    assert store.open_intents(lane) == [receipt.row]
    store.record_result(receipt.row["request_id"], "done", {"branch": "lane/next"})
    assert intent(store, "dotted", lane="lane.with.dots").created is True


def test_lane_grammar_matches_team_exactly():
    import re
    from aegis_core.team import LANE_GRAMMAR
    for lane in ("a", "a.b", "a.", "a..b", "a_lock", "A", "a/b", "a" * 63, "a" * 64):
        assert bool(gitops._LANE.fullmatch(lane)) == bool(re.fullmatch(LANE_GRAMMAR, lane))


def test_redaction_policy_cannot_hide_stored_intents(make_store, monkeypatch):
    store = make_store()
    row = intent(store, expected_new={"branch": "lane/allowed"}).row
    monkeypatch.setattr(gitops, "redact_command_secrets", lambda text: "[changed-policy]")
    assert store.read().rows == [row]
    assert store.open_intents() == [row]


def test_slow_observer_does_not_hold_the_journal_lock(make_store):
    store = make_store()
    orphan_intent(store)
    entered, release = Event(), Event()
    def observe(row):
        entered.set()
        if not release.wait(15):
            raise TimeoutError("test barrier")
        return gitops.Observation(NEW)
    with ThreadPoolExecutor(max_workers=2) as pool:
        observed = pool.submit(store.reconcile, "lane-1", observe)
        try:
            assert entered.wait(10)
            writer = gitops.GitOpsJournal(store.common_dir)
            receipt = intent(writer, "concurrent")
            assert receipt.created is True
            writer.record_result("concurrent", "done", NEW)
        finally:
            release.set()
        assert observed.result(timeout=15)[0]["status"] == "done"


def test_reconcile_reads_snapshot_and_recheck_only(make_store, monkeypatch):
    store = make_store()
    orphan_intent(store)
    orphan_intent(store, "request-2")
    calls = []
    original = gitops._read_fd
    def counted(fd):
        calls.append(fd)
        return original(fd)
    monkeypatch.setattr(gitops, "_read_fd", counted)
    assert len(store.reconcile("lane-1", lambda row: gitops.Observation(NEW))) == 2
    assert len(calls) <= 2


def test_parse_line_count_is_bounded_before_row_parsing(make_store):
    store = make_store()
    intent(store)
    (store.common_dir / "aegis" / "gitops.jsonl").write_bytes(b"\n" * 32769)
    refusal("journal_too_large", store.read)


def test_symlink_refusal_names_canonical_root_without_echoing_input(make_store, tmp_path):
    store = make_store()
    alias = tmp_path / "alias"
    symlink_or_skip(store.common_dir, alias, target_is_directory=True)
    supplied = gitops.GitOpsJournal(alias)
    with pytest.raises(gitops.GitOpsError) as error:
        intent(supplied)
    assert error.value.code == "unsafe_journal"
    assert error.value.next_action["path"] == str(store.common_dir.resolve())
    assert "realpath" in error.value.next_action["command"]
    assert str(alias) not in str(error.value)
    assert intent(gitops.GitOpsJournal(store.common_dir.resolve())).created is True


@pytest.mark.parametrize("response", [OSError("token=private"), TimeoutError("temporary"), None, "invalid"])
def test_transient_observer_failure_stays_pending_until_observable(make_store, response):
    store = make_store()
    row = orphan_intent(store).row
    def unavailable(intent):
        if isinstance(response, Exception):
            raise response
        return response
    assert store.reconcile("lane-1", unavailable) == []
    assert store.open_intents() == [row]
    assert len(store.read().rows) == 1
    assert store.reconcile("lane-1", lambda row: gitops.Observation(NEW))[0]["status"] == "done"
    assert intent(store).created is False


def test_admission_reserves_parse_slots_as_well_as_bytes(make_store, monkeypatch):
    store = make_store()
    monkeypatch.setattr(gitops, "MAX_RECORD_LINES", 6)
    intent(store)
    intent(store, "request-2")
    refusal("journal_capacity", lambda: intent(store, "request-3"))
    store.record_result("request-1", "done", NEW)
    store.record_result("request-2", "done", NEW)
    assert len(store.read().rows) == 4
    assert store.open_intents() == []


def test_reconcile_rechecks_terminal_state_before_appending(make_store, monkeypatch):
    owner = make_store()
    intent(owner)
    observer = gitops.GitOpsJournal(owner.common_dir)
    original = gitops._try_effect
    def finish_before_acquire(directory, request_id):
        owner.record_result(request_id, "done", NEW)
        return original(directory, request_id)
    monkeypatch.setattr(gitops, "_try_effect", finish_before_acquire)
    assert observer.reconcile("lane-1", lambda row: gitops.Observation(OLD)) == []
    assert len(observer.read().rows) == 2
    assert observer.read().rows[-1]["status"] == "done"


@pytest.mark.parametrize("reason,code", [("unsupported", "unsupported_platform"),
                                        ("too_large", "journal_too_large"),
                                        ("unsafe", "unsafe_journal"),
                                        ("durability", "journal_io"), ("io", "journal_io")])
def test_storage_refusals_are_not_downgraded(tmp_path, monkeypatch, reason, code):
    @contextmanager
    def refused(*args, **kwargs):
        raise storage_confined.ConfinedFileError(reason)
        yield
    monkeypatch.setattr(gitops, "descriptor_supported", lambda: True)
    monkeypatch.setattr(gitops, "confined_file", refused)
    refusal(code, gitops.GitOpsJournal(tmp_path).read)


def test_refused_receipt_closes_effect_handle_if_transaction_exit_fails(make_store, monkeypatch):
    store = make_store()
    opened = []
    original_open, original_storage = os.open, gitops.storage
    def tracked(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        opened.append(fd)
        return fd
    @contextmanager
    def fail_exit(*args, **kwargs):
        with original_storage.file_lock(*args, **kwargs):
            yield
        raise OSError(errno.EIO, "private lock diagnostic")
    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "open": tracked}))
    monkeypatch.setattr(gitops, "storage", SimpleNamespace(file_lock=fail_exit,
                       confined_descriptor_supported=original_storage.confined_descriptor_supported))
    refusal("journal_io", lambda: intent(store))
    for fd in opened:
        with pytest.raises(OSError) as error:
            os.fstat(fd)
        assert error.value.errno == errno.EBADF
    monkeypatch.setattr(gitops, "storage", original_storage)
    assert intent(store).created is False
    assert store.reconcile("lane-1", lambda row: gitops.Observation(OLD))[0]["status"] == "not_applied"


def test_sigkill_owner_keeps_inherited_child_effect_in_flight(make_store):
    store = make_store()
    read_end, write_end = os.pipe()
    script = """
import os, signal, subprocess, sys
sys.path.insert(0, sys.argv[1])
from aegis_core.team_gitops import GitOpsJournal
receipt = GitOpsJournal(sys.argv[2]).record_intent(op='push', lane='lane-1', request_id='inherited',
    expected_old='a'*40, expected_new='b'*40, actor='owner')
subprocess.Popen([sys.executable, '-I', '-c',
    'import os, select, sys; fd=int(sys.argv[1]); select.select([fd], [], [], 30); os.read(fd, 1)',
    sys.argv[3]], pass_fds=receipt.inheritable_fds() + (int(sys.argv[3]),),
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
os.kill(os.getpid(), signal.SIGKILL)
"""
    observe_script = """
import json, sys
sys.path.insert(0, sys.argv[1])
from aegis_core.team_gitops import GitOpsJournal, Observation
store = GitOpsJournal(sys.argv[2])
rows = store.reconcile('lane-1', lambda row: Observation('a'*40))
print(json.dumps({'results': rows, 'pending': len(store.open_intents())}))
"""
    try:
        owner = subprocess.run([sys.executable, "-I", "-c", script,
                                str(Path(__file__).resolve().parents[3]), str(store.common_dir), str(read_end)],
                               pass_fds=(read_end,), capture_output=True, timeout=20)
        assert owner.returncode == -signal.SIGKILL, owner.stderr
        for _ in range(2):
            observer = subprocess.run([sys.executable, "-I", "-c", observe_script,
                                       str(Path(__file__).resolve().parents[3]), str(store.common_dir)],
                                      capture_output=True, text=True, timeout=20)
            assert observer.returncode == 0, observer.stderr
            assert json.loads(observer.stdout) == {"results": [], "pending": 1}
        assert len(store.read().rows) == 1
        os.write(write_end, b"x")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            rows = store.reconcile("lane-1", lambda row: gitops.Observation(NEW))
            if rows:
                break
            time.sleep(0.01)
        assert [row["status"] for row in rows] == ["done"]
        assert store.reconcile("lane-1", lambda row: pytest.fail("terminal retry observed")) == []
    finally:
        os.close(write_end)
        os.close(read_end)


def test_inheriting_child_can_record_result_with_descriptor(make_store):
    store = make_store()
    receipt = intent(store)
    script = """
import os, sys
sys.path.insert(0, sys.argv[1])
from aegis_core.team_gitops import GitOpsJournal
fd = int(sys.argv[3])
try:
    store = GitOpsJournal(sys.argv[2])
    result = store.record_result('request-1', 'done', 'b'*40, effect_fd=fd)
    assert store.record_result('request-1', 'done', 'b'*40, effect_fd=fd) == result
    print(result['status'])
finally:
    os.close(fd)
"""
    fds = receipt.inheritable_fds()
    assert len(fds) == 1
    child = subprocess.run([sys.executable, "-I", "-c", script,
                            str(Path(__file__).resolve().parents[3]), str(store.common_dir), str(fds[0])],
                           pass_fds=fds, capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stderr
    assert child.stdout.strip() == "done"
    assert store.record_result("request-1", "done", NEW, receipt=receipt)["status"] == "done"
    with pytest.raises(OSError) as error:
        os.fstat(fds[0])
    assert error.value.errno == errno.EBADF


@pytest.mark.parametrize("ending", ["close", "release", "context", "exception", "terminal"])
def test_receipt_lifetime_is_explicit_and_retry_never_regrants(make_store, ending):
    store = make_store()
    receipt = intent(store)
    fd, = receipt.inheritable_fds()
    if ending == "terminal":
        store.record_result("request-1", "done", NEW, receipt=receipt)
    elif ending in ("context", "exception"):
        try:
            with receipt as entered:
                assert entered is receipt
                if ending == "exception":
                    raise ValueError("caller stopped")
        except ValueError:
            pass
    elif ending == "close":
        receipt.close()
    else:
        receipt.release()
    receipt.close()
    receipt.release()
    with pytest.raises(OSError) as error:
        os.fstat(fd)
    assert error.value.errno == errno.EBADF
    assert intent(store).created is False
    refusal("effect_busy", receipt.inheritable_fds)
    if ending != "terminal":
        assert store.reconcile("lane-1", lambda row: gitops.Observation(OLD))[0]["status"] == "not_applied"


@pytest.mark.parametrize("character,shape", [("\U00010000", "argon"), ("\U0001f600", "security")])
@pytest.mark.parametrize("completion", ["direct", "reconcile"])
def test_astral_terminal_rows_refuse_before_effect_admission(make_store, character, shape, completion):
    store = make_store()
    state = {"path": character * 1024, "branch": character * 1024,
             "ref" if shape == "argon" else "state": character * (1000 if shape == "argon" else 1024)}
    changes = (dict(op="worktree_remove", expected_old=state, expected_new=None)
               if shape == "argon" else dict(expected_new=state))
    def attempt():
        receipt = intent(store, "unicode", **changes)
        try:
            if completion == "direct":
                store.record_result("unicode", "not_applied" if shape == "argon" else "done", state)
            else:
                receipt.close()
                store.reconcile("lane-1", lambda row: gitops.Observation(state))
        finally:
            receipt.close()
    refusal("invalid_intent", attempt)
    assert store.read().rows == []
    # A refusal grants no execution ownership and does not consume the request.
    assert intent(store, "unicode").created is True
    store.record_result("unicode", "done", NEW)


@pytest.mark.parametrize("completion", ["direct", "reconcile"])
def test_largest_astral_foreign_observation_fits_reserved_capacity(make_store, completion):
    store = make_store()
    receipt = intent(store)
    state = {key: "\U00010000" * 1024 for key in ("path", "state", "branch", "ref")}
    if completion == "direct":
        rows = [store.record_result("request-1", "unknown", state)]
    else:
        receipt.close()
        rows = store.reconcile("lane-1", lambda row: gitops.Observation(state))
    assert rows[0]["observed"] == state
    assert store.open_intents() == []
    assert max(map(len, (store.common_dir / "aegis" / "gitops.jsonl").read_bytes().splitlines())) <= gitops.MAX_ROW_BYTES


@pytest.mark.parametrize("failure", ["io", "size"])
def test_reconcile_append_refusal_is_fixed_retriable_and_releases_ownership(make_store, monkeypatch, failure):
    store = make_store()
    orphan_intent(store)
    original_os, row_cap = gitops.os, gitops.MAX_ROW_BYTES
    if failure == "io":
        def failed_write(*args):
            raise OSError(errno.ENOSPC, "token=private-input")
        monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "write": failed_write}))
    else:
        # The intent remains readable, but a terminal row cannot fit this cap.
        monkeypatch.setattr(gitops, "MAX_ROW_BYTES", len((store.common_dir / "aegis" / "gitops.jsonl").read_bytes()) - 1)
    with pytest.raises(gitops.GitOpsError) as error:
        store.reconcile("lane-1", lambda row: gitops.Observation(NEW))
    code = "journal_io" if failure == "io" else "invalid_result"
    assert error.value.code == code
    assert str(error.value) == gitops.REFUSALS[code]
    assert "storage" in error.value.next_action["command"]
    assert "private-input" not in str(error.value.next_action)
    monkeypatch.setattr(gitops, "os", original_os)
    monkeypatch.setattr(gitops, "MAX_ROW_BYTES", row_cap)
    assert len(store.open_intents()) == 1
    assert store.reconcile("lane-1", lambda row: gitops.Observation(NEW))[0]["status"] == "done"
    assert intent(store).created is False


def test_reservation_includes_largest_state_keys_numbers_and_boolean(make_store, monkeypatch):
    store = make_store()
    stamp = "2026-11-12T10:00:00Z"
    monkeypatch.setattr(gitops, "utc_stamp", lambda: stamp)
    state = {"head": "\U00010000" * 1024, "branch": "\U00010000" * 1024,
             "lease_id": "\U00010000" * 1024, "base": "\U00010000" * 1021,
             "state": "\U00010000", "path": "\U00010000", "owner": "\U00010000",
             "number": 2**63-1, "run_id": 2**63-1, "pr_number": 2**63-1,
             "generation": 2**63-1, "exists": False}
    row = dict(v=1, kind="intent", op="push", lane="lane-1", request_id="request-1",
               expected_old=OLD, expected_new=NEW, actor="session-1", created_at=stamp, ts=stamp)
    terminal = dict(row, kind="result", status="unknown", observed=state)
    sizes = [len(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii"))
             for value in (row, terminal)]
    # Two newlines plus a quarantine marker must fit, down to the last byte.
    monkeypatch.setattr(gitops, "MAX_JOURNAL_BYTES", sum(sizes) + 3)
    refusal("journal_capacity", lambda: intent(store))
    monkeypatch.setattr(gitops, "MAX_JOURNAL_BYTES", sum(sizes) + 4)
    assert intent(store).created is True
    assert store.record_result("request-1", "unknown", state)["observed"] == state
    assert store.open_intents() == []


@pytest.mark.parametrize("kind", ["closed", "unrelated", "separate_open", "wrong_receipt", "retry_receipt"])
def test_result_ownership_refusals_close_temporaries_and_allow_owner_retry(make_store, monkeypatch, kind):
    store = make_store()
    receipt = intent(store)
    original_os = gitops.os
    temporaries, supplied = [], None
    def opened(*args, **kwargs):
        fd = original_os.open(*args, **kwargs)
        temporaries.append(fd)
        return fd
    def duplicated(fd):
        duplicate = original_os.dup(fd)
        temporaries.append(duplicate)
        return duplicate
    if kind == "wrong_receipt":
        kwargs = {"receipt": intent(store, "other")}
    elif kind == "retry_receipt":
        kwargs = {"receipt": intent(store)}
    else:
        if kind == "closed":
            supplied = os.dup(receipt.inheritable_fds()[0])
            os.close(supplied)
        else:
            path = (store.common_dir / "aegis" / next(
                p.name for p in (store.common_dir / "aegis").iterdir() if p.name.startswith("gitops-effect-"))
                    if kind == "separate_open" else store.common_dir / "aegis" / "gitops.jsonl")
            supplied = os.open(path, os.O_RDONLY)
        kwargs = {"effect_fd": supplied}
    try:
        monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "open": opened, "dup": duplicated}))
        code = "effect_busy" if kind == "separate_open" else "invalid_result"
        refusal(code, lambda: gitops.GitOpsJournal(store.common_dir).record_result("request-1", "done", NEW, **kwargs))
        for fd in temporaries:
            with pytest.raises(OSError) as error:
                os.fstat(fd)
            assert error.value.errno == errno.EBADF
    finally:
        monkeypatch.setattr(gitops, "os", original_os)
        if supplied is not None and kind != "closed":
            os.close(supplied)
    assert gitops.GitOpsJournal(store.common_dir).record_result("request-1", "done", NEW, receipt=receipt)["status"] == "done"


def test_receipt_outlives_original_journal_without_retaining_it(make_store):
    import gc
    import weakref
    store = make_store()
    root = store.common_dir
    reference = weakref.ref(store)
    receipt = intent(store)
    del store
    gc.collect()
    assert reference() is None
    assert gitops.GitOpsJournal(root).record_result("request-1", "done", NEW, receipt=receipt)["status"] == "done"


def test_same_process_fresh_instance_can_finish_without_instance_affinity(make_store):
    store = make_store()
    intent(store)
    assert gitops.GitOpsJournal(store.common_dir).record_result("request-1", "done", NEW)["status"] == "done"


@pytest.mark.parametrize("fd", [-1, True, "3", 2**100])
def test_invalid_inherited_descriptor_values_have_fixed_refusal(make_store, fd):
    store = make_store()
    receipt = intent(store)
    refusal("invalid_result", lambda: store.record_result("request-1", "done", NEW, effect_fd=fd))
    assert store.record_result("request-1", "done", NEW, receipt=receipt)["status"] == "done"


def probe_lock(path):
    """A separate process must still find a test-owned replacement lock held."""
    script = """
import fcntl, sys
with open(sys.argv[1], 'rb') as stream:
    try:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print('busy')
    else:
        print('free')
"""
    child = subprocess.run([sys.executable, "-I", "-c", script, str(path)],
                           capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stderr
    return child.stdout.strip()


def replace_closed_number(fd, path):
    """Force real descriptor reuse, independent of pytest's allocation order."""
    opened = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    if opened != fd:
        try:
            os.dup2(opened, fd)
        finally:
            os.close(opened)
    gitops.fcntl.flock(fd, gitops.fcntl.LOCK_EX | gitops.fcntl.LOCK_NB)


def close_test_descriptor_if_open(fd):
    # Failure witnesses can leave the descriptor closed or leaked. This only
    # cleans descriptors created by this test after its assertions have run.
    try:
        os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
    else:
        os.close(fd)


@pytest.mark.parametrize("ending", ["release", "terminal", "context"])
def test_failed_owner_close_forgets_number_before_reuse(make_store, monkeypatch, ending):
    store = make_store()
    receipt = intent(store)
    effect, = receipt.inheritable_fds()
    original_os = gitops.os
    attempts = []
    def failed_close(fd):
        if fd == effect:
            attempts.append(fd)
            original_os.close(fd)
            raise OSError(errno.EIO, "token=private-close-diagnostic")
        original_os.close(fd)
    def leave_context():
        with receipt:
            pass
    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "close": failed_close}))
    if ending == "terminal":
        refusal("journal_io", lambda: store.record_result("request-1", "done", NEW, receipt=receipt))
    elif ending == "context":
        refusal("journal_io", leave_context)
    else:
        refusal("journal_io", receipt.close)
    monkeypatch.setattr(gitops, "os", original_os)
    refusal("effect_busy", receipt.inheritable_fds)
    replacement = store.common_dir / "second-effect.lock"
    replace_closed_number(effect, replacement)
    try:
        assert attempts == [effect]
        assert probe_lock(replacement) == "busy"
        receipt.close()
        receipt.release()
        leave_context()
        if ending == "terminal":
            assert store.record_result("request-1", "done", NEW)["status"] == "done"
        assert probe_lock(replacement) == "busy"
        refusal("effect_busy", receipt.inheritable_fds)
    finally:
        close_test_descriptor_if_open(effect)
    if ending != "terminal":
        assert store.reconcile("lane-1", lambda row: gitops.Observation(OLD))[0]["status"] == "not_applied"
    assert intent(store).created is False


@pytest.mark.parametrize("phase", ["original", "busy", "rejected"])
def test_failed_inherited_close_is_once_and_closes_other_owned_descriptors(make_store, monkeypatch, phase):
    store = make_store()
    receipt = intent(store)
    effect, = receipt.inheritable_fds()
    original_os = gitops.os
    supplied = effect
    if phase == "busy":
        path = next((store.common_dir / "aegis").glob("gitops-effect-*.lock"))
        supplied = os.open(path, os.O_RDONLY)
    elif phase == "rejected":
        supplied = os.open(store.common_dir / "aegis" / "gitops.jsonl", os.O_RDONLY)
    target, duplicates, attempts, opened_fds, pins = [], [], [], [], []
    replacement = store.common_dir / "replacement-effect.lock"
    def tracked_open(path, *args, **kwargs):
        fd = original_os.open(path, *args, **kwargs)
        opened_fds.append(fd)
        if phase == "original" and str(path).startswith("gitops-effect-"):
            target.append(fd)
        return fd
    def tracked_dup(fd):
        duplicate = original_os.dup(fd)
        if not opened_fds:
            pins.append(duplicate)
        else:
            duplicates.append(duplicate)
            if phase != "original":
                target.append(duplicate)
        return duplicate
    def failed_close(fd):
        if target and fd == target[0]:
            attempts.append(fd)
            original_os.close(fd)
            if len(attempts) == 1:
                replace_closed_number(fd, replacement)
                raise OSError(errno.EIO, "token=private-inherited-close")
            return
        original_os.close(fd)
    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "open": tracked_open,
                       "dup": tracked_dup, "close": failed_close}))
    try:
        refusal("journal_io", lambda: store.record_result("request-1", "done", NEW, effect_fd=supplied))
        assert attempts == target
        assert probe_lock(replacement) == "busy"
        for fd in set(opened_fds + duplicates + pins) - set(target):
            with pytest.raises(OSError) as error:
                os.fstat(fd)
            assert error.value.errno == errno.EBADF
    finally:
        monkeypatch.setattr(gitops, "os", original_os)
        for fd in set(target + duplicates + opened_fds + pins) - {effect, supplied}:
            close_test_descriptor_if_open(fd)
        if phase != "original":
            close_test_descriptor_if_open(supplied)
    assert store.record_result("request-1", "done", NEW, receipt=receipt)["status"] == "done"


@pytest.mark.parametrize("case,command", [
    ("status", "correct the result status and observation to match the durable intent; then record the result"),
    ("contradiction", "correct the result status and observation to match the durable intent; then record the result"),
    ("multiline", "correct the result status and observation to match the durable intent; then record the result"),
    ("receipt_shape", "provide the matching active receipt for this request; then record the observed result"),
    ("receipt_request", "provide the matching active receipt for this request; then record the observed result"),
    ("receipt_retry", "provide the matching active receipt for this request; then record the observed result"),
    ("descriptor_shape", "provide the inherited effect-lock descriptor for this request; then record the observed result"),
    ("descriptor_range", "provide the inherited effect-lock descriptor for this request; then record the observed result"),
    ("descriptor_closed", "provide the inherited effect-lock descriptor for this request; then record the observed result"),
    ("descriptor_copy_error", "provide the inherited effect-lock descriptor for this request; then record the observed result"),
    ("descriptor_identity", "provide the inherited effect-lock descriptor for this request; then record the observed result"),
    ("both_owners", "supply one ownership argument: a matching receipt or an inherited effect-lock descriptor; then record the observed result"),
    ("capacity", "inspect the pending intent and restore journal capacity or storage; reconcile by observation before any further action"),
])
def test_invalid_result_next_action_matches_every_refusal_cause(make_store, monkeypatch, case, command):
    store = make_store()
    receipt = intent(store)
    status, observed, kwargs = "done", NEW, {}
    row_cap = gitops.MAX_ROW_BYTES
    original_os = gitops.os
    with ExitStack() as resources:
        if case == "status":
            status = "invalid-status"
        elif case == "contradiction":
            observed = OLD
        elif case == "multiline":
            observed = {"state": "two\nlines"}
        elif case == "receipt_shape":
            kwargs["receipt"] = object()
        elif case == "receipt_request":
            kwargs["receipt"] = resources.enter_context(intent(store, "other"))
        elif case == "receipt_retry":
            kwargs["receipt"] = intent(store)
        elif case == "descriptor_shape":
            kwargs["effect_fd"] = True
        elif case == "descriptor_range":
            kwargs["effect_fd"] = 2**100
        elif case == "descriptor_closed":
            closed = os.dup(receipt.inheritable_fds()[0])
            os.close(closed)
            kwargs["effect_fd"] = closed
        elif case == "descriptor_identity":
            stream = resources.enter_context((store.common_dir / "aegis" / "gitops.jsonl").open("rb"))
            kwargs["effect_fd"] = stream.fileno()
        elif case == "descriptor_copy_error":
            calls = []
            def failed_second_dup(fd):
                calls.append(fd)
                if len(calls) == 2:
                    raise OSError(errno.EBADF, "token=private-copy-error")
                return original_os.dup(fd)
            monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "dup": failed_second_dup}))
            kwargs["effect_fd"] = receipt.inheritable_fds()[0]
        elif case == "both_owners":
            kwargs = {"receipt": receipt, "effect_fd": receipt.inheritable_fds()[0]}
        elif case == "capacity":
            monkeypatch.setattr(gitops, "MAX_ROW_BYTES", len((store.common_dir / "aegis" / "gitops.jsonl").read_bytes()) - 1)
        with pytest.raises(gitops.GitOpsError) as error:
            store.record_result("request-1", status, observed, **kwargs)
        assert error.value.code == "invalid_result"
        assert str(error.value) == gitops.REFUSALS["invalid_result"]
        assert error.value.next_action == {"actor": "owner", "command": command}
    monkeypatch.setattr(gitops, "os", original_os)
    monkeypatch.setattr(gitops, "MAX_ROW_BYTES", row_cap)
    result = store.record_result("request-1", "done", NEW, receipt=receipt)
    assert store.record_result("request-1", "done", NEW) == result


def test_concurrent_result_refusals_keep_their_own_next_actions(make_store):
    store = make_store()
    receipt = intent(store)
    cases = [
        ({"observed": OLD}, "correct the result status and observation to match the durable intent; then record the result"),
        ({"receipt": object()}, "provide the matching active receipt for this request; then record the observed result"),
        ({"effect_fd": True}, "provide the inherited effect-lock descriptor for this request; then record the observed result"),
    ]
    def reject(case):
        changes, command = case
        fields = {"observed": NEW, **changes}
        with pytest.raises(gitops.GitOpsError) as error:
            gitops.GitOpsJournal(store.common_dir).record_result("request-1", "done", **fields)
        assert error.value.code == "invalid_result"
        return error.value.next_action, command
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(reject, cases * 3))
    for action, command in results:
        assert action == {"actor": "owner", "command": command}
    assert store.read().rows == [receipt.row]
    assert store.record_result("request-1", "done", NEW, receipt=receipt)["status"] == "done"


@pytest.mark.parametrize("reuse", ["closed", "unrelated"])
def test_argon_effect_descriptor_is_pinned_before_any_journal_open(make_store, monkeypatch, reuse):
    store = make_store()
    receipt = intent(store, "req-1", actor="owner")
    supplied, = receipt.inheritable_fds()
    receipt.close()
    with pytest.raises(OSError) as error:
        os.fstat(supplied)
    assert error.value.errno == errno.EBADF
    replacement = store.common_dir / "unrelated.lock"
    if reuse == "unrelated":
        replace_closed_number(supplied, replacement)
    original_os, events = gitops.os, []
    def opened(*args, **kwargs):
        fd = original_os.open(*args, **kwargs)
        events.append(("open", fd))
        return fd
    def duplicated(fd):
        events.append(("dup", fd))
        return original_os.dup(fd)
    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "open": opened, "dup": duplicated}))
    try:
        for _ in range(2):
            events.clear()
            refusal("invalid_result", lambda: store.record_result("req-1", "done", NEW, effect_fd=supplied))
            assert events[0] == ("dup", supplied)
            if reuse == "closed":
                assert events == [("dup", supplied)]
            else:
                assert probe_lock(replacement) == "busy"
            assert store.read().rows == [receipt.row]
    finally:
        monkeypatch.setattr(gitops, "os", original_os)
        if reuse == "unrelated":
            close_test_descriptor_if_open(supplied)
    assert store.reconcile("lane-1", lambda row: gitops.Observation(OLD))[0]["status"] == "not_applied"


@pytest.mark.parametrize("fault,code", [(errno.EBADF, "invalid_result"),
                                       (errno.EINVAL, "invalid_result"),
                                       (errno.EMFILE, "journal_io")])
def test_entry_descriptor_pin_errors_refuse_before_open_and_allow_valid_retry(make_store, monkeypatch, fault, code):
    store = make_store()
    receipt = intent(store)
    original_os, opens = gitops.os, []
    def failed_dup(fd):
        raise OSError(fault, "token=private-pin-error")
    def opened(*args, **kwargs):
        fd = original_os.open(*args, **kwargs)
        opens.append(fd)
        return fd
    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "open": opened, "dup": failed_dup}))
    try:
        with pytest.raises(gitops.GitOpsError) as error:
            store.record_result("request-1", "done", NEW, effect_fd=receipt.inheritable_fds()[0])
        assert error.value.code == code
        command = ("provide the inherited effect-lock descriptor for this request; then record the observed result"
                   if code == "invalid_result" else
                   "inspect the pending intent and restore journal capacity or storage; reconcile by observation before any further action")
        assert error.value.next_action == {"actor": "owner", "command": command}
        assert opens == []
    finally:
        monkeypatch.setattr(gitops, "os", original_os)
    assert store.record_result("request-1", "done", NEW, receipt=receipt)["status"] == "done"


def test_entry_pin_is_closed_if_transaction_entry_refuses(make_store, monkeypatch):
    store = make_store()
    receipt = intent(store)
    original_os, original_storage = gitops.os, gitops.storage
    pins = []
    def duplicated(fd):
        pinned = original_os.dup(fd)
        pins.append(pinned)
        return pinned
    @contextmanager
    def timeout(*args, **kwargs):
        raise gitops.LockTimeoutError("token=private-pin-timeout")
        yield
    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "dup": duplicated}))
    monkeypatch.setattr(gitops, "storage", SimpleNamespace(file_lock=timeout,
                       confined_descriptor_supported=original_storage.confined_descriptor_supported))
    refusal("journal_busy", lambda: store.record_result("request-1", "done", NEW, effect_fd=receipt.inheritable_fds()[0]))
    assert len(pins) == 1
    with pytest.raises(OSError) as error:
        os.fstat(pins[0])
    assert error.value.errno == errno.EBADF
    monkeypatch.setattr(gitops, "os", original_os)
    monkeypatch.setattr(gitops, "storage", original_storage)
    assert store.record_result("request-1", "done", NEW, receipt=receipt)["status"] == "done"


def test_failed_entry_pin_close_never_retries_a_reused_number(make_store, monkeypatch):
    store = make_store()
    receipt = intent(store)
    original_os, pins, attempts = gitops.os, [], []
    replacement = store.common_dir / "reused-pin.lock"
    def duplicated(fd):
        pinned = original_os.dup(fd)
        pins.append(pinned)
        return pinned
    def failed_close(fd):
        if pins and fd == pins[0]:
            attempts.append(fd)
            original_os.close(fd)
            replace_closed_number(fd, replacement)
            raise OSError(errno.EIO, "token=private-pin-close")
        original_os.close(fd)
    monkeypatch.setattr(gitops, "os", SimpleNamespace(**{**vars(os), "dup": duplicated, "close": failed_close}))
    try:
        refusal("journal_io", lambda: store.record_result("request-1", "done", NEW, effect_fd=receipt.inheritable_fds()[0]))
    finally:
        monkeypatch.setattr(gitops, "os", original_os)
    try:
        assert attempts == pins[:1]
        receipt.close()
        receipt.release()
        assert store.record_result("request-1", "done", NEW)["status"] == "done"
        assert probe_lock(replacement) == "busy"
        refusal("effect_busy", receipt.inheritable_fds)
        for fd in pins[1:]:
            with pytest.raises(OSError) as error:
                os.fstat(fd)
            assert error.value.errno == errno.EBADF
    finally:
        close_test_descriptor_if_open(pins[0])


@pytest.mark.parametrize("descriptor", ["none", "live_unrelated", "closed"])
def test_terminal_replay_requires_liveness_but_keeps_identity_exemption(make_store, descriptor):
    store = make_store()
    receipt = intent(store)
    closed, = receipt.inheritable_fds()
    result = store.record_result("request-1", "done", NEW, receipt=receipt)
    with ExitStack() as resources:
        kwargs = {}
        if descriptor == "closed":
            kwargs["effect_fd"] = closed
            refusal("invalid_result", lambda: store.record_result("request-1", "done", NEW, **kwargs))
        else:
            if descriptor == "live_unrelated":
                stream = resources.enter_context((store.common_dir / "aegis" / "gitops.jsonl").open("rb"))
                kwargs["effect_fd"] = stream.fileno()
            assert store.record_result("request-1", "done", NEW, **kwargs) == result
    assert store.read().rows == [receipt.row, result]
