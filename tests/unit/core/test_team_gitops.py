"""Git/forge journal public API: durable reservation, results and observation only."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, ExitStack
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
from threading import Barrier, Event

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

    def track_effect(directory, request_id):
        fd = original_effect(directory, request_id)
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
        if self is store and write and len(acquired) == 2 and failure == "reread":
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

    def acquire_together(directory, request_id):
        fd = original_effect(directory, request_id)
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
    # Initial snapshot, at most one pre-observe re-read, final append recheck.
    assert all(count <= 3 for count in transactions.values()), transactions
    if grow:
        assert set(transactions.values()) == {3}
    else:
        assert all(count == 2 for count in transactions.values()), transactions


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
    assert "reconcile" in error.value.next_action["command"]
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
