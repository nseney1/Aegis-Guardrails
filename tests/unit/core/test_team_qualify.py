"""Qualification public contracts; repositories and history belong to each test."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
from threading import Barrier, Event, get_ident
from types import SimpleNamespace

import pytest

from aegis_core import gitsafe, gitsafe_run, gitops_fds, team_git as tg, team_qualify as qual, team_gitops
from tests.unit.core.test_team_git import (IDENTITY, commit, git, make_store,
                                           shared_bytes)
from tests.unit.core.test_gitsafe import _native_program, strict_program_guard

LEGS = ("linux-3.12", "linux-3.9")


def test_unsupported_platform_refuses_before_store_or_journal_access(monkeypatch):
    monkeypatch.setattr(qual, "descriptor_supported", lambda: False)
    item = qual.QualificationResult("a" * 40, LEGS[0], "b" * 40, "run-1", True)
    with pytest.raises(qual.QualificationError) as caught:
        qual.record_pass(None, item, expected=None, identity=IDENTITY, journal=None,
                         lane="lane-1", request_id="request-1", actor="custodian-1")
    assert caught.value.code == "unsupported_platform"
    assert str(caught.value) == qual.REFUSALS["unsupported_platform"]


def test_holder_only_unsupported_platform_refuses_before_store_or_journal_access(monkeypatch):
    monkeypatch.setattr(qual, "team_git", SimpleNamespace(**{**vars(tg), "descriptor_support": lambda: True}))
    monkeypatch.setattr(qual, "team_gitops", SimpleNamespace(**{**vars(team_gitops), "descriptor_supported": lambda: True}))
    monkeypatch.setattr(gitops_fds, "descriptor_supported", lambda: False)
    item = qual.QualificationResult("a" * 40, LEGS[0], "b" * 40, "run-1", True)
    with pytest.raises(qual.QualificationError) as caught:
        qual.record_pass(None, item, expected=None, identity=IDENTITY, journal=None,
                         lane="lane-1", request_id="request-1", actor="custodian-1")
    assert caught.value.code == "unsupported_platform"
    assert str(caught.value) == qual.REFUSALS["unsupported_platform"]
    assert not qual.descriptor_supported()


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    commit(path, "x", b"base\n")
    return path


@pytest.fixture
def rig(repo):
    context = make_store(repo)
    if not team_gitops.descriptor_supported() or not gitops_fds.descriptor_supported():
        pytest.skip("journal and effect custody require supported descriptor operations")
    with context as store:
        head = git(repo, "rev-parse", "HEAD").decode().strip()
        tree = git(repo, "rev-parse", "HEAD^{tree}").decode().strip()
        yield SimpleNamespace(repo=repo, store=store, head=head, tree=tree,
                              journal=team_gitops.GitOpsJournal(repo / ".git"))


def result(rig, leg=LEGS[0], run="run-1"):
    return qual.QualificationResult(rig.tree, leg, rig.head, run, True)


def write(rig, item=None, expected=None, request="request-1"):
    return qual.record_pass(rig.store, item or result(rig), expected=expected,
                            identity=IDENTITY, journal=rig.journal, lane="lane-1",
                            request_id=request, actor="custodian-1")


def tip(rig, leg=LEGS[0]):
    return git(rig.repo, "rev-parse", qual.qualification_ref(rig.tree, leg)).decode().strip()


def test_holder_only_unsupported_platform_leaves_store_and_journal_unchanged(rig, monkeypatch):
    before = shared_bytes(rig.repo)
    private = {p.relative_to(rig.store.scratch): p.read_bytes()
               for p in rig.store.scratch.rglob("*") if p.is_file()}
    monkeypatch.setattr(gitops_fds, "descriptor_supported", lambda: False)
    with pytest.raises(qual.QualificationError) as caught:
        write(rig)
    assert caught.value.code == "unsupported_platform"
    assert str(caught.value) == qual.REFUSALS["unsupported_platform"]
    assert shared_bytes(rig.repo) == before
    assert {p.relative_to(rig.store.scratch): p.read_bytes()
            for p in rig.store.scratch.rglob("*") if p.is_file()} == private


def test_first_record_retry_and_newer_record_fast_forward(rig):
    assert not qual.qualified(rig.store, rig.tree, LEGS)
    assert write(rig) == "updated"
    first = tip(rig)
    assert write(rig) == "already"
    assert tip(rig) == first
    assert write(rig, result(rig, run="run-2"), expected=first, request="request-2") == "updated"
    newer = tip(rig)
    assert git(rig.repo, "rev-parse", newer + "^").decode().strip() == first
    assert qual.qualified(rig.store, rig.tree, [LEGS[0]])
    assert not qual.qualified(rig.store, rig.tree, LEGS)
    assert write(rig, result(rig, LEGS[1]), request="request-3") == "updated"
    assert qual.qualified(rig.store, rig.tree, LEGS)
    rows = rig.journal.read().rows
    assert [row["kind"] for row in rows] == ["intent", "result"] * 3
    assert all(row["status"] == "done" for row in rows if row["kind"] == "result")


@pytest.mark.parametrize("retry", [False, True])
@pytest.mark.parametrize("other_state", ["stuck", "active", "tombstone", "malformed", "storage", "killed"])
def test_publication_reconciles_only_its_request(rig, monkeypatch, retry, other_state):
    if retry:
        assert write(rig) == "updated"
        # A lost final append leaves the authoritative checkpoint for replay.
        path = rig.repo / ".git" / "aegis" / "gitops.jsonl"
        path.write_bytes(path.read_bytes().splitlines(keepends=True)[0])
    directory = rig.repo / ".git" / "aegis"
    before = set(directory.glob("gitops-effect-*.lock"))
    other = None
    if other_state == "killed":
        if os.name != "posix":
            pytest.skip("custodian SIGKILL requires POSIX signals")
        script = '''
import os, signal, sys
sys.path.insert(0, sys.argv[1])
from aegis_core.team_gitops import GitOpsJournal
receipt = GitOpsJournal(sys.argv[2]).record_intent(op="ref_update", lane="lane-1",
    request_id="unselected", expected_old=None, expected_new=sys.argv[3], actor="custodian-1")
os.kill(os.getpid(), signal.SIGKILL)
'''
        child = subprocess.run([sys.executable, "-I", "-c", script,
                                str(Path(__file__).resolve().parents[3]), str(rig.repo / ".git"), rig.head],
                               capture_output=True, timeout=20)
        assert child.returncode == -signal.SIGKILL, child.stderr
    else:
        other = rig.journal.record_intent(op="ref_update", lane="lane-1", request_id="unselected",
                                         expected_old=None, expected_new=rig.head, actor="custodian-1")
    checkpoint = (set(directory.glob("gitops-effect-*.lock")) - before).pop()
    if other is not None and other_state != "active":
        other.close()
    if other_state == "stuck":
        checkpoint.write_bytes(b"!\n")
    if other_state == "tombstone":
        terminal = rig.journal.record_result("unselected", "done", rig.head)
        path = directory / "gitops.jsonl"
        rows = [row for row in rig.journal.read().rows if row["request_id"] != "unselected"]
        rows.append(dict(terminal, kind="tombstone"))
        path.write_bytes(b"".join(team_gitops.rows.encoded(row) + b"\n" for row in rows))
    if other_state == "malformed":
        with (directory / "gitops.jsonl").open("ab") as stream:
            stream.write(b'{"malformed":\n')
    saved = checkpoint.read_bytes()
    probes, original = [], team_gitops._try_effect

    def probe(directory_fd, request_id, **kwargs):
        if kwargs.get("existing_only"):
            probes.append(request_id)
        if request_id == "unselected" and other_state == "storage":
            raise team_gitops.GitOpsError("journal_io")
        return original(directory_fd, request_id, **kwargs)

    monkeypatch.setattr(team_gitops, "_try_effect", probe)
    try:
        assert write(rig) == ("already" if retry else "updated")
        assert probes == ["request-1"]
        assert checkpoint.read_bytes() == saved
        assert write(rig) == "already"
        assert probes == ["request-1"]
    finally:
        if other is not None:
            other.close()
    assert [row["request_id"] for row in rig.journal.open_intents()] == (
        [] if other_state == "tombstone" else ["unselected"])


@pytest.mark.parametrize("retry", [False, True])
def test_publication_uses_reconcile_result_without_reading_history(rig, monkeypatch, retry):
    if retry:
        assert write(rig) == "updated"
        path = rig.repo / ".git" / "aegis" / "gitops.jsonl"
        path.write_bytes(path.read_bytes().splitlines(keepends=True)[0])

    def unavailable(self):
        raise OSError("history must not be reread after a durable reconcile result")

    monkeypatch.setattr(team_gitops.GitOpsJournal, "read", unavailable)
    assert write(rig) == ("already" if retry else "updated")


@pytest.mark.parametrize("retry", [False, True])
@pytest.mark.parametrize("compacted", [False, True])
def test_publication_reads_history_when_request_finishes_before_effect_claim(rig, monkeypatch, retry, compacted):
    if retry:
        assert write(rig) == "updated"
        path = rig.repo / ".git" / "aegis" / "gitops.jsonl"
        path.write_bytes(path.read_bytes().splitlines(keepends=True)[0])
    original_effect, original_read = team_gitops._try_effect, team_gitops.GitOpsJournal.read
    completed, reads = [], []

    def complete(directory, request_id, **kwargs):
        if kwargs.get("existing_only") and not completed:
            completed.append(request_id)
            row = next(row for row in original_read(rig.journal).rows
                       if row["kind"] == "intent" and row["request_id"] == request_id)
            terminal = rig.journal.record_result(request_id, "done", row["expected_new"])
            if compacted:
                path = rig.repo / ".git" / "aegis" / "gitops.jsonl"
                path.write_bytes(team_gitops.rows.encoded(dict(terminal, kind="tombstone")) + b"\n")
        return original_effect(directory, request_id, **kwargs)

    def read(self):
        reads.append(None)
        return original_read(self)

    monkeypatch.setattr(team_gitops, "_try_effect", complete)
    monkeypatch.setattr(team_gitops.GitOpsJournal, "read", read)
    assert write(rig) == ("already" if retry else "updated")
    assert completed == ["request-1"]
    assert len(reads) == 1


def test_publication_exports_the_active_receipt_to_the_sole_writer(rig, monkeypatch):
    if not gitops_fds.descriptor_supported():
        pytest.skip("effect custody requires Linux child subreaper support")
    original, seen = tg.cas_fast_forward, []
    def observe(*args, **kwargs):
        descriptors = kwargs.get("effect_fds")
        assert descriptors is not None, "qualification CAS lost its receipt custody"
        assert len(descriptors) == 1 and not os.get_inheritable(descriptors[0])
        seen.append(descriptors)
        return original(*args, **kwargs)
    monkeypatch.setattr(qual, "team_git", SimpleNamespace(**{**vars(tg), "cas_fast_forward": observe}))
    assert write(rig) == "updated"
    assert write(rig) == "already"
    assert len(seen) == 1


@pytest.mark.parametrize("fast_forward", [False, True], ids=["first", "fast-forward"])
@pytest.mark.parametrize("stage", ["alive", "killed-before", "killed-after", "failed"])
def test_publication_effect_custody_survives_until_git_exits(rig, tmp_path, fast_forward, stage):
    if not gitops_fds.descriptor_supported():
        pytest.skip("effect custody requires Linux child subreaper support")
    strict_program_guard(native_fixture=True)
    expected = None
    if fast_forward:
        assert write(rig, request="previous") == "updated"
        expected = tip(rig)
    program = shutil.which("git")
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    ready, release, finished = (tmp_path / name for name in ("ready", "release", "finished"))
    # The test owns the native shim and pauses only the actual mutation command.
    # Other Git calls exec the real binary, so discovery and validation are real.
    source = "#!/usr/bin/env python3\n" + f'''
import os, subprocess, sys, time
from pathlib import Path
program, ready, release, finished = {str(program)!r}, Path({str(ready)!r}), Path({str(release)!r}), Path({str(finished)!r})
if "update-ref" not in sys.argv[1:]:
    os.execv(program, [program, *sys.argv[1:]])
after, failed = {stage == "killed-after"!r}, {stage == "failed"!r}
code = subprocess.call([program, *sys.argv[1:]]) if after else None
ready.write_text("ready")
deadline = time.monotonic() + 30
while not release.exists():
    if time.monotonic() >= deadline:
        raise SystemExit(124)
    time.sleep(0.01)
if not after:
    code = 1 if failed else subprocess.call([program, *sys.argv[1:]])
finished.write_text(str(code))
raise SystemExit(code)
'''
    _native_program(shim_dir / "git", source)
    scratch = tmp_path / "owner-scratch"
    scratch.mkdir(mode=0o700)
    (scratch / "objects").mkdir(mode=0o700)
    script = '''
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from aegis_core import team_git as tg, team_gitops, team_qualify as qual
from tests.unit.core.test_team_git import IDENTITY
repo, scratch = Path(sys.argv[2]), Path(sys.argv[3])
item = qual.QualificationResult(sys.argv[4], "linux-3.12", sys.argv[5], "run-custody", True)
with tg.GitStore(repo, scratch) as store:
    try:
        status = qual.record_pass(store, item, expected=json.loads(sys.argv[6]), identity=IDENTITY,
            journal=team_gitops.GitOpsJournal(repo / ".git"), lane="lane-1",
            request_id="custody", actor="custodian-1")
    except qual.QualificationError as exc:
        status = exc.code
    print(status, flush=True)
'''
    environment = {**os.environ, "PATH": str(shim_dir) + os.pathsep + os.environ["PATH"]}
    def observe_ref():
        return git(rig.repo, "for-each-ref", "--format=%(objectname)",
                   qual.qualification_ref(rig.tree, LEGS[0])).decode().strip() or None
    args = [sys.executable, "-I", "-c", script, str(Path(__file__).resolve().parents[3]),
            str(rig.repo), str(scratch), rig.tree, rig.head, json.dumps(expected)]
    with (tmp_path / "owner.log").open("w+b") as output:
        owner = subprocess.Popen(args, env=environment, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 30
            while not ready.exists() and owner.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            assert ready.exists(), "custodian did not reach the test-owned Git mutation shim"
            if stage.startswith("killed"):
                owner.kill()
                assert owner.wait(timeout=10) == -signal.SIGKILL
            item = result(rig, run="run-custody")
            # Repeat the real public retry, including read-only reconciliation.
            for _ in range(2):
                with pytest.raises(qual.QualificationError) as caught:
                    write(rig, item, expected=expected, request="custody")
                assert caught.value.code == "request_closed"
                assert [row["request_id"] for row in rig.journal.open_intents()] == ["custody"]
            pending = rig.journal.open_intents()[0]
            observed = observe_ref()
            assert observed == (pending["expected_new"] if stage == "killed-after" else expected)
        finally:
            release.write_text("release")
            try:
                owner.wait(timeout=30)
            finally:
                if owner.poll() is None:
                    owner.kill()
                    owner.wait(timeout=10)
            # Also drain the orphaned holder when an assertion fails, before
            # pytest can remove the test-owned repository and release marker.
            deadline = time.monotonic() + 15
            while ready.exists() and rig.journal.open_intents() and time.monotonic() < deadline:
                rig.journal.reconcile("lane-1", lambda row: team_gitops.Observation(observe_ref()))
                time.sleep(0.01)
        assert finished.read_text() == ("1" if stage == "failed" else "0")
        assert not rig.journal.open_intents()
        terminal = [row for row in rig.journal.read().rows
                    if row["kind"] == "result" and row["request_id"] == "custody"]
        assert [row["status"] for row in terminal] == (["not_applied"] if stage == "failed" else ["done"])
        if stage == "failed":
            with pytest.raises(qual.QualificationError) as caught:
                write(rig, item, expected=expected, request="custody")
            assert caught.value.code == "request_closed"
            assert write(rig, item, expected=expected, request="recovery") == "updated"
        else:
            assert write(rig, item, expected=expected, request="custody") == "already"
        if not stage.startswith("killed"):
            output.seek(0)
            assert output.read().decode().strip() == ("ref_update_failed" if stage == "failed" else "updated")


def test_snapshot_can_qualify_before_the_tested_bytes_commit_exists(rig):
    (rig.repo / "x").write_bytes(b"uncommitted tested bytes\n")
    tree = tg.snapshot_tree(rig.store)
    assert tree != rig.tree
    item = replace(result(rig), tree=tree)
    assert write(rig, item) == "updated"
    assert qual.qualified(rig.store, tree, [LEGS[0]])
    record = git(rig.repo, "rev-parse", qual.qualification_ref(tree, LEGS[0])).decode().strip()
    assert git(rig.repo, "rev-parse", record + "^").decode().strip() == rig.head
    assert git(rig.repo, "rev-parse", record + "^{tree}").decode().strip() == tree
    assert git(rig.repo, "rev-parse", "HEAD").decode().strip() == rig.head


@pytest.mark.parametrize("fast_forward", [False, True], ids=["first", "fast-forward"])
@pytest.mark.parametrize("schedule,applied", [("before", False), ("before", True),
    ("after", True), ("identical", True)], ids=["not-applied", "applied", "after-mutation", "identical-commit"])
def test_indeterminate_cas_waits_for_stopped_holder_before_reconciliation(rig, tmp_path, monkeypatch, fast_forward, schedule, applied):
    strict_program_guard(native_fixture=True)
    expected = None
    if fast_forward:
        assert write(rig, request="previous") == "updated"
        expected = tip(rig)
    ready, release, finished = (tmp_path / name for name in ("ready", "release", "finished"))
    program = shutil.which("git")
    shim = tmp_path / "git-shim"
    _native_program(shim, "#!/usr/bin/env python3\n" + f'''
import os, subprocess, sys, time
from pathlib import Path
program = {str(program)!r}
if "update-ref" not in sys.argv[1:]:
    os.execv(program, [program, *sys.argv[1:]])
ready, release, finished = Path({str(ready)!r}), Path({str(release)!r}), Path({str(finished)!r})
code = subprocess.call([program, *sys.argv[1:]]) if {schedule == "after"!r} else None
ready.write_text("ready")
deadline = time.monotonic() + 90
while not release.exists():
    if time.monotonic() >= deadline:
        raise SystemExit(124)
    time.sleep(0.01)
if code is None:
    code = subprocess.call([program, *sys.argv[1:]]) if {applied!r} else 1
finished.write_text(str(code))
raise SystemExit(code)
''')
    original_capture, original_holder = gitsafe_run.capture, gitops_fds.holder_recipe
    writer_thread = get_ident()
    stopped = []

    def identical_writer():
        with make_store(rig.repo) as store:
            other = SimpleNamespace(**{**vars(rig), "store": store})
            return write(other, expected=expected, request="identical-2")

    def bounded_capture(argv, **kwargs):
        if "update-ref" in argv and get_ident() == writer_thread:
            kwargs["timeout"] = 2
        return original_capture(argv, **kwargs)

    @contextmanager
    def stopped_holder(argv, options, timeout, **kwargs):
        with original_holder(argv, options, timeout, **kwargs) as (launch, settings, bind):
            if "update-ref" not in argv or get_ident() != writer_thread:
                yield launch, settings, bind
                return
            def pause(raw):
                process = bind(raw)
                stopped.append(process)
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                assert ready.exists() and process.started
                os.kill(raw.pid, signal.SIGSTOP)
                if schedule == "identical":
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        assert pool.submit(identical_writer).result(timeout=20) == "updated"
                    intent = rig.journal.open_intents()[0]
                    assert tip(rig) == intent["expected_new"]
                return process
            yield launch, settings, pause

    # Patch only owned module seams. The real holder and capture cleanup run,
    # including both five-second waits which cannot reap a stopped holder.
    monkeypatch.setattr(gitsafe, "custody_program", lambda cwd, **kwargs:
                        str(shim) if get_ident() == writer_thread else str(program))
    monkeypatch.setattr(gitsafe, "git_executable", lambda **kwargs:
                        str(shim) if get_ident() == writer_thread else str(program))
    monkeypatch.setattr(gitsafe_run, "capture", bounded_capture)
    monkeypatch.setattr(gitops_fds, "holder_recipe", stopped_holder)
    try:
        with pytest.raises(qual.QualificationError) as caught:
            write(rig, expected=expected)
        assert caught.value.code == "ref_update_unknown"
        assert str(caught.value) == qual.REFUSALS["ref_update_unknown"]
        assert len(stopped) == 1 and stopped[0].raw.poll() is None
        assert [row["request_id"] for row in rig.journal.open_intents()] == ["request-1"]
        assert [row["request_id"] for row in rig.journal.in_flight()] == ["request-1"]
        for _ in range(2):
            assert rig.journal.reconcile("lane-1", lambda row: pytest.fail("live holder was observed")) == []
            with pytest.raises(qual.QualificationError) as retry:
                write(rig, expected=expected)
            assert retry.value.code == "request_closed"
        release.write_text("release")
        deadline = time.monotonic() + 5
        while not finished.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert finished.exists()
        assert rig.journal.reconcile("lane-1", lambda row: pytest.fail("unreaped holder was observed")) == []
    finally:
        release.write_text("release")
        for process in stopped:
            if process.raw.poll() is None:
                deadline = time.monotonic() + 5
                while not finished.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                process.raw.send_signal(signal.SIGCONT)
                process.raw.wait(timeout=10)
    if applied:
        assert write(rig, expected=expected) == "already"
    else:
        with pytest.raises(qual.QualificationError) as retry:
            write(rig, expected=expected)
        assert retry.value.code == "request_closed"
    assert len(stopped) == 1
    assert not rig.journal.open_intents()
    assert not rig.journal.in_flight()
    rows = [row for row in rig.journal.read().rows if row["request_id"] == "request-1"]
    assert [row["kind"] for row in rows] == ["intent", "result"]
    assert rows[-1]["status"] == ("done" if applied else "not_applied")
    assert rows[-1]["observed"] == (rows[0]["expected_new"] if applied else expected)


@pytest.mark.parametrize("field,value", [("passed", False), ("passed", 1), ("tree", "b" * 40),
    ("leg", "../linux"), ("leg", "x" * 129), ("run_id", "token=SECRET"),
    ("run_id", "x" * 129), ("source_commit", "bad\nsecret"), ("tree", "x" * 100000)],
    ids=["failed", "not-bool", "foreign-tree", "traversal-leg", "long-leg", "secret-run",
         "long-run", "bad-commit", "oversized-tree"])
def test_invalid_result_has_fixed_refusal_and_zero_shared_effects(rig, field, value):
    before = shared_bytes(rig.repo)
    with pytest.raises(qual.QualificationError) as caught:
        write(rig, replace(result(rig), **{field: value}))
    assert caught.value.code == "invalid_result"
    assert str(caught.value) == qual.REFUSALS["invalid_result"]
    assert shared_bytes(rig.repo) == before
    assert write(rig) == "updated"


@pytest.mark.parametrize("code", ["cas_mismatch", "not_fast_forward", "git_failed"])
def test_writer_refusals_do_not_move_refs_and_retry_does_not_repeat(rig, monkeypatch, code):
    attempts = []
    def refuse(*args, **kwargs):
        attempts.append(args)
        raise tg.GitRefusal(code)
    monkeypatch.setattr(qual, "team_git", SimpleNamespace(**{**vars(tg), "cas_fast_forward": refuse}))
    with pytest.raises(qual.QualificationError) as caught:
        write(rig)
    assert caught.value.code == code
    assert not qual.qualified(rig.store, rig.tree, [LEGS[0]])
    monkeypatch.setattr(qual, "team_git", tg)
    with pytest.raises(qual.QualificationError) as caught:
        write(rig)
    assert caught.value.code == "request_closed"
    assert len(attempts) == 1
    assert write(rig, request="new-attempt") == "updated"


@pytest.mark.parametrize("code", ["ref_update_unknown", "git_cleanup_failed", "git_timeout", "git_output_limit"])
def test_indeterminate_writer_refusals_leave_pending_without_ref_observation(rig, monkeypatch, code):
    attempts, observed = [], []
    original = qual.gitsafe
    def refuse(*args, **kwargs):
        attempts.append(args)
        raise tg.GitRefusal(code)
    def read_ref(*args, **kwargs):
        observed.append(args)
        return original.read_ref(*args, **kwargs)
    monkeypatch.setattr(qual, "team_git", SimpleNamespace(**{**vars(tg), "cas_fast_forward": refuse}))
    monkeypatch.setattr(qual, "gitsafe", SimpleNamespace(**{**vars(original), "read_ref": read_ref}))
    with pytest.raises(qual.QualificationError) as caught:
        write(rig)
    assert caught.value.code == "ref_update_unknown"
    assert str(caught.value) == qual.REFUSALS["ref_update_unknown"]
    assert observed == []
    assert [row["kind"] for row in rig.journal.read().rows] == ["intent"]
    monkeypatch.setattr(qual, "team_git", tg)
    with pytest.raises(qual.QualificationError) as retry:
        write(rig)
    assert retry.value.code == "request_closed"
    assert len(attempts) == len(observed) == 1
    assert not rig.journal.open_intents()
    assert rig.journal.read().rows[-1]["status"] == "not_applied"


@pytest.mark.parametrize("code", ["git_failed", "ref_unreadable", "cas_mismatch"])
def test_other_cas_refusals_cannot_terminalize_a_retained_effect_receipt(rig, monkeypatch, code):
    retained, attempts = [], []
    def refuse(*args, **kwargs):
        attempts.append(args)
        # A real duplicate of the exported receipt has the same kernel lifetime
        # as a surviving holder. The stopped-holder matrix covers real processes.
        retained.append(os.dup(kwargs["effect_fds"][0]))
        raise tg.GitRefusal(code)
    monkeypatch.setattr(qual, "team_git", SimpleNamespace(**{**vars(tg), "cas_fast_forward": refuse}))
    try:
        with pytest.raises(qual.QualificationError) as caught:
            write(rig)
        assert caught.value.code == "ref_update_unknown"
        assert str(caught.value) == qual.REFUSALS["ref_update_unknown"]
        assert [row["kind"] for row in rig.journal.read().rows] == ["intent"]
        assert [row["request_id"] for row in rig.journal.in_flight()] == ["request-1"]
        assert rig.journal.reconcile("lane-1", lambda row: pytest.fail("live receipt was observed")) == []
    finally:
        for descriptor in retained:
            os.close(descriptor)
    monkeypatch.setattr(qual, "team_git", tg)
    with pytest.raises(qual.QualificationError) as retry:
        write(rig)
    assert retry.value.code == "request_closed"
    assert len(attempts) == 1
    assert rig.journal.read().rows[-1]["status"] == "not_applied"
    assert not rig.journal.open_intents()


@pytest.mark.parametrize("status", ["updated", "already"])
@pytest.mark.parametrize("published", [False, True], ids=["old-ref", "new-ref"])
def test_normal_cas_return_requires_a_fresh_receipt_lock(rig, monkeypatch, status, published):
    retained, attempts = [], []
    original = tg.cas_fast_forward
    def returned(*args, **kwargs):
        attempts.append(args)
        if published:
            assert original(*args, **kwargs) == "updated"
        retained.append(os.dup(kwargs["effect_fds"][0]))
        return status
    monkeypatch.setattr(qual, "team_git", SimpleNamespace(**{**vars(tg), "cas_fast_forward": returned}))
    try:
        with pytest.raises(qual.QualificationError) as caught:
            write(rig)
        assert caught.value.code == "ref_update_unknown"
        assert str(caught.value) == qual.REFUSALS["ref_update_unknown"]
        assert [row["kind"] for row in rig.journal.read().rows] == ["intent"]
        assert [row["request_id"] for row in rig.journal.in_flight()] == ["request-1"]
        assert rig.journal.reconcile("lane-1", lambda row: pytest.fail("live receipt was observed")) == []
        with pytest.raises(qual.QualificationError) as retry:
            write(rig)
        assert retry.value.code == "request_closed"
        assert len(attempts) == 1
    finally:
        for descriptor in retained:
            os.close(descriptor)
    if published:
        assert write(rig) == "already"
    else:
        with pytest.raises(qual.QualificationError) as retry:
            write(rig)
        assert retry.value.code == "request_closed"
    assert len(attempts) == 1
    assert not rig.journal.open_intents()
    assert not rig.journal.in_flight()
    assert rig.journal.read().rows[-1]["status"] == ("done" if published else "not_applied")


def test_concurrent_writers_preserve_one_winner(rig, monkeypatch):
    original, barrier = tg.cas_fast_forward, Barrier(2)
    def race(*args, **kwargs):
        barrier.wait(timeout=20)
        return original(*args, **kwargs)
    monkeypatch.setattr(qual, "team_git", SimpleNamespace(**{**vars(tg), "cas_fast_forward": race}))
    def worker(number):
        with make_store(rig.repo) as store:
            other = SimpleNamespace(**{**vars(rig), "store": store})
            try:
                return write(other, result(rig, run="run-" + str(number)), request="race-" + str(number))
            except qual.QualificationError as exc:
                return exc.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(worker, number) for number in (1, 2)]
        assert sorted(f.result(timeout=40) for f in futures) == ["cas_mismatch", "updated"]
    assert qual.qualified(rig.store, rig.tree, [LEGS[0]])


@pytest.mark.parametrize("damage", ["foreign-tree", "wrong-leg", "malformed", "oversized",
                                   "non-commit", "duplicate-key", "failed", "extra-key"])
def test_reader_fails_closed_for_every_invalid_record_and_recovers(rig, damage):
    write(rig)
    oid = tip(rig)
    raw = git(rig.repo, "show", "-s", "--format=%B", oid)
    body = json.loads(raw)
    if damage == "foreign-tree":
        body["tree"] = "b" * 40
    elif damage == "wrong-leg":
        body["leg"] = LEGS[1]
    elif damage == "failed":
        body["passed"] = False
    elif damage == "extra-key":
        body["unexpected"] = "value"
    raw = json.dumps(body).encode()
    if damage == "malformed":
        raw = b"{"
    elif damage == "oversized":
        raw = b"x" * (qual.MAX_RECORD_BYTES + 1)
    elif damage == "duplicate-key":
        raw = raw[:-1] + b', "passed": true}'
    if damage == "non-commit":
        bad = git(rig.repo, "hash-object", "-w", "--stdin", data=raw).decode().strip()
    else:
        bad = git(rig.repo, "commit-tree", rig.tree, "-p", rig.head, data=raw).decode().strip()
    ref = qual.qualification_ref(rig.tree, LEGS[0])
    git(rig.repo, "update-ref", ref, bad)
    assert not qual.qualified(rig.store, rig.tree, [LEGS[0]])
    git(rig.repo, "update-ref", ref, oid)
    assert qual.qualified(rig.store, rig.tree, [LEGS[0]])


@pytest.mark.parametrize("legs", [[], [LEGS[0], LEGS[0]], ["../bad"], "linux-3.12", ["x"] * 100000],
                         ids=["empty", "duplicate", "invalid", "string", "oversized"])
def test_invalid_reader_selection_is_not_qualified(rig, legs):
    assert not qual.qualified(rig.store, rig.tree, legs)


def test_qualified_validates_each_full_source_once_per_call(rig, monkeypatch):
    legs = ["leg-" + str(number) for number in range(qual.MAX_LEGS)]
    for leg in legs:
        body = dict(v=1, tree=rig.tree, leg=leg, source_commit=rig.head, run_id="shared", passed=True)
        oid = git(rig.repo, "commit-tree", rig.tree, "-p", rig.head,
                  data=json.dumps(body).encode()).decode().strip()
        git(rig.repo, "update-ref", qual.qualification_ref(rig.tree, leg), oid)
    original, reads = tg.GitStore.object, []
    def counted(self, oid, kind, **kwargs):
        reads.append((oid, kind))
        return original(self, oid, kind, **kwargs)
    monkeypatch.setattr(tg.GitStore, "object", counted)
    for _ in range(2):
        reads.clear()
        assert qual.qualified(rig.store, rig.tree, legs)
        assert len(reads) == 34
        assert reads.count((rig.head, "commit")) == 1

    with ThreadPoolExecutor(max_workers=2) as pool:
        reads.clear()
        futures = [pool.submit(qual.qualified, rig.store, rig.tree, legs) for _ in range(2)]
        assert all(future.result(timeout=30) for future in futures)
        assert len(reads) == 2 * 34
        assert reads.count((rig.head, "commit")) == 2

    # Sharing a tree does not make different source commits interchangeable.
    other_source = git(rig.repo, "commit-tree", rig.tree, "-p", rig.head,
                       data=b"other source\n").decode().strip()
    body = dict(v=1, tree=rig.tree, leg=legs[-1], source_commit=other_source, run_id="shared", passed=True)
    oid = git(rig.repo, "commit-tree", rig.tree, "-p", rig.head,
              data=json.dumps(body).encode()).decode().strip()
    git(rig.repo, "update-ref", qual.qualification_ref(rig.tree, legs[-1]), oid)
    reads.clear()
    assert qual.qualified(rig.store, rig.tree, legs)
    assert len(reads) == 35
    assert reads.count((rig.head, "commit")) == reads.count((other_source, "commit")) == 1

    # The cache is local to one read: a later failure cannot reuse old validation.
    def unavailable(self, oid, kind, **kwargs):
        if oid == rig.head:
            raise tg.GitRefusal("invalid_object")
        return original(self, oid, kind, **kwargs)
    monkeypatch.setattr(tg.GitStore, "object", unavailable)
    assert not qual.qualified(rig.store, rig.tree, legs)
    monkeypatch.setattr(tg.GitStore, "object", original)
    assert qual.qualified(rig.store, rig.tree, legs)


@pytest.mark.parametrize("damage", ["foreign-tree", "wrong-leg", "malformed", "oversized",
                                   "non-commit", "duplicate-key", "failed", "extra-key", "bad-source"])
def test_source_cache_never_bypasses_later_record_checks(rig, damage):
    records = []
    for leg in LEGS:
        body = dict(v=1, tree=rig.tree, leg=leg, source_commit=rig.head, run_id="shared", passed=True)
        if leg == LEGS[1]:
            if damage == "foreign-tree":
                body["tree"] = "b" * 40
            elif damage == "wrong-leg":
                body["leg"] = LEGS[0]
            elif damage == "failed":
                body["passed"] = False
            elif damage == "extra-key":
                body["extra"] = "value"
            elif damage == "bad-source":
                body["source_commit"] = git(rig.repo, "hash-object", "-w", "--stdin", data=b"blob").decode().strip()
        raw = json.dumps(body).encode()
        if leg == LEGS[1]:
            if damage == "malformed":
                raw = b"{"
            elif damage == "oversized":
                raw = b"x" * (qual.MAX_RECORD_BYTES + 1)
            elif damage == "duplicate-key":
                raw = raw[:-1] + b', "passed": true}'
        oid = (git(rig.repo, "hash-object", "-w", "--stdin", data=raw) if leg == LEGS[1] and damage == "non-commit"
               else git(rig.repo, "commit-tree", rig.tree, "-p", rig.head, data=raw)).decode().strip()
        ref = qual.qualification_ref(rig.tree, leg)
        git(rig.repo, "update-ref", ref, oid)
        records.append((ref, oid))
    assert qual.qualified(rig.store, rig.tree, [LEGS[0]])
    assert not qual.qualified(rig.store, rig.tree, LEGS)
    body = dict(v=1, tree=rig.tree, leg=LEGS[1], source_commit=rig.head, run_id="shared", passed=True)
    repaired = git(rig.repo, "commit-tree", rig.tree, "-p", rig.head, data=json.dumps(body).encode()).decode().strip()
    git(rig.repo, "update-ref", records[-1][0], repaired)
    assert qual.qualified(rig.store, rig.tree, LEGS)


@pytest.mark.parametrize("message,changed,accepted", [
    ("chore: approve governance state\n\nAegis-Approve: " + "a" * 64 + "\n", False, True),
    ("chore: approve governance state\n\nAegis-Approve: " + "a" * 64 + "\nOther: change\n", False, False),
    ("chore: approve governance state\n\nAegis-Approve: " + "a" * 64 + "\n", True, False),
    ("chore: approve governance state\n\nAegis-Approve: forged\n continued\n", False, False),
    ("chore: approve governance state\n\nAegis-Approve: " + "a" * 64 + "\nAegis-Approve: " + "b" * 64, False, False),
    ("ordinary empty commit\n", False, False),
])
def test_approval_equivalence_only_for_empty_authority_only_commit(rig, message, changed, accepted):
    write(rig)
    tree = rig.tree
    if changed:
        head = commit(rig.repo, "changed", b"other bytes")
        tree = git(rig.repo, "rev-parse", head + "^{tree}").decode().strip()
    approval = git(rig.repo, "commit-tree", tree, "-p", rig.head, data=message.encode()).decode().strip()
    assert qual.approval_equivalent(rig.store, rig.head, approval, [LEGS[0]]) is accepted


def test_read_git_failure_is_closed_and_retry_recovers(rig, monkeypatch):
    write(rig)
    original = qual.gitsafe
    def fail(*args, **kwargs):
        raise OSError("token=SECRET")
    monkeypatch.setattr(qual, "gitsafe", SimpleNamespace(**{**vars(original), "read_ref": fail}))
    assert not qual.qualified(rig.store, rig.tree, [LEGS[0]])
    monkeypatch.setattr(qual, "gitsafe", original)
    assert qual.qualified(rig.store, rig.tree, [LEGS[0]])


def test_closed_or_missing_store_refuses_without_a_raw_exception(rig):
    assert not qual.qualified(None, rig.tree, [LEGS[0]])
    assert not qual.approval_equivalent(None, rig.head, rig.head, [LEGS[0]])
    with pytest.raises(qual.QualificationError) as caught:
        qual.record_pass(None, result(rig), expected=None, identity=IDENTITY,
                         journal=rig.journal, lane="lane-1", request_id="request-1", actor="custodian-1")
    assert caught.value.code == "invalid_record"


def test_lost_cas_ack_is_observed_and_never_repeated(rig, monkeypatch):
    original, attempts = tg.cas_fast_forward, []
    def lost(*args, **kwargs):
        attempts.append(args)
        original(*args, **kwargs)
        raise tg.GitRefusal("ref_update_unknown")
    monkeypatch.setattr(qual, "team_git", SimpleNamespace(**{**vars(tg), "cas_fast_forward": lost}))
    with pytest.raises(qual.QualificationError) as caught:
        write(rig)
    assert caught.value.code == "ref_update_unknown"
    assert [row["kind"] for row in rig.journal.read().rows] == ["intent"]
    assert write(rig) == "already"
    assert len(attempts) == 1
    assert not rig.journal.open_intents()


@pytest.mark.parametrize("stage", ["intent", "result"])
def test_journal_failure_never_repeats_effect_and_recovers_by_observation(rig, monkeypatch, stage):
    original, attempts = tg.cas_fast_forward, []
    def track(*args, **kwargs):
        attempts.append(args)
        return original(*args, **kwargs)
    class FailingJournal(team_gitops.GitOpsJournal):
        def record_intent(self, **fields):
            if self.failure == "intent":
                raise team_gitops.GitOpsError("journal_io")
            return super().record_intent(**fields)

        def record_result(self, *args, **kwargs):
            if self.failure == "result":
                raise team_gitops.GitOpsError("journal_io")
            return super().record_result(*args, **kwargs)

        def reconcile(self, *args, **kwargs):
            if self.failure == "result":
                raise team_gitops.GitOpsError("journal_io")
            return super().reconcile(*args, **kwargs)

    journal = FailingJournal(rig.repo / ".git")
    journal.failure = stage
    other = SimpleNamespace(**{**vars(rig), "journal": journal})
    monkeypatch.setattr(qual, "team_git", SimpleNamespace(**{**vars(tg), "cas_fast_forward": track}))
    monkeypatch.setattr(qual, "team_gitops", SimpleNamespace(**{**vars(team_gitops), "GitOpsJournal": FailingJournal}))
    with pytest.raises(qual.QualificationError) as caught:
        write(other)
    assert caught.value.code == "journal_failed"
    assert len(attempts) == (1 if stage == "result" else 0)
    journal.failure = None
    assert write(other) == ("already" if stage == "result" else "updated")
    assert len(attempts) == 1
    assert not rig.journal.open_intents()


def test_concurrent_retry_cannot_close_the_active_writers_intent(rig, monkeypatch):
    original, entered, release = tg.cas_fast_forward, Event(), Event()
    def paused(*args, **kwargs):
        entered.set()
        assert release.wait(timeout=20)
        return original(*args, **kwargs)
    monkeypatch.setattr(qual, "team_git", SimpleNamespace(**{**vars(tg), "cas_fast_forward": paused}))
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(write, rig)
        try:
            assert entered.wait(timeout=20)
            with make_store(rig.repo) as store:
                other = SimpleNamespace(**{**vars(rig), "store": store})
                with pytest.raises(qual.QualificationError) as caught:
                    write(other)
                assert caught.value.code == "request_closed"
            pending = rig.journal.open_intents()
        finally:
            release.set()
        assert first.result(timeout=30) == "updated"
    assert [row["request_id"] for row in pending] == ["request-1"]
    assert not rig.journal.open_intents()


@pytest.mark.parametrize("operation", ["qualified", "publication", "publication-failure",
                                       "retry", "approval"])
def test_checkout_local_git_never_executes_for_qualification_callers(rig, monkeypatch, operation):
    strict_program_guard(native_fixture=True)
    if operation in ("qualified", "retry", "approval"):
        assert write(rig) == "updated"
    if operation == "retry":
        with rig.journal.record_intent(op="ref_update", lane="lane-1", request_id="retry-1",
                                       expected_old=None, expected_new=tip(rig), actor="custodian-1"):
            pass
    if operation == "approval":
        message = "chore: approve governance state\n\nAegis-Approve: " + "a" * 64 + "\n"
        approval = git(rig.repo, "commit-tree", rig.tree, "-p", rig.head,
                       data=message.encode()).decode().strip()
    if operation == "publication-failure":
        def refuse(*args, **kwargs):
            raise tg.GitRefusal("git_failed")
        monkeypatch.setattr(qual, "team_git", SimpleNamespace(**{**vars(tg), "cas_fast_forward": refuse}))

    planted = rig.repo / "bin"
    planted.mkdir()
    marker = rig.repo / "planted-git-ran"
    _native_program(planted / "git", "#!/usr/bin/env python3\nfrom pathlib import Path\n"
                    + "Path(" + repr(str(marker)) + ").write_text('executed')\nraise SystemExit(1)\n")
    assert not rig.store.scratch.is_relative_to(rig.repo)

    expected = {"qualified": True, "approval": True, "retry": "already",
                "publication": "updated", "publication-failure": "git_failed"}[operation]
    previous_path = os.environ["PATH"]
    os.environ["PATH"] = str(planted) + os.pathsep + previous_path
    try:
        if operation == "qualified":
            observed = qual.qualified(rig.store, rig.tree, [LEGS[0]])
        elif operation == "approval":
            observed = qual.approval_equivalent(rig.store, rig.head, approval, [LEGS[0]])
        elif operation == "retry":
            observed = write(rig, request="retry-1")
        else:
            observed = write(rig)
    except qual.QualificationError as exc:
        observed = exc.code
    finally:
        os.environ["PATH"] = previous_path

    assert not marker.exists(), "checkout-local Git executed with custodian access"
    assert observed == expected
