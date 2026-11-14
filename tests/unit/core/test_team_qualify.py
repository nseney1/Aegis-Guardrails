"""Qualification public contracts; repositories and history belong to each test."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from threading import Barrier, Event
from types import SimpleNamespace

import pytest

from aegis_core import team_git as tg, team_qualify as qual, team_gitops
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
    if not team_gitops.descriptor_supported():
        pytest.skip("journal requires descriptor-relative no-follow operations")
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
    def refuse(*args):
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


def test_concurrent_writers_preserve_one_winner(rig, monkeypatch):
    original, barrier = tg.cas_fast_forward, Barrier(2)
    def race(*args):
        barrier.wait(timeout=20)
        return original(*args)
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
    def lost(*args):
        attempts.append(args)
        original(*args)
        raise tg.GitRefusal("ref_update_unknown")
    monkeypatch.setattr(qual, "team_git", SimpleNamespace(**{**vars(tg), "cas_fast_forward": lost}))
    assert write(rig) == "already"
    assert write(rig) == "already"
    assert len(attempts) == 1
    assert not rig.journal.open_intents()


@pytest.mark.parametrize("stage", ["intent", "result"])
def test_journal_failure_never_repeats_effect_and_recovers_by_observation(rig, monkeypatch, stage):
    original, attempts = tg.cas_fast_forward, []
    def track(*args):
        attempts.append(args)
        return original(*args)
    class FailingJournal(team_gitops.GitOpsJournal):
        def record_intent(self, **fields):
            if self.failure == "intent":
                raise team_gitops.GitOpsError("journal_io")
            return super().record_intent(**fields)

        def record_result(self, *args, **kwargs):
            if self.failure == "result":
                raise team_gitops.GitOpsError("journal_io")
            return super().record_result(*args, **kwargs)

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
    def paused(*args):
        entered.set()
        assert release.wait(timeout=20)
        return original(*args)
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
        def refuse(*args):
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
