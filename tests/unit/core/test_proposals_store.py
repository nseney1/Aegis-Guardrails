"""Public proposal-store contracts: refusal, revision custody and private ancestry."""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
import errno
import stat
import threading
import subprocess
import sys
from random import Random
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis_core.proposals import Proposal, ProposalError, ProposalStore
from aegis_core.proposals import store as store_module
from aegis_core.proposals import model as model_module
from aegis_core.insights import add_insight, capture_suggestion, review_insights, write_proposal
from aegis_core.insights import review as review_module
from aegis_core.insights.keys import insights_path
from aegis_core.storage import confined_descriptor_supported, file_lock
from aegis_core.redaction import redact_insight_text
from conftest import symlink_or_skip
from tests import helpers_proposal_workers


def make_store(tmp_path):
    if not confined_descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    root = tmp_path / "repo"
    root.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    return ProposalStore(root, home=home)


def candidate(pid="mine-example", **kwargs):
    fields = dict(id=pid, source="mine", kind="platform", candidate_key="repo:platform:example",
                  evidence_ids=("git:repo:" + "a" * 40,), target_paths=("src/**",))
    fields.update(kwargs)
    return Proposal(**fields)


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*")
            if p.is_file() and not p.is_symlink()}


def refusal(code):
    return pytest.raises(ProposalError, match="^proposal refused: " + code + "$")


@pytest.mark.parametrize("caller", ["list", "read"])
@pytest.mark.parametrize("shape", ["chain", "diamond", "cycle", "missing", "malformed",
                                  "lineage", "evidence", "insight", "over-bound"])
def test_transaction_ancestry_snapshot(tmp_path, monkeypatch, caller, shape):
    store = make_store(tmp_path)
    store.write(candidate("node-000"))
    directory = store.root / ".aegis/proposals"
    count = 128 if shape == "chain" else 129 if shape == "over-bound" else 4
    proposals = [candidate(f"node-{i:03d}", parent_proposals=(f"node-{i + 1:03d}",)
                           if i + 1 < count else ()) for i in range(count)]
    if shape == "diamond":
        proposals[0] = replace(proposals[0], parent_proposals=("node-001", "node-002"))
        proposals[1] = replace(proposals[1], parent_proposals=("node-003",))
    elif shape in ("cycle", "missing"):
        proposals[-1] = replace(proposals[-1], parent_proposals=(
            "node-000" if shape == "cycle" else "node-missing",))
    elif shape in ("lineage", "evidence", "insight"):
        field, value = {"lineage": ("source_lineage", ("mine", "lint")),
                        "evidence": ("evidence_ids", ("extra:evidence",)),
                        "insight": ("insight_ids", ("ins-extra",))}[shape]
        if shape == "insight":
            proposals = [replace(p, source_lineage=("mine", "insight"), insight_ids=("ins-base",))
                         for p in proposals]
        proposals[-1] = replace(proposals[-1], **{field: value})
    for p in proposals:
        (directory / (p.id + ".md")).write_bytes(p.to_bytes())
    if shape == "malformed":
        (directory / (proposals[-1].id + ".md")).write_bytes(b"not a proposal")
    reads, parses = [], []
    original_read, original_parse = store_module._read, store_module.parse_proposal

    def reading(directory, name, limit, durable=False):
        reads.append(name[:-3])
        return original_read(directory, name, limit, durable=durable)

    def parsing(raw, pid):
        parses.append(pid)
        return original_parse(raw, pid)

    monkeypatch.setattr(store_module, "_read", reading)
    monkeypatch.setattr(store_module, "parse_proposal", parsing)
    expected = None if shape in ("chain", "diamond") else (
        "invalid" if shape == "malformed" and caller == "list" else "ancestry")
    for _ in range(2):  # A new transaction must read fresh bytes after either result.
        reads.clear()
        parses.clear()
        if expected:
            with refusal(expected):
                store.list() if caller == "list" else store.read("node-000")
        elif caller == "list":
            assert [s.proposal for s in store.list()] == proposals
        else:
            assert store.read("node-000").proposal == proposals[0]
        if caller == "list":
            assert reads == parses == [p.id for p in proposals]
    # A completed transaction's snapshot must never hide a subsequent edit.
    (directory / "node-000.md").write_bytes(b"not a proposal")
    with refusal("invalid"):
        store.list() if caller == "list" else store.read("node-000")


@pytest.mark.parametrize("case", ["history-256", "byte-limit", "row-limit", "no-newline",
                                 "retry", "malformed", "empty", "absent"])
def test_private_decision_history_snapshot(tmp_path, monkeypatch, case):
    store = make_store(tmp_path)
    p = candidate("ins-snapshot", source="insight", source_lineage=("insight",),
                  insight_ids=("ins-snapshot",))
    store.write(p)
    first = store.decide([p.id], decision="propose", operation_id="op-seed")
    path, = store.home.rglob("*.jsonl")
    history = path.read_bytes()
    if case == "history-256":
        history = b"".join((json.dumps(dict(first, operation_id=f"op-{i}")) + "\n").encode()
                           for i in range(256))
    elif case == "byte-limit":
        remaining = store_module.MAX_LOG_BYTES - len(history)
        padding = b" " * (store_module.MAX_ROW_BYTES - 1) + b"\n"
        history += padding * (remaining // len(padding))
        tail = remaining % len(padding)
        if tail:
            history += b" " * (tail - 1) + b"\n"
    elif case == "row-limit":
        history = b"".join((json.dumps(dict(first, operation_id=f"op-{i}")) + "\n").encode()
                           for i in range(store_module.MAX_ROWS))
    elif case == "no-newline":
        history = history.rstrip(b"\n")
    elif case == "malformed":
        history = b"{broken\n"
    elif case in ("empty", "absent"):
        history = b""
    path.write_bytes(history)
    if case == "absent":
        path.unlink()
    reads, parses = [], []
    original_read, original_rows = store_module._read, store_module._log_rows

    def reading(directory, name, limit, durable=False):
        if name == path.name:
            reads.append(durable)
        return original_read(directory, name, limit, durable=durable)

    def parsing(raw):
        parses.append(raw)
        return original_rows(raw)

    monkeypatch.setattr(store_module, "_read", reading)
    monkeypatch.setattr(store_module, "_log_rows", parsing)
    expected = {"byte-limit": "too_large", "row-limit": "too_large",
                "no-newline": "decision", "malformed": "decision"}.get(case)
    operation = "op-seed" if case == "retry" else "op-new"
    if expected:
        with refusal(expected):
            store.decide([p.id], decision="propose", operation_id=operation)
        assert path.read_bytes() == history
    else:
        row = store.decide([p.id], decision="propose", operation_id=operation)
        assert row == dict(first, operation_id=operation, ts=row["ts"])
        if case == "retry":
            assert row == first
        added = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
        assert path.read_bytes() == (history if case == "retry" else history + added)
    assert reads == ([False] if case == "malformed" else
                     [False, False, True] if case == "retry" else [False, False])
    assert parses == [history] * (1 if case == "malformed" else 2)


def test_list_snapshot_releases_lock_before_next_transaction(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    saved = store.write(candidate())
    started, release = threading.Event(), threading.Event()
    original = store_module._read

    def reading(directory, name, limit, durable=False):
        if not started.is_set():
            started.set()
            assert release.wait(timeout=5)
        return original(directory, name, limit, durable=durable)

    monkeypatch.setattr(store_module, "_read", reading)
    waiting = ProposalStore(store.root, home=store.home, timeout=0.01)
    changed = replace(saved.proposal, do="Updated after listing.")
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(store.list)
        try:
            assert started.wait(timeout=5)
            with refusal("timeout"):
                waiting.write(changed, expected_digest=saved.digest)
        finally:
            release.set()
        assert future.result(timeout=5) == [saved]
    updated = waiting.write(changed, expected_digest=saved.digest)
    assert store.list() == [updated]


@pytest.mark.parametrize("change", ["append", "quota", "malformed"])
def test_private_snapshot_uses_authoritative_locked_history(tmp_path, monkeypatch, change):
    store = make_store(tmp_path)
    p = candidate("ins-snapshot", source="insight", source_lineage=("insight",),
                  insight_ids=("ins-snapshot",))
    store.write(p)
    seed = store.decide([p.id], decision="propose", operation_id="op-seed")
    path, = store.home.rglob("*.jsonl")
    original = path.read_bytes()
    interleaved = original + (json.dumps(dict(seed, operation_id="op-other")) + "\n").encode()
    if change == "malformed":
        interleaved = b"{broken\n"
    if change == "quota":
        monkeypatch.setattr(store_module, "MAX_ROWS", 2)
    shared_reads = []

    @contextmanager
    def entering(lock_path, *args, **kwargs):
        with file_lock(lock_path, *args, **kwargs):
            if lock_path.suffix == ".lock":
                shared_reads.append(True)
                if len(shared_reads) == 2:  # Preflight released; authoritative lock is now held.
                    path.write_bytes(interleaved)
            yield

    monkeypatch.setattr(store_module, "file_lock", entering)
    try:
        if change == "append":
            result = store.decide([p.id], decision="confirm", operation_id="op-new")
            assert result["operation_id"] == "op-new"
            assert path.read_bytes().startswith(interleaved)
            assert len(path.read_bytes().splitlines()) == 3
        else:
            with refusal("too_large" if change == "quota" else "decision"):
                store.decide([p.id], decision="confirm", operation_id="op-new")
            assert path.read_bytes() == interleaved
    finally:
        monkeypatch.setattr(store_module, "file_lock", file_lock)
    path.write_bytes(original)
    assert store.decide([p.id], decision="confirm", operation_id="op-new")["operation_id"] == "op-new"


def test_private_snapshot_retry_keeps_durable_reread_and_stale_refusal(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    p = candidate("ins-snapshot", source="insight", source_lineage=("insight",),
                  insight_ids=("ins-snapshot",))
    store.write(p)
    row = store.decide([p.id], decision="propose", operation_id="op-seed")
    path, = store.home.rglob("*.jsonl")
    before = path.read_bytes()
    original = store_module._read

    def reading(directory, name, limit, durable=False):
        raw = original(directory, name, limit, durable=durable)
        return raw + b"\n" if durable and name == path.name else raw

    monkeypatch.setattr(store_module, "_read", reading)
    try:
        with refusal("stale"):
            store.decide([p.id], decision="propose", operation_id="op-seed")
    finally:
        monkeypatch.setattr(store_module, "_read", original)
    assert path.read_bytes() == before
    assert store.decide([p.id], decision="propose", operation_id="op-seed") == row


def test_stale_collision_and_terminal_updates_leave_tree_unchanged(tmp_path):
    store = make_store(tmp_path)
    original = store.write(candidate())
    before = snapshot(tmp_path)
    with refusal("exists"):
        store.write(candidate(kind="other"))
    with refusal("stale"):
        store.write(replace(original.proposal, do="Validate paths."), expected_digest="0" * 64)
    assert snapshot(tmp_path) == before
    store.decide([original.proposal.id], decision="reject", reason="Insufficient evidence", operation_id="reject-1")
    before = snapshot(tmp_path)
    with refusal("terminal"):
        store.write(replace(original.proposal, do="Validate paths."), expected_digest=original.digest)
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("component", [".aegis", "proposals", "leaf", "decisions", "state", "lock"])
def test_symlink_components_refuse_without_touching_target(tmp_path, component):
    store = make_store(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret"
    secret.write_bytes(b"keep")
    if component in ("decisions", "leaf"):
        store.write(candidate())
    paths = {".aegis": store.root / ".aegis", "proposals": store.root / ".aegis/proposals",
             "leaf": store.root / ".aegis/proposals/mine-example.md",
             "decisions": store.root / ".aegis/proposals/decisions",
             "state": store.root / ".aegis/state", "lock": store.root / ".aegis/state/lock"}
    path = paths[component]
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    symlink_or_skip(secret if component in ("leaf", "lock") else outside, path,
                    target_is_directory=component not in ("leaf", "lock"))
    before = snapshot(outside)
    with refusal("unsafe"):
        if component == "decisions":
            store.decide(["mine-example"], decision="reject", reason="why", operation_id="reject-1")
        else:
            store.write(candidate())
    assert snapshot(outside) == before


def test_pending_update_requires_digest_and_preserves_provenance(tmp_path):
    store = make_store(tmp_path)
    saved = store.write(candidate())
    store.decide([saved.proposal.id], decision="confirm", operation_id="confirm-1")
    for changes in ({"evidence_ids": ("different",)}, {"source": "one", "source_lineage": ("one",)}, {"revision": 2},
                    {"amends": "other"}, {"parent_proposals": ("mine-missing",)}):
        with refusal("provenance"):
            store.write(replace(saved.proposal, **changes), expected_digest=saved.digest)
    updated = store.write(replace(saved.proposal, do="Validate paths.", status="proposal"),
                          expected_digest=saved.digest)
    assert store.read(saved.proposal.id) == updated
    assert store.state(saved.proposal.id) == "proposal"


def test_evidence_deduplicates_and_identical_retry_is_noop(tmp_path):
    store = make_store(tmp_path)
    p = candidate()
    p = replace(p, evidence_ids=p.evidence_ids * 2)
    saved = store.write(p)
    before = snapshot(tmp_path)
    assert saved.proposal.count == 1
    assert store.write(p) == saved
    assert snapshot(tmp_path) == before


def test_concurrent_compare_replace_has_one_winner(tmp_path):
    store = make_store(tmp_path)
    saved = store.write(candidate())

    def update(do):
        try:
            store.write(replace(saved.proposal, do=do), expected_digest=saved.digest)
            return "written"
        except ProposalError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(update, ["First guidance.", "Second guidance."]))
    assert sorted(results) == ["stale", "written"]


def test_transitive_merge_decisions_remain_private_and_retry_is_idempotent(tmp_path):
    store = make_store(tmp_path)
    insight = replace(candidate("ins-origin"), source="insight", source_lineage=("insight",),
                      insight_ids=("ins-123",), evidence_ids=("insight:ins-123",))
    store.write(insight)
    store.write(candidate())
    merged = store.merge(["ins-origin", "mine-example"], "mine-merged")
    store.decide(["ins-origin", "mine-example"], decision="merge-into-rule", reason="first private merge",
                 operation_id="merge-1")
    final = store.merge([merged.proposal.id], "mine-public-looking")
    store.decide([merged.proposal.id], decision="merge-into-rule", reason="second private merge",
                 operation_id="merge-2")
    assert final.proposal.count == 2
    row = store.decide([final.proposal.id], decision="reject", reason="private explanation",
                       operation_id="private-reject")
    before = snapshot(tmp_path)
    assert store.decide([final.proposal.id], decision="reject", reason="private explanation",
                        operation_id="private-reject") == row
    assert snapshot(tmp_path) == before
    public = b"\n".join(snapshot(store.root).values())
    assert b"private explanation" not in public
    assert b"private merge" not in public
    private = list(store.home.rglob("*.jsonl"))
    assert len(private) == 1 and b"private explanation" in private[0].read_bytes()
    assert private[0].stat().st_mode & 0o777 == 0o600
    assert len([json.loads(line) for line in private[0].read_text().splitlines()]) == 3
    assert store.state("ins-origin") == store.state("mine-example") == store.state("mine-merged") == "merged"


def test_missing_or_inconsistent_ancestry_refuses(tmp_path):
    store = make_store(tmp_path)
    with refusal("ancestry"):
        store.write(candidate(parent_proposals=("mine-missing",)))
    store.write(replace(candidate("ins-parent"), source="insight", source_lineage=("insight",),
                        insight_ids=("ins-123",)))
    with refusal("ancestry"):
        store.write(candidate(parent_proposals=("ins-parent",)))


@pytest.mark.parametrize("decision", ["invalid", "accept\nreject", "", None])
def test_invalid_decision_vocabulary_refuses_before_write(tmp_path, decision):
    store = make_store(tmp_path)
    store.write(candidate())
    before = snapshot(tmp_path)
    with refusal("decision"):
        store.decide(["mine-example"], decision=decision, operation_id="op-1")
    assert snapshot(tmp_path) == before


def test_reject_requires_reason_and_operation_collision_refuses(tmp_path):
    store = make_store(tmp_path)
    store.write(candidate())
    with refusal("reason"):
        store.decide(["mine-example"], decision="reject", operation_id="op-1")
    row = store.decide(["mine-example"], decision="propose", operation_id="op-1")
    assert row["decision"] == "propose"
    with refusal("operation"):
        store.decide(["mine-example"], decision="noise", operation_id="op-1")


@pytest.mark.parametrize("field,value", [("id", "../secret"), ("id", "mine-x\n"),
    ("revision", True), ("revision", 0), ("do", "x" * 4097),
    ("evidence_ids", ["x"] * 257), ("target_paths", ("../secret",)),
    ("candidate_key", "token=supersecret"), ("kind", "bad\nkind")])
def test_invalid_model_fields_have_stable_non_echoing_refusal(field, value):
    with pytest.raises(ProposalError) as error:
        replace(candidate(), **{field: value})
    assert str(error.value) == "proposal refused: " + error.value.code


def test_oversized_file_refused_before_parsing(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    store.write(candidate())
    (store.root / ".aegis/proposals/mine-example.md").write_bytes(b"x" * 65537)
    monkeypatch.setattr(store_module, "parse_proposal", lambda *a: pytest.fail("parsed oversized bytes"))
    with refusal("too_large"):
        store.read("mine-example")


def test_malformed_decision_refuses_mutation(tmp_path):
    store = make_store(tmp_path)
    saved = store.write(candidate())
    directory = store.root / ".aegis/proposals/decisions"
    directory.mkdir()
    (directory / "bad.json").write_text('{"decision":"accept"}')
    before = snapshot(tmp_path)
    with refusal("decision"):
        store.write(replace(saved.proposal, do="Changed."), expected_digest=saved.digest)
    assert snapshot(tmp_path) == before


def test_unsupported_platform_has_documented_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    with refusal("unsupported"):
        ProposalStore(tmp_path).write(candidate())


def test_canonicalize_redact_then_truncate_every_free_text_field():
    secret = "ghp_" + "a" * 24
    p = replace(candidate(), do="Do\x00 token=" + secret, hypothesis="Check " + secret,
                labels=("untrusted\x1b[31m " + secret,))
    assert secret not in p.to_bytes().decode()
    assert b"\x1b" not in p.to_bytes() and b"\x00" not in p.to_bytes()


def test_snooze_expiry_and_confirm_do_not_accept(tmp_path):
    store = make_store(tmp_path)
    original = store.write(candidate())
    store.decide(["mine-example"], decision="snooze", until="2000-01-01", operation_id="op-1")
    before = snapshot(tmp_path)
    assert store.state("mine-example") == "needs_draft"
    successor = store.resume("mine-example")
    assert successor.proposal.id != original.proposal.id
    assert successor.proposal.revision == original.proposal.revision + 1
    assert successor.proposal.parent_proposals == (original.proposal.id,)
    assert store.resume(original.proposal.id) == successor
    assert all(snapshot(tmp_path)[path] == raw for path, raw in before.items())
    updated = store.write(replace(successor.proposal, do="Validate paths.", status="proposal"),
                          expected_digest=successor.digest)
    store.decide([updated.proposal.id], decision="accept", operation_id="op-2")
    assert store.state(updated.proposal.id) == "accepted"
    with refusal("terminal"):
        store.write(replace(original.proposal, do="Mutate history."), expected_digest=original.digest)


def module_os(**overrides):
    base = dict(O_RDONLY=os.O_RDONLY, O_WRONLY=os.O_WRONLY, O_CREAT=os.O_CREAT, O_EXCL=os.O_EXCL,
                O_DIRECTORY=getattr(os, "O_DIRECTORY", 0), O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0),
                O_NONBLOCK=getattr(os, "O_NONBLOCK", 0), O_CLOEXEC=getattr(os, "O_CLOEXEC", 0),
                fsencode=os.fsencode, open=os.open, close=os.close, mkdir=os.mkdir, fsync=os.fsync,
                getuid=getattr(os, "getuid", None), fstat=os.fstat, read=os.read, stat=os.stat,
                fchmod=getattr(os, "fchmod", None), write=os.write, replace=os.replace, link=os.link,
                unlink=os.unlink, scandir=os.scandir)
    return SimpleNamespace(**{**base, **overrides})


@pytest.mark.parametrize("component", ["repo", ".aegis", "proposals"])
def test_concurrent_ancestor_rename_cannot_redirect_publication(tmp_path, monkeypatch, component):
    store = make_store(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_bytes(b"secret")
    before = snapshot(outside)
    swapped = []
    moved = tmp_path / "moved"

    def opening(path, flags, *args, **kwargs):
        fd = os.open(path, flags, *args, **kwargs)
        if path == component and not swapped:
            swapped.append(True)
            original = {"repo": store.root, ".aegis": store.root / ".aegis",
                        "proposals": store.root / ".aegis/proposals"}[component]
            original.rename(moved)
            symlink_or_skip(outside, original, target_is_directory=True)
        return fd

    monkeypatch.setattr(store_module, "os", module_os(open=opening))
    assert store.write(candidate()).proposal.id == "mine-example"
    assert swapped and snapshot(outside) == before
    assert list(moved.rglob("mine-example.md"))


@pytest.mark.parametrize("stage", ["open", "fchmod", "write", "file_fsync", "directory_fsync"])
def test_failure_cleanup_and_identical_retry(tmp_path, monkeypatch, stage):
    store = make_store(tmp_path)
    saved = store.write(candidate())
    before = snapshot(tmp_path)
    opened = set()

    def opening(path, flags, *args, **kwargs):
        if stage == "open" and flags & os.O_CREAT:
            raise OSError(errno.EIO, "do not echo secret")
        fd = os.open(path, flags, *args, **kwargs)
        opened.add(fd)
        return fd

    def closing(fd):
        opened.discard(fd)
        return os.close(fd)

    def failed(*args, **kwargs):
        raise OSError(errno.EIO, "do not echo secret")

    def syncing(fd):
        regular = stat.S_ISREG(os.fstat(fd).st_mode)
        if (stage == "file_fsync" and regular) or (stage == "directory_fsync" and not regular):
            failed()
        return os.fsync(fd)

    proxy = module_os(open=opening, close=closing, fsync=syncing)
    if stage == "fchmod":
        proxy.fchmod = failed
    if stage == "write":
        proxy.write = failed
    monkeypatch.setattr(store_module, "os", proxy)
    try:
        with refusal("durability" if stage.endswith("fsync") else "io"):
            store.write(replace(saved.proposal, do="New guidance."), expected_digest=saved.digest)
    finally:
        monkeypatch.setattr(store_module, "os", os)
    assert opened == set()
    assert snapshot(tmp_path) == before
    assert not list(store.root.rglob(".proposal-*"))
    assert store.write(replace(saved.proposal, do="New guidance."), expected_digest=saved.digest).proposal.do == "New guidance."


def test_post_publication_flush_failure_retries_same_decision(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    store.write(candidate())
    decisions = store.root / ".aegis/proposals/decisions"
    decisions.mkdir()
    identity = decisions.stat()

    def flush_then_fail(fd):
        os.fsync(fd)
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
            raise OSError(errno.EIO, "do not echo secret")

    monkeypatch.setattr(store_module, "os", module_os(fsync=flush_then_fail))
    try:
        with refusal("durability"):
            store.decide(["mine-example"], decision="reject", reason="Review", operation_id="op-1")
        with refusal("durability"):
            store.decide(["mine-example"], decision="reject", reason="Review", operation_id="op-1")
    finally:
        monkeypatch.setattr(store_module, "os", os)
    row = store.decide(["mine-example"], decision="reject", reason="Review", operation_id="op-1")
    assert row["decision"] == "reject"
    assert len(list((store.root / ".aegis/proposals/decisions").glob("*.json"))) == 1


def test_store_lock_timeout_and_retry(tmp_path):
    store = make_store(tmp_path)
    store.write(candidate())
    entered, release = threading.Event(), threading.Event()

    def hold():
        with file_lock(store.root / ".aegis/state/lock"):
            entered.set()
            assert release.wait(5)

    with ThreadPoolExecutor(max_workers=1) as pool:
        holding = pool.submit(hold)
        assert entered.wait(5)
        try:
            waiting = ProposalStore(store.root, home=store.home, timeout=0.01)
            with refusal("timeout"):
                waiting.read("mine-example")
        finally:
            release.set()
        holding.result(timeout=5)
    assert store.read("mine-example").proposal.id == "mine-example"


def test_malformed_stored_proposals_and_counts_are_refused(tmp_path):
    store = make_store(tmp_path)
    saved = store.write(candidate())
    path = store.root / ".aegis/proposals/mine-example.md"
    raw = path.read_bytes()
    for bad in (b"\xff", raw.replace(b"count: 1", b"count: 9"),
                raw.replace(b'id: "mine-example"', b'id: "mine-other"'),
                raw.replace(b"revision: 1", b"revision: true"),
                raw.replace(b"kind: ", b"unknown_key: ")):
        path.write_bytes(bad)
        with refusal("invalid"):
            store.read(saved.proposal.id)


def test_large_inputs_refuse_without_open_or_parse(tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "os", module_os(open=lambda *a, **k: pytest.fail("opened")))
    store = ProposalStore(tmp_path)
    for bad in ("x" * 100000, "../secret", "mine-x\n"):
        with refusal("invalid"):
            store.read(bad)
    with refusal("too_large"):
        model_module.parse_proposal(b"x" * 65537, "mine-x")


def test_public_decisions_are_immutable_and_concurrent_retries_share_one_file(tmp_path):
    store = make_store(tmp_path)
    store.write(candidate())

    def decide(_):
        return store.decide(["mine-example"], decision="reject", reason="Review", operation_id="op-1")

    with ThreadPoolExecutor(max_workers=3) as pool:
        rows = list(pool.map(decide, range(3)))
    assert rows[0] == rows[1] == rows[2]
    paths = list((store.root / ".aegis/proposals/decisions").glob("*.json"))
    assert len(paths) == 1
    assert json.loads(paths[0].read_bytes())["operation_id"] == "op-1"


def test_private_ancestor_symlink_refuses_without_public_reason(tmp_path):
    store = make_store(tmp_path)
    store.write(replace(candidate("ins-private"), source="insight", source_lineage=("insight",),
                        insight_ids=("ins-123",)))
    outside = tmp_path / "outside"
    outside.mkdir()
    symlink_or_skip(outside, store.home / ".aegis", target_is_directory=True)
    with refusal("unsafe"):
        store.decide(["ins-private"], decision="reject", reason="Private reason", operation_id="op-1")
    assert b"Private reason" not in b"".join(snapshot(store.root).values())
    assert snapshot(outside) == {}


def test_evidence_and_parent_order_have_identical_canonical_bytes():
    p = candidate(evidence_ids=("event-b", "event-a"), parent_proposals=("mine-b", "mine-a"))
    other = replace(p, evidence_ids=tuple(reversed(p.evidence_ids)),
                    parent_proposals=tuple(reversed(p.parent_proposals)))
    assert p.to_bytes() == other.to_bytes()


def test_ansi_inside_a_secret_is_removed_before_redaction():
    text = "ghp_" + "a" * 24
    obfuscated = "ghp_\x1b[31m" + "a" * 24 + "\x1b[0m"
    p = replace(candidate(), do=obfuscated, hypothesis=obfuscated, prediction=obfuscated,
                labels=(obfuscated,))
    assert text not in p.to_bytes().decode()
    assert "[31m" not in p.do


def test_expanding_unicode_is_bounded_after_canonicalization():
    with refusal("too_large"):
        replace(candidate(), do="\ufdfa" * 4096)


def test_empty_existing_private_log_can_be_published(tmp_path):
    from aegis_core.insights import insights_path
    store = make_store(tmp_path)
    store.write(replace(candidate("ins-private"), source="insight", source_lineage=("insight",),
                        insight_ids=("ins-123",)))
    path = insights_path(store.root, home=store.home)
    path.parent.mkdir(parents=True, mode=0o700)
    path.parent.parent.chmod(0o700)
    path.write_bytes(b"")
    store.decide(["ins-private"], decision="reject", reason="Private", operation_id="op-1")
    assert json.loads(path.read_bytes())["reason"] == "Private"


def test_insight_presentation_order_survives_reordered_concurrent_retries(tmp_path):
    store = make_store(tmp_path)
    ids = ("ins-bbbbbbbbbbbb", "ins-aaaaaaaaaaaa")
    p = candidate("ins-presentation", source="insight", source_lineage=("insight",),
                  insight_ids=ids, evidence_ids=tuple("insight:" + i for i in ids))
    saved = store.write(p)
    assert saved.proposal.insight_ids == ids
    before = snapshot(tmp_path)

    def retry(order):
        return store.write(replace(p, insight_ids=order))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(retry, [ids, tuple(reversed(ids))]))
    assert results == [saved, saved]
    assert snapshot(tmp_path) == before
    assert store.read(p.id).proposal.insight_ids == ids


def test_guidance_bullets_keep_each_redacted_line_and_its_limit(tmp_path):
    store = make_store(tmp_path)
    bullets = ("Ask reviewer@example.com " + "a" * 250, "Keep " + "b" * 250)
    saved = store.write(candidate(guidance=bullets))
    assert saved.proposal.guidance == tuple(model_module.clean_text(b, 200) for b in bullets)
    raw = (store.root / ".aegis/proposals/mine-example.md").read_text()
    for bullet in saved.proposal.guidance:
        assert "- " + bullet + "\n" in raw
    assert "reviewer@example.com" not in raw
    assert all(len(line) <= 200 for line in saved.proposal.guidance)
    assert store.read(saved.proposal.id) == saved


@pytest.mark.parametrize("bad", ["ins-aaaaaaaaaaaa\n", "ins-\x1b[31maaaaaaaaaaaa", "../secret",
                                  "ins-" + "a" * 10000, "ins-ＡＡＡＡＡＡＡＡＡＡＡＡ"],
                         ids=["newline", "ansi", "traversal", "oversized", "unicode"])
def test_invalid_insight_identity_refuses_before_read_without_echo(tmp_path, monkeypatch, bad):
    monkeypatch.setattr(review_module, "read_insight_rows", lambda *a, **k: pytest.fail("read invalid identity"))
    with pytest.raises(ProposalError) as caught:
        write_proposal(tmp_path, proposal_id="ins-refusal", insight_ids=[bad], home=tmp_path)
    assert caught.value.code == "insight_counted"
    assert str(caught.value) == "not a counted insight"


def test_missing_insight_echo_is_limited_to_validated_identity(tmp_path):
    identity = "ins-aaaaaaaaaaaa"
    with pytest.raises(ProposalError) as caught:
        write_proposal(tmp_path, proposal_id="ins-refusal", insight_ids=[identity], home=tmp_path)
    assert caught.value.code == "insight_counted"
    assert str(caught.value) == "not a counted insight: " + identity


def seed_legacy_insight(tmp_path, kind="release"):
    root, home = tmp_path / "repo", tmp_path / "home"
    (root / "src").mkdir(parents=True)
    (root / "src/app.py").write_text("pass\n")
    home.mkdir()
    row = add_insight(root, "Require serial validation before publishing the release.",
                      paths=["src/app.py"], kind=kind, home=home)
    return root, home, row


@pytest.mark.parametrize("kind,copies,blank", [("release", 1, False), ("release", 2, False),
                         ("resource safety", 1, False), ("release", 1, True)],
                         ids=["ordinary", "duplicate-bullets", "free-form-kind", "blank-bullets"])
def test_unsupported_insight_publication_keeps_exact_legacy_bytes_and_retry(tmp_path, monkeypatch, kind, copies, blank):
    root, home, row = seed_legacy_insight(tmp_path, kind)
    monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    expected = ("---\nid: trap-legacy\ntype: trap\nstatus: proposal\nenforcement: advisory\n"
                'kind: "' + kind + '"\ncount: 1\n'
                'hypothesis: "Prevent recurring ' + kind + ' issues in src/**."\n'
                'target_paths:\n  - "src/**"\ninsight_ids:\n  - "' + row["id"] + '"\n'
                "---\n# Proposal: trap-legacy\n\n## Guidance\n\n"
                "- 1 counted correction(s) of kind `" + kind + "`.\n" +
                "- Keep release checks bounded.\n" * copies).encode()
    bullets = ["Keep release checks bounded."] * copies
    if blank:
        bullets = ["", "  \t"] + bullets
    path = write_proposal(root, proposal_id="trap-legacy", insight_ids=[row["id"]],
                          summary_bullets=bullets, home=home)
    assert path.read_bytes() == expected
    assert write_proposal(root, proposal_id="trap-legacy", insight_ids=[row["id"]],
                          summary_bullets=bullets, home=home) == path
    assert path.read_bytes() == expected

    def retry(_):
        return write_proposal(root, proposal_id="trap-legacy", insight_ids=[row["id"]],
                              summary_bullets=bullets, home=home)

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(retry, range(2))) == [path, path]
    assert path.read_bytes() == expected


def test_maximum_legacy_summary_count_keeps_every_bullet(tmp_path, monkeypatch):
    root, home, row = seed_legacy_insight(tmp_path)
    monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    bullets = [f"Keep release check {number} bounded." for number in range(64)]
    path = write_proposal(root, proposal_id="trap-legacy", insight_ids=[row["id"]],
                          summary_bullets=bullets, home=home)
    text = path.read_text()
    assert all("- " + bullet + "\n" in text for bullet in bullets)


def test_unsupported_insight_io_failure_is_fixed_and_retry_succeeds(tmp_path, monkeypatch):
    root, home, row = seed_legacy_insight(tmp_path)
    monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    target = root / ".aegis/proposals/trap-legacy.md"
    target.mkdir(parents=True)
    with refusal("io"):
        write_proposal(root, proposal_id="trap-legacy", insight_ids=[row["id"]], home=home)
    target.rmdir()
    assert write_proposal(root, proposal_id="trap-legacy", insight_ids=[row["id"]], home=home) == target


@pytest.mark.parametrize("operation", ["write", "read", "list", "state", "merge", "decide", "resume"])
def test_new_store_surface_refuses_when_probe_is_unsupported(tmp_path, monkeypatch, operation):
    monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    store = ProposalStore(tmp_path)
    with refusal("unsupported"):
        if operation == "write":
            store.write(candidate())
        elif operation == "read":
            store.read("mine-example")
        elif operation == "list":
            store.list()
        elif operation == "state":
            store.state("mine-example")
        elif operation == "merge":
            store.merge(["mine-example"], "mine-merged")
        elif operation == "resume":
            store.resume("mine-example")
        else:
            store.decide(["mine-example"], decision="confirm", operation_id="op-1")


@pytest.mark.parametrize("field", ["id", "parent_proposals", "insight_ids", "amends"])
def test_secret_shaped_model_identifiers_are_refused_without_echo(field):
    secret = "op-ghp_" + "a" * 24
    value = (secret,) if field in ("parent_proposals", "insight_ids") else secret
    with refusal("invalid") as caught:
        replace(candidate(), **{field: value})
    assert secret not in str(caught.value)


@pytest.mark.parametrize("field", ["operation_id", "proposal_ids", "rule_id", "destination_id"])
def test_secret_shaped_store_identifiers_never_reach_files(tmp_path, field):
    store = make_store(tmp_path)
    store.write(candidate())
    before = snapshot(tmp_path)
    secret = "op-ghp_" + "a" * 24
    with refusal("invalid"):
        if field == "destination_id":
            store.merge(["mine-example"], secret)
        else:
            kwargs = {"decision": "propose", "operation_id": "op-1"}
            ids = [secret] if field == "proposal_ids" else ["mine-example"]
            if field != "proposal_ids":
                kwargs[field] = secret
            store.decide(ids, **kwargs)
    assert snapshot(tmp_path) == before


def test_expired_snooze_resume_is_private_concurrent_and_nonexpiring_refuses(tmp_path):
    store = make_store(tmp_path)
    p = candidate("ins-snoozed", source="insight", source_lineage=("insight",),
                  insight_ids=("ins-aaaaaaaaaaaa",))
    store.write(p)
    store.decide([p.id], decision="snooze", until="9999-01-01", operation_id="op-1")
    before = snapshot(tmp_path)
    with refusal("terminal"):
        store.resume(p.id)
    assert snapshot(tmp_path) == before
    log, = store.home.rglob("*.jsonl")
    row = json.loads(log.read_bytes())
    row["until"] = "2000-01-01"
    log.write_text(json.dumps(row) + "\n")
    historical = log.read_bytes()
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: store.resume(p.id), range(3)))
    assert results[0] == results[1] == results[2]
    child = results[0].proposal
    assert child.private and child.insight_ids == p.insight_ids
    store.decide([child.id], decision="reject", reason="Keep private", operation_id="op-2")
    assert log.read_bytes().startswith(historical)
    assert b"Keep private" not in b"".join(snapshot(store.root).values())


def test_proposal_capacity_refuses_before_publishing_and_retry_remains_readable(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    monkeypatch.setattr(store_module, "MAX_ROWS", 2)
    store.write(candidate("mine-one"))
    store.write(candidate("mine-two"))
    before = snapshot(tmp_path)
    with refusal("too_large"):
        store.write(candidate("mine-three"))
    assert snapshot(tmp_path) == before
    assert len(store.list()) == 2
    assert store.write(candidate("mine-one")).proposal.id == "mine-one"


@pytest.mark.parametrize("private", [False, True], ids=["public", "private"])
def test_decision_capacity_serializes_concurrent_writers_and_allows_retry(tmp_path, monkeypatch, private):
    store = make_store(tmp_path)
    p = candidate()
    if private:
        p = replace(p, source="insight", source_lineage=("insight",), insight_ids=("ins-aaaaaaaaaaaa",))
    store.write(p)
    monkeypatch.setattr(store_module, "MAX_ROWS", 2)
    first = store.decide([p.id], decision="propose", operation_id="op-1")

    def decide(op):
        try:
            store.decide([p.id], decision="confirm", operation_id=op)
            return "written"
        except ProposalError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(decide, ["op-2", "op-3"]))
    assert sorted(results) == ["too_large", "written"]
    assert store.state(p.id) == "needs_draft"
    before = snapshot(tmp_path)
    assert store.decide([p.id], decision="propose", operation_id="op-1") == first
    assert snapshot(tmp_path) == before


def test_public_decision_directory_reserves_its_parent_entry(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    store.write(candidate("mine-one"))
    store.write(candidate("mine-two"))
    monkeypatch.setattr(store_module, "MAX_ROWS", 2)
    before = snapshot(tmp_path)
    with refusal("too_large"):
        store.decide(["mine-one"], decision="propose", operation_id="op-1")
    assert snapshot(tmp_path) == before
    assert not (store.root / ".aegis/proposals/decisions").exists()
    assert len(store.list()) == 2


def test_private_log_byte_projection_refuses_without_append_and_retries(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    p = candidate("ins-bytes", source="insight", source_lineage=("insight",), insight_ids=("ins-aaaaaaaaaaaa",))
    store.write(p)
    first = store.decide([p.id], decision="propose", operation_id="op-1")
    path, = store.home.rglob("*.jsonl")
    before = path.read_bytes()
    projected = dict(first, operation_id="op-2")
    raw = (json.dumps(projected, sort_keys=True, separators=(",", ":")) + "\n").encode()
    monkeypatch.setattr(store_module, "MAX_LOG_BYTES", len(before) + len(raw) - 1)
    with refusal("too_large"):
        store.decide([p.id], decision="propose", operation_id="op-2")
    assert path.read_bytes() == before
    assert store.state(p.id) == "needs_draft"
    monkeypatch.setattr(store_module, "MAX_LOG_BYTES", len(before) + len(raw))
    store.decide([p.id], decision="propose", operation_id="op-2")
    assert store.state(p.id) == "needs_draft"


def shared_worktree_stores(tmp_path):
    first = make_store(tmp_path)
    second_root = tmp_path / "second"
    second_root.mkdir()
    common = tmp_path / "common.git"
    for root, name in ((first.root, "first"), (second_root, "second")):
        gitdir = common / "worktrees" / name
        gitdir.mkdir(parents=True)
        (gitdir / "commondir").write_text("../..\n")
        (root / ".git").write_text("gitdir: " + str(gitdir) + "\n")
    second = ProposalStore(second_root, home=first.home)
    assert insights_path(first.root, home=first.home) == insights_path(second.root, home=second.home)
    return first, second


def test_shared_private_capacity_is_atomic_across_worktrees(tmp_path, monkeypatch):
    first, second = shared_worktree_stores(tmp_path)
    for store, pid in ((first, "ins-first"), (second, "ins-second")):
        store.write(candidate(pid, source="insight", source_lineage=("insight",),
                              insight_ids=("ins-aaaaaaaaaaaa",)))
    first.decide(["ins-first"], decision="propose", operation_id="op-seed")
    monkeypatch.setattr(store_module, "MAX_ROWS", 2)
    barrier, active, local = threading.Barrier(2), threading.Event(), threading.local()

    @contextmanager
    def coordinated_lock(path, *args, **kwargs):
        shared = path.suffix == ".lock"
        depth = getattr(local, "depth", 0)
        with file_lock(path, *args, **kwargs):
            if shared:
                local.depth = depth + 1
            try:
                yield
            finally:
                if shared:
                    local.depth = depth
        # Force both old implementations to finish their first shared-log read
        # before either appends. With the fix, this point follows publication.
        if shared and depth == 0 and active.is_set() and not getattr(local, "waited", False):
            local.waited = True
            barrier.wait(timeout=3)

    monkeypatch.setattr(store_module, "file_lock", coordinated_lock)

    def decide(item):
        store, pid, operation = item
        try:
            return store.decide([pid], decision="confirm", operation_id=operation)
        except ProposalError as error:
            return error.code

    items = [(first, "ins-first", "op-first"), (second, "ins-second", "op-second")]
    active.set()
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(decide, items))
    finally:
        active.clear()
    assert sum(isinstance(result, dict) for result in results) == 1
    assert results.count("too_large") == 1
    for item, result in zip(items, results):
        assert decide(item) == result
        assert item[0].state(item[1]) == "needs_draft"


def test_public_and_shared_private_quotas_remain_readable_across_worktrees(tmp_path, monkeypatch):
    first, second = shared_worktree_stores(tmp_path)
    first.write(candidate())
    second.write(candidate("ins-second", source="insight", source_lineage=("insight",),
                           insight_ids=("ins-aaaaaaaaaaaa",)))
    monkeypatch.setattr(store_module, "MAX_ROWS", 2)
    first.decide(["mine-example"], decision="propose", operation_id="op-public-1")
    for operation in ("op-private-1", "op-private-2"):
        second.decide(["ins-second"], decision="propose", operation_id=operation)
    assert first.state("mine-example") == "needs_draft"
    first.decide(["mine-example"], decision="confirm", operation_id="op-public-2")
    before = snapshot(tmp_path)
    with refusal("too_large"):
        first.decide(["mine-example"], decision="confirm", operation_id="op-public-3")
    with refusal("too_large"):
        second.decide(["ins-second"], decision="confirm", operation_id="op-private-3")
    assert snapshot(tmp_path) == before
    assert first.state("mine-example") == second.state("ins-second") == "needs_draft"


@pytest.mark.parametrize("private", [False, True], ids=["public", "private"])
def test_shared_log_lock_timeout_refuses_without_mutation_and_retries(tmp_path, private):
    first, second = shared_worktree_stores(tmp_path)
    first.write(candidate("ins-first", source="insight", source_lineage=("insight",),
                          insight_ids=("ins-aaaaaaaaaaaa",)))
    first.decide(["ins-first"], decision="propose", operation_id="op-seed")
    p = candidate()
    if private:
        p = replace(p, source="insight", source_lineage=("insight",), insight_ids=("ins-aaaaaaaaaaaa",))
    second.write(p)
    waiting = ProposalStore(second.root, home=second.home, timeout=0.03)
    path = insights_path(first.root, home=first.home).with_suffix(".lock")
    before = snapshot(tmp_path)

    def attempt():
        with refusal("timeout"):
            waiting.decide([p.id], decision="propose", operation_id="op-retry")

    with file_lock(path), ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(attempt).result(timeout=2) is None
    assert snapshot(tmp_path) == before
    assert waiting.decide([p.id], decision="propose", operation_id="op-retry")["operation_id"] == "op-retry"


def test_private_log_line_limit_covers_whitespace_and_allows_recovery(tmp_path):
    store = make_store(tmp_path)
    p = candidate("ins-lines", source="insight", source_lineage=("insight",),
                  insight_ids=("ins-aaaaaaaaaaaa",))
    store.write(p)
    store.decide([p.id], decision="propose", operation_id="op-1")
    path, = store.home.rglob("*.jsonl")
    original = path.read_bytes()
    path.write_bytes(original + b" " * store_module.MAX_ROW_BYTES + b"\n")
    before = snapshot(tmp_path)
    with refusal("too_large"):
        store.state(p.id)
    assert snapshot(tmp_path) == before
    path.write_bytes(original)
    assert store.state(p.id) == "needs_draft"


def test_identical_digest_retry_finishes_post_replace_durability(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    original = store.write(candidate())
    changed = replace(original.proposal, do="Updated guidance.")
    directory = store.root / ".aegis/proposals"
    identity = directory.stat()
    target = directory / "mine-example.md"

    def flushing(fd):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino) and b"Updated guidance." in target.read_bytes():
            raise OSError(errno.EIO, "fixed fault")
        return os.fsync(fd)

    monkeypatch.setattr(store_module, "os", module_os(fsync=flushing))
    try:
        with refusal("durability"):
            store.write(changed, expected_digest=original.digest)
        with refusal("durability"):
            store.write(changed, expected_digest=original.digest)
    finally:
        monkeypatch.setattr(store_module, "os", os)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: store.write(changed, expected_digest=original.digest), range(2)))
    assert results[0] == results[1]
    assert results[0].proposal == changed
    with refusal("stale"):
        store.write(replace(changed, do="Different unseen content."), expected_digest=original.digest)


def test_astral_text_round_trips_all_free_text_and_paths(tmp_path):
    store = make_store(tmp_path)
    p = candidate(kind="kind 😀", hypothesis="Hypothesis 😀", prediction="Prediction 😀", do="Do 😀",
                  labels=("Label 😀",), guidance=("Guide 😀",), target_paths=("src/😀/**",))
    saved = store.write(p)
    assert saved.proposal == p
    assert store.read(p.id) == saved
    assert store.list() == [saved]


def test_legacy_insight_is_readable_listable_and_reproposable_on_both_paths(tmp_path, monkeypatch):
    from aegis_core.proposals.model import legacy_insight_text
    store = make_store(tmp_path)
    row = add_insight(store.root, "Keep validation distinct from publication.", paths=["src/app.py"],
                      kind="release 😀", home=store.home)
    monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    path = write_proposal(store.root, proposal_id="trap-legacy", insight_ids=[row["id"]],
                          summary_bullets=["Check before publication."], home=store.home)
    original = path.read_bytes()
    monkeypatch.setattr(store_module, "descriptor_supported", confined_descriptor_supported)
    saved = store.read("trap-legacy")
    assert saved.proposal.legacy is True
    assert saved.proposal.private and saved.proposal.insight_ids == (row["id"],)
    assert legacy_insight_text(saved.proposal).encode() == original
    assert store.list() == [saved]
    assert write_proposal(store.root, proposal_id="trap-legacy", insight_ids=[row["id"]],
                          summary_bullets=["Check before publication."], home=store.home) == path
    assert path.read_bytes() == original
    store.decide([saved.proposal.id], decision="reject", reason="Legacy private reason", operation_id="op-1")
    assert b"Legacy private reason" not in b"".join(snapshot(store.root).values())


@pytest.mark.parametrize("url,cleaned", [
    ("http://192.0.2.1", "http://[REDACTED_IP]"),
    ("http://[REDACTED_IP]", "http://[REDACTED_IP]"),
    ("https://[2001:db8::1]:443/path", "https://[2001:db8::1]:443/path"),
    ("HTTPS://u:pass@ci.example/path?sig=hidden#private", "https://ci.example/path"),
    ("ftp://u:pass@ci.example/path?sig=hidden#private", "ftp://ci.example/path"),
    ("SSH://u:pass@ci.example/path?sig=hidden#private", "ssh://ci.example/path"),
    ("git://u:pass@ci.example/path?sig=hidden#private", "git://ci.example/path"),
    ("s3://u:pass@ci.example/path?sig=hidden#private", "s3://ci.example/path"),
    ("Custom+v1://u:pass@ci.example/path?sig=hidden#private", "custom+v1://ci.example/path"),
], ids=["ipv4", "masked-host", "ipv6", "credentials", "ftp", "ssh", "git", "s3", "custom"])
@pytest.mark.parametrize("suffix", ["`", ".", "]", ")", "}", ",", ";", ":", "!", "?", "`.", "]).", "?!"],
                         ids=["backtick", "period", "bracket", "parenthesis", "brace", "comma", "semicolon",
                              "colon", "exclamation", "question", "code-period", "closers", "punctuation"])
def test_url_boundaries_preserve_surrounding_syntax_in_every_text_field(url, cleaned, suffix):
    # RULE M: a restored query separator must not become a fresh query on retry.
    kept_suffix = suffix.rsplit("?", 1)[-1]
    text, expected = "See " + url + suffix, "See " + cleaned + kept_suffix
    p = candidate(kind=text, hypothesis=text, prediction=text, do=text, labels=(text,), guidance=(text,))
    assert (p.kind, p.hypothesis, p.prediction, p.do, p.labels[0], p.guidance[0]) == (expected,) * 6
    assert replace(p) == p
    assert model_module.parse_proposal(p.to_bytes(), p.id) == p
    # A URL is never a filesystem target, with or without surrounding syntax.
    with refusal("invalid"):
        candidate(target_paths=(url + suffix,))


@pytest.mark.parametrize("kind", ["http://192.0.2.1", "http://[REDACTED_IP]", "a`[0]"],
                         ids=["ipv4", "masked-host", "parameter-after-backtick"])
@pytest.mark.parametrize("baseline", [False, True], ids=["retained-writer", "historical-guidance"])
def test_legacy_generated_guidance_is_canonical_and_retries_keep_bytes(tmp_path, monkeypatch, kind, baseline):
    store = make_store(tmp_path)
    row = add_insight(store.root, "Keep review and publication distinct.", paths=["src/app.py"],
                      kind=kind, home=store.home)
    monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    path = write_proposal(store.root, proposal_id="trap-legacy-syntax", insight_ids=[row["id"]],
                          kind=kind, summary_bullets=["Keep punctuation intact."], home=store.home)
    original = path.read_bytes()
    if baseline:
        # The baseline writer embedded the kind after removing backticks; it did
        # not clean the generated guidance after that embedding operation.
        front, separator, body = original.partition(b"\n## Guidance\n\n")
        first, newline, rest = body.partition(b"\n")
        assert first.startswith(b"- 1 counted correction(s)") and separator and newline
        embedded_kind = model_module.clean_text(kind, 64).replace("`", "")
        generated = f"- 1 counted correction(s) of kind `{embedded_kind}`."
        original = front + separator + generated.encode() + newline + rest
        path.write_bytes(original)
    monkeypatch.setattr(store_module, "descriptor_supported", confined_descriptor_supported)
    saved = store.read("trap-legacy-syntax")
    assert saved.proposal.legacy and saved.proposal.private
    assert store.list() == [saved]
    if kind.startswith("http"):
        assert saved.proposal.guidance[0] == "1 counted correction(s) of kind `http://[REDACTED_IP]`."
    before = snapshot(tmp_path)

    def retry(_):
        return write_proposal(store.root, proposal_id="trap-legacy-syntax", insight_ids=[row["id"]],
                              kind=kind, summary_bullets=["Keep punctuation intact."], home=store.home)

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(retry, range(3))) == [path] * 3
    assert path.read_bytes() == original
    assert snapshot(tmp_path) == before
    malformed = original.replace(b"1 counted correction(s)", b"2 counted correction(s)")
    path.write_bytes(malformed)
    before = snapshot(tmp_path)
    with refusal("invalid"):
        store.read("trap-legacy-syntax")
    assert snapshot(tmp_path) == before
    path.write_bytes(original)
    assert store.read("trap-legacy-syntax") == saved


@pytest.mark.parametrize("kind", ["http://192.0.2.1", "http://[REDACTED_IP]", "a`[0]"],
                         ids=["ipv4", "masked-host", "parameter-after-backtick"])
def test_unsupported_writer_produces_parseable_legacy_guidance(tmp_path, monkeypatch, kind):
    root, home, row = seed_legacy_insight(tmp_path, kind)
    monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    path = write_proposal(root, proposal_id="trap-legacy-syntax", insight_ids=[row["id"]],
                          kind=kind, home=home)
    original = path.read_bytes()
    proposal = model_module.parse_proposal(original, "trap-legacy-syntax")
    assert proposal.legacy and proposal.private
    assert model_module.legacy_insight_text(proposal).encode() == original
    assert write_proposal(root, proposal_id=proposal.id, insight_ids=[row["id"]], kind=kind, home=home) == path
    assert path.read_bytes() == original


@pytest.mark.parametrize("stored_kind,typed_kind", [
    ("a" * 63 + " ", "a" * 63 + " b"),
    ("a" * 31 + " " + "b" * 32, "a" * 31 + " " + "b" * 32),
    ("token=[REDACTED]", "token=abcd"),
], ids=["trailing-space", "internal-space", "redacted-key"])
def test_historical_kind_normalization_preserves_read_and_reproposal(tmp_path, stored_kind, typed_kind):
    store = make_store(tmp_path)
    row = add_insight(store.root, "Keep historical proposals reviewable.", paths=["src/app.py"],
                      kind=typed_kind, home=store.home)
    text = ("---\nid: trap-historical\ntype: trap\nstatus: proposal\nenforcement: advisory\nkind: "
            + json.dumps(stored_kind) + "\ncount: 1\nhypothesis: "
            + json.dumps("Prevent recurring " + stored_kind + " issues in src/**.")
            + '\ntarget_paths:\n  - "src/**"\ninsight_ids:\n  - ' + json.dumps(row["id"])
            + "\n---\n# Proposal: trap-historical\n\n## Guidance\n\n"
            + "- 1 counted correction(s) of kind `" + stored_kind.replace("`", "") + "`.\n")
    path = store.root / ".aegis/proposals/trap-historical.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    original = text.encode()
    path.write_bytes(original)
    saved = store.read("trap-historical")
    assert saved.proposal.kind == model_module.clean_text(typed_kind, 64)
    assert store.list() == [saved]
    assert write_proposal(store.root, proposal_id="trap-historical", insight_ids=[row["id"]],
                          kind=typed_kind, home=store.home) == path
    assert path.read_bytes() == original


def test_legacy_kind_truncated_at_query_marker_reproposes_without_rewrite(tmp_path):
    store = make_store(tmp_path)
    prefix = "https://ci.example/"
    base = prefix + "x" * (63 - len(prefix) - len("/job")) + "/job"
    typed_kind, stored_kind = base + "?sig=hunter2#private", base + "?"
    assert len(stored_kind) == 64 and stored_kind.endswith("job?")
    row = add_insight(store.root, "Keep old drafts reviewable.", paths=["src/app.py"],
                      kind=typed_kind, home=store.home)
    raw = ("---\nid: trap-query-edge\ntype: trap\nstatus: proposal\nenforcement: advisory\nkind: "
           + json.dumps(stored_kind) + "\ncount: 1\nhypothesis: "
           + json.dumps("Prevent recurring " + stored_kind + " issues in src/**.")
           + '\ntarget_paths:\n  - "src/**"\ninsight_ids:\n  - ' + json.dumps(row["id"])
           + "\n---\n# Proposal: trap-query-edge\n\n## Guidance\n\n"
           + "- 1 counted correction(s) of kind `" + stored_kind + "`.\n").encode()
    path = store.root / ".aegis/proposals/trap-query-edge.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    before = store.read("trap-query-edge")
    assert store.list() == [before]
    assert write_proposal(store.root, proposal_id="trap-query-edge", insight_ids=[row["id"]],
                          kind=typed_kind, home=store.home) == path
    assert path.read_bytes() == raw
    assert store.read("trap-query-edge") == before


@pytest.mark.parametrize("scheme", ["ftp", "SSH", "git", "s3", "Custom+v1"])
def test_all_hierarchical_url_schemes_are_redacted_in_persisted_fields(tmp_path, scheme):
    store = make_store(tmp_path)
    text = scheme + "://u:pass@ci.example/path?sig=hidden#private`."
    p = candidate(kind=text, hypothesis=text, prediction=text, do=text, labels=(text,), guidance=(text,))
    saved = store.write(p)
    expected = scheme.lower() + "://ci.example/path`."
    assert saved.proposal.kind == expected
    row = store.decide([p.id], decision="propose", operation_id="op-1", reason=text)
    assert row["reason"] == expected
    assert store.read(p.id) == saved
    assert all(secret not in b"".join(snapshot(store.root).values())
               for secret in (b"u:pass", b"hidden", b"#private"))


_MASKED_AUTHORITY_SECRETS = {
    "redis://:hunter2'mail@example.com/0": ("hunter2", "mail"),
    "https://ci.example;password=a@hunter2": ("a@hunter2", "hunter2"),
    "https://ci.example,password=a@hunter2": ("a@hunter2", "hunter2"),
}


def assert_masked_authority_secrets_absent(text, output):
    for secret in _MASKED_AUTHORITY_SECRETS.get(text, ()):
        assert secret.lower().encode() not in output.lower()


# Scanner-shaped token, composed so the source has no credential literal.
_GOOGLE_TOKEN = "AIza" + "Sy" + "DaGmWKa4JsXZ" + "-HjGw7x8_" + "0" * 12
_STRUCTURAL_URL_CASES = [
    ("https://ci.example/job?sig=(hunter2)", "https://ci.example/job)", "hunter2"),
    ("https://ci.example/job?sig=[hunter2]", "https://ci.example/job]", "hunter2"),
    ('https://ci.example/job?sig="hunter2"', 'https://ci.example/job"', "hunter2"),
    ("https://ci.example/job#sig=(hunter2)", "https://ci.example/job)", "hunter2"),
    ("redis://:(hunter2)@localhost/0", "redis://localhost/0", "hunter2"),
    ("://:hunter2@localhost/0", "://localhost/0", "hunter2"),
    ("_://:hunter2@localhost/0", "_://localhost/0", "hunter2"),
    ("1://:hunter2@localhost/0", "1://localhost/0", "hunter2"),
    ("redis://:hunter2@@localhost/0", "redis://localhost/0", "hunter2"),
    ("redis://:hunter2'mail@example.com/0", "[REDACTED_URL]", "hunter2"),
    ("https://AKIAIOSFODNN7EXAMPLE.example.com/job?sig=1",
     "https://[REDACTED_AWS].example.com/job", "AKIAIOSFODNN7EXAMPLE"),
    ("https://" + _GOOGLE_TOKEN + ".example.com/job",
     "https://[REDACTED_TOKEN].example.com/job", _GOOGLE_TOKEN),
    ("https://ci.example/job?sig=(hunter2)]}.`'\"", "https://ci.example/job)]}.`'\"", "hunter2"),
    ("redis://:hunter2?more@localhost/0", "[REDACTED_URL]", "hunter2"),
    ("redis://:hunter2#more@localhost/0", "[REDACTED_URL]", "hunter2"),
    ("https://ci.example?sig=hunter2@example.com", "https://ci.example", "hunter2"),
    ("https://ci.example/job(1)?sig=hunter2#private", "https://ci.example/job(1)", "hunter2"),
    ("https://AKIAIOSFODNN7EXAMPLE/path", "https://[REDACTED_AWS]/path", "AKIAIOSFODNN7EXAMPLE"),
    ("://:hunter2@localhost:6379/0", "://localhost:6379/0", "hunter2"),
    ("https://ci.example/job?a=[]&sig=hunter2", "https://ci.example/job", "hunter2"),
]
_STRUCTURAL_URL_IDS = ["query-parentheses", "query-brackets", "query-quotes", "fragment", "empty-user",
                       "bare-scheme", "underscore-scheme", "numeric-scheme", "last-at", "masked-at",
                       "aws-host", "google-host", "trailing-syntax", "userinfo-query-overlap",
                       "userinfo-fragment-overlap", "query-at-overlap", "path-parenthesis", "bare-aws-host",
                       "bare-user-port", "passing-empty-brackets"]


@pytest.mark.parametrize("text,expected,secret", _STRUCTURAL_URL_CASES, ids=_STRUCTURAL_URL_IDS)
def test_structural_url_cleaning_is_stable_for_all_model_fields_and_keys(text, expected, secret):
    p = candidate(kind=text, hypothesis=text, prediction=text, do=text, labels=(text,), guidance=(text,))
    assert (p.kind, p.hypothesis, p.prediction, p.do, p.labels[0], p.guidance[0]) == (expected,) * 6
    assert model_module.clean_text(expected) == expected
    assert replace(p) == p
    assert model_module.parse_proposal(p.to_bytes(), p.id) == p
    assert secret.lower() not in p.to_bytes().decode().lower()
    assert_masked_authority_secrets_absent(text, p.to_bytes())
    for field, value in (("candidate_key", text), ("evidence_ids", (text,))):
        with refusal("invalid"):
            candidate(**{field: value})


@pytest.mark.parametrize("text,expected,secret", _STRUCTURAL_URL_CASES, ids=_STRUCTURAL_URL_IDS)
def test_structural_url_secrets_never_reach_proposal_or_decision_bytes(tmp_path, text, expected, secret):
    store = make_store(tmp_path)
    p = candidate(kind=text, hypothesis=text, prediction=text, do=text, labels=(text,), guidance=(text,))
    saved = store.write(p)
    assert saved.proposal == p
    row = store.decide([p.id], decision="propose", operation_id="op-structural", reason=text)
    assert row["reason"] == expected
    before = snapshot(tmp_path)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: store.write(p), range(3))) == [saved] * 3
    assert store.decide([p.id], decision="propose", operation_id="op-structural", reason=text) == row
    assert snapshot(tmp_path) == before
    assert secret.lower().encode() not in b"".join(before.values()).lower()
    assert_masked_authority_secrets_absent(text, row["reason"].encode())
    assert_masked_authority_secrets_absent(text, b"".join(before.values()))


def test_generated_url_secret_spans_remain_removed_and_stable():
    rng = Random(1516)
    alphabet = "abc012()[]{}<>.,;:!?`'\"@#_%+-"
    for scheme in ("https", "redis", "", "_", "1"):
        for _ in range(100):
            material = "needle" + "".join(rng.choices(alphabet, k=25))
            for text in (scheme + "://ci.example/job?sig=" + material,
                         scheme + "://:" + material + "@localhost/0"):
                cleaned = model_module.clean_text(text)
                assert "needle" not in cleaned
                assert model_module.clean_text(cleaned) == cleaned
                p = candidate(hypothesis=text, prediction=text, do=text, labels=(text,), guidance=(text,))
                assert replace(p) == p
                assert model_module.parse_proposal(p.to_bytes(), p.id) == p


_CONTEXT_REDACTION_CASES = [
    ("https://ci.example/?q=Bearer abcdefghijklmnop", "abcdefghijklmnop"),
    ("https://ci.example/?q=Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop"),
    ("https://ci.example/?q=token= abcdefghijklmnop", "abcdefghijklmnop"),
    ("https://ci.example/?q=" + "-----BEGIN " + "PRIVATE KEY-----\nSHORTKEYLINE\n-----END "
     + "PRIVATE KEY-----", "SHORTKEYLINE"),
    ("https://ci.example/?q=ghp_" + "a" * 24, "ghp_" + "a" * 24),
]


@pytest.mark.parametrize("text,secret", _CONTEXT_REDACTION_CASES,
                         ids=["bearer", "authorization", "key-value", "pem", "token-prefix"])
def test_original_redaction_and_url_removal_protect_all_text_fields(tmp_path, text, secret):
    store = make_store(tmp_path)
    kwargs = dict(hypothesis=text, prediction=text, do=text, labels=(text,), guidance=(text,))
    if "\n" not in text:
        kwargs["kind"] = text
    else:
        with refusal("invalid"):
            candidate(kind=text)
    p = candidate(**kwargs)
    saved = store.write(p)
    row = store.decide([p.id], decision="propose", operation_id="op-context", reason=text)
    assert secret not in p.to_bytes().decode()
    assert secret not in row["reason"]
    assert secret.encode() not in b"".join(snapshot(tmp_path).values())
    assert model_module.clean_text(row["reason"]) == row["reason"]
    assert store.read(p.id) == saved
    before = snapshot(tmp_path)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: store.write(p), range(3))) == [saved] * 3
    assert store.decide([p.id], decision="propose", operation_id="op-context", reason=text) == row
    assert snapshot(tmp_path) == before


_AUTHORITY_CASES = [
    ("https://ci.example;password=a@hunter2", "https://ci.example;password=[REDACTED]", "hunter2", False),
    ("https://ci.example,password=a@hunter2", "https://ci.example,password=[REDACTED]", "hunter2", False),
    ("https://:hunter2://@example.com/path", "[REDACTED_URL]", "hunter2", False),
    ("://:hunter2://@example.com/path", "[REDACTED_URL]", "hunter2", False),
    ("See https://ci.example?user=alice@example.com for details",
     "See https://ci.example for details", "alice", False),
    ("https://ci.example#sec@1", "https://ci.example", "sec@1", False),
    ("https://ci.example/path/redis://:hunter2@localhost/0", "[REDACTED_URL]", "hunter2", False),
    ("https://ci.example/?next=redis://:hunter2@localhost/0", "[REDACTED_URL]", "hunter2", False),
    ("https://ci.example/#next=redis://:hunter2@localhost/0", "[REDACTED_URL]", "hunter2", False),
    ("https://ci.example/path@revision", "https://ci.example/path@revision", None, True),
    ("https://[2001:db8::1]:443/path?sig=hunter2", "https://[2001:db8::1]:443/path", "hunter2", False),
    ("https://[2001:db8::1/path?sig=hunter2", "[REDACTED_URL]", "hunter2", False),
    ("https:///path?sig=hunter2", "[REDACTED_URL]", "hunter2", False),
]
_AUTHORITY_IDS = ["semicolon-param", "comma-param", "nested-authority", "nested-bare", "query-at",
                  "fragment-at", "nested-path", "nested-query", "nested-fragment", "path-at", "ipv6",
                  "unterminated-ipv6", "empty-authority"]


@pytest.mark.parametrize("text,expected,secret,key_allowed", _AUTHORITY_CASES, ids=_AUTHORITY_IDS)
def test_authority_boundaries_and_ambiguous_tokens_are_stable(text, expected, secret, key_allowed):
    p = candidate(kind=text, hypothesis=text, prediction=text, do=text, labels=(text,), guidance=(text,))
    assert (p.kind, p.hypothesis, p.prediction, p.do, p.labels[0], p.guidance[0]) == (expected,) * 6
    assert model_module.clean_text(expected) == expected
    assert replace(p) == p
    assert model_module.parse_proposal(p.to_bytes(), p.id) == p
    assert_masked_authority_secrets_absent(text, p.to_bytes())
    if key_allowed:
        keys = candidate(candidate_key=text, evidence_ids=(text,))
        assert model_module.parse_proposal(keys.to_bytes(), keys.id) == keys
    else:
        for field, value in (("candidate_key", text), ("evidence_ids", (text,))):
            with refusal("invalid"):
                candidate(**{field: value})


@pytest.mark.parametrize("text,expected,secret,key_allowed", _AUTHORITY_CASES, ids=_AUTHORITY_IDS)
def test_authority_edits_protect_persisted_fields_and_retries(tmp_path, text, expected, secret, key_allowed):
    store = make_store(tmp_path)
    p = candidate(kind=text, hypothesis=text, prediction=text, do=text, labels=(text,), guidance=(text,))
    saved = store.write(p)
    row = store.decide([p.id], decision="propose", operation_id="op-authority", reason=text)
    assert row["reason"] == expected
    before = snapshot(tmp_path)
    if secret is not None:
        assert secret.lower().encode() not in b"".join(before.values()).lower()
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: store.write(p), range(3))) == [saved] * 3
    assert store.decide([p.id], decision="propose", operation_id="op-authority", reason=text) == row
    assert snapshot(tmp_path) == before
    assert_masked_authority_secrets_absent(text, row["reason"].encode())
    assert_masked_authority_secrets_absent(text, b"".join(before.values()))


_MASKED_USERINFO_CASES = [
    ("https://" + "-----BEGIN " + "PRIVATE KEY-----\nsourceprivate@ci.example/0\n-----END "
     + "PRIVATE KEY-----",
     "https://[REDACTED_PEM]", ("sourceprivate", "PRIVATE KEY")),
    ("https://:Bearer abcdefghijklmnop;password=left@ci.example/0",
     "[REDACTED_URL] [REDACTED];password=[REDACTED]", ("abcdefghijklmnop", "left@ci.example", "left")),
    ("https://sourceprivate@example.com/path",
     "https://[REDACTED_EMAIL]/path", ("sourceprivate@example.com", "sourceprivate")),
    ("https://:Bearer abcdefghijklmnop'sourceprivate@example.com/path",
     "[REDACTED_URL] [REDACTED]'[REDACTED_EMAIL]/path", ("abcdefghijklmnop", "sourceprivate")),
]
_MASKED_USERINFO_IDS = ["pem", "bearer-key", "email-userinfo", "bearer-email"]


@pytest.mark.parametrize("text,expected,secrets", _MASKED_USERINFO_CASES, ids=_MASKED_USERINFO_IDS)
def test_masked_userinfo_preserves_ordered_results_and_never_exposes_secrets(text, expected, secrets):
    assert "@" in text and "@" not in redact_insight_text(text, max_len=0)
    kwargs = dict(hypothesis=text, prediction=text, do=text, labels=(text,), guidance=(text,))
    if "\n" in text:
        with refusal("invalid"):
            candidate(kind=text)
    else:
        kwargs["kind"] = text
    p = candidate(**kwargs)
    assert (p.hypothesis, p.prediction, p.do, p.labels[0], p.guidance[0]) == (expected,) * 5
    if "\n" not in text:
        assert p.kind == expected
    assert model_module.clean_text(expected) == expected
    assert replace(p) == p
    assert model_module.parse_proposal(p.to_bytes(), p.id) == p
    for secret in secrets:
        assert secret.lower().encode() not in p.to_bytes().lower()
    for field, value in (("candidate_key", text), ("evidence_ids", (text,))):
        with refusal("invalid"):
            candidate(**{field: value})


@pytest.mark.parametrize("text,expected,secrets", _MASKED_USERINFO_CASES, ids=_MASKED_USERINFO_IDS)
def test_masked_userinfo_keeps_disk_private_through_concurrent_retries(tmp_path, text, expected, secrets):
    store = make_store(tmp_path)
    kwargs = dict(hypothesis=text, prediction=text, do=text, labels=(text,), guidance=(text,))
    if "\n" not in text:
        kwargs["kind"] = text
    p = candidate(**kwargs)
    saved = store.write(p)
    row = store.decide([p.id], decision="propose", operation_id="op-masked-userinfo", reason=text)
    assert row["reason"] == expected
    assert store.read(p.id) == saved
    before = snapshot(tmp_path)
    for secret in secrets:
        assert secret.lower() not in row["reason"].lower()
        assert secret.lower().encode() not in b"".join(before.values()).lower()
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: store.write(p), range(3))) == [saved] * 3
    assert store.decide([p.id], decision="propose", operation_id="op-masked-userinfo", reason=text) == row
    assert snapshot(tmp_path) == before


def baseline_proposal_bytes(pid, identity, kind, summaries):
    raw_kind = redact_insight_text(" ".join(kind.split()), max_len=64)
    bullets = [f"1 counted correction(s) of kind `{raw_kind.replace('`', '')}`."]
    bullets.extend(redact_insight_text(b.strip(), max_len=200) for b in summaries if b.strip())
    lines = ["---", "id: " + pid, "type: trap", "status: proposal", "enforcement: advisory",
             "kind: " + json.dumps(raw_kind), "count: 1",
             "hypothesis: " + json.dumps("Prevent recurring " + raw_kind + " issues in src/**."),
             'target_paths:\n  - "src/**"', "insight_ids:\n  - " + json.dumps(identity),
             "---", "# Proposal: " + pid, "", "## Guidance", ""]
    lines.extend("- " + bullet for bullet in bullets)
    return ("\n".join(lines) + "\n").encode()


@pytest.mark.parametrize("field", ["kind", "summary"])
@pytest.mark.parametrize("shape", ["combining", "expanding", "grapheme", "query", "fragment", "at", "punctuation"])
@pytest.mark.parametrize("offset", [-1, 0, 1], ids=["before", "at", "after"])
def test_baseline_retry_uses_historical_truncation_before_normalization(tmp_path, field, shape, offset):
    store = make_store(tmp_path)
    limit = 64 if field == "kind" else 200
    if shape in ("combining", "expanding", "grapheme"):
        ending = {"combining": "e\u0301Z", "expanding": "\ufb03Z", "grapheme": "👩\u200d💻Z"}[shape]
        text = "a" * (limit - 1 + offset) + ending
    else:
        prefix = "https://ci.example/"
        head = prefix + "x" * (limit - len(prefix) - 1 + offset)
        ending = {"query": "?sig=hunter2)", "fragment": "#sig=hunter2]",
                  "at": "@localhost/path)", "punctuation": ".) trailing"}[shape]
        text = head + ending
    kind, summaries = (text, ["Keep checks distinct."]) if field == "kind" else ("release", [text])
    row = add_insight(store.root, "Keep baseline retries stable.", paths=["src/app.py"],
                      kind="release", home=store.home)
    pid = "trap-baseline-retry"
    raw = baseline_proposal_bytes(pid, row["id"], kind, summaries)
    path = store.root / (".aegis/proposals/" + pid + ".md")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    saved = store.read(pid)
    before = snapshot(tmp_path)

    def retry(_):
        return write_proposal(store.root, proposal_id=pid, insight_ids=[row["id"]], kind=kind,
                              summary_bullets=summaries, home=store.home)

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(retry, range(3))) == [path] * 3
    assert store.read(pid) == saved
    assert snapshot(tmp_path) == before
    with refusal("exists"):
        write_proposal(store.root, proposal_id=pid, insight_ids=[row["id"]], kind=kind,
                       summary_bullets=["Different guidance."], home=store.home)
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("field", ["kind", "summary"])
def test_new_insight_proposals_keep_current_normalization_pipeline(tmp_path, field):
    store = make_store(tmp_path)
    row = add_insight(store.root, "Keep current proposal preparation stable.", paths=["src/app.py"],
                      kind="release", home=store.home)
    kind = "a" * 63 + "e\u0301" if field == "kind" else "release"
    summaries = ["a" * 199 + "e\u0301"] if field == "summary" else ["Keep checks distinct."]
    path = write_proposal(store.root, proposal_id="trap-current", insight_ids=[row["id"]], kind=kind,
                          summary_bullets=summaries, home=store.home)
    saved = store.read("trap-current")
    assert not saved.proposal.legacy
    assert saved.proposal.kind == model_module.clean_text(kind, 64)
    assert saved.proposal.guidance[1:] == tuple(model_module.clean_text(b, 200) for b in summaries)
    before = path.read_bytes()
    assert write_proposal(store.root, proposal_id="trap-current", insight_ids=[row["id"]], kind=kind,
                          summary_bullets=summaries, home=store.home) == path
    assert path.read_bytes() == before


def test_legacy_retry_projection_cannot_override_provenance_or_digest_updates(tmp_path):
    store = make_store(tmp_path)
    p = candidate("ins-hint", source="insight", source_lineage=("insight",), insight_ids=("ins-aaaaaaaaaaaa",))
    saved = store.write(p)
    before = snapshot(tmp_path)
    for hint in ([], replace(p, id="ins-other"), replace(p, evidence_ids=("different",))):
        with refusal("invalid"):
            store.write(p, legacy_retry=hint)
    with refusal("invalid"):
        store.write(replace(p, do="New guidance."), expected_digest=saved.digest, legacy_retry=p)
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("field", ["kind", "summary"])
@pytest.mark.parametrize("shape", ["combining", "query", "fragment"])
@pytest.mark.parametrize("offset", [-1, 0, 1], ids=["before", "at", "after"])
def test_retained_writer_boundary_retries_accept_current_equality(tmp_path, monkeypatch, field, shape, offset):
    store = make_store(tmp_path)
    limit = 64 if field == "kind" else 200
    if shape == "combining":
        text = "a" * (limit - 1 + offset) + "e\u0301Z"
    else:
        prefix = "https://ci.example/"
        text = prefix + "x" * (limit - len(prefix) - 1 + offset)
        text += "?sig=hunter2)" if shape == "query" else "#sig=hunter2]"
    kind, summaries = (text, ["Keep checks distinct."]) if field == "kind" else ("release", [text])
    row = add_insight(store.root, "Keep retained writer retries stable.", paths=["src/app.py"],
                      kind="release", home=store.home)
    kwargs = dict(proposal_id="trap-retained-boundary", insight_ids=[row["id"]], kind=kind,
                  summary_bullets=summaries, home=store.home)
    monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    path = write_proposal(store.root, **kwargs)
    monkeypatch.setattr(store_module, "descriptor_supported", confined_descriptor_supported)
    saved = store.read(kwargs["proposal_id"])
    assert saved.proposal.legacy
    assert saved.proposal.kind == model_module.clean_text(kind, 64)
    assert saved.proposal.guidance[1:] == tuple(model_module.clean_text(b, 200) for b in summaries)
    before = snapshot(tmp_path)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: write_proposal(store.root, **kwargs), range(3))) == [path] * 3
    assert store.read(kwargs["proposal_id"]) == saved
    assert snapshot(tmp_path) == before
    with refusal("exists"):
        write_proposal(store.root, **dict(kwargs, kind="different", summary_bullets=["Different guidance."]))
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("supported", [False, True], ids=["unsupported", "supported"])
def test_format_character_kind_creates_and_retries_without_historical_veto(tmp_path, monkeypatch, supported):
    if supported:
        store = make_store(tmp_path)
        root, home = store.root, store.home
        row = add_insight(root, "Keep current writer inputs valid.", paths=["src/app.py"],
                          kind="release", home=home)
    else:
        root, home, row = seed_legacy_insight(tmp_path)
        monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    kwargs = dict(proposal_id="trap-format-kind", insight_ids=[row["id"]],
                  kind="\u200b" * 64 + "release", home=home)
    path = write_proposal(root, **kwargs)
    saved = model_module.parse_proposal(path.read_bytes(), kwargs["proposal_id"])
    assert saved.kind == "release"
    assert saved.legacy is not supported
    before = snapshot(tmp_path)
    assert write_proposal(root, **kwargs) == path
    assert snapshot(tmp_path) == before


def test_unbuildable_historical_projection_is_only_a_legacy_mismatch(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    row = add_insight(store.root, "Keep legacy mismatch refusals stable.", paths=["src/app.py"],
                      kind="release", home=store.home)
    kwargs = dict(proposal_id="trap-unbuildable", insight_ids=[row["id"]], home=store.home)
    monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    path = write_proposal(store.root, **kwargs)
    monkeypatch.setattr(store_module, "descriptor_supported", confined_descriptor_supported)
    assert store.read(kwargs["proposal_id"]).proposal.legacy
    before = snapshot(tmp_path)
    assert write_proposal(store.root, **dict(kwargs, kind="\u200b" * 64 + "release")) == path
    with refusal("exists"):
        write_proposal(store.root, **dict(kwargs, kind="\u200b" * 64 + "different"))
    assert snapshot(tmp_path) == before
    store.decide([kwargs["proposal_id"]], decision="reject", reason="Keep terminal proposals immutable.",
                 operation_id="op-unbuildable")
    before = snapshot(tmp_path)
    with refusal("terminal"):
        write_proposal(store.root, **dict(kwargs, kind="\u200b" * 64 + "release"))
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("text,expected", [
    ("See https://192.0.2.1.nip.io/run for details", "See https://[REDACTED_IP].nip.io/run for details"),
    ("https://192.0.2.1.nip.io/run", "https://[REDACTED_IP].nip.io/run"),
], ids=["surrounding-prose", "url-only-kind"])
def test_masked_authorities_keep_surrounding_prose_and_nonempty_kind(text, expected):
    assert model_module.clean_text(text, 240) == expected
    assert model_module.clean_text(expected, 240) == expected
    p = candidate(kind=text)
    assert p.kind == expected
    assert model_module.parse_proposal(p.to_bytes(), p.id) == p


@pytest.mark.parametrize("decision", ["propose", "reject", "noise", "confirm", "snooze", "merge-into-rule", "accept"])
@pytest.mark.parametrize("historical", [False, True], ids=["new-event", "historical-event"])
def test_private_proposal_decisions_do_not_change_insight_review(tmp_path, decision, historical):
    store = make_store(tmp_path)
    row = add_insight(store.root, "Keep proposal review separate from insight state.",
                      paths=["src/app.py"], kind="release", home=store.home)
    write_proposal(store.root, proposal_id="trap-private-event", insight_ids=[row["id"]], home=store.home)
    before = json.dumps(review_insights(store.root, home=store.home), sort_keys=True).encode()
    kwargs = {"decision": decision, "operation_id": "op-private-event", "reason": "Proposal queue only"}
    if decision == "snooze":
        kwargs["until"] = "9999-01-01"
    result = store.decide(["trap-private-event"], **kwargs)
    if historical:
        path = insights_path(store.root, home=store.home)
        rows = [json.loads(line) for line in path.read_bytes().splitlines()]
        for stored in rows:
            if "proposal_ids" in stored:
                stored["event"] = "decision"
        path.write_text("".join(json.dumps(stored) + "\n" for stored in rows))
    after = snapshot(tmp_path)
    assert json.dumps(review_insights(store.root, home=store.home), sort_keys=True).encode() == before
    assert result["event"] == "proposal_decision"
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: store.decide(["trap-private-event"], **kwargs), range(3))) == [result] * 3
    assert snapshot(tmp_path) == after
    assert json.dumps(review_insights(store.root, home=store.home), sort_keys=True).encode() == before


def test_private_proposal_confirm_cannot_count_an_unconfirmed_suggestion(tmp_path):
    store = make_store(tmp_path)
    row = capture_suggestion(store.root, "Keep suggestions separate from human confirmation.",
                             paths=["src/app.py"], home=store.home)
    p = candidate("ins-suggestion", source="insight", source_lineage=("insight",),
                  insight_ids=(row["id"],), evidence_ids=("insight:" + row["id"],))
    store.write(p)
    before = json.dumps(review_insights(store.root, home=store.home), sort_keys=True).encode()
    assert len(review_insights(store.root, home=store.home)["suggestions"]) == 1
    store.decide([p.id], decision="confirm", operation_id="op-suggestion")
    assert json.dumps(review_insights(store.root, home=store.home), sort_keys=True).encode() == before


def legacy_identity_bytes(identity):
    p = candidate("ins-legacy-id", source="insight", source_lineage=("insight",),
                  insight_ids=("ins-aaaaaaaaaaaa",), evidence_ids=("insight:ins-aaaaaaaaaaaa",),
                  status="proposal", guidance=("1 counted correction(s) of kind `platform`.",))
    raw = model_module.legacy_insight_text(p).encode()
    return p, raw.replace(b'"ins-aaaaaaaaaaaa"', json.dumps(identity).encode())


@pytest.mark.parametrize("identity", ["not-an-insight", "ins-zzzzzzzzzzzz", "x" * 256, None, 42, ["nested"]],
                         ids=["wrong-shape", "wrong-alphabet", "long", "none", "number", "nested"])
def test_legacy_insight_element_errors_have_the_documented_parser_category(identity):
    p, raw = legacy_identity_bytes(identity)
    with refusal("invalid"):
        model_module.parse_proposal(raw, p.id)


@pytest.mark.parametrize("operation", ["read", "list", "state", "merge", "decide", "resume", "write"])
def test_legacy_insight_element_errors_refuse_all_store_surfaces_and_recover(tmp_path, operation):
    store = make_store(tmp_path)
    p, raw = legacy_identity_bytes("not-an-insight")
    store.write(p)
    path = store.root / ".aegis/proposals/ins-legacy-id.md"
    path.write_bytes(raw)
    before = snapshot(tmp_path)

    def attempt(_):
        with refusal("invalid"):
            if operation == "list":
                store.list()
            elif operation == "merge":
                store.merge([p.id], "mine-destination")
            elif operation == "decide":
                store.decide([p.id], decision="propose", operation_id="op-legacy")
            elif operation == "write":
                store.write(p)
            elif operation == "resume":
                store.resume(p.id)
            elif operation == "state":
                store.state(p.id)
            else:
                store.read(p.id)

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(attempt, range(3))) == [None] * 3
    assert snapshot(tmp_path) == before
    _, valid = legacy_identity_bytes("ins-aaaaaaaaaaaa")
    path.write_bytes(valid)
    assert store.read(p.id).proposal.insight_ids == ("ins-aaaaaaaaaaaa",)


@pytest.mark.parametrize("spelling", ["relative", "symlink"])
def test_owner_home_resolves_for_compatibility_writer_and_decisions(tmp_path, spelling):
    workspace, home, row = seed_legacy_insight(tmp_path)
    selected = home.name if spelling == "relative" else tmp_path / "selected-home"
    if spelling == "symlink":
        symlink_or_skip(home, selected, target_is_directory=True)
    code = ("import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
            "from aegis_core.insights import write_proposal; "
            "from aegis_core.proposals import ProposalStore, ProposalError; "
            "from aegis_core.storage import confined_descriptor_supported; "
            "root, home, expected = Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]); "
            "path = write_proposal(root, proposal_id='trap-home', insight_ids=[sys.argv[5]], home=home); "
            "assert write_proposal(root, proposal_id='trap-home', insight_ids=[sys.argv[5]], home=home) == path; "
            "store = ProposalStore(root, home=home); assert store.home == expected; "
            "\nif confined_descriptor_supported():\n"
            "    row = store.decide(['trap-home'], decision='propose', operation_id='op-home')\n"
            "    assert store.decide(['trap-home'], decision='propose', operation_id='op-home') == row\n"
            "else:\n"
            "    try: store.decide(['trap-home'], decision='propose', operation_id='op-home')\n"
            "    except ProposalError as error: assert error.code == 'unsupported'\n"
            "    else: raise AssertionError('missing unsupported refusal')\n")
    result = subprocess.run([sys.executable, "-I", "-c", code, str(Path(__file__).resolve().parents[3]),
                             str(workspace), str(selected), str(home), row["id"]], cwd=tmp_path,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("field", ["root", "home"])
def test_owner_root_spelling_is_bounded_before_path_resolution(tmp_path, field):
    oversized = "x" * 32769
    with refusal("invalid"):
        ProposalStore(oversized if field == "root" else tmp_path,
                      home=oversized if field == "home" else tmp_path)


def test_owner_home_loop_refuses_without_echo_then_recovers(tmp_path):
    workspace, home, row = seed_legacy_insight(tmp_path)
    selected = tmp_path / "loop-home"
    symlink_or_skip(selected, selected, target_is_directory=True)
    before = snapshot(workspace), snapshot(home)
    with refusal("invalid"):
        ProposalStore(workspace, home=selected)
    with refusal("invalid"):
        write_proposal(workspace, proposal_id="trap-home-retry", insight_ids=[row["id"]], home=selected)
    assert (snapshot(workspace), snapshot(home)) == before
    selected.unlink()
    symlink_or_skip(home, selected, target_is_directory=True)
    path = write_proposal(workspace, proposal_id="trap-home-retry", insight_ids=[row["id"]], home=selected)
    assert path.is_file()
    if confined_descriptor_supported():
        assert ProposalStore(workspace, home=selected).decide(
            ["trap-home-retry"], decision="propose", operation_id="op-home-retry")["decision"] == "propose"


@pytest.mark.parametrize("mutation", ["missing-insights", "extra-source", "wrong-count", "wrong-header"])
def test_ambiguous_legacy_proposals_refuse(tmp_path, mutation):
    from aegis_core.proposals.model import legacy_insight_text
    store = make_store(tmp_path)
    p = candidate("ins-legacy", source="insight", source_lineage=("insight",),
                  insight_ids=("ins-aaaaaaaaaaaa",), evidence_ids=("insight:ins-aaaaaaaaaaaa",),
                  status="proposal", do="1 counted correction(s) of kind `platform`.",
                  guidance=("1 counted correction(s) of kind `platform`.", "Keep checks bounded."))
    store.write(p)
    raw = legacy_insight_text(p).encode()
    if mutation == "missing-insights":
        raw = raw.replace(b'insight_ids:\n  - "ins-aaaaaaaaaaaa"\n', b"")
    elif mutation == "extra-source":
        raw = raw.replace(b"type: trap", b"source: mine\ntype: trap")
    elif mutation == "wrong-count":
        raw = raw.replace(b"count: 1", b"count: 2")
    else:
        raw = raw.replace(b"# Proposal: ins-legacy", b"# Proposal: mine-other")
    (store.root / ".aegis/proposals/ins-legacy.md").write_bytes(raw)
    with refusal("invalid"):
        store.read(p.id)


@pytest.mark.parametrize("scheme", ["HTTPS", "hTtPs", "HTTP"])
def test_url_secrets_are_removed_from_every_free_text_field(tmp_path, scheme):
    store = make_store(tmp_path)
    text = scheme + "://operator:password@ci.example/job?sig=hunter2#private-fragment"
    p = candidate(kind=text, hypothesis=text, prediction=text, do=text, guidance=(text,), labels=(text,))
    saved = store.write(p)
    row = store.decide([p.id], decision="propose", reason=text, operation_id="op-1")
    assert row["reason"].lower().startswith(scheme.lower() + "://ci.example/job")
    assert store.read(p.id) == saved
    raw = b"".join(snapshot(store.root).values())
    assert all(secret not in raw for secret in (b"operator", b"password", b"hunter2", b"private-fragment"))


@pytest.mark.parametrize("private", [False, True], ids=["public", "private"])
def test_missing_markdown_cannot_recreate_a_decided_revision(tmp_path, private):
    store = make_store(tmp_path)
    p = candidate()
    if private:
        p = replace(p, source="insight", source_lineage=("insight",), insight_ids=("ins-aaaaaaaaaaaa",))
    store.write(p)
    store.decide([p.id], decision="reject", reason="Preserve history", operation_id="op-1")
    (store.root / ".aegis/proposals/mine-example.md").unlink()
    before = snapshot(tmp_path)
    with refusal("terminal"):
        store.write(replace(p, do="Different content."))
    with refusal("terminal"):
        store.write(p)
    assert snapshot(tmp_path) == before


def test_creation_refuses_malformed_decision_history(tmp_path):
    store = make_store(tmp_path)
    store.write(candidate())
    directory = store.root / ".aegis/proposals/decisions"
    directory.mkdir()
    (directory / "broken.json").write_text('{"decision":"accept"}')
    before = snapshot(tmp_path)
    with refusal("decision"):
        store.write(candidate("mine-new"))
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("private", [False, True], ids=["public", "private"])
def test_decision_retries_flush_private_or_public_leaf_directory(tmp_path, monkeypatch, private):
    store = make_store(tmp_path)
    p = candidate()
    if private:
        p = replace(p, source="insight", source_lineage=("insight",), insight_ids=("ins-aaaaaaaaaaaa",))
    store.write(p)
    store.decide([p.id], decision="propose", operation_id="op-first")
    directory = (next(store.home.rglob("*.jsonl")).parent if private
                 else store.root / ".aegis/proposals/decisions")
    identity = directory.stat()

    def flushing(fd):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
            raise OSError(errno.EIO, "fixed fault")
        return os.fsync(fd)

    monkeypatch.setattr(store_module, "os", module_os(fsync=flushing))
    try:
        with refusal("durability"):
            store.decide([p.id], decision="propose", operation_id="op-retry")
        with refusal("durability"):
            store.decide([p.id], decision="propose", operation_id="op-retry")
    finally:
        monkeypatch.setattr(store_module, "os", os)
    row = store.decide([p.id], decision="propose", operation_id="op-retry")
    assert row["operation_id"] == "op-retry"


@pytest.mark.parametrize("spelling", ["dot", "relative", "symlink"])
def test_insight_writer_resolves_owner_selected_workspace(tmp_path, spelling):
    workspace, home, row = seed_legacy_insight(tmp_path)
    if spelling == "dot":
        root, cwd = ".", workspace
    elif spelling == "relative":
        root, cwd = "repo", workspace.parent
    else:
        root, cwd = tmp_path / "selected", workspace.parent
        symlink_or_skip(workspace, root, target_is_directory=True)
    path = workspace / ".aegis/proposals/trap-owner-root.md"
    code = ("import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
            "from aegis_core.insights import write_proposal; "
            "first = write_proposal(sys.argv[2], proposal_id='trap-owner-root', "
            "insight_ids=[sys.argv[3]], home=Path(sys.argv[4])); "
            "assert first == Path(sys.argv[5]); "
            "assert write_proposal(sys.argv[2], proposal_id='trap-owner-root', "
            "insight_ids=[sys.argv[3]], home=Path(sys.argv[4])) == first")
    result = subprocess.run([sys.executable, "-I", "-c", code, str(Path(__file__).resolve().parents[3]),
                             str(root), row["id"], str(home), str(path)], cwd=cwd,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert path.is_file()
    if confined_descriptor_supported():
        assert ProposalStore(workspace, home=home).read("trap-owner-root").proposal.insight_ids == (row["id"],)


@pytest.mark.parametrize("text", ["a[0][1][2]", "a" * 299 + " b", "prefix_ghp_" + "a" * 24,
    "ghp_[a][b]" + "a" * 30, "http://192.0.2.1/job?sig=hunter2",
    "https://[2001:db8::1]/job?sig=hunter2", "e\u200d\u0301", "e[0]\u0301"],
    ids=["adjacent-params", "truncated-space", "adjacent-mask", "exposed-token", "ipv4-url", "ipv6-url",
         "removed-control", "removed-parameter"])
def test_canonical_text_is_stable_across_store_and_decision_round_trips(tmp_path, text):
    store = make_store(tmp_path)
    canonical = model_module.clean_text(text, 300)
    assert model_module.clean_text(canonical, 300) == canonical
    p = candidate(labels=(text,), guidance=(text,), hypothesis=text, prediction=text, do=text)
    saved = store.write(p)
    assert saved.proposal == p
    updated = store.write(replace(saved.proposal, do="Next guidance."), expected_digest=saved.digest)
    assert updated.proposal.labels == saved.proposal.labels
    row = store.decide([p.id], decision="propose", reason=text, operation_id="op-1")
    assert row["reason"] == canonical
    assert store.state(p.id) == "needs_draft"


def test_generated_text_cleaning_and_model_round_trips_are_fixpoints():
    prefixes = ("word", "prefix_", "a " * 149, "kind 😀 ")
    endings = ("", " next", " b", " ghp_" + "a" * 24, " HTTPS://u:pass@ci.example/job?sig=hidden")
    for prefix in prefixes:
        for count in range(5):
            for ending in endings:
                groups = "".join("[" + str(number) + "]" for number in range(count))
                text = prefix + groups + ending
                for limit in (64, 120, 200, 300, 512):
                    cleaned = model_module.clean_text(text, limit)
                    assert model_module.clean_text(cleaned, limit) == cleaned
                p = candidate(kind="kind " + text, hypothesis=text, prediction=text, do=text,
                              labels=(text,), guidance=(text,), target_paths=("src/😀/**",))
                assert replace(p) == p
                assert model_module.parse_proposal(p.to_bytes(), p.id) == p


CORPUS_SEED = 1492
CORPUS_COUNT = 5000
CORPUS_BATCH_LIMIT = 250
CORPUS_LIMITS = (64, 120, 200, 300, 512)
CORPUS_PIECES = (
    "a", "[0]", "[1]", "[", "[REDACTED_IP]", "]", "x", "/", "=", ":", " ", "1",
    "ghp_", "HTTPS://example.org/a?x=y", "password=aaaa", "a@b.com", "192.0.2.1",
    "😀", "/home/me/file", "ｅｘａｍｐｌｅ", "\u200d", "\u0301",
)
_BATCH_IDS = ["batch-%02d" % index for index in range(CORPUS_COUNT // CORPUS_BATCH_LIMIT)]


def corpus_cases():
    """Historical seeded sequence: seed 1492, the same pieces, limits and lengths."""
    if CORPUS_COUNT > 5000 or not 1 <= CORPUS_BATCH_LIMIT <= 500:
        raise AssertionError("seed=%s batch=bound index=0" % CORPUS_SEED)
    rng = Random(CORPUS_SEED)
    cases = []
    for _ in range(CORPUS_COUNT):
        text = "".join(rng.choices(CORPUS_PIECES, k=rng.randrange(1, 25)))
        cases.append((text, rng.choice(CORPUS_LIMITS)))
    return cases


def corpus_batches(cases):
    if len(cases) != CORPUS_COUNT:
        raise AssertionError("seed=%s batch=union index=%s" % (CORPUS_SEED, len(cases)))
    batches = []
    start = 0
    while start < CORPUS_COUNT:
        batch = tuple(cases[start:start + CORPUS_BATCH_LIMIT])
        if not batch or len(batch) > CORPUS_BATCH_LIMIT:
            raise AssertionError("seed=%s batch=%s index=%s" % (CORPUS_SEED, len(batches), len(batch)))
        batches.append(batch)
        start += CORPUS_BATCH_LIMIT
    return tuple(batches)


_CORPUS_CASES = corpus_cases()
_CORPUS_BATCHES = corpus_batches(_CORPUS_CASES)


def _case_label(batch_index, index):
    return "seed=%s batch=%s index=%s" % (CORPUS_SEED, batch_index, index)


def _refusal_token(code):
    if (type(code) is str and 1 <= len(code) <= 32 and code.isascii()
            and all(char.isalnum() or char in "_-" for char in code)):
        return code
    return "invalid"


def _raise_labeled(label, exc):
    """Replace an operation failure with the case label and keep the cause."""
    if type(exc) is AssertionError:
        message = str(exc)
        if ("\n" not in message and "\r" not in message
                and (message == label or message.startswith(label + " code="))):
            raise exc
        raise AssertionError(label) from exc
    if type(exc) is ProposalError:
        raise AssertionError(label + " code=" + _refusal_token(exc.code)) from exc
    raise AssertionError(label) from exc


def _assert_cleaning_fixpoint(batch_index, index, text, limit, *, plant=False, replaced_by=None):
    label = _case_label(batch_index, index)
    try:
        cleaned = model_module.clean_text(text, limit)
        again = model_module.clean_text(cleaned, limit)
        proposal = candidate(hypothesis=text, prediction=text, do=text, labels=(text,), guidance=(text,))
        parsed = model_module.parse_proposal(proposal.to_bytes(), proposal.id)
        replaced = replace(proposal) if replaced_by is None else replaced_by(proposal)
        if plant:
            raise AssertionError(label)
        if again != cleaned or replaced != proposal or parsed != proposal:
            raise AssertionError(label)
    except Exception as exc:
        _raise_labeled(label, exc)


@pytest.mark.parametrize("batch_index", range(len(_CORPUS_BATCHES)), ids=_BATCH_IDS)
def test_generated_truncation_boundaries_are_cleaning_fixpoints(batch_index):
    batch = _CORPUS_BATCHES[batch_index]
    assert len(batch) <= CORPUS_BATCH_LIMIT
    for index, (text, limit) in enumerate(batch):
        _assert_cleaning_fixpoint(batch_index, index, text, limit)


def test_corpus_batches_union_equals_seeded_sequence():
    rng = Random(1492)
    pieces = ("a", "[0]", "[1]", "[", "[REDACTED_IP]", "]", "x", "/", "=", ":", " ", "1",
              "ghp_", "HTTPS://example.org/a?x=y", "password=aaaa", "a@b.com", "192.0.2.1",
              "😀", "/home/me/file", "ｅｘａｍｐｌｅ", "\u200d", "\u0301")
    limits = (64, 120, 200, 300, 512)
    original = []
    for _ in range(5000):
        text = "".join(rng.choices(pieces, k=rng.randrange(1, 25)))
        original.append((text, rng.choice(limits)))
    assert pieces == CORPUS_PIECES and limits == CORPUS_LIMITS
    assert (CORPUS_SEED, CORPUS_COUNT, CORPUS_BATCH_LIMIT) == (1492, 5000, 250)
    flat = [case for batch in _CORPUS_BATCHES for case in batch]
    assert len(flat) == len(original) == len(_CORPUS_CASES) == 5000
    for index, case in enumerate(original):
        if flat[index] != case or _CORPUS_CASES[index] != case:
            raise AssertionError("seed=1492 batch=union index=%s" % index)
    assert [len(batch) for batch in _CORPUS_BATCHES] == [250] * 20


@pytest.mark.parametrize("slot", ["first", "last", "planted"])
@pytest.mark.parametrize("batch_index", range(len(_CORPUS_BATCHES)), ids=_BATCH_IDS)
def test_corpus_failure_names_seed_batch_and_index(batch_index, slot):
    batch = _CORPUS_BATCHES[batch_index]
    index = {"first": 0, "last": len(batch) - 1, "planted": 1}[slot]
    text, limit = batch[index]
    with pytest.raises(AssertionError) as caught:
        _assert_cleaning_fixpoint(batch_index, index, text, limit, plant=True)
    message = str(caught.value)
    assert message == _case_label(batch_index, index)
    assert "\n" not in message and "\r" not in message


def test_corpus_unexpected_failure_names_seed_batch_and_index(monkeypatch):
    """An exception from a wrapped case operation keeps the label and the cause."""
    def boom(text, limit):
        raise RuntimeError("secret\ncase")

    monkeypatch.setattr(model_module, "clean_text", boom)
    with pytest.raises(AssertionError) as caught:
        _assert_cleaning_fixpoint(0, 0, "a", 64)
    message = str(caught.value)
    assert message == _case_label(0, 0)
    assert "\n" not in message and "\r" not in message and "secret" not in message
    assert type(caught.value.__cause__) is RuntimeError


def test_corpus_replace_refusal_names_seed_batch_and_index():
    """ProposalError from the wrapped replace call stays inside the labeled boundary."""
    def broken(proposal):
        raise ProposalError("stale")

    with pytest.raises(AssertionError) as caught:
        _assert_cleaning_fixpoint(0, 3, "a", 64, replaced_by=broken)
    message = str(caught.value)
    assert message == _case_label(0, 3) + " code=stale"
    assert "\n" not in message and "\r" not in message
    assert type(caught.value.__cause__) is ProposalError


def test_decision_directory_entry_limit_refuses_before_new_publication(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    store.write(candidate())
    store.decide(["mine-example"], decision="propose", operation_id="op-1")
    directory = store.root / ".aegis/proposals/decisions"
    (directory / "unrelated").write_text("keep")
    monkeypatch.setattr(store_module, "MAX_ROWS", 2)
    before = snapshot(tmp_path)
    with refusal("too_large"):
        store.decide(["mine-example"], decision="confirm", operation_id="op-2")
    assert snapshot(tmp_path) == before
    assert store.state("mine-example") == "needs_draft"


_STRING_FIELDS = ("id", "source", "kind", "candidate_key", "status", "type", "enforcement",
                  "amends", "hypothesis", "prediction", "do")
_SEQUENCE_FIELDS = ("evidence_ids", "target_paths", "parent_proposals", "source_lineage",
                    "insight_ids", "labels", "guidance")
_METADATA_FIELDS = _STRING_FIELDS[:-1] + ("revision",) + _SEQUENCE_FIELDS[:-2]


@pytest.mark.parametrize("field", _STRING_FIELDS)
@pytest.mark.parametrize("bad", [None, [], 0, b"opaque"], ids=["none", "list", "number", "bytes"])
def test_proposal_constructor_refuses_wrong_scalar_types(field, bad):
    with refusal("invalid"):
        replace(candidate(), **{field: bad})


@pytest.mark.parametrize("field", _SEQUENCE_FIELDS)
@pytest.mark.parametrize("bad", [None, [[None]], 0, b"opaque"], ids=["none", "nested-list", "number", "bytes"])
def test_proposal_constructor_refuses_wrong_collection_types(field, bad):
    with refusal("invalid"):
        replace(candidate(), **{field: bad})


@pytest.mark.parametrize("bad", [None, [], 1.5, b"opaque"], ids=["none", "list", "number", "bytes"])
def test_proposal_constructor_refuses_wrong_revision_type(bad):
    with refusal("invalid"):
        replace(candidate(), revision=bad)


def proposal_with_metadata(field, bad):
    lines = candidate().to_bytes().decode().splitlines()
    start = next(index for index, line in enumerate(lines) if line.startswith(field + ":"))
    end = start + 1
    while end < len(lines) and lines[end].startswith("  - "):
        end += 1
    lines[start:end] = [field + ": " + json.dumps(bad)]
    return ("\n".join(lines) + "\n").encode()


@pytest.mark.parametrize("field", _METADATA_FIELDS + ("count",))
@pytest.mark.parametrize("bad", [None, [], 0, {}], ids=["none", "list", "number", "mapping"])
def test_proposal_parser_refuses_wrong_metadata_types(field, bad):
    # A list is a valid collection spelling; reject its malformed member instead.
    value = [None] if field in _SEQUENCE_FIELDS and bad == [] else bad
    with refusal("invalid"):
        model_module.parse_proposal(proposal_with_metadata(field, value), "mine-example")


@pytest.mark.parametrize("bad", [None, [], 0, {}], ids=["none", "list", "number", "mapping"])
def test_proposal_parser_refuses_wrong_evidence_label_type(bad):
    raw = candidate().to_bytes() + ("- label (untrusted data): " + json.dumps(bad) + "\n").encode()
    with refusal("invalid"):
        model_module.parse_proposal(raw, "mine-example")


@pytest.mark.parametrize("bad", [None, [], 0, b"opaque"], ids=["none", "list", "number", "bytes"])
def test_proposal_parser_refuses_wrong_expected_identity_type(bad):
    with refusal("invalid"):
        model_module.parse_proposal(candidate().to_bytes(), bad)


@pytest.mark.parametrize("raw", [b"not frontmatter", b"---\nunterminated", b"\xff",
                                  b"---\n[]\n---\n## Do\n\n## Evidence\n",
                                  b"---\nnull\n---\n## Do\n\n## Evidence\n"],
                         ids=["absent", "unterminated", "invalid-utf8", "list", "none"])
def test_proposal_parser_refuses_absent_or_wrong_mapping(raw):
    with refusal("invalid"):
        model_module.parse_proposal(raw, "mine-example")


_ROW_FIELDS = ("v", "ts", "event", "decision", "proposal_ids", "revisions", "evidence_ids",
               "operation_id", "reason", "rule_id", "rule_digest", "until", "insight_ids")


@pytest.mark.parametrize("field", _ROW_FIELDS)
@pytest.mark.parametrize("bad", [None, [], 0, {}], ids=["none", "list", "number", "mapping"])
def test_stored_decision_refuses_wrong_field_types_and_retries(tmp_path, field, bad):
    store = make_store(tmp_path)
    store.write(candidate())
    row = store.decide(["mine-example"], decision="propose", operation_id="op-1")
    path, = (store.root / ".aegis/proposals/decisions").glob("*.json")
    original = path.read_bytes()
    if field == "until":
        row["decision"] = "snooze"
    row[field] = [None] if field in ("proposal_ids", "evidence_ids", "insight_ids") and bad == [] else bad
    path.write_text(json.dumps(row))
    before = snapshot(tmp_path)
    with refusal("decision"):
        store.state("mine-example")
    assert snapshot(tmp_path) == before
    path.write_bytes(original)
    assert store.state("mine-example") == "needs_draft"


@pytest.mark.parametrize("raw", [b"null", b"[]", b"0", b"\xff"], ids=["none", "list", "number", "bytes"])
def test_stored_decision_refuses_wrong_mapping_type(tmp_path, raw):
    store = make_store(tmp_path)
    store.write(candidate())
    store.decide(["mine-example"], decision="propose", operation_id="op-1")
    path, = (store.root / ".aegis/proposals/decisions").glob("*.json")
    path.write_bytes(raw)
    with refusal("decision"):
        store.state("mine-example")


@pytest.mark.parametrize("field,code", [("decision", "decision"), ("proposal_ids", "invalid"),
    ("operation_id", "invalid"), ("reason", "invalid"), ("rule_id", "invalid"),
    ("rule_digest", "decision"), ("until", "decision")])
def test_decision_api_refuses_byte_values_before_publication(tmp_path, field, code):
    store = make_store(tmp_path)
    store.write(candidate())
    before = snapshot(tmp_path)
    kwargs = {"decision": "snooze" if field == "until" else "propose", "operation_id": "op-1"}
    ids = b"opaque" if field == "proposal_ids" else ["mine-example"]
    if field != "proposal_ids":
        kwargs[field] = b"opaque"
    with refusal(code):
        store.decide(ids, **kwargs)
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("kind", ["proposal", "decision"])
def test_malformed_types_refuse_for_concurrent_readers_then_retry(tmp_path, kind):
    store = make_store(tmp_path)
    saved = store.write(candidate())
    if kind == "proposal":
        path = store.root / ".aegis/proposals/mine-example.md"
        malformed = proposal_with_metadata("source", None)
        code = "invalid"
    else:
        row = store.decide(["mine-example"], decision="propose", operation_id="op-1")
        path, = (store.root / ".aegis/proposals/decisions").glob("*.json")
        row["ts"] = None
        malformed = json.dumps(row).encode()
        code = "decision"
    original = path.read_bytes()
    path.write_bytes(malformed)
    before = snapshot(tmp_path)

    def read(_):
        with refusal(code):
            return store.read("mine-example") if kind == "proposal" else store.state("mine-example")

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(read, range(3))) == [None] * 3
    assert snapshot(tmp_path) == before
    path.write_bytes(original)
    assert store.read("mine-example") == saved
    assert store.state("mine-example") == "needs_draft"


_ATOMIC_MARKERS = ("[REDACTED]", "[REDACTED_IP]", "[REDACTED_EMAIL]", "[REDACTED_PEM]",
                   "[REDACTED_URL]", "[REDACTED_HIENT]")


def complete_snapshot(root):
    return snapshot(root), tuple(sorted(p.relative_to(root).as_posix() for p in root.rglob("*")))


@pytest.mark.parametrize("text", ["Keep timeout in range[0, 30) seconds",
                                 "Reject raw slice items[1: without bounds"])
def test_unmatched_parameter_brackets_preserve_literal_text_in_every_field(tmp_path, text):
    p = candidate(kind=text, hypothesis=text, prediction=text, do=text, labels=(text,), guidance=(text,))
    assert (p.kind, p.hypothesis, p.prediction, p.do, p.labels[0], p.guidance[0]) == (text,) * 6
    assert model_module.parse_proposal(p.to_bytes(), p.id) == p
    store = make_store(tmp_path)
    assert store.write(p).proposal == p
    row = store.decide([p.id], decision="propose", operation_id="op-literal-bracket", reason=text)
    assert row["reason"] == text


def test_real_redaction_at_the_kind_boundary_is_atomic():
    text = "x" * 58 + " 192.0.2.1"
    assert model_module.clean_text(text, 64) == "x" * 58
    assert candidate(kind=text).kind == "x" * 58


def test_proposal_text_keeps_integration_tip_escape_clipping_goldens():
    """Moving the cleaner preserves literal escape prefixes at every cut."""
    samples = (("abcd\\x41efgh", 4), ("abcd\\u0041ef", 6), ("abcd\\U00000041ef", 10))
    for text, atom in samples:
        start = text.index("\\")
        end = start + atom
        for limit in range(start + 1, end):
            clipped = model_module.clean_text(text, limit)
            assert clipped == text[:limit]
            assert model_module.clean_text(clipped, limit) == clipped
        whole = model_module.clean_text(text, end)
        assert whole == text[:end]
        assert model_module.clean_text(whole, end) == whole


@pytest.mark.parametrize("text,limit,expected", [
    ("https://[2001:db8::1]/job?sig=hidden", 3, "htt"),
    ("https://[2001:db8::1]/job?sig=hidden", 64, "https://[2001:db8::1]/job"),
    ("https://[2001:db8::1]/job?sig=hidden", 17, ""),
    ("https://[2001:db8::1]:443/job?sig=hidden", 64, "https://[2001:db8::1]:443/job"),
], ids=["short-scheme", "ipv6", "inside-ipv6", "ipv6-port"])
def test_proposal_url_authority_keeps_integration_tip_goldens(text, limit, expected):
    assert model_module.clean_text(text, limit) == expected
    assert model_module.clean_text(expected, limit) == expected


def test_shared_cleaner_matches_proposal_goldens_and_refuses_without_echo():
    """Any-scheme URLs, trailing spaces and mask edges stay stable; failures do not publish."""
    from aegis_core.redaction import (
        REDACTION_MARKER_RE, RedactionRefusal, clip_atomic_text, remove_url_credentials,
    )

    for scheme in ("ftp", "SSH", "git", "s3", "Custom+v1", "HTTPS"):
        raw = scheme + "://u:pass@ci.example/path?sig=hidden#private"
        assert remove_url_credentials(raw, limit=300) == scheme + "://ci.example/path"
        assert model_module.clean_text(raw) == scheme.lower() + "://ci.example/path"
        assert "pass" not in model_module.clean_text(raw) and "hidden" not in model_module.clean_text(raw)
    assert model_module.clean_text("a" * 63 + " ", 64) == "a" * 63
    assert clip_atomic_text("a" * 63 + " ", 64) == "a" * 63
    marker = "[REDACTED_IP]"
    text = "x" * 10 + marker + " tail"
    start = text.index(marker)
    for limit in range(start + 1, start + len(marker)):
        clipped = clip_atomic_text(text, limit)
        assert clipped == "x" * 10
        assert "[REDACTED" not in clipped
        assert REDACTION_MARKER_RE.fullmatch(marker)
    assert clip_atomic_text("a\nb", 10) == "a\nb"
    secret = "hunter2"
    try:
        remove_url_credentials("https://user:" + secret + "@h/p?" + secret, limit=0)
    except RedactionRefusal as denied:
        assert denied.code == "too_large"
        assert secret not in str(denied) and "https://" not in str(denied)
    else:
        raise AssertionError("oversized URL stream was returned")
    for bad in (None, b"text", 1, ["text"]):
        try:
            remove_url_credentials(bad, limit=32)
        except RedactionRefusal as denied:
            assert denied.code == "invalid" and str(denied) == "invalid"
        else:
            raise AssertionError("malformed input was cleaned")
    try:
        clip_atomic_text("ok", -1)
    except RedactionRefusal as denied:
        assert denied.code == "invalid" and "ok" not in str(denied)
    else:
        raise AssertionError("negative clip limit was accepted")
    expanding = " ".join(["https://["] * 300)
    try:
        remove_url_credentials(expanding, limit=model_module.MAX_TEXT)
    except RedactionRefusal as denied:
        assert denied.code == "too_large" and "https://[" not in str(denied)
    else:
        raise AssertionError("expanding URL stream was returned")
    assert remove_url_credentials("https://h/p", limit=model_module.MAX_TEXT) == "https://h/p"
    with refusal("too_large"):
        model_module.clean_text(expanding)
    assert model_module.clean_text("https://h/p") == "https://h/p"

    def once(index):
        cleaned = remove_url_credentials("ftp://u:pass@h/p?q=1", limit=100)
        clipped = clip_atomic_text("x" * 10 + "[REDACTED_URL] tail", 12)
        return index, cleaned, clipped

    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(once, range(8)))
    assert rows == [(index, "ftp://h/p", "x" * 10) for index in range(8)]


def test_expanding_url_credentials_refuse_before_proposal_publication(tmp_path):
    store = make_store(tmp_path)
    before = snapshot(tmp_path)
    expanding = " ".join(["https://["] * 300)
    with refusal("too_large"):
        candidate(hypothesis=expanding)
    assert snapshot(tmp_path) == before
    saved = store.write(candidate())
    after = snapshot(tmp_path)
    with refusal("too_large"):
        store.write(candidate(hypothesis=expanding))
    assert snapshot(tmp_path) == after
    assert store.read(saved.proposal.id) == saved


_GUIDANCE_MASK_GOLDENS = (
    ("HTTPS://u:pass@ci.example/path?sig=hidden#private",
     "HTTPS://u:[REDACTED]@ci.example/path#private"),
    ("ftp://u:pass@ci.example/path?sig=hidden#private",
     "ftp://u:[REDACTED]@ci.example/path#private"),
    ("SSH://u:pass@ci.example/path?sig=hidden#private",
     "SSH://u:[REDACTED]@ci.example/path#private"),
    ("git://u:pass@ci.example/path?sig=hidden#private",
     "git://u:[REDACTED]@ci.example/path#private"),
    ("s3://u:pass@ci.example/path?sig=hidden#private",
     "s3://u:[REDACTED]@ci.example/path#private"),
    ("Custom+v1://u:pass@ci.example/path?sig=hidden#private",
     "Custom+v1://u:[REDACTED]@ci.example/path#private"),
    ("http://192.0.2.1", "http://192.0.2.1"),
    ("https://ci.example/job?sig=(hunter2)", "[REDACTED_URL]"),
    ("redis://:hunter2@localhost/0", "redis://:[REDACTED]@localhost/0"),
    ("token=[REDACTED]", "token=REDACTED"),
)


def test_guidance_projection_keeps_its_recorded_masks_for_the_same_inputs():
    """Guidance's named URL policy preserves its recorded masks and structure."""
    from aegis_core.guidance_projection import (
        GuidanceProjectionError, redact_clean_text, project_display_text,
    )

    for text, expected in _GUIDANCE_MASK_GOLDENS:
        assert redact_clean_text(text) == expected
        assert project_display_text(text, 300) == expected
    shown = "x" * 58 + " 192.0.2.1"
    assert project_display_text(shown, 64) == "x" * 58 + " 19..."
    payload = "Z" * (1024 * 1024 + 1)
    with pytest.raises(GuidanceProjectionError) as failure:
        redact_clean_text(payload)
    assert failure.value.code == "guidance_projection_limit"
    assert "Z" not in str(failure.value)


def test_generated_parameter_grammar_preserves_literals_at_every_clip_boundary():
    rng = Random(1835)
    for index in range(96):
        word = rng.choice(("range", "items", "value", "check_"))
        depth = rng.randrange(1, 6)
        group = "[parameter]"
        for _ in range(depth):
            group = "[outer" + group + "tail]"
        marker, last = rng.sample(_ATOMIC_MARKERS, 2)
        if index % 4 == 0:
            text, expected = word + group * 2 + " tail", word + " tail"
        elif index % 4 == 1:
            literal = word + "[" * depth + " inner"
            text, expected = literal + group + " tail", literal + " tail"
        elif index % 4 == 2:
            text = expected = word + "[0, 30) seconds [literal] tail"
        else:
            text = expected = word + "] unmatched [ tail"
        text = marker + " " + text + " " + last
        expected = marker + " " + expected + " " + last
        # The generator records which groups are parameters; all other text is
        # literal. Equality here proves preservation, beyond mere idempotence.
        assert model_module.clean_text(text, 4096) == expected
        spans = [(expected.index(tag), expected.index(tag) + len(tag)) for tag in (marker, last)]
        for boundary in range(len(expected) + 1):
            end = next((start for start, stop in spans if start < boundary < stop), boundary)
            clipped = expected[:end].rstrip()
            assert model_module.clean_text(text, boundary) == clipped
            assert model_module.clean_text(clipped, boundary) == clipped


@pytest.mark.parametrize("field,limit", [("kind", 64), ("labels", 120), ("guidance", 200),
                                        ("hypothesis", 300), ("prediction", 300), ("do", 300)])
def test_every_bounded_field_clips_redaction_markers_as_atoms(field, limit):
    for marker in _ATOMIC_MARKERS:
        for offset in range(len(marker) + 1):
            prefix = "x" * (limit - offset - 1) + " "
            text = prefix + marker + " tail"
            expected = (prefix + marker if offset == len(marker) else prefix).rstrip()
            value = (text,) if field in ("labels", "guidance") else text
            p = candidate(**{field: value})
            actual = {"kind": p.kind, "labels": p.labels, "guidance": p.guidance,
                      "hypothesis": p.hypothesis, "prediction": p.prediction, "do": p.do}[field]
            assert actual == ((expected,) if field in ("labels", "guidance") else expected)
            assert model_module.parse_proposal(p.to_bytes(), p.id) == p


@pytest.mark.parametrize("until", [b"", "", 0, False, [], {}],
                         ids=["bytes", "empty", "zero", "false", "list", "mapping"])
@pytest.mark.parametrize("existing", [False, True], ids=["uninitialized", "existing"])
def test_falsy_snooze_dates_refuse_before_filesystem_effects(tmp_path, until, existing):
    store = make_store(tmp_path)
    if existing:
        store.write(candidate())
    before = complete_snapshot(tmp_path)
    with refusal("decision"):
        store.decide(["mine-example"], decision="snooze", operation_id="op-falsy-date", until=until)
    assert complete_snapshot(tmp_path) == before
    if not existing:
        assert not (store.root / ".aegis").exists()


@pytest.mark.parametrize("reason", ["", "   ", "\u200b" * 32], ids=["empty", "spaces", "format"])
@pytest.mark.parametrize("decision", ["propose", "reject", "snooze", "merge-into-rule", "noise", "confirm", "accept"])
@pytest.mark.parametrize("existing", [False, True], ids=["uninitialized", "existing"])
def test_blank_reasons_refuse_before_filesystem_effects(tmp_path, reason, decision, existing):
    store = make_store(tmp_path)
    if existing:
        store.write(candidate())
    before = complete_snapshot(tmp_path)
    with refusal("reason"):
        store.decide(["mine-example"], decision=decision, operation_id="op-blank-reason", reason=reason)
    assert complete_snapshot(tmp_path) == before
    if not existing:
        assert not (store.root / ".aegis").exists()


@pytest.mark.parametrize("reason", [b"", 0, False, [], {}],
                         ids=["bytes", "zero", "false", "list", "mapping"])
def test_falsy_wrong_reason_types_refuse_before_filesystem_effects(tmp_path, reason):
    store = make_store(tmp_path)
    before = complete_snapshot(tmp_path)
    with refusal("invalid"):
        store.decide(["mine-example"], decision="propose", operation_id="op-wrong-reason", reason=reason)
    assert complete_snapshot(tmp_path) == before
    assert not (store.root / ".aegis").exists()


@pytest.mark.parametrize("kind", [b"", 0, False, [], {}, b"release", 1, True,
                                 "release\nnext", "release\rnext", "release\r\nnext"],
                         ids=["bytes", "zero", "false", "list", "mapping", "nonempty-bytes", "one", "true",
                              "newline", "carriage-return", "crlf"])
@pytest.mark.parametrize("supported", [False, True], ids=["unsupported", "supported"])
def test_invalid_insight_kinds_refuse_before_filesystem_effects(tmp_path, monkeypatch, kind, supported):
    if supported:
        store = make_store(tmp_path)
        root, home = store.root, store.home
        row = add_insight(root, "Keep proposal input checks explicit.", paths=["src/app.py"],
                          kind="release", home=home)
    else:
        root, home, row = seed_legacy_insight(tmp_path)
        monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    before = complete_snapshot(tmp_path)
    with refusal("invalid"):
        write_proposal(root, proposal_id="trap-invalid-kind", insight_ids=[row["id"]], kind=kind, home=home)
    assert complete_snapshot(tmp_path) == before
    assert not (root / ".aegis").exists()


@pytest.mark.parametrize("data", [None, [], 0, {}, "str", False, bytearray()],
                         ids=["none", "list", "zero", "mapping", "string", "false", "bytearray"])
def test_proposal_parser_wrong_input_types_refuse_invalid(data):
    with refusal("invalid"):
        model_module.parse_proposal(data, "mine-example")


@pytest.mark.parametrize("limit", [None, [], 0.5, {}, "64", False, -1],
                         ids=["none", "list", "float", "mapping", "string", "false", "negative"])
def test_text_clip_limits_refuse_invalid_types_and_negative_values(limit):
    with refusal("invalid"):
        model_module.clean_text("Keep the literal text.", limit)


def _worker_outcomes(report, count):
    import multiprocessing

    assert report.timed_out is False
    assert report.forced is False
    assert report.exitcodes == (0,) * count
    assert len(report.results) == count
    found = {}
    for worker, status, code in report.results:
        assert worker not in found
        assert "\n" not in worker and "\n" not in status and "\n" not in code
        assert "\r" not in worker and "\r" not in status and "\r" not in code
        found[worker] = (status, code)
    assert all(status != "error" for status, _code in found.values())
    live = {proc.pid for proc in multiprocessing.active_children()}
    assert not (set(report.pids) & live)
    return found


def _insight(pid):
    return candidate(pid, source="insight", source_lineage=("insight",), insight_ids=("ins-aaaaaaaaaaaa",))


def _log_rows(home):
    logs = [path for path in home.rglob("*.jsonl") if path.is_file() and not path.is_symlink()]
    assert len(logs) == 1
    return logs[0], [json.loads(line) for line in logs[0].read_text().splitlines() if line]


def test_process_compare_replace_has_one_winner(tmp_path):
    store = make_store(tmp_path)
    saved = store.write(candidate())
    root, home = str(store.root), str(store.home)
    texts = {"a": "First guidance.", "b": "Second guidance."}
    report = helpers_proposal_workers.run_workers([
        (helpers_proposal_workers.compare_replace,
         (root, home, saved.proposal.id, saved.digest, texts["a"], "a")),
        (helpers_proposal_workers.compare_replace,
         (root, home, saved.proposal.id, saved.digest, texts["b"], "b")),
    ], timeout=60)
    outcomes = _worker_outcomes(report, 2)
    winners = [worker for worker, (status, _code) in outcomes.items() if status == "written"]
    losers = [worker for worker, (status, _code) in outcomes.items() if status == "refused"]
    assert len(winners) == 1 and len(losers) == 1
    assert outcomes[losers[0]] == ("refused", "stale")
    current = store.read(saved.proposal.id)
    assert current.proposal.do == texts[winners[0]]
    assert [item.proposal.id for item in store.list()] == [saved.proposal.id]
    before = snapshot(tmp_path)
    assert store.write(current.proposal) == current
    with refusal("stale"):
        store.write(replace(saved.proposal, do=texts[losers[0]]), expected_digest=saved.digest)
    assert snapshot(tmp_path) == before


def test_process_private_quota_has_one_winner_and_too_large(tmp_path, monkeypatch):
    first, second = shared_worktree_stores(tmp_path)
    first.write(_insight("ins-first"))
    second.write(_insight("ins-second"))
    first.decide(["ins-first"], decision="propose", operation_id="op-seed")
    report = helpers_proposal_workers.run_workers([
        (helpers_proposal_workers.decide,
         (str(first.root), str(first.home), "ins-first", "op-first", "confirm", 2, "a")),
        (helpers_proposal_workers.decide,
         (str(second.root), str(second.home), "ins-second", "op-second", "confirm", 2, "b")),
    ], timeout=60)
    outcomes = _worker_outcomes(report, 2)
    winners = [worker for worker, (status, _code) in outcomes.items() if status == "written"]
    losers = [worker for worker, (status, _code) in outcomes.items() if status == "refused"]
    assert len(winners) == 1 and len(losers) == 1
    winner_op = {"a": "op-first", "b": "op-second"}[winners[0]]
    loser_op = {"a": "op-first", "b": "op-second"}[losers[0]]
    assert outcomes[winners[0]] == ("written", winner_op)
    assert outcomes[losers[0]] == ("refused", "too_large")
    _log, rows = _log_rows(first.home)
    assert {row["operation_id"] for row in rows} == {"op-seed", winner_op}
    assert len(rows) == 2
    assert first.read("ins-first").proposal.id == "ins-first"
    assert second.read("ins-second").proposal.id == "ins-second"
    monkeypatch.setattr(store_module, "MAX_ROWS", 2)
    before = snapshot(tmp_path)
    winner_store, winner_id = (first, "ins-first") if winners[0] == "a" else (second, "ins-second")
    loser_store, loser_id = (second, "ins-second") if winners[0] == "a" else (first, "ins-first")
    assert winner_store.decide([winner_id], decision="confirm", operation_id=winner_op)["operation_id"] == winner_op
    with refusal("too_large"):
        loser_store.decide([loser_id], decision="confirm", operation_id=loser_op)
    assert snapshot(tmp_path) == before
    assert first.state("ins-first") == second.state("ins-second") == "needs_draft"


def test_process_concurrent_identical_publication_is_one_row(tmp_path):
    """Two processes publishing one new operation leave a single readable row."""
    store = make_store(tmp_path)
    proposal = _insight("ins-race")
    store.write(proposal)
    root, home = str(store.root), str(store.home)
    report = helpers_proposal_workers.run_workers([
        (helpers_proposal_workers.decide, (root, home, proposal.id, "op-race", "propose", None, "a")),
        (helpers_proposal_workers.decide, (root, home, proposal.id, "op-race", "propose", None, "b")),
    ], timeout=60)
    outcomes = _worker_outcomes(report, 2)
    assert outcomes == {"a": ("written", "op-race"), "b": ("written", "op-race")}
    _log, rows = _log_rows(store.home)
    assert len(rows) == 1 and rows[0]["operation_id"] == "op-race" and rows[0]["decision"] == "propose"
    assert store.read(proposal.id).proposal == proposal
    assert store.state(proposal.id) == "needs_draft"


def test_process_identical_retry_is_byte_identical(tmp_path):
    """Retries of an older seeded operation leave the captured snapshot unchanged."""
    import time

    from aegis_core.primitives import utc_stamp

    store = make_store(tmp_path)
    proposal = _insight("ins-retry")
    store.write(proposal)
    seeded = store.decide([proposal.id], decision="propose", operation_id="op-retry")
    deadline = time.monotonic() + 3
    while utc_stamp() == seeded["ts"]:
        if time.monotonic() >= deadline:
            raise AssertionError("seed=1492 batch=retry index=0")
        time.sleep(0.05)
    before = snapshot(tmp_path)
    log, rows = _log_rows(store.home)
    assert len(rows) == 1 and rows[0]["operation_id"] == "op-retry" and rows[0]["ts"] == seeded["ts"]
    root, home = str(store.root), str(store.home)
    report = helpers_proposal_workers.run_workers([
        (helpers_proposal_workers.decide, (root, home, proposal.id, "op-retry", "propose", None, "a")),
        (helpers_proposal_workers.decide, (root, home, proposal.id, "op-retry", "propose", None, "b")),
    ], timeout=60)
    outcomes = _worker_outcomes(report, 2)
    assert outcomes == {"a": ("written", "op-retry"), "b": ("written", "op-retry")}
    assert snapshot(tmp_path) == before
    assert log.read_bytes() == before[log.relative_to(tmp_path).as_posix()]
    assert store.decide([proposal.id], decision="propose", operation_id="op-retry")["operation_id"] == "op-retry"
    assert snapshot(tmp_path) == before
    assert store.read(proposal.id).proposal == proposal
    assert store.state(proposal.id) == "needs_draft"


@pytest.mark.parametrize("private", [False, True], ids=["public", "private"])
def test_process_shared_log_lock_timeout_refuses_without_mutation(tmp_path, private):
    first, second = shared_worktree_stores(tmp_path)
    first.write(_insight("ins-first"))
    first.decide(["ins-first"], decision="propose", operation_id="op-seed")
    proposal = _insight("ins-second") if private else candidate("mine-second")
    second.write(proposal)
    lock_path = str(insights_path(first.root, home=first.home).with_suffix(".lock"))
    before = snapshot(tmp_path)
    context = helpers_proposal_workers.worker_context()
    ready = context.Event()
    done = context.Event()
    report = helpers_proposal_workers.run_workers([
        (helpers_proposal_workers.hold_shared_lock,
         (str(first.root), str(first.home), lock_path, ready, done, "holder")),
        (helpers_proposal_workers.decide_locked,
         (str(second.root), str(second.home), proposal.id, "op-retry", "propose", 0.25, ready, done, "waiter")),
    ], timeout=30, context=context)
    outcomes = _worker_outcomes(report, 2)
    assert outcomes["holder"] == ("released", "")
    assert outcomes["waiter"] == ("refused", "timeout")
    assert snapshot(tmp_path) == before
    assert second.decide([proposal.id], decision="propose", operation_id="op-retry")["operation_id"] == "op-retry"
    after = snapshot(tmp_path)
    assert second.decide([proposal.id], decision="propose", operation_id="op-retry")["operation_id"] == "op-retry"
    assert snapshot(tmp_path) == after
    assert second.read(proposal.id).proposal.id == proposal.id


def _reaped(report):
    import multiprocessing

    live = {proc.pid for proc in multiprocessing.active_children()}
    assert report.pids and not (set(report.pids) & live)


def test_hung_proposal_worker_is_terminated_and_reaped():
    report = helpers_proposal_workers.run_workers([
        (helpers_proposal_workers.hang, ("sleeper",)),
    ], timeout=5)
    assert report.timed_out is True
    assert report.forced is True
    assert report.results == ()
    assert report.exitcodes != (0,)
    assert len(report.exitcodes) == 1 and report.exitcodes[0] not in (None, 0)
    _reaped(report)
    with pytest.raises(AssertionError):
        _worker_outcomes(report, 1)


def test_reported_then_crashed_worker_is_not_a_successful_exit():
    report = helpers_proposal_workers.run_workers([
        (helpers_proposal_workers.report_then_crash, ("crasher",)),
    ], timeout=15)
    assert report.timed_out is False
    assert report.forced is False
    assert report.results == (("crasher", "written", ""),)
    assert report.exitcodes == (1,)
    _reaped(report)
    with pytest.raises(AssertionError):
        _worker_outcomes(report, 1)


def test_reported_then_hung_worker_is_forced_cleanup():
    report = helpers_proposal_workers.run_workers([
        (helpers_proposal_workers.report_then_hang, ("linger",)),
    ], timeout=15)
    assert report.timed_out is False
    assert report.forced is True
    assert report.results == (("linger", "written", ""),)
    assert len(report.exitcodes) == 1 and report.exitcodes[0] not in (None, 0)
    _reaped(report)
    with pytest.raises(AssertionError):
        _worker_outcomes(report, 1)


def test_spawned_worker_reports_unsupported_when_the_probe_is_false(tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    root = tmp_path / "repo"
    home = tmp_path / "home"
    root.mkdir()
    home.mkdir()
    box = []

    class Barrier:
        def wait(self, timeout=None):
            return 0

    class Results:
        def put(self, item):
            box.append(item)

    helpers_proposal_workers.compare_replace(
        str(root), str(home), "mine-example", "ab" * 32, "Next guidance.", "worker", Barrier(), Results())
    assert box == [("worker", "refused", "unsupported")]
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("text", ["First\nSecond", "First\rSecond", "First\r\nSecond"], ids=["lf", "cr", "crlf"])
def test_worker_refuses_multiline_replacement_before_publication(tmp_path, text):
    root = tmp_path / "repo"
    home = tmp_path / "home"
    root.mkdir()
    home.mkdir()
    box = []

    class Barrier:
        def wait(self, timeout=None):
            return 0

    class Results:
        def put(self, item):
            box.append(item)

    helpers_proposal_workers.compare_replace(
        str(root), str(home), "mine-example", "ab" * 32, text, "worker", Barrier(), Results())
    assert box == [("worker", "refused", "invalid")]
    assert list(root.iterdir()) == []
