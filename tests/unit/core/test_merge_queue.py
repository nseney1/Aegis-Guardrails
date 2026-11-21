"""Serial queue contracts using test-owned history and real qualification records."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, replace
from itertools import permutations, product
import json
import os
from pathlib import Path
import pickle
import shutil
from threading import Barrier
from types import SimpleNamespace

import pytest

from aegis_core import gitsafe_run, merge_queue as mq, merge_queue_types, team_gitops, team_qualify as qual
from tests.helpers_team_git import (
    IDENTITY, commit, copy_immutable_repo, filter_git_env, git, make_store, shared_bytes, state,
)


class StateBackend:
    """Atomic owner-storage boundary retained across queue instances in tests."""

    def __init__(self):
        self.state = None
        self.lanes, self.commits = {}, {}
        self.fail = None
        self.healths = {}
        self.dirty = False
        self.pending = {}

    def load(self, target):
        if self.state is None:
            assert not self.dirty
            return None
        state = self.state
        health = self.healths.get(state.health_commit, state.health_result)
        issued = state.issued
        if issued is not None:
            issued = replace(issued, result=self.healths.get(issued.landing.commit, issued.result))
        cleanup = state.cleanup
        if cleanup is not None:
            cleanup = replace(cleanup, result=self.healths.get(cleanup.landing.commit, cleanup.result))
        results = state.results
        if self.pending:
            if type(results) is not tuple or len(results) > mq.MAX_REPLAY_RESULTS:
                raise OSError("invalid checkpoint result bounds")
            replayed = {row.commit: row for row in results}
            if len(replayed) != len(results):
                raise OSError("invalid checkpoint result bindings")
            for oid in self.pending:
                if (oid != state.health_commit and (issued is None or oid != issued.landing.commit)
                        and (cleanup is None or oid != cleanup.landing.commit)):
                    replayed[oid] = self.healths[oid]
            results = tuple(replayed.values())
        return replace(state, issued=issued, cleanup=cleanup, health_result=health,
                       red=state.red or (health is not None and not health.passed),
                       results=results,
                       reconciliation_required=self.dirty or state.reconciliation_required)

    def begin(self, target, expected, observation, recovering):
        generation = self.state.generation if self.state is not None else 0
        unsettled = self.dirty
        if observation is not None:
            old = self.healths.get(observation.commit)
            if (old is None or observation.attempt > old.attempt
                    or observation.attempt == old.attempt and not observation.passed):
                self.healths[observation.commit] = observation
            self.pending[observation.commit] = self.healths[observation.commit]
        if generation != expected or unsettled and not recovering:
            self.dirty = unsettled or observation is not None
            return False
        self.dirty = True
        if self.fail == "begin":
            raise OSError("private intent reply lost")
        return True

    def health(self, target, commit):
        if self.fail == "health":
            raise OSError("private health archive failure")
        if self.fail == "health-invalid":
            return object()
        return self.healths.get(commit)

    def save(self, target, expected, state, completion):
        generation = self.state.generation if self.state is not None else 0
        if generation != expected:
            return False
        finishing = self.state is not None and self.state.cleanup is not None and state.cleanup is None
        if self.fail == "issue-before" and state.issued is not None:
            raise OSError("private issuance checkpoint failure")
        if self.fail == "before" or self.fail == "cleanup-before" and finishing:
            raise OSError("private storage failure")
        if completion is not None:
            old = self.lanes.get(completion.entry.lane)
            assert old is None or replace(old, result=completion.result) == completion
            self.lanes[completion.entry.lane] = completion
            self.commits[completion.landing.commit] = completion
        self.state = state
        if self.fail == "after" or self.fail == "cleanup-after" and finishing:
            raise OSError("private storage reply lost")
        self.dirty = False
        self.pending.clear()
        return True

    def lane(self, target, lane):
        return self.lanes.get(lane)

    def commit(self, target, commit):
        if self.fail == "commit-exception":
            raise OSError("private archive failure")
        if self.fail == "commit-invalid":
            return object()
        return self.commits.get(commit)

    def port(self):
        return mq.QueueStorage(self.load, self.save, self.lane, self.commit, self.begin, self.health)


def fresh_queue(rig, *, backend=None, initialize=True, **config):
    backend = backend or StateBackend()
    q = mq.MergeQueue("integration", storage=backend.port(), **config)
    rig.backends[q] = backend
    if initialize and backend.state is None:
        q.restore_target(rig.store, mq.HostedResult(rig.base, True), read_target=lambda _: rig.base)
    return q


def issue(q, rig, candidate):
    return q.revalidate(rig.store, candidate, read_target=lambda _: candidate.tip,
                        read_mode=lambda *args: "none", identity=IDENTITY, now=100)


def merge_queue_author_env():
    """Pinned author dates so a fresh graph and the worker template share one id."""
    home = Path(os.environ.get("HOME", os.path.expanduser("~")))
    return {**filter_git_env(home), "GIT_AUTHOR_DATE": "1700000000 +0000",
            "GIT_COMMITTER_DATE": "1700000000 +0000"}


def build_merge_queue_graph(repo, env):
    """The rig graph: main at ``other``, lane/a at ``head``, both children of ``base``."""
    git(repo, "init", "-q", "-b", "main", env=env)
    base = commit(repo, "base", b"base\n", env=env)
    git(repo, "checkout", "-qb", "lane/a", env=env)
    head = commit(repo, "a", b"a\n", env=env)
    tree = git(repo, "rev-parse", "HEAD^{tree}", env=env).decode().strip()
    git(repo, "checkout", "-q", "main", env=env)
    other = commit(repo, "b", b"b\n", env=env)
    return SimpleNamespace(repo=repo, base=base, head=head, tree=tree, other=other)


@pytest.fixture(scope="module")
def merge_queue_template(tmp_path_factory):
    """One immutable graph per worker. Each test mutates only its own copy."""
    if shutil.which("git") is None:
        pytest.skip("needs git")
    repo = tmp_path_factory.mktemp("merge-queue-template") / "repo"
    repo.mkdir()
    template = build_merge_queue_graph(repo, merge_queue_author_env())
    template.baseline = state(template)
    yield template
    assert state(template) == template.baseline


@pytest.fixture
def rig(tmp_path, request):
    # Capability skip before the template exists: resolving it copies a Git graph.
    context = make_store(tmp_path / "repo")
    if not qual.descriptor_supported():
        pytest.skip("qualification requires descriptor-relative custody")
    template = request.getfixturevalue("merge_queue_template")
    repo = copy_immutable_repo(template, tmp_path)
    with context as store:
        yield SimpleNamespace(repo=repo, store=store, base=template.base,
                              head=template.head, tree=template.tree,
                              other=template.other,
                              journal=team_gitops.GitOpsJournal(repo / ".git"), count=0,
                              backends={})


@contextmanager
def sequence_stores():
    """Close every store opened for one sequence before the caller continues."""
    opened = []
    with ExitStack() as stack:
        def open_store(repo):
            store = stack.enter_context(make_store(repo))
            opened.append(store.scratch)
            return store
        yield open_store
    for scratch in opened:
        assert not scratch.exists()


def test_fresh_graph_matches_the_immutable_template(tmp_path, merge_queue_template):
    repo = tmp_path / "repo"
    repo.mkdir()
    built = build_merge_queue_graph(repo, merge_queue_author_env())
    assert (built.base, built.head, built.tree, built.other) == (
        merge_queue_template.base, merge_queue_template.head,
        merge_queue_template.tree, merge_queue_template.other)
    assert (repo / "base").read_bytes() == (merge_queue_template.repo / "base").read_bytes() == b"base\n"
    assert (repo / "b").read_bytes() == b"b\n"
    assert not (repo / "a").exists()
    assert not (merge_queue_template.repo / "a").exists()


def test_failed_copy_leaves_the_template_unchanged_and_retry_matches(tmp_path, merge_queue_template):
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "repo").mkdir()
    with pytest.raises(FileExistsError):
        copy_immutable_repo(merge_queue_template, blocked)
    assert state(merge_queue_template) == merge_queue_template.baseline
    assert list((blocked / "repo").iterdir()) == []
    repo = copy_immutable_repo(merge_queue_template, tmp_path)
    again = tmp_path / "retry"
    again.mkdir()
    retried = copy_immutable_repo(merge_queue_template, again)
    assert state(SimpleNamespace(repo=repo)) == merge_queue_template.baseline
    assert state(SimpleNamespace(repo=retried)) == merge_queue_template.baseline
    assert repo != retried


def test_concurrent_copies_mutate_only_their_own_bytes(tmp_path, merge_queue_template):
    barrier = Barrier(2)

    def mutate(name):
        directory = tmp_path / name
        directory.mkdir()
        repo = copy_immutable_repo(merge_queue_template, directory)
        barrier.wait(timeout=30)
        commit(repo, name + ".txt", name.encode() + b"\n")
        return repo

    with ThreadPoolExecutor(max_workers=2) as pool:
        left, right = tuple(pool.map(mutate, ("left", "right")))
    assert (left / "left.txt").read_bytes() == b"left\n"
    assert not (left / "right.txt").exists()
    assert (right / "right.txt").read_bytes() == b"right\n"
    assert not (right / "left.txt").exists()
    assert (left / "base").read_bytes() == (right / "base").read_bytes() == b"base\n"
    assert state(merge_queue_template) == merge_queue_template.baseline


def test_rig_mutation_does_not_change_the_template_or_a_sibling_copy(rig, tmp_path, request):
    # rig already passed the capability guards; do not resolve the template first.
    merge_queue_template = request.getfixturevalue("merge_queue_template")
    sibling_dir = tmp_path / "sibling"
    sibling_dir.mkdir()
    sibling = copy_immutable_repo(merge_queue_template, sibling_dir)
    (rig.repo / "base").write_bytes(b"mutated-by-this-test\n")
    assert (sibling / "base").read_bytes() == b"base\n"
    assert (merge_queue_template.repo / "base").read_bytes() == b"base\n"
    assert state(merge_queue_template) == merge_queue_template.baseline


def test_sequence_store_closes_on_failure_and_retry_opens_another(rig):
    failed = None
    with pytest.raises(RuntimeError, match="injected sequence failure"):
        with sequence_stores() as open_store:
            store = open_store(rig.repo)
            failed = store.scratch
            assert failed.exists() and failed != rig.store.scratch
            raise RuntimeError("injected sequence failure")
    assert failed is not None and not failed.exists()
    with sequence_stores() as open_store:
        store = open_store(rig.repo)
        retried = store.scratch
        assert retried.exists() and retried != failed
    assert not retried.exists()


def test_concurrent_sequence_stores_release_independent_scratches(tmp_path, request):
    # Main-thread capability skip. Workers must not be the first make_store probe.
    make_store(tmp_path)
    merge_queue_template = request.getfixturevalue("merge_queue_template")

    def once(name):
        directory = tmp_path / name
        directory.mkdir()
        repo = copy_immutable_repo(merge_queue_template, directory)
        with sequence_stores() as open_store:
            store = open_store(repo)
            scratch = store.scratch
            assert scratch.exists()
        assert not scratch.exists()
        return str(scratch)

    with ThreadPoolExecutor(max_workers=2) as pool:
        scratches = tuple(pool.map(once, ("one", "two")))
    assert scratches[0] != scratches[1]
    assert state(merge_queue_template) == merge_queue_template.baseline


def passing(rig, tree=None, head=None, legs=mq.REQUIRED_LEGS):
    tree, head = tree or rig.tree, head or rig.head
    for leg in legs:
        if qual.qualified(rig.store, tree, (leg,)):
            continue
        rig.count += 1
        qual.record_pass(rig.store, qual.QualificationResult(tree, leg, head, "run-%d" % rig.count, True),
                         expected=None, identity=IDENTITY, journal=rig.journal,
                         lane="a", request_id="qual-%d" % rig.count, actor="executor")


def entry(rig, **changes):
    reviews = tuple(mq.Review(session, rig.head, rig.tree, "ACCEPT", True)
                    for session in ("reviewer-1", "reviewer-2"))
    return replace(mq.QueueEntry("a", "writer", rig.head, reviews), **changes)


def successor_entry(rig, *, parent=None, **changes):
    """A real new lane commit, even when the previous lane already landed."""
    head = git(rig.repo, "commit-tree", rig.tree, "-p", parent or rig.head,
               data=b"next reviewed lane commit\n").decode().strip()
    reviews = tuple(mq.Review(session, head, rig.tree, "ACCEPT", True)
                    for session in ("reviewer-1", "reviewer-2"))
    return entry(rig, head=head, reviews=reviews, **changes)


def queue(rig, **changes):
    passing(rig, legs=("linux-3.12",))
    result = fresh_queue(rig)
    assert result.enqueue(rig.store, entry(rig, **changes)) == "queued"
    return result


def direct_prepare(q, rig, tip=None):
    """One prepare call. The scheduling helper may restore the target first."""
    observed = rig.base if tip is None else tip
    return q.prepare(rig.store, read_target=lambda target: observed,
                     read_mode=lambda *args: "none", identity=IDENTITY, now=100)


def prepare(q, rig, tip=None, mode="none"):
    """Supply test-owned authentication when scheduling explicitly requires it."""
    observed = tip or rig.base
    state = rig.backends[q].state
    if (state is not None and state.entries and state.health_commit != observed
            and state.issued is None and not state.red and not state.results):
        q.restore_target(rig.store, mq.HostedResult(observed, True), read_target=lambda _: observed)
    result = q.prepare(rig.store, read_target=lambda target: observed,
                       read_mode=lambda target, base, head: mode, identity=IDENTITY, now=100)
    if (result.status == "target-unobserved" and state is not None and state.entries
            and state.health_commit == observed and not state.reconciliation_required
            and state.issued is None and state.cleanup is None and not state.red and not state.results):
        q.restore_target(rig.store, mq.HostedResult(observed, True), read_target=lambda _: observed)
        result = q.prepare(rig.store, read_target=lambda target: observed,
                           read_mode=lambda target, base, head: mode, identity=IDENTITY, now=100)
    return result


def refused(code, action):
    with pytest.raises(mq.QueueRefused) as caught:
        action()
    assert caught.value.code == code
    assert str(caught.value) == mq.REFUSALS[code]
    assert caught.value.next_action


@pytest.mark.parametrize("name", merge_queue_types.__all__)
def test_model_and_queue_export_the_existing_record_type(name):
    from aegis_core import merge_queue_model as model

    legacy = getattr(merge_queue_types, name)
    assert getattr(mq, name) is getattr(model, name) is legacy
    assert legacy.__module__ == "aegis_core.merge_queue_types"
    assert pickle.loads(pickle.dumps(legacy, protocol=4)) is legacy


def test_model_checkpoint_json_fields_load_through_queue():
    from aegis_core import merge_queue_model as model

    commit = "a" * 40
    recorded = mq.QueueState("integration", mq.REQUIRED_LEGS, ("linux-3.12",),
                             health_commit=commit, health_result=mq.HostedResult(commit, True),
                             health_order=1, green_order=1, serial=1)
    fields = json.loads(json.dumps(asdict(recorded)))
    for field in ("required_legs", "entry_legs", "entries", "results"):
        fields[field] = tuple(fields[field])
    fields["health_result"] = model.HostedResult(**fields["health_result"])
    recovered = model.QueueState(**fields)
    assert recovered == recorded
    assert isinstance(recovered, mq.QueueState)

    backend = StateBackend()
    backend.state = recovered
    queue = mq.MergeQueue("integration", storage=backend.port())
    assert queue.hosted_result(commit, passed=False, attempt=1) == "target-red"
    assert backend.state.health_result == model.HostedResult(commit, False, 1)
    assert backend.state.generation == 1


def json_round_trip_backend(backend):
    from aegis_core import merge_queue_model as model

    def entry_record(row):
        return model.QueueEntry(**{**row, "parents": tuple(row["parents"]),
                                   "reviews": tuple(model.Review(**review) for review in row["reviews"])})

    def landing_record(row):
        return model.Landing(**{**row, "missing_legs": tuple(row["missing_legs"])})

    def result_record(row):
        return None if row is None else model.HostedResult(**row)

    def issued_record(row):
        if row is None:
            return None
        return model.IssuedRecord(**{**row, "entry": entry_record(row["entry"]),
                                     "landing": landing_record(row["landing"]),
                                     "result": result_record(row["result"])})

    def completion_record(row):
        return model.Completion(**{**row, "entry": entry_record(row["entry"]),
                                   "landing": landing_record(row["landing"]),
                                   "result": result_record(row["result"])})

    fields, lanes, commits, healths, pending, dirty = json.loads(json.dumps([
        asdict(backend.state),
        {key: asdict(row) for key, row in backend.lanes.items()},
        {key: asdict(row) for key, row in backend.commits.items()},
        {key: asdict(row) for key, row in backend.healths.items()},
        {key: asdict(row) for key, row in backend.pending.items()},
        backend.dirty,
    ]))
    recovered = StateBackend()
    recovered.state = model.QueueState(**{
        **fields, "required_legs": tuple(fields["required_legs"]), "entry_legs": tuple(fields["entry_legs"]),
        "entries": tuple(entry_record(row) for row in fields["entries"]),
        "results": tuple(result_record(row) for row in fields["results"]),
        "health_result": result_record(fields["health_result"]),
        "issued": issued_record(fields["issued"]), "cleanup": issued_record(fields["cleanup"]),
    })
    recovered.lanes = {key: completion_record(row) for key, row in lanes.items()}
    recovered.commits = {key: completion_record(row) for key, row in commits.items()}
    recovered.healths = {key: result_record(row) for key, row in healths.items()}
    recovered.pending = {key: result_record(row) for key, row in pending.items()}
    recovered.dirty = dirty
    return recovered


def test_model_json_checkpoint_reopens_queued_entry_with_parent(rig):
    original = queue(rig, parents=("parent",))
    backend = rig.backends[original]
    recovered = json_round_trip_backend(backend)
    restarted = fresh_queue(rig, backend=recovered, initialize=False)
    assert recovered.state == backend.state
    assert restarted.enqueue(rig.store, entry(rig, parents=("parent",))) == "already"
    assert prepare(restarted, rig).status == "blocked-by-parent"


@pytest.mark.parametrize("disposition", ["pending", "replayed"])
def test_model_json_checkpoint_recovers_unapplied_results(rig, disposition):
    original = queue(rig)
    backend = rig.backends[original]
    result = mq.HostedResult(rig.other, False, 4)
    if disposition == "pending":
        assert original.hosted_result(result.commit, passed=result.passed, attempt=result.attempt) == "unapplied"
    else:
        backend.fail = "before"
        refused("state_unavailable", lambda: original.hosted_result(
            result.commit, passed=result.passed, attempt=result.attempt))

    recovered = json_round_trip_backend(backend)
    restarted = fresh_queue(rig, backend=recovered, initialize=False)
    assert recovered.state == backend.state
    assert recovered.pending == backend.pending
    assert prepare(restarted, rig).status == "unapplied-results"
    assert restarted.restore_target(rig.store, mq.HostedResult(rig.base, True), read_target=lambda _: rig.base) == "green"
    observed = []

    def not_applied(row):
        observed.append(row)
        return "not_applied"

    assert restarted.reconcile_result(rig.store, result.commit, read_outcome=not_applied,
                                      read_target=lambda _: rig.base) == "not_applied"
    assert restarted.reconcile_result(rig.store, result.commit, read_outcome=not_applied,
                                      read_target=lambda _: rig.base) == "already"
    assert observed == [result]
    assert prepare(restarted, rig).status == "pending"


@pytest.mark.parametrize("phase", ["issued", "completed"])
@pytest.mark.parametrize("has_result", [False, True], ids=["without-result", "with-result"])
def test_model_json_checkpoint_reopens_receipts_and_archive(rig, phase, has_result):
    original = queue(rig)
    backend = rig.backends[original]
    passing(rig)
    receipt = issue(original, rig, prepare(original, rig))
    if has_result:
        assert original.hosted_result(receipt.commit, passed=True, attempt=3) == "pending"

    def acknowledge(active):
        return active.observe_landed(rig.store, receipt, read_target=lambda _: receipt.commit)

    if phase == "completed":
        assert acknowledge(original) == "done"

    recovered = json_round_trip_backend(backend)
    restarted = fresh_queue(rig, backend=recovered, initialize=False)
    assert recovered.state == backend.state
    assert recovered.lanes == backend.lanes
    assert recovered.commits == backend.commits
    if phase == "issued":
        assert restarted.issued == receipt
        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(acknowledge, (restarted, restarted))) == ["already", "done"]
    assert restarted.issued is None
    assert acknowledge(restarted) == "already"
    assert restarted.hosted_result(receipt.commit, passed=False, attempt=2) == (
        "green" if has_result else "target-red")
    assert restarted.hosted_result(receipt.commit, passed=False, attempt=3) == "target-red"

    descendant = git(rig.repo, "commit-tree", receipt.tree, "-p", receipt.commit,
                     data=b"next target after the archived landing\n").decode().strip()
    assert restarted.restore_target(rig.store, mq.HostedResult(descendant, True),
                                    read_target=lambda _: descendant) == "green"
    assert restarted.hosted_result(receipt.commit, passed=True, attempt=4) == "stale"


# Test-owned durable strings and outcomes. Coverage is compared with the model's
# named declaration; these literals are not read from the validator source.
DURABLE_CLEANUP_OUTCOMES = {
    "issuing": "not_applied",
    "aborted": "not_applied",
    "done": "already",
    "not_applied": "not_applied",
    "released": "released",
}
UNKNOWN_CLEANUP_RESOLUTIONS = ("unknown", "done\n", "not_applied\r", "issuing aborted", "ISSUING", "")


def _synthetic_entry(lane, parents=()):
    commit, tree = "a" * 40, "b" * 40
    reviews = tuple(mq.Review(session, commit, tree, "ACCEPT", True)
                    for session in ("reviewer-1", "reviewer-2"))
    return mq.QueueEntry(lane, "writer", commit, reviews, parents=tuple(parents))


def _validated_state(entries, cleanup=None, serial=0):
    from aegis_core import merge_queue_model as model

    state = model.QueueState("integration", model.REQUIRED_LEGS, ("linux-3.12",),
                             entries=tuple(entries), cleanup=cleanup, serial=serial)
    return model.validate_state(state, "integration", model.REQUIRED_LEGS, ("linux-3.12",),
                                model.MAX_ENTRIES)


def _cleanup_state(resolution, result=None):
    from aegis_core import merge_queue_model as model

    entry = _synthetic_entry("a")
    landing = model.Landing("ready", "a", "c" * 40, entry.head, "b" * 40, issuance=1)
    record = model.IssuedRecord(entry, landing, result=result, resolution=resolution,
                                ref=model.pin_ref("integration", landing), expected=entry.head)
    return _validated_state((entry,), record, serial=1)


def test_cleanup_resolution_declaration_matches_independent_recovery_table():
    """Invariant: the durable resolution declaration and the test-owned table agree."""
    from aegis_core import merge_queue_model as model

    declared = getattr(model, "CLEANUP_RESOLUTIONS", None)
    assert type(declared) is tuple and declared
    assert len(set(declared)) == len(declared)
    assert set(declared) == set(DURABLE_CLEANUP_OUTCOMES)
    for value in declared:
        assert type(value) is str and value == value.strip() and "\n" not in value and "\r" not in value
        assert " " not in value


def test_validate_state_pins_declared_cleanup_resolutions_and_refuses_unknown():
    """Unknown and multi-line resolutions are refused whole; a declared value retries."""
    from aegis_core import merge_queue_model as model

    for resolution in DURABLE_CLEANUP_OUTCOMES:
        for result in (None, model.HostedResult("a" * 40, True, 3)):
            state = _cleanup_state(resolution, result)
            assert state.cleanup.resolution == resolution
            assert state.cleanup.result == result
    for resolution in UNKNOWN_CLEANUP_RESOLUTIONS:
        for result in (None, model.HostedResult("a" * 40, True, 3)):
            refused("state_unavailable", lambda resolution=resolution, result=result:
                    _cleanup_state(resolution, result))
            repaired = _cleanup_state("issuing", result)
            assert repaired.cleanup.resolution == "issuing"
            assert repaired.cleanup.result == result


def test_validate_state_rejects_pending_cycles_and_keeps_external_parents():
    """One cycle check: enqueue root is parent_cycle; full restore is state_unavailable."""
    from aegis_core import merge_queue_model as model

    solo = _synthetic_entry("solo", ("outside",))
    left = _synthetic_entry("left", ("right",))
    right = _synthetic_entry("right", ("left",))
    diamond_d = _synthetic_entry("d")
    diamond_b = _synthetic_entry("b", ("d",))
    diamond_c = _synthetic_entry("c", ("d", "outside"))
    diamond_a = _synthetic_entry("a", ("b", "c"))
    acyclic = {"solo": solo, "d": diamond_d, "b": diamond_b, "c": diamond_c, "a": diamond_a}
    snapshot = dict(acyclic)

    model.check_acyclic(_synthetic_entry("fresh", ("outside",)), acyclic)
    refused("parent_cycle", lambda: model.check_acyclic(_synthetic_entry("right", ("left",)),
                                                        {"left": left}))
    hidden = {"loop-a": _synthetic_entry("loop-a", ("loop-b",)),
              "loop-b": _synthetic_entry("loop-b", ("loop-a",))}
    refused("parent_cycle", lambda: model.check_acyclic(_synthetic_entry("child", ("loop-a",)), hidden))
    model.check_acyclic(_synthetic_entry("child", ("outside",)), dict(hidden))
    assert acyclic == snapshot

    _validated_state((solo, diamond_d, diamond_b, diamond_c, diamond_a))
    _validated_state(())
    refused("state_unavailable", lambda: _validated_state((solo, left, right)))
    refused("state_unavailable", lambda: _validated_state((
        _synthetic_entry("a", ("b",)), _synthetic_entry("b", ("c",)), _synthetic_entry("c", ("a",)))))
    refused("state_unavailable", lambda: _validated_state((_synthetic_entry("a", ("a",)),)))
    chain = tuple(_synthetic_entry("n%d" % index, (("n%d" % (index + 1),) if index < 4 else ("n0",)))
                  for index in range(5))
    refused("state_unavailable", lambda: _validated_state((solo,) + chain))
    repaired = _validated_state((solo, left, replace(right, parents=("outside",))))
    assert {item.lane for item in repaired.entries} == {"solo", "left", "right"}
    refused("state_unavailable", lambda: model.check_acyclic(None, {"left": left, "right": right}))
    model.check_acyclic(None, {item.lane: item for item in repaired.entries})


@pytest.mark.parametrize("resolution", list(DURABLE_CLEANUP_OUTCOMES))
@pytest.mark.parametrize("has_result", [False, True], ids=["without-result", "with-result"])
def test_model_json_checkpoint_recovers_every_cleanup_resolution(rig, resolution, has_result):
    original = queue(rig)
    backend = rig.backends[original]
    passing(rig)
    candidate = prepare(original, rig)
    if resolution in ("issuing", "aborted"):
        backend.fail = "issue-before"
        refused("state_unavailable", lambda: issue(original, rig, candidate))
        backend.fail = None
        original = fresh_queue(rig, backend=backend, initialize=False)
    else:
        issue(original, rig, candidate)
    receipt = original.issued
    observed = []

    def settled(row):
        observed.append(row)
        return "not_applied"

    def reconcile(active, read_outcome=settled):
        return active.reconcile_not_landed(rig.store, receipt, read_target=lambda _: receipt.tip,
                                           read_outcome=read_outcome)

    def withdraw(active):
        return active.withdraw(receipt.lane, expected_head=rig.head, store=rig.store,
                               read_target=lambda _: receipt.tip, read_outcome=settled)

    def acknowledge(active):
        return active.observe_landed(rig.store, receipt, read_target=lambda _: receipt.commit)

    expected = DURABLE_CLEANUP_OUTCOMES[resolution]
    recover = {"not_applied": reconcile, "already": acknowledge, "released": withdraw}[expected]
    if resolution != "issuing":
        backend.fail = "cleanup-before"
        refused("state_unavailable", lambda: recover(original))
        backend.fail = None
    if has_result:
        observer = fresh_queue(rig, backend=backend, initialize=False)
        assert observer.hosted_result(receipt.commit, passed=True, attempt=3) == "pending"
    assert backend.state.cleanup.resolution == resolution
    assert backend.state.cleanup.result == (mq.HostedResult(receipt.commit, True, 3) if has_result else None)

    recovered = json_round_trip_backend(backend)
    checkpoint = recovered.state
    restarted = fresh_queue(rig, backend=recovered, initialize=False)
    assert restarted.issued == receipt
    observed.clear()
    if resolution in ("issuing", "aborted"):
        refused("landing_unconfirmed", lambda: reconcile(restarted, lambda _: "pending"))
        assert restarted.issued == receipt
    assert recover(restarted) == expected
    assert observed == ([receipt] if resolution in ("issuing", "aborted") else [])
    assert restarted.issued is None
    assert checkpoint == backend.state
    assert recovered.lanes == backend.lanes
    assert recovered.commits == backend.commits
    if expected == "not_applied":
        refused("stale_candidate", lambda: recover(restarted))
    else:
        assert recover(restarted) == "already"
    assert git(rig.repo, "for-each-ref", "--format=%(objectname)", "refs/aegis/merge-queue/") == b""


@pytest.mark.parametrize("has_result", [False, True], ids=["without-result", "with-result"])
def test_unknown_cleanup_resolution_reopen_refuses_and_declared_retry_recovers(rig, has_result):
    """Reopen refuses unknown input whole; a declared resolution retries the saved result."""
    original = queue(rig)
    backend = rig.backends[original]
    passing(rig)
    candidate = prepare(original, rig)
    backend.fail = "issue-before"
    refused("state_unavailable", lambda: issue(original, rig, candidate))
    backend.fail = None
    original = fresh_queue(rig, backend=backend, initialize=False)
    receipt = original.issued
    if has_result:
        assert original.hosted_result(receipt.commit, passed=True, attempt=3) == "pending"
    saved_result = mq.HostedResult(receipt.commit, True, 3) if has_result else None
    assert backend.state.cleanup.resolution == "issuing"
    assert backend.state.cleanup.result == saved_result

    def reopen(active_backend):
        fresh_queue(rig, backend=active_backend, initialize=False)

    for unknown in UNKNOWN_CLEANUP_RESOLUTIONS:
        backend.state = replace(backend.state, cleanup=replace(backend.state.cleanup, resolution=unknown))
        recovered = json_round_trip_backend(backend)
        assert recovered.state.cleanup.resolution == unknown
        assert recovered.state.cleanup.result == saved_result
        refused("state_unavailable", lambda recovered=recovered: reopen(recovered))
        assert recovered.state.cleanup.resolution == unknown

    backend.state = replace(backend.state, cleanup=replace(backend.state.cleanup, resolution="done\n"))
    recovered = json_round_trip_backend(backend)
    barrier = Barrier(2)

    def concurrent(_):
        barrier.wait(timeout=10)
        try:
            reopen(recovered)
            return "opened"
        except mq.QueueRefused as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(concurrent, (0, 1))) == ["state_unavailable", "state_unavailable"]
    assert recovered.state.cleanup.resolution == "done\n"
    assert recovered.state.cleanup.result == saved_result

    recovered.state = replace(recovered.state, cleanup=replace(recovered.state.cleanup, resolution="issuing"))
    restarted = fresh_queue(rig, backend=recovered, initialize=False)
    assert restarted.issued == receipt
    refused("landing_unconfirmed", lambda: restarted.reconcile_not_landed(
        rig.store, receipt, read_target=lambda _: receipt.tip, read_outcome=lambda _: "pending"))
    assert restarted.issued == receipt
    assert restarted.reconcile_not_landed(
        rig.store, receipt, read_target=lambda _: receipt.tip,
        read_outcome=lambda _: "not_applied") == "not_applied"
    assert restarted.issued is None
    refused("stale_candidate", lambda: restarted.reconcile_not_landed(
        rig.store, receipt, read_target=lambda _: receipt.tip, read_outcome=lambda _: "not_applied"))


# Resolutions that are not in the durable declaration. Built directly so recovery
# is tested without validate_state rewriting or refusing them first.
UNDECLARED_CLEANUP_RESOLUTIONS = ("retry", "forced")


def _issuing_checkpoint(rig):
    """Settled issuing cleanup from a lost issuance reply. The caller plants resolutions."""
    original = queue(rig)
    backend = rig.backends[original]
    passing(rig)
    candidate = prepare(original, rig)
    backend.fail = "issue-before"
    refused("state_unavailable", lambda: issue(original, rig, candidate))
    backend.fail = None
    receipt = original.issued
    baseline = backend.state
    assert baseline.cleanup.resolution == "issuing"
    assert receipt == baseline.cleanup.landing
    # The lost reply left the test journal dirty. The planted record is the settled checkpoint.
    backend.dirty = False
    backend.pending.clear()
    return backend, baseline, receipt


def _bind_direct_cleanup(rig, backend, baseline, resolution, result=None):
    """Install cleanup.resolution on a live queue without calling validate_state."""
    planted = replace(baseline, reconciliation_required=baseline.reconciliation_required or backend.dirty,
                      cleanup=replace(baseline.cleanup, resolution=resolution, result=result))
    backend.state = planted
    opened = mq.MergeQueue("integration")
    opened._storage = backend.port()
    opened._state = planted
    opened._repo = rig.store.repo
    rig.backends[opened] = backend
    return opened


def _recovery_snapshot(rig, active, backend):
    cleanup = active._state.cleanup
    return (cleanup.resolution, cleanup.result, tuple(item.lane for item in active._state.entries),
            dict(backend.lanes), dict(backend.commits), active._target_checked, active._faulted,
            git(rig.repo, "rev-parse", cleanup.ref).decode().strip())


def test_direct_undeclared_cleanup_resolution_refuses_without_reopen(rig, monkeypatch):
    """An undeclared resolution built past validate_state refuses at recovery and does not reopen."""
    from aegis_core import merge_queue_model as model

    backend, baseline, receipt = _issuing_checkpoint(rig)
    real_validate = model.validate_state
    validations = []

    def reject_validation(*args, **kwargs):
        validations.append(args)
        raise mq.QueueRefused("state_unavailable")

    monkeypatch.setattr(mq.model, "validate_state", reject_validation)

    def recover_all(active):
        refused("state_unavailable", lambda: active.withdraw(
            receipt.lane, expected_head=rig.head, store=rig.store,
            read_target=lambda _: receipt.tip, read_outcome=lambda _: "not_applied"))
        refused("state_unavailable", lambda: active.observe_landed(
            rig.store, receipt, read_target=lambda _: receipt.commit))
        refused("state_unavailable", lambda: active.reconcile_not_landed(
            rig.store, receipt, read_target=lambda _: receipt.tip, read_outcome=lambda _: "not_applied"))

    for resolution in UNDECLARED_CLEANUP_RESOLUTIONS:
        for result in (None, mq.HostedResult(receipt.commit, True, 3)):
            planted = replace(baseline, cleanup=replace(baseline.cleanup, resolution=resolution, result=result))
            refused("state_unavailable", lambda planted=planted: real_validate(
                planted, "integration", model.REQUIRED_LEGS, ("linux-3.12",), model.MAX_ENTRIES))
            opened = _bind_direct_cleanup(rig, backend, baseline, resolution, result)
            before = _recovery_snapshot(rig, opened, backend)
            recover_all(opened)
            assert validations == []
            assert _recovery_snapshot(rig, opened, backend) == before
            assert opened.issued == receipt
            assert opened.prepare(rig.store, read_target=lambda _: rig.base,
                                  read_mode=lambda *args: "none", identity=IDENTITY,
                                  now=100).status == "reconciliation-required"
            assert opened._state.cleanup.resolution == resolution
            assert opened._state.cleanup.result == result

    concurrent = _bind_direct_cleanup(rig, backend, baseline, "retry", mq.HostedResult(receipt.commit, True, 3))
    before = _recovery_snapshot(rig, concurrent, backend)
    barrier = Barrier(3)

    def attack(kind):
        barrier.wait(timeout=10)
        try:
            if kind == "withdraw":
                concurrent.withdraw(receipt.lane, expected_head=rig.head, store=rig.store,
                                    read_target=lambda _: receipt.tip, read_outcome=lambda _: "not_applied")
            elif kind == "acknowledge":
                concurrent.observe_landed(rig.store, receipt, read_target=lambda _: receipt.commit)
            else:
                concurrent.reconcile_not_landed(rig.store, receipt, read_target=lambda _: receipt.tip,
                                                read_outcome=lambda _: "not_applied")
            return "opened"
        except mq.QueueRefused as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert sorted(pool.map(attack, ("withdraw", "acknowledge", "reconcile"))) == ["state_unavailable"] * 3
    assert validations == []
    assert _recovery_snapshot(rig, concurrent, backend) == before
    assert concurrent.issued == receipt

    restart = _bind_direct_cleanup(rig, backend, baseline, "retry")
    before = _recovery_snapshot(rig, restart, backend)
    refused("state_unavailable", lambda: restart.restore_target(
        rig.store, mq.HostedResult(rig.base, True), read_target=lambda _: rig.base))
    assert _recovery_snapshot(rig, restart, backend) == before
    assert restart.issued == receipt
    assert restart.prepare(rig.store, read_target=lambda _: rig.base,
                           read_mode=lambda *args: "none", identity=IDENTITY,
                           now=100).status == "reconciliation-required"
    refused("state_unavailable", lambda: restart.withdraw(
        receipt.lane, expected_head=rig.head, store=rig.store,
        read_target=lambda _: receipt.tip, read_outcome=lambda _: "not_applied"))
    assert validations == []

    repaired = _bind_direct_cleanup(rig, backend, baseline, "issuing")
    refused("landing_unconfirmed", lambda: repaired.reconcile_not_landed(
        rig.store, receipt, read_target=lambda _: receipt.tip, read_outcome=lambda _: "pending"))
    assert repaired.issued == receipt
    assert repaired.reconcile_not_landed(
        rig.store, receipt, read_target=lambda _: receipt.tip,
        read_outcome=lambda _: "not_applied") == "not_applied"
    assert repaired.issued is None
    assert validations == []


def test_recovery_dispatch_keys_match_declaration_and_reach_each_handler(rig, monkeypatch):
    """Every declared resolution reaches the one dispatch handler for the independent outcome."""
    from aegis_core import merge_queue_model as model

    declared = model.CLEANUP_RESOLUTIONS
    assert tuple(mq._CLEANUP_RECOVERY) == declared
    assert set(mq._CLEANUP_RECOVERY) == set(DURABLE_CLEANUP_OUTCOMES)
    assert len(mq._CLEANUP_RECOVERY) == len(declared)
    backend, baseline, receipt = _issuing_checkpoint(rig)
    validations = []

    def reject_validation(*args, **kwargs):
        validations.append(args)
        raise mq.QueueRefused("state_unavailable")

    monkeypatch.setattr(mq.model, "validate_state", reject_validation)
    git(rig.repo, "update-ref", baseline.cleanup.ref, baseline.cleanup.expected)

    def reconcile(active, outcome="not_applied"):
        return active.reconcile_not_landed(rig.store, receipt, read_target=lambda _: receipt.tip,
                                           read_outcome=lambda _: outcome)

    def acknowledge(active):
        return active.observe_landed(rig.store, receipt, read_target=lambda _: receipt.commit)

    def release(active):
        return active.withdraw(receipt.lane, expected_head=rig.head, store=rig.store,
                              read_target=lambda _: receipt.tip, read_outcome=lambda _: "not_applied")

    wrong = _bind_direct_cleanup(rig, backend, baseline, "done")
    refused("stale_candidate", lambda: reconcile(wrong))
    refused("request_conflict", lambda: release(wrong))
    assert wrong._state.cleanup.resolution == "done"
    held = _bind_direct_cleanup(rig, backend, baseline, "not_applied")
    refused("stale_candidate", lambda: acknowledge(held))
    refused("request_conflict", lambda: release(held))
    assert held._state.cleanup.resolution == "not_applied"

    failed = _bind_direct_cleanup(rig, backend, baseline, "done")
    backend.fail = "cleanup-before"
    refused("state_unavailable", lambda: acknowledge(failed))
    backend.fail = None
    assert failed._state.cleanup.resolution == "done"
    assert failed._faulted is True
    retried = _bind_direct_cleanup(rig, backend, baseline, "done")
    assert acknowledge(retried) == "already"
    assert retried.issued is None

    runners = {"abort": reconcile, "acknowledge": acknowledge, "settle": reconcile, "release": release}
    for resolution in declared:
        git(rig.repo, "update-ref", baseline.cleanup.ref, baseline.cleanup.expected)
        opened = _bind_direct_cleanup(rig, backend, baseline, resolution)
        handler = mq._CLEANUP_RECOVERY[resolution]
        if resolution in ("issuing", "aborted"):
            assert handler == mq._CLEANUP_RECOVERY["issuing"] == mq._CLEANUP_RECOVERY["aborted"]
            refused("landing_unconfirmed", lambda opened=opened: reconcile(opened, "pending"))
            assert opened.issued == receipt
            assert opened._state.cleanup.resolution == resolution
        else:
            # A finish-only handler must not rewrite the resolution before the failing save.
            backend.fail = "cleanup-before"
            refused("state_unavailable", lambda opened=opened, handler=handler: runners[handler](opened))
            backend.fail = None
            assert opened._state.cleanup.resolution == resolution
            assert opened._faulted is True
            git(rig.repo, "update-ref", baseline.cleanup.ref, baseline.cleanup.expected)
            opened = _bind_direct_cleanup(rig, backend, baseline, resolution)
        assert runners[handler](opened) == DURABLE_CLEANUP_OUTCOMES[resolution]
        assert opened.issued is None
    assert validations == []


@pytest.mark.parametrize("phase", ["empty", "queued", "issued", "cleanup", "completed"])
def test_pickled_model_checkpoint_and_archive_reopen_through_queue(rig, phase):
    from aegis_core import merge_queue_model as model

    original = fresh_queue(rig) if phase == "empty" else queue(rig)
    backend = rig.backends[original]
    receipt = None
    if phase in ("issued", "cleanup", "completed"):
        passing(rig)
        receipt = issue(original, rig, prepare(original, rig))
        assert isinstance(receipt, model.Landing)
        if phase == "cleanup":
            backend.fail = "cleanup-before"
            refused("state_unavailable", lambda: original.observe_landed(
                rig.store, receipt, read_target=lambda _: receipt.commit))
            backend.fail = None
        elif phase == "completed":
            assert original.observe_landed(rig.store, receipt, read_target=lambda _: receipt.commit) == "done"

    state = backend.state
    backend.state, backend.lanes, backend.commits = pickle.loads(
        pickle.dumps((state, backend.lanes, backend.commits), protocol=4))
    assert backend.state == state
    assert isinstance(backend.state, model.QueueState)
    restarted = fresh_queue(rig, backend=backend, initialize=False)
    if phase in ("issued", "cleanup"):
        assert restarted.issued == receipt
    else:
        assert restarted.issued is None
    if phase in ("cleanup", "completed"):
        assert isinstance(backend.commits[receipt.commit], model.Completion)
        assert restarted.observe_landed(rig.store, receipt, read_target=lambda _: receipt.commit) == "already"
    if phase == "queued":
        assert restarted.enqueue(rig.store, entry(rig)) == "already"


@pytest.mark.parametrize("field", ["session", "commit", "tree", "verdict", "helpers_off"])
def test_review_requires_every_admission_field_explicitly(field):
    values = dict(session="reviewer", commit="a" * 40, tree="b" * 40,
                  verdict="ACCEPT", helpers_off=True)
    del values[field]
    for _ in range(2):
        with pytest.raises(TypeError, match="missing 1 required positional argument: '" + field + "'"):
            mq.Review(**values)


@pytest.mark.parametrize("field,value", [
    ("verdict", None), ("verdict", True), ("verdict", "accept"),
    ("verdict", "ACCEPT\n"), ("verdict", "REJECT"), ("verdict", []),
    ("helpers_off", None), ("helpers_off", False), ("helpers_off", 1),
    ("helpers_off", "True"), ("helpers_off", []),
])
def test_review_refusal_leaves_storage_untouched_and_allows_corrected_retry(rig, field, value):
    passing(rig)
    q = fresh_queue(rig)
    backend = rig.backends[q]
    original = entry(rig)
    bad = replace(original, reviews=(replace(original.reviews[0], **{field: value}),
                                     original.reviews[1]))
    before = backend.state
    for _ in range(2):
        refused("not_reviewed", lambda: q.enqueue(rig.store, bad))
        assert backend.state == before and not backend.dirty
    assert q.enqueue(rig.store, original) == "queued"


class CountingIndexBackend(StateBackend):
    """Records commit-index and health reads on the test-owned storage port."""

    def __init__(self):
        super().__init__()
        self.reads = []

    def commit(self, target, commit):
        self.reads.append(("commit", commit))
        return super().commit(target, commit)

    def health(self, target, commit):
        self.reads.append(("health", commit))
        return super().health(target, commit)


class ImmutableIndexBackend(StateBackend):
    """Same port with an immutable commit-to-completion identity."""

    def save(self, target, expected, state, completion):
        if completion is not None:
            old = self.commits.get(completion.landing.commit)
            if old is not None and replace(old, result=completion.result) != completion:
                raise OSError("immutable completion index")
        return super().save(target, expected, state, completion)


@pytest.mark.parametrize("backend_type", [StateBackend, ImmutableIndexBackend])
@pytest.mark.parametrize("relation", ["equal", "behind", "ahead", "diverged"])
@pytest.mark.parametrize("caller", ["first", "second", "requeued"])
def test_head_relation_and_completion_identity_matrix(rig, backend_type, relation, caller):
    passing(rig)
    descendant = git(rig.repo, "commit-tree", rig.tree, "-p", rig.head,
                     data=b"outside advance\n").decode().strip()
    tip = {"equal": rig.head, "behind": descendant,
           "ahead": rig.base, "diverged": rig.other}[relation]
    backend = backend_type()
    q = fresh_queue(rig, backend=backend)
    q.restore_target(rig.store, mq.HostedResult(tip, True), read_target=lambda _: tip)
    original = entry(rig)
    assert q.enqueue(rig.store, original) == "queued"
    integrated = relation in ("equal", "behind")
    if not integrated:
        candidate = prepare(q, rig, tip)
        passing(rig, candidate.tree, candidate.commit)
        candidate = prepare(q, rig, tip)
        assert candidate.status == "ready"
    if caller != "first":
        if integrated:
            if caller == "second":
                assert q.withdraw("a", expected_head=rig.head) == "released"
        else:
            receipt = issue(q, rig, candidate)
            assert q.observe_landed(rig.store, receipt, read_target=lambda _: receipt.commit) == "done"
            tip = receipt.commit
            q.restore_target(rig.store, mq.HostedResult(tip, True), read_target=lambda _: tip)
            integrated = True
        assert q.enqueue(rig.store, replace(original, lane="second") if caller == "second"
                         else original) == ("queued" if caller == "second" else "already")
    before, archives = backend.state, dict(backend.commits)
    if caller == "requeued" and backend.lanes:
        assert prepare(q, rig, tip).status == "empty"
    elif integrated:
        for _ in range(2):
            refused("already_integrated", lambda: prepare(q, rig, tip))
        assert q.issued is None
    else:
        assert prepare(q, rig, tip) == candidate
    assert backend.state == before and backend.commits == archives and not backend.dirty
    assert len(backend.commits) == len(backend.lanes) <= 1


@pytest.mark.parametrize("events", tuple(permutations(("green", "red0", "red1", "ack"))))
def test_hosted_return_reports_resulting_pause_in_every_arrival_order(rig, events):
    q = queue(rig)
    passing(rig)
    receipt = issue(q, rig, prepare(q, rig))
    backend = rig.backends[q]
    for event in events:
        if event == "ack":
            assert q.observe_landed(rig.store, receipt, read_target=lambda _: receipt.commit) == "done"
        else:
            result = q.hosted_result(receipt.commit, passed=event == "green",
                                     attempt=1 if event == "red1" else 0)
            assert result == ("pending" if backend.state.issued is not None
                              else "target-red" if backend.state.red else "green")
    assert backend.state.red
    assert q.hosted_result(receipt.commit, passed=False, attempt=1) == "target-red"
    assert q.hosted_result(receipt.commit, passed=True, attempt=2) == "green"


@pytest.mark.parametrize("restart", [False, True])
@pytest.mark.parametrize("advanced", [False, True])
def test_landing_target_observation_requires_restore_after_outside_advance(rig, restart, advanced):
    q = queue(rig)
    passing(rig)
    receipt = issue(q, rig, prepare(q, rig))
    tip = (git(rig.repo, "commit-tree", rig.tree, "-p", receipt.commit,
               data=b"outside advance\n").decode().strip() if advanced else receipt.commit)
    assert q.observe_landed(rig.store, receipt, read_target=lambda _: tip) == "done"
    next_head = git(rig.repo, "commit-tree", rig.tree, "-p", tip,
                    data=b"next lane\n").decode().strip()
    reviews = tuple(mq.Review(s, next_head, rig.tree, "ACCEPT", True) for s in ("r1", "r2"))
    q.enqueue(rig.store, entry(rig, lane="next", head=next_head, reviews=reviews))
    if restart:
        q = fresh_queue(rig, backend=rig.backends[q], initialize=False)
    observed = q.prepare(rig.store, read_target=lambda _: tip, read_mode=lambda *args: "none",
                         identity=IDENTITY, now=100)
    assert observed.status == "target-unobserved"
    refused("observation_failed", lambda: q.restore_target(rig.store,
        mq.HostedResult(rig.base, True), read_target=lambda _: tip))
    q = fresh_queue(rig, backend=rig.backends[q], initialize=False)
    assert q.restore_target(rig.store, mq.HostedResult(tip, True), read_target=lambda _: tip) == "green"
    assert prepare(q, rig, tip).status == "ready"


@pytest.mark.parametrize("field", ["repair", "parents", "deadline", "reviewer sessions", "hosted attempts"])
def test_module_declares_trusted_caller_preconditions(field):
    assert field in mq.__doc__
    assert "trusted caller input" in mq.__doc__
    assert "model-controlled" in mq.__doc__


@pytest.mark.parametrize("backend_type", [StateBackend, ImmutableIndexBackend])
def test_concurrent_equal_head_plans_never_issue_or_change_archive(rig, backend_type):
    passing(rig)
    q = fresh_queue(rig, backend=backend_type())
    q.restore_target(rig.store, mq.HostedResult(rig.head, True), read_target=lambda _: rig.head)
    q.enqueue(rig.store, entry(rig))
    before = rig.backends[q].state
    barrier = Barrier(2)

    def plan(_):
        barrier.wait(timeout=10)
        refused("already_integrated", lambda: prepare(q, rig, rig.head))

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(plan, range(2), timeout=30))
    assert q.issued is None and rig.backends[q].state == before
    assert rig.backends[q].commits == {}


@pytest.mark.parametrize("backend_type", [StateBackend, ImmutableIndexBackend])
def test_archived_commit_cannot_acquire_second_completion_after_target_rewind(rig, backend_type):
    passing(rig)
    q = fresh_queue(rig, backend=backend_type())
    q.enqueue(rig.store, entry(rig))
    receipt = issue(q, rig, prepare(q, rig))
    assert q.observe_landed(rig.store, receipt, read_target=lambda _: rig.head) == "done"
    q.restore_target(rig.store, mq.HostedResult(rig.base, True), read_target=lambda _: rig.base)
    q.enqueue(rig.store, entry(rig, lane="second"))
    backend = rig.backends[q]
    before = backend.state
    for _ in range(2):
        refused("archived_completion", lambda: prepare(q, rig))
    assert "ancestor" not in mq.REFUSALS["archived_completion"]
    assert "expected head" in mq.REFUSALS["archived_completion"]
    assert mq.REFUSALS["archived_completion"] != mq.REFUSALS["already_integrated"]
    assert q.issued is None and backend.state == before and not backend.dirty
    assert backend.commits[rig.head].landing == receipt
    assert tuple(backend.lanes) == ("a",)


def test_prepare_uses_one_authenticated_completion_miss(rig):
    """A preparation reads the commit index once and reuses that miss for health.

    Revalidation and issuance keep independent reads. A later preparation does
    not reuse the earlier miss, and a red health result stays a health result.
    """
    passing(rig)
    backend = CountingIndexBackend()
    q = fresh_queue(rig, backend=backend)
    assert q.enqueue(rig.store, entry(rig)) == "queued"
    backend.reads.clear()
    candidate = direct_prepare(q, rig)
    assert [kind for kind, oid in backend.reads] == ["commit", "health"]
    assert all(oid == rig.head for _, oid in backend.reads)
    assert candidate.status == "ready" and candidate.commit == rig.head
    backend.reads.clear()
    assert direct_prepare(q, rig) == candidate
    assert [kind for kind, oid in backend.reads] == ["commit", "health"]
    backend.healths[rig.head] = mq.HostedResult(rig.head, False, 1)
    backend.reads.clear()
    assert direct_prepare(q, rig).status == "target-red"
    assert [kind for kind, oid in backend.reads] == ["commit", "health"]
    assert all(oid == rig.head for _, oid in backend.reads)
    del backend.healths[rig.head]
    ready = direct_prepare(q, rig)
    backend.healths[ready.commit] = mq.HostedResult(ready.commit, False, 1)
    backend.reads.clear()
    refused("target_red", lambda: issue(q, rig, ready))
    assert [kind for kind, oid in backend.reads] == ["commit", "health"]
    del backend.healths[ready.commit]
    ready = direct_prepare(q, rig)
    backend.reads.clear()
    receipt = issue(q, rig, ready)
    assert [kind for kind, oid in backend.reads] == ["commit", "health", "commit", "health"]
    assert all(oid == receipt.commit for _, oid in backend.reads)
    backend.reads.clear()
    assert q.check_issued(rig.store, receipt, read_target=lambda _: rig.base,
                          read_mode=lambda *args: "none", now=100) is True
    assert [kind for kind, oid in backend.reads] == ["commit", "health"]
    assert backend.reads[0][1] == receipt.commit


@pytest.mark.parametrize("shape", ["fast-forward", "merge"])
def test_archived_completion_refusal_is_distinct_from_ancestry(rig, shape):
    """An archived commit stays archived after rewind, including when its result is red.

    Recovery is expected-head withdrawal. A fresh lane on the same commit is
    refused again, and ancestry advice is left unchanged.
    """
    passing(rig)
    backend = CountingIndexBackend()
    q = fresh_queue(rig, backend=backend)
    assert q.enqueue(rig.store, entry(rig)) == "queued"
    tip = rig.base if shape == "fast-forward" else rig.other
    if shape == "merge":
        assert q.restore_target(rig.store, mq.HostedResult(tip, True),
                                read_target=lambda _: tip) == "green"
    candidate = direct_prepare(q, rig, tip)
    passing(rig, candidate.tree, candidate.commit)
    candidate = direct_prepare(q, rig, tip)
    assert candidate.status == "ready"
    receipt = issue(q, rig, candidate)
    assert q.observe_landed(rig.store, receipt, read_target=lambda _: receipt.commit) == "done"
    assert q.restore_target(rig.store, mq.HostedResult(tip, True), read_target=lambda _: tip) == "green"
    assert q.hosted_result(receipt.commit, passed=False, attempt=1) == "stale"
    assert q.enqueue(rig.store, entry(rig, lane="second")) == "queued"
    assert backend.state.red is False
    before = backend.state
    backend.reads.clear()
    for _ in range(2):
        start = len(backend.reads)
        refused("archived_completion", lambda: direct_prepare(q, rig, tip))
        assert [kind for kind, oid in backend.reads[start:]] == ["commit"]
        assert backend.reads[-1][1] == receipt.commit
    assert "ancestor" not in mq.REFUSALS["archived_completion"]
    assert "expected head" in mq.REFUSALS["archived_completion"]
    assert mq.REFUSALS["archived_completion"] != mq.REFUSALS["already_integrated"]
    assert "ancestor" in mq.REFUSALS["already_integrated"]
    assert q.issued is None and backend.state == before and not backend.dirty
    assert backend.commits[receipt.commit].result == mq.HostedResult(receipt.commit, False, 1)
    assert q.withdraw("second", expected_head=rig.head) == "released"
    assert direct_prepare(q, rig, tip).status == "empty"
    assert q.enqueue(rig.store, entry(rig, lane="third")) == "queued"
    refused("archived_completion", lambda: direct_prepare(q, rig, tip))
    assert backend.commits[receipt.commit].landing == receipt
    assert tuple(backend.lanes) == ("a",)


@pytest.mark.parametrize("failure", ["commit-exception", "commit-invalid", "health", "health-invalid"])
def test_prepare_completion_fault_skips_the_other_read_and_retries_after_restart(rig, failure):
    """A failed completion or health read returns the documented refusal and faults the queue."""
    passing(rig)
    backend = CountingIndexBackend()
    q = fresh_queue(rig, backend=backend)
    assert q.enqueue(rig.store, entry(rig)) == "queued"
    before = backend.state
    archives = dict(backend.commits)
    backend.fail = failure
    backend.reads.clear()
    refused("state_unavailable", lambda: direct_prepare(q, rig))
    if failure.startswith("commit-"):
        assert [kind for kind, _ in backend.reads] == ["commit"]
    else:
        assert [kind for kind, oid in backend.reads] == ["commit", "health"]
        assert all(oid == rig.head for _, oid in backend.reads)
    assert backend.state == before and backend.commits == archives
    held = list(backend.reads)
    refused("state_unavailable", lambda: direct_prepare(q, rig))
    assert backend.reads == held
    backend.fail = None
    restarted = fresh_queue(rig, backend=backend, initialize=False)
    assert restarted.restore_target(rig.store, mq.HostedResult(rig.base, True),
                                    read_target=lambda _: rig.base) == "green"
    backend.reads.clear()
    candidate = direct_prepare(restarted, rig)
    assert [kind for kind, oid in backend.reads] == ["commit", "health"]
    assert all(oid == rig.head for _, oid in backend.reads)
    assert candidate.status == "ready" and candidate.commit == rig.head


@pytest.mark.parametrize("archived", [False, True])
def test_concurrent_prepares_each_authenticate_one_completion(rig, archived):
    """Concurrent preparations each take one commit-index read and do not publish."""
    passing(rig)
    backend = CountingIndexBackend()
    q = fresh_queue(rig, backend=backend)
    assert q.enqueue(rig.store, entry(rig)) == "queued"
    receipt = None
    if archived:
        receipt = issue(q, rig, prepare(q, rig))
        assert q.observe_landed(rig.store, receipt, read_target=lambda _: receipt.commit) == "done"
        assert q.restore_target(rig.store, mq.HostedResult(rig.base, True),
                                read_target=lambda _: rig.base) == "green"
        assert q.enqueue(rig.store, entry(rig, lane="second")) == "queued"
    before = backend.state
    backend.reads.clear()
    barrier = Barrier(2)

    def plan(_):
        barrier.wait(timeout=10)
        if archived:
            refused("archived_completion", lambda: direct_prepare(q, rig))
            return "refused"
        return direct_prepare(q, rig)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(plan, range(2), timeout=30))
    kinds = [kind for kind, _ in backend.reads]
    assert q.issued is None and backend.state == before and not backend.dirty
    if archived:
        assert results == ["refused", "refused"]
        assert kinds == ["commit", "commit"]
        assert all(oid == receipt.commit for _, oid in backend.reads)
        assert backend.commits[rig.head].landing == receipt
    else:
        assert results[0] == results[1] and results[0].status == "ready"
        assert kinds == ["commit", "health", "commit", "health"]
        assert all(oid == rig.head for _, oid in backend.reads)
        assert backend.commits == {}


def test_concurrent_invalid_review_does_not_block_explicit_valid_admission(rig):
    passing(rig)
    q = fresh_queue(rig)
    original = entry(rig)
    invalid = replace(original, reviews=(replace(original.reviews[0], helpers_off=None),
                                         original.reviews[1]))
    barrier = Barrier(2)

    def admit(index):
        barrier.wait(timeout=10)
        if index:
            refused("not_reviewed", lambda: q.enqueue(rig.store, invalid))
            return "refused"
        return q.enqueue(rig.store, original)

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(admit, range(2), timeout=30)) == ["queued", "refused"]
    assert q.enqueue(rig.store, original) == "already"
    assert rig.backends[q].state.entries == (original,)


def test_concurrent_higher_red_and_ack_after_early_green_reports_pause(rig):
    q = queue(rig)
    passing(rig)
    receipt = issue(q, rig, prepare(q, rig))
    assert q.hosted_result(receipt.commit, passed=True) == "pending"
    barrier = Barrier(2)

    def deliver(index):
        barrier.wait(timeout=10)
        if index:
            return q.hosted_result(receipt.commit, passed=False, attempt=1)
        return q.observe_landed(rig.store, receipt, read_target=lambda _: receipt.commit)

    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(deliver, range(2), timeout=30))
    assert result[0] == "done" and result[1] in ("pending", "target-red")
    assert q.hosted_result(receipt.commit, passed=False, attempt=1) == "target-red"
    assert q.hosted_result(receipt.commit, passed=True, attempt=2) == "green"


def test_concurrent_advanced_landing_acknowledgements_require_restore(rig):
    q = queue(rig)
    passing(rig)
    receipt = issue(q, rig, prepare(q, rig))
    tip = git(rig.repo, "commit-tree", rig.tree, "-p", receipt.commit,
              data=b"concurrent outside advance\n").decode().strip()
    q.enqueue(rig.store, successor_entry(rig, parent=tip, lane="next"))
    barrier = Barrier(2)

    def acknowledge(_):
        barrier.wait(timeout=10)
        return q.observe_landed(rig.store, receipt, read_target=lambda _: tip)

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(acknowledge, range(2), timeout=30)) == ["already", "done"]
    assert q.prepare(rig.store, read_target=lambda _: tip, read_mode=lambda *args: "none",
                     identity=IDENTITY, now=100).status == "target-unobserved"
    q.restore_target(rig.store, mq.HostedResult(tip, True), read_target=lambda _: tip)
    assert prepare(q, rig, tip).status == "ready"


def test_fast_forward_runs_only_missing_leg_and_never_moves_refs(rig):
    q = queue(rig)
    before = shared_bytes(rig.repo)
    pending = prepare(q, rig)
    assert (pending.status, pending.commit, pending.tree, pending.missing_legs) == (
        "pending", rig.head, rig.tree, ("linux-3.9",))
    assert shared_bytes(rig.repo) == before
    passing(rig)
    ready = prepare(q, rig)
    assert ready.status == "ready" and ready.missing_legs == ()
    assert prepare(q, rig) == ready
    published = issue(q, rig, ready)
    assert replace(published, issuance=0) == ready
    assert published.issuance > 0


def test_merge_requires_both_legs_on_exact_combined_tree_and_replans_on_tip_move(rig):
    q = queue(rig)
    passing(rig)
    merged = prepare(q, rig, rig.other)
    assert merged.status == "pending" and merged.tree != rig.tree
    assert merged.missing_legs == mq.REQUIRED_LEGS
    raw = rig.store.object(merged.commit, "commit")
    assert ("parent " + rig.other + "\nparent " + rig.head).encode() in raw
    passing(rig, merged.tree, merged.commit, ("linux-3.12",))
    assert prepare(q, rig, rig.other).missing_legs == ("linux-3.9",)
    passing(rig, merged.tree, merged.commit)
    ready = prepare(q, rig, rig.other)
    assert ready.status == "ready"
    new_tip = commit(rig.repo, "c", b"c\n")
    refused("stale_candidate", lambda: q.revalidate(rig.store, ready,
        read_target=lambda _: new_tip, read_mode=lambda *args: "none", identity=IDENTITY, now=100))
    newer = prepare(q, rig, new_tip)
    assert newer.tree != merged.tree and newer.missing_legs == mq.REQUIRED_LEGS
    assert prepare(q, rig, new_tip) == newer


@pytest.mark.parametrize("change", ["same_session", "author", "helpers", "wrong_head", "wrong_tree", "reject", "missing"])
def test_review_admission_is_exact_independent_and_helpers_off(rig, change):
    passing(rig)
    original = entry(rig)
    first, second = original.reviews
    second = {"same_session": replace(second, session=first.session),
              "author": replace(second, session=original.author),
              "helpers": replace(second, helpers_off=False),
              "wrong_head": replace(second, commit=rig.base),
              "wrong_tree": replace(second, tree="a" * 40),
              "reject": replace(second, verdict="REJECT")}.get(change, second)
    item = replace(original, reviews=(first,) if change == "missing" else (first, second))
    q = fresh_queue(rig)
    refused("not_reviewed", lambda: q.enqueue(rig.store, item))
    assert prepare(q, rig).status == "empty"


def test_admission_needs_lane_tree_pass_and_retries_are_immutable(rig):
    q = fresh_queue(rig)
    refused("not_qualified", lambda: q.enqueue(rig.store, entry(rig)))
    passing(rig, legs=("linux-3.12",))
    assert q.enqueue(rig.store, entry(rig)) == "queued"
    assert q.enqueue(rig.store, entry(rig)) == "already"
    refused("request_conflict", lambda: q.enqueue(rig.store, entry(rig, author="another-writer")))


def test_parent_order_and_acknowledgement_are_observed_not_asserted(rig):
    passing(rig, legs=("linux-3.12",))
    q = fresh_queue(rig)
    q.enqueue(rig.store, successor_entry(rig, lane="child", parents=("a",)))
    assert prepare(q, rig).status == "blocked-by-parent"
    assert q.enqueue(rig.store, entry(rig)) == "queued"
    passing(rig)
    parent = prepare(q, rig)
    assert parent.lane == "a" and parent.status == "ready"
    parent = issue(q, rig, parent)
    refused("landing_unconfirmed", lambda: q.observe_landed(rig.store, parent, read_target=lambda _: rig.base))
    assert q.observe_landed(rig.store, parent, read_target=lambda _: rig.head) == "done"
    assert q.observe_landed(rig.store, parent, read_target=lambda _: rig.head) == "already"
    assert prepare(q, rig, rig.head).lane == "child"


def test_hosted_red_pauses_regular_lanes_and_prioritizes_repair(rig):
    q = queue(rig)
    passing(rig)
    first = issue(q, rig, prepare(q, rig))
    q.observe_landed(rig.store, first, read_target=lambda _: rig.head)
    assert q.hosted_result(rig.head, passed=False) == "target-red"
    q.enqueue(rig.store, entry(rig, lane="ordinary"))
    assert prepare(q, rig, rig.head).status == "target-red"
    q.enqueue(rig.store, successor_entry(rig, lane="repair", repair=True))
    assert prepare(q, rig, rig.head).lane == "repair"
    assert q.hosted_result(rig.base, passed=True) == "unapplied"
    q.restore_target(rig.store, mq.HostedResult(rig.head, False), read_target=lambda _: rig.head)
    assert q.hosted_result(rig.head, passed=True, attempt=1) == "green"


@pytest.mark.parametrize("mode,status", [("review", "awaiting-owner-review"), ("signature", "awaiting-owner-signature")])
def test_protected_modes_never_return_ready(rig, mode, status):
    q = queue(rig)
    passing(rig)
    assert prepare(q, rig, mode=mode).status == status


def test_policy_and_tip_are_rechecked_after_qualification(rig):
    q = queue(rig)
    passing(rig)
    tips = iter((rig.base, rig.other))
    refused("tip_moved", lambda: q.prepare(rig.store, read_target=lambda _: next(tips),
        read_mode=lambda *args: "none", identity=IDENTITY, now=100))
    modes = iter(("none", "review"))
    assert q.prepare(rig.store, read_target=lambda _: rig.base,
        read_mode=lambda *args: next(modes), identity=IDENTITY, now=100).status == "awaiting-owner-review"


def test_concurrent_duplicate_admission_and_prepare_have_one_candidate(rig):
    passing(rig)
    q = fresh_queue(rig)
    barrier = Barrier(2)

    def submit(_):
        barrier.wait(timeout=10)
        return q.enqueue(rig.store, entry(rig))

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(submit, range(2))) == ["already", "queued"]
        candidates = list(pool.map(lambda _: prepare(q, rig, rig.other), range(2)))
    assert candidates[0] == candidates[1]


@pytest.mark.parametrize("value", [None, [], "../escape", "a\nb", "x" * 257, "ghp_" + "x" * 36])
def test_invalid_target_is_fixed_refusal(value):
    refused("invalid_request", lambda: mq.MergeQueue(value))


def test_unsupported_platform_probe_precedes_store_access(monkeypatch):
    monkeypatch.setattr(mq, "descriptor_supported", lambda: False)
    q = mq.MergeQueue("integration")
    refused("unsupported_platform", lambda: q.enqueue(None, None))
    refused("unsupported_platform", lambda: q.prepare(None, read_target=None, read_mode=None, identity=None))


@pytest.mark.parametrize("phase", ["target", "mode"])
@pytest.mark.parametrize("error", [OSError, ValueError, TimeoutError, RuntimeError])
def test_reader_failures_are_fixed_refusals_and_retry_is_safe(rig, phase, error):
    q = queue(rig)

    def failed(*args):
        raise error("secret\nnever echo")

    refused("observation_failed", lambda: q.prepare(rig.store,
        read_target=failed if phase == "target" else lambda _: rig.base,
        read_mode=failed if phase == "mode" else lambda *args: "none", identity=IDENTITY, now=100))
    assert prepare(q, rig).status == "pending"


@pytest.mark.parametrize("before_ack", [True, False])
@pytest.mark.parametrize("passed", [True, False])
def test_hosted_red_is_retained_in_either_acknowledgement_order(rig, before_ack, passed):
    q = queue(rig)
    passing(rig)
    ready = prepare(q, rig)
    issued = q.revalidate(rig.store, ready, read_target=lambda _: rig.base,
                          read_mode=lambda *args: "none", identity=IDENTITY, now=100)
    if before_ack:
        q.hosted_result(issued.commit, passed=passed)
    assert q.observe_landed(rig.store, issued, read_target=lambda _: issued.commit) == "done"
    if not before_ack:
        q.hosted_result(issued.commit, passed=passed)
    q.enqueue(rig.store, successor_entry(rig, lane="ordinary"))
    assert prepare(q, rig, issued.commit).status == ("ready" if passed else "target-red")


@pytest.mark.parametrize("operation", ["enqueue", "withdraw", "prepare", "hosted", "restore", "result"])
def test_publication_receipt_survives_every_scheduling_invalidation(rig, operation):
    q = queue(rig)
    passing(rig)
    first = prepare(q, rig)
    first = q.revalidate(rig.store, first, read_target=lambda _: rig.base,
                         read_mode=lambda *args: "none", identity=IDENTITY, now=100)
    q.observe_landed(rig.store, first, read_target=lambda _: first.commit)
    other_tree = git(rig.repo, "rev-parse", rig.other + "^{tree}").decode().strip()
    passing(rig, other_tree, rig.other)
    q.enqueue(rig.store, entry(rig, lane="second", head=rig.other,
        reviews=tuple(mq.Review(s, rig.other, other_tree, "ACCEPT", True) for s in ("r1", "r2"))))
    q.enqueue(rig.store, entry(rig, lane="unrelated"))
    pending = prepare(q, rig, first.commit)
    passing(rig, pending.tree, pending.commit)
    ready = prepare(q, rig, first.commit)
    issued = q.revalidate(rig.store, ready, read_target=lambda _: first.commit,
                          read_mode=lambda *args: "none", identity=IDENTITY, now=100)
    if operation == "enqueue":
        q.enqueue(rig.store, entry(rig, lane="extra"))
    elif operation == "withdraw":
        q.withdraw("unrelated", expected_head=rig.head)
    elif operation == "prepare":
        assert prepare(q, rig, issued.commit).status == "reconciliation-required"
    elif operation == "hosted":
        q.hosted_result(first.commit, passed=True)
    elif operation == "restore":
        q.restore_target(rig.store, mq.HostedResult(issued.commit, False),
                         read_target=lambda _: issued.commit)
    else:
        unrelated = git(rig.repo, "commit-tree", rig.tree, "-p", rig.base,
                        data=b"unrelated result\n").decode().strip()
        q.hosted_result(unrelated, passed=False)
        q.reconcile_result(rig.store, unrelated, read_target=lambda _: issued.commit,
                           read_outcome=lambda result: "not_applied")
    assert q.observe_landed(rig.store, issued, read_target=lambda _: issued.commit) == "done"
    assert q.observe_landed(rig.store, issued, read_target=lambda _: issued.commit) == "already"


def test_deadline_and_capacity_refuse_without_consuming_queue(rig):
    passing(rig)
    q = fresh_queue(rig, capacity=1)
    q.enqueue(rig.store, entry(rig, deadline=99))
    assert prepare(q, rig).status == "deadline-passed"
    refused("queue_full", lambda: q.enqueue(rig.store, entry(rig, lane="b")))
    assert q.enqueue(rig.store, entry(rig, deadline=99)) == "already"


def test_conflict_has_no_candidate_or_worktree_effect(rig):
    commit(rig.repo, "a", b"conflicting\n")
    tip = git(rig.repo, "rev-parse", "HEAD").decode().strip()
    q = queue(rig)
    before = shared_bytes(rig.repo)
    result = prepare(q, rig, tip)
    assert result.status == "conflict" and result.commit is None
    assert shared_bytes(rig.repo) == before
    assert prepare(q, rig, tip) == result


def test_merged_landing_retry_is_exact_and_never_accepts_forged_fields(rig):
    q = queue(rig)
    pending = prepare(q, rig, rig.other)
    passing(rig, pending.tree, pending.commit)
    ready = issue(q, rig, prepare(q, rig, rig.other))
    q.observe_landed(rig.store, ready, read_target=lambda _: ready.commit)
    assert q.observe_landed(rig.store, ready, read_target=lambda _: ready.commit) == "already"
    refused("stale_candidate", lambda: q.observe_landed(rig.store,
        replace(ready, tree=rig.tree), read_target=lambda _: ready.commit))


def test_delayed_hosted_red_pauses_and_older_green_cannot_clear_newer_red(rig):
    q = queue(rig)
    passing(rig)
    first = issue(q, rig, prepare(q, rig))
    q.observe_landed(rig.store, first, read_target=lambda _: first.commit)
    other_tree = git(rig.repo, "rev-parse", rig.other + "^{tree}").decode().strip()
    passing(rig, other_tree, rig.other, ("linux-3.12",))
    q.enqueue(rig.store, entry(rig, lane="second", head=rig.other,
        reviews=tuple(mq.Review(s, rig.other, other_tree, "ACCEPT", True)
                      for s in ("r1", "r2"))))
    second = prepare(q, rig, first.commit)
    passing(rig, second.tree, second.commit)
    second = issue(q, rig, prepare(q, rig, first.commit))
    q.observe_landed(rig.store, second, read_target=lambda _: second.commit)
    assert q.hosted_result(first.commit, passed=False) == "target-red"
    assert q.hosted_result(second.commit, passed=False) == "target-red"
    assert q.hosted_result(first.commit, passed=True, attempt=1) == "target-red"
    assert q.hosted_result(second.commit, passed=True, attempt=1) == "green"
    assert q.hosted_result(first.commit, passed=False) == "stale"


def test_already_integrated_lane_is_refused_without_remerging(rig):
    git(rig.repo, "merge", "--no-edit", "lane/a")
    tip = git(rig.repo, "rev-parse", "HEAD").decode().strip()
    q = queue(rig)
    refused("already_integrated", lambda: prepare(q, rig, tip))
    refused("already_integrated", lambda: prepare(q, rig, tip))


def test_final_policy_check_uses_exact_merge_commit(rig):
    q = queue(rig)
    q.restore_target(rig.store, mq.HostedResult(rig.other, True), read_target=lambda _: rig.other)
    result = q.prepare(rig.store, read_target=lambda _: rig.other,
        read_mode=lambda target, tip, head: "none" if head == rig.head else "review",
        identity=IDENTITY, now=100)
    assert result.status == "awaiting-owner-review"


def test_parent_cycles_are_rejected_and_retry_keeps_existing_order(rig):
    q = queue(rig, parents=("b",))
    refused("parent_cycle", lambda: q.enqueue(rig.store, entry(rig, lane="b", parents=("a",))))
    assert prepare(q, rig).status == "blocked-by-parent"
    q.enqueue(rig.store, entry(rig, lane="b"))
    assert prepare(q, rig).lane == "b"


def test_enqueue_cycle_refuses_and_open_prefix_restores(rig):
    """Admission refuses parent_cycle; an open external prefix reopens and then retries."""
    passing(rig, legs=("linux-3.12",))
    q = fresh_queue(rig)
    first = entry(rig, lane="a", parents=("c",))
    second = entry(rig, lane="b", parents=("a",))
    closing = entry(rig, lane="c", parents=("b",))
    assert q.enqueue(rig.store, first) == "queued"
    assert q.enqueue(rig.store, second) == "queued"
    refused("parent_cycle", lambda: q.enqueue(rig.store, closing))
    refused("parent_cycle", lambda: q.enqueue(rig.store, closing))
    assert {item.lane for item in rig.backends[q].state.entries} == {"a", "b"}

    restarted = fresh_queue(rig, backend=rig.backends[q], initialize=False)
    assert prepare(restarted, rig).status == "blocked-by-parent"
    before = rig.backends[restarted].state
    barrier = Barrier(2)

    def close(_):
        barrier.wait(timeout=10)
        try:
            return restarted.enqueue(rig.store, closing)
        except mq.QueueRefused as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(close, (0, 1))) == ["parent_cycle", "parent_cycle"]
    assert rig.backends[restarted].state == before
    opened = replace(closing, parents=())
    assert restarted.enqueue(rig.store, opened) == "queued"
    assert restarted.enqueue(rig.store, opened) == "already"
    assert prepare(restarted, rig).lane == "c"
    assert {item.lane for item in rig.backends[restarted].state.entries} == {"a", "b", "c"}


def test_restart_refuses_cyclic_checkpoint_and_retries_acyclic_graph(rig):
    """A durable cycle is state_unavailable; repairing it reopens the external parents."""
    passing(rig, legs=("linux-3.12",))
    q = fresh_queue(rig)
    keep = entry(rig, lane="keep", parents=("outside",))
    assert q.enqueue(rig.store, keep) == "queued"
    restarted = fresh_queue(rig, backend=rig.backends[q], initialize=False)
    assert restarted.enqueue(rig.store, keep) == "already"
    assert prepare(restarted, rig).status == "blocked-by-parent"

    backend = rig.backends[q]
    left = entry(rig, lane="left", parents=("right",))
    right = entry(rig, lane="right", parents=("left",))
    backend.state = replace(backend.state, entries=(keep, left, right))
    recovered = json_round_trip_backend(backend)
    before = recovered.state
    barrier = Barrier(2)

    def reopen(_):
        barrier.wait(timeout=10)
        try:
            fresh_queue(rig, backend=recovered, initialize=False)
            return "opened"
        except mq.QueueRefused as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(reopen, (0, 1))) == ["state_unavailable", "state_unavailable"]
    refused("state_unavailable", lambda: fresh_queue(rig, backend=recovered, initialize=False))
    assert recovered.state == before

    recovered.state = replace(recovered.state, entries=(keep, left, replace(right, parents=("new",))))
    repaired = fresh_queue(rig, backend=recovered, initialize=False)
    assert {item.lane for item in rig.backends[repaired].state.entries} == {"keep", "left", "right"}
    joining = entry(rig, lane="new", parents=("left",))
    refused("parent_cycle", lambda: repaired.enqueue(rig.store, joining))
    assert repaired.enqueue(rig.store, replace(joining, parents=())) == "queued"
    assert prepare(repaired, rig).lane == "new"


def test_reloaded_cycle_refuses_issued_check_until_repaired_restart(rig):
    """check_issued reloads through the same restore validation as restart."""
    q = queue(rig)
    passing(rig)
    receipt = issue(q, rig, prepare(q, rig))
    backend = rig.backends[q]
    record = backend.state.issued
    left = entry(rig, lane="left", parents=("right",))
    right = entry(rig, lane="right", parents=("left",))
    backend.state = replace(backend.state, entries=(record.entry, left, right))
    refused("state_unavailable", lambda: q.check_issued(
        rig.store, receipt, read_target=lambda _: rig.base, read_mode=lambda *args: "none", now=100))
    refused("state_unavailable", lambda: q.check_issued(
        rig.store, receipt, read_target=lambda _: rig.base, read_mode=lambda *args: "none", now=100))
    backend.state = replace(backend.state, entries=(record.entry, left, replace(right, parents=("outside",))))
    restarted = fresh_queue(rig, backend=backend, initialize=False)
    restarted.restore_target(rig.store, mq.HostedResult(rig.base, True), read_target=lambda _: rig.base)
    assert restarted.check_issued(rig.store, receipt, read_target=lambda _: rig.base,
                                  read_mode=lambda *args: "none", now=100) is True


@pytest.mark.parametrize("kwargs", [
    {"required_legs": ()}, {"required_legs": ("linux-3.12",)},
    {"required_legs": mq.REQUIRED_LEGS * 2}, {"required_legs": ["linux-3.12", "linux-3.9"]},
    {"entry_legs": ("../escape",)}, {"entry_legs": ("missing",)},
    {"required_legs": ("x",) * 33}, {"capacity": 0}, {"capacity": True},
    {"capacity": mq.MAX_ENTRIES + 1},
])
def test_configuration_bounds_refuse_before_git(kwargs):
    refused("invalid_request", lambda: mq.MergeQueue("integration", **kwargs))


@pytest.mark.parametrize("changes", [
    {"parents": ["b"]}, {"parents": ("b",) * 33}, {"parents": ("a",)},
    {"parents": ("b", "b")}, {"parents": ("../escape",)}, {"repair": 1},
    {"deadline": True}, {"deadline": -1}, {"deadline": 2**63},
    {"head": "a" * 41}, {"author": "x\ny"}, {"lane": "x" * 64},
])
def test_entry_bounds_and_types_refuse_without_admission(rig, changes):
    q = fresh_queue(rig)
    refused("invalid_request", lambda: q.enqueue(rig.store, entry(rig, **changes)))
    assert prepare(q, rig).status == "empty"


@pytest.mark.parametrize("tip,mode", [(None, "none"), ("x" * 41, "none"), ("a" * 40, None), ("a" * 40, "legacy")])
def test_malformed_observations_refuse_without_candidate(rig, tip, mode):
    q = queue(rig)
    refused("observation_failed", lambda: q.prepare(rig.store, read_target=lambda _: tip,
        read_mode=lambda *args: mode, identity=IDENTITY, now=100))


def test_landing_qualification_and_target_are_rechecked(rig):
    q = queue(rig)
    passing(rig)
    ready = prepare(q, rig)
    git(rig.repo, "update-ref", "-d", qual.qualification_ref(rig.tree, "linux-3.9"))
    refused("stale_candidate", lambda: issue(q, rig, ready))
    assert prepare(q, rig).status == "pending"
    refused("stale_candidate", lambda: q.observe_landed(rig.store, ready, read_target=lambda _: ready.commit))


def test_hosted_red_invalidates_a_previously_ready_regular_candidate(rig):
    q = queue(rig)
    passing(rig)
    first = issue(q, rig, prepare(q, rig))
    q.observe_landed(rig.store, first, read_target=lambda _: first.commit)
    q.enqueue(rig.store, successor_entry(rig, lane="next"))
    ready = prepare(q, rig, rig.head)
    q.hosted_result(rig.head, passed=False)
    refused("stale_candidate", lambda: q.observe_landed(rig.store, ready, read_target=lambda _: ready.commit))
    assert prepare(q, rig).status == "target-red"


def test_withdraw_uses_expected_head_and_invalidates_candidate_before_resubmission(rig):
    q = queue(rig, deadline=99)
    refused("request_conflict", lambda: q.withdraw("a", expected_head=rig.other))
    assert q.withdraw("a", expected_head=rig.head) == "released"
    assert q.withdraw("a", expected_head=rig.head) == "already"
    assert prepare(q, rig).status == "empty"
    passing(rig)
    q.enqueue(rig.store, entry(rig))
    ready = prepare(q, rig)
    q.withdraw("a", expected_head=rig.head)
    refused("stale_candidate", lambda: q.observe_landed(rig.store, ready, read_target=lambda _: ready.commit))


def test_concurrent_landing_observations_acknowledge_once(rig):
    q = queue(rig)
    passing(rig)
    ready = issue(q, rig, prepare(q, rig))
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: q.observe_landed(rig.store, ready,
            read_target=lambda _: ready.commit), range(2)))
    assert sorted(results) == ["already", "done"]
    assert prepare(q, rig).status == "empty"


def test_merge_driver_is_refused_without_running_repository_code(rig):
    q = queue(rig)
    marker = rig.repo / "driver-ran"
    git(rig.repo, "config", "merge.hostile.driver", "echo unsafe > driver-ran")
    (rig.repo / ".git" / "info" / "attributes").write_text("* merge=hostile\n")
    refused("git_failed", lambda: prepare(q, rig, rig.other))
    assert not marker.exists()
    git(rig.repo, "config", "--unset", "merge.hostile.driver")
    (rig.repo / ".git" / "info" / "attributes").write_text("")
    assert prepare(q, rig, rig.other).status == "pending"


@pytest.mark.parametrize("message,accepted", [
    ("chore: approve governance state\n\nAegis-Approve: " + "a" * 64 + "\n", True),
    ("chore: ordinary empty commit\n", False),
    ("chore: approve governance state\n\nAegis-Approve: " + "a" * 32 + "\n " + "a" * 32 + "\n", False),
])
def test_only_structural_empty_approval_carries_reviews_to_a_new_head(rig, message, accepted):
    passing(rig, legs=("linux-3.12",))
    head = git(rig.repo, "commit-tree", rig.tree, "-p", rig.head, data=message.encode()).decode().strip()
    q = fresh_queue(rig)
    item = entry(rig, head=head)
    if accepted:
        assert q.enqueue(rig.store, item) == "queued"
        assert q.enqueue(rig.store, item) == "already"
        assert prepare(q, rig).commit == head
    else:
        refused("not_reviewed", lambda: q.enqueue(rig.store, item))
        assert prepare(q, rig).status == "empty"


def test_malformed_candidate_fields_refuse_without_python_type_errors(rig):
    q = fresh_queue(rig)
    candidate = mq.Landing("ready", "a", rig.base, rig.head, rig.tree)
    for changes in ({"lane": []}, {"lane": {}}, {"status": []}, {"tip": []},
                    {"commit": None}, {"tree": "x" * 41}, {"missing_legs": ["linux-3.9"]}):
        malformed = replace(candidate, **changes)
        refused("stale_candidate", lambda: q.observe_landed(rig.store, malformed,
            read_target=lambda _: rig.head))
        refused("stale_candidate", lambda: q.revalidate(rig.store, malformed,
            read_target=lambda _: rig.base, read_mode=lambda *args: "none", identity=IDENTITY))


@pytest.mark.parametrize("ancestor", [True, False])
def test_ancestry_uses_public_read_for_published_commits(rig, monkeypatch, ancestor):
    q = queue(rig)
    tip = rig.base if ancestor else rig.other
    for oid in (tip, rig.head):
        git(rig.repo, "cat-file", "-e", oid + "^{commit}")
    q.restore_target(rig.store, mq.HostedResult(tip, True), read_target=lambda _: tip)
    calls, original = [], mq.gitsafe

    def read(args, cwd, **kwargs):
        calls.append((tuple(args), cwd, kwargs))
        return original.run(args, cwd, **kwargs)

    monkeypatch.setattr(mq, "gitsafe", SimpleNamespace(**{**vars(original), "run": read}))
    candidate = prepare(q, rig, tip)
    assert candidate.status == "pending"
    assert (candidate.commit == rig.head) is ancestor
    expected = [("merge-base", "--is-ancestor", tip, rig.head)]
    if not ancestor:
        expected.append(("merge-base", "--is-ancestor", rig.head, tip))
    assert [args for args, _, _ in calls] == expected
    assert all(cwd == rig.repo and not kwargs for _, cwd, kwargs in calls)
    assert prepare(q, rig, tip) == candidate


@pytest.mark.parametrize("failure", ["exit", "git", "timeout", "limit", "os"])
def test_ancestry_read_failures_refuse_without_echo_and_retry_safely(rig, monkeypatch, failure):
    q = queue(rig)
    original, calls = mq.gitsafe, []

    def failed(args, cwd):
        calls.append(tuple(args))
        if failure == "exit":
            return SimpleNamespace(returncode=2)
        if failure == "os":
            raise OSError("untrusted diagnostic must not escape")
        code = {"git": "git_failed", "timeout": "git_timeout", "limit": "git_output_limit"}[failure]
        raise original.GitError("untrusted diagnostic must not escape", code=code)

    real_run = original.run
    monkeypatch.setattr("aegis_core.gitsafe.run", failed)
    try:
        refused("git_failed", lambda: prepare(q, rig))
        refused("git_failed", lambda: prepare(q, rig))
    finally:
        monkeypatch.setattr("aegis_core.gitsafe.run", real_run)
    assert calls == [("merge-base", "--is-ancestor", rig.base, rig.head)] * 2
    assert prepare(q, rig).status == "pending"


def test_restart_restores_red_target_and_issued_early_result(rig):
    q = queue(rig)
    passing(rig)
    published = issue(q, rig, prepare(q, rig))
    q.hosted_result(published.commit, passed=False)
    restarted = fresh_queue(rig, backend=rig.backends[q], initialize=False)
    assert restarted.issued == published
    assert prepare(restarted, rig).status == "reconciliation-required"
    restarted.observe_landed(rig.store, published, read_target=lambda _: published.commit)
    again = fresh_queue(rig, backend=rig.backends[q], initialize=False)
    again.enqueue(rig.store, entry(rig, lane="ordinary"))
    assert prepare(again, rig, published.commit).status == "target-red"


def test_fresh_queue_requires_authenticated_current_target_health(rig):
    q = fresh_queue(rig, initialize=False)
    passing(rig)
    q.enqueue(rig.store, entry(rig))
    assert q.prepare(rig.store, read_target=lambda _: rig.base,
        read_mode=lambda *args: "none", identity=IDENTITY).status == "target-unobserved"
    q.restore_target(rig.store, mq.HostedResult(rig.base, False), read_target=lambda _: rig.base)
    assert prepare(q, rig).status == "target-red"


@pytest.mark.parametrize("failure", ["before", "after"])
def test_issuance_storage_failure_never_grants_publication_and_restart_reconciles(rig, failure):
    q = queue(rig)
    passing(rig)
    ready = prepare(q, rig)
    backend = rig.backends[q]
    backend.fail = failure
    refused("state_unavailable", lambda: issue(q, rig, ready))
    refused("state_unavailable", lambda: prepare(q, rig))
    backend.fail = None
    restarted = fresh_queue(rig, backend=backend, initialize=False)
    if failure == "after":
        assert restarted.issued is not None
        assert prepare(restarted, rig).status == "reconciliation-required"
        refused("landing_unconfirmed", lambda: restarted.reconcile_not_landed(rig.store,
            restarted.issued, read_target=lambda _: rig.base, read_outcome=lambda receipt: "unknown"))
        assert restarted.reconcile_not_landed(rig.store, restarted.issued,
            read_target=lambda _: rig.base, read_outcome=lambda receipt: "not_applied") == "not_applied"
    restarted.restore_target(rig.store, mq.HostedResult(rig.base, True), read_target=lambda _: rig.base)
    assert prepare(restarted, rig).status == "ready"


def test_pending_receipt_blocks_withdraw_and_second_publication_until_reconciliation(rig):
    q = queue(rig)
    passing(rig)
    ready = prepare(q, rig)
    published = issue(q, rig, ready)
    refused("issued_unresolved", lambda: q.withdraw("a", expected_head=rig.head))
    refused("issued_unresolved", lambda: issue(q, rig, ready))
    assert prepare(q, rig).status == "reconciliation-required"
    q.reconcile_not_landed(rig.store, published, read_target=lambda _: rig.base,
                           read_outcome=lambda receipt: "not_applied")
    next_issue = issue(q, rig, prepare(q, rig))
    assert next_issue.issuance > published.issuance
    refused("stale_candidate", lambda: q.observe_landed(rig.store, published,
        read_target=lambda _: published.commit))


def test_completed_archive_does_not_exhaust_pending_capacity_or_forget_ids(rig, monkeypatch):
    monkeypatch.setattr(mq, "MAX_ENTRIES", 2)
    q = fresh_queue(rig, capacity=1)
    passing(rig)
    tip = rig.base
    first = entry(rig, lane="lane-0")
    for index in range(4):
        item = first if index == 0 else successor_entry(rig, parent=tip, lane="lane-%d" % index)
        q.enqueue(rig.store, item)
        published = issue(q, rig, prepare(q, rig, tip))
        q.observe_landed(rig.store, published, read_target=lambda _: published.commit)
        tip = published.commit
    restarted = fresh_queue(rig, backend=rig.backends[q], capacity=1, initialize=False)
    assert restarted.enqueue(rig.store, first) == "already"
    refused("request_conflict", lambda: restarted.enqueue(rig.store, replace(first, author="other")))
    restarted.enqueue(rig.store, successor_entry(rig, parent=tip, lane="child", parents=("lane-0",)))
    restarted.restore_target(rig.store, mq.HostedResult(tip, True), read_target=lambda _: tip)
    assert prepare(restarted, rig, tip).lane == "child"


def test_concurrent_hosted_result_and_acknowledgement_keep_the_failure(rig):
    q = queue(rig)
    passing(rig)
    published = issue(q, rig, prepare(q, rig))
    barrier = Barrier(2)

    def act(index):
        barrier.wait(timeout=10)
        if index:
            return q.hosted_result(published.commit, passed=False)
        return q.observe_landed(rig.store, published, read_target=lambda _: published.commit)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(act, range(2), timeout=30))
    q.enqueue(rig.store, entry(rig, lane="ordinary"))
    assert prepare(q, rig, published.commit).status == "target-red"


def test_restart_cannot_use_stale_green_after_a_failed_result_write(rig):
    q = queue(rig)
    passing(rig)
    backend = rig.backends[q]
    backend.fail = "before"
    refused("state_unavailable", lambda: q.hosted_result(rig.base, passed=False))
    backend.fail = None
    restarted = fresh_queue(rig, backend=backend, initialize=False)
    assert restarted.prepare(rig.store, read_target=lambda _: rig.base,
        read_mode=lambda *args: "none", identity=IDENTITY).status == "target-unobserved"
    restarted.restore_target(rig.store, mq.HostedResult(rig.base, False), read_target=lambda _: rig.base)
    assert prepare(restarted, rig).status == "target-red"


@pytest.mark.parametrize("failure", ["before", "after"])
def test_acknowledgement_storage_failure_preserves_reconciliation_and_archive(rig, failure):
    q = queue(rig)
    passing(rig)
    published = issue(q, rig, prepare(q, rig))
    q.hosted_result(published.commit, passed=False)
    backend = rig.backends[q]
    backend.fail = failure
    refused("state_unavailable", lambda: q.observe_landed(rig.store, published,
        read_target=lambda _: published.commit))
    assert q.issued == published
    backend.fail = None
    restarted = fresh_queue(rig, backend=backend, initialize=False)
    assert restarted.observe_landed(rig.store, published, read_target=lambda _: published.commit) == (
        "done" if failure == "before" else "already")
    assert len(backend.lanes) == 1
    restarted.enqueue(rig.store, entry(rig, lane="ordinary"))
    assert prepare(restarted, rig, published.commit).status == "target-red"


def test_unknown_hosted_result_blocks_until_authenticated_target_reconciliation(rig):
    q = queue(rig)
    passing(rig)
    assert q.hosted_result(rig.other, passed=False) == "unapplied"
    assert prepare(q, rig).status == "unapplied-results"
    q.restore_target(rig.store, mq.HostedResult(rig.other, False), read_target=lambda _: rig.other)
    assert prepare(q, rig, rig.other).status == "target-red"


def test_not_landed_requires_settled_proof_and_refuses_a_conflicting_hosted_result(rig):
    q = queue(rig)
    passing(rig)
    published = issue(q, rig, prepare(q, rig))
    refused("landing_unconfirmed", lambda: q.reconcile_not_landed(rig.store, published,
        read_target=lambda _: rig.base, read_outcome=lambda receipt: "unknown"))
    q.hosted_result(published.commit, passed=False)
    refused("state_conflict", lambda: q.reconcile_not_landed(rig.store, published,
        read_target=lambda _: rig.base, read_outcome=lambda receipt: "not_applied"))
    assert q.issued == published


@pytest.mark.parametrize("results", [(True, False), (False, True)])
def test_same_attempt_contradiction_is_red_in_any_delivery_order(rig, results):
    q = queue(rig)
    passing(rig)
    published = issue(q, rig, prepare(q, rig))
    for passed in results:
        q.hosted_result(published.commit, passed=passed)
    q.observe_landed(rig.store, published, read_target=lambda _: published.commit)
    q.enqueue(rig.store, entry(rig, lane="ordinary"))
    assert prepare(q, rig, published.commit).status == "target-red"
    assert q.hosted_result(published.commit, passed=True, attempt=1) == "green"


def test_issued_reconciliation_survives_qualification_evidence_retirement(rig):
    q = queue(rig)
    passing(rig)
    published = issue(q, rig, prepare(q, rig))
    git(rig.repo, "update-ref", "-d", qual.qualification_ref(published.tree, "linux-3.9"))
    assert q.observe_landed(rig.store, published, read_target=lambda _: published.commit) == "done"


def test_stale_service_instance_cannot_overwrite_checkpoint(rig):
    q = queue(rig)
    backend = rig.backends[q]
    stale = fresh_queue(rig, backend=backend, initialize=False)
    q.enqueue(rig.store, entry(rig, lane="new"))
    refused("state_unavailable", lambda: stale.enqueue(rig.store, entry(rig, lane="stale")))
    assert {item.lane for item in backend.state.entries} == {"a", "new"}


def test_no_storage_port_never_issues_a_candidate(rig):
    q = mq.MergeQueue("integration")
    refused("state_unavailable", lambda: q.enqueue(rig.store, entry(rig)))


@pytest.mark.parametrize("field", ["entries", "results", "health", "target", "red"])
def test_malformed_loaded_state_is_a_fixed_refusal(rig, field):
    q = queue(rig)
    backend = rig.backends[q]
    changes = {"entries": {"entries": (entry(rig),) * (mq.MAX_ENTRIES + 1)},
               "results": {"results": (mq.HostedResult(rig.base, True),) * (mq.MAX_RESULTS + 1)},
               "health": {"health_commit": []}, "target": {"target": "other"},
               "red": {"red": False, "red_order": backend.state.serial, "green_order": 0}}[field]
    backend.state = replace(backend.state, **changes)
    refused("state_unavailable", lambda: fresh_queue(rig, backend=backend, initialize=False))


@pytest.mark.parametrize("key", ["lane", "commit", "pending"])
def test_archive_bindings_are_checked_before_replay_or_dependency_admission(rig, key):
    q = queue(rig)
    passing(rig)
    published = issue(q, rig, prepare(q, rig))
    q.observe_landed(rig.store, published, read_target=lambda _: published.commit)
    backend = rig.backends[q]
    if key == "lane":
        backend.lanes["missing"] = backend.lanes["a"]
        q.enqueue(rig.store, entry(rig, lane="child", parents=("missing",)))
        refused("state_unavailable", lambda: prepare(q, rig, published.commit))
    elif key == "commit":
        backend.commits[rig.other] = backend.lanes["a"]
        refused("state_unavailable", lambda: q.hosted_result(rig.other, passed=False))
    else:
        backend.state = replace(backend.state, entries=(entry(rig),))
        refused("state_unavailable", lambda: fresh_queue(rig, backend=backend, initialize=False))


def test_concurrent_revalidation_issues_one_unique_receipt(rig):
    q = queue(rig)
    passing(rig)
    ready = prepare(q, rig)
    barrier = Barrier(2)

    def run(_):
        barrier.wait(timeout=10)
        try:
            return issue(q, rig, ready)
        except mq.QueueRefused as exc:
            assert exc.code == "issued_unresolved"
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(pool.map(run, range(2), timeout=30))
    assert sum(receipt is not None for receipt in receipts) == 1
    assert q.issued == next(receipt for receipt in receipts if receipt is not None)


@pytest.mark.parametrize("reason,code", [("red", "target_red"), ("policy", "policy_refused"),
    ("missing_leg", "not_qualified"), ("early_result", "issued_unresolved"),
    ("deadline", "deadline_passed")])
def test_issued_eligibility_can_be_revoked_without_erasing_reconciliation(rig, reason, code):
    q = queue(rig, deadline=101)
    passing(rig)
    published = issue(q, rig, prepare(q, rig))
    assert q.check_issued(rig.store, published, read_target=lambda _: rig.base,
        read_mode=lambda *args: "none", now=100) is True
    if reason == "red":
        q.restore_target(rig.store, mq.HostedResult(rig.base, False), read_target=lambda _: rig.base)
    elif reason == "missing_leg":
        git(rig.repo, "update-ref", "-d", qual.qualification_ref(published.tree, "linux-3.9"))
    elif reason == "early_result":
        q.hosted_result(published.commit, passed=False)
    refused(code, lambda: q.check_issued(rig.store, published, read_target=lambda _: rig.base,
        read_mode=lambda *args: "review" if reason == "policy" else "none",
        now=102 if reason == "deadline" else 100))
    assert q.issued == published
    assert q.observe_landed(rig.store, published, read_target=lambda _: published.commit) == "done"


def test_restart_requires_target_authentication_before_issued_eligibility(rig):
    q = queue(rig)
    passing(rig)
    published = issue(q, rig, prepare(q, rig))
    restarted = fresh_queue(rig, backend=rig.backends[q], initialize=False)
    refused("observation_failed", lambda: restarted.check_issued(rig.store, published,
        read_target=lambda _: rig.base, read_mode=lambda *args: "none", now=100))
    restarted.restore_target(rig.store, mq.HostedResult(rig.base, True), read_target=lambda _: rig.base)
    assert restarted.check_issued(rig.store, published, read_target=lambda _: rig.base,
        read_mode=lambda *args: "none", now=100) is True


def test_acknowledging_ancestor_preserves_descendant_red_across_restart(rig):
    q = queue(rig)
    passing(rig)
    published = issue(q, rig, prepare(q, rig))
    descendant = git(rig.repo, "commit-tree", rig.tree, "-p", published.commit,
                     data=b"descendant\n").decode().strip()
    q.restore_target(rig.store, mq.HostedResult(descendant, False, 1),
                     read_target=lambda _: descendant)
    q.observe_landed(rig.store, published, read_target=lambda _: descendant)
    restarted = fresh_queue(rig, backend=rig.backends[q], initialize=False)
    assert restarted.restore_target(rig.store, mq.HostedResult(descendant, True, 0),
                                     read_target=lambda _: descendant) == "target-red"
    restarted.enqueue(rig.store, entry(rig, lane="ordinary"))
    assert prepare(restarted, rig, descendant).status == "target-red"
    assert restarted.hosted_result(descendant, passed=True, attempt=1) == "target-red"
    assert restarted.hosted_result(descendant, passed=True, attempt=2) == "green"


@pytest.mark.parametrize("archived", [True, False])
def test_restoration_merges_all_same_revision_copies(rig, archived):
    q = queue(rig)
    passing(rig)
    first = issue(q, rig, prepare(q, rig))
    if archived:
        q.observe_landed(rig.store, first, read_target=lambda _: first.commit)
        q.hosted_result(first.commit, passed=True)
        q.enqueue(rig.store, successor_entry(rig, lane="duplicate"))
        issue(q, rig, prepare(q, rig, first.commit))
        q.hosted_result(first.commit, passed=False, attempt=1)
    else:
        q.restore_target(rig.store, mq.HostedResult(first.commit, False, 1),
                         read_target=lambda _: first.commit)
    assert q.restore_target(rig.store, mq.HostedResult(first.commit, True, 0),
                            read_target=lambda _: first.commit) == "target-red"


@pytest.mark.parametrize("restart", [True, False])
def test_not_applied_receipt_reconciles_after_unrelated_target_advance(rig, restart):
    q = queue(rig)
    passing(rig)
    published = issue(q, rig, prepare(q, rig))
    if restart:
        q = fresh_queue(rig, backend=rig.backends[q], initialize=False)
    assert q.reconcile_not_landed(rig.store, published, read_target=lambda _: rig.other,
                                  read_outcome=lambda receipt: "not_applied") == "not_applied"
    assert q.issued is None
    q.restore_target(rig.store, mq.HostedResult(rig.other, True), read_target=lambda _: rig.other)
    assert prepare(q, rig, rig.other).status == "pending"


@pytest.mark.parametrize("ingestion", ["hosted", "restore"])
@pytest.mark.parametrize("failure", ["exception", "invalid"])
def test_archive_read_failure_retains_red_and_faults_publication(rig, ingestion, failure):
    q = queue(rig)
    passing(rig)
    ready = prepare(q, rig)
    backend = rig.backends[q]

    backend.fail = "commit-" + failure
    if ingestion == "hosted":
        refused("state_unavailable", lambda: q.hosted_result(rig.base, passed=False))
    else:
        refused("state_unavailable", lambda: q.restore_target(rig.store,
            mq.HostedResult(rig.base, False), read_target=lambda _: rig.base))
    refused("state_unavailable", lambda: prepare(q, rig))
    refused("state_unavailable", lambda: issue(q, rig, ready))
    backend.fail = None
    restarted = fresh_queue(rig, backend=backend, initialize=False)
    assert restarted.restore_target(rig.store, mq.HostedResult(rig.base, True),
                                     read_target=lambda _: rig.base) == "target-red"
    assert prepare(restarted, rig).status == "target-red"
    refused("stale_candidate", lambda: issue(restarted, rig, ready))


@pytest.mark.parametrize("failure", ["before", "after", "begin", "health", "health-invalid"])
def test_failed_red_persist_cannot_be_cleared_by_stale_restore_after_restart(rig, failure):
    q = queue(rig)
    passing(rig)
    backend = rig.backends[q]
    backend.fail = failure
    refused("state_unavailable", lambda: q.hosted_result(rig.base, passed=False, attempt=1))
    backend.fail = None
    restarted = fresh_queue(rig, backend=backend, initialize=False)
    assert restarted.restore_target(rig.store, mq.HostedResult(rig.base, True, 0),
                                     read_target=lambda _: rig.base) == "target-red"


def test_proven_withdrawal_resolves_a_non_landed_receipt_with_hosted_evidence(rig):
    q = queue(rig)
    passing(rig)
    published = issue(q, rig, prepare(q, rig))
    q.hosted_result(published.commit, passed=False)
    refused("landing_unconfirmed", lambda: q.withdraw("a", expected_head=rig.head,
        store=rig.store, read_target=lambda _: rig.head, read_outcome=lambda receipt: "not_applied"))
    restarted = fresh_queue(rig, backend=rig.backends[q], initialize=False)
    assert restarted.withdraw("a", expected_head=rig.head, store=rig.store,
        read_target=lambda _: rig.other, read_outcome=lambda receipt: "not_applied") == "released"
    assert restarted.issued is None
    # Settling non-publication never deletes that revision's authenticated RED.
    assert restarted.restore_target(rig.store, mq.HostedResult(rig.head, True),
                                     read_target=lambda _: rig.head) == "target-red"


def test_revision_health_survives_nondescendant_target_changes(rig):
    q = queue(rig)
    q.restore_target(rig.store, mq.HostedResult(rig.head, False, 1), read_target=lambda _: rig.head)
    assert q.restore_target(rig.store, mq.HostedResult(rig.other, True, 1),
                            read_target=lambda _: rig.other) == "green"
    q = fresh_queue(rig, backend=rig.backends[q], initialize=False)
    assert q.restore_target(rig.store, mq.HostedResult(rig.head, True, 0),
                            read_target=lambda _: rig.head) == "target-red"


@pytest.mark.parametrize("already_issued", [True, False])
def test_other_instance_cannot_publish_through_a_durable_fault(rig, already_issued):
    q = queue(rig)
    passing(rig)
    candidate = prepare(q, rig)
    if already_issued:
        candidate = issue(q, rig, candidate)
    backend = rig.backends[q]
    observer = fresh_queue(rig, backend=backend, initialize=False)
    backend.fail = "before"
    refused("state_unavailable", lambda: observer.hosted_result(rig.base, passed=False))
    backend.fail = None
    if already_issued:
        refused("issued_unresolved", lambda: q.check_issued(rig.store, candidate,
            read_target=lambda _: rig.base, read_mode=lambda *args: "none", now=100))
    else:
        refused("state_unavailable", lambda: issue(q, rig, candidate))


def test_stale_instance_red_is_retained_even_when_its_generation_loses_cas(rig):
    q = queue(rig)
    passing(rig)
    backend = rig.backends[q]
    stale = fresh_queue(rig, backend=backend, initialize=False)
    q.enqueue(rig.store, entry(rig, lane="extra"))
    refused("state_unavailable", lambda: stale.hosted_result(rig.base, passed=False, attempt=1))
    restarted = fresh_queue(rig, backend=backend, initialize=False)
    assert restarted.restore_target(rig.store, mq.HostedResult(rig.base, True),
                                     read_target=lambda _: rig.base) == "target-red"


def test_failed_unknown_result_replays_as_unapplied_after_restart(rig):
    q = queue(rig)
    passing(rig)
    backend = rig.backends[q]
    backend.fail = "before"
    refused("state_unavailable", lambda: q.hosted_result(rig.other, passed=False, attempt=1))
    backend.fail = None
    restarted = fresh_queue(rig, backend=backend, initialize=False)
    restarted.restore_target(rig.store, mq.HostedResult(rig.base, True), read_target=lambda _: rig.base)
    assert prepare(restarted, rig).status == "unapplied-results"
    assert restarted.reconcile_result(rig.store, rig.other, read_target=lambda _: rig.base,
        read_outcome=lambda row: "not_applied") == "not_applied"
    assert prepare(restarted, rig).status == "ready"
    assert restarted.restore_target(rig.store, mq.HostedResult(rig.other, True),
        read_target=lambda _: rig.other) == "target-red"


@pytest.mark.parametrize("transition", ["enqueue", "withdraw", "issue", "acknowledge",
    "reconcile", "restore", "hosted", "result"])
@pytest.mark.parametrize("failure", ["before", "after"])
def test_every_transition_storage_fault_survives_restart(rig, transition, failure):
    q = queue(rig)
    passing(rig)
    candidate = prepare(q, rig)
    if transition in ("acknowledge", "reconcile"):
        candidate = issue(q, rig, candidate)
    if transition == "result":
        q.hosted_result(rig.other, passed=False)
    backend = rig.backends[q]
    backend.fail = failure
    actions = {
        "enqueue": lambda: q.enqueue(rig.store, entry(rig, lane="extra")),
        "withdraw": lambda: q.withdraw("a", expected_head=rig.head),
        "issue": lambda: issue(q, rig, candidate),
        "acknowledge": lambda: q.observe_landed(rig.store, candidate, read_target=lambda _: rig.head),
        "reconcile": lambda: q.reconcile_not_landed(rig.store, candidate,
            read_target=lambda _: rig.other, read_outcome=lambda row: "not_applied"),
        "restore": lambda: q.restore_target(rig.store, mq.HostedResult(rig.base, False),
            read_target=lambda _: rig.base),
        "hosted": lambda: q.hosted_result(rig.base, passed=False),
        "result": lambda: q.reconcile_result(rig.store, rig.other,
            read_target=lambda _: rig.base, read_outcome=lambda row: "not_applied"),
    }
    refused("state_unavailable", actions[transition])
    refused("state_unavailable", lambda: prepare(q, rig))
    backend.fail = None
    restarted = fresh_queue(rig, backend=backend, initialize=False)
    observation = restarted.prepare(rig.store, read_target=lambda _: rig.base,
        read_mode=lambda *args: "none", identity=IDENTITY, now=100)
    assert observation.status != "ready"
    # Even unrelated queue changes cannot settle the retained recovery marker.
    restarted.enqueue(rig.store, entry(rig, lane="after-fault"))
    assert restarted.prepare(rig.store, read_target=lambda _: rig.base,
        read_mode=lambda *args: "none", identity=IDENTITY, now=100).status != "ready"


@pytest.mark.parametrize("restart", [False, True])
def test_withdraw_reenqueue_preserves_candidate_red_at_publication_gates(rig, restart):
    q = queue(rig)
    passing(rig)
    candidate = prepare(q, rig)
    receipt = issue(q, rig, candidate)
    q.hosted_result(receipt.commit, passed=False, attempt=1)
    q.withdraw("a", expected_head=rig.head, store=rig.store,
               read_target=lambda _: rig.base, read_outcome=lambda row: "not_applied")
    if restart:
        q = fresh_queue(rig, backend=rig.backends[q], initialize=False)
    q.restore_target(rig.store, mq.HostedResult(rig.base, True), read_target=lambda _: rig.base)
    q.enqueue(rig.store, entry(rig))
    assert prepare(q, rig).status == "target-red"
    refused("target_red", lambda: issue(q, rig, candidate))
    q.hosted_result(rig.head, passed=True, attempt=1)
    q.reconcile_result(rig.store, rig.head, read_target=lambda _: rig.base,
                       read_outcome=lambda row: "not_applied")
    assert prepare(q, rig).status == "target-red"
    q.hosted_result(rig.head, passed=True, attempt=2)
    q.reconcile_result(rig.store, rig.head, read_target=lambda _: rig.base,
                       read_outcome=lambda row: "not_applied")
    receipt = issue(q, rig, prepare(q, rig))
    assert q.check_issued(rig.store, receipt, read_target=lambda _: rig.base,
        read_mode=lambda *args: "none", now=100) is True


@pytest.mark.parametrize("gate", ["prepare", "revalidate", "check_issued"])
def test_each_gate_reads_retained_candidate_health(rig, gate):
    q = queue(rig)
    passing(rig)
    candidate = prepare(q, rig)
    if gate == "check_issued":
        candidate = issue(q, rig, candidate)
    # The authenticated port may have a stronger record than this instance's
    # checkpoint/receipt copy (for example, a recovered prior issuance).
    rig.backends[q].healths[rig.head] = mq.HostedResult(rig.head, False, 1)
    if gate == "prepare":
        assert prepare(q, rig).status == "target-red"
    elif gate == "revalidate":
        refused("target_red", lambda: issue(q, rig, candidate))
    else:
        refused("target_red", lambda: q.check_issued(rig.store, candidate,
            read_target=lambda _: rig.base, read_mode=lambda *args: "none", now=100))


def result_subjects(rig):
    return tuple(git(rig.repo, "commit-tree", rig.tree, "-p", rig.base,
                     data=("result-%d\n" % index).encode()).decode().strip()
                 for index in range(mq.MAX_RESULTS + 1))


@pytest.mark.parametrize("ingestion", ["hosted", "restore"])
def test_result_capacity_refuses_before_intent_and_receipt_still_loads(rig, ingestion):
    q = queue(rig)
    passing(rig)
    receipt = issue(q, rig, prepare(q, rig))
    subjects = result_subjects(rig)
    for subject in subjects[:-1]:
        assert q.hosted_result(subject, passed=False) == "unapplied"
    backend, before = rig.backends[q], rig.backends[q].state
    if ingestion == "hosted":
        refused("state_capacity", lambda: q.hosted_result(subjects[-1], passed=False))
    else:
        refused("state_capacity", lambda: q.restore_target(rig.store,
            mq.HostedResult(subjects[-1], False), read_target=lambda _: rig.base))
    assert backend.state == before and not backend.dirty
    assert subjects[-1] not in backend.healths and not backend.pending
    restarted = fresh_queue(rig, backend=backend, initialize=False)
    assert restarted.reconcile_not_landed(rig.store, receipt, read_target=lambda _: rig.base,
        read_outcome=lambda row: "not_applied") == "not_applied"


@pytest.mark.parametrize("resolution", ["acknowledge", "reconcile", "withdraw"])
def test_over_capacity_replay_loads_and_receipt_is_resolvable(rig, resolution):
    q = queue(rig)
    passing(rig)
    receipt = issue(q, rig, prepare(q, rig))
    backend = rig.backends[q]
    subjects = result_subjects(rig)
    stale = fresh_queue(rig, backend=backend, initialize=False)
    for subject in subjects[:-1]:
        assert q.hosted_result(subject, passed=False) == "unapplied"
    # A stale authenticated observer loses CAS but must retain its RED, producing
    # an over-capacity recovery replay through the actual public ingestion path.
    refused("state_unavailable", lambda: stale.hosted_result(subjects[-1], passed=False))
    restarted = fresh_queue(rig, backend=backend, initialize=False)
    assert restarted.issued == receipt
    assert prepare(restarted, rig).status == "reconciliation-required"
    if resolution == "acknowledge":
        assert restarted.observe_landed(rig.store, receipt, read_target=lambda _: rig.head) == "done"
    elif resolution == "reconcile":
        assert restarted.reconcile_not_landed(rig.store, receipt, read_target=lambda _: rig.base,
            read_outcome=lambda row: "not_applied") == "not_applied"
    else:
        assert restarted.withdraw("a", expected_head=rig.head, store=rig.store,
            read_target=lambda _: rig.base, read_outcome=lambda row: "not_applied") == "released"
    again = fresh_queue(rig, backend=backend, initialize=False)
    assert again.issued is None
    assert prepare(again, rig).status != "ready"


def cached_merge_candidate(rig):
    passing(rig)
    base_tree = git(rig.repo, "rev-parse", rig.base + "^{tree}").decode().strip()
    tip = git(rig.repo, "commit-tree", base_tree, "-p", rig.base,
              data=b"divergent empty commit\n").decode().strip()
    q = queue(rig)
    git(rig.repo, "update-ref", "refs/heads/main", tip)
    q.restore_target(rig.store, mq.HostedResult(tip, True), read_target=lambda _: tip)
    candidate = prepare(q, rig, tip)
    assert candidate.status == "ready" and candidate.tree == rig.tree
    assert candidate.commit != rig.head
    return q, candidate, tip


@pytest.mark.parametrize("resolution", ["acknowledge", "reconcile", "withdraw"])
def test_cached_merge_issuance_survives_fresh_store_and_gc(rig, resolution):
    q, candidate, tip = cached_merge_candidate(rig)
    receipt = issue(q, rig, candidate)
    retained = git(rig.repo, "for-each-ref", "--format=%(objectname)", "refs/aegis/merge-queue/")
    assert retained.splitlines() == [receipt.commit.encode()]
    git(rig.repo, "gc", "--prune=now")
    with make_store(rig.repo) as fresh:
        assert fresh.scratch != rig.store.scratch
        assert not tuple((fresh.scratch / "objects").iterdir())
        assert fresh.object(receipt.commit, "commit") == rig.store.object(receipt.commit, "commit")
        restarted = fresh_queue(rig, backend=rig.backends[q], initialize=False)
        if resolution == "acknowledge":
            git(rig.repo, "update-ref", "refs/heads/main", receipt.commit)
            assert restarted.observe_landed(fresh, receipt, read_target=lambda _: receipt.commit) == "done"
        elif resolution == "reconcile":
            assert restarted.reconcile_not_landed(fresh, receipt, read_target=lambda _: rig.other,
                read_outcome=lambda row: "not_applied") == "not_applied"
        else:
            assert restarted.withdraw("a", expected_head=rig.head, store=fresh,
                read_target=lambda _: tip, read_outcome=lambda row: "not_applied") == "released"
    assert git(rig.repo, "for-each-ref", "--format=%(objectname)", "refs/aegis/merge-queue/") == b""


@pytest.mark.parametrize("failure", ["cleanup-before", "cleanup-after"])
@pytest.mark.parametrize("resolution", ["acknowledge", "reconcile", "withdraw"])
def test_ref_cleanup_checkpoint_failure_recovers_after_gc(rig, failure, resolution):
    q, candidate, tip = cached_merge_candidate(rig)
    receipt = issue(q, rig, candidate)
    if resolution == "acknowledge":
        git(rig.repo, "update-ref", "refs/heads/main", receipt.commit)
    backend = rig.backends[q]
    backend.fail = failure

    def resolve(instance, store):
        if resolution == "acknowledge":
            return instance.observe_landed(store, receipt, read_target=lambda _: receipt.commit)
        if resolution == "reconcile":
            return instance.reconcile_not_landed(store, receipt, read_target=lambda _: tip,
                read_outcome=lambda row: "not_applied")
        return instance.withdraw("a", expected_head=rig.head, store=store,
            read_target=lambda _: tip, read_outcome=lambda row: "not_applied")

    refused("state_unavailable", lambda: resolve(q, rig.store))
    refused("state_unavailable", lambda: prepare(q, rig))
    backend.fail = None
    git(rig.repo, "gc", "--prune=now")
    if resolution != "acknowledge":
        assert git(rig.repo, "cat-file", "--batch-check", data=(receipt.commit + "\n").encode()) == (
            receipt.commit + " missing\n").encode()
    with make_store(rig.repo) as fresh:
        assert not tuple((fresh.scratch / "objects").iterdir())
        restarted = fresh_queue(rig, backend=backend, initialize=False)
        if restarted.issued is not None:
            assert resolve(restarted, fresh) in ("already", "not_applied", "released")
        assert restarted.issued is None
    assert git(rig.repo, "for-each-ref", "--format=%(objectname)", "refs/aegis/merge-queue/") == b""


def test_lost_ref_delete_reply_keeps_cleanup_reconcilable(rig, monkeypatch):
    q = queue(rig)
    passing(rig)
    receipt = issue(q, rig, prepare(q, rig))
    real_update, calls = mq.gitsafe.update_ref, []

    def lost(*args, **kwargs):
        calls.append(args)
        real_update(*args, **kwargs)
        raise mq.gitsafe.GitError("private lost deletion reply", code="git_timeout")

    monkeypatch.setattr("aegis_core.gitsafe.update_ref", lost)
    refused("git_failed", lambda: q.reconcile_not_landed(rig.store, receipt,
        read_target=lambda _: rig.base, read_outcome=lambda row: "not_applied"))
    assert len(calls) == 1
    restarted = fresh_queue(rig, backend=rig.backends[q], initialize=False)
    assert restarted.issued == receipt
    assert restarted.reconcile_not_landed(rig.store, receipt, read_target=lambda _: rig.base,
        read_outcome=lambda row: "not_applied") == "not_applied"
    assert restarted.issued is None
    assert len(calls) == 1


def test_exhausted_issuance_counter_refuses_before_pin_or_intent(rig):
    q = queue(rig)
    passing(rig)
    backend = rig.backends[q]
    backend.state = replace(backend.state, serial=2**63 - 1)
    restarted = fresh_queue(rig, backend=backend, initialize=False)
    restarted.restore_target(rig.store, mq.HostedResult(rig.base, True), read_target=lambda _: rig.base)
    candidate = prepare(restarted, rig)
    refused("state_capacity", lambda: issue(restarted, rig, candidate))
    assert not backend.dirty
    assert git(rig.repo, "for-each-ref", "--format=%(objectname)", "refs/aegis/merge-queue/") == b""


@pytest.mark.parametrize("step,restart,action", tuple(product(
    ("after_intent", "after_pin", "save_failure", "after_acknowledgement"),
    (False, True), ("withdraw", "replace", "reconcile"))))
def test_generated_issuance_failures_leave_no_unowned_pins(rig, monkeypatch, step, restart, action):
    q, candidate, tip = cached_merge_candidate(rig)
    backend = rig.backends[q]
    real_pin, calls = mq.team_git.cas_fast_forward, []

    def assert_owned():
        records = (backend.state.issued, backend.state.cleanup)
        rows = git(rig.repo, "for-each-ref", "--format=%(refname) %(objectname)",
                   "refs/aegis/merge-queue/").decode().splitlines()
        for row in rows:
            ref, oid = row.split()
            assert any(record is not None and getattr(record, "ref", None) == ref
                       and getattr(record, "expected", None) == oid for record in records)

    def pin(store, ref, expected, new, **kwargs):
        if not ref.startswith("refs/aegis/merge-queue/"):
            return real_pin(store, ref, expected, new, **kwargs)
        records = (backend.state.issued, backend.state.cleanup)
        assert any(record is not None and record.landing.commit == new
                   and getattr(record, "ref", None) == ref
                   and getattr(record, "expected", None) == new for record in records), (
                       "exact pin intent must be checkpointed before its effect")
        calls.append(ref)
        if len(calls) == 1 and step == "after_intent":
            raise OSError("injected interruption after durable intent")
        result = real_pin(store, ref, expected, new, **kwargs)
        assert_owned()
        if len(calls) == 1 and step == "after_pin":
            raise OSError("injected lost pin acknowledgement")
        if len(calls) == 1 and step == "save_failure":
            backend.fail = "issue-before"
        return result

    monkeypatch.setattr("aegis_core.team_git.cas_fast_forward", pin)
    if step == "after_acknowledgement":
        receipt = issue(q, rig, candidate)
        assert receipt == q.issued
    else:
        refused("state_unavailable" if step == "save_failure" else "git_failed",
                lambda: issue(q, rig, candidate))
        refused("state_unavailable", lambda: prepare(q, rig, tip))
    assert_owned()
    backend.fail = None
    with ExitStack() as contexts:
        store = contexts.enter_context(make_store(rig.repo)) if restart else rig.store
        if restart:
            assert store.scratch != rig.store.scratch
            assert not tuple((store.scratch / "objects").iterdir())
        recovered = fresh_queue(rig, backend=backend, initialize=False)
        receipt = recovered.issued
        assert receipt is not None
        if action == "reconcile":
            assert recovered.reconcile_not_landed(store, receipt, read_target=lambda _: tip,
                read_outcome=lambda row: "not_applied") == "not_applied"
        else:
            assert recovered.withdraw("a", expected_head=rig.head, store=store,
                read_target=lambda _: tip, read_outcome=lambda row: "not_applied") == "released"
        assert len(calls) == 1  # Recovery observes/cleans; it never retries creation.
        assert_owned()
        if action == "replace":
            head = git(rig.repo, "commit-tree", rig.tree, "-p", rig.head,
                       data=b"replacement head\n").decode().strip()
            git(rig.repo, "update-ref", "refs/heads/lane/replacement", head)
            reviews = tuple(mq.Review(session, head, rig.tree, "ACCEPT", True) for session in ("r1", "r2"))
            recovered.enqueue(store, entry(rig, head=head, reviews=reviews))
            recovered.restore_target(store, mq.HostedResult(tip, True), read_target=lambda _: tip)
            next_candidate = recovered.prepare(store, read_target=lambda _: tip,
                read_mode=lambda *args: "none", identity=IDENTITY, now=100)
            next_receipt = recovered.revalidate(store, next_candidate, read_target=lambda _: tip,
                read_mode=lambda *args: "none", identity=IDENTITY, now=100)
            assert len(calls) == 2 and calls[0] != calls[1]
            assert_owned()
            recovered.reconcile_not_landed(store, next_receipt, read_target=lambda _: tip,
                                           read_outcome=lambda row: "not_applied")
        assert recovered.issued is None
    assert git(rig.repo, "for-each-ref", "--format=%(objectname)", "refs/aegis/merge-queue/") == b""
    git(rig.repo, "gc", "--prune=now")
    assert git(rig.repo, "cat-file", "--batch-check", data=(candidate.commit + "\n").encode()) == (
        candidate.commit + " missing\n").encode()


@pytest.mark.parametrize("restart", [False, True])
def test_full_results_allow_target_restoration_to_reconcile_ancestors(rig, restart):
    q = queue(rig)
    passing(rig)
    subjects = result_subjects(rig)[:-1]
    for subject in subjects:
        assert q.hosted_result(subject, passed=False) == "unapplied"
    args = tuple(arg for subject in subjects for arg in ("-p", subject))
    target = git(rig.repo, "commit-tree", rig.tree, *args, data=b"all results landed\n").decode().strip()
    git(rig.repo, "update-ref", "refs/heads/main", target)
    if restart:
        q = fresh_queue(rig, backend=rig.backends[q], initialize=False)
    assert q.restore_target(rig.store, mq.HostedResult(target, True, 1), read_target=lambda _: target) == "green"
    assert rig.backends[q].state.results == ()
    assert prepare(q, rig, target).status == "ready"


def test_archive_only_hosted_update_is_admitted_at_capacity(rig):
    q = queue(rig)
    passing(rig)
    receipt = issue(q, rig, prepare(q, rig))
    q.observe_landed(rig.store, receipt, read_target=lambda _: rig.head)
    q.restore_target(rig.store, mq.HostedResult(rig.other, True), read_target=lambda _: rig.other)
    for subject in result_subjects(rig)[:-1]:
        assert q.hosted_result(subject, passed=False) == "unapplied"
    backend = rig.backends[q]
    pending = backend.state.results
    assert q.hosted_result(rig.head, passed=False, attempt=1) == "stale"
    assert backend.state.results == pending
    assert backend.commits[rig.head].result == mq.HostedResult(rig.head, False, 1)
    assert backend.healths[rig.head] == mq.HostedResult(rig.head, False, 1)


@pytest.mark.parametrize("failure", ["commit-exception", "commit-invalid"])
def test_archive_classification_failure_at_capacity_retains_red(rig, failure):
    q = queue(rig)
    passing(rig)
    receipt = issue(q, rig, prepare(q, rig))
    q.observe_landed(rig.store, receipt, read_target=lambda _: rig.head)
    q.restore_target(rig.store, mq.HostedResult(rig.other, True), read_target=lambda _: rig.other)
    for subject in result_subjects(rig)[:-1]:
        q.hosted_result(subject, passed=False)
    backend = rig.backends[q]
    backend.fail = failure
    refused("state_unavailable", lambda: q.hosted_result(rig.head, passed=False, attempt=1))
    refused("state_unavailable", lambda: prepare(q, rig, rig.other))
    backend.fail = None
    q = fresh_queue(rig, backend=backend, initialize=False)
    assert q.restore_target(rig.store, mq.HostedResult(rig.head, True),
                            read_target=lambda _: rig.head) == "target-red"


def test_unissued_intent_result_survives_abort_with_empty_scratch(rig, monkeypatch):
    q, candidate, tip = cached_merge_candidate(rig)

    def interrupted(*args, **kwargs):
        raise OSError("interruption before pin creation")

    monkeypatch.setattr("aegis_core.team_git.cas_fast_forward", interrupted)
    refused("git_failed", lambda: issue(q, rig, candidate))
    backend = rig.backends[q]
    observer = fresh_queue(rig, backend=backend, initialize=False)
    backend.fail = "before"
    refused("state_unavailable", lambda: observer.hosted_result(candidate.commit, passed=False, attempt=1))
    backend.fail = None
    with make_store(rig.repo) as fresh:
        restarted = fresh_queue(rig, backend=backend, initialize=False)
        restarted.restore_target(fresh, mq.HostedResult(tip, True), read_target=lambda _: tip)
        assert restarted.issued is None
        assert restarted.prepare(fresh, read_target=lambda _: tip, read_mode=lambda *args: "none",
            identity=IDENTITY, now=100).status == "target-red"
    assert git(rig.repo, "for-each-ref", "--format=%(objectname)", "refs/aegis/merge-queue/") == b""


@pytest.mark.parametrize("prefix", ["initial", "issued", "landed", "descendant-red",
    "duplicate-red", "withdrawn-red", "cached-merge"])
def test_bounded_exhaustive_state_sequences_preserve_i1_i2_i3(rig, monkeypatch, prefix):
    """Every two-event suffix from seven prefixes; I1-I4 checked after each event.

    The independent oracle tracks per-revision attempts, actual target ancestry
    and unresolved storage faults. Real Git/qualification/public queue APIs are
    used; immutable ancestry reads are cached at the Git process boundary after
    their first real read. No repository history or new dependency is needed.
    """
    passing(rig)
    subjects = result_subjects(rig)
    base_tree = git(rig.repo, "rev-parse", rig.base + "^{tree}").decode().strip()
    cached_tip = git(rig.repo, "commit-tree", base_tree, "-p", rig.base,
                     data=b"cached-prefix empty commit\n").decode().strip()
    descendant = git(rig.repo, "commit-tree", rig.tree, "-p", rig.head,
                     data=b"sequence descendant\n").decode().strip()
    real_run, ancestry = mq.gitsafe.run, {}

    def cached_read(args, cwd, **kwargs):
        if args[:2] != ["merge-base", "--is-ancestor"]:
            return real_run(args, cwd, **kwargs)
        key = (tuple(args), cwd)
        if key not in ancestry:
            ancestry[key] = real_run(args, cwd, **kwargs)
        return ancestry[key]

    monkeypatch.setattr("aegis_core.gitsafe.run", cached_read)
    immutable, runners = {}, {}
    real_lane_run = gitsafe_run.LaneRunner.run

    def cached_objects(runner, args, *positional, **kwargs):
        real = real_lane_run.__get__(runner)
        stable_ref = any(arg.startswith("refs/aegis/qual/") for arg in args)
        if (args[:1] not in (["cat-file"], ("cat-file",)) and not stable_ref
                or kwargs.get("_env") is not None or kwargs.get("effect_fds") is not None):
            return real(args, *positional, **kwargs)
        # Cache immutable reads only within one bound process adapter. A fresh
        # GitStore has a distinct runner and must really resolve its first read.
        identity = id(real.__self__)
        runners[identity] = real.__self__
        key = (identity, tuple(args), kwargs.get("stdin"), kwargs.get("stdout_limit"))
        if key not in immutable:
            result = real(args, *positional, **kwargs)
            if result.returncode == 0 and b" missing\n" not in result.stdout:
                immutable[key] = result
            return result
        return immutable[key]

    monkeypatch.setattr(gitsafe_run.LaneRunner, "run", cached_objects)

    def clone(backend):
        result = StateBackend()
        result.state = backend.state
        result.lanes, result.commits = dict(backend.lanes), dict(backend.commits)
        result.healths, result.dirty = dict(backend.healths), backend.dirty
        result.pending = dict(backend.pending)
        return result

    def observe(oracle, subject, passed, attempt):
        old = oracle.get(subject)
        if old is None or attempt > old[0] or attempt == old[0] and not passed:
            oracle[subject] = (attempt, passed)

    def call(action):
        try:
            return action()
        except mq.QueueRefused as exc:
            assert exc.code in mq.REFUSALS
            assert str(exc) == mq.REFUSALS[exc.code]
            return exc.code

    parents = {rig.base: (), rig.head: (rig.base,), rig.other: (rig.base,),
               descendant: (rig.head,), cached_tip: (rig.base,)}

    def landed(ancestor, target):
        pending, seen = [target], set()
        while pending:
            oid = pending.pop()
            if oid == ancestor:
                return True
            if oid not in seen:
                seen.add(oid)
                pending.extend(parents[oid])
        return False

    seeds = []
    for seed_prefix in (prefix,):
        q = fresh_queue(rig)
        q.enqueue(rig.store, entry(rig))
        target = rig.base
        if seed_prefix == "cached-merge":
            target = cached_tip
            q.restore_target(rig.store, mq.HostedResult(target, True), read_target=lambda _: target)
        if seed_prefix != "initial":
            receipt = issue(q, rig, prepare(q, rig, target))
            parents.setdefault(receipt.commit, (receipt.tip, rig.head))
            if seed_prefix in ("landed", "duplicate-red"):
                target = receipt.commit
            elif seed_prefix == "descendant-red":
                target = descendant
                q.restore_target(rig.store, mq.HostedResult(target, False, 1),
                                 read_target=lambda _: target)
            if seed_prefix == "duplicate-red":
                q.observe_landed(rig.store, receipt, read_target=lambda _: target)
                q.hosted_result(target, passed=True)
                q.enqueue(rig.store, successor_entry(rig, lane="duplicate"))
                next_receipt = issue(q, rig, prepare(q, rig, target))
                parents[next_receipt.commit] = (target,)
                q.hosted_result(target, passed=False, attempt=1)
            if seed_prefix == "withdrawn-red":
                q.hosted_result(receipt.commit, passed=False, attempt=1)
                q.withdraw(receipt.lane, expected_head=rig.head, store=rig.store,
                    read_target=lambda _: target, read_outcome=lambda row: "not_applied")
        seeds.append((clone(rig.backends[q]), target))

    events = ("issue", "land", "advance-descendant", "advance-nondescendant",
              "red0", "green0", "red1", "green1", "receipt-red0", "receipt-green1",
              "acknowledge", "restore", "reconcile", "withdraw", "restart", "storage-fault",
              "reenqueue", "at-capacity", "over-capacity", "restart-fresh-store")
    resolved_states = set()
    for seed, initial_target in seeds:
        for sequence in product(events, repeat=2):
            with sequence_stores() as open_store:
                backend, target = clone(seed), initial_target
                store = rig.store
                q = fresh_queue(rig, backend=backend, initialize=False)
                oracle = {oid: (row.attempt, row.passed) for oid, row in backend.healths.items()}
                observe(oracle, target, True, 0)
                q.restore_target(store, mq.HostedResult(target, True), read_target=lambda _: target)
                fault = False
                for event in sequence:
                    receipt = q.issued
                    if event == "issue":
                        candidate = call(lambda: q.prepare(store, read_target=lambda _: target,
                            read_mode=lambda *args: "none", identity=IDENTITY, now=100))
                        if isinstance(candidate, mq.Landing) and candidate.status == "ready":
                            assert not fault and oracle.get(target, (0, True))[1], sequence
                            assert oracle.get(candidate.commit, (0, True))[1], sequence
                            issued = call(lambda: q.revalidate(store, candidate, read_target=lambda _: target,
                                read_mode=lambda *args: "none", identity=IDENTITY, now=100))
                            if isinstance(issued, mq.Landing):
                                parents.setdefault(issued.commit, (issued.tip, rig.head))
                    elif event == "land":
                        if receipt is not None:
                            target = receipt.commit
                    elif event.startswith("advance-"):
                        target = descendant if event == "advance-descendant" else rig.other
                    elif event in ("red0", "green0", "red1", "green1", "receipt-red0", "receipt-green1"):
                        subject = receipt.commit if event.startswith("receipt-") and receipt else target
                        passed, attempt = "green" in event, int(event[-1])
                        outcome = call(lambda: q.hosted_result(subject, passed=passed, attempt=attempt))
                        if outcome not in ("state_unavailable", "state_capacity"):
                            observe(oracle, subject, passed, attempt)
                    elif event == "acknowledge" and receipt is not None:
                        call(lambda: q.observe_landed(store, receipt, read_target=lambda _: target))
                    elif event == "restore":
                        outcome = call(lambda: q.restore_target(store, mq.HostedResult(target, True),
                                                                read_target=lambda _: target))
                        if outcome in ("green", "target-red"):
                            observe(oracle, target, True, 0)
                            fault = False
                    elif event == "reconcile" and receipt is not None:
                        call(lambda: q.reconcile_not_landed(store, receipt,
                            read_target=lambda _: target, read_outcome=lambda row: "not_applied"))
                    elif event == "withdraw" and receipt is not None:
                        record = backend.state.issued or backend.state.cleanup
                        call(lambda: q.withdraw(receipt.lane, expected_head=record.entry.head, store=store,
                            read_target=lambda _: target, read_outcome=lambda row: "not_applied"))
                    elif event == "reenqueue":
                        call(lambda: q.enqueue(store, entry(rig)))
                    elif event == "at-capacity":
                        for subject in subjects[:-1]:
                            outcome = call(lambda: q.hosted_result(subject, passed=False))
                            if outcome not in ("state_unavailable", "state_capacity"):
                                observe(oracle, subject, False, 0)
                    elif event == "over-capacity":
                        for subject in subjects:
                            observe(oracle, subject, False, 0)
                            backend.healths[subject] = mq.HostedResult(subject, oracle[subject][1], oracle[subject][0])
                            backend.pending[subject] = backend.healths[subject]
                        backend.dirty = True
                        q = fresh_queue(rig, backend=backend, initialize=False)
                    elif event == "restart-fresh-store":
                        if prefix == "cached-merge":
                            store = open_store(rig.repo)
                            assert store.scratch != rig.store.scratch
                            assert not tuple((store.scratch / "objects").iterdir())
                            if receipt is not None:
                                assert store.object(receipt.commit, "commit")
                        q = fresh_queue(rig, backend=backend, initialize=False)
                    elif event == "restart":
                        q = fresh_queue(rig, backend=backend, initialize=False)
                    elif event == "storage-fault":
                        backend.fail = "before"
                        assert call(lambda: q.hosted_result(target, passed=False, attempt=1)) == "state_unavailable"
                        observe(oracle, target, False, 1)
                        backend.fail, fault = None, True
                    red = oracle.get(target, (0, True))[1] is False
                    if red or fault:  # I1 / I3: no ordinary publication after RED / uncertainty.
                        observation = call(lambda: q.prepare(store, read_target=lambda _: target,
                            read_mode=lambda *args: "none", identity=IDENTITY, now=100))
                        assert not isinstance(observation, mq.Landing) or observation.status != "ready", sequence
                        if q.issued is not None:
                            assert call(lambda: q.check_issued(store, q.issued,
                                read_target=lambda _: target, read_mode=lambda *args: "none", now=100)) is not True
                    # I2: even with a fault/restart/contradictory hosted result, every
                    # durable receipt has a public authenticated resolution path.
                    fingerprint = (backend.state, target, backend.dirty, tuple(backend.healths.items()),
                                   tuple(backend.lanes.items()), tuple(backend.commits.items()),
                                   tuple(backend.pending.items()))
                    if fingerprint in resolved_states:
                        continue
                    resolved_states.add(fingerprint)
                    probe = fresh_queue(rig, backend=clone(backend), initialize=False)
                    if probe.issued is not None:
                        pending = probe.issued
                        if landed(pending.commit, target):
                            assert probe.observe_landed(store, pending,
                                read_target=lambda _: target) == "done", sequence
                        else:
                            outcome = call(lambda: probe.reconcile_not_landed(store, pending,
                                read_target=lambda _: target, read_outcome=lambda row: "not_applied"))
                            if outcome == "state_conflict":
                                record = backend.state.issued or backend.state.cleanup
                                assert probe.withdraw(pending.lane, expected_head=record.entry.head, store=store,
                                    read_target=lambda _: target, read_outcome=lambda row: "not_applied") == "released"
                            else:
                                assert outcome == "not_applied", sequence
                        assert probe.issued is None, sequence
