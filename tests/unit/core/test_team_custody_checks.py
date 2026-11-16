"""Ordered custody refusals through the public precondition boundary."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
from threading import Event
from types import SimpleNamespace

import pytest

from aegis_core import gitsafe, gitsafe_run, team, team_git, team_gitops, team_qualify
from aegis_core import team_custody_checks as checks
from tests.conftest import symlink_or_skip
from tests.unit.core.test_team_git import IDENTITY, commit, git, make_store, shared_bytes


@pytest.fixture
def rig(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("needs git")
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "lane/work")
    context = make_store(repo)  # Capability guard before descriptor-only work.
    if not team_qualify.descriptor_supported():
        pytest.skip("qualification requires descriptor custody")
    (repo / "src").mkdir()
    head = commit(repo, "src/a.py", b"base\n")
    policy = team.parse_team(json.dumps({"v": 1, "shared": ["shared.txt"],
                                       "lanes": {"work": ["src/**"]}}).encode())
    lease = team.claim(repo, "work", ["/src/**", "/shared.txt"], owner="team-1",
                       branch="lane/work", now=100, ttl_s=60)
    (repo / "src/a.py").write_bytes(b"tested\n")
    with context as store:
        tree = team_git.snapshot_tree(store)
        journal = team_gitops.GitOpsJournal(repo / ".git")
        item = team_qualify.QualificationResult(tree, "unit", head, "run-1", True)
        team_qualify.record_pass(store, item, expected=None, identity=IDENTITY,
                                journal=journal, lane="work", request_id="pass-1", actor="custodian")
        def paths(old, new):
            # Trusted adapter sees the private object directory. No repository history needed.
            return tuple(p.decode() for p in git(repo, "diff-tree", "-r", "--no-renames",
                                                "--name-only", "-z", old, new,
                                                env=store.env).split(b"\0") if p)
        options = dict(lane="work", owner="team-1", expected_head=head, tested_tree=tree,
                       required_legs=("unit",), message="Implement work\n\nDetails.\n", now=101,
                       read_branch=lambda: git(repo, "symbolic-ref", "--short", "HEAD").decode().strip(),
                       read_head=lambda: git(repo, "rev-parse", "HEAD").decode().strip(),
                       read_paths=paths, read_policy=lambda: policy)
        yield SimpleNamespace(repo=repo, store=store, options=options, lease=lease, policy=policy)


def state(rig):
    return (shared_bytes(rig.repo), {
        p.relative_to(rig.repo).as_posix(): ("link", str(p.readlink())) if p.is_symlink() else
        ("file", p.read_bytes()) if p.is_file() else ("directory",)
        for p in rig.repo.rglob("*") if ".git" not in p.parts})


def run(rig, **changes):
    return checks.check_preconditions(rig.store, **{**rig.options, **changes})


def refusal(rig, code, **changes):
    before = state(rig)
    with pytest.raises(checks.CustodyRefused) as caught:
        run(rig, **changes)
    assert caught.value.code == code
    assert str(caught.value) == checks.REFUSALS[code]
    assert set(caught.value.next_action) == {"actor", "command"}
    assert state(rig) == before
    return caught.value


def test_success_and_retry_preserve_shared_bytes(rig):
    before = state(rig)
    assert run(rig) == rig.options["tested_tree"]
    assert run(rig) == rig.options["tested_tree"]
    assert state(rig) == before


@pytest.mark.parametrize("changes", [{"now": 160}, {"owner": "another-team"}, {"lane": "missing"},
                                      {"lane": "../invalid"}, {"owner": None}])
def test_lease_is_first_and_retry_is_effect_free(rig, changes):
    refusal(rig, "lease_not_live", message="bad\0", read_branch=lambda: None, **changes)
    assert run(rig) == rig.options["tested_tree"]


def test_branch_mismatch_precedes_head_and_has_resume_action(rig):
    error = refusal(rig, "branch_mismatch", read_branch=lambda: "other", expected_head=None)
    assert error.next_action == {"actor": "implementer", "command": "lane resume work"}


@pytest.mark.parametrize("value", [None, "b" * 40, "x" * 100000, ["a"]],
                         ids=["missing", "stale", "oversized", "wrong-type"])
def test_expected_head_mismatch_precedes_tree(rig, value):
    refusal(rig, "head_mismatch", expected_head=value, tested_tree=None)


def test_worktree_change_refuses_before_qualification_and_retry_recovers(rig):
    (rig.repo / "src/a.py").write_bytes(b"untested\n")
    refusal(rig, "tree_mismatch", required_legs=())
    (rig.repo / "src/a.py").write_bytes(b"tested\n")
    assert run(rig) == rig.options["tested_tree"]


def qualify_current(rig):
    tree = team_git.snapshot_tree(rig.store)
    item = team_qualify.QualificationResult(tree, "unit", rig.options["expected_head"], "run-2", True)
    team_qualify.record_pass(rig.store, item, expected=None, identity=IDENTITY,
                            journal=team_gitops.GitOpsJournal(rig.repo / ".git"),
                            lane="work", request_id="pass-2", actor="custodian")
    rig.options["tested_tree"] = tree


@pytest.mark.parametrize("change", ["addition", "rename", "deletion"])
def test_actual_snapshot_diff_covers_new_renamed_and_deleted_paths(rig, change):
    if change == "addition":
        (rig.repo / "outside.py").write_bytes(b"untracked\n")
    elif change == "rename":
        (rig.repo / "src/a.py").rename(rig.repo / "outside.py")
    else:
        (rig.repo / "src/a.py").unlink()
    qualify_current(rig)
    if change == "deletion":
        before = state(rig)
        assert run(rig) == rig.options["tested_tree"]
        assert state(rig) == before
    else:
        assert refusal(rig, "path_outside_lease").path == "outside.py"


def test_corrupt_pass_is_not_qualification(rig):
    ref = team_qualify.qualification_ref(rig.options["tested_tree"], "unit")
    old = git(rig.repo, "rev-parse", ref).decode().strip()
    git(rig.repo, "update-ref", ref, rig.options["expected_head"])
    refusal(rig, "not_qualified")
    git(rig.repo, "update-ref", ref, old)
    assert run(rig) == rig.options["tested_tree"]


def test_snapshot_path_failure_is_typed_and_retryable(rig):
    held = rig.repo.parent / "held"
    (rig.repo / "src").rename(held)
    symlink_or_skip(held, rig.repo / "src", target_is_directory=True)
    refusal(rig, "tree_mismatch")
    (rig.repo / "src").unlink()
    held.rename(rig.repo / "src")
    assert run(rig) == rig.options["tested_tree"]


@pytest.mark.parametrize("legs", [(), ("missing",), ("unit", "unit"), ("unit", "missing"), None])
def test_exact_tree_pass_required_before_scope(rig, legs):
    refusal(rig, "not_qualified", required_legs=legs, read_paths=lambda old, new: ("outside",))


@pytest.mark.parametrize("path,code", [("outside.py", "path_outside_lease"),
                                      ("src/private.py", "path_outside_team")])
def test_scope_is_intersection_and_reports_safe_path(rig, path, code):
    policy = team.TeamPolicy(shared=("shared.txt",), lanes={"work": ("src/a.py",)})
    error = refusal(rig, code, read_paths=lambda old, new: (path,), read_policy=lambda: policy,
                    message="bad\0")
    assert error.path == path
    assert run(rig) == rig.options["tested_tree"]


def test_shared_policy_path_still_needs_lease(rig):
    assert run(rig, read_paths=lambda old, new: ("shared.txt",)) == rig.options["tested_tree"]
    refusal(rig, "path_outside_lease", read_paths=lambda old, new: ("other-shared.txt",),
            read_policy=lambda: team.TeamPolicy(shared=("other-shared.txt",)))


@pytest.mark.parametrize("path", ["../src/a.py", "/src/a.py", "src/../a.py", "src//a.py",
                                 "src/./a.py", "src\\a.py", "src/a\0.py", "x" * 4097, None],
                         ids=["climb", "absolute", "inner-climb", "empty-component", "dot-component",
                              "backslash", "nul", "oversized", "wrong-type"])
def test_malformed_changed_paths_refuse_without_echo(rig, path):
    error = refusal(rig, "invalid_paths", read_paths=lambda old, new: (path,))
    assert error.path is None


def test_path_list_bound_precedes_iteration(rig):
    class LargeList(list):
        def __iter__(self):
            pytest.fail("oversized list was iterated")
    refusal(rig, "invalid_paths", read_paths=lambda old, new: LargeList(["src/a.py"] * 10001))


@pytest.mark.parametrize("policy", [None, team.TeamPolicy(shared=["src/**"]),
                                  team.TeamPolicy(lanes=1),
                                  team.TeamPolicy(lanes={"work": ["src/**"]})])
def test_invalid_policy_shapes_return_fixed_refusal(rig, policy):
    refusal(rig, "invalid_policy", read_policy=lambda: policy)


def test_policy_bound_precedes_scope_concatenation(rig):
    class TooMany(tuple):
        def __add__(self, other):
            pytest.fail("oversized policy was concatenated")
    policy = team.TeamPolicy(shared=TooMany(("a",) * 65537))
    refusal(rig, "invalid_policy", read_policy=lambda: policy)


def test_secret_lane_does_not_enter_recovery_action(rig):
    lane = "ghp_" + "a" * 36
    team.claim(rig.repo, lane, ["outside/**"], owner="team-1", branch="other", now=100, ttl_s=60)
    error = refusal(rig, "branch_mismatch", lane=lane)
    assert error.next_action == {"actor": "implementer", "command": "lane resume"}


def test_diagnostic_canonicalizes_then_redacts_then_truncates(rig):
    path = "outside/" + "p" * 260 + "/token=sec\x1b[31mret-value-123"
    error = refusal(rig, "path_outside_lease", read_paths=lambda old, new: (path,))
    assert len(error.path) <= 240 and "\x1b" not in error.path
    assert "secret-value-123" not in error.path
    shorter = "outside/token=sec\x1b[31mret-value-123"
    error = refusal(rig, "path_outside_lease", read_paths=lambda old, new: (shorter,))
    assert "secret-value-123" not in error.path and "\x1b" not in error.path


@pytest.mark.parametrize("message", ["", "bad\0", "x" * 65537, "😀" * 16385, "\ud800", None,
    "change\nAegis-Approve: abc", " aegis-approve : abc", "Aegis-Approve-Insight: abc",
    "change\n\tAEGIS-EXEMPT-TEST : abc"],
    ids=["empty", "nul", "character-cap", "byte-cap", "surrogate", "wrong-type",
         "approve", "approve-folded", "approve-insight", "exempt-test"])
def test_invalid_messages_are_last_input_free_and_retryable(rig, message):
    refusal(rig, "invalid_message", message=message)
    assert run(rig) == rig.options["tested_tree"]


@pytest.mark.parametrize("message", ["x" * 65536, "😀" * 16384, "Mention Aegis-Approve: inline"],
                         ids=["ascii-limit", "utf8-limit", "inline"])
def test_message_boundary_and_inline_text(rig, message):
    assert run(rig, message=message) == rig.options["tested_tree"]


@pytest.mark.parametrize("phase,code", [("read_branch", "branch_mismatch"), ("read_head", "head_mismatch"),
                                        ("read_paths", "invalid_paths"), ("read_policy", "invalid_policy")])
def test_adapter_read_failures_are_fixed_and_retryable(rig, phase, code):
    def fail(*args):
        raise OSError("token=never-print-this")
    refusal(rig, code, **{phase: fail})
    assert run(rig) == rig.options["tested_tree"]


def test_unsupported_platform_probe_refuses_without_touching_store(monkeypatch):
    monkeypatch.setattr(checks, "team_git", SimpleNamespace(**{**vars(team_git), "descriptor_support": lambda: False}))
    with pytest.raises(checks.CustodyRefused) as caught:
        checks.check_preconditions(None, lane="work", owner="team-1", expected_head="a" * 40,
            tested_tree="b" * 40, required_legs=("unit",), message="change", read_branch=None,
            read_head=None, read_paths=None, read_policy=None)
    assert caught.value.code == "unsupported_platform"
    assert str(caught.value) == checks.REFUSALS["unsupported_platform"]


def test_concurrent_lease_transfer_is_seen_on_next_check(rig):
    entered, transferred = Event(), Event()
    def transfer():
        assert entered.wait(10)
        team.transfer(rig.repo, "work", expect=rig.lease.oid, owner="team-2", now=102)
        transferred.set()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(transfer)
        assert run(rig) == rig.options["tested_tree"]
        entered.set()
        assert transferred.wait(10)
        future.result(timeout=10)
    refusal(rig, "lease_not_live")


def test_concurrent_worktree_edit_is_not_qualified(rig):
    edited = Event()
    def edit():
        (rig.repo / "src/a.py").write_bytes(b"concurrent change\n")
        edited.set()
    def head():
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(edit).result(timeout=10)
        assert edited.wait(10)
        return rig.options["expected_head"]
    # The edit is external to the precondition call; capture zero-effects after it.
    head()
    refusal(rig, "tree_mismatch", read_head=head)


@pytest.mark.parametrize("case", ["live", "other-owner", "expired", "missing"])
def test_lease_lookup_never_executes_worktree_git_with_cold_cache(rig, case):
    # rig's make_store guard precedes the POSIX executable and mode operations.
    marker = rig.repo.parent / "planted-git-ran"
    programs = rig.repo / "bin"
    programs.mkdir()
    planted = programs / "git"
    planted.write_text("#!/bin/sh\nprintf ran > " + shlex.quote(str(marker)) + "\n", encoding="utf-8")
    planted.chmod(0o755)
    exclude = rig.repo / ".git" / "info" / "exclude"
    exclude.write_text(exclude.read_text(encoding="utf-8") + "\n/bin/\n", encoding="utf-8")
    environment = dict(os.environ, PATH=str(programs) + os.pathsep + os.environ["PATH"])
    # A fresh isolated process starts with a cold ordinary lookup cache. Only
    # its environment contains the hostile PATH; no parent globals are patched.
    script = """
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from aegis_core import team, team_git, team_custody_checks as checks
repo, scratch, head, tree, case = sys.argv[2:]
outcomes = []
with team_git.GitStore(Path(repo), Path(scratch)) as store:
    for _ in range(2):
        try:
            result = checks.check_preconditions(
                store, lane="absent" if case == "missing" else "work",
                owner="other-team" if case == "other-owner" else "team-1",
                expected_head=head, tested_tree=tree, required_legs=("unit",),
                message="Implement work", now=160 if case == "expired" else 101,
                read_branch=lambda: "lane/work", read_head=lambda: head,
                read_paths=lambda old, new: ("src/a.py",),
                read_policy=lambda: team.TeamPolicy(lanes={"work": ("src/**",)}))
        except checks.CustodyRefused as exc:
            outcomes.append(exc.code)
        else:
            outcomes.append(result)
print(json.dumps(outcomes))
"""
    before = state(rig)
    with tempfile.TemporaryDirectory(dir=rig.repo.parent) as scratch:
        (Path(scratch) / "objects").mkdir(mode=0o700)
        child = subprocess.run(
            [sys.executable, "-I", "-c", script, str(Path(__file__).resolve().parents[3]),
             str(rig.repo), scratch, rig.options["expected_head"], rig.options["tested_tree"], case],
            env=environment, capture_output=True, text=True, timeout=30)
    assert not marker.exists(), "the lease check executed the worktree's planted git"
    assert state(rig) == before
    assert child.returncode == 0, child.stderr
    expected = rig.options["tested_tree"] if case == "live" else "lease_not_live"
    assert json.loads(child.stdout) == [expected, expected]


def test_ref_oid_observes_only_the_requested_ref_and_retains_lease_record(rig, monkeypatch):
    foreign = git(rig.repo, "hash-object", "-w", "--stdin", data=b"not a lease").decode().strip()
    git(rig.repo, "update-ref", "refs/aegis/lanes/work-other", foreign)
    calls = []
    original = gitsafe_run.LaneRunner.run
    def observed(runner, args, *rest, **kwargs):
        calls.append(tuple(args))
        return original(runner, args, *rest, **kwargs)
    monkeypatch.setattr(gitsafe_run.LaneRunner, "run", observed)
    before = state(rig)
    oid = team_git.ref_oid(rig.store, "refs/aegis/lanes/work")
    assert oid == rig.lease.oid
    lease = team.parse_lease(rig.store.object(oid, "blob", max_bytes=team.MAX_LEASE_BYTES), "work", oid)
    assert lease.oid == rig.lease.oid and lease.lane == "work" and lease.owner == "team-1"
    assert lease.expired(160) and not lease.expired(101)
    assert [args[-1] for args in calls if args[0] == "for-each-ref"] == ["refs/aegis/lanes/work"]
    assert state(rig) == before


@pytest.mark.parametrize("ref", [None, "../untrusted", "refs/aegis/" + "x" * 241, 1,
                                "HEAD", "refs/aegis/has\nnewline"],
                         ids=["missing", "traversal", "oversized", "wrong-type", "head", "multiline"])
def test_ref_oid_refuses_invalid_name_before_git(rig, monkeypatch, ref):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid ref reached the Git process boundary")
    monkeypatch.setattr(gitsafe_run.LaneRunner, "run", forbidden)
    before = state(rig)
    with pytest.raises(team_git.GitRefusal) as caught:
        team_git.ref_oid(rig.store, ref)
    assert caught.value.code == "ref_unreadable"
    assert str(caught.value) == "Lane Git operation refused: ref_unreadable"
    assert state(rig) == before


@pytest.mark.parametrize("kind", ["malformed", "wrong-lane", "oversized", "missing-object"])
def test_unreadable_selected_lease_refuses_and_retry_reads_restored_record(rig, kind):
    data = b"not-json"
    if kind == "wrong-lane":
        row = json.loads(git(rig.repo, "cat-file", "blob", rig.lease.oid))
        row["lane"] = "other"
        data = json.dumps(row).encode()
    elif kind == "oversized":
        data = b"x" * (team.MAX_LEASE_BYTES + 1)
    bad = git(rig.repo, "hash-object", "-w", "--stdin", data=data).decode().strip()
    git(rig.repo, "update-ref", "refs/aegis/lanes/work", bad)
    if kind == "missing-object":
        (rig.repo / ".git" / "objects" / bad[:2] / bad[2:]).unlink()
    refusal(rig, "lease_not_live", read_branch=lambda: None, message="bad\0")
    git(rig.repo, "update-ref", "refs/aegis/lanes/work", rig.lease.oid)
    assert run(rig) == rig.options["tested_tree"]


def test_lease_transport_failure_is_fixed_and_retryable(rig, monkeypatch):
    original = gitsafe_run.LaneRunner.run
    def fail_ref(runner, args, *rest, **kwargs):
        if args[0] == "for-each-ref":
            raise gitsafe.GitError("token=never-echo-this", code="ref_unreadable")
        return original(runner, args, *rest, **kwargs)
    monkeypatch.setattr(gitsafe_run.LaneRunner, "run", fail_ref)
    refusal(rig, "lease_not_live", read_branch=lambda: None, message="bad\0")
    monkeypatch.setattr(gitsafe_run.LaneRunner, "run", original)
    assert run(rig) == rig.options["tested_tree"]


@pytest.mark.parametrize("moment", [101, 160])
def test_default_clock_and_injected_time_use_the_same_expiry_boundary(rig, monkeypatch, moment):
    monkeypatch.setattr(checks, "time", SimpleNamespace(time=lambda: moment))
    if moment == 101:
        before = state(rig)
        assert run(rig, now=None) == run(rig, now=moment) == rig.options["tested_tree"]
        assert state(rig) == before
    else:
        refusal(rig, "lease_not_live", now=None)
        refusal(rig, "lease_not_live", now=moment)


def test_ref_oid_requires_an_active_store(rig):
    before = state(rig)
    inactive = team_git.GitStore(rig.repo, rig.store.scratch)
    with pytest.raises(team_git.GitRefusal) as caught:
        team_git.ref_oid(inactive, "refs/aegis/lanes/work")
    assert caught.value.code == "store_closed"
    assert state(rig) == before


@pytest.mark.parametrize("ref", ["refs/heads/topic", "refs/tags/release", "refs/remotes/origin/topic"])
def test_ref_oid_reads_generic_namespaces_without_shared_effects(rig, ref):
    git(rig.repo, "update-ref", ref, rig.options["expected_head"])
    before = state(rig)
    assert team_git.ref_oid(rig.store, ref) == rig.options["expected_head"]
    assert team_git.ref_oid(rig.store, ref) == rig.options["expected_head"]
    assert state(rig) == before


def test_ref_oid_missing_ref_and_later_creation_are_fresh_observations(rig):
    ref = "refs/aegis/new-observation"
    before = state(rig)
    assert team_git.ref_oid(rig.store, ref) is None
    assert state(rig) == before
    git(rig.repo, "update-ref", ref, rig.options["expected_head"])
    before = state(rig)
    assert team_git.ref_oid(rig.store, ref) == rig.options["expected_head"]
    assert state(rig) == before


@pytest.mark.parametrize("length", [240, 241])
def test_ref_oid_enforces_ref_length_boundary(rig, length):
    prefix = "refs/aegis/"
    ref = prefix + "x" * (length - len(prefix))
    before = state(rig)
    if length == 240:
        assert team_git.ref_oid(rig.store, ref) is None
    else:
        with pytest.raises(team_git.GitRefusal) as caught:
            team_git.ref_oid(rig.store, ref)
        assert caught.value.code == "ref_unreadable"
    assert state(rig) == before


def test_ref_oid_os_failure_has_fixed_code_and_retry(rig, monkeypatch):
    original = gitsafe_run.LaneRunner.run
    def fail_ref(runner, args, *rest, **kwargs):
        if args[0] == "for-each-ref":
            raise OSError("token=never-echo-this")
        return original(runner, args, *rest, **kwargs)
    monkeypatch.setattr(gitsafe_run.LaneRunner, "run", fail_ref)
    before = state(rig)
    with pytest.raises(team_git.GitRefusal) as caught:
        team_git.ref_oid(rig.store, "refs/aegis/lanes/work")
    assert caught.value.code == "ref_unreadable"
    assert str(caught.value) == "Lane Git operation refused: ref_unreadable"
    assert state(rig) == before
    monkeypatch.setattr(gitsafe_run.LaneRunner, "run", original)
    assert team_git.ref_oid(rig.store, "refs/aegis/lanes/work") == rig.lease.oid
    assert state(rig) == before


@pytest.mark.parametrize("kind", ["never-entered", "closed"])
def test_inactive_store_refuses_before_any_reader_or_git(rig, monkeypatch, kind):
    if kind == "closed":
        with make_store(rig.repo) as inactive:
            pass
    else:
        inactive = team_git.GitStore(rig.repo, rig.store.scratch)
    def forbidden(*args, **kwargs):
        pytest.fail("an inactive store reached a callback or Git read")
    original = gitsafe_run.LaneRunner.run
    monkeypatch.setattr(gitsafe_run.LaneRunner, "run", forbidden)
    before = state(rig)
    with pytest.raises(checks.CustodyRefused) as caught:
        checks.check_preconditions(inactive, **{**rig.options, "read_branch": forbidden,
            "read_head": forbidden, "read_paths": forbidden, "read_policy": forbidden})
    assert caught.value.code == "lease_not_live"
    assert str(caught.value) == checks.REFUSALS["lease_not_live"]
    assert state(rig) == before
    monkeypatch.setattr(gitsafe_run.LaneRunner, "run", original)
    assert run(rig) == rig.options["tested_tree"]


@pytest.mark.parametrize("source", ["shared", "lane"])
def test_team_policy_glob_cannot_widen_through_lease_normalization(rig, source):
    team.release(rig.repo, "work", rig.lease.oid, caller="team-1")
    rig.lease = team.claim(rig.repo, "work", ["/**"], owner="team-1",
                           branch="lane/work", now=100, ttl_s=60)
    (rig.repo / "outside").mkdir()
    (rig.repo / "outside/secret.py").write_bytes(b"new\n")
    qualify_current(rig)
    row = {"v": 1, "shared": ["/.//."]} if source == "shared" else {
        "v": 1, "lanes": {"work": ["/.//."]}}
    policy = team.parse_team(json.dumps(row).encode())
    assert (policy.shared if source == "shared" else policy.lanes["work"]) == (".//.",)
    error = refusal(rig, "path_outside_team", read_policy=lambda: policy)
    assert error.path == "outside/secret.py"
    before = state(rig)
    assert run(rig, read_policy=lambda: team.TeamPolicy(shared=("**",))) == rig.options["tested_tree"]
    assert state(rig) == before


@pytest.mark.parametrize("kind", ["second-iteration", "concurrent-clear"])
def test_path_capture_cannot_lose_outside_changes_after_validation(rig, kind):
    (rig.repo / "outside.py").write_bytes(b"new\n")
    qualify_current(rig)
    expected = ("src/a.py", "outside.py")
    class Once(list):
        iterations = 0
        def __iter__(self):
            self.iterations += 1
            return super().__iter__() if self.iterations == 1 else iter(())
    paths = Once(expected) if kind == "second-iteration" else list(expected)
    def policy():
        if kind == "concurrent-clear":
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(paths.clear).result(timeout=10)
        return rig.policy
    error = refusal(rig, "path_outside_lease", read_paths=lambda old, new: paths, read_policy=policy)
    assert error.path == "outside.py"
    if kind == "second-iteration":
        assert paths.iterations == 1
    refusal(rig, "path_outside_lease", read_paths=lambda old, new: expected)


def test_path_capture_is_bounded_even_when_iteration_exceeds_declared_length(rig):
    count = []
    class Longer(list):
        def __iter__(self):
            for ordinal in range(team_git.MAX_PATHS + 2):
                if ordinal > team_git.MAX_PATHS:
                    pytest.fail("capture iterated past the bounded refusal slot")
                count.append(ordinal)
                yield "src/a.py"
    refusal(rig, "invalid_paths", read_paths=lambda old, new: Longer(["src/a.py"]), message="bad\0")
    assert len(count) == team_git.MAX_PATHS + 1
    assert run(rig) == rig.options["tested_tree"]


@pytest.mark.parametrize("phase", ["length", "iteration"])
def test_collection_protocol_errors_have_fixed_input_free_refusal(rig, phase):
    class Broken(list):
        def __len__(self):
            if phase == "length":
                raise ValueError("token=never-echo-this")
            return super().__len__()
        def __iter__(self):
            raise OSError("token=never-echo-this")
    refusal(rig, "invalid_paths", read_paths=lambda old, new: Broken(["src/a.py"]))
    assert run(rig) == rig.options["tested_tree"]
