"""aegis_core.gitevidence: one request's repository facts and the object-id caches (R-structure-4).

Spawns are counted at ``gitsafe.run``, the only git launcher. Every repository is a throwaway one
under ``tmp_path``; a shallow clone is made from a local repository with ``file://`` (no network).
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, List

import pytest

from aegis_core import credit, gitevidence, gitsafe, rule_integrity, storage

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    gitevidence._reset_for_tests()
    yield
    gitevidence._reset_for_tests()


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=T", *args], cwd=str(cwd),
                          check=True, capture_output=True, text=True).stdout.strip()


def _repo(path: Path, commits: int = 1) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q", "-b", "main")
    for n in range(commits):
        (path / "f.txt").write_text(f"{n}\n", encoding="utf-8")
        _git(path, "add", "-A")
        _git(path, "commit", "-q", "-m", f"c{n}")
    return path


def _origin(repo: Path, ref: str = "refs/remotes/origin/main") -> None:
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    _git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", ref)


@pytest.fixture
def calls(monkeypatch) -> List[List[str]]:
    real, seen = gitsafe.run, []

    def spy(args, cwd, *rest, **kwargs):
        seen.append(list(args))
        return real(args, cwd, *rest, **kwargs)

    monkeypatch.setattr(gitsafe, "run", spy)
    return seen


def _verbs(seen: List[List[str]]) -> List[str]:
    return [" ".join(a[:2]) for a in seen]


# ── repo_facts ──────────────────────────────────────────────────────────────

def test_repository_facts_cost_three_git_calls_and_one_outside_git(tmp_path, calls):
    repo = _repo(tmp_path / "repo")
    _origin(repo)
    head = _git(repo, "rev-parse", "HEAD")
    facts = gitevidence.repo_facts(repo)
    assert len(calls) == 3, calls
    assert facts.top == str(repo.resolve()) and facts.head == head and facts.shallow is False
    assert facts.origin_head_ref == "refs/remotes/origin/main"
    assert dict(facts.refs) == {"refs/remotes/origin/HEAD": head, "refs/remotes/origin/main": head,
                                "refs/heads/main": head}
    calls.clear()
    plain = tmp_path / "plain"
    plain.mkdir()
    assert gitevidence.repo_facts(plain) is None and len(calls) == 1


def test_a_request_asks_for_the_facts_once(tmp_path, calls):
    repo = _repo(tmp_path / "repo")
    with gitsafe.memo():
        first = gitevidence.repo_facts(repo)
        assert gitevidence.repo_facts(str(repo)) is first
        assert gitsafe.toplevel(repo) == repo.resolve()
    assert len(calls) == 3


def test_a_ref_below_a_probed_name_is_not_taken_for_it(tmp_path):
    repo = _repo(tmp_path / "repo")
    _git(repo, "branch", "-m", "trunk")
    _git(repo, "update-ref", "refs/heads/main/x", "HEAD")  # for-each-ref matches a prefix up to a slash
    facts = gitevidence.repo_facts(repo)
    assert "refs/heads/main" not in facts.refs and gitevidence.protected_branch(facts) is None


# ── protected_branch ────────────────────────────────────────────────────────

def test_the_protected_branch_is_the_one_origin_head_names_then_main_then_master(tmp_path):
    repo = _repo(tmp_path / "repo")
    assert gitevidence.protected_branch(gitevidence.repo_facts(repo)) == "main"
    _git(repo, "update-ref", "refs/remotes/origin/trunk", "HEAD")
    _git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk")
    assert gitevidence.protected_branch(gitevidence.repo_facts(repo)) == "trunk"
    _git(repo, "branch", "-m", "master")
    _git(repo, "symbolic-ref", "--delete", "refs/remotes/origin/HEAD")
    assert gitevidence.protected_branch(gitevidence.repo_facts(repo)) == "master"
    assert gitevidence.protected_branch(None) is None


def test_a_dangling_origin_head_is_read_as_absent(tmp_path):
    # symbolic-ref answers the target of a broken origin/HEAD, which no ref backs: nothing can
    # land there. The facts drop it, as resolve_base's commit lookup already does.
    repo = _repo(tmp_path / "repo")
    _git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/gone")
    facts = gitevidence.repo_facts(repo)
    assert facts.origin_head_ref is None and "refs/remotes/origin/HEAD" not in facts.refs
    assert gitevidence.protected_branch(facts) == "main"
    assert credit.resolve_protected_branch(repo) == "main"


# ── merge_base_with, commits, is_ancestor ───────────────────────────────────

def _forked(tmp_path: Path) -> Dict[str, str]:
    repo = _repo(tmp_path / "repo", commits=2)
    _origin(repo)
    fork = _git(repo, "rev-parse", "HEAD")
    (repo / "g.txt").write_text("local\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "local")
    return {"root": str(repo), "fork": fork, "head": _git(repo, "rev-parse", "HEAD")}


def test_a_merge_base_is_asked_once_per_pair_of_commits(tmp_path, calls):
    shape = _forked(tmp_path)
    for _ in range(3):
        with gitsafe.memo():
            assert gitevidence.merge_base_with(gitevidence.repo_facts(shape["root"])) == shape["fork"]
    assert _verbs(calls).count("merge-base " + shape["head"]) == 1, calls


def test_a_commit_is_its_own_merge_base_without_asking(tmp_path, calls):
    repo = _repo(tmp_path / "repo")
    _origin(repo)
    facts = gitevidence.repo_facts(repo)
    calls.clear()
    assert gitevidence.merge_base_with(facts) == facts.head and calls == []
    assert gitevidence.merge_base_with(facts, "refs/remotes/origin/nope") is None and calls == []


def test_the_commit_list_of_a_tip_is_read_once(tmp_path, calls):
    repo = _repo(tmp_path / "repo", commits=3)
    facts = gitevidence.repo_facts(repo)
    tips = gitevidence.branch_tips(facts, "main")
    first = gitevidence.commits(facts, tips, 10)
    assert gitevidence.commits(facts, tips, 10) == first and len(first) == 3
    assert first[0] == (facts.head, _git(repo, "rev-parse", "HEAD^{tree}"))
    assert [a[0] for a in calls].count("rev-list") == 1
    assert gitevidence.commits(facts, ("--all",), 10) == () and [a[0] for a in calls].count("rev-list") == 1


def test_a_branch_other_than_main_or_master_costs_one_ref_listing(tmp_path, calls):
    repo = _repo(tmp_path / "repo")
    _git(repo, "branch", "release")
    facts = gitevidence.repo_facts(repo)
    calls.clear()
    with gitsafe.memo():
        assert gitevidence.branch_tips(facts, "release") == (facts.head,)
        assert gitevidence.branch_tips(facts, "release") == (facts.head,)
    assert len(calls) == 1 and calls[0][0] == "for-each-ref"
    assert gitevidence.branch_tips(facts, "main") == (facts.head,) and len(calls) == 1


def test_only_an_ancestor_answer_is_remembered(tmp_path, calls, monkeypatch):
    shape = _forked(tmp_path)
    facts = gitevidence.repo_facts(shape["root"])
    calls.clear()
    assert gitevidence.is_ancestor(facts, shape["fork"], shape["head"]) is True
    assert gitevidence.is_ancestor(facts, shape["fork"], shape["head"]) is True
    assert gitevidence.is_ancestor(facts, shape["head"], shape["fork"]) is False
    assert gitevidence.is_ancestor(facts, shape["head"], shape["fork"]) is False
    assert len(calls) == 3, calls  # one yes, remembered; each no asked again


@pytest.mark.parametrize("bad", ["--all", "HEAD", "-x", "abc123", "A" * 40, "0" * 39], ids=lambda v: v[:6])
def test_an_ancestor_argument_that_is_not_a_full_object_id_never_reaches_git(tmp_path, calls, bad):
    shape = _forked(tmp_path)
    facts = gitevidence.repo_facts(shape["root"])
    calls.clear()
    assert gitevidence.is_ancestor(facts, bad, shape["head"]) is False
    assert gitevidence.is_ancestor(facts, shape["fork"], bad) is False
    assert calls == []


def test_a_shallow_clone_bypasses_the_merge_base_and_commit_caches(tmp_path, calls):
    source = _repo(tmp_path / "source", commits=3)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", "--depth", "1", source.resolve().as_uri(), str(clone)], check=True,
                   capture_output=True)
    (clone / "h.txt").write_text("local\n", encoding="utf-8")
    _git(clone, "add", "-A")
    _git(clone, "commit", "-q", "-m", "local")
    facts = gitevidence.repo_facts(clone)
    assert facts.shallow is True
    upstream = facts.refs["refs/remotes/origin/main"]
    calls.clear()
    for _ in range(2):
        assert gitevidence.merge_base_with(facts) == upstream
        assert len(gitevidence.commits(facts, (facts.head,), 10)) == 2
        assert gitevidence.is_ancestor(facts, upstream, facts.head) is True
    verbs = [a[0] for a in calls]
    assert verbs.count("merge-base") == 3  # two merge bases, one remembered ancestor answer
    assert verbs.count("rev-list") == 2


# ── golden parity: the same answers in and out of a request ─────────────────

def _shape(tmp_path: Path, name: str) -> Dict[str, Any]:
    """A workspace of the named shape and what each lookup answers there."""
    repo = tmp_path / "repo"
    if name == "no-git":
        repo.mkdir()
        return {"ws": repo, "base": None, "shared": False, "branch": None, "landed": None, "tree": "0" * 40}
    if name == "unborn":
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "main")
        return {"ws": repo, "base": None, "shared": True, "branch": None, "landed": None, "tree": "0" * 40}
    _repo(repo, commits=2)
    head = _git(repo, "rev-parse", "HEAD")
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    out = {"ws": repo, "base": ("local-head", head), "shared": True, "branch": "main", "landed": head, "tree": tree}
    if name == "clean-main":
        return out
    if name == "origin-head":
        _origin(repo)
        return dict(out, base=("origin-head", head))
    if name == "dangling-origin-head":
        _git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/gone")
        return out  # the branch is main now; before, the name of the missing branch
    if name == "detached":
        first = _git(repo, "rev-parse", "HEAD~1")
        _git(repo, "checkout", "-q", "--detach", first)
        return dict(out, base=("local-head", first), landed=first, tree=_git(repo, "rev-parse", "HEAD^{tree}"))
    if name == "worktree":
        _git(repo, "worktree", "add", "-q", "-b", "feature", str(tmp_path / "wt"))
        return dict(out, ws=tmp_path / "wt")
    if name in ("nested", "newline"):
        sub = repo / ("pkg\nline" if name == "newline" else "pkg")
        sub.mkdir()
        return dict(out, ws=sub)
    if name == "bare":
        bare = tmp_path / "bare.git"
        _git(tmp_path, "clone", "-q", "--bare", str(repo), str(bare))
        return {"ws": bare, "base": ("local-head", head), "shared": False, "branch": None, "landed": None,
                "tree": tree}
    raise AssertionError(name)


SHAPES = ["no-git", "unborn", "clean-main", "origin-head", "dangling-origin-head", "detached", "worktree", "nested",
          "bare"] + ([] if os.name == "nt" else ["newline"])


def _answers(ws: Path, tree: str) -> Dict[str, Any]:
    anchor = rule_integrity.resolve_base(ws)
    site = storage.ledger_site(ws, create=False)
    return {"base": None if anchor is None else (anchor.source, anchor.commit), "site": site,
            "branch": credit.resolve_protected_branch(ws), "landed": credit.landed_lookup(ws)(tree)}


@pytest.mark.parametrize("name", SHAPES)
def test_every_lookup_answers_the_same_in_and_out_of_a_request(tmp_path, name):
    shape = _shape(tmp_path, name)
    outside = _answers(shape["ws"], shape["tree"])
    with gitsafe.memo():
        inside = _answers(shape["ws"], shape["tree"])
    assert inside == outside
    assert (outside["base"], outside["site"].shared, outside["branch"], outside["landed"]) == (
        shape["base"], shape["shared"], shape["branch"], shape["landed"])


def test_a_linked_worktree_shares_the_main_ledger(tmp_path):
    shape = _shape(tmp_path, "worktree")
    with gitsafe.memo():
        assert storage.ledger_site(shape["ws"], create=False).path == storage.ledger_site(tmp_path / "repo",
                                                                                          create=False).path
