"""What a Workspace knows about git: is_git, is_worktree and git_hooks_dir (#27).

The GitWorkspace subclass is gone (branch_name, get_changed_files and _run_git had
no production caller); changed files come from aegis_core.gitsafe (test_gitsafe.py).
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from aegis_core import gitsafe
from aegis_core.workspace import as_workspace
from aegis_core.workspace.base import Workspace

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=T", *args],
                   cwd=str(repo), check=True, capture_output=True)


def _inside_real_repo(path: Path) -> bool:
    res = subprocess.run(["git", "-C", str(path), "rev-parse", "--git-dir"], capture_output=True, text=True)
    return res.returncode == 0


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "commit", "-q", "--allow-empty", "-m", "init")
    return root


def test_plain_directory_is_not_git(tmp_path: Path):
    plain = tmp_path / "plain_project"
    plain.mkdir()
    if _inside_real_repo(plain):
        pytest.skip("tmp_path is inside a real git repository")
    ws = Workspace.resolve(start=plain)
    assert type(ws) is Workspace
    assert not ws.is_git
    assert ws.git_hooks_dir is None


def test_repo_root_and_subdirectories_are_git(repo: Path):
    deep = repo / "subdir" / "deep"
    deep.mkdir(parents=True)
    assert Workspace(root=repo).is_git
    assert Workspace.resolve(start=deep).is_git
    assert Workspace(root=repo).git_hooks_dir == (repo / ".git" / "hooks").resolve()


def test_as_workspace_is_idempotent(repo: Path):
    ws = as_workspace(repo)
    assert type(ws) is Workspace and as_workspace(ws) is ws
    assert isinstance(ws, os.PathLike)


def test_linked_worktree(repo: Path, tmp_path: Path):
    wt = tmp_path / "wt_branch"
    _git(repo, "worktree", "add", "-q", "-b", "feature", str(wt))

    ws = Workspace.resolve(start=wt)
    assert ws.is_git and ws.is_worktree
    assert not Workspace(root=repo).is_worktree
    # hooks are shared: the linked worktree uses the common directory's hooks
    assert ws.git_hooks_dir == (repo / ".git" / "hooks").resolve()
    assert repr(ws) == f"Workspace(root={ws.root!r}, is_worktree=True)"


def test_subdirectory_of_linked_worktree_is_git(repo: Path, tmp_path: Path):
    wt = tmp_path / "wt"
    _git(repo, "worktree", "add", "-q", "-b", "feature", str(wt))
    deep = wt / "pkg" / "deep"
    deep.mkdir(parents=True)

    ws = Workspace.resolve(start=deep)
    assert ws.is_git
    assert gitsafe.toplevel(deep) == wt.resolve()


class TestAncestorDiscoveryMatchesGit:
    """An ancestor `.git` only counts when git itself would accept it as a repository.

    A stray empty `/tmp/.git` (seen on shared CI and dev machines) used to make every
    tmp directory look like a git workspace.
    """

    @pytest.fixture
    def outer(self, tmp_path: Path) -> Path:
        if _inside_real_repo(tmp_path):
            pytest.skip("tmp_path is inside a real git repository")
        outer = tmp_path / "outer"
        (outer / "proj").mkdir(parents=True)
        return outer

    def test_empty_ancestor_git_dir_is_not_adopted(self, outer: Path):
        (outer / ".git").mkdir()
        proj = outer / "proj"
        assert not _inside_real_repo(proj)  # git agrees: not a repository
        assert not Workspace.resolve(start=proj).is_git

    def test_ancestor_git_dir_without_objects_is_not_adopted(self, outer: Path):
        fake = outer / ".git"
        (fake / "refs").mkdir(parents=True)
        (fake / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        assert not Workspace.for_init(outer / "proj").is_git

    def test_ancestor_gitfile_to_missing_gitdir_is_not_adopted(self, outer: Path):
        marker = outer / ".git"
        marker.write_text(f"gitdir: {outer / 'gone' / '.git'}\n", encoding="utf-8")
        if sys.platform != "linux":
            assert not Workspace.resolve(start=outer / "proj").is_git
            return
        _git(outer.parent, "init", "-q", "-b", "main")
        ws = Workspace.resolve(start=outer / "proj")
        with pytest.raises(gitsafe.GitError) as caught:
            _ = ws.is_git
        assert (caught.value.code, str(caught.value)) == (
            "git_path_unavailable",
            "Git metadata path is unavailable.",
        )
