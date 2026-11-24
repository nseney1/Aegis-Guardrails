"""Tests for Git worktree hook resolution and installation (BUG-082).

Ensures that aegis init and aegis doctor properly locate the hooks directory
when running inside a Git worktree (.git is a file, not a directory).
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest

from aegis_cli.doctor import _check_precommit_hook
from aegis_cli.init import (
    _AEGIS_HOOK_START,
    AEGIS_HOOK_FORMAT,
    install_hook,
)
from aegis_core.workspace.hooks import resolve_git_hooks_dir

_NEEDS_GIT = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=T", "-c", "commit.gpgsign=false", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
    )


def _setup_mock_worktree(tmp_path: Path) -> tuple[Path, Path]:
    """Create a main git repo and an attached worktree layout.

    Returns (main_repo_path, worktree_path).
    """
    main_repo = tmp_path / "main_repo"
    main_repo.mkdir()
    _git(main_repo, "init", "-q", "-b", "main")
    _git(main_repo, "commit", "-q", "--allow-empty", "-m", "init")
    (main_repo / ".git" / "hooks").mkdir(exist_ok=True)
    worktree = tmp_path / "my_worktree"
    _git(main_repo, "worktree", "add", "-q", "--detach", str(worktree))
    return main_repo, worktree


class TestGitHooksDirResolution:
    """Tests for resolve_git_hooks_dir across repository layouts."""

    def test_standard_git_dir_resolves_hooks(self, tmp_path: Path):
        """Standard repository with .git directory resolves .git/hooks."""
        repo = tmp_path / "repo"
        repo.mkdir()
        hooks = repo / ".git" / "hooks"
        hooks.mkdir(parents=True)

        resolved = resolve_git_hooks_dir(repo)
        assert resolved is not None
        assert resolved.resolve() == hooks.resolve()

    @_NEEDS_GIT
    def test_worktree_resolves_main_repo_hooks(self, tmp_path: Path):
        """Worktree with .git file resolves to main repository hooks directory."""
        main_repo, worktree = _setup_mock_worktree(tmp_path)
        expected_hooks = main_repo / ".git" / "hooks"

        resolved = resolve_git_hooks_dir(worktree)
        assert resolved is not None
        assert resolved.resolve() == expected_hooks.resolve()

    @_NEEDS_GIT
    def test_worktree_with_relative_gitdir(self, tmp_path: Path):
        """Worktree with relative gitdir path resolves properly."""
        main_repo = tmp_path / "main_repo"
        main_repo.mkdir()
        _git(main_repo, "init", "-q", "-b", "main")
        _git(main_repo, "commit", "-q", "--allow-empty", "-m", "init")
        (main_repo / ".git" / "hooks").mkdir(exist_ok=True)
        worktree = tmp_path / "wt1"
        _git(main_repo, "worktree", "add", "-q", "--detach", str(worktree))
        (worktree / ".git").write_text("gitdir: ../main_repo/.git/worktrees/wt1\n", encoding="utf-8")

        resolved = resolve_git_hooks_dir(worktree)
        assert resolved is not None
        assert resolved.resolve() == (main_repo / ".git" / "hooks").resolve()

    def test_non_git_directory_returns_none(self, tmp_path: Path):
        """Directory without any .git returns None."""
        plain_dir = tmp_path / "plain"
        plain_dir.mkdir()

        assert resolve_git_hooks_dir(plain_dir) is None


@_NEEDS_GIT
class TestWorktreeHookInstallation:
    """Tests for install_hook and doctor in worktrees."""

    def test_install_hook_succeeds_in_worktree(self, tmp_path: Path):
        """install_hook successfully creates pre-commit in worktree shared hooks."""
        main_repo, worktree = _setup_mock_worktree(tmp_path)
        expected_hook = main_repo / ".git" / "hooks" / "pre-commit"

        installed = install_hook(worktree)
        assert installed is True
        assert expected_hook.is_file()
        content = expected_hook.read_text(encoding="utf-8")
        assert _AEGIS_HOOK_START in content or _AEGIS_HOOK_START in content
        assert AEGIS_HOOK_FORMAT in content or AEGIS_HOOK_FORMAT in content
        assert os.access(expected_hook, os.X_OK)

    def test_doctor_detects_precommit_hook_in_worktree(self, tmp_path: Path):
        """_check_precommit_hook detects the hook when executed on a worktree."""
        _main_repo, worktree = _setup_mock_worktree(tmp_path)
        install_hook(worktree)

        status = _check_precommit_hook(worktree)
        assert status is True
