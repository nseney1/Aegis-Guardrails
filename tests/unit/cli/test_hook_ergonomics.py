"""Tests for Phase 19: Multi-Repo Hook Ergonomics & Dedicated Hook Management (v0.116.0).

Validates:
1. `aegis hook install` porcelain: atomic install, idempotency, user-hook preservation, symlink guards.
2. `aegis hook status` porcelain: inspection of hook state, format detection, interpreter probe, JSON output.
3. `aegis hook uninstall` porcelain: clean block removal, total cleanup if solitary, user-hook preservation.
4. Dispatcher: install/status/uninstall plus the isolated `safety-gate` (lifecycle phases were cut in v4, D15).
5. Hook generator: POSIX sh block that pins the installing interpreter (format 5).
6. Genesis integration: `--install-hooks` and `--no-hooks` flags.
7. Smart `aegis init` attachment: attaching local repository without clobbering existing global rules.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from aegis_cli.hooks import (
    _AEGIS_HOOK_END,
    _AEGIS_HOOK_START,
    AEGIS_HOOK_FORMAT,
    CURRENT_HOOK_FORMAT_VERSION,
    hook_status,
    install_hook,
    uninstall_hook,
    run_hook_install,
    run_hook_status,
    run_hook_uninstall,
    run_hook,
)
from aegis_core.workspace.base import Workspace


def _setup_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    hooks = repo / ".git" / "hooks"
    hooks.mkdir(parents=True)
    return repo


class TestHookInstallPorcelain:
    """Tests for aegis hook install porcelain."""

    def test_install_creates_hook_with_current_format(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        ok = install_hook(repo)
        assert ok is True

        hook = repo / ".git" / "hooks" / "pre-commit"
        assert hook.is_file()
        content = hook.read_text(encoding="utf-8")
        assert content.startswith("#!/bin/sh\n")
        assert _AEGIS_HOOK_START in content or _AEGIS_HOOK_START in content
        assert _AEGIS_HOOK_END in content or _AEGIS_HOOK_END in content
        assert f"aegis-hook-format: {CURRENT_HOOK_FORMAT_VERSION}" in content
        # The hook never resolves aegis from the environment or the repository.
        assert "VIRTUAL_ENV" not in content
        assert ".venv" not in content
        if os.name != "nt":
            assert hook.stat().st_mode & stat.S_IXUSR

    def test_install_is_idempotent(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        assert install_hook(repo) is True
        first_content = (repo / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")

        assert install_hook(repo) is True
        second_content = (repo / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
        assert first_content == second_content
        assert second_content.count(_AEGIS_HOOK_START) == 1 or second_content.count(_AEGIS_HOOK_START) == 1

    def test_install_preserves_user_hooks(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        hook = repo / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\necho 'custom user linter'\n", encoding="utf-8")

        assert install_hook(repo) is True
        content = hook.read_text(encoding="utf-8")
        assert "echo 'custom user linter'" in content
        assert _AEGIS_HOOK_START in content or _AEGIS_HOOK_START in content
        assert _AEGIS_HOOK_END in content or _AEGIS_HOOK_END in content

    def test_install_replaces_old_format_block_in_place(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        hook = repo / ".git" / "hooks" / "pre-commit"
        old_block = (
            f"{_AEGIS_HOOK_START}\n"
            "# aegis-hook-format: 2\n"
            "aegis checkpoint --pre-commit\n"
            f"{_AEGIS_HOOK_END}\n"
        )
        hook.write_text(f"#!/bin/sh\necho pre\n{old_block}echo post\n", encoding="utf-8")

        assert install_hook(repo) is True
        content = hook.read_text(encoding="utf-8")
        assert "echo pre" in content
        assert "echo post" in content
        assert f"aegis-hook-format: {CURRENT_HOOK_FORMAT_VERSION}" in content
        assert "aegis-hook-format: 2" not in content

    def test_install_refuses_external_symlink_without_force(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        outside_hook = tmp_path / "outside_pre_commit"
        outside_hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

        hook_link = repo / ".git" / "hooks" / "pre-commit"
        try:
            hook_link.symlink_to(outside_hook)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not supported on this platform/filesystem")

        # Without force: should return False and not modify outside file
        assert install_hook(repo, force=False) is False
        assert _AEGIS_HOOK_START not in outside_hook.read_text(encoding="utf-8") and _AEGIS_HOOK_START not in outside_hook.read_text(encoding="utf-8")

        # With force: should succeed
        assert install_hook(repo, force=True) is True
        assert _AEGIS_HOOK_START in outside_hook.read_text(encoding="utf-8") or _AEGIS_HOOK_START in outside_hook.read_text(encoding="utf-8")

    def test_install_returns_false_when_no_git_dir(self, tmp_path: Path):
        non_repo = tmp_path / "plain_dir"
        non_repo.mkdir()
        assert install_hook(non_repo) is False


class TestHookUninstallPorcelain:
    """Tests for aegis hook uninstall porcelain."""

    def test_uninstall_removes_solitary_aegis_hook(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        install_hook(repo)
        hook = repo / ".git" / "hooks" / "pre-commit"
        assert hook.exists()

        assert uninstall_hook(repo) is True
        assert not hook.exists(), "Hook file should be deleted when only Aegis content was present"

    def test_uninstall_preserves_user_hooks(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        hook = repo / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\necho 'keep me'\n", encoding="utf-8")
        install_hook(repo)
        assert _AEGIS_HOOK_START in hook.read_text(encoding="utf-8") or _AEGIS_HOOK_START in hook.read_text(encoding="utf-8")

        assert uninstall_hook(repo) is True
        assert hook.exists(), "Hook file should remain if user hooks exist"
        content = hook.read_text(encoding="utf-8")
        assert "echo 'keep me'" in content
        assert _AEGIS_HOOK_START not in content and _AEGIS_HOOK_START not in content
        assert _AEGIS_HOOK_END not in content and _AEGIS_HOOK_END not in content

    def test_uninstall_returns_false_when_no_hook_found(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        assert uninstall_hook(repo) is False


class TestHookStatusPorcelain:
    """Tests for aegis hook status porcelain."""

    def test_status_reports_not_installed(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        st = hook_status(repo)
        assert st["status"] == "not_installed"
        assert st["is_git_repo"] is True
        assert st["managed_by_aegis"] is False

    def test_status_reports_installed_and_current_format(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        install_hook(repo)
        st = hook_status(repo)
        assert st["status"] == "installed"
        assert st["managed_by_aegis"] is True
        assert st["format_version"] == CURRENT_HOOK_FORMAT_VERSION
        # The hook pins a shell path, so on Windows it is written with forward slashes.
        assert Path(st["interpreter"]["path"]) == Path(sys.executable)

    def test_status_reports_outdated_format(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        hook = repo / ".git" / "hooks" / "pre-commit"
        hook.write_text(
            f"#!/bin/sh\n{_AEGIS_HOOK_START}\n# aegis-hook-format: 2\naegis checkpoint\n{_AEGIS_HOOK_END}\n",
            encoding="utf-8",
        )
        st = hook_status(repo)
        assert st["status"] == "outdated"
        assert st["managed_by_aegis"] is True
        assert st["format_version"] == 2

    def test_status_reports_no_git_repository(self, tmp_path: Path):
        non_repo = tmp_path / "empty"
        non_repo.mkdir()
        st = hook_status(non_repo)
        assert st["status"] == "no_git_repository"
        assert st["is_git_repo"] is False


class TestHybridDispatcher:
    """Tests for routing `aegis hook` actions."""

    def test_dispatch_porcelain_install(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        args = argparse.Namespace(
            hook_action="install",
            phase=None,
            workspace=str(repo),
            force=False,
            dry_run=False,
            json=False,
        )
        rc = run_hook(args)
        assert rc == 0
        assert (repo / ".git" / "hooks" / "pre-commit").exists()

    def test_dispatch_porcelain_status_json(self, tmp_path: Path, capsys):
        repo = _setup_git_repo(tmp_path)
        install_hook(repo)
        args = argparse.Namespace(
            hook_action="status",
            phase=None,
            workspace=str(repo),
            json=True,
        )
        rc = run_hook(args)
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["status"] == "installed"

    def test_dispatch_porcelain_uninstall(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        install_hook(repo)
        args = argparse.Namespace(
            hook_action="uninstall",
            phase=None,
            workspace=str(repo),
            force=False,
            dry_run=False,
            json=False,
        )
        rc = run_hook(args)
        assert rc == 0
        assert not (repo / ".git" / "hooks" / "pre-commit").exists()

    def test_dispatch_safety_gate(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)  # the gate logs into the cwd's workspace
        args = argparse.Namespace(
            hook_action="safety-gate",
            phase="safety-gate",
            cmd="git status",
            workspace=None,
            json=False,
        )
        rc = run_hook(args)
        assert rc == 0


class TestGenesisHookIntegration:
    """Tests for genesis --install-hooks and --no-hooks."""

    def test_genesis_with_install_hooks(self, tmp_path: Path, monkeypatch):
        from aegis_cli.init import run_init

        repo = _setup_git_repo(tmp_path)
        (repo / "pyproject.toml").write_text('[project]\nname = "myapp"\nversion = "0.1.0"\n', encoding="utf-8")
        src = repo / "src"
        src.mkdir()
        (src / "__init__.py").write_text("", encoding="utf-8")
        (src / "config.py").write_text('DATABASE_URL = "postgres://localhost/db"\n', encoding="utf-8")
        args = argparse.Namespace(
            project_root=str(repo),
            ws=Workspace.resolve(repo),
            dry_run=False,
            json=False,
            force=True,
            yes=True,
            install_hooks=True,
            no_hooks=False,
            local=True,
            platform="gemini",
            rules="minimal",
        )
        rc = run_init(args)
        assert rc == 0
        assert (repo / ".git" / "hooks" / "pre-commit").exists()

    def test_genesis_with_no_hooks(self, tmp_path: Path):
        from aegis_cli.init import run_init

        repo = _setup_git_repo(tmp_path)
        (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
        args = argparse.Namespace(
            project_root=str(repo),
            ws=Workspace.resolve(repo),
            dry_run=False,
            json=False,
            force=True,
            yes=True,
            install_hooks=False,
            no_hooks=True,
            local=True,
            platform="gemini",
            rules="minimal",
        )
        rc = run_init(args)
        assert rc == 0
        assert not (repo / ".git" / "hooks" / "pre-commit").exists()


class TestHookSecurityAndSymlinkHardening:
    """Tests for symlink preservation, dangling link guards, and edge cases."""

    def test_in_repo_symlink_preserved_on_install(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        scripts_dir = repo / "scripts"
        scripts_dir.mkdir()
        target_script = scripts_dir / "my-hook"
        target_script.write_text("#!/bin/sh\necho 'project hook'\n", encoding="utf-8")

        hook_link = repo / ".git" / "hooks" / "pre-commit"
        try:
            hook_link.symlink_to(Path("..") / ".." / "scripts" / "my-hook")
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not supported")

        assert install_hook(repo) is True
        assert hook_link.is_symlink(), "In-repo symlink must not be destroyed by install"
        target_content = target_script.read_text(encoding="utf-8")
        assert "echo 'project hook'" in target_content
        assert _AEGIS_HOOK_START in target_content or _AEGIS_HOOK_START in target_content

    def test_dangling_symlink_handling(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        dangling_target = repo / "nonexistent" / "hook"
        hook_link = repo / ".git" / "hooks" / "pre-commit"
        try:
            hook_link.symlink_to(dangling_target)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not supported")

        assert install_hook(repo, force=False) is False
        assert install_hook(repo, force=True) is True
        assert not hook_link.is_symlink(), "Dangling symlink should be replaced with regular file on --force"
        assert hook_link.is_file()

    def test_uninstall_unterminated_block_preserves_content(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        hook = repo / ".git" / "hooks" / "pre-commit"
        original = f"#!/bin/sh\n{_AEGIS_HOOK_START}\necho 'corrupt without end marker'\necho 'user hook'\n"
        hook.write_text(original, encoding="utf-8")

        assert uninstall_hook(repo) is False
        assert hook.read_text(encoding="utf-8") == original, "Unterminated block must not truncate subsequent lines"

    def test_uninstall_external_symlink_requires_force(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        outside_hook = tmp_path / "outside_script"
        outside_hook.write_text(
            f"#!/bin/sh\n{_AEGIS_HOOK_START}\n# aegis-hook-format: 3\naegis checkpoint\n{_AEGIS_HOOK_END}\n",
            encoding="utf-8",
        )
        hook_link = repo / ".git" / "hooks" / "pre-commit"
        try:
            hook_link.symlink_to(outside_hook)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not supported")

        assert uninstall_hook(repo, force=False) is False
        assert outside_hook.exists()

        assert uninstall_hook(repo, force=True) is True

    def test_status_format_1_unversioned_fallback(self, tmp_path: Path):
        repo = _setup_git_repo(tmp_path)
        hook = repo / ".git" / "hooks" / "pre-commit"
        hook.write_text(
            f"#!/bin/sh\n{_AEGIS_HOOK_START}\naegis checkpoint --pre-commit\n{_AEGIS_HOOK_END}\n",
            encoding="utf-8",
        )
        st = hook_status(repo)
        assert st["status"] == "outdated"
        assert st["format_version"] == 1
