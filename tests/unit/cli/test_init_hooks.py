from pathlib import Path
"""TDD Gate 1 tests for aegis init --hooks pre-commit hook installation.

The pre-commit hook bridges governance rules into the git workflow:
- `aegis init` installs a git pre-commit hook that runs `aegis checkpoint --pre-commit`
- Hook is executable and contains the aegis checkpoint invocation
- Hook installation is skipped if no .git directory exists
- Existing hooks are preserved (appended to, not overwritten)
- --dry-run previews but doesn't install
- install_hook() is importable from aegis_cli.init
"""
import argparse
import os
import stat
import sys
import textwrap
import pytest

REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
sys.path.insert(0, REPO_ROOT)


class TestInstallHookFunction:
    """Test the install_hook() helper function."""

    def test_install_hook_is_importable(self):
        """install_hook must be importable from aegis_cli.init."""
        from aegis_cli.init import install_hook
        assert callable(install_hook)

    def test_install_hook_creates_pre_commit_file(self, tmp_path):
        """install_hook creates .git/hooks/pre-commit in a git repo."""
        from aegis_cli.init import install_hook

        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)

        install_hook(tmp_path, dry_run=False)

        hook_file = git_dir / "pre-commit"
        assert hook_file.exists(), "pre-commit hook must be created"

    @pytest.mark.skipif(os.name == "nt", reason="Windows has no POSIX execute bit")
    def test_install_hook_is_executable(self, tmp_path):
        """Installed hook file must have executable permission."""
        from aegis_cli.init import install_hook

        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)

        install_hook(tmp_path, dry_run=False)

        hook_file = git_dir / "pre-commit"
        mode = hook_file.stat().st_mode
        assert mode & stat.S_IXUSR, "Hook must be user-executable"

    def test_install_hook_contains_aegis_checkpoint(self, tmp_path):
        """Hook content must invoke aegis checkpoint --pre-commit."""
        from aegis_cli.init import install_hook

        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)

        install_hook(tmp_path, dry_run=False)

        hook_file = git_dir / "pre-commit"
        content = hook_file.read_text()
        assert "check --hook" in content or "aegis checkpoint" in content

    def test_install_hook_has_shebang(self, tmp_path):
        """Hook file must start with a valid shebang line."""
        from aegis_cli.init import install_hook

        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)

        install_hook(tmp_path, dry_run=False)

        hook_file = git_dir / "pre-commit"
        content = hook_file.read_text()
        assert content.startswith("#!/"), "Hook must start with shebang"

    def test_install_hook_skips_when_no_git_dir(self, tmp_path):
        """install_hook returns False when no .git directory exists."""
        from aegis_cli.init import install_hook

        result = install_hook(tmp_path, dry_run=False)
        assert result is False

    def test_install_hook_dry_run_does_not_create_file(self, tmp_path):
        """--dry-run preview does not actually create the hook file."""
        from aegis_cli.init import install_hook

        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)

        install_hook(tmp_path, dry_run=True)

        hook_file = git_dir / "pre-commit"
        assert not hook_file.exists(), "Dry run must not create hook"

    def test_install_hook_preserves_existing_hook(self, tmp_path):
        """If pre-commit already exists, aegis appends rather than overwriting."""
        from aegis_cli.init import install_hook

        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)

        hook_file = git_dir / "pre-commit"
        hook_file.write_text("#!/bin/sh\necho 'existing hook'\n")
        hook_file.chmod(0o755)

        install_hook(tmp_path, dry_run=False)

        content = hook_file.read_text()
        assert "existing hook" in content, "Original hook content must be preserved"
        assert "check --hook" in content or "aegis checkpoint" in content, "Hook must be appended"

    def test_install_hook_idempotent(self, tmp_path):
        """Running install_hook twice does not duplicate the aegis section."""
        from aegis_cli.init import install_hook

        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)

        install_hook(tmp_path, dry_run=False)
        install_hook(tmp_path, dry_run=False)

        hook_file = git_dir / "pre-commit"
        content = hook_file.read_text()
        assert (
            content.count("# >>> aegis pre-commit >>>") == 1
            or content.count("# >>> aegis pre-commit >>>") == 1
            or content.count("aegis checkpoint") == 1
        ), "Must not duplicate hook section"

    def test_install_hook_returns_true_on_success(self, tmp_path):
        """install_hook returns True when hook is successfully installed."""
        from aegis_cli.init import install_hook

        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)

        result = install_hook(tmp_path, dry_run=False)
        assert result is True


class TestInitInstallsHook:
    """Test that aegis init integrates hook installation."""

    def test_init_installs_hook_in_git_repo(self, tmp_path, monkeypatch):
        """aegis init in a git repo installs the pre-commit hook."""
        from aegis_cli.init import run_init

        # Set up a minimal git repo
        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)

        args = argparse.Namespace(
            dry_run=False,
            rules="minimal",
            yes=True,
            force=False,
            _project_root=tmp_path,
        )
        run_init(args)

        hook_file = git_dir / "pre-commit"
        assert hook_file.exists(), "aegis init must install pre-commit hook"
        content = hook_file.read_text()
        assert "check --hook" in content or "aegis checkpoint" in content

    def test_init_dry_run_does_not_install_hook(self, tmp_path, monkeypatch):
        """aegis init --dry-run does not create the hook file."""
        from aegis_cli.init import run_init

        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)

        args = argparse.Namespace(
            dry_run=True,
            rules="minimal",
            yes=True,
            force=False,
            _project_root=tmp_path,
        )
        run_init(args)

        hook_file = git_dir / "pre-commit"
        assert not hook_file.exists(), "Dry run must not create hook"
