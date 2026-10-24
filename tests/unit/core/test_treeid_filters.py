"""Tree identity reads the config files the caller's git reads (w7 R-trust-12/A8, D-git-defaults):
a clean filter of the system scope runs, so a git-lfs-style tree equals the tree git commits, while a
driver the repository's own config defines stays switched off.

The system config is a file in the throwaway HOME named by GIT_CONFIG_SYSTEM, with
GIT_CONFIG_NOSYSTEM unset for these tests only. The filters are POSIX shell scripts outside every
repository: a marker file means git ran one.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess

import pytest

from aegis_core import treeid
from tests import helpers_humangate as hg
from tests import helpers_verified as hv

pytestmark = [pytest.mark.skipif(not hg.git_ok(), reason="needs git"),
              pytest.mark.skipif(os.name == "nt", reason="the marker filter is a POSIX shell script")]


@pytest.fixture
def system_config(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "GIT_CONFIG_GLOBAL", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
                 "GIT_CONFIG_NOSYSTEM"):
        monkeypatch.delenv(name, raising=False)
    path = home / "gitconfig-system"
    path.write_bytes(b"")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(path))
    probe = subprocess.run(["git", "config", "--system", "--list"], capture_output=True, cwd=str(tmp_path))
    if probe.returncode != 0:
        pytest.skip("this git does not read GIT_CONFIG_SYSTEM")
    return path


def _filter(tmp_path: Path, marker: Path) -> str:
    """A clean filter that records it ran and stores a pointer instead of the content (as git-lfs does)."""
    script = tmp_path / f"filter-{marker.name}"
    script.write_bytes(f'#!/bin/sh\necho ran >> "{marker}"\necho "pointer $(wc -c)"\n'.encode("utf-8"))
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def _system_git(root: Path, *args: str) -> str:
    """Plain git as the user runs it: the system config is read (hg.git sets GIT_CONFIG_NOSYSTEM)."""
    env = {k: v for k, v in os.environ.items() if k != "GIT_CONFIG_NOSYSTEM"}
    return subprocess.run(["git", "-c", "user.email=dev@example.com", "-c", "user.name=Dev", "-c",
                           "commit.gpgsign=false", *args], cwd=str(root), env=env, check=True, capture_output=True,
                          text=True).stdout.strip()


def _lfs_project(tmp_path: Path, system_config: Path, driver: str, marker: Path) -> hg.Repo:
    with open(system_config, "ab") as fh:
        fh.write(f'[filter "{driver}"]\n\tclean = {_filter(tmp_path, marker)}\n'.encode("utf-8"))
    repo = hv.make_project(tmp_path, runner=None)
    repo.write(".gitattributes", f"*.bin filter={driver}\n")
    repo.write("asset.bin", "large content\n")
    _system_git(repo.root, "add", "-A")
    _system_git(repo.root, "commit", "-q", "-m", "asset through the system filter")
    return repo


def test_a_system_clean_filter_runs_so_a_git_lfs_style_tree_is_its_commits_tree(tmp_path, system_config):
    marker = tmp_path / "SYSTEM_FILTER_RAN"
    repo = _lfs_project(tmp_path, system_config, "lfsish", marker)
    assert marker.exists(), "plain git did not run the system filter"
    marker.unlink()
    commit_tree = _system_git(repo.root, "rev-parse", "HEAD^{tree}")
    os.utime(repo.root / "asset.bin")  # racily clean: git must hash the file again to know it is unchanged
    binding = treeid.tree_of(repo.root)
    assert binding.status == "ok", binding.reason
    assert binding.tree == commit_tree


def test_a_driver_the_repository_also_defines_stays_switched_off_with_a_system_config(tmp_path, system_config):
    system_marker, repo_marker = tmp_path / "SYSTEM_RAN", tmp_path / "REPO_RAN"
    repo = _lfs_project(tmp_path, system_config, "dual", system_marker)
    system_marker.unlink()
    hg.git(repo.root, "config", "filter.dual.clean", _filter(tmp_path, repo_marker))
    repo.write("asset.bin", "changed content\n")
    binding = treeid.tree_of(repo.root)
    assert binding.status == "ok", binding.reason
    assert not system_marker.exists() and not repo_marker.exists()


def test_with_the_system_config_switched_off_its_filter_does_not_run_either(tmp_path, system_config, monkeypatch):
    """GIT_CONFIG_NOSYSTEM is the caller's choice too: no system driver runs where the user's git runs none."""
    marker = tmp_path / "SYSTEM_FILTER_RAN"
    repo = _lfs_project(tmp_path, system_config, "lfsish", marker)
    marker.unlink()
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    os.utime(repo.root / "asset.bin")
    binding = treeid.tree_of(repo.root)
    assert binding.status == "ok", binding.reason
    assert not marker.exists()
    assert binding.tree != _system_git(repo.root, "rev-parse", "HEAD^{tree}")
