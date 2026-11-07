"""Workspace discovery never makes $HOME a workspace (ADR 0005 AD-4, C-fix T6).

In v4 ``~/.aegis/rules`` is the personal read-only rule layer (H8) and ``~/.aegis`` the
user plane, so neither makes the home directory a governed workspace: not as a marker
the walk-up accepts, not as an operator pin, and not as the root an uninitialized
repository under it falls back to.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from aegis_core.errors import WorkspaceNotFoundError
from aegis_core.workspace.base import Workspace
from aegis_core.workspace.discovery import _is_workspace_dir, resolve_workspace_root


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    (home / ".aegis" / "rules" / "traps").mkdir(parents=True)
    (home / ".aegis" / "rules" / "traps" / "user-plane.md").write_text(
        "---\nid: user-plane\ntype: trap\n---\nUser rule.\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    return home.resolve()


def _repo(path: Path, initialized: bool = False) -> Path:
    (path / ".git").mkdir(parents=True)
    if initialized:
        (path / ".aegis" / "rules").mkdir(parents=True)
    return path.resolve()


def test_the_user_rule_layer_never_marks_home_as_a_workspace(home):
    assert not _is_workspace_dir(str(home))
    # Spelled another way (a trailing separator, unresolved): still the home directory.
    assert not _is_workspace_dir(str(home) + "/")


def test_a_real_workspace_is_still_one(home, tmp_path):
    assert _is_workspace_dir(str(_repo(tmp_path / "proj", initialized=True)))
    assert not _is_workspace_dir(str(_repo(tmp_path / "bare")))


@pytest.mark.parametrize("how", ["cwd", "start", "caller_file"])
def test_an_uninitialized_repository_under_home_never_resolves_to_home(home, monkeypatch, how):
    repo = _repo(home / "code" / "repo")
    src = repo / "src"
    src.mkdir()
    monkeypatch.chdir(src if how == "cwd" else home.parent)
    kwargs = {"start": src} if how == "start" else ({"caller_file": src / "app.py"} if how == "caller_file" else {})
    root = resolve_workspace_root(**kwargs)
    assert root != home
    # Nothing governs it: the start point (or the cwd, for a caller file) names itself.
    assert root == (home.parent if how == "caller_file" else src)


@pytest.mark.parametrize("strict", [False, True])
def test_a_pin_naming_home_is_refused_not_bound(home, monkeypatch, tmp_path, strict):
    monkeypatch.setenv("AEGIS_WORKSPACE", str(home))
    monkeypatch.chdir(tmp_path)
    with pytest.raises(WorkspaceNotFoundError, match="home directory"):
        resolve_workspace_root(strict_env=strict)
    with pytest.raises(WorkspaceNotFoundError, match="home directory"):
        Workspace.resolve()


def test_a_pin_naming_a_real_workspace_still_binds(home, monkeypatch, tmp_path):
    proj = _repo(tmp_path / "proj", initialized=True)
    monkeypatch.setenv("AEGIS_WORKSPACE", str(proj))
    monkeypatch.chdir(tmp_path)
    assert resolve_workspace_root() == proj


@pytest.fixture
def real_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """``$HOME`` overridden (``make test``, CI, sandboxes) while the account's own home, as
    the password database names it, holds the user rule layer. ROOT C2's 2026-11-02 hang:
    tests whose TMPDIR sat inside the real home bound the whole home as their workspace."""
    pwd = pytest.importorskip("pwd")
    real = tmp_path / "real-home"
    (real / ".aegis" / "rules").mkdir(parents=True)
    isolated = tmp_path / "isolated-home"
    isolated.mkdir()
    monkeypatch.setenv("HOME", str(isolated))
    monkeypatch.setenv("USERPROFILE", str(isolated))
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    getpwuid = pwd.getpwuid
    mine = getpwuid(os.getuid())
    entry = pwd.struct_passwd((*mine[:5], str(real), *mine[6:]))
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: entry if uid == os.getuid() else getpwuid(uid))
    return real.resolve()


@pytest.mark.parametrize("how", ["cwd", "start", "caller_file"])
def test_a_folder_under_the_real_home_never_resolves_to_it_when_home_is_overridden(real_home, monkeypatch, how):
    start = real_home / "jobs" / "job" / "tmp"
    start.mkdir(parents=True)
    assert not _is_workspace_dir(str(real_home))
    monkeypatch.chdir(start if how == "cwd" else real_home.parent)
    kwargs = {"start": start} if how == "start" else ({"caller_file": start / "app.py"} if how == "caller_file" else {})
    root = resolve_workspace_root(**kwargs)
    assert root != real_home
    assert root == (real_home.parent if how == "caller_file" else start)


def test_a_legacy_soma_in_the_real_home_is_not_read_as_a_workspace(real_home):
    # A long-time user's real home: v2's ~/.soma, no ~/.aegis. Like $HOME, never walked into.
    shutil.rmtree(real_home / ".aegis")
    (real_home / ".soma").mkdir()
    start = real_home / "code"
    start.mkdir()
    assert resolve_workspace_root(start=start) == start
    assert resolve_workspace_root(start=real_home) == real_home
