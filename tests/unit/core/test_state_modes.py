"""File modes of the shared state (v4.4 spec §12.7): private by construction, counted by doctor."""
from __future__ import annotations

import os
from pathlib import Path
import stat

import pytest

from aegis_core import storage
from tests import helpers_humangate as hg

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@posix_only
@needs_git
def test_a_repository_with_no_shared_state_has_nothing_to_report(tmp_path):
    repo = hg.make_repo(tmp_path)
    assert storage.shared_state_modes(repo.root) == storage.StateModes(0, 0, 0, True)
    assert not (repo.root / ".git" / "aegis").exists(), "reading creates nothing"


@posix_only
def test_outside_a_repository_it_reads_the_local_state_without_creating_it(tmp_path):
    assert storage.shared_state_modes(tmp_path) == storage.StateModes(0, 0, 0, True)
    assert not (tmp_path / ".aegis").exists()


@posix_only
@needs_git
def test_a_symlink_below_the_top_is_neither_followed_nor_counted(tmp_path):
    repo = hg.make_repo(tmp_path)
    site = storage.ledger_site(repo.root)
    storage.append_jsonl(site.path, [{"v": 2}])
    target = tmp_path / "elsewhere"
    target.write_text("x", encoding="utf-8")
    os.chmod(target, 0o666)
    os.symlink(target, site.path.parent / "alias")
    report = storage.shared_state_modes(repo.root, fix=True)
    assert report.looser == 0
    assert _mode(target) == 0o666


@posix_only
@needs_git
def test_only_the_shared_state_is_made_private_not_the_workspace_local_state(tmp_path):
    repo = hg.make_repo(tmp_path)
    (repo.root / ".aegis").mkdir(exist_ok=True)
    old = os.umask(0o022)
    try:
        local = storage.state_dir(repo.root)
        storage.append_jsonl(local / "activity.jsonl", [{"v": 1}])
    finally:
        os.umask(old)
    assert _mode(local / "activity.jsonl") == 0o644, "workspace state keeps the mode the umask gives"


@posix_only
@needs_git
def test_a_file_written_atomically_into_the_shared_state_is_private(tmp_path):
    repo = hg.make_repo(tmp_path)
    shared = storage.shared_state_dir(repo.root)
    old = os.umask(0o000)
    try:
        storage.atomic_write_bytes(shared / "note.json", b"{}")
    finally:
        os.umask(old)
    assert _mode(shared / "note.json") == 0o600


@posix_only
@needs_git
def test_tightening_twice_changes_nothing_the_second_time(tmp_path):
    repo = hg.make_repo(tmp_path)
    site = storage.ledger_site(repo.root)
    storage.append_jsonl(site.path, [{"v": 2}])
    os.chmod(site.path, 0o664)
    first = storage.shared_state_modes(repo.root, fix=True)
    second = storage.shared_state_modes(repo.root, fix=True)
    assert (first.looser, first.fixed) == (1, 1)
    assert (second.looser, second.fixed) == (0, 0)


def _modes_below(top: Path) -> dict:
    return {p.relative_to(top).as_posix(): _mode(p) for p in [top, *top.rglob("*")]}


@posix_only
@pytest.mark.parametrize("fix", [False, True], ids=["count", "fix"])
def test_outside_git_the_umask_moded_local_state_is_neither_counted_nor_tightened(tmp_path, fix):
    """R-cli-39: the 0700/0600 standard covers the git common dir only. Given a non-git
    workspace whose .aegis/state the umask made 0755/0644, When the modes are read (and
    fixed), Then nothing is counted and no mode changes."""
    old = os.umask(0o022)
    try:
        local = storage.state_dir(tmp_path)
        with storage.locked(tmp_path):
            pass
        storage.append_jsonl(local / "ledger.jsonl", [{"v": 2}])
    finally:
        os.umask(old)
    before = _modes_below(local)
    assert before["."] == 0o755 and before["ledger.jsonl"] == 0o644
    assert storage.shared_state_modes(tmp_path, fix=fix) == storage.StateModes(0, 0, 0, True)
    assert _modes_below(local) == before
