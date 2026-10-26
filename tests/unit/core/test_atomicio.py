"""aegis_core.atomicio (R-structure-33): the L0 leaf that holds the atomic writes and the regular-file
opener, so storage (which re-exports the public names) and gitsafe (which imports it directly) no
longer import each other. Through either module a write behaves the same."""
from __future__ import annotations

import os
from pathlib import Path
import stat

import pytest

from aegis_core import atomicio, storage
from aegis_core.errors import PathTraversalError

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits, FIFOs and O_NOFOLLOW")
both = pytest.mark.parametrize("module", [storage, atomicio], ids=["storage", "atomicio"])
PUBLIC = ("atomic_write_and_unlink", "atomic_write_bytes", "atomic_write_text", "create_private_file", "fsync_dir")


def _link_or_skip(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")


@pytest.fixture
def umask():
    saved = os.umask(0o022)
    yield
    os.umask(saved)


def test_storage_keeps_every_public_atomic_name():
    assert set(PUBLIC) <= set(atomicio.__all__) and set(PUBLIC) <= set(storage.__all__)
    assert all(getattr(storage, name) is getattr(atomicio, name) for name in PUBLIC)


@both
def test_a_write_replaces_the_file_and_leaves_no_temporary_file(module, tmp_path):
    target = tmp_path / "state.json"
    target.write_bytes(b"old")
    module.atomic_write_bytes(target, b"new")
    assert target.read_bytes() == b"new"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["state.json"]


@both
@posix_only
def test_an_existing_file_keeps_its_mode_and_a_new_file_in_shared_state_is_private(module, tmp_path, umask):
    kept = tmp_path / "rule.md"
    kept.write_bytes(b"old")
    os.chmod(kept, 0o640)
    git_dir = tmp_path / "repo.git"
    (git_dir / "objects").mkdir(parents=True)
    (git_dir / "HEAD").write_bytes(b"ref: refs/heads/main\n")
    shared = git_dir / "aegis" / "note.json"
    module.atomic_write_bytes(kept, b"new")
    module.atomic_write_bytes(shared, b"{}")
    assert stat.S_IMODE(kept.stat().st_mode) == 0o640
    assert stat.S_IMODE(shared.stat().st_mode) == 0o600


@both
def test_a_destination_link_is_followed_by_default_and_replaced_when_not_followed(module, tmp_path):
    victim = tmp_path / "victim.json"
    victim.write_bytes(b"precious")
    link = tmp_path / "config.json"
    _link_or_skip(link, victim)
    module.atomic_write_bytes(link, b"through")
    assert link.is_symlink() and victim.read_bytes() == b"through"
    module.atomic_write_bytes(link, b"replaced", follow_links=False)
    assert not link.is_symlink() and link.read_bytes() == b"replaced" and victim.read_bytes() == b"through"


@both
def test_a_transient_permission_error_on_replace_is_retried(module, tmp_path, monkeypatch):
    target = tmp_path / "locked.txt"
    real_replace, attempts = os.replace, []

    def flaky(src, dst):
        attempts.append(dst)
        if len(attempts) < 3:
            raise PermissionError("[WinError 32] The process cannot access the file")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky)
    module.atomic_write_bytes(target, b"eventually", initial_delay=0.0001)
    assert len(attempts) == 3 and target.read_bytes() == b"eventually"


@both
def test_a_private_file_is_never_created_through_a_link(module, tmp_path):
    victim = tmp_path / "victim"
    victim.write_bytes(b"precious")
    link = tmp_path / "link.key"
    _link_or_skip(link, victim)
    with pytest.raises(PathTraversalError, match="it is a symlink"):
        module.create_private_file(link, b"k" * 32)
    assert victim.read_bytes() == b"precious" and link.is_symlink()


@both
@posix_only
def test_a_private_file_is_never_created_over_a_fifo(module, tmp_path):
    fifo = tmp_path / "link.key"
    os.mkfifo(fifo)
    with pytest.raises(PathTraversalError, match="it is not a regular file"):
        module.create_private_file(fifo, b"k")
    assert stat.S_ISFIFO(os.lstat(fifo).st_mode)


@posix_only
def test_the_readers_refuse_a_link_and_a_fifo_each_with_its_own_reason(tmp_path):
    victim = tmp_path / "victim.jsonl"
    victim.write_bytes(b'{"a": 1}\n')
    link = tmp_path / "link.jsonl"
    _link_or_skip(link, victim)
    fifo = tmp_path / "fifo.jsonl"
    os.mkfifo(fifo)
    linked, piped = storage.read_jsonl(link), storage.read_jsonl(fifo)
    assert linked.rows == [] and "it is a symlink" in linked.error and "not a regular file" not in linked.error
    assert piped.rows == [] and "it is not a regular file" in piped.error
    assert storage.read_tail_bytes(link, 64) == b"" and storage.read_json_dict(fifo) is None


@posix_only
def test_a_link_swapped_in_between_the_check_and_the_open_is_refused(tmp_path, monkeypatch):
    """Given a ledger that lstat finds to be a regular file, When a symlink to another file replaces it
    before the open, Then the read is refused and nothing behind the link is read."""
    victim = tmp_path / "victim.jsonl"
    victim.write_bytes(b'{"secret": 1}\n')
    target = tmp_path / "ledger.jsonl"
    target.write_bytes(b'{"a": 1}\n')
    real_lstat, swapped = os.lstat, []

    def lstat_then_swap(path, *args, **kwargs):
        found = real_lstat(path, *args, **kwargs)
        if os.fspath(path) == os.fspath(target) and not swapped:
            os.unlink(target)
            os.symlink(victim, target)
            swapped.append(True)
        return found

    monkeypatch.setattr(os, "lstat", lstat_then_swap)
    result = storage.read_jsonl(target)
    monkeypatch.undo()
    assert swapped, "the swap happened between the check and the open"
    assert result.rows == [] and "it is a symlink" in result.error
