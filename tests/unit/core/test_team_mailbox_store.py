"""Public parent-anchored Store construction and descriptor lifetime."""
import errno
import os
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import team_mailbox_store as storage
from aegis_core.team_mailbox_primitives import MailboxRefusal


@pytest.fixture
def parent(tmp_path):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    path = tmp_path / "parent"
    path.mkdir(mode=0o700)
    return path


def test_parent_anchor_validates_only_selected_parent(parent, monkeypatch):
    grandparent = parent.parent.stat()

    def foreign_grandparent(fd):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (grandparent.st_dev, grandparent.st_ino):
            return os.stat_result((*info[:4], os.geteuid() + 1, *info[5:]))
        return info

    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "fstat": foreign_grandparent}))
    (parent / "record").write_bytes(b"held parent")
    with storage.Store.from_parent(parent) as store:
        assert store.read(parent / "record") == b"held parent"
        with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
            store.read(parent.parent / "record")
        descriptors = (store.fd, store.parent_fd)
    store.close()
    for fd in descriptors:
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF
    with pytest.raises(MailboxRefusal, match="^mailbox refused: closed$"):
        store.read(parent / "record")


def test_parent_anchor_unsupported_platform_refuses_before_io(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "descriptor_supported", lambda: False)
    with pytest.raises(MailboxRefusal, match="^mailbox refused: unsupported_platform$"):
        storage.Store.from_parent(tmp_path / "missing")
    assert not (tmp_path / "missing").exists()


@pytest.mark.parametrize("component", ["parent", "ancestor"])
def test_parent_anchor_refuses_symlink_components(parent, component):
    selected = parent if component == "parent" else parent / "child"
    if component == "ancestor":
        selected.mkdir(mode=0o700)
    saved = parent.with_name("saved")
    parent.rename(saved)
    symlink_or_skip(saved, parent, target_is_directory=True)
    with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
        storage.Store.from_parent(selected)
    assert list(saved.iterdir()) == ([] if component == "parent" else [saved / "child"])


def test_parent_anchor_stays_confined_after_ancestor_rename(parent):
    (parent / "record").write_bytes(b"original")
    with storage.Store.from_parent(parent) as store:
        saved = parent.parent.with_name(parent.parent.name + "-saved")
        parent.parent.rename(saved)
        try:
            parent.mkdir(parents=True, mode=0o700)
            (parent / "record").write_bytes(b"replacement")
            assert store.read(parent / "record") == b"original"
            assert (parent / "record").read_bytes() == b"replacement"
        finally:
            (parent / "record").unlink()
            parent.rmdir()
            parent.parent.rmdir()
            saved.rename(parent.parent)


@pytest.mark.parametrize("failure", ["walk", "validation", "replaced"])
def test_parent_anchor_constructor_failure_closes_descriptors_and_retries(parent, monkeypatch, failure):
    opened = set()
    identity = parent.stat()
    checked = []

    def tracking_open(path, *args, **kwargs):
        if failure == "walk" and path == parent.name:
            raise OSError(errno.EIO, "private walk failure")
        fd = os.open(path, *args, **kwargs)
        opened.add(fd)
        return fd

    def tracking_close(fd):
        os.close(fd)
        opened.remove(fd)

    def fstat(fd):
        info = os.fstat(fd)
        if not checked and (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
            checked.append(True)
            if failure == "validation":
                raise OSError(errno.EIO, "private validation failure")
            if failure == "replaced":
                parent.rename(parent.with_name("saved"))
                parent.mkdir(mode=0o700)
        return info

    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "open": tracking_open,
                                                       "close": tracking_close, "fstat": fstat}))
    reason = "unsafe_path" if failure == "replaced" else "io"
    with pytest.raises(MailboxRefusal, match="^mailbox refused: " + reason + "$"):
        storage.Store.from_parent(parent)
    monkeypatch.setattr(storage, "os", os)
    assert opened == set()
    assert list(parent.iterdir()) == []
    with storage.Store.from_parent(parent) as store:
        with store.directory(parent) as fd:
            assert os.fstat(fd).st_ino == parent.stat().st_ino
