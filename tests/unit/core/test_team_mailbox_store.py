"""Public parent-anchored Store construction and descriptor lifetime."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import errno
import multiprocessing
import os
import stat
from threading import Event
from types import SimpleNamespace
from unittest import mock

import pytest

from conftest import symlink_or_skip
from aegis_core import team_mailbox_store as storage
from aegis_core.team_mailbox_primitives import MailboxRefusal, OWNER_EVIDENCE_LOCK
from tests.unit.core.test_team_mailbox import owner_plane


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
    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    assert storage.descriptor_supported() is False


def test_proof_free_capability_admission_and_no_clobber_publish(parent, monkeypatch):
    assert not hasattr(storage, "publication_proof")
    assert not hasattr(storage, "fcntl")
    proof_free_os = SimpleNamespace(
        name="posix",
        supports_dir_fd=os.supports_dir_fd,
        supports_fd=os.supports_fd,
        O_NOFOLLOW=os.O_NOFOLLOW,
        O_DIRECTORY=os.O_DIRECTORY,
        O_RDONLY=os.O_RDONLY,
        O_WRONLY=os.O_WRONLY,
        O_CREAT=os.O_CREAT,
        O_EXCL=os.O_EXCL,
        O_NONBLOCK=os.O_NONBLOCK,
        open=os.open,
        close=os.close,
        dup=os.dup,
        fstat=os.fstat,
        stat=os.stat,
        mkdir=os.mkdir,
        rmdir=os.rmdir,
        link=os.link,
        unlink=os.unlink,
        read=os.read,
        write=os.write,
        fsync=os.fsync,
        scandir=os.scandir,
        geteuid=os.geteuid,
        fsencode=os.fsencode,
        path=os.path,
    )
    assert not hasattr(proof_free_os, "fchmod")
    monkeypatch.setattr(storage, "os", proof_free_os)
    assert storage.descriptor_supported() is True
    root = parent / "mail"
    folder = root / "route"
    folder.mkdir(parents=True, mode=0o700)
    record = folder / "record"
    with storage.Store(root) as rooted, storage.Store.from_parent(parent) as anchored:
        rooted.publish(record, b"first")
        assert anchored.exists(record) is True
        assert anchored.entries(folder) == [record]
        assert anchored.read(record) == b"first"
        with pytest.raises(MailboxRefusal, match="^mailbox refused: exists$"):
            anchored.publish(record, b"clobber")
        assert not list(folder.glob(".pending-*"))
        assert rooted.read(record) == b"first"


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


def _exact_pending(suffix="ab"):
    return ".pending-" + (suffix * 16)


@contextmanager
def _live_publications(parent, monkeypatch, records, *, before_link=False):
    """Pause genuine publications at the link and staging-unlink boundaries."""
    linking, allow_link, unlinking, allow_unlink = (Event() for _ in range(4))
    names = list(records)
    stages = {}

    def link(source, target, *args, **kwargs):
        stages[target] = source
        if before_link:
            linking.set()
            assert allow_link.wait(5)
        return os.link(source, target, *args, **kwargs)

    def unlink(name, *args, **kwargs):
        if len(names) == 2 and name == stages.get(names[0]):
            writer.publish(parent / names[1], records[names[1]])
        if name == stages.get(names[-1]):
            unlinking.set()
            assert allow_unlink.wait(5)
        return os.unlink(name, *args, **kwargs)

    with storage.Store.from_parent(parent) as writer:
        original_os = storage.os
        monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "link": link, "unlink": unlink}))
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(writer.publish, parent / names[0], records[names[0]])

                def finish(*, close=False):
                    allow_link.set()
                    allow_unlink.set()
                    future.result(timeout=5)
                    if close:
                        writer.close()

                def link_now():
                    allow_link.set()
                    assert unlinking.wait(5)

                try:
                    assert (linking if before_link else unlinking).wait(5)
                    yield stages, finish, link_now
                finally:
                    finish()
        finally:
            monkeypatch.setattr(storage, "os", original_os)


def test_dormant_exact_pair_refuses_then_recovers(parent):
    record = parent / "record"
    record.write_bytes(b"retained")
    pending = parent / _exact_pending()
    os.link(record, pending)
    with storage.Store.from_parent(parent) as store:
        for operation in (lambda: store.entries(parent), lambda: store.exists(record), lambda: store.read(record)):
            with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                operation()
        pending.unlink()
        assert store.read(record) == b"retained"


def test_staging_before_link_succeeds_and_active_two_link_refuses(parent, monkeypatch):
    record = parent / "record"
    kept = parent / "kept"
    kept.write_bytes(b"sibling")
    payload = b"published-bytes"
    with _live_publications(parent, monkeypatch, {record.name: payload}, before_link=True) as (stages, finish, link_now):
        with storage.Store.from_parent(parent) as store:
            pending = parent / stages[record.name]
            assert pending.stat().st_nlink == 1
            assert store.exists(record) is False
            assert store.exists(pending) is True
            assert [path.name for path in store.entries(parent)] == sorted(["kept", pending.name])
            assert store.read(kept) == b"sibling"
            link_now()
            assert record.stat().st_nlink == 2 and pending.stat().st_nlink == 2
            with store.directory(parent) as fd:
                for candidate_parent in (None, fd):
                    for operation in (
                        lambda p=candidate_parent: store.entries(parent, parent=p),
                        lambda p=candidate_parent: store.exists(record, parent=p),
                        lambda p=candidate_parent: store.exists(pending, parent=p),
                        lambda p=candidate_parent: store.read(record, parent=p),
                        lambda p=candidate_parent: store.read(pending, parent=p),
                    ):
                        with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                            operation()
            outside = parent.parent / "outside-link"
            os.link(record, outside)
            try:
                for operation in (lambda: store.entries(parent), lambda: store.read(record), lambda: store.exists(record)):
                    with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                        operation()
            finally:
                outside.unlink()
            for operation in (lambda: store.entries(parent), lambda: store.read(record), lambda: store.exists(record)):
                with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                    operation()
            finish()
            assert [path.name for path in store.entries(parent)] == ["kept", "record"]
            assert store.exists(record) is True
            assert store.exists(pending) is False
            assert store.read(record) == payload


def test_link_appearing_after_name_snapshot_refuses_without_rescan(parent, monkeypatch):
    record = parent / "record"
    sibling = parent / "sibling"
    sibling.write_bytes(b"kept")
    with _live_publications(parent, monkeypatch, {record.name: b"linked-later"}, before_link=True) as (stages, finish, link_now):
        with storage.Store.from_parent(parent) as store:
            pending = parent / stages[record.name]
            calls = []
            parent_stat = parent.stat()

            @contextmanager
            def scan(fd):
                with os.scandir(fd) as entries:
                    if not os.path.samestat(os.fstat(fd), parent_stat):
                        yield entries
                        return
                    names = list(entries)
                calls.append(sorted(entry.name for entry in names))
                link_now()
                yield names

            publication_os = storage.os
            monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(publication_os), "scandir": scan}))
            try:
                with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                    store.entries(parent)
                with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                    store.read(record)
                with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                    store.exists(record)
            finally:
                monkeypatch.setattr(storage, "os", publication_os)
            assert calls == [sorted([pending.name, sibling.name])]
            finish()
            assert store.entries(parent) == [record, sibling]
            assert store.read(record) == b"linked-later"


@pytest.mark.parametrize("stage_first", [True, False])
@pytest.mark.parametrize("final_name", ["record", _exact_pending("ee")])
def test_entries_refuses_observed_two_link_in_both_stat_orders(parent, monkeypatch, stage_first, final_name):
    record = parent / final_name
    sibling = parent / "sibling"
    sibling.write_bytes(b"retained")
    with _live_publications(parent, monkeypatch, {record.name: b"settling"}) as (stages, finish, _):
        with storage.Store.from_parent(parent) as store:
            stage = stages[record.name]
            first = stage if stage_first else record.name
            scans, torn_down = [], []
            parent_stat = parent.stat()
            publication_os = storage.os
            real_stat = publication_os.stat

            @contextmanager
            def scan(fd):
                with os.scandir(fd) as entries:
                    if not os.path.samestat(os.fstat(fd), parent_stat):
                        yield entries
                        return
                    scans.append(True)
                    yield sorted(entries, key=lambda entry: entry.name != first)

            def stat_and_teardown(name, *args, **kwargs):
                info = real_stat(name, *args, **kwargs)
                if not torn_down and name == first and info.st_nlink == 2:
                    torn_down.append(True)
                    finish(close=True)
                return info

            monkeypatch.setattr(storage, "os", SimpleNamespace(**{
                **vars(publication_os), "scandir": scan, "stat": stat_and_teardown}))
            try:
                with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                    store.entries(parent)
                assert scans == [True] and torn_down == [True]
                assert store.entries(parent) == sorted([record, sibling])
                assert store.read(record) == b"settling"
            finally:
                monkeypatch.setattr(storage, "os", publication_os)


def test_read_refuses_active_two_link_before_reading_bytes(parent, monkeypatch):
    """Invariant: an observed two-link file refuses unsafe_path before reading bytes, even if stage unlinks."""
    record = parent / "record"
    settled, reads = [], []

    def fstat_settle(fd):
        info = os.fstat(fd)
        if not settled and stat.S_ISREG(info.st_mode) and info.st_nlink == 2:
            settled.append(True)
            finish()
        return info

    def tracked_read(fd, size):
        reads.append(size)
        return os.read(fd, size)

    with _live_publications(parent, monkeypatch, {record.name: b"settled-bytes"}) as (stages, finish, _):
        with storage.Store.from_parent(parent) as store:
            pending = parent / stages[record.name]
            publication_os = storage.os
            monkeypatch.setattr(storage, "os", SimpleNamespace(**{
                **vars(publication_os), "fstat": fstat_settle, "read": tracked_read}))
            try:
                with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                    store.read(record)
            finally:
                monkeypatch.setattr(storage, "os", publication_os)
    assert settled == [True] and reads == []
    assert not pending.exists()
    assert record.read_bytes() == b"settled-bytes"
    with storage.Store.from_parent(parent) as store:
        assert store.read(record) == b"settled-bytes"
        assert store.exists(parent / "absent") is False


@pytest.mark.parametrize("boundary", ["before_read", "after_read"])
@pytest.mark.parametrize("change", ["lose_final", "replace_final", "add_link", "add_stage"])
def test_read_rejects_changed_leaf_membership(parent, monkeypatch, boundary, change):
    record = parent / "record"
    outside = parent.parent / "extra"
    pending = parent / _exact_pending("77")
    with storage.Store.from_parent(parent) as store:
        store.publish(record, b"published")
        identity = record.stat()
        injected, reads = [], []

        def change_membership(fd):
            if injected or not os.path.samestat(os.fstat(fd), identity):
                return
            injected.append(True)
            if change == "add_link":
                os.link(record, outside)
                return
            if change == "add_stage":
                os.link(record, pending)
                return
            record.unlink()
            if change == "replace_final":
                record.write_bytes(b"replacement")

        def fstat(fd):
            info = os.fstat(fd)
            if boundary == "before_read":
                change_membership(fd)
            return info

        def read(fd, size):
            if os.path.samestat(os.fstat(fd), identity):
                reads.append(True)
            raw = os.read(fd, size)
            if boundary == "after_read":
                change_membership(fd)
            return raw

        monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "fstat": fstat, "read": read}))
        try:
            with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                store.read(record)
        finally:
            monkeypatch.setattr(storage, "os", os)
            if outside.exists():
                outside.unlink()
            if pending.exists():
                pending.unlink()
        assert injected == [True]
        assert (reads == []) if boundary == "before_read" else (len(reads) >= 1)


@pytest.mark.parametrize("replacement", [b"changed data", b"987654321"])
def test_one_link_read_keeps_invalid_record_for_changed_data(parent, monkeypatch, replacement):
    record = parent / "record"
    with storage.Store.from_parent(parent) as store:
        store.publish(record, b"123456789")
        assert record.stat().st_nlink == 1
        changed = []

        def read(fd, size):
            raw = os.read(fd, size)
            if not changed and os.path.samestat(os.fstat(fd), record.stat()):
                changed.append(True)
                record.write_bytes(replacement)
            return raw

        monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "read": read}))
        try:
            with pytest.raises(MailboxRefusal, match="^mailbox refused: invalid_record$"):
                store.read(record)
        finally:
            monkeypatch.setattr(storage, "os", os)
        assert changed == [True]
        assert store.read(record) == replacement


def _publish_fork_and_exit(root, record, owner_home, linked, pid_file):
    import time

    def fork_then_exit(name, *args, **kwargs):
        if isinstance(name, str) and name.startswith(".pending-"):
            child = os.fork()
            if child == 0:
                # The at-fork closer has already dropped the inherited proof.
                temporary = pid_file + ".tmp"
                with open(temporary, "w", encoding="ascii") as handle:
                    handle.write(str(os.getpid()))
                os.replace(temporary, pid_file)
                time.sleep(60)
                os._exit(0)
            deadline = time.monotonic() + 5
            while True:
                try:
                    with open(pid_file, encoding="ascii") as handle:
                        seen = handle.read()
                except OSError:
                    seen = ""
                if seen == str(child):
                    break
                if time.monotonic() >= deadline:
                    os._exit(24)
                time.sleep(0.01)
            linked.set()
            os._exit(23)
        return os.unlink(name, *args, **kwargs)

    account = SimpleNamespace(getpwuid=lambda uid: SimpleNamespace(pw_dir=str(owner_home)))
    publication_os = SimpleNamespace(**{**vars(os), "unlink": fork_then_exit})
    with mock.patch.object(storage, "pwd", account), mock.patch.object(storage, "os", publication_os):
        with storage.Store(root) as writer:
            writer.publish(record, b"published")


def _publish_until_exit(root, record, owner_home, linked, exit_writer):
    def stop_at_unlink(name, *args, **kwargs):
        if name.startswith(".pending-"):
            linked.set()
            if exit_writer.wait(5):
                os._exit(23)
        return os.unlink(name, *args, **kwargs)

    account = SimpleNamespace(getpwuid=lambda uid: SimpleNamespace(pw_dir=str(owner_home)))
    publication_os = SimpleNamespace(**{**vars(os), "unlink": stop_at_unlink})
    with mock.patch.object(storage, "pwd", account), mock.patch.object(storage, "os", publication_os):
        with storage.Store(root) as writer:
            writer.publish(record, b"published")


def test_writer_exit_revokes_proof_for_independent_readers(parent, owner_plane):
    context = multiprocessing.get_context("spawn")
    linked, exit_writer = context.Event(), context.Event()
    root = parent / "mail"
    folder = root / "route"
    folder.mkdir(parents=True, mode=0o700)
    record = folder / "record"
    process = context.Process(target=_publish_until_exit, args=(root, record, owner_plane.parent, linked, exit_writer))
    process.start()
    try:
        assert linked.wait(5)
        [stage] = folder.glob(".pending-*")
        with storage.Store(root) as root_reader, storage.Store.from_parent(parent) as parent_reader:
            for store in (root_reader, parent_reader):
                with store.directory(folder) as fd:
                    for operation in (lambda: store.entries(folder, parent=fd),
                                      lambda: store.exists(record, parent=fd),
                                      lambda: store.read(record, parent=fd),
                                      lambda: store.entries(folder),
                                      lambda: store.exists(stage),
                                      lambda: store.read(stage)):
                        with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                            operation()
            exit_writer.set()
            process.join(5)
            assert process.exitcode == 23
            for store in (root_reader, parent_reader):
                with store.directory(folder) as fd:
                    for operation in (lambda: store.entries(folder, parent=fd),
                                      lambda: store.exists(record, parent=fd),
                                      lambda: store.read(record, parent=fd)):
                        with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                            operation()
            stage.unlink()
            assert root_reader.read(record) == b"published"
            assert parent_reader.entries(folder) == [record]
    finally:
        exit_writer.set()
        process.join(5)
        if process.is_alive():
            process.kill()
            process.join(5)
        process.close()


def _dropping_scan(target):
    class DropOnYield:
        def __init__(self, directory):
            self.entries = os.scandir(directory)

        def __enter__(self):
            return self

        def __iter__(self):
            for entry in self.entries:
                if entry.name == target.name and target.exists():
                    target.unlink()
                yield entry

        def __exit__(self, *error):
            self.entries.close()

    return DropOnYield


def test_vanished_exact_stage_keeps_sibling_and_other_vanished_names_refuse(parent, monkeypatch):
    """Invariant: only an exact staging name may disappear between enumeration and stat."""
    kept = parent / "kept"
    kept.write_bytes(b"retained")
    pending = parent / _exact_pending("12")
    pending.write_bytes(b"stage")
    gone = parent / "gone"
    gone.write_bytes(b"temporary")
    with storage.Store.from_parent(parent) as store:
        monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "scandir": _dropping_scan(gone)}))
        try:
            with pytest.raises(MailboxRefusal, match="^mailbox refused: missing$"):
                store.entries(parent)
        finally:
            monkeypatch.setattr(storage, "os", os)
        assert kept.read_bytes() == b"retained"
        gone.write_bytes(b"back")
        monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "scandir": _dropping_scan(pending)}))
        try:
            assert [path.name for path in store.entries(parent)] == ["gone", "kept"]
            assert store.read(kept) == b"retained"
        finally:
            monkeypatch.setattr(storage, "os", os)
    assert not pending.exists()
    with storage.Store.from_parent(parent) as store:
        assert store.read(gone) == b"back"
        assert store.read(kept) == b"retained"


def test_inflated_link_count_refuses_without_repeating_the_census(parent, monkeypatch):
    """Invariant: a stable extra link is unsafe_path after one bounded scan."""
    record = parent / "record"
    record.write_bytes(b"single")
    scans = []
    real_stat = os.stat

    def scan(fd):
        scans.append(True)
        return os.scandir(fd)

    def inflate(name, *args, **kwargs):
        info = real_stat(name, *args, **kwargs)
        if name == "record":
            return os.stat_result((*info[:3], 2, *info[4:]))
        return info

    with storage.Store.from_parent(parent) as store:
        monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "stat": inflate, "scandir": scan}))
        try:
            with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                store.entries(parent)
        finally:
            monkeypatch.setattr(storage, "os", os)
    assert scans == [True]
    with storage.Store.from_parent(parent) as store:
        assert store.read(record) == b"single"


@pytest.mark.parametrize("link_name", [
    "other-name",
    ".pending-" + "a" * 31,
    ".pending-" + "a" * 33,
    ".pending-" + "A" * 32,
    ".pending-" + "g" * 32,
    ".pending-root-id",
    ".pending-grants",
    ".pending-stub",
    ".pending-" + "a" * 32 + "-extra",
])
def test_non_exact_staging_links_refuse_then_read_after_unlink(parent, link_name):
    record = parent / "record"
    record.write_bytes(b"kept")
    link = parent / link_name
    os.link(record, link)
    with storage.Store.from_parent(parent) as store:
        with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$") as caught:
            store.entries(parent)
        assert link_name not in str(caught.value)
        with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
            store.read(record)
        link.unlink()
        assert store.read(record) == b"kept"
        assert [path.name for path in store.entries(parent)] == ["record"]


def test_two_exact_staging_names_are_not_a_publication_pair(parent):
    first = parent / _exact_pending("11")
    second = parent / _exact_pending("22")
    first.write_bytes(b"left")
    os.link(first, second)
    with storage.Store.from_parent(parent) as store:
        with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
            store.entries(parent)
        second.unlink()
        assert store.read(first) == b"left"
        assert [path.name for path in store.entries(parent)] == [first.name]


def test_staging_symlink_and_directory_refuse_then_a_file_retries(parent):
    record = parent / "record"
    record.write_bytes(b"kept")
    link_name = parent / _exact_pending("34")
    symlink_or_skip(record, link_name)
    with storage.Store.from_parent(parent) as store:
        with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
            store.entries(parent)
        link_name.unlink()
        directory = parent / _exact_pending("56")
        directory.mkdir()
        with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
            store.entries(parent)
        directory.rmdir()
        assert store.read(record) == b"kept"
        assert [path.name for path in store.entries(parent)] == ["record"]


def test_census_enforces_logical_max_and_raw_max_plus_one_bounds(parent, monkeypatch):
    monkeypatch.setattr(storage, "MAX_RECORDS", 2)
    one, two, three = parent / "one", parent / "two", parent / "three"
    one.write_bytes(b"1")
    three.write_bytes(b"3")
    with storage.Store.from_parent(parent) as store:
        spare = parent / "spare"
        spare.write_bytes(b"temporary")
        with pytest.raises(MailboxRefusal, match="^mailbox refused: too_large$"):
            store.entries(parent)
        spare.unlink()
        vanished = parent / _exact_pending("99")
        vanished.write_bytes(b"stage")
        monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "scandir": _dropping_scan(vanished)}))
        try:
            assert store.entries(parent) == [one, three]
        finally:
            monkeypatch.setattr(storage, "os", os)
        vanished_a = parent / _exact_pending("9a")
        vanished_b = parent / _exact_pending("9b")
        vanished_a.write_bytes(b"a")
        vanished_b.write_bytes(b"b")
        statted = []
        parent_stat = parent.stat()

        def spy_stat(name, *args, **kwargs):
            if kwargs.get("dir_fd") is not None and os.path.samestat(os.fstat(kwargs["dir_fd"]), parent_stat):
                statted.append(name)
            return os.stat(name, *args, **kwargs)

        monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "stat": spy_stat}))
        try:
            with pytest.raises(MailboxRefusal, match="^mailbox refused: too_large$"):
                store.entries(parent)
            assert statted == []
        finally:
            monkeypatch.setattr(storage, "os", os)
            vanished_a.unlink()
            vanished_b.unlink()
        three.unlink()
        with _live_publications(parent, monkeypatch, {two.name: b"2"}) as (_, finish, _):
            with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                store.entries(parent)
            with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                store.read(two)
            finish()
        assert [path.name for path in store.entries(parent)] == ["one", "two"]
        assert store.read(one) == b"1"


@pytest.mark.parametrize("with_sibling", [False, True], ids=["solo", "with-sibling"])
def test_one_census_refuses_observed_stage_then_reads_settled_final(parent, monkeypatch, with_sibling):
    """One scan lists only staging, observes the link, refuses unsafe_path, then reads the settled final."""
    record = parent / (_exact_pending("aa") if with_sibling else "record")
    sibling = parent / "sibling"
    if with_sibling:
        sibling.write_bytes(b"retained")
    monkeypatch.setattr(storage, "MAX_RECORDS", 2 if with_sibling else 1)
    with _live_publications(parent, monkeypatch, {record.name: b"settled"}, before_link=True) as (stages, finish, link_now):
        with storage.Store.from_parent(parent) as store:
            stage = stages[record.name]
            scans, torn_down = [], []
            parent_stat = parent.stat()
            publication_os = storage.os
            real_stat = publication_os.stat

            @contextmanager
            def scan(fd):
                with os.scandir(fd) as scanned:
                    if not os.path.samestat(os.fstat(fd), parent_stat):
                        yield scanned
                        return
                    entries = list(scanned)
                scans.append(sorted(entry.name for entry in entries))
                link_now()
                yield entries

            def stat_and_teardown(name, *args, **kwargs):
                info = real_stat(name, *args, **kwargs)
                if not torn_down and name == stage and info.st_nlink == 2:
                    torn_down.append(True)
                    finish(close=True)
                return info

            monkeypatch.setattr(storage, "os", SimpleNamespace(**{
                **vars(publication_os), "scandir": scan, "stat": stat_and_teardown}))
            try:
                with store.directory(parent) as parent_fd:
                    with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                        store.entries(parent, parent=parent_fd)
            finally:
                monkeypatch.setattr(storage, "os", publication_os)
            assert scans == [sorted([stage, sibling.name] if with_sibling else [stage])]
            assert torn_down == [True]
            with store.directory(parent) as parent_fd:
                expected = sorted([record.name, sibling.name] if with_sibling else [record.name])
                assert [path.name for path in store.entries(parent, parent=parent_fd)] == expected
                assert store.read(record, parent=parent_fd) == b"settled"
                assert store.exists(record, parent=parent_fd) is True
                if with_sibling:
                    assert store.read(sibling, parent=parent_fd) == b"retained"
            extra = parent / "extra"
            extra.write_bytes(b"over")
            with pytest.raises(MailboxRefusal, match="^mailbox refused: too_large$"):
                store.entries(parent)
            extra.unlink()
            assert store.exists(parent / "absent") is False


@pytest.mark.parametrize("operation", ["exists", "read"])
def test_exists_and_read_refuse_observed_two_link_even_if_writer_tears_down(parent, monkeypatch, operation):
    record = parent / "record"
    with _live_publications(parent, monkeypatch, {record.name: b"settled"}) as (_, finish, _):
        with storage.Store.from_parent(parent) as store:
            torn_down = []
            publication_os = storage.os
            real_stat, real_fstat = publication_os.stat, publication_os.fstat

            def stat_teardown(name, *args, **kwargs):
                info = real_stat(name, *args, **kwargs)
                if not torn_down and name == record.name and info.st_nlink == 2:
                    torn_down.append(True)
                    finish(close=True)
                return info

            def fstat_teardown(fd):
                info = real_fstat(fd)
                if not torn_down and stat.S_ISREG(info.st_mode) and info.st_nlink == 2:
                    torn_down.append(True)
                    finish(close=True)
                return info

            monkeypatch.setattr(storage, "os", SimpleNamespace(**{
                **vars(publication_os), "stat": stat_teardown, "fstat": fstat_teardown}))
            try:
                with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                    if operation == "exists":
                        store.exists(record)
                    else:
                        store.read(record)
            finally:
                monkeypatch.setattr(storage, "os", publication_os)
            assert torn_down == [True]
            assert store.exists(record) is True
            assert store.read(record) == b"settled"


def test_two_active_publications_refuse_then_respect_max_records_on_settlement(parent, monkeypatch):
    monkeypatch.setattr(storage, "MAX_RECORDS", 2)
    one, two = parent / "one", parent / "two"
    with _live_publications(parent, monkeypatch, {one.name: b"1", two.name: b"2"}) as (_, finish, _):
        with storage.Store.from_parent(parent) as store:
            with pytest.raises(MailboxRefusal, match="^mailbox refused: too_large$"):
                store.entries(parent)
            monkeypatch.setattr(storage, "MAX_RECORDS", 3)
            for operation in (lambda: store.entries(parent), lambda: store.read(two), lambda: store.exists(two)):
                with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                    operation()
            finish()
            monkeypatch.setattr(storage, "MAX_RECORDS", 2)
            assert [path.name for path in store.entries(parent)] == ["one", "two"]
            assert store.read(one) == b"1"
            assert store.read(two) == b"2"
            extra = parent / "three"
            extra.write_bytes(b"3")
            with pytest.raises(MailboxRefusal, match="^mailbox refused: too_large$"):
                store.entries(parent)
            extra.unlink()
            assert store.read(two) == b"2"


@contextmanager
def _counted_syncs(monkeypatch):
    counts = {"proof": 0, "data": 0, "directory": 0, "proof_open": 0}
    proof_fds = set()
    original = storage.os

    def tracked_open(path, *args, **kwargs):
        descriptor = os.open(path, *args, **kwargs)
        if isinstance(path, str) and path.startswith(".mailbox-stage-"):
            proof_fds.add(descriptor)
            counts["proof_open"] += 1
        return descriptor

    def tracked_fsync(descriptor):
        if descriptor in proof_fds:
            counts["proof"] += 1
        elif stat.S_ISDIR(os.fstat(descriptor).st_mode):
            counts["directory"] += 1
        else:
            counts["data"] += 1
        return os.fsync(descriptor)

    monkeypatch.setattr(storage, "os", SimpleNamespace(**{
        **vars(original), "open": tracked_open, "fsync": tracked_fsync}))
    try:
        yield counts
    finally:
        monkeypatch.setattr(storage, "os", original)


@pytest.mark.parametrize("operation", ["entries", "exists", "exists_stage", "read", "read_stage", "read_after"])
@pytest.mark.parametrize("gone", ["stage", "final", "both"])
def test_unproven_pair_refuses_when_observed_names_disappear(parent, monkeypatch, operation, gone):
    """An observed two-link file without proof stays unsafe_path, including on return of read bytes."""
    record = parent / "record"
    pending = parent / _exact_pending()
    with storage.Store.from_parent(parent) as initial:
        assert initial.exists(record) is False
        initial.publish(record, b"alias")
    if operation != "read_after":
        os.link(record, pending)
    identity = record.stat()
    dropped, reads = [], []

    def drop():
        if dropped:
            return
        dropped.append(True)
        if gone in ("stage", "both") and pending.exists():
            pending.unlink()
        if gone in ("final", "both") and record.exists():
            record.unlink()

    def stat_name(name, *args, **kwargs):
        info = os.stat(name, *args, **kwargs)
        if operation != "read_after" and name in (record.name, pending.name) and info.st_nlink == 2:
            drop()
        return info

    def fstat(fd):
        info = os.fstat(fd)
        if stat.S_ISREG(info.st_mode) and info.st_nlink == 2 and (operation != "read_after" or reads):
            drop()
        return info

    def read(fd, size):
        target_read = os.path.samestat(os.fstat(fd), identity)
        if target_read:
            reads.append(True)
        raw = os.read(fd, size)
        if operation == "read_after" and target_read and len(reads) == 1:
            os.link(record, pending)
        return raw

    with storage.Store.from_parent(parent) as store:
        monkeypatch.setattr(storage, "os", SimpleNamespace(**{
            **vars(os), "stat": stat_name, "fstat": fstat, "read": read}))
        try:
            target = pending if operation.endswith("_stage") else record
            with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                if operation == "entries":
                    store.entries(parent)
                elif operation.startswith("exists"):
                    store.exists(target)
                else:
                    store.read(target)
        finally:
            monkeypatch.setattr(storage, "os", os)
    assert dropped == [True]
    assert (len(reads) >= 1) if operation == "read_after" else (reads == [])
    if pending.exists():
        pending.unlink()
    with storage.Store.from_parent(parent) as store:
        if record.exists():
            assert store.read(record) == b"alias"
        else:
            assert store.exists(record) is False
            assert not record.exists()


def test_lost_exact_stage_final_refuses_in_one_census(parent, monkeypatch):
    """Replacing the observed exact-stage final refuses that census, then the cursor remains."""
    final = parent / _exact_pending("cd")
    sibling = parent / "sibling"
    sibling.write_bytes(b"kept")
    cursor = parent / "cursor.json"
    with _live_publications(parent, monkeypatch, {final.name: b"cursor"}) as (stages, finish, _):
        with storage.Store.from_parent(parent) as store:
            scans, replaced = [], []
            stage = stages[final.name]
            parent_stat = parent.stat()
            publication_os = storage.os
            real_stat = publication_os.stat

            @contextmanager
            def scan(fd):
                with os.scandir(fd) as scanned:
                    if not os.path.samestat(os.fstat(fd), parent_stat):
                        yield scanned
                        return
                    names = list(scanned)
                scans.append(sorted(entry.name for entry in names))
                yield names

            def stat_and_replace(name, *args, **kwargs):
                info = real_stat(name, *args, **kwargs)
                if not replaced and name in (final.name, stage) and info.st_nlink == 2:
                    replaced.append(True)
                    os.replace(final, cursor)
                    finish(close=True)
                return info

            monkeypatch.setattr(storage, "os", SimpleNamespace(**{
                **vars(publication_os), "scandir": scan, "stat": stat_and_replace}))
            try:
                with store.directory(parent) as parent_fd:
                    with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                        store.entries(parent, parent=parent_fd)
                    assert len(scans) == 1 and len(scans[0]) == 3
                    assert {final.name, sibling.name} <= set(scans[0])
                    assert replaced == [True]
            finally:
                monkeypatch.setattr(storage, "os", publication_os)
            assert sorted(path.name for path in store.entries(parent)) == sorted([cursor.name, sibling.name])
            assert store.read(cursor) == b"cursor"
            assert store.read(sibling) == b"kept"
            assert store.exists(parent / "absent") is False
    assert not final.exists()
    assert cursor.is_file()


def test_fork_child_surviving_writer_exit_keeps_retained_two_link_refused(parent, owner_plane):
    if not hasattr(os, "fork"):
        pytest.skip("fork survival test requires os.fork")
    context = multiprocessing.get_context("spawn")
    linked = context.Event()
    root = parent / "mail"
    folder = root / "route"
    folder.mkdir(parents=True, mode=0o700)
    record = folder / "record"
    pid_file = parent / "child-pid"
    process = context.Process(
        target=_publish_fork_and_exit,
        args=(root, record, owner_plane.parent, linked, str(pid_file)))
    process.start()
    try:
        assert linked.wait(30)
        process.join(30)
        assert process.exitcode == 23
        pid = int(pid_file.read_text(encoding="ascii"))
        os.kill(pid, 0)
        [stage] = folder.glob(".pending-*")
        assert not list(owner_plane.glob(".mailbox-stage-*"))
        assert record.stat().st_nlink == 2
        with storage.Store(root) as root_reader, storage.Store.from_parent(parent) as parent_reader:
            for store in (root_reader, parent_reader):
                with store.directory(folder) as fd:
                    for operation in (lambda: store.entries(folder, parent=fd),
                                      lambda: store.exists(record, parent=fd),
                                      lambda: store.read(record, parent=fd)):
                        with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                            operation()
            os.kill(pid, 0)
            stage.unlink()
            assert root_reader.read(record) == b"published"
            with parent_reader.directory(folder) as fd:
                assert parent_reader.entries(folder, parent=fd) == [record]
                assert parent_reader.read(record, parent=fd) == b"published"
            owner_lock = owner_plane / OWNER_EVIDENCE_LOCK
            if owner_lock.exists():
                owner_lock.unlink()
            later = folder / "later"
            root_reader.publish(later, b"recovered")
            assert parent_reader.read(later) == b"recovered"
            os.kill(pid, 0)
    finally:
        process.join(5)
        if process.is_alive():
            process.kill()
            process.join(5)
        process.close()
        if pid_file.exists():
            try:
                os.kill(int(pid_file.read_text(encoding="ascii")), 9)
            except (OSError, ValueError):
                pass


def test_cleanup_failure_retains_warnings_refuses_leftover_and_recovers(parent, monkeypatch, owner_plane):
    root = parent / "mail"
    folder = root / "route"
    folder.mkdir(parents=True, mode=0o700)
    record, rolled_back, other = folder / "record", folder / "rolled-back", folder / "other"

    def fail_stage_unlink(name, *args, **kwargs):
        if isinstance(name, str) and name.startswith(".pending-"):
            raise OSError(errno.EIO, "stage unlink failed")
        return os.unlink(name, *args, **kwargs)

    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "unlink": fail_stage_unlink}))
    try:
        with storage.Store(root) as writer:
            with pytest.raises(MailboxRefusal, match="^mailbox refused: io$"):
                writer.publish(rolled_back, b"discarded")
            assert writer.drain_warnings() == []
    finally:
        monkeypatch.setattr(storage, "os", os)
    assert not rolled_back.exists()
    for leftover in folder.glob(".pending-*"):
        leftover.unlink()

    def skip_stage_and_fail_owner_release(name, *args, **kwargs):
        if isinstance(name, str) and name.startswith(".pending-"):
            return None
        if name == OWNER_EVIDENCE_LOCK:
            raise OSError(errno.EIO, "owner lock release failed")
        return os.unlink(name, *args, **kwargs)

    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "unlink": skip_stage_and_fail_owner_release}))
    try:
        with storage.Store(root) as writer:
            writer.publish(record, b"kept")
            warnings = writer.drain_warnings()
    finally:
        monkeypatch.setattr(storage, "os", os)
    assert len(warnings) == 1 and warnings[0]["reason"] == "lock_release"
    assert OWNER_EVIDENCE_LOCK in warnings[0]["lock_path"]
    assert not list(owner_plane.glob(".mailbox-stage-*"))
    owner_lock = owner_plane / OWNER_EVIDENCE_LOCK
    assert owner_lock.is_file()
    [stage] = folder.glob(".pending-*")
    assert record.stat().st_nlink == 2
    with storage.Store(root) as rooted, storage.Store.from_parent(parent) as anchored:
        for store in (rooted, anchored):
            with store.directory(folder) as fd:
                for operation in (lambda: store.entries(folder, parent=fd),
                                  lambda: store.exists(record, parent=fd),
                                  lambda: store.read(record, parent=fd)):
                    with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$"):
                        operation()
        stage.unlink()
        owner_lock.unlink()
        assert rooted.read(record) == b"kept"
        anchored.publish(other, b"again")
        assert anchored.read(other) == b"again"
        assert [path.name for path in rooted.entries(folder)] == ["other", "record"]
        assert not list(owner_plane.iterdir())


def test_normal_completion_leaves_no_proof_state_and_reads_create_nothing(parent, owner_plane):
    assert not hasattr(storage, "_settled_proofs")
    assert not hasattr(storage, "_live_proofs")
    root = parent / "mail"
    folder = root / "route"
    folder.mkdir(parents=True, mode=0o700)
    owner_plane.rmdir()
    with storage.Store(root) as writer:
        assert writer.exists(folder / "record-0") is False
        assert writer.entries(folder) == []
        assert not owner_plane.exists()
        owner_plane.mkdir(mode=0o700)
        for index in range(6):
            writer.publish(folder / f"record-{index}", f"done-{index}".encode("ascii"))
    record = folder / "record-5"
    assert record.stat().st_nlink == 1
    assert not list(folder.glob(".pending-*"))
    assert not list(owner_plane.iterdir())
    owner_plane.rmdir()
    with storage.Store(root) as rooted, storage.Store.from_parent(parent) as anchored:
        for store in (rooted, anchored):
            with store.directory(folder) as fd:
                present = set(folder.iterdir())
                assert store.read(record, parent=fd) == b"done-5"
                assert store.exists(folder / "absent", parent=fd) is False
                with pytest.raises(MailboxRefusal, match="^mailbox refused: missing$"):
                    store.read(folder / "absent", parent=fd)
                assert set(folder.iterdir()) == present
                assert not owner_plane.exists()
                assert len(store.entries(folder, parent=fd)) == 6


def test_publish_counts_data_and_directory_syncs_separately(parent, monkeypatch, owner_plane):
    record = parent / "record"
    with _counted_syncs(monkeypatch) as counts:
        with storage.Store.from_parent(parent) as store:
            store.publish(record, b"synced")
            assert store.read(record) == b"synced"
    assert counts["proof"] == 0
    assert counts["proof_open"] == 0
    assert counts["data"] >= 1
    assert counts["directory"] >= 1
    assert not list(owner_plane.iterdir())
