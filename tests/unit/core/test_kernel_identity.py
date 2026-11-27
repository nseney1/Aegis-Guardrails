"""Shared kernel facts: bounded parsing, confinement and stable failures."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import errno
import os
import threading
from types import SimpleNamespace

import pytest

from aegis_core import kernel_identity as kernel
from aegis_core import storage_confined
from aegis_core import team_supervisor_start as starter
from aegis_core import team_writer_binding as binding
from aegis_mcp import queue_role


BOOT = "12345678-1234-1234-1234-123456789abc"


class _BorrowedParent:
    """Public parent_fd only. A closed borrow raises the storage refusal."""

    def __init__(self, read, fd):
        self._read = read
        self._fd = fd
        self._open = True

    @property
    def parent_fd(self):
        if not self._open:
            raise storage_confined.ConfinedFileError("closed")
        return self._fd

    def read_bytes(self, maximum):
        return self._read(maximum)

    def close(self):
        self._open = False


def proc_stat(pid=123, state=b"S", ticks=b"77", comm=b"name ) with ( spaces\n"):
    return str(pid).encode() + b" (" + comm + b") " + b" ".join([state] + [b"0"] * 18 + [ticks])


def source(monkeypatch, data):
    calls, closed = [], []
    monkeypatch.setattr(kernel, "descriptor_supported", lambda: True)

    @contextmanager
    def confined(root, parts):
        calls.append((str(root), parts))

        def read(maximum):
            item = data(parts) if callable(data) else data
            if isinstance(item, Exception):
                raise item
            if len(item) > maximum:
                raise storage_confined.ConfinedFileError("too_large")
            return item

        handle = _BorrowedParent(read, 42)
        try:
            yield handle
        finally:
            handle.close()
            closed.append(parts)

    return confined, calls, closed


@pytest.mark.parametrize("state", [b"S", b"Z", b"X", b"x"])
def test_start_ticks_and_zombies(monkeypatch, state):
    confined, calls, closed = source(monkeypatch, proc_stat(state=state))
    result = kernel.process_identity(123, confined_file=confined)
    assert result == ({"pid": 123, "start_ticks": 77} if state == b"S" else None)
    assert calls == [("/proc", ("123", "stat"))]
    assert closed == [("123", "stat")]


@pytest.mark.parametrize("raw", [b"", b"123 S 0", proc_stat(pid=124), proc_stat(ticks=b"-1"),
    proc_stat(ticks=b"9" * 21), proc_stat(ticks=b"x"), b"x" * 4097])
def test_malformed_stat_is_fixed_refusal_and_closes(monkeypatch, raw):
    confined, calls, closed = source(monkeypatch, raw)
    for _ in range(2):
        with pytest.raises(kernel.IdentityError, match="^kernel identity unavailable$"):
            kernel.process_identity(123, confined_file=confined)
    assert len(calls) == len(closed) == 2


@pytest.mark.parametrize("pid", [True, 0, -1, 2147483648, "123", None])
def test_invalid_pid_never_opens(monkeypatch, pid):
    confined, calls, _ = source(monkeypatch, proc_stat())
    with pytest.raises(kernel.IdentityError, match="^kernel identity unavailable$"):
        kernel.process_identity(pid, confined_file=confined)
    assert calls == []


@pytest.mark.parametrize("own", [proc_stat(pid=os.getpid()),
    storage_confined.ConfinedFileError("missing"), storage_confined.ConfinedFileError("io"),
    proc_stat(pid=os.getpid(), state=b"Z")], ids=["live", "missing", "unreadable", "zombie"])
def test_absence_requires_readable_live_self(monkeypatch, own):
    pid = 2147483647 if os.getpid() != 2147483647 else 2147483646
    confined, calls, closed = source(monkeypatch, lambda parts: own if parts[0] == str(os.getpid())
                                    else storage_confined.ConfinedFileError("missing"))
    if isinstance(own, bytes) and b") S " in own:
        assert kernel.process_identity(pid, confined_file=confined) is None
    else:
        with pytest.raises(kernel.IdentityError, match="^kernel identity unavailable$"):
            kernel.process_identity(pid, confined_file=confined)
    assert len(calls) == len(closed) == 2


@pytest.mark.parametrize("raw", [(BOOT + "\n").encode(), BOOT.encode()])
def test_boot_id_exact_format(monkeypatch, raw):
    confined, _, closed = source(monkeypatch, raw)
    assert kernel.boot_id(confined_file=confined) == BOOT
    assert closed == [("sys", "kernel", "random", "boot_id")]


@pytest.mark.parametrize("raw", [b"", (BOOT + "\r").encode(), (BOOT + "\n\n").encode(),
    b"-" * 36, b"\xff" * 36, b"x" * 1000])
def test_invalid_boot_refuses_without_echo(monkeypatch, raw):
    confined, _, closed = source(monkeypatch, raw)
    with pytest.raises(kernel.IdentityError, match="^kernel identity unavailable$"):
        kernel.boot_id(confined_file=confined)
    assert len(closed) == 1


@pytest.mark.parametrize("link", ["pid:[12345]", "pid:[x]", "pid:[" + "9" * 21 + "]", None])
def test_namespace_links_are_read_on_held_parents(monkeypatch, link):
    confined, calls, closed = source(monkeypatch, b"")
    seen = []

    def readlink(name, *, dir_fd):
        seen.append((name, dir_fd))
        return str(os.getpid()) if name == "self" else link

    if link == "pid:[12345]":
        assert kernel.pid_namespace(confined_file=confined, readlink=readlink) == link
    else:
        with pytest.raises(kernel.IdentityError, match="^kernel identity unavailable$"):
            kernel.pid_namespace(confined_file=confined, readlink=readlink)
    assert seen == [("self", 42), ("pid", 42)]
    assert calls == [("/proc", ("self",)), ("/proc", (str(os.getpid()), "ns", "pid"))]
    assert len(closed) == 2


def test_namespace_mount_mismatch_never_opens_numeric_pid(monkeypatch):
    confined, calls, closed = source(monkeypatch, b"")
    with pytest.raises(kernel.IdentityError, match="^kernel identity unavailable$"):
        kernel.pid_namespace(confined_file=confined, readlink=lambda *a, **k: "0")
    assert calls == [("/proc", ("self",))] and closed == [("self",)]


def test_unsupported_probe_prevents_io(monkeypatch):
    confined, calls, _ = source(monkeypatch, b"")
    monkeypatch.setattr(kernel, "descriptor_supported", lambda: False)
    for function, args in [(kernel.process_identity, (123,)), (kernel.boot_id, ()),
                           (kernel.pid_namespace, ()), (kernel.scope, ())]:
        with pytest.raises(kernel.IdentityError) as refused:
            function(*args, confined_file=confined)
        assert refused.value.reason == "unsupported"
    with pytest.raises(kernel.IdentityError) as refused:
        with kernel.owner_directory_lock(42):
            pytest.fail("unsupported lock entered")
    assert refused.value.reason == "unsupported" and calls == []


@pytest.mark.parametrize("number,reason", [(errno.EACCES, "locked"), (errno.EAGAIN, "locked"),
    (errno.EWOULDBLOCK, "locked"), (errno.EIO, "unavailable")])
def test_lock_failure_and_retry(monkeypatch, number, reason):
    if not kernel.descriptor_supported():
        pytest.skip("requires Linux directory locks")
    boundary = kernel.fcntl
    calls = []

    def flock(fd, operation):
        calls.append((fd, operation))
        if len(calls) == 1:
            raise OSError(number, "SECRET")

    monkeypatch.setattr(kernel, "fcntl", SimpleNamespace(**{**vars(boundary), "flock": flock}))
    with pytest.raises(kernel.IdentityError) as refused:
        with kernel.owner_directory_lock(42):
            pytest.fail("failed lock entered")
    assert refused.value.reason == reason and "SECRET" not in str(refused.value)
    with kernel.owner_directory_lock(42):
        pass
    assert calls == [(42, boundary.LOCK_EX | boundary.LOCK_NB)] * 2 + [(42, boundary.LOCK_UN)]


@pytest.mark.parametrize("reason,code", [("invalid", "role_invalid"), ("unavailable", "role_io_unavailable"),
    ("missing", "role_missing"), ("unsafe", "role_invalid"), ("unsupported", "unsupported_platform")])
def test_callers_keep_their_refusal_codes(monkeypatch, reason, code):
    monkeypatch.setattr(binding, "descriptor_supported", lambda: True)
    monkeypatch.setattr(starter, "descriptor_supported", lambda: True)

    def unavailable(*args, **kwargs):
        raise kernel.IdentityError(reason)

    monkeypatch.setattr(kernel, "process_identity", unavailable)
    for consumer in (binding, starter):
        with pytest.raises(consumer._Refusal) as refused:
            consumer.process_identity(123)
        assert refused.value.code == ("unsupported_platform" if reason == "unsupported" else "identity_unavailable")
    with pytest.raises(queue_role.RoleRefusal, match="^" + code + "$"):
        queue_role.process_identity()


def test_slice_callers_borrow_the_public_parent_descriptor():
    """Admitted callers reach the held parent only through parent_fd."""
    import ast
    from aegis_core import (
        team_gitops, team_profile, team_session_wake, team_supervisor, team_supervisor_observe,
    )
    modules = (
        kernel, team_gitops, team_profile, team_supervisor, team_supervisor_observe, team_session_wake,
    )
    private, public = [], set()
    for item in modules:
        tree = ast.parse(open(item.__file__, encoding="utf-8").read(), filename=item.__file__)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "_parent":
                private.append(item.__name__ + ":" + str(node.lineno))
            elif isinstance(node, ast.Attribute) and node.attr == "parent_fd":
                public.add(item.__name__)
            elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                  and node.func.id == "getattr" and len(node.args) >= 2
                  and isinstance(node.args[1], ast.Constant) and node.args[1].value == "_parent"):
                private.append(item.__name__ + ":" + str(node.lineno))
    assert private == []
    assert public == {item.__name__ for item in modules}


def test_closed_borrow_refuses_then_retry_reads_an_open_parent(monkeypatch):
    """A closed parent_fd is the fixed identity refusal; a later open borrow succeeds."""
    monkeypatch.setattr(kernel, "descriptor_supported", lambda: True)
    state = {"open": False}
    entered = []

    class Handle:
        @property
        def parent_fd(self):
            if not state["open"]:
                raise storage_confined.ConfinedFileError("closed")
            return 42

    @contextmanager
    def confined(root, parts):
        entered.append(parts)
        yield Handle()

    def readlink(name, *, dir_fd):
        assert dir_fd == 42
        return str(os.getpid()) if name == "self" else "pid:[12345]"

    with pytest.raises(kernel.IdentityError) as refused:
        kernel.pid_namespace(confined_file=confined, readlink=readlink)
    assert refused.value.reason == "closed"
    assert str(refused.value) == "kernel identity unavailable"
    state["open"] = True
    assert kernel.pid_namespace(confined_file=confined, readlink=readlink) == "pid:[12345]"
    assert entered == [("self",), ("self",), (str(os.getpid()), "ns", "pid")]


def test_detached_borrow_survives_link_failure_and_retry(tmp_path, monkeypatch):
    """The caller owns the directory descriptor. Link failure must not close it."""
    if not kernel.descriptor_supported():
        pytest.skip("requires a Linux directory descriptor")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(tmp_path, flags)
    try:
        attempts = {"n": 0}

        class Handle:
            @property
            def parent_fd(self):
                return fd

        @contextmanager
        def confined(root, parts):
            yield Handle()

        def readlink(name, *, dir_fd):
            os.fstat(dir_fd)
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise OSError(errno.EIO, "TOKEN=secret")
            return str(os.getpid()) if name == "self" else "pid:[8]"

        with pytest.raises(kernel.IdentityError) as refused:
            kernel.pid_namespace(confined_file=confined, readlink=readlink)
        assert refused.value.reason == "unavailable"
        assert str(refused.value) == "kernel identity unavailable"
        assert "secret" not in str(refused.value)
        os.fstat(fd)
        assert kernel.pid_namespace(confined_file=confined, readlink=readlink) == "pid:[8]"
        os.fstat(fd)
    finally:
        os.close(fd)


def test_concurrent_namespace_borrows_stay_distinct(monkeypatch):
    """Each open borrow is closed-checked on its own handle and is not shared."""
    monkeypatch.setattr(kernel, "descriptor_supported", lambda: True)
    local = threading.local()

    class Handle:
        @property
        def parent_fd(self):
            if not local.open:
                raise storage_confined.ConfinedFileError("closed")
            return local.fd

    @contextmanager
    def confined(root, parts):
        yield Handle()

    def readlink(name, *, dir_fd):
        if dir_fd != local.fd:
            raise OSError("crossed borrow")
        return str(os.getpid()) if name == "self" else "pid:[4]"

    def one(fd):
        local.fd = fd
        local.open = False
        with pytest.raises(kernel.IdentityError) as refused:
            kernel.pid_namespace(confined_file=confined, readlink=readlink)
        assert refused.value.reason == "closed"
        assert str(refused.value) == "kernel identity unavailable"
        local.open = True
        assert kernel.pid_namespace(confined_file=confined, readlink=readlink) == "pid:[4]"

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(one, fd) for fd in (11, 12, 13)]
        for future in futures:
            future.result(timeout=5)


def test_queue_identity_retains_session_filename_and_keys(monkeypatch):
    monkeypatch.setattr(kernel, "boot_id", lambda **kwargs: BOOT)
    monkeypatch.setattr(kernel, "process_identity", lambda pid, **kwargs: {"pid": pid, "start_ticks": 77})
    assert queue_role.process_identity() == {"boot_id": BOOT, "pid": os.getpid(), "start_ticks": 77}
    # Issuance and grant revalidation use this exact name, independent of namespace.
    assert queue_role._session_parts(queue_role.process_identity()) == (
        "sessions", BOOT + "-" + str(os.getpid()) + "-77.json")
