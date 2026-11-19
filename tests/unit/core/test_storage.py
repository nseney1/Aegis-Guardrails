"""aegis_core.storage atomic writes and JSONL I/O (ADR 0005 AD-3 L0)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from unittest.mock import patch

import pytest

from aegis_core.storage import append_jsonl, atomic_write_bytes, atomic_write_text, read_jsonl

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")


@pytest.fixture
def umask():
    """Set the process umask for one test and restore it."""
    saved = []

    def set_mask(mask: int) -> None:
        saved.append(os.umask(mask))

    yield set_mask
    if saved:
        os.umask(saved[0])


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# ── atomic writes ────────────────────────────────────────────────────────────

def test_atomic_write_text_creates_parent_and_file(tmp_path: Path):
    target = tmp_path / "subdir" / "test.txt"
    atomic_write_text(target, "hello world\n")
    assert target.read_bytes() == b"hello world\n"


def test_atomic_write_text_keeps_crlf_bytes(tmp_path: Path):
    target = tmp_path / "crlf.md"
    atomic_write_text(target, "a\r\nb\r\n")
    assert target.read_bytes() == b"a\r\nb\r\n"


def test_atomic_write_overwrites_existing(tmp_path: Path):
    target = tmp_path / "test.txt"
    target.write_text("initial content", encoding="utf-8")
    atomic_write_text(target, "updated content")
    assert target.read_text(encoding="utf-8") == "updated content"


def test_atomic_write_bytes(tmp_path: Path):
    target = tmp_path / "binary.dat"
    atomic_write_bytes(target, b"\x00\x01\x02\xff")
    assert target.read_bytes() == b"\x00\x01\x02\xff"


@posix_only
@pytest.mark.parametrize("mask, expected", [(0o022, 0o644), (0o077, 0o600), (0o002, 0o664)])
def test_new_file_mode_follows_the_umask(tmp_path: Path, umask, mask: int, expected: int):
    umask(mask)
    target = tmp_path / "new.json"
    atomic_write_text(target, "{}")
    assert _mode(target) == expected


@posix_only
@pytest.mark.parametrize("mode", [0o640, 0o755, 0o600])
def test_existing_file_keeps_its_mode(tmp_path: Path, umask, mode: int):
    umask(0o022)
    target = tmp_path / "rule.md"
    target.write_text("old", encoding="utf-8")
    os.chmod(target, mode)
    atomic_write_text(target, "new")
    assert target.read_text(encoding="utf-8") == "new"
    assert _mode(target) == mode


def test_atomic_write_retries_windows_sharing_violation(tmp_path: Path):
    target = tmp_path / "locked.txt"
    attempts = 0
    real_replace = os.replace

    def flaky_replace(src, dst):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            err = PermissionError("[WinError 32] The process cannot access the file")
            err.winerror = 32
            raise err
        return real_replace(src, dst)

    with patch("os.replace", side_effect=flaky_replace):
        atomic_write_text(target, "eventually written", initial_delay=0.001)
    assert attempts == 3
    assert target.read_text(encoding="utf-8") == "eventually written"


def test_atomic_write_gives_up_after_eight_attempts(tmp_path: Path):
    target = tmp_path / "never.txt"
    attempts = 0

    def always_locked(src, dst):
        nonlocal attempts
        attempts += 1
        raise PermissionError("[WinError 32] Sharing violation")

    with patch("os.replace", side_effect=always_locked):
        with pytest.raises(PermissionError):
            atomic_write_text(target, "x", initial_delay=0.0001)
    assert attempts == 8
    assert list(tmp_path.iterdir()) == []


def test_atomic_write_failure_leaves_target_and_no_temp(tmp_path: Path):
    target = tmp_path / "fail.txt"
    target.write_text("original", encoding="utf-8")

    with patch("os.replace", side_effect=RuntimeError("Disk explosion")):
        with pytest.raises(RuntimeError, match="Disk explosion"):
            atomic_write_text(target, "doomed", initial_delay=0.001)

    assert target.read_text(encoding="utf-8") == "original"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["fail.txt"]


# ── append_jsonl ─────────────────────────────────────────────────────────────

def test_append_jsonl_writes_one_object_per_line(tmp_path: Path):
    path = tmp_path / "state" / "ledger.jsonl"
    assert append_jsonl(path, [{"a": 1}, {"b": "two"}]) == 2
    assert append_jsonl(path, [{"c": None}]) == 1
    assert [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] == [
        {"a": 1}, {"b": "two"}, {"c": None},
    ]


def test_append_jsonl_keeps_the_file_valid_utf8(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    append_jsonl(path, [{"note": "café \ud800  "}])
    raw = path.read_bytes()
    raw.decode("utf-8")  # a lone surrogate must not reach the file as raw bytes
    assert read_jsonl(path).rows == [{"note": "café \ud800  "}]
    assert raw.count(b"\n") == 1


def test_append_jsonl_terminates_a_torn_tail_before_writing(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    path.write_bytes(b'{"a":1}\n{"b":')  # a crash mid-write
    append_jsonl(path, [{"c": 3}])
    assert path.read_bytes() == b'{"a":1}\n{"b":\n{"c":3}\n'
    result = read_jsonl(path)
    assert result.rows == [{"a": 1}, {"c": 3}]
    assert result.skipped_lines == [2]


def test_append_jsonl_writes_nothing_when_a_row_cannot_be_serialized(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    path.write_bytes(b'{"a":1}\n')
    with pytest.raises((TypeError, ValueError)):
        append_jsonl(path, [{"ok": 1}, {"bad": object()}])
    with pytest.raises(ValueError):
        append_jsonl(path, [{"nan": float("nan")}])
    with pytest.raises(ValueError, match="JSON object"):
        append_jsonl(path, [["not", "an", "object"]])
    assert path.read_bytes() == b'{"a":1}\n'


def test_append_jsonl_fsyncs_once_per_call(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    path.write_bytes(b'{"a":1}\n')
    real_fsync = os.fsync
    calls = []

    def counting(fd):
        calls.append(fd)
        return real_fsync(fd)

    with patch("os.fsync", side_effect=counting):
        append_jsonl(path, [{"n": i} for i in range(50)])
    assert len(calls) == 1
    assert len(read_jsonl(path).rows) == 51


@posix_only
def test_append_jsonl_new_file_follows_the_umask(tmp_path: Path, umask):
    umask(0o022)
    path = tmp_path / "ledger.jsonl"
    append_jsonl(path, [{"a": 1}])
    assert _mode(path) == 0o644


def test_append_jsonl_with_no_rows_creates_nothing(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    assert append_jsonl(path, []) == 0
    assert not path.exists()


# ── read_jsonl ───────────────────────────────────────────────────────────────

def test_read_jsonl_missing_file_is_empty(tmp_path: Path):
    result = read_jsonl(tmp_path / "nope.jsonl")
    assert (result.rows, result.skipped, result.torn_tail, result.error) == ([], 0, False, None)


def test_read_jsonl_skips_and_counts_invalid_lines(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    deep = b"[" * 100000 + b"]" * 100000
    path.write_bytes(
        b"\xef\xbb\xbf" + b'{"first":1}\n'   # BOM
        + b"\n"                               # blank: ignored, not counted
        + b"not json\n"                       # 3
        + b'"a string"\n'                     # 4: not an object
        + b'{"bad":"\xff\xfe"}\n'             # 5: invalid UTF-8
        + deep + b"\n"                        # 6: nesting past the recursion limit
        + b'{"crlf":true}\r\n'                # CRLF line endings are fine
        + b"   \t\n"                          # whitespace only: ignored
        + b'{"last":2}\n'
    )
    result = read_jsonl(path)
    assert result.rows == [{"first": 1}, {"crlf": True}, {"last": 2}]
    assert result.line_numbers == [1, 7, 9]
    assert result.skipped_lines == [3, 4, 5, 6]
    assert result.skipped == 4
    assert result.torn_tail is False


def test_read_jsonl_reports_a_torn_tail_separately(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    path.write_bytes(b'{"a":1}\n{"b":')
    result = read_jsonl(path)
    assert result.rows == [{"a": 1}]
    assert result.skipped == 0
    assert result.torn_tail is True


def test_read_jsonl_accepts_a_complete_last_line_without_newline(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    path.write_bytes(b'{"a":1}\n{"b":2}')
    result = read_jsonl(path)
    assert result.rows == [{"a": 1}, {"b": 2}]
    assert result.torn_tail is False


def test_read_jsonl_reports_an_unreadable_file_without_raising(tmp_path: Path):
    path = tmp_path / "dir.jsonl"
    path.mkdir()
    result = read_jsonl(path)
    assert result.rows == []
    assert result.error is not None and str(path) in result.error


# ── Never through a link (review B2a round 3, F1) ────────────────────────────

def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")


def test_append_jsonl_never_writes_through_a_symlink(tmp_path: Path):
    from aegis_core.errors import PathTraversalError

    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"keep me\n")
    link = tmp_path / "ledger.jsonl"
    _symlink_or_skip(link, victim)

    with pytest.raises(PathTraversalError, match=r"ledger\.jsonl: it is a symlink"):
        append_jsonl(link, [{"rule": "x$(touch /tmp/pwn)"}])

    assert victim.read_bytes() == b"keep me\n"
    assert link.is_symlink()


def test_append_jsonl_never_creates_the_target_of_a_dangling_symlink(tmp_path: Path):
    from aegis_core.errors import PathTraversalError

    target = tmp_path / "created-by-aegis.txt"
    link = tmp_path / "gate_events.jsonl"
    _symlink_or_skip(link, target)

    with pytest.raises(PathTraversalError, match="it is a symlink"):
        append_jsonl(link, [{"a": 1}])

    assert not os.path.lexists(target)


def test_read_jsonl_does_not_follow_a_symlink(tmp_path: Path):
    victim = tmp_path / "victim.jsonl"
    victim.write_bytes(b'{"secret": 1}\n')
    link = tmp_path / "ledger.jsonl"
    _symlink_or_skip(link, victim)

    result = read_jsonl(link)

    assert result.rows == []
    assert result.error is not None and "symlink" in result.error and str(link) in result.error


# ── Exact modes for private copies (review B2a round 3, F2) ──────────────────

@posix_only
@pytest.mark.parametrize("mode", [0o600, 0o640, 0o755])
def test_atomic_write_bytes_can_set_an_exact_mode(tmp_path: Path, umask, mode: int):
    umask(0o022)
    target = tmp_path / "copy.key"
    atomic_write_bytes(target, b"k", mode=mode)
    assert _mode(target) == mode
    atomic_write_bytes(target, b"k2", mode=0o600)  # an explicit mode wins over the existing one
    assert _mode(target) == 0o600


# ── Legacy files written with surrogatepass (review B2a round 3, F5) ─────────

def test_read_jsonl_can_decode_like_the_v3_writer(tmp_path: Path):
    path = tmp_path / "signals.jsonl"
    row = {"metadata": {"target_files": ["caf\udce9.py"]}}
    path.write_bytes(json.dumps(row, ensure_ascii=False).encode("utf-8", "surrogatepass") + b"\n")

    strict = read_jsonl(path)
    assert strict.rows == [] and strict.skipped_lines == [1]

    legacy = read_jsonl(path, errors="surrogatepass")
    assert legacy.rows == [row]
    assert legacy.skipped_lines == []


# ── One location, however the OS spells it (Windows CI, wave B2a) ────────────
# Windows' realpath can answer for a directory another process is creating in its
# extended-length form (\\?\C:\...): three processes appending to one new ledger saw
# .aegis/state "resolve outside the workspace". realpath is the OS boundary faked here.

def _extended_spelling(monkeypatch, target=None):
    """os.path.realpath answers for any path named ``state`` as ``\\\\?\\`` + where it
    resolves (or + ``target``, a directory elsewhere)."""
    real = os.path.realpath

    def realpath(path, *args, **kwargs):
        resolved = real(path, *args, **kwargs)
        if os.path.basename(resolved) == "state":
            return "\\\\?\\" + (str(target) if target is not None else resolved)
        return resolved

    monkeypatch.setattr(os.path, "realpath", realpath)


def test_the_state_dir_is_inside_the_workspace_in_its_extended_length_spelling(tmp_path: Path, monkeypatch):
    from aegis_core.storage import state_dir

    ws = tmp_path / "ws"
    ws.mkdir()
    _extended_spelling(monkeypatch)

    assert state_dir(ws) == Path(os.path.realpath(ws)) / ".aegis" / "state"
    assert (ws / ".aegis" / "state" / ".gitignore").is_file()


def test_the_lock_and_appends_work_in_the_extended_length_spelling(tmp_path: Path, monkeypatch):
    from aegis_core.storage import locked

    ws = tmp_path / "ws"
    ws.mkdir()
    _extended_spelling(monkeypatch)

    with locked(ws):
        with locked(str(ws), timeout=0.5):  # re-entrant: one location, one lock
            append_jsonl(ws / ".aegis" / "state" / "ledger.jsonl", [{"a": 1}])

    assert read_jsonl(ws / ".aegis" / "state" / "ledger.jsonl").rows == [{"a": 1}]


def test_a_state_dir_resolving_elsewhere_is_still_refused_in_the_extended_length_spelling(tmp_path: Path, monkeypatch):
    """What a Windows junction looks like: not a symlink, but it resolves outside."""
    from aegis_core.errors import PathTraversalError
    from aegis_core.storage import state_dir

    ws = tmp_path / "ws"
    (ws / ".aegis" / "state").mkdir(parents=True)
    outside = tmp_path / "outside" / "state"
    outside.mkdir(parents=True)
    _extended_spelling(monkeypatch, target=outside)

    with pytest.raises(PathTraversalError, match="resolves outside the workspace"):
        state_dir(ws)
    assert list(outside.iterdir()) == []


def test_a_state_dir_holding_subdirectories_is_used(tmp_path: Path):
    from aegis_core.storage import state_dir

    ws = tmp_path / "ws"
    (ws / ".aegis" / "state" / "backups" / "2026").mkdir(parents=True)
    (ws / ".aegis" / "state" / "ledger.jsonl").write_text("", encoding="utf-8")

    assert state_dir(ws) == Path(os.path.realpath(ws)) / ".aegis" / "state"


def test_an_entry_of_the_state_dir_resolving_elsewhere_is_refused(tmp_path: Path, monkeypatch):
    """A junction inside .aegis/state: not a symlink, but what is written through it lands outside."""
    from aegis_core.errors import PathTraversalError
    from aegis_core.storage import state_dir

    ws = tmp_path / "ws"
    (ws / ".aegis" / "state" / "backups").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    real = os.path.realpath

    def realpath(path, *args, **kwargs):
        resolved = real(path, *args, **kwargs)
        return str(outside) if os.path.basename(resolved) == "backups" else resolved

    monkeypatch.setattr(os.path, "realpath", realpath)

    with pytest.raises(PathTraversalError, match="backups: it resolves outside the workspace"):
        state_dir(ws)


# ── follow_links=False: a link at the name is replaced, never followed (R-cli-41) ─

def _strays(*directories: Path) -> list:
    return sorted(p.name for d in directories for p in d.iterdir() if p.name.endswith(".tmp"))


def test_by_default_a_write_goes_through_a_link_at_the_name(tmp_path: Path):
    victim = tmp_path / "victim.json"
    victim.write_bytes(b"old")
    link = tmp_path / "config.json"
    _symlink_or_skip(link, victim)
    atomic_write_bytes(link, b"new")
    assert link.is_symlink() and victim.read_bytes() == b"new"


def test_without_following_links_the_link_is_replaced_and_its_target_spared(tmp_path: Path):
    """Given a symlink at the name, When it is written with follow_links=False, Then the name
    becomes a regular file holding the data and the link's target keeps its bytes."""
    victim = tmp_path / "victim.json"
    victim.write_bytes(b"precious")
    link = tmp_path / "config.json"
    _symlink_or_skip(link, victim)
    atomic_write_bytes(link, b"new", follow_links=False)
    assert not link.is_symlink() and link.read_bytes() == b"new"
    assert victim.read_bytes() == b"precious"
    assert _strays(tmp_path) == []


@posix_only
def test_a_replaced_link_inherits_none_of_its_targets_bits(tmp_path: Path, umask):
    umask(0o022)
    victim = tmp_path / "victim"
    victim.write_bytes(b"#!/bin/sh\n")
    os.chmod(victim, 0o4755)
    link = tmp_path / "config.json"
    _symlink_or_skip(link, victim)
    atomic_write_bytes(link, b"{}", follow_links=False)
    assert _mode(link) == 0o644
    assert stat.S_IMODE(os.lstat(victim).st_mode) == 0o4755 and victim.read_bytes() == b"#!/bin/sh\n"


def test_a_dangling_link_is_replaced_without_creating_its_target(tmp_path: Path):
    missing = tmp_path / "nowhere" / "target.json"
    link = tmp_path / "config.json"
    _symlink_or_skip(link, missing)
    atomic_write_bytes(link, b"{}", follow_links=False)
    assert not link.is_symlink() and link.read_bytes() == b"{}"
    assert not missing.parent.exists()


@pytest.mark.parametrize("relative", ["through/config.json", "through/sub/../config.json"],
                         ids=["direct", "dotdot"])
def test_a_linked_directory_above_the_name_is_still_written_through(tmp_path: Path, relative: str):
    real = tmp_path / "real"
    (real / "sub").mkdir(parents=True)
    try:
        (tmp_path / "through").symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    atomic_write_bytes(tmp_path / relative, b"{}", follow_links=False)
    assert (real / "config.json").read_bytes() == b"{}"
    assert _strays(real, real / "sub", tmp_path) == []


@posix_only
def test_without_following_links_an_existing_regular_file_keeps_its_mode(tmp_path: Path, umask):
    umask(0o022)
    target = tmp_path / "rule.md"
    target.write_bytes(b"old")
    os.chmod(target, 0o640)
    atomic_write_bytes(target, b"new", follow_links=False)
    assert _mode(target) == 0o640 and target.read_bytes() == b"new"


# ── The temporary file's mode is set through its descriptor (review L3) ─────────

@posix_only
def test_the_mode_is_set_on_the_temporary_file_never_on_a_link_swapped_in_at_its_name(
        tmp_path: Path, umask, monkeypatch):
    """Given a write with an exact mode, When a symlink to another file is swapped in at the
    temporary name after it was opened, Then the opened file gets the mode and the link's
    target keeps its own."""
    from aegis_core import atomicio

    umask(0o022)
    victim = tmp_path / "victim"
    victim.write_bytes(b"precious")
    os.chmod(victim, 0o600)
    out = tmp_path / "out"
    out.mkdir()
    moved = tmp_path / "opened-file"
    real_write_all = atomicio._write_all

    def write_then_swap(fd, data):
        real_write_all(fd, data)
        tmp, = (p for p in out.iterdir() if p.name.endswith(".tmp"))
        os.rename(tmp, moved)
        _symlink_or_skip(tmp, victim)

    monkeypatch.setattr(atomicio, "_write_all", write_then_swap)
    atomic_write_bytes(out / "config.json", b"{}", mode=0o644)
    assert stat.S_IMODE(os.lstat(victim).st_mode) == 0o600 and victim.read_bytes() == b"precious"
    assert _mode(moved) == 0o644 and moved.read_bytes() == b"{}"


# ── create_private_file: an exclusive 0o600 file, never through a link (R-evidence-45) ──

def test_create_private_file_writes_a_new_file_exclusively(tmp_path: Path, umask):
    from aegis_core.storage import create_private_file

    umask(0o000)
    target = tmp_path / "link.key"
    assert create_private_file(target, b"k" * 32) is True
    assert target.read_bytes() == b"k" * 32
    if os.name == "posix":
        assert _mode(target) == 0o600


def test_create_private_file_leaves_an_existing_file_alone(tmp_path: Path):
    from aegis_core.storage import create_private_file

    target = tmp_path / "link.key"
    target.write_bytes(b"old")
    assert create_private_file(target, b"new") is False
    assert target.read_bytes() == b"old"


@pytest.mark.parametrize("dangling", [False, True], ids=["link", "dangling"])
def test_create_private_file_refuses_a_symlink(tmp_path: Path, dangling: bool):
    from aegis_core.errors import PathTraversalError
    from aegis_core.storage import create_private_file

    victim = tmp_path / "victim"
    if not dangling:
        victim.write_bytes(b"precious")
    target = tmp_path / "link.key"
    _symlink_or_skip(target, victim)
    with pytest.raises(PathTraversalError):
        create_private_file(target, b"k" * 32)
    assert victim.read_bytes() == b"precious" if not dangling else not victim.exists()
    assert os.path.islink(target)


def test_create_private_file_refuses_a_directory(tmp_path: Path):
    from aegis_core.errors import PathTraversalError
    from aegis_core.storage import create_private_file

    (tmp_path / "link.key").mkdir()
    with pytest.raises(PathTraversalError):
        create_private_file(tmp_path / "link.key", b"k")
    assert (tmp_path / "link.key").is_dir()


def test_create_private_file_removes_a_partial_file_when_the_write_fails(tmp_path: Path, monkeypatch):
    from aegis_core import atomicio, storage

    def broken(fd, data):
        os.write(fd, data[:3])
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(atomicio, "_write_all", broken)
    with pytest.raises(OSError, match="No space"):
        storage.create_private_file(tmp_path / "link.key", b"k" * 32)
    assert list(tmp_path.iterdir()) == []


# ── file_lock anchored to a directory descriptor ─────────────────────────────
# macOS hosted CI (run 42491904451) saw the anchored O_CREAT open of a lock file fail
# with ENOENT while four processes created it at once in a live directory. These tests
# inject that interleaving through os.open so it reproduces on any POSIX host.

dir_fd_only = pytest.mark.skipif(os.name != "posix", reason="POSIX directory descriptors")


def _enoent(name: str) -> FileNotFoundError:
    import errno

    return FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), name)


def _anchored_lock_opens(monkeypatch, hook) -> list:
    """Send every open of "audit.lock" relative to a dir fd to ``hook(real_open, name,
    flags, mode, dir_fd, attempt)``; other opens are untouched. Returns the call list."""
    real_open = os.open
    calls: list = []

    def wrapper(path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is not None and os.fspath(path) == "audit.lock":
            calls.append(flags)
            return hook(real_open, path, flags, mode, dir_fd, len(calls))
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", wrapper)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {wrapper})
    return calls


@pytest.fixture
def lock_dir(tmp_path: Path):
    """A private directory and a descriptor for it, closed after the test."""
    root = tmp_path / "store"
    root.mkdir(mode=0o700)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    yield root, fd
    os.close(fd)


class _FakeClock:
    """Stands in for ``time`` inside aegis_core.storage, so no test depends on wall-clock
    speed: ``sleep`` records the request and advances ``monotonic`` by it, plus
    ``overshoot(seconds)`` to model a host that oversleeps."""

    def __init__(self, overshoot=lambda seconds: 0.0):
        self.now = 1000.0
        self.sleeps: list = []
        self._overshoot = overshoot

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds + self._overshoot(seconds)


def _fake_clock(monkeypatch, **kwargs) -> _FakeClock:
    from aegis_core import storage

    clock = _FakeClock(**kwargs)
    monkeypatch.setattr(storage, "time", clock)
    return clock


@dir_fd_only
def test_the_enoent_retry_is_small_and_bounded():
    from aegis_core import storage

    attempts = storage._LOCK_OPEN_ENOENT_ATTEMPTS
    first = storage._LOCK_OPEN_ENOENT_DELAY_SECONDS
    assert 2 <= attempts <= 10
    # Every sleep doubles the last one; all of them together stay far below the 5 s lock wait.
    assert 0 < sum(first * 2 ** n for n in range(attempts - 1)) < 0.5


@dir_fd_only
def test_an_anchored_lock_opens_the_file_another_process_created_during_a_transient_enoent(lock_dir, monkeypatch):
    import fcntl

    from aegis_core import storage

    root, fd = lock_dir
    created = []

    def racing_creator(real_open, name, flags, mode, dir_fd, attempt):
        if attempt == 1:
            # The other process wins the creation; this open still reports ENOENT (macOS).
            other = real_open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o644, dir_fd=dir_fd)
            created.append(os.fstat(other).st_ino)
            os.close(other)
            raise _enoent(name)
        return real_open(name, flags, mode, dir_fd=dir_fd)

    calls = _anchored_lock_opens(monkeypatch, racing_creator)
    with storage.file_lock(root / "audit.lock", dir_fd=fd):
        info = os.lstat(root / "audit.lock")
        assert info.st_ino == created[0]
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        assert stat.S_IMODE(info.st_mode) == 0o600
        probe = os.open(root / "audit.lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(probe)
    assert len(calls) == 2
    assert sorted(os.listdir(root)) == ["audit.lock"]


@dir_fd_only
def test_an_anchored_lock_gives_up_after_the_bounded_enoent_attempts(lock_dir, monkeypatch):
    from aegis_core import storage

    root, fd = lock_dir

    def always_enoent(real_open, name, flags, mode, dir_fd, attempt):
        raise _enoent(name)

    calls = _anchored_lock_opens(monkeypatch, always_enoent)
    clock = _fake_clock(monkeypatch)
    with pytest.raises(FileNotFoundError), storage.file_lock(root / "audit.lock", dir_fd=fd):
        pytest.fail("lock admitted without an open")
    attempts = storage._LOCK_OPEN_ENOENT_ATTEMPTS
    assert len(calls) == attempts
    # One doubling sleep between attempts, none after the last: the whole wait is bounded.
    first = storage._LOCK_OPEN_ENOENT_DELAY_SECONDS
    assert clock.sleeps == [first * 2 ** n for n in range(attempts - 1)]
    assert os.listdir(root) == []


@dir_fd_only
def test_an_anchored_lock_does_not_retry_past_the_callers_timeout(lock_dir, monkeypatch):
    from aegis_core import storage

    root, fd = lock_dir

    def always_enoent(real_open, name, flags, mode, dir_fd, attempt):
        raise _enoent(name)

    calls = _anchored_lock_opens(monkeypatch, always_enoent)
    with pytest.raises(FileNotFoundError), storage.file_lock(root / "audit.lock", timeout=0, dir_fd=fd):
        pytest.fail("lock admitted without an open")
    assert len(calls) == 1


@dir_fd_only
def test_an_anchored_lock_in_a_removed_directory_fails_closed_without_retrying(tmp_path: Path, monkeypatch):
    from aegis_core import storage
    from aegis_core.errors import PathTraversalError

    root = tmp_path / "store"
    root.mkdir(mode=0o700)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        root.rmdir()
        calls = _anchored_lock_opens(
            monkeypatch, lambda real_open, name, flags, mode, dir_fd, attempt: real_open(name, flags, mode, dir_fd=dir_fd))
        # Linux reports an unlinked directory with st_nlink 0, and the lock refuses it at once.
        # A platform that kept a nonzero count would still fail closed after the bounded attempts.
        nlink = os.fstat(fd).st_nlink
        # Shown with -rA: tells a hosted run which branch this platform took.
        print(f"removed lock directory: st_nlink={nlink} platform={os.uname().sysname}")
        unlinked = nlink == 0
        clock = _fake_clock(monkeypatch)
        with pytest.raises(PathTraversalError if unlinked else FileNotFoundError), \
                storage.file_lock(root / "audit.lock", dir_fd=fd):
            pytest.fail("lock admitted in a removed directory")
        assert len(calls) == (1 if unlinked else storage._LOCK_OPEN_ENOENT_ATTEMPTS)
        assert len(clock.sleeps) == len(calls) - 1
        if os.uname().sysname == "Linux":
            assert unlinked
    finally:
        os.close(fd)
    assert os.listdir(tmp_path) == []


@dir_fd_only
def test_an_anchored_lock_does_not_retry_other_open_errors(lock_dir, monkeypatch):
    import errno

    from aegis_core import storage

    root, fd = lock_dir

    def denied(real_open, name, flags, mode, dir_fd, attempt):
        raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), name)

    calls = _anchored_lock_opens(monkeypatch, denied)
    with pytest.raises(PermissionError), storage.file_lock(root / "audit.lock", dir_fd=fd):
        pytest.fail("lock admitted without an open")
    assert len(calls) == 1
    assert os.listdir(root) == []


@dir_fd_only
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory"])
def test_an_anchored_lock_retry_keeps_refusing_unsafe_entries(tmp_path: Path, lock_dir, monkeypatch, kind):
    from aegis_core import storage
    from aegis_core.errors import PathTraversalError
    from tests.conftest import symlink_or_skip

    root, fd = lock_dir
    outside = tmp_path / "outside"
    outside.write_bytes(b"retain bytes\n")
    outside.chmod(0o644)

    def plant_on_retry(real_open, name, flags, mode, dir_fd, attempt):
        if attempt == 1:
            raise _enoent(name)
        if kind == "symlink":
            symlink_or_skip(outside, root / "audit.lock")
        elif kind == "hardlink":
            os.link(outside, root / "audit.lock")
        else:
            (root / "audit.lock").mkdir()
        return real_open(name, flags, mode, dir_fd=dir_fd)

    calls = _anchored_lock_opens(monkeypatch, plant_on_retry)
    with pytest.raises(PathTraversalError), storage.file_lock(root / "audit.lock", dir_fd=fd):
        pytest.fail("unsafe lock admitted")
    assert len(calls) == 2
    assert outside.read_bytes() == b"retain bytes\n"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o644


# The hosted traceback shows the stat after the ENOENT found a private regular lock file.
# The next attempt then only looks the name up (no O_CREAT), so it does not go through the
# create path that just failed.

def _racing_creator_then(after):
    """Hook: attempt 1 lets another process create audit.lock and still reports ENOENT
    (as macOS did); later attempts go to ``after``."""
    def hook(real_open, name, flags, mode, dir_fd, attempt):
        if attempt == 1:
            other = real_open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o644, dir_fd=dir_fd)
            os.close(other)
            raise _enoent(name)
        return after(real_open, name, flags, mode, dir_fd, attempt)
    return hook


def _assert_locked(path: Path) -> None:
    import fcntl

    probe = os.open(path, os.O_RDWR)
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(probe)


@dir_fd_only
def test_an_anchored_lock_reopens_the_racing_creators_file_without_o_creat(lock_dir, monkeypatch):
    from aegis_core import storage

    root, fd = lock_dir
    calls = _anchored_lock_opens(monkeypatch, _racing_creator_then(
        lambda real_open, name, flags, mode, dir_fd, attempt: real_open(name, flags, mode, dir_fd=dir_fd)))
    inode = None
    with storage.file_lock(root / "audit.lock", dir_fd=fd):
        info = os.lstat(root / "audit.lock")
        inode = info.st_ino
        assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
        _assert_locked(root / "audit.lock")
    assert len(calls) == 2
    assert calls[0] & os.O_CREAT and calls[0] & os.O_NOFOLLOW
    # Exactly the first open's flags without O_CREAT: still O_NOFOLLOW, O_NONBLOCK, O_CLOEXEC.
    assert calls[1] == calls[0] & ~os.O_CREAT
    assert inode == os.lstat(root / "audit.lock").st_ino
    assert sorted(os.listdir(root)) == ["audit.lock"]


@dir_fd_only
def test_an_anchored_lock_creates_again_when_the_lock_file_vanished(lock_dir, monkeypatch):
    from aegis_core import storage

    root, fd = lock_dir

    def vanish_once(real_open, name, flags, mode, dir_fd, attempt):
        if attempt == 2:
            os.unlink(name, dir_fd=dir_fd)  # the file really went away before the lookup-only open
        return real_open(name, flags, mode, dir_fd=dir_fd)

    calls = _anchored_lock_opens(monkeypatch, _racing_creator_then(vanish_once))
    with storage.file_lock(root / "audit.lock", dir_fd=fd):
        info = os.lstat(root / "audit.lock")
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        assert stat.S_IMODE(info.st_mode) == 0o600
        _assert_locked(root / "audit.lock")
    create = calls[0]
    assert create & os.O_CREAT
    assert calls == [create, create & ~os.O_CREAT, create]
    assert sorted(os.listdir(root)) == ["audit.lock"]


@dir_fd_only
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory"])
def test_an_anchored_lock_open_without_o_creat_still_refuses_unsafe_entries(tmp_path: Path, lock_dir, monkeypatch,
                                                                            kind):
    from aegis_core import storage
    from aegis_core.errors import PathTraversalError
    from tests.conftest import symlink_or_skip

    root, fd = lock_dir
    outside = tmp_path / "outside"
    outside.write_bytes(b"retain bytes\n")
    outside.chmod(0o644)

    def swap_before_lookup(real_open, name, flags, mode, dir_fd, attempt):
        # The stat saw a regular file; it is replaced before the lookup-only open.
        os.unlink(name, dir_fd=dir_fd)
        if kind == "symlink":
            symlink_or_skip(outside, root / "audit.lock")
        elif kind == "hardlink":
            os.link(outside, root / "audit.lock")
        else:
            (root / "audit.lock").mkdir()
        return real_open(name, flags, mode, dir_fd=dir_fd)

    calls = _anchored_lock_opens(monkeypatch, _racing_creator_then(swap_before_lookup))
    with pytest.raises(PathTraversalError), storage.file_lock(root / "audit.lock", dir_fd=fd):
        pytest.fail("unsafe lock admitted")
    assert len(calls) == 2
    assert calls[1] == calls[0] & ~os.O_CREAT
    assert outside.read_bytes() == b"retain bytes\n"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o644


# One time budget: the open retries and the lock wait together stay within ``timeout``.

@dir_fd_only
def test_an_anchored_lock_does_not_open_after_an_oversleep_crossed_the_deadline(lock_dir, monkeypatch):
    from aegis_core import storage

    root, fd = lock_dir
    # The racing creator makes the file, so a second open would succeed and admit the lock.
    calls = _anchored_lock_opens(monkeypatch, _racing_creator_then(
        lambda real_open, name, flags, mode, dir_fd, attempt: real_open(name, flags, mode, dir_fd=dir_fd)))
    clock = _fake_clock(monkeypatch, overshoot=lambda seconds: 2.0)  # a stalled host
    with pytest.raises(FileNotFoundError), storage.file_lock(root / "audit.lock", timeout=1.0, dir_fd=fd):
        pytest.fail("lock admitted after its deadline")
    assert len(calls) == 1
    assert clock.sleeps == [storage._LOCK_OPEN_ENOENT_DELAY_SECONDS]


@dir_fd_only
def test_an_anchored_lock_waits_only_for_what_the_open_retries_left_of_the_timeout(lock_dir, monkeypatch):
    import fcntl

    from aegis_core import storage
    from aegis_core.errors import LockTimeoutError
    from aegis_core.taxonomy import LOCK_MAX_BACKOFF_SECONDS

    root, fd = lock_dir
    holder = []

    def creator_holding_the_lock(real_open, name, flags, mode, dir_fd, attempt):
        if attempt == 1:
            # Another process creates the lock file and holds the lock; this open sees ENOENT.
            other = real_open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dir_fd)
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            holder.append(other)
            raise _enoent(name)
        return real_open(name, flags, mode, dir_fd=dir_fd)

    calls = _anchored_lock_opens(monkeypatch, creator_holding_the_lock)
    # The first sleep (the open retry) stalls 0.9 s of a 1 s budget; later sleeps are exact.
    clock = _fake_clock(monkeypatch, overshoot=lambda seconds: 0.9 if len(clock.sleeps) == 1 else 0.0)
    deadline = clock.now + 1.0
    try:
        with pytest.raises(LockTimeoutError) as raised, \
                storage.file_lock(root / "audit.lock", timeout=1.0, dir_fd=fd):
            pytest.fail("lock admitted while another process holds it")
    finally:
        for other in holder:
            os.close(other)
    assert len(calls) == 2
    assert clock.sleeps[0] == storage._LOCK_OPEN_ENOENT_DELAY_SECONDS
    # The wait ends at the caller's deadline (within one backoff step), not a full timeout later.
    assert deadline <= clock.now < deadline + LOCK_MAX_BACKOFF_SECONDS
    # The message still names the caller's whole timeout.
    assert str(raised.value).startswith("timed out after 1s waiting for the Aegis file lock ")
