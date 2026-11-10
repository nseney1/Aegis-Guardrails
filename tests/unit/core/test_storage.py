"""aegis_core.storage atomic writes and JSONL I/O (ADR 0005 AD-3 L0)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from aegis_core import storage
from aegis_core.storage import append_jsonl, atomic_write_bytes, atomic_write_text, read_jsonl
from tests.conftest import symlink_or_skip

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
anchored_locks_only = pytest.mark.skipif(
    os.name != "posix" or os.open not in os.supports_dir_fd
    or not getattr(os, "O_NOFOLLOW", 0) or not getattr(os, "O_DIRECTORY", 0),
    reason="POSIX descriptor-relative locks require dir_fd and O_NOFOLLOW",
)
byte_range_locks_only = pytest.mark.skipif(
    storage.fcntl is not None or storage.msvcrt is None,
    reason="Windows byte-range lock primitive required",
)


# ── Descriptor-anchored file locks ───────────────────────────────────────────

@pytest.fixture
def lock_directory():
    descriptors = []

    def open_directory(path):
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(descriptor)
        return descriptor

    yield open_directory
    for descriptor in reversed(descriptors):
        os.close(descriptor)


def _contend_for_file_lock(path):
    """Use another process so a thread lock cannot conceal a missing OS lock."""
    env = {"HOME": str(path.parent), "USERPROFILE": str(path.parent),
           "PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
    result = subprocess.run(
        [sys.executable, "-I", "-c", """
import sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from aegis_core.errors import LockTimeoutError
from aegis_core.storage import file_lock
try:
    with file_lock(Path(sys.argv[2]), timeout=0.0):
        print("acquired")
except LockTimeoutError as exc:
    print(exc.code)
""", str(Path(__file__).resolve().parents[3]), str(path)],
        cwd=Path(__file__).resolve().parents[3],
        capture_output=True, text=True, timeout=5, env=env,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@anchored_locks_only
def test_anchored_file_lock_still_locks_after_an_ancestor_swap(tmp_path, lock_directory):
    from aegis_core.storage import file_lock

    a, b = tmp_path / "a", tmp_path / "b"
    for parent in (a, b):
        (parent / "private").mkdir(parents=True)
    a_fd = lock_directory(a / "private")
    b_fd = lock_directory(b / "private")
    moved_b = tmp_path / "original-b"

    with file_lock(a / "private" / "log.lock", dir_fd=a_fd):
        b.rename(moved_b)
        symlink_or_skip(a, b, target_is_directory=True)
        with file_lock(b / "private" / "log.lock", timeout=0.0, dir_fd=b_fd):
            assert _contend_for_file_lock(moved_b / "private" / "log.lock") == "LOCK_TIMEOUT"
        with file_lock(moved_b / "private" / "log.lock", timeout=0.0):
            pass


@anchored_locks_only
@pytest.mark.parametrize("alternate_spelling", [False, True], ids=["same-path", "different-path"])
def test_anchored_file_lock_reenters_the_same_file(
        tmp_path, lock_directory, alternate_spelling):
    from aegis_core.storage import file_lock

    directory = lock_directory(tmp_path)
    lock = tmp_path / "log.lock"
    nested = tmp_path / "unused-parent" / lock.name if alternate_spelling else lock
    with file_lock(lock, dir_fd=directory):
        with file_lock(nested, timeout=0.0, dir_fd=directory):
            pass
        assert _contend_for_file_lock(lock) == "LOCK_TIMEOUT"
    with file_lock(lock, timeout=0.0):
        pass


@anchored_locks_only
@pytest.mark.parametrize("outer_anchored", [False, True], ids=["path-first", "anchored-first"])
def test_file_lock_reenters_across_acquisition_modes(tmp_path, lock_directory, outer_anchored):
    from aegis_core.storage import file_lock

    directory = lock_directory(tmp_path)
    lock = tmp_path / "log.lock"
    with file_lock(lock, dir_fd=directory if outer_anchored else None):
        with file_lock(lock, timeout=0.0, dir_fd=None if outer_anchored else directory):
            pass
        assert _contend_for_file_lock(lock) == "LOCK_TIMEOUT"
    with file_lock(lock, timeout=0.0):
        pass


@anchored_locks_only
@pytest.mark.parametrize("outer_anchored", [False, True], ids=["path-first", "anchored-first"])
@pytest.mark.parametrize("inner_anchored", [False, True], ids=["path-inner", "anchored-inner"])
def test_file_lock_does_not_reenter_a_replacement_inode(
        tmp_path, lock_directory, outer_anchored, inner_anchored):
    from aegis_core.storage import file_lock

    directory = lock_directory(tmp_path)
    lock = tmp_path / "log.lock"
    with file_lock(lock, dir_fd=directory if outer_anchored else None):
        original = lock.stat()
        lock.rename(tmp_path / "original.lock")
        lock.touch()
        replacement = lock.stat()
        assert (original.st_dev, original.st_ino) != (replacement.st_dev, replacement.st_ino)
        with file_lock(lock, timeout=0.0, dir_fd=directory if inner_anchored else None):
            assert _contend_for_file_lock(lock) == "LOCK_TIMEOUT"
        with file_lock(lock, timeout=0.0):
            pass


def test_anchored_file_lock_refuses_an_unsupported_platform(tmp_path, monkeypatch):
    from aegis_core import storage

    monkeypatch.setattr(storage, "os", SimpleNamespace(name="nt", fspath=os.fspath))
    with pytest.raises(ValueError, match="^dir_fd requires a POSIX directory descriptor$"):
        with storage.file_lock(tmp_path / "log.lock", dir_fd=0):
            pytest.fail("unsupported descriptor-relative lock was accepted")
    assert list(tmp_path.iterdir()) == []


def test_byte_range_file_lock_does_not_reenter_a_distinct_stream(tmp_path, monkeypatch):
    """Model stream identity and contention at the OS boundary on every platform."""
    from aegis_core.errors import LockTimeoutError

    one, two = tmp_path / "one.lock", tmp_path / "two.lock"
    one.write_bytes(b"1")
    two.write_bytes(b"2")
    held_elsewhere = True

    def stream_fstat(fd):
        return SimpleNamespace(st_dev=1, st_ino=1)

    def locking(fd, operation, count):
        # The fixture bytes distinguish streams independently of stat/fstat's
        # platform-specific identity fields. _try_os_lock seeks to byte zero.
        if operation == 2 and held_elsewhere and os.read(fd, count) == b"2":
            raise OSError("stream held by another process")

    monkeypatch.setattr(storage, "fcntl", None)
    monkeypatch.setattr(storage, "msvcrt", SimpleNamespace(LK_NBLCK=2, LK_UNLCK=0, locking=locking))
    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "fstat": stream_fstat}))
    with storage.file_lock(one):
        with storage.file_lock(one, timeout=0.0):
            pass
        with pytest.raises(LockTimeoutError) as error:
            with storage.file_lock(two, timeout=0.0):
                pytest.fail("a distinct stream bypassed the OS lock")
        assert error.value.code == "LOCK_TIMEOUT"
    held_elsewhere = False
    with storage.file_lock(two, timeout=0.0):
        pass


@byte_range_locks_only
def test_windows_file_lock_does_not_reenter_a_contended_alternate_stream(tmp_path):
    from aegis_core.errors import LockTimeoutError

    base = tmp_path / "p.lock"
    base.touch()
    one, two = tmp_path / "p.lock:one", tmp_path / "p.lock:two"
    one.write_bytes(b"1")
    two.write_bytes(b"2")
    one_info, two_info = one.stat(), two.stat()
    assert (one_info.st_dev, one_info.st_ino) == (two_info.st_dev, two_info.st_ino)
    ready = tmp_path / "held"
    repo = Path(__file__).resolve().parents[3]
    env = {"HOME": str(tmp_path), "USERPROFILE": str(tmp_path),
           "PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
    child = subprocess.Popen(
        [sys.executable, "-I", "-c", """
import sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from aegis_core.storage import file_lock
with file_lock(Path(sys.argv[2]), timeout=0.0):
    Path(sys.argv[3]).write_text("held", encoding="ascii")
    sys.stdin.buffer.read(1)
""", str(repo), str(two), str(ready)],
        cwd=repo, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
    )
    try:
        deadline = time.monotonic() + 5
        while not ready.exists():
            if child.poll() is not None:
                _, err = child.communicate(timeout=5)
                pytest.fail(f"stream holder exited before acquiring its lock: {err!r}")
            assert time.monotonic() < deadline, "stream holder did not acquire its lock"
            time.sleep(0.01)
        with storage.file_lock(one, timeout=0.0):
            with storage.file_lock(one, timeout=0.0):
                pass
            with pytest.raises(LockTimeoutError) as error:
                with storage.file_lock(two, timeout=0.0):
                    pytest.fail("a contended alternate stream was treated as reentrant")
            assert error.value.code == "LOCK_TIMEOUT"
            assert _contend_for_file_lock(one) == "LOCK_TIMEOUT"
    finally:
        try:
            _, err = child.communicate(input=b"x" if child.poll() is None else None, timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate(timeout=5)
            pytest.fail("stream holder did not exit after release")
    assert child.returncode == 0, err
    with storage.file_lock(two, timeout=0.0):
        pass


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


@pytest.mark.parametrize("prefix", [None, b'{"old":'])
def test_jsonl_reports_the_descriptor_identity_end_offset_and_bounded_tail(tmp_path, monkeypatch, prefix):
    path = tmp_path / "ledger.jsonl"
    if prefix is not None:
        path.write_bytes(prefix)
    real_fsync = os.fsync
    written_through = []

    def fsync(fd):
        info = os.fstat(fd)
        if stat.S_ISREG(info.st_mode):
            written_through.append(((info.st_dev, info.st_ino), info.st_size))
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    row = {"note": "café", "padding": "x" * 512}
    written = append_jsonl(path, [row])
    data = path.read_bytes()

    assert isinstance(written, int) and written == 1
    assert written.report.identity == written_through[0][0]
    assert written.report.size == written_through[0][1] == len(data)
    assert written.report.added == len(data) - len(prefix or b"")
    assert written.report.tail == data[-256:]
    assert written.report.head == data[:256]
    read = read_jsonl(path)
    assert read.rows == [row]
    assert read.report.identity == written.report.identity
    assert read.report.size == len(data)
    assert read.report.tail == data[-256:]
    assert read.report.head == data[:256]


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
