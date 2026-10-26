"""storage.file_lock: an unordered, re-entrant lock on any file (R-structure-32, TA-5).

Characterization written before file_lock went through storage._hold: each behavior held for
file_lock's own copy of the acquire loop and holds for _hold(ordered=False). A test that waits
on a lock waits at most 0.5 s, and none asserts how long anything took.
"""
from __future__ import annotations

import inspect
import os
from pathlib import Path
import stat
import subprocess
import sys
import threading

import pytest

from aegis_core.errors import LockTimeoutError, PathTraversalError
from aegis_core.storage import file_lock, locked, shared_locked
from tests.conftest import symlink_or_skip

REPO = Path(__file__).resolve().parents[3]
posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("USERPROFILE", str(h))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(h / ".gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "AEGIS_WORKSPACE", "CLAUDE_PROJECT_DIR"):
        monkeypatch.delenv(name, raising=False)
    return h


@pytest.fixture
def lock(home: Path) -> Path:
    return home / ".aegis" / "insights" / "ws.lock"


@pytest.fixture
def ws(tmp_path: Path, home: Path) -> Path:
    # Outside git, so the shared state of shared_locked is the workspace's .aegis/state.
    root = tmp_path / "ws"
    (root / ".aegis").mkdir(parents=True)
    return root


def _take(path: Path, timeout: float) -> str:
    with file_lock(path, timeout=timeout):
        return "acquired"


def _in_thread(path: Path, timeout: float):
    """(result, error) of taking ``path`` in another thread."""
    out: dict = {}

    def run() -> None:
        try:
            out["result"] = _take(path, timeout)
        except Exception as exc:  # noqa: BLE001 - the error is the result under test
            out["error"] = exc

    thread = threading.Thread(target=run)
    thread.start()
    thread.join(timeout=30)
    assert not thread.is_alive()
    return out.get("result"), out.get("error")


def test_a_missing_directory_is_made_and_the_block_gets_none(lock: Path):
    """Given a lock path whose directory does not exist, When file_lock is held with the default
    wait of 5 s, Then the directory and the lock file exist and the block gets None."""
    assert inspect.signature(file_lock).parameters["timeout"].default == 5.0
    with file_lock(lock) as value:
        assert value is None
        assert lock.is_file()
    assert lock.is_file()  # the lock file stays after release


def test_a_nested_hold_on_the_same_path_does_not_wait_and_releases_nothing(lock: Path):
    """Given file_lock held, When the same thread takes it again with no wait at all, Then the inner
    block runs, and after it another thread still cannot take the lock until the outer releases."""
    with file_lock(lock):
        with file_lock(lock, timeout=0.0):
            pass
        _, error = _in_thread(lock, 0.2)
        assert isinstance(error, LockTimeoutError)
    assert _in_thread(lock, 0.5) == ("acquired", None)


def test_a_second_thread_waits_and_takes_the_lock_after_release(lock: Path):
    started, acquired = threading.Event(), threading.Event()
    errors: list = []

    def contender() -> None:
        started.set()
        try:
            with file_lock(lock, timeout=0.5):
                acquired.set()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    with file_lock(lock):
        thread = threading.Thread(target=contender)
        thread.start()
        assert started.wait(5)
        assert not acquired.wait(0.05)  # held here: the contender is still waiting
    thread.join(timeout=30)
    assert (errors, acquired.is_set()) == ([], True)


def test_a_second_holder_times_out_with_an_error_naming_the_lock_file(lock: Path):
    with file_lock(lock):
        result, error = _in_thread(lock, 0.2)
    assert result is None and isinstance(error, LockTimeoutError)
    assert str(error) == (f"timed out after 0.2s waiting for the Aegis file lock {lock}: "
                          "another aegis process or thread holds it")
    assert error.path == str(lock)


def test_two_spellings_of_one_path_are_one_lock(lock: Path):
    lock.parent.mkdir(parents=True)
    other = lock.parent / ".." / lock.parent.name / lock.name
    with file_lock(lock):
        with file_lock(other, timeout=0.0):  # re-entrant: the same lock under another spelling
            pass
        _, error = _in_thread(other, 0.2)
    assert isinstance(error, LockTimeoutError)


def test_a_file_lock_takes_no_part_in_lock_order(ws: Path, lock: Path):
    """Given the workspace lock or a shared lock (a leaf) held, When a file lock is taken, Then no
    LockOrderError: a file lock is not ordered. And the workspace and a shared lock can be taken
    while a file lock is held."""
    entered = []
    with locked(ws):
        with file_lock(lock, timeout=0.2):
            entered.append("inside the workspace lock")
    with shared_locked(ws, "events.lock"):
        with file_lock(lock, timeout=0.2):
            entered.append("inside a shared lock")
    with file_lock(lock):
        with locked(ws, timeout=0.2):
            with shared_locked(ws, "events.lock", timeout=0.2):
                entered.append("around both")
    assert entered == ["inside the workspace lock", "inside a shared lock", "around both"]


def test_a_file_lock_on_the_workspace_lock_file_is_a_lock_of_its_own(ws: Path):
    """Given the workspace lock held, When the same thread takes a file lock on the workspace lock
    file itself, Then it is not re-entrant into the workspace lock: it waits and times out."""
    with locked(ws) as path:
        with pytest.raises(LockTimeoutError, match="Aegis file lock"):
            with file_lock(path, timeout=0.2):
                pass


@posix_only
def test_the_lock_file_is_private(lock: Path):
    lock.parent.mkdir(parents=True)
    lock.write_bytes(b"")
    os.chmod(lock, 0o644)
    with file_lock(lock):
        pass
    assert stat.S_IMODE(os.stat(lock).st_mode) == 0o600
    fresh = lock.with_name("fresh.lock")
    old = os.umask(0o022)
    try:
        with file_lock(fresh):
            pass
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(fresh).st_mode) == 0o600


def test_a_symlinked_parent_is_refused_and_nothing_is_created(tmp_path: Path, home: Path):
    """Sad: Given the lock's directory is a symlink to a directory elsewhere, When file_lock is
    taken, Then PathTraversalError and nothing is created where the link points."""
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = home / "linked"
    symlink_or_skip(outside, linked, target_is_directory=True)
    with pytest.raises(PathTraversalError):
        with file_lock(linked / "ws.lock"):
            pass
    assert list(outside.iterdir()) == []


def test_a_lock_file_that_is_a_symlink_is_refused(tmp_path: Path, home: Path):
    target = tmp_path / "target"
    target.write_bytes(b"keep")
    lock = home / "locks" / "ws.lock"
    lock.parent.mkdir(parents=True)
    symlink_or_skip(target, lock)
    with pytest.raises(PathTraversalError):
        with file_lock(lock):
            pass
    assert target.read_bytes() == b"keep"


_CHILD = (
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from pathlib import Path\n"
    "from aegis_core.storage import file_lock\n"
    "with file_lock(Path(sys.argv[2])):\n"
    "    sys.stdout.buffer.write(b'held\\n')\n"
    "    sys.stdout.buffer.flush()\n"
    "    sys.stdin.buffer.read()\n"
)


def test_a_lock_another_process_holds_times_out(lock: Path, home: Path):
    """Sad: Given a child process holding the file lock, When this process takes it with a wait of
    0.3 s, Then LockTimeoutError naming the file lock; after the child exits it is free."""
    env = {"HOME": str(home), "USERPROFILE": str(home), "PATH": os.environ.get("PATH", ""),
           "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
    child = subprocess.Popen([sys.executable, "-I", "-c", _CHILD, str(REPO), str(lock)], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    try:
        assert child.stdout is not None and child.stdout.readline().strip() == b"held"
        with pytest.raises(LockTimeoutError, match="Aegis file lock"):
            with file_lock(lock, timeout=0.3):
                pass
    finally:
        _, err = child.communicate(timeout=60)
    assert child.returncode == 0, err
    with file_lock(lock, timeout=0.5):
        pass
