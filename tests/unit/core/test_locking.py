"""The one workspace lock, aegis_core.storage.locked (ADR 0005 AD-3, build-sheet D12).

One lock file, ``.aegis/state/lock``, guards rules and the ledger. It is re-entrant per
thread (the v3 evidence_lock/workspace_lock pair deadlocked when nested) and its wait
is bounded with an error that names the lock file.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap
import threading
import time

import pytest

from aegis_core.errors import LockTimeoutError
from aegis_core.storage import locked

REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))

_HOLD_UNTIL_EOF = textwrap.dedent("""
    import sys
    from aegis_core.storage import locked
    with locked(sys.argv[1]):
        print("held", flush=True)
        sys.stdin.read()
""")

_COUNTER_WORKER = textwrap.dedent("""
    import sys, time
    from pathlib import Path
    from aegis_core.storage import locked
    ws, n = Path(sys.argv[1]), int(sys.argv[2])
    counter = ws / "counter.txt"
    for _ in range(n):
        with locked(ws, timeout=60):
            value = int(counter.read_text(encoding="utf-8"))
            time.sleep(0.001)  # widen the read-modify-write window
            counter.write_text(str(value + 1), encoding="utf-8")
""")


def _child_env(tmp_path: Path) -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _lock_path(ws: Path) -> Path:
    return ws.resolve() / ".aegis" / "state" / "lock"


def test_lock_file_is_aegis_state_lock(tmp_path: Path):
    with locked(tmp_path) as path:
        assert path == _lock_path(tmp_path)
        assert path.is_file()
    assert not (tmp_path / ".aegis" / "locks").exists()


def test_nested_acquire_in_one_thread_does_not_deadlock(tmp_path: Path):
    started = time.monotonic()
    with locked(tmp_path):
        with locked(tmp_path, timeout=0.5):
            with locked(str(tmp_path), timeout=0.5):
                pass
        # still held by the outer block: another thread must not get in
        got_in = []

        def rival():
            try:
                with locked(tmp_path, timeout=0.1):
                    got_in.append(True)
            except LockTimeoutError:
                got_in.append(False)

        t = threading.Thread(target=rival)
        t.start()
        t.join()
        assert got_in == [False]
    assert time.monotonic() - started < 5


def test_every_spelling_of_one_root_shares_the_lock(tmp_path: Path):
    from aegis_core.workspace.base import Workspace

    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with locked(real):
        with locked(Workspace(root=real), timeout=0.5) as via_ws, locked(str(link), timeout=0.5) as via_link:
            assert via_ws.resolve() == via_link.resolve() == _lock_path(real)


def test_lock_is_released_when_the_block_raises(tmp_path: Path):
    with pytest.raises(RuntimeError, match="boom"):
        with locked(tmp_path):
            raise RuntimeError("boom")
    done = []

    def other():
        with locked(tmp_path, timeout=1):
            done.append(True)

    t = threading.Thread(target=other)
    t.start()
    t.join()
    assert done == [True]


def test_thread_held_lock_times_out_with_exact_error(tmp_path: Path):
    started, stop = threading.Event(), threading.Event()

    def holder():
        with locked(tmp_path):
            started.set()
            stop.wait(5)

    t = threading.Thread(target=holder)
    t.start()
    try:
        assert started.wait(5)
        with pytest.raises(LockTimeoutError) as info:
            with locked(tmp_path, timeout=0.2):
                pytest.fail("acquired a lock another thread holds")
    finally:
        stop.set()
        t.join()
    assert str(info.value) == (
        f"timed out after 0.2s waiting for the Aegis workspace lock {_lock_path(tmp_path)}: "
        "another aegis process or thread holds it"
    )
    assert info.value.path == str(_lock_path(tmp_path))


@pytest.mark.timing
def test_lock_held_by_another_process_times_out_with_exact_error(tmp_path: Path):
    holder = subprocess.Popen(
        [sys.executable, "-c", _HOLD_UNTIL_EOF, str(tmp_path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=_child_env(tmp_path), cwd=REPO_ROOT,
    )
    try:
        assert holder.stdout.readline().strip() == "held", holder.stderr.read()
        began = time.monotonic()
        with pytest.raises(LockTimeoutError) as info:
            with locked(tmp_path, timeout=0.3):
                pytest.fail("acquired a lock another process holds")
        waited = time.monotonic() - began
    finally:
        holder.stdin.close()
        holder.wait(timeout=30)
    assert str(info.value) == (
        f"timed out after 0.3s waiting for the Aegis workspace lock {_lock_path(tmp_path)}: "
        "another aegis process or thread holds it"
    )
    # It waited out its 0.3 s timeout: the lower bound allows for the 15.6 ms tick of the
    # Windows monotonic clock, the upper one only catches a hang.
    assert 0.3 - 0.1 <= waited < 5
    # The holder exited, so the lock is free again.
    with locked(tmp_path, timeout=5):
        pass


def test_a_waiter_backs_off_from_10_ms_by_half_again_each_try_up_to_50_ms(tmp_path: Path, monkeypatch):
    """Polling a lock another process holds neither spins nor stalls: waits of 10, 15,
    22.5 and 33.75 ms, then 50 ms (LOCK_RETRY_INTERVAL_SECONDS, LOCK_MAX_BACKOFF_SECONDS)."""
    from aegis_core import storage

    # A fake clock that only the waiter's sleeps advance, so the sequence does not depend
    # on how fast the runner is (a slow macOS runner used up the 0.5 s deadline early).
    waits = []
    clock = [0.0]

    def sleep(seconds):
        waits.append(seconds)
        clock[0] += seconds

    holder = subprocess.Popen(
        [sys.executable, "-c", _HOLD_UNTIL_EOF, str(tmp_path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=_child_env(tmp_path), cwd=REPO_ROOT,
    )
    try:
        assert holder.stdout.readline().strip() == "held", holder.stderr.read()
        monkeypatch.setattr(storage.time, "sleep", sleep)
        monkeypatch.setattr(storage.time, "monotonic", lambda: clock[0])
        with pytest.raises(LockTimeoutError):
            with locked(tmp_path, timeout=0.5):
                pytest.fail("acquired a lock another process holds")
        monkeypatch.undo()
    finally:
        holder.stdin.close()
        holder.wait(timeout=30)
    assert waits[:5] == pytest.approx([0.01, 0.015, 0.0225, 0.03375, 0.05])
    assert len(waits) > 5 and set(waits[5:]) == {0.05}


def test_threads_never_lose_an_update(tmp_path: Path):
    counter = tmp_path / "counter.txt"
    counter.write_text("0", encoding="utf-8")

    def bump(n: int) -> None:
        for _ in range(n):
            with locked(tmp_path, timeout=30):
                value = int(counter.read_text(encoding="utf-8"))
                time.sleep(0.0005)
                counter.write_text(str(value + 1), encoding="utf-8")

    with ThreadPoolExecutor(max_workers=4) as pool:
        for future in [pool.submit(bump, 25) for _ in range(4)]:
            future.result()
    assert counter.read_text(encoding="utf-8") == "100"


def test_three_processes_never_lose_an_update(tmp_path: Path):
    counter = tmp_path / "counter.txt"
    counter.write_text("0", encoding="utf-8")
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _COUNTER_WORKER, str(tmp_path), "40"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=_child_env(tmp_path), cwd=REPO_ROOT,
        )
        for _ in range(3)
    ]
    for proc in procs:
        out, err = proc.communicate(timeout=120)
        assert proc.returncode == 0, err
    assert counter.read_text(encoding="utf-8") == "120"


def test_lock_works_where_fcntl_is_unavailable(tmp_path: Path):
    """BUG-008: on Windows `fcntl` does not exist; importing storage must not need it."""
    code = "import sys; sys.modules['fcntl'] = None\n" + textwrap.dedent("""
        from aegis_core.storage import locked
        with locked(sys.argv[1]):
            with locked(sys.argv[1]):
                print("ok")
    """)
    proc = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path)], capture_output=True, text=True,
        env=_child_env(tmp_path), cwd=REPO_ROOT, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ok"


# ── Confinement (review B2a-4): state never lands outside the workspace ──────

def _symlink_dir_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")


@pytest.mark.parametrize("linked", [".aegis/state", ".aegis"])
def test_a_symlinked_state_dir_is_refused_and_nothing_is_written_outside(tmp_path: Path, linked: str):
    from aegis_core.errors import PathTraversalError
    from aegis_core.telemetry_engine import ledger

    ws = tmp_path / "ws"
    (ws / ".aegis").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = ws / linked
    if link.exists():
        link.rmdir()
    _symlink_dir_or_skip(link, outside)

    with pytest.raises(PathTraversalError, match=r"is a symlink; aegis keeps workspace state only inside the workspace"):
        with locked(ws):
            pass
    with pytest.raises(PathTraversalError):
        ledger.append(ws, [{"rule": "trap-x", "outcome": "tp", "source": "mcp"}])

    assert sorted(p.relative_to(outside).as_posix() for p in outside.rglob("*")) == []


def test_the_safety_gate_log_is_not_written_through_a_symlinked_state_dir(tmp_path: Path):
    from aegis_cli.hooks.safety import log_gate_event

    ws = tmp_path / "ws"
    (ws / ".aegis").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    _symlink_dir_or_skip(ws / ".aegis" / "state", outside)

    log_gate_event("rm -rf /", "deny", "destructive", ws)  # logging never fails the gate

    assert list(outside.iterdir()) == []


# ── Confinement of the files inside .aegis/state (review B2a round 3, F1) ────

def _symlink_file_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")


def _state_ws(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / ".aegis" / "state").mkdir(parents=True)
    return ws


def test_a_symlinked_ledger_is_refused_and_its_target_is_untouched(tmp_path: Path):
    from aegis_core.errors import PathTraversalError
    from aegis_core.telemetry_engine import ledger

    ws = _state_ws(tmp_path)
    victim = tmp_path / "victim" / ".bashrc"
    victim.parent.mkdir()
    victim.write_bytes(b"export PATH=/usr/bin\n")
    _symlink_file_or_skip(ws / ".aegis" / "state" / "ledger.jsonl", victim)

    with pytest.raises(PathTraversalError, match=r"ledger\.jsonl: it is a symlink"):
        ledger.append(ws, [{"rule": "x$(touch /tmp/pwn)", "outcome": "trigger", "source": "mcp", "key": "k"}])

    assert victim.read_bytes() == b"export PATH=/usr/bin\n"


def test_a_dangling_lock_symlink_is_refused_and_creates_nothing(tmp_path: Path):
    from aegis_core.errors import PathTraversalError

    ws = _state_ws(tmp_path)
    target = tmp_path / "victim" / "created"
    target.parent.mkdir()
    _symlink_file_or_skip(ws / ".aegis" / "state" / "lock", target)

    with pytest.raises(PathTraversalError, match=r"lock: it is a symlink"):
        with locked(ws):
            pass

    assert not os.path.lexists(target)


@pytest.mark.parametrize("name", ["gate_events.jsonl", "lifecycle.jsonl", "derived.json", "migrate-backup-20261015T120000Z"])
def test_any_symlink_inside_the_state_dir_is_refused(tmp_path: Path, name: str):
    from aegis_core.errors import PathTraversalError

    ws = _state_ws(tmp_path)
    outside = tmp_path / "victim"
    outside.mkdir()
    _symlink_file_or_skip(ws / ".aegis" / "state" / name, outside / name)

    with pytest.raises(PathTraversalError, match=f"{name}: it is a symlink"):
        with locked(ws):
            pass

    assert list(outside.iterdir()) == []


def test_the_safety_gate_log_is_not_written_through_a_symlinked_log_file(tmp_path: Path):
    from aegis_cli.hooks.safety import log_gate_event

    ws = _state_ws(tmp_path)
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"keep\n")
    _symlink_file_or_skip(ws / ".aegis" / "state" / "gate_events.jsonl", victim)

    log_gate_event("rm -rf /", "deny", "destructive", ws)  # logging never fails the gate

    assert victim.read_bytes() == b"keep\n"


# ── The state dir ignores itself (review B2a round 3, F3) ────────────────────

def _git(repo: Path, *args: str) -> str:
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1")
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=T", *args],
        cwd=str(repo), check=True, capture_output=True, text=True, env=env,
    ).stdout


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
@pytest.mark.parametrize("aegis_gitignore", [None, "evidence/\nlocks/\nkeys/\n"])
def test_state_written_before_any_migration_never_shows_in_git_status(tmp_path: Path, aegis_gitignore):
    from aegis_core.telemetry_engine import ledger

    repo = tmp_path / "repo"
    (repo / ".aegis" / "rules").mkdir(parents=True)
    (repo / ".aegis" / "rules" / "trap-a.md").write_text("---\nid: trap-a\n---\n", encoding="utf-8")
    if aegis_gitignore is not None:  # what a v3 workspace has: no state/ entry
        (repo / ".aegis" / ".gitignore").write_text(aegis_gitignore, encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "v3 workspace")

    ledger.append(repo, [{"rule": "trap-a", "outcome": "tp", "source": "mcp", "key": "k", "meta": {"notes": "free text"}}])
    with locked(repo):
        pass

    # The worktree's own state (its lock) is in .aegis/state; the ledger is shared, in the common dir.
    assert (repo / ".aegis" / "state" / "lock").is_file()
    assert ledger.ledger_path(repo).is_file() and not (repo / ".aegis" / "state" / "ledger.jsonl").exists()
    assert _git(repo, "status", "--porcelain", "--untracked-files=all") == ""
