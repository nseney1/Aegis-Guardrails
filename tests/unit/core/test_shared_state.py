"""aegis_core.storage.shared_state_dir and shared_locked (v4.1 §1, "Events log").

State every worktree of one repository shares (the events log) lives in
``<git common dir>/aegis``, never ``.git/worktrees/<name>``; outside git it falls back
to the workspace's ``.aegis/state``. It is refused, like ``state_dir``, when it or an
entry directly inside it is a symlink or resolves outside the common dir. A shared lock
uses the workspace lock's primitive on its own file, and is a leaf: nothing is taken
while holding it.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import textwrap
import time

import pytest

from aegis_core.errors import LockTimeoutError, PathTraversalError
from aegis_core.storage import LockOrderError, locked, shared_locked, shared_state_dir, state_dir

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))

_HOLD = textwrap.dedent("""
    import sys
    from aegis_core.storage import locked, shared_locked
    lock = shared_locked(sys.argv[1], sys.argv[3]) if sys.argv[2] == "shared" else locked(sys.argv[1])
    with lock:
        print("held", flush=True)
        sys.stdin.read()
""")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=T", *args],
        cwd=str(repo), check=True, capture_output=True, text=True,
    ).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / "a.txt").write_text("a\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return root


def _common(repo: Path) -> Path:
    return Path(os.path.realpath(repo / ".git"))


def _symlink_or_skip(link: Path, target: Path, directory: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")


class _Holder:
    """Another process holding a lock until it is told to let go."""

    def __init__(self, ws: Path, kind: str, name: str = "events.lock") -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        self.proc = subprocess.Popen(
            [sys.executable, "-c", _HOLD, str(ws), kind, name],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=env, cwd=REPO_ROOT,
        )

    def __enter__(self) -> "_Holder":
        assert self.proc.stdout.readline().strip() == "held", self.proc.stderr.read()
        return self

    def __exit__(self, *exc) -> None:
        self.proc.stdin.close()
        self.proc.wait(timeout=30)


# ── Where shared state lives ─────────────────────────────────────────────────

@needs_git
def test_shared_state_lives_in_the_common_dir_for_every_worktree(repo: Path, tmp_path: Path):
    expected = _common(repo) / "aegis"
    linked = tmp_path / "linked"
    _git(repo, "worktree", "add", "-q", "-b", "lane/x", str(linked))
    (repo / "pkg").mkdir()
    for workspace in (repo, linked, repo / "pkg"):
        assert shared_state_dir(workspace) == expected, workspace
    assert expected.is_dir()
    assert not (_common(repo) / "worktrees" / "linked" / "aegis").exists()
    assert not (repo / ".aegis").exists() and not (linked / ".aegis").exists()


@needs_git
@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_the_shared_state_dir_is_created_private(repo: Path):
    old = os.umask(0o022)
    try:
        path = shared_state_dir(repo)
    finally:
        os.umask(old)
    assert stat.S_IMODE(path.stat().st_mode) == 0o700


def test_outside_git_it_is_the_workspace_state_dir(tmp_path: Path):
    ws = tmp_path / "plain"
    ws.mkdir()
    assert shared_state_dir(ws) == state_dir(ws) == ws.resolve() / ".aegis" / "state"
    assert (ws / ".aegis" / "state" / ".gitignore").is_file()


@needs_git
def test_without_git_it_is_the_workspace_state_dir(repo: Path, tmp_path: Path, monkeypatch):
    empty = tmp_path / "no-programs"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    assert shared_state_dir(repo) == repo.resolve() / ".aegis" / "state"
    assert not (_common(repo) / "aegis").exists()


@needs_git
def test_create_false_creates_nothing(repo: Path, tmp_path: Path):
    assert shared_state_dir(repo, create=False) == _common(repo) / "aegis"
    assert not (_common(repo) / "aegis").exists()
    plain = tmp_path / "plain"
    plain.mkdir()
    assert shared_state_dir(plain, create=False) == plain.resolve() / ".aegis" / "state"
    assert not (plain / ".aegis").exists()


# ── Confinement ──────────────────────────────────────────────────────────────

def _link_message(path: Path, base: Path) -> str:
    return f"refusing to use {path}: it is a symlink; aegis keeps shared state only inside {base}"


@needs_git
@pytest.mark.parametrize("create", [True, False])
def test_a_symlinked_shared_state_dir_is_refused(repo: Path, tmp_path: Path, create: bool):
    outside = tmp_path / "outside"
    outside.mkdir()
    link = _common(repo) / "aegis"
    _symlink_or_skip(link, outside, directory=True)
    with pytest.raises(PathTraversalError) as info:
        shared_state_dir(repo, create=create)
    assert str(info.value) == _link_message(link, _common(repo))
    with pytest.raises(PathTraversalError):
        with shared_locked(repo, "events.lock"):
            pytest.fail("locked through a symlink")
    assert list(outside.iterdir()) == []


@needs_git
@pytest.mark.parametrize("name, directory", [("events.jsonl", False), ("events.lock", False), ("cache", True)])
def test_a_symlink_inside_the_shared_state_dir_is_refused(repo: Path, tmp_path: Path, name: str, directory: bool):
    shared = shared_state_dir(repo)
    target = tmp_path / "outside-target"
    if directory:
        target.mkdir()
    _symlink_or_skip(shared / name, target, directory=directory)  # dangling for files
    for create in (True, False):
        with pytest.raises(PathTraversalError) as info:
            shared_state_dir(repo, create=create)
        assert str(info.value) == _link_message(shared / name, _common(repo))
    assert not target.exists() or list(target.iterdir()) == []


def _resolve_elsewhere(monkeypatch, name: str, target: Path) -> None:
    """What a Windows junction looks like: not a symlink, but it resolves elsewhere."""
    real = os.path.realpath

    def realpath(path, *args, **kwargs):
        resolved = real(path, *args, **kwargs)
        return str(target) if os.path.basename(resolved) == name else resolved

    monkeypatch.setattr(os.path, "realpath", realpath)


@needs_git
def test_a_shared_state_dir_resolving_outside_the_common_dir_is_refused(repo: Path, tmp_path: Path, monkeypatch):
    (_common(repo) / "aegis").mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    _resolve_elsewhere(monkeypatch, "aegis", outside)
    with pytest.raises(PathTraversalError) as info:
        shared_state_dir(repo)
    path = _common(repo) / "aegis"
    assert str(info.value) == (
        f"refusing to use {path}: it resolves outside {_common(repo)}; aegis keeps shared state only inside it"
    )
    assert list(outside.iterdir()) == []


@needs_git
def test_a_directory_inside_resolving_outside_is_refused(repo: Path, tmp_path: Path, monkeypatch):
    inner = shared_state_dir(repo) / "junction"
    inner.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    _resolve_elsewhere(monkeypatch, "junction", outside)
    with pytest.raises(PathTraversalError, match="it resolves outside .*; aegis keeps shared state only inside it"):
        shared_state_dir(repo)


@needs_git
def test_a_file_where_the_shared_state_dir_belongs_is_refused(repo: Path):
    path = _common(repo) / "aegis"
    path.write_text("not a directory", encoding="utf-8")
    for create in (True, False):
        with pytest.raises(PathTraversalError) as info:
            shared_state_dir(repo, create=create)
        assert str(info.value) == f"refusing to use {path}: it is not a directory"


def test_the_fallback_keeps_the_state_dir_refusals(tmp_path: Path):
    ws = tmp_path / "plain"
    (ws / ".aegis").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    _symlink_or_skip(ws / ".aegis" / "state", outside, directory=True)
    for create in (True, False):
        with pytest.raises(PathTraversalError, match="it is a symlink"):
            shared_state_dir(ws, create=create)
    assert list(outside.iterdir()) == []


# ── The shared lock ──────────────────────────────────────────────────────────

@needs_git
def test_a_shared_lock_is_its_own_file_in_the_shared_state_dir(repo: Path):
    with shared_locked(repo, "events.lock") as path:
        assert path == _common(repo) / "aegis" / "events.lock"
        assert path.is_file()
        with shared_locked(str(repo), "events.lock", timeout=0.2):  # re-entrant per thread
            pass


@pytest.mark.parametrize(
    "name", ["", ".", "..", ".lock", "a/b.lock", "a\\b.lock", "x\0y.lock", "/abs.lock", "lock", "ledger.jsonl", "events"],
)
def test_a_shared_lock_name_is_one_plain_file_name_ending_in_lock(tmp_path: Path, name: str):
    # Outside git the shared dir is .aegis/state: the suffix keeps a shared lock off the
    # workspace lock ("lock") and the state files.
    with pytest.raises(ValueError, match="a shared lock is one file name ending in .lock"):
        with shared_locked(tmp_path, name):
            pytest.fail("locked")


@needs_git
@pytest.mark.timing
def test_a_shared_lock_held_from_another_worktree_times_out_with_exact_error(repo: Path, tmp_path: Path):
    linked = tmp_path / "linked"
    _git(repo, "worktree", "add", "-q", "-b", "lane/x", str(linked))
    lock = _common(repo) / "aegis" / "events.lock"
    with _Holder(linked, "shared"):
        began = time.monotonic()
        with pytest.raises(LockTimeoutError) as info:
            with shared_locked(repo, "events.lock", timeout=0.3):
                pytest.fail("acquired a lock another worktree's process holds")
        waited = time.monotonic() - began
    assert str(info.value) == (
        f"timed out after 0.3s waiting for the Aegis shared lock {lock}: another aegis process or thread holds it"
    )
    assert info.value.path == str(lock)
    assert 0.25 <= waited < 5
    with shared_locked(repo, "events.lock", timeout=5):  # released with the holder
        pass


@needs_git
def test_the_shared_lock_and_the_workspace_lock_are_independent(repo: Path):
    with _Holder(repo, "workspace"):
        with shared_locked(repo, "events.lock", timeout=0.5):
            pass
    with _Holder(repo, "shared"):
        with locked(repo, timeout=0.5):
            pass


# ── Lock order: the workspace lock first; a shared lock is a leaf ───────────

def test_a_shared_lock_may_be_taken_inside_the_workspace_lock(tmp_path: Path):
    with locked(tmp_path):
        with shared_locked(tmp_path, "events.lock", timeout=0.5):
            pass


def test_the_workspace_lock_is_never_taken_inside_a_shared_lock(tmp_path: Path):
    with shared_locked(tmp_path, "events.lock") as path:
        with pytest.raises(LockOrderError) as info:
            with locked(tmp_path, timeout=0.5):
                pytest.fail("took the workspace lock inside a shared lock")
    assert str(info.value) == (
        f"lock order: the Aegis workspace lock is taken before a shared lock, never while holding {path}"
    )
    with locked(tmp_path, timeout=0.5):  # nothing leaked: the order check is per holding
        pass


def test_shared_locks_never_nest(tmp_path: Path):
    with shared_locked(tmp_path, "a.lock") as first:
        with pytest.raises(LockOrderError) as info:
            with shared_locked(tmp_path, "b.lock", timeout=0.5):
                pytest.fail("nested two shared locks")
    second = first.parent / "b.lock"
    assert str(info.value) == f"lock order: a shared lock is a leaf; {second} cannot be taken while holding {first}"
    with shared_locked(tmp_path, "b.lock", timeout=0.5):
        pass


def test_the_fallback_without_creating_checks_only_what_state_dir_checks(tmp_path: Path):
    ws = tmp_path / "plain"
    (ws / ".aegis" / "state").mkdir(parents=True)
    elsewhere = tmp_path / "shared-rules"
    elsewhere.mkdir()
    _symlink_or_skip(ws / ".aegis" / "rules", elsewhere, directory=True)  # not state: allowed
    expected = ws.resolve() / ".aegis" / "state"
    assert shared_state_dir(ws, create=False) == expected
    assert shared_state_dir(ws) == state_dir(ws) == expected
