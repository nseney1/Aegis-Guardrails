"""L0 storage: the one workspace lock, atomic file writes and JSONL I/O (ADR 0005 AD-3).

Every write of Aegis state or rule files goes through this module, so the crash and
concurrency guarantees live in one place:

- ``locked(workspace)``: the single workspace lock, ``.aegis/state/lock``. It is
  re-entrant per thread, so nested acquisition never deadlocks, and its wait is
  bounded with an error that names the lock file.
- ``shared_state_dir(workspace)``: ``<git common dir>/aegis``, the state every
  worktree of one repository shares (the events log), with the same symlink and
  outside-entry refusals, confined to the resolved common dir; ``.aegis/state`` outside
  git. ``shared_locked(workspace, name)`` holds a lock file there with the same
  primitive as ``locked``. Lock order: the workspace lock first; a shared lock is a
  leaf, so nothing else is taken while holding one (LockOrderError otherwise).
- ``ledger_site(workspace)`` / ``ledger_locked(workspace)``: where the outcome ledger and
  its lock are (v4.2 #7). In git every worktree shares
  ``<git common dir>/aegis/state/<ws-id>/{ledger.jsonl,lock}``, ``<ws-id>`` being
  ``workspace_id``; the lock is a shared lock (a leaf, taken after the workspace lock when
  a caller holds it). Outside git the ledger is ``.aegis/state/ledger.jsonl`` under the
  workspace lock.
- Shared state is private: its directories are 0o700 and its files 0o600, set explicitly
  (``chmod``/``fchmod``, so the umask does not matter). ``shared_state_modes`` counts the
  entries of ``<git common dir>/aegis`` that are looser (never naming them) and, with
  ``fix``, tightens them (v4.4 spec §12.7). Outside git there is no shared state: the
  workspace's ``.aegis/state`` keeps the umask's modes and is neither counted nor changed.
- ``state_dir(workspace)``: ``.aegis/state``, refused when it (or ``.aegis``, or any
  entry directly inside it: the ledger, the lock, a log, a backup) is a symlink or
  resolves outside the workspace, so machine-local state is never written through a
  link a commit planted (a tracked symlink is not hidden by the ``state/`` ignore
  entry). It also keeps ``state/.gitignore`` ("*"), so state never shows in
  ``git status`` even where ``.aegis/.gitignore`` lacks ``state/``.
- ``atomic_write_bytes``/``atomic_write_text``: write a temporary file next to the
  target, fsync it, then replace. An existing file keeps its mode; a new file gets
  the mode the umask gives (0o644 typically), not mkstemp's 0o600; ``mode`` sets it
  exactly (a private copy stays private).
- ``append_jsonl``: one ``O_APPEND`` write and one fsync, never through a symlink. A
  torn trailing line left by a crash is terminated first, so it cannot swallow the
  new row.
- ``read_jsonl``: decodes line by line (bytes, utf-8-sig); invalid lines are skipped
  and counted, never raised. It does not follow a symlink.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import threading
import time
from typing import Any, Dict, Iterable, Iterator, List, NamedTuple, Optional, Set, Union

from aegis_core import gitsafe
from aegis_core.errors import AegisError, LockTimeoutError, PathTraversalError
from aegis_core.taxonomy import (
    LOCK_MAX_BACKOFF_SECONDS,
    LOCK_RETRY_INTERVAL_SECONDS,
    LOCK_TIMEOUT_SECONDS,
    STORAGE_INITIAL_DELAY_SECONDS,
    STORAGE_MAX_RETRIES,
)
from aegis_core.workspace.layout import WorkspaceLayout

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]

try:
    import msvcrt
except ImportError:  # POSIX
    msvcrt = None  # type: ignore[assignment]

__all__ = [
    "JsonlRead",
    "LedgerSite",
    "LockOrderError",
    "LockTimeoutError",
    "append_jsonl",
    "atomic_write_and_unlink",
    "atomic_write_bytes",
    "atomic_write_text",
    "file_lock",
    "fsync_dir",
    "ledger_locked",
    "ledger_site",
    "locked",
    "read_json_dict",
    "read_jsonl",
    "read_tail_bytes",
    "StateModes",
    "shared_locked",
    "shared_state_dir",
    "shared_state_modes",
    "state_dir",
    "workspace_id",
    "workspace_relative",
    "worktree_label",
]

_O_BINARY = getattr(os, "O_BINARY", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
# POSIX: the open itself refuses a symlink, so a link swapped in after the lstat check
# is refused too. Windows has no O_NOFOLLOW; the lstat check is the guard there.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
# A new file's permission bits before the umask: the kernel applies the umask, so no
# process-wide os.umask() round trip (which races other threads) is needed.
_NEW_FILE_MODE = 0o666


# ── The one workspace lock ───────────────────────────────────────────────────

class LockOrderError(AegisError, RuntimeError):
    """A lock was requested out of order: the workspace lock comes before any shared
    lock, and a shared lock is a leaf (two processes taking two locks in opposite
    orders would deadlock until a timeout)."""

    def __init__(self, message: str = "", code: str = "LOCK_ORDER", **kwargs: Any) -> None:
        super().__init__(message, code=code, **kwargs)


_GUARD = threading.Lock()
_THREAD_LOCKS: Dict[str, "threading.RLock"] = {}
# .keys: the lock keys this thread holds; .leaves: {lock key: path} of the shared locks among them
_HELD = threading.local()


def _reset_after_fork() -> None:
    # A forked child inherits RLocks that threads of the parent may hold: start clean.
    global _GUARD, _THREAD_LOCKS, _HELD
    _GUARD = threading.Lock()
    _THREAD_LOCKS = {}
    _HELD = threading.local()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_after_fork)


def _thread_lock(key: str) -> "threading.RLock":
    with _GUARD:
        lock = _THREAD_LOCKS.get(key)
        if lock is None:
            lock = _THREAD_LOCKS[key] = threading.RLock()
        return lock


def _held() -> Set[str]:
    held = getattr(_HELD, "keys", None)
    if held is None:
        held = _HELD.keys = set()
    return held


def _held_leaves() -> Dict[str, Path]:
    leaves = getattr(_HELD, "leaves", None)
    if leaves is None:
        leaves = _HELD.leaves = {}
    return leaves


def _try_os_lock(fd: int) -> bool:
    if fcntl is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False
    if msvcrt is not None:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    # Neither primitive exists: the per-process thread lock is all there is.
    return True


def _os_unlock(fd: int) -> None:
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
        elif msvcrt is not None:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    except OSError:
        pass


def _timeout_error(path: Path, timeout: float, kind: str = "workspace") -> LockTimeoutError:
    return LockTimeoutError(
        f"timed out after {timeout:g}s waiting for the Aegis {kind} lock {path}: "
        "another aegis process or thread holds it",
        path=str(path),
    )


_EXTENDED_UNC, _EXTENDED = "\\\\?\\UNC\\", "\\\\?\\"


def _resolved(path: Path | str) -> str:
    """``path`` with every link resolved and without the Windows extended-length prefix.

    realpath, not Path.resolve(): it never raises (3.9 resolve raises RuntimeError on
    loops) and it resolves Windows junctions, which is_symlink() misses before 3.12.
    Windows realpath answers in the extended-length form (``\\\\?\\C:\\...``) when the
    path appears or disappears while it resolves it (another process creating
    ``.aegis/state``); that prefix is dropped.
    """
    real = os.path.realpath(path)
    if real.startswith(_EXTENDED_UNC):
        real = "\\\\" + real[len(_EXTENDED_UNC):]
    elif real.startswith(_EXTENDED):
        real = real[len(_EXTENDED):]
    return real


def _real(path: Path | str) -> str:
    """``path`` resolved (``_resolved``) in one spelling per location: normcase folds the
    case Windows ignores, so two spellings of one location compare equal."""
    return os.path.normcase(_resolved(path))


def _within(path: Path, root: Path) -> bool:
    real, base = _real(path), _real(root)
    return real == base or real.startswith(base.rstrip(os.sep) + os.sep)


def _link_error(path: Path) -> PathTraversalError:
    return PathTraversalError(
        f"refusing to use {path}: it is a symlink; aegis keeps workspace state only inside the workspace",
        path=str(path),
    )


def _outside_error(path: Path) -> PathTraversalError:
    return PathTraversalError(
        f"refusing to use {path}: it resolves outside the workspace; aegis keeps workspace "
        "state only inside the workspace",
        path=str(path),
    )


_STATE_GITIGNORE = b"# Aegis machine-local state; never committed.\n*\n"


def state_dir(workspace: Any) -> Path:
    """The workspace's ``.aegis/state`` directory, created if missing.

    Raises PathTraversalError when ``.aegis`` or ``.aegis/state`` is a symlink or
    otherwise resolves outside the workspace (nothing is created then), or when an entry
    directly inside ``.aegis/state`` is a symlink or resolves outside it (a Windows
    junction): the ledger, the lock, the logs and migration backups would be written
    wherever it points. Writes ``state/.gitignore`` ("*") when it is missing.
    """
    layout = WorkspaceLayout(Path(os.fspath(workspace)).resolve())
    for path in (layout.aegis_dir, layout.state_dir):
        if path.is_symlink():
            raise _link_error(path)
    if not _within(layout.state_dir, layout.root):  # a Windows junction is not a symlink
        raise _outside_error(layout.state_dir)
    layout.state_dir.mkdir(parents=True, exist_ok=True)
    with os.scandir(layout.state_dir) as entries:
        for entry in entries:
            if entry.is_symlink():
                raise _link_error(Path(entry.path))
            # Every entry, not only directories: a file here always resolves inside it.
            if not _within(Path(entry.path), layout.root):
                raise _outside_error(Path(entry.path))
    if not os.path.lexists(layout.state_gitignore):
        atomic_write_bytes(layout.state_gitignore, _STATE_GITIGNORE)
    return layout.state_dir


# ── Shared state: one directory for every worktree of a repository ───────────

_SHARED_DIR_NAME = "aegis"
_SHARED_DIR_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600


def _in_shared_state(path: Path) -> bool:
    """Whether ``path`` is inside a repository's shared state: below a directory named
    ``aegis`` that sits directly in a git directory (it holds ``HEAD`` and ``objects``)."""
    for parent in list(path.parents)[:8]:
        if parent.name == _SHARED_DIR_NAME and (parent.parent / "HEAD").is_file() \
                and (parent.parent / "objects").is_dir():
            return True
    return False


def _make_private(fd: int, mode: int) -> None:
    """Set ``mode`` exactly on an open file; the umask does not apply. Windows has no
    POSIX bits to set."""
    if hasattr(os, "fchmod"):
        os.fchmod(fd, mode)


def _shared_link_error(path: Path, base: Path) -> PathTraversalError:
    return PathTraversalError(
        f"refusing to use {path}: it is a symlink; aegis keeps shared state only inside {base}",
        path=str(path),
    )


def _shared_outside_error(path: Path, base: Path) -> PathTraversalError:
    return PathTraversalError(
        f"refusing to use {path}: it resolves outside {base}; aegis keeps shared state only inside it",
        path=str(path),
    )


def _confined(directory: Path, base: Path, link_error, outside_error, entries: bool = True) -> None:
    """Refuse ``directory`` when it is a symlink, is not a directory, or resolves outside
    ``base``, and (``entries``) when an entry directly inside it is a symlink or a
    directory that resolves outside ``base``. A missing ``directory`` passes."""
    if directory.is_symlink():
        raise link_error(directory)
    if not os.path.lexists(directory):
        return
    if not _within(directory, base):  # a Windows junction is not a symlink
        raise outside_error(directory)
    if not directory.is_dir():
        raise PathTraversalError(f"refusing to use {directory}: it is not a directory", path=str(directory))
    if not entries:
        return
    with os.scandir(directory) as found:
        for entry in found:
            if entry.is_symlink():
                raise link_error(Path(entry.path))
            if entry.is_dir(follow_symlinks=False) and not _within(Path(entry.path), base):
                raise outside_error(Path(entry.path))


def shared_state_dir(workspace: Any, create: bool = True) -> Path:
    """Machine-local state every worktree of the workspace's repository shares:
    ``<git common dir>/aegis`` (realpath of ``git rev-parse --git-common-dir``, so a
    linked worktree answers the main ``.git``, never ``.git/worktrees/<name>``).

    Created mode 0o700 when ``create``; with ``create=False`` nothing is created and the
    path is returned whether or not it exists. Raises PathTraversalError (nothing is
    created) when ``<common>/aegis`` is a symlink, is not a directory or resolves outside
    the common dir, or when an entry directly inside it is a symlink or a directory that
    resolves outside it. Raises OSError when it cannot be listed or created. Outside a
    git repository, or when git cannot run, it is the workspace's ``.aegis/state`` with
    ``state_dir``'s refusals.
    """
    root = Path(os.fspath(workspace)).resolve()
    common = gitsafe.common_dir(root)
    if common is None:
        return _local_state_dir(root, create)
    return _shared_dir(Path(_resolved(common)), create)


class StateModes(NamedTuple):
    """What ``shared_state_modes`` found: ``checked`` entries (directories and files) in the
    shared state, ``looser`` of them with any group or other permission bit, ``fixed`` of
    those tightened. Counts only: a name in a report would leak what the state holds."""

    checked: int
    looser: int
    fixed: int
    supported: bool

    def as_dict(self) -> Dict[str, Any]:
        return {"checked": self.checked, "looser": self.looser, "fixed": self.fixed, "supported": self.supported}


def shared_state_modes(workspace: Any, fix: bool = False) -> StateModes:
    """Count the entries of ``<git common dir>/aegis`` looser than 0o700 (directories) and
    0o600 (files); with ``fix`` set them to exactly that. Nothing is created.

    Outside a git repository (or when git cannot run) there is no shared state, so nothing
    is checked: the workspace-local ``.aegis/state`` is not held to the shared standard.
    A symlink is never followed or changed. Raises what ``shared_state_dir`` raises for an
    unconfined directory. Without POSIX permission bits (Windows) nothing is checked and
    ``supported`` is False.
    """
    if os.name == "nt":
        return StateModes(0, 0, 0, False)
    common = gitsafe.common_dir(Path(os.fspath(workspace)).resolve())
    if common is None:
        return StateModes(0, 0, 0, True)
    top = _shared_dir(Path(_resolved(common)), create=False)
    if not os.path.lexists(top):
        return StateModes(0, 0, 0, True)
    checked = looser = fixed = 0
    pending = [(top, True)]
    while pending:
        path, is_dir = pending.pop()
        checked += 1
        if stat.S_IMODE(os.lstat(path).st_mode) & 0o077:
            looser += 1
            if fix and _chmod_exact(path, _SHARED_DIR_MODE if is_dir else _PRIVATE_FILE_MODE, is_dir):
                fixed += 1
        if is_dir:
            with os.scandir(path) as found:
                pending.extend((Path(e.path), e.is_dir(follow_symlinks=False)) for e in found if not e.is_symlink())
    return StateModes(checked, looser, fixed, True)


def _chmod_exact(path: Path, mode: int, is_dir: bool) -> bool:
    flags = os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | (getattr(os, "O_DIRECTORY", 0) if is_dir else 0)
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return False
    try:
        _make_private(fd, mode)
    except OSError:
        return False
    finally:
        os.close(fd)
    return True


def _local_state_dir(root: Path, create: bool) -> Path:
    """The workspace's ``.aegis/state`` with ``state_dir``'s refusals; with ``create`` False
    nothing is created."""
    if create:
        return state_dir(root)
    layout = WorkspaceLayout(root)
    _confined(layout.aegis_dir, layout.root, _link_error, _outside_error, entries=False)
    _confined(layout.state_dir, layout.root, _link_error, _outside_error)
    return layout.state_dir


def _shared_errors(base: Path):
    def link_error(path: Path) -> PathTraversalError:
        return _shared_link_error(path, base)

    def outside_error(path: Path) -> PathTraversalError:
        return _shared_outside_error(path, base)

    return link_error, outside_error


def _confined_shared(directory: Path, base: Path, create: bool) -> None:
    """``_confined`` for a directory of the shared state under ``base`` (the resolved common
    dir); with ``create`` a missing one is made private and checked again."""
    link_error, outside_error = _shared_errors(base)
    _confined(directory, base, link_error, outside_error)
    if create and not os.path.lexists(directory):
        try:
            directory.mkdir(mode=_SHARED_DIR_MODE)
            os.chmod(directory, _SHARED_DIR_MODE)  # mkdir's mode passes through the umask; this is exact
        except FileExistsError:
            pass  # another worktree's process made it first; checked again below
        _confined(directory, base, link_error, outside_error)


def _shared_dir(base: Path, create: bool) -> Path:
    shared = base / _SHARED_DIR_NAME
    _confined_shared(shared, base, create)
    return shared


def _shared_lock_name(name: object) -> str:
    ok = (
        isinstance(name, str)
        and name.endswith(".lock")
        and name != ".lock"
        and not any(ch in name for ch in "/\\\0")
        and name not in (".", "..")
    )
    if not ok:
        raise ValueError(f"a shared lock is one file name ending in .lock, got {name!r}")
    return name  # type: ignore[return-value]


@contextmanager
def shared_locked(workspace: Any, name: str, timeout: float = LOCK_TIMEOUT_SECONDS) -> Iterator[Path]:
    """Hold the lock file ``<shared_state_dir>/<name>`` (e.g. ``events.lock``) for the block.

    The same primitive as ``locked`` (re-entrant per thread, bounded wait, the OS lock
    across processes and worktrees) on its own file, so it never waits on the workspace
    lock. It is a leaf: take it after the workspace lock, never before, and take no lock
    while holding it (LockOrderError). Raises ValueError for a ``name`` that is not one
    file name ending in ``.lock``, LockTimeoutError naming the lock file, and
    PathTraversalError when the shared state dir is not confined.
    """
    _shared_lock_name(name)
    directory = shared_state_dir(workspace)
    lock_path = directory / name
    key = os.path.join(_real(directory), name)
    with _hold(lock_path, key, timeout, shared=True) as path:
        yield path


# ── The outcome ledger: one file for every worktree of a repository (v4.2 #7) ──

_LEDGER_STATE_DIRNAME = "state"
_LEDGER_FILE = "ledger.jsonl"
_LEDGER_LOCK = "lock"
_WORKSPACE_ID_LENGTH = 16


class LedgerSite(NamedTuple):
    """Where one workspace's ledger is. ``path``: the ledger file; ``lock``: the lock every
    writer holds; ``shared``: whether it is the worktree-shared one (in the git common
    dir) rather than ``.aegis/state/ledger.jsonl``; ``worktree``: the top of the work tree
    asking, in POSIX spelling, set only when ``shared`` (rows carry it)."""

    path: Path
    lock: Path
    shared: bool
    worktree: Optional[str] = None


def _relative_posix(root: Path, top: Path) -> Optional[str]:
    """``root`` below ``top`` as one POSIX spelling per location ("." for the top itself),
    or None when it cannot be named (another drive on Windows). Both are resolved, so a
    link to the repository answers as the repository does, and normcase folds the case
    Windows ignores, so the same workspace has one name in every worktree."""
    try:
        relative = os.path.relpath(os.path.normcase(_resolved(root)), os.path.normcase(_resolved(top)))
    except ValueError:
        return None
    return relative.replace(os.sep, "/")


def _id_of(relative: str) -> str:
    # surrogatepass: a path from a non-UTF-8 file name still has an id.
    return hashlib.sha256(relative.encode("utf-8", "surrogatepass")).hexdigest()[:_WORKSPACE_ID_LENGTH]


def workspace_relative(workspace: Any) -> Optional[str]:
    """``workspace``'s POSIX path relative to the git toplevel ("." for the toplevel itself):
    one spelling for a workspace in every worktree of its repository. None outside a work
    tree."""
    root = Path(os.fspath(workspace)).resolve()
    top = gitsafe.toplevel(root)
    return None if top is None else _relative_posix(root, top)


def workspace_id(workspace: Any) -> Optional[str]:
    """The id naming this workspace's shared ledger directory: the first 16 hex characters
    of the SHA-256 of ``workspace_relative``, the same in every worktree of the repository.
    None outside a work tree."""
    relative = workspace_relative(workspace)
    return None if relative is None else _id_of(relative)


def worktree_label(top: Any) -> str:
    """How a work tree's top directory is written in a ledger row's ``worktree``: resolved,
    POSIX spelling."""
    return Path(_resolved(Path(os.fspath(top)))).as_posix()


def ledger_site(workspace: Any, create: bool = True) -> LedgerSite:
    """Where ``workspace``'s ledger and its lock are.

    In a git work tree: ``<git common dir>/aegis/state/<ws-id>/ledger.jsonl`` and ``lock``
    (see ``workspace_id``), with the confinement of ``shared_state_dir``: PathTraversalError
    when ``aegis``, ``state`` or ``<ws-id>`` is a symlink, is not a directory or resolves
    outside the common dir, or when an entry directly inside one of them is a symlink
    (the ledger and the lock included) or a directory that resolves outside it. OSError
    when one cannot be listed or created. The directories are made mode 0o700 when
    ``create``; with it False nothing is created and the paths are returned whether or not
    they exist. Outside a work tree, or when git cannot run: ``.aegis/state/ledger.jsonl``
    and ``.aegis/state/lock`` with ``state_dir``'s refusals.
    """
    root = Path(os.fspath(workspace)).resolve()
    common = gitsafe.common_dir(root)
    top = gitsafe.toplevel(root) if common is not None else None
    relative = _relative_posix(root, top) if top is not None else None
    if common is None or top is None or relative is None:
        local = _local_state_dir(root, create)
        return LedgerSite(local / _LEDGER_FILE, local / _LEDGER_LOCK, False)
    base = Path(_resolved(common))
    state = _shared_dir(base, create) / _LEDGER_STATE_DIRNAME
    _confined_shared(state, base, create)
    directory = state / _id_of(relative)
    _confined_shared(directory, base, create)
    return LedgerSite(directory / _LEDGER_FILE, directory / _LEDGER_LOCK, True, worktree_label(top))


@contextmanager
def ledger_locked(workspace: Any, timeout: Optional[float] = None) -> Iterator[LedgerSite]:
    """Hold the ledger lock of ``workspace`` for the block and yield its ``LedgerSite``.

    In a git work tree that is ``<ws-id>/lock`` in the common dir, shared by every
    worktree: the same primitive as ``locked`` (re-entrant per thread, bounded wait,
    the OS lock across processes), and a leaf like ``shared_locked`` (take it after the
    worktree lock, never before; take no lock while holding it: LockOrderError). Outside
    git it is the workspace lock itself, so a ledger writer there also excludes whatever
    else holds that lock. ``timeout`` defaults to LOCK_TIMEOUT_SECONDS, read when called.
    Raises LockTimeoutError naming the lock file and the errors of ``ledger_site``.
    """
    wait = LOCK_TIMEOUT_SECONDS if timeout is None else timeout
    site = ledger_site(workspace, create=True)
    if not site.shared:
        with locked(workspace, wait):
            yield site
        return
    key = os.path.join(_real(site.lock.parent), site.lock.name)
    with _hold(site.lock, key, wait, shared=True):
        yield site


def _open_regular(path: Path, flags: int, mode: Optional[int] = None) -> int:
    """``os.open`` that refuses a symlink at ``path`` and anything but a regular file.

    Raises PathTraversalError for a symlink (an existing one, or, on POSIX, one swapped
    in before the open) and for a FIFO, device or directory. A missing file is created
    when ``flags`` has O_CREAT.
    """
    try:
        st: Optional[os.stat_result] = os.lstat(path)
    except FileNotFoundError:
        st = None
    if st is not None and stat.S_ISLNK(st.st_mode):
        raise _link_error(path)
    if st is not None and not stat.S_ISREG(st.st_mode):
        raise PathTraversalError(f"refusing to use {path}: it is not a regular file", path=str(path))
    create_mode = _NEW_FILE_MODE if mode is None else stat.S_IMODE(mode)
    try:
        fd = os.open(str(path), flags | _O_NOFOLLOW | _O_BINARY | _O_CLOEXEC, create_mode)
    except OSError as exc:
        if os.path.islink(path):  # ELOOP (EMLINK on BSD): a link replaced it since the lstat
            raise _link_error(path) from exc
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PathTraversalError(f"refusing to use {path}: it is not a regular file", path=str(path))
        if mode is not None:
            _make_private(fd, stat.S_IMODE(mode))
        elif st is None and _in_shared_state(Path(path)):
            _make_private(fd, _PRIVATE_FILE_MODE)
    except BaseException:
        os.close(fd)
        raise
    return fd


@contextmanager
def _hold(lock_path: Path, key: str, timeout: float, shared: bool) -> Iterator[Path]:
    """Hold the lock file ``lock_path`` (``key``: its one spelling) for the block:
    re-entrant per thread, a thread lock then the OS lock, bounded by ``timeout``.

    While another process holds it, the wait between tries starts at
    LOCK_RETRY_INTERVAL_SECONDS and grows by half each time, up to LOCK_MAX_BACKOFF_SECONDS.
    Raises LockTimeoutError, naming the lock file, when another thread or process holds
    it for longer than ``timeout`` seconds.

    ``shared`` marks a shared lock, which is a leaf: taking the workspace lock or another
    shared lock while this thread holds one raises LockOrderError before waiting.
    """
    held = _held()
    if key in held:
        # Re-entrant: this thread's outermost locked() holds the lock and releases it, so
        # a nested block keeps no count of its own.
        yield lock_path
        return

    leaves = _held_leaves()
    if leaves:
        holding = next(iter(leaves.values()))
        if shared:
            raise LockOrderError(
                f"lock order: a shared lock is a leaf; {lock_path} cannot be taken while holding {holding}"
            )
        raise LockOrderError(
            f"lock order: the Aegis workspace lock is taken before a shared lock, never while holding {holding}"
        )

    deadline = time.monotonic() + max(0.0, timeout)
    kind = "shared" if shared else "workspace"
    thread_lock = _thread_lock(key)
    if not thread_lock.acquire(timeout=max(0.0, timeout)):
        raise _timeout_error(lock_path, timeout, kind)
    fd = None
    try:
        fd = _open_regular(lock_path, os.O_RDWR | os.O_CREAT)
        interval = LOCK_RETRY_INTERVAL_SECONDS
        while not _try_os_lock(fd):
            if time.monotonic() >= deadline:
                raise _timeout_error(lock_path, timeout, kind)
            time.sleep(interval)
            interval = min(interval * 1.5, LOCK_MAX_BACKOFF_SECONDS)
        held.add(key)
        if shared:
            leaves[key] = lock_path
        try:
            yield lock_path
        finally:
            held.discard(key)
            leaves.pop(key, None)
            _os_unlock(fd)
    finally:
        if fd is not None:
            os.close(fd)
        thread_lock.release()


@contextmanager
def locked(workspace: Any, timeout: float = LOCK_TIMEOUT_SECONDS) -> Iterator[Path]:
    """Hold the workspace lock (``.aegis/state/lock``) for the duration of the block.

    ``workspace`` is a Workspace, a path or a string; every spelling of one root shares
    one lock. Re-entrant per thread: a nested ``locked()`` in the thread that holds it
    returns immediately. Raises LockTimeoutError, naming the lock file, when another
    thread or process holds it for longer than ``timeout`` seconds, PathTraversalError
    when the state directory is not confined (``state_dir``), and LockOrderError when
    this thread holds a shared lock (``shared_locked``).
    """
    layout = WorkspaceLayout(Path(os.fspath(workspace)).resolve())
    state = state_dir(layout.root)
    lock_path = layout.lock_file
    # state_dir() confined the directory; the lock file itself is opened by its own
    # name, never through what a link named "lock" points at. One spelling per location:
    # two keys for one lock file would make a nested locked() wait on itself.
    key = os.path.join(_real(state), lock_path.name)
    with _hold(lock_path, key, timeout, shared=False) as path:
        yield path


@contextmanager
def file_lock(lock_path: Path, timeout: float = 5.0) -> Iterator[None]:
    """Hold an arbitrary lock file ``lock_path`` (e.g. a user-scope ``.lock`` file).

    Re-entrant per thread, bounded by ``timeout`` seconds, using the same thread lock
    and OS lock primitives as ``locked`` without participating in workspace/shared lock
    ordering.
    """
    target = Path(os.fspath(lock_path))
    if target.parent.is_symlink():
        raise _link_error(target.parent)
    target.parent.mkdir(parents=True, exist_ok=True)
    key = f"file:{_real(target)}"
    held = _held()
    if key in held:
        yield
        return

    deadline = time.monotonic() + max(0.0, timeout)
    thread_lock = _thread_lock(key)
    if not thread_lock.acquire(timeout=max(0.0, timeout)):
        raise _timeout_error(target, timeout, "file")
    fd = None
    try:
        fd = _open_regular(target, os.O_RDWR | os.O_CREAT, mode=_PRIVATE_FILE_MODE)
        interval = LOCK_RETRY_INTERVAL_SECONDS
        while not _try_os_lock(fd):
            if time.monotonic() >= deadline:
                raise _timeout_error(target, timeout, "file")
            time.sleep(interval)
            interval = min(interval * 1.5, LOCK_MAX_BACKOFF_SECONDS)
        held.add(key)
        try:
            yield
        finally:
            held.discard(key)
            _os_unlock(fd)
    finally:
        if fd is not None:
            os.close(fd)
        thread_lock.release()


# ── Atomic writes ─────────────────────────────────────────────────────────────

def fsync_dir(directory: Path | str) -> None:
    """Best-effort directory fsync so a rename or a new file survives power loss (POSIX)."""
    if os.name != "posix":
        return
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _replace_with_retry(src: str, dst: str, max_retries: int, initial_delay: float) -> None:
    """os.replace, retrying the transient Windows sharing violations (WinError 32/5) an
    indexer or antivirus causes. 8 attempts from 0.01s back off to ~2.55s in total."""
    delay = initial_delay
    for attempt in range(max_retries):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == max_retries - 1:
                raise
            time.sleep(delay)
            delay *= 2


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def atomic_write_bytes(
    path: Path | str,
    data: bytes,
    max_retries: int = STORAGE_MAX_RETRIES,
    initial_delay: float = STORAGE_INITIAL_DELAY_SECONDS,
    mode: Optional[int] = None,
) -> None:
    """Replace ``path`` with ``data`` atomically: readers see the old or the new bytes.

    The parent directory is created if missing. ``mode`` sets the permission bits
    exactly (the umask does not apply); without it an existing file keeps its bits and
    a new one gets ``0o666 & ~umask``. The temporary file is removed on failure.
    """
    target = Path(path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    keep_mode: Optional[int] = None if mode is None else stat.S_IMODE(mode)
    if keep_mode is None:
        try:
            keep_mode = stat.S_IMODE(os.stat(target).st_mode)
        except FileNotFoundError:
            if _in_shared_state(target):
                keep_mode = _PRIVATE_FILE_MODE

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY | _O_CLOEXEC
    # A file that ends with set bits starts private, so it is never looser in between.
    create_mode = _NEW_FILE_MODE if keep_mode is None else 0o600
    while True:
        tmp = str(target.parent / f".{target.name}.{secrets.token_hex(6)}.tmp")
        try:
            fd = os.open(tmp, flags, create_mode)
            break
        except FileExistsError:
            continue
    try:
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        if keep_mode is not None:
            os.chmod(tmp, keep_mode)
        _replace_with_retry(tmp, str(target), max_retries, initial_delay)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    fsync_dir(target.parent)


def atomic_write_text(
    path: Path | str,
    text: str,
    encoding: str = "utf-8",
    max_retries: int = STORAGE_MAX_RETRIES,
    initial_delay: float = STORAGE_INITIAL_DELAY_SECONDS,
) -> None:
    """atomic_write_bytes for text; the text is written byte for byte (no newline translation)."""
    atomic_write_bytes(path, text.encode(encoding), max_retries=max_retries, initial_delay=initial_delay)


def atomic_write_and_unlink(source_path: Path | str, target_path: Path | str, new_content: str) -> None:
    """Write ``new_content`` to ``target_path`` atomically, then remove ``source_path``.

    If the source cannot be removed the new target is removed again, so a rule never
    ends up in two places.
    """
    src = Path(source_path)
    dst = Path(target_path)
    atomic_write_text(dst, new_content)
    try:
        if src != dst and src.exists():
            src.unlink()
    except Exception:
        if dst.exists() and src.exists():
            try:
                os.remove(dst)
            except Exception as ex:
                raise RuntimeError(f"Rollback failed: duplicate rule remains at {dst}") from ex
        raise


# ── JSONL ─────────────────────────────────────────────────────────────────────

def _encode_rows(rows: Iterable[Dict[str, Any]]) -> bytes:
    lines = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"a JSONL row must be a JSON object, got {type(row).__name__}")
        # ensure_ascii: the file stays valid UTF-8 whatever the strings hold (a lone
        # surrogate becomes an escape instead of an undecodable byte).
        lines.append(json.dumps(row, ensure_ascii=True, separators=(",", ":"), allow_nan=False))
    return "".join(line + "\n" for line in lines).encode("ascii")


def append_jsonl(path: Path | str, rows: Iterable[Dict[str, Any]], *, mode: Optional[int] = None) -> int:
    """Append ``rows`` as JSON lines with one ``O_APPEND`` write and one fsync.

    Every row is serialized before anything is written, so a row that is not JSON
    serializable writes nothing (ValueError/TypeError). A symlink at ``path``, dangling
    or not, raises PathTraversalError and nothing is written. If the file ends in a torn line
    (no trailing newline, as a crash mid-write leaves it), a newline is written first:
    the torn bytes stay as one unreadable line and the new rows stay intact. Callers that
    need ordering or deduplication hold ``locked()``. Returns the number of rows written.
    """
    rows = list(rows)
    payload = _encode_rows(rows)
    if not rows:
        return 0
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    created = not os.path.lexists(target)
    fd = _open_regular(target, os.O_RDWR | os.O_APPEND | os.O_CREAT, mode=mode)
    try:
        size = os.fstat(fd).st_size
        if size:
            os.lseek(fd, size - 1, os.SEEK_SET)
            if os.read(fd, 1) != b"\n":
                payload = b"\n" + payload
        _write_all(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    if created:
        fsync_dir(target.parent)
    return len(rows)


@dataclass(frozen=True)
class JsonlRead:
    """What read_jsonl found: the object rows (with their 1-based line numbers) and the rest.

    ``skipped_lines`` are complete lines that are not a UTF-8 JSON object. A final line
    without a newline that does not parse is ``torn_tail`` (a write in progress or a
    crash), not a skipped line. ``error`` is set when the file exists but cannot be read.
    """

    rows: List[Dict[str, Any]]
    line_numbers: List[int]
    skipped_lines: List[int]
    torn_tail: bool = False
    error: Optional[str] = None

    @property
    def skipped(self) -> int:
        return len(self.skipped_lines)


def _parse_line(raw: bytes, errors: str) -> Optional[Dict[str, Any]]:
    try:
        value = json.loads(raw.decode("utf-8-sig", errors))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _read_tail_from_fd(fd: int, limit: int) -> bytes:
    if limit <= 0:
        return b""
    found = os.fstat(fd)
    if not stat.S_ISREG(found.st_mode):
        return b""
    size = found.st_size
    start = max(0, size - limit)
    os.lseek(fd, start, os.SEEK_SET)
    chunks: List[bytes] = []
    remaining = size - start
    while remaining > 0:
        chunk = os.read(fd, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    return data[data.find(b"\n") + 1:] if start else data


def read_tail_bytes(path: Union[str, os.PathLike[str]], limit: int) -> bytes:
    """The whole lines in the last ``limit`` bytes of ``path`` (a partial first line
    dropped); b"" when it is missing, unreadable, a symlink or not a regular file."""
    if limit <= 0:
        return b""
    try:
        fd = _open_regular(Path(path), os.O_RDONLY | _O_NONBLOCK)
    except (OSError, PathTraversalError):
        return b""
    try:
        return _read_tail_from_fd(fd, limit)
    except OSError:
        return b""
    finally:
        os.close(fd)


def read_json_dict(
    path: Union[str, os.PathLike[str]],
    *,
    max_bytes: int = 1024 * 1024,
) -> Optional[Dict[str, Any]]:
    """Safely read a regular non-symlink JSON file and return its dict, or None."""
    if max_bytes <= 0:
        return None
    try:
        fd = _open_regular(Path(path), os.O_RDONLY | _O_NONBLOCK)
    except (OSError, PathTraversalError):
        return None
    try:
        found = os.fstat(fd)
        if not stat.S_ISREG(found.st_mode) or found.st_size > max_bytes:
            return None
        chunks: List[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(fd, max_bytes + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError:
        return None
    finally:
        os.close(fd)
    if total > max_bytes:
        return None
    try:
        parsed = json.loads(b"".join(chunks).decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    return parsed if isinstance(parsed, dict) else None


def read_jsonl(
    path: Path | str,
    errors: str = "strict",
    *,
    tail_bytes: Optional[int] = None,
    contains: Optional[bytes] = None,
) -> JsonlRead:
    """Read a JSONL file; never raises for its content. A missing file reads as empty.

    ``errors`` is the UTF-8 error handler: ``"surrogatepass"`` reads what v3 wrote with
    it (a lone surrogate from a non-UTF-8 file name). A symlink, or anything but a
    regular file, is not read: ``error`` says why.

    ``contains`` is a point read: lines without those bytes are dropped before parsing
    (they are neither rows nor skipped lines; line numbers stay file line numbers). The
    caller passes bytes every wanted row carries verbatim and re-checks the fields.
    """
    try:
        # O_NONBLOCK: opening a FIFO for reading would otherwise wait for a writer.
        fd = _open_regular(Path(path), os.O_RDONLY | _O_NONBLOCK)
    except FileNotFoundError:
        return JsonlRead([], [], [])
    except PathTraversalError as exc:
        return JsonlRead([], [], [], error=f"cannot read {path}: {exc}")
    except OSError as exc:
        return JsonlRead([], [], [], error=f"cannot read {path}: {exc.strerror or exc}")
    if tail_bytes is not None:
        try:
            data = _read_tail_from_fd(fd, tail_bytes)
        except OSError as exc:
            return JsonlRead([], [], [], error=f"cannot read {path}: {exc.strerror or exc}")
        finally:
            os.close(fd)
    else:
        try:
            with os.fdopen(fd, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            return JsonlRead([], [], [], error=f"cannot read {path}: {exc.strerror or exc}")

    if contains is not None and contains not in data:
        return JsonlRead([], [], [])
    rows: List[Dict[str, Any]] = []
    numbers: List[int] = []
    skipped: List[int] = []
    torn = False
    lines = data.split(b"\n")
    last = len(lines) - 1
    for index, raw in enumerate(lines):
        if index == last and not raw:
            break  # the file ended with a newline
        if contains is not None and contains not in raw:
            continue
        raw = raw.rstrip(b"\r")
        if not raw.strip():
            continue
        row = _parse_line(raw, errors)
        if row is not None:
            rows.append(row)
            numbers.append(index + 1)
        elif index == last:
            torn = True
        else:
            skipped.append(index + 1)
    return JsonlRead(rows, numbers, skipped, torn_tail=torn)
