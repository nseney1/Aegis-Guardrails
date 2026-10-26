"""L0 atomic file writes (ADR 0005 AD-3): a leaf over the errors and taxonomy tables only, so
storage, which re-exports the public names, and gitsafe both use them without importing each other.

- ``atomic_write_bytes``/``atomic_write_text``: write a temporary file next to the
  target, fsync it, then replace. An existing file keeps its mode; a new file gets
  the mode the umask gives (0o644 typically), not mkstemp's 0o600; ``mode`` sets it
  exactly (a private copy stays private).
- ``create_private_file``: a new 0o600 file, created exclusively and never through a link
  (a key file); False when the file already exists.
- ``_open_regular``: the opener of storage's readers, locks and appends; it refuses a symlink and
  anything but a regular file.
"""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import stat
import time
from typing import Optional

from aegis_core.errors import PathTraversalError
from aegis_core.taxonomy import STORAGE_INITIAL_DELAY_SECONDS, STORAGE_MAX_RETRIES

__all__ = [
    "atomic_write_and_unlink",
    "atomic_write_bytes",
    "atomic_write_text",
    "create_private_file",
    "fsync_dir",
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
_SHARED_DIR_NAME = "aegis"
_PRIVATE_FILE_MODE = 0o600


def _link_error(path: Path) -> PathTraversalError:
    return PathTraversalError(
        f"refusing to use {path}: it is a symlink; aegis keeps workspace state only inside the workspace",
        path=str(path),
    )


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


def create_private_file(path: Path | str, data: bytes) -> bool:
    """Create ``path`` holding ``data``, mode 0o600 whatever the umask, and fsync it; False
    when a regular file is already there (it is left as it is).

    PathTraversalError for a symlink (dangling or not, or swapped in before the open) and for
    anything but a regular file. A file this call created is removed again if the write fails.
    """
    target = Path(path)
    try:
        fd = _open_regular(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _PRIVATE_FILE_MODE)
    except FileExistsError:
        return False
    try:
        _write_all(fd, data)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(target)
        except OSError:
            pass
        raise
    os.close(fd)
    fsync_dir(target.parent)
    return True


def _resolve_directory(path: Path | str) -> Path:
    """``path`` with its directory resolved and its last component kept as written."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    if absolute.name in ("", ".."):
        return absolute.resolve()
    return absolute.parent.resolve() / absolute.name


def atomic_write_bytes(
    path: Path | str,
    data: bytes,
    max_retries: int = STORAGE_MAX_RETRIES,
    initial_delay: float = STORAGE_INITIAL_DELAY_SECONDS,
    mode: Optional[int] = None,
    *,
    follow_links: bool = True,
) -> None:
    """Replace ``path`` with ``data`` atomically: readers see the old or the new bytes.

    The parent directory is created if missing. ``mode`` sets the permission bits
    exactly (the umask does not apply); without it an existing file keeps its bits and
    a new one gets ``0o666 & ~umask``. The temporary file is removed on failure. With
    ``follow_links=False`` a symlink at ``path`` is replaced, never followed, and lends
    the new file none of its target's bits (directories above it are still resolved).
    """
    # A caller that checked the name with lstat passes follow_links=False: rename(2)
    # replaces a link at the destination instead of following it, so a link swapped in
    # after the check is overwritten as itself, never its target.
    target = Path(path).resolve() if follow_links else _resolve_directory(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    keep_mode: Optional[int] = None if mode is None else stat.S_IMODE(mode)
    if keep_mode is None:
        try:
            st: Optional[os.stat_result] = os.stat(target) if follow_links else os.lstat(target)
        except FileNotFoundError:
            st = None
        if st is not None and not stat.S_ISLNK(st.st_mode):
            keep_mode = stat.S_IMODE(st.st_mode)
        elif _in_shared_state(target):
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
            # Through the descriptor: a link swapped in at the temporary name is never followed.
            if keep_mode is not None and os.name == "posix":
                os.fchmod(fd, keep_mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        if keep_mode is not None and os.name != "posix":
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
