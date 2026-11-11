"""Descriptor-confined storage, re-exported by :mod:`aegis_core.storage`.

The caller selects an absolute trusted str/Path root (resolve owner-selected aliases before
calling). Every root ancestor and relative component is opened without following
links. A context holds the parent descriptor across reads and atomic publication,
including concurrent ancestor renames. Relative directories may be created with
mode 0700. With create_parents=True, every relative ancestor's containing
directory is flushed, including entries found existing. Roots are limited to
32768 characters, and relative paths to 128
components of at most 255 UTF-8 bytes. Keep the context open while using its handle.

ConfinedFileError.reason distinguishes missing, exists, unsafe, too_large,
unsupported, invalid_path, invalid_limit, invalid_data, invalid_mode, closed and
io and durability. Messages contain neither supplied paths nor OS error text. This API handles
bytes only; callers retain their own parsing and schema refusal contracts.
"""
from __future__ import annotations

from contextlib import contextmanager
import errno
import os
from pathlib import Path
import stat
import uuid

__all__ = ("ConfinedFile", "ConfinedFileError", "confined_file", "descriptor_supported")


_MESSAGES = {
    "missing": "confined file path missing",
    "exists": "confined file already exists",
    "unsafe": "unsafe confined file path; regular file and directories required",
    "too_large": "confined file size limit exceeded",
    "unsupported": "unsupported platform: confined file operations unavailable",
    "invalid_path": "invalid confined file path",
    "invalid_limit": "invalid confined file byte limit",
    "invalid_data": "confined file data must be bytes",
    "invalid_mode": "invalid confined file mode",
    "closed": "confined file context is closed",
    "io": "confined file I/O failed",
    "durability": "confined file durability flush failed",
}


class ConfinedFileError(ValueError):
    """A stable refusal reason and code, without untrusted diagnostic text."""

    def __init__(self, reason):
        super().__init__(_MESSAGES[reason])
        self.reason = reason
        self.code = "CONFINED_" + reason.upper()


def descriptor_supported():
    """Whether all primitives needed by this API are available."""
    names = {function.__name__ for function in os.supports_dir_fd}
    return (os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
            and {"open", "mkdir", "link", "rename", "unlink", "stat"} <= names)


@contextmanager
def _refusals():
    try:
        yield
    except OSError as error:
        reason = {errno.ENOENT: "missing", errno.EEXIST: "exists",
                  errno.ELOOP: "unsafe", errno.ENOTDIR: "unsafe"}.get(error.errno, "io")
        raise ConfinedFileError(reason) from None


def _flush(fd):
    try:
        os.fsync(fd)
    except OSError:
        raise ConfinedFileError("durability") from None


def _parts(relative_parts):
    # Bound the container and each spelling before tuple/encoding allocation.
    if type(relative_parts) not in (tuple, list) or not 1 <= len(relative_parts) <= 128:
        raise ConfinedFileError("invalid_path")
    for part in relative_parts:
        if (type(part) is not str or not 1 <= len(part) <= 255 or part in (".", "..")
                or any(char in part for char in ("/", "\\", "\x00"))):
            raise ConfinedFileError("invalid_path")
        try:
            if len(part.encode("utf-8")) > 255:
                raise ConfinedFileError("invalid_path")
        except UnicodeError:
            raise ConfinedFileError("invalid_path") from None
    return tuple(relative_parts)


def _open_parent(root, components, create):
    try:
        spelling = str(root) if isinstance(root, Path) else root
        if type(spelling) is not str or not 1 <= len(spelling) <= 32768:
            raise ConfinedFileError("invalid_path")
        os.fsencode(spelling)
        given = Path(spelling)
    except ValueError:
        raise ConfinedFileError("invalid_path") from None
    if not given.is_absolute() or ".." in given.parts or "\x00" in str(given):
        raise ConfinedFileError("invalid_path")
    fd = os.open(given.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        for index, component in enumerate((*given.parts[1:], *components)):
            if create and index >= len(given.parts) - 1:
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                _flush(fd)
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
            parent, fd = fd, child
            os.close(parent)
        return fd
    except BaseException:
        os.close(fd)
        raise


class ConfinedFile:
    """A file name bound to one held parent; obtain through confined_file."""

    def __init__(self, parent, name):
        self._parent = parent
        self._name = name

    def _check_open(self):
        if self._parent is None:
            raise ConfinedFileError("closed")

    def parent_stat(self):
        """Inspect the held parent for caller-specific ownership/mode policy."""
        self._check_open()
        with _refusals():
            return os.fstat(self._parent)

    def read_bytes(self, max_bytes):
        """Read a regular file, refusing size before allocation and on growth."""
        self._check_open()
        if type(max_bytes) is not int or max_bytes < 0:
            raise ConfinedFileError("invalid_limit")
        with _refusals():
            fd = os.open(self._name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=self._parent)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise ConfinedFileError("unsafe")
                if info.st_size > max_bytes:
                    raise ConfinedFileError("too_large")
                data = bytearray()
                while len(data) <= max_bytes:
                    chunk = os.read(fd, min(8192, max_bytes + 1 - len(data)))
                    if not chunk:
                        return bytes(data)
                    data.extend(chunk)
                raise ConfinedFileError("too_large")
            finally:
                os.close(fd)

    def _inspect_destination(self, replace):
        try:
            info = os.stat(self._name, dir_fd=self._parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(info.st_mode):
            raise ConfinedFileError("unsafe")
        if not replace:
            raise ConfinedFileError("exists")

    def _write_temporary(self, fd, data, mode):
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise ConfinedFileError("io")
            view = view[count:]
        _flush(fd)

    def publish_bytes(self, data, replace=False, mode=0o600):
        """Durably publish bytes; default is exclusive creation, never overwrite.

        Replacement replaces the directory entry, never follows a leaf link.
        Existing nonregular entries refuse; a racing entry cannot redirect I/O.
        A directory-fsync failure can be reported after publication took effect.
        """
        self._check_open()
        if type(data) is not bytes:
            raise ConfinedFileError("invalid_data")
        if type(mode) is not int or not 0 <= mode <= 0o777:
            raise ConfinedFileError("invalid_mode")
        with _refusals():
            self._inspect_destination(replace)
            temporary = ".confined-" + uuid.uuid4().hex
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=self._parent)
            try:
                try:
                    self._write_temporary(fd, data, mode)
                finally:
                    os.close(fd)
                if replace:
                    os.replace(temporary, self._name, src_dir_fd=self._parent, dst_dir_fd=self._parent)
                else:
                    os.link(temporary, self._name, src_dir_fd=self._parent, dst_dir_fd=self._parent, follow_symlinks=False)
            finally:
                try:
                    os.unlink(temporary, dir_fd=self._parent)
                except FileNotFoundError:
                    pass
            _flush(self._parent)


@contextmanager
def confined_file(root, relative_parts, create_parents=False):
    """Hold a confined file's parent until exit; see this module's contract."""
    parts = _parts(relative_parts)
    if not descriptor_supported():
        raise ConfinedFileError("unsupported")
    with _refusals():
        parent = _open_parent(root, parts[:-1], create_parents)
    handle = None
    try:
        handle = ConfinedFile(parent, parts[-1])
        yield handle
    finally:
        if handle is not None:
            handle._parent = None
        with _refusals():
            os.close(parent)
