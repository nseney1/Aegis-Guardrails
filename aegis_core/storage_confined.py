"""Descriptor-confined storage, re-exported by :mod:`aegis_core.storage`.

The caller selects an absolute trusted str/Path root (resolve owner-selected aliases before
calling). Every root ancestor and relative component is opened without following
links. A context holds the parent descriptor across reads and atomic publication,
including concurrent ancestor renames. Relative directories may be created with
mode 0700. With create_parents=True, every relative ancestor's containing
directory is flushed, including entries found existing. Roots are limited to
32768 characters, and relative paths to 128
components of at most 255 UTF-8 bytes. Keep the context open while using its handle.
Removal rechecks the named parent identity, unlinks only relative to the held
descriptor and flushes that parent, even when a retry finds the child missing.

ConfinedFileError.reason distinguishes missing, exists, unsafe, changed, too_large,
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

__all__ = ("ConfinedFile", "ConfinedFileError", "DirectoryAnchor", "confined_file",
           "descriptor_supported", "open_directory", "read_checked_file")


_MESSAGES = {
    "missing": "confined file path missing",
    "exists": "confined file already exists",
    "unsafe": "unsafe confined file path; regular file and directories required",
    "changed": "confined file generation changed during read",
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

    def __init__(self, reason, *, os_errno=None, os_error=None):
        super().__init__(_MESSAGES[reason])
        self.reason = reason
        self.code = "CONFINED_" + reason.upper()
        self.errno = os_errno
        self.os_error = os_error
        self.directory_stage = None
        self.directory_anchor = None


def _descriptor_names():
    return {function.__name__ for function in os.supports_dir_fd}


def _directory_flags_supported():
    return os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")


def _walk_supported():
    """Descriptor-relative open and no-follow stat, with directory flags.

    A read does not require publication primitives. A missing walk primitive
    refuses before any filesystem operation.
    """
    follow = {function.__name__ for function in os.supports_follow_symlinks}
    return (_directory_flags_supported() and {"open", "stat"} <= _descriptor_names()
            and "stat" in follow)


def descriptor_supported():
    """Whether confined publication and parent creation are available."""
    return (_directory_flags_supported()
            and {"open", "mkdir", "link", "rename", "unlink", "stat"} <= _descriptor_names())


def _require_descriptor_mkdir():
    """Refuse creation unless mkdir accepts a directory descriptor.

    Reads of existing directories do not call this. The refusal is the same
    one hosts without descriptor-relative mkdir already returned.
    """
    if "mkdir" not in _descriptor_names():
        raise ConfinedFileError("unsupported") from None


@contextmanager
def _refusals(stage=None, *, missing_passthrough=False):
    try:
        yield
    except ConfinedFileError as error:
        if error.directory_stage is None:
            error.directory_stage = stage
        raise
    except OSError as error:
        if missing_passthrough and isinstance(error, FileNotFoundError):
            raise
        reason = {errno.ENOENT: "missing", errno.EEXIST: "exists",
                  errno.ELOOP: "unsafe", errno.ENOTDIR: "unsafe"}.get(error.errno, "io")
        if stage is None:
            raise ConfinedFileError(reason) from None
        refusal = ConfinedFileError(reason, os_errno=error.errno, os_error=error)
        refusal.directory_stage = stage
        raise refusal from None


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


def _directory_path(root):
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
    return given


def _close_directories(descriptors, close_fd, stage=None, *, outermost=False):
    failure = None
    while descriptors:
        try:
            close_fd(descriptors.pop())
        except OSError as error:
            if failure is None or outermost:
                failure = error
    if failure is not None:
        with _refusals(stage):
            raise failure


def _directory_fd(name, parent, opener):
    if opener is None:
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                       dir_fd=parent)
    return opener(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                  dir_fd=parent)


def _walk_directory(given, components=(), create=False, inspect=None, on_missing=None, retain=False,
                    opener=None, close_fd=None, cleanup_fd=None, cleanup_stage=None):
    """One root-anchored walk; inspection and missing-directory policy are optional.

    The create branch and a caller's on_missing handler run only when
    descriptor-relative mkdir is supported. Otherwise this raises
    ConfinedFileError('unsupported') before either one. Reads of directories
    that already exist do not require mkdir.
    """
    close_fd = os.close if close_fd is None else close_fd
    cleanup_fd = close_fd if cleanup_fd is None else cleanup_fd
    descriptors = []
    try:
        descriptors.append(_directory_fd(given.anchor, None, opener))
        if inspect is not None:
            inspect(descriptors[-1], None, None)
        for index, component in enumerate((*given.parts[1:], *components)):
            parent = descriptors[-1]
            if create and index >= len(given.parts) - 1:
                _require_descriptor_mkdir()
                try:
                    os.mkdir(component, 0o700, dir_fd=parent)
                except FileExistsError:
                    pass
                _flush(parent)
            try:
                child = _directory_fd(component, parent, opener)
            except FileNotFoundError:
                if on_missing is None:
                    raise
                _require_descriptor_mkdir()
                on_missing(parent, component)
                child = _directory_fd(component, parent, opener)
            descriptors.append(child)
            if inspect is not None:
                inspect(child, parent, component)
            if not retain:
                close_fd(descriptors.pop(0))
        result, descriptors = descriptors, []
        return result
    finally:
        _close_directories(descriptors, cleanup_fd, cleanup_stage, outermost=retain)


class DirectoryAnchor:
    """Owned directory descriptor, identity and root-to-leaf (dev, ino, uid, mode).

    Use as a context manager or call close/detach. With retained ancestors, check()
    verifies each entry through its held parent; observations grant no authority.
    """

    def __init__(self, descriptors, names, observations, close_fd, stat_entry, cleanup_fd):
        self._descriptors = descriptors
        self._names = names
        self.observations = tuple(observations)
        self.identity = self.observations[-1][:2]
        self.fd = descriptors[-1]
        self._close_fd = close_fd
        self._stat_entry = stat_entry
        self._cleanup_fd = cleanup_fd

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        try:
            self.close()
        except ConfinedFileError as error:
            # The caller may also receive a staged refusal from its own body.
            error.directory_anchor = self
            raise

    def close(self):
        """Release every owned descriptor, including if an earlier close fails."""
        self.fd = None
        # Match nested directory lifetimes: the last (outermost) failure wins.
        _close_directories(self._descriptors, self._close_fd, "close", outermost=True)

    def detach(self):
        """Transfer the leaf descriptor to the caller; close any retained parents."""
        if self.fd is None:
            raise ConfinedFileError("closed")
        leaf = self._descriptors.pop()
        try:
            self.close()
        except BaseException:
            with _refusals("cleanup"):
                self._cleanup_fd(leaf)
            raise
        return leaf

    def check(self):
        """Refuse renamed ancestors; requires retain_ancestors=True at opening."""
        if self.fd is None:
            raise ConfinedFileError("closed")
        if len(self._descriptors) != len(self.observations):
            raise ConfinedFileError("invalid_data")
        with _refusals("check"):
            for parent, name, expected in zip(self._descriptors, self._names, self.observations[1:]):
                current = self._stat_entry(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != expected[:2]:
                    raise ConfinedFileError("unsafe")


def open_directory(opener, root, *, policy=None, on_missing=None, retain_ancestors=False,
                   close_fd=None, stat_fd=None, stat_entry=None, cleanup_fd=None):
    """Walk an absolute root without following any component; no path fallback.

    Refuse before any filesystem operation unless descriptor-relative open and
    no-follow stat are supported with the directory flags. Publication stays
    behind descriptor_supported(). A missing directory is created only when
    descriptor-relative mkdir is supported; otherwise the walk raises
    ConfinedFileError('unsupported') before the caller's on_missing handler.

    policy(stat_result) validates the leaf before transfer. on_missing(parent_fd,
    name, observations) may create a missing directory under the held parent;
    creation policy and durability belong to that caller. Refusals use this
    module's fixed reasons; exceptions raised by policy callbacks pass through.
    By default only the leaf stays open. Retain ancestors for check() when needed.
    opener is the caller's trusted os.open boundary; close_fd, stat_fd and
    stat_entry default to this module's os.close, os.fstat and os.stat. Passing
    the caller's boundaries preserves its descriptor ownership instrumentation.
    cleanup_fd defaults to close_fd; a caller may supply its established
    failure-cleanup policy to preserve the primary refusal if close also fails.
    A refusal retains os_error and directory_stage for callers whose established
    error contract passes particular OS failures through; its own text stays fixed.
    """
    with _refusals("prepare"):
        given = _directory_path(root)
        if not _walk_supported():
            raise ConfinedFileError("unsupported")
    close_fd = os.close if close_fd is None else close_fd
    cleanup_fd = close_fd if cleanup_fd is None else cleanup_fd
    stat_fd = os.fstat if stat_fd is None else stat_fd
    stat_entry = os.stat if stat_entry is None else stat_entry
    observations = []
    opening = "open"

    def opened(name, flags, *, dir_fd=None):
        nonlocal opening
        try:
            with _refusals("open_root" if dir_fd is None else opening,
                           missing_passthrough=dir_fd is not None and opening == "open"):
                return opener(name, flags, dir_fd=dir_fd)
        finally:
            opening = "open"

    def closed(fd):
        with _refusals("walk_close"):
            close_fd(fd)

    def inspect(fd, parent, component):
        with _refusals("stat"):
            info = stat_fd(fd)
        observations.append((info.st_dev, info.st_ino, info.st_uid, info.st_mode))
        if len(observations) == len(given.parts):
            with _refusals("policy"):
                if policy is not None:
                    policy(info)
            with _refusals("verify"):
                visible = stat_entry(component if parent is not None else ".",
                                     dir_fd=parent if parent is not None else fd, follow_symlinks=False)
                if not stat.S_ISDIR(visible.st_mode) or (visible.st_dev, visible.st_ino) != observations[-1][:2]:
                    raise ConfinedFileError("unsafe")

    def missing(parent, component):
        nonlocal opening
        with _refusals("create"):
            on_missing(parent, component, tuple(observations))
        opening = "reopen"

    with _refusals("open"):
        descriptors = _walk_directory(given, inspect=inspect,
                                      on_missing=missing if on_missing is not None else None,
                                      retain=retain_ancestors, opener=opened, close_fd=closed,
                                      cleanup_fd=cleanup_fd, cleanup_stage="cleanup")
        try:
            result = DirectoryAnchor(descriptors, given.parts[1:], observations, close_fd, stat_entry, cleanup_fd)
            descriptors = []
            return result
        finally:
            _close_directories(descriptors, cleanup_fd, "cleanup", outermost=retain_ancestors)


def _open_parent(root, components, create):
    return _walk_directory(_directory_path(root), components, create)[0]


def _file_generation(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def _check_read_record(info, max_bytes, owner_uid, generation=None, *, admitted=False):
    if not stat.S_ISREG(info.st_mode):
        raise ConfinedFileError("unsafe")
    changed = generation is not None and _file_generation(info) != generation
    if admitted and changed:
        raise ConfinedFileError("changed")
    if info.st_size > max_bytes:
        raise ConfinedFileError("too_large")
    if owner_uid is not None and (info.st_uid != owner_uid or not info.st_mode & stat.S_IRUSR
                                  or info.st_mode & 0o077 or info.st_nlink != 1):
        raise ConfinedFileError("unsafe")
    if changed:
        raise ConfinedFileError("changed")


def _read_bounded(fd, max_bytes, *, overflow="too_large"):
    data = bytearray()
    while True:
        remaining = max_bytes - len(data)
        chunk = os.read(fd, min(8192, remaining + 1))
        if not chunk:
            return bytes(data)
        if len(chunk) > remaining:
            raise ConfinedFileError(overflow)
        data.extend(chunk)


def _check_read_limit(max_bytes, *, checked=False):
    if type(max_bytes) is not int or max_bytes < 0:
        raise ConfinedFileError("invalid_limit")
    if checked and not _walk_supported():
        raise ConfinedFileError("unsupported")


class _ReadDecision:
    """Keep the first typed defect and record unresolved I/O failures."""

    def __init__(self):
        self.error = None

    @contextmanager
    def observe(self):
        try:
            yield
        except ConfinedFileError as error:
            if self.error is None or self.error.reason == "io":
                self.error = error
        except OSError:
            if self.error is None:
                self.error = ConfinedFileError("io")

    def close(self, fd):
        with self.observe():
            os.close(fd)

    def require_success(self):
        if self.error is not None:
            raise self.error from None


class ConfinedFile:
    """A file name bound to one held parent; obtain through confined_file."""

    def __init__(self, parent, name):
        self._parent = parent
        self._name = name
        self._location = None

    def _check_open(self):
        if self._parent is None:
            raise ConfinedFileError("closed")

    @property
    def parent_fd(self):
        """Borrow the held parent descriptor while open; never close it or retain it after exit."""
        self._check_open()
        return self._parent

    def parent_stat(self):
        """Inspect the held parent for caller-specific ownership/mode policy."""
        self._check_open()
        with _refusals():
            return os.fstat(self._parent)

    def _check_parent(self):
        """Refuse a moved/replaced parent; removal still uses only the held fd."""
        if self._location is None:
            raise ConfinedFileError("unsafe")
        try:
            current = _open_parent(*self._location, False)
        except ConfinedFileError as error:
            if error.reason in ("missing", "unsafe"):
                raise ConfinedFileError("unsafe") from None
            raise
        except OSError as error:
            if error.errno in (errno.ENOENT, errno.ELOOP, errno.ENOTDIR):
                raise ConfinedFileError("unsafe") from None
            raise
        try:
            held, named = os.fstat(self._parent), os.fstat(current)
            if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
                raise ConfinedFileError("unsafe")
        finally:
            os.close(current)

    def remove(self):
        """Unlink a regular child and flush its held parent, including on retry.

        Return 'removed' or 'missing'; refuse unsafe entries/changed parents
        with CONFINED_UNSAFE, and OS/flush failure with CONFINED_IO. A flush
        can fail after unlink landed. No path is followed by the unlink itself.
        """
        self._check_open()
        with _refusals():
            self._check_parent()
            try:
                info = os.stat(self._name, dir_fd=self._parent, follow_symlinks=False)
            except FileNotFoundError:
                info = None
            if info is not None and not stat.S_ISREG(info.st_mode):
                raise ConfinedFileError("unsafe")
            self._check_parent()
            outcome = "missing"
            if info is not None:
                try:
                    os.unlink(self._name, dir_fd=self._parent)
                    outcome = "removed"
                except FileNotFoundError:
                    pass
                except IsADirectoryError:
                    raise ConfinedFileError("unsafe") from None
            # Missing may be a retry after unlink succeeded but fsync failed.
            os.fsync(self._parent)
            return outcome

    def read_bytes(self, max_bytes):
        """Read a regular file, refusing size before allocation and on growth."""
        self._check_open()
        _check_read_limit(max_bytes)
        with _refusals():
            fd = self._open_read_fd()
            try:
                _check_read_record(os.fstat(fd), max_bytes, None)
                return _read_bounded(fd, max_bytes)
            finally:
                os.close(fd)

    def read_checked(self, max_bytes, *, owner_uid=None, expected=None, policy=None):
        """Return bounded bytes and their opened stat result.

        When owner_uid is supplied, require a private, owner-readable file with
        that UID and one link. When expected is a previous checked stat result,
        require its generation at the initial observation. Named metadata can
        refuse a read. Only the name-verified descriptor supplies bytes and
        reaches the optional policy callback. Read exactly the opened length
        and verify the name and descriptor again before returning. Use
        read_checked_file when the read must also own the parent lifetime.
        """
        self._check_open()
        _check_read_limit(max_bytes, checked=True)
        decision = _ReadDecision()
        with decision.observe():
            result = self._read_checked(decision, max_bytes, owner_uid, expected, policy)
        decision.require_success()
        return result

    def _open_read_fd(self):
        return os.open(self._name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
                       dir_fd=self._parent)

    def _read_checked(self, decision, max_bytes, owner_uid, expected, policy):
        expected_generation = _file_generation(expected) if expected is not None else None
        initial = self._observe_read_name(decision, max_bytes, owner_uid, expected_generation)
        decision.require_success()
        fd = None
        with decision.observe(), _refusals():
            fd = self._open_read_fd()
        if fd is None:
            if decision.error.reason == "io":
                self._observe_read_name(decision, max_bytes, owner_uid, initial)
            decision.require_success()
        try:
            info, generation = self._admit_read_fd(decision, fd, max_bytes, owner_uid, initial)
            if policy is not None:
                policy(info)
            raw = None
            with decision.observe():
                raw = _read_bounded(fd, info.st_size, overflow="changed")
                if len(raw) != info.st_size:
                    raise ConfinedFileError("changed")
            self._verify_read_fd(decision, fd, max_bytes, owner_uid, generation)
            return raw, info
        finally:
            decision.close(fd)

    def _observe_read_name(self, decision, max_bytes, owner_uid, generation, *, admitted=False):
        with decision.observe(), _refusals():
            named = os.stat(self._name, dir_fd=self._parent, follow_symlinks=False)
            _check_read_record(named, max_bytes, owner_uid, generation, admitted=admitted)
            return _file_generation(named)

    def _admit_read_fd(self, decision, fd, max_bytes, owner_uid, initial):
        info = None
        with decision.observe():
            info = os.fstat(fd)
        if info is not None and info.st_nlink > 0:
            # Commit descriptor eligibility before a later name observation.
            with decision.observe():
                _check_read_record(info, max_bytes, owner_uid)
            decision.require_success()
        generation = _file_generation(info) if info is not None else initial
        self._observe_read_name(decision, max_bytes, owner_uid, generation)
        if info is not None and (info.st_nlink == 0 or generation != initial):
            # A reliable name refusal takes precedence for a detached descriptor.
            with decision.observe():
                raise ConfinedFileError("changed")
        decision.require_success()
        return info, generation

    def _verify_read_fd(self, decision, fd, max_bytes, owner_uid, generation):
        named = self._observe_read_name(decision, max_bytes, owner_uid, generation, admitted=True)
        current = None
        with decision.observe():
            current = os.fstat(fd)
            _check_read_record(current, max_bytes, owner_uid, generation, admitted=True)
        if current is None and named is not None:
            # The entry may have changed while the descriptor stat failed.
            self._observe_read_name(decision, max_bytes, owner_uid, generation, admitted=True)

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
        handle._location = (root, parts[:-1])
        yield handle
    finally:
        if handle is not None:
            handle._parent = None
        with _refusals():
            os.close(parent)


def read_checked_file(root, relative_parts, max_bytes, *, owner_uid=None, expected=None,
                      policy=None, parent_policy=None):
    """Read a checked record and include owned parent cleanup in its refusal.

    The parent and optional record policies receive held descriptor metadata.
    See ConfinedFile.read_checked for the record and generation checks.
    """
    parts = _parts(relative_parts)
    _check_read_limit(max_bytes, checked=True)
    decision = _ReadDecision()
    with decision.observe():
        with _refusals():
            parent = _walk_directory(_directory_path(root), parts[:-1],
                                     close_fd=decision.close, cleanup_fd=decision.close)[0]
        try:
            handle = ConfinedFile(parent, parts[-1])
            if parent_policy is not None:
                parent_policy(handle.parent_stat())
            result = handle._read_checked(decision, max_bytes, owner_uid, expected, policy)
        finally:
            decision.close(parent)
    decision.require_success()
    return result
