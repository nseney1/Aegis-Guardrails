"""Kernel facts and borrowed owner-directory locks, independent of consumers.

IdentityError.reason is fixed data for caller-specific refusal mapping. Optional
confined_file/readlink boundaries let adapters retain their existing OS seams.
Every proc read is bounded and descriptor-confined; a missing foreign PID is
dead only after a readable, live self identity proves the proc mount works.
"""
from __future__ import annotations

from contextlib import contextmanager
import errno
import os
from pathlib import Path
import re
import sys

from aegis_core import storage_confined

try:
    import fcntl
except ImportError:
    fcntl = None

__all__ = ["IdentityError", "descriptor_supported", "process_identity", "boot_id",
           "pid_namespace", "scope", "owner_directory_lock"]


class IdentityError(ValueError):
    """A fixed refusal; never expose supplied paths, proc bytes or OS diagnostics."""

    def __init__(self, reason):
        super().__init__("kernel identity unavailable")
        self.reason = reason


def descriptor_supported():
    """Linux proc facts and descriptor-relative no-follow operations are required."""
    return sys.platform == "linux" and storage_confined.descriptor_supported()


@contextmanager
def identity_errors():
    """Translate storage and OS failures into stable consumer-neutral reasons."""
    try:
        yield
    except IdentityError:
        raise
    except storage_confined.ConfinedFileError as error:
        raise IdentityError(error.reason) from None
    except Exception:
        raise IdentityError("unavailable") from None


def process_identity(pid, *, confined_file=None):
    """Return pid/start_ticks, or None for absent/zombie; unknown always refuses."""
    if not descriptor_supported():
        raise IdentityError("unsupported")
    if type(pid) is not int or not 1 <= pid <= 2147483647:
        raise IdentityError("invalid")
    opener = storage_confined.confined_file if confined_file is None else confined_file
    with identity_errors():
        try:
            with opener(Path("/proc"), (str(pid), "stat")) as handle:
                data = handle.read_bytes(4096)
        except storage_confined.ConfinedFileError as error:
            if error.reason != "missing" or pid == os.getpid():
                raise
            if process_identity(os.getpid(), confined_file=opener) is None:
                raise IdentityError("unavailable")
            return None
        if type(data) is not bytes or len(data) > 4096:
            raise IdentityError("invalid")
        # comm may contain spaces, parentheses and newlines. Ticks are field 22.
        prefix, separator, tail = data.rpartition(b") ")
        if not separator or not prefix.startswith(str(pid).encode("ascii") + b" ("):
            raise IdentityError("invalid")
        fields = tail.split()
        if len(fields) < 20 or len(fields[19]) > 20 or not fields[19].isdigit():
            raise IdentityError("invalid")
        if fields[0] in (b"Z", b"X", b"x"):
            return None
        return {"pid": pid, "start_ticks": int(fields[19])}


def boot_id(*, confined_file=None):
    """Read exactly one UUID, optionally followed by the kernel's newline."""
    if not descriptor_supported():
        raise IdentityError("unsupported")
    opener = storage_confined.confined_file if confined_file is None else confined_file
    with identity_errors():
        with opener(Path("/proc"), ("sys", "kernel", "random", "boot_id")) as handle:
            data = handle.read_bytes(37)
        if (type(data) is not bytes or len(data) not in (36, 37)
                or len(data) == 37 and data[-1:] != b"\n"):
            raise IdentityError("invalid")
        boot = data[:36].decode("ascii")
        if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot) is None:
            raise IdentityError("invalid")
        return boot


def pid_namespace(*, confined_file=None, readlink=None):
    """Read kernel symlinks on held parents; never follow /proc/self as a path."""
    if not descriptor_supported():
        raise IdentityError("unsupported")
    opener = storage_confined.confined_file if confined_file is None else confined_file
    link = os.readlink if readlink is None else readlink
    with identity_errors():
        with opener(Path("/proc"), ("self",)) as handle:
            own_pid = link("self", dir_fd=handle.parent_fd)
            if own_pid != str(os.getpid()):
                raise IdentityError("invalid")
        with opener(Path("/proc"), (own_pid, "ns", "pid")) as handle:
            namespace = link("pid", dir_fd=handle.parent_fd)
        if (type(namespace) is not str or len(namespace) > 26
                or re.fullmatch(r"pid:\[[0-9]{1,20}\]", namespace) is None):
            raise IdentityError("invalid")
        return namespace


def scope(*, confined_file=None, readlink=None):
    """One boot ID and PID namespace snapshot, parsed by the canonical readers."""
    return {"boot_id": boot_id(confined_file=confined_file),
            "pid_namespace": pid_namespace(confined_file=confined_file, readlink=readlink)}


@contextmanager
def owner_directory_lock(directory):
    """Borrow a descriptor for a nonblocking flock; its caller owns closure.

    EACCES/EAGAIN/EWOULDBLOCK are contention. Other acquisition errors refuse.
    Unlock errors cannot mask the operation; closing the caller's descriptor
    releases the lock even when explicit unlock fails.
    """
    if not descriptor_supported() or fcntl is None:
        raise IdentityError("unsupported")
    try:
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise IdentityError("locked") from None
    except OSError as error:
        reason = "locked" if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EACCES) else "unavailable"
        raise IdentityError(reason) from None
    try:
        yield
    finally:
        try:
            fcntl.flock(directory, fcntl.LOCK_UN)
        except OSError:
            pass
