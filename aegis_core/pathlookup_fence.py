"""Cold descriptor backend for path provenance and fail-closed checkout discovery.

The metadata hot path stays in pathlookup. Both descriptor clients use this one
iterative location/continuation/hop state. Operations enter through the facade so
capability and failure tests patch their owning module references.
"""
from __future__ import annotations

import errno
import os
import stat
from typing import Optional

__all__ = [
    "open_directory", "open_leaf", "directory_kind", "fd_location",
    "discover_descriptors", "proven_outside",
]


def open_directory(parent: Optional[int], name: str) -> int:
    """Open directory ``name`` under ``parent`` without following a link.

    ``parent`` None is an absolute path. ``O_RDONLY`` is 0, so a missing
    ``O_PATH`` and ``O_SEARCH`` stays read-only. A nested getattr is not a
    constant flag expression.
    """
    return os.open(
        name,
        getattr(os, "O_PATH", 0)
        | getattr(os, "O_SEARCH", 0)
        | os.O_NOFOLLOW
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )


def open_leaf(parent: Optional[int], name: str) -> int:
    """Open non-directory ``name`` under ``parent`` without following a link."""
    return os.open(
        name,
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )


def directory_kind(dir_fd: int, part: str) -> str:
    """No-follow type of ``part`` under ``dir_fd``, before any open."""
    try:
        info = os.stat(part, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        return "missing"
    mode = info.st_mode
    if stat.S_ISLNK(mode):
        return "link"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "file"
    return "special"


def fd_location(fd: int, host) -> str:
    root = "/proc/self/fd" if os.path.isdir("/proc/self/fd") else "/dev/fd"
    located = os.path.realpath(host.join(root, str(fd)))
    if os.path.islink(located):
        raise OSError(errno.ELOOP, "descriptor location loop")
    return os.path.normcase(located)



def discover_descriptors(start, host):
    raw = host.raw(start)
    parsed = host.literal(raw) if raw is not None else None
    if parsed is None:
        return host.closed(start)
    try:
        markers = host.markers()
        physical = _walk(parsed, host, None, markers)
        if physical is None:
            return host.closed(start)
        canonical = host.canonical(raw)
        if not host.bounded(canonical):
            return host.closed(start)
        if host.normcase(canonical) != host.normcase(physical):
            parsed = host.literal(canonical)
            physical = _walk(parsed, host, None, markers) if parsed is not None else None
            if physical is None:
                return host.closed(start)
        return host.choose(markers, physical, start)
    except (OSError, ValueError, RuntimeError):
        return host.closed(start)


def proven_outside(path, fence, host):
    parsed = host.literal(path)
    if parsed is None:
        return False
    try:
        return _walk(parsed, host, fence) is not None
    except (OSError, ValueError, RuntimeError):
        return False


def _walk(parsed, host, fence, markers=None):
    drive, parts = parsed
    pending = list(parts)
    current = None
    try:
        current = host.open_directory(None, host.root(drive))
        located = host.fd_location(current)
        if not host.literal_root(located, drive):
            return None
        hops = 0
        while True:
            if not host.bounded(located) or (fence is not None and host.inside(located, fence)):
                return None
            if markers is not None:
                host.record(located, markers)
                if host.marker(current):
                    markers.add(host.normcase(located))
            if not pending:
                return located
            step = _step(host, current, located, pending, hops, fence)
            if step is None:
                return None
            current, located, hops, stopped = step
            if current is None:
                return None
            if stopped:
                return located
    finally:
        if current is not None:
            host.close(current)


def _child(host, located, part):
    extra = 0 if located[-1:] in host.separators() else 1
    if len(located) + extra + len(part) > host.max_chars():
        return None
    text = host.join(located, part)
    return text if host.bounded(text) else None


def _step(host, current, located, pending, hops, fence):
    part = pending.pop(0)
    if part == "..":
        entered = _enter(host, current, "..")
        return None if entered is None else (*entered, hops, False)
    candidate = _child(host, located, part)
    if candidate is None or (fence is not None and host.inside(candidate, fence)):
        return None
    kind = host.kind(current, part)
    if kind in ("missing", "special", "unsupported"):
        return None
    if kind == "link":
        return _retarget(host, current, located, part, pending, hops)
    if kind != "dir":
        if pending or (fence is not None and not _file_outside(host, current, part, fence, candidate)):
            return None
        return current, located, hops, True
    entered = _enter(host, current, part)
    return None if entered is None else (*entered, hops, False)


def _enter(host, current, part, *, root_drive=None):
    opened = host.open_directory(current, part)
    try:
        located = host.fd_location(opened)
        proven_root = root_drive is None or host.literal_root(located, root_drive)
    except (OSError, ValueError, RuntimeError):
        host.close(opened)
        raise
    if not proven_root:
        host.close(opened)
        return None
    try:
        return host.replace(current, opened), located
    except OSError:
        return None, located


def _retarget(host, current, located, part, pending, hops):
    if hops >= host.max_hops():
        return None
    drive = host.splitdrive(located)[0]
    spliced = host.splice(host.readlink(part, current), pending, drive)
    if spliced is None:
        return None
    new_drive, new_parts, absolute = spliced
    pending[:] = new_parts
    if not absolute:
        return current, located, hops + 1, False
    root = host.root(new_drive)
    entered = _enter(host, current, root, root_drive=new_drive)
    return None if entered is None else (*entered, hops + 1, False)


def _file_outside(host, current, part, fence, candidate):
    opened = None
    try:
        opened = host.open_leaf(current, part)
        return stat.S_ISREG(os.fstat(opened).st_mode) and not host.inside(host.fd_location(opened), fence)
    except OSError as exc:
        return exc.errno == errno.EACCES and not host.inside(candidate, fence)
    finally:
        if opened is not None:
            host.close(opened)
