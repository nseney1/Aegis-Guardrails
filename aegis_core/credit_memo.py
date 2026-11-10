"""Bounded in-process exposure persistence evidence; the locked ledger stays authoritative."""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import os
from pathlib import Path
import stat
from typing import Any, Dict, Mapping, Optional, Sequence, Set, Tuple

from aegis_core import atomicio, storage
from aegis_core.errors import PathTraversalError

__all__ = ["before_read", "contains", "reconcile", "remember", "reset", "root_key"]

_Key = Tuple[str, str, str, str, Optional[str]]
_Ancestors = Tuple[Tuple[Path, Tuple[int, int]], ...]
_PERSISTED: Set[_Key] = set()
_MAX_PERSISTED = 50_000
# Mirrors aegis_core.telemetry_engine.ledger._TAIL_CHECK_BYTES. RF-32-style
# unification comes with a later refactor; do not couple to that module's private names.
_TAIL_CHECK_BYTES = 256


@dataclass(frozen=True)
class _PersistedLedger:
    path: Path
    identity: Tuple[int, int]
    size: int
    tail: bytes
    head: bytes


_PERSISTED_IDENTITY: Dict[str, _PersistedLedger] = {}


@dataclass(frozen=True)
class _ReadGeneration:
    identity: Optional[Tuple[int, int]]
    size: int
    ancestors: Optional[_Ancestors]


@dataclass(frozen=True)
class _MemoSite:
    path: Path
    ancestors: Optional[_Ancestors]


def _site_evidence(site: storage.LedgerSite) -> _MemoSite:
    """Record every validated state ancestor, through its trusted workspace/git root."""
    try:
        ancestors = []
        for index in range(4 if site.shared else 3):
            directory = site.path.parents[index]
            info = os.lstat(directory)
            if not stat.S_ISDIR(info.st_mode):
                return _MemoSite(site.path, None)
            ancestors.append((directory, (info.st_dev, info.st_ino)))
        return _MemoSite(site.path, tuple(ancestors))
    except OSError:
        return _MemoSite(site.path, None)


def _same_ancestors(ancestors: Optional[_Ancestors]) -> bool:
    if ancestors is None:
        return False
    for directory, identity in ancestors:
        info = os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity:
            return False
    return True


def root_key(root: Any) -> Tuple[str, Optional[_MemoSite]]:
    """Use storage's resolved ledger site, including linked worktrees sharing a ledger.

    A site lookup failure falls back to the resolved workspace root, so it cannot
    hit that site's memo and the normal locked path handles the failure.
    """
    try:
        site = _site_evidence(storage.ledger_site(root, create=False))
        return str(site.path), site
    except (OSError, PathTraversalError):
        try:
            return str(Path(str(root)).resolve()), None
        except OSError:
            return str(root), None


def reset() -> None:
    """Discard this process's persistence memo, without importing or reading the ledger."""
    _PERSISTED.clear()
    _PERSISTED_IDENTITY.clear()


def _forget(root: str) -> None:
    _PERSISTED.difference_update({k for k in _PERSISTED if k[0] == root})
    _PERSISTED_IDENTITY.pop(root, None)


def _snapshot(path: Path, size: Optional[int] = None,
              ancestors: Optional[_Ancestors] = None) -> Optional[_PersistedLedger]:
    """Optional bounded cache evidence, read from one anchored regular-file descriptor.

    Use the regular-file opener on platforms without descriptor-relative no-follow
    operations. Cache I/O failures are misses, never failures of an exposure write.
    """
    if not path.is_absolute():
        return None
    anchored = (hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW")
                and {"open", "stat"} <= {f.__name__ for f in os.supports_dir_fd}
                and "stat" in {f.__name__ for f in os.supports_follow_symlinks})
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    try:
        with ExitStack() as opened:
            chain = []
            if anchored:
                flags |= os.O_NOFOLLOW
                parent = os.open(path.anchor, flags | os.O_DIRECTORY)
                opened.callback(os.close, parent)
                for part in path.parts[1:-1]:
                    child = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent)
                    opened.callback(os.close, child)
                    info = os.fstat(child)
                    chain.append((parent, part, (info.st_dev, info.st_ino)))
                    parent = child
                fd = os.open(path.name, flags | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0),
                             dir_fd=parent)
            else:
                expected = os.lstat(path)
                fd = atomicio._open_regular(path, flags | getattr(os, "O_NONBLOCK", 0))
            opened.callback(os.close, fd)
            info = os.fstat(fd)
            if not anchored and (expected.st_dev, expected.st_ino) != (info.st_dev, info.st_ino):
                return None
            if not anchored and not _same_ancestors(ancestors):
                return None
            offset = info.st_size if size is None else size
            if not stat.S_ISREG(info.st_mode) or not 0 < offset <= info.st_size:
                return None
            count = min(offset, _TAIL_CHECK_BYTES)
            os.lseek(fd, offset - count, os.SEEK_SET)
            tail = os.read(fd, count)
            if len(tail) != count:
                return None
            head = tail
            if offset > count:
                os.lseek(fd, 0, os.SEEK_SET)
                head = os.read(fd, count)
                if len(head) != count:
                    return None
            # Descriptors pin every ancestor. Reject a rename or link substitution
            # as well, so a detached old ledger cannot validate the current site.
            for directory, part, identity in chain:
                current = os.stat(part, dir_fd=directory, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != identity:
                    return None
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False) if anchored else os.lstat(path)
            if not anchored and not _same_ancestors(ancestors):
                return None
            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino) or current.st_size < offset:
                return None
            return _PersistedLedger(path, (info.st_dev, info.st_ino), offset, tail, head)
    except (OSError, PathTraversalError):
        return None


def contains(root: str, keys: Sequence[_Key], site: Optional[_MemoSite]) -> bool:
    """Check persisted keys against the current site, without a lock or full read.

    Validate identity, size and bounded head/tail continuity. Deliberate content
    forgery preserving both sampled regions is outside the memo's threat model.
    """
    cached = _PERSISTED_IDENTITY.get(root)
    if cached is not None:
        if site is None or site.path != cached.path or _snapshot(site.path, cached.size, site.ancestors) != cached:
            _forget(root)
    return all(key in _PERSISTED for key in keys)


def before_read(root: str, site: storage.LedgerSite) -> Optional[_ReadGeneration]:
    """Revalidate metadata after acquiring the ledger lock and before reading its rows."""
    path = site.path
    ancestors = _site_evidence(site).ancestors
    try:
        current = os.stat(path)
    except FileNotFoundError:
        _forget(root)
        return _ReadGeneration(None, 0, ancestors)
    except OSError:
        _forget(root)
        return None
    else:
        cached = _PERSISTED_IDENTITY.get(root)
        if cached is not None and (path != cached.path
                                   or (current.st_dev, current.st_ino) != cached.identity
                                   or current.st_size < cached.size):
            _forget(root)
        return _ReadGeneration((current.st_dev, current.st_ino), current.st_size, ancestors)


def reconcile(root: str, seen: Set[Tuple[str, str, Optional[str]]]) -> None:
    """Keep only keys actually found by the caller's locked read; perform no I/O."""
    _PERSISTED.difference_update({k for k in _PERSISTED if k[0] == root and (k[2], k[3], k[4]) not in seen})


def remember(root: str, keys: Sequence[_Key], path: Path, before: Optional[_ReadGeneration],
             appended: Sequence[Mapping[str, Any]], read: Optional[storage.FileReport]) -> None:
    """Memoise after the caller's locked append, within the process-wide size bound."""
    if len(_PERSISTED) + len(keys) > _MAX_PERSISTED:
        reset()
    if len(keys) <= _MAX_PERSISTED:
        evidence = getattr(appended, "report", None) if appended else read
        if (before is None or evidence is None or not evidence.tail or not evidence.head
                or evidence.size < before.size + evidence.added
                or (before.identity is not None and evidence.identity != before.identity)
                or (read is not None and not evidence.head.startswith(read.head))
                or (read is None and before.size > 0)):
            _forget(root)
            return
        # Compare the exact bounded suffix of the bytes actually read/appended,
        # at that operation's end offset. Later ordinary appends remain valid.
        snapshot = _snapshot(path, evidence.size, before.ancestors)
        if (snapshot is not None and snapshot.identity == evidence.identity
                and snapshot.tail.endswith(evidence.tail) and snapshot.head == evidence.head):
            _PERSISTED_IDENTITY[root] = snapshot
            _PERSISTED.update(keys)
        else:
            _forget(root)
