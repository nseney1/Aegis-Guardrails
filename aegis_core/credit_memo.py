"""Bounded in-process exposure persistence evidence; the locked ledger stays authoritative."""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import os
from pathlib import Path
import stat
from time import time_ns
from typing import Any, Dict, Mapping, Optional, Sequence, Set, Tuple

from aegis_core import atomicio, storage
from aegis_core.errors import PathTraversalError

__all__ = ["before_read", "contains", "reconcile", "remember", "reset", "root_key"]

_Key = Tuple[str, str, str, str, Optional[str]]
_Ancestors = Tuple[Tuple[Path, Tuple[int, int]], ...]
_PERSISTED: Set[_Key] = set()
_MAX_PERSISTED = 50_000
_RACY_WINDOW_NS = 2_000_000_000


def _settled(evidence: storage.FileReport) -> bool:
    """Racy I/O evidence cannot become eligible by aging before a later fill."""
    _, mtime_ns, ctime_ns = storage.file_generation(evidence.size, evidence.mtime_ns, evidence.ctime_ns)
    return (evidence.started_ns is not None
            and evidence.started_ns - mtime_ns > _RACY_WINDOW_NS
            and (ctime_ns == 0 or evidence.started_ns - ctime_ns > _RACY_WINDOW_NS))


@dataclass(frozen=True)
class _PersistedLedger:
    path: Path
    identity: Tuple[int, int]
    size: int
    mtime_ns: int
    ctime_ns: int


_PERSISTED_IDENTITY: Dict[str, _PersistedLedger] = {}


@dataclass(frozen=True)
class _ReadGeneration:
    identity: Optional[Tuple[int, int]]
    size: int
    ancestors: Optional[_Ancestors]
    mtime_ns: int = 0
    ctime_ns: int = 0


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


def _snapshot(path: Path, ancestors: Optional[_Ancestors] = None) -> Optional[_PersistedLedger]:
    """Optional stat evidence from one anchored regular-file descriptor, without reads.

    Use the regular-file opener on platforms without descriptor-relative no-follow
    operations. Cache I/O failures are misses, never failures of an exposure write.
    """
    if not path.is_absolute():
        return None
    captured_ns = time_ns()
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
            if (not stat.S_ISREG(info.st_mode) or info.st_size <= 0
                    or captured_ns - info.st_mtime_ns <= _RACY_WINDOW_NS):
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
            stamps = storage.file_generation(info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if ((current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
                    or storage.file_generation(current.st_size, current.st_mtime_ns, current.st_ctime_ns) != stamps):
                return None
            return _PersistedLedger(path, (info.st_dev, info.st_ino), *stamps)
    except (OSError, PathTraversalError):
        return None


def contains(root: str, keys: Sequence[_Key], site: Optional[_MemoSite]) -> bool:
    """Check persisted keys against the current site, without a lock or full read.

    Validate identity, size and file generation stamps. Every write, including an
    unrelated append, invalidates the memo and takes the authoritative locked read.
    """
    cached = _PERSISTED_IDENTITY.get(root)
    if cached is not None:
        if site is None or site.path != cached.path or _snapshot(site.path, site.ancestors) != cached:
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
        stamps = storage.file_generation(current.st_size, current.st_mtime_ns, current.st_ctime_ns)
        cached = _PERSISTED_IDENTITY.get(root)
        if cached is not None and (path != cached.path
                                   or (current.st_dev, current.st_ino) != cached.identity
                                   or stamps
                                   != (cached.size, cached.mtime_ns, cached.ctime_ns)):
            _forget(root)
        return _ReadGeneration((current.st_dev, current.st_ino), stamps[0], ancestors, *stamps[1:])


def reconcile(root: str, seen: Set[Tuple[str, str, Optional[str]]]) -> None:
    """Keep only keys actually found by the caller's locked read; perform no I/O."""
    _PERSISTED.difference_update({k for k in _PERSISTED if k[0] == root and (k[2], k[3], k[4]) not in seen})


def remember(root: str, keys: Sequence[_Key], path: Path, before: Optional[_ReadGeneration],
             appended: Sequence[Mapping[str, Any]], read: Optional[storage.FileReport]) -> None:
    """Memoise only a settled locked read, within the process-wide size bound."""
    if appended:
        _forget(root)
        return
    if len(_PERSISTED) + len(keys) > _MAX_PERSISTED:
        reset()
    if len(keys) <= _MAX_PERSISTED:
        evidence = read
        if (before is None or evidence is None or not _settled(evidence)
                or evidence.identity != before.identity):
            _forget(root)
            return
        # The read must describe the generation observed before it started.
        # A reset in that gap cannot certify keys seen only in the old file.
        prior = (before.size, before.mtime_ns, before.ctime_ns)
        if storage.file_generation(evidence.size, evidence.mtime_ns, evidence.ctime_ns) != prior:
            _forget(root)
            return
        snapshot = _snapshot(path, before.ancestors)
        if (snapshot is not None and snapshot.identity == evidence.identity
                and (snapshot.size, snapshot.mtime_ns, snapshot.ctime_ns)
                == storage.file_generation(evidence.size, evidence.mtime_ns, evidence.ctime_ns)):
            _PERSISTED_IDENTITY[root] = snapshot
            _PERSISTED.update(keys)
        else:
            _forget(root)
