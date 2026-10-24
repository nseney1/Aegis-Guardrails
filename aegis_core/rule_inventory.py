"""Canonical, race-detecting byte snapshot of the rule files (aegis_core.rules projects it)."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
from aegis_core.workspace.layout import WorkspaceLayout
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class RuleInventoryEntry:
    """One immutable rule snapshot captured during inventory."""

    relative_path: str
    absolute_path: str
    content: bytes
    digest: str
    size: int


@dataclass(frozen=True)
class RuleInventory:
    """Stable entries and their aggregate content fingerprint."""

    entries: Tuple[RuleInventoryEntry, ...]
    fingerprint: str


class RuleInventoryError(RuntimeError):
    """The rule tree could not be inventoried safely and consistently."""

    def __init__(
        self,
        operation: str,
        path: str,
        message: str,
        cause: Optional[BaseException] = None,
    ) -> None:
        self.operation = operation
        self.path = os.path.abspath(path)
        self.cause = cause
        super().__init__(f"rule inventory {operation} failed for {self.path}: {message}")


# On Windows os.stat() reports st_ctime as the creation time while os.fstat()
# reports the last-change time, so a path stat and an fd stat of the same
# unchanged file disagree once it has ever been written (BUG-035). Creation
# time never moves on a rewrite anyway; st_ino, st_size and st_mtime_ns still
# catch replacement and modification there.
_COMPARE_CTIME = os.name != "nt"


def _stat_signature(info: os.stat_result) -> Tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns if _COMPARE_CTIME else 0,
    )


def _identity_signature(info: os.stat_result) -> Tuple[int, int, int]:
    """Identity fields used for ancestors whose unrelated contents may change."""
    return (info.st_dev, info.st_ino, info.st_mode)


def _stat_path(path: str, operation: str = "stat") -> os.stat_result:
    try:
        return os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise RuleInventoryError(operation, path, str(exc), exc) from exc


def _optional_stat(path: str) -> Optional[os.stat_result]:
    try:
        return os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RuleInventoryError("stat", path, str(exc), exc) from exc


def _require_directory(path: str, info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode):
        raise RuleInventoryError("validate", path, "symlinked directory is not allowed")
    if not stat.S_ISDIR(info.st_mode):
        raise RuleInventoryError("validate", path, "expected a directory")


def _read_stable_file(path: str, before: os.stat_result) -> bytes:
    if stat.S_ISLNK(before.st_mode):
        raise RuleInventoryError("validate", path, "symlinked .md rule is not allowed")
    if not stat.S_ISREG(before.st_mode):
        raise RuleInventoryError("validate", path, ".md rule is not a regular file")

    flags = os.O_RDONLY
    # Without O_BINARY, Windows opens in text mode: os.read() turns CRLF into
    # LF and stops at 0x1A, so the snapshot would not be the bytes on disk.
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuleInventoryError("open", path, str(exc), exc) from exc

    try:
        try:
            opened = os.fstat(fd)
        except OSError as exc:
            raise RuleInventoryError("stat", path, str(exc), exc) from exc
        if _stat_signature(opened) != _stat_signature(before):
            raise RuleInventoryError("read", path, "file changed before it was opened")

        chunks = []  # type: List[bytes]
        while True:
            try:
                chunk = os.read(fd, 65536)
            except OSError as exc:
                raise RuleInventoryError("read", path, str(exc), exc) from exc
            if not chunk:
                break
            chunks.append(chunk)

        try:
            after_read = os.fstat(fd)
        except OSError as exc:
            raise RuleInventoryError("stat", path, str(exc), exc) from exc
        if _stat_signature(after_read) != _stat_signature(opened):
            raise RuleInventoryError("read", path, "file changed while it was read")
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    after_path = _stat_path(path)
    if _stat_signature(after_path) != _stat_signature(before):
        raise RuleInventoryError("read", path, "file changed during inventory")
    return b"".join(chunks)


def fingerprint(entries: Iterable[RuleInventoryEntry]) -> str:
    """The aggregate fingerprint of ``entries``, in their order: the one definition for a working-tree
    inventory and a commit's (aegis_core.rule_integrity), so equal rules always compare equal."""
    aggregate = hashlib.sha256(b"aegis-rule-inventory-v1\0")
    for entry in entries:
        aggregate.update(entry.relative_path.encode("utf-8") + b"\0" + bytes.fromhex(entry.digest) + b"\0")
    return aggregate.hexdigest()


def _empty_inventory() -> RuleInventory:
    return RuleInventory(entries=(), fingerprint=fingerprint(()))


def inventory_rules(workspace: str) -> RuleInventory:
    """Capture every ``.md`` below ``.aegis/rules`` without following links.

    The returned content bytes are the same bytes used to calculate each entry
    digest and the aggregate fingerprint. Directory and file metadata are
    checked before and after capture so concurrent changes fail closed.
    """
    workspace_abs = os.path.abspath(os.fspath(workspace))
    layout = WorkspaceLayout(Path(workspace_abs))
    parent_dir = str(layout.aegis_dir)
    rules_root = str(layout.rules_dir)

    workspace_info = _optional_stat(workspace_abs)
    if workspace_info is None:
        return _empty_inventory()
    _require_directory(workspace_abs, workspace_info)

    parent_info = _optional_stat(parent_dir)
    if parent_info is None:
        return _empty_inventory()
    _require_directory(parent_dir, parent_info)

    rules_info = _optional_stat(rules_root)
    if rules_info is None:
        return _empty_inventory()
    _require_directory(rules_root, rules_info)

    ancestor_identities = {
        workspace_abs: _identity_signature(workspace_info),
        parent_dir: _identity_signature(parent_info),
    }
    directory_signatures = {}  # type: dict[str, Tuple[int, int, int, int, int, int]]
    rule_paths = []  # type: List[str]

    def walk_error(exc: OSError) -> None:
        path = getattr(exc, "filename", None) or rules_root
        raise RuleInventoryError("list", path, str(exc), exc)

    # os.walk's defaults: top down, so each directory's children are validated (a
    # symlinked one raises) before any is entered, and links are never followed. A
    # listing error reaches walk_error; nothing else in the loop raises OSError.
    for dirpath, dirnames, filenames in os.walk(rules_root, onerror=walk_error):
        dir_info = _stat_path(dirpath)
        _require_directory(dirpath, dir_info)
        directory_signatures[dirpath] = _stat_signature(dir_info)

        dirnames.sort()
        for dirname in dirnames:
            child = os.path.join(dirpath, dirname)
            child_info = _stat_path(child)
            if stat.S_ISLNK(child_info.st_mode):
                raise RuleInventoryError(
                    "validate", child, "symlinked directory is not allowed"
                )
            if not stat.S_ISDIR(child_info.st_mode):
                raise RuleInventoryError("validate", child, "expected a directory")

        for filename in sorted(filenames):
            # Any case of the extension: the loader reports a rule named x.MD instead
            # of letting it go unseen.
            if filename.lower().endswith(".md"):
                rule_paths.append(os.path.join(dirpath, filename))

    entries = []  # type: List[RuleInventoryEntry]
    for path in sorted(rule_paths):
        before = _stat_path(path)
        content = _read_stable_file(path, before)
        digest = hashlib.sha256(content).hexdigest()
        relative = os.path.relpath(path, workspace_abs).replace(os.sep, "/")
        entries.append(RuleInventoryEntry(
            relative_path=relative,
            absolute_path=os.path.abspath(path),
            content=content,
            digest=digest,
            size=len(content),
        ))

    for path, expected in ancestor_identities.items():
        current = _stat_path(path)
        if _identity_signature(current) != expected:
            raise RuleInventoryError("list", path, "ancestor changed during inventory")
    for path, expected in directory_signatures.items():
        current = _stat_path(path)
        if _stat_signature(current) != expected:
            raise RuleInventoryError("list", path, "directory changed during inventory")

    return RuleInventory(entries=tuple(entries), fingerprint=fingerprint(entries))


__all__ = [
    "RuleInventory",
    "RuleInventoryEntry",
    "RuleInventoryError",
    "fingerprint",
    "inventory_rules",
]
