"""Confined append-only manager audit records, separate from repository ledgers.

The store is same-uid audit evidence, not authenticated or tamper-resistant authority.
Every event has a sequence and canonical SHA256 chain. Replay rejects every malformed
or torn row without repairing history. Bounds are 16 MiB per audit and 1 MiB per row.
The bounded lock serializes readers and transactions across processes; file and
containing-directory fsyncs complete before a transaction acknowledges its append.
POSIX creation, lock and audit opens are anchored to directory descriptors. Windows
rejects existing path escapes; concurrent same-user ancestor swaps are unsupported.
"""
from __future__ import annotations

import copy
import hashlib
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path

from aegis_core import storage
from aegis_core.config import read_capped
from aegis_core.errors import LockTimeoutError, PathTraversalError
from aegis_core.manager_policy import ManagerError, canonical
from aegis_core.primitives import strict_loads

__all__ = ["MAX_AUDIT_BYTES", "MAX_ROW_BYTES", "ManagerStore"]

MAX_AUDIT_BYTES = 16 * 1024 * 1024
MAX_ROW_BYTES = 1024 * 1024
_RESERVED = frozenset({"seq", "prev", "hash"})
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FLAGS = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)



def _private(info, directory=False):
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    mode = 0o700 if directory else 0o600
    if not expected(info.st_mode) or (not directory and info.st_nlink != 1):
        raise ManagerError("unsafe_store")
    if os.name == "posix" and (stat.S_IMODE(info.st_mode) != mode or info.st_uid != os.getuid()):
        raise ManagerError("unsafe_store")


def _sync_directory(path):
    if os.name != "posix":
        return
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _FLAGS)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class ManagerStore:
    def __init__(self, root: Path, forbidden_roots=()):
        raw = Path(root)
        if not raw.is_absolute() or ".." in raw.parts:
            raise ManagerError("unsafe_store")
        self.root = raw
        self.forbidden_roots = tuple(Path(item).resolve() for item in forbidden_roots)

    def _placement(self):
        for forbidden in self.forbidden_roots:
            if self.root == forbidden or forbidden in self.root.parents or self.root in forbidden.parents:
                raise ManagerError("store_in_worktree")
        for ancestor in (self.root, *self.root.parents):
            if os.path.lexists(ancestor / ".git"):
                raise ManagerError("store_in_worktree")

    def _check(self, create=False):
        self._placement()
        for path in reversed((self.root, *self.root.parents)):
            try:
                info = path.lstat()
            except FileNotFoundError:
                if not create:
                    return False
                try:
                    path.mkdir(mode=0o700)
                    _sync_directory(path.parent)
                except FileExistsError:
                    pass  # Another writer may create this same directory under its lock.
                info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or path.resolve() != path:
                raise ManagerError("unsafe_store")
        _private(self.root.lstat(), directory=True)
        for name in ("audit.lock", "audit.jsonl"):
            try:
                _private((self.root / name).lstat())
            except FileNotFoundError:
                pass
        return True

    def _anchor_check(self, chain):
        self._placement()
        for path, identity in chain:
            try:
                info = path.lstat()
            except OSError as exc:
                raise ManagerError("unsafe_store") from exc
            if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity:
                raise ManagerError("unsafe_store")

    def _entries(self, directory):
        for name in ("audit.lock", "audit.jsonl"):
            try:
                _private(os.stat(name, dir_fd=directory, follow_symlinks=False))
            except FileNotFoundError:
                pass

    @contextmanager
    def _anchor(self, create=False):
        self._placement()
        if os.name != "posix":
            if not self._check(create=create):
                yield None
                return
            yield None, ()
            return
        flags = os.O_RDONLY | os.O_DIRECTORY | _FLAGS
        directory = os.open(self.root.anchor, flags)
        chain = [(Path(self.root.anchor), (os.fstat(directory).st_dev, os.fstat(directory).st_ino))]
        current = Path(self.root.anchor)
        try:
            for part in self.root.parts[1:]:
                current = current / part
                try:
                    child = os.open(part, flags, dir_fd=directory)
                except FileNotFoundError:
                    if not create:
                        yield None
                        return
                    self._anchor_check(chain)
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=directory)
                        os.fsync(directory)
                    except FileExistsError:
                        pass
                    child = os.open(part, flags, dir_fd=directory)
                except OSError as exc:
                    raise ManagerError("unsafe_store") from exc
                os.close(directory)
                directory = child
                info = os.fstat(directory)
                chain.append((current, (info.st_dev, info.st_ino)))
            _private(os.fstat(directory), directory=True)
            self._anchor_check(chain)
            self._entries(directory)
            yield directory, chain
        finally:
            os.close(directory)

    @contextmanager
    def _lock_at(self, anchor):
        directory, chain = anchor
        kwargs = {"dir_fd": directory} if directory is not None else {}
        try:
            with storage.file_lock(self.root / "audit.lock", timeout=5.0, **kwargs):
                if directory is None:
                    self._check()
                else:
                    self._anchor_check(chain)
                    self._entries(directory)
                yield anchor
        except LockTimeoutError as exc:
            raise ManagerError("store_busy") from exc
        except PathTraversalError as exc:
            raise ManagerError("unsafe_store") from exc

    @contextmanager
    def _locked(self):
        with self._anchor(create=True) as anchor, self._lock_at(anchor):
            yield anchor

    @contextmanager
    def _audit(self, flags, anchor):
        directory, chain = anchor
        if directory is not None:
            self._anchor_check(chain)
        fd = None
        try:
            target = "audit.jsonl" if directory is not None else self.root / "audit.jsonl"
            kwargs = {"dir_fd": directory} if directory is not None else {}
            fd = os.open(target, flags | _FLAGS, 0o600, **kwargs)
            _private(os.fstat(fd))
            yield fd
        finally:
            if fd is not None:
                os.close(fd)

    def _read(self, anchor):
        try:
            with self._audit(os.O_RDONLY, anchor) as fd:
                if os.fstat(fd).st_size > MAX_AUDIT_BYTES:
                    raise ManagerError("audit_limit")
                raw = read_capped(fd, MAX_AUDIT_BYTES)
        except FileNotFoundError:
            return []
        if len(raw) > MAX_AUDIT_BYTES:
            raise ManagerError("audit_limit")
        if raw and not raw.endswith(b"\n"):
            raise ManagerError("audit_corrupt")
        rows = []
        previous = "0" * 64
        for line in raw.split(b"\n")[:-1]:
            if len(line) + 1 > MAX_ROW_BYTES:
                raise ManagerError("audit_limit")
            try:
                row = strict_loads(line)
                if not isinstance(row, dict) or not _RESERVED <= set(row) \
                        or type(row["seq"]) is not int or row["seq"] != len(rows) + 1 \
                        or row["prev"] != previous or not isinstance(row["hash"], str) \
                        or not _SHA.fullmatch(row["hash"]):
                    raise ValueError("invalid envelope")
                body = {key: value for key, value in row.items() if key != "hash"}
                if hashlib.sha256(canonical(body)).hexdigest() != row["hash"]:
                    raise ValueError("invalid chain")
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise ManagerError("audit_corrupt") from exc
            rows.append(row)
            previous = row["hash"]
        return rows

    def read(self):
        with self._anchor() as anchor:
            if anchor is None:
                return []
            directory, _ = anchor
            try:
                if directory is None:
                    (self.root / "audit.jsonl").stat()
                else:
                    os.stat("audit.jsonl", dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return []
            with self._lock_at(anchor):
                return self._read(anchor)

    def _event(self, payload, rows):
        if type(payload) is not dict or _RESERVED & set(payload):
            raise ManagerError("invalid_event")
        row = {**payload, "seq": len(rows) + 1, "prev": rows[-1]["hash"] if rows else "0" * 64}
        try:
            row["hash"] = hashlib.sha256(canonical(row)).hexdigest()
            raw = canonical(row) + b"\n"
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ManagerError("invalid_event") from exc
        if len(raw) > MAX_ROW_BYTES:
            raise ManagerError("audit_limit")
        return row, raw

    def _append(self, payload, rows, anchor):
        row, raw = self._event(payload, rows)
        with self._audit(os.O_RDWR | os.O_CREAT | os.O_APPEND, anchor) as fd:
            if os.fstat(fd).st_size + len(raw) > MAX_AUDIT_BYTES:
                raise ManagerError("audit_limit")
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                if written <= 0:
                    raise OSError("manager audit write made no progress")
                offset += written
            os.fsync(fd)
        if anchor[0] is None:
            _sync_directory(self.root)
            self._check()
        else:
            os.fsync(anchor[0])
            self._anchor_check(anchor[1])
            self._entries(anchor[0])
        return row

    def transaction(self, callback):
        with self._locked() as anchor:
            rows = self._read(anchor)
            payload, result = callback(copy.deepcopy(rows))
            if self._read(anchor) != rows:
                raise ManagerError("audit_conflict")
            if payload is not None:
                self._append(payload, rows, anchor)
            return result

    def append(self, payload):
        with self._locked() as anchor:
            return self._append(payload, self._read(anchor), anchor)
