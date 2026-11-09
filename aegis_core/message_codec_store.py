"""Anchored, content-addressed message storage; every read verifies bytes."""
from contextlib import contextmanager, suppress
import errno
import hashlib
import os
from pathlib import Path
import stat
from threading import Lock
import uuid
import weakref

from .message_codec_format import (CodecError, HANDLE, MAX_BYTES, SHA, Budget,
                                  require, canonical, parse)


__all__ = ["Store"]


def _store_error(error):
    operational = isinstance(error, OSError) and error.errno not in (
        errno.ENOENT, errno.ENOTDIR, errno.ELOOP, getattr(errno, "ESTALE", None))
    return CodecError("E_AUTH", detail="operation" if operational else None)


def _at(fd, *names):
    require(type(fd) is int and fd >= 0, "E_AUTH")
    return {name: fd for name in names or ("dir_fd",)}


def _release(fd):
    with suppress(OSError):  # A failed close may already release the number; never retry.
        os.close(fd)


class Store:
    """Existing caller-bound root; all entry operations require anchored primitives."""
    def __init__(self, root):
        self.fd = None
        self._lock = Lock()
        try:
            capabilities = {function.__name__ for function in os.supports_dir_fd}
            require({"open", "stat", "link", "unlink"} <= capabilities and
                  hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"), "E_AUTH")
            require(type(root) in (str, Path) or isinstance(root, Path), "E_AUTH")
            given = Path(root)
            if not given.is_absolute() or ".." in given.parts:
                raise CodecError("E_AUTH", detail="path")
            before = given.lstat()
            require(stat.S_ISDIR(before.st_mode), "E_AUTH")
            self.root = given.resolve(strict=True)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            self.fd = os.open(self.root.anchor, flags)
            for component in self.root.parts[1:]:
                child = os.open(component, flags, **_at(self.fd))
                parent, self.fd = self.fd, child
                os.close(parent)
            info = os.fstat(self.fd)
            self._identity = (info.st_dev, info.st_ino)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise CodecError("E_AUTH", detail="private")
            require((info.st_dev, info.st_ino) == (before.st_dev, before.st_ino), "E_AUTH")
            self._finalizer = weakref.finalize(self, _release, self.fd)
        except (OSError, ValueError, RuntimeError) as error:
            fd, self.fd = self.fd, None
            if fd is not None:
                _release(fd)
            if isinstance(error, CodecError):
                raise
            raise _store_error(error) from None

    def close(self):
        with self._lock:
            fd, self.fd = self.fd, None
            if fd is not None:
                self._finalizer.detach()
                _release(fd)

    def _check_root(self, fd):
        require(type(fd) is int, "E_AUTH")
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_nlink > 0 and (info.st_dev, info.st_ino) == self._identity, "E_AUTH")
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise CodecError("E_AUTH", detail="private")
        current = os.stat(self.root, follow_symlinks=False)
        require((current.st_dev, current.st_ino) == self._identity, "E_AUTH")

    @contextmanager
    def _directory(self):
        with self._lock:
            try:
                fd = self.fd
                self._check_root(fd)
                yield fd
                self._check_root(fd)
            except (OSError, ValueError, RuntimeError) as exc:
                if isinstance(exc, CodecError):
                    raise
                raise _store_error(exc) from None

    def _reference(self, rootfd, operation, *args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except FileNotFoundError:
            self._check_root(rootfd)
            raise CodecError("E_REF", detail="resolution") from None

    def _open(self, name, flags, rootfd):
        flags |= os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(name, flags, 0o600, **_at(rootfd))
        try:
            require(stat.S_ISREG(os.fstat(fd).st_mode), "E_AUTH")
            return fd
        except BaseException:
            _release(fd)
            raise

    def resolve(self, reference):
        with self._directory() as rootfd:
            return self._resolve(reference, rootfd)

    def _resolve(self, reference, rootfd):
        require(type(reference) is str and HANDLE.fullmatch(reference) is not None, "E_REF", detail="handle")
        matches = [reference] if len(reference) == 64 else []
        if not matches:
            scan_fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, **_at(rootfd))
            try:
                with os.scandir(scan_fd) as entries:
                    for entry in entries:
                        name = entry.name
                        if len(name) == 69 and name.endswith(".json") and SHA.fullmatch(name[:64]) and name[:64].startswith(reference):
                            matches.append(name[:64])
                            if len(matches) == 2:
                                break
            finally:
                os.close(scan_fd)
        if len(matches) != 1:
            self._check_root(rootfd)
            raise CodecError("E_REF", detail="resolution")
        info = self._reference(rootfd, os.stat, matches[0] + ".json", follow_symlinks=False, **_at(rootfd))
        require(stat.S_ISREG(info.st_mode), "E_AUTH")
        return matches[0]

    def _read_bytes(self, rid, rootfd, budget=None, expected_size=None):
        fd = self._open(rid + ".json", os.O_RDONLY, rootfd)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if expected_size is not None:
                require(before.st_size == expected_size, "E_HASH")
            require(before.st_size <= MAX_BYTES, "E_LIMIT", detail="record")
            if budget is not None:
                budget.check(before.st_size)
            chunks, size = [], 0
            while True:
                count = min(4096, MAX_BYTES + 1 - size)
                if budget is not None:
                    count = min(count, max(1, budget.limit - budget.used + 1))
                chunk = stream.read(count)
                if not chunk:
                    break
                size += len(chunk)
                require(size <= MAX_BYTES, "E_LIMIT", detail="record")
                if budget is not None:
                    budget.charge(len(chunk))
                chunks.append(chunk)
            after = os.fstat(stream.fileno())
            # Link-count/ctime changes during publication do not alter content.
            require((before.st_dev, before.st_ino, before.st_size) ==
                  (after.st_dev, after.st_ino, after.st_size), "E_HASH")
        data = b"".join(chunks)
        require(len(data) == before.st_size and hashlib.sha256(data).hexdigest() == rid, "E_HASH")
        return data, len(data)

    def _verified(self, reference, budget, describe=False):
        require(budget is None or type(budget) is Budget, "E_LIMIT")
        with self._directory() as rootfd:
            rid = self._resolve(reference, rootfd)
            data, size = self._reference(rootfd, self._read_bytes, rid, rootfd, budget)
            value = parse(data)
            if not describe:
                return value
            return {"ref": rid[:16], "kind": value["kind"], "chars": size}

    def read(self, reference, *, _budget=None):
        return self._verified(reference, _budget)

    def describe(self, reference, *, _budget=None):
        """Verify actual bytes, canonical encoding and schema on every call."""
        return self._verified(reference, _budget, describe=True)

    def write(self, value):
        data = canonical(value)
        rid = hashlib.sha256(data).hexdigest()
        with self._directory() as rootfd:
            try:
                require(self._read_bytes(rid, rootfd, expected_size=len(data))[0] == data, "E_HASH")
                return rid
            except FileNotFoundError:
                pass
            name, temporary = rid + ".json", ".msg-" + uuid.uuid4().hex
            fd = self._open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, rootfd)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(temporary, name, follow_symlinks=False, **_at(rootfd, "src_dir_fd", "dst_dir_fd"))
                except FileExistsError:
                    pass  # Existing bytes receive exactly the same verification.
                require(self._read_bytes(rid, rootfd, expected_size=len(data))[0] == data, "E_HASH")
                os.fsync(rootfd)
            finally:
                with suppress(OSError):  # Cleanup never replaces the original refusal.
                    os.unlink(temporary, **_at(rootfd))
                with suppress(OSError):
                    os.fsync(rootfd)
        return rid
