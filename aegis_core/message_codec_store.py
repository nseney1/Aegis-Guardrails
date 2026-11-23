"""Anchored, content-addressed message storage; every read verifies bytes."""
from contextlib import contextmanager, ExitStack, suppress
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
from .storage_confined import ConfinedFileError, open_directory


__all__ = ["Store", "store_supported"]


class _FlatStoreError(CodecError):
    def __init__(self):
        super().__init__("E_AUTH")
        self.args = ("flat message store layout is unsupported; use a new empty store directory",)


def _record_name(name):
    return len(name) == 69 and name.endswith(".json") and SHA.fullmatch(name[:64]) is not None


def _private(info):
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise CodecError("E_AUTH", detail="private")


def _store_error(error):
    if isinstance(error, ConfinedFileError) and error.os_error is not None:
        error = error.os_error
    operational = isinstance(error, OSError) and error.errno not in (
        errno.ENOENT, errno.ENOTDIR, errno.ELOOP, getattr(errno, "ESTALE", None))
    if isinstance(error, ConfinedFileError):
        operational = error.reason == "io" and error.errno != getattr(errno, "ESTALE", None)
    return CodecError("E_AUTH", detail="operation" if operational else None)


def _at(fd, *names):
    require(type(fd) is int and fd >= 0, "E_AUTH")
    return {name: fd for name in names or ("dir_fd",)}


def _release(fd):
    with suppress(OSError):  # A failed close may already release the number; never retry.
        os.close(fd)


def _discard(operation):
    try:
        operation()
    except OSError as error:
        return error
    return None


def _finish_stream(stream, fd, failed):
    """Close stream, then the raw descriptor, once.

    os.fdopen is given closefd=False so a failure before the stream exists,
    or after the stream has accepted the descriptor, leaves that descriptor
    with this closer only. A close error never replaces the caller's error.
    """
    try:
        stream_error = _discard(stream.close)
    finally:
        raw_error = _discard(lambda: os.close(fd))
    if failed:
        return
    if stream_error is not None:
        raise stream_error
    if raw_error is not None:
        raise raw_error


class _DirectoryOwnership:
    def __init__(self):
        self.identity = None
        self.created = False


class _Publication:
    def __init__(self, store):
        self.store = store
        self.rid = None
        self.shard = _DirectoryOwnership()
        self.grants = _DirectoryOwnership()
        self.record_identity = None
        self.staging_name = None
        self.staging_identity = None


def store_supported(*, publication=False):
    """Probe the anchored operations before opening or creating storage."""
    capabilities = {function.__name__ for function in os.supports_dir_fd}
    nofollow = {function.__name__ for function in os.supports_follow_symlinks}
    descriptors = {function.__name__ for function in os.supports_fd}
    required = {"open", "mkdir", "stat", "link", "rename", "unlink"}
    if publication:
        required.add("rmdir")
    return (required <= capabilities and "stat" in nofollow and "scandir" in descriptors and
            hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW") and hasattr(os, "geteuid"))


class Store:
    """Existing caller-bound root; all entry operations require anchored primitives."""

    supported = staticmethod(store_supported)

    def __init__(self, root):
        self.fd = None
        self._lock = Lock()
        try:
            require(self.supported(), "E_AUTH")
            require(type(root) in (str, Path) or isinstance(root, Path), "E_AUTH")
            given = Path(root)
            if not given.is_absolute() or ".." in given.parts:
                raise CodecError("E_AUTH", detail="path")
            parent_path, leaf = given.parent.resolve(strict=True), given.name or "."
            self.root = parent_path / leaf
            with open_directory(os.open, self.root, policy=_private, close_fd=os.close,
                                stat_fd=os.fstat, stat_entry=os.stat, cleanup_fd=_release) as held:
                # Check the layout once when binding the owner-controlled root.
                with os.scandir(held.fd) as entries:
                    if any(_record_name(entry.name) for entry in entries):
                        raise _FlatStoreError()
                self._identity = held.identity
                self.fd = held.detach()
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
        _private(info)
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

    @contextmanager
    def _shard(self, rootfd, name, *, create=False, ownership=None):
        try:
            expected = os.stat(name, follow_symlinks=False, **_at(rootfd))
        except FileNotFoundError:
            if not create:
                self._check_root(rootfd)
                raise CodecError("E_REF", detail="resolution") from None
            try:
                os.mkdir(name, 0o700, **_at(rootfd))
            except FileExistsError:
                pass  # A concurrent creator won; check the visible entry below.
            else:
                if ownership is not None:
                    ownership.created = True
            expected = os.stat(name, follow_symlinks=False, **_at(rootfd))
        require(stat.S_ISDIR(expected.st_mode), "E_AUTH")
        _private(expected)
        identity = expected.st_dev, expected.st_ino
        if ownership is not None:
            ownership.identity = identity
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, **_at(rootfd))
        try:
            def check():
                self._check_root(rootfd)
                opened = os.fstat(fd)
                visible = os.stat(name, follow_symlinks=False, **_at(rootfd))
                require(opened.st_nlink > 0 and (opened.st_dev, opened.st_ino) == identity
                        and (visible.st_dev, visible.st_ino) == identity, "E_AUTH")
                _private(visible)

            check()
            yield fd, check
            check()
        finally:
            _release(fd)

    def _reference(self, check, operation, *args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except FileNotFoundError:
            check()
            raise CodecError("E_REF", detail="resolution") from None

    def _open(self, name, flags, rootfd, *, publication=None):
        flags |= os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(name, flags, 0o600, **_at(rootfd))
        try:
            if publication is not None:
                publication.staging_name = name
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode), "E_AUTH")
            if publication is not None:
                publication.staging_identity = info.st_dev, info.st_ino
            return fd
        except BaseException:
            _release(fd)
            raise

    def resolve(self, reference):
        with self._lookup(reference) as (rid, _, _):
            return rid

    @contextmanager
    def _lookup(self, reference):
        with self._directory() as rootfd:
            require(type(reference) is str and HANDLE.fullmatch(reference) is not None, "E_REF", detail="handle")
            with self._shard(rootfd, reference[:2]) as (shardfd, check):
                yield self._resolve(reference, shardfd, check), shardfd, check

    def _resolve(self, reference, shardfd, check):
        matches = [reference] if len(reference) == 64 else []
        if not matches:
            with os.scandir(shardfd) as entries:
                for entry in entries:
                    name = entry.name
                    if name.startswith(reference) and _record_name(name):
                        matches.append(name[:64])
                        if len(matches) == 2:
                            break
        if len(matches) != 1:
            check()
            raise CodecError("E_REF", detail="resolution")
        info = self._reference(check, os.stat, matches[0] + ".json", follow_symlinks=False, **_at(shardfd))
        require(stat.S_ISREG(info.st_mode), "E_AUTH")
        return matches[0]

    def _read_bytes(self, rid, rootfd, budget=None, expected_size=None):
        fd = self._open(rid + ".json", os.O_RDONLY, rootfd)
        try:
            stream = os.fdopen(fd, "rb", closefd=False)
        except BaseException:
            _release(fd)
            raise
        failed = True
        try:
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
            failed = False
        finally:
            _finish_stream(stream, fd, failed)
        data = b"".join(chunks)
        require(len(data) == before.st_size and hashlib.sha256(data).hexdigest() == rid, "E_HASH")
        return data, len(data)

    def _verified(self, reference, budget, describe=False):
        require(budget is None or type(budget) is Budget, "E_LIMIT")
        with self._lookup(reference) as (rid, shardfd, check):
            data, size = self._reference(check, self._read_bytes, rid, shardfd, budget)
            value = parse(data)
            if not describe:
                return value
            return {"ref": rid[:16], "kind": value["kind"], "chars": size}

    def read(self, reference, *, _budget=None):
        return self._verified(reference, _budget)

    def describe(self, reference, *, _budget=None):
        """Verify actual bytes, canonical encoding and schema on every call."""
        return self._verified(reference, _budget, describe=True)

    def begin_publication(self):
        """Track one write attempt while the caller holds its publication lease."""
        require("rmdir" in {function.__name__ for function in os.supports_dir_fd}, "E_AUTH")
        return _Publication(self)

    @contextmanager
    def grant_directory(self, *, publication=None):
        """Bind the grant directory under the codec root and track any creation."""
        ownership = None
        if publication is not None:
            require(type(publication) is _Publication and publication.store is self and
                    publication.rid is not None, "E_AUTH")
            ownership = publication.grants
        with self._directory() as rootfd, ExitStack() as stack:
            try:
                bound = stack.enter_context(self._shard(rootfd, "grants", create=ownership is not None,
                                                        ownership=ownership))
            except CodecError as error:
                if error.code != "E_REF":
                    raise
                bound = None
            if ownership is not None:
                os.fsync(rootfd)
            yield bound

    def rollback(self, publication):
        """Reclaim only names created by this attempt under the same caller lease."""
        require(type(publication) is _Publication and publication.store is self, "E_AUTH")
        staging = publication.staging_name
        record = publication.record_identity
        if not (publication.shard.created or publication.grants.created) and staging is None and record is None:
            return
        shard, filename = publication.rid[:2], publication.rid + ".json"
        with self._directory() as rootfd:
            if staging is not None or record is not None:
                try:
                    with self._shard(rootfd, shard) as (shardfd, shard_check):
                        opened = os.fstat(shardfd)
                        require((opened.st_dev, opened.st_ino) == publication.shard.identity, "E_AUTH")
                        # Keep the payload if staging cleanup fails.
                        entries = ((staging, publication.staging_identity),
                                   (filename if record is not None else None, record))
                        for name, identity in entries:
                            if name is None:
                                continue
                            try:
                                current = os.stat(name, follow_symlinks=False, **_at(shardfd))
                            except FileNotFoundError:
                                if name != staging:
                                    continue
                            else:
                                require(stat.S_ISREG(current.st_mode) and
                                        (current.st_dev, current.st_ino) == identity, "E_AUTH")
                                os.unlink(name, **_at(shardfd))
                            os.fsync(shardfd)
                            if name == staging:
                                publication.staging_name = None
                except CodecError as error:
                    if error.code != "E_REF":
                        raise
            for name, ownership in ((shard, publication.shard), ("grants", publication.grants)):
                if not ownership.created:
                    continue
                try:
                    current = os.stat(name, follow_symlinks=False, **_at(rootfd))
                    require(stat.S_ISDIR(current.st_mode), "E_AUTH")
                    _private(current)
                    identity = current.st_dev, current.st_ino
                    # mkdir succeeded under the caller's lease. Its first stat may have failed.
                    if ownership.identity is None:
                        ownership.identity = identity
                    require(identity == ownership.identity, "E_AUTH")
                    os.rmdir(name, **_at(rootfd))
                except OSError as error:
                    if error.errno not in (errno.ENOENT, errno.ENOTEMPTY, errno.EEXIST):
                        raise
                else:
                    os.fsync(rootfd)

    def write(self, value, *, publication=None):
        data = canonical(value)
        rid = hashlib.sha256(data).hexdigest()
        ownership = None
        if publication is not None:
            require(type(publication) is _Publication and publication.store is self and
                    publication.rid is None, "E_AUTH")
            publication.rid = rid
            ownership = publication.shard
        with self._directory() as rootfd, self._shard(
                rootfd, rid[:2], create=True, ownership=ownership) as (shardfd, check):
            try:
                require(self._read_bytes(rid, shardfd, expected_size=len(data))[0] == data, "E_HASH")
                return rid
            except FileNotFoundError:
                pass
            # A peer may have just created the shard or failed to sync its name.
            os.fsync(rootfd)
            name, temporary = rid + ".json", ".msg-" + uuid.uuid4().hex
            fd = self._open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, shardfd,
                            publication=publication)
            staged = True
            try:
                try:
                    stream = os.fdopen(fd, "wb", closefd=False)
                except BaseException:
                    _release(fd)
                    raise
                failed = True
                try:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                    failed = False
                finally:
                    _finish_stream(stream, fd, failed)
                check()
                if publication is not None:
                    publication.record_identity = publication.staging_identity
                try:
                    os.link(temporary, name, follow_symlinks=False, **_at(shardfd, "src_dir_fd", "dst_dir_fd"))
                except FileExistsError:
                    # Existing bytes receive exactly the same verification.
                    if publication is not None:
                        publication.record_identity = None
                require(self._read_bytes(rid, shardfd, expected_size=len(data))[0] == data, "E_HASH")
                os.unlink(temporary, **_at(shardfd))
                staged = False
                # Persist the final name and the removal of the staging name together.
                os.fsync(shardfd)
                if publication is not None:
                    publication.staging_name = None
            except BaseException:
                if staged and publication is None:
                    with suppress(OSError):
                        os.unlink(temporary, **_at(shardfd))
                with suppress(OSError):  # Cleanup never replaces the original refusal.
                    os.fsync(shardfd)
                raise
        return rid
