"""Private cached admissions; public callers receive writable copies only."""
from __future__ import annotations

import contextlib as _pra_contextlib
import errno as _pra_errno
import hashlib as _pra_hashlib
import json as _pra_json
import os as _pra_os
from pathlib import Path as _pra_Path
import stat as _pra_stat
import sys as _pra_sys
import time as _pra_time
import unicodedata as _pra_unicode
from types import SimpleNamespace as _pra_Namespace
from typing import Iterator as _pra_Iterator

import pytest as _pra_pytest
from aegis_core.primitives import sanitize_display as _pra_sanitize
from aegis_core.redaction import guidance_value as _pra_guidance

try:
    import fcntl as _pra_fcntl
except ImportError:
    _pra_fcntl = None


_pra_LIMIT = 256 * 1024 * 1024
_pra_FILE_LIMIT = 32 * 1024 * 1024
_pra_SOURCE_LIMIT = 4 * 1024 * 1024
_pra_NODES = 65536
_pra_CASES = tuple((terminal, recipes) for terminal in ("completed", "failed", None)
                   for recipes in ("match", "mismatch", "absent"))
_pra_REFUSAL = "admission fixture unreadable"
_pra_STATE = _pra_pytest.StashKey[object]()


def supported() -> bool:
    return bool(_pra_sys.platform.startswith("linux") and _pra_fcntl is not None
                and hasattr(_pra_os, "O_NOFOLLOW") and hasattr(_pra_os, "O_DIRECTORY")
                and _pra_os.open in _pra_os.supports_dir_fd
                and _pra_os.stat in _pra_os.supports_dir_fd
                and _pra_os.scandir in _pra_os.supports_fd)


def _pra_name(name):
    if (type(name) is not str or not name or len(name) > 255 or name in {".", ".."}
            or "/" in name or "\0" in name or len(_pra_os.fsencode(name)) > 255):
        raise AssertionError(_pra_REFUSAL)
    return name


def _pra_stamp(info):
    return (info.st_dev, info.st_ino, _pra_stat.S_IFMT(info.st_mode),
            _pra_stat.S_IMODE(info.st_mode), info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _pra_close(fd):
    if fd is not None:
        _pra_os.close(fd)


def _pra_dir(parent, name, expected=None):
    _pra_name(name)
    fd = _pra_os.open(name, _pra_os.O_RDONLY | _pra_os.O_DIRECTORY | _pra_os.O_NOFOLLOW
                      | _pra_os.O_CLOEXEC, dir_fd=parent)
    try:
        info = _pra_os.fstat(fd)
        if (not _pra_stat.S_ISDIR(info.st_mode) or not info.st_dev or not info.st_ino
                or expected is not None and (info.st_dev, info.st_ino) != expected):
            raise AssertionError(_pra_REFUSAL)
        return fd
    except BaseException:
        _pra_close(fd)
        raise


def _pra_anchor(root):
    raw = _pra_os.fspath(root)
    if type(raw) is not str or not raw or len(raw) > 4096 or "\0" in raw:
        raise AssertionError(_pra_REFUSAL)
    raw = _pra_os.path.abspath(raw)
    parts = raw.split("/")[1:]
    if len(raw) > 4096 or not parts or len(parts) > 128:
        raise AssertionError(_pra_REFUSAL)
    for name in parts:
        _pra_name(name)
    current = _pra_os.open("/", _pra_os.O_RDONLY | _pra_os.O_DIRECTORY | _pra_os.O_CLOEXEC)
    try:
        for name in parts[:-1]:
            child = _pra_dir(current, name)
            _pra_close(current)
            current = child
        info = _pra_os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        if not _pra_stat.S_ISDIR(info.st_mode):
            raise AssertionError(_pra_REFUSAL)
        return current, parts[-1], (info.st_dev, info.st_ino)
    except BaseException:
        _pra_close(current)
        raise


def _pra_names(fd):
    names = []
    with _pra_os.scandir(fd) as entries:
        for entry in entries:
            if len(names) >= _pra_NODES:
                raise AssertionError(_pra_REFUSAL)
            names.append(_pra_name(entry.name))
    if len(set(names)) != len(names):
        raise AssertionError(_pra_REFUSAL)
    return sorted(names)


def _pra_scan(fd):
    records = {(): ("dir", _pra_stamp(_pra_os.fstat(fd)))}
    budget = {"used": 0}

    def walk(parent, prefix):
        if len(prefix) > 64:
            raise AssertionError(_pra_REFUSAL)
        for name in _pra_names(parent):
            if len(records) >= _pra_NODES:
                raise AssertionError(_pra_REFUSAL)
            parts = prefix + (name,)
            info = _pra_os.stat(name, dir_fd=parent, follow_symlinks=False)
            stamp = _pra_stamp(info)
            if not info.st_dev or not info.st_ino:
                raise AssertionError(_pra_REFUSAL)
            if _pra_stat.S_ISDIR(info.st_mode):
                records[parts] = ("dir", stamp)
                child = _pra_dir(parent, name, stamp[:2])
                try:
                    walk(child, parts)
                finally:
                    _pra_close(child)
            elif _pra_stat.S_ISREG(info.st_mode):
                if info.st_size < 0 or info.st_size > _pra_FILE_LIMIT:
                    raise AssertionError(_pra_REFUSAL)
                budget["used"] += info.st_size
                if budget["used"] > _pra_LIMIT:
                    raise AssertionError(_pra_REFUSAL)
                records[parts] = ("file", stamp)
            elif _pra_stat.S_ISLNK(info.st_mode):
                if info.st_size < 0 or budget["used"] + info.st_size > _pra_LIMIT:
                    raise AssertionError(_pra_REFUSAL)
                target = _pra_os.readlink(name, dir_fd=parent)
                used = len(_pra_os.fsencode(target))
                if used != info.st_size:
                    raise AssertionError(_pra_REFUSAL)
                budget["used"] += used
                records[parts] = ("link", stamp, target)
            else:
                records[parts] = ("other", stamp)
    walk(fd, ())
    return records


def _pra_read(parent, name, expected):
    _pra_name(name)
    size = expected[4]
    if type(size) is not int or not 0 <= size <= _pra_FILE_LIMIT:
        raise AssertionError(_pra_REFUSAL)
    fd = _pra_os.open(name, _pra_os.O_RDONLY | _pra_os.O_NOFOLLOW | _pra_os.O_NONBLOCK
                      | _pra_os.O_CLOEXEC, dir_fd=parent)
    try:
        if _pra_stamp(_pra_os.fstat(fd)) != expected or expected[2] != _pra_stat.S_IFREG:
            raise AssertionError(_pra_REFUSAL)
        chunks, count = [], 0
        while count < size:
            chunk = _pra_os.read(fd, min(1024 * 1024, size - count))
            if not chunk:
                raise AssertionError(_pra_REFUSAL)
            count += len(chunk)
            chunks.append(chunk)
        if _pra_os.read(fd, 1) or _pra_stamp(_pra_os.fstat(fd)) != expected:
            raise AssertionError(_pra_REFUSAL)
        return b"".join(chunks)
    finally:
        _pra_close(fd)


class _pra_SourceError(AssertionError):
    pass


def _pra_source_parts(parts, allow_root=False):
    if type(parts) is not tuple or len(parts) > 64 or not parts and not allow_root:
        raise AssertionError("invalid source path")
    size = 0
    for part in parts:
        _pra_name(part)
        size += len(_pra_os.fsencode(part)) + 1
        if size > 4096:
            raise AssertionError("invalid source path")
    return parts


def _pra_canonical(value, max_len=None):
    return _pra_sanitize(_pra_unicode.normalize("NFKC", value), max_len=max_len)


def source_name(parts) -> str:
    _pra_source_parts(parts, allow_root=True)
    return _pra_guidance("/".join(("tests",) + parts), limit=400, canonicalize=_pra_canonical)


def _pra_source_error(parts):
    try:
        label = source_name(parts)
    except AssertionError:
        label = "tests/[invalid source path]"
    return _pra_SourceError("refused test source: " + label)


@_pra_contextlib.contextmanager
def _pra_source_root(root):
    parent, name, identity = _pra_anchor(root)
    try:
        fd = _pra_dir(parent, name, identity)
    finally:
        _pra_close(parent)
    try:
        yield fd
    finally:
        _pra_close(fd)


def read_source(root, parts) -> str:
    if not supported():
        raise AssertionError("admission descriptors unavailable")
    _pra_source_parts(parts)
    parent = None
    try:
        with _pra_source_root(root) as fd:
            parent = _pra_os.dup(fd)
            for name in parts[:-1]:
                info = _pra_os.stat(name, dir_fd=parent, follow_symlinks=False)
                child = _pra_dir(parent, name, (info.st_dev, info.st_ino))
                _pra_close(parent)
                parent = child
            info = _pra_os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            if not _pra_stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= _pra_SOURCE_LIMIT:
                raise _pra_source_error(parts)
            return _pra_read(parent, parts[-1], _pra_stamp(info)).decode("utf-8")
    except (AssertionError, OSError, UnicodeError):
        raise _pra_source_error(parts) from None
    finally:
        _pra_close(parent)


def _pra_source_inventory(fd):
    headers = {(): ("dir", _pra_stamp(_pra_os.fstat(fd))[:2])}
    budget = {"entries": 0, "bytes": 0}

    def walk(parent, prefix):
        try:
            if len(prefix) > 64:
                raise _pra_source_error(prefix)
            for name in _pra_names(parent):
                parts = prefix + (name,)
                _pra_source_parts(parts)
                budget["entries"] += 1
                if budget["entries"] > _pra_NODES:
                    raise _pra_source_error(parts)
                info = _pra_os.stat(name, dir_fd=parent, follow_symlinks=False)
                if name.endswith(".py"):
                    if not _pra_stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= _pra_SOURCE_LIMIT:
                        raise _pra_source_error(parts)
                    budget["bytes"] += info.st_size
                    if budget["bytes"] > _pra_LIMIT:
                        raise _pra_source_error(parts)
                    headers[parts] = ("file", _pra_stamp(info))
                elif _pra_stat.S_ISDIR(info.st_mode):
                    child = _pra_dir(parent, name, (info.st_dev, info.st_ino))
                    try:
                        headers[parts] = ("dir", (info.st_dev, info.st_ino))
                        walk(child, parts)
                    finally:
                        _pra_close(child)
        except _pra_SourceError:
            raise
        except (AssertionError, OSError):
            raise _pra_source_error(prefix) from None

    walk(fd, ())
    wanted = {()}
    for parts, row in headers.items():
        if row[0] == "file":
            for length in range(1, len(parts) + 1):
                wanted.add(parts[:length])
    return {parts: headers[parts] for parts in wanted}


def source_files(root) -> dict:
    if not supported():
        raise AssertionError("admission descriptors unavailable")
    try:
        with _pra_source_root(root) as fd:
            headers = _pra_source_inventory(fd)
            sources = {}
            for parts, row in headers.items():
                if row[0] == "file":
                    try:
                        sources[parts] = _pra_body(fd, parts, headers).decode("utf-8")
                    except (AssertionError, OSError, UnicodeError):
                        raise _pra_source_error(parts) from None
            if _pra_source_inventory(fd) != headers:
                raise _pra_source_error(())
            return sources
    except _pra_SourceError:
        raise
    except (AssertionError, OSError):
        raise _pra_source_error(()) from None


def _pra_body(root, parts, headers):
    parent, owned = root, []
    try:
        for index, name in enumerate(parts[:-1], 1):
            parent = _pra_dir(parent, name, headers[parts[:index]][1][:2])
            owned.append(parent)
        return _pra_read(parent, parts[-1], headers[parts][1])
    finally:
        for fd in reversed(owned):
            _pra_close(fd)


def _pra_snapshot(parent, name, identity):
    root = _pra_dir(parent, name, identity)
    try:
        headers = _pra_scan(root)
        bodies = {parts: _pra_body(root, parts, headers) for parts, row in headers.items() if row[0] == "file"}
    finally:
        _pra_close(root)
    final = _pra_dir(parent, name, identity)
    try:
        if _pra_scan(final) != headers:
            raise AssertionError(_pra_REFUSAL)
        for parts, payload in bodies.items():
            if _pra_body(final, parts, headers) != payload:
                raise AssertionError(_pra_REFUSAL)
        if _pra_scan(final) != headers:
            raise AssertionError(_pra_REFUSAL)
    finally:
        _pra_close(final)
    return {parts: row + ((bodies[parts],) if row[0] == "file" else ()) for parts, row in headers.items()}


def typed_snapshot(root) -> dict:
    if not supported():
        raise AssertionError("admission descriptors unavailable")
    parent = None
    try:
        parent, name, identity = _pra_anchor(root)
        return _pra_snapshot(parent, name, identity)
    except (OSError, ValueError, TypeError):
        raise AssertionError(_pra_REFUSAL) from None
    finally:
        _pra_close(parent)


def assert_copy_unchanged(root, before, surface) -> None:
    token = _pra_surface(surface)
    try:
        if typed_snapshot(root) != before:
            raise AssertionError(_pra_REFUSAL)
    except AssertionError:
        raise AssertionError("probe " + token + " mutated retained fixture bytes") from None


def _pra_surface(surface):
    if surface not in {"api", "cli-before", "cli-after", "copy-only", "master-write"}:
        raise AssertionError("invalid admission probe surface")
    return surface


def _pra_key(terminal, recipes):
    if (terminal, recipes) not in _pra_CASES:
        raise AssertionError("invalid admission scenario")
    return {None: "unsettled", "completed": "finished", "failed": "failed"}[terminal] + "-" + recipes


def _pra_mkdir(parent, name):
    _pra_name(name)
    try:
        _pra_os.mkdir(name, 0o700, dir_fd=parent)
    except FileExistsError:
        pass
    return _pra_dir(parent, name)


def _pra_cleanup_enter(parent, name):
    _pra_name(name)
    try:
        info = _pra_os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not _pra_stat.S_ISDIR(info.st_mode):
        _pra_os.unlink(name, dir_fd=parent)
        return None
    fd = None
    try:
        try:
            fd = _pra_dir(parent, name, (info.st_dev, info.st_ino))
        except PermissionError:
            if not hasattr(_pra_os, "O_PATH"):
                raise AssertionError(_pra_REFUSAL)
            raw = _pra_os.open(name, _pra_os.O_PATH | _pra_os.O_DIRECTORY | _pra_os.O_NOFOLLOW, dir_fd=parent)
            try:
                if _pra_stamp(_pra_os.fstat(raw))[:2] != (info.st_dev, info.st_ino):
                    raise AssertionError(_pra_REFUSAL)
                _pra_os.chmod("/proc/self/fd/" + str(raw), 0o700)
            finally:
                _pra_close(raw)
            fd = _pra_dir(parent, name, (info.st_dev, info.st_ino))
        _pra_os.fchmod(fd, 0o700)
        return fd
    except OSError as error:
        _pra_close(fd)
        if error.errno in {_pra_errno.ELOOP, _pra_errno.ENOTDIR}:
            fresh = _pra_os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not _pra_stat.S_ISDIR(fresh.st_mode):
                _pra_os.unlink(name, dir_fd=parent)
                return None
        raise
    except BaseException:
        _pra_close(fd)
        raise


def _pra_cleanup_batch(fd):
    # A fresh description starts enumeration at the beginning after deletions.
    opened = _pra_os.open(".", _pra_os.O_RDONLY | _pra_os.O_DIRECTORY | _pra_os.O_NOFOLLOW
                          | _pra_os.O_CLOEXEC, dir_fd=fd)
    try:
        if _pra_stamp(_pra_os.fstat(opened))[:2] != _pra_stamp(_pra_os.fstat(fd))[:2]:
            raise AssertionError(_pra_REFUSAL)
        names = []
        with _pra_os.scandir(opened) as entries:
            for entry in entries:
                names.append(_pra_name(entry.name))
                if len(names) == 64:
                    break
        return names
    finally:
        _pra_close(opened)


def _pra_remove(parent, name):
    _pra_name(name)
    current, following = None, None
    try:
        parent_info = _pra_os.fstat(parent)
        if not _pra_stat.S_ISDIR(parent_info.st_mode):
            raise AssertionError(_pra_REFUSAL)
        current = _pra_cleanup_enter(parent, name)
        if current is None:
            return
        frames = [(name, _pra_stamp(_pra_os.fstat(current))[:2],
                   (parent_info.st_dev, parent_info.st_ino))]
        while frames:
            batch = _pra_cleanup_batch(current)
            if batch:
                for child in batch:
                    following = _pra_cleanup_enter(current, child)
                    if following is not None:
                        frames.append((child, _pra_stamp(_pra_os.fstat(following))[:2],
                                       _pra_stamp(_pra_os.fstat(current))[:2]))
                        _pra_close(current)
                        current, following = following, None
                        break
                continue
            leaf, identity, parent_identity = frames[-1]
            following = (_pra_os.dup(parent) if len(frames) == 1 else
                         _pra_os.open("..", _pra_os.O_RDONLY | _pra_os.O_DIRECTORY | _pra_os.O_NOFOLLOW
                                      | _pra_os.O_CLOEXEC, dir_fd=current))
            info = _pra_os.fstat(following)
            if not _pra_stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != parent_identity:
                raise AssertionError(_pra_REFUSAL)
            try:
                fresh = _pra_os.stat(leaf, dir_fd=following, follow_symlinks=False)
            except FileNotFoundError:
                fresh = None
            if fresh is not None:
                if _pra_stat.S_ISDIR(fresh.st_mode):
                    if (fresh.st_dev, fresh.st_ino) != identity:
                        raise AssertionError(_pra_REFUSAL)
                    try:
                        _pra_os.rmdir(leaf, dir_fd=following)
                    except OSError as error:
                        if error.errno == _pra_errno.ENOTEMPTY:
                            _pra_close(following)
                            following = None
                            continue
                        raise
                else:
                    _pra_os.unlink(leaf, dir_fd=following)
            _pra_close(current)
            frames.pop()
            current, following = following, None
    except OSError:
        raise AssertionError(_pra_REFUSAL) from None
    finally:
        _pra_close(following)
        _pra_close(current)


def _pra_write(parent, name, data, mode=0o600):
    _pra_name(name)
    if type(data) is not bytes or len(data) > _pra_FILE_LIMIT:
        raise AssertionError(_pra_REFUSAL)
    fd = _pra_os.open(name, _pra_os.O_CREAT | _pra_os.O_EXCL | _pra_os.O_WRONLY
                      | _pra_os.O_NOFOLLOW | _pra_os.O_CLOEXEC, mode, dir_fd=parent)
    try:
        view = memoryview(data)
        while view:
            count = _pra_os.write(fd, view)
            if count <= 0:
                raise AssertionError(_pra_REFUSAL)
            view = view[count:]
        _pra_os.fchmod(fd, mode)
        expected = _pra_stamp(_pra_os.fstat(fd))
    finally:
        _pra_close(fd)
    if _pra_read(parent, name, expected) != data:
        raise AssertionError(_pra_REFUSAL)


def _pra_materialize(parent, name, records):
    _pra_remove(parent, name)
    root = _pra_mkdir(parent, name)
    directories = {(): root}
    try:
        for parts, row in sorted(records.items(), key=lambda item: (len(item[0]), item[0])):
            if not parts:
                continue
            target, leaf = directories[parts[:-1]], parts[-1]
            if row[0] == "dir":
                directories[parts] = _pra_mkdir(target, leaf)
            elif row[0] == "file":
                _pra_write(target, leaf, row[2], row[1][3] | 0o200)
            elif row[0] == "link":
                _pra_os.symlink(row[2], leaf, dir_fd=target)
            else:
                raise AssertionError(_pra_REFUSAL)
    finally:
        for fd in reversed(list(directories.values())):
            _pra_close(fd)


def _pra_freeze(parent, name):
    root = _pra_dir(parent, name)
    try:
        def freeze(fd):
            for child in _pra_names(fd):
                info = _pra_os.stat(child, dir_fd=fd, follow_symlinks=False)
                if _pra_stat.S_ISDIR(info.st_mode):
                    opened = _pra_dir(fd, child, (info.st_dev, info.st_ino))
                    try:
                        freeze(opened)
                    finally:
                        _pra_close(opened)
                elif _pra_stat.S_ISREG(info.st_mode):
                    opened = _pra_os.open(child, _pra_os.O_RDONLY | _pra_os.O_NOFOLLOW | _pra_os.O_CLOEXEC, dir_fd=fd)
                    try:
                        if _pra_stamp(_pra_os.fstat(opened)) != _pra_stamp(info):
                            raise AssertionError(_pra_REFUSAL)
                        _pra_os.fchmod(opened, _pra_stat.S_IMODE(info.st_mode) & ~0o222)
                    finally:
                        _pra_close(opened)
            _pra_os.fchmod(fd, _pra_stat.S_IMODE(_pra_os.fstat(fd).st_mode) & ~0o222)
        freeze(root)
    finally:
        _pra_close(root)


@_pra_contextlib.contextmanager
def _pra_lock(parent, name):
    fd = _pra_os.open(_pra_name(name), _pra_os.O_CREAT | _pra_os.O_RDWR | _pra_os.O_NOFOLLOW
                      | _pra_os.O_CLOEXEC, 0o600, dir_fd=parent)
    try:
        if not _pra_stat.S_ISREG(_pra_os.fstat(fd).st_mode):
            raise AssertionError(_pra_REFUSAL)
        deadline = _pra_time.monotonic() + 120
        while True:
            try:
                _pra_fcntl.flock(fd, _pra_fcntl.LOCK_EX | _pra_fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if _pra_time.monotonic() >= deadline:
                    raise AssertionError("admission fixture lock unavailable") from None
                _pra_time.sleep(0.05)
        try:
            yield
        finally:
            _pra_fcntl.flock(fd, _pra_fcntl.LOCK_UN)
    finally:
        _pra_close(fd)


def _pra_digest(records):
    return _pra_hashlib.sha256(repr(sorted(records.items())).encode("utf-8")).hexdigest()


def _pra_metrics():
    return {"build": 0.0, "copy": 0.0, "probe_verify": 0.0, "session_verify": 0.0, "build_count": 0}


def _pra_ready(parent, key):
    name = _pra_name("_pra_ready-" + key + ".json")
    info = _pra_os.stat(name, dir_fd=parent, follow_symlinks=False)
    if not 0 <= info.st_size <= 1024:
        raise AssertionError(_pra_REFUSAL)
    value = _pra_json.loads(_pra_read(parent, name, _pra_stamp(info)))
    if (type(value) is not dict or set(value) != {"digest", "identity"}
            or type(value["digest"]) is not str or len(value["digest"]) != 64
            or any(c not in "0123456789abcdef" for c in value["digest"])
            or type(value["identity"]) is not list or len(value["identity"]) != 2
            or any(type(part) is not int or part <= 0 for part in value["identity"])):
        raise AssertionError(_pra_REFUSAL)
    return value


def _pra_verify_master(parent, key, expected, surface=None):
    try:
        slot = _pra_dir(parent, key)
        try:
            records = _pra_snapshot(slot, "_pra_master", tuple(expected["identity"]))
            if _pra_digest(records) != expected["digest"]:
                raise AssertionError(_pra_REFUSAL)
        finally:
            _pra_close(slot)
    except (AssertionError, OSError):
        if surface is None:
            raise AssertionError("cached master " + key + " changed at session teardown") from None
        raise AssertionError("probe " + surface + " mutated cached master") from None


class _pra_Cache:
    def __init__(self, root, fd, seed):
        self._pra_root = root
        self._pra_fd = fd
        self._pra_seed = seed
        self._pra_expected = {}
        self._pra_metrics = _pra_metrics()

    def _pra_prepare(self, slot, terminal, recipes):
        key = _pra_key(terminal, recipes)
        try:
            expected = _pra_ready(self._pra_fd, key)
        except FileNotFoundError:
            from tests.integration.test_hierarchy_jobs import Shop
            from tests.integration.test_hierarchy_jobs_followups import recovery_admission_case

            started = _pra_time.perf_counter()
            _pra_remove(slot, "copy")
            live = _pra_mkdir(slot, "copy")
            _pra_close(live)
            shop = Shop(self._pra_root / key / "copy", source_seed=self._pra_seed)
            recovery_admission_case(shop, terminal)
            if recipes == "mismatch":
                shop.recipes["recipes"]["ok"]["timeout_seconds"] += 1
                shop.save_recipes()
            info = _pra_os.stat("copy", dir_fd=slot, follow_symlinks=False)
            records = _pra_snapshot(slot, "copy", (info.st_dev, info.st_ino))
            _pra_materialize(slot, "_pra_master", records)
            _pra_freeze(slot, "_pra_master")
            info = _pra_os.stat("_pra_master", dir_fd=slot, follow_symlinks=False)
            expected = {"identity": [info.st_dev, info.st_ino], "digest":
                        _pra_digest(_pra_snapshot(slot, "_pra_master", (info.st_dev, info.st_ino)))}
            _pra_write(self._pra_fd, "_pra_ready-" + key + ".json",
                       _pra_json.dumps(expected).encode("utf-8"), 0o400)
            self._pra_metrics["build"] += _pra_time.perf_counter() - started
            self._pra_metrics["build_count"] += 1
        self._pra_expected[key] = expected

    def _pra_verify(self, key, surface):
        started = _pra_time.perf_counter()
        try:
            _pra_verify_master(self._pra_fd, key, self._pra_expected[key], surface)
        finally:
            self._pra_metrics["probe_verify"] += _pra_time.perf_counter() - started


@_pra_pytest.fixture(scope="session")
def _pra_session(tmp_path_factory, request):
    if not supported():
        _pra_pytest.skip("admission cache requires Linux descriptor support")
    from tests.integration.test_hierarchy_provision import worker_source_seed

    base = tmp_path_factory.getbasetemp()
    run = base.parent if hasattr(request.config, "workerinput") else base
    parent, name, identity = _pra_anchor(run)
    try:
        run_fd = _pra_dir(parent, name, identity)
    finally:
        _pra_close(parent)
    cache_fd = None
    try:
        cache_fd = _pra_mkdir(run_fd, "provider-admissions")
        root = run / "provider-admissions"
        cache = _pra_Cache(root, cache_fd, worker_source_seed(tmp_path_factory, request))
        request.config.stash[_pra_STATE] = _pra_Namespace(run=run, metrics=cache._pra_metrics)
        yield cache
    finally:
        _pra_close(cache_fd)
        _pra_close(run_fd)


class _pra_Copy(_pra_Namespace):
    pass


@_pra_pytest.fixture
def _pra_scenario(_pra_session, request):
    params = request.node.callspec.params
    key = _pra_key(params["terminal"], params["recipes"])
    surface = _pra_surface(params["surface"])
    cache = _pra_session
    with _pra_lock(cache._pra_fd, key + ".lock"):
        slot = _pra_mkdir(cache._pra_fd, key)
        try:
            cache._pra_prepare(slot, params["terminal"], params["recipes"])
            yield _pra_Namespace(cache=cache, key=key, slot=slot, surface=surface)
        finally:
            _pra_close(slot)


@_pra_pytest.fixture
def planned_admission(_pra_scenario) -> _pra_Iterator[_pra_Copy]:
    context = _pra_scenario
    cache, key = context.cache, context.key
    try:
        started = _pra_time.perf_counter()
        expected = cache._pra_expected[key]
        records = _pra_snapshot(context.slot, "_pra_master", tuple(expected["identity"]))
        if _pra_digest(records) != expected["digest"]:
            raise AssertionError(_pra_REFUSAL)
        _pra_materialize(context.slot, "copy", records)
        cache._pra_metrics["copy"] += _pra_time.perf_counter() - started
        live = cache._pra_root / key / "copy"
        yield _pra_Copy(root=live, store=live / "store", recipes_path=live / "recipes.json")
    finally:
        cache._pra_verify(key, context.surface)


def _pra_finish(session):
    config = session.config
    state = config.stash.get(_pra_STATE, None)
    if hasattr(config, "workerinput"):
        worker = config.workerinput["workerid"]
        count = config.workerinput["workercount"]
        run = _pra_Path(config.option.basetemp).parent
        if (type(worker) is not str or not worker.startswith("gw") or len(worker) > 16
                or not worker[2:].isdigit() or type(count) is not int or not 1 <= count <= 1024):
            raise AssertionError(_pra_REFUSAL)
    else:
        if state is None:
            return []
        worker, count, run = "master", 1, state.run
    metrics = state.metrics if state is not None else _pra_metrics()
    parent, name, identity = _pra_anchor(run)
    try:
        run_fd = _pra_dir(parent, name, identity)
    finally:
        _pra_close(parent)
    cache_fd = None
    try:
        cache_fd = _pra_mkdir(run_fd, "provider-admissions")
        with _pra_lock(cache_fd, "_pra_finish.lock"):
            _pra_write(cache_fd, "_pra_finished-" + worker, b"finished")
            completed = [entry for entry in _pra_names(cache_fd) if entry.startswith("_pra_finished-")]
            failures, checked = [], []
            if len(completed) == count:
                started = _pra_time.perf_counter()
                for terminal, recipes in _pra_CASES:
                    key = _pra_key(terminal, recipes)
                    try:
                        expected = _pra_ready(cache_fd, key)
                    except FileNotFoundError:
                        continue
                    except (AssertionError, OSError, ValueError):
                        failures.append("cached master " + key + " changed at session teardown")
                        continue
                    checked.append(key)
                    try:
                        _pra_verify_master(cache_fd, key, expected)
                    except AssertionError as error:
                        failures.append(str(error))
                metrics["session_verify"] += _pra_time.perf_counter() - started
                _pra_write(cache_fd, "_pra_verified.json", _pra_json.dumps(checked).encode("utf-8"))
            _pra_write(cache_fd, "_pra_stats-" + worker + ".json", _pra_json.dumps(metrics).encode("utf-8"))
            return failures
    finally:
        _pra_close(cache_fd)
        _pra_close(run_fd)


class _pra_Hooks:
    @_pra_pytest.hookimpl(trylast=True)
    def pytest_sessionfinish(self, session, exitstatus):
        if not supported():
            return
        try:
            failures = _pra_finish(session)
        except (AssertionError, OSError, ValueError):
            failures = ["admission session verification unavailable"]
        for message in failures:
            item = session.items[-1]
            report = _pra_pytest.TestReport(nodeid=item.nodeid, location=item.location, keywords={},
                                           outcome="failed", longrepr=message, when="teardown")
            session.config.hook.pytest_runtest_logreport(report=report)
            session.exitstatus = _pra_pytest.ExitCode.TESTS_FAILED


def pytest_configure(config) -> None:
    if not config.pluginmanager.hasplugin("_pra_admission_lifecycle"):
        config.pluginmanager.register(_pra_Hooks(), "_pra_admission_lifecycle")


PUBLIC_SIGNATURES = (
    ("source_name", (("parts", "pos", None, None),), "str", "none"),
    ("read_source", (("root", "pos", None, None), ("parts", "pos", None, None)), "str", "none"),
    ("source_files", (("root", "pos", None, None),), "dict", "none"),
    ("pytest_configure", (("config", "pos", None, None),), "None", "none"),
    ("supported", (), "bool", "none"),
    ("typed_snapshot", (("root", "pos", None, None),), "dict", "none"),
    ("assert_copy_unchanged", (("root", "pos", None, None), ("before", "pos", None, None),
                              ("surface", "pos", None, None)), "None", "none"),
    ("planned_admission", (("_pra_scenario", "pos", None, None),),
     "_pra_Iterator[_pra_Copy]", "fresh copy only"),
)
