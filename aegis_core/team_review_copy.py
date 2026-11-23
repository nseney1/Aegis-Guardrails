"""Exact review copies using injected Git policy and held directory descriptors."""
from __future__ import annotations

import errno
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
import stat
import time
from types import SimpleNamespace
import uuid

from aegis_core import gitsafe, gitsafe_run, storage_confined
from aegis_core.git_path_codec import path_text
from aegis_core.primitives import sanitize_display
from aegis_core.redaction import redact_insight_text
from aegis_core.team_review_files import strict_json as _strict_json
__all__ = [
    "MAX_DIFF_BYTES", "MAX_ENTRIES", "MAX_HEADER_BYTES", "MAX_LISTING_BYTES", "MAX_LOG_BYTES",
    "MAX_MANIFEST_BYTES", "MAX_OBJECT_BYTES", "MAX_PATH_BYTES", "MAX_PROBLEMS", "MAX_SIDE_BYTES",
    "ReviewRefusal", "descriptor_support", "prepare", "remove", "verify",
]

SCHEMA = "aegis.hierarchy-review/v1"
SIDES = ("base", "candidate")
GIT_TIMEOUT_SECONDS = 300
SCAFFOLD_TIMEOUT_SECONDS = 60
CHUNK_BYTES = 1048576
MAX_PROBLEMS = 100
MAX_OBJECT_BYTES = 64 * 1024 * 1024
MAX_SIDE_BYTES = 512 * 1024 * 1024
MAX_LISTING_BYTES = 16 * 1024 * 1024
MAX_DIFF_BYTES = 32 * 1024 * 1024
MAX_LOG_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 10000
MAX_PATH_BYTES = 4096
MAX_MANIFEST_BYTES = 262144
MAX_HEADER_BYTES = 256
MAX_WALK_DEPTH = 128
_HEX = "0123456789abcdef"
_BREAKS = "\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029"
_KNOWN = {"manifest.json", "changes.diff", "commits.txt", ".git", "base", "candidate",
          "base.files.jsonl", "candidate.files.jsonl"}
MEANING = ("Exact committed bytes. A symlink is a plain file holding its target, and a submodule is listed but not followed. "
           "Run verify before relying on this folder; read-only modes alone prove nothing.")
_NEXT = {
    "port_required": "Supply the Git ports and the spawn port's validated absolute executable.",
    "record_required": "Pass an existing owner-private preparation directory outside the repository and copy.",
    "unsupported_platform": "Use a platform with directory descriptors and no-follow opens.",
    "invalid_input": "Pass the documented argument types and retry.",
    "unsafe_path": "Pass an absolute path with no symlink component and no parent traversal.",
    "inside_repository": "Choose an output folder outside the repository.",
    "output_exists": "Choose a path that does not already exist.",
    "not_repository": "Choose a local Git repository that contains both commits.",
    "invalid_commit": "Pass 40-character lowercase hexadecimal commit ids.",
    "commit_missing": "Choose commits that exist in this repository and retry.",
    "tree_unreadable": "Retry when the commit trees can be listed locally.",
    "tree_mismatch": "Retry with the tree ids recorded for these commits.",
    "unsafe_tree_path": "Refuse this tree; it contains a path the copy will not create.",
    "unsupported_entry": "Refuse this tree; it contains an entry kind the copy does not export.",
    "object_missing": "Retry with commits whose objects are already present; the copy does not fetch.",
    "object_truncated": "Retry the export; an object stream ended before its declared size.",
    "export_failed": "Retry the export when local object reads succeed.",
    "diff_failed": "Retry when the local diff of the two commits succeeds.",
    "log_failed": "Retry when the local log of the two commits succeeds.",
    "scaffold_failed": "Retry when an empty Git directory can be created for the copy.",
    "limit_exceeded": "Reduce the tree to the documented byte and entry limits and retry.",
    "filesystem": "Retry when the output filesystem accepts the copy.",
    "encoding": "Retry with paths and objects that decode as the documented encodings.",
    "recursion": "Refuse this tree; its nesting exceeds the documented depth.",
    "manifest_shape": "Refuse this folder; its manifest is not a review copy record.",
    "not_review_copy": "Choose a folder created by prepare, or leave an unrelated folder untouched.",
    "git_timeout": "Retry the local Git read within the documented time limit.",
    "git_failed": "Retry when the local Git read finishes without an internal error.",
    "multiline_field": "Refuse text that contains a line break; review fields stay single-line.",
    "copy_differs": "Inspect the named side and problem, then prepare a fresh copy.",
}
class ReviewRefusal(Exception):
    """Typed refusal. The message is the stable code and never includes caller input."""

    def __init__(self, reason, side=None):
        self.reason = reason if side is None else side + " " + reason
        self.code = reason
        self.next_action = _NEXT[reason]
        super().__init__(reason)

    def as_dict(self):
        return {"reason": self.reason, "code": self.code, "next_action": self.next_action}

def _refusal_envelope(reason):
    return {"reason": reason, "code": reason, "next_action": _NEXT[reason]}

def _guard(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ReviewRefusal as refusal:
            return 2, refusal.as_dict()
        except Exception as error:
            for kind, code in ((TimeoutError, "git_timeout"), (RecursionError, "recursion"),
                               (UnicodeError, "encoding"), (OSError, "filesystem"),
                               (KeyError, "manifest_shape"), (ValueError, "invalid_input")):
                if isinstance(error, kind):
                    return 2, _refusal_envelope(code)
            return 2, _refusal_envelope("git_timeout" if type(error).__name__ == "TimeoutExpired" else "git_failed")
    return call

def descriptor_support():
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        return False
    directory = os.supports_dir_fd
    return (os.open in directory and os.stat in directory and os.rename in directory
            and os.unlink in directory and os.mkdir in directory and os.rmdir in directory
            and os.readlink in directory and os.scandir in os.supports_fd)

def _broken(text):
    return any(char in text for char in _BREAKS)
def _single_line(text):
    if type(text) is not str or _broken(text):
        raise ReviewRefusal("multiline_field")
    canonical = sanitize_display(text, max_len=None)
    if type(canonical) is not str or _broken(canonical):
        raise ReviewRefusal("multiline_field")
    redacted = redact_insight_text(canonical, max_len=8 * max(len(canonical), 1))
    if type(redacted) is not str or _broken(redacted):
        raise ReviewRefusal("multiline_field")
    return sanitize_display(redacted, max_len=200)
def _commit_text(value, *, optional=False):
    if optional and value is None:
        return None
    if type(value) is not str or len(value) != 40 or any(char not in _HEX for char in value):
        raise ReviewRefusal("tree_mismatch" if optional else "invalid_commit")
    return value
def _absolute_path(value, refusal="unsafe_path", *, outside=None):
    if type(value) is not str or not value or len(value) > MAX_PATH_BYTES or "\0" in value or _broken(value):
        raise ReviewRefusal(refusal)
    path = Path(value)
    if not path.is_absolute() or path.anchor != os.sep or not path.parts or path.parts[0] != path.anchor:
        raise ReviewRefusal(refusal)
    if ".." in path.parts or len(path.parts) > MAX_WALK_DEPTH or len(os.fsencode(value)) > MAX_PATH_BYTES:
        raise ReviewRefusal(refusal)
    _refuse_inside(path, outside, refusal)
    return path
def _close(fd):
    if isinstance(fd, int) and fd >= 0:
        os.close(fd)
@contextmanager
def _held(fd):
    try:
        yield fd
    finally:
        os.close(fd)
def _claim(fd):
    try:
        os.set_inheritable(fd, False)
    except BaseException:
        os.close(fd)
        raise
    return fd
def _open_root(path):
    return _claim(os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)))
def _open_directory(name, dir_fd):
    return _claim(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=dir_fd))
def _open_readonly(name, dir_fd):
    return _claim(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=dir_fd))
def _create_file(name, dir_fd):
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o644, dir_fd=dir_fd)
    except FileExistsError:
        raise ReviewRefusal("unsafe_tree_path") from None
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR, errno.EEXIST):
            raise ReviewRefusal("unsafe_tree_path") from None
        raise
    return _claim(fd)
def _rename_at(src_dir_fd, src, dst_dir_fd, dst):
    try:
        os.rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)
    except OSError as error:
        if error.errno in (errno.EEXIST, errno.ENOTEMPTY, errno.ENOTDIR):
            raise ReviewRefusal("output_exists") from None
        raise
def _raise_walk(error, missing):
    if isinstance(error, FileNotFoundError):
        raise ReviewRefusal(missing) from None
    if error.errno in (errno.ELOOP, errno.ENOTDIR, errno.ENAMETOOLONG, errno.EEXIST):
        raise ReviewRefusal("unsafe_path") from None
    raise error
def _walk(path, missing, *, inspect=None):
    fd = _open_root(path.anchor)
    try:
        for depth, part in enumerate(path.parts[1:], 1):
            if inspect is not None:
                inspect(fd, depth)
            try:
                child = _open_directory(part, fd)
            except OSError as error:
                if missing is None and isinstance(error, FileNotFoundError):
                    return None
                _raise_walk(error, missing or "unsafe_path")
            parent, fd = fd, child
            os.close(parent)
        if inspect is not None:
            inspect(fd, len(path.parts))
        kept = fd
        fd = -1
        return kept
    finally:
        _close(fd)
@contextmanager
def _output_parent(path):
    fds, created = [_open_root(path.anchor)], []
    try:
        for part in path.parts[1:]:
            parent = fds[-1]
            try:
                child = _open_directory(part, parent)
            except FileNotFoundError:
                try:
                    os.mkdir(part, 0o755, dir_fd=parent)
                except FileExistsError:
                    pass  # A concurrent prepare can create the same parent.
                else:
                    created.append((parent, part, os.stat(part, dir_fd=parent, follow_symlinks=False)))
                try:
                    child = _open_directory(part, parent)
                except OSError as error:
                    _raise_walk(error, "unsafe_path")
            except OSError as error:
                _raise_walk(error, "unsafe_path")
            fds.append(child)
        yield fds[-1]
    except BaseException:
        for parent, part, original in reversed(created):
            try:
                observed = os.stat(part, dir_fd=parent, follow_symlinks=False)
                if os.path.samestat(original, observed):
                    os.rmdir(part, dir_fd=parent)
            except OSError as error:
                if error.errno not in (errno.ENOENT, errno.ENOTEMPTY, errno.EEXIST):
                    raise
        raise
    finally:
        for fd in reversed(fds):
            os.close(fd)
def _fd_chunks(fd, size):
    left = size
    while left:
        chunk = os.read(fd, min(CHUNK_BYTES, left))
        if not chunk:
            raise ReviewRefusal("filesystem")
        yield chunk
        left -= len(chunk)
    if os.read(fd, 1):
        raise ReviewRefusal("filesystem")
def _write_full(fd, data):
    view = memoryview(data)
    while len(view):
        wrote = os.write(fd, view)
        if wrote <= 0:
            raise ReviewRefusal("filesystem")
        view = view[wrote:]
def _digest_at(dir_fd, name):
    with _held(_open_readonly(name, dir_fd)) as fd:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ReviewRefusal("unsafe_path")
        size = info.st_size
        if size > MAX_OBJECT_BYTES:
            raise ReviewRefusal("limit_exceeded")
        digest = hashlib.sha256()
        for chunk in _fd_chunks(fd, size):
            digest.update(chunk)
        return digest.hexdigest()
def _bounded_chunks(process, limit):
    while True:
        want = min(CHUNK_BYTES, limit + 1)
        chunk = process.read(want)[:want]
        if not chunk:
            return
        if len(chunk) > limit:
            killer = getattr(process, "kill", None)
            if callable(killer):
                killer()
            raise ReviewRefusal("limit_exceeded")
        limit -= len(chunk)
        yield chunk
def _command(repository, argv, env, spawn, timeout, limit):
    process = spawn(repository, argv, env, timeout)
    try:
        process.close_stdin()
        data = b"".join(_bounded_chunks(process, limit))
        return process.wait(timeout), data
    finally:
        process.close()
def _object_environment(ports, planned):
    _, env_fn, child, _, _ = ports
    env = env_fn()
    return child(env, "no-host") if planned is not False else env
def _invoke(ports, planned, arguments):
    argv_fn, _, _, spawn, program = ports
    env = _object_environment(ports, planned)
    argv = argv_fn(*arguments)
    if type(env) is not dict or type(argv) not in (list, tuple) or any(type(item) is not str for item in argv):
        raise ReviewRefusal("port_required")
    return [program, *argv], env, spawn
def _git(repository, arguments, ports, planned, limit):
    argv, env, spawn = _invoke(ports, planned, arguments)
    return _command(repository, argv, env, spawn, GIT_TIMEOUT_SECONDS, limit)
def _object_id(raw, reason, side):
    raw = raw.removesuffix(b"\n")
    if len(raw) != 40 or any(byte not in b"0123456789abcdef" for byte in raw):
        raise ReviewRefusal(reason, side)
    return raw.decode("ascii")
def _exact_side(repository, side, commit, expected, ports, planned):
    code, raw = _git(repository, ("rev-parse", "--verify", "-q", commit + "^{commit}"), ports, planned, 128)
    if code != 0 or _object_id(raw, "commit_missing", side) != commit:
        raise ReviewRefusal("commit_missing", side)
    code, raw = _git(repository, ("rev-parse", commit + "^{tree}"), ports, planned, 128)
    if code != 0:
        raise ReviewRefusal("tree_unreadable", side)
    tree = _object_id(raw, "tree_unreadable", side)
    if expected is not None and tree != expected:
        raise ReviewRefusal("tree_mismatch", side)
    return {"commit": commit, "tree": tree}
def _repository_top(repository, ports, planned):
    code, raw = _git(repository, ("rev-parse", "--show-toplevel"), ports, planned, MAX_PATH_BYTES)
    try:
        # Command framing removes one LF. Path validation rejects remaining line breaks.
        top = _absolute_path(path_text(raw)) if code == 0 else None
    except gitsafe.GitError as error:
        raise ReviewRefusal("encoding" if error.code == "git_path_encoding" else "unsafe_path") from None
    code, _raw = _git(repository, ("rev-parse", "--git-dir"), ports, planned, MAX_PATH_BYTES)
    if code != 0:
        raise ReviewRefusal("not_repository")
    return top
def _refuse_inside(dest, top, refusal="inside_repository"):
    if top is not None and dest.is_relative_to(top):
        raise ReviewRefusal(refusal)
def _check_tree_path(path):
    if _broken(path):
        raise ReviewRefusal("multiline_field")
    encoded = os.fsencode(path)
    if len(encoded) > MAX_PATH_BYTES or b"\0" in encoded or path.startswith("/") or path.startswith("\\"):
        raise ReviewRefusal("unsafe_tree_path")
    # The stage is depth zero and the side is its first directory.
    if 1 + path.count("/") > MAX_WALK_DEPTH:
        raise ReviewRefusal("limit_exceeded")
    parts = path.split("/")
    if not parts or any(part in ("", ".", "..") or part.lower() == ".git" or len(os.fsencode(part)) > 255 for part in parts):
        raise ReviewRefusal("unsafe_tree_path")
def _parse_listing(raw):
    entries = []
    for row in _records(raw, b"\0", MAX_HEADER_BYTES + MAX_PATH_BYTES + 1):
        if not row:
            continue
        if len(entries) >= MAX_ENTRIES:
            raise ReviewRefusal("limit_exceeded")
        head, tab, name = row.partition(b"\t")
        if tab != b"\t":
            raise ReviewRefusal("tree_unreadable")
        if len(head) > MAX_HEADER_BYTES or len(name) > MAX_PATH_BYTES:
            raise ReviewRefusal("limit_exceeded")
        try:
            pieces = head.decode("ascii").split(" ")
            path = os.fsdecode(name)
        except UnicodeError:
            raise ReviewRefusal("encoding") from None
        if len(pieces) != 3 or not pieces[0].isdigit() or not 4 <= len(pieces[0]) <= 6:
            raise ReviewRefusal("tree_unreadable")
        mode, kind, oid = pieces
        if len(oid) != 40 or any(char not in _HEX for char in oid):
            raise ReviewRefusal("tree_unreadable")
        if kind not in ("blob", "commit"):
            raise ReviewRefusal("unsupported_entry")
        _check_tree_path(path)
        entries.append((mode, kind, oid, path))
    return entries
def _side_entries(repository, commit, ports, planned):
    code, raw = _git(repository, ("ls-tree", "-r", "-z", "--full-tree", commit), ports, planned, MAX_LISTING_BYTES)
    if code != 0:
        raise ReviewRefusal("tree_unreadable")
    return _parse_listing(raw)
def _mkdir_open(dir_fd, name):
    try:
        os.mkdir(name, 0o755, dir_fd=dir_fd)
    except FileExistsError:
        pass
    try:
        return _open_directory(name, dir_fd)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR, errno.EEXIST):
            raise ReviewRefusal("unsafe_tree_path") from None
        raise
def _place(root_fd, relative):
    fd = _claim(os.dup(root_fd))
    try:
        parts = relative.split("/")
        for part in parts[:-1]:
            child = _mkdir_open(fd, part)
            parent, fd = fd, child
            os.close(parent)
        parent = fd
        fd = -1
        return parent, parts[-1]
    finally:
        _close(fd)
def _git_directory(fd):
    path = f"/proc/{os.getpid()}/fd/{fd}"
    expected = os.fstat(fd)
    try:
        if os.path.samestat(os.stat(path + "/."), expected):
            return path
    except OSError:
        raise ReviewRefusal("unsupported_platform") from None
    raise ReviewRefusal("unsupported_platform")
def _git_objects(reader, cwd, scratch, env, program, oids, limit, deadline, invalid):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ReviewRefusal("git_timeout")
    try:
        with gitsafe.custody(scratch=scratch, env=env, stdout_limit=limit, replace_env=True, program=program):
            return reader(cwd, oids, timeout=remaining)
    except gitsafe.GitError as error:
        reason = {"git_timeout": "git_timeout", "git_output_limit": "limit_exceeded",
                  "ERR_AEGIS": invalid}.get(error.code, "export_failed")
        raise ReviewRefusal(reason) from None
def _write_blob(side_fd, path, data):
    parent, leaf = _place(side_fd, path)
    try:
        _write_named(parent, leaf, data)
        return hashlib.sha256(data).hexdigest()
    finally:
        os.close(parent)
def _blob_batches(entries, sizes):
    batch, used = [], 0
    for entry in entries:
        size = sizes[entry[2]] if entry[1] == "blob" else 0
        if batch and used + size > MAX_OBJECT_BYTES:
            yield batch
            batch, used = [], 0
        batch.append(entry)
        used += size
    if batch:
        yield batch
def _export_side(repository, pending_fd, side, entries, env, program, deadline):
    cwd, scratch = _git_directory(repository), _git_directory(pending_fd)
    oids = tuple(dict.fromkeys(oid for _, kind, oid, _ in entries if kind == "blob"))
    row_limit = MAX_HEADER_BYTES + 1
    sizes = _git_objects(gitsafe.blob_sizes, cwd, scratch, env, program, oids,
                         len(oids) * row_limit, deadline, "object_missing")
    if (any(size > MAX_OBJECT_BYTES for size in sizes.values())
            or sum(sizes[oid] for _, kind, oid, _ in entries if kind == "blob") > MAX_SIDE_BYTES):
        raise ReviewRefusal("limit_exceeded")
    os.mkdir(side, 0o755, dir_fd=pending_fd)
    rows = []
    with _held(_open_directory(side, pending_fd)) as side_fd:
        for batch in _blob_batches(entries, sizes):
            wanted = tuple(dict.fromkeys(oid for _, kind, oid, _ in batch if kind == "blob"))
            limit = sum(sizes[oid] + row_limit + 1 for oid in wanted)
            blobs = _git_objects(gitsafe.read_blobs, cwd, scratch, env, program, wanted, limit, deadline, "object_truncated")
            if any(len(blobs[oid]) != sizes[oid] for oid in wanted):
                raise ReviewRefusal("object_truncated")
            for mode, kind, oid, path in batch:
                payload = {"commit": oid} if kind == "commit" else {"sha256": _write_blob(side_fd, path, blobs[oid])}
                rows.append({"path": path, "mode": mode, **payload})
            del blobs
    return rows
def _listing_payload(rows):
    chunks, total = [], 0
    for row in rows:
        line = (json.dumps(row, sort_keys=True) + "\n").encode("ascii")
        total += len(line)
        if total > MAX_LISTING_BYTES:
            raise ReviewRefusal("limit_exceeded")
        chunks.append(line)
    return b"".join(chunks)
def _store_listing(dir_fd, side, rows):
    payload = _listing_payload(rows)
    _write_named(dir_fd, side + ".files.jsonl", payload)
    return hashlib.sha256(payload).hexdigest()
def _write_named(dir_fd, name, payload):
    with _held(_create_file(name, dir_fd)) as fd:
        _write_full(fd, payload)
def _stream_file(repository, dir_fd, name, arguments, ports, planned, limit, failure):
    argv, env, spawn = _invoke(ports, planned, arguments)
    with _held(_create_file(name, dir_fd)) as fd:
        process = spawn(repository, argv, env, GIT_TIMEOUT_SECONDS)
        try:
            process.close_stdin()
            digest = hashlib.sha256()
            for chunk in _bounded_chunks(process, limit):
                digest.update(chunk)
                _write_full(fd, chunk)
            if process.wait(GIT_TIMEOUT_SECONDS) != 0:
                raise ReviewRefusal(failure)
            return digest.hexdigest()
        finally:
            process.close()
def _changed_count(repository, base, candidate, ports, planned):
    arguments = ("diff", "--no-ext-diff", "--no-renames", "--name-only", "-z", base, candidate)
    code, raw = _git(repository, arguments, ports, planned, MAX_DIFF_BYTES)
    if code != 0:
        raise ReviewRefusal("diff_failed")
    return sum(1 for name in _records(raw, b"\0") if name)

def _records(raw, separator, limit=MAX_PATH_BYTES):
    start = 0
    while start < len(raw):
        end = raw.find(separator, start)
        if end < 0:
            end = len(raw)
        if end - start > limit:
            raise ReviewRefusal("limit_exceeded")
        yield raw[start:end]
        start = end + 1

def _names(dir_fd):
    names = []
    with os.scandir(dir_fd) as entries:
        for entry in entries:
            if len(names) == MAX_ENTRIES:
                raise ReviewRefusal("limit_exceeded")
            names.append(entry.name)
    return names
def _init_empty(pending_fd, ports, planned):
    argv, env, spawn = _invoke(ports, planned, ("init", "-q", "--template="))
    code, _raw = _command(pending_fd, argv, env, spawn, SCAFFOLD_TIMEOUT_SECONDS, 4096)
    if code != 0:
        raise ReviewRefusal("scaffold_failed")
def _hash_walk(dir_fd, prefix, digest, depth, on_writable=None):
    if depth > MAX_WALK_DEPTH:
        raise ReviewRefusal("limit_exceeded")
    stats = [(name, os.stat(name, dir_fd=dir_fd, follow_symlinks=False)) for name in sorted(_names(dir_fd))]
    for name, info in stats:
        rel = name if not prefix else prefix + os.sep + name
        if on_writable is not None and not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o222:
            on_writable(".git/%s is writable" % rel)
        digest.update(os.fsencode(rel) + b"\0" + str(stat.S_IFMT(info.st_mode)).encode("ascii") + b"\0")
        if stat.S_ISREG(info.st_mode):
            digest.update(_digest_at(dir_fd, name).encode("ascii"))
        elif stat.S_ISLNK(info.st_mode):
            digest.update(os.fsencode(os.readlink(name, dir_fd=dir_fd)))
    for name, info in stats:
        if stat.S_ISDIR(info.st_mode):
            rel = name if not prefix else prefix + os.sep + name
            with _held(_open_directory(name, dir_fd)) as child:
                _hash_walk(child, rel, digest, depth + 1, on_writable)
def _scaffold_sha(pending_fd, on_writable=None):
    with _held(_open_directory(".git", pending_fd)) as fd:
        digest = hashlib.sha256()
        _hash_walk(fd, "", digest, 0, on_writable)
        return digest.hexdigest()
def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
def _timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
def _lock_tree(dir_fd, depth):
    if depth > MAX_WALK_DEPTH:
        raise ReviewRefusal("limit_exceeded")
    for name in _names(dir_fd):
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            with _held(_open_directory(name, dir_fd)) as child:
                _lock_tree(child, depth + 1)
                os.fchmod(child, 0o555)
        elif stat.S_ISREG(info.st_mode):
            with _held(_open_readonly(name, dir_fd)) as fd:
                os.fchmod(fd, 0o444)
def _purge_tree(dir_fd, *, preflight=False):
    # Remember the parent identity and unvisited children, leaving at most two
    # descriptors open beyond the borrowed root, including the scan's descriptor.
    fd, identity, parents, children = dir_fd, os.fstat(dir_fd), [], []
    scan = True
    try:
        while True:
            if scan and not children:
                scan = False
                if parents and not preflight:
                    os.fchmod(fd, 0o755)
                with os.scandir(fd) as entries:
                    for count, entry in enumerate(entries, 1):
                        if preflight and count > MAX_ENTRIES:
                            raise ReviewRefusal("limit_exceeded")
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISDIR(info.st_mode):
                            if preflight and len(parents) == MAX_WALK_DEPTH:
                                raise ReviewRefusal("limit_exceeded")
                            children.append((entry.name, info))
                            if not preflight and len(children) >= MAX_ENTRIES:
                                scan = True  # Drain this batch before scanning again.
                                break
                        elif not preflight:
                            os.unlink(entry.name, dir_fd=fd)
            removed = None
            if children:
                component, expected = children.pop()
                parents.append((component, identity, children, scan))
                children, scan = [], True
            elif parents:
                name, expected, children, scan = parents.pop()
                component, removed = "..", (name, identity)
            else:
                return
            previous, fd = fd, _open_directory(component, fd)
            if previous != dir_fd:
                os.close(previous)
            identity = os.fstat(fd)
            if not os.path.samestat(identity, expected):
                raise ReviewRefusal("unsafe_path")
            if removed is not None and not preflight:
                name, original = removed
                if not os.path.samestat(os.stat(name, dir_fd=fd, follow_symlinks=False), original):
                    raise ReviewRefusal("unsafe_path")
                os.rmdir(name, dir_fd=fd)
    finally:
        if fd != dir_fd:
            os.close(fd)
def _discard(parent_fd, name, fd, identity):
    if fd >= 0:
        os.fchmod(fd, 0o755)
        _purge_tree(fd)
    try:
        if _matches_entry(parent_fd, name, identity):
            os.rmdir(name, dir_fd=parent_fd)
    except FileNotFoundError:
        pass
def _outputs(repository, pending_fd, base, candidate, ports, planned):
    diff_args = ("diff", "--no-ext-diff", "--no-textconv", "--no-color", "--full-index", "--find-renames", base, candidate)
    log_args = ("log", "--no-color", "--no-show-signature", "--format=commit %H%nAuthor: %an <%ae>%nDate: %aI%n%n%B",
                base + ".." + candidate)
    diff = _stream_file(repository, pending_fd, "changes.diff", diff_args, ports, planned, MAX_DIFF_BYTES, "diff_failed")
    commits = _stream_file(repository, pending_fd, "commits.txt", log_args, ports, planned, MAX_LOG_BYTES, "log_failed")
    return diff, commits
def _write_manifest(pending_fd, repository, sides, diff, commits, count, scaffold):
    manifest = {"schema": SCHEMA, "created_at": _timestamp(), "repository": str(repository), "base": sides["base"],
                "candidate": sides["candidate"], "diff_sha256": diff, "commits_sha256": commits, "changed_files": count,
                "git_scaffold_sha256": scaffold, "meaning": MEANING}
    raw = _encoded(manifest) + b"\n"
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ReviewRefusal("limit_exceeded")
    _write_named(pending_fd, "manifest.json", raw)
    return raw
def _populate(repository_fd, repository, pending_fd, sides, entries, ports, planned):
    deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
    for side in SIDES:
        rows = _export_side(repository_fd, pending_fd, side, entries[side], _object_environment(ports, planned), ports[-1], deadline)
        listing = _store_listing(pending_fd, side, rows)
        sides[side].update(files=len(rows), listing_sha256=listing)
    base, candidate = sides["base"]["commit"], sides["candidate"]["commit"]
    diff, commits = _outputs(repository_fd, pending_fd, base, candidate, ports, planned)
    count = _changed_count(repository_fd, base, candidate, ports, planned)
    _init_empty(pending_fd, ports, planned)
    scaffold = _scaffold_sha(pending_fd)
    raw = _write_manifest(pending_fd, repository, sides, diff, commits, count, scaffold)
    _lock_tree(pending_fd, 0)
    return raw, diff, count
@contextmanager
def _preparation_record(root, identity, refusal, *, expected_parent=None):
    name = f"{identity.st_dev:x}-{identity.st_ino:x}"
    try:
        with storage_confined.confined_file(root, (name,)) as record:
            info = record.parent_stat()
            if (info.st_uid != os.geteuid() or info.st_mode & 0o077
                    or expected_parent is not None and (info.st_dev, info.st_ino) != expected_parent):
                raise ReviewRefusal(refusal)
            yield record
    except storage_confined.ConfinedFileError as error:
        raise ReviewRefusal("filesystem" if error.reason in ("io", "durability") else refusal) from None
def _preparation_bytes(identity, manifest):
    return f"{identity.st_dev:x}:{identity.st_ino:x}:{hashlib.sha256(manifest).hexdigest()}\n".encode("ascii")
def _forget_preparation(record, payload):
    try:
        if record.read_bytes(len(payload)) == payload:
            record.remove()
    except storage_confined.ConfinedFileError as error:
        if error.reason not in ("missing", "too_large"):
            raise
def _publish(repository_fd, repository, parent, dest, sides, entries, ports, planned, preparation_dir, preparation_id):
    name = dest.name
    pending_name = ".pending-" + uuid.uuid4().hex
    if _stat_leaf(parent, name) is not None:
        raise ReviewRefusal("output_exists")
    with ExitStack() as reserve:
        # The purge borrows the stage fd and needs at most two additional slots.
        for _ in range(2):
            reserve.callback(os.close, os.dup(parent))
        os.mkdir(pending_name, 0o700, dir_fd=parent)
        identity = os.stat(pending_name, dir_fd=parent, follow_symlinks=False)
        pending_fd, payload = -1, None
        try:
            pending_fd = _open_directory(pending_name, parent)
            created = os.fstat(pending_fd)
            if not os.path.samestat(created, identity):
                os.close(pending_fd)
                pending_fd = -1
                raise ReviewRefusal("unsafe_path")
            raw, diff, count = _populate(repository_fd, repository, pending_fd, sides, entries, ports, planned)
            os.fchmod(pending_fd, 0o555)
            with _preparation_record(preparation_dir, created, "record_required", expected_parent=preparation_id) as record:
                payload = _preparation_bytes(created, raw)
                record.publish_bytes(payload, replace=True)
            if _stat_leaf(parent, name) is not None:
                raise ReviewRefusal("output_exists")
            if not _matches_entry(parent, pending_name, identity):
                raise ReviewRefusal("unsafe_path")
            _rename_at(parent, pending_name, parent, name)
            return raw, diff, count
        except BaseException:
            reserve.close()
            try:
                if payload is not None:
                    with _preparation_record(preparation_dir, identity, "record_required", expected_parent=preparation_id) as record:
                        _forget_preparation(record, payload)
            finally:
                _discard(parent, pending_name, pending_fd, identity)
            raise
        finally:
            _close(pending_fd)
def _stat_leaf(dir_fd, name):
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
def _matches_entry(dir_fd, name, identity):
    visible = _stat_leaf(dir_fd, name)
    return visible is not None and os.path.samestat(visible, identity)
def _prepare_impl(repository, base, candidate, out, expect_base_tree, expect_candidate_tree, planned, ports, preparation_dir):
    if not descriptor_support():
        raise ReviewRefusal("unsupported_platform")
    if any(not callable(item) for item in ports):
        raise ReviewRefusal("port_required")
    repo, dest = _absolute_path(repository), _absolute_path(out)
    base_id, candidate_id = _commit_text(base), _commit_text(candidate)
    expect_base = _commit_text(expect_base_tree, optional=True)
    expect_candidate = _commit_text(expect_candidate_tree, optional=True)
    try:
        program = str(_absolute_path(getattr(ports[-1], "executable", None)))
    except ReviewRefusal:
        raise ReviewRefusal("port_required") from None
    if planned is not None and type(planned) is not bool:
        raise ReviewRefusal("invalid_input")
    preparation = _absolute_path(preparation_dir, "record_required", outside=dest)
    _refuse_inside(preparation, repo, "record_required")
    with ExitStack() as source:
        try:
            fd, preparation_id = gitsafe_run.validate_review_preparation(
                repo, preparation, source, walk=lambda inspect: _walk(repo, "not_repository", inspect=inspect),
                read_open=_open_readonly)
        except gitsafe.GitError:
            raise ReviewRefusal("record_required") from None
        ports = (*ports, program)
        _git_directory(fd)
        top = _repository_top(fd, ports, planned)
        _refuse_inside(preparation, top, "record_required")
        _refuse_inside(dest, top)
        parent = _walk(dest.parent, None)
        if parent is not None:
            with _held(parent):
                if not dest.name or _stat_leaf(parent, dest.name) is not None:
                    raise ReviewRefusal("output_exists")
        sides = {"base": _exact_side(fd, "base", base_id, expect_base, ports, planned),
                 "candidate": _exact_side(fd, "candidate", candidate_id, expect_candidate, ports, planned)}
        entries = {side: _side_entries(fd, sides[side]["commit"], ports, planned) for side in SIDES}
        with _output_parent(dest.parent) as parent:
            raw, diff, count = _publish(fd, repo, parent, dest, sides, entries, ports, planned, preparation, preparation_id)
    return 0, {"out": str(dest), "manifest_sha256": hashlib.sha256(raw).hexdigest(), "base": sides["base"],
               "candidate": sides["candidate"], "diff_sha256": diff, "changed_files": count}
def _read_manifest(dir_fd, *, validate=True):
    try:
        fd = _open_readonly("manifest.json", dir_fd)
    except OSError as error:
        if error.errno in (errno.ENOENT, errno.ELOOP, errno.ENOTDIR):
            raise ReviewRefusal("not_review_copy") from None
        raise
    with _held(fd):
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST_BYTES:
            raise ReviewRefusal("not_review_copy" if not stat.S_ISREG(info.st_mode) else "limit_exceeded")
        raw = b"".join(_fd_chunks(fd, info.st_size))
    if not validate:
        return raw
    try:
        manifest = _strict_json(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise ReviewRefusal("manifest_shape") from None
    if type(manifest) is not dict or manifest.get("schema") != SCHEMA:
        raise ReviewRefusal("not_review_copy")
    return manifest, raw
def _verify_host():
    return SimpleNamespace(
        descriptor_support=descriptor_support,
        absolute_path=_absolute_path,
        walk=_walk,
        held=_held,
        read_manifest=_read_manifest,
        single_line=_single_line,
        broken=_broken,
        scaffold_sha=_scaffold_sha,
        stat_leaf=_stat_leaf,
        digest_at=_digest_at,
        names=_names,
        open_directory=_open_directory,
        open_readonly=_open_readonly,
        records=_records,
        read_chunks=_fd_chunks,
        file_stat=os.stat,
        file_fstat=os.fstat,
        max_problems=MAX_PROBLEMS,
        max_entries=MAX_ENTRIES,
        max_walk_depth=MAX_WALK_DEPTH,
        max_listing_bytes=MAX_LISTING_BYTES,
        max_header_bytes=MAX_HEADER_BYTES,
        max_path_bytes=MAX_PATH_BYTES,
        known=_KNOWN,
        refusal=ReviewRefusal,
        refusal_envelope=_refusal_envelope,
    )
def _remove_impl(out, preparation_dir):
    if not descriptor_support():
        raise ReviewRefusal("unsupported_platform")
    dest = _absolute_path(out)
    if not dest.name:
        raise ReviewRefusal("unsafe_path")
    with _held(_walk(dest.parent, "not_review_copy")) as parent:
        try:
            fd = _open_directory(dest.name, parent)
        except OSError as error:
            if error.errno in (errno.ELOOP, errno.ENOTDIR, errno.ENOENT):
                raise ReviewRefusal("not_review_copy") from None
            raise
        with _held(fd):
            identity = os.fstat(fd)
            preparation = _absolute_path(preparation_dir, "not_review_copy", outside=dest)
            with _preparation_record(preparation, identity, "not_review_copy") as record:
                held = record.read_bytes(128)
                try:
                    raw = _read_manifest(fd, validate=False)
                except ReviewRefusal:
                    raise ReviewRefusal("not_review_copy") from None
                if held != _preparation_bytes(identity, raw):
                    raise ReviewRefusal("not_review_copy")
                _purge_tree(fd, preflight=True)
                if not _matches_entry(parent, dest.name, identity):
                    raise ReviewRefusal("not_review_copy")
                os.fchmod(fd, 0o755)
                _purge_tree(fd)
                if not _matches_entry(parent, dest.name, identity):
                    raise ReviewRefusal("not_review_copy")
                os.rmdir(dest.name, dir_fd=parent)
                record.remove()
    return 0, {"removed": str(dest)}
@_guard
def prepare(repository, base, candidate, out, *, expect_base_tree=None, expect_candidate_tree=None, planned=None,
            object_read_argv=None, object_read_env=None, child_environment=None, git_spawn=None, preparation_dir=None):
    """Build a copy with owner-private preparation state and an owner-supplied Git spawn port.

    The port supplies its validated absolute executable as ``git_spawn.executable``
    and accepts full argv and a borrowed cwd descriptor.
    """
    ports = (object_read_argv, object_read_env, child_environment, git_spawn)
    return _prepare_impl(repository, base, candidate, out, expect_base_tree, expect_candidate_tree, planned, ports, preparation_dir)
@_guard
def verify(out, *, expect_manifest=None):
    from aegis_core.team_review_verify import verify_copy
    return verify_copy(out, expect_manifest, _verify_host())
@_guard
def remove(out, *, preparation_dir=None):
    """Delete only a descriptor-bound copy recorded in the owner-private directory."""
    return _remove_impl(out, preparation_dir)
