"""Job source checks, worktree witnesses and read-only commit exports.

The owner supplies absolute checkout and export-parent paths and the trusted
Git read policy. Metadata capture is capped before allocation. Commit and blob
reads use gitsafe's public readers inside bounded custody. Paths and Git
output are untrusted. Refusals contain static diagnostics. A path refusal
identifies the caller's original array position out of band.
"""
from contextlib import ExitStack, contextmanager
from functools import wraps
import errno
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from uuid import uuid4

from aegis_core import gitsafe
from aegis_core.errors import AegisError
from aegis_core.storage_confined import (
    ConfinedFileError,
    descriptor_supported as storage_descriptor_supported,
    open_directory,
)

__all__ = ("JobSource", "JobSourceRefusal", "GitReadError", "descriptor_supported")

_MAX_EXPORT_BYTES = 2147483648
_MAX_ENTRIES = 200000
_MAX_PATH = 4096
_MAX_COMPONENTS = 128
_MAX_RECIPE_PATHS = 512
_MAX_RECIPE_BYTES = 1024 * 1024
_MAX_LINK = 4096
_MAX_LINK_HOPS = 40
_MAX_LIST = 64 * 1024 * 1024
_MAX_LINK_BYTES = 64 * 1024 * 1024
_MAX_CONFIG = 65536
_MAX_CONFIG_KEY = 256
_MAX_GIT_RECORD_BYTES = 256
_READ_SECONDS = 120
_EXPORT_SECONDS = 600
_GIT_CAPTURE_SECONDS = 300
_CHUNK = 1024 * 1024
# Retention batch used by the public reader. It is not an export refusal.
_READ_BATCH_BYTES = 16 * 1024 * 1024
_OWNER_HOME = ("HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "XDG_CONFIG_HOME")
_OWNER_CONFIG = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM")
_TRANSPORT_PINS = (("GIT_ALLOW_PROTOCOL", ""), ("GIT_NO_LAZY_FETCH", "1"),
                   ("GIT_NO_REPLACE_OBJECTS", "1"), ("GIT_PROTOCOL_FROM_USER", "0"),
                   ("GIT_OPTIONAL_LOCKS", "0"), ("GIT_TERMINAL_PROMPT", "0"))
_OID = re.compile(rb"[0-9a-f]{40}|[0-9a-f]{64}")
_RECIPE_PATH = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_./@+-]*(::[^\x00-\x1f]{1,512})?")
_MODES = {b"100644": 0o444, b"100755": 0o555, b"120000": None}
_STATUS = frozenset(b" MTADRCU?!")
_STUB_CONFIG = b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
_ACTIONS = {
    "invalid_input": "Supply the documented job source values and retry.",
    "invalid_path": "Supply a bounded path in the documented format.",
    "unsupported_platform": "Use a host with descriptor-relative no-follow operations.",
    "unsafe_checkout_entry": "Restore stable regular files, symlinks and directories in the checkout.",
    "checkout_io": "Restore the checkout and its read permissions.",
    "checkout_changed": "Stop concurrent checkout changes and retry the witness.",
    "witness_limit": "Reduce the dirty or untracked checkout content and retry.",
    "git_failed": "Restore the local repository and retry the Git read.",
    "git_timeout": "Restore local Git responsiveness and retry.",
    "git_output_limit": "Reduce the checkout metadata or query size and retry.",
    "git_protocol": "Repair the repository or the Git read adapter and retry.",
    "partial_clone": "Use a full local repository with all required objects present.",
    "path_outside_commit": "Choose a recipe path present in the pinned commit.",
    "tree_mismatch": "Supply the tree of the pinned local commit.",
    "missing_object": "Restore the required object locally and retry the export.",
    "invalid_object": "Repair the corrupt local Git object before exporting again.",
    "submodule": "Choose source without submodules.",
    "unsafe_tree": "Choose a tree with unique safe paths and supported entry modes.",
    "export_limit": "Choose a commit within the export entry and byte limits.",
    "export_blob_limit": "Choose a commit with smaller exported blobs.",
    "export_exists": "Choose an unused export target.",
    "export_io": "Restore the owner-controlled export parent and retry.",
    "export_cleanup": "Inspect the owner-controlled export parent before retrying.",
    "unsafe_link": "Choose a commit whose exported symlinks stay within the export.",
    "merge_config": "Remove the custom merge configuration or use an integrator lane.",
    "merge_commit": "Choose a merge commit present in the repository.",
    "merge_contained": "Choose a merge commit that would change the checkout.",
    "merge_unrelated": "Choose a merge commit with a common ancestor.",
    "merge_attributes": "Use an integrator lane for changes involving Git attributes.",
}


class JobSourceRefusal(ValueError):
    """Stable reason, exit code and next action. Path indexes are zero-based."""

    def __init__(self, reason, *, path_index=None):
        self.reason, self.code, self.status = reason, 1, "refused"
        self.next_action = _ACTIONS[reason]
        self.path_index = path_index
        super().__init__("job source refused: " + reason)

    def as_dict(self):
        return {"status": self.status, "reason": self.reason, "code": self.code, "next_action": self.next_action}


class GitReadError(Exception):
    """Transport refusal. Ports use timeout, output_limit or git_failed."""

    def __init__(self, reason):
        reasons = {"timeout": "git_timeout", "output_limit": "git_output_limit"}
        self.reason = reasons.get(reason, "git_failed") if type(reason) is str else "git_failed"
        super().__init__(self.reason)


def _require(condition, reason):
    if not condition:
        raise JobSourceRefusal(reason)

def _boundary(reason):
    def decorate(function):
        @wraps(function)
        def call(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except JobSourceRefusal:
                raise
            except GitReadError as error:
                raise JobSourceRefusal(error.reason) from None
            except TimeoutError:
                raise JobSourceRefusal("git_timeout") from None
            except (OSError, ConfinedFileError):
                raise JobSourceRefusal(reason) from None
            except (ValueError, OverflowError):
                raise JobSourceRefusal("invalid_input") from None
        return call
    return decorate


def descriptor_supported():
    return storage_descriptor_supported() and (
        {os.readlink, os.rmdir, os.symlink} <= os.supports_dir_fd and os.scandir in os.supports_fd
        and hasattr(os, "fchmod") and hasattr(os, "O_NONBLOCK"))

def _absolute(value):
    _require(isinstance(value, (str, Path)), "invalid_path")
    name = str(value)
    _require(0 < len(name) <= _MAX_PATH and "\0" not in name, "invalid_path")
    path = Path(name)
    _require(path.is_absolute() and ".." not in path.parts and len(os.fsencode(name)) <= _MAX_PATH, "invalid_path")
    return path

def _oid(value):
    _require(type(value) is str and len(value) in (40, 64) and value.isascii(), "invalid_input")
    _require(_OID.fullmatch(value.encode("ascii")), "invalid_input")
    return value

def _rows(raw, limit=_MAX_PATH + _MAX_GIT_RECORD_BYTES):
    """Read bounded NUL records without allocating a list or splitting a long record."""
    start = 0
    while start < len(raw):
        stop = raw.find(b"\0", start, start + limit + 1)
        _require(stop >= start, "git_protocol")
        yield raw[start:stop]
        start = stop + 1

def _parts(path, reason):
    _require(0 < len(path) <= _MAX_PATH and path.count(b"/") < _MAX_COMPONENTS, reason)
    parts = path.split(b"/")
    _require(all(0 < len(part) <= 255 and part not in (b".", b"..")
                 and part.lower() != b".git" and b"\0" not in part for part in parts), reason)
    return parts

def _clock(deadline):
    remaining = deadline - time.monotonic()
    _require(remaining > 0, "git_timeout")
    return remaining


def _directory(name, _anchor_flags=None, *, dir_fd):
    """Narrow the shared anchor's opener to read-only directory descriptors."""
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=dir_fd)

def _node_id(info):
    return info.st_dev, info.st_ino

@contextmanager
def _descend(root, parts, create=False, created=None, deadline=None):
    parent, chain = root, []
    with ExitStack() as stack:
        for name in parts:
            if created is not None:
                _clock(deadline)
                try:
                    key = (_node_id(os.fstat(parent)), name)
                    previous = created.get(key)
                    if create:
                        try:
                            os.mkdir(name, 0o700, dir_fd=parent)
                        except FileExistsError:
                            _require(previous is not None, "unsafe_tree")
                        else:
                            _require(previous is None, "unsafe_tree")
                    child = _directory(name, dir_fd=parent)
                    stack.callback(os.close, child)
                    found = _node_id(os.fstat(child))
                    if create and previous is None:
                        created[key] = found
                    else:
                        _require(previous == found, "unsafe_tree")
                except OSError:
                    raise JobSourceRefusal("unsafe_tree") from None
            else:
                child = _directory(name, dir_fd=parent)
                stack.callback(os.close, child)
                chain.append((parent, name, child))
            parent = child
        yield parent
        for held, name, child in reversed(chain):
            _require(os.path.samestat(os.stat(name, dir_fd=held, follow_symlinks=False), os.fstat(child)),
                     "checkout_changed")

@contextmanager
def _source_anchor(checkout):
    _require(descriptor_supported(), "unsupported_platform")
    with open_directory(_directory, checkout, retain_ancestors=True) as root:
        yield root
        try:
            root.check()
        except ConfinedFileError:
            raise JobSourceRefusal("checkout_changed") from None

def _file_signature(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns

def _hash_file(parent, name, expected, budget, deadline):
    _require(expected.st_size <= budget, "witness_limit")
    digest = hashlib.sha256()
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        _require(_file_signature(os.fstat(fd)) == _file_signature(expected), "checkout_changed")
        left = expected.st_size
        while left:
            _clock(deadline)
            chunk = os.read(fd, min(left, _CHUNK))
            _require(chunk, "checkout_changed")
            digest.update(chunk)
            left -= len(chunk)
        _require(not os.read(fd, 1) and _file_signature(os.fstat(fd)) == _file_signature(expected),
                 "checkout_changed")
    finally:
        os.close(fd)
    mode = b"x" if expected.st_mode & 0o111 else b"-"
    return b"file:" + mode + b":" + digest.hexdigest().encode("ascii"), expected.st_size

def _leaf_fingerprint(parent, name, budget, deadline):
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return b"absent", 0
    if stat.S_ISLNK(info.st_mode):
        _require(info.st_size <= min(_MAX_LINK, budget), "witness_limit")
        target = os.readlink(name, dir_fd=parent)
        _require(len(target) <= min(_MAX_LINK, budget), "witness_limit")
        result = b"link:" + target, len(target)
    else:
        _require(stat.S_ISREG(info.st_mode), "unsafe_checkout_entry")
        result = _hash_file(parent, name, info, budget, deadline)
    _require(_file_signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) == _file_signature(info),
             "checkout_changed")
    return result

def _fingerprint(root, raw, budget, deadline):
    parts = _parts(raw, "unsafe_checkout_entry")
    entered = False
    try:
        with _descend(root, parts[:-1]) as parent:
            entered = True
            return _leaf_fingerprint(parent, parts[-1], budget, deadline)
    except FileNotFoundError:
        if entered:
            raise JobSourceRefusal("checkout_changed") from None
        return b"absent", 0
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise JobSourceRefusal("unsafe_checkout_entry") from None
        raise

def _status_records(raw):
    rows = _rows(raw, _MAX_PATH + 3)
    for count, row in enumerate(rows, 1):
        _require(count <= _MAX_ENTRIES, "witness_limit")
        _require(len(row) >= 4 and row[2] == 32 and row[0] in _STATUS and row[1] in _STATUS, "git_protocol")
        state = row[:2]
        names = (row[3:],)
        if b"R" in state or b"C" in state:
            previous = next(rows, b"")
            _require(previous, "git_protocol")
            names += (previous,)
        yield state, names

def _size(raw, reason):
    _require(0 < len(raw) <= 20 and raw.isdigit(), reason)
    return int(raw)


def _tree_entries(raw, deadline, env):
    entries, file_names = [], set()
    size = link_bytes = admitted_frame = 0
    for row in _rows(raw):
        _clock(deadline)
        _require(len(entries) < _MAX_ENTRIES, "export_limit")
        meta, sep, path = row.partition(b"\t")
        _require(sep and len(meta) <= _MAX_GIT_RECORD_BYTES, "git_protocol")
        fields = meta.split()
        _require(len(fields) == 4 and _OID.fullmatch(fields[2]), "git_protocol")
        mode, kind, oid, length = fields
        _require(kind != b"commit", "submodule")
        _require(kind == b"blob" and mode in _MODES, "unsafe_tree")
        parts = _parts(path, "unsafe_tree")
        _require(path not in file_names, "unsafe_tree")
        file_names.add(path)
        length = _size(length, "missing_object")
        size += length
        _require(size <= _MAX_EXPORT_BYTES, "export_limit")
        if (frame := _frame_size(oid, "blob", length)) > admitted_frame:
            _check_capture(frame, env, "export_blob_limit")
            admitted_frame = frame
        if mode == b"120000":
            _require(0 < length <= _MAX_LINK, "unsafe_link")
            link_bytes += length
            _require(link_bytes <= _MAX_LINK_BYTES, "export_limit")
        entries.append((parts, mode, oid, length))
    directories, previous = 0, ()
    for path in sorted(file_names):
        _clock(deadline)
        current = path.split(b"/")[:-1]
        shared = 0
        for old, new in zip(previous, current):
            if old != new:
                break
            shared += 1
        directories += len(current) - shared
        _require(directories <= _MAX_ENTRIES, "export_limit")
        previous = current
        parent, sep, _ = path.rpartition(b"/")
        while sep:
            _require(parent not in file_names, "unsafe_tree")
            parent, sep, _ = parent.rpartition(b"/")
    return entries, size


def _reader_reason(error, overflow):
    code = error.code
    message = error.message if type(error.message) is str else ""
    if code == "git_timeout" or "timed out" in message:
        return "git_timeout"
    if "does not match" in message:
        return "invalid_object"
    if "cannot read object" in message:
        return "missing_object"
    if code == "git_output_limit":
        return overflow
    return "git_failed"

def _frame_size(oid, kind, size):
    return len(oid) + len(kind) + len(str(size)) + size + 4  # Two spaces and two LFs.

def _check_capture(limit, env, overflow):
    """Ask custody to admit the frame using the scratch and env it already validated."""
    try:
        with gitsafe.custody(scratch=Path(tempfile.gettempdir()), env=env, stdout_limit=limit):
            pass
    except gitsafe.GitError as error:
        raise JobSourceRefusal(overflow if error.code == "invalid_custody" else _reader_reason(error, overflow)) from None

def _call_reader(function, *args, env, program, stdout_limit, timeout, overflow="git_protocol", **options):
    try:
        with gitsafe.custody(scratch=Path(tempfile.gettempdir()), env=env, stdout_limit=stdout_limit,
                            replace_env=True, program=program):
            return function(*args, timeout=min(timeout, _GIT_CAPTURE_SECONDS), **options)
    except gitsafe.GitError as error:
        raise JobSourceRefusal(_reader_reason(error, overflow)) from None

def _object_reader(function, checkout, oids, kind, deadline, env, program, sizes=None):
    limit = (sum(len(oid) + 33 for oid in oids) if sizes is None
             else sum(_frame_size(oid, kind, sizes[oid]) for oid in oids))
    return _call_reader(function, checkout, list(oids), env=env, program=program, stdout_limit=limit,
                        kind=kind, timeout=_clock(deadline))

def _commit_tree(data, expected):
    stop = data.find(b"\n", 5, 70)
    _require(stop >= 0 and data.startswith(b"tree "), "git_protocol")
    found = data[5:stop]
    _require(_OID.fullmatch(found) is not None, "git_protocol")
    _require(found.decode("ascii") == expected, "tree_mismatch")

def _read_commit(checkout, commit, deadline, env, program):
    sizes = _object_reader(gitsafe.blob_sizes, checkout, [commit], "commit", deadline, env, program)
    length = sizes.get(commit)
    _require(type(length) is int, "missing_object")
    _check_capture(_frame_size(commit, "commit", length), env, "git_output_limit")
    data = _object_reader(gitsafe.read_blobs, checkout, [commit], "commit", deadline, env, program,
                        {commit: length}).get(commit)
    _require(type(data) is bytes and len(data) == length, "invalid_object")
    return data

def _preflight_blobs(checkout, entries, deadline, env, program):
    declared = {}
    for _parts, _mode, oid, length in entries:
        text = oid.decode("ascii")
        previous = declared.get(text)
        _require(previous is None or previous == length, "git_protocol")
        declared[text] = length
    if not declared:
        return {}
    sizes = _object_reader(gitsafe.blob_sizes, checkout, declared, "blob", deadline, env, program)
    for oid, length in declared.items():
        _clock(deadline)
        actual = sizes.get(oid)
        _require(type(actual) is int, "missing_object")
        if actual != length:
            _check_capture(_frame_size(oid, "blob", actual), env, "export_blob_limit")
            raise JobSourceRefusal("git_protocol")
    return sizes

def _object_batches(sizes):
    batch, total = [], 0
    for oid, size in sizes.items():
        if batch and total + size > _READ_BATCH_BYTES:
            yield batch
            batch, total = [], 0
        batch.append(oid)
        total += size
        if total >= _READ_BATCH_BYTES:
            yield batch
            batch, total = [], 0
    if batch:
        yield batch


def _write_file(parent, name, mode, data, deadline):
    _clock(deadline)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
    except FileExistsError:
        raise JobSourceRefusal("unsafe_tree") from None
    try:
        payload = memoryview(data)
        for offset in range(0, len(payload), _CHUNK):
            _clock(deadline)
            view = payload[offset:offset + _CHUNK]
            while view:
                written = os.write(fd, view)
                _require(written > 0, "export_io")
                view = view[written:]
    finally:
        os.close(fd)

def _place_entry(root, parts, mode, data, links, deadline, created):
    _clock(deadline)
    with _descend(root, parts[:-1], create=True, created=created, deadline=deadline) as parent:
        if mode == b"120000":
            _require(b"\0" not in data, "unsafe_link")
            links[tuple(parts)] = data
        else:
            _write_file(parent, parts[-1], _MODES[mode], data, deadline)

def _write_blobs(checkout, root, entries, sizes, deadline, env, program, created):
    grouped, links = {}, {}
    for parts, mode, oid, _length in entries:
        grouped.setdefault(oid.decode("ascii"), []).append((parts, mode))
    for batch in _object_batches(sizes):
        _clock(deadline)
        objects = _object_reader(gitsafe.read_blobs, checkout, batch, "blob", deadline, env, program, sizes)
        for oid in batch:
            _require(oid in objects and oid in grouped, "missing_object")
            data = objects.pop(oid)
            _require(type(data) is bytes and len(data) == sizes[oid], "invalid_object")
            for parts, mode in grouped[oid]:
                _place_entry(root, parts, mode, data, links, deadline, created)
            del data
        del objects
    return links


def _link_steps(data, root):
    absolute = data.startswith(b"/")
    if absolute:
        prefix = root + b"/"
        _require(data == root or data.startswith(prefix), "unsafe_link")
        data = b"" if data == root else data[len(prefix):]
    return absolute, [part for part in data.split(b"/") if part and part != b"."]

def _entry_kind(parent, name):
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return "missing", None
    except OSError:
        raise JobSourceRefusal("unsafe_link") from None
    if not stat.S_ISLNK(info.st_mode):
        return ("dir" if stat.S_ISDIR(info.st_mode) else "other"), info
    try:
        target = os.readlink(name, dir_fd=parent)
    except OSError:
        raise JobSourceRefusal("unsafe_link") from None
    if type(target) is str:
        target = os.fsencode(target)
    _require(type(target) is bytes and b"\0" not in target and len(target) <= _MAX_LINK, "unsafe_link")
    return "link", target

def _enter_created(parent, name, info, created, opened):
    try:
        parent_id = _node_id(os.fstat(parent))
        _require((parent_id, _node_id(info)) in created, "unsafe_link")
        child = _directory(name, dir_fd=parent)
        opened.append(child)
        _require(_node_id(os.fstat(child)) == _node_id(info), "unsafe_link")
    except OSError:
        raise JobSourceRefusal("unsafe_link") from None
    return child

def _walk_link(stage, opened, payload, root, created, deadline):
    hops, virtual, at_file = 1, 0, False
    absolute, parts = _link_steps(payload, root)
    if absolute:
        while opened:
            os.close(opened.pop())
    pending, cursors = [parts], [0]
    while pending:
        _clock(deadline)
        if cursors[-1] >= len(pending[-1]):
            pending.pop()
            cursors.pop()
            continue
        part = pending[-1][cursors[-1]]
        cursors[-1] += 1
        _require(not at_file, "unsafe_link")
        if part == b"..":
            if virtual:
                virtual -= 1
            else:
                _require(opened, "unsafe_link")
                os.close(opened.pop())
            continue
        _require(len(opened) + virtual < _MAX_COMPONENTS, "unsafe_link")
        if virtual:
            virtual += 1
            continue
        parent = opened[-1] if opened else stage
        kind, info = _entry_kind(parent, part)
        if kind == "missing":
            virtual += 1
        elif kind == "dir":
            _enter_created(parent, part, info, created, opened)
        elif kind == "link":
            hops += 1
            _require(hops <= _MAX_LINK_HOPS, "unsafe_link")
            nested_absolute, nested = _link_steps(info, root)
            if nested_absolute:
                while opened:
                    os.close(opened.pop())
            pending.append(nested)
            cursors.append(0)
        else:
            at_file = True

def _confine_link(stage, path, payload, root, created, deadline):
    opened = []
    try:
        parent = stage
        for name in path[:-1]:
            _clock(deadline)
            kind, info = _entry_kind(parent, name)
            _require(kind == "dir", "unsafe_link")
            parent = _enter_created(parent, name, info, created, opened)
        _walk_link(stage, opened, payload, root, created, deadline)
    finally:
        while opened:
            os.close(opened.pop())

def _git_stub(root, commit, created, deadline):
    with _descend(root, (b".git",), create=True, created=created, deadline=deadline) as stub:
        for name in (b"objects", b"refs"):
            with _descend(stub, (name,), create=True, created=created, deadline=deadline):
                pass
        for name, data in ((b"HEAD", commit.encode("ascii") + b"\n"), (b"config", _STUB_CONFIG)):
            _write_file(stub, name, 0o444, data, deadline)
        os.fchmod(stub, 0o555)

def _install_links(root, links, created, deadline):
    for path, contents in links.items():
        _clock(deadline)
        with _descend(root, path[:-1], created=created, deadline=deadline) as parent:
            try:
                os.symlink(contents, path[-1], dir_fd=parent)
            except FileExistsError:
                raise JobSourceRefusal("unsafe_tree") from None

def _seal_export(root, directory_ids, deadline):
    try:
        parent_id = _node_id(os.fstat(root))
        with os.scandir(root) as children:
            for child in children:
                _clock(deadline)
                if child.is_dir(follow_symlinks=False):
                    fd = _directory(child.name, dir_fd=root)
                    try:
                        _require((parent_id, _node_id(os.fstat(fd))) in directory_ids, "unsafe_tree")
                        _seal_export(fd, directory_ids, deadline)
                    finally:
                        os.close(fd)
    except OSError:
        raise JobSourceRefusal("unsafe_tree") from None
    os.fchmod(root, 0o555)

def _clear_directory(root):
    os.fchmod(root, 0o700)
    with os.scandir(root) as children:
        for child in children:
            if child.is_dir(follow_symlinks=False):
                fd = _directory(child.name, dir_fd=root)
                try:
                    _clear_directory(fd)
                finally:
                    os.close(fd)
                os.rmdir(child.name, dir_fd=root)
            else:
                os.unlink(child.name, dir_fd=root)

@contextmanager
def _staged_export(parent, name, deadline):
    """Publish a sealed sibling over only the empty slot reserved by this call."""
    _clock(deadline)
    try:
        os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise JobSourceRefusal("export_exists")
    fd = parent.fd
    temporary = ".aegis-job-export-" + uuid4().hex
    os.mkdir(temporary, 0o700, dir_fd=fd)
    staged, sealed, reserved, published = None, False, False, False
    try:
        staged = _directory(temporary, dir_fd=fd)
        yield staged
        sealed = True
        closing, staged = staged, None
        os.close(closing)
        parent.check()
        _clock(deadline)
        try:
            os.mkdir(name, 0o700, dir_fd=fd)
        except FileExistsError:
            raise JobSourceRefusal("export_exists") from None
        reserved = True
        os.rename(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        published = True
    finally:
        try:
            try:
                if reserved and not published:
                    os.rmdir(name, dir_fd=fd)
            finally:
                if not published:
                    if staged is not None:
                        _clear_directory(staged)
                    elif sealed:
                        with _descend(fd, (temporary,)) as directory:
                            _clear_directory(directory)
                    os.rmdir(temporary, dir_fd=fd)
        except OSError:
            raise JobSourceRefusal("export_cleanup") from None
        finally:
            if staged is not None:
                os.close(staged)


def _owner_config(values, name, limit=_MAX_CONFIG):
    value = values.get(name)
    _require(name not in values or (type(value) is str and len(value) <= limit and "\0" not in value), "invalid_input")
    return value

def _numbered_config(values):
    raw = _owner_config(values, "GIT_CONFIG_COUNT")
    if raw is None:
        return
    _require(raw.isascii() and raw.isdecimal(), "invalid_input")
    count = raw.lstrip("0") or "0"
    _require(len(count) <= 2 and (size := int(count)) <= 64, "invalid_input")
    for index in range(size):
        key = _owner_config(values, "GIT_CONFIG_KEY_%d" % index, _MAX_CONFIG_KEY)
        value = _owner_config(values, "GIT_CONFIG_VALUE_%d" % index)
        yield key, value

def _owner_configs(env):
    pairs = list(_numbered_config(env if "GIT_CONFIG_COUNT" in env else os.environ))
    name = "GIT_CONFIG_PARAMETERS"
    parameters = _owner_config(env if name in env else os.environ, name)
    probe = {key: env[key] for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP") if key in env}
    probe.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    width = (64 - len(probe) - 1 - (parameters is not None)) // 2
    # Keep Git's numbered-then-parameters order through the replacement scope's key limit.
    for offset in range(0, len(pairs) or int(parameters is not None), width):
        batch = pairs[offset:offset + width]
        mapping = dict(probe, GIT_CONFIG_COUNT=str(len(batch)))
        for idx, (key, value) in enumerate(batch):
            if key is not None:
                mapping["GIT_CONFIG_KEY_%d" % idx] = key
            if value is not None:
                mapping["GIT_CONFIG_VALUE_%d" % idx] = value
        if parameters is not None and offset + width >= len(pairs):
            mapping[name] = parameters
        yield mapping

def _owner_excludes(checkout, configs, program, deadline):
    found = None
    # Fence at the checkout without reading its local configuration.
    args = ("--git-dir=" + os.devnull, "config", "--no-includes", "--null", "--show-scope",
            "--get-regexp", r"^(core\.excludesfile|include\.path|includeif\..*\.path)$")
    key = b"core.excludesfile"
    for mapping in configs:
        reply = _call_reader(gitsafe.run, args, checkout, env=mapping, program=program,
                             stdout_limit=_MAX_LIST, timeout=_clock(deadline), overflow="git_output_limit")
        _require(reply.returncode in (0, 1), "git_failed")
        rows = _rows(reply.stdout, (_MAX_CONFIG + _MAX_CONFIG_KEY) * 4 + 1)
        for scope in rows:
            record = next(rows, None)
            _require(scope == b"command" and record is not None, "git_protocol")
            name, separator, value = record.partition(b"\n")
            _require(name == key and separator, "git_failed")
            found = os.fsdecode(value)
            _require(len(found) <= _MAX_CONFIG, "invalid_input")
    return found

def _apply_owner_policy(checkout, env, program, deadline, projection):
    merged = {key: value for key, value in env.items() if not key.startswith("GIT_CONFIG_")}
    for name in _OWNER_HOME + _OWNER_CONFIG:
        value = _owner_config(env if name in env else os.environ, name)
        if value is not None:
            merged[name] = value
    configs = tuple(_owner_configs(env))
    if configs != projection.get("inputs"):
        projection.update(inputs=configs, excludes=_owner_excludes(checkout, configs, program, deadline))
    excludes = projection["excludes"]
    if excludes is not None:
        merged.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.excludesFile", GIT_CONFIG_VALUE_0=excludes)
    merged.update(_TRANSPORT_PINS)
    return merged


class JobSource:
    """Owner-wired source service requiring a caller-selected absolute Git program.

    run(checkout, argv, env, timeout=, limit=, stdin=) returns (exit_code,
    stdout_bytes) for metadata inside replacement custody. The port delegates to
    gitsafe.run without environment overrides.
    """

    @_boundary("invalid_input")
    def __init__(self, *, run, object_read_argv, object_read_env, child_environment, program=None):
        _require(all(callable(port) for port in (run, object_read_argv, object_read_env, child_environment)),
                 "invalid_input")
        _require(type(program) is str and 0 < len(program) <= 16384 and "\0" not in program
                 and Path(program).is_absolute() and ".." not in Path(program).parts
                 and os.path.isfile(program) and os.access(program, os.X_OK), "invalid_input")
        self._run_port, self._program = run, program
        self._argv = object_read_argv
        self._env = object_read_env
        self._child_environment = child_environment

    def _environment(self, planned, *, checkout=None, deadline=None, projection=None):
        _require(planned is None or type(planned) is bool, "invalid_input")
        try:
            env = self._env(None, inherit_config=projection is not None)
            if planned is not False:
                env = self._child_environment(env, "no-host")
        except (AegisError, ValueError, RuntimeError):
            raise JobSourceRefusal("invalid_input") from None
        _require(type(env) is dict, "invalid_input")
        if projection is not None:
            env = _apply_owner_policy(checkout, env, self._program, deadline, projection)
        _require(all(env.get(key) == value for key, value in _TRANSPORT_PINS[:3]), "invalid_input")
        return env

    def _read(self, checkout, *arguments, planned=None, env=None, timeout=_READ_SECONDS,
              limit=_MAX_LIST, stdin=None):
        env = self._environment(planned) if env is None else env
        result = _call_reader(self._run_port, checkout, self._argv(*arguments), env, env=env,
                              program=self._program, stdout_limit=limit, overflow="git_output_limit",
                              timeout=timeout, limit=limit, stdin=stdin)
        _require(type(result) is tuple and len(result) == 2, "git_protocol")
        code, raw = result
        _require(type(code) is int and type(raw) is bytes, "git_protocol")
        _require(len(raw) <= limit, "git_output_limit")
        return code, raw

    def _no_partial_clone(self, checkout, planned, deadline):
        partial, _ = self._read(checkout, "config", "--local", "--includes", "--get", "extensions.partialClone",
                                planned=planned, timeout=_clock(deadline), limit=_MAX_CONFIG)
        code, raw = self._read(checkout, "config", "--local", "--includes", "--type=bool", "--get-regexp",
                               r"^remote\..*\.promisor$", planned=planned, timeout=_clock(deadline), limit=_MAX_CONFIG)
        _require(partial in (0, 1) and code in (0, 1), "git_failed")
        _require(partial == 1 and not any(line.endswith(b" true") for line in raw.splitlines()), "partial_clone")

    @_boundary("checkout_io")
    def refuse_paths_outside_commit(self, checkout, commit, paths, *, planned=None):
        checkout, commit = _absolute(checkout), _oid(commit)
        _require(type(paths) in (list, tuple) and len(paths) <= _MAX_RECIPE_PATHS, "invalid_path")
        size = 2
        for path in paths:
            _require(type(path) is str and 0 < len(path) <= _MAX_PATH, "invalid_path")
            size += len(path.encode("utf-8")) + 4
            _require(size <= _MAX_RECIPE_BYTES and _RECIPE_PATH.fullmatch(path), "invalid_path")
            _require(".." not in path.partition("::")[0].split("/"), "invalid_path")
        deadline = time.monotonic() + _READ_SECONDS
        self._no_partial_clone(checkout, planned, deadline)
        env = self._environment(planned)
        _read_commit(checkout, commit, deadline, env, self._program)
        for idx, path in enumerate(paths):
            name = path.partition("::")[0].rstrip("/")
            args = self._argv("cat-file", "-e", commit + ":" + ("" if name == "." else name))
            found = _call_reader(gitsafe.run, args, checkout, env=env, program=self._program,
                                 stdout_limit=0, timeout=_clock(deadline))
            if found.returncode:
                raise JobSourceRefusal("path_outside_commit", path_index=idx)

    @_boundary("export_io")
    def export_commit(self, checkout, commit, tree, target, git_stub=False, *, planned=None):
        _require(descriptor_supported(), "unsupported_platform")
        checkout, target = _absolute(checkout), _absolute(target)
        commit, tree = _oid(commit), _oid(tree)
        _require(type(git_stub) is bool and target.name and len(os.fsencode(target.name)) <= 255, "invalid_input")
        deadline = time.monotonic() + _EXPORT_SECONDS
        self._no_partial_clone(checkout, planned, deadline)
        env = self._environment(planned)
        _commit_tree(_read_commit(checkout, commit, deadline, env, self._program), tree)
        code, raw = self._read(checkout, "ls-tree", "-r", "-z", "-l", "--full-tree", tree,
                               planned=planned, timeout=_clock(deadline))
        _require(code == 0, "git_failed")
        entries, size = _tree_entries(raw, deadline, env)
        sizes = _preflight_blobs(checkout, entries, deadline, env, self._program)
        export_root = os.fsencode(os.fspath(target))
        with open_directory(_directory, target.parent, retain_ancestors=True) as parent:
            with _staged_export(parent, target.name, deadline) as root:
                created = {}
                links = _write_blobs(checkout, root, entries, sizes, deadline, env, self._program, created)
                _install_links(root, links, created, deadline)
                if git_stub:
                    _git_stub(root, commit, created, deadline)
                directory_ids = set()
                for (parent_id, _), child_id in created.items():
                    _clock(deadline)
                    directory_ids.add((parent_id, child_id))
                for path, payload in links.items():
                    _confine_link(root, path, payload, export_root, directory_ids, deadline)
                _seal_export(root, directory_ids, deadline)
        record = {"commit": commit, "tree": tree, "entries": len(entries), "bytes": size}
        if git_stub:
            record["git_stub"] = True
        return record

    def _submodules(self, checkout, revisions, planned, deadline):
        reads = [("ls-files", "--stage", "-z")]
        reads.extend(("ls-tree", "-r", "-z", "--full-tree", revision) for revision in revisions)
        for args in reads:
            code, raw = self._read(checkout, *args, planned=planned, timeout=_clock(deadline))
            _require(code == 0, "git_failed")
            for row in _rows(raw):
                _require(not row.startswith(b"160000 "), "submodule")

    def _status(self, checkout, view, planned, deadline, projection):
        _require(view is None or type(view) is dict and len(view) <= 64, "invalid_input")
        if view is not None:
            _require(all(type(k) is str and 0 < len(k) <= 256 and "\0" not in k and "=" not in k
                         and type(v) is str and len(v) <= _MAX_CONFIG and "\0" not in v
                         for k, v in view.items()), "invalid_input")
        env = self._environment(planned, checkout=checkout, deadline=deadline, projection=projection)
        code, raw = self._read(checkout, "status", "--porcelain=v1", "-z", "--untracked-files=all",
                               env=env, timeout=_clock(deadline))
        _require(code == 0, "git_failed")
        return raw

    def _identity(self, checkout, ref, planned, projection):
        deadline = time.monotonic() + _READ_SECONDS
        env = self._environment(planned, checkout=checkout, deadline=deadline, projection=projection)
        code, raw = self._read(checkout, "rev-parse", ref, env=env, timeout=5, limit=_MAX_GIT_RECORD_BYTES)
        _require(code == 0, "git_failed")
        _require(raw.endswith(b"\n") and _OID.fullmatch(raw[:-1]), "git_protocol")
        return raw[:-1].decode("ascii")

    def _witness(self, checkout, root, view, planned, projection):
        deadline = time.monotonic() + _READ_SECONDS
        status = self._status(checkout, view, planned, deadline, projection)
        self._submodules(checkout, (), planned, deadline)
        digest, count, budget = hashlib.sha256(), 0, _MAX_EXPORT_BYTES
        for state, names in _status_records(status):
            _clock(deadline)
            count += 1
            digest.update(state + b"\0")
            for name in names:
                data, size = _fingerprint(root, name, budget, deadline)
                budget -= size
                digest.update(name + b"\0" + data + b"\0")
        return digest.hexdigest(), count

    @_boundary("checkout_io")
    def uncommitted_content(self, checkout, view=None, *, planned=None):
        checkout = _absolute(checkout)
        with _source_anchor(checkout) as root:
            return self._witness(checkout, root.fd, view, planned, {})

    @_boundary("checkout_io")
    def source_state(self, checkout, view=None, *, planned=None):
        checkout = _absolute(checkout)
        projection = {}
        with _source_anchor(checkout) as root:
            status = self._status(checkout, None, planned, time.monotonic() + 60, projection)
            commit = self._identity(checkout, "HEAD", planned, projection)
            tree = self._identity(checkout, "HEAD^{tree}", planned, projection)
            digest, _ = self._witness(checkout, root.fd, view, planned, projection)
            return {"worktree": str(checkout), "source_revision": commit, "source_tree": tree,
                    "dirty_state_sha256": hashlib.sha256(status).hexdigest(),
                    "dirty_entries": sum(1 for _ in _status_records(status)), "dirty_content_sha256": digest}

    @_boundary("checkout_io")
    def source_digest(self, checkout, *, planned=None):
        checkout = _absolute(checkout)
        projection = {}
        with _source_anchor(checkout) as root:
            digest, count = self._witness(checkout, root.fd, None, planned, projection)
            return 0, {"commit": self._identity(checkout, "HEAD", planned, projection),
                       "tree": self._identity(checkout, "HEAD^{tree}", planned, projection),
                       "dirty_content_sha256": digest, "dirty_entries": count}

    @_boundary("checkout_io")
    def head_ref(self, checkout, *, planned=None):
        code, raw = self._read(_absolute(checkout), "symbolic-ref", "-q", "HEAD", planned=planned, limit=_MAX_PATH)
        _require(code in (0, 1), "git_failed")
        if code == 1:
            _require(not raw, "git_protocol")
            return None
        # One symbolic-ref record ends on LF. Unicode line separators are legal ref bytes.
        value = raw[:-1]
        _require(raw.endswith(b"\n") and b"\n" not in value and value.startswith(b"refs/")
                 and not any(c < 32 or c == 127 for c in value),
                 "git_protocol")
        return os.fsdecode(value)

    def _attributes(self, checkout, paths, revisions, planned):
        if not paths:
            return
        _require(sum(len(path) + 1 for path in paths) <= _MAX_LIST, "git_output_limit")
        stdin = b"\0".join(paths) + b"\0"
        builtin = (b"unspecified", b"set", b"unset", b"text", b"binary")
        for revision in revisions:
            code, raw = self._read(checkout, "check-attr", "-z", "--stdin", "--source", revision, "filter", "merge",
                                   stdin=stdin, planned=planned)
            _require(code == 0, "git_failed")
            rows = _rows(raw)
            for path in paths:
                for name, allowed in ((b"filter", (b"unspecified", b"unset")), (b"merge", builtin)):
                    _require(next(rows, None) == path and next(rows, None) == name, "git_protocol")
                    _require(next(rows, None) in allowed, "merge_attributes")
            _require(next(rows, None) is None, "git_protocol")

    @_boundary("checkout_io")
    def merge_refusals(self, checkout, commit, merge, *, planned=None):
        checkout, commit, merge = _absolute(checkout), _oid(commit), _oid(merge)
        code, raw = self._read(checkout, "config", "--get-regexp", r"^merge\.(default|.+\.driver)$",
                               planned=planned, limit=_MAX_CONFIG)
        _require(code in (0, 1), "git_failed")
        _require(not raw, "merge_config")
        code, raw = self._read(checkout, "rev-parse", "--verify", "--quiet", "--end-of-options", merge + "^{commit}",
                               planned=planned, limit=_MAX_GIT_RECORD_BYTES)
        _require(code == 0 and raw == merge.encode("ascii") + b"\n", "merge_commit")
        code, _ = self._read(checkout, "merge-base", "--is-ancestor", merge, commit, planned=planned, limit=128)
        _require(code in (0, 1), "git_failed")
        _require(code == 1, "merge_contained")
        code, raw = self._read(checkout, "merge-base", "--all", commit, merge, planned=planned, limit=_MAX_CONFIG)
        _require(code in (0, 1), "git_failed")
        bases = raw.splitlines()
        _require(bases, "merge_unrelated")
        _require(all(_OID.fullmatch(base) for base in bases), "git_protocol")
        self._submodules(checkout, (commit, merge), planned, time.monotonic() + _READ_SECONDS)
        changed = set()
        for base in bases:
            for side in (commit, merge):
                code, raw = self._read(checkout, "diff-tree", "-r", "-z", "--name-only", "--no-renames",
                                       base.decode("ascii"), side, planned=planned)
                _require(code == 0, "git_failed")
                for name in _rows(raw, _MAX_PATH):
                    _require(len(changed) < _MAX_ENTRIES or name in changed, "git_output_limit")
                    _parts(name, "invalid_path")
                    changed.add(name)
        self._attributes(checkout, sorted(changed), (commit, merge), planned)
        _require(not any(name.rsplit(b"/", 1)[-1] == b".gitattributes" for name in changed), "merge_attributes")
