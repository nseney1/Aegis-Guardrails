#!/usr/bin/env python3
"""Compose a bounded, durable brief without changing any coordination store."""
from __future__ import annotations

import argparse
import copy
from collections import ChainMap
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import errno
import hashlib
from functools import lru_cache, wraps
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import FunctionType
import uuid

sys.dont_write_bytecode = True
# These are captured public APIs, not direct filesystem operations. The
# structural census reviews this literal list; every raw syscall stays below.
_ACQUISITION_CALL_ALLOWLIST = {
    "datetime.now(timezone.utc).isoformat().replace": "Trusted UTC timestamp formatting replaces a literal suffix; it performs no filesystem IO.",
    "read": "The _link_snapshot callback comes from _symlink_reader and enters _acquire(link).",
    "operation.exists": "Operation existence checks consume the write-once witness ledger.",
    "self.operation.exists": "Captured mailbox existence checks delegate to the operation ledger.",
    "brief.operation.exists": "Brief discovery uses the operation's captured existence API.",
    "mailbox.operation.exists": "Mailbox discovery uses the operation's captured existence API.",
    "self.read": "Operation cached reads revalidate their captured witnesses before reuse.",
    "operation.read": "Operation reads acquire and verify through the single filesystem boundary.",
    "declaration.read": "Declaration reads inherit and compare the parent's immutable witnesses.",
    "self.operation.read": "Captured mailbox reads use the operation's bounded acquisition API.",
    "brief.operation.read": "Brief reads use the operation's bounded captured-reference API.",
}


def _acquire(kind, *args, _guard=None, _negative=None, _path=None, _before=None,
             _expected_mark=None, _reader=None, **kwargs):
    """One acquisition transaction: validate after IO, before recording or delivery."""
    if kind == "source":
        # Trusted installation metadata, never a user-derived path.
        try:
            return Path(args[0]).resolve()
        except OSError as error:
            raise ValueError("reference parent changed while opening") from error
    guard = _acquisition_guard(_guard)
    opened = transferred = None
    try:
        if kind == "witness":
            ledger = _operation_ledger(guard)
            return ledger.observe(*args) if ledger is not None else None
        if kind == "proof":
            return args[0](*args[1], **args[2])
        if kind == "negative-leaf":
            path, parent = args
            try:
                info = (os.lstat(path) if parent is None else
                        os.stat(path.name, dir_fd=parent, follow_symlinks=False))
            except FileNotFoundError as missing:
                if missing.errno == errno.ENOENT:
                    return
                raise
            _acquisition_replacement(guard, path, info)
        if kind == "peer-directory":
            return _admit_publication_directory(guard, args[0], _before)
        ledger, path = _acquisition_prepare(kind, args, kwargs, guard, _path, _negative)
        mutation = (_AcquisitionMutation(ledger, kind, args, kwargs).capture()
                    if ledger is not None and kind in {"replace", "rename", "unlink"} else None)
        if kind == "mkdir":
            try:
                os.mkdir(*args, **kwargs)
            except FileExistsError as error:
                if error.errno != errno.EEXIST:
                    raise
            return _acquire("peer-directory", path, _guard=guard)
        if kind == "names":
            with os.scandir(args[0]) as entries:
                value = _bounded_directory_names(entries)
        elif kind == "link":
            directory, name, size = args
            buffer = _acquisition_link_buffer(directory, size)
            count = _reader(directory, os.fsencode(name), buffer, size + 1)
            value = buffer.raw[:max(0, min(count, size + 1))]
        elif kind == "stream-read":
            value = args[0].read(*args[1:], **kwargs)
        else:
            value = getattr(os, "fstat" if kind == "identify" else kind)(*args, **kwargs)
        if kind == "open":
            opened = value
        elif kind == "fdopen":
            transferred = value
        descriptor = _acquisition_descriptor(kind, args, value)
        info = (os.fstat(descriptor) if descriptor is not None else
                value if kind in {"stat", "lstat", "fstat", "identify"} else None)
        if mutation is not None:
            mutation.finish()
        elif ledger is not None and not ledger.validating.get():
            if kind == "identify":
                path = ledger.directory_path(args[0], info)
            _AttachmentCheck(ledger, path, info).run()
            if kind in {"open", "stat", "lstat", "fstat", "identify"}:
                path = _acquisition_record(ledger, kind, path, info, value, args, _before)
        _acquisition_expected(guard, _path, value, _expected_mark)
        if kind == "link":
            require(count == size, "public link changed while reading")
        opened = transferred = None
        return (path, value) if kind == "identify" else value
    except BaseException as error:
        _acquisition_close_opened(opened, guard, error)
        if transferred is not None:
            _acquisition_close_transferred(transferred, guard, error)
        _acquisition_observed_error(kind, args, kwargs, guard, error, _path, _negative)
        _acquisition_mkdir_recheck(kind, args, kwargs, guard, error, _path)
        _acquisition_failure(kind, args, guard, error, transferred=transferred is not None)
        if not isinstance(error, Exception):
            raise
        if (isinstance(error, FileNotFoundError) and error.errno == errno.ENOENT
                and _negative is not None and _expected_mark is None):
            _acquisition_absence(guard, _negative, error)
            raise
        if kind in {"open", "mkdir"} and _path is not None and _before is not None:
            _acquisition_recheck_open(guard, _path, _before, args, kwargs)
        _acquisition_refuse(guard, error)

sys.path.insert(0, str(_acquire("source", __file__).parent))
from hierarchy_mailbox import (Mailbox, MAX_BYTES, SHA256, SLUG, TERMINAL_JOB_STATES, digest, encoded,  # noqa: E402
                               endpoint_parts, fields, integer, matching, parse_time, require,
                               strict_json, text)
from hierarchy_lifecycle import Lifecycle, raw_value  # noqa: E402
import hierarchy_lifecycle as life  # noqa: E402
import hierarchy_mailbox as protocol  # noqa: E402
import hierarchy_roles  # noqa: E402
import hierarchy_hosts  # noqa: E402
from hierarchy_operator import MAX_EVIDENCE_BYTES  # noqa: E402


SCHEMA = "aegis.hierarchy-fresh-brief/v1"
SECTIONS = ("Role contract", "Approved scope", "Source identity", "Open obligations",
            "Dependencies", "Unread work", "Evidence references")
MAX_ENTRIES = 256
MAX_LIST_ENTRIES = protocol.MAX_RECORDS
MAX_LIST_BYTES = MAX_LIST_ENTRIES * 1024
MAX_LIFECYCLE_EVIDENCE_BYTES = MAX_EVIDENCE_BYTES
MAX_INPUT_DEPTH = 64
MAX_INPUT_NODES = life.MAX_BYTES
MAX_SYMLINK_BYTES = 4096
MAX_SYMLINK_HOPS = 40
_PATH_GUARD = ContextVar("hierarchy_path_guard", default=None)


def safe_path(value):
    """Use the checked operation boundary instead of pinned bottom-up pathname metadata."""
    from hierarchy_router import _operation_guard, _lexical_path
    path = _lexical_path(value)
    require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
    _operation_guard().check(path)
    return Path(path)


def cli_path(value, flag):
    from hierarchy_router import _lexical_path
    path = _lexical_path(value)
    if not path.is_absolute() or ".." in path.parts:
        return protocol.cli_path(value, flag)
    return safe_path(path)


def _directory_names(directory):
    """Bound discovery itself, including pending/ignored names, before retaining the list."""
    return _acquire("names", directory)


def _bounded_directory_names(entries):
    names, used = [], 0
    for entry in entries:
        require(len(names) < MAX_LIST_ENTRIES, "directory listing exceeds entry limit")
        name = entry.name
        require(len(name) <= MAX_LIST_BYTES - used, "directory listing exceeds byte limit")
        size = len(os.fsencode(name)) + 1
        require(size <= MAX_LIST_BYTES - used, "directory listing exceeds byte limit")
        used += size
        names.append(name)
    return tuple(sorted(names))


def _bounded_json(raw):
    """Bound structure before any recursive schema/hash helper consumes untrusted JSON."""
    try:
        value = strict_json(raw)
    except RecursionError as exc:
        raise ValueError("input nesting exceeds 64 levels") from exc
    pending, used = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        used += 1
        require(depth <= MAX_INPUT_DEPTH, "input nesting exceeds 64 levels")
        require(used <= MAX_INPUT_NODES, "input structure exceeds node limit")
        if isinstance(item, (dict, list)):
            require(len(pending) + used + len(item) <= MAX_INPUT_NODES, "input structure exceeds node limit")
            children = item.values() if isinstance(item, dict) else item
            pending.extend((child, depth + 1) for child in children)
    return value


def _private_paths(value, *, inert=None, paths=None):
    """Bounded iterative preflight of every string, including decoded raw capsules."""
    from hierarchy_router import _operation_guard
    check_path = paths or _operation_guard().refuse
    pending, used = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        used += 1
        require(depth <= MAX_INPUT_DEPTH, "input nesting exceeds 64 levels")
        require(used <= MAX_INPUT_NODES, "input structure exceeds node limit")
        if isinstance(item, dict):
            if inert is not None and set(item) == {"path", "sha256"}:
                inert(item)
                continue
            if set(item) == {"raw", "sha256"}:
                try:
                    decoded = life.raw_value(item)
                except RecursionError as exc:
                    raise ValueError("input nesting exceeds 64 levels") from exc
                pending.append((decoded, depth + 1))
            require(len(pending) + used + 2 * len(item) <= MAX_INPUT_NODES, "input structure exceeds node limit")
            pending.extend((key, depth + 1) for key in reversed(item))
            pending.extend((child, depth + 1) for child in reversed(item.values()))
        elif isinstance(item, list):
            require(len(pending) + used + len(item) <= MAX_INPUT_NODES, "input structure exceeds node limit")
            pending.extend((child, depth + 1) for child in reversed(item))
        elif isinstance(item, str):
            check_path(item)


GLOBAL, ROW_UNKNOWN, ABSENT, QUARANTINE = "global", "row_unknown", "absent", "quarantine"


class _ProofPathError(ValueError):
    """Directory proof failed without establishing a public path."""
    def __init__(self, message, *, acquisition=None):
        super().__init__(message)
        self.acquisition = acquisition


def _fatal_path_error(error, guard=None):
    """Recognize explicit failure causes, never another request's ambient except context."""
    from hierarchy_router import CapturedPolicyError
    identity_error = getattr(guard, "_identity_error", None)
    seen = set()
    for _ in range(MAX_INPUT_DEPTH):
        if error is None or id(error) in seen:
            return None
        seen.add(id(error))
        if isinstance(error, CapturedPolicyError) or error is identity_error:
            return error
        error = error.__cause__
    return CapturedPolicyError("path failure chain exceeds limit")


def _raise_global(error, *, operation=None, guard=None):
    if operation is None and guard is None:
        guard = _PATH_GUARD.get()
    guard = operation.path_guard if operation is not None else guard
    fatal = getattr(guard, "_global_failure", None) or _fatal_path_error(error, guard)
    if fatal is not None:
        latch = getattr(guard, "_latch_global", None)
        if latch is not None:
            fatal = latch(fatal)
        fatal._global_path_failure = fatal._path_failure = True
        if operation is not None:
            operation.fail(fatal)
        raise fatal


class _ProofValue:
    def __init__(self, value):
        self.value = value


class _ProofFailure:
    def __init__(self, stage, error):
        self.stage, self.error = stage, error


class _MetadataDirectory:
    """A diagnostic metadata witness, never authority for a public-chain proof."""
    def __init__(self, path, guard, marks):
        self.path, self.guard, self.marks = path, guard, tuple(marks)
        self.closed = False


class _AbsentReference:
    """A revalidated negative edge and the complete existing directory prefix."""
    def __init__(self, path, ancestors, *, non_directory=False, requested=None):
        self.path, self.ancestors = path, tuple(ancestors)
        self.requested = path if requested is None else requested
        self.non_directory = non_directory
        self.outcome = _AcquisitionOutcome("ABSENT", negative=(self.path, self.ancestors))


class _AcquisitionOutcome:
    """A detected filesystem fact, independent of its caller's refusal contract."""
    def __init__(self, kind, error=None, *, replacement=False, negative=None):
        self.kind, self.error, self.replacement = kind, error, replacement
        self.negative = negative


_private_classification = ContextVar("fresh_private_classification", default=False)



def _acquisition_guard(guard):
    if guard is None:
        from hierarchy_router import _operation_guard
        return _operation_guard()
    return guard



def _acquisition_descriptor(kind, args, value):
    if kind == "open":
        return value
    if kind in {"fstat", "identify", "read", "fdopen"}:
        return args[0]
    if kind == "stream-read":
        return args[0].fileno()
    if kind == "names" and type(args[0]) is int:
        return args[0]
    return None


def _acquisition_observed_error(kind, args, kwargs, guard, error, path, negative):
    """An error cannot authorize a later absent-to-peer recovery."""
    if not isinstance(error, OSError) or error.errno == errno.ENOENT:
        return
    ledger = _operation_ledger(guard)
    if ledger is None or ledger.validating.get() or kind in {"proof", "witness", "peer-directory"}:
        return
    path = ledger.acquisition_path(kind, args, kwargs, path, negative)
    captured = ledger.positive.get(path)
    if path in ledger.negative_edges or captured is not None and captured[2] == stat.S_IFDIR:
        changed = _acquisition_changed(guard)
        changed.__cause__ = error
        if kind in {"open", "mkdir"} and kwargs.get("dir_fd") is not None:
            token = ledger.peer_validation.set(path)
            try:
                info = _acquire("stat", args[0], dir_fd=kwargs["dir_fd"],
                                 follow_symlinks=False, _guard=guard, _path=path)
                _acquisition_replacement(guard, path, info)
            finally:
                ledger.peer_validation.reset(token)
        raise changed


class _AttachmentCheck:
    """A bounded validation transaction; provisional IO never enters the ledger."""
    def __init__(self, ledger, path, info, *, absent=False):
        self.absent = absent
        self.ledger, self.guard, self.path, self.info = ledger, ledger.guard, path, info
        self.positive = ChainMap(ledger.positive, ledger.provisional.get())
        self.stack = []

    def metadata(self, kind, value, *, path, **kwargs):
        return _acquire(kind, value, _guard=self.guard, _path=path, **kwargs)

    def compare(self, path, info, expected):
        if expected is not None and _directory_mark(info) != expected:
            _acquisition_replacement(self.guard, path, info)

    def run(self):
        path, ledger = self.path, self.ledger
        _acquisition_require(path is not None, self.guard, "reference parent changed while opening")
        parents = list(reversed(path.parents)) if path != path.parent else []
        for parent in parents:
            _acquisition_require(parent in self.positive, self.guard, "reference parent changed while opening")
        expected = _directory_mark(self.info) if self.info is not None else self.positive.get(path)
        if self.info is not None:
            self.compare(path, self.info, self.positive.get(path))
            if path in ledger.owned and ledger.owned[path] != file_identity(self.info):
                _acquisition_replacement(self.guard, path, self.info)
        token = ledger.validating.set(True)
        try:
            if _reference_descriptors():
                self.anchored(parents, expected)
            else:
                self.portable(parents, expected)
        except BaseException as error:
            if isinstance(error, Exception):
                _acquisition_refuse(self.guard, error)
            raise
        finally:
            try:
                _close_witness_stack(self.stack, self.guard, sys.exc_info()[1])
            finally:
                ledger.validating.reset(token)

    def leaf(self, parent, expected):
        path = self.path
        if self.absent:
            return _acquire("negative-leaf", path, parent, _guard=self.guard)
        if expected is None:
            _acquisition_require(path in self.ledger.negative_edges, self.guard,
                                 "reference parent changed while opening")
        info = self.metadata("stat", path.name, path=path, dir_fd=parent, follow_symlinks=False)
        self.compare(path, info, expected)

    def keep(self, path, descriptor):
        try:
            self.stack.append((path, descriptor, None))
        except BaseException as error:
            _acquisition_close_opened(descriptor, self.guard, error)
            raise

    def anchored(self, parents, expected):
        path = self.path
        root = Path(path.anchor)
        flags = (_search_directory_flag() or os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
        descriptor = _acquire("open", str(root), flags, _guard=self.guard, _path=root)
        self.keep(root, descriptor)
        root_mark = self.positive.get(root, expected if path == root else None)
        self.compare(root, self.metadata("fstat", descriptor, path=root), root_mark)
        for child in parents[1:]:
            info = self.metadata("stat", child.name, path=child, dir_fd=descriptor, follow_symlinks=False)
            mark = self.positive[child]
            self.compare(child, info, mark)
            _acquisition_require(mark[2] == stat.S_IFDIR, self.guard, "reference parent changed while opening")
            descriptor = _acquire("open", child.name, flags, dir_fd=descriptor, _guard=self.guard, _path=child)
            self.keep(child, descriptor)
            self.compare(child, self.metadata("fstat", descriptor, path=child), mark)
        if path != root:
            self.leaf(descriptor, expected)
        for index in range(len(self.stack) - 1, 0, -1):
            child = self.stack[index][0]
            info = self.metadata("stat", child.name, path=child, dir_fd=self.stack[index - 1][1],
                                 follow_symlinks=False)
            self.compare(child, info, self.positive[child])
        self.compare(root, self.metadata("lstat", root, path=root), root_mark)

    def portable(self, parents, expected):
        # Unsupported platforms retain metadata witnesses, never proof authority.
        for parent in parents:
            self.compare(parent, self.metadata("lstat", parent, path=parent), self.positive[parent])
        if self.absent:
            _acquire("negative-leaf", self.path, None, _guard=self.guard)
        else:
            self.compare(self.path, self.metadata("lstat", self.path, path=self.path), expected)
        for parent in reversed(parents):
            self.compare(parent, self.metadata("lstat", parent, path=parent), self.positive[parent])



class _AcquisitionMutation:
    """Validate both endpoints of a publication mutation before admitting its effect."""
    def __init__(self, ledger, kind, args, kwargs):
        self.ledger, self.guard, self.kind, self.args, self.kwargs = ledger, ledger.guard, kind, args, kwargs
        source_fd = kwargs.get("dir_fd") if kind == "unlink" else kwargs.get("src_dir_fd")
        receipt = ledger.handles.get(source_fd)
        _acquisition_require(receipt is not None, self.guard, "reference parent changed while opening")
        self.source, self.source_fd = receipt[0] / args[0], source_fd
        self.destination = None
        if kind != "unlink":
            destination = ledger.handles.get(kwargs.get("dst_dir_fd"))
            _acquisition_require(destination is not None, self.guard, "reference parent changed while opening")
            self.destination = destination[0] / args[1]
        self.info = None

    def capture(self):
        ledger = self.ledger
        _acquisition_require(self.source.parent in ledger.outputs, self.guard,
                             "reference parent changed while opening")
        token = ledger.validating.set(True)
        try:
            self.info = _acquire("stat", self.source.name, dir_fd=self.source_fd,
                follow_symlinks=False, _guard=self.guard, _path=self.source)
        finally:
            ledger.validating.reset(token)
        _AttachmentCheck(ledger, self.source, self.info).run()
        _acquisition_identity(self.guard, self.source, self.info)
        owned = ledger.owned.get(self.source) == file_identity(self.info)
        expected = ledger.positive.get(self.source)
        _acquisition_require(owned or expected == _directory_mark(self.info), self.guard,
                             "reference parent changed while opening")
        if self.destination is not None:
            _acquisition_require(owned and self.destination in ledger.outputs, self.guard,
                                 "reference parent changed while opening")
            _AttachmentCheck(ledger, self.destination, None, absent=True).run()
        return self

    def finish(self):
        _AttachmentCheck(self.ledger, self.source, None, absent=True).run()
        if self.destination is not None:
            _AttachmentCheck(self.ledger, self.destination, self.info).run()
            self.ledger.observe("effect", self.destination, file_identity(self.info))


def _admit_publication_directory(guard, path, before):
    opened = None
    try:
        with _peer_publication_directory(guard, path, before) as peer:
            peer.directory(_acquire("stat", path.name, dir_fd=peer.parent,
                                    follow_symlinks=False, _guard=guard, _path=path))
            opened = _acquire("open", path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=peer.parent, _guard=guard, _path=path, _before=peer.info)
            peer.directory(_acquire("fstat", opened, _guard=guard, _path=path))
            for _ in range(2):
                names = _acquire("names", opened, _guard=guard, _path=path)
                peer.names(names)
                for name in names:
                    peer.name(name)
                    peer.entry(name, _acquire("stat", name, dir_fd=opened, follow_symlinks=False,
                                             _guard=guard, _path=path / name))
            peer.recheck_parent()
            peer.directory(_acquire("fstat", opened, _guard=guard, _path=path))
            peer.directory(_acquire("stat", path.name, dir_fd=peer.parent,
                                    follow_symlinks=False, _guard=guard, _path=path))
            peer.admit(opened)
        value, opened = opened, None
        return value
    finally:
        _acquisition_close_opened(opened, guard, sys.exc_info()[1])


def _acquisition_mkdir_recheck(kind, args, kwargs, guard, error, path):
    if (kind != "mkdir" or path is None or not isinstance(error, OSError)
            or error.errno not in {errno.ENOENT, errno.ENOTDIR, errno.ELOOP}):
        return
    ledger = _operation_ledger(guard)
    token = ledger.peer_validation.set(path) if ledger is not None else None
    try:
        # This is refusal diagnostics, never permission to adopt a peer. Preserve
        # an observed private replacement before reducing the original errno.
        _acquire("stat", args[0], dir_fd=kwargs.get("dir_fd"), follow_symlinks=False,
                 _guard=guard, _path=path)
    finally:
        if token is not None:
            ledger.peer_validation.reset(token)


def _acquisition_expected(guard, path, value, expected):
    if expected is not None:
        if _reference_mark(value) != expected:
            _acquisition_replacement(guard, path, value)
        _acquire("witness", "ancestor", path, value, _guard=guard)


def _acquisition_absence(guard, negative, error):
    path, expected = negative
    check = final = None
    try:
        try:
            path, expected = _acquisition_negative_expected(guard, path, expected)
            if _descriptor_capabilities():
                check, marks = _proof_parent(path.parent, _guard=guard, _expected=expected)
                _acquisition_require(len(marks) == len(path.parent.parts)
                        and (expected is None or _same_path_ancestors(marks, expected)),
                        guard, "reference parent changed while opening")
                _acquire("negative-leaf", path, check, _guard=guard)
                final, after = _proof_parent(path.parent, _guard=guard, _expected=marks)
                _acquisition_require(_same_path_ancestors(marks, after), guard,
                                     "reference parent changed while opening")
            else:
                marks = _reference_ancestors(path, _guard=guard, _expected=expected)
                _acquire("negative-leaf", path, None, _guard=guard)
                after = _reference_ancestors(path, _guard=guard, _expected=marks)
                _acquisition_require(_same_path_ancestors(marks, after), guard,
                                     "reference parent changed while opening")
        finally:
            _acquisition_close_negative(final, check)
    except Exception as failed:
        _acquisition_refuse(guard, failed)
    _acquire("witness", "negative", _AbsentReference(path, expected), _guard=guard)
    _acquisition_detect(guard, "ABSENT", error, negative=(path, expected))


@contextmanager
def _peer_publication_directory(guard, path, before):
    ledger = _operation_ledger(guard)
    captured = ledger.peer_directory(path) if ledger is not None else None
    _acquisition_require(captured is not None, guard, "reference parent changed while opening")
    parent, marks = _proof_parent(path.parent, _guard=guard, _expected=captured.ancestors)
    token = ledger.peer_validation.set(path)
    provisional = ledger.provisional.set({})
    try:
        _acquisition_require(_same_path_ancestors(marks, captured.ancestors), guard,
                             "reference parent changed while opening")
        info = _acquire("fstat", parent, _guard=guard)
        yield _PeerPublicationDirectory(ledger, path, parent, info, captured, before)
    finally:
        try:
            _close_rechecked_reference(parent, guard, sys.exc_info()[1])
        finally:
            ledger.provisional.reset(provisional)
            ledger.peer_validation.reset(token)


class _PeerPublicationDirectory:
    """Provisional peer metadata; no witness is rebound before validation."""
    def __init__(self, ledger, path, parent, parent_info, captured, before):
        self.ledger, self.path, self.parent = ledger, path, parent
        self.owner, self.parent_identity = os.geteuid(), file_identity(parent_info)
        self.captured, self.before, self.info = captured, before, None
        self.listing, self.entries = None, {}

    def directory(self, info):
        guard = self.ledger.guard
        _acquisition_identity(guard, self.path, info)
        _acquisition_require(stat.S_ISDIR(info.st_mode) and not _reparse(info)
                and info.st_uid == self.owner and stat.S_IMODE(info.st_mode) == 0o700,
                guard, "reference parent changed while opening")
        previous = self.info if self.info is not None else self.before
        if previous is not None and _directory_mark(previous) != _directory_mark(info):
            _acquisition_replacement(guard, self.path, info)
        self.info = info
        self.ledger.provisional.get()[self.path] = _directory_mark(info)

    def names(self, names):
        _acquisition_require(self.listing is None or self.listing == names, self.ledger.guard,
                             "reference parent changed while opening")
        self.listing = names

    def name(self, name):
        _acquisition_require(re.fullmatch(r"(?:(?:fresh|check)-[a-f0-9]{64}[.]md|[.]fresh-[a-f0-9]{32})", name) is not None,
                             self.ledger.guard, "reference parent changed while opening")

    def entry(self, name, info):
        guard = self.ledger.guard
        _acquisition_identity(guard, self.path / name, info)
        _acquisition_require(stat.S_ISREG(info.st_mode) and not _reparse(info) and info.st_uid == self.owner
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and 0 <= info.st_size <= MAX_BYTES,
                guard, "reference parent changed while opening")
        mark = _directory_mark(info)
        _acquisition_require(name not in self.entries or self.entries[name] == mark,
                             guard, "reference parent changed while opening")
        self.entries.setdefault(name, mark)

    def recheck_parent(self):
        guard = self.ledger.guard
        parent, marks = _proof_parent(self.path.parent, _guard=guard, _expected=self.captured.ancestors)
        try:
            _acquisition_require(_same_path_ancestors(marks, self.captured.ancestors)
                    and file_identity(_acquire("fstat", parent, _guard=guard)) == self.parent_identity,
                    guard, "reference parent changed while opening")
        finally:
            _close_rechecked_reference(parent, guard, sys.exc_info()[1])

    def admit(self, descriptor):
        _acquisition_require(self.ledger.peer_directory(self.path, validating=True) is self.captured, self.ledger.guard,
                             "reference parent changed while opening")
        # The ruling admits this one absent-to-validated-peer-directory effect.
        # Keep the original negative object; all later identities must match.
        self.ledger.observe("effect", self.path, file_identity(self.info))
        self.ledger.acquired("open", self.path, self.info, descriptor=descriptor)
        self.ledger.peer_directories.discard(self.path)


def _acquisition_prepare(kind, args, kwargs, guard, path, negative):
    if kind not in {"open", "mkdir", "stat", "lstat", "fstat", "identify", "read", "fdopen", "names", "link", "stream-read", "replace", "rename", "unlink"}:
        raise KeyError(kind)
    ledger = _operation_ledger(guard)
    if ledger is not None and ledger.validating.get():
        return ledger, path
    if kind == "identify":
        return ledger, None
    # Relative lookups use the caller's held parent acquired through this
    # boundary. Namespace changes cannot replace that descriptor's inode.
    # Borrowed directory/stream entry points bind before exposing content.
    if ledger is not None and kind in {"names", "link"} and type(args[0]) is int and ledger.peer_validation.get() is None:
        _bind_directory_descriptor(args[0], guard, revalidate=kind == "names")
    path = ledger.acquisition_path(kind, args, kwargs, path, negative) if ledger is not None else path
    if kind in {"names", "link", "read", "fdopen", "stream-read"} and ledger is not None:
        if kind in {"read", "fdopen", "stream-read"}:
            descriptor = args[0].fileno() if kind == "stream-read" else args[0]
            _acquire("fstat", descriptor, _guard=guard, _path=path)
        elif kind == "names":
            if type(args[0]) is not int:
                _acquire("lstat", args[0], _guard=guard, _path=path)
        else:
            _acquire("stat", args[1], dir_fd=args[0], follow_symlinks=False,
                     _guard=guard, _path=path)
    return ledger, path


def _acquisition_record(ledger, kind, path, info, value, args, before):
    if ledger.peer_validation.get() is not None and path is not None and (path == ledger.peer_validation.get() or ledger.peer_validation.get() in path.parents):
        return path
    if kind == "identify":
        path = ledger.directory_path(args[0], info)
        ledger.observe("descriptor", path, (args[0], info))
        kind = "fstat"
    if ledger.peer_directories and ledger.peer_directory(path) is not None:
        peer = _acquire("peer-directory", path, _guard=ledger.guard, _before=info)
        _close_rechecked_reference(peer, ledger.guard, None)
    owned = kind == "open" and bool(args[1] & os.O_CREAT and args[1] & os.O_EXCL)
    ledger.acquired(kind, path, info,
                    descriptor=value if kind in {"open", "mkdir"} else args[0] if kind == "fstat" else None,
                    owned=owned)
    return path


def _bind_directory_descriptor(descriptor, guard, *, revalidate=True):
    ledger = _operation_ledger(guard)
    previous = ledger.handles.get(descriptor)
    path, info = _acquire("identify", descriptor, _guard=guard)
    # A receipt identifies an inode, not its current ancestor attachment. Even
    # the same descriptor can outlive a rename. Names reach the caller here;
    # link text stays inside its existing complete-chain proof boundary.
    if revalidate or previous is None or previous[:2] != (path, file_identity(info)):
        _bind_descriptor(descriptor, info, path, guard, content=False)


def _acquisition_recheck_open(guard, path, before, args, kwargs):
    try:
        now = _acquire("stat", args[0], dir_fd=kwargs.get("dir_fd"),
                       follow_symlinks=False, _guard=guard, _path=path)
    except Exception as checking:
        _raise_global(checking, guard=guard)
        observed = _acquisition_fact(checking)
        if observed is not None and (observed.kind == "PRIVATE" or _operation_ledger(guard) is not None):
            # A ledger already latched this observation; never reduce its typed
            # cause to the earlier syscall's diagnostic. Legacy readers without
            # an operation retain their original OS-error priority.
            raise
    else:
        if _reference_mark(now) != _reference_mark(before):
            _acquisition_replacement(guard, path, now)


def _acquisition_link_buffer(directory, size):
    import ctypes
    require(type(size) is int and 0 < size <= MAX_SYMLINK_BYTES, "public link proof unavailable")
    require(type(directory) is int and directory >= 0, "public link proof unavailable")
    return ctypes.create_string_buffer(size + 1)


def _acquisition_close_opened(opened, guard, error):
    if opened is not None:
        try:
            os.close(opened)
        except OSError as closing:
            _raise_global(error, guard=guard)
            _raise_global(closing, guard=guard)


def _acquisition_close_transferred(stream, guard, error):
    try:
        stream.close()
    except BaseException as closing:
        _raise_global(error, guard=guard)
        _raise_global(closing, guard=guard)
        if not isinstance(closing, Exception):
            raise
        _acquisition_refuse(guard, error)


def _acquisition_close_negative(final, check):
    try:
        if final is not None:
            _proof_close(final, os.close)
    finally:
        if check is not None:
            _proof_close(check, os.close)


def _operation_ledger(guard):
    context = getattr(guard, "_witness_context", None)
    return context.get() if context is not None else None


def _private_context(guard):
    ledger = _operation_ledger(guard)
    return ledger.classification if ledger is not None else _private_classification


def _acquisition_negative_expected(guard, path, expected):
    if expected is None:
        ledger = _operation_ledger(guard)
        captured = (ledger.output_negatives.get(path) or ledger.negatives.get(path)) if ledger is not None else None
        if captured is not None:
            if path in ledger.outputs and captured.path in ledger.outputs and captured.path in ledger.positive:
                return path, ledger.prefix(path.parent)
            return captured.path, captured.ancestors
        missing, _marks = _scope_reference_info(path, guard)
        _acquisition_require(isinstance(missing, _AbsentReference), guard,
                             "reference parent changed while opening")
        return missing.path, missing.ancestors
    return path, expected


class _WitnessLedger:
    """Write-once namespace witnesses; known output effects retain their original negatives."""
    def __init__(self, guard, parent=None):
        self.guard = guard
        if parent is not None:
            _acquisition_require(sum(map(len, (parent.positive, parent.negatives, parent.outputs,
                parent.effects, parent.output_negatives, parent.prospective, parent.handles, parent.owned))) <= MAX_INPUT_NODES, guard,
                "reference parent changed while opening")
        self.positive = {} if parent is None else dict(parent.positive)
        self.negatives = {} if parent is None else dict(parent.negatives)
        self.outputs = set() if parent is None else set(parent.outputs)
        self.effects = {} if parent is None else dict(parent.effects)
        self.owned = {} if parent is None else dict(parent.owned)
        self.output_negatives = {} if parent is None else dict(parent.output_negatives)
        self.prospective = set() if parent is None else set(parent.prospective)
        self.handles = {} if parent is None else dict(parent.handles)
        self.negative_edges = {} if parent is None else dict(parent.negative_edges)
        self.peer_directories = set()
        self.peer_validation = ContextVar("fresh_peer_directory_validation", default=None)
        self.classification = ContextVar("fresh_witness_private_diagnostic", default=False)
        self.validating = ContextVar("fresh_attachment_validation", default=False)
        self.provisional = ContextVar("fresh_provisional_directory", default={})

    def peer_directory(self, path, *, validating=False):
        if path not in self.peer_directories:
            return None
        captured = self.negative_edges.get(path)
        if ((validating or self.peer_validation.get() != path)
                and path in self.outputs
                and path not in self.positive and path not in self.effects
                and captured is not None and captured.path == path and captured in self.prospective):
            return captured
        return None

    def directory_path(self, descriptor, info):
        """A borrowed directory may route only to an already captured identity."""
        mark = _directory_mark(info)
        previous = self.handles.get(descriptor)
        if previous is not None and self.positive.get(previous[0]) == mark and previous[1] == file_identity(info):
            return previous[0]
        matches = [path for path, expected in self.positive.items() if expected == mark]
        _acquisition_require(stat.S_ISDIR(info.st_mode) and len(matches) == 1, self.guard,
                             "reference parent changed while opening")
        return matches[0]

    def acquisition_path(self, kind, args, kwargs, path, negative):
        """Bind relative operations to a descriptor acquired through this boundary."""
        if path is not None:
            return path if isinstance(path, Path) else Path(path)
        if negative is not None:
            return negative[0] if isinstance(negative[0], Path) else Path(negative[0])
        if kind in {"fstat", "read", "fdopen", "stream-read"}:
            descriptor = args[0].fileno() if kind == "stream-read" else args[0]
            receipt = self.handles.get(descriptor)
            _acquisition_require(receipt is not None, self.guard, "reference parent changed while opening")
            return receipt[0]
        descriptor = (kwargs.get("dst_dir_fd") if kind in {"replace", "rename"} else
            args[0] if kind == "link" or kind == "names" and type(args[0]) is int else kwargs.get("dir_fd"))
        value = args[1] if kind in {"link", "replace", "rename"} else args[0]
        if descriptor is not None:
            receipt = self.handles.get(descriptor)
            _acquisition_require(receipt is not None, self.guard, "reference parent changed while opening")
            return receipt[0] if kind == "names" else receipt[0] / value
        path = Path(value)
        _acquisition_require(path.is_absolute(), self.guard, "reference parent changed while opening")
        return path

    def acquired(self, kind, path, info, *, descriptor=None, owned=False):
        """Compare before exposure; handle receipts carry no new input authority."""
        previous = self.handles.get(descriptor) if descriptor is not None and kind == "fstat" else None
        if previous is not None:
            if previous[0] != path or previous[1] != file_identity(info):
                _acquisition_replacement(self.guard, path, info)
            owned = previous[2]
        _acquisition_identity(self.guard, path, info)
        if owned:
            _acquisition_require(path.parent in self.outputs, self.guard, "reference parent changed while opening")
        self.observe("owned" if owned else "ancestor", path, info)
        if kind in {"open", "mkdir"}:
            _acquisition_require(descriptor in self.handles or len(self.handles) < MAX_INPUT_NODES,
                                 self.guard, "reference parent changed while opening")
            self.handles[descriptor] = path, file_identity(info), owned

    def prefix(self, path):
        result, current = [], None
        for component in path.parts:
            current = Path(component) if current is None else current / component
            _acquisition_require(current in self.positive, self.guard, "reference parent changed while opening")
            result.append((component, self.positive[current]))
        return tuple(result)

    def observe(self, kind, path, value=None):
        if kind == "negative":
            absent = path
            path = absent.path
            if path in self.positive or path in self.effects:
                raise _acquisition_changed(self.guard)
            destination = self.negatives
            previous = self.negatives.get(absent.requested)
            if (previous is not None and previous.path != path and absent.requested in self.outputs
                    and previous.path in self.outputs and previous.path in self.positive):
                # Keep the initial edge. A known output directory creation has
                # its own subsequent leaf-negative witness, never a replacement
                # for the operation's original observation.
                destination = self.output_negatives
                previous = destination.get(absent.requested)
            if previous is not None:
                _acquisition_require(previous.path == path
                    and _same_ancestors(previous.ancestors, absent.ancestors), self.guard,
                    "reference parent changed while opening")
            captured = destination.setdefault(absent.requested, absent)
            self.negative_edges.setdefault(path, captured)
            # Only first capture can carry namespace intent. Rechecking an
            # earlier input absence never grants publication permission.
            if previous is None and (path in self.outputs or path.parent in self.outputs):
                self.prospective.add(captured)
            return absent
        path = path if isinstance(path, Path) else Path(path)
        if kind == "descriptor":
            descriptor, info = value
            _acquisition_require(path in self.positive and self.positive[path] == _directory_mark(info),
                                 self.guard, "reference parent changed while opening")
            _acquisition_require(descriptor in self.handles or len(self.handles) < MAX_INPUT_NODES,
                                 self.guard, "reference parent changed while opening")
            self.handles[descriptor] = path, file_identity(info), False
            return
        if kind in {"output", "output-directory"}:
            # An early namespace declaration may select its prospective leaf
            # for publication. Original input negatives stay immutable.
            namespace = kind == "output" and path.parent in self.outputs
            for output in ((path,) if kind == "output-directory" else (path.parent, path)):
                _acquisition_require(output in self.outputs or not any(
                    item.path == output and not (namespace and output == path and item in self.prospective)
                    for item in self.negatives.values()), self.guard,
                    "reference parent changed while opening")
                self.outputs.add(output)
            return
        if kind == "publication-directory":
            _acquisition_require(path in self.outputs, self.guard, "reference parent changed while opening")
            if path in self.positive or path in self.effects:
                return
            _acquisition_require(path in self.peer_directories or len(self.peer_directories) < MAX_INPUT_NODES,
                                 self.guard, "reference parent changed while opening")
            self.peer_directories.add(path)
            return
        if kind == "effect":
            _acquisition_require(path in self.outputs, self.guard, "reference parent changed while opening")
            previous = self.effects.setdefault(path, value)
            _acquisition_require(previous == value, self.guard, "reference parent changed while opening")
            return
        require(kind in {"ancestor", "owned"}, "invalid witness kind")
        mark = _directory_mark(value)
        previous = self.positive.get(path)
        # An admitted positive already has its complete immutable parent graph.
        # Rechecking that membership only rebuilds Path objects; identities and
        # negative edges still compare on every acquisition below.
        changed = (previous is None and path != path.parent and path.parent not in self.positive or
            previous is not None and previous != mark or
            path in self.effects and self.effects[path] != file_identity(value)) or (path in self.negative_edges and path not in self.effects)
        if changed:
            error = _acquisition_changed(self.guard)
            if self.classification.get():
                # The mismatch is already latched. Finish only the diagnostic
                # link lookup so a typed privacy cause can take precedence;
                # this observation never enters the ledger or certifies input.
                return
            raise error
        if kind == "owned":
            identity = file_identity(value)
            _acquisition_require(path in self.owned or len(self.owned) < MAX_INPUT_NODES, self.guard,
                                 "reference parent changed while opening")
            _acquisition_require(self.owned.setdefault(path, identity) == identity, self.guard,
                                 "reference parent changed while opening")
        if kind == "ancestor" and not _reparse(value):
            self.positive.setdefault(path, mark)

    def _check(self, path, info, mark):
        _acquisition_identity(self.guard, path, info, replacement=_directory_mark(info) != mark)
        if _directory_mark(info) != mark:
            _acquisition_replacement(self.guard, path, info)

    def _negative(self, absent, descriptor):
        path = absent.path
        try:
            info = (_acquire("stat", path.name, dir_fd=descriptor, follow_symlinks=False,
                             _guard=self.guard, _negative=(path, absent.ancestors))
                    if descriptor is not None else _acquire("lstat", path, _guard=self.guard,
                             _negative=(path, absent.ancestors)))
        except FileNotFoundError:
            return
        _acquisition_replacement(self.guard, path, info)

    def verify(self):
        """Walk attached children, then check each attachment again after its descendants."""
        children, negatives = {}, {}
        for path in self.positive:
            if path != path.parent:
                children.setdefault(path.parent, []).append(path)
        for absent in (*self.negatives.values(), *self.output_negatives.values()):
            path = absent.path
            if path not in self.positive and path not in self.effects:
                negatives[path] = absent
        for path, absent in negatives.items():
            # Keep the original complete chain; no discovery may move this edge.
            _acquisition_require(all(parent in self.positive for parent in path.parents), self.guard,
                                 "reference parent changed while opening")
        if not _reference_descriptors():
            ordered = sorted(self.positive.items(), key=lambda item: len(item[0].parts))
            for path, mark in ordered:
                self._check(path, _acquire("lstat", path, _guard=self.guard), mark)
            for path in negatives:
                self._negative(negatives[path], None)
            for path, mark in ordered:
                if mark[2] == stat.S_IFDIR:
                    self._check(path, _acquire("lstat", path, _guard=self.guard), mark)
            return
        roots = [path for path in self.positive if path == path.parent]
        for root in roots:
            self._verify_root(root, children, negatives)

    def _verify_root(self, root, children, negatives):
        flags = (_search_directory_flag() or os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
        stack = []
        try:
            descriptor = _acquire("open", str(root), flags, _guard=self.guard)
            stack.append((root, descriptor, iter(children.get(root, ()))))
            self._check(root, _acquire("fstat", descriptor, _guard=self.guard), self.positive[root])
            while stack:
                path, descriptor, pending = stack[-1]
                child = next(pending, None)
                if child is not None:
                    info = _acquire("stat", child.name, dir_fd=descriptor, follow_symlinks=False, _guard=self.guard)
                    self._check(child, info, self.positive[child])
                    if self.positive[child][2] != stat.S_IFDIR:
                        continue
                    opened = _acquire("open", child.name, flags, dir_fd=descriptor, _guard=self.guard,
                                      _path=child, _before=info)
                    stack.append((child, opened, iter(children.get(child, ()))))
                    self._check(child, _acquire("fstat", opened, _guard=self.guard), self.positive[child])
                    continue
                for absent in negatives:
                    if absent.parent == path:
                        self._negative(negatives[absent], descriptor)
                for output, identity in self.effects.items():
                    if output.parent == path:
                        info = _acquire("stat", output.name, dir_fd=descriptor, follow_symlinks=False, _guard=self.guard)
                        if file_identity(info) != identity:
                            _acquisition_replacement(self.guard, output, info)
                if len(stack) > 1:
                    info = _acquire("stat", path.name, dir_fd=stack[-2][1], follow_symlinks=False, _guard=self.guard)
                    self._check(path, info, self.positive[path])
                stack.pop()
                _close_rechecked_reference(descriptor, self.guard, None)
        finally:
            _close_witness_stack(stack, self.guard, sys.exc_info()[1])


def _close_witness_stack(stack, guard, error):
    """Release every ancestor even when cleanup also fails; keep the strongest cause."""
    failure = error
    while stack:
        _path, descriptor, _pending = stack.pop()
        try:
            _close_rechecked_reference(descriptor, guard, failure)
        except BaseException as cleanup:
            failure = cleanup
    if failure is not error:
        _acquisition_refuse(guard, failure)



def _acquisition_detect(guard, kind, error=None, *, replacement=False, negative=None):
    """Latch an observed change/privacy cause before diagnostics or optional IO."""
    previous = getattr(error, "_acquisition_outcome", None)
    replacement = replacement or bool(previous is not None and previous.replacement)
    outcome = _AcquisitionOutcome(kind, error, replacement=replacement or kind == "CHANGED", negative=negative)
    if error is not None:
        error._acquisition_outcome = outcome
    if kind == "CHANGED" or kind == "PRIVATE" and replacement:
        context = getattr(guard, "_acquisition_context", None)
        owner = context.get() if context is not None else None
        if owner is not None:
            owner.fail(error)
    return outcome


def _acquisition_changed(guard, message="reference parent changed while opening"):
    error = ValueError("reference parent changed while opening")
    _acquisition_detect(guard, "CHANGED", error)
    return error


def _acquisition_refuse(guard, error):
    """Refuse an unproved acquisition error before any caller can reduce it."""
    from hierarchy_router import PrivatePathError
    _raise_global(error, guard=guard)
    if isinstance(error, PrivatePathError):
        _acquisition_detect(guard, "PRIVATE", error, replacement=True)
        raise error
    raise _acquisition_changed(guard) from error


def _acquisition_failure(kind, args, guard, error, *, transferred=False):
    """Release transferred handles before propagating a captured policy failure."""
    if kind == "fdopen" and not transferred:
        # fdopen has not accepted ownership if it raises.
        try:
            os.close(args[0])
        except OSError as closing:
            _raise_global(error, guard=guard)
            _acquisition_refuse(guard, closing)
    _raise_global(error, guard=guard)
    detected = _acquisition_fact(error)
    if detected is not None and (kind == "witness" or detected.kind == "CHANGED"):
        raise error
    observed = _acquisition_fact(error)
    if observed is not None and observed.kind == "PRIVATE" and not observed.replacement:
        raise error
    if kind == "proof":
        from hierarchy_router import PrivatePathError
        if isinstance(error, PrivatePathError):
            _acquisition_detect(guard, "PRIVATE", error)
            raise error
        observed = _acquisition_fact(error)
        if observed is not None and observed.kind == "ABSENT":
            raise error
        if observed is not None and observed.kind == "PRIVATE":
            raise observed.error if observed.replacement else error


def _acquisition_require(condition, guard, message):
    if not condition:
        raise _acquisition_changed(guard, message)


def _acquisition_replacement(guard, path, info=None):
    """Inspect a replacement before reducing its observed cause to a mismatch."""
    from hierarchy_router import PrivatePathError
    if info is not None:
        _acquisition_identity(guard, path, info, replacement=True)
        if stat.S_ISLNK(info.st_mode) or _reparse(info):
            result = _private_symlink_target(guard, path, path)
            if isinstance(result, _ProofFailure):
                error = result.error
                if isinstance(error, PrivatePathError):
                    _acquisition_detect(guard, "PRIVATE", error, replacement=True)
                    raise error
    raise _acquisition_changed(guard)


def _acquisition_open_refusal(error, guard, path, directory, *, before, ancestors):
    """The errno triggers a check; the anchored witness decides the outcome."""
    if directory is not None:
        proof = _ProvedChain(guard, path, (), (), directory, path, ancestors)
        _LeafLookup("present" if before is not None else "error", before if before is not None else error, proof)
        _recheck_scope_witness(proof)
    else:
        # Ordinary portable readers retain metadata diagnostics. They cannot
        # certify a fresh-brief proof through this branch.
        if ancestors:
            _acquisition_require(_same_ancestors(_reference_ancestors(path, _guard=guard), ancestors),
                                 guard, "reference parent changed while opening")
        info = _acquire("lstat", path, _guard=guard)
        changed = before is not None and _reference_mark(info) != _reference_mark(before)
        _acquisition_identity(guard, path, info, replacement=changed)
        if changed:
            _acquisition_replacement(guard, path, info)
        if ancestors:
            _acquisition_require(_same_ancestors(_reference_ancestors(path, _guard=guard), ancestors),
                                 guard, "reference parent changed while opening")
    _acquisition_refuse(guard, error)


def _acquisition_identity(guard, path, info, *, replacement=False, revalidating=False):
    ledger = _operation_ledger(guard)
    canonical = path if isinstance(path, Path) else Path(path)
    previous = ledger.positive.get(canonical) if ledger is not None else None
    replacement = replacement or previous is not None and previous != _directory_mark(info)
    effect = ledger.effects.get(canonical) if ledger is not None else None
    replacement = replacement or effect is not None and effect != file_identity(info)
    replacement = replacement or ledger is not None and canonical in ledger.negative_edges
    try:
        guard.check_identity(path, info)
    except ValueError as exc:
        from hierarchy_router import PrivatePathError
        if isinstance(exc, PrivatePathError):
            _acquisition_detect(guard, "PRIVATE", exc, replacement=replacement or revalidating)
        raise
    if replacement and not _private_context(guard).get() and (stat.S_ISLNK(info.st_mode) or _reparse(info)):
        from hierarchy_router import PrivatePathError
        result = _private_symlink_target(guard, path, path)
        if isinstance(result, _ProofFailure) and isinstance(result.error, PrivatePathError):
            _acquisition_detect(guard, "PRIVATE", result.error, replacement=True)
            raise result.error


def _acquisition_ancestor(guard, path, info, expected, *, replacement=False, identity_path=None):
    """Compare a later walk with this acquisition's already captured prefix."""
    index = len(path.parts) - 1
    previous = expected[index] if index < len(expected) else None
    changed = previous is not None and (previous[0] != (path.name or path.anchor)
        or not _same_mark(_directory_mark(info), previous[1]))
    # Active-ledger observations were already screened by _acquire.
    if _operation_ledger(guard) is None:
        _acquisition_identity(guard, path if identity_path is None else identity_path, info,
                              replacement=replacement or changed)
    if changed:
        _acquisition_replacement(guard, path, info)
    _acquire("witness", "ancestor", path, info, _guard=guard)


def _acquisition_map(outcome, caller):
    """Only an anchored negative witness permits absence reduction."""
    if outcome.kind == "ABSENT":
        return ABSENT
    if outcome.kind == "PRIVATE" and not outcome.replacement:
        return QUARANTINE
    return GLOBAL


def _acquisition_fact(error):
    """Carry an already detected fact through public diagnostic wrappers."""
    seen = set()
    for _ in range(MAX_INPUT_DEPTH):
        if error is None or id(error) in seen:
            return None
        seen.add(id(error))
        outcome = getattr(error, "_acquisition_outcome", None)
        if outcome is not None:
            return outcome
        error = error.__cause__
    return None


def _acquisition_caller(guard, *, trust=False):
    context = getattr(guard, "_acquisition_route", None)
    return "trust" if trust else context.get() if context is not None else "public"


def _acquisition_error(error, guard, *, caller="public", path=None):
    """A detected change always refuses; policy privacy keeps its typed cause."""
    outcome = _acquisition_fact(error)
    if outcome is not None and outcome.kind == "CHANGED":
        mapped = ValueError("reference parent changed while opening")
        mapped._acquisition_outcome = outcome
        raise mapped from error
    if outcome is not None and outcome.kind == "PRIVATE" and outcome.replacement:
        raise outcome.error
    raise error


def _metadata_ancestor_marks(path, guard):
    require(len(path.parts) <= MAX_INPUT_NODES, "public chain proof exceeds limit")
    marks, current = [], None
    for component in path.parts:
        current = Path(component) if current is None else current / component
        guard.refuse(current)
        info = _acquire("lstat", current, _guard=guard)
        _acquisition_ancestor(guard, current, info, ())
        _reference_directory(info, current, _ancestors=marks, _guard=guard)
        require(info.st_ino, "public component identity unavailable")
        marks.append((component, _directory_mark(info)))
    return marks


def _metadata_parent_recheck(directory):
    from hierarchy_router import PrivatePathError, SymlinkPathError
    if directory.closed:
        raise _ProofPathError("public metadata witness already closed")
    try:
        marks = tuple(_metadata_ancestor_marks(directory.path, directory.guard))
    except (PrivatePathError, SymlinkPathError) as exc:
        exc._unproved_ancestor = True
        raise
    except (ValueError, OSError) as exc:
        _raise_global(exc, guard=directory.guard)
        raise _ProofPathError("public ancestor changed") from exc
    if marks != directory.marks:
        raise _ProofPathError("public ancestor changed")


def _metadata_info(directory, name=None):
    _metadata_parent_recheck(directory)
    pending = None
    try:
        return _acquire("lstat", directory.path / name if name else directory.path, _guard=directory.guard)
    except BaseException as exc:
        pending = exc
        raise
    finally:
        try:
            _metadata_parent_recheck(directory)
        finally:
            _raise_global(pending, guard=directory.guard)


def _proof_close(directory, close):
    if isinstance(directory, _MetadataDirectory):
        directory.closed = True
    else:
        close(directory)


def _require_proof_descriptor(directory):
    if type(directory) is not int or directory < 0:
        raise _ProofPathError("public chain requires descriptor anchoring")
    return directory


class _ProvedChain:
    def __init__(self, guard, original, observations, links, directory=None, leaf=None, ancestors=()):
        if directory is not None:
            _require_proof_descriptor(directory)
        self.guard, self.original = guard, original
        self.observations, self.links = tuple(observations), tuple(links)
        self.directory, self.leaf, self.valid = directory, leaf, True
        self.ancestors = ancestors
        self.leaf_outcome = None
        self.expected = None
        self.expected_ancestors = ()
        self.reference_mark = None
        self.failure = None

    def proved(self, guard):
        if not self.valid or guard is not self.guard:
            return False
        result = _proof_operation(guard, "recheck", _proof_recheck, self)
        self.valid = isinstance(result, _ProofValue)
        self.failure = result.error if isinstance(result, _ProofFailure) else None
        return self.valid


class _LinkLookupFailure:
    """Only a final-leaf failure can carry an ordinary target error."""
    def __init__(self, error, proof, *, through=True):
        require(isinstance(proof, _ProvedChain), "target failure requires a proved chain")
        self.error, self.proof = error, proof
        self.through = through

    def proved(self, guard):
        return self.proof.proved(guard)


def _leaf_outcome(kind, value, guard):
    return (("present", value.st_dev, value.st_ino, value.st_mode,
             stat.S_ISLNK(value.st_mode), _reparse(value),
             (value.st_dev, value.st_ino) in guard.identities())
            if kind == "present" else ("errno", value.errno))


class _LeafLookup:
    leaf_refusal = False

    def __init__(self, kind, value, proof):
        self.kind, self.value, self.proof = kind, value, proof
        # Retain the raw lookup result, independently of consumer diagnostics.
        proof.leaf_outcome = _leaf_outcome(kind, value, proof.guard)


class _HopBoundary:
    def __init__(self, stage):
        self.stage = stage


def _proof_failure_disposition(error, failure):
    """Carry the detection site's outcome through an alias's diagnostic boundary."""
    acquired = _acquisition_fact(failure)
    if acquired is not None:
        error._acquisition_outcome = acquired
        return _acquisition_map(acquired, "trust")
    return QUARANTINE


def _disposition(error, *, guard, seam, path=None, inert=False):
    """Only a complete negative witness permits an acquisition's absence reduction."""
    from hierarchy_router import PrivatePathError, SymlinkPathError, _lexical_path
    fatal = _fatal_path_error(error, guard)
    if fatal is not None:
        fatal._global_path_failure = fatal._path_failure = True
        error._path_failure = True
        return GLOBAL
    acquired = _acquisition_fact(error)
    if acquired is not None:
        caller = ("trust" if isinstance(error, _ProofPathError) else
                  "inert" if seam == "scope" and inert else "trial" if seam == "trial" else
                  "metadata" if seam == "readiness" else "stored" if seam == "scope" else
                  "reader-check" if seam == "reader-check" else "public")
        return _acquisition_map(acquired, caller)
    if isinstance(error, SymlinkPathError):
        error._path_failure = True
        _recheck_observed_link(error, guard)
    if isinstance(error, _ProofPathError):
        return QUARANTINE
    if isinstance(error, PrivatePathError) or getattr(error, "_unproved_ancestor", False):
        return QUARANTINE
    classified = getattr(error, "_private_alias_for", None)
    if isinstance(error, SymlinkPathError) or classified is not None:
        guard.current()
        candidate = _lexical_path(path if path is not None else
                                  classified[1] if classified is not None else error.path)
        if classified is None or classified[0] is not guard or classified[1] != candidate:
            if not isinstance(error, SymlinkPathError):
                return QUARANTINE
            proof = _private_symlink_target(guard, error.path, candidate,
                                            _observed=getattr(error, "_observed_link", None))
            _recheck_observed_link(error, guard,
                private=proof.error if isinstance(proof, _ProofFailure)
                and isinstance(proof.error, PrivatePathError) else None)
            classified = guard, candidate, proof
            error._private_alias_for = classified
        if isinstance(classified[2], _LinkLookupFailure):
            proof = classified[2]
            # A consuming scope can suppress a public lookup failure only while
            # every link and ancestor remains the captured public identity.
            if not proof.proved(guard):
                return _proof_failure_disposition(error, proof.proof.failure)
            if proof.through and not (seam == "scope" and inert):
                proof.error._private_alias_for = classified
                if error is proof.error:
                    return GLOBAL
                # Plain errno: its caller, not the privacy guard, owns disposition.
                raise proof.error from error
        elif isinstance(classified[2], _ProvedChain):
            if not classified[2].proved(guard):
                return _proof_failure_disposition(error, classified[2].failure)
            if (classified[2].leaf_outcome == ("errno", errno.ENOENT)
                    and (seam == "scope" and inert or seam == "scope-check"
                         and _acquisition_caller(guard) == "inert")):
                _acquisition_detect(guard, "ABSENT", error)
                return ABSENT
        elif isinstance(classified[2], _ProofFailure):
            return _proof_failure_disposition(error, classified[2].error)
        else:
            return QUARANTINE
    if isinstance(error, SymlinkPathError):
        _recheck_observed_link(error, guard)
    if path is not None and seam in {"scope", "readiness", "trial", "consume"}:
        try:
            guard.refuse(path)
        except PrivatePathError:
            return QUARANTINE
    if seam == "trial" and isinstance(error, (ValueError, TypeError, KeyError)):
        return ROW_UNKNOWN
    return GLOBAL


def _walk_error(error, path, *, seam, anchored=True):
    """Raise the owning seam's baseline bytes while preserving proof-failure type."""
    from hierarchy_router import SymlinkPathError
    _raise_global(error)
    error._path_failure = True
    acquired = _acquisition_fact(error)
    if acquired is not None and (acquired.kind == "CHANGED"
            or acquired.kind == "PRIVATE" and acquired.replacement):
        if seam in {"lock", "lock-preflight"} and acquired.kind == "CHANGED":
            cause = error
            for _ in range(MAX_INPUT_DEPTH):
                if cause is None:
                    break
                if isinstance(cause, OSError):
                    lock_parent = (cause.errno == errno.ENOTDIR
                        and isinstance(cause.filename, str)
                        and Path(cause.filename).is_absolute()
                        and Path(cause.filename) in Path(path).parents)
                    if seam == "lock" and cause.errno in {None, errno.ENOTDIR} or lock_parent:
                        mapped = _diagnostic_error(cause, path, seam="lock", anchored=anchored)
                        mapped._acquisition_outcome = acquired
                        if seam == "lock-preflight":
                            mapped.source = "journal"
                        raise mapped from error
                    break
                cause = cause.__cause__
        _acquisition_error(error, None)
    if getattr(error, "_unproved_ancestor", False):
        raise error
    classified = getattr(error, "_private_alias_for", None)
    if classified is not None and isinstance(classified[2], _ProofFailure):
        failure = classified[2].error
        if (classified[2].stage in {"prefix ancestor", "hop target", "traversal prefix",
                                    "post-traversal", "suffix ancestor"}
                and not (isinstance(error, SymlinkPathError) and error.path == classified[1])
                and isinstance(failure, OSError) and failure.errno is not None
                and failure.errno not in {errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP}):
            diagnostic = _diagnostic_error(failure, classified[1], seam="link")
            refused = _ProofPathError(str(diagnostic))
            refused._path_failure = True
            raise refused from error
    mapped = _diagnostic_error(error, path, seam=seam, anchored=anchored)
    acquired = getattr(error, "_acquisition_outcome", None)
    if acquired is not None:
        mapped._acquisition_outcome = acquired
    if mapped is error:
        raise error
    raise mapped from error


def _diagnostic_error(error, path, *, seam, anchored=True):
    """Pure formatting: a diagnostic never changes an error's producing layer."""
    from hierarchy_router import SymlinkPathError
    if seam == "ancestors" and isinstance(error, SymlinkPathError):
        return ValueError("reference parent must be a directory: " + str(error.path))
    if (not isinstance(error, OSError) or seam != "lock" and error.errno is None
            or seam not in {"lock", "link"} and error.filename is None):
        return error
    if seam == "parent-check" and error.errno == errno.ELOOP:
        return SymlinkPathError(path)
    if seam == "lock" and error.errno is None:
        return ValueError("cannot create journal lock")
    filename = error.filename
    if seam == "exists" and getattr(error, "_search_only_parent_error", False):
        # Baseline exists() exposed a consuming parent's relative open error.
        filename = error.filename
    elif seam in {"check", "exists", "lock", "link"}:
        filename = str(path)
    elif seam in {"parent", "parent-check"}:
        component = Path(filename) if filename is not None else Path(path)
        filename = component.name or component.anchor
    elif seam in {"read", "members", "ancestors"} and not anchored and error.errno == errno.ENOTDIR:
        return ValueError("reference parent must be a directory: " + str(filename))
    message = (os.strerror(error.errno) if error.errno is not None and (seam == "lock" or error.strerror is None)
               else error.strerror)
    if filename == error.filename and message == error.strerror and seam != "lock":
        return error
    mapped = type(error)(error.errno, message, filename)
    mapped._path_failure = True
    if getattr(error, "_search_only_parent_error", False):
        mapped._search_only_parent_error = True
    return mapped


@lru_cache(maxsize=1)
def _symlink_reader():
    """Optional bounded readlinkat; pathname link text cannot certify a chain."""
    if os.name != "posix":
        return None
    try:
        import ctypes
        library = ctypes.CDLL(None, use_errno=True)
        function = library.readlinkat
    except (ImportError, AttributeError):
        return None
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t)
    function.restype = ctypes.c_ssize_t

    def read(directory, name, size):
        if type(size) is not int or not 0 < size <= MAX_SYMLINK_BYTES:
            return None
        if type(directory) is not int or directory < 0:
            return None
        return _acquire("link", directory, name, size, _reader=function)
    return read


def _proof_result(action, args, kwargs):
    value = action(*args, **kwargs)
    try:
        return _ProofValue(value)
    except BaseException:
        if isinstance(value, _ProvedChain) and value.directory is not None:
            descriptor, value.directory = value.directory, None
            _proof_close(descriptor, os.close)
        raise


def _proof_operation(guard, stage, action, *args, **kwargs):
    """The sole proof exception boundary: no errno can turn a proof into absence."""
    try:
        if action is os.close or action is _proof_close:
            # A latched policy refusal cannot prevent release of an owned handle.
            result = _acquire("proof", _proof_result, (action, args, kwargs), {}, _guard=guard)
            guard.current()
            return result
        guard.current()
        return _acquire("proof", _proof_result, (action, args, kwargs), {}, _guard=guard)
    except Exception as exc:
        _raise_global(exc, guard=guard)
        return _ProofFailure(stage, exc)


def _final_leaf_lookup(proof):
    """The sole target boundary, accessible only with a complete parent-chain proof."""
    require(isinstance(proof, _ProvedChain) and proof.valid and proof.directory is not None,
            "final lookup requires a live proved-chain token")
    proof.guard.current()
    _require_proof_descriptor(proof.directory)
    try:
        proof.guard.refuse(proof.leaf)
        info = _acquire("stat", proof.leaf.name, dir_fd=proof.directory, follow_symlinks=False,
                        _guard=proof.guard, _path=proof.leaf, _expected_mark=proof.reference_mark,
                        _negative=(proof.leaf, proof.ancestors) if proof.expected is None
                        or proof.expected == ("errno", errno.ENOENT) else None)
        changed = proof.expected is not None and proof.expected != _leaf_outcome("present", info, proof.guard)
        _acquisition_ancestor(proof.guard, proof.leaf, info, proof.expected_ancestors, replacement=changed)
        result = _LeafLookup("present", info, proof)
    except Exception as exc:
        _raise_global(exc, guard=proof.guard)
        from hierarchy_router import PrivatePathError
        if isinstance(exc, PrivatePathError):
            _acquisition_detect(proof.guard, "PRIVATE", exc)
        elif _acquisition_fact(exc) is None:
            _acquisition_refuse(proof.guard, exc)
        if isinstance(exc, (FileNotFoundError, NotADirectoryError)):
            result = _LeafLookup("absent", exc, proof)
        elif not isinstance(exc, OSError):
            return _ProofFailure("final leaf", exc)
        else:
            try:
                _walk_error(exc, proof.original, seam="link")
            except OSError as mapped:
                result = _LeafLookup("error", mapped, proof)
                result.leaf_refusal = True
    return result


def _proof_parent_failure(exc, *, _guard, current, before, marks, _error_depth):
    from hierarchy_router import SymlinkPathError
    # Revalidate while the failed acquisition's prefix is still held open.
    if marks and not isinstance(exc, SymlinkPathError):
        if _error_depth >= MAX_INPUT_DEPTH:
            raise _acquisition_changed(_guard) from exc
        prefix = current.parent
        check, checked = _proof_parent(prefix, _guard=_guard, _revalidating=True,
                                       _error_depth=_error_depth + 1, _expected=marks)
        try:
            _acquisition_require(checked == marks, _guard, "reference parent changed while opening")
            if before is not None:
                now = _acquire("stat", current.name, dir_fd=check, follow_symlinks=False, _guard=_guard)
                if _reference_mark(now) != _reference_mark(before):
                    _acquisition_replacement(_guard, current, now)
        finally:
            _proof_close(check, os.close)
    if not isinstance(exc, SymlinkPathError):
        _acquisition_refuse(_guard, exc)


def _proof_parent(path, *, _guard, _revalidating=False, _consume=False, _error_depth=0,
                  _expected=None, _captured=False, _absent=None):
    """Raw search-only walk; its caller must consume the proof-operation result."""
    from hierarchy_router import _lexical_path
    path = _lexical_path(path)
    require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
    require(_descriptor_capabilities(), "secure link proof requires directory descriptor support")
    # A readable anchored handle is safe when no search-only handle exists.
    # If permissions prevent that open, the proof fails and aliases quarantine.
    flags = (_search_directory_flag() or os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    directory, pending, before = None, None, None
    marks = []
    current = Path(path.anchor)
    try:
        _guard(path)
        expected = _ancestor_components(_expected) if _expected is not None else ()
        before = _acquire("stat", path.anchor, follow_symlinks=False, _guard=_guard)
        _acquisition_ancestor(_guard, current, before, expected, replacement=_revalidating)
        _reference_directory(before, current, _ancestors=marks, _guard=_guard)
        directory = _acquire("open", path.anchor, flags, _guard=_guard, _path=current, _before=before)
        info = _acquire("fstat", directory, _guard=_guard)
        _acquisition_identity(_guard, current, info,
                              replacement=_directory_mark(before) != _directory_mark(info))
        _acquisition_require(_directory_mark(before) == _directory_mark(info), _guard,
                             "reference parent changed while opening")
        marks.append((path.anchor, _directory_mark(info)))
        for component in path.parts[1:]:
            current = current / component
            # The immutable full pathname was screened above. Keep the policy
            # snapshot current; each stat/open identity is still checked below.
            _guard.current()
            before = None
            # A recorded component cannot become a new negative edge merely
            # because this walk has reached only its shorter existing prefix.
            before = _acquire("stat", component, dir_fd=directory, follow_symlinks=False, _guard=_guard,
                              _negative=(current, marks) if not _captured and len(marks) >= len(expected) else None)
            if _absent is not None and current == _absent.path:
                _acquisition_replacement(_guard, current, before)
            _acquisition_ancestor(_guard, current, before, expected, replacement=_revalidating)
            if _consume and stat.S_ISLNK(before.st_mode):
                # Refuse a private/unproved alias before opening it. A proved
                # public link retains the consuming reader's native errno.
                from hierarchy_router import SymlinkPathError
                alias = SymlinkPathError(current)
                if _disposition(alias, guard=_guard, seam="consume", path=path) == QUARANTINE:
                    raise alias
            if not _consume or _reparse(before):
                _reference_directory(before, current, _ancestors=marks, _guard=_guard)
            previous = directory
            directory = _acquire("open", component, flags, dir_fd=previous, _guard=_guard, _path=current, _before=before)
            os.close(previous)
            info = _acquire("fstat", directory, _guard=_guard)
            _acquisition_identity(_guard, current, info,
                                  replacement=_directory_mark(before) != _directory_mark(info))
            _acquisition_require(_directory_mark(before) == _directory_mark(info), _guard,
                                 "reference parent changed while opening")
            marks.append((component, _directory_mark(info)))
        result = directory, marks
        directory = None
        return result
    except Exception as exc:
        pending = exc
        from hierarchy_router import PrivatePathError, SymlinkPathError
        if isinstance(exc, PrivatePathError):
            _acquisition_detect(_guard, "PRIVATE", exc, replacement=_revalidating or _captured)
        elif getattr(exc, "_acquisition_outcome", None) is None and isinstance(exc, (OSError, ValueError)):
            if _captured:
                if before is not None:
                    _acquisition_replacement(_guard, current, before)
                _acquisition_refuse(_guard, exc)
            if _revalidating and isinstance(exc, SymlinkPathError):
                _acquisition_replacement(_guard, current, _acquire("stat", current.name, dir_fd=directory, follow_symlinks=False, _guard=_guard))
            if isinstance(exc, OSError) and (exc.errno == errno.ELOOP or
                    exc.errno == errno.ENOTDIR and before is not None and stat.S_ISDIR(before.st_mode)):
                _acquisition_open_refusal(exc, _guard, current, directory, before=before, ancestors=marks)
            _proof_parent_failure(exc, _guard=_guard, current=current, before=before,
                                  marks=marks, _error_depth=_error_depth)
        raise
    finally:
        if directory is not None:
            try:
                os.close(directory)
            finally:
                _raise_global(pending, guard=_guard)


def _proof_check(path, *, _guard, _revalidating=False, _expected=None, _expected_mark=None):
    """Non-following component metadata; links are data, never exception control flow."""
    from hierarchy_router import _lexical_path
    path = _lexical_path(path)
    _guard.refuse(path)
    directory, pending = None, None
    try:
        directory, ancestors = _proof_parent(path.parent, _guard=_guard, _revalidating=_revalidating,
                                             _expected=_expected)
        _require_proof_descriptor(directory)
        info = (_acquire("stat", path.name, dir_fd=directory, follow_symlinks=False, _guard=_guard,
                         _path=path, _expected_mark=_expected_mark)
                if path.name else _acquire("fstat", directory, _guard=_guard))
        _acquisition_identity(_guard, path, info, revalidating=_revalidating)
        if stat.S_ISDIR(info.st_mode):
            _acquire("witness", "ancestor", path, info, _guard=_guard)
        require(info.st_ino and all(mark[1] for _component, mark in ancestors),
                "public component identity unavailable")
        return info, ancestors
    except BaseException as exc:
        pending = exc
        raise
    finally:
        if directory is not None:
            try:
                _proof_close(directory, os.close)
            finally:
                _raise_global(pending, guard=_guard)


def _stable_link(guard, snapshot):
    path, mark, ancestors = snapshot
    directory, pending = None, None
    try:
        directory, current = _proof_parent(path.parent, _guard=guard, _revalidating=True, _expected=ancestors)
        _require_proof_descriptor(directory)
        info = _acquire("stat", path.name, dir_fd=directory, follow_symlinks=False, _guard=guard)
        _acquisition_identity(guard, path, info, replacement=_reference_mark(info) != mark)
        if _reference_mark(info) != mark:
            _acquisition_replacement(guard, path, info)
        return (ancestors == current
                and mark == _reference_mark(info))
    except BaseException as exc:
        pending = exc
        raise
    finally:
        if directory is not None:
            try:
                _proof_close(directory, os.close)
            finally:
                _raise_global(pending, guard=guard)


def _link_snapshot(guard, path, *, _observed=None):
    """Bounded link text plus its full ancestry; all failures belong to the proof entry."""
    directory, pending, before = None, None, None
    try:
        directory, ancestors = _proof_parent(path.parent, _guard=guard)
        _require_proof_descriptor(directory)
        before = _acquire("stat", path.name, dir_fd=directory, follow_symlinks=False, _guard=guard)
        require(before.st_ino, "public link proof unavailable")
        replaced = _observed is not None and _reference_mark(before) != _reference_mark(_observed)
        _acquisition_identity(guard, path, before, replacement=replaced)
        if replaced:
            _acquisition_replacement(guard, path, before)
        require(stat.S_ISLNK(before.st_mode) and not _reparse(before) and before.st_ino
                and all(mark[1] for _component, mark in ancestors)
                and 0 < before.st_size <= MAX_SYMLINK_BYTES, "public link proof unavailable")
        read = _symlink_reader()
        require(read is not None, "public link reader unavailable")
        raw = read(directory, path.name, before.st_size)
        if raw is None or len(raw) != before.st_size or b"\0" in raw:
            proof = _ProvedChain(guard, path, (), (), directory, path, ancestors)
            _LeafLookup("present", before, proof)
            _recheck_scope_witness(proof)
            error = ValueError("public link changed while reading")
            _acquisition_refuse(guard, error)
            raise error
        after = _acquire("stat", path.name, dir_fd=directory, follow_symlinks=False, _guard=guard)
        require(after.st_ino, "public link proof unavailable")
        _acquisition_identity(guard, path, after, replacement=_reference_mark(before) != _reference_mark(after))
        if _reference_mark(before) != _reference_mark(after):
            _acquisition_replacement(guard, path, after)
        _acquisition_require(_reference_mark(before) == _reference_mark(after), guard, "public link changed while reading")
        snapshot = path, _reference_mark(before), ancestors
        _acquisition_require(_stable_link(guard, snapshot), guard, "public link ancestry changed")
        return raw, snapshot
    except Exception as exc:
        pending = exc
        if directory is not None and isinstance(exc, OSError) and getattr(exc, "_acquisition_outcome", None) is None:
            _acquisition_open_refusal(exc, guard, path, directory,
                                      before=before if before is not None else _observed, ancestors=ancestors)
        raise
    except BaseException as exc:
        pending = exc
        raise
    finally:
        if directory is not None:
            try:
                _proof_close(directory, os.close)
            finally:
                _raise_global(pending, guard=guard)


def _proof_link(guard, path, observed):
    raw, snapshot = _link_snapshot(guard, path, _observed=observed)
    _acquisition_require(snapshot[1] == _reference_mark(observed), guard, "public link changed before capture")
    return raw, snapshot


def _chain_parent_marks(guard, parent, observations):
    """Compare captured common prefixes before another walk reaches a replacement."""
    expected, remaining = [], MAX_INPUT_NODES
    for value, mark, ancestors, directory in observations:
        count = len(ancestors) + int(directory)
        remaining -= count
        require(remaining >= 0, "public chain proof exceeds limit")
        for index in range(min(count, len(parent.parts))):
            component, captured = (ancestors[index] if index < len(ancestors)
                                   else (value.name or value.anchor, mark))
            if component != parent.parts[index]:
                break
            if index < len(expected):
                _acquisition_require(expected[index] == (component, captured), guard,
                                     "reference parent changed while opening")
            else:
                expected.append((component, captured))
    return expected


def _proof_token(guard, original, leaf, observations, links):
    directory, pending = None, None
    try:
        expected = _chain_parent_marks(guard, leaf.parent, observations)
        directory, ancestors = _proof_parent(leaf.parent, _guard=guard, _expected=expected)
        proof = _ProvedChain(guard, original, observations, links, directory, leaf, ancestors)
        for value, mark, _ancestors, is_directory in observations:
            if value == leaf and not is_directory:
                _acquisition_require(proof.reference_mark is None or proof.reference_mark == mark,
                                     guard, "reference parent changed while opening")
                proof.reference_mark = mark
        _proof_recheck(proof)
        directory = None
        return proof
    except BaseException as exc:
        pending = exc
        raise
    finally:
        if directory is not None:
            try:
                _proof_close(directory, os.close)
            finally:
                _raise_global(pending, guard=guard)


def _proof_recheck(proof):
    remaining = MAX_INPUT_NODES - len(proof.ancestors)
    require(remaining >= 0, "public chain proof exceeds limit")
    opened, cursor = {}, None
    for component, mark in proof.ancestors:
        cursor = Path(component) if cursor is None else cursor / component
        opened[cursor] = mark
    for path, mark, ancestors, directory in proof.observations:
        remaining -= len(path.parent.parts) + 1
        require(remaining >= 0, "public chain proof exceeds limit")
        # The descriptor used by the final lookup must belong to the SAME
        # chain as the observations, even when a substituted directory is
        # restored before these observations are rechecked (A -> B -> A).
        ancestor_path = None
        for component, ancestor_mark in ancestors:
            ancestor_path = Path(component) if ancestor_path is None else ancestor_path / component
            _acquisition_require(ancestor_path not in opened or opened[ancestor_path] == ancestor_mark, proof.guard,
                    "final lookup parent ancestry changed")
        _acquisition_require(not directory or path not in opened or opened[path] == mark, proof.guard,
                "final lookup parent changed")
        info, current = _proof_check(path, _guard=proof.guard, _revalidating=True,
                                     _expected=ancestors, _expected_mark=None if directory else mark)
        if mark != (_directory_mark(info) if directory else _reference_mark(info)):
            _acquisition_replacement(proof.guard, path, info)
        _acquisition_require(mark == (_directory_mark(info) if directory else _reference_mark(info))
                and ancestors == current, proof.guard, "public component changed")
    for snapshot in proof.links:
        remaining -= len(snapshot[0].parent.parts) + 1
        require(remaining >= 0, "public chain proof exceeds limit")
        _acquisition_require(_stable_link(proof.guard, snapshot), proof.guard, "public link changed")
    if proof.leaf is not None:
        _recheck_final_witness(proof)
    return True


def _recheck_final_witness(proof):
    """Re-open the captured parent chain and repeat its no-follow leaf lookup."""
    directory, pending = None, None
    try:
        directory, current = _proof_parent(proof.leaf.parent, _guard=proof.guard, _revalidating=True, _expected=proof.ancestors)
        _acquisition_require(current == proof.ancestors, proof.guard, "final lookup parent ancestry changed")
        if proof.directory is not None:
            _require_proof_descriptor(proof.directory)
            info = _acquire("fstat", proof.directory, _guard=proof.guard)
            _acquisition_identity(proof.guard, proof.leaf.parent, info)
            _acquisition_require(_directory_mark(info) == current[-1][1], proof.guard, "final lookup descriptor changed")
        if proof.leaf_outcome is not None:
            fresh = _ProvedChain(proof.guard, proof.original, (), (), directory, proof.leaf, current)
            fresh.expected = proof.leaf_outcome
            fresh.reference_mark = proof.reference_mark
            result = _final_leaf_lookup(fresh)
            if isinstance(result, _ProofFailure):
                if getattr(result.error, "_acquisition_outcome", None) is not None:
                    raise result.error
            if isinstance(result, _LeafLookup) and result.kind == "present":
                _acquisition_identity(proof.guard, proof.leaf, result.value)
            if not isinstance(result, _LeafLookup) or fresh.leaf_outcome != proof.leaf_outcome:
                _acquisition_replacement(proof.guard, proof.leaf,
                    result.value if isinstance(result, _LeafLookup) and result.kind == "present" else None)
    except BaseException as exc:
        pending = exc
        raise
    finally:
        if directory is not None:
            try:
                _proof_close(directory, os.close)
            finally:
                _raise_global(pending, guard=proof.guard)


def _lookup_chain_leaf(guard, candidate, value, observations, links, stage):
    """Capture, use and release the complete parent proof for one final lookup."""
    token = _proof_operation(guard, stage, _proof_token, guard, candidate, value, observations, links)
    if isinstance(token, _ProofFailure):
        return token
    proof = token.value
    try:
        result = _final_leaf_lookup(proof)
        if isinstance(result, _LeafLookup) and result.kind != "present":
            checked = _proof_operation(guard, "final outcome", _proof_recheck, proof)
            if isinstance(checked, _ProofFailure):
                return checked
            if result.kind == "absent":
                _acquisition_detect(guard, "ABSENT", result.value)
            else:
                _acquisition_refuse(guard, result.value)
    finally:
        cleanup = (_proof_operation(guard, "cleanup", _proof_close, proof.directory, os.close)
                   if isinstance(proof.directory, _MetadataDirectory)
                   else _proof_operation(guard, "cleanup", os.close, proof.directory))
        proof.directory = None
    return cleanup if isinstance(cleanup, _ProofFailure) else result


def _recheck_failed_chain_links(guard, result, links):
    from hierarchy_router import PrivatePathError
    if not isinstance(result, _ProofFailure):
        return result
    acquired = _acquisition_fact(result.error)
    if acquired is not None and acquired.kind == "ABSENT":
        # A negative edge reached before the final lookup has no completed
        # chain token. Its earlier observations still owe full revalidation.
        result = _ProofFailure(result.stage, _acquisition_changed(guard))
    require(len(links) <= MAX_SYMLINK_HOPS, "public link chain exceeds limit")
    remaining, changed, refused = MAX_INPUT_NODES, False, result
    private = result.error if isinstance(result.error, PrivatePathError) else None
    for snapshot in links:
        remaining -= len(snapshot[0].parent.parts) + 1
        require(remaining >= 0, "public chain proof exceeds limit")
        checked = _proof_operation(guard, "failed chain link", _stable_link, guard, snapshot)
        if isinstance(checked, _ProofFailure):
            changed = True
            refused = checked
            if isinstance(checked.error, PrivatePathError):
                private = checked.error
        elif not checked.value:
            changed = True
            refused = _ProofFailure("failed chain link", _acquisition_changed(guard))
    if changed and private is not None:
        _acquisition_detect(guard, "PRIVATE", private, replacement=True)
        return _ProofFailure("failed chain link", private)
    return refused


def _chain_check(guard, observed, stage, action, *args, **kwargs):
    if action is _proof_check and observed is not None:
        observed_path, mark, ancestors = observed
        value = args[0]
        if value == observed_path or value in observed_path.parents:
            kwargs["_expected"] = ancestors
            if value == observed_path:
                kwargs["_expected_mark"] = mark
    return _proof_operation(guard, stage, action, *args, **kwargs)


def _chain_observe(guard, observed, observations, value, info, ancestors):
    if observed is not None and value == observed[0]:
        if (_reference_mark(info) != observed[1]
                or not _same_path_ancestors(ancestors, observed[2])):
            _acquisition_replacement(guard, value, info)
    is_directory = stat.S_ISDIR(info.st_mode)
    mark = _directory_mark(info) if is_directory else _reference_mark(info)
    observations.append((value, mark, ancestors, is_directory))


def _resolve_public_chain(guard, path, candidate, *, _observed=None):
    from hierarchy_router import _lexical_path
    require(_descriptor_capabilities(), "secure link proof requires directory descriptor support")
    path, candidate = _lexical_path(path), _lexical_path(candidate)
    through = path != candidate
    pending, cursor = list(candidate.parts[1:]), Path(candidate.anchor)
    observations, links = [], []
    if _observed is not None:
        observed_path, observed_mark, observed_ancestors = _observed
        observations.append((observed_path, observed_mark, observed_ancestors, False))
        links.append(_observed)
    remaining, hops, seen_link = MAX_INPUT_NODES, 0, False

    def walk():
        nonlocal pending, cursor, remaining, hops, seen_link
        while pending:
            component = pending.pop(0)
            if isinstance(component, _HopBoundary):
                remaining -= len(cursor.parent.parts) + 1
                require(remaining >= 0, "public chain proof exceeds limit")
                result = _chain_check(guard, _observed, component.stage, _proof_check, cursor, _guard=guard)
                if isinstance(result, _ProofFailure):
                    return result
                info, ancestors = result.value
                if any(isinstance(item, str) for item in pending):
                    _reference_directory(info, cursor, _guard=guard)
                _chain_observe(guard, _observed, observations, cursor, info, ancestors)
                continue
            if component == "..":
                for stage, value in (("traversal prefix", cursor), ("post-traversal", cursor.parent)):
                    remaining -= len(value.parent.parts) + 1
                    require(remaining >= 0, "public chain proof exceeds limit")
                    result = _chain_check(guard, _observed, stage, _proof_check, value, _guard=guard)
                    if isinstance(result, _ProofFailure):
                        return result
                    info, ancestors = result.value
                    _reference_directory(info, value, _guard=guard)
                    _chain_observe(guard, _observed, observations, value, info, ancestors)
                cursor = cursor.parent
                continue
            value = cursor / component
            boundary = pending[0] if pending and isinstance(pending[0], _HopBoundary) else None
            # Boundaries recheck proof components; only remaining pathname parts
            # determine whether this is the leaf under the last proved parent.
            final = not any(isinstance(item, str) for item in pending)
            stage = (boundary.stage if boundary else
                     "traversal prefix" if pending and pending[0] == ".." else
                     "suffix ancestor" if seen_link else "prefix ancestor")
            remaining -= len(value.parent.parts) + 1
            require(remaining >= 0, "public chain proof exceeds limit")
            if final:
                result = _lookup_chain_leaf(guard, candidate, value, observations, links,
                                            boundary.stage if boundary else "suffix ancestor" if seen_link else "prefix ancestor")
                if isinstance(result, _ProofFailure):
                    return result
                proof = result.proof
                if result.kind != "present":
                    return _LinkLookupFailure(result.value, proof, through=through) if result.leaf_refusal else proof
                info = result.value
                identity = _chain_check(guard, _observed, "final identity", guard.check_identity, value, info)
                if isinstance(identity, _ProofFailure):
                    return identity
                # Parent marks belong to the token that authorized this exact lookup.
                ancestors = _proof_parent_marks(proof, value)
            else:
                result = _chain_check(guard, _observed, stage, _proof_check, value, _guard=guard)
                if isinstance(result, _ProofFailure):
                    return result
                info, ancestors = result.value
            _chain_observe(guard, _observed, observations, value, info, ancestors)
            if stat.S_ISLNK(info.st_mode) or _reparse(info):
                hops += 1
                require(hops <= MAX_SYMLINK_HOPS, "public link chain exceeds limit")
                captured = _chain_check(guard, _observed, "link", _proof_link, guard, value, info)
                if isinstance(captured, _ProofFailure):
                    return captured
                raw, snapshot = captured.value
                require(len(os.fspath(value.parent)) + len(raw) + sum(len(x) + 1 for x in pending if isinstance(x, str)) + 2
                        <= MAX_INPUT_NODES, "public link target exceeds limit")
                if _observed is None or snapshot[0] != observed_path:
                    links.append(snapshot)
                target = _lexical_path(value.parent / os.fsdecode(raw))
                destination = "direct-leaf destination" if not through and value == path else "hop target"
                pending = list(target.parts[1:]) + [_HopBoundary(destination)] + pending
                cursor, seen_link = Path(target.anchor), True
                continue
            if any(isinstance(item, str) for item in pending):
                _reference_directory(info, value, _guard=guard)
            cursor = value
            if final:
                return proof
        return _ProvedChain(guard, candidate, observations, links)

    result = _proof_operation(guard, "chain", walk)
    if isinstance(result, _ProofValue):
        result = result.value
    return _recheck_failed_chain_links(guard, result, links)


def _proof_parent_marks(proof, value):
    # The target's parent descriptor is already closed; retain the ancestry
    # from the last proved parent instead of minting an unguarded lookup.
    return proof.ancestors


def _private_symlink_target(guard, path, candidate, *, _observed=None):
    context = _private_context(guard)
    token = context.set(True)
    try:
        result = _proof_operation(guard, "chain", _resolve_public_chain, guard, path, candidate, _observed=_observed)
    finally:
        context.reset(token)
    if isinstance(result, _ProofFailure):
        return result
    return result.value


def _stored_reference_check(path, guard, *, trial=False, inert=False):
    """Stored scopes retain their original typed refusal, not proof quarantine."""
    caller = "inert" if inert else "trial" if trial else "stored"
    route = getattr(guard, "_acquisition_route", None)
    if route is None:
        route = guard._acquisition_route = ContextVar("fresh_acquisition_caller", default="public")
    token = route.set(caller)
    try:
        return _acquire("proof", guard.check, (path,), {"scope": True}, _guard=guard)
    finally:
        route.reset(token)


def _raise_reference_acquisition(error, path, guard):
    """Restore an ordinary reader's OS refusal without weakening a failed proof."""
    original = error.acquisition
    if getattr(guard, "_proof_refusals", False) or not isinstance(original, OSError):
        raise error
    _raise_global(error, guard=guard)
    _walk_error(original, path, seam="check")


def _ordinary_reference_check(path, guard):
    """Preserve the reader's checked-open contract without certifying a proof."""
    if getattr(guard, "_proof_refusals", False):
        return guard.check(path)
    from hierarchy_router import SymlinkPathError, _lexical_path
    path = _lexical_path(path)
    require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
    guard.refuse(path)
    directory, failure = None, None
    try:
        if _reference_descriptors():
            directory, ancestors = _reference_parent(path.parent, _guard=guard, _checking=True)
            info = (_acquire("stat", path.name, dir_fd=directory, follow_symlinks=False, _guard=guard, _negative=(path, ancestors)) if path.name
                    else _acquire("fstat", directory, _guard=guard))
        else:
            ancestors = _reference_ancestors(path, _guard=guard, _checking=True)
            info = _acquire("lstat", path, _guard=guard, _negative=(path, ancestors))
        _acquisition_identity(guard, path, info)
        if stat.S_ISLNK(info.st_mode) or _reparse(info):
            raise _link_refusal(info, path, ancestors)
        _acquire("witness", "ancestor", path, info, _guard=guard)
        return info, ancestors
    except (ValueError, OSError) as exc:
        failure = exc
        if _disposition(exc, guard=guard, seam="reader-check", path=path) == ABSENT:
            acquired = _acquisition_fact(exc)
            _acquisition_require(acquired.negative is not None, guard, "reference parent changed while opening")
            negative, captured = acquired.negative
            observation = getattr(guard, "_acquisition_observation", None)
            if observation is None:
                observation = guard._acquisition_observation = ContextVar("fresh_acquisition_observation", default=None)
            observation.set((path, _AbsentReference(negative, captured, requested=path)))
            return None
        _walk_error(exc, path, seam="check")
    finally:
        if directory is not None:
            _close_reference_directory(directory, guard=guard, error=failure)


def _inert_evidence_reducer(*, _guard):
    """Bind the pinned functions once per pass, separating evidence from scope.

    Evidence occurrences stay lexical. Every scope occurrence independently
    checks identity, even when the same pathname also occurs as evidence.
    Per-call refusals are restored in finally; no pinned namespace is changed.
    """
    refusals, inert_paths = None, set()
    route = {"trial": False}

    def lexical_path(value):
        path = Path(value)
        require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
        return path

    def scope_path(value):
        path = lexical_path(value)
        try:
            _stored_reference_check(path, _guard, trial=route["trial"], inert=path in inert_paths)
        except (ValueError, OSError) as exc:
            outcome = _disposition(exc, guard=_guard, seam="scope", path=path, inert=path in inert_paths)
            if outcome == ABSENT:
                return path
            if refusals is None or outcome != QUARANTINE:
                raise
            refusal = str(path), str(exc)
            if refusal not in refusals:
                refusals.append(refusal)
        return path

    namespace = dict(vars(life), safe_path=scope_path)
    for name, function in vars(life).items():
        if isinstance(function, FunctionType) and function.__globals__ is vars(life):
            clone = FunctionType(function.__code__, namespace, function.__name__, function.__defaults__, function.__closure__)
            clone.__kwdefaults__ = function.__kwdefaults__
            namespace[name] = clone
    original = life.evidence
    evidence = FunctionType(original.__code__, dict(namespace, safe_path=lexical_path),
                            original.__name__, original.__defaults__, original.__closure__)
    evidence.__kwdefaults__ = original.__kwdefaults__
    namespace["evidence"] = evidence

    def policy_path(value):
        path = lexical_path(value)
        _guard.check(path)
        return path
    policy_evidence = FunctionType(original.__code__, dict(namespace, safe_path=policy_path),
                                   original.__name__, original.__defaults__, original.__closure__)
    policy_evidence.__kwdefaults__ = original.__kwdefaults__
    original = life.validate_policy
    validate_policy = FunctionType(original.__code__, dict(namespace, evidence=policy_evidence),
                                  original.__name__, original.__defaults__, original.__closure__)
    validate_policy.__kwdefaults__ = original.__kwdefaults__

    def reduce(policy, state, envelope, at, *, _refusals=None, _inert_paths=()):
        nonlocal refusals, inert_paths
        previous, refusals = refusals, _refusals
        previous_paths, inert_paths = inert_paths, _inert_paths
        previous_trial = route["trial"]
        route["trial"] = envelope["event"]["type"] in {"disposition", "resolve"}
        try:
            return namespace["reduce_event"](policy, state, envelope, at)
        finally:
            refusals = previous
            inert_paths = previous_paths
            route["trial"] = previous_trial
    reduce.validate_policy = validate_policy
    return reduce


class JSONArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def _reference_mark(info):
    # Windows pathname stat synthesizes executable permissions from the filename;
    # descriptor stat does not. Permissions are not an identity/content witness.
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), _reparse(info), info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _directory_mark(info):
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), _reparse(info)


def _same_mark(left, right):
    return left == right or (left[2:] == right[2:]
        and all(not a or not b or a == b for a, b in zip(left[:2], right[:2])))


def _same_ancestors(left, right):
    return left == right or (len(left) == len(right)
        and all(a[0] == b[0] and _same_mark(a[1], b[1]) for a, b in zip(left, right)))


def _ancestor_components(marks):
    """Normalize complete root-first chains without allocating every full prefix."""
    require(len(marks) <= MAX_INPUT_NODES, "reference ancestry exceeds limit")
    result = []
    for component, mark in marks:
        if (isinstance(component, str) and component not in {"", ".", ".."}
                and not any(separator in component for separator in ("/", "\\", ":"))):
            result.append((component, mark))
        else:
            path = Path(component)
            result.append((path.name or path.anchor, mark))
    return result


def _same_path_ancestors(left, right):
    """Compare captured prefixes across component-keyed and portable readers."""
    require(len(left) <= MAX_INPUT_NODES and len(right) <= MAX_INPUT_NODES, "reference ancestry exceeds limit")
    if left == right:
        return True
    return _same_ancestors(_ancestor_components(left), _ancestor_components(right))


def _descriptor_capabilities():
    names = {function.__name__ for function in os.supports_dir_fd}
    return (all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
            and {"open", "stat"} <= names)


def _search_directory_flag():
    """Prefer Linux's existing handle, then native search-only directory access."""
    for name in ("O_PATH", "O_SEARCH", "O_EXEC"):
        flag = getattr(os, name, None)
        if flag is not None:
            return flag
    return None


def _reference_descriptors():
    """Select the reference reader; bounded link proofs independently require native primitives."""
    return _descriptor_capabilities()


def _link_refusal(info, path, ancestors):
    from hierarchy_router import SymlinkPathError
    error = SymlinkPathError(path)
    error._observed_link = path, _reference_mark(info), _ancestor_components(ancestors)
    return error


def _recheck_observed_link(error, guard, *, private=None):
    snapshot = getattr(error, "_observed_link", None)
    if snapshot is not None:
        result = _proof_operation(guard, "observed link", _stable_link, guard, snapshot)
        if isinstance(result, _ProofFailure):
            if private is not None:
                _acquisition_detect(guard, "PRIVATE", private, replacement=True)
                raise private
            _acquisition_refuse(guard, result.error)
        _acquisition_require(result.value, guard, "reference parent changed while opening")


def _reference_directory(info, path, *, _guard, _ancestors=()):
    from hierarchy_router import SymlinkPathError
    if stat.S_ISLNK(info.st_mode) or _reparse(info):
        raise _link_refusal(info, path, _ancestors)
    if not stat.S_ISDIR(info.st_mode):
        _acquisition_refuse(_guard, NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(path)))


def _close_reference_directory(descriptor, *, guard, error=None):
    try:
        os.close(descriptor)
    except OSError as exc:
        # Explicit pending causes preserve policy failures without consulting
        # an unrelated request's ambient exception context.
        _raise_global(error, guard=guard)
        _raise_global(exc, guard=guard)
        if _acquisition_fact(error) is not None:
            raise error
        raise _ProofPathError("cannot complete public path proof") from exc


def _reference_parent(path, *, _guard=None, _checking=False, _classifying=False, _expected=None, _absent=None):
    """Walk without following links, with bounded handles and recorded ancestor identities."""
    from hierarchy_router import _operation_guard, _lexical_path
    path = _lexical_path(path)
    require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
    guard = _operation_guard() if _guard is None else _guard
    supported = _descriptor_capabilities() if _classifying else _reference_descriptors()
    metadata_first = _checking and not _classifying and _search_directory_flag() is None
    if not supported or metadata_first:
        guard(path)
    require(supported, "secure reference hashing requires directory descriptor support")
    if metadata_first:
        # Kind-only checks must reach ENOTDIR before a readable-handle fallback
        # can introduce EACCES on an otherwise searchable public prefix.
        _metadata_ancestor_marks(path, guard)
    try:
        return _proof_parent(path, _guard=guard, _consume=not _checking, _expected=_expected, _absent=_absent)
    except OSError as exc:
        current = Path(exc.filename) if exc.filename is not None else path
        _disposition(exc, guard=guard, seam="parent", path=current)
        if _search_directory_flag() is None:
            exc._search_only_parent_error = True
        _walk_error(exc, current, seam="parent-check" if _checking else "parent")


def check_reference_parent_access(path, *, guard):
    """Preserve consuming-parent refusal order without search-only handles."""
    if _reference_descriptors() and _search_directory_flag() is None:
        try:
            directory, _ancestors = _reference_parent(Path(path).parent, _guard=guard)
        except (FileNotFoundError, NotADirectoryError) as exc:
            _raise_global(exc, guard=guard)
            return
        _close_reference_directory(directory, guard=guard)


def _reparse(info):
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _reference_ancestors(path, *, _guard=None, _checking=False, _expected=None, _absent=None):
    """Portable identity witnesses; no path resolution or link traversal."""
    from hierarchy_router import _operation_guard, _lexical_path
    path = _lexical_path(path)
    require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
    guard = _operation_guard() if _guard is None else _guard
    guard(path)
    result = []
    try:
        expected = _ancestor_components(_expected) if _expected is not None else ()
        for parent in reversed(path.parents):
            info = _acquire("lstat", parent, _guard=guard)
            if _absent is not None and parent == _absent.path:
                _acquisition_replacement(guard, parent, info)
            _acquisition_ancestor(guard, parent, info, expected, identity_path=path)
            _reference_directory(info, parent, _ancestors=result, _guard=guard)
            result.append((str(parent), _directory_mark(info)))
    except (ValueError, OSError) as exc:
        seam = "ancestor-check" if _checking else "ancestors"
        _disposition(exc, guard=guard, seam=seam, path=path)
        _walk_error(exc, path, seam=seam, anchored=False)
    return result


def _missing_input_info(path, guard, *, expected=None):
    """Capture a second anchored negative witness, never a pathname diagnosis."""
    try:
        info, _ancestors = _scope_reference_info(path, guard)
    except (ValueError, OSError) as exc:
        _acquisition_error(exc, guard, path=path)
    if not isinstance(info, _AbsentReference):
        raise _acquisition_changed(guard, "captured missing input changed")
    if expected is not None:
        _acquisition_require(info.path == expected.path and info.non_directory == expected.non_directory
            and _same_ancestors(info.ancestors, expected.ancestors), guard, "captured missing input changed")
    if info.non_directory:
        error = NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(path))
        _acquisition_refuse(guard, error)
        raise error
    return info


def _recheck_scope_prefix(proof):
    """Revalidate the complete prefix after the last leaf outcome was read."""
    directory, pending = None, None
    try:
        directory, current = _proof_parent(proof.leaf.parent, _guard=proof.guard, _revalidating=True, _expected=proof.ancestors)
        _acquisition_require(current == proof.ancestors, proof.guard, "final lookup parent ancestry changed")
        return True
    except BaseException as exc:
        pending = exc
        raise
    finally:
        if directory is not None:
            _close_reference_directory(directory, guard=proof.guard, error=pending)


def _recheck_scope_witness(proof):
    """A changed prefix is a proof refusal even if its replacement is public."""
    # The first pass repeats the captured leaf outcome. The second re-opens
    # every ancestor after that lookup and checks the outcome under that chain.
    # The end-prefix pass closes the last lookup's namespace window. Every
    # validation is mandatory; a failed proof is never retried.
    for stage, action in (("scope outcome", _recheck_final_witness),
                          ("scope prefix after lookup", _recheck_final_witness),
                          ("scope end prefix", _recheck_scope_prefix)):
        checked = _proof_operation(proof.guard, stage, action, proof)
        if isinstance(checked, _ProofFailure):
            error = checked.error
            if getattr(error, "_acquisition_outcome", None) is None:
                _acquisition_detect(proof.guard, "CHANGED", error)
            raise error


def _scope_reference_info(path, guard):
    """Prove absence at its first negative edge, including during acquisition."""
    require(len(path.parts) <= MAX_INPUT_NODES, "public chain proof exceeds limit")
    directory, pending = None, None
    try:
        current = Path(path.anchor)
        directory, ancestors = _proof_parent(current, _guard=guard)
        flags = (_search_directory_flag() or os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
        info = _acquire("fstat", directory, _guard=guard)
        if not info.st_ino:
            raise _ProofPathError("secure scope proof requires descriptor anchoring")
        for component in path.parts[1:]:
            current = current / component
            proof = _ProvedChain(guard, path, (), (), directory, current, list(ancestors))
            result = _final_leaf_lookup(proof)
            if isinstance(result, _ProofFailure):
                if getattr(result.error, "_acquisition_outcome", None) is None:
                    _recheck_scope_witness(proof)
                    _acquisition_refuse(guard, result.error)
                raise result.error
            if result.kind == "error":
                _recheck_scope_witness(proof)
                _acquisition_refuse(guard, result.value)
                raise result.value
            if result.kind == "absent":
                # A detached prefix can also produce ENOENT/ENOTDIR. Re-open
                # every existing ancestor by name and repeat this negative
                # lookup before accepting it as evidence about the scope.
                _recheck_scope_witness(proof)
                _acquisition_detect(guard, "ABSENT")
                absent = _AbsentReference(current, ancestors, requested=path)
                _acquire("witness", "negative", absent, _guard=guard)
                return absent, ancestors
            info = result.value
            _acquisition_identity(guard, current, info)
            if not info.st_ino:
                raise _ProofPathError("secure scope proof requires descriptor anchoring")
            if current == path:
                _recheck_scope_witness(proof)
                return info, ancestors
            if stat.S_ISLNK(info.st_mode) or _reparse(info):
                _reference_directory(info, current, _ancestors=ancestors, _guard=guard)
            if not stat.S_ISDIR(info.st_mode):
                _acquisition_refuse(guard,
                    NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(current)))
            previous = directory
            try:
                directory = _acquire("open", component, flags, dir_fd=previous, _guard=guard, _path=current, _before=info)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    _acquisition_open_refusal(exc, guard, current, previous, before=info, ancestors=ancestors)
                _recheck_scope_witness(proof)
                _acquisition_refuse(guard, exc)
                raise
            _close_reference_directory(previous, guard=guard)
            opened = _acquire("fstat", directory, _guard=guard)
            _acquisition_identity(guard, current, opened,
                                  replacement=_directory_mark(info) != _directory_mark(opened))
            _reference_directory(opened, current, _ancestors=ancestors, _guard=guard)
            _acquisition_require(_directory_mark(info) == _directory_mark(opened), guard,
                                 "reference parent changed while opening")
            ancestors.append((component, _directory_mark(opened)))
        return info, ancestors  # The trusted filesystem root itself.
    except Exception as exc:
        pending = exc
        _raise_global(exc, guard=guard)
        from hierarchy_router import PrivatePathError, SymlinkPathError
        if isinstance(exc, _ProofPathError):
            _acquisition_refuse(guard, exc)
        if isinstance(exc, (PrivatePathError, SymlinkPathError)):
            if isinstance(exc, PrivatePathError): _acquisition_detect(guard, "PRIVATE", exc)
            raise
        if not isinstance(exc, (ValueError, OSError)):
            refused = _ProofPathError("secure scope proof requires descriptor anchoring")
            _acquisition_refuse(guard, refused)
            raise refused from exc
        # Our own identity/kind invariants are proof failures. Only an OS
        # acquisition error retains the stored walk's original refusal type.
        if getattr(exc, "_acquisition_outcome", None) is None:
            _acquisition_refuse(guard, exc)
        raise
    except BaseException as exc:
        pending = exc
        raise
    finally:
        if directory is not None:
            _close_reference_directory(directory, guard=guard, error=pending)


def _reference_check(path, *, _guard, _scope=False, _classifying=False):
    """Validate every existing component top down, including a regular-file leaf."""
    from hierarchy_router import PrivatePathError, SymlinkPathError, _lexical_path
    path = _lexical_path(path)
    require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
    try:
        # Capability flags choose the handle, never the proof algorithm.
        # Every successful or absent result comes from the same anchored walk.
        if not _descriptor_capabilities():
            unsupported = _ProofPathError("secure scope proof requires directory descriptor support")
            _acquisition_detect(_guard, "CHANGED", unsupported)
            raise unsupported
        info, ancestors = _scope_reference_info(path, _guard)
        observation = getattr(_guard, "_acquisition_observation", None)
        if observation is not None:
            observation.set((path, info))
        if isinstance(info, _AbsentReference):
            return None
        _acquisition_identity(_guard, path, info)
        if stat.S_ISLNK(info.st_mode) or _reparse(info):
            raise _link_refusal(info, path, ancestors)
        return info, ancestors
    except (ValueError, OSError) as exc:
        acquired = getattr(exc, "_acquisition_outcome", None)
        if acquired is not None:
            if isinstance(exc, _ProofPathError) and not _descriptor_capabilities():
                raise
            caller = _acquisition_caller(_guard, trust=_classifying or getattr(_guard, "_proof_refusals", False)
                                         or isinstance(exc, _ProofPathError))
            if _acquisition_map(acquired, caller) == ABSENT:
                return None
            _acquisition_error(exc, _guard, caller=caller, path=path)
        if isinstance(exc, _ProofPathError) and not _classifying and not getattr(_guard, "_proof_refusals", False):
            original = exc.acquisition
            if (isinstance(original, (ValueError, OSError))
                    and not isinstance(original, (PrivatePathError, SymlinkPathError, _ProofPathError,
                                                  FileNotFoundError, NotADirectoryError))):
                # An ordinary caller keeps its HEAD refusal. Unproved negative
                # edges and failed identity/revalidation proofs stay wrapped.
                _raise_global(exc, guard=_guard)
                _walk_error(original, path, seam="check")
        if (isinstance(exc, ValueError)
                and not isinstance(exc, (PrivatePathError, SymlinkPathError, _ProofPathError))):
            _raise_global(exc, guard=_guard)
            raise _ProofPathError("secure scope proof requires descriptor anchoring") from exc
        if isinstance(exc, OSError):
            _raise_global(exc, guard=_guard)
            raise _ProofPathError("secure scope proof requires descriptor anchoring") from exc
        if _classifying:
            _raise_global(exc, guard=_guard)
            raise
        if _disposition(exc, guard=_guard, seam="scope-check" if _scope else "check", path=path) == ABSENT:
            return None
        _walk_error(exc, path, seam="check")


def _bind_descriptor(descriptor, before, path, guard, *, content=True):
    """Adopt a caller-owned descriptor only after anchoring its exact pathname."""
    if _operation_ledger(guard) is None:
        return
    path = Path(path)
    directory, pending = None, None
    try:
        if _reference_descriptors():
            directory, _marks = _reference_parent(path.parent, _guard=guard)
            current = _acquire("stat", path.name, dir_fd=directory, follow_symlinks=False,
                               _guard=guard, _path=path)
        else:
            _reference_ancestors(path, _guard=guard)
            current = _acquire("lstat", path, _guard=guard, _path=path)
        _acquisition_require(_directory_mark(current) == _directory_mark(before), guard,
                             "reference parent changed while opening")
        _acquire("witness", "descriptor", path, (descriptor, before), _guard=guard)
        actual = _acquire("fstat", descriptor, _guard=guard, _path=path,
                          _expected_mark=_reference_mark(before) if content else None)
        _acquisition_require(_directory_mark(actual) == _directory_mark(before), guard,
                             "reference parent changed while opening")
    except BaseException as error:
        pending = error
        raise
    finally:
        if directory is not None:
            _close_rechecked_reference(directory, guard, pending)


def _stream_reference(descriptor, before, path, consume=None, *, _guard=None, _opened_here=False):
    """Finite declared-length read plus one EOF probe; never follow an append stream.

    _opened_here is reserved for _read_reference's checked, still-owned handle.
    """
    if _guard is None:
        from hierarchy_router import _operation_guard
        _guard = _operation_guard()
    if not _opened_here:
        _bind_descriptor(descriptor, before, path, _guard)
    mark = _reference_mark(before)
    sha, remaining = hashlib.sha256(), before.st_size
    while remaining:
        requested = min(65536, remaining)
        chunk = _acquire("read", descriptor, requested, _guard=_guard)
        _acquisition_require(len(chunk) == requested, _guard, "reference changed while hashing: " + str(path))
        remaining -= len(chunk)
        sha.update(chunk)
        if consume is not None:
            consume(chunk)
    # Refuse observed growth before probing EOF, preserving the initial-size budget on changed files.
    _acquisition_require(_same_mark(_reference_mark(_acquire("fstat", descriptor, _guard=_guard)), mark), _guard, "reference changed while hashing: " + str(path))
    _acquisition_require(_acquire("read", descriptor, 1, _guard=_guard) == b"", _guard, "reference content exceeds reported size: " + str(path))
    _acquisition_require(_same_mark(_reference_mark(_acquire("fstat", descriptor, _guard=_guard)), mark), _guard, "reference changed while hashing: " + str(path))
    return sha.hexdigest()


def _read_reference(path, *, limit=MAX_EVIDENCE_BYTES, capture=False, _witness=None, budget_error=None, _guard=None, _cache=None):
    """Consume one opened identity, using anchored descriptors where supported and a portable checked open otherwise."""
    from hierarchy_router import _operation_guard, _lexical_path
    path = _lexical_path(path)
    require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
    guard = _operation_guard() if _guard is None else _guard
    checked = _ordinary_reference_check(path, guard)
    expected = checked[1] if checked is not None else None
    absent = None
    if expected is None:
        observation = guard._acquisition_observation.get()
        if (observation is not None and observation[0] == path
                and getattr(getattr(observation[1], "outcome", None), "kind", None) == "ABSENT"):
            absent = observation[1]
            expected = absent.ancestors
    if checked is None:
        _acquisition_require(isinstance(absent, _AbsentReference) and absent.requested == path
                and (absent.path == path or absent.path in path.parents), guard,
                "reference parent changed while opening")
    require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
    anchored = _reference_descriptors()
    directory = None
    try:
        if anchored:
            directory, ancestors = _reference_parent(path.parent, _guard=guard, _expected=expected, _absent=absent)
            before = _acquire("stat", path.name, dir_fd=directory, follow_symlinks=False, _guard=guard,
                              _negative=(path, expected) if checked is None else None)
        else:
            ancestors = _reference_ancestors(path, _guard=guard, _expected=expected, _absent=absent)
            before = _acquire("lstat", path, _guard=guard,
                              _negative=(path, expected) if checked is None else None)
        replaced = checked is None or not (_same_mark(_reference_mark(checked[0]), _reference_mark(before))
                                           and _same_path_ancestors(checked[1], ancestors))
        _acquisition_identity(guard, path, before, replacement=replaced)
        if replaced:
            _acquisition_replacement(guard, path, before)
        require(stat.S_ISREG(before.st_mode) and not _reparse(before), "reference must be a regular file: " + str(path))
        _acquisition_require(checked is not None and _same_mark(_reference_mark(checked[0]), _reference_mark(before)),
                guard, "reference changed while opening")
        require(limit is None or before.st_size <= limit, budget_error or "input exceeds " + str(limit) + " bytes")
        mark = _reference_mark(before)
        cached = _cache.get(path, {}).get(mark) if _cache is not None and not capture else None
        chunks = []
        if cached is not None:
            sha, previous_ancestors = cached
            _acquisition_require(_same_ancestors(ancestors, previous_ancestors), guard, "cached evidence reference path changed")
        else:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
            descriptor = (_acquire("open", path.name, flags, dir_fd=directory, _guard=guard, _path=path, _before=before) if anchored else _acquire("open", path, flags, _guard=guard, _path=path, _before=before))
            try:
                opened = _acquire("fstat", descriptor, _guard=guard)
                _acquisition_identity(guard, path, opened, replacement=not _same_mark(_reference_mark(opened), mark))
                _acquisition_require(stat.S_ISREG(opened.st_mode) and not _reparse(opened) and _same_mark(_reference_mark(opened), mark),
                        guard, "reference changed while opening: " + str(path))
                if not anchored:
                    _acquisition_require(_same_ancestors(_reference_ancestors(path, _guard=guard, _expected=ancestors), ancestors), guard, "reference path changed while opening: " + str(path))
                sha = _stream_reference(descriptor, before, path, chunks.append if capture else None, _guard=guard, _opened_here=True)
                if not anchored:
                    _acquisition_require(_same_ancestors(_reference_ancestors(path, _guard=guard, _expected=ancestors), ancestors),
                            guard, "reference path changed while hashing")
                current = (_acquire("stat", path.name, dir_fd=directory, follow_symlinks=False, _guard=guard, _path=path, _expected_mark=mark) if anchored else _acquire("lstat", path, _guard=guard, _path=path, _expected_mark=mark))
                _acquisition_identity(guard, path, current, replacement=not _same_mark(_reference_mark(current), mark))
                _acquisition_require(_same_mark(_reference_mark(current), mark), guard, "reference changed while hashing: " + str(path))
            finally:
                os.close(descriptor)
        if anchored:
            returned, current_ancestors = _reference_parent(path.parent, _guard=guard, _expected=ancestors)
            try:
                current = _acquire("stat", path.name, dir_fd=returned, follow_symlinks=False, _guard=guard, _path=path, _expected_mark=mark)
                _acquisition_identity(guard, path, current, replacement=not _same_mark(_reference_mark(current), mark))
                _acquisition_require(_same_ancestors(current_ancestors, ancestors)
                        and _same_mark(_reference_mark(current), mark),
                        guard, "reference path changed while hashing: " + str(path))
            finally:
                os.close(returned)
        else:
            current = _acquire("lstat", path, _guard=guard, _path=path, _expected_mark=mark)
            _acquisition_identity(guard, path, current, replacement=not _same_mark(_reference_mark(current), mark))
            _acquisition_require(_same_ancestors(_reference_ancestors(path, _guard=guard, _expected=ancestors), ancestors) and _same_mark(_reference_mark(current), mark),
                    guard, "reference path changed while hashing: " + str(path))
        if _witness is not None:
            _witness.update(path=path, mark=mark, ancestors=ancestors, anchored=anchored)
        if _cache is not None:
            _cache.setdefault(path, {})[mark] = sha, ancestors
        return {"path": str(path), "sha256": sha}, b"".join(chunks) if capture else None
    except (ValueError, OSError) as exc:
        if getattr(guard, "_proof_refusals", False) and getattr(exc, "_acquisition_outcome", None) is not None:
            _acquisition_error(exc, guard, caller="trust", path=path)
        _disposition(exc, guard=guard, seam="read", path=path)
        _walk_error(exc, path, seam="read", anchored=anchored)
    finally:
        if directory is not None:
            os.close(directory)


def file_ref(path):
    return _read_reference(path)[0]


def _brief_bytes(path):
    try:
        return _read_reference(path, limit=MAX_BYTES, capture=True)
    except FileNotFoundError as exc:
        raise ValueError("file unavailable: " + str(path)) from exc


def _attachment(mailbox, reference):
    """Validate the public envelope without content IO, then consume only the captured bytes."""
    if isinstance(mailbox, _CapturedMailbox):
        return mailbox.brief(reference)
    mailbox.brief(reference, verify=False)
    actual, raw = _brief_bytes(reference["path"])
    require(actual["sha256"] == reference["sha256"], "brief sha256 mismatch")
    return raw


def _unread_attachment(mailbox, reference, *, _authoritative=False):
    """A first-time typed note is a declaration, never an authority dependency.

    Keep its attempted capture's failure latched in that separate operation.
    Dispatcher composition uses the publishing parent's operation, including
    retained jobs outside the hash cache. Standalone declarations never latch a
    hash mismatch in that parent, even when another note consumed the same path.
    """
    from hierarchy_router import PrivatePathError
    if not isinstance(mailbox, _CapturedMailbox):
        return _attachment(mailbox, reference)
    operation, path = mailbox.operation, Path(reference["path"])
    if _authoritative:
        with operation.capture():
            raw = _attachment(mailbox, reference)
            operation.path_guard.verify()
            return raw
    mailbox.brief(reference, verify=False)
    # Required/cached witnesses still belong to the parent. Validate their
    # identity before isolating only this declaration's expected-hash check.
    _recheck_consumed_reference(operation, path)
    declaration = _declaration_operation(operation)
    try:
        with declaration.capture():
            actual, raw = declaration.read(path)
            require(actual["sha256"] == reference["sha256"], "brief sha256 mismatch")
            declaration.verify()
    except PrivatePathError:
        raise
    except (ValueError, OSError) as exc:
        _raise_global(exc, operation=operation)
        raise UnverifiedAttachment(str(exc)) from exc
    return raw


def _declaration_operation(operation, *, _proof=True):
    """Isolate semantic declarations while inheriting every required witness."""
    def policy(action, *args):
        try:
            return action(*args)
        except (ValueError, OSError) as exc:
            _raise_global(exc, operation=operation)
            raise

    class DeclarationGuard:
        _proof_refusals = True

        @property
        def _acquisition_context(self):
            return operation.path_guard._acquisition_context

        @property
        def _witness_context(self):
            return operation.path_guard._witness_context

        @property
        def _acquisition_observation(self):
            return operation.path_guard._acquisition_observation

        @property
        def _acquisition_route(self):
            return operation.path_guard._acquisition_route

        @property
        def _identity_error(self):
            return getattr(operation.path_guard, "_identity_error", None)

        @property
        def _global_failure(self):
            return getattr(operation.path_guard, "_global_failure", None)

        def _latch_global(self, error):
            return operation.path_guard._latch_global(error)

        def __call__(self, path):
            return policy(operation.path_guard, path)

        def verify(self):
            return policy(operation.path_guard.verify)

        def identities(self):
            return policy(operation.path_guard.identities)

        def current(self):
            return policy(operation.path_guard.current)

        def refuse(self, *paths):
            return policy(operation.path_guard.refuse, *paths)

        def check(self, path, *, scope=False):
            self.refuse(path)
            return _reference_check(path, _guard=self, _scope=scope)

        def check_identity(self, path, info):
            return policy(operation.path_guard.check_identity, path, info)

        def active(self):
            return operation.path_guard.active()

    declaration = _Operation(reference_cache=operation.reference_cache,
        _path_guard=DeclarationGuard() if _proof else operation.path_guard,
        _witness_parent=operation.witnesses)
    declaration._detection_owner = operation
    return declaration


def _recheck_consumed_reference(operation, path):
    """A declaration cannot hide an identity failure of an existing required witness."""
    with operation.capture():
        if path in operation.files:
            _recheck_reference(operation.files[path][2], _guard=operation.path_guard)
        elif path in operation.reference_cache:
            operation.reference(path)


class UnverifiedAttachment(ValueError):
    """A missing/mismatched regular attachment, distinguishable from unsafe IO."""

    def __init__(self, detail, *, message_id=None):
        super().__init__(detail)
        self.message_id = (None if message_id is None else
                           matching(text(message_id, "message_id", 80), SLUG, "message_id"))


def _recheck_reference(witness, *, _guard=None):
    """Metadata-only revalidation of the exact captured identity."""
    _recheck_references((witness,), _guard=_guard)


def _close_rechecked_reference(descriptor, guard, pending):
    try:
        os.close(descriptor)
    except BaseException as cleanup:
        _raise_global(pending, guard=guard)
        _raise_global(cleanup, guard=guard)
        if _acquisition_fact(pending) is not None:
            raise pending
        raise


def _recheck_references(witnesses, *, _guard=None):
    """Share held parents, retaining every leaf and the complete end-prefix check."""
    from hierarchy_router import _operation_guard
    guard = _operation_guard() if _guard is None else _guard
    groups = {}
    for witness in witnesses:
        path = Path(witness["path"])
        guard.refuse(path)
        groups.setdefault((path.parent, witness["anchored"]), []).append(witness)
    for (parent, anchored), group in groups.items():
        directory, pending = None, None
        expected = group[0]["ancestors"]
        try:
            if anchored:
                directory, ancestors = _reference_parent(parent, _guard=guard, _expected=expected)
            else:
                ancestors = _reference_ancestors(parent / "entry", _guard=guard, _expected=expected)
            for witness in group:
                path = Path(witness["path"])
                if anchored:
                    info = _acquire("stat", path.name, dir_fd=directory, follow_symlinks=False,
                                    _guard=guard, _path=path, _expected_mark=witness["mark"])
                else:
                    info = _acquire("lstat", path, _guard=guard, _path=path, _expected_mark=witness["mark"])
                _acquisition_identity(guard, path, info,
                                      replacement=not _same_mark(_reference_mark(info), witness["mark"]))
                _acquisition_require(_same_ancestors(ancestors, witness["ancestors"])
                        and _same_mark(_reference_mark(info), witness["mark"]), guard,
                        "captured reference changed before content promotion")
            if anchored:
                final, after = _reference_parent(parent, _guard=guard, _expected=expected)
                final_pending = None
                try:
                    _acquisition_require(_same_ancestors(after, expected), guard,
                                         "reference parent changed while opening")
                except BaseException as error:
                    final_pending = error
                    raise
                finally:
                    _close_rechecked_reference(final, guard, final_pending)
            else:
                after = _reference_ancestors(parent / "entry", _guard=guard, _expected=expected)
                _acquisition_require(_same_ancestors(after, expected), guard,
                                     "reference parent changed while opening")
        except BaseException as error:
            pending = error
            raise
        finally:
            if directory is not None:
                _close_rechecked_reference(directory, guard, pending)


class CaptureChanged(ValueError):
    def __init__(self, path, error):
        super().__init__(str(error))
        self.path = Path(path)


def _capture_attempt(method):
    @wraps(method)
    def captured(self, *args, **kwargs):
        with self.capture():
            return method(self, *args, **kwargs)
    return captured


def _latch_operation_path_failure(operation, error):
    """Global policy has priority; filesystem outcomes latch where observed."""
    _raise_global(error, operation=operation)


def _operation_context(method):
    @wraps(method)
    def captured(self, *args, **kwargs):
        with self.operation.active():
            try:
                return method(self, *args, **kwargs)
            except (ValueError, OSError) as exc:
                _latch_operation_path_failure(self.operation, exc)
                raise
    return captured


class _Operation:
    """One captured identity per path; bounded byte promotions preserve its original witnesses."""
    def __init__(self, *, reference_cache=None, parent=None, _path_guard=None, _witness_parent=None):
        self.files, self.parsed, self.folders, self.journals = {}, {}, {}, {}
        self.reference_cache = {} if reference_cache is None else reference_cache
        self.failed_validation = False
        self.validation_failure = None
        self.parent = parent
        from hierarchy_router import _CapturedPathGuard, _path_context
        self.path_guard = (_path_context().get() or _CapturedPathGuard()) if _path_guard is None else _path_guard
        if not hasattr(self.path_guard, "_acquisition_context"):
            self.path_guard._acquisition_context = ContextVar("fresh_acquisition_owner", default=self)
        if not hasattr(self.path_guard, "_acquisition_route"):
            self.path_guard._acquisition_route = ContextVar("fresh_acquisition_caller", default="public")
        if not hasattr(self.path_guard, "_acquisition_observation"):
            self.path_guard._acquisition_observation = ContextVar("fresh_acquisition_observation", default=None)
        self.witnesses = _WitnessLedger(self.path_guard, _witness_parent)
        if not hasattr(self.path_guard, "_witness_context"):
            self.path_guard._witness_context = ContextVar("fresh_witness_ledger", default=self.witnesses)
        self.absences, self.validators = {}, [self.path_guard.verify]
        self.existences = {}

    @contextmanager
    def active(self):
        context = self.path_guard._acquisition_context
        token = context.set(getattr(self, "_detection_owner", self))
        witness_token = self.path_guard._witness_context.set(self.witnesses)
        try:
            with self.path_guard.active():
                yield
        finally:
            context.reset(token)
            self.path_guard._witness_context.reset(witness_token)

    @contextmanager
    def required(self):
        context = self.path_guard._acquisition_route
        token = context.set("required")
        try:
            yield
        finally:
            context.reset(token)

    @_capture_attempt
    def output_directory(self, path):
        """Declare the publication namespace before its first metadata acquisition."""
        path = Path(path)
        require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
        _acquire("witness", "output-directory", path, _guard=self.path_guard)
        return path

    @_capture_attempt
    def read(self, path, *, limit=MAX_BYTES, capture=True, budget_error=None):
        path = Path(path)
        if path not in self.files:
            witness = {}
            ref, raw = _read_reference(path, limit=limit, capture=capture, _witness=witness, budget_error=budget_error,
                                       _guard=self.path_guard, _cache=self.reference_cache)
            self.files[path] = ref, raw, witness
        else:
            _recheck_reference(self.files[path][2], _guard=self.path_guard)
        ref, raw, witness = self.files[path]
        require(limit is None or witness["mark"][4] <= limit, budget_error or "input exceeds " + str(limit) + " bytes")
        if capture and raw is None:
            current = {}
            promoted, raw = _read_reference(path, limit=limit, capture=True, _witness=current, budget_error=budget_error,
                                            _guard=self.path_guard, _cache=self.reference_cache)
            _acquisition_require(promoted == ref and _same_mark(current["mark"], witness["mark"])
                    and _same_ancestors(current["ancestors"], witness["ancestors"]),
                    self.path_guard, "captured reference changed before content promotion: " + str(path))
            self.files[path] = ref, raw, witness
        return ref, raw

    @_capture_attempt
    def recheck_files(self, paths, *, limit=MAX_BYTES):
        witnesses = [self.files[Path(path)][2] for path in paths]
        _recheck_references(witnesses, _guard=self.path_guard)
        for witness in witnesses:
            require(limit is None or witness["mark"][4] <= limit, "input exceeds " + str(limit) + " bytes")

    @_capture_attempt
    def json(self, path, *, limit=MAX_BYTES, private=True):
        path = Path(path)
        if path not in self.parsed:
            self.parsed[path] = _bounded_json(self.read(path, limit=limit)[1].decode("utf-8"))
            ref, _raw, witness = self.files[path]
            self.files[path] = ref, None, witness
        else:
            self.read(path, limit=limit, capture=False)
        if private:
            _private_paths(self.parsed[path], paths=self.path_guard)
        return self.parsed[path]

    @_capture_attempt
    def exists(self, path):
        path = Path(path)
        try:
            return self._exists(path)
        except (ValueError, OSError) as exc:
            _disposition(exc, guard=self.path_guard, seam="exists", path=path)
            _walk_error(exc, path, seam="exists")

    def _exists(self, path):
        checked = self.path_guard.check(path)
        if checked is not None:
            info, ancestors = checked
            if path in self.existences:
                previous, previous_ancestors = self.existences[path]
                if not (_same_mark(_directory_mark(info), previous)
                        and _same_ancestors(ancestors, previous_ancestors)):
                    raise _acquisition_changed(self.path_guard)
            _acquire("witness", "ancestor", path, info, _guard=self.path_guard)
            self.existences.setdefault(path, (_directory_mark(info), ancestors))
            return True
        else:
            if path in self.existences:
                raise _acquisition_changed(self.path_guard)
            observed = self.path_guard._acquisition_observation.get()
            expected = (observed[1] if observed is not None and observed[0] == path
                        and getattr(getattr(observed[1], "outcome", None), "kind", None) == "ABSENT" else None)
            missing = _missing_input_info(path, self.path_guard, expected=expected)
            self.absences.setdefault(missing.path, missing.ancestors)
            return False

    def reference(self, path):
        return self.read(path, limit=MAX_LIFECYCLE_EVIDENCE_BYTES, capture=False,
                         budget_error="lifecycle evidence exceeds %d-byte limit" % MAX_LIFECYCLE_EVIDENCE_BYTES)[0]

    @_capture_attempt
    def check_ref(self, ref):
        fields(ref, {"path", "sha256"})
        matching(ref["sha256"], SHA256, "reference sha256")
        require(self.reference(text(ref["path"], "reference path")) == ref,
                "reference sha256 mismatch: " + ref["path"])

    def _members(self, path, *, membership=True, _expected=None):
        try:
            return self._directory_members(path, membership=membership, _expected=_expected)
        except (ValueError, OSError) as exc:
            _disposition(exc, guard=self.path_guard, seam="members", path=path)
            _walk_error(exc, path, seam="members", anchored=_reference_descriptors())

    def _directory_members(self, path, *, membership=True, _expected=None):
        path = Path(path)
        checked = self.path_guard.check(path) if _expected is None else None
        if checked is None and _expected is None:
            observation = self.path_guard._acquisition_observation.get()
            absent = observation[1] if observation is not None and observation[0] == path else None
            _acquisition_require(getattr(getattr(absent, "outcome", None), "kind", None) == "ABSENT"
                    and not absent.non_directory
                    and (absent.path == path or absent.path in path.parents)
                    and len(absent.ancestors) == len(absent.path.parent.parts),
                    self.path_guard, "reference parent changed while opening")
            filename = (absent.path.name or absent.path.anchor) if _reference_descriptors() else str(absent.path)
            error = FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), filename)
            error._acquisition_outcome = absent.outcome
            raise error
        if _expected is None:
            captured_mark = _directory_mark(checked[0])
            captured = _ancestor_components(checked[1])
            if len(captured) < len(path.parts):
                captured.append((path.name or path.anchor, captured_mark))
        else:
            captured_mark, _names, captured = _expected
            self.path_guard.refuse(path)
        if _reference_descriptors():
            directory, ancestors = _reference_parent(path, _guard=self.path_guard, _expected=captured)
            # O_PATH descriptors cannot be enumerated. Open the same anchored identity for listing.
            listing = None
            try:
                info = _acquire("fstat", directory, _guard=self.path_guard)
                _acquisition_identity(self.path_guard, path, info,
                                      replacement=_directory_mark(info) != captured_mark)
                mark, names = _directory_mark(info), None
                _acquisition_require(mark == captured_mark and _same_path_ancestors(ancestors, captured),
                                     self.path_guard, "reference parent changed while opening")
                if membership:
                    listing = _acquire("open", ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory, _guard=self.path_guard)
                    _acquisition_require(_same_mark(mark, _directory_mark(_acquire("fstat", listing, _guard=self.path_guard))), self.path_guard, "captured directory changed")
                    names = _directory_names(listing)
                    _acquisition_require(_same_mark(mark, _directory_mark(_acquire("fstat", listing, _guard=self.path_guard))), self.path_guard, "captured directory changed")
            finally:
                if listing is not None:
                    os.close(listing)
                os.close(directory)
        else:
            ancestors = _reference_ancestors(path / "entry", _guard=self.path_guard, _expected=captured)
            info = _acquire("lstat", path, _guard=self.path_guard)
            _acquisition_identity(self.path_guard, path, info,
                                  replacement=_directory_mark(info) != captured_mark)
            mark = _directory_mark(info)
            _acquisition_require(mark == captured_mark and _same_path_ancestors(ancestors, captured),
                                 self.path_guard, "reference parent changed while opening")
            names = _directory_names(path) if membership else None
        if _reference_descriptors():
            directory, after = _reference_parent(path, _guard=self.path_guard, _expected=ancestors)
            try:
                _acquisition_require(_same_path_ancestors(after, ancestors), self.path_guard,
                                     "reference parent changed while opening")
            finally:
                os.close(directory)
        else:
            after = _reference_ancestors(path / "entry", _guard=self.path_guard, _expected=ancestors)
            _acquisition_require(_same_path_ancestors(after, ancestors), self.path_guard,
                                 "reference parent changed while opening")
        return mark, names, ancestors

    @_capture_attempt
    def entries(self, path, *, optional=False, append=False, identity_only=False):
        path = Path(path)
        previous = self.folders.get(path)
        try:
            current = self._members(path, membership=not identity_only or previous is not None and previous[1] is not None,
                                    _expected=previous)
        except FileNotFoundError as error:
            require(optional and path not in self.folders, "captured directory disappeared: " + str(path))
            outcome = _acquisition_fact(error)
            _acquisition_require(outcome is not None and outcome.negative is not None, self.path_guard,
                                 "reference parent changed while opening")
            edge, ancestors = outcome.negative
            expected = _AbsentReference(edge, ancestors, requested=path)
            missing = _missing_input_info(path, self.path_guard, expected=expected)
            self.absences.setdefault(missing.path, missing.ancestors)
            return []
        if path in self.folders:
            previous = self.folders[path]
            _acquisition_require(_same_mark(current[0], previous[0]) and _same_ancestors(current[2], previous[2])
                    and (previous[1] is None or (set(previous[1]) <= set(current[1]) if append
                                                 else previous[1] == current[1])), self.path_guard, "captured directory changed: " + str(path))
        self.folders[path] = current
        return [] if identity_only else [path / name for name in current[1]]

    @_capture_attempt
    def accept(self, path, expected=None):
        """Adopt only this operation's known committed append, never an arbitrary membership change."""
        path = Path(path)
        if path.parent in self.folders and self.folders[path.parent][1] is not None:
            previous = self.folders[path.parent]
            current = self._members(path.parent, _expected=previous)
            _acquisition_require(_same_mark(previous[0], current[0]) and _same_ancestors(previous[2], current[2])
                    and set(current[1]) == set(previous[1]) | {path.name},
                    self.path_guard, "captured directory changed during publication: " + str(path.parent))
            self.folders[path.parent] = current
        actual, _raw = self.read(path, limit=life.MAX_BYTES if path.suffix == ".json" else MAX_BYTES)
        _acquisition_require(expected is None or actual["sha256"] == expected, self.path_guard, "committed publication content changed: " + str(path))

    def fail(self, error):
        from hierarchy_router import PrivatePathError
        previous = self.validation_failure
        if isinstance(error, PrivatePathError) and not isinstance(previous, PrivatePathError):
            self.validation_failure = error
        acquired = getattr(previous, "_acquisition_outcome", None)
        if acquired is not None and acquired.kind == "CHANGED" and error.__cause__ is previous:
            error._acquisition_outcome = acquired
            if isinstance(error, CaptureChanged):
                self.validation_failure = error
        if not self.failed_validation:
            self.validation_failure = (error if isinstance(error, (ValueError, OSError))
                                       else ValueError("captured input validation failed"))
        self.failed_validation = True
        if self.parent is not None:
            self.parent.fail(error)

    @contextmanager
    def capture(self):
        """A failed attempt remains failed even if it never registered a witness."""
        with self.active():
            try:
                yield
            except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
                _raise_global(exc, operation=self)
                self.fail(exc)
                raise

    def reject_failed(self):
        if self.failed_validation:
            if self.validation_failure is not None:
                raise self.validation_failure.with_traceback(None)
            raise ValueError("captured operation validation previously failed")

    def prove(self, verification, *args):
        """A proof exists only after the complete parent-owned pass and its final witnesses.

        A Hold or any exception skips proof creation, including checks outside
        capture(). Recovery may inspect captured metadata but cannot mint proof.
        """
        with self.active(), self.required():
            try:
                verification(*args)
                self.verify()
                return object()
            except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
                _latch_operation_path_failure(self, exc)
                # A semantic HOLD mints no proof, but retains its validated
                # inputs for the owner's existing blocked-disposition drafts.
                raise

    @_capture_attempt
    def verify(self):
        from hierarchy_router import PrivatePathError
        try:
            self.reject_failed()
            for validate in self.validators:
                validate()
            for path, (mark, ancestors) in self.existences.items():
                current = self.path_guard.check(path)
                _acquisition_require(current is not None and _same_mark(_directory_mark(current[0]), mark)
                        and _same_ancestors(current[1], ancestors), self.path_guard, "captured existing input changed")
            groups = {}
            for _ref, _raw, witness in self.files.values():
                groups.setdefault(witness["path"].parent, []).append(witness)
            for path in self.folders:
                groups.setdefault(path, [])
            for parent, witnesses in groups.items():
                descriptor = listing = None
                path = parent
                try:
                    anchored = _reference_descriptors()
                    expected = witnesses[0]["ancestors"] if witnesses else self.folders[parent][2]
                    if anchored:
                        descriptor, ancestors = _reference_parent(parent, _guard=self.path_guard, _expected=expected)
                    else:
                        ancestors = _reference_ancestors(parent / "entry", _guard=self.path_guard, _expected=expected)
                    for witness in witnesses:
                        path = witness["path"]
                        info = (_acquire("stat", path.name, dir_fd=descriptor, follow_symlinks=False, _guard=self.path_guard, _path=path, _expected_mark=witness["mark"]) if anchored else _acquire("lstat", path, _guard=self.path_guard, _path=path, _expected_mark=witness["mark"]))
                        _acquisition_identity(self.path_guard, path, info,
                                              replacement=not _same_mark(_reference_mark(info), witness["mark"]))
                        _acquisition_require(_same_ancestors(ancestors, witness["ancestors"])
                                and _same_mark(_reference_mark(info), witness["mark"]),
                                self.path_guard, "captured attachment identity/content metadata changed: " + str(path))
                    if parent in self.folders:
                        path = parent
                        previous = self.folders[parent]
                        if previous[1] is None:
                            mark = _directory_mark(_acquire("fstat", descriptor, _guard=self.path_guard) if anchored else _acquire("lstat", parent, _guard=self.path_guard))
                            names = None
                        elif anchored:
                            listing = _acquire("open", ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor, _guard=self.path_guard)
                            mark, names = _directory_mark(_acquire("fstat", listing, _guard=self.path_guard)), _directory_names(listing)
                        else:
                            mark, names = _directory_mark(_acquire("lstat", parent, _guard=self.path_guard)), _directory_names(parent)
                        _acquisition_require(_same_mark(mark, previous[0]) and names == previous[1]
                                and _same_ancestors(ancestors, previous[2]),
                                self.path_guard, "captured directory membership changed: " + str(parent))
                except PrivatePathError:
                    raise
                except (ValueError, OSError) as exc:
                    _raise_global(exc, operation=self)
                    raise CaptureChanged(path, exc) from exc
                finally:
                    if listing is not None:
                        os.close(listing)
                    if descriptor is not None:
                        os.close(descriptor)
            for path, previous in self.absences.items():
                try:
                    try:
                        info, ancestors = _scope_reference_info(path, self.path_guard)
                    except _ProofPathError as exc:
                        _raise_reference_acquisition(exc, path, self.path_guard)
                    # The shared walk checks private identity before returning
                    # either the leaf or its anchored negative witness.
                    _acquisition_require(_same_ancestors(ancestors, previous), self.path_guard, "captured absent input parent changed: " + str(path))
                    _acquisition_require(isinstance(info, _AbsentReference), self.path_guard, "captured absent input changed (appeared): " + str(path))
                except PrivatePathError:
                    raise
                except (ValueError, OSError) as exc:
                    _raise_global(exc, operation=self)
                    raise CaptureChanged(path, exc) from exc
            self.witnesses.verify()
        except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
            _raise_global(exc, operation=self)
            self.fail(exc)
            if (getattr(self.path_guard, "_proof_refusals", False)
                    and getattr(exc, "_acquisition_outcome", None) is not None):
                _acquisition_error(exc, self.path_guard, caller="trust")
            raise

    @_capture_attempt
    def lifecycle(self, root):
        root = Path(root)
        if root not in self.journals:
            self.journals[root] = _CapturedLifecycle(root, self)
        return self.journals[root]


def _event_shape(envelope):
    """Closed v1 key sets from the pinned reducer, before correlation or quarantine.

    This checks structure only. The original reducers still enforce every role,
    custody, payload, state-transition and accounting rule.
    """
    require(isinstance(envelope, dict), "invalid lifecycle envelope")
    initial = envelope.get("schema") == life.INITIAL_ENVELOPE
    outer = {"schema", "id", "event"} if initial else {"id", "actor", "generation", "custody", "event"}
    require(set(envelope) == outer, "invalid lifecycle envelope")
    event = envelope["event"]
    require(isinstance(event, dict) and isinstance(event.get("type"), str), "invalid lifecycle event")
    kind = event["type"]
    payloads = {
        "publish": {"request"}, "meter": {"subject", "active_seconds", "open_since"},
        "succeed": {"predecessor", "checkpoint_sha256"},
        "decision": {"decision", "reason"}, "read": set(), "route": {"to"},
        "admit": {"source", "gates"}, "wait": {"reason"}, "intent": {"intent_id"},
        "start": {"intent_id"}, "terminal": {"result"},
        "review": {"result_sha256", "source", "verdict", "evidence"}, "delivery": {"evidence"},
        "disposition": {"status", "resolution"}, "resolve": {"blocker_sha256", "resolution"},
        "associate": {"association"}, "observe": {"intent_id", "association_sha256", "observation"},
        "cancel_attempt": {"intent_id", "association_sha256", "reason"},
        "delegated_decision": {"delegation_id", "delegation_sha256", "commit", "review", "decision", "reason"},
        "small_change_plan": {"proposal", "participants"},
        "small_change_decision": {"plan_sha256", "decision", "reason"},
        "small_change_admit": {"plan_sha256", "decision_sha256", "source", "participants", "checks", "gates"}}
    bootstrap = {
        "initial_reservations": {"approved_plan", "channel_witness", "reservations"},
        "initial_creation": {"genesis_event_sha256", "approved_plan_sha256", "reservation_set_sha256", "actor_cid",
                             "role", "generation", "profile_sha256", "cap_seconds", "channel_instance_sha256",
                             "reservation_witness_sha256"}}
    require(set(payloads) == set(life.PERMISSIONS), "unsupported lifecycle event vocabulary")
    allowed = bootstrap if initial else payloads
    require(kind in allowed, "invalid lifecycle event shape")
    common = set() if initial or kind in {"publish", "meter", "succeed"} else {"request_id", "request_sha256"}
    require(set(event) == {"type"} | common | allowed[kind], "invalid lifecycle event shape")
    if common:
        matching(event["request_id"], SLUG, "lifecycle request id")
        matching(event["request_sha256"], SHA256, "lifecycle request sha256")
    elif kind == "meter":
        matching(event["subject"], SLUG, "meter subject")
        require(type(event["active_seconds"]) in (int, float)
                and (event["open_since"] is None or isinstance(event["open_since"], str)), "invalid lifecycle event shape")
    elif kind == "succeed":
        matching(event["predecessor"], SLUG, "succession predecessor")
        matching(event["checkpoint_sha256"], SHA256, "succession checkpoint sha256")
    return event


class _CapturedLifecycle(Lifecycle):
    """Pinned lifecycle reducers over the operation's captured bytes, indexed once per revision."""
    def __init__(self, root, operation):
        with operation.capture():
            operation.reject_failed()
            operation.path_guard.check(root)
            self.root = Path(root)
        self.operation, self.records, self.index = operation, [], {}
        self.private_refusals = {}
        self.declared_references = {}
        self.reference_operations = {}
        self.unknown_rows = {}
        self.refused_events = set()
        self._snapshot = None

    @_operation_context
    def _replay(self):
        reducer = _inert_evidence_reducer(_guard=self.operation.path_guard)
        with self.operation.capture():
            policy = reducer.validate_policy(self.operation.json(self.root / "policy.json", limit=life.MAX_BYTES))
        paths = self.operation.entries(self.root / "events", append=True)
        require(len(paths) <= life.MAX_EVENTS, "lifecycle event limit reached")
        if self._snapshot is not None and len(paths) == len(self.records):
            self.operation.recheck_files(paths, limit=life.MAX_BYTES)
            return copy.deepcopy(self._snapshot)
        state, genesis = life.initial_state(policy), None
        # Dependency captures belong to this operation, not a journal revision.
        # An appended event cannot replace their witnesses or clear a failure.
        self.records, self.index, self.private_refusals, self.unknown_rows = [], {}, {}, {}
        self.declared_references = {}
        self.refused_events = set()
        seen = set()
        for sequence, path in enumerate(paths, 1):
            require(path.name == "%06d.json" % sequence, "journal gap or uncommitted entry: " + path.name)
            record = self.operation.json(path, limit=life.MAX_BYTES, private=False)
            fields(record, {"schema", "sequence", "previous", "policy_sha256", "at", "envelope", "event_sha256"})
            require(record["schema"] == life.JOURNAL and type(record["sequence"]) is int
                    and record["sequence"] == sequence, "invalid journal sequence/schema")
            require(record["previous"] == state["head"], "journal hash chain mismatch")
            require(record["policy_sha256"] == digest(policy), "journal policy sha256 mismatch")
            require(record["event_sha256"] == digest(record["envelope"]), "journal event sha256 mismatch")
            parse_time(record["at"])
            require(isinstance(record["envelope"], dict) and isinstance(record["envelope"].get("id"), str),
                    "invalid lifecycle envelope")
            identifier = record["envelope"]["id"]
            require(identifier not in seen, "duplicate journal event id")
            seen.add(identifier)
            accepted = self._reduce_row(policy, state, record, reducer)
            if accepted:
                self.finish(state, record)
            else:
                # Hash-chain membership is evidence of the refused input, not a
                # successful lifecycle receipt. Keep the accepted prefix intact.
                state["sequence"], state["head"] = sequence, digest(record)
                self.refused_events.add(identifier)
            if record["envelope"].get("schema") == life.INITIAL_ENVELOPE and sequence == 1:
                genesis = copy.deepcopy(life.checkpoint(policy, state))
            self.records.append(record)
            event = record["envelope"]["event"]
            target = raw_value(event["request"])["id"] if event["type"] == "publish" else event.get("request_id")
            if accepted:
                self.index.setdefault((target, event["type"]), []).append(record)
        for identifier, row in state["requests"].items():
            if self._unknown_for(state, identifier):
                row["lifecycle_unknown"] = True
        if self.refused_events:
            state["_refused_event_ids"] = sorted(self.refused_events)
        self._snapshot = copy.deepcopy((policy, state, genesis))
        return policy, state, genesis

    def _reduce_row(self, policy, state, record, reducer):
        from hierarchy_router import PrivatePathError
        envelope = record["envelope"]
        event = _event_shape(envelope)
        target = event.get("request_id")
        if event["type"] == "publish":
            fields(event, {"type", "request"})
            published = raw_value(event["request"])
            require(isinstance(published, dict), "invalid lifecycle publish request")
            target = published.get("id")
        if event["type"] in {"meter", "succeed", "initial_reservations", "initial_creation"} or not isinstance(target, str):
            _private_paths(record, paths=self.operation.path_guard)
            reducer(policy, state, envelope, record["at"])
            return True
        refusals = []
        declared_references = []

        def scoped_path(value):
            try:
                self.operation.path_guard.refuse(value)
            except PrivatePathError as exc:
                refusals.append((str(exc.path), str(exc)))

        def declared(ref):
            # Only an exact inert evidence reference can be quarantined. All
            # malformed schema/hash/actor checks still run in the pinned reducer.
            fields(ref, {"path", "sha256"})
            path = Path(text(ref["path"], "evidence path"))
            matching(ref["sha256"], SHA256, "evidence sha256")
            require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
            scoped_path(path)
            # Journal references are inert claims. Canonical status/route must
            # not inspect their metadata or content, including on closed rows.
            declared_references.append(dict(ref))

        _private_paths(record, inert=declared, paths=scoped_path)
        inert_paths = {Path(ref["path"]) for ref in declared_references}
        if event["type"] == "publish":
            reducer(policy, state, envelope, record["at"], _refusals=refusals, _inert_paths=inert_paths)
        else:
            # Correlate with the pinned actor/custody and raw request checks
            # BEFORE allowing a semantic refusal to be scoped to an existing row.
            life.actor_for(policy, state, envelope)
            life.target(state, event)
            if event["type"] in {"admit", "intent", "wait", "small_change_plan"}:
                # These events can open meters or spend starts. An invalid one
                # has unknown accounting and cannot be silently omitted. A plan
                # registration also cannot disappear into an empty projection.
                require(not self._unknown_for(state, target), "unknown lifecycle accounting dependency")
                reducer(policy, state, envelope, record["at"], _refusals=refusals, _inert_paths=inert_paths)
            elif self._unknown_for(state, target):
                return False
            else:
                trial = dict(state, requests=dict(state["requests"]),
                             decisions=list(state["decisions"]), consumed=dict(state["consumed"]),
                             meters=copy.deepcopy(state["meters"]))
                trial["requests"][target] = copy.deepcopy(state["requests"][target])
                try:
                    reducer(policy, trial, envelope, record["at"], _refusals=refusals, _inert_paths=inert_paths)
                except (ValueError, OSError, TypeError, KeyError) as exc:
                    _raise_global(exc, operation=self.operation)
                    if _disposition(exc, guard=self.operation.path_guard, seam="trial") == GLOBAL:
                        raise
                    self.unknown_rows[target] = "lifecycle row UNKNOWN at event %s: %s" % (envelope["id"], exc)
                    return False
                state.update(trial)
        self.declared_references.setdefault(target, []).extend(declared_references)
        if refusals:
            self.private_refusals.setdefault(target, []).extend(refusals)
            if event["type"] in {"disposition", "resolve"} and event["resolution"]["kind"] == "next":
                following = raw_value(event["resolution"]["request"])["id"]
                self.private_refusals.setdefault(following, []).extend(refusals)
        if event["type"] in {"disposition", "resolve"} and event["resolution"]["kind"] == "next":
            following = raw_value(event["resolution"]["request"])["id"]
            self.declared_references.setdefault(following, []).extend(declared_references)
        return True

    def _unknown_for(self, state, identifier):
        pending, seen = [identifier], set()
        while pending:
            key = pending.pop()
            if key in seen:
                continue
            seen.add(key)
            if key in self.unknown_rows:
                return self.unknown_rows[key]
            row = state["requests"].get(key)
            if row is not None:
                pending.extend([row["request"]["authority"], *row["request"]["prerequisites"]])
        return None

    @_operation_context
    def refusals_for(self, identifier, *, consume=False):
        result, pending, seen = [], [identifier], set()
        state = self._snapshot[1] if self._snapshot is not None else None
        while pending:
            key = pending.pop()
            if key in seen:
                continue
            seen.add(key)
            result.extend(self.private_refusals.get(key, []))
            if key in self.unknown_rows:
                result.append((str(self.root), self.unknown_rows[key]))
            row = state["requests"].get(key) if state is not None else None
            if row is not None:
                pending.extend([row["request"]["authority"], *row["request"]["prerequisites"]])
        if consume and not result:
            # Producer-sized bounds apply to each reference, including policy
            # authority. Other rows' evidence remains inert. Hashes are shared
            # only for the same captured identity/mark within this pass.
            if identifier not in self.reference_operations:
                self.reference_operations[identifier] = _Operation(reference_cache=self.operation.reference_cache,
                                                                   parent=self.operation)
            references = self.reference_operations[identifier]
            groups = (self._snapshot[0]["authority"], *(self.declared_references.get(key, []) for key in sorted(seen)))
            for group in groups:
                for ref in group:
                    try:
                        references.reject_failed()
                        actual = references.reference(ref["path"])
                        require(actual == ref, "evidence reference hash mismatch")
                    except (ValueError, OSError) as exc:
                        _raise_global(exc, operation=self.operation)
                        references.fail(exc)
                        if _disposition(exc, guard=self.operation.path_guard, seam="consume", path=ref["path"]) == QUARANTINE:
                            self.private_refusals.setdefault(identifier, []).append((ref["path"], str(exc)))
                        else:
                            self.operation.fail(exc)
                        result.append((ref["path"], str(exc)))
        # Captured-reference failures propagate just like lexical refusals. In
        # particular, recheck an earlier dependency capture before publication.
        for key in sorted(seen):
            references = self.reference_operations.get(key)
            if references is None:
                continue
            try:
                references.verify()
            except (ValueError, OSError) as exc:
                _raise_global(exc, operation=self.operation)
                if _disposition(exc, guard=self.operation.path_guard, seam="consume") != QUARANTINE:
                    self.operation.fail(exc)
                result.append((str(self.root), "declared evidence changed: " + str(exc)))
        return result

    @_operation_context
    def verify_dependencies(self, identifier):
        refusals = self.refusals_for(identifier, consume=True)
        require(not refusals, refusals[0][1] if refusals else "lifecycle dependency evidence unavailable")

    @_operation_context
    def _record_under_lock(self, envelope, policy, state):
        # Only the dispatcher's existing router route authority uses this private seam.
        fields(envelope, {"id", "actor", "generation", "custody", "event"})
        event = _event_shape(envelope)
        require(event["type"] == "route", "captured lifecycle writer only records route")
        matching(envelope["id"], SLUG, "event id")
        require(envelope["id"] not in self.refused_events, "event id belongs to refused journal input")
        previous = state["receipts"].get(envelope["id"])
        if previous:
            require(previous["event_sha256"] == digest(envelope), "event id conflicts with different bytes")
            return previous
        life.actor_for(policy, state, envelope)
        require(state["sequence"] < life.MAX_EVENTS, "lifecycle event limit reached")
        record = {"schema": life.JOURNAL, "sequence": state["sequence"] + 1, "previous": state["head"],
                  "policy_sha256": digest(policy), "at": protocol.timestamp(), "envelope": envelope, "event_sha256": digest(envelope)}
        life.reduce_event(policy, state, envelope, record["at"])
        path = self.root / "events" / ("%06d.json" % record["sequence"])
        raw = encoded(record) + b"\n"
        evidence = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}
        self.operation.verify()
        if "small_change" in state["requests"][envelope["event"]["request_id"]]:
            self.verify_dependencies(envelope["event"]["request_id"])
        life.publish_file(path, raw, limit=life.MAX_BYTES)
        # Publication returned: retain its original identity even if durability or a later witness check fails.
        try:
            life.sync_directory(path.parent)
            self.operation.accept(path, evidence["sha256"])
            self.operation.verify()
            if "small_change" in state["requests"][envelope["event"]["request_id"]]:
                self.verify_dependencies(envelope["event"]["request_id"])
        except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
            raise _CommittedEvent(envelope["id"], evidence, exc) from exc
        return self.finish(state, record)


class _CommittedEvent(RuntimeError):
    """A known journal publication must never enter the router's ValueError/busy retry loop."""
    def __init__(self, event_id, evidence, error):
        super().__init__("committed route event " + evidence["path"] + " sha256 " + evidence["sha256"]
                         + " requires reconciliation: " + str(error))
        self.record = {"message_id": event_id, "evidence": dict(evidence)}


class PartialPublication(ValueError):
    def __init__(self, record, error):
        super().__init__("committed publication requires reconciliation: " + str(error))
        self.record, self.error = record, error


class _CapturedMailbox(Mailbox):
    """Operation-local captures for every virtual validation/publication hook."""
    def __init__(self, root, *, _operation=None):
        self.operation = _operation if _operation is not None else _Operation()
        with self.operation.capture():
            self.operation.reject_failed()
            self.operation.path_guard.check(root)
            self.root = Path(root)
            self.manifest = protocol.validate_manifest(self.operation.json(self.root / "manifest.json"))
        self._records = None
        self._record_folders = None
        self.message_refusals = {}
        self._stored_message_paths = None
        self._stored_message_refusals = None
        self._publishing = False
        self._publication = None
        self.before_publication = None

    @_operation_context
    def brief(self, reference, *, verify=True):
        from hierarchy_router import PrivatePathError
        # A cache hit already has a validated envelope/path; defer metadata checks to the effect boundary.
        fields(reference, {"path", "sha256"})
        matching(reference["sha256"], SHA256, "brief sha256")
        path = Path(text(reference["path"], "brief path"))
        stored = self._stored_message_paths is not None
        if not stored:
            try:
                with self.operation.required():
                    self.operation.path_guard.check(path)
            except PrivatePathError as exc:
                self.operation.fail(exc)
                raise
            except (ValueError, OSError) as exc:
                _raise_global(exc, operation=self.operation)
                raise UnverifiedAttachment(str(exc)) from exc
        if path not in self.operation.files and not stored:
            require(path.suffix == ".md", "brief must be a Markdown file")
            require(self.root.parent in path.parents, "brief must be within the mailbox parent directory")
        else:
            require(path.suffix == ".md", "brief must be a Markdown file")
            # Exact already-quarantined private declarations stay inert even
            # outside the parent; they are never opened or usable as briefs.
            quarantined = stored and path in self._stored_message_paths
            require(path.is_absolute() and ".." not in path.parts and (quarantined or self.root.parent in path.parents),
                    "brief must be within the mailbox parent directory")
        if not verify:
            return None
        try:
            actual, raw = self.operation.read(reference["path"])
        except FileNotFoundError as exc:
            raise UnverifiedAttachment("file unavailable: " + reference["path"]) from exc
        except PrivatePathError:
            raise
        except (ValueError, OSError) as exc:
            _raise_global(exc, operation=self.operation)
            # Metadata rejects linked/nonregular/oversized notes before open.
            # Unread typed-note consumers retain these as unverified claims;
            # open dispatch/job consumers still propagate this refusal.
            raise UnverifiedAttachment(str(exc)) from exc
        if actual["sha256"] != reference["sha256"]:
            raise UnverifiedAttachment("brief sha256 mismatch")
        return raw

    @_operation_context
    def readiness(self, readiness, *, observe=True):
        private = self._stored_message_paths if self._stored_message_paths is not None else set()
        def path(value):
            candidate = Path(value)
            require(candidate.is_absolute() and ".." not in candidate.parts, "path must be absolute without traversal")
            if candidate in private:
                return candidate
            # Historical readiness remains a local metadata declaration even
            # when its mailbox is inspected inside a required proof pass.
            route = self.operation.path_guard._acquisition_route
            token = route.set("metadata") if self._stored_message_paths is not None else None
            try:
                observation = (_declaration_operation(self.operation, _proof=False)
                    if self._stored_message_paths is not None else self.operation)
                with observation.active():
                    self.operation.path_guard.check(candidate, scope=True)
                    if observation is not self.operation:
                        observation.verify()
                return candidate
            except (ValueError, OSError) as exc:
                if (self._stored_message_paths is None or _disposition(exc, guard=self.operation.path_guard,
                        seam="readiness", path=candidate) != QUARANTINE):
                    raise
                self._stored_message_paths.add(candidate)
                self._stored_message_refusals.append(str(exc))
                return candidate
            finally:
                if token is not None:
                    route.reset(token)
        original = Mailbox.readiness
        function = FunctionType(original.__code__, dict(original.__globals__, safe_path=path),
                                original.__name__, original.__defaults__, original.__closure__)
        function.__kwdefaults__ = original.__kwdefaults__
        return function(self, readiness, observe=observe)

    @_operation_context
    def check_ref(self, ref):
        with self.operation.capture():
            fields(ref, {"path", "sha256"})
            matching(ref["sha256"], SHA256, "reference sha256")
            text(ref["path"], "reference path")
            self.operation.check_ref(ref)

    @_operation_context
    def stage(self, raw, reference):
        # Repeated checks share one content-addressed packet. Reuse its capture,
        # including after a partial batch, without rereading it through publish().
        require_secure_publication()
        fields(reference, {"path", "sha256"})
        matching(reference["sha256"], SHA256, "brief sha256")
        text(reference["path"], "brief path")
        _acquire("witness", "output", reference["path"], _guard=self.operation.path_guard)
        self.brief(reference, verify=False)
        if Path(reference["path"]) not in self.operation.files:
            info, _ancestors = _acquire("proof", _scope_reference_info,
                (Path(reference["path"]), self.operation.path_guard), {}, _guard=self.operation.path_guard)
            if isinstance(info, _AbsentReference):
                publish(raw, reference, _operation=self.operation)
                return
        require(self.brief(reference) == raw, "content-addressed brief already exists with different bytes")

    @_operation_context
    def dispatch_history(self, records):
        history = super().dispatch_history(records)
        if self._publishing:
            # Last virtual call before the pinned dispatch/job_request commit. Reply publication is not borrowed.
            if self.before_publication is not None:
                self.before_publication(self._publication)
            self.operation.verify()
        return history

    @_operation_context
    def publish(self, request):
        require(request["type"] in {"dispatch", "job_request"}, "captured dispatcher cannot publish participant replies")
        self._publishing = True
        self._publication = request
        try:
            record = super().publish(request)
        finally:
            self._publishing = False
            self._publication = None
        try:
            self.operation.accept(record["path"], record["sha256"])
            self.operation.verify()
        except (ValueError, OSError) as exc:
            raise PartialPublication(record, exc) from exc
        self._records[request["message_id"]] = record
        return record


    @_operation_context
    def bindings(self, endpoint):
        self.endpoint(endpoint)
        directory = safe_path(self.root / "bindings" / endpoint)
        result = []
        entries = self.operation.entries(directory, optional=True)
        for path in entries:
            safe_path(path)
            require(re.fullmatch(r"\d{6}\.(json|ack)", path.name) is not None or path.name.startswith(".pending-"),
                    "unexpected binding history entry")
        for path in (p for p in entries if p.suffix == ".json"):
            require(len(result) < protocol.MAX_RECORDS, "binding history exceeds record limit")
            record = self.operation.json(path)
            fields(record, {"schema", "endpoint", "host", "session", "generation", "created_at", "checkpoint", "checkpoint_sha256"})
            require(record["schema"] == "aegis.role-binding/v1" and record["endpoint"] == endpoint,
                    "malformed role binding")
            integer(record["generation"], "binding generation")
            require(record["generation"] == len(result) + 1 and path.name == "%06d.json" % record["generation"],
                    "nonconsecutive binding history")
            text(record["host"], "host", 128)
            text(record["session"], "session", 256)
            parse_time(record["created_at"])
            if record["generation"] == 1:
                require(record["checkpoint"] is None and record["checkpoint_sha256"] is None, "invalid initial binding")
            else:
                self.checkpoint(record["checkpoint"], {}, verify=False)
                require(digest(record["checkpoint"]) == record["checkpoint_sha256"], "checkpoint digest mismatch")
            result.append(record)
        for path in (p for p in entries if p.suffix == ".ack"):
            generation = int(path.stem)
            require(1 < generation <= len(result), "handoff acknowledgment has no replacement binding")
            ack = self.operation.json(path)
            fields(ack, {"endpoint", "generation", "session", "checkpoint_sha256"})
            require(ack == {key: result[generation - 1][key] for key in ack},
                    "handoff acknowledgment does not match binding")
        return result

    @_operation_context
    def ready(self, binding):
        if binding["generation"] == 1:
            return True
        with self.operation.required():
            path = safe_path(self.root / "bindings" / binding["endpoint"] / ("%06d.ack" % binding["generation"]))
        if not self.operation.exists(path):
            return False
        ack = self.operation.json(path)
        fields(ack, {"endpoint", "generation", "session", "checkpoint_sha256"})
        require(ack == {key: binding[key] for key in ack}, "handoff acknowledgment does not match binding")
        return True

    @_operation_context
    def messages(self):
        if self._records is not None:
            self.operation.json(self.root / "manifest.json")
            for folder in self._record_folders:
                self.operation.entries(folder)
            self.operation.recheck_files([record["path"] for record in self._records.values()])
            return dict(self._records)
        records = {}
        folders = {self.root / endpoint.split("/")[0] / endpoint.split("/")[1]
                   for endpoint in self.manifest["endpoints"]}
        folders |= {self.root / "across" / role for role in protocol.ACROSS_ROLES}
        self._record_folders = sorted(folders)
        for folder in self._record_folders:
            safe_path(folder)
            for path in self.operation.entries(folder):
                info, _ancestors = _proof_check(path, _guard=self.operation.path_guard)
                require(not stat.S_ISLNK(info.st_mode), "symlink mailbox entry is not supported")
                if path.name.startswith(".pending-"):
                    continue
                require(path.suffix == ".md", "unexpected mailbox entry: " + str(path))
                require(len(records) < protocol.MAX_RECORDS, "mailbox exceeds record limit")
                raw = self.operation.read(path)[1].decode("utf-8")
                try:
                    require(raw.startswith("---\n"), "missing header")
                    header, body = raw[4:].split("\n---\n\n", 1)
                    message = _bounded_json(header)
                    message["body"] = body
                    from hierarchy_router import PrivatePathError
                    private, refusals = set(), []
                    def declared_path(value):
                        try:
                            self.operation.path_guard.refuse(value)
                        except PrivatePathError as exc:
                            private.add(Path(value))
                            refusals.append(str(exc))
                    _private_paths(message, paths=declared_path)
                    self._stored_message_paths = private
                    self._stored_message_refusals = refusals
                    try:
                        destination = self.validate_message(message, stored=True)
                    finally:
                        self._stored_message_paths = None
                        self._stored_message_refusals = None
                    require(destination == folder, "message is in the wrong routing folder")
                    require(message["message_id"] not in records, "duplicate message_id in history")
                    records[message["message_id"]] = {"path": str(path), "message": message}
                    if refusals:
                        self.message_refusals[message["message_id"]] = [
                            "malformed mailbox message: " + str(path) + ": " + error for error in refusals]
                except (ValueError, TypeError, KeyError) as exc:
                    _raise_global(exc, operation=self.operation)
                    raise ValueError("malformed mailbox message: " + str(path) + ": " + str(exc)) from exc
        for record in records.values():
            message = record["message"]
            if "in_reply_to" in message:
                self.reply(message, records)
        for record in records.values():
            path = Path(record["path"])
            ref, _raw, witness = self.operation.files[path]
            self.operation.files[path] = ref, None, witness
        self._records = records
        return dict(records)

    @_operation_context
    def delivery_receipts(self, directory, kind, endpoint, records):
        folder = safe_path(self.delivery_directory(directory) / kind / endpoint)
        if not self.operation.exists(folder):
            return []
        history = self.bindings(endpoint)
        receipts = []
        for path in self.operation.entries(folder):
            safe_path(path)
            if path.name.startswith("."):
                continue
            require(len(receipts) < protocol.MAX_RECORDS, "delivery receipt history exceeds record limit")
            try:
                receipts.append(self._delivery_receipt(self.operation.json(path), kind, endpoint, history, records))
            except (ValueError, TypeError, KeyError, UnicodeError) as exc:
                _raise_global(exc, operation=self.operation)
                raise ValueError("malformed delivery receipt: " + str(path) + ": " + str(exc)) from exc
        return receipts


def check_ref(ref):
    fields(ref, {"path", "sha256"})
    matching(ref["sha256"], SHA256, "reference sha256")
    require(file_ref(text(ref["path"], "reference path")) == ref,
            "reference sha256 mismatch: " + ref["path"])


class Brief:
    def __init__(self, *, _check_ref=check_ref, _operation=None, _authoritative=False):
        self.sections = {name: [] for name in SECTIONS}
        self.seen = set()
        self.inline = ""
        self.notes = {name: [] for name in SECTIONS}
        self.check_reference = _check_ref
        self.operation = _operation if _operation is not None else _Operation()
        self.reference = self.operation.reference
        self.authoritative = _authoritative

    def add(self, section, kind, ref, **details):
        item = {"kind": kind, "ref": ref, **details}
        key = (section, encoded(item))
        if key in self.seen:
            return
        require(len(self.seen) < MAX_ENTRIES, "fresh brief exceeds 256 entries")
        self.seen.add(key)
        self.sections[section].append(item)

    @_operation_context
    def evidence(self, value, origin):
        """Keep unavailable or mismatched evidence as a declaration anchored to its durable record."""
        from hierarchy_router import PrivatePathError
        if isinstance(value, dict):
            if set(value) == {"path", "sha256"}:
                try:
                    if self.authoritative:
                        if not _descriptor_capabilities():
                            refused = _ProofPathError("secure scope proof requires directory descriptor support")
                            _acquisition_detect(self.operation.path_guard, "CHANGED", refused)
                            raise refused
                        self.check_reference(value)
                    else:
                        path = Path(text(value["path"], "reference path"))
                        _recheck_consumed_reference(self.operation, path)
                        declaration = _declaration_operation(self.operation)
                        declaration.check_ref(value)
                        declaration.verify()
                        # A successful declaration becomes a primary brief reference.
                        # Retain its validated witness without repeating the read;
                        # only failed declarations stay outside the parent.
                        self.operation.files.setdefault(path, declaration.files[path])
                except PrivatePathError:
                    raise
                except (ValueError, OSError) as exc:
                    _raise_global(exc, operation=self.operation)
                    if self.authoritative:
                        raise
                    self.add("Evidence references", "unverified_evidence", origin, declared=value,
                             state="unavailable_or_mismatched")
                else:
                    self.add("Evidence references", "evidence", value)
            else:
                for key in sorted(value):
                    self.evidence(value[key], origin)
        elif isinstance(value, list):
            for item in value:
                self.evidence(item, origin)

    def render(self, endpoint, as_of, generation):
        lines = ["# Fresh thread brief", "<!-- " + SCHEMA + " -->", "", "Endpoint: " + endpoint,
                 "As of: " + as_of, "Target generation: " + str(generation), "",
                 "Resume path: First verify this brief and its references, then read the current binding and checkpoint; "
                 "acknowledge a successor checkpoint through your own connection, page the inbox from your own "
                 "generation's cursor (from the beginning for a new generation), and "
                 "reconcile unknown effects and original job IDs before considering new work. "
                 "Before resuming, validate expiry live; this snapshot grants no continuing authority. "
                 "Missing records require a hold; this brief grants no authority."]
        for name, items in self.sections.items():
            lines += ["", "## " + name, ""]
            lines.extend(self.notes[name])
            lines.extend("- " + json.dumps(item, sort_keys=True, ensure_ascii=True, allow_nan=False) for item in items)
            if not items:
                lines.append("No entries recorded in the inspected inputs; absence is not approval or settlement.")
            if name == "Role contract" and self.inline:
                lines += ["", "Contract text, rendered as on first start:", ""]
                lines.extend("> " + line for line in self.inline.splitlines())
        raw = ("\n".join(lines) + "\n").encode("utf-8")
        require(len(raw) <= MAX_BYTES, "fresh brief exceeds mailbox brief byte limit (262144)")
        return raw


def locate(root, initiative, *, _mailbox=None, _operation=None):
    """Accept a team run, its initiative base, or the mailbox root used by handoff entries."""
    operation = _mailbox.operation if _mailbox is not None else (_operation or _Operation())
    with operation.capture():
        return _locate(root, initiative, _mailbox=_mailbox, operation=operation)


def _locate(root, initiative, *, _mailbox, operation):
    if operation.exists(root / "manifest.json"):
        base, mailbox_root, run = root.parent, root, root.parent
    else:
        base = root if operation.exists(root / "provision.json") else root / "initiatives" / initiative
        mailbox_root, run = base / "mailbox", root
    provision = safe_path(base / "provision.json")
    setup = operation.json(provision) if operation.exists(provision) else None
    if setup is not None:
        require(isinstance(setup, dict) and setup.get("initiative") == initiative, "provision initiative mismatch")
        named = safe_path(text(setup.get("mailbox_root"), "provision mailbox_root"))
        require(named == mailbox_root, "provision does not name this mailbox root")
    # A base supplied directly still uses the team run's shared lifecycle folder.
    if base.parent.name == "initiatives":
        run = base.parent.parent
    require(_mailbox is None or _mailbox.root == mailbox_root, "composer mailbox root mismatch")
    return _mailbox if _mailbox is not None else _CapturedMailbox(mailbox_root, _operation=operation), base, run, setup


def tidy_contract(lines):
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def template_view(content, family, origin):
    """Pure template rendering, pinned against launcher.start_prompt by subprocess tests.

    Importing the launcher also imports executable MCP startup guards. Keep this
    small reader local while the allowed change scope excludes the launcher.
    Marker examples inside Markdown fences remain literal, as in the launcher.
    """
    kept, opened, fence = [], None, None
    for number, line in enumerate(content.splitlines(), 1):
        if fence is not None:
            if opened is None or opened[1] == family:
                kept.append(line)
            if re.fullmatch(r" {0,3}" + re.escape(fence[0]) + r"{%d,}\s*" % len(fence), line):
                fence = None
            continue
        opening = re.fullmatch(r" {0,3}(`{3,}|~{3,})(.*)", line)
        if opening and not (opening.group(1)[0] == "`" and "`" in opening.group(2)):
            fence = opening.group(1)
            if opened is None or opened[1] == family:
                kept.append(line)
            continue
        marker = re.fullmatch(r"<!-- host:([a-z]+) -->", line.strip())
        if marker:
            require(opened is None, "unbalanced host markers in %s: line %d opens a nested block" % (origin, number))
            require(marker.group(1) in {"claude", "codex"}, "invalid host marker in %s: line %d" % (origin, number))
            opened = (number, marker.group(1))
        elif line.strip() == "<!-- /host -->":
            require(opened is not None, "unbalanced host markers in %s: line %d closes no block" % (origin, number))
            opened = None
        else:
            require(re.search(r"<!--\s*/?\s*host\b", line, re.IGNORECASE) is None,
                    "invalid host marker in %s: line %d" % (origin, number))
            if opened is None or opened[1] == family:
                kept.append(line)
    require(opened is None, "unbalanced host markers in " + str(origin))
    return tidy_contract(kept)


def contract_text(source, role, family, *, _operation=None):
    operation = _operation if _operation is not None else _Operation()
    folder = source / "tools/hierarchy_templates/roles"
    path = folder / ("lane.md" if role == "implementer" else role + ".md")
    files = ([folder / "lane.md"] if role in {"reviewer", "integrator"} else []) + [path]
    parts, contracts = [], []
    for each in files:
        require(operation.exists(each), "no role contract for %s: %s" % (role, each))
        ref, raw = operation.read(each, budget_error="fresh brief exceeds mailbox brief byte limit (262144)")
        contracts.append(ref)
        parts.append(template_view(raw.decode("utf-8"), family, each))
    if len(parts) > 1:
        headings = ("## Assignments", "## Protocol checklist")
        require(all(heading in parts[-1].splitlines() for heading in headings),
                "%s must restate lane.md's %s for its kind" % (path, " and ".join(headings)))
        headings += ("## Writing rules",) if role == "reviewer" else ()
        kept, skipping = [], False
        for line in parts[0].splitlines():
            if line.startswith(("# ", "## ")):
                skipping = line.strip() in headings
            if not skipping:
                kept.append(line)
        parts[0] = tidy_contract(kept)
    return "\n\n".join(parts), contracts


@_operation_context
def role_contract(brief, mailbox, base, setup, endpoint):
    # Role resolution must use the same bounded snapshot/witness as the rendered contracts.
    registry = hierarchy_roles.validate(brief.operation.json(hierarchy_roles.PATH))
    endpoint_role = endpoint_parts(endpoint)[1]
    key = mailbox.endpoint(endpoint).get("kind") if endpoint_role == "lane" else endpoint_role
    role = next((name for name, entry in registry["roles"].items() if entry["endpoint"] is not None
                 and entry["endpoint"].get("lane_kind", entry["endpoint"]["role"]) == key), None)
    require(role is not None, "no registry role for endpoint " + endpoint)
    plan_path = base / hierarchy_hosts.PLAN_FILE
    plan = hierarchy_hosts.validate_plan(brief.operation.json(plan_path)) if brief.operation.exists(plan_path) else None
    require(plan is None or plan["hierarchy"] == endpoint_parts(endpoint)[0], "host plan hierarchy mismatch")
    host, _ = hierarchy_hosts.plan_host(plan, endpoint)
    family = hierarchy_hosts.family(host) if host is not None else "codex"
    source = safe_path(setup["source"]) if setup else _acquire("source", __file__).parents[1]
    if plan is not None:
        brief.add("Evidence references", "host_plan", brief.reference(base / hierarchy_hosts.PLAN_FILE))
    if role == "root":
        # ROOT never starts through the launcher, so its contract is referenced, not inlined.
        contracts = [brief.operation.read(source / "tools/hierarchy_templates/roles/root.md")[0]]
    else:
        brief.inline, contracts = contract_text(source, role, family, _operation=brief.operation)
    for contract in contracts:
        brief.check_reference(contract)
        brief.add("Role contract", "role_contract", contract, role=role, family=family)
    if role in {"implementer", "integrator"}:
        template = "lane-brief-claude.md" if family == "claude" else "lane-brief.md"
        brief.add("Evidence references", "assignment_template", brief.operation.read(source / "tools/hierarchy_templates" / template)[0])


@_operation_context
def lifecycle_records(brief, directory, at, *, request_id=None):
    require(brief.operation.exists(directory), "lifecycle directory unavailable: " + str(directory))
    lifecycle = brief.operation.lifecycle(directory)
    status = lifecycle.status()
    policy_ref = brief.reference(directory / "policy.json")
    brief.add("Evidence references", "lifecycle_policy", policy_ref)
    selected = None
    if request_id is not None:
        selected, pending = set(), [request_id]
        while pending:
            identifier = pending.pop()
            if identifier in selected:
                continue
            require(identifier in status["requests"], "lifecycle dependency is unavailable")
            selected.add(identifier)
            request = status["requests"][identifier]["request"]
            pending.extend([request["authority"], *request["prerequisites"]])
        brief.notes["Open obligations"].append("Lifecycle coverage is limited to this request's authority and prerequisite closure.")
    else:
        brief.notes["Open obligations"].append("Lifecycle coverage is journal-wide: requests have no durable endpoint mapping.")
    events, created, latest = [], {}, {}
    for record in lifecycle.records:
        event = record["envelope"]["event"]
        events.append(record)
        identifier = event.get("request_id")
        if event["type"] == "publish":
            identifier = raw_value(event["request"])["id"]
            created.setdefault(identifier, record)
        elif record["envelope"]["id"] not in lifecycle.refused_events and event["type"] in {"disposition", "resolve"} and event["resolution"]["kind"] == "next":
            successor = raw_value(event["resolution"]["request"])["id"]
            created[successor] = latest[successor] = record
        if identifier is not None:
            latest[identifier] = record
    if events:
        brief.add("Evidence references", "lifecycle_head", brief.reference(directory / "events" / ("%06d.json" % status["sequence"])),
                  sequence=status["sequence"], journal_head_sha256=status["head"])
    brief.evidence(brief.operation.json(directory / "policy.json", limit=life.MAX_BYTES)["authority"], policy_ref)

    def reference(record):
        return brief.reference(directory / "events" / ("%06d.json" % record["sequence"]))

    def add_event(record):
        event = record["envelope"]["event"]
        origin = reference(record)
        brief.add("Evidence references", "lifecycle_event", origin, event_type=event["type"],
                  event_id=record["envelope"]["id"], request_id=event.get("request_id"))
        brief.evidence(event, origin)
        if event["type"] == "terminal":
            brief.evidence(raw_value(event["result"])["evidence"], origin)
        return origin

    def provenance(mark, kind, identifier):
        # Reduced marks carry actor/generation/time, not journal sequence numbers.
        matches = []
        for record in lifecycle.index.get((identifier, kind), []):
            envelope = record["envelope"]
            event = envelope["event"]
            if (event["type"] == kind and event.get("request_id") == identifier
                    and envelope["actor"] == mark["actor"] and envelope["generation"] == mark["generation"]
                    and record["at"] == mark["at"] and all(mark[key] == event[key] for key in mark.keys() & event.keys())):
                matches.append(record)
        require(bool(matches), "lifecycle mark has no journal provenance")
        return matches[-1]

    for identifier, row in sorted(status["requests"].items()):
        if selected is not None and identifier not in selected:
            continue
        refusals = lifecycle.refusals_for(identifier)
        if refusals:
            # Keep the row visible, without promoting a refused declaration into
            # another row's approved scope or a reference the inspector will open.
            brief.add("Open obligations", "lifecycle_hold", reference(latest[identifier]),
                      request_id=identifier, request_sha256=row["raw"]["sha256"],
                      state="held", reason="reference_unavailable", detail=refusals[0][1])
            continue
        if row["resolution"] and row["resolution"]["kind"] in {"complete", "next"}:
            if selected is not None:
                origin = add_event(latest[identifier])
                brief.add("Dependencies", "lifecycle_dependency", origin, request_id=identifier,
                          state=row["resolution"]["kind"])
                for kind in ("terminal", "review", "delivery"):
                    if row[kind]:
                        add_event(provenance(row[kind], kind, identifier))
            continue
        request = row["request"]
        origin = reference(created[identifier])
        decisions = [item for item in status["decisions"] if item["request_id"] == request["authority"]]
        authority = status["requests"].get(request["authority"], row)["request"]
        current_scope = all(parse_time(item["continuation"]["expires_at"]) > at for item in (request, authority))
        if current_scope:
            brief.add("Approved scope", "request_scope", origin, request_id=identifier,
                      request_sha256=row["raw"]["sha256"], paths=request["paths"], authority=request["authority"],
                      expires_at=request["continuation"]["expires_at"],
                      approval=decisions[-1]["decision"] if decisions else "not_recorded")
        brief.add("Source identity", "request_source", origin, request_id=identifier, source=request["source"])
        for prerequisite in request["prerequisites"]:
            brief.add("Dependencies", "prerequisite", origin, request_id=identifier, prerequisite=prerequisite,
                      state="recorded" if prerequisite in status["requests"] else "missing")
        change = row.get("small_change")
        if change and current_scope:
            registration = change["registration"]
            proposal = raw_value(registration["proposal"])
            brief.add("Approved scope", "small_change_plan", add_event(provenance(registration, "small_change_plan", identifier)), request_id=identifier,
                      plan_sha256=registration["proposal"]["sha256"], path_scopes=proposal["plan"]["path_scopes"],
                      checks=proposal["plan"]["checks"],
                      approval=change["decisions"][-1]["decision"] if change["decisions"] else "not_recorded")
        authorities = [(item, "decision", request["authority"]) for item in decisions[-1:]]
        if row["admission"]:
            authorities.append((row["admission"], "admit", identifier))
        if change:
            authorities += [(item, "small_change_decision", identifier) for item in change["decisions"][-1:]]
            if change["admission"]:
                authorities.append((change["admission"], "small_change_admit", identifier))
        for authority, kind, target in authorities:
            record = provenance(authority, kind, target)
            origin = add_event(record)
            event = record["envelope"]["event"]
            if current_scope:
                brief.add("Approved scope", "authority_record", origin, request_id=identifier,
                          event_type=event["type"], record_sha256=digest(authority),
                          decision=event.get("decision"), plan_sha256=event.get("plan_sha256"),
                          decision_sha256=event.get("decision_sha256"))
        # Only evidence belonging to unsettled rows becomes an individual entry.
        for kind in ("terminal", "review", "delivery"):
            if row[kind]:
                add_event(provenance(row[kind], kind, identifier))
    for obligation in status["obligations"]:
        if selected is not None and obligation["request_id"] not in selected:
            continue
        # Owner, next decision and the blocker stay in their validated lifecycle record.
        brief.add("Open obligations", "lifecycle_obligation", reference(latest[obligation["request_id"]]),
                  **{key: obligation[key] for key in ("request_id", "request_sha256", "state", "owner", "next_decision")})


def validate_packet_declaration(packet, message_id):
    """Validate the runner's common packet schema without admitting or executing a job.

    The runner has no standalone schema validator: admit() also requires live
    recipes, checkouts and dependency evidence. Reuse its constants and primitives
    here; recipe-specific and physical admission remain the runner's responsibility.
    """
    from hierarchy_jobs import (DEPENDENT_PACKET_SCHEMA, EMPTY_STATUS, GIT_ID, MAX_PATHS, MAX_PATHS_BYTES,
                                PACKET_SCHEMA, PATH_ARGUMENT, absolute)

    require(isinstance(packet, dict), "invalid JSON field: packet must be an object")
    schema = packet.get("schema")
    require(isinstance(schema, str) and schema in (PACKET_SCHEMA, DEPENDENT_PACKET_SCHEMA), "invalid schema/version")
    dependent = schema == DEPENDENT_PACKET_SCHEMA
    fields(packet, {"schema", "recipe", "checkout", "commit", "tree"} |
           ({"after", "recipes_sha256"} if dependent else set()),
           {"dirty_content_sha256", "paths", "expected_tree", "message", "merge"})
    matching(packet["recipe"], SLUG, "recipe")
    absolute(packet["checkout"], "checkout")
    for name in ("commit", "tree", "expected_tree", "merge"):
        if name in packet:
            matching(packet[name], GIT_ID, name)
    if "dirty_content_sha256" in packet:
        matching(packet["dirty_content_sha256"], SHA256, "dirty_content_sha256")
    if "message" in packet:
        text(packet["message"], "message", 65536)
    # checked_paths() accepts falsy values for recipes that take no paths.
    # Live recipe-specific admission remains with the runner.
    if packet.get("paths"):
        paths = packet["paths"]
        require(isinstance(paths, list) and len(paths) <= MAX_PATHS, "invalid paths")
        for index, path in enumerate(paths):
            label = "paths[%d]" % index
            matching(path, PATH_ARGUMENT, label)
            require(".." not in path.partition("::")[0].split("/"), "invalid " + label)
        require(len(json.dumps(paths)) <= MAX_PATHS_BYTES, "paths exceed runner byte limit")
    if dependent:
        require(isinstance(packet["after"], dict), "invalid after: expected a JSON object")
        fields(packet["after"], {"message_id", "sha256"})
        matching(packet["after"]["message_id"], SLUG, "after.message_id")
        matching(packet["after"]["sha256"], SHA256, "after.sha256")
        matching(packet["recipes_sha256"], SHA256, "recipes_sha256")
        require(packet["after"]["message_id"] != message_id, "invalid after: a job cannot depend on itself")
        require(packet.get("dirty_content_sha256", EMPTY_STATUS) == EMPTY_STATUS,
                "invalid dirty_content_sha256: dependent jobs require clean source")


@_operation_context
def job_packet(brief, mailbox, message, origin):
    from hierarchy_jobs import packet_text

    reference = message["brief"]
    raw = _attachment(mailbox, reference)
    try:
        content = packet_text(raw)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid packet %s field JSON: %s" % (reference["path"], exc)) from exc
    if not content.lstrip().startswith(("{", "[")):
        # Legacy prose packets cannot supply structured dependencies; retain the original, never guess.
        brief.add("Evidence references", "job_packet", reference, job_id=message["message_id"])
        brief.add("Dependencies", "unstructured_job_packet", origin, job_id=message["message_id"],
                  state="dependencies_not_recorded")
        return
    try:
        packet = _bounded_json(content)
    except ValueError as exc:
        raise ValueError("invalid packet %s field JSON: %s" % (reference["path"], exc)) from exc
    try:
        validate_packet_declaration(packet, message["message_id"])
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid packet %s: %s" % (reference["path"], exc)) from exc
    brief.add("Evidence references", "job_packet", reference, job_id=message["message_id"])
    if "after" in packet:
        after = packet["after"]
        brief.add("Dependencies", "job_after", reference, job_id=message["message_id"], after=after)
    source = {key: packet[key] for key in ("checkout", "commit", "tree", "paths", "dirty_content_sha256",
                                          "expected_tree", "merge", "recipes_sha256") if key in packet}
    if "paths" in source and not source["paths"]:
        source["paths"] = []  # The runner's effective no-paths value, never an object.
    if source:
        brief.add("Source identity", "job_source", reference, job_id=message["message_id"], source=source)


def receipt_order(record):
    message = record["message"]
    return parse_time(message["created_at"]), message["message_id"]


def job_state(receipts):
    """Only a strictly later terminal reply to this same request settles uncertainty.

    A timestamp tie cannot establish order. Conflicting terminal outcomes, or a
    terminal tied with unknown, stay unknown regardless of message-id spelling.
    """
    groups = {}
    for record in receipts:
        groups.setdefault(receipt_order(record)[0], []).append(record)
    state, witness = "unreconciled", None
    for _, group in sorted(groups.items()):
        group.sort(key=receipt_order)
        unknown = [row for row in group if row["message"]["receipt"]["state"] == "unknown"]
        terminal = [row for row in group if row["message"]["receipt"]["state"] in TERMINAL_JOB_STATES]
        outcomes = {(row["message"]["receipt"]["state"], row["message"]["receipt"].get("exit_code")) for row in terminal}
        if unknown or len(outcomes) > 1:
            state, witness = "unknown", (unknown or terminal)[-1]
        elif terminal:
            witness = terminal[-1]
            state = witness["message"]["receipt"]["state"]
        elif state != "unknown":
            witness = group[-1]
            state = witness["message"]["receipt"]["state"]
    return state, witness


@_operation_context
def unread_records(brief, mailbox, endpoint, delivery, records, generation):
    mailbox.delivery_directory(delivery)
    read_ids, own_reads, predecessor_reads, wakes = set(), set(), set(), {}
    receipts = {}
    for kind in ("reads", "wakes"):
        values = mailbox.delivery_receipts(delivery, kind, endpoint, records)
        folder = safe_path(delivery / kind / endpoint)
        paths = [path for path in brief.operation.entries(folder, optional=True) if not path.name.startswith(".")]
        require(len(paths) == len(values), "delivery history changed during composition")
        receipts[kind] = list(zip(paths, values))
        if paths:
            path, _ = max(receipts[kind], key=lambda item: (parse_time(item[1]["at"]), str(item[0])))
            brief.add("Evidence references", "delivery_" + ("read" if kind == "reads" else "wake"), brief.reference(path))
    for _, receipt in receipts["reads"]:
        read_ids.update(receipt["message_ids"])
        if receipt["generation"] == generation:
            own_reads.update(receipt["message_ids"])
        elif receipt["generation"] < generation:
            predecessor_reads.update(receipt["message_ids"])
    predecessor_reads -= own_reads
    if predecessor_reads:
        candidates = [(path, value) for path, value in receipts["reads"]
                      if value["generation"] < generation and predecessor_reads.intersection(value["message_ids"])]
        path, _ = max(candidates, key=lambda item: (parse_time(item[1]["at"]), str(item[0])))
        counts = {}
        for identifier in sorted(predecessor_reads):
            kind = records[identifier]["message"]["type"]
            counts[kind] = counts.get(kind, 0) + 1
        brief.add("Unread work", "predecessor_reads", brief.reference(path), state="read_by_predecessor",
                  count=len(predecessor_reads), generation=generation, message_types=counts)
    failed = {(value["generation"], value["wake_id"]) for _, value in receipts["wakes"] if value["state"] == "failed_to_start"}
    for path, receipt in receipts["wakes"]:
        if receipt["state"] == "started" and (receipt["generation"], receipt["wake_id"]) not in failed:
            for identifier in receipt["message_ids"]:
                wakes[identifier] = path
    brief.notes["Unread work"].append("Reads were applied for target generation %s. Predecessor-only reads are aggregated; "
                                      "never-read messages are listed individually." % generation)
    unread, after = set(), None
    while True:
        page = mailbox.inbox(endpoint, limit=100, after=after)
        for record in page["messages"]:
            identifier = record["message"]["message_id"]
            if identifier not in read_ids:
                unread.add(identifier)
                details = {"wake_ref": brief.reference(wakes[identifier])} if identifier in wakes else {}
                brief.add("Unread work", "message", brief.reference(record["path"]), message_id=identifier,
                          generation=generation, state="woken" if identifier in wakes else "published", **details)
        if page["next_after"] is None:
            return unread
        require(page["next_after"] != after, "inbox cursor did not advance")
        after = page["next_after"]


@contextmanager
def _attachment_message(message_id, *, authoritative):
    """Anchor every authoritative attachment refusal to its durable message."""
    try:
        yield
    except UnverifiedAttachment as exc:
        if not authoritative:
            raise
        raise UnverifiedAttachment("authoritative brief attachment is unverified",
                                   message_id=message_id) from exc


@_operation_context
def mailbox_records(brief, mailbox, endpoint, initiative, delivery, at, generation, binding, *, _authoritative=False):
    records = mailbox.messages()
    relevant = {key: row for key, row in records.items()
                if initiative in (endpoint_parts(row["message"]["from"])[0], endpoint_parts(row["message"]["to"])[0])}
    refused = mailbox.message_refusals
    usable = {k: r for k, r in records.items() if k not in refused and r["message"].get("in_reply_to") not in refused}
    closed, accepted = mailbox.dispatch_history(usable)
    if binding:
        origin = brief.reference(mailbox.root / "bindings" / endpoint / ("%06d.json" % binding["generation"]))
        brief.add("Evidence references", "binding", origin, generation=binding["generation"])
        if binding["checkpoint"]:
            # Old checkpoints remain records, not a source of currently held leases.
            brief.add("Evidence references", "checkpoint_history", origin, state="unverified")
    unread = unread_records(brief, mailbox, endpoint, delivery, records, generation)
    for identifier in sorted(set(relevant) & set(refused)):
        record = relevant[identifier]
        if endpoint in (record["message"]["from"], record["message"]["to"]):
            brief.add("Unread work", "message_hold", brief.reference(record["path"]), message_id=identifier,
                      state="held", reason="reference_unavailable", detail=refused[identifier][0])
    relevant = {k: r for k, r in relevant.items() if k in usable}
    historical = []

    def evidence(record):
        message = record["message"]
        origin = brief.reference(record["path"])
        brief.add("Evidence references", "mailbox_evidence", origin,
                  message_id=message["message_id"], message_type=message["type"])
        brief.evidence(message.get("receipt", {}), origin)

    job_receipts = {}
    for record in relevant.values():
        message = record["message"]
        if message["type"] == "job_receipt":
            job_receipts.setdefault(message["in_reply_to"], []).append(record)
    open_jobs = set()
    for identifier, record in sorted(relevant.items()):
        message = record["message"]
        if message["type"] != "job_request":
            continue
        receipts = job_receipts.get(identifier, [])
        state, witness = job_state(receipts)
        if state in TERMINAL_JOB_STATES:
            historical.extend([record] + receipts)
            continue
        open_jobs.add(identifier)
        origin = brief.reference(record["path"])
        with _attachment_message(identifier, authoritative=_authoritative):
            job_packet(brief, mailbox, message, origin)  # Missing/changed open packets refuse the whole composition.
        brief.add("Open obligations", "job", origin, job_id=initiative + "/" + identifier,
                  message_id=identifier, state=state)
        if witness:
            evidence(witness)
        if receipts:
            evidence(max(receipts, key=receipt_order))
    open_dispatches = set()
    for identifier, record in sorted(relevant.items()):
        message = record["message"]
        touching = endpoint in (message["from"], message["to"])
        if message["type"] != "dispatch" or not touching:
            continue
        if identifier in closed:
            historical.append(record)
            continue
        open_dispatches.add(identifier)
        with _attachment_message(identifier, authoritative=_authoritative):
            _attachment(mailbox, message["brief"])
        brief.add("Open obligations", "dispatch", brief.reference(record["path"]), message_id=identifier, state="open")
        brief.add("Evidence references", "message_brief", message["brief"], message_id=identifier)
        acknowledgments = [value for value in accepted if value["in_reply_to"] == identifier]
        if acknowledgments:
            acknowledgment = max(acknowledgments, key=lambda value: (parse_time(value["created_at"]), value["message_id"]))
            acknowledgment_record = relevant[acknowledgment["message_id"]]
            evidence(acknowledgment_record)
            if "readiness" in acknowledgment:
                ready = acknowledgment["readiness"]
                origin = brief.reference(acknowledgment_record["path"])
                brief.add("Source identity", "accepted_source", origin,
                          source={key: ready[key] for key in ("worktree", "branch", "base_revision")})
                if parse_time(ready["lease_expires_at"]) > at:
                    brief.add("Approved scope", "accepted_lease", origin, owned_paths=ready["owned_paths"],
                              **{key: ready[key] for key in ("lease_ref", "lease_oid", "lease_expires_at")})
    for identifier, record in sorted(relevant.items()):
        message = record["message"]
        kind = message["type"]
        parent = message.get("in_reply_to")
        if parent and parent not in open_jobs | open_dispatches and kind in {"job_receipt", "ack", "result", "review"}:
            historical.append(record)
        elif identifier in unread and kind in {"result", "review", "ack", "job_receipt"}:
            evidence(record)
        if "brief" in message and kind not in {"dispatch", "job_request"}:
            if identifier in unread:
                try:
                    with _attachment_message(identifier, authoritative=_authoritative):
                        _unread_attachment(mailbox, message["brief"], _authoritative=_authoritative)
                except UnverifiedAttachment:
                    if _authoritative:
                        # Authoritative composition refuses here, before a later
                        # metadata check can replace this typed attachment refusal.
                        raise
                    brief.add("Evidence references", "unverified_evidence", brief.reference(record["path"]),
                              declared=message["brief"], state="unavailable_or_mismatched")
                    continue
                brief.evidence(message["brief"], brief.reference(record["path"]))
            else:
                historical.append(record)
    if historical:
        # Mailbox files have no hash chain. This is a locator for retained history,
        # not a claim that one message authenticates all earlier mailbox records.
        brief.add("Evidence references", "mailbox_history", brief.reference(max(historical, key=receipt_order)["path"]),
                  state="unverified", historical_briefs="not_reverified")


def inspect(raw, *, _check_ref=check_ref, _operation=None):
    """Verify the seven-section format, the global count and every primary reference."""
    operation = _operation if _operation is not None else _Operation()
    with operation.capture():
        return _inspect(raw, _check_ref=_check_ref, operation=operation)


def _inspect(raw, *, _check_ref, operation):
    body = raw.decode("utf-8")
    require("<!-- " + SCHEMA + " -->" in body.splitlines(), "unsupported fresh brief schema")
    headings, count, resume = [], 0, 0
    for line in body.splitlines():
        if line.startswith("Resume path: "):
            resume += 1
        elif line.startswith("## "):
            headings.append(line[3:])
        elif line.startswith("- "):
            require(bool(headings), "entry outside a brief section")
            item = _bounded_json(line[2:])
            _private_paths(item, paths=operation.path_guard)
            require(isinstance(item, dict) and "kind" in item and "ref" in item, "invalid brief entry")
            text(item["kind"], "entry kind")
            _check_ref(item["ref"])
            count += 1
            require(count <= MAX_ENTRIES, "fresh brief exceeds 256 entries")
    require(tuple(headings) == SECTIONS and resume == 1, "invalid fresh brief sections or resume path")
    operation.verify()
    return count


def composition_time(value):
    if value is None:
        value = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2})(?:\.(\d+))?(?:[Zz]|\+00:00)", value)
    require(match is not None, "invalid --as-of: expected RFC3339 UTC")
    seconds = match.group(1).upper()
    fraction = (match.group(2) or "").rstrip("0")
    try:
        # Expiry records have microsecond precision. Retain the full input time
        # in the brief; truncation cannot cross an expiry on that precision grid.
        at = parse_time(seconds + "." + fraction[:6].ljust(6, "0") + "Z")
    except ValueError as exc:
        raise ValueError("invalid --as-of: expected RFC3339 UTC") from exc
    return at, seconds + ("." + fraction if fraction else "") + "Z"


def protect_stores(output, mailbox, base, run, lifecycle, delivery, setup):
    """Reject overlap in either direction, including stores declared by other run provisions."""
    output = safe_path(output)
    stores = {mailbox.root, lifecycle, delivery, run / "lifecycle", run / "store", base / "delivery"}
    provisions = {base / "provision.json", run / "evidence/provision-init.json", run / "inputs/provision-init.json"}
    folder = safe_path(run / "initiatives")
    for path in mailbox.operation.entries(folder, optional=True):
        # Capture each selected directory's identity even when its provision is absent.
        safe_path(path)
        if stat.S_ISDIR(_acquire("lstat", path, _guard=mailbox.operation.path_guard).st_mode):
            mailbox.operation.entries(path, identity_only=True)
            provisions.add(path / "provision.json")
    values = [setup] if setup is not None else []
    for path in sorted(provisions):
        path = safe_path(path)
        if mailbox.operation.exists(path):
            values.append(mailbox.operation.json(path))
    for record in values:
        require(isinstance(record, dict), "invalid provision record")
        for key in ("store", "board", "mailbox_root", "delivery_dir"):
            if key in record:
                stores.add(safe_path(text(record[key], "provision " + key)))
    for store in sorted(stores):
        store = safe_path(store)
        require(output != store and store not in output.parents and output not in store.parents,
                "output directory overlaps coordination store: " + str(store))


def prepare(args, *, _mailbox=None, _request_id=None):
    from hierarchy_router import _lexical_path
    for value, flag in ((args.root, "--root"), (args.lifecycle, "--lifecycle"), (args.delivery_dir, "--delivery-dir")):
        if value is not None:
            parsed = _lexical_path(value)
            if not parsed.is_absolute() or ".." in parsed.parts:
                cli_path(value, flag)
    operation = _mailbox.operation if _mailbox is not None else _Operation()
    with operation.capture():
        return _prepare(args, _mailbox=_mailbox, _request_id=_request_id, _operation=operation)


def _prepare(args, *, _mailbox, _request_id, _operation):
    from hierarchy_router import preflight_paths
    preflight_paths(*(value for value in (args.root, args.lifecycle, args.delivery_dir) if value is not None),
                    _guard=_operation.path_guard)
    matching(args.initiative, SLUG, "initiative")
    require(endpoint_parts(args.endpoint)[0] == args.initiative, "endpoint is outside initiative " + args.initiative)
    mailbox, base, run, setup = locate(cli_path(args.root, "--root"), args.initiative,
                                     _mailbox=_mailbox, _operation=_operation)
    mailbox.operation.output_directory(base / "briefs")
    args._prepared_mailbox = mailbox
    mailbox.endpoint(args.endpoint)
    at, as_of = composition_time(args.as_of)
    history = mailbox.bindings(args.endpoint)
    binding = history[-1] if history else None
    current = binding["generation"] if binding else 1
    generation = args.target_generation
    if generation is None:
        generation = current + 1 if binding and mailbox.ready(binding) else current
    integer(generation, "target generation")
    require(generation >= current, "target generation precedes current binding")
    lifecycle = cli_path(args.lifecycle, "--lifecycle") if args.lifecycle else safe_path(run / "lifecycle")
    delivery = cli_path(args.delivery_dir, "--delivery-dir") if args.delivery_dir else safe_path(
        setup["delivery_dir"] if setup else base / "delivery")
    protect_stores(base / "briefs", mailbox, base, run, lifecycle, delivery, setup)
    require_secure_publication()
    brief = Brief(_check_ref=mailbox.check_ref, _operation=mailbox.operation,
                  _authoritative=_request_id is not None)
    role_contract(brief, mailbox, base, setup, args.endpoint)
    brief.add("Source identity", "mailbox_identity", brief.reference(mailbox.root / "manifest.json"))
    if setup:
        brief.add("Source identity", "runtime_pin", brief.reference(base / "provision.json"), verification="recorded_only",
                  **{key: setup[key] for key in ("source", "source_commit", "source_tree") if key in setup})
    else:
        brief.notes["Source identity"].append("No provisioned runtime pin recorded; contracts come from the composer's checkout.")
    if args.lifecycle or mailbox.operation.exists(lifecycle):
        lifecycle_records(brief, lifecycle, at, request_id=_request_id)
        lifecycle_coverage = "journal_wide_registered_requests" if _request_id is None else "request_dependency_closure"
    else:
        lifecycle_coverage = "absent"
        brief.notes["Open obligations"].append("No lifecycle journal recorded at the default location; supply --lifecycle for an external journal.")
    brief.notes["Unread work"].append("Messages without a recorded read remain unread; a wake is not a read.")
    mailbox_records(brief, mailbox, args.endpoint, args.initiative, delivery, at, generation, binding,
                    _authoritative=_request_id is not None)
    raw = brief.render(args.endpoint, as_of, generation)
    inspect(raw, _check_ref=mailbox.check_ref, _operation=mailbox.operation)  # Validate before publication.
    sha = hashlib.sha256(raw).hexdigest()
    reference = {"path": str(base / "briefs" / ("fresh-" + sha + ".md")), "sha256": sha}
    _acquire("witness", "output", reference["path"], _guard=mailbox.operation.path_guard)
    mailbox.brief(reference, verify=False)
    return raw, {"ok": True, "brief": reference, "entries": len(brief.seen),
                 "coverage": {"lifecycle": lifecycle_coverage}, "as_of": as_of, "target_generation": generation}


class PublicationRefused(ValueError):
    """A directory changed or cannot be securely addressed; never follow it elsewhere."""


def require_secure_publication():
    # CPython lists rename, not replace, in supports_dir_fd, even when replace
    # supports both descriptors. Inspect the native capability names so wrapping
    # an OS call for a deterministic boundary test does not change its capability.
    names = {function.__name__ for function in os.supports_dir_fd}
    require(hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW") and callable(getattr(os, "geteuid", None))
            and {"open", "mkdir", "rename", "unlink", "stat"} <= names,
            "secure brief publication requires directory descriptor support")


def open_directory(path):
    """Traverse from the filesystem root, opening every component without following links."""
    descriptor = None
    try:
        from hierarchy_router import _operation_guard
        descriptor, _marks = _proof_parent(path, _guard=_operation_guard())
        return descriptor
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if exc.errno == errno.EACCES:
            raise PublicationRefused("publication directory permission denied: " + str(path)) from exc
        raise PublicationRefused("publication directory changed or unavailable") from exc
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise


def directory_flags():
    # Linux O_PATH needs search permission only. Other supported POSIX hosts
    # retain O_RDONLY where no search-only directory handle is exposed.
    return getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW


def check_directory(base_fd, directory_fd, name, *, path):
    from hierarchy_router import _operation_guard
    guard = _operation_guard()
    current = _acquire("stat", name, dir_fd=base_fd, follow_symlinks=False, _guard=guard)
    opened = _acquire("fstat", directory_fd, _guard=guard)
    if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
        _acquisition_replacement(guard, path, current)


def _publication_directory_failure(path, base_fd, error):
    from hierarchy_router import _operation_guard
    guard = _operation_guard()
    if error.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENOENT}:
        try:
            current = _acquire("stat", path.name, dir_fd=base_fd,
                               follow_symlinks=False, _guard=guard)
        except (ValueError, OSError) as checking:
            _raise_global(checking, guard=guard)
        else:
            _acquisition_replacement(guard, path, current)
    _acquisition_refuse(guard, error)


def file_identity(value):
    return value.st_dev, value.st_ino


def check_returned_path(path, identity, *, directory_fd, ancestors):
    from hierarchy_router import _operation_guard
    guard = _operation_guard()
    returned, _marks = _proof_parent(path.parent, _guard=guard, _expected=ancestors)
    try:
        _acquisition_require(file_identity(_acquire("fstat", returned, _guard=guard))
                == file_identity(_acquire("fstat", directory_fd, _guard=guard)), guard,
                "reference parent changed while opening")
        leaf = _acquire("stat", path.name, dir_fd=returned, follow_symlinks=False, _guard=guard)
        _acquisition_require(file_identity(leaf) == identity, guard, "reference parent changed while opening")
    finally:
        os.close(returned)
    _check_output_ancestor(path, directory_fd, _expected=ancestors)


def _check_output_ancestor(path, directory_fd, *, _expected=None):
    """Preserve the output-path refusal before an input witness can obscure a moved ancestor."""
    from hierarchy_router import _operation_guard
    guard = _operation_guard()
    # The held directory is already a positive witness, even before its full
    # pathname ancestry has been recorded for later returned-path checks.
    returned, ancestors = _proof_parent(path.parent, _guard=guard, _expected=_expected, _captured=True)
    try:
        _acquisition_require(file_identity(_acquire("fstat", returned, _guard=guard))
                == file_identity(_acquire("fstat", directory_fd, _guard=guard)), guard,
                "reference parent changed while opening")
        return ancestors
    finally:
        os.close(returned)


def remove_written_file(directory_fd, name, identity, *, _failure=None):
    try:
        current = _acquire("stat", name, dir_fd=directory_fd, follow_symlinks=False)
        # Another composer can have replaced the same content address. Remove
        # only our inode, through the held directory, during cleanup.
        if file_identity(current) == identity:
            _acquire("unlink", name, dir_fd=directory_fd)
    except (ValueError, OSError) as exc:
        from hierarchy_router import PrivatePathError
        _raise_global(exc)
        acquired = _acquisition_fact(exc)
        cause = exc.__cause__ if acquired is not None and acquired.kind == "CHANGED" else exc
        if isinstance(cause, FileNotFoundError) and cause.errno == errno.ENOENT:
            return  # Another actor already removed the owned entry; no unlink is needed.
        if isinstance(_failure, PrivatePathError):
            raise _failure
        raise


def sync_publication_directory(directory_fd):
    if os.name == "nt":
        # Windows does not support fsync on directory handles. Publication also
        # retains its separate refusal when secure dir_fd operations are absent.
        return
    # O_PATH handles permit traversal but cannot be fsynced. Reopen the anchored
    # directory read-only on POSIX, rather than resolving its pathname again.
    descriptor = _acquire("open", ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publication_context(method):
    @wraps(method)
    def publication(raw, reference, *, _operation=None):
        operation = _operation
        if operation is None:
            from hierarchy_router import _operation_guard
            guard = _operation_guard()
            context = getattr(guard, "_acquisition_context", None)
            operation = context.get() if context is not None else None
            if operation is None:
                operation = _Operation(_path_guard=guard)
        with operation.active():
            return method(raw, reference, _operation=operation)
    return publication


@_publication_context
def publish(raw, reference, *, _operation=None):
    require_secure_publication()
    path = Path(reference["path"])
    _acquire("witness", "output", path)
    _acquire("witness", "publication-directory", path.parent)
    base_fd = open_directory(path.parent.parent)
    directory_fd = None
    pending = None
    try:
        try:
            try:
                directory_fd = _acquire("open", path.parent.name, directory_flags(), dir_fd=base_fd, _negative=(path.parent, None))
            except FileNotFoundError:
                directory_fd = _acquire("mkdir", path.parent.name, mode=0o700,
                                        dir_fd=base_fd, _path=path.parent)
        except OSError as exc:
            _publication_directory_failure(path.parent, base_fd, exc)
        check_directory(base_fd, directory_fd, path.parent.name, path=path.parent)
        ancestors = _check_output_ancestor(path, directory_fd)
        try:
            existing = _acquire("open", path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd, _negative=(path, None))
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise PublicationRefused("content-addressed brief is a symlink") from exc
            if not stat.S_ISREG(_acquire("stat", path.name, dir_fd=directory_fd, follow_symlinks=False).st_mode):
                raise PublicationRefused("brief must be a regular file") from exc
            raise
        if existing is not None:
            try:
                metadata = _acquire("fstat", existing)
                if not stat.S_ISREG(metadata.st_mode):
                    raise PublicationRefused("brief must be a regular file")
                owned, existing = existing, None
                with _acquire("fdopen", owned, "rb") as stream:
                    if _acquire("stream-read", stream, MAX_BYTES + 1) != raw:
                        raise PublicationRefused("content-addressed brief already exists with different bytes")
            finally:
                if existing is not None:
                    os.close(existing)
            check_directory(base_fd, directory_fd, path.parent.name, path=path.parent)
            check_returned_path(path, file_identity(metadata), directory_fd=directory_fd, ancestors=ancestors)
            sync_publication_directory(directory_fd)
            sync_publication_directory(base_fd)
            check_returned_path(path, file_identity(metadata), directory_fd=directory_fd, ancestors=ancestors)
            if _operation is not None:
                _operation.verify()
            return
        pending = ".fresh-" + uuid.uuid4().hex
        descriptor = _acquire("open", pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        with _acquire("fdopen", descriptor, "wb") as stream:
            identity = file_identity(_acquire("fstat", stream.fileno()))
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        check_directory(base_fd, directory_fd, path.parent.name, path=path.parent)
        _check_output_ancestor(path, directory_fd, _expected=ancestors)
        if _operation is not None:
            _operation.verify()
        _acquire("replace", pending, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        pending = None
        _acquire("witness", "effect", path, identity)
        try:
            check_returned_path(path, identity, directory_fd=directory_fd, ancestors=ancestors)
        except (ValueError, RuntimeError) as exc:
            remove_written_file(directory_fd, path.name, identity, _failure=exc)
            raise
        if _operation is not None:
            try:
                _operation.verify()
            except (ValueError, OSError) as exc:
                raise PublicationRefused("committed brief " + str(path) + " requires reconciliation; verify this original path before reuse: " + str(exc)) from exc
        try:
            check_returned_path(path, identity, directory_fd=directory_fd, ancestors=ancestors)
            check_directory(base_fd, directory_fd, path.parent.name, path=path.parent)
            sync_publication_directory(directory_fd)
            sync_publication_directory(base_fd)
            check_returned_path(path, identity, directory_fd=directory_fd, ancestors=ancestors)
        except (ValueError, RuntimeError) as exc:
            remove_written_file(directory_fd, path.name, identity, _failure=exc)
            raise
    finally:
        if directory_fd is not None:
            try:
                if pending is not None:
                    _acquire("unlink", pending, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            finally:
                os.close(directory_fd)
        os.close(base_fd)


def main(argv=None):
    parser = JSONArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    compose = commands.add_parser("compose")
    compose.add_argument("--root", required=True, help="Absolute team run, initiative base or handoff mailbox root")
    compose.add_argument("--initiative", required=True)
    compose.add_argument("--endpoint", required=True)
    compose.add_argument("--lifecycle", help="External lifecycle journal; default <run>/lifecycle")
    compose.add_argument("--delivery-dir", help="Read/wake receipts; default provisioned or <base>/delivery")
    compose.add_argument("--as-of", help="RFC3339 UTC snapshot time for expiry decisions; default now")
    compose.add_argument("--target-generation", type=int,
                         help="Read generation; default the next generation for a ready binding, otherwise the current one")
    verify = commands.add_parser("verify")
    verify.add_argument("--path", required=True)
    verify.add_argument("--sha256", required=True)
    try:
        args = parser.parse_args(argv)
        if args.command == "compose":
            raw, answer = prepare(args)
        else:
            from hierarchy_router import _lexical_path
            path = _lexical_path(args.path)
            if not path.is_absolute() or ".." in path.parts:
                cli_path(args.path, "--path")
            operation = _Operation()
            _ordinary_reference_check(path, operation.path_guard)
            matching(args.sha256, SHA256, "brief sha256")
            require(path.suffix == ".md", "brief must be a Markdown file")
            _reference, raw = operation.read(path)
            require(hashlib.sha256(raw).hexdigest() == args.sha256, "brief sha256 mismatch")
            answer = {"ok": True, "brief": {"path": str(path), "sha256": args.sha256},
                      "entries": inspect(raw, _check_ref=operation.check_ref, _operation=operation)}
            operation.verify()
    except (ValueError, OSError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    except Exception as exc:
        print(json.dumps({"error": "internal composition error: " + str(exc)}, sort_keys=True))
        return 3
    try:
        if args.command == "compose":
            publish(raw, answer["brief"], _operation=args._prepared_mailbox.operation)
    except (PublicationRefused, CaptureChanged) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    except Exception as exc:
        acquired = _acquisition_fact(exc)
        if acquired is not None:
            message = ("owner-private host directory is not an input" if acquired.kind == "PRIVATE"
                       else "reference parent changed while opening")
            print(json.dumps({"error": message}, sort_keys=True))
            return 2
        print(json.dumps({"error": "brief publication failed: " + str(exc)}, sort_keys=True))
        return 3
    print(json.dumps(answer, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
