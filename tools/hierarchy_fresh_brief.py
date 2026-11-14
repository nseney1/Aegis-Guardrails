#!/usr/bin/env python3
"""Compose a bounded, durable brief without changing any coordination store."""
from __future__ import annotations

import argparse
import copy
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
sys.path.insert(0, str(Path(__file__).resolve().parent))
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
    names, used = [], 0
    with os.scandir(directory) as entries:
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


class _ProvedChain:
    def __init__(self, guard, original, observations, links, directory=None, leaf=None, ancestors=()):
        self.guard, self.original = guard, original
        self.observations, self.links = tuple(observations), tuple(links)
        self.directory, self.leaf, self.valid = directory, leaf, True
        self.ancestors = ancestors
        self.leaf_outcome = None

    def proved(self, guard):
        if not self.valid or guard is not self.guard:
            return False
        result = _proof_operation(guard, "recheck", _proof_recheck, self)
        self.valid = isinstance(result, _ProofValue)
        return self.valid


class _LinkLookupFailure:
    """Only a final-leaf failure can carry an ordinary target error."""
    def __init__(self, error, proof, *, through=True):
        require(isinstance(proof, _ProvedChain), "target failure requires a proved chain")
        self.error, self.proof = error, proof
        self.through = through

    def proved(self, guard):
        return self.proof.proved(guard)


class _LeafLookup:
    leaf_refusal = False

    def __init__(self, kind, value, proof):
        self.kind, self.value, self.proof = kind, value, proof
        # Retain the raw lookup result, independently of consumer diagnostics.
        proof.leaf_outcome = (("present", value.st_dev, value.st_ino, value.st_mode,
                               stat.S_ISLNK(value.st_mode), _reparse(value),
                               (value.st_dev, value.st_ino) in proof.guard.identities())
                              if kind == "present" else ("errno", value.errno))


class _HopBoundary:
    def __init__(self, stage):
        self.stage = stage


def _disposition(error, *, guard, seam, path=None, inert=False):
    """Preserve each public seam's contract; private and unproved chains quarantine.

    Scope checks accept absent/non-directory paths. Isolated successor trials
    keep their original ValueError/TypeError/KeyError -> UNKNOWN boundary.
    Inert evidence exempts public scope observations, never private identity.
    """
    from hierarchy_router import PrivatePathError, SymlinkPathError, _lexical_path
    fatal = _fatal_path_error(error, guard)
    if fatal is not None:
        fatal._global_path_failure = fatal._path_failure = True
        error._path_failure = True
        return GLOBAL
    if isinstance(error, SymlinkPathError):
        error._path_failure = True
    if isinstance(error, (PrivatePathError, _ProofPathError)):
        return QUARANTINE
    classified = getattr(error, "_private_alias_for", None)
    if isinstance(error, SymlinkPathError) or classified is not None:
        guard.current()
        candidate = _lexical_path(path if path is not None else
                                  classified[1] if classified is not None else error.path)
        if classified is None or classified[0] is not guard or classified[1] != candidate:
            if not isinstance(error, SymlinkPathError):
                return QUARANTINE
            proof = _private_symlink_target(guard, error.path, candidate)
            classified = guard, candidate, proof
            error._private_alias_for = classified
        if isinstance(classified[2], _LinkLookupFailure):
            proof = classified[2]
            # A consuming scope can suppress a public lookup failure only while
            # every link and ancestor remains the captured public identity.
            if not proof.proved(guard):
                return QUARANTINE
            if proof.through and not (seam == "scope" and inert):
                proof.error._private_alias_for = classified
                if error is proof.error:
                    return GLOBAL
                # Plain errno: its caller, not the privacy guard, owns disposition.
                raise proof.error from error
        elif isinstance(classified[2], _ProvedChain):
            if not classified[2].proved(guard):
                return QUARANTINE
        elif isinstance(classified[2], _ProofFailure):
            return QUARANTINE
        else:
            return QUARANTINE
    if path is not None and seam in {"scope", "readiness", "trial", "consume"}:
        try:
            guard.refuse(path)
        except PrivatePathError:
            return QUARANTINE
    if seam in {"check", "scope-check"} and isinstance(error, OSError) and error.errno in {errno.ENOENT, errno.ENOTDIR}:
        return ABSENT
    if seam == "exists" and isinstance(error, FileNotFoundError):
        return ABSENT
    if seam == "scope" and inert:
        return ABSENT
    if seam == "trial" and isinstance(error, (ValueError, TypeError, KeyError)):
        return ROW_UNKNOWN
    return GLOBAL


def _walk_error(error, path, *, seam, anchored=True):
    """Raise the owning seam's baseline bytes while preserving proof-failure type."""
    from hierarchy_router import SymlinkPathError
    _raise_global(error)
    error._path_failure = True
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
    if seam in {"check", "exists", "lock", "link"}:
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
    return mapped


@lru_cache(maxsize=1)
def _symlink_reader():
    """Optional descriptor-relative readlinkat with a caller-bounded buffer."""
    if os.name != "posix":
        return None
    try:
        import ctypes
        function = ctypes.CDLL(None, use_errno=True).readlinkat
    except (ImportError, AttributeError):
        return None
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t)
    function.restype = ctypes.c_ssize_t

    def read(directory, name, size):
        if type(size) is not int or not 0 < size <= MAX_SYMLINK_BYTES:
            return None
        buffer = ctypes.create_string_buffer(size + 1)
        count = function(directory, os.fsencode(name), buffer, size + 1)
        if count < 0:
            return None
        return buffer.raw[:count] if count == size else None
    return read


def _proof_operation(guard, stage, action, *args, **kwargs):
    """The sole proof exception boundary: no errno can turn a proof into absence."""
    value = None
    try:
        if action is os.close:
            # A latched policy refusal cannot prevent release of an owned handle.
            value = action(*args, **kwargs)
            guard.current()
            return _ProofValue(value)
        guard.current()
        value = action(*args, **kwargs)
        return _ProofValue(value)
    except Exception as exc:
        if isinstance(value, _ProvedChain) and value.directory is not None:
            descriptor, value.directory = value.directory, None
            try:
                os.close(descriptor)
            except Exception as closing:
                _raise_global(exc, guard=guard)
                exc = closing
        _raise_global(exc, guard=guard)
        return _ProofFailure(stage, exc)


def _final_leaf_lookup(proof):
    """The sole target boundary, accessible only with a complete parent-chain proof."""
    require(isinstance(proof, _ProvedChain) and proof.valid and proof.directory is not None,
            "final lookup requires a live proved-chain token")
    proof.guard.current()
    try:
        proof.guard.refuse(proof.leaf)
        info = os.stat(proof.leaf.name, dir_fd=proof.directory, follow_symlinks=False)
        return _LeafLookup("present", info, proof)
    except Exception as exc:
        _raise_global(exc, guard=proof.guard)
        if isinstance(exc, (FileNotFoundError, NotADirectoryError)):
            return _LeafLookup("absent", exc, proof)
        if not isinstance(exc, OSError):
            return _ProofFailure("final leaf", exc)
        try:
            _walk_error(exc, proof.original, seam="link")
        except OSError as mapped:
            result = _LeafLookup("error", mapped, proof)
            result.leaf_refusal = True
            return result


def _proof_parent(path, *, _guard):
    """Raw descriptor walk; its caller must consume the proof-operation result."""
    from hierarchy_router import _lexical_path
    path = _lexical_path(path)
    require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
    require(_descriptor_capabilities(), "secure link proof requires directory descriptor support")
    _guard(path)
    flags = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    directory, pending = None, None
    marks = []
    current = Path(path.anchor)
    try:
        before = os.stat(path.anchor, follow_symlinks=False)
        _guard.check_identity(current, before)
        _reference_directory(before, current)
        directory = os.open(path.anchor, flags)
        info = os.fstat(directory)
        _guard.check_identity(current, info)
        require(_directory_mark(before) == _directory_mark(info), "public ancestor changed")
        marks.append((path.anchor, _directory_mark(info)))
        for component in path.parts[1:]:
            current = current / component
            _guard.refuse(current)
            before = os.stat(component, dir_fd=directory, follow_symlinks=False)
            _guard.check_identity(current, before)
            _reference_directory(before, current)
            previous = directory
            directory = os.open(component, flags, dir_fd=previous)
            os.close(previous)
            info = os.fstat(directory)
            _guard.check_identity(current, info)
            require(_directory_mark(before) == _directory_mark(info), "public ancestor changed")
            marks.append((component, _directory_mark(info)))
        result = directory, marks
        directory = None
        return result
    except BaseException as exc:
        pending = exc
        raise
    finally:
        if directory is not None:
            try:
                os.close(directory)
            finally:
                _raise_global(pending, guard=_guard)


def _proof_check(path, *, _guard):
    """Non-following component metadata; links are data, never exception control flow."""
    from hierarchy_router import _lexical_path
    path = _lexical_path(path)
    _guard.refuse(path)
    directory, pending = None, None
    try:
        directory, ancestors = _proof_parent(path.parent, _guard=_guard)
        info = (os.stat(path.name, dir_fd=directory, follow_symlinks=False) if path.name
                else os.fstat(directory))
        _guard.check_identity(path, info)
        require(info.st_ino and all(mark[1] for _component, mark in ancestors),
                "public component identity unavailable")
        return info, ancestors
    except BaseException as exc:
        pending = exc
        raise
    finally:
        if directory is not None:
            try:
                os.close(directory)
            finally:
                _raise_global(pending, guard=_guard)


def _stable_link(guard, snapshot):
    path, mark, ancestors = snapshot
    directory, pending = None, None
    try:
        directory, current = _proof_parent(path.parent, _guard=guard)
        return (ancestors == current
                and mark == _reference_mark(os.stat(path.name, dir_fd=directory, follow_symlinks=False)))
    except BaseException as exc:
        pending = exc
        raise
    finally:
        if directory is not None:
            try:
                os.close(directory)
            finally:
                _raise_global(pending, guard=guard)


def _link_snapshot(guard, path):
    """Bounded link text plus its full ancestry; all failures belong to the proof entry."""
    directory, pending = None, None
    try:
        directory, ancestors = _proof_parent(path.parent, _guard=guard)
        before = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        require(stat.S_ISLNK(before.st_mode) and not _reparse(before) and before.st_ino
                and all(mark[1] for _component, mark in ancestors)
                and 0 < before.st_size <= MAX_SYMLINK_BYTES, "public link proof unavailable")
        read = _symlink_reader()
        require(read is not None, "public link reader unavailable")
        raw = read(directory, path.name, before.st_size)
        require(raw is not None and len(raw) == before.st_size and b"\0" not in raw,
                "public link changed while reading")
        after = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        require(_reference_mark(before) == _reference_mark(after), "public link changed while reading")
        snapshot = path, _reference_mark(before), ancestors
        require(_stable_link(guard, snapshot), "public link ancestry changed")
        return raw, snapshot
    except BaseException as exc:
        pending = exc
        raise
    finally:
        if directory is not None:
            try:
                os.close(directory)
            finally:
                _raise_global(pending, guard=guard)


def _proof_link(guard, path, observed):
    raw, snapshot = _link_snapshot(guard, path)
    require(snapshot[1] == _reference_mark(observed), "public link changed before capture")
    return raw, snapshot


def _proof_token(guard, original, leaf, observations, links):
    directory, pending = None, None
    try:
        directory, ancestors = _proof_parent(leaf.parent, _guard=guard)
        proof = _ProvedChain(guard, original, observations, links, directory, leaf, ancestors)
        _proof_recheck(proof)
        directory = None
        return proof
    except BaseException as exc:
        pending = exc
        raise
    finally:
        if directory is not None:
            try:
                os.close(directory)
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
            require(ancestor_path not in opened or opened[ancestor_path] == ancestor_mark,
                    "final lookup parent ancestry changed")
        require(not directory or path not in opened or opened[path] == mark,
                "final lookup parent changed")
        info, current = _proof_check(path, _guard=proof.guard)
        require(mark == (_directory_mark(info) if directory else _reference_mark(info))
                and ancestors == current, "public component changed")
    for snapshot in proof.links:
        remaining -= len(snapshot[0].parent.parts) + 1
        require(remaining >= 0 and _stable_link(proof.guard, snapshot), "public link changed")
    if proof.leaf is not None:
        _recheck_final_witness(proof)
    return True


def _recheck_final_witness(proof):
    """Re-open the captured parent chain and repeat its no-follow leaf lookup."""
    directory, pending = None, None
    try:
        directory, current = _proof_parent(proof.leaf.parent, _guard=proof.guard)
        require(current == proof.ancestors, "final lookup parent ancestry changed")
        if proof.directory is not None:
            info = os.fstat(proof.directory)
            proof.guard.check_identity(proof.leaf.parent, info)
            require(_directory_mark(info) == current[-1][1], "final lookup descriptor changed")
        if proof.leaf_outcome is not None:
            fresh = _ProvedChain(proof.guard, proof.original, (), (), directory, proof.leaf, current)
            result = _final_leaf_lookup(fresh)
            require(isinstance(result, _LeafLookup) and fresh.leaf_outcome == proof.leaf_outcome,
                    "final leaf outcome changed")
    except BaseException as exc:
        pending = exc
        raise
    finally:
        if directory is not None:
            try:
                os.close(directory)
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
    finally:
        cleanup = _proof_operation(guard, "cleanup", os.close, proof.directory)
        proof.directory = None
    return cleanup if isinstance(cleanup, _ProofFailure) else result


def _resolve_public_chain(guard, path, candidate):
    from hierarchy_router import _lexical_path
    require(_descriptor_capabilities(), "secure link proof requires directory descriptor support")
    path, candidate = _lexical_path(path), _lexical_path(candidate)
    through = path != candidate
    pending, cursor = list(candidate.parts[1:]), Path(candidate.anchor)
    observations, links = [], []
    remaining, hops, seen_link = MAX_INPUT_NODES, 0, False

    def checked(stage, action, *args, **kwargs):
        return _proof_operation(guard, stage, action, *args, **kwargs)

    def observe(value, info, ancestors):
        is_directory = stat.S_ISDIR(info.st_mode)
        mark = _directory_mark(info) if is_directory else _reference_mark(info)
        observations.append((value, mark, ancestors, is_directory))

    while pending:
        component = pending.pop(0)
        if isinstance(component, _HopBoundary):
            remaining -= len(cursor.parent.parts) + 1
            require(remaining >= 0, "public chain proof exceeds limit")
            result = checked(component.stage, _proof_check, cursor, _guard=guard)
            if isinstance(result, _ProofFailure):
                return result
            info, ancestors = result.value
            if any(isinstance(item, str) for item in pending):
                _reference_directory(info, cursor)
            observe(cursor, info, ancestors)
            continue
        if component == "..":
            for stage, value in (("traversal prefix", cursor), ("post-traversal", cursor.parent)):
                remaining -= len(value.parent.parts) + 1
                require(remaining >= 0, "public chain proof exceeds limit")
                result = checked(stage, _proof_check, value, _guard=guard)
                if isinstance(result, _ProofFailure):
                    return result
                info, ancestors = result.value
                _reference_directory(info, value)
                observe(value, info, ancestors)
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
            identity = checked("final identity", guard.check_identity, value, info)
            if isinstance(identity, _ProofFailure):
                return identity
            # Parent marks belong to the token that authorized this exact lookup.
            ancestors = _proof_parent_marks(proof, value)
        else:
            result = checked(stage, _proof_check, value, _guard=guard)
            if isinstance(result, _ProofFailure):
                return result
            info, ancestors = result.value
        observe(value, info, ancestors)
        if stat.S_ISLNK(info.st_mode) or _reparse(info):
            hops += 1
            require(hops <= MAX_SYMLINK_HOPS, "public link chain exceeds limit")
            captured = checked("link", _proof_link, guard, value, info)
            if isinstance(captured, _ProofFailure):
                return captured
            raw, snapshot = captured.value
            require(len(os.fspath(value.parent)) + len(raw) + sum(len(x) + 1 for x in pending if isinstance(x, str)) + 2
                    <= MAX_INPUT_NODES, "public link target exceeds limit")
            links.append(snapshot)
            target = _lexical_path(value.parent / os.fsdecode(raw))
            destination = "direct-leaf destination" if not through and value == path else "hop target"
            pending = list(target.parts[1:]) + [_HopBoundary(destination)] + pending
            cursor, seen_link = Path(target.anchor), True
            continue
        if any(isinstance(item, str) for item in pending):
            _reference_directory(info, value)
        cursor = value
        if final:
            return proof
    return _ProvedChain(guard, candidate, observations, links)


def _proof_parent_marks(proof, value):
    # The target's parent descriptor is already closed; retain the ancestry
    # from the last proved parent instead of minting an unguarded lookup.
    return proof.ancestors


def _private_symlink_target(guard, path, candidate):
    result = _proof_operation(guard, "chain", _resolve_public_chain, guard, path, candidate)
    if isinstance(result, _ProofFailure):
        return result
    return result.value


def _inert_evidence_reducer(*, _guard):
    """Bind the pinned functions once per pass, separating evidence from scope.

    Evidence occurrences stay lexical. Every scope occurrence independently
    checks identity, even when the same pathname also occurs as evidence.
    Per-call refusals are restored in finally; no pinned namespace is changed.
    """
    refusals, inert_paths = None, set()

    def lexical_path(value):
        path = Path(value)
        require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
        return path

    def scope_path(value):
        path = lexical_path(value)
        try:
            _guard.check(path, scope=True)
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
        try:
            return namespace["reduce_event"](policy, state, envelope, at)
        finally:
            refusals = previous
            inert_paths = previous_paths
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
    return _reference_mark(info)[:4]


def _same_mark(left, right):
    return left[2:] == right[2:] and all(not a or not b or a == b for a, b in zip(left[:2], right[:2]))


def _same_ancestors(left, right):
    return len(left) == len(right) and all(a[0] == b[0] and _same_mark(a[1], b[1]) for a, b in zip(left, right))


def _descriptor_capabilities():
    names = {function.__name__ for function in os.supports_dir_fd}
    return (all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
            and {"open", "stat"} <= names)


def _reference_descriptors():
    """Select the reference reader; bounded link proofs independently require native primitives."""
    return _descriptor_capabilities()


def _reference_directory(info, path):
    from hierarchy_router import SymlinkPathError
    if stat.S_ISLNK(info.st_mode) or _reparse(info):
        raise SymlinkPathError(path)
    if not stat.S_ISDIR(info.st_mode):
        raise NotADirectoryError(errno.ENOTDIR, None, str(path))


def _close_reference_directory(descriptor, *, guard, error=None):
    try:
        os.close(descriptor)
    except OSError as exc:
        # Explicit pending causes preserve policy failures without consulting
        # an unrelated request's ambient exception context.
        _raise_global(error, guard=guard)
        _raise_global(exc, guard=guard)
        raise _ProofPathError("cannot complete public path proof") from exc


def _reference_parent(path, *, _guard=None, _checking=False, _classifying=False):
    """Walk without following links, with bounded handles and recorded ancestor identities."""
    from hierarchy_router import _operation_guard, _lexical_path
    path = _lexical_path(path)
    require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
    guard = _operation_guard() if _guard is None else _guard
    guard(path)
    require(_descriptor_capabilities() if _classifying else _reference_descriptors(),
            "secure reference hashing requires directory descriptor support")
    flags = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = None
    marks = []
    current = Path(path.anchor)
    try:
        before = os.stat(path.anchor, follow_symlinks=False)
        guard.check_identity(path, before)
        _reference_directory(before, Path(path.anchor))
        descriptor = os.open(path.anchor, flags)
        info = os.fstat(descriptor)
        guard.check_identity(path, info)
        require(_same_mark(_directory_mark(info), _directory_mark(before)), "reference parent changed while opening")
        _reference_directory(info, Path(path.anchor))
        marks.append((path.anchor, _directory_mark(info)))
        current = Path(path.anchor)
        for component in path.parts[1:]:
            current = current / component
            before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            guard.check_identity(path, before)
            if _checking or _reparse(before):
                _reference_directory(before, current)
            elif stat.S_ISLNK(before.st_mode):
                from hierarchy_router import SymlinkPathError
                refused = SymlinkPathError(current)
                if _disposition(refused, guard=guard, seam="consume", path=path) == QUARANTINE:
                    raise refused
            # Native O_DIRECTORY|O_NOFOLLOW reports its own baseline errno for
            # public failures; it cannot open a link or follow its target.
            previous = descriptor
            descriptor = os.open(component, flags, dir_fd=previous)
            _close_reference_directory(previous, guard=guard)
            info = os.fstat(descriptor)
            guard.check_identity(path, info)
            require(_same_mark(_directory_mark(info), _directory_mark(before)), "reference parent changed while opening")
            _reference_directory(info, current)
            marks.append((component, _directory_mark(info)))
        return descriptor, marks
    except OSError as exc:
        if descriptor is not None:
            _close_reference_directory(descriptor, guard=guard, error=exc)
        _disposition(exc, guard=guard, seam="parent", path=current)
        _walk_error(exc, current, seam="parent-check" if _checking else "parent")
    except BaseException as exc:
        if descriptor is not None:
            _close_reference_directory(descriptor, guard=guard, error=exc)
        raise


def _reparse(info):
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _reference_ancestors(path, *, _guard=None, _checking=False):
    """Portable identity witnesses; no path resolution or link traversal."""
    from hierarchy_router import _operation_guard, _lexical_path
    path = _lexical_path(path)
    require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
    guard = _operation_guard() if _guard is None else _guard
    guard(path)
    result = []
    try:
        for parent in reversed(path.parents):
            info = os.lstat(parent)
            guard.check_identity(path, info)
            _reference_directory(info, parent)
            result.append((str(parent), _directory_mark(info)))
    except (ValueError, OSError) as exc:
        seam = "ancestor-check" if _checking else "ancestors"
        _disposition(exc, guard=guard, seam=seam, path=path)
        _walk_error(exc, path, seam=seam, anchored=False)
    return result


def _reference_check(path, *, _guard, _scope=False, _classifying=False):
    """Validate every existing component top down, including a regular-file leaf."""
    from hierarchy_router import _lexical_path
    path = _lexical_path(path)
    require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
    directory, failure = None, None
    try:
        anchored = _descriptor_capabilities() if _classifying else _reference_descriptors()
        require(not _classifying or anchored, "secure link proof requires directory descriptor support")
        if anchored:
            directory, ancestors = _reference_parent(path.parent, _guard=_guard, _checking=True,
                                                     _classifying=_classifying)
            info = (os.stat(path.name, dir_fd=directory, follow_symlinks=False) if path.name
                    else os.fstat(directory))
        else:
            ancestors = _reference_ancestors(path, _guard=_guard, _checking=True)
            info = os.lstat(path)
        _guard.check_identity(path, info)
        if stat.S_ISLNK(info.st_mode) or _reparse(info):
            from hierarchy_router import SymlinkPathError
            raise SymlinkPathError(path)
        return info, ancestors
    except (ValueError, OSError) as exc:
        failure = exc
        if _classifying:
            _raise_global(exc, guard=_guard)
            raise
        if _disposition(exc, guard=_guard, seam="scope-check" if _scope else "check", path=path) == ABSENT:
            return None
        _walk_error(exc, path, seam="check")
    finally:
        if directory is not None:
            _close_reference_directory(directory, guard=_guard, error=failure)


def _stream_reference(descriptor, before, path, consume=None):
    """Finite declared-length read plus one EOF probe; never follow an append stream."""
    mark = _reference_mark(before)
    sha, remaining = hashlib.sha256(), before.st_size
    while remaining:
        requested = min(65536, remaining)
        chunk = os.read(descriptor, requested)
        require(len(chunk) == requested, "reference changed while hashing: " + str(path))
        remaining -= len(chunk)
        sha.update(chunk)
        if consume is not None:
            consume(chunk)
    # Refuse observed growth before probing EOF, preserving the initial-size budget on changed files.
    require(_same_mark(_reference_mark(os.fstat(descriptor)), mark), "reference changed while hashing: " + str(path))
    require(os.read(descriptor, 1) == b"", "reference content exceeds reported size: " + str(path))
    require(_same_mark(_reference_mark(os.fstat(descriptor)), mark), "reference changed while hashing: " + str(path))
    return sha.hexdigest()


def _read_reference(path, *, limit=MAX_EVIDENCE_BYTES, capture=False, _witness=None, budget_error=None, _guard=None, _cache=None):
    """Consume one opened identity, using anchored descriptors where supported and a portable checked open otherwise."""
    from hierarchy_router import _operation_guard, _lexical_path
    path = _lexical_path(path)
    require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
    guard = _operation_guard() if _guard is None else _guard
    checked = guard.check(path)
    require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
    anchored = _reference_descriptors()
    directory = None
    try:
        if anchored:
            directory, ancestors = _reference_parent(path.parent, _guard=guard)
            before = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        else:
            ancestors = _reference_ancestors(path, _guard=guard)
            before = os.lstat(path)
        guard.check_identity(path, before)
        require(stat.S_ISREG(before.st_mode) and not _reparse(before), "reference must be a regular file: " + str(path))
        require(checked is not None and _same_mark(_reference_mark(checked[0]), _reference_mark(before)),
                "reference changed while opening")
        require(limit is None or before.st_size <= limit, budget_error or "input exceeds " + str(limit) + " bytes")
        mark = _reference_mark(before)
        cached = _cache.get(path, {}).get(mark) if _cache is not None and not capture else None
        chunks = []
        if cached is not None:
            sha, previous_ancestors = cached
            require(_same_ancestors(ancestors, previous_ancestors), "cached evidence reference path changed")
        else:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
            descriptor = (os.open(path.name, flags, dir_fd=directory) if anchored else os.open(path, flags))
            try:
                opened = os.fstat(descriptor)
                guard.check_identity(path, opened)
                require(stat.S_ISREG(opened.st_mode) and not _reparse(opened) and _same_mark(_reference_mark(opened), mark),
                        "reference changed while opening: " + str(path))
                if not anchored:
                    require(_same_ancestors(_reference_ancestors(path, _guard=guard), ancestors), "reference path changed while opening: " + str(path))
                sha = _stream_reference(descriptor, before, path, chunks.append if capture else None)
                if not anchored:
                    require(_same_ancestors(_reference_ancestors(path, _guard=guard), ancestors),
                            "reference path changed while hashing")
                current = (os.stat(path.name, dir_fd=directory, follow_symlinks=False) if anchored else os.lstat(path))
                require(_same_mark(_reference_mark(current), mark), "reference changed while hashing: " + str(path))
            finally:
                os.close(descriptor)
        if anchored:
            returned, current_ancestors = _reference_parent(path.parent, _guard=guard)
            try:
                require(_same_ancestors(current_ancestors, ancestors)
                        and _same_mark(_reference_mark(os.stat(path.name, dir_fd=returned, follow_symlinks=False)), mark),
                        "reference path changed while hashing: " + str(path))
            finally:
                os.close(returned)
        else:
            require(_same_ancestors(_reference_ancestors(path, _guard=guard), ancestors) and _same_mark(_reference_mark(os.lstat(path)), mark),
                    "reference path changed while hashing: " + str(path))
        if _witness is not None:
            _witness.update(path=path, mark=mark, ancestors=ancestors, anchored=anchored)
        if _cache is not None:
            _cache.setdefault(path, {})[mark] = sha, ancestors
        return {"path": str(path), "sha256": sha}, b"".join(chunks) if capture else None
    except (ValueError, OSError) as exc:
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


def _declaration_operation(operation):
    """Isolate optional declarations, while shared privacy policy remains authoritative."""
    class DeclarationGuard:
        @property
        def _identity_error(self):
            return getattr(operation.path_guard, "_identity_error", None)

        @property
        def _global_failure(self):
            return getattr(operation.path_guard, "_global_failure", None)

        def _latch_global(self, error):
            return operation.path_guard._latch_global(error)

        def __call__(self, path):
            with operation.capture():
                return operation.path_guard(path)

        def verify(self):
            with operation.capture():
                return operation.path_guard.verify()

        def identities(self):
            with operation.capture():
                return operation.path_guard.identities()

        def current(self):
            with operation.capture():
                return operation.path_guard.current()

        def refuse(self, *paths):
            with operation.capture():
                return operation.path_guard.refuse(*paths)

        def check(self, path, *, scope=False):
            self.refuse(path)
            return _reference_check(path, _guard=self, _scope=scope)

        def check_identity(self, path, info):
            with operation.capture():
                return operation.path_guard.check_identity(path, info)

        def active(self):
            return operation.path_guard.active()

    return _Operation(reference_cache=operation.reference_cache, _path_guard=DeclarationGuard())


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
    """Metadata-only revalidation of the exact captured identity, never a second content read."""
    from hierarchy_router import _operation_guard
    guard = _operation_guard() if _guard is None else _guard
    path = Path(witness["path"])
    guard.check(path)
    if witness["anchored"]:
        directory, ancestors = _reference_parent(path.parent, _guard=guard)
        try:
            info = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            guard.check_identity(path, info)
            mark = _reference_mark(info)
        finally:
            os.close(directory)
    else:
        ancestors, info = _reference_ancestors(path, _guard=guard), os.lstat(path)
        guard.check_identity(path, info)
        mark = _reference_mark(info)
    require(_same_ancestors(ancestors, witness["ancestors"]) and _same_mark(mark, witness["mark"]),
            "captured reference changed before content promotion")


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


def _operation_context(method):
    @wraps(method)
    def captured(self, *args, **kwargs):
        from hierarchy_router import PrivatePathError
        with self.operation.path_guard.active():
            try:
                return method(self, *args, **kwargs)
            except (ValueError, OSError) as exc:
                _raise_global(exc, operation=self.operation)
                outcome = _disposition(exc, guard=self.operation.path_guard, seam="operation")
                # Path failures latch here. Existing domain validators retain
                # their caller's row refusal, rather than gaining a new latch.
                if (isinstance(exc, PrivatePathError)
                        or outcome == GLOBAL and getattr(exc, "_path_failure", False)):
                    self.operation.fail(exc)
                raise
    return captured


class _Operation:
    """One captured identity per path; bounded byte promotions preserve its original witnesses."""
    def __init__(self, *, reference_cache=None, parent=None, _path_guard=None):
        self.files, self.parsed, self.folders, self.journals = {}, {}, {}, {}
        self.reference_cache = {} if reference_cache is None else reference_cache
        self.failed_validation = False
        self.validation_failure = None
        self.parent = parent
        from hierarchy_router import _CapturedPathGuard, _path_context
        self.path_guard = (_path_context().get() or _CapturedPathGuard()) if _path_guard is None else _path_guard
        self.absences, self.validators = {}, [self.path_guard.verify]
        self.existences = {}

    @_capture_attempt
    def read(self, path, *, limit=MAX_BYTES, capture=True, budget_error=None):
        path = Path(path)
        if path not in self.files:
            witness = {}
            ref, raw = _read_reference(path, limit=limit, capture=capture, _witness=witness, budget_error=budget_error,
                                       _guard=self.path_guard, _cache=self.reference_cache)
            self.files[path] = ref, raw, witness
        else:
            self.path_guard.check(path)
        ref, raw, witness = self.files[path]
        require(limit is None or witness["mark"][4] <= limit, budget_error or "input exceeds " + str(limit) + " bytes")
        if capture and raw is None:
            current = {}
            promoted, raw = _read_reference(path, limit=limit, capture=True, _witness=current, budget_error=budget_error,
                                            _guard=self.path_guard, _cache=self.reference_cache)
            require(promoted == ref and _same_mark(current["mark"], witness["mark"])
                    and _same_ancestors(current["ancestors"], witness["ancestors"]),
                    "captured reference changed before content promotion: " + str(path))
            self.files[path] = ref, raw, witness
        return ref, raw

    @_capture_attempt
    def json(self, path, *, limit=MAX_BYTES, private=True):
        path = Path(path)
        if path not in self.parsed:
            self.parsed[path] = _bounded_json(self.read(path, limit=limit)[1].decode("utf-8"))
            ref, _raw, witness = self.files[path]
            self.files[path] = ref, None, witness
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
                require(_same_mark(_directory_mark(info), previous)
                        and _same_ancestors(ancestors, previous_ancestors), "captured existing input changed")
            self.existences[path] = _directory_mark(info), ancestors
            return True
        else:
            require(path not in self.existences, "captured existing input changed")
            missing = path
            while True:
                parent = missing.parent
                try:
                    if _reference_descriptors():
                        descriptor, ancestors = _reference_parent(parent, _guard=self.path_guard)
                        os.close(descriptor)
                    else:
                        ancestors = _reference_ancestors(missing, _guard=self.path_guard, _checking=True)
                    break
                except FileNotFoundError as exc:
                    if _disposition(exc, guard=self.path_guard, seam="exists", path=missing) != ABSENT:
                        _walk_error(exc, missing, seam="exists")
                    missing = parent
            self.absences[missing] = ancestors
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

    def _members(self, path, *, membership=True):
        try:
            return self._directory_members(path, membership=membership)
        except (ValueError, OSError) as exc:
            _disposition(exc, guard=self.path_guard, seam="members", path=path)
            _walk_error(exc, path, seam="members", anchored=_reference_descriptors())

    def _directory_members(self, path, *, membership=True):
        self.path_guard.check(path)
        path = Path(path)
        if _reference_descriptors():
            directory, ancestors = _reference_parent(path, _guard=self.path_guard)
            # O_PATH descriptors cannot be enumerated. Open the same anchored identity for listing.
            listing = None
            try:
                info = os.fstat(directory)
                self.path_guard.check_identity(path, info)
                mark, names = _directory_mark(info), None
                if membership:
                    listing = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                    require(_same_mark(mark, _directory_mark(os.fstat(listing))), "captured directory changed")
                    names = _directory_names(listing)
                    require(_same_mark(mark, _directory_mark(os.fstat(listing))), "captured directory changed")
            finally:
                if listing is not None:
                    os.close(listing)
                os.close(directory)
        else:
            ancestors = _reference_ancestors(path / "entry", _guard=self.path_guard)
            info = os.lstat(path)
            self.path_guard.check_identity(path, info)
            mark = _directory_mark(info)
            names = _directory_names(path) if membership else None
        return mark, names, ancestors

    @_capture_attempt
    def entries(self, path, *, optional=False, append=False, identity_only=False):
        path = Path(path)
        if path in self.folders and not append:
            if identity_only:
                return []
            if self.folders[path][1] is not None:
                return [path / name for name in self.folders[path][1]]
        try:
            current = self._members(path, membership=not identity_only)
        except FileNotFoundError:
            require(optional and path not in self.folders, "captured directory disappeared: " + str(path))
            self.exists(path)
            return []
        if path in self.folders:
            previous = self.folders[path]
            require(_same_mark(current[0], previous[0]) and _same_ancestors(current[2], previous[2])
                    and (previous[1] is None or set(previous[1]) <= set(current[1])), "captured directory changed: " + str(path))
        self.folders[path] = current
        return [] if identity_only else [path / name for name in current[1]]

    @_capture_attempt
    def accept(self, path, expected=None):
        """Adopt only this operation's known committed append, never an arbitrary membership change."""
        path = Path(path)
        if path.parent in self.folders and self.folders[path.parent][1] is not None:
            previous, current = self.folders[path.parent], self._members(path.parent)
            require(_same_mark(previous[0], current[0]) and _same_ancestors(previous[2], current[2])
                    and set(current[1]) == set(previous[1]) | {path.name},
                    "captured directory changed during publication: " + str(path.parent))
            self.folders[path.parent] = current
        actual, _raw = self.read(path, limit=life.MAX_BYTES if path.suffix == ".json" else MAX_BYTES)
        require(expected is None or actual["sha256"] == expected, "committed publication content changed: " + str(path))

    def fail(self, error):
        if not self.failed_validation:
            self.validation_failure = (error if isinstance(error, (ValueError, OSError))
                                       else ValueError("captured input validation failed"))
        self.failed_validation = True
        if self.parent is not None:
            self.parent.fail(error)

    @contextmanager
    def capture(self):
        """A failed attempt remains failed even if it never registered a witness."""
        with self.path_guard.active():
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
        from hierarchy_router import PrivatePathError
        with self.path_guard.active():
            try:
                verification(*args)
                self.verify()
                return object()
            except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
                _raise_global(exc, operation=self)
                outcome = _disposition(exc, guard=self.path_guard, seam="operation")
                if (isinstance(exc, PrivatePathError)
                        or outcome == GLOBAL and getattr(exc, "_path_failure", False)):
                    self.fail(exc)
                # A semantic HOLD mints no proof, but retains its validated
                # inputs for the owner's existing blocked-disposition drafts.
                raise

    def verify(self):
        from hierarchy_router import PrivatePathError
        try:
            self.reject_failed()
            for validate in self.validators:
                validate()
            for path, (mark, ancestors) in self.existences.items():
                current = self.path_guard.check(path)
                require(current is not None and _same_mark(_directory_mark(current[0]), mark)
                        and _same_ancestors(current[1], ancestors), "captured existing input changed")
            groups = {}
            for _ref, _raw, witness in self.files.values():
                groups.setdefault(witness["path"].parent, []).append(witness)
            for path in set(self.folders) | {p.parent for p in self.absences}:
                groups.setdefault(path, [])
            for parent, witnesses in groups.items():
                descriptor = listing = None
                path = parent
                try:
                    anchored = _reference_descriptors()
                    if anchored:
                        descriptor, ancestors = _reference_parent(parent, _guard=self.path_guard)
                    else:
                        ancestors = _reference_ancestors(parent / "entry", _guard=self.path_guard)
                    for witness in witnesses:
                        path = witness["path"]
                        info = (os.stat(path.name, dir_fd=descriptor, follow_symlinks=False) if anchored else os.lstat(path))
                        self.path_guard.check_identity(path, info)
                        require(_same_ancestors(ancestors, witness["ancestors"])
                                and _same_mark(_reference_mark(info), witness["mark"]),
                                "captured attachment identity/content metadata changed: " + str(path))
                    for path, previous in self.absences.items():
                        if path.parent != parent:
                            continue
                        require(_same_ancestors(ancestors, previous), "captured absent input parent changed: " + str(path))
                        try:
                            info = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False) if anchored else os.lstat(path)
                        except FileNotFoundError:
                            pass
                        else:
                            self.path_guard.check_identity(path, info)
                            raise ValueError("captured absent input changed (appeared): " + str(path))
                    if parent in self.folders:
                        path = parent
                        previous = self.folders[parent]
                        if previous[1] is None:
                            mark = _directory_mark(os.fstat(descriptor) if anchored else os.lstat(parent))
                            names = None
                        elif anchored:
                            listing = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
                            mark, names = _directory_mark(os.fstat(listing)), _directory_names(listing)
                        else:
                            mark, names = _directory_mark(os.lstat(parent)), _directory_names(parent)
                        require(_same_mark(mark, previous[0]) and names == previous[1]
                                and _same_ancestors(ancestors, previous[2]),
                                "captured directory membership changed: " + str(parent))
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
        except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
            _raise_global(exc, operation=self)
            self.fail(exc)
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
            try:
                self.operation.path_guard.check(candidate, scope=True)
                return candidate
            except (ValueError, OSError) as exc:
                if (self._stored_message_paths is None or _disposition(exc, guard=self.operation.path_guard,
                        seam="readiness", path=candidate) != QUARANTINE):
                    raise
                self._stored_message_paths.add(candidate)
                self._stored_message_refusals.append(str(exc))
                return candidate
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
        self.brief(reference, verify=False)
        if Path(reference["path"]) not in self.operation.files:
            try:
                os.lstat(reference["path"])
            except FileNotFoundError:
                publish(raw, reference)
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
            return dict(self._records)
        records = {}
        folders = {self.root / endpoint.split("/")[0] / endpoint.split("/")[1]
                   for endpoint in self.manifest["endpoints"]}
        folders |= {self.root / "across" / role for role in protocol.ACROSS_ROLES}
        for folder in sorted(folders):
            safe_path(folder)
            for path in self.operation.entries(folder):
                require(not path.is_symlink(), "symlink mailbox entry is not supported")
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
    source = safe_path(setup["source"]) if setup else Path(__file__).resolve().parents[1]
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
        if stat.S_ISDIR(os.lstat(path).st_mode):
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
    require(hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW")
            and {"open", "mkdir", "rename", "unlink", "stat"} <= names,
            "secure brief publication requires directory descriptor support")


def open_directory(path):
    """Traverse from the filesystem root, opening every component without following links."""
    flags = directory_flags()
    descriptor = None
    try:
        descriptor = os.open(path.anchor, flags)
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if exc.errno == errno.EACCES:
            raise PublicationRefused("publication directory permission denied: " + str(path)) from exc
        raise PublicationRefused("publication directory changed or unavailable") from exc


def directory_flags():
    # Linux O_PATH needs search permission only. Other supported POSIX hosts
    # retain O_RDONLY where no search-only directory handle is exposed.
    return getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW


def check_directory(base_fd, directory_fd, name):
    try:
        current = os.stat(name, dir_fd=base_fd, follow_symlinks=False)
    except OSError as exc:
        if exc.errno == errno.EACCES:
            raise PublicationRefused("publication directory permission denied: " + name) from exc
        raise PublicationRefused("publication directory changed") from exc
    opened = os.fstat(directory_fd)
    if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
        raise PublicationRefused("publication directory changed")


def file_identity(value):
    return value.st_dev, value.st_ino


def check_returned_path(path, identity):
    try:
        returned = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError("published brief pathname no longer identifies written file: " + str(path)) from exc
    if file_identity(returned) != identity:
        raise RuntimeError("published brief pathname no longer identifies written file: " + str(path))


def _check_output_ancestor(path, directory_fd):
    """Preserve the output-path refusal before an input witness can obscure a moved ancestor."""
    try:
        returned = open_directory(path.parent)
    except PublicationRefused as exc:
        raise RuntimeError("published brief pathname no longer identifies written file: " + str(path)) from exc
    try:
        if file_identity(os.fstat(returned)) != file_identity(os.fstat(directory_fd)):
            raise RuntimeError("published brief pathname no longer identifies written file: " + str(path))
    finally:
        os.close(returned)


def remove_written_file(directory_fd, name, identity):
    try:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    # Another composer can have replaced the same content address. Remove only
    # our inode; never delete the other tool's publication during cleanup.
    if file_identity(current) == identity:
        os.unlink(name, dir_fd=directory_fd)


def sync_publication_directory(directory_fd):
    if os.name == "nt":
        # Windows does not support fsync on directory handles. Publication also
        # retains its separate refusal when secure dir_fd operations are absent.
        return
    # O_PATH handles permit traversal but cannot be fsynced. Reopen the anchored
    # directory read-only on POSIX, rather than resolving its pathname again.
    descriptor = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish(raw, reference, *, _operation=None):
    require_secure_publication()
    path = Path(reference["path"])
    base_fd = open_directory(path.parent.parent)
    directory_fd = None
    pending = None
    try:
        try:
            try:
                directory_fd = os.open(path.parent.name, directory_flags(), dir_fd=base_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(path.parent.name, mode=0o700, dir_fd=base_fd)
                except FileExistsError:
                    pass  # Another composer created the same output directory.
                directory_fd = os.open(path.parent.name, directory_flags(), dir_fd=base_fd)
        except OSError as exc:
            if exc.errno == errno.EACCES:
                raise PublicationRefused("publication directory permission denied: " + str(path.parent)) from exc
            if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENOENT}:
                raise PublicationRefused("publication directory changed") from exc
            raise
        check_directory(base_fd, directory_fd, path.parent.name)
        try:
            existing = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise PublicationRefused("content-addressed brief is a symlink") from exc
            if not stat.S_ISREG(os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False).st_mode):
                raise PublicationRefused("brief must be a regular file") from exc
            raise
        if existing is not None:
            metadata = os.fstat(existing)
            if not stat.S_ISREG(metadata.st_mode):
                os.close(existing)
                raise PublicationRefused("brief must be a regular file")
            with os.fdopen(existing, "rb") as stream:
                if stream.read(MAX_BYTES + 1) != raw:
                    raise PublicationRefused("content-addressed brief already exists with different bytes")
            check_directory(base_fd, directory_fd, path.parent.name)
            check_returned_path(path, file_identity(metadata))
            sync_publication_directory(directory_fd)
            sync_publication_directory(base_fd)
            check_returned_path(path, file_identity(metadata))
            if _operation is not None:
                _operation.verify()
            return
        pending = ".fresh-" + uuid.uuid4().hex
        descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, "wb") as stream:
            identity = file_identity(os.fstat(stream.fileno()))
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        check_directory(base_fd, directory_fd, path.parent.name)
        _check_output_ancestor(path, directory_fd)
        if _operation is not None:
            _operation.verify()
        os.replace(pending, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        pending = None
        if _operation is not None:
            try:
                _operation.verify()
            except (ValueError, OSError) as exc:
                raise PublicationRefused("committed brief " + str(path) + " requires reconciliation; verify this original path before reuse: " + str(exc)) from exc
        try:
            check_directory(base_fd, directory_fd, path.parent.name)
            check_returned_path(path, identity)
            sync_publication_directory(directory_fd)
            sync_publication_directory(base_fd)
            check_returned_path(path, identity)
        except (PublicationRefused, RuntimeError):
            remove_written_file(directory_fd, path.name, identity)
            raise
    finally:
        if directory_fd is not None:
            try:
                if pending is not None:
                    os.unlink(pending, dir_fd=directory_fd)
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
            from hierarchy_router import preflight_paths, _lexical_path
            path = _lexical_path(args.path)
            if not path.is_absolute() or ".." in path.parts:
                cli_path(args.path, "--path")
            operation = _Operation()
            preflight_paths(path, _guard=operation.path_guard)
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
        print(json.dumps({"error": "brief publication failed: " + str(exc)}, sort_keys=True))
        return 3
    print(json.dumps(answer, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
