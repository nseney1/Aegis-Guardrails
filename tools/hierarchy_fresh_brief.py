#!/usr/bin/env python3
"""Compose a bounded, durable brief without changing any coordination store."""
from __future__ import annotations

import argparse
import copy
from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import hashlib
from functools import wraps
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
from hierarchy_mailbox import (Mailbox, MAX_BYTES, SHA256, SLUG, TERMINAL_JOB_STATES, cli_path, digest, encoded,  # noqa: E402
                               endpoint_parts, fields, integer, matching, parse_time, require,
                               safe_path, strict_json, text)
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
    from hierarchy_router import preflight_paths
    check_path = paths or preflight_paths
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


def _inert_evidence_reducer(private_paths):
    """Operation-local dependency binding; never patch the lifecycle module.

    Execute the pinned reducer functions' ORIGINAL code, defaults and closures.
    Only safe_path differs for inert references and quarantined scope paths:
    those paths are checked lexically, so their metadata is never inspected. Their bytes/hashes,
    actor checks, history, consumption and accounting are neither changed nor
    skipped. This callable is used only for read replay, never event recording.
    """
    def evidence_path(value):
        path = Path(value)
        if path in private_paths:
            require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
            return path
        return life.safe_path(value)

    namespace = dict(vars(life), safe_path=evidence_path)
    for name, function in vars(life).items():
        if isinstance(function, FunctionType) and function.__globals__ is vars(life):
            clone = FunctionType(function.__code__, namespace, function.__name__, function.__defaults__, function.__closure__)
            clone.__kwdefaults__ = function.__kwdefaults__
            namespace[name] = clone
    return namespace["reduce_event"]


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


def _reference_descriptors():
    names = {function.__name__ for function in os.supports_dir_fd}
    return (all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
            and {"open", "stat"} <= names)


def _reference_parent(path):
    """Walk without following links, with bounded handles and recorded ancestor identities."""
    require(_reference_descriptors(), "secure reference hashing requires directory descriptor support")
    flags = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = None
    marks = []
    try:
        descriptor = os.open(path.anchor, flags)
        info = os.fstat(descriptor)
        require(stat.S_ISDIR(info.st_mode) and not _reparse(info), "reference parent must be a directory")
        marks.append((path.anchor, _directory_mark(info)))
        for component in path.parts[1:]:
            previous = descriptor
            descriptor = os.open(component, flags, dir_fd=previous)
            os.close(previous)
            info = os.fstat(descriptor)
            require(stat.S_ISDIR(info.st_mode) and not _reparse(info), "reference parent must be a directory")
            marks.append((component, _directory_mark(info)))
        return descriptor, marks
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise


def _reparse(info):
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _reference_ancestors(path):
    """Portable identity witnesses; no path resolution or link traversal."""
    result = []
    for parent in reversed(path.parents):
        info = os.lstat(parent)
        require(stat.S_ISDIR(info.st_mode) and not _reparse(info), "reference parent must be a directory: " + str(parent))
        result.append((str(parent), _directory_mark(info)))
    return result


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
    from hierarchy_router import preflight_paths
    (preflight_paths if _guard is None else _guard)(path)
    path = safe_path(path)
    anchored = _reference_descriptors()
    directory = None
    try:
        if anchored:
            directory, ancestors = _reference_parent(path.parent)
            before = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        else:
            ancestors = _reference_ancestors(path)
            before = os.lstat(path)
        require(stat.S_ISREG(before.st_mode) and not _reparse(before), "reference must be a regular file: " + str(path))
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
                require(stat.S_ISREG(opened.st_mode) and not _reparse(opened) and _same_mark(_reference_mark(opened), mark),
                        "reference changed while opening: " + str(path))
                if not anchored:
                    require(_same_ancestors(_reference_ancestors(path), ancestors), "reference path changed while opening: " + str(path))
                sha = _stream_reference(descriptor, before, path, chunks.append if capture else None)
                current = (os.stat(path.name, dir_fd=directory, follow_symlinks=False) if anchored else os.lstat(path))
                require(_same_mark(_reference_mark(current), mark), "reference changed while hashing: " + str(path))
            finally:
                os.close(descriptor)
        if anchored:
            returned, current_ancestors = _reference_parent(path.parent)
            try:
                require(_same_ancestors(current_ancestors, ancestors)
                        and _same_mark(_reference_mark(os.stat(path.name, dir_fd=returned, follow_symlinks=False)), mark),
                        "reference path changed while hashing: " + str(path))
            finally:
                os.close(returned)
        else:
            require(_same_ancestors(_reference_ancestors(path), ancestors) and _same_mark(_reference_mark(os.lstat(path)), mark),
                    "reference path changed while hashing: " + str(path))
        if _witness is not None:
            _witness.update(path=path, mark=mark, ancestors=ancestors, anchored=anchored)
        if _cache is not None:
            _cache.setdefault(path, {})[mark] = sha, ancestors
        return {"path": str(path), "sha256": sha}, b"".join(chunks) if capture else None
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
    except (ValueError, OSError) as exc:
        raise UnverifiedAttachment(str(exc)) from exc
    return raw


def _declaration_operation(operation):
    """Isolate optional declarations, while shared privacy policy remains authoritative."""
    class DeclarationGuard:
        def __call__(self, path):
            with operation.capture():
                return operation.path_guard(path)

        def verify(self):
            with operation.capture():
                return operation.path_guard.verify()

    return _Operation(reference_cache=operation.reference_cache, _path_guard=DeclarationGuard())


def _recheck_consumed_reference(operation, path):
    """A declaration cannot hide an identity failure of an existing required witness."""
    with operation.capture():
        if path in operation.files:
            _recheck_reference(operation.files[path][2])
        elif path in operation.reference_cache:
            operation.reference(path)


class UnverifiedAttachment(ValueError):
    """A missing/mismatched regular attachment, distinguishable from unsafe IO."""

    def __init__(self, detail, *, message_id=None):
        super().__init__(detail)
        self.message_id = (None if message_id is None else
                           matching(text(message_id, "message_id", 80), SLUG, "message_id"))


def _recheck_reference(witness):
    """Metadata-only revalidation of the exact captured identity, never a second content read."""
    path = safe_path(witness["path"])
    if witness["anchored"]:
        directory, ancestors = _reference_parent(path.parent)
        try:
            mark = _reference_mark(os.stat(path.name, dir_fd=directory, follow_symlinks=False))
        finally:
            os.close(directory)
    else:
        ancestors, mark = _reference_ancestors(path), _reference_mark(os.lstat(path))
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


class _Operation:
    """One captured identity per path; bounded byte promotions preserve its original witnesses."""
    def __init__(self, *, reference_cache=None, parent=None, _path_guard=None):
        self.files, self.parsed, self.folders, self.journals = {}, {}, {}, {}
        self.reference_cache = {} if reference_cache is None else reference_cache
        self.failed_validation = False
        self.validation_failure = None
        self.parent = parent
        from hierarchy_router import _CapturedPathGuard
        self.path_guard = _CapturedPathGuard() if _path_guard is None else _path_guard
        self.absences, self.validators = {}, [self.path_guard.verify]

    @_capture_attempt
    def read(self, path, *, limit=MAX_BYTES, capture=True, budget_error=None):
        self.path_guard(path)
        path = Path(path)
        if path not in self.files:
            witness = {}
            ref, raw = _read_reference(path, limit=limit, capture=capture, _witness=witness, budget_error=budget_error,
                                       _guard=self.path_guard, _cache=self.reference_cache)
            self.files[path] = ref, raw, witness
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
        from hierarchy_router import preflight_paths
        preflight_paths(path)
        path = safe_path(path)
        try:
            os.lstat(path)
            return True
        except FileNotFoundError:
            missing = path
            while True:
                parent = missing.parent
                try:
                    if _reference_descriptors():
                        descriptor, ancestors = _reference_parent(parent)
                        os.close(descriptor)
                    else:
                        ancestors = _reference_ancestors(missing)
                    break
                except FileNotFoundError:
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

    @staticmethod
    def _members(path, *, membership=True):
        path = safe_path(path)
        if _reference_descriptors():
            directory, ancestors = _reference_parent(path)
            # O_PATH descriptors cannot be enumerated. Open the same anchored identity for listing.
            listing = None
            try:
                mark, names = _directory_mark(os.fstat(directory)), None
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
            ancestors = _reference_ancestors(path / "entry")
            mark = _directory_mark(os.lstat(path))
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
        try:
            yield
        except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
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
        verification(*args)
        self.verify()
        return object()

    def verify(self):
        try:
            self.reject_failed()
            for validate in self.validators:
                validate()
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
                        descriptor, ancestors = _reference_parent(parent)
                    else:
                        ancestors = _reference_ancestors(parent / "entry")
                    for witness in witnesses:
                        path = witness["path"]
                        info = (os.stat(path.name, dir_fd=descriptor, follow_symlinks=False) if anchored else os.lstat(path))
                        require(_same_ancestors(ancestors, witness["ancestors"])
                                and _same_mark(_reference_mark(info), witness["mark"]),
                                "captured attachment identity/content metadata changed: " + str(path))
                    for path, previous in self.absences.items():
                        if path.parent != parent:
                            continue
                        require(_same_ancestors(ancestors, previous), "captured absent input parent changed: " + str(path))
                        try:
                            os.stat(path.name, dir_fd=descriptor, follow_symlinks=False) if anchored else os.lstat(path)
                        except FileNotFoundError:
                            pass
                        else:
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
                except (ValueError, OSError) as exc:
                    raise CaptureChanged(path, exc) from exc
                finally:
                    if listing is not None:
                        os.close(listing)
                    if descriptor is not None:
                        os.close(descriptor)
        except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
            self.fail(exc)
            raise

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
        super().__init__(root)
        self.operation, self.records, self.index = operation, [], {}
        self.private_refusals = {}
        self.declared_references = {}
        self.reference_operations = {}
        self.unknown_rows = {}
        self.refused_events = set()
        self._snapshot = None

    def _replay(self):
        policy = life.validate_policy(self.operation.json(self.root / "policy.json", limit=life.MAX_BYTES))
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
            accepted = self._reduce_row(policy, state, record)
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

    def _reduce_row(self, policy, state, record):
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
            life.reduce_event(policy, state, envelope, record["at"])
            return True
        private_paths, refusals = set(), []
        declared_references = []

        def scoped_path(value):
            try:
                self.operation.path_guard.refuse(value)
            except PrivatePathError as exc:
                private_paths.add(Path(value))
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
            private_paths.add(path)
            declared_references.append(dict(ref))

        _private_paths(record, inert=declared, paths=scoped_path)
        reducer = _inert_evidence_reducer(private_paths) if private_paths else life.reduce_event
        if event["type"] == "publish":
            reducer(policy, state, envelope, record["at"])
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
                reducer(policy, state, envelope, record["at"])
            elif self._unknown_for(state, target):
                return False
            else:
                trial = dict(state, requests=dict(state["requests"]),
                             decisions=list(state["decisions"]), consumed=dict(state["consumed"]),
                             meters=copy.deepcopy(state["meters"]))
                trial["requests"][target] = copy.deepcopy(state["requests"][target])
                try:
                    reducer(policy, trial, envelope, record["at"])
                except (ValueError, TypeError, KeyError) as exc:
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
                        references.fail(exc)
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
                self.operation.fail(exc)
                result.append((str(self.root), "declared evidence changed: " + str(exc)))
        return result

    def verify_dependencies(self, identifier):
        refusals = self.refusals_for(identifier, consume=True)
        require(not refusals, refusals[0][1] if refusals else "lifecycle dependency evidence unavailable")

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
        from hierarchy_router import preflight_paths
        preflight_paths(root)
        self.operation = _operation if _operation is not None else _Operation()
        self.root = safe_path(root)
        self.manifest = protocol.validate_manifest(self.operation.json(self.root / "manifest.json"))
        self._records = None
        self.message_refusals = {}
        self._stored_message_paths = None
        self._publishing = False
        self._publication = None
        self.before_publication = None

    def brief(self, reference, *, verify=True):
        # A cache hit already has a validated envelope/path; defer metadata checks to the effect boundary.
        fields(reference, {"path", "sha256"})
        matching(reference["sha256"], SHA256, "brief sha256")
        path = Path(text(reference["path"], "brief path"))
        from hierarchy_router import preflight_paths
        stored = self._stored_message_paths is not None
        if not stored:
            preflight_paths(path)
        if path not in self.operation.files and not stored:
            try:
                super().brief(reference, verify=False)
            except (ValueError, OSError) as exc:
                raise UnverifiedAttachment(str(exc)) from exc
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
        except (ValueError, OSError) as exc:
            # Metadata rejects linked/nonregular/oversized notes before open.
            # Unread typed-note consumers retain these as unverified claims;
            # open dispatch/job consumers still propagate this refusal.
            raise UnverifiedAttachment(str(exc)) from exc
        if actual["sha256"] != reference["sha256"]:
            raise UnverifiedAttachment("brief sha256 mismatch")
        return raw

    def readiness(self, readiness, *, observe=True):
        private = self._stored_message_paths
        if not private:
            return super().readiness(readiness, observe=observe)
        def path(value):
            candidate = Path(value)
            if candidate in private:
                require(candidate.is_absolute() and ".." not in candidate.parts, "path must be absolute without traversal")
                return candidate
            return safe_path(candidate)
        original = Mailbox.readiness
        function = FunctionType(original.__code__, dict(original.__globals__, safe_path=path),
                                original.__name__, original.__defaults__, original.__closure__)
        function.__kwdefaults__ = original.__kwdefaults__
        return function(self, readiness, observe=observe)

    def check_ref(self, ref):
        with self.operation.capture():
            fields(ref, {"path", "sha256"})
            matching(ref["sha256"], SHA256, "reference sha256")
            text(ref["path"], "reference path")
            self.operation.check_ref(ref)

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

    def dispatch_history(self, records):
        history = super().dispatch_history(records)
        if self._publishing:
            # Last virtual call before the pinned dispatch/job_request commit. Reply publication is not borrowed.
            if self.before_publication is not None:
                self.before_publication(self._publication)
            self.operation.verify()
        return history

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
                    try:
                        destination = self.validate_message(message, stored=True)
                    finally:
                        self._stored_message_paths = None
                    require(destination == folder, "message is in the wrong routing folder")
                    require(message["message_id"] not in records, "duplicate message_id in history")
                    records[message["message_id"]] = {"path": str(path), "message": message}
                    if refusals:
                        self.message_refusals[message["message_id"]] = [
                            "malformed mailbox message: " + str(path) + ": " + error for error in refusals]
                except (ValueError, TypeError, KeyError) as exc:
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

    def evidence(self, value, origin):
        """Keep unavailable or mismatched evidence as a declaration anchored to its durable record."""
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
                except (ValueError, OSError):
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


def locate(root, initiative, *, _mailbox=None):
    """Accept a team run, its initiative base, or the mailbox root used by handoff entries."""
    operation = _mailbox.operation if _mailbox is not None else _Operation()
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
    from hierarchy_router import preflight_paths
    preflight_paths(*(value for value in (args.root, args.lifecycle, args.delivery_dir) if value is not None))
    matching(args.initiative, SLUG, "initiative")
    require(endpoint_parts(args.endpoint)[0] == args.initiative, "endpoint is outside initiative " + args.initiative)
    mailbox, base, run, setup = locate(cli_path(args.root, "--root"), args.initiative, _mailbox=_mailbox)
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
            from hierarchy_router import preflight_paths
            preflight_paths(args.path)
            path = cli_path(args.path, "--path")
            matching(args.sha256, SHA256, "brief sha256")
            require(path.suffix == ".md", "brief must be a Markdown file")
            operation = _Operation()
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
