"""Intent/result journal for model-free git custody (Git ADR G3, D13, AC18).

The caller supplies the trusted absolute git common directory, outside role-writable
roots. This module runs neither git nor gh nor an effect callback. A *new*, durable
IntentReceipt permits the caller's one attempt; an existing receipt never does.
The effect transport passes receipt.inheritable_fds() only to its custody holder.
Supply effect_fds and the owner-bound worktree_root; the holder retains the lock
until every effect descendant exits. After a lost reply, reconcile uses
only the caller's read-only observer. Unknown
is terminal only for an observed foreign state. Unavailable observations keep
the intent pending; neither condition authorizes another effect attempt.
An interrupted observation checkpoint refuses checkpoint_stuck after healthy
intents in the lane have finished. Its next_action lists at most 16 safe request
identifiers; reconcile again after resolving them to discover any remainder.
The owner must read external state for those requests, then call
record_result(request_id, status, observed) to resolve each reservation; never
retry the effect. A complete saved observation remains authoritative: every
terminal writer replays a matching result and refuses a contradiction.

State is an object id, None (absence), or a closed, flat remote/worktree/lease
description. Commands, messages, credentials and environments are not accepted.
Adapters must use display_row before showing externally supplied fields. Refusals
have fixed codes/messages; OS and observer exception text is never propagated.
Unsupported descriptor platforms refuse explicitly; there is no path fallback.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext, ExitStack
from dataclasses import dataclass, field
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import threading
import uuid

try:
    import fcntl
except ImportError:
    fcntl = None

from aegis_core import storage
from aegis_core.errors import LockTimeoutError, PathTraversalError
from aegis_core.storage import ConfinedFileError, confined_file
from aegis_core.primitives import utc_stamp

__all__ = ["GitOpsJournal", "GitOpsError", "IntentReceipt", "JournalRead", "Observation",
           "OPS", "REFUSALS", "display_row", "descriptor_supported"]

from aegis_core import gitops_checkpoint as checkpoints
from aegis_core import gitops_rows as rows
from aegis_core.gitops_rows import (GitOpsError, JournalRead, OPS, REFUSALS,
    MAX_JOURNAL_BYTES, MAX_ROW_BYTES, MAX_RECORD_LINES, RECONCILE_BATCH_SIZE,
    FINAL_RECORD_ATTEMPTS, DISPLAY_LIMIT, BASE_KEYS as _BASE_KEYS,
    LANE as _LANE, identifier as _identifier, state as _state,
    same_intent as _same_intent, encoded as _encoded, terminal_bytes as _terminal_bytes)


def _parse(data):
    return rows.parse(data, max_lines=MAX_RECORD_LINES, max_row_bytes=MAX_ROW_BYTES)


def display_row(value, _depth=0):
    """Render through the shared codec using this facade's configured limits."""
    return rows.display_row(value, _depth, max_row_bytes=MAX_ROW_BYTES, display_limit=DISPLAY_LIMIT)


def _intent(op, lane, request_id, expected_old, expected_new, actor):
    return rows.intent(op, lane, request_id, expected_old, expected_new, actor, stamp=utc_stamp())


def _result(intent, status, observed):
    return rows.result(intent, status, observed, stamp=utc_stamp())


_OWNERS = {}
_OWNER_GUARD = threading.RLock()
_IN_FLIGHT_ACTION = {"actor": "owner", "command": "wait for the effect owner to exit, then reconcile by observation; never retry the effect"}


@dataclass(frozen=True)
class IntentReceipt:
    """One attempt's ownership, independent of the GitOpsJournal instance.

    One custody holder retains this descriptor until all effect descendants exit.
    inheritable_fds() exports a close-on-exec tuple; pass it as effect_fds to
    the admitted transport. Effect programs receive no descriptor; the parent
    closes its receipt after all of its own effect activity has stopped.
    The shared lock descriptor is read-only: children cannot write checkpoints.
    Closing an abandoned receipt never grants a retry of the durable intent.
    A close attempt forgets ownership even if the OS reports a close failure;
    subsequent release calls cannot close a reused descriptor number.
    """

    row: dict
    created: bool  # Only True grants the caller its single effect attempt.
    _key: object = field(default=None, repr=False, compare=False)
    _token: object = field(default=None, repr=False, compare=False)

    def inheritable_fds(self):
        from aegis_core import gitops_fds
        return gitops_fds.export_receipt(self, _OWNERS, _OWNER_GUARD, GitOpsError)

    def release(self):
        with _refusals(None):
            _release_owner(self._key, self._token)

    close = release

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


@dataclass(frozen=True)
class Observation:
    """An authoritative read-only state observation; None means observed absence."""

    state: object


def descriptor_supported():
    return fcntl is not None and storage.confined_descriptor_supported()


def _effect_key(directory, request_id):
    info = os.fstat(directory)
    return info.st_dev, info.st_ino, request_id


@contextmanager
def _pin_effect(effect_fd):
    """Pin a caller's descriptor before any operation can reuse its number."""
    if effect_fd is None:
        yield None
        return
    try:
        pinned = os.dup(effect_fd)
    except OSError as error:
        if error.errno in (errno.EBADF, errno.EINVAL):
            raise GitOpsError("invalid_result", result_cause="descriptor") from None
        raise
    try:
        yield pinned
    finally:
        closing, pinned = pinned, None
        os.close(closing)


def _effect_name(request_id):
    return "gitops-effect-" + hashlib.sha256(request_id.encode("ascii")).hexdigest() + ".lock"


def _effect_named(directory, name, fd):
    info = os.fstat(fd)
    try:
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return (info.st_nlink == named.st_nlink == 1
            and (info.st_dev, info.st_ino) == (named.st_dev, named.st_ino))


def _try_effect(directory, request_id, pinned_fd=None, *, new_intent=False, existing_only=False):
    # A waiter may have opened the old inode before compaction unlinked it.
    # Reopen after flock rather than granting ownership of a detached inode.
    for _ in range(3):
        effect = _acquire_effect(directory, request_id, pinned_fd,
                                 new_intent=new_intent, existing_only=existing_only)
        if effect is not _RETIRED_EFFECT:
            return effect
    raise GitOpsError("journal_busy")


_RETIRED_EFFECT = object()


def _flock(fd, mode):
    try:
        fcntl.flock(fd, mode)
    except OSError as error:
        if error.errno in (errno.EBADF, errno.ENOLCK):
            raise GitOpsError("unsupported_platform") from None
        raise


def _acquire_effect(directory, request_id, pinned_fd=None, *, new_intent=False, existing_only=False):
    name = _effect_name(request_id)
    if new_intent:
        fd = _open_receipt_lock(directory, name)
    else:
        created = False
        try:
            if existing_only:
                fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            else:
                fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            if existing_only:
                return None
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK,
                         0o600, dir_fd=directory)
            created = True
    try:
        if not new_intent and created:
            os.fsync(directory)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink not in (0, 1) or info.st_uid != os.geteuid():
            raise GitOpsError("unsafe_journal")
        if pinned_fd is not None:
            # record_result pinned this descriptor at entry, before any open.
            # Take this frame's own copy of that stable open file description;
            # a separate open of the anchored name cannot retain its flock.
            try:
                inherited = os.dup(pinned_fd)
            except OSError as error:
                if error.errno in (errno.EBADF, errno.EINVAL):
                    raise GitOpsError("invalid_result", result_cause="descriptor") from None
                raise
            try:
                inherited_info = os.fstat(inherited)
                if (inherited_info.st_dev, inherited_info.st_ino) != (info.st_dev, info.st_ino):
                    raise GitOpsError("invalid_result", result_cause="descriptor")
            except BaseException:
                closing, inherited = inherited, None
                os.close(closing)
                raise
            closing, fd = fd, inherited
            inherited = None
            os.close(closing)
        try:
            _flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            try:
                _flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return None
            _flock(fd, fcntl.LOCK_UN)
            # Only a shared ownership probe blocked us. Reopen and briefly
            # retry the exclusive claim, never misreport it as a live owner.
            return _RETIRED_EFFECT
        if not _effect_named(directory, name, fd):
            if pinned_fd is not None:
                raise GitOpsError("invalid_result", result_cause="descriptor")
            return _RETIRED_EFFECT
        if not existing_only:
            os.fchmod(fd, 0o600)
        if new_intent:
            # A failed prior admission may have created this checkpoint name
            # without flushing it. The first successful admission must commit
            # the namespace before its durable intent can authorize an effect.
            os.fsync(directory)
            _clear_retired_checkpoint(directory, name, fd)
        owned, fd = fd, None
        return owned
    finally:
        if fd is not None:
            closing, fd = fd, None
            os.close(closing)


def _open_receipt_lock(directory, name):
    # A new intent acquires the very same read-only open file description that
    # the receipt and its children retain; there is no lock-transfer gap.
    return os.open(name, os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)


def _clear_retired_checkpoint(directory, name, effect):
    return checkpoints.reset_retired(directory, name, effect, truncate=os.ftruncate, flush=os.fsync)


def _release_owner(key, token=None):
    with _OWNER_GUARD:
        held = _OWNERS.get(key)
        if held is not None and held[1] == os.getpid() and (token is None or held[2] is token):
            del _OWNERS[key]
            os.close(held[0])


@contextmanager
def _receipt_guard():
    """A refused receipt cannot retain newly acquired execution ownership."""
    granted = []
    try:
        yield granted
    except BaseException:
        for key, token in granted:
            _release_owner(key, token)
        raise


@contextmanager
def _directory(root, create):
    if not descriptor_supported():
        raise GitOpsError("unsupported_platform")
    if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
        raise GitOpsError("unsafe_journal")
    parts = ("aegis", "gitops.jsonl") if create else ("aegis",)
    with confined_file(root, parts, create_parents=create) as handle:
        # Explicit same-package coupling: borrow only while the helper owns the
        # context. It supplies the sole root traversal and unconditional flush.
        parent = handle._parent
        if create:
            fd = parent
        else:
            try:
                fd = os.open("aegis", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                yield None
                return
        try:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise GitOpsError("unsafe_journal")
            yield fd
        finally:
            if not create:
                os.close(fd)


def _read_fd(fd):
    if os.fstat(fd).st_size > MAX_JOURNAL_BYTES:
        raise GitOpsError("journal_too_large")
    os.lseek(fd, 0, os.SEEK_SET)
    data = bytearray()
    while len(data) <= MAX_JOURNAL_BYTES:
        chunk = os.read(fd, min(8192, MAX_JOURNAL_BYTES + 1 - len(data)))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
    raise GitOpsError("journal_too_large")


def _append(fd, row, size):
    payload = _encoded(row)
    if len(payload) > MAX_ROW_BYTES:
        if row["kind"] == "intent":
            raise GitOpsError("invalid_intent")
        raise GitOpsError("invalid_result", result_cause="capacity")
    payload += b"\n"
    if size + len(payload) > MAX_JOURNAL_BYTES:
        raise GitOpsError("journal_too_large")
    os.lseek(fd, 0, os.SEEK_END)
    pending = memoryview(payload)
    while pending:
        count = os.write(fd, pending)
        if count <= 0:
            raise GitOpsError("journal_io")
        pending = pending[count:]
    os.fsync(fd)
    return size + len(payload)


def _quarantine(fd, data):
    """Discard uncommitted bytes before parsing; a fixed invalid row records it.

    Collapse adjacent quarantine markers so repeated interrupted result writes
    cannot consume an unbounded amount of their reserved terminal capacity.
    """
    if not data or data.endswith(b"\n"):
        return data
    prefix = data[:data.rfind(b"\n") + 1]
    while prefix.endswith(b"!\n"):
        prefix = prefix[:-2]
    os.ftruncate(fd, len(prefix))
    os.lseek(fd, 0, os.SEEK_END)
    if os.write(fd, b"!\n") != 2:
        raise GitOpsError("journal_io")
    os.fsync(fd)
    return prefix + b"!\n"


def _pending(rows, lane=None):
    completed = {row["request_id"] for row in rows if row["kind"] in ("result", "tombstone")}
    return [row for row in rows if row["kind"] == "intent" and row["request_id"] not in completed
            and (lane is None or row["lane"] == lane)]


def _admission_full(data, read, encoded, terminal_bytes):
    pending = _pending(read.rows)
    outstanding = len(pending) + 1
    # Include each terminal newline and one durable quarantine marker.
    reserved = terminal_bytes + 3 + sum(_terminal_bytes(old) + 3 for old in pending)
    return (len(data) + len(encoded) + 1 + reserved > MAX_JOURNAL_BYTES
            or data.count(b"\n") + 1 + 2 * outstanding > MAX_RECORD_LINES)


def _retire_effect(directory, request_id, held=None):
    """Caller proved terminal state under gitops.lock; never unlink a held effect."""
    effect = os.dup(held) if held is not None else _try_effect(directory, request_id, existing_only=True)
    if effect is None:
        return
    try:
        name = _effect_name(request_id)
        if _effect_named(directory, name, effect):
            os.unlink(name, dir_fd=directory)
        # Lock names/checkpoints carry no authority once the result is durable.
        # A crash resurrecting this name is harmless; no directory flush needed.
    finally:
        os.close(effect)


def _effect_held(directory, request_id):
    """Probe ownership without changing filesystem contents or granting a retry."""
    name = _effect_name(request_id)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink not in (0, 1) or info.st_uid != os.geteuid():
            raise GitOpsError("unsafe_journal")
        try:
            _flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return True if _effect_named(directory, name, fd) else None
        try:
            return False if _effect_named(directory, name, fd) else None
        finally:
            _flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _compact(directory, old_fd, read, data):
    """Replace, never truncate, the active authority while holding gitops.lock."""
    payload = rows.compacted(read, data=data, max_row_bytes=MAX_ROW_BYTES,
                             max_journal_bytes=MAX_JOURNAL_BYTES, max_lines=MAX_RECORD_LINES)
    if payload is None:
        return None
    parsed = _parse(payload)
    if parsed.skipped != read.skipped:
        raise GitOpsError("journal_io")
    # A complete prior append can have failed its fsync. Flush the old whole
    # journal too: a crash after replace but before directory fsync may restore
    # that inode, and either generation must retain every terminal result.
    os.fsync(old_fd)
    name = ".gitops-compact-" + uuid.uuid4().hex
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK,
                 0o600, dir_fd=directory)
    try:
        remaining = memoryview(payload)
        while remaining:
            count = os.write(fd, remaining)
            if count <= 0:
                raise GitOpsError("journal_io")
            remaining = remaining[count:]
        os.fsync(fd)
        os.replace(name, "gitops.jsonl", src_dir_fd=directory, dst_dir_fd=directory)
        name = None
        os.fsync(directory)
        result, fd = (fd, payload, parsed), None
        return result
    finally:
        try:
            if fd is not None:
                os.close(fd)
        finally:
            if name is not None:
                try:
                    os.unlink(name, dir_fd=directory)
                except FileNotFoundError:
                    pass


def _committed_generation(fd, data, read, *, appended=0):
    """Key a lock-held snapshot and committed appends; never cache a torn read."""
    if fd is None:
        raise GitOpsError("journal_io")
    if read.torn_tail:
        return None
    info = os.fstat(fd)
    return info.st_dev, info.st_ino, data.rfind(b"\n") + 1 + appended


def _observation_checkpoint(effect, intent, *, result=None, reset=False, reserve=True, flush=True):
    if reset:
        return checkpoints.reset(effect, truncate=os.ftruncate, flush=os.fsync)
    if result is not None:
        return checkpoints.publish(effect, result, append=_append)
    row = checkpoints.inspect(effect, intent, max_row_bytes=MAX_ROW_BYTES, flush=os.fsync if flush else None)
    if row is None and reserve:
        checkpoints.reserve(effect, intent, max_row_bytes=MAX_ROW_BYTES,
                            write=os.write, flush=os.fsync, truncate=os.ftruncate)
    return row


def _checkpoint_unreplayable(effect, intent):
    """Inspect remaining bytes; unreadable storage retains the original refusal."""
    try:
        _observation_checkpoint(effect, intent, reserve=False, flush=False)
    except GitOpsError as error:
        return error.code == "checkpoint_stuck"
    except OSError:
        return False
    return False


@contextmanager
def _refusals(root):
    try:
        yield
    except GitOpsError as error:
        if error.code == "unsafe_journal":
            error.next_action = GitOpsError(error.code, root).next_action
        raise
    except LockTimeoutError:
        raise GitOpsError("journal_busy") from None
    except PathTraversalError:
        raise GitOpsError("unsafe_journal", root) from None
    except ConfinedFileError as error:
        code = {"missing": "unsafe_journal", "unsafe": "unsafe_journal", "invalid_path": "unsafe_journal",
                "unsupported": "unsupported_platform", "too_large": "journal_too_large"}.get(error.reason, "journal_io")
        raise GitOpsError(code, root) from None
    except OSError as error:
        unsafe = error.errno in (errno.ELOOP, errno.ENOTDIR, errno.ENOENT)
        raise GitOpsError("unsafe_journal" if unsafe else "journal_io", root) from None


class GitOpsJournal:
    """Shared journal under a caller-selected, trusted git common directory.

    All processes must use this API and its dedicated gitops.lock. The parent is
    anchored once per transaction: concurrent component renames cannot redirect
    lock, reads or appends. The owner UID and the common directory are trusted.
    Any I/O refusal may follow a durable write: do not execute or replay effects
    after that refusal; inspect/reconcile the existing request instead.
    """

    def __init__(self, common_dir):
        if not isinstance(common_dir, (str, Path)) or not 0 < len(str(common_dir)) <= 32768:
            raise GitOpsError("unsafe_journal")
        spelling = str(common_dir)
        if "\x00" in spelling or any(0xd800 <= ord(char) <= 0xdfff for char in spelling):
            raise GitOpsError("unsafe_journal")
        root = Path(spelling)
        if not root.is_absolute() or ".." in root.parts:
            raise GitOpsError("unsafe_journal")
        self.common_dir = root
        self._in_flight = {}
        self._flight_guard = threading.RLock()

    def _sync_flights(self, pending):
        current = {row["request_id"]: row for row in pending}
        with self._flight_guard:
            self._in_flight = {key: row for key, row in self._in_flight.items()
                               if key in current and _same_intent(row, current[key])}

    def _flight_update(self, intent, held):
        with self._flight_guard:
            if held:
                self._in_flight[intent["request_id"]] = intent
            else:
                self._in_flight.pop(intent["request_id"], None)

    def _forget_flights(self, requests):
        with self._flight_guard:
            for request in requests:
                self._in_flight.pop(request, None)

    def _retire_completed_claim(self, directory, intent, effect):
        with self._transaction(write=True, directory_fd=directory) as (_, _, read, _):
            if any(row["kind"] == "tombstone" and _same_intent(row, intent)
                   for row in read.rows):
                _retire_effect(directory, intent["request_id"], held=effect)
                self._flight_update(intent, False)

    @contextmanager
    def _transaction(self, write=False, *, directory_fd=None):
        with _refusals(self.common_dir):
            context = _directory(self.common_dir, write) if directory_fd is None else nullcontext(directory_fd)
            with context as directory:
                if directory is None:
                    yield None, b"", JournalRead([]), None
                    return
                lock = storage.file_lock(Path("gitops.lock"), timeout=5.0, dir_fd=directory) if write else nullcontext()
                with lock:
                    try:
                        if write:
                            try:
                                fd = os.open("gitops.jsonl", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                                             dir_fd=directory)
                            except FileNotFoundError:
                                fd = os.open("gitops.jsonl", os.O_RDWR | os.O_CREAT | os.O_EXCL |
                                             os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
                        else:
                            fd = os.open("gitops.jsonl", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                         dir_fd=directory)
                    except FileNotFoundError:
                        if write:
                            raise
                        yield None, b"", JournalRead([]), directory
                        return
                    with ExitStack() as handles:
                        handles.callback(os.close, fd)
                        info = os.fstat(fd)
                        if (not stat.S_ISREG(info.st_mode) or info.st_nlink not in ((1,) if write else (0, 1))
                                or info.st_uid != os.geteuid()):
                            raise GitOpsError("unsafe_journal")
                        if write:
                            os.fchmod(fd, 0o600)
                            # An earlier replace may have survived without its
                            # directory fsync. Commit that namespace before any
                            # writer acknowledges new or replayed result bytes.
                            os.fsync(directory)
                        data = _read_fd(fd)
                        if write:
                            data = _quarantine(fd, data)
                        read = _parse(data)
                        yield fd, data, read, directory

    def read(self):
        """Bounded public history; compacted terminal rows retain result semantics."""
        with self._transaction() as (_, _, read, _):
            return JournalRead([rows.as_result(row) if row["kind"] == "tombstone" else row
                                for row in read.rows], read.skipped, read.torn_tail)

    def open_intents(self, lane=None):
        """Intents with no result. Unknown results stay terminal and are not retried."""
        if lane is not None and not _identifier(lane, _LANE):
            raise GitOpsError("invalid_request")
        return _pending(self.read().rows, lane)

    def in_flight(self, lane=None):
        """Read-only live ownership query, including held rows from this reconcile.

        Shared probes never create files or retain execution ownership. Cached
        facts are bound to the current pending intent and never replace a live
        probe. A retired/missing name gets one anchored journal refresh.
        """
        if lane is not None and not _identifier(lane, _LANE):
            raise GitOpsError("invalid_request")
        reported = []
        with self._transaction() as (_, _, read, directory):
            self._sync_flights(_pending(read.rows))
            for intent in _pending(read.rows, lane):
                request = intent["request_id"]
                held = _effect_held(directory, request)
                if held is None:
                    with self._transaction(directory_fd=directory) as (_, _, fresh, _):
                        current = next((row for row in _pending(fresh.rows, lane)
                                        if row["request_id"] == request), None)
                    held = current is not None
                    if current is not None:
                        intent = current
                self._flight_update(intent, held)
                if held:
                    reported.append(dict(intent, kind="in_flight", status="in_flight",
                                         next_action=dict(_IN_FLIGHT_ACTION)))
        return reported

    def record_intent(self, *, op, lane, request_id, expected_old, expected_new, actor):
        row = _intent(op, lane, request_id, expected_old, expected_new, actor)
        encoded, terminal_bytes = _encoded(row), _terminal_bytes(row)
        if max(len(encoded), terminal_bytes) > MAX_ROW_BYTES:
            raise GitOpsError("invalid_intent")
        with _receipt_guard() as granted, self._transaction(write=True) as (fd, data, read, directory), \
                ExitStack() as replacements:
            for old in read.rows:
                if old["kind"] in ("intent", "tombstone") and old["request_id"] == request_id:
                    original = rows.as_intent(old)
                    if any(original[key] != row[key] for key in _BASE_KEYS - {"ts", "created_at"}):
                        raise GitOpsError("request_conflict")
                    return IntentReceipt(original, False)
            if _admission_full(data, read, encoded, terminal_bytes):
                compacted = _compact(directory, fd, read, data)
                if compacted is not None:
                    fd, data, read = compacted
                    replacements.callback(os.close, fd)
                    for old in read.rows:
                        if old["kind"] == "tombstone":
                            _retire_effect(directory, old["request_id"])
                # One rewrite and one retry only. Full tombstones/open intents
                # remain authoritative; failed capacity never grants an effect.
                if _admission_full(data, read, encoded, terminal_bytes):
                    raise GitOpsError("journal_capacity")
            key = _effect_key(directory, request_id)
            effect = _try_effect(directory, request_id, new_intent=True)
            if effect is None:
                raise GitOpsError("effect_busy")
            try:
                _append(fd, row, len(data))
            except BaseException:
                os.close(effect)
                raise
            with _OWNER_GUARD:
                token = object()
                _OWNERS[key] = (effect, os.getpid(), token)
                granted.append((key, token))
            return IntentReceipt(row, True, key, token)

    def record_result(self, request_id, status, observed=None, *, receipt=None, effect_fd=None):
        """Record an observed result, with process ownership or an inherited fd.

        A fresh instance in the owner process may present its receipt. An exec'd
        child supplies effect_fd from pass_fds; the caller owns that descriptor
        and closes it after all effect activity ends. It is pinned before any
        journal open, and this method closes its temporary copies. A durable
        terminal result releases this
        process's receipt; other processes must close their own copies.
        A complete checkpoint must match the supplied observation. An owner
        can resolve an interrupted checkpoint by reading external state and
        recording that observation here, without repeating the effect.
        """
        if not _identifier(request_id):
            raise GitOpsError("invalid_request")
        if receipt is not None and type(receipt) is not IntentReceipt:
            raise GitOpsError("invalid_result", result_cause="receipt")
        if effect_fd is not None and (type(effect_fd) is not int or not 0 <= effect_fd <= 2**31-1):
            raise GitOpsError("invalid_result", result_cause="descriptor")
        if receipt is not None and effect_fd is not None:
            raise GitOpsError("invalid_result", result_cause="ownership")
        with _refusals(self.common_dir), _pin_effect(effect_fd) as pinned, \
                self._transaction(write=True) as (fd, data, read, directory):
            intent = next((row for row in read.rows
                           if row["kind"] in ("intent", "tombstone") and row["request_id"] == request_id), None)
            if intent is None:
                raise GitOpsError("missing_intent")
            key = _effect_key(directory, request_id)
            if receipt is not None and (not receipt.created or receipt._key != key):
                raise GitOpsError("invalid_result", result_cause="receipt")
            row = _result(intent, status, observed)
            for old in read.rows:
                if old["kind"] in ("result", "tombstone") and old["request_id"] == request_id:
                    if old["status"] != status or old["observed"] != row["observed"]:
                        raise GitOpsError("result_conflict", result_cause="durable")
                    os.fsync(fd)
                    _release_owner(key)
                    self._forget_flights([request_id])
                    return rows.as_result(old)
            with _OWNER_GUARD:
                held = _OWNERS.get(key)
                owned = (held is not None and held[1] == os.getpid()
                         and (receipt is None or held[2] is receipt._token))
                effect = os.dup(held[0]) if owned and effect_fd is None else None
            if effect is None:
                if receipt is not None:
                    raise GitOpsError("effect_busy")
                effect = (_try_effect(directory, request_id) if effect_fd is None
                          else _try_effect(directory, request_id, pinned))
            if effect is None:
                raise GitOpsError("effect_busy")
            try:
                try:
                    checkpoint = _observation_checkpoint(effect, intent, reserve=False)
                except GitOpsError as error:
                    if error.code != "checkpoint_stuck":
                        raise
                    # The owner's explicit observation resolves an interrupted
                    # reservation. A valid saved result may never be superseded.
                    checkpoint = None
                if checkpoint is not None:
                    if checkpoint["status"] != status or checkpoint["observed"] != row["observed"]:
                        raise GitOpsError("result_conflict")
                    row = checkpoint
                _append(fd, row, len(data))
                _release_owner(key)
                self._forget_flights([request_id])
            finally:
                os.close(effect)
            return row

    def _observe_once(self, effect, intent, observe):
        """Checkpoint one callback under its effect lock, outside the journal lock."""
        with _refusals(self.common_dir):
            row = _observation_checkpoint(effect, intent)
            if row is not None:
                return row
            status = "unknown"
            try:
                # Never let an adapter mutate persisted bindings.
                observation = observe(json.loads(json.dumps(intent)))
                if type(observation) is not Observation:
                    raise ValueError("unavailable observation")
                state = _state(observation.state)
                if state == intent["expected_new"]:
                    status = "done"
                elif state == intent["expected_old"]:
                    status = "not_applied"
            except Exception:
                _observation_checkpoint(effect, intent, reset=True)
                return None
            row = _result(intent, status, state)
            _observation_checkpoint(effect, intent, result=row)
            return row

    def _record_observations(self, directory, lane, observations):
        for attempt in range(FINAL_RECORD_ATTEMPTS):
            try:
                with _refusals(self.common_dir), self._transaction(
                        write=True, directory_fd=directory) as (fd, data, read, _):
                    completed = {row["request_id"]: rows.as_result(row) for row in read.rows
                                 if row["kind"] in ("result", "tombstone")}
                    size, recorded = len(data), []
                    replayed = False
                    for row in observations:
                        old = completed.get(row["request_id"])
                        if old is None:
                            size = _append(fd, row, size)
                        else:
                            replayed = True
                            if (not _same_intent(old, row) or old["status"] != row["status"]
                                    or old["observed"] != row["observed"]):
                                raise GitOpsError("result_conflict", result_cause="durable")
                        recorded.append(old if old is not None else row)
                    if replayed:
                        os.fsync(fd)
                    next_generation = _committed_generation(fd, data, read, appended=size - len(data))
                    next_cached = {row["request_id"]: row for row in
                                   _pending(read.rows + recorded, lane)}
                self._forget_flights(row["request_id"] for row in recorded)
                return next_cached, next_generation, recorded
            except GitOpsError as error:
                if (error.code not in ("journal_busy", "journal_io")
                        or attempt + 1 == FINAL_RECORD_ATTEMPTS):
                    raise

    def reconcile(self, lane, observe):
        """Observe abandoned requests outside the journal lock; never run effects.

        ``observe(intent) -> Observation`` must only read external state. Its
        failure or invalid response keeps the intent pending without exception
        details. An authoritative foreign state records terminal unknown.
        This callback is a trusted service boundary, never supplied by a model.
        Successful observations are checkpointed under the effect lock and
        survive failed final records. An interrupted checkpoint refuses closed.
        Healthy intents finish before reporting retriable storage/capacity errors
        or checkpoints needing the owner's explicit record_result recovery.
        Claims use eight-descriptor batches and three final-record attempts under
        those locks; exhausted retries leave durable checkpoints for recovery.
        """
        if not _identifier(lane, _LANE) or not callable(observe):
            raise GitOpsError("invalid_request")
        results = []
        blocked, deferred = [], None
        with _refusals(self.common_dir), _directory(self.common_dir, True) as directory:
            with self._transaction(write=True, directory_fd=directory) as (fd, data, read, _):
                all_pending = _pending(read.rows)
                self._sync_flights(all_pending)
                pending = [row for row in all_pending if row["lane"] == lane]
                cached = {row["request_id"]: row for row in pending}
                generation = _committed_generation(fd, data, read)
            pending.sort(key=lambda row: row["request_id"])
            for start in range(0, len(pending), RECONCILE_BATCH_SIZE):
                with ExitStack() as effects:
                    claimed, unclaimed = [], []
                    # Claim the whole bounded batch before observing. Writers
                    # probe effects nonblockingly even under the journal lock.
                    for intent in pending[start:start + RECONCILE_BATCH_SIZE]:
                        effect = _try_effect(directory, intent["request_id"], existing_only=True)
                        if effect is not None:
                            effects.callback(os.close, effect)
                            claimed.append((intent, effect))
                        else:
                            unclaimed.append(intent)
                    # Only lock-held snapshots seed the cache; refresh for this batch alone.
                    current, compacted_requests = cached, set()
                    try:
                        info = os.stat("gitops.jsonl", dir_fd=directory, follow_symlinks=False)
                    except FileNotFoundError:
                        raise GitOpsError("journal_io") from None
                    if unclaimed or (info.st_dev, info.st_ino, info.st_size) != generation:
                        with self._transaction(directory_fd=directory) as (fd, _, read, _):
                            if fd is None:
                                raise GitOpsError("journal_io")
                            current = {row["request_id"]: row for row in _pending(read.rows, lane)}
                            compacted_requests = {row["request_id"] for row in read.rows
                                                  if row["kind"] == "tombstone"}
                    for intent in unclaimed:
                        live = current.get(intent["request_id"])
                        self._flight_update(intent, live is not None and _same_intent(live, intent))
                    observations = []
                    for intent, effect in claimed:
                        live = current.get(intent["request_id"])
                        if live is None or not _same_intent(live, intent):
                            self._flight_update(intent, False)
                            if intent["request_id"] in compacted_requests:
                                self._retire_completed_claim(directory, intent, effect)
                            continue
                        try:
                            row = self._observe_once(effect, intent, observe)
                        except GitOpsError as error:
                            if error.code not in ("checkpoint_stuck", "journal_io", "invalid_result"):
                                raise
                            if error.code == "checkpoint_stuck" or _checkpoint_unreplayable(effect, intent):
                                blocked.append(intent["request_id"])
                            else:
                                deferred = deferred or error
                            continue
                        if row is not None:
                            observations.append(row)
                    if not observations:
                        continue
                    cached, generation, recorded = self._record_observations(directory, lane, observations)
                    results.extend(recorded)
            if blocked:
                error = GitOpsError("checkpoint_stuck", request_ids=blocked)
                error.results = results
                raise error
            if deferred is not None:
                deferred.results = results
                raise deferred
        return results
