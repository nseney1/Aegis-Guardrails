"""Intent/result journal for model-free git custody (Git ADR G3, D13, AC18).

The caller supplies the trusted absolute git common directory, outside role-writable
roots. This module runs neither git nor gh nor an effect callback. A *new*, durable
IntentReceipt permits the caller's one attempt; an existing receipt never does.
Every process that may perform the effect must hold the receipt's effect-lock
descriptor; pass receipt.inheritable_fds() as subprocess pass_fds. Each process
closes its copy after its effect has stopped. After a lost reply, reconcile uses
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
import re
import stat
import threading

try:
    import fcntl
except ImportError:
    fcntl = None

from aegis_core import storage
from aegis_core.errors import LockTimeoutError, PathTraversalError
from aegis_core.storage import ConfinedFileError, confined_file
from aegis_core.primitives import parse_utc, sanitize_display, utc_stamp
from aegis_core.redaction import (CANDIDATE_TOKEN_RE, is_high_entropy_secret,
                                  redact_command_secrets)

__all__ = ["GitOpsJournal", "GitOpsError", "IntentReceipt", "JournalRead", "Observation",
           "OPS", "REFUSALS", "display_row", "descriptor_supported"]

OPS = ("worktree_add", "worktree_remove", "commit", "ref_update", "push", "pr_open",
       "pr_ready", "pr_close", "merge", "run_cancel", "lease_claim", "lease_renew",
       "lease_transfer", "lease_release")
MAX_JOURNAL_BYTES = 8 * 1024 * 1024
MAX_ROW_BYTES = 65536
MAX_RECORD_LINES = 32768
RECONCILE_BATCH_SIZE = 8
FINAL_RECORD_ATTEMPTS = 3
MAX_CHECKPOINT_REQUEST_IDS = 16
DISPLAY_LIMIT = 256
REFUSALS = {
    "invalid_intent": "invalid git operation intent",
    "invalid_result": "invalid git operation result",
    "invalid_request": "invalid git operation request identifier",
    "request_conflict": "git operation request already reserved with different inputs",
    "result_conflict": "git operation already has a different terminal result",
    "missing_intent": "git operation result requires a durable intent",
    "unsupported_platform": "descriptor-relative git operation journal unavailable",
    "unsafe_journal": "unsafe git operation journal path or file; use the trusted root's realpath spelling",
    "journal_too_large": "git operation journal size limit exceeded; ask the owner to archive closed history",
    "journal_capacity": "git operation result capacity reserved; reconcile pending intents and ask the owner to archive closed history",
    "journal_busy": "git operation journal lock timed out",
    "effect_busy": "git operation effect is still owned; wait for its result or reconcile after its owner exits",
    "journal_io": "git operation journal I/O failed; observe before any further action",
    "checkpoint_stuck": "git operation observation checkpoints require owner recovery",
}
_RESULT_ACTIONS = {
    "observation": "correct the result status and observation to match the durable intent; then record the result",
    "receipt": "provide the matching active receipt for this request; then record the observed result",
    "descriptor": "provide the inherited effect-lock descriptor for this request; then record the observed result",
    "ownership": "supply one ownership argument: a matching receipt or an inherited effect-lock descriptor; then record the observed result",
    "capacity": "inspect the pending intent and restore journal capacity or storage; reconcile by observation before any further action",
}
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_LANE = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}\Z")
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_STATE_TEXT = {"ref", "head", "base", "state", "path", "owner", "branch", "lease_id", "oid"}
_STATE_NUMBER = {"number", "run_id", "pr_number", "generation"}
_BASE_KEYS = {"v", "kind", "op", "lane", "request_id", "expected_old", "expected_new",
              "actor", "created_at", "ts"}
_OWNERS = {}
_OWNER_GUARD = threading.RLock()


class GitOpsError(ValueError):
    """Documented refusal, safe to render verbatim."""

    def __init__(self, code, root=None, *, result_cause="observation", request_ids=()):
        super().__init__(REFUSALS[code])
        self.code = code
        self.next_action = {"actor": "owner", "command": REFUSALS[code]}
        if code == "invalid_result":
            self.next_action["command"] = _RESULT_ACTIONS[result_cause]
        elif code == "journal_io":
            self.next_action["command"] = _RESULT_ACTIONS["capacity"]
        elif code == "unsupported_platform":
            self.next_action["command"] = "use a supported descriptor platform and a local filesystem for the git common dir"
        elif code == "result_conflict":
            self.next_action["command"] = ("read the durable result for this request; never retry the effect"
                                           if result_cause == "durable" else
                                           "reconcile the lane to publish the saved observation, then read its result")
        elif code == "checkpoint_stuck":
            self.next_action["command"] = "owner reads external state for each listed request, then calls record_result(request_id, status, observed) to resolve it; never retry the effect; at most 16 request IDs are listed, reconcile again after resolving them"
            self.next_action["request_ids"] = [_clean(request)[:DISPLAY_LIMIT] for request in request_ids[:MAX_CHECKPOINT_REQUEST_IDS]]
            self.next_action["request_ids_truncated"] = len(request_ids) > MAX_CHECKPOINT_REQUEST_IDS
        if code == "unsafe_journal" and root is not None:
            try:
                canonical = sanitize_display(os.path.realpath(root), max_len=None)
                self.next_action["path"] = sanitize_display(redact_command_secrets(canonical), max_len=DISPLAY_LIMIT)
            except (OSError, ValueError):
                self.next_action["path"] = "[canonical root unavailable]"


@dataclass(frozen=True)
class IntentReceipt:
    """One attempt's ownership, independent of the GitOpsJournal instance.

    Every process that may perform the effect must hold this descriptor. Pass
    inheritable_fds() to subprocess pass_fds; a child may finish with
    record_result(effect_fd=fd), then must close its inherited copy. The parent
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
        with _OWNER_GUARD:
            held = _OWNERS.get(self._key)
            if (not self.created or held is None or held[1] != os.getpid()
                    or held[2] is not self._token):
                raise GitOpsError("effect_busy")
            return (held[0],)

    def release(self):
        with _refusals(None):
            _release_owner(self._key, self._token)

    close = release

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


@dataclass(frozen=True)
class JournalRead:
    rows: list
    skipped: int = 0
    torn_tail: bool = False


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


def _try_effect(directory, request_id, pinned_fd=None, *, new_intent=False):
    name = "gitops-effect-" + hashlib.sha256(request_id.encode("ascii")).hexdigest() + ".lock"
    if new_intent:
        fd = _open_receipt_lock(directory, name)
    else:
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
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
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return None
        except OSError as error:
            if error.errno in (errno.EBADF, errno.ENOLCK):
                raise GitOpsError("unsupported_platform") from None
            raise
        os.fchmod(fd, 0o600)
        os.fsync(directory)
        if new_intent:
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
    # Only record_intent reaches this, under the journal lock after proving
    # there is no existing intent and while holding the read-only effect flock.
    # A retired request's saved checkpoint must not become authoritative for
    # the new intent; the writable descriptor must be the same inode.
    info = os.fstat(effect)
    if info.st_size == 0:
        return
    writable = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        fresh = os.fstat(writable)
        if (fresh.st_dev, fresh.st_ino) != (info.st_dev, info.st_ino):
            raise GitOpsError("unsafe_journal")
        os.ftruncate(writable, 0)
        os.fsync(writable)
    finally:
        os.close(writable)


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


def _clean(text):
    canonical = sanitize_display(text, max_len=None)
    redacted = redact_command_secrets(canonical)
    return CANDIDATE_TOKEN_RE.sub(
        lambda match: "[REDACTED]" if is_high_entropy_secret(match.group()) else match.group(), redacted)


def _text(value, limit, *, check_secrets=True):
    return (type(value) is str and 0 < len(value) <= limit
            and all(char.isprintable() for char in value)
            and (not check_secrets or redact_command_secrets(value) == value))


def _identifier(value, pattern=_ID):
    return type(value) is str and 0 < len(value) <= 128 and pattern.fullmatch(value) is not None


def _state(value, *, check_secrets=True):
    if value is None:
        return None
    if type(value) is str and len(value) in (40, 64) and _OID.fullmatch(value):
        return value
    if type(value) is not dict or not 1 <= len(value) <= 12:
        raise ValueError("state shape")
    result, size = {}, 0
    for key, child in value.items():
        if type(key) is not str or len(key) > 16:
            raise ValueError("state field")
        if key in _STATE_TEXT:
            if not _text(child, 1024, check_secrets=check_secrets):
                raise ValueError("state text")
            size += len(child)
        elif key in _STATE_NUMBER:
            if type(child) is not int or not 0 <= child <= 2 ** 63 - 1:
                raise ValueError("state number")
        elif key == "exists":
            if type(child) is not bool:
                raise ValueError("state presence")
        else:
            raise ValueError("unknown state field")
        if size > 4096:
            raise ValueError("state size")
        result[key] = child
    return result


def display_row(value, _depth=0):
    """Canonicalize, redact, then truncate every string, including dictionary keys.

    Over-limit containers/fields are replaced by a fixed marker, never sliced
    before redaction. This is display only, never an observation or identity key.
    """
    if _depth > 4:
        return "[oversized]"
    if type(value) is str:
        if len(value) > MAX_ROW_BYTES:
            return "[oversized]"
        return sanitize_display(_clean(value), max_len=DISPLAY_LIMIT)
    if type(value) is dict:
        if len(value) > 32:
            return "[oversized]"
        return {display_row(key, _depth + 1): display_row(child, _depth + 1)
                for key, child in value.items() if type(key) is str}
    if value is None or type(value) in (bool, int):
        return value
    return "[invalid]"


def _binding(op, lane, request_id, expected_old, expected_new, actor, *, check_secrets=True):
    if (type(op) is not str or op not in OPS or not _identifier(lane, _LANE)
            or not _identifier(request_id) or not _identifier(actor)):
        raise ValueError("intent fields")
    old = _state(expected_old, check_secrets=check_secrets)
    new = _state(expected_new, check_secrets=check_secrets)
    if old == new:
        raise ValueError("indeterminate expected transition")
    return old, new


def _intent(op, lane, request_id, expected_old, expected_new, actor):
    try:
        old, new = _binding(op, lane, request_id, expected_old, expected_new, actor)
    except ValueError:
        raise GitOpsError("invalid_intent") from None
    stamp = utc_stamp()
    return dict(v=1, kind="intent", op=op, lane=lane, request_id=request_id,
                expected_old=old, expected_new=new, actor=actor, created_at=stamp, ts=stamp)


def _result_state(intent, status, observed, *, check_secrets=True):
    if type(status) is not str or status not in ("done", "not_applied", "unknown"):
        raise ValueError("status")
    observed = _state(observed, check_secrets=check_secrets)
    if ((status == "done" and observed != intent["expected_new"])
            or (status == "not_applied" and observed != intent["expected_old"])):
        raise ValueError("contradictory observation")
    return observed


def _result(intent, status, observed):
    try:
        observed = _result_state(intent, status, observed)
    except ValueError:
        raise GitOpsError("invalid_result", result_cause="observation") from None
    return dict(intent, kind="result", status=status, observed=observed,
                ts=max(utc_stamp(), intent["ts"]))


def _pairs(pairs):
    value = {}
    for key, child in pairs:
        if key in value:
            raise ValueError("duplicate field")
        value[key] = child
    return value


def _valid_row(row):
    if type(row) is not dict or type(row.get("v")) is not int or row["v"] != 1:
        return False
    keys = _BASE_KEYS if row.get("kind") == "intent" else _BASE_KEYS | {"status", "observed"}
    if row.keys() != keys or row["kind"] not in ("intent", "result"):
        return False
    try:
        _binding(*(row[key] for key in ("op", "lane", "request_id", "expected_old", "expected_new", "actor")),
                 check_secrets=False)
        if any(not _text(row[key], 32, check_secrets=False) or parse_utc(row[key]) is None
               for key in ("ts", "created_at")):
            return False
        if row["ts"] < row["created_at"]:
            return False
        if row["kind"] == "result":
            _result_state(row, row["status"], row["observed"], check_secrets=False)
        return True
    except ValueError:
        return False


def _same_intent(left, right):
    return all(left[key] == right[key] for key in _BASE_KEYS - {"kind", "ts"})


def _parse(data):
    if data.count(b"\n") > MAX_RECORD_LINES:
        raise GitOpsError("journal_too_large")
    rows, skipped, intents, results = [], 0, {}, set()
    lines = data.split(b"\n")
    torn = bool(data and not data.endswith(b"\n"))
    for index, raw in enumerate(lines):
        if index == len(lines) - 1 and not raw:
            break
        try:
            # A complete JSON object without its newline is still uncommitted.
            if len(raw) > MAX_ROW_BYTES or (torn and index == len(lines) - 1):
                raise ValueError("line size or torn tail")
            row = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
            if not _valid_row(row):
                raise ValueError("schema")
            request = row["request_id"]
            if row["kind"] == "intent":
                if request in intents:
                    raise ValueError("duplicate intent")
                intents[request] = row
            elif request not in intents or request in results or not _same_intent(row, intents[request]):
                raise ValueError("orphan or conflicting result")
            else:
                results.add(request)
            rows.append(row)
        except (ValueError, UnicodeError, RecursionError):
            skipped += 1
    return JournalRead(rows, skipped, torn)


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


def _encoded(row):
    return json.dumps(row, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _maximum_observation_bytes():
    """Measure the largest legal state, including ensure_ascii surrogate pairs.

    All four 19-digit numbers and false occupy more bytes than another text
    key at the fixed 4096-character budget. Fill the remaining seven slots
    with the longest text keys. Ref and oid are the two shortest keys.
    """
    maximum = {key: "\U00010000" * (1024 if key in ("branch", "lease_id", "head")
                                    else 1021 if key == "base" else 1)
               for key in _STATE_TEXT - {"oid", "ref"}}
    maximum.update({key: 2 ** 63 - 1 for key in _STATE_NUMBER})
    maximum["exists"] = False
    return len(_encoded(maximum))


MAX_OBSERVATION_BYTES = _maximum_observation_bytes()


def _terminal_bytes(intent):
    """Measure this intent's largest terminal row, including duplicated state.

    Substitute the measured maximum observation for JSON null without allocating
    that state for every pending intent. Bound observations also participate:
    not_applied has a longer status than unknown. Timestamps retain the fixed
    utc_stamp width (or a longer timestamp already present in stored intent).
    """
    unknown = len(_encoded(dict(intent, kind="result", status="unknown", observed=None)))
    return max(unknown - len(b"null") + MAX_OBSERVATION_BYTES,
               *(len(_encoded(dict(intent, kind="result", status=status, observed=state)))
                 for status, state in (("done", intent["expected_new"]),
                                       ("not_applied", intent["expected_old"]))))


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
    completed = {row["request_id"] for row in rows if row["kind"] == "result"}
    return [row for row in rows if row["kind"] == "intent" and row["request_id"] not in completed
            and (lane is None or row["lane"] == lane)]


def _committed_generation(fd, data, read, *, appended=0):
    """Key a lock-held snapshot and committed appends; never cache a torn read."""
    if fd is None:
        raise GitOpsError("journal_io")
    if read.torn_tail:
        return None
    info = os.fstat(fd)
    return info.st_dev, info.st_ino, data.rfind(b"\n") + 1 + appended


def _observation_checkpoint(effect, intent, *, result=None, reset=False, reserve=True, flush=True):
    """Reserve one observation durably in its already-locked effect file.

    Empty means unobserved; ! followed by a newline reserves the callback. A
    complete result after that marker can be replayed into the journal. A torn
    checkpoint refuses closed: even permanent storage failure or process death
    after observation must never authorize another observation. An invalid or
    unavailable callback response clears its reservation for a later pass, as
    does a failed reservation before the callback has run (best effort).
    The owner UID is trusted, just as for the journal and effect-lock inode.
    """
    if reset:
        os.ftruncate(effect, 0)
        os.fsync(effect)
        return None
    if result is not None:
        _append(effect, result, 2)
        return result
    size = os.fstat(effect).st_size
    if size == 0:
        if not reserve:
            return None
        # Admission reserved this capacity. Recheck before reserving/observing
        # in case a caller changed the configured row bound since admission.
        if _terminal_bytes(intent) > MAX_ROW_BYTES:
            raise GitOpsError("invalid_result", result_cause="capacity")
        os.lseek(effect, 0, os.SEEK_SET)
        try:
            if os.write(effect, b"!\n") != 2:
                raise GitOpsError("journal_io")
            os.fsync(effect)
        except (OSError, GitOpsError):
            # Observe has not run. Best-effort rollback restores liveness; a
            # crash or failed cleanup still leaves a fail-closed reservation.
            try:
                os.ftruncate(effect, 0)
                os.fsync(effect)
            except OSError:
                pass
            raise
        return None
    if not 2 < size <= MAX_ROW_BYTES + 3:
        raise GitOpsError("checkpoint_stuck")
    os.lseek(effect, 0, os.SEEK_SET)
    data = bytearray()
    while len(data) < size:
        chunk = os.read(effect, min(8192, size - len(data)))
        if not chunk:
            raise GitOpsError("checkpoint_stuck")
        data.extend(chunk)
    try:
        if not data.startswith(b"!\n") or not data.endswith(b"\n") or data.count(b"\n") != 2:
            raise ValueError("checkpoint framing")
        row = json.loads(data[2:-1].decode("ascii"), object_pairs_hook=_pairs)
        if not _valid_row(row) or row["kind"] != "result" or not _same_intent(row, intent):
            raise ValueError("checkpoint binding")
    except (ValueError, UnicodeError, RecursionError):
        raise GitOpsError("checkpoint_stuck") from None
    # A previous writer may have failed its fsync after writing a complete row.
    if flush:
        os.fsync(effect)
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
                            fd = os.open("gitops.jsonl", os.O_RDWR | os.O_CREAT |
                                         os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
                        else:
                            fd = os.open("gitops.jsonl", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                         dir_fd=directory)
                    except FileNotFoundError:
                        if write:
                            raise
                        yield None, b"", JournalRead([]), directory
                        return
                    try:
                        info = os.fstat(fd)
                        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                                or info.st_uid != os.geteuid()):
                            raise GitOpsError("unsafe_journal")
                        if write:
                            os.fchmod(fd, 0o600)
                            os.fsync(directory)
                        data = _read_fd(fd)
                        if write:
                            data = _quarantine(fd, data)
                        yield fd, data, _parse(data), directory
                    finally:
                        os.close(fd)

    def read(self):
        """Bounded strict-schema read; malformed/torn rows are skipped and counted."""
        with self._transaction() as (_, _, read, _):
            return read

    def open_intents(self, lane=None):
        """Intents with no result. Unknown results stay terminal and are not retried."""
        if lane is not None and not _identifier(lane, _LANE):
            raise GitOpsError("invalid_request")
        return _pending(self.read().rows, lane)

    def record_intent(self, *, op, lane, request_id, expected_old, expected_new, actor):
        row = _intent(op, lane, request_id, expected_old, expected_new, actor)
        encoded, terminal_bytes = _encoded(row), _terminal_bytes(row)
        if max(len(encoded), terminal_bytes) > MAX_ROW_BYTES:
            raise GitOpsError("invalid_intent")
        with _receipt_guard() as granted, self._transaction(write=True) as (fd, data, read, directory):
            for old in read.rows:
                if old["kind"] == "intent" and old["request_id"] == request_id:
                    if any(old[key] != row[key] for key in _BASE_KEYS - {"ts", "created_at"}):
                        raise GitOpsError("request_conflict")
                    return IntentReceipt(old, False)
            pending = _pending(read.rows)
            outstanding = len(pending) + 1
            # Include each terminal newline and one durable quarantine marker.
            reserved = terminal_bytes + 3 + sum(_terminal_bytes(old) + 3 for old in pending)
            if (len(data) + len(encoded) + 1 + reserved > MAX_JOURNAL_BYTES
                    or data.count(b"\n") + 1 + 2 * outstanding > MAX_RECORD_LINES):
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
                           if row["kind"] == "intent" and row["request_id"] == request_id), None)
            if intent is None:
                raise GitOpsError("missing_intent")
            key = _effect_key(directory, request_id)
            if receipt is not None and (not receipt.created or receipt._key != key):
                raise GitOpsError("invalid_result", result_cause="receipt")
            row = _result(intent, status, observed)
            for old in read.rows:
                if old["kind"] == "result" and old["request_id"] == request_id:
                    if old["status"] != status or old["observed"] != row["observed"]:
                        raise GitOpsError("result_conflict", result_cause="durable")
                    os.fsync(fd)
                    _release_owner(key)
                    return old
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
                pending = _pending(read.rows, lane)
                cached = {row["request_id"]: row for row in pending}
                generation = _committed_generation(fd, data, read)
            pending.sort(key=lambda row: row["request_id"])
            for start in range(0, len(pending), RECONCILE_BATCH_SIZE):
                with ExitStack() as effects:
                    claimed = []
                    # Claim the whole bounded batch before observing. Writers
                    # probe effects nonblockingly even under the journal lock.
                    for intent in pending[start:start + RECONCILE_BATCH_SIZE]:
                        effect = _try_effect(directory, intent["request_id"])
                        if effect is not None:
                            effects.callback(os.close, effect)
                            claimed.append((intent, effect))
                    if not claimed:
                        continue
                    # Only lock-held snapshots seed the cache; refresh for this batch alone.
                    current = cached
                    try:
                        info = os.stat("gitops.jsonl", dir_fd=directory, follow_symlinks=False)
                    except FileNotFoundError:
                        raise GitOpsError("journal_io") from None
                    if (info.st_dev, info.st_ino, info.st_size) != generation:
                        with self._transaction(directory_fd=directory) as (fd, _, read, _):
                            if fd is None:
                                raise GitOpsError("journal_io")
                            current = {row["request_id"]: row for row in _pending(read.rows, lane)}
                    observations = []
                    for intent, effect in claimed:
                        live = current.get(intent["request_id"])
                        if live is None or not _same_intent(live, intent):
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
                    for attempt in range(FINAL_RECORD_ATTEMPTS):
                        try:
                            with _refusals(self.common_dir), self._transaction(
                                    write=True, directory_fd=directory) as (fd, data, read, _):
                                completed = {row["request_id"]: row for row in read.rows
                                             if row["kind"] == "result"}
                                size, recorded = len(data), []
                                for row in observations:
                                    old = completed.get(row["request_id"])
                                    if old is None:
                                        size = _append(fd, row, size)
                                    elif (not _same_intent(old, row) or old["status"] != row["status"]
                                          or old["observed"] != row["observed"]):
                                        raise GitOpsError("result_conflict", result_cause="durable")
                                    recorded.append(old if old is not None else row)
                                os.fsync(fd)
                                next_generation = _committed_generation(fd, data, read, appended=size - len(data))
                                next_cached = {row["request_id"]: row for row in
                                               _pending(read.rows + recorded, lane)}
                            cached, generation = next_cached, next_generation
                            results.extend(recorded)
                            break
                        except GitOpsError as error:
                            if (error.code not in ("journal_busy", "journal_io")
                                    or attempt + 1 == FINAL_RECORD_ATTEMPTS):
                                raise
            if blocked:
                raise GitOpsError("checkpoint_stuck", request_ids=blocked)
            if deferred is not None:
                raise deferred
        return results
