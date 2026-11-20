"""Workspace ledger and lease advice under held no-follow descriptors.
Observers are injected; readers retain the legacy v1/v2 encoding and values.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import os
import errno
import stat
from threading import Lock, local
import uuid
import weakref
from pathlib import Path
import re
import time

from aegis_core.team_mailbox_primitives import ( GIT_ID, MAX_BYTES, MAX_RECORDS, MAX_WRITERS, SHA256, SLUG, MailboxRefusal,
    bounded_tree, encoded, integer, matching, parse_time, strict_json, strings, text, )
from aegis_core.team_mailbox_store import descriptor_supported
from aegis_core import kernel_identity as _kernel
from aegis_core.team_workspace_display import ( WorkspaceRefusal, require, refusals, queue_facts as _queue_facts,
    render_report as _render_report, display_response as _display_response, )

@refusals
def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

EVENT_SCHEMA = "aegis.hierarchy-workspace-event/v1"
SUPERSEDE_EVENT_SCHEMA = "aegis.hierarchy-workspace-event/v2"
REPLAY_SCHEMAS = frozenset((EVENT_SCHEMA, SUPERSEDE_EVENT_SCHEMA))
MAX_HEAVY = 3
MAX_HEAVY_TESTS = 1
DEFAULT_HEAVY_TESTS = 1
MAX_PRIORITY = 1000
MAX_VIEW_ROWS = 100
MAX_EVIDENCE_BYTES = 67108864
KINDS = ("writer", "heavy", "heavy-tests")
INITIATIVE_STATES = {"active", "paused", "done"}
EVENT_NAME = re.compile(r"(\d{8})\.json")
_FIELD_LIMIT = MAX_RECORDS

__all__ = [ 'timestamp', 'EVENT_SCHEMA', 'SUPERSEDE_EVENT_SCHEMA', 'REPLAY_SCHEMAS', 'MAX_HEAVY', 'MAX_HEAVY_TESTS',
    'DEFAULT_HEAVY_TESTS', 'MAX_PRIORITY', 'MAX_VIEW_ROWS', 'MAX_EVIDENCE_BYTES', 'KINDS', 'INITIATIVE_STATES',
    'EVENT_NAME', 'fields', 'absolute', 'evidence_reference', 'verify_evidence', 'validate_initiative',
    'validate_lists', 'Ledger', 'apply_init', 'LIMIT_FIELDS', 'apply_set_limits', 'require_unclaimed_lanes',
    'apply_register', 'apply_update', 'apply_request', 'apply_withdraw', 'apply_grant', 'apply_release',
    'apply_merge', 'apply_clear', 'APPLY', 'refusal_context', 'WorkspaceStore', 'capacity_view',
    'request_view', 'initiative_view', 'grant_next', 'check_paths', 'check_initiative_paths', 'check_delivery',
    'mailbox_facts', 'queue_facts', 'report', 'report_text', 'observe', ]

def _record(value):
    require(type(value) is dict)
    return value

def _key(value):
    """Validate JSON-shaped dictionary identities without attempting hash()."""
    if type(value) is tuple:
        for item in value:
            _key(item)
    else:
        require(type(value) in (str, int, float, bool, type(None)))
    return value

def _rows(mapping):
    for row in _record(mapping).values():
        yield _record(row)

def _ledger(value):
    for name in ("initiatives", "requests", "granted_counts"):
        _record(getattr(value, name, None))
    require(isinstance(getattr(value, "seq", None), int))
    require(type(getattr(value, "open_holders", None)) is set)
    require(all(callable(getattr(value, name, None)) for name in ("initiative", "request", "held", "unresolved")))
    limits = getattr(value, "limits", None)
    require(limits is None or type(limits) is dict)
    for name in KINDS:
        require(isinstance(value.granted_counts.get(name), (int, float)))
        require(limits is None or isinstance(limits.get(name), (int, float)))

def _names(value):
    require(type(value) in (str, list, tuple, dict, set, frozenset) and len(value) <= _FIELD_LIMIT)
    require(all(type(name) is str for name in value))
    return set(value)

def _order(ledger, request):
    initiative = _record(ledger.initiatives[_key(request["initiative"])])
    require(isinstance(initiative["priority"], (int, float)) and isinstance(request["seq"], (int, float)))
    return initiative["priority"], request["seq"]

def _ports(value):
    require(type(value) in (tuple, list) and len(value) == 3)
    _, team, paths = value
    require(callable(getattr(team, "read_leases", None)))
    require(all(callable(getattr(paths, name, None)) for name in ("claim_paths", "stored_paths", "overlap", "PathSet")))
    error = getattr(paths, "LeasePathError", None)
    require(isinstance(error, type) and issubclass(error, Exception))
    return team, paths

@refusals
def fields(value, required, optional=()):
    """Bound and validate the legacy fields without echoing unexpected keys."""
    bounded_tree(value)
    require(isinstance(value, dict))
    require(_names(required) <= value.keys())
    require(value.keys() <= _names(required) | _names(optional))

@refusals
def absolute(value, label):
    _path(value)
    return value

@refusals
def evidence_reference(value):
    fields(value, {"path", "sha256"})
    matching(value["sha256"], SHA256, "evidence sha256")
    absolute(value["path"], "evidence path")

@refusals
def verify_evidence(value):
    """Read bounded regular evidence beneath its descriptor-bound owner directory."""
    evidence_reference(value)
    path = _path(value["path"])
    try:
        with _Files(path.parent, coordination=False) as storage:
            raw = storage.read(path, limit=MAX_EVIDENCE_BYTES)
    except _Changed:
        raise WorkspaceRefusal("invalid_record") from None
    require(hashlib.sha256(raw).hexdigest() == value["sha256"], reason="evidence_mismatch")

@refusals
def validate_initiative(data):
    fields(data, {"id", "project", "repository", "priority", "target_branch"},
           {"touched_paths", "blocked_by", "checkouts", "lanes", "mailbox_root", "delivery_dir", "source"})
    if "source" in data:
        text(data["source"], "source")
    matching(data["id"], SLUG, "initiative id")
    matching(data["project"], SLUG, "project")
    text(data["repository"], "repository", 256)
    integer(data["priority"], "priority", maximum=MAX_PRIORITY)
    text(data["target_branch"], "target_branch", 256)
    validate_lists(data)
    for name in ("mailbox_root", "delivery_dir"):
        if name in data:
            absolute(data[name], name)

@refusals
def validate_lists(data):
    _record(data)
    if "touched_paths" in data:
        strings(data["touched_paths"], "touched paths")
    if "blocked_by" in data:
        strings(data["blocked_by"], "blocked_by")
    if "lanes" in data:
        strings(data["lanes"], "lanes")
    if "checkouts" in data:
        strings(data["checkouts"], "checkouts")
        for checkout in data["checkouts"]:
            absolute(checkout, "checkout")

class Ledger:
    """State rebuilt by replaying immutable events. Every rule runs on replay too, so a bad edit fails loudly."""

    @refusals
    def __init__(self):
        self.seq = 0
        self.limits = None
        self.initiatives = {}
        self.requests = {}
        self.open_holders = set()
        self.granted_counts = dict.fromkeys(KINDS, 0)

    @refusals
    def initiative(self, identifier):
        _key(identifier)
        require(identifier in self.initiatives)
        return self.initiatives[identifier]

    @refusals
    def request(self, identifier):
        _key(identifier)
        require(identifier in self.requests)
        return self.requests[identifier]

    @refusals
    def held(self, kind):
        require(type(kind) is str)
        return [r for r in _rows(self.requests) if r["kind"] == kind and r["state"] == "granted"]

    @refusals
    def unresolved(self, initiative):
        _record(initiative)
        strings(initiative["blocked_by"], "blockers")
        return [b for b in initiative["blocked_by"] if b not in self.initiatives or _record(self.initiatives[b])["state"] != "done"]

    @refusals
    def apply(self, event):
        bounded_tree(event)
        fields(event, {"schema", "seq", "at", "kind", "data"})
        snapshot = deepcopy(self.__dict__)
        try:
            self._apply(event)
        except BaseException:
            self.__dict__.clear()
            self.__dict__.update(snapshot)
            raise

    def _apply(self, event):
        _key(event["kind"])
        require(event["kind"] in APPLY)
        require(event["kind"] == "init" or self.limits is not None)
        APPLY[event["kind"]](self, event["data"], event)
        self.seq = event["seq"]

@refusals
def apply_init(ledger, data, _event):
    _ledger(ledger)
    fields(data, {"writer_limit", "heavy_limit"}, {"heavy_tests_limit"})
    integer(data["writer_limit"], "writer_limit", maximum=MAX_WRITERS)
    integer(data["heavy_limit"], "heavy_limit", maximum=MAX_HEAVY)
    heavy_tests = integer(data.get("heavy_tests_limit", DEFAULT_HEAVY_TESTS), "heavy_tests_limit", maximum=MAX_HEAVY_TESTS)
    require(ledger.limits is None)
    ledger.limits = {"writer": data["writer_limit"], "heavy": data["heavy_limit"], "heavy-tests": heavy_tests}

LIMIT_FIELDS = {"writer_limit": ("writer", MAX_WRITERS), "heavy_limit": ("heavy", MAX_HEAVY),
                "heavy_tests_limit": ("heavy-tests", MAX_HEAVY_TESTS)}

@refusals
def apply_set_limits(ledger, data, _event):
    _ledger(ledger)
    """A reviewed change to an initialized store's limits. Lowering below the work already granted would
    leave the replayed ledger over capacity, and accepted work is never preempted, so that is refused."""
    fields(data, {"source"}, set(LIMIT_FIELDS))
    text(data["source"], "source")
    changes = sorted(data.keys() - {"source"})
    require(changes)
    for name in changes:
        kind, ceiling = LIMIT_FIELDS[name]
        integer(data[name], name, maximum=ceiling)
        held = ledger.granted_counts[kind]
        require(data[name] >= held)
    for name in changes:
        ledger.limits[LIMIT_FIELDS[name][0]] = data[name]

@refusals
def require_unclaimed_lanes(ledger, repository, lanes, identifier):
    _ledger(ledger)
    strings(lanes, "lanes")
    for other in _rows(ledger.initiatives):
        strings(other["lanes"], "lanes")
        if other["id"] != identifier and other["repository"] == repository:
            taken = sorted(set(lanes) & set(other["lanes"]))
            require(not taken)

@refusals
def apply_register(ledger, data, event):
    _ledger(ledger)
    _record(event)
    validate_initiative(data)
    require(data["id"] not in ledger.initiatives)
    require_unclaimed_lanes(ledger, data["repository"], data.get("lanes", []), data["id"])
    ledger.initiatives[data["id"]] = {
        "touched_paths": [], "blocked_by": [], "checkouts": [], "lanes": [], **data, "state": "active",
        "base_moved": None, "registered_at": event["at"]}

@refusals
def apply_update(ledger, data, _event):
    _ledger(ledger)
    fields(data, {"initiative", "source"}, {"priority", "state", "blocked_by", "touched_paths", "checkouts", "lanes"})
    initiative = ledger.initiative(data["initiative"])
    text(data["source"], "source")
    validate_lists(data)
    require_unclaimed_lanes(ledger, initiative["repository"], data.get("lanes", []), initiative["id"])
    if "priority" in data:
        integer(data["priority"], "priority", maximum=MAX_PRIORITY)
    if "state" in data:
        require(isinstance(data["state"], str) and data["state"] in INITIATIVE_STATES)
        if data["state"] == "done":
            require(not any(r["initiative"] == initiative["id"] and r["state"] in ("queued", "granted")
                            for r in _rows(ledger.requests)))
    initiative.update({key: value for key, value in data.items() if key not in ("initiative", "source")})

@refusals
def apply_request(ledger, data, event):
    _ledger(ledger)
    _record(event)
    fields(data, {"request_id", "initiative", "kind", "holder"}, {"reference", "supersedes"})
    initiative = ledger.initiative(data["initiative"])
    require(initiative["state"] == "active")
    require(isinstance(data["kind"], str) and data["kind"] in KINDS)
    text(data["holder"], "holder", 256)
    if "reference" in data:
        text(data["reference"], "reference")
    require(_key(data["request_id"]) not in ledger.requests)
    previous = None
    if "supersedes" in data:
        identifier = text(data["supersedes"], "supersedes", 12)
        require(re.fullmatch(r"req-[0-9]{8}", identifier) is not None)
        require(event["schema"] == SUPERSEDE_EVENT_SCHEMA)
        require(identifier in ledger.requests)
        previous = ledger.requests[identifier]
        require(all(previous[key] == data[key] for key in ("initiative", "holder", "kind")))
        require(previous["state"] != "granted")
        require(previous["state"] == "queued")
    holder = (data["kind"], data["holder"])
    require(previous is not None or holder not in ledger.open_holders)
    replacement = {**data, "state": "queued", "seq": previous["seq"] if previous is not None else event["seq"],
                   "requested_at": event["at"], "reserved_repository": initiative["repository"],
                   "reserved_paths": list(initiative["touched_paths"])}
    if previous is not None:
        previous.update(state="withdrawn", closed_at=event["at"], superseded_by=data["request_id"])
    ledger.requests[data["request_id"]] = replacement
    ledger.open_holders.add(holder)

@refusals
def apply_withdraw(ledger, data, event):
    _ledger(ledger)
    _record(event)
    fields(data, {"request_id", "source"})
    text(data["source"], "source")
    request = ledger.request(data["request_id"])
    require(request["state"] == "queued")
    request.update(state="withdrawn", closed_at=event["at"])
    ledger.open_holders.remove((request["kind"], request["holder"]))

@refusals
def apply_grant(ledger, data, event):
    _ledger(ledger)
    _record(event)
    fields(data, {"request_id"})
    request = ledger.request(data["request_id"])
    require(request["state"] == "queued")
    require(ledger.granted_counts[request["kind"]] < ledger.limits[request["kind"]], reason="capacity_full")
    request.update(state="granted", granted_at=event["at"])
    ledger.granted_counts[request["kind"]] += 1

@refusals
def apply_release(ledger, data, event):
    _ledger(ledger)
    _record(event)
    fields(data, {"request_id", "evidence"})
    evidence_reference(data["evidence"])
    request = ledger.request(data["request_id"])
    require(request["state"] == "granted")
    request.update(state="released", closed_at=event["at"], evidence=data["evidence"])
    ledger.open_holders.remove((request["kind"], request["holder"]))
    ledger.granted_counts[request["kind"]] -= 1

@refusals
def apply_merge(ledger, data, event):
    _ledger(ledger)
    _record(event)
    fields(data, {"repository", "branch", "commit", "source"}, {"initiative"})
    text(data["repository"], "repository", 256)
    text(data["branch"], "branch", 256)
    matching(data["commit"], GIT_ID, "commit")
    text(data["source"], "source")
    if "initiative" in data:
        ledger.initiative(data["initiative"])
    for initiative in _rows(ledger.initiatives):
        if (initiative["repository"] == data["repository"] and initiative["target_branch"] == data["branch"]
                and initiative["state"] != "done" and initiative["id"] != data.get("initiative")):
            initiative["base_moved"] = {"commit": data["commit"], "at": event["at"], "source": data["source"]}

@refusals
def apply_clear(ledger, data, _event):
    _ledger(ledger)
    fields(data, {"initiative", "base_commit", "evidence", "source"})
    text(data["source"], "source")
    evidence_reference(data["evidence"])
    initiative = ledger.initiative(data["initiative"])
    require(initiative["base_moved"] is not None)
    require(initiative["base_moved"]["commit"] == data["base_commit"])
    initiative["base_moved"] = None

APPLY = {"init": apply_init, "register": apply_register, "update": apply_update, "request": apply_request,
         "withdraw": apply_withdraw, "grant": apply_grant, "release": apply_release, "merge": apply_merge,
         "clear_base_moved": apply_clear, "set_limits": apply_set_limits}

@refusals
@contextmanager
def refusal_context():
    """Normalize failures raised while a storage context is active."""
    try:
        yield
    except WorkspaceRefusal:
        raise
    except MailboxRefusal as error:
        raise WorkspaceRefusal(error.reason) from None
    except OSError as error:
        raise WorkspaceRefusal({errno.ENOENT: "missing", errno.EEXIST: "exists", errno.ELOOP: "unsafe_path",
                                errno.ENOTDIR: "unsafe_path"}.get(error.errno, "io")) from None
    except (ValueError, KeyError, IndexError, AttributeError, RecursionError, OverflowError):
        raise WorkspaceRefusal("invalid_record") from None

def _write(descriptor, raw):
    view = memoryview(raw)
    while view:
        count = os.write(descriptor, view)
        require(count > 0, reason="io")
        view = view[count:]
    os.fsync(descriptor)

def _path(value):
    spelling = str(value) if isinstance(value, Path) else value
    require(type(spelling) is str and 0 < len(spelling) <= 32768 and "\x00" not in spelling, reason="unsafe_path")
    path = Path(spelling)
    require(path.is_absolute() and ".." not in path.parts and len(path.parts) <= 128, reason="unsafe_path")
    for part in path.parts[1:]:
        require(len(part) <= 255 and not any(0xD800 <= ord(c) <= 0xDFFF for c in part), reason="unsafe_path")
        require(len(part.encode("utf-8")) <= 255, reason="unsafe_path")
    return path

def _key_info(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def _trusted(info, root_uid=0):
    require(stat.S_ISDIR(info.st_mode) and (info.st_uid in (os.geteuid(), root_uid) and not info.st_mode & 0o022 or
             info.st_uid == root_uid and info.st_mode & stat.S_ISVTX), reason="unsafe_path")

def _private(info):
    require(info.st_uid == os.geteuid() and not info.st_mode & 0o022, reason="unsafe_path")

class _Changed(WorkspaceRefusal):
    def __init__(self):
        super().__init__("io")

def _stat(directory, name, *, busy=False):
    try:
        return os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        raise (WorkspaceRefusal("busy") if busy else _Changed()) from None

class _Files:
    """Workspace-specific descriptor reader; shared JSON primitives retain their bounds."""
    def __init__(self, root, *, coordination=True):
        require(descriptor_supported(), reason="unsupported_platform")
        self.root, self.fd, self.root_uid, self.coordination = _path(root), None, None, coordination
        with self.directory(self.root) as fd:
            self.fd = os.dup(fd)
        try:
            self.finalizer = weakref.finalize(self, os.close, self.fd)
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise

    def __enter__(self):
        require(self.fd is not None, reason="closed")
        return self

    def __exit__(self, *error):
        self.close()

    def close(self):
        if self.fd is not None:
            self.finalizer()
            self.fd = None

    @contextmanager
    def directory(self, path, *, readable=False):
        path, policy = _path(path), _private if self.coordination else _trusted
        with refusal_context():
            binding = self.fd is None
            if binding:
                require(self.root_uid is None, reason="closed")
                parts, fd = path.parts, None
                self.root_uid = 0  # Root ownership is never learned from filesystem metadata.
            else:
                parts = path.relative_to(self.root).parts
                fd = os.dup(self.fd)
            try:
                if fd is not None:
                    policy(os.fstat(fd))
                for index, part in enumerate(parts):
                    # DISP-MACOS-OPATH: absent search-only flags fall back to read-only (zero).
                    child = os.open(part, getattr(os, "O_PATH", 0) | getattr(os, "O_SEARCH", 0) |
                                    os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
                    parent, fd = fd, child
                    if parent is not None:
                        os.close(parent)
                    if binding and index < len(parts) - 1:
                        _trusted(os.fstat(fd), self.root_uid)
                    else:
                        policy(os.fstat(fd))
                if readable:
                    child = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    parent, fd = fd, child
                    os.close(parent)
                policy(os.fstat(fd))
                yield fd
            finally:
                if fd is not None:
                    os.close(fd)

    def entries(self, path, *, parent):
        """Count all names; only a validated in-directory publication pair gets one extra slot."""
        _private(os.fstat(parent))
        generation = _key_info(os.fstat(parent))
        names = []
        with os.scandir(parent) as entries:
            for entry in entries:
                require(len(names) < MAX_RECORDS + 1, reason="too_large")
                names.append(entry.name)
        infos, groups = {}, {}
        for name in names:
            info = _stat(parent, name)
            require(stat.S_ISREG(info.st_mode), reason="unsafe_path")
            require(info.st_uid == os.geteuid(), reason="unsafe_path")
            infos[name] = info
            groups.setdefault((info.st_dev, info.st_ino), []).append(name)
        pairs = set()
        for name, info in infos.items():
            if info.st_nlink == 1:
                continue
            matching_names = groups[(info.st_dev, info.st_ino)]
            pending = [other for other in matching_names if re.fullmatch(r"\.pending-[0-9a-f]{32}", other)]
            events = [other for other in matching_names if EVENT_NAME.fullmatch(other)]
            if info.st_nlink == 2 and len(matching_names) == 2 and len(pending) == len(events) == 1:
                pairs.add(pending[0])
            else:
                current = _stat(parent, name)
                if _key_info(current) != _key_info(info) or _key_info(os.fstat(parent)) != generation:
                    raise _Changed()
                raise WorkspaceRefusal("unsafe_path")
        require(len(names) - len(pairs) <= MAX_RECORDS, reason="too_large")
        return [Path(path) / name for name in sorted(names)]

    def read(self, path, *, limit=MAX_BYTES, parent=None, key=None):
        if parent is None:
            with self.directory(path.parent) as parent:
                return self.read(path, limit=limit, parent=parent, key=key)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode), reason="unsafe_path")
            if path.parent == self.root / "events":
                require(before.st_uid == os.geteuid(), reason="unsafe_path")
            if self.coordination and path.name == ".write.lock":
                _private(before)
            if before.st_nlink != 1:
                require(path.parent == self.root / "events", reason="unsafe_path")
                self.entries(path.parent, parent=parent)
            if key is not None and _key_info(before) != key:
                raise _Changed()
            require(before.st_size <= limit, reason="too_large")
            raw = bytearray()
            while len(raw) <= limit:
                chunk = os.read(fd, min(8192, limit + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            require(len(raw) <= limit, reason="too_large")
            if (_key_info(before) != _key_info(os.fstat(fd)) or _key_info(before) != _key_info(_stat(parent, path.name))):
                raise _Changed()
            return bytes(raw)
        finally:
            os.close(fd)

_RECOVERY_GUARD = Lock()

@contextmanager
def _recovery_guard(directory):
    # Serialize stale compare/unlink/create across processes as well as threads.
    try:
        with _RECOVERY_GUARD, (_kernel.owner_directory_lock(directory) if _kernel.descriptor_supported() else nullcontext()):
            yield
    except _kernel.IdentityError as error:
        raise WorkspaceRefusal("busy" if error.reason == "locked" else "io") from None

def _stale(storage, directory):
    info = _stat(directory, ".write.lock", busy=True)
    _private(info)
    try:
        raw = storage.read(storage.root / ".write.lock", parent=directory, key=_key_info(info))
        record = strict_json(raw)
        fields(record, {"pid", "created_at", "grant_id", "dev", "ino", "identity", "released"})
        matching(record["grant_id"], re.compile(r"[0-9a-f]{32}"), "lock grant")
        require((record["dev"], record["ino"]) == (info.st_dev, info.st_ino))
        require(type(record["released"]) is int and record["released"] in (0, 1))
        integer(record["pid"], "pid", minimum=1, maximum=2147483647)
        # Unknown identity retains legacy manual recovery, including same-PID retries.
        require(type(record["identity"]) is dict and record["identity"].get("pid") == record["pid"])
        fields(record["identity"], {"pid", "start_ticks"})
        integer(record["identity"]["start_ticks"], "start ticks", minimum=0, maximum=10 ** 20 - 1)
        if record["pid"] == os.getpid() and record["released"] == 1:
            return _key_info(info)
        require(_kernel.process_identity(record["pid"]) != record["identity"])
        return _key_info(info)
    except (MailboxRefusal, WorkspaceRefusal, _kernel.IdentityError, KeyError):
        raise WorkspaceRefusal("busy") from None

class WorkspaceStore:
    @refusals
    def __init__(self, path):
        require(descriptor_supported(), reason="unsupported_platform")
        self.path = _path(path)
        self.events = self.path / "events"
        self.storage = _Files(self.path)
        self._memo, self._local = None, local()

    @refusals
    def __enter__(self):
        self.storage.__enter__()
        return self

    def __exit__(self, *error):
        self.close()

    @refusals
    def close(self):
        self.storage.close()

    @refusals
    @contextmanager
    def lock(self):
        with refusal_context(), self.storage.directory(self.path, readable=True) as directory:
            with _recovery_guard(directory):
                for attempt in range(2):
                    try:
                        descriptor = os.open(".write.lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                             0o600, dir_fd=directory)
                        break
                    except FileExistsError:
                        require(attempt == 0, reason="busy")
                        key = _stale(self.storage, directory)
                        require(_key_info(_stat(directory, ".write.lock", busy=True)) == key, reason="busy")
                        os.unlink(".write.lock", dir_fd=directory)
            self._local.locked, self._local.committed, self._local.warnings = True, False, []
            record = None
            try:
                info = os.fstat(descriptor)
                try:
                    identity = _kernel.process_identity(os.getpid()) or "unavailable"
                except _kernel.IdentityError:
                    identity = "unavailable"
                record = {"pid": os.getpid(), "created_at": timestamp(), "grant_id": uuid.uuid4().hex,
                          "dev": info.st_dev, "ino": info.st_ino, "identity": identity, "released": 0}
                _write(descriptor, encoded(record))
                os.fsync(directory)
                yield
            finally:
                self._local.locked = False
                try:
                    try:
                        os.unlink(".write.lock", dir_fd=directory)
                        os.fsync(directory)
                    except OSError:
                        self._local.warnings[:] = [{"status": "warning", "code": 0, "reason": "lock_release",
                            "lock_path": ".write.lock", "next_action": "Inspect the abandoned workspace lock; recover it manually when process identity is unavailable."}]
                        try:
                            if record is not None:
                                os.lseek(descriptor, 0, os.SEEK_SET)
                                _write(descriptor, encoded({**record, "released": 1}))
                        except (OSError, WorkspaceRefusal):
                            pass  # The committed result still stands; warning requires owner inspection.
                        if not self._local.committed:
                            raise
                finally:
                    os.close(descriptor)

    @refusals
    def load(self, *, for_report=False):
        """Reuse only a descriptor-bound, metadata-validated history prefix."""
        require(type(for_report) is bool)
        previous, self._memo = self._memo, None
        for attempt in range(3):
            try:
                with self.storage.directory(self.events, readable=True) as directory:
                    paths = self.storage.entries(self.events, parent=directory)
                    paths = [path for path in paths if not path.name.startswith(".pending-")]
                    info = os.fstat(directory)
                    context = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, os.geteuid(), tuple(os.getgroups()))
                    keys = [(path.name, _key_info(_stat(directory, path.name))) for path in paths]
                    ledger = Ledger()
                    if not for_report and previous is not None and context == previous[0] and keys[:len(previous[1])] == previous[1]:
                        ledger = deepcopy(previous[2])
                    self._replay(paths, keys, directory, ledger, for_report)
                    if not for_report:
                        self._memo = (context, keys, deepcopy(ledger))
                    return ledger
            except _Changed:
                previous = None
        raise WorkspaceRefusal("io")

    def _replay(self, paths, keys, directory, ledger, for_report):
        for count, path in enumerate(paths, 1):
            name = EVENT_NAME.fullmatch(path.name)
            require(name is not None and int(name.group(1)) == count)
            if count <= ledger.seq:
                continue
            event = strict_json(self.storage.read(path, parent=directory, key=keys[count - 1][1]))
            fields(event, {"schema", "seq", "at", "kind", "data"})
            require(_key(event["schema"]) in REPLAY_SCHEMAS and event["seq"] == count)
            try:
                parse_time(event["at"])
            except ValueError:
                if not (for_report and event["kind"] in ("request", "grant", "release", "withdraw")):
                    raise
                event = {**event, "at": None}
            ledger._apply(event)
        require(ledger.limits is not None)

    @refusals
    def publish(self, name, raw):
        """Publish one bounded event without replacement under a held directory."""
        require(type(name) is str and EVENT_NAME.fullmatch(name) is not None)
        require(type(raw) is bytes and len(raw) <= MAX_BYTES, reason="too_large")
        if not getattr(self._local, "locked", False):
            with self.lock():
                return self.publish(name, raw)
        with self.storage.directory(self.events, readable=True) as directory:
            require(len(self.storage.entries(self.events, parent=directory)) + 1 <= MAX_RECORDS, reason="too_large")
            pending = ".pending-" + uuid.uuid4().hex
            descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            linked = False
            pending_exists = True
            try:
                try:
                    _write(descriptor, raw)
                finally:
                    os.close(descriptor)
                try:
                    os.link(pending, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                except FileExistsError:
                    raise WorkspaceRefusal("exists") from None
                linked = True
                os.unlink(pending, dir_fd=directory)
                pending_exists = False
                os.fsync(directory)
                self._local.committed = True
            except BaseException:
                if linked:
                    os.unlink(name, dir_fd=directory)
                raise
            finally:
                if pending_exists:
                    os.unlink(pending, dir_fd=directory)

    @refusals
    def append(self, ledger, kind, data):
        """Validate on a copy; refusal leaves both memory and durable history intact."""
        if not getattr(self._local, "locked", False):
            with self.lock():
                return self.append(ledger, kind, data)
        _ledger(ledger)
        _key(kind)
        _record(data)
        bounded_tree(data)
        require(ledger.seq < MAX_RECORDS, reason="too_large")
        schema = SUPERSEDE_EVENT_SCHEMA if kind == "request" and "supersedes" in data else EVENT_SCHEMA
        event = {"schema": schema, "seq": ledger.seq + 1, "at": timestamp(), "kind": kind, "data": data}
        candidate = deepcopy(ledger)
        candidate._apply(event)
        self.publish("%08d.json" % event["seq"], encoded(event) + b"\n")
        # Keep legacy retained references current after publication.
        ledger._apply(event)
        return event

@refusals
def capacity_view(ledger):
    _ledger(ledger)
    require(ledger.limits is not None)
    view = {}
    for kind in KINDS:
        held = ledger.held(kind)
        view[kind] = {"limit": ledger.limits[kind], "used": len(held), "free": ledger.limits[kind] - len(held),
                      "holders": [request_view(r) for r in held][:MAX_VIEW_ROWS]}
    queued = sorted((r for r in _rows(ledger.requests) if r["state"] == "queued"), key=lambda r: _order(ledger, r))
    view["queue"] = [request_view(r) for r in queued][:MAX_VIEW_ROWS]
    return view

@refusals
def request_view(request):
    _record(request)
    return {key: request[key] for key in ("request_id", "initiative", "kind", "holder", "state", "requested_at")}

@refusals
def initiative_view(ledger, identifier):
    _ledger(ledger)
    initiative = ledger.initiative(identifier)
    counts = {state: {kind: sum(1 for r in _rows(ledger.requests) if r["initiative"] == identifier
                                and r["kind"] == kind and r["state"] == state) for kind in KINDS}
              for state in ("granted", "queued")}
    return {key: initiative[key] for key in ("id", "project", "repository", "priority", "state", "target_branch",
                                             "touched_paths", "lanes", "base_moved")} | {
        "blocked_by": ledger.unresolved(initiative), "holds": counts["granted"], "queued": counts["queued"]}

@_display_response
@refusals
def grant_next(store, kind, outside=None):
    """Count outside work and grant atomically under the same writer lock."""
    require(isinstance(store, WorkspaceStore))
    require(kind in KINDS)
    with store.lock():
        code, result = _grant(store, kind, outside)
    if store._local.warnings:
        result["warnings"], store._local.warnings = store._local.warnings, []
    return code, result

def _grant(store, kind, outside):
    ledger = store.load()
    others = observe(outside, ledger) if outside is not None else []
    bounded_tree(others)
    require(type(others) in (tuple, list))
    waiting, eligible = [], []
    for request in _rows(ledger.requests):
        if request["kind"] != kind or request["state"] != "queued":
            continue
        initiative = _record(ledger.initiatives[_key(request["initiative"])])
        require(type(initiative["state"]) is str)
        blockers = ledger.unresolved(initiative)
        if initiative["state"] != "active":
            waiting.append({**request_view(request), "reason": "initiative is " + initiative["state"]})
        elif blockers:
            waiting.append({**request_view(request), "reason": "blocked", "blocked_by": blockers})
        else:
            eligible.append(request)
    answer = {"kind": kind, "granted": None, "waiting": waiting[:MAX_VIEW_ROWS]}
    if len(ledger.held(kind)) + len(others) >= ledger.limits[kind]:
        # Full means full: a higher priority request waits, because accepted work is never preempted.
        return 3, {**answer, "reason": "capacity_full", "outside": others[:MAX_VIEW_ROWS],
                   "holders": [request_view(r) for r in ledger.held(kind)][:MAX_VIEW_ROWS]}
    if not eligible:
        return 3, {**answer, "reason": "all_blocked" if waiting else "queue_empty"}
    chosen = min(eligible, key=lambda r: _order(ledger, r))
    store.append(ledger, "grant", {"request_id": chosen["request_id"]})
    chosen = ledger.requests[chosen["request_id"]]
    return 0, {**answer, "granted": {**request_view(chosen), "granted_at": chosen["granted_at"]}, "capacity": capacity_view(ledger)}

@_display_response
@refusals
def check_paths(ledger, identifier, paths, *, lease_ports=None):
    _ledger(ledger)
    initiative = ledger.initiative(identifier)
    require(lease_ports is not None, reason="port_required")
    team, team_paths = _ports(lease_ports)
    require(type(paths) in (tuple, list))
    try:
        requested = team_paths.claim_paths(paths)
    except team_paths.LeasePathError as exc:
        # Claim parsing owns bounded normalization and fixed diagnostics.
        raise WorkspaceRefusal("invalid_record") from None
    if isinstance(paths, tuple):
        paths = list(paths)
    return _check_path_overlap(ledger, initiative, paths, requested, team, team_paths)

@_display_response
@refusals
def check_initiative_paths(ledger, identifier, *, lease_ports=None):
    """Inspect a registered declaration with the lease reader's legacy semantics."""
    _ledger(ledger)
    initiative = ledger.initiative(identifier)
    paths = initiative["touched_paths"]
    require(lease_ports is not None, reason="port_required")
    team, team_paths = _ports(lease_ports)
    try:
        requested = team_paths.stored_paths(paths) if paths else team_paths.PathSet((), ())
    except team_paths.LeasePathError:
        # A readable ledger can retain a scope no lease reader can interpret.
        # Inventory it as a conflict; it is not a malformed new request.
        requested = None
    return _check_path_overlap(ledger, initiative, paths, requested, team, team_paths)

def _check_path_overlap(ledger, initiative, paths, requested, team, team_paths):
    identifier = initiative["id"]

    def stored_overlap(scope):
        if not scope or not paths:
            return False  # An undeclared workspace scope reserves no paths.
        if requested is None:
            return True  # An unreadable requested scope cannot prove disjointness.
        try:
            parsed = team_paths.stored_paths(scope)
        except team_paths.LeasePathError:
            # Like an unreadable lease, an unparseable stored scope cannot prove
            # disjointness. Keep legacy declarations/reservations fail-closed.
            return True
        return team_paths.overlap(parsed, requested)

    now = int(time.time())
    peers = [i for i in _rows(ledger.initiatives) if i["repository"] == initiative["repository"] and i["state"] != "done"]
    # Shared worktree refs require both an assigned lane and a declared checkout.
    assigned = {lane: peer["id"] for peer in peers for lane in peer["lanes"]}
    ordered = ([initiative] + [peer for peer in peers if peer["id"] != identifier]) if paths else []
    visible_here, seen, conflicts, own_overlaps, unreadable_checkouts = set(), set(), [], [], []
    checked = 0
    for peer in ordered:
        for checkout in peer["checkouts"]:
            try:
                found = team.read_leases(Path(checkout))
            except Exception as exc:  # Any failure to read counts as a conflict: unsure means conflict.
                unreadable_checkouts.append({"initiative": peer["id"], "checkout": checkout, "error": "lease observation unavailable"})
                continue
            checked += 1
            for lease in found.leases:
                key = (lease.lane, lease.oid)
                if peer["id"] == identifier:
                    visible_here.add(key)
                if (key in seen or lease.expired(now)
                        or (requested is not None and not team_paths.overlap(lease.path_set, requested))):
                    continue
                seen.add(key)
                row = {"lane": lease.lane, "paths": list(lease.paths), "owner": lease.owner, "initiative": peer["id"],
                       "assigned_to": assigned.get(lease.lane), "checkout": checkout, "expires_at": lease.expires_at}
                mine = assigned.get(lease.lane) == identifier and key in visible_here
                (own_overlaps if mine else conflicts).append(row)
            for bad in found.unreadable:
                key = (bad.lane, bad.oid)
                if key not in seen:
                    seen.add(key)
                    conflicts.append({"lane": bad.lane, "initiative": peer["id"],
                                      "checkout": checkout, "unreadable": "lease record unreadable"})
    declared = [peer["id"] for peer in peers if peer["id"] != identifier and stored_overlap(peer["touched_paths"])]
    # Replay pins the original request scope until terminal capacity evidence.
    reserved = [{"request_id": r["request_id"], "initiative": r["initiative"], "holder": r["holder"],
                 "paths": r["reserved_paths"]} for r in ledger.held("writer")
                if r["initiative"] != identifier and r["reserved_repository"] == initiative["repository"]
                and stored_overlap(r["reserved_paths"])]
    conflict = requested is None or bool(conflicts or unreadable_checkouts or reserved)
    result = { "initiative": identifier, "paths": paths, "conflict": conflict, "conflicts": conflicts[:MAX_VIEW_ROWS],
        "reserved_conflicts": reserved[:MAX_VIEW_ROWS],
        "unreadable_checkouts": unreadable_checkouts[:MAX_VIEW_ROWS], "own_overlaps": own_overlaps[:MAX_VIEW_ROWS],
        "declared_overlaps": declared, "checked_checkouts": checked,
        "note": "A clear result is advice, not a lock: run the check and the lease claim one after another."}
    if requested is None:
        result["reason"] = "stored_paths_unreadable"
    return (3 if conflict else 0), result

@_display_response
@refusals
def check_delivery(ledger, identifier):
    _ledger(ledger)
    initiative = ledger.initiative(identifier)
    blockers = ledger.unresolved(initiative)
    ready = initiative["state"] == "active" and not blockers and initiative["base_moved"] is None
    return (0 if ready else 3), {"initiative": identifier, "ready": ready, "state": initiative["state"],
                                 "blocked_by": blockers, "base_moved": initiative["base_moved"]}

@refusals
def mailbox_facts(initiative, *, mailbox_factory=None):
    _record(initiative)
    if "mailbox_root" not in initiative:
        return None
    require(mailbox_factory is not None, reason="port_required")
    try:
        mailbox = observe(mailbox_factory, initiative["mailbox_root"])
        try:
            status = observe(mailbox.status)
            delivery = observe(mailbox.delivery, initiative["delivery_dir"]) if "delivery_dir" in initiative else None
        finally:
            close = getattr(mailbox, "close", None)
            if close is not None:
                observe(close)
    except (ValueError, OSError, UnicodeError, RecursionError) as exc:
        return {"error": "mailbox observation unavailable"}
    # Malformed backend values are operational refusals, not report facts.
    _record(status)
    require(type(status["open_job_requests"]) in (list, tuple, dict))
    require(type(status["accepted_writers"]) in (list, tuple, dict))
    facts = {"messages": status["messages"], "open_job_requests": len(status["open_job_requests"]),
             "accepted_writers": len(status["accepted_writers"])}
    if "delivery_dir" in initiative:
        summary = _record(_record(delivery)["endpoints"])
        facts["unread"] = 0
        for row in _rows(summary):
            require(isinstance(row["unread_count"], (int, float)))
            facts["unread"] += row["unread_count"]
    return facts

@refusals
def queue_facts(ledger, now):
    _ledger(ledger)
    return _queue_facts(ledger.requests, now, kinds=KINDS)

@refusals
def report(ledger, *, mailbox_factory=None):
    """One view across all initiatives, built by this script. It is a listing, not a judgment."""
    _ledger(ledger)
    require(all(isinstance(row["priority"], (int, float)) and type(row["id"]) is str for row in _rows(ledger.initiatives)))
    ordered = sorted(_rows(ledger.initiatives), key=lambda i: (i["priority"], i["id"]))
    rows = [{**initiative_view(ledger, i["id"]), "mailbox": mailbox_facts(i, mailbox_factory=mailbox_factory)} for i in ordered]
    now = timestamp()
    return {"generated_by": "script", "generated_at": now, "capacity": capacity_view(ledger), "initiatives": rows,
            "queue_facts": queue_facts(ledger, now)}

@refusals
def report_text(data):
    return _render_report(data)

def observe(port, *args):
    require(callable(port), reason="port_unavailable")
    try:
        return port(*args)
    except WorkspaceRefusal:
        raise
    except Exception:
        raise WorkspaceRefusal("port_unavailable") from None
