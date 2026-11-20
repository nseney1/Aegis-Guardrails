"""Bounded, read-only mailbox diagnostics over the product validators.

The adapter injects role/host tables, time and a process-status observation.
One descriptor store is retained for the entire inspection; no tool imports,
function cloning, global hooks, process execution or persistent index writes.
"""
import errno
import os
from pathlib import Path
import stat
from threading import local
import unicodedata

from aegis_core.diagnostic_messages import guidance_value
from aegis_core.team_mailbox import Mailbox
from aegis_core.team_mailbox_index import Index, compare
from aegis_core.team_mailbox_index_scan import parse_message
from aegis_core.team_mailbox_primitives import (
    MAX_BYTES, MAX_RECORDS, MailboxRefusal, RoleTables, fields, integer,
    parse_time, render_mailbox_refusal, reply_reference, safe_path, strict_json,
)
from aegis_core import team_mailbox_store as storage

__all__ = ["inspect_mailbox", "Refusal", "descriptor_reads_supported", "SCHEMA", "REFUSALS"]

SCHEMA = "aegis.hierarchy-mailbox-doctor/v1"
MAX_FILES = 20000
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_NAME_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 64
REFUSALS = {
    "MD_USAGE": "Supply an absolute mailbox root and valid diagnostic options.",
    "MD_PLATFORM": "secure mailbox diagnostics require directory descriptors and O_NOFOLLOW",
    "MD_PATH": "unsafe mailbox or reference path; use regular files and directories without symlinks",
    "MD_LIMIT": "mailbox exceeds the fixed file-count, byte, path or nesting budget",
    "MD_IO": "mailbox input is unavailable or changed during inspection",
    "MD_DATA": "mailbox manifest is malformed",
}
NEXT_ACTIONS = {
    "MD_USAGE": "Use the documented mail doctor options and an absolute root.",
    "MD_PLATFORM": "Use a platform with descriptor-relative no-follow storage.",
    "MD_PATH": "Restore regular files and directories beneath the trusted mailbox parent.",
    "MD_LIMIT": "Reconcile retained input against the fixed diagnostic budgets.",
    "MD_IO": "Restore unavailable input or retry after concurrent changes have stopped.",
    "MD_DATA": "Restore the manifest from trusted evidence before retrying.",
}


class Refusal(Exception):
    def __init__(self, code):
        self.code, self.next_action = code, NEXT_ACTIONS[code]
        super().__init__(REFUSALS[code])


def descriptor_reads_supported():
    return storage.descriptor_supported()


def checked_path(value):
    if not isinstance(value, (str, Path)):
        raise Refusal("MD_PATH")
    raw = str(value)
    if len(raw) > MAX_PATH_BYTES:
        raise Refusal("MD_LIMIT")
    try:
        if len(os.fsencode(raw)) > MAX_PATH_BYTES:
            raise Refusal("MD_LIMIT")
        path = safe_path(raw)
    except (MailboxRefusal, UnicodeError):
        raise Refusal("MD_PATH") from None
    if len(path.parts) > MAX_DEPTH:
        raise Refusal("MD_LIMIT")
    return path


def mark(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class DiagnosticStore(storage.Store):
    """Read-only Store specialization with whole-tree admission before parsing."""
    def __init__(self, root):
        self.seen, self.metadata, self.names = set(), {}, {}
        self.raw = {}
        self.name_bytes = self.declared_bytes = self.read_bytes = 0
        self.message_scan = False
        super().__init__(root)

    def admit_path(self, path):
        path = checked_path(path)
        if path not in self.seen:
            size = len(os.fsencode(str(path)))
            if len(self.seen) >= MAX_FILES or size > MAX_NAME_BYTES - self.name_bytes:
                raise Refusal("MD_LIMIT")
            self.seen.add(path)
            self.name_bytes += size
        return path

    def verify_admission(self, path, *, observed=None):
        """Require every admitted record on the anchored chain to stay identical."""
        for candidate in (*reversed(path.parents), path):
            if candidate not in self.metadata:
                continue
            try:
                if candidate == path and observed is not None:
                    info = observed
                else:
                    with self.directory(candidate.parent) as parent:
                        info = os.stat(candidate.name, dir_fd=parent, follow_symlinks=False)
            except (MailboxRefusal, OSError, ValueError, NotImplementedError):
                raise Refusal("MD_IO") from None
            if mark(info) != mark(self.metadata[candidate]):
                raise Refusal("MD_IO")

    def probe(self, path):
        path = self.admit_path(path)
        try:
            with self.directory(path.parent) as parent:
                info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except (MailboxRefusal, OSError) as error:
            self.verify_admission(path)
            if isinstance(error, FileNotFoundError) or (isinstance(error, MailboxRefusal)
                    and render_mailbox_refusal(error)["reason"] == "missing"):
                return None
            raise
        self.verify_admission(path, observed=info)
        if path not in self.metadata:
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise Refusal("MD_PATH")
            if stat.S_ISREG(info.st_mode):
                if info.st_size > MAX_BYTES or info.st_size > MAX_TOTAL_BYTES - self.declared_bytes:
                    raise Refusal("MD_LIMIT")
                self.declared_bytes += info.st_size
            self.metadata[path] = info
        return info

    def listing(self, path, *, missing=False):
        path = self.admit_path(path)
        if self.probe(path) is None:
            if missing:
                return ()
            raise Refusal("MD_IO")
        names = []
        try:
            with self.directory(path) as parent, os.scandir(parent) as entries:
                for entry in entries:
                    self.admit_path(path / entry.name)
                    names.append(entry.name)
        except (MailboxRefusal, OSError, Refusal):
            self.verify_admission(path)
            raise
        self.verify_admission(path)
        names = tuple(sorted(names))
        if path in self.names and self.names[path] != names:
            raise Refusal("MD_IO")
        self.names[path] = names
        return names

    def preflight(self):
        pending = [self.root]
        while pending:
            folder = pending.pop()
            for name in self.listing(folder):
                path = folder / name
                info = self.probe(path)
                if info is None:
                    raise Refusal("MD_IO")
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)

    def entries(self, path, *, missing=False, parent=None):
        # Mailbox's public validators enumerate only this admitted observation.
        return [Path(path) / name for name in self.listing(path, missing=missing)
                if not (self.message_scan and name.startswith(".pending-"))]

    def read(self, path, *, limit=MAX_BYTES, parent=None):
        path = self.admit_path(path)
        info = self.probe(path)
        if info is None:
            raise FileNotFoundError()
        if path in self.raw:
            if len(self.raw[path]) > limit:
                raise Refusal("MD_LIMIT")
            return self.raw[path]
        if info.st_size > MAX_TOTAL_BYTES - self.read_bytes:
            raise Refusal("MD_LIMIT")
        try:
            raw = super().read(path, limit=min(limit, MAX_BYTES, MAX_TOTAL_BYTES - self.read_bytes), parent=parent)
        except MailboxRefusal:
            self.verify_admission(path)
            raise
        self.read_bytes += len(raw)
        self.probe(path)
        self.raw[path] = raw
        return raw

    def confirm(self):
        for path in tuple(self.metadata):
            self.probe(path)
        for path in tuple(self.names):
            self.listing(path)


class DiagnosticMailbox(Mailbox):
    def __init__(self, store, *, roles, hosts, clock):
        self.store, self.root = store, store.root
        self.roles, self.hosts, self.clock = roles, dict(hosts), clock
        self.host = next(iter(hosts)) if len(hosts) == 1 else None
        self.caller_role, self.calls, self.delivery_roots = "diagnostic", local(), ()
        self.refresh()

    def refresh(self):
        # A decorated read may re-enter here. Re-stat cached bytes on every
        # use, but validate this inspection's one admitted manifest only once.
        path = self.root / "manifest.json"
        if hasattr(self, "manifest"):
            self.store.read(path)
        else:
            self.manifest = self.roles.validate_manifest(self.store.read_json(path))


def issue(issues, code, path, store):
    relative = Path(path).relative_to(store.root.parent)
    issues.append({"code": code, "path": guidance_value(unicodedata.normalize("NFKC", str(relative)), limit=256)})


def data_failure(error):
    reason = render_mailbox_refusal(error)["reason"]
    if reason not in ("invalid_record", "unknown_host", "scope", "binding", "reference", "history"):
        raise error


def messages(box, store, issues):
    folders = {box.root / endpoint.split("/")[0] / endpoint.split("/")[1]
               for endpoint in box.manifest["endpoints"]}
    folders |= {box.root / "across" / role for role in box.roles.across_roles}
    records, count = {}, 0
    for folder in sorted(folders):
        for path in store.entries(folder):
            if path.suffix == ".md":
                count += 1
            try:
                if path.suffix != ".md":
                    raise MailboxRefusal("invalid_record")
                message = parse_message(store.read(path))
                if box.validate_message(message, stored=True) != folder:
                    raise MailboxRefusal("invalid_record")
            except MailboxRefusal as error:
                data_failure(error)
                issue(issues, "MD_MESSAGE", path, store)
                continue
            identifier = message["message_id"]
            if identifier in records:
                issue(issues, "MD_DUPLICATE", path, store)
            else:
                records[identifier] = {"path": str(path), "message": message}
    for record in records.values():
        if "in_reply_to" in record["message"]:
            try:
                reply_reference(record["message"], records)
            except MailboxRefusal as error:
                data_failure(error)
                issue(issues, "MD_MESSAGE", record["path"], store)
    return count


def index_report(box):
    index = Index(box, mode="shadow")
    try:
        differences = compare(box, index)
    except MailboxRefusal as error:
        data_failure(error)
        return {"status": "unavailable", "reason": "pinned_reconciliation", "differences": []}
    if differences:
        return {"status": "diverged", "differences": differences}
    if index.last_reconciliation is not None:
        return {"status": "unavailable", "reason": "pinned_reconciliation", "differences": []}
    return {"status": "equal", "differences": []}


def briefs(box, store, issues):
    for endpoint in sorted(box.manifest["endpoints"]):
        try:
            history = box.bindings(endpoint)
        except MailboxRefusal as error:
            data_failure(error)
            issue(issues, "MD_BINDING", store.root / "bindings" / endpoint, store)
            continue
        for record in history:
            checkpoint = record["checkpoint"]
            for brief in checkpoint["briefs"] if checkpoint is not None else ():
                try:
                    box.brief(brief)
                except MailboxRefusal as error:
                    if render_mailbox_refusal(error)["reason"] not in ("missing", "invalid_record", "io"):
                        raise
                    issue(issues, "MD_BRIEF", brief["path"], store)


def lock_report(store, issues, process_status):
    path = store.root / ".write.lock"
    if store.probe(path) is None:
        return {"status": "absent"}
    try:
        holder = strict_json(store.read(path))
        fields(holder, {"pid", "created_at"})
        integer(holder["pid"], "lock pid", maximum=(1 << 31) - 1)
        parse_time(holder["created_at"])
    except MailboxRefusal as error:
        data_failure(error)
        issue(issues, "MD_LOCK", path, store)
        return {"status": "malformed"}
    status = process_status(holder["pid"])
    if status not in ("alive", "dead", "unknown"):
        raise Refusal("MD_IO")
    if status != "alive":
        issue(issues, "MD_LOCK", path, store)
    return {"status": status, "pid": holder["pid"]}


def inspect_store(store, *, roles, hosts, clock, process_status):
    store.preflight()
    try:
        box = DiagnosticMailbox(store, roles=roles, hosts=hosts, clock=clock)
    except MailboxRefusal as error:
        data_failure(error)
        raise Refusal("MD_DATA") from None
    issues = []
    store.message_scan = True
    try:
        count = messages(box, store, issues)
        index = index_report(box)
    finally:
        store.message_scan = False
    if index["status"] != "equal":
        issue(issues, "MD_INDEX", store.root, store)
    briefs(box, store, issues)
    lock = lock_report(store, issues, process_status)
    for path in sorted(store.seen):
        if store.root in path.parents and path.name.startswith(".pending-"):
            issue(issues, "MD_PENDING", path, store)
    if count >= MAX_RECORDS:
        issue(issues, "MD_CAP", store.root, store)
    store.confirm()
    return {"schema": SCHEMA, "mailbox": guidance_value(unicodedata.normalize("NFKC", store.root.name), limit=256), "healthy": not issues,
            "cap": {"count": count, "limit": MAX_RECORDS, "headroom": max(0, MAX_RECORDS - count)},
            "lock": lock, "issues": issues, "index": index}


def inspect_mailbox(root, *, roles, hosts, clock, process_status):
    """Observe admitted disk records; every expected failure is a fixed Refusal."""
    if not descriptor_reads_supported():
        raise Refusal("MD_PLATFORM")
    if not isinstance(roles, RoleTables) or type(hosts) is not dict or not hosts or not callable(clock) or not callable(process_status):
        raise Refusal("MD_USAGE")
    try:
        with DiagnosticStore(checked_path(root)) as store:
            return inspect_store(store, roles=roles, hosts=hosts, clock=clock, process_status=process_status)
    except MailboxRefusal as error:
        reason = render_mailbox_refusal(error)["reason"]
        code = {"unsafe_path": "MD_PATH", "too_large": "MD_LIMIT", "unsupported_platform": "MD_PLATFORM",
                "missing": "MD_IO", "io": "MD_IO"}.get(reason, "MD_IO")
        raise Refusal(code) from None
    except OSError as error:
        raise Refusal("MD_PATH" if error.errno in (errno.ELOOP, errno.ENOTDIR) else "MD_IO") from None
    except (ValueError, KeyError, UnicodeError, RecursionError, OverflowError, NotImplementedError):
        raise Refusal("MD_IO") from None
