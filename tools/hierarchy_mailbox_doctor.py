#!/usr/bin/env python3
"""Bounded, read-only mailbox diagnostics using the pinned mailbox validators."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import stat
import sys
from types import FunctionType, MethodType, SimpleNamespace
import unicodedata

sys.dont_write_bytecode = True
if __package__:
    from . import hierarchy_mailbox as hm
    from . import hierarchy_mailbox_index as index_module
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import hierarchy_mailbox as hm
    import hierarchy_mailbox_index as index_module
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aegis_core.redaction import redact_command_secrets  # noqa: E402


SCHEMA = "aegis.hierarchy-mailbox-doctor/v1"
MAX_FILES = 20000
MAX_FILE_BYTES = hm.MAX_BYTES
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_NAME_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 64
MAX_DISPLAY = 256
MESSAGE_CAP = hm.MAX_RECORDS
REFUSALS = {
    "MD_USAGE": "usage: hierarchy_mailbox_doctor.py <absolute-mailbox-root> [--json]",
    "MD_PLATFORM": "secure mailbox diagnostics require directory descriptors and O_NOFOLLOW",
    "MD_PATH": "unsafe mailbox or reference path; use regular files and directories without symlinks",
    "MD_LIMIT": "mailbox exceeds the fixed file-count, byte, path or nesting budget",
    "MD_IO": "mailbox input is unavailable or changed during inspection",
    "MD_DATA": "mailbox manifest is malformed",
}
INVALID = (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError, AttributeError)


class Refusal(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(REFUSALS[code])


def descriptor_reads_supported():
    return (os.name == "posix" and {"open", "stat"} <= {fn.__name__ for fn in os.supports_dir_fd}
            and "stat" in {fn.__name__ for fn in os.supports_follow_symlinks}
            and "scandir" in {fn.__name__ for fn in os.supports_fd}
            and all(getattr(os, name, 0) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")))


def _lexical(value):
    if not isinstance(value, (str, Path)):
        raise Refusal("MD_PATH")
    raw = str(value)
    if len(raw) > MAX_PATH_BYTES or "\x00" in raw:
        raise Refusal("MD_LIMIT" if len(raw) > MAX_PATH_BYTES else "MD_PATH")
    if len(os.fsencode(raw)) > MAX_PATH_BYTES:
        raise Refusal("MD_LIMIT")
    path = Path(raw)
    if not path.is_absolute() or ".." in path.parts:
        raise Refusal("MD_PATH")
    if len(path.parts) > MAX_DEPTH:
        raise Refusal("MD_LIMIT")
    return path


def _json(raw):
    """Limit encoded size and syntactic depth before the pinned JSON parser."""
    if len(raw) > MAX_FILE_BYTES:
        raise Refusal("MD_LIMIT")
    quoted, escaped, depth = False, False, 0
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("JSON nesting exceeds diagnostic limit")
        elif char in "]}":
            depth -= 1
    return hm.strict_json(raw)


def _display(value):
    canonical = unicodedata.normalize("NFKC", str(value))
    canonical = redact_command_secrets(canonical)
    canonical = " ".join("".join(" " if unicodedata.category(c)[0] == "C" else c for c in canonical).split())
    redacted = redact_command_secrets(canonical)
    return redacted[:MAX_DISPLAY] + ("..." if len(redacted) > MAX_DISPLAY else "")


def _mark(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _Store:
    """Pin root and parent identities; every subsequent byte open is relative to them."""
    def __init__(self, root):
        self.root = root
        self.parent_fd = self.root_fd = None
        self.names, self.metadata, self.raw = {}, {}, {}
        self.seen = set()
        self.name_bytes = self.declared_bytes = self.read_bytes = 0
        self.selected = None
        self.selected_folder = None

    @staticmethod
    def _flags():
        return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK

    @contextmanager
    def _walk(self, start, components):
        fd = os.open(start if isinstance(start, str) else ".", self._flags(),
                     **({} if isinstance(start, str) else {"dir_fd": start}))
        try:
            for component in components:
                child = os.open(component, self._flags(), dir_fd=fd)
                os.close(fd)
                fd = child
            yield fd
        finally:
            os.close(fd)

    def __enter__(self):
        try:
            # The filesystem anchor is trusted; no component is resolved through a symlink.
            with self._walk(self.root.anchor, self.root.parent.parts[1:]) as fd:
                self.parent_fd = os.open(".", self._flags(), dir_fd=fd)
            self.root_fd = os.open(self.root.name, self._flags(), dir_fd=self.parent_fd)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_args):
        if self.root_fd is not None:
            os.close(self.root_fd)
            self.root_fd = None
        if self.parent_fd is not None:
            os.close(self.parent_fd)
            self.parent_fd = None

    @contextmanager
    def directory(self, path):
        path = _lexical(path)
        if path == self.root or self.root in path.parents:
            start, parts = self.root_fd, path.relative_to(self.root).parts
        elif path == self.root.parent or self.root.parent in path.parents:
            start, parts = self.parent_fd, path.relative_to(self.root.parent).parts
        else:
            # Stored readiness references may be outside the mailbox parent. Only
            # no-follow metadata is inspected there; byte reads stay confined.
            start, parts = path.anchor, path.parts[1:]
        with self._walk(start, parts) as fd:
            yield fd

    def _admit(self, path):
        if path in self.seen:
            return
        if len(self.seen) >= MAX_FILES:
            raise Refusal("MD_LIMIT")
        size = len(os.fsencode(str(path)))
        if size > MAX_NAME_BYTES - self.name_bytes:
            raise Refusal("MD_LIMIT")
        self.name_bytes += size
        self.seen.add(path)

    def probe(self, path):
        path = _lexical(path)
        if path in self.metadata:
            return self.metadata[path]
        self._admit(path)
        try:
            with self.directory(path.parent) as fd:
                info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise Refusal("MD_PATH")
        if stat.S_ISREG(info.st_mode):
            if info.st_size > MAX_FILE_BYTES or info.st_size > MAX_TOTAL_BYTES - self.declared_bytes:
                raise Refusal("MD_LIMIT")
            self.declared_bytes += info.st_size
        self.metadata[path] = info
        return info

    def listing(self, path):
        path = _lexical(path)
        if path not in self.names:
            names = []
            with self.directory(path) as fd, os.scandir(fd) as entries:
                for entry in entries:
                    if len(entry.name) > MAX_PATH_BYTES:
                        raise Refusal("MD_LIMIT")
                    child = _lexical(path / entry.name)
                    self._admit(child)
                    names.append(entry.name)
            self.names[path] = tuple(sorted(names))
        return self.names[path]

    def preflight(self):
        """Bound all mailbox entries and declared bytes before parsing even the manifest."""
        pending = [self.root]
        while pending:
            folder = pending.pop()
            self.probe(folder)
            for name in self.listing(folder):
                path = folder / name
                info = self.probe(path)
                if info is None:
                    raise Refusal("MD_IO")
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)

    def read(self, path, *, fresh=False):
        path = _lexical(path)
        if self.root.parent not in path.parents:
            raise Refusal("MD_PATH")
        if not fresh and path in self.raw:
            return self.raw[path]
        self.probe(path)
        with self.directory(path.parent) as parent:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode):
                    raise Refusal("MD_PATH")
                if before.st_size > MAX_FILE_BYTES or before.st_size > MAX_TOTAL_BYTES - self.read_bytes:
                    raise Refusal("MD_LIMIT")
                self.read_bytes += before.st_size
                chunks, remaining = [], before.st_size
                while remaining:
                    chunk = os.read(fd, min(65536, remaining))
                    if not chunk:
                        raise Refusal("MD_IO")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if _mark(os.fstat(fd)) != _mark(before) or os.read(fd, 1):
                    raise Refusal("MD_IO")
                raw = b"".join(chunks)
            finally:
                os.close(fd)
        if not fresh:
            self.raw[path] = raw
        return raw


def _pinned_mailbox(store):
    """Bind original pinned method code to an operation-local filesystem view.

    This changes no module globals or validator code. In particular the pinned
    messages() method remains the sole header parser and message validator.
    Refused scans can narrow enumeration to one folder/file without changing
    endpoint lookups or route validation. Reply validation is deferred until
    the full set of valid records is available.
    """
    class CheckedPath(type(Path())):
        def exists(self):
            return store.probe(self) is not None

        def is_symlink(self):
            store.probe(self)  # A symlink is a hard diagnostic refusal.
            return False

        def iterdir(self):
            if store.selected_folder is not None and self != store.selected_folder:
                return iter(())
            if store.selected is not None:
                return iter((self / store.selected.name,)) if self == store.selected.parent else iter(())
            return iter(self / name for name in store.listing(self))

    def safe_path(value):
        path = CheckedPath(_lexical(value))
        store.probe(path)
        return path

    namespace = dict(vars(hm), Path=CheckedPath, safe_path=safe_path, read_bytes=store.read,
                     read_json=lambda path: _json(store.read(path).decode("utf-8")), strict_json=_json)
    methods = {}
    for name in ("__init__", "endpoint", "route", "brief", "checkpoint", "bindings", "messages",
                 "validate_message", "readiness", "completion", "job_receipt"):
        method = vars(hm.Mailbox)[name]
        function = method.__func__ if isinstance(method, staticmethod) else method
        clone = FunctionType(function.__code__, namespace, function.__name__, function.__defaults__, function.__closure__)
        clone.__kwdefaults__ = function.__kwdefaults__
        methods[name] = staticmethod(clone) if isinstance(method, staticmethod) else clone
    methods["reply"] = staticmethod(lambda message, records: None)
    box = type("DiagnosticMailbox", (hm.Mailbox,), methods)(store.root)
    endpoints = box.manifest["endpoints"]
    representatives = {store.root / endpoint.split("/")[0] / endpoint.split("/")[1]: endpoint
                       for endpoint in endpoints}
    class RoutingEndpoints(dict):
        def __iter__(self):
            if store.selected_folder is None:
                return super().__iter__()
            endpoint = representatives.get(store.selected_folder)
            return iter((endpoint,)) if endpoint is not None else iter(())
    # Only enumeration narrows. Dict membership, indexing, get/items and values
    # still expose every endpoint to the original pinned validators and digest.
    box.manifest = {**box.manifest, "endpoints": RoutingEndpoints(endpoints)}
    box.diagnostic_namespace = namespace
    return box


def _clone(function, namespace):
    clone = FunctionType(function.__code__, namespace, function.__name__, function.__defaults__, function.__closure__)
    clone.__kwdefaults__ = function.__kwdefaults__
    return clone


class _Listing:
    """An already bounded directory observation with scandir's context interface."""
    def __init__(self, names):
        self.names = names

    def __enter__(self):
        return (SimpleNamespace(name=name) for name in self.names)

    def __exit__(self, *_args):
        pass


class _IndexOS:
    """Bind index OS boundaries to the same pinned root, with fresh file stats."""
    def __init__(self, store, guard):
        self.store = store
        self.lstat = guard(self._lstat)
        self.scandir = guard(lambda path: _Listing(store.listing(path)))
        self.open = guard(self._open)
        self.fdopen = guard(os.fdopen)
        self.path = SimpleNamespace(**{**vars(os.path), "exists": lambda path: store.probe(path) is not None})

    def __getattr__(self, name):
        return getattr(os, name)

    def _lstat(self, path):
        path = _lexical(path)
        self.store._admit(path)
        if path == self.store.root:
            return os.fstat(self.store.root_fd)
        if path == self.store.root.parent:
            return os.fstat(self.store.parent_fd)
        try:
            with self.store.directory(path.parent) as fd:
                info = os.stat(path.name or ".", dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            if path in self.store.metadata:
                raise  # A previously observed input disappeared during inspection.
            return None  # Pinned stored brief/readiness references may be absent.
        if stat.S_ISLNK(info.st_mode):
            raise Refusal("MD_PATH")
        if stat.S_ISREG(info.st_mode) and info.st_size > MAX_FILE_BYTES:
            raise Refusal("MD_LIMIT")
        return info

    def _open(self, path, flags):
        path = _lexical(path)
        if self.store.root.parent not in path.parents or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise Refusal("MD_PATH")
        fd = None
        try:
            with self.store.directory(path.parent) as parent:
                fd = os.open(path.name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise Refusal("MD_PATH")
            if info.st_size > MAX_FILE_BYTES or info.st_size > MAX_TOTAL_BYTES - self.store.read_bytes:
                raise Refusal("MD_LIMIT")
            self.store.read_bytes += info.st_size
            return fd  # The original index _open_checked owns it, including fdopen failures.
        except BaseException:
            if fd is not None:
                os.close(fd)
            raise


def _index_report(box, store):
    """Run the existing comparator in shadow mode; bind IO locally, never patch modules."""
    failures = []
    def guard(call):
        def checked(*args, **kwargs):
            try:
                return call(*args, **kwargs)
            except (Refusal, OSError, NotImplementedError) as exc:
                if not failures:
                    failures.append(exc)
                raise
        return checked

    # Deferred message-by-message validation is complete. The full pinned oracle
    # and the derived index now both perform their original reply checks.
    box.reply = hm.Mailbox.reply
    pinned = SimpleNamespace(**{**box.diagnostic_namespace,
                               "read_bytes": guard(lambda path: store.read(path, fresh=True)),
                               "safe_path": guard(box.diagnostic_namespace["safe_path"])})
    namespace = dict(vars(index_module), hm=pinned, os=_IndexOS(store, guard))
    observer = index_module._Observations
    methods = {}
    for name, method in vars(observer).items():
        if isinstance(method, FunctionType):
            methods[name] = _clone(method, namespace)
        elif isinstance(method, staticmethod):
            methods[name] = staticmethod(_clone(method.__func__, namespace))
    namespace["_Observations"] = type("DiagnosticObservations", (observer,), methods)
    index = index_module.MailboxIndex(box, mode="shadow")
    # Keep the constructor and mode untouched. Original method code uses only
    # this call's descriptor adapter; no global filesystem hooks are installed.
    def bound(name):
        return MethodType(_clone(getattr(type(index), name), namespace), index)
    index._read_message = bound("_read_message")
    index._read_raw = bound("_read_raw")
    index._parse_message = bound("_parse_message")
    index._open_checked = bound("_open_checked")
    index._admit_returned = bound("_admit_returned")
    index._list_folders = bound("_list_folders")
    index._list_folder = bound("_list_folder")
    index._observe_entry = bound("_observe_entry")
    index._validate_entry = bound("_validate_entry")
    index._confirm_entry = bound("_confirm_entry")
    index._scan = bound("_scan")
    differences = index_module.compare(box, index)
    if failures:
        raise failures[0]  # An index fallback must never hide an IO/budget refusal.
    if differences:
        return {"status": "diverged", "differences": differences}
    if index.last_reconciliation is not None:
        return {"status": "unavailable", "reason": "pinned_reconciliation", "differences": []}
    return {"status": "equal", "differences": []}


def _issue(issues, code, path, store):
    relative = Path(path).relative_to(store.root.parent)
    issues.append({"code": code, "path": _display(relative)})


def _parse_messages(box, store, folder=None, path=None):
    store.selected_folder, store.selected = folder, path
    try:
        return box.messages()
    finally:
        store.selected_folder = store.selected = None


def _merge_records(records, found, store, issues):
    for identifier, record in found.items():
        if identifier in records:
            _issue(issues, "MD_DUPLICATE", record["path"], store)
        else:
            records[identifier] = record


def _isolate_messages(box, store, folders, issues):
    records = {}
    for folder in folders:
        try:
            found = _parse_messages(box, store, folder)
        except INVALID:
            for name in store.listing(folder):
                if name.startswith(".pending-"):
                    continue
                path = folder / name
                try:
                    found = _parse_messages(box, store, folder, path)
                except INVALID:
                    _issue(issues, "MD_MESSAGE", path, store)
                    continue
                _merge_records(records, found, store, issues)
        else:
            _merge_records(records, found, store, issues)
    return records


def _messages(box, store, issues):
    folders = {store.root / endpoint.split("/")[0] / endpoint.split("/")[1]
               for endpoint in box.manifest["endpoints"]}
    folders |= {store.root / "across" / role for role in hm.ACROSS_ROLES}
    folders = sorted(folders)
    count = sum(not name.startswith(".pending-") and Path(name).suffix == ".md"
                for folder in folders for name in store.listing(folder))
    try:
        records = _parse_messages(box, store)
    except INVALID:
        records = _isolate_messages(box, store, folders, issues)
    for record in records.values():
        if "in_reply_to" in record["message"]:
            try:
                hm.Mailbox.reply(record["message"], records)
            except INVALID:
                _issue(issues, "MD_MESSAGE", record["path"], store)
    return count


def _briefs(box, store, issues):
    for endpoint in sorted(box.manifest["endpoints"]):
        directory = store.root / "bindings" / endpoint
        try:
            history = box.bindings(endpoint)
        except INVALID:
            _issue(issues, "MD_BINDING", directory, store)
            continue
        for record in history:
            checkpoint = record["checkpoint"]
            for brief in checkpoint["briefs"] if checkpoint is not None else ():
                try:
                    box.brief(brief)
                except (*INVALID, FileNotFoundError):
                    _issue(issues, "MD_BRIEF", brief["path"], store)


def _lock(store, issues):
    path = store.root / ".write.lock"
    if store.probe(path) is None:
        return {"status": "absent"}
    try:
        holder = _json(store.read(path).decode("utf-8"))
        hm.fields(holder, {"pid", "created_at"})
        hm.integer(holder["pid"], "lock pid", maximum=(1 << 31) - 1)
        hm.parse_time(holder["created_at"])
    except INVALID:
        _issue(issues, "MD_LOCK", path, store)
        return {"status": "malformed"}
    try:
        os.kill(holder["pid"], 0)
        status = "alive"
    except ProcessLookupError:
        status = "dead"
    except PermissionError:
        status = "unknown"
    if status != "alive":
        _issue(issues, "MD_LOCK", path, store)
    return {"status": status, "pid": holder["pid"]}


def inspect_mailbox(root):
    """Return one bounded observation; never create, replace or remove input files."""
    if not descriptor_reads_supported():
        raise Refusal("MD_PLATFORM")
    with _Store(_lexical(root)) as store:
        store.preflight()
        try:
            box = _pinned_mailbox(store)
        except INVALID:
            raise Refusal("MD_DATA") from None
        issues = []
        count = _messages(box, store, issues)
        index = _index_report(box, store)
        if index["status"] != "equal":
            _issue(issues, "MD_INDEX", store.root, store)
        _briefs(box, store, issues)
        lock = _lock(store, issues)
        for path in sorted(store.seen):
            if store.root in path.parents and path.name.startswith(".pending-"):
                _issue(issues, "MD_PENDING", path, store)
        if count >= MESSAGE_CAP:
            _issue(issues, "MD_CAP", store.root, store)
        return {"schema": SCHEMA, "mailbox": _display(store.root.name), "healthy": not issues,
                "cap": {"count": count, "limit": MESSAGE_CAP, "headroom": max(0, MESSAGE_CAP - count)},
                "lock": lock, "issues": issues, "index": index}


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise Refusal("MD_USAGE")


def _render(report, as_json):
    if as_json:
        print(json.dumps(report, sort_keys=True, ensure_ascii=True, allow_nan=False))
    elif "error" in report:
        print(report["error"]["code"] + ": " + report["error"]["message"])
    else:
        print("mailbox " + report["mailbox"] + ": " + ("healthy" if report["healthy"] else "problems found"))
        cap = report["cap"]
        print("messages: {count}/{limit}; headroom: {headroom}".format(**cap))
        lock = report["lock"]
        print("lock: " + lock["status"] + (" (pid " + str(lock["pid"]) + ")" if "pid" in lock else ""))
        for issue in report["issues"]:
            print(issue["code"] + ": " + issue["path"])
        print("index: " + report["index"]["status"])


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in args
    parser = _Parser(prog="hierarchy_mailbox_doctor.py", description=__doc__)
    parser.add_argument("mailbox_root")
    parser.add_argument("--json", action="store_true")
    try:
        options = parser.parse_args(args)
        if len(options.mailbox_root) > MAX_PATH_BYTES:
            raise Refusal("MD_LIMIT")
        if not Path(options.mailbox_root).is_absolute():
            raise Refusal("MD_USAGE")
        report = inspect_mailbox(options.mailbox_root)
        code = 0 if report["healthy"] else 1
    except Refusal as exc:
        report, code = {"schema": SCHEMA, "error": {"code": exc.code, "message": REFUSALS[exc.code]}}, 2
    except OSError as exc:
        refusal = "MD_PATH" if exc.errno in (errno.ELOOP, errno.ENOTDIR) else "MD_IO"
        report, code = {"schema": SCHEMA, "error": {"code": refusal, "message": REFUSALS[refusal]}}, 2
    except (*INVALID, NotImplementedError):
        report, code = {"schema": SCHEMA, "error": {"code": "MD_DATA", "message": REFUSALS["MD_DATA"]}}, 2
    try:
        _render(report, as_json)
    except (OSError, UnicodeError):
        return 2  # A broken output stream cannot carry a diagnostic document.
    return code


if __name__ == "__main__":
    sys.exit(main())
