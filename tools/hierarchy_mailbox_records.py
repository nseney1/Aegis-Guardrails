"""Opt-in D4 adapter. Only the code-recorded grant index authorizes record reads.

Errors use the codec's fixed envelopes: E_HASH for altered bytes, E_FORMAT for
stub/kind/retry conflicts, E_AUTH for attribution or scope mismatches, E_REF for
unresolved replies and E_LIMIT for history limits. No input
or exception text is copied into a refusal. The pinned mailbox remains v1.
"""
from contextlib import contextmanager, ExitStack
import errno
import importlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import uuid
from types import FunctionType


TOOLS = Path(__file__).resolve().parent
STUB = re.compile(r"aegis-record/1 sha256=([0-9a-f]{64}) kind=([a-z][a-z0-9.]*)")
MAX_CHARS = 60000
ROOT_MARKER = b"aegis.record-root/1\n"
NEXT_ACTIONS = {
    "binding": "refresh the connection from the current acknowledged endpoint binding",
    "reference": "cite only records sent, received or delegated to this endpoint",
    "cited_reference": "select fields without refs (e.g. body) or ask the sender to delegate the cited records",
    "lock": "inspect <parent>/.records-store.lock and <store>/.publish.lock for abandoned reservations before retrying",
    "mailbox_lock": "inspect the mailbox .write.lock before retrying",
    "scope": "choose a permitted route and message role for this endpoint",
    "identity": "restore the complete .root-id from a trusted backup; initialize a fresh root separately",
    "attribution": "read the original code-published stub for this record",
    "message_id": "choose a new message_id for this sender binding",
}
# Pinned ValueError vocabulary. Prefixes are explicit because paths/endpoints may follow them.
PINNED_REFUSALS = (
    ("route is not vertical or an explicit counterpart", "E_AUTH", "scope"),
    ("unknown endpoint: ", "E_AUTH", "scope"),
    ("only an orchestrator can dispatch its own lane", "E_AUTH", "scope"),
    ("only an orchestrator can request a job from its own root", "E_AUTH", "scope"),
    ("job receipt must come from root and reply to a job request", "E_AUTH", "scope"),
    ("reply endpoints do not reverse the referenced message", "E_AUTH", "scope"),
    ("message is in the wrong routing folder", "E_AUTH", "scope"),
    ("stale or mismatched sender binding", "E_AUTH", "binding"),
    ("mailbox manifest changed since server startup", "E_AUTH", "binding"),
    ("handoff checkpoint has not been acknowledged", "E_AUTH", "binding"),
    ("recipient has not acknowledged its handoff checkpoint", "E_AUTH", "binding"),
    ("endpoint has no session binding: ", "E_AUTH", "binding"),
    ("mailbox writer is busy; inspect an abandoned lock before retrying", "E_AUTH", "mailbox_lock"),
    ("symlink mailbox entry is not supported", "E_AUTH", None),
    ("symlink paths are not supported: ", "E_AUTH", None),
    ("referenced message does not exist", "E_REF", None),
    ("mailbox history limit reached", "E_LIMIT", "history"),
    ("mailbox exceeds record limit", "E_LIMIT", "history"),
    ("binding history exceeds record limit", "E_LIMIT", "history"),
    ("input exceeds 262144 bytes", "E_LIMIT", None),
    ("message exceeds 262144 bytes", "E_LIMIT", None),
)


def _pinned_error(codec, error, default="E_FORMAT"):
    text = str(error)
    for message, code, cause in PINNED_REFUSALS:
        if text == message or (message.endswith(": ") and text.startswith(message)):
            return codec.CodecError(code, detail=cause)
    return codec.CodecError(default, detail="binding" if default == "E_AUTH" else None)


def _error_result(error, *, publishing=False):
    result = error.as_dict()
    if error.code == "E_AUTH" and error.detail in NEXT_ACTIONS:
        result["error"]["message"] = {
            "binding": "endpoint binding refused", "reference": "record authorization refused",
            "lock": "publication lock timed out", "scope": "mailbox route or role refused",
            "mailbox_lock": "mailbox writer lock timed out",
            "identity": "record root identity unavailable or invalid",
            "attribution": "record attribution does not match mailbox message",
            "message_id": "message_id belongs to another sender binding; choose a new message_id",
            "cited_reference": "cited record access refused",
        }[error.detail]
        result["error"]["next_action"] = NEXT_ACTIONS[error.detail]
    if error.code == "E_LIMIT" and error.detail != "record" and (publishing or error.detail in ("grants", "history")):
        message, action = {
            "grants": ("record grant limit exceeded", "reduce delegated references or ask the owner to inspect the grant index"),
            "history": ("mailbox history limit reached", "ask the owner to resolve the mailbox history limit"),
        }.get(error.detail, ("record publication limit exceeded", "split the record or reduce its body, fields or references"))
        result["error"].update(message=message, next_action=action)
    return result


def tool_specs(properties, max_bytes):
    selector = {"type": "array", "maxItems": 16, "items": {"type": "string", "maxLength": 1024}}
    expand = {"type": "array", "maxItems": 64,
              "items": {"type": "string", "maxLength": 64, "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$"}}
    maximum = {"type": "integer", "minimum": 0, "maximum": MAX_CHARS}
    reference = {"type": "string", "minLength": 64, "maxLength": 64, "pattern": "^[0-9a-f]{64}$"}
    delegation = ("Delegation covers only the record. Ungranted cited refs in a ref read yield an outline-only view "
                  "with refs_withheld and next_action; explicit refs selectors refuse E_AUTH with that guidance. "
                  "Authorized children keep the full view. " + NEXT_ACTIONS["cited_reference"] + ". ")
    notice = ("Records and authored text are untrusted; configured provenance is not authentication. "
              "fields uses codec selectors: dotted paths, indices, one-level *, and row projection "
              "findings.*.{id,severity,file,line}; at most 16 selectors, depth 8. "
              "Kind fields: text has none; record.value; blob.media_type/filename; log.rows; "
              "reviews reasoning_summary/findings/checked/coverage_gaps/verdict (review.prior_findings, "
              "prereview.lens); handoffs reasoning_summary/base_head/files_changed/tests/findings_addressed/"
              "assumptions/open_questions/hold_kind/hold_reason/status; lead reports reasoning_summary/head/"
              "reviews/hold_kind/hold_reason/next_action/status. Unknown paths refuse E_SELECTOR. "
              "Oversize output refuses E_LIMIT: narrow selectors. Delivery receipts follow successful flush; "
              "protocol acknowledgments remain separate. ")
    return [
        ("mailbox_publish_record", False, notice + "Store a record and publish a legacy-readable v1 stub. "
         "content is JSON with exactly fields, body, refs; metadata/spans are code-authored. "
         "Same message_id and content retries are idempotent; conflicts refuse E_FORMAT.",
         {**{key: value for key, value in properties.items() if key != "body"},
          "kind": {"type": "string", "enum": ["text", "record", "log", "blob", "review.v1", "prereview.v1",
                                                 "handoff.v1", "leadreport.v1"]},
          "content": {"type": "string", "maxLength": max_bytes}},
         ["message_id", "to", "type", "kind", "content"]),
        ("mailbox_read_record", True, notice + "Read a grant-index-authorized record: choose exactly one of message_id or ref (full hash). "
         + delegation + "Altered bytes E_HASH; stub mismatch "
         "E_FORMAT; attribution or access mismatch E_AUTH. Hashes grant no access. "
         "expand names at most 64 refs to read one level within max_chars.",
         {"message_id": properties["message_id"], "ref": reference, "fields": selector, "outline": {"type": "boolean"},
          "expand": expand, "max_chars": maximum}, []),
        ("mailbox_digest", True, notice + "One row per new received message; ordinary messages retain body. "
         "after_message_id is exclusive. Other record errors refuse the entire result. " + delegation +
         "Outline fallback affects only that ref's records row; inbox rows remain visible. "
         "refs adds up to 64 full-hash grant-authorized records in records, using the same fields/outline and total limit. "
         "expand names at most 64 refs to read one level within max_chars.",
         {"after_message_id": properties["message_id"], "refs": {"type": "array", "maxItems": 64, "items": reference},
          "fields": selector, "outline": {"type": "boolean"}, "expand": expand, "max_chars": maximum,
          "limit": {"type": "integer", "minimum": 1, "maximum": 100}}, []),
    ]


def call(connection, name, arguments, writer_lock):
    if not connection.records:
        raise ValueError("unknown mailbox tool: " + name)
    try:
        codec = codec_tools()
    except RecursionError:
        return {"error": {"code": "E_FORMAT", "message": "invalid canonical message record"}}
    except (ValueError, OSError, ImportError, RuntimeError):
        return {"error": {"code": "E_AUTH", "message": "record codec unavailable from this checkout"}}
    try:
        _store_path(codec, connection.root)
        if name == "mailbox_publish_record":
            with writer_lock(connection.root):
                return publish(codec, _checked(codec, connection, ready=True), connection.sender, arguments)
        mailbox = _checked(codec, connection)
        operation = read if name == "mailbox_read_record" else digest
        result, returned = operation(codec, mailbox, connection.sender, arguments)
        connection.returned = returned
        return result
    except codec.CodecError as error:
        return _error_result(error, publishing=name == "mailbox_publish_record")
    except RecursionError:
        return codec.CodecError("E_FORMAT").as_dict()
    except (OSError, UnicodeError, RuntimeError):
        return codec.CodecError("E_AUTH").as_dict()
    except ValueError as error:
        return _error_result(_pinned_error(codec, error), publishing=name == "mailbox_publish_record")
    except (TypeError, KeyError):
        return codec.CodecError("E_FORMAT").as_dict()


def _checked(codec, connection, *, ready=False):
    try:
        return connection.checked_mailbox(ready=ready)
    except RecursionError:
        raise codec.CodecError("E_FORMAT") from None
    except ValueError as error:
        raise _pinned_error(codec, error, "E_AUTH") from None
    except (OSError, UnicodeError):
        raise codec.CodecError("E_AUTH") from None


def codec_tools():
    """Load only this checkout, including cached package attributes (lease_tools pattern)."""
    package = TOOLS.parent / "aegis_core"
    names = ("message_codec", "message_codec_format", "message_codec_store", "message_codec_views")
    error = ValueError("record codec unavailable from this checkout")

    def check():
        if package.resolve() != package:
            raise error
        expected = {"aegis_core": package / "__init__.py"}
        expected.update({"aegis_core." + name: package / (name + ".py") for name in names})
        for name, path in expected.items():
            if not path.is_file() or path.resolve() != path:
                raise error
        for name, module in tuple(sys.modules.items()):
            if name == "aegis_core" or name.startswith("aegis_core."):
                origin = getattr(module, "__file__", None)
                if origin is None:
                    raise error
                resolved = Path(origin).resolve()
                if not resolved.is_relative_to(package) or (name in expected and resolved != expected[name]):
                    raise error
                search = getattr(module, "__path__", None)
                if search is not None and tuple(Path(p).resolve() for p in search) != (resolved.parent,):
                    raise error
        loaded = sys.modules.get("aegis_core")
        for name in names:
            if loaded is not None and hasattr(loaded, name):
                module = sys.modules.get("aegis_core." + name)
                if module is None or getattr(loaded, name) is not module:
                    raise error

    check()
    root = str(TOOLS.parent)
    sys.path[:] = [root] + [entry for entry in sys.path if entry != root]
    codec = importlib.import_module("aegis_core.message_codec")
    check()
    return codec


def supported():
    capabilities = {function.__name__ for function in os.supports_dir_fd}
    nofollow = {function.__name__ for function in os.supports_follow_symlinks}
    return ({"open", "mkdir", "stat", "link", "unlink", "rename", "rmdir"} <= capabilities and "stat" in nofollow and
            hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW") and hasattr(os, "geteuid"))


@contextmanager
def record_store(codec, root, *, write=False, state=None):
    """Bind safe descriptors; serialize store lifetime and undo our refused initialization."""
    codec.require(supported(), "E_AUTH")
    path = _store_path(codec, root)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with ExitStack() as stack:
        parent = os.open(path.anchor, flags)
        stack.callback(os.close, parent)
        for component in path.parent.parts[1:]:
            parent = os.open(component, flags, dir_fd=parent)
            stack.callback(os.close, parent)
        lease = stack.enter_context(_publication_lock(codec, parent, ".records-store.lock")) if write else None
        created, identity, rootfd = None, None, None
        try:
            if write:
                try:
                    os.mkdir(path.name, mode=0o700, dir_fd=parent)
                    created = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                except FileExistsError:
                    pass
            directory = os.open(path.name, flags, dir_fd=parent)
            stack.callback(os.close, directory)
            expected = os.fstat(directory)
            codec.require(stat.S_ISDIR(expected.st_mode) and expected.st_uid == os.geteuid()
                          and not expected.st_mode & 0o022, "E_AUTH")
            _check_store_identity(codec, expected, root)
            store = codec.Store(path)
            stack.callback(store.close)
            actual = os.fstat(store.fd)
            codec.require((expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino), "E_AUTH")
            if write and state is not None:
                rootfd = stack.enter_context(_directory(codec, root))
                pending = ".pending-root-id"
                if _staged_exists(codec, rootfd, pending):
                    os.unlink(pending, dir_fd=rootfd)
                if _root_token(codec, rootfd) is None:
                    raw = ROOT_MARKER + uuid.uuid4().hex.encode("ascii") + b"\n"
                    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=rootfd)
                    try:
                        identity = os.fstat(fd)
                        with os.fdopen(fd, "wb", closefd=False) as stream:
                            stream.write(raw)
                            stream.flush()
                            os.fsync(fd)
                        os.link(pending, ".root-id", src_dir_fd=rootfd, dst_dir_fd=rootfd, follow_symlinks=False)
                        os.fsync(rootfd)
                    finally:
                        os.close(fd)
                        os.unlink(pending, dir_fd=rootfd)
            yield store
        finally:
            if state is not None and state["uncertain"]:
                lease["clean"] = False
            elif state is not None and not state["committed"]:
                try:
                    if identity is not None:
                        try:
                            current = os.stat(".root-id", dir_fd=rootfd, follow_symlinks=False)
                        except FileNotFoundError:
                            current = None
                        if current is not None and _is_root_or_ancestor(identity, (current,)):
                            os.unlink(".root-id", dir_fd=rootfd)
                            os.fsync(rootfd)
                    if created is not None:
                        try:
                            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                            if _is_root_or_ancestor(created, (current,)):
                                os.rmdir(path.name, dir_fd=parent)  # Parent lease excludes another first publisher.
                                os.fsync(parent)
                        except OSError as error:
                            if error.errno not in (errno.ENOENT, errno.ENOTEMPTY, errno.EEXIST):
                                raise
                except OSError:
                    lease["clean"] = False
                    raise


def _is_root_or_ancestor(store, ancestors):
    return any((store.st_dev, store.st_ino) == (item.st_dev, item.st_ino) for item in ancestors)


def _check_store_identity(codec, expected, root):
    # Walk real parents of the held root, including mount/alias identities, without resolving names.
    with _directory(codec, root) as directory:
        with ExitStack() as stack:
            while True:
                current = os.fstat(directory)
                codec.require(not _is_root_or_ancestor(expected, (current,)), "E_AUTH")
                parent = os.open("..", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                stack.callback(os.close, parent)
                info = os.fstat(parent)
                if _is_root_or_ancestor(info, (current,)):
                    break
                directory = parent


def _store_path(codec, root):
    root = Path(root)
    codec.require(root.is_absolute() and ".." not in root.parts, "E_AUTH")
    path = root.parent / "mailbox-records"
    def disjoint(left, right):
        return left != right and left not in right.parents and right not in left.parents
    # Lexical overlap is rejected without filesystem access. Resolve aliases only
    # for admission; all subsequent opens still walk with held no-follow descriptors.
    codec.require(disjoint(root, path), "E_AUTH")
    try:
        codec.require(disjoint(root.resolve(), path.resolve()), "E_AUTH")
    except (OSError, ValueError, RuntimeError):
        raise codec.CodecError("E_AUTH") from None
    return path


@contextmanager
def _directory(codec, path):
    codec.require(supported(), "E_AUTH")
    path = Path(path)
    codec.require(path.is_absolute() and ".." not in path.parts, "E_AUTH")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with ExitStack() as stack:
        fd = os.open(path.anchor, flags)
        stack.callback(os.close, fd)
        for component in path.parts[1:]:
            fd = os.open(component, flags, dir_fd=fd)
            stack.callback(os.close, fd)
        yield fd


def _root_token(codec, directory):
    """Only a complete atomic bundle is initialized; legacy remnants refuse."""
    try:
        try:
            os.stat(".records-root", dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("partial identity")
        try:
            fd = os.open(".root-id", os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=directory)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            maximum = len(ROOT_MARKER) + 33
            codec.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                          not info.st_mode & 0o022 and info.st_size == maximum)
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(maximum + 1)
            codec.require(len(raw) == maximum and raw.startswith(ROOT_MARKER))
            token = raw[len(ROOT_MARKER):]
            codec.require(re.fullmatch(rb"[0-9a-f]{32}\n", token))
            return token[:32].decode("ascii")
        finally:
            os.close(fd)
    except (OSError, ValueError, TypeError, RuntimeError):
        raise codec.CodecError("E_AUTH", detail="identity") from None


def _root_identity(codec, root):
    with _directory(codec, root) as directory:
        token = _root_token(codec, directory)
        return None if token is None else [Path(root).name, token]


@contextmanager
def _publication_lock(codec, directory, name=".publish.lock"):
    """Serialize commits/reclamation across all mailbox roots sharing this store.

    A failed reclamation leaves this fixed reservation for owner inspection; it
    cannot turn later refused requests into an unbounded series of orphan files.
    """
    codec.require(name in (".publish.lock", ".records-store.lock"), "E_AUTH")
    deadline = time.monotonic() + 5
    while True:
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            os.close(fd)
            break
        except FileExistsError:
            codec.require(time.monotonic() < deadline, "E_AUTH", detail="lock")
            time.sleep(0.01)
    lease = {"clean": True}
    try:
        yield lease
    finally:
        if lease["clean"]:
            os.unlink(name, dir_fd=directory)


def _index_bytes(codec, entry):
    # The index uses the codec's bounded generic record format, independently of payload files.
    return codec.canonical({"schema": "aegis.msg/1", "kind": "record", "meta": entry["author"],
                            "fields": {"value": entry}, "body": "", "refs": {}, "spans": []})


def _grant_entry(codec, store, rid):
    """One bounded, no-follow index read; missing and denied IDs have the same refusal."""
    codec.require(type(rid) is str and re.fullmatch(r"[0-9a-f]{64}", rid), "E_AUTH", detail="reference")
    try:
        fd = os.open(".grants-" + rid, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=store.fd)
        try:
            info = os.fstat(fd)
            codec.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                          not info.st_mode & 0o022 and info.st_size <= codec.MAX_BYTES, "E_AUTH", detail="reference")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(codec.MAX_BYTES + 1)
            codec.require(len(raw) == info.st_size and len(raw) <= codec.MAX_BYTES, "E_AUTH", detail="reference")
        finally:
            os.close(fd)
        envelope = codec.parse(raw)  # Codec preflights bytes, depth and nodes before parsing.
        entry = envelope["fields"]["value"]
        codec.require(envelope["kind"] == "record" and not envelope["body"] and
                      not envelope["refs"] and not envelope["spans"] and
                      type(entry) is dict and entry.keys() == {"schema", "id", "author", "kind", "grants"})
        codec.require(entry["schema"] == "aegis.record-grants/1" and entry["id"] == rid and
                      entry["kind"] in codec.KIND_SCHEMAS and entry["author"] == envelope["meta"])
        grants = entry["grants"]
        codec.require(type(grants) is list and 0 < len(grants) <= 1024)
        for row in grants:
            codec.require(type(row) is dict and {"root", "endpoint"} <= row.keys() <= {"root", "endpoint", "via"} and
                          type(row["root"]) is list and len(row["root"]) == 2 and
                          type(row["root"][0]) is str and 0 < len(row["root"][0]) <= 256 and
                          type(row["root"][1]) is str and re.fullmatch(r"[0-9a-f]{32}", row["root"][1]) and
                          type(row["endpoint"]) is str and 0 < len(row["endpoint"]) <= 256)
            codec.require("via" not in row or (type(row["via"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["via"])))
        return entry, raw
    except FileNotFoundError:
        return None, None
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        raise codec.CodecError("E_AUTH", detail="reference") from None


class _RecordAccess:
    """The grant index is authority; mailbox bodies are only locators, never grants."""
    def __init__(self, codec, store, root, sender, *, rollback=False):
        self.codec, self.store, self.endpoint = codec, store, sender["from"]
        self.original_read, self.cache = store.read, {}
        self.io = codec.Budget(codec.MAX_REF_BYTES)
        self.root = _root_identity(codec, root)
        # Read paths keep the authorization fact. Publication keeps entry and raw bytes.
        self.rollback, self.facts, self.entries, self.activations = rollback, {}, {}, {}
        # Per-instance bindings preserve the core's exact Store type contract.
        store.read, store.describe = self.read, self.describe

    def authorize(self, rid):
        codec = self.codec
        codec.require(self.root is not None, "E_AUTH", detail="reference")
        if rid not in self.facts:
            entry, raw = _grant_entry(codec, self.store, rid)
            allowed = entry is not None and self.permitted(entry, self.endpoint)
            if self.rollback:
                self.entries[rid] = (entry, raw)
            author = entry["author"] if allowed else None
            self.facts[rid] = None if not allowed else {
                "author": dict(author) if type(author) is dict else author, "kind": entry["kind"]}
        codec.require(self.facts[rid] is not None, "E_AUTH", detail="reference")
        return self.facts[rid]

    def permitted(self, entry, endpoint):
        direct = {"root": self.root, "endpoint": endpoint}
        if direct in entry["grants"]:
            return True
        for row in entry["grants"]:
            if row["root"] != self.root or row["endpoint"] != endpoint or "via" not in row:
                continue
            key = (row["via"], endpoint)
            if key not in self.activations:
                try:
                    wrapper, _raw = _grant_entry(self.codec, self.store, row["via"])
                except self.codec.CodecError:
                    wrapper = None  # An unprovable provisional row cannot revoke a separate complete grant.
                self.activations[key] = wrapper is not None and direct in wrapper["grants"]
            if self.activations[key]:
                return True
        return False

    def authorize_refs(self, value, options=None):
        ids = _reference_ids(self.codec, value, options)
        for rid in ids:
            self.authorize(rid)
        for rid in ids:
            self.read(rid)

    def read(self, rid, *, _budget=None):
        entry = self.authorize(rid)
        if rid not in self.cache:
            # Both the per-call I/O ceiling and the codec view's budget apply before reading.
            budget = self.codec.Budget(self.io.limit - self.io.used, parent=_budget)
            try:
                value = self.original_read(rid, _budget=budget)
            except self.codec.CodecError as error:
                if error.code == "E_REF":
                    raise self.codec.CodecError("E_AUTH", detail="reference") from None
                raise
            self.io.charge(budget.used)
            self.codec.require(value["meta"] == entry["author"] and value["kind"] == entry["kind"],
                               "E_AUTH", detail="reference")
            self.cache[rid] = (value, budget.used)
        else:
            value, size = self.cache[rid]
            if _budget is not None:
                _budget.charge(size)
        return self.cache[rid][0]

    def describe(self, rid, *, _budget=None):
        value = self.read(rid, _budget=_budget)
        return {"ref": rid[:16], "kind": value["kind"], "chars": self.cache[rid][1]}


def _grant_changes(codec, access, value, recipient):
    """Prepare complete replacement entries; only the locked commit writes them."""
    rid = codec.record_id(value)
    changes = []
    for target in sorted(set(value["refs"].values()) - {rid}) + [rid]:
        if target == rid:
            previous, raw = _grant_entry(codec, access.store, target)
            entry = {"schema": "aegis.record-grants/1", "id": rid, "author": value["meta"],
                     "kind": value["kind"], "grants": []} if previous is None else dict(previous, grants=list(previous["grants"]))
            codec.require(entry["author"] == value["meta"] and entry["kind"] == value["kind"], "E_AUTH", detail="reference")
            endpoints = (access.endpoint, recipient)
        else:
            previous, raw = access.entries[target]
            entry = dict(previous, grants=list(previous["grants"]))
            endpoints = (recipient,)
        for endpoint in endpoints:
            row = {"root": access.root, "endpoint": endpoint}
            if target != rid:
                if access.permitted(entry, endpoint):
                    continue
                row["via"] = rid
            if row not in entry["grants"]:
                codec.require(len(entry["grants"]) < 1024, "E_LIMIT", detail="grants")
                entry["grants"].append(row)
        try:
            updated = _index_bytes(codec, entry)
        except codec.CodecError as error:
            if error.code == "E_LIMIT":
                raise codec.CodecError("E_LIMIT", detail="grants") from None
            raise
        if updated != raw:
            changes.append((".grants-" + target, updated, raw))
    return changes


def _reference_ids(codec, value, options):
    if options is not None and options["outline"] and not (options["selectors"] or options["spans"] or
                                                          options["since"] is not None or options["expand"]):
        return set()
    if options is None or not options["selectors"]:
        return set(value["refs"].values())
    planned = codec.preflight_read(**options).planned
    paths = [path for path in planned if path[0] == "refs"]
    if any(len(path) == 1 or path[1] == "*" for path in paths):
        return set(value["refs"].values())
    names = {path[1] for path in paths} | set(options["expand"])
    return {value["refs"][name] for name in names if name in value["refs"]}


def _arguments(codec, arguments, required=(), optional=()):
    codec.require(type(arguments) is dict and set(required) <= arguments.keys() and
                  arguments.keys() <= set(required) | set(optional))


def _identifier(codec, value):
    from hierarchy_mailbox import SLUG
    codec.require(type(value) is str and len(value) <= 80 and SLUG.fullmatch(value), "E_REF")


def _options(codec, arguments):
    maximum = arguments.get("max_chars", MAX_CHARS)
    codec.require(type(maximum) is int and 0 <= maximum <= MAX_CHARS, "E_LIMIT")
    return codec.preflight_read(selectors=arguments.get("fields", ()), expand=arguments.get("expand", ()),
                                outline=arguments.get("outline", False), max_chars=maximum).options


def _references(codec, values):
    codec.require(type(values) in (list, tuple) and len(values) <= codec.MAX_REFS, "E_REF")
    for value in values:
        codec.require(type(value) is str and len(value) == 64 and re.fullmatch(r"[0-9a-f]{64}", value),
                      "E_AUTH", detail="reference")
    return values


def _content(codec, content):
    codec.require(type(content) is str)
    codec.require(len(content) <= codec.MAX_BYTES, "E_LIMIT", detail="record")
    try:
        raw = content.encode("utf-8")
    except UnicodeEncodeError:
        raise codec.CodecError("E_FORMAT") from None
    codec.require(len(raw) <= codec.MAX_BYTES, "E_LIMIT", detail="record")
    return raw


def _stub(codec, value):
    result = "aegis-record/1 sha256=" + codec.record_id(value) + " kind=" + value["kind"]
    verdict = value["fields"].get("verdict")
    if verdict is not None:
        # Closed schemas normally enforce this; also protect the signed single-line surface.
        codec.require(type(verdict) is str and not any(c in verdict for c in "\r\n"))
        result += "\nverdict: " + verdict
    return result


def _stub_id(codec, message):
    body = message["body"]
    codec.require(type(body) is str and len(body) <= 65536)
    match = STUB.fullmatch(body.split("\n", 1)[0])
    codec.require(match is not None)
    return match.group(1)


def _read(codec, store, message):
    value = store.read(_stub_id(codec, message))
    _check_stub(codec, value, message)
    return value


@contextmanager
def _reader(codec, root, message, sender):
    # Parsing and root scope precede store access, so a missing store behaves
    # like an empty store and a pristine root is never diagnosed as damaged.
    with _reference_store(codec, root, sender, (_stub_id(codec, message),)) as pair:
        yield pair


@contextmanager
def _reference_store(codec, root, sender, references):
    codec.require(_root_identity(codec, root) is not None, "E_AUTH", detail="reference")
    try:
        with record_store(codec, root) as store:
            access = _RecordAccess(codec, store, root, sender)
            for reference in references:
                access.authorize(reference)
            yield store, access
    except FileNotFoundError:
        raise codec.CodecError("E_AUTH", detail="reference") from None


def _check_stub(codec, value, message):
    codec.require(all(value["meta"][key] == message[key] for key in ("from", "host", "session")),
                  "E_AUTH", detail="attribution")
    codec.require(_stub(codec, value) == message["body"])


def _view(codec, store, message, options, access):
    value = _read(codec, store, message)
    return _value_view(codec, store, message, value, options, access)


def _value_view(codec, store, message, value, options, access):
    # Share read_view's record-specific validation without describing any child.
    codec._options(value, store=store, unknown={}, **options)
    if access is not None:
        access.authorize_refs(value, options)
    else:
        codec.require(not value["refs"], "E_AUTH", detail="reference")
    view = json.loads(codec.read_view(value, store=store, **options))
    if message is not None:
        view["mailbox_from"] = message["from"]
    view["attribution"] = "match" if message is not None else "grant-index"
    return view


def _reference_view(codec, store, access, reference, options):
    value = store.read(reference)
    # Share read_view's record-specific validation without describing any child.
    planned = codec._options(value, store=store, unknown={}, **options)
    try:
        for child in _reference_ids(codec, value, options):
            access.authorize(child)
    except codec.CodecError as error:
        if (error.code, error.detail) != ("E_AUTH", "reference"):
            raise
        if any(path[0] == "refs" for path in planned):
            raise codec.CodecError("E_AUTH", detail="cited_reference") from None
        outline = _options(codec, {"outline": True, "max_chars": options["max_chars"]})
        view = _value_view(codec, store, None, value, outline, access)
        view.update(refs_withheld=True, next_action=NEXT_ACTIONS["cited_reference"])
        return view
    return _value_view(codec, store, None, value, options, access)


def _digest_renderer(codec, maximum):
    renderer = importlib.import_module("aegis_core.message_codec_views").Renderer
    fmt = importlib.import_module("aegis_core.message_codec_format")
    return renderer(codec.require, fmt.escape_char, fmt.neutral_text, maximum)


def _bounded(codec, value, maximum):
    # Core's renderer accounts before allocating the final output and escapes controls.
    return _digest_renderer(codec, maximum).render(value, "json")


class _DigestSize:
    def __init__(self, codec, maximum):
        self.codec, self.maximum, self.total = codec, maximum, None
        self.renderer, self.counts = _digest_renderer(codec, maximum), {"messages": 0, "records": 0}

    def add(self, result, row, key):
        # Skeleton is measured after this row is built, so its refusal still precedes E_LIMIT.
        if self.total is None:
            self.total = self.renderer.json_size(result, self.maximum)
        extra = self.renderer.json_array_extra(row, self.counts[key] > 0, self.maximum)
        self.codec.require(self.total + extra <= self.maximum, "E_LIMIT")
        self.total += extra
        self.counts[key] += 1


def _staged_exists(codec, directory, name):
    try:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return False
    codec.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                  not info.st_mode & 0o022, "E_AUTH")
    return True


def _link_message(codec, pending, destination, name, state, store, changes):
    """Atomically replace each complete grant entry, then publish; undo definite failures."""
    applied, temporary, warning, staged = [], ".pending-grants", False, False
    try:
        for target, raw, previous in changes:
            if _staged_exists(codec, store.fd, temporary):
                os.unlink(temporary, dir_fd=store.fd)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=store.fd)
            staged = True
            try:
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
            applied.append((target, previous))
            os.rename(temporary, target, src_dir_fd=store.fd, dst_dir_fd=store.fd)
            staged = False
        os.fsync(store.fd)
        try:
            os.link(pending, name, src_dir_fd=destination, dst_dir_fd=destination, follow_symlinks=False)
        except OSError:
            state["uncertain"] = True
            try:
                source = os.stat(pending, dir_fd=destination, follow_symlinks=False)
                target = os.stat(name, dir_fd=destination, follow_symlinks=False)
            except FileNotFoundError:
                state["uncertain"] = False
                raise
            state["uncertain"] = False
            codec.require(stat.S_ISREG(target.st_mode) and
                          (source.st_dev, source.st_ino) == (target.st_dev, target.st_ino), "E_AUTH")
            warning = True
        state["committed"] = True
        return warning
    finally:
        try:
            if not state["committed"] and not state["uncertain"]:
                for target, previous in reversed(applied):
                    if previous is None:
                        try:
                            os.unlink(target, dir_fd=store.fd)
                        except FileNotFoundError:
                            pass
                    else:
                        if _staged_exists(codec, store.fd, temporary):
                            os.unlink(temporary, dir_fd=store.fd)
                        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=store.fd)
                        staged = True
                        try:
                            with os.fdopen(fd, "wb", closefd=False) as stream:
                                stream.write(previous)
                                stream.flush()
                                os.fsync(fd)
                        finally:
                            os.close(fd)
                        os.rename(temporary, target, src_dir_fd=store.fd, dst_dir_fd=store.fd)
                        staged = False
                os.fsync(store.fd)
            if staged and _staged_exists(codec, store.fd, temporary):
                os.unlink(temporary, dir_fd=store.fd)
        except (OSError, ValueError):
            state["uncertain"] = True
            raise


def _commit_record(codec, mailbox, sender, value, path, raw, state):
    """Pinned publish has accepted all semantics before entering this I/O boundary."""
    codec.require(type(raw) is bytes and len(raw) <= codec.MAX_BYTES, "E_LIMIT")
    codec.require(path.parent == mailbox.route(sender["from"], sender["to"]), "E_AUTH")
    rid, pending = codec.record_id(value), ".pending-stub"
    if _root_identity(codec, mailbox.root) is None:
        # A new root has no grants. Refuse refs and bound its default view before
        # allocating either the shared store or the root's atomic identity.
        options = _options(codec, {})
        _bounded(codec, _value_view(codec, None, sender, value, options, None), MAX_CHARS)
    with record_store(codec, mailbox.root, write=True, state=state) as store:
        with _publication_lock(codec, store.fd) as lease, _directory(codec, path.parent) as destination:
            access = _RecordAccess(codec, store, mailbox.root, sender, rollback=True)
            for reference in set(value["refs"].values()):
                access.authorize(reference)
            # Exactly the default read's accounting, including the wrapper itself.
            access.io.charge(len(codec.canonical(value)))
            options = _options(codec, {})
            _bounded(codec, _value_view(codec, store, sender, value, options, access), MAX_CHARS)
            changes = _grant_changes(codec, access, value, sender["to"])
            try:
                os.stat(rid + ".json", dir_fd=store.fd, follow_symlinks=False)
                existed = True
            except FileNotFoundError:
                existed = False
            created = warning = False
            try:
                if _staged_exists(codec, destination, pending):
                    os.unlink(pending, dir_fd=destination)
                fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=destination)
                created = True
                try:
                    # The raw fd remains ours even when fdopen or stream entry fails.
                    with os.fdopen(fd, "wb", closefd=False) as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(fd)
                finally:
                    os.close(fd)
                store.write(value)
                warning = _link_message(codec, pending, destination, path.name, state, store, changes)
            finally:
                if state["uncertain"]:
                    lease["clean"] = False
                try:
                    if not state["committed"] and not state["uncertain"] and not existed:
                        try:
                            os.unlink(rid + ".json", dir_fd=store.fd)
                        except FileNotFoundError:
                            pass
                    if created:
                        os.unlink(pending, dir_fd=destination)
                except OSError:
                    lease["clean"] = False
                    if not state["committed"]:
                        raise
        return warning or not lease["clean"]


def _accepted_publish(codec, mailbox, request, value):
    """Keep pinned validation bytecode, replacing only its final write binding.

    This per-call globals dictionary never patches the module or any other
    connection. The pinned hash and a contract test bind the single write seam.
    """
    invoked = warning = False
    state = {"committed": False, "uncertain": False}
    def commit(path, raw):
        nonlocal invoked, warning
        codec.require(not invoked)
        invoked = True
        try:
            warning = _commit_record(codec, mailbox, request, value, path, raw, state)
        except OSError:
            if not state["committed"]:
                raise
            warning = True
    publish = mailbox.publish
    function = publish.__func__
    bound = FunctionType(function.__code__, dict(function.__globals__, publish_file=commit),
                         function.__name__, function.__defaults__, function.__closure__)
    bound(mailbox, request)
    codec.require(invoked)
    return warning


def publish(codec, mailbox, sender, arguments):
    from hierarchy_mailbox import timestamp
    required = {"message_id", "to", "type", "kind", "content"}
    optional = {"brief", "in_reply_to", "acknowledgment", "readiness", "result", "receipt"}
    _arguments(codec, arguments, required, optional)
    _store_path(codec, mailbox.root)
    _identifier(codec, arguments["message_id"])
    raw = _content(codec, arguments["content"])
    # Compose before creating directories, even when there is no prior publication.
    meta = {key: sender[key] for key in ("from", "host", "session")}
    value = codec.compose(arguments["kind"], raw, dict(meta, created_at=timestamp()))
    request = {key: item for key, item in arguments.items() if key not in ("kind", "content")}
    request.update(sender, body=_stub(codec, value))
    mailbox.validate_message(request)
    mailbox.fence(request)
    history = mailbox.messages()
    previous = history.get(arguments["message_id"])
    if previous is not None:
        original = previous["message"]
        codec.require(all(original[key] == sender[key]
                          for key in ("from", "host", "session", "binding_generation")), "E_AUTH", detail="message_id")
        with _reader(codec, mailbox.root, original, sender) as (store, _access):
            stored = _read(codec, store, original)
            value = codec.compose(arguments["kind"], raw, dict(meta, created_at=stored["meta"]["created_at"]))
            request["body"] = _stub(codec, value)
            codec.require(all(original.get(k) == v for k, v in request.items()) and
                          set(original) - {"schema", "created_at", "authority", "verification"} == set(request))
            return {"id": codec.record_id(value), "message_id": original["message_id"]}
    warning = _accepted_publish(codec, mailbox, request, value)
    result = {"id": codec.record_id(value), "message_id": request["message_id"]}
    if warning:
        result["note"] = "message published; cleanup status uncertain; inspect store; do not retry publication"
    return result


def read(codec, mailbox, sender, arguments):
    _arguments(codec, arguments, (), {"message_id", "ref", "fields", "outline", "expand", "max_chars"})
    codec.require(("ref" in arguments) != ("message_id" in arguments))
    if "ref" in arguments:
        references = _references(codec, (arguments["ref"],))
        with _reference_store(codec, mailbox.root, sender, references) as (store, access):
            options = _options(codec, arguments)
            view = _reference_view(codec, store, access, references[0], options)
            return _bounded(codec, view, options["max_chars"]), []
    _identifier(codec, arguments["message_id"])
    messages = [row["message"] for row in mailbox.messages().values()]
    record = next((message for message in messages if message["message_id"] == arguments["message_id"]), None)
    codec.require(record is not None and sender["from"] in (record["from"], record["to"]), "E_AUTH", detail="reference")
    options = _options(codec, arguments)
    with _reader(codec, mailbox.root, record, sender) as (store, access):
        result = _bounded(codec, _view(codec, store, record, options, access), options["max_chars"])
    return result, [record["message_id"]] if record["to"] == sender["from"] else []


def digest(codec, mailbox, sender, arguments):
    _arguments(codec, arguments, (), {"after_message_id", "refs", "fields", "outline", "expand", "limit", "max_chars"})
    references = _references(codec, arguments.get("refs", ()))
    options = None if references else _options(codec, arguments)
    after = arguments.get("after_message_id")
    if after is not None:
        _identifier(codec, after)
    limit = arguments.get("limit", 20)
    codec.require(type(limit) is int and 1 <= limit <= 100, "E_LIMIT")
    messages = [row["message"] for row in mailbox.messages().values()]
    received = [message for message in messages if message["to"] == sender["from"]]
    ordered = sorted(received, key=lambda message: (message["created_at"], message["message_id"]))
    if after is not None:
        positions = [index for index, message in enumerate(ordered) if message["message_id"] == after]
        codec.require(bool(positions), "E_REF")
        ordered = ordered[positions[0] + 1:]
    selected = ordered[:limit]
    next_after = selected[-1]["message_id"] if len(ordered) > limit else None
    result = {"messages": [], "next_after": next_after}
    if "refs" in arguments:
        result["records"] = []
    with ExitStack() as stack:
        store = None
        if references:
            store, access = stack.enter_context(_reference_store(codec, mailbox.root, sender, references))
            options = _options(codec, arguments)
        accounted = _DigestSize(codec, options["max_chars"])
        for message in selected:
            row = {key: message[key] for key in ("message_id", "from", "type")}
            row["untrusted"] = True
            if message["body"].startswith("aegis-record/1"):
                if store is None:
                    store, access = stack.enter_context(_reader(codec, mailbox.root, message, sender))
                row["record"] = _view(codec, store, message, options, access)
            else:
                row["body"] = message["body"]
            # Account this row before retaining it or building the next one.
            accounted.add(result, row, "messages")
            result["messages"].append(row)
        for reference in references:
            row = _reference_view(codec, store, access, reference, options)
            accounted.add(result, row, "records")
            result["records"].append(row)
    return _bounded(codec, result, options["max_chars"]), [message["message_id"] for message in selected]
