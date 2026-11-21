"""Validated record publication, grant reads and bounded digest views.

The product mailbox supplies injected role/host tables and clock. The optional
inbox port measures transport recovery against an already validated history.
Legacy checkout loading and transport registration remain in the adapters.
"""
from contextlib import contextmanager, ExitStack
from copy import copy
import errno
from functools import partial
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import NamedTuple, Union
import uuid

from aegis_core import message_codec as codec_module
from aegis_core import team_mailbox_guidance as guidance
from aegis_core.diagnostic_messages import clip_rendered_text, guidance_value
from aegis_core.message_codec_format import escape_char, neutral_text
from aegis_core.message_codec_store import store_supported
from aegis_core.message_codec_views import Renderer
from aegis_core.team_mailbox import Mailbox
from aegis_core.team_mailbox_primitives import (
    render_mailbox_refusal,
    BusyError, MailboxRefusal, SLUG, fields, text, integer, require,
)
from aegis_core.team_mailbox_guidance import MAX_CHARS, NEXT_ACTIONS

__all__ = ["Records", "RecordRefusal", "RecordResult", "tool_specs"]
tool_specs = guidance.tool_specs
STUB = re.compile(r"aegis-record/1 sha256=([0-9a-f]{64}) kind=([a-z][a-z0-9.]*)")
ROOT_MARKER = b"aegis.record-root/1\n"
LOCK_WAIT_SECONDS = 5.0
LOCK_POLL_SECONDS = 0.01


class _RecordCodec:
    """Fixed codec interface; no imported namespace crosses request dispatch."""
    CodecError = codec_module.CodecError
    KIND_SCHEMAS = codec_module.KIND_SCHEMAS
    MAX_BYTES = codec_module.MAX_BYTES
    MAX_REFS = codec_module.MAX_REFS
    ReadContext = codec_module.ReadContext
    canonical = codec_module.canonical
    compose = codec_module.compose
    parse = codec_module.parse
    preflight_read = codec_module.preflight_read
    prepare_read = codec_module.prepare_read
    read_view = codec_module.read_view
    record_id = codec_module.record_id
    require = codec_module.require

    @staticmethod
    def Store(path):
        return codec_module.Store(path)


class RecordRefusal(MailboxRefusal):
    """Typed operational refusal retaining the codec's fixed wire envelope."""
    advice_contract = "record_codec"
    def __init__(self, error, tool):
        self.record_error = guidance.error_result(error, tool=tool, max_chars=MAX_CHARS)
        detail = self.record_error["error"]
        self.reason, self.code, self.status = error.code, 1, "refused"
        self.next_action = detail.get("next_action", {
            "E_FORMAT": "Supply a valid canonical record and matching retry arguments.",
            "E_HASH": "Restore the record bytes from trusted evidence.",
            "E_AUTH": "Use the current binding and granted record references.",
            "E_REF": "Use a validated existing message or record reference.",
            "E_SELECTOR": "Select fields present in the record schema.",
            "E_SPAN": "Select spans present in the validated record.",
            "E_LIMIT": "Reduce the record, selection or retained history.",
        }[error.code])
        ValueError.__init__(self, "record refused: " + self.reason)


class _PublicationStore:
    """Borrow storage; only this call's final message publication is injected."""
    def __init__(self, store, commit):
        self.store, self.commit = store, commit

    def __getattr__(self, name):
        return getattr(self.store, name)

    def publish(self, path, raw):
        return self.commit(path, raw)


class RecordResult(NamedTuple):
    """The payload and received message IDs from one successful operation."""
    payload: Union[dict, str]
    returned: tuple[str, ...] = ()


class Records:
    def __init__(self, mailbox, sender, *, inbox=None, monotonic=time.monotonic, sleep=time.sleep):
        fields(sender, {"from", "host", "session", "binding_generation"})
        for key in ("from", "host", "session"):
            text(sender[key], key, 256)
        integer(sender["binding_generation"], "binding generation")
        require(inbox is None or callable(inbox))
        require(callable(monotonic) and callable(sleep))
        self.mailbox, self.sender, self.inbox = mailbox, dict(sender), inbox
        self._wait = partial(_wait_for_lock, monotonic=monotonic, sleep=sleep)

    def call_with_result(self, name, arguments):
        """Return the payload and IDs together for transport delivery accounting."""
        return self.call(name, arguments, _with_result=True)

    def call(self, name, arguments, *, _with_result=False):
        """Return the original tool payload."""
        require(supported(), reason="unsupported_platform")
        require(type(name) is str and name in (
            "mailbox_publish_record", "mailbox_read_record", "mailbox_digest"))
        require(isinstance(self.mailbox, Mailbox))
        handlers = {"mailbox_publish_record": self._publish_record,
                    "mailbox_read_record": self._read_record, "mailbox_digest": self._digest}
        codec = _RecordCodec
        try:
            _arguments(codec, arguments, (), {"message_id", "to", "type", "kind", "content", "brief",
                "in_reply_to", "acknowledgment", "readiness", "result", "receipt", "ref", "refs", "fields",
                "outline", "expand", "max_chars", "after_message_id", "limit"})
            result = handlers[name](arguments)
            return result if _with_result else result.payload
        except MailboxRefusal as error:
            payload = render_mailbox_refusal(error)
            pinned = guidance.pinned_record_error(codec, payload["reason"])
            if pinned is not None:
                raise RecordRefusal(pinned, name) from None
            render_mailbox_refusal(error, reraise=True)
        except codec.CodecError as error:
            raise RecordRefusal(error, name) from None
        except RecursionError:
            raise RecordRefusal(codec.CodecError("E_FORMAT"), name) from None
        except (OSError, UnicodeError, RuntimeError):
            raise RecordRefusal(codec.CodecError("E_AUTH"), name) from None
        except (ValueError, KeyError):
            raise RecordRefusal(codec.CodecError("E_FORMAT"), name) from None

    def _publish_record(self, arguments):
        mailbox = self.mailbox
        mailbox.roles.authorize(mailbox.caller_role, "publish")
        # Acquire the owner reservation once before polling the mailbox reservation.
        with mailbox.store.evidence_transaction(), self._wait(lambda: mailbox.store.lock(mailbox.root)):
            mailbox.refresh()
            mailbox.fence(self.sender)
            result = publish(_RecordCodec, mailbox, self.sender, arguments, wait=self._wait)
        warnings = mailbox.store.drain_warnings()
        if warnings:
            result["warnings"] = result.get("warnings", []) + warnings
        return RecordResult(result)

    def _read_record(self, arguments):
        self.mailbox.refresh()
        self.mailbox.fence(self.sender, ready=False)
        result, returned = read(_RecordCodec, self.mailbox, self.sender, arguments)
        return RecordResult(result, tuple(returned))

    def _digest(self, arguments):
        self.mailbox.refresh()
        self.mailbox.fence(self.sender, ready=False)
        result, returned = digest(_RecordCodec, self.mailbox, self.sender, arguments, inbox=self.inbox)
        return RecordResult(result, tuple(returned))


@contextmanager
def _wait_for_lock(lock, *, monotonic=time.monotonic, sleep=time.sleep):
    """Retry acquisition only, with a fresh deadline for each reservation."""
    deadline = monotonic() + LOCK_WAIT_SECONDS
    with ExitStack() as stack:
        while True:
            try:
                lease = stack.enter_context(lock())
            except BusyError:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    raise
                sleep(min(LOCK_POLL_SECONDS, remaining))
                if monotonic() >= deadline:
                    raise
            else:
                break
        yield lease


def supported():
    return store_supported(publication=True)


@contextmanager
def record_store(codec, root, *, write=False, state=None, wait=_wait_for_lock):
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
        lease = stack.enter_context(wait(lambda: _publication_lock(codec, parent, ".records-store.lock"))) if write else None
        created = False
        created_identity = identity = rootfd = None
        try:
            if write:
                try:
                    os.mkdir(path.name, mode=0o700, dir_fd=parent)
                except FileExistsError:
                    pass
                else:
                    created = True
                    created_identity = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            directory = os.open(path.name, flags, dir_fd=parent)
            stack.callback(os.close, directory)
            expected = os.fstat(directory)
            codec.require(stat.S_ISDIR(expected.st_mode) and expected.st_uid == os.geteuid()
                          and not expected.st_mode & 0o022, "E_AUTH")
            codec.require(created_identity is None or _is_root_or_ancestor(created_identity, (expected,)), "E_AUTH")
            _check_store_identity(codec, expected, root)
            store = codec.Store(path)
            stack.callback(store.close)
            actual = os.fstat(store.fd)
            codec.require((expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino), "E_AUTH")
            # Release the inner lease before the rollback can remove a new store.
            with ExitStack() as publishing:
                if write and state is not None:
                    state["publication_lease"] = publishing.enter_context(wait(lambda: _publication_lock(codec, store.fd)))
                    rootfd = stack.enter_context(_directory(codec, root))
                    pending = ".pending-" + uuid.uuid4().hex
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
                    if created:
                        try:
                            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                            if created_identity is None or _is_root_or_ancestor(created_identity, (current,)):
                                # If the first stat failed, reconcile through the parent while peers are excluded.
                                codec.require(stat.S_ISDIR(current.st_mode) and current.st_uid == os.geteuid()
                                              and not current.st_mode & 0o022, "E_AUTH")
                                os.rmdir(path.name, dir_fd=parent)
                                os.fsync(parent)
                        except OSError as error:
                            if error.errno not in (errno.ENOENT, errno.ENOTEMPTY, errno.EEXIST):
                                raise
                except (OSError, codec.CodecError):
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
    except (OSError, ValueError, RuntimeError):
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
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
    except FileExistsError:
        raise BusyError() from None
    os.close(fd)
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
        with store.grant_directory() as bound:
            if bound is None:
                return None, None
            grantsfd, _ = bound
            try:
                fd = os.open(".grants-" + rid, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=grantsfd)
            except FileNotFoundError:
                return None, None
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
                      type(entry["kind"]) is str and entry["kind"] in codec.KIND_SCHEMAS and
                      entry["author"] == envelope["meta"])
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
    except (OSError, ValueError, KeyError, RuntimeError):
        raise codec.CodecError("E_AUTH", detail="reference") from None


class _RecordAccess:
    """The grant index is authority; mailbox bodies are only locators, never grants."""
    def __init__(self, codec, store, root, sender, *, rollback=False):
        self.codec, self.store, self.endpoint = codec, store, sender["from"]
        self.reader = codec.ReadContext(store, self.authorize)
        self.io = self.reader.io
        self.root = _root_identity(codec, root)
        # Read paths keep the authorization fact. Publication keeps entry and raw bytes.
        self.rollback, self.facts, self.entries, self.activations = rollback, {}, {}, {}

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
        return self.reader.read(rid, _budget=_budget)


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
    codec.require(type(value) is str and len(value) <= 80 and SLUG.fullmatch(value), "E_REF")


def _options(codec, arguments):
    maximum = arguments.get("max_chars", MAX_CHARS)
    codec.require(type(maximum) is int and 0 <= maximum <= MAX_CHARS, "E_LIMIT")
    return codec.preflight_read(selectors=arguments.get("fields", ()), expand=arguments.get("expand", ()),
                                outline=arguments.get("outline", False), max_chars=maximum).options


def _digest_options(codec, arguments):
    """Tag the existing max_chars refusal. The check stays inside _options."""
    try:
        return _options(codec, arguments)
    except codec.CodecError as error:
        if error.code == "E_LIMIT" and not error.detail:
            raise codec.CodecError("E_LIMIT", detail="digest_max_chars") from None
        raise


def _references(codec, values):
    codec.require(type(values) in (list, tuple) and len(values) <= codec.MAX_REFS, "E_REF")
    for value in values:
        codec.require(type(value) is str and len(value) == 64 and re.fullmatch(r"[0-9a-f]{64}", value),
                      "E_AUTH", detail="reference")
    return values


def _content(codec, content):
    codec.require(type(content) is str)
    codec.require(len(content) <= codec.MAX_BYTES, "E_LIMIT", detail="record")
    if not content.isascii():
        size = 0
        for char in content:
            point = ord(char)
            codec.require(not 0xD800 <= point <= 0xDFFF)
            size += 1 if point < 128 else 2 if point < 2048 else 3 if point < 65536 else 4
            codec.require(size <= codec.MAX_BYTES, "E_LIMIT", detail="record")
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


def _read(codec, access, message):
    value = access.read(_stub_id(codec, message))
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
    value = _read(codec, access, message)
    return _value_view(codec, store, message, value, options, access)


def _value_view(codec, store, message, value, options, access):
    # Share read_view's record-specific validation without describing any child.
    reader = access.reader if access is not None else store
    codec.prepare_read(value, store=reader, **options)
    if access is not None:
        access.authorize_refs(value, options)
    else:
        codec.require(not value["refs"], "E_AUTH", detail="reference")
    view = json.loads(codec.read_view(value, store=reader, **options))
    if message is not None:
        view["mailbox_from"] = message["from"]
    view["attribution"] = "match" if message is not None else "grant-index"
    return view


def _reference_view(codec, store, access, reference, options):
    value = access.read(reference)
    # Share read_view's record-specific validation without describing any child.
    planned = codec.prepare_read(value, store=access.reader, **options).planned
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
    return Renderer(codec.require, escape_char, neutral_text, maximum)


def _bounded(codec, value, maximum):
    # Core's renderer accounts before allocating the final output and escapes controls.
    return _digest_renderer(codec, maximum).render(value, "json")


def _staged_exists(codec, directory, name):
    try:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return False
    codec.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                  not info.st_mode & 0o022, "E_AUTH")
    return True


def _link_message(codec, pending, destination, name, state, grantsfd, check, changes):
    """Atomically replace each complete grant entry, then publish; undo definite failures."""
    applied, temporary, warning, staged = [], ".pending-" + uuid.uuid4().hex, False, False
    try:
        for target, raw, previous in changes:
            if _staged_exists(codec, grantsfd, temporary):
                os.unlink(temporary, dir_fd=grantsfd)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=grantsfd)
            staged = True
            try:
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
            applied.append((target, previous))
            os.rename(temporary, target, src_dir_fd=grantsfd, dst_dir_fd=grantsfd)
            staged = False
        os.fsync(grantsfd)
        check()
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
                            os.unlink(target, dir_fd=grantsfd)
                        except FileNotFoundError:
                            pass
                    else:
                        if _staged_exists(codec, grantsfd, temporary):
                            os.unlink(temporary, dir_fd=grantsfd)
                        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=grantsfd)
                        staged = True
                        try:
                            with os.fdopen(fd, "wb", closefd=False) as stream:
                                stream.write(previous)
                                stream.flush()
                                os.fsync(fd)
                        finally:
                            os.close(fd)
                        os.rename(temporary, target, src_dir_fd=grantsfd, dst_dir_fd=grantsfd)
                        staged = False
                os.fsync(grantsfd)
            if staged and _staged_exists(codec, grantsfd, temporary):
                os.unlink(temporary, dir_fd=grantsfd)
        except (OSError, ValueError):
            state["uncertain"] = True
            raise


def _commit_record(codec, mailbox, sender, value, path, raw, state, wait):
    """Mailbox publish validates semantics before entering this I/O boundary."""
    codec.require(type(raw) is bytes and len(raw) <= codec.MAX_BYTES, "E_LIMIT")
    codec.require(path.parent == mailbox.route(sender["from"], sender["to"]), "E_AUTH")
    pending = ".pending-" + uuid.uuid4().hex
    state["stage"] = path.parent / pending
    if _root_identity(codec, mailbox.root) is None:
        # A new root has no grants. Refuse refs and bound its default view before
        # allocating either the shared store or the root's atomic identity.
        options = _options(codec, {})
        _bounded(codec, _value_view(codec, None, sender, value, options, None), MAX_CHARS)
    with record_store(codec, mailbox.root, write=True, state=state, wait=wait) as store:
        lease = state["publication_lease"]
        with _directory(codec, path.parent) as destination:
            access = _RecordAccess(codec, store, mailbox.root, sender, rollback=True)
            for reference in set(value["refs"].values()):
                access.authorize(reference)
            # Exactly the default read's accounting, including the wrapper itself.
            access.io.charge(len(codec.canonical(value)))
            options = _options(codec, {})
            _bounded(codec, _value_view(codec, store, sender, value, options, access), MAX_CHARS)
            changes = _grant_changes(codec, access, value, sender["to"])
            publication = store.begin_publication()
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
                store.write(value, publication=publication)
                try:
                    with store.grant_directory(publication=publication) as (grantsfd, check):
                        try:
                            warning = _link_message(codec, pending, destination, path.name, state, grantsfd, check, changes)
                        except OSError:
                            raise codec.CodecError("E_AUTH") from None
                except (OSError, codec.CodecError):
                    if not state["committed"]:
                        raise
                    state["uncertain"] = True  # The link is final. Keep both reservations for inspection.
            finally:
                if state["uncertain"]:
                    lease["clean"] = False
                try:
                    if not state["committed"] and not state["uncertain"]:
                        store.rollback(publication)
                    if created:
                        os.unlink(pending, dir_fd=destination)
                except (OSError, codec.CodecError):
                    lease["clean"] = False
                    if not state["committed"]:
                        state["uncertain"] = True
                        raise
        return warning or not lease["clean"]


def _accepted_publish(codec, mailbox, request, value, wait):
    """Reuse the public mailbox validator with a per-call publication port."""
    invoked = warning = False
    state = {"committed": False, "uncertain": False}
    def commit(path, raw):
        nonlocal invoked, warning
        codec.require(not invoked)
        invoked = True
        try:
            warning = _commit_record(codec, mailbox, request, value, path, raw, state, wait)
        except codec.CodecError as error:
            # Preserve record codes through Mailbox.publish's ValueError normalizer.
            raise RecordRefusal(error, "mailbox_publish_record") from None
        except OSError:
            if not state["committed"]:
                raise RecordRefusal(codec.CodecError("E_AUTH"), "mailbox_publish_record") from None
            warning = True
    view = copy(mailbox)
    view.store = _PublicationStore(mailbox.store, commit)
    result = view.publish(request)
    codec.require(invoked)
    return warning, result.get("warnings", []), state["stage"], state["uncertain"]


def publish(codec, mailbox, sender, arguments, *, wait=_wait_for_lock):
    required = {"message_id", "to", "type", "kind", "content"}
    optional = {"brief", "in_reply_to", "acknowledgment", "readiness", "result", "receipt"}
    _arguments(codec, arguments, required, optional)
    _store_path(codec, mailbox.root)
    _identifier(codec, arguments["message_id"])
    raw = _content(codec, arguments["content"])
    # Compose before creating directories, even when there is no prior publication.
    meta = {key: sender[key] for key in ("from", "host", "session")}
    value = codec.compose(arguments["kind"], raw, dict(meta, created_at=mailbox.timestamp()))
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
            stored = _read(codec, _access, original)
            value = codec.compose(arguments["kind"], raw, dict(meta, created_at=stored["meta"]["created_at"]))
            request["body"] = _stub(codec, value)
            codec.require(all(original.get(k) == v for k, v in request.items()) and
                          set(original) - {"schema", "created_at", "authority", "verification"} == set(request))
            return {"id": codec.record_id(value), "message_id": original["message_id"]}
    warning, warnings, stage, cleanup_uncertain = _accepted_publish(codec, mailbox, request, value, wait)
    result = {"id": codec.record_id(value), "message_id": request["message_id"]}
    if warnings:
        result["warnings"] = warnings
    if cleanup_uncertain:
        result["note"] = ("Message published. The owner should inspect staging and both reservations. "
                          "Once cleanup is verified, clear an abandoned <store>/.publish.lock first, "
                          "then an abandoned <parent>/.records-store.lock. Check history before publishing again.")
    elif warning:
        # Redact the untrusted parent; the generated staging identifier stays usable.
        parent = guidance_value(str(stage.parent), 512)
        parent = clip_rendered_text(parent, 512)
        result["note"] = ("message published; cleanup status uncertain; owner: inspect "
                          + parent.rstrip("/") + "/" + stage.name
                          + "; remove only the leftover staging file if present, then read history and "
                          "retry the same message_id; inspect the retained <store>/.publish.lock "
                          "before a new publication")
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


def digest(codec, mailbox, sender, arguments, *, inbox):
    _arguments(codec, arguments, (), {"after_message_id", "refs", "fields", "outline", "expand", "limit", "max_chars"})
    references = _references(codec, arguments.get("refs", ()))
    # No explicit ref: options before cursor and page limit.
    # Explicit refs: authorize first; options after that grant check.
    options = None if references else _digest_options(codec, arguments)
    after = arguments.get("after_message_id")
    if after is not None:
        _identifier(codec, after)
    limit = arguments.get("limit", 20)
    codec.require(type(limit) is int and 1 <= limit <= 100, "E_LIMIT", detail="digest_limit")
    history = mailbox.messages()
    messages = [row["message"] for row in history.values()]
    received = [message for message in messages if message["to"] == sender["from"]]
    ordered = sorted(received, key=lambda message: (message["created_at"], message["message_id"]))
    if after is not None:
        positions = [index for index, message in enumerate(ordered) if message["message_id"] == after]
        codec.require(bool(positions), "E_REF")
        ordered = ordered[positions[0] + 1:]
    selected = ordered[:limit]
    failure = (None, None, 0, 0)
    with ExitStack() as stack:
        reader = [None, None]
        if references:
            reader[:] = stack.enter_context(_reference_store(codec, mailbox.root, sender, references))
            options = _digest_options(codec, arguments)

        def row(item, chosen, key):
            if key == "records":
                return _reference_view(codec, *reader, item, chosen)
            value = {key: item[key] for key in ("message_id", "from", "type")}
            value["untrusted"] = True
            if item["body"].startswith("aegis-record/1"):
                if reader[0] is None:
                    reader[:] = stack.enter_context(_reader(codec, mailbox.root, item, sender))
                value["record"] = _view(codec, reader[0], item, chosen, reader[1])
            else:
                value["body"] = item["body"]
            return value

        def probe(tool, edits):
            key, item, _messages, _references = failure
            if tool == "mailbox_inbox":
                codec.require(inbox is not None, "E_AUTH")
                retry = {"limit": 100}
                if after is not None:
                    retry["after_message_id"] = after
                try:
                    return inbox(retry, item["message_id"], history)
                except MailboxRefusal as error:
                    render_mailbox_refusal(error)
                    return None
            chosen = _options(codec, dict(arguments, **edits))
            if tool == "mailbox_read_record":
                view = row(item, chosen, "messages")["record"] if key == "messages" else row(item, chosen, "records")
                return _bounded(codec, view, chosen["max_chars"])
            count = edits.get("limit", limit)
            next_after = ordered[count - 1]["message_id"] if len(ordered) > count else None
            return guidance.render_digest(codec, _digest_renderer, chosen, ordered[:count], next_after,
                                          references, "refs" in arguments, row)

        try:
            next_after = selected[-1]["message_id"] if len(ordered) > limit else None
            rendered = guidance.render_digest(codec, _digest_renderer, options, selected, next_after,
                                              references, "refs" in arguments, row)
        except codec.CodecError as error:
            if error.code != "E_LIMIT" or error.detail not in ("", "digest_floor", "digest_page", "digest_view", "digest_inbox"):
                raise
            failure = getattr(error, "digest_failure", (None, None, 0, 0))
            raise guidance.measured_refusal(codec, error, options["max_chars"], probe,
                                             failure=failure) from None
    return rendered, [message["message_id"] for message in selected]
