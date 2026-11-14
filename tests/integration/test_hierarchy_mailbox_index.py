"""In-process mailbox memo: fail-closed parity, incremental reads and no writes."""
import ast
import hashlib
import importlib
import gc
import io
import errno
import os
from pathlib import Path
import statistics
import shutil
import subprocess
import sys
import time
import tracemalloc
import weakref
from concurrent.futures import ThreadPoolExecutor
from copy import copy
from functools import partial
import inspect
from unittest import mock
from types import SimpleNamespace

import pytest

from tools import hierarchy_mailbox as hm


def index_module():
    return importlib.import_module("tools.hierarchy_mailbox_index")


def test_read_counters_cover_index_imports():
    # Read this tracked source plainly on every host. Counter adapters own only
    # hm.Path and module.os; new reader imports need corresponding interception.
    tree = ast.parse(Path(index_module().__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not any(alias.name in {"builtins", "io", "pathlib"} for alias in node.names), (
                "read counters do not cover this import: " + ast.dump(node))
        elif isinstance(node, ast.ImportFrom):
            assert node.module not in {"builtins", "io"}, (
                "read counters do not cover this import: " + ast.dump(node))
            if node.module == "pathlib":
                assert all(alias.name == "Path" and alias.asname in (None, "Path") for alias in node.names), (
                    "read counters require the canonical Path import: " + ast.dump(node))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "open", "read counters do not cover builtin open"


def require_posix_reuse():
    if not index_module()._checked_reads_supported():
        pytest.skip("requires POSIX checked reads and keyed validation/access reuse")


@pytest.fixture
def posix_reuse():
    require_posix_reuse()


def test_platform_guard_uses_capability_probe(monkeypatch):
    monkeypatch.setattr(index_module(), "_checked_reads_supported", lambda: False)
    with pytest.raises(pytest.skip.Exception, match="requires POSIX checked reads"):
        require_posix_reuse()


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("api", ["messages", "get", "inbox", "verify"])
@pytest.mark.parametrize("boundary", ["nt", "no_nofollow", "unsupported_probe"])
def test_platform_without_checked_reads_hashes_and_validates(mailbox, monkeypatch, mode, api, boundary):
    module = index_module()
    mailbox.publish(request("second"))
    real_fstat = os.fstat

    def fstat(descriptor):
        value = real_fstat(descriptor)
        return SimpleNamespace(st_mode=value.st_mode, st_size=value.st_size,
                               st_mtime_ns=value.st_mtime_ns, st_ctime_ns=value.st_ctime_ns,
                               st_ino=0, st_dev=0)

    def unavailable(*args, **kwargs):
        raise NotImplementedError("descriptor primitive unavailable")

    overrides = {"fstat": fstat}
    if boundary == "no_nofollow":
        overrides.update(O_NOFOLLOW=0, open=unavailable)
    elif boundary == "unsupported_probe":
        monkeypatch.setattr(module, "_checked_reads_supported", lambda: False)
        overrides["open"] = unavailable
    monkeypatch.setattr(module, "os", PlatformOS("nt" if boundary == "nt" else os.name,
                                                base=module.os, **overrides))
    index = module.MailboxIndex(mailbox, mode=mode)
    records = index.messages()
    assert records == mailbox.messages() and index.last_reconciliation is None
    source = Path(records["seed"]["path"])
    old_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    expected = ([] if api == "verify" else records if api == "messages" else records["seed"]
                if api == "get" else mailbox.inbox("a/lane/review"))
    assert invoke(index, api) == expected
    assert index.last_reconciliation is None
    rewrite(source, {**records["seed"]["message"], "body": "modified body"})
    assert index.verify() == [{"kind": "content_changed", "path": str(source), "old_sha256": old_sha,
                               "new_sha256": hashlib.sha256(source.read_bytes()).hexdigest()}]
    assert index.verify() == []
    rewrite(source, {**records["seed"]["message"], "type": "evil"})
    assert caught(lambda: invoke(index, api)) == caught(mailbox.messages)


class PlatformOS:
    """Override a platform boundary without replacing the rest of the OS API."""
    def __init__(self, name, *, base, **overrides):
        self.name = name
        self._base = base
        self.__dict__.update(overrides)

    def __getattr__(self, name):
        return getattr(self._base, name)


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("mutation", ["body", "format"])
def test_platform_fallback_retains_observed_sha(mailbox, monkeypatch, mode, mutation):
    module = index_module()
    monkeypatch.setattr(module, "_checked_reads_supported", lambda: False)
    index = module.MailboxIndex(mailbox, mode=mode)
    record = index.messages()["seed"]
    source = Path(record["path"])
    original = source.read_bytes()
    old_sha = hashlib.sha256(original).hexdigest()
    if mutation == "body":
        rewrite(source, {**record["message"], "body": "modified body"})
    else:
        source.write_bytes(b"---\n " + original[4:])
    new_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    real_os = module.os
    denied = []

    def scandir(path):
        if not denied:
            denied.append(True)
            raise PermissionError(errno.EACCES, "injected listing denial")
        return real_os.scandir(path)

    monkeypatch.setattr(module, "os", PlatformOS(real_os.name, base=real_os, scandir=scandir))
    assert index.messages() == mailbox.messages()
    assert denied and index.last_reconciliation["kind"] == "pinned_fallback"
    assert index.content_changed == [{"kind": "content_changed", "path": str(source),
                                      "old_sha256": old_sha, "new_sha256": new_sha}]
    source.write_bytes(original)
    changes = index.verify()
    assert {"kind": "content_changed", "path": str(source), "old_sha256": old_sha,
            "new_sha256": old_sha} in changes


def request(identifier, sender="a/orchestrator", recipient="a/lane/review", **extra):
    return {"message_id": identifier, "from": sender, "to": recipient,
            "host": "test-host", "session": sender, "binding_generation": 1,
            "type": "info", "body": "original body", **extra}


@pytest.fixture
def mailbox(tmp_path):
    root = tmp_path / "mailbox"
    manifest = {"schema": "aegis.hierarchy-pilot/v1", "writer_limit": 3,
                "endpoints": {"a/front-door": {}, "a/orchestrator": {}, "a/root": {},
                              "a/lane/review": {"kind": "reviewer"}}, "counterparts": []}
    hm.initialize(root, manifest)
    box = hm.Mailbox(root)
    for endpoint in manifest["endpoints"]:
        box.bind({"endpoint": endpoint, "host": "test-host", "session": endpoint,
                  "expected_generation": 0})
    box.publish(request("seed"))
    return box


def caught(call):
    try:
        call()
    except Exception as exc:
        return type(exc), str(exc)
    pytest.fail("expected a fail-closed exception")


def _warm_mailbox_reader(mailbox, mode):
    """Exercise the reader on a scratch mailbox so one-time caches stay outside the trace.

    The scratch root is a sibling of the measured mailbox. The measured seed is untouched.
    """
    root = mailbox.root.parent / ("_warm_index_" + mode)
    manifest = {"schema": "aegis.hierarchy-pilot/v1", "writer_limit": 3,
                "endpoints": {"a/front-door": {}, "a/orchestrator": {}, "a/root": {},
                              "a/lane/review": {"kind": "reviewer"}}, "counterparts": []}
    hm.initialize(root, manifest)
    box = hm.Mailbox(root)
    for endpoint in manifest["endpoints"]:
        box.bind({"endpoint": endpoint, "host": "test-host", "session": endpoint,
                  "expected_generation": 0})
    box.publish(request("warm-seed"))
    index = index_module().MailboxIndex(box, mode=mode)
    seed = index.messages()["warm-seed"]
    path = Path(seed["path"])
    path.write_bytes(b"malformed A")
    caught(lambda: index.get("warm-seed"))
    caught(box.messages)
    brief = {"path": "/" + "a/" * 300 + "x.md", "sha256": "a" * 64}
    rewrite(path, {**seed["message"], "brief": brief})
    caught(index.messages)
    brief = {"path": "../../../outside/secret.md", "sha256": "a" * 64}
    rewrite(path, {**seed["message"], "brief": brief})
    caught(index.messages)


def assert_fallback_verification(index, expected):
    """Canonical returns preserve observed facts while disclaiming PIN bytes."""
    first = index.verify()
    facts = [item for item in first if item["kind"] == "content_changed"]
    assert sorted(facts, key=lambda item: item["path"]) == sorted(expected, key=lambda item: item["path"])
    markers = [item for item in first if item["kind"] == "verification_unavailable"]
    assert len(markers) == 1 and markers[0]["reason"] == "baseline_unavailable"
    assert markers[0]["scope"] == "all_returned_records"
    assert len(first) == len(expected) + 1
    # Unavailable verification cannot acknowledge even fully observed facts.
    complete = index.verify()
    assert sorted(complete, key=lambda item: item["path"]) == sorted(expected, key=lambda item: item["path"])
    assert index.verify() == []


def rewrite(path, message):
    header = {key: value for key, value in message.items() if key != "body"}
    path.write_bytes(b"---\n" + hm.encoded(header) + b"\n---\n\n" + message["body"].encode())


def symlink(link, target):
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError) as exc:
        pytest.skip("symlink capability unavailable: %s" % exc)


def snapshot(root):
    result = {}
    for path in sorted(root.rglob("*")):
        key = str(path.relative_to(root))
        result[key] = ("symlink", os.readlink(path)) if path.is_symlink() else (
            "directory" if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest())
    return result


def invoke(index, api):
    if api == "get":
        return index.get("seed")
    if api == "inbox":
        return index.inbox("a/lane/review")
    return getattr(index, api)()


def intercept_source_opens(monkeypatch, action):
    """Apply an OS access condition to both pinned and descriptor-based reads."""
    real_path_open, real_os_open = Path.open, os.open

    def path_open(path, *args, **kwargs):
        action(path)
        return real_path_open(path, *args, **kwargs)

    def os_open(path, *args, **kwargs):
        action(Path(path))
        return real_os_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", path_open)
    monkeypatch.setattr(os, "open", os_open)


class MemoTrace:
    """Test-only memo diagnostics; no extra filesystem observations or writes."""
    def __init__(self, monkeypatch, mailbox):
        module = index_module()
        self.events, self.validations, self.memo_validations, self.in_scan = [], 0, 0, 0
        self.above_root = {str(path) for path in mailbox.root.parents}
        real_clear, real_scan = module.MailboxIndex._clear, module.MailboxIndex._scan
        real_observations = module._Observations.__init__
        real_validate = mailbox.validate_message

        def clear(index):
            caller = sys._getframe(1)
            error = caller.f_locals.get("error")
            self.events.append({"kind": "clear", "caller": caller.f_code.co_name,
                                "records": len(getattr(index, "_entries", {})),
                                "reason": None if error is None else
                                {"type": type(error).__name__, "message": str(error)}})
            return real_clear(index)

        def observations(observed, previous):
            real_observations(observed, previous)
            for path in sorted(observed.changed.intersection(previous)):
                old, new = previous[path], observed.values[path]
                current = new if new is not None else old
                fields = (("device", "inode", "mode", "uid") if current is not None and len(current) == 4
                          else ("inode", "mode", "uid", "size", "mtime_ns", "ctime_ns", "device"))
                changed = list(fields) if old is None or new is None else [
                    field for field, left, right in zip(fields, old, new) if left != right]
                self.events.append({"kind": "observation_changed", "path": path,
                                    "fields": changed, "old": old, "new": new})
            if observed.unknown:
                self.events.append({"kind": "unknown_observations", "paths": sorted(observed.unknown)})

        def scan(index, force):
            context, layout = index._context, index._folder_layout
            self.in_scan += 1
            try:
                result = real_scan(index, force)
                if context != result[5]:
                    fields = ("root", "manifest", "max_bytes", "credentials")
                    changed = list(fields) if context is None else [
                        field for field, old, new in zip(fields, context, result[5]) if old != new]
                    self.events.append({"kind": "context_changed", "fields": changed,
                                        "old": context, "new": result[5]})
                return result
            except Exception as error:
                self.events.append({"kind": "scan_error", "type": type(error).__name__,
                                    "message": str(error)})
                raise
            finally:
                self.in_scan -= 1
                if layout is not index._folder_layout:
                    self.events.append({"kind": "layout_refresh", "key":
                                        None if index._folder_layout is None else index._folder_layout[0]})

        def validate(message, **kwargs):
            self.validations += 1
            self.memo_validations += bool(self.in_scan)
            return real_validate(message, **kwargs)

        monkeypatch.setattr(module.MailboxIndex, "_clear", clear)
        monkeypatch.setattr(module.MailboxIndex, "_scan", scan)
        monkeypatch.setattr(module._Observations, "__init__", observations)
        monkeypatch.setattr(mailbox, "validate_message", validate)

    def reset(self):
        self.events.clear()
        self.validations = 0
        self.memo_validations = 0


class ReadCounts:
    """Count actual lstat calls once, including Python 3.9's pathlib boundary."""
    def __init__(self, monkeypatch, trace):
        self.lstats, self.memo_lstats, self.opens, self.depth = {}, {}, [], 0
        real_lstat, real_os_lstat, real_open, real_os_open = Path.lstat, os.lstat, io.open, os.open

        def count(path):
            path = os.fspath(path)
            self.lstats[path] = self.lstats.get(path, 0) + 1
            if trace.in_scan and path not in trace.above_root:
                self.memo_lstats[path] = self.memo_lstats.get(path, 0) + 1

        def lstat(path, *args, **kwargs):
            count(path)
            self.depth += 1
            try:
                return real_lstat(path, *args, **kwargs)
            finally:
                self.depth -= 1

        def os_lstat(path, *args, **kwargs):
            if not self.depth:
                count(path)
            return real_os_lstat(path, *args, **kwargs)

        def opened(path, *args, **kwargs):
            if not isinstance(path, int):
                self.opens.append(os.fspath(path))
            return real_open(path, *args, **kwargs)

        def os_open(path, *args, **kwargs):
            self.opens.append(os.fspath(path))
            return real_os_open(path, *args, **kwargs)

        monkeypatch.setattr(Path, "lstat", lstat)
        monkeypatch.setattr(os, "lstat", os_lstat)
        monkeypatch.setattr(io, "open", opened)
        monkeypatch.setattr(os, "open", os_open)

    def reset(self):
        self.lstats.clear()
        self.memo_lstats.clear()
        self.opens.clear()


def prepare_ac1(mailbox, first="messages"):
    records = mailbox.messages()
    identifier = next(iter(records))
    endpoint = records[identifier]["message"]["to"]
    # Oracle preparation may outlast the memo's observations in a shared tree.
    # Finish it before warming the API that the measurement will follow.
    expected_inbox = mailbox.inbox(endpoint, limit=20)
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    if first == "get":
        index.get(identifier)
    elif first == "inbox":
        index.inbox(endpoint, limit=20)
    else:
        index.messages()
    return index, records, identifier, endpoint, expected_inbox


DEFECTS = ["missing_header", "bad_json", "duplicate_key", "nonfinite", "utf8", "unknown_field",
           "invalid_type", "wrong_folder", "duplicate_id", "missing_reply", "reverse_reply",
           "non_md", "symlink", "pending_symlink", "directory_entry", "oversized_message",
           "missing_folder", "folder_symlink", "unencodable_brief_path"]


def inject(box, defect):
    seed = box.messages()["seed"]
    original = Path(seed["path"])
    path = original.parent / "zz-bad.md"
    message = {**seed["message"], "message_id": "bad"}
    raw = {"missing_header": b"hello", "bad_json": b"---\n{\n---\n\nbody",
           "duplicate_key": b'---\n{"x":1,"x":2}\n---\n\nbody',
           "nonfinite": b'---\n{"x":NaN}\n---\n\nbody', "utf8": b"\xff",
           "oversized_message": b"x" * (hm.MAX_BYTES + 1)}
    if defect in raw:
        path.write_bytes(raw[defect])
    elif defect == "unknown_field":
        rewrite(path, {**message, "surprise": True})
    elif defect == "invalid_type":
        rewrite(original, {**seed["message"], "type": "invalid-type"})
    elif defect == "unencodable_brief_path":
        rewrite(path, {**message, "brief": {"path": str(box.root.parent / "x\ud800.md"), "sha256": "a" * 64}})
    elif defect == "wrong_folder":
        rewrite(box.root / "a/orchestrator/zz-bad.md", message)
    elif defect == "duplicate_id":
        path.write_bytes(original.read_bytes())
    elif defect in {"missing_reply", "reverse_reply"}:
        rewrite(path, {**message, "in_reply_to": "absent" if defect == "missing_reply" else "seed"})
    elif defect == "non_md":
        path.with_suffix(".txt").write_text("unexpected")
    elif defect in {"symlink", "pending_symlink"}:
        symlink(path if defect == "symlink" else path.parent / ".pending-bad", original)
    elif defect == "directory_entry":
        path.mkdir()
    else:
        folder = box.root / "across/front-door"
        folder.rmdir()
        if defect == "folder_symlink":
            symlink(folder, original.parent)


@pytest.mark.parametrize("defect", DEFECTS)
@pytest.mark.parametrize("warm", [False, True])
@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("api", ["messages", "get", "verify", "inbox"])
def test_malformed_equivalence(mailbox, defect, warm, mode, api):
    index = index_module().MailboxIndex(mailbox, mode=mode)
    if warm:
        index.messages()
    inject(mailbox, defect)
    if defect == "unencodable_brief_path":
        expected = mailbox.messages()
        result = invoke(index, api)
        expected_result = ([] if api == "verify" else expected if api == "messages" else expected["seed"]
                           if api == "get" else mailbox.inbox("a/lane/review"))
        assert result == expected_result
        assert index.last_reconciliation is None
        assert index_module().compare(mailbox, index) == []
        return
    expected = caught(mailbox.messages)
    assert caught(lambda: invoke(index, api)) == expected
    assert index_module().compare(mailbox, index) == []


@pytest.mark.parametrize("api", ["messages", "get", "verify", "inbox"])
@pytest.mark.parametrize("warm", [False, True])
def test_record_limit_rechecked(mailbox, monkeypatch, api, warm):
    seed = mailbox.messages()["seed"]
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    if warm:
        index.messages()
    rewrite(Path(seed["path"]).parent / "zz-extra.md", {**seed["message"], "message_id": "extra"})
    monkeypatch.setattr(hm, "MAX_RECORDS", 1)
    assert caught(lambda: invoke(index, api)) == caught(mailbox.messages)


@pytest.mark.parametrize("api", ["messages", "get", "verify", "inbox"])
@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_unchanged_file_made_unreadable_is_not_reused(mailbox, monkeypatch, api, mode):
    index = index_module().MailboxIndex(mailbox, mode=mode)
    seed = index.messages()["seed"]
    path = Path(seed["path"])
    injected = []

    def inaccessible(target):
        if target == path:
            injected.append(True)
            raise PermissionError("injected unreadable message: " + str(target))

    intercept_source_opens(monkeypatch, inaccessible)
    assert caught(lambda: invoke(index, api)) == caught(mailbox.messages)
    assert injected


@pytest.mark.parametrize("lookup", ["seed", "dispatch", "absent"])
@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_every_lookup_rechecks_unreturned_brief(mailbox, tmp_path, lookup, mode):
    folder = tmp_path / "briefs"
    folder.mkdir()
    packet = folder / "packet.md"
    packet.write_text("Pinned brief.\n")
    brief = {"path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}
    mailbox.publish(request("dispatch", type="dispatch", brief=brief))
    index = index_module().MailboxIndex(mailbox, mode=mode)
    index.messages()
    moved = tmp_path / "old-briefs"
    folder.rename(moved)
    symlink(folder, moved)
    assert caught(lambda: index.get(lookup)) == caught(mailbox.messages)
    assert index_module().compare(mailbox, index) == []


def legacy_cache(mailbox, seed, *, identifier="seed", valid=True):
    source = Path(seed["path"])
    metadata = source.stat()
    return {"schema": "aegis.mailbox-index/v3", "mailbox_root": str(mailbox.root),
            "manifest_sha256": hm.digest(mailbox.manifest),
            "source_sha256": hashlib.sha256(Path(hm.__file__).read_bytes()).hexdigest(),
            "entries": {str(source.relative_to(mailbox.root)): {
                "key": [metadata.st_size, metadata.st_mtime_ns, metadata.st_ino, metadata.st_ctime_ns],
                "metadata": {**{key: seed["message"][key] for key in
                                ("from", "to", "created_at", "type")}, "message_id": identifier},
                "destination": "a/lane", "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "valid": valid}}}


@pytest.mark.parametrize("poison", ["membership", "validity"])
def test_legacy_persisted_input_is_ignored(mailbox, tmp_path, poison):
    expected = mailbox.messages()
    seed = expected["seed"]
    directory = tmp_path / "mailbox-index"
    directory.mkdir(mode=0o700)
    path = directory / ("index-" + hashlib.sha256(os.fsencode(mailbox.root)).hexdigest()[:16] + ".json")
    fake = legacy_cache(mailbox, seed, identifier="hidden-seed", valid=poison != "validity")
    path.write_bytes(hm.encoded(fake))
    path.chmod(0o600)
    before = snapshot(tmp_path)
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    assert index.get("seed") == seed
    assert index.get("hidden-seed") is None
    assert index.messages() == expected
    assert snapshot(tmp_path) == before
    fresh = index_module().MailboxIndex(mailbox, mode="indexed")
    assert fresh.get("seed") == seed


@pytest.mark.parametrize("warm", [False, True])
def test_forged_type_and_matching_disk_attestation_never_bypass_validation(mailbox, tmp_path, warm):
    module = index_module()
    seed = mailbox.messages()["seed"]
    index = module.MailboxIndex(mailbox, mode="indexed")
    if warm:
        index.messages()
    rewrite(Path(seed["path"]), {**seed["message"], "type": "invalid-type"})
    directory = tmp_path / "mailbox-index"
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / ("index-" + hashlib.sha256(os.fsencode(mailbox.root)).hexdigest()[:16] + ".json")
    path.write_bytes(hm.encoded(legacy_cache(mailbox, seed)))
    path.chmod(0o600)
    before = snapshot(tmp_path)
    assert caught(index.messages) == caught(mailbox.messages)
    assert module.compare(mailbox, index) == []
    assert snapshot(tmp_path) == before


def spy_parses(monkeypatch):
    module = index_module()
    real_parse = module.MailboxIndex._parse_message
    calls = []

    def parse(self, path, raw):
        calls.append(str(path))
        return real_parse(self, path, raw)

    monkeypatch.setattr(module.MailboxIndex, "_parse_message", parse)
    return calls


@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
def test_one_publish_parses_only_new_record(mailbox, monkeypatch, api):
    for number in range(16):
        mailbox.publish(request("note-%02d" % number))
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    index.messages()
    calls = spy_parses(monkeypatch)
    mailbox.publish(request("one-new"))
    result = invoke(index, api)
    assert len(calls) == 1 and calls[0].endswith("-one-new.md")
    assert result == (mailbox.messages() if api == "messages" else mailbox.messages()["seed"]
                      if api == "get" else mailbox.inbox("a/lane/review"))
    calls.clear()
    invoke(index, api)
    assert calls == []
    fresh = index_module().MailboxIndex(mailbox, mode="indexed")
    fresh.messages()
    assert len(calls) == len(mailbox.messages())


@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
def test_deletion_drops_membership_without_reparsing(mailbox, monkeypatch, api):
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    seed = index.messages()["seed"]
    calls = spy_parses(monkeypatch)
    Path(seed["path"]).unlink()
    result = invoke(index, api)
    assert calls == []
    assert result == ({} if api == "messages" else None if api == "get"
                      else mailbox.inbox("a/lane/review"))
    assert index_module().compare(mailbox, index) == []


@pytest.mark.parametrize("preserve_ctime", [False, True], ids=["native", "creation-time"])
def test_inode_reuse_with_different_ctime_reparses(mailbox, tmp_path, monkeypatch, preserve_ctime):
    module = index_module()
    if preserve_ctime:
        monkeypatch.setattr(module, "_checked_reads_supported", lambda: False)
    index = module.MailboxIndex(mailbox, mode="indexed")
    seed = index.messages()["seed"]
    path = Path(seed["path"])
    old = path.stat()
    replacement = tmp_path / "replacement"
    rewrite(replacement, {**seed["message"], "body": "modified body"})
    replacement.replace(path)
    os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns))
    current = path.stat()
    if preserve_ctime:
        current = SimpleNamespace(st_dev=current.st_dev, st_ino=current.st_ino,
                                  st_size=current.st_size, st_ctime_ns=old.st_ctime_ns)
    assert current.st_ino != old.st_ino
    # Checked metadata reuse needs a changed ctime. Windows hashes the bytes;
    # its creation time can survive replacement through file-name tunneling.
    if module._checked_reads_supported():
        assert current.st_ctime_ns != old.st_ctime_ns
    assert current.st_size == old.st_size
    real_os = module.os
    injected = []

    def reused(value):
        if (value.st_dev, value.st_ino) != (current.st_dev, current.st_ino):
            return value
        injected.append(True)
        return SimpleNamespace(st_mode=value.st_mode, st_dev=value.st_dev, st_ino=old.st_ino,
                               st_size=value.st_size, st_mtime_ns=value.st_mtime_ns,
                               st_ctime_ns=current.st_ctime_ns)

    def fstat(descriptor):
        return reused(real_os.fstat(descriptor))

    def os_lstat(path, *args, **kwargs):
        return reused(real_os.lstat(path, *args, **kwargs))

    monkeypatch.setattr(module, "os", PlatformOS(real_os.name, base=real_os,
                                                lstat=os_lstat, fstat=fstat))
    calls = spy_parses(monkeypatch)
    assert index.get("seed") == mailbox.messages()["seed"]
    assert len(calls) == 1 and injected
    assert index_module().compare(mailbox, index) == []


@pytest.mark.parametrize("verify_first", [False, True])
def test_mtime_restore_and_verify_report_changed_bytes(mailbox, monkeypatch, verify_first):
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    seed = index.messages()["seed"]
    path = Path(seed["path"])
    metadata = path.stat()
    old_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    rewrite(path, {**seed["message"], "body": "modified body"})
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    new_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    calls = spy_parses(monkeypatch)
    changes = index.verify() if verify_first else (index.messages(), index.content_changed)[1]
    assert changes == [{"kind": "content_changed", "path": str(path),
                        "old_sha256": old_sha, "new_sha256": new_sha}]
    assert len(calls) == 1
    calls.clear()
    assert index.verify() == []
    assert len(calls) == 1  # Force rehash even when every stat key matches.


@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
def test_callers_cannot_mutate_memo(mailbox, api):
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    result = invoke(index, api)
    record = result["seed"] if api == "messages" else result if api == "get" else result["messages"][0]
    record["message"]["body"] = "caller mutation"
    record["message"]["message_id"] = "hidden-seed"
    assert index.get("seed") == mailbox.messages()["seed"]
    assert index.get("hidden-seed") is None


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_operations_never_write_root_or_parent(mailbox, tmp_path, monkeypatch, mode):
    index = index_module().MailboxIndex(mailbox, mode=mode)
    cleanup = tmp_path / "cleanup-probe"
    cleanup.mkdir()
    (cleanup / "file").write_bytes(b"cleanup outside the index operation")
    before = snapshot(tmp_path)
    real_open = Path.open
    attempted = []

    def targeted(path):
        if isinstance(path, int):
            return False
        try:
            Path(path).relative_to(tmp_path)
        except (TypeError, ValueError):
            return False
        return True

    def read_only(path, mode="r", *args, **kwargs):
        if targeted(path) and any(flag in mode for flag in "wax+"):
            attempted.append(str(path))
            raise AssertionError("index attempted a write")
        return real_open(path, mode, *args, **kwargs)

    def forbidden(*args, **kwargs):
        attempted.append(str(args))
        raise AssertionError("index attempted a filesystem mutation")

    with monkeypatch.context() as operation:
        operation.setattr(Path, "open", read_only)
        for owner, names in ((Path, ("mkdir", "unlink", "rename", "replace", "symlink_to", "hardlink_to")),
                             (os, ("mkdir", "unlink", "rename", "replace", "link", "symlink"))):
            for name in names:
                if not hasattr(owner, name):
                    continue
                original = getattr(owner, name)

                def guarded(*args, _call=original, **kwargs):
                    if any(key.endswith("dir_fd") and value is not None for key, value in kwargs.items()):
                        return _call(*args, **kwargs)
                    if any(targeted(path) for path in args):
                        return forbidden(*args, **kwargs)
                    return _call(*args, **kwargs)

                operation.setattr(owner, name, guarded)
        assert index.messages() == mailbox.messages()
        assert index.get("seed") == mailbox.messages()["seed"]
        assert index.inbox("a/lane/review") == mailbox.inbox("a/lane/review")
        assert index.verify() == []
        assert index_module().compare(mailbox, index) == []
        assert attempted == [] and snapshot(tmp_path) == before
    shutil.rmtree(cleanup)  # Exercise fd-based container cleanup before fixture teardown.


def test_shadow_and_oracle_keep_differences_in_memory(mailbox, tmp_path, monkeypatch):
    module = index_module()
    index = module.MailboxIndex(mailbox)
    expected = mailbox.messages()
    before = snapshot(tmp_path)
    assert module.compare(mailbox, index) == []
    calls = []

    def wrong():
        calls.append(True)
        return {}

    monkeypatch.setattr(index, "_indexed_messages", wrong)
    assert index.messages() == expected
    assert index.last_divergence
    assert module.compare(mailbox, index)
    assert calls and snapshot(tmp_path) == before


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_varied_mailbox_and_pinned_inbox(mailbox, tmp_path, mode):
    packet = tmp_path / "packet.md"
    packet.write_text("Task packet.\n")
    brief = {"path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}
    mailbox.publish(request("dispatch", type="dispatch", brief=brief))
    mailbox.publish(request("received", "a/lane/review", "a/orchestrator", type="ack",
                            in_reply_to="dispatch", acknowledgment="received"))
    mailbox.publish(request("job", recipient="a/root", type="job_request", brief=brief))
    mailbox.publish(request("receipt", "a/root", "a/orchestrator", type="job_receipt",
                            in_reply_to="job", receipt={"state": "started"}))
    index = index_module().MailboxIndex(mailbox, mode=mode)
    assert index.messages() == mailbox.messages()
    assert hm.encoded(index.messages()) == hm.encoded(mailbox.messages())
    assert index_module().compare(mailbox, index) == []
    for endpoint in ("a/lane/review", "a/orchestrator", "a/root"):
        for include_briefs in (False, True):
            assert index.inbox(endpoint, limit=1, include_briefs=include_briefs) == mailbox.inbox(
                endpoint, limit=1, include_briefs=include_briefs)
    assert index.inbox("a/lane/review", after="seed") == mailbox.inbox("a/lane/review", after="seed")


def test_pending_can_vanish_during_symlink_check(mailbox, monkeypatch):
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    expected = index.messages()
    pending = mailbox.root / "a/lane/.pending-vanish"
    pending.write_text("partial")
    real_lstat = os.lstat
    injected = []

    def check(path, *args, **kwargs):
        if os.fspath(path) == str(pending) and not injected:
            pending.unlink()
            injected.append(True)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", check)
    assert index.messages() == expected
    assert injected and index_module().compare(mailbox, index) == []


def test_unknown_mode_refused(mailbox):
    error_type, message = caught(lambda: index_module().MailboxIndex(mailbox, mode="bad"))
    assert issubclass(error_type, ValueError) and "indexed" in message and "shadow" in message


MODE_REFUSAL = "mailbox index mode is read-only; changing mode requires the ADR phase-0 exit"


def _attempt_mode_change(index, other, operation):
    target = "indexed" if index.mode == "shadow" else "shadow"
    if operation == "assignment":
        index.mode = target
    elif operation == "setattr":
        setattr(index, "mode", target)
    elif operation == "imported-setattr":
        from builtins import setattr as assign
        assign(index, "mode", target)
    elif operation == "captured-setattr":
        assign = setattr
        assign(index, "mode", target)
    elif operation == "bound-setattr":
        assign = index.__setattr__
        assign("mode", target)
    elif operation == "object-setattr":
        assign = object.__setattr__
        assign(index, "mode", target)
    elif operation == "delete":
        del index.mode
    elif operation == "delattr":
        delattr(index, "mode")
    elif operation == "object-delattr":
        object.__delattr__(index, "mode")
    elif operation == "dict-update":
        index.__dict__.update(mode=target)
    elif operation == "dict-item":
        index.__dict__["mode"] = target
    elif operation == "dict-replacement":
        index.__dict__ = {"mode": target}
    elif operation == "vars-update":
        vars(index).update(mode=target)
    elif operation == "captured-vars":
        state = vars
        state(index).update(mode=target)
    elif operation == "imported-vars":
        from builtins import vars as state
        state(index).update(mode=target)
    elif operation == "reinit":
        index.__init__(other, mode=target)
    elif operation == "captured-reinit":
        reinit = index.__init__
        reinit(other, mode=target)
    elif operation == "partial-reinit":
        partial(index.__init__, mode=target)(other)
    elif operation == "invalid-reinit":
        index.__init__(other, mode="invalid\nmode")
    elif operation == "slot-assignment":
        index._MailboxIndex__mode = target
    elif operation == "slot-setattr":
        object.__setattr__(index, "_MailboxIndex__mode", target)
    elif operation == "slot-deletion":
        del index._MailboxIndex__mode
    elif operation == "slot-delattr":
        object.__delattr__(index, "_MailboxIndex__mode")
    elif operation == "slot-delete-reinit":
        try:
            del index._MailboxIndex__mode
        except AttributeError as exc:
            assert str(exc) == MODE_REFUSAL
        index.__init__(other, mode=target)
    else:
        raise AssertionError("unknown test operation")


MODE_OPERATIONS = ["assignment", "setattr", "imported-setattr", "captured-setattr", "bound-setattr",
                   "object-setattr", "delete", "delattr", "object-delattr", "dict-update", "dict-item",
                   "dict-replacement", "vars-update", "captured-vars", "imported-vars", "reinit",
                   "captured-reinit", "partial-reinit", "invalid-reinit"]
BACKING_OPERATIONS = ["slot-assignment", "slot-setattr", "slot-deletion", "slot-delattr", "slot-delete-reinit"]


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("operation", MODE_OPERATIONS)
def test_mode_guard_refuses_existing_instance_changes(mailbox, mode, operation):
    index = index_module().MailboxIndex(mailbox, mode=mode)
    expected = index.messages()
    # Reinitialization must refuse before replacing the mailbox or clearing memo.
    entries = index._entries
    for _ in range(2):
        with pytest.raises(AttributeError) as refused:
            _attempt_mode_change(index, object(), operation)
        assert str(refused.value) == MODE_REFUSAL
        assert index.mode == mode and index.mailbox is mailbox and index._entries is entries
    assert index.messages() == expected
    assert index.get("seed") == expected["seed"]
    assert index.inbox("a/lane/review") == mailbox.inbox("a/lane/review")
    assert index.verify() == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_mode_guard_concurrent_refusals_keep_dispatch(mailbox, mode):
    module = index_module()
    index = module.MailboxIndex(mailbox, mode=mode)
    expected = mailbox.messages()

    def attempt(operation):
        return caught(lambda: _attempt_mode_change(index, object(), operation))

    with ThreadPoolExecutor(max_workers=3) as workers:
        results = list(workers.map(attempt, MODE_OPERATIONS + BACKING_OPERATIONS, timeout=10))
    assert all(kind is AttributeError and message == MODE_REFUSAL for kind, message in results)
    assert index.mode == mode and index.mailbox is mailbox
    calls = []

    def wrong():
        calls.append(True)
        return {}

    index._indexed_messages = wrong
    assert index.messages() == (expected if mode == "shadow" else {})
    assert len(calls) == (2 if mode == "shadow" else 1)
    assert bool(index.last_divergence) == (mode == "shadow")


@pytest.mark.parametrize("mode", ["shadow", "indexed"])
def test_mode_guard_sentinel_is_local(mailbox, monkeypatch, mode):
    from tools import hierarchy_mailbox_index as module
    index = module.MailboxIndex(mailbox, mode=mode)
    monkeypatch.setattr(module, "_MISSING", mode)
    with pytest.raises(AttributeError, match="^" + MODE_REFUSAL + "$"):
        index.__init__(object(), mode="indexed" if mode == "shadow" else "shadow")
    assert index.mode == mode and index.mailbox is mailbox


def test_mode_guard_invalid_initialization_can_retry(mailbox):
    cls = index_module().MailboxIndex
    index = cls.__new__(cls)
    with pytest.raises(ValueError, match="^unknown mailbox index mode; valid modes: shadow, indexed$"):
        index.__init__(mailbox, mode="bad")
    index.__init__(mailbox, mode="shadow")
    assert index.mode == "shadow" and index.messages() == mailbox.messages()
    for mode in ("shadow", "indexed"):
        fresh = type(index)(mailbox, mode=mode)
        assert fresh.mode == mode and fresh.messages() == mailbox.messages()


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("operation", BACKING_OPERATIONS)
def test_mode_backing_slot_refuses_mutation_and_reinitialization(mailbox, mode, operation):
    index = index_module().MailboxIndex(mailbox, mode=mode)
    expected = index.messages()
    entries = index._entries
    for _ in range(2):
        with pytest.raises(AttributeError) as refused:
            _attempt_mode_change(index, object(), operation)
        assert str(refused.value) == MODE_REFUSAL
        assert index.mode == mode and index.mailbox is mailbox and index._entries is entries
    assert index.messages() == expected


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_mode_dict_snapshot_keeps_inspection_copy_and_mock_usable(mailbox, mode):
    index = index_module().MailboxIndex(mailbox, mode=mode)
    expected = index.messages()
    assert hasattr(index, "__dict__") and "mode" in dir(index)
    assert dict(inspect.getmembers(index))["mode"] == mode
    snapshot = vars(index)
    assert snapshot["mailbox"] is mailbox and snapshot["_entries"] is index._entries
    assert snapshot == index.__dict__ and snapshot is not index.__dict__
    index.last_reconciliation = {"kind": "test"}
    assert snapshot["last_reconciliation"] is None
    clone = copy(index)
    assert clone is not index and clone.mode == mode and clone.mailbox is mailbox
    assert clone._entries is index._entries and clone.messages() == expected
    with mock.patch.object(index, "last_reconciliation", "patched"):
        assert index.last_reconciliation == "patched"
    assert index.last_reconciliation == {"kind": "test"}


@pytest.mark.parametrize("operation", ["item", "delete", "clear", "pop", "popitem", "setdefault", "update", "ior"])
@pytest.mark.parametrize("mode", ["shadow", "indexed"])
def test_mode_dict_snapshot_mutators_have_fixed_refusal(mailbox, operation, mode):
    index = index_module().MailboxIndex(mailbox, mode=mode)
    snapshot = vars(index)
    with pytest.raises(AttributeError) as refused:
        if operation == "item":
            snapshot["mode"] = "indexed"
        elif operation == "delete":
            del snapshot["mailbox"]
        elif operation == "clear":
            snapshot.clear()
        elif operation == "pop":
            snapshot.pop("mailbox")
        elif operation == "popitem":
            snapshot.popitem()
        elif operation == "setdefault":
            snapshot.setdefault("mode", "indexed")
        elif operation == "update":
            snapshot.update(mode="indexed")
        else:
            snapshot |= {"mode": "indexed"}
    assert str(refused.value) == MODE_REFUSAL
    assert index.mode == mode and index.mailbox is mailbox


def test_oracle_detects_order_only_difference(mailbox, monkeypatch):
    module = index_module()
    index = module.MailboxIndex(mailbox, mode="indexed")
    expected = mailbox.messages()
    changed = {key: dict(reversed(list(record.items()))) for key, record in expected.items()}
    assert hm.encoded(changed) == hm.encoded(expected)
    monkeypatch.setattr(index, "_indexed_messages", lambda: changed)
    assert module.compare(mailbox, index) == [{"kind": "mailbox_index_key_order"}]


@pytest.mark.parametrize("platform", ["nt", "unproven"])
@pytest.mark.parametrize("change", ["type", "body"])
@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("api", ["messages", "get", "verify", "inbox"])
def test_r12_unreliable_metadata_rehashes_before_reuse(mailbox, monkeypatch, platform, change, mode, api):
    module = index_module()
    index = module.MailboxIndex(mailbox, mode=mode)
    seed = index.messages()["seed"]
    path = Path(seed["path"])
    original = path.stat()
    message = {**seed["message"], change: "evil" if change == "type" else "modified body"}
    rewrite(path, message)
    os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
    assert path.stat().st_size == original.st_size
    real_lstat, real_os_lstat, real_fstat = Path.lstat, os.lstat, os.fstat
    observed = []

    def creation_time(value):
        if (value.st_dev, value.st_ino) != (original.st_dev, original.st_ino):
            return value
        observed.append(True)
        return SimpleNamespace(st_mode=value.st_mode, st_dev=value.st_dev, st_ino=value.st_ino,
                               st_size=value.st_size, st_mtime_ns=value.st_mtime_ns,
                               st_ctime_ns=original.st_ctime_ns)

    def lstat(target, *args, **kwargs):
        return creation_time(real_lstat(target, *args, **kwargs))

    def fstat(descriptor):
        return creation_time(real_fstat(descriptor))

    def os_lstat(path, *args, **kwargs):
        return creation_time(real_os_lstat(path, *args, **kwargs))

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(os, "lstat", os_lstat)
    # Isolate the platform boundary; do not change global os.name/pathlib classes.
    monkeypatch.setattr(module, "os", PlatformOS(platform, base=module.os, fstat=fstat))
    if change == "type":
        assert caught(lambda: invoke(index, api)) == caught(mailbox.messages)
    else:
        result = invoke(index, api)
        expected = mailbox.messages()
        if api == "verify":
            assert any(item["kind"] == "content_changed" for item in result)
        else:
            assert result == (expected if api == "messages" else expected["seed"]
                              if api == "get" else mailbox.inbox("a/lane/review"))
    assert observed and module.compare(mailbox, index) == []


@pytest.mark.parametrize("platform", ["posix", "nt", "unproven"])
def test_r12_hash_policy_reuses_parsing_only_after_hash_match(mailbox, monkeypatch, platform):
    if platform == "posix":
        require_posix_reuse()
    module = index_module()
    mailbox.publish(request("second"))
    index = module.MailboxIndex(mailbox, mode="indexed")
    index.messages()
    monkeypatch.setattr(module, "os", PlatformOS(platform, base=module.os, fstat=module.os.fstat))
    real_parse = module.MailboxIndex._parse_message
    real_read = module.MailboxIndex._read_message
    parses, reads = [], []

    def parse(self, path, raw):
        parses.append(str(path))
        return real_parse(self, path, raw)

    def read(self, path, **kwargs):
        reads.append(str(path))
        return real_read(self, path, **kwargs)

    monkeypatch.setattr(module.MailboxIndex, "_parse_message", parse)
    monkeypatch.setattr(module.MailboxIndex, "_read_message", read)
    index.messages()
    assert parses == [] and len(reads) == (0 if platform == "posix" else 2)
    mailbox.publish(request("one-new"))
    reads.clear()
    index.messages()
    assert len(parses) == 1 and parses[0].endswith("-one-new.md")
    assert len(reads) == (1 if platform == "posix" else 3)


@pytest.mark.parametrize("race", ["pending_unlink", "reply_between_listings"])
@pytest.mark.parametrize("pinned_error", [False, True])
@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("api", ["messages", "get", "verify", "inbox"])
def test_r12_publication_races_return_pinned_result(mailbox, monkeypatch, race, pinned_error, mode, api):
    module = index_module()
    cleanup = mailbox.root.parent / "cleanup-probe"
    cleanup.mkdir()
    (cleanup / "file").write_bytes(b"cleanup outside the index operation")
    index = module.MailboxIndex(mailbox, mode=mode)
    seed = index.messages()["seed"]
    retained = dict(index._entries)
    injected = []
    with monkeypatch.context() as race_patch:
        if race == "pending_unlink":
            require_posix_reuse()
            pending, aliases = [], {}
            real_unlink = Path.unlink

            def defer(path, *args, **kwargs):
                if path.name.startswith(".pending-"):
                    pending.append(path)
                    return None
                return real_unlink(path, *args, **kwargs)

            with monkeypatch.context() as publication:
                publication.setattr(Path, "unlink", defer)
                for identifier in ("race-1", "race-2"):
                    mailbox.publish(request(identifier))
                    final = Path(mailbox.messages()[identifier]["path"])
                    assert pending[-1].stat().st_ino == final.stat().st_ino
                    aliases[final] = pending[-1]
            real_lstat, real_os_lstat = Path.lstat, os.lstat

            def unlink_after_stat(call, path, *args, **kwargs):
                value = call(path, *args, **kwargs)
                if isinstance(path, int) or kwargs.get("dir_fd") is not None:
                    return value
                target = Path(path)
                if target in aliases:
                    alias = aliases.pop(target)
                    real_unlink(alias)
                    injected.append(str(target))
                    assert real_lstat(target).st_ctime_ns != value.st_ctime_ns
                    if pinned_error and len(injected) == 2:
                        rewrite(Path(seed["path"]), {**seed["message"], "type": "evil"})
                return value

            def path_lstat(path, *args, **kwargs):
                return unlink_after_stat(real_lstat, path, *args, **kwargs)

            def os_lstat(path, *args, **kwargs):
                return unlink_after_stat(real_os_lstat, path, *args, **kwargs)

            race_patch.setattr(Path, "lstat", path_lstat)
            race_patch.setattr(os, "lstat", os_lstat)
        else:
            real_iterdir, real_scandir = Path.iterdir, os.scandir

            def publish_between(path):
                if isinstance(path, int):
                    return
                if os.fspath(path) == str(mailbox.root / "a/orchestrator") and not injected:
                    injected.append(True)
                    mailbox.publish(request("parent-between-listings"))
                    mailbox.publish(request("reply-between-listings", "a/lane/review", "a/orchestrator",
                                            in_reply_to="parent-between-listings"))
                    if pinned_error:
                        rewrite(Path(seed["path"]), {**seed["message"], "type": "evil"})
            def iterdir(path):
                publish_between(path)
                return real_iterdir(path)

            def scandir(path):
                publish_between(path)
                return real_scandir(path)

            race_patch.setattr(Path, "iterdir", iterdir)
            race_patch.setattr(os, "scandir", scandir)
        if pinned_error:
            assert caught(lambda: invoke(index, api)) == caught(mailbox.messages)
        else:
            result = invoke(index, api)
            expected = mailbox.messages()
            if api == "verify":
                assert any(item["kind"] == "verification_unavailable" for item in result)
            else:
                assert result == (expected if api == "messages" else expected["seed"]
                                  if api == "get" else mailbox.inbox("a/lane/review"))
        assert len(injected) == (2 if race == "pending_unlink" else 1)
        assert index.last_reconciliation["kind"] == "pinned_fallback"
        assert index.last_reconciliation["attempts"] == (2 if race == "pending_unlink" else 1)
        assert index._entries == retained  # Candidates are re-keyed on the next call, never bound to PIN's snapshot.
        assert module.compare(mailbox, index) == []
    shutil.rmtree(cleanup)


@pytest.mark.parametrize("loading", ["sibling", "isolated_path"])
def test_r12_isolated_reader_import_uses_pinned_sibling(mailbox, loading):
    source = Path(hm.__file__).with_name("hierarchy_mailbox_index.py")
    if loading == "sibling":
        driver = ("import sys; sys.path.insert(0, sys.argv[1]); "
                  "import hierarchy_mailbox_index as m; "
                  "print(m.hm.encoded(m.MailboxIndex(m.hm.Mailbox(sys.argv[2]), mode='indexed').messages()).decode())")
        target = source.parent
    else:
        driver = ("import runpy,sys; m=runpy.run_path(sys.argv[1]); "
                  "print(m['hm'].encoded(m['MailboxIndex'](m['hm'].Mailbox(sys.argv[2]), "
                  "mode='indexed').messages()).decode())")
        target = source
    result = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(target), str(mailbox.root)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert hm.strict_json(result.stdout) == mailbox.messages()


def test_r13_pinned_inbox_raises_instead_of_refilling(mailbox, tmp_path):
    folder = tmp_path / "packet-folder"
    folder.mkdir()
    packet = folder / "packet.md"
    packet.write_text("Packet for the first candidate.\n")
    brief = {"path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}
    mailbox.publish(request("bad-candidate", type="dispatch", brief=brief))
    mailbox.publish(request("refill-candidate"))
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    records = index.messages()
    keys = {record["path"]: (Path(record["path"]).stat().st_size,
                             Path(record["path"]).stat().st_mtime_ns,
                             Path(record["path"]).stat().st_ctime_ns,
                             Path(record["path"]).stat().st_ino) for record in records.values()}
    moved = tmp_path / "moved-packet-folder"
    folder.rename(moved)
    symlink(folder, moved)
    assert keys == {path: (Path(path).stat().st_size, Path(path).stat().st_mtime_ns,
                          Path(path).stat().st_ctime_ns, Path(path).stat().st_ino) for path in keys}
    expected_error = caught(lambda: mailbox.inbox("a/lane/review", limit=2))
    assert expected_error[0] is ValueError and "symlink paths" in expected_error[1]
    assert "bad-candidate.md" in expected_error[1]
    assert caught(lambda: index.inbox("a/lane/review", limit=2)) == expected_error
    # A filled [seed, refill-candidate] page would contradict this pinned outcome.


def measure_ac1(root, monkeypatch, record_property, first, delivery):
    mailbox = hm.Mailbox(root)
    trace = MemoTrace(monkeypatch, mailbox)
    index, records, identifier, endpoint, expected_inbox = prepare_ac1(mailbox, first)
    assert len(records) == 10000
    binding = mailbox.current_binding(endpoint)
    sender = {"from": endpoint, "host": binding["host"], "session": binding["session"],
              "binding_generation": binding["generation"]}
    record_property("warmup_trace", hm.encoded(trace.events).decode())
    counts = ReadCounts(monkeypatch, trace)
    samples = {}
    sources = {record["path"] for record in records.values()}
    for api in ("get", "inbox"):
        before = mailbox.root.stat()
        mailbox.record_read(delivery / api, sender, [identifier])
        after = mailbox.root.stat()
        record_property(api + "_pinned_write", "record_read")
        record_property(api + "_root_times_before", (before.st_mtime_ns, before.st_ctime_ns))
        record_property(api + "_root_times_after", (after.st_mtime_ns, after.st_ctime_ns))
        assert (before.st_dev, before.st_ino, before.st_mode, before.st_uid) == (
            after.st_dev, after.st_ino, after.st_mode, after.st_uid)
        trace.reset()
        counts.reset()
        load = os.getloadavg() if hasattr(os, "getloadavg") else None
        started = time.perf_counter()
        if api == "get":
            result = index.get(identifier)
        else:
            result = index.inbox(endpoint, limit=20)
        elapsed = time.perf_counter() - started
        expected = records[identifier] if api == "get" else expected_inbox
        assert result == expected
        returned = [result] if api == "get" else result["messages"]
        source_opens = [path for path in counts.opens if path in sources]
        warm = (trace.validations == 0 and not trace.events and index.last_reconciliation is None
                and counts.memo_lstats == {path: 1 for path in index._observations}
                and sorted(source_opens) == sorted(record["path"] for record in returned)
                and len(counts.opens) == len(returned) + (1 if api == "inbox" else 0))
        samples[api] = {"seconds": elapsed, "warm": warm}
        for field, value in {"seconds": elapsed, "warm": warm, "load_1_5_15": load,
                             "lstats": sum(counts.lstats.values()), "opens": len(counts.opens),
                             "validations": trace.validations, "trace": hm.encoded(trace.events).decode(),
                             "max_memo_lstats": max(counts.memo_lstats.values(), default=0)}.items():
            record_property(api + "_" + field, value)
    return samples


@pytest.mark.timing
@pytest.mark.skipif(not os.environ.get("AEGIS_MB1_AC1_ROOT"), reason="explicit existing 10k fixture required")
def test_r13_ac1_existing_10k_fixture(record_property, monkeypatch, tmp_path):
    root = Path(os.environ["AEGIS_MB1_AC1_ROOT"])
    record_property("mailbox", str(root))
    record_property("records", 10000)
    record_property("cpu_count", os.cpu_count())
    samples = []
    # Three complete, sequential benchmark runs, each with a fresh memo.
    for number, first in enumerate(("get", "inbox", "messages"), 1):
        prefix = "sample_%d_" % number
        record_property(prefix + "first", first)
        with monkeypatch.context() as patches:
            samples.append(measure_ac1(root, patches,
                                       lambda key, value: record_property(prefix + key, value), first,
                                       tmp_path / ("receipts-%d" % number)))
    medians = {api: statistics.median(sample[api]["seconds"] for sample in samples)
               for api in ("get", "inbox")}
    for api, median in medians.items():
        record_property(api + "_median_seconds", median)
        record_property(api + "_wall_clock_below_0_2", median <= 0.2)
    record_property("wall_clock_gate", "deferred_until_quiet_machine_owner_acceptance")
    assert all(sample[api]["warm"] for sample in samples for api in medians), samples


@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
@pytest.mark.usefixtures("posix_reuse")
def test_r14_warm_validation_is_reused_by_observation_key(mailbox, monkeypatch, api):
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    index.messages()
    real_validate = mailbox.validate_message
    validations = []

    def validate(message, **kwargs):
        validations.append(message["message_id"])
        return real_validate(message, **kwargs)

    monkeypatch.setattr(mailbox, "validate_message", validate)
    invoke(index, api)
    assert validations == []


@pytest.mark.usefixtures("posix_reuse")
def test_r14_warm_lstats_are_deduplicated(mailbox, monkeypatch):
    mailbox.publish(request("second"))
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    index.messages()
    real_lstat = os.lstat
    counts = {}

    def lstat(path, *args, **kwargs):
        counts[path] = counts.get(path, 0) + 1
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    assert index.get("seed")["message"]["message_id"] == "seed"
    assert counts and max(counts.values()) == 1


@pytest.mark.parametrize("change", ["brief_symlink", "rename_swap", "in_place"])
def test_r14_changed_observation_and_restoration(mailbox, tmp_path, change):
    folder = tmp_path / "brief-folder"
    folder.mkdir()
    packet = folder / "packet.md"
    packet.write_text("Keyed brief.\n")
    brief = {"path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}
    mailbox.publish(request("dispatch", type="dispatch", brief=brief))
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    seed = index.messages()["seed"]
    source = Path(seed["path"])
    original = source.read_bytes()
    if change == "brief_symlink":
        moved = tmp_path / "old-brief-folder"
        folder.rename(moved)
        symlink(folder, moved)
    elif change == "rename_swap":
        replacement = tmp_path / "replacement.md"
        rewrite(replacement, {**seed["message"], "type": "evil"})
        replacement.replace(source)
    else:
        metadata = source.stat()
        rewrite(source, {**seed["message"], "type": "evil"})
        os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    assert caught(lambda: index.get("seed")) == caught(mailbox.messages)
    if change == "brief_symlink":
        folder.unlink()
        moved.rename(folder)
    else:
        source.write_bytes(original)
    assert index.get("seed") == mailbox.messages()["seed"]
    assert index_module().compare(mailbox, index) == []


@pytest.mark.usefixtures("posix_reuse")
def test_r14_reference_mode_change_rechecks_its_record(mailbox, tmp_path, monkeypatch):
    packet = tmp_path / "packet.md"
    packet.write_text("Referenced file mode.\n")
    packet.chmod(0o644)
    brief = {"path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}
    mailbox.publish(request("dispatch", type="dispatch", brief=brief))
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    index.messages()
    real_validate = mailbox.validate_message
    validations = []

    def validate(message, **kwargs):
        validations.append(message["message_id"])
        return real_validate(message, **kwargs)

    monkeypatch.setattr(mailbox, "validate_message", validate)
    packet.chmod(0o600)
    assert index.get("seed")["message"]["message_id"] == "seed"
    assert validations == ["dispatch"]


def test_r14_process_identity_is_live(mailbox, monkeypatch):
    if not hasattr(os, "getgroups"):
        pytest.skip("POSIX group observation required")
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    index.messages()
    groups = os.getgroups()
    real_validate = mailbox.validate_message
    validations = []

    def validate(message, **kwargs):
        validations.append(message["message_id"])
        return real_validate(message, **kwargs)

    monkeypatch.setattr(mailbox, "validate_message", validate)
    monkeypatch.setattr(os, "getgroups", lambda: groups + [max(groups + [0]) + 1])
    assert index.get("seed")["message"]["message_id"] == "seed"
    assert validations == ["seed"]


@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
def test_r15_cached_access_opens_and_reads_only_returned_records(mailbox, monkeypatch, api):
    if api != "messages":
        require_posix_reuse()
    mailbox.publish(request("second"))
    mailbox.publish(request("third"))
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    expected = index.messages()
    sources = {record["path"] for record in expected.values()}
    real_open = Path.open
    real_os_open, real_fdopen = os.open, os.fdopen
    descriptors = {}
    opened, read = [], []

    class Stream:
        def __init__(self, stream, path):
            self.stream, self.path = stream, path

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def read(self, *args, **kwargs):
            read.append(str(self.path))
            return self.stream.read(*args, **kwargs)

    def opening(path, *args, **kwargs):
        stream = real_open(path, *args, **kwargs)
        if str(path) in sources:
            opened.append(str(path))
            return Stream(stream, path)
        return stream

    def os_open(path, *args, **kwargs):
        descriptor = real_os_open(path, *args, **kwargs)
        if os.fspath(path) in sources:
            opened.append(os.fspath(path))
            descriptors[descriptor] = os.fspath(path)
        return descriptor

    def fdopen(descriptor, *args, **kwargs):
        stream = real_fdopen(descriptor, *args, **kwargs)
        path = descriptors.pop(descriptor, None)
        return Stream(stream, path) if path is not None else stream

    class SourcePath(type(Path())):
        def open(self, *args, **kwargs):
            return opening(self, *args, **kwargs)

    module = index_module()
    monkeypatch.setattr(hm, "Path", SourcePath)
    monkeypatch.setattr(module, "os", PlatformOS(module.os.name, base=module.os, open=os_open, fdopen=fdopen))
    if api == "inbox":
        result = index.inbox("a/lane/review", limit=1)
        assert result["messages"][0] == expected["seed"]
    else:
        assert invoke(index, api) == (expected if api == "messages" else expected["seed"])
    assert len(opened) == len(read) == (3 if api == "messages" else 1)


@pytest.mark.usefixtures("posix_reuse")
def test_r15_unreturned_access_policy_change_is_the_accepted_risk(mailbox, monkeypatch):
    mailbox.publish(request("second"))
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    expected = index.messages()
    blocked = Path(expected["second"]["path"])

    def denied(path):
        if path == blocked:
            raise PermissionError("simulated mandatory policy reload")

    intercept_source_opens(monkeypatch, denied)
    assert index.get("seed") == expected["seed"]
    assert caught(index.messages) == caught(mailbox.messages)


def test_r15_changed_access_key_reprobes_unreturned_record(mailbox, monkeypatch):
    mailbox.publish(request("second"))
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    expected = index.messages()
    blocked = Path(expected["second"]["path"])

    def denied(path):
        if path == blocked:
            raise PermissionError("simulated changed access")

    blocked.chmod(0o400)
    intercept_source_opens(monkeypatch, denied)
    assert caught(lambda: index.get("seed")) == caught(mailbox.messages)


def test_r15_hot_loop_does_not_hash_pathlib_objects(mailbox, monkeypatch):
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    index.messages()
    real_hash = Path.__hash__
    calls = []

    def hashed(path):
        calls.append(True)
        return real_hash(path)

    monkeypatch.setattr(Path, "__hash__", hashed)
    assert index.get("seed")["message"]["message_id"] == "seed"
    assert calls == []


@pytest.fixture
def prefix_mailbox(tmp_path):
    # These hierarchy slugs are accepted by the pinned endpoint grammar.
    hierarchies = ("a-x", "a-1", "a")
    endpoints = {}
    for hierarchy in hierarchies:
        endpoints.update({hierarchy + "/front-door": {}, hierarchy + "/orchestrator": {},
                          hierarchy + "/lane/review": {"kind": "reviewer"}})
    root = tmp_path / "prefix-mailbox"
    hm.initialize(root, {"schema": "aegis.hierarchy-pilot/v1", "writer_limit": 3,
                         "endpoints": endpoints, "counterparts": []})
    mailbox = hm.Mailbox(root)
    for endpoint in endpoints:
        mailbox.bind({"endpoint": endpoint, "host": "test-host", "session": endpoint,
                      "expected_generation": 0})
    packet = tmp_path / "prefix-packet.md"
    packet.write_text("Check component order.\n")
    brief = {"path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}
    for number, hierarchy in enumerate(hierarchies):
        sender, lane = hierarchy + "/orchestrator", hierarchy + "/lane/review"
        mailbox.publish(request("note-%d" % number, sender, hierarchy + "/front-door"))
        mailbox.publish(request("dispatch-%d" % number, sender, lane, type="dispatch", brief=brief))
        mailbox.publish(request("accepted-%d" % number, lane, sender, type="ack",
                                acknowledgment="accepted", in_reply_to="dispatch-%d" % number))
    return mailbox


@pytest.mark.parametrize("api", ["messages", "get", "inbox", "dispatch_history", "compare"])
@pytest.mark.parametrize("warm", [False, True])
def test_r16_component_order_parity(prefix_mailbox, api, warm):
    module = index_module()
    mailbox = prefix_mailbox
    index = module.MailboxIndex(mailbox, mode="indexed")
    if warm:
        index.messages()
    expected = mailbox.messages()
    # Explicitly pin the independent oracle's hierarchy/component order.
    assert list(expected) == ["note-2", "dispatch-2", "accepted-2", "note-1", "dispatch-1",
                              "accepted-1", "note-0", "dispatch-0", "accepted-0"]
    if api == "messages":
        actual = index.messages()
        assert actual == expected and list(actual) == list(expected)
    elif api == "get":
        for identifier, record in expected.items():
            actual = index.get(identifier)
            assert actual == record and list(actual) == list(record)
    elif api == "inbox":
        for endpoint in mailbox.manifest["endpoints"]:
            actual = index.inbox(endpoint)
            pinned = mailbox.inbox(endpoint)
            assert actual == pinned and list(actual) == list(pinned)
    elif api == "dispatch_history":
        assert mailbox.dispatch_history(index.messages()) == mailbox.dispatch_history(expected)
    else:
        assert module.compare(mailbox, index) == []


@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
def test_r16_shadow_component_order_has_no_divergence(prefix_mailbox, api):
    index = index_module().MailboxIndex(prefix_mailbox)
    if api == "messages":
        assert index.messages() == prefix_mailbox.messages()
    elif api == "get":
        assert index.get("dispatch-2") == prefix_mailbox.messages()["dispatch-2"]
    else:
        assert index.inbox("a/lane/review") == prefix_mailbox.inbox("a/lane/review")
    assert index.last_divergence == []


@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
def test_r16_shadow_component_order_does_not_repeat_reads(prefix_mailbox, monkeypatch, api):
    index = index_module().MailboxIndex(prefix_mailbox)
    index.messages()
    calls = {"indexed": 0, "pinned": 0}
    real_indexed, real_pinned = index._read_index, prefix_mailbox.messages

    def indexed(*args, **kwargs):
        calls["indexed"] += 1
        return real_indexed(*args, **kwargs)

    def pinned():
        calls["pinned"] += 1
        return real_pinned()

    monkeypatch.setattr(index, "_read_index", indexed)
    monkeypatch.setattr(prefix_mailbox, "messages", pinned)
    if api == "messages":
        index.messages()
    elif api == "get":
        index.get("dispatch-2")
    else:
        index.inbox("a/lane/review")
    assert calls == {"indexed": 1, "pinned": 1}


def assert_warm_call(index, records, identifier, endpoint, page, api, trace, counts, record_property):
    trace.reset()
    counts.reset()
    if api == "messages":
        result = index.messages()
        assert result == records and list(result) == list(records)
        returned = list(records.values())
    elif api == "get":
        result = index.get(identifier)
        assert result == records[identifier]
        returned = [result]
    else:
        result = index.inbox(endpoint, limit=20)
        assert result == page
        returned = result["messages"]
    record_property("memo_trace", hm.encoded(trace.events).decode())
    record_property("validations", trace.validations)
    record_property("lstats", sum(counts.lstats.values()))
    record_property("opens", len(counts.opens))
    assert trace.validations == 0, trace.events
    assert not any(event["kind"] in {"clear", "scan_error"} for event in trace.events), trace.events
    assert index.last_reconciliation is None
    assert counts.memo_lstats and max(counts.memo_lstats.values()) == 1
    sources = {record["path"] for record in records.values()}
    assert sorted(path for path in counts.opens if path in sources) == sorted(
        record["path"] for record in returned)
    # Live pinned inbox delegation also opens the binding record.
    assert len(counts.opens) == len(returned) + (1 if api == "inbox" else 0)


@pytest.mark.parametrize("first", ["get", "inbox", "messages"])
@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
@pytest.mark.parametrize("refresh_layout", [False, True])
@pytest.mark.usefixtures("posix_reuse")
def test_r17_unchanged_warm_counts(prefix_mailbox, monkeypatch, record_property, first, api, refresh_layout):
    trace = MemoTrace(monkeypatch, prefix_mailbox)
    index, records, identifier, endpoint, page = prepare_ac1(prefix_mailbox, first)
    if refresh_layout:
        index._folder_layout = None  # A missing derived layout must not invalidate checked records.
    counts = ReadCounts(monkeypatch, trace)
    assert_warm_call(index, records, identifier, endpoint, page, api, trace, counts, record_property)
    assert [event["kind"] for event in trace.events] == (["layout_refresh"] if refresh_layout else [])


@pytest.mark.parametrize("first", ["get", "inbox", "messages"])
@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
@pytest.mark.usefixtures("posix_reuse")
def test_r17_oracle_preparation_finishes_before_warmup(prefix_mailbox, monkeypatch, record_property, first, api):
    mailbox = prefix_mailbox
    trace = MemoTrace(monkeypatch, mailbox)
    real_open = io.open
    marker = mailbox.root.parent / "concurrent-evidence"
    injected = []

    def opened(path, *args, **kwargs):
        # Reproduce a sibling evidence publication during the oracle's binding read.
        if isinstance(path, (str, os.PathLike)) and "/bindings/" in os.fspath(path) and not injected:
            injected.append(True)
            marker.write_bytes(b"independent evidence publication\n")
        return real_open(path, *args, **kwargs)

    before = snapshot(mailbox.root)
    monkeypatch.setattr(io, "open", opened)
    index, records, identifier, endpoint, page = prepare_ac1(mailbox, first)
    assert injected == [True] and snapshot(mailbox.root) == before
    counts = ReadCounts(monkeypatch, trace)
    assert_warm_call(index, records, identifier, endpoint, page, api, trace, counts, record_property)


@pytest.mark.parametrize("ancestor", ["parent", "grandparent"])
@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
@pytest.mark.usefixtures("posix_reuse")
def test_r18_above_root_timestamps_do_not_invalidate(prefix_mailbox, monkeypatch, record_property, ancestor, api):
    mailbox = prefix_mailbox
    trace = MemoTrace(monkeypatch, mailbox)
    index, records, identifier, endpoint, page = prepare_ac1(mailbox)
    path = mailbox.root.parent if ancestor == "parent" else mailbox.root.parent.parent
    metadata = path.stat()
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1000000))
    counts = ReadCounts(monkeypatch, trace)
    assert_warm_call(index, records, identifier, endpoint, page, api, trace, counts, record_property)
    assert trace.events == []
    assert trace.above_root.isdisjoint(index._observations)
    assert all(trace.above_root.isdisjoint(entry["paths"]) for entry in index._entries.values())
    assert all(trace.above_root.isdisjoint(paths) for paths in index._folder_paths.values())


@pytest.mark.parametrize("relative,expected", [
    (".", ["note-0", "dispatch-0", "accepted-0", "note-1", "dispatch-1", "accepted-1",
           "note-2", "dispatch-2", "accepted-2"]),
    ("a", ["note-2", "dispatch-2", "accepted-2"]),
    ("a/lane", ["dispatch-2", "accepted-2"]),
    ("a/orchestrator", ["accepted-2"]),
    ("across/lane", []),
])
@pytest.mark.parametrize("change", ["timestamp", "chmod", "replace"])
@pytest.mark.usefixtures("posix_reuse")
def test_r18_in_scope_directory_change_revalidates_its_records(prefix_mailbox, monkeypatch, relative, expected, change):
    mailbox = prefix_mailbox
    trace = MemoTrace(monkeypatch, mailbox)
    index, records, identifier, _, _ = prepare_ac1(mailbox)
    real_validate = mailbox.validate_message
    validated = []

    def validate(message, **kwargs):
        validated.append(message["message_id"])
        return real_validate(message, **kwargs)

    monkeypatch.setattr(mailbox, "validate_message", validate)
    path = mailbox.root / relative
    metadata = path.stat()
    if change == "timestamp":
        os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1000000))
        expected = []  # ADR ~21:02Z: directory timestamps no longer bind outcomes.
    elif change == "chmod":
        path.chmod(metadata.st_mode ^ 0o040)
    else:
        path = mailbox.root if relative == "." else path
        moved = mailbox.root.parent / "moved-directory"
        path.rename(moved)
        path.mkdir(mode=metadata.st_mode & 0o777)
        for child in moved.iterdir():
            child.rename(path / child.name)
    trace.reset()
    assert index.get(identifier) == records[identifier]
    if change == "replace":
        # Moving leaf files also changes their ctime, requiring fresh parsing
        # and fresh pinned validation. Unaffected records stay reused.
        assert sorted(set(validated)) == sorted(expected)
    else:
        assert sorted(validated) == sorted(expected)
    assert index.last_reconciliation is None


@pytest.mark.usefixtures("posix_reuse")
def test_r18_pending_sibling_keeps_full_internal_directory_observation(prefix_mailbox, monkeypatch):
    mailbox = prefix_mailbox
    trace = MemoTrace(monkeypatch, mailbox)
    index, records, identifier, _, _ = prepare_ac1(mailbox)
    (mailbox.root / "a/lane/.pending-sibling").write_bytes(b"unrelated publication")
    trace.reset()
    assert index.get(identifier) == records[identifier]
    assert trace.validations == 0  # ADR ~21:02Z: the directory identity is unchanged.
    assert index.messages() == mailbox.messages()


def preserve_source_stat(monkeypatch, metadata):
    """Simulate the same-stat boundary only at the index's OS reference."""
    module = index_module()
    real_os = module.os

    def original(value):
        return metadata if (value.st_dev, value.st_ino) == (metadata.st_dev, metadata.st_ino) else value

    monkeypatch.setattr(module, "os", PlatformOS(real_os.name, base=real_os,
        lstat=lambda path, *a, **kw: original(real_os.lstat(path, *a, **kw)),
        fstat=lambda descriptor: original(real_os.fstat(descriptor))))


@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("following", ["none", "read", "invalid_inbox"])
def test_r18_returned_hash_evidence_survives_fallback(mailbox, monkeypatch, api, mode, following):
    mailbox.publish(request("second"))
    index = index_module().MailboxIndex(mailbox, mode=mode)
    seed = index.messages()["seed"]
    path = Path(seed["path"])
    metadata = path.stat()
    old_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    rewrite(path, {**seed["message"], "body": "modified body"})
    assert path.stat().st_size == metadata.st_size
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    new_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    preserve_source_stat(monkeypatch, metadata)
    expected = mailbox.messages()
    result = invoke(index, api)
    assert result == (expected if api == "messages" else expected["seed"] if api == "get"
                      else mailbox.inbox("a/lane/review"))
    changes = [{"kind": "content_changed", "path": str(path),
                "old_sha256": old_sha, "new_sha256": new_sha}]
    checked = index_module()._checked_reads_supported()
    if checked:
        assert index.last_reconciliation["kind"] == "pinned_fallback"
    else:
        assert index.last_reconciliation is None and index.content_changed == changes
    if following == "read":
        assert index.get("second") == expected["second"]
    elif following == "invalid_inbox":
        assert caught(lambda: index.inbox("a/lane/review", after="absent")) == caught(
            lambda: mailbox.inbox("a/lane/review", after="absent"))
    if checked:
        assert_fallback_verification(index, changes)
    else:
        assert not any(item["kind"] == "content_changed" for item in index.verify())


@pytest.mark.parametrize("defect", ["malformed", "missing_reply"])
def test_r18_scan_hash_evidence_survives_later_failure(mailbox, defect):
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    seed = index.messages()["seed"]
    path = Path(seed["path"])
    old_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    rewrite(path, {**seed["message"], "body": "modified body"})
    new_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    bad = path.parent / "zz-bad.md"
    if defect == "malformed":
        bad.write_bytes(b"missing header")
    else:
        rewrite(bad, {**seed["message"], "message_id": "bad", "in_reply_to": "absent"})
    assert caught(index.messages) == caught(mailbox.messages)
    bad.unlink()
    assert index.verify() == [{"kind": "content_changed", "path": str(path),
                               "old_sha256": old_sha, "new_sha256": new_sha}]
    assert index.verify() == []


@pytest.mark.parametrize("api", ["messages", "get", "inbox", "verify"])
def test_r18_above_root_symlink_still_has_pinned_error(tmp_path, api):
    parent = tmp_path / "above-root"
    parent.mkdir()
    root = parent / "mailbox"
    endpoints = {"a/front-door": {}, "a/orchestrator": {}, "a/lane/review": {"kind": "reviewer"}}
    hm.initialize(root, {"schema": "aegis.hierarchy-pilot/v1", "writer_limit": 3,
                         "endpoints": endpoints, "counterparts": []})
    mailbox = hm.Mailbox(root)
    for endpoint in endpoints:
        mailbox.bind({"endpoint": endpoint, "host": "test-host", "session": endpoint,
                      "expected_generation": 0})
    mailbox.publish(request("seed"))
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    index.messages()
    moved = tmp_path / "moved-parent"
    parent.rename(moved)
    symlink(parent, moved)
    assert caught(lambda: invoke(index, api)) == caught(mailbox.messages)


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("fault", ["bad_cursor", "brief_missing", "other_return_mismatch"])
def test_r18_evidence_after_successful_scan_then_failure(mailbox, tmp_path, monkeypatch, mode, fault):
    packet = tmp_path / "failure-packet.md"
    packet.write_bytes(b"Pinned brief.\n")
    brief = {"path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}
    mailbox.publish(request("dispatch", type="dispatch", brief=brief))
    mailbox.publish(request("second"))
    index = index_module().MailboxIndex(mailbox, mode=mode)
    records = index.messages()
    path = Path(records["seed"]["path"])
    old_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    rewrite(path, {**records["seed"]["message"], "body": "modified body"})
    expected = [{"kind": "content_changed", "path": str(path), "old_sha256": old_sha,
                 "new_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}]
    if fault == "bad_cursor":
        assert caught(lambda: index.inbox("a/lane/review", after="absent")) == caught(
            lambda: mailbox.inbox("a/lane/review", after="absent"))
    elif fault == "brief_missing":
        packet.unlink()
        assert caught(lambda: index.inbox("a/lane/review", include_briefs=True)) == caught(
            lambda: mailbox.inbox("a/lane/review", include_briefs=True))
        packet.write_bytes(b"Pinned brief.\n")
    else:
        other = Path(records["second"]["path"])
        metadata = other.stat()
        old_other = hashlib.sha256(other.read_bytes()).hexdigest()
        rewrite(other, {**records["second"]["message"], "body": "modified body"})
        assert other.stat().st_size == metadata.st_size
        preserve_source_stat(monkeypatch, metadata)
        expected.append({"kind": "content_changed", "path": str(other), "old_sha256": old_other,
                         "new_sha256": hashlib.sha256(other.read_bytes()).hexdigest()})
        assert index.get("second") == mailbox.messages()["second"]
    if fault == "other_return_mismatch" and index_module()._checked_reads_supported():
        assert_fallback_verification(index, expected)
    elif fault == "other_return_mismatch":
        assert sorted(index.content_changed, key=lambda item: item["path"]) == sorted(
            expected, key=lambda item: item["path"])
        assert index.verify() == []
    else:
        assert sorted(index.verify(), key=lambda item: item["path"]) == sorted(expected, key=lambda item: item["path"])
        assert index.verify() == []


def test_r18_shadow_oracle_error_keeps_prior_hash_observation(mailbox, monkeypatch):
    index = index_module().MailboxIndex(mailbox)
    seed = index.messages()["seed"]
    path = Path(seed["path"])
    old_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    rewrite(path, {**seed["message"], "body": "modified body"})
    new_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    attempts = []
    restored = False

    def opened(target):
        if target == path and not restored:
            attempts.append(True)
            if len(attempts) >= 2:  # Local read succeeds; the pinned oracle then sees access failure.
                raise PermissionError("injected source access change after local scan")

    intercept_source_opens(monkeypatch, opened)
    assert caught(index.messages) == caught(mailbox.messages)
    restored = True
    assert index.verify() == [{"kind": "content_changed", "path": str(path),
                               "old_sha256": old_sha, "new_sha256": new_sha}]
    assert index.verify() == []


@pytest.mark.parametrize("ceiling", ["normal", "entries", "bytes"])
def test_r19_thousand_malformed_alternations_are_bounded(mailbox, monkeypatch, record_property, ceiling):
    module = index_module()
    if ceiling == "entries":
        monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", 1)
    elif ceiling == "bytes":
        monkeypatch.setattr(module, "MAX_EVIDENCE_BYTES",
                            module.EVIDENCE_SUMMARY_BYTES)
    mailbox.publish(request("second"))
    index = module.MailboxIndex(mailbox, mode="indexed")
    seed = index.messages()["seed"]
    path = Path(seed["path"])
    old_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    tracing = tracemalloc.is_tracing()
    if not tracing:
        _warm_mailbox_reader(mailbox, "indexed")
        tracemalloc.start()
    try:
        gc.collect()
        before = tracemalloc.get_traced_memory()[0]
        expected_error = None
        for number in range(1000):
            path.write_bytes(b"malformed A" if number % 2 == 0 else b"malformed B")
            if expected_error is None:
                expected_error = caught(mailbox.messages)
            assert caught(lambda: index.get("seed")) == expected_error
        gc.collect()
        growth = tracemalloc.get_traced_memory()[0] - before
    finally:
        if not tracing:
            tracemalloc.stop()
    record_property("retained_growth_bytes", growth)
    assert growth <= 128 * 1024
    stats = index.evidence_stats()
    record_property("evidence_stats", hm.encoded(stats).decode())
    assert stats["pending_entries"] == 1
    assert stats["entries"] <= stats["max_entries"]
    assert stats["summary_paths"] <= stats["max_summary_paths"]
    assert stats["bytes"] <= stats["max_bytes"]
    assert stats["overflow"] == (ceiling != "normal")
    rewrite(path, {**seed["message"], "body": "modified body"})
    new_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    changes = index.verify()
    assert [item for item in changes if item["kind"] == "content_changed"] == [
        {"kind": "content_changed", "path": str(path), "old_sha256": old_sha, "new_sha256": new_sha}]
    overflow = [item for item in changes if item["kind"] == "content_change_overflow"]
    assert bool(overflow) == (ceiling != "normal")
    if overflow:
        assert overflow[0]["overflow"] is True
        assert len(overflow[0]["paths"]) <= stats["max_summary_paths"]
    assert len(hm.encoded(changes)) <= stats["max_bytes"]
    assert index.evidence_stats()["pending_entries"] == 0


@pytest.mark.parametrize("following", ["none", "read", "invalid_inbox"])
def test_r19_first_old_and_latest_new_are_coalesced(mailbox, monkeypatch, following):
    mailbox.publish(request("second"))
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    seed = index.messages()["seed"]
    path = Path(seed["path"])
    metadata = path.stat()
    old_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    preserve_source_stat(monkeypatch, metadata)
    previous_sha = old_sha
    checked = index_module()._checked_reads_supported()
    for body in ("modified body", "altered! body", "modified body"):
        rewrite(path, {**seed["message"], "body": body})
        assert path.stat().st_size == metadata.st_size
        assert index.get("seed") == mailbox.messages()["seed"]
        if not checked:
            current_sha = hashlib.sha256(path.read_bytes()).hexdigest()
            assert index.content_changed == [{"kind": "content_changed", "path": str(path),
                                               "old_sha256": previous_sha, "new_sha256": current_sha}]
            previous_sha = current_sha
    if following == "read":
        assert index.get("second") == mailbox.messages()["second"]
    elif following == "invalid_inbox":
        assert caught(lambda: index.inbox("a/lane/review", after="absent")) == caught(
            lambda: mailbox.inbox("a/lane/review", after="absent"))
    new_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    if checked:
        assert_fallback_verification(index, [{"kind": "content_changed", "path": str(path),
                                             "old_sha256": old_sha, "new_sha256": new_sha}])
    else:
        assert not any(item["kind"] == "content_changed" for item in index.verify())


@pytest.mark.parametrize(("read_path", "defect"), [
    ("native", "missing_header"), ("native", "unknown_field"),
    ("native", "wrong_folder"), ("native", "missing_reply"),
    ("nonposix_fixture_cache", "missing_header"),
])
def test_r19_rejected_new_paths_do_not_enter_hash_history(mailbox, monkeypatch, defect, record_property, read_path):
    fixture_path = Path
    if read_path == "nonposix_fixture_cache":
        monkeypatch.setattr(index_module(), "_checked_reads_supported", lambda: False)

        class CachedPath(type(Path())):
            def write_bytes(self, data):
                # Allocation control for late caches on retained fixture Paths.
                # It does not identify the native Windows allocation sites.
                self.casefold_cache = tuple(part.lower() for part in self.parts)
                return super().write_bytes(data)

        fixture_path = CachedPath
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    seed = index.messages()["seed"]
    source = Path(seed["path"])
    folder = mailbox.root / "a/orchestrator" if defect == "wrong_folder" else source.parent
    paths = [os.fspath(folder / ("zz-rejected-%04d.md" % number)) for number in range(1000)]
    # Python 3.9 and 3.12 pathlib intern Path components. Retain the interned
    # strings before tracing so table growth is not charged to reader history.
    # Keep immutable strings only. Retaining Paths charges their lazily filled
    # platform caches to the reader's post-GC retention measurement.
    interned_components = [sys.intern(component) for name in paths for component in Path(name).parts]
    tracing = tracemalloc.is_tracing()
    if not tracing:
        _warm_mailbox_reader(mailbox, "indexed")
        if read_path == "nonposix_fixture_cache":
            # Fill the fixture Path cache outside the measured mailbox, then drop the Path.
            warm_cached = fixture_path(os.fspath(mailbox.root.parent / "_warm_cached.md"))
            warm_cached.write_bytes(b"warm")
            warm_cached.unlink()
            del warm_cached
        tracemalloc.start()
    try:
        gc.collect()
        before_snapshot = tracemalloc.take_snapshot()
        before = tracemalloc.get_traced_memory()[0]
        for number, name in enumerate(paths):
            path = fixture_path(name)
            message = {**seed["message"], "message_id": "rejected-%04d" % number}
            if defect == "missing_header":
                path.write_bytes(b"malformed")
            else:
                if defect == "unknown_field":
                    message["unknown"] = True
                elif defect == "missing_reply":
                    message["in_reply_to"] = "absent"
                rewrite(path, message)
            assert caught(index.messages) == caught(mailbox.messages)
            path.unlink()
        del path
        gc.collect()
        growth = tracemalloc.get_traced_memory()[0] - before
        retained = tracemalloc.take_snapshot().compare_to(before_snapshot, "traceback")[:5]
        allocation_details = "\n".join("%s\n%s" % (item, "\n".join(item.traceback.format()))
                                       for item in retained)
    finally:
        if not tracing:
            tracemalloc.stop()
        del interned_components
    record_property("retained_growth_bytes", growth)
    record_property("retained_allocation_tracebacks", allocation_details)
    assert growth <= 128 * 1024, "retained %d bytes; top 5 allocation tracebacks:\n%s" % (
        growth, allocation_details)
    assert index.verify() == []
    stats = index.evidence_stats()
    assert stats["entries"] == 1 and stats["pending_entries"] == 0
    assert stats["overflow"] is False


@pytest.mark.parametrize("ceiling", ["entries", "bytes"])
def test_r19_global_overflow_has_bounded_paths_hashes_and_counters(mailbox, monkeypatch, ceiling):
    module = index_module()
    if ceiling == "entries":
        monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", 1)
    else:
        monkeypatch.setattr(module, "MAX_EVIDENCE_BYTES",
                            module.EVIDENCE_SUMMARY_BYTES)
    monkeypatch.setattr(module, "MAX_EVIDENCE_SAMPLE_PATHS", 2)
    monkeypatch.setattr(module, "MAX_EVIDENCE_COUNT", 3)
    for number in range(5):
        mailbox.publish(request("other-%d" % number))
    index = module.MailboxIndex(mailbox, mode="indexed")
    records = index.messages()
    for record in records.values():
        rewrite(Path(record["path"]), {**record["message"], "body": "modified body"})
    assert index.messages() == mailbox.messages()
    changes = index.verify()
    overflow = [item for item in changes if item["kind"] == "content_change_overflow"]
    assert len(overflow) == 1
    summary = overflow[0]
    assert summary["overflow"] is True and summary["counts_saturated"] is True
    assert len(summary["paths"]) == 2
    assert summary["omitted_changes"] <= 3 and summary["omitted_baseline_observations"] <= 3
    assert all(item["old_sha256"] != item["new_sha256"] for item in summary["paths"])
    stats = index.evidence_stats()
    assert stats["bytes"] <= stats["max_bytes"]
    assert len(hm.encoded(changes)) <= stats["max_bytes"]


@pytest.mark.usefixtures("posix_reuse")
def test_r19_shadow_verify_retry_coalesces_latest_hash(mailbox, monkeypatch):
    index = index_module().MailboxIndex(mailbox)
    seed = index.messages()["seed"]
    path = Path(seed["path"])
    old_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    preserve_source_stat(monkeypatch, path.stat())
    rewrite(path, {**seed["message"], "body": "modified body"})
    assert index.get("seed") == mailbox.messages()["seed"]
    real_open = Path.open
    reads = []

    def opened(target, *args, **kwargs):
        if target == path and args and args[0] == "rb":
            reads.append(True)
            if len(reads) == 2:
                rewrite(path, {**seed["message"], "body": "altered! body"})
        return real_open(target, *args, **kwargs)

    monkeypatch.setattr(Path, "open", opened)
    expected_raw = b"---\n" + hm.encoded({k: v for k, v in seed["message"].items() if k != "body"})
    expected_raw += b"\n---\n\naltered! body"
    assert_fallback_verification(index, [{"kind": "content_changed", "path": str(path), "old_sha256": old_sha,
                                         "new_sha256": hashlib.sha256(expected_raw).hexdigest()}])
    assert len(reads) >= 4


@pytest.mark.parametrize("name", ["renamed.md", "caf\u00e9-\U0001f4e91.md"])
def test_r19_summary_path_is_byte_bounded_and_identifiable(mailbox, monkeypatch, name):
    module = index_module()
    monkeypatch.setattr(module, "MAX_EVIDENCE_BYTES",
                        module.EVIDENCE_SUMMARY_BYTES)
    monkeypatch.setattr(module, "MAX_EVIDENCE_SAMPLE_PATH_BYTES", 24)
    source = Path(mailbox.messages()["seed"]["path"])
    source = source.rename(source.with_name(name))
    index = module.MailboxIndex(mailbox, mode="indexed")
    seed = index.messages()["seed"]
    old_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    source.write_bytes(b"malformed")
    assert caught(index.messages) == caught(mailbox.messages)
    rewrite(source, {**seed["message"], "body": "modified body"})
    new_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    changes = index.verify()
    overflow = [item for item in changes if item["kind"] == "content_change_overflow"]
    assert len(overflow) == 1
    sample = overflow[0]["paths"][0]
    assert sample["path_truncated"] is True
    assert len(hm.encoded(sample["path"])) <= 24
    assert str(source).startswith(sample["path"])
    assert sample["path_sha256"] == hashlib.sha256(os.fsencode(source)).hexdigest()
    assert sample["old_sha256"] == old_sha and sample["new_sha256"] == new_sha
    assert len(hm.encoded(changes)) <= module.MAX_EVIDENCE_BYTES
    assert not any(item["kind"] == "content_changed" for item in changes)


@pytest.mark.parametrize("write", ["publish", "record_read"])
@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
@pytest.mark.usefixtures("posix_reuse")
def test_r20_pinned_write_keeps_existing_validation(mailbox, tmp_path, monkeypatch, write, api):
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    existing = set(index.messages())
    if write == "publish":
        mailbox.publish(request("new"))
    else:
        mailbox.record_read(tmp_path / "delivery", request("reader", "a/lane/review"), ["seed"])
    validated = []
    real_validate = mailbox.validate_message

    def validate(message, **kwargs):
        validated.append(message["message_id"])
        return real_validate(message, **kwargs)

    monkeypatch.setattr(mailbox, "validate_message", validate)
    parses = spy_parses(monkeypatch)
    invoke(index, api)
    assert not existing.intersection(validated)
    assert len(parses) == (1 if write == "publish" else 0)
    assert index.last_reconciliation is None


@pytest.mark.parametrize("fault", ["cursor", "zero_limit", "large_limit", "endpoint", "brief_hash"])
@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.usefixtures("posix_reuse")
def test_r20_caller_error_preserves_warm_memo(mailbox, tmp_path, monkeypatch, fault, mode):
    packet = tmp_path / "caller-brief.md"
    packet.write_bytes(b"Original brief.\n")
    mailbox.publish(request("dispatch", type="dispatch",
                            brief={"path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}))
    trace = MemoTrace(monkeypatch, mailbox)
    index = index_module().MailboxIndex(mailbox, mode=mode)
    expected = index.messages()["seed"]
    endpoint, kwargs = "a/lane/review", {}
    if fault == "cursor":
        kwargs["after"] = "absent"
    elif fault in ("zero_limit", "large_limit"):
        kwargs["limit"] = 0 if fault == "zero_limit" else 101
    elif fault == "endpoint":
        endpoint = "a/lane/unknown"
    else:
        packet.write_bytes(b"Different brief.\n")
        kwargs["include_briefs"] = True
    assert caught(lambda: index.inbox(endpoint, **kwargs)) == caught(lambda: mailbox.inbox(endpoint, **kwargs))
    trace.reset()
    assert index.get("seed") == expected
    assert trace.memo_validations == 0
    assert not any(event["kind"] == "clear" for event in trace.events)
    assert index.last_reconciliation is None


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_r20_get_unhashable_caller_key_preserves_memo(mailbox, monkeypatch, mode):
    trace = MemoTrace(monkeypatch, mailbox)
    index = index_module().MailboxIndex(mailbox, mode=mode)
    expected = index.messages()["seed"]
    assert caught(lambda: index.get([])) == caught(lambda: mailbox.messages().get([]))
    trace.reset()
    assert index.get("seed") == expected
    assert trace.memo_validations == (0 if index_module()._checked_reads_supported() else 1)
    assert not any(event["kind"] == "clear" for event in trace.events)


def test_r20_lost_directory_search_permission_fails_live(mailbox):
    folder = mailbox.root / "a/lane"
    mode = folder.stat().st_mode & 0o777
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    index.messages()
    try:
        folder.chmod(0)
        if os.access(folder, os.X_OK):
            pytest.skip("search permission is not enforced for this uid")
        assert caught(lambda: index.get("seed")) == caught(mailbox.messages)
    finally:
        folder.chmod(mode)


@pytest.mark.parametrize("site", ["probe", "materialize"])
@pytest.mark.parametrize("kind", ["fifo", "symlink_fifo"])
def test_r20_replaced_fifo_cannot_block_reader(mailbox, site, kind):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO capability unavailable")
    driver = '''import sys,os,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from tools import hierarchy_mailbox as hm
from tools.hierarchy_mailbox_index import MailboxIndex
box=hm.Mailbox(sys.argv[2]); index=MailboxIndex(box,mode="indexed")
record=index.messages()["seed"]; target=Path(record["path"])
if sys.argv[3]=="probe": target.parent.chmod(target.parent.stat().st_mode ^ 0o040)
real_path_open,real_os_open=Path.open,os.open
swapped=False
def swap(path):
 global swapped
 if os.fspath(path)==str(target) and not swapped:
  swapped=True
  fifo=box.root.parent/"replacement-fifo"
  os.mkfifo(fifo)
  if sys.argv[4]=="symlink_fifo":
   link=box.root.parent/"replacement-link"; link.symlink_to(fifo); os.replace(link,target)
  else: os.replace(fifo,target)
def path_open(path,*a,**kw):
 swap(path); return real_path_open(path,*a,**kw)
def os_open(path,*a,**kw):
 swap(path); return real_os_open(path,*a,**kw)
Path.open,os.open=path_open,os_open
def error(call):
 try: call()
 except Exception as exc: return [type(exc).__name__,str(exc)]
 raise AssertionError("FIFO was returned")
actual=error(lambda:index.get("seed")); expected=error(box.messages)
assert swapped and actual==expected,(actual,expected)
print(json.dumps(actual))
'''
    try:
        result = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(Path(hm.__file__).parent.parent),
                                 str(mailbox.root), site, kind], capture_output=True, text=True, timeout=2)
    except subprocess.TimeoutExpired:
        pytest.fail("reader blocked after a FIFO replacement (2 s guard)")
    assert result.returncode == 0, result.stderr


def change_confirmation_inode(monkeypatch, source, attempts=2):
    """Race confirmation at module-owned filesystem boundaries."""
    module = index_module()
    real_os = module.os
    state = {"read": False, "injected": False, "injections": 0}

    class ReadPath(type(hm.Path())):
        def open(self, *args, **kwargs):
            if os.fspath(self) == str(source) and args and args[0] == "rb":
                state["read"] = True
            return super().open(*args, **kwargs)

    def lstat(path, *args, **kwargs):
        value = real_os.lstat(path, *args, **kwargs)
        if os.fspath(path) == str(source.parent) and state["read"] and state["injections"] < attempts:
            state.update(read=False, injected=True, injections=state["injections"] + 1)
            return SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino + 1, st_mode=value.st_mode,
                                   st_uid=value.st_uid, st_size=value.st_size,
                                   st_mtime_ns=value.st_mtime_ns, st_ctime_ns=value.st_ctime_ns)
        return value

    monkeypatch.setattr(hm, "Path", ReadPath)
    monkeypatch.setattr(module, "os", PlatformOS(real_os.name, base=real_os, lstat=lstat))
    return state


@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_r20_cold_fallback_return_seeds_hash_baseline(mailbox, monkeypatch, api, mode):
    seed = mailbox.messages()["seed"]
    source = Path(seed["path"])
    old_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    state = change_confirmation_inode(monkeypatch, source)
    index = index_module().MailboxIndex(mailbox, mode=mode)
    result = invoke(index, api)
    assert result == (mailbox.messages() if api == "messages" else seed if api == "get"
                      else mailbox.inbox("a/lane/review"))
    assert state["injected"] and index.last_reconciliation is not None
    metadata = source.stat()
    rewrite(source, {**seed["message"], "body": "modified body"})
    os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    new_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    assert_fallback_verification(index, [{"kind": "content_changed", "path": str(source),
                                         "old_sha256": old_sha, "new_sha256": new_sha}])


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_r20_unavailable_verify_keeps_overflow_and_pending(mailbox, monkeypatch, mode):
    module = index_module()
    monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", 1)
    mailbox.publish(request("second"))
    index = module.MailboxIndex(mailbox, mode=mode)
    seed = index.messages()["seed"]
    source = Path(seed["path"])
    metadata = source.stat()
    old_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    preserve_source_stat(monkeypatch, metadata)
    rewrite(source, {**seed["message"], "body": "modified body"})
    new_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    if module._checked_reads_supported():
        assert index.get("seed") == mailbox.messages()["seed"]
    else:
        # A hash-first successful read acknowledges its own change. Force the
        # same interrupted-read schedule so the pending fact is unreported.
        with monkeypatch.context() as failure:
            interrupted = change_confirmation_inode(failure, source)
            assert index.get("seed") == mailbox.messages()["seed"]
            assert interrupted["injected"]
    before = next(item for item in index.content_changed if item["kind"] == "content_change_overflow")
    state = change_confirmation_inode(monkeypatch, source)
    unavailable = index.verify()
    assert state["injected"]
    assert any(item["kind"] == "verification_unavailable" for item in unavailable)
    assert index.evidence_stats()["overflow"] is True
    assert index.evidence_stats()["pending_entries"] >= 1
    reported = index.verify()
    assert any(item["kind"] == "verification_unavailable" for item in reported)
    assert index.evidence_stats()["overflow"] is True
    assert index.evidence_stats()["pending_entries"] >= 1
    completed = index.verify()
    assert not any(item["kind"] == "verification_unavailable" for item in completed)
    assert [item for item in completed if item["kind"] == "content_changed"] == [
        {"kind": "content_changed", "path": str(source), "old_sha256": old_sha, "new_sha256": new_sha}]
    after = next(item for item in completed if item["kind"] == "content_change_overflow")
    assert after["paths"] == before["paths"]
    assert after["omitted_baseline_observations"] >= before["omitted_baseline_observations"]
    assert index.evidence_stats()["overflow"] is False


def test_r20_fallback_preserves_already_read_canonical_bytes(mailbox, monkeypatch):
    seed = mailbox.messages()["seed"]
    source = Path(seed["path"])
    original = source.read_bytes()
    old_sha = hashlib.sha256(original).hexdigest()
    changed = b"---\n " + original[4:]  # Same parsed message; different frontmatter bytes.
    metadata = source.stat()
    state = change_confirmation_inode(monkeypatch, source)
    real_open = Path.open
    reads = []

    class Stream:
        def __init__(self, stream, number):
            self.stream, self.number = stream, number

        def __enter__(self):
            return self.stream.__enter__()

        def __exit__(self, *args):
            result = self.stream.__exit__(*args)
            if self.number == 3:  # Two raced scans, then PIN reads A before the file changes.
                source.write_bytes(changed)
                os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
            return result

    def opened(path, *args, **kwargs):
        stream = real_open(path, *args, **kwargs)
        if path == source and args and args[0] == "rb":
            reads.append(True)
            return Stream(stream, len(reads))
        return stream

    monkeypatch.setattr(Path, "open", opened)
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    assert index.get("seed") == seed
    assert state["injections"] == 2 and len(reads) >= 3
    changes = index.verify()
    assert [item for item in changes if item["kind"] == "content_changed"] == [
        {"kind": "content_changed", "path": str(source), "old_sha256": old_sha,
         "new_sha256": hashlib.sha256(changed).hexdigest()}]
    # A changed stat fence cannot distinguish an edit before PIN read from one
    # after it. Keep the observed change and explicitly disclaim PIN-byte coverage.
    assert any(item["kind"] == "verification_unavailable" for item in changes)


def r21_fill_history(mailbox, count):
    # Same fixture construction as the pinned full-history test: clone a pinned
    # stored message, then let both public readers validate the complete history.
    seed = mailbox.messages()["seed"]
    folder = Path(seed["path"]).parent
    for number in range(1, count):
        rewrite(folder / ("dead-%05d.md" % number),
                {**seed["message"], "message_id": "dead-%05d" % number})


def r21_force_fallback(index, mailbox, monkeypatch):
    records = mailbox.messages()
    source = Path(next(iter(records.values()))["path"])
    metadata = source.stat()
    # Windows file times have 100 ns resolution; one nanosecond can round away.
    index_module().os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1000000))
    assert source.stat().st_mtime_ns != metadata.st_mtime_ns
    with monkeypatch.context() as patches:
        state = change_confirmation_inode(patches, source)
        assert index.messages() == records
        assert state["injected"] and index.last_reconciliation is not None


def test_platform_coarse_timestamps_still_force_fallback(mailbox, monkeypatch):
    source = Path(mailbox.messages()["seed"]["path"])
    metadata = source.stat()
    os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns // 100 * 100))
    module = index_module()
    real_os = module.os

    def creation_time(value):
        if (value.st_dev, value.st_ino) != (metadata.st_dev, metadata.st_ino):
            return value
        return SimpleNamespace(st_mode=value.st_mode, st_size=value.st_size, st_uid=value.st_uid,
                               st_mtime_ns=value.st_mtime_ns, st_ctime_ns=metadata.st_ctime_ns,
                               st_dev=value.st_dev, st_ino=value.st_ino)

    monkeypatch.setattr(module, "os", PlatformOS(real_os.name, base=real_os,
        lstat=lambda path, *a, **kw: creation_time(real_os.lstat(path, *a, **kw)),
        fstat=lambda fd: creation_time(real_os.fstat(fd))))
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    index.messages()
    real_utime = os.utime

    def coarse_utime(path, *, ns):
        return real_utime(path, ns=tuple(value // 100 * 100 for value in ns))

    monkeypatch.setattr(module, "os", PlatformOS(module.os.name, base=module.os, utime=coarse_utime))
    r21_force_fallback(index, mailbox, monkeypatch)


def r21_assert_covered(changes, path, old_sha, new_sha):
    expected = {"kind": "content_changed", "path": str(path),
                "old_sha256": old_sha, "new_sha256": new_sha}
    if expected not in changes:
        unavailable = [item for item in changes if item["kind"] == "verification_unavailable"]
        # A global scope explicitly disclaims coverage for every returned path,
        # including paths omitted from the bounded diagnostic sample.
        assert any(item.get("scope") == "all_returned_records" or
                   any(sample["path"] == str(path) for sample in item.get("paths", []))
                   for item in unavailable), changes


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("rejected_scan", [False, True])
def test_r21_deleted_history_reclaims_live_capacity(mailbox, monkeypatch, mode, rejected_scan):
    module = index_module()
    monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", 2)
    mailbox.publish(request("second"))
    index = module.MailboxIndex(mailbox, mode=mode)
    records = index.messages()
    for record in records.values():
        Path(record["path"]).unlink()
    if rejected_scan:
        bad = mailbox.root / "a/lane/bad.md"
        bad.write_bytes(b"malformed")
        assert caught(index.messages) == caught(mailbox.messages)
        assert index.evidence_stats()["entries"] == 2  # Failed scans prove no deletion.
        bad.unlink()
    assert index.messages() == {}
    assert index.evidence_stats()["entries"] == 0
    assert index.evidence_stats()["bytes"] == module.EVIDENCE_SUMMARY_BYTES
    for number in range(2):
        mailbox.publish(request("new-%d" % number))
    assert index.messages() == mailbox.messages()
    assert index.evidence_stats()["entries"] == 2
    assert index.evidence_stats()["overflow"] is False
    assert index.verify() == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("count", [12, pytest.param(10000, marks=pytest.mark.skipif(
    not os.environ.get("AEGIS_MB1_R21_10K"), reason="explicit 10k retirement regression required"))])
def test_r21_argon_deleted_full_history_then_unsampled_fallback(mailbox, monkeypatch, mode, count):
    module = index_module()
    monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", count)
    r21_fill_history(mailbox, count)
    index = module.MailboxIndex(mailbox, mode=mode)
    records = index.messages()
    assert len(records) == count and records == mailbox.messages()
    for record in records.values():
        Path(record["path"]).unlink()
    for number in range(1, 10):
        mailbox.publish(request("m%d" % number))
    records = index.messages()
    assert records == mailbox.messages()
    r21_force_fallback(index, mailbox, monkeypatch)
    record = records["m9"]
    source = Path(record["path"])
    metadata = source.stat()
    old_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    rewrite(source, {**record["message"], "body": "modified body"})
    os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    new_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    r21_assert_covered(index.verify(), source, old_sha, new_sha)
    assert index.evidence_stats()["entries"] == 9


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("fallback", [False, True])
def test_r21_unsampled_live_overflow_cannot_claim_coverage(mailbox, monkeypatch, mode, fallback):
    module = index_module()
    monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", 1)
    for number in range(1, 10):
        mailbox.publish(request("m%d" % number))
    index = module.MailboxIndex(mailbox, mode=mode)
    records = index.messages()
    if fallback:
        r21_force_fallback(index, mailbox, monkeypatch)
    source = Path(records["m9"]["path"])
    metadata = source.stat()
    old_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    rewrite(source, {**records["m9"]["message"], "body": "modified body"})
    os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    new_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    changes = index.verify()
    overflow = next(item for item in changes if item["kind"] == "content_change_overflow")
    assert overflow["omitted_changes"] > 0, changes
    assert len(overflow["paths"]) <= module.MAX_EVIDENCE_SAMPLE_PATHS
    r21_assert_covered(changes, source, old_sha, new_sha)
    marker = next(item for item in changes if item["kind"] == "verification_unavailable")
    assert marker["unbaselined_paths"] == 1 and marker["paths_complete"] is True
    assert [item["path"] for item in marker["paths"]] == [str(source)]
    # Persistent capacity loss cannot become a clean verification after one report.
    r21_assert_covered(index.verify(), source, old_sha, new_sha)
    for identifier, record in records.items():
        if identifier != "m9":
            Path(record["path"]).unlink()
    index.verify()  # Report the historical gap while establishing the remaining baseline.
    assert index.evidence_stats()["entries"] == 1
    assert index.verify() == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_r21_canonical_full_scan_reclaims_deleted_history(mailbox, monkeypatch, mode):
    module = index_module()
    monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", 1)
    index = module.MailboxIndex(mailbox, mode=mode)
    seed = index.messages()["seed"]
    Path(seed["path"]).unlink()
    mailbox.publish(request("replacement"))
    r21_force_fallback(index, mailbox, monkeypatch)
    assert index.evidence_stats()["overflow"] is False
    assert_fallback_verification(index, [])


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_r21_gap_diagnostics_remain_bounded_and_global(mailbox, monkeypatch, mode):
    module = index_module()
    monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", 0)
    for number in range(20):
        mailbox.publish(request("m%02d" % number))
    index = module.MailboxIndex(mailbox, mode=mode)
    index.messages()
    # No bounded samples are available for these thirteen paths. Every verify must
    # explicitly disclaim coverage, even after a previous unavailable report.
    for _ in range(2):
        result = index.verify()
        marker = next(item for item in result if item["kind"] == "verification_unavailable")
        assert marker["scope"] == "all_returned_records"
        assert marker["unbaselined_paths"] == 13 and marker["paths_complete"] is False
        assert len(marker["paths"]) == module.MAX_EVIDENCE_SAMPLE_PATHS
        assert len(hm.encoded(result)) <= module.EVIDENCE_SUMMARY_BYTES


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_r21_retiring_path_preserves_unreported_hash_change(mailbox, monkeypatch, mode):
    module = index_module()
    monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", 1)
    index = module.MailboxIndex(mailbox, mode=mode)
    record = index.messages()["seed"]
    source = Path(record["path"])
    old_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    rewrite(source, {**record["message"], "body": "modified body"})
    new_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    assert caught(lambda: index.inbox("a/lane/review", after="absent")) == caught(
        lambda: mailbox.inbox("a/lane/review", after="absent"))
    source.unlink()
    assert index.messages() == {}
    assert index.evidence_stats()["entries"] == 0
    changes = index.verify()
    assert {"kind": "content_changed", "path": str(source),
            "old_sha256": old_sha, "new_sha256": new_sha} in changes
    assert index.verify() == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("reported_change", [False, True])
def test_r22_verify_retains_live_sample_baseline(mailbox, monkeypatch, mode, fallback, reported_change):
    module = index_module()
    monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", 1)
    mailbox.publish(request("second"))
    index = module.MailboxIndex(mailbox, mode=mode)
    records = index.messages()
    source = Path(records["second"]["path"])
    original_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    if reported_change:
        rewrite(source, {**records["second"]["message"], "body": "modified body"})
    old_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    initial = index.verify()
    assert not any(item["kind"] == "verification_unavailable" for item in initial)
    assert [item for item in initial if item["kind"] == "content_changed"] == ([
        {"kind": "content_changed", "path": str(source), "old_sha256": original_sha,
         "new_sha256": old_sha}] if reported_change else [])
    # Repeated acknowledgements must keep the latest baseline while consuming
    # already reported facts, including a previous A->B change in the sample.
    assert not any(item["kind"] == "content_changed" for item in index.verify())
    assert index.evidence_stats()["pending_entries"] == 0
    metadata = source.stat()
    rewrite(source, {**records["second"]["message"],
                     "body": "altered! body" if reported_change else "modified body"})
    os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    new_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    if fallback:
        r21_force_fallback(index, mailbox, monkeypatch)
    changes = index.verify()
    assert [item for item in changes if item["kind"] == "content_changed"] == [
        {"kind": "content_changed", "path": str(source), "old_sha256": old_sha, "new_sha256": new_sha}]
    if fallback:
        assert any(item["kind"] == "verification_unavailable" for item in changes)
        complete = index.verify()
        assert [item for item in complete if item["kind"] == "content_changed"] == [
            {"kind": "content_changed", "path": str(source), "old_sha256": old_sha, "new_sha256": new_sha}]
        assert not any(item["kind"] == "verification_unavailable" for item in complete)
    else:
        assert not any(item["kind"] == "verification_unavailable" for item in changes)
    assert not any(item["kind"] == "content_changed" for item in index.verify())
    assert index.evidence_stats()["pending_entries"] == 0


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("rejected_scan", [False, True])
def test_r22_live_sample_retires_only_after_successful_scan(mailbox, monkeypatch, mode, rejected_scan):
    module = index_module()
    monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", 1)
    mailbox.publish(request("second"))
    index = module.MailboxIndex(mailbox, mode=mode)
    records = index.messages()
    index.verify()
    assert index.evidence_stats()["summary_paths"] == 1
    source = Path(records["second"]["path"])
    source.unlink()
    if rejected_scan:
        bad = source.parent / "bad.md"
        bad.write_bytes(b"malformed")
        assert caught(index.messages) == caught(mailbox.messages)
        assert index.evidence_stats()["summary_paths"] == 1
        bad.unlink()
    assert index.messages() == mailbox.messages()
    assert index.evidence_stats()["summary_paths"] == 0
    assert index.verify() == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_r22_retired_sample_fact_is_acknowledged_without_retaining_dead_baseline(mailbox, monkeypatch, mode):
    module = index_module()
    monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", 1)
    mailbox.publish(request("second"))
    index = module.MailboxIndex(mailbox, mode=mode)
    record = index.messages()["second"]
    source = Path(record["path"])
    old_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    rewrite(source, {**record["message"], "body": "modified body"})
    new_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    assert caught(lambda: index.inbox("a/lane/review", after="absent")) == caught(
        lambda: mailbox.inbox("a/lane/review", after="absent"))
    source.unlink()
    assert index.messages() == mailbox.messages()
    changes = index.verify()
    assert {"kind": "content_changed", "path": str(source),
            "old_sha256": old_sha, "new_sha256": new_sha} in changes
    assert index.evidence_stats()["summary_paths"] == 0
    assert index.evidence_stats()["pending_entries"] == 0
    assert index.verify() == []


def r23_publish_during_pinned_listings(monkeypatch, mailbox, *, replace, count, mutation):
    """Publish at PIN's Path.iterdir boundary; index listing uses os.scandir."""
    folder = Path(mailbox.messages()["seed"]["path"]).parent
    real_iterdir, real_open = Path.iterdir, Path.open
    state = {"publications": 0, "busy": False, "target": None, "old": None, "new": None}

    def listing(path):
        if path == folder and not state["busy"] and state["publications"] < count:
            state["busy"] = True
            try:
                if replace:
                    Path(mailbox.messages()["seed"]["path"]).unlink()
                number = state["publications"] + 1
                record = mailbox.publish(request("seed" if replace else "published-%d" % number))
                state.update(publications=number, target=Path(record["path"]))
            finally:
                state["busy"] = False
        return real_iterdir(path)

    class Stream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self.stream.__enter__()

        def __exit__(self, *args):
            result = self.stream.__exit__(*args)
            target = state["target"]
            if state["old"] is None:
                state["old"] = "capturing"
                raw = target.read_bytes()
                state["old"] = hashlib.sha256(raw).hexdigest()
                metadata = target.stat()
                changed = b"---\n " + raw[4:] if mutation == "format" else raw.replace(
                    b"original body", b"modified body")
                target.write_bytes(changed)
                os.utime(target, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
                state["new"] = hashlib.sha256(changed).hexdigest()
            return result

    def opened(path, *args, **kwargs):
        stream = real_open(path, *args, **kwargs)
        if (mutation != "none" and path == state["target"] and args and args[0] == "rb"
                and not state["busy"] and state["publications"] == count and state["old"] is None):
            return Stream(stream)
        return stream

    monkeypatch.setattr(Path, "iterdir", listing)
    monkeypatch.setattr(Path, "open", opened)
    return state


def r23_finish_return_coverage(index, state):
    source = state["target"]
    if state["old"] is None:
        raw = source.read_bytes()
        metadata = source.stat()
        state["old"] = hashlib.sha256(raw).hexdigest()
        changed = raw.replace(b"original body", b"modified body")
        source.write_bytes(changed)
        os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        state["new"] = hashlib.sha256(changed).hexdigest()
    r21_assert_covered(index.verify(), source, state["old"], state["new"])
    assert not any(item["kind"] == "verification_unavailable" for item in index.verify())


def r23_source_reads(monkeypatch, source, *, descriptor_only=False):
    """Count real reads through module-owned path/descriptor references."""
    module = index_module()
    real_os = module.os
    descriptors, reads = set(), []

    def opened(path, *args, **kwargs):
        descriptor = real_os.open(path, *args, **kwargs)
        if os.fspath(path) == str(source):
            descriptors.add(descriptor)
        else:
            descriptors.discard(descriptor)
        return descriptor

    class Stream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self, *args):
            reads.append(True)
            return self.stream.read(*args)

        def __getattr__(self, name):
            return getattr(self.stream, name)

    def fdopen(descriptor, *args, **kwargs):
        value = real_os.fdopen(descriptor, *args, **kwargs)
        return Stream(value) if descriptor in descriptors else value

    class SourcePath(type(hm.Path())):
        def open(self, *args, **kwargs):
            value = super().open(*args, **kwargs)
            return Stream(value) if not descriptor_only and os.fspath(self) == str(source) else value

    monkeypatch.setattr(module, "os", PlatformOS(real_os.name, base=real_os, open=opened, fdopen=fdopen))
    monkeypatch.setattr(hm, "Path", SourcePath)
    return reads


@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
@pytest.mark.parametrize("mutation", ["none", "body", "format"])
def test_r23_final_shadow_records_keep_coverage(mailbox, monkeypatch, api, mutation):
    index = index_module().MailboxIndex(mailbox)
    state = r23_publish_during_pinned_listings(monkeypatch, mailbox, replace=api == "get",
                                              count=2, mutation=mutation)
    result = invoke(index, api)
    assert state["publications"] == 2 and index.last_divergence
    returned = result.values() if api == "messages" else [result] if api == "get" else result["messages"]
    assert str(state["target"]) in [record["path"] for record in returned]
    r23_finish_return_coverage(index, state)


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("branch", ["scan", "materialize"])
@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
@pytest.mark.parametrize("mutation", ["none", "body", "format"])
def test_r23_pinned_fallback_return_coverage(mailbox, monkeypatch, mode, branch, api, mutation):
    index = index_module().MailboxIndex(mailbox, mode=mode)
    source = Path(mailbox.messages()["seed"]["path"])
    if branch == "materialize":
        index.messages()
    state = r23_publish_during_pinned_listings(monkeypatch, mailbox, replace=api == "get",
                                              count=1, mutation=mutation)
    if branch == "scan":
        injected = change_confirmation_inode(monkeypatch, source)
    else:
        module = index_module()
        real_os = module.os
        injected = {"injected": False}

        def opened(path, *args, **kwargs):
            if os.fspath(path) == str(source) and not injected["injected"]:
                injected["injected"] = True
                raise PermissionError("injected materialization access change")
            return real_os.open(path, *args, **kwargs)

        if module._checked_reads_supported():
            monkeypatch.setattr(module, "os", PlatformOS(real_os.name, base=real_os, open=opened))
        else:
            real_read = hm.read_bytes

            def read(path):
                if os.fspath(path) == str(source) and not injected["injected"]:
                    injected["injected"] = True
                    raise PermissionError("injected current-byte access change")
                return real_read(path)

            monkeypatch.setattr(hm, "read_bytes", read)
    result = invoke(index, api)
    assert injected["injected"] and state["publications"] == 1
    returned = result.values() if api == "messages" else [result] if api == "get" else result["messages"]
    assert str(state["target"]) in [record["path"] for record in returned]
    r23_finish_return_coverage(index, state)


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("dependency", ["packet", "packet_ancestor"])
def test_r23_changed_packet_rereads_all_dependents(mailbox, tmp_path, monkeypatch, mode, dependency):
    folder = tmp_path / "packets"
    folder.mkdir()
    packet = folder / "packet.md"
    packet.write_bytes(b"Packet A.\n")
    brief = {"path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}
    for identifier in ("dispatch-1", "dispatch-2"):
        mailbox.publish(request(identifier, type="dispatch", brief=brief))
    index = index_module().MailboxIndex(mailbox, mode=mode)
    records = index.messages()
    for identifier in ("dispatch-1", "dispatch-2"):
        preserve_source_stat(monkeypatch, Path(records[identifier]["path"]).stat())
    if dependency == "packet_ancestor":
        preserve_source_stat(monkeypatch, packet.stat())
        folder.chmod(folder.stat().st_mode ^ 0o040)
    packet.write_bytes(b"Packet B.\n")
    changed = {"path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}
    for identifier in ("dispatch-1", "dispatch-2"):
        record = records[identifier]
        rewrite(Path(record["path"]), {**record["message"], "brief": changed})
    expected = mailbox.inbox("a/lane/review", include_briefs=True)
    for _ in range(2):
        assert index.inbox("a/lane/review", include_briefs=True) == expected
        assert index.last_divergence == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("dependency", ["worktree", "worktree_ancestor"])
def test_r23_changed_readiness_dependency_rereads_unreturned_record(mailbox, tmp_path, monkeypatch, mode, dependency):
    mailbox.publish(request("reverse", sender="a/lane/review", recipient="a/orchestrator"))
    source = mailbox.messages()["seed"]
    worktree = tmp_path / "ready" / "worktree"
    worktree.mkdir(parents=True)
    readiness = {"worktree": str(worktree), "scan_workspace": str(worktree), "branch": "feature/a",
                 "base_revision": "a" * 40, "lease_oid": "b" * 40, "lease_ref": "refs/aegis/lanes/a",
                 "lease_expires_at": "2099-01-01T00:00:00Z", "owned_paths": ["tools/x.py"],
                 "scan_evidence": "scan", "hook_evidence": "hook", "enforcement_tier": "advisory"}
    path = Path(source["path"])
    message = {**source["message"], "type": "ack", "in_reply_to": "reverse", "acknowledgment": "accepted",
               "readiness": readiness}
    rewrite(path, message)
    expected = mailbox.messages()
    index = index_module().MailboxIndex(mailbox, mode=mode)
    assert index.messages() == expected
    preserve_source_stat(monkeypatch, path.stat())
    changed_path = worktree if dependency == "worktree" else worktree.parent
    if os.name == "posix":
        changed_path.chmod(changed_path.stat().st_mode ^ 0o040)
    else:
        moved = tmp_path / "previous-readiness"
        changed_path.rename(moved)
        shutil.copytree(moved, changed_path)
    rewrite(path, {**message, "body": "modified body"})
    reads = r23_source_reads(monkeypatch, path)
    assert index.get("reverse") == expected["reverse"]
    assert len(reads) == (1 if mode == "indexed" else 2)
    assert index.last_divergence == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
@pytest.mark.parametrize("following", ["none", "read", "invalid_inbox"])
def test_r23_overflow_promotion_waits_for_verify(mailbox, monkeypatch, mode, api, following):
    module = index_module()
    monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", 1)
    mailbox.publish(request("second"))
    index = module.MailboxIndex(mailbox, mode=mode)
    records = index.messages()
    source = Path(records["second"]["path"])
    old_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    rewrite(source, {**records["second"]["message"], "body": "modified body"})
    new_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    assert caught(lambda: index.inbox("a/lane/review", after="absent")) == caught(
        lambda: mailbox.inbox("a/lane/review", after="absent"))
    Path(records["seed"]["path"]).unlink()
    result = index.get("second") if api == "get" else index.messages() if api == "messages" else index.inbox(
        "a/lane/review")
    assert result is not None
    if following == "read":
        index.get("second")
    elif following == "invalid_inbox":
        assert caught(lambda: index.inbox("a/lane/review", after="absent")) == caught(
            lambda: mailbox.inbox("a/lane/review", after="absent"))
    assert [item for item in index.verify() if item["kind"] == "content_changed"] == [
        {"kind": "content_changed", "path": str(source), "old_sha256": old_sha, "new_sha256": new_sha}]
    assert index.verify() == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
def test_r23_candidate_changed_before_pinned_read_disclaims_original_bytes(mailbox, monkeypatch, mode, api):
    seed = mailbox.messages()["seed"]
    source = Path(seed["path"])
    raw = source.read_bytes()
    confirmation = change_confirmation_inode(monkeypatch, source)
    real_iterdir = Path.iterdir
    injected = []

    def listing(path):
        if path == source.parent and confirmation["injected"] and not injected:
            injected.append(True)
            source.write_bytes(b"---\n " + raw[4:])
        return real_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", listing)
    index = index_module().MailboxIndex(mailbox, mode=mode)
    assert invoke(index, api) == (mailbox.messages() if api == "messages" else seed if api == "get"
                                 else mailbox.inbox("a/lane/review"))
    assert injected and confirmation["injected"]
    original_returned = source.read_bytes()
    metadata = source.stat()
    changed = original_returned.replace(b"original body", b"modified body")
    source.write_bytes(changed)
    os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    r21_assert_covered(index.verify(), source, hashlib.sha256(original_returned).hexdigest(),
                       hashlib.sha256(changed).hexdigest())


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_r23_changed_reply_target_rereads_dependent(mailbox, monkeypatch, mode):
    mailbox.publish(request("reply", sender="a/lane/review", recipient="a/orchestrator", in_reply_to="seed"))
    index = index_module().MailboxIndex(mailbox, mode=mode)
    records = index.messages()
    reply = Path(records["reply"]["path"])
    preserve_source_stat(monkeypatch, reply.stat())
    rewrite(Path(records["seed"]["path"]), {**records["seed"]["message"], "body": "modified body"})
    rewrite(reply, {**records["reply"]["message"], "body": "modified body"})
    reads = r23_source_reads(monkeypatch, reply)
    assert index.get("absent") is None
    assert len(reads) == (1 if mode == "indexed" else 2)
    assert index.last_divergence == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("warm", [False, True])
@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
@pytest.mark.usefixtures("posix_reuse")
def test_r24_unencodable_brief_stays_warm_without_fallback(mailbox, monkeypatch, mode, warm, api):
    trace = MemoTrace(monkeypatch, mailbox)
    index = index_module().MailboxIndex(mailbox, mode=mode)
    if warm:
        index.messages()
    inject(mailbox, "unencodable_brief_path")
    trace.reset()
    expected = mailbox.messages()
    assert invoke(index, api) == (expected if api == "messages" else expected["seed"] if api == "get"
                                  else mailbox.inbox("a/lane/review"))
    assert index.last_reconciliation is None
    assert not any(item["kind"] == "clear" for item in trace.events)
    trace.reset()
    assert invoke(index, api) == (expected if api == "messages" else expected["seed"] if api == "get"
                                  else mailbox.inbox("a/lane/review"))
    assert trace.memo_validations == 0 and trace.events == []
    assert index.verify() == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("error", [errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP, "value",
                                   errno.EACCES, errno.EIO])
def test_r24_pathlib_observation_error_parity(mailbox, monkeypatch, mode, error):
    seed = mailbox.messages()["seed"]
    packet = mailbox.root.parent / "probe.md"
    rewrite(Path(seed["path"]), {**seed["message"], "brief": {"path": str(packet), "sha256": "a" * 64}})
    real_lstat, real_path_lstat = os.lstat, Path.lstat

    def observe(call, path, *args, **kwargs):
        if os.fspath(path) == str(packet):
            if error == "value":
                raise ValueError("injected unencodable path")
            raise OSError(error, "injected pathlib probe", str(packet))
        return call(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lambda path, *a, **kw: observe(real_lstat, path, *a, **kw))
    monkeypatch.setattr(Path, "lstat", lambda path, *a, **kw: observe(real_path_lstat, path, *a, **kw))
    index = index_module().MailboxIndex(mailbox, mode=mode)
    if error in (errno.EACCES, errno.EIO):
        assert caught(index.messages) == caught(mailbox.messages)
    else:
        expected = mailbox.messages()
        assert index.messages() == expected
        assert index.last_reconciliation is None
        assert index.messages() == expected and index.last_reconciliation is None
        assert index.verify() == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
def test_r24_pending_unlink_check_race_retries_without_clear(mailbox, monkeypatch, mode, api):
    require_posix_reuse()
    trace = MemoTrace(monkeypatch, mailbox)
    index = index_module().MailboxIndex(mailbox, mode=mode)
    index.messages()
    real_unlink = Path.unlink
    pending = []

    def defer(path, *args, **kwargs):
        if path.name.startswith(".pending-"):
            pending.append(path)
            return None
        return real_unlink(path, *args, **kwargs)

    with monkeypatch.context() as publication:
        publication.setattr(Path, "unlink", defer)
        record = mailbox.publish(request("new-record"))
    source = Path(record["path"])
    assert len(pending) == 1 and source.stat().st_ino == pending[0].stat().st_ino
    state = {"read": False, "injected": False}
    real_open, real_lstat = Path.open, os.lstat

    def opened(path, *args, **kwargs):
        if path == source and args and args[0] == "rb":
            state["read"] = True
        return real_open(path, *args, **kwargs)

    def lstat(path, *args, **kwargs):
        value = real_lstat(path, *args, **kwargs)
        if os.fspath(path) == str(source) and state["read"] and not state["injected"]:
            real_unlink(pending[0])
            state["injected"] = True
            assert source.stat().st_ctime_ns != value.st_ctime_ns
        return value

    monkeypatch.setattr(Path, "open", opened)
    monkeypatch.setattr(os, "lstat", lstat)
    trace.reset()
    expected = mailbox.messages()
    state["read"] = False
    # Oracle preparation reads source; arm only the indexed call below.
    assert not state["injected"]
    result = invoke(index, api)
    assert result == (expected if api == "messages" else expected["seed"] if api == "get"
                      else mailbox.inbox("a/lane/review"))
    assert state["injected"] and index.last_reconciliation is None
    errors = [item for item in trace.events if item["kind"] == "scan_error"]
    assert [item["type"] for item in errors] == ["_ChangedCheckObservation"]
    assert not any(item["kind"] == "clear" for item in trace.events)
    trace.reset()
    index.get("seed")
    assert trace.memo_validations == 0 and trace.events == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
@pytest.mark.usefixtures("posix_reuse")
def test_r24_fallback_retains_rekeyed_memo(mailbox, monkeypatch, mode, api):
    mailbox.publish(request("second"))
    trace = MemoTrace(monkeypatch, mailbox)
    index = index_module().MailboxIndex(mailbox, mode=mode)
    expected = index.messages()
    source = expected["seed"]["path"]
    real_open = os.open
    injected = []

    def opened(path, *args, **kwargs):
        if os.fspath(path) == source and not injected:
            injected.append(True)
            raise PermissionError("injected descriptor access failure")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", opened)
    trace.reset()
    assert invoke(index, api) == (expected if api == "messages" else expected["seed"] if api == "get"
                                  else mailbox.inbox("a/lane/review"))
    assert injected and index.last_reconciliation is not None
    assert not any(item["kind"] == "clear" for item in trace.events)
    trace.reset()
    assert index.get("seed") == expected["seed"]
    assert trace.memo_validations == 0 and trace.events == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
@pytest.mark.parametrize("change", ["cold", "publish", "edit", "dependency"])
def test_r24_each_fresh_record_validated_once(mailbox, monkeypatch, tmp_path, mode, api, change):
    if change != "cold":
        require_posix_reuse()
    packet = tmp_path / "fresh-packet.md"
    packet.write_bytes(b"Packet A.\n")
    mailbox.publish(request("second", brief={"path": str(packet), "sha256": hashlib.sha256(
        packet.read_bytes()).hexdigest()}))
    mailbox.publish(request("third"))
    trace = MemoTrace(monkeypatch, mailbox)
    index = index_module().MailboxIndex(mailbox, mode=mode)
    if change != "cold":
        records = index.messages()
        if change == "publish":
            mailbox.publish(request("new-record"))
        elif change == "edit":
            rewrite(Path(records["seed"]["path"]), {**records["seed"]["message"], "body": "modified body"})
        else:
            packet.write_bytes(b"Packet B.\n")
    trace.reset()
    expected = mailbox.messages()
    assert invoke(index, api) == (expected if api == "messages" else expected["seed"] if api == "get"
                                  else mailbox.inbox("a/lane/review"))
    assert trace.memo_validations == (3 if change == "cold" else 1)


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
@pytest.mark.usefixtures("posix_reuse")
def test_r24_fallback_evicts_observed_byte_contradictions(mailbox, monkeypatch, mode, api):
    mailbox.publish(request("second"))
    trace = MemoTrace(monkeypatch, mailbox)
    index = index_module().MailboxIndex(mailbox, mode=mode)
    seed = index.messages()["seed"]
    source = Path(seed["path"])
    preserve_source_stat(monkeypatch, source.stat())
    rewrite(source, {**seed["message"], "body": "modified body"})
    invoke(index, api)
    trace.reset()
    assert index.get("seed") == mailbox.messages()["seed"]
    assert index.last_reconciliation is None
    assert trace.memo_validations == 1
    assert not any(item["kind"] == "clear" for item in trace.events)
    trace.reset()
    index.get("seed")
    assert trace.memo_validations == 0 and trace.events == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("malformed", ["type", "json"])
@pytest.mark.parametrize("ceiling", ["normal", "entries", "bytes"])
def test_r24_failed_reconciliation_cannot_reuse_contradicted_header(mailbox, monkeypatch, mode, malformed, ceiling):
    mailbox.publish(request("second"))
    if ceiling != "normal":
        for number in range(8):
            mailbox.publish(request("overflow-%d" % number))
        module = index_module()
        if ceiling == "entries":
            monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", 1)
        else:
            monkeypatch.setattr(module, "MAX_EVIDENCE_BYTES", module.EVIDENCE_SUMMARY_BYTES)
    index = index_module().MailboxIndex(mailbox, mode=mode)
    records = index.messages()
    identifier = "seed" if ceiling == "normal" else "overflow-7"
    seed = records[identifier]
    if ceiling != "normal":
        stats = index.evidence_stats()
        assert stats["summary_paths"] == stats["max_summary_paths"] == 8
        assert len(records) > stats["entries"] + stats["summary_paths"]
    source = Path(seed["path"])
    preserve_source_stat(monkeypatch, source.stat())
    if malformed == "type":
        rewrite(source, {**seed["message"], "type": "evil"})
    else:
        source.write_bytes(b"---\n{\n---\n\nbody")
    assert caught(lambda: index.get(identifier)) == caught(mailbox.messages)
    assert caught(lambda: index.get("second")) == caught(mailbox.messages)
    assert index.last_divergence == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("warm", [False, True])
@pytest.mark.parametrize("defect", ["long_path", "relative_path"])
def test_critical_validate_before_dependency_expansion(mailbox, monkeypatch, record_property, mode, warm, defect):
    index = index_module().MailboxIndex(mailbox, mode=mode)
    seed = mailbox.messages()["seed"]
    if warm:
        index.messages()
    source = Path(seed["path"])
    reference = "/" + "a/" * 3000 + "x.md" if defect == "long_path" else "../../../outside/secret.md"
    rewrite(source, {**seed["message"], "brief": {"path": reference, "sha256": "a" * 64}})
    assert source.stat().st_size < hm.MAX_BYTES
    expected = caught(mailbox.messages)
    if not tracemalloc.is_tracing():
        # Before the lstat spy, so the scratch refusal cannot record a measured probe.
        _warm_mailbox_reader(mailbox, mode)
    probes = []
    real_lstat, real_path_lstat = os.lstat, Path.lstat

    def observed(call, path, *args, **kwargs):
        if not isinstance(path, int) and not os.path.isabs(os.fspath(path)):
            probes.append(os.fspath(path))
            raise FileNotFoundError("blocked relative probe")
        return call(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lambda path, *a, **kw: observed(real_lstat, path, *a, **kw))
    monkeypatch.setattr(Path, "lstat", lambda path, *a, **kw: observed(real_path_lstat, path, *a, **kw))
    tracing = tracemalloc.is_tracing()
    if not tracing:
        tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        before = tracemalloc.get_traced_memory()[0]
        actual = caught(index.messages)
        peak = tracemalloc.get_traced_memory()[1] - before
    finally:
        if not tracing:
            tracemalloc.stop()
    record_property("dependency_peak_bytes", peak)
    assert actual == expected
    assert probes == []
    assert peak < 8 * 1024 * 1024


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("blocked", ["selected", "unreturned"])
@pytest.mark.parametrize("later_error", ["brief_missing", "brief_hash", "cursor", "limit"])
def test_r24_inbox_first_error_matches_pinned_read_order(mailbox, tmp_path, monkeypatch, mode, blocked, later_error):
    packet = tmp_path / "ordering-packet.md"
    packet.write_bytes(b"Packet A.\n")
    dispatch = mailbox.publish(request("dispatch", type="dispatch", brief={
        "path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}))
    other = mailbox.publish(request("unreturned", recipient="a/root"))
    if later_error == "brief_missing":
        packet.unlink()
    elif later_error == "brief_hash":
        packet.write_bytes(b"Packet B.\n")
    index = index_module().MailboxIndex(mailbox, mode=mode)
    index.messages()  # Stored PIN validation permits the missing/mismatched brief.
    source = Path((dispatch if blocked == "selected" else other)["path"])

    def denied(path):
        if path == source:
            raise PermissionError("injected message read denial: " + str(source))

    intercept_source_opens(monkeypatch, denied)
    kwargs = {"include_briefs": True}
    if later_error == "cursor":
        kwargs["after"] = "absent"
    elif later_error == "limit":
        kwargs["limit"] = 0  # PIN rejects this before reading any messages.
    expected = caught(lambda: mailbox.inbox("a/lane/review", **kwargs))
    assert expected[0] is (ValueError if later_error == "limit" else PermissionError)
    assert caught(lambda: index.inbox("a/lane/review", **kwargs)) == expected
    assert index.last_divergence == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
def test_r24_canonical_fallback_aba_is_not_a_byte_witness(mailbox, monkeypatch, mode, api):
    index = index_module().MailboxIndex(mailbox, mode=mode)
    seed = index.messages()["seed"]
    source = Path(seed["path"])
    original = source.read_bytes()
    equivalent = b"---\n " + original[4:]
    other = mailbox.publish(request("other-folder", sender="a/lane/review", recipient="a/orchestrator"))
    confirmation = change_confirmation_inode(monkeypatch, Path(other["path"]))
    state = {"active": True, "reads": 0}

    class Stream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self.stream.__enter__()

        def __exit__(self, *args):
            result = self.stream.__exit__(*args)
            source.write_bytes(original)
            return result

    class ABAPath(type(hm.Path())):
        def open(self, *args, **kwargs):
            if (os.fspath(self) == str(source) and args and args[0] == "rb" and state["active"]
                    and confirmation["injections"] == 2):
                state["reads"] += 1
                source.write_bytes(equivalent)
                return Stream(super().open(*args, **kwargs))
            return super().open(*args, **kwargs)

    monkeypatch.setattr(hm, "Path", ABAPath)
    result = invoke(index, api)
    state["active"] = False
    assert state["reads"] >= 1 and source.read_bytes() == original
    assert result == (mailbox.messages() if api == "messages" else seed if api == "get"
                      else mailbox.inbox("a/lane/review"))
    first = index.verify()
    assert any(item["kind"] == "verification_unavailable" for item in first)
    facts = [item for item in first if item["kind"] == "content_changed"]
    if not index_module()._checked_reads_supported():
        # The fallback now observes B's equivalent encoding, then verify sees A
        # again. Keep that A->B->A observation through the unavailable report.
        sha = hashlib.sha256(original).hexdigest()
        assert facts == [{"kind": "content_changed", "path": str(source),
                          "old_sha256": sha, "new_sha256": sha}]
    else:
        assert facts == []
    assert index.verify() == facts
    assert index.verify() == []


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("clear", [False, True])
def test_r24_unsampled_coverage_survives_clear_and_failed_fallback(mailbox, monkeypatch, mode, clear):
    module = index_module()
    monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", 1)
    monkeypatch.setattr(module, "MAX_EVIDENCE_SAMPLE_PATHS", 1)
    for number in range(1, 4):
        mailbox.publish(request("m%d" % number))
    index = module.MailboxIndex(mailbox, mode=mode)
    records = index.messages()
    assert any(item["kind"] == "verification_unavailable" for item in index.verify())
    if clear:
        index._clear()  # Explicitly test disposal; normal fallback now retains keyed candidates.
    monkeypatch.setattr(hm, "MAX_RECORDS", 4)
    extra = Path(records["seed"]["path"]).parent / "zz-overflow.md"
    rewrite(extra, {**records["seed"]["message"], "message_id": "overflow"})
    assert caught(lambda: index.get("absent")) == caught(mailbox.messages)
    before = dict(index._evidence.counts)
    extra.unlink()
    source = Path(records["m3"]["path"])
    metadata = source.stat()
    rewrite(source, {**records["m3"]["message"], "body": "modified body"})
    os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    assert index.get("absent") is None
    overflow = next(item for item in index.content_changed if item["kind"] == "content_change_overflow")
    assert overflow["omitted_changes"] > before["omitted_changes"]
    if clear:
        assert overflow["unbaselined_reads"] > before["unbaselined_reads"]
    else:
        assert overflow["unbaselined_reads"] == 0


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("mutation", ["delete", "remove_brief"])
def test_mb7_obsolete_brief_permission_recovers_incremental_reads(mailbox, monkeypatch, tmp_path,
                                                                 mode, fallback, mutation):
    folder = tmp_path / "separate-briefs"
    folder.mkdir()
    packet = folder / "packet.md"
    packet.write_bytes(b"Obsolete packet.\n")
    mailbox.publish(request("obsolete", brief={"path": str(packet), "sha256": hashlib.sha256(
        packet.read_bytes()).hexdigest()}))
    mailbox.publish(request("unreturned"))
    trace = MemoTrace(monkeypatch, mailbox)
    index = index_module().MailboxIndex(mailbox, mode=mode)
    records = index.messages()
    obsolete = Path(records["obsolete"]["path"])
    if mutation == "delete":
        obsolete.unlink()
    else:
        message = dict(records["obsolete"]["message"])
        del message["brief"]
        rewrite(obsolete, message)
    permission = folder.stat().st_mode & 0o777
    try:
        if os.name == "posix":
            folder.chmod(0)
            if os.access(folder, os.X_OK):
                pytest.skip("search permission is not enforced for this uid")
        else:
            module = index_module()
            real_os = module.os

            def lstat(path, *args, **kwargs):
                if os.fspath(path) in (str(folder), str(packet)):
                    raise PermissionError(errno.EACCES, "injected obsolete dependency denial")
                return real_os.lstat(path, *args, **kwargs)

            monkeypatch.setattr(module, "os", PlatformOS(real_os.name, base=real_os, lstat=lstat))
        expected = mailbox.messages()
        real_scandir = os.scandir
        denied = []

        def scandir(path):
            if fallback and not denied:
                denied.append(True)
                raise PermissionError(errno.EACCES, "injected transient routing denial", os.fspath(path))
            return real_scandir(path)

        # Deny the first indexed listing; canonical reconciliation stays live.
        with monkeypatch.context() as failure:
            failure.setattr(os, "scandir", scandir)
            assert index.get("seed") == expected["seed"]
        assert bool(index.last_reconciliation) == fallback
        assert bool(denied) == fallback
        counts = ReadCounts(monkeypatch, trace)
        parses = spy_parses(monkeypatch)
        sources = {record["path"] for record in expected.values()}
        for position, identifier in enumerate(("seed", "absent", "seed")):
            trace.reset()
            counts.reset()
            parses.clear()
            assert index.get(identifier) == expected.get(identifier)
            assert index.last_reconciliation is None
            # A fallback before listing cannot establish the edited record's
            # new byte key. Rebuild that header once, then require warm reuse.
            rebuild = fallback and mutation == "remove_brief" and position == 0
            checked = index_module()._checked_reads_supported()
            assert trace.memo_validations == (int(rebuild) if checked else len(expected))
            assert trace.events == []
            assert parses == ([str(obsolete)] if rebuild else [])
            assert str(packet) not in counts.lstats
            if mode == "indexed" and checked:
                assert [path for path in counts.opens if path in sources] == (
                    ([str(obsolete)] if rebuild else [])
                    + ([expected[identifier]["path"]] if identifier in expected else []))
            elif mode == "indexed":
                assert sorted(path for path in counts.opens if path in sources) == sorted(sources)
    finally:
        if os.name == "posix":
            folder.chmod(permission)


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_mb7_live_brief_permission_error_still_matches_pin(mailbox, tmp_path, mode):
    folder = tmp_path / "live-briefs"
    folder.mkdir()
    packet = folder / "packet.md"
    packet.write_bytes(b"Required packet.\n")
    mailbox.publish(request("required", brief={"path": str(packet), "sha256": hashlib.sha256(
        packet.read_bytes()).hexdigest()}))
    index = index_module().MailboxIndex(mailbox, mode=mode)
    index.messages()
    permission = folder.stat().st_mode & 0o777
    try:
        folder.chmod(0)
        if os.access(folder, os.X_OK):
            pytest.skip("search permission is not enforced for this uid")
        expected = caught(mailbox.messages)
        assert expected[0] is PermissionError
        for _ in range(2):
            assert caught(lambda: index.get("seed")) == expected
    finally:
        folder.chmod(permission)


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_mb7_obsolete_probe_does_not_retain_exception_traceback(mailbox, monkeypatch, tmp_path, mode):
    packet = tmp_path / "obsolete-packet.md"
    packet.write_bytes(b"Obsolete packet.\n")
    mailbox.publish(request("obsolete", brief={"path": str(packet), "sha256": hashlib.sha256(
        packet.read_bytes()).hexdigest()}))
    index = index_module().MailboxIndex(mailbox, mode=mode)
    records = index.messages()
    Path(records["obsolete"]["path"]).unlink()
    real_lstat, real_scandir = os.lstat, os.scandir
    errors, retained_at_listing = [], []

    class ProbeError(PermissionError):
        pass

    def lstat(path, *args, **kwargs):
        if os.fspath(path) == str(packet):
            error = ProbeError(errno.EACCES, "injected obsolete dependency denial", str(packet))
            errors.append(weakref.ref(error))
            raise error
        return real_lstat(path, *args, **kwargs)

    def scandir(path):
        if not retained_at_listing:
            gc.collect()
            retained_at_listing.append(any(reference() is not None for reference in errors))
        return real_scandir(path)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "scandir", scandir)
    assert index.get("seed") == records["seed"]
    assert retained_at_listing == [False]
    assert index.last_reconciliation is None


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_mb7_reconciliation_preserves_changed_live_sha_baseline(mailbox, monkeypatch, mode):
    module = index_module()
    Path(mailbox.messages()["seed"]["path"]).unlink()
    for identifier in ("a", "b", "r"):
        mailbox.publish(request(identifier))
    monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", 1)
    monkeypatch.setattr(module, "MAX_EVIDENCE_SAMPLE_PATHS", 1)
    index = module.MailboxIndex(mailbox, mode=mode)
    records = index.messages()
    assert list(records) == ["a", "b", "r"]
    assert index.evidence_stats()["entries"] == index.evidence_stats()["summary_paths"] == 1
    source = Path(records["r"]["path"])
    old_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    for identifier in ("a", "b"):
        Path(records[identifier]["path"]).unlink()
    rewrite(source, {**records["r"]["message"], "body": "modified body"})
    new_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    expected = mailbox.messages()
    real_scandir = os.scandir
    denied = []

    def scandir(path):
        if not denied:
            denied.append(True)
            raise PermissionError(errno.EACCES, "injected routing denial before listing", os.fspath(path))
        return real_scandir(path)

    with monkeypatch.context() as failure:
        failure.setattr(os, "scandir", scandir)
        assert index.messages() == expected
    assert denied == [True] and index.last_reconciliation["kind"] == "pinned_fallback"
    changes = index.verify()
    assert {"kind": "content_changed", "path": str(source), "old_sha256": old_sha,
            "new_sha256": new_sha} in changes
    assert all(item["unbaselined_reads"] == 0 for item in changes if item["kind"] == "content_change_overflow")


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("denied", [False, True])
@pytest.mark.parametrize("platform", ["nt", "unproven"])
def test_mb7_hashes_current_record_before_observing_dependencies(mailbox, monkeypatch, tmp_path,
                                                                mode, denied, platform):
    module = index_module()
    monkeypatch.setattr(module, "MAX_EVIDENCE_ENTRIES", 1)
    monkeypatch.setattr(module, "MAX_EVIDENCE_SAMPLE_PATHS", 1)
    seed = mailbox.messages()["seed"]
    source = Path(seed["path"])
    packet = tmp_path / "former-packet.md"
    packet.write_bytes(b"Former packet.\n")
    rewrite(source, {**seed["message"], "brief": {"path": str(packet), "sha256": hashlib.sha256(
        packet.read_bytes()).hexdigest()}})
    index = module.MailboxIndex(mailbox, mode=mode)
    record = index.messages()["seed"]
    original = source.read_bytes()
    old_sha = hashlib.sha256(original).hexdigest()
    metadata = source.stat()
    preserve_source_stat(monkeypatch, metadata)
    monkeypatch.setattr(module, "os", PlatformOS(platform, base=module.os))
    message = {**record["message"], "body": "modified body"}
    del message["brief"]
    rewrite(source, message)
    padding = len(original) - len(source.read_bytes())
    assert padding > 0
    message["body"] += " " * padding
    rewrite(source, message)
    current = source.read_bytes()
    assert len(current) == len(original)
    # This is the pathname key that _scan must find reusable. Unsupported
    # hosts deliberately do not assume matching pathname/fstat identities.
    assert module.os.lstat(source) is metadata
    new_sha = hashlib.sha256(current).hexdigest()
    expected = mailbox.messages()["seed"]
    real_os = module.os
    probes = []

    def lstat(path, *args, **kwargs):
        if os.fspath(path) == str(packet):
            probes.append(os.fspath(path))
            if denied:
                raise PermissionError(errno.EACCES, "injected former dependency denial", str(packet))
        return real_os.lstat(path, *args, **kwargs)

    monkeypatch.setattr(module, "os", PlatformOS(platform, base=real_os, lstat=lstat))
    assert index.get("seed") == expected
    assert probes == []
    assert index.last_reconciliation is None and index.last_divergence == []
    assert {"kind": "content_changed", "path": str(source), "old_sha256": old_sha,
            "new_sha256": new_sha} in index.content_changed
    assert index.get("seed") == expected
    assert probes == [] and index.last_reconciliation is None


@pytest.fixture
def reply_mailbox(mailbox, monkeypatch):
    mailbox.publish(request("reply", sender="a/lane/review", recipient="a/orchestrator", in_reply_to="seed"))
    records = mailbox.messages()
    Path(records["seed"]["path"]).replace(mailbox.root / "a/lane/1.md")
    Path(records["reply"]["path"]).replace(mailbox.root / "a/orchestrator/2.md")
    return mailbox, records["seed"]["message"], records["reply"]["message"]


@pytest.fixture(params=["native", "posix_emulated"])
def reply_policy(request, reply_mailbox, monkeypatch):
    """Run native reads too; emulate POSIX policy only against owned fixtures."""
    if request.param == "native":
        return
    module = index_module()
    real_os = module.os
    descriptors = {}

    def opened(path, *args, **kwargs):
        descriptor = real_os.open(path, *args, **kwargs)
        descriptors[descriptor] = path
        return descriptor

    # Windows fstat lacks pathname identity on some Python versions. The test
    # adapter supplies stable identities from these test-owned, unraced paths.
    monkeypatch.setattr(module, "os", PlatformOS("posix", base=real_os, open=opened,
        fstat=lambda descriptor: real_os.lstat(descriptors[descriptor]),
        getuid=lambda: 1000, geteuid=lambda: 1000, getgid=lambda: 1000,
        getegid=lambda: 1000, getgroups=lambda: [1000]))
    monkeypatch.setattr(module, "_checked_reads_supported", lambda: True)


def rewrite_same_stat(path, message, monkeypatch):
    metadata = path.stat()
    # utime cannot restore POSIX ctime; keep that boundary explicit, as in the
    # existing mmap/privileged same-stat tests. File contents/IO remain real.
    preserve_source_stat(monkeypatch, metadata)
    rewrite(path, message)
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    current = path.stat()
    assert (current.st_dev, current.st_ino, current.st_size, current.st_atime_ns, current.st_mtime_ns) == (
        metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_atime_ns, metadata.st_mtime_ns)


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_mb7_relocated_reply_target_invalidates_retained_dependencies(reply_mailbox, reply_policy, monkeypatch, mode):
    mailbox, seed, reply = reply_mailbox
    old_target, target, reply_path = (mailbox.root / "a/lane/1.md", mailbox.root / "a/lane/3.md",
                                    mailbox.root / "a/orchestrator/2.md")
    index = index_module().MailboxIndex(mailbox, mode=mode)
    assert index.messages() == mailbox.messages()
    other = {**seed, "message_id": "other", "body": seed["body"][:-1]}
    rewrite_same_stat(old_target, other, monkeypatch)
    rewrite(target, seed)
    assert index.get("other") == mailbox.messages()["other"]
    if index_module()._checked_reads_supported():
        assert index.last_reconciliation["kind"] == "pinned_fallback"
    else:
        assert index.last_reconciliation is None
    assert index.get("other") == mailbox.messages()["other"]
    assert index.last_reconciliation is None
    rewrite(target, {**seed, "body": "modified body"})
    rewrite_same_stat(reply_path, {**reply, "type": "evil"}, monkeypatch)
    expected = caught(mailbox.messages)
    assert expected[0] is ValueError and "unsupported message type" in expected[1]
    checked_reads = r23_source_reads(monkeypatch, reply_path,
                                    descriptor_only=index_module()._checked_reads_supported())
    assert caught(lambda: index.get("other")) == expected
    assert checked_reads


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
def test_mb7_deleted_reply_target_is_not_probed_after_reconciliation(reply_mailbox, reply_policy, monkeypatch, mode):
    mailbox, seed, _ = reply_mailbox
    old_target, target = mailbox.root / "a/lane/1.md", mailbox.root / "a/lane/3.md"
    index = index_module().MailboxIndex(mailbox, mode=mode)
    assert index.messages() == mailbox.messages()
    old_target.unlink()
    rewrite(target, seed)
    real_scandir = os.scandir
    denied = []

    def scandir(path):
        if not denied:
            denied.append(True)
            raise PermissionError(errno.EACCES, "transient indexed listing denial", os.fspath(path))
        return real_scandir(path)

    with monkeypatch.context() as failure:
        failure.setattr(os, "scandir", scandir)
        assert index.get("seed") == mailbox.messages()["seed"]
    assert denied == [True] and index.last_reconciliation["kind"] == "pinned_fallback"
    real_lstat, real_path_lstat = os.lstat, Path.lstat
    probes = []

    def lstat(call, path, *args, **kwargs):
        probes.append(os.fspath(path))
        return call(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lambda path, *a, **kw: lstat(real_lstat, path, *a, **kw))
    monkeypatch.setattr(Path, "lstat", lambda path, *a, **kw: lstat(real_path_lstat, path, *a, **kw))
    assert index.get("seed") == mailbox.messages()["seed"]
    assert index.last_reconciliation is None
    assert str(old_target) not in probes


@pytest.mark.parametrize("mode", ["indexed", "shadow"])
@pytest.mark.parametrize("target_change", ["rewrite", "replace"])
def test_mb7_normal_rescan_rebinds_relocated_reply_dependencies(reply_mailbox, reply_policy, monkeypatch, mode, target_change):
    mailbox, seed, reply = reply_mailbox
    old_target, target, reply_path = (mailbox.root / "a/lane/1.md", mailbox.root / "a/lane/3.md",
                                    mailbox.root / "a/orchestrator/2.md")
    packet = mailbox.root.parent / "packet.md"
    packet.write_bytes(b"Packet A.\n")
    seed = {**seed, "brief": {"path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}}
    rewrite(old_target, seed)
    index = index_module().MailboxIndex(mailbox, mode=mode)
    assert index.messages() == mailbox.messages()
    packet.write_bytes(b"Packet B.\n")
    other = {**seed, "message_id": "other", "body": seed["body"][:-1],
             "brief": {**seed["brief"], "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}}
    rewrite_same_stat(old_target, other, monkeypatch)
    rewrite(target, seed)
    assert index.get("other") == mailbox.messages()["other"]
    assert index.last_reconciliation is None and index.last_divergence == []
    if target_change == "replace":
        previous = target.stat()
        replacement = mailbox.root.parent / "replacement.md"
        rewrite(replacement, {**seed, "body": "modified body"})
        os.utime(replacement, ns=(previous.st_atime_ns, previous.st_mtime_ns))
        replacement.replace(target)
        assert target.stat().st_ino != previous.st_ino
    else:
        rewrite(target, {**seed, "body": "modified body"})
    rewrite_same_stat(reply_path, {**reply, "type": "evil"}, monkeypatch)
    expected = caught(mailbox.messages)
    assert expected[0] is ValueError and "unsupported message type" in expected[1]
    checked_reads = r23_source_reads(monkeypatch, reply_path,
                                    descriptor_only=index_module()._checked_reads_supported())
    assert caught(lambda: index.get("other")) == expected
    assert checked_reads
