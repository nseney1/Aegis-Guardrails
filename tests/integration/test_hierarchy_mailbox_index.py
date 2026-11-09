"""In-process mailbox memo: fail-closed parity, incremental reads and no writes."""
import hashlib
import importlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import hierarchy_mailbox as hm


def index_module():
    return importlib.import_module("tools.hierarchy_mailbox_index")


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


DEFECTS = ["missing_header", "bad_json", "duplicate_key", "nonfinite", "utf8", "unknown_field",
           "invalid_type", "wrong_folder", "duplicate_id", "missing_reply", "reverse_reply",
           "non_md", "symlink", "pending_symlink", "directory_entry", "oversized_message",
           "missing_folder", "folder_symlink"]


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
    real_open = Path.open
    injected = []

    def inaccessible(target, *args, **kwargs):
        if target == path:
            injected.append(True)
            raise PermissionError("injected unreadable message: " + str(target))
        return real_open(target, *args, **kwargs)

    monkeypatch.setattr(Path, "open", inaccessible)
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


def spy_reads(monkeypatch):
    module = index_module()
    real_read = module.MailboxIndex._read_message
    calls = []

    def read(self, path):
        calls.append(str(path))
        return real_read(self, path)

    monkeypatch.setattr(module.MailboxIndex, "_read_message", read)
    return calls


@pytest.mark.parametrize("api", ["messages", "get", "inbox"])
def test_one_publish_parses_only_new_record(mailbox, monkeypatch, api):
    for number in range(16):
        mailbox.publish(request("note-%02d" % number))
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    index.messages()
    calls = spy_reads(monkeypatch)
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
    calls = spy_reads(monkeypatch)
    Path(seed["path"]).unlink()
    result = invoke(index, api)
    assert calls == []
    assert result == ({} if api == "messages" else None if api == "get"
                      else mailbox.inbox("a/lane/review"))
    assert index_module().compare(mailbox, index) == []


def test_inode_reuse_with_different_ctime_reparses(mailbox, tmp_path, monkeypatch):
    index = index_module().MailboxIndex(mailbox, mode="indexed")
    seed = index.messages()["seed"]
    path = Path(seed["path"])
    old = path.stat()
    replacement = tmp_path / "replacement"
    rewrite(replacement, {**seed["message"], "body": "modified body"})
    replacement.replace(path)
    os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns))
    current = path.stat()
    assert current.st_ino != old.st_ino and current.st_ctime_ns != old.st_ctime_ns
    assert current.st_size == old.st_size
    real_lstat, real_fstat = Path.lstat, os.fstat
    injected = []

    def reused(value):
        if (value.st_dev, value.st_ino) != (current.st_dev, current.st_ino):
            return value
        injected.append(True)
        return SimpleNamespace(st_mode=value.st_mode, st_dev=value.st_dev, st_ino=old.st_ino,
                               st_size=value.st_size, st_mtime_ns=value.st_mtime_ns,
                               st_ctime_ns=value.st_ctime_ns)

    def lstat(target, *args, **kwargs):
        return reused(real_lstat(target, *args, **kwargs))

    def fstat(descriptor):
        return reused(real_fstat(descriptor))

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(os, "fstat", fstat)
    calls = spy_reads(monkeypatch)
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
    calls = spy_reads(monkeypatch)
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
    before = snapshot(tmp_path)
    real_open = Path.open
    attempted = []

    def read_only(path, mode="r", *args, **kwargs):
        if any(flag in mode for flag in "wax+"):
            attempted.append(str(path))
            raise AssertionError("index attempted a write")
        return real_open(path, mode, *args, **kwargs)

    def forbidden(*args, **kwargs):
        attempted.append(str(args))
        raise AssertionError("index attempted a filesystem mutation")

    monkeypatch.setattr(Path, "open", read_only)
    for name in ("mkdir", "unlink", "rename", "replace", "symlink_to", "hardlink_to"):
        if hasattr(Path, name):
            monkeypatch.setattr(Path, name, forbidden)
    for name in ("mkdir", "unlink", "rename", "replace", "link", "symlink"):
        monkeypatch.setattr(os, name, forbidden)
    assert index.messages() == mailbox.messages()
    assert index.get("seed") == mailbox.messages()["seed"]
    assert index.inbox("a/lane/review") == mailbox.inbox("a/lane/review")
    assert index.verify() == []
    assert index_module().compare(mailbox, index) == []
    assert attempted == [] and snapshot(tmp_path) == before


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
    real_check = Path.is_symlink
    injected = []

    def check(path):
        if path == pending and not injected:
            path.unlink()
            injected.append(True)
        return real_check(path)

    monkeypatch.setattr(Path, "is_symlink", check)
    assert index.messages() == expected
    assert injected and index_module().compare(mailbox, index) == []


def test_unknown_mode_refused(mailbox):
    error_type, message = caught(lambda: index_module().MailboxIndex(mailbox, mode="bad"))
    assert issubclass(error_type, ValueError) and "indexed" in message and "shadow" in message


def test_oracle_detects_order_only_difference(mailbox, monkeypatch):
    module = index_module()
    index = module.MailboxIndex(mailbox, mode="indexed")
    expected = mailbox.messages()
    changed = {key: dict(reversed(list(record.items()))) for key, record in expected.items()}
    assert hm.encoded(changed) == hm.encoded(expected)
    monkeypatch.setattr(index, "_indexed_messages", lambda: changed)
    assert module.compare(mailbox, index) == [{"kind": "mailbox_index_key_order"}]
