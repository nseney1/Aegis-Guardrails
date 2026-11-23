"""Product records, typed refusals and legacy wire parity through public APIs."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
import errno
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
from threading import Barrier, Event
from types import SimpleNamespace
import tracemalloc

import pytest

from conftest import symlink_or_skip
from tests.unit.core.test_team_mailbox import (
    bind, handoff_ack, mailbox, make_store, owner_plane, replacement_request, snapshot,
)
from aegis_core.team_mailbox_primitives import BusyError, MailboxRefusal, OWNER_EVIDENCE_LOCK
from aegis_core import message_codec as codec
from aegis_core import message_codec_store as codec_store
from tools import hierarchy_mailbox as legacy_mailbox
from aegis_core import team_mailbox as mailbox_module
from aegis_core import team_mailbox_records as records_module
from aegis_core import team_mailbox_store as store_module
from tests.integration.test_hierarchy_mailbox_records import (
    records as legacy_records, records_guidance as legacy_guidance,
)


def request(identifier="record", **changes):
    return dict({"message_id": identifier, "to": "alpha/orchestrator", "type": "info",
                 "kind": "text", "content": json.dumps({"fields": {}, "body": "evidence", "refs": {}})},
                **changes)


def sender(endpoint="alpha/front-door"):
    return {"from": endpoint, "host": "test-host", "session": endpoint, "binding_generation": 1}


@contextmanager
def service(tmp_path, **options):
    root = make_store(tmp_path)
    with mailbox(root) as box:
        bind(box, "alpha/front-door")
        bind(box, "alpha/orchestrator")
        yield root, box, records_module.Records(box, sender(), **options)


def test_publish_retry_read_digest_and_injected_clock(tmp_path):
    with service(tmp_path) as (root, box, records):
        first = records.call("mailbox_publish_record", request())
        before = snapshot(root.parent)
        assert records.call("mailbox_publish_record", request()) == first
        assert snapshot(root.parent) == before
        reader = records_module.Records(box, sender("alpha/orchestrator"))
        view = json.loads(reader.call("mailbox_read_record", {"message_id": "record"}))
        assert view["from"] == "alpha/front-door"
        rid = first["id"]
        raw = json.loads((root.parent / "mailbox-records" / rid[:2] / (rid + ".json")).read_bytes())
        assert raw["meta"]["created_at"] == "2026-11-16T12:00:00.000000Z"
        digest = json.loads(reader.call("mailbox_digest", {}))
        assert digest["messages"][0]["record"] == view
        assert json.loads(reader.call("mailbox_digest", {"after_message_id": "record"}))["messages"] == []


@pytest.mark.parametrize("failure,existing", [
    ("stub-link", False), ("stub-link", True), ("payload-fdopen", False), ("payload-link-after", False),
])
def test_refused_publication_rolls_back_only_owned_payload(tmp_path, monkeypatch, failure, existing):
    with service(tmp_path) as (root, _box, records):
        directory = root.parent / "mailbox-records"
        first = records.call(PUBLISH_RECORD, request("first")) if existing else None
        if first is not None:
            rid = first["id"]
            payload = directory / rid[:2] / (rid + ".json")
            original = payload.stat()
        before = snapshot(root.parent)

        def stub_link(source, target, *args, **kwargs):
            if str(target).endswith(".md"):
                raise OSError("injected stub link failure")
            return os.link(source, target, *args, **kwargs)

        def payload_fdopen(fd, mode, *args, **kwargs):
            if mode == "wb":
                raise OSError("injected payload fdopen failure")
            return os.fdopen(fd, mode, *args, **kwargs)

        def payload_link(source, target, *args, **kwargs):
            os.link(source, target, *args, **kwargs)
            raise OSError("injected failure after payload link")

        if failure == "stub-link":
            monkeypatch.setattr(records_module, "os", SimpleNamespace(**{**vars(os), "link": stub_link}))
        elif failure == "payload-fdopen":
            monkeypatch.setattr(codec_store, "os", SimpleNamespace(**{**vars(os), "fdopen": payload_fdopen}))
        else:
            monkeypatch.setattr(codec_store, "os", SimpleNamespace(**{**vars(os), "link": payload_link}))
        try:
            with pytest.raises(records_module.RecordRefusal) as caught:
                records.call(PUBLISH_RECORD, request("retry"))
            assert caught.value.reason == "E_AUTH"
            assert "injected" not in json.dumps(caught.value.record_error)
            assert snapshot(root.parent) == before
            assert directory.exists() is existing
        finally:
            if failure == "stub-link":
                monkeypatch.setattr(records_module, "os", os)
            else:
                monkeypatch.setattr(codec_store, "os", os)
        sent = records.call(PUBLISH_RECORD, request("retry"))
        assert records.call(PUBLISH_RECORD, request("retry")) == sent
        if first is not None:
            assert sent["id"] == first["id"]
            assert os.path.samestat(payload.stat(), original)


@pytest.mark.parametrize("publisher", ["core", "legacy"])
def test_rf44_staging_cleanup_failure_retains_both_reservations(tmp_path, monkeypatch, publisher):
    with service(tmp_path) as (root, _box, records):
        directory = root.parent / "mailbox-records"
        inner = directory / ".publish.lock"
        outer = root.parent / ".records-store.lock"

        def unlink(name, *args, **kwargs):
            if name.startswith(".msg-"):
                raise OSError("injected staging cleanup failure")
            return os.unlink(name, *args, **kwargs)

        monkeypatch.setattr(codec_store, "os", SimpleNamespace(**{**vars(os), "unlink": unlink}))
        if publisher == "core":
            with pytest.raises(records_module.RecordRefusal) as caught:
                records.call(PUBLISH_RECORD, request())
            assert caught.value.reason == "E_AUTH"
            assert "injected" not in json.dumps(caught.value.record_error)
        else:
            result = legacy_call(root, sender(), PUBLISH_RECORD, request())
            assert result["error"]["code"] == "E_AUTH"
            assert "injected" not in json.dumps(result)
        assert inner.is_file() and outer.is_file()
        [staging] = list(directory.glob("*/.msg-*"))
        [payload] = list(directory.glob("*/*.json"))
        original = payload.read_bytes()
        assert staging.read_bytes() == original
        monkeypatch.setattr(codec_store, "os", os)
        # Simulate the owner inspecting and clearing the abandoned reservation.
        staging.unlink()
        inner.unlink()
        outer.unlink()
        sent = (records.call(PUBLISH_RECORD, request()) if publisher == "core" else
                legacy_call(root, sender(), PUBLISH_RECORD, request()))
        assert "id" in sent
        retry = (records.call(PUBLISH_RECORD, request()) if publisher == "core" else
                 legacy_call(root, sender(), PUBLISH_RECORD, request()))
        assert retry == sent
        assert payload.read_bytes() == original


@pytest.mark.parametrize("publisher", ["core", "legacy"])
@pytest.mark.parametrize("failure", ["stat", "replacement"])
def test_rf44_first_store_bind_reclaims_only_owned_root(tmp_path, monkeypatch, publisher, failure):
    with service(tmp_path) as (root, _box, records):
        directory = root.parent / "mailbox-records"
        retired = root.parent / "retired-store"
        outer = root.parent / ".records-store.lock"
        before = snapshot(root.parent)
        injected = []

        def stated(name, *args, **kwargs):
            if failure == "stat" and name == directory.name and not injected:
                assert os.path.samestat(os.fstat(kwargs["dir_fd"]), root.parent.stat())
                assert directory.is_dir() and outer.is_file()
                injected.append(name)
                raise OSError(errno.EIO, "injected first store stat failure")
            return os.stat(name, *args, **kwargs)

        def opened(name, *args, **kwargs):
            if failure == "replacement" and name == directory.name and not injected:
                assert outer.is_file()
                directory.rename(retired)
                directory.mkdir(mode=0o700)
                injected.append(name)
            return os.open(name, *args, **kwargs)

        patched_os = SimpleNamespace(**{**vars(os), "stat": stated, "open": opened})
        if publisher == "core":
            monkeypatch.setattr(records_module, "os", patched_os)
            try:
                with pytest.raises(records_module.RecordRefusal) as caught:
                    records.call(PUBLISH_RECORD, request())
                assert caught.value.reason == "E_AUTH"
                assert "injected" not in json.dumps(caught.value.record_error)
            finally:
                monkeypatch.setattr(records_module, "os", os)
        else:
            monkeypatch.setattr(legacy_records, "os", patched_os)
            try:
                assert legacy_call(root, sender(), PUBLISH_RECORD, request()) == codec.CodecError("E_AUTH").as_dict()
            finally:
                monkeypatch.setattr(legacy_records, "os", os)

        assert injected == [directory.name]
        if failure == "stat":
            assert not directory.exists() and not outer.exists()
            assert snapshot(root.parent) == before
        else:
            # A replacement with a different inode is not ours to reclaim or publish into.
            assert not list(directory.iterdir()) and not list(retired.iterdir())
            assert not (root / ".root-id").exists()
            assert not outer.exists()
        if publisher == "core":
            sent = records.call(PUBLISH_RECORD, request())
            assert records.call(PUBLISH_RECORD, request()) == sent
        else:
            sent = legacy_call(root, sender(), PUBLISH_RECORD, request())
            assert legacy_call(root, sender(), PUBLISH_RECORD, request()) == sent
        assert sent["message_id"] == "record"


@pytest.mark.parametrize("publisher", ["core", "legacy"])
@pytest.mark.parametrize("check", ["before-link", "after-link-grants", "after-link-root"])
def test_rf44_grant_context_fault_uses_message_commit_state(tmp_path, monkeypatch, publisher, check):
    clock = WaitClock()
    with service(tmp_path, monotonic=clock.monotonic, sleep=clock.sleep) as (root, box, records):
        directory = root.parent / "mailbox-records"
        fault_target = directory.resolve() if check == "after-link-root" else "grants"
        inner = directory / ".publish.lock"
        outer = root.parent / ".records-store.lock"
        before = snapshot(root.parent)
        armed = Event()
        injected = []

        def synced(fd):
            os.fsync(fd)
            grants = directory / "grants"
            if check == "before-link" and grants.is_dir() and os.path.samestat(os.fstat(fd), grants.stat()):
                armed.set()

        def linked(source, target, *args, **kwargs):
            os.link(source, target, *args, **kwargs)
            if check != "before-link" and target.endswith(".md"):
                armed.set()

        def stated(name, *args, **kwargs):
            if armed.is_set() and name == fault_target and not injected:
                assert inner.is_file() and outer.is_file()
                injected.append(name)
                raise OSError(errno.EIO, "injected grant context check failure")
            return os.stat(name, *args, **kwargs)

        def publish():
            if publisher == "core":
                return records.call(PUBLISH_RECORD, request())
            return legacy_call(root, sender(), PUBLISH_RECORD, request())

        patched_os = SimpleNamespace(**{**vars(os), "fsync": synced, "link": linked})
        if publisher == "core":
            monkeypatch.setattr(records_module, "os", patched_os)
        else:
            monkeypatch.setattr(legacy_records, "os", patched_os)
        monkeypatch.setattr(codec_store, "os", SimpleNamespace(**{**vars(os), "stat": stated}))
        try:
            if check == "before-link" and publisher == "core":
                with pytest.raises(records_module.RecordRefusal) as caught:
                    publish()
                assert caught.value.reason == "E_AUTH"
                assert "injected" not in json.dumps(caught.value.record_error)
            else:
                result = publish()
        finally:
            monkeypatch.setattr(codec_store, "os", os)
            if publisher == "core":
                monkeypatch.setattr(records_module, "os", os)
            else:
                monkeypatch.setattr(legacy_records, "os", os)

        assert len(injected) == 1
        if check == "before-link":
            if publisher == "legacy":
                assert result["error"]["code"] == "E_AUTH"
                assert "injected" not in json.dumps(result)
            assert not directory.exists() and not outer.exists()
            assert snapshot(root.parent) == before
            result = publish()
        else:
            assert "injected" not in json.dumps(result)
            assert result["note"] == (
                "Message published. The owner should inspect staging and both reservations. "
                "Once cleanup is verified, clear an abandoned <store>/.publish.lock first, "
                "then an abandoned <parent>/.records-store.lock. Check history before publishing again."
            )
            assert inner.is_file() and outer.is_file()
            committed = snapshot(root.parent)
            with pytest.raises(BusyError):
                records.call(PUBLISH_RECORD, request("new"))
            assert snapshot(root.parent) == committed

        reader = records_module.Records(box, sender("alpha/orchestrator"))
        assert json.loads(reader.call(READ_RECORD, {"message_id": "record"}))["data"]["body"] == "evidence"
        retried = publish()
        assert retried == {key: result[key] for key in ("id", "message_id")}
        if check != "before-link":
            assert inner.is_file() and outer.is_file()
            inner.unlink()
            outer.unlink()
            assert publish() == retried


@pytest.mark.parametrize("publisher", ["core", "legacy"])
def test_rf44_mailbox_bind_does_not_enumerate_grant_history(tmp_path, monkeypatch, publisher):
    with service(tmp_path) as (root, box, records):
        directory = root.parent / "mailbox-records"
        identifiers = []
        for index in range(4):
            args = request("grant-" + str(index), content=json.dumps({
                "fields": {}, "body": "grant " + str(index), "refs": {},
            }))
            sent = (records.call(PUBLISH_RECORD, args) if publisher == "core" else
                    legacy_call(root, sender(), PUBLISH_RECORD, args))
            identifiers.append(sent["id"])
        expected = directory.stat()
        binds, visited = [], []

        @contextmanager
        def scan(fd):
            with os.scandir(fd) as entries:
                if not os.path.samestat(os.fstat(fd), expected):
                    yield entries
                    return
                binds.append(fd)

                def observe():
                    for entry in entries:
                        visited.append(entry.name)
                        yield entry

                yield observe()

        monkeypatch.setattr(codec_store, "os", SimpleNamespace(**{**vars(os), "scandir": scan}))
        author = sender("alpha/orchestrator")
        arguments = {"ref": identifiers[0]}
        if publisher == "core":
            result = json.loads(records_module.Records(box, author).call(READ_RECORD, arguments))
        else:
            result = json.loads(legacy_call(root, author, READ_RECORD, arguments))
        assert result["data"]["body"] == "grant 0"
        assert binds and "grants" in visited
        assert all(not name.startswith(".grants-") for name in visited)
        assert sorted(path.name for path in (directory / "grants").iterdir()) == sorted(
            ".grants-" + rid for rid in identifiers)


@pytest.mark.parametrize("publisher", ["core", "legacy"])
def test_rf44_missing_descriptor_scandir_refuses_before_store_creation(tmp_path, monkeypatch, publisher):
    with service(tmp_path) as (root, _box, records):
        before = snapshot(root.parent)
        attempted = []

        def mkdir(*args, **kwargs):
            attempted.append(True)
            return os.mkdir(*args, **kwargs)

        monkeypatch.setattr(codec_store, "os", SimpleNamespace(**{**vars(os), "supports_fd": set()}))
        monkeypatch.setattr(legacy_records, "os", SimpleNamespace(**{**vars(os), "mkdir": mkdir}))
        if publisher == "core":
            with pytest.raises(MailboxRefusal) as caught:
                records.call(PUBLISH_RECORD, request())
            assert caught.value.reason == "unsupported_platform"
        else:
            assert legacy_call(root, sender(), PUBLISH_RECORD, request()) == codec.CodecError("E_AUTH").as_dict()
        assert snapshot(root.parent) == before
        assert attempted == []
        assert not (root.parent / "mailbox-records").exists()


@pytest.mark.parametrize("name,arguments,reason", [
    ("unknown\nsecret", {}, "invalid_record"),
    ("mailbox_publish_record", request(content="{"), "E_FORMAT"),
    ("mailbox_publish_record", request(content="x" * 1048577), "E_LIMIT"),
    ("mailbox_read_record", {"ref": "a" * 64}, "E_AUTH"),
    ("mailbox_digest", {"limit": 0}, "E_LIMIT"),
])
def test_refusal_has_reason_action_no_side_effects_and_retry(tmp_path, name, arguments, reason):
    with service(tmp_path) as (root, box, records):
        before = snapshot(root.parent)
        with pytest.raises(MailboxRefusal) as caught:
            records.call(name, arguments)
        assert caught.value.reason == reason
        assert caught.value.next_action
        assert caught.value.code == 1
        assert "secret" not in str(caught.value)
        assert snapshot(root.parent) == before
        assert "id" in records.call("mailbox_publish_record", request())


def test_unsupported_platform_has_typed_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(records_module, "supported", lambda: False)
    with pytest.raises(MailboxRefusal) as caught:
        records_module.Records(SimpleNamespace(), sender()).call("mailbox_digest", {})
    assert caught.value.reason == "unsupported_platform"
    assert list(tmp_path.iterdir()) == []


def test_publish_concurrent_idempotent_retry(tmp_path):
    with service(tmp_path) as (root, box, records):
        def attempt(_):
            try:
                return records.call("mailbox_publish_record", request())
            except BusyError:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, range(2)))
        completed = [result for result in results if result is not None]
        assert completed
        assert all(result == completed[0] for result in completed)
        assert records.call("mailbox_publish_record", request()) == completed[0]
        assert len(box.messages()) == 1


def test_busy_mailbox_is_shared_type_then_retry(tmp_path):
    clock = WaitClock()
    with service(tmp_path, monotonic=clock.monotonic, sleep=clock.sleep) as (root, box, records):
        lock = root / ".write.lock"
        lock.write_bytes(b"")
        try:
            with pytest.raises(BusyError):
                records.call("mailbox_publish_record", request())
        finally:
            lock.unlink()
        assert "id" in records.call("mailbox_publish_record", request())


def test_legacy_read_digest_and_retry_parity(tmp_path):
    legacy = legacy_records
    with service(tmp_path) as (root, box, records):
        sent = records.call("mailbox_publish_record", request())
        old_box = legacy_mailbox.Mailbox(root)
        assert legacy.publish(codec, old_box, sender(), request()) == sent
        for arguments in ({"message_id": "record"}, {"ref": sent["id"], "fields": ["body"]},
                          {"message_id": "record", "outline": True}):
            assert records.call("mailbox_read_record", arguments) == legacy.read(
                codec, old_box, sender(), arguments)[0]
        reader = records_module.Records(box, sender("alpha/orchestrator"))
        for arguments in ({}, {"fields": ["kind"]}, {"after_message_id": "record"}):
            assert reader.call("mailbox_digest", arguments) == legacy.digest(
                codec, old_box, sender("alpha/orchestrator"), arguments, inbox=lambda *args: None)[0]


PUBLISH_RECORD = "mailbox_publish_record"
READ_RECORD = "mailbox_read_record"
DIGEST = "mailbox_digest"


def legacy_call(root, author, tool, arguments):
    def checked_mailbox(*, ready=False):
        box = legacy_mailbox.Mailbox(root)
        box.fence(author, ready=ready)
        return box
    connection = SimpleNamespace(root=root, sender=author, records=True, checked_mailbox=checked_mailbox)
    return legacy_records.call(connection, tool, arguments, nullcontext)


@pytest.mark.parametrize("case,code", [
    ("route", "E_AUTH"), ("endpoint", "E_AUTH"), ("dispatch", "E_AUTH"),
    ("job_request", "E_AUTH"), ("job_receipt", "E_AUTH"), ("reply_scope", "E_AUTH"),
    ("reply_missing", "E_REF"), ("recipient_unbound", "E_AUTH"), ("history_full", "E_LIMIT"),
])
def test_records_publish_pinned_refusal_parity(tmp_path, monkeypatch, case, code):
    with service(tmp_path) as (root, box, records):
        if case == "recipient_unbound":
            author = sender("alpha/orchestrator")
            records = records_module.Records(box, author)
            args = request(to="alpha/root")
        else:
            author, args = sender(), request()
        if case == "route":
            args["to"] = "alpha/root"
        elif case == "endpoint":
            args["to"] = "beta/orchestrator"
        elif case == "dispatch":
            brief = tmp_path / "brief.md"
            body = b"# Evidence\n"
            brief.write_bytes(body)
            args.update(type="dispatch", brief={"path": str(brief), "sha256": hashlib.sha256(body).hexdigest()})
        elif case in ("job_request", "job_receipt"):
            args["type"] = case
        elif case in ("reply_scope", "history_full"):
            records.call(PUBLISH_RECORD, request("first"))
            if case == "reply_scope":
                args["in_reply_to"] = "first"
            else:
                monkeypatch.setattr(mailbox_module, "MAX_RECORDS", 1)
                monkeypatch.setattr(legacy_mailbox, "MAX_RECORDS", 1)
        elif case == "reply_missing":
            args["in_reply_to"] = "missing"
        before = snapshot(root.parent)
        expected = legacy_call(root, author, PUBLISH_RECORD, args)
        assert expected["error"]["code"] == code
        with pytest.raises(records_module.RecordRefusal) as caught:
            records.call(PUBLISH_RECORD, args)
        assert caught.value.record_error == expected
        assert caught.value.next_action
        assert snapshot(root.parent) == before
        assert "id" in records_module.Records(box, sender()).call(
            PUBLISH_RECORD, request("first" if case == "history_full" else "retry"))


def rewrite_header(path, **changes):
    raw = path.read_text(encoding="utf-8")
    header, body = raw[4:].split("\n---\n\n", 1)
    path.write_text("---\n" + json.dumps(dict(json.loads(header), **changes)) + "\n---\n\n" + body,
                    encoding="utf-8")


@pytest.mark.parametrize("tool", [PUBLISH_RECORD, READ_RECORD, DIGEST])
@pytest.mark.parametrize("case,code", [
    ("binding", "E_AUTH"), ("misrouted_history", "E_AUTH"), ("broken_reply", "E_REF"),
    ("history_limit", "E_LIMIT"), ("unknown_argument", "E_FORMAT"),
])
def test_records_operation_refusal_parity_then_retry(tmp_path, monkeypatch, tool, case, code):
    with service(tmp_path) as (root, box, writer):
        writer.call(PUBLISH_RECORD, request("first"))
        writer.call(PUBLISH_RECORD, request("second"))
        sender_config = sender() if tool == PUBLISH_RECORD else sender("alpha/orchestrator")
        args = {PUBLISH_RECORD: request("third"), READ_RECORD: {"message_id": "first"}, DIGEST: {}}[tool]
        path = Path(box.messages()["first"]["path"])
        original = path.read_bytes()
        original_limit = mailbox_module.MAX_RECORDS
        if case == "binding":
            sender_config["binding_generation"] = 2
        elif case == "misrouted_history":
            misplaced = path.parents[1] / "root" / path.name
            path.rename(misplaced)
        elif case == "broken_reply":
            rewrite_header(path, in_reply_to="missing")
        elif case == "history_limit":
            monkeypatch.setattr(mailbox_module, "MAX_RECORDS", 1)
            monkeypatch.setattr(legacy_mailbox, "MAX_RECORDS", 1)
        else:
            args["unknown"] = "PRIVATE\nargument"
        records = records_module.Records(box, sender_config)
        before = snapshot(root.parent)
        expected = legacy_call(root, sender_config, tool, args)
        if case == "misrouted_history":
            # Legacy replay wraps this exact pinned cause in a generic ValueError.
            # The ruling names the routing-folder check itself.
            assert expected == codec.CodecError("E_FORMAT").as_dict()
            _, pinned_code, cause = next(row for row in legacy_guidance.PINNED_REFUSALS
                                         if row[0] == "message is in the wrong routing folder")
            expected = legacy_guidance.error_result(
                codec.CodecError(pinned_code, detail=cause), tool=tool, max_chars=60000)
        assert expected["error"]["code"] == code
        with pytest.raises(records_module.RecordRefusal) as caught:
            records.call(tool, args)
        assert caught.value.record_error == expected
        assert "PRIVATE" not in str(caught.value)
        assert snapshot(root.parent) == before
        if case == "misrouted_history":
            misplaced.rename(path)
        elif case == "broken_reply":
            path.write_bytes(original)
        elif case == "history_limit":
            monkeypatch.setattr(mailbox_module, "MAX_RECORDS", original_limit)
        sender_config["binding_generation"] = 1
        args.pop("unknown", None)
        assert records_module.Records(box, sender_config).call(tool, args)


@pytest.mark.parametrize("case", ["sender_checkpoint", "recipient_checkpoint", "binding_history"])
def test_records_binding_history_and_acknowledgment_parity(tmp_path, monkeypatch, case):
    with service(tmp_path) as (root, box, _records):
        replacement = replacement_request(tmp_path, 1)
        if case == "recipient_checkpoint":
            author = sender("alpha/orchestrator")
            replacement["endpoint"] = "alpha/lane/review"
            bind(box, replacement["endpoint"])
            args = request(to=replacement["endpoint"], type="dispatch",
                           brief=replacement["checkpoint"]["briefs"][0])
        else:
            author = {**sender(), "session": replacement["session"], "binding_generation": 2}
            args = request()
        binding = box.bind(replacement)
        records = records_module.Records(box, author)
        original_limit = mailbox_module.MAX_RECORDS
        if case == "binding_history":
            monkeypatch.setattr(mailbox_module, "MAX_RECORDS", 1)
            monkeypatch.setattr(legacy_mailbox, "MAX_RECORDS", 1)
        before = snapshot(root.parent)
        expected = legacy_call(root, author, PUBLISH_RECORD, args)
        assert expected["error"]["code"] == ("E_LIMIT" if case == "binding_history" else "E_AUTH")
        with pytest.raises(records_module.RecordRefusal) as caught:
            records.call(PUBLISH_RECORD, args)
        assert caught.value.record_error == expected
        assert snapshot(root.parent) == before
        if case == "binding_history":
            monkeypatch.setattr(mailbox_module, "MAX_RECORDS", original_limit)
        box.acknowledge_handoff(handoff_ack(binding))
        assert "id" in records.call(PUBLISH_RECORD, args)


def test_records_returned_ids_belong_to_each_success_and_write_no_receipt(tmp_path):
    with service(tmp_path) as (root, box, writer):
        reader = records_module.Records(box, sender("alpha/orchestrator"))
        assert reader.call_with_result(DIGEST, {}).returned == ()
        published = writer.call_with_result(PUBLISH_RECORD, request("m1"))
        assert published.returned == ()
        before = snapshot(root.parent)
        view = reader.call_with_result(READ_RECORD, {"message_id": "m1"})
        assert view.returned == ("m1",)
        assert view.payload == reader.call(READ_RECORD, {"message_id": "m1"})
        assert writer.call_with_result(READ_RECORD, {"message_id": "m1"}).returned == ()
        assert reader.call_with_result(READ_RECORD, {"ref": published.payload["id"]}).returned == ()
        assert reader.call_with_result(DIGEST, {}).returned == ("m1",)
        with pytest.raises(AttributeError):
            view.returned = ()
        with pytest.raises(records_module.RecordRefusal):
            reader.call_with_result(READ_RECORD, {"message_id": "absent"})
        assert reader.call_with_result(DIGEST, {"after_message_id": "m1"}).returned == ()
        assert view.returned == ("m1",)
        assert snapshot(root.parent) == before


def test_records_returned_ids_are_independent_during_concurrent_reads(tmp_path):
    with service(tmp_path) as (root, box, writer):
        for identifier in ("m1", "m2", "m3", "m4"):
            writer.call(PUBLISH_RECORD, request(identifier))
        reader = records_module.Records(box, sender("alpha/orchestrator"))
        old_box = legacy_mailbox.Mailbox(root)
        before = snapshot(root.parent)
        start = Barrier(2, timeout=5)
        def read(tool, arguments):
            start.wait()
            return reader.call_with_result(tool, arguments)
        arguments = {"limit": 2, "after_message_id": "m1"}
        with ThreadPoolExecutor(max_workers=2) as pool:
            single = pool.submit(read, READ_RECORD, {"message_id": "m1"})
            page = pool.submit(read, DIGEST, arguments)
            actual_view, actual_page = single.result(timeout=5), page.result(timeout=5)
        expected_page, expected_ids = legacy_records.digest(
            codec, old_box, sender("alpha/orchestrator"), arguments, inbox=lambda *args: None)
        assert actual_view.returned == ("m1",)
        assert actual_page.payload == expected_page
        assert actual_page.returned == tuple(expected_ids) == ("m2", "m3")
        assert snapshot(root.parent) == before


def test_records_digest_returns_at_most_one_page_of_ids(tmp_path):
    with service(tmp_path) as (root, box, _writer):
        message = {**sender(), "to": "alpha/orchestrator", "body": "ordinary", "type": "info"}
        box.publish(dict(message, message_id="m000"))
        path = Path(box.messages()["m000"]["path"])
        identifiers = [f"m{index:03d}" for index in range(101)]
        for identifier in identifiers[1:]:
            other = path.with_name(identifier + path.suffix)
            other.write_bytes(path.read_bytes())
            rewrite_header(other, message_id=identifier)
        reader = records_module.Records(box, sender("alpha/orchestrator"))
        before = snapshot(root.parent)
        page = reader.call_with_result(DIGEST, {"limit": 100})
        payload = json.loads(page.payload)
        assert page.returned == tuple(identifiers[:100])
        assert payload["next_after"] == identifiers[99]
        assert reader.call_with_result(DIGEST, {"after_message_id": payload["next_after"]}).returned == ("m100",)
        assert snapshot(root.parent) == before


class WaitClock:
    def __init__(self, on_sleep=None):
        self.milliseconds = 0
        self.on_sleep = on_sleep

    def monotonic(self):
        return self.milliseconds / 1000

    def sleep(self, seconds):
        assert 0 < seconds <= 0.01
        self.milliseconds += round(seconds * 1000)
        if self.on_sleep is not None:
            self.on_sleep(self.milliseconds)


def test_records_owner_contention_refuses_immediately_then_retries(tmp_path, owner_plane):
    clock = WaitClock()
    with service(tmp_path, monotonic=clock.monotonic, sleep=clock.sleep) as (root, _box, records):
        owner_lock = owner_plane / OWNER_EVIDENCE_LOCK
        owner_lock.write_bytes(b"")
        before = snapshot(root.parent)
        with pytest.raises(BusyError) as caught:
            records.call(PUBLISH_RECORD, request())
        assert caught.value.as_dict() == BusyError(owner_lock).as_dict()
        assert clock.milliseconds == 0
        assert owner_lock.is_file() and snapshot(root.parent) == before
        owner_lock.unlink()
        assert "id" in records.call(PUBLISH_RECORD, request())
        assert not owner_lock.exists()


@pytest.mark.parametrize("release", [True, False])
def test_records_holds_one_owner_claim_through_write_lock_polling(tmp_path, owner_plane, monkeypatch, release):
    with service(tmp_path) as (root, box, _writer):
        owner_lock = owner_plane / OWNER_EVIDENCE_LOCK
        write_lock = root / ".write.lock"
        write_lock.write_bytes(b"")
        before = snapshot(root.parent)
        acquisitions = []

        def opened(name, flags, *args, **kwargs):
            if name == owner_lock.name and flags & os.O_EXCL:
                acquisitions.append(name)
            return os.open(name, flags, *args, **kwargs)

        monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "open": opened}))

        def observe(elapsed):
            assert owner_lock.is_file()
            assert acquisitions == [owner_lock.name]
            if release and elapsed == 20:
                write_lock.unlink()

        clock = WaitClock(observe)
        records = records_module.Records(box, sender(), monotonic=clock.monotonic, sleep=clock.sleep)
        if release:
            assert "id" in records.call(PUBLISH_RECORD, request())
            assert clock.milliseconds == 20
        else:
            with pytest.raises(BusyError) as caught:
                records.call(PUBLISH_RECORD, request())
            assert caught.value.as_dict() == BusyError(write_lock).as_dict()
            assert clock.milliseconds == 5000
            assert snapshot(root.parent) == before
        assert acquisitions == [owner_lock.name]
        assert not owner_lock.exists()
        if not release:
            write_lock.unlink()
            assert "id" in records.call(PUBLISH_RECORD, request())


@pytest.mark.parametrize("lock_name", [".write.lock", ".records-store.lock", ".publish.lock"])
@pytest.mark.parametrize("release", [True, False])
def test_records_waits_for_each_reservation_then_refuses_or_retries(tmp_path, lock_name, release):
    with service(tmp_path) as (root, box, writer):
        writer.call(PUBLISH_RECORD, request("first"))
        parent = {".write.lock": root, ".records-store.lock": root.parent,
                  ".publish.lock": root.parent / "mailbox-records"}[lock_name]
        lock = parent / lock_name
        lock.write_bytes(b"")
        before = snapshot(root.parent)
        clock = WaitClock(lambda elapsed: lock.unlink() if release and elapsed == 4990 else None)
        records = records_module.Records(box, sender(), monotonic=clock.monotonic, sleep=clock.sleep)
        if not release:
            with pytest.raises(BusyError) as caught:
                records.call(PUBLISH_RECORD, request("second"))
            assert type(caught.value) is BusyError
            assert snapshot(root.parent) == before
            assert clock.milliseconds == 5000
            lock.unlink()
        assert "id" in records.call(PUBLISH_RECORD, request("second"))
        assert clock.milliseconds == (4990 if release else 5000)
        assert not lock.exists()


def test_records_reservations_get_independent_wait_windows(tmp_path):
    with service(tmp_path) as (root, box, writer):
        writer.call(PUBLISH_RECORD, request("first"))
        locks = [root / ".write.lock", root.parent / ".records-store.lock",
                 root.parent / "mailbox-records" / ".publish.lock"]
        for path in locks:
            path.write_bytes(b"")
        releases = dict(zip((4900, 9800, 14700), locks))
        def release(elapsed):
            if elapsed in releases:
                releases[elapsed].unlink()
        clock = WaitClock(release)
        records = records_module.Records(box, sender(), monotonic=clock.monotonic, sleep=clock.sleep)
        assert "id" in records.call(PUBLISH_RECORD, request("second"))
        assert clock.milliseconds == 14700
        assert all(not path.exists() for path in locks)


def test_records_waits_before_initializing_root_identity(tmp_path):
    with service(tmp_path) as (root, box, _writer):
        store = root.parent / "mailbox-records"
        store.mkdir(mode=0o700)
        lock = store / ".publish.lock"
        lock.write_bytes(b"")
        before = snapshot(root.parent)
        def no_initialization(_elapsed):
            assert not (root / ".root-id").exists()
        clock = WaitClock(no_initialization)
        records = records_module.Records(box, sender(), monotonic=clock.monotonic, sleep=clock.sleep)
        with pytest.raises(BusyError):
            records.call(PUBLISH_RECORD, request())
        assert snapshot(root.parent) == before
        lock.unlink()
        assert "id" in records.call(PUBLISH_RECORD, request())
        assert (root / ".root-id").is_file()


def test_records_concurrent_publishers_both_commit_with_caller_retry(tmp_path, owner_plane):
    with service(tmp_path) as (root, box, _writer):
        write_lock = root / ".write.lock"
        write_lock.write_bytes(b"")
        waiting, released = Event(), Event()

        def wait_for_release(_seconds):
            waiting.set()
            assert released.wait(5)

        records = records_module.Records(box, sender(), sleep=wait_for_release)
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(records.call, PUBLISH_RECORD, request("first"))
            try:
                assert waiting.wait(5)
                contender = pool.submit(records.call, PUBLISH_RECORD, request("second"))
                with pytest.raises(BusyError) as caught:
                    contender.result(timeout=5)
                assert caught.value.as_dict() == BusyError(owner_plane / OWNER_EVIDENCE_LOCK).as_dict()
            finally:
                write_lock.unlink()
                released.set()
            first.result(timeout=5)
            second = pool.submit(records.call, PUBLISH_RECORD, request("second"))
            assert [first.result(timeout=5)["message_id"], second.result(timeout=5)["message_id"]] == [
                "first", "second"]
        assert set(box.messages()) == {"first", "second"}


def test_guidance_specs_and_refusal_bytes_match_legacy():
    guidance = importlib.import_module("aegis_core.team_mailbox_guidance")
    legacy = legacy_guidance
    properties = {key: {"type": "string"} for key in ("message_id", "body", "to", "type")}
    assert guidance.tool_specs(properties, codec.MAX_BYTES) == legacy.tool_specs(properties, codec.MAX_BYTES)
    for tool in ("mailbox_publish_record", "mailbox_read_record", "mailbox_digest"):
        for code in ("E_FORMAT", "E_HASH", "E_REF", "E_AUTH", "E_LIMIT", "E_SELECTOR"):
            for detail in ("", *guidance.NEXT_ACTIONS, "digest_floor", "digest_limit", "digest_max_chars",
                           "digest_page", "digest_inbox", "digest_view", "digest_view_minimum", "grants", "history"):
                error = codec.CodecError(code, detail=detail)
                assert guidance.error_result(error, tool=tool, max_chars=60000) == legacy.error_result(
                    error, tool=tool, max_chars=60000)


def test_unhashable_grant_kind_refuses_and_retry(tmp_path):
    with service(tmp_path) as (root, box, records):
        sent = records.call("mailbox_publish_record", request())
        path = root.parent / "mailbox-records" / "grants" / (".grants-" + sent["id"])
        previous = path.read_bytes()
        value = codec.parse(previous)
        value["fields"]["value"]["kind"] = {}
        path.write_bytes(codec.canonical(value))
        before = snapshot(root.parent)
        with pytest.raises(MailboxRefusal) as caught:
            records.call("mailbox_read_record", {"ref": sent["id"]})
        assert caught.value.reason == "E_AUTH"
        assert snapshot(root.parent) == before
        path.write_bytes(previous)
        assert records.call("mailbox_read_record", {"ref": sent["id"]})


def test_digest_without_inbox_port_returns_measured_refusal(tmp_path):
    with service(tmp_path) as (root, box, records):
        box.publish({**sender(), "message_id": "ordinary", "to": "alpha/orchestrator", "type": "info",
                     "body": "body" * 1000})
        reader = records_module.Records(box, sender("alpha/orchestrator"))
        before = snapshot(root.parent)
        with pytest.raises(MailboxRefusal) as caught:
            reader.call("mailbox_digest", {"max_chars": 200})
        assert caught.value.reason == "E_LIMIT"
        assert "inbox retry could not be verified" in caught.value.next_action
        assert snapshot(root.parent) == before
        assert json.loads(reader.call("mailbox_digest", {}))["messages"][0]["message_id"] == "ordinary"


@pytest.mark.parametrize("phase", ["identity", "stub", "grant", "read", "grant_read"])
def test_fdopen_failure_closes_owned_descriptors_and_retry(tmp_path, monkeypatch, phase):
    with service(tmp_path) as (root, box, records):
        tracked, names = set(), {}
        if phase in ("read", "grant_read"):
            sent = records.call("mailbox_publish_record", request())
        before = snapshot(root.parent)
        def opened(path, flags, *args, **kwargs):
            fd = os.open(path, flags, *args, **kwargs)
            tracked.add(fd)
            names[fd] = (path, kwargs.get("dir_fd"))
            return fd
        def closed(fd):
            tracked.discard(fd)
            os.close(fd)
        def wrapped(fd, *args, **kwargs):
            name, directory = names[fd]
            if phase in ("identity", "stub", "grant"):
                parent = {"identity": root, "stub": root / "alpha" / "orchestrator",
                          "grant": root.parent / "mailbox-records" / "grants"}[phase]
                selected = (re.fullmatch(r"\.pending-[0-9a-f]{32}", name) is not None and
                            os.path.samestat(os.fstat(directory), parent.stat()))
            else:
                selected = name == (".root-id" if phase == "read" else ".grants-" + sent["id"])
            if selected:
                raise OSError("injected fdopen failure")
            return os.fdopen(fd, *args, **kwargs)
        monkeypatch.setattr(records_module, "os", SimpleNamespace(**{**vars(os), "open": opened,
                            "close": closed, "fdopen": wrapped}))
        try:
            with pytest.raises(MailboxRefusal) as caught:
                reading = phase in ("read", "grant_read")
                records.call("mailbox_read_record" if reading else "mailbox_publish_record",
                             {"message_id": "record"} if reading else request())
            assert caught.value.reason == "E_AUTH"
        finally:
            monkeypatch.setattr(records_module, "os", os)
        assert not tracked
        assert snapshot(root.parent) == before
        assert "id" in records.call("mailbox_publish_record", request())


def test_symlinked_store_refuses_without_side_effects_then_retry(tmp_path):
    with service(tmp_path) as (root, box, records):
        outside = tmp_path / "outside"
        outside.mkdir()
        path = root.parent / "mailbox-records"
        symlink_or_skip(outside, path, target_is_directory=True)
        before = snapshot(root)
        with pytest.raises(MailboxRefusal):
            records.call("mailbox_publish_record", request())
        assert snapshot(root) == before
        assert list(outside.iterdir()) == []
        path.unlink()
        assert "id" in records.call("mailbox_publish_record", request())


@pytest.mark.parametrize("lock_name", [".records-store.lock", ".publish.lock"])
def test_store_reservation_is_shared_busy_type_then_retry(tmp_path, lock_name):
    clock = WaitClock()
    with service(tmp_path, monotonic=clock.monotonic, sleep=clock.sleep) as (root, box, records):
        records.call("mailbox_publish_record", request())
        path = root.parent if lock_name == ".records-store.lock" else root.parent / "mailbox-records"
        lock = path / lock_name
        lock.write_bytes(b"")
        before = snapshot(root.parent)
        try:
            with pytest.raises(BusyError) as caught:
                records.call("mailbox_publish_record", request("second"))
            assert caught.value.reason == "busy"
            assert snapshot(root.parent) == before
        finally:
            lock.unlink()
        assert "id" in records.call("mailbox_publish_record", request("second"))


def test_concurrent_parent_swap_never_follows_replacement_symlink(tmp_path, monkeypatch):
    with service(tmp_path) as (root, box, records):
        sent = records.call("mailbox_publish_record", request())
        outside, moved, probe = tmp_path / "outside", tmp_path / "held", tmp_path / "probe"
        outside.mkdir()
        symlink_or_skip(outside, probe, target_is_directory=True)
        probe.unlink()
        original = root.parent / "mailbox-records"
        swapped = []
        def opened(name, flags, *args, **kwargs):
            fd = os.open(name, flags, *args, **kwargs)
            if name == "mailbox-records" and not swapped:
                swapped.append(True)
                original.rename(moved)
                symlink_or_skip(outside, original, target_is_directory=True)
            return fd
        try:
            monkeypatch.setattr(records_module, "os", SimpleNamespace(**{**vars(os), "open": opened}))
            with pytest.raises(MailboxRefusal):
                records.call("mailbox_read_record", {"ref": sent["id"]})
            assert swapped
            assert list(outside.iterdir()) == []
        finally:
            monkeypatch.setattr(records_module, "os", os)
            if swapped:
                original.unlink()
                moved.rename(original)
        assert records.call("mailbox_read_record", {"ref": sent["id"]})


@pytest.mark.parametrize("name,arguments", [
    ("mailbox_publish_record", None),
    ("mailbox_publish_record", request(kind=[])),
    ("mailbox_publish_record", request(content=[])),
    ("mailbox_publish_record", request(message_id=[])),
    ("mailbox_read_record", {"ref": []}),
    ("mailbox_read_record", {"message_id": "missing"}),
    ("mailbox_digest", {"fields": [None]}),
    ("mailbox_digest", {"refs": [None]}),
    ("mailbox_digest", {"limit": True}),
    ("mailbox_digest", {"max_chars": None}),
])
def test_malformed_public_arguments_are_typed_and_do_not_mutate(tmp_path, name, arguments):
    with service(tmp_path) as (root, box, records):
        before = snapshot(root.parent)
        with pytest.raises(MailboxRefusal) as caught:
            records.call(name, arguments)
        assert caught.value.reason in {"E_FORMAT", "E_AUTH", "E_REF", "E_SELECTOR", "E_LIMIT"}
        assert caught.value.next_action
        assert snapshot(root.parent) == before


@pytest.mark.parametrize("code", ["E_FORMAT", "E_HASH", "E_AUTH", "E_REF", "E_SELECTOR", "E_SPAN", "E_LIMIT"])
def test_every_codec_refusal_has_public_reason_and_action(code):
    error = records_module.RecordRefusal(codec.CodecError(code), "mailbox_read_record")
    assert error.as_dict() == {"status": "refused", "reason": code, "code": 1,
                               "next_action": error.next_action}
    assert error.next_action
    assert error.record_error == codec.CodecError(code).as_dict()


def test_unicode_byte_limit_is_checked_before_encoding_allocation(tmp_path):
    with service(tmp_path) as (root, box, records):
        arguments = request(content="\U0001f600" * codec.MAX_BYTES)
        before = snapshot(root.parent)
        tracemalloc.start()
        try:
            with pytest.raises(MailboxRefusal) as caught:
                records.call("mailbox_publish_record", arguments)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert caught.value.reason == "E_LIMIT"
        assert peak < codec.MAX_BYTES * 3
        assert snapshot(root.parent) == before
        assert "id" in records.call("mailbox_publish_record", request())


def test_committed_publish_retains_mailbox_cleanup_warning(tmp_path, monkeypatch):
    clock = WaitClock()
    with service(tmp_path, monotonic=clock.monotonic, sleep=clock.sleep) as (root, box, records):
        def unlink(name, *args, **kwargs):
            if name == ".write.lock":
                raise OSError("injected lock cleanup failure")
            return os.unlink(name, *args, **kwargs)
        monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "unlink": unlink}))
        try:
            sent = records.call("mailbox_publish_record", request())
        finally:
            monkeypatch.setattr(store_module, "os", os)
        assert sent["warnings"][0]["reason"] == "lock_release"
        assert sent["warnings"][0]["lock_path"].endswith("/mail/.write.lock")
        assert len(sent["warnings"][0]["lock_path"]) <= 1024
        with pytest.raises(BusyError):
            records.call("mailbox_publish_record", request())
        (root / ".write.lock").unlink()
        assert records.call("mailbox_publish_record", request()) == {key: sent[key] for key in ("id", "message_id")}


@pytest.mark.parametrize("verdict", ["ACCEPT\nREQUEST_CHANGES", "ACCEPT\rREQUEST_CHANGES"])
def test_multiline_signed_verdict_is_refused_without_joining(tmp_path, verdict):
    with service(tmp_path) as (root, box, records):
        fields = {"reasoning_summary": "checked", "findings": [], "checked": [], "coverage_gaps": "",
                  "verdict": verdict, "prior_findings": []}
        arguments = request(kind="review.v1", content=json.dumps({"fields": fields, "body": "", "refs": {}}))
        before = snapshot(root.parent)
        with pytest.raises(MailboxRefusal) as caught:
            records.call("mailbox_publish_record", arguments)
        assert caught.value.reason == "E_FORMAT"
        assert snapshot(root.parent) == before
        fields["verdict"] = "ACCEPT"
        arguments["content"] = json.dumps({"fields": fields, "body": "", "refs": {}})
        assert "id" in records.call("mailbox_publish_record", arguments)


@pytest.mark.parametrize("leave_staging", [False, True])
def test_readers_accept_live_and_leftover_publication_staging(tmp_path, monkeypatch, leave_staging):
    with service(tmp_path) as (root, box, records):
        records.call("mailbox_publish_record", request("first"))
        reader = records_module.Records(box, sender("alpha/orchestrator"))
        expected = reader.call("mailbox_read_record", {"message_id": "first"})
        route = root / "alpha" / "orchestrator"
        entered, release = Event(), Event()
        staged_names = []

        def link(source, target, *args, **kwargs):
            if str(target).endswith(".md"):
                staged_names.append(source)
                entered.set()
                assert release.wait(5), "publication staging was not released"
            return os.link(source, target, *args, **kwargs)

        def unlink(name, *args, **kwargs):
            if (leave_staging and name.startswith(".pending-") and
                    os.path.samestat(os.fstat(kwargs["dir_fd"]), route.stat())):
                raise OSError("injected staging unlink failure")
            return os.unlink(name, *args, **kwargs)

        def check_readers(identifiers):
            digest = json.loads(reader.call("mailbox_digest", {}))
            assert [row["message_id"] for row in digest["messages"]] == identifiers
            assert reader.call("mailbox_read_record", {"message_id": "first"}) == expected
            inbox = box.inbox("alpha/orchestrator")
            assert [row["message"]["message_id"] for row in inbox["messages"]] == identifiers

        monkeypatch.setattr(records_module, "os", SimpleNamespace(**{**vars(os), "link": link, "unlink": unlink}))
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(records.call, "mailbox_publish_record", request("second"))
                try:
                    assert entered.wait(5), "publication did not reach staging"
                    check_readers(["first"])
                finally:
                    release.set()
                sent = future.result(timeout=5)
        finally:
            monkeypatch.setattr(records_module, "os", os)
        assert all(re.fullmatch(r"\.pending-[0-9a-f]{32}", name) for name in staged_names)
        leftovers = list(route.glob(".pending-*"))
        assert bool(leftovers) is leave_staging
        assert ("note" in sent) is leave_staging
        if leave_staging:
            reservation = root.parent / "mailbox-records" / ".publish.lock"
            assert reservation.is_file()
            for read in (lambda: reader.call("mailbox_digest", {}),
                         lambda: reader.call("mailbox_read_record", {"message_id": "first"}),
                         lambda: box.inbox("alpha/orchestrator")):
                with pytest.raises(MailboxRefusal, match="^mailbox refused: unsafe_path$") as caught:
                    read()
                assert caught.value.reason == "unsafe_path"
                assert caught.value.code == 1
                assert caught.value.next_action
            assert leftovers[0].name in sent["note"]
            assert "/mail/alpha/orchestrator/" in sent["note"]
            assert "owner:" in sent["note"]
            assert "remove only the leftover staging file" in sent["note"]
            assert "retry the same message_id" in sent["note"]
            assert ".publish.lock" in sent["note"]
            assert len(sent["note"]) <= 1024
            for stage in leftovers:
                stage.unlink()  # The owner's recovery, with production refusal preserved above.
        check_readers(["first", "second"])
        assert records.call("mailbox_publish_record", request("second")) == {
            key: sent[key] for key in ("id", "message_id")}
        if leave_staging:
            assert reservation.is_file()  # Idempotent retry does not clear an owner-inspected reservation.


def test_cleanup_note_redacts_and_bounds_untrusted_stage_parent(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX control-character directory names required")
    parent = tmp_path / "password=OPERATOR_SENTINEL\x1b[31m\n"
    for index in range(4):
        parent = parent / ("directory-" + str(index) + "-" + "x" * 120)
    parent.mkdir(mode=0o700, parents=True)
    with service(parent) as (root, box, records):
        route = root / "alpha" / "orchestrator"
        def unlink(name, *args, **kwargs):
            if (name.startswith(".pending-") and
                    os.path.samestat(os.fstat(kwargs["dir_fd"]), route.stat())):
                raise OSError("injected staging unlink failure")
            return os.unlink(name, *args, **kwargs)
        monkeypatch.setattr(records_module, "os", SimpleNamespace(**{**vars(os), "unlink": unlink}))
        try:
            sent = records.call("mailbox_publish_record", request())
        finally:
            monkeypatch.setattr(records_module, "os", os)
        stage, = route.glob(".pending-*")
        note = sent["note"]
        assert stage.name in note  # The code-generated identifier stays usable after parent clipping.
        assert "OPERATOR_SENTINEL" not in note
        assert "REDACTED" in note
        assert "\x1b" not in note and "\n" not in note and "\r" not in note
        assert len(note) <= 1024
        assert "remove only the leftover staging file" in note
        stage.unlink()
        assert records.call("mailbox_read_record", {"message_id": "record"})
        assert records.call("mailbox_publish_record", request()) == {
            key: sent[key] for key in ("id", "message_id")}


def test_all_publication_staging_names_are_random_and_distinct(tmp_path, monkeypatch):
    with service(tmp_path) as (root, box, records):
        names = []
        def opened(name, flags, *args, **kwargs):
            if type(name) is str and name.startswith(".pending-") and flags & os.O_CREAT:
                names.append(name)
            return os.open(name, flags, *args, **kwargs)
        monkeypatch.setattr(records_module, "os", SimpleNamespace(**{**vars(os), "open": opened}))
        try:
            records.call("mailbox_publish_record", request("first"))
            records.call("mailbox_publish_record", request("second"))
        finally:
            monkeypatch.setattr(records_module, "os", os)
        assert len(names) >= 4  # Identity, grants and both route-file publications.
        assert all(re.fullmatch(r"\.pending-[0-9a-f]{32}", name) for name in names)
        assert len(names) == len(set(names))


@pytest.mark.parametrize("later_row", [False, True])
@pytest.mark.parametrize("failure", ["mailbox", "busy", "codec"])
def test_refusing_inbox_probe_preserves_limit_and_smaller_page_retry(tmp_path, later_row, failure):
    with service(tmp_path) as (root, box, records):
        if later_row:
            box.publish({**sender(), "message_id": "first", "to": "alpha/orchestrator",
                         "type": "info", "body": "small"})
        box.publish({**sender(), "message_id": "oversized", "to": "alpha/orchestrator",
                     "type": "info", "body": "large" * 1000})
        attempts = []
        def inbox(options, message_id, history):
            attempts.append((options, message_id, set(history)))
            if failure == "codec":
                raise codec.CodecError("E_AUTH")
            if failure == "busy":
                raise BusyError()
            raise MailboxRefusal("io")
        reader = records_module.Records(box, sender("alpha/orchestrator"), inbox=inbox)
        maximum = len(reader.call("mailbox_digest", {"limit": 1})) + 16 if later_row else 200
        arguments = {"max_chars": maximum}
        before = snapshot(root.parent)
        with pytest.raises(records_module.RecordRefusal) as caught:
            reader.call("mailbox_digest", arguments)
        assert caught.value.reason == "E_LIMIT"
        assert caught.value.next_action
        assert attempts == [({"limit": 100}, "oversized", {"first", "oversized"} if later_row else {"oversized"})]
        if later_row:
            retry = caught.value.record_error["error"]["retry"]
            assert retry["tool"] == "mailbox_digest"
            assert retry["options"] == {"limit": 1}
            page = json.loads(reader.call(retry["tool"], {**arguments, **retry["options"]}))
            assert [row["message_id"] for row in page["messages"]] == ["first"]
            assert page["next_after"] == "first"
        else:
            assert "inbox retry could not be verified" in caught.value.next_action
        assert snapshot(root.parent) == before
        complete = json.loads(reader.call("mailbox_digest", {}))
        assert [row["message_id"] for row in complete["messages"]] == (
            ["first", "oversized"] if later_row else ["oversized"])
