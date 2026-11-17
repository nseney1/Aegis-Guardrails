"""Product records, typed refusals and legacy wire parity through public APIs."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import importlib
import json
import os
from pathlib import Path
import re
from threading import Event
from types import SimpleNamespace
import tracemalloc

import pytest

from conftest import symlink_or_skip
from tests.unit.core.test_team_mailbox import (
    bind, mailbox, make_store, owner_plane, snapshot,
)
from aegis_core.team_mailbox_primitives import BusyError, MailboxRefusal
from aegis_core import message_codec as codec
from tools import hierarchy_mailbox as legacy_mailbox
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
def service(tmp_path):
    root = make_store(tmp_path)
    with mailbox(root) as box:
        bind(box, "alpha/front-door")
        bind(box, "alpha/orchestrator")
        yield root, box, records_module.Records(box, sender())


def test_publish_retry_read_digest_and_injected_clock(tmp_path):
    with service(tmp_path) as (root, box, records):
        first = records.call("mailbox_publish_record", request())
        before = snapshot(root.parent)
        assert records.call("mailbox_publish_record", request()) == first
        assert snapshot(root.parent) == before
        reader = records_module.Records(box, sender("alpha/orchestrator"))
        view = json.loads(reader.call("mailbox_read_record", {"message_id": "record"}))
        assert view["from"] == "alpha/front-door"
        raw = json.loads((root.parent / "mailbox-records" / (first["id"] + ".json")).read_bytes())
        assert raw["meta"]["created_at"] == "2026-11-16T12:00:00.000000Z"
        digest = json.loads(reader.call("mailbox_digest", {}))
        assert digest["messages"][0]["record"] == view
        assert json.loads(reader.call("mailbox_digest", {"after_message_id": "record"}))["messages"] == []


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
    with service(tmp_path) as (root, box, records):
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
        path = root.parent / "mailbox-records" / (".grants-" + sent["id"])
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
                          "grant": root.parent / "mailbox-records"}[phase]
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
    with service(tmp_path) as (root, box, records):
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
    with service(tmp_path) as (root, box, records):
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
