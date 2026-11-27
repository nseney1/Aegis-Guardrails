"""RF-8: the codec facade retains storage behavior and bounded canonical bytes."""
from contextlib import closing
import errno
import hashlib
import json
import os
import sys
from types import SimpleNamespace

import pytest

from aegis_core import message_codec as codec
from aegis_core import message_codec_store as codec_store
from tests.integration.test_hierarchy_mailbox_records import record_path
from tests.unit.core.test_message_codec import assert_error, assert_record_limit, make_store, raw, record


OPERATION_ERROR = (
    "store operation unavailable; check permissions, free space, write access and file descriptor limits"
)


def canonical_dumps(value):
    """Observe real stdlib calls without replacing validation or encoding."""
    calls, previous = [], sys.getprofile()

    def observed(frame, event, _arg):
        if event == "call" and frame.f_code is json.dumps.__code__:
            calls.append(frame.f_locals["obj"])

    try:
        sys.setprofile(observed)
        encoded = codec.canonical(value)
    finally:
        sys.setprofile(previous)
    return encoded, calls


@pytest.mark.parametrize("body", ["Prose from the writer. " * 700, "\U0001f600" * 1000],
                         ids=["prose", "supplementary"])
def test_rf8_canonical_encodes_budgeted_string_once(body):
    value = record(body=body)
    encoded, calls = canonical_dumps(value)
    assert encoded == raw(value)
    assert sum(item is body for item in calls) == 1


@pytest.mark.parametrize("late", [False, True])
def test_rf8_canonical_keeps_chunks_when_worst_case_exceeds_remaining_budget(late):
    text = "b" * (1000 if late else 100000)
    value = (record("record", {"value": {"a": "x" * 258000, "z": text}}) if late
             else record(body=text))
    encoded, calls = canonical_dumps(value)
    assert encoded == raw(value)
    assert not any(item is text for item in calls)
    assert max(len(item) for item in calls if type(item) is str) <= 8192


@pytest.mark.parametrize("invalid", ["bytes", "escaped", "depth", "nodes", "refs", "schema"])
def test_rf8_preflight_refuses_before_record_encoding(invalid):
    value = record()
    if invalid == "bytes":
        value["body"] = "x" * codec.MAX_BYTES
    elif invalid == "escaped":
        value["body"] = "\x01" * 50000
    elif invalid == "depth":
        nested = None
        for _ in range(32):
            nested = [nested]
        value = record("record", {"value": nested})
    elif invalid == "nodes":
        value = record("record", {"value": [None] * 10001})
    elif invalid == "refs":
        value["refs"] = {str(i): "a" * 64 for i in range(65)}
    else:
        value["schema"] = "unknown"
    calls, previous = [], sys.getprofile()

    def observed(frame, event, _arg):
        if event == "call" and frame.f_code is json.dumps.__code__:
            calls.append(frame.f_locals["obj"])

    try:
        sys.setprofile(observed)
        if invalid == "schema":
            assert_error("E_FORMAT", lambda: codec.canonical(value))
        else:
            assert_record_limit(lambda: codec.canonical(value))
    finally:
        sys.setprofile(previous)
    assert not any(type(item) is str for item in calls)


@pytest.mark.parametrize("payload", [
    "".join(chr(i) for i in range(128)) + "\u0080\u00e9\u2028\u202e\uffff\U00010000\U0010ffff",
    {"z": -0.0, "a": [None, True, False, 1e-20, 1e20, 1.7976931348623157e308,
                        -(10 ** 63) + 1, 10 ** 64 - 1]},
    {"\U0001f600": "\\u202e", "\ue000": "\n\t\\\"", "": [[], {}]},
])
def test_rf8_canonical_matches_stdlib_bytes_and_digest(payload):
    value = record("record", {"value": payload})
    expected = raw(value)
    assert codec.canonical(value) == expected
    assert codec.record_id(value) == hashlib.sha256(expected).hexdigest()
    assert codec.parse(expected) == value


def test_rf8_store_module_preserves_facade_and_verified_refs(tmp_path):
    from aegis_core.message_codec_store import Store

    assert codec.Store is Store
    store = make_store(tmp_path)
    try:
        child = record(body="child\n\U0001f600")
        rid = store.write(child)
        path = record_path(tmp_path, rid)
        assert path.read_bytes() == raw(child)
        assert store.read(rid[:16]) == child
        assert store.describe(rid) == {"ref": rid[:16], "kind": "text", "chars": len(raw(child))}
        parent = dict(record(), refs={"child": rid})
        assert json.loads(codec.read_view(parent, store=store, expand=["child"]))["data"]["refs"]["child"] == child
        path.write_bytes(raw(record(body="tampered")))
        assert_error("E_HASH", lambda: codec.read_view(parent, store=store))
    finally:
        store.close()
    assert_error("E_AUTH", lambda: store.read(rid))


@pytest.mark.parametrize("step", ["stat", "open"])
def test_rf44_rollback_reclaims_shard_after_failed_binding(tmp_path, monkeypatch, step):
    value = record(body="shard binding")
    rid = codec.record_id(value)
    shard = tmp_path / rid[:2]
    failed = []
    with closing(make_store(tmp_path)) as store:
        publication = store.begin_publication()

        def stated(name, *args, **kwargs):
            if step == "stat" and name == shard.name and shard.is_dir() and not failed:
                failed.append(step)
                raise OSError(errno.EIO, "injected shard stat failure")
            return os.stat(name, *args, **kwargs)

        def opened(name, *args, **kwargs):
            if step == "open" and name == shard.name:
                failed.append(step)
                raise OSError(errno.EIO, "injected shard open failure")
            return os.open(name, *args, **kwargs)

        monkeypatch.setattr(codec_store, "os", SimpleNamespace(**{**vars(os), "stat": stated, "open": opened}))
        assert_error("E_AUTH", lambda: store.write(value, publication=publication), OPERATION_ERROR)
        assert failed == [step]
        assert list(shard.iterdir()) == []
        store.rollback(publication)
        assert failed == [step]
        assert list(tmp_path.iterdir()) == []
        monkeypatch.setattr(codec_store, "os", os)
        assert store.write(value, publication=store.begin_publication()) == rid


@pytest.mark.parametrize("failure", ["unlink", "sync"])
def test_rf44_rollback_preserves_payload_until_staging_is_reclaimed(tmp_path, monkeypatch, failure):
    value = record(body="staging cleanup")
    rid = codec.record_id(value)
    payload = record_path(tmp_path, rid)
    with closing(make_store(tmp_path)) as store:
        publication = store.begin_publication()
        blocked = []

        def unlink(name, *args, **kwargs):
            if failure == "unlink" and name.startswith(".msg-"):
                blocked.append(name)
                raise OSError(errno.EACCES, "injected staging unlink failure")
            return os.unlink(name, *args, **kwargs)

        def sync(fd):
            if failure == "sync" and os.path.samestat(os.fstat(fd), payload.parent.stat()):
                blocked.append(failure)
                raise OSError(errno.EIO, "injected staging directory sync failure")
            os.fsync(fd)

        monkeypatch.setattr(codec_store, "os", SimpleNamespace(**{**vars(os), "unlink": unlink, "fsync": sync}))
        assert_error("E_AUTH", lambda: store.write(value, publication=publication), OPERATION_ERROR)
        assert_error("E_AUTH", lambda: store.rollback(publication), OPERATION_ERROR)
        assert len(blocked) >= 2 and set(blocked) == {blocked[0]}
        assert payload.read_bytes() == raw(value)
        if failure == "unlink":
            assert (payload.parent / blocked[0]).read_bytes() == raw(value)
        monkeypatch.setattr(codec_store, "os", os)
        store.rollback(publication)
        store.rollback(publication)
        assert list(tmp_path.iterdir()) == []


def test_rf44_capability_probe_refuses_without_descriptor_scandir(tmp_path, monkeypatch):
    def opened(*args, **kwargs):
        pytest.fail("an unsupported platform reached the store's open boundary")

    monkeypatch.setattr(codec_store, "os", SimpleNamespace(**{**vars(os), "supports_fd": set(), "open": opened}))
    assert not codec.Store.supported()
    assert_error("E_AUTH", lambda: codec.Store(tmp_path))
