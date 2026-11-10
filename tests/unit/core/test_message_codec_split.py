"""RF-8: the codec facade retains storage behavior and bounded canonical bytes."""
import hashlib
import json
import sys

import pytest

from aegis_core import message_codec as codec
from tests.unit.core.test_message_codec import assert_error, assert_record_limit, make_store, raw, record


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
    assert max(len(item) for item in calls if type(item) is str) <= 128


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
        assert (tmp_path / (rid + ".json")).read_bytes() == raw(child)
        assert store.read(rid[:16]) == child
        assert store.describe(rid) == {"ref": rid[:16], "kind": "text", "chars": len(raw(child))}
        parent = dict(record(), refs={"child": rid})
        assert json.loads(codec.read_view(parent, store=store, expand=["child"]))["data"]["refs"]["child"] == child
        (tmp_path / (rid + ".json")).write_bytes(raw(record(body="tampered")))
        assert_error("E_HASH", lambda: codec.read_view(parent, store=store))
    finally:
        store.close()
    assert_error("E_AUTH", lambda: store.read(rid))
