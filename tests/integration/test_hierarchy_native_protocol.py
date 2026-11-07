"""Public inert codec behavior; fake wire bytes never dispatch host controls."""
import json
from pathlib import Path
import importlib
import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def protocol():
    return importlib.import_module("tools.hierarchy_native_protocol")


def frame(value):
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


def turn(identifier="turn-1", **changes):
    return dict(id=identifier, items=[], status="inProgress", **changes)


def thread():
    return {"cliVersion": "0.166.0", "createdAt": 1, "updatedAt": 1, "cwd": "/fixture",
            "ephemeral": False, "id": "thread-1", "modelProvider": "openai",
            "preview": "", "projectId": None, "sessionId": "session-1",
            "source": "cli", "status": {"type": "idle"}, "turns": []}


def request(protocol, method="thread/read", **params):
    return protocol.prepare_request(method, {"threadId": "thread-1", **params}, 7)


def reply(result, identifier=7):
    return frame({"id": identifier, "result": result})


def test_public_metadata_decode_requires_pinned_nested_fields(protocol):
    prepared = request(protocol)
    result = protocol.interpret_response(prepared, reply({"thread": thread()}))
    assert result["state"] == "observed" and result["effect"] == "none"
    assert result["thread_id"] == "thread-1"
    assert result["ownership_authenticated"] is False
    assert result["native_qualified"] is False
    assert result["completion_proven"] is False
    value = thread()
    del value["sessionId"]
    assert protocol.interpret_response(prepared, reply({"thread": value}))["code"] == "INVALID_RESULT"


@pytest.mark.parametrize("method,params", [
    ("thread/read", {}), ("thread/turns/list", {"limit": 100, "itemsView": "full"}),
    ("thread/items/list", {"turnId": "turn-1", "limit": 1}),
    ("thread/resume", {"excludeTurns": True}),
    ("turn/start", {"input": [{"type": "text", "text": "inert"}], "clientUserMessageId": "intent-1"}),
    ("turn/interrupt", {"turnId": "turn-1"}),
])
def test_supported_preparations_are_inert_closed_jsonl(protocol, method, params):
    value = request(protocol, method, **params)
    assert value.endswith(b"\n") and value.count(b"\n") == 1
    decoded = json.loads(value)
    assert decoded == {"id": 7, "method": method, "params": {"threadId": "thread-1", **params}}


@pytest.mark.parametrize("key", ["model", "effort", "config", "approvalPolicy",
                               "approvalsReviewer", "sandboxPolicy", "baseInstructions",
                               "developerInstructions", "cwd", "disabledPluginIds",
                               "serviceTier", "outputSchema"])
def test_null_overrides_cannot_be_prepared(protocol, key):
    with pytest.raises(protocol.ProtocolError) as caught:
        request(protocol, "turn/start", input=[{"type": "text", "text": "x"}], **{key: None})
    assert caught.value.code == "UNSUPPORTED_PARAMETER"


@pytest.mark.parametrize("method", ["command/exec", "thread/start", "thread/fork", "unknown"])
def test_unreviewed_methods_are_refused(protocol, method):
    with pytest.raises(protocol.ProtocolError) as caught:
        request(protocol, method)
    assert caught.value.code == "UNSUPPORTED_METHOD"


@pytest.mark.parametrize("identifier", [True, False, -1, "", [], 1.0])
def test_request_id_exact_types_and_bounds(protocol, identifier):
    with pytest.raises(protocol.ProtocolError) as caught:
        protocol.prepare_request("thread/read", {"threadId": "thread-1"}, identifier)
    assert caught.value.code == "INVALID_REQUEST_ID"


def test_unsupported_version_has_no_wire_or_filesystem_effect(protocol, tmp_path):
    with pytest.raises(protocol.ProtocolError) as caught:
        protocol.prepare_request("thread/read", {"threadId": "thread-1"}, 7, version="0.999")
    assert caught.value.code == "UNSUPPORTED_VERSION"
    with pytest.raises(protocol.ProtocolError) as caught:
        protocol.verify_schema_bundle(tmp_path, version="0.999")
    assert caught.value.code == "UNSUPPORTED_VERSION"


@pytest.mark.parametrize("response_id", ["7", True, 8])
def test_start_wrong_rpc_id_preserves_possible_effect(protocol, response_id):
    prepared = request(protocol, "turn/start", input=[{"type": "text", "text": "x"}])
    result = protocol.interpret_response(prepared, reply({"turn": turn()}, response_id))
    assert (result["state"], result["effect"], result["code"]) == ("unknown", "possible", "WRONG_RESPONSE_ID")
    assert result["can_retry"] is False


def test_thread_and_reconnect_turn_mismatch_are_never_ownership(protocol):
    value = thread()
    value["id"] = "other"
    result = protocol.interpret_response(request(protocol), reply({"thread": value}))
    assert result["code"] == "WRONG_THREAD" and result["state"] == "invalid"
    prepared = request(protocol, "turn/start", input=[{"type": "text", "text": "x"}])
    result = protocol.interpret_response(prepared, reply({"turn": turn()}), expected_turn_id="other")
    assert result["code"] == "WRONG_TURN" and result["effect"] == "possible"


def test_start_ack_has_request_only_correlation_and_no_completion(protocol):
    prepared = request(protocol, "turn/start", input=[{"type": "text", "text": "x"}])
    result = protocol.interpret_response(prepared, reply({"turn": turn()}))
    assert result["state"] == "acknowledged" and result["effect"] == "possible"
    assert result["turn_id"] == "turn-1" and result["correlation"] == "request_id_only"
    assert not result["completion_proven"] and not result["can_retry"]


@pytest.mark.parametrize("method,result_body,extra", [
    ("turn/interrupt", {}, {"turnId": "turn-1"}),
    ("thread/resume", {"thread": thread(), "approvalPolicy": "on-request",
                       "approvalsReviewer": "auto_review", "cwd": "/fixture",
                       "model": "model", "modelProvider": "openai", "sandbox": {"type": "readOnly"}},
     {"excludeTurns": True}),
])
def test_effectful_ack_is_not_terminal_or_quiescent(protocol, method, result_body, extra):
    result = protocol.interpret_response(request(protocol, method, **extra), reply(result_body))
    assert (result["state"], result["effect"]) == ("acknowledged", "possible")
    assert not result["native_qualified"] and not result["ownership_authenticated"]
    assert not result["completion_proven"] and not result["can_retry"]


@pytest.mark.parametrize("error", ["timeout", "disconnected", "lost_reply"])
def test_transport_loss_never_retries_uncertain_start(protocol, error):
    prepared = request(protocol, "turn/start", input=[{"type": "text", "text": "x"}])
    before = prepared
    first = protocol.interpret_response(prepared, transport_error=error)
    second = protocol.interpret_response(prepared, transport_error=error)
    assert first == second and prepared == before
    assert (first["state"], first["effect"]) == ("unknown", "possible")
    assert first["code"] == "TRANSPORT_" + error.upper()
    assert not first["can_retry"]


@pytest.mark.parametrize("raw,code", [
    (b'{"id":7,"result":{}}', "TORN_FRAME"),
    (b'not-json\n', "INVALID_JSON"),
    (b'{"id":7,"id":7,"result":{}}\n', "DUPLICATE_KEY"),
    (b'{"id":7,"result":NaN}\n', "NONFINITE_NUMBER"),
    (b'{}\n{}\n', "MULTIPLE_FRAMES"),
    (b'\xff\n', "INVALID_UTF8"),
    (b'{"method":"item/tool/call","params":{"callId":"fake"}}\n', "NOT_A_RESPONSE"),
])
def test_malformed_effectful_reply_is_unknown(protocol, raw, code):
    prepared = request(protocol, "turn/interrupt", turnId="turn-1")
    result = protocol.interpret_response(prepared, raw)
    assert result["code"] == code and result["state"] == "unknown"
    assert result["effect"] == "possible" and not result["can_retry"]


def test_bounded_frames_and_depth(protocol):
    prepared = request(protocol, "turn/interrupt", turnId="turn-1")
    assert protocol.interpret_response(prepared, b"x" * (protocol.MAX_FRAME_BYTES + 1))["code"] == "FRAME_TOO_LARGE"
    raw = frame({"id": 7, "result": {"nested": [[[[0]]]]}})
    deep = b'{"id":7,"result":' + b'[' * 40 + b'0' + b']' * 40 + b'}\n'
    assert protocol.interpret_response(prepared, deep)["code"] == "MAX_DEPTH"
    assert protocol.interpret_response(prepared, raw)["state"] == "unknown"


@pytest.mark.parametrize("cursor,present,next_cursor,complete", [
    (None, True, None, True), (None, False, None, False),
    (None, True, "next", False), ("earlier", True, None, False),
])
def test_page_end_requires_root_and_explicit_null(protocol, cursor, present, next_cursor, complete):
    prepared = request(protocol, "thread/turns/list", cursor=cursor)
    body = {"data": [turn()]}
    if present:
        body["nextCursor"] = next_cursor
    result = protocol.interpret_response(prepared, reply(body))
    assert result["pagination_complete"] is complete
    assert not result["completion_proven"] and not result["ownership_authenticated"]


def test_item_page_turn_filter_and_required_nested_fields(protocol):
    prepared = request(protocol, "thread/items/list", turnId="turn-1")
    item = {"turnId": "other", "item": {"type": "userMessage", "id": "item-1",
                                       "content": [{"type": "text", "text": "inert"}]}}
    assert protocol.interpret_response(prepared, reply({"data": [item], "nextCursor": None}))["code"] == "WRONG_TURN"
    item["turnId"] = "turn-1"
    del item["item"]["id"]
    assert protocol.interpret_response(prepared, reply({"data": [item], "nextCursor": None}))["code"] == "INVALID_RESULT"


def test_remote_denial_does_not_prove_no_effect(protocol):
    prepared = request(protocol, "turn/start", input=[{"type": "text", "text": "x"}])
    result = protocol.interpret_response(prepared, frame({"id": 7, "error": {"code": -32000, "message": "denied"}}))
    assert (result["state"], result["effect"], result["code"]) == ("unknown", "possible", "REMOTE_ERROR")
    assert not result["can_retry"]


def test_mutated_preparation_is_revalidated_before_effect_classification(protocol):
    raw = frame({"id": 7, "method": "thread/read", "params": {"threadId": "thread-1", "model": None}})
    result = protocol.interpret_response(raw, reply({"thread": thread()}))
    assert (result["state"], result["effect"], result["code"]) == ("unknown", "possible", "INVALID_PREPARATION")


def test_missing_and_tampered_schema_fail_exactly(protocol, tmp_path):
    with pytest.raises(protocol.ProtocolError) as caught:
        protocol.verify_schema_bundle(tmp_path)
    assert caught.value.code == "SCHEMA_MISSING"
    path = tmp_path / "v2" / "ThreadReadParams.json"
    path.parent.mkdir()
    path.write_text("{}")
    with pytest.raises(protocol.ProtocolError) as caught:
        protocol.verify_schema_bundle(tmp_path)
    assert caught.value.code == "SCHEMA_HASH_MISMATCH"


def test_start_conflicting_client_correlation_preserves_unknown(protocol):
    prepared = request(protocol, "turn/start", input=[{"type": "text", "text": "x"}],
                       clientUserMessageId="intent-one")
    value = turn()
    value["items"] = [{"type": "userMessage", "id": "item-one", "clientId": "other-intent",
                       "content": [{"type": "text", "text": "x"}]}]
    result = protocol.interpret_response(prepared, reply({"turn": value}))
    assert (result["state"], result["effect"], result["code"]) == ("unknown", "possible", "WRONG_CLIENT_ID")


def test_malformed_schema_directory_and_nonregular_schema_fail_exactly(protocol, tmp_path):
    with pytest.raises(protocol.ProtocolError) as caught:
        protocol.verify_schema_bundle(None)
    assert caught.value.code == "SCHEMA_UNAVAILABLE"
    path = tmp_path / "v2" / "ThreadReadParams.json"
    path.mkdir(parents=True)
    with pytest.raises(protocol.ProtocolError) as caught:
        protocol.verify_schema_bundle(tmp_path)
    assert caught.value.code == "SCHEMA_NOT_REGULAR"


@pytest.mark.parametrize("method", ["thread/read", "thread/resume"])
@pytest.mark.parametrize("updated", ["missing", True, "1", None, 2 ** 63, -(2 ** 63) - 1])
def test_pinned_thread_updated_at_is_required_strict_int64(protocol, method, updated):
    value = thread()
    if updated == "missing":
        del value["updatedAt"]
    else:
        value["updatedAt"] = updated
    body = {"thread": value}
    if method == "thread/resume":
        body.update(approvalPolicy="on-request", approvalsReviewer="auto_review",
                    cwd="/fixture", model="model", modelProvider="openai", sandbox={"type": "readOnly"})
    result = protocol.interpret_response(request(protocol, method), reply(body))
    assert result["code"] == "INVALID_RESULT"
    assert result["state"] == ("invalid" if method == "thread/read" else "unknown")
