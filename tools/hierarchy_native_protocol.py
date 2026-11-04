#!/usr/bin/env python3
"""Inert, bounded Codex 0.166.0 wire subset; never a transport or authority."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import stat

VERSION = "0.166.0"
MAX_FRAME_BYTES = 1024 * 1024
MAX_SCHEMA_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 32
MAX_PAGE = 100
SCHEMA_PINS = {
    "v2/ThreadReadParams.json": "dfe040c6ac71d30795b8be3f3ff232e66f362a37f883b491e5d1ea367f470db4",
    "v2/ThreadReadResponse.json": "6eb05cf9bf73d9f873e782868189cd37dc393d12c7a7c49118adb9756b30c485",
    "v2/ThreadTurnsListParams.json": "2a8b93d7d4437cc25e16a1dde16d8db3c338d39e16c5eece2a56e943a21577d7",
    "v2/ThreadTurnsListResponse.json": "7953d842384fbc572c0b33f03c0fb1c6b746d3a3cc9c25302e6a03f9dce6d46a",
    "v2/ThreadItemsListParams.json": "d5cf9784413f1d1abba756e04e48b273a9d12ab2c5675442e91b6a4ee55e19f0",
    "v2/ThreadItemsListResponse.json": "5bcd27fa23f443b790dcae8d0045a700b4aff6025602b032cb2c558694c921e6",
    "v2/ThreadResumeParams.json": "8dceca415b2c16693b55658ea629cba5ffc82ac300dcd403db0ba7455e491496",
    "v2/ThreadResumeResponse.json": "2f8aa868ca008731622673d518b12f70ea8920eaf00fa5e80bfeb49cd8f2a77c",
    "v2/TurnStartParams.json": "49e53282f327c25e7b39d97afacd038ef10ad5c4fb0431608b354d3a7bf6bcea",
    "v2/TurnStartResponse.json": "85da8d16c86432da14440504ae1e76d13527058920d4ed81632dd50c3fbd054d",
    "v2/TurnInterruptParams.json": "6dff382dae73d1dbc58406ed045605f647e7a49660e2540fbd2c6c24d60c5f2b",
    "v2/CommandExecParams.json": "e4f20080b92c6199cf132941840c4bd0fb9a90e3fec197ceb0e1ce9084346e18",
    "v2/CommandExecTerminateParams.json": "979ece7059c6713d0909ab1690daec27149510f4ea2ec10014600bfb1d631c97",
}
PARAMETERS = {
    "thread/read": {"threadId", "includeTurns"},
    "thread/turns/list": {"threadId", "cursor", "limit", "itemsView", "sortDirection"},
    "thread/items/list": {"threadId", "turnId", "cursor", "limit", "sortDirection"},
    "thread/resume": {"threadId", "excludeTurns"},
    "turn/start": {"threadId", "input", "clientUserMessageId"},
    "turn/interrupt": {"threadId", "turnId"},
}
READ_ONLY = {"thread/read", "thread/turns/list", "thread/items/list"}


class ProtocolError(ValueError):
    """Stable public diagnostic code; not an execution refusal receipt."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _check(condition, code="INVALID_RESULT"):
    if not condition:
        raise ProtocolError(code)


def _string(value, maximum=8192, empty=False):
    return (isinstance(value, str) and (empty or bool(value))
            and len(value) <= maximum and "\x00" not in value)


def _int(value, minimum=-(2 ** 63), maximum=2 ** 63 - 1):
    return type(value) is int and minimum <= value <= maximum


def _object(value, required, allowed=None, code="INVALID_RESULT"):
    _check(isinstance(value, dict) and set(required) <= value.keys(), code)
    if allowed is not None:
        _check(value.keys() <= set(allowed), code)


def _list(value):
    _check(isinstance(value, list) and len(value) <= MAX_PAGE)


def _version(version):
    _check(version == VERSION, "UNSUPPORTED_VERSION")


def _request_id(value):
    _check((_string(value, 128) or _int(value, 0)), "INVALID_REQUEST_ID")


def _depth(value):
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        _check(depth <= MAX_DEPTH, "MAX_DEPTH")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, float):
            _check(math.isfinite(item), "NONFINITE_NUMBER")


def _parse(raw):
    _check(type(raw) is bytes, "INVALID_FRAME_TYPE")
    _check(len(raw) <= MAX_FRAME_BYTES, "FRAME_TOO_LARGE")
    _check(raw.endswith(b"\n"), "TORN_FRAME")
    _check(b"\n" not in raw[:-1], "MULTIPLE_FRAMES")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise ProtocolError("INVALID_UTF8") from exc

    def pairs(items):
        result = {}
        for key, value in items:
            _check(key not in result, "DUPLICATE_KEY")
            result[key] = value
        return result

    def nonfinite(_value):
        raise ProtocolError("NONFINITE_NUMBER")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)
    except RecursionError as exc:
        raise ProtocolError("MAX_DEPTH") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, ProtocolError):
            raise
        raise ProtocolError("INVALID_JSON") from exc
    _depth(value)
    return value


def _text_input(value):
    _object(value, {"type", "text"}, {"type", "text", "text_elements"})
    _check(value["type"] == "text" and _string(value["text"], empty=True))
    if "text_elements" in value:
        _check(value["text_elements"] == [])  # Deliberately narrow pinned subset.


def _validate_request(value):
    _object(value, {"id", "method", "params"}, {"id", "method", "params"}, "INVALID_REQUEST")
    _request_id(value["id"])
    method, params = value["method"], value["params"]
    _check(isinstance(method, str) and method in PARAMETERS, "UNSUPPORTED_METHOD")
    _object(params, {"threadId"}, code="INVALID_PARAMETER")
    _check(params.keys() <= PARAMETERS[method], "UNSUPPORTED_PARAMETER")
    _check(_string(params["threadId"], 256), "INVALID_PARAMETER")
    for key in ("turnId", "clientUserMessageId"):
        if key in params:
            _check(_string(params[key], 256), "INVALID_PARAMETER")
    if method == "turn/interrupt":
        _check("turnId" in params, "INVALID_PARAMETER")
    if "includeTurns" in params:
        _check(params["includeTurns"] is False, "INVALID_PARAMETER")
    if "excludeTurns" in params:
        _check(params["excludeTurns"] is True, "INVALID_PARAMETER")
    if "cursor" in params:
        _check(params["cursor"] is None or _string(params["cursor"], 4096), "INVALID_PARAMETER")
    if "limit" in params:
        _check(_int(params["limit"], 1, MAX_PAGE), "INVALID_PARAMETER")
    if "itemsView" in params:
        _check(params["itemsView"] == "full", "INVALID_PARAMETER")
    if "sortDirection" in params:
        _check(params["sortDirection"] in ("asc", "desc"), "INVALID_PARAMETER")
    if method == "turn/start":
        _check(isinstance(params.get("input"), list) and len(params["input"]) == 1, "INVALID_PARAMETER")
        try:
            _text_input(params["input"][0])
        except ProtocolError as exc:
            raise ProtocolError("INVALID_PARAMETER") from exc
    _depth(value)
    return value


def prepare_request(method, params, request_id, *, version=VERSION):
    """Prepare inert JSONL bytes. No call, session, intent or grant is created."""
    _version(version)
    value = _validate_request({"id": request_id, "method": method, "params": params})
    try:
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False) + "\n").encode()
    except (ValueError, TypeError, RecursionError) as exc:
        raise ProtocolError("INVALID_PARAMETER") from exc
    _check(len(raw) <= MAX_FRAME_BYTES, "FRAME_TOO_LARGE")
    return raw


def _item(value):
    _object(value, {"id", "type"})
    _check(_string(value["id"], 256))
    if value["type"] == "userMessage":
        _object(value, {"content"})
        _list(value["content"])
        for item in value["content"]:
            _text_input(item)
        if "clientId" in value:
            _check(value["clientId"] is None or _string(value["clientId"], 256))
    elif value["type"] == "agentMessage":
        _object(value, {"text"})
        _check(_string(value["text"], empty=True))
    else:
        # A valid host variant outside this reviewed subset is not decoded.
        raise ProtocolError("UNSUPPORTED_RESULT_VARIANT")


def _turn(value):
    _object(value, {"id", "items", "status"})
    _check(_string(value["id"], 256))
    _check(value["status"] in ("completed", "interrupted", "failed", "inProgress"))
    _list(value["items"])
    for item in value["items"]:
        _item(item)


def _thread(value):
    required = {"cliVersion", "createdAt", "cwd", "ephemeral", "id", "modelProvider",
                "preview", "projectId", "sessionId", "source", "status", "turns", "updatedAt"}
    _object(value, required)
    for key in ("cliVersion", "cwd", "id", "modelProvider", "sessionId"):
        _check(_string(value[key]))
    _check(_string(value["preview"], empty=True) and _int(value["createdAt"])
           and _int(value["updatedAt"]))
    _check(type(value["ephemeral"]) is bool)
    _check(value["projectId"] is None or _string(value["projectId"]))
    _check(value["source"] in ("cli", "vscode", "exec", "appServer", "unknown"))
    status = value["status"]
    _object(status, {"type"})
    _check(status["type"] in ("idle", "notLoaded", "systemError", "active"))
    if status["type"] == "active":
        _object(status, {"activeFlags"})
        _list(status["activeFlags"])
        _check(all(flag in ("waitingOnApproval", "waitingOnUserInput") for flag in status["activeFlags"]))
    _list(value["turns"])
    for item in value["turns"]:
        _turn(item)


def _result(value, request, expected_turn_id):
    method, params = request["method"], request["params"]
    _object(value, set())
    if method in ("thread/read", "thread/resume"):
        _object(value, {"thread"})
        _thread(value["thread"])
        _check(value["thread"]["id"] == params["threadId"], "WRONG_THREAD")
        if method == "thread/resume":
            _object(value, {"approvalPolicy", "approvalsReviewer", "cwd", "model", "modelProvider", "sandbox"})
            _check(value["approvalPolicy"] in ("untrusted", "on-request", "never"))
            _check(value["approvalsReviewer"] in ("user", "auto_review", "guardian_subagent"))
            _check(all(_string(value[key]) for key in ("cwd", "model", "modelProvider")))
            _object(value["sandbox"], {"type"})
            _check(value["sandbox"]["type"] == "readOnly", "UNSUPPORTED_RESULT_VARIANT")
            if "networkAccess" in value["sandbox"]:
                _check(type(value["sandbox"]["networkAccess"]) is bool)
    elif method in ("thread/turns/list", "thread/items/list"):
        _object(value, {"data"})
        _list(value["data"])
        for key in ("nextCursor", "backwardsCursor"):
            if key in value:
                _check(value[key] is None or _string(value[key], 4096))
        for entry in value["data"]:
            if method == "thread/turns/list":
                _turn(entry)
            else:
                _object(entry, {"item", "turnId"})
                _check(_string(entry["turnId"], 256))
                _item(entry["item"])
                if "turnId" in params:
                    _check(entry["turnId"] == params["turnId"], "WRONG_TURN")
    elif method == "turn/start":
        _object(value, {"turn"})
        _turn(value["turn"])
        if expected_turn_id is not None:
            _check(value["turn"]["id"] == expected_turn_id, "WRONG_TURN")
        if "clientUserMessageId" in params:
            for item in value["turn"]["items"]:
                if item["type"] == "userMessage" and item.get("clientId") is not None:
                    _check(item["clientId"] == params["clientUserMessageId"], "WRONG_CLIENT_ID")
    else:
        _check(value == {})


def interpret_response(prepared_request, response_bytes=None, *, transport_error=None,
                       expected_turn_id=None):
    """Interpret inert bytes only; even an ACK proves no ownership/completion."""
    answer = {"state": "unknown", "effect": "possible", "code": "INVALID_PREPARATION",
              "request_id": None, "method": None, "thread_id": None, "turn_id": None,
              "correlation": "unverified", "pagination_complete": False,
              "native_qualified": False, "ownership_authenticated": False,
              "completion_proven": False, "can_retry": False}
    try:
        request = _validate_request(_parse(prepared_request))
    except ProtocolError:
        # Untrusted preparation cannot relabel an uncertain effect as read-only.
        return answer
    method, params = request["method"], request["params"]
    effectful = method not in READ_ONLY
    answer.update(request_id=request["id"], method=method, thread_id=params["threadId"],
                  state="unknown" if effectful else "invalid",
                  effect="possible" if effectful else "none")
    try:
        if expected_turn_id is not None:
            _check(_string(expected_turn_id, 256), "INVALID_EXPECTED_TURN")
        if transport_error is not None:
            _check(response_bytes is None, "AMBIGUOUS_TRANSPORT_INPUT")
            _check(transport_error in ("timeout", "disconnected", "lost_reply"), "INVALID_TRANSPORT_ERROR")
            raise ProtocolError("TRANSPORT_" + transport_error.upper())
        _check(response_bytes is not None, "MISSING_RESPONSE")
        response = _parse(response_bytes)
        _object(response, {"id"}, {"id", "result", "error"}, "NOT_A_RESPONSE")
        _check(type(response["id"]) is type(request["id"]) and response["id"] == request["id"],
               "WRONG_RESPONSE_ID")
        _check(("result" in response) != ("error" in response), "NOT_A_RESPONSE")
        if "error" in response:
            _object(response["error"], {"code", "message"})
            _check(type(response["error"]["code"]) is int and _string(response["error"]["message"], empty=True))
            answer["error"] = response["error"]
            raise ProtocolError("REMOTE_ERROR")
        value = response["result"]
        _result(value, request, expected_turn_id)
        answer.update(state="acknowledged" if effectful else "observed", code="OK", result=value,
                      correlation="thread_id" if method in ("thread/read", "thread/resume")
                      else "request_id_only")
        if method == "turn/start":
            answer["turn_id"] = value["turn"]["id"]
        elif method == "turn/interrupt":
            answer["turn_id"] = params["turnId"]  # Request provenance only.
        if method in ("thread/turns/list", "thread/items/list"):
            answer["pagination_complete"] = (params.get("cursor") is None
                                               and "nextCursor" in value and value["nextCursor"] is None)
    except ProtocolError as exc:
        answer["code"] = exc.code
    return answer


def verify_schema_bundle(directory, version=VERSION):
    """Verify exact retained bytes. No schema interpretation authenticates a host."""
    _version(version)
    try:
        root = Path(directory)
    except (TypeError, ValueError) as exc:
        raise ProtocolError("SCHEMA_UNAVAILABLE") from exc
    for relative, wanted in SCHEMA_PINS.items():
        path = root / relative
        try:
            for parent in (root, path.parent):
                _check(not parent.is_symlink(), "SCHEMA_NOT_REGULAR")
            observed = path.lstat()
            _check(stat.S_ISREG(observed.st_mode), "SCHEMA_NOT_REGULAR")
            _check(observed.st_size <= MAX_SCHEMA_BYTES, "SCHEMA_TOO_LARGE")
            descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                                 | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(descriptor, "rb") as stream:
                opened = os.fstat(stream.fileno())
                _check(stat.S_ISREG(opened.st_mode), "SCHEMA_NOT_REGULAR")
                _check((opened.st_dev, opened.st_ino) == (observed.st_dev, observed.st_ino),
                       "SCHEMA_CHANGED")
                raw = stream.read(MAX_SCHEMA_BYTES + 1)
            _check(len(raw) <= MAX_SCHEMA_BYTES, "SCHEMA_TOO_LARGE")
        except FileNotFoundError as exc:
            raise ProtocolError("SCHEMA_MISSING") from exc
        except OSError as exc:
            raise ProtocolError("SCHEMA_UNAVAILABLE") from exc
        _check(hashlib.sha256(raw).hexdigest() == wanted, "SCHEMA_HASH_MISMATCH")
    return {"version": VERSION, "pins": dict(SCHEMA_PINS), "verified": True,
            "native_qualified": False, "ownership_authenticated": False}
