"""Restricted roles can use the file protocol without general write/shell tools."""
import ast
import json
import hashlib
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading

import pytest

from tests.integration.test_hierarchy_mailbox import HELPER, invoke, message, pilot  # noqa: F401
from tests.integration.test_hierarchy_mailbox import (
    INBOX_WIRE_BUDGET, WIRE_PAYLOADS, checkpoint_wire_binding, corrupt_wire_fixture,
    mailbox_snapshot, record_wire_process, seed_wire_inbox, wire_peer_mailbox,
)

sys.path.insert(0, str(HELPER.parent))
from hierarchy_mailbox import GIT_ID, MESSAGE_TYPES, STAGES  # noqa: E402


def exchange(root, calls=(), *, endpoint="a/lane/review", session=None, host="host-one", generation=1, raw=None,
             delivery=None):
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    frames.extend({"jsonrpc": "2.0", "id": index + 3, "method": "tools/call", "params": {
        "name": name, "arguments": arguments}} for index, (name, arguments) in enumerate(calls))
    receipts = [] if delivery is None else ["--delivery-dir", str(delivery)]
    result = subprocess.run([sys.executable, "-I", str(HELPER), "--root", str(root), "serve",
                             "--endpoint", endpoint, "--host", host, "--session", session or endpoint,
                             "--generation", str(generation), *receipts],
                            input=raw or "".join(json.dumps(f) + "\n" for f in frames),
                            capture_output=True, text=True, timeout=15,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert not result.stderr
    return [json.loads(line) for line in result.stdout.splitlines()]


def payload(response):
    return json.loads(response["result"]["content"][0]["text"])


@pytest.mark.parametrize("boundary", ["current", "foreign", "generation", "busy", "broken"])
def test_receipt_freshness_mcp_flush_boundary(tmp_path, boundary):
    from tests.integration.test_hierarchy_mailbox import receipt_boundary_case
    result, root, delivery, observed = receipt_boundary_case(tmp_path, "mcp", boundary)
    if boundary == "broken":
        assert observed == {"broken_pipe": True}
        assert result.stdout == "" and result.stderr == ""
    else:
        assert observed["page_flushed"] is True
        response = json.loads(result.stdout)
        assert response["id"] == "receipt-page"
        assert [r["message"]["message_id"] for r in payload(response)["messages"]] == ["receipt-note"]
    state = invoke(root, "delivery", delivery_dir=delivery, message_id="receipt-note")["message"]
    if boundary == "current":
        assert result.stderr == ""
        assert state["state"] == "read" and state["read_by"]["generation"] == 1
    else:
        assert state["state"] == "published" and state["read_at"] is None
        assert not list(delivery.glob("reads/**/*.json"))
        if boundary != "broken":
            expected = ("mailbox writer is busy; inspect an abandoned lock before retrying"
                        if boundary == "busy" else "stale or mismatched sender binding")
            assert result.stderr == "read receipt not recorded: " + expected + "\n"


def test_transport_advertises_only_scoped_mailbox_tools(pilot):  # noqa: F811
    root, _ = pilot
    responses = exchange(root)
    assert responses[0]["result"]["serverInfo"]["name"] == "aegis-hierarchy-mailbox"
    tools = {t["name"]: t for t in responses[1]["result"]["tools"]}
    assert set(tools) == {"mailbox_inbox", "mailbox_publish", "mailbox_ack_handoff", "mailbox_self"}
    assert tools["mailbox_inbox"]["annotations"]["readOnlyHint"] is True
    assert tools["mailbox_publish"]["annotations"]["readOnlyHint"] is False
    assert all(t["inputSchema"]["additionalProperties"] is False for t in tools.values())
    assert not {"from", "host", "session", "binding_generation", "root"} & set(
        tools["mailbox_publish"]["inputSchema"]["properties"])


# The publish schema teaches what the pinned validator in hierarchy_mailbox.py checks. That file is pinned, so the
# expectations below are parsed from its own source and constants; a validator change fails here, not in a live run.


def validator(name):
    tree = ast.parse(HELPER.read_text(encoding="utf-8"))
    [mailbox] = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Mailbox"]
    [function] = [node for node in mailbox.body if isinstance(node, ast.FunctionDef) and node.name == name]
    return function


def strings(node):
    return {element.value for element in node.elts}


def field_sets(function, subject):
    """The key sets the validator passes to fields(<subject>, required[, optional])."""
    for node in ast.walk(function):
        if (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "fields"
                and getattr(node.args[0], "id", None) == subject):
            return [strings(argument) for argument in node.args[1:]]
    raise AssertionError("no fields(%s, ...) in %s" % (subject, function.name))


def keyed(node, key):
    return isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and node.slice.value == key


def allowed(function, key):
    """The set literal that <value>[key] is checked to be in."""
    for node in ast.walk(function):
        if (isinstance(node, ast.Compare) and keyed(node.left, key) and isinstance(node.ops[0], ast.In)
                and isinstance(node.comparators[0], ast.Set)):
            return strings(node.comparators[0])
    raise AssertionError("no %s membership check in %s" % (key, function.name))


def git_id_keys(function):
    return {node.args[0].slice.value for node in ast.walk(function)
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "matching"
            and isinstance(node.args[0], ast.Subscript) and getattr(node.args[1], "id", None) == "GIT_ID"}


def fullmatch_pattern(function, key):
    for node in ast.walk(function):
        if (isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "fullmatch" and len(node.args) > 1
                and keyed(node.args[1], key)):
            return node.args[0].value
    raise AssertionError("no fullmatch on %s in %s" % (key, function.name))


def length_bounds(function, key):
    """(minimum, maximum) from a `lower < len(<value>[key]) <= upper` check."""
    for node in ast.walk(function):
        if (isinstance(node, ast.Compare) and len(node.comparators) == 2 and isinstance(node.comparators[0], ast.Call)
                and getattr(node.comparators[0].func, "id", None) == "len" and keyed(node.comparators[0].args[0], key)):
            assert isinstance(node.ops[0], ast.Lt) and isinstance(node.ops[1], ast.LtE)
            return node.left.value + 1, node.comparators[1].value
    raise AssertionError("no length check on %s in %s" % (key, function.name))


def publish_tool(root):
    return {tool["name"]: tool for tool in exchange(root)[1]["result"]["tools"]}["mailbox_publish"]


def test_publish_types_readiness_exactly_as_the_pinned_validator_checks_it(pilot):  # noqa: F811
    root, _ = pilot
    schema = publish_tool(root)["inputSchema"]["properties"]["readiness"]
    function = validator("readiness")
    [required] = field_sets(function, "readiness")
    assert schema["type"] == "object" and schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"]) == required
    assert set(schema["properties"]["enforcement_tier"]["enum"]) == allowed(function, "enforcement_tier")
    assert git_id_keys(function) == {"base_revision", "lease_oid"}
    for key in git_id_keys(function):
        assert schema["properties"][key]["pattern"] == "^%s$" % GIT_ID.pattern, key
    assert schema["properties"]["lease_ref"]["pattern"] == "^%s$" % fullmatch_pattern(function, "lease_ref")
    assert schema["properties"]["owned_paths"]["type"] == "array" and schema["properties"]["owned_paths"]["minItems"] == 1


def test_publish_types_the_result_exactly_as_the_pinned_validator_checks_it(pilot):  # noqa: F811
    root, _ = pilot
    schema = publish_tool(root)["inputSchema"]["properties"]["result"]
    function = validator("completion")
    required, optional = field_sets(function, "result")
    assert schema["type"] == "object" and schema["additionalProperties"] is False
    assert set(schema["required"]) == required and set(schema["properties"]) == required | optional
    for key in git_id_keys(function):
        assert schema["properties"][key]["pattern"] == "^%s$" % GIT_ID.pattern, key
    checks = schema["properties"]["checks"]
    assert (checks["minItems"], checks["maxItems"]) == length_bounds(function, "checks")
    [check_keys] = field_sets(function, "check")
    items = checks["items"]
    assert set(items["required"]) == set(items["properties"]) == check_keys and items["additionalProperties"] is False
    assert set(items["properties"]["outcome"]["enum"]) == allowed(function, "outcome")
    assert "reviewer" in schema["properties"]["lane_check"]["description"]


def test_publish_type_and_stage_enums_are_the_mailbox_constants(pilot):  # noqa: F811
    root, _ = pilot
    properties = publish_tool(root)["inputSchema"]["properties"]
    assert set(properties["type"]["enum"]) == MESSAGE_TYPES
    assert set(properties["acknowledgment"]["enum"]) == STAGES


def test_publish_teaches_the_order_accept_then_report_and_fix_only_the_named_field(pilot):  # noqa: F811
    root, _ = pilot
    description = publish_tool(root)["description"]
    assert description.startswith("Publish information under the configured sender; grants no approval or verified "
                                  "completion.")
    first, second, third = (description.index(step) for step in ("1. ", "2. ", "3. "))
    assert first < second < third
    accept, report, refusal = description[first:second], description[second:third], description[third:]
    assert "ack" in accept and "accepted" in accept and "in reply to the dispatch" in accept and "readiness" in accept
    assert "result" in report and "review" in report
    assert "refusal" in refusal and "never re-send unchanged" in refusal


def test_a_typed_publish_still_accepts_the_reviewers_two_messages(pilot):  # noqa: F811
    """The schema is advice for the model; the pinned validator stays the check, so a reviewer's bare ack and a
    result without lane_check publish as before."""
    root, brief = pilot
    invoke(root, "publish", message(recipient="a/lane/review", kind="dispatch", brief=brief))
    evidence = {"source_revision": "a" * 40, "source_tree": "b" * 40,
                "checks": [{"check": "independent-review", "outcome": "not_run", "reference": "review/findings.md"}]}
    responses = exchange(root, [
        ("mailbox_publish", {"message_id": "review-accepted", "to": "a/orchestrator", "type": "ack", "body": "Accepted",
                             "in_reply_to": "dispatch-1", "acknowledgment": "accepted"}),
        ("mailbox_publish", {"message_id": "review-result", "to": "a/orchestrator", "type": "result",
                             "body": "verdict in body", "in_reply_to": "dispatch-1", "result": evidence})])
    assert [response["result"].get("isError", False) for response in responses[2:]] == [False, False]


def test_reviewer_reads_its_brief_and_reports_without_source_write_tools(pilot):  # noqa: F811
    root, brief = pilot
    invoke(root, "publish", message(recipient="a/lane/review", kind="dispatch", brief=brief))
    invoke(root, "publish", message(identifier="another-recipient"))
    evidence = {"source_revision": "a" * 40, "source_tree": "b" * 40,
                "checks": [{"check": "independent-review", "outcome": "pass", "reference": "review/findings.md"}]}
    responses = exchange(root, [
        ("mailbox_inbox", {"include_briefs": True}),
        ("mailbox_publish", {"message_id": "review-accepted", "to": "a/orchestrator", "type": "ack", "body": "Accepted",
                             "in_reply_to": "dispatch-1", "acknowledgment": "accepted"}),
        ("mailbox_publish", {"message_id": "review-result", "to": "a/orchestrator", "type": "review", "body": "SHIP recommendation",
                             "in_reply_to": "dispatch-1", "result": evidence}),
    ])
    inbox = payload(responses[2])
    assert [r["message"]["message_id"] for r in inbox["messages"]] == ["dispatch-1"]
    assert inbox["messages"][0]["brief_text"].startswith("Goal: improve diagnostics.")
    result = payload(responses[-1])
    assert result["message"]["from"] == "a/lane/review"
    assert result["message"]["verification"]["human_approval"] == "not_established"
    assert result["path"].endswith(".md")


@pytest.mark.parametrize("field", ["from", "host", "session", "binding_generation", "root", "approved"])
def test_tool_arguments_cannot_override_startup_identity_or_authority(pilot, field):  # noqa: F811
    root, _ = pilot
    request = {"message_id": "forged", "to": "a/orchestrator", "type": "info", "body": "data", field: "forged"}
    response = exchange(root, [("mailbox_publish", request)])[-1]
    assert response["result"]["isError"] is True
    assert "unexpected fields" in payload(response)["error"]
    assert list(root.glob("**/*.md")) == []


def test_successor_can_acknowledge_before_becoming_ready(pilot):  # noqa: F811
    root, brief = pilot
    checkpoint = {"outgoing_stopped": True, "briefs": [brief], "sources": [], "lease_refs": [],
                  "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}
    binding = invoke(root, "bind", {"endpoint": "a/lane/review", "host": "host-two", "session": "replacement",
                                   "expected_generation": 1, "checkpoint": checkpoint})
    own = payload(exchange(root, [("mailbox_inbox", {"include_briefs": True})],
                           host="host-two", session="replacement", generation=2)[-1])
    assert own["binding"]["checkpoint"] == checkpoint
    assert own["binding"]["ready"] is False
    assert own["checkpoint_briefs"][0]["text"] == Path(brief["path"]).read_text()
    responses = exchange(root, [("mailbox_ack_handoff", {"checkpoint_sha256": own["binding"]["checkpoint_sha256"]})],
                         host="host-two", session="replacement", generation=2)
    assert payload(responses[-1])["ready"] is True
    assert own["binding"]["checkpoint_sha256"] == binding["checkpoint_sha256"]


def test_binding_only_inbox_returns_no_messages_and_records_no_read(pilot):  # noqa: F811
    root, _ = pilot
    invoke(root, "publish", message(recipient="a/lane/review"))
    delivery = root.parent / "delivery"
    view = payload(exchange(root, [("mailbox_inbox", {"binding_only": True})], delivery=delivery)[-1])
    assert view == {"endpoint": "a/lane/review", "binding": invoke(root, "status")["bindings"]["a/lane/review"],
                    "checkpoint_briefs": [], "messages_total": 1}
    assert not (delivery / "reads").exists()
    page = payload(exchange(root, [("mailbox_inbox", {})], delivery=delivery)[-1])
    assert [row["message"]["message_id"] for row in page["messages"]] == ["dispatch-1"]
    assert len(list((delivery / "reads" / "a/lane/review").iterdir())) == 1  # The control: a real page is recorded.


@pytest.mark.parametrize("arguments,error", [
    ({"binding_only": "yes"}, "binding_only must be boolean"),
    ({"binding_only": True, "include_briefs": False}, "binding_only takes no include_briefs, limit or after_message_id"),
    ({"binding_only": True, "limit": 5}, "binding_only takes no include_briefs, limit or after_message_id"),
])
def test_binding_only_inbox_refuses_other_arguments(pilot, arguments, error):  # noqa: F811
    root, _ = pilot
    response = exchange(root, [("mailbox_inbox", arguments)])[-1]
    assert response["result"]["isError"] is True
    assert payload(response) == {"error": error}


def test_malformed_frame_is_explicit_and_next_request_still_works(pilot):  # noqa: F811
    root, _ = pilot
    raw = '{"jsonrpc":"2.0","id":1,"id":2}\n' + json.dumps({"jsonrpc": "2.0", "id": 3, "method": "ping"}) + "\n"
    responses = exchange(root, raw=raw)
    assert responses[0]["error"]["code"] == -32700
    assert "duplicate JSON key" in responses[0]["error"]["message"]
    assert responses[1] == {"jsonrpc": "2.0", "id": 3, "result": {}}


def test_running_adapter_rejects_replaced_sender_and_changed_manifest(pilot):  # noqa: F811
    root, brief = pilot
    seed_wire_inbox(root, "x" * 262144, endpoint="a/lane/review")
    process = subprocess.Popen([sys.executable, "-I", str(HELPER), "--root", str(root), "serve",
                                "--endpoint", "a/lane/review", "--host", "host-one", "--session", "a/lane/review",
                                "--generation", "1"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    def call(identifier, method, params=None):
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params or {}}) + "\n")
        process.stdin.flush()
        response = queue.Queue()
        threading.Thread(target=lambda: response.put(process.stdout.readline()), daemon=True).start()
        return json.loads(response.get(timeout=5))

    try:
        assert call(1, "initialize")["result"]["serverInfo"]["name"] == "aegis-hierarchy-mailbox"
        checkpoint = {"outgoing_stopped": True, "briefs": [brief], "sources": [], "lease_refs": [],
                      "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}
        invoke(root, "bind", {"endpoint": "a/lane/review", "host": "host-two", "session": "successor",
                              "expected_generation": 1, "checkpoint": checkpoint})
        before = mailbox_snapshot(root)
        response = call("stale-inbox", "tools/call", {"name": "mailbox_inbox", "arguments": {"include_briefs": True}})
        assert response["result"]["isError"] is True
        assert payload(response) == {"error": "stale or mismatched sender binding"}
        response = call(2, "tools/call", {"name": "mailbox_publish", "arguments": {
            "message_id": "stale", "to": "a/orchestrator", "type": "info", "body": "stale sender"}})
        assert payload(response)["error"] == "stale or mismatched sender binding"
        assert mailbox_snapshot(root) == before
        manifest_path = root / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["writer_limit"] = 2
        manifest_path.write_text(json.dumps(manifest))
        response = call(3, "tools/call", {"name": "mailbox_inbox", "arguments": {}})
        assert payload(response)["error"] == "mailbox manifest changed since server startup"
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        assert not process.stderr.read()


def test_scoped_adapter_does_not_write_python_cache_in_source_checkout(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    source = tmp_path / "source-copy"
    source.mkdir()
    for name in ("hierarchy_mailbox.py", "hierarchy_mailbox_mcp.py"):
        (source / name).write_bytes((HELPER.parent / name).read_bytes())
    argv = [sys.executable, "-I", str(source / HELPER.name), "--root", str(root), "serve", "--endpoint", "a/lane/review",
            "--host", "host-one", "--session", "a/lane/review", "--generation", "1"]
    frame = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n"
    result = subprocess.run(argv, input=frame, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["result"]["serverInfo"]["name"] == "aegis-hierarchy-mailbox"
    assert sorted(p.name for p in source.iterdir()) == ["hierarchy_mailbox.py", "hierarchy_mailbox_mcp.py"]


def test_oversized_frame_closes_without_parsing_fragments(pilot):  # noqa: F811
    root, _ = pilot
    responses = exchange(root, raw="x" * 262145 + "\n" + json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"}) + "\n")
    assert responses == [{"jsonrpc": "2.0", "id": None, "error": {
        "code": -32700, "message": "mailbox frame exceeds 262144 bytes"}}]


def test_locked_mailbox_refuses_mutation_without_partial_files(pilot):  # noqa: F811
    root, _ = pilot
    (root / ".write.lock").write_text("fixture active writer")
    response = exchange(root, [("mailbox_publish", {"message_id": "busy", "to": "a/orchestrator",
                                                   "type": "info", "body": "data"})])[-1]
    assert "writer is busy" in payload(response)["error"]
    assert list(root.glob("**/*.md")) == []


def test_front_door_authors_hash_bound_brief_using_only_scoped_tools(pilot):  # noqa: F811
    root, _ = pilot
    intent = {"message_id": "intent-file", "to": "a/orchestrator", "type": "info",
              "body": "Goal: improve diagnostics.\nAcceptance: retain conservative overlap evidence.\n"}
    created = payload(exchange(root, [("mailbox_publish", intent)], endpoint="a/front-door")[-1])
    assert hashlib.sha256(Path(created["path"]).read_bytes()).hexdigest() == created["sha256"]
    reference = {"path": created["path"], "sha256": created["sha256"]}
    handed_off = {"message_id": "intent-handoff", "to": "a/orchestrator", "type": "brief",
                  "body": "Use this immutable hierarchy brief.", "brief": reference}
    result = payload(exchange(root, [("mailbox_publish", handed_off)], endpoint="a/front-door")[-1])
    assert result["message"]["brief"] == reference
    inbox = payload(exchange(root, [("mailbox_inbox", {"include_briefs": True})], endpoint="a/orchestrator")[-1])
    delivered = next(r for r in inbox["messages"] if r["message"]["message_id"] == "intent-handoff")
    assert intent["body"] in delivered["brief_text"]


def mcp_wire_exchange(root, frames=(), *, endpoint="a/lane/f2", host="host-one", session=None, generation=1, raw=None):
    initialization = {"jsonrpc": "2.0", "id": "init", "method": "initialize", "params": {}}
    prefix = (json.dumps(initialization) + "\n").encode("utf-8")
    if raw is None:
        lines = [(json.dumps(frame, ensure_ascii=False) + "\n").encode("utf-8") for frame in frames]
        assert all(len(line) <= 262144 for line in lines), "fixtures must remain valid input frames"
        raw = b"".join(lines)
    argv = [sys.executable, "-I", str(HELPER), "--root", str(root), "serve",
            "--endpoint", endpoint, "--host", host, "--session", session or endpoint,
            "--generation", str(generation)]
    result = subprocess.run(argv, input=prefix + raw, capture_output=True, timeout=15,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    evidence = record_wire_process(root, argv, result, stdin=prefix + raw)
    assert result.returncode == 0, (str(evidence), result.stdout[:2048], result.stderr[:2048])
    assert result.stderr == b""
    lines = result.stdout.splitlines(keepends=True)
    assert all(line.endswith(b"\n") for line in lines)
    responses = [json.loads(line.decode("utf-8")) for line in lines]
    assert responses[0]["id"] == "init"
    assert responses[0]["result"]["serverInfo"]["name"] == "aegis-hierarchy-mailbox"
    return lines[1:], responses[1:]


def inbox_frame(arguments, identifier="inbox"):
    return {"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
            "params": {"name": "mailbox_inbox", "arguments": arguments}}


def mcp_inbox_wire(root, arguments, *, identifier="inbox", **identity):
    raw, responses = mcp_wire_exchange(root, [inbox_frame(arguments, identifier),
                                           {"jsonrpc": "2.0", "id": "after-inbox", "method": "ping"}], **identity)
    assert len(responses) == 2
    assert responses[0]["id"] == identifier
    assert responses[1] == {"jsonrpc": "2.0", "id": "after-inbox", "result": {}}
    return raw[0], responses[0]


@pytest.mark.parametrize("content", WIRE_PAYLOADS)
def test_mcp_bounded_inbox_wire_pages_are_lossless(pilot, content):  # noqa: F811
    root, _ = pilot
    expected = seed_wire_inbox(root, content)
    binding = invoke(root, "status")["bindings"]["a/lane/f2"]
    before = mailbox_snapshot(root)
    received, cursor = [], None
    identifier = 'é"\\\n😀' * 2048  # Accepted request ID contributes to the real outer frame.
    for page_number in range(len(expected) + 1):
        arguments = {"include_briefs": True}
        if cursor is not None:
            arguments["after_message_id"] = cursor
        raw, response = mcp_inbox_wire(root, arguments, identifier=identifier)
        assert len(raw) <= INBOX_WIRE_BUDGET, "MCP outer-frame budget exceeded; raw evidence: " + str(root.parent / "wire-evidence")
        assert response["result"].get("isError", False) is False
        page = payload(response)
        assert page["binding"] == binding
        assert page["endpoint"] == "a/lane/f2"
        assert page["checkpoint_briefs"] == []
        assert page["messages"], "nonempty eligible history must make cursor progress"
        end = len(received) + len(page["messages"])
        assert page["messages"] == expected[len(received):end]
        received.extend(page["messages"])
        assert page["remaining"] == len(expected) - len(received)
        if page_number == 0:
            assert 0 < len(page["messages"]) < 20
        if not page["remaining"]:
            assert page["next_after"] is None
            break
        assert page["next_after"] == received[-1]["message"]["message_id"]
        assert page["next_after"] != cursor
        cursor = page["next_after"]
    assert received == expected
    for limit in (1, 100):
        raw, response = mcp_inbox_wire(root, {"limit": limit})
        assert len(raw) <= INBOX_WIRE_BUDGET
        page = payload(response)
        count = min(limit, len(expected))
        assert page["messages"] == [{"path": r["path"], "message": r["message"]} for r in expected[:count]]
        assert page["remaining"] == len(expected) - count
        assert page["next_after"] == (expected[count - 1]["message"]["message_id"] if page["remaining"] else None)
    raw, response = mcp_inbox_wire(root, {"include_briefs": True,
                                         "after_message_id": expected[-1]["message"]["message_id"]})
    assert len(raw) <= INBOX_WIRE_BUDGET
    assert payload(response) == {"endpoint": "a/lane/f2", "binding": binding, "checkpoint_briefs": [],
                                 "messages": [], "remaining": 0, "next_after": None}
    assert mailbox_snapshot(root) == before


def test_mcp_bounded_inbox_checkpoint_metadata_is_mandatory(pilot):  # noqa: F811
    root, _ = pilot
    binding = checkpoint_wire_binding(root, "x" * 262144, 20)
    identity = {"host": "host-two", "session": "replacement", "generation": 2}
    before = mailbox_snapshot(root)
    raw, response = mcp_inbox_wire(root, {"include_briefs": True}, **identity)
    assert len(raw) <= INBOX_WIRE_BUDGET
    assert response["result"]["isError"] is True
    assert payload(response) == {"error": "inbox response metadata exceeds 4194304 bytes"}
    raw, response = mcp_inbox_wire(root, {}, **identity)
    assert len(raw) <= INBOX_WIRE_BUDGET
    assert payload(response) == {"endpoint": "a/lane/f2", "binding": binding, "checkpoint_briefs": [],
                                 "messages": [], "remaining": 0, "next_after": None}
    assert mailbox_snapshot(root) == before


def test_mcp_bounded_inbox_exact_wire_boundary(pilot):  # noqa: F811
    root, _ = pilot
    identifier = 'edge-é"\\\n😀'
    # Calibrate from the real outer JSON-RPC line, including the escaped ID,
    # inner text and newline. Equal-length roots keep path framing identical.
    seed = wire_peer_mailbox(root, "edge-seed")
    seed_wire_inbox(seed, "x" * 262144, count=16, final_content="x" * 200000)
    raw, response = mcp_inbox_wire(seed, {"include_briefs": True, "limit": 100}, identifier=identifier)
    assert len(payload(response)["messages"]) == 16
    padding = INBOX_WIRE_BUDGET - len(raw)
    assert 0 < padding < 262144 - 200000
    fit = wire_peer_mailbox(root, "edge-fit0")
    expected = seed_wire_inbox(fit, "x" * 262144, count=16, final_content="x" * (200000 + padding))
    raw, response = mcp_inbox_wire(fit, {"include_briefs": True, "limit": 100}, identifier=identifier)
    assert len(raw) == INBOX_WIRE_BUDGET
    page = payload(response)
    assert page["messages"] == expected
    assert page["remaining"] == 0 and page["next_after"] is None
    over = wire_peer_mailbox(root, "edge-over")
    expected = seed_wire_inbox(over, "x" * 262144, count=16, final_content="x" * (200001 + padding))
    before = mailbox_snapshot(over)
    raw, response = mcp_inbox_wire(over, {"include_briefs": True, "limit": 100}, identifier=identifier)
    assert len(raw) <= INBOX_WIRE_BUDGET
    page = payload(response)
    assert page["messages"] == expected[:-1]
    assert page["remaining"] == 1
    assert page["next_after"] == expected[-2]["message"]["message_id"]
    raw, response = mcp_inbox_wire(over, {"include_briefs": True, "limit": 100,
                                        "after_message_id": page["next_after"]}, identifier=identifier)
    assert len(raw) <= INBOX_WIRE_BUDGET
    last = payload(response)
    assert last["messages"] == expected[-1:]
    assert last["remaining"] == 0 and last["next_after"] is None
    assert mailbox_snapshot(over) == before


def test_mcp_bounded_inbox_first_message_cannot_be_skipped(pilot):  # noqa: F811
    root, _ = pilot
    binding = checkpoint_wire_binding(root, "x" * 262144, 15)
    identity = {"host": "host-two", "session": "replacement", "generation": 2}
    raw, response = mcp_inbox_wire(root, {"include_briefs": True}, **identity)
    assert len(raw) <= INBOX_WIRE_BUDGET
    metadata = payload(response)
    assert metadata["binding"] == binding
    assert metadata["messages"] == []
    assert metadata["checkpoint_briefs"] == [
        {**reference, "text": "x" * 262144} for reference in binding["checkpoint"]["briefs"]]
    expected = seed_wire_inbox(root, "x" * 262144, count=2)
    before = mailbox_snapshot(root)
    raw, response = mcp_inbox_wire(root, {"include_briefs": True}, **identity)
    assert len(raw) <= INBOX_WIRE_BUDGET
    assert response["result"]["isError"] is True
    assert payload(response) == {"error": "inbox first message cannot fit 4194304 byte response budget"}
    _, response = mcp_inbox_wire(root, {}, **identity)
    small = payload(response)
    assert small["messages"] == [{"path": r["path"], "message": r["message"]} for r in expected]
    assert small["binding"] == binding
    assert small["remaining"] == 0 and small["next_after"] is None
    assert mailbox_snapshot(root) == before


@pytest.mark.parametrize("arguments,error", [
    ({"limit": True}, "invalid inbox limit"),
    ({"limit": 0}, "invalid inbox limit"),
    ({"limit": 101}, "invalid inbox limit"),
    ({"after_message_id": "missing"}, "inbox cursor does not name a received message"),
    ({"after_message_id": "foreign"}, "inbox cursor does not name a received message"),
])
def test_mcp_bounded_inbox_retains_argument_errors(pilot, arguments, error):  # noqa: F811
    root, _ = pilot
    seed_wire_inbox(root, "x" * 262144)
    invoke(root, "publish", message(recipient="a/lane/review", identifier="foreign"))
    before = mailbox_snapshot(root)
    raw, response = mcp_inbox_wire(root, {"include_briefs": True, **arguments})
    assert len(raw) <= INBOX_WIRE_BUDGET
    assert response["result"]["isError"] is True
    assert payload(response) == {"error": error}
    assert mailbox_snapshot(root) == before


@pytest.mark.parametrize("kind", ["first-brief", "deferred-brief", "missing-brief", "history"])
def test_mcp_bounded_inbox_does_not_hide_corruption(pilot, kind):  # noqa: F811
    root, _ = pilot
    rows = seed_wire_inbox(root, "x" * 262144)
    error = corrupt_wire_fixture(root, rows, kind)
    before = mailbox_snapshot(root)
    raw, response = mcp_inbox_wire(root, {"include_briefs": True})
    assert len(raw) <= INBOX_WIRE_BUDGET
    assert response["result"]["isError"] is True
    assert payload(response) == {"error": error}
    assert mailbox_snapshot(root) == before


def test_mcp_bounded_inbox_preserves_malformed_frame_and_cross_role_errors(pilot):  # noqa: F811
    root, _ = pilot
    expected = seed_wire_inbox(root, "x" * 262144)
    frames = [inbox_frame({"include_briefs": True}),
              {"jsonrpc": "2.0", "id": "diagonal", "method": "tools/call", "params": {
                  "name": "mailbox_publish", "arguments": {"message_id": "forbidden", "to": "b/orchestrator",
                                                           "type": "info", "body": "must not publish"}}},
              {"jsonrpc": "2.0", "id": "ping", "method": "ping"}]
    raw = b'{"jsonrpc":"2.0","id":1,"id":2}\n'
    raw += b"".join((json.dumps(frame) + "\n").encode("utf-8") for frame in frames)
    before = mailbox_snapshot(root)
    lines, responses = mcp_wire_exchange(root, raw=raw)
    assert len(responses) == 4
    assert responses[0] == {"jsonrpc": "2.0", "id": None, "error": {
        "code": -32700, "message": "duplicate JSON key: id"}}
    assert len(lines[1]) <= INBOX_WIRE_BUDGET
    page = payload(responses[1])
    assert page["messages"] == expected[:len(page["messages"])]
    assert 0 < len(page["messages"]) < 20
    assert page["remaining"] == len(expected) - len(page["messages"])
    assert page["next_after"] == page["messages"][-1]["message"]["message_id"]
    assert responses[2]["result"]["isError"] is True
    assert payload(responses[2]) == {"error": "route is not vertical or an explicit counterpart"}
    assert responses[3] == {"jsonrpc": "2.0", "id": "ping", "result": {}}
    assert mailbox_snapshot(root) == before


def test_mcp_bounded_inbox_errors_do_not_misreport_mutations(pilot):  # noqa: F811
    root, _ = pilot
    binding = checkpoint_wire_binding(root, "x" * 262144, 20)
    body = 'é"\\\n😀' * 4096
    publish = {"name": "mailbox_publish", "arguments": {
        "message_id": "after-overflow", "to": "a/orchestrator", "type": "info", "body": body}}
    frames = [inbox_frame({"include_briefs": True}),
              {"jsonrpc": "2.0", "id": "handoff", "method": "tools/call", "params": {
                  "name": "mailbox_ack_handoff", "arguments": {"checkpoint_sha256": binding["checkpoint_sha256"]}}},
              {"jsonrpc": "2.0", "id": 'publish-é"\\\n😀', "method": "tools/call", "params": publish},
              {"jsonrpc": "2.0", "id": "duplicate", "method": "tools/call", "params": publish},
              inbox_frame({}, "metadata"), {"jsonrpc": "2.0", "id": "ping", "method": "ping"}]
    lines, responses = mcp_wire_exchange(root, frames, host="host-two", session="replacement", generation=2)
    assert len(responses) == len(frames)
    assert len(lines[0]) <= INBOX_WIRE_BUDGET
    assert responses[0]["result"]["isError"] is True
    assert payload(responses[0]) == {"error": "inbox response metadata exceeds 4194304 bytes"}
    for index in (1, 2):
        assert responses[index]["result"].get("isError", False) is False
        assert responses[index]["id"] == frames[index]["id"]
    assert payload(responses[1]) == {"endpoint": "a/lane/f2", "generation": 2, "ready": True, "observed_sources": []}
    receipt = payload(responses[2])
    assert receipt["message"]["body"] == body
    assert receipt["message"]["message_id"] == "after-overflow"
    assert receipt["sha256"] == hashlib.sha256(Path(receipt["path"]).read_bytes()).hexdigest()
    assert responses[3]["result"]["isError"] is True
    assert payload(responses[3]) == {"error": "message_id already exists: after-overflow"}
    assert payload(responses[4])["binding"] == {**binding, "ready": True}
    assert responses[5] == {"jsonrpc": "2.0", "id": "ping", "result": {}}
    assert json.loads((root / "bindings/a/lane/f2/000002.ack").read_text()) == {
        "endpoint": "a/lane/f2", "generation": 2, "session": "replacement",
        "checkpoint_sha256": binding["checkpoint_sha256"]}
    assert invoke(root, "inbox", endpoint="a/orchestrator")["messages"] == [
        {"path": receipt["path"], "message": receipt["message"]}]
