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
import copy
import math
import random
import uuid
from types import SimpleNamespace
from datetime import datetime, timezone

import pytest

from tests.integration.test_hierarchy_mailbox import ENDPOINTS, HELPER, invoke, message, pilot  # noqa: F401
from tests.integration.test_hierarchy_mailbox import (
    INBOX_WIRE_BUDGET, WIRE_PAYLOADS, checkpoint_wire_binding, corrupt_wire_fixture,
    mailbox_snapshot, record_wire_process, seed_wire_inbox, wire_peer_mailbox,
)

sys.path.insert(0, str(HELPER.parent))
from hierarchy_mailbox import GIT_ID, MESSAGE_TYPES, STAGES  # noqa: E402


MB3_FIXED_NOW = datetime(2026, 1, 10, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def mb3_fixed_clock(monkeypatch):
    import hierarchy_mailbox_mcp as mcp
    monkeypatch.setattr(mcp, "_inbox_now", lambda: MB3_FIXED_NOW, raising=False)


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


@pytest.mark.parametrize("host", [None, "codex-cli", "claude-code"])
def test_front_door_authors_hash_bound_brief_using_only_scoped_tools(mb3_pilot, host):
    root, _ = mb3_pilot
    if host is None:
        (root.parent / "host-plan.json").unlink()
    else:
        mb3_host_plan(root, host=host)
    intent = {"message_id": "intent-file", "to": "a/orchestrator", "type": "info",
              "body": "Goal: improve diagnostics.\nAcceptance: retain conservative overlap evidence.\n"}
    created = payload(exchange(root, [("mailbox_publish", intent)], endpoint="a/front-door")[-1])
    assert hashlib.sha256(Path(created["path"]).read_bytes()).hexdigest() == created["sha256"]
    reference = {"path": created["path"], "sha256": created["sha256"]}
    handed_off = {"message_id": "intent-handoff", "to": "a/orchestrator", "type": "brief",
                  "body": "Use this immutable hierarchy brief.", "brief": reference}
    result = payload(exchange(root, [("mailbox_publish", handed_off)], endpoint="a/front-door")[-1])
    assert result["path"].endswith(".md")
    inbox = payload(exchange(root, [("mailbox_inbox", {"include_briefs": True})], endpoint="a/orchestrator")[-1])
    delivered = next(r for r in inbox["messages"] if r["message"]["message_id"] == "intent-handoff")
    assert delivered["message"]["brief"] == reference
    assert intent["body"] in delivered["brief_text"]


def mcp_wire_exchange(root, frames=(), *, endpoint="a/lane/f2", host="host-one", session=None, generation=1, raw=None,
                      clock=None):
    initialization = {"jsonrpc": "2.0", "id": "init", "method": "initialize", "params": {}}
    prefix = (json.dumps(initialization) + "\n").encode("utf-8")
    if raw is None:
        lines = [(json.dumps(frame, ensure_ascii=False) + "\n").encode("utf-8") for frame in frames]
        assert all(len(line) <= 262144 for line in lines), "fixtures must remain valid input frames"
        raw = b"".join(lines)
    argv = [sys.executable, "-I", str(HELPER), "--root", str(root), "serve",
            "--endpoint", endpoint, "--host", host, "--session", session or endpoint,
            "--generation", str(generation)]
    if clock is not None:
        # Only this test driver overrides the module clock; no production env/argument bypass.
        driver = ("import json,sys; from datetime import datetime,timezone; "
                  "from pathlib import Path; sys.path.insert(0,str(Path(sys.argv[1]).parent)); "
                  "import hierarchy_mailbox_mcp as mcp; "
                  "now=datetime(*json.loads(sys.argv[2]),tzinfo=timezone.utc); "
                  "mcp._inbox_now=lambda: now; from hierarchy_mailbox import main; "
                  "sys.exit(main(sys.argv[3:]))")
        stamp = [clock.year, clock.month, clock.day, clock.hour, clock.minute, clock.second, clock.microsecond]
        argv = [sys.executable, "-I", "-B", "-c", driver, str(HELPER), json.dumps(stamp), *argv[3:]]
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


def test_publish_schema_has_nonempty_text_bounds_and_utc_time(pilot):  # noqa: F811
    import re
    root, _ = pilot
    fields = publish_tool(root)["inputSchema"]["properties"]
    readiness, result = fields["readiness"]["properties"], fields["result"]["properties"]
    for key in ("worktree", "branch", "scan_workspace", "scan_evidence", "hook_evidence"):
        assert readiness[key]["minLength"] == 1
        assert readiness[key]["maxLength"] == (256 if key == "branch" else 4096)
    assert result["lane_check"]["minLength"] == 1
    assert readiness["owned_paths"]["items"]["minLength"] == 1
    pattern = readiness["lease_expires_at"]["pattern"]
    assert re.fullmatch(pattern, "2099-01-01T00:00:00.000001Z")
    assert not re.fullmatch(pattern, "2099-01-01T00:00:00+00:00")


@pytest.mark.parametrize("field,label", [
    ("worktree", "worktree"), ("branch", "branch"), ("scan_workspace", "scan workspace"),
    ("scan_evidence", "scan_evidence"), ("hook_evidence", "hook_evidence"),
])
def test_publish_refuses_text_beyond_its_advertised_readiness_limit(pilot, tmp_path, field, label):  # noqa: F811
    from tests.integration.test_hierarchy_mailbox import readiness
    root, brief = pilot
    invoke(root, "publish", message(kind="dispatch", brief=brief))
    ready = readiness(tmp_path)
    schema = publish_tool(root)["inputSchema"]["properties"]["readiness"]["properties"][field]
    ready[field] = "x" * (schema["maxLength"] + 1)
    answer = exchange(root, [("mailbox_publish", {"message_id": "accepted", "to": "a/orchestrator",
                         "type": "ack", "body": "Accepted", "in_reply_to": "dispatch-1",
                         "acknowledgment": "accepted", "readiness": ready})], endpoint="a/lane/f2")[-1]
    assert answer["result"]["isError"] is True
    assert payload(answer)["error"] == "invalid " + label


def test_publish_requires_the_writers_advertised_lane_check(pilot, tmp_path):  # noqa: F811
    from tests.integration.test_hierarchy_mailbox import readiness
    root, brief = pilot
    invoke(root, "publish", message(kind="dispatch", brief=brief))
    evidence = {"source_revision": "a" * 40, "source_tree": "b" * 40,
                "checks": [{"check": "affected-tests", "outcome": "pass", "reference": "tests.log"}]}
    answers = exchange(root, [
        ("mailbox_publish", {"message_id": "accepted", "to": "a/orchestrator", "type": "ack", "body": "Accepted",
                             "in_reply_to": "dispatch-1", "acknowledgment": "accepted", "readiness": readiness(tmp_path)}),
        ("mailbox_publish", {"message_id": "result", "to": "a/orchestrator", "type": "result", "body": "Done",
                             "in_reply_to": "dispatch-1", "result": evidence})], endpoint="a/lane/f2")
    assert not answers[2]["result"].get("isError", False)
    assert answers[3]["result"]["isError"] is True
    assert payload(answers[3])["error"] == "invalid lane check reference"


@pytest.fixture
def mb3_pilot(tmp_path_factory):
    # Binding/session fixtures must never reuse a pytest per-test path across invocations.
    directory = tmp_path_factory.mktemp("mb3-" + uuid.uuid4().hex)
    root = directory / "mailbox"
    manifest = {"schema": "aegis.hierarchy-pilot/v1", "endpoints": ENDPOINTS,
                "counterparts": [["a/front-door", "b/front-door"], ["a/orchestrator", "b/orchestrator"],
                                 ["a/lane/f2", "b/lane/f6"]], "writer_limit": 3}
    invoke(root, "init", manifest)
    for endpoint in ENDPOINTS:
        invoke(root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint,
                              "expected_generation": 0})
        mb3_binding_time(root, 1, "2026-01-01T00:00:00.000000Z", endpoint)
    brief = directory / "brief.md"
    brief.write_bytes(b"Goal: improve diagnostics.\nAcceptance: retain overlap evidence.\n")
    mb3_host_plan(root)
    return root, {"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}


def mb3_host_plan(root, hierarchy="a", host="codex-cli"):
    import hierarchy_hosts
    plan = hierarchy_hosts.plan_record(hierarchy, host, host, {}, "0" * 64)
    (root.parent / hierarchy_hosts.PLAN_FILE).write_bytes(json.dumps(plan, sort_keys=True).encode("utf-8"))


def mb3_binding_time(root, generation, stamp, endpoint="a/lane/f2"):
    path = root / "bindings" / endpoint / ("%06d.json" % generation)
    binding = json.loads(path.read_bytes())
    binding["created_at"] = stamp
    path.write_bytes((json.dumps(binding, sort_keys=True) + "\n").encode("utf-8"))


def mb3_message_time(row, stamp):
    path = Path(row["path"])
    path.write_bytes(path.read_bytes().replace(row["message"]["created_at"].encode("ascii"), stamp.encode("ascii"), 1))
    row["message"]["created_at"] = stamp
    return row


def mb3_seed(root, content="brief", count=5):
    rows = seed_wire_inbox(root, content, count=count)
    for number, row in enumerate(rows):
        mb3_message_time(row, "2026-01-03T00:00:00.%06dZ" % number)
    return rows


def mb3_checkpoint(root, content="checkpoint", copies=1):
    binding = checkpoint_wire_binding(root, content, copies)
    binding["created_at"] = "2026-01-02T00:00:00.000000Z"
    mb3_binding_time(root, 2, binding["created_at"])
    return binding


@pytest.mark.parametrize("key,value,error", [
    *[("order", value, "order must be oldest or newest; use an exact string")
      for value in (None, True, 1, [], {}, "Newest", "NEWEST", "newesté", "", "newest\x00")],
    *[("since", value, "since must be current_generation; use that exact string or omit since")
      for value in (None, False, 1, [], {}, "CURRENT_GENERATION", "current_generationé", "", "all")],
    ("fields", [], "unexpected fields: fields"),
    ("unknown", "secret", "unexpected fields: unknown"),
])
def test_mb3_argument_refusals(mb3_pilot, key, value, error):
    root, _ = mb3_pilot
    _, answer = mcp_inbox_wire(root, {key: value})
    assert answer["result"]["isError"] is True
    assert payload(answer) == {"error": error}


@pytest.mark.parametrize("key,value", [("order", "newest"), ("since", "current_generation")])
def test_mb3_binding_only_refuses_view_options(mb3_pilot, key, value):
    root, _ = mb3_pilot
    _, answer = mcp_inbox_wire(root, {"binding_only": True, key: value})
    assert answer["result"]["isError"] is True
    assert payload(answer) == {"error": "binding_only takes no order or since; omit those options"}


def mb3_handler_page(result, monkeypatch=None, renderer=None):
    import hierarchy_mailbox_mcp as mcp
    connection = SimpleNamespace(begin_response=lambda: None, call=lambda *args: copy.deepcopy(result),
                                 note_returned=lambda *args: None)
    if renderer is not None:
        monkeypatch.setattr(mcp, "_response_line", renderer)
    return {"jsonrpc": "2.0", "id": "é-edge", "result": mcp.handle(connection, inbox_frame({}, "é-edge"))}


def mb3_oracle_response(result):
    # The frozen CLI's original linear algorithm remains the independent oracle.
    from hierarchy_mailbox import _bounded_inbox
    import hierarchy_mailbox_mcp as mcp
    def render(page):
        return mcp._response_line({"jsonrpc": "2.0", "id": "é-edge", "result": mcp._tool_result(page)})
    try:
        selected = _bounded_inbox(copy.deepcopy(result), render)
        answer = mcp._tool_result(selected)
    except ValueError as exc:
        answer = {"content": [{"type": "text", "text": json.dumps({"error": str(exc)})}], "isError": True}
    return mcp._response_line({"jsonrpc": "2.0", "id": "é-edge", "result": answer})


def mb3_result(sizes, *, remaining=0):
    rows = [{"path": "/mailbox/a/lane/message-%04d.md" % i,
             "message": {"message_id": "m-%04d" % i, "body": body}}
            for i, body in enumerate(sizes)]
    return {"endpoint": "a/lane/f2", "binding": None, "checkpoint_briefs": [],
            "messages": rows, "remaining": remaining, "next_after": None}


@pytest.mark.parametrize("case", ["empty", "tiny", "mixed", "utf8", "over", "metadata", "exact", "one-over",
                                  "many", "seeded"])
def test_mb3_pager_equivalence_through_handler(case):
    import hierarchy_mailbox_mcp as mcp
    rng = random.Random(30709)
    choices = {
        "empty": [], "tiny": ["x"] * 100, "mixed": ["x", "q" * 200000, "é😀" * 50000] * 3,
        "utf8": ['é😀"\\\n' * 24000] * 8, "over": ["x" * INBOX_WIRE_BUDGET],
        "metadata": [], "exact": [""], "one-over": [""], "many": ["x"] * 2000,
        "seeded": [rng.choice(("x", 'é😀"\\\n')) * rng.randrange(1, 9000) for _ in range(40)],
    }
    result = mb3_result(choices[case], remaining=7 if case in ("mixed", "many") else 0)
    if case == "metadata":
        result["checkpoint_briefs"] = [{"text": "x" * INBOX_WIRE_BUDGET}]
    if case in ("exact", "one-over"):
        overhead = len(mb3_oracle_response(result))
        result["messages"][0]["message"]["body"] = "x" * (INBOX_WIRE_BUDGET - overhead + (case == "one-over"))
    expected = mb3_oracle_response(result)
    observed = mcp._response_line(mb3_handler_page(result))
    assert observed == expected
    if case == "exact":
        assert len(observed) == INBOX_WIRE_BUDGET


@pytest.mark.parametrize("count", [0, 1, 2, 20, 100, 512, 2000])
def test_mb3_render_count_is_logarithmic(monkeypatch, count):
    renders = []
    def render(response):
        page = payload(response)
        renders.append(len(page["messages"]))
        # External transport boundary: all candidate prefixes fit.
        return b"x"
    answer = mb3_handler_page(mb3_result(["x"] * count), monkeypatch, render)
    assert len(payload(answer)["messages"]) == count
    assert len(renders) <= math.ceil(math.log2(count + 1)) + 2


def test_mb3_newest_cursor_walk_and_explicit_oldest(mb3_pilot):
    root, _ = mb3_pilot
    rows = mb3_seed(root)
    ids = [r["message"]["message_id"] for r in rows]
    frames = [inbox_frame({"order": "newest", "limit": 2}),
              inbox_frame({"order": "newest", "limit": 2, "after_message_id": ids[-2]}),
              inbox_frame({"order": "newest", "limit": 2, "after_message_id": ids[-4]}),
              inbox_frame({"order": "oldest", "limit": 2})]
    _, answers = mcp_wire_exchange(root, frames)
    pages = [payload(a) for a in answers]
    assert [r["message"]["message_id"] for p in pages[:3] for r in p["messages"]] == ids[::-1]
    assert [p["next_after"] for p in pages[:3]] == [ids[-2], ids[-4], None]
    assert [p["remaining"] for p in pages[:3]] == [3, 1, 0]
    assert [r["message"]["message_id"] for r in pages[3]["messages"]] == ids[:2]
    _, answer = mcp_inbox_wire(root, {"order": "newest", "after_message_id": "missing"})
    assert payload(answer) == {"error": "inbox cursor does not match this walk; restart the walk without after_message_id"}


def test_mb3_since_generation_boundary_and_filtered_cursor(mb3_pilot):
    root, _ = mb3_pilot
    mb3_message_time(invoke(root, "publish", message(identifier="old")), "2026-01-01T00:00:00.000000Z")
    binding = mb3_checkpoint(root)
    mb3_message_time(invoke(root, "publish", message(identifier="fresh")), binding["created_at"])
    mb3_message_time(invoke(root, "publish", message(identifier="latest")), "2026-01-03T00:00:00.000000Z")
    identity = {"host": "host-two", "session": "replacement", "generation": 2}
    _, answers = mcp_wire_exchange(root, [
        inbox_frame({"since": "current_generation", "include_briefs": True}),
        inbox_frame({"since": "current_generation", "order": "newest"}),
        inbox_frame({"since": "current_generation", "after_message_id": "old"}),
        inbox_frame({"since": "current_generation", "after_message_id": "fresh"}),
    ], clock=MB3_FIXED_NOW, **identity)
    for answer, ids in zip(answers[:2], (["fresh", "latest"], ["latest", "fresh"])):
        assert [r["message"]["message_id"] for r in payload(answer)["messages"]] == ids
        assert payload(answer)["excluded"] == 1
    for answer in answers[2:]:
        assert payload(answer) == {"error": "inbox cursor does not match this walk; restart the walk without after_message_id"}
    assert binding["generation"] == 2


def test_mb3_since_without_binding_names_next_action(mb3_pilot):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    connection = mcp.Connection(root, "a/lane/f2", "host-one", "a/lane/f2", 1)
    (root / "bindings/a/lane/f2/000001.json").unlink()
    answer = {"result": mcp.handle(connection, inbox_frame({"since": "current_generation"}))}
    assert payload(answer) == {"error": "current_generation requires a binding; bind the endpoint and reconnect"}


def test_mb3_brief_dedupe_and_slim_binding_on_wire(mb3_pilot):
    root, _ = mb3_pilot
    binding = mb3_checkpoint(root, "checkpoint" * 1000, 2)
    identity = {"host": "host-two", "session": "replacement", "generation": 2}
    lines, answers = mcp_wire_exchange(root, [inbox_frame({"include_briefs": True}),
                                             inbox_frame({"include_briefs": True}),
                                             inbox_frame({"binding_only": True})], **identity)
    first, later, control = [payload(a) for a in answers]
    assert first["binding"] == binding
    assert first["checkpoint_briefs"] == [{**r, "text": "checkpoint" * 1000}
                                           for r in binding["checkpoint"]["briefs"]]
    assert later["checkpoint_briefs"] == [{**r, "ok": True} for r in binding["checkpoint"]["briefs"]]
    assert later["binding"] == {key: binding[key] for key in
                                ("endpoint", "host", "generation", "checkpoint_sha256", "session", "ready")}
    assert len(lines[1]) < len(lines[0])
    assert control["binding"] == binding
    # A fresh process is a fresh session even for the same binding.
    _, answer = mcp_inbox_wire(root, {"include_briefs": True}, **identity)
    assert payload(answer) == first


@pytest.mark.parametrize("damage,reason", [("changed", "brief_changed"), ("missing", "brief_unavailable"),
                                          ("unreadable", "brief_unavailable")])
def test_mb3_later_brief_checks_and_generation_reset(mb3_pilot, monkeypatch, damage, reason):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    binding = mb3_checkpoint(root, "original checkpoint")
    reference = binding["checkpoint"]["briefs"][0]
    connection = mcp.Connection(root, "a/lane/f2", "host-two", "replacement", 2)
    frame = inbox_frame({"include_briefs": True})
    first = {"result": mcp.handle(connection, frame)}
    assert payload(first)["checkpoint_briefs"][0]["text"] == "original checkpoint"
    # No successful flush yet: the full text must still be sent.
    assert payload({"result": mcp.handle(connection, frame)}) == payload(first)
    connection.record_inbox_page()
    path = Path(reference["path"])
    if damage == "changed":
        path.write_bytes(b"changed")
    elif damage == "missing":
        path.unlink()
    else:
        original = Path.open
        def denied(target, *args, **kwargs):
            if target == path:
                raise PermissionError("secret OS path must not leak")
            return original(target, *args, **kwargs)
        monkeypatch.setattr(Path, "open", denied)
    answer = {"result": mcp.handle(connection, frame)}
    assert payload(answer)["checkpoint_briefs"] == [{**reference, "ok": False, "reason": reason}]
    if damage == "unreadable":
        monkeypatch.setattr(Path, "open", original)
    path.write_bytes(b"original checkpoint")
    successor = invoke(root, "bind", {"endpoint": "a/lane/f2", "host": "host-three", "session": "third",
                                     "expected_generation": 2, "checkpoint": binding["checkpoint"]})
    successor["created_at"] = "2026-01-04T00:00:00.000000Z"
    mb3_binding_time(root, 3, successor["created_at"])
    stale = {"result": mcp.handle(connection, frame)}
    assert payload(stale) == {"error": "stale or mismatched sender binding"}
    connection = mcp.Connection(root, "a/lane/f2", "host-three", "third", 3)
    answer = {"result": mcp.handle(connection, frame)}
    assert payload(answer)["binding"] == successor
    assert payload(answer)["checkpoint_briefs"][0]["text"] == "original checkpoint"


def test_mb3_tool_description_is_static_across_session_state(mb3_pilot):
    root, _ = mb3_pilot
    listed = {"jsonrpc": "2.0", "id": "list", "method": "tools/list"}
    _, answers = mcp_wire_exchange(root, [listed, inbox_frame({}), listed])
    assert answers[0] == answers[2]
    tool = next(t for t in answers[0]["result"]["tools"] if t["name"] == "mailbox_inbox")
    assert tool["inputSchema"]["properties"]["order"]["enum"] == ["oldest", "newest"]
    assert tool["inputSchema"]["properties"]["since"]["enum"] == ["current_generation"]


def test_mb3_default_pages_match_pinned_inbox_through_real_connection(mb3_pilot):
    from hierarchy_mailbox import Mailbox
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    mb3_seed(root, 'é😀"\\\n')
    for include in (False, True):
        for limit, after in ((1, None), (3, None), (2, "wire-001"), (5, "wire-004")):
            original = Mailbox(root).inbox("a/lane/f2", include_briefs=include, limit=limit, after=after)
            arguments = {"include_briefs": include, "limit": limit}
            if after is not None:
                arguments["after_message_id"] = after
            connection = mcp.Connection(root, "a/lane/f2", "host-one", "a/lane/f2", 1)
            answer = {"jsonrpc": "2.0", "id": "é-edge", "result": mcp.handle(
                connection, inbox_frame(arguments, "é-edge"))}
            assert mcp._response_line(answer) == mb3_oracle_response(original)


@pytest.mark.parametrize("seed", [3, 17, 91, 30709])
def test_mb3_seeded_pager_prefixes_match_oracle(seed):
    import hierarchy_mailbox_mcp as mcp
    rng = random.Random(seed)
    bodies = [rng.choice(("x", "é😀", '"\\\n')) * rng.randrange(1, 30000) for _ in range(45)]
    for remaining in (0, 9):
        result = mb3_result(bodies, remaining=remaining)
        # Long cursors and shrinking remaining counts exercise the monotonicity boundary.
        for row in result["messages"]:
            row["message"]["message_id"] += "z" * 70
        answer = mb3_handler_page(result)
        assert mcp._response_line(answer) == mb3_oracle_response(result)
        assert 0 < len(payload(answer)["messages"]) < len(bodies)


def test_mb3_unrequested_briefs_and_binding_only_do_not_consume_texts(mb3_pilot):
    root, _ = mb3_pilot
    binding = mb3_checkpoint(root)
    _, answers = mcp_wire_exchange(root, [inbox_frame({"binding_only": True}), inbox_frame({}),
                                         inbox_frame({"include_briefs": True}),
                                         inbox_frame({"include_briefs": True})],
                                    host="host-two", session="replacement", generation=2)
    pages = [payload(a) for a in answers]
    assert pages[1]["binding"] == binding
    assert pages[2]["checkpoint_briefs"][0]["text"] == "checkpoint"
    assert pages[3]["checkpoint_briefs"] == [{**binding["checkpoint"]["briefs"][0], "ok": True}]


def test_mb3_newest_ties_and_since_cursor_walk(mb3_pilot):
    root, _ = mb3_pilot
    binding = mb3_checkpoint(root)
    rows = mb3_seed(root)
    # Stored message header bytes may be attacker-written; still use the pinned parser.
    timestamp = "2026-01-03T00:00:00.000000Z"
    for row in rows:
        mb3_message_time(row, timestamp)
    options = {"since": "current_generation", "order": "newest", "limit": 2}
    _, answers = mcp_wire_exchange(root, [inbox_frame(options),
                                         inbox_frame({**options, "after_message_id": "wire-003"}),
                                         inbox_frame({**options, "after_message_id": "wire-001"})],
                                    host="host-two", session="replacement", generation=2, clock=MB3_FIXED_NOW)
    assert [r["message"]["message_id"] for a in answers for r in payload(a)["messages"]] == [
        "wire-004", "wire-003", "wire-002", "wire-001", "wire-000"]
    assert binding["generation"] == 2


MB3_RESTART = "inbox cursor does not match this walk; restart the walk without after_message_id"


def mb3_connection(root, generation=1):
    import hierarchy_mailbox_mcp as mcp
    return mcp.Connection(root, "a/lane/f2", "host-one" if generation == 1 else "host-two",
                          "a/lane/f2" if generation == 1 else "replacement", generation)


def mb3_call(connection, arguments, *, flush=True):
    import hierarchy_mailbox_mcp as mcp
    answer = {"result": mcp.handle(connection, inbox_frame(arguments))}
    if flush:
        connection.record_inbox_page()
    return answer


def mb3_drain(connection, options, *, limit=2):
    collected, cursor = [], None
    for _ in range(20):
        args = {**options, "limit": limit}
        if cursor is not None:
            args["after_message_id"] = cursor
        answer = mb3_call(connection, args)
        assert not answer["result"].get("isError", False), payload(answer)
        page = payload(answer)
        collected.extend(row["message"]["message_id"] for row in page["messages"])
        assert len(collected) == len(set(collected)), "walk repeated a delivered message"
        cursor = page["next_after"]
        if cursor is None:
            assert page["remaining"] == 0
            return collected
    pytest.fail("bounded fixture walk did not drain")


def mb3_committed_state(connection):
    return copy.deepcopy((connection.pager.session, connection.pager.briefs_session,
                          connection.pager.cutoffs, connection.pager.cursors))


@pytest.mark.parametrize("tool,args", [("mailbox_inbox", {}), ("mailbox_inbox", {"since": "current_generation"}),
                                      ("mailbox_inbox", {"binding_only": True}), ("mailbox_self", {})])
@pytest.mark.parametrize("rebind", [False, True])
def test_mb3_2_class_a_one_snapshot(mb3_pilot, monkeypatch, tool, args, rebind):
    import hierarchy_mailbox_mcp as mcp
    from hierarchy_mailbox import Mailbox
    root, brief = mb3_pilot
    rows = mb3_seed(root)
    connection = mb3_connection(root)
    original = Mailbox.fence
    calls = []
    def fenced(mailbox, sender, **kwargs):
        binding = original(mailbox, sender, **kwargs)
        calls.append(binding["generation"])
        if rebind:
            checkpoint = {"outgoing_stopped": True, "briefs": [brief], "sources": [], "lease_refs": [],
                          "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}
            mailbox.bind({"endpoint": "a/lane/f2", "host": "host-two", "session": "replacement",
                          "expected_generation": 1, "checkpoint": checkpoint})
            mb3_binding_time(root, 2, "2026-01-04T00:00:00.000000Z")
        return binding
    monkeypatch.setattr(Mailbox, "fence", fenced)
    request = {"jsonrpc": "2.0", "id": "race", "method": "tools/call",
               "params": {"name": tool, "arguments": args}}
    answer = {"result": mcp.handle(connection, request)}
    page = payload(answer)
    assert not answer["result"].get("isError", False), page
    binding = page if tool == "mailbox_self" else page["binding"]
    assert binding["generation"] == 1 and binding["session"] == "a/lane/f2"
    assert calls == [1]
    if "messages" in page:
        assert len(page["messages"]) == len(rows)
        assert page["checkpoint_briefs"] == []


@pytest.mark.parametrize("size,dedupes", [(100, True), (100000, False)])
def test_mb3_2_class_b_size_gate_and_recovery(mb3_pilot, size, dedupes):
    root, _ = mb3_pilot
    binding = mb3_checkpoint(root, "x" * size)
    lines, answers = mcp_wire_exchange(root, [inbox_frame({"include_briefs": True}),
                                             inbox_frame({"include_briefs": True}),
                                             inbox_frame({"briefs": "full"})],
                                    host="host-two", session="replacement", generation=2)
    first, later, recovered = [payload(a) for a in answers]
    assert (len(lines[0]) <= 60000) is dedupes
    assert first["checkpoint_briefs"][0]["text"] == "x" * size
    if dedupes:
        assert later["checkpoint_briefs"] == [{**binding["checkpoint"]["briefs"][0], "ok": True}]
    else:
        assert later == first
    assert recovered == first


@pytest.mark.parametrize("value", [None, True, 1, [], {}, "Full", "fullé", "", "full\x00"])
def test_mb3_2_class_b_recovery_refusals(mb3_pilot, value):
    root, _ = mb3_pilot
    answer = mb3_call(mb3_connection(root), {"briefs": value})
    assert payload(answer) == {"error": "briefs must be full; use that exact string or omit briefs"}


@pytest.mark.parametrize("target_size,dedupes", [(60000, True), (60001, False)])
def test_mb3_2_class_b_exact_size_gate(mb3_pilot, target_size, dedupes):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    binding = mb3_checkpoint(root, "x")
    calibration = mb3_call(mb3_connection(root, 2), {"include_briefs": True}, flush=False)
    size = len(mcp._response_line({"jsonrpc": "2.0", "id": "inbox", "result": calibration["result"]}))
    reference = binding["checkpoint"]["briefs"][0]
    raw = b"x" * (target_size - size + 1)
    Path(reference["path"]).write_bytes(raw)
    reference["sha256"] = hashlib.sha256(raw).hexdigest()
    binding["checkpoint_sha256"] = mcp.digest(binding["checkpoint"])
    stored = {key: value for key, value in binding.items() if key != "ready"}
    (root / "bindings/a/lane/f2/000002.json").write_bytes(json.dumps(stored).encode("utf-8"))
    lines, answers = mcp_wire_exchange(root, [inbox_frame({"include_briefs": True})] * 2,
                                    host="host-two", session="replacement", generation=2)
    assert len(lines[0]) == target_size
    first, later = [payload(a) for a in answers]
    assert ("text" not in later["checkpoint_briefs"][0]) is dedupes
    if not dedupes:
        assert later == first


@pytest.mark.parametrize("arguments,error", [
    ({"binding_only": True, "briefs": "full"}, "binding_only takes no briefs; omit briefs"),
    ({"include_briefs": False, "briefs": "full"}, "briefs full requires include_briefs; omit include_briefs or use true"),
])
def test_mb3_2_class_b_recovery_combinations(mb3_pilot, arguments, error):
    root, _ = mb3_pilot
    assert payload(mb3_call(mb3_connection(root), arguments)) == {"error": error}


@pytest.mark.parametrize("already_delivered", [False, True])
@pytest.mark.parametrize("failure", ["argument", "brief", "pager", "malformed", "write", "flush"])
def test_mb3_2_class_b_failures_leave_state_unchanged(mb3_pilot, monkeypatch, already_delivered, failure):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    binding = mb3_checkpoint(root)
    mb3_seed(root)
    connection = mb3_connection(root, 2)
    args = {"include_briefs": True, "since": "current_generation", "limit": 2}
    if already_delivered:
        mb3_call(connection, {**args, "limit": 1})
    before = mb3_committed_state(connection)
    reference = Path(binding["checkpoint"]["briefs"][0]["path"])
    if failure in ("write", "flush"):
        class BrokenOutput:
            def write(self, raw):
                if failure == "write":
                    raise BrokenPipeError("consumer disconnected")
                return len(raw)
            def flush(self):
                raise BrokenPipeError("consumer disconnected at flush")
        original_open = os.open
        with monkeypatch.context() as patch:
            import io
            patch.setattr(mcp, "Connection", lambda *a, **k: connection)
            patch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(
                (json.dumps(inbox_frame({**args, "briefs": "full"})) + "\n").encode("utf-8"))))
            patch.setattr(sys, "stdout", SimpleNamespace(buffer=BrokenOutput(), fileno=lambda: 1))
            patch.setattr(os, "open", lambda p, *a, **k: 100000 if p == os.devnull else original_open(p, *a, **k))
            patch.setattr(os, "dup2", lambda *a: None)
            assert mcp.serve(root, "a/lane/f2", "host-two", "replacement", 2) == 0
    else:
        with monkeypatch.context() as patch:
            request = inbox_frame({**args, "briefs": "full"})
            if failure == "argument":
                request["params"]["arguments"]["order"] = "bad"
            elif failure == "brief":
                reference.write_bytes(b"changed")
            elif failure == "pager":
                patch.setattr(mcp, "MAX_INBOX_RESPONSE_BYTES", 1)
            else:
                mb3_call(connection, args, flush=False)
                request["params"] = []
            try:
                result = mcp.handle(connection, request)
            except ValueError:
                assert failure == "malformed"
            else:
                assert result["isError"] is True
            connection.record_inbox_page()  # serve does this after an error response too.
    assert mb3_committed_state(connection) == before
    reference.write_bytes(b"checkpoint")
    assert payload(mb3_call(connection, {"briefs": "full"}))["checkpoint_briefs"][0]["text"] == "checkpoint"


@pytest.mark.parametrize("first,second,allowed", [
    ({"order": "newest"}, {}, False), ({}, {"order": "newest"}, False),
    ({"since": "current_generation"}, {}, False), ({}, {"since": "current_generation"}, False),
    ({"order": "newest", "since": "current_generation"}, {"order": "newest"}, False),
    ({"order": "newest", "since": "current_generation"}, {"since": "current_generation"}, False),
    ({}, {}, True), ({"order": "newest"}, {"order": "newest"}, True),
    ({"since": "current_generation"}, {"since": "current_generation"}, True),
])
def test_mb3_2_class_c_cursor_options(mb3_pilot, first, second, allowed):
    root, _ = mb3_pilot
    mb3_seed(root)
    connection = mb3_connection(root)
    first_page = payload(mb3_call(connection, {**first, "limit": 2}))
    answer = mb3_call(connection, {**second, "after_message_id": first_page["next_after"], "limit": 2})
    if allowed:
        assert not answer["result"].get("isError", False)
        assert len(payload(answer)["messages"]) == 2
    else:
        assert payload(answer) == {"error": MB3_RESTART}
    for key in ("order", "since"):
        if key in first and first[key] != "oldest":
            assert first_page[key] == first[key]


@pytest.mark.parametrize("options,allowed", [({}, True), ({"order": "oldest"}, True),
                                           ({"order": "newest"}, False), ({"since": "current_generation"}, False)])
def test_mb3_2_class_c_unknown_cursor(mb3_pilot, options, allowed):
    root, _ = mb3_pilot
    mb3_seed(root)
    answer = mb3_call(mb3_connection(root), {**options, "after_message_id": "wire-001"})
    if allowed:
        assert len(payload(answer)["messages"]) == 3
    else:
        assert payload(answer) == {"error": MB3_RESTART}


@pytest.mark.parametrize("collide", [False, True])
def test_mb3_3_class1_order_collision_recovery(mb3_pilot, collide):
    root, _ = mb3_pilot
    mb3_seed(root)
    connection = mb3_connection(root)
    if collide:
        payload(mb3_call(connection, {"limit": 3}))
    mb3_call(connection, {"limit": 3, "order": "newest"})
    newest = mb3_drain(connection, {"order": "newest"}, limit=3)
    assert newest == ["wire-004", "wire-003", "wire-002", "wire-001", "wire-000"]
    # Once that non-default walk drains, a legacy/default restart must drain too.
    if collide:
        assert mb3_drain(connection, {}, limit=3) == newest[::-1]


@pytest.mark.parametrize("change", ["checkpoint", "created_at"])
def test_mb3_2_class_c_cursor_binding_identity(mb3_pilot, change):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    mb3_seed(root)
    mb3_checkpoint(root)
    connection = mb3_connection(root, 2)
    first = payload(mb3_call(connection, {"limit": 2, "order": "newest"}))
    path = root / "bindings/a/lane/f2/000002.json"
    binding = json.loads(path.read_bytes())
    if change == "created_at":
        binding["created_at"] = "2026-01-01T00:00:00.000000Z"
    else:
        binding["checkpoint"]["completed_checks"] = ["changed"]
        binding["checkpoint_sha256"] = mcp.digest(binding["checkpoint"])
    path.write_bytes(json.dumps(binding).encode("utf-8"))
    assert payload(mb3_call(connection, {"order": "newest", "after_message_id": first["next_after"]})) == {
        "error": MB3_RESTART}


@pytest.mark.parametrize("stamp", ["2099-01-01T00:00:00.000000Z", "2025-01-01T00:00:00.000000Z"])
def test_mb3_2_class_d_cutoff_drift(mb3_pilot, stamp):
    root, _ = mb3_pilot
    mb3_seed(root)
    connection = mb3_connection(root)
    mb3_call(connection, {"since": "current_generation", "limit": 1})
    mb3_binding_time(root, 1, stamp)
    before = mb3_committed_state(connection)
    answer = mb3_call(connection, {"since": "current_generation"})
    assert "omit since to read the full inbox" in payload(answer)["error"]
    assert mb3_committed_state(connection) == before
    assert len(payload(mb3_call(connection, {}))["messages"]) == 5


@pytest.mark.parametrize("checkpoint_change", [False, True])
def test_mb3_2_class_d_cutoff_frozen_before_first_since(mb3_pilot, checkpoint_change):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    mb3_checkpoint(root)
    mb3_seed(root)
    connection = mb3_connection(root, 2)
    mb3_call(connection, {"limit": 1})
    path = root / "bindings/a/lane/f2/000002.json"
    binding = json.loads(path.read_bytes())
    binding["created_at"] = "2026-01-04T00:00:00.000000Z"
    if checkpoint_change:
        binding["checkpoint"]["completed_checks"] = ["changed"]
        binding["checkpoint_sha256"] = mcp.digest(binding["checkpoint"])
    path.write_bytes(json.dumps(binding).encode("utf-8"))
    for _ in range(2):
        before = mb3_committed_state(connection)
        assert payload(mb3_call(connection, {"since": "current_generation"})) == {
            "error": "current_generation cutoff changed; omit since to read the full inbox"}
        assert mb3_committed_state(connection) == before
        # Unfiltered recovery must never replace the original frozen cutoff.
        assert len(payload(mb3_call(connection, {}))["messages"]) == 5


@pytest.mark.parametrize("stamp,allowed", [("2026-01-02T00:00:05.000000Z", True),
                                         ("2026-01-02T00:00:05.000001Z", False)])
def test_mb3_2_class_d_future_skew_boundary(mb3_pilot, monkeypatch, stamp, allowed):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    mb3_binding_time(root, 1, stamp)
    monkeypatch.setattr(mcp, "_inbox_now", lambda: datetime(2026, 1, 2, tzinfo=timezone.utc), raising=False)
    answer = mb3_call(mb3_connection(root), {"since": "current_generation"})
    if allowed:
        assert not answer["result"].get("isError", False)
    else:
        assert "omit since to read the full inbox" in payload(answer)["error"]


@pytest.mark.parametrize("binding_time,message_time,ambiguous", [
    ("2026-01-02T00:00:00Z", "2026-01-02T00:00:00.100000Z", True),
    ("2026-01-02T00:00:00.100Z", "2026-01-02T00:00:00.100000Z", True),
    ("2026-01-02T00:00:00.000000Z", "2026-01-02T00:00:00Z", False),
    ("2026-01-02T00:00:00.100Z", "2026-01-02T00:00:01Z", False),
])
def test_mb3_2_class_d_mixed_precision(mb3_pilot, binding_time, message_time, ambiguous):
    root, _ = mb3_pilot
    mb3_binding_time(root, 1, binding_time)
    mb3_message_time(invoke(root, "publish", message()), message_time)
    answer = mb3_call(mb3_connection(root), {"since": "current_generation"})
    if ambiguous:
        assert "omit since to read the full inbox" in payload(answer)["error"]
    else:
        assert len(payload(answer)["messages"]) == 1 and payload(answer)["excluded"] == 0


def test_mb3_2_class_d_pending_equal_and_excluded(mb3_pilot):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    rows = mb3_seed(root)
    for row, stamp in zip(rows[:3], ("2026-01-01T00:00:00.000000Z", "2026-01-01T00:00:00.000000Z",
                                    "2026-01-02T00:00:00.000000Z")):
        mb3_message_time(row, stamp)
    mb3_checkpoint(root)
    path = root / "bindings/a/lane/f2/000002.json"
    binding = json.loads(path.read_bytes())
    binding["checkpoint"]["pending_message_ids"] = ["wire-000"]
    binding["checkpoint_sha256"] = mcp.digest(binding["checkpoint"])
    path.write_bytes(json.dumps(binding).encode("utf-8"))
    connection = mb3_connection(root, 2)
    page = payload(mb3_call(connection, {"since": "current_generation", "limit": 2}))
    later = payload(mb3_call(connection, {"since": "current_generation", "after_message_id": page["next_after"]}))
    assert [r["message"]["message_id"] for p in (page, later) for r in p["messages"]] == [
        "wire-000", "wire-002", "wire-003", "wire-004"]
    assert page["excluded"] == later["excluded"] == 1


def test_mb3_2_class_e_description_discloses_recovery(mb3_pilot):
    root, _ = mb3_pilot
    spec = next(t for t in mb3_connection(root).definitions() if t["name"] == "mailbox_inbox")
    documentation = spec["description"] + json.dumps(spec["inputSchema"], sort_keys=True)
    for text in ("briefs", "full", "compaction", "truncation", "60000", "5 seconds", "excluded",
                 "woken_unread", "without since", "oldest"):
        assert text in documentation
    assert spec["inputSchema"]["properties"]["briefs"]["enum"] == ["full"]


def test_mb3_2_class_f_pager_negative_control(monkeypatch):
    import hierarchy_mailbox_mcp as mcp
    result = mb3_result(["x", "y", "z"])
    expected = mb3_oracle_response(result)
    def equivalent():
        assert mcp._response_line(mb3_handler_page(result)) == expected
    equivalent()
    real = mcp._bounded_inbox
    def off_by_one(page, render):
        answer = real(page, render)
        answer["messages"] = answer["messages"][:-1]
        return answer
    monkeypatch.setattr(mcp, "_bounded_inbox", off_by_one)
    with pytest.raises(AssertionError):
        equivalent()


def test_mb3_2_class_f_changed_brief_uses_hash_not_error_text(mb3_pilot, monkeypatch):
    from hierarchy_mailbox import Mailbox
    root, _ = mb3_pilot
    binding = mb3_checkpoint(root)
    connection = mb3_connection(root, 2)
    mb3_call(connection, {"include_briefs": True})
    Path(binding["checkpoint"]["briefs"][0]["path"]).write_bytes(b"changed")
    original = Mailbox.brief
    def renamed(mailbox, brief, *, verify=True):
        if verify:
            raise ValueError("a changed pinned error message")
        return original(mailbox, brief, verify=False)
    monkeypatch.setattr(Mailbox, "brief", renamed)
    assert payload(mb3_call(connection, {"include_briefs": True}))["checkpoint_briefs"] == [
        {**binding["checkpoint"]["briefs"][0], "ok": False, "reason": "brief_changed"}]


@pytest.mark.parametrize("change", ["since", "checkpoint", "timestamp"])
def test_mb3_3_class1_nondefault_collision_recovery(mb3_pilot, change):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    mb3_checkpoint(root)
    mb3_seed(root)
    connection = mb3_connection(root, 2)
    original = payload(mb3_call(connection, {"order": "newest", "limit": 3}))
    options = {"order": "newest"}
    if change == "since":
        options["since"] = "current_generation"
    else:
        path = root / "bindings/a/lane/f2/000002.json"
        binding = json.loads(path.read_bytes())
        if change == "checkpoint":
            binding["checkpoint"]["completed_checks"] = ["changed"]
            binding["checkpoint_sha256"] = mcp.digest(binding["checkpoint"])
        else:
            binding["created_at"] = "2026-01-02T00:00:01.000000Z"
        path.write_bytes(json.dumps(binding).encode("utf-8"))
    restarted = payload(mb3_call(connection, {**options, "limit": 3}))
    assert restarted["next_after"] == original["next_after"] == "wire-002"
    assert mb3_drain(connection, options, limit=3) == ["wire-004", "wire-003", "wire-002", "wire-001", "wire-000"]


MB3_CAPACITY = "inbox walk capacity reached; finish an existing walk or restart the MCP connection"


@pytest.mark.parametrize("rewrite", ["message_ids", "binding"])
def test_mb3_3_class2_growth_stops_at_cap(mb3_pilot, monkeypatch, rewrite):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    rows = mb3_seed(root)
    connection = mb3_connection(root)
    monkeypatch.setattr(mcp, "MAX_INBOX_CURSOR_PAIRS", 3, raising=False)
    live_cursors = []
    for number in range(3):
        if rewrite == "binding":
            mb3_binding_time(root, 1, "2026-01-01T00:00:0%d.000000Z" % number)
        else:
            row = rows[3]
            new_id = "rewrite-%d" % number
            path = Path(row["path"])
            path.write_bytes(path.read_bytes().replace(row["message"]["message_id"].encode("ascii"),
                                                      new_id.encode("ascii")))
            row["message"]["message_id"] = new_id
        answer = mb3_call(connection, {"order": "newest", "limit": 2})
        assert not answer["result"].get("isError", False), payload(answer)
        live_cursors.append(payload(answer)["next_after"])
        assert sum(map(len, connection.pager.cursors.values())) == number + 1
    if rewrite == "binding":
        mb3_binding_time(root, 1, "2026-01-01T00:00:04.000000Z")
    else:
        row = rows[3]
        path = Path(row["path"])
        path.write_bytes(path.read_bytes().replace(row["message"]["message_id"].encode("ascii"), b"rewrite-3"))
        row["message"]["message_id"] = "rewrite-3"
    before = mb3_committed_state(connection)
    assert payload(mb3_call(connection, {"order": "newest", "limit": 2})) == {"error": MB3_CAPACITY}
    assert mb3_committed_state(connection) == before
    assert sum(map(len, connection.pager.cursors.values())) == 3
    # A full default read works without evicting or reclassifying live associations.
    assert len(payload(mb3_call(connection, {"limit": 100}))["messages"]) == 5
    assert sum(map(len, connection.pager.cursors.values())) == 3


def test_mb3_3_class2_default_provenance_is_freed_on_drain(mb3_pilot):
    root, _ = mb3_pilot
    mb3_seed(root)
    connection = mb3_connection(root)
    mb3_call(connection, {"limit": 1})
    assert sum(map(len, connection.pager.cursors.values())) == 1
    assert mb3_drain(connection, {}, limit=2) == ["wire-000", "wire-001", "wire-002", "wire-003", "wire-004"]
    assert connection.pager.cursors == {}


def test_mb3_3_class2_drain_frees_only_finished_context(mb3_pilot, monkeypatch):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    mb3_seed(root)
    connection = mb3_connection(root)
    monkeypatch.setattr(mcp, "MAX_INBOX_CURSOR_PAIRS", 2, raising=False)
    first = payload(mb3_call(connection, {"order": "newest", "limit": 3}))
    other = payload(mb3_call(connection, {"order": "newest", "since": "current_generation", "limit": 3}))
    assert first["next_after"] == other["next_after"] == "wire-002"
    assert sum(map(len, connection.pager.cursors.values())) == 2
    done = payload(mb3_call(connection, {"order": "newest", "after_message_id": "wire-002", "limit": 3}))
    assert done["next_after"] is None
    assert sum(map(len, connection.pager.cursors.values())) == 1
    # The still-live since context must not regain the default/unknown fallback.
    assert payload(mb3_call(connection, {"after_message_id": "wire-002"})) == {"error": MB3_RESTART}
    remaining = payload(mb3_call(connection, {"order": "newest", "since": "current_generation",
                                             "after_message_id": "wire-002", "limit": 3}))
    assert remaining["next_after"] is None
    assert connection.pager.cursors == {}
    assert len(payload(mb3_call(connection, {"after_message_id": "wire-002"}))["messages"]) == 2


def test_mb3_3_class2_cap_constant():
    import hierarchy_mailbox_mcp as mcp
    from hierarchy_mailbox import MAX_RECORDS
    assert mcp.MAX_INBOX_CURSOR_PAIRS == 4 * MAX_RECORDS


@pytest.mark.parametrize("fraction,microsecond", [("", 0), (".1", 100000), (".12", 120000),
                                                 (".123", 123000), (".1234", 123400),
                                                 (".12345", 123450), (".123456", 123456)])
def test_mb3_3_class3_timestamp_parser(fraction, microsecond):
    import hierarchy_mailbox_mcp as mcp
    # Test the MCP parser directly: pinned loaders on 3.9 can reject some valid
    # pinned-regex fractions before the MCP adapter gets control of the request.
    assert mcp._parse_inbox_time("2026-01-02T03:04:05" + fraction + "Z") == datetime(
        2026, 1, 2, 3, 4, 5, microsecond, tzinfo=timezone.utc)


@pytest.mark.parametrize("value", [None, True, 1, "", "2026-02-30T00:00:00Z", "2026-01-02T00:00:00.1234567Z",
                                   "2026-01-02T00:00:00+00:00", "٢٠٢٦-01-02T00:00:00Z"])
def test_mb3_3_class3_timestamp_refusals(value):
    import hierarchy_mailbox_mcp as mcp
    with pytest.raises(ValueError, match="^invalid UTC timestamp$"):
        mcp._parse_inbox_time(value)


@pytest.mark.parametrize("now,allowed", [(datetime(2026, 1, 1, tzinfo=timezone.utc), False), (MB3_FIXED_NOW, True)])
def test_mb3_3_class4_clock_seam(mb3_pilot, monkeypatch, now, allowed):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    mb3_checkpoint(root)
    monkeypatch.setattr(mcp, "_inbox_now", lambda: now, raising=False)
    answer = mb3_call(mb3_connection(root, 2), {"since": "current_generation"})
    if allowed:
        assert not answer["result"].get("isError", False)
    else:
        assert payload(answer) == {"error": "current_generation cutoff is in the future; omit since to read the full inbox"}


def test_mb3_3_class5_description_budget(mb3_pilot):
    root, _ = mb3_pilot
    spec = next(t for t in mb3_connection(root).definitions() if t["name"] == "mailbox_inbox")
    assert len(spec["description"].encode("utf-8")) <= 300
    documentation = (spec["description"] + json.dumps(spec["inputSchema"], sort_keys=True)).lower()
    for phrase in ("order", "newest", "since", "current_generation", "excluded", "60000", "briefs=full",
                   "session", "restart", "receipts", "returned", "woken_unread"):
        assert phrase in documentation


@pytest.mark.parametrize("options", [{"order": "newest"}, {"since": "current_generation"}])
def test_mb3_3b_immediate_default_restart_and_cleanup(mb3_pilot, options):
    root, _ = mb3_pilot
    mb3_seed(root)
    connection = mb3_connection(root)
    first = payload(mb3_call(connection, {**options, "limit": 3}))
    assert first["next_after"] == "wire-002"
    assert sum(map(len, connection.pager.cursors.values())) == 1
    default = payload(mb3_call(connection, {"limit": 3}))
    assert default["next_after"] == "wire-002"
    assert sum(map(len, connection.pager.cursors.values())) == 2
    done_default = payload(mb3_call(connection, {"limit": 3, "after_message_id": "wire-002"}))
    assert [r["message"]["message_id"] for r in done_default["messages"]] == ["wire-003", "wire-004"]
    assert done_default["remaining"] == 0 and done_default["next_after"] is None
    done_other = payload(mb3_call(connection, {**options, "limit": 3, "after_message_id": "wire-002"}))
    for start, end in ((first, done_other), (default, done_default)):
        ids = [r["message"]["message_id"] for p in (start, end) for r in p["messages"]]
        expected = ["wire-%03d" % n for n in range(5)]
        assert ids == (expected[::-1] if start.get("order") == "newest" else expected)
        assert len(ids) == len(set(ids))
        assert end["next_after"] is None and end["remaining"] == 0
    assert connection.pager.cursors == {}


@pytest.mark.parametrize("options", [{"order": "newest"}, {"since": "current_generation"}])
def test_mb3_3b_restart_recovers_over_stdio(mb3_pilot, options):
    root, _ = mb3_pilot
    mb3_seed(root)
    _, answers = mcp_wire_exchange(root, [
        inbox_frame({**options, "limit": 3}), inbox_frame({"limit": 3}),
        inbox_frame({"limit": 3, "after_message_id": "wire-002"}),
        inbox_frame({**options, "limit": 3, "after_message_id": "wire-002"}),
    ], clock=MB3_FIXED_NOW)
    assert all(not a["result"].get("isError", False) for a in answers), [payload(a) for a in answers]
    pages = [payload(a) for a in answers]
    expected = ["wire-%03d" % n for n in range(5)]
    for start, end, ids in ((pages[0], pages[3], expected[::-1] if "order" in options else expected),
                            (pages[1], pages[2], expected)):
        assert [r["message"]["message_id"] for p in (start, end) for r in p["messages"]] == ids
        assert end["remaining"] == 0 and end["next_after"] is None


@pytest.mark.parametrize("limit,allowed", [(3, False), (1, False), (100, True)])
def test_mb3_3b_collision_at_cap_refuses_before_staging(mb3_pilot, monkeypatch, limit, allowed):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    mb3_seed(root)
    connection = mb3_connection(root)
    monkeypatch.setattr(mcp, "MAX_INBOX_CURSOR_PAIRS", 1)
    mb3_call(connection, {"order": "newest", "limit": 3})
    before = mb3_committed_state(connection)
    answer = mb3_call(connection, {"limit": limit})
    assert connection.pager.pending is None
    assert mb3_committed_state(connection) == before
    if allowed:
        assert not answer["result"].get("isError", False)
        assert len(payload(answer)["messages"]) == min(limit, 5)
    else:
        assert payload(answer) == {"error": MB3_CAPACITY}
        assert connection.returned == []


def test_mb3_3b_collision_pair_reissue_at_exact_cap(mb3_pilot, monkeypatch):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    mb3_seed(root)
    connection = mb3_connection(root)
    monkeypatch.setattr(mcp, "MAX_INBOX_CURSOR_PAIRS", 2)
    mb3_call(connection, {"order": "newest", "limit": 3})
    for _ in range(2):
        answer = mb3_call(connection, {"limit": 3})
        assert not answer["result"].get("isError", False)
        assert sum(map(len, connection.pager.cursors.values())) == 2
    assert payload(mb3_call(connection, {"order": "newest", "after_message_id": "wire-002"}))["next_after"] is None
    assert sum(map(len, connection.pager.cursors.values())) == 1  # The default walk is still live.
    assert payload(mb3_call(connection, {"after_message_id": "wire-002"}))["next_after"] is None
    assert connection.pager.cursors == {}


def test_mb3_3b_cleanup_retains_default_until_last_nondefault_finishes(mb3_pilot):
    root, _ = mb3_pilot
    mb3_seed(root)
    connection = mb3_connection(root)
    walks = [{"order": "newest"}, {"order": "newest", "since": "current_generation"}]
    for options in walks:
        mb3_call(connection, {**options, "limit": 3})
    mb3_call(connection, {"limit": 3})
    assert len(connection.pager.cursors["wire-002"]) == 3
    mb3_call(connection, {**walks[0], "after_message_id": "wire-002"})
    assert len(connection.pager.cursors["wire-002"]) == 2
    default = payload(mb3_call(connection, {"after_message_id": "wire-002"}))
    assert [r["message"]["message_id"] for r in default["messages"]] == ["wire-003", "wire-004"]
    mb3_call(connection, {**walks[1], "after_message_id": "wire-002"})
    assert connection.pager.cursors == {}


@pytest.mark.parametrize("first,second", [({}, {"order": "newest"}), ({"order": "newest"}, {}),
                                         ({"since": "current_generation"}, {})])
def test_mb3_3b_wrong_walk_without_default_issuance_still_refuses(mb3_pilot, first, second):
    root, _ = mb3_pilot
    mb3_seed(root)
    connection = mb3_connection(root)
    page = payload(mb3_call(connection, {**first, "limit": 3}))
    before = mb3_committed_state(connection)
    assert payload(mb3_call(connection, {**second, "after_message_id": page["next_after"]})) == {"error": MB3_RESTART}
    assert mb3_committed_state(connection) == before


@pytest.mark.parametrize("failure", ["write", "flush"])
def test_mb3_3b_colliding_default_commits_only_after_successful_flush(mb3_pilot, monkeypatch, failure):
    import io
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    mb3_seed(root)
    connection = mb3_connection(root)
    mb3_call(connection, {"order": "newest", "limit": 3})
    before = mb3_committed_state(connection)
    class BrokenOutput:
        def write(self, raw):
            if failure == "write":
                raise BrokenPipeError("disconnected")
            return len(raw)
        def flush(self):
            raise BrokenPipeError("disconnected at flush")
    original_open = os.open
    with monkeypatch.context() as patch:
        patch.setattr(mcp, "Connection", lambda *a, **k: connection)
        patch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(
            (json.dumps(inbox_frame({"limit": 3})) + "\n").encode("utf-8"))))
        patch.setattr(sys, "stdout", SimpleNamespace(buffer=BrokenOutput(), fileno=lambda: 1))
        patch.setattr(os, "open", lambda p, *a, **k: 100000 if p == os.devnull else original_open(p, *a, **k))
        patch.setattr(os, "dup2", lambda *a: None)
        assert mcp.serve(root, "a/lane/f2", "host-one", "a/lane/f2", 1) == 0
    assert mb3_committed_state(connection) == before
    assert connection.pager.pending is None
    mb3_call(connection, {"limit": 3})
    assert sum(map(len, connection.pager.cursors.values())) == 2


@pytest.mark.parametrize("planned", [False, True])
@pytest.mark.parametrize("include_briefs", [False, True])
def test_mb3_coord2_plan_gate_preserves_legacy_pages(mb3_pilot, planned, include_briefs):
    root, _ = mb3_pilot
    binding = mb3_checkpoint(root)
    if not planned:
        (root.parent / "host-plan.json").unlink()
    _, answers = mcp_wire_exchange(root, [inbox_frame({"include_briefs": include_briefs})] * 2,
                                    host="host-two", session="replacement", generation=2)
    first, second = [payload(a) for a in answers]
    assert first["binding"] == binding
    if not planned:
        assert answers[0] == answers[1]  # Includes the actual nested MCP text bytes.
        assert second["binding"] == binding
    else:
        assert "checkpoint" not in second["binding"]
        if include_briefs:
            assert second["checkpoint_briefs"] == [{**binding["checkpoint"]["briefs"][0], "ok": True}]


@pytest.mark.parametrize("damage", ["malformed", "wrong_hierarchy", "unreadable"])
def test_mb3_coord2_bad_plan_fails_closed(mb3_pilot, monkeypatch, damage):
    root, _ = mb3_pilot
    path = root.parent / "host-plan.json"
    if damage == "malformed":
        path.write_bytes(b"{}")
    elif damage == "wrong_hierarchy":
        mb3_host_plan(root, hierarchy="b")
    else:
        original = Path.open
        def denied(target, *args, **kwargs):
            if target == path:
                raise PermissionError("private OS details")
            return original(target, *args, **kwargs)
        monkeypatch.setattr(Path, "open", denied)
    assert payload(mb3_call(mb3_connection(root), {})) == {
        "error": "invalid host plan; repair the governing plan before retrying"}


@pytest.mark.parametrize("options", [{"order": "newest"}, {"since": "current_generation"},
                                      {"order": "newest", "since": "current_generation"}])
@pytest.mark.parametrize("default_first", [False, True])
def test_mb3_coord2_prior_default_cursor_survives_other_walk(mb3_pilot, options, default_first):
    root, _ = mb3_pilot
    mb3_seed(root)
    connection = mb3_connection(root)
    sequence = ({}, options) if default_first else (options, {})
    starts = [payload(mb3_call(connection, {**option, "limit": 3})) for option in sequence]
    assert all(p["next_after"] == "wire-002" for p in starts)
    for option, first in zip(sequence, starts):
        answer = mb3_call(connection, {**option, "limit": 3, "after_message_id": "wire-002"})
        assert not answer["result"].get("isError", False), payload(answer)
        final = payload(answer)
        ids = [r["message"]["message_id"] for p in (first, final) for r in p["messages"]]
        expected = ["wire-%03d" % n for n in range(5)]
        assert ids == (expected[::-1] if option.get("order") == "newest" else expected)
        assert final["remaining"] == 0 and final["next_after"] is None
    assert connection.pager.cursors == {}


def test_mb3_coord2_legal_mailbox_transport_walk_exceeds_old_capacity(mb3_pilot):
    from hierarchy_mailbox import Mailbox, MAX_RECORDS, encoded
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    sample = mb3_seed(root, count=1)[0]
    folder = Path(sample["path"]).parent
    # Build a legal full mailbox once through the pinned parser. Replaying its
    # validated one-message pages through the public delivery lifecycle avoids
    # 100 million redundant file reads; selection/retry also use the MCP handler.
    for number in range(1, MAX_RECORDS):
        header = {**sample["message"], "message_id": "legal-%05d" % number}
        body = header.pop("body")
        (folder / ("legal-%05d.md" % number)).write_bytes(b"---\n" + encoded(header) + b"\n---\n\n" + body.encode("utf-8"))
    rows = sorted(Mailbox(root).messages().values(),
                  key=lambda r: (r["message"]["created_at"], r["message"]["message_id"]), reverse=True)
    assert len(rows) == MAX_RECORDS
    connection = mb3_connection(root)
    first = payload(mb3_call(connection, {"order": "newest", "limit": 1}))
    assert first["messages"] == rows[:1]
    for index, row in enumerate(rows[1:-1], 1):
        page = {**first, "messages": [row], "next_after": row["message"]["message_id"],
                "remaining": len(rows) - index - 1}
        size = len(mcp._response_line({"jsonrpc": "2.0", "id": "page", "result": mcp._tool_result(page)}))
        connection.note_returned(page, size)
        connection.record_inbox_page()
    count = sum(map(len, connection.pager.cursors.values()))
    assert count == MAX_RECORDS - 1
    retry = mb3_call(connection, {"order": "newest", "limit": 1,
                                "after_message_id": rows[0]["message"]["message_id"]})
    assert payload(retry)["messages"] == rows[1:2]
    assert sum(map(len, connection.pager.cursors.values())) == count
    last = mb3_call(connection, {"order": "newest", "limit": 1,
                               "after_message_id": rows[-2]["message"]["message_id"]})
    assert payload(last)["messages"] == rows[-1:]
    assert payload(last)["next_after"] is None and connection.pager.cursors == {}


def test_mb3_coord2_capacity_covers_all_option_combinations():
    from hierarchy_mailbox import MAX_RECORDS
    import hierarchy_mailbox_mcp as mcp
    assert mcp.MAX_INBOX_CURSOR_PAIRS >= 4 * (MAX_RECORDS - 1)


def test_mb3_coord2_clock_driver_does_not_write_importable_cache(mb3_pilot, monkeypatch, tmp_path_factory):
    root, _ = mb3_pilot
    directory = tmp_path_factory.mktemp("coord2-cache-" + uuid.uuid4().hex)
    source = directory / "source"
    source.mkdir()
    for name in ("hierarchy_mailbox.py", "hierarchy_mailbox_mcp.py"):
        (source / name).write_bytes((HELPER.parent / name).read_bytes())
    monkeypatch.setattr(sys.modules[__name__], "HELPER", source / "hierarchy_mailbox.py")
    _, answers = mcp_wire_exchange(root, [{"jsonrpc": "2.0", "id": "ping", "method": "ping"}], clock=MB3_FIXED_NOW)
    assert answers == [{"jsonrpc": "2.0", "id": "ping", "result": {}}]
    assert sorted(p.name for p in source.iterdir()) == ["hierarchy_mailbox.py", "hierarchy_mailbox_mcp.py"]
    # A real interpreter control demonstrates that -I ignores the environment
    # bytecode setting, so the cache assertion can catch a missing startup -B.
    control = directory / "control"
    control.mkdir()
    (control / "plain.py").write_bytes(b"value = 1\n")
    result = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0,sys.argv[1]); import plain", str(control)],
                            capture_output=True, timeout=10, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0, result.stderr
    assert (control / "__pycache__").is_dir()


def test_mb3_coord2_gate_disposition_is_documented():
    tree = ast.parse((HELPER.parent / "hierarchy_mailbox_mcp.py").read_bytes())
    index = next(i for i, node in enumerate(tree.body) if isinstance(node, ast.Assign)
                 and any(getattr(target, "id", None) == "BRIEF_DEDUPE_MAX_BYTES" for target in node.targets))
    doc = tree.body[index + 1]
    assert isinstance(doc, ast.Expr) and isinstance(doc.value, ast.Constant) and isinstance(doc.value.value, str)
    for phrase in ("flush", "agent", "truncation", "compaction", "resend"):
        assert phrase in doc.value.value.lower()


def test_mb3_coord2_preserves_gate_after_large_later_page(mb3_pilot):
    root, _ = mb3_pilot
    binding = mb3_checkpoint(root)
    connection = mb3_connection(root, 2)
    mb3_call(connection, {"include_briefs": True})
    assert connection.pager.briefs_session is not None
    mb3_message_time(invoke(root, "publish", message(body="x" * 62000)), "2026-01-03T00:00:00.000000Z")
    mb3_call(connection, {})
    assert connection.pager.session is None and connection.pager.briefs_session is None
    assert payload(mb3_call(connection, {"include_briefs": True}))["checkpoint_briefs"] == [
        {**binding["checkpoint"]["briefs"][0], "text": "checkpoint"}]


# Captured once from 5e0a718c:tools/hierarchy_mailbox_mcp.py, definitions()
# serialized as the complete tools/list response for id="list". Keep these bytes
# literal so shallow checkouts and source snapshots need no Git history/runtime.
MB3_BASELINE_NO_PLAN_TOOLS_LIST = (
    b'{"id": "list", "jsonrpc": "2.0", "result": {"tools": [{"annotations": {"readOnlyHint": true}, "descr'
    b'iption": "Read only this endpoint\'s mailbox; optionally include its hash-verified briefs. binding_on'
    b'ly returns just the binding, a hash check per checkpoint brief and the message count.", "inputSchema'
    b'": {"additionalProperties": false, "properties": {"after_message_id": {"maxLength": 80, "type": "str'
    b'ing"}, "binding_only": {"type": "boolean"}, "include_briefs": {"type": "boolean"}, "limit": {"maximu'
    b'm": 100, "minimum": 1, "type": "integer"}}, "required": [], "type": "object"}, "name": "mailbox_inbo'
    b'x"}, {"annotations": {"readOnlyHint": false}, "description": "Publish information under the configur'
    b'ed sender; grants no approval or verified completion. Answering a dispatch takes this order: 1. type'
    b' ack, acknowledgment accepted, in reply to the dispatch (a writing lane adds readiness; a reviewer a'
    b'dds none); 2. then type result or review in reply to the same dispatch, with result; 3. on a refusal'
    b', read its text and fix exactly the field it names; never re-send unchanged.", "inputSchema": {"addi'
    b'tionalProperties": false, "properties": {"acknowledgment": {"enum": ["accepted", "completed", "recei'
    b'ved"], "type": "string"}, "body": {"maxLength": 65536, "type": "string"}, "brief": {"type": "object"'
    b'}, "in_reply_to": {"maxLength": 80, "type": "string"}, "message_id": {"maxLength": 80, "type": "stri'
    b'ng"}, "readiness": {"additionalProperties": false, "description": "A writing lane\'s acceptance of it'
    b's dispatch; a reviewer sends none.", "properties": {"base_revision": {"description": "an ancestor of'
    b' the worktree HEAD", "pattern": "^[0-9a-f]{40}$", "type": "string"}, "branch": {"description": "the '
    b'worktree\'s current branch", "maxLength": 256, "minLength": 1, "type": "string"}, "enforcement_tier":'
    b' {"enum": ["advisory", "best-effort"], "type": "string"}, "hook_evidence": {"maxLength": 4096, "minL'
    b'ength": 1, "type": "string"}, "lease_expires_at": {"description": "UTC, as 2026-11-06T12:00:00Z; lat'
    b'er than now", "maxLength": 64, "pattern": "^\\\\d{4}-\\\\d{2}-\\\\d{2}T\\\\d{2}:\\\\d{2}:\\\\d{2}(?:\\\\.\\\\d{1,6})'
    b'?Z$", "type": "string"}, "lease_oid": {"pattern": "^[0-9a-f]{40}$", "type": "string"}, "lease_ref": '
    b'{"pattern": "^refs/aegis/lanes/[a-z0-9][a-z0-9_-]{0,79}$", "type": "string"}, "owned_paths": {"descr'
    b'iption": "repository-relative paths or patterns", "items": {"maxLength": 4096, "minLength": 1, "type'
    b'": "string"}, "maxItems": 256, "minItems": 1, "type": "array"}, "scan_evidence": {"maxLength": 4096,'
    b' "minLength": 1, "type": "string"}, "scan_workspace": {"description": "the same path as worktree", "'
    b'maxLength": 4096, "minLength": 1, "type": "string"}, "worktree": {"description": "absolute path of t'
    b'he lane worktree\'s root", "maxLength": 4096, "minLength": 1, "type": "string"}}, "required": ["workt'
    b'ree", "branch", "base_revision", "lease_ref", "lease_oid", "lease_expires_at", "owned_paths", "scan_'
    b'workspace", "scan_evidence", "enforcement_tier", "hook_evidence"], "type": "object"}, "receipt": {"t'
    b'ype": "object"}, "result": {"additionalProperties": false, "description": "Completion evidence on a '
    b'result or review that replies to the accepted dispatch. Nothing else goes in result; put paths, dige'
    b'sts and test detail in body.", "properties": {"checks": {"items": {"additionalProperties": false, "p'
    b'roperties": {"check": {"maxLength": 4096, "minLength": 1, "type": "string"}, "outcome": {"enum": ["p'
    b'ass", "fail", "not_run", "partial"], "type": "string"}, "reference": {"maxLength": 4096, "minLength"'
    b': 1, "type": "string"}}, "required": ["check", "outcome", "reference"], "type": "object"}, "maxItems'
    b'": 256, "minItems": 1, "type": "array"}, "lane_check": {"description": "a reference to the lane\'s ow'
    b'n check; required for every lane except the reviewer", "maxLength": 4096, "minLength": 1, "type": "s'
    b'tring"}, "source_revision": {"pattern": "^[0-9a-f]{40}$", "type": "string"}, "source_tree": {"patter'
    b'n": "^[0-9a-f]{40}$", "type": "string"}}, "required": ["source_revision", "source_tree", "checks"], '
    b'"type": "object"}, "to": {"maxLength": 256, "type": "string"}, "type": {"enum": ["ack", "brief", "di'
    b'spatch", "escalation", "info", "job_receipt", "job_request", "result", "review"], "type": "string"}}'
    b', "required": ["message_id", "to", "type", "body"], "type": "object"}, "name": "mailbox_publish"}, {'
    b'"annotations": {"readOnlyHint": false}, "description": "Acknowledge this configured successor\'s chec'
    b'kpoint; grants no owner approval.", "inputSchema": {"additionalProperties": false, "properties": {"c'
    b'heckpoint_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"}}, "required": ["checkpoint_sha256'
    b'"], "type": "object"}, "name": "mailbox_ack_handoff"}, {"annotations": {"readOnlyHint": true}, "desc'
    b'ription": "Show what this connection is configured as: endpoint, role, host, session and generation,'
    b' whether it is the current binding and has acknowledged its checkpoint, and the tools it offers. The'
    b' identity is configuration, not authentication. Changes nothing.", "inputSchema": {"additionalProper'
    b'ties": false, "properties": {}, "required": [], "type": "object"}, "name": "mailbox_self"}]}}\n'
)


def test_mb3_coord3_no_plan_codex_wire_matches_baseline(mb3_pilot):
    root, _ = mb3_pilot
    (root.parent / "host-plan.json").unlink()
    binding_path = root / "bindings/a/lane/f2/000001.json"
    binding = json.loads(binding_path.read_bytes())
    binding["host"] = "codex-cli"
    binding_path.write_bytes(json.dumps(binding).encode("utf-8"))
    frames = [{"jsonrpc": "2.0", "id": "list", "method": "tools/list"},
              {"jsonrpc": "2.0", "id": "self", "method": "tools/call", "params": {"name": "mailbox_self"}},
              inbox_frame({}, "first"), inbox_frame({}, "second"),
              *[inbox_frame({key: value}, key) for key, value in
                (("order", "newest"), ("since", "current_generation"), ("briefs", "full"))]]
    lines, answers = mcp_wire_exchange(root, frames, host="codex-cli", clock=MB3_FIXED_NOW)
    assert lines[0] == MB3_BASELINE_NO_PLAN_TOOLS_LIST, "no-plan tools/list wire bytes changed"
    assert payload(answers[1])["host"] == "codex-cli"
    assert payload(answers[2]) == payload(answers[3]), "repeated no-plan inbox changed"
    for key, answer in zip(("order", "since", "briefs"), answers[4:]):
        assert answer["result"]["isError"] is True
        assert payload(answer) == {"error": "unexpected fields: " + key}


def test_mb3_coord3_planned_discovery_and_parameters_work(mb3_pilot):
    root, _ = mb3_pilot
    mb3_seed(root, count=3)
    listed = {"jsonrpc": "2.0", "id": "list", "method": "tools/list"}
    options = {"order": "newest", "since": "current_generation", "briefs": "full", "limit": 2}
    _, answers = mcp_wire_exchange(root, [listed, inbox_frame(options),
                                         inbox_frame({**options, "after_message_id": "wire-001"}), listed],
                                    clock=MB3_FIXED_NOW)
    assert answers[0] == answers[-1]
    spec = next(t for t in answers[0]["result"]["tools"] if t["name"] == "mailbox_inbox")
    for key, values in (("order", ["oldest", "newest"]), ("since", ["current_generation"]), ("briefs", ["full"])):
        assert spec["inputSchema"]["properties"][key]["enum"] == values
    assert len(spec["description"].encode("utf-8")) <= 300
    pages = [payload(a) for a in answers[1:3]]
    assert [r["message"]["message_id"] for p in pages for r in p["messages"]] == ["wire-002", "wire-001", "wire-000"]
    assert pages[0]["next_after"] == "wire-001" and pages[1]["next_after"] is None
    assert all(r["brief_text"] == "brief" for p in pages for r in p["messages"])


def test_mb3_coord3_pure_builder_defaults_to_legacy():
    import hierarchy_mailbox_mcp as mcp
    spec = next(t for t in mcp.definitions() if t["name"] == "mailbox_inbox")
    assert len(spec["description"].encode("utf-8")) == 175
    assert set(spec["inputSchema"]["properties"]) == {"include_briefs", "limit", "after_message_id", "binding_only"}


@pytest.mark.parametrize("damage", ["malformed", "wrong_hierarchy", "unreadable"])
def test_mb3_coord3_discovery_uses_validated_plan(mb3_pilot, monkeypatch, damage):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    path = root.parent / "host-plan.json"
    if damage == "malformed":
        path.write_bytes(b"{}")
    elif damage == "wrong_hierarchy":
        mb3_host_plan(root, hierarchy="b")
    else:
        original = Path.open
        def denied(target, *args, **kwargs):
            if target == path:
                raise PermissionError("private OS detail")
            return original(target, *args, **kwargs)
        monkeypatch.setattr(Path, "open", denied)
    request = {"jsonrpc": "2.0", "id": "list", "method": "tools/list"}
    with pytest.raises(ValueError, match="^invalid host plan; repair the governing plan before retrying$"):
        mcp.handle(mb3_connection(root), request)


def test_mb3_coord3_one_plan_decision_per_inbox_call(mb3_pilot, monkeypatch):
    from contextlib import contextmanager
    root, _ = mb3_pilot
    mb3_checkpoint(root)
    connection = mb3_connection(root, 2)
    path = root.parent / "host-plan.json"
    original = Path.open
    opened = []
    @contextmanager
    def stream(target, *args, **kwargs):
        with original(target, *args, **kwargs) as handle:
            yield handle
        if target == path:
            opened.append(target)
            target.unlink()
    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", stream)
        answer = mb3_call(connection, {"briefs": "full"})
    assert not answer["result"].get("isError", False)
    assert opened == [path]
    assert connection.pager.session is not None  # The validated first snapshot, not a second absence check.
    legacy = next(t for t in connection.definitions() if t["name"] == "mailbox_inbox")
    assert "order" not in legacy["inputSchema"]["properties"]


def mb3_coord5_codex(root, *, planned=False, generation=1):
    import hierarchy_mailbox_mcp as mcp
    plan = root.parent / "host-plan.json"
    if not planned and plan.exists():
        plan.unlink()
    path = root / "bindings/a/lane/f2" / ("%06d.json" % generation)
    binding = json.loads(path.read_bytes())
    binding["host"] = "codex-cli"
    path.write_bytes(json.dumps(binding).encode("utf-8"))
    return mcp.Connection(root, "a/lane/f2", "codex-cli", binding["session"], generation)


@pytest.mark.parametrize("planned", [False, True])
@pytest.mark.parametrize("rewrite", ["created_at", "checkpoint"])
def test_mb3_coord5_flushed_cursor_binding_rewrite(mb3_pilot, planned, rewrite):
    # Real stdio: observe a flushed partial page before rewriting pinned data.
    root, _ = mb3_pilot
    mb3_checkpoint(root)
    mb3_seed(root, count=4)
    mb3_coord5_codex(root, planned=planned, generation=2)
    process = subprocess.Popen([sys.executable, "-I", "-B", str(HELPER), "--root", str(root), "serve",
                                "--endpoint", "a/lane/f2", "--host", "codex-cli", "--session", "replacement",
                                "--generation", "2"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    def request(arguments):
        process.stdin.write((json.dumps(inbox_frame(arguments)) + "\n").encode("utf-8"))
        process.stdin.flush()
        received = queue.Queue()
        threading.Thread(target=lambda: received.put(process.stdout.readline()), daemon=True).start()
        return json.loads(received.get(timeout=5))
    try:
        first = payload(request({"limit": 1}))
        assert first["next_after"] == "wire-000" and first["remaining"] == 3
        path = root / "bindings/a/lane/f2/000002.json"
        binding = json.loads(path.read_bytes())
        if rewrite == "created_at":
            binding["created_at"] = "2026-01-02T01:00:00.000000Z"
        else:
            binding["checkpoint"]["completed_checks"] = ["another-check"]
            from hierarchy_mailbox import digest
            binding["checkpoint_sha256"] = digest(binding["checkpoint"])
        path.write_bytes(json.dumps(binding).encode("utf-8"))
        answer = request({"limit": 2, "after_message_id": first["next_after"]})
        if planned:
            assert payload(answer) == {"error": MB3_RESTART}
        else:
            from hierarchy_mailbox import Mailbox
            assert payload(answer) == Mailbox(root).inbox("a/lane/f2", limit=2, after="wire-000")
            assert [r["message"]["message_id"] for r in payload(answer)["messages"]] == ["wire-001", "wire-002"]
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        assert process.stderr.read() == b""


@pytest.mark.parametrize("arguments", [{}, {"limit": 1}, {"limit": 3, "after_message_id": "wire-001"},
                                       {"after_message_id": "wire-004"}, {"include_briefs": True},
                                       {"binding_only": True}])
def test_mb3_coord5_no_plan_pages_match_pinned_wire(mb3_pilot, arguments):
    from hierarchy_mailbox import Mailbox
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    mb3_checkpoint(root)
    mb3_seed(root, content="brief é 漢字", count=5)
    connection = mb3_coord5_codex(root, generation=2)
    mailbox = Mailbox(root)
    if arguments.get("binding_only"):
        original = mailbox.binding_view("a/lane/f2")
        expected = mcp._response_line({"jsonrpc": "2.0", "id": "é-edge", "result": mcp._tool_result(original)})
    else:
        original = mailbox.inbox("a/lane/f2", include_briefs=arguments.get("include_briefs", False),
                                 limit=arguments.get("limit", 20), after=arguments.get("after_message_id"))
        expected = mb3_oracle_response(original)
    for _ in range(2):
        result = mcp.handle(connection, inbox_frame(arguments, "é-edge"))
        actual = mcp._response_line({"jsonrpc": "2.0", "id": "é-edge", "result": result})
        assert actual == expected
        connection.record_inbox_page()
        assert mb3_committed_state(connection) == (None, None, {}, {})


@pytest.mark.parametrize("arguments,error", [
    ({"order": "oldest"}, "unexpected fields: order"),
    ({"order": None}, "unexpected fields: order"),
    ({"since": "current_generation"}, "unexpected fields: since"),
    ({"briefs": "full"}, "unexpected fields: briefs"),
    ({"binding_only": True, "briefs": "full"}, "unexpected fields: briefs"),
    ({"fields": []}, "unexpected fields: fields"),
    ({"binding_only": 1}, "binding_only must be boolean"),
    ({"binding_only": True, "limit": 1}, "binding_only takes no include_briefs, limit or after_message_id"),
    ({"include_briefs": 1}, "include_briefs must be boolean"),
    ({"limit": 0}, "invalid inbox limit"),
    ({"after_message_id": "missing"}, "inbox cursor does not name a received message"),
    ({"after_message_id": "BAD"}, "invalid after message id"),
])
def test_mb3_coord5_no_plan_legacy_refusals(mb3_pilot, arguments, error):
    root, _ = mb3_pilot
    connection = mb3_coord5_codex(root)
    answer = mb3_call(connection, arguments)
    assert answer["result"]["isError"] is True
    assert payload(answer) == {"error": error}


def test_mb3_coord5_no_plan_does_not_freeze_future_planned_cutoff(mb3_pilot):
    root, _ = mb3_pilot
    mb3_seed(root)
    connection = mb3_coord5_codex(root)
    mb3_call(connection, {"limit": 1})
    mb3_binding_time(root, 1, "2026-01-02T00:00:00.000000Z")
    mb3_host_plan(root)
    page = mb3_call(connection, {"since": "current_generation"})
    assert not page["result"].get("isError", False), payload(page)
    assert len(payload(page)["messages"]) == 5


@pytest.mark.parametrize("tool,arguments", [("mailbox_inbox", {}), ("mailbox_inbox", {"binding_only": True}),
                                           ("mailbox_self", {})])
def test_mb3_coord5_no_plan_preserves_binding_reread(mb3_pilot, monkeypatch, tool, arguments):
    # Change a valid file at the OS read boundary, after fencing read its old bytes.
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    connection = mb3_coord5_codex(root)
    path = root / "bindings/a/lane/f2/000001.json"
    updated = {**json.loads(path.read_bytes()), "created_at": "2026-01-02T00:00:00.000000Z",
               "host": "codex-rebound"}
    original = Path.open
    from contextlib import contextmanager
    changed = []
    @contextmanager
    def opened(target, *args, **kwargs):
        with original(target, *args, **kwargs) as stream:
            yield stream
        if target == path and not changed:
            changed.append(True)
            with original(path, "wb") as stream:
                stream.write(json.dumps(updated).encode("utf-8"))
    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", opened)
        answer = {"result": mcp.handle(connection, {"jsonrpc": "2.0", "id": "race", "method": "tools/call",
                                                  "params": {"name": tool, "arguments": arguments}})}
    assert not answer["result"].get("isError", False), payload(answer)
    binding = payload(answer) if tool == "mailbox_self" else payload(answer)["binding"]
    assert changed == [True] and binding["host"] == "codex-rebound"


def test_mb3_coord5_no_plan_discovery_and_mcp_metadata(mb3_pilot):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    mb3_coord5_codex(root)
    frames = [{"jsonrpc": "2.0", "id": "list", "method": "tools/list"}, inbox_frame({}),
              {"jsonrpc": "2.0", "id": "list", "method": "tools/list"},
              {"jsonrpc": "2.0", "id": "ping", "method": "ping"}]
    lines, answers = mcp_wire_exchange(root, frames, host="codex-cli", clock=MB3_FIXED_NOW)
    assert lines[0] == lines[2] == MB3_BASELINE_NO_PLAN_TOOLS_LIST
    assert lines[-1] == b'{"id": "ping", "jsonrpc": "2.0", "result": {}}\n'
    assert set(answers[1]["result"]) == {"content"}
    connection = mb3_coord5_codex(root)
    assert mcp.handle(connection, {"jsonrpc": "2.0", "id": "init", "method": "initialize"}) == {
        "protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
        "serverInfo": {"name": "aegis-hierarchy-mailbox", "version": "1"},
        "instructions": "File-mailbox convention only. Configured sender provenance is not authenticated identity. "
                        "Acknowledgments confer no approval, membership, execution proof or fitness credit."}


def test_mb3_coord5_no_plan_byte_boundary_and_linear_renders(mb3_pilot, monkeypatch):
    from hierarchy_mailbox import Mailbox, _bounded_inbox as legacy_pager
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    mb3_seed(root, content="é" * 100000, count=20)
    connection = mb3_coord5_codex(root)
    original = Mailbox(root).inbox("a/lane/f2", include_briefs=True)
    render = mcp._response_line
    counts = []
    def counted(response):
        counts.append(len(response["result"]["content"][0]["text"]))
        return render(response)
    expected_page = legacy_pager(original, lambda p: counted({
        "jsonrpc": "2.0", "id": "budget", "result": mcp._tool_result(p)}))
    expected_renders = len(counts)
    assert 0 < len(expected_page["messages"]) < 20
    counts.clear()
    with monkeypatch.context() as patch:
        patch.setattr(mcp, "_response_line", counted)
        result = mcp.handle(connection, inbox_frame({"include_briefs": True}, "budget"))
    assert len(counts) == expected_renders
    assert render({"jsonrpc": "2.0", "id": "budget", "result": result}) == render({
        "jsonrpc": "2.0", "id": "budget", "result": mcp._tool_result(expected_page)})


def test_mb3_coord5_no_plan_changed_brief_uses_legacy_errors(mb3_pilot):
    root, _ = mb3_pilot
    binding = mb3_checkpoint(root)
    connection = mb3_coord5_codex(root, generation=2)
    first = mb3_call(connection, {"include_briefs": True})
    assert payload(first)["checkpoint_briefs"][0]["text"] == "checkpoint"
    Path(binding["checkpoint"]["briefs"][0]["path"]).write_bytes(b"changed")
    answer = mb3_call(connection, {"include_briefs": True})
    assert answer["result"]["isError"] is True
    assert payload(answer) == {"error": "brief sha256 mismatch"}
    view = payload(mb3_call(connection, {"binding_only": True}))
    assert view["checkpoint_briefs"] == [{**binding["checkpoint"]["briefs"][0], "ok": False}]


def test_mb3_coord5_no_plan_ignores_prior_planned_cursor_state(mb3_pilot):
    root, _ = mb3_pilot
    mb3_seed(root)
    connection = mb3_coord5_codex(root, planned=True)
    first = payload(mb3_call(connection, {"order": "newest", "limit": 3}))
    assert first["next_after"] == "wire-002"
    (root.parent / "host-plan.json").unlink()
    mb3_binding_time(root, 1, "2026-01-02T00:00:00.000000Z")
    page = payload(mb3_call(connection, {"after_message_id": first["next_after"]}))
    assert [r["message"]["message_id"] for r in page["messages"]] == ["wire-003", "wire-004"]
    assert page["next_after"] is None and page["remaining"] == 0


@pytest.mark.parametrize("host", [None, "codex-cli", "claude-code"])
@pytest.mark.parametrize("body", ["x" * 60000, 'é😀"\\\n' * 1000], ids=["ascii", "utf8-escapes"])
def test_mb6_publish_receipt_and_legacy_wire_bytes(mb3_pilot, host, body):
    root, _ = mb3_pilot
    if host is None:
        (root.parent / "host-plan.json").unlink()
    else:
        mb3_host_plan(root, host=host)
    arguments = {"message_id": "mb6-publish", "to": "a/orchestrator", "type": "info", "body": body}
    frame = {"jsonrpc": "2.0", "id": "publish", "method": "tools/call",
             "params": {"name": "mailbox_publish", "arguments": arguments}}
    lines, answers = mcp_wire_exchange(root, [frame])
    assert not answers[0]["result"].get("isError", False), payload(answers[0])
    row, = invoke(root, "inbox", endpoint="a/orchestrator")["messages"]
    raw = Path(row["path"]).read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    assert row["message"]["body"] == body
    assert row["message"]["from"] == "a/lane/f2"
    assert row["message"]["authority"] == "information_only"
    print("MB6 publish wire bytes:", host, len(lines[0]))
    if host is None:
        expected = {**row, "sha256": sha256}
    else:
        expected = {"id": arguments["message_id"], "path": row["path"], "sha256": sha256,
                    "created_at": row["message"]["created_at"], "size": len(raw)}
    assert payload(answers[0]) == expected
    expected_response = {"jsonrpc": "2.0", "id": "publish", "result": {
        "content": [{"type": "text", "text": json.dumps(expected, sort_keys=True)}]}}
    assert lines[0] == (json.dumps(expected_response, sort_keys=True) + "\n").encode("utf-8")


@pytest.mark.parametrize("damage", ["malformed", "wrong_hierarchy", "unreadable"])
def test_mb6_publish_refuses_invalid_plan_before_writing(mb3_pilot, monkeypatch, damage):
    import hierarchy_hosts
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    connection = mb3_connection(root)
    path = root.parent / "host-plan.json"
    if damage == "malformed":
        path.write_bytes(b"{}")
    elif damage == "wrong_hierarchy":
        mb3_host_plan(root, hierarchy="b")
    before = mailbox_snapshot(root)
    with monkeypatch.context() as patch:
        if damage == "unreadable":
            original = hierarchy_hosts.read_json
            def denied(target):
                if target == path:
                    raise PermissionError("private OS detail")
                return original(target)
            patch.setattr(hierarchy_hosts, "read_json", denied)
        result = mcp.handle(connection, {"jsonrpc": "2.0", "id": "publish", "method": "tools/call", "params": {
            "name": "mailbox_publish", "arguments": {
                "message_id": "mb6-refused", "to": "a/orchestrator", "type": "info", "body": "private body"}}})
    assert result["isError"] is True
    assert json.loads(result["content"][0]["text"]) == {
        "error": "invalid host plan; repair the governing plan before retrying"}
    assert mailbox_snapshot(root) == before


@pytest.mark.parametrize("error", [FileNotFoundError, PermissionError])
def test_mb6_publish_stat_failure_is_a_sanitized_refusal(mb3_pilot, monkeypatch, error):
    import hierarchy_mailbox_mcp as mcp
    root, _ = mb3_pilot
    connection = mb3_connection(root)
    def unavailable(path):
        raise error("private OS detail: " + str(path))
    monkeypatch.setattr(mcp, "os", SimpleNamespace(stat=unavailable))
    result = mcp.handle(connection, {"jsonrpc": "2.0", "id": "publish", "method": "tools/call", "params": {
        "name": "mailbox_publish", "arguments": {
            "message_id": "mb6-stat", "to": "a/orchestrator", "type": "info", "body": "private body"}}})
    assert result["isError"] is True
    assert json.loads(result["content"][0]["text"]) == {
        "error": "published message metadata unavailable; inspect the mailbox before retrying"}
    row, = invoke(root, "inbox", endpoint="a/orchestrator")["messages"]
    assert row["message"]["message_id"] == "mb6-stat"
