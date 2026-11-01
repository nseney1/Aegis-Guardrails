"""Restricted roles can use the file protocol without general write/shell tools."""
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


def exchange(root, calls=(), *, endpoint="a/lane/review", session=None, host="host-one", generation=1, raw=None):
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    frames.extend({"jsonrpc": "2.0", "id": index + 3, "method": "tools/call", "params": {
        "name": name, "arguments": arguments}} for index, (name, arguments) in enumerate(calls))
    result = subprocess.run([sys.executable, "-I", str(HELPER), "--root", str(root), "serve",
                             "--endpoint", endpoint, "--host", host, "--session", session or endpoint,
                             "--generation", str(generation)], input=raw or "".join(json.dumps(f) + "\n" for f in frames),
                            capture_output=True, text=True, timeout=15,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert not result.stderr
    return [json.loads(line) for line in result.stdout.splitlines()]


def payload(response):
    return json.loads(response["result"]["content"][0]["text"])


def test_transport_advertises_only_scoped_mailbox_tools(pilot):
    root, _ = pilot
    responses = exchange(root)
    assert responses[0]["result"]["serverInfo"]["name"] == "aegis-hierarchy-mailbox"
    tools = {t["name"]: t for t in responses[1]["result"]["tools"]}
    assert set(tools) == {"mailbox_inbox", "mailbox_publish", "mailbox_ack_handoff"}
    assert tools["mailbox_inbox"]["annotations"]["readOnlyHint"] is True
    assert tools["mailbox_publish"]["annotations"]["readOnlyHint"] is False
    assert all(t["inputSchema"]["additionalProperties"] is False for t in tools.values())
    assert not {"from", "host", "session", "binding_generation", "root"} & set(
        tools["mailbox_publish"]["inputSchema"]["properties"])


def test_reviewer_reads_its_brief_and_reports_without_source_write_tools(pilot):
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
def test_tool_arguments_cannot_override_startup_identity_or_authority(pilot, field):
    root, _ = pilot
    request = {"message_id": "forged", "to": "a/orchestrator", "type": "info", "body": "data", field: "forged"}
    response = exchange(root, [("mailbox_publish", request)])[-1]
    assert response["result"]["isError"] is True
    assert "unexpected fields" in payload(response)["error"]
    assert list(root.glob("**/*.md")) == []


def test_successor_can_acknowledge_before_becoming_ready(pilot):
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


def test_malformed_frame_is_explicit_and_next_request_still_works(pilot):
    root, _ = pilot
    raw = '{"jsonrpc":"2.0","id":1,"id":2}\n' + json.dumps({"jsonrpc": "2.0", "id": 3, "method": "ping"}) + "\n"
    responses = exchange(root, raw=raw)
    assert responses[0]["error"]["code"] == -32700
    assert "duplicate JSON key" in responses[0]["error"]["message"]
    assert responses[1] == {"jsonrpc": "2.0", "id": 3, "result": {}}


def test_running_adapter_rejects_replaced_sender_and_changed_manifest(pilot):
    root, brief = pilot
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
        response = call(2, "tools/call", {"name": "mailbox_publish", "arguments": {
            "message_id": "stale", "to": "a/orchestrator", "type": "info", "body": "stale sender"}})
        assert payload(response)["error"] == "stale or mismatched sender binding"
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


def test_scoped_adapter_does_not_write_python_cache_in_source_checkout(pilot, tmp_path):
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


def test_oversized_frame_closes_without_parsing_fragments(pilot):
    root, _ = pilot
    responses = exchange(root, raw="x" * 262145 + "\n")
    assert responses == [{"jsonrpc": "2.0", "id": None, "error": {
        "code": -32700, "message": "mailbox frame exceeds 262144 bytes"}}]


def test_locked_mailbox_refuses_mutation_without_partial_files(pilot):
    root, _ = pilot
    (root / ".write.lock").write_text("fixture active writer")
    response = exchange(root, [("mailbox_publish", {"message_id": "busy", "to": "a/orchestrator",
                                                   "type": "info", "body": "data"})])[-1]
    assert "writer is busy" in payload(response)["error"]
    assert list(root.glob("**/*.md")) == []


def test_front_door_authors_hash_bound_brief_using_only_scoped_tools(pilot):
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
