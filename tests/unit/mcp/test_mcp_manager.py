"""Public stdio manager registration is separate from repository governance."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tests.helpers_manager import manager_root

REPO = Path(__file__).resolve().parents[3]


def exchange(tmp_path, calls=(), environment=None):
    env = dict(os.environ, PYTHONPATH=str(REPO))
    env.pop("AEGIS_WORKSPACE", None)
    env.pop("AEGIS_MANAGER_CONFIG", None)
    env.update(environment or {})
    if "AEGIS_MANAGER_CONFIG" in env:
        env.setdefault("AEGIS_MANAGER_CONFIG_SHA256", "0" * 64)
    messages = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "clientInfo": {"name": "pytest", "version": "test"}, "capabilities": {"roots": {}}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    messages.extend({"jsonrpc": "2.0", "id": i + 3, "method": "tools/call", "params": {
        "name": name, "arguments": args}} for i, (name, args) in enumerate(calls))
    result = subprocess.run([sys.executable, "-m", "aegis_mcp"], cwd=tmp_path, env=env,
                            input="".join(json.dumps(item) + "\n" for item in messages),
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return [json.loads(line) for line in result.stdout.splitlines()]


def test_manager_advertises_three_separate_schemas(tmp_path):
    responses = exchange(tmp_path, environment={"AEGIS_MANAGER_CONFIG": str(tmp_path / "draft.json")})
    assert responses[0]["result"]["serverInfo"]["name"] == "aegis-manager-mcp"
    definitions = {item["name"]: item for item in responses[1]["result"]["tools"]}
    assert set(definitions) == {"aegis_scan", "aegis_list_rules", "aegis_report_outcome"}
    assert set(definitions["aegis_scan"]["inputSchema"]["properties"]) == {"action", "context"}
    assert definitions["aegis_scan"]["inputSchema"]["additionalProperties"] is False
    assert definitions["aegis_scan"]["annotations"]["readOnlyHint"] is False
    assert "audit" in responses[0]["result"]["instructions"].lower()
    assert not (tmp_path / ".aegis").exists()


@pytest.mark.parametrize("field", ["scope", "workspace", "identity", "host", "session", "approval",
                                    "_host", "_session", "_binding", "files", "native_identity"])
def test_manager_refuses_forged_server_fields_before_config_read(tmp_path, field):
    response = exchange(tmp_path, [("aegis_scan", {"action": "handoff", "context": {}, field: "forged"})],
                        {"AEGIS_MANAGER_CONFIG": str(tmp_path / "absent.json")})[-1]
    assert response["error"]["code"] == -32602
    assert "unexpected manager argument" in response["error"]["message"]
    assert field in response["error"]["message"]


def test_manager_refuses_nested_context_scope(tmp_path):
    response = exchange(tmp_path, [("aegis_scan", {"action": "handoff", "context": {"member_id": "aegis", "worktree_id": "main", "scope": "forged"}})],
                        {"AEGIS_MANAGER_CONFIG": str(tmp_path / "absent.json")})[-1]
    assert response["error"]["code"] == -32602
    assert "scope" in response["error"]["message"]


def test_manager_cannot_advertise_or_call_implementation_tools(tmp_path):
    response = exchange(tmp_path, [("aegis_create_rule", {"description": "forged"})],
                        {"AEGIS_MANAGER_CONFIG": str(tmp_path / "absent.json")})[-1]
    assert response["error"] == {"code": -32602, "message": "Unknown tool: aegis_create_rule"}


def test_manager_rejects_conflicting_startup_scope(tmp_path):
    response = exchange(tmp_path, [("aegis_list_rules", {})], {
        "AEGIS_MANAGER_CONFIG": str(tmp_path / "draft.json"), "AEGIS_WORKSPACE": str(tmp_path)})[-1]
    payload = json.loads(response["result"]["content"][0]["text"])
    assert response["result"]["isError"] is True
    assert payload["reason"] == "conflicting_manager_scope"


def test_repository_registration_keeps_original_surface_and_parent_refusal(tmp_path):
    responses = exchange(tmp_path, [("aegis_scan", {"files": ["unknown.py"]})])
    definitions = {item["name"]: item for item in responses[1]["result"]["tools"]}
    contract = json.loads((REPO / "tests" / "contract" / "mcp_tools.json").read_text(encoding="utf-8"))
    assert set(definitions) == {tool["name"] for tool in contract["tools"]}
    assert "files" in definitions["aegis_scan"]["inputSchema"]["properties"]
    payload = json.loads(responses[-1]["result"]["content"][0]["text"])
    assert payload["status"] == "not_governed"
    assert not (tmp_path / ".git").exists()
    assert not (tmp_path / ".aegis").exists()


@pytest.mark.parametrize("arguments", [
    {"action": "handoff", "context": {"member_id": "aegis", "worktree_id": "main", "role": {"scope": "owner"}}},
    {"action": "handoff", "context": {"member_id": "aegis", "worktree_id": "main", "summary": "s" * 4097}},
    {"action": "code_change", "context": {"member_id": "aegis", "worktree_id": "main"}},
])
def test_manager_refuses_unbounded_or_executable_context(tmp_path, arguments):
    response = exchange(tmp_path, [("aegis_scan", arguments)],
                        {"AEGIS_MANAGER_CONFIG": str(tmp_path / "absent.json")})[-1]
    assert response["error"]["code"] == -32602


def test_manager_evidence_rejects_scope_and_file_read_fields(tmp_path):
    arguments = {"decision_ref": "a" * 64, "rules_used": [], "outcome": "success", "idempotency_key": "k",
                 "evidence": [{"member_id": "aegis", "worktree_id": "main", "source_tree": "a" * 40,
                               "check": "pytest", "rule_id": "handoff", "rule_revision": "a" * 64,
                               "reference": "claim", "read_file": "/forged"}]}
    response = exchange(tmp_path, [("aegis_report_outcome", arguments)],
                        {"AEGIS_MANAGER_CONFIG": str(tmp_path / "absent.json")})[-1]
    assert response["error"]["code"] == -32602
    assert "read_file" in response["error"]["message"]


@pytest.mark.parametrize("digest", ["", "forged", "A" * 64])
def test_manager_requires_digest_pinned_registration(tmp_path, digest):
    response = exchange(tmp_path, [("aegis_list_rules", {})], {
        "AEGIS_MANAGER_CONFIG": str(tmp_path / "draft.json"), "AEGIS_MANAGER_CONFIG_SHA256": digest})[-1]
    payload = json.loads(response["result"]["content"][0]["text"])
    assert response["result"]["isError"] is True
    assert payload["reason"] == "invalid_manager_registration"


@pytest.mark.parametrize("bad", [
    '{"jsonrpc":"2.0","id":3,"method":"ping","params":{"scope":"one","scope":"two"}}',
    '{"jsonrpc":"2.0","id":3,"method":"ping","params":{"value":NaN}}',
    '{"jsonrpc":"2.0","id":3,"method":"ping","params":{"value":Infinity}}',
    '{"jsonrpc":"2.0","id":1e999,"method":"ping"}',
    '{"jsonrpc":"2.0","id":3,"method":"ping","params":{"value":1e999}}',
])
def test_manager_protocol_rejects_ambiguous_json_and_continues(tmp_path, bad):
    env = dict(os.environ, PYTHONPATH=str(REPO), AEGIS_MANAGER_CONFIG=str(tmp_path / "draft.json"),
               AEGIS_MANAGER_CONFIG_SHA256="0" * 64)
    env.pop("AEGIS_WORKSPACE", None)
    ping = json.dumps({"jsonrpc": "2.0", "id": 4, "method": "ping"})
    result = subprocess.run([sys.executable, "-m", "aegis_mcp"], cwd=tmp_path, env=env,
                            input=bad + "\n" + ping + "\n", capture_output=True,
                            text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    frames = [json.loads(line) for line in result.stdout.splitlines()]
    assert frames[0]["error"]["code"] == -32700
    assert frames[1] == {"jsonrpc": "2.0", "id": 4, "result": {}}


def test_real_manager_scan_report_and_reconnect_keep_claims_separate(manager_root):
    from tests.helpers_manager import active, prepare

    tmp_path = manager_root
    prepared = prepare(tmp_path)
    active(prepared)
    digest = __import__("hashlib").sha256(prepared["config"].read_bytes()).hexdigest()
    env = {"AEGIS_MANAGER_CONFIG": str(prepared["config"]), "AEGIS_MANAGER_CONFIG_SHA256": digest}
    frames = exchange(tmp_path, [("aegis_scan", {"action": "handoff", "context": prepared["context"]})], env)
    response = frames[-1]["result"]
    assert response["isError"] is False, response
    decision = json.loads(response["content"][0]["text"])
    assert decision["scope"] == "manager"
    assert [rule["id"] for rule in decision["rules"]] == ["manager-handoff"]
    assert decision["provenance"]["native_identity"] is None
    assert decision["provenance"]["client_identity"] == "self_reported"
    arguments = {"decision_ref": decision["decision_ref"], "rules_used": ["manager-handoff"],
                 "outcome": "success", "tests_passed": True, "idempotency_key": "process-retry", "evidence": []}
    first = exchange(tmp_path, [("aegis_report_outcome", arguments)], env)[-1]
    first = json.loads(first["result"]["content"][0]["text"])
    assert first["fitness_credit"] == 0
    assert first["execution"] == "unverified"
    assert first["human_approval"] == "not_established"
    assert first["verified_completion"] is False
    second = exchange(tmp_path, [("aegis_report_outcome", arguments)], env)[-1]
    second = json.loads(second["result"]["content"][0]["text"])
    assert second == first
    conflict = exchange(tmp_path, [("aegis_report_outcome", dict(arguments, outcome="failure"))], env)[-1]
    assert conflict["result"]["isError"] is True
    assert json.loads(conflict["result"]["content"][0]["text"])["error"] == "idempotency_conflict"


def test_repository_registration_imports_no_manager_implementation(tmp_path):
    env = dict(os.environ, PYTHONPATH=str(REPO))
    env.pop("AEGIS_MANAGER_CONFIG", None)
    script = "import json,sys; import aegis_mcp.server; print(json.dumps([m for m in sys.modules if m.startswith('aegis_core.manager')]))"
    result = subprocess.run([sys.executable, "-c", script], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == []


@pytest.mark.parametrize("reference", ["a" * 63, "A" * 64, "g" * 64])
def test_manager_report_requires_exact_decision_reference(tmp_path, reference):
    arguments = {"decision_ref": reference, "rules_used": [], "outcome": "success", "idempotency_key": "k"}
    response = exchange(tmp_path, [("aegis_report_outcome", arguments)],
                        {"AEGIS_MANAGER_CONFIG": str(tmp_path / "absent.json")})[-1]
    assert response["error"]["code"] == -32602
    assert "decision_ref" in response["error"]["message"]
