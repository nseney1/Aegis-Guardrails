"""The MCP surface: registered tools, no receipts, no session token, no execution tier.

These drive ``handle_request`` end to end, the way a host does over stdio.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import aegis_mcp.server as server

SURVIVING_TOOLS = {tool["name"] for tool in json.loads(
    (Path(__file__).resolve().parents[2] / "contract" / "mcp_tools.json").read_text(encoding="utf-8"))["tools"]}

REMOVED_TOOLS = [
    "aegis_request_receipt",
    "aegis_propose_change",
    "aegis_audit_security",
    "aegis_audit_performance",
    "aegis_verify_changes",
    "aegis_poll_verification",
    "aegis_checkpoint",
    "aegis_generate_manifest",
    "aegis_grade",
    "aegis_coverage",
    "aegis_rule_fitness",
    "aegis_handoff",
]


@pytest.fixture
def initialized(tmp_path, monkeypatch):
    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    monkeypatch.setattr(server, "_canonical_workspace", str(tmp_path))
    monkeypatch.setattr(server, "_workspace_error", None)
    monkeypatch.setattr(server, "_session_id", None)
    response = server.handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"clientInfo": {"name": "pytest"}},
    })
    return response


def _list_tools():
    return server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})


def _call(name, arguments):
    return server.handle_request({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })


def test_execution_env_flag_no_longer_widens_the_surface(initialized, monkeypatch):
    monkeypatch.setenv("AEGIS_EXECUTION_ENABLED", "1")
    names = {tool["name"] for tool in _list_tools()["result"]["tools"]}
    assert names == SURVIVING_TOOLS


@pytest.mark.parametrize("name", REMOVED_TOOLS)
def test_removed_tool_is_an_unknown_tool_protocol_error(initialized, name):
    response = _call(name, {})
    assert response["error"] == {"code": -32602, "message": f"Unknown tool: {name}"}


def test_initialize_hands_out_no_session_token(initialized):
    server_info = initialized["result"]["serverInfo"]
    assert set(server_info) == {"name", "version"}


def test_tools_call_before_initialize_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_canonical_workspace", str(tmp_path))
    monkeypatch.setattr(server, "_session_id", None)
    response = _call("aegis_list_rules", {})
    assert response["error"] == {"code": -32002, "message": "Server not initialized"}


def test_write_tool_runs_without_a_receipt_or_token(initialized, monkeypatch):
    monkeypatch.setenv("AEGIS_REQUIRE_SESSION_TOKEN", "1")
    response = _call("aegis_create_rule", {"description": "no eval on user input"})
    assert response["result"]["isError"] is False
    payload = json.loads(response["result"]["content"][0]["text"])
    assert "prompt" in payload


def test_read_tool_ignores_a_client_chosen_workspace(tmp_path, monkeypatch):
    def governed(root, rule):
        rules = root / ".aegis" / "rules" / "traps"
        rules.mkdir(parents=True)
        (rules / f"{rule}.md").write_text(f"---\nid: {rule}\ntype: trap\nhypothesis: h\n---\n", encoding="utf-8")
        return root

    canonical = governed(tmp_path / "canonical", "rule-canonical")
    other = governed(tmp_path / "other", "rule-other")
    monkeypatch.setattr(server, "_canonical_workspace", str(canonical))
    monkeypatch.setattr(server, "_workspace_error", None)
    monkeypatch.setattr(server, "_session_id", "session-test")

    response = _call("aegis_list_rules", {"workspace": str(other)})

    names = {rule.get("_name") for rule in json.loads(response["result"]["content"][0]["text"])["rules"]}
    assert names == {"rule-canonical"}


def test_serving_every_tool_never_imports_the_sdk(tmp_path):
    """aegis_mcp calls aegis_core directly; aegis_sdk is a facade for external callers only."""
    import subprocess
    import sys
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[3]
    script = (
        "import json, sys\n"
        "from aegis_mcp.tools import execute_tool\n"
        "ws = sys.argv[1]\n"
        "execute_tool('aegis_scan', {'workspace': ws, 'files': ['a.py']})\n"
        "execute_tool('aegis_list_rules', {'workspace': ws})\n"
        "execute_tool('aegis_create_rule', {'workspace': ws, 'description': 'x'})\n"
        "execute_tool('aegis_report_outcome', {'workspace': ws, 'outcome': 'tp', 'idempotency_key': 'k'})\n"
        "print(json.dumps(sorted(m for m in sys.modules if m.split('.')[0] == 'aegis_sdk')))\n"
    )
    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    proc = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        cwd=repo_root, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout.strip().splitlines()[-1]) == []
