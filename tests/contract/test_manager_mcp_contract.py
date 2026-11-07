"""Manager tools/list has its own wire contract; repository tools stay unchanged.

Regenerate the reviewed manager surface from an isolated stdio registration:

    PYTHONPATH=. python3 tests/contract/test_manager_mcp_contract.py --write
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

SNAPSHOT = Path(__file__).with_name("manager_mcp_tools.json")
REPO = Path(__file__).resolve().parents[2]


def live_tools_list():
    environment = dict(os.environ, AEGIS_MANAGER_CONFIG=str(REPO / "unloaded-manager-contract.json"),
                       AEGIS_MANAGER_CONFIG_SHA256="0" * 64)
    environment.pop("AEGIS_WORKSPACE", None)
    code = ("import sys; sys.path.insert(0,sys.argv[1]); "
            "from aegis_mcp.server import run_stdio_server; raise SystemExit(run_stdio_server())")
    requests = [{"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    process = subprocess.run([sys.executable, "-I", "-c", code, str(REPO)], cwd=REPO,
                             input="".join(json.dumps(item) + "\n" for item in requests),
                             env=environment, capture_output=True, text=True, timeout=30, check=False)
    assert process.returncode == 0, process.stderr
    frames = [json.loads(line) for line in process.stdout.splitlines()]
    assert frames[0]["result"]["serverInfo"]["name"] == "aegis-manager-mcp"
    return frames[1]["result"]


def test_manager_tools_match_their_separate_contract():
    assert SNAPSHOT.is_file(), "regenerate the separate manager MCP contract snapshot"
    assert live_tools_list() == json.loads(SNAPSHOT.read_text(encoding="utf-8"))


def test_manager_contract_keeps_authority_and_scope_out_of_tool_arguments():
    tools = {tool["name"]: tool for tool in live_tools_list()["tools"]}
    assert set(tools) == {"aegis_scan", "aegis_list_rules", "aegis_report_outcome"}
    scan = tools["aegis_scan"]["inputSchema"]
    assert set(scan["properties"]) == {"action", "context"}
    assert set(scan["required"]) == {"action", "context"}
    assert scan["additionalProperties"] is False
    context = scan["properties"]["context"]
    assert context["additionalProperties"] is False
    assert set(context["required"]) == {"member_id", "worktree_id"}
    assert tools["aegis_scan"]["annotations"]["readOnlyHint"] is False
    report = tools["aegis_report_outcome"]["inputSchema"]
    assert set(report["required"]) == {"decision_ref", "rules_used", "outcome", "idempotency_key"}
    assert report["additionalProperties"] is False
    assert report["properties"]["decision_ref"] == {
        "type": "string", "minLength": 64, "maxLength": 64, "pattern": "[0-9a-f]{64}"}
    assert report["properties"]["idempotency_key"]["maxLength"] == 128
    assert report["properties"]["rules_used"]["maxItems"] == 128
    assert report["properties"]["rules_used"]["items"]["maxLength"] == 64
    assert report["properties"]["evidence"]["items"]["additionalProperties"] is False
    forbidden = {"files", "workspace", "scope", "approval", "identity", "session", "host", "native_identity"}
    assert forbidden.isdisjoint(report["properties"])


if __name__ == "__main__":
    if sys.argv[1:] != ["--write"]:
        sys.exit("usage: PYTHONPATH=. python3 tests/contract/test_manager_mcp_contract.py --write")
    SNAPSHOT.write_text(json.dumps(live_tools_list(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {SNAPSHOT}")
