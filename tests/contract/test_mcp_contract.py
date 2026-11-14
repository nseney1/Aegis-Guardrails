"""MCP contract snapshot (ADR 0005 AD-6): the live tools/list result must equal
tests/contract/mcp_tools.json, so any change to a tool name, description, schema or
annotation is a reviewed diff of that file. docs/reference.md is generated from it
(tests/contract/gen_reference.py).

Regenerate after an intended change, from the repository root:

    PYTHONPATH=. python3 tests/contract/test_mcp_contract.py --write
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

import aegis_mcp.server as server

SNAPSHOT = Path(__file__).with_name("mcp_tools.json")
QUEUE_SNAPSHOT = Path(__file__).with_name("mcp_queue_tools.json")


def live_tools_list() -> dict:
    server.handle_request({"jsonrpc": "2.0", "id": 0, "method": "initialize"})
    response = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    # Round-trip through JSON so tuples and other in-memory types compare as the wire sees them.
    return json.loads(json.dumps(response["result"]))


def test_tools_list_matches_the_contract_snapshot(monkeypatch):
    monkeypatch.setattr(server, "_session_id", None)
    expected = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert live_tools_list() == expected


def test_queue_tools_list_matches_the_contract_snapshot(monkeypatch):
    # Exercise the advertised schema of a refused queue connection, granting no
    # authority and reading no real account-home records (cross-platform).
    monkeypatch.setattr(server, "_session_id", None)
    monkeypatch.setattr(server, "_queue_initialized", False)
    monkeypatch.setattr(server, "_queue_grant", None)
    monkeypatch.setattr(server, "_queue_registration", "alpha")
    assert live_tools_list() == json.loads(QUEUE_SNAPSHOT.read_text(encoding="utf-8"))


if __name__ == "__main__":
    if sys.argv[1:] == ["--write-queue"]:
        from aegis_mcp.registry import QUEUE_TOOL_DEFINITIONS

        QUEUE_SNAPSHOT.write_text(json.dumps({"tools": QUEUE_TOOL_DEFINITIONS}, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {QUEUE_SNAPSHOT}")
    elif sys.argv[1:] == ["--write"]:
        SNAPSHOT.write_text(json.dumps(live_tools_list(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"wrote {SNAPSHOT}")
    else:
        sys.exit("usage: PYTHONPATH=. python3 tests/contract/test_mcp_contract.py --write|--write-queue")

