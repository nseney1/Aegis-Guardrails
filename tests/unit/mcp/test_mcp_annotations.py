"""MCP tool annotations: every tool explicitly declares all four boolean hints
(readOnlyHint, destructiveHint, idempotentHint, openWorldHint) and a title, matching
its handler's actual behavior. The values are pinned by the contract snapshot
(tests/contract/mcp_tools.json).
"""
import pytest

import aegis_mcp.server as server_module
from aegis_mcp.server import handle_request

_HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


@pytest.fixture
def tools(monkeypatch):
    monkeypatch.setattr(server_module, "_session_id", None)
    handle_request({"jsonrpc": "2.0", "id": 0, "method": "initialize"})
    resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    return {t["name"]: t for t in resp["result"]["tools"]}


def test_every_tool_declares_all_four_boolean_hints_and_title(tools):
    for name, tool in tools.items():
        ann = tool.get("annotations")
        assert isinstance(ann, dict), f"{name}: missing annotations"
        assert set(ann) == {*_HINTS, "title"}, f"{name}: {sorted(ann)}"
        for hint in _HINTS:
            assert isinstance(ann.get(hint), bool), f"{name}: {hint} not a bool"
        assert isinstance(ann.get("title"), str) and ann["title"], f"{name}: no title"


def test_read_only_tools_are_never_destructive(tools):
    for name, tool in tools.items():
        ann = tool["annotations"]
        if ann["readOnlyHint"]:
            assert ann["destructiveHint"] is False, name
            assert ann["idempotentHint"] is True, name
            assert ann["openWorldHint"] is False, name


def test_write_tools_declare_exact_handler_behavior_hints(tools):
    writers = {n: t["annotations"] for n, t in tools.items() if not t["annotations"]["readOnlyHint"]}
    assert set(writers) == {"aegis_report_outcome", "aegis_capture_insight"}
    # Both write tools append to local JSONL files only (non-destructive, closed-world).
    # aegis_report_outcome requires idempotency_key and deduplicates retries;
    # aegis_capture_insight appends a new insight row on each call.
    assert writers["aegis_report_outcome"] == {
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
        "title": "Report Outcome",
    }
    assert writers["aegis_capture_insight"] == {
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
        "title": "Capture Insight",
    }


def test_every_input_schema_property_has_a_meaningful_description(tools):
    for name, tool in tools.items():
        schema = tool.get("inputSchema", {})
        props = schema.get("properties", {})
        assert props, f"{name}: empty inputSchema properties"
        for prop_name, prop_schema in props.items():
            desc = prop_schema.get("description")
            assert isinstance(desc, str) and len(desc.strip()) >= 40, (
                f"{name}.inputSchema.properties.{prop_name} missing or stub description: {desc!r}"
            )

