"""MCP tool annotations: every tool explicitly declares all four boolean hints
(readOnlyHint, destructiveHint, idempotentHint, openWorldHint) and a title, matching
its handler's actual behavior. The values are pinned by the contract snapshot
(tests/contract/mcp_tools.json).
"""
from __future__ import annotations

import json

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


def test_every_tool_declares_valid_output_schema(tools):
    for name, tool in tools.items():
        schema = tool.get("outputSchema")
        assert isinstance(schema, dict), f"{name}: missing outputSchema"
        assert schema.get("type") == "object", f"{name}: outputSchema.type must be 'object'"
        assert schema.get("additionalProperties") is False, (
            f"{name}: outputSchema.additionalProperties must be False"
        )
        props = schema.get("properties")
        assert isinstance(props, dict) and props, f"{name}: empty outputSchema.properties"
        for prop_name, prop_schema in props.items():
            assert isinstance(prop_schema, dict), f"{name}.outputSchema.properties.{prop_name} not a dict"
            desc = prop_schema.get("description")
            assert isinstance(desc, str) and desc.strip(), (
                f"{name}.outputSchema.properties.{prop_name} missing description"
            )


def test_live_tool_calls_emit_structured_content_matching_output_schema(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    rules_dir = ws / ".aegis" / "rules" / "invariants"
    rules_dir.mkdir(parents=True)
    (rules_dir / "invariant-sample.md").write_text(
        "---\n"
        "type: invariant\n"
        "domain: correctness\n"
        "enforcement: gate\n"
        "hypothesis: Sample hypothesis for outputSchema verification\n"
        "prediction: Sample prediction for outputSchema verification\n"
        "falsification: Sample falsification for outputSchema verification\n"
        "target_paths:\n"
        "  - '**'\n"
        "---\n"
        "# Sample Rule\n\n"
        "Sample body.\n",
        encoding="utf-8",
    )
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(server_module, "_canonical_workspace", str(ws))
    monkeypatch.setattr(server_module, "_session_id", None)

    handle_request({"jsonrpc": "2.0", "id": 0, "method": "initialize"})
    listed = handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    tools_by_name = {t["name"]: t for t in listed["result"]["tools"]}

    calls = [
        ("aegis_scan", {"files": ["app.py"]}),
        ("aegis_scan", {"files": ["app.py"], "view": "full"}),
        ("aegis_scan", {"files": ["app.py"], "view": "summary"}),
        ("aegis_scan", {"files": ["app.py"], "view": "ids"}),
        ("aegis_list_rules", {}),
        ("aegis_list_rules", {"view": "full"}),
        ("aegis_list_rules", {"view": "summary"}),
        ("aegis_list_rules", {"view": "ids"}),
        ("aegis_create_rule", {"description": "Prevent raw SQL string interpolation"}),
        (
            "aegis_report_outcome",
            {"outcome": "success", "rules_used": ["invariant-sample"], "idempotency_key": "k-full", "view": "full"},
        ),
        (
            "aegis_report_outcome",
            {"outcome": "success", "rules_used": ["invariant-sample"], "idempotency_key": "k-summary", "view": "summary"},
        ),
        (
            "aegis_report_outcome",
            {"outcome": "success", "rules_used": ["invariant-sample"], "idempotency_key": "k-ids", "view": "ids"},
        ),
        (
            "aegis_capture_insight",
            {"quote": "Always validate structuredContent against outputSchema", "paths": ["app.py"]},
        ),
    ]

    for idx, (tool_name, arguments) in enumerate(calls, start=10):
        resp = handle_request(
            {"jsonrpc": "2.0", "id": idx, "method": "tools/call", "params": {"name": tool_name, "arguments": arguments}}
        )
        result = resp["result"]
        assert result["isError"] is False, f"{tool_name} ({arguments}) returned error: {result}"
        assert "structuredContent" in result, f"{tool_name} ({arguments}) missing structuredContent"
        structured = result["structuredContent"]
        parsed_text = json.loads(result["content"][0]["text"])
        assert structured == parsed_text, f"{tool_name} ({arguments}) structuredContent != parsed content text"

        output_schema = tools_by_name[tool_name]["outputSchema"]
        declared_props = set(output_schema["properties"])
        extra_keys = set(structured) - declared_props
        assert not extra_keys, f"{tool_name} ({arguments}) returned undeclared keys: {sorted(extra_keys)}"
        for req_key in output_schema.get("required", []):
            assert req_key in structured, f"{tool_name} ({arguments}) missing required key {req_key!r}"

    err_resp = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {"name": "aegis_create_rule", "arguments": {"description": ""}},
        }
    )
    assert err_resp["result"]["isError"] is True
    assert "structuredContent" not in err_resp["result"]


def test_write_tool_descriptions_specify_sibling_routing_and_limits(tools):
    report_desc = tools["aegis_report_outcome"]["description"]
    assert "aegis_scan" in report_desc
    assert "aegis_capture_insight" in report_desc
    assert "200" in report_desc
    assert "5 calls per 60 seconds" in report_desc
    assert "aegis check --record" in report_desc
    assert "unwitnessed" in report_desc
    for sentence in [s.strip() for s in report_desc.split(".") if s.strip()]:
        assert len(sentence.split()) <= 45, f"Sentence exceeds 45 words: {sentence!r}"

    insight_desc = tools["aegis_capture_insight"]["description"]
    assert "aegis_create_rule" in insight_desc
    assert "aegis_report_outcome" in insight_desc
    assert "~/.aegis/insights/" in insight_desc
    assert "level: 'suggestion'" in insight_desc
    assert "level: 'W2'" in insight_desc
    assert "debits" not in insight_desc
    assert "redacts secrets" in insight_desc
    assert "300 characters" in insight_desc


