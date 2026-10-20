"""MCP tool annotations (author decision 2026-10-17, R-evidence-48): every tool is either a read
tool, which declares all four hints (read-only, not destructive, idempotent, closed world) plus a
title, or a write tool, which declares only ``readOnlyHint: false`` plus a title. Hosts treat
annotations as untrusted hints, so a write tool claims nothing more and the MCP defaults make the
host prompt. The dicts are exact; the contract snapshot (tests/contract/mcp_tools.json) pins them too.
"""
from __future__ import annotations

import copy
import json
from typing import Dict, List

import pytest

import aegis_mcp.server as server_module
from aegis_mcp.server import handle_request

_HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
_READ_HINTS = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
READ = {"aegis_scan": "Scan JIT Rules", "aegis_list_rules": "List Rules", "aegis_create_rule": "Create Rule"}
WRITE = {"aegis_report_outcome": "Report Outcome", "aegis_capture_insight": "Capture Insight"}


@pytest.fixture
def tools(monkeypatch):
    monkeypatch.setattr(server_module, "_session_id", None)
    handle_request({"jsonrpc": "2.0", "id": 0, "method": "initialize"})
    resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    return {t["name"]: t for t in resp["result"]["tools"]}


def _classification_errors(tools: Dict[str, dict]) -> List[str]:
    """One line per tool whose annotations are not exactly its class's, or that has no class."""
    errors = []
    for name in sorted(tools):
        if name in WRITE:
            expected = {"readOnlyHint": False, "title": WRITE[name]}
        elif name in READ:
            expected = {**_READ_HINTS, "title": READ[name]}
        else:
            errors.append(f"{name}: not classified as a read or a write tool")
            continue
        if tools[name].get("annotations") != expected:
            errors.append(f"{name}: annotations {tools[name].get('annotations')!r} are not {expected!r}")
    errors += [f"{name}: classified but not served" for name in sorted((set(READ) | set(WRITE)) - set(tools))]
    return errors


def test_every_tool_is_in_exactly_one_of_read_and_write():
    assert not set(READ) & set(WRITE)


def test_every_served_tool_has_exactly_the_annotations_of_its_class(tools):
    assert _classification_errors(tools) == []


def test_write_tools_claim_nothing_beyond_not_read_only(tools):
    writers = {n: t["annotations"] for n, t in tools.items() if t["annotations"].get("readOnlyHint") is not True}
    assert writers == {
        "aegis_report_outcome": {"readOnlyHint": False, "title": "Report Outcome"},
        "aegis_capture_insight": {"readOnlyHint": False, "title": "Capture Insight"},
    }


@pytest.mark.parametrize("name,extra", [
    ("aegis_report_outcome", {"destructiveHint": False}),
    ("aegis_report_outcome", {"idempotentHint": True}),
    ("aegis_capture_insight", {"openWorldHint": False}),
])
def test_the_guard_names_a_write_tool_that_redeclares_a_hint(tools, name, extra):
    broken = copy.deepcopy(tools)
    broken[name]["annotations"].update(extra)
    assert [e.split(":", 1)[0] for e in _classification_errors(broken)] == [name]


@pytest.mark.parametrize("hint", _HINTS[1:])
def test_the_guard_names_a_read_tool_missing_a_hint(tools, hint):
    broken = copy.deepcopy(tools)
    del broken["aegis_list_rules"]["annotations"][hint]
    assert [e.split(":", 1)[0] for e in _classification_errors(broken)] == ["aegis_list_rules"]


def test_the_guard_names_an_unclassified_tool(tools):
    extra = dict(tools, aegis_new_tool={"name": "aegis_new_tool", "annotations": {**_READ_HINTS, "title": "New"}})
    assert _classification_errors(extra) == ["aegis_new_tool: not classified as a read or a write tool"]


def test_read_only_tools_are_never_destructive(tools):
    for name, tool in tools.items():
        ann = tool["annotations"]
        if ann["readOnlyHint"]:
            assert ann["destructiveHint"] is False, name
            assert ann["idempotentHint"] is True, name
            assert ann["openWorldHint"] is False, name


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


def test_read_tool_descriptions_specify_sibling_routing_and_mechanics(tools):
    create_desc = tools["aegis_create_rule"]["description"]
    assert "aegis_list_rules" in create_desc
    assert "aegis_capture_insight" in create_desc
    assert "three active workspace rules" in create_desc
    assert "500 chars" in create_desc
    assert "writes nothing to disk" in create_desc
    assert ".aegis/rules/<type_dir>/<id>.md" in create_desc

    list_desc = tools["aegis_list_rules"]["description"]
    assert "aegis_scan" in list_desc
    assert "directory order without recording a scan or exposure event" in list_desc
    assert "_error" in list_desc
    assert "_expired: true" in list_desc
    assert "stale_rules" in list_desc
    assert "ignored" in list_desc
    assert "rule_type" in list_desc
    assert "view" in list_desc

    scan_desc = tools["aegis_scan"]["description"]
    assert "aegis_list_rules" in scan_desc
    assert "aegis_report_outcome" in scan_desc
    assert "at most two slots" in scan_desc
    assert "unreviewed_rules" in scan_desc
    assert "pre-edit scan" in scan_desc
    assert "session rule exposure" in scan_desc
