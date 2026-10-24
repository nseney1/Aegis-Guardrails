"""MCP tool annotations (author decision 2026-10-17, R-evidence-48): every tool is either a read
tool, which declares all four hints (read-only, not destructive, idempotent, closed world) plus a
title, or a write tool, which declares only ``readOnlyHint: false`` plus a title. Hosts treat
annotations as untrusted hints, so a write tool claims nothing more and the MCP defaults make the
host prompt. The dicts are exact; the contract snapshot (tests/contract/mcp_tools.json) pins them too.
"""
from __future__ import annotations

import copy
import json
import re
from typing import Dict, List

import pytest

from aegis_core import credit
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


def test_every_input_schema_property_has_a_short_description(tools):
    for name, tool in tools.items():
        props = tool.get("inputSchema", {}).get("properties", {})
        assert props, f"{name}: empty inputSchema properties"
        for prop_name, prop_schema in props.items():
            desc = prop_schema.get("description")
            limit = 120 if prop_name == "view" else 160
            assert isinstance(desc, str) and 0 < len(desc.strip()) <= limit, (
                f"{name}.inputSchema.properties.{prop_name}: {desc!r}"
            )


def test_tools_list_declares_no_output_schema(tools):
    """D-mcp-schema: no tool declares an outputSchema, so a result key needs no schema edit."""
    assert [name for name, tool in tools.items() if "outputSchema" in tool] == []
    assert len(json.dumps(list(tools.values()))) <= 10_642  # 60% of the 4.3.3 list


@pytest.fixture
def governed(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    rules_dir = ws / ".aegis" / "rules" / "invariants"
    rules_dir.mkdir(parents=True)
    (rules_dir / "invariant-sample.md").write_text(
        "---\n"
        "type: invariant\n"
        "domain: correctness\n"
        "enforcement: gate\n"
        "hypothesis: Sample hypothesis for the result shape\n"
        "prediction: Sample prediction for the result shape\n"
        "falsification: Sample falsification for the result shape\n"
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
    return ws


def _tool_call(req_id: int, name: str, arguments: dict) -> dict:
    return handle_request(
        {"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    )["result"]


_REPORT = {"outcome": "success", "rules_used": ["invariant-sample"]}


@pytest.mark.parametrize("name,arguments", [
    ("aegis_scan", {"files": ["app.py"]}),
    ("aegis_scan", {"files": ["app.py"], "view": "full"}),
    ("aegis_scan", {"files": ["app.py"], "view": "summary"}),
    ("aegis_scan", {"files": ["app.py"], "view": "ids"}),
    ("aegis_list_rules", {}),
    ("aegis_list_rules", {"view": "summary"}),
    ("aegis_list_rules", {"view": "ids"}),
    ("aegis_create_rule", {"description": "Prevent raw SQL string interpolation"}),
    ("aegis_report_outcome", dict(_REPORT, idempotency_key="k-full", view="full")),
    ("aegis_report_outcome", dict(_REPORT, idempotency_key="k-summary", view="summary")),
    ("aegis_report_outcome", dict(_REPORT, idempotency_key="k-ids", view="ids")),
    ("aegis_capture_insight", {"quote": "Always keep one payload per answer", "paths": ["app.py"]}),
])
def test_a_tool_result_carries_its_payload_once(governed, name, arguments):
    result = _tool_call(10, name, arguments)
    assert set(result) == {"content", "isError"}, result
    assert result["isError"] is False, result
    assert isinstance(json.loads(result["content"][0]["text"]), dict)


def test_an_error_result_has_the_same_two_keys(governed):
    result = _tool_call(99, "aegis_create_rule", {"description": ""})
    assert set(result) == {"content", "isError"} and result["isError"] is True
    assert json.loads(result["content"][0]["text"]) == {
        "status": "FAIL", "error": "'description' must be a non-empty string."}


# The tool an agent could confuse each tool with, or should call next (D-mcp-schema).
SIBLINGS = {
    "aegis_scan": ("aegis_report_outcome", "aegis_list_rules"),
    "aegis_report_outcome": ("aegis_scan", "aegis_capture_insight"),
    "aegis_list_rules": ("aegis_scan",),
    "aegis_create_rule": ("aegis_list_rules",),
    "aegis_capture_insight": ("aegis_report_outcome",),
}


def _description_errors(tools: Dict[str, dict]) -> List[str]:
    """One line per tool whose description is not 2 to 4 sentences or omits a sibling tool."""
    errors = []
    for name in sorted(tools):
        text = tools[name]["description"]
        sentences = re.split(r"(?<=[.!?])\s+", text.strip())
        if not 2 <= len(sentences) <= 4:
            errors.append(f"{name}: {len(sentences)} sentences")
        errors += [f"{name}: names no {sibling}" for sibling in SIBLINGS.get(name, ()) if sibling not in text]
    return errors


def test_every_description_is_two_to_four_sentences_naming_its_siblings(tools):
    assert set(SIBLINGS) == set(tools)
    assert _description_errors(tools) == []


def test_the_report_description_states_the_limits_the_code_enforces(tools):
    text = tools["aegis_report_outcome"]["description"]
    calls, window = server_module._RATE_LIMITS["aegis_report_outcome"]
    assert f"{credit.MAX_REPORT_ROWS_PER_SESSION} report rows per session" in text
    assert f"{calls} calls per {window} seconds" in text


def test_tools_list_fits_the_handshake_budget(tools):
    assert len(json.dumps(list(tools.values()))) <= 6_500


@pytest.mark.parametrize("name,description,error", [
    ("aegis_list_rules", "One. Two. Three. Four. Five; see aegis_scan.", "aegis_list_rules: 5 sentences"),
    ("aegis_create_rule", "Drafts a rule. It writes nothing.", "aegis_create_rule: names no aegis_list_rules"),
    ("aegis_scan", "Call aegis_report_outcome and aegis_list_rules.", "aegis_scan: 1 sentences"),
], ids=["five-sentences", "no-sibling", "one-sentence"])
def test_the_description_guard_names_the_tool(tools, name, description, error):
    broken = copy.deepcopy(tools)
    broken[name]["description"] = description
    assert _description_errors(broken) == [error]
