"""Agent-facing MCP text is a contract: every claim it makes is true (R-evidence-49).

Every `aegis <command> [sub ...] [--flag ...]` named in backticks or quotes inside a tool or
property description must resolve through the parser tree of ``cli_tree.json`` (never through
its removed commands), with each flag defined on that command or the top-level parser. The
other tests pin statements the descriptions used to get wrong against what the code does.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

from aegis_core import credit
from aegis_core.telemetry_engine import ledger
from aegis_mcp.registry import TOOL_DEFINITIONS
from aegis_mcp.tools import execute_tool

CLI_TREE = Path(__file__).with_name("cli_tree.json")
_MENTION = re.compile(r"[`'\"](aegis(?: [^`'\"]*)?)[`'\"]")


def _descriptions(node: Any, where: str) -> Iterator[Tuple[str, str]]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "description" and isinstance(value, str):
                yield where, value
            else:
                yield from _descriptions(value, f"{where}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _descriptions(value, f"{where}[{index}]")


def _flags(node: Dict[str, Any]) -> set:
    return {flag for arg in node.get("arguments", []) for flag in arg.get("flags", [])}


def _resolves(mention: str, parser: Dict[str, Any]) -> bool:
    node, flags, positional = parser, _flags(parser), False
    for word in mention.split()[1:]:
        if word.startswith("-"):
            if word.split("=", 1)[0] not in flags:
                return False
            continue
        children = node.get("commands") or {}
        if positional or not children:
            positional = True  # an argument value or a positional, not a command name
            continue
        child = children.get(word) or next((c for c in children.values() if word in (c.get("aliases") or [])), None)
        if child is None:
            return False
        node, flags = child, flags | _flags(child)
    return True


def unresolved_mentions(tools: List[Dict[str, Any]], tree: Dict[str, Any]) -> List[str]:
    return [f"{where}: {m.group(1)}" for tool in tools for where, text in _descriptions(tool, tool["name"])
            for m in _MENTION.finditer(text) if not _resolves(m.group(1), tree["parser"])]


def _tree() -> Dict[str, Any]:
    return json.loads(CLI_TREE.read_text(encoding="utf-8"))


def _tool(name: str) -> Dict[str, Any]:
    return next(t for t in TOOL_DEFINITIONS if t["name"] == name)


def test_every_command_a_description_names_exists():
    assert unresolved_mentions(TOOL_DEFINITIONS, _tree()) == []


def test_the_guard_rejects_a_missing_command_a_removed_one_and_an_unknown_flag():
    tools = [{"name": "t", "description": "see `aegis insights review`, 'aegis verify' and `aegis check --nope`",
              "inputSchema": {"properties": {"p": {"description": "run \"aegis rule insight review\""}}}}]
    assert unresolved_mentions(tools, _tree()) == [
        "t: aegis insights review", "t: aegis verify", "t: aegis check --nope"]


def test_insight_ids_are_random_and_never_called_content_addressed(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    ws = tmp_path / "ws"
    (ws / ".aegis" / "rules" / "traps").mkdir(parents=True)
    ids = [execute_tool("aegis_capture_insight", {"workspace": str(ws), "quote": "same quote", "paths": ["a.py"],
                                                  "_host": "claude-code", "_session": "s1"})["id"] for _ in range(2)]
    assert all(re.fullmatch(r"ins-[0-9a-f]{12}", i) for i in ids) and ids[0] != ids[1]
    texts = [text for tool in TOOL_DEFINITIONS for _, text in _descriptions(tool, tool["name"])]
    assert not any("content-addressed" in text.lower() for text in texts)


def _report_schema() -> Dict[str, Any]:
    return _tool("aegis_report_outcome")


def test_a_rate_limited_report_carries_no_recorded_key_and_the_schema_says_so(tmp_path):
    result = credit.submit_report(tmp_path, tree="t" * 40, session="s", host="h", key="k", outcome="tp",
                                  rules_for=lambda check: [], cap=0)
    assert result["status"] == "rate_limited" and "recorded" not in result
    recorded = _report_schema()["outputSchema"]["properties"]["recorded"]["description"]
    assert "rate_limited" not in recorded


def test_a_witnessed_failure_is_kept_as_the_claim_and_read_as_a_neutral_trigger(tmp_path):
    tree = "a" * 40
    ledger.append_rows(tmp_path, [{"v": ledger.LEDGER_VERSION, "ts": "2026-10-20T00:00:00Z", "event": "check",
                                   "id": "c1", "tree": tree, "witness": "aegis", "passed": True,
                                   "tests": {"exit": 0, "passed": 3}}])
    result = credit.submit_report(tmp_path, tree=tree, session="s", host="h", key="k", outcome="failure",
                                  rules_for=lambda check: ["trap-x"])
    assert (result["status"], result["credited"]) == ("recorded", ["trap-x"])
    rows = credit.read_rows(tmp_path)
    assert [r["result"] for r in rows if r.get("event") == "report"] == ["fp"]
    derived, = credit.derive(rows, landed=lambda *a, **k: None)
    assert derived.result == "trigger" and derived.counts is False
    outcome = _report_schema()["inputSchema"]["properties"]["outcome"]["description"]
    assert "neutral trigger" in outcome and "never a false positive" in outcome
    credited = _report_schema()["outputSchema"]["properties"]["credited"]["description"]
    assert "attached to" in credited and "CI" in credited


def test_ignored_report_fields_are_described_as_ignored_and_never_stored(tmp_path):
    ws = tmp_path / "ws"
    (ws / ".aegis" / "rules" / "traps").mkdir(parents=True)
    (ws / ".aegis" / "rules" / "traps" / "trap-x.md").write_text(
        "---\nid: trap-x\ntype: trap\nhypothesis: h\nprediction: p\n---\n# x\n", encoding="utf-8")
    result = execute_tool("aegis_report_outcome", {
        "workspace": str(ws), "outcome": "success", "rules_used": ["trap-x"], "idempotency_key": "k1",
        "tests_passed": True, "rework_count": 2, "notes": "it helped"})
    assert result["status"] == "claimed", result
    rows = credit.read_rows(ws)
    assert [r["event"] for r in rows] == ["claimed"]
    assert not any({"tests_passed", "rework_count", "notes", "meta"} & set(r) for r in rows)
    assert "it helped" not in json.dumps(rows)
    props = _report_schema()["inputSchema"]["properties"]
    for name in ("tests_passed", "rework_count", "notes"):
        assert "ignored, never stored" in props[name]["description"], name
    assert "non-negative" not in props["rework_count"]["description"]


def test_hints_and_conditional_fields_are_described_as_such():
    rule_type = _tool("aegis_create_rule")["inputSchema"]["properties"]["rule_type"]["description"]
    assert "hint" in rule_type and "Determines the target subdirectory" not in rule_type
    total = _tool("aegis_scan")["outputSchema"]["properties"]["unreviewed_total"]["description"]
    assert "present only when" in total
