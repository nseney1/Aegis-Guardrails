"""The opt-in ``view`` projection of tool responses: full, summary or ids.

A rule's identity is the name ``aegis_report_outcome`` accepts in ``rules_used``: its
file stem (``_name``) in aegis_list_rules and ``name`` in aegis_scan. A rule needs no
``id`` field to be named, and an error is never projected away.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import aegis_mcp.server as server
from aegis_mcp.projection import project_response
from aegis_mcp.tools import execute_tool

BAD_WORKSPACE = "/invalid\0path"


def _rule(root: Path, stem: str, frontmatter: str) -> None:
    rules = root / ".aegis" / "rules" / "traps"
    rules.mkdir(parents=True, exist_ok=True)
    (rules / f"{stem}.md").write_text(f"---\n{frontmatter}---\nbody\n", encoding="utf-8")


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    _rule(tmp_path, "trap-noid", "type: trap\nhypothesis: no id here\ntarget_paths: ['src/*.py']\n")
    _rule(tmp_path, "trap-with-id", "id: trap-with-id\ntype: trap\nhypothesis: h\n")
    return tmp_path


def test_full_view_and_no_view_return_the_response_unchanged(workspace):
    plain = execute_tool("aegis_list_rules", {"workspace": str(workspace)})
    assert execute_tool("aegis_list_rules", {"workspace": str(workspace), "view": "full"}) == plain


def test_list_rules_ids_view_names_each_rule_by_its_file_stem(workspace):
    ids = execute_tool("aegis_list_rules", {"workspace": str(workspace), "view": "ids"})
    assert ids == {"rules": ["trap-noid", "trap-with-id"], "stale_rules": [], "ignored": []}


def test_list_rules_summary_view_keeps_identity_type_and_fitness(workspace):
    summary = execute_tool("aegis_list_rules", {"workspace": str(workspace), "view": "summary"})
    assert summary["rules_count"] == 2
    assert summary["rules"][0] == {
        "_name": "trap-noid",
        "type": "trap",
        "fitness": {"triggers": 0, "tp": 0, "fp": 0, "last_ts": None, "score": 0.0,
                    "reported_score": None, "status": "insufficient (n=0)"},
    }
    assert summary["rules"][1]["_name"] == "trap-with-id"
    assert "hypothesis" not in summary["rules"][1]
    assert (summary["stale_rules_count"], summary["ignored_count"]) == (0, 0)


def test_scan_ids_view_names_the_matched_rules(workspace):
    ids = execute_tool("aegis_scan", {"workspace": str(workspace), "files": ["src/app.py"], "view": "ids"})
    assert ids == {"relevant_rules": ["trap-noid"], "invariant_warnings": [], "omitted_mandatory": [], "stale_rules": []}


def test_scan_summary_view_counts_and_names_rules_without_the_rendered_guidance(workspace):
    summary = execute_tool("aegis_scan", {"workspace": str(workspace), "files": ["src/app.py"], "view": "summary"})
    assert summary["relevant_rules_count"] == 1
    assert summary["relevant_rules"][0]["name"] == "trap-noid"
    assert summary["rules_staged"] == 1
    assert "guidance" not in summary


def test_scan_ids_view_over_stdio_names_rules_and_is_not_an_error(workspace, monkeypatch):
    monkeypatch.setattr(server, "_canonical_workspace", str(workspace))
    monkeypatch.setattr(server, "_workspace_error", None)
    server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"clientInfo": {"name": "pytest"}}})
    response = server.handle_request({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "aegis_scan", "arguments": {"files": ["src/app.py"], "view": "ids"}},
    })
    assert response["result"]["isError"] is False
    assert json.loads(response["result"]["content"][0]["text"])["relevant_rules"] == ["trap-noid"]


@pytest.mark.parametrize("view", ["ids", "summary"])
def test_an_error_is_returned_whole_whatever_the_view(view):
    result = execute_tool("aegis_list_rules", {"workspace": BAD_WORKSPACE, "view": view})
    assert result["status"] == "FAIL"
    assert result["error"]


@pytest.mark.parametrize("view", ["ids", "summary"])
@pytest.mark.parametrize("error", [
    {"error": "boom", "rules": [{"_name": "a", "hypothesis": "h"}]},  # an error without a FAIL status
    {"status": "FAIL", "rules": [{"_name": "a", "hypothesis": "h"}]},  # a FAIL without an error text
])
def test_a_result_that_names_an_error_or_a_failure_is_never_projected(error, view):
    assert project_response(error, view=view) == error


def test_ids_view_skips_an_item_with_no_identity_instead_of_dumping_it():
    assert project_response([{"hypothesis": "secret-ish body"}, {"name": "kept"}], view="ids") == ["kept"]


def test_projection_keeps_scalars_and_plain_string_lists():
    assert project_response("hello", view="ids") == "hello"
    assert project_response(123, view="summary") == 123
    payload = {"relevant_rules": [], "warnings": ["slot files could not be read"]}
    assert project_response(payload, view="ids")["warnings"] == ["slot files could not be read"]
    assert project_response(payload, view="summary")["warnings"] == ["slot files could not be read"]


def test_frontmatter_keys_pass_through_the_full_view_unchanged(tmp_path):
    _rule(tmp_path, "trap-prompt", "type: trap\nprompt: kept as written\n")
    rules = execute_tool("aegis_list_rules", {"workspace": str(tmp_path), "view": "full"})["rules"]
    assert rules[0]["prompt"] == "kept as written"
