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
from aegis_core.scan import estimate_tokens, scan

BAD_WORKSPACE = "/invalid\0path"


def _rule(root: Path, stem: str, frontmatter: str, rule_type: str = "trap") -> None:
    rules = root / ".aegis" / "rules" / f"{rule_type}s"
    rules.mkdir(parents=True, exist_ok=True)
    (rules / f"{stem}.md").write_text(f"---\n{frontmatter}---\nbody\n", encoding="utf-8")


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))


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
    assert ids == {"relevant_rules": ["trap-noid"], "invariant_warnings": [], "omitted_mandatory": [],
                   "omitted_mandatory_count": 0, "omitted_mandatory_listed_count": 0, "stale_rules": []}


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


def _scan_payload(witnessed=True):
    return {
        "relevant_rules": [{"name": "inv-a", "type": "invariant", "hypothesis": "full guidance"}],
        "invariant_warnings": [{"name": "inv-a", "type": "invariant"}],
        "rules_staged": 1,
        "guidance": "Read the full rule before editing.",
        "omitted_mandatory": [{"name": "inv-b", "type": "invariant", "reason": "token_budget"}],
        "stale_rules": [],
        "stats": {"omitted": 4, "omitted_mandatory": 12, "clamped": True,
                  "estimated_tokens": 500, "max_tokens_budget": 2000},
        "rules_base": {"ref": "origin/HEAD" if witnessed else "HEAD", "commit": "a" * 40,
                       "source": "origin-head" if witnessed else "local-head",
                       "witnessed": witnessed, "label": "reviewed base" if witnessed else "local-head, not review-witnessed"},
        "unreviewed_rules": [{"id": f"inv-{i}", "title": "branch-local title", "change": "changed"}
                             for i in range(10)],
        "unreviewed_total": 27,
    }


@pytest.mark.parametrize("witnessed", [True, False])
def test_scan_summary_preserves_base_witness_and_exact_omission_totals(witnessed):
    payload = _scan_payload(witnessed)
    before = json.dumps(payload, sort_keys=True)
    summary = project_response(payload, view="summary")
    assert summary["omitted_mandatory_count"] == 12
    assert summary["omitted_mandatory_listed_count"] == len(summary["omitted_mandatory"]) == 1
    assert summary["omitted_mandatory"][0]["reason"] == "token_budget"
    assert summary["stats"] == payload["stats"]
    assert summary["rules_base"] == payload["rules_base"]
    assert summary["unreviewed_total"] == summary["unreviewed_rules_count"] == 27
    assert summary["unreviewed_rules_listed_count"] == len(summary["unreviewed_rules"]) == 10
    assert "inspection" in summary["inspection"].lower()
    assert "full" in summary["inspection"] and "before editing" in summary["inspection"]
    assert "guidance" not in summary
    assert json.dumps(payload, sort_keys=True) == before
    assert project_response(payload, view="full") is payload


@pytest.mark.parametrize("change", ["new", "changed", "removed"])
def test_scan_summary_keeps_unreviewed_change_kinds(change):
    payload = _scan_payload()
    payload["unreviewed_rules"][0]["change"] = change
    summary = project_response(payload, view="summary")
    assert summary["unreviewed_rules"][0] == {"id": "inv-0", "change": change}


@pytest.mark.parametrize("listed", [0, 1, 10, 12])
def test_scan_summary_distinguishes_omitted_total_from_both_list_caps(listed):
    payload = _scan_payload()
    payload["omitted_mandatory"] *= listed
    summary = project_response(payload, view="summary")
    assert summary["omitted_mandatory_count"] == 12
    assert summary["omitted_mandatory_listed_count"] == len(summary["omitted_mandatory"]) == min(listed, 10)


def test_scan_summary_keeps_unreviewed_total_when_core_trimmed_all_names():
    payload = _scan_payload()
    payload["guidance"] = "Full rule guidance. " * 40
    del payload["unreviewed_rules"]
    summary = project_response(payload, view="summary")
    assert summary["unreviewed_total"] == summary["unreviewed_rules_count"] == 27
    assert summary["unreviewed_rules_listed_count"] == 0


@pytest.mark.parametrize("budget", [200, 600, 2000])
def test_public_scan_summary_keeps_exact_totals_within_the_scan_budget(tmp_path, monkeypatch, budget):
    for i in range(40):
        _rule(tmp_path, f"inv-{i:02d}", "type: invariant\nhypothesis: h\ntarget_paths: ['src/*.py']\n", "invariant")
    monkeypatch.setenv("AEGIS_MAX_JIT_TOKENS", str(budget))
    args = {"workspace": str(tmp_path), "files": ["src/app.py"]}
    full = execute_tool("aegis_scan", args)
    summary = execute_tool("aegis_scan", {**args, "view": "summary"})
    assert estimate_tokens(json.dumps(summary)) <= budget
    assert summary["stats"]["omitted_mandatory"] == full["stats"]["omitted_mandatory"]
    assert summary["stats"]["omitted"] == full["stats"]["omitted"]
    assert estimate_tokens(json.dumps(summary)) <= estimate_tokens(json.dumps(full))
    if "inspection" in summary:
        assert summary["omitted_mandatory_count"] == full["stats"]["omitted_mandatory"]
        assert summary["omitted_mandatory_listed_count"] == len(summary["omitted_mandatory"])
    else:
        assert summary == full


def test_scan_without_a_review_base_does_not_invent_one(workspace):
    summary = execute_tool("aegis_scan", {"workspace": str(workspace), "files": ["src/app.py"], "view": "summary"})
    assert "rules_base" not in summary
    assert not {"unreviewed_rules", "unreviewed_rules_count", "unreviewed_rules_listed_count"} & summary.keys()
    assert summary["omitted_mandatory_count"] == summary["omitted_mandatory_listed_count"] == 0


def test_unbound_scan_summary_keeps_personal_rule_source_and_next_action(tmp_path):
    _rule(Path.home(), "personal", "type: trap\nhypothesis: " + "Personal guidance. " * 40
          + "\ntarget_paths: ['src/*.py']\n")
    args = {"workspace": str(tmp_path / "unbound"), "files": ["src/app.py"], "_unbound": "no_workspace"}
    full = execute_tool("aegis_scan", args)
    summary = execute_tool("aegis_scan", {**args, "view": "summary"})
    assert "inspection" in summary
    assert summary["status"] == "not_governed"
    assert summary["user_layer"] == full["user_layer"] == {"path": str(Path.home() / ".aegis/rules"), "rules": 1}
    assert summary["message"] == full["message"] == 'not an Aegis workspace: run "aegis init" in your repository'
    assert summary["reason"] == full["reason"] == "no_workspace"
    assert not {"rules_base", "unreviewed_rules", "unreviewed_rules_count",
                "unreviewed_rules_listed_count", "unreviewed_total"} & summary.keys()


@pytest.mark.parametrize("guidance_length", [0, 2000])
def test_scan_summary_returns_the_less_expensive_shape(guidance_length):
    payload = {"relevant_rules": [], "omitted_mandatory": [], "guidance": "x" * guidance_length,
               "stats": {"omitted": 0, "omitted_mandatory": 0, "max_tokens_budget": 2000}}
    summary = project_response(payload, view="summary")
    if guidance_length:
        assert "inspection" in summary
        assert estimate_tokens(json.dumps(summary)) < estimate_tokens(json.dumps(payload))
    else:
        assert summary is payload


def test_scan_summary_returns_full_when_the_shapes_cost_the_same():
    payload = {"relevant_rules": [], "omitted_mandatory": [], "guidance": "x" * 2000,
               "stats": {"omitted": 0, "omitted_mandatory": 0, "max_tokens_budget": 2000}}
    summary_tokens = estimate_tokens(json.dumps(project_response(payload, view="summary")))
    candidates = ({**payload, "guidance": "x" * length} for length in range(400))
    equal_cost = next(p for p in candidates if estimate_tokens(json.dumps(p)) == summary_tokens)
    assert project_response(equal_cost, view="summary") is equal_cost


@pytest.mark.parametrize("kind,guidance_length,budget", [("gate", 210, 204), ("gate", 130, None),
                                                       ("invariant", 6, None), ("gate", 2000, 199),
                                                       ("invariant", 2000, 214)])
def test_scan_summary_never_trims_staged_rules_or_constraints(kind, guidance_length, budget):
    payload = _scan_payload()
    payload.update(
        relevant_rules=[{"name": "g", "type": kind, "enforcement": "GATE (must pass)", "fitness": None,
                         "hypothesis": "h", "prediction": "", "matched_files": ["a.py"],
                         "_path": f".aegis/rules/{kind}s/g.md"}],
        invariant_warnings=[] if kind == "gate" else [
            {"name": "g", "type": "invariant", "tier": "gate", "hypothesis": "h",
             "prediction": "", "matched_files": ["a.py"]}],
        omitted_mandatory=[], guidance="x" * guidance_length,
        stats={"omitted": 0, "omitted_mandatory": 0, "clamped": False, "max_tokens_budget": 2000},
    )
    del payload["unreviewed_rules"], payload["unreviewed_total"]
    payload["stats"]["max_tokens_budget"] = budget or estimate_tokens(json.dumps(payload)) + 2
    if budget == 204:
        assert estimate_tokens(json.dumps(payload)) == 194
    summary = project_response(payload, view="summary")
    assert [rule["name"] for rule in summary["relevant_rules"]] == ["g"]
    assert [rule["name"] for rule in summary["invariant_warnings"]] == ([] if kind == "gate" else ["g"])
    assert summary["stats"] == payload["stats"]
    if guidance_length == 2000:
        # A lossy summary would be cheaper than full, exposing either trim regression.
        assert summary is payload
    else:
        assert estimate_tokens(json.dumps(summary)) <= payload["stats"]["max_tokens_budget"]


def test_scan_summary_cap_never_hides_a_staged_rule(tmp_path):
    for index in range(11):
        _rule(tmp_path, f"trap-{index:02d}", "type: trap\nhypothesis: h\ntarget_paths: ['src/*.py']\n")
    full = scan(tmp_path, changed_files=["src/app.py"], budget=11, max_tokens=10000)
    assert full["rules_staged"] == 11 and full["stats"]["omitted"] == 0
    summary = project_response(full, view="summary")
    assert summary is full


def test_scan_summary_reports_stale_and_warning_totals_and_displayed_counts():
    payload = _scan_payload()
    payload["guidance"] = "Full guidance. " * 80
    payload["stale_rules"] = [{"name": f"stale-{index:02d}"} for index in range(12)]
    payload["warnings"] = [f"Warning {index:02d}." for index in range(12)]
    summary = project_response(payload, view="summary")
    for key in ("stale_rules", "warnings"):
        assert summary[f"{key}_count"] == len(payload[key]) == 12
        assert summary[f"{key}_listed_count"] == len(summary[key]) == 10


def test_scan_summary_trims_names_to_pay_for_metadata_without_losing_totals():
    payload = _scan_payload()
    payload["guidance"] = ""
    payload["relevant_rules"] = []
    payload["invariant_warnings"] = []
    payload["rules_staged"] = 0
    for item in payload["unreviewed_rules"]:
        del item["title"]
    payload["stats"]["max_tokens_budget"] = estimate_tokens(json.dumps(payload))
    before = json.dumps(payload, sort_keys=True)
    summary = project_response(payload, view="summary")
    assert "inspection" in summary
    assert estimate_tokens(json.dumps(summary)) <= payload["stats"]["max_tokens_budget"]
    assert summary["unreviewed_rules_count"] == 27
    assert summary["unreviewed_rules_listed_count"] == len(summary["unreviewed_rules"]) < 10
    assert summary["omitted_mandatory_count"] == 12
    assert summary["rules_base"] == payload["rules_base"]
    assert json.dumps(payload, sort_keys=True) == before


def test_scan_summary_delivers_full_guidance_if_metadata_alone_cannot_fit():
    payload = {"relevant_rules": [], "guidance": "No governance rules match your current changes.",
               "omitted_mandatory": [],
               "stats": {"omitted": 0, "omitted_mandatory": 0, "max_tokens_budget": 60}}
    assert estimate_tokens(json.dumps(payload)) <= 60
    assert project_response(payload, view="summary") is payload


@pytest.mark.parametrize("view", ["full", "summary", "ids"])
def test_scan_failure_is_never_compacted(view):
    payload = {**_scan_payload(), "status": "FAIL", "error": "Scan refused."}
    assert project_response(payload, view=view) is payload


@pytest.mark.parametrize("listed", [0, 1, 10, 12])
def test_scan_ids_preserves_exact_totals_for_core_trimmed_lists(listed):
    payload = _scan_payload()
    payload["omitted_mandatory"] *= listed
    before = json.dumps(payload, sort_keys=True)
    ids = project_response(payload, view="ids")
    assert ids["omitted_mandatory_count"] == 12
    assert ids["omitted_mandatory_listed_count"] == len(ids["omitted_mandatory"]) == listed
    assert ids["unreviewed_rules_count"] == 27
    assert ids["unreviewed_rules_listed_count"] == len(ids["unreviewed_rules"]) == 10
    assert ids["relevant_rules"] == ["inv-a"]
    assert "guidance" not in ids
    assert json.dumps(payload, sort_keys=True) == before


def test_scan_ids_keeps_unreviewed_total_when_core_trimmed_all_names():
    payload = _scan_payload()
    del payload["unreviewed_rules"]
    ids = project_response(payload, view="ids")
    assert ids["unreviewed_rules_count"] == 27
    assert ids["unreviewed_rules_listed_count"] == 0
    assert ids["unreviewed_rules"] == []


@pytest.mark.parametrize("budget", [200, 600])
def test_public_scan_ids_reports_more_omitted_mandatory_rules_than_names(tmp_path, monkeypatch, budget):
    for index in range(40):
        _rule(tmp_path, f"inv-{index:02d}", "type: invariant\nhypothesis: h\ntarget_paths: ['src/*.py']\n", "invariant")
    monkeypatch.setenv("AEGIS_MAX_JIT_TOKENS", str(budget))
    args = {"workspace": str(tmp_path), "files": ["src/app.py"]}
    full = execute_tool("aegis_scan", args)
    ids = execute_tool("aegis_scan", {**args, "view": "ids"})
    assert ids["omitted_mandatory_count"] == full["stats"]["omitted_mandatory"]
    assert ids["omitted_mandatory_listed_count"] == len(ids["omitted_mandatory"])
    assert ids["omitted_mandatory_count"] > ids["omitted_mandatory_listed_count"]
    assert ids["omitted_mandatory"] == [item["name"] for item in full["omitted_mandatory"]]


@pytest.mark.parametrize("key", ["rules", "stale_rules", "ignored"])
def test_ids_counts_items_dropped_for_lack_of_identity(key):
    payload = {key: [{"name": "kept"}, {"hypothesis": "body without an identity"}]}
    assert project_response(payload, view="ids") == {
        key: ["kept"], f"{key}_count": 2, f"{key}_listed_count": 1,
    }


def test_scan_ids_displayed_counts_include_identity_filtering():
    payload = _scan_payload()
    payload["omitted_mandatory"].append({"reason": "token_budget"})
    payload["unreviewed_rules"].append({"change": "changed"})
    ids = project_response(payload, view="ids")
    assert ids["omitted_mandatory_count"] == 12
    assert ids["omitted_mandatory_listed_count"] == len(ids["omitted_mandatory"]) == 1
    assert ids["unreviewed_rules_count"] == 27
    assert ids["unreviewed_rules_listed_count"] == len(ids["unreviewed_rules"]) == 10


def test_empty_workspace_list_rules_summary_returns_full_response(tmp_path):
    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    args = {"workspace": str(tmp_path)}
    full = execute_tool("aegis_list_rules", args)
    assert full == {"rules": [], "stale_rules": [], "ignored": []}
    summary = execute_tool("aegis_list_rules", {**args, "view": "summary"})
    assert summary == full
    assert estimate_tokens(json.dumps(summary)) == estimate_tokens(json.dumps(full))


@pytest.mark.parametrize("as_list", [False, True])
@pytest.mark.parametrize("body_length", [0, 2000])
def test_generic_summary_returns_the_less_expensive_shape(body_length, as_list):
    rules = [{"_name": "rule", "hypothesis": "x" * body_length}]
    payload = rules if as_list else {"rules": rules, "stale_rules": [], "ignored": []}
    before = json.dumps(payload, sort_keys=True)
    summary = project_response(payload, view="summary")
    if as_list or body_length:
        assert estimate_tokens(json.dumps(summary)) < estimate_tokens(json.dumps(payload))
        assert "hypothesis" not in (summary[0] if as_list else summary["rules"][0])
    else:
        assert summary is payload
    assert json.dumps(payload, sort_keys=True) == before


def test_generic_summary_returns_full_when_the_shapes_cost_the_same():
    payload = {"rules": [{"_name": "rule", "hypothesis": "x" * 2000}], "stale_rules": [], "ignored": []}
    summary_tokens = estimate_tokens(json.dumps(project_response(payload, view="summary")))
    candidates = ({**payload, "rules": [{"_name": "rule", "hypothesis": "x" * length}]}
                  for length in range(400))
    equal_cost = next(p for p in candidates if estimate_tokens(json.dumps(p)) == summary_tokens)
    assert project_response(equal_cost, view="summary") is equal_cost


@pytest.mark.parametrize("key", ["rules", "stale_rules", "ignored"])
def test_generic_summary_reports_total_and_displayed_count_for_capped_lists(key):
    payload = {key: [{"_name": f"rule-{index}", "hypothesis": "Full guidance. " * 40} for index in range(12)]}
    summary = project_response(payload, view="summary")
    assert summary[f"{key}_count"] == 12
    assert summary[f"{key}_listed_count"] == len(summary[key]) == 10
    assert estimate_tokens(json.dumps(summary)) < estimate_tokens(json.dumps(payload))
