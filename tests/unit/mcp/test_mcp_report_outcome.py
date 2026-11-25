"""aegis_report_outcome: attributed by the server; without a check row, one unwitnessed claim.

With no ``aegis check --record`` row for the current tree (v4.3 T1), a report is one ``claimed``
row per (session, tree) with ``witness: self``: it carries ``source: "mcp"`` plus the client
host and the server session, both owned by the server, and the outcome as ``result``; it is
never a per-rule fitness row. A report needs an idempotency key, scoped by host and session
(host-matrix §3.8): a retry within a session is recorded once, and two sessions that pick the
same key are two reports. A report names at least one rule.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from aegis_core import checkrun, credit, rule_integrity, scan_exposure, treeid
import aegis_core.scan as scanner
from aegis_core.telemetry_engine import ledger
import aegis_mcp.server as server
from aegis_mcp.tools import execute_tool
from tests import helpers_humangate as hg
from tests import helpers_verified as hv

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")
DOCS_RULE = ("---\nid: trap-docs\ntype: trap\nenforcement: advisory\nhypothesis: docs\n"
             "target_paths:\n  - docs/*.md\n---\n# Docs\n\nBody long enough to be a rule body.\n")

KEY_REQUIRED = (
    "'idempotency_key' is required: send a unique key per report so a retry is never recorded twice."
)
RULES_REQUIRED = (
    "'rules_used' must name at least one rule from aegis_scan: "
    "an outcome with no rule has nothing to credit."
)


def _workspace_with_rule(root: Path, rule: str = "trap-x") -> Path:
    rules = root / ".aegis" / "rules" / "traps"
    rules.mkdir(parents=True)
    (rules / f"{rule}.md").write_text(
        f"---\nid: {rule}\ntype: trap\nhypothesis: h\nprediction: p\n---\n# x\n",
        encoding="utf-8",
    )
    return root


def _rows(ws: Path) -> list:
    path = ws / ".aegis" / "state" / "ledger.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture
def served(tmp_path, monkeypatch):
    """A server bound to a governed workspace and initialized by a claude-code client."""
    ws = _workspace_with_rule(tmp_path / "ws")
    monkeypatch.setattr(server, "_canonical_workspace", str(ws))
    monkeypatch.setattr(server, "_workspace_error", None)
    monkeypatch.setattr(server, "_session_id", None)
    monkeypatch.setattr(server, "_client_platform", server._client_platform)
    server._tool_call_times.clear()
    server.handle_request({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"clientInfo": {"name": "claude-code", "version": "1.0"}},
    })
    return ws


def _call(arguments, req_id=1):
    response = server.handle_request({
        "jsonrpc": "2.0", "id": req_id, "method": "tools/call",
        "params": {"name": "aegis_report_outcome", "arguments": arguments},
    })
    return response, json.loads(response["result"]["content"][0]["text"])


def test_row_records_source_host_and_server_session(served):
    response, payload = _call({"outcome": "success", "rules_used": ["trap-x"], "idempotency_key": "r-1"})
    assert response["result"]["isError"] is False, payload
    row, = _rows(served)
    assert (row["event"], row["witness"], row["result"], row["source"]) == ("claimed", "self", "tp", "mcp")
    assert "rule" not in row and "outcome" not in row  # an unwitnessed claim is never fitness evidence
    assert row["host"] == "claude-code"
    assert row["session"] == server._session_id
    assert len(server._session_id) == 32


def test_tool_arguments_cannot_choose_host_session_source_or_workspace(served, tmp_path):
    other = _workspace_with_rule(tmp_path / "other")
    response, payload = _call({
        "outcome": "success",
        "rules_used": ["trap-x"],
        "idempotency_key": "spoof-1",
        "host": "ci",
        "session": "forged-session",
        "source": "ci",
        "workspace": str(other),
        "_host": "ci",
        "_session": "forged-session",
    })
    assert response["result"]["isError"] is False, payload
    row, = _rows(served)
    assert row["source"] == "mcp"
    assert row["host"] == "claude-code"
    assert row["session"] == server._session_id
    assert _rows(other) == []


def test_missing_idempotency_key_is_rejected_and_records_nothing(served):
    response, payload = _call({"outcome": "success", "rules_used": ["trap-x"]})
    assert response["result"]["isError"] is True
    assert payload == {"status": "FAIL", "error": KEY_REQUIRED}
    assert _rows(served) == []


@pytest.mark.parametrize("key, error", [
    ("", KEY_REQUIRED),
    ("   ", KEY_REQUIRED),
    (None, KEY_REQUIRED),
    # A value of the wrong type breaks the published schema and is named as such.
    (7, "Invalid 'idempotency_key': 7. Expected a string."),
])
def test_blank_or_non_string_idempotency_key_is_rejected(served, key, error):
    response, payload = _call({"outcome": "success", "rules_used": ["trap-x"], "idempotency_key": key})
    assert response["result"]["isError"] is True
    assert payload == {"status": "FAIL", "error": error}
    assert _rows(served) == []


def test_retry_with_the_same_key_is_recorded_once(served):
    args = {"outcome": "fp", "rules_used": ["trap-x"], "idempotency_key": "retry-1"}
    _call(args, req_id=1)
    response, payload = _call(args, req_id=2)
    assert response["result"]["isError"] is False, payload
    assert len(_rows(served)) == 1


@pytest.mark.parametrize("alias", ["obsolete_rules_used", "rules", "rule_id"])
def test_legacy_argument_names_are_rejected(served, alias):
    response, payload = _call({"outcome": "success", alias: ["trap-x"], "idempotency_key": "alias-1"})
    assert response["result"]["isError"] is True
    assert payload == {
        "status": "FAIL",
        "error": f"Unknown argument(s) for aegis_report_outcome: ['{alias}']",
    }
    assert _rows(served) == []


@pytest.mark.parametrize("outcome,ledger_outcome", [
    ("success", "tp"), ("tp", "tp"), ("pass", "tp"),
    ("failure", "fp"), ("fp", "fp"), ("fail", "fp"),
    ("partial", "trigger"),
])
def test_outcome_maps_to_ledger_outcome(served, outcome, ledger_outcome):
    _call({"outcome": outcome, "rules_used": ["trap-x"], "idempotency_key": f"k-{outcome}"})
    row, = _rows(served)
    assert (row["v"], row["result"], row["report_key"]) == (2, ledger_outcome,
                                                           f"claude-code/{server._session_id}/k-{outcome}")


def test_invalid_outcome_is_rejected(served):
    response, payload = _call({"outcome": "maybe", "rules_used": ["trap-x"], "idempotency_key": "k"})
    assert response["result"]["isError"] is True
    assert payload["error"] == (
        "Invalid 'outcome': 'maybe'. Expected one of "
        "['success', 'partial', 'failure', 'tp', 'fp', 'pass', 'fail']."
    )


def test_unknown_rule_name_is_rejected(served):
    response, payload = _call({"outcome": "tp", "rules_used": ["no-such-rule"], "idempotency_key": "k"})
    assert response["result"]["isError"] is True
    assert payload["error"] == "Unknown rule(s): ['no-such-rule']. Only existing rules can be reported."
    assert _rows(served) == []


def test_rules_used_must_be_a_list_of_names(served):
    response, payload = _call({"outcome": "tp", "rules_used": "trap-x", "idempotency_key": "k"})
    assert response["result"]["isError"] is True
    assert payload["error"] == "'rules_used' must be a list of rule names."


def test_in_process_call_without_a_server_is_attributed_to_no_host(tmp_path):
    ws = _workspace_with_rule(tmp_path)
    result = execute_tool("aegis_report_outcome", {
        "workspace": str(ws), "outcome": "tp", "rules_used": ["trap-x"], "idempotency_key": "local-1",
    })
    assert result["status"] == "claimed"
    row, = _rows(ws)
    assert row["source"] == "mcp"
    assert row["host"] is None
    assert row["session"] is None


def test_rate_limit_still_applies_to_report_outcome(served):
    limit = server._RATE_LIMITS["aegis_report_outcome"][0]
    for i in range(limit):
        _call({"outcome": "tp", "rules_used": ["trap-x"], "idempotency_key": f"rl-{i}"}, req_id=i)
    response = server.handle_request({
        "jsonrpc": "2.0", "id": 99, "method": "tools/call",
        "params": {"name": "aegis_report_outcome",
                   "arguments": {"outcome": "tp", "rules_used": ["trap-x"], "idempotency_key": "rl-x"}},
    })
    assert response["error"]["code"] == -32000
    assert response["error"]["message"].startswith("Rate limit exceeded for 'aegis_report_outcome'")


def _reconnect(client_name="claude-code", req_id=5):
    server.handle_request({"jsonrpc": "2.0", "id": req_id, "method": "initialize",
                           "params": {"clientInfo": {"name": client_name}}})


def test_a_new_session_is_a_new_scope_for_the_same_key(served):
    """The trade-off of scoping keys by session: a retry after a reconnect records again,
    and a key another session already used never swallows or blocks a new report."""
    args = {"outcome": "tp", "rules_used": ["trap-x"], "idempotency_key": "cross-session"}
    _call(args)
    first_session = server._session_id
    _reconnect()
    assert server._session_id != first_session

    response, payload = _call(dict(args, outcome="fp"), req_id=6)

    assert response["result"]["isError"] is False, payload
    assert [(r["session"], r["result"]) for r in _rows(served)] == [(first_session, "tp"), (server._session_id, "fp")]


def test_reusing_a_key_for_a_different_report_is_refused(served):
    _call({"outcome": "tp", "rules_used": ["trap-x"], "idempotency_key": "reused"})

    response, payload = _call({"outcome": "fp", "rules_used": ["trap-x"], "idempotency_key": "reused"}, req_id=6)

    assert response["result"]["isError"] is True
    assert payload == {
        "status": "FAIL",
        "error": "'idempotency_key' 'reused' was already used for a different report: "
                 "send a new key for each new report.",
    }
    row, = _rows(served)
    assert row["result"] == "tp"


@pytest.mark.parametrize("arguments", [
    {"outcome": "tp", "idempotency_key": "no-rules"},
    {"outcome": "tp", "idempotency_key": "no-rules", "rules_used": []},
])
def test_a_report_without_rules_is_rejected_and_records_nothing(served, arguments):
    response, payload = _call(arguments)
    assert response["result"]["isError"] is True
    assert payload == {"status": "FAIL", "error": RULES_REQUIRED}
    assert _rows(served) == []


def test_schema_requires_a_key_and_at_least_one_rule():
    tool = next(t for t in server.TOOL_DEFINITIONS if t["name"] == "aegis_report_outcome")
    schema = tool["inputSchema"]
    assert sorted(schema["required"]) == ["idempotency_key", "outcome", "rules_used"]
    assert schema["properties"]["rules_used"]["minItems"] == 1


@pytest.mark.parametrize("client_name,host", [
    ("claude-code", "claude-code"),
    ("antigravity-client", "antigravity"),
    ("codex-mcp-client", "codex-cli"),
    ("some-new-agent", "generic"),
    ("", "generic"),
])
def test_row_host_names_the_client_and_an_unknown_client_is_generic(served, client_name, host):
    _reconnect(client_name)
    response, payload = _call({"outcome": "tp", "rules_used": ["trap-x"], "idempotency_key": f"h-{client_name}"})
    assert response["result"]["isError"] is False, payload
    row, = _rows(served)
    assert row["host"] == host


# ── the credited set is the server's own exposure (R-trust-64) ──────────────

def _project(tmp_path, monkeypatch) -> hg.Repo:
    """``trap-sample`` (src/*.py) and ``trap-docs`` (docs/*.md); the work tree changes both paths."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "GIT_CONFIG_GLOBAL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setattr(credit, "_EXPOSED", {})
    repo = hv.make_project(tmp_path)
    repo.write(".aegis/rules/traps/trap-docs.md", DOCS_RULE)
    repo.write("docs/guide.md", "# guide\n")
    repo.commit("a docs rule")
    hv.use_stub_runner(repo.home.path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    repo.write("docs/guide.md", "# guide v2\n")
    return repo


def _scan_as(repo: hg.Repo, files, session: str = "S") -> None:
    assert hv.mcp_call("aegis_scan", repo.root, session=session, files=list(files)).get("status") != "FAIL"


def _check(repo: hg.Repo) -> dict:
    out = checkrun.record(repo.root, tests=True, base="main")
    assert out.status == "recorded" and out.row["passed"] is True
    return out.row


def _report_as(repo: hg.Repo, session: str = "S", key: str = "k1") -> dict:
    return hv.mcp_call("aegis_report_outcome", repo.root, session=session, outcome="success",
                       rules_used=["trap-sample"], idempotency_key=key)


@needs_git
def test_a_ledger_exposure_row_never_enlarges_the_credited_set(tmp_path, monkeypatch):
    """Given session S's scan exposed only trap-sample and an exposure row naming trap-docs for S and
    its host appended straight to the ledger, When S reports a passing check whose change matches
    both, Then only trap-sample is credited."""
    repo = _project(tmp_path, monkeypatch)
    _scan_as(repo, ["src/app.py"])
    ledger.append_rows(repo.root, [{"v": ledger.LEDGER_VERSION, "ts": "2026-10-19T00:00:00Z", "event": "exposure",
                                    "rule": "trap-docs", "session": "S", "host": "claude-code",
                                    "paths": ["docs/guide.md"], "rev": None}])
    assert credit.exposed_rules(repo.root, "claude-code", "S") == {"trap-sample", "trap-docs"}  # display reads both
    _check(repo)
    res = _report_as(repo)
    assert (res["status"], res["credited"]) == ("recorded", ["trap-sample"])
    assert [r["rule"] for r in hv.rows_of(repo.root, "report")] == ["trap-sample"]


@needs_git
def test_a_rule_the_servers_own_scan_exposed_is_credited(tmp_path, monkeypatch):
    repo = _project(tmp_path, monkeypatch)
    _scan_as(repo, ["src/app.py", "docs/guide.md"])
    _check(repo)
    assert _report_as(repo)["credited"] == ["trap-docs", "trap-sample"]


@needs_git
def test_fresh_scope_gets_a_receipt_when_idle_scopes_fill_retention(tmp_path, monkeypatch):
    repo = _project(tmp_path, monkeypatch)
    host, session, backlog = "claude-code", "pressure-report", "pressure-backlog"
    try:
        _scan_as(repo, ["src/app.py"], session=session)
        original = scan_exposure.resolve(str(repo.root), host, session, None)
        assert original is not None
        for index in range(256):
            scan_exposure.offer(str(tmp_path / f"past-root-{index}"), host, backlog, None)

        _scan_as(repo, ["src/app.py"], session="pressure-fresh")
        _check(repo)
        assert _report_as(repo, session="pressure-fresh")["credited"] == ["trap-sample"]
        assert scan_exposure.resolve(str(repo.root), host, session, original[0]) is None

        _scan_as(repo, ["src/app.py"], session=session)
        assert _report_as(repo, session=session)["credited"] == []
    finally:
        for name in (session, backlog, "pressure-fresh"):
            scan_exposure.retire(name)


@needs_git
def test_server_issues_distinct_receipts_only_on_opted_in_full_scan(tmp_path, monkeypatch):
    repo = _project(tmp_path, monkeypatch)
    monkeypatch.setattr(server, "_canonical_workspace", str(repo.root))
    monkeypatch.setattr(server, "_workspace_error", None)
    server._tool_call_times.clear()
    _reconnect()

    def scan(files, view="full", opt_in=True):
        return _scan_response(files, view, opt_in)

    assert "_meta" not in scan(["src/app.py"], "ids")
    source = scan(["src/app.py"])["_meta"]["aegis/scanRef"]
    assert "_meta" not in scan(["src/app.py"], opt_in=False)
    assert scan(["src/app.py"])["_meta"]["aegis/scanRef"] == source
    docs = scan(["docs/guide.md"])["_meta"]["aegis/scanRef"]
    assert source != docs
    _check(repo)
    args = {"outcome": "success", "rules_used": ["trap-sample"]}
    assert _call(dict(args, idempotency_key="implicit"))[1]["credited"] == []
    assert _call(dict(args, idempotency_key="source", scan_ref=source))[1]["credited"] == ["trap-sample"]
    assert _call(dict(args, idempotency_key="docs", scan_ref=docs))[1]["credited"] == ["trap-docs"]
    _reconnect()
    assert _call(dict(args, idempotency_key="stale", scan_ref=source))[1]["error"] == "invalid_scan_ref"


def _scan_response(files, view="full", opt_in=True):
    return server.handle_request({
        "jsonrpc": "2.0", "id": 30, "method": "tools/call", "params": {
            "name": "aegis_scan", "arguments": {"files": files, "view": view},
            "_meta": {"aegis/returnScanRef": opt_in},
        },
    })["result"]


@needs_git
def test_explicit_receipts_do_not_cross_revisions_or_reappear_after_eviction(tmp_path, monkeypatch):
    repo = _project(tmp_path, monkeypatch)
    monkeypatch.setattr(server, "_canonical_workspace", str(repo.root))
    monkeypatch.setattr(server, "_workspace_error", None)
    server._tool_call_times.clear()
    _reconnect()
    original = _scan_response(["src/app.py"])["_meta"]["aegis/scanRef"]
    path = repo.root / ".aegis/rules/traps/trap-sample.md"
    path.write_bytes(path.read_bytes() + b"\nA distinct rule revision.\n")
    revised = _scan_response(["src/app.py"])["_meta"]["aegis/scanRef"]
    assert original != revised
    _check(repo)
    args = {"outcome": "success", "rules_used": ["trap-sample"]}
    assert _call(dict(args, idempotency_key="old", scan_ref=original))[1]["credited"] == []
    assert _call(dict(args, idempotency_key="new", scan_ref=revised))[1]["credited"] == ["trap-sample"]
    for index in range(16):
        assert "_meta" in _scan_response([f"src/path-{index}.py"])
    assert _call(dict(args, idempotency_key="evicted", scan_ref=revised))[1]["error"] == "invalid_scan_ref"
    assert _call(dict(args, idempotency_key="implicit"))[1]["credited"] == []
    assert _scan_response(["src/app.py"])["_meta"]["aegis/scanRef"] != revised


@needs_git
@pytest.mark.parametrize(("budget", "full"), [(2000, False), (200, True)])
def test_summary_attests_only_when_it_returns_full_guidance(tmp_path, monkeypatch, budget, full):
    repo = _project(tmp_path, monkeypatch)
    monkeypatch.setattr(server, "_canonical_workspace", str(repo.root))
    monkeypatch.setattr(server, "_workspace_error", None)
    repo.write(".aegis/config.json", json.dumps({"jit": {"max_tokens": budget}}))
    _reconnect()
    summary = _scan_response(["src/app.py"], "summary")
    payload = json.loads(summary["content"][0]["text"])
    assert ("guidance" in payload) == full
    assert ("_meta" in summary) == full
    expected = [r["name"] for r in payload["relevant_rules"]] if full else []
    assert [r["rule"] for r in hv.rows_of(repo.root, "exposure")] == expected


@needs_git
def test_inspection_and_notification_do_not_create_report_evidence(tmp_path, monkeypatch):
    repo = _project(tmp_path, monkeypatch)
    monkeypatch.setattr(server, "_canonical_workspace", str(repo.root))
    monkeypatch.setattr(server, "_workspace_error", None)
    server._tool_call_times.clear()
    _reconnect()
    params = {"name": "aegis_scan", "arguments": {"files": ["src/app.py"]}}
    server.handle_request({"jsonrpc": "2.0", "method": "tools/call", "params": params})
    params["arguments"]["view"] = "ids"
    server.handle_request({"jsonrpc": "2.0", "id": 31, "method": "tools/call", "params": params})
    _check(repo)
    result = _call({"outcome": "success", "rules_used": ["trap-sample"], "idempotency_key": "no-delivery"})[1]
    assert result["credited"] == []
    assert hv.rows_of(repo.root, "exposure") == []


@needs_git
@pytest.mark.parametrize("request_id", [float("inf"), -float("inf"), float("nan"), True, []],
                         ids=["overflow", "negative-overflow", "nan", "boolean", "array"])
def test_invalid_scan_request_id_refuses_before_dispatch(tmp_path, monkeypatch, request_id):
    repo = _project(tmp_path, monkeypatch)
    monkeypatch.setattr(server, "_canonical_workspace", str(repo.root))
    monkeypatch.setattr(server, "_workspace_error", None)
    _reconnect()
    response = server.handle_request({"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {
        "name": "aegis_scan", "arguments": {"files": ["src/app.py"]},
        "_meta": {"aegis/returnScanRef": True},
    }})
    assert response == {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
    assert hv.rows_of(repo.root, "exposure") == []
    _check(repo)
    assert _call({"outcome": "success", "rules_used": ["trap-sample"], "idempotency_key": "invalid-id"})[1]["credited"] == []


@needs_git
def test_stdio_rejects_overflowing_id_and_returns_a_strict_full_response(tmp_path, monkeypatch):
    repo = _project(tmp_path, monkeypatch)
    init = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"clientInfo": {"name": "claude-code"}}}
    scan = {"jsonrpc": "2.0", "id": 17, "method": "tools/call", "params": {
        "name": "aegis_scan", "arguments": {"files": ["src/app.py"]}, "_meta": {"aegis/returnScanRef": True},
    }}
    invalid = json.dumps(scan).replace('"id": 17', '"id": 1e9999')
    completed = subprocess.run([sys.executable, "-m", "aegis_mcp"],
                               input="\n".join((json.dumps(init), invalid, json.dumps(scan), "")),
                               env={**os.environ, "AEGIS_WORKSPACE": str(repo.root)},
                               text=True, capture_output=True, timeout=20, check=True)

    def reject_constant(_):
        pytest.fail("nonfinite value in the JSON response")

    initialized, rejected, delivered = [json.loads(line, parse_constant=reject_constant)
                                        for line in completed.stdout.splitlines()]
    assert initialized["id"] == 0
    assert rejected == {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
    assert delivered["id"] == 17 and delivered["result"]["_meta"]["aegis/scanRef"]
    payload = json.loads(delivered["result"]["content"][0]["text"], parse_constant=reject_constant)
    assert [rule["name"] for rule in payload["relevant_rules"]] == ["trap-sample"]
    assert [row["rule"] for row in hv.rows_of(repo.root, "exposure")] == ["trap-sample"]


@needs_git
def test_full_deliveries_record_their_own_revision_once(tmp_path, monkeypatch):
    from aegis_core.rules import lf_digest

    repo = _project(tmp_path, monkeypatch)
    path = repo.root / ".aegis/rules/traps/trap-sample.md"
    prior = lf_digest(path.read_bytes())[:16]
    _scan_as(repo, ["src/app.py"])
    path.write_bytes(path.read_bytes() + b"\nNew guidance for the same path.\n")
    current = lf_digest(path.read_bytes())[:16]
    hv.mcp_call("aegis_scan", repo.root, session="S", files=["src/app.py"], view="ids")
    assert [r["rev"] for r in hv.rows_of(repo.root, "exposure")] == [prior]
    _scan_as(repo, ["src/app.py"])
    _scan_as(repo, ["src/app.py"])
    assert [r["rev"] for r in hv.rows_of(repo.root, "exposure")] == [prior, current]


@needs_git
@pytest.mark.skipif(os.name == "nt", reason="requires distinct POSIX backslash and slash paths")
@pytest.mark.parametrize("inferred", [False, True])
@pytest.mark.parametrize("tested_literal", [False, True], ids=["slash", "literal"])
def test_literal_backslash_scan_cannot_credit_slash_path(tmp_path, monkeypatch, inferred, tested_literal):
    repo = _project(tmp_path, monkeypatch)
    literal = "src\\app.py"
    repo.write(literal, "before\n")
    repo.commit("add the literal POSIX path")
    repo.git("branch", "-f", "main", repo.head())
    repo.write(literal, "after\n")
    options = {} if inferred else {"files": [literal]}
    res = hv.mcp_call("aegis_scan", repo.root, session="path-proof", **options)
    assert [entry["name"] for entry in res["relevant_rules"]] == ["trap-sample"]
    if not tested_literal:
        repo.write(literal, "before\n")
        repo.write("src/app.py", "def app():\n    return 3\n")
    _check(repo)
    assert _report_as(repo, session="path-proof")["credited"] == []
    assert not any(row.get("observation") == "empty_join" for row in ledger.read(repo.root).raw_rows)
    if not tested_literal:
        _scan_as(repo, ["src/app.py"], session="exact-path")
        assert _report_as(repo, session="exact-path")["credited"] == ["trap-sample"]


@needs_git
def test_subdirectory_scope_requires_workspace_relative_path_proof(tmp_path, monkeypatch):
    repo = _project(tmp_path, monkeypatch)
    scope = repo.root / "package"
    repo.write("package/.aegis/rules/traps/trap-sample.md", hg.RULE)
    repo.write("package/src/app.py", "def app():\n    return 1\n")
    repo.write("package/run_checks.py", hv.PASSING)
    repo.commit("establish a nested workspace")
    repo.git("branch", "-f", "main", repo.head())
    repo.write("package/src/app.py", "def app():\n    return 2\n")
    result = checkrun.record(scope, tests=True, base="main")
    assert result.status == "recorded" and result.row["passed"] is True

    def report(session, **options):
        hv.mcp_call("aegis_scan", scope, session=session, **options)
        return hv.mcp_call("aegis_report_outcome", scope, session=session, outcome="success",
                           rules_used=["trap-sample"], idempotency_key=session)

    assert report("nested-inferred")["credited"] == []
    assert not any(row.get("observation") == "empty_join" for row in ledger.read(scope).raw_rows)
    assert report("nested-exact", files=["src/app.py"])["credited"] == ["trap-sample"]


@needs_git
def test_composed_reviewed_rule_cannot_attest_widened_policy_with_base_blob(tmp_path, monkeypatch):
    repo = _project(tmp_path, monkeypatch)
    path = ".aegis/rules/invariants/inv-reviewed.md"
    base = ("---\nid: inv-reviewed\ntype: invariant\nhypothesis: preserve settings\n"
            "target_paths:\n  - config/base.txt\n---\n# Reviewed rule\n")
    repo.write(path, base)
    repo.write("config/extra.txt", "initial\n")
    repo.commit("establish reviewed scope")
    repo.git("branch", "-f", "main", repo.head())
    repo.git("update-ref", "refs/remotes/origin/main", repo.head())
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    repo.write(path, base.replace("  - config/base.txt\n", "  - config/base.txt\n  - config/extra.txt\n"))
    repo.write("config/extra.txt", "changed\n")
    result = hv.mcp_call("aegis_scan", repo.root, session="composed", files=["config/extra.txt"])
    assert [item["name"] for item in result["relevant_rules"]] == ["inv-reviewed"]
    repo.write(path, base)
    _check(repo)
    assert _report_as(repo, session="composed")["credited"] == []
    assert hv.rows_of(repo.root, "report") == []


def _mixed_receipt_project(tmp_path, monkeypatch):
    repo = _project(tmp_path, monkeypatch)
    path = ".aegis/rules/invariants/inv-reviewed.md"
    reviewed = ("---\nid: inv-reviewed\ntype: invariant\nhypothesis: preserve settings\n"
                "target_paths:\n  - config/base.txt\n---\n# Reviewed rule\n")
    repo.write(path, reviewed)
    for name in ("base", "extra", "disjoint"):
        repo.write(f"config/{name}.txt", "initial\n")
    repo.commit("establish captured policy")
    repo.git("update-ref", "refs/remotes/origin/main", repo.head())
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    repo.write(path, reviewed.replace("  - config/base.txt\n", "  - config/base.txt\n  - config/extra.txt\n"))
    repo.commit("prepare unreviewed scope change")
    repo.git("branch", "-f", "main", repo.head())
    monkeypatch.setattr(server, "_canonical_workspace", str(repo.root))
    monkeypatch.setattr(server, "_workspace_error", None)
    _reconnect()
    return repo


@needs_git
@pytest.mark.parametrize("explicit", [True, False], ids=["explicit", "implicit"])
@pytest.mark.parametrize("overlap", ["exact", "synthetic", "both", "disjoint"])
def test_mixed_receipt_joins_exact_policy_and_keeps_full_path_coverage(tmp_path, monkeypatch, explicit, overlap):
    from aegis_core import fitness
    from aegis_core.rules import lf_digest

    repo = _mixed_receipt_project(tmp_path, monkeypatch)
    scope = ["src/app.py", "config/extra.txt"]
    changes = {"exact": scope[:1], "synthetic": scope[1:], "both": scope,
               "disjoint": ["config/disjoint.txt"]}[overlap]
    for path in changes:
        repo.write(path, "changed\n")
    credit.record_exposure(repo.root, "claude-code", "earlier", ["trap-sample", "inv-reviewed"],
                           ts="2001-01-01T00:00:00Z", scope_basis="match")

    first = _scan_response(scope)
    second = _scan_response(scope)
    ordinary = _scan_response(scope, opt_in=False)
    assert ordinary["content"] == first["content"] == second["content"]
    assert "aegis/scanRef" not in ordinary.get("_meta", {})
    result = json.loads(first["content"][0]["text"])
    assert {entry["name"]: entry["matched_files"] for entry in result["relevant_rules"]} == {
        "trap-sample": ["src/app.py"], "inv-reviewed": ["config/extra.txt"]}
    revision = lf_digest((repo.root / ".aegis/rules/traps/trap-sample.md").read_bytes())
    delivered, = [r for r in hv.rows_of(repo.root, "exposure") if r["session"] == server._session_id]
    assert (delivered["rule"], delivered["rev"]) == ("trap-sample", revision[:16])
    reference = first.get("_meta", {}).get("aegis/scanRef")
    assert reference and second["_meta"]["aegis/scanRef"] == reference
    check = _check(repo)
    args = {"outcome": "success", "rules_used": ["trap-sample", "inv-reviewed"], "idempotency_key": "mixed"}
    if explicit:
        args["scan_ref"] = reference
    expected = ["trap-sample"] if overlap in ("exact", "both") else []
    for _ in range(2):
        report = _call(args)[1]
        assert report["status"] == "recorded" and report["check"] == check["id"]
        assert report["credited"] == expected
    rows = hv.rows_of(repo.root, "report")
    assert [r["rule"] for r in rows] == expected
    assert [r["check"] for r in ledger.read(repo.root).raw_rows if r.get("observation") == "empty_join"] == (
        [check["id"]] if overlap == "disjoint" else [])
    if expected:
        saved, = rows
        assert (saved["scan_ref"], saved["rule_revision"], saved["rule_type"]) == (reference, revision, "trap")
        repo.commit("land the tested tree")
        repo.git("branch", "-f", "main", repo.head())
        credit.project_credits(repo.root, client=hv.FakeCI([hv.ci_run(repo.head())]), verify_ci=True)
        scores = fitness.for_rules(repo.root, rule_integrity.effective_ruleset(repo.root).served)
        assert scores["trap-sample"].tp == 1 and scores["trap-sample"].eligible_sessions == 0
        assert scores["inv-reviewed"].tp == 0 and scores["inv-reviewed"].eligible_sessions == 1


@needs_git
@pytest.mark.parametrize("failure", ["digest", "foreign-rule", "literal-scope"])
def test_indeterminate_mixed_delivery_does_not_offer_a_receipt(tmp_path, monkeypatch, failure):
    from dataclasses import replace
    from aegis_core.rules import Rule

    repo = _mixed_receipt_project(tmp_path, monkeypatch)
    scope = ["src/app.py", "config/extra.txt"]
    if failure == "literal-scope":
        scope[0] = "src/../src/app.py"
    else:
        effective = rule_integrity.effective

        class ForeignRule(Rule):
            pass

        def alter(rule):
            if failure == "digest":
                return replace(rule, digest="bad")
            return ForeignRule(rule.id, rule.path, rule.type, rule.meta, rule.body, rule.digest, raw=rule.raw)

        def damaged(*args, **kwargs):
            snapshot = effective(*args, **kwargs)
            rules = tuple(alter(rule) if rule.id == "trap-sample" else rule for rule in snapshot.ruleset.rules)
            return replace(snapshot, ruleset=replace(snapshot.ruleset, rules=rules))

        monkeypatch.setattr(rule_integrity, "effective", damaged)
    repo.write("src/app.py", "changed\n")
    reply = _scan_response(scope)
    assert len(json.loads(reply["content"][0]["text"])["relevant_rules"]) == 2
    assert "aegis/scanRef" not in reply.get("_meta", {})
    if failure != "literal-scope":
        assert hv.rows_of(repo.root, "exposure") == []
    _check(repo)
    assert _call({"outcome": "success", "rules_used": ["trap-sample"], "idempotency_key": "unproved"})[1][
        "credited"] == []
    assert not any(r.get("observation") == "empty_join" for r in ledger.read(repo.root).raw_rows)


@needs_git
def test_policy_proof_uses_only_members_that_survive_selection(tmp_path, monkeypatch):
    from dataclasses import replace

    repo = _mixed_receipt_project(tmp_path, monkeypatch)
    repo.write(".aegis/rules/traps/z-unknown.md", hg.RULE.replace("trap-sample", "z-unknown"))
    effective = rule_integrity.effective

    def damaged(*args, **kwargs):
        snapshot = effective(*args, **kwargs)
        rules = tuple(replace(rule, digest="bad") if rule.id == "z-unknown" else rule
                      for rule in snapshot.ruleset.rules)
        return replace(snapshot, ruleset=replace(snapshot.ruleset, rules=rules))

    monkeypatch.setattr(rule_integrity, "effective", damaged)
    scope = ["src/app.py", "config/extra.txt"]
    assert scanner.scan(repo.root, scope, budget=3).exposure_snapshot() is None
    mixed = scanner.scan(repo.root, scope, budget=2).exposure_snapshot()
    assert mixed is not None
    assert mixed.coverage == (("inv-reviewed", ("config/extra.txt",)), ("trap-sample", ("src/app.py",)))
    assert [rule.rule_id for rule in mixed.rules] == ["trap-sample"]
    assert scanner.scan(repo.root, scope, budget=1).exposure_snapshot() is None
    empty = scanner.scan(repo.root, scope, budget=0).exposure_snapshot()
    assert empty is not None and empty.coverage == empty.rules == ()


@needs_git
def test_mixed_receipt_requires_flush_and_keeps_distinct_returns_separate(tmp_path, monkeypatch, capsys):
    repo = _mixed_receipt_project(tmp_path, monkeypatch)
    scope = ["src/app.py", "config/extra.txt"]
    repo.write("src/app.py", "changed\n")
    request = {"jsonrpc": "2.0", "id": 36, "method": "tools/call", "params": {
        "name": "aegis_scan", "arguments": {"files": scope}, "_meta": {"aegis/returnScanRef": True},
    }}

    class FailedFlush(io.StringIO):
        def flush(self):
            raise OSError("transport unavailable")

    reset = scan_exposure.stdio.set(True)
    try:
        response = server.handle_request(request)
        failed_ref = response["result"]["_meta"]["aegis/scanRef"]
        with contextlib.redirect_stdout(FailedFlush()), pytest.raises(OSError):
            server.send_response(response)
        assert hv.rows_of(repo.root, "exposure") == []
        response = server.handle_request(request)
        reference = response["result"]["_meta"]["aegis/scanRef"]
        server.send_response(response)
        assert json.loads(capsys.readouterr().out)["result"]["_meta"]["aegis/scanRef"] == reference
    finally:
        scan_exposure.stdio.reset(reset)

    assert [row["rule"] for row in hv.rows_of(repo.root, "exposure")] == ["trap-sample"]
    competing = _scan_response([*scope, "config/disjoint.txt"])["_meta"]["aegis/scanRef"]
    assert competing != reference
    _check(repo)
    args = {"outcome": "success", "rules_used": ["trap-sample"], "idempotency_key": "mixed-transport"}
    assert _call(args)[1]["credited"] == []
    assert _call(dict(args, scan_ref=failed_ref))[1]["error"] == "invalid_scan_ref"
    assert _call(dict(args, scan_ref=reference))[1]["credited"] == ["trap-sample"]
    _reconnect()
    assert _call(dict(args, scan_ref=reference))[1]["error"] == "invalid_scan_ref"
    assert len(hv.rows_of(repo.root, "report")) == 1


@needs_git
def test_confirmed_credit_follows_the_effective_policy_revision(tmp_path, monkeypatch):
    from aegis_core import fitness

    repo = _project(tmp_path, monkeypatch)
    path = ".aegis/rules/invariants/inv-reviewed.md"
    original = ("---\nid: inv-reviewed\ntype: invariant\nhypothesis: preserve settings\n"
                "target_paths:\n  - src/app.py\n---\n# Reviewed rule\n")
    repo.write(path, original)
    repo.commit("establish reviewed scope")
    repo.git("branch", "-f", "main", repo.head())
    repo.git("update-ref", "refs/remotes/origin/main", repo.head())
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    repo.write("src/app.py", "def app():\n    return 3\n")
    credit.record_exposure(repo.root, "claude-code", "earlier", ["inv-reviewed"],
                           ts="2001-01-01T00:00:00Z", scope_basis="match")
    _scan_as(repo, ["src/app.py"], session="effective-policy")
    _check(repo)
    for key in ("initial", "retry"):
        assert "inv-reviewed" in _report_as(repo, session="effective-policy", key=key)["credited"]
    repo.commit("land the reviewed tree")
    repo.git("branch", "-f", "main", repo.head())
    credit.project_credits(repo.root, client=hv.FakeCI([hv.ci_run(repo.head())]), verify_ci=True)

    def counts():
        rules = rule_integrity.effective_ruleset(repo.root).served
        score = fitness.for_rules(repo.root, rules)["inv-reviewed"]
        return score.tp, score.eligible_sessions

    initial = counts()
    assert initial[0] == 1
    assert len([r for r in hv.rows_of(repo.root, "report") if r["rule"] == "inv-reviewed"]) == 1
    repo.write(path, original.replace("  - src/app.py\n", "  - src/app.py\n  - src/extra.py\n"))
    widened = counts()
    assert widened[0] == 0 and widened[1] > initial[1]
    repo.write(path, original)
    assert counts() == initial


@needs_git
def test_directory_inferred_promotion_serves_guidance_without_revision_evidence(tmp_path, monkeypatch):
    from aegis_core import fitness
    from aegis_core.rules import lf_digest, load_rules

    repo = _project(tmp_path, monkeypatch)
    rule_id, subject = "inv-reviewed", "config/subject.txt"
    original = repo.root / ".aegis/rules/invariants/inv-reviewed.md"
    promoted = repo.root / ".aegis/rules/gates/inv-reviewed.md"
    initial_source = ("---\nid: inv-reviewed\nhypothesis: preserve settings\n"
                      "target_paths:\n  - config/subject.txt\n---\n# Reviewed rule\n")
    repo.write(original.relative_to(repo.root).as_posix(), initial_source)
    repo.write(subject, "initial\n")
    repo.commit("establish reviewed scope")
    repo.git("branch", "-f", "main", repo.head())
    repo.git("update-ref", "refs/remotes/origin/main", repo.head())
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    monkeypatch.setattr(server, "_canonical_workspace", str(repo.root))
    monkeypatch.setattr(server, "_workspace_error", None)
    arguments = {"outcome": "success", "rules_used": [rule_id], "idempotency_key": "evidence"}
    revision = lf_digest(original.read_bytes())

    def scan():
        _reconnect()
        response = _scan_response([subject])
        payload = json.loads(response["content"][0]["text"])
        entry, = payload["relevant_rules"]
        assert entry["name"] == rule_id
        exposed = [r["rev"] for r in hv.rows_of(repo.root, "exposure") if r["session"] == server._session_id]
        return response.get("_meta", {}).get("aegis/scanRef"), exposed, entry["type"]

    def score(ruleset=rule_integrity.effective_ruleset):
        rule = ruleset(repo.root).get(rule_id)
        observed = fitness.for_rules(repo.root, [rule])[rule_id]
        return observed.tp, observed.eligible_sessions

    def listed():
        result = hv.mcp_call("aegis_list_rules", repo.root)
        return next(row["fitness"]["tp"] for row in result["rules"] if row["id"] == rule_id)

    repo.write(subject, "changed\n")
    credit.record_exposure(repo.root, "claude-code", "earlier", [rule_id], scope_basis="match",
                           ts="2001-01-01T00:00:00Z")
    reference, exposures, kind = scan()
    assert reference and exposures == [revision[:16]] and kind == "invariant"
    original_check = _check(repo)
    assert _call(dict(arguments, scan_ref=reference))[1]["credited"] == [rule_id]
    repo.commit("land the tested tree")
    repo.git("branch", "-f", "main", repo.head())
    credit.project_credits(repo.root, client=hv.FakeCI([hv.ci_run(repo.head())]), verify_ci=True)
    initial_score = score()
    assert initial_score[0] == 1
    assert score(load_rules) == initial_score and listed() == 1

    promoted.parent.mkdir(exist_ok=True)
    original.rename(promoted)
    assert lf_digest(promoted.read_bytes()) == revision
    synthetic_ref, synthetic_exposures, synthetic_kind = scan()
    assert synthetic_kind == "gate"
    synthetic_check = _check(repo)
    assert synthetic_check["id"] != original_check["id"]
    synthetic_credit = _call(arguments)[1]["credited"]
    synthetic_score = score()
    assert synthetic_ref is None and synthetic_exposures == []
    assert synthetic_credit == []
    assert synthetic_score[0] == 0 and synthetic_score[1] > initial_score[1]
    assert score(load_rules) == synthetic_score and listed() == 0

    promoted.rename(original)
    assert score() == initial_score
    assert score(load_rules) == initial_score and listed() == 1
    reference, exposures, kind = scan()
    assert reference and exposures == [revision[:16]] and kind == "invariant"
    assert _call(dict(arguments, scan_ref=reference))[1]["credited"] == [rule_id]
    report, = hv.rows_of(repo.root, "report")
    assert (report["check"], report["rule_revision"]) == (original_check["id"], revision)


@needs_git
@pytest.mark.parametrize(("source_dir", "next_dir", "kind"), [
    ("invariants", "gates", "invariant"),
    ("traps", "personas", "trap"),
])
@pytest.mark.parametrize("historical", ["current", "recover", "ambiguous"])
def test_confirmed_policy_type_survives_only_exact_restoration(tmp_path, monkeypatch, source_dir, next_dir,
                                                              kind, historical):
    from aegis_core import fitness
    from aegis_core.rules import lf_digest, load_rules

    repo = _project(tmp_path, monkeypatch)
    rule_id, subject = "captured-policy", "config/captured.txt"
    source = f".aegis/rules/{source_dir}/{rule_id}.md"
    other = f".aegis/rules/{next_dir}/{rule_id}.md"
    body = f"---\nid: {rule_id}\nhypothesis: preserve settings\ntarget_paths: [{subject}]\n---\n# Captured\n"
    repo.write(source, body)
    repo.write(subject, "initial\n")
    repo.commit("establish captured policy")
    repo.git("branch", "-f", "main", repo.head())
    repo.git("update-ref", "refs/remotes/origin/main", repo.head())
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    repo.write(subject, "changed\n")
    credit.record_exposure(repo.root, "claude-code", "earlier", [rule_id], scope_basis="match",
                           ts="2001-01-01T00:00:00Z")
    monkeypatch.setattr(server, "_canonical_workspace", str(repo.root))
    monkeypatch.setattr(server, "_workspace_error", None)
    _reconnect()
    scan = _scan_response([subject])
    ref = scan["_meta"]["aegis/scanRef"]
    revision = lf_digest((repo.root / source).read_bytes())
    if historical == "ambiguous":
        repo.write(other, body)
        repo.write(subject, "initial\n")
        repo.commit("establish ambiguous historical policy")
        repo.git("branch", "-f", "main", repo.head())
        repo.write(subject, "changed\n")
    check = _check(repo)
    if historical == "ambiguous":
        ledger.append_rows(repo.root, [{"v": 2, "event": "report", "witness": "aegis",
                                       "check": check["id"], "tree": check["tree"], "rule": rule_id,
                                       "scan_ref": ref, "rule_revision": revision, "result": "tp"}])
    else:
        args = {"outcome": "success", "rules_used": [rule_id], "idempotency_key": "typed", "scan_ref": ref}
        assert _call(args)[1]["credited"] == [rule_id]
    repo.commit("land the tested tree")
    repo.git("branch", "-f", "main", repo.head())
    landing = repo.head()
    report, = hv.rows_of(repo.root, "report")
    if historical == "recover":
        # Replay the exact historical row shape written before policy type was stored.
        rows = hv.ledger_rows(repo.root)
        for row in rows:
            if row.get("event") == "report":
                row.pop("rule_type", None)
        ledger.ledger_path(repo.root).write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    if historical == "ambiguous":
        (repo.root / other).unlink()
        repo.commit("restore one definition")
    repo.git("update-ref", "refs/remotes/origin/main", repo.head())
    credit.project_credits(repo.root, client=hv.FakeCI([hv.ci_run(landing)]), verify_ci=True)

    def scores(*, has_ordinary_trigger=False):
        values = []
        for load in (load_rules, rule_integrity.effective_ruleset):
            rule = load(repo.root).get(rule_id)
            fit = fitness.for_rules(repo.root, [rule])[rule_id]
            assert fit.evidence_available and fit.evidence_error is None
            values.append((fit.tp, fit.eligible_sessions))
        result = hv.mcp_call("aegis_list_rules", repo.root)
        listed = next(row["fitness"]["tp"] for row in result["rules"] if row["id"] == rule_id)
        assert values[0] == values[1] and listed == values[0][0]
        delivered = scanner.scan(repo.root, [subject])
        entry, = delivered["relevant_rules"]
        assert entry["name"] == rule_id
        assert ("no evidence yet" in delivered["guidance"]) == (listed == 0 and not has_ordinary_trigger)
        return values[0]

    before = scores()
    if historical == "ambiguous":
        assert before[0] == 0 and before[1] > 0
        return
    assert before[0] == 1
    (repo.root / other).parent.mkdir(exist_ok=True)
    (repo.root / source).rename(repo.root / other)
    repo.write("reviewed-type-change.txt", "distinguish the reviewed update from the earlier tested tree\n")
    repo.commit("review the directory change")
    repo.git("update-ref", "refs/remotes/origin/main", repo.head())
    assert lf_digest((repo.root / other).read_bytes()) == revision
    after = scores()
    assert after[0] == 0 and after[1] > before[1]
    (repo.root / other).rename(repo.root / source)
    repo.commit("review the restored type")
    repo.git("update-ref", "refs/remotes/origin/main", repo.head())
    assert scores() == before
    assert report["rule_revision"] == revision
    if historical == "current":
        assert report["rule_type"] == kind
        ledger.append(repo.root, [{"rule": rule_id, "outcome": "trigger", "source": "manual", "key": report["key"]}])
        assert scores(has_ordinary_trigger=True) == before


@pytest.mark.parametrize("alias", ["timestamp", "triggered_at", "ts"])
@pytest.mark.parametrize(("stamp", "has_age"), [
    ("0001-01-01T00:00:00+01:00", False), ("9999-12-31T23:59:59-01:00", False),
    ("2000-01-01T01:00:00+01:00", True), (None, False),
], ids=["underflow", "overflow", "offset", "absent"])
def test_legacy_timestamp_bounds_keep_ordinary_outcome_weight_in_scan(tmp_path, alias, stamp, has_age):
    from aegis_core import fitness, scan as scanner
    from aegis_core.adjudication import Adjudications
    from aegis_core.rules import load_rules

    rule_id = "trap-x"
    rule_dir = _workspace_with_rule(tmp_path, rule_id) / ".aegis/rules/traps"
    path = rule_dir / f"{rule_id}.md"
    path.write_text(path.read_text(encoding="utf-8").replace("prediction: p", "target_paths: [src/app.py]"),
                    encoding="utf-8")
    row = {"rule_id": rule_id, "signal": "success", "source": "ci", "metadata": {"credit_weight": 1.5}}
    if stamp is not None:
        row[alias] = stamp
    history = ledger.ledger_path(tmp_path)
    history.parent.mkdir(parents=True, exist_ok=True)
    history.write_text(json.dumps(row) + "\n", encoding="utf-8")
    rule = load_rules(tmp_path).get(rule_id)
    fit = fitness.for_rules(tmp_path, [rule], adjudications=Adjudications())[rule_id]
    assert (fit.triggers, fit.tp, fit.evidence_available) == (1, 1.5, True)
    assert (fit.mde is not None) == has_age
    result = scanner.scan(tmp_path, ["src/app.py"])
    entry, = result["relevant_rules"]
    assert entry["name"] == rule_id
    label = "untestable (insufficient trigger volume)" if has_age else "insufficient (n=1)"
    assert label in result["guidance"]


@needs_git
def test_mandatory_slot_fallback_retains_the_reviewed_revision(tmp_path, monkeypatch):
    from aegis_core.rules import lf_digest

    repo = _project(tmp_path, monkeypatch)
    original = ("---\nid: inv-reviewed\nhypothesis: preserve settings\n"
                "target_paths:\n  - config/first.txt\n---\n# Reviewed rule\n")
    rule_path = ".aegis/rules/invariants/inv-reviewed.md"
    repo.write(rule_path, original)
    for number in (1, 2):
        rule_id = f"inv-peer-{number}"
        repo.write(f".aegis/rules/invariants/{rule_id}.md",
                   original.replace("inv-reviewed", rule_id).replace("config/first.txt", "config/second.txt"))
    repo.write("config/first.txt", "initial\n")
    repo.write("config/second.txt", "initial\n")
    repo.commit("establish reviewed scope")
    repo.git("branch", "-f", "main", repo.head())
    repo.git("update-ref", "refs/remotes/origin/main", repo.head())
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    revision = lf_digest((repo.root / rule_path).read_bytes())
    repo.write(rule_path, original.replace("  - config/first.txt\n", "  - config/first.txt\n  - config/second.txt\n"))
    monkeypatch.setattr(server, "_canonical_workspace", str(repo.root))
    monkeypatch.setattr(server, "_workspace_error", None)
    _reconnect()
    scan = _scan_response(["config/first.txt"])
    payload = json.loads(scan["content"][0]["text"])
    assert [entry["name"] for entry in payload["relevant_rules"]] == ["inv-reviewed"]
    exposure, = hv.rows_of(repo.root, "exposure")
    assert exposure["rev"] == revision[:16]
    repo.write(rule_path, original)
    repo.write("config/first.txt", "changed\n")
    _check(repo)
    args = {"outcome": "success", "rules_used": ["inv-reviewed"], "idempotency_key": "fallback",
            "scan_ref": scan["_meta"]["aegis/scanRef"]}
    assert _call(args)[1]["credited"] == ["inv-reviewed"]


@needs_git
def test_scope_retention_limit_preserves_the_served_telemetry_revision(tmp_path, monkeypatch):
    from aegis_core.rules import lf_digest

    repo = _project(tmp_path, monkeypatch)
    files = ["src/app.py"] + [f"extra/unmatched-{number}" for number in range(256)]
    res = hv.mcp_call("aegis_scan", repo.root, session="bounded", files=files)
    assert [entry["name"] for entry in res["relevant_rules"]] == ["trap-sample"]
    row, = hv.rows_of(repo.root, "exposure")
    assert row["rev"] == lf_digest((repo.root / ".aegis/rules/traps/trap-sample.md").read_bytes())[:16]
    _check(repo)
    assert _report_as(repo, session="bounded")["credited"] == []
    assert not any(row.get("observation") == "empty_join" for row in ledger.read(repo.root).raw_rows)


@needs_git
def test_full_return_records_exposure_when_all_receipt_scopes_are_reserved(tmp_path, monkeypatch):
    from aegis_core.rules import lf_digest

    repo = _project(tmp_path, monkeypatch)
    monkeypatch.setattr(scan_exposure, "_SCOPES", {})
    monkeypatch.setattr(scan_exposure, "_MAX_SCOPES", 1)
    with scan_exposure.capture() as pending:
        scan_exposure.offer(str(tmp_path / "other"), "claude-code", "other", None)
    scan_exposure.commit(pending[0])

    reply = hv.mcp_call("aegis_scan", repo.root, session="capacity", files=["src/app.py"])
    assert [entry["name"] for entry in reply["relevant_rules"]] == ["trap-sample"]
    row, = hv.rows_of(repo.root, "exposure")
    source = repo.root / ".aegis/rules/traps/trap-sample.md"
    assert row["rev"] == lf_digest(source.read_bytes())[:16]
    _check(repo)
    assert _report_as(repo, session="capacity")["credited"] == []

    scan_exposure.retire("other")
    _scan_as(repo, ["src/app.py"], session="capacity")
    assert _report_as(repo, session="capacity", key="after-capacity")["credited"] == []
    assert len(hv.rows_of(repo.root, "exposure")) == 1


@needs_git
@pytest.mark.parametrize("failure", ["type", "nonfinite", "flush"])
def test_stdio_receipt_becomes_visible_only_after_a_successful_send(tmp_path, monkeypatch, capsys, failure):
    repo = _project(tmp_path, monkeypatch)
    monkeypatch.setattr(server, "_canonical_workspace", str(repo.root))
    monkeypatch.setattr(server, "_workspace_error", None)
    _reconnect()
    request = {"jsonrpc": "2.0", "id": 36, "method": "tools/call", "params": {
        "name": "aegis_scan", "arguments": {"files": ["src/app.py"]},
        "_meta": {"aegis/returnScanRef": True},
    }}
    reset = scan_exposure.stdio.set(True)
    try:
        response = server.handle_request(request)
        reference = response["result"]["_meta"]["aegis/scanRef"]
        subject = (str(repo.root), "claude-code", server._session_id)
        assert scan_exposure.resolve(*subject, reference) is None
        assert hv.rows_of(repo.root, "exposure") == []

        class FailedFlush(io.StringIO):
            def flush(self):
                raise OSError("transport unavailable")

        with contextlib.ExitStack() as stack:
            if failure == "flush":
                stack.enter_context(contextlib.redirect_stdout(FailedFlush()))
                error = OSError
            else:
                response["result"]["unencodable"] = object() if failure == "type" else float("nan")
                error = TypeError if failure == "type" else ValueError
            with pytest.raises(error):
                server.send_response(response)
        assert scan_exposure.resolve(*subject, reference) is None
        assert hv.rows_of(repo.root, "exposure") == []

        response = server.handle_request(request)
        reference = response["result"]["_meta"]["aegis/scanRef"]
        server.send_response(response)
        frame = json.loads(capsys.readouterr().out)
        assert frame["result"]["_meta"]["aegis/scanRef"] == reference
        assert scan_exposure.resolve(*subject, reference) is not None
        assert [row["rule"] for row in hv.rows_of(repo.root, "exposure")] == ["trap-sample"]
    finally:
        scan_exposure.stdio.reset(reset)
        _reconnect()
    assert scan_exposure.resolve(*subject, reference) is None


@needs_git
def test_amended_rule_is_not_credited_from_an_older_scan(tmp_path, monkeypatch):
    repo = _project(tmp_path, monkeypatch)
    _scan_as(repo, ["src/app.py"])
    path = repo.root / ".aegis/rules/traps/trap-sample.md"
    path.write_text(path.read_text(encoding="utf-8") + "\nAmended after the scan.\n", encoding="utf-8")
    check = _check(repo)

    for key in ("one", "one", "two"):
        result = _report_as(repo, key=key)
        assert (result["check"], result["credited"]) == (check["id"], [])
    assert hv.rows_of(repo.root, "report") == []
    assert not any(row.get("observation") == "empty_join" for row in ledger.read(repo.root).raw_rows)
    assert credit.derive(credit.read_rows(repo.root), landed=lambda _: None) == []


@needs_git
def test_rule_restored_after_report_tree_binding_still_does_not_credit(tmp_path, monkeypatch):
    repo = _project(tmp_path, monkeypatch)
    path = repo.root / ".aegis/rules/traps/trap-sample.md"
    original = path.read_bytes()
    _scan_as(repo, ["src/app.py"])
    path.write_bytes(original + b"\nAmended after the scan.\n")
    check = _check(repo)

    @contextlib.contextmanager
    def restore_after_bind(root):
        with treeid.bind(root) as bound:
            path.write_bytes(original)
            yield bound

    monkeypatch.setattr("aegis_mcp.handlers.telemetry.treeid",
                        SimpleNamespace(bind=restore_after_bind, TreeError=treeid.TreeError))
    result = _report_as(repo)
    assert (result["check"], result["credited"]) == (check["id"], [])
    assert hv.rows_of(repo.root, "report") == []


@needs_git
def test_identical_scans_credit_the_exact_unchanged_revision_once(tmp_path, monkeypatch):
    from aegis_core import fitness
    from aegis_core.rules import lf_digest
    from aegis_core.scan import RULE_CACHE

    repo = _project(tmp_path, monkeypatch)
    repo.git("branch", "-f", "main", repo.head())
    credit.record_exposure(repo.root, "claude-code", "older-observation", ["trap-sample"],
                           ts="2001-01-01T00:00:00Z", scope_basis="match")
    for _ in range(2):
        _scan_as(repo, ["src/app.py"])
    check = _check(repo)
    for key in ("one", "one", "two"):
        assert _report_as(repo, key=key)["credited"] == ["trap-sample"]
    _scan_as(repo, ["src/app.py"], session="another")
    assert _report_as(repo, session="another")["credited"] == ["trap-sample"]
    report, = hv.rows_of(repo.root, "report")
    path = repo.root / ".aegis/rules/traps/trap-sample.md"
    assert report["check"] == check["id"]
    assert report["rule_revision"] == lf_digest(path.read_bytes())
    assert report["scan_ref"]
    assert credit.project_credits(repo.root).outcome_rows == ()
    repo.commit("land the tested tree")
    repo.git("branch", "-f", "main", repo.head())
    ci = hv.FakeCI([hv.ci_run(repo.head())])
    projected = credit.project_credits(repo.root, client=ci, verify_ci=True)
    assert [row["rule"] for row in projected.outcome_rows] == ["trap-sample"]
    assert ci.asked == [repo.head()]
    assert projected.outcome_rows[0]["rule_revision"] == report["rule_revision"]
    rules = RULE_CACHE.get(repo.root).served
    original = fitness.for_rules(repo.root, rules)["trap-sample"]
    assert original.tp == 1
    path.write_bytes(path.read_bytes() + b"\nA new revision.\n")
    rules = RULE_CACHE.get(repo.root).served
    amended = fitness.for_rules(repo.root, rules)["trap-sample"]
    assert amended.tp == 0
    assert amended.eligible_sessions > original.eligible_sessions


@needs_git
def test_unscanned_matching_path_does_not_credit_the_rule(tmp_path, monkeypatch):
    repo = _project(tmp_path, monkeypatch)
    _scan_as(repo, ["src/elsewhere.py"])
    check = _check(repo)

    assert _report_as(repo)["credited"] == []
    assert hv.rows_of(repo.root, "report") == []
    observation, = [row for row in ledger.read(repo.root).raw_rows if row.get("observation") == "empty_join"]
    assert (observation["check"], observation["tree"]) == (check["id"], check["tree"])


@needs_git
def test_distinct_session_projections_are_ambiguous_without_a_reference(tmp_path, monkeypatch):
    repo = _project(tmp_path, monkeypatch)
    _scan_as(repo, ["src/app.py"])
    _scan_as(repo, ["docs/guide.md"])
    _check(repo)

    assert _report_as(repo)["credited"] == []
    assert hv.rows_of(repo.root, "report") == []


@needs_git
def test_a_fresh_server_process_credits_nothing_from_persisted_exposure_rows(tmp_path, monkeypatch):
    """Given S's exposure rows persisted by an earlier server process, When a new process (no
    in-process exposure) records S's report, Then it is witnessed, credits nothing and does not fail."""
    repo = _project(tmp_path, monkeypatch)
    _scan_as(repo, ["src/app.py", "docs/guide.md"])
    assert {r["rule"] for r in hv.rows_of(repo.root, "exposure")} == {"trap-sample", "trap-docs"}
    monkeypatch.setattr(credit, "_EXPOSED", {})
    scan_exposure.retire("S")
    _check(repo)
    res = _report_as(repo)
    assert (res["status"], res["witness"], res["credited"]) == ("recorded", "aegis", [])
    assert hv.rows_of(repo.root, "report") == []


# ── one tree computation per report, outside the ledger lock (R-trust-53) ────

@needs_git
def test_one_report_computes_the_work_tree_once(tmp_path, monkeypatch):
    """Given a passing check for the current tree and an exposed rule, When one report runs, Then
    the tree is bound once and git add runs once; the credit is unchanged."""
    repo = _project(tmp_path, monkeypatch)
    _scan_as(repo, ["src/app.py"])
    _check(repo)
    real_bind, real_run = treeid.bind, subprocess.run
    entered, adds = [], []

    @contextlib.contextmanager
    def counting_bind(root):
        entered.append(root)
        with real_bind(root) as bound:
            yield bound

    def spying_run(argv, *args, **kwargs):
        if isinstance(argv, (list, tuple)) and "add" in argv and "-A" in argv:
            adds.append(list(argv))
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(treeid, "bind", counting_bind)
    monkeypatch.setattr(subprocess, "run", spying_run)
    res = _report_as(repo)
    assert (res["status"], res["credited"]) == ("recorded", ["trap-sample"])
    assert (len(entered), len(adds)) == (1, 1)


@needs_git
def test_the_credited_rules_follow_the_check_chosen_under_the_lock(tmp_path, monkeypatch):
    """Given a second passing check for the same tree appended after the handler bound the tree but
    before the ledger lock is taken, Then the diff is taken against the base of the check the report
    chose (the newest) and that check's rules are credited, not the first check's."""
    repo = _project(tmp_path, monkeypatch)
    _scan_as(repo, ["src/app.py", "docs/guide.md"])
    first = _check(repo)
    second = dict(first, id="e" * 16, base="docs-base")
    diffed = []
    real_bind = treeid.bind

    def diff_entries(base):
        diffed.append(base)
        return [("M", "docs/guide.md")] if base == "docs-base" else [("M", "src/app.py")]

    @contextlib.contextmanager
    def late_check_bind(root):
        with real_bind(root) as bound:
            ledger.append_rows(repo.root, [second])
            yield SimpleNamespace(binding=bound.binding, diff_entries=diff_entries, run=bound.run)

    monkeypatch.setattr(treeid, "bind", late_check_bind)
    res = _report_as(repo)
    assert diffed == ["docs-base"]
    assert (res["check"], res["credited"]) == (second["id"], ["trap-docs"])


@needs_git
@pytest.mark.parametrize("error", [treeid.TreeError("git is not installed or not on PATH"), OSError("no temp dir")])
def test_a_bind_that_fails_records_one_unwitnessed_claim(tmp_path, monkeypatch, error):
    repo = _project(tmp_path, monkeypatch)
    _scan_as(repo, ["src/app.py"])
    _check(repo)

    @contextlib.contextmanager
    def failing_bind(root):
        raise error
        yield  # pragma: no cover

    monkeypatch.setattr(treeid, "bind", failing_bind)
    res = _report_as(repo)
    assert (res["status"], res["witness"], res["credited"], res["scope"]) == ("claimed", "self", [], {"tree": None})
    claimed, = hv.rows_of(repo.root, "claimed")
    assert claimed["tree"] is None and hv.rows_of(repo.root, "report") == []


@needs_git
def test_a_failure_while_recording_is_reported_not_raised(tmp_path, monkeypatch):
    repo = _project(tmp_path, monkeypatch)

    def broken_submit(*_args, **_kwargs):
        raise RuntimeError("ledger is on fire")

    monkeypatch.setattr(credit, "submit_report", broken_submit)
    assert _report_as(repo) == {"status": "FAIL", "error": "Failed to record outcome: ledger is on fire"}


# ── a report that records nothing writes nothing (R-structure-a1) ────────────

def _edits(ws: Path) -> list:
    path = ws / ".aegis" / "state" / "activity.jsonl"
    if not path.exists():
        return []
    return [r for r in map(json.loads, path.read_text(encoding="utf-8").splitlines()) if r["event"] == "edit"]


@pytest.fixture
def reporting(tmp_path, monkeypatch):
    """A governed workspace whose work tree binds to ``trees[-1]``, and an in-process report call
    (the server's rate limiter is not in play)."""
    from aegis_mcp.handlers import telemetry

    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    ws = _workspace_with_rule(tmp_path / "ws")
    trees = ["a" * 40]

    @contextlib.contextmanager
    def bind(root):
        class Bound:
            binding = treeid.TreeBinding("ok", trees[-1], "")

            def diff_entries(self, base):
                return []
        yield Bound()

    monkeypatch.setattr(treeid, "bind", bind)
    # The process-lifetime maps start empty, as in a fresh server.
    monkeypatch.setattr(telemetry, "_RECORDED", type(telemetry._RECORDED)())
    monkeypatch.setattr(telemetry, "_EDITS", {})

    def report(key: str, session: str = "S") -> dict:
        return telemetry.handle_report_outcome({
            "workspace": str(ws), "outcome": "success", "rules_used": ["trap-x"], "idempotency_key": key,
            "files": ["src/a.py"], "_host": "claude-code", "_session": session})

    return ws, trees, report, telemetry


def _witness(ws: Path, tree: str) -> None:
    ledger.append_rows(ws, [{"v": ledger.LEDGER_VERSION, "ts": "2026-10-20T00:00:00Z", "event": "check",
                             "id": "c1", "tree": tree, "witness": "aegis", "passed": True,
                             "tests": {"exit": 0, "passed": 3}}])


def test_unwitnessed_reports_with_fresh_keys_write_one_edit_row(reporting):
    ws, _, report, telemetry = reporting
    answers = [report(f"k{i}") for i in range(300)]
    assert [(a["status"], a["recorded"]) for a in answers[:2]] == [("claimed", True), ("claimed", False)]
    assert [r["event"] for r in _rows(ws)] == ["claimed"]
    assert [e["key"] for e in _edits(ws)] == ["k0"]
    assert [k[1:] for k in telemetry._RECORDED] == [("S", "k0")]


def test_witnessed_reports_write_at_most_the_session_cap_of_edit_rows(reporting):
    ws, trees, report, telemetry = reporting
    _witness(ws, trees[-1])
    assert {report(f"k{i}")["status"] for i in range(300)} == {"recorded"}
    assert len(_edits(ws)) == credit.MAX_REPORT_ROWS_PER_SESSION
    assert len(telemetry._RECORDED) == credit.MAX_REPORT_ROWS_PER_SESSION <= 1024


def test_a_rate_limited_report_writes_no_edit_row(reporting, monkeypatch):
    ws, _, report, _ = reporting
    monkeypatch.setattr(credit, "MAX_REPORT_ROWS_PER_SESSION", 0)
    assert report("k1")["status"] == "rate_limited"
    assert _edits(ws) == []


def test_a_retry_with_the_same_key_leaves_one_edit_row(reporting):
    ws, trees, report, _ = reporting
    _witness(ws, trees[-1])
    assert report("k1")["status"] == report("k1")["status"] == "recorded"
    assert [e["key"] for e in _edits(ws)] == ["k1"]


def test_a_new_claim_after_the_tree_changed_still_writes_its_edit_row(reporting):
    ws, trees, report, _ = reporting
    assert report("k1")["recorded"] is True
    trees.append("b" * 40)
    assert report("k2")["recorded"] is True
    assert [e["key"] for e in _edits(ws)] == ["k1", "k2"]


def test_a_failed_append_does_not_count_toward_the_cap_or_fail_the_report(reporting, monkeypatch, capsys):
    ws, trees, report, _ = reporting
    _witness(ws, trees[-1])
    monkeypatch.setattr(credit, "MAX_REPORT_ROWS_PER_SESSION", 1)
    activity = ws / ".aegis" / "state" / "activity.jsonl"
    activity.mkdir(parents=True)  # cannot be appended to
    assert report("k1")["status"] == "recorded"
    assert "edit event not recorded" in capsys.readouterr().err
    activity.rmdir()
    assert report("k2")["status"] == report("k3")["status"] == "recorded"
    assert [e["key"] for e in _edits(ws)] == ["k2"]


def test_the_process_maps_stay_bounded(reporting, monkeypatch):
    ws, _, report, telemetry = reporting
    monkeypatch.setattr(telemetry, "_MAX_RECORDED", 2)
    for session in ("S1", "S2", "S3", "S4"):
        assert report("k", session)["recorded"] is True
    assert [e["session"] for e in _edits(ws)] == ["S1", "S2", "S3", "S4"]
    assert len(telemetry._RECORDED) <= 2 and len(telemetry._EDITS) <= 2
