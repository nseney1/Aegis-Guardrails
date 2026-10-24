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
import json
from pathlib import Path
import subprocess

import pytest

from aegis_core import checkrun, credit, treeid
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


@pytest.mark.parametrize("alias", ["cells_used", "rules", "rule_id", "cell_id"])
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
def test_a_fresh_server_process_credits_nothing_from_persisted_exposure_rows(tmp_path, monkeypatch):
    """Given S's exposure rows persisted by an earlier server process, When a new process (no
    in-process exposure) records S's report, Then it is witnessed, credits nothing and does not fail."""
    repo = _project(tmp_path, monkeypatch)
    _scan_as(repo, ["src/app.py", "docs/guide.md"])
    assert {r["rule"] for r in hv.rows_of(repo.root, "exposure")} == {"trap-sample", "trap-docs"}
    monkeypatch.setattr(credit, "_EXPOSED", {})
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

    class Bound:
        binding = treeid.TreeBinding("ok", first["tree"], "")

        def diff_entries(self, base):
            diffed.append(base)
            return [("M", "docs/guide.md")] if base == "docs-base" else [("M", "src/app.py")]

    @contextlib.contextmanager
    def late_check_bind(root):
        bound = Bound()
        ledger.append_rows(repo.root, [second])
        yield bound

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
    monkeypatch.setattr(telemetry, "_EDITS", {}, raising=False)

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
