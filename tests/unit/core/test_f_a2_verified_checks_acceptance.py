"""Acceptance contract for lane f-a2-verified-checks (v4.3 spec §3 T1, §9; v4.4 spec §12).

Given/When/Then, written before the code and never weakened to make it pass:

1. No credit without CI confirmation: a check row is a label until the required workflow on the
   landing commit concluded success; a failing run voids it, and only ``confirmed`` counts.
2. Hidden files cannot fake a pass: an assume-unchanged file makes the tree unbindable, and a file
   hidden through .git/info/exclude is not in the snapshot the tests run on.
3. A file swap during the run does not reach the snapshot, and the row binds the tree that was run.
4. A ``conftest.py`` change is protected: the row says so and credit is withheld until approved.
5. Exit 5 and zero passed tests are never evidence; a failing check is never a witness.
6. The repository never chooses the command that runs.
7. A report with no check row for the current tree writes at most one ``claimed`` row per
   (session, tree), never earns credit, and the session is capped.
8. The credited rules are the ones the server saw: exposed in this session's scans and matching the
   change; the agent's ``rules_used`` is ignored.
"""
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from aegis_core import checkrun, credit, human_gate, treeid
from aegis_core.telemetry_engine import ledger
from tests import helpers_humangate as hg
from tests import helpers_verified as hv

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")

SECOND_RULE = ("---\nid: trap-docs\ntype: trap\nenforcement: advisory\nhypothesis: docs\n"
               "target_paths:\n  - docs/*.md\n---\n# Docs\n\nBody long enough to be a rule body.\n")
THIRD_RULE = ("---\nid: trap-src\ntype: trap\nenforcement: advisory\nhypothesis: src\n"
              "target_paths:\n  - src/*.py\n---\n# Src\n\nBody long enough to be a rule body.\n")


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)


def _edit_app(repo: hg.Repo, value: int = 2) -> None:
    repo.write("src/app.py", f"def app():\n    return {value}\n")


def _scan(repo: hg.Repo, files=("src/app.py",), session: str = "sess-1") -> None:
    res = hv.mcp_call("aegis_scan", repo.root, session=session, files=list(files))
    assert res.get("status") != "FAIL", res


def _report(repo: hg.Repo, rules=("trap-sample",), key: str = "k1", outcome: str = "success", session: str = "sess-1"):
    return hv.mcp_call("aegis_report_outcome", repo.root, session=session, outcome=outcome,
                       rules_used=list(rules), idempotency_key=key)


def _landed(repo: hg.Repo):
    return credit.landed_lookup(repo.root, refs=("HEAD",))


def _credits(repo: hg.Repo, approved=None):
    return credit.derive(credit.read_rows(repo.root), landed=_landed(repo), approved=approved)


def _fake_bind(next_tree):
    """``treeid.bind`` for report floods: each report binds ``next_tree()`` without spawning git."""

    class Bound:
        def __init__(self, tree):
            self.binding = treeid.TreeBinding("ok", tree, "")

        def diff_entries(self, base):
            return []

    @contextlib.contextmanager
    def bind(root):
        yield Bound(next_tree())

    return bind


# ── 1. No credit without CI confirmation ─────────────────────────────────────

@needs_git
@pytest.mark.parametrize("runs,state,counts", [
    ([("success", "completed")], "confirmed", True),
    ([("failure", "completed")], "voided", False),
    ([("timed_out", "completed")], "voided", False),
    ([("cancelled", "completed")], "landed", False),
    ([(None, "in_progress")], "landed", False),
    ([], "landed", False),
])
def test_only_a_ci_confirmed_landing_counts(tmp_path, runs, state, counts):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo)
    _scan(repo)
    out = checkrun.record(repo.root, tests=True)
    assert out.status == "recorded" and out.row["witness"] == "aegis"
    assert _report(repo)["status"] == "recorded"
    assert [c.state for c in _credits(repo)] == ["witnessed"]  # a label until it lands
    commit = repo.commit("work")
    client = hv.FakeCI([hv.ci_run(commit, conclusion, status=status, run_id=i + 1)
                        for i, (conclusion, status) in enumerate(runs)])
    credit.confirm(repo.root, client=client, workflow=hv.CI_WORKFLOW, landed=_landed(repo))
    derived, = _credits(repo)
    assert (derived.rule, derived.state, derived.counts) == ("trap-sample", state, counts)
    rows = credit.confirmed_outcome_rows(_credits(repo))
    assert [r["rule"] for r in rows] == (["trap-sample"] if counts else [])
    # nothing in the ledger scores the rule before CI said so
    assert ledger.aggregate(repo.root, "trap-sample")["triggers"] == 0


@needs_git
def test_a_failure_report_on_a_confirmed_check_is_a_neutral_trigger_never_fp(tmp_path):
    """Given three witnessed, landed, CI-green checks each reported ``failure``, When credit is
    projected, Then each counts as a trigger, the rule's fp stays 0 and nothing is decided."""
    from aegis_core import fitness, rules

    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    commits = []
    for n in range(3):
        _edit_app(repo, n + 2)
        _scan(repo)
        assert checkrun.record(repo.root, tests=True, base="main").row["passed"] is True
        assert _report(repo, key=f"f{n}", outcome="failure")["status"] == "recorded"
        commits.append(repo.commit(f"work {n}"))
    repo.git("branch", "-f", "main", commits[-1])
    runs = [hv.ci_run(c, run_id=i + 1) for i, c in enumerate(commits)]
    credit.confirm(repo.root, client=hv.FakeCI(runs), workflow=hv.CI_WORKFLOW)
    proj = credit.project_credits(repo.root)
    assert [(c.state, c.counts, c.result) for c in proj.credits] == [("confirmed", True, "trigger")] * 3
    assert [r["outcome"] for r in proj.outcome_rows] == ["trigger"] * 3
    fit = fitness.for_rules(repo.root, rules.load_rules(repo.root).served)["trap-sample"]
    assert (fit.fp, fit.tp) == (0, 0) and fit.state != "decided"


@needs_git
def test_a_check_that_never_landed_stays_a_label(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo)
    _scan(repo)
    checkrun.record(repo.root, tests=True)
    _report(repo)
    credit.confirm(repo.root, client=hv.FakeCI(), workflow=hv.CI_WORKFLOW, landed=_landed(repo))
    derived, = _credits(repo)
    assert derived.state == "witnessed" and not derived.counts


@needs_git
def test_a_void_row_is_terminal_even_when_ci_later_succeeds(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo)
    _scan(repo)
    out = checkrun.record(repo.root, tests=True)
    _report(repo)
    commit = repo.commit("work")
    credit.record_void(repo.root, out.row["id"], "ci_divergence")
    credit.confirm(repo.root, client=hv.FakeCI([hv.ci_run(commit)]), workflow=hv.CI_WORKFLOW, landed=_landed(repo))
    derived, = _credits(repo)
    assert derived.state == "voided" and derived.reason == "ci_divergence" and not derived.counts


# ── 2. Hidden files cannot fake a pass ───────────────────────────────────────

@needs_git
def test_an_assume_unchanged_file_makes_the_tree_unbindable_and_gives_no_label(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    repo.git("update-index", "--assume-unchanged", "src/app.py")
    _edit_app(repo, 999)  # git no longer sees the edit
    out = checkrun.record(repo.root, tests=True)
    assert out.status == "unbindable" and out.row is None
    assert "assume-unchanged" in out.reason
    assert hv.rows_of(repo.root, "check") == []
    _scan(repo)
    res = _report(repo)
    assert res["witness"] == "self" and res["status"] == "claimed"


@needs_git
def test_a_skip_worktree_file_present_on_disk_makes_the_tree_unbindable(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    repo.git("update-index", "--skip-worktree", "src/app.py")
    _edit_app(repo, 999)
    out = checkrun.record(repo.root, tests=True)
    assert out.status == "unbindable" and "skip-worktree" in out.reason


@needs_git
def test_a_file_hidden_through_info_exclude_is_not_in_the_snapshot_so_the_run_fails(tmp_path):
    repo = hv.make_project(tmp_path, runner="import sys\nimport hidden_helper\nprint('3 passed in 0s')\n")
    hv.use_stub_runner(repo.home.path)
    (repo.root / ".git" / "info").mkdir(exist_ok=True)
    (repo.root / ".git" / "info" / "exclude").write_text("hidden_helper.py\n", encoding="utf-8")
    repo.write("hidden_helper.py", "FORGED = True\n")
    _edit_app(repo)
    out = checkrun.record(repo.root, tests=True)
    assert out.status == "recorded"
    assert out.row["passed"] is False and out.row["exit"] != 0
    assert "hidden_helper.py" not in treeid.tree_files(repo.root)
    _scan(repo)
    assert _report(repo)["witness"] == "self"


@needs_git
def test_sabotage_after_the_check_changes_the_tree_and_loses_the_label(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo)
    _scan(repo)
    out = checkrun.record(repo.root, tests=True)
    assert out.row["passed"] is True
    repo.write("src/app.py", "def app():\n    raise SystemExit(1)\n")  # sabotage after verification
    res = _report(repo)
    assert res["witness"] == "self" and res["status"] == "claimed"
    assert _credits(repo) == []


# ── 3. File swaps do not fool the snapshot ───────────────────────────────────

@needs_git
@pytest.mark.skipif(os.name == "nt", reason="symlinks are POSIX here")
def test_a_tree_holding_any_symlink_gets_no_witness_label(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo)
    os.symlink("app.py", repo.root / "src" / "alias.py")  # inside the tree, still refused
    _scan(repo)
    out = checkrun.record(repo.root, tests=True, base="main")
    assert out.status == "unbindable" and out.row is None and "src/alias.py" in out.reason
    res = _report(repo)
    assert res["witness"] == "self" and res["status"] == "claimed"
    assert _credits(repo) == []


@needs_git
def test_a_swap_during_the_run_does_not_reach_the_snapshot(tmp_path):
    root = tmp_path / "project"
    swap = (
        "import os, pathlib, sys\n"
        f"pathlib.Path({str(root)!r}, 'src', 'app.py').write_text('def app():\\n    return 999\\n')\n"
        "sys.path.insert(0, os.getcwd())\n"
        "from src.app import app\n"
        "ok = app() == 2\n"
        "print('1 passed in 0s' if ok else '1 failed in 0s')\n"
        "sys.exit(0 if ok else 1)\n"
    )
    repo = hv.make_project(tmp_path, runner=swap)
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo, 2)
    before = hv.tree_now(repo.root)
    out = checkrun.record(repo.root, tests=True)
    assert out.status == "recorded"
    assert out.row["tree"] == before  # the row names the tree that was run, not the swapped one
    assert out.row["passed"] is True  # the snapshot still held the version that returns 2
    assert hv.tree_now(repo.root) != before  # and the swap really happened in the work tree
    _scan(repo)
    assert _report(repo)["witness"] == "self"  # the work tree no longer is the verified tree


# ── 4. conftest.py changes are gated ─────────────────────────────────────────

@needs_git
def test_a_conftest_change_is_protected_and_earns_no_credit_until_approved(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    repo.write("conftest.py", "import pytest\n")
    _edit_app(repo)
    _scan(repo)
    out = checkrun.record(repo.root, tests=True, base="main")
    assert out.row["protected_changed"] is True and "test-infra" in out.row["protected"]
    assert _report(repo)["status"] == "recorded"
    commit = repo.commit("work")
    credit.confirm(repo.root, client=hv.FakeCI([hv.ci_run(commit)]), workflow=hv.CI_WORKFLOW, landed=_landed(repo))
    withheld, = _credits(repo)
    assert withheld.state == "confirmed" and withheld.counts is False and withheld.reason == "protected_changed"
    assert credit.confirmed_outcome_rows(_credits(repo)) == []
    approved, = _credits(repo, approved=lambda check_id, categories: True)
    assert approved.counts is True


@needs_git
def test_an_unprotected_change_has_protected_changed_false(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo)
    out = checkrun.record(repo.root, tests=True, base="main")
    assert out.row["protected_changed"] is False and out.row["protected"] == []


# ── 5. Exit 5, zero passed and failures are never evidence ───────────────────

@needs_git
@pytest.mark.parametrize("runner", [hv.NO_TESTS, hv.ZERO_PASSED, hv.FAILING])
def test_a_run_without_passing_tests_is_never_a_witness(tmp_path, runner):
    repo = hv.make_project(tmp_path, runner=runner)
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo)
    _scan(repo)
    out = checkrun.record(repo.root, tests=True)
    assert out.status == "recorded" and out.row["passed"] is False
    res = _report(repo)
    assert res["witness"] == "self" and res["status"] == "claimed"
    assert _credits(repo) == []


# ── 6. The repository never chooses the command ──────────────────────────────

@needs_git
def test_the_repository_config_cannot_name_the_test_command(tmp_path):
    marker = tmp_path / "evil-ran"
    repo = hv.make_project(tmp_path)
    repo.write("evil.py", f"import pathlib\npathlib.Path({str(marker)!r}).write_text('x')\n")
    repo.write(".aegis/config.json", '{"v": 1, "tests": {"command": "python evil.py"}}\n')
    repo.commit("repo config names a command")
    _edit_app(repo)
    out = checkrun.record(repo.root, tests=True, base="main")
    assert not marker.exists()
    assert out.row["tests"]["exit"] != 0 or out.row["passed"] is False


# ── 7. The limited-write tier ────────────────────────────────────────────────

@needs_git
def test_a_report_with_no_check_row_writes_one_claimed_row_per_session_and_tree(tmp_path):
    repo = hv.make_project(tmp_path)
    _edit_app(repo)
    _scan(repo)
    first = _report(repo, key="a", rules=("trap-sample",), outcome="success")
    again = _report(repo, key="b", rules=("trap-sample", "trap-sample"), outcome="failure")
    assert first["status"] == again["status"] == "claimed"
    assert first["witness"] == "self" and first.get("credited", []) == []
    assert len(hv.rows_of(repo.root, "claimed")) == 1
    assert hv.rows_of(repo.root, "report") == []
    agg = ledger.aggregate(repo.root, "trap-sample")
    assert (agg["triggers"], agg["tp"], agg["fp"]) == (0, 0, 0)
    assert _credits(repo) == []
    other = _report(repo, key="c", session="sess-2")  # another session is another claim
    assert other["status"] == "claimed" and len(hv.rows_of(repo.root, "claimed")) == 2
    _edit_app(repo, 3)  # and another tree is another claim
    _report(repo, key="d")
    assert len(hv.rows_of(repo.root, "claimed")) == 3


@needs_git
def test_claimed_rows_have_their_own_count_apart_from_per_rule_evidence(tmp_path):
    repo = hv.make_project(tmp_path)
    _edit_app(repo)
    _report(repo)
    summary = credit.claimed_summary(repo.root)
    assert summary["claimed"] == 1 and summary["sessions"] == 1 and summary["label"] == "claimed (unwitnessed)"
    assert ledger.aggregate(repo.root) == {}


@needs_git
@pytest.mark.parametrize("command", ["status", "sync"])
def test_status_and_sync_show_claims_apart_from_every_rule(tmp_path, monkeypatch, capsys, command):
    from aegis_cli.cli import main

    repo = hv.make_project(tmp_path)
    _edit_app(repo)
    _scan(repo)
    assert _report(repo)["status"] == "claimed"
    monkeypatch.chdir(repo.root)
    capsys.readouterr()
    main([command, "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["claimed"] == {"label": "claimed (unwitnessed)", "claimed": 1, "sessions": 1}
    rules = {r.get("name") or r.get("id"): r for r in payload["rules"]}
    assert rules["trap-sample"]["triggers"] == 0


@needs_git
def test_a_rate_limited_report_writes_nothing_and_says_so(tmp_path, monkeypatch):
    repo = hv.make_project(tmp_path)
    monkeypatch.setattr(credit, "MAX_REPORT_ROWS_PER_SESSION", 1)
    _edit_app(repo)
    assert _report(repo, key="a")["status"] == "claimed"
    _edit_app(repo, 3)
    before = hv.ledger_path(repo.root).read_bytes()
    limited = _report(repo, key="b", rules=("trap-sample",))
    assert limited["status"] == "rate_limited" and limited["limit"] == 1 and limited["credited"] == []
    assert hv.ledger_path(repo.root).read_bytes() == before


@needs_git
def test_the_report_result_carries_the_machine_readable_head(tmp_path):
    repo = hv.make_project(tmp_path)
    _edit_app(repo)
    res = _report(repo)
    assert res["source"] == "aegis_report_outcome" and res["aegis_version"]
    assert res["checked_at"].endswith("Z") and res["scope"] == {"tree": hv.tree_now(repo.root)}


def test_the_session_cap_is_a_documented_constant():
    assert credit.MAX_REPORT_ROWS_PER_SESSION == 200


@needs_git
def test_a_flood_of_reports_leaves_the_ledger_bounded(tmp_path, monkeypatch):
    repo = hv.make_project(tmp_path)
    trees = [f"{n:040x}" for n in range(1, 400)]
    state = {"n": 0}

    def fake_tree():
        state["n"] += 1
        return trees[state["n"] % len(trees)]

    monkeypatch.setattr(treeid, "bind", _fake_bind(fake_tree))
    # 50 past the cap exercises rate limiting; every call beyond it answers the same way.
    results = [_report(repo, key=f"k{n}") for n in range(credit.MAX_REPORT_ROWS_PER_SESSION + 50)]
    statuses = {r["status"] for r in results}
    assert "rate_limited" in statuses
    written = [r for r in hv.ledger_rows(repo.root) if r.get("event") in ("claimed", "report")]
    assert len(written) <= credit.MAX_REPORT_ROWS_PER_SESSION
    limited = next(r for r in results if r["status"] == "rate_limited")
    assert limited["limit"] == credit.MAX_REPORT_ROWS_PER_SESSION
    assert len(hv.ledger_rows(repo.root)) <= credit.MAX_REPORT_ROWS_PER_SESSION


@needs_git
def test_the_cap_is_per_session_so_another_session_still_reports(tmp_path, monkeypatch):
    repo = hv.make_project(tmp_path)
    monkeypatch.setattr(credit, "MAX_REPORT_ROWS_PER_SESSION", 2)
    counter = {"n": 0}

    def fake_tree():
        counter["n"] += 1
        return f"{counter['n']:040x}"

    monkeypatch.setattr(treeid, "bind", _fake_bind(fake_tree))
    assert [_report(repo, key=f"a{n}")["status"] for n in range(4)] == ["claimed", "claimed", "rate_limited", "rate_limited"]
    assert _report(repo, key="z", session="sess-2")["status"] == "claimed"


# ── 8. The credited rules are the server's, not the agent's ──────────────────

@needs_git
def test_the_credited_rules_are_exposed_in_the_session_and_match_the_change(tmp_path):
    repo = hv.make_project(tmp_path)
    repo.write(".aegis/rules/traps/trap-docs.md", SECOND_RULE)
    repo.write("docs/guide.md", "# guide\n")
    repo.commit("a second rule", allow_empty=False)
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo)
    repo.write("docs/guide.md", "# guide v2\n")
    _scan(repo, files=("src/app.py",))  # only src is scanned: trap-docs is never exposed
    checkrun.record(repo.root, tests=True, base="main")
    res = _report(repo, rules=("trap-docs",))  # the agent names a rule it never saw
    assert res["status"] == "recorded" and res["credited"] == ["trap-sample"]
    assert [c.rule for c in _credits(repo)] == ["trap-sample"]


@needs_git
def test_a_workspace_below_the_top_level_credits_the_exposed_rule_that_matches_the_change(tmp_path):
    home = hg.Home(tmp_path / "home")
    repo = hg.Repo(tmp_path / "mono", home)
    repo.write("README.md", "# mono\n")
    repo.write("pkg/src/app.py", hv.APP)
    repo.write("pkg/.aegis/rules/traps/trap-sample.md", hg.RULE)
    repo.write("pkg/.aegis/rules/traps/trap-docs.md", SECOND_RULE)
    repo.write("pkg/docs/guide.md", "# guide\n")
    repo.write("run_checks.py", hv.PASSING)  # checkrun runs the command at the snapshot's top level
    repo.write("pkg/.gitignore", ".aegis/state/\n")
    repo.commit("base")
    repo.branch("work")
    ws = repo.root / "pkg"
    hv.use_stub_runner(home.path)
    repo.write("pkg/src/app.py", "def app():\n    return 2\n")
    scanned = hv.mcp_call("aegis_scan", ws, session="sess-1", files=["src/app.py", "docs/guide.md"])
    assert scanned.get("status") != "FAIL", scanned  # both rules exposed; only src/ changes
    checkrun.record(ws, tests=True, base="main")
    res = hv.mcp_call("aegis_report_outcome", ws, session="sess-1", outcome="success",
                      rules_used=["trap-sample", "trap-docs"], idempotency_key="k1")
    assert res["status"] == "recorded" and res["credited"] == ["trap-sample"]


@needs_git
def test_an_exposed_rule_that_does_not_match_the_change_is_not_credited(tmp_path):
    repo = hv.make_project(tmp_path)
    repo.write(".aegis/rules/traps/trap-docs.md", SECOND_RULE)
    repo.write("docs/guide.md", "# guide\n")
    repo.commit("a second rule")
    hv.use_stub_runner(repo.home.path)
    repo.write("docs/guide.md", "# guide v2\n")  # the change touches only docs
    _scan(repo, files=("src/app.py", "docs/guide.md"))  # both rules were exposed
    checkrun.record(repo.root, tests=True, base="main")
    res = _report(repo, rules=("trap-sample", "trap-docs"))
    assert res["credited"] == ["trap-docs"]


@needs_git
def test_one_report_crediting_two_rules_writes_one_row_per_rule(tmp_path):
    repo = hv.make_project(tmp_path)
    repo.write(".aegis/rules/traps/trap-src.md", THIRD_RULE)
    repo.commit("a second src rule")
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo)
    _scan(repo)
    assert _report(repo, key="early")["status"] == "claimed"  # before the check: a claim
    checkrun.record(repo.root, tests=True, base="main")
    res = _report(repo, key="early")  # the same key once a check exists still credits
    assert res["status"] == "recorded" and res["credited"] == ["trap-sample", "trap-src"]
    assert sorted(r["for_rule"] for r in hv.rows_of(repo.root, "report")) == ["trap-sample", "trap-src"]
    assert sorted(c.rule for c in _credits(repo)) == ["trap-sample", "trap-src"]


@needs_git
def test_a_rule_the_session_never_scanned_earns_nothing_whatever_the_agent_says(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo)
    checkrun.record(repo.root, tests=True, base="main")  # no scan in this session
    res = _report(repo, rules=("trap-sample",))
    assert res["credited"] == [] and hv.rows_of(repo.root, "report") == []


@needs_git
def test_the_tool_takes_no_receipt_and_keys_are_namespaced_by_server_session(tmp_path):
    from aegis_mcp.registry import TOOL_ARGUMENTS

    assert not {"receipt", "check", "tree", "token"} & set(TOOL_ARGUMENTS["aegis_report_outcome"])
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo)
    _scan(repo)
    _scan(repo, session="sess-2")
    checkrun.record(repo.root, tests=True, base="main")
    first = _report(repo, key="same")
    retry = _report(repo, key="same")
    other = _report(repo, key="same", session="sess-2", outcome="failure")  # same key, another server session
    assert first["credited"] == retry["credited"] == ["trap-sample"]
    assert other["status"] == "recorded" and other["credited"] == ["trap-sample"]
    assert len(hv.rows_of(repo.root, "report")) == 1  # credit identity is (check, rule): unique
    conflict = _report(repo, key="same", outcome="failure")
    assert conflict["status"] == "FAIL" and "already used for a different report" in conflict["error"]


# ── Flaky runs are excluded without penalty ──────────────────────────────────

@needs_git
def test_a_tree_with_both_a_pass_and_a_fail_is_flaky_and_excluded(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo)
    _scan(repo)
    first = checkrun.record(repo.root, tests=True, base="main")
    assert first.row["run_ordinal"] == 1
    _report(repo)
    # the same tree, the same command, a different outcome: write the failing row the run would give
    failing = dict(first.row, passed=False, exit=1, run_ordinal=2, id="f" * 16)
    ledger.append_rows(repo.root, [failing])
    commit = repo.commit("work")
    credit.confirm(repo.root, client=hv.FakeCI([hv.ci_run(commit)]), workflow=hv.CI_WORKFLOW, landed=_landed(repo))
    derived, = _credits(repo)
    assert derived.flaky is True and derived.counts is False and derived.state != "voided"


# ── 9. Non-forgeable CI, branch alignment, reruns, and repeated trees ────────

@needs_git
def test_forged_ci_rows_in_memory_or_on_disk_never_count_without_external_verification(tmp_path):
    from aegis_core import fitness, rules, sync
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo)
    _scan(repo)
    checkrun.record(repo.root, tests=True, base="main")
    _report(repo)
    commit = repo.commit("work")
    repo.git("branch", "-f", "main", commit)
    # Append a fabricated ci row directly to the ledger without calling confirm()
    ledger.append_rows(repo.root, [{
        "v": ledger.LEDGER_VERSION, "ts": "2026-10-17T10:00:00Z", "event": "ci",
        "commit": commit, "workflow": hv.CI_WORKFLOW, "ci_conclusion": "success",
        "run_id": 99, "ci_run_attempt": 1, "verified_ci": True,
    }])
    proj = credit.project_credits(repo.root)
    assert len(proj.credits) == 1
    assert proj.credits[0].state == "landed" and proj.credits[0].reason == "unverified_ci" and proj.credits[0].counts is False
    assert proj.outcome_rows == ()
    fit = fitness.for_rules(repo.root, rules.load_rules(repo.root).served)["trap-sample"]
    assert fit.tp == 0 and fit.triggers == 0
    s_res = sync.build(repo.root)
    assert s_res["rules"]["trap-sample"]["tp"] == 0


@needs_git
def test_protected_branch_agreement_and_missing_head_branch_fail_closed(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo)
    _scan(repo)
    checkrun.record(repo.root, tests=True, base="main")
    _report(repo)
    commit = repo.commit("work")  # only on work, not on main
    assert credit.landed_lookup(repo.root)(hv.tree_now(repo.root)) is None
    for ev in ("push", "workflow_dispatch", "release"):
        assert credit.select_ci_run([hv.ci_run(commit, event=ev, head_branch=None)], commit, hv.CI_WORKFLOW, branch="main") is None
        assert credit.select_ci_run([hv.ci_run(commit, event=ev, head_branch="work")], commit, hv.CI_WORKFLOW, branch="main") is None
        assert credit.select_ci_run([hv.ci_run(commit, event=ev, head_branch="develop")], commit, hv.CI_WORKFLOW, branch="main") is None
        assert credit.select_ci_run([hv.ci_run(commit, event=ev, head_branch="release/v1")], commit, hv.CI_WORKFLOW, branch="main") is None
        assert credit.select_ci_run([hv.ci_run(commit, event=ev, head_branch="main")], commit, hv.CI_WORKFLOW, branch="main") is not None


@needs_git
def test_rerun_transitions_failure_to_success_and_success_to_failure_and_unavailable(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo)
    _scan(repo)
    checkrun.record(repo.root, tests=True, base="main")
    _report(repo)
    commit = repo.commit("work")
    repo.git("branch", "-f", "main", commit)
    # 1. Initial failure -> voided (reason=ci_failed), but no terminal void row written
    r1 = hv.ci_run(commit, "failure", attempt=1, run_id=10, run_started_at="2026-10-17T10:01:00Z")
    credit.confirm(repo.root, client=hv.FakeCI([r1]), workflow=hv.CI_WORKFLOW)
    assert hv.rows_of(repo.root, "void") == []
    c1, = credit.project_credits(repo.root).credits
    assert c1.state == "voided" and c1.reason == "ci_failed" and c1.counts is False
    # 2. Rerun succeeds (failure -> success) -> confirmed, counts=True
    r2 = hv.ci_run(commit, "success", attempt=2, run_id=10, run_started_at="2026-10-17T10:05:00Z")
    credit.confirm(repo.root, client=hv.FakeCI([r1, r2]), workflow=hv.CI_WORKFLOW)
    c2, = credit.project_credits(repo.root).credits
    assert c2.state == "confirmed" and c2.counts is True
    # 3. Later rerun fails (success -> failure) -> voided, counts=False
    r3 = hv.ci_run(commit, "failure", attempt=3, run_id=10, run_started_at="2026-10-17T10:10:00Z")
    credit.confirm(repo.root, client=hv.FakeCI([r1, r2, r3]), workflow=hv.CI_WORKFLOW)
    c3, = credit.project_credits(repo.root).credits
    assert c3.state == "voided" and c3.reason == "ci_failed" and c3.counts is False
    # 4. Restore success then CI becomes unavailable (success -> unavailable) -> landed, reason=ci_unavailable, counts=False
    r4 = hv.ci_run(commit, "success", attempt=4, run_id=10, run_started_at="2026-10-17T10:15:00Z")
    credit.confirm(repo.root, client=hv.FakeCI([r4]), workflow=hv.CI_WORKFLOW)
    assert credit.project_credits(repo.root).credits[0].counts is True
    credit.confirm(repo.root, client=hv.FakeCI(error="gh api failed"), workflow=hv.CI_WORKFLOW)
    c4, = credit.project_credits(repo.root).credits
    assert c4.state == "landed" and c4.reason == "ci_unavailable" and c4.counts is False


@needs_git
def test_repeated_tree_after_revert_does_not_inherit_older_commit_ci(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    repo.git("checkout", "main")
    _edit_app(repo, 2)
    c1 = repo.commit("c1: app=2")  # c1 has tree T2
    _edit_app(repo, 3)
    c2 = repo.commit("c2: app=3")  # main is now at c2
    repo.branch("feature-revert")
    _edit_app(repo, 2)  # back to tree T2, while HEAD is c2
    _scan(repo)
    out = checkrun.record(repo.root, tests=True, base="main")
    assert out.row["head"] == c2
    _report(repo)
    # Even though c1 on main had tree T2 and passing CI, c1 is older than check["head"] (c2)
    credit.confirm(repo.root, client=hv.FakeCI([hv.ci_run(c1, "success")]), workflow=hv.CI_WORKFLOW)
    c_before, = credit.project_credits(repo.root).credits
    assert c_before.state == "witnessed" and c_before.commit is None and c_before.counts is False
    # Once the new commit c3 actually lands on main and gets CI, it confirms
    c3 = repo.commit("c3: revert to app=2")
    repo.git("branch", "-f", "main", c3)
    credit.confirm(repo.root, client=hv.FakeCI([hv.ci_run(c3, "success")]), workflow=hv.CI_WORKFLOW)
    c_after, = credit.project_credits(repo.root).credits
    assert c_after.state == "confirmed" and c_after.commit == c3 and c_after.counts is True



# ── 10. GitHub, not the ledger or a local ref, pins the workflow and the branch ──

class GitHub:
    """``gh api`` at the runner boundary: the repository GET answers ``repo`` (a body, or a
    ``(returncode, stdout)`` pair, or None for a missing gh); the runs GET lists ``runs``."""

    def __init__(self, runs, repo=None):
        self.runs = list(runs)
        self.repo = {"full_name": "octo/proj", "default_branch": "main"} if repo is None else repo
        self.calls = []

    def __call__(self, argv, stdin=None, cwd=None, timeout=None):
        self.calls.append(list(argv))
        if argv[:1] != ["api"]:
            return subprocess.CompletedProcess(argv, 1, "", "unexpected")
        if "/actions/runs?head_sha=" in argv[1]:
            sha = argv[1].split("head_sha=", 1)[1].split("&", 1)[0]
            body = {"workflow_runs": [r for r in self.runs if r.get("head_sha") == sha]}
            return subprocess.CompletedProcess(argv, 0, json.dumps(body), "")
        if self.repo == "missing":
            return None
        code, out = self.repo if isinstance(self.repo, tuple) else (0, json.dumps(self.repo))
        return subprocess.CompletedProcess(argv, code, out, "")

    @property
    def repo_gets(self):
        return [c for c in self.calls if c[:1] == ["api"] and "/actions/" not in c[1]]


def _ci_row(commit, workflow=hv.CI_WORKFLOW, run_id=9):
    return {"v": ledger.LEDGER_VERSION, "ts": "2026-10-19T10:00:00Z", "event": "ci", "commit": commit,
            "workflow": workflow, "ci_conclusion": "success", "run_id": run_id, "ci_run_attempt": 1}


def _reported_commit(tmp_path, monkeypatch):
    """A reported, passing check for trap-sample committed on ``work``; nothing points at it yet."""
    monkeypatch.setattr(credit, "_VERIFIED_CI", {})
    monkeypatch.setattr(credit, "_UNAVAILABLE_CI", set())
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    _edit_app(repo)
    _scan(repo)
    checkrun.record(repo.root, tests=True, base="main")
    assert _report(repo)["status"] == "recorded"
    return repo, repo.commit("work")


def _point_origin_head_at(repo, branch, commit):
    repo.git("update-ref", f"refs/remotes/origin/{branch}", commit)
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", f"refs/remotes/origin/{branch}")


@needs_git
def test_a_ledger_row_cannot_name_the_workflow_that_confirms_credit(tmp_path, monkeypatch):
    """Given commit C whose validate.yml run failed (id 9) and whose other.yml run succeeded (id 5),
    and an agent-written ci row naming other.yml run 5, When credit is projected over REST, Then it
    is not confirmed; GitHub's repository is asked once per process for the default branch."""
    repo, commit = _reported_commit(tmp_path, monkeypatch)
    repo.git("branch", "-f", "main", commit)
    gh = GitHub([hv.ci_run(commit, "failure", run_id=9), hv.ci_run(commit, workflow="other.yml", run_id=5)])
    monkeypatch.setattr(human_gate, "default_gh_runner", gh)
    ledger.append_rows(repo.root, [_ci_row(commit, workflow="other.yml", run_id=5)])
    proj = credit.project_credits(repo.root, verify_ci=True)
    assert [(c.state, c.counts) for c in proj.credits] == [("landed", False)]
    assert proj.outcome_rows == () and len(gh.repo_gets) == 1
    again = credit.project_credits(repo.root, verify_ci=True)
    assert [c.counts for c in again.credits] == [False] and len(gh.repo_gets) == 1  # memoised per root


@needs_git
def test_an_honest_ci_row_still_confirms_through_github(tmp_path, monkeypatch):
    repo, commit = _reported_commit(tmp_path, monkeypatch)
    repo.git("branch", "-f", "main", commit)
    gh = GitHub([hv.ci_run(commit, run_id=9)])
    monkeypatch.setattr(human_gate, "default_gh_runner", gh)
    ledger.append_rows(repo.root, [_ci_row(commit)])
    proj = credit.project_credits(repo.root, verify_ci=True)
    assert [(c.state, c.counts) for c in proj.credits] == [("confirmed", True)]
    assert len(gh.repo_gets) == 1


@needs_git
@pytest.mark.parametrize("github_default,counts", [("main", False), ("feature", True)])
def test_the_default_branch_is_githubs_not_the_local_origin_head(tmp_path, monkeypatch, github_default, counts):
    """Given origin/HEAD repointed at origin/feature, whose run succeeded, When credit is projected,
    Then only GitHub's default branch decides whether the run speaks for the commit."""
    repo, commit = _reported_commit(tmp_path, monkeypatch)
    _point_origin_head_at(repo, "feature", commit)
    gh = GitHub([hv.ci_run(commit, run_id=9, head_branch="feature")],
                repo={"full_name": "octo/proj", "default_branch": github_default})
    monkeypatch.setattr(human_gate, "default_gh_runner", gh)
    ledger.append_rows(repo.root, [_ci_row(commit)])
    proj = credit.project_credits(repo.root, verify_ci=True)
    assert [c.counts for c in proj.credits] == [counts]


_BAD_REPO_REPLIES = ["missing", (1, ""), (0, "not json"), {}, {"default_branch": ""}, {"default_branch": 7}]
_BAD_IDS = ["no-gh", "exit-1", "not-json", "empty", "blank", "int"]


@needs_git
@pytest.mark.parametrize("reply", _BAD_REPO_REPLIES, ids=_BAD_IDS)
def test_an_unreadable_default_branch_leaves_credit_landed_with_no_local_fallback(tmp_path, monkeypatch, reply):
    """Given a local origin/HEAD naming a branch whose run succeeded, When GitHub's repository GET fails
    or is malformed, Then nothing raises, nothing counts, and the projection says it is incomplete."""
    repo, commit = _reported_commit(tmp_path, monkeypatch)
    _point_origin_head_at(repo, "feature", commit)
    gh = GitHub([hv.ci_run(commit, run_id=9, head_branch="feature")], repo=reply)
    monkeypatch.setattr(human_gate, "default_gh_runner", gh)
    ledger.append_rows(repo.root, [_ci_row(commit)])
    proj = credit.project_credits(repo.root, verify_ci=True)
    assert [(c.state, c.reason, c.counts) for c in proj.credits] == [("landed", "unverified_ci", False)]
    assert proj.available is False and "default branch" in proj.error
    assert [c for c in gh.calls if "/actions/" in c[1]] == []  # no run was read for an unknown branch


@needs_git
@pytest.mark.parametrize("reply", _BAD_REPO_REPLIES, ids=_BAD_IDS)
def test_confirm_records_an_unreadable_default_branch_as_ci_unavailable(tmp_path, monkeypatch, reply):
    repo, commit = _reported_commit(tmp_path, monkeypatch)
    _point_origin_head_at(repo, "feature", commit)
    gh = GitHub([hv.ci_run(commit, run_id=9, head_branch="feature")], repo=reply)
    monkeypatch.setattr(human_gate, "default_gh_runner", gh)
    summary = credit.confirm(repo.root, client=credit.GhRestClient(cwd=str(repo.root)), workflow=hv.CI_WORKFLOW)
    assert (summary["asked"], summary["confirmed"], len(summary["errors"])) == (0, 0, 1)
    assert hv.rows_of(repo.root, "ci") == []
    derived, = credit.project_credits(repo.root).credits
    assert (derived.state, derived.reason, derived.counts) == ("landed", "ci_unavailable", False)


@needs_git
def test_confirm_asks_github_for_the_branch_and_the_run_once(tmp_path, monkeypatch):
    repo, commit = _reported_commit(tmp_path, monkeypatch)
    _point_origin_head_at(repo, "feature", commit)  # the local ref says feature; GitHub says main
    gh = GitHub([hv.ci_run(commit, run_id=9, head_branch="feature")])
    monkeypatch.setattr(human_gate, "default_gh_runner", gh)
    summary = credit.confirm(repo.root, client=credit.GhRestClient(cwd=str(repo.root)), workflow=hv.CI_WORKFLOW)
    assert (summary["asked"], summary["confirmed"]) == (1, 0)
    row, = hv.rows_of(repo.root, "ci")
    assert (row["ci_conclusion"], row["run_id"]) == ("none", None)
    assert len(gh.repo_gets) == 1


@needs_git
def test_a_runs_get_that_fails_after_github_named_the_branch_still_trips_the_breaker(tmp_path, monkeypatch):
    """Given GitHub names the default branch but its runs GET then fails, When credit is projected,
    Then verification stops at that commit, nothing counts, and the projection is unavailable."""
    repo, commit = _reported_commit(tmp_path, monkeypatch)
    repo.git("branch", "-f", "main", commit)
    gh = GitHub([hv.ci_run(commit, run_id=9)])

    def runs_fail(argv, stdin=None, cwd=None, timeout=None):
        if argv[:1] == ["api"] and "/actions/runs?" in argv[1]:
            gh.calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 1, "", "rate limited")
        return gh(argv, stdin, cwd, timeout)

    monkeypatch.setattr(human_gate, "default_gh_runner", runs_fail)
    ledger.append_rows(repo.root, [_ci_row(commit)])
    proj = credit.project_credits(repo.root, verify_ci=True)
    assert [(c.state, c.reason, c.counts) for c in proj.credits] == [("landed", "unverified_ci", False)]
    assert proj.available is False
    assert proj.error == f"CI verification stopped after gh failed for {commit[:12]}; 1 commit(s) were not verified"
    asked = [c[1].split("?", 1)[0] for c in gh.calls if c[:1] == ["api"]]
    assert asked == ["repos/{owner}/{repo}", "repos/{owner}/{repo}/actions/runs"]
