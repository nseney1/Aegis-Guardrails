"""R-trust-52 / ratchet R6 (reads): no read-only surface runs ``gh``; sync and the decision callers do.

Two probes see every surface: ``CountingGh`` on ``human_gate.default_gh_runner``, and (POSIX) a
marker-writing fake ``gh`` first on ``PATH`` under the pytest temp root with the real runner
restored, so an actual exec is logged. The conftest lets ``pathlookup.which`` find only that ``gh``.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Callable, Dict, List, Optional

import pytest

from aegis_core import checkrun, credit, human_gate
from aegis_core.telemetry_engine import ledger
from tests import helpers_humangate as hg
from tests import helpers_verified as hv

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")

FORGED = [f"{0xbeef + i:040x}" for i in range(6)]
AMBIENT_TP = 24  # one short of fitness.MIN_N: only the CI-confirmed credit makes it promotable
# 8 tp + 17 fp are MIN_N verdicts misfiring alone (Wilson lower bound of the fp rate 0.516 > 0.5);
# 0.493 with the confirmed tp
AMBIENT_FP_TP, AMBIENT_FP = 8, 17
RULE = ("---\nid: trap-sample\ntype: trap\nenforcement: advisory\nhypothesis: sample\ncreated: '2026-01-01'\n"
        "target_paths:\n  - src/*.py\n---\n# Sample\n\nBody long enough to be a rule body.\n")


def _is_runs_get(argv: List[str]) -> bool:
    return argv[:1] == ["api"] and "head_sha=" in argv[1]


class CountingGh:
    """``gh`` at the runner boundary: the repository GET names ``main`` (R-trust-62) unless
    ``fail_repo``; the runs GET lists ``runs`` unless ``fail_runs``; ``fail`` refuses everything."""

    def __init__(self, runs: Optional[List[Dict[str, Any]]] = None, fail: bool = False, *,
                 fail_repo: bool = False, fail_runs: bool = False) -> None:
        self.runs, self.fail = list(runs or []), fail
        self.fail_repo, self.fail_runs = fail_repo, fail_runs
        self.calls: List[List[str]] = []

    def __call__(self, argv, stdin=None, cwd=None, timeout=None):
        self.calls.append(list(argv))
        if self.fail or argv[:1] != ["api"]:
            return subprocess.CompletedProcess(argv, 1, "", "offline")
        if not _is_runs_get(argv):
            if self.fail_repo:
                return subprocess.CompletedProcess(argv, 1, "", "offline")
            return subprocess.CompletedProcess(argv, 0, json.dumps({"default_branch": "main"}), "")
        if self.fail_runs:
            return subprocess.CompletedProcess(argv, 1, "", "rate limited")
        sha = argv[1].split("head_sha=", 1)[1].split("&", 1)[0]
        body = {"workflow_runs": [r for r in self.runs if r.get("head_sha") == sha]}
        return subprocess.CompletedProcess(argv, 0, json.dumps(body), "")


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "GIT_CONFIG_GLOBAL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setattr(credit, "_VERIFIED_CI", {})
    monkeypatch.setattr(credit, "_UNAVAILABLE_CI", set())


def _fresh_process() -> None:
    credit._VERIFIED_CI.clear()
    credit._UNAVAILABLE_CI.clear()


def _landed(tmp_path: Path, monkeypatch):
    """``trap-sample`` with one reported check landed on ``main`` and no ``ci`` row yet."""
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    repo.write(".aegis/rules/traps/trap-sample.md", RULE)
    repo.git("checkout", "-q", "main")
    repo.commit("rule age")
    repo.git("checkout", "-q", "work")
    repo.git("merge", "-q", "main")
    repo.write("src/app.py", "def app():\n    return 2\n")
    hv.mcp_call("aegis_scan", repo.root, session="s1", files=["src/app.py"])
    assert checkrun.record(repo.root, tests=True, base="main").status == "recorded"
    hv.mcp_call("aegis_report_outcome", repo.root, session="s1", outcome="success",
                rules_used=["trap-sample"], idempotency_key="k1")
    commit = repo.commit("work")
    repo.git("branch", "-f", "main", commit)
    monkeypatch.chdir(repo.root)
    _fresh_process()
    return repo, commit


def _project(tmp_path: Path, monkeypatch):
    """``trap-sample`` with 24 ledger tp rows and one reported check landed on ``main``, plus a
    ``ci`` row for that commit and 6 forged full-SHA ``ci`` rows."""
    repo, commit = _landed(tmp_path, monkeypatch)
    ledger.append(repo.root, [{"rule": "trap-sample", "outcome": "tp", "source": "ci", "key": f"tp{i}"}
                              for i in range(AMBIENT_TP)])
    ledger.append_rows(repo.root, [
        {"v": ledger.LEDGER_VERSION, "ts": "2026-10-17T10:00:00Z", "event": "ci", "commit": sha,
         "workflow": hv.CI_WORKFLOW, "ci_conclusion": "success", "run_id": 10, "ci_run_attempt": 1}
        for sha in [commit] + FORGED
    ])
    return repo, commit


def _misfiring(tmp_path: Path, monkeypatch):
    """``trap-sample`` with 8 tp and 17 fp ledger rows and one reported check landed on ``main``, no ``ci``
    row: archived on the ledger alone, kept once CI confirms the landed check."""
    repo, commit = _landed(tmp_path, monkeypatch)
    ledger.append(repo.root, [{"rule": "trap-sample", "outcome": "fp", "source": "ci", "key": f"fp{i}"}
                              for i in range(AMBIENT_FP)]
                  + [{"rule": "trap-sample", "outcome": "tp", "source": "ci", "key": f"tp{i}"}
                     for i in range(AMBIENT_FP_TP)])
    return repo, commit


def _rule_row(capsys, rule_id: str = "trap-sample") -> Dict[str, Any]:
    return next(r for r in json.loads(capsys.readouterr().out)["rules"] if r["id"] == rule_id)


def _surfaces(root: Path, capsys) -> Dict[str, Callable[[], Any]]:
    from aegis_cli.cli import main
    from aegis_cli.hooks import pretool
    from aegis_cli.status import run_status
    from aegis_core import scan
    from aegis_sdk.governance import Governance

    edit = {"session_id": "s", "transcript_path": "t", "cwd": str(root), "permission_mode": "default",
            "hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_use_id": "toolu_1",
            "tool_input": {"file_path": str(root / "src" / "app.py"), "old_string": "2", "new_string": "3"}}
    return {
        "scan": lambda: scan.scan(root, changed_files=["src/app.py"]),
        "aegis_list_rules": lambda: hv.mcp_call("aegis_list_rules", root),
        "status": lambda: run_status(argparse.Namespace(_root=root, plain=True)),
        "rule list": lambda: main(["rule", "list"]),
        "check": lambda: main(["check"]),
        "hook run pre-tool": lambda: pretool.run_pre_tool("claude-code", json.dumps(edit).encode("utf-8"), {}),
        "sdk list_rules": lambda: Governance(root).list_rules(),
        "sdk fitness_landscape": lambda: Governance(root).fitness_landscape(),
    }


@needs_git
def test_read_surfaces_make_no_gh_call_through_the_runner(tmp_path, monkeypatch, capsys):
    repo, commit = _project(tmp_path, monkeypatch)
    gh = CountingGh([hv.ci_run(commit, run_id=10)])
    monkeypatch.setattr(human_gate, "default_gh_runner", gh)
    called = {}
    for name, run in _surfaces(repo.root, capsys).items():
        _fresh_process()
        before = len(gh.calls)
        run()
        capsys.readouterr()
        called[name] = len(gh.calls) - before
    assert called == {name: 0 for name in called}


@needs_git
@pytest.mark.skipif(os.name == "nt", reason="the fake gh is a shebang script")
def test_read_surfaces_exec_no_gh_found_on_path(tmp_path, monkeypatch, capsys):
    repo, _commit = _project(tmp_path, monkeypatch)
    marker = tmp_path / "gh-calls.log"
    bindir = tmp_path / "fakebin"
    bindir.mkdir()
    fake = bindir / "gh"
    fake.write_bytes(f'#!/bin/sh\necho "$@" >> "{marker}"\nexit 1\n'.encode("utf-8"))
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setattr(human_gate, "default_gh_runner", human_gate._real_default_gh_runner)
    for name, run in _surfaces(repo.root, capsys).items():
        _fresh_process()
        run()
        capsys.readouterr()
        assert not marker.exists(), f"{name} ran gh: {marker.read_text(encoding='utf-8')}"


@needs_git
def test_sync_and_promotion_decisions_verify_ci_through_gh(tmp_path, monkeypatch, capsys):
    from aegis_cli.cli import main
    from aegis_core.lifecycle.promotion import promote_rule

    repo, commit = _project(tmp_path, monkeypatch)
    gh = CountingGh([hv.ci_run(commit, run_id=10)])
    monkeypatch.setattr(human_gate, "default_gh_runner", gh)

    assert main(["sync", "--json"]) == 0
    assert _rule_row(capsys)["tp"] == AMBIENT_TP + 1
    assert gh.calls

    _fresh_process()
    gh.calls.clear()
    assert main(["rule", "promote", "--json"]) == 0
    assert [c["rule_id"] for c in json.loads(capsys.readouterr().out)["candidates"]] == ["trap-sample"]
    assert gh.calls

    _fresh_process()
    gh.calls.clear()
    res = promote_rule(repo.root, "trap-sample", force=False)
    assert (res["status"], res["to_type"]) == ("promoted", "invariant")
    assert gh.calls


@needs_git
@pytest.mark.parametrize("gh", [None, CountingGh(fail=True)], ids=["missing", "failing"])
def test_without_gh_sync_reports_ci_unavailable_and_promotion_is_ineligible(tmp_path, monkeypatch, capsys, gh):
    from aegis_cli.cli import main
    from aegis_core.lifecycle.promotion import promote_rule

    repo, _commit = _project(tmp_path, monkeypatch)
    if gh is not None:
        gh.calls.clear()
        monkeypatch.setattr(human_gate, "default_gh_runner", gh)

    assert main(["sync", "--apply", "--json"]) == 0
    row = _rule_row(capsys)
    assert (row["tp"], row["type"]) == (AMBIENT_TP, "trap")
    assert [(c.state, c.reason) for c in credit.project_credits(repo.root).credits] == [("landed", "ci_unavailable")]

    _fresh_process()
    res = promote_rule(repo.root, "trap-sample", force=False)
    assert res["status"] == "ineligible" and "does not meet the promotion threshold" in res["message"]
    assert (repo.root / ".aegis" / "rules" / "traps" / "trap-sample.md").is_file()


class FlakyGh(CountingGh):
    """``gh`` that names the default branch, fails its first runs GET, and answers every later call."""

    def __call__(self, argv, stdin=None, cwd=None, timeout=None):
        if _is_runs_get(argv) and not any(_is_runs_get(c) for c in self.calls):
            self.calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 1, "", "transient")
        return super().__call__(argv, stdin, cwd, timeout)


def _api_calls(gh: CountingGh) -> int:
    return sum(1 for c in gh.calls if c[:1] == ["api"])


def _runs_gets(gh: CountingGh) -> int:
    return sum(1 for c in gh.calls if _is_runs_get(c))


@needs_git
def test_a_transient_gh_failure_stops_ci_verification_and_decisions_fail_closed(tmp_path, monkeypatch):
    """Given seven pending well-formed commits and a gh whose first runs GET fails, When credit is
    projected for a decision, Then the breaker stops there: one runs GET, and the projection is unavailable."""
    from aegis_core import fitness
    from aegis_core.lifecycle.promotion import promote_rule
    from aegis_core.rules import load_rules

    repo, commit = _project(tmp_path, monkeypatch)
    gh = FlakyGh([hv.ci_run(commit, run_id=10)])
    monkeypatch.setattr(human_gate, "default_gh_runner", gh)

    proj = credit.project_credits(repo.root, verify_ci=True)
    assert (_api_calls(gh), _runs_gets(gh)) == (2, 1)  # the repository GET, then the one runs GET that failed
    assert proj.available is False
    assert proj.error == f"CI verification stopped after gh failed for {commit[:12]}; 7 commit(s) were not verified"

    _fresh_process()
    gh.calls.clear()  # the next runs GET fails again
    rule = load_rules(repo.root).get("trap-sample")
    fit = fitness.for_rules(repo.root, [rule], verify_ci=True)["trap-sample"]
    assert (fit.state, fit.suggestion, fit.evidence_available) == ("evidence_unavailable", None, False)

    _fresh_process()
    gh.calls.clear()
    res = promote_rule(repo.root, "trap-sample", force=False)
    assert res["status"] == "ineligible"
    assert (repo.root / ".aegis" / "rules" / "traps" / "trap-sample.md").is_file()


@needs_git
def test_a_failing_repository_get_stops_ci_verification_before_any_run_is_read(tmp_path, monkeypatch):
    repo, commit = _project(tmp_path, monkeypatch)
    gh = CountingGh([hv.ci_run(commit, run_id=10)], fail_repo=True)
    monkeypatch.setattr(human_gate, "default_gh_runner", gh)

    proj = credit.project_credits(repo.root, verify_ci=True)
    assert (_api_calls(gh), _runs_gets(gh)) == (1, 0)
    assert proj.available is False
    assert proj.error == ("CI verification stopped: GitHub did not name the default branch "
                          "(gh api failed (exit 1)); 7 commit(s) were not verified")


@needs_git
@pytest.mark.parametrize("fails", ["fail_repo", "fail_runs"], ids=["repository-get", "runs-get"])
def test_sync_decides_nothing_when_gh_fails_inside_confirm(tmp_path, monkeypatch, fails):
    """Given a misfiring trap whose landed check CI would confirm, When ``sync --apply`` runs and gh
    fails inside confirm (the repository GET or the runs GET), Then the evidence is reported
    unavailable, there is no suggestion, nothing is applied, and an offline read stays available."""
    from aegis_core import sync

    repo, commit = _misfiring(tmp_path, monkeypatch)
    gh = CountingGh([hv.ci_run(commit, run_id=10)], **{fails: True})
    monkeypatch.setattr(human_gate, "default_gh_runner", gh)

    res = sync.sync(repo.root, apply=True)
    assert (res.applied, res.refused) == ([], None)
    assert (repo.root / ".aegis" / "rules" / "traps" / "trap-sample.md").is_file()
    row = res.derived["rules"]["trap-sample"]
    assert (row["evidence_available"], row["state"], row["suggestion"]) == (False, "evidence_unavailable", None)
    assert row["evidence_error"] == (f"CI verification stopped: gh failed while confirming CI for {commit[:12]}; "
                                     "1 landed commit(s) were not verified")

    asked = len(gh.calls)
    proj = credit.project_credits(repo.root)
    assert (proj.available, proj.error) == (True, None)
    assert [(c.state, c.reason) for c in proj.credits] == [("landed", "ci_unavailable")]
    assert len(gh.calls) == asked


@needs_git
@pytest.mark.parametrize("conclusion,archived", [("success", False), ("failure", True)])
def test_sync_with_a_healthy_gh_confirms_and_decides(tmp_path, monkeypatch, conclusion, archived):
    """Control: gh answers, so sync confirms the landed check and decides on complete evidence: a
    green run keeps the trap, a red run voids the credit and the misfiring trap is archived."""
    from aegis_core import sync

    repo, commit = _misfiring(tmp_path, monkeypatch)
    monkeypatch.setattr(human_gate, "default_gh_runner", CountingGh([hv.ci_run(commit, conclusion, run_id=10)]))

    res = sync.sync(repo.root, apply=True)
    assert [(a["rule"], a["action"], a["status"]) for a in res.applied] == (
        [("trap-sample", "archive", "archived")] if archived else [])
    assert (repo.root / ".aegis" / "rules" / "traps" / "trap-sample.md").is_file() is not archived
    if not archived:
        row = res.derived["rules"]["trap-sample"]
        assert (row["evidence_available"], row["tp"], row["fp"], row["suggestion"]) == (True, AMBIENT_FP_TP + 1, AMBIENT_FP, None)


@needs_git
def test_a_healthy_gh_verifies_every_commit_and_reads_stay_offline(tmp_path, monkeypatch):
    repo, commit = _project(tmp_path, monkeypatch)
    gh = CountingGh([hv.ci_run(commit, run_id=10)])
    monkeypatch.setattr(human_gate, "default_gh_runner", gh)

    proj = credit.project_credits(repo.root, verify_ci=True)
    assert (proj.available, proj.error) == (True, None)
    assert [c.state for c in proj.credits] == ["confirmed"]
    assert _api_calls(gh) == 2 + len(FORGED)  # the repository GET, then one runs GET per commit

    _fresh_process()
    gh.calls.clear()
    proj = credit.project_credits(repo.root)
    assert (proj.available, proj.error) == (True, None)
    assert gh.calls == []


def _ci_confirmable(repo, commit: str) -> None:
    ledger.append_rows(repo.root, [
        {"v": ledger.LEDGER_VERSION, "ts": "2026-10-17T10:00:00Z", "event": "ci", "commit": commit,
         "workflow": hv.CI_WORKFLOW, "ci_conclusion": "success", "run_id": 10, "ci_run_attempt": 1}])


@needs_git
@pytest.mark.parametrize("fails", ["fail_repo", "fail_runs"], ids=["repository-get", "runs-get"])
def test_direct_decisions_refuse_when_ci_verification_stops(tmp_path, monkeypatch, fails):
    """Given a misfiring trap whose landed check has a ``ci`` row CI would confirm, When gh fails while
    ``aegis rule archive`` or ``aegis rule tiers`` verifies CI, Then nothing is archived or rewritten and
    each says the evidence is unavailable: an unavailable projection never drives a decision."""
    from aegis_core.lifecycle.promotion import evaluate_rule_tiers
    from aegis_core.lifecycle.selection import archive_rule

    repo, commit = _misfiring(tmp_path, monkeypatch)
    _ci_confirmable(repo, commit)
    monkeypatch.setattr(human_gate, "default_gh_runner", CountingGh([hv.ci_run(commit, run_id=10)], **{fails: True}))
    path = repo.root / ".aegis" / "rules" / "traps" / "trap-sample.md"
    before = path.read_bytes()

    res = archive_rule(repo.root, "trap-sample")
    assert res["status"] == "ineligible" and "its evidence is unavailable (CI verification stopped" in res["message"]
    _fresh_process()
    assert evaluate_rule_tiers(repo.root, execute=True)["refused"].startswith(
        "not written: the evidence is unavailable (CI verification stopped")
    assert path.read_bytes() == before


@needs_git
def test_direct_archive_still_acts_on_complete_evidence(tmp_path, monkeypatch):
    """Control: when gh answers and CI failed on the landed commit, the credit is void, the evidence is
    complete, and the misfiring trap is archived."""
    from aegis_core.lifecycle.selection import archive_rule

    repo, commit = _misfiring(tmp_path, monkeypatch)
    _ci_confirmable(repo, commit)
    monkeypatch.setattr(human_gate, "default_gh_runner", CountingGh([hv.ci_run(commit, "failure", run_id=10)]))

    assert archive_rule(repo.root, "trap-sample")["status"] == "archived"
    assert not (repo.root / ".aegis" / "rules" / "traps" / "trap-sample.md").exists()


@needs_git
@pytest.mark.parametrize("argv", [["sync"], ["rule", "archive", "--dry-run"], ["rule", "demote"]],
                         ids=["sync", "rule-archive", "rule-demote"])
def test_text_output_says_why_the_evidence_is_unavailable(tmp_path, monkeypatch, capsys, argv):
    """Given a landed check with a ``ci`` row to verify and a gh that always fails, When ``sync``,
    ``rule archive`` or ``rule demote`` prints text, Then it names the reason once, not only that the
    evidence is unavailable (the reason used to reach only --json and derived.json)."""
    from aegis_cli.cli import main

    repo, commit = _misfiring(tmp_path, monkeypatch)
    _ci_confirmable(repo, commit)
    monkeypatch.setattr(human_gate, "default_gh_runner", CountingGh(fail=True))

    main(argv)
    out = capsys.readouterr().out
    assert out.count("CI verification stopped") == 1, out
    assert "commit(s) were not verified" in out


@needs_git
@pytest.mark.parametrize("argv", [["sync"], ["rule", "archive", "--dry-run"], ["rule", "demote"]],
                         ids=["sync", "rule-archive", "rule-demote"])
def test_text_output_names_no_reason_when_the_evidence_is_complete(tmp_path, monkeypatch, capsys, argv):
    from aegis_cli.cli import main

    repo, commit = _misfiring(tmp_path, monkeypatch)
    _ci_confirmable(repo, commit)
    monkeypatch.setattr(human_gate, "default_gh_runner", CountingGh([hv.ci_run(commit, run_id=10)]))

    main(argv)
    out = capsys.readouterr().out
    assert "CI verification stopped" not in out and "evidence unavailable" not in out.lower()
