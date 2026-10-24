"""R-trust-52 (ARCH-5): the read path never asks GitHub; decision callers verify, once per projection.

``credit.project_credits``, ``fitness.for_rules`` and ``sync.build`` take ``verify_ci`` (default
False). Offline, a ledger ``ci`` row counts only when this process verified it earlier, so a scan
can under-credit but never over-credit. With ``verify_ci=True`` a dead ``gh`` costs one attempt per
projection (circuit breaker), and a cached verdict is re-checked unless it is terminal and names
the run the newest ``ci`` row names (B14b).

``CountingGh`` replaces ``ghcli.default_gh_runner`` (no shell stub, so Windows and 3.9 safe).
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any, Dict, List, Optional

import pytest

from aegis_core import checkrun, credit, fitness, ghcli, rules, scan
from aegis_core.telemetry_engine import ledger
from tests import helpers_humangate as hg
from tests import helpers_verified as hv

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")

FORGED = [f"{0xf0f0 + i:040x}" for i in range(6)]
RULE_B = ("---\nid: trap-b\ntype: trap\nenforcement: advisory\nhypothesis: b\n"
          "target_paths:\n  - src/*.py\n---\n# B\n\nBody long enough to be a rule body.\n")


class CountingGh:
    """``gh`` at the runner boundary: answers ``gh api .../runs?head_sha=`` from ``runs`` (or fails it
    with ``fail_runs``) and the repository GET with default branch ``main`` (R-trust-62), refuses
    the rest; ``fail`` refuses every call."""

    def __init__(self, runs: Optional[List[Dict[str, Any]]] = None, fail: bool = False, *,
                 fail_runs: bool = False) -> None:
        self.runs, self.fail, self.fail_runs = list(runs or []), fail, fail_runs
        self.calls: List[List[str]] = []

    def __call__(self, argv, stdin=None, cwd=None, timeout=None):
        self.calls.append(list(argv))
        if self.fail or argv[:1] != ["api"]:
            return subprocess.CompletedProcess(argv, 1, "", "offline")
        if "head_sha=" not in argv[1]:
            return subprocess.CompletedProcess(argv, 0, json.dumps({"default_branch": "main"}), "")
        if self.fail_runs:
            return subprocess.CompletedProcess(argv, 1, "", "rate limited")
        sha = argv[1].split("head_sha=", 1)[1].split("&", 1)[0]
        body = {"workflow_runs": [r for r in self.runs if r.get("head_sha") == sha]}
        return subprocess.CompletedProcess(argv, 0, json.dumps(body), "")

    @property
    def api(self) -> List[List[str]]:
        return [c for c in self.calls if c[:1] == ["api"]]

    @property
    def runs_api(self) -> List[List[str]]:
        return [c for c in self.api if "head_sha=" in c[1]]


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


def _gh(monkeypatch, gh: CountingGh) -> CountingGh:
    monkeypatch.setattr(ghcli, "default_gh_runner", gh)
    return gh


def _ci_row(commit: str, conclusion: str = "success", run_id: int = 10, attempt: int = 1) -> Dict[str, Any]:
    """A ``ci`` row as ``credit.confirm`` writes it (here: as a sync in another process left it)."""
    return {"v": ledger.LEDGER_VERSION, "ts": "2026-10-17T10:00:00Z", "event": "ci", "commit": commit,
            "workflow": hv.CI_WORKFLOW, "ci_conclusion": conclusion, "run_id": run_id, "ci_run_attempt": attempt}


def _landed(tmp_path: Path, extra_rules: Optional[Dict[str, str]] = None):
    """A reported, passing check for ``trap-sample`` whose tree landed on ``main`` (HEAD)."""
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    for path, text in (extra_rules or {}).items():
        repo.write(path, text)
    if extra_rules:
        repo.git("checkout", "-q", "main")
        repo.commit("more rules")
        repo.git("checkout", "-q", "work")
        repo.git("merge", "-q", "main")
    repo.write("src/app.py", "def app():\n    return 2\n")
    assert hv.mcp_call("aegis_scan", repo.root, session="s1", files=["src/app.py"]).get("status") != "FAIL"
    assert checkrun.record(repo.root, tests=True, base="main").status == "recorded"
    hv.mcp_call("aegis_report_outcome", repo.root, session="s1", outcome="success",
                rules_used=["trap-sample"], idempotency_key="k1")
    commit = repo.commit("work")
    repo.git("branch", "-f", "main", commit)
    return repo, commit


def _states(proj) -> List[tuple]:
    return [(c.state, c.reason, c.counts) for c in proj.credits]


def _fit(root: Path, rule_id: str = "trap-sample", **kw):
    return fitness.for_rules(root, rules.load_rules(root).served, **kw)[rule_id]


@needs_git
def test_scan_with_real_and_forged_ci_rows_makes_no_gh_call(tmp_path, monkeypatch):
    repo, commit = _landed(tmp_path)
    ledger.append_rows(repo.root, [_ci_row(commit)] + [_ci_row(sha) for sha in FORGED])
    gh = _gh(monkeypatch, CountingGh([hv.ci_run(commit, run_id=10)]))
    res = scan.scan(repo.root, changed_files=["src/app.py"])
    assert [r["name"] for r in res["relevant_rules"]] == ["trap-sample"]
    assert gh.calls == []


@needs_git
def test_a_verdict_verified_earlier_in_this_process_counts_offline(tmp_path, monkeypatch):
    repo, commit = _landed(tmp_path)
    credit.confirm(repo.root, client=hv.FakeCI([hv.ci_run(commit, run_id=10)]), workflow=hv.CI_WORKFLOW)
    gh = _gh(monkeypatch, CountingGh())
    assert _fit(repo.root, verify_ci=False).tp == 1
    assert gh.calls == []


@needs_git
def test_offline_projection_never_credits_an_unverified_ci_row_and_verifying_does(tmp_path, monkeypatch):
    repo, commit = _landed(tmp_path)
    ledger.append_rows(repo.root, [_ci_row(commit)])
    gh = _gh(monkeypatch, CountingGh([hv.ci_run(commit, run_id=10)]))
    assert _states(credit.project_credits(repo.root, verify_ci=False)) == [("landed", "unverified_ci", False)]
    assert _fit(repo.root, verify_ci=False).tp == 0
    assert gh.calls == []
    assert _states(credit.project_credits(repo.root, verify_ci=True)) == [("confirmed", "", True)]
    assert _fit(repo.root, verify_ci=True).tp == 1
    assert (len(gh.api), len(gh.runs_api)) == (2, 1)


@needs_git
def test_a_dead_gh_costs_one_attempt_per_projection(tmp_path, monkeypatch):
    """Given GitHub names the default branch and then every runs GET fails, When seven well-formed
    commits are pending, Then the breaker stops at the first: one runs GET, projection unavailable."""
    repo, commit = _landed(tmp_path)
    ledger.append_rows(repo.root, [_ci_row(commit)] + [_ci_row(sha) for sha in FORGED])
    gh = _gh(monkeypatch, CountingGh(fail_runs=True))
    proj = credit.project_credits(repo.root, verify_ci=True)
    assert (len(gh.api), len(gh.runs_api)) == (2, 1)
    assert (proj.available, proj.error) == (
        False, f"CI verification stopped after gh failed for {commit[:12]}; 7 commit(s) were not verified")
    assert _states(proj) == [("landed", "unverified_ci", False)]
    assert credit._UNAVAILABLE_CI == set()


@needs_git
def test_a_dead_repository_get_costs_one_attempt_and_reads_no_run(tmp_path, monkeypatch):
    repo, commit = _landed(tmp_path)
    ledger.append_rows(repo.root, [_ci_row(commit)] + [_ci_row(sha) for sha in FORGED])
    gh = _gh(monkeypatch, CountingGh(fail=True))
    proj = credit.project_credits(repo.root, verify_ci=True)
    assert (len(gh.api), len(gh.runs_api)) == (1, 0)
    assert (proj.available, proj.error) == (
        False, "CI verification stopped: GitHub did not name the default branch (gh api failed (exit 1)); "
               "7 commit(s) were not verified")
    assert _states(proj) == [("landed", "unverified_ci", False)]


@needs_git
def test_a_healthy_gh_still_verifies_every_row(tmp_path, monkeypatch):
    repo, commit = _landed(tmp_path)
    ledger.append_rows(repo.root, [_ci_row(sha) for sha in FORGED[:3]] + [_ci_row(commit)])
    gh = _gh(monkeypatch, CountingGh([hv.ci_run(commit, run_id=10)]))
    proj = credit.project_credits(repo.root, verify_ci=True)
    assert (len(gh.api), len(gh.runs_api)) == (5, 4)
    assert _states(proj) == [("confirmed", "", True)]


@needs_git
def test_malformed_commit_ids_do_not_switch_verification_off(tmp_path, monkeypatch):
    repo, commit = _landed(tmp_path)
    ledger.append_rows(repo.root, [_ci_row(f"not-a-sha-{i}") for i in range(6)] + [_ci_row(commit)])
    gh = _gh(monkeypatch, CountingGh([hv.ci_run(commit, run_id=10)]))
    proj = credit.project_credits(repo.root, verify_ci=True)
    assert len(gh.runs_api) == 1 and commit in gh.runs_api[0][1]
    assert _states(proj) == [("confirmed", "", True)]


@needs_git
def test_a_cached_pending_verdict_is_rechecked_in_a_long_lived_process(tmp_path, monkeypatch):
    repo, commit = _landed(tmp_path)
    ledger.append_rows(repo.root, [_ci_row(commit, "pending")])
    _gh(monkeypatch, CountingGh([hv.ci_run(commit, None, status="in_progress", run_id=10)]))
    assert [c.counts for c in credit.project_credits(repo.root, verify_ci=True).credits] == [False]
    ledger.append_rows(repo.root, [_ci_row(commit, "success")])
    _gh(monkeypatch, CountingGh([hv.ci_run(commit, run_id=10)]))
    assert _states(credit.project_credits(repo.root, verify_ci=True)) == [("confirmed", "", True)]


@needs_git
def test_a_cached_failure_is_superseded_by_a_later_successful_attempt(tmp_path, monkeypatch):
    repo, commit = _landed(tmp_path)
    ledger.append_rows(repo.root, [_ci_row(commit, "failure", attempt=1)])
    _gh(monkeypatch, CountingGh([hv.ci_run(commit, "failure", run_id=10, attempt=1)]))
    assert _states(credit.project_credits(repo.root, verify_ci=True)) == [("voided", "ci_failed", False)]
    ledger.append_rows(repo.root, [_ci_row(commit, "success", attempt=2)])
    _gh(monkeypatch, CountingGh([hv.ci_run(commit, run_id=10, attempt=2, run_started_at="2026-10-17T11:00:00Z")]))
    assert _states(credit.project_credits(repo.root, verify_ci=True)) == [("confirmed", "", True)]


@needs_git
def test_scan_ranks_a_credit_only_rule_as_a_no_credit_rule_in_a_fresh_process(tmp_path, monkeypatch):
    """Documented 4.4.0 behaviour: scan-time fitness ignores CI-confirmed credit this process did not
    verify (sync does not persist the verdict). Ranking from sync's derived.json is a v4.5 change."""
    repo, commit = _landed(tmp_path)
    ledger.append_rows(repo.root, [_ci_row(commit)])
    gh = _gh(monkeypatch, CountingGh([hv.ci_run(commit, run_id=10)]))
    result = scan.scan(repo.root, changed_files=["src/app.py"])
    # no number below MIN_N either way (R-evidence-8); the text says the CI tp was not counted
    assert [(r["name"], r["fitness"]) for r in result["relevant_rules"]] == [("trap-sample", None)]
    assert "Fitness: no evidence yet" in result["guidance"]
    assert gh.calls == []
    verified = _fit(repo.root, verify_ci=True)
    assert verified.tp == 1 and verified.score > 0.0


@needs_git
def test_scan_orders_by_ledger_outcomes_while_the_verifying_path_counts_ci_credit(tmp_path, monkeypatch):
    repo, commit = _landed(tmp_path, {".aegis/rules/traps/trap-b.md": RULE_B})
    ledger.append_rows(repo.root, [_ci_row(commit)])
    ledger.append(repo.root, [{"rule": "trap-b", "outcome": "tp", "source": "ci", "key": "b-tp"},
                              {"rule": "trap-b", "outcome": "fp", "source": "ci", "key": "b-fp"}])
    _gh(monkeypatch, CountingGh([hv.ci_run(commit, run_id=10)]))
    scanned = scan.scan(repo.root, changed_files=["src/app.py"])["relevant_rules"]
    assert [r["name"] for r in scanned] == ["trap-b", "trap-sample"]
    fits = fitness.for_rules(repo.root, rules.load_rules(repo.root).served, verify_ci=True)
    assert fits["trap-sample"].score > fits["trap-b"].score > 0.0


def test_select_ci_run_skips_a_run_whose_id_is_not_an_integer():
    """F3: ``ci_green.counted_runs`` skips such a run; credit used to raise ValueError."""
    sha = "a" * 40
    bad = dict(hv.ci_run(sha, run_id=1), id="not-a-number", run_started_at="2026-10-17T12:00:00Z")
    good = hv.ci_run(sha, run_id=7)
    assert credit.select_ci_run([bad, good], sha, hv.CI_WORKFLOW, branch="main") is good
    assert credit.select_ci_run([bad], sha, hv.CI_WORKFLOW, branch="main") is None
