"""R-checks-34: `aegis check --ci` has one blocking predicate. The printed verdict, the JSON status and
the exit code agree; a FAILED run names its cause; perf, coverage and trailer results are visible."""
from __future__ import annotations

import itertools
import json
import os
from pathlib import Path

import pytest

from aegis_cli import check
from aegis_cli.cli import main
from aegis_core import human_gate, regression, rule_integrity
from aegis_core.verification import coverage_check, perf_check
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")

PERF = {
    "pass": {"status": "pass", "regressed": False, "noisy": False, "passed": True, "rounds": 15, "threshold": 0.05,
             "aa_drift": 0.0, "base_min": 0.0100, "head_min": 0.0101, "base_median": 0.0100, "head_median": 0.0101},
    "fail": {"status": "fail", "regressed": True, "noisy": False, "passed": False, "rounds": 15, "threshold": 0.05,
             "aa_drift": 0.0, "base_min": 0.0100, "head_min": 0.0200, "base_median": 0.0100, "head_median": 0.0200},
    "unverified": {"status": "unverified", "reason": "no perf.command configured and pytest-benchmark is not installed",
                   "regressed": False, "noisy": False, "passed": True},
}
COVERAGE = {
    "reported": {"status": "reported", "reason": "", "covered_lines": 2, "executable_lines": 4, "ratio": 0.5,
                 "uncovered_ranges": {"pkg/a.py": [[3, 4]]}, "unmeasured": []},
    "unverified": {"status": "unverified", "reason": "no coverage module", "covered_lines": 0, "executable_lines": 0,
                   "ratio": None, "uncovered_ranges": {}, "unmeasured": []},
}


@pytest.fixture(autouse=True)
def _env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(tmp_path / "home"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GITHUB_BASE_REF", "GITHUB_EVENT_PATH", "GITHUB_STEP_SUMMARY", "GITHUB_EVENT_NAME"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> hg.Repo:
    project = hg.make_repo(tmp_path)
    project.write("src/app.py", "def app():\n    return 2\n")
    project.commit("feat: app returns two")
    monkeypatch.chdir(project.root)
    return project


def _approved(monkeypatch, repo: hg.Repo) -> None:
    """check_ci answers one weakening that a valid signature approved (the signing itself is covered
    by the rule-integrity tests; here only the verdict over it is under test)."""
    real = rule_integrity.check_ci

    def approved(root, base, head, **kw):
        report = real(root, base, head, **kw)
        return rule_integrity.CiReport(
            report.base, report.head, report.merge_base, report.rules_checked,
            (rule_integrity.Weakening("rule-deleted", "trap-sample", ".aegis/rules/traps/trap-sample.md", "deleted"),),
            human_gate.Approval(True, "ok", "", report.head, "Human"))
    monkeypatch.setattr(rule_integrity, "check_ci", approved)


def _ci(capsys, *extra: str):
    try:
        rc = main(["check", "--ci", "--base", "main", *extra])
    except SystemExit as exc:
        rc = int(exc.code or 0)
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


def _verdict(out: str) -> str:
    return next(line for line in out.splitlines() if line.startswith("aegis check --ci:"))


@needs_git
def test_the_verdict_line_the_json_status_and_the_exit_code_agree(repo, capsys, monkeypatch):
    for cov, perf, fmt, weakened in itertools.product((None, "reported", "unverified"), (None, "pass", "unverified", "fail"),
                                                      ("text", "github"), (False, True)):
        with monkeypatch.context() as m:
            m.setattr(coverage_check, "run_diff_coverage", lambda *a, **k: dict(COVERAGE[cov]))
            m.setattr(perf_check, "run_perf_check", lambda *a, **k: dict(PERF[perf]))
            if weakened:
                _approved(m, repo)
            flags = (["--coverage"] if cov else []) + (["--perf"] if perf else [])
            rc, out, _ = _ci(capsys, *flags, "--format", fmt)
            _, doc_out, _ = _ci(capsys, *flags, "--format", "json")
        doc = json.loads(doc_out)
        case = (cov, perf, fmt, weakened)
        assert rc == (1 if perf == "fail" else 0), case
        assert (": FAILED" in _verdict(out)) is (rc == 1) and (": PASSED" in _verdict(out)) is (rc == 0), (case, out)
        assert (doc["status"] == "fail") is (rc == 1) and bool(doc["blocking"]) is (rc == 1), case


@needs_git
def test_a_failing_perf_names_its_cause_with_and_without_an_approved_weakening(repo, capsys, monkeypatch):
    monkeypatch.setattr(perf_check, "run_perf_check", lambda *a, **k: dict(PERF["fail"]))
    rc, out, _ = _ci(capsys, "--perf")
    assert rc == 1 and _verdict(out).startswith("aegis check --ci: FAILED: performance regression (")
    assert "  [FAIL:perf] " in out
    _approved(monkeypatch, repo)
    rc, out, _ = _ci(capsys, "--perf")
    assert rc == 1 and _verdict(out).endswith("); 1 weakening(s) approved")
    assert "FAILED: performance regression (" in _verdict(out)
    rc, out, _ = _ci(capsys, "--perf", "--format", "json")
    doc = json.loads(out)
    assert doc["status"] == "fail" and doc["blocking"][0].startswith("performance regression (")


def test_an_approved_weakening_and_a_blocking_regression_names_the_regression(tmp_path, capsys):
    head, mb = "b" * 40, "a" * 40
    report = rule_integrity.CiReport("main", head, mb, 1, (rule_integrity.Weakening("rule-deleted", "r", "p.md", "gone"),),
                                     human_gate.Approval(True, "ok", "", head, "Human"))
    failing = regression.CommitRegression("c" * 40, "fix: x", "failed", "no test")
    reg = regression.RegressionReport(tier="gate", commits=(failing,),
                                      findings=(regression.RegressionFinding("no_test_changes", "c" * 40, "src/a.py", "no test"),))
    blocking = check._print_ci(report, "text", str(tmp_path), reg_report=reg)
    out = capsys.readouterr().out
    assert blocking == [f"regression check failed (1 finding(s), {mb[:10]}..{head[:10]})"]
    assert _verdict(out) == f"aegis check --ci: FAILED: {blocking[0]}; 1 weakening(s) approved"


@needs_git
def test_a_trailer_only_failure_is_in_the_step_summary(repo, capsys, monkeypatch, tmp_path):
    from aegis_core import checkrun

    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setattr(checkrun, "verify_commit_trailers", lambda *a, **k: [
        {"commit": "d" * 40, "result": "void", "failed": True, "reason": "outcomes still diverge on the same tree"}])
    rc, out, _ = _ci(capsys)
    assert rc == 1 and "FAILED: Aegis-Check trailer divergence" in _verdict(out)
    text = summary.read_text(encoding="utf-8")
    assert "outcomes still diverge on the same tree" in text and "No findings reported." not in text
    rc, out, _ = _ci(capsys, "--format", "github")
    assert [line for line in out.splitlines() if line.startswith("::error title=Aegis-Check trailer divergence::dddddddddd: ")]


@needs_git
def test_the_step_summary_shows_the_perf_result(repo, capsys, monkeypatch, tmp_path):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setattr(perf_check, "run_perf_check", lambda *a, **k: dict(PERF["fail"]))
    _ci(capsys, "--perf")
    assert "### Performance: FAIL" in summary.read_text(encoding="utf-8")


@needs_git
def test_github_annotations_for_perf(repo, capsys, monkeypatch):
    monkeypatch.setattr(perf_check, "run_perf_check", lambda *a, **k: dict(PERF["fail"]))
    rc, out, _ = _ci(capsys, "--perf", "--format", "github")
    assert rc == 1 and len([line for line in out.splitlines() if line.startswith("::error title=performance regression::")]) == 1
    monkeypatch.setattr(perf_check, "run_perf_check", lambda *a, **k: dict(PERF["unverified"]))
    rc, out, _ = _ci(capsys, "--perf", "--format", "github")
    assert rc == 0 and ": PASSED" in _verdict(out) and "::error" not in out
    assert len([line for line in out.splitlines() if line.startswith("::warning")]) == 1
    rc, out, _ = _ci(capsys, "--perf")
    assert "  [UNVERIFIED:perf] no perf.command configured and pytest-benchmark is not installed" in out


@needs_git
def test_an_unwritable_step_summary_is_one_note_and_the_same_exit(repo, capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "no-such-dir" / "summary.md"))
    rc, out, err = _ci(capsys)
    assert rc == 0 and ": PASSED" in _verdict(out)
    assert len([line for line in err.splitlines() if "step summary" in line]) == 1


@needs_git
def test_the_step_summary_is_appended_to(repo, capsys, monkeypatch, tmp_path):
    summary = tmp_path / "summary.md"
    summary.write_bytes(b"## an earlier step\n")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    _ci(capsys)
    text = summary.read_text(encoding="utf-8")
    assert text.startswith("## an earlier step\n") and "## Aegis Check Summary: PASSED" in text


@needs_git
def test_a_workspace_subdirectory_resolves_as_the_other_modes_do(repo, capsys, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    try:
        rc = main(["check", "--ci", "--base", "main", "--workspace", str(repo.root)])
    except SystemExit as exc:
        rc = int(exc.code or 0)
    assert rc == 0 and ": PASSED" in _verdict(capsys.readouterr().out)


@needs_git
def test_without_coverage_or_perf_the_text_is_unchanged_but_for_the_scanners_line(repo, capsys):
    rc, out, _ = _ci(capsys)
    lines = out.splitlines()
    assert rc == 0 and lines[0].startswith("aegis check --ci: PASSED, no rule weakened (")
    assert lines[1:] == ["  [untested-change] " + repo.head()[:10] + " (feat: app returns two): src/app.py",
                         "scanners: none configured"]
