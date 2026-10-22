"""R-checks-35: every option a mode would ignore is refused, `--coverage` and `--perf` only apply with
`--ci`, an explicit `--perf` that measured nothing is visible, and the format is resolved once."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from aegis_cli.cli import main
from aegis_core.verification import coverage_check
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")


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


def _run(*argv: str):
    try:
        return main(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)


@needs_git
@pytest.mark.parametrize("flag", ["--coverage", "--perf"])
@pytest.mark.parametrize("mode", [[], ["--record"], ["--card"], ["--lane", "x"], ["--hook"]],
                         ids=["plain", "record", "card", "lane", "hook"])
def test_coverage_and_perf_outside_ci_are_usage_errors(repo, capsys, flag, mode):
    rc = _run("check", "--workspace", str(repo.root), *mode, flag)
    err = capsys.readouterr().err
    assert rc == 2 and f"{flag} only applies with --ci" in err


@needs_git
def test_perf_on_a_checkout_that_is_not_the_head_is_unverified_and_runs_nothing(repo, capsys, monkeypatch):
    """w7 made coverage UNVERIFIED for a checkout that is not --head; perf measures the same work tree."""
    from aegis_core.verification import perf_check

    calls = []
    monkeypatch.setattr(perf_check, "run_perf_check", lambda *a, **k: calls.append(a) or {"status": "pass", "passed": True})
    other = repo.git("rev-parse", "HEAD~1")
    rc = _run("check", "--ci", "--base", "main", "--perf", "--head", other, "--format", "json")
    perf = json.loads(capsys.readouterr().out)["perf"]
    assert (rc, perf["status"], calls) == (0, "unverified", [])
    assert f"the checkout is not {other[:12]}" in perf["reason"]
    rc = _run("check", "--ci", "--base", "main", "--perf", "--head", "HEAD", "--format", "json")
    assert rc == 0 and json.loads(capsys.readouterr().out)["perf"]["status"] == "pass" and len(calls) == 1


@needs_git
@pytest.mark.parametrize("fmt", ["sarif", "github"])
def test_json_with_a_machine_format_is_a_usage_error(repo, capsys, fmt):
    rc = _run("check", "--ci", "--base", "main", "--format", fmt, "--json")
    out, err = capsys.readouterr()
    assert rc == 2 and "--json" in err and f"--format {fmt}" in err and out == ""


@needs_git
def test_perf_with_nothing_to_run_is_reported_unverified_and_does_not_block(repo, capsys):
    rc = _run("check", "--ci", "--base", "HEAD~1", "--perf")
    out = capsys.readouterr().out
    assert rc == 0 and "  [UNVERIFIED:perf] no perf.command configured and pytest-benchmark is not installed" in out
    rc = _run("check", "--ci", "--base", "HEAD~1", "--perf", "--format", "github")
    out = capsys.readouterr().out
    assert rc == 0 and [line for line in out.splitlines() if line.startswith("::warning title=performance unverified::")]


@needs_git
def test_coverage_on_the_head_checkout_runs(repo, capsys, monkeypatch):
    calls = []
    monkeypatch.setattr(coverage_check, "run_diff_coverage", lambda *a, **k: calls.append(a) or {
        "status": "unverified", "reason": "stub", "ratio": None, "uncovered_ranges": {}, "unmeasured": []})
    assert _run("check", "--ci", "--base", "main", "--coverage", "--head", "HEAD") == 0 and len(calls) == 1


def test_the_help_names_every_format_and_says_coverage_is_a_report():
    import argparse

    from aegis_cli.check import CheckCommand

    parser = argparse.ArgumentParser()
    CheckCommand().configure_parser(parser)
    text = " ".join(parser.format_help().split())
    assert "github|sarif" in text and "SARIF 2.1.0" in text and "report-only diff coverage" in text
