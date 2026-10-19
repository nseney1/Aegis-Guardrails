"""Pre-tag release check .github/scripts/ci_green.py (ADR 0005 AD-10, defense #33; v4.3 T1/T2).

A workflow job cannot see its own run's conclusion, so "CI green on the exact SHA" is checked
before tagging. It asks the REST API (``gh api repos/{o}/{r}/actions/runs?head_sha=<sha>``) and
applies the v4.3 T1 rules: only runs whose ``path`` is the required workflow, whose head is this
commit in this repository, and whose event is push, workflow_dispatch or release count; cancelled
runs are ignored and the newest run (its latest attempt) decides. The gh subprocess is mocked;
every case asserts the exit code and the message.

The eight v4.0 cases that pinned ``gh run list`` were rewritten to this contract under an
author waiver (lane f-a3-rule-integrity); the bad-sha, missing-gh and unparseable-output cases
are kept as they were.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "ci_green.py"
SHA = "4f2810174fbd6014dd5db3e7c90121e1bc514676"
OTHER = "175f3b3aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
REQUIRED = ".github/workflows/validate.yml"
REPO = "owner/project"


@pytest.fixture
def ci_green():
    spec = importlib.util.spec_from_file_location("ci_green", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _gh(monkeypatch, module, runs=None, returncode=0, stdout=None, raises=None):
    """Every gh call answers ``runs`` as one page (the newest run decides, so one page is read)."""
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if raises is not None:
            raise raises
        if stdout is not None:
            out = stdout
        else:
            page = list(runs or [])
            out = json.dumps({"total_count": len(page), "workflow_runs": page})
        return subprocess.CompletedProcess(argv, returncode, stdout=out, stderr="gh: boom" if returncode else "")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    return calls


def _run(run_id: int = 1, *, status: str = "completed", conclusion: Optional[str] = "success", sha: str = SHA,
         path: str = REQUIRED, event: str = "push", head: Optional[str] = REPO,
         started: str = "2026-10-16T10:00:00Z", attempt: int = 1) -> Dict[str, Any]:
    run: Dict[str, Any] = {
        "id": run_id, "name": "Validate", "path": path, "head_sha": sha, "event": event, "status": status,
        "conclusion": conclusion, "run_attempt": attempt, "run_started_at": started,
        "created_at": "2026-10-16T09:00:00Z", "repository": {"full_name": REPO},
    }
    if head is not None:
        run["head_repository"] = {"full_name": head}
    return run


def _endpoint() -> str:
    return f"repos/{{owner}}/{{repo}}/actions/runs?head_sha={SHA}&per_page=100"


def test_green_when_the_newest_run_of_the_required_workflow_succeeded(ci_green, monkeypatch, capsys):
    calls = _gh(monkeypatch, ci_green, [_run()])
    assert ci_green.main([SHA]) == 0
    assert calls == [["gh", "api", "-H", "Accept: application/vnd.github+json", _endpoint()]]
    out = capsys.readouterr().out
    assert f"CI is green on {SHA}" in out and "validate.yml" in out


def test_red_when_the_newest_run_failed(ci_green, monkeypatch, capsys):
    runs = [_run(1, started="2026-10-16T10:00:00Z"), _run(2, conclusion="failure", started="2026-10-16T12:00:00Z")]
    _gh(monkeypatch, ci_green, runs)
    assert ci_green.main([SHA]) == 1
    assert "run 2: failure" in capsys.readouterr().err


def test_a_successful_rerun_wins_over_the_failed_run_before_it(ci_green, monkeypatch, capsys):
    runs = [_run(1, conclusion="failure", started="2026-10-16T10:00:00Z"),
            _run(2, attempt=2, started="2026-10-16T12:00:00Z")]
    _gh(monkeypatch, ci_green, runs)
    assert ci_green.main([SHA]) == 0
    assert "attempt 2" in capsys.readouterr().out


def test_a_cancelled_run_is_ignored_and_the_older_success_decides(ci_green, monkeypatch):
    runs = [_run(2, conclusion="cancelled", started="2026-10-16T12:00:00Z"), _run(1, started="2026-10-16T10:00:00Z")]
    _gh(monkeypatch, ci_green, runs)
    assert ci_green.main([SHA]) == 0


def test_only_cancelled_runs_is_not_green(ci_green, monkeypatch, capsys):
    _gh(monkeypatch, ci_green, [_run(conclusion="cancelled")])
    assert ci_green.main([SHA]) == 1
    assert f"no CI run of validate.yml found for {SHA}" in capsys.readouterr().err


def test_red_while_a_run_is_still_in_progress(ci_green, monkeypatch, capsys):
    _gh(monkeypatch, ci_green, [_run(status="in_progress", conclusion=None)])
    assert ci_green.main([SHA]) == 1
    assert "in_progress" in capsys.readouterr().err


def test_red_when_no_run_exists_for_the_sha(ci_green, monkeypatch, capsys):
    _gh(monkeypatch, ci_green, [])
    assert ci_green.main([SHA]) == 1
    assert f"no CI run of validate.yml found for {SHA}" in capsys.readouterr().err


@pytest.mark.parametrize("label,run", [
    ("other-commit", _run(sha=OTHER)),
    ("other-workflow", _run(path=".github/workflows/publish.yml")),
    ("fork-head", _run(head="attacker/project")),
    ("no-head-repo", _run(head=None)),
    ("pull_request", _run(event="pull_request")),
    ("pr_target", _run(event="pull_request_target")),
    ("schedule", _run(event="schedule")),
])
def test_runs_that_may_not_decide_do_not_count(ci_green, monkeypatch, capsys, label, run):
    _gh(monkeypatch, ci_green, [run])
    assert ci_green.main([SHA]) == 1
    assert f"no CI run of validate.yml found for {SHA}" in capsys.readouterr().err


@pytest.mark.parametrize("event", ["push", "workflow_dispatch", "release"])
def test_each_trusted_event_counts(ci_green, monkeypatch, event):
    _gh(monkeypatch, ci_green, [_run(event=event)])
    assert ci_green.main([SHA]) == 0


def test_a_failing_run_of_another_workflow_does_not_turn_it_red(ci_green, monkeypatch):
    _gh(monkeypatch, ci_green, [_run(1), _run(2, path=".github/workflows/publish.yml", conclusion="failure",
                                              started="2026-10-16T12:00:00Z")])
    assert ci_green.main([SHA]) == 0


def test_the_workflow_flag_selects_the_required_workflow_by_path(ci_green, monkeypatch):
    calls = _gh(monkeypatch, ci_green, [_run(path=".github/workflows/release.yml")])
    assert ci_green.main([SHA, "--workflow", "release.yml"]) == 0
    assert calls[0][-1] == _endpoint()


def test_the_repo_flag_is_gone(ci_green, monkeypatch, capsys):
    calls = _gh(monkeypatch, ci_green, [_run()])
    with pytest.raises(SystemExit) as exc:
        ci_green.main([SHA, "--repo", REPO])
    assert exc.value.code == 2 and calls == []
    assert "unrecognized arguments: --repo" in capsys.readouterr().err


@pytest.mark.parametrize("bad", ["4f28101", "HEAD", "4F2810174FBD6014DD5DB3E7C90121E1BC514676", SHA + "0", ""])
def test_only_a_full_lowercase_sha_is_accepted(ci_green, monkeypatch, capsys, bad):
    calls = _gh(monkeypatch, ci_green, [_run()])
    assert ci_green.main([bad]) == 2
    assert calls == []
    assert "full 40-character commit SHA" in capsys.readouterr().err


def test_missing_gh_is_an_error(ci_green, monkeypatch, capsys):
    _gh(monkeypatch, ci_green, raises=FileNotFoundError("gh"))
    assert ci_green.main([SHA]) == 2
    assert "gh (GitHub CLI) not found" in capsys.readouterr().err


def test_gh_timeout_is_an_error(ci_green, monkeypatch, capsys):
    _gh(monkeypatch, ci_green, raises=subprocess.TimeoutExpired(["gh"], 120))
    assert ci_green.main([SHA]) == 2
    assert "gh api did not answer within 120s" in capsys.readouterr().err


def test_gh_failure_is_an_error(ci_green, monkeypatch, capsys):
    _gh(monkeypatch, ci_green, returncode=1)
    assert ci_green.main([SHA]) == 2
    assert "gh api failed (exit 1): gh: boom" in capsys.readouterr().err


def test_unparseable_gh_output_is_an_error(ci_green, monkeypatch, capsys):
    _gh(monkeypatch, ci_green, stdout="not json")
    assert ci_green.main([SHA]) == 2
    assert "could not parse gh output" in capsys.readouterr().err


@pytest.mark.parametrize("body", ["[]", json.dumps({"workflow_runs": "x"}), json.dumps({"message": "Not Found"})])
def test_a_body_that_is_not_a_run_list_is_an_error(ci_green, monkeypatch, capsys, body):
    _gh(monkeypatch, ci_green, stdout=body)
    assert ci_green.main([SHA]) == 2
    assert "could not parse gh output" in capsys.readouterr().err


def test_a_run_with_a_malformed_id_is_not_counted(ci_green, monkeypatch, capsys):
    _gh(monkeypatch, ci_green, [_run(1), dict(_run(2, conclusion="failure", started="2026-10-16T12:00:00Z"), id="x")])
    assert ci_green.main([SHA]) == 0
    _gh(monkeypatch, ci_green, [dict(_run(2), id=True)])
    assert ci_green.main([SHA]) == 1
