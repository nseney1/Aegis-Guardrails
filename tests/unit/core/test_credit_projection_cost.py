"""credit.project_credits does work only for the evidence it derives from (R-structure-4, R-evidence-20(a)).

Credits derive from ``report`` rows only, so a ledger without one needs no landed lookup, no protected
branch and no CI. Git calls are counted at ``gitsafe.run``; no gh and no network is reached.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
from typing import List

import pytest

from aegis_core import credit, gitevidence, gitsafe, human_gate
from aegis_core.telemetry_engine import ledger

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    gitevidence._reset_for_tests()
    yield
    gitevidence._reset_for_tests()


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=T", *args], cwd=str(cwd),
                          check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / ".gitignore").write_text(".aegis/\n", encoding="utf-8")
    (root / "a.txt").write_text("a\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return root


@pytest.fixture
def git_calls(monkeypatch) -> List[List[str]]:
    real, seen = gitsafe.run, []

    def spy(args, cwd, *rest, **kwargs):
        seen.append(list(args))
        return real(args, cwd, *rest, **kwargs)

    monkeypatch.setattr(gitsafe, "run", spy)
    return seen


def _row(**fields) -> dict:
    return {"v": ledger.LEDGER_VERSION, "ts": "2026-10-20T00:00:00Z", **fields}


def _exposures(root: Path) -> None:
    ledger.append_rows(root, [_row(event="exposure", rule="rule-a", session="s1", host="h", paths=[], rev=None)])


def test_without_a_report_row_the_projection_is_empty_and_asks_git_only_where_the_ledger_is(repo, git_calls):
    _exposures(repo)
    ledger.append_rows(repo, [_row(event="ci", commit="a" * 40, workflow="validate.yml", ci_conclusion="success",
                                   run_id=1, ci_run_attempt=1)])
    git_calls.clear()
    with gitsafe.memo():
        proj = credit.project_credits(repo)
    assert proj == credit.CreditProjection((), (), True, None)
    assert len(git_calls) == 1 and "--git-common-dir" in git_calls[0], git_calls


@pytest.mark.parametrize("with_view", [False, True], ids=["read", "view"])
def test_a_torn_ledger_without_reports_is_still_unavailable_with_the_same_reason(repo, git_calls, with_view):
    _exposures(repo)
    with open(ledger.ledger_path(repo), "ab") as fh:
        fh.write(b"{not json\n")
    ledger.append_rows(repo, [_row(event="exposure", rule="rule-b", session="s2", host="h", paths=[], rev=None)])
    view = ledger.read(repo) if with_view else None
    proj = credit.project_credits(repo, view=view)
    assert (proj.credits, proj.available, proj.error) == ((), False, "1 unreadable line(s)")


def test_a_landed_check_with_a_report_still_derives_landed(repo):
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    head = _git(repo, "rev-parse", "HEAD")
    ledger.append_rows(repo, [
        _row(event="check", id="chk-1", tree=tree, head=head, witness="aegis", passed=True,
             tests={"exit": 0, "passed": 2, "timed_out": False}),
        _row(event="report", witness="aegis", check="chk-1", tree=tree, rule="rule-a", for_rule="rule-a", result="tp",
             key="credit:chk-1:rule-a"),
    ])
    proj = credit.project_credits(repo)
    assert proj.available and [(c.rule, c.state, c.commit) for c in proj.credits] == [("rule-a", "landed", head)]


def test_a_scan_never_asks_gh_about_a_ci_row(repo, monkeypatch):
    from aegis_core.scan import scan
    from tests.helpers_humangate import RULE

    asked = []
    monkeypatch.setattr(human_gate, "default_gh_runner", lambda argv, stdin=None, cwd=None: asked.append(argv))
    rule = repo / ".aegis" / "rules" / "traps" / "trap-sample.md"
    rule.parent.mkdir(parents=True)
    rule.write_text(RULE, encoding="utf-8")
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    head = _git(repo, "rev-parse", "HEAD")
    ledger.append_rows(repo, [
        _row(event="check", id="chk-1", tree=tree, head=head, witness="aegis", passed=True,
             tests={"exit": 0, "passed": 2, "timed_out": False}),
        _row(event="report", witness="aegis", check="chk-1", tree=tree, rule="trap-sample", for_rule="trap-sample",
             result="tp", key="credit:chk-1:trap-sample"),
        _row(event="ci", commit=head, workflow="validate.yml", ci_conclusion="success", run_id=1, ci_run_attempt=1),
    ])
    assert scan(repo, ["src/app.py"])["relevant_rules"]
    assert asked == []
