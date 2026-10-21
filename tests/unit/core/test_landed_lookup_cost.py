"""credit.landed_lookup asks git once per question it can answer for good (R-structure-4, R-evidence-20,
R-structure-9): one commit list per tip, one ancestry test per (tree, head), never a negative kept.

Git calls are counted at ``gitsafe.run``; the repositories are throwaway ones under ``tmp_path``.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, List

import pytest

from aegis_core import credit, gitevidence, gitsafe
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


def _history(tmp_path: Path, contents: List[str]) -> Dict[str, Any]:
    """One commit per content on main: {"commits": [...], "trees": [...]}, oldest first."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / ".gitignore").write_text(".aegis/\n", encoding="utf-8")
    commits, trees = [], []
    for text in contents:
        (repo / "f.txt").write_text(text, encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", text.strip())
        commits.append(_git(repo, "rev-parse", "HEAD"))
        trees.append(_git(repo, "rev-parse", "HEAD^{tree}"))
    return {"root": str(repo), "commits": commits, "trees": trees}


@pytest.fixture
def git_calls(monkeypatch) -> List[List[str]]:
    real, seen = gitsafe.run, []

    def spy(args, cwd, *rest, **kwargs):
        seen.append(list(args))
        return real(args, cwd, *rest, **kwargs)

    monkeypatch.setattr(gitsafe, "run", spy)
    return seen


def _ancestry(seen: List[List[str]]) -> int:
    return sum(1 for a in seen if a[:2] == ["merge-base", "--is-ancestor"])


def _check_and_reports(root: str, tree: str, head: str, rules: int, check_id: str = "chk-1") -> None:
    rows = [{"v": ledger.LEDGER_VERSION, "ts": "2026-10-20T00:00:00Z", "event": "check", "id": check_id,
             "tree": tree, "head": head, "witness": "aegis", "passed": True,
             "tests": {"exit": 0, "passed": 3, "timed_out": False}}]
    rows += [{"v": ledger.LEDGER_VERSION, "ts": "2026-10-20T00:00:01Z", "event": "report", "witness": "aegis",
              "check": check_id, "tree": tree, "rule": f"rule-{n}", "for_rule": f"rule-{n}", "result": "tp",
              "key": f"credit:{check_id}:rule-{n}"} for n in range(rules)]
    ledger.append_rows(root, rows)


def test_forty_reports_on_one_landed_check_ask_one_ancestry_question(tmp_path, git_calls):
    h = _history(tmp_path, ["a\n", "b\n", "c\n"])
    root = h["root"]
    _check_and_reports(root, h["trees"][1], h["commits"][0], rules=40)
    proj = credit.project_credits(root)
    assert len(proj.credits) == 40 and {(c.state, c.commit) for c in proj.credits} == {("landed", h["commits"][1])}
    assert _ancestry(git_calls) == 1, git_calls


def test_a_second_projection_in_the_process_asks_git_nothing_it_already_knows(tmp_path, git_calls):
    h = _history(tmp_path, ["a\n", "b\n", "c\n"])
    root = h["root"]
    _check_and_reports(root, h["trees"][1], h["commits"][0], rules=3)
    for _ in range(2):
        assert {c.state for c in credit.project_credits(root).credits} == {"landed"}
    assert _ancestry(git_calls) == 1
    assert sum(1 for a in git_calls if a[0] == "rev-list") == 1


def test_a_tree_that_never_landed_is_answered_without_an_ancestry_question(tmp_path, git_calls):
    h = _history(tmp_path, ["a\n", "b\n"])
    look = credit.landed_lookup(h["root"])
    for n in range(5):
        assert look("f" * 40, h["commits"][n % 2]) is None
    assert _ancestry(git_calls) == 0


def test_the_answer_depends_on_the_head_and_not_on_the_tree_alone(tmp_path, git_calls):
    # c0, c1 (T2), c2 (T3), c3 (T2), c4 (T4): T2 landed at c3 for every head c3 descends from.
    h = _history(tmp_path, ["zero\n", "two\n", "three\n", "two\n", "four\n"])
    c, t2 = h["commits"], h["trees"][1]
    assert h["trees"][3] == t2
    look = credit.landed_lookup(h["root"])
    heads = [c[0], c[1], c[2], c[4], None]
    expected = [c[3], c[3], c[3], None, c[3]]
    for order in (heads, list(reversed(heads))):
        for _ in range(2):
            got = [look(t2, head) if head else look(t2) for head in order]
            assert got == [expected[heads.index(head)] for head in order]


def test_a_head_that_is_not_a_full_object_id_lands_nowhere_and_reaches_no_git(tmp_path, git_calls):
    h = _history(tmp_path, ["a\n", "b\n"])
    root = h["root"]
    _check_and_reports(root, h["trees"][1], "--all", rules=2)
    proj = credit.project_credits(root)
    assert {(c.state, c.commit) for c in proj.credits} == {("witnessed", None)}
    assert not [a for a in git_calls if "--all" in a]


def test_a_no_is_asked_again_so_a_deeper_history_can_still_land_the_credit(tmp_path, git_calls, monkeypatch):
    h = _history(tmp_path, ["a\n", "b\n", "c\n"])
    root = h["root"]
    _check_and_reports(root, h["trees"][1], h["commits"][0], rules=1)
    spy, answered = gitsafe.run, []

    def first_says_no(args, cwd, *rest, **kwargs):
        if list(args[:2]) == ["merge-base", "--is-ancestor"] and not answered:
            answered.append(1)
            return subprocess.CompletedProcess(list(args), 1, b"", b"")
        return spy(args, cwd, *rest, **kwargs)

    monkeypatch.setattr(gitsafe, "run", first_says_no)
    first = credit.project_credits(root).credits[0]
    second = credit.project_credits(root).credits[0]
    assert (first.state, first.commit) == ("witnessed", None)
    assert (second.state, second.commit) == ("landed", h["commits"][1])
