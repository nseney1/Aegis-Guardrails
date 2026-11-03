"""Fixtures for the verified-checks tests: real git repositories, a stub test command, a fake CI.

Nothing here reaches the network, a model or the developer's own files: the repository and the
user-scope config live in a temporary directory, and ``FakeCI`` stands in for GitHub at the
client boundary (``aegis_core.credit`` takes the client as an argument).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List, Optional
import xml.etree.ElementTree as ET

from tests import helpers_humangate as hg

APP = "def app():\n    return 1\n"

def _runner_script(passed: int, failed: int, code: int, summary: str) -> str:
    """A synthetic command boundary with explicit case-level results, never log-only evidence."""
    suite = ET.Element("testsuite", name="stub", tests=str(passed + failed), failures=str(failed),
                       errors="0", skipped="0")
    for index in range(passed + failed):
        case = ET.SubElement(suite, "testcase", classname="stub", name=f"test_{index}")
        if index >= passed:
            ET.SubElement(case, "failure", message="stub failure")
    report = ET.tostring(suite, encoding="unicode")
    return ("import sys\nfrom pathlib import Path\n"
            f"Path(sys.argv[1]).write_text({report!r}, encoding='utf-8')\n"
            f"print({summary!r})\nsys.exit({code})\n")


PASSING = _runner_script(3, 0, 0, "3 passed in 0.01s")
FAILING = _runner_script(2, 1, 1, "2 passed, 1 failed in 0.01s")
NO_TESTS = _runner_script(0, 0, 5, "no tests ran in 0.01s")
ZERO_PASSED = _runner_script(0, 0, 0, "0 passed in 0.01s")
PYTEST_INI = "[pytest]\npythonpath = .\n"
REAL_TEST = "from src.app import app\n\n\ndef test_app():\n    assert app() == 1\n\n\ndef test_other():\n    assert True\n"
CI_WORKFLOW = "validate.yml"


def hermetic_pytest_ok() -> bool:
    """True when the interpreter finds pytest without the user site (the hermetic run passes ``-s``)."""
    probe = subprocess.run([sys.executable, "-s", "-c", "import pytest"], capture_output=True)
    return probe.returncode == 0


def make_project(tmp_path: Path, name: str = "project", runner: Optional[str] = PASSING,
                 real_tests: bool = False) -> hg.Repo:
    """``main`` holds a rule, a source file and a test runner; ``work`` is checked out, clean."""
    home = hg.Home(tmp_path / "home")
    repo = hg.Repo(tmp_path / name, home)
    repo.write("README.md", "# project\n")
    repo.write("src/app.py", APP)
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE)
    repo.write(".gitignore", ".aegis/state/\n")
    if runner is not None:
        repo.write("run_checks.py", runner)
    if real_tests:
        repo.write("pytest.ini", PYTEST_INI)
        repo.write("tests/test_app.py", REAL_TEST)
    repo.commit("base")
    repo.branch("work")
    return repo


def write_user_config(home: Path, **config: Any) -> Path:
    """``~/.aegis/config.json`` of the throwaway HOME."""
    path = home / ".aegis" / "config.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"v": 1, **config}), encoding="utf-8")
    return path


def use_stub_runner(home: Path, script: str = "run_checks.py") -> None:
    write_user_config(home, tests={"command": ["python", script, "{junit}"]})


def ledger_rows(root: Path) -> List[Dict[str, Any]]:
    from aegis_core.storage import read_jsonl
    from aegis_core.telemetry_engine import ledger

    return list(read_jsonl(ledger.ledger_path(root)).rows)


def rows_of(root: Path, event: str) -> List[Dict[str, Any]]:
    return [r for r in ledger_rows(root) if r.get("event") == event]


def ci_run(commit: str, conclusion: Optional[str] = "success", *, status: str = "completed",
           workflow: str = CI_WORKFLOW, event: str = "push", attempt: int = 1, run_id: int = 1,
           same_repo: bool = True, created: str = "2026-10-17T10:00:00Z",
           head_branch: Optional[str] = "main", run_started_at: Optional[str] = None) -> Dict[str, Any]:
    """One workflow run as GitHub's REST API lists it."""
    run: Dict[str, Any] = {
        "id": run_id, "run_attempt": attempt, "head_sha": commit, "event": event, "status": status,
        "conclusion": conclusion, "path": f".github/workflows/{workflow}", "created_at": created,
        "head_branch": head_branch,
        "repository": {"full_name": "octo/proj"},
        "head_repository": {"full_name": "octo/proj" if same_repo else "fork/proj"},
    }
    if run_started_at is not None:
        run["run_started_at"] = run_started_at
    return run


class FakeCI:
    """The CI client boundary: lists the workflow runs of a commit and records every ask."""

    def __init__(self, runs: Optional[List[Dict[str, Any]]] = None, error: Optional[str] = None) -> None:
        self.runs = list(runs or [])
        self.error = error
        self.asked: List[str] = []

    def runs_for(self, commit: str) -> List[Dict[str, Any]]:
        self.asked.append(commit)
        if self.error:
            from aegis_core import credit

            raise credit.CIUnavailable(self.error)
        return [r for r in self.runs if r.get("head_sha") == commit]


def workspace_of(root: Path):
    from aegis_core.workspace.base import Workspace

    return Workspace.confine(str(root))


def mcp_call(tool: str, root: Path, session: str = "sess-1", host: str = "claude-code", **arguments: Any) -> Any:
    from aegis_mcp.tools import execute_tool

    args = dict(arguments, workspace=workspace_of(root), _host=host, _session=session)
    return execute_tool(tool, args)


def tree_now(root: Path) -> str:
    """The tree the work tree would commit (what ``git add -A`` then ``write-tree`` gives)."""
    env = dict(os.environ)
    env["GIT_INDEX_FILE"] = str(root / ".git" / "test-index")
    try:
        subprocess.run(["git", "read-tree", "HEAD"], cwd=str(root), env=env, check=True, capture_output=True)
        subprocess.run(["git", "add", "-A"], cwd=str(root), env=env, check=True, capture_output=True)
        return subprocess.run(["git", "write-tree"], cwd=str(root), env=env, check=True, capture_output=True,
                              text=True).stdout.strip()
    finally:
        try:
            os.unlink(root / ".git" / "test-index")
        except OSError:
            pass


def ledger_path(root: Path) -> Path:
    from aegis_core.telemetry_engine import ledger

    return Path(ledger.ledger_path(root))
