"""The pre-tag check and credit confirmation pick the same decisive CI run (v4.3 T1).

``.github/scripts/ci_green.py`` must stay a standalone standard-library file that runs before a
tag exists, so it cannot import ``aegis_core.credit``; the two selectors are tied together here
instead. Every fixture run is on ``main`` so credit's branch filter keeps them all.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from aegis_core import credit

SCRIPT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()) \
    / ".github" / "scripts" / "ci_green.py"
SHA = "4f2810174fbd6014dd5db3e7c90121e1bc514676"
REPO = "owner/project"
WORKFLOW = "validate.yml"


def _ci_green():
    spec = importlib.util.spec_from_file_location("ci_green", str(SCRIPT))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(run_id: Any, *, conclusion: Optional[str] = "success", started: str = "2026-10-16T10:00:00Z",
         attempt: int = 1, head: str = REPO, path: str = ".github/workflows/validate.yml",
         status: str = "completed") -> Dict[str, Any]:
    return {"id": run_id, "path": path, "head_sha": SHA, "head_branch": "main", "event": "push",
            "status": status, "conclusion": conclusion, "run_attempt": attempt, "run_started_at": started,
            "created_at": "2026-10-16T09:00:00Z", "repository": {"full_name": REPO},
            "head_repository": {"full_name": head}}


EARLY, LATE = "2026-10-16T10:00:00Z", "2026-10-16T12:00:00Z"
CASES = {
    "rerun": ([_run(1, conclusion="failure", started=EARLY), _run(2, attempt=2, started=LATE)], 2),
    "cancelled": ([_run(2, conclusion="cancelled", started=LATE), _run(1, conclusion="failure", started=EARLY)], 1),
    "fork": ([_run(1, started=EARLY), _run(2, conclusion="failure", started=LATE, head="attacker/project")], 1),
    "path": ([_run(1, conclusion="failure", started=EARLY), _run(2, started=LATE, path=".github/workflows/publish.yml")], 1),
    "tie": ([_run(7, conclusion="failure"), _run(9), _run(8, conclusion="failure")], 9),
    "none": ([_run(1, conclusion="cancelled"), _run(2, head="attacker/project")], None),
}


def _decisive(runs: List[Dict[str, Any]]):
    script = _ci_green()
    counted = script.counted_runs(runs, SHA, WORKFLOW)
    by_script = script.newest(counted)["id"] if counted else None
    chosen = credit.select_ci_run(runs, SHA, WORKFLOW, branch="main")
    by_credit = chosen["id"] if chosen is not None else None
    return by_script, by_credit, chosen


@pytest.mark.parametrize("runs,expected", list(CASES.values()), ids=list(CASES))
def test_both_selectors_name_the_same_decisive_run(runs, expected):
    by_script, by_credit, chosen = _decisive(runs)
    assert by_script == by_credit == expected
    if expected is None:
        assert credit.ci_conclusion(chosen) == "none"


def test_a_run_with_a_non_numeric_id_is_skipped_by_both():
    runs = [_run(1, started=EARLY), _run("x", conclusion="failure", started=LATE)]
    by_script, by_credit, _ = _decisive(runs)
    assert by_script == by_credit == 1
