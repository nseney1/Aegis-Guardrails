"""Unit tests for `aegis sync --pr` and `format_pr_body` (v4.3 §3 T4)."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from aegis_cli.sync import EXIT_OK, EXIT_PROBLEMS, SyncCommand, run_sync
from aegis_core.sync import format_pr_body
from tests import helpers_adjudication as ha


def _write_rule(ws: Path, rule_type: str, rule_id: str) -> Path:
    folder = {"trap": "traps", "invariant": "invariants", "gate": "gates"}[rule_type]
    path = ws / ".aegis" / "rules" / folder / f"{rule_id}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    enforcement = "gate" if rule_type in ("gate", "invariant") else "advisory"
    text = (
        f"---\n"
        f"id: {rule_id}\n"
        f"type: {rule_type}\n"
        f"enforcement: {enforcement}\n"
        f"hypothesis: hypothesis for {rule_id}\n"
        f"created: '2026-01-01'\n"
        f"target_paths:\n"
        f"  - 'src/*.py'\n"
        f"---\n"
        f"# {rule_id}\n\nRule body for {rule_id}.\n"
    )
    path.write_text(text, encoding="utf-8")
    return path


def _seed_decided_promotion(ws: Path, rule_id: str) -> None:
    """25 tp labels merged at the reviewed base: the only labels that count (R-evidence-3)."""
    ha.write_labels(ws, rule_id, [
        {"example_id": f"PR-{i + 1}", "verdict": "tp", "ref": f"PR-{i + 1}", "session": f"sess-{(i % 3) + 1}",
         "repo": f"repo-{(i % 2) + 1}", "file": "src/app.py", "line": i + 1, "summary": f"Caught issue #{i + 1}"}
        for i in range(25)
    ])
    ha.merge_to_base(ws)


def test_sync_command_parser_registers_pr_flag() -> None:
    cmd = SyncCommand()
    parser = argparse.ArgumentParser()
    cmd.configure_parser(parser)
    parsed = parser.parse_args(["--pr"])
    assert parsed.pr is True
    assert parsed.apply is False


def test_format_pr_body_includes_up_to_three_samples_and_prior_disclosure() -> None:
    pre_rules = {
        "r-promote": {
            "tp": 25,
            "fp": 0,
            "precision_lo": 0.89,
            "precision_hi": 1.00,
            "fitness": 0.91,
            "sessions_count": 4,
            "repos_count": 2,
            "contested": 1,
            "override_rate": 1 / 26,
            "prior_disclosure": "prior supplies 28% of the evidence",
            "samples": [
                {"ref": "PR-1", "file": "src/a.py", "line": 10, "summary": "Sample one"},
                {"ref": "PR-2", "file": "src/b.py", "line": 20, "summary": "Sample two"},
                {"ref": "PR-3", "file": "src/c.py", "line": 30, "summary": "Sample three"},
                {"ref": "PR-4", "file": "src/d.py", "line": 40, "summary": "Sample four ignored"},
            ],
        }
    }
    applied = [
        {"rule": "r-promote", "action": "promote", "from_type": "trap", "to_type": "invariant"}
    ]
    body = format_pr_body(pre_rules, applied)
    assert "### `r-promote` — **promote** (`trap` -> `invariant`)" in body
    assert "prior supplies 28% of the evidence" in body
    assert "1. [PR-1] (`src/a.py:10`): Sample one" in body
    assert "2. [PR-2] (`src/b.py:20`): Sample two" in body
    assert "3. [PR-3] (`src/c.py:30`): Sample three" in body
    assert "Sample four ignored" not in body


def test_sync_pr_no_transitions_does_not_invoke_gh(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_rule(tmp_path, "trap", "r-quiet")
    gh_calls: list[list[str]] = []

    def fake_gh(argv: list[str], cwd: str | None = None) -> object:
        gh_calls.append(list(argv))
        raise AssertionError("gh should not be called when there are no transitions")

    rc = run_sync(argparse.Namespace(_root=tmp_path, pr=True, json=True), gh_runner=fake_gh)
    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["pr"]["status"] == "no_transitions"
    assert gh_calls == []


def test_sync_pr_gh_failure_returns_exit_problems_and_never_calls_merge(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_rule(tmp_path, "trap", "r-promote")
    _seed_decided_promotion(tmp_path, "r-promote")
    gh_calls: list[list[str]] = []

    def failing_gh(argv: list[str], cwd: str | None = None) -> object:
        gh_calls.append(list(argv))

        class _Res:
            returncode = 1
            stdout = ""
            stderr = "gh: not authenticated"

        return _Res()

    rc = run_sync(argparse.Namespace(_root=tmp_path, pr=True, json=False), gh_runner=failing_gh)
    assert rc == EXIT_PROBLEMS
    out = capsys.readouterr().out
    assert "PR creation failed: gh: not authenticated" in out
    assert len(gh_calls) == 1
    assert gh_calls[0][:2] == ["pr", "create"]
    assert not any("merge" in call for call in gh_calls)
