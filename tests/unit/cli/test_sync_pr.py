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


def test_format_pr_body_states_the_evidence_and_lists_the_examples_to_label() -> None:
    pre_rules = {
        "r-promote": {
            "state": "decided", "status": None, "n": 25, "effective_weight": 0.5, "reported_score": 0.81,
            "p_below_demote": 0.01, "precision_lo": 0.89, "precision_hi": 1.00, "sessions_count": 4,
            "repos_count": 2, "contested": 1, "override_rate": 1 / 26, "caught": 3, "leaked": 1,
            "prior_disclosure": "prior supplies 28% of the evidence",
        },
        "r-young": {"state": "insufficient", "status": "insufficient (n=4)", "n": 4, "effective_weight": 1.0,
                    "reported_score": None, "precision_lo": 0.4, "precision_hi": 1.0},
    }
    applied = [
        {"rule": "r-promote", "action": "promote", "from_type": "trap", "to_type": "invariant"},
        {"rule": "r-young", "action": "archive"},
    ]
    examples = {"r-promote": [{"example_id": "abc123def456", "verdict": None, "file": "src/a.py",
                               "pattern": "eval", "rev": "f" * 40}]}
    body = format_pr_body(pre_rules, applied, base="b" * 40, examples=examples)
    promote, young = body.split("### `r-young`")
    assert "### `r-promote` — **promote** (`trap` -> `invariant`)" in promote
    assert "- **State**: decided; n = 25; weight 0.50" in promote and "- **Score**: 0.81" in promote
    assert "P(precision < 0.7)**: 0.01; precision 90% interval [0.89, 1.00]" in promote
    assert "prior supplies 28% of the evidence" in promote and "0.75 (3 caught, 1 leaked)" in promote
    assert f"`{'b' * 40}`" in promote and "1. `abc123def456`: `eval` in `src/a.py`" in promote
    assert "insufficient (n=4); n = 4" in young and "Score**" not in young and "interval" not in young
    assert "no replay examples" in young and "Compliance** caught / (caught + leaked): n/a" in young
    assert format_pr_body(pre_rules, applied[1:]).count("no BASE") == 1


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


def test_sync_pr_without_a_remote_is_refused_and_never_calls_gh(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_rule(tmp_path, "trap", "r-promote")
    _seed_decided_promotion(tmp_path, "r-promote")  # a reviewed base, but no remote to push a branch to
    gh_calls: list[list[str]] = []

    def gh(argv: list[str], cwd: str | None = None) -> object:
        gh_calls.append(list(argv))
        raise AssertionError("gh must not be called when the PR is refused")

    rule = tmp_path / ".aegis" / "rules" / "traps" / "r-promote.md"
    before = rule.read_bytes()
    rc = run_sync(argparse.Namespace(_root=tmp_path, pr=True, json=False), gh_runner=gh)
    assert rc == EXIT_PROBLEMS
    out = capsys.readouterr().out
    assert "no pull request opened: no usable remote named 'origin'" in out
    assert gh_calls == [] and rule.read_bytes() == before
