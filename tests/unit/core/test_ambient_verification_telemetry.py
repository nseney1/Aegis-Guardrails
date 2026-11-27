"""Tests for ambient verification telemetry (Phase 13: v0.110.0).

Verifies that:
1. `record_verification_telemetry` writes one trigger ledger row per matched rule (a local
   run is never a verdict: R-evidence-1); whether it passed is kept in ``meta``.
2. `aegis check` automatically records those rows in .aegis/state/ledger.jsonl.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from aegis_core.yaml_engine.serializer import dump_frontmatter


def _create_rule(workspace: Path, rule_id: str, target_paths: list[str]) -> Path:
    rules_dir = workspace / ".aegis" / "rules" / "traps"
    rules_dir.mkdir(parents=True, exist_ok=True)
    rule_path = rules_dir / f"{rule_id}.md"
    fm = {
        "id": rule_id,
        "type": "trap",
        "enforcement": "advisory",
        "target_paths": target_paths,
        "hypothesis": f"Hypothesis for {rule_id}",
    }
    rule_path.write_text(dump_frontmatter(fm, body=f"# {rule_id}\n"), encoding="utf-8")
    return rule_path


@pytest.fixture
def test_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / ".aegis").mkdir()
    return ws


def test_record_verification_telemetry_appends_signals(test_workspace: Path):
    """record_verification_telemetry writes one row for each matched rule."""
    from aegis_core.outcomes.telemetry import Recorded, record_verification_telemetry
    from aegis_core.telemetry_engine import ledger

    _create_rule(test_workspace, "rule-math", ["math_*.py", "calc.py"])
    _create_rule(test_workspace, "rule-ui", ["ui_*.py"])

    # Target file matches rule-math only
    recorded = record_verification_telemetry(
        workspace=str(test_workspace),
        target_files=["math_utils.py"],
        passed=True,
        verdict="SHIP",
        source="session",
    )

    assert recorded == Recorded(1)
    rows = ledger.read(test_workspace).rows
    assert [(r["rule"], r["outcome"], r["meta"]["passed"]) for r in rows] == [("rule-math", "trigger", True)]
    assert ledger.aggregate(test_workspace, "rule-math")["triggers"] == 1
    assert ledger.aggregate(test_workspace, "rule-math")["tp"] == 0


def test_record_verification_telemetry_handles_failure(test_workspace: Path):
    """When verification fails, the row is still only a trigger: never an fp."""
    from aegis_core.outcomes.telemetry import Recorded, record_verification_telemetry
    from aegis_core.telemetry_engine import ledger

    _create_rule(test_workspace, "rule-auth", ["auth.py"])

    recorded = record_verification_telemetry(
        workspace=str(test_workspace),
        target_files=["auth.py"],
        passed=False,
        verdict="BLOCK",
        source="session",
    )

    assert recorded == Recorded(1)
    totals = ledger.aggregate(test_workspace, "rule-auth")
    assert totals["triggers"] == 1
    assert totals["fp"] == 0
    assert ledger.read(test_workspace).rows[-1]["meta"]["verdict"] == "BLOCK"


def test_cli_verify_emits_telemetry_ambiently(test_workspace: Path, monkeypatch):
    """Running aegis verify via CLI must emit ambient telemetry for verified files."""
    from aegis_cli.verify import run_verify

    _create_rule(test_workspace, "rule-core", ["core.py"])
    test_file = test_workspace / "core.py"
    test_file.write_text("x = 1\n", encoding="utf-8")

    args = argparse.Namespace(
        files=["core.py"],
        layer1_only=True,
        dry_run=False,
        repo_root=str(test_workspace),
        workspace=str(test_workspace),
        plan=None,
        plan_file=None,
        provider=None,
    )

    exit_code = run_verify(args)
    assert exit_code == 0

    from aegis_core.telemetry_engine import ledger

    assert any(r["rule"] == "rule-core" for r in ledger.read(test_workspace).rows)
