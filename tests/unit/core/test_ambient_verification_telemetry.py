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


def _create_cell(workspace: Path, cell_id: str, target_paths: list[str]) -> Path:
    cells_dir = workspace / ".aegis" / "rules" / "traps"
    cells_dir.mkdir(parents=True, exist_ok=True)
    cell_path = cells_dir / f"{cell_id}.md"
    fm = {
        "id": cell_id,
        "type": "trap",
        "enforcement": "advisory",
        "target_paths": target_paths,
        "hypothesis": f"Hypothesis for {cell_id}",
    }
    cell_path.write_text(dump_frontmatter(fm, body=f"# {cell_id}\n"), encoding="utf-8")
    return cell_path


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

    _create_cell(test_workspace, "cell-math", ["math_*.py", "calc.py"])
    _create_cell(test_workspace, "cell-ui", ["ui_*.py"])

    # Target file matches cell-math only
    recorded = record_verification_telemetry(
        workspace=str(test_workspace),
        target_files=["math_utils.py"],
        passed=True,
        verdict="SHIP",
        source="session",
    )

    assert recorded == Recorded(1)
    rows = ledger.read(test_workspace).rows
    assert [(r["rule"], r["outcome"], r["meta"]["passed"]) for r in rows] == [("cell-math", "trigger", True)]
    assert ledger.aggregate(test_workspace, "cell-math")["triggers"] == 1
    assert ledger.aggregate(test_workspace, "cell-math")["tp"] == 0


def test_record_verification_telemetry_handles_failure(test_workspace: Path):
    """When verification fails, the row is still only a trigger: never an fp."""
    from aegis_core.outcomes.telemetry import Recorded, record_verification_telemetry
    from aegis_core.telemetry_engine import ledger

    _create_cell(test_workspace, "cell-auth", ["auth.py"])

    recorded = record_verification_telemetry(
        workspace=str(test_workspace),
        target_files=["auth.py"],
        passed=False,
        verdict="BLOCK",
        source="session",
    )

    assert recorded == Recorded(1)
    totals = ledger.aggregate(test_workspace, "cell-auth")
    assert totals["triggers"] == 1
    assert totals["fp"] == 0
    assert ledger.read(test_workspace).rows[-1]["meta"]["verdict"] == "BLOCK"


def test_cli_verify_emits_telemetry_ambiently(test_workspace: Path, monkeypatch):
    """Running soma verify via CLI must emit ambient telemetry for verified files."""
    from aegis_cli.verify import run_verify

    _create_cell(test_workspace, "cell-core", ["core.py"])
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

    assert any(r["rule"] == "cell-core" for r in ledger.read(test_workspace).rows)
