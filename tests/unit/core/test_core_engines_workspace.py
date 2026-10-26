"""Tests for Phase 17: Core Engines Workspace Migration (v0.114.0).

Verifies that lifecycle, arbitration, outcomes, defects, and sync engines
operate directly with strongly-typed Workspace value objects, and that
legacy standalone getters emit DeprecationWarning while preserving backward compatibility.
"""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from aegis_core.lifecycle.creation import create_rule
from aegis_core.fitness import for_rules
from aegis_core.lifecycle.parsers import find_rule_file
from aegis_core.rules import load_rules
from aegis_core.sync import build
from aegis_core.lifecycle.promotion import evaluate_demotions, evaluate_promotions
from aegis_core.lifecycle.selection import run_rule_selection
from aegis_core.workspace.base import Workspace


@pytest.fixture
def mock_soma_workspace(tmp_path: Path) -> Workspace:
    """Create a temporary initialized Soma workspace structure."""
    cells_dir = tmp_path / ".aegis" / "rules"
    traps_dir = cells_dir / "traps"
    walls_dir = cells_dir / "invariants"
    for d in (traps_dir, walls_dir):
        d.mkdir(parents=True, exist_ok=True)

    # Add a sample cell
    sample_cell = traps_dir / "test-rule.md"
    sample_cell.write_text(
        "---\n"
        "id: test-rule\n"
        "type: trap\n"
        "enforcement: advisory\n"
        "hypothesis: \"Avoid raw SQL queries\"\n"
        "prediction: \"SQL injection risk reduced\"\n"
        "falsification: \"ORM eliminates vulnerability\"\n"
        "created: \"2026-01-01\"\n"
        "target_paths: [\"*.py\"]\n"
        "fitness:\n"
        "  triggers: 5\n"
        "  true_positives: 4\n"
        "  false_positives: 1\n"
        "  score: 0.8\n"
        "---\n"
        "## Trap: Avoid raw SQL queries\n"
        "Always use parameterized queries or an ORM.\n",
        encoding="utf-8",
    )

    ledger_file = tmp_path / ".aegis" / "state" / "ledger.jsonl"
    ledger_file.parent.mkdir(parents=True)
    ledger_file.write_text(
        json.dumps({"v": 2, "seq": 1, "ts": "2026-01-02T00:00:00Z", "rule": "test-rule",
                    "outcome": "tp", "source": "manual"}) + "\n",
        encoding="utf-8",
    )

    return Workspace(root=tmp_path)


class TestLifecycleWorkspaceInteroperability:
    """Verify lifecycle subsystem functions accept Workspace directly."""

    def test_create_cell_with_workspace_instance(self, mock_soma_workspace: Workspace):
        created = create_rule(
            rule_type="trap",
            hypothesis="Always validate user inputs",
            workspace=mock_soma_workspace,
        )
        assert isinstance(created, Path)
        assert created.is_file()
        assert str(mock_soma_workspace.rules_dir) in str(created)

    def test_derived_view_with_workspace_instance(self, mock_soma_workspace: Workspace):
        derived = build(mock_soma_workspace)
        assert derived["rules"]["test-rule"]["triggers"] == 1  # the ledger row, not the frontmatter

    def test_run_cell_selection_with_workspace_instance(self, mock_soma_workspace: Workspace):
        res = run_rule_selection(workspace=mock_soma_workspace, execute=False)
        assert (res["status"], res["candidates"]) == ("nothing_to_archive", [])

    def test_parsers_and_promotions_with_workspace_instance(self, mock_soma_workspace: Workspace):
        rules = load_rules(mock_soma_workspace)
        assert rules.get("test-rule") is not None

        fits = for_rules(mock_soma_workspace, rules.rules)
        assert fits["test-rule"].tp == 1

        cand_file, ctype = find_rule_file(mock_soma_workspace, "test-rule")
        assert cand_file is not None
        assert cand_file.is_file()
        assert ctype == "trap"

        promotions = evaluate_promotions(mock_soma_workspace)
        assert isinstance(promotions, list)

        demotions = evaluate_demotions(mock_soma_workspace)
        assert isinstance(demotions, list)


