"""Unit and behavioral tests for pure-Python migrated enzymes in Phase 4."""
from __future__ import annotations

from pathlib import Path

from conftest import REPO_ROOT

ENZYMES_DIR = Path(REPO_ROOT) / "enzymes"


def test_cell_selection_evaluation(tmp_path):
    """Selection archives a trap the ledger says misfires; its frontmatter counters are ignored."""
    from aegis_core.lifecycle.selection import run_rule_selection
    from aegis_core.telemetry_engine import ledger

    cells_dir = tmp_path / ".aegis" / "rules"
    traps_dir = cells_dir / "traps"
    archive_dir = cells_dir / ".archive"
    traps_dir.mkdir(parents=True)

    cell_content = """---
id: test-cell
type: trap
fitness:
  score: 0.95
  triggers: 10
  true_positives: 10
---
Test body
"""
    (traps_dir / "test-cell.md").write_text(cell_content, encoding="utf-8")
    # MIN_N (25) false positives: the one sample gate before any archive (R-evidence-8).
    ledger.append(tmp_path, [{"rule": "test-cell", "outcome": "fp", "source": "ci", "key": f"k{n}"} for n in range(25)])

    # Run check mode (dry run)
    (row,) = run_rule_selection(workspace=tmp_path, execute=False)["candidates"]
    assert (row["rule_id"], row["archive"]) == ("test-cell", None)
    assert (traps_dir / "test-cell.md").exists()

    # Run execute mode
    (row,) = run_rule_selection(workspace=tmp_path, execute=True)["candidates"]
    assert row["archive"]["status"] == "archived"
    assert not (traps_dir / "test-cell.md").exists()
    assert (archive_dir / "test-cell.md").read_text(encoding="utf-8") == cell_content
