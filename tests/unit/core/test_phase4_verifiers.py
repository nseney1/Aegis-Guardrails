"""Unit and behavioral tests for pure-Python migrated verifiers in Phase 4."""
from __future__ import annotations

from pathlib import Path

from conftest import REPO_ROOT

VERIFIERS_DIR = Path(REPO_ROOT) / "verifiers"


def test_rule_selection_evaluation(tmp_path):
    """Selection archives a trap the ledger says misfires; its frontmatter counters are ignored."""
    from aegis_core.lifecycle.selection import run_rule_selection
    from aegis_core.telemetry_engine import ledger

    rules_dir = tmp_path / ".aegis" / "rules"
    traps_dir = rules_dir / "traps"
    archive_dir = rules_dir / ".archive"
    traps_dir.mkdir(parents=True)

    rule_content = """---
id: test-rule
type: trap
fitness:
  score: 0.95
  triggers: 10
  true_positives: 10
---
Test body
"""
    (traps_dir / "test-rule.md").write_text(rule_content, encoding="utf-8")
    # MIN_N (25) false positives: the one sample gate before any archive (R-evidence-8).
    ledger.append(tmp_path, [{"rule": "test-rule", "outcome": "fp", "source": "ci", "key": f"k{n}"} for n in range(25)])

    # Run check mode (dry run)
    (row,) = run_rule_selection(workspace=tmp_path, execute=False)["candidates"]
    assert (row["rule_id"], row["archive"]) == ("test-rule", None)
    assert (traps_dir / "test-rule.md").exists()

    # Run execute mode
    (row,) = run_rule_selection(workspace=tmp_path, execute=True)["candidates"]
    assert row["archive"]["status"] == "archived"
    assert not (traps_dir / "test-rule.md").exists()
    assert (archive_dir / "test-rule.md").read_text(encoding="utf-8") == rule_content
