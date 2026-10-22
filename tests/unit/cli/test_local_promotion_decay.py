from pathlib import Path
"""Promotion candidates in the --local path come from ledger fitness.

Evidence decays only by eligible exposure sessions, never by calendar days (R-evidence-15),
consistently with the --tier-check path.
"""
import os
import sys

REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, 'enzymes'))



# ── Phase 3: C2 — Promotion Zero-Trigger Guard ───────────────────────────

class TestPromotionZeroTriggerGuard:
    """Verify untested cells cannot be promoted regardless of impact_weight."""

    def test_normalize_fitness_zero_triggers_not_promoted(self, tmp_path):
        """A cell with 0 triggers must not be promotable via lifecycle evaluation."""
        from aegis_core.lifecycle.promotion import evaluate_promotions
        from tests.helpers_rule import make_cell

        cells_dir = tmp_path / ".aegis" / "rules" / "traps"
        cells_dir.mkdir(parents=True)
        evidence_dir = tmp_path / ".aegis" / "evidence"
        evidence_dir.mkdir(parents=True)

        make_cell(str(cells_dir), "zero-cell", cell_type="trap", created_days_ago=60)
        # 0 triggers in evidence
        candidates = evaluate_promotions(str(tmp_path))
        assert not any(c["rule_id"] == "zero-cell" for c in candidates), \
            "Zero-trigger cell must not appear in promotion candidates"

    def test_normalize_fitness_high_triggers_preserves_data(self, tmp_path, monkeypatch):
        """A high-quality cell with 49 labels (48 TP, 1 FP) merged at the reviewed BASE must be
        promoted; the same counts as ledger rows alone never promote (R-evidence-4)."""
        from aegis_core.lifecycle.promotion import evaluate_promotions
        from tests import helpers_adjudication as ha
        from tests.helpers_rule import make_cell, write_evidence

        cells_dir = tmp_path / ".aegis" / "rules" / "traps"
        cells_dir.mkdir(parents=True)
        evidence_dir = tmp_path / ".aegis" / "evidence"
        evidence_dir.mkdir(parents=True)

        make_cell(str(cells_dir), "high-cell", cell_type="trap", created_days_ago=60)
        write_evidence(evidence_dir.parent.parent, "high-cell", triggers=50, tp=48, fp=1)
        assert evaluate_promotions(str(tmp_path)) == []

        ha.write_labels(tmp_path, "high-cell", ha.labels("high-cell", "tp", 48) + ha.labels("high-cell", "fp", 1))
        monkeypatch.setenv("HOME", str(tmp_path.parent / f"{tmp_path.name}-home"))
        ha.merge_to_base(tmp_path)

        candidates = evaluate_promotions(str(tmp_path))
        promoted_ids = [c["rule_id"] for c in candidates]
        assert "high-cell" in promoted_ids, \
            f"High-quality cell should be promoted, got candidates {candidates}"
