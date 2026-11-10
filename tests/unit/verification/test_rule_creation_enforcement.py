"""Tests for rule creation schema enforcement (BUG-083).

Ensures that rules generated via create_rule include the required 'enforcement'
frontmatter field, so they pass the checkpoint's rule_conventions and rule_load checks.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from aegis_core.yaml_engine.frontmatter import parse_frontmatter
from aegis_core.lifecycle.creation import create_rule


class TestRuleCreationEnforcement:
    """Tests for enforcement frontmatter in create_rule."""

    def test_create_trap_defaults_to_advisory_enforcement(self, tmp_path: Path):
        """create_rule for trap defaults to enforcement: advisory."""
        rule_path = create_rule(
            rule_type="trap",
            hypothesis="When coordinates invert, render pipelines fail silently",
            workspace=tmp_path,
        )
        assert rule_path.is_file()
        content = rule_path.read_text(encoding="utf-8")
        meta = parse_frontmatter(content)
        assert meta is not None
        assert meta.get("enforcement") == "advisory"
        assert meta.get("type") == "trap"

    def test_create_invariant_defaults_to_gate_enforcement(self, tmp_path: Path):
        """create_rule for invariant defaults to enforcement: gate."""
        rule_path = create_rule(
            rule_type="invariant",
            hypothesis="Direct network calls outside sandbox are forbidden",
            workspace=tmp_path,
        )
        assert rule_path.is_file()
        content = rule_path.read_text(encoding="utf-8")
        meta = parse_frontmatter(content)
        assert meta is not None
        assert meta.get("enforcement") == "gate"
        assert meta.get("type") == "invariant"

    def test_create_rule_honors_explicit_enforcement(self, tmp_path: Path):
        """Explicit enforcement argument is honored."""
        rule_path = create_rule(
            rule_type="trap",
            hypothesis="Custom enforced trap",
            enforcement="gate",
            workspace=tmp_path,
        )
        content = rule_path.read_text(encoding="utf-8")
        meta = parse_frontmatter(content)
        assert meta is not None
        assert meta.get("enforcement") == "gate"

    def test_invalid_enforcement_raises_value_error(self, tmp_path: Path):
        """Invalid enforcement tier raises ValueError."""
        with pytest.raises(ValueError, match="Invalid enforcement"):
            create_rule(
                rule_type="trap",
                hypothesis="Should fail on invalid enforcement",
                enforcement="strictly_forbidden",
                workspace=tmp_path,
            )

    def test_generated_rules_pass_checkpoint_rule_conventions(self, tmp_path: Path):
        """Rules created via create_rule load and pass the checkpoint rule_conventions checks."""
        from aegis_core.verification.checkpoint_checks import check_rule_conventions

        # Create one trap and one invariant
        create_rule(
            rule_type="trap",
            hypothesis="Coordinate inversion trap",
            id_override="trap-coord-inv",
            workspace=tmp_path,
        )
        create_rule(
            rule_type="invariant",
            hypothesis="Network sandbox invariant",
            id_override="invariant-network-sandbox",
            workspace=tmp_path,
        )

        issues = check_rule_conventions(tmp_path)
        assert issues == []
