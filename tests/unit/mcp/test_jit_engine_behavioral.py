"""Behavioural tests of the scan (formerly the JIT engine) through its one entry point.

Selection, ranking, budgets and rendering are observed in what aegis_core.scan.scan
returns for real rule files; no internal helper is called directly.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from aegis_core.scan import scan
from aegis_core.telemetry_engine import ledger
from aegis_core.yaml_engine.serializer import dump_frontmatter

_DIRS = {"trap": "traps", "invariant": "invariants", "gate": "gates", "boundary": "boundaries",
         "persona": "personas", "contract": "contracts"}


def _make_rule(ws: Path, rule_id: str, rule_type: str = "trap", target_paths=None,
               enforcement: str = "", expired: bool = False) -> Path:
    folder = ws / ".aegis" / "rules" / _DIRS[rule_type]
    folder.mkdir(parents=True, exist_ok=True)
    fm = {
        "id": rule_id,
        "type": rule_type,
        "enforcement": enforcement or ("gate" if rule_type in ("invariant", "gate") else "advisory"),
        "target_paths": target_paths or ["src/*.py"],
        "hypothesis": f"Hypothesis for {rule_id}",
        "prediction": f"Prediction for {rule_id}",
    }
    if expired:
        fm["expired_at"] = "2020-01-01"
    path = folder / f"{rule_id}.md"
    path.write_text(dump_frontmatter(fm, body="Guidance text\n"), encoding="utf-8")
    return path


def _names(result: dict) -> list:
    return [r["name"] for r in result["relevant_rules"]]


class TestSelection:
    def test_an_empty_workspace_returns_the_full_shape(self, tmp_path):
        (tmp_path / ".aegis" / "rules").mkdir(parents=True)
        result = scan(tmp_path, ["src/foo.py"])
        assert result["relevant_rules"] == [] and result["stats"]["total_rules"] == 0

    def test_a_matching_glob_selects_the_rule_and_a_non_matching_one_does_not(self, tmp_path):
        _make_rule(tmp_path, "match-me", target_paths=["src/*.py"])
        _make_rule(tmp_path, "docs-only", target_paths=["docs/*.md"])
        assert _names(scan(tmp_path, ["src/foo.py"])) == ["match-me"]
        assert _names(scan(tmp_path, ["lib/other.go"])) == []

    def test_a_rule_without_target_paths_matches_nothing(self, tmp_path):
        path = _make_rule(tmp_path, "no-paths")
        path.write_text("---\nid: no-paths\ntype: trap\nhypothesis: h\n---\nBody\n", encoding="utf-8")
        assert _names(scan(tmp_path, ["src/foo.py"])) == []

    def test_a_mandatory_rule_takes_a_slot_before_advisory_rules(self, tmp_path):
        _make_rule(tmp_path, "mandatory-inv", "invariant", target_paths=["src/*.py"])
        _make_rule(tmp_path, "optional-trap")
        assert _names(scan(tmp_path, ["src/foo.py"], budget=1)) == ["mandatory-inv"]

    def test_expired_rules_are_skipped(self, tmp_path):
        _make_rule(tmp_path, "expired-rule", expired=True)
        assert _names(scan(tmp_path, ["src/foo.py"])) == []

    def test_the_rule_count_budget_caps_the_rules_staged(self, tmp_path):
        for i in range(10):
            _make_rule(tmp_path, f"budget-rule-{i}")
        result = scan(tmp_path, ["src/foo.py"], budget=2)
        assert result["stats"]["budget"] == 2 and result["rules_staged"] == 2


class TestFitnessInTheResult:
    def test_every_staged_rule_carries_its_ledger_fitness(self, tmp_path):
        _make_rule(tmp_path, "inv-auth", "invariant", target_paths=["app.py"])
        _make_rule(tmp_path, "trap-style", target_paths=["app.py"])
        ledger.append(tmp_path, [{"rule": "inv-auth", "outcome": "tp", "source": "ci", "key": f"k{i}"} for i in range(30)])

        result = scan(tmp_path, ["app.py"], budget=5)

        fitness = {r["name"]: r["fitness"] for r in result["relevant_rules"]}
        assert fitness["inv-auth"] > 0.9 and fitness["trap-style"] == 0.0
        assert "Fitness: 0." in result["guidance"]


class TestRendering:
    def test_an_invariant_is_staged_with_a_pre_edit_warning(self, tmp_path):
        _make_rule(tmp_path, "invariant-zero-deps", "invariant", target_paths=["aegis_core/*.py"])

        res = scan(tmp_path, ["aegis_core/yaml.py"], budget=5)

        assert _names(res) == ["invariant-zero-deps"]
        assert "Pre-Edit Invariants & Constraints" in res["guidance"]
        assert "🧱 [INVARIANT] invariant-zero-deps" in res["guidance"]

    @pytest.mark.parametrize(
        ("rule_type", "emoji", "label"),
        [
            ("invariant", "🧱", "INVARIANT (must not violate)"),
            ("trap", "🧫", "ANTI-PATTERN TRAP (watch out)"),
            ("boundary", "🔬", "ESCALATION GATE (needs review)"),
            ("persona", "🌿", "BEST PRACTICE (follow this pattern)"),
            ("contract", "🔗", "CONTRACT (cross-service agreement)"),
            ("gate", "📋", "GATE"),
        ],
    )
    def test_each_rule_type_renders_with_its_icon_and_label(self, tmp_path, rule_type, emoji, label):
        _make_rule(tmp_path, f"rule-{rule_type}", rule_type)
        res = scan(tmp_path, ["src/foo.py"])
        assert f"{emoji} [{label}] rule-{rule_type}" in res["guidance"]
        assert res["relevant_rules"][0]["enforcement"] == label
