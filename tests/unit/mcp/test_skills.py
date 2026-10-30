"""The shipped skills and the ${SLOT.*} registry used by aegis_scan.

The Layer-1 runner maps aegis_core/skills/* to this file. The v4 skill graph and its
typed handoffs were removed, so a skill is a SKILL.md with ``kind: skill``; nothing
reads the graph's frontmatter (tier, consumes, produces, handoff_targets).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from aegis_core.skills.slots import SlotRegistry, SlotResolutionError
from aegis_core.yaml_engine.frontmatter import AegisYAML

SKILLS_ROOT = Path(__file__).resolve().parents[3] / "skills"
REMOVED_GRAPH_KEYS = ("tier", "consumes", "produces", "handoff_targets")


def _shipped_skills():
    return sorted(SKILLS_ROOT.glob("*/SKILL.md"))


def test_fifteen_skills_ship():
    # The CI wheel smoke counts them too (.github/scripts/wheel_smoke.py).
    assert len(_shipped_skills()) == 15


@pytest.mark.parametrize("path", _shipped_skills(), ids=lambda p: p.parent.name)
def test_each_shipped_skill_is_kind_skill_without_the_removed_graph_keys(path: Path):
    doc = AegisYAML.parse_text(path.read_text(encoding="utf-8"))
    assert doc.kind == "skill"
    assert doc.id == path.parent.name
    assert doc.get("name") and doc.get("description")
    assert [k for k in REMOVED_GRAPH_KEYS if k in doc] == []


class TestSlotRegistry:
    """Test fail-closed slot resolution."""

    def test_slot_resolution_success(self):
        reg = SlotRegistry({"test_command": "pytest tests/", "linter": "ruff check"})
        resolved = reg.resolve("Run: ${SLOT.test_command} && ${SLOT.linter}")
        assert resolved == "Run: pytest tests/ && ruff check"

    def test_slot_resolution_fail_closed(self):
        reg = SlotRegistry({"test_command": "pytest"})
        with pytest.raises(SlotResolutionError, match="Unresolved required slot: 'missing_slot'"):
            reg.resolve("Run: ${SLOT.missing_slot}", strict=True)

    def test_slot_loading_from_user_config(self, tmp_path: Path, monkeypatch):
        home = tmp_path / "home"
        (home / ".aegis").mkdir(parents=True)
        (home / ".aegis" / "config.json").write_text(
            '{"v": 1, "slots": {"test_command": "cargo test", "build_command": "cargo build"}}',
            encoding="utf-8",
        )
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        reg = SlotRegistry.load_user(tmp_path / "ws")
        assert reg.get("test_command") == "cargo test"
        assert reg.get("build_command") == "cargo build"
        assert reg.get("missing") is None


class TestSlotRegistryBranches:

    def test_slot_registry_branches(self, tmp_path: Path):
        # Nonexistent file returns empty
        reg = SlotRegistry.load(tmp_path)
        assert reg.to_dict() == {}

        # Invalid JSON raises SlotResolutionError
        aegis_dir = tmp_path / ".aegis"
        aegis_dir.mkdir(parents=True, exist_ok=True)
        (aegis_dir / "config.json").write_text('{"a": [unclosed', encoding="utf-8")
        with pytest.raises(SlotResolutionError, match="not valid JSON"):
            SlotRegistry.load(tmp_path)

        # packaged_drivers not a list: ignored with a warning
        (aegis_dir / "config.json").write_text('{"ast": {"packaged_drivers": "rs"}}', encoding="utf-8")
        loaded = SlotRegistry.load(tmp_path)
        assert loaded.to_dict() == {}
        assert loaded.warnings

        # resolve with strict=False returns token
        reg2 = SlotRegistry({"existing": "val"})
        assert reg2.resolve("Hello ${existing} and ${missing}", strict=False) == "Hello val and ${missing}"
        assert reg2.to_dict() == {"existing": "val"}

        # resolve default strict=True raises SlotResolutionError when slot is missing
        with pytest.raises(SlotResolutionError, match="Unresolved required slot: 'missing'"):
            reg2.resolve("Hello ${missing}")

    def test_get_ast_driver_branch_coverage_and_mutant_kills(self):
        from aegis_core.skills.slots import SlotRegistry
        reg = SlotRegistry({
            "ast_driver_external": "external-parser driver",
            "ast_driver": "default-runner",
        })
        # .py returns None
        assert reg.get_ast_driver("py") is None
        assert reg.get_ast_driver(".py") is None
        assert reg.get_ast_driver("PY") is None

        # specific extension
        assert reg.get_ast_driver("external") == "external-parser driver"
        assert reg.get_ast_driver(".external") == "external-parser driver"
        assert reg.get_ast_driver(".ts") is None

        # fallback to default ast_driver
        assert reg.get_ast_driver("go") == "default-runner"
        assert reg.get_ast_driver(".go") == "default-runner"

        # empty registry
        empty_reg = SlotRegistry()
        assert empty_reg.get_ast_driver("ts") is None
        assert empty_reg.get_ast_driver("py") is None
