"""Canary test verifying workspace confinement and discovery for the supported .aegis layout."""
from pathlib import Path
from aegis_core.workspace.confinement import validate_workspace_path, confine_path_internal
from aegis_core.workspace.discovery import resolve_workspace_root
from aegis_core.workspace.base import Workspace


def test_confinement_accepts_aegis_rules(tmp_path: Path):
    """Verify validate_workspace_path accepts .aegis/rules/ workspace."""
    ws = tmp_path / "my_project_aegis"
    ws.mkdir()
    aegis_rules = ws / ".aegis" / "rules" / "invariants"
    aegis_rules.mkdir(parents=True)
    rule_file = aegis_rules / "test-rule.md"
    rule_file.write_text("---\nname: test\n---\n")

    validated = validate_workspace_path(ws)
    assert validated == ws.resolve()

    resolved_abs, rel = confine_path_internal(ws, ".aegis/rules/invariants/test-rule.md")
    assert resolved_abs == str(rule_file.resolve())


def test_workspace_discovery(tmp_path: Path):
    """Verify discovery detects .aegis as a valid workspace."""
    ws_aegis = tmp_path / "ws_aegis"
    ws_aegis.mkdir()
    (ws_aegis / ".aegis" / "rules").mkdir(parents=True)
    assert resolve_workspace_root(ws_aegis) == ws_aegis

    ws_obj = Workspace(ws_aegis)
    assert ws_obj.aegis_dir == ws_aegis / ".aegis"
    assert ws_obj.rules_dir == ws_aegis / ".aegis" / "rules"
