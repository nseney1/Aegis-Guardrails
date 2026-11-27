"""Tests for Phase 16: Perimeter & Edge Workspace Adoption.

Verifies that:
1. aegis_sdk.Governance initializes with and exposes Workspace instances.
2. aegis_mcp tools operate with strongly-typed Workspace instances.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_core.workspace.base import Workspace
from aegis_mcp.tools import execute_tool
from aegis_sdk import Governance


@pytest.fixture
def mock_aegis_workspace(tmp_path: Path) -> Path:
    """Create a minimal valid Aegis workspace directory structure."""
    rules_dir = tmp_path / ".aegis" / "rules" / "invariants"
    rules_dir.mkdir(parents=True)
    sample_rule = rules_dir / "sample_rule.md"
    sample_rule.write_text(
        "---\nname: sample-rule\ntype: invariant\nenforcement: gate\n---\nRule content\n",
        encoding="utf-8",
    )
    tracked_file = tmp_path / "hello.py"
    tracked_file.write_text("print('hello')\n", encoding="utf-8")
    return tmp_path


class TestGovernanceWorkspacePorcelain:
    """Verifies aegis_sdk.Governance integration with Workspace."""

    def test_governance_init_with_path_creates_workspace(self, mock_aegis_workspace: Path):
        gov = Governance(project_root=mock_aegis_workspace)
        assert hasattr(gov, "workspace")
        assert isinstance(gov.workspace, Workspace)
        assert gov.workspace.root == mock_aegis_workspace.resolve()
        assert gov.root == mock_aegis_workspace.resolve()
        assert gov.rules_dir == mock_aegis_workspace.resolve() / ".aegis" / "rules"

    def test_governance_init_with_workspace_object(self, mock_aegis_workspace: Path):
        ws = Workspace.confine(mock_aegis_workspace)
        gov = Governance(project_root=ws)
        assert gov.workspace is ws
        assert gov.root == ws.root
        assert gov.rules_dir == ws.rules_dir

    def test_governance_list_rules_with_workspace(self, mock_aegis_workspace: Path):
        ws = Workspace.confine(mock_aegis_workspace)
        gov = Governance(project_root=ws)
        rules = gov.list_rules()
        assert len(rules) == 1
        assert rules[0]["_name"] == "sample_rule"


class TestMCPToolsWorkspace:
    """Verifies MCP tool handlers with Workspace."""

    def test_mcp_execute_tool_with_workspace_object(self, mock_aegis_workspace: Path):
        ws = Workspace.confine(mock_aegis_workspace)
        result = execute_tool("aegis_list_rules", {"workspace": ws})
        data = json.loads(result) if isinstance(result, str) else result
        assert [(r["_name"], r["name"]) for r in data["rules"]] == [("sample_rule", "sample-rule")]
