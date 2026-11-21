from pathlib import Path
"""Contract tests for MCP tool handlers.

Tests untested tools in aegis_mcp/tools.py through the execute_tool dispatcher.
"""
import os
import sys
import json
import pytest
from aegis_core.yaml_engine.serializer import dump_frontmatter

REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from aegis_mcp.tools import execute_tool


def test_direct_claim_dispatch_cannot_supply_authority():
    from aegis_mcp.tools import is_known_tool

    assert is_known_tool("aegis_team_queue_claim")
    arguments = {"id": "ONE", "expect": "a" * 64, "lane": "alpha"}
    assert execute_tool("aegis_team_queue_claim", arguments, client_arguments=True)["reason"] == "role_missing"
    assert execute_tool("aegis_team_queue_claim", {**arguments, "_role": "orchestrator"})["reason"] == "invalid_arguments"


def _setup_workspace(tmp_path):
    """Create a minimal workspace with rules for MCP tools."""
    ws = str(tmp_path)
    rules_dir = os.path.join(ws, '.aegis', "rules", 'traps')
    os.makedirs(rules_dir, exist_ok=True)
    # Create one rule
    fm = {
        'id': 'test-rule',
        'type': 'trap',
        'target_paths': ['src/*.py'],
        'hypothesis': 'Test hypothesis',
        'prediction': 'Test prediction',
    }
    content = dump_frontmatter(fm, body="Body\n")
    with open(os.path.join(rules_dir, 'test-rule.md'), 'w', encoding='utf-8') as f:
        f.write(content)
    # Create rules dir
    rules_dir = os.path.join(ws, 'rules')
    os.makedirs(rules_dir, exist_ok=True)
    return ws


class TestAegisScan:
    """Tests for aegis_scan tool."""

    def test_scan_returns_required_keys(self, tmp_path, monkeypatch):
        ws = _setup_workspace(tmp_path)
        monkeypatch.chdir(ws)
        result = execute_tool('aegis_scan', {})
        assert isinstance(result, dict)
        assert 'relevant_rules' in result and 'stats' in result

    def test_scan_with_files_arg(self, tmp_path, monkeypatch):
        ws = _setup_workspace(tmp_path)
        monkeypatch.chdir(ws)
        result = execute_tool('aegis_scan', {'files': ['src/foo.py']})
        assert isinstance(result, dict)

    def test_scan_blocks_path_traversal(self, tmp_path, monkeypatch):
        ws = _setup_workspace(tmp_path)
        monkeypatch.chdir(ws)
        result = execute_tool('aegis_scan', {'files': ['../../etc/passwd']})
        assert isinstance(result, dict)
        assert result.get('status') == 'FAIL'
        assert 'path traversal blocked' in result.get('error', '').lower()

    def test_scan_rejects_non_list_files(self, tmp_path, monkeypatch):
        ws = _setup_workspace(tmp_path)
        monkeypatch.chdir(ws)
        result = execute_tool('aegis_scan', {'files': 'not_a_list'})
        assert isinstance(result, dict)
        assert result.get('status') == 'FAIL'
        assert "'files' must be a list" in result.get('error', '')


class TestAegisListRules:
    """Tests for aegis_list_rules tool."""

    def test_list_returns_rules_stale_rules_and_ignored(self, tmp_path, monkeypatch):
        ws = _setup_workspace(tmp_path)
        monkeypatch.chdir(ws)
        result = execute_tool('aegis_list_rules', {})
        assert set(result) == {'rules', 'stale_rules', 'ignored'}
        assert [r['_name'] for r in result['rules']] == ['test-rule']
        assert result['stale_rules'] == [] and result['ignored'] == []


class TestAegisCreateRule:
    """Tests for aegis_create_rule tool."""

    def test_create_rule_returns_prompt(self, tmp_path, monkeypatch):
        ws = _setup_workspace(tmp_path)
        monkeypatch.chdir(ws)
        result = execute_tool('aegis_create_rule', {
            'description': 'Test rule for catching null dereferences'
        })
        assert isinstance(result, dict)
        assert 'prompt' in result or 'instruction' in result


class TestAegisReportOutcome:
    """Tests for aegis_report_outcome tool."""

    def test_valid_outcome_returns_recorded(self, tmp_path, monkeypatch):
        ws = _setup_workspace(tmp_path)
        monkeypatch.chdir(ws)
        result = execute_tool('aegis_report_outcome', {
            'outcome': 'success',
            'rules_used': ['test-rule'],
            'tests_passed': True,
            'idempotency_key': 'test-report-1',
        })
        assert isinstance(result, dict)
        assert result.get('status') == 'claimed'
        assert result.get('witness') == 'self' and result.get('credited') == []

    def test_invalid_outcome_returns_error(self, tmp_path, monkeypatch):
        ws = _setup_workspace(tmp_path)
        monkeypatch.chdir(ws)
        result = execute_tool('aegis_report_outcome', {
            'outcome': 'invalid_value_xyz',
            'idempotency_key': 'key-0',
        })
        assert isinstance(result, dict)
        assert result.get('status') == 'FAIL'
        assert "Invalid 'outcome'" in result.get('error', '')

    def test_report_outcome_rejects_non_list_rules(self, tmp_path, monkeypatch):
        ws = _setup_workspace(tmp_path)
        monkeypatch.chdir(ws)
        result = execute_tool('aegis_report_outcome', {
            'outcome': 'success',
            'rules_used': 'not_a_list',
            'idempotency_key': 'key-1',
        })
        assert isinstance(result, dict)
        assert result.get('status') == 'FAIL'
        assert result.get('error') == "'rules_used' must be a list of rule names."


class TestToolOutputSerializability:
    """All tool outputs must be JSON-serializable."""

    @pytest.mark.parametrize('tool_name,args', [
        ('aegis_list_rules', {}),
        ('aegis_create_rule', {'description': 'test'}),
        ('aegis_scan', {'files': ['src/a.py']}),
        ('aegis_report_outcome', {'outcome': 'tp', 'rules_used': ['test-rule'], 'idempotency_key': 'k'}),
    ])
    def test_output_is_json_serializable(self, tool_name, args, tmp_path, monkeypatch):
        ws = _setup_workspace(tmp_path)
        monkeypatch.chdir(ws)
        result = execute_tool(tool_name, args)
        # Should not raise
        json.dumps(result)
