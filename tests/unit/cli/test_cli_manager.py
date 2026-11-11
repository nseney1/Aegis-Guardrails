"""Manager CLI selects an explicit configuration without making cwd a repository."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tests.helpers_manager import manager_root

REPO = Path(__file__).resolve().parents[3]


def invoke(tmp_path, *arguments, env=None):
    selected = dict(os.environ, PYTHONPATH=str(REPO))
    selected.pop("AEGIS_WORKSPACE", None)
    selected.pop("AEGIS_MANAGER_CONFIG", None)
    selected.update(env or {})
    return subprocess.run([sys.executable, "-m", "aegis_cli", "workspace", *arguments],
                          cwd=tmp_path, env=selected, capture_output=True, text=True, timeout=30)


def test_manager_help_names_only_manager_commands(tmp_path):
    result = invoke(tmp_path, "--help")
    assert result.returncode == 0, result.stderr
    for command in ("init", "activate", "status", "scan", "report"):
        assert command in result.stdout
    assert not (tmp_path / ".git").exists()
    assert not (tmp_path / ".aegis").exists()


@pytest.mark.parametrize("environment, arguments", [
    ({"AEGIS_WORKSPACE": "/forged"}, []),
    ({}, ["--workspace", "/forged"]),
])
def test_manager_rejects_repository_scope_selection(tmp_path, environment, arguments):
    result = invoke(tmp_path, *arguments, "status", "--config", str(tmp_path / "missing.json"),
                    env=environment)
    assert result.returncode == 1
    assert "manager mode cannot use --workspace or AEGIS_WORKSPACE" in result.stderr
    assert not (tmp_path / ".aegis").exists()


def test_manager_requires_explicit_config(tmp_path):
    result = invoke(tmp_path, "status")
    assert result.returncode == 1
    assert "manager mode requires --config" in result.stderr


def test_manager_scan_rejects_malformed_context_before_loading_config(tmp_path):
    result = invoke(tmp_path, "scan", "--config", str(tmp_path / "missing.json"),
                    "--action", "handoff", "--context", "{broken")
    assert result.returncode == 1
    assert "invalid JSON object" in result.stderr


def test_manager_scan_rejects_duplicate_context_keys(tmp_path):
    result = invoke(tmp_path, "scan", "--config", str(tmp_path / "missing.json"),
                    "--action", "handoff", "--context", '{"role":"owner","role":"worker"}')
    assert result.returncode == 1
    assert "duplicate key 'role'" in result.stderr


def test_activation_has_no_self_approval_flag(tmp_path):
    result = invoke(tmp_path, "activate", "--config", str(tmp_path / "missing.json"),
                    "--revision", "a" * 40, "--expect", "none", "--approved")
    assert result.returncode == 2
    assert "--approved" in result.stderr


def test_manager_init_and_status_work_without_parent_repository(manager_root):
    from tests.helpers_manager import prepare

    tmp_path = manager_root
    prepared = prepare(tmp_path)
    control = prepared["control"]
    config = tmp_path / "manager.json"
    result = invoke(tmp_path, "init", "--config", str(config), "--workspace-id", "aegis-pilot",
                    "--control-repo", str(control), "--store", str(tmp_path / "audit2"),
                    "--trusted-signers", str(prepared["signers"]), "--json")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["registration"]["aegis-manager"]["env"]["AEGIS_MANAGER_CONFIG"] == str(config)
    result = invoke(tmp_path, "status", "--config", str(config), "--json")
    assert result.returncode == 0, result.stderr
    status = json.loads(result.stdout)
    assert status["policy_approval"] == "draft"
    assert status["native_enforcement_ready"] is False
    assert not (tmp_path / ".git").exists()
    assert not (tmp_path / ".aegis").exists()


@pytest.mark.parametrize("evidence", ['[],"scope":"forged"', "{}", "NaN", "1e999"])
def test_manager_report_refuses_invalid_evidence_before_config_read(tmp_path, evidence):
    result = invoke(tmp_path, "report", "--config", str(tmp_path / "missing.json"),
                    "--decision", "a" * 64, "--outcome", "success", "--idempotency-key", "retry",
                    "--evidence", evidence)
    assert result.returncode == 1
    assert "config_unavailable" not in result.stderr


def test_owner_reviews_and_activates_exact_policy_through_cli(manager_root):
    from tests.helpers_manager import approve, prepare

    tmp_path = manager_root
    prepared = prepare(tmp_path)
    result = invoke(tmp_path, "activate", "--config", str(prepared["config"]),
                    "--revision", prepared["revision"], "--expect", "none", "--json")
    assert result.returncode == 0, result.stderr
    candidate = json.loads(result.stdout)
    assert candidate["status"] == "awaiting_owner_approval"
    approval = approve(prepared, candidate)
    approval_path = tmp_path / "reviewed-approval.json"
    approval_path.write_text(json.dumps(approval))
    result = invoke(tmp_path, "activate", "--config", str(prepared["config"]),
                    "--revision", prepared["revision"], "--expect", "none", "--approval", str(approval_path))
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["policy_approval"] == "approved"
