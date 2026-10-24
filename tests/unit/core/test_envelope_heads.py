"""Output heads keep their order and stored stamps across the shared-builder move."""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from aegis_core import human_gate, lane_gate, primitives, release_verify, rule_integrity, scan_compliance
from aegis_core._version import __version__

STAMP = "2020-01-02T03:04:05Z"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for key in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for key in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(key, raising=False)


def _lane(root):
    return lane_gate.LaneCheck(
        "A", str(root), str(root), "main", "a" * 40, "a" * 40, "b" * 40,
        ("src/**",), "cli", (), "cli", (), (), (), (), STAMP)


def _documents(root, monkeypatch, capsys):
    from aegis_cli import approve, benchmark, cli, doctor_render, init_views, package, rule, skills_sync, team
    from aegis_cli.hooks import registrar
    from aegis_core import card, partition
    from aegis_core.workspace.binding import WorkspaceBinding, WorkspaceHold

    (root / ".aegis" / "rules").mkdir(parents=True)
    docs = {
        "benchmark": benchmark._envelope(root, 3),
        "team": team._envelope("list", root, 0, refs="refs/aegis/lanes"),
        "hook": registrar._envelope("install", "claude-code", "user", root, []),
        "approve": approve._envelope(root, "refused", reason="no signature"),
        "package": package._envelope(root, root / "out"),
        "pack": rule._pack_envelope("export", root, {"files": 1}),
        "tier": human_gate.TierReport("C", scope={"workspace": str(root)}, checked_at=STAMP).as_dict(),
        "approval": human_gate.Approval(False, "missing", "no approval", "a" * 40).as_dict(root),
        "lane": _lane(root).as_dict(),
        "lane_error": lane_gate.error_report(root, "A", "no base", now=0),
        "release": release_verify.ReleaseReport("a" * 40, False, "gh_missing", "not installed").as_dict(root),
        "integrity": rule_integrity.CiReport("main", "b" * 40, "a" * 40, 0, (), None).as_dict(root),
        "compliance": scan_compliance.report(root),
        "card": card.build(root, now=0).as_dict(),
        "partition": partition.check(root, {"A": ("src/**",), "B": ("tests/**",)}, now=0, record=False).as_dict(),
    }
    init_views.Report(True, "aegis init").finish("ok", {"workspace": str(root)}, True, [])
    docs["init"] = json.loads(capsys.readouterr().out)
    skills_sync.run_skills(argparse.Namespace(_project_root=root, host=["claude-code"],
                                             force=False, dry_run=True, json=True))
    docs["skills"] = json.loads(capsys.readouterr().out)
    held = WorkspaceHold(WorkspaceBinding("hold", source="pin", reason="mismatch", message="disagree"))
    cli._print_hold(argparse.Namespace(json=True, command="status"), held)
    docs["hold"] = json.loads(capsys.readouterr().out)
    diag = SimpleNamespace(ctx=SimpleNamespace(root=root, governed=True, selected=(), selection="default"),
                           rows=[], findings=[], tiers=[], trust=None, modes=None)
    docs["doctor"] = doctor_render._payload(diag, [])
    monkeypatch.setattr(doctor_render.human_gate, "detect_tier", lambda root: human_gate.TierReport("C"))
    assert doctor_render._run_github(root, True, False, None) == 0
    docs["doctor_github"] = json.loads(capsys.readouterr().out)
    monkeypatch.setattr(doctor_render, "_run_checks", lambda *args, **kwargs: [
        {"id": "ast_drivers", "status": "pass", "text": "healthy", "detail": []}])
    assert doctor_render._run_drivers_only(root, True, False, False) == 0
    docs["doctor_drivers"] = json.loads(capsys.readouterr().out)
    return docs


def _head(doc):
    keys = list(doc)
    return keys[:keys.index("scope") + 1]


def test_recorded_output_heads(tmp_path, monkeypatch, capsys):
    # Given each real rendering route, its head matches the recording from w11.
    docs = _documents(tmp_path / "repo", monkeypatch, capsys)
    expected = json.loads(Path(__file__).with_name("envelope_heads.json").read_text(encoding="utf-8"))
    assert {name: _head(doc) for name, doc in docs.items()} == expected
    for name, doc in docs.items():
        assert doc["aegis_version"] == __version__
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", doc["checked_at"])
    assert docs["tier"]["checked_at"] == docs["lane"]["checked_at"] == STAMP
    assert docs["hold"]["source"] == "aegis status"
    assert docs["team"]["checked_at"] == docs["lane_error"]["checked_at"] == "1970-01-01T00:00:00Z"


def test_check_row_and_cli_head(tmp_path, capsys):
    from aegis_cli.cli import main
    from tests import helpers_humangate as hg, helpers_verified as hv

    if not hg.git_ok():
        pytest.skip("needs git")
    repo = hv.make_project(tmp_path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    assert main(["check", "--record", "--json", "--base", "main", "--workspace", str(repo.root)]) == 0
    doc = json.loads(capsys.readouterr().out)
    row, = hv.rows_of(repo.root, "check")
    assert _head(doc) == ["source", "aegis_version", "checked_at", "scope"]
    assert list(doc["check"])[:9] == ["v", "ts", "event", "witness", "source", "aegis_version", "checked_at", "scope", "tree"]
    assert row["ts"] == row["checked_at"]
    assert list(row)[:10] == ["v", "seq", "ts", "event", "witness", "source", "aegis_version", "checked_at", "scope", "tree"]
    assert doc["check"] == {key: value for key, value in row.items() if key not in ("seq", "worktree")}


def test_mcp_report_head(tmp_path, monkeypatch):
    from aegis_core.workspace.base import Workspace
    from aegis_mcp.handlers import telemetry

    root = tmp_path / "repo"
    (root / ".aegis" / "rules" / "traps").mkdir(parents=True)
    (root / ".aegis" / "rules" / "traps" / "trap-x.md").write_bytes(
        b"---\nid: trap-x\ntype: trap\nhypothesis: h\nprediction: p\n---\n# x\n")
    monkeypatch.setattr(telemetry, "get_workspace", lambda args: Workspace(root))
    doc = telemetry.handle_report_outcome({"outcome": "success", "rules_used": ["trap-x"],
                                          "idempotency_key": "head", "_session": "heads"})
    assert _head(doc) == ["source", "aegis_version", "checked_at", "scope"]
    assert doc["source"] == "aegis_report_outcome"
    assert doc["aegis_version"] == __version__
    assert doc["status"] == "claimed" and doc["witness"] == "self"


def test_shared_head_keeps_scope_identity_and_stamp():
    scope = {"workspace": "somewhere"}
    doc = primitives.envelope("aegis x", scope)
    assert list(doc) == ["source", "aegis_version", "checked_at", "scope"]
    assert doc["scope"] is scope and doc["aegis_version"] == __version__
    assert primitives.envelope("x", {}, schema="aegis.x/v1", now=0) == {
        "schema": "aegis.x/v1", "source": "x", "aegis_version": __version__,
        "checked_at": "1970-01-01T00:00:00Z", "scope": {}}
    assert primitives.envelope("x", {}, checked_at="already captured")["checked_at"] == "already captured"


def test_shared_head_refuses_ambiguous_time_but_defers_json_validation():
    with pytest.raises(TypeError):
        primitives.envelope("x", {}, now=0, checked_at=STAMP)
    scope = {"not_json": object()}
    doc = primitives.envelope("x", scope)
    assert doc["scope"] is scope
    with pytest.raises(TypeError):
        json.dumps(doc)


def test_only_the_leaf_builds_checked_at_fields():
    root = Path(__file__).resolve().parents[3]
    copies = []
    for package in ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk"):
        for path in (root / package).rglob("*.py"):
            relative = path.relative_to(root).as_posix()
            if relative in ("aegis_core/primitives.py", "aegis_mcp/registry.py"):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            if any(isinstance(node, ast.Dict) and any(
                isinstance(key, ast.Constant) and key.value == "checked_at" for key in node.keys
            ) for node in ast.walk(tree)):
                copies.append(relative)
    assert copies == []


def test_compliance_head_contains_version_in_documented_order(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    doc = scan_compliance.report(root)
    assert _head(doc) == ["schema", "source", "aegis_version", "checked_at", "scope"]
    assert doc["aegis_version"] == __version__
