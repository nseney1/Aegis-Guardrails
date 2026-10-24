"""Doctor's public driver report agrees with the plan the card and runner actually use."""
import json
import os
import shlex
import subprocess

import pytest

from aegis_cli.cli import main
from aegis_core import card
from aegis_core.ast import runner


@pytest.fixture
def project(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".aegis").mkdir(parents=True)
    for key in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for key in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(key, raising=False)
    programs = tmp_path / "bin"
    programs.mkdir()
    node = programs / ("node.exe" if os.name == "nt" else "node")
    node.write_bytes(b"#!/bin/sh\nexit 99\n")  # only resolved; no driver is executed by a diagnostic
    node.chmod(0o755)
    monkeypatch.setenv("PATH", str(programs))
    monkeypatch.setenv("PATHEXT", ".EXE")
    root = tmp_path / "ws"
    (root / ".aegis" / "rules").mkdir(parents=True)
    (root / "app.js").write_bytes(b"const value = 1;\n")
    return root, home, node


def _doctor(root, capsys):
    code = main(["doctor", "--drivers", "--workspace", str(root), "--json"])
    out = capsys.readouterr()
    assert out.err == ""
    doc = json.loads(out.out)
    check, = doc["checks"]
    assert check["id"] == "ast_drivers"
    return code, check


def _card_reason(root):
    driver, = [row for row in card.build(root).drivers if row["language"] == "javascript"]
    return driver["status"], driver["reason"]


@pytest.mark.parametrize("inside", [False, True], ids=["usable", "workspace-install"])
def test_packaged_driver_report_checks_its_installation(project, monkeypatch, capsys, inside):
    root, _home, node = project
    templates = (root / ".venv" if inside else root.parent / "installed") / "templates"
    templates.mkdir(parents=True)
    (templates / "ts_ast.js").write_bytes(b"// a packaged template\n")
    # Installation layout is the filesystem boundary; the real planner makes the decision.
    monkeypatch.setattr(runner, "_TEMPLATES_DIR", templates)
    (root / ".aegis" / "config.json").write_bytes(b'{"v":1,"ast":{"packaged_drivers":["js"]}}\n')
    code, check = _doctor(root, capsys)
    if inside:
        reason = (f"the packaged ts_ast.js driver is installed inside the workspace ({templates}), "
                  "where node would load modules from the repository; install aegis outside it")
        assert (code, check["status"]) == (1, "warn")
        assert check["detail"] == [f"⚠️  AST driver (.js): {reason}"]
        assert _card_reason(root) == ("unavailable", reason)
    else:
        assert (code, check["status"]) == (0, "pass")
        assert check["detail"] == [f"✅ AST driver (.js): node resolvable ({node})"]
        assert _card_reason(root) == ("ready", None)


@pytest.mark.parametrize("inside", [False, True], ids=["usable", "workspace-script"])
def test_custom_driver_report_checks_its_script(project, capsys, inside):
    root, home, node = project
    script = (root if inside else root.parent) / "driver.js"
    script.write_bytes(b"// a custom driver\n")
    argv = ["node", "driver.js" if inside else str(script)]
    command = subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)
    (home / ".aegis" / "config.json").write_bytes(json.dumps({"v": 1, "drivers": {"js": command}}).encode())
    code, check = _doctor(root, capsys)
    if inside:
        reason = "the ~/.aegis/config.json driver for '.js' passes driver.js, which is inside the workspace"
        assert (code, check["status"]) == (1, "warn")
        assert check["detail"] == [f"⚠️  AST driver (.js): {reason}"]
        assert _card_reason(root) == ("unavailable", reason)
    else:
        assert (code, check["status"]) == (0, "pass")
        assert check["detail"] == [f"✅ AST driver (.js): node resolvable ({node})"]
        assert _card_reason(root) == ("ready", None)


def test_malformed_custom_driver_reports_the_planner_refusal(project, capsys):
    root, home, _node = project
    command = "node 'unterminated"
    (home / ".aegis" / "config.json").write_bytes(json.dumps({"v": 1, "drivers": {"js": command}}).encode())
    code, check = _doctor(root, capsys)
    reason = "the driver command cannot be parsed: No closing quotation"
    assert (code, check["status"]) == (1, "warn")
    assert check["detail"] == [f"⚠️  AST driver (.js): {reason}"]
    assert _card_reason(root) == ("unavailable", reason)
