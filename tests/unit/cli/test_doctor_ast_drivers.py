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
    return root, home, node


def _doctor(root, capsys):
    code = main(["doctor", "--drivers", "--workspace", str(root), "--json"])
    out = capsys.readouterr()
    assert out.err == ""
    doc = json.loads(out.out)
    check, = doc["checks"]
    assert check["id"] == "ast_drivers"
    return code, check


def _card_reason(root, language):
    driver, = [row for row in card.build(root).drivers if row["language"] == language]
    return driver["status"], driver["reason"]


def test_legacy_packaged_js_opt_in_reports_the_native_parser_not_node(project, monkeypatch, capsys):
    root, _home, _node = project
    (root / "app.js").write_bytes(b"const value = 1;\n")
    templates = root.parent / "installed" / "templates"
    templates.mkdir(parents=True)
    (templates / "ts_ast.js").write_bytes(b"// a stale packaged template\n")
    monkeypatch.setattr(runner, "_TEMPLATES_DIR", templates)
    (root / ".aegis" / "config.json").write_bytes(b'{"v":1,"ast":{"packaged_drivers":["js"]}}\n')
    code, check = _doctor(root, capsys)
    assert (code, check["status"]) == (0, "pass")
    assert check["detail"] == [
        "javascript: parser in-process; pack 5; tests not configured; coverage not configured",
        "✅ AST driver (.js): native JavaScript/TypeScript (in-process)",
    ]
    assert _card_reason(root, "javascript") == ("ready", None)


def test_packaged_driver_report_checks_its_installation(project, monkeypatch, capsys):
    root, _home, node = project
    go = node.with_name("go.exe" if os.name == "nt" else "go")
    go.write_bytes(b"#!/bin/sh\nexit 99\n")  # only resolved; the refusal comes before any build
    go.chmod(0o755)
    (root / "app.go").write_bytes(b"package main\n")
    templates = root / ".venv" / "templates"
    templates.mkdir(parents=True)
    (templates / "go_ast.go").write_bytes(b"// a packaged template\n")
    # Installation layout is the filesystem boundary; the real planner makes the decision.
    monkeypatch.setattr(runner, "_TEMPLATES_DIR", templates)
    (root / ".aegis" / "config.json").write_bytes(b'{"v":1,"ast":{"packaged_drivers":["go"]}}\n')
    code, check = _doctor(root, capsys)
    reason = (f"the packaged go_ast.go driver is installed inside the workspace ({templates}), "
              "where go would load modules from the repository; install aegis outside it")
    assert (code, check["status"]) == (1, "warn")
    assert check["detail"] == [
        "go: parser unavailable; pack 4; tests go test (default); coverage coverprofile (default)",
        f"⚠️  AST driver (.go): {reason}",
    ]
    assert _card_reason(root, "go") == ("unavailable", reason)


@pytest.mark.parametrize("inside", [False, True], ids=["usable", "workspace-script"])
def test_custom_driver_report_checks_its_script(project, capsys, inside):
    root, home, node = project
    (root / "app.go").write_bytes(b"package main\n")
    script = (root if inside else root.parent) / "driver.script"
    script.write_bytes(b"// a custom driver\n")
    argv = ["node", "driver.script" if inside else str(script)]
    command = subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)
    (home / ".aegis" / "config.json").write_bytes(json.dumps({"v": 1, "drivers": {"go": command}}).encode())
    code, check = _doctor(root, capsys)
    if inside:
        reason = "the ~/.aegis/config.json driver for '.go' passes driver.script, which is inside the workspace"
        assert (code, check["status"]) == (1, "warn")
        assert check["detail"] == [
            "go: parser unavailable; pack 4; tests go test (default); coverage coverprofile (default)",
            f"⚠️  AST driver (.go): {reason}",
        ]
        assert _card_reason(root, "go") == ("unavailable", reason)
    else:
        assert (code, check["status"]) == (0, "pass")
        assert check["detail"] == [
            "go: parser user driver; pack 4; tests go test (default); coverage coverprofile (default)",
            f"✅ AST driver (.go): node resolvable ({node})",
        ]
        assert _card_reason(root, "go") == ("ready", None)


def test_malformed_custom_driver_reports_the_planner_refusal(project, capsys):
    root, home, _node = project
    (root / "app.go").write_bytes(b"package main\n")
    command = "node 'unterminated"
    (home / ".aegis" / "config.json").write_bytes(json.dumps({"v": 1, "drivers": {"go": command}}).encode())
    code, check = _doctor(root, capsys)
    reason = "the driver command cannot be parsed: No closing quotation"
    assert (code, check["status"]) == (1, "warn")
    assert check["detail"] == [
        "go: parser unavailable; pack 4; tests go test (default); coverage coverprofile (default)",
        f"⚠️  AST driver (.go): {reason}",
    ]
    assert _card_reason(root, "go") == ("unavailable", reason)


@pytest.mark.skipif(os.name == "nt", reason="symlink creation requires Windows privileges")
def test_driver_planning_failure_keeps_the_public_warning_document(project, capsys):
    root, home, _node = project
    (root / "app.go").write_bytes(b"package main\n")
    (root / "loop.js").symlink_to("loop.js")
    (home / ".aegis" / "config.json").write_bytes(b'{"v":1,"drivers":{"go":"node loop.js"}}\n')
    code, check = _doctor(root, capsys)
    assert (code, check["status"]) == (1, "warn")
    status, reason = _card_reason(root, "go")
    assert status == "unavailable" and reason.startswith("RuntimeError: Symlink loop")
    assert "loop.js" in reason
    assert check["detail"] == [
        "go: parser unavailable; pack 4; tests go test (default); coverage coverprofile (default)",
        f"⚠️  AST driver (.go): {reason}",
    ]
