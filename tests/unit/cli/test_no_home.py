"""User-plane commands refuse missing homes without a traceback or a partial write."""
import argparse
import json
import os
from pathlib import Path

import pytest

from aegis_cli import rule
from aegis_cli.cli import main
from aegis_core.errors import WorkspaceNotFoundError
from aegis_core.workspace import binding

MESSAGE = "no home directory can be resolved on this machine (set HOME, or USERPROFILE on Windows)"


@pytest.fixture
def root(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for key in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for key in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(key, raising=False)
    root = tmp_path / "repo"
    (root / ".aegis" / "rules").mkdir(parents=True)
    return root


def _snapshot(directory):
    return {p.relative_to(directory).as_posix():
            ("link", os.readlink(p)) if p.is_symlink() else
            ("file", p.read_bytes()) if p.is_file() else ("directory",)
            for p in directory.rglob("*")}


@pytest.mark.parametrize("failure", [RuntimeError, KeyError])
@pytest.mark.parametrize("command,expected", [("init", 1), ("uninstall", 1), ("skills", 2)])
def test_missing_home_refuses_before_writes(root, monkeypatch, capsys, failure, command, expected):
    home = root.parent / "home"
    (root / "keep.txt").write_bytes(b"workspace content\n")
    (home / "keep.txt").write_bytes(b"user content\n")
    before = (_snapshot(root), _snapshot(home))

    def absent(cls):
        raise failure("no passwd entry")

    monkeypatch.setattr(Path, "home", classmethod(absent))
    argv = {"init": ["init", "--yes", "--rules", "none-active"],
            "uninstall": ["uninstall"],
            "skills": ["skills", "sync", "--host", "auto"]}[command]
    assert main([*argv, "--workspace", str(root), "--json"]) == expected
    out = capsys.readouterr()
    if command == "skills":
        assert out.err.strip() == "Error: " + MESSAGE + "; name the hosts with --host"
        assert not out.out
    else:
        doc = json.loads(out.out)
        assert doc["status"] == "refused" and doc["dry_run"] is False
        assert doc["errors"] == [MESSAGE] + (["Nothing was changed."] if command == "uninstall" else [])
        assert not out.err
    assert (_snapshot(root), _snapshot(home)) == before


@pytest.mark.parametrize("failure", [RuntimeError, KeyError])
def test_explicit_host_selection_needs_no_home(root, monkeypatch, capsys, failure):
    def absent(cls):
        raise failure("no passwd entry")

    monkeypatch.setattr(Path, "home", classmethod(absent))
    assert main(["skills", "sync", "--host", "claude-code", "--workspace", str(root), "--json"]) == 0
    out = capsys.readouterr()
    assert out.err == ""
    doc = json.loads(out.out)
    assert doc["status"] == "ok" and doc["dry_run"] is False
    assert doc["scope"]["hosts"] == ["claude-code"]
    assert doc["counts"]["created"] > 0 and doc["errors"] == []
    assert list((root / ".claude" / "skills").glob("*/SKILL.md"))


def test_rule_refuses_filesystem_root_with_the_binding_message(root, monkeypatch):
    filesystem_root = Path(root.anchor)
    monkeypatch.setattr(rule, "is_aegis_workspace", lambda path: True)
    with pytest.raises(WorkspaceNotFoundError) as caught:
        rule._resolve_workspace_root(argparse.Namespace(_rule_workspace_arg=str(filesystem_root)), require_aegis=True)
    assert str(caught.value) == binding.denial_message(filesystem_root)
    assert str(caught.value) == f"not an Aegis workspace ({filesystem_root} is the filesystem root); run aegis init in a project"
