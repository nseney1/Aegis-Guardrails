"""User-plane commands refuse missing homes without a traceback or a partial write."""
import argparse
import json
from pathlib import Path

import pytest

from aegis_cli import init, rule, skills_sync, uninstall
from aegis_core.errors import WorkspaceNotFoundError
from aegis_core.workspace import binding
from aegis_core.workspace.layout import UserLayout

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


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyError])
@pytest.mark.parametrize("command,expected", [("init", 1), ("uninstall", 1), ("skills", 2)])
def test_missing_home_refuses_before_writes(root, monkeypatch, capsys, failure, command, expected):
    if failure is None:
        monkeypatch.setattr(UserLayout, "current", classmethod(lambda cls: None))
    else:
        def absent(cls):
            raise failure("no passwd entry")
        monkeypatch.setattr(Path, "home", classmethod(absent))
    before = sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))
    args = argparse.Namespace(_project_root=root, workspace=str(root), yes=True, dry_run=True,
                              json=True, force=False, host="auto" if command == "skills" else None)
    call = {"init": init.run_init, "uninstall": uninstall.run_uninstall, "skills": skills_sync.run_skills}[command]
    assert call(args) == expected
    out = capsys.readouterr()
    if command == "skills":
        assert out.err.strip() == "Error: " + MESSAGE + "; name the hosts with --host"
    else:
        doc = json.loads(out.out)
        assert doc["status"] == "refused" and MESSAGE in doc["errors"]
        if command == "uninstall":
            assert "Nothing was changed." in doc["errors"]
    assert sorted(p.relative_to(root).as_posix() for p in root.rglob("*")) == before


def test_explicit_host_selection_needs_no_home(root, monkeypatch):
    monkeypatch.setattr(UserLayout, "current", classmethod(lambda cls: None))
    assert skills_sync._hosts(argparse.Namespace(host=["claude-code"]), root) == (["claude-code"], "")


def test_rule_refuses_filesystem_root_with_the_binding_message(root, monkeypatch):
    filesystem_root = Path(root.anchor)
    monkeypatch.setattr(rule, "is_aegis_workspace", lambda path: True)
    with pytest.raises(WorkspaceNotFoundError) as caught:
        rule._resolve_workspace_root(argparse.Namespace(_rule_workspace_arg=str(filesystem_root)), require_aegis=True)
    assert str(caught.value) == binding.denial_message(filesystem_root)
    assert str(caught.value) == f"not an Aegis workspace ({filesystem_root} is the filesystem root); run aegis init in a project"
