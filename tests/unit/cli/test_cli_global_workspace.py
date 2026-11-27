"""The global ``aegis --workspace X`` flag and cwd discovery follow the AD-4 rules
(wave A deferral, build sheet wave C): never above X's git toplevel, never $HOME, and
a HOLD with a machine-readable reason when an AEGIS_WORKSPACE pin disagrees with X.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from aegis_cli.cli import main


def _tree(root: Path) -> list:
    out = []
    for dirpath, dirs, files in os.walk(root):
        for name in dirs:
            out.append((Path(dirpath, name).relative_to(root).as_posix() + "/", ""))
        for name in files:
            full = Path(dirpath, name)
            out.append((full.relative_to(root).as_posix(), hashlib.sha256(full.read_bytes()).hexdigest()))
    return sorted(out)


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    (home / ".aegis" / "rules" / "traps").mkdir(parents=True)
    (home / ".aegis" / "rules" / "traps" / "user-plane.md").write_text(
        "---\nid: user-plane\ntype: trap\ntarget_paths: ['**']\n---\nUser rule.\n", encoding="utf-8"
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home.resolve()


def _governed(path: Path) -> Path:
    (path / ".aegis" / "rules" / "traps").mkdir(parents=True, exist_ok=True)
    return path.resolve()


def test_global_workspace_inside_a_nested_repo_never_syncs_the_outer_workspace(home, tmp_path, capsys):
    outer = _governed(tmp_path / "outer")
    inner = outer / "inner"
    (inner / ".git").mkdir(parents=True)
    before = _tree(outer / ".aegis")

    rc = main(["--workspace", str(inner), "sync"])

    assert rc != 0
    assert f"not an Aegis workspace (no .aegis/ in {inner})" in capsys.readouterr().err
    assert _tree(outer / ".aegis") == before


def test_cwd_inside_a_nested_repo_never_syncs_the_outer_workspace(home, tmp_path, capsys, monkeypatch):
    outer = _governed(tmp_path / "outer")
    inner = outer / "inner"
    (inner / ".git").mkdir(parents=True)
    monkeypatch.chdir(inner)
    before = _tree(outer / ".aegis")

    rc = main(["sync"])

    assert rc != 0
    assert f"not an Aegis workspace (no .aegis/ in {inner})" in capsys.readouterr().err
    assert _tree(outer / ".aegis") == before


@pytest.mark.parametrize("argv", [["status"], ["sync"], ["--workspace", "~", "status"]])
def test_home_is_never_the_workspace(home, capsys, monkeypatch, argv):
    monkeypatch.chdir(home)
    before = _tree(home)

    rc = main(argv)

    assert rc == 1
    assert (
        f"Error: not an Aegis workspace ({home} is the home directory; ~/.aegis is the user rule layer); "
        "run aegis init in a project"
    ) in capsys.readouterr().err
    assert _tree(home) == before


def test_a_subdirectory_target_resolves_to_its_workspace(home, tmp_path, capsys):
    root = _governed(tmp_path / "repo")
    (root / ".git").mkdir()
    (root / "src").mkdir()

    rc = main(["--workspace", str(root / "src"), "rule", "list", "--json"])

    assert rc == 0, capsys.readouterr().err


def test_a_pin_that_disagrees_with_the_target_is_a_machine_readable_hold(home, tmp_path, capsys, monkeypatch):
    pinned = _governed(tmp_path / "pinned")
    target = _governed(tmp_path / "target")
    monkeypatch.setenv("AEGIS_WORKSPACE", str(pinned))
    before = (_tree(pinned), _tree(target))

    rc = main(["--workspace", str(target), "status", "--json"])

    out = capsys.readouterr().out
    assert rc == 1
    payload = json.loads(out)
    assert payload["status"] == "hold"
    assert payload["reason"] == "pin_conflicts_with_target"
    assert payload["details"] == {"pin": str(pinned), "target": str(target)}
    assert payload["source"] == "aegis status"
    assert payload["scope"] == {"command": "status", "workspace": None}
    assert payload["checked_at"].endswith("Z") and payload["aegis_version"]
    assert (_tree(pinned), _tree(target)) == before


def test_a_pin_hold_without_json_is_one_line_on_stderr(home, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("AEGIS_WORKSPACE", str(_governed(tmp_path / "pinned")))

    rc = main(["--workspace", str(_governed(tmp_path / "target")), "status"])

    assert rc == 1
    err = capsys.readouterr().err
    assert err.startswith("Hold (pin_conflicts_with_target): --workspace ")


@pytest.mark.parametrize("argv", [["check", "--hook"], ["status"], ["sync"]], ids=lambda argv: " ".join(argv))
def test_a_pin_to_another_repository_holds_instead_of_acting_on_it(home, tmp_path, capsys, monkeypatch, argv):
    """In the git hook the cwd is the repository being committed: a pin elsewhere must
    not make `check --hook` check (and pass) another repository's changes."""
    from aegis_cli.registry import get_default_registry

    ran = []
    monkeypatch.setattr(type(get_default_registry().get(argv[0])), "execute", lambda self, args: ran.append(args) or 0)
    pinned = _governed(tmp_path / "pinned")
    (pinned / ".git").mkdir()
    here = _governed(tmp_path / "here")
    (here / ".git").mkdir()
    monkeypatch.setenv("AEGIS_WORKSPACE", str(pinned))
    monkeypatch.chdir(here)

    rc = main(argv)

    assert rc == 1
    assert ran == []
    assert capsys.readouterr().err.startswith(f"Hold (pin_conflicts_with_cwd): AEGIS_WORKSPACE pins {pinned}")


def test_a_pin_that_is_not_a_workspace_is_an_error(home, tmp_path, capsys, monkeypatch):
    from aegis_cli.registry import get_default_registry

    ran = []
    monkeypatch.setattr(type(get_default_registry().get("status")), "execute", lambda self, args: ran.append(args) or 0)
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.setenv("AEGIS_WORKSPACE", str(plain))
    monkeypatch.chdir(plain)

    assert main(["status"]) == 1
    assert ran == []
    assert capsys.readouterr().err == (
        f"Error: AEGIS_WORKSPACE is set to {plain}, which has no .aegis/ (run aegis init there)\n"
    )


def test_doctor_still_runs_from_home(home, monkeypatch):
    """Host checks are machine-level: doctor resolves no workspace at $HOME but is not refused."""
    import argparse

    from aegis_cli.cli import _attach_workspace

    monkeypatch.chdir(home)
    args = argparse.Namespace(command="doctor", workspace=None)

    _attach_workspace(args)

    assert (args.ws, args._project_root, args._workspace_arg) == (None, home, None)


# ── scan: the daily command takes the same hold and never governs $HOME ─────────

def _rule_in(root: Path, rule_id: str) -> Path:
    traps = root / ".aegis" / "rules" / "traps"
    traps.mkdir(parents=True, exist_ok=True)
    (traps / f"{rule_id}.md").write_text(
        f"---\nid: {rule_id}\ntype: trap\ntarget_paths: ['**']\n---\nRule {rule_id}.\n", encoding="utf-8"
    )
    return root.resolve()


def test_scan_with_a_pin_that_disagrees_with_the_target_holds_and_scans_nothing(home, tmp_path, capsys, monkeypatch):
    pinned = _rule_in(tmp_path / "a", "trap-a")
    target = _rule_in(tmp_path / "b", "trap-b")
    monkeypatch.setenv("AEGIS_WORKSPACE", str(pinned))
    monkeypatch.chdir(target)

    rc = main(["scan", "--workspace", str(target), "x.py", "--json"])

    out = capsys.readouterr().out
    assert rc == 2  # scan's contract: a workspace error exits 2
    payload = json.loads(out)
    assert (payload["status"], payload["reason"]) == ("hold", "pin_conflicts_with_target")
    assert payload["details"] == {"pin": str(pinned), "target": str(target)}
    assert payload["source"] == "aegis scan"
    assert "relevant_rules" not in payload


def test_scan_hold_without_json_is_one_line_on_stderr(home, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("AEGIS_WORKSPACE", str(_rule_in(tmp_path / "a", "trap-a")))

    rc = main(["--workspace", str(_rule_in(tmp_path / "b", "trap-b")), "scan", "x.py"])

    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out == ""
    assert captured.err.startswith("Hold (pin_conflicts_with_target): --workspace ")


def test_scan_with_a_pin_that_agrees_with_the_target_scans_the_pin(home, tmp_path, capsys, monkeypatch):
    pinned = _rule_in(tmp_path / "a", "trap-a")
    (pinned / "src").mkdir()
    monkeypatch.setenv("AEGIS_WORKSPACE", str(pinned))
    monkeypatch.chdir(pinned)

    rc = main(["scan", "--workspace", str(pinned / "src"), "x.py", "--json"])

    assert rc == 0
    assert [r["name"] for r in json.loads(capsys.readouterr().out)["relevant_rules"]] == ["trap-a"]


def test_scan_from_home_never_scans_the_user_layer_as_a_project(home, capsys, monkeypatch):
    monkeypatch.chdir(home)
    before = _tree(home)

    rc = main(["scan", "x.py", "--json"])

    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out == ""
    assert captured.err == (
        f"Error: not an Aegis workspace ({home} is the home directory; ~/.aegis is the user rule layer); "
        "run aegis init in a project\n"
    )
    assert _tree(home) == before


# ── init, migrate, uninstall: the pin hold, and never above the toplevel or $HOME ─

@pytest.mark.parametrize("command", ["init", "migrate", "uninstall"])
def test_a_pin_that_disagrees_with_the_target_holds_before_the_command_runs(home, tmp_path, capsys, monkeypatch, command):
    from aegis_cli.registry import get_default_registry

    ran = []
    monkeypatch.setattr(type(get_default_registry().get(command)), "execute", lambda self, args: ran.append(args) or 0)
    pinned = _governed(tmp_path / "pinned")
    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.setenv("AEGIS_WORKSPACE", str(pinned))

    rc = main(["--json", "--workspace", str(target), command])

    assert rc == 1
    assert ran == []
    payload = json.loads(capsys.readouterr().out)
    assert (payload["status"], payload["reason"]) == ("hold", "pin_conflicts_with_target")
    assert payload["details"] == {"pin": str(pinned), "target": str(target.resolve())}
    assert payload["source"] == f"aegis {command}"


def test_migrate_never_walks_above_the_git_toplevel(home, tmp_path, capsys, monkeypatch):
    outer = tmp_path / "outer"
    (outer / ".aegis").mkdir(parents=True)
    sub = outer / "repo" / "sub"
    (outer / "repo" / ".git").mkdir(parents=True)
    sub.mkdir()
    monkeypatch.chdir(sub)

    rc = main(["migrate", "--json"])

    assert rc == 0
    assert json.loads(capsys.readouterr().out)["root"] == str(sub.resolve())


def test_migrate_below_home_never_plans_the_user_plane(home, capsys, monkeypatch):
    (home / ".aegis" / "evidence").mkdir(parents=True)
    (home / ".aegis" / "evidence" / "signals.jsonl").write_text("", encoding="utf-8")
    sub = home / "proj" / "sub"
    sub.mkdir(parents=True)
    monkeypatch.chdir(sub)

    rc = main(["migrate", "--json"])

    report = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert report["root"] == str(sub)
    assert report["ledger"] is None


@pytest.mark.parametrize("argv", [["migrate", "--json"], ["uninstall", "--dry-run"]])
def test_migrate_and_uninstall_refuse_home(home, capsys, monkeypatch, argv):
    from aegis_cli.registry import get_default_registry

    ran = []
    monkeypatch.setattr(type(get_default_registry().get(argv[0])), "execute", lambda self, args: ran.append(args) or 0)
    monkeypatch.chdir(home)

    rc = main(argv)

    captured = capsys.readouterr()
    assert rc == 1
    assert ran == []
    assert captured.out == ""
    assert captured.err == (
        f"Error: not an Aegis workspace ({home} is the home directory; ~/.aegis is the user rule layer); "
        "run aegis init in a project\n"
    )


def test_uninstall_below_home_targets_the_project_not_the_user_plane(home, capsys, monkeypatch):
    project = home / "proj"
    project.mkdir()
    monkeypatch.chdir(project)

    rc = main(["uninstall", "--dry-run"])

    out = capsys.readouterr().out
    assert rc == 0
    assert str(home / ".aegis") not in out
