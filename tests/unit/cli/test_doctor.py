"""Tests for aegis doctor health checks."""
from __future__ import annotations

import argparse
import os
import sys
from unittest.mock import patch

import pytest

from aegis_cli import doctor, doctor_base
from aegis_cli.doctor import (
    _check_cli_resolvable,
    _check_python_version,
    _check_zero_dependencies,
    run_doctor,
)


@pytest.fixture(autouse=True)
def isolated_hosts(tmp_path, tmp_path_factory, monkeypatch):
    """Doctor reads host configs under HOME and may start a host CLI: keep both fake."""
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)

    def no_host_cli(argv, cwd, timeout):
        raise OSError("host CLIs are not run in these tests")

    monkeypatch.setattr(doctor, "_run_host_cli", no_host_cli)
    # Doctor's own lookups (the aegis CLI, host CLIs, python3) search a private directory
    # holding only an aegis stub, never this machine's PATH. It lies outside tmp_path, which many of these tests use as the
    # workspace. Tests of the CLI check itself use the real lookup (``real_lookup``).
    programs = tmp_path_factory.mktemp("programs")
    _stub(programs, "aegis")
    real_which, real_skipped = doctor_base.which, doctor_base.only_skipped
    monkeypatch.setattr(doctor_base, "which", lambda name, path=None, outside=None:
                        real_which(name, str(programs), outside))
    monkeypatch.setattr(doctor_base, "only_skipped", lambda name, path=None, outside=None, base=None:
                        real_skipped(name, str(programs), outside, base))
    return home


def _stub(directory, name):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (name + (".exe" if os.name == "nt" else ""))
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture
def real_lookup(monkeypatch):
    """Doctor's lookups search $PATH again, which each test sets to its own directories."""
    from aegis_core import pathlookup

    monkeypatch.setattr(doctor_base, "which", pathlookup.which)
    monkeypatch.setattr(doctor_base, "only_skipped", pathlookup.only_skipped)


def _governed(root):
    """A workspace that serves one rule (what `aegis init` leaves behind)."""
    rules = root / ".aegis" / "rules" / "invariants"
    rules.mkdir(parents=True, exist_ok=True)
    (rules / "invariant-sample.md").write_text(
        "---\nid: invariant-sample\ntype: invariant\nenforcement: gate\n"
        "hypothesis: Sample rule for doctor tests.\ntarget_paths:\n  - src/*.py\n---\n"
        "# Sample\n\nKeep the sample rule body long enough to be a real rule body.\n", encoding="utf-8")
    return root


# ── Individual check tests ──────────────────────────────────────────────────


def test_doctor_python_version_passes():
    """On any 3.9+ interpreter this must pass."""
    assert sys.version_info >= (3, 9), "Test suite requires Python ≥ 3.9"
    assert _check_python_version() is True


def test_doctor_zero_dependencies_check():
    """Zero-dependency frontmatter engine should be operational in test environment."""
    assert _check_zero_dependencies() is True


# ── Integration: full run_doctor ─────────────────────────────────────────────


def test_doctor_returns_zero_in_valid_env(tmp_path, monkeypatch):
    """run_doctor returns 0 when the workspace serves rules and aegis is on PATH."""
    _governed(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = run_doctor(argparse.Namespace())
    assert result == 0


def test_doctor_fails_when_no_rule_is_served(tmp_path, monkeypatch, capsys):
    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    assert run_doctor(argparse.Namespace()) == 1
    out = capsys.readouterr().out
    assert "No rules are served" in out and "aegis init" in out


def test_doctor_returns_one_on_failure(tmp_path, monkeypatch):
    """Monkeypatch sys.version_info to (3, 8) and verify exit code 1."""
    # Even with a valid environment, a failing Python version check → exit 1
    _governed(tmp_path)
    monkeypatch.chdir(tmp_path)

    from collections import namedtuple
    _VersionInfo = namedtuple("version_info", "major minor micro releaselevel serial")
    fake_version = _VersionInfo(3, 8, 0, "final", 0)

    monkeypatch.setattr("aegis_cli.doctor.sys.version_info", fake_version)
    args = argparse.Namespace()
    result = run_doctor(args)

    assert result == 1


# ── BUG-041: CLI not on PATH ─────────────────────────────────────────────────


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell remedy; Windows path covered in test_pathcheck")
def test_cli_check_prints_zsh_remedy_when_unresolvable(tmp_path, monkeypatch, capsys, real_lookup):
    bindir = tmp_path / ".local" / "bin"
    bindir.mkdir(parents=True)
    (bindir / "aegis").write_text("#!/bin/sh\n")
    (tmp_path / "empty").mkdir()
    monkeypatch.setenv("SHELL", "/usr/bin/zsh")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.delenv("ZDOTDIR", raising=False)
    monkeypatch.setattr("aegis_cli.pathcheck.default_candidates", lambda: [str(bindir)])
    monkeypatch.setattr("aegis_cli.pathcheck.sys.platform", "linux")
    assert _check_cli_resolvable(tmp_path / "ws") is False
    out = capsys.readouterr().out
    assert "aegis CLI not found on PATH" in out
    assert "~/.zshrc" in out
    assert f"{bindir / 'aegis'} <command>" in out
    assert "-m aegis_cli" not in out


def test_cli_check_never_says_aegis_is_where_only_a_v3_soma_script_is(tmp_path, monkeypatch, capsys,
                                                                      real_lookup):
    bindir = tmp_path / ".local" / "bin"
    bindir.mkdir(parents=True)
    (bindir / "soma").write_text("#!/bin/sh\n")
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.setattr("aegis_cli.pathcheck.default_candidates", lambda: [str(bindir)])
    assert _check_cli_resolvable(tmp_path / "ws") is False
    out = capsys.readouterr().out
    assert "The 'aegis' command is not installed" in out
    assert "pip install aegis-guardrails" in out
    assert str(bindir) not in out and "soma" not in out


def test_cli_check_silent_remedy_when_resolvable(tmp_path, monkeypatch, capsys, real_lookup):
    exe = _stub(tmp_path / "bin", "aegis")
    monkeypatch.setenv("PATH", str(exe.parent))
    assert _check_cli_resolvable(tmp_path / "ws") is True
    out = capsys.readouterr().out
    assert f"aegis CLI resolvable ({exe})" in out
    assert "export PATH" not in out


@pytest.mark.parametrize("entry", ["bin", "", "."])
def test_an_aegis_reached_through_a_relative_path_entry_is_not_the_cli(tmp_path, monkeypatch, capsys,
                                                                       real_lookup, entry):
    # The bootstrap sends agents to `aegis scan` in a shell; an empty or relative PATH entry
    # finds whatever `aegis` the directory the shell starts in (the repository) holds.
    ws = tmp_path / "ws"
    exe = _stub(ws / "bin" if entry == "bin" else ws, "aegis")
    monkeypatch.chdir(ws)
    monkeypatch.setenv("PATH", entry)
    assert _check_cli_resolvable(ws) is False
    out = capsys.readouterr().out
    assert "aegis CLI resolvable" not in out and "aegis CLI not found on PATH" in out
    assert f"{exe} is reached only through the relative PATH entry {entry!r}" in out


def test_an_aegis_on_an_absolute_path_entry_inside_the_workspace_counts_and_says_where(tmp_path, monkeypatch,
                                                                                      capsys, real_lookup):
    # A project virtualenv the user activated: doctor runs nothing, and that is what `aegis` runs.
    ws = tmp_path / "ws"
    exe = _stub(ws / ".venv" / "bin", "aegis")
    monkeypatch.setenv("PATH", str(exe.parent))
    assert _check_cli_resolvable(ws) is True
    assert f"aegis CLI resolvable ({exe}, inside the workspace)" in capsys.readouterr().out


def test_check_ast_drivers_native_when_no_slots(tmp_path, capsys):
    from aegis_cli.doctor import _check_ast_drivers
    assert _check_ast_drivers(tmp_path) is True
    out = capsys.readouterr().out
    assert "native Python stdlib" in out

    # config.json exists, but enables no packaged driver
    config = tmp_path / ".aegis" / "config.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('{"v": 1, "hosts": ["codex-cli"]}')
    assert _check_ast_drivers(tmp_path) is True
    out2 = capsys.readouterr().out
    assert "native Python stdlib" in out2


def test_check_ast_drivers_with_valid_and_invalid_slots(tmp_path, capsys, monkeypatch, real_lookup):
    from aegis_cli.doctor import _check_ast_drivers
    home = tmp_path / "home"
    (home / ".aegis").mkdir(parents=True)
    (home / ".aegis" / "config.json").write_text('{"v": 1, "drivers": {"external": "node runner.js"}}')
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    ws = tmp_path / "ws"
    ws.mkdir()
    tmp_path = ws

    # With the binary on an absolute PATH entry
    node = _stub(tmp_path.parent / "bin", "node")
    monkeypatch.setenv("PATH", str(node.parent))
    assert _check_ast_drivers(tmp_path) is True
    out = capsys.readouterr().out
    assert f"AST driver (.external): node resolvable ({node})" in out

    # With missing binary
    (tmp_path.parent / "empty").mkdir()
    monkeypatch.setenv("PATH", str(tmp_path.parent / "empty"))
    assert _check_ast_drivers(tmp_path) is False
    out = capsys.readouterr().out
    assert "executable 'node' not found on PATH" in out

    # Found only inside the workspace or through a relative entry: aegis never runs it
    planted = _stub(tmp_path / "node_modules" / ".bin", "node")
    _stub(tmp_path, "node")
    monkeypatch.chdir(tmp_path)
    for entry, where in ((str(planted.parent), f"{planted}, inside the workspace"),
                         ("", f"{tmp_path / planted.name}, through the relative PATH entry ''")):
        monkeypatch.setenv("PATH", entry)
        assert _check_ast_drivers(tmp_path) is False
        out = capsys.readouterr().out
        assert f"AST driver (.external): executable 'node' is found only at {where}, where aegis never runs it" in out

    # An unreadable config is reported, not a crash
    (tmp_path / ".aegis").mkdir()
    (tmp_path / ".aegis" / "config.json").write_text("{corrupt")
    assert _check_ast_drivers(tmp_path) is False
    assert ".aegis/config.json is not valid JSON" in capsys.readouterr().out


def test_doctor_warns_when_ast_drivers_unresolvable(tmp_path, monkeypatch, capsys):
    _governed(tmp_path)

    # H5: an external packaged driver (Go) remains opt-in; arbitrary repo
    # commands are dropped before doctor sees them.
    config = tmp_path / ".aegis" / "config.json"
    config.write_text('{"v": 1, "ast": {"packaged_drivers": ["go"]}, "drivers": {"go": "evil"}}')

    monkeypatch.chdir(tmp_path)
    (tmp_path / "empty").mkdir()
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))  # no node; doctor's own lookups are faked
    result = run_doctor(argparse.Namespace())
    assert result == 0
    captured = capsys.readouterr().out
    assert 'go' in captured and 'not found on PATH' in captured


def test_check_ast_drivers_missing_driver_warns_and_fixes(tmp_path, capsys):
    from aegis_cli.doctor import _check_ast_drivers
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.go").write_text("package fixture\n")

    # The check warns and returns False
    assert _check_ast_drivers(tmp_path) is False
    out = capsys.readouterr().out
    assert "unconfigured driver for detected source extension(s): .go" in out
    assert "Run 'aegis doctor --fix' to provision" in out

    # --fix provisions the packaged driver through the backed-up plan
    run_doctor(argparse.Namespace(drivers=True, workspace=str(tmp_path), fix=True, yes=True))
    out = capsys.readouterr().out
    assert "enable the packaged AST drivers for .go" in out
    assert (tmp_path / ".aegis" / "config.json").is_file()


def test_check_ast_drivers_missing_extension_slot_warns_and_fixes(tmp_path, capsys):
    from aegis_cli.doctor import _check_ast_drivers
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.rs").write_text("fn main() {}")

    # Existing config enables ts but not rs
    config = tmp_path / ".aegis" / "config.json"
    config.parent.mkdir(parents=True)
    config.write_text('{"v": 1, "ast": {"packaged_drivers": ["ts"]}}')

    # The check warns
    assert _check_ast_drivers(tmp_path) is False
    out = capsys.readouterr().out
    assert "unconfigured driver for detected source extension(s): .rs" in out

    # --fix provisions the missing slot
    assert run_doctor(argparse.Namespace(drivers=True, workspace=str(tmp_path), fix=True, yes=True)) == 0
    out = capsys.readouterr().out
    assert "enable the packaged AST drivers for .rs" in out
    assert '"rs"' in config.read_text()


def test_run_doctor_with_fix_flag(tmp_path, monkeypatch, capsys):
    _governed(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.ts").write_text("console.log(1);")

    monkeypatch.chdir(tmp_path)
    res = run_doctor(argparse.Namespace(fix=True, yes=True))
    assert res == 0
    captured = capsys.readouterr().out
    assert "native JavaScript/TypeScript (in-process)" in captured
    assert not (tmp_path / ".aegis" / "config.json").exists()


def test_run_doctor_without_fix_flag_does_not_provision(tmp_path, monkeypatch, capsys):
    _governed(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.ts").write_text("console.log(1);")

    monkeypatch.chdir(tmp_path)
    run_doctor(argparse.Namespace())
    assert not (tmp_path / ".aegis" / "config.json").exists()
    out = capsys.readouterr().out
    assert "native JavaScript/TypeScript (in-process)" in out



def test_run_doctor_drivers_flag(tmp_path):
    # The check only reports; provisioning goes through the backed-up --fix plan.
    with patch("aegis_cli.doctor._check_ast_drivers") as mock_check:
        mock_check.return_value = True
        args = argparse.Namespace(drivers=True, workspace=str(tmp_path), fix=False)
        assert run_doctor(args) == 0
        mock_check.assert_called_with(tmp_path)

        mock_check.return_value = False
        args_fail = argparse.Namespace(drivers=True, workspace=str(tmp_path), fix=True, yes=True)
        assert run_doctor(args_fail) == 1
        mock_check.assert_called_with(tmp_path)


def test_drivers_fix_provisions_after_a_backup(tmp_path, isolated_hosts, capsys):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.rs").write_text("fn main() {}\n")
    rc = run_doctor(argparse.Namespace(drivers=True, workspace=str(tmp_path), fix=True, yes=True))
    assert '"rs"' in (tmp_path / ".aegis" / "config.json").read_text()
    assert "enable the packaged AST drivers for .rs" in capsys.readouterr().out
    assert (isolated_hosts / ".aegis" / "backups").is_dir()
    assert rc == 0


@pytest.mark.parametrize("flag", ["--fix-path", "-y"])
def test_doctor_rejects_cut_fix_path_flags(flag, capsys):
    """D17: doctor never edits shell rc files; the PATH hint stays advisory."""
    from aegis_cli.cli import main

    with pytest.raises(SystemExit) as exc:
        main(["doctor", flag])
    assert exc.value.code == 2
    assert f"unrecognized arguments: {flag}" in capsys.readouterr().err


def _rust_project_with_python3_driver(tmp_path, monkeypatch):
    """A rust project plus a user-scope driver named by its legacy 'python3' selector."""
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "main.rs").write_text("fn main() {}")
    home = tmp_path / "home"  # outside the workspace, so it is user scope
    (home / ".aegis").mkdir(parents=True)
    (home / ".aegis" / "config.json").write_text('{"v": 1, "drivers": {"rs": "python3 .aegis/drivers/rust_ast.py"}}')
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))
    return proj


def test_check_ast_drivers_python3_slot_resolves_without_python3_on_path(tmp_path, monkeypatch, capsys):
    """#144: python.org installs on Windows ship no python3.exe; the driver runs
    on the interpreter running aegis, so doctor must not report it broken."""
    from aegis_cli.doctor import _check_ast_drivers
    proj = _rust_project_with_python3_driver(tmp_path, monkeypatch)

    assert _check_ast_drivers(proj) is True
    out = capsys.readouterr().out
    assert "AST driver (.rs): python3 resolvable" in out
    assert sys.executable in out


def test_check_ast_drivers_python3_slot_unresolvable_without_any_interpreter(tmp_path, monkeypatch, capsys):
    from aegis_cli.doctor import _check_ast_drivers
    proj = _rust_project_with_python3_driver(tmp_path, monkeypatch)
    monkeypatch.setattr(sys, "executable", "")

    assert _check_ast_drivers(proj) is False
    assert "executable 'python3' not found on PATH" in capsys.readouterr().out


def test_check_precommit_hook_all_branches(tmp_path, capsys):
    from aegis_cli.doctor import _check_precommit_hook
    git_dir = tmp_path / ".git" / "hooks"
    git_dir.mkdir(parents=True)
    hook_file = git_dir / "pre-commit"

    # 1. Non-aegis hook
    hook_file.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    assert _check_precommit_hook(tmp_path) is None

    # 2. Current hook
    from aegis_cli.hooks.management import generate_hook_block
    hook_file.write_text("#!/bin/sh\n" + generate_hook_block(sys.executable), encoding="utf-8")
    hook_file.chmod(0o755)  # git skips a hook it cannot execute
    assert _check_precommit_hook(tmp_path) is True
    assert "Pre-commit hook is current" in capsys.readouterr().out

    # 2b. Format 4 resolved aegis through PATH and the repo: outdated now
    hook_file.write_text("#!/bin/sh\n# >>> aegis pre-commit >>>\n# aegis-hook-format: 4\naegis check --hook\n# <<< aegis pre-commit <<<\n", encoding="utf-8")
    assert _check_precommit_hook(tmp_path) is False
    assert "Pre-commit hook uses an old block" in capsys.readouterr().out

    # 3. Old hook format
    hook_file.write_text("#!/bin/sh\n# >>> aegis pre-commit >>>\nsoma checkpoint --pre-commit\n# <<< aegis pre-commit <<<\n", encoding="utf-8")
    assert _check_precommit_hook(tmp_path) is False
    assert "Pre-commit hook uses an old block" in capsys.readouterr().out


def test_doctor_json_mode_and_warning_counts(tmp_path, monkeypatch, capsys):
    """doctor supports --json, prints 'aegis doctor', tallies warnings, and includes Fix: lines."""
    import json

    (tmp_path / ".aegis" / "rules").mkdir(parents=True)

    monkeypatch.chdir(tmp_path)
    # 1. Text mode with no served rules -> fails with Fix: remediation and warning/fail summary
    rc_text = run_doctor(argparse.Namespace())
    assert rc_text == 1
    out_text = capsys.readouterr().out
    assert "aegis doctor — running health checks" in out_text
    assert "Fix:" in out_text
    assert "warning" in out_text and "failed" in out_text

    # 2. JSON mode -> valid JSON with zero ANSI codes
    _governed(tmp_path)
    rc_json = run_doctor(argparse.Namespace(json=True))
    assert rc_json == 0
    raw_json = capsys.readouterr().out
    assert "\x1b[" not in raw_json
    payload = json.loads(raw_json)
    assert payload["checks_ok"] is True
    assert payload["summary"]["passed"] >= 5
    assert "warnings" in payload["summary"]
    assert payload["summary"]["failed"] == 0
    assert {c["id"] for c in payload["checks"]} >= {"python_version", "rules", "cli_on_path"}



def test_doctor_fix_refuses_a_symlinked_config_without_crashing(tmp_path, capsys):
    from conftest import symlink_or_skip

    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "main.rs").write_text("fn main() {}")
    (proj / ".aegis").mkdir()
    outside = tmp_path / "user-config.json"
    symlink_or_skip(outside, proj / ".aegis" / "config.json")

    assert run_doctor(argparse.Namespace(drivers=True, workspace=str(proj), fix=True, yes=True)) == 1
    assert "is a symlink" in capsys.readouterr().out
    assert not outside.exists()


def test_drivers_json_is_one_json_document(tmp_path, capsys):
    import json

    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")
    rc = run_doctor(argparse.Namespace(drivers=True, json=True, workspace=str(tmp_path)))
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "aegis.doctor/v1"
    assert [c["id"] for c in payload["checks"]] == ["ast_drivers"]
    assert rc == 0 and payload["checks_ok"] is True


def test_doctor_fails_closed_on_a_rule_that_cannot_be_served(tmp_path, monkeypatch, capsys):
    _governed(tmp_path)
    (tmp_path / ".aegis" / "rules" / "invariants" / "broken.md").write_text("---\nid: [unclosed\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert run_doctor(argparse.Namespace()) == 1
    assert "cannot be served" in capsys.readouterr().out
