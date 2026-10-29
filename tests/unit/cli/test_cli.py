"""aegis CLI skeleton: every command has help, dispatch goes through the registry."""
from pathlib import Path
import os
import subprocess
import sys

import pytest

import aegis_cli.cli as cli


from aegis_cli.registry import get_default_registry

SUBCOMMANDS = sorted(c.name for c in get_default_registry().list_commands())


class TestCLIImport:
    """Verify the CLI module is importable without side effects."""

    def test_cli_importable(self):
        from aegis_cli.cli import main
        assert callable(main)

    def test_cli_build_parser(self):
        from aegis_cli.cli import _build_parser
        parser = _build_parser()
        assert parser.prog == "aegis"


class TestCLIHelp:
    """Verify --help works for the main command and all subcommands."""

    def test_main_help_exits_zero(self):
        from aegis_cli.cli import main
        # No args → prints help, returns 0
        assert main([]) == 0

    @pytest.mark.parametrize("cmd", SUBCOMMANDS)
    def test_subcommand_help_exits_zero(self, cmd):
        from aegis_cli.cli import main
        with pytest.raises(SystemExit) as exc_info:
            main([cmd, "--help"])
        assert exc_info.value.code == 0

    def test_top_level_help_lists_the_commands_by_category(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli.main(["--help"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "usage: aegis <command> [options]" in out
        assert "Setup & Environment:" in out and "Daily Workflow & Verification:" in out
        for name in SUBCOMMANDS:
            assert f"\n  {name} " in out

    def test_a_subcommand_help_is_that_command_s_own_usage(self, capsys):
        with pytest.raises(SystemExit):
            cli.main(["status", "--help"])
        out = capsys.readouterr().out
        assert out.startswith("usage: aegis status ")
        assert "--compliance" in out
        assert "Setup & Environment:" not in out


class TestCLIDispatch:
    """Verify subcommands dispatch to their handlers."""

    @pytest.mark.parametrize("cmd,extra_args", [
        ("init", ["--dry-run", "--yes"]),
        ("status", []),
        ("check", ["--dry-run"]),
        ("rule", ["list"]),
        ("doctor", []),
        ("scan", ["src/app.py"]),
        ("hook", ["status"]),
    ])
    def test_subcommand_runs_without_crash(self, cmd, extra_args, capsys, monkeypatch, tmp_path):
        from aegis_cli import doctor
        from aegis_cli.cli import main

        def no_host_cli(argv, cwd, timeout):  # doctor asks codex; never a real host in tests
            raise OSError("host CLIs are not run in tests")

        monkeypatch.setattr(doctor, "_run_host_cli", no_host_cli)
        # A workspace of its own: run from the checkout, scan recorded activity in the repository's .aegis/state.
        (tmp_path / ".aegis").mkdir()
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        result = main([cmd] + extra_args)
        assert result in (0, 1)
        captured = capsys.readouterr()
        assert 'Traceback' not in captured.err

    @pytest.mark.parametrize("argv", [["agent", "scan"], ["agent", "scan", "a.py"], ["agent", "scan", "a.py", "b.py"]])
    def test_a_removed_command_action_gets_its_own_pointer_whatever_follows(self, argv, capsys):
        assert cli.main(argv) == 2
        assert capsys.readouterr().err == "aegis agent scan was removed in v4: use aegis scan\n"

    def test_without_argv_main_reads_the_process_arguments(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["aegis", "agent", "scan"])
        assert cli.main() == 2
        assert capsys.readouterr().err == "aegis agent scan was removed in v4: use aegis scan\n"

    def test_unknown_command_returns_nonzero(self):
        from aegis_cli.cli import main
        # argparse treats unknown subcommand as args.command = None? No,
        # it raises SystemExit(2) for unrecognized args.
        with pytest.raises(SystemExit) as exc_info:
            main(["nonexistent_command_xyz"])
        assert exc_info.value.code == 2


class TestCLIEntryPoint:
    """Verify the installed entry point resolves correctly."""

    def test_aegis_dash_dash_help_via_subprocess(self):
        """Run `python -m aegis_cli.cli --help` to test without requiring
        pip install."""
        repo_root = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
        proc = subprocess.run(
            [sys.executable, "-m", "aegis_cli.cli", "--help"],
            capture_output=True, text=True, timeout=10,
            cwd=repo_root,
        )
        assert proc.returncode == 0
        assert "Aegis Governance" in proc.stdout


class TestNonUtf8Console:
    """BUG-012: a cp1252 stdout (Windows, redirected output) made `soma
    status` exit 1 with UnicodeEncodeError on its emoji."""

    def test_status_survives_cp1252_stdout(self, tmp_path):
        repo_root = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
        home = tmp_path / "home"
        home.mkdir()
        env = dict(os.environ, PYTHONIOENCODING="cp1252", PYTHONPATH=repo_root,
                   HOME=str(home), USERPROFILE=str(home))
        proc = subprocess.run(
            [sys.executable, "-m", "aegis_cli.cli", "status"],
            capture_output=True, encoding="cp1252", errors="replace",
            timeout=30, cwd=str(tmp_path), env=env,
        )
        assert "can't encode" not in proc.stderr, proc.stderr
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip()


# ── TDD Red Phase: --rules preset tests ────────────────────────────────────


def _run_init_in(tmp_path, extra_args=None):
    """Helper: invoke aegis init targeting tmp_path using a subprocess (no --host: nothing is registered)."""
    argv = [sys.executable, "-m", "aegis_cli.cli", "init", "--yes"]
    if extra_args:
        argv.extend(extra_args)

    home = tmp_path.parent / f"{tmp_path.name}-home"
    home.mkdir(exist_ok=True)
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home))
    repo_root = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
    env["PYTHONPATH"] = repo_root + (os.pathsep + env["PYTHONPATH"] if "PYTHONPATH" in env else "")
    proc = subprocess.run(argv, cwd=str(tmp_path), capture_output=True, text=True, env=env)
    return proc.returncode


def _installed_rules(tmp_path):
    """Return set of .md filenames seeded into the workspace's persona rules."""
    rules_dir = tmp_path / ".aegis" / "rules" / "personas"
    if not rules_dir.is_dir():
        return set()
    return {f.name for f in rules_dir.iterdir() if f.suffix == ".md"}


class TestRulePresetMinimal:
    """--rules minimal should install exactly 2 rules."""

    def test_init_minimal_installs_two_rules(self, tmp_path):
        """--rules minimal should install exactly providence + destructive-ops."""
        rc = _run_init_in(tmp_path, ["--rules", "minimal"])
        assert rc == 0
        installed = _installed_rules(tmp_path)
        assert installed == {"providence.md", "destructive-ops.md"}, (
            f"Expected 2 minimal rules, got {installed}"
        )


class TestRulePresetStandard:
    """--rules standard (default) should install the 5 starter rules."""

    def test_init_standard_installs_five_rules(self, tmp_path):
        """--rules standard installs 5 rules (current behavior — should PASS)."""
        rc = _run_init_in(tmp_path, ["--rules", "standard"])
        assert rc == 0
        installed = _installed_rules(tmp_path)
        assert len(installed) == 5, f"Expected 5 standard rules, got {len(installed)}: {installed}"

    def test_init_default_preset_is_standard(self, tmp_path):
        """When --rules is not specified, default to standard (5 rules)."""
        rc = _run_init_in(tmp_path)  # no --rules flag
        assert rc == 0
        installed = _installed_rules(tmp_path)
        assert len(installed) == 5, f"Default should match standard (5 rules), got {len(installed)}"


# Every shipped rule in rules/ and rules/.oracles/ except META.md (D16: the
# dogfood rules live in this repo's .aegis/rules; desktop-automation is not shipped).
FULL_PRESET = {
    "cost-optimization.md", "destructive-ops.md", "providence.md", "subagent-delegation.md",
    "architectural-tenets.md", "atomic-workstream-protocol.md", "documentation.md",
    "feature-specs.md", "git-workflow.md", "polyglot-standards.md", "tdd-protocol.md", "testing.md",
}


class TestRulePresetFull:
    """--rules full should discover and install every shipped rule."""

    def test_init_full_installs_every_shipped_rule(self, tmp_path):
        """--rules full installs exactly the shipped rules, flattened."""
        rc = _run_init_in(tmp_path, ["--rules", "full"])
        assert rc == 0
        assert _installed_rules(tmp_path) == FULL_PRESET

    def test_init_full_skips_meta_md(self, tmp_path):
        """--rules full should skip META.md and README.md."""
        _run_init_in(tmp_path, ["--rules", "full"])
        installed = _installed_rules(tmp_path)
        assert "META.md" not in installed, "META.md should be excluded from full preset"
        assert "README.md" not in installed, "README.md should be excluded from full preset"


# ── Registry-only dispatch ──────────────────────────────────────────────────


def test_main_dispatches_through_the_registry(tmp_path, monkeypatch):
    from aegis_cli.base import CommandCategory, AegisCommand
    from aegis_cli.registry import CommandRegistry

    seen = []

    class CustomTestCommand(AegisCommand):
        name = "custom-test"
        category = CommandCategory.WORKFLOW
        help = "Custom test command"

        def configure_parser(self, parser):
            parser.add_argument("--flag", action="store_true")

        def execute(self, args):
            seen.append((args.command, args.flag, args.workspace))
            return 7

    reg = CommandRegistry()
    reg.register(CustomTestCommand)
    monkeypatch.setattr(cli, "get_default_registry", lambda: reg)
    (tmp_path / ".aegis" / "rules").mkdir(parents=True)

    assert cli.main(["custom-test", "--flag", "--workspace", str(tmp_path)]) == 7
    assert seen == [("custom-test", True, str(tmp_path.resolve()))]


def test_command_exception_is_reported_and_exits_1(tmp_path, monkeypatch, capsys):
    from aegis_cli.base import CommandCategory, AegisCommand
    from aegis_cli.registry import CommandRegistry

    class BoomCommand(AegisCommand):
        name = "boom"
        category = CommandCategory.WORKFLOW
        help = "Raises"

        def configure_parser(self, parser):
            pass

        def execute(self, args):
            raise RuntimeError("kaboom")

    reg = CommandRegistry()
    reg.register(BoomCommand)
    monkeypatch.setattr(cli, "get_default_registry", lambda: reg)
    monkeypatch.chdir(tmp_path)

    assert cli.main(["boom"]) == 1
    assert capsys.readouterr().err == "Error: kaboom\n"


# ── `aegis hook run`: dispatched before the parser and the workspace attachment ──

def _governed(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    (root / ".aegis" / "rules").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    return root.resolve()


def _hook_stdin(monkeypatch, payload: dict) -> None:
    import io
    import json
    import types

    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode("utf-8"))))


def test_hook_run_decides_from_the_payload_where_no_workspace_attaches(tmp_path, monkeypatch, capsys):
    """The registered form runs from any cwd: a directory the CLI cannot attach (here an
    unmigrated .soma/) must not stop the handler, which reads the workspace from stdin."""
    ws = _governed(tmp_path)
    legacy = tmp_path / "legacy"
    (legacy / ".soma").mkdir(parents=True)
    monkeypatch.chdir(legacy)
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    _hook_stdin(monkeypatch, {"cwd": str(ws), "hook_event_name": "PreToolUse", "tool_name": "Bash",
                              "tool_input": {"command": "git reset --hard"}, "tool_use_id": "t"})
    assert cli.main(["hook", "run", "pre-tool", "--host", "claude-code"]) == 2
    out, err = capsys.readouterr()
    assert out == "" and err.startswith("aegis: blocked git-reset-hard")


def test_hook_run_never_reaches_a_usage_error(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    _hook_stdin(monkeypatch, {})
    assert cli.main(["hook", "run", "pre-tool", "--bogus"]) == 0
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("argv", [["hook", "run", "--help"], ["hook", "run", "pre-tool", "-h"]])
def test_hook_run_help_goes_through_the_parser(argv, monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exited:
        cli.main(argv)
    assert exited.value.code == 0
    assert "--host" in capsys.readouterr().out


def test_registry_does_not_retry_a_parser_type_error():
    import argparse
    from aegis_cli.base import AegisCommand, CommandCategory
    from aegis_cli.registry import CommandRegistry

    class Broken(AegisCommand):
        name = "broken"
        help = "test"
        category = CommandCategory.SETUP
        calls = 0

        def configure_parser(self, parser, parents=None):
            self.calls += 1
            if self.calls == 1:
                raise TypeError("parser implementation failed")

        def execute(self, args):
            return 0

    command = Broken()
    registry = CommandRegistry()
    registry.register(command)
    parser = argparse.ArgumentParser()
    with pytest.raises(TypeError, match="^parser implementation failed$"):
        registry.populate_subparsers(parser.add_subparsers())
    assert command.calls == 1


@pytest.mark.parametrize("position", ["before", "after"])
def test_skills_common_flags_work_on_both_sides_of_sync(position, tmp_path, capsys):
    (tmp_path / ".aegis").mkdir()
    common = ["--workspace", str(tmp_path), "--json", "--plain"]
    argv = ["skills"] + (common if position == "before" else []) + ["sync"]
    argv += common if position == "after" else []
    assert cli.main(argv + ["--host", "claude-code", "--dry-run"]) in (0, 1)
    import json
    payload = json.loads(capsys.readouterr().out)
    assert payload["source"] == "aegis skills sync"
    assert payload["scope"]["workspace"] == str(tmp_path)


@pytest.mark.parametrize("position", ["before", "after"])
def test_hook_common_flags_work_on_both_sides_of_status(position, tmp_path, capsys):
    import json
    (tmp_path / ".aegis").mkdir()
    common = ["--workspace", str(tmp_path), "--json", "--plain"]
    argv = ["hook"] + (common if position == "before" else []) + ["status"]
    argv += common if position == "after" else []
    assert cli.main(argv) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["repository_root"] == str(tmp_path)
    assert payload["is_git_repo"] is False
