"""Tests for aegis doctor AST driver diagnostics and --fix auto-repair."""
import argparse
from pathlib import Path
import pytest

from aegis_cli import doctor, doctor_base
from aegis_cli.cli import main
from aegis_cli.doctor import run_doctor, _check_ast_drivers
from aegis_core.skills.slots import SlotRegistry


@pytest.fixture(autouse=True)
def isolated_hosts(tmp_path, monkeypatch):
    """Doctor reads host configs under HOME and may start a host CLI: keep both fake."""
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    def no_host_cli(argv, cwd, timeout):
        raise OSError("host CLIs are not run in these tests")

    monkeypatch.setattr(doctor, "_run_host_cli", no_host_cli)
    # Host CLIs and python3 are looked up in an empty private directory, never on this
    # machine's PATH (doctor's own lookup).
    no_programs = tmp_path / "no-programs"
    no_programs.mkdir()
    real_which, real_skipped = doctor_base.which, doctor_base.only_skipped
    monkeypatch.setattr(doctor_base, "which", lambda name, path=None, outside=None:
                        real_which(name, str(no_programs), outside))
    monkeypatch.setattr(doctor_base, "only_skipped", lambda name, path=None, outside=None, base=None:
                        real_skipped(name, str(no_programs), outside, base))
    return home


def test_doctor_detects_unconfigured_polyglot_language(tmp_path: Path):
    # Setup Rust project without .aegis/config.json
    (tmp_path / "Cargo.toml").write_text("[package]\nname = 'app'\n", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

    # Doctor check without fix returns False / warns
    ok = _check_ast_drivers(tmp_path, fix=False)
    assert ok is False


def test_doctor_fix_provisions_missing_drivers(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text("[package]\nname = 'app'\n", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

    # Doctor check with fix=True automatically provisions slots
    ok = _check_ast_drivers(tmp_path, fix=True)
    assert ok is True

    # The repo now opts in to the packaged rust driver; nothing is staged
    registry = SlotRegistry.load(tmp_path)
    assert registry.get_ast_driver(".rs") is not None
    assert not (tmp_path / ".aegis" / "drivers").exists()


def test_doctor_cli_fix_flag(tmp_path: Path, monkeypatch):
    (tmp_path / "go.mod").write_text("module example.com/app\n", encoding="utf-8")
    (tmp_path / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    (tmp_path / ".aegis").mkdir()

    args = argparse.Namespace(_project_root=tmp_path, fix=True, yes=True)

    monkeypatch.chdir(tmp_path)
    run_doctor(args)
    registry = SlotRegistry.load(tmp_path)
    assert registry.get_ast_driver(".go") is not None


def test_doctor_fix_output_reports_provisioned_driver_status(tmp_path: Path, capsys):
    (tmp_path / "Cargo.toml").write_text("[package]\nname = 'app'\n", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

    ok = _check_ast_drivers(tmp_path, fix=True)
    assert ok is True
    out = capsys.readouterr().out
    assert "AST driver (.rs)" in out
    assert "AST drivers: native Python stdlib (in-process)" not in out


def test_doctor_drivers_flag_only_runs_ast_checks(tmp_path, capsys):
    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")
    code = main(["doctor", "--drivers", "--workspace", str(tmp_path)])
    assert code == 0

    out = capsys.readouterr().out
    assert "AST driver health check" in out
    assert "native Python stdlib" in out
    # Full doctor checks (e.g. MCP launcher, rules, zero-dependencies) should not run
    assert "MCP launcher" not in out
    assert "zero-dependency runtime operational" not in out
