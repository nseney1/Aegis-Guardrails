"""Tests for aegis doctor AST driver diagnostics and --fix auto-repair."""
import argparse
import json
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


@pytest.fixture
def go_project(tmp_path: Path, monkeypatch) -> Path:
    (tmp_path / "go.mod").write_text("module example.com/app\n", encoding="utf-8")
    (tmp_path / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    monkeypatch.setenv("PATH", "")  # Provisioning is tested without starting a compiler.
    return tmp_path


def test_doctor_detects_unconfigured_polyglot_language(go_project: Path, capsys):
    assert _check_ast_drivers(go_project) is False
    assert "unconfigured driver for detected source extension(s): .go" in capsys.readouterr().out
    assert not (go_project / ".aegis" / "config.json").exists()


def test_doctor_fix_provisions_missing_drivers(go_project: Path):
    rc = run_doctor(argparse.Namespace(drivers=True, workspace=str(go_project), fix=True, yes=True))
    registry = SlotRegistry.load(go_project)
    assert registry.get_ast_driver(".go") == "go run .aegis/drivers/go_ast.go"
    assert not (go_project / ".aegis" / "drivers").exists()
    assert rc == 1  # Configuration succeeds while the absent compiler remains a warning.


def test_doctor_fix_output_reports_provisioned_driver_status(go_project: Path, capsys):
    rc = run_doctor(argparse.Namespace(drivers=True, workspace=str(go_project), fix=True, yes=True))
    out = capsys.readouterr().out
    assert "enable the packaged AST drivers for .go" in out
    assert "AST driver (.go)" in out
    assert "driver_unavailable:go_missing" in out
    assert "AST drivers: native Python stdlib (in-process)" not in out
    assert rc == 1


def test_doctor_reports_native_rust_without_configuration(tmp_path: Path):
    # Rust parsing needs no .aegis/config.json
    (tmp_path / "Cargo.toml").write_text("[package]\nname = 'app'\n", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

    # The check only reports
    ok = _check_ast_drivers(tmp_path)
    assert ok is True


def test_doctor_fix_keeps_native_rust_configuration_free(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text("[package]\nname = 'app'\n", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

    # --fix has no Rust command or opt-in to provision
    rc = run_doctor(argparse.Namespace(drivers=True, workspace=str(tmp_path), fix=True, yes=True))
    assert rc == 0

    # Native Rust has no command slot and stages no driver
    registry = SlotRegistry.load(tmp_path)
    assert registry.get_ast_driver(".rs") is None
    assert not (tmp_path / ".aegis/config.json").exists()
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


def test_doctor_fix_output_reports_native_rust_status(tmp_path: Path, capsys):
    (tmp_path / "Cargo.toml").write_text("[package]\nname = 'app'\n", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

    rc = run_doctor(argparse.Namespace(drivers=True, workspace=str(tmp_path), fix=True, yes=True))
    assert rc == 0
    out = capsys.readouterr().out
    assert "enable the packaged AST drivers for .rs" not in out
    assert "native Rust (in-process)" in out
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


def _named(text, before, after):
    """The extensions a line names between ``before`` and ``after``, or none."""
    for line in text.splitlines():
        if before in line:
            return set(line.split(before, 1)[1].split(after, 1)[0].split(", "))
    return set()


@pytest.mark.parametrize("repo_drivers,user,expected", [
    (None, None, {".go"}),
    (["rs", "go"], None, set()),
    (None, {"drivers": {"rs": "rs-driver", "go": "go-driver"}}, set()),
    (None, {"slots": {"ast_driver": "any-driver"}}, set()),
    (["rs"], {"drivers": {"go": "go-driver"}}, set()),
    (None, {"drivers": {"rs": "rs-driver"}}, {".go"}),
    (["rs"], None, {".go"}),
], ids=["nothing", "repo-packaged", "user-drivers", "user-catch-all", "mixed", "user-only", "repo-only"])
def test_the_driver_check_and_the_fix_plan_agree_on_what_is_unconfigured(tmp_path, isolated_hosts, capsys,
                                                                          repo_drivers, user, expected):
    """Given main.rs and main.go and a driver configuration, When the AST check runs and
    doctor --fix --json plans, Then both name the same unconfigured extensions."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "main.rs").write_bytes(b"fn main() {}\n")
    (ws / "main.go").write_bytes(b"package main\nfunc main() {}\n")
    if repo_drivers is not None:
        (ws / ".aegis").mkdir()
        (ws / ".aegis" / "config.json").write_bytes(
            json.dumps({"v": 1, "ast": {"packaged_drivers": repo_drivers}}).encode())
    if user is not None:
        (isolated_hosts / ".aegis").mkdir()
        (isolated_hosts / ".aegis" / "config.json").write_bytes(json.dumps({"v": 1, **user}).encode())
    _check_ast_drivers(ws)
    checked = _named(capsys.readouterr().out, "unconfigured driver for detected source extension(s): ", ". Run")
    run_doctor(argparse.Namespace(workspace=str(ws), fix=True, yes=True, json=True))
    fixes = json.loads(capsys.readouterr().out)["fixes"]
    planned = set().union(*(_named(change, "enable the packaged AST drivers for ", "\n")
                            for fix in fixes if fix["action"] == "enable_packaged_ast_drivers"
                            for change in fix["changes"]))
    assert checked == planned == expected


def test_a_corrupt_repository_config_is_reported_and_fix_leaves_it_alone(tmp_path, isolated_hosts, capsys):
    ws = tmp_path / "ws"
    (ws / ".aegis").mkdir(parents=True)
    (ws / "main.rs").write_bytes(b"fn main() {}\n")
    config = ws / ".aegis" / "config.json"
    config.write_bytes(b"{corrupt")
    assert _check_ast_drivers(ws) is False
    assert ".aegis/config.json is not valid JSON" in capsys.readouterr().out
    run_doctor(argparse.Namespace(workspace=str(ws), fix=True, yes=True, json=True))
    payload = json.loads(capsys.readouterr().out)
    assert [fix for fix in payload["fixes"] if fix["action"] == "enable_packaged_ast_drivers"] == []
    assert config.read_bytes() == b"{corrupt"
