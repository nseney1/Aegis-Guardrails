"""Unit tests for AST Driver Runner, confinement, and external driver invocation."""
from __future__ import annotations

import json
from pathlib import Path
import pytest
import shutil
import sys

from aegis_core.ast.runner import (
    ASTDriverError,
    ASTDriverRegistry,
    ASTDriverRunner,
    ASTDriverTimeoutError,
    NoDriverConfiguredError,
)
from aegis_core.ast.schema import NormalizedAST
from aegis_core.skills.slots import SlotRegistry


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path_factory, monkeypatch):
    """parse_file consults ~/.aegis/config.json; a developer's own driver config must not run here."""
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))


def test_native_python_fast_path(tmp_path):
    py_file = tmp_path / "hello.py"
    py_file.write_text("def greet(): return 'hi'", encoding="utf-8")

    runner = ASTDriverRunner()
    result = runner.parse_file(py_file, workspace_root=tmp_path)
    assert isinstance(result, NormalizedAST)
    assert result.language == "python"
    assert len(result.definitions) == 1
    assert result.definitions[0].name == "greet"


def test_external_driver_subprocess_invocation(tmp_path):
    # Create a mock driver script that outputs valid NormalizedAST JSON
    driver_script = tmp_path / "mock_driver.py"
    driver_code = """
import sys, json

target = sys.argv[1]
result = {
    "version": "1.0",
    "language": "typescript",
    "file_path": target,
    "definitions": [{"name": "mockFunc", "kind": "function", "line": 5, "is_exported": True}],
    "call_sites": [],
    "imports": [],
    "mutation_points": []
}
print(json.dumps(result))
"""
    driver_script.write_text(driver_code, encoding="utf-8")

    target_ts = tmp_path / "app.external"
    target_ts.write_text("export function mockFunc() {}", encoding="utf-8")

    registry = ASTDriverRegistry()
    registry.register_driver(".external", f"{sys.executable} {driver_script}")

    runner = ASTDriverRunner(registry=registry)
    result = runner.parse_file(target_ts, workspace_root=tmp_path)

    assert isinstance(result, NormalizedAST)
    assert result.language == "typescript"
    assert result.definitions[0].name == "mockFunc"


def test_external_driver_timeout(tmp_path):
    driver_script = tmp_path / "sleep_driver.py"
    driver_script.write_text("import time; time.sleep(5)", encoding="utf-8")

    target_ts = tmp_path / "slow.external"
    target_ts.write_text("// slow", encoding="utf-8")

    registry = ASTDriverRegistry()
    registry.register_driver(".external", f"{sys.executable} {driver_script}")

    runner = ASTDriverRunner(registry=registry)
    with pytest.raises(ASTDriverTimeoutError, match="timed out"):
        runner.parse_file(target_ts, workspace_root=tmp_path, timeout=0.2)


def test_external_driver_crash_fails_closed(tmp_path):
    driver_script = tmp_path / "failing_driver.py"
    driver_script.write_text("import sys; sys.stderr.write('Fatal crash'); sys.exit(2)", encoding="utf-8")

    target_ts = tmp_path / "fail.external"
    target_ts.write_text("// fail", encoding="utf-8")

    registry = ASTDriverRegistry()
    registry.register_driver(".external", f"{sys.executable} {driver_script}")

    runner = ASTDriverRunner(registry=registry)
    with pytest.raises(ASTDriverError, match="failed with exit code 2"):
        runner.parse_file(target_ts, workspace_root=tmp_path)


def test_no_driver_configured_raises_expected_error(tmp_path):
    target_rs = tmp_path / "main.external"
    target_rs.write_text("fn main() {}", encoding="utf-8")

    runner = ASTDriverRunner()
    with pytest.raises(NoDriverConfiguredError, match="No AST driver configured for extension '.external'"):
        runner.parse_file(target_rs, workspace_root=tmp_path)


def test_workspace_config_only_selects_packaged_drivers(tmp_path):
    """A repo .aegis/config.json cannot name driver commands (H5, D10): it can only opt
    in to an extension's packaged driver; any driver command it names is dropped."""
    config = tmp_path / ".aegis" / "config.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        '{"v": 1, "ast": {"packaged_drivers": ["go"]}, '
        '"drivers": {"go": "go run ./ast_parser.go"}, "ast_driver": "generic-driver"}',
        encoding="utf-8",
    )

    slot_reg = SlotRegistry.load(tmp_path)
    assert slot_reg.get_ast_driver(".go") == "go run .aegis/drivers/go_ast.go"
    assert slot_reg.get_ast_driver(".rs") is None
    assert slot_reg.get_ast_driver(".py") is None  # Python is native


def test_split_command_windows(monkeypatch):
    from aegis_core.ast.runner import _split_command
    with monkeypatch.context() as m:
        m.setattr("aegis_core.ast.runner.os.name", "nt")
        cmd = r'"C:\Program Files\nodejs\node.exe" "D:\my project\driver.js"'
        parts = _split_command(cmd)
        assert parts == [r"C:\Program Files\nodejs\node.exe", r"D:\my project\driver.js"]

        cmd_unquoted = r"C:\Python312\python.exe D:\driver.py"
        parts2 = _split_command(cmd_unquoted)
        assert parts2 == [r"C:\Python312\python.exe", r"D:\driver.py"]


RUST_DRIVER = "must-not-execute-legacy-rust-driver"


@pytest.mark.parametrize("interpreter", ["python3", "python"])
def test_python_driver_runs_when_interpreter_name_is_not_on_path(tmp_path, monkeypatch, interpreter):
    """A python.org install on Windows has no python3.exe (#144); the driver
    must still run, using the interpreter that is running soma."""
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))
    source = tmp_path / "lib.rs"
    source.write_text("fn alpha() {}\nfn beta() { alpha(); }\n", encoding="utf-8")

    registry = ASTDriverRegistry({".rs": f"{interpreter} {RUST_DRIVER}"})
    result = ASTDriverRunner(registry=registry).parse_file(source, workspace_root=tmp_path)

    assert result.language == "rust"
    assert {"alpha", "beta"} <= {d.name for d in result.definitions}


def test_resolve_driver_executable_deterministic_tokens(tmp_path, monkeypatch):
    from aegis_core.ast.runner import resolve_driver_executable
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))
    monkeypatch.chdir(empty_bin)

    # Python tokens resolve to the active interpreter regardless of PATH
    assert resolve_driver_executable("python3") == sys.executable
    assert resolve_driver_executable("python3.exe") == sys.executable
    assert resolve_driver_executable("python") == sys.executable
    assert resolve_driver_executable("PYTHON") == sys.executable
    assert resolve_driver_executable("{python}") == sys.executable
    assert resolve_driver_executable("node") is None

    monkeypatch.setattr(sys, "executable", "")
    assert resolve_driver_executable("python3") is None
    assert resolve_driver_executable("{python}") is None


def test_in_process_rust_driver_execution(tmp_path):
    """Verify built-in Rust AST driver executes in-process with zero subprocess overhead."""
    source = tmp_path / "lib.rs"
    source.write_text("pub fn calculate(x: i32) -> i32 { x * 2 }\n", encoding="utf-8")

    registry = ASTDriverRegistry({".rs": "{python} .aegis/drivers/rust_ast.py"})
    runner = ASTDriverRunner(registry=registry)
    result = runner.parse_file(source, workspace_root=tmp_path)

    assert result.language == "rust"
    assert len(result.definitions) == 1
    assert result.definitions[0].name == "calculate"
    assert result.definitions[0].is_exported is True
