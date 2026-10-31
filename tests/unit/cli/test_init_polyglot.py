"""Tests for soma init zero-touch polyglot AST driver provisioning."""
import argparse
from pathlib import Path
import pytest

from aegis_cli.init import run_init
from aegis_core.skills.slots import SlotRegistry
from aegis_core.workspace.base import Workspace


def test_init_uses_native_rust_without_a_driver_opt_in(tmp_path: Path, monkeypatch):
    # Setup simulated Rust project
    (tmp_path / "Cargo.toml").write_text("[package]\nname = 'rust_app'\n", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()

    # Stub input to auto-accept
    monkeypatch.setattr("builtins.input", lambda _: "y")

    args = argparse.Namespace(
        ws=Workspace.for_init(tmp_path),
        _project_root=tmp_path,
        dry_run=False,
        rules="minimal",
        yes=True,
        force=True,
    )

    exit_code = run_init(args)
    assert exit_code == 0

    # Native Rust needs no packaged-driver opt-in in .aegis/config.json
    config = tmp_path / ".aegis" / "config.json"
    assert '"rs"' not in config.read_text(encoding="utf-8")

    registry = SlotRegistry.load(tmp_path)
    rs_driver = registry.get_ast_driver(".rs")
    assert rs_driver is None
    assert ".rs" in registry.get_configured_extensions()

    # Nothing is staged in the repository: Rust parsing is built in
    assert not (tmp_path / ".aegis" / "drivers").exists()


def test_init_provisions_polyglot_ts_go_drivers(tmp_path: Path, monkeypatch):
    # Setup simulated mixed Go + TypeScript project
    (tmp_path / "go.mod").write_text("module example.com/app\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name": "frontend"}', encoding="utf-8")
    (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")
    (tmp_path / ".git").mkdir()

    monkeypatch.setattr("builtins.input", lambda _: "y")

    args = argparse.Namespace(
        ws=Workspace.for_init(tmp_path),
        _project_root=tmp_path,
        dry_run=False,
        rules="minimal",
        yes=True,
        force=True,
    )

    exit_code = run_init(args)
    assert exit_code == 0

    registry = SlotRegistry.load(tmp_path)
    assert registry.get_ast_driver(".ts") is None
    assert '.ts' in registry.get_configured_extensions()
    assert registry.get_ast_driver(".go") is not None
    assert not (tmp_path / ".aegis" / "drivers").exists()
