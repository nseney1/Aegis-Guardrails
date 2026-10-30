"""Tests for polyglot language detection and zero-touch AST driver provisioning."""
import json
from pathlib import Path

from aegis_core.ast.detect import (
    detect_project_languages,
    resolve_recommended_drivers,
    provision_ast_driver_slots,
)
from aegis_core.skills.slots import SlotRegistry


def test_native_js_has_no_external_recipe_and_needs_no_provisioning(tmp_path: Path):
    from aegis_core.ast.detect import LANGUAGE_DEFINITIONS, names_packaged_driver

    (tmp_path / 'index.ts').write_text('export const value = 1', encoding='utf-8')
    for language in ('typescript', 'javascript'):
        assert LANGUAGE_DEFINITIONS[language]['driver_slot'] is None
        assert LANGUAGE_DEFINITIONS[language]['default_command'] is None
        assert LANGUAGE_DEFINITIONS[language]['driver_filename'] is None
        assert not names_packaged_driver('.aegis/drivers/None', LANGUAGE_DEFINITIONS[language])
    assert provision_ast_driver_slots(tmp_path) == ({}, [])
    assert not (tmp_path / '.aegis').exists()


def test_native_js_ignores_legacy_slot_commands_and_opt_ins(tmp_path: Path):
    config = tmp_path / '.aegis/config.json'
    config.parent.mkdir()
    config.write_text('{"v":1,"ast":{"packaged_drivers":["ts","tsx","js","go","rs"]}}')
    registry = SlotRegistry.load(tmp_path)
    assert not registry.warnings
    assert registry.get_ast_driver('.go') is not None
    assert registry.get_ast_driver('.rs') is not None
    assert registry.get_ast_driver('.ts') is None
    assert not any('ts_ast' in value for value in registry.to_dict().values())
    explicit = SlotRegistry({'ast_driver_ts': 'must-not-execute', 'ast_driver': 'external-fallback'})
    assert explicit.get_ast_driver('.ts') is None
    assert 'ast_driver_ts' not in explicit.to_dict()
    assert explicit.get_ast_driver('.external') == 'external-fallback'
    assert {'.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'} <= explicit.get_configured_extensions()


def test_detect_project_languages_python(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='foo'\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")

    detected = detect_project_languages(tmp_path)
    assert "python" in detected
    assert detected["python"]["manifests"] == ["pyproject.toml"]
    assert ".py" in detected["python"]["extensions"]


def test_detect_project_languages_rust(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text("[package]\nname='foo'\n", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

    detected = detect_project_languages(tmp_path)
    assert "rust" in detected
    assert detected["rust"]["manifests"] == ["Cargo.toml"]
    assert ".rs" in detected["rust"]["extensions"]


def test_detect_project_languages_typescript_and_javascript(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"name": "foo"}', encoding="utf-8")
    (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")
    (tmp_path / "index.ts").write_text("const x: number = 1;", encoding="utf-8")

    detected = detect_project_languages(tmp_path)
    assert "typescript" in detected
    assert ".ts" in detected["typescript"]["extensions"]


def test_detect_project_languages_go(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module example.com/foo\n\ngo 1.21\n", encoding="utf-8")
    (tmp_path / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")

    detected = detect_project_languages(tmp_path)
    assert "go" in detected
    assert detected["go"]["manifests"] == ["go.mod"]
    assert ".go" in detected["go"]["extensions"]


def test_detect_polyglot_repository(tmp_path: Path):
    # Mixed Rust backend + TypeScript frontend
    (tmp_path / "Cargo.toml").write_text("[package]\nname='core'\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name": "frontend"}', encoding="utf-8")
    (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")

    detected = detect_project_languages(tmp_path)
    assert "rust" in detected
    assert "typescript" in detected


def test_resolve_recommended_drivers():
    languages = {
        "rust": {"extensions": [".rs"]},
        "typescript": {"extensions": [".ts", ".tsx"]},
        "go": {"extensions": [".go"]},
        "python": {"extensions": [".py"]},
    }
    drivers = resolve_recommended_drivers(languages)
    # Python is handled in-process; no external slot needed
    assert "ast_driver_py" not in drivers
    # External parsers retain opt-in commands; native JS needs none.
    assert "ast_driver_rs" in drivers
    assert "ast_driver_ts" not in drivers
    assert "ast_driver_go" in drivers


def test_provision_ast_driver_slots(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text("[package]\nname='foo'\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name": "web"}', encoding="utf-8")
    (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")

    slots, created_files = provision_ast_driver_slots(tmp_path)
    assert set(slots) == {"ast_driver_rs"}

    # The opt-ins live in .aegis/config.json and SlotRegistry reads them back
    config = tmp_path / ".aegis" / "config.json"
    assert created_files == [str(config)]
    registry = SlotRegistry.load(tmp_path)
    assert registry.get_ast_driver(".rs") is not None
    assert registry.get_ast_driver(".ts") is None
    # Nothing is staged in the repository: the packaged templates are what runs
    assert not (tmp_path / ".aegis" / "drivers").exists()


def test_provision_keeps_existing_config_keys(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text("[package]\nname='foo'\n", encoding="utf-8")
    config = tmp_path / ".aegis" / "config.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"v": 1, "hosts": ["codex-cli"], "jit": {"max_tokens": 900}}), encoding="utf-8")

    provision_ast_driver_slots(tmp_path)

    assert json.loads(config.read_text(encoding="utf-8")) == {
        "v": 1, "hosts": ["codex-cli"], "jit": {"max_tokens": 900}, "ast": {"packaged_drivers": ["rs"]},
    }
    assert SlotRegistry.load(tmp_path).get_ast_driver(".rs") == "{python} .aegis/drivers/rust_ast.py"


def test_provision_does_not_overwrite_unparseable_config(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text("[package]\nname='foo'\n", encoding="utf-8")
    config = tmp_path / ".aegis" / "config.json"
    config.parent.mkdir(parents=True)
    config.write_text("{hand-edited, not yet valid\n", encoding="utf-8")

    _, created_files = provision_ast_driver_slots(tmp_path)

    assert config.read_text(encoding="utf-8") == "{hand-edited, not yet valid\n"
    assert created_files == []


def test_provision_dry_run_writes_nothing(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")

    slots, created_files = provision_ast_driver_slots(tmp_path, dry_run=True)

    assert slots == {"ast_driver_go": "go run .aegis/drivers/go_ast.go"}
    assert created_files == []
    assert not (tmp_path / ".aegis").exists()


def test_provision_tolerates_an_unknown_extension_already_listed(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text("[package]\nname='foo'\n", encoding="utf-8")
    config = tmp_path / ".aegis" / "config.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"v": 1, "ast": {"packaged_drivers": ["md"]}}), encoding="utf-8")

    slots, _ = provision_ast_driver_slots(tmp_path)

    assert slots == {"ast_driver_rs": "{python} .aegis/drivers/rust_ast.py"}
    assert json.loads(config.read_text(encoding="utf-8"))["ast"]["packaged_drivers"] == ["md", "rs"]


def test_provision_merges_into_a_config_written_after_it_was_read(tmp_path: Path, monkeypatch):
    """Lost update (review B2a-6): another writer lands between the read and the locked write."""
    from aegis_core import config as config_mod

    (tmp_path / "Cargo.toml").write_text("[package]\nname = 'x'\n", encoding="utf-8")
    real_load = config_mod.RepoConfig.load

    def load_then_someone_else_writes(cls, root):
        loaded = real_load(root)
        config_mod.update_repo_config(root, lambda data: data.update(ast={"packaged_drivers": ["go"]}))
        return loaded

    monkeypatch.setattr(config_mod.RepoConfig, "load", classmethod(load_then_someone_else_writes))
    slots, written = provision_ast_driver_slots(tmp_path)

    data = json.loads((tmp_path / ".aegis" / "config.json").read_text(encoding="utf-8"))
    assert data["ast"]["packaged_drivers"] == ["go", "rs"]
    assert set(slots) == {"ast_driver_go", "ast_driver_rs"}
    assert written
