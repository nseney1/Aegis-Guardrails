"""Tests for aegis init zero-touch polyglot AST driver provisioning."""
import argparse
import json
from pathlib import Path
import pytest

from aegis_cli.init import run_init
from aegis_core.skills.slots import SlotRegistry
from aegis_core.workspace.base import Workspace


@pytest.mark.parametrize('runner', ['vitest', 'jest'])
def test_init_json_dry_run_retains_language_guidance(tmp_path, capsys, runner):
    from aegis_cli.cli import main

    project = tmp_path / 'project with spaces'
    project.mkdir()
    for name, content in [('main.py', 'value = 1\n'), ('go.mod', 'module example.com/app\n'),
                          ('Cargo.toml', '[package]\nname="app"\n'), ('main.ts', 'const x = 1;\n')]:
        (project / name).write_text(content, encoding='utf-8')
    dependencies = {runner: '1', 'jest-junit': '1'}
    (project / 'package.json').write_text(json.dumps({
        'devDependencies': dependencies, 'scripts': {'test': 'UNTRUSTED_SCRIPT'},
    }), encoding='utf-8')
    user = Path.home() / '.aegis/config.json'
    user.parent.mkdir(parents=True, exist_ok=True)
    user.write_text(json.dumps({'v': 1, 'tests': {'languages': {
        'ts': {'command': ['node', 'PRIVATE_USER_COMMAND']},
    }}}), encoding='utf-8')
    before = user.read_bytes()
    argv = ['init', '--workspace', str(project), '--dry-run', '--no-hooks', '--rules', 'minimal']
    assert main(argv + ['--json']) == 0
    output = capsys.readouterr().out
    data = json.loads(output)
    capabilities = {entry['language']: entry for entry in data['language_capabilities']}
    assert set(capabilities) == {'python', 'javascript', 'typescript', 'go', 'rust'}
    assert capabilities['python'] == {'language': 'python', 'parser': 'in-process',
                                      'security_rules': 7, 'tests': 'pytest', 'coverage': 'coverage.py'}
    assert capabilities['typescript']['tests'] == 'user command'
    assert capabilities['go']['coverage'] == 'coverprofile (default)'
    suggestion = data['runner_suggestion']
    assert suggestion['status'] == 'suggested' and suggestion['runner'] == runner
    command = suggestion['configuration']['tests']['languages']['ts']['command']
    assert command[0] == 'node' and command[-1] == '{files}'
    assert str(project / ('node_modules/vitest/vitest.mjs' if runner == 'vitest'
                          else 'node_modules/jest/bin/jest.js')) in command
    assert 'UNTRUSTED_SCRIPT' not in output and 'PRIVATE_USER_COMMAND' not in output
    assert data['status'] == 'ok' and data['dry_run'] is True
    assert main(argv) == 0
    human = capsys.readouterr().out
    for entry in capabilities.values():
        assert (f"{entry['language']}: parser {entry['parser']}; pack {entry['security_rules']}; "
                f"tests {entry['tests']}; coverage {entry['coverage']}") in human
    assert json.loads(next(line for line in human.splitlines() if line.lstrip().startswith('{"tests":'))) == suggestion['configuration']
    assert user.read_bytes() == before and not (project / '.aegis').exists()


@pytest.mark.parametrize(('package', 'status', 'message'), [
    (None, 'none', None),
    ('{bad UNTRUSTED', 'unavailable', 'package.json cannot be read as JSON'),
    ('[]', 'unavailable', 'package.json must be an object'),
    ('{"dependencies":{"jest":"1"}}', 'needs_reporter', 'Jest needs jest-junit'),
    ('{"scripts":{"test":"UNTRUSTED"}}', 'none', None),
])
def test_init_json_dry_run_runner_diagnostics(tmp_path, capsys, package, status, message):
    from aegis_cli.cli import main

    if package is not None:
        (tmp_path / 'package.json').write_text(package, encoding='utf-8')
    assert main(['init', '--workspace', str(tmp_path), '--dry-run', '--json', '--no-hooks']) == 0
    output = capsys.readouterr().out
    data = json.loads(output)
    suggestion = data['runner_suggestion']
    assert suggestion['status'] == status and suggestion['configuration'] is None
    assert 'UNTRUSTED' not in output
    if message:
        assert message in ' '.join(suggestion['messages'])


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
