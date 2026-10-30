"""Language setup is informative and never trusts package scripts as commands."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from aegis_cli.cli import main

_NODE = shutil.which("node")


@pytest.fixture
def project(tmp_path, monkeypatch):
    root = tmp_path / 'project with spaces'
    root.mkdir()
    monkeypatch.setenv('PATH', str(tmp_path / 'empty-bin'))
    return root


def _init(root, capsys, *extra):
    assert main(['init', '--workspace', str(root), '--yes', '--no-hooks', '--rules', 'minimal', *extra]) == 0
    return capsys.readouterr().out


def test_init_reports_each_language_and_suggests_vitest_without_writing_user_config(project, capsys):
    (project / 'go.mod').write_text('module example.com/app\ngo 1.21\n')
    (project / 'Cargo.toml').write_text('[package]\nname="app"\n')
    (project / 'main.py').write_text('value = 1\n')
    (project / 'tsconfig.json').write_text('{}')
    (project / 'package.json').write_text(json.dumps({'devDependencies': {'vitest': '1'}, 'scripts': {'test': 'touch WRONG'}}))
    user = Path.home() / '.aegis' / 'config.json'
    assert not user.exists()
    out = _init(project, capsys, '--ci')
    for language in ('python', 'typescript', 'javascript', 'go', 'rust'):
        assert f'  {language}: parser ' in out
    assert 'pack 7; tests pytest; coverage coverage.py' in out
    assert 'pack 5; tests not configured; coverage not configured' in out
    assert 'pack 4; tests go test (default); coverage coverprofile (default)' in out
    assert 'Suggested user configuration' in out and '~/.aegis/config.json' in out
    assert str(project / 'node_modules/vitest/vitest.mjs') in out
    assert '--reporter=junit' in out and '--outputFile={junit}' in out
    assert 'touch WRONG' not in out and not user.exists()
    config = json.loads((project / '.aegis/config.json').read_text())
    assert config['ast']['packaged_drivers'] == ['go']
    assert 'tests' not in config
    assert (project / '.github/workflows/aegis.yml').read_text().count('actions/setup-go@') == 2


def test_doctor_capabilities_use_user_settings_and_preserve_native_parser_status(project, capsys):
    (project / 'main.ts').write_text('const value = 1;\n')
    (project / 'main.rs').write_text('fn main() {}\n')
    user = Path.home() / '.aegis/config.json'
    user.parent.mkdir(parents=True, exist_ok=True)
    user.write_text(json.dumps({'v': 1, 'tests': {'languages': {'ts': {'command': ['node', 'custom runner']}}},
                                'coverage': {'languages': {'rust': {'command': 'cargo llvm-cov'}}}}))
    before = user.read_bytes()
    assert main(['doctor', '--drivers', '--workspace', str(project)]) == 0
    out = capsys.readouterr().out
    assert 'typescript: parser in-process; pack 5; tests user command; coverage not configured' in out
    assert 'rust: parser in-process; pack 2;' in out and 'tests cargo test (default); coverage user command' in out
    assert 'native Rust (in-process)' in out
    assert user.read_bytes() == before


def test_repository_test_commands_are_not_presented_as_user_configuration(project, capsys):
    (project / 'main.ts').write_text('const value = 1;\n')
    (project / '.aegis').mkdir()
    (project / '.aegis/config.json').write_text(json.dumps({'v': 1, 'tests': {'languages': {'ts': {'command': 'repo-selected'}}}}))
    assert main(['doctor', '--drivers', '--workspace', str(project)]) == 0
    out = capsys.readouterr().out
    assert 'tests not configured' in out and 'repo-selected' not in out


@pytest.mark.parametrize('package', ['{bad', '[]', '{"devDependencies": []}', '{"scripts":{"test":"vitest; touch WRONG"}}'])
def test_package_data_cannot_invent_a_runner_suggestion(project, capsys, package):
    (project / 'package.json').write_text(package)
    out = _init(project, capsys)
    assert 'Suggested user configuration' not in out
    assert 'touch WRONG' not in out


def test_linked_package_metadata_is_not_read_for_suggestions(project, tmp_path, capsys):
    package = tmp_path / 'outside.json'
    package.write_text('{"devDependencies":{"vitest":"1"}}')
    (project / 'package.json').symlink_to(package)
    out = _init(project, capsys)
    assert 'Suggested user configuration' not in out


def test_jest_without_junit_reports_the_missing_reporter(project, capsys):
    (project / 'package.json').write_text('{"devDependencies":{"jest":"1"}}')
    out = _init(project, capsys)
    assert 'Jest needs jest-junit' in out
    assert 'Suggested user configuration' not in out


def test_existing_workflow_is_preserved_when_go_is_enabled(project, capsys):
    (project / 'go.mod').write_text('module example.com/app\n')
    target = project / '.github/workflows/aegis.yml'
    target.parent.mkdir(parents=True)
    target.write_text('name: User workflow\non: push\n')
    before = target.read_bytes()
    _init(project, capsys, '--ci')
    assert target.read_bytes() == before


def test_jest_suggestion_keeps_paths_as_argv_and_sets_junit_contract(project, tmp_path):
    import subprocess

    from aegis_cli.language_capabilities import runner_suggestion

    # A real Node process exercises only our fixed bootstrap; no third-party Jest install.
    node = _NODE
    if node is None:
        pytest.skip('Node is needed to execute the suggested bootstrap')
    (project / 'package.json').write_text('{"devDependencies":{"jest":"1","jest-junit":"1"}}')
    lines = runner_suggestion(project)
    command = json.loads(lines[1])['tests']['languages']['ts']['command']
    assert command[0] == 'node'
    assert command[4] == str(project / 'node_modules/jest/bin/jest.js')
    assert '--outputFile={junit}' not in command
    target = Path(command[4])
    target.parent.mkdir(parents=True)
    target.write_text("console.log(JSON.stringify({argv:process.argv,report:process.env.JEST_JUNIT_OUTPUT_FILE,"
                      "files:process.env.JEST_JUNIT_ADD_FILE_ATTRIBUTE,errors:process.env.JEST_JUNIT_REPORT_TEST_SUITE_ERRORS}));")
    report = str(tmp_path / 'report with spaces.xml')
    argv = [node] + [report if item == '{junit}' else 'src/a.test.ts' if item == '{files}' else item for item in command[1:]]
    result = subprocess.run(argv, cwd=project, text=True, capture_output=True, timeout=10, check=True)
    observed = json.loads(result.stdout)
    assert observed['report'] == report and observed['files'] == observed['errors'] == 'true'
    assert observed['argv'][1:] == command[4:-1] + ['src/a.test.ts']


@pytest.mark.parametrize('command', [[], 7, '', ['node', ''], ['node', 4]])
def test_capability_invalid_command_is_visible(project, command):
    from aegis_cli.language_capabilities import capability_lines

    (project / 'main.ts').write_text('const x = 1;\n')
    user = Path.home() / '.aegis/config.json'
    user.parent.mkdir(parents=True, exist_ok=True)
    user.write_text(json.dumps({'v': 1, 'tests': {'languages': {'ts': {'command': command}}}}))
    assert 'tests invalid configuration' in '\n'.join(capability_lines(project))


def test_oversized_package_json_does_not_supply_a_suggestion(project):
    from aegis_cli.language_capabilities import runner_suggestion

    (project / 'package.json').write_bytes(b' ' * ((1 << 20) + 1))
    assert runner_suggestion(project) == ['  Runner suggestion unavailable: package.json exceeds 1 MiB']


def test_python_uses_global_command_settings_not_an_invented_language_key(project):
    from aegis_cli.language_capabilities import capability_lines

    (project / 'main.py').write_text('value = 1\n')
    user = Path.home() / '.aegis/config.json'
    user.parent.mkdir(parents=True, exist_ok=True)
    user.write_text(json.dumps({'v': 1, 'tests': {'languages': {'python': {'command': 'ignored'}}},
                                'coverage': {'command': 'ignored global', 'languages': {'python': {'command': 'ignored'}}}}))
    assert capability_lines(project) == ['  python: parser in-process; pack 7; tests pytest; coverage coverage.py']
    user.write_text(json.dumps({'v': 1, 'tests': {'command': ['python', 'runner.py']}}))
    assert capability_lines(project) == [
        '  python: parser in-process; pack 7; tests user command (all languages); '
        'coverage unavailable (tests.command is not pytest-based)'
    ]
    user.write_text(json.dumps({'v': 1, 'tests': {'command': ['python', '-m', 'pytest']}}))
    assert 'coverage coverage.py' in '\n'.join(capability_lines(project))


def test_native_coverage_ignores_unsupported_global_coverage_command(project):
    from aegis_cli.language_capabilities import capability_lines

    (project / 'main.ts').write_text('const value = 1;\n')
    user = Path.home() / '.aegis/config.json'
    user.parent.mkdir(parents=True, exist_ok=True)
    user.write_text(json.dumps({'v': 1, 'coverage': {'command': 'ignored global'}}))
    assert 'coverage not configured' in '\n'.join(capability_lines(project))
