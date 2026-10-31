"""Native Rust dispatch and fail-closed boundaries through public entry points."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from aegis_cli.cli import main
from aegis_core import card, benchmark_ast
from aegis_core.ast.detect import provision_ast_driver_slots
from aegis_core.ast.policy import ASTExtractionError, evaluate_forbid_ast_structured, extract_normalized_ast
from aegis_core.ast.runner import ASTDriverError, ASTDriverRegistry, ASTDriverRunner
from aegis_core.skills.slots import SlotRegistry
from aegis_core.verification import runner, security_pack


def test_native_rust_ignores_commands_and_malformed_repository_config(tmp_path, monkeypatch):
    source = tmp_path / 'lib.rs'
    source.write_text('use std::process::Command as Cmd; fn run() { Cmd::new("sh"); }', encoding='utf-8')
    (tmp_path / '.aegis').mkdir()
    (tmp_path / '.aegis/config.json').write_text('{invalid config', encoding='utf-8')
    monkeypatch.setenv('PATH', '')
    registry = ASTDriverRegistry({'.rs': 'must-never-execute'})
    tree = ASTDriverRunner(registry).parse_file(source, workspace_root=tmp_path)
    assert tree.language == 'rust'
    assert [site.target for site in tree.call_sites] == ['Cmd::new']
    assert tree.call_sites[0].args == {'#0': "'sh'"}
    assert tree.metadata['capabilities'] == ['allow_comments', 'args', 'decorators', 'test_module']


def test_native_rust_description_and_extensions_need_no_workspace():
    registry = ASTDriverRegistry({'.rs': 'must-never-execute'})
    assert registry.resolve_driver('.rs') == 'native Rust (in-process)'
    assert '.rs' in registry.get_configured_extensions()
    slots = SlotRegistry({'ast_driver_rs': 'must-never-execute', 'ast_driver': 'fallback'})
    assert slots.get_ast_driver('.rs') is None
    assert 'ast_driver_rs' not in slots.to_dict()
    assert '.rs' in slots.get_configured_extensions()
    assert slots.get_ast_driver('.external') == 'fallback'


def test_rust_provisioning_needs_no_opt_in_or_repository_write(tmp_path):
    (tmp_path / 'Cargo.toml').write_text('[package]\nname="app"\n', encoding='utf-8')
    assert provision_ast_driver_slots(tmp_path) == ({}, [])
    assert not (tmp_path / '.aegis').exists()


def test_rust_supplied_source_overrides_the_file(tmp_path):
    source = tmp_path / 'lib.rs'
    source.write_text('fn safe() {}', encoding='utf-8')
    tree = extract_normalized_ast(source, code='fn run() { std::process::Command::new("sh"); }')
    assert [site.target for site in tree.call_sites] == ['std::process::Command::new']
    assert source.read_text() == 'fn safe() {}'


def test_rust_invalid_utf8_is_a_typed_syntax_error(tmp_path):
    source = tmp_path / 'lib.rs'
    source.write_bytes(b'fn run() {}\xff')
    with pytest.raises(ASTDriverError, match='invalid UTF-8') as error:
        ASTDriverRunner().parse_file(source, workspace_root=tmp_path)
    assert error.value.reason == 'syntax'


@pytest.mark.parametrize('supplied', [False, True])
def test_rust_native_size_limit_counts_utf8_bytes(tmp_path, supplied):
    source = tmp_path / 'lib.rs'
    text = '//' + 'é' * ((2 * 1024 * 1024 - 2) // 2)
    if supplied:
        assert not extract_normalized_ast(source, code=text).call_sites
        with pytest.raises(ASTExtractionError, match='2 MiB') as error:
            extract_normalized_ast(source, code=text + 'x')
        assert error.value.__cause__.reason == 'too_large'
    else:
        source.write_text(text, encoding='utf-8')
        assert not ASTDriverRunner().parse_file(source, workspace_root=tmp_path).call_sites
        with source.open('ab') as stream:
            stream.write(b'x')
        with pytest.raises(ASTDriverError, match='2 MiB') as error:
            ASTDriverRunner().parse_file(source, workspace_root=tmp_path)
        assert error.value.reason == 'too_large'


def test_rust_oversized_source_is_advisory_but_lexical_errors_block(tmp_path):
    rules = tmp_path / '.aegis/rules/invariants'
    rules.mkdir(parents=True)
    (rules / 'blocked.md').write_text('---\nid: blocked\ntype: invariant\nenforcement: gate\n'
        'hypothesis: No unsafe calls.\ntarget_paths: ["*.rs"]\nforbid_ast:\n  calls: [unsafe_call]\n---\n# Blocked\n',
        encoding='utf-8')
    source = tmp_path / 'lib.rs'
    source.write_bytes(b'//' + b'x' * (2 * 1024 * 1024))
    rows = runner.run_layer1([source.name], str(tmp_path), fast_mode=True, reviewed=False)
    assert runner.gate_verdict(rows, strict=True) is True
    assert any('unverified too_large' in row.detail for row in rows)
    pack = security_pack.evaluate_security_pack(tmp_path, [source.name], {})
    assert pack['passed'] is True and pack['violations'] == []
    assert any(row.get('reason') == 'too_large' for row in pack['unverified_findings'])
    source.write_text('fn run() { /* unterminated', encoding='utf-8')
    rows = runner.run_layer1([source.name], str(tmp_path), fast_mode=True, reviewed=False)
    assert runner.gate_verdict(rows) is False


def test_rust_doctor_and_card_are_ready_without_a_toolchain(tmp_path, monkeypatch, capsys):
    (tmp_path / 'lib.rs').write_text('fn run() {}', encoding='utf-8')
    monkeypatch.setenv('PATH', '')
    assert main(['doctor', '--drivers', '--workspace', str(tmp_path), '--json']) == 0
    doc = json.loads(capsys.readouterr().out)
    assert any('native Rust (in-process)' in line for row in doc['checks'] for line in row['detail'])
    driver, = card.build(tmp_path).as_dict()['drivers']
    assert driver['status'] == 'ready' and driver['driver'] == 'native Rust (in-process)'


def test_python_parsing_does_not_import_native_rust(tmp_path):
    source = tmp_path / 'app.py'
    source.write_text('value = 1', encoding='utf-8')
    script = ('import json,sys; sys.path.insert(0,sys.argv[1]); '
              'from aegis_core.ast.runner import ASTDriverRunner; '
              'ASTDriverRunner().parse_file(sys.argv[2],workspace_root=sys.argv[3]); '
              'print(json.dumps([m for m in sys.modules if m.startswith("aegis_core.ast.drivers.rust")]))')
    result = subprocess.run([sys.executable, '-I', '-S', '-c', script, str(Path.cwd()), str(source), str(tmp_path)],
                            capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == []


def test_rust_benchmark_requires_its_own_import_and_call_witness():
    from aegis_core.ast.drivers.rust import parse

    case = next(row for row in benchmark_ast.load_corpus()['cases'] if row['language'] == 'rust')
    tree = parse(case['source'], case['path'])
    assert benchmark_ast.check_witness(tree, 'rust')['calls'] > 0
    corrupted = parse(case['source'].replace('codec::max', 'wrong::max'), case['path'])
    with pytest.raises(benchmark_ast.ASTBenchmarkError, match='rust extraction witness failed'):
        benchmark_ast.check_witness(corrupted, 'rust')


@pytest.mark.parametrize('statement,bound', [
    ('use std::process;', 'process'),
    ('use std::process::{self, exit};', 'process'),
    ('use std::process as p;', 'p'),
    ('use std::process::{self as p, exit};', 'p'),
])
def test_rust_whole_module_bindings_preserve_import_and_call_matching(statement, bound):
    source = statement + ' fn run() { ' + bound + '::Command::new("sh"); }'
    tree = extract_normalized_ast('src/lib.rs', code=source)
    found = evaluate_forbid_ast_structured(tree, {'imports': ['process'], 'calls': ['std::process::Command::new']}, source=source)
    assert [(row['kind'], row['pattern']) for row in found] == [
        ('imports', 'process'), ('calls', 'std::process::Command::new')]
    assert not evaluate_forbid_ast_structured(tree, {'calls': ['std::process::process::Command::new']}, source=source)


def test_a_distinct_rust_member_alias_is_not_the_module_it_is_named_after():
    source = 'use std::process::Child as process; fn run() { process::new(); }'
    tree = extract_normalized_ast('src/lib.rs', code=source)
    assert not evaluate_forbid_ast_structured(tree, {'imports': ['process'], 'calls': ['std::process::new']}, source=source)
    found = evaluate_forbid_ast_structured(tree, {'imports': ['Child'], 'calls': ['std::process::Child::new']}, source=source)
    assert [row['kind'] for row in found] == ['imports', 'calls']


def test_namespace_imports_in_js_keep_the_existing_prefix_semantics():
    source = 'import * as io from "fs/promises"; io.readFile("x");'
    tree = extract_normalized_ast('src/app.js', code=source)
    assert not evaluate_forbid_ast_structured(tree, {'imports': ['promises']}, source=source)
    found = evaluate_forbid_ast_structured(tree, {'imports': ['fs/promises']}, source=source)
    assert len(found) == 1 and found[0]['kind'] == 'imports'


def test_ac6_grouped_command_alias_is_a_confirmed_shell_finding(tmp_path):
    source = tmp_path / 'lib.rs'
    source.write_text('use std::process::{Command as Cmd, Stdio};\nfn run() { Cmd::new("sh"); }\n',
                      encoding='utf-8')
    result = security_pack.evaluate_security_pack(tmp_path, [source.name], {})
    assert result['passed'] is False
    assert [(row['rule_id'], row['kind'], row['pattern'], row['line'])
            for row in result['violations']] == [
        ('sec-rs-command-shell', 'calls', 'std::process::Command::new', 2),
    ]
    assert result['unverified_findings'] == []
    assert result['exempted_test_findings'] == []


def test_ac6_absolute_command_matches_import_and_call_without_use():
    source = 'fn run() {\n std::process::Command::new("sh");\n}\n'
    tree = extract_normalized_ast('src/lib.rs', code=source)
    found = evaluate_forbid_ast_structured(
        tree, {'imports': ['std::process'], 'calls': ['std::process::Command::new']}, source=source)
    assert [(row['kind'], row['pattern'], row['line'], row['unknown'], row['override'])
            for row in found] == [
        ('imports', 'std::process', 2, False, None),
        ('calls', 'std::process::Command::new', 2, False, None),
    ]
