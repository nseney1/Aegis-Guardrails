"""Native JS dispatch through the public runner and source extraction surfaces."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from aegis_core.ast.policy import evaluate_forbid_ast_structured, extract_normalized_ast
from aegis_core.ast.runner import ASTDriverRegistry, ASTDriverRunner

EXTENSIONS = ('.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs')


@pytest.mark.parametrize('extension', EXTENSIONS)
def test_native_js_runs_without_config_or_an_external_program(tmp_path, monkeypatch, extension):
    target = tmp_path / ('app' + extension)
    target.write_text('export function run() { eval("danger") }', encoding='utf-8')
    (tmp_path / '.aegis').mkdir()
    (tmp_path / '.aegis/config.json').write_text('{invalid config', encoding='utf-8')
    monkeypatch.setenv('PATH', '')
    registry = ASTDriverRegistry({extension: 'must-never-execute'})
    tree = ASTDriverRunner(registry).parse_file(target, workspace_root=tmp_path)
    assert [definition.name for definition in tree.definitions] == ['run']
    assert any(site.target == 'eval' for site in tree.call_sites)
    assert tree.metadata['capabilities'] == ['allow_comments', 'args', 'decorators']


@pytest.mark.parametrize('extension', EXTENSIONS)
def test_native_descriptions_and_default_extensions_need_no_workspace(extension):
    registry = ASTDriverRegistry({extension: 'must-never-execute'})
    assert 'in-process' in registry.resolve_driver(extension)
    assert extension in registry.get_configured_extensions()


@pytest.mark.parametrize('extension', EXTENSIONS)
def test_supplied_js_source_is_parsed_instead_of_the_file(tmp_path, extension):
    target = tmp_path / ('app' + extension)
    target.write_text('harmless()', encoding='utf-8')
    tree = extract_normalized_ast(target, code='eval("changed source")')
    assert [site.target for site in tree.call_sites] == ['eval']
    assert target.read_text() == 'harmless()'


def test_python_parsing_does_not_import_native_js(tmp_path):
    target = tmp_path / 'app.py'
    target.write_text('value = 1', encoding='utf-8')
    script = ('import json,sys; sys.path.insert(0,sys.argv[1]); '
              'from aegis_core.ast.runner import ASTDriverRunner; '
              'ASTDriverRunner().parse_file(sys.argv[2],workspace_root=sys.argv[3]); '
              'print(json.dumps([m for m in sys.modules if m.startswith("aegis_core.ast.drivers.js")]))')
    result = subprocess.run([sys.executable, '-I', '-S', '-c', script, str(Path.cwd()), str(target), str(tmp_path)],
                            capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == []


@pytest.mark.parametrize('code', ['require(name)', 'import(name)'])
def test_dynamic_imports_reach_the_shared_unknown_evaluator(tmp_path, code):
    tree = extract_normalized_ast(tmp_path / 'virtual.ts', code=code)
    found = evaluate_forbid_ast_structured(tree, {'imports': ['child_process']}, source=code)
    assert found and all(row['unknown'] for row in found)


@pytest.mark.parametrize('code,pattern,unknown', [
    ('const cp = require(name); cp.exec("x")', 'child_process.exec', True),
    ('const cp = require("child_process"); cp[property]("x")', 'child_process.exec', True),
    ('const cp = require(name); cp.exec("x")', '.exec', False),
    ('const {exec: run} = require(name); run("x")', 'child_process.exec', True),
])
def test_real_native_uncertain_calls_reach_the_shared_evaluator(tmp_path, code, pattern, unknown):
    tree = extract_normalized_ast(tmp_path / 'virtual.ts', code=code)
    found = evaluate_forbid_ast_structured(tree, {'calls': [pattern]}, source=code)
    assert len(found) == 1 and found[0]['unknown'] is unknown
