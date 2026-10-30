"""The native 2 MiB advisory is separate from syntax and staged-index failures."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from aegis_core import card
from aegis_core.ast.policy import ASTExtractionError, extract_normalized_ast
from aegis_core.ast.runner import ASTDriverError, ASTDriverRunner
from aegis_core.verification import runner, security_pack
from tests.conftest import symlink_or_skip


def source(root, size, extension='ts'):
    target = root / ('app.' + extension)
    target.write_bytes(b'//' + b'x' * (size - 2))
    return target


def rule(root, extension='ts'):
    rules = root / '.aegis/rules/invariants'
    rules.mkdir(parents=True)
    (rules / 'blocked.md').write_text('---\nid: blocked\ntype: invariant\nenforcement: gate\n'
        f'hypothesis: No unsafe calls.\ntarget_paths: ["*.{extension}"]\nforbid_ast:\n  calls: [eval]\n---\n# Blocked\n',
        encoding='utf-8')


def test_exact_utf8_native_limit_and_one_byte_over(tmp_path):
    target = source(tmp_path, 2 * 1024 * 1024)
    assert not ASTDriverRunner().parse_file(target, workspace_root=tmp_path).call_sites
    with target.open('ab') as stream:
        stream.write(b'x')
    with pytest.raises(ASTDriverError) as error:
        ASTDriverRunner().parse_file(target, workspace_root=tmp_path)
    assert error.value.reason == 'too_large'


def test_oversized_native_file_is_advisory_for_rules_structural_checks_and_t7(tmp_path):
    target = source(tmp_path, 2 * 1024 * 1024 + 1)
    rule(tmp_path)
    rows = runner.run_layer1([target.name], str(tmp_path), fast_mode=True, reviewed=False)
    assert runner.gate_verdict(rows, strict=True) is True
    assert 'unverified' in runner.format_summary(rows, strict=True)
    assert any('unverified too_large' in row.detail for row in rows)
    assert any('doctor' in row.detail for row in rows)
    pack = security_pack.evaluate_security_pack(tmp_path, [target.name], {})
    assert pack['passed'] is True and pack['violations'] == []
    assert any(row.get('reason') == 'too_large' for row in pack['unverified_findings'])


def test_card_exposes_the_advisory_instead_of_reporting_full_verification(tmp_path):
    source(tmp_path, 2 * 1024 * 1024 + 1)
    rule(tmp_path)
    data = card.build(tmp_path).as_dict()
    assert data['layer1']['failed'] == 0
    assert any('too_large' in detail for detail in data['layer1']['checks_that_could_not_run'])


def test_native_lexical_error_still_blocks(tmp_path):
    target = tmp_path / 'app.ts'
    target.write_text('/* unterminated', encoding='utf-8')
    rule(tmp_path)
    rows = runner.run_layer1([target.name], str(tmp_path), fast_mode=True, reviewed=False)
    assert runner.gate_verdict(rows) is False
    with pytest.raises(ASTExtractionError) as error:
        extract_normalized_ast(target, workspace_root=tmp_path)
    assert 'too_large' not in error.value.reason


def test_multibyte_supplied_source_uses_the_utf8_limit(tmp_path):
    text = '//' + 'é' * ((2 * 1024 * 1024 - 2) // 2)
    assert not extract_normalized_ast(tmp_path / 'virtual.ts', code=text).call_sites
    with pytest.raises(ASTExtractionError) as error:
        extract_normalized_ast(tmp_path / 'virtual.ts', code=text + 'x')
    assert error.value.__cause__.reason == 'too_large'


def test_native_depth_error_still_blocks(tmp_path):
    target = tmp_path / 'app.ts'
    target.write_text('(' * 257 + '1' + ')' * 257, encoding='utf-8')
    rule(tmp_path)
    rows = runner.run_layer1([target.name], str(tmp_path), fast_mode=True, reviewed=False)
    assert runner.gate_verdict(rows) is False


@pytest.mark.parametrize('extension', ['ts', 'tsx', 'js', 'mjs'])
def test_t7_checks_only_size_and_containment_for_native_js_until_js_rules_ship(tmp_path, extension):
    # T7 has no JS/TS rule pack yet, so a source the native parser rejects is not a T7 failure
    # (a user forbid_ast rule targeting it still fails closed: test_native_lexical_error_still_blocks;
    # structural checks such as call_graph still fail closed, as they do on a Python SyntaxError).
    target = tmp_path / ('app.' + extension)
    target.write_text('/* unterminated', encoding='utf-8')
    pack = security_pack.evaluate_security_pack(tmp_path, [target.name], {})
    assert pack == {'passed': True, 'violations': [], 'exempted_test_findings': [], 'unverified_findings': []}
    rows = runner.run_layer1([target.name], str(tmp_path), fast_mode=True, reviewed=False)
    assert [row.tool for row in rows if not row.verdict] == ['call_graph']


def test_staged_index_limit_still_fails_closed_above_five_mib(tmp_path):
    def git(*args):
        subprocess.run(['git', '-c', 'user.name=fixture', '-c', 'user.email=t@example.invalid', *args],
                       cwd=tmp_path, capture_output=True, check=True, timeout=5)

    git('init', '-q')
    rule(tmp_path)
    git('add', '.aegis')
    git('commit', '-qm', 'fixture')
    target = source(tmp_path, 5 * 1024 * 1024 + 1)
    git('add', target.name)
    rows = runner.run_layer1_on_index([target.name], str(tmp_path))
    assert runner.gate_verdict(rows) is False
    assert any(not row.verdict and 'staged content' in row.detail for row in rows)


def test_go_over_limit_is_advisory_before_any_compiler_or_driver_process(tmp_path, monkeypatch):
    root = tmp_path / 'project'
    root.mkdir()
    target = source(root, 2 * 1024 * 1024 + 1, 'go')
    rule(root, 'go')
    (root / '.aegis/config.json').write_text('{"v":1,"ast":{"packaged_drivers":["go"]}}')
    tools = tmp_path / 'tools'
    tools.mkdir()
    compiler = tools / ('go.exe' if os.name == 'nt' else 'go')
    compiler.write_bytes(b'process boundary fixture; never execute')
    compiler.chmod(0o700)
    monkeypatch.setenv('PATH', str(tools) + os.pathsep + os.environ.get('PATH', ''))
    invoked = []
    real_run, real_popen = subprocess.run, subprocess.Popen

    def checked_run(argv, *args, **kwargs):
        if Path(str(argv[0])).name.lower().startswith(('go.', 'go_ast-')) or str(argv[0]) == str(compiler):
            invoked.append(list(argv))
            raise AssertionError('oversized Go invoked a compiler or driver')
        return real_run(argv, *args, **kwargs)

    def checked_popen(argv, *args, **kwargs):
        if Path(str(argv[0])).name.lower().startswith(('go.', 'go_ast-')) or str(argv[0]) == str(compiler):
            invoked.append(list(argv))
            raise AssertionError('oversized Go invoked a compiler or driver')
        return real_popen(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, 'run', checked_run)
    monkeypatch.setattr(subprocess, 'Popen', checked_popen)
    with pytest.raises(ASTDriverError) as error:
        ASTDriverRunner().parse_file(target, workspace_root=root)
    assert error.value.reason == 'too_large'
    rows = runner.run_layer1([target.name], str(root), fast_mode=True, reviewed=False)
    assert runner.gate_verdict(rows, strict=True) is True
    pack = security_pack.evaluate_security_pack(root, [target.name], {})
    assert any(row.get('reason') == 'too_large' for row in pack['unverified_findings'])
    assert invoked == []


def test_go_at_exact_limit_is_not_classified_as_too_large(tmp_path, monkeypatch):
    target = source(tmp_path, 2 * 1024 * 1024, 'go')
    monkeypatch.setenv('PATH', '')
    with pytest.raises(ASTDriverError) as error:
        ASTDriverRunner().parse_file(target, workspace_root=tmp_path)
    assert getattr(error.value, 'reason', None) != 'too_large'


def test_security_pack_refuses_sources_resolving_outside_workspace(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    outside = tmp_path / 'outside.py'
    outside.write_text('eval("outside fixture")', encoding='utf-8')
    symlink_or_skip(outside, root / 'app.py')
    result = security_pack.evaluate_security_pack(root, ['app.py'], {})
    assert result['violations'] == []
    assert result['unverified_findings'][0]['reason'] == 'source escapes workspace'
