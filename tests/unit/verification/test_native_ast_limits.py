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


@pytest.mark.parametrize('count', [1, 3])
def test_card_exposes_the_advisory_instead_of_reporting_full_verification(tmp_path, capsys, count):
    import json

    from aegis_cli.cli import main

    for number in range(count):
        source(tmp_path, 2 * 1024 * 1024 + 1).rename(tmp_path / f'bundle{number}.ts')
    rule(tmp_path)
    data = card.build(tmp_path).as_dict()
    layer1 = data['layer1']
    assert (layer1['checked'], layer1['passed'], layer1['failed'], layer1['pass_rate']) == (count, count, 0, 1.0)
    assert layer1['findings'] == 0
    assert any('too_large' in detail for detail in layer1['checks_that_could_not_run'])
    assert layer1['not_analyzed'] == [
        {'path': f'bundle{number}.ts', 'reason': 'size limit (too_large; exceeds 2 MiB)'}
        for number in range(count)
    ]
    assert not any('does not count them' in note for note in data['notes'])
    assert data['notes'][-1] == f'{count} size advisory check(s): AST coverage is incomplete (aegis check shows why).'
    assert not any('fail aegis check' in note for note in data['notes'])
    assert main(['check', '--card', '--workspace', str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert f'100% of {count} files without blocking findings' in output
    assert f'AST coverage: {count} file(s) not analyzed' in output
    assert 'bundle0.ts: size limit' in output
    assert 'all analyzed' not in output
    assert main(['check', '--card', '--workspace', str(tmp_path), '--json']) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['layer1'] == layer1


def test_card_separates_coverage_from_findings_in_a_mixed_workspace(tmp_path):
    source(tmp_path, 2 * 1024 * 1024 + 1)
    rule(tmp_path)
    (tmp_path / 'good.ts').write_text('export const x = 1;\n', encoding='utf-8')
    (tmp_path / 'bad.ts').write_text('eval("1");\n', encoding='utf-8')
    layer1 = card.build(tmp_path).as_dict()['layer1']
    assert (layer1['checked'], layer1['passed'], layer1['failed'], layer1['pass_rate']) == (3, 2, 1, 0.6667)
    assert layer1['findings'] == 1
    assert layer1['not_analyzed'] == [
        {'path': 'app.ts', 'reason': 'size limit (too_large; exceeds 2 MiB)'}
    ]


@pytest.mark.parametrize('limit_mib', [1, 2])
def test_card_size_reason_tracks_the_native_source_limit(tmp_path, monkeypatch, limit_mib):
    from aegis_core.ast import runner as ast_runner

    source(tmp_path, 2 * 1024 * 1024 + 1)
    rule(tmp_path)
    monkeypatch.setattr(ast_runner, 'SOURCE_LIMIT_BYTES', limit_mib * 1024 * 1024)
    layer1 = card.build(tmp_path).as_dict()['layer1']
    assert layer1['not_analyzed'] == [
        {'path': 'app.ts', 'reason': f'size limit (too_large; exceeds {limit_mib} MiB)'}
    ]
    assert layer1['checks_that_could_not_run'] == [
        f'ast_unverified: unverified too_large: app.ts exceeds {limit_mib} MiB; '
        'use target_paths to exclude generated bundles (aegis doctor)'
    ]


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
    # Native packs now ship: retain this migration control and require the parser
    # failure to remain visible in both the pack and the full Layer 1 entry point.
    target = tmp_path / ('app.' + extension)
    target.write_text('/* unterminated', encoding='utf-8')
    pack = security_pack.evaluate_security_pack(tmp_path, [target.name], {})
    assert pack['violations'] == [] and pack['exempted_test_findings'] == []
    assert pack['unverified_findings'] == [{
        'rule_id': '', 'file': target.name, 'line': 0, 'kind': 'file', 'status': 'unverified',
        'reason': 'JSLexError: syntax:unterminated_comment at line 1, offset 0', 'severity': 'high',
    }]
    rows = runner.run_layer1([target.name], str(tmp_path), fast_mode=True, reviewed=False)
    assert [row.tool for row in rows if not row.verdict] == ['call_graph', 'security_pack']


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
