"""Ordinary and staged T7 checks share source-bound ASTs and driver processes."""
from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from aegis_core.verification import runner
from tests.unit.core.test_go_integration import go_workspace  # noqa: F401


def git(root, *args):
    return subprocess.run(['git', '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid',
                           '-c', 'commit.gpgsign=false', *args], cwd=root, check=True, capture_output=True,
                          text=True, timeout=10).stdout.strip()


def repository(root):
    git(root, 'init', '-q')
    (root / 'README').write_text('fixture', encoding='utf-8')
    git(root, 'add', '.')
    git(root, 'commit', '-qm', 'base')


def forbid_rule(root, extension, call='blocked'):
    rules = root / '.aegis/rules/invariants'
    rules.mkdir(parents=True, exist_ok=True)
    (rules / 'blocked.md').write_text(
        '---\nid: blocked\ntype: invariant\nenforcement: gate\nhypothesis: No blocked calls.\n'
        f'target_paths: ["*.{extension}"]\nforbid_ast:\n  calls: ["{call}"]\n---\n# Blocked\n', encoding='utf-8')


@pytest.mark.parametrize('extension,unsafe,safe,rid', [
    ('ts', "import cp from 'child_process'; cp.exec('x')", "const safe = 1;", 'sec-js-child-process-shell'),
    ('rs', 'fn f() { std::process::Command::new("sh"); }', 'fn f() {}', 'sec-rs-command-shell'),
])
def test_index_pack_reads_staged_unsafe_source_without_user_rules(tmp_path, extension, unsafe, safe, rid):
    repository(tmp_path)
    name = 'app.' + extension
    target = tmp_path / name
    target.write_text(unsafe, encoding='utf-8')
    git(tmp_path, 'add', name)
    target.write_text(safe, encoding='utf-8')
    rows = runner.run_layer1_on_index([name], str(tmp_path))
    assert [(r.tool, r.target, r.verdict, r.language) for r in rows if r.tool.startswith('security_pack:')] == [
        ('security_pack:' + rid, name, False, 'rust' if extension == 'rs' else 'typescript')]


@pytest.mark.parametrize('staged', [False, True])
def test_missing_go_driver_is_advisory_and_strict_blocking_without_user_rules(tmp_path, staged):
    repository(tmp_path)
    (tmp_path / 'app.go').write_text('package fixture\nfunc f() {}', encoding='utf-8')
    git(tmp_path, 'add', 'app.go')
    rows = (runner.run_layer1_on_index(['app.go'], str(tmp_path)) if staged else
            runner.run_layer1(['app.go'], str(tmp_path), fast_mode=True, reviewed=False))
    assert runner.gate_verdict(rows) is True
    assert runner.gate_verdict(rows, strict=True) is False
    notes = [row for row in rows if 'no_driver:.go' in row.detail]
    assert len(notes) == 1 and notes[0].language == 'go'
    assert 'security pack' in notes[0].detail


@pytest.mark.parametrize('staged', [False, True])
def test_configured_go_driver_failure_blocks_t7_without_user_rules(go_workspace, staged):
    state = go_workspace
    state.version = 'go1.20.9'
    repository(state.root)
    (state.root / 'app.go').write_text('package fixture', encoding='utf-8')
    git(state.root, 'add', 'app.go')
    rows = (runner.run_layer1_on_index(['app.go'], str(state.root)) if staged else
            runner.run_layer1(['app.go'], str(state.root), fast_mode=True, reviewed=False))
    failed = [row for row in rows if row.tool == 'security_pack' and not row.verdict]
    assert len(failed) == 1 and '1.21' in failed[0].detail
    assert failed[0].language == 'go'
    assert not state.processes


@pytest.mark.parametrize('staged', [False, True])
def test_head_base_and_user_rules_share_one_packaged_go_process(go_workspace, staged):
    state = go_workspace
    script = state.compiler.parent / 'protocol.py'
    text = script.read_text()
    text = text.replace('def tree(path):', '''def tree(path):
    from pathlib import Path
    with open(Path(__file__).with_suffix('.requests'), 'a') as log:
        log.write(path + '\\n')
    calls = [{'target': 'blocked', 'line': 2}]
    for line, source in enumerate(Path(path).read_text().splitlines(), 1):
        if 'Command("sh")' in source:
            calls.append({'target': 'os/exec.Command', 'line': line, 'args': {'#0': "'sh'"}})
''')
    text = text.replace("'call_sites': [{'target': 'blocked', 'line': 2, 'column': 0}],", "'call_sites': calls,")
    script.write_text(text, encoding='utf-8')
    forbid_rule(state.root, 'go')
    target = state.root / 'app.go'
    base = 'package fixture\nfunc f() { blocked() }\nfunc old() { exec.Command("sh") }\n'
    target.write_text(base, encoding='utf-8')
    repository(state.root)
    target.write_text(base + 'func fresh() { exec.Command("sh") }\n', encoding='utf-8')
    git(state.root, 'add', 'app.go')
    if staged:
        target.write_text('package fixture\nfunc safe() {}\n', encoding='utf-8')
    rows = (runner.run_layer1_on_index(['app.go'], str(state.root)) if staged else
            runner.run_layer1(['app.go'], str(state.root), fast_mode=True, reviewed=False))
    assert [(row.tool, row.lines) for row in rows if row.tool.startswith('security_pack:')] == [
        ('security_pack:sec-go-exec-shell', [4])]
    assert len([row for row in rows if row.tool == 'forbid_ast:blocked']) == 1
    assert len(state.processes) == 1
    assert [argv[1] for argv, _ in state.calls].count('build') == 1
    paths = script.with_suffix('.requests').read_text().splitlines()
    assert len(paths) == 2 and len(set(paths)) == 2
    assert Path(paths[0]).name == 'app.go' and Path(paths[1]).name == 'base.go'
    assert not Path(paths[1]).exists()


def test_legacy_base_native_findings_are_suppressed_and_new_calls_keep_language(tmp_path):
    target = tmp_path / 'app.rs'
    base = 'fn f() {\n std::process::Command::new("sh");\n}\n'
    target.write_text(base, encoding='utf-8')
    repository(tmp_path)
    target.write_text(base + 'fn g() { std::process::Command::new("sh"); }\n', encoding='utf-8')
    rows = runner.run_layer1(['app.rs'], str(tmp_path), fast_mode=True, reviewed=False)
    assert [(r.tool, r.lines, r.language) for r in rows if r.tool.startswith('security_pack:')] == [
        ('security_pack:sec-rs-command-shell', [4], 'rust')]


def test_user_rule_owns_its_pack_site_without_suppressing_other_calls(tmp_path):
    repository(tmp_path)
    forbid_rule(tmp_path, 'ts', 'child_process.exec')
    (tmp_path / 'app.ts').write_text("import cp from 'child_process'; cp.exec('x'); eval(input)", encoding='utf-8')
    rows = runner.run_layer1(['app.ts'], str(tmp_path), fast_mode=True, reviewed=False)
    assert len([r for r in rows if r.tool == 'forbid_ast:blocked' and not r.verdict]) == 1
    assert [r.tool for r in rows if r.tool.startswith('security_pack:')] == ['security_pack:sec-js-eval']


def test_unknown_native_findings_are_advisory_with_language(tmp_path):
    repository(tmp_path)
    (tmp_path / 'app.ts').write_text("import crypto from 'crypto'; crypto.createHash(algorithm)", encoding='utf-8')
    rows = runner.run_layer1(['app.ts'], str(tmp_path), fast_mode=True, reviewed=False)
    notes = [row for row in rows if row.tool == 'security_pack']
    assert len(notes) == 1 and notes[0].language == 'typescript'
    assert notes[0].verdict and 'unverified (advisory): sec-js-weak-hash' in notes[0].detail


@pytest.mark.parametrize('extension', ['ts', 'rs', 'go'])
def test_oversized_pack_source_is_visible_when_index_snapshot_cannot_read_it(tmp_path, extension):
    repository(tmp_path)
    name = 'large.' + extension
    (tmp_path / name).write_bytes(b'//' + b'x' * (5 * 1024 * 1024))
    git(tmp_path, 'add', name)
    rows = runner.run_layer1_on_index([name], str(tmp_path))
    assert runner.gate_verdict(rows, strict=True)
    assert any('unverified too_large' in row.detail and row.target == name for row in rows)
