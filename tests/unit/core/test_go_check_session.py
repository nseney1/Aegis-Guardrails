"""A complete public check owns one Go process through grouping and finding enrichment."""
import json
import subprocess

import pytest

from aegis_cli.cli import main
from aegis_core import baseline
from aegis_core.ast.runner import ASTDriverRunner
from tests.unit.core.test_go_integration import go_workspace  # noqa: F401


def prepared(state, *, same_basename=False):
    script = state.compiler.parent / 'protocol.py'
    script.write_text(script.read_text().replace(
        "'target': 'blocked', 'line': 2, 'column': 0}",
        "'target': 'blocked', 'line': 2, 'column': 0}, {'target': 'second', 'line': 3, 'column': 0}"),
        encoding='utf-8')
    names = ['a/main.go', 'b/main.go'] if same_basename else ['a.go', 'b.go']
    for name in names:
        path = state.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('package fixture\nfunc A() { blocked() }\nfunc B() { second() }\n', encoding='utf-8')
    rules = state.root / '.aegis/rules/invariants'
    rules.mkdir(parents=True)
    (rules / 'blocked.md').write_text(
        '---\nid: blocked\ntype: invariant\nenforcement: gate\n'
        'hypothesis: Production Go does not call blocked or second.\n'
        'target_paths: ["*.go"]\nforbid_ast:\n  calls: [blocked, second]\n---\n# Blocked\n', encoding='utf-8')
    return names


@pytest.mark.parametrize('same_basename', [False, True])
def test_grouped_layer1_and_enrichment_share_one_go_session(go_workspace, same_basename):
    state = go_workspace
    names = prepared(state, same_basename=same_basename)
    pairs, sources = baseline.run_fast(state.root, names, reviewed=False)
    collected = baseline.collect(pairs, sources)
    assert len(collected.findings) == 4 and collected.blocked == ()
    assert len(state.processes) == 1
    assert [argv[1] for argv, _ in state.calls].count('build') == 1


@pytest.mark.parametrize('mode', ['card', 'plain', 'hook'])
def test_cli_check_uses_one_warm_process_and_keeps_all_findings(go_workspace, capsys, mode):
    state = go_workspace
    names = prepared(state, same_basename=True)
    baseline.write(state.root, [])
    if mode == 'hook':
        for argv in (['git', 'init', '-q'], ['git', 'add', '--', *names, '.aegis']):
            subprocess.run(argv, cwd=state.root, check=True, capture_output=True)
    with ASTDriverRunner() as runner:
        runner.parse_file(state.root / names[0], workspace_root=state.root)
    state.calls.clear()
    state.processes.clear()
    args = ['check', '--workspace', str(state.root), '--json']
    args += ['--card'] if mode == 'card' else ['--hook'] if mode == 'hook' else names
    code = main(args)
    output = capsys.readouterr()
    data = json.loads(output.out)
    assert output.err == ''
    if mode == 'card':
        assert code == 0 and data['layer1']['findings'] == 4
    else:
        assert code == 1 and not data['passed']
        assert len(data['baseline']['new']) == 4
    assert len(state.processes) == 1
    assert all(argv[1] != 'build' for argv, _ in state.calls)
