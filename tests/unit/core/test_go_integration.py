"""Packaged Go sessions through the runner, with a real protocol process."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import shlex
from types import SimpleNamespace

import pytest

from aegis_core.ast.runner import ASTDriverError, ASTDriverRunner
from aegis_core.errors import PathTraversalError


DRIVER = '''import json, os, sys
def tree(path):
    return {'version': '1.0', 'language': 'go', 'file_path': path,
            'definitions': [], 'imports': [], 'mutation_points': [],
            'call_sites': [{'target': 'blocked', 'line': 2, 'column': 0}],
            'metadata': {'pid': os.getpid(), 'cwd': os.getcwd()}}
if len(sys.argv) > 1:
    print(json.dumps(tree(sys.argv[1])))
else:
    for line in sys.stdin:
        request = json.loads(line)
        if request['op'] == 'hello':
            reply = {'aegis_ast': 2, 'op': 'hello', 'driver': 'fixture',
                     'driver_version': '2.0.0', 'languages': ['go'],
                     'capabilities': ['allow_comments', 'args']}
        else:
            reply = {'op': 'parse', 'id': request['id'], 'ok': True,
                     'ast': tree(request['path'])}
        print(json.dumps(reply), flush=True)
'''


@pytest.fixture
def go_workspace(tmp_path, monkeypatch):
    home, workspace, tools = [tmp_path / name for name in ('home', 'workspace', 'tools')]
    for path in (home, workspace, tools):
        path.mkdir()
    for key in ('HOME', 'USERPROFILE', 'LOCALAPPDATA'):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv('XDG_CACHE_HOME', str(home / 'cache'))
    compiler = tools / ('go.exe' if os.name == 'nt' else 'go')
    compiler.write_bytes(b'fake compiler; intercepted at process boundary')
    compiler.chmod(0o755)
    monkeypatch.setenv('PATH', str(tools) + os.pathsep + os.environ.get('PATH', ''))
    (workspace / '.aegis').mkdir()
    (workspace / '.aegis/config.json').write_text(json.dumps({
        'v': 1, 'ast': {'packaged_drivers': ['go']}}), encoding='utf-8')
    script = tools / 'protocol.py'
    script.write_text(DRIVER, encoding='utf-8')
    state = SimpleNamespace(home=home, root=workspace, compiler=compiler, calls=[],
                            processes=[], outputs=set(), version='go1.22.2', build_failed=False)
    real_run, real_popen = subprocess.run, subprocess.Popen

    def fake_run(argv, *args, **kwargs):
        command = [str(value) for value in argv]
        if command[0] == str(compiler):
            state.calls.append((command, kwargs))
            if command[1] == 'env':
                return subprocess.CompletedProcess(command, 0, state.version + '\n' +
                                                   ('windows' if os.name == 'nt' else 'linux') + '\namd64\n', '')
            assert command[1] == 'build', command
            if state.build_failed:
                return subprocess.CompletedProcess(command, 2, '', 'fixture go build failed')
            binary = Path(command[command.index('-o') + 1])
            binary.write_bytes(b'mock built driver')
            binary.chmod(0o700)
            state.outputs.add(str(binary))
            return subprocess.CompletedProcess(command, 0, '', '')
        if command[0] in state.outputs:
            command = [sys.executable, str(script), *command[1:]]
        return real_run(command, *args, **kwargs)

    def fake_popen(argv, *args, **kwargs):
        command = [str(value) for value in argv]
        if command[0] == str(compiler):
            state.calls.append((command, kwargs))
            if command[1] == 'env':
                identity = state.version + '\n' + ('windows' if os.name == 'nt' else 'linux') + '\namd64'
                code = f'print({identity!r})'
            elif state.build_failed:
                code = "raise SystemExit('fixture go build failed')"
            else:
                assert command[1] == 'build', command
                binary = Path(command[command.index('-o') + 1])
                state.outputs.add(str(binary))
                code = (f'from pathlib import Path; p=Path({str(binary)!r}); '
                        "p.write_bytes(b'mock built driver'); p.chmod(0o700)")
            return real_popen([sys.executable, '-c', code], *args, **kwargs)
        target = Path(command[0])
        if target.name.startswith('go_ast-') and home in target.parents:
            assert target.read_bytes() == b'mock built driver'
            state.processes.append(command)
            command = [sys.executable, str(script), *command[1:]]
        return real_popen(command, *args, **kwargs)

    monkeypatch.setattr(subprocess, 'run', fake_run)
    monkeypatch.setattr(subprocess, 'Popen', fake_popen)
    return state


def source(state, name='main.go'):
    path = state.root / name
    path.write_text('package fixture\nfunc Example() { blocked() }\n', encoding='utf-8')
    return path


def test_one_build_and_one_process_serve_multiple_go_files(go_workspace):
    state = go_workspace
    first, second = source(state), source(state, 'second.go')
    with ASTDriverRunner() as runner:
        a = runner.parse_file(first, workspace_root=state.root)
        b = runner.parse_file(second, workspace_root=state.root)
    assert len([argv for argv, _ in state.calls if argv[1] == 'build']) == 1
    assert a.metadata['pid'] == b.metadata['pid']
    assert len(state.processes) == 1
    assert a.metadata['capabilities'] == ['allow_comments', 'args']
    assert not Path(a.metadata['cwd']).exists()


def test_warm_cache_starts_a_new_session_without_rebuilding(go_workspace):
    state = go_workspace
    path = source(state)
    for _ in range(2):
        with ASTDriverRunner() as runner:
            assert runner.parse_file(path, workspace_root=state.root).language == 'go'
    assert len([argv for argv, _ in state.calls if argv[1] == 'build']) == 1
    assert len(state.processes) == 2


def test_old_toolchain_failure_is_reused_without_building(go_workspace):
    state = go_workspace
    state.version = 'go1.20.9'
    paths = [source(state), source(state, 'second.go')]
    failures = []
    with ASTDriverRunner() as runner:
        for path in paths:
            try:
                runner.parse_file(path, workspace_root=state.root)
            except ASTDriverError as exc:
                failures.append(str(exc))
    assert len(failures) == 2 and all('1.21' in value for value in failures)
    assert failures[0] == failures[1]
    assert [argv[1] for argv, _ in state.calls] == ['env']
    assert state.processes == []


def test_confinement_precedes_compilation(go_workspace, tmp_path):
    state = go_workspace
    outside = tmp_path / 'outside.go'
    outside.write_text('package fixture\n', encoding='utf-8')
    with pytest.raises(PathTraversalError, match='escapes workspace'):
        ASTDriverRunner().parse_file(outside, workspace_root=state.root)
    assert state.calls == [] and state.processes == []


def test_driver_description_does_not_probe_or_build(go_workspace):
    state = go_workspace
    assert 'go_ast' in ASTDriverRunner().resolve_driver('.go', workspace_root=state.root)
    assert state.calls == [] and state.processes == []


def test_user_go_driver_keeps_the_per_file_protocol_without_a_build(go_workspace):
    state = go_workspace
    config = state.home / '.aegis/config.json'
    config.parent.mkdir()
    arguments = [sys.executable, str(state.compiler.parent / 'protocol.py')]
    command = subprocess.list2cmdline(arguments) if os.name == 'nt' else shlex.join(arguments)
    config.write_text(json.dumps({'v': 1, 'drivers': {'go': command}}), encoding='utf-8')
    path = source(state)
    with ASTDriverRunner() as runner:
        assert runner.parse_file(path, workspace_root=state.root).file_path == str(path)
    assert state.calls == [] and state.processes == []


def test_cold_card_never_builds_the_packaged_driver(go_workspace):
    from aegis_core import card

    state = go_workspace
    source(state)
    data = card.build(state.root).as_dict()
    assert state.calls and all(argv[1] == 'env' for argv, _ in state.calls)
    assert state.processes == []
    driver = next(row for row in data['drivers'] if row['language'] == 'go')
    assert driver['status'] == 'unavailable' and 'cache' in driver['reason']
    assert not list(state.home.rglob('go_ast-*'))


def test_warm_card_reads_real_findings_without_building(go_workspace):
    from aegis_core import card

    state = go_workspace
    path = source(state)
    rules = state.root / '.aegis/rules/invariants'
    rules.mkdir(parents=True)
    (rules / 'blocked-go.md').write_text(
        '---\nid: blocked-go\ntype: invariant\nenforcement: gate\n'
        'hypothesis: Production Go does not call blocked.\n'
        'target_paths: ["*.go"]\nforbid_ast:\n  calls: [blocked]\n---\n# Blocked\n',
        encoding='utf-8')
    with ASTDriverRunner() as runner:
        runner.parse_file(path, workspace_root=state.root)
    state.calls.clear()
    data = card.build(state.root).as_dict()
    assert data['layer1']['failed'] == 1
    assert data['top_files'] == [{'path': 'main.go', 'findings': 1}]
    assert state.calls and all(argv[1] == 'env' for argv, _ in state.calls)
