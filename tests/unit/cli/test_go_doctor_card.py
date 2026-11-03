"""Read-only Go diagnostics and explicitly confirmed cache preparation."""
import io
import json
import sys

from aegis_cli.cli import main
from aegis_core import card
from tests.unit.core.test_go_integration import go_workspace, source  # noqa: F401


def doctor(state, capsys, *extra):
    code = main(['doctor', '--drivers', '--workspace', str(state.root), '--json', *extra])
    output = capsys.readouterr()
    assert output.err == ''
    return code, json.loads(output.out)


def test_cold_doctor_reports_cache_miss_without_building(go_workspace, capsys):
    state = go_workspace
    source(state)
    code, doc = doctor(state, capsys)
    assert code == 1 and not doc['checks_ok']
    assert 'cache' in '\n'.join(doc['checks'][0]['detail'])
    assert state.calls and all(argv[1] == 'env' for argv, _ in state.calls)
    assert not list(state.home.rglob('go_ast-*'))


def test_old_go_is_reported_without_building(go_workspace, capsys):
    state = go_workspace
    source(state)
    state.version = 'go1.20.9'
    code, doc = doctor(state, capsys)
    assert code == 1 and '1.21' in '\n'.join(doc['checks'][0]['detail'])
    assert all(argv[1] == 'env' for argv, _ in state.calls)


def test_unconfirmed_cache_repair_changes_nothing(go_workspace, capsys, monkeypatch):
    state = go_workspace
    source(state)
    class TerminalInput(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, 'stdin', TerminalInput('n\n'))
    before = (state.root / '.aegis/config.json').read_bytes()
    code = main(['doctor', '--drivers', '--workspace', str(state.root), '--fix'])
    output = capsys.readouterr()
    assert code == 1 and 'No changes made.' in output.out and output.err == ''
    assert 'generated Go cache entries are not backed up' in output.out
    assert (state.root / '.aegis/config.json').read_bytes() == before
    assert not list(state.home.rglob('go_ast-*'))
    assert not (state.home / '.aegis/backups').exists()
    assert all(argv[1] == 'env' for argv, _ in state.calls)


def test_confirmed_cache_only_repair_never_backs_up_a_binary(go_workspace, capsys):
    state = go_workspace
    source(state)
    code, doc = doctor(state, capsys, '--fix', '--yes')
    assert code == 0 and doc['checks_ok']
    assert [row['status'] for row in doc['fixes']] == ['applied']
    assert doc['backup_dir'] is None
    assert not (state.home / '.aegis/backups').exists()
    assert len([argv for argv, _ in state.calls if argv[1] == 'build']) == 1


def test_initial_go_provisioning_backs_up_config_and_prepares_cache(go_workspace, capsys):
    state = go_workspace
    source(state)
    config = state.root / '.aegis/config.json'
    before = b'{"v":1}\n'
    config.write_bytes(before)
    code, doc = doctor(state, capsys, '--fix', '--yes')
    assert code == 0 and all(row['status'] == 'applied' for row in doc['fixes'])
    assert len([argv for argv, _ in state.calls if argv[1] == 'build']) == 1
    assert json.loads(config.read_text())['ast']['packaged_drivers'] == ['go']
    from pathlib import Path

    backup = Path(doc['backup_dir'])
    manifest = json.loads((backup / 'manifest.json').read_text())
    assert len(manifest['files']) == 1 and manifest['files'][0]['path'] == str(config)
    assert (backup / manifest['files'][0]['backup']).read_bytes() == before


def test_build_failure_is_visible_in_confirmed_repair(go_workspace, capsys):
    state = go_workspace
    source(state)
    state.build_failed = True
    code, doc = doctor(state, capsys, '--fix', '--yes')
    assert code == 1 and not doc['checks_ok']
    assert [row['status'] for row in doc['fixes']] == ['failed']
    assert 'fixture go build failed' in doc['fixes'][0]['reason']


def test_changed_toolchain_after_confirmation_never_builds_an_unreviewed_key(go_workspace, capsys, monkeypatch):
    state = go_workspace
    source(state)

    class ChangedToolchain(io.StringIO):
        def isatty(self):
            return True

        def readline(self, *args):
            state.version = 'go1.22.3'
            return super().readline(*args)

    monkeypatch.setattr(sys, 'stdin', ChangedToolchain('y\n'))
    code = main(['doctor', '--drivers', '--workspace', str(state.root), '--fix'])
    output = capsys.readouterr()
    assert code == 1 and 'cache key changed since the check' in output.out
    assert all(argv[1] == 'env' for argv, _ in state.calls)
    assert not list(state.home.rglob('go_ast-*'))


def test_python_only_diagnostics_never_probe_go(go_workspace, capsys):
    state = go_workspace
    (state.root / '.aegis/config.json').write_text('{"v":1}', encoding='utf-8')
    (state.root / 'app.py').write_text('value = 1\n', encoding='utf-8')
    assert doctor(state, capsys)[0] == 0
    assert card.build(state.root).as_dict()['drivers'][0]['language'] == 'python'
    assert state.calls == []
