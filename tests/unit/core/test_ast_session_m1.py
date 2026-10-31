"""Check-local parsing shares plans, results and failures without stale reuse."""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

from aegis_core.ast.policy import ASTExtractionError, extract_normalized_ast
from aegis_core.ast.runner import ASTDriverRegistry, ASTDriverRunner


def test_supplied_nonpython_source_never_parses_python_or_disk(tmp_path):
    target = tmp_path / 'source.external'
    target.write_text('const harmless = 1;', encoding='utf-8')
    with pytest.raises(ASTExtractionError, match="source parsing unsupported for extension '.external'"):
        extract_normalized_ast(target, code='eval(dangerous)')


def test_extract_without_workspace_preserves_no_driver_result(tmp_path):
    target = tmp_path / 'source.unknown'
    target.write_text('unparsed source', encoding='utf-8')
    assert extract_normalized_ast(target) is None


def test_v2_registered_in_code_shares_process_within_runner_context(tmp_path):
    from tests.unit.core.test_ast_batch_m1 import SCRIPT

    script = tmp_path / 'driver.py'
    script.write_text(SCRIPT, encoding='utf-8')
    first, second = tmp_path / 'a.go', tmp_path / 'b.go'
    first.write_text('package a', encoding='utf-8')
    second.write_text('package b', encoding='utf-8')
    registry = ASTDriverRegistry()
    import subprocess
    import shlex
    argv = [sys.executable, str(script), 'ok']
    import os
    command = subprocess.list2cmdline(argv) if os.name == 'nt' else shlex.join(argv)
    registry.register_driver('.go', command, protocol=2)
    with ASTDriverRunner(registry) as runner:
        a = runner.parse_file(first, workspace_root=tmp_path)
        b = runner.parse_file(second, workspace_root=tmp_path)
        assert a.metadata['pid'] == b.metadata['pid']
    with ASTDriverRunner(registry) as runner:
        c = runner.parse_file(first, workspace_root=tmp_path)
        assert c.metadata['pid'] != a.metadata['pid']


def test_parse_cache_reads_each_source_once_and_restarts_for_next_pass(tmp_path):
    from aegis_core.ast.session import ASTParseSession

    target = tmp_path / 'app.py'
    target.write_text('first()', encoding='utf-8')
    with ASTParseSession(str(tmp_path)) as session:
        assert [c.target for c in session.get(str(target)).call_sites] == ['first']
        target.write_text('second()', encoding='utf-8')
        assert [c.target for c in session.get(str(target)).call_sites] == ['first']
    with ASTParseSession(str(tmp_path)) as session:
        assert [c.target for c in session.get(str(target)).call_sites] == ['second']


def test_error_cache_keeps_failure_for_the_current_pass(tmp_path):
    from aegis_core.ast.session import ASTParseSession

    target = tmp_path / 'app.py'
    target.write_text('def broken(', encoding='utf-8')
    with ASTParseSession(str(tmp_path)) as session:
        with pytest.raises(ASTExtractionError) as first:
            session.get(str(target))
        target.write_text('fixed()', encoding='utf-8')
        with pytest.raises(ASTExtractionError) as second:
            session.get(str(target))
        assert first.value is second.value


def test_user_driver_plan_is_frozen_for_one_pass_not_the_next(tmp_path, monkeypatch):
    import os
    import shlex
    import subprocess

    root = tmp_path / 'repo'
    root.mkdir()
    home = tmp_path / 'home'
    (home / '.aegis').mkdir(parents=True)
    for name in ('HOME', 'USERPROFILE'):
        monkeypatch.setenv(name, str(home))
    script = tmp_path / 'outside-driver.py'
    script.write_text('import json,sys\nprint(json.dumps({"language":"go","file_path":sys.argv[2],'
                      '"metadata":{"label":sys.argv[1]}}))', encoding='utf-8')
    def configure(label):
        argv = [sys.executable, str(script), label]
        command = subprocess.list2cmdline(argv) if os.name == 'nt' else shlex.join(argv)
        drivers = {'go': command, 'kt': command}
        if label == 'second':
            drivers['later'] = command
        (home / '.aegis/config.json').write_text(json.dumps({'drivers': drivers}), encoding='utf-8')
    for name in ('a.go', 'b.kt'):
        (root / name).write_text('package fixture', encoding='utf-8')
    configure('first')
    with ASTDriverRunner() as runner:
        assert runner.parse_file(root / 'a.go', workspace_root=root).metadata['label'] == 'first'
        configure('second')
        assert runner.parse_file(root / 'b.kt', workspace_root=root).metadata['label'] == 'first'
        assert '.later' not in runner.get_configured_extensions(root)
    with ASTDriverRunner() as runner:
        assert runner.parse_file(root / 'b.kt', workspace_root=root).metadata['label'] == 'second'
        assert '.later' in runner.get_configured_extensions(root)
