"""Packaged-v2 transport through a real external process boundary."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import pytest


SCRIPT = '''import json, os, subprocess, sys, time
mode = sys.argv[1]
for line in sys.stdin:
    request = json.loads(line)
    if request['op'] == 'hello':
        if mode == 'hello_timeout':
            time.sleep(5)
        answer = {'aegis_ast': 2, 'op': 'hello', 'driver': 'fixture',
                  'driver_version': '2.0.0', 'languages': ['go'],
                  'capabilities': ['allow_comments', 'args']}
        if mode == 'bad_hello':
            answer['aegis_ast'] = 1
    else:
        child = None
        if mode.startswith('descendant_'):
            child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        if mode == 'stderr':
            sys.stderr.write('bounded diagnostic:' + 'x' * (70 * 1024))
            sys.stderr.flush()
            sys.exit(7)
        if mode == 'timeout':
            time.sleep(5)
        if mode == 'oversize':
            sys.stdout.write('x' * (8 * 1024 * 1024 + 1) + '\\n')
            sys.stdout.flush()
            continue
        if mode == 'crash':
            sys.stderr.write('driver crashed')
            sys.stderr.flush()
            sys.exit(7)
        if mode == 'syntax' and request['id'] == 1:
            answer = {'op': 'parse', 'id': 1, 'ok': False,
                      'error': {'kind': 'syntax', 'message': 'expected expression', 'line': 7}}
        else:
            answer = {'op': 'parse', 'id': request['id'], 'ok': True,
                      'ast': {'version': '1.0', 'language': 'go', 'file_path': request['path'],
                              'definitions': [], 'call_sites': [], 'imports': [],
                              'metadata': {'pid': os.getpid(), 'cwd': os.getcwd(),
                                           'child_pid': child.pid if child else None,
                                           'path_env': os.environ.get('PATH')}}}
        if mode == 'id':
            answer['id'] += 1
        if mode == 'bool_id':
            answer['id'] = True
        if mode == 'language':
            answer['ast']['language'] = 'python'
        if mode == 'malformed':
            print('not json', flush=True)
            continue
    print(json.dumps(answer), flush=True)
    if mode == 'exit_after' and request['op'] == 'parse':
        sys.exit(7)
    if mode in ('descendant_exit', 'descendant_crash') and request['op'] == 'parse':
        sys.exit(7 if mode == 'descendant_crash' else 0)
    if mode == 'shutdown_timeout' and request['op'] == 'parse':
        time.sleep(5)
'''


def _driver(tmp_path: Path, mode: str = 'ok', timeout: float = 1.0):
    from aegis_core.ast.batch import BatchDriver

    script = tmp_path / 'driver.py'
    script.write_text(SCRIPT, encoding='utf-8')
    return BatchDriver((sys.executable, str(script), mode), label='fixture', timeout=timeout)


def test_one_process_serves_ordered_files_in_empty_cwd_without_path(tmp_path):
    with _driver(tmp_path) as driver:
        first = driver.parse(tmp_path / 'a.go')
        second = driver.parse(tmp_path / 'b.go')
        assert first.file_path == str(tmp_path / 'a.go')
        assert second.file_path == str(tmp_path / 'b.go')
        assert first.metadata['pid'] == second.metadata['pid']
        assert first.metadata['path_env'] is None
        cwd = Path(first.metadata['cwd'])
        assert cwd != tmp_path and list(cwd.iterdir()) == []
        assert second.metadata['capabilities'] == ['allow_comments', 'args']
    assert not cwd.exists()


@pytest.mark.parametrize('mode,reason', [
    ('bad_hello', 'hello'), ('hello_timeout', 'timed out'), ('id', 'id'),
    ('oversize', '8 MiB'), ('timeout', 'timed out'), ('crash', 'driver crashed'),
    ('malformed', 'JSON'), ('bool_id', 'id'), ('language', 'language'),
])
def test_protocol_failure_poisoned_session_fails_every_remaining_file(tmp_path, mode, reason):
    from aegis_core.ast.runner import ASTDriverError

    driver = _driver(tmp_path, mode, timeout=0.3)
    with pytest.raises(ASTDriverError, match=reason) as first:
        driver.parse(tmp_path / 'a.go')
    with pytest.raises(ASTDriverError) as remaining:
        driver.parse(tmp_path / 'b.go')
    assert str(remaining.value) == str(first.value)
    driver.close()


def test_valid_syntax_error_does_not_poison_following_file(tmp_path):
    from aegis_core.ast.runner import ASTDriverError

    with _driver(tmp_path, 'syntax') as driver:
        with pytest.raises(ASTDriverError, match='syntax.*line 7.*expected expression'):
            driver.parse(tmp_path / 'a.go')
        assert driver.parse(tmp_path / 'b.go').file_path == str(tmp_path / 'b.go')


def test_nonzero_shutdown_after_valid_response_fails_closed(tmp_path):
    from aegis_core.ast.runner import ASTDriverError

    with pytest.raises(ASTDriverError, match='exit code 7'):
        with _driver(tmp_path, 'exit_after') as driver:
            assert driver.parse(tmp_path / 'a.go').language == 'go'


def test_shutdown_deadline_kills_a_driver_that_ignores_eof(tmp_path):
    from aegis_core.ast.runner import ASTDriverTimeoutError

    with pytest.raises(ASTDriverTimeoutError, match='shutdown'):
        with _driver(tmp_path, 'shutdown_timeout', timeout=0.3) as driver:
            assert driver.parse(tmp_path / 'a.go').language == 'go'


def test_stderr_is_drained_and_diagnostics_are_bounded(tmp_path):
    from aegis_core.ast.runner import ASTDriverError

    driver = _driver(tmp_path, 'stderr')
    with pytest.raises(ASTDriverError, match='bounded diagnostic:') as caught:
        driver.parse(tmp_path / 'a.go')
    assert len(str(caught.value)) < 66 * 1024


def test_group_termination_failure_still_reaps_and_cleans_scratch(tmp_path, monkeypatch):
    from aegis_core.ast import batch
    from aegis_core.ast.runner import ASTDriverError

    driver = _driver(tmp_path, 'shutdown_timeout', timeout=0.1)
    tree = driver.parse(tmp_path / 'a.go')
    scratch = Path(tree.metadata['cwd'])
    if os.name == 'nt':
        kernel = driver._windows_job._kernel
        job_handle = driver._windows_job._handle
        close_handle = kernel.CloseHandle
        closed = False

        def failed_close(handle):
            nonlocal closed
            if handle != job_handle:
                return close_handle(handle)
            if not closed:
                assert close_handle(handle)
                closed = True
            raise OSError('job termination failed')

        monkeypatch.setattr(kernel, 'CloseHandle', failed_close)
    else:
        def failed_group(*args):
            raise OSError('group termination failed')
        monkeypatch.setattr(batch.os, 'killpg', failed_group)
    with pytest.raises(ASTDriverError, match='cleanup failed:.*(job|group) termination failed'):
        driver.close()
    assert not scratch.exists()
    if os.name != 'nt':
        with pytest.raises(ProcessLookupError):
            os.kill(tree.metadata['pid'], 0)
    driver.close()  # a second close has no remaining cleanup work


@pytest.mark.skipif(os.name == 'nt', reason='POSIX process-group ownership')
def test_closing_a_session_terminates_its_process_group(tmp_path):
    import time

    driver = _driver(tmp_path)
    pid = driver.parse(tmp_path / 'a.go').metadata['pid']
    driver.close()
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    else:
        pytest.fail('driver process survived close')


@pytest.mark.parametrize('termination_fails', [False, True])
def test_windows_close_retains_tree_ownership_after_driver_root_exits(tmp_path, monkeypatch, termination_fails):
    """The Windows process boundary has already exited when public close runs."""
    import io
    from types import ModuleType, SimpleNamespace
    from aegis_core.ast import batch

    events = []
    scratch = []

    def terminate():
        events.append('tree stopped')
        if termination_fails:
            raise OSError('job termination failed')

    job = SimpleNamespace(
        assign_and_resume=lambda pid: events.append(('assigned', pid)),
        terminate_and_wait=terminate,
        close=lambda: events.append('job closed'),
    )
    module = ModuleType('aegis_core.ast.windows_job')
    module.CREATE_SUSPENDED = 4
    module.WindowsJob = lambda: (events.append('job created'), job)[1]
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(batch, 'os', SimpleNamespace(name='nt', path=os.path, environ={}))
    monkeypatch.setattr(batch.subprocess, 'CREATE_NEW_PROCESS_GROUP', 512, raising=False)
    path = tmp_path / 'a.go'
    responses = [
        {'aegis_ast': 2, 'op': 'hello', 'driver': 'fixture', 'driver_version': '2',
         'languages': ['go'], 'capabilities': []},
        {'op': 'parse', 'id': 1, 'ok': True,
         'ast': {'version': '1.0', 'language': 'go', 'file_path': str(path),
                 'definitions': [], 'call_sites': [], 'imports': []}},
    ]
    proc = SimpleNamespace(
        pid=731, returncode=0, stdin=io.BytesIO(), stderr=io.BytesIO(),
        stdout=io.BytesIO(b''.join(json.dumps(row).encode() + b'\n' for row in responses)),
        poll=lambda: 0, wait=lambda **kwargs: 0,
    )

    def spawn(*args, **kwargs):
        events.append(('spawn', kwargs.get('creationflags', 0)))
        scratch.append(Path(kwargs['cwd']))
        return proc

    monkeypatch.setattr(batch.subprocess, 'Popen', spawn)
    driver = batch.BatchDriver((sys.executable,), label='fixture')
    assert driver.parse(path).file_path == str(path)
    if termination_fails:
        from aegis_core.ast.driver_errors import ASTDriverError

        with pytest.raises(ASTDriverError, match='cleanup failed:.*job termination failed'):
            driver.close()
    else:
        driver.close()
    assert 'job closed' in events, 'exited root left its descendant tree unowned'
    assert events == ['job created', ('spawn', 516), ('assigned', 731), 'tree stopped', 'job closed']
    assert all(not path.exists() for path in scratch)


@pytest.mark.skipif(os.name != 'nt', reason='native Windows job ownership')
@pytest.mark.parametrize('mode', ['descendant_exit', 'descendant_crash', 'descendant_eof'])
def test_windows_job_terminates_descendant_after_root_exit(tmp_path, mode):
    """Keep child/root handles open so observations cannot target reused PIDs."""
    from aegis_core.ast.driver_errors import ASTDriverError
    from aegis_core.ast import windows_job

    kernel = windows_job._load_kernel32()
    import ctypes

    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.WaitForSingleObject.restype = ctypes.c_uint32
    kernel.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.TerminateProcess.restype = ctypes.c_int32
    driver = _driver(tmp_path, mode)
    child_handle = root_handle = None
    try:
        tree = driver.parse(tmp_path / 'a.go')
        child_handle = kernel.OpenProcess(0x100000 | 1, False, tree.metadata['child_pid'])
        root_handle = kernel.OpenProcess(0x100000, False, tree.metadata['pid'])
        assert child_handle and root_handle
        assert kernel.WaitForSingleObject(child_handle, 0) == 258  # WAIT_TIMEOUT
        if mode != 'descendant_eof':
            assert kernel.WaitForSingleObject(root_handle, 2000) == 0
        if mode == 'descendant_crash':
            with pytest.raises(ASTDriverError, match='exit code 7'):
                driver.close()
        else:
            driver.close()
        assert not Path(tree.metadata['cwd']).exists()
        assert kernel.WaitForSingleObject(root_handle, 0) == 0
        assert kernel.WaitForSingleObject(child_handle, 0) == 0
    finally:
        try:
            driver.close()
        finally:
            if child_handle:
                if kernel.WaitForSingleObject(child_handle, 0) == 258:
                    assert kernel.TerminateProcess(child_handle, 1)
                    assert kernel.WaitForSingleObject(child_handle, 2000) == 0
                assert kernel.CloseHandle(child_handle)
            if root_handle:
                assert kernel.CloseHandle(root_handle)
