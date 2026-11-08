"""Packaged-v2 transport through a real external process boundary."""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
import traceback

import pytest


SCRIPT = '''import json, os, subprocess, sys, time
mode = sys.argv[1]
for line in sys.stdin:
    request = json.loads(line)
    if mode in ('hello_timeout', 'timeout'):
        receipt = os.path.join(os.path.dirname(__file__), 'requests.jsonl')
        with open(receipt, 'a', encoding='utf-8') as log:
            log.write(json.dumps(request) + '\\n')
    if request['op'] == 'hello':
        if mode == 'language':
            time.sleep(0.5)
        if mode == 'hello_timeout':
            time.sleep(60)
        answer = {'aegis_ast': 2, 'op': 'hello', 'driver': 'fixture',
                  'driver_version': '2.0.0', 'languages': ['go'],
                  'capabilities': ['allow_comments', 'args']}
        if mode == 'bad_hello':
            answer['aegis_ast'] = 1
    else:
        child = None
        if mode.startswith('descendant_'):
            child_argv = [sys.executable, '-c', 'import time; time.sleep(30)']
            inherited = {}
            if len(sys.argv) > 2:
                child_argv = [sys.executable, '-c', 'import os,sys; os.read(int(sys.argv[1]), 1)', sys.argv[2]]
                inherited = {'pass_fds': (int(sys.argv[2]),)}
            child = subprocess.Popen(child_argv, env=dict(os.environ), **inherited,
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        if mode == 'stderr':
            sys.stderr.write('bounded diagnostic:' + 'x' * (70 * 1024))
            sys.stderr.flush()
            sys.exit(7)
        if mode == 'timeout' and request['id'] == 2:
            time.sleep(60)
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
        if mode == 'schema':
            answer['ast']['version'] = '2.0'
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


def _driver(tmp_path: Path, mode: str = 'ok', timeout: float = 1.0, *, child_pipe=None):
    from aegis_core.ast.batch import BatchDriver

    script = tmp_path / 'driver.py'
    script.write_text(SCRIPT, encoding='utf-8')
    argv = (sys.executable, str(script), mode)
    if child_pipe is not None:
        argv += (str(child_pipe),)
    return BatchDriver(argv, label='fixture', timeout=timeout)


def _owned_process_state(pgid, *, pid=None, timeout=1.0):
    """One nonreaping ps observation, limited to 4096 bytes and a deadline."""
    # Apple documents -g, -p, these four fields, and empty headers in ps(1):
    # https://github.com/apple-oss-distributions/adv_cmds/blob/main/ps/ps.1
    # compat(5) documents COMMAND_MODE=unix2003; legacy ps ignores -g.
    # https://github.com/apple-oss-distributions/Libc/blob/main/gen/compat.5
    # procps -g selects a session for a numeric argument. BatchDriver creates a
    # new session whose SID equals this PGID; filter its rows back to the PGID.
    # https://github.com/procps-ng/procps/blob/master/man/ps.1
    argv = ['/bin/ps', '-g', str(pgid)]
    if pid is not None:
        argv += ['-p', str(pid)]
    argv += ['-o', 'pid=,ppid=,pgid=,state=']
    deadline = time.monotonic() + timeout
    observer = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={'LC_ALL': 'C', 'COMMAND_MODE': 'unix2003'},
    )
    buffers = {observer.stdout: bytearray(), observer.stderr: bytearray()}
    size = 0
    try:
        with selectors.DefaultSelector() as ready:
            for stream in buffers:
                ready.register(stream, selectors.EVENT_READ)
            while ready.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('ps observation exceeded its deadline')
                events = ready.select(remaining)
                if not events:
                    raise TimeoutError('ps observation exceeded its deadline')
                for key, _ in events:
                    chunk = os.read(key.fd, min(1024, 4097 - size))
                    if not chunk:
                        ready.unregister(key.fileobj)
                        continue
                    size += len(chunk)
                    if size > 4096:
                        raise ValueError('ps observation exceeded 4096 bytes')
                    buffers[key.fileobj].extend(chunk)
        observer.wait(timeout=max(0.001, deadline - time.monotonic()))
        if buffers[observer.stderr] or observer.returncode not in (0, 1):
            raise RuntimeError(f'ps observation failed (returncode={observer.returncode})')
        if observer.returncode == 1 and buffers[observer.stdout]:
            raise RuntimeError('ps observation returned incomplete output')
        rows = []
        for line in buffers[observer.stdout].decode('ascii').splitlines():
            fields = line.split()
            if (len(fields) != 4 or not all(value.isdecimal() for value in fields[:3])
                    or not fields[3] or len(fields[3]) > 16
                    or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+<>?-' for c in fields[3])):
                raise ValueError('ps observation returned malformed numeric process state')
            process_pid, ppid, process_pgid = map(int, fields[:3])
            if process_pgid == pgid or process_pid == pid:
                rows.append({'pid': process_pid, 'ppid': ppid, 'pgid': process_pgid, 'state': fields[3]})
        return {'status': 'observed' if observer.returncode == 0 else 'no_rows', 'processes': rows}
    finally:
        try:
            if observer.returncode is None:
                # Bound only the diagnostic observer's lifetime; never signal or
                # poll the driver here. A failed observation remains UNKNOWN.
                observer.kill()
                observer.wait(timeout=1)
        finally:
            for stream in buffers:
                stream.close()


def _record_owned_group_cleanup(monkeypatch, driver):
    records = []
    original = os.killpg

    def observed(pgid, sig):
        proc = driver._proc  # Read cached ownership; no poll/wait before the snapshot.
        if proc is None or pgid != proc.pid:
            return original(pgid, sig)
        record = {'operation': 'os.killpg', 'pid': proc.pid, 'pgid': pgid,
                  'signal': int(sig), 'cached_returncode': proc.returncode}
        records.append(record)
        try:
            result = original(pgid, sig)  # Exactly one call, including failure.
        except OSError as error:
            record['errno'] = error.errno
            record['traceback'] = ''.join(traceback.format_exception(type(error), error, error.__traceback__))
            try:
                record['observation'] = _owned_process_state(pgid, pid=proc.pid)
            except Exception as observation_error:
                # Diagnostic failure must not replace the original OS exception.
                record['observation'] = {'status': 'UNKNOWN', 'error_type': type(observation_error).__name__,
                                         'errno': getattr(observation_error, 'errno', None)}
            raise
        record['result'] = 'returned'
        return result

    monkeypatch.setattr(os, 'killpg', observed)
    return records


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
    ('bad_hello', 'hello'), ('id', 'id'), ('oversize', '8 MiB'),
    ('crash', 'driver crashed'), ('malformed', 'JSON'), ('bool_id', 'id'),
    ('language', 'language'), ('schema', 'schema version'),
])
def test_protocol_failure_poisoned_session_fails_every_remaining_file(tmp_path, monkeypatch, mode, reason):
    from aegis_core.ast.runner import ASTDriverError, ASTDriverTimeoutError

    # The language fixture delays hello beyond the old shared 0.3s allowance.
    # Content validation must still reach its intended defect on a loaded host.
    driver = _driver(tmp_path, mode, timeout=30)
    cleanup = _record_owned_group_cleanup(monkeypatch, driver) if os.name == 'posix' else []
    try:
        with pytest.raises(ASTDriverError, match=reason) as first:
            driver.parse(tmp_path / 'a.go')
        assert not isinstance(first.value, ASTDriverTimeoutError)
        diagnostic = f'{first.value}\nowned group cleanup:\n'
        for record in cleanup:
            diagnostic += json.dumps({key: value for key, value in record.items() if key != 'traceback'},
                                     sort_keys=True) + '\n'
            diagnostic += record.get('traceback', '')
        if not any(record.get('errno') == errno.EPERM for record in cleanup):
            diagnostic += ('\nNo owned os.killpg EPERM observed; any cleanup EPERM syscall remains UNKNOWN. '
                           'Next instrument root fallback poll/kill/wait, stream close and scratch cleanup.')
        assert 'cleanup failed' not in str(first.value), diagnostic
        with pytest.raises(ASTDriverError) as remaining:
            driver.parse(tmp_path / 'b.go')
        assert str(remaining.value) == str(first.value)
        assert remaining.value is first.value
    finally:
        driver.close()


@pytest.mark.parametrize('mode,operation', [('hello_timeout', 'hello'), ('timeout', 'parse')])
def test_timeout_in_requested_phase_poisons_every_remaining_file(tmp_path, mode, operation):
    from aegis_core.ast.runner import ASTDriverTimeoutError

    driver = _driver(tmp_path, mode, timeout=30)
    expected = [{'aegis_ast': 2, 'op': 'hello'}]
    target = tmp_path / 'a.go'
    try:
        if operation == 'parse':
            # Public warmup completes startup before the short parse deadline is used.
            warmup = tmp_path / 'warmup.go'
            assert driver.parse(warmup).file_path == str(warmup)
            expected.extend([
                {'op': 'parse', 'id': 1, 'path': str(warmup)},
                {'op': 'parse', 'id': 2, 'path': str(target)},
            ])
        driver.timeout = 3.0
        with pytest.raises(ASTDriverTimeoutError, match=f'waiting for {operation}') as first:
            driver.parse(target)
        assert str(first.value) == (
            f"AST driver 'fixture': timed out after 3.0s waiting for {operation}"
        ), str(first.value)
        # The child records receipt before stalling: startup delay alone cannot pass.
        receipt = tmp_path / 'requests.jsonl'
        if operation == 'hello':
            assert receipt.is_file(), (
                'No hello request receipt within the 3.0s hello window; interpreter startup '
                'can consume this window. Inspect subprocess startup, Windows job setup '
                'and host-load diagnostics before changing the deadline.'
            )
        received = [
            json.loads(line)
            for line in receipt.read_text(encoding='utf-8').splitlines()
        ]
        assert received == expected
        with pytest.raises(ASTDriverTimeoutError, match=f'waiting for {operation}') as remaining:
            driver.parse(tmp_path / 'b.go')
        assert str(remaining.value) == str(first.value)
        assert remaining.value is first.value
    finally:
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


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process-group ownership')
@pytest.mark.parametrize('mode', ['descendant_exit', 'descendant_crash'])
def test_posix_close_terminates_descendant_after_root_exit(tmp_path, monkeypatch, mode):
    from aegis_core.ast.runner import ASTDriverError

    read_end, write_end = os.pipe()
    driver = _driver(tmp_path, mode, timeout=30, child_pipe=read_end)
    original = subprocess.Popen

    def spawn(argv, *args, **options):
        if tuple(argv) == driver.argv:
            options['pass_fds'] = (read_end,)
        return original(argv, *args, **options)

    monkeypatch.setattr(subprocess, 'Popen', spawn)
    tree = None
    try:
        tree = driver.parse(tmp_path / 'a.go')
        pgid, child = tree.metadata['pid'], tree.metadata['child_pid']
        deadline = time.monotonic() + 3
        while True:
            remaining = deadline - time.monotonic()
            assert remaining > 0, 'root did not exit while its ordinary descendant remained alive'
            before = _owned_process_state(pgid, pid=pgid, timeout=min(1, remaining))
            rows = {row['pid']: row for row in before['processes']}
            if pgid in rows and rows[pgid]['state'].startswith('Z'):
                break
        assert child in rows and rows[child]['pgid'] == pgid, before
        assert not rows[child]['state'].startswith('Z'), before
        if mode == 'descendant_crash':
            with pytest.raises(ASTDriverError) as error:
                driver.close()
            assert str(error.value) == "AST driver 'fixture' exited with exit code 7"
        else:
            driver.close()
        deadline = time.monotonic() + 3
        while True:
            remaining = deadline - time.monotonic()
            assert remaining > 0, 'owned descendant survived public close'
            after = _owned_process_state(pgid, timeout=min(1, remaining))
            if all(row['state'].startswith('Z') for row in after['processes']):
                break  # Container init may retain a dead orphan as a zombie.
        assert not Path(tree.metadata['cwd']).exists()
    finally:
        try:
            driver.close()
        finally:
            # Only this test owns the writer. EOF safely releases a surviving
            # descendant without signalling a possibly reused numeric PID.
            os.close(write_end)
            os.close(read_end)
            if tree is not None:
                deadline = time.monotonic() + 3
                while True:
                    remaining = deadline - time.monotonic()
                    assert remaining > 0, 'owned descendant survived safety-pipe EOF'
                    state = _owned_process_state(tree.metadata['pid'], timeout=min(1, remaining))
                    if all(row['state'].startswith('Z') for row in state['processes']):
                        break


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process-group diagnostic boundary')
@pytest.mark.parametrize('observation', ['observed', 'denied', 'timeout', 'oversize', 'malformed'])
def test_owned_group_diagnostic_preserves_error_and_observes_before_reaping(
        tmp_path, monkeypatch, observation):
    from aegis_core.ast.runner import ASTDriverError

    driver = _driver(tmp_path, 'crash', timeout=30)
    denied = PermissionError(errno.EPERM, 'controlled owned-group denial')
    original_popen, original_killpg = subprocess.Popen, os.killpg
    calls, events, identities, scratch = [], [], [], []

    def spawn(argv, *args, **options):
        if argv[0] == '/bin/ps':
            events.append('snapshot started')
            if observation == 'denied':
                events.append('snapshot failed')
                raise PermissionError(errno.EACCES, 'controlled observation denial')
            # These observation faults are modelled at the real process boundary.
            code = {
                'timeout': 'import threading; threading.Event().wait()',
                'oversize': "import sys; sys.stdout.write('0' * 4097); sys.stdout.flush()",
                'malformed': "print('malformed numeric state')",
            }.get(observation)
            proc = original_popen([sys.executable, '-c', code] if code else argv, *args, **options)
            wait = proc.wait

            def observer_wait(*args, **kwargs):
                result = wait(*args, **kwargs)
                events.append('snapshot completed')
                return result

            monkeypatch.setattr(proc, 'wait', observer_wait)
            return proc
        proc = original_popen(argv, *args, **options)
        scratch.append(Path(options['cwd']))
        poll, wait = proc.poll, proc.wait

        def root_poll():
            events.append('root poll')
            return poll()

        def root_wait(*args, **kwargs):
            events.append('root wait')
            return wait(*args, **kwargs)

        monkeypatch.setattr(proc, 'poll', root_poll)
        monkeypatch.setattr(proc, 'wait', root_wait)
        return proc

    def fail_group(pgid, sig):
        if driver._proc is not None and pgid == driver._proc.pid:
            calls.append((pgid, int(sig)))
            raise denied
        return original_killpg(pgid, sig)

    monkeypatch.setattr(subprocess, 'Popen', spawn)
    monkeypatch.setattr(os, 'killpg', fail_group)
    records = _record_owned_group_cleanup(monkeypatch, driver)
    recorded_killpg = os.killpg

    def check_identity(pgid, sig):
        try:
            return recorded_killpg(pgid, sig)
        except OSError as error:
            identities.append(error is denied)
            raise

    monkeypatch.setattr(os, 'killpg', check_identity)
    try:
        with pytest.raises(ASTDriverError, match='cleanup failed:.*controlled owned-group denial') as error:
            driver.parse(tmp_path / 'a.go')
        assert 'driver crashed' in str(error.value)
        proc = driver._proc
        assert calls == [(proc.pid, int(signal.SIGKILL))]
        assert identities == [True]
        assert len(records) == 1
        record = records[0]
        assert record['operation'] == 'os.killpg'
        assert record['pid'] == record['pgid'] == proc.pid
        assert record['signal'] == int(signal.SIGKILL)
        assert record['errno'] == errno.EPERM
        assert record['cached_returncode'] is None
        assert 'fail_group' in record['traceback'] and 'PermissionError' in record['traceback']
        assert events.count('snapshot started') == 1
        completed = 'snapshot failed' if observation == 'denied' else 'snapshot completed'
        assert events.index(completed) < events.index('root poll')
        assert events.index(completed) < events.index('root wait')
        if observation == 'observed':
            assert record['observation']['status'] == 'observed'
            assert any(row['pid'] == proc.pid for row in record['observation']['processes'])
        else:
            error_type = {'denied': 'PermissionError', 'timeout': 'TimeoutError',
                          'oversize': 'ValueError', 'malformed': 'ValueError'}[observation]
            assert record['observation'] == {'status': 'UNKNOWN', 'error_type': error_type,
                                              'errno': errno.EACCES if observation == 'denied' else None}
        assert proc.returncode == 7
        assert proc.stdin.closed and proc.stdout.closed and proc.stderr.closed
        assert all(not path.exists() for path in scratch)
    finally:
        driver.close()


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
