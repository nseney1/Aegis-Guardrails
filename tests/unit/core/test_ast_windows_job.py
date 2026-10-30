"""Windows process ownership at the kernel and public batch boundaries."""
from __future__ import annotations

import ctypes
import io
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


class KernelBoundary:
    """A stateful Win32 boundary: handles are real resources in this model."""

    def __init__(self, failure=None):
        self.failure = failure
        self.handles = set()
        self.events = []
        self.error = 5
        self.threads = [(41, 999), (42, 731)]
        self.thread_index = 0
        self.resume_count = 1

    def _handle(self, name, value):
        self.events.append(name)
        if self.failure == name:
            return 0
        self.handles.add(value)
        return value

    def CreateJobObjectW(self, security, name):
        assert security is None and name is None  # unnamed, non-inheritable job
        return self._handle('CreateJobObjectW', 101)

    def SetInformationJobObject(self, handle, kind, pointer, size):
        from aegis_core.ast.windows_job import JobExtendedLimitInformation

        info = ctypes.cast(pointer, ctypes.POINTER(JobExtendedLimitInformation)).contents
        assert handle == 101 and kind == 9
        assert size == ctypes.sizeof(info)
        assert info.BasicLimitInformation.LimitFlags == 0x2000
        self.events.append('SetInformationJobObject')
        if self.failure == 'SetInformationRaises':
            raise OSError('SetInformationJobObject raised')
        return self.failure != 'SetInformationJobObject'

    def OpenProcess(self, rights, inherit, pid):
        assert (rights, inherit, pid) == (0x101, False, 731)
        return self._handle('OpenProcess', 102)

    def AssignProcessToJobObject(self, job, process):
        assert (job, process) == (101, 102)
        self.events.append('AssignProcessToJobObject')
        return self.failure != 'AssignProcessToJobObject'

    def CreateToolhelp32Snapshot(self, flags, pid):
        assert (flags, pid) == (4, 0)
        handle = self._handle('CreateToolhelp32Snapshot', 103)
        return handle if handle else ctypes.c_void_p(-1).value

    def _entry(self, pointer):
        from aegis_core.ast.windows_job import ThreadEntry32

        entry = ctypes.cast(pointer, ctypes.POINTER(ThreadEntry32)).contents
        assert entry.dwSize == ctypes.sizeof(entry)
        entry.th32ThreadID, entry.th32OwnerProcessID = self.threads[self.thread_index]
        return True

    def Thread32First(self, snapshot, pointer):
        assert snapshot == 103
        self.events.append('Thread32First')
        if self.failure == 'Thread32First':
            return False
        self.thread_index = 0
        return self._entry(pointer)

    def Thread32Next(self, snapshot, pointer):
        assert snapshot == 103
        self.thread_index += 1
        if self.thread_index < len(self.threads):
            return self._entry(pointer)
        self.error = 5 if self.failure == 'Thread32Next' else 18
        return False

    def OpenThread(self, rights, inherit, tid):
        assert (rights, inherit, tid) == (0x802, False, 42)
        return self._handle('OpenThread', 104)

    def GetProcessIdOfThread(self, handle):
        assert handle == 104
        self.events.append('GetProcessIdOfThread')
        if self.failure == 'GetProcessIdOfThread':
            return 0
        return 999 if self.failure == 'thread_reused' else 731

    def ResumeThread(self, handle):
        assert handle == 104
        self.events.append('ResumeThread')
        return 0xFFFFFFFF if self.failure == 'ResumeThread' else self.resume_count

    def CloseHandle(self, handle):
        assert handle in self.handles, 'double close or unknown handle'
        self.events.append(('CloseHandle', handle))
        self.handles.remove(handle)
        return True

    def GetLastError(self):
        return self.error


def _kernel(monkeypatch, failure=None):
    from aegis_core.ast import windows_job

    kernel = KernelBoundary(failure)
    monkeypatch.setattr(windows_job, '_load_kernel32', lambda: kernel)
    return windows_job, kernel


def test_assignment_precedes_resume_and_job_outlives_process_handle(monkeypatch):
    windows_job, kernel = _kernel(monkeypatch)
    job = windows_job.WindowsJob()
    job.assign_and_resume(731)
    assert kernel.handles == {101}
    assert kernel.events.index('AssignProcessToJobObject') < kernel.events.index('ResumeThread')
    job.close()
    job.close()
    assert kernel.handles == set()
    assert kernel.events[-1] == ('CloseHandle', 101)


@pytest.mark.parametrize('failure', ['CreateJobObjectW', 'SetInformationJobObject', 'SetInformationRaises'])
def test_job_setup_failure_closes_handles_without_starting_process(monkeypatch, failure):
    windows_job, kernel = _kernel(monkeypatch, failure)
    reason = 'SetInformationJobObject raised' if failure == 'SetInformationRaises' else failure
    with pytest.raises(OSError, match=reason):
        windows_job.WindowsJob()
    assert not kernel.handles
    assert 'OpenProcess' not in kernel.events


@pytest.mark.parametrize('failure', [
    'OpenProcess', 'AssignProcessToJobObject', 'CreateToolhelp32Snapshot', 'Thread32First',
    'Thread32Next', 'OpenThread', 'GetProcessIdOfThread', 'thread_reused', 'ResumeThread',
])
def test_startup_failures_reap_suspended_root_and_close_every_handle(tmp_path, monkeypatch, failure):
    from aegis_core.ast import batch
    from aegis_core.ast.driver_errors import ASTDriverError

    _, kernel = _kernel(monkeypatch, failure)
    events = []
    proc = SimpleNamespace(pid=731, returncode=None, stdin=io.BytesIO(),
                           stdout=io.BytesIO(), stderr=io.BytesIO())

    def kill():
        events.append('kill')
        proc.returncode = 1

    def wait(**kwargs):
        assert kwargs['timeout'] <= 3
        events.append('wait')
        return proc.returncode

    proc.kill, proc.wait, proc.poll = kill, wait, lambda: proc.returncode

    def spawn(*args, **kwargs):
        assert kwargs['creationflags'] & 4
        events.append('suspended start')
        return proc

    monkeypatch.setattr(batch, 'os', SimpleNamespace(name='nt', path=os.path, environ={}))
    monkeypatch.setattr(batch.subprocess, 'CREATE_NEW_PROCESS_GROUP', 512, raising=False)
    monkeypatch.setattr(batch.subprocess, 'Popen', spawn)
    driver = batch.BatchDriver((sys.executable,), label='fixture', timeout=0.1)
    reason = 'thread.*owner' if failure == 'thread_reused' else failure
    with pytest.raises(ASTDriverError, match=reason) as first:
        driver.parse(tmp_path / 'a.go')
    with pytest.raises(ASTDriverError) as second:
        driver.parse(tmp_path / 'b.go')
    assert str(second.value) == str(first.value)
    assert events == ['suspended start', 'kill', 'wait']
    assert not kernel.handles
    assert all(stream.closed for stream in (proc.stdin, proc.stdout, proc.stderr))
    if failure != 'ResumeThread':
        assert 'ResumeThread' not in kernel.events
    driver.close()


@pytest.mark.parametrize('threads', [[(41, 999)], [(42, 731), (43, 731)]])
def test_ambiguous_primary_thread_is_never_resumed(monkeypatch, threads):
    windows_job, kernel = _kernel(monkeypatch)
    kernel.threads = threads
    job = windows_job.WindowsJob()
    try:
        with pytest.raises(OSError, match='exactly one.*thread'):
            job.assign_and_resume(731)
        assert 'ResumeThread' not in kernel.events
    finally:
        job.close()
    assert not kernel.handles


@pytest.mark.parametrize('count', [0, 2])
def test_unexpected_suspend_count_is_an_error(monkeypatch, count):
    windows_job, kernel = _kernel(monkeypatch)
    kernel.resume_count = count
    job = windows_job.WindowsJob()
    try:
        with pytest.raises(OSError, match=f'ResumeThread expected suspend count 1, got {count}'):
            job.assign_and_resume(731)
    finally:
        job.close()
    assert not kernel.handles


@pytest.mark.parametrize('failure', ['CreateJobObjectW', 'SetInformationJobObject', 'Popen'])
def test_failed_creation_never_leaves_an_unowned_process_or_job(tmp_path, monkeypatch, failure):
    from aegis_core.ast import batch
    from aegis_core.ast.driver_errors import ASTDriverError

    _, kernel = _kernel(monkeypatch, failure)
    scratch = []

    def failed_spawn(*args, **kwargs):
        assert failure == 'Popen', 'no process may be created without a configured job'
        assert kwargs['creationflags'] & 4
        scratch.append(Path(kwargs['cwd']))
        raise OSError('Popen failed')

    monkeypatch.setattr(batch, 'os', SimpleNamespace(name='nt', path=os.path, environ={}))
    monkeypatch.setattr(batch.subprocess, 'CREATE_NEW_PROCESS_GROUP', 512, raising=False)
    monkeypatch.setattr(batch.subprocess, 'Popen', failed_spawn)
    driver = batch.BatchDriver((sys.executable,), label='fixture', timeout=0.1)
    with pytest.raises(ASTDriverError, match=failure):
        driver.parse(tmp_path / 'a.go')
    assert not kernel.handles
    assert all(not path.exists() for path in scratch)
    driver.close()


def test_job_close_error_retains_the_original_startup_diagnostic(tmp_path, monkeypatch):
    from aegis_core.ast import batch
    from aegis_core.ast.driver_errors import ASTDriverError

    _, kernel = _kernel(monkeypatch, 'AssignProcessToJobObject')
    close_handle = kernel.CloseHandle

    def failed_close(handle):
        if handle == 101:
            kernel.error = 6
            return False
        return close_handle(handle)

    monkeypatch.setattr(kernel, 'CloseHandle', failed_close)
    proc = SimpleNamespace(pid=731, returncode=None, stdin=io.BytesIO(),
                           stdout=io.BytesIO(), stderr=io.BytesIO())

    def kill():
        proc.returncode = 1

    proc.kill, proc.poll = kill, lambda: proc.returncode
    proc.wait = lambda **kwargs: proc.returncode
    monkeypatch.setattr(batch, 'os', SimpleNamespace(name='nt', path=os.path, environ={}))
    monkeypatch.setattr(batch.subprocess, 'CREATE_NEW_PROCESS_GROUP', 512, raising=False)
    monkeypatch.setattr(batch.subprocess, 'Popen', lambda *args, **kwargs: proc)
    driver = batch.BatchDriver((sys.executable,), label='fixture', timeout=0.1)
    try:
        with pytest.raises(ASTDriverError, match=r'AssignProcessToJobObject.*cleanup failed:.*CloseHandle\(job\)'):
            driver.parse(tmp_path / 'a.go')
        assert proc.returncode == 1
        assert kernel.handles == {101}  # the injected kernel failure is reported, never hidden
    finally:
        close_handle(101)
    assert not kernel.handles


@pytest.mark.skipif(os.name != 'nt', reason='native Windows suspended startup')
@pytest.mark.parametrize('failure', ['CreateJobObjectW', 'AssignProcessToJobObject', 'ResumeThread'])
def test_native_startup_failure_never_executes_driver_code(tmp_path, monkeypatch, failure):
    from aegis_core.ast import batch, windows_job
    from aegis_core.ast.driver_errors import ASTDriverError

    kernel = windows_job._load_kernel32()
    real_close = kernel.CloseHandle
    handles = set()
    real_load = windows_job._load_kernel32
    for name in ('CreateJobObjectW', 'OpenProcess', 'CreateToolhelp32Snapshot', 'OpenThread'):
        original = getattr(kernel, name)

        def tracked_open(*args, _original=original):
            handle = _original(*args)
            if handle and handle != ctypes.c_void_p(-1).value:
                handles.add(handle)
            return handle

        monkeypatch.setattr(kernel, name, tracked_open)

    def tracked_close(handle):
        result = real_close(handle)
        if result:
            handles.remove(handle)
        return result

    monkeypatch.setattr(kernel, 'CloseHandle', tracked_close)
    monkeypatch.setattr(kernel, failure, lambda *args: 0xFFFFFFFF if failure == 'ResumeThread' else 0)
    monkeypatch.setattr(windows_job, '_load_kernel32', lambda: kernel)
    real_spawn = batch.subprocess.Popen
    processes = []

    def tracked_spawn(*args, **kwargs):
        process = real_spawn(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(batch.subprocess, 'Popen', tracked_spawn)
    marker = tmp_path / 'executed'
    script = tmp_path / 'never_run.py'
    script.write_text("import pathlib, sys\npathlib.Path(sys.argv[1]).write_text('ran')\n", encoding='utf-8')
    driver = batch.BatchDriver((sys.executable, str(script), str(marker)), label='fixture', timeout=0.2)
    try:
        with pytest.raises(ASTDriverError, match=failure):
            driver.parse(tmp_path / 'a.go')
        assert not marker.exists()
        assert not handles
        assert all(proc.poll() is not None for proc in processes)
        assert bool(processes) == (failure != 'CreateJobObjectW')
        assert all(stream.closed for proc in processes for stream in (proc.stdin, proc.stdout, proc.stderr))
    finally:
        driver.close()
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
        cleanup_kernel = real_load()
        for handle in handles:
            assert cleanup_kernel.CloseHandle(handle)
