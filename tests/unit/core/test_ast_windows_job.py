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

    def TerminateJobObject(self, job, code):
        assert (job, code) == (101, 1)
        return True

    def QueryInformationJobObject(self, job, kind, pointer, size, returned):
        assert job == 101 and kind in (1, 3)
        if kind == 1:
            # Four LARGE_INTEGER times, then page faults, lifetime process count.
            ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32))[9] = 1
        return True  # startup failures have no un-reaped descendant in this boundary


class ShutdownKernel(KernelBoundary):
    """Terminating a job requests exit; only process waits witness completion."""

    def __init__(self, failure=None, members=(731, 732)):
        super().__init__(failure)
        self.members = members
        self.waits = []
        self.total_processes = len(set(members) | {731})
        self.clear_on_termination = False
        self.query_capacities = []

    def TerminateJobObject(self, job, code):
        assert (job, code) == (101, 1)
        self.events.append('terminate requested')
        if self.clear_on_termination:
            self.members = ()
        if self.failure == 'late_member':
            self.total_processes += 1
        return self.failure != 'TerminateJobObject'

    def QueryInformationJobObject(self, job, kind, pointer, size, returned):
        assert job == 101 and kind in (1, 3)
        if kind == 1:
            self.events.append('lifetime queried')
            if self.failure == 'QueryAccounting':
                self.error = 5
                return False
            ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32))[9] = self.total_processes
            return True
        self.events.append('members queried')
        if self.failure == 'QueryInformationJobObject':
            self.error = 5
            return False
        header = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32 * 2)).contents
        capacity = (size - 8) // ctypes.sizeof(ctypes.c_size_t)
        self.query_capacities.append(capacity)
        header[0] = 65537 if self.failure == 'too_many_members' else len(self.members)
        header[1] = min(capacity, len(self.members))
        pids = (ctypes.c_size_t * capacity).from_address(ctypes.addressof(header) + 8)
        for index, pid in enumerate(self.members[:capacity]):
            pids[index] = pid
        if self.failure == 'truncated_members':
            header[1] = capacity + 1
            return True
        if self.failure == 'count_exceeds_assigned':
            header[0] = 0
            return True
        if self.failure == 'partial_members' or (
                self.failure == 'partial_members_once' and len(self.query_capacities) == 1):
            header[1] -= 1
            return True
        self.error = 234
        return capacity >= header[0]

    def OpenProcess(self, rights, inherit, pid):
        if rights == 0x101:
            return super().OpenProcess(rights, inherit, pid)
        assert (rights, inherit) == (0x101000, False)
        self.events.append(('member opened', pid))
        if self.failure in ('OpenProcess(member)', 'member_gone'):
            self.error = 87 if self.failure == 'member_gone' else 5
            return 0
        handle = pid + 1000
        self.handles.add(handle)
        return handle

    def IsProcessInJob(self, process, job, pointer):
        assert job == 101 and process in self.handles
        self.events.append(('member checked', process))
        outside = self.failure in ('member_reused', 'member_retired', 'member_status_failed')
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_int32)).contents.value = not outside
        return self.failure != 'IsProcessInJob'

    def WaitForSingleObject(self, process, milliseconds):
        assert process in self.handles and 0 <= milliseconds <= 3000
        self.waits.append((process, milliseconds))
        if self.failure in ('wait_failed', 'member_status_failed'):
            return 0xFFFFFFFF
        return 258 if self.failure in ('wait_timeout', 'member_reused') else 0


def _shutdown_job(monkeypatch, failure=None, members=(731, 732)):
    from aegis_core.ast import windows_job

    kernel = ShutdownKernel(failure, members)
    monkeypatch.setattr(windows_job, '_load_kernel32', lambda: kernel)
    job = windows_job.WindowsJob()
    job.assign_and_resume(731)
    return job, kernel


def test_shutdown_waits_for_every_member_before_releasing_job(monkeypatch):
    job, kernel = _shutdown_job(monkeypatch, members=tuple(range(731, 861)))
    try:
        job.terminate_and_wait()
        assert [handle - 1000 for handle, _ in kernel.waits] == list(range(731, 861))
        assert kernel.events.index('members queried') < kernel.events.index('terminate requested')
        assert kernel.handles == {101}
    finally:
        job.close()
    assert not kernel.handles


def test_pretermination_handles_survive_members_disappearing_from_the_job_list(monkeypatch):
    job, kernel = _shutdown_job(monkeypatch)
    kernel.clear_on_termination = True
    try:
        job.terminate_and_wait()
        assert [handle - 1000 for handle, _ in kernel.waits] == [731, 732]
        assert kernel.handles == {101}
    finally:
        job.close()


@pytest.mark.parametrize('completed_go', [False, True])
def test_shutdown_grows_a_successfully_returned_partial_member_list(monkeypatch, completed_go):
    job, kernel = _shutdown_job(monkeypatch, 'partial_members_once')
    root = SimpleNamespace(pid=731, returncode=0, wait=lambda **kw: 0)
    try:
        if completed_go:
            job.terminate_completed_go_compiler_and_wait(root)
        else:
            job.terminate_and_wait()
        assert len(kernel.query_capacities) == 2
        assert kernel.query_capacities[1] > kernel.query_capacities[0]
        assert [handle - 1000 for handle, _ in kernel.waits] == [731, 732]
        assert kernel.handles == {101}
    finally:
        job.close()
    assert not kernel.handles


def test_a_permanently_partial_member_list_cannot_pass_shutdown_or_exceed_the_cap(monkeypatch):
    job, kernel = _shutdown_job(monkeypatch, 'partial_members')
    try:
        with pytest.raises(OSError, match=r'^Windows job process list exceeds 65536 members$'):
            job.terminate_and_wait()
        assert len(kernel.query_capacities) > 1
        assert max(kernel.query_capacities) <= 65536
        assert 'terminate requested' not in kernel.events
        assert not kernel.waits and kernel.handles == {101}
    finally:
        job.close()
    assert not kernel.handles


def test_partial_member_list_growth_obeys_the_shared_shutdown_deadline(monkeypatch):
    from aegis_core.ast import windows_job

    job, kernel = _shutdown_job(monkeypatch, 'partial_members')
    clock = [100.0]
    monkeypatch.setattr(windows_job, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    original = kernel.QueryInformationJobObject

    def query(*args):
        result = original(*args)
        clock[0] += 3.0
        return result

    monkeypatch.setattr(kernel, 'QueryInformationJobObject', query)
    try:
        with pytest.raises(OSError, match=r'^timed out waiting for Windows job termination$'):
            job.terminate_and_wait()
        assert len(kernel.query_capacities) == 1
        assert 'terminate requested' not in kernel.events
        assert not kernel.waits and kernel.handles == {101}
    finally:
        job.close()
    assert not kernel.handles


@pytest.mark.parametrize('late', [False, True])
def test_unobserved_historical_or_late_descendant_cannot_pass_shutdown(monkeypatch, late):
    job, kernel = _shutdown_job(monkeypatch, 'late_member' if late else None, members=())
    if not late:
        kernel.total_processes = 2  # a prior child vanished before handle collection
    try:
        with pytest.raises(OSError, match='cannot verify complete Windows descendant termination'):
            job.terminate_and_wait()
        assert kernel.handles == {101}
    finally:
        job.close()


def test_completed_trusted_go_parent_accounts_for_its_waited_historical_children(monkeypatch):
    job, kernel = _shutdown_job(monkeypatch, members=(732,))
    kernel.total_processes = 4  # root + two completed Go tools + one retained live member
    waits = []
    root = SimpleNamespace(pid=731, returncode=0, wait=lambda **kw: waits.append(kw) or 0)
    try:
        job.terminate_completed_go_compiler_and_wait(root)
        assert waits == [{'timeout': 0}]
        assert [handle - 1000 for handle, _ in kernel.waits] == [732]
        assert kernel.handles == {101}
    finally:
        job.close()


@pytest.mark.parametrize('pid,returncode', [(731, None), (731, 1), (999, 0)])
def test_completed_go_cleanup_requires_the_successfully_waited_owned_root(monkeypatch, pid, returncode):
    job, kernel = _shutdown_job(monkeypatch)
    root = SimpleNamespace(pid=pid, returncode=returncode, wait=lambda **kw: returncode)
    try:
        with pytest.raises(OSError, match='successful completed Go compiler root required'):
            job.terminate_completed_go_compiler_and_wait(root)
        assert 'terminate requested' not in kernel.events
    finally:
        job.close()


@pytest.mark.parametrize('failure,reason', [
    ('late_member', 'cannot verify complete Windows descendant termination'),
    ('wait_timeout', 'timed out.*termination'),
    ('QueryAccounting', 'QueryInformationJobObject.*failed'),
])
def test_completed_go_cleanup_still_rejects_new_admissions_and_os_wait_failures(monkeypatch, failure, reason):
    job, kernel = _shutdown_job(monkeypatch, failure)
    kernel.total_processes += 3  # historical children are trusted only before the cleanup census
    root = SimpleNamespace(pid=731, returncode=0, wait=lambda **kw: 0)
    try:
        with pytest.raises(OSError, match=reason):
            job.terminate_completed_go_compiler_and_wait(root)
        assert kernel.handles == {101}
    finally:
        job.close()


def test_lifetime_accounting_is_checked_again_after_member_waits(monkeypatch):
    job, kernel = _shutdown_job(monkeypatch)
    original = kernel.WaitForSingleObject

    def wait(handle, milliseconds):
        result = original(handle, milliseconds)
        kernel.total_processes += 1
        return result

    monkeypatch.setattr(kernel, 'WaitForSingleObject', wait)
    try:
        with pytest.raises(OSError, match='cannot verify complete Windows descendant termination'):
            job.terminate_and_wait()
        assert len(kernel.waits) == 2
        assert kernel.handles == {101}
    finally:
        job.close()


def test_shutdown_waits_share_one_deadline(monkeypatch):
    from aegis_core.ast import windows_job

    job, kernel = _shutdown_job(monkeypatch)
    clock = [100.0]
    monkeypatch.setattr(windows_job, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    original = kernel.WaitForSingleObject

    def wait(handle, milliseconds):
        result = original(handle, milliseconds)
        clock[0] += 0.5
        return result

    monkeypatch.setattr(kernel, 'WaitForSingleObject', wait)
    try:
        job.terminate_and_wait()
        assert [milliseconds for _, milliseconds in kernel.waits] == [3000, 2500]
    finally:
        job.close()


def test_shutdown_deadline_also_bounds_already_signaled_members(monkeypatch):
    from aegis_core.ast import windows_job

    job, kernel = _shutdown_job(monkeypatch)
    clock = [100.0]
    monkeypatch.setattr(windows_job, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    original = kernel.WaitForSingleObject

    def wait(handle, milliseconds):
        result = original(handle, milliseconds)
        clock[0] += 3.0
        return result

    monkeypatch.setattr(kernel, 'WaitForSingleObject', wait)
    try:
        with pytest.raises(OSError, match='timed out.*termination'):
            job.terminate_and_wait()
        assert len(kernel.waits) == 1
        assert kernel.handles == {101}
    finally:
        job.close()


@pytest.mark.parametrize('failure,reason', [
    ('TerminateJobObject', 'TerminateJobObject failed'),
    ('QueryInformationJobObject', 'QueryInformationJobObject failed'),
    ('QueryAccounting', 'QueryInformationJobObject.*failed'),
    ('OpenProcess(member)', 'OpenProcess.*failed'),
    ('IsProcessInJob', 'IsProcessInJob failed'),
    ('wait_failed', 'WaitForSingleObject failed'),
    ('member_status_failed', 'WaitForSingleObject failed'),
    ('wait_timeout', 'timed out.*termination'),
    ('too_many_members', 'process list exceeds'),
    ('truncated_members', 'invalid.*process list'),
    ('count_exceeds_assigned', '^invalid Windows job process list: returned 2, assigned 0, capacity 64$'),
])
def test_shutdown_os_failures_remain_visible_and_release_transient_handles(monkeypatch, failure, reason):
    job, kernel = _shutdown_job(monkeypatch, failure)
    try:
        with pytest.raises(OSError, match=reason):
            job.terminate_and_wait()
        assert kernel.handles == {101}
    finally:
        job.close()
    assert not kernel.handles


@pytest.mark.parametrize('failure', ['member_gone', 'member_retired'])
def test_shutdown_accepts_only_provably_gone_or_signaled_former_members(monkeypatch, failure):
    job, kernel = _shutdown_job(monkeypatch, failure)
    try:
        job.terminate_and_wait()
        assert all(milliseconds == 0 for _, milliseconds in kernel.waits)
        assert kernel.handles == {101}
    finally:
        job.close()


def test_unowned_nonsignaled_process_cannot_pass_shutdown_or_receive_a_timed_wait(monkeypatch):
    job, kernel = _shutdown_job(monkeypatch, 'member_reused')
    try:
        with pytest.raises(OSError, match='cannot verify complete Windows descendant termination'):
            job.terminate_and_wait()
        assert len(kernel.waits) == 1 and kernel.waits[0][1] == 0
        assert kernel.handles == {101}
    finally:
        job.close()


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
