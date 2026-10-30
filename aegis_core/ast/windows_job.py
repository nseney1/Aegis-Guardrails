"""Retain Windows batch descendants in a non-inheritable, kill-on-close job.

Only imported by Windows batch execution. Popen closes the primary thread
handle, so a suspended root is assigned before its sole thread is found using
Toolhelp and resumed. No driver instruction can run before job assignment.

Win32 contracts: https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
and https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import ctypes
import time


CREATE_SUSPENDED = 0x00000004
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_PROCESS_SET_QUOTA = 0x0100
_PROCESS_TERMINATE = 0x0001
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SYNCHRONIZE = 0x100000
_JOB_OBJECT_BASIC_PROCESS_ID_LIST = 3
_MAX_JOB_PROCESSES = 65536
_THREAD_SUSPEND_RESUME = 0x0002
_THREAD_QUERY_LIMITED_INFORMATION = 0x0800
_TH32CS_SNAPTHREAD = 0x00000004
_ERROR_NO_MORE_FILES = 18
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int32
_HANDLE = ctypes.c_void_p
_SIZE_T = ctypes.c_size_t


def _remaining_milliseconds(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise OSError('timed out waiting for Windows job termination')
    return int(remaining * 1000)


class JobBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ('PerProcessUserTimeLimit', ctypes.c_int64), ('PerJobUserTimeLimit', ctypes.c_int64),
        ('LimitFlags', _DWORD), ('MinimumWorkingSetSize', _SIZE_T),
        ('MaximumWorkingSetSize', _SIZE_T), ('ActiveProcessLimit', _DWORD),
        ('Affinity', _SIZE_T), ('PriorityClass', _DWORD), ('SchedulingClass', _DWORD),
    ]


class IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        'ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
        'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount',
    )]


class JobExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ('BasicLimitInformation', JobBasicLimitInformation), ('IoInfo', IoCounters),
        ('ProcessMemoryLimit', _SIZE_T), ('JobMemoryLimit', _SIZE_T),
        ('PeakProcessMemoryUsed', _SIZE_T), ('PeakJobMemoryUsed', _SIZE_T),
    ]


class JobBasicAccountingInformation(ctypes.Structure):
    _fields_ = [(name, ctypes.c_int64) for name in (
        'TotalUserTime', 'TotalKernelTime', 'ThisPeriodTotalUserTime', 'ThisPeriodTotalKernelTime',
    )] + [(name, _DWORD) for name in (
        'TotalPageFaultCount', 'TotalProcesses', 'ActiveProcesses', 'TotalTerminatedProcesses',
    )]


class ThreadEntry32(ctypes.Structure):
    _fields_ = [
        ('dwSize', _DWORD), ('cntUsage', _DWORD), ('th32ThreadID', _DWORD),
        ('th32OwnerProcessID', _DWORD), ('tpBasePri', ctypes.c_int32),
        ('tpDeltaPri', ctypes.c_int32), ('dwFlags', _DWORD),
    ]


def _load_kernel32():
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    declarations = {
        'CreateJobObjectW': (_HANDLE, [ctypes.c_void_p, ctypes.c_wchar_p]),
        'SetInformationJobObject': (_BOOL, [_HANDLE, ctypes.c_int, ctypes.c_void_p, _DWORD]),
        'AssignProcessToJobObject': (_BOOL, [_HANDLE, _HANDLE]),
        'TerminateJobObject': (_BOOL, [_HANDLE, _DWORD]),
        'QueryInformationJobObject': (_BOOL, [_HANDLE, ctypes.c_int, ctypes.c_void_p, _DWORD,
                                             ctypes.POINTER(_DWORD)]),
        'IsProcessInJob': (_BOOL, [_HANDLE, _HANDLE, ctypes.POINTER(_BOOL)]),
        'WaitForSingleObject': (_DWORD, [_HANDLE, _DWORD]),
        'OpenProcess': (_HANDLE, [_DWORD, _BOOL, _DWORD]),
        'CreateToolhelp32Snapshot': (_HANDLE, [_DWORD, _DWORD]),
        'Thread32First': (_BOOL, [_HANDLE, ctypes.POINTER(ThreadEntry32)]),
        'Thread32Next': (_BOOL, [_HANDLE, ctypes.POINTER(ThreadEntry32)]),
        'OpenThread': (_HANDLE, [_DWORD, _BOOL, _DWORD]),
        'GetProcessIdOfThread': (_DWORD, [_HANDLE]),
        'ResumeThread': (_DWORD, [_HANDLE]),
        'CloseHandle': (_BOOL, [_HANDLE]),
        'GetLastError': (_DWORD, []),
    }
    for name, (result, arguments) in declarations.items():
        function = getattr(kernel, name)
        function.restype, function.argtypes = result, arguments
    return kernel


class WindowsJob:
    """Own one batch tree, including descendants of an already exited root."""

    def __init__(self):
        self._kernel = _load_kernel32()
        self._assigned = False
        self._root_pid = None
        self._handle = self._kernel.CreateJobObjectW(None, None)
        if not self._handle:
            raise self._error('CreateJobObjectW')
        try:
            limits = JobExtendedLimitInformation()
            limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not self._kernel.SetInformationJobObject(
                    self._handle, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    ctypes.byref(limits), ctypes.sizeof(limits)):
                raise self._error('SetInformationJobObject')
        except BaseException as original:
            try:
                self.close()
            except OSError as cleanup:
                raise OSError(f'{original}; cleanup failed: {cleanup}') from original
            raise

    def _error(self, operation):
        code = self._kernel.GetLastError()
        return OSError(code, f'{operation} failed (Windows error {code})')

    @contextmanager
    def _owned(self, handle):
        """Close transient handles without replacing the original failure."""
        original = None
        try:
            yield handle
        except BaseException as exc:
            original = exc
            raise
        finally:
            if not self._kernel.CloseHandle(handle):
                cleanup = self._error('CloseHandle')
                if original is not None:
                    raise OSError(f'{original}; cleanup failed: {cleanup}') from original
                raise cleanup

    def _primary_thread(self, pid):
        snapshot = self._kernel.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
        if snapshot == _INVALID_HANDLE_VALUE:
            raise self._error('CreateToolhelp32Snapshot')
        with self._owned(snapshot):
            entry = ThreadEntry32()
            entry.dwSize = ctypes.sizeof(entry)
            if not self._kernel.Thread32First(snapshot, ctypes.byref(entry)):
                raise self._error('Thread32First')
            threads = []
            while True:  # a finite snapshot, not a polling loop
                if entry.th32OwnerProcessID == pid:
                    threads.append(entry.th32ThreadID)
                entry.dwSize = ctypes.sizeof(entry)
                if not self._kernel.Thread32Next(snapshot, ctypes.byref(entry)):
                    if self._kernel.GetLastError() != _ERROR_NO_MORE_FILES:
                        raise self._error('Thread32Next')
                    break
            if len(threads) != 1:
                raise OSError('suspended driver must have exactly one primary thread')
            return threads[0]

    def assign_and_resume(self, pid: int) -> None:
        """The caller keeps Popen's root handle alive, preventing PID reuse."""
        process = self._kernel.OpenProcess(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE, False, pid)
        if not process:
            raise self._error('OpenProcess')
        with self._owned(process):
            if not self._kernel.AssignProcessToJobObject(self._handle, process):
                raise self._error('AssignProcessToJobObject')
            self._assigned = True
            self._root_pid = pid
            tid = self._primary_thread(pid)
            thread = self._kernel.OpenThread(
                _THREAD_SUSPEND_RESUME | _THREAD_QUERY_LIMITED_INFORMATION, False, tid)
            if not thread:
                raise self._error('OpenThread')
            with self._owned(thread):
                owner = self._kernel.GetProcessIdOfThread(thread)
                if not owner:
                    raise self._error('GetProcessIdOfThread')
                if owner != pid:
                    raise OSError('suspended driver thread changed owner')
                previous = self._kernel.ResumeThread(thread)
                if previous == 0xFFFFFFFF:
                    raise self._error('ResumeThread')
                if previous != 1:
                    raise OSError(f'ResumeThread expected suspend count 1, got {previous}')

    def _process_ids(self, deadline):
        capacity = 64
        while capacity <= _MAX_JOB_PROCESSES:
            _remaining_milliseconds(deadline)

            class ProcessIds(ctypes.Structure):
                _fields_ = [('assigned', _DWORD), ('count', _DWORD), ('pids', _SIZE_T * capacity)]

            info = ProcessIds()
            if self._kernel.QueryInformationJobObject(
                    self._handle, _JOB_OBJECT_BASIC_PROCESS_ID_LIST,
                    ctypes.byref(info), ctypes.sizeof(info), None):
                if info.count > capacity or info.assigned != info.count:
                    raise OSError('invalid Windows job process list')
                return list(info.pids[:info.count])
            if self._kernel.GetLastError() != 234:  # ERROR_MORE_DATA
                raise self._error('QueryInformationJobObject')
            capacity = max(capacity * 2, info.assigned)
        raise OSError('Windows job process list exceeds 65536 members')

    def _check_process_census(self, observed, deadline):
        _remaining_milliseconds(deadline)
        info = JobBasicAccountingInformation()
        if not self._kernel.QueryInformationJobObject(
                self._handle, 1, ctypes.byref(info), ctypes.sizeof(info), None):
            raise self._error('QueryInformationJobObject(accounting)')
        _remaining_milliseconds(deadline)
        if info.TotalProcesses != len(observed):
            raise OSError('cannot verify complete Windows descendant termination: '
                          f'job admitted {info.TotalProcesses} processes; observed {len(observed)} identities')

    def terminate_and_wait(self) -> None:
        """Wait for process exits, rather than asynchronous kill-on-close.

        Retain validated member handles before termination can remove their
        PIDs from the job list. A lifetime admission count detects descendants
        missing from that snapshot, including prior children: those sessions
        fail closed because complete descendant termination cannot be proven.
        The caller retains and reaps the known root through its Popen handle.
        A handle no longer in the job must already be signaled; an alive process
        outside the job is ambiguous and receives no timed wait.

        https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject
        https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess
        https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information
        """
        if self._handle is None or not self._assigned:
            return
        deadline = time.monotonic() + 3.0
        pids = self._process_ids(deadline)
        observed = set(pids) | {self._root_pid}
        with ExitStack() as owners:
            processes = []
            for pid in pids:
                _remaining_milliseconds(deadline)
                process = self._kernel.OpenProcess(
                    _SYNCHRONIZE | _PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if not process:
                    if self._kernel.GetLastError() == 87:  # ERROR_INVALID_PARAMETER: process gone
                        continue
                    raise self._error('OpenProcess(member)')
                owners.enter_context(self._owned(process))
                member = _BOOL()
                if not self._kernel.IsProcessInJob(process, self._handle, ctypes.byref(member)):
                    raise self._error('IsProcessInJob')
                if member.value:
                    processes.append(process)
                else:
                    result = self._kernel.WaitForSingleObject(process, 0)
                    if result == 0xFFFFFFFF:
                        raise self._error('WaitForSingleObject')
                    if result != 0:
                        raise OSError('cannot verify complete Windows descendant termination: '
                                      'former member is not signaled')
            if not self._kernel.TerminateJobObject(self._handle, 1):
                raise self._error('TerminateJobObject')
            self._check_process_census(observed, deadline)
            for process in processes:
                milliseconds = _remaining_milliseconds(deadline)
                result = self._kernel.WaitForSingleObject(process, milliseconds)
                if result == 0xFFFFFFFF:
                    raise self._error('WaitForSingleObject')
                if result == 258:  # WAIT_TIMEOUT
                    raise OSError('timed out waiting for Windows job termination')
                if result != 0:
                    raise OSError(f'WaitForSingleObject returned unexpected result {result}')
            self._check_process_census(observed, deadline)

    def close(self) -> None:
        if self._handle is not None:
            if not self._kernel.CloseHandle(self._handle):
                raise self._error('CloseHandle(job)')
            self._handle = None
