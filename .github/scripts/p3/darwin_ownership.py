"""External Darwin ownership; private libproc ABI and real host validation required."""
from __future__ import annotations

import contextlib
import ctypes
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

__all__ = ['DarwinAPI', 'DarwinOwnedTree', 'OwnershipError', 'defer_stops', 'stop_handlers']


@contextlib.contextmanager
def stop_handlers():
    """Convert launcher INT/TERM into exceptions so its finally block runs."""
    def request_stop(signum, _frame):
        raise KeyboardInterrupt(f'termination signal {signum}')

    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for sig in previous:
            signal.signal(sig, request_stop)
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


@contextlib.contextmanager
def defer_stops(record):
    """Latch further stops while bounded cleanup and evidence are finalized."""
    def remember(signum, _frame):
        record.setdefault('deferred_signals', []).append(signum)
        record['status'] = 'FAIL'
        record.setdefault('error', f'termination signal {signum} during finalization')

    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for sig in previous:
            signal.signal(sig, remember)
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


class OwnershipError(RuntimeError):
    pass


class InventoryError(OwnershipError):
    def __init__(self, errors, rows):
        super().__init__('; '.join(errors))
        self.rows = rows


class UniqueInfo(ctypes.Structure):
    _fields_ = [('uuid', ctypes.c_uint8 * 16), ('unique', ctypes.c_uint64),
                ('parent', ctypes.c_uint64), ('version', ctypes.c_int32),
                ('parent_version', ctypes.c_int32), ('reserved2', ctypes.c_uint64),
                ('reserved3', ctypes.c_uint64)]


class BSDInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in
                ('flags', 'status', 'xstatus', 'pid', 'ppid', 'uid', 'gid',
                 'ruid', 'rgid', 'svuid', 'svgid', 'reserved')]
    _fields_ += [('comm', ctypes.c_char * 16), ('name', ctypes.c_char * 32)]
    _fields_ += [(name, ctypes.c_uint32) for name in
                ('nfiles', 'pgid', 'jobc', 'tdev', 'tpgid')]
    _fields_ += [('nice', ctypes.c_int32), ('start_sec', ctypes.c_uint64),
                 ('start_usec', ctypes.c_uint64)]


class CombinedInfo(ctypes.Structure):
    _fields_ = [('bsd', BSDInfo), ('identity', UniqueInfo)]


class AuditToken(ctypes.Structure):
    _fields_ = [('val', ctypes.c_uint32 * 8)]


def require(condition, detail):
    if not condition:
        raise OwnershipError(detail)


class DarwinAPI:
    """Only the three OS calls are replaced by the boundary tests."""
    def __init__(self, library=None, *, max_pids=65536, observer=None):
        require(ctypes.sizeof(ctypes.c_void_p) == 8 and ctypes.sizeof(ctypes.c_int) == 4,
                'unsupported_darwin_abi')
        require((ctypes.sizeof(UniqueInfo), ctypes.sizeof(BSDInfo),
                 ctypes.sizeof(CombinedInfo), ctypes.sizeof(AuditToken)) == (56, 136, 192, 32)
                and UniqueInfo.version.offset == 32 and BSDInfo.start_sec.offset == 120
                and CombinedInfo.identity.offset == 136, 'invalid_darwin_struct_layout')
        require(256 <= max_pids <= 65536, 'invalid_pid_capacity')
        self.max_pids, self.observer = max_pids, observer
        if library is None:
            require(sys.platform == 'darwin', 'darwin_host_required')
            try:
                library = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
            except OSError as exc:
                raise OwnershipError('libproc_unavailable: ' + str(exc)) from exc
        self.library = library
        signatures = {
            'proc_listpids': [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int32],
            'proc_pidinfo': [ctypes.c_int32, ctypes.c_int32, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int32],
            'proc_signal_with_audittoken': [ctypes.POINTER(AuditToken), ctypes.c_int32],
        }
        for name, args in signatures.items():
            try:
                function = getattr(library, name)
            except AttributeError as exc:
                raise OwnershipError('missing_libproc_symbol: ' + name) from exc
            function.argtypes, function.restype = args, ctypes.c_int32

    def emit(self, event):
        if self.observer is not None:
            self.observer(event)

    def _list(self, buffer, size):
        ctypes.set_errno(0)
        count = self.library.proc_listpids(1, 0, buffer, size)
        error = ctypes.get_errno()
        self.emit({'api': 'proc_listpids', 'requested_bytes': size, 'returned_bytes': count, 'errno': error})
        require(count > 0 and count % 4 == 0,
                f'pid_list_failed_or_unaligned: bytes={count} errno={error}')
        return count

    def inventory(self, *, deadline=None):
        deadline = time.monotonic() + 5 if deadline is None else deadline
        require(time.monotonic() < deadline, 'census_deadline_exceeded')
        estimate = self._list(None, 0) // 4
        capacity = estimate + 256
        require(capacity <= self.max_pids, 'pid_list_capacity_exceeded')
        buffer = (ctypes.c_int32 * capacity)()
        count = self._list(buffer, ctypes.sizeof(buffer))
        require(count < ctypes.sizeof(buffer), 'pid_list_saturated')
        pids = list(buffer[:count // 4])
        require(all(pid >= 0 for pid in pids) and len(set(pids)) == len(pids), 'pid_list_invalid_or_duplicate')
        result, errors = {}, []
        for pid in pids:
            try:
                require(time.monotonic() < deadline, 'census_deadline_exceeded')
                result[pid] = self.identity(pid)
                require(time.monotonic() < deadline, 'census_deadline_exceeded')
            except OwnershipError as exc:
                errors.append(str(exc))
        if errors:
            raise InventoryError(errors, result)
        require(len({r['unique'] for r in result.values()}) == len(result), 'duplicate_unique_identity')
        require(os.getpid() in result, 'supervisor_missing_from_inventory')
        return result

    def _query(self, pid, flavor, value):
        require(0 <= pid < 2 ** 31, 'invalid_pid')
        ctypes.set_errno(0)
        size = ctypes.sizeof(value)
        count = self.library.proc_pidinfo(pid, flavor, 1, ctypes.byref(value), size)
        error = ctypes.get_errno()
        self.emit({'api': 'proc_pidinfo', 'pid': pid, 'flavor': flavor, 'zombie_lookup': 1,
                       'requested_bytes': size, 'returned_bytes': count, 'errno': error})
        require(count == size, f'pidinfo_failed: pid={pid} flavor={flavor} bytes={count} expected={size} errno={error}')

    def _identity(self, pid, value):
        require(pid == 0 or value.unique != 0, 'invalid_unique_identity')
        row = {'pid': pid, 'unique': value.unique, 'parent': value.parent,
                   'version': value.version & 0xFFFFFFFF, 'parent_version': value.parent_version & 0xFFFFFFFF}
        self.emit(dict(api='identity', **row))
        return row

    def identity(self, pid):
        value = UniqueInfo()
        self._query(pid, 17, value)
        return self._identity(pid, value)

    def process(self, pid):
        value = CombinedInfo()
        self._query(pid, 18, value)
        bsd = value.bsd
        require(bsd.pid == pid and 1 <= bsd.status <= 5 and bsd.start_usec < 1000000,
                'invalid_combined_process_record')
        row = dict(self._identity(pid, value.identity), status=bsd.status,
                   start=[bsd.start_sec, bsd.start_usec], uid=bsd.uid, ppid=bsd.ppid, pgid=bsd.pgid)
        self.emit(dict(api='owned_process', **row))
        return row

    def send(self, row, signum):
        require(signum in (signal.SIGTERM, signal.SIGKILL), 'unsupported_signal')
        token = AuditToken((ctypes.c_uint32 * 8)(*([0xFFFFFFFF] * 8)))
        token.val[5], token.val[7] = row['pid'], row['version']
        error = self.library.proc_signal_with_audittoken(ctypes.byref(token), signum)
        self.emit({'api': 'proc_signal_with_audittoken', 'unique': row['unique'],
                       'token': list(token.val), 'signal': int(signum), 'result': error})
        require(error == 0, f"token_signal_failed: pid={row['pid']} unique={row['unique']} errno={error}")


class DarwinOwnedTree:
    """prepare -> launch/attach_gated -> wait -> close; errors remain latched."""
    def __init__(self, api=None, *, observer=None, interval=.1, cleanup_seconds=5,
                 max_rounds=20000, max_records=5000000):
        require(0 < interval <= 1 and 0 < cleanup_seconds <= 5, 'invalid_cleanup_bound')
        self.api = api if api is not None else DarwinAPI(observer=observer)
        self.observer, self.interval, self.cleanup_seconds = observer, interval, cleanup_seconds
        self.max_rounds, self.max_records, self.count = max_rounds, max_records, 0
        self.graph, self.pid_history, self.outside, self.starts = {}, {}, set(), {}
        self.blocked, self.errors, self.rounds = set(), [], []
        self.proc, self.root, self.initial, self.closed = None, None, None, False
        self.result = None

    def _error(self, message):
        message = str(message)
        if message not in self.errors:
            self.errors.append(message)

    def _event(self, event):
        if self.observer is not None:
            self.observer(event)

    def _ingest(self, rows):
        for pid, row in rows.items():
            unique = row['unique']
            if pid in self.pid_history and self.pid_history[pid] != unique:
                self._error(f'pid_reuse: {pid}')
            self.pid_history[pid] = unique
            prior = self.graph.get(unique)
            if prior is not None and any(prior[k] != row[k] for k in ('pid', 'parent', 'parent_version')):
                self._error(f'immutable_identity_changed: {unique}')
                self.blocked.add(unique)
            else:
                self.graph[unique] = dict(row)

    def classification(self, unique):
        seen = set()
        while unique not in seen:
            if unique == self.root:
                return 'owned'
            if unique in self.outside:
                return 'outside'
            seen.add(unique)
            row = self.graph.get(unique)
            if row is None:
                break
            unique = row['parent']
        return 'unresolved'

    def _round(self, label, *, classify=True, deadline=None):
        entry = {'label': label, 'status': 'FAIL'}
        self.rounds.append(entry)
        rows = None
        try:
            require(len(self.rounds) <= self.max_rounds, 'census_round_budget_exceeded')
            rows = self.api.inventory(deadline=deadline)
            self.count += len(rows)
            require(self.count <= self.max_records, 'census_record_budget_exceeded')
            self._ingest(rows)
            if classify:
                unknown = [r['unique'] for r in rows.values() if self.classification(r['unique']) == 'unresolved']
                require(not unknown, 'unresolved_ancestry: ' + repr(unknown))
            entry.update(status='PASS', count=len(rows))
        except OwnershipError as exc:
            if isinstance(exc, InventoryError):
                rows = exc.rows
                self.count += len(rows)
                self._ingest(rows)
            self._error(exc)
            entry['error'] = str(exc)
        self._event(dict(event='census', **entry, rows=rows))
        if label.startswith(('initial-', 'final-')):
            entry['rows'] = rows
        return rows

    def prepare(self):
        require(self.initial is None and self.proc is None and not self.closed, 'invalid_prepare_state')
        deadline = time.monotonic() + 5
        first = self._round('initial-1', classify=False, deadline=deadline)
        second = self._round('initial-2', classify=False, deadline=deadline)
        if first is None or first != second:
            self._error('initial_maps_differ_or_incomplete')
        require(not self.errors, '; '.join(self.errors))
        self.initial = second
        self.outside = {r['unique'] for r in second.values()}
        try:
            own = self.api.process(os.getpid())
            require(all(own[k] == second[os.getpid()][k] for k in second[os.getpid()]), 'supervisor_identity_changed')
            require(own['uid'] == os.geteuid() and own['pgid'] == os.getpgrp(), 'supervisor_abi_check_failed')
        except OwnershipError as exc:
            self._error(exc)
            raise

    def attach_gated(self, proc, release):
        require(self.initial is not None and self.proc is None and not self.closed and not self.errors,
                'invalid_attach_state_or_failed_preparation')
        self.proc = proc
        try:
            row = self.api.process(proc.pid)
            require(proc.poll() is None and row['unique'] not in self.outside
                    and row['pid'] not in self.initial, 'worker_not_new_and_gated')
            require(row['parent'] == self.initial[os.getpid()]['unique'], 'worker_not_direct_child')
            self.root = row['unique']
            self.starts[self.root] = row['start']
            self._ingest({row['pid']: {k: row[k] for k in ('pid', 'unique', 'parent', 'version', 'parent_version')}})
            release()
            self._event({'event': 'worker_released', 'identity': row})
        except BaseException as exc:
            self._error('worker_attach_failed: ' + str(exc))
            raise

    def launch(self, argv, **kwargs):
        """The Python trampoline cannot exec until its identity is admitted."""
        require('pass_fds' not in kwargs and 'start_new_session' not in kwargs, 'reserved_launch_option')
        self.prepare()
        reader, writer = os.pipe()
        try:
            command = [sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()),
                       '--gate', str(reader), '--', *map(str, argv)]
            proc = subprocess.Popen(command, pass_fds=(reader,), start_new_session=True, **kwargs)
            self.attach_gated(proc, lambda: require(os.write(writer, b'G') == 1, 'gate_release_failed'))
            return proc
        finally:
            os.close(reader)
            os.close(writer)

    def scan(self, *, deadline=None):
        require(self.root is not None and not self.closed, 'invalid_scan_state')
        return self._round('running', deadline=deadline)

    def wait(self, timeout):
        require(self.proc is not None and 0 < timeout <= 1500, 'invalid_worker_wait')
        try:
            deadline = time.monotonic() + timeout
            while self.proc.poll() is None:
                require(time.monotonic() < deadline, 'worker_timeout')
                self.scan(deadline=deadline)
                require(not self.errors, '; '.join(self.errors))
                time.sleep(min(self.interval, max(0, deadline - time.monotonic())))
            return self.proc.wait(timeout=0)
        except BaseException as exc:
            self._error(str(exc))
            raise

    def _owned(self, rows, deadline):
        live = []
        for row in (rows or {}).values():
            unique = row['unique']
            if self.classification(unique) != 'owned' or unique in self.blocked:
                continue
            try:
                require(time.monotonic() < deadline, 'census_deadline_exceeded')
                current = self.api.process(row['pid'])
                require(time.monotonic() < deadline, 'census_deadline_exceeded')
                require(all(current[k] == row[k] for k in ('pid', 'unique', 'parent', 'parent_version')),
                        f'owned_identity_changed: {unique}')
                require(unique not in self.starts or current['start'] == self.starts[unique],
                        f'owned_start_changed: {unique}')
                self.starts[unique] = current['start']
                if current['status'] != 5:
                    live.append(current)
            except OwnershipError as exc:
                self._error(exc)
                self.blocked.add(unique)
        return live

    def close(self):
        if self.closed:
            return self.result
        final_one = final_two = None
        close_deadline = time.monotonic() + 2 * self.cleanup_seconds
        try:
            if self.proc is None or self.root is None:
                self._error('worker_never_admitted')
                if self.proc is not None:
                    # launch closes the gate on admission failure. Reap only
                    # this direct child; an unverified PID never authorizes a
                    # signal, even when it was our attempted worker.
                    try:
                        self.proc.wait(timeout=5)
                    except subprocess.TimeoutExpired as exc:
                        self._error('unadmitted_worker_not_reaped: ' + str(exc))
            else:
                rows = self._round('cleanup-start', deadline=close_deadline)
                living = self._owned(rows, close_deadline)
                if living or self.proc.poll() is None:
                    self._error('fallback_cleanup_required')
                for signum in (signal.SIGTERM, signal.SIGKILL):
                    if not living:
                        break
                    sent = set()
                    deadline = min(close_deadline, time.monotonic() + self.cleanup_seconds)
                    while living:
                        for row in living:
                            if row['unique'] not in sent:
                                sent.add(row['unique'])
                                try:
                                    self.api.send(row, signum)
                                except OwnershipError as exc:
                                    self._error(exc)
                                    self.blocked.add(row['unique'])
                        rows = self._round('cleanup', deadline=close_deadline)
                        living = self._owned(rows, close_deadline)
                        if not living or time.monotonic() >= deadline:
                            break
                        time.sleep(min(self.interval, max(0, deadline - time.monotonic())))
                try:
                    self.proc.wait(timeout=min(.5, max(0, close_deadline - time.monotonic())))
                except subprocess.TimeoutExpired as exc:
                    self._error('worker_not_reaped: ' + str(exc))
                if self.proc.returncode != 0:
                    self._error('worker_exit: ' + str(self.proc.returncode))
                final_one = self._round('final-1', deadline=close_deadline)
                final_two = self._round('final-2', deadline=close_deadline)
                if final_one is None or final_one != final_two:
                    self._error('final_maps_differ_or_incomplete')
                if self._owned(final_two, close_deadline):
                    self._error('live_owned_process_in_final_census')
        except BaseException as exc:  # noqa: BLE001 - the public cleanup result must retain every failure, including interrupts.
            self._error(type(exc).__name__ + ': ' + str(exc))
        self.closed = True
        cleanup_errors = [e for e in self.errors if e != 'fallback_cleanup_required' and not e.startswith('worker_exit:')]
        self.result = {'platform': 'darwin', 'status': 'FAIL' if self.errors else 'PASS',
                           'cleanup_complete': final_one is not None and final_one == final_two and not cleanup_errors,
                           'errors': list(self.errors), 'rounds': self.rounds, 'graph': self.graph,
                           'classification': {str(u): self.classification(u) for u in self.graph},
                           'starts': self.starts, 'returncode': self.proc.returncode if self.proc is not None else None,
                           'census_records': self.count}
        self._event({'event': 'result', 'result': self.result})
        return self.result


def _gate_main():
    require(len(sys.argv) >= 5 and sys.argv[1] == '--gate' and sys.argv[3] == '--', 'invalid_gate_arguments')
    descriptor = int(sys.argv[2])
    try:
        released = os.read(descriptor, 1)
    finally:
        os.close(descriptor)
    require(released == b'G', 'worker_gate_closed')
    os.execvpe(sys.argv[4], sys.argv[4:], os.environ)


if __name__ == '__main__':
    _gate_main()
