"""Spawned workers for proposal-store cross-process contracts.

Importable by module and name because racers start with the ``spawn`` start
method, which pickles the target. pytest's importlib mode does not make the
test module importable that way.

Each worker constructs its own store, then waits on the shared barrier, then
performs one store operation. Results are short status tokens. A child that
does not report is terminated and reaped by ``run_workers``.
"""
from __future__ import annotations

from collections import namedtuple
import multiprocessing
import queue
import re
import time
from pathlib import Path

WorkerReport = namedtuple("WorkerReport", "results timed_out exitcodes pids forced")

_DECISIONS = ("propose", "reject", "snooze", "merge-into-rule", "noise", "confirm", "accept")
_ID = re.compile(r"[a-z0-9][a-z0-9_-]{1,63}\Z")
_WORKER = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_CODE = re.compile(r"[a-z0-9_-]{0,32}\Z")
_STATUSES = {"written", "refused", "released", "error"}
_MAX_WORKERS = 2
_MAX_TIMEOUT = 60.0
_BARRIER_TIMEOUT = 30
_EVENT_TIMEOUT = 10.0


def worker_context():
    """Spawn context shared by processes, barriers and events."""
    return multiprocessing.get_context("spawn")


def _token(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def _line(value, limit):
    """A single-line bounded string. Newlines are refused, never flattened."""
    return (type(value) is str and len(value) <= limit and "\n" not in value and "\r" not in value)


def _path(value):
    if not _line(value, 4096) or "\x00" in value:
        return False
    return Path(value).is_absolute()


def _number(value, upper):
    return type(value) in (int, float) and type(value) is not bool and 0 < value <= upper


def _wait(barrier):
    try:
        barrier.wait(timeout=_BARRIER_TIMEOUT)
    except BaseException as exc:
        return False
    return True


def _put(results, worker, status, code):
    if not _token(worker, _WORKER):
        worker = "worker"
    if status not in _STATUSES or not _token(code, _CODE):
        status, code = "error", "worker"
    try:
        results.put((worker, status, code))
    except BaseException as exc:
        return


def _refusal(exc):
    code = getattr(exc, "code", None)
    if _token(code, _CODE) and code:
        return code
    return "invalid"


def _failure(exc):
    """Exception class only. The message can carry untrusted input and is never returned."""
    name = type(exc).__name__.lower()
    if _token(name, _CODE) and name:
        return name
    return "worker"


def _invalid(barrier, results, worker):
    _wait(barrier)
    _put(results, worker, "refused", "invalid")


def _store(root, home, timeout=5.0):
    from aegis_core.proposals import ProposalStore

    return ProposalStore(root, home=home, timeout=timeout)


def _sanitize(item):
    if (type(item) is tuple and len(item) == 3 and _token(item[0], _WORKER)
            and item[1] in _STATUSES and _token(item[2], _CODE)):
        return item
    return ("worker", "error", "worker")


def _event(value):
    return callable(getattr(value, "wait", None)) and callable(getattr(value, "set", None))


def _signal(event):
    try:
        event.set()
    except BaseException as exc:
        return


def _reap(procs, *, impatient):
    """Join children that have exited. Terminate, then kill, any that remain.

    A zero exit is a completed worker. ``forced`` is true only when this parent
    had to terminate or kill a child, which is a cleanup failure, not success.
    """
    forced = False
    if not impatient:
        for proc in procs:
            proc.join(timeout=5)
    for proc in procs:
        if proc.is_alive():
            proc.terminate()
            forced = True
    for proc in procs:
        proc.join(timeout=2)
    for proc in procs:
        if proc.is_alive():
            proc.kill()
            forced = True
    for proc in procs:
        proc.join(timeout=2)
    if any(proc.is_alive() for proc in procs):
        raise RuntimeError("unreaped workers")
    return tuple(proc.exitcode for proc in procs), forced


def _close(procs, results):
    for proc in procs:
        try:
            proc.close()
        except (ValueError, AttributeError):
            pass
    try:
        results.close()
    except BaseException as exc:
        pass
    try:
        results.cancel_join_thread()
    except BaseException as exc:
        pass


def run_workers(entries, *, timeout, context=None):
    """Start one or two spawned workers and always reap them.

    ``entries`` is a sequence of ``(target, args)``. Each target is called as
    ``target(*args, barrier, results)``. ``timeout`` bounds how long the parent
    waits for every child to report. On timeout the children are terminated and
    reaped. The returned report contains only short status tokens.
    """
    if type(entries) not in (list, tuple) or not 1 <= len(entries) <= _MAX_WORKERS:
        raise ValueError("worker bound")
    if not _number(timeout, _MAX_TIMEOUT):
        raise ValueError("timeout bound")
    for target, args in entries:
        if not callable(target) or type(args) not in (list, tuple):
            raise ValueError("worker bound")
    ctx = context or multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(len(entries))
    results = ctx.Queue()
    procs = [ctx.Process(target=target, args=tuple(args) + (barrier, results))
             for target, args in entries]
    collected = []
    timed_out = False
    started = []
    exitcodes = ()
    forced = False
    pids = ()
    try:
        for proc in procs:
            proc.start()
            started.append(proc)
        deadline = time.monotonic() + timeout
        while len(collected) < len(started):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            try:
                collected.append(_sanitize(results.get(timeout=remaining)))
            except queue.Empty:
                timed_out = True
                break
    finally:
        pids = tuple(proc.pid for proc in started)
        try:
            exitcodes, forced = _reap(started, impatient=timed_out or len(collected) != len(started))
        finally:
            _close(procs, results)
    return WorkerReport(tuple(collected), timed_out, exitcodes, pids, forced)


def compare_replace(root, home, proposal_id, digest, text, worker, barrier, results):
    """Replace one proposal under its current digest. One racer wins; the other is stale."""
    if not (_path(root) and _path(home) and _token(proposal_id, _ID) and _token(digest, _DIGEST)
            and _line(text, 300) and _token(worker, _WORKER)):
        _invalid(barrier, results, worker)
        return
    try:
        from dataclasses import replace

        from aegis_core.proposals import ProposalError

        store = _store(root, home)
    except ProposalError as exc:
        _wait(barrier)
        _put(results, worker, "refused", _refusal(exc))
        return
    except BaseException as exc:
        _wait(barrier)
        _put(results, worker, "error", _failure(exc))
        return
    if not _wait(barrier):
        _put(results, worker, "error", "barrier")
        return
    try:
        saved = store.read(proposal_id)
        store.write(replace(saved.proposal, do=text), expected_digest=digest)
    except ProposalError as exc:
        _put(results, worker, "refused", _refusal(exc))
        return
    except BaseException as exc:
        _put(results, worker, "error", _failure(exc))
        return
    _put(results, worker, "written", "")


def decide(root, home, proposal_id, operation, decision, max_rows, worker, barrier, results):
    """Decide one proposal after the barrier. ``max_rows`` narrows the shared-log quota."""
    if not (_path(root) and _path(home) and _token(proposal_id, _ID) and _token(operation, _ID)
            and _line(decision, 32) and decision in _DECISIONS and _token(worker, _WORKER)
            and (max_rows is None or (type(max_rows) is int and 1 <= max_rows <= 4096))):
        _invalid(barrier, results, worker)
        return
    try:
        from aegis_core.proposals import ProposalError
        from aegis_core.proposals import store as store_module

        if max_rows is not None:
            store_module.MAX_ROWS = max_rows
        store = _store(root, home)
    except ProposalError as exc:
        _wait(barrier)
        _put(results, worker, "refused", _refusal(exc))
        return
    except BaseException as exc:
        _wait(barrier)
        _put(results, worker, "error", _failure(exc))
        return
    if not _wait(barrier):
        _put(results, worker, "error", "barrier")
        return
    try:
        row = store.decide([proposal_id], decision=decision, operation_id=operation)
        if type(row) is not dict or row.get("operation_id") != operation:
            _put(results, worker, "error", "worker")
            return
    except ProposalError as exc:
        _put(results, worker, "refused", _refusal(exc))
        return
    except BaseException as exc:
        _put(results, worker, "error", _failure(exc))
        return
    _put(results, worker, "written", operation)


def hold_shared_lock(root, home, lock_path, ready, done, worker, barrier, results):
    """Hold the shared-log lock until the waiter signals that its attempt finished."""
    if not (_path(root) and _path(home) and _path(lock_path) and _event(ready) and _event(done)
            and _token(worker, _WORKER)):
        _invalid(barrier, results, worker)
        return
    try:
        from aegis_core.proposals import ProposalError

        _store(root, home)
    except ProposalError as exc:
        _wait(barrier)
        _put(results, worker, "refused", _refusal(exc))
        return
    except BaseException as exc:
        _wait(barrier)
        _put(results, worker, "error", _failure(exc))
        return
    if not _wait(barrier):
        _put(results, worker, "error", "barrier")
        return
    finished = False
    try:
        from aegis_core.storage import file_lock

        holder = file_lock(Path(lock_path), timeout=5)
        entered = False
        try:
            holder.__enter__()
            entered = True
            ready.set()
            finished = bool(done.wait(timeout=_EVENT_TIMEOUT))
        finally:
            if entered:
                holder.__exit__(None, None, None)
    except BaseException as exc:
        _put(results, worker, "error", _failure(exc))
        return
    if not finished:
        _put(results, worker, "error", "done")
        return
    _put(results, worker, "released", "")


def decide_locked(root, home, proposal_id, operation, decision, timeout_s, ready, done, worker,
                  barrier, results):
    """Construct a store, wait until the peer holds the lock, then decide once."""
    if not (_path(root) and _path(home) and _token(proposal_id, _ID) and _token(operation, _ID)
            and _line(decision, 32) and decision in _DECISIONS and _number(timeout_s, 30)
            and _event(ready) and _event(done) and _token(worker, _WORKER)):
        _invalid(barrier, results, worker)
        _signal(done)
        return
    try:
        from aegis_core.proposals import ProposalError

        store = _store(root, home, timeout=timeout_s)
    except ProposalError as exc:
        _wait(barrier)
        _put(results, worker, "refused", _refusal(exc))
        _signal(done)
        return
    except BaseException as exc:
        _wait(barrier)
        _put(results, worker, "error", _failure(exc))
        _signal(done)
        return
    if not _wait(barrier):
        _put(results, worker, "error", "barrier")
        _signal(done)
        return
    try:
        if not ready.wait(timeout=_EVENT_TIMEOUT):
            _put(results, worker, "error", "ready")
            return
        try:
            row = store.decide([proposal_id], decision=decision, operation_id=operation)
            if type(row) is not dict or row.get("operation_id") != operation:
                _put(results, worker, "error", "worker")
                return
        except ProposalError as exc:
            _put(results, worker, "refused", _refusal(exc))
            return
        except BaseException as exc:
            _put(results, worker, "error", _failure(exc))
            return
        _put(results, worker, "written", operation)
    finally:
        _signal(done)


def hang(worker, barrier, results):
    """Pass the barrier, then sleep until the parent terminates this process."""
    if not _token(worker, _WORKER):
        _invalid(barrier, results, "worker")
        return
    if not _wait(barrier):
        _put(results, worker, "error", "barrier")
        return
    time.sleep(30)
    _put(results, worker, "written", "")


def report_then_crash(worker, barrier, results):
    """Report a normal write, then exit nonzero without being killed."""
    if not _token(worker, _WORKER):
        _invalid(barrier, results, "worker")
        return
    if not _wait(barrier):
        _put(results, worker, "error", "barrier")
        return
    _put(results, worker, "written", "")
    raise SystemExit(1)


def report_then_hang(worker, barrier, results):
    """Report a normal write, then sleep until the parent terminates this process."""
    if not _token(worker, _WORKER):
        _invalid(barrier, results, "worker")
        return
    if not _wait(barrier):
        _put(results, worker, "error", "barrier")
        return
    _put(results, worker, "written", "")
    time.sleep(30)
