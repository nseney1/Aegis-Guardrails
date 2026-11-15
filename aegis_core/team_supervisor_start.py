"""Explicit owner-invoked starter; the policy and ordinary Codex paths stay pure.

Commands are owner-supplied argv, never read from a repository. One held owner
directory descriptor covers lock, reads and atomic publication. An unfinished
attempt is a durable refusal requiring owner reconciliation, never a blind retry.
"""
from __future__ import annotations

from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

from aegis_core import storage_confined
from aegis_core.primitives import json_preflight
from aegis_core.team_supervisor import (
    COMPONENTS, STATE_NAME, STATE_MAX_BYTES, SupervisorError, empty_state,
    note_failure, note_success, plan, read_owned_leaf, validate_input,
)

__all__ = ["PROCESSES_NAME", "descriptor_supported", "process_identity", "start"]
PROCESSES_NAME = "supervisor-processes.json"
_REASONS = {
    "state_unavailable": "unsafe or unreadable supervisor state",
    "unsupported_platform": "unsupported platform: supervisor process identity unavailable",
    "state_locked": "supervisor state is locked",
    "identity_unavailable": "supervisor process identity unavailable",
    "identity_ambiguous": "supervisor process identity scope is ambiguous",
    "recovery_required": "unfinished supervisor attempt requires owner reconciliation",
    "invalid_commands": "invalid supervisor owner commands",
    "invalid_timeout": "invalid supervisor start timeout",
}
_children = {}
_BOOT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_PID_NAMESPACE = re.compile(r"pid:\[[0-9]{1,20}\]")
_EXEC_FAILURE_ERRNOS = frozenset((errno.ENOENT, errno.EACCES, errno.ENOEXEC, errno.ENOTDIR))


class _Refusal(ValueError):
    def __init__(self, code):
        super().__init__(_REASONS[code])
        self.code = code


def descriptor_supported():
    """Linux start ticks and POSIX directory locks are required; no fallback by PID."""
    return sys.platform == "linux" and storage_confined.descriptor_supported()


def process_identity(pid):
    """Read kernel identity, never a repository PID file; unknown is not dead."""
    if not descriptor_supported():
        raise _Refusal("unsupported_platform")
    if type(pid) is not int or not 1 <= pid <= 2147483647:
        raise _Refusal("identity_unavailable")
    try:
        with storage_confined.confined_file(Path("/proc"), (str(pid), "stat")) as handle:
            data = handle.read_bytes(4096)
        # comm may contain spaces, parentheses and newlines. Start ticks are field 22.
        prefix, separator, tail = data.rpartition(b") ")
        if not separator or not prefix.startswith(str(pid).encode("ascii") + b" ("):
            raise _Refusal("identity_unavailable")
        fields = tail.split()
        if len(fields) < 20 or not fields[19].isdigit() or len(fields[19]) > 20:
            raise _Refusal("identity_unavailable")
        if fields[0] in (b"Z", b"X", b"x"):
            return None
        return {"pid": pid, "start_ticks": int(fields[19])}
    except storage_confined.ConfinedFileError as error:
        if error.reason == "missing" and pid != os.getpid():
            if process_identity(os.getpid()) is None:
                raise _Refusal("identity_unavailable")
            return None
        raise _Refusal("identity_unavailable") from None


def _namespace():
    """Inspect kernel links on parent descriptors borrowed from confined storage."""
    with storage_confined.confined_file(Path("/proc"), ("self",)) as handle:
        # Reading self, rather than following it, also checks that numeric PIDs
        # mean the same thing in this proc mount and the caller's PID namespace.
        own_pid = os.readlink("self", dir_fd=handle._parent)
        if own_pid != str(os.getpid()):
            raise _Refusal("identity_unavailable")
    with storage_confined.confined_file(Path("/proc"), (own_pid, "ns", "pid")) as handle:
        namespace = os.readlink("pid", dir_fd=handle._parent)
        if len(namespace) > 26 or _PID_NAMESPACE.fullmatch(namespace) is None:
            raise _Refusal("identity_unavailable")
        return namespace


def _scope():
    try:
        with storage_confined.confined_file(Path("/proc"), ("sys", "kernel", "random", "boot_id")) as handle:
            data = handle.read_bytes(37)
        if len(data) not in (36, 37) or len(data) == 37 and data[-1:] != b"\n":
            raise _Refusal("identity_unavailable")
        boot = data[:36].decode("ascii")
        if _BOOT_ID.fullmatch(boot) is None:
            raise _Refusal("identity_unavailable")
        return {"boot_id": boot, "pid_namespace": _namespace()}
    except (storage_confined.ConfinedFileError, OSError, UnicodeError):
        raise _Refusal("identity_unavailable") from None


@contextmanager
def _state_directory(home):
    # Do not resolve untrusted intermediate links, even before opening the root.
    root = validate_input(home, {"type": "root", "maxLength": 32740,
                                "refusal": _REASONS["state_unavailable"]}, "root", "state")
    if ".." in root.parts:
        raise _Refusal("state_unavailable")
    with storage_confined.confined_file(root, (".config", "aegis", STATE_NAME)) as handle:
        info = handle.parent_stat()
        if info.st_uid != os.getuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise _Refusal("state_unavailable")
        yield handle._parent


@contextmanager
def _locked(directory):
    import fcntl
    try:
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise _Refusal("state_locked") from None
    try:
        yield
    finally:
        fcntl.flock(directory, fcntl.LOCK_UN)


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise _Refusal("state_unavailable")
        value[key] = item
    return value


def _decode(data):
    # Root/version/components plus five slots of six nodes and 100 events.
    text = json_preflight(data, max_bytes=STATE_MAX_BYTES, max_depth=8,
                          max_nodes=5 + len(COMPONENTS) * 106, max_items=100,
                          max_string=64, string_units="escaped", max_atom=20)
    return json.loads(text, object_pairs_hook=_pairs)


def _read(directory, name, default):
    data = read_owned_leaf(directory, name)
    return default if data is None else _decode(data)


def _records(value):
    if type(value) is dict and type(value.get("version")) is int and value["version"] == 1:
        raise _Refusal("identity_ambiguous")
    if (type(value) is not dict or set(value) != {"version", "processes", "pending"}
            or type(value["version"]) is not int or value["version"] != 2
            or type(value["processes"]) is not dict or len(value["processes"]) > len(COMPONENTS)
            or set(value["processes"]) - set(COMPONENTS)
            or value["pending"] is not None and value["pending"] not in COMPONENTS):
        raise _Refusal("state_unavailable")
    for record in value["processes"].values():
        if (type(record) is not dict or set(record) != {"pid", "start_ticks", "boot_id", "pid_namespace"}
                or type(record["pid"]) is not int or not 1 <= record["pid"] <= 2147483647
                or type(record["start_ticks"]) is not int or not 0 <= record["start_ticks"] < 10 ** 20
                or type(record["boot_id"]) is not str or len(record["boot_id"]) != 36
                or _BOOT_ID.fullmatch(record["boot_id"]) is None
                or type(record["pid_namespace"]) is not str or len(record["pid_namespace"]) > 26
                or _PID_NAMESPACE.fullmatch(record["pid_namespace"]) is None):
            raise _Refusal("state_unavailable")
    return value


def _publish(directory, name, value):
    # Recheck the destination through the same parent before atomic replacement.
    read_owned_leaf(directory, name)
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > STATE_MAX_BYTES:
        raise _Refusal("state_unavailable")
    storage_confined.ConfinedFile(directory, name).publish_bytes(data, replace=True, mode=0o600)


def _commands(commands):
    if type(commands) is not dict or len(commands) > len(COMPONENTS):
        raise _Refusal("invalid_commands")
    for name, argv in commands.items():
        if name not in COMPONENTS or type(argv) not in (tuple, list) or not 1 <= len(argv) <= 64:
            raise _Refusal("invalid_commands")
        total = 0
        for arg in argv:
            if type(arg) is not str or len(arg) > 4096 or "\0" in arg:
                raise _Refusal("invalid_commands")
            total += len(arg)
        if total > 32768 or not os.path.isabs(argv[0]):
            raise _Refusal("invalid_commands")
        for arg in argv:
            try:
                os.fsencode(arg)
            except UnicodeError:
                raise _Refusal("invalid_commands") from None
    return {name: tuple(argv) for name, argv in commands.items()}


def _spawn(argv, timeout):
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, cwd="/", close_fds=True, start_new_session=True)
    except BaseException as error:
        # CPython reaps the child before reporting these exec errors with the
        # executable filename. Other constructor failures can occur after fork.
        if (isinstance(error, OSError) and type(error.errno) is int
                and error.errno in _EXEC_FAILURE_ERRNOS and error.filename == argv[0]):
            raise
        if isinstance(error, Exception):
            raise _Refusal("recovery_required") from None
        # The attempt's intent was durably published before calling Popen.
        raise
    try:
        deadline = time.monotonic() + timeout
        while True:
            if process.poll() is not None:
                raise OSError("supervisor child exited during startup")
            identity = process_identity(process.pid)
            if identity is not None:
                _children[process.pid] = process
                return identity
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("supervisor startup", timeout)
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))
    except BaseException:
        try:
            if process.poll() is None:
                process.kill()
            if type(process.wait(timeout=timeout)) is not int:
                raise _Refusal("recovery_required")
        except Exception:
            raise _Refusal("recovery_required") from None
        raise


def _reap_children():
    for pid, process in tuple(_children.items()):
        if process.poll() is not None:
            _children.pop(pid, None)


def _attempt(directory, state, records, name, spec, argv, now, timeout, scope):
    # An intent survives every crash window, including successful exec before
    # identity publication. A new starter never guesses whether that exec ran.
    records["pending"] = name
    _publish(directory, PROCESSES_NAME, records)
    state = note_failure(state, name, now, spec["restart"])
    _publish(directory, STATE_NAME, state)
    outcome = "start_failed"
    try:
        identity = _spawn(argv, timeout)
    except (OSError, subprocess.TimeoutExpired):
        records["processes"].pop(name, None)
    else:
        records["processes"][name] = {**identity, **scope}
        _publish(directory, PROCESSES_NAME, records)
        state = note_success(state, name, spec["restart"])
        _publish(directory, STATE_NAME, state)
        outcome = "started"
    records["pending"] = None
    _publish(directory, PROCESSES_NAME, records)
    return state, {"id": name, "outcome": outcome}


def _running(records, scope):
    running = []
    for name, record in records["processes"].items():
        if record["boot_id"] != scope["boot_id"]:
            continue
        if record["pid_namespace"] != scope["pid_namespace"]:
            raise _Refusal("identity_ambiguous")
        if process_identity(record["pid"]) == {"pid": record["pid"], "start_ticks": record["start_ticks"]}:
            running.append(name)
    return running


def _run(directory, resolved, commands, now, timeout, attempts):
    state = _read(directory, STATE_NAME, empty_state())
    # Validate policy/state before reading identity records or probing a PID.
    proposed = plan(resolved, state, [], now)
    if proposed["status"] != "dry_run":
        if proposed["layer"] == "state" and proposed["reason"] == _REASONS["state_unavailable"]:
            raise _Refusal("state_unavailable")
        return {"status": "refused", "code": "plan_refused", "reason": proposed["reason"], "attempts": attempts}
    records = _records(_read(directory, PROCESSES_NAME, {"version": 2, "processes": {}, "pending": None}))
    if records["pending"] is not None:
        raise _Refusal("recovery_required")
    scope = _scope()
    if process_identity(os.getpid()) is None:
        raise _Refusal("identity_unavailable")
    running = _running(records, scope)
    proposed = plan(resolved, state, running, now)
    rows = {row["id"]: row for row in proposed["components"]}
    for name in proposed["start"]:
        if name not in commands or rows[name]["action"] != "would_start":
            continue
        state, outcome = _attempt(directory, state, records, name,
                                  resolved["supervisor"]["components"][name], commands[name], now, timeout, scope)
        attempts.append(outcome)
    return {"status": "ok", "attempts": attempts}


def start(resolved, commands, *, user_root, now, timeout=1):
    """Start the eligible owner argv under a nonblocking owner-directory lock.

    timeout bounds identity registration after exec, not application readiness.
    Missing/unsafe state directories refuse; this API creates no directories.
    Fixed codes/reasons never contain commands, paths or exception diagnostics.
    A refusal may carry already completed attempts when a later write fails.
    """
    attempts = []
    try:
        if not descriptor_supported():
            raise _Refusal("unsupported_platform")
        if type(timeout) not in (int, float) or not 0 < timeout <= 30:
            raise _Refusal("invalid_timeout")
        commands = _commands(commands)
        with _state_directory(user_root) as directory, _locked(directory):
            _reap_children()
            return _run(directory, resolved, commands, now, timeout, attempts)
    except _Refusal as error:
        return {"status": "refused", "code": error.code, "reason": str(error), "attempts": attempts}
    except (SupervisorError, storage_confined.ConfinedFileError, OSError, ValueError, UnicodeError, RecursionError):
        return {"status": "refused", "code": "state_unavailable",
                "reason": _REASONS["state_unavailable"], "attempts": attempts}
