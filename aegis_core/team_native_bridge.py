"""Evidence-only disposable process port; native continuation stays refused.

Owner-supplied argv is a run control, never authority obtained from a model
reply. Process-group cleanup does not account for escaped descendants or prove
that a separately associated provider job stopped.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import copy
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
import uuid

from aegis_core.primitives import json_preflight, strict_loads, sanitize_display, redact_display_secrets
from aegis_core.redaction_patterns import RedactionRefusal
from aegis_core.team_mailbox_primitives import MailboxRefusal, bounded_tree, safe_path
from aegis_core.team_mailbox_store import Store, descriptor_supported

__all__ = ["BridgeRefusal", "correlation", "NativeBridge", "ProcessBridge",
           "validate_process_provider", "process_provider_call", "process_supported"]

_ADVICE = {
    "invalid_correlation": "Supply a valid request identifier, SHA256 and operation identifier.",
    "evidence_only_required": "Declare evidence-only operation with owner-supplied process controls.",
    "invalid_input": "Supply a bounded plain JSON value matching the process-port schema.",
    "unsupported_platform": "Use POSIX waitid WNOWAIT and descriptor-relative no-follow storage.",
    "unsafe_path": "Select owner-held directories without symlinks or writable components.",
    "too_large": "Reduce the input to the documented process-port limits.",
    "io": "Restore evidence storage availability before retrying.",
}
_RETRY = "Inspect retained evidence and reconcile possible effects before retrying."
_UNQUALIFIED = "native identity, decision service, continuation and persistent executor are unqualified"
_OVERFLOW = "process bridge output limit exceeded"
_OBSERVATION_FAILED = "process bridge observation failed"
_DISPLAY_LIMIT = 4096


class _CreationInterrupted(Exception):
    """Unwind newly created directories with the actual interruption reason."""


class _CreationParentRemoved(Exception):
    """A concurrent rollback removed an empty shared directory."""


class BridgeRefusal(ValueError):
    """Fixed, input-free validation refusal with recovery advice."""
    def __init__(self, reason):
        self.reason = reason if type(reason) is str and reason in _ADVICE else "invalid_input"
        self.next_action = _ADVICE[self.reason]
        super().__init__("native bridge refused: " + self.reason)


def _require(condition, reason="invalid_input"):
    if not condition:
        raise BridgeRefusal(reason)


@contextmanager
def _boundary():
    try:
        yield
    except MailboxRefusal as error:
        reason = error.reason if error.reason in _ADVICE else "invalid_input"
        raise BridgeRefusal(reason) from None
    except OSError:
        raise BridgeRefusal("io") from None


def _display(value, limit):
    # Both public primitives operate before clipping; do not truncate raw data.
    try:
        value = sanitize_display(value, max_len=None)
        return redact_display_secrets(value, limit=len(value))[:limit]
    except RedactionRefusal:
        raise BridgeRefusal("too_large") from None


def correlation(request_id, request_sha256, operation_id=None):
    _require(type(request_id) is str and len(request_id) <= 80
             and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,79}", request_id) is not None,
             "invalid_correlation")
    _require(type(request_sha256) is str and len(request_sha256) == 64
             and re.fullmatch(r"[0-9a-f]{64}", request_sha256) is not None, "invalid_correlation")
    if operation_id is not None:
        _require(type(operation_id) is str and len(operation_id) <= 80
                 and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,79}", operation_id) is not None,
                 "invalid_correlation")


def _text(value, limit):
    _require(type(value) is str and 0 < len(value) <= limit and "\0" not in value
             and not any(0xD800 <= ord(char) <= 0xDFFF for char in value))
    return value


class NativeBridge:
    """Qualification observations never enable the legacy refused continuation."""
    def __init__(self, host="codex", *, qualification_gate=None):
        self.host = _display(_text(host, 128), 128)
        self.qualification_gate = qualification_gate

    def capabilities(self):
        return {"schema": "aegis.watch-bridge-capabilities/v1", "host": self.host,
                "native_qualified": False, "execution_enabled": False,
                "persistent_executor": "unqualified", "reason": _UNQUALIFIED,
                "publication_is_execution": False, "execution_is_read": False}

    def observe(self, request_id, request_sha256):
        correlation(request_id, request_sha256)
        return {"state": "hold", "reason": _UNQUALIFIED, "native_qualified": False,
                "next_action": "Retain the refusal; native execution requires a separate owner-approved design."}

    def continue_request(self, request_id, request_sha256, operation_id):
        correlation(request_id, request_sha256, operation_id)
        return {"state": "refused", "effect": "none", "reason": _UNQUALIFIED,
                "intent_id": None, "native_qualified": False,
                "next_action": "Retain the refusal; native execution requires a separate owner-approved design."}


def process_supported():
    return (descriptor_supported() and os.name == "posix"
            and hasattr(selectors, "PollSelector") and hasattr(os, "waitid")
            and hasattr(os, "P_PID") and hasattr(os, "WEXITED") and hasattr(os, "WNOHANG")
            and hasattr(os, "WNOWAIT") and hasattr(os, "set_blocking")
            and Path("/dev/fd").is_dir())


def _plain_json(value, *, limit=1048576):
    # Preflight the entire tree before deepcopy/serialization, including cycles,
    # scalar sizes, total nodes and nesting. Plain types exclude hostile hooks.
    with _boundary():
        bounded_tree(value, limit=limit)
    def plain(item):
        if type(item) is dict:
            return {key: plain(child) for key, child in item.items()}
        if type(item) is list:
            return [plain(child) for child in item]
        _require(type(item) in (str, int, float, bool, type(None)))
        return item
    return plain(value)


def _wire(value, *, limit=1048576):
    with _boundary():
        bounded_tree(value, limit=limit, ascii_strings=True)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def _path(value):
    with _boundary():
        return safe_path(value)


def _directory_check(path, *, missing=False):
    try:
        with Store.from_parent(path):
            pass
    except MailboxRefusal as error:
        if missing and error.reason == "missing":
            _directory_check(path.parent, missing=True)
        else:
            raise BridgeRefusal("unsafe_path") from None
    except OSError:
        raise BridgeRefusal("io") from None


def _anchor(path):
    """Select an existing held root; Store owns the no-follow ancestor walk."""
    try:
        return Store.from_parent(path)
    except MailboxRefusal as error:
        if error.reason == "missing" and path != path.parent:
            return _anchor(path.parent)
        raise


@contextmanager
def _evidence_child(store, path, parent, *, exclusive=False):
    """Bind a shared ancestor or create a private leaf beneath the held parent."""
    if not exclusive:
        with ExitStack() as existing:
            try:
                fd = existing.enter_context(store.directory(path, parent=parent))
            except MailboxRefusal as error:
                if error.reason != "missing":
                    raise
            else:
                yield fd
                return

    created = False
    try:
        os.mkdir(path.name, 0o700, dir_fd=parent)
        created = True
    except FileExistsError:
        if exclusive:
            raise
    except FileNotFoundError:
        # Creating an entry in a removed directory fails with ENOENT and the directory reports st_nlink == 0.
        if os.fstat(parent).st_nlink == 0:
            raise _CreationParentRemoved() from None
        raise
    opened = False
    try:
        with store.directory(path, parent=parent) as fd:
            opened = True
            yield fd
    except BaseException as error:
        if created:
            try:
                os.rmdir(path.name, dir_fd=parent)
            except FileNotFoundError:
                pass
            except OSError as cleanup:
                # A competing call may already have populated a shared parent.
                if exclusive or cleanup.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                    raise
        elif not opened and isinstance(error, MailboxRefusal) and error.reason == "missing":
            raise _CreationParentRemoved() from None
        raise


def _write(fd, raw):
    view = memoryview(raw)
    while view:
        count = os.write(fd, view)
        _require(count > 0, "io")
        view = view[count:]


@contextmanager
def _file(directory, name):
    # Integer descriptors have a single closer; fdopen cannot leak ownership.
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        yield fd
    finally:
        os.close(fd)


class ProcessBridge:
    """A bounded evidence-only process under a deadline and an owned group."""
    MAX_OUTPUT = 1024 * 1024

    def __init__(self, argv, *, cwd, evidence_dir, timeout_seconds=30, stop_grace=0.2, evidence_only=False):
        _require(evidence_only is True, "evidence_only_required")
        _require(type(argv) in (list, tuple) and 1 <= len(argv) <= 64
                 and all(type(v) is str and 0 < len(v) <= 4096 and "\0" not in v for v in argv))
        _plain_json(list(argv), limit=262144)
        for value, maximum in ((timeout_seconds, 3600), (stop_grace, 2)):
            _require(type(value) in (int, float) and 0 < value <= maximum and math.isfinite(value))
        _require(process_supported(), "unsupported_platform")
        _require(Path(argv[0]).is_absolute())
        self.argv, self.cwd = list(argv), _path(cwd)
        self.evidence_dir = _path(evidence_dir)
        _directory_check(self.cwd)
        _directory_check(self.evidence_dir, missing=True)
        self.timeout_seconds, self.stop_grace = timeout_seconds, stop_grace
        self.deadline, self.stop_event = None, None

    def with_control(self, *, deadline, stop_event):
        _require(deadline is None or type(deadline) in (int, float)
                 and -sys.float_info.max <= deadline <= sys.float_info.max and math.isfinite(deadline))
        _require(stop_event is None or callable(getattr(stop_event, "is_set", None)))
        bridge = copy.copy(self)
        bridge.deadline, bridge.stop_event = deadline, stop_event
        return bridge

    def _interruption(self, deadline):
        if self.stop_event is not None and self.stop_event.is_set():
            return "process bridge stop requested"
        if time.monotonic() >= deadline:
            return "process bridge deadline reached"
        return None

    def _stop(self, process, selector, outputs, totals):
        details = {"pid": process.pid, "reaped": False, "group_signalled": False}
        observation_failed = False
        try:
            # WNOWAIT reserves the direct-child identity through group cleanup.
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            for number in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(process.pid, number)
                    details["group_signalled"] = True
                except ProcessLookupError:
                    break
                if number == signal.SIGTERM:
                    grace_end = time.monotonic() + self.stop_grace
                    try:
                        while time.monotonic() < grace_end:
                            self._drain(selector, outputs, totals, wait=max(0, grace_end - time.monotonic()))
                    except (OSError, ValueError):
                        observation_failed = True
            details["returncode"] = process.wait(timeout=self.stop_grace)
            details["reaped"] = True
        except (OSError, subprocess.TimeoutExpired):
            details["cleanup_error"] = "process bridge cleanup unconfirmed"
        return details, observation_failed

    def _drain(self, selector, outputs, totals, *, wait):
        if not selector.get_map():
            if wait:
                time.sleep(wait)
            return False
        ready = selector.select(wait)
        for key, _events in ready:
            index = key.data
            room = max(0, self.MAX_OUTPUT - totals[index])
            # After overflow, keep consuming during grace without retaining
            # more bytes. The saturated counter preserves the refusal.
            raw = os.read(key.fd, min(8192, room + 1) if room else 8192)
            if not raw:
                selector.unregister(key.fd)
                continue
            totals[index] = min(self.MAX_OUTPUT + 1, totals[index] + len(raw))
            if room:
                _write(outputs[index], raw[:room])
        return bool(ready)

    def _run(self, request_fd, outputs, cwd_fd, deadline):
        try:
            selector = selectors.PollSelector()
        except (OSError, ValueError):
            return False, None, _OBSERVATION_FAILED
        try:
            process = subprocess.Popen(self.argv, cwd="/dev/fd/" + str(cwd_fd), stdin=request_fd,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True, close_fds=True, pass_fds=(cwd_fd,))
        except BaseException as error:
            selector.close()
            if isinstance(error, (OSError, ValueError)):
                return False, None, "process bridge launch failed"
            raise
        reason, details, totals = None, None, [0, 0]
        try:
            with selector:
                try:
                    for index, stream in enumerate((process.stdout, process.stderr)):
                        fd = stream.fileno()
                        os.set_blocking(fd, False)
                        selector.register(fd, selectors.EVENT_READ, index)
                    while True:
                        reason = self._interruption(deadline)
                        if reason is not None:
                            break
                        self._drain(selector, outputs, totals, wait=min(0.01, max(0, deadline - time.monotonic())))
                        if max(totals) > self.MAX_OUTPUT:
                            break
                        if os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
                            break
                except (OSError, ValueError):
                    reason = _OBSERVATION_FAILED
                finally:
                    details, observation_failed = self._stop(process, selector, outputs, totals)
                    if observation_failed:
                        reason = _OBSERVATION_FAILED
                # The group is stopped. End on an empty poll or on overflow,
                # even if an escaped descendant keeps a pipe open.
                while max(totals) <= self.MAX_OUTPUT:
                    if not self._drain(selector, outputs, totals, wait=0):
                        break
        except (OSError, ValueError):
            reason = _OBSERVATION_FAILED
        finally:
            try:
                process.stdout.close()
            except OSError:
                reason = _OBSERVATION_FAILED
            finally:
                try:
                    process.stderr.close()
                except OSError:
                    reason = _OBSERVATION_FAILED
        if details is None or not details["reaped"]:
            reason = "process bridge cleanup unconfirmed"
        if max(totals) > self.MAX_OUTPUT:
            reason = _OVERFLOW
        return True, details, reason

    def _response(self, fd, request, method, provider, details, folder):
        _require(os.fstat(fd).st_size <= self.MAX_OUTPUT, "too_large")
        os.lseek(fd, 0, os.SEEK_SET)
        raw = bytearray()
        while len(raw) <= self.MAX_OUTPUT:
            chunk = os.read(fd, min(8192, self.MAX_OUTPUT + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        _require(len(raw) <= self.MAX_OUTPUT, "too_large")
        try:
            checked = json_preflight(bytes(raw), max_bytes=self.MAX_OUTPUT, max_depth=32,
                                     max_nodes=32768, max_items=10000, max_string=self.MAX_OUTPUT, max_atom=64)
            response = strict_loads(checked)
            _plain_json(response)
        except (ValueError, UnicodeError, RecursionError):
            return None, "invalid process bridge response"
        if not (type(response) is dict and set(response) == set(request) | {"result"}
                and all(response[key] == value for key, value in request.items())
                and (not provider or _wire({key: response[key] for key in request}) == _wire(request))):
            return None, "process bridge response correlation mismatch"
        result = response["result"]
        if provider:
            reason = _validate_provider_observation(result, request)
            if reason:
                return None, reason
            return _provider_answer("received", "", result=result, process=details, evidence_dir=folder), None
        if type(result) is not dict or result.get("native_qualified") is not False:
            return None, "invalid process bridge qualification"
        state = result.get("state")
        if method == "observe":
            if type(state) is not str or state not in {"eligible", "hold"}:
                return None, "invalid process bridge observation"
        elif (type(state) is not str or state not in {"completed", "refused", "unknown"}
              or result.get("effect") != {"completed": "confirmed", "refused": "none", "unknown": "possible"}[state]):
            return None, "invalid process bridge effect"
        refused = state in {"hold", "refused", "unknown"}
        if refused:
            diagnostic = result.get("reason")
            if type(diagnostic) is not str or not 0 < len(diagnostic) <= _DISPLAY_LIMIT:
                return None, "invalid process bridge refusal reason"
        shown = {**_shown_tree(result), "process": details, "evidence_dir": folder}
        if refused:
            if not shown["reason"].strip():
                return None, "invalid process bridge refusal reason"
            shown["child_reason"] = shown["reason"]
            shown["reason"] = "process bridge child reported " + state
            shown["next_action"] = _RETRY
        return shown, None

    def _failure(self, method, provider, spawned, reason, details, folder):
        if provider:
            return _provider_answer("uncertain" if spawned else "not_sent", reason,
                                    process=details, evidence_dir=folder)
        result = {"state": "hold" if method == "observe" else "unknown" if spawned else "refused",
                  "reason": reason, "next_action": _RETRY, "native_qualified": False,
                  "process": details, "evidence_dir": folder}
        if method != "observe":
            result["effect"] = "possible" if spawned else "none"
        return result

    def _evidence_candidate(self):
        path = _path(self.evidence_dir / uuid.uuid4().hex)
        return path, _display(str(path), 32768)

    def _prepare_call(self, stack, cwd_store, deadline):
        """Reserve one evidence directory and retain its descriptor for the call."""
        try:
            while True:
                self._check_creation(deadline)
                try:
                    with ExitStack() as creating:
                        store = (cwd_store if self.evidence_dir.is_relative_to(self.cwd)
                                 else creating.enter_context(_anchor(self.evidence_dir)))
                        path = store.root
                        parent = creating.enter_context(store.directory(path))
                        folder_path, folder = self._evidence_candidate()
                        for name in self.evidence_dir.relative_to(path).parts:
                            self._check_creation(deadline)
                            path /= name
                            parent = creating.enter_context(_evidence_child(store, path, parent))
                        while True:
                            self._check_creation(deadline)
                            try:
                                leaf = creating.enter_context(_evidence_child(store, folder_path, parent, exclusive=True))
                            except FileExistsError:
                                self._check_creation(deadline)
                                folder_path, folder = self._evidence_candidate()
                            else:
                                break
                        folder_fd = stack.enter_context(store.directory(folder_path, parent=leaf, held=True))
                        self._check_creation(deadline)
                    return folder_fd, folder, None
                except _CreationParentRemoved:
                    # Rewalk a shared path removed by rollback from its trusted anchor.
                    if os.fstat(cwd_store.fd).st_nlink == 0:
                        raise BridgeRefusal("unsafe_path") from None
        except _CreationInterrupted as error:
            return None, None, error.args[0]

    def _check_creation(self, deadline):
        reason = self._interruption(deadline)
        if reason:
            raise _CreationInterrupted(reason)

    def _call(self, method, request_id, request_sha256, operation_id=None, *, _provider_frame=None):
        correlation(request_id, request_sha256, operation_id)
        deadline = time.monotonic() + self.timeout_seconds
        if self.deadline is not None:
            deadline = min(deadline, self.deadline)
        provider = _provider_frame is not None
        request = _provider_frame if provider else {
            "schema": "aegis.watch-process/v1", "method": method, "request_id": request_id,
            "request_sha256": request_sha256, "operation_id": operation_id}
        _plain_json(request)
        raw = _wire(request)
        _require(len(raw) + int(provider) <= self.MAX_OUTPUT, "too_large")
        raw += b"\n" if provider else b""
        reason = self._interruption(deadline)
        if reason:
            return self._failure(method, provider, False, reason, None, None)
        spawned, details, folder = False, None, None
        try:
            with ExitStack() as stack:
                cwd_store = stack.enter_context(Store.from_parent(self.cwd))
                folder_fd, folder, reason = self._prepare_call(stack, cwd_store, deadline)
                if reason:
                    return self._failure(method, provider, False, reason, None, None)
                stdin = stack.enter_context(_file(folder_fd, "request.json"))
                stdout = stack.enter_context(_file(folder_fd, "stdout"))
                stderr = stack.enter_context(_file(folder_fd, "stderr"))
                _write(stdin, raw)
                os.lseek(stdin, 0, os.SEEK_SET)
                reason = self._interruption(deadline)
                if reason is None:
                    spawned, details, reason = self._run(stdin, (stdout, stderr), cwd_store.fd, deadline)
                result = None
                if spawned and reason is None:
                    if details["returncode"] != 0:
                        reason = "process bridge exited unsuccessfully"
                    else:
                        result, reason = self._response(stdout, request, method, provider, details, folder)
                if reason:
                    result = self._failure(method, provider, spawned, reason, details, folder)
                _plain_json(result)
                result_raw = _wire(result)
                with _file(folder_fd, "result.json") as output:
                    _write(output, result_raw)
                return result
        except (MailboxRefusal, OSError, BridgeRefusal):
            return self._failure(method, provider, spawned, "process bridge evidence unavailable", details, folder)

    def observe(self, request_id, request_sha256):
        return self._call("observe", request_id, request_sha256)

    def continue_request(self, request_id, request_sha256, operation_id):
        return self._call("continue_request", request_id, request_sha256, operation_id)


def _shown_tree(value):
    if type(value) is str:
        return _display(value, _DISPLAY_LIMIT)
    if type(value) is list:
        return [_shown_tree(item) for item in value]
    if type(value) is dict:
        shown = {}
        for key, item in value.items():
            displayed = _display(key, _DISPLAY_LIMIT)
            _require(displayed not in shown)
            shown[displayed] = _shown_tree(item)
        return shown
    return value


def validate_process_provider(spec):
    """Validate and copy an owner-selected descriptor without durable effects."""
    spec = _plain_json(spec, limit=262144)
    _require(type(spec) is dict and set(spec) == {"schema", "mode", "provider", "endpoint_id", "argv",
                                               "cwd", "evidence_dir", "stop_grace"})
    _require(spec["schema"] == "aegis.fixture-process-provider/v1" and spec["mode"] == "fixture")
    _text(spec["provider"], 128)
    _text(spec["endpoint_id"], 128)
    _require("://" not in spec["endpoint_id"])
    argv = spec["argv"]
    _require(type(argv) is list and 1 <= len(argv) <= 64
             and all(type(item) is str and 0 < len(item) <= 4096 and "\0" not in item for item in argv))
    _require(Path(argv[0]).is_absolute())
    cwd, evidence = _path(spec["cwd"]), _path(spec["evidence_dir"])
    # On unsupported platforms descriptor validation remains pure; the call
    # boundary reports the documented not_sent refusal before touching paths.
    if process_supported():
        _directory_check(cwd)
        _directory_check(evidence, missing=True)
    grace = spec["stop_grace"]
    _require(type(grace) in (int, float) and 0 < grace <= 0.2 and math.isfinite(grace))
    _wire(spec, limit=262144)
    return spec


def _provider_answer(transport, reason, *, result=None, process=None, evidence_dir=None):
    return {"schema": "aegis.fixture-process-call-result/v1", "transport": transport,
            "reason": reason, "next_action": _RETRY if transport != "received" else "",
            "result": _shown_tree(result), "process": process, "evidence_dir": evidence_dir, "native_qualified": False}


def _validate_provider_observation(result, frame):
    if frame["method"] == "inspect":
        if not (type(result) is dict and set(result) == {"qualified", "mode", "source", "gates", "reason"}
                and type(result["qualified"]) is bool and result["mode"] == "fixture"
                and result["source"] == frame["request"]["source"] and type(result["gates"]) is dict
                and set(result["gates"]) == {"source", "capability", "lease", "capacity", "observer", "job"}
                and type(result["reason"]) is str and len(result["reason"]) <= 1024):
            return "invalid process provider inspection"
        return None
    if not (type(result) is dict and set(result) == {"association_sha256", "provider_state", "provider_handle",
                                                   "exit_code", "evidence", "quiescent"}
            and result["association_sha256"] == frame["association_sha256"]
            and type(result["provider_state"]) is str
            and result["provider_state"] in {"not_started", "running", "disconnected", "ambiguous",
                                             "cancel_requested", "cancelled", "passed", "failed", "unknown"}
            and type(result["quiescent"]) is bool
            and (result["exit_code"] is None or type(result["exit_code"]) is int)
            and type(result["evidence"]) is list and bool(result["evidence"])):
        return "invalid process provider observation"
    handle = result["provider_handle"]
    if handle is not None:
        if not (type(handle) is dict and set(handle) == {"thread_id", "turn_id"}
                and all(type(value) is str and 0 < len(value) <= 256 for value in handle.values())):
            return "invalid process provider handle"
        if not (handle["thread_id"] == frame["association"]["thread_id"]
                and (frame["provider_handle"] is None or handle == frame["provider_handle"])):
            return "process provider handle correlation mismatch"
    return None


def process_provider_call(spec, method, request, request_sha256, *, actor, generation, association=None,
                          provider_handle=None, reason=None, deadline, evidence_only=False):
    """Call a disposable process; never settle the separately associated job."""
    _require(evidence_only is True, "evidence_only_required")
    spec = validate_process_provider(spec)
    _require(type(method) is str and method in {"inspect", "submit", "observe", "cancel"})
    request = _plain_json(request)
    _require(type(request) is dict and type(request.get("source")) is dict)
    correlation(request.get("id"), request_sha256)
    _text(actor, 128)
    _require(type(generation) is int and generation >= 1)
    _require(type(deadline) in (int, float) and -sys.float_info.max <= deadline <= time.monotonic() + 5
             and math.isfinite(deadline))
    association, provider_handle = _plain_json(association), _plain_json(provider_handle)
    if method == "inspect":
        _require(association is None and provider_handle is None and reason is None)
    else:
        _require(type(association) is dict and association.get("request_id") == request["id"]
                 and association.get("request_sha256") == request_sha256
                 and association.get("source") == request["source"]
                 and association.get("provider") == spec["provider"]
                 and association.get("endpoint_id") == spec["endpoint_id"]
                 and type(association.get("thread_id")) is str and 0 < len(association["thread_id"]) <= 256)
        if provider_handle is not None:
            _require(type(provider_handle) is dict and set(provider_handle) == {"thread_id", "turn_id"}
                     and provider_handle["thread_id"] == association["thread_id"]
                     and all(type(value) is str and 0 < len(value) <= 256 for value in provider_handle.values()))
        if method == "cancel":
            _require(provider_handle is not None)
            _text(reason, 1024)
        else:
            _require(reason is None)
    frame = {"schema": "aegis.fixture-process-call/v1", "call_id": uuid.uuid4().hex, "method": method,
             "request": request, "request_sha256": request_sha256, "actor": actor, "generation": generation,
             "association": association,
             "association_sha256": hashlib.sha256(_wire(association)).hexdigest() if association is not None else None,
             "provider_handle": provider_handle, "reason": reason}
    _plain_json(frame)
    _require(len(_wire(frame)) + 1 <= ProcessBridge.MAX_OUTPUT, "too_large")
    if not process_supported():
        return _provider_answer("not_sent", "process provider requires POSIX waitid WNOWAIT")
    reserve = 2 * spec["stop_grace"]
    remaining = deadline - time.monotonic() - reserve
    if remaining <= 0:
        return _provider_answer("not_sent", "process provider cleanup reserve exceeds remaining budget")
    try:
        adapter = ProcessBridge(spec["argv"], cwd=spec["cwd"], evidence_dir=spec["evidence_dir"],
                                timeout_seconds=remaining, stop_grace=spec["stop_grace"], evidence_only=True)
    except BridgeRefusal:
        return _provider_answer("not_sent", "process provider controls unavailable")
    adapter = adapter.with_control(deadline=deadline - reserve, stop_event=None)
    return adapter._call(method, request["id"], request_sha256, _provider_frame=frame)
