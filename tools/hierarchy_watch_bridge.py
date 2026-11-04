#!/usr/bin/env python3
"""Supported continuation port; native execution remains explicitly unqualified.

This adapter does not turn metadata, CLI success, or local JSON into authority.
OperatorBridge joins the canonical operator to the watch port for evidence-only
qualification. It never substitutes raw RPC or starts another native session.
"""
from __future__ import annotations

import argparse
import copy
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import SHA256, SLUG, digest, encoded, matching, require, safe_path, strict_json, text  # noqa: E402


def correlation(request_id, request_sha256, operation_id=None):
    matching(request_id, SLUG, "request id")
    matching(request_sha256, SHA256, "request sha256")
    if operation_id is not None:
        matching(operation_id, SLUG, "watch operation id")


class NativeBridge:
    """No installed provider has yet passed the required native acceptance gate."""

    def __init__(self, host="codex"):
        self.host = text(host, "host", 128)

    def capabilities(self):
        return {"schema": "aegis.watch-bridge-capabilities/v1", "host": self.host,
                "native_qualified": False, "execution_enabled": False,
                "persistent_executor": "unqualified",
                "reason": "native identity, decision service, continuation and persistent executor are unqualified",
                "publication_is_execution": False, "execution_is_read": False}

    def observe(self, request_id, request_sha256):
        correlation(request_id, request_sha256)
        return {"state": "hold", "reason": self.capabilities()["reason"], "native_qualified": False}

    def continue_request(self, request_id, request_sha256, operation_id):
        correlation(request_id, request_sha256, operation_id)
        return {"state": "refused", "effect": "none", "reason": self.capabilities()["reason"],
                "intent_id": None, "native_qualified": False}


class ProcessBridge:
    """Bounded disposable host process; never native authentication/admission.

    A trusted integration supplies an argv, not a shell command. Every call gets
    retained input/stdout/stderr. waitid(WNOWAIT) keeps our child PID reserved
    until group cancellation is finished, including exit-with-live-descendants.
    Descendants that escape the process group need a separately qualified host.
    """

    MAX_OUTPUT = 1024 * 1024

    def __init__(self, argv, *, cwd, evidence_dir, timeout_seconds=30, stop_grace=0.2, evidence_only=False):
        require(evidence_only is True, "process bridge requires explicit evidence-only operation")
        require(isinstance(argv, (list, tuple)) and argv and all(isinstance(v, str) and v and "\0" not in v for v in argv),
                "invalid process bridge argv")
        for value, maximum, name in ((timeout_seconds, 3600, "timeout"), (stop_grace, 2, "stop grace")):
            require(type(value) in (int, float) and math.isfinite(value) and 0 < value <= maximum,
                    "invalid process bridge " + name)
        require(os.name == "posix" and all(hasattr(os, name) for name in
                ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")), "process bridge requires POSIX waitid WNOWAIT")
        require(Path(argv[0]).is_absolute(), "process bridge executable must be absolute")
        self.argv, self.cwd = list(argv), safe_path(cwd)
        require(self.cwd.is_dir(), "process bridge cwd must be a directory")
        self.evidence_dir = safe_path(evidence_dir)
        self.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.timeout_seconds, self.stop_grace = timeout_seconds, stop_grace
        self.deadline, self.stop_event = None, None

    def with_control(self, *, deadline, stop_event):
        bridge = copy.copy(self)
        require(deadline is None or (type(deadline) in (int, float) and math.isfinite(deadline)),
                "invalid process bridge deadline")
        bridge.deadline, bridge.stop_event = deadline, stop_event
        return bridge

    def _interruption(self, deadline):
        if self.stop_event is not None and self.stop_event.is_set():
            return "process bridge stop requested"
        if time.monotonic() >= deadline:
            return "process bridge deadline reached"
        return None

    def _stop(self, process):
        # Observe without reaping before signalling: a recycled PID/group must
        # never be addressed. This is our direct child, created in a new session.
        details = {"pid": process.pid, "reaped": False, "group_signalled": False}
        try:
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            for number in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(process.pid, number)
                    details["group_signalled"] = True
                except ProcessLookupError:
                    break
                if number == signal.SIGTERM:
                    time.sleep(self.stop_grace)
            details["returncode"] = process.wait(timeout=self.stop_grace)
            details["reaped"] = True
        except (OSError, subprocess.TimeoutExpired) as exc:
            details["cleanup_error"] = str(exc)
        return details

    def _call(self, method, request_id, request_sha256, operation_id=None, *, _provider_frame=None):
        correlation(request_id, request_sha256, operation_id)
        deadline = time.monotonic() + self.timeout_seconds
        if self.deadline is not None:
            deadline = min(deadline, self.deadline)
        spawned, details = False, None
        reason = self._interruption(deadline)
        request = {"schema": "aegis.watch-process/v1", "method": method, "request_id": request_id,
                   "request_sha256": request_sha256, "operation_id": operation_id}
        if _provider_frame is not None:
            request = _provider_frame
        folder = None
        if reason is None:
            folder = safe_path(self.evidence_dir / uuid.uuid4().hex)
            folder.mkdir(mode=0o700)
            (folder / "request.json").write_bytes(encoded(request) + (b"\n" if _provider_frame is not None else b""))
            with (folder / "request.json").open("rb") as stdin, (folder / "stdout").open("xb") as stdout, (folder / "stderr").open("xb") as stderr:
                reason = self._interruption(deadline)
                if reason is None:
                    try:
                        process = subprocess.Popen(self.argv, cwd=self.cwd, stdin=stdin, stdout=stdout, stderr=stderr,
                                                   start_new_session=True, close_fds=True)
                    except OSError as exc:
                        reason = "process bridge launch failed: " + str(exc)
                    else:
                        spawned = True
                        try:
                            while True:
                                reason = self._interruption(deadline)
                                if max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) > self.MAX_OUTPUT:
                                    reason = "process bridge output limit exceeded"
                                if reason is not None:
                                    break
                                exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                                if exited is not None:
                                    break
                                time.sleep(min(0.01, max(0, deadline - time.monotonic())))
                        except OSError as exc:
                            reason = "process bridge observation failed: " + str(exc)
                        finally:
                            details = self._stop(process)
        if spawned and not details["reaped"]:
            reason = "process bridge cleanup unconfirmed"
        if spawned and details["reaped"] and max((folder / name).stat().st_size for name in ("stdout", "stderr")) > self.MAX_OUTPUT:
            reason = "process bridge output limit exceeded"
        if spawned and reason is None:
            if details["returncode"] != 0:
                reason = "process bridge exited unsuccessfully"
            else:
                try:
                    with (folder / "stdout").open("rb") as stream:
                        raw = stream.read(self.MAX_OUTPUT + 1)
                    require(len(raw) <= self.MAX_OUTPUT, "process bridge output limit exceeded")
                    try:
                        response = strict_json(raw.decode("utf-8"))
                    except (ValueError, UnicodeError, RecursionError) as exc:
                        raise ValueError("invalid process bridge response") from exc
                    if _provider_frame is not None:
                        _plain_json(response)
                    require(isinstance(response, dict) and set(response) == set(request) | {"result"}
                            and all(response[key] == value for key, value in request.items())
                            and (_provider_frame is None
                                 or encoded({key: response[key] for key in request}) == encoded(request)),
                            "process bridge response correlation mismatch")
                    result = response["result"]
                    if _provider_frame is not None:
                        _validate_provider_observation(result, request)
                        result = _provider_answer("received", "", result=result, process=details,
                                                  evidence_dir=str(folder))
                    else:
                        require(isinstance(result, dict) and result.get("native_qualified") is False,
                                "invalid process bridge qualification")
                        if method == "observe":
                            require(result.get("state") in {"eligible", "hold"}, "invalid process bridge observation")
                        else:
                            require(result.get("state") in {"completed", "refused", "unknown"}
                                    and result.get("effect") == {"completed": "confirmed", "refused": "none",
                                                               "unknown": "possible"}.get(result.get("state")),
                                    "invalid process bridge effect")
                        result = {**result, "process": details, "evidence_dir": str(folder)}
                except ValueError as exc:
                    reason = str(exc)
        if reason is not None:
            if _provider_frame is not None:
                result = _provider_answer("uncertain" if spawned else "not_sent", reason, process=details,
                                          evidence_dir=str(folder) if folder else None)
            else:
                result = {"state": "hold" if method == "observe" else ("unknown" if spawned else "refused"),
                          "reason": reason, "native_qualified": False, "process": details,
                          "evidence_dir": str(folder) if folder else None}
                if method != "observe":
                    result["effect"] = "possible" if spawned else "none"
        if folder is not None:
            (folder / "result.json").write_bytes(encoded(result))
        return result

    def observe(self, request_id, request_sha256):
        return self._call("observe", request_id, request_sha256)

    def continue_request(self, request_id, request_sha256, operation_id):
        return self._call("continue_request", request_id, request_sha256, operation_id)


def _plain_json(value, depth=0):
    require(depth <= 32, "process provider data exceeds nesting limit")
    if type(value) in (str, int, bool, type(None)):
        return value
    if type(value) is float:
        require(math.isfinite(value), "process provider data must be finite")
        return value
    if type(value) is list:
        require(len(value) <= ProcessBridge.MAX_OUTPUT, "process provider data exceeds size limit")
        return [_plain_json(item, depth + 1) for item in value]
    require(type(value) is dict and len(value) <= ProcessBridge.MAX_OUTPUT
            and all(type(key) is str for key in value), "process provider requires plain JSON data")
    return {key: _plain_json(item, depth + 1) for key, item in value.items()}


def validate_process_provider(spec):
    """Copy a closed disposable-process descriptor without creating evidence or a child."""
    spec = _plain_json(spec)
    require(type(spec) is dict and set(spec) == {"schema", "mode", "provider", "endpoint_id", "argv",
                                               "cwd", "evidence_dir", "stop_grace"},
            "invalid process provider descriptor fields")
    require(spec["schema"] == "aegis.fixture-process-provider/v1" and spec["mode"] == "fixture",
            "process provider requires a fixture descriptor")
    text(spec["provider"], "provider", 128)
    text(spec["endpoint_id"], "provider endpoint", 128)
    require("://" not in spec["endpoint_id"], "provider endpoint must be an opaque identifier")
    argv = spec["argv"]
    require(type(argv) is list and 1 <= len(argv) <= 64
            and all(type(item) is str and 0 < len(item) <= 4096 and "\0" not in item for item in argv),
            "invalid process provider argv")
    require(Path(argv[0]).is_absolute(), "process provider executable must be absolute")
    require(safe_path(spec["cwd"]).is_dir(), "process provider cwd must be a directory")
    safe_path(spec["evidence_dir"])
    grace = spec["stop_grace"]
    require(type(grace) in (int, float) and 0 < grace <= 0.2 and math.isfinite(grace),
            "invalid process provider stop grace")
    require(len(encoded(spec)) <= 262144, "process provider descriptor exceeds byte limit")
    return spec


def _provider_answer(transport, reason, *, result=None, process=None, evidence_dir=None):
    return {"schema": "aegis.fixture-process-call-result/v1", "transport": transport,
            "reason": str(reason)[:4096], "result": result, "process": process,
            "evidence_dir": evidence_dir, "native_qualified": False}


def _validate_provider_observation(result, frame):
    result = _plain_json(result)
    if frame["method"] == "inspect":
        require(type(result) is dict and set(result) == {"qualified", "mode", "source", "gates", "reason"}
                and type(result["qualified"]) is bool and result["mode"] == "fixture"
                and result["source"] == frame["request"]["source"] and type(result["gates"]) is dict
                and set(result["gates"]) == {"source", "capability", "lease", "capacity", "observer", "job"}
                and type(result["reason"]) is str and len(result["reason"]) <= 1024,
                "invalid process provider inspection")
        return
    require(type(result) is dict and set(result) == {"association_sha256", "provider_state", "provider_handle",
                                                   "exit_code", "evidence", "quiescent"}
            and result["association_sha256"] == frame["association_sha256"]
            and type(result["provider_state"]) is str
            and result["provider_state"] in {"not_started", "running", "disconnected", "ambiguous",
                                             "cancel_requested", "cancelled", "passed", "failed", "unknown"}
            and type(result["quiescent"]) is bool
            and (result["exit_code"] is None or type(result["exit_code"]) is int)
            and type(result["evidence"]) is list and bool(result["evidence"]),
            "invalid process provider observation")
    handle = result["provider_handle"]
    if handle is not None:
        require(type(handle) is dict and set(handle) == {"thread_id", "turn_id"}
                and all(type(value) is str and 0 < len(value) <= 256 for value in handle.values()),
                "invalid process provider handle")
        require(handle["thread_id"] == frame["association"]["thread_id"]
                and (frame["provider_handle"] is None or handle == frame["provider_handle"]),
                "process provider handle correlation mismatch")


def process_provider_call(spec, method, request, request_sha256, *, actor, generation, association=None,
                          provider_handle=None, reason=None, deadline, evidence_only=False):
    """Call one disposable process under the caller's existing absolute deadline.

    No provider callback runs here. Call-process cleanup never proves that the
    separately associated provider job stopped; canonical settlement owns that.
    """
    require(evidence_only is True, "process provider requires explicit evidence-only operation")
    spec = validate_process_provider(spec)
    require(type(method) is str and method in {"inspect", "submit", "observe", "cancel"},
            "invalid process provider method")
    request = _plain_json(request)
    require(type(request) is dict and type(request.get("source")) is dict, "invalid process provider request")
    correlation(request.get("id"), request_sha256)
    text(actor, "process provider actor", 128)
    require(type(generation) is int and generation >= 1, "invalid process provider generation")
    require(type(deadline) in (int, float) and -sys.float_info.max <= deadline <= sys.float_info.max
            and math.isfinite(deadline)
            and deadline <= time.monotonic() + 5, "invalid process provider deadline")
    association, provider_handle = _plain_json(association), _plain_json(provider_handle)
    if method == "inspect":
        require(association is None and provider_handle is None and reason is None,
                "process provider inspection cannot carry an association")
    else:
        require(type(association) is dict and association.get("request_id") == request["id"]
                and association.get("request_sha256") == request_sha256
                and association.get("source") == request["source"]
                and association.get("provider") == spec["provider"]
                and association.get("endpoint_id") == spec["endpoint_id"]
                and type(association.get("thread_id")) is str and 0 < len(association["thread_id"]) <= 256,
                "process provider association correlation mismatch")
        if provider_handle is not None:
            require(type(provider_handle) is dict and set(provider_handle) == {"thread_id", "turn_id"}
                    and provider_handle["thread_id"] == association["thread_id"]
                    and all(type(value) is str and 0 < len(value) <= 256 for value in provider_handle.values()),
                    "process provider handle correlation mismatch")
        if method == "cancel":
            require(provider_handle is not None, "process provider cancellation requires a known handle")
            text(reason, "process provider cancellation reason", 1024)
        else:
            require(reason is None, "unexpected process provider cancellation reason")
    if not (os.name == "posix" and all(hasattr(os, name) for name in
            ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT"))):
        return _provider_answer("not_sent", "process provider requires POSIX waitid WNOWAIT")
    reserve = 2 * spec["stop_grace"]
    remaining = deadline - time.monotonic() - reserve
    if remaining <= 0:
        return _provider_answer("not_sent", "process provider cleanup reserve exceeds remaining budget")
    frame = {"schema": "aegis.fixture-process-call/v1", "call_id": uuid.uuid4().hex, "method": method,
             "request": request, "request_sha256": request_sha256, "actor": actor, "generation": generation,
             "association": association, "association_sha256": digest(association) if association is not None else None,
             "provider_handle": provider_handle, "reason": reason}
    frame = _plain_json(frame)
    require(len(encoded(frame)) + 1 <= ProcessBridge.MAX_OUTPUT, "process provider request exceeds byte limit")
    try:
        bridge = ProcessBridge(spec["argv"], cwd=spec["cwd"], evidence_dir=spec["evidence_dir"],
                               timeout_seconds=remaining, stop_grace=spec["stop_grace"], evidence_only=True)
    except (OSError, ValueError) as exc:
        return _provider_answer("not_sent", str(exc))
    bridge = bridge.with_control(deadline=deadline - reserve, stop_event=None)
    return bridge._call(method, request["id"], request_sha256, _provider_frame=frame)


class OperatorBridge:
    """External-provider boundary around Session 1's canonical Operator API.

The caller must explicitly select evidence-only operation. Provider observations
remain fixture evidence; the operator independently repeats admission checks.
"""

    def __init__(self, lifecycle_root, provider, actor, generation, *, evidence_only=False, async_target=None):
        from hierarchy_lifecycle import Lifecycle
        from hierarchy_operator import Operator
        self.lifecycle = Lifecycle(lifecycle_root)
        self.provider = provider
        self.actor = actor
        self.generation = generation
        self.evidence_only = evidence_only
        self.async_target = _plain_json(async_target) if async_target is not None else None
        self.deadline, self.stop_event = None, None
        self.operator = Operator(lifecycle_root, provider, evidence_only=evidence_only)

    def request(self, request_id, request_sha256):
        correlation(request_id, request_sha256)
        status = self.lifecycle.status()
        require(request_id in status["requests"], "unknown request id")
        row = status["requests"][request_id]
        require(row["raw"]["sha256"] == request_sha256, "request sha256 mismatch")
        return status, row

    def observe(self, request_id, request_sha256):
        status, row = self.request(request_id, request_sha256)
        if not self.evidence_only:
            return NativeBridge().observe(request_id, request_sha256)
        if request_id not in status["continuation_candidates"]:
            return {"state": "hold", "reason": status["continuation_holds"].get(request_id, "not a continuation candidate"),
                    "native_qualified": False}
        if self.async_target is not None:
            validate_process_provider(self.provider)
            return {"state": "eligible", "reason": "canonical submit repeats bounded fixture admission",
                    "native_qualified": False}
        result = self.provider.inspect(row["request"], self.actor, self.generation)
        require(isinstance(result, dict) and type(result.get("qualified")) is bool, "invalid provider observation")
        require(result.get("mode") == "fixture", "evidence-only bridge requires a fixture provider")
        return {"state": "eligible" if result["qualified"] else "hold", "reason": result.get("reason", ""),
                "native_qualified": False}

    def continue_request(self, request_id, request_sha256, operation_id):
        correlation(request_id, request_sha256, operation_id)
        _, row = self.request(request_id, request_sha256)
        if not self.evidence_only:
            return NativeBridge().continue_request(request_id, request_sha256, operation_id)
        if self.async_target is not None:
            if row["intent"] is not None:
                return self.poll_request(request_id, request_sha256, operation_id)
            refused = self._budget_refusal(row)
            if refused is not None:
                return refused
            return self.operator.submit(request_id, request_sha256, self.actor, self.generation, self.async_target)
        # The watch ID correlates delivery only. Operator owns the one canonical
        # execution intent and revalidates authority/source/generation under lock.
        result = self.operator.execute(request_id, self.actor, self.generation)
        return {**result, "native_qualified": False}

    def with_control(self, *, deadline, stop_event):
        require(deadline is None or (type(deadline) in (int, float) and math.isfinite(deadline)),
                "invalid operator bridge deadline")
        bridge = copy.copy(self)
        bridge.deadline, bridge.stop_event = deadline, stop_event
        return bridge

    @staticmethod
    def _refusal(reason, row):
        association = row.get("association")
        return {"state": "refused", "effect": "none", "reason": reason, "native_qualified": False,
                "request_id": row["request"]["id"], "request_sha256": row["raw"]["sha256"],
                "intent_id": row["intent"]["id"] if row["intent"] else None,
                "association_sha256": association["sha256"] if association else None}

    def _budget_refusal(self, row):
        if self.stop_event is not None and self.stop_event.is_set():
            return self._refusal("watch stop requested before operator call", row)
        # N1 owns the complete <=5s inspect/publication/call/cleanup transaction.
        # Its public API has no external-deadline argument. Do not start a call
        # that cannot fit in this run, or silently reset that transaction budget.
        if self.deadline is not None and self.deadline - time.monotonic() < 5:
            return self._refusal("watch budget cannot fit the bounded operator transaction", row)
        return None

    def _follow_request(self, method, request_id, request_sha256, operation_id, reason=None):
        correlation(request_id, request_sha256, operation_id)
        if not self.evidence_only:
            return NativeBridge().continue_request(request_id, request_sha256, operation_id)
        _, row = self.request(request_id, request_sha256)
        if self.async_target is None or row["intent"] is None or row.get("association") is None:
            return self._refusal("canonical provider association is unavailable", row)
        refused = self._budget_refusal(row)
        if refused is not None:
            return refused
        args = [request_id, request_sha256, self.actor, self.generation]
        if method == "cancel":
            args.append(reason)
        result = getattr(self.operator, method)(*args)
        require(isinstance(result, dict) and result.get("schema") == "aegis.operator-async-result/v1"
                and result.get("request_id") == request_id and result.get("request_sha256") == request_sha256
                and result.get("intent_id") == row["intent"]["id"]
                and result.get("association_sha256") == row["association"]["sha256"]
                and result.get("association") == row["association"]["value"],
                "operator follow-up correlation mismatch")
        return result

    def poll_request(self, request_id, request_sha256, operation_id):
        return self._follow_request("observe", request_id, request_sha256, operation_id)

    def cancel_request(self, request_id, request_sha256, operation_id, reason):
        return self._follow_request("cancel", request_id, request_sha256, operation_id, reason)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capabilities = commands.add_parser("capabilities")
    capabilities.add_argument("--host", required=True)
    args = parser.parse_args(argv)
    try:
        result = NativeBridge(args.host).capabilities()
    except ValueError as exc:
        print(encoded({"state": "hold", "error": str(exc), "native_qualified": False}).decode())
        return 2
    print(encoded(result).decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
