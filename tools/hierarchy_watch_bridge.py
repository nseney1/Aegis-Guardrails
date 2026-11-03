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
from hierarchy_mailbox import SHA256, SLUG, encoded, matching, require, safe_path, strict_json, text  # noqa: E402


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

    def _call(self, method, request_id, request_sha256, operation_id=None):
        correlation(request_id, request_sha256, operation_id)
        deadline = time.monotonic() + self.timeout_seconds
        if self.deadline is not None:
            deadline = min(deadline, self.deadline)
        spawned, details = False, None
        reason = self._interruption(deadline)
        request = {"schema": "aegis.watch-process/v1", "method": method, "request_id": request_id,
                   "request_sha256": request_sha256, "operation_id": operation_id}
        folder = None
        if reason is None:
            folder = safe_path(self.evidence_dir / uuid.uuid4().hex)
            folder.mkdir(mode=0o700)
            (folder / "request.json").write_bytes(encoded(request))
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
                    except (ValueError, UnicodeError) as exc:
                        raise ValueError("invalid process bridge response") from exc
                    require(isinstance(response, dict) and set(response) == set(request) | {"result"}
                            and all(response[key] == value for key, value in request.items()),
                            "process bridge response correlation mismatch")
                    result = response["result"]
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


class OperatorBridge:
    """External-provider boundary around Session 1's canonical Operator API.

The caller must explicitly select evidence-only operation. Provider observations
remain fixture evidence; the operator independently repeats admission checks.
"""

    def __init__(self, lifecycle_root, provider, actor, generation, *, evidence_only=False):
        from hierarchy_lifecycle import Lifecycle
        from hierarchy_operator import Operator
        self.lifecycle = Lifecycle(lifecycle_root)
        self.provider = provider
        self.actor = actor
        self.generation = generation
        self.evidence_only = evidence_only
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
        result = self.provider.inspect(row["request"], self.actor, self.generation)
        require(isinstance(result, dict) and type(result.get("qualified")) is bool, "invalid provider observation")
        require(result.get("mode") == "fixture", "evidence-only bridge requires a fixture provider")
        return {"state": "eligible" if result["qualified"] else "hold", "reason": result.get("reason", ""),
                "native_qualified": False}

    def continue_request(self, request_id, request_sha256, operation_id):
        correlation(request_id, request_sha256, operation_id)
        self.request(request_id, request_sha256)
        if not self.evidence_only:
            return NativeBridge().continue_request(request_id, request_sha256, operation_id)
        # The watch ID correlates delivery only. Operator owns the one canonical
        # execution intent and revalidates authority/source/generation under lock.
        result = self.operator.execute(request_id, self.actor, self.generation)
        return {**result, "native_qualified": False}


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
