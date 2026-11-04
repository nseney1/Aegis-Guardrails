#!/usr/bin/env python3
"""Persistent, unauthenticated disposable fixture work; never a native service.

The canonical Operator owns admission/intent/association. This broker owns only
its fixed test processes. N2's caller deadline is not present on the wire:
timeout or disconnect can leave a possible late fixture start, never a retry.
"""
from __future__ import annotations

import argparse
import hashlib
import math
import os
from pathlib import Path
import select
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_lifecycle import Lifecycle, active_seconds  # noqa: E402
from hierarchy_mailbox import digest, encoded, parse_time, safe_path, strict_json, timestamp  # noqa: E402
from hierarchy_watch_bridge import validate_process_provider  # noqa: E402

MAX_REQUEST = 768 * 1024
MAX_RESPONSE = 1024 * 1024
FRAME_FIELDS = {"schema", "call_id", "method", "request", "request_sha256", "actor", "generation",
                "association", "association_sha256", "provider_handle", "reason"}
READY_FIELDS = {"schema", "provider", "endpoint_id", "socket", "lifecycle_root", "pid", "native_qualified"}
HOST_ERROR = "fixture broker requires POSIX waitid WNOWAIT"
ERROR_CODES = {"FIXTURE_UNSUPPORTED_HOST", "FIXTURE_INVALID_CONFIG", "FIXTURE_ENDPOINT_REUSED",
               "FIXTURE_ENDPOINT_UNAVAILABLE", "FIXTURE_FRAME_INVALID", "FIXTURE_FRAME_TOO_LARGE",
               "FIXTURE_CORRELATION_MISMATCH", "FIXTURE_STALE_ACTOR", "FIXTURE_HANDLE_MISMATCH",
               "FIXTURE_DEADLINE_EXPIRED", "FIXTURE_CAPACITY_REACHED", "FIXTURE_OUTCOME_UNKNOWN",
               "FIXTURE_SOCKET_TIMEOUT"}


class BrokerError(ValueError):
    """Closed public fixture diagnostic; never an authenticated refusal receipt."""

    def __init__(self, code):
        self.code = code
        super().__init__(HOST_ERROR if code == "FIXTURE_UNSUPPORTED_HOST" else code)


def check(condition, code="FIXTURE_FRAME_INVALID"):
    if not condition:
        raise BrokerError(code)


def supported():
    check(os.name == "posix" and hasattr(socket, "AF_UNIX") and all(hasattr(os, name) for name in
          ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")), "FIXTURE_UNSUPPORTED_HOST")


def string(value, limit=256):
    return type(value) is str and 0 < len(value) <= limit and "\0" not in value


def path_value(value):
    try:
        result = safe_path(value)
    except (ValueError, TypeError) as exc:
        raise BrokerError("FIXTURE_INVALID_CONFIG") from exc
    check(len(str(result)) <= 1024, "FIXTURE_INVALID_CONFIG")
    return result


def parse(raw, limit):
    check(type(raw) is bytes)
    check(len(raw) <= limit, "FIXTURE_FRAME_TOO_LARGE")
    check(raw.endswith(b"\n") and b"\n" not in raw[:-1])
    try:
        value = strict_json(raw.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise BrokerError("FIXTURE_FRAME_INVALID") from exc
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        check(depth <= 32)
        if type(item) is dict:
            stack.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is float:
            check(math.isfinite(item))
    return value


def frame(raw):
    value = parse(raw, MAX_REQUEST)
    check(type(value) is dict and set(value) == FRAME_FIELDS)
    check(value["schema"] == "aegis.fixture-process-call/v1")
    check(value["method"] in ("inspect", "submit", "observe", "cancel"))
    check(string(value["call_id"], 128) and string(value["actor"], 128))
    check(type(value["generation"]) is int and value["generation"] >= 1)
    check(type(value["request"]) is dict and type(value["request"].get("source")) is dict)
    check(string(value["request"].get("id"), 80) and string(value["request_sha256"], 64))
    handle = value["provider_handle"]
    check(handle is None or (type(handle) is dict and set(handle) == {"thread_id", "turn_id"}
                            and all(string(item) for item in handle.values())))
    if value["method"] == "inspect":
        check(value["association"] is None and value["association_sha256"] is None
              and handle is None and value["reason"] is None)
    else:
        check(type(value["association"]) is dict and string(value["association_sha256"], 64))
        if value["method"] == "cancel":
            check(handle is not None and string(value["reason"], 1024))
        else:
            check(value["reason"] is None)
    check(len(encoded(value)) + 1 <= MAX_REQUEST, "FIXTURE_FRAME_TOO_LARGE")
    return value


def read_stream(stream, limit, deadline):
    chunks, total = [], 0
    while True:
        remaining = deadline - time.monotonic()
        check(remaining > 0, "FIXTURE_SOCKET_TIMEOUT")
        stream.settimeout(remaining)
        try:
            part = stream.recv(min(65536, limit + 1 - total))
        except socket.timeout as exc:
            raise BrokerError("FIXTURE_SOCKET_TIMEOUT") from exc
        if not part:
            break
        chunks.append(part)
        total += len(part)
        check(total <= limit, "FIXTURE_FRAME_TOO_LARGE")
    return b"".join(chunks)


def ready(directory):
    directory = path_value(directory)
    try:
        value = parse(read_file(directory / "ready.json", 65536), 65536)
    except OSError as exc:
        raise BrokerError("FIXTURE_ENDPOINT_UNAVAILABLE") from exc
    check(type(value) is dict and set(value) == READY_FIELDS, "FIXTURE_INVALID_CONFIG")
    check(value["schema"] == "aegis.fixture-broker-ready/v1" and value["provider"] == "fixture-broker"
          and string(value["endpoint_id"], 128) and value["socket"] == "broker.sock"
          and type(value["pid"]) is int and value["pid"] > 0
          and value["native_qualified"] is False, "FIXTURE_INVALID_CONFIG")
    path_value(value["lifecycle_root"])
    return value


def read_file(path, limit):
    path = path_value(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        check(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "FIXTURE_INVALID_CONFIG")
        raw = stream.read(limit + 1)
    check(len(raw) <= limit, "FIXTURE_FRAME_TOO_LARGE")
    return raw


def descriptor(directory, *, cwd, evidence_dir):
    """Return N2's existing closed fixture descriptor, never a trust grant."""
    directory = path_value(directory)
    info = ready(directory)
    return validate_process_provider({
        "schema": "aegis.fixture-process-provider/v1", "mode": "fixture", "provider": info["provider"],
        "endpoint_id": info["endpoint_id"], "argv": [sys.executable, "-I", "-B", str(Path(__file__).resolve()),
                                                        "call", "--directory", str(directory)],
        "cwd": str(cwd), "evidence_dir": str(evidence_dir), "stop_grace": 0.02,
    })


def call(directory, raw_frame):
    """One short-lived bounded relay; no reconnect, resend or process ownership."""
    request = frame(raw_frame)  # Reject malformed input before endpoint access.
    supported()
    directory = path_value(directory)
    info = ready(directory)
    deadline = time.monotonic() + 1
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(max(0.001, deadline - time.monotonic()))
            stream.connect(str(directory / info["socket"]))
            stream.sendall(encoded(request) + b"\n")
            stream.shutdown(socket.SHUT_WR)
            response = parse(read_stream(stream, MAX_RESPONSE, deadline), MAX_RESPONSE)
    except (OSError, TimeoutError) as exc:
        raise BrokerError("FIXTURE_ENDPOINT_UNAVAILABLE") from exc
    if type(response) is dict and set(response) == {"error"}:
        check(type(response["error"]) is str and response["error"] in ERROR_CODES)
        raise BrokerError(response["error"])
    check(type(response) is dict and set(response) == FRAME_FIELDS | {"result"})
    check(encoded({key: response[key] for key in FRAME_FIELDS}) == encoded(request),
          "FIXTURE_CORRELATION_MISMATCH")
    return response


def write_json(path, value):
    with path.open("xb") as output:
        output.write(encoded(value) + b"\n")


def reference(path):
    raw = path.read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}


class Work:
    """Transient OS ownership only; no authority/intent/resource replay store."""

    def __init__(self, directory, request, end, descendant):
        self.directory = directory
        self.handle = {"thread_id": request["association"]["thread_id"], "turn_id": uuid.uuid4().hex}
        self.process, self.terminal = None, None
        self.cancelled, self.uncertain = False, False
        self.output = None
        directory.mkdir(mode=0o700)
        write_json(directory / "attempt.json", {"association_sha256": request["association_sha256"],
                                                "provider_handle": self.handle, "fixture_only": True})
        argv = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "worker", "--directory", str(directory),
                "--end", str(end)]
        if descendant:
            argv.append("--with-descendant")
        self.output = (directory / "output").open("xb")
        try:
            self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=self.output, stderr=self.output,
                                            close_fds=True, start_new_session=True)
        except OSError:
            # The attempt is consumed even when launch acknowledgement is ambiguous.
            self.uncertain = True
        else:
            write_json(directory / "spawned.json", {"pid": self.process.pid, "fixture_only": True})

    def ownership(self):
        # Popen is retained and never poll()/wait()ed before group cleanup.
        return os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)

    def refresh(self):
        if self.terminal is not None or self.process is None:
            return
        try:
            exited = self.ownership()
        except OSError:
            self.uncertain = True
            return
        if exited is None:
            return
        receipt = self.directory / "finished.json"
        try:
            value = parse(read_file(receipt, 65536), 65536)
            started = parse(read_file(self.directory / "started.json", 65536), 65536)
            valid = (type(value) is dict and set(value) == {"pid", "descendant_pid", "descendant_reaped",
                                                          "cancelled", "exit_code"}
                     and type(value["pid"]) is int and value["pid"] == self.process.pid
                     and value["descendant_pid"] == started["descendant_pid"]
                     and value["descendant_reaped"] is True and type(value["cancelled"]) is bool
                     and type(value["exit_code"]) is int and value["exit_code"] == exited.si_status)
        except (OSError, BrokerError):
            valid = False
        if not valid:
            # A leader can exit with live descendants. Reserve its PID until
            # the group cleanup attempt, and retain UNKNOWN regardless of reap.
            self.uncertain = True
            self.stop()
            return
        code = self.process.wait(timeout=0.2)
        if self.process.stdin is not None:
            self.process.stdin.close()
        self.output.close()
        phase = "cancelled" if value["cancelled"] else "passed" if code == 0 else "failed"
        self.terminal = (phase, code, receipt)

    def stop(self):
        if self.process is None or self.terminal is not None or self.process.returncode is not None:
            return
        self.cancelled = True
        try:
            self.ownership()  # Still our unreaped direct child, not a supplied PID.
            os.kill(self.process.pid, signal.SIGTERM)
            end = time.monotonic() + 0.2
            while time.monotonic() < end:
                if self.ownership() is not None:
                    break
                time.sleep(0.01)
            if self.ownership() is None or self.uncertain:
                self.uncertain = True
                # Keep the group leader unreaped until all signals are issued.
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait(timeout=0.2)
                if self.process.stdin is not None:
                    self.process.stdin.close()
                self.output.close()
        except (OSError, subprocess.TimeoutExpired):
            self.uncertain = True

    def observation(self, association_sha256):
        self.refresh()
        phase, code, quiescent = "unknown" if self.uncertain else "cancel_requested" if self.cancelled else "running", None, False
        proof = self.directory / "spawned.json" if (self.directory / "spawned.json").exists() else self.directory / "attempt.json"
        if self.terminal is not None and not self.uncertain:
            phase, code, proof = self.terminal
            quiescent = True
        return {"association_sha256": association_sha256, "provider_state": phase, "provider_handle": self.handle,
                "exit_code": code, "evidence": [reference(proof)], "quiescent": quiescent}


class Broker:
    def __init__(self, directory, lifecycle_root, work_seconds, end, descendant, info):
        self.directory, self.lifecycle_root = directory, lifecycle_root
        self.work_seconds, self.end, self.descendant, self.info = work_seconds, end, descendant, info
        self.work = {}

    def context(self, request):
        try:
            policy, state = Lifecycle(self.lifecycle_root).load()
            row = state["requests"][request["request"]["id"]]
        except (OSError, ValueError, KeyError) as exc:
            raise BrokerError("FIXTURE_CORRELATION_MISMATCH") from exc
        actor = policy["actors"].get(request["actor"])
        check(actor is not None and actor["role"] == "operator"
              and state["current"]["operator"] == request["actor"]
              and actor["generation"] == request["generation"], "FIXTURE_STALE_ACTOR")
        check(row["raw"]["sha256"] == request["request_sha256"]
              and encoded(row["request"]) == encoded(request["request"]), "FIXTURE_CORRELATION_MISMATCH")
        if request["method"] != "inspect":
            association = row.get("association")
            check(association is not None and encoded(association["value"]) == encoded(request["association"])
                  and association["sha256"] == request["association_sha256"] == digest(request["association"])
                  and association["value"]["provider"] == self.info["provider"]
                  and association["value"]["endpoint_id"] == self.info["endpoint_id"], "FIXTURE_CORRELATION_MISMATCH")
            from hierarchy_lifecycle import provider_handle
            known = provider_handle(row)
            if request["provider_handle"] is not None:
                check(known == request["provider_handle"], "FIXTURE_HANDLE_MISMATCH")
        return policy, state, row

    def handle(self, request):
        policy, state, row = self.context(request)
        method = request["method"]
        if method == "inspect":
            proof = [reference(self.directory / "fixture-gates.json")]
            return {"qualified": True, "mode": "fixture", "source": request["request"]["source"],
                    "gates": {key: proof for key in ("source", "capability", "lease", "capacity", "observer", "job")},
                    "reason": "synthetic disposable fixture gates; no original job or native authority"}
        key = request["association_sha256"]
        work = self.work.get(key)
        if method == "submit" and work is None:
            association = request["association"]
            monotonic_now = time.monotonic()
            now = parse_time(timestamp())
            seconds = min(self.work_seconds, self.end - monotonic_now,
                          (parse_time(association["deadline"]) - now).total_seconds(),
                          (parse_time(association["authority_expires_at"]) - now).total_seconds())
            decisions = [d for d in state["decisions"] if d["request_id"] == association["authority"]]
            check(seconds > 0 and active_seconds(state, request["actor"], timestamp())
                  < policy["actors"][request["actor"]]["cap_seconds"], "FIXTURE_DEADLINE_EXPIRED")
            check(decisions and decisions[-1]["decision"] == "approve"
                  and digest(decisions[-1]) == association["decision_sha256"]
                  and row["terminal"] is None, "FIXTURE_CORRELATION_MISMATCH")
            check(len(self.work) < 32, "FIXTURE_CAPACITY_REACHED")
            # Memory reservation precedes launch. Failed/ambiguous launch remains
            # consumed here; no new submit queue or canonical record is created.
            self.work[key] = None
            work = Work(self.directory / ("work-" + key), request, monotonic_now + seconds, self.descendant)
            self.work[key] = work
        if work is None:
            return {"association_sha256": key, "provider_state": "unknown", "provider_handle": None,
                    "exit_code": None, "evidence": [reference(self.directory / "fixture-gates.json")], "quiescent": False}
        if request["provider_handle"] is not None:
            check(request["provider_handle"] == work.handle, "FIXTURE_HANDLE_MISMATCH")
        if method == "cancel":
            check(request["provider_handle"] == work.handle, "FIXTURE_HANDLE_MISMATCH")
            if not work.cancelled:
                work.stop()
        return work.observation(key)


def serve(directory, lifecycle_root, *, work_seconds, lifetime_seconds, with_descendant=False):
    """Run only an explicitly test-owned, finite fixture instance."""
    for value, low, high in ((work_seconds, 0.05, 30), (lifetime_seconds, 1, 120)):
        check(type(value) in (int, float) and math.isfinite(value) and low <= value <= high, "FIXTURE_INVALID_CONFIG")
    check(type(with_descendant) is bool, "FIXTURE_INVALID_CONFIG")
    directory, lifecycle_root = path_value(directory), path_value(lifecycle_root)
    supported()
    check(len(os.fsencode(str(directory / "broker.sock"))) <= 100, "FIXTURE_INVALID_CONFIG")
    if directory.exists():
        raise BrokerError("FIXTURE_ENDPOINT_REUSED")
    check(lifecycle_root.is_dir(), "FIXTURE_INVALID_CONFIG")
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise BrokerError("FIXTURE_ENDPOINT_REUSED") from exc
    info = {"schema": "aegis.fixture-broker-ready/v1", "provider": "fixture-broker",
            "endpoint_id": "fixture-" + uuid.uuid4().hex, "socket": "broker.sock",
            "lifecycle_root": str(lifecycle_root), "pid": os.getpid(), "native_qualified": False}
    write_json(directory / "fixture-gates.json", {"schema": "aegis.synthetic-fixture-gates/v1",
                                                  "native_qualified": False, "original_job_binding": "unavailable"})
    end = time.monotonic() + lifetime_seconds
    broker = Broker(directory, lifecycle_root, work_seconds, end, with_descendant, info)
    stopping = [False]

    def stop(_number, _frame):
        stopping[0] = True

    previous = {number: signal.signal(number, stop) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(directory / "broker.sock"))
            listener.listen(8)
            listener.settimeout(0.05)
            write_json(directory / "ready.json", info)
            while not stopping[0] and time.monotonic() < end:
                for work in broker.work.values():
                    if work is not None:
                        work.refresh()
                try:
                    stream, _ = listener.accept()
                except socket.timeout:
                    continue
                with stream:
                    deadline = min(end, time.monotonic() + 0.5)
                    try:
                        request = frame(read_stream(stream, MAX_REQUEST, deadline))
                        result = broker.handle(request)
                        output = encoded({**request, "result": result}) + b"\n"
                        check(len(output) <= MAX_RESPONSE, "FIXTURE_FRAME_TOO_LARGE")
                    except BrokerError as exc:
                        output = encoded({"error": exc.code}) + b"\n"
                    try:
                        stream.settimeout(max(0.001, deadline - time.monotonic()))
                        stream.sendall(output)
                    except OSError:
                        # Reply loss never discards the actual owned workload.
                        pass
    finally:
        for work in broker.work.values():
            if work is not None:
                work.stop()
                work.refresh()
        for number, handler in previous.items():
            signal.signal(number, handler)
        # Keep the incarnation directory/socket as retired evidence. No rebind.


def worker(directory, end, with_descendant):
    """The only workload: bounded waiting and one fixed, nonescaping child."""
    cancelled, child = [False], None

    def stop(_number, _frame):
        cancelled[0] = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    cancelled[0] = time.monotonic() >= end
    if with_descendant and not cancelled[0]:
        child = subprocess.Popen([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
                                  "descendant", "--end", str(end)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 close_fds=True)
    write_json(directory / "started.json", {"pid": os.getpid(), "descendant_pid": child.pid if child else None})
    try:
        while not cancelled[0] and time.monotonic() < end:
            readable, _, _ = select.select([sys.stdin.buffer], [], [], min(0.02, max(0, end - time.monotonic())))
            if readable and sys.stdin.buffer.read(1) == b"":
                cancelled[0] = True
    finally:
        reaped = child is None
        if child is not None:
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=0.2)
                reaped = True
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=0.2)
                reaped = True
        code = 130 if cancelled[0] else 0
        write_json(directory / "finished.json", {"pid": os.getpid(), "descendant_pid": child.pid if child else None,
                                               "descendant_reaped": reaped, "cancelled": cancelled[0], "exit_code": code})
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    serve_parser = sub.add_parser("serve")
    serve_parser.add_argument("--directory", required=True)
    serve_parser.add_argument("--lifecycle-root", required=True)
    serve_parser.add_argument("--work-seconds", type=float, required=True)
    serve_parser.add_argument("--lifetime-seconds", type=float, required=True)
    serve_parser.add_argument("--with-descendant", action="store_true")
    relay = sub.add_parser("call")
    relay.add_argument("--directory", required=True)
    work_parser = sub.add_parser("worker")
    work_parser.add_argument("--directory", required=True)
    work_parser.add_argument("--end", type=float, required=True)
    work_parser.add_argument("--with-descendant", action="store_true")
    descendant = sub.add_parser("descendant")
    descendant.add_argument("--end", type=float, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            serve(args.directory, args.lifecycle_root, work_seconds=args.work_seconds,
                  lifetime_seconds=args.lifetime_seconds, with_descendant=args.with_descendant)
        elif args.command == "call":
            response = call(args.directory, sys.stdin.buffer.read(MAX_REQUEST + 1))
            sys.stdout.buffer.write(encoded(response) + b"\n")
        elif args.command == "worker":
            check(math.isfinite(args.end) and 0 < args.end and args.end - time.monotonic() <= 30,
                  "FIXTURE_INVALID_CONFIG")
            return worker(path_value(args.directory), args.end, args.with_descendant)
        else:
            check(math.isfinite(args.end) and 0 < args.end and args.end - time.monotonic() <= 30,
                  "FIXTURE_INVALID_CONFIG")
            time.sleep(max(0, args.end - time.monotonic()))
        return 0
    except BrokerError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
