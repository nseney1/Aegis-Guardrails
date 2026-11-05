#!/usr/bin/env python3
"""The provider bridge: start, resume and stop a provisioned Codex role, and record every outcome.

`start` runs a role's start argv once with a fixed prompt, reads the session ID from the first
`thread.started` event and binds it through add-role. `resume` runs the pinned wake tool with the
bound wake profile, unchanged. `stop` signals the process groups of the processes that name the
bound session, so it cannot stop a session on another host. `status` reads the records back.

A launch record is not a lifecycle event and grants nothing: the journal has no provider-bridge
role. A clean start proves a process ran and reported a thread, not that the role will behave.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import uuid

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import Mailbox, fields, integer, read_json, require, safe_path, text, timestamp  # noqa: E402
from hierarchy_provision import CODEX, NATIVE, SESSION, add_role, codex_start  # noqa: E402
from hierarchy_wake import stop_group  # noqa: E402


SCHEMA = "aegis.hierarchy-launch/v1"
STATUS_SCHEMA = "aegis.hierarchy-launch-status/v1"
MAX_RECORDS = 10000
DEFAULT_START_TIMEOUT_SECONDS = 300
KILL_WAIT_SECONDS = 5.0
POLL_SECONDS = 0.05
# The wake tool bounds the turn by the profile timeout; this only bounds the wake tool itself.
WAKE_MARGIN_SECONDS = 60
CODEX_START_KEYS = {"cwd", "reader_shell", "writable_roots", "tmpdir", "add_dirs", "model", "effort", "skip_git_repo_check"}
ADD_ROLE_KEYS = CODEX_START_KEYS | {"timeout_seconds", "source_repo", "kind", "lifecycle", "actor"}
START_PROMPT = "The Aegis launcher started this session for %s. Reply READY and take no other action."


class Refused(Exception):
    """A refusal already recorded, so main prints the record and nothing else."""

    def __init__(self, record):
        super().__init__(record["error"])
        self.record = record


def quoted(endpoint):
    return endpoint.replace("/", "%2F")


class Launches:
    def __init__(self, base):
        self.base = safe_path(text(base, "base"))
        self.setup = read_json(self.base / "provision.json")
        self.mailbox = Mailbox(self.setup["mailbox_root"])

    def folder(self, endpoint):
        return self.base / "launches" / quoted(endpoint)

    def paths(self, endpoint):
        folder = self.folder(endpoint)
        return sorted(path for path in folder.glob("*.json") if path.is_file()) if folder.is_dir() else []

    def resolve(self, endpoint):
        """An endpoint is resolved once the manifest knows it; from then on every outcome is recorded."""
        self.mailbox.endpoint(endpoint)
        require(len(self.paths(endpoint)) < MAX_RECORDS, "launch record limit reached for " + endpoint)
        return endpoint

    def binding(self, endpoint):
        history = self.mailbox.bindings(endpoint)
        return history[-1] if history else None

    def new_id(self):
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex

    def make(self, endpoint, *below):
        folder = self.folder(endpoint)
        for directory in (folder.parent, folder, *(folder.joinpath(*below[:n + 1]) for n in range(len(below)))):
            directory.mkdir(mode=0o700, exist_ok=True)
        return folder.joinpath(*below)

    def write(self, endpoint, identifier, record):
        folder = self.make(endpoint)
        require(len(self.paths(endpoint)) < MAX_RECORDS, "launch record limit reached for " + endpoint)
        fd = os.open(folder / (identifier + ".json"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        return record

    def record(self, endpoint, identifier, action, state, *, host=None, session=None, generation=None, **details):
        return self.write(endpoint, identifier, {"schema": SCHEMA, "at": timestamp(), "action": action, "state": state,
                                                 "endpoint": endpoint, "host": host, "session": session,
                                                 "generation": generation, **details})

    def refuse(self, endpoint, identifier, action, error, **known):
        raise Refused(self.record(endpoint, identifier, action, "refused", error=error, **known))


def read_events(stream, copy, found):
    """Copy the start's stdout to its log and keep the first thread.started session."""
    with open(copy, "xb") as log:
        for line in iter(stream.readline, b""):
            log.write(line)
            if "session" in found:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if isinstance(event, dict) and event.get("type") == "thread.started":
                found["session"] = event.get("thread_id")


def run_start(argv, cwd, logs, timeout):
    found = {}
    with open(logs["stderr"], "xb") as stderr:
        process = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=stderr,
                                   start_new_session=True)
    reader = threading.Thread(target=read_events, args=(process.stdout, logs["stdout"], found), daemon=True)
    reader.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
    # Also after a clean exit, so nothing the start left in its group keeps running unrecorded.
    stop_group(process)
    reader.join(timeout=KILL_WAIT_SECONDS)
    process.stdout.close()
    return found.get("session"), process.returncode, timed_out


def start(launches, request_path):
    request = read_json(safe_path(text(request_path, "request")))
    require(isinstance(request, dict), "expected a JSON object")
    endpoint = launches.resolve(request.get("endpoint"))
    identifier = launches.new_id()
    known = {"host": CODEX}
    try:
        fields(request, {"endpoint"}, ADD_ROLE_KEYS | {"start_timeout_seconds"})
        timeout = integer(request.get("start_timeout_seconds", DEFAULT_START_TIMEOUT_SECONDS), "start_timeout_seconds",
                          maximum=3600)
        require(launches.binding(endpoint) is None, "endpoint is already bound; resume it or hand it off")
        started = codex_start({"base": str(launches.base), "endpoint": endpoint,
                               **{key: request[key] for key in CODEX_START_KEYS if key in request}})
    except (ValueError, OSError, TypeError, KeyError) as exc:
        launches.refuse(endpoint, identifier, "start", str(exc), **known)
    argv = started["start_argv"] + [START_PROMPT % endpoint]
    folder = launches.make(endpoint, "logs")
    logs = {name: str(folder / (identifier + "." + name)) for name in ("stdout", "stderr")}
    session, exit_code, timed_out = run_start(argv, started["cwd"], logs, timeout)
    details = {"argv": argv, "cwd": started["cwd"], "start_timeout_seconds": timeout, "exit_code": exit_code,
               "timed_out": timed_out}
    if not (isinstance(session, str) and SESSION.fullmatch(session)):
        error = None if session is None else "the start reported an invalid session"
        record = launches.record(endpoint, identifier, "start", "failed_to_start", **known, **details,
                                 **({"error": error} if error else {}))
        return 3, {**record, "log": logs}
    known["session"] = session
    if exit_code != 0 or timed_out:
        return 3, {**launches.record(endpoint, identifier, "start", "start_incomplete", **known, **details), "log": logs}
    try:
        bound = add_role({"base": str(launches.base), "endpoint": endpoint, "host": CODEX, "session": session,
                          **{key: request[key] for key in ADD_ROLE_KEYS if key in request}})
    except (ValueError, OSError, TypeError, KeyError) as exc:
        record = launches.record(endpoint, identifier, "start", "bind_refused", **known, **details, error=str(exc))
        return 3, {**record, "log": logs}
    kept = {key: bound[key] for key in ("connection", "wake_profile", "codex_profile") if key in bound}
    record = launches.record(endpoint, identifier, "start", "bound", generation=bound["generation"], **known, **details, **kept)
    return 0, {**record, "log": logs}


def bound_session(launches, endpoint, identifier, action):
    binding = launches.binding(endpoint)
    if binding is None:
        launches.refuse(endpoint, identifier, action, "endpoint has no binding")
    known = {key: binding[key] for key in ("host", "session", "generation")}
    profile = launches.base / "profiles" / ("%s-g%d.wake.json" % (quoted(endpoint), binding["generation"]))
    return known, profile


def resume(launches, endpoint, dry_run):
    endpoint = launches.resolve(endpoint)
    identifier = launches.new_id()
    known, profile = bound_session(launches, endpoint, identifier, "resume")
    if known["host"] == NATIVE:
        launches.refuse(endpoint, identifier, "resume", "a native thread is resumed by its own app, not the launcher", **known)
    if not profile.is_file():
        launches.refuse(endpoint, identifier, "resume", "no wake profile for the current binding: " + str(profile), **known)
    try:
        limit = integer(read_json(profile).get("timeout_seconds"), "timeout_seconds", maximum=86400) + WAKE_MARGIN_SECONDS
    except (ValueError, OSError, AttributeError) as exc:
        launches.refuse(endpoint, identifier, "resume", str(exc), **known)
    argv = [sys.executable, "-I", "-B", str(Path(launches.setup["source"]) / "tools" / "hierarchy_wake.py"),
            "--root", launches.setup["mailbox_root"], "--delivery-dir", launches.setup["delivery_dir"],
            "--endpoint", endpoint, "--profile", str(profile)] + (["--dry-run"] if dry_run else [])
    try:
        ran = subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=limit)
    except subprocess.TimeoutExpired:
        launches.refuse(endpoint, identifier, "resume", "the wake tool did not finish within %d seconds" % limit, **known)
    try:
        answer = json.loads(ran.stdout)
    except ValueError:
        answer = {}
    answer = answer if isinstance(answer, dict) else {}
    wake = {key: answer.get(key) for key in ("wake_id", "state", "exit_code", "timed_out")}
    details = {"dry_run": dry_run, "wake": wake, "wake_exit_code": ran.returncode}
    if ran.returncode in (0, 3):
        state = "resumed" if ran.returncode == 0 else "resumed_unread"
        return ran.returncode, launches.record(endpoint, identifier, "resume", state, **known, **details)
    error = answer.get("error") if isinstance(answer.get("error"), str) else "the wake tool exited %d" % ran.returncode
    return 2, launches.record(endpoint, identifier, "resume", "refused", **known, **details, error=error)


def ancestors():
    mine, pid = set(), os.getpid()
    while pid > 1 and pid not in mine:
        mine.add(pid)
        shown = subprocess.run(["ps", "-o", "ppid=", "-p", str(pid)], capture_output=True, text=True, timeout=10).stdout.strip()
        pid = int(shown) if shown.isdigit() else 0
    return mine


def session_processes(session, excluded):
    """(pid, pgid) of every live process that names the session as a whole argument, as the wake tool's check does."""
    census = subprocess.run(["ps", "-ax", "-ww", "-o", "pid=,pgid=,stat=,args="], capture_output=True, text=True, timeout=10)
    require(census.returncode == 0, "process census failed")
    found = []
    for line in census.stdout.splitlines():
        words = line.split()
        if len(words) < 4 or not (words[0].isdigit() and words[1].isdigit()):
            continue
        pid, pgid = int(words[0]), int(words[1])
        # A zombie has already ended; it only waits for its parent to collect it.
        if pid not in excluded and not words[2].startswith("Z") and session in words[3:]:
            found.append((pid, pgid))
    return found


def signal_all(found, number):
    own_group = os.getpgrp()
    pids = {pid for pid, _ in found}
    for group in sorted({pgid for _, pgid in found}):
        targets = [pid for pid, pgid in found if pgid == group]
        try:
            if group in pids and group != own_group:
                os.killpg(group, number)
            else:
                for pid in targets:
                    os.kill(pid, number)
        except (ProcessLookupError, PermissionError):
            continue


def gone_within(session, excluded, pids, seconds):
    deadline = time.monotonic() + seconds
    while True:
        left = {pid for pid, _ in session_processes(session, excluded)} & pids
        if not left or time.monotonic() >= deadline:
            return not left
        time.sleep(POLL_SECONDS)


def stop(launches, endpoint, grace):
    endpoint = launches.resolve(endpoint)
    identifier = launches.new_id()
    if not (type(grace) is int and 0 <= grace <= 60):
        launches.refuse(endpoint, identifier, "stop", "invalid grace_seconds")
    known, profile = bound_session(launches, endpoint, identifier, "stop")
    try:
        background = profile.is_file() and read_json(profile).get("mode") == "background"
    except (ValueError, OSError, AttributeError) as exc:
        launches.refuse(endpoint, identifier, "stop", str(exc), **known)
    if background:
        launches.refuse(endpoint, identifier, "stop",
                        "a background claude session stops through claude stop; use the wake tool's control", **known)
    excluded = ancestors()
    found = session_processes(known["session"], excluded)
    marker = {"wake_marker_present": launches.mailbox.wake_marker(endpoint).exists(), "grace_seconds": grace}
    if not found:
        return 0, launches.record(endpoint, identifier, "stop", "not_running", **known, pids=[], **marker)
    pids = {pid for pid, _ in found}
    signal_all(found, signal.SIGTERM)
    stopped = gone_within(known["session"], excluded, pids, grace)
    if not stopped:
        signal_all(session_processes(known["session"], excluded), signal.SIGKILL)
        stopped = gone_within(known["session"], excluded, pids, KILL_WAIT_SECONDS)
    # The marker belongs to the wake that made it; whoever inspects it decides whether that turn has ended.
    marker["wake_marker_present"] = launches.mailbox.wake_marker(endpoint).exists()
    state = "stopped" if stopped else "stop_failed"
    return (0 if stopped else 3), launches.record(endpoint, identifier, "stop", state, **known, pids=sorted(pids), **marker)


def status(launches, endpoint):
    if endpoint is not None:
        launches.mailbox.endpoint(endpoint)
        names = [endpoint]
    else:
        folder = launches.base / "launches"
        names = sorted(path.name.replace("%2F", "/") for path in folder.iterdir() if path.is_dir()) if folder.is_dir() else []
    rows = {}
    for name in names:
        binding = launches.binding(name)
        paths = launches.paths(name)
        rows[name] = {"binding": None if binding is None else {key: binding[key] for key in ("host", "session", "generation")},
                      "last": read_json(paths[-1]) if paths else None, "records": len(paths)}
    return 0, {"schema": STATUS_SCHEMA, "endpoints": rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", required=True, help="Absolute path to a provisioned initiative base")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("start").add_argument("--request", required=True, help="Absolute path to a strict JSON request")
    resumed = commands.add_parser("resume")
    resumed.add_argument("--endpoint", required=True)
    resumed.add_argument("--dry-run", action="store_true", help="Run the wake tool's dry run; launch nothing")
    stopped = commands.add_parser("stop")
    stopped.add_argument("--endpoint", required=True)
    stopped.add_argument("--grace-seconds", type=int, default=5)
    commands.add_parser("status").add_argument("--endpoint")
    args = parser.parse_args(argv)
    try:
        require(args.command == "status" or os.name == "posix", "the launcher supports POSIX process groups only")
        launches = Launches(args.base)
        if args.command == "start":
            code, result = start(launches, args.request)
        elif args.command == "resume":
            code, result = resume(launches, args.endpoint, args.dry_run)
        elif args.command == "stop":
            code, result = stop(launches, args.endpoint, args.grace_seconds)
        else:
            code, result = status(launches, args.endpoint)
    except Refused as refusal:
        code, result = 2, refusal.record
    except (ValueError, OSError, TypeError, KeyError, UnicodeError, RecursionError, subprocess.SubprocessError) as exc:
        code, result = 2, {"error": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
