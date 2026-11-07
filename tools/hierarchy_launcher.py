#!/usr/bin/env python3
"""The provider bridge: start, resume and stop a provisioned role, and record every outcome.

`start` runs a role's start argv once with its role contract as the prompt and binds the session through add-role.
The role runs on the host the base's host plan assigns it (ADR T2(a) §1), or on codex-cli where no plan covers it,
as before plans existed. The contract leaves out passages marked for another host family; a reviewer or an
integrator also gets lane.md's shared rules. A codex-cli start takes the prompt as its last argument and reports the
session in its first `thread.started` event. A claude-code start runs under a session the launcher chooses, takes
the prompt on stdin, and is bound only once its stream-json init event reports that session and its transcript is
under CLAUDE_CONFIG_DIR. A stand-in runs no host, and a native thread belongs to its app: neither is started.
`resume` runs the pinned wake tool with the bound wake profile, unchanged. `stop` signals the bound host's programs
that select the bound session and verified descendants in their groups. `status` reads the
records back.
ROOT is the owner's session and a native thread belongs to its app: the launcher starts and stops neither.

A launch record is not a lifecycle event and grants nothing: the journal has no provider-bridge
role. A clean start proves a process ran and reported a thread, not that the role will behave.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from typing import NamedTuple
import uuid

# Provisioned CLI actions must enter through the retained verifier before importing any peer module.
# A process-local marker prevents recursion; an environment variable cannot bypass verification.
if __name__ == "__main__" and getattr(sys, "_aegis_verified_runtime_entry", None) != str(Path(__file__).resolve()):
    import runpy
    early = argparse.ArgumentParser(add_help=False)
    guarded = False
    try:
        early.add_argument("--base")
        early.add_argument("command", nargs="?")
        parsed, _ = early.parse_known_args()
        if parsed.command in ("start", "resume") and parsed.base:
            base = Path(parsed.base)
            guarded = True
        if guarded:
            provision = base / "provision.json"
            setup = json.loads(provision.read_text(encoding="utf-8"))
            verifier = base / "runtime-source.py"
            if not verifier.is_file():
                raise ValueError("runtime source verifier is missing; reprovision into a new base through the existing handoff flow")
            loaded = runpy.run_path(str(verifier))
            loaded["run"](provision, Path(setup["source"]) / "tools" / Path(__file__).name, sys.argv[1:])
            sys.exit(0)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        sys.exit(2)

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import (Mailbox, endpoint_parts, fields, integer, read_json, require, safe_path, text,  # noqa: E402
                               timestamp)
from hierarchy_provision import CLAUDE, CODEX, NATIVE, SESSION, add_role, claude_start, codex_start  # noqa: E402
import hierarchy_hosts  # noqa: E402
import hierarchy_roles  # noqa: E402
from hierarchy_roles import role_name  # noqa: E402
from hierarchy_router import patient  # noqa: E402
from hierarchy_wake import stop_group  # noqa: E402
import hierarchy_runtime_source  # noqa: E402


SCHEMA = "aegis.hierarchy-launch/v1"
STATUS_SCHEMA = "aegis.hierarchy-launch-status/v1"
MAX_RECORDS = 10000
DEFAULT_START_TIMEOUT_SECONDS = 300
KILL_WAIT_SECONDS = 5.0
POLL_SECONDS = 0.05
# The mailbox writer lock is held only for a moment; a start already paid for should outlast that.
BIND_WAIT_SECONDS = 10.0
INTERRUPTS = tuple(getattr(signal, name) for name in ("SIGTERM", "SIGINT", "SIGHUP") if hasattr(signal, name))
INTERRUPTED = "the launcher was interrupted"
ROOT_START = "ROOT is the owner's session; bind it with add-role"
ROOT_STOP = "ROOT is the owner's session; the launcher does not stop it"
STAND_IN_START = "%s is a stand-in and runs no host"
NATIVE_START = "a native codex thread is started by its own app, not the launcher"
CLAUDE_HOME_UNSET = "a claude-code start needs CLAUDE_CONFIG_DIR set to the run's claude home"
CLAUDE_HOME_OWNERS = "CLAUDE_CONFIG_DIR is the owner's ~/.claude; a team run uses its own claude home"
CLAUDE_HOME_LINK = "%s is a symlink; a team run's claude home keeps its own files"
TRANSCRIPT_OUTSIDE = "the transcript for session %s is a symlink or lies outside CLAUDE_CONFIG_DIR %s: %s"
CODEX_START_KEYS = {"cwd", "reader_shell", "writable_roots", "tmpdir", "add_dirs", "model", "effort", "skip_git_repo_check"}
ADD_ROLE_KEYS = CODEX_START_KEYS | {"timeout_seconds", "source_repo", "kind", "lifecycle", "actor"}
START_HEADER = ("The Aegis launcher started this session for %s as %s. This turn comes from the operator who launched "
                "you; it is your role contract.")
START_FOOTER = "Reply READY. Act only when woken."
# The contract file for each role the launcher starts; a lane's role is its manifest kind. ROOT never starts here.
CONTRACTS = {"orchestrator": "orchestrator.md", "router": "router.md", "decider": "decider.md",
             "front-door": "front-door.md", "implementer": "lane.md", "reviewer": "reviewer.md",
             "integrator": "integrator.md"}
# reviewer.md and integrator.md open with "Follow the shared lane rules (lane.md)", so lane.md comes first. Its
# Assignments and Protocol checklist are the implementer's (11-field readiness, a required lane_check); each kind file
# restates both for its kind, so they are left out of lane.md rather than sent twice and contradicting each other.
SHARED_LANE_RULES = "lane.md"
SHARED_FOR = ("reviewer", "integrator")
KIND_SECTIONS = ("## Assignments", "## Protocol checklist")
# A contract marks a passage for one host family with a line `<!-- host:claude -->` or `<!-- host:codex -->` and ends
# it with `<!-- /host -->`. A start renders it for its host's family (hierarchy_hosts.family); START_HOST is the family
# of codex-cli, the host where no plan covers an endpoint.
CONTRACT_HOSTS = ("claude", "codex")
START_HOST = "codex"
HOST_OPEN = re.compile(r"<!-- host:([a-z]+) -->")
HOST_CLOSE = "<!-- /host -->"
HOST_LIKE = re.compile(r"<!--\s*/?\s*host\b", re.IGNORECASE)
FENCE_OPEN = re.compile(r" {0,3}(`{3,}|~{3,})(.*)$")


class Interrupted(Exception):
    """A signal arrived while the start ran."""


def interrupt(number, frame):
    raise Interrupted()


class Deferred:
    """Records an interrupt instead of raising it, so a bind already under way finishes its write."""

    def __init__(self):
        self.seen = False

    def __call__(self, number, frame):
        self.seen = True


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
        """An endpoint is resolved once the manifest knows it; from then on every outcome is recorded.

        The cap is checked here, once, before anything runs, so an outcome is never lost to it. It is
        approximate: record writes take no lock, and each concurrent invocation can add one record past it.
        """
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
        # Written whole under a name status does not read, then linked: a reader sees all of a record or none.
        temporary = folder / ("." + identifier + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write((json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
            # link fails on an existing name, as O_EXCL does.
            os.link(temporary, folder / (identifier + ".json"))
        finally:
            temporary.unlink()
        directory = os.open(folder, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return record

    def record(self, endpoint, identifier, action, state, *, host=None, session=None, generation=None, **details):
        return self.write(endpoint, identifier, {"schema": SCHEMA, "at": timestamp(), "action": action, "state": state,
                                                 "endpoint": endpoint, "host": host, "session": session,
                                                 "generation": generation, **details})

    def refuse(self, endpoint, identifier, action, error, **known):
        raise Refused(self.record(endpoint, identifier, action, "refused", error=error, **known))


def first_session(path):
    """The thread ID of the first thread.started event in the start's stdout log."""
    with open(path, "rb") as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if isinstance(event, dict) and event.get("type") == "thread.started":
                return event.get("thread_id")
    return None


def claude_session(path):
    """The session_id of the first stream-json init event in the start's stdout log."""
    with open(path, "rb") as stream:
        # Line by line, as first_session reads, so a start that floods its log is not read whole.
        init = hierarchy_hosts.claude_init(stream)
    return None if init is None else init["session_id"]


def run_start(argv, cwd, logs, timeout, deferred, stdin_path=None, read_session=first_session):
    """Return (session, exit_code, timed_out, error); this raises nothing an outcome record cannot hold.

    stdout goes to a file, not a pipe: a descendant that leaves the group can keep a pipe open forever,
    and nothing here may wait on it. A signal to the launcher stops the start's group instead of leaving
    it running unrecorded; on return every interrupt signal is ignored until the caller has written the
    record. The caller installs the raising handlers (see start); on the way out they become `deferred`,
    switched with the signals blocked so none lands between the two.

    stdin is stdin_path's file when given, not a pipe, for the same reason: feeding a pipe would mean
    writing while the start runs, and a start that never reads it would block that write once the pipe
    filled. read_session reads the session from the stdout log.
    """
    process, timed_out, error = None, False, None
    try:
        with open(logs["stdout"], "xb") as stdout, open(logs["stderr"], "xb") as stderr, \
                (nullcontext(subprocess.DEVNULL) if stdin_path is None else open(stdin_path, "rb")) as stdin:
            # Deferred across Popen: a signal raised after the fork but before `process` is assigned would leave
            # a child in its own session that nothing stops. Not a blocked mask, which the child would inherit
            # and so ignore stop_group's SIGTERM; exec resets handled signals to their defaults.
            spawning = Deferred()
            for number in INTERRUPTS:
                signal.signal(number, spawning)
            try:
                process = subprocess.Popen(argv, cwd=cwd, stdin=stdin, stdout=stdout, stderr=stderr,
                                           start_new_session=True)
            finally:
                for number in INTERRUPTS:
                    signal.signal(number, interrupt)
            if spawning.seen:
                raise Interrupted()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        # Also after a clean exit, so nothing the start left in its group keeps running unrecorded.
        stop_group(process)
    except Interrupted:
        error = INTERRUPTED
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        error = str(exc)
    finally:
        # Blocked only for the switch, in the launcher alone: no child is spawned while the mask is set.
        signal.pthread_sigmask(signal.SIG_BLOCK, INTERRUPTS)
        for number in INTERRUPTS:
            signal.signal(number, deferred)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, INTERRUPTS)
    if error is not None and process is not None:
        try:
            stop_group(process)
        except OSError as exc:
            error += "; stopping the start's process group failed: " + str(exc)
    try:
        session = read_session(logs["stdout"])
    except OSError as exc:
        session, error = None, error or str(exc)
    return session, None if process is None else process.returncode, timed_out, error


@contextmanager
def start_lock(launches, endpoint, identifier, host):
    """One start per endpoint at a time, so two starts cannot both pass the unbound check and both pay for a turn."""
    lock = launches.make(endpoint) / ".start.lock"
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        launches.refuse(endpoint, identifier, "start", "a start is already running for %s; inspect %s if none is"
                        % (endpoint, lock), host=host)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps({"pid": os.getpid(), "created_at": timestamp()}, sort_keys=True) + "\n").encode("utf-8"))
        yield
    finally:
        lock.unlink()


def host_view(text, host, origin):
    """The contract as a role on `host` reads it: blocks marked for another host and every marker line left out.

    A marker stands alone on its line and blocks do not nest. Anything else that looks like a marker refuses the
    contract, so a typo can never hand one host's instructions to another."""
    kept, opened, fence = [], None, None
    for number, line in enumerate(text.splitlines(), 1):
        # Markdown examples are literal text, including marker examples. A closing
        # fence must use the opening character and be at least as long.
        if fence is not None:
            if opened is None or opened[1] == host:
                kept.append(line)
            if re.fullmatch(r" {0,3}" + re.escape(fence[0]) + r"{%d,}\s*" % len(fence), line):
                fence = None
            continue
        opening = FENCE_OPEN.fullmatch(line)
        if opening and not (opening.group(1)[0] == "`" and "`" in opening.group(2)):
            fence = opening.group(1)
            if opened is None or opened[1] == host:
                kept.append(line)
            continue
        marker = HOST_OPEN.fullmatch(line.strip())
        if marker:
            if opened is not None:
                raise ValueError("unbalanced host markers in %s: line %d opens a block inside the one opened at line %d"
                                 % (origin, number, opened[0]))
            require(marker.group(1) in CONTRACT_HOSTS,
                    "invalid host marker in %s: line %d names an unknown host: %s" % (origin, number, marker.group(1)))
            opened = (number, marker.group(1))
        elif line.strip() == HOST_CLOSE:
            require(opened is not None,
                    "unbalanced host markers in %s: line %d closes a block that is not open" % (origin, number))
            opened = None
        else:
            require(HOST_LIKE.search(line) is None,
                    "invalid host marker in %s: line %d: a host marker must stand alone on its line" % (origin, number))
            if opened is None or opened[1] == host:
                kept.append(line)
    if opened is not None:
        raise ValueError("unbalanced host markers in %s: the block opened at line %d is not closed"
                         % (origin, opened[0]))
    return tidy(kept)


def tidy(lines):
    # A dropped block or section leaves its blank lines behind; Markdown reads a run of them as one.
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def without_sections(text, headings):
    """text without each section headed by one of `headings`, up to the next level-1 or level-2 heading."""
    kept, skipping = [], False
    for line in text.splitlines():
        if line.startswith(("# ", "## ")):
            skipping = line.strip() in headings
        if not skipping:
            kept.append(line)
    return tidy(kept)


def start_prompt(launches, endpoint, family=START_HOST):
    """(prompt, contracts) for the start turn, rendered for the host family. contracts lists {path, sha256} for each
    file the prompt carries, in order; the last is the role's own.

    The contract goes inline: the start turn has no MCP servers and may run in a cwd that cannot see the
    source. It is read from the pinned source, beside the mailbox code the role's adapter runs, so the
    fields it teaches are the ones that adapter checks.
    """
    role = role_name(endpoint, launches.mailbox.endpoint(endpoint).get("kind"))
    folder = Path(launches.setup["source"]) / "tools" / "hierarchy_templates" / "roles"
    path = folder / CONTRACTS.get(role, "")
    require(role in CONTRACTS and path.is_file(), "no role contract for %s: %s" % (role, path))
    files = ([folder / SHARED_LANE_RULES] if role in SHARED_FOR else []) + [path]
    parts, contracts = [], []
    for each in files:
        require(each.is_file(), "no role contract for %s: %s" % (role, each))
        raw = each.read_bytes()
        parts.append(host_view(raw.decode("utf-8"), family, each))
        contracts.append({"path": str(each), "sha256": hashlib.sha256(raw).hexdigest()})
    if len(files) > 1:
        lines = parts[-1].splitlines()
        require(all(heading in lines for heading in KIND_SECTIONS),
                "%s must restate lane.md's %s for its kind" % (path, " and ".join(KIND_SECTIONS)))
        headings = KIND_SECTIONS + (("## Writing rules",) if role == "reviewer" else ())
        parts[0] = without_sections(parts[0], headings)
    prompt = "\n\n".join((START_HEADER % (endpoint, role), *parts, START_FOOTER))
    return prompt, contracts


def start(launches, request_path):
    hierarchy_runtime_source.verify(launches.setup, launches.base)
    request = read_json(safe_path(text(request_path, "request")))
    require(isinstance(request, dict), "expected a JSON object")
    endpoint = launches.resolve(request.get("endpoint"))
    identifier = launches.new_id()
    plan, host, stand_in = start_host(launches, endpoint, identifier)
    # Installed before the lock is taken and kept until the outcome is recorded: a signal with its default
    # action would skip start_lock's finally and leave the endpoint refusing every later start.
    previous = {number: signal.getsignal(number) for number in INTERRUPTS}
    try:
        for number in INTERRUPTS:
            signal.signal(number, interrupt)
        with start_lock(launches, endpoint, identifier, host):
            return locked_start(launches, request, endpoint, identifier, plan, host, stand_in)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def start_host(launches, endpoint, identifier):
    """(plan, host, stand-in) for the endpoint: the plan's host, or codex-cli where no plan covers it.

    Read before the start lock, so that even a lock refusal names the host; a plan that cannot be read is refused
    here, before anything runs, rather than after a start already paid for meets the same refusal in add-role.
    """
    try:
        plan = hierarchy_hosts.read_plan(launches.base)
    # RecursionError: a deeply nested file defeats the JSON parser, and its refusal must be recorded like any other.
    except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
        launches.refuse(endpoint, identifier, "start", str(exc))
    host, stand_in = hierarchy_hosts.plan_host(plan, endpoint)
    return plan, CODEX if host is None else host, stand_in


def claude_home():
    """The run's claude home from CLAUDE_CONFIG_DIR, which the start inherits. Never a default: without it a real
    claude would use ~/.claude, the owner's own login, history and settings."""
    home = os.environ.get("CLAUDE_CONFIG_DIR")
    require(home, CLAUDE_HOME_UNSET)
    # Relative, it would resolve against the start's cwd there and the launcher's here.
    require(os.path.isabs(home) and os.path.isdir(home),
            "CLAUDE_CONFIG_DIR must be an absolute path to an existing folder: " + home[:256])
    import pwd  # POSIX only, like every start; imported here so status still loads on any platform.
    try:
        # From the password database, not HOME: a changed HOME must not hide the owner's real folder.
        owner = os.path.realpath(os.path.join(pwd.getpwuid(os.getuid()).pw_dir, ".claude"))
    except KeyError:
        raise ValueError("cannot find the owner's home folder, so ~/.claude cannot be kept out") from None
    # By realpath, so a link to the owner's folder, or to a folder inside it, is refused too.
    found = os.path.realpath(home)
    require(found != owner and not found.startswith(owner.rstrip(os.sep) + os.sep), CLAUDE_HOME_OWNERS)
    # A separate home whose entries link elsewhere, such as projects into the owner's history, would put the start's
    # files there. Every entry of the home counts, not a list: no real login has shown which ones a start writes
    # (ADR T2(a) §3). So do the project folders a transcript is written into. confirmed() checks the transcript too,
    # for a link made after this look.
    for folder in (home, os.path.join(home, "projects")):
        if folder != home and (os.path.islink(folder) or not os.path.isdir(folder)):
            continue
        with os.scandir(folder) as entries:
            linked = sorted(entry.path for entry in entries if entry.is_symlink())
        if linked:
            raise ValueError(CLAUDE_HOME_LINK % linked[0])
    return home


def confirmed(reported, chosen, home, error):
    """(session, error): the chosen session once the init event reported it and its transcript is a regular file
    inside the run's home, else None.

    Either check failing means no session to bind: a different id means the host did not run --session-id, and
    with no transcript under the run's home a later --resume finds no conversation.
    """
    if reported is None:
        return None, error
    problem = None
    if reported != chosen:
        problem = "the start reported session %s, not the session the launcher chose: %s" % (str(reported)[:128], chosen)
    else:
        try:
            found = hierarchy_hosts.transcripts(CLAUDE, home, chosen)
            # A regular file inside the home itself: the glob follows links, and a transcript that resolves elsewhere
            # is in someone else's history, not the run's.
            inside = os.path.realpath(home).rstrip(os.sep) + os.sep
            kept = [path for path in found
                    if not path.is_symlink() and path.is_file() and os.path.realpath(path).startswith(inside)]
            if not found:
                problem = "no transcript for session %s under CLAUDE_CONFIG_DIR %s" % (chosen, home)
            elif not kept:
                problem = TRANSCRIPT_OUTSIDE % (chosen, home, found[0])
        except (OSError, ValueError) as exc:
            problem = "reading the start's transcript failed: " + str(exc)
    if problem is None:
        return reported, error
    return None, problem if error is None else error + "; " + problem


def locked_start(launches, request, endpoint, identifier, plan, host, stand_in):
    known = {"host": host}
    try:
        fields(request, {"endpoint"}, ADD_ROLE_KEYS | {"start_timeout_seconds"})
        timeout = integer(request.get("start_timeout_seconds", DEFAULT_START_TIMEOUT_SECONDS), "start_timeout_seconds",
                          maximum=3600)
        require(endpoint_parts(endpoint)[1] != "root", ROOT_START)
        require(launches.binding(endpoint) is None, "endpoint is already bound; resume it or hand it off")
        require(not stand_in, STAND_IN_START % endpoint)
        require(host != NATIVE, NATIVE_START)
        if plan is not None:
            # The start's enforcement point (ADR T2(a) "Enforcement points"): qualified before a turn is paid for.
            entry = hierarchy_roles.role(endpoint, launches.mailbox.endpoint(endpoint).get("kind"))
            hierarchy_hosts.require_binding(plan, endpoint, host, hierarchy_roles.writer(entry))
        if host == CLAUDE:
            home = claude_home()
        prompt, contracts = start_prompt(launches, endpoint, hierarchy_hosts.family(host))
        options = {key: request[key] for key in CODEX_START_KEYS if key in request}
        if host == CLAUDE:
            # Chosen here so that the start can be checked against it; Codex picks its own.
            session = str(uuid.uuid4())
            # Codex-only options go along so that claude_start refuses them by name.
            started = claude_start({"base": str(launches.base), "endpoint": endpoint, "session": session, **options})
            argv = started["start_argv"]
        else:
            started = codex_start({"base": str(launches.base), "endpoint": endpoint, **options})
            argv = started["start_argv"] + [prompt]
        folder = launches.make(endpoint, "logs")
        via = {}
        if host == CLAUDE:
            # Kept beside the logs as the exact bytes the start read.
            prompt_file = folder / (identifier + ".prompt")
            with open(prompt_file, "xb") as stream:
                stream.write(prompt.encode("utf-8"))
            via = {"prompt_via": "stdin", "prompt_file": str(prompt_file)}
    except Interrupted:
        launches.refuse(endpoint, identifier, "start", INTERRUPTED, **known)
    except (ValueError, OSError, TypeError, KeyError) as exc:
        launches.refuse(endpoint, identifier, "start", str(exc), **known)
    logs = {name: str(folder / (identifier + "." + name)) for name in ("stdout", "stderr")}
    deferred = Deferred()
    if host == CLAUDE:
        reported, exit_code, timed_out, error = run_start(argv, started["cwd"], logs, timeout, deferred,
                                                          stdin_path=prompt_file, read_session=claude_session)
        session, error = confirmed(reported, session, home, error)
    else:
        session, exit_code, timed_out, error = run_start(argv, started["cwd"], logs, timeout, deferred)
    # contract keeps its meaning (the role's own file); contracts lists every file the prompt carries.
    details = {"argv": argv, "cwd": started["cwd"], "contract": contracts[-1], "contracts": contracts,
               "start_timeout_seconds": timeout, "exit_code": exit_code, "timed_out": timed_out, **via}
    if not (isinstance(session, str) and SESSION.fullmatch(session)):
        error = error or (None if session is None else "the start reported an invalid session")
        record = launches.record(endpoint, identifier, "start", "failed_to_start", **known, **details,
                                 **({"error": error} if error else {}))
        return 3, {**record, "log": logs}
    known["session"] = session
    if error or exit_code != 0 or timed_out:
        record = launches.record(endpoint, identifier, "start", "start_incomplete", **known, **details,
                                 **({"error": error} if error else {}))
        return 3, {**record, "log": logs}

    def bind():
        # Checked before each attempt, so an interrupt ends the busy wait; an add_role already running finishes.
        if deferred.seen:
            raise Interrupted()
        return add_role({"base": str(launches.base), "endpoint": endpoint, "host": host, "session": session,
                         **{key: request[key] for key in ADD_ROLE_KEYS if key in request}})
    try:
        bound = patient(bind, BIND_WAIT_SECONDS)
    except Interrupted:
        # The turn ran and its session is good: add-role with this session finishes the bind.
        record = launches.record(endpoint, identifier, "start", "start_incomplete", **known, **details, error=INTERRUPTED)
        return 3, {**record, "log": logs}
    except (ValueError, OSError, TypeError, KeyError) as exc:
        # Still busy: the session is good, so the caller can bind it with add-role instead of starting again.
        state = "bind_busy" if isinstance(exc, ValueError) and "busy" in str(exc) else "bind_refused"
        record = launches.record(endpoint, identifier, "start", state, **known, **details, error=str(exc))
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
    hierarchy_runtime_source.verify(launches.setup, launches.base)
    endpoint = launches.resolve(endpoint)
    identifier = launches.new_id()
    known, profile = bound_session(launches, endpoint, identifier, "resume")
    if known["host"] == NATIVE:
        launches.refuse(endpoint, identifier, "resume", "a native thread is resumed by its own app, not the launcher", **known)
    if not profile.is_file():
        launches.refuse(endpoint, identifier, "resume", "no wake profile for the current binding: " + str(profile), **known)
    argv = [sys.executable, *hierarchy_runtime_source.entry_args(launches.setup, "hierarchy_wake.py"),
            "--root", launches.setup["mailbox_root"], "--delivery-dir", launches.setup["delivery_dir"],
            "--endpoint", endpoint, "--profile", str(profile)] + (["--dry-run"] if dry_run else [])
    # No outer timeout: the wake tool bounds every phase itself, and killing it mid-turn would leave the
    # session running and its wake marker held.
    try:
        ran = subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        launches.refuse(endpoint, identifier, "resume", str(exc), **known)
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


class ProcessSnapshot(NamedTuple):
    pid: int
    pgid: int
    state: str
    uid: int
    start_time: str
    cmdline: bytes
    argv: tuple
    ppid: int
    euid: int


class ProcessCensus(list):
    def __init__(self, rows, argv_boundaries):
        super().__init__(rows)
        self.argv_boundaries = argv_boundaries


def ps_census(pid=None):
    command = ["ps", "-p", str(pid)] if pid is not None else ["ps", "-ax"]
    shown = subprocess.run([*command, "-ww", "-o", "pid=,pgid=,ppid=,ruid=,uid=,stat=,lstart=,args="],
                           capture_output=True, text=True, timeout=10)
    require(shown.returncode == 0 or (pid is not None and shown.returncode == 1), "process census failed")
    rows = []
    for line in shown.stdout.splitlines():
        words = line.split(None, 11)
        if len(words) < 12 or not all(word.isdigit() for word in words[:5]):
            continue
        # ps is not shell-escaped: quotes are literal, and paths with spaces cannot be recovered here.
        # Linux uses the NUL-separated /proc argv instead; lstart is the fallback's coarser birth timestamp.
        rows.append(ProcessSnapshot(int(words[0]), int(words[1]), words[5], int(words[3]),
                                    " ".join(words[6:11]), os.fsencode(words[11]), tuple(words[11].split()),
                                    int(words[2]), int(words[4])))
    return rows


def read_process(pid, argv_boundaries="proven"):
    """Read a process snapshot, also used immediately before signalling it."""
    if argv_boundaries == "unproven":
        return next(iter(ps_census(pid)), None)
    folder = Path("/proc") / str(pid)
    try:
        fields = (folder / "stat").read_bytes().rpartition(b")")[2].split()
        status = (folder / "status").read_bytes()
        cmdline = (folder / "cmdline").read_bytes()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        # A process can end during the census; inaccessible argv cannot establish ownership.
        return None
    if not cmdline or len(fields) < 20 or not all(fields[index].isdigit() for index in (1, 2, 19)):
        return None
    uids = next((line.split()[1:] for line in status.splitlines() if line.startswith(b"Uid:")), [])
    uid, euid = (int(uids[0]), int(uids[1])) if len(uids) >= 2 and all(v.isdigit() for v in uids[:2]) else (-1, -1)
    arguments = cmdline.split(b"\0")
    if arguments[-1] == b"":
        arguments.pop()
    return ProcessSnapshot(pid, int(fields[2]), fields[0].decode("ascii"), uid, fields[19].decode("ascii"),
                           cmdline, tuple(os.fsdecode(a) for a in arguments), int(fields[1]), euid)


def process_census(session):
    """Retain birth time and exact Linux argv; ps is an explicitly unproven fallback without /proc."""
    proc = Path("/proc")
    if not proc.is_dir():
        return ProcessCensus(ps_census(), "unproven")
    rows = (read_process(int(folder.name)) for folder in proc.iterdir() if folder.name.isdigit())
    return ProcessCensus((row for row in rows if row is not None), "proven")


def names_session(row, session):
    # Equals selectors still carry a whole session value, never an arbitrary substring of a prompt.
    return any(word == session or word.partition("=")[2] == session for word in row.argv)


def our_uid(row):
    return row.uid == row.euid == os.geteuid()


def owns_process(row, session, host, boundaries):
    return our_uid(row) and hierarchy_hosts.matches_session(host, row.argv, session, boundaries)


def session_processes(session, excluded, host=CODEX, unowned=None, observed=None):
    """(pid, pgid) of live processes with our UID and the bound host's session selector."""
    hierarchy_hosts.entrypoints(host)
    found = []
    census = process_census(session)
    if observed is not None:
        observed.update(census={row.pid: row for row in census}, argv_boundaries=census.argv_boundaries)
    for row in census:
        # A zombie has already ended; it only waits for its parent to collect it.
        if row.pid in excluded or row.state.startswith("Z") or not names_session(row, session):
            continue
        # A diagnostic command naming the session must never be signalled.
        if owns_process(row, session, host, census.argv_boundaries):
            found.append((row.pid, row.pgid))
        elif unowned is not None:
            unowned.append(row.pid)
    return found


def unchanged_process(expected, boundaries, session, host, unowned, require_host=True, parent=None):
    current = read_process(expected.pid, boundaries)
    if current is None or current.state.startswith("Z"):
        return False
    if (current.start_time != expected.start_time or current.cmdline != expected.cmdline or
            current.pgid != expected.pgid or not our_uid(current) or
            (current.uid, current.euid) != (expected.uid, expected.euid) or
            (parent is not None and current.ppid != parent) or
            (require_host and not owns_process(current, session, host, boundaries))):
        # A replacement PID, or an unrelated changed group member, is not a process naming this session.
        if current.start_time == expected.start_time and names_session(current, session):
            unowned.append(current.pid)
        return False
    return True


def signal_process(chain, number, boundaries, session, host, unowned):
    handles = {}
    try:
        for expected in chain:
            if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
                try:
                    # Pin every process in the parent chain before rechecking it.
                    handles[expected.pid] = os.pidfd_open(expected.pid)
                except OSError as exc:
                    if exc.errno == errno.ESRCH:
                        return False
                    # Older kernels and seccomp may reject pidfds while ordinary signalling still works.
        for index in reversed(range(len(chain))):
            expected = chain[index]
            parent = chain[index + 1].pid if index + 1 < len(chain) else None
            if not unchanged_process(expected, boundaries, session, host, unowned, parent is None, parent):
                return False
            if parent is not None and hierarchy_hosts.selects_other_session(expected.argv, session):
                return False
        expected, handle = chain[0], handles.get(chain[0].pid)
        if handle is None:
            os.kill(expected.pid, number)
        else:
            signal.pidfd_send_signal(handle, number)
        return "sent"
    except ProcessLookupError:
        return False
    except PermissionError:
        # Retain the attempted host PID so a live process denied by the OS still produces stop_failed.
        return "denied"
    finally:
        for handle in handles.values():
            os.close(handle)


def descendant_chain(member, census, owners, session):
    chain, seen = [], set()
    while member.pid not in seen:
        seen.add(member.pid)
        chain.append(member)
        if member.pid in owners:
            return chain
        if not our_uid(member) or hierarchy_hosts.selects_other_session(member.argv, session):
            return []
        member = census.get(member.ppid)
        if member is None:
            return []
    return []


def process_depth(member, census):
    seen = set()
    while member.pid not in seen:
        seen.add(member.pid)
        member = census.get(member.ppid)
        if member is None:
            break
    return len(seen)


def signal_all(found, number, observed, session, host, unowned, attempted=None):
    census, boundaries = observed["census"], observed["argv_boundaries"]
    attempted = set() if attempted is None else attempted
    pids = {pid for pid, _ in found}
    groups = {pgid for _, pgid in found if pgid != os.getpgrp()}
    targets = [[census[pid]] for pid in pids]
    for member in census.values():
        if member.pid not in pids and member.pid not in unowned and member.pgid in groups:
            chain = descendant_chain(member, census, pids, session)
            if chain:
                targets.append(chain)
    # Children go first so their owned ancestors can still be rechecked at each signal.
    for chain in sorted(targets, key=lambda rows: process_depth(rows[0], census), reverse=True):
        result = signal_process(chain, number, boundaries, session, host, unowned)
        if result and chain[0].pid in pids:
            attempted.add(chain[0].pid)
    return attempted


def gone_within(session, excluded, pids, seconds, host, observed, unowned):
    deadline = time.monotonic() + seconds
    while True:
        left = {pid for pid in pids if pid not in excluded and unchanged_process(
            observed["census"][pid], observed["argv_boundaries"], session, host, unowned)}
        if not left or time.monotonic() >= deadline:
            return not left
        time.sleep(POLL_SECONDS)


def stop(launches, endpoint, grace):
    endpoint = launches.resolve(endpoint)
    identifier = launches.new_id()
    if not (type(grace) is int and 0 <= grace <= 60):
        launches.refuse(endpoint, identifier, "stop", "invalid grace_seconds")
    known, profile = bound_session(launches, endpoint, identifier, "stop")
    if endpoint_parts(endpoint)[1] == "root":
        launches.refuse(endpoint, identifier, "stop", ROOT_STOP, **known)
    if known["host"] == NATIVE:
        # Its thread lives inside the shared app-server, so no process names it; signalling would only cut its mail.
        launches.refuse(endpoint, identifier, "stop", "a native thread is stopped by its own app, not the launcher", **known)
    try:
        background = profile.is_file() and read_json(profile).get("mode") == "background"
    except (ValueError, OSError, AttributeError) as exc:
        launches.refuse(endpoint, identifier, "stop", str(exc), **known)
    if background:
        launches.refuse(endpoint, identifier, "stop",
                        "a background claude session stops through claude stop; use the wake tool's control", **known)
    signalled = False
    try:
        excluded = ancestors()
        unowned, observed = [], {}
        found = session_processes(known["session"], excluded, known["host"], unowned, observed)
        marker = {"wake_marker_present": launches.mailbox.wake_marker(endpoint).exists(), "grace_seconds": grace}
        if observed["argv_boundaries"] == "unproven":
            marker["argv_boundaries"] = "unproven"
        pids, stopped = set(), True
        if found:
            signalled = True
            signal_all(found, signal.SIGTERM, observed, known["session"], known["host"], unowned, pids)
            stopped = gone_within(known["session"], excluded, pids, grace, known["host"], observed, unowned)
            if not stopped:
                signal_all([pair for pair in found if pair[0] in pids], signal.SIGKILL, observed,
                           known["session"], known["host"], unowned)
                stopped = gone_within(known["session"], excluded, pids, KILL_WAIT_SECONDS, known["host"], observed, unowned)
            # The marker belongs to the wake that made it; whoever inspects it decides whether that turn has ended.
            marker["wake_marker_present"] = launches.mailbox.wake_marker(endpoint).exists()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        if not signalled:
            launches.refuse(endpoint, identifier, "stop", str(exc), **known)
        # Signals were already sent, so "refused" would claim nothing was done.
        if unowned:
            marker["unowned_pids"] = sorted(set(unowned))
        return 3, launches.record(endpoint, identifier, "stop", "stop_failed", **known, pids=sorted(pids),
                                  error=str(exc), **marker)
    if unowned:
        marker["unowned_pids"] = sorted(set(unowned))
    if not pids:
        return 0, launches.record(endpoint, identifier, "stop", "not_running", **known, pids=[], **marker)
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
                      "last": None, "records": len(paths)}
        if paths:
            # One bad record must not hide every endpoint's status.
            try:
                rows[name]["last"] = read_json(paths[-1])
            except (OSError, ValueError, RecursionError):
                rows[name]["unreadable"] = str(paths[-1])
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
