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
import select
import signal
import stat
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
from hierarchy_mailbox import (Mailbox, endpoint_parts, fields, integer, read_json, require, safe_path, strict_json, text,  # noqa: E402
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
STOP_EXIT_PROOFS = ("original_pidfd_exit", "qualified_namespace_ESRCH", "matching_birth_zombie",
                    "matching_partial_birth_zombie", "confirmed_instance_exit", "signal_ESRCH")
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


class ProcessObservation(NamedTuple):
    kind: str
    pid: int
    snapshot: object = None
    partial: object = None
    reason: str = ""
    proof: str = ""


class ProcessCensus(list):
    def __init__(self, rows, argv_boundaries, unavailable=None):
        super().__init__(rows)
        self.argv_boundaries = argv_boundaries
        self.unavailable = unavailable or {}


@contextmanager
def directory_descriptor(path, create=False, durable_from=None):
    """Pin every directory in the chain. A pathname check cannot protect a subsequent open."""
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "invalid directory path")
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current = current / part
            if create:
                made = False
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                else:
                    made = True
                if made or (durable_from is not None and
                            (current == durable_from or durable_from in current.parents)):
                    # Also repeat initialization after a crash which made the entry but never synced it.
                    os.fsync(fd)
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


@contextmanager
def stop_endpoint_lock(root, endpoint):
    """Shared with handoff. Lock order: mailbox writer (handoff only), endpoint, custody.

    Bindings already have a directory. Locking that inode creates no file for an otherwise no-op stop.
    Direct mailbox bind/draft callers are outside this serialization contract.
    """
    import fcntl

    endpoint_parts(endpoint)
    with directory_descriptor(Path(root) / "bindings" / endpoint) as fd:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("stop custody endpoint is busy: " + endpoint) from exc
        yield


def custody_refusal(base, endpoint, cause=None):
    import shlex

    path = Path(base) / "launches" / quoted(endpoint) / ".stop-custody" / "state.json"
    command = shlex.join(["hierarchy_launcher.py", "--base", str(base), "stop", "--endpoint", endpoint])
    if cause is None:
        return "stop custody unresolved for %s; run %s" % (endpoint, command)
    return ("stop custody unavailable for %s: %s; inspect %s; manual reconciliation: preserve this file and "
            "its process/boot evidence, have the owner verify every original instance has exited, then archive "
            "with %s; retry %s" % (endpoint, cause, path, shlex.join([
                "mv", "-i", "--", str(path), str(Path(base) / ("reconciled-stop-custody-" + quoted(endpoint) + ".json"))]),
                                   command))


def require_resolved_custody(base, endpoint):
    require(not unresolved_stop_custody(base, endpoint), custody_refusal(base, endpoint))


class StopCustody:
    """Endpoint-local, pre-effect custody. A lost launcher must not lose a possibly signalled orphan.

    Descriptors cannot survive a new invocation. Recovery therefore uses the original boot/birth/raw/UID
    evidence and retains the numeric-PID residual race; an observed replacement latches loss of identity.
    The lock serializes read/merge/write, and the hidden subdirectory is outside immutable launch records.
    """

    def __init__(self, launches, endpoint, binding, create=True):
        self.base, self.endpoint = launches.base, endpoint
        self.folder = safe_path(launches.folder(endpoint) / ".stop-custody")
        self.path, self.binding = self.folder / "state.json", binding
        self.fd, self.directory_fd = None, None
        self.entered = False

    def __enter__(self):
        self.entered = True
        if self.folder.exists():
            self.lock()
        return self

    def lock(self):
        # Only the POSIX stop writer needs flock; read-only consumers must remain importable without it.
        import fcntl

        with directory_descriptor(self.folder) as directory:
            self.fd = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            self.private(os.fstat(self.fd))
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError("stop custody is busy") from exc
            return self
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise

    def __exit__(self, *unused):
        if self.fd is not None:
            os.close(self.fd)
        if self.directory_fd is not None:
            os.close(self.directory_fd)

    @staticmethod
    def private(info):
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "invalid stop custody file")

    @staticmethod
    def boot():
        path = Path("/proc/sys/kernel/random/boot_id")
        return path.read_text().strip() if Path("/proc").is_dir() else None

    @staticmethod
    def encode(facts):
        return {key: value.hex() if key == "cmdline" else value for key, value in facts.items()}

    @staticmethod
    def decode(facts):
        require(isinstance(facts, dict), "invalid stop custody evidence")
        allowed = set(ProcessSnapshot._fields) | {"coherent_birth", "exit_observed"}
        require(facts.keys() <= allowed, "unexpected stop custody evidence")
        facts = dict(facts)
        for key, value in facts.items():
            if key in ("pid", "pgid", "ppid", "uid", "euid"):
                require(type(value) is int and value >= 0, "invalid stop custody " + key)
            elif key in ("coherent_birth", "exit_observed"):
                require(type(value) is bool, "invalid stop custody " + key)
            elif key == "argv":
                require(isinstance(value, list) and all(isinstance(word, str) and "\0" not in word for word in value),
                        "invalid stop custody argv")
                facts[key] = tuple(value)
            elif key == "cmdline":
                require(isinstance(value, str) and re.fullmatch(r"(?:[0-9a-f]{2})*", value) is not None,
                        "invalid stop custody cmdline")
                facts[key] = bytes.fromhex(value)
            elif key == "state":
                require(isinstance(value, str) and value in tuple("RSDZTtXxKWPI") and len(value) == 1,
                        "invalid stop custody state")
            elif key == "start_time":
                require(isinstance(value, str) and re.fullmatch(r"[0-9]+", value) is not None,
                        "invalid stop custody start_time")
            else:
                require(isinstance(value, str) and value and "\0" not in value, "invalid stop custody " + key)
        return facts

    def read(self):
        try:
            return self.read_evidence()
        except (ValueError, OSError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
            raise ValueError(custody_refusal(self.base, self.endpoint, exc)) from exc

    def read_evidence(self):
        """Read and validate without creating a directory/lock or interpreting unreadability as absence."""
        try:
            with directory_descriptor(self.folder) as directory:
                directory_info = os.fstat(directory)
                require(directory_info.st_uid == os.geteuid() and stat.S_IMODE(directory_info.st_mode) == 0o700,
                        "invalid stop custody directory")
                try:
                    fd = os.open("state.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                    try:
                        info = os.fstat(fd)
                        self.private(info)
                        with os.fdopen(os.dup(fd), "rb") as stream:
                            raw = stream.read(262145)
                        require(len(raw) <= 262144 and raw.isascii(), "invalid stop custody bytes: bounded ASCII required")
                        require(self.identity(os.fstat(fd)) == self.identity(info), "stop custody changed while reading")
                    finally:
                        os.close(fd)
                finally:
                    # Missing state is absence only when the pinned directory remained unchanged too.
                    require(self.identity(os.fstat(directory)) == self.identity(directory_info),
                            "stop custody directory changed while reading")
        except FileNotFoundError:
            return None
        saved = strict_json(raw.decode("ascii"))
        fields(saved, ("schema", "binding", "boot", "active", "entries", "coverage"))
        require(saved["schema"] == "aegis.hierarchy-stop-custody/v1" and type(saved["active"]) is bool and
                isinstance(saved["entries"], list) and len(saved["entries"]) <= MAX_RECORDS and
                saved["coverage"] in (None, "argv_boundaries_unavailable"), "invalid stop custody")
        fields(saved["binding"], ("host", "session", "generation"))
        require(saved["binding"]["host"] in hierarchy_hosts.TEAM_HOSTS and
                isinstance(saved["binding"]["session"], str) and SESSION.fullmatch(saved["binding"]["session"]),
                "invalid stop custody binding")
        integer(saved["binding"]["generation"], "stop custody generation")
        entries, seen = [], set()
        for entry in saved["entries"]:
            fields(entry, ("pid", "snapshot", "partial", "attempted", "blocked", "identity_lost", "resolved"))
            pid = entry["pid"]
            require(type(pid) is int and pid > 0 and pid not in seen, "invalid stop custody pid")
            seen.add(pid)
            require(all(type(entry[key]) is bool for key in ("attempted", "blocked", "identity_lost")) and
                    (entry["resolved"] is None or entry["resolved"] in STOP_EXIT_PROOFS), "invalid stop custody state")
            facts = self.decode(entry["snapshot"]) if entry["snapshot"] is not None else None
            if facts is not None:
                require(facts.keys() == set(ProcessSnapshot._fields) and facts["pid"] == pid,
                        "invalid stop custody snapshot")
            require(not entry["attempted"] or facts is not None, "attempted stop custody has no identity")
            entries.append((entry, ProcessSnapshot(**facts) if facts is not None else None,
                            self.decode(entry["partial"])))
        # Inactive evidence is still validated. A corrupt file is never an absent configuration.
        if not saved["active"]:
            require(saved["coverage"] is None and all(entry["resolved"] for entry, _, _ in entries),
                    "inactive stop custody has unresolved evidence")
        boot = self.boot()
        require(isinstance(saved["boot"], str) and saved["boot"] and boot is not None,
                "stop custody boot identity unavailable")
        if saved["boot"] != boot:
            require(not saved["active"], "stop custody boot changed with active evidence: " + str(self.path))
        else:
            for entry, expected, partial in entries:
                if not entry["resolved"]:
                    continue
                current = read_process(entry["pid"])
                if current.kind == "CONFIRMED_ABSENT" and not entry["identity_lost"]:
                    continue
                row = current.snapshot if current.kind == "PRESENT" else None
                birth = expected.start_time if expected is not None else partial.get("start_time")
                require(row is not None and birth == row.start_time and row.state.startswith("Z"),
                        "resolved stop custody lacks physical exit proof for pid %d" % entry["pid"])
        return saved, entries

    def restore(self, observed, attempted):
        retained = self.read()
        if retained is None:
            return
        saved, entries = retained
        if not saved["active"]:
            return
        require(saved["binding"] == self.binding, "unresolved stop custody belongs to another binding")
        for entry, expected, partial in entries:
            pid = entry["pid"]
            current = observed["census"].get(pid)
            observed["candidates"][pid] = expected
            observed["initial_unavailable"][pid] = partial
            if entry["attempted"]:
                attempted.add(pid)
            for key in ("blocked", "identity_lost"):
                if entry[key]:
                    observed[key].add(pid)
            if entry["resolved"]:
                observed["resolved"][pid] = entry["resolved"]
                observed["unresolved"].pop(pid, None)
            else:
                unresolved(observed, pid, "recovery", "original_instance_pending")
            if expected is not None and current is not None and (
                    (current.start_time, current.cmdline, current.uid, current.euid) !=
                    (expected.start_time, expected.cmdline, expected.uid, expected.euid) or
                    (not entry["attempted"] and current.pgid != expected.pgid)):
                if current.start_time != expected.start_time:
                    observed["identity_lost"].add(pid)
                observed["blocked"].add(pid)
                observed["resolved"].pop(pid, None)
                unresolved(observed, pid, "recovery", "original_instance_replaced")
        if saved["coverage"]:
            observed["coverage"] = saved["coverage"]

    def save(self, observed, attempted, active=True):
        entries = []
        for pid, row in sorted(observed["candidates"].items()):
            entries.append(dict(pid=pid, snapshot=self.encode(row._asdict()) if row is not None else None,
                                partial=self.encode(observed["initial_unavailable"].get(pid, {})),
                                attempted=pid in attempted, blocked=pid in observed["blocked"],
                                identity_lost=pid in observed["identity_lost"], resolved=observed["resolved"].get(pid)))
        data = dict(schema="aegis.hierarchy-stop-custody/v1", binding=self.binding, boot=self.boot(), active=active,
                    entries=entries, coverage=observed.get("coverage"))
        raw = (json.dumps(data, sort_keys=True) + "\n").encode("utf-8")
        require(len(entries) <= MAX_RECORDS and len(raw) <= 262144, "stop custody exceeds evidence limit")
        # No acknowledged-byte cache: every request here is an actual transition or pre-effect barrier.
        with directory_descriptor(self.folder, create=True,
                                  durable_from=self.folder.parent.parent if self.directory_fd is None else None) as directory:
            info = os.fstat(directory)
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                    "invalid stop custody directory")
            if self.directory_fd is None:
                # v1 has no durable-parent receipt. Revalidate initialization once per writer, including
                # recovery from old/failed writers; pin the inode through every subsequent checkpoint.
                self.directory_fd = os.dup(directory)
            else:
                require(self.directory_identity(info) == self.directory_identity(os.fstat(self.directory_fd)),
                        "stop custody directory changed during durable commit")
        if self.entered and self.fd is None:
            self.lock()
        temporary = self.folder / ("." + uuid.uuid4().hex + ".tmp")
        fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
                written = os.fstat(stream.fileno())
            os.replace(temporary, self.path)
            published = self.commit_identity()
            require(published[:3] == (written.st_dev, written.st_ino, len(raw)),
                    "stop custody changed during durable commit")
            directory = os.open(self.folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                require(self.directory_identity(os.fstat(directory)) ==
                        self.directory_identity(os.fstat(self.directory_fd)),
                        "stop custody directory changed during durable commit")
                os.fsync(directory)
            finally:
                os.close(directory)
            require(self.commit_identity() == published and self.read_committed_bytes(published) == raw,
                    "stop custody changed during durable commit")
        finally:
            if temporary.exists():
                temporary.unlink()

    def commit_identity(self):
        info = safe_path(self.path).lstat()
        self.private(info)
        return self.identity(info)

    @staticmethod
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                info.st_mode, info.st_uid, info.st_nlink)

    @staticmethod
    def directory_identity(info):
        return info.st_dev, info.st_ino

    def read_committed_bytes(self, expected):
        with directory_descriptor(self.folder) as directory:
            require(self.directory_identity(os.fstat(directory)) ==
                    self.directory_identity(os.fstat(self.directory_fd)),
                    "stop custody directory changed during durable commit")
            fd = os.open("state.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                info = os.fstat(fd)
                self.private(info)
                raw = os.read(fd, 262145)
                require(self.identity(info) == expected and self.identity(os.fstat(fd)) == expected,
                        "stop custody changed during durable commit")
                return raw
            finally:
                os.close(fd)


def unresolved_stop_custody(base, endpoint):
    """Read-only consumer check. False means absent or validated resolved custody; unknown always refuses.

    The explicit base/endpoint confines discovery. A session-only census cannot find an orphan retained by
    an interrupted stop, and checking this must not create state in a legacy base with no custody file.
    """
    try:
        base = safe_path(text(base, "base"))
        endpoint_parts(endpoint)
        path = safe_path(base / "launches" / quoted(endpoint) / ".stop-custody" / "state.json")
        present = True
        try:
            path.lstat()
        except FileNotFoundError:
            present = False
            try:
                path.parent.lstat()
            except FileNotFoundError:
                return False
        launches = Launches(str(base))
        # Schema/boot validation is independent from restoring signal authority for the current binding.
        # Any active custody blocks a consumer, including custody left by an earlier binding.
        retained = StopCustody(launches, endpoint, None, create=False).read()
        require(retained is not None or not present, "stop custody disappeared while reading")
        return retained[0]["active"] if retained is not None else False
    except (ValueError, OSError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        if str(exc).startswith("stop custody unavailable for " + endpoint + ":"):
            raise
        raise ValueError(custody_refusal(base, endpoint, exc)) from exc


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
        # ps erases argv boundaries. Quotes are literal; neither paths with spaces nor freeform values can
        # be recovered. These rows are diagnostic only, including apparently canonical selector strings.
        rows.append(ProcessSnapshot(int(words[0]), int(words[1]), words[5], int(words[3]),
                                    " ".join(words[6:11]), os.fsencode(words[11]), tuple(words[11].split()),
                                    int(words[2]), int(words[4])))
    return rows


def process_existence(pid, reason, partial=None):
    """Missing metadata alone proves nothing; qualified numeric ESRCH is a distinct observation."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return ProcessObservation("CONFIRMED_ABSENT", pid, partial=partial, proof="qualified_namespace_ESRCH")
    except PermissionError:
        return ProcessObservation("UNAVAILABLE", pid, partial=partial, reason=reason + "; existence_unknown")
    return ProcessObservation("UNAVAILABLE", pid, partial=partial, reason=reason + "; existence_live")


def read_process(pid, argv_boundaries="proven"):
    """Retry a torn multipart observation once, never turn unreadable evidence into absence."""
    first = read_process_once(pid, argv_boundaries)
    if (first.kind == "UNAVAILABLE" and first.reason.partition("; existence_")[0] ==
            "evidence_unavailable: unstable parent/group evidence"):
        return read_process_once(pid, argv_boundaries)
    return first


def read_process_once(pid, argv_boundaries="proven"):
    if argv_boundaries == "unproven":
        rows = ps_census(pid)
        return (ProcessObservation("PRESENT", pid, rows[0]) if rows else
                ProcessObservation("UNAVAILABLE", pid, reason="argv_boundaries_unavailable"))
    folder, data, errors = Path("/proc") / str(pid), {}, []
    for name, filename in (("before", "stat"), ("status", "status"), ("cmdline", "cmdline"), ("after", "stat")):
        try:
            data[name] = (folder / filename).read_bytes()
        except OSError as exc:
            errors.append("%s: %s" % (filename, exc))
    partial = {}
    fields = data.get("before", b"").rpartition(b")")[2].split()
    after = data.get("after", b"").rpartition(b")")[2].split()
    if len(fields) >= 20 and all(fields[index].isdigit() for index in (1, 2, 19)):
        partial.update(start_time=fields[19].decode("ascii"), ppid=int(fields[1]), pgid=int(fields[2]),
                       state=os.fsdecode(fields[0]))
    else:
        errors.append("malformed stat")
    coherent_birth = ("start_time" in partial and len(after) >= 20 and after[19].isdigit() and
                      after[19:20] == fields[19:20])
    partial["coherent_birth"] = coherent_birth
    partial["exit_observed"] = coherent_birth and (fields[0] == b"Z" or after[0] == b"Z")
    if not coherent_birth:
        errors.append("unstable birth evidence")
    elif after[1:3] != fields[1:3]:
        errors.append("unstable parent/group evidence")
    uids = next((line.split()[1:] for line in data.get("status", b"").splitlines() if line.startswith(b"Uid:")), [])
    if len(uids) >= 2 and all(value.isdigit() for value in uids[:2]):
        partial.update(uid=int(uids[0]), euid=int(uids[1]))
    else:
        errors.append("missing real/effective status UIDs")
    if "cmdline" in data:
        raw = data["cmdline"]
        arguments = raw.split(b"\0")
        if arguments[-1] == b"":
            arguments.pop()
        partial.update(cmdline=raw, argv=tuple(os.fsdecode(a) for a in arguments))
        if raw and not raw.endswith(b"\0"):
            errors.append("truncated cmdline")
    if errors:
        return process_existence(pid, "evidence_unavailable: " + "; ".join(errors), partial)
    row = ProcessSnapshot(pid, partial["pgid"], partial["state"], partial["uid"], partial["start_time"],
                          partial["cmdline"], partial["argv"], partial["ppid"], partial["euid"])
    return ProcessObservation("PRESENT", pid, row)


def process_census(session):
    """Complete atoms on Linux; lost boundaries or relevant unreadable coverage cannot prove no targets."""
    proc = Path("/proc")
    if not proc.is_dir():
        return ProcessCensus(ps_census(), "unproven")
    rows, unavailable = [], {}
    for folder in proc.iterdir():
        if not folder.name.isdigit():
            continue
        observation = read_process(int(folder.name))
        if observation.kind == "PRESENT":
            rows.append(observation.snapshot)
        elif observation.kind == "UNAVAILABLE":
            unavailable[observation.pid] = observation
    return ProcessCensus(rows, "proven", unavailable)


def names_session(row, session):
    # Discovery is negative-only: prompt/config atoms may name S without selecting it.
    return argv_names_session(row.argv, session)


def argv_names_session(argv, session):
    return any(word == session or word.partition("=")[2] == session
               for atom in argv for word in atom.split())


def our_uid(row):
    return row.uid == row.euid == os.geteuid()


def owns_process(row, session, host, boundaries):
    return our_uid(row) and hierarchy_hosts.matches_session(host, row.argv, session, boundaries)


def unresolved(observed, pid, stage, reason):
    observed["unresolved"][pid] = {"pid": pid, "stage": stage, "reason": reason}


class CustodyUnavailable(OSError):
    """A failed checkpoint forbids subsequent effects but must not erase public attempt accounting."""


def persist_custody(observed, proposed=None):
    if observed is not None and "custody" in observed:
        if observed.get("custody_error"):
            raise CustodyUnavailable(observed["custody_error"])
        try:
            observed["custody"].save(observed, observed["attempted"] if proposed is None else proposed)
            observed["checkpoint_pending"] = False
        except (OSError, ValueError) as exc:
            observed["custody_error"] = "stop custody unavailable: " + str(exc)
            raise CustodyUnavailable(observed["custody_error"]) from exc


class CensusUnavailable(TypeError):
    """An incomplete census cannot be represented as a legacy list of owned roots."""


def session_processes(session, excluded, host=None, unowned=None, observed=None):
    """Owned roots only; retain unresolved candidates independently from attempted signals."""
    if host is not None:
        hierarchy_hosts.entrypoints(host)
    state = observed if observed is not None else {}
    census = process_census(session)
    state.update(census={row.pid: row for row in census}, argv_boundaries=census.argv_boundaries,
                 candidates={}, unresolved={}, resolved={}, handles={}, blocked=set(), identity_lost=set(),
                 initial_unavailable={}, numeric=False)
    found = []
    if census.argv_boundaries != "proven":
        state["coverage"] = "argv_boundaries_unavailable"
    for row in census:
        if row.pid in excluded or row.state.startswith("Z") or not names_session(row, session):
            continue
        # A diagnostic command naming the session must never be signalled.
        verdict = hierarchy_hosts.session_verdict(host, row.argv, session, census.argv_boundaries)
        if our_uid(row) and verdict == "OWNED":
            found.append((row.pid, row.pgid))
            state["candidates"][row.pid] = row
        else:
            if unowned is not None:
                unowned.append(row.pid)
            if census.argv_boundaries == "proven" and our_uid(row) and verdict == "HOLD":
                state["candidates"][row.pid] = row
                unresolved(state, row.pid, "census", "host_grammar_unavailable")
    for pid, observation in getattr(census, "unavailable", {}).items():
        facts = observation.partial or {}
        if pid in excluded or any(facts.get(key) is not None and facts[key] != os.geteuid()
                                  for key in ("uid", "euid")):
            continue
        # Incomplete same-user coverage can hide a descendant with no session argument. A readable command
        # line alone cannot prove that its unknown UID/birth/parent data is outside this session's scope.
        state["candidates"][pid] = None
        state["initial_unavailable"][pid] = facts
        unresolved(state, pid, "census", observation.reason)
        raw = facts.get("cmdline")
        if unowned is not None and isinstance(raw, bytes) and raw.endswith(b"\0") and argv_names_session(
                facts.get("argv", ()), session):
            # A current, complete cmdline can prove the name was observed without proving signal ownership.
            unowned.append(pid)
    if observed is None and (state.get("coverage") or state["unresolved"]):
        raise CensusUnavailable("process census unresolved: " +
                                (state.get("coverage") or ",".join(map(str, sorted(state["unresolved"])))))
    return found


def original_exit(expected, observed):
    handle = observed["handles"].get(expected.pid)
    if handle is None or not handle["verified"]:
        return False
    poller = select.poll()
    poller.register(handle["fd"], select.POLLIN)
    if any(event & select.POLLIN for _, event in poller.poll(0)):
        observed["checkpoint_pending"] = True
        observed["resolved"][expected.pid] = "original_pidfd_exit"
        observed["unresolved"].pop(expected.pid, None)
        return True
    return False


def process_state(expected, current, boundaries, session, host, unowned, require_host=True, parent=None,
                  retained=False):
    if current is None:
        current = process_existence(expected.pid, "evidence_unavailable: reader returned None")
    if isinstance(current, ProcessSnapshot):
        current = ProcessObservation("PRESENT", expected.pid, current)
    if current.kind == "CONFIRMED_ABSENT":
        return "gone"
    if current.kind != "PRESENT":
        return "unavailable"
    row = current.snapshot
    if row.start_time == expected.start_time and row.state.startswith("Z"):
        return "gone"
    if (row.start_time != expected.start_time or row.cmdline != expected.cmdline or
            (not retained and row.pgid != expected.pgid) or not our_uid(row) or
            (row.uid, row.euid) != (expected.uid, expected.euid) or
            (parent is not None and row.ppid != parent) or
            (require_host and not owns_process(row, session, host, boundaries))):
        # A changed census candidate stays unresolved; stale positive argv cannot reclassify it as spared.
        return "changed"
    return "authorized"


def unchanged_process(expected, boundaries, session, host, unowned, require_host=True, parent=None, retained=False):
    return process_state(expected, read_process(expected.pid, boundaries), boundaries, session, host, unowned,
                         require_host, parent, retained) == "authorized"


def note_identity_loss(expected, observation, observed):
    if observed is None:
        return
    if observation.kind == "PRESENT":
        birth = observation.snapshot.start_time
    else:
        facts = observation.partial or {}
        birth = facts.get("start_time") if facts.get("coherent_birth") else None
    if birth is not None and birth != expected.start_time and expected.pid not in observed["identity_lost"]:
        observed["identity_lost"].add(expected.pid)
        observed["blocked"].add(expected.pid)
        observed["checkpoint_pending"] = True
        persist_custody(observed)


def retained_state(expected, boundaries, session, host, unowned, observed=None):
    if observed is not None and original_exit(expected, observed):
        return "gone"
    current = read_process(expected.pid, boundaries)
    note_identity_loss(expected, current, observed)
    if observed is not None:
        if current.kind == "CONFIRMED_ABSENT" and expected.pid in observed["identity_lost"]:
            return "unavailable"  # A later numeric absence does not recover a lost original-instance proof.
    result = process_state(expected, current, boundaries, session, host, unowned,
                           require_host=False, retained=True)
    if observed is not None and result == "gone":
        observed["checkpoint_pending"] = True
        observed["resolved"][expected.pid] = current.proof or "matching_birth_zombie"
        observed["unresolved"].pop(expected.pid, None)
    return result


def signal_process(chain, number, boundaries, session, host, unowned, retained=False, observed=None, attempted=None):
    state = observed
    target, opened = chain[0], {}
    if state is not None and any(row.pid in state.get("excluded", ()) for row in chain):
        unresolved(state, target.pid, "before_signal", "ancestor_excluded")
        return False
    try:
        for expected in chain:
            kept = state["handles"].get(expected.pid) if state is not None else None
            if kept is not None:
                opened[expected.pid] = kept
            elif hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
                try:
                    opened[expected.pid] = {"fd": os.pidfd_open(expected.pid), "verified": False}
                except OSError as exc:
                    if exc.errno == errno.ESRCH:
                        if state is not None:
                            if expected.pid == target.pid:
                                if target.pid in state["identity_lost"]:
                                    unresolved(state, target.pid, "before_signal",
                                               "original_instance_unresolved_after_numeric_ESRCH")
                                else:
                                    state["resolved"][target.pid] = "qualified_namespace_ESRCH"
                                    state["unresolved"].pop(target.pid, None)
                            else:
                                unresolved(state, target.pid, "before_signal", "parent_instance_absent")
                        return False
                    # Non-ESRCH pidfd failures retain the admitted numeric fallback, after identical rechecks.
        for index in reversed(range(len(chain))):
            expected = chain[index]
            parent = chain[index + 1].pid if index + 1 < len(chain) else None
            observation = read_process(expected.pid, boundaries)
            note_identity_loss(expected, observation, state)
            result = process_state(expected, observation, boundaries, session, host, unowned,
                                   parent is None and not retained, parent, retained)
            if (state is not None and expected.pid in state["identity_lost"] and
                    observation.kind == "CONFIRMED_ABSENT"):
                result = "unavailable"
            if result != "authorized" or (state is not None and target.pid in state["blocked"]):
                if state is not None:
                    if result == "gone" and expected.pid == target.pid:
                        state["resolved"][target.pid] = observation.proof or "matching_birth_zombie"
                        state["unresolved"].pop(target.pid, None)
                    else:
                        reason = "evidence_unavailable" if result == "unavailable" else "instance_or_parent_changed"
                        unresolved(state, target.pid, "before_signal", reason)
                        if result == "changed":
                            if target.pid not in state["blocked"]:
                                state["checkpoint_pending"] = True
                            state["blocked"].add(target.pid)
                    if state.get("checkpoint_pending", True):
                        persist_custody(state)
                return False
            if expected.pid in opened:
                opened[expected.pid]["verified"] = True
            if parent is not None and hierarchy_hosts.selects_other_session(expected.argv, session):
                if state is not None:
                    unresolved(state, target.pid, "before_signal", "descendant_selection_ambiguous")
                return False
        handle = opened.get(target.pid)
        if state is not None and handle is not None:
            state["handles"][target.pid] = handle
        if state is not None:
            state["unresolved"].pop(target.pid, None)
            # Durable A precedes the effect. A crash between this fsync and the syscall is a possible attempt.
            persist_custody(state, set(attempted or ()) | {target.pid})
        if attempted is not None:
            # The journal carries possible A before the syscall. This invocation has made no attempt when
            # the barrier fails; recovery still retains an A whose acknowledgement was lost.
            attempted.add(target.pid)
        if handle is None:
            if state is not None:
                state["numeric"] = True
            # The birth/cmdline/UID check and numeric kill are not atomic; ADR7 admits this residual race.
            os.kill(target.pid, number)
        else:
            signal.pidfd_send_signal(handle["fd"], number)
        return "sent"
    except ProcessLookupError:
        if state is not None:
            state["resolved"][target.pid] = "signal_ESRCH"
            state["unresolved"].pop(target.pid, None)
        return False
    except PermissionError as exc:
        if state is not None:
            unresolved(state, target.pid, "signal", "signal_denied: " + str(exc))
        return "denied"
    finally:
        for pid, handle in opened.items():
            if state is None or state["handles"].get(pid) is not handle:
                os.close(handle["fd"])


def descendant_lineage(member, census, owners, session):
    """A candidate chain can be unresolved without becoming signal authority."""
    chain, seen, verdict = [], set(), "CLEAR"
    while member.pid not in seen:
        seen.add(member.pid)
        chain.append(member)
        if member.pid in owners:
            return chain, verdict
        if not our_uid(member):
            return [], "OTHER"
        selection = hierarchy_hosts.descendant_verdict(member.argv, session)
        if selection == "OTHER":
            return [], "OTHER"
        if selection == "HOLD":
            verdict = "HOLD"
        member = census.get(member.ppid)
        if member is None:
            return [], "HOLD"
    return [], "HOLD"


def descendant_chain(member, census, owners, session):
    chain, verdict = descendant_lineage(member, census, owners, session)
    return chain if verdict == "CLEAR" else []


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
    owners = {pid for pid, _ in found}
    groups = {pgid for _, pgid in found if pgid != os.getpgrp()}
    targets = [[census[pid]] for pid in owners]
    for member in census.values():
        if member.pid not in owners and member.pgid in groups:
            chain, verdict = descendant_lineage(member, census, owners, session)
            if chain:
                if verdict == "HOLD":
                    if names_session(member, session):
                        # An ambiguous S-naming host cannot vanish from scope merely because its program is
                        # another host kind. No-S negative exclusions still confer no borrowed authority.
                        observed["candidates"].setdefault(member.pid, member)
                        unresolved(observed, member.pid, "census", "descendant_selection_ambiguous")
                else:
                    targets.append(chain)
    for chain in targets:
        pid = chain[0].pid
        observed["candidates"].setdefault(pid, chain[0])
    # Children first: every parent edge still exists and is freshly checked BEFORE the child's first signal.
    for chain in sorted(targets, key=lambda rows: process_depth(rows[0], census), reverse=True):
        signal_process(chain, number, boundaries, session, host, unowned, observed=observed, attempted=attempted)
    return attempted


def signal_retained(pids, number, observed, session, host, unowned):
    if observed["argv_boundaries"] != "proven":
        return  # Lossy discovery cannot renew original-instance signal authority.
    for pid in sorted(pids):
        expected = observed["candidates"][pid]
        if pid not in observed["resolved"] and not original_exit(expected, observed):
            # W's first pass proved ancestry; dead M must not erase W's retained original-instance evidence.
            signal_process([expected], number, observed["argv_boundaries"], session, host, unowned,
                           retained=True, observed=observed, attempted=pids)


def gone_within(session, excluded, pids, seconds, host, observed, unowned):
    deadline = time.monotonic() + seconds
    while True:
        for pid, expected in observed["candidates"].items():
            if pid in excluded or pid in observed["resolved"]:
                continue
            if expected is None:
                observation = read_process(pid, observed["argv_boundaries"])
                initial = observed["initial_unavailable"].get(pid, {})
                birth = initial.get("start_time") if initial.get("coherent_birth") else None
                if observation.kind == "PRESENT":
                    current = {"start_time": observation.snapshot.start_time, "coherent_birth": True,
                               "exit_observed": observation.snapshot.state.startswith("Z")}
                else:
                    current = observation.partial or {}
                current_birth = current.get("start_time") if current.get("coherent_birth") else None
                if birth and current_birth and current_birth != birth and pid not in observed["identity_lost"]:
                    observed["identity_lost"].add(pid)
                    observed["blocked"].add(pid)
                    observed["checkpoint_pending"] = True
                    persist_custody(observed)
                if birth and current_birth == birth and current.get("exit_observed"):
                    observed["resolved"][pid] = "matching_partial_birth_zombie"
                    result = "gone"
                elif observation.kind == "CONFIRMED_ABSENT" and pid not in observed["identity_lost"]:
                    observed["resolved"][pid] = observation.proof
                    result = "gone"
                else:
                    result = "unavailable"
            else:
                result = retained_state(expected, observed["argv_boundaries"], session, host, unowned, observed)
            if result == "gone":
                observed["checkpoint_pending"] = True
                observed["resolved"].setdefault(pid, "confirmed_instance_exit")
                observed["unresolved"].pop(pid, None)
            else:
                unresolved(observed, pid, "after_signal" if pid in pids else "before_signal",
                           "evidence_unavailable" if result == "unavailable" else "original_instance_live_or_changed")
                if result == "changed":
                    if pid not in observed["blocked"]:
                        observed["checkpoint_pending"] = True
                    observed["blocked"].add(pid)
        if len(observed["resolved"]) == len(observed["candidates"]):
            return not observed.get("coverage")
        if not pids or time.monotonic() >= deadline:
            return False
        time.sleep(POLL_SECONDS)


def stop(launches, endpoint, grace):
    endpoint = launches.resolve(endpoint)
    identifier = launches.new_id()
    if not (type(grace) is int and 0 <= grace <= 60):
        launches.refuse(endpoint, identifier, "stop", "invalid grace_seconds")
    stop_checks(launches, endpoint, identifier)
    with stop_endpoint_lock(launches.mailbox.root, endpoint):
        return stop_locked(launches, endpoint, grace, identifier)


def stop_locked(launches, endpoint, grace, identifier):
    known = stop_checks(launches, endpoint, identifier)
    with StopCustody(launches, endpoint, known) as custody:
        return stop_owned(launches, endpoint, identifier, known, grace, custody)


def stop_checks(launches, endpoint, identifier):
    """Pure preflight is repeated under the endpoint lock; only that fresh binding reaches effects."""
    known, profile = bound_session(launches, endpoint, identifier, "stop")
    if endpoint_parts(endpoint)[1] == "root":
        launches.refuse(endpoint, identifier, "stop", ROOT_STOP, **known)
    if known["host"] == NATIVE:
        launches.refuse(endpoint, identifier, "stop", "a native thread is stopped by its own app, not the launcher", **known)
    try:
        background = profile.is_file() and read_json(profile).get("mode") == "background"
    except (ValueError, OSError, AttributeError) as exc:
        launches.refuse(endpoint, identifier, "stop", str(exc), **known)
    if background:
        launches.refuse(endpoint, identifier, "stop",
                        "a background claude session stops through claude stop; use the wake tool's control", **known)
    return known


def stop_owned(launches, endpoint, identifier, known, grace, custody):
    pids, unowned, observed = set(), [], {}
    marker = {"wake_marker_present": launches.mailbox.wake_marker(endpoint).exists(), "grace_seconds": grace}
    error = None
    try:
        excluded = ancestors()
        found = session_processes(known["session"], excluded, known["host"], unowned, observed)
        custody.restore(observed, pids)
        observed.update(custody=custody, attempted=pids, excluded=excluded, checkpoint_pending=True)
        if observed["argv_boundaries"] != "proven":
            marker["argv_boundaries"] = "unproven"
        if pids:
            signal_retained(pids, signal.SIGTERM, observed, known["session"], known["host"], unowned)
        if found:
            signal_all(found, signal.SIGTERM, observed, known["session"], known["host"], unowned, pids)
        stopped = gone_within(known["session"], excluded, pids, grace, known["host"], observed, unowned)
        if not stopped and pids:
            signal_retained(pids, signal.SIGKILL, observed, known["session"], known["host"], unowned)
            stopped = gone_within(known["session"], excluded, pids, KILL_WAIT_SECONDS, known["host"], observed, unowned)
        marker["wake_marker_present"] = launches.mailbox.wake_marker(endpoint).exists()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        if not pids:
            launches.refuse(endpoint, identifier, "stop", str(exc), **known)
        error, stopped = str(exc), False
        for pid in observed.get("candidates", {}):
            if pid not in observed["resolved"]:
                unresolved(observed, pid, "operation_error", "evidence_unavailable: " + str(exc))
    finally:
        for handle in observed.get("handles", {}).values():
            os.close(handle["fd"])
    # On success no more signals are needed: retain durable active custody through the immutable outcome,
    # then commit all exit proofs and terminal clear together. An intermediate resolved-active write adds
    # no recovery protection. Failures still checkpoint, and every escalation keeps its pre-effect barrier.
    # A failed checkpoint is never retried into success or allowed to erase possible attempts.
    if (not stopped and not observed.get("custody_error") and observed.get("checkpoint_pending", True) and
            (observed.get("candidates") or observed.get("coverage"))):
        try:
            persist_custody(observed)
        except CustodyUnavailable as exc:
            error = str(exc)
    spared = sorted(set(unowned) - pids)
    if spared:
        marker["unowned_pids"] = spared
    if observed.get("unresolved"):
        marker["unresolved_pids"] = sorted(observed["unresolved"])
        marker["unresolved"] = [observed["unresolved"][pid] for pid in sorted(observed["unresolved"])]
    if observed.get("coverage"):
        marker["reason"] = observed["coverage"]
    if observed.get("resolved"):
        marker["absence_evidence"] = [{"pid": pid, "proof": observed["resolved"][pid]}
                                      for pid in sorted(observed["resolved"])]
    if pids:
        marker["identity_check_mode"] = "start_time_recheck" if observed["numeric"] else "pidfd"
    if error is not None:
        marker["error"] = error
    state = "stopped" if pids else "not_running"
    if not stopped:
        state = "stop_failed"
    # Keep active custody until the immutable outcome is durable, including failure/interruption windows.
    record = launches.record(endpoint, identifier, "stop", state, **known, pids=sorted(pids), **marker)
    if (not observed.get("custody_error") and (stopped or observed.get("checkpoint_pending", True)) and
            (observed.get("candidates") or observed.get("coverage") or custody.path.exists())):
        try:
            custody.save(observed, pids, active=not stopped)
        except (OSError, ValueError) as exc:
            # The earlier record cannot be changed. A later immutable failure prevents a terminal success
            # claim while active custody remains, including loss of the state-file commit acknowledgement.
            marker["error"] = "stop custody unavailable: " + str(exc)
            return 3, launches.record(endpoint, launches.new_id(), "stop", "stop_failed", **known,
                                      pids=sorted(pids), **marker)
    return (0 if stopped else 3), record


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
