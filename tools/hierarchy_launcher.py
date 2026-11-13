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

Limits: descendants that escape the observed group/ancestry (for example with setsid) need kernel custody,
such as a per-session cgroup. So do orphans recovered after both host and intermediary have exited: a journal
identifies an instance but cannot authenticate session ownership. Stop retains these as unresolved custody
(exit 3) for owner reconciliation, rather than signalling from journal claims alone.
Resolved custody requires an unrestricted process view: hidepid/restricted procfs with EPERM refuses
with manual reconciliation guidance rather than treating another user's hidden PID as a proven exit.

A launch record is not a lifecycle event and grants nothing: the journal has no provider-bridge
role. A clean start proves a process ran and reported a thread, not that the role will behave.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, nullcontext, ExitStack
from datetime import datetime, timezone
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import sys
import time
from typing import NamedTuple, Optional
import uuid

# Bootstrap stays stdlib-only: importing the selected provisioner here would be too late to fence
# an older runtime. Keep the governing-pin rule aligned with hierarchy_provision.check_governing_pin.
BOOTSTRAP_PIN_CHECK_ERROR = "governing source pin check failed; use the governing base or reprovision"
BOOTSTRAP_JSON_LIMIT = 262144
BOOTSTRAP_DESCRIPTOR_CAPS = (all(hasattr(os, key) for key in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")) and
                             os.open in getattr(os, "supports_dir_fd", ()) and
                             os.stat in getattr(os, "supports_dir_fd", ()))


def bootstrap_descriptor_capable():
    return BOOTSTRAP_DESCRIPTOR_CAPS


@contextmanager
def bootstrap_directory(path):
    """Open from the filesystem root, retaining every edge until the bootstrap read is checked."""
    if not bootstrap_descriptor_capable():
        raise ValueError(BOOTSTRAP_PIN_CHECK_ERROR)
    path = Path(path)
    if ".." in path.parts or len(path.parts) > 256:
        raise ValueError(BOOTSTRAP_PIN_CHECK_ERROR)
    path = Path(os.path.abspath(path))
    if len(path.parts) > 256:
        raise ValueError(BOOTSTRAP_PIN_CHECK_ERROR)
    descriptors, edges = [], []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path.anchor, flags)
        descriptors.append(descriptor)
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            descriptors.append(child)
            info = os.fstat(child)
            edges.append((descriptor, part, (info.st_dev, info.st_ino)))
            descriptor = child

        def check():
            for parent, name, identity in edges:
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity:
                    raise ValueError(BOOTSTRAP_PIN_CHECK_ERROR)

        yield descriptor, check
        check()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def bootstrap_json(directory):
    """Bound before allocation/parsing, reject duplicate keys, and never format untrusted input."""
    descriptor = os.open("provision.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > BOOTSTRAP_JSON_LIMIT:
            raise ValueError(BOOTSTRAP_PIN_CHECK_ERROR)
        raw = bytearray()
        while len(raw) <= BOOTSTRAP_JSON_LIMIT:
            block = os.read(descriptor, min(65536, BOOTSTRAP_JSON_LIMIT + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
        named = os.stat("provision.json", dir_fd=directory, follow_symlinks=False)
        def mark(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if len(raw) > BOOTSTRAP_JSON_LIMIT or mark(before) != mark(after) or mark(after) != mark(named):
            raise ValueError(BOOTSTRAP_PIN_CHECK_ERROR)
    finally:
        os.close(descriptor)

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(BOOTSTRAP_PIN_CHECK_ERROR)
            result[key] = value
        return result

    def integer_literal(value):
        if len(value.lstrip("-")) > 128:
            raise ValueError(BOOTSTRAP_PIN_CHECK_ERROR)
        return int(value)

    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError(BOOTSTRAP_PIN_CHECK_ERROR)
        return number

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_int=integer_literal,
                      parse_float=finite, parse_constant=finite)


def bootstrap_plan_present(folder):
    """Silent lstat discovery: True is present, False is proven absent, None is indeterminate."""
    path = None
    try:
        path = Path(folder) / "host-plan.json"
        path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return False
    except ValueError:
        return False if path is not None and "\0" in str(path) else None
    except Exception:
        # A failed lookup is not proof that an older retained runtime may resolve policy.
        return None
    return True


def bootstrap_setup(base):
    """Preserve the integration-tip read and diagnostics until a governing plan is established."""
    local_plan = bootstrap_plan_present(base)
    if local_plan is True:
        return bootstrap_planned_setup(base)
    # This is the legacy bootstrap read, deliberately unchanged on the no-plan path.
    # Its mailbox association is needed to discover a plan beside the canonical mailbox.
    provision = Path(base) / "provision.json"
    setup = json.loads(provision.read_text(encoding="utf-8"))
    # Preserve a legacy read failure first; a successful read cannot authorize uncertain discovery.
    if local_plan is None:
        raise ValueError(BOOTSTRAP_PIN_CHECK_ERROR)
    mailbox_root = setup.get("mailbox_root") if isinstance(setup, dict) else None
    if isinstance(mailbox_root, str) and mailbox_root:
        governing_plan = bootstrap_plan_present(Path(mailbox_root).parent)
        if governing_plan is None:
            raise ValueError(BOOTSTRAP_PIN_CHECK_ERROR)
        if governing_plan is True:
            # Re-read through descriptors after discovery; never dispatch using this preliminary read.
            return bootstrap_planned_setup(base)
    return setup


def bootstrap_planned_setup(base):
    """The same equal-or-refuse rule as provision, before any retained code can run."""
    try:
        with bootstrap_directory(base) as (directory, check_base):
            setup = bootstrap_json(directory)
            mailbox_root = setup.get("mailbox_root") if isinstance(setup, dict) else None
            if not isinstance(mailbox_root, str) or not mailbox_root:
                return setup  # Ordinary runtime validation retains its malformed-record diagnostic.

            def planned(folder):
                try:
                    os.stat("host-plan.json", dir_fd=folder, follow_symlinks=False)
                except FileNotFoundError:
                    return False
                return True

            local_plan = planned(directory)
            with ExitStack() as homes:
                try:
                    home, check_home = homes.enter_context(bootstrap_directory(Path(mailbox_root).parent))
                except FileNotFoundError:
                    if local_plan:
                        raise
                    return setup  # No governing home and no local plan: retain legacy dispatch.
                if not local_plan and not planned(home):
                    return setup
                left, right = os.fstat(directory), os.fstat(home)
                if (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino):
                    return setup
                governing = bootstrap_json(home)
                check_home()
                check_base()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, RecursionError, OverflowError, RuntimeError) as exc:
        raise ValueError(BOOTSTRAP_PIN_CHECK_ERROR) from exc
    if (not isinstance(governing, dict) or governing.get("schema") != "aegis.hierarchy-provision/v1" or
            governing.get("mailbox_root") != mailbox_root or governing.get("initiative") != setup.get("initiative")):
        raise ValueError("governing provision record does not match this run; reprovision the base")
    keys = ("source_commit", "source_tree")
    if not all(isinstance(governing.get(key), str) and
               re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", governing[key]) for key in keys):
        raise ValueError("governing provision record has an invalid source pin; reprovision the base")
    if any(setup.get(key) != governing[key] for key in keys):
        raise ValueError("runtime source pin differs from governing provision; use the governing base or reprovision")
    return setup


def bootstrap_runtime(arguments):
    """Enter the retained verifier only after the current bootstrap has checked the governing pin."""
    import runpy
    early = argparse.ArgumentParser(add_help=False)
    early.add_argument("--base")
    early.add_argument("command", nargs="?")
    parsed, _ = early.parse_known_args(arguments)
    if parsed.command not in ("start", "resume", "_resume-wake") or not parsed.base:
        return False
    base = Path(parsed.base)
    provision = base / "provision.json"
    setup = bootstrap_setup(base)
    verifier = base / "runtime-source.py"
    if not verifier.is_file():
        raise ValueError("runtime source verifier is missing; reprovision into a new base through the existing handoff flow")
    loaded = runpy.run_path(str(verifier))
    loaded["run"](provision, Path(setup["source"]) / "tools" / Path(__file__).name, arguments)
    return True


# Provisioned CLI actions must enter through the retained verifier before importing any peer module.
# A process-local marker prevents recursion; an environment variable cannot bypass verification.
if __name__ == "__main__" and getattr(sys, "_aegis_verified_runtime_entry", None) != str(Path(__file__).resolve()):
    try:
        if bootstrap_runtime(sys.argv[1:]):
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
ENDPOINT_NAMESPACE_CHANGED = "endpoint namespace changed; preserve custody and retry"
MAX_NAMESPACE_DEPTH = 256
MAX_NAMESPACE_MANIFEST = 32768
PID_NAMESPACE_REFUSAL = ("stop unsupported without matching PID namespace and caller procfs view; "
    "preserve custody, stop the host manually in its original PID namespace, and have the owner "
    "reconcile this endpoint before retrying")
CURRENT_PID_NAMESPACE = object()
PIDFD_REFUSAL = ("stop could not obtain a safe process handle; preserve custody, restore "
    "pidfd availability and retry stop, or stop the host manually and have the owner reconcile this endpoint")
OWNING_CHAIN_REFUSAL = ("stop owning chain is unverified; preserve custody, stop the host and descendants "
    "manually, and have the owner reconcile this endpoint before retrying")
# Cache physical capability facts before test-owned OS facades wrap individual calls. A wrapped open
# is not evidence that the platform lost dir_fd support; the public probe remains replaceable in tests.
LAUNCH_DESCRIPTOR_CAPS = (all(hasattr(os, key) for key in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")) and
                          os.open in getattr(os, "supports_dir_fd", ()) and
                          os.stat in getattr(os, "supports_dir_fd", ()) and
                          os.scandir in getattr(os, "supports_fd", ()))
RUNNING_PUBLICATION_CAPS = (os.link in getattr(os, "supports_dir_fd", ()) and
                            os.rename in getattr(os, "supports_dir_fd", ()) and
                            os.unlink in getattr(os, "supports_dir_fd", ()) and
                            os.link in getattr(os, "supports_follow_symlinks", ()))
MAILBOX_WAKE_STAT_CAPS = os.stat in getattr(os, "supports_follow_symlinks", ())
WAKE_REFUSALS = ("a wake is already in progress for this endpoint; inspect the lock before retrying",
                 "session is already running; do not start a second copy",
                 "binding changed before launch; the outgoing session was not started",
                 "running wake atomic publication unsupported on this platform",
                 "process census failed", ENDPOINT_NAMESPACE_CHANGED, PID_NAMESPACE_REFUSAL)
# Closed diagnostic vocabulary from hierarchy_wake/mailbox validation and their literal field schemas.
# Keep arbitrary values out: no exception formatting, source inspection or imports expand this at runtime.
WAKE_VALIDATION_REFUSALS = (
    "--binding-only takes no --include-briefs, --limit, --after or --mark-read",
    "--host, --session and --generation go only with --mark-read", "--mark-read needs --delivery-dir",
    "--mark-read needs --host, --session and --generation for the reading root",
    "--request - (stdin) is only for publish and ack-handoff",
    "a wake is already in progress for this endpoint; inspect the lock before retrying",
    "a wake is in progress for this endpoint; stop it and remove its lock before replacing the session",
    "ack requires a stage and referenced message", "acknowledgment field requires ack type",
    "an interactive session has this ID; do not start a second copy", "argv does not name the bound session",
    "background mode is for claude-code sessions", "background mode needs its control command",
    "background mode passes the prompt as an argument",
    "binding changed before launch; the outgoing session was not started", "binding generation changed",
    "binding history exceeds record limit", "binding history limit reached", "brief must be a Markdown file",
    "brief must be within the mailbox parent directory", "brief or dispatch message requires a brief hash",
    "brief sha256 mismatch", "checkpoint acknowledgment is not an ack",
    "checkpoint branch changed since acceptance", "checkpoint digest mismatch",
    "checkpoint omits active brief", "checkpoint omits active dispatch", "checkpoint omits active lease",
    "checkpoint omits active source snapshot", "checkpoint omits open job request",
    "checkpoint references an unknown message", "checkpoint requires brief references",
    "checkpoint source mixes literal and digest dirty state",
    "checkpoint source snapshot does not match worktree", "completed job requires exit code 0",
    "completion requires checks", "concurrent writer limit reached", "control is only for background mode",
    "could not confirm that the idle background session stopped",
    "counterparts must have the same role across hierarchies", "counterparts must name two endpoints",
    "delivery receipt history exceeds record limit", "delivery receipt history limit reached",
    "dispatch has not been accepted", "dispatch is already accepted", "dispatch is already completed",
    "duplicate message_id in history", "each hierarchy requires a front door and orchestrator",
    "embedded null byte", "endpoint has more than one counterpart", "evidence path must be absolute",
    "expected a JSON object", "failed job requires a nonzero exit code", "git identity check failed",
    "git identity check timed out", "handoff acknowledgment does not match binding",
    "handoff acknowledgment has no replacement binding", "handoff checkpoint has not been acknowledged",
    "handoff exceeds 256 brief references", "handoff exceeds 256 pending messages",
    "inbox cursor does not name a received message",
    "inbox first message cannot fit 4194304 byte response budget",
    "inbox response metadata exceeds 4194304 bytes",
    "initial binding cannot contain a replacement checkpoint", "input exceeds 262144 bytes",
    "input must be a regular file", "invalid UTC timestamp", "invalid after message id", "invalid argv",
    "invalid base revision", "invalid binding generation", "invalid body", "invalid branch",
    "invalid brief path", "invalid brief sha256", "invalid briefs", "invalid check outcome",
    "invalid checkpoint sources", "invalid checkpoint worktree", "invalid counterparts",
    "invalid dirty entries", "invalid dirty evidence", "invalid dirty state", "invalid dirty state digest",
    "invalid endpoint", "invalid endpoint role", "invalid endpoints", "invalid enforcement tier",
    "invalid evidence list", "invalid evidence path", "invalid evidence sha256", "invalid exit code",
    "invalid expected generation", "invalid hierarchy", "invalid host", "invalid in_reply_to",
    "invalid inbox limit", "invalid initial binding", "invalid job state", "invalid kind",
    "invalid lane check reference", "invalid lane id", "invalid lane kind", "invalid lease oid",
    "invalid lease ref", "invalid message id", "invalid message_id", "invalid mode", "invalid prompt_via",
    "invalid reason", "invalid receipt generation", "invalid runtime source provision",
    "invalid scan workspace", "invalid session", "invalid source revision", "invalid source tree",
    "invalid timeout_seconds", "invalid wake id", "invalid wake state", "invalid worktree",
    "invalid writer_limit", "job receipt must come from root and reply to a job request",
    "job receipt must reply to a job request", "job receipt requires a reason",
    "job receipt requires evidence", "job request already has a terminal receipt",
    "job request requires a hash-bound packet", "lane completion must reply to its dispatch",
    "lane completion requires source and check evidence", "mailbox exceeds record limit",
    "mailbox history limit reached", "mailbox root already exists",
    "mailbox writer is busy; inspect an abandoned lock before retrying",
    "malformed mailbox authority or schema", "malformed role binding", "maximum recursion depth exceeded",
    "maximum recursion depth exceeded while decoding a JSON array from a unicode string",
    "maximum recursion depth exceeded while decoding a JSON object from a unicode string",
    "message exceeds 262144 bytes", "message is in the wrong routing folder", "missing header",
    "non-finite JSON is not supported", "nonconsecutive binding history",
    "only an orchestrator can dispatch its own lane",
    "only an orchestrator can request a job from its own root",
    "only front doors, orchestrators and lanes can be counterparts",
    "only root reads through the CLI with a receipt; a session's adapter records its own",
    "outgoing session must be stopped before replacement", "owned paths must be repository relative",
    "path must be absolute without traversal", "process census failed", "profile cwd is not a directory",
    "profile does not match the current binding", "profile is for a different endpoint",
    "readiness branch does not match worktree", "readiness is only valid when accepting a lane dispatch",
    "readiness lease has expired", "readiness must name the exact worktree root",
    "readiness requires dispatch acceptance", "readiness worktree is unavailable",
    "receipt does not match binding history", "receipt field requires job_receipt type",
    "receipt names a message not addressed to this endpoint",
    "recipient has not acknowledged its handoff checkpoint", "referenced message does not exist",
    "replacement requires a checkpoint", "reply endpoints do not reverse the referenced message",
    "reserved hierarchy name", "result evidence requires lane completion",
    "reviewer acceptance must not include writing readiness", "root endpoints cannot be counterparts",
    "route is not vertical or an explicit counterpart",
    "runtime source verifier is missing; reprovision into a new base through the existing handoff flow",
    "scan workspace does not match lane worktree", "session is already running; do not start a second copy",
    "stale or mismatched sender binding", "symlink mailbox entry is not supported",
    "the background session is still working; wake it after its turn ends",
    "the background session is waiting on its owner (a dialog or an unknown status); it was not stopped, so answer it before the next wake",
    "the background session list is not JSON", "the background session list is not a list",
    "the host listed an invalid background session ID",
    "the host lists more than one running session with this ID",
    "the wake tool supports POSIX process groups only", "unexpected binding history entry",
    "unsupported manifest schema", "unsupported message type", "unsupported verification claim",
    "unsupported wake profile schema", "writing lane acceptance requires readiness",
    "writing lane already has an accepted dispatch",
    "writing lanes must use separate worktrees, branches and leases", "wrong receipt schema or endpoint",
)
WAKE_ERROR_FIELDS = (
    "argv", "at", "base_revision", "branch", "briefs", "check", "checkpoint", "checkpoint_sha256", "checks",
    "completed_checks", "control", "counterparts", "created_at", "cwd", "delivery_dir", "dirty_entries",
    "dirty_evidence", "dirty_state", "dirty_state_sha256", "endpoint", "endpoints", "enforcement_tier",
    "evidence", "evidence_dir", "exit_code", "expected_generation", "generation", "hook_evidence", "host",
    "kind", "lane_check", "last_acknowledgment_ids", "lease_expires_at", "lease_oid", "lease_ref",
    "lease_refs", "message_ids", "mode", "outcome", "outgoing_stopped", "owned_paths", "path",
    "pending_message_ids", "prompt_via", "reason", "reference", "scan_evidence", "scan_workspace", "schema",
    "session", "sha256", "source_revision", "source_tree", "sources", "state", "timeout_seconds", "worktree",
    "writer_limit",
)
WAKE_JSON_ERRORS = ("Expecting value", "Expecting property name enclosed in double quotes",
    "Expecting ':' delimiter", "Expecting ',' delimiter", "Unterminated string starting at",
    "Invalid \\escape", "Invalid \\uXXXX escape", "Extra data", "Invalid control character at")
DEFAULT_START_TIMEOUT_SECONDS = 300
KILL_WAIT_SECONDS = 5.0
POLL_SECONDS = 0.05
STOP_EXIT_PROOFS = ("original_pidfd_exit", "qualified_namespace_ESRCH", "matching_birth_zombie",
                    "matching_partial_birth_zombie", "confirmed_instance_exit", "signal_ESRCH")
STOP_COVERAGE = (None, "argv_boundaries_unavailable", "session_instance_unresolved_after_exit")
# The mailbox writer lock is held only for a moment; a start already paid for should outlast that.
BIND_WAIT_SECONDS = 10.0
INTERRUPTS = tuple(getattr(signal, name) for name in ("SIGTERM", "SIGINT", "SIGHUP") if hasattr(signal, name))
INTERRUPTED = "the launcher was interrupted"
ROOT_START = "ROOT is the owner's session; bind it with add-role"
ROOT_STOP = "ROOT is the owner's session; the launcher does not stop it"
MAILBOX_WAKE_PENDING = ("mailbox wake admission is pending; wait for the producer to finish, or preserve and "
                        "reconcile its marker before retrying")
CLEANUP_BINDING_CHANGED = ("cleanup binding changed; preserve the worktree and inspect the successor binding "
                           "before rerunning cleanup")
NO_EXPECTED_BINDING = object()
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
        return launch_record_paths(self.base, endpoint)

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


def run_start(argv, cwd, logs, timeout, deferred, stdin_path=None, read_session=first_session, before_spawn=None):
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
                if before_spawn is not None:
                    before_spawn()
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
    known = binding_identity(launches.binding(endpoint)) or {"host": host}
    # Installed before the lock is taken and kept until the outcome is recorded: a signal with its default
    # action would skip start_lock's finally and leave the endpoint refusing every later start.
    previous = {number: signal.getsignal(number) for number in INTERRUPTS}
    try:
        for number in INTERRUPTS:
            signal.signal(number, interrupt)
        with recorded_endpoint_lock(launches, endpoint, identifier, "start", known, create=True) as fence:
            recorded_custody_check(launches, endpoint, identifier, "start", known)
            fence.check()
            with start_lock(launches, endpoint, identifier, host):
                return locked_start(launches, request, endpoint, identifier, plan, host, stand_in, fence)
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


def locked_start(launches, request, endpoint, identifier, plan, host, stand_in, fence):
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
        fence.check()
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
            stdin_path=prompt_file, read_session=claude_session, before_spawn=fence.check)
        session, error = confirmed(reported, session, home, error)
    else:
        session, exit_code, timed_out, error = run_start(argv, started["cwd"], logs, timeout, deferred,
                                                        before_spawn=fence.check)
    # contract keeps its meaning (the role's own file); contracts lists every file the prompt carries.
    details = {"argv": argv, "cwd": started["cwd"], "contract": contracts[-1], "contracts": contracts,
               "start_timeout_seconds": timeout, "exit_code": exit_code, "timed_out": timed_out, **via}
    if not (isinstance(session, str) and SESSION.fullmatch(session)):
        error = error or ("the start reported an invalid session" if session is not None else
                          "the start timed out" if timed_out else
                          "the start process exited unsuccessfully" if exit_code != 0 else
                          "the start exited without reporting a session")
        record = launches.record(endpoint, identifier, "start", "failed_to_start", **known, **details, error=error)
        return 3, {**record, "log": logs}
    known["session"] = session
    if error or exit_code != 0 or timed_out:
        record = launches.record(endpoint, identifier, "start", "start_incomplete", **known, **details,
                                 error=error or ("the start timed out" if timed_out else
                                                 "the start process exited unsuccessfully"))
        return 3, {**record, "log": logs}

    def bind():
        # Checked before each attempt, so an interrupt ends the busy wait; an add_role already running finishes.
        if deferred.seen:
            raise Interrupted()
        fence.check()
        return fenced_add_role({"base": str(launches.base), "endpoint": endpoint, "host": host, "session": session,
                                **{key: request[key] for key in ADD_ROLE_KEYS if key in request}}, fence)
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


def fenced_add_role(request, fence):
    """Use the unchanged producer with a private Mailbox boundary, never shared-module monkeypatches."""
    from types import FunctionType

    producer = add_role
    mailbox = producer.__globals__["Mailbox"]
    class FencedMailbox(mailbox):
        def bind(self, *args, **kwargs):
            fence.check()
            return super().bind(*args, **kwargs)
    private = FunctionType(producer.__code__, {**producer.__globals__, "Mailbox": FencedMailbox},
                           producer.__name__, producer.__defaults__, producer.__closure__)
    private.__kwdefaults__ = producer.__kwdefaults__
    return private(request)


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
    known, _ = bound_session(launches, endpoint, identifier, "resume")
    with recorded_endpoint_lock(launches, endpoint, identifier, "resume", known) as admission:
        recorded_custody_check(launches, endpoint, identifier, "resume", known)
        try:
            require(read_running_wake(launches.base, endpoint) is None,
                    "a turn is in flight; wait for it to finish, or run stop to end it")
        except (OSError, ValueError) as exc:
            launches.refuse(endpoint, identifier, "resume", str(exc), **known)
        return resume_locked(launches, endpoint, identifier, dry_run, admission)


def load_wake(launches):
    """A private producer namespace: its process-creation adapter cannot affect another endpoint."""
    from types import ModuleType

    source = Path(launches.setup["source"])
    path = source / "tools/hierarchy_wake.py"
    # Execute the exact verified commit's blob, never reopen mutable source by pathname or import a
    # cache. Object identity is immutable; bound its declared size before requesting its body.
    reference = launches.setup["source_commit"] + ":tools/hierarchy_wake.py"
    size = hierarchy_runtime_source.git(source, "cat-file", "-s", reference).strip()
    require(len(size) <= 8 and size.isdigit() and int(size) <= 1048576, "invalid or oversized wake source")
    raw = hierarchy_runtime_source.git(source, "cat-file", "blob", reference)
    require(len(raw) == int(size), "wake source object changed")
    module = ModuleType("_admitted_wake_" + uuid.uuid4().hex)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)  # aegis: allow[sec-py-eval-exec] verified pinned wake blob
    return module


def wake_failure_text(exc, fallback):
    """Preserve fixed legacy diagnostics without reflecting arbitrary values or exception payloads."""
    if isinstance(exc, OSError) and type(exc.errno) is int and exc.errno in errno.errorcode:
        return "[Errno %d] %s" % (exc.errno, os.strerror(exc.errno))
    if (isinstance(exc, json.JSONDecodeError) and exc.msg in WAKE_JSON_ERRORS and
            all(type(value) is int and 0 <= value < 2 ** 63 for value in (exc.lineno, exc.colno, exc.pos))):
        return "%s: line %d column %d (char %d)" % (exc.msg, exc.lineno, exc.colno, exc.pos)
    argument = (exc.args[0] if isinstance(exc, (ValueError, RecursionError)) and len(exc.args) == 1 and
                isinstance(exc.args[0], str) else None)
    if argument is not None and argument.startswith("unexpected fields: "):
        return "unexpected fields: [redacted]"
    reason = argument if argument is not None and len(argument) <= 256 else None
    if reason in (*WAKE_REFUSALS, *WAKE_VALIDATION_REFUSALS):
        return reason
    if reason is not None and reason.startswith("missing fields: "):
        names = reason[len("missing fields: "):].split(", ")
        if names and names == sorted(set(names)) and set(names) <= set(WAKE_ERROR_FIELDS):
            return reason
    if argument is not None and argument.startswith("duplicate JSON key: "):
        if reason is not None and reason[len("duplicate JSON key: "):] in WAKE_ERROR_FIELDS:
            return reason
        return "duplicate JSON key: [redacted]"
    for prefix in ("symlink paths are not supported: ", "file unavailable: "):
        if argument is not None and argument.startswith(prefix):
            return prefix + "[redacted]"
    return fallback


def resume_locked(launches, endpoint, identifier, dry_run, admission):
    import fcntl

    known, profile = bound_session(launches, endpoint, identifier, "resume")
    if known["host"] == NATIVE:
        launches.refuse(endpoint, identifier, "resume", "a native thread is resumed by its own app, not the launcher", **known)
    if not profile.is_file():
        launches.refuse(endpoint, identifier, "resume", "no wake profile for the current binding: " + str(profile), **known)
    try:
        require(len(launches.paths(endpoint)) < MAX_RECORDS, "launch record limit reached for " + endpoint)
    except (OSError, ValueError) as exc:
        launches.refuse(endpoint, identifier, "resume", str(exc), **known)
    # Admission must sort after any stop that acquired the fence before us. The eventual outcome
    # retains this order even when a concurrent stop completes during the synchronous turn.
    identifier = launches.new_id()
    argv = [sys.executable, *hierarchy_runtime_source.entry_args(launches.setup, "hierarchy_launcher.py"),
            "--base", str(launches.base), "_resume-wake", "--endpoint", endpoint,
            "--admission-fd", str(admission.fd), "--admission-namespace", admission.manifest(), "--wake-source",
            str(Path(launches.setup["source"]) / "tools/hierarchy_wake.py")]
    if dry_run:
        argv.append("--dry-run")
    admitted_at = timestamp()
    admission.check()
    try:
        write_resume_admission(launches, endpoint, identifier, known, admitted_at, not dry_run)
    except (OSError, ValueError):
        launches.refuse(endpoint, identifier, "resume", "resume admission publication failed; inspect admission evidence", **known)
    try:
        # The child inherits this exact open file description. Its explicit unlock releases admission
        # in both processes; the parent's descriptor lifetime does not fence the synchronous turn.
        admission.check()
        ran = subprocess.run(argv, pass_fds=(admission.fd,), capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        error = wake_failure_text(exc, "resume driver failed; inspect admission evidence and run stop")
        launches.refuse(endpoint, identifier, "resume", error, **known)
    try:
        answer = json.loads(ran.stdout)
    except ValueError:
        answer = {}
    answer = answer if isinstance(answer, dict) else {}
    result = {key: answer.get(key) for key in ("wake_id", "state", "exit_code", "timed_out")}
    details = {"dry_run": dry_run, "wake": result, "wake_exit_code": ran.returncode}
    code = ran.returncode if ran.returncode in (0, 3) else 2
    state = "resumed" if code == 0 else "resumed_unread" if code == 3 else "refused"
    if code == 2:
        details["error"] = (answer.get("error") if isinstance(answer.get("error"), str) else
                            "the wake tool exited %d" % ran.returncode)
    # Reacquire the same inherited description, which may still be locked after failed admission.
    # A fresh descriptor would deadlock with that lock. The pre-spawn obligation stays durable until
    # the normal immutable outcome is committed, preserving the existing public history format.
    admission.check()
    fcntl.flock(admission.fd, fcntl.LOCK_EX)
    admission.check()
    try:
        write_resume_admission(launches, endpoint, identifier, known, admitted_at,
                               not dry_run and answer.get("_admission_attempted") is not False,
                               spawn_failed=answer.get("_spawn_failed") is True)
    except (OSError, ValueError):
        launches.refuse(endpoint, identifier, "resume", "resume admission publication failed; preserve admission evidence and run stop", **known)
    try:
        admission.check()
        record = launches.record(endpoint, identifier, "resume", state, **known, **details)
    except (OSError, ValueError) as exc:
        raise ValueError(wake_failure_text(exc, "resume outcome publication failed; preserve admission evidence and run stop")) from exc
    proof = answer.get("_admission_exit")
    if (isinstance(proof, dict) and proof.keys() == {"wake_id", "driver_pid", "host_pid"} and
            type(proof["host_pid"]) is int and 1 <= proof["host_pid"] <= 2 ** 22 - 1):
        try:
            current = read_running_wake(launches.base, endpoint)
            if (current is not None and current["binding"] == known and
                    all(current[key] == proof[key] for key in ("wake_id", "driver_pid"))):
                require(current["host_pid"] in (None, proof["host_pid"]), "running wake identity changed")
                # The verified private worker witnessed child exit and kernel ESRCH for its group.
                # This terminal fact grants no authority over a reused numeric PID.
                admission.check()
                clear_running_wake(launches.base, endpoint, current)
        except (OSError, ValueError, TypeError):
            details.update(wake={**result, "state": "stop_unconfirmed"},
                           error="running wake retirement unavailable; preserve its evidence and run stop")
            try:
                return 3, launches.record(endpoint, launches.new_id(), "resume", "resumed_unread", **known, **details)
            except (OSError, ValueError) as failure:
                raise ValueError(wake_failure_text(failure, "resume outcome publication failed; preserve admission evidence and run stop")) from failure
    return code, record


def admitted_wake(launches, endpoint, admission, wake_source, dry_run, namespace=None):
    require(type(admission) is int and 0 <= admission < 2 ** 31, ENDPOINT_NAMESPACE_CHANGED)
    with endpoint_namespace(launches.mailbox.root, endpoint, admission=admission) as fence:
        fence.require_manifest(namespace)
        return admitted_wake_locked(launches, endpoint, fence, wake_source, dry_run)


class FencedWakeProcesses:
    """Keep the pinned producer's process boundary private to this one endpoint invocation."""
    def __init__(self, provider, check, created):
        self._provider, self._check, self._created = provider, check, created

    def __getattr__(self, name):
        return getattr(self._provider, name)

    def Popen(self, *args, **kwargs):
        self._check()
        process = self._provider.Popen(*args, **kwargs)
        # Own the returned child before producer log closure or any other caller code can fail.
        self._created(process)
        return process

    def run(self, *args, **kwargs):
        self._check()
        return self._provider.run(*args, **kwargs)


def fenced_wake_turn(launches, endpoint, fence, known, wake, namespace, running, children, released,
                     spawn_failed, spawn_value_failure):
    """Wrap turn creation without qualifying producer no-launch outcomes."""
    import fcntl

    admission, create_turn = fence.fd, wake.start_turn
    def admitted_turn(profile, log_directory, wake_id, prompt):
        spawning, creating = False, False
        try:
            spawning = True
            require(Path(profile["cwd"]).is_dir(), "host spawn failed: profile cwd is unavailable")
            spawning = False
            require_pid_namespace(namespace)
            record = dict(schema="aegis.hierarchy-running-wake/v3", binding=known, wake_id=wake_id,
                          driver_pid=os.getpid(), host_pid=None, snapshot=None, pid_namespace=namespace)
            validate_running_wake(record)
            fence.check()
            publish_wake_record(launches, endpoint, record)
            running.append(record)
            spawning = True
            creating = True
            process, logs = create_turn(profile, log_directory, wake_id, prompt)
            spawning = False
            fence.check()
            # The binding, custody, marker claim, process creation and durable identity are all fenced.
            # finish_turn waits outside that fence, so stop can acquire it.
            fcntl.flock(admission, fcntl.LOCK_UN)
            released.append(True)
        except (ValueError, OSError) as exc:
            if spawning and not children:
                spawn_failed.append(True)
                error = wake_failure_text(exc, "host spawn failed; correct the host executable or cwd and retry resume")
                if isinstance(exc, ValueError) and (creating or error == "embedded null byte"):
                    # The legacy producer's outer handler returns code2 for Popen ValueError. Let its
                    # OSError cleanup remove the claimed mailbox marker, then preserve that public result.
                    spawn_value_failure.append(wake_failure_text(exc,
                        "wake execution failed; inspect its receipts and admission evidence"))
                if running:
                    # Popen has raised before returning a child; its failed exec is already reaped.
                    # Admission is still fenced. Retire only our matching pre-spawn identity.
                    clear_running_wake(launches.base, endpoint, running[0])
                    running.clear()
                raise OSError(error) from exc
            if children:
                try:
                    wake.abandon_turn(children[0])
                except (ValueError, OSError, subprocess.SubprocessError):
                    pass  # The durable admission remains; neither failure authorizes retirement.
            # The pinned producer catches OSError from start_turn, records failed_to_start and drops
            # its wake marker. Descriptor validation errors must enter that same cleanup path.
            raise OSError("running wake publication failed; inspect " +
                          str(launches.folder(endpoint) / ".running-wake")) from exc
        return process, logs

    return admitted_turn


def admitted_wake_locked(launches, endpoint, fence, wake_source, dry_run):
    import fcntl

    admission = fence.fd
    hierarchy_runtime_source.verify(launches.setup, launches.base)
    require(wake_source == str(Path(launches.setup["source"]) / "tools/hierarchy_wake.py"), "invalid wake source")
    known, profile = bound_session(launches, endpoint, launches.new_id(), "resume")
    require(known["host"] != NATIVE, "a native thread is resumed by its own app, not the launcher")
    fence.check()
    fcntl.flock(admission, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fence.check()
    require_resolved_custody(str(launches.base), endpoint)
    require(read_running_wake(launches.base, endpoint) is None, "a turn is in flight; wait for it to finish, or run stop to end it")
    require(len(launches.paths(endpoint)) < MAX_RECORDS, "launch record limit reached for " + endpoint)
    wake = load_wake(launches)
    # Observe without refusing: the producer's no-launch outcomes need no process authority.
    # The process and signal facades require this scope before an actual process operation.
    namespace = current_pid_namespace()
    wake.os = NamespaceOS(wake.os, namespace)
    running, children, released, confirmed, spawn_failed, spawn_value_failure = [], [], [], [], [], []
    def created_child(process):
        # In-memory ownership precedes even identity publication: a publication failure must never
        # turn successful process creation into the no-child failed-spawn path.
        children.append(process)
        fence.check()
        write_running_wake(launches, endpoint, known, running[0]["wake_id"], process.pid, expected=running[0])
    def check_process():
        fence.check()
        require(running_wake_publication_capable(), "running wake atomic publication unsupported on this platform")
        require_pid_namespace(namespace)
    wake.subprocess = FencedWakeProcesses(wake.subprocess, check_process, created_child)
    wake.start_turn = fenced_wake_turn(launches, endpoint, fence, known, wake, namespace, running, children,
                                        released, spawn_failed, spawn_value_failure)
    try:
        code, answer = wake.wake(launches.mailbox.root, launches.setup["delivery_dir"], endpoint, str(profile), dry_run)
    except TypeError:
        # The original producer CLI did not catch TypeError: its parent recorded exit1/no JSON.
        # Preserve that public record without emitting a traceback or an input-bearing exception.
        code, answer = 1, {}
    except (OSError, ValueError, UnicodeError, RecursionError, subprocess.SubprocessError) as exc:
        # Preserve fixed producer refusals without formatting arbitrary exception arguments or input.
        error = wake_failure_text(exc, "wake execution failed; inspect its receipts and admission evidence")
        code, answer = 2, {"error": error}
    finally:
        if running and children and children[0].returncode is not None:
            # stop never waits for the resume driver. Waiting here preserves its pinned read through the
            # stop outcome and cannot deadlock with the producer's already-finished turn.
            def witness_exit():
                fence.check()
                if running_wake_group_exited({**running[0], "host_pid": children[0].pid}):
                    confirmed.append(True)
            try:
                if released:
                    with stop_endpoint_lock(launches.mailbox.root, endpoint, blocking=True) as settlement:
                        settlement.check()
                        witness_exit()
                else:
                    witness_exit()
            except (OSError, ValueError, TypeError, subprocess.SubprocessError):
                pass  # Unconfirmed exit retains admission and returns stop_unconfirmed below.
    if spawn_value_failure:
        code, answer = 2, {"error": spawn_value_failure[-1]}
    if running and code != 2:
        answer = {**answer, "wake_id": running[0]["wake_id"]}
    # Only the producer's two explicit no-launch outcomes rule out admission. Missing/malformed
    # replies and every other failure stay conservative, including background producer failures.
    answer = {**answer, "_admission_attempted": bool(running) or
              not spawn_failed and answer.get("state") not in ("nothing_unread", "dry_run"),
              "_spawn_failed": bool(spawn_failed)}
    if running and not confirmed:
        reason = "running wake admission or group exit is unconfirmed; preserve its evidence and run stop"
        return 3, {**answer, "state": "stop_unconfirmed", "error": reason}
    if confirmed:
        answer = {**answer, "_admission_exit": dict(wake_id=running[0]["wake_id"],
                  driver_pid=running[0]["driver_pid"], host_pid=children[0].pid)}
    return code, answer


def running_wake_group_exited(record):
    """Host exit alone cannot retire an admitted group's unresolved survivors."""
    return process_group_exited(record["host_pid"], running_pid_namespace(record))


class PidNamespaceUnavailable(ValueError):
    def __init__(self, pids=()):
        super().__init__(PID_NAMESPACE_REFUSAL)
        self.pids = sorted(set(pids))


def validate_pid_namespace(value):
    require(isinstance(value, dict) and value.keys() in ({"device", "inode"}, {"device", "inode", "boot"}) and
            type(value["device"]) is int and 0 <= value["device"] < 2 ** 64 and
            type(value["inode"]) is int and 0 < value["inode"] < 2 ** 64,
            "invalid PID namespace identity")
    if value.get("boot") is not None:
        require(isinstance(value["boot"], str) and len(value["boot"]) == 36 and
                re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value["boot"]),
                "invalid PID namespace boot")
    return value


def pid_namespace_boot():
    with directory_descriptor(Path("/proc/sys/kernel/random"), verify=True) as directory:
        descriptor = os.open("boot_id", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            raw = os.read(descriptor, 38)
        finally:
            os.close(descriptor)
    require(len(raw) == 37 and raw[-1:] == b"\n" and
            re.fullmatch(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", raw[:-1]),
            "invalid PID namespace boot")
    return raw[:-1].decode("ascii")


def pid_namespace_probe():
    """Pin trusted procfs directories; only the kernel's namespace magic link is followed."""
    if not launch_descriptor_capable():
        return None
    try:
        pid = os.getpid()
        with directory_descriptor(Path("/proc"), verify=True) as proc:
            if os.readlink("self", dir_fd=proc) != str(pid):
                return None
            process = os.open(str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=proc)
            try:
                status = os.open("status", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=process)
                try:
                    raw = bytearray()
                    while True:
                        chunk = os.read(status, min(4096, 65537 - len(raw)))
                        if not chunk:
                            break
                        require(len(raw) + len(chunk) <= 65536, "procfs status exceeds namespace probe limit")
                        raw.extend(chunk)
                finally:
                    os.close(status)
                namespace_pids = [line.split(None, 2) for line in raw.splitlines() if line.startswith(b"NSpid:")]
                if namespace_pids != [[b"NSpid:", str(pid).encode("ascii")]]:
                    return None  # Ancestor procfs can coincidentally expose the same numeric PID.
                namespace = os.open("ns", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=process)
                try:
                    identity = os.stat("pid", dir_fd=namespace)
                    if os.getpid() != pid or os.readlink("self", dir_fd=proc) != str(pid):
                        return None
                    return dict(device=identity.st_dev, inode=identity.st_ino, procfs_pid=pid,
                                boot=pid_namespace_boot())
                finally:
                    os.close(namespace)
            finally:
                os.close(process)
    except (OSError, ValueError, AttributeError, NotImplementedError):
        return None


def current_pid_namespace():
    try:
        probe = pid_namespace_probe()
        if (not isinstance(probe, dict) or probe.keys() != {"device", "inode", "procfs_pid", "boot"} or
                type(probe["procfs_pid"]) is not int or probe["procfs_pid"] != os.getpid() or probe["boot"] is None):
            return None
        return validate_pid_namespace({key: probe[key] for key in ("device", "inode", "boot")})
    except (OSError, ValueError, TypeError, KeyError):
        return None


def require_pid_namespace(expected=CURRENT_PID_NAMESPACE, pids=()):
    current = current_pid_namespace()
    if current is None or expected is not CURRENT_PID_NAMESPACE and expected != current:
        raise PidNamespaceUnavailable(pids)
    return current


def running_pid_namespace(record):
    return record.get("pid_namespace") if record.get("schema") == "aegis.hierarchy-running-wake/v3" else None


class NamespaceOS:
    """An invocation-private guard for the pinned producer's group signals and existence probes."""
    def __init__(self, provider, namespace):
        self._provider, self._namespace = provider, namespace
    def __getattr__(self, name):
        return getattr(self._provider, name)
    def kill(self, pid, number):
        require_pid_namespace(self._namespace)
        try:
            result = self._provider.kill(pid, number)
        except OSError:
            require_pid_namespace(self._namespace)
            raise
        require_pid_namespace(self._namespace)
        return result
    def killpg(self, group, number):
        require_pid_namespace(self._namespace)
        try:
            result = self._provider.killpg(group, number)
        except OSError:
            require_pid_namespace(self._namespace)
            raise
        require_pid_namespace(self._namespace)
        return result


def process_group_exited(group, namespace=CURRENT_PID_NAMESPACE):
    """Only a kernel ESRCH proves group absence; enumeration cannot close a fork/exit race."""
    namespace = require_pid_namespace(namespace)
    try:
        os.killpg(group, 0)
    except OSError as exc:
        require_pid_namespace(namespace)
        return exc.errno == errno.ESRCH
    require_pid_namespace(namespace)
    return False


def retained_groups_exited(observed):
    require(len(observed.get("owned_groups", ())) <= MAX_RECORDS, "stop custody exceeds group limit")
    namespace = observed.get("pid_namespace")
    require_pid_namespace(namespace)
    pending = sorted(group for group in observed.get("owned_groups", ()) if not process_group_exited(group, namespace))
    observed["unresolved_groups"] = pending
    return not pending


def running_wake_publication_capable():
    return launch_descriptor_capable() and RUNNING_PUBLICATION_CAPS


def resume_admission_name(identifier):
    return (isinstance(identifier, str) and len(identifier) == 55 and
            re.fullmatch(r"[0-9]{8}T[0-9]{12}Z-[0-9a-f]{32}", identifier) is not None)


def validate_resume_admission(record):
    StopCustody.exact_fields(record, ("schema", "binding", "at", "admission_attempted",
                                     *(("failure",) if isinstance(record, dict) and "failure" in record else ())))
    require(record.get("failure") in (None, "host spawn failed"), "invalid resume admission failure")
    require(record["schema"] == "aegis.hierarchy-resume-admission/v1" and
            type(record["admission_attempted"]) is bool and isinstance(record["at"], str) and
            re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z", record["at"]) is not None,
            "invalid resume admission")
    StopCustody.exact_fields(record["binding"], ("host", "session", "generation"))
    require(record["binding"]["host"] in hierarchy_hosts.TEAM_HOSTS, "invalid resume admission host")
    text(record["binding"]["session"], "resume admission session", 256)
    integer(record["binding"]["generation"], "resume admission generation", maximum=2 ** 31 - 1)
    return record


def read_resume_admission(base, endpoint, identifier):
    """Legacy histories have no sidecar. New metadata never changes their public record shape."""
    endpoint_parts(endpoint)
    if not resume_admission_name(identifier):
        return None
    require(launch_descriptor_capable(), "resume admission descriptors unsupported on this platform")
    folder = Path(base) / "launches" / quoted(endpoint) / ".resume-admissions"
    try:
        with directory_descriptor(folder, verify=True) as directory:
            fd = os.open(identifier, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with descriptor_stream(fd, "rb") as stream:
                before = os.fstat(fd)
                StopCustody.private(before)
                require(before.st_size <= 4096, "resume admission exceeds evidence limit")
                raw = stream.read(4097)
                require(len(raw) <= 4096 and StopCustody.identity(os.fstat(fd)) == StopCustody.identity(before),
                        "resume admission changed or exceeds evidence limit")
                require(StopCustody.identity(os.stat(identifier, dir_fd=directory, follow_symlinks=False)) ==
                        StopCustody.identity(before), "resume admission replaced while reading")
        return validate_resume_admission(metadata_json(raw, "launch record"))
    except FileNotFoundError:
        return None


def write_resume_admission(launches, endpoint, identifier, known, at, attempted, spawn_failed=False):
    require(launch_descriptor_capable(), "resume admission descriptors unsupported on this platform")
    require(resume_admission_name(identifier), "invalid resume admission identity")
    record = validate_resume_admission(dict(schema="aegis.hierarchy-resume-admission/v1", binding=known,
                                           at=at, admission_attempted=attempted,
                                           **({"failure": "host spawn failed"} if spawn_failed else {})))
    raw = json.dumps(record, sort_keys=True).encode("ascii")  # Every scalar was bounded above.
    require(len(raw) <= 4096, "resume admission exceeds evidence limit")
    folder = launches.folder(endpoint) / ".resume-admissions"
    with directory_descriptor(folder, create=True, durable_from=launches.base / "launches", verify=True) as directory:
        previous = read_resume_admission(launches.base, endpoint, identifier)
        require(previous is None or previous["binding"] == known and previous["at"] == at,
                "resume admission identity changed")
        temporary = ".admission-" + uuid.uuid4().hex
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with descriptor_stream(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(fd)
            os.rename(temporary, identifier, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
    return record


def write_running_wake(launches, endpoint, known, wake_id, pid, expected=None):
    require(running_wake_publication_capable(), "running wake atomic publication unsupported on this platform")
    namespace = require_pid_namespace(running_pid_namespace(expected) if expected is not None else CURRENT_PID_NAMESPACE)
    observation = read_process(pid)
    row = observation.snapshot if observation.kind == "PRESENT" else None
    record = dict(schema="aegis.hierarchy-running-wake/v3", binding=known, wake_id=wake_id,
                  driver_pid=os.getpid(), host_pid=pid, pid_namespace=namespace,
                  snapshot=StopCustody.encode(process_identity(row)._asdict()) if row is not None else None)
    # Validate every field before serialization. A missing strong provider records no signal authority.
    validate_running_wake(record)
    require_pid_namespace(namespace)
    publish_wake_record(launches, endpoint, record, expected=expected)
    return record


@contextmanager
def descriptor_stream(fd, mode):
    """Own the descriptor even if constructing its non-owning stream fails."""
    try:
        with os.fdopen(fd, mode, closefd=False) as stream:
            yield stream
    finally:
        os.close(fd)


def publish_wake_record(launches, endpoint, record, expected=None):
    require(running_wake_publication_capable(), "running wake atomic publication unsupported on this platform")
    validate_running_wake(record)  # Bound every field before allocating its serialized representation.
    name = ".running-wake"
    raw = json.dumps(record, sort_keys=True).encode("ascii")
    require(len(raw) <= 262144, "running wake exceeds evidence limit")
    with directory_descriptor(launches.folder(endpoint), create=True, durable_from=launches.base / "launches",
                              verify=True):
        with launch_directory(launches.base, endpoint) as directory:
            temporary, published, identity = ".running-wake-" + uuid.uuid4().hex + ".tmp", False, None
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                with descriptor_stream(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                    written = os.fstat(stream.fileno())
                    identity = written.st_dev, written.st_ino
                    if expected is None:
                        os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                    else:
                        require(read_running_wake(launches.base, endpoint) == expected, "running wake identity changed")
                        os.rename(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
                    published = True
                    if expected is None:
                        os.unlink(temporary, dir_fd=directory)
                    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    require(stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity and
                            current.st_size == len(raw), "running wake changed during publication")
                    os.fsync(directory)
            except BaseException:
                if published and expected is None:
                    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    require((current.st_dev, current.st_ino) == identity, "running wake replaced during publication")
                    os.unlink(name, dir_fd=directory)
                raise
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass


def validate_running_wake(record):
    StopCustody.exact_fields(record, ("schema", "binding", "wake_id", "driver_pid", "host_pid", "snapshot",
                            *(("pid_namespace",) if isinstance(record, dict) and "pid_namespace" in record else ())))
    require(record["schema"] in ("aegis.hierarchy-running-wake/v1", "aegis.hierarchy-running-wake/v2",
                                "aegis.hierarchy-running-wake/v3"),
            "invalid running wake")
    StopCustody.exact_fields(record["binding"], ("host", "session", "generation"))
    require(record["binding"]["host"] in hierarchy_hosts.TEAM_HOSTS, "invalid running wake host")
    text(record["binding"]["session"], "running wake session", 256)
    integer(record["binding"]["generation"], "running wake generation", maximum=2 ** 31 - 1)
    require(isinstance(record["wake_id"], str) and re.fullmatch("wake-[0-9a-f]{32}", record["wake_id"]) is not None,
            "invalid running wake identity")
    integer(record["driver_pid"], "running wake pid", maximum=2 ** 22 - 1)
    if record.get("pid_namespace") is not None:
        validate_pid_namespace(record["pid_namespace"])
    if record["schema"] == "aegis.hierarchy-running-wake/v2":
        require(record["host_pid"] is None and record["snapshot"] is None, "invalid wake admission")
    elif record["schema"] != "aegis.hierarchy-running-wake/v3" or record["host_pid"] is not None:
        integer(record["host_pid"], "running wake pid", maximum=2 ** 22 - 1)
    else:
        require(record["snapshot"] is None, "invalid wake admission")
    if record["snapshot"] is not None:
        facts = StopCustody.decode(record["snapshot"])
        names = StoredProcess._fields if record["schema"] == "aegis.hierarchy-running-wake/v1" else ProcessIdentity._fields
        require(facts.keys() == set(names) and facts["pid"] == record["host_pid"],
                "invalid running wake snapshot")
    return record


def read_running_wake(base, endpoint):
    try:
        raw = read_launch_record(base, endpoint, ".running-wake")
        return validate_running_wake(metadata_json(raw, "launch record")) if raw is not None else None
    except (ValueError, OSError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        raise ValueError(running_wake_recovery(base, endpoint)) from exc


def running_wake_recovery(base, endpoint):
    import shlex

    path = Path(base) / "launches" / quoted(endpoint) / ".running-wake"
    recovery = Path(base) / ("reconciled-running-wake-" + quoted(endpoint) + ".json")
    return ("running wake unavailable: %s; manual recovery: preserve this file, verify the admitted "
            "child and all process-group descendants have exited, then archive with %s and retry stop" %
            (path, shlex.join(["mv", "-i", "--", str(path), str(recovery)])))


def clear_running_wake(base, endpoint, expected):
    with launch_directory(base, endpoint) as directory:
        current = read_running_wake(base, endpoint)
        if current is None:
            return
        require(current == expected, "running wake identity changed")
        require_pid_namespace(running_pid_namespace(current))
        os.unlink(".running-wake", dir_fd=directory)
        os.fsync(directory)


@contextmanager
def launch_directory(base, endpoint):
    """Pin every edge through enumeration/read, including the witness for legacy absence."""
    require(launch_descriptor_capable(), "launch record descriptors unsupported on this platform")
    endpoint_parts(endpoint)
    base = Path(base)
    require(base.is_absolute() and ".." not in base.parts, "invalid launch directory")
    parts = (*base.parts[1:], "launches", quoted(endpoint))
    descriptors, edges, missing = [], [], None
    try:
        descriptors.append(os.open(base.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for index, part in enumerate(parts):
            parent = descriptors[-1]
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                if index < len(base.parts) - 1:
                    raise
                missing = parent, part
                break
            descriptors.append(child)
            info = os.fstat(child)
            edges.append((parent, part, (info.st_dev, info.st_ino)))
        yield None if missing else descriptors[-1]
        for parent, name, identity in edges:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == identity,
                    "launch directory changed while reading")
        if missing:
            try:
                os.stat(missing[1], dir_fd=missing[0], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError("launch directory appeared while reading")
    except OSError as exc:
        reason = ": symlink or non-directory" if exc.errno in (errno.ELOOP, errno.ENOTDIR) else ""
        raise ValueError("launch directory unreadable" + reason) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def launch_descriptor_capable():
    return os.name == "posix" and LAUNCH_DESCRIPTOR_CAPS


class LaunchRecordLimit(ValueError):
    """A bounded directory scan can report overflow without retaining more than MAX_RECORDS paths."""

    def __init__(self, endpoint, count):
        super().__init__("launch record limit reached for " + endpoint)
        self.count = count


def launch_record_paths(base, endpoint):
    folder, paths, records = Path(base) / "launches" / quoted(endpoint), [], 0
    with launch_directory(base, endpoint) as directory:
        if directory is not None:
            with os.scandir(directory) as entries:
                for count, entry in enumerate(entries):
                    require(count < MAX_RECORDS + 64, "launch directory entry limit reached")
                    if entry.name.endswith(".json"):
                        info = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                        require(stat.S_ISREG(info.st_mode), "invalid launch record entry")
                        records += 1
                        if records <= MAX_RECORDS:
                            paths.append(folder / entry.name)
    if records > MAX_RECORDS:
        raise LaunchRecordLimit(endpoint, records)
    return sorted(paths)


def read_launch_record(base, endpoint, name):
    require(isinstance(name, str) and len(name) <= 255 and "\0" not in name and
            (name.endswith(".json") or name == ".running-wake") and name == Path(name).name,
            "invalid launch record name")
    with launch_directory(base, endpoint) as directory:
        if name == ".running-wake" and directory is None:
            return None
        require(directory is not None, "launch directory disappeared while reading")
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            if name == ".running-wake":
                return None
            raise
        try:
            info = os.fstat(fd)
            if name == ".running-wake":
                StopCustody.private(info)
            require(stat.S_ISREG(info.st_mode) and info.st_size <= 262144, "launch record exceeds evidence limit")
            with descriptor_stream(os.dup(fd), "rb") as stream:
                raw = stream.read(262145)
            require(len(raw) <= 262144 and StopCustody.identity(os.fstat(fd)) == StopCustody.identity(info),
                    "launch record changed or exceeds evidence limit")
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(StopCustody.identity(current) == StopCustody.identity(info), "launch record replaced while reading")
            return raw
        finally:
            os.close(fd)


def metadata_json(raw, label):
    """Bound bytes and numeric tokens before parsing; errors never repeat untrusted keys/values."""
    require(label in ("launch record", "stop custody", "endpoint namespace"), "invalid metadata kind")
    require(isinstance(raw, bytes) and len(raw) <= 262144, "invalid " + label + " JSON")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    def integer_token(value):
        if len(value.lstrip("-")) > 128:
            raise ValueError("integer token limit")
        return int(value)
    def float_token(value):
        if len(value) > 128:
            raise ValueError("float token limit")
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("non-finite number")
        return number
    def constant(_value):
        raise ValueError("non-finite number")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_int=integer_token,
                          parse_float=float_token, parse_constant=constant)
    except json.JSONDecodeError as exc:
        # Preserve fixed stdlib syntax diagnostics and numeric coordinates, never arbitrary decoder text:
        # the Python string decoder can embed an offending input character in some error messages.
        safe_syntax = ("Expecting property name enclosed in double quotes", "Expecting value",
                       "Expecting ':' delimiter", "Expecting ',' delimiter", "Extra data",
                       "Unterminated string starting at", "Invalid \\uXXXX escape")
        if exc.msg in safe_syntax:
            raise ValueError("%s: line %d column %d (char %d)" %
                             (exc.msg, exc.lineno, exc.colno, exc.pos)) from None
        raise ValueError("invalid " + label + " JSON") from None
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("invalid " + label + " JSON") from None


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
    def __init__(self, rows, argv_boundaries, unavailable=None, complete=True, births=None, identities=None):
        super().__init__(rows)
        self.argv_boundaries = argv_boundaries
        self.unavailable = unavailable or {}
        self.complete = complete
        self.births = {} if births is None else births
        self.identities = {} if identities is None else identities
        for row in self:
            self.births.setdefault(row.pid, set()).add(row.start_time)
            remember_census_identity(self.identities, process_identity(row))
        for pid, observation in self.unavailable.items():
            facts = observation.partial or {}
            if facts.get("coherent_birth") and facts.get("start_time"):
                self.births.setdefault(pid, set()).add(facts["start_time"])
                if any(type(facts.get(key)) is int for key in ("uid", "euid")):
                    remember_census_identity(self.identities, IdentityWitness(pid, facts["start_time"],
                        facts.get("uid"), facts.get("euid")))


@contextmanager
def directory_descriptor(path, create=False, durable_from=None, verify=False, witnesses=None):
    """Pin every directory in the chain. A pathname check cannot protect a subsequent open."""
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "invalid directory path")
    if witnesses is not None:
        require(len(path.parts) <= MAX_NAMESPACE_DEPTH, "endpoint namespace exceeds depth limit")
        verify = True
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptors, edges = [fd] if verify else [], []
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
            if verify:
                descriptors.append(child)
                info = os.fstat(child)
                edges.append((fd, part, (info.st_dev, info.st_ino)))
            else:
                os.close(fd)
            fd = child
        if witnesses is not None:
            witnesses.extend(edges)
        yield fd
        for parent, name, identity in edges if witnesses is None else ():
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == identity,
                    "directory namespace changed while inspecting")
    finally:
        for descriptor in reversed(descriptors) if verify else (fd,):
            os.close(descriptor)


class EndpointFence:
    """The locked descriptor and every witnessed namespace edge; no global descriptor registry."""
    def __init__(self, descriptor, directory, edges, anchor):
        self.fd, self.directory, self.edges, self.anchor = descriptor, directory, tuple(edges), anchor
        root = os.fstat(edges[0][0] if edges else directory)
        self.identities = ((root.st_dev, root.st_ino), *(identity for _, _, identity in edges))
        require(len(self.identities) <= MAX_NAMESPACE_DEPTH and all(
            type(value) is int and 0 <= value < 2 ** 64 for pair in self.identities for value in pair),
            ENDPOINT_NAMESPACE_CHANGED)

    def __index__(self):
        return self.fd

    def __str__(self):
        return str(self.fd)

    def fileno(self):
        return self.fd

    def check(self):
        try:
            root = os.stat(self.anchor, follow_symlinks=False)
            require(stat.S_ISDIR(root.st_mode) and (root.st_dev, root.st_ino) == self.identities[0],
                    ENDPOINT_NAMESPACE_CHANGED)
            for index, (parent, name, identity) in enumerate(self.edges):
                held = os.fstat(parent)
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require((held.st_dev, held.st_ino) == self.identities[index] and
                        stat.S_ISDIR(current.st_mode) and (current.st_dev, current.st_ino) == identity,
                        ENDPOINT_NAMESPACE_CHANGED)
            locked, directory = os.fstat(self.fd), os.fstat(self.directory)
            require(stat.S_ISDIR(locked.st_mode) and (locked.st_dev, locked.st_ino) ==
                    (directory.st_dev, directory.st_ino) == self.identities[-1], ENDPOINT_NAMESPACE_CHANGED)
        except (OSError, ValueError):
            raise ValueError(ENDPOINT_NAMESPACE_CHANGED) from None

    def manifest(self):
        # Depth and uint64 scalar bounds precede serialization; the maximum is below32768 bytes.
        return json.dumps(self.identities, separators=(",", ":"))

    def require_manifest(self, raw):
        try:
            require(isinstance(raw, str) and len(raw) <= MAX_NAMESPACE_MANIFEST and raw.isascii(),
                    ENDPOINT_NAMESPACE_CHANGED)
            value = metadata_json(raw.encode("ascii"), "endpoint namespace")
            require(isinstance(value, list) and len(value) == len(self.identities) and all(
                isinstance(pair, list) and len(pair) == 2 and all(
                    type(number) is int and 0 <= number < 2 ** 64 for number in pair) for pair in value),
                ENDPOINT_NAMESPACE_CHANGED)
            require(tuple(tuple(pair) for pair in value) == self.identities, ENDPOINT_NAMESPACE_CHANGED)
        except (ValueError, TypeError, RecursionError):
            raise ValueError(ENDPOINT_NAMESPACE_CHANGED) from None


@contextmanager
def directory_fence(path, create=False, admission=None):
    require(launch_descriptor_capable(), "endpoint namespace descriptors unsupported on this platform")
    path, edges = Path(path), []
    with ExitStack() as stack:
        try:
            directory = stack.enter_context(directory_descriptor(path, create=create, witnesses=edges))
            descriptor = directory if admission is None else admission
            fence = EndpointFence(descriptor, directory, edges, path.anchor)
        except OSError:
            raise ValueError(ENDPOINT_NAMESPACE_CHANGED) from None
        fence.check()
        yield fence
        fence.check()


@contextmanager
def endpoint_namespace(root, endpoint, create=False, admission=None):
    endpoint_parts(endpoint)
    with directory_fence(Path(root) / "bindings" / endpoint, create=create, admission=admission) as fence:
        yield fence


def mailbox_wake_inspection_capable():
    return launch_descriptor_capable() and MAILBOX_WAKE_STAT_CAPS


def mailbox_wake_pending(mailbox, endpoint):
    """Inspect admission, never marker content or its symlink target. Call under the writer fence."""
    require(mailbox_wake_inspection_capable(), "mailbox wake inspection unsupported on this platform; "
            "preserve the worktree and reconcile the marker manually")
    endpoint_parts(endpoint)
    try:
        with directory_descriptor(mailbox.root, verify=True) as directory:
            try:
                os.stat(".wake-" + quoted(endpoint) + ".lock", dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return False
            return True
    except (ValueError, OSError) as exc:
        raise ValueError("mailbox wake inspection unavailable; preserve the worktree and reconcile the producer "
                         "and marker before retrying") from exc


@contextmanager
def stop_endpoint_lock(root, endpoint, create=False, blocking=False):
    """Shared with handoff. Lock order: mailbox writer (handoff only), endpoint, custody.

    Bindings already have a directory. Locking that inode creates no file for an otherwise no-op stop.
    Direct mailbox bind/draft callers are outside this serialization contract.
    """
    with endpoint_namespace(root, endpoint, create=create) as fence:
        import fcntl
        try:
            fcntl.flock(fence.fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError as exc:
            raise ValueError("stop custody endpoint is busy: " + endpoint) from exc
        fence.check()
        yield fence


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
    if unresolved_stop_custody(base, endpoint):
        retained = StopCustody(base, endpoint, None, create=False).read()
        lost = retained is not None and any(entry["identity_lost"] for entry, _, _ in retained[1])
        blocked = retained is not None and any(entry["blocked"] and not entry["resolved"] for entry, _, _ in retained[1])
        cause = "original process identity lost" if lost else "original process identity blocked" if blocked else None
        raise ValueError(custody_refusal(base, endpoint, cause))


@contextmanager
def recorded_endpoint_lock(launches, endpoint, identifier, action, known, **options):
    """Record admission failures without catching an outcome from inside the admitted operation."""
    with ExitStack() as stack:
        try:
            admission = stack.enter_context(stop_endpoint_lock(launches.mailbox.root, endpoint, **options))
        except (OSError, ValueError) as exc:
            launches.refuse(endpoint, identifier, action, str(exc), **known)
        yield admission


def recorded_custody_check(launches, endpoint, identifier, action, known):
    try:
        require_resolved_custody(str(launches.base), endpoint)
    except (OSError, ValueError) as exc:
        launches.refuse(endpoint, identifier, action, str(exc), **known)


@contextmanager
def custody_namespace(base, endpoint):
    """Portable absence requires real directories at every component; unknown never means absent.

    Readers need no POSIX descriptor flags for a legacy absent namespace. The pinned reader/writer still
    uses no-follow descriptors once present. Recheck every witnessed edge before accepting absence/read.
    """
    current, seen, present = Path(base), [], True
    try:
        for part in (None, "launches", quoted(endpoint), ".stop-custody"):
            if part is not None:
                current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                present = False
                break
            require(stat.S_ISDIR(info.st_mode), "stop custody namespace is not a real directory: " + str(current))
            seen.append((current, (info.st_dev, info.st_ino)))
        yield present
    finally:
        for path, identity in seen:
            try:
                info = path.lstat()
            except FileNotFoundError as exc:
                raise ValueError("stop custody namespace changed") from exc
            require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == identity,
                    "stop custody namespace changed")


class CustodyExitUnproven(ValueError):
    """A writable terminal claim cannot discharge an occupied or unreadable process identity."""

    def __init__(self, base, endpoint, pid, attempted, unsupported=False):
        self.pids = sorted(set(attempted))
        reason = ("stop custody unsupported on hidepid/restricted procfs; use an unrestricted process view "
                  "or reconcile this endpoint manually" if unsupported else
                  "resolved stop custody lacks physical exit proof for pid %d" % pid)
        super().__init__(custody_refusal(base, endpoint, reason))


class StopCustody:
    """Endpoint-local, pre-effect custody. A lost launcher must not lose a possibly signalled orphan.

    Descriptors cannot survive a new invocation. Recovery therefore uses the original boot/birth/raw/UID
    evidence and retains the numeric-PID residual race; an observed replacement latches loss of identity.
    The lock serializes read/merge/write, and the hidden subdirectory is outside immutable launch records.
    """

    def __init__(self, launches, endpoint, binding, create=True):
        self.base = launches.base if isinstance(launches, Launches) else safe_path(launches)
        self.endpoint = endpoint
        self.folder = safe_path(self.base / "launches" / quoted(endpoint) / ".stop-custody")
        self.path, self.binding = self.folder / "state.json", binding
        self.fd, self.directory_fd, self.parent_fd = None, None, None
        self.namespace = []
        self.entered = False

    def __enter__(self):
        self.entered = True
        return self

    @contextmanager
    def read_directory(self):
        if self.directory_fd is not None:
            yield self.directory_fd
        else:
            with directory_descriptor(self.folder) as directory:
                yield directory

    def prepare(self):
        if self.directory_fd is None:
            # Keep every edge, not only the endpoint inode: its ancestors can be renamed/replaced too.
            fd = os.open(self.folder.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.namespace.append((self.folder.anchor, fd))
            current = Path(self.folder.anchor)
            for part in self.folder.parts[1:]:
                current = current / part
                made = False
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                else:
                    made = True
                durable = self.folder.parent.parent
                if made or current == durable or durable in current.parents:
                    os.fsync(fd)
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                self.namespace.append((part, fd))
            self.parent_fd, self.directory_fd = self.namespace[-2][1], self.namespace[-1][1]
        info = os.fstat(self.directory_fd)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                "invalid stop custody directory")
        self.check_namespace()

    def check_namespace(self):
        for index in range(1, len(self.namespace)):
            name, child = self.namespace[index]
            try:
                info = os.stat(name, dir_fd=self.namespace[index - 1][1], follow_symlinks=False)
            except FileNotFoundError as exc:
                raise ValueError("stop custody namespace changed") from exc
            require(stat.S_ISDIR(info.st_mode) and self.directory_identity(info) ==
                    self.directory_identity(os.fstat(child)), "stop custody namespace changed")

    def lock(self):
        # Only the POSIX stop writer needs flock; read-only consumers must remain importable without it.
        import fcntl

        with self.read_directory() as directory:
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
        for _, descriptor in reversed(self.namespace):
            os.close(descriptor)

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
        facts = dict(facts)
        facts.pop("argv", None)
        raw = facts.pop("cmdline", None)
        if raw is not None:
            facts["cmdline_sha256"] = hashlib.sha256(raw).hexdigest()
        return facts

    @staticmethod
    def decode(facts):
        require(isinstance(facts, dict), "invalid stop custody evidence")
        allowed = set(StoredProcess._fields) | {"coherent_birth", "exit_observed"}
        require(facts.keys() <= allowed, "unexpected stop custody evidence")
        facts = dict(facts)
        for key, value in facts.items():
            if key in ("pid", "pgid", "ppid", "uid", "euid"):
                ceiling = (2 ** 22) - 1 if key in ("pid", "pgid", "ppid") else (2 ** 32) - 2
                require(type(value) is int and (1 if key == "pid" else 0) <= value <= ceiling,
                        "invalid stop custody " + key)
            elif key in ("coherent_birth", "exit_observed"):
                require(type(value) is bool, "invalid stop custody " + key)
            elif key == "cmdline_sha256":
                require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
                        "invalid stop custody cmdline digest")
            elif key == "state":
                require(isinstance(value, str) and value in tuple("RSDZTtXxKWPI") and len(value) == 1,
                        "invalid stop custody state")
            elif key == "start_time":
                require(isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value) is not None and
                        0 < int(value) < 2 ** 64,
                        "invalid stop custody start_time")
            else:
                require(isinstance(value, str) and value and "\0" not in value, "invalid stop custody " + key)
        return facts

    def read(self):
        try:
            return self.read_evidence()
        except (PidNamespaceUnavailable, CustodyExitUnproven):
            raise
        except (ValueError, OSError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
            raise ValueError(custody_refusal(self.base, self.endpoint, exc)) from exc

    def read_evidence(self):
        with custody_namespace(self.base, self.endpoint) as present:
            if not present:
                return None
            return self.read_pinned_evidence()

    def read_pinned_evidence(self):
        """Read and validate without creating a directory/lock or interpreting unreadability as absence."""
        try:
            with self.read_directory() as directory:
                directory_info = os.fstat(directory)
                require(directory_info.st_uid == os.geteuid() and stat.S_IMODE(directory_info.st_mode) == 0o700,
                        "invalid stop custody directory")
                try:
                    # Existence is only a race witness, never a permission/identity grant for parsed bytes.
                    os.stat("state.json", dir_fd=directory, follow_symlinks=False)
                    try:
                        fd = os.open("state.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                    except FileNotFoundError as exc:
                        raise ValueError("stop custody disappeared while reading") from exc
                    try:
                        info = os.fstat(fd)
                        self.private(info)
                        require(info.st_size <= 262144, "invalid stop custody bytes: bounded ASCII required")
                        with descriptor_stream(os.dup(fd), "rb") as stream:
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
        saved = metadata_json(raw, "stop custody")
        entries = self.decode_record(saved)
        namespace = saved.get("pid_namespace")
        attempted = [entry["pid"] for entry, _, _ in entries if entry["attempted"]]
        require_pid_namespace(namespace, attempted)
        boot = self.boot()
        # An unproven provider cannot renew signal authority. Qualified absence remains independently usable.
        if boot is not None and saved["boot"] != boot:
            require(not saved["active"], "stop custody boot changed with active evidence: " + str(self.path))
        for entry, expected, partial in entries:
            if not entry["resolved"]:
                continue
            require_pid_namespace(namespace, attempted)
            birth = expected.start_time if expected is not None else (
                partial.get("start_time") if partial.get("coherent_birth") else None)
            current = read_process(entry["pid"])
            require_pid_namespace(namespace, attempted)
            if not procfs_exit_evidence_supported(current):
                raise CustodyExitUnproven(self.base, self.endpoint, entry["pid"], attempted, unsupported=True)
            if current.kind == "CONFIRMED_ABSENT":
                continue
            row = current.snapshot if current.kind == "PRESENT" else None
            original = expected._asdict() if expected is not None else partial
            if (row is not None and birth is not None and row.start_time == birth and row.state.startswith("Z") and
                    all(original.get(key) is None or original[key] == getattr(row, key) for key in ("uid", "euid"))):
                continue
            facts = current.partial or {}
            if (birth is not None and facts.get("coherent_birth") and facts.get("start_time") == birth and
                    facts.get("exit_observed") and all(original.get(key) is None or facts.get(key) is None or
                        original[key] == facts[key] for key in ("uid", "euid"))):
                continue
            # A journal can invent a different birth or a birthless ESRCH claim. Even honest PID
            # reuse needs reconciliation while occupied; only absence or this original's exit counts.
            raise CustodyExitUnproven(self.base, self.endpoint, entry["pid"], attempted)
        require_pid_namespace(namespace, attempted)
        return saved, entries

    def decode_record(self, saved):
        """One schema for every publication and read; physical exit validation remains read-time work."""
        self.exact_fields(saved, ("schema", "binding", "boot", "active", "entries", "coverage",
                                 *(("pid_namespace",) if isinstance(saved, dict) and "pid_namespace" in saved else ()),
                                 *(("groups",) if isinstance(saved, dict) and "groups" in saved else ())))
        if saved.get("pid_namespace") is not None:
            validate_pid_namespace(saved["pid_namespace"])
        groups = saved.get("groups", [])
        require(isinstance(groups, list) and len(groups) <= MAX_RECORDS and
                all(type(group) is int and 0 < group < 2 ** 22 for group in groups) and
                groups == sorted(set(groups)), "invalid stop custody groups")
        require(saved["schema"] == "aegis.hierarchy-stop-custody/v2" and type(saved["active"]) is bool and
                isinstance(saved["entries"], list) and len(saved["entries"]) <= MAX_RECORDS and
                saved["coverage"] in STOP_COVERAGE, "invalid stop custody")
        require(saved["boot"] is None or (isinstance(saved["boot"], str) and saved["boot"]),
                "stop custody boot identity unavailable")
        self.exact_fields(saved["binding"], ("host", "session", "generation"))
        require(saved["binding"]["host"] in hierarchy_hosts.TEAM_HOSTS and
                text(saved["binding"]["session"], "stop custody session", 256),
                "invalid stop custody binding")
        integer(saved["binding"]["generation"], "stop custody generation", maximum=2 ** 31 - 1)
        entries, seen, previous = [], set(), {}
        for entry in saved["entries"]:
            self.exact_fields(entry, ("pid", "snapshot", "partial", "attempted", "blocked", "identity_lost", "resolved"))
            pid = entry["pid"]
            require(type(pid) is int and 0 < pid < 2 ** 22, "invalid stop custody pid")
            require(all(type(entry[key]) is bool for key in ("attempted", "blocked", "identity_lost")) and
                    (entry["resolved"] is None or entry["resolved"] in STOP_EXIT_PROOFS), "invalid stop custody state")
            facts = self.decode(entry["snapshot"]) if entry["snapshot"] is not None else None
            if facts is not None:
                require(facts.keys() == set(StoredProcess._fields) and facts["pid"] == pid,
                        "invalid stop custody snapshot")
            require(not entry["attempted"] or facts is not None, "attempted stop custody has no identity")
            partial = self.decode(entry["partial"])
            key = custody_instance(entry)
            require(key not in seen and (pid not in previous or previous[pid]), "invalid stop custody pid")
            seen.add(key)
            previous[pid] = bool(entry["resolved"])
            entries.append((entry, StoredProcess(**facts) if facts is not None else None, partial))
        # Inactive evidence is still validated. A corrupt file is never an absent configuration.
        if not saved["active"]:
            require(not groups and saved["coverage"] is None and all(entry["resolved"] for entry, _, _ in entries),
                    "inactive stop custody has unresolved evidence")
        return entries

    @staticmethod
    def exact_fields(record, names):
        require(isinstance(record, dict) and record.keys() == set(names), "invalid stop custody fields")

    def restore(self, observed, attempted):
        fresh = {key: observed[key] for key in ("census", "argv_boundaries")}
        fresh.update({key: dict(observed[key]) for key in ("candidates", "initial_unavailable", "unresolved")})
        retained = self.read()
        if retained is None:
            return
        saved, entries = retained
        require_pid_namespace(saved.get("pid_namespace"))
        require_pid_namespace(observed.get("pid_namespace", CURRENT_PID_NAMESPACE))
        observed["pid_namespace"] = saved["pid_namespace"]
        observed["committed_exits"] = {custody_instance(entry) for entry, _, _ in entries if entry["resolved"]}
        observed["retained_custody"] = True
        observed["custody_boot"] = saved["boot"]
        observed["retained_exit_evidence"] = bool(entries) and not saved["active"]
        if not saved["active"]:
            return
        observed["retained_active"] = True
        for group in saved.get("groups", ()):
            retain_group(observed, group)
        observed["recovered"] = {entry["pid"] for entry, _, _ in entries if entry["attempted"]}
        observed["checkpoint_pending"] = True
        require(saved["binding"] == self.binding,
                custody_refusal(self.base, self.endpoint, "unresolved stop custody belongs to another binding"))
        # The durable ledger is keyed by (pid,birth). The numeric maps below index only the latest
        # incarnation for OS calls; older resolved instances never lend a handle, attempt or exclusion.
        latest = {entry["pid"]: (entry, expected, partial) for entry, expected, partial in entries}
        for entry, _, _ in entries:
            if latest[entry["pid"]][0] is not entry:
                require(entry["resolved"] is not None, "unresolved prior process incarnation")
                observed.setdefault("retired_instances", {})[custody_instance(entry)] = entry
                remember_retired_group(observed, entry)
                if entry["attempted"]:
                    observed.setdefault("historical_pids", set()).add(entry["pid"])
        entries = list(latest.values())
        for entry, expected, partial in entries:
            pid = entry["pid"]
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
        # Restore every obligation and admit fresh incarnations BEFORE any latch can checkpoint.
        advance_resolved_instances(observed, fresh)
        latch_census_replacements(observed)
        for entry, expected, partial in entries:
            if entry["resolved"]:
                continue  # read_evidence already validated the original-instance exit; never revoke it.
            pid = entry["pid"]
            current = observed["census"].get(pid)
            if expected is not None and current is not None and process_state(
                    expected, current, observed["argv_boundaries"], self.binding["session"], self.binding["host"], [],
                    require_host=False, retained=entry["attempted"]) == "changed":
                observed["resolved"].pop(pid, None)
                unresolved(observed, pid, "recovery", "original_instance_replaced")
                latch_blocked(observed, pid, current.start_time != expected.start_time)
        # Coverage is a property of this invocation's census, never inherited from flattened old text.

    def save(self, observed, attempted, active=True):
        namespace = require_pid_namespace(observed.get("pid_namespace", CURRENT_PID_NAMESPACE))
        observed["pid_namespace"] = namespace
        remember_candidate_groups(observed)
        require(observed.get("coverage") in STOP_COVERAGE, "invalid stop custody coverage")
        attempted = set(attempted) | observed.get("possible_attempts", set())
        retired = observed.get("retired_instances", {})
        require(len(retired) + len(observed["candidates"]) <= MAX_RECORDS, "stop custody exceeds evidence limit")
        instances = dict(retired)
        for pid, row in sorted(observed["candidates"].items()):
            require(len(instances) < MAX_RECORDS, "stop custody exceeds evidence limit")
            entry = custody_entry(observed, pid, attempted)
            require(custody_instance(entry) not in instances, "duplicate stop custody incarnation")
            instances[custody_instance(entry)] = entry
        observed["instances"] = instances
        entries = list(instances.values())
        boot = self.boot()
        # Provider loss is not a reboot: retain the original strong evidence's boot, never replace it
        # with None merely because ps cannot read /proc. This grants no new ps signal authority.
        if boot is None:
            boot = observed.get("custody_boot")
        data = dict(schema="aegis.hierarchy-stop-custody/v2", binding=self.binding, boot=boot, active=active,
                    pid_namespace=namespace,
                    entries=entries, coverage=observed.get("coverage"))
        require(len(observed.get("owned_groups", ())) <= MAX_RECORDS, "stop custody exceeds group limit")
        groups = sorted(observed.get("owned_groups", ())) if active else []
        if groups:
            data["groups"] = groups
        self.decode_record(data)
        # Schema validation bounds every scalar first. Stream ASCII JSON into a capped buffer, checking
        # before each extension; a large incarnation history must refuse before allocating the full JSON.
        buffer = bytearray()
        for chunk in json.JSONEncoder(sort_keys=True).iterencode(data):
            require(len(buffer) + len(chunk) < 262144, "stop custody exceeds evidence limit")
            buffer.extend(chunk.encode("ascii"))
        buffer.append(10)
        raw = bytes(buffer)
        # No acknowledged-byte cache: every request here is an actual transition or pre-effect barrier.
        require_pid_namespace(namespace)
        self.prepare()
        if self.entered and self.fd is None:
            self.lock()
        temporary = "." + uuid.uuid4().hex + ".tmp"
        fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                     dir_fd=self.directory_fd)
        try:
            with descriptor_stream(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
                written = os.fstat(stream.fileno())
            os.replace(temporary, "state.json", src_dir_fd=self.directory_fd, dst_dir_fd=self.directory_fd)
            published = self.commit_identity()
            require(published[:3] == (written.st_dev, written.st_ino, len(raw)),
                    "stop custody changed during durable commit")
            os.fsync(self.directory_fd)
            self.check_namespace()
            require(self.commit_identity() == published and self.read_committed_bytes(published) == raw,
                    "stop custody changed during durable commit")
            observed["custody_boot"] = boot  # Retain the last acknowledged boot if the provider disappears later.
        finally:
            try:
                os.unlink(temporary, dir_fd=self.directory_fd)
            except FileNotFoundError:
                pass

    def commit_identity(self):
        self.check_namespace()
        info = os.stat("state.json", dir_fd=self.directory_fd, follow_symlinks=False)
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
        with self.read_directory() as directory:
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


def custody_instance(entry):
    facts = entry["snapshot"] if entry["snapshot"] is not None else entry["partial"]
    birth = facts.get("start_time") if entry["snapshot"] is not None or facts.get("coherent_birth") else None
    return entry["pid"], birth


def remember_retired_group(observed, entry):
    # Exit discharges only the old instance, not its group/tree. This retains discovery scope, never
    # authority: an orphan with no fresh owned chain must remain held rather than receiving a signal.
    facts = entry["snapshot"] if entry["snapshot"] is not None else entry["partial"]
    group = facts.get("pgid")
    if group and (entry["snapshot"] is not None or custody_instance(entry) in observed.get("group_candidates", ())):
        retain_group(observed, group)


def retain_group(observed, group):
    groups = observed.setdefault("owned_groups", set())
    if group not in groups:
        require(len(groups) < MAX_RECORDS, "stop custody exceeds group limit")
        groups.add(group)


def remember_candidate_groups(observed):
    for pid, row in observed["candidates"].items():
        partial = observed.get("initial_unavailable", {}).get(pid, {})
        if row is None:
            birth = partial.get("start_time") if partial.get("coherent_birth") else None
            if (pid, birth) not in observed.get("group_candidates", ()):
                continue  # An unlinked unreadable instance does not establish group custody.
        group = row.pgid if row is not None else partial.get("pgid")
        if type(group) is int and group > 0:
            retain_group(observed, group)


def latch_census_replacements(observed):
    """Filtered/settled census rows retain negative birth witnesses, never signal authority."""
    if observed["argv_boundaries"] != "proven":
        return
    for pid, expected in observed["candidates"].items():
        if pid in observed["resolved"]:
            continue  # An already committed strong original exit remains a terminal fact.
        partial = observed["initial_unavailable"].get(pid, {})
        birth = expected.start_time if expected is not None else (
            partial.get("start_time") if partial.get("coherent_birth") else None)
        changed = birth is not None and any(other != birth for other in observed.get("census_births", {}).get(pid, ()))
        for current in observed.get("census_identities", {}).get(pid, ()):
            facts = expected._asdict() if expected is not None else partial
            changed = changed or any(facts.get(key) is not None and getattr(current, key) is not None and
                                     facts[key] != getattr(current, key)
                                     for key in ("uid", "euid"))
        if changed:
            unresolved(observed, pid, "census", "original_instance_replaced")
            latch_blocked(observed, pid, True)


def custody_entry(observed, pid, attempted):
    row = observed["candidates"][pid]
    return dict(pid=pid, snapshot=StopCustody.encode(row._asdict()) if row is not None else None,
                partial=StopCustody.encode(observed["initial_unavailable"].get(pid, {})),
                attempted=pid in attempted, blocked=pid in observed["blocked"],
                identity_lost=pid in observed["identity_lost"], resolved=observed["resolved"].get(pid))


def advance_resolved_instances(observed, fresh):
    """Keep fresh uncertainty separate from an exited instance's resolution."""
    if fresh["argv_boundaries"] != "proven":
        return
    for pid, row in list(observed["candidates"].items()):
        if pid not in observed["resolved"]:
            continue
        entry = custody_entry(observed, pid, observed.get("attempted", set()) |
                              observed.get("possible_attempts", set()))
        current = fresh["census"].get(pid)
        partial = fresh.get("initial_unavailable", {}).get(pid, {})
        replacement = current.start_time if current is not None else (
            partial.get("start_time") if partial.get("coherent_birth") else None)
        birth = custody_instance(entry)[1]
        # A fresh unreadable candidate is a new obligation after the known original's proven exit,
        # including when no coherent replacement birth is available. Never upgrade it on a later read.
        if ((birth is None and replacement is None) or replacement == birth or
                (replacement is None and pid not in fresh["candidates"])):
            if pid in fresh["candidates"]:
                observed["coverage"] = "session_instance_unresolved_after_exit"
                unresolved(observed, pid, "census", "fresh_session_instance_after_exit")
            continue
        if birth is None and replacement is not None:
            entry.update(identity_lost=True, blocked=True)  # Old birthless identity; never block the new birth.
        observed.setdefault("retired_instances", {})[custody_instance(entry)] = entry
        remember_retired_group(observed, entry)
        if entry["attempted"]:
            observed.setdefault("historical_pids", set()).add(pid)
        handle = observed["handles"].pop(pid, None)
        if handle is not None:
            os.close(handle["fd"])
        # Callers may still hold the preceding attempt set. Retire by replacing these indexes, never
        # mutate their active pass's accounting or lend an earlier birth's TERM to its replacement.
        for key in ("attempted", "possible_attempts", "recovered"):
            observed[key] = observed.get(key, set()) - {pid}
        for key in ("blocked", "identity_lost"):
            observed[key].discard(pid)
        for key in ("candidates", "resolved", "unresolved", "initial_unavailable"):
            observed[key].pop(pid, None)
        if pid in fresh["candidates"]:
            observed["candidates"][pid] = fresh["candidates"][pid]
            if pid in fresh.get("initial_unavailable", {}):
                observed["initial_unavailable"][pid] = fresh["initial_unavailable"][pid]
            if pid in fresh.get("unresolved", {}):
                observed["unresolved"][pid] = fresh["unresolved"][pid]
        observed["checkpoint_pending"] = True


def unresolved_stop_custody(base, endpoint):
    """Read-only consumer check. False means absent or validated resolved custody; unknown always refuses.

    The explicit base/endpoint confines discovery. A session-only census cannot find an orphan retained by
    an interrupted stop, and checking this must not create state in a legacy base with no custody file.
    """
    try:
        base = safe_path(text(base, "base"))
        endpoint_parts(endpoint)
        # Schema/boot validation is independent from restoring signal authority for the current binding.
        # Any active custody blocks a consumer, including custody left by an earlier binding.
        retained = StopCustody(base, endpoint, None, create=False).read()
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
    rows, complete = [], True
    for line in shown.stdout.splitlines():
        words = line.split(None, 11)
        if not words:
            continue
        if len(words) < 11 or not all(word.isdigit() for word in words[:5]):
            complete = False  # A discarded unreadable row cannot prove that the session is absent.
            continue
        arguments = words[11] if len(words) == 12 else ""
        # ps erases argv boundaries. Quotes are literal; neither paths with spaces nor freeform values can
        # be recovered. These rows are diagnostic only, including apparently canonical selector strings.
        rows.append(ProcessSnapshot(int(words[0]), int(words[1]), words[5], int(words[3]),
                                    " ".join(words[6:11]), os.fsencode(arguments), tuple(arguments.split()),
                                    int(words[2]), int(words[4])))
    return ProcessCensus(rows, "unproven", complete=complete)


def procfs_exit_evidence_supported(observation):
    # A negative capability marker, never an exit proof. Hidden/foreign PIDs cannot renew resolved evidence.
    return observation.proof != "process_visibility_denied"


def process_existence(pid, reason, partial=None):
    """Missing metadata alone proves nothing; qualified numeric ESRCH is a distinct observation."""
    namespace = current_pid_namespace()
    if namespace is None:
        return ProcessObservation("UNAVAILABLE", pid, partial=partial, reason=PID_NAMESPACE_REFUSAL,
                                  proof="pid_namespace_unavailable")
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        if current_pid_namespace() != namespace:
            return ProcessObservation("UNAVAILABLE", pid, partial=partial, reason=PID_NAMESPACE_REFUSAL,
                                      proof="pid_namespace_unavailable")
        return ProcessObservation("CONFIRMED_ABSENT", pid, partial=partial, proof="qualified_namespace_ESRCH")
    except PermissionError:
        return ProcessObservation("UNAVAILABLE", pid, partial=partial, reason=reason + "; existence_unknown",
                                  proof="process_visibility_denied")
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
                process_existence(pid, "argv_boundaries_unavailable"))
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


def census_kernel_thread(row):
    """Negative scope evidence only; emptiness or a readable unrelated ancestor proves no such thing."""
    if row.pgid != 0:
        return False
    try:
        samples = [(Path("/proc") / str(row.pid) / "stat").read_bytes().rpartition(b")")[2].split()
                   for _ in range(2)]
    except OSError:
        return False
    # Linux include/linux/sched.h: PF_KTHREAD. Key both flag samples to the observed original birth.
    return all(len(fields) >= 20 and fields[19] == row.start_time.encode("ascii") and
               fields[2] == b"0" and fields[6].isdigit() and int(fields[6]) & 0x00200000
               for fields in samples)


def census_observation(pid, births=None, identities=None):
    """Settle an empty discovery sample; never weaken retained-instance or pre-signal observations.

    The include flag filters proven terminal/kernel-only discovery rows, not original custody obligations.
    A new birth is a new observation, not an exit proof lent to another process at that numeric PID.
    """
    observation = read_process(pid)
    for attempt in range(4):
        if births is not None:
            facts = observation.partial or {}
            birth = observation.snapshot.start_time if observation.kind == "PRESENT" else (
                facts.get("start_time") if facts.get("coherent_birth") else None)
            if birth is not None:
                births.setdefault(pid, set()).add(birth)
                if identities is not None:
                    if observation.kind == "PRESENT":
                        remember_census_identity(identities, process_identity(observation.snapshot))
                    elif any(type(facts.get(key)) is int for key in ("uid", "euid")):
                        remember_census_identity(identities, IdentityWitness(pid, birth, facts.get("uid"), facts.get("euid")))
        if observation.kind != "PRESENT":
            return observation, True
        row = observation.snapshot
        if not our_uid(row) or (row.cmdline and row.argv):
            return observation, True
        if row.state in ("Z", "X", "x") or census_kernel_thread(row):
            return observation, False
        if attempt == 3:
            break
        # An exiting task can release its mm before /proc reports Z or removes its PID. A bounded fresh
        # read distinguishes that transition from a live session whose command line remains unavailable.
        time.sleep(0.005)
        observation = read_process(pid)
    return observation, True


def process_census(session):
    """Complete atoms on Linux; lost boundaries or relevant unreadable coverage cannot prove no targets."""
    proc = Path("/proc")
    if not proc.is_dir():
        rows = ps_census()
        return ProcessCensus(rows, "unproven", complete=getattr(rows, "complete", True))
    rows, unavailable, births, identities = [], {}, {}, {}
    for folder in proc.iterdir():
        if not folder.name.isdigit():
            continue
        observation, include = census_observation(int(folder.name), births, identities)
        if not include:
            continue
        if observation.kind == "PRESENT":
            rows.append(observation.snapshot)
        elif observation.kind == "UNAVAILABLE":
            unavailable[observation.pid] = observation
    return ProcessCensus(rows, "proven", unavailable, births=births, identities=identities)


def names_session(row, session):
    # Discovery is negative-only: prompt/config atoms may name S without selecting it.
    return argv_names_session(row.argv, session)


def argv_names_session(argv, session):
    return hierarchy_hosts.names_session(argv, session)


def our_uid(row):
    return row.uid == row.euid == os.geteuid()


def owns_process(row, session, host, boundaries):
    return our_uid(row) and hierarchy_hosts.matches_session(host, row.argv, session, boundaries)


def unresolved(observed, pid, stage, reason):
    previous = observed["unresolved"].get(pid)
    entry = {"pid": pid, "stage": stage, "reason": reason}
    if reason == "signal_command_line_not_authorized":
        entry["signal_refusal"] = reason
    elif previous is not None and "signal_refusal" in previous:
        # Discovery/lifetime polling adds its current reason without erasing the last signal refusal.
        entry["signal_refusal"] = previous["signal_refusal"]
    observed["unresolved"][pid] = entry


def retain_candidate(observed, row, reason, missing=False):
    """Discovery retains uncertainty, never promotes diagnostic ps fields to a proven identity."""
    if row.pid not in observed["candidates"]:
        proven = observed["argv_boundaries"] == "proven"
        observed["candidates"][row.pid] = row if proven and not missing else None
        if not proven or missing:
            partial = dict(pid=row.pid, pgid=row.pgid, ppid=row.ppid, uid=row.uid, euid=row.euid,
                           coherent_birth=proven)
            if proven:
                partial.update(start_time=row.start_time, state=row.state, exit_observed=row.state.startswith("Z"))
            observed["initial_unavailable"][row.pid] = partial
        observed["checkpoint_pending"] = True
    unresolved(observed, row.pid, "census", reason)


class CustodyUnavailable(OSError):
    """A failed checkpoint forbids subsequent effects but must not erase public attempt accounting."""


class PidfdUnavailable(ValueError):
    """A handle error is not evidence that numeric signal delivery is permitted."""


def persist_custody(observed, proposed=None):
    if observed is not None and "custody" in observed:
        if observed.get("custody_error"):
            raise CustodyUnavailable(observed["custody_error"])
        try:
            observed["custody"].save(observed, observed["attempted"] if proposed is None else proposed)
            observed["checkpoint_pending"] = False
        except PidNamespaceUnavailable:
            raise
        except (OSError, ValueError) as exc:
            observed["custody_error"] = "stop custody unavailable: " + str(exc)
            raise CustodyUnavailable(observed["custody_error"]) from exc


def latch_blocked(observed, pid, identity_lost=False):
    """A new latch is a durable transition, not a deferred end-of-loop bookkeeping update."""
    changed = pid not in observed["blocked"] or (identity_lost and pid not in observed["identity_lost"])
    observed["blocked"].add(pid)
    if identity_lost:
        observed["identity_lost"].add(pid)
    if changed:
        observed["checkpoint_pending"] = True
        persist_custody(observed)


def resolve_process(observed, pid, proof):
    require_pid_namespace(observed.get("pid_namespace"))
    changed = observed["resolved"].get(pid) != proof
    observed["resolved"][pid] = proof
    observed["unresolved"].pop(pid, None)
    if changed:
        observed["checkpoint_pending"] = True
        # A loss latch rejects later numeric absence. Preserve the strong exit witness before a crash
        # can discard it; ordinary unblocked exits still share the outcome/terminal-clear barriers.
        if pid in observed["blocked"]:
            persist_custody(observed)


class CensusUnavailable(TypeError):
    """An incomplete census cannot be represented as a legacy list of owned roots."""

    def __init__(self, message, unresolved_pids=None, coverage=None):
        super().__init__(message)
        self.unresolved_pids = unresolved_pids or {}
        self.coverage = coverage


def session_processes(session, excluded, host=None, unowned=None, observed=None):
    """Owned roots only; retain unresolved candidates independently from attempted signals."""
    if host is not None:
        hierarchy_hosts.entrypoints(host)
    state = observed if observed is not None else {}
    namespace = require_pid_namespace()
    census = process_census(session)
    state.update(census={row.pid: row for row in census}, argv_boundaries=census.argv_boundaries,
                 census_births=census.births, census_identities=census.identities,
                 census_complete=census.complete,
                 candidates={}, unresolved={}, resolved={}, handles={}, blocked=set(), identity_lost=set(),
                 initial_unavailable={}, group_candidates=set(), numeric=False, pid_namespace=namespace)
    found = []
    if census.argv_boundaries != "proven":
        state["coverage"] = "argv_boundaries_unavailable"
    for row in census:
        if row.pid in excluded or row.state.startswith("Z"):
            continue
        if our_uid(row) and (not row.cmdline or not row.argv):
            retain_candidate(state, row, "cmdline_unavailable", missing=True)
            continue
        if not names_session(row, session):
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
                retain_candidate(state, row, "host_grammar_unavailable")
    for pid, observation in getattr(census, "unavailable", {}).items():
        facts = observation.partial or {}
        if facts.get("coherent_birth") and facts.get("exit_observed"):
            continue  # A physically observed zombie cannot hide a live session, even if UID is unreadable.
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
    require(len(state["candidates"]) <= MAX_RECORDS, "stop custody exceeds evidence limit")
    owners = {pid for pid, _ in found}
    for pid, row in state["candidates"].items():
        if row is not None:
            continue
        facts = state["initial_unavailable"].get(pid, {})
        linked = argv_names_session(facts.get("argv", ()), session)
        parent, seen = facts.get("ppid"), set()
        while not linked and parent is not None and parent not in seen:
            require(len(seen) < MAX_RECORDS, "process ancestry exceeds evidence limit")
            seen.add(parent)
            if parent in owners:
                linked = True
            ancestor = state["census"].get(parent)
            parent = ancestor.ppid if ancestor is not None else None
        if linked:
            birth = facts.get("start_time") if facts.get("coherent_birth") else None
            state["group_candidates"].add((pid, birth))
    if observed is None and (state.get("coverage") or state["unresolved"]):
        raise CensusUnavailable("process census unresolved: " +
                                (state.get("coverage") or ",".join(map(str, sorted(state["unresolved"])))),
                                state["unresolved"], state.get("coverage"))
    return found


def original_exit(expected, observed):
    require_pid_namespace(observed.get("pid_namespace"))
    handle = observed["handles"].get(expected.pid)
    if handle is None or not handle["verified"]:
        return False
    poller = select.poll()
    poller.register(handle["fd"], select.POLLIN)
    if any(event & select.POLLIN for _, event in poller.poll(0)):
        resolve_process(observed, expected.pid, "original_pidfd_exit")
        return True
    return False


class ProcessIdentity(NamedTuple):
    pid: int
    start_time: str
    uid: int
    euid: int


class IdentityWitness(NamedTuple):
    """Negative census evidence; missing UIDs never supply instance or signal authority."""
    pid: int
    start_time: str
    uid: Optional[int]
    euid: Optional[int]


def process_identity(row):
    return ProcessIdentity(row.pid, row.start_time, row.uid, row.euid)


def remember_census_identity(identities, identity):
    if identity.pid not in identities:
        require(len(identities) < MAX_RECORDS, "process census exceeds identity limit")
        identities[identity.pid] = set()
    values = identities[identity.pid]
    require(identity in values or len(values) < MAX_RECORDS, "process census exceeds identity limit")
    values.add(identity)


class StoredProcess(NamedTuple):
    pid: int
    pgid: int
    state: str
    uid: int
    start_time: str
    cmdline_sha256: str
    ppid: int
    euid: int


def same_process_identity(expected, current):
    return process_identity(expected) == process_identity(current)


def signal_command_authorized(expected, current, boundaries, session, host):
    """Command authority is separate from lifetime identity, including retained/recovered signals."""
    if boundaries != "proven" or current.kind != "PRESENT":
        return False
    row = current.snapshot
    if not row.cmdline or not row.argv:
        return False
    if owns_process(row, session, host, boundaries):
        return True
    captured = getattr(expected, "cmdline", None)
    if captured is not None:
        return row.cmdline == captured
    digest = getattr(expected, "cmdline_sha256", None)
    return digest is not None and hashlib.sha256(row.cmdline).hexdigest() == digest


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
    if boundaries != "proven":
        return "unavailable"  # Textual ps birth/state is incomparable, not evidence of PID reuse or exec.
    row = current.snapshot
    if same_process_identity(expected, row) and row.state.startswith("Z"):
        return "gone"
    if (row.start_time != expected.start_time or
            (not retained and row.pgid != expected.pgid) or not our_uid(row) or
            (row.uid, row.euid) != (expected.uid, expected.euid) or
            (parent is not None and row.ppid != parent)):
        # A changed census candidate stays unresolved; stale positive argv cannot reclassify it as spared.
        return "changed"
    if row.cmdline == b"" and row.argv == ():
        # A transient empty /proc cmdline is missing data, not proof of exec/UID/birth replacement.
        # It cannot authorize a signal, and it must not invalidate a later qualified original exit.
        return "unavailable"
    if (not same_process_identity(expected, row) or
            (require_host and not owns_process(row, session, host, boundaries)) or
            (not require_host and hierarchy_hosts.selects_other_session(row.argv, session))):
        # Classification is freshly checked even when the instance survived exec. Retained attempts
        # cannot authorise a host selecting another session or an ambiguous descendant selector.
        return "changed"
    return "authorized"


def unchanged_process(expected, boundaries, session, host, unowned, require_host=True, parent=None, retained=False):
    return process_state(expected, read_process(expected.pid, boundaries), boundaries, session, host, unowned,
                         require_host, parent, retained) == "authorized"


def note_identity_loss(expected, observation, observed):
    if observed is None or observed["argv_boundaries"] != "proven":
        return
    facts = observation.snapshot._asdict() if observation.kind == "PRESENT" else observation.partial or {}
    birth = facts.get("start_time") if observation.kind == "PRESENT" or facts.get("coherent_birth") else None
    changed = birth is not None and birth != expected.start_time
    changed = changed or any(facts.get(key) is not None and facts[key] != getattr(expected, key) for key in ("uid", "euid"))
    if changed and expected.pid not in observed["identity_lost"]:
        latch_blocked(observed, expected.pid, True)


def numeric_absence_blocked(observed, pid):
    """Classification latches forbid signals; lost birth/UID identity also forbids numeric exit."""
    if pid not in observed["blocked"]:
        return False
    expected = observed["candidates"].get(pid)
    partial = observed["initial_unavailable"].get(pid, {})
    birth = expected.start_time if expected is not None else (
        partial.get("start_time") if partial.get("coherent_birth") else None)
    return pid in observed["identity_lost"] or birth is None


def retained_state(expected, boundaries, session, host, unowned, observed=None):
    require_pid_namespace(observed.get("pid_namespace") if observed is not None else CURRENT_PID_NAMESPACE)
    if observed is not None and original_exit(expected, observed):
        return "gone"
    current = read_process(expected.pid, boundaries)
    note_identity_loss(expected, current, observed)
    if observed is not None:
        if current.kind == "CONFIRMED_ABSENT" and numeric_absence_blocked(observed, expected.pid):
            return "unavailable"  # A later numeric absence does not recover a lost original-instance proof.
    result = process_state(expected, current, boundaries, session, host, unowned,
                           require_host=False, retained=True)
    if observed is not None and result == "gone":
        resolve_process(observed, expected.pid, current.proof or "matching_birth_zombie")
    return result


def original_signal_chain(chain, observed, for_open=False):
    """Discovery rows locate a chain; only its retained original evidence can authorize delivery."""
    # A blocked target can still look up lifetime evidence; the later delivery gate always refuses it.
    if any(observed["candidates"].get(row.pid) is None or
           row.pid in observed["blocked"] and (not for_open or index > 0)
           for index, row in enumerate(chain)):
        unresolved(observed, chain[0].pid, "before_signal", "owning_chain_unverified")
        observed["chain_refusal"] = True
        return None
    return [observed["candidates"][row.pid] for row in chain]


def signal_process(chain, number, boundaries, session, host, unowned, retained=False, observed=None, attempted=None):
    state = observed
    namespace = state.get("pid_namespace") if state is not None else None
    require_pid_namespace(namespace)
    chain = original_signal_chain(chain, state, for_open=True)
    if chain is None:
        return False
    target, opened = chain[0], {}
    if state is not None and any(row.pid in state.get("excluded", ()) for row in chain):
        unresolved(state, target.pid, "before_signal", "ancestor_excluded")
        return False

    def cancel_unsent_intent():
        # Only this live invocation can prove its new syscall was never entered. Recovered/actual
        # attempts remain in attempted; a crash before this abort acknowledgement retains possible A.
        if state is not None and target.pid not in (attempted or ()):
            if target.pid in state.get("possible_attempts", ()):
                state["possible_attempts"].discard(target.pid)
                state["checkpoint_pending"] = True

    def validate_chain():
        require_pid_namespace(namespace)
        if original_signal_chain(chain, state) is None:
            cancel_unsent_intent()
            return False
        for index in reversed(range(len(chain))):
            expected = chain[index]
            parent = chain[index + 1].pid if index + 1 < len(chain) else None
            observation = read_process(expected.pid, boundaries)
            result = process_state(expected, observation, boundaries, session, host, unowned,
                                   parent is None and not retained, parent, retained)
            if result != "authorized":
                cancel_unsent_intent()
            note_identity_loss(expected, observation, state)
            if expected.pid in state["blocked"]:
                original_signal_chain(chain, state)
                cancel_unsent_intent()
                return False
            if (state is not None and numeric_absence_blocked(state, expected.pid) and
                    observation.kind == "CONFIRMED_ABSENT"):
                result = "unavailable"
            if result != "authorized" or (state is not None and target.pid in state["blocked"]):
                if state is not None:
                    if result == "gone" and expected.pid == target.pid:
                        resolve_process(state, target.pid, observation.proof or "matching_birth_zombie")
                    else:
                        reason = "evidence_unavailable" if result == "unavailable" else "instance_or_parent_changed"
                        unresolved(state, target.pid, "before_signal", reason)
                        if result == "changed":
                            latch_blocked(state, target.pid)
                    if state.get("checkpoint_pending", True):
                        persist_custody(state)
                return False
            if not signal_command_authorized(expected, observation, boundaries, session, host):
                cancel_unsent_intent()
                if state is not None:
                    unresolved(state, target.pid, "before_signal", "signal_command_line_not_authorized")
                    state["checkpoint_pending"] = True
                    persist_custody(state)
                return False
            if expected.pid in opened:
                opened[expected.pid]["verified"] = True
            if parent is not None and hierarchy_hosts.selects_other_session(observation.snapshot.argv, session):
                if state is not None:
                    cancel_unsent_intent()
                    unresolved(state, target.pid, "before_signal", "descendant_selection_ambiguous")
                    if state.get("checkpoint_pending", True):
                        persist_custody(state)
                return False
        return True

    try:
        for expected in chain:
            kept = state["handles"].get(expected.pid) if state is not None else None
            if kept is not None:
                opened[expected.pid] = kept
            elif hasattr(os, "pidfd_open"):
                try:
                    opened[expected.pid] = {"fd": os.pidfd_open(expected.pid), "verified": False}
                except OSError as exc:
                    if exc.errno == errno.ESRCH:
                        require_pid_namespace(namespace)
                        if state is not None:
                            if expected.pid == target.pid:
                                if numeric_absence_blocked(state, target.pid):
                                    unresolved(state, target.pid, "before_signal",
                                               "original_instance_unresolved_after_numeric_ESRCH")
                                else:
                                    resolve_process(state, target.pid, "qualified_namespace_ESRCH")
                            else:
                                unresolved(state, target.pid, "before_signal", "parent_instance_absent")
                        return False
                    if exc.errno != errno.ENOSYS:
                        unresolved(state, target.pid, "before_signal", "pidfd_unavailable")
                        raise PidfdUnavailable(PIDFD_REFUSAL) from None
                    # Only ENOSYS establishes that this kernel lacks pidfd support.
        if opened and not hasattr(signal, "pidfd_send_signal"):
            unresolved(state, target.pid, "before_signal", "pidfd_delivery_unavailable")
            raise PidfdUnavailable(PIDFD_REFUSAL)
        if state is not None and target.pid in state["blocked"]:
            unresolved(state, target.pid, "before_signal", "original_instance_blocked")
            return False  # No new effect is possible; do not publish another attempt on every poll/pass.
        if state is not None:
            # Publish the possible attempt before the last validation. fsync may block across an exec.
            # A later failed validation sends nothing, but never erases this durable possible-attempt fact.
            state.setdefault("possible_attempts", set()).add(target.pid)
            persist_custody(state, set(attempted or ()) | {target.pid})
            state["custody"].check_namespace()
        if not validate_chain():
            return False
        handle = opened.get(target.pid)
        if state is not None and handle is not None:
            state["handles"][target.pid] = handle
        if state is not None:
            state["unresolved"].pop(target.pid, None)
            state.get("recovered", set()).discard(target.pid)
        if state is not None and state.get("endpoint_fence") is not None:
            state["endpoint_fence"].check()
            # Namespace reads can block across exec. Renew every chain member's instance/command
            # authority after that I/O; the authorised path performs no further namespace work.
            if not validate_chain():
                return False
        # No persistence or namespace I/O after the final instance/command checks above.
        if attempted is not None:
            # The journal carries possible A before the syscall. This invocation has made no attempt when
            # the barrier fails; recovery still retains an A whose acknowledgement was lost.
            attempted.add(target.pid)
        try:
            if handle is None:
                if state is not None:
                    state["numeric"] = True
                # Only a missing pidfd_open or ENOSYS permits this ADR7 residual numeric race.
                os.kill(target.pid, number)
            else:
                signal.pidfd_send_signal(handle["fd"], number)
        except OSError as exc:
            if handle is not None and not isinstance(exc, ProcessLookupError):
                unresolved(state, target.pid, "signal", "pidfd_delivery_unavailable")
                raise PidfdUnavailable(PIDFD_REFUSAL) from None
            raise
        return "sent"
    except ProcessLookupError:
        require_pid_namespace(namespace)
        if state is not None:
            resolve_process(state, target.pid, "signal_ESRCH")
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
    chain, seen, verdict, group = [], set(), "CLEAR", member.pgid
    while member.pid not in seen:
        seen.add(member.pid)
        chain.append(member)
        if member.pid in owners:
            return chain, verdict
        if not our_uid(member):
            return chain, "UNKNOWN"  # Protected UID is no parsed other-session proof and cannot mean gone.
        selection = hierarchy_hosts.descendant_verdict(member.argv, session)
        if selection == "OTHER":
            return [], "OTHER"
        if selection == "HOLD":
            verdict = "HOLD"
        member = census.get(member.ppid)
        if member is None or member.pgid != group:
            return chain, "UNKNOWN"
    return chain, "UNKNOWN"


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


def refresh_stop_scope(observed, session, host, unowned):
    """Refresh discovery without replacing original-instance evidence or reviving resolved PIDs."""
    require_pid_namespace(observed.get("pid_namespace"))
    fresh = {}
    found = session_processes(session, observed["excluded"], host, unowned, fresh)
    require_pid_namespace(observed.get("pid_namespace"))
    observed["census"] = fresh["census"]
    observed["argv_boundaries"] = fresh["argv_boundaries"]
    observed["census_complete"] = fresh["census_complete"]
    observed["census_births"] = fresh["census_births"]
    observed["census_identities"] = fresh["census_identities"]
    advance_resolved_instances(observed, fresh)
    latch_census_replacements(observed)
    for pid, expected in observed["candidates"].items():
        if pid in observed["resolved"]:
            if pid in fresh["candidates"]:
                # Original-instance exit does not prove a freshly discovered session candidate is gone.
                # Keep the old attempt/exit proof, but never lend it to this new or unreadable instance.
                observed["coverage"] = "session_instance_unresolved_after_exit"
                observed["checkpoint_pending"] = True
                unresolved(observed, pid, "census", "fresh_session_instance_after_exit")
            continue
        current = fresh["census"].get(pid)
        missing = fresh["initial_unavailable"].get(pid, {})
        if expected is None:
            initial = observed["initial_unavailable"].get(pid, {})
            birth = initial.get("start_time") if initial.get("coherent_birth") else None
            new_birth = current.start_time if current is not None and fresh["argv_boundaries"] == "proven" else (
                missing.get("start_time") if missing.get("coherent_birth") else None)
            if birth and new_birth and birth != new_birth:
                latch_blocked(observed, pid, True)
        elif current is not None:
            observation = ProcessObservation("PRESENT", pid, current)
            note_identity_loss(expected, observation, observed)
            if process_state(expected, observation, fresh["argv_boundaries"], session, host, unowned,
                             require_host=False, retained=True) == "changed":
                latch_blocked(observed, pid)
        elif missing:
            note_identity_loss(expected, ProcessObservation("UNAVAILABLE", pid, partial=missing), observed)
    for pid, row in fresh["candidates"].items():
        if pid not in observed["candidates"]:
            observed["candidates"][pid] = row
            observed["checkpoint_pending"] = True
            if pid in fresh["initial_unavailable"]:
                observed["initial_unavailable"][pid] = fresh["initial_unavailable"][pid]
            if pid in fresh["unresolved"]:
                observed["unresolved"][pid] = fresh["unresolved"][pid]
    if fresh.get("coverage"):
        observed["coverage"] = fresh["coverage"]
    linked = observed.setdefault("group_candidates", set())
    for key in fresh.get("group_candidates", ()):
        require(key in linked or len(linked) < MAX_RECORDS, "stop custody exceeds evidence limit")
        linked.add(key)
    remember_candidate_groups(fresh)
    for group in fresh.get("owned_groups", ()):
        retain_group(observed, group)
    return found


def signal_all(found, number, observed, session, host, unowned, attempted=None, new_only=False):
    census, boundaries = observed["census"], observed["argv_boundaries"]
    attempted = set() if attempted is None else attempted
    owners = {pid for pid, _ in found if pid not in observed["resolved"]}
    groups = observed.setdefault("owned_groups", set())
    remember_candidate_groups(observed)  # Group scope never grants signal authority.
    targets = [[census[pid]] for pid in owners]
    for member in census.values():
        if member.state.startswith("Z") or member.pid in observed["resolved"]:
            continue
        if member.pid not in owners and member.pgid in groups:
            chain, verdict = descendant_lineage(member, census, owners, session)
            if verdict == "OTHER":
                observed.setdefault("spared_descendants", set()).add(member.pid)
            if chain:
                if verdict == "UNKNOWN":
                    retain_candidate(observed, member, "descendant_parent_unavailable")
                elif verdict == "HOLD":
                    retain_candidate(observed, member, "descendant_selection_ambiguous")
                else:
                    targets.append(chain)
    for chain in targets:
        pid = chain[0].pid
        if pid not in observed["candidates"]:
            observed["candidates"][pid] = chain[0]
            observed["checkpoint_pending"] = True
    # Children first: every parent edge still exists and is freshly checked BEFORE the child's first signal.
    for chain in sorted(targets, key=lambda rows: process_depth(rows[0], census), reverse=True):
        if number is None or chain[0].pid in observed["resolved"]:
            continue
        if observed["candidates"][chain[0].pid] is None:
            continue  # Fresh readable metadata cannot replace an initially unknown instance's evidence.
        if new_only and chain[0].pid in attempted:
            continue
        signal_process(chain, number, boundaries, session, host, unowned, observed=observed, attempted=attempted)
    return attempted


def signal_retained(pids, number, observed, session, host, unowned, skip=()):
    if observed["argv_boundaries"] != "proven":
        return  # Lossy discovery cannot renew original-instance signal authority.
    for pid in sorted(pids):
        if pid in skip:
            continue
        expected = observed["candidates"][pid]
        if pid not in observed["resolved"] and not original_exit(expected, observed):
            if pid in observed.get("recovered", ()):
                # Claimed A is bookkeeping, never authority. A fresh complete chain must end at a live
                # owned host; equality of the recovered target's identity alone proves no ownership.
                census = observed["census"]
                owners = {row.pid for row in census.values() if owns_process(row, session, host, "proven")}
                member = census.get(pid)
                chain = descendant_chain(member, census, owners, session) if member is not None else []
                if not chain or chain[-1].pid not in owners:
                    unresolved(observed, pid, "recovery", "fresh_ownership_unproven")
                    continue
                signal_process(chain, number, "proven", session, host, unowned,
                               observed=observed, attempted=pids)
                continue
            # W's first pass proved ancestry; dead M must not erase W's retained original-instance evidence.
            signal_process([expected], number, observed["argv_boundaries"], session, host, unowned,
                           retained=True, observed=observed, attempted=pids)


def gone_within(session, excluded, pids, seconds, host, observed, unowned):
    require_pid_namespace(observed.get("pid_namespace"))
    remember_candidate_groups(observed)
    deadline = time.monotonic() + seconds
    while True:
        for pid, expected in observed["candidates"].items():
            if pid in excluded or pid in observed["resolved"]:
                continue
            if expected is None:
                observation = read_process(pid, observed["argv_boundaries"])
                initial = observed["initial_unavailable"].get(pid, {})
                birth = initial.get("start_time") if initial.get("coherent_birth") else None
                if observation.kind == "PRESENT" and observed["argv_boundaries"] == "proven":
                    current = {"start_time": observation.snapshot.start_time, "coherent_birth": True,
                               "uid": observation.snapshot.uid, "euid": observation.snapshot.euid,
                               "exit_observed": observation.snapshot.state.startswith("Z")}
                else:
                    current = observation.partial or {}
                current_birth = current.get("start_time") if current.get("coherent_birth") else None
                changed = birth and current_birth and current_birth != birth
                changed = changed or any(initial.get(key) is not None and current.get(key) is not None and
                                         initial[key] != current[key] for key in ("uid", "euid"))
                if changed and pid not in observed["identity_lost"]:
                    latch_blocked(observed, pid, True)
                uids_match = (pid not in observed["identity_lost"] or
                    all(initial.get(key) is None or current.get(key) == initial[key] for key in ("uid", "euid")))
                if birth and current_birth == birth and current.get("exit_observed") and uids_match:
                    resolve_process(observed, pid, "matching_partial_birth_zombie")
                    result = "gone"
                elif observation.kind == "CONFIRMED_ABSENT" and not numeric_absence_blocked(observed, pid):
                    resolve_process(observed, pid, observation.proof)
                    result = "gone"
                else:
                    result = "unavailable"
            else:
                result = retained_state(expected, observed["argv_boundaries"], session, host, unowned, observed)
            if result == "gone":
                resolve_process(observed, pid, observed["resolved"].get(pid, "confirmed_instance_exit"))
            else:
                unresolved(observed, pid, "after_signal" if pid in pids else "before_signal",
                           "evidence_unavailable" if result == "unavailable" else "original_instance_live_or_changed")
                if result == "changed":
                    latch_blocked(observed, pid)
        groups_exited = retained_groups_exited(observed)
        if len(observed["resolved"]) == len(observed["candidates"]):
            # Original-instance exit is not complete scope evidence. Lossy ps cannot discharge a
            # coverage obligation, even after every original handle/qualified namespace exit is known.
            if groups_exited and not observed.get("coverage") and not observed.get("admission_unknown"):
                return True
        if not pids or time.monotonic() >= deadline:
            return False
        time.sleep(POLL_SECONDS)


def binding_identity(binding):
    return {key: binding[key] for key in ("host", "session", "generation")} if binding is not None else None


def expected_stop_binding(raw):
    # CLI input is bounded before encoding/parsing, including the explicit unbound (null) expectation.
    require(isinstance(raw, str) and len(raw) <= 4096 and raw.isascii(), "invalid expected stop binding")
    try:
        value = metadata_json(raw.encode("ascii"), "launch record")
        if value is not None:
            StopCustody.exact_fields(value, ("host", "session", "generation"))
            text(value["host"], "host", 128)
            text(value["session"], "session", 256)
            integer(value["generation"], "generation", maximum=2 ** 31 - 1)
        return value
    except (ValueError, TypeError, KeyError, RecursionError):
        raise ValueError("invalid expected stop binding") from None


def stop(launches, endpoint, grace, expected_binding=NO_EXPECTED_BINDING):
    endpoint = launches.resolve(endpoint)
    identifier = launches.new_id()
    if not (type(grace) is int and 0 <= grace <= 60):
        launches.refuse(endpoint, identifier, "stop", "invalid grace_seconds")
    if expected_binding is NO_EXPECTED_BINDING:
        stop_checks(launches, endpoint, identifier)
    known = binding_identity(launches.binding(endpoint)) or {}
    with recorded_endpoint_lock(launches, endpoint, identifier, "stop", known) as fence:
        if expected_binding is not NO_EXPECTED_BINDING:
            current = binding_identity(launches.binding(endpoint))
            if current != expected_binding:
                launches.refuse(endpoint, identifier, "stop", CLEANUP_BINDING_CHANGED, **(current or {}))
        return stop_locked(launches, endpoint, grace, identifier, fence)


def stop_locked(launches, endpoint, grace, identifier, fence):
    fence.check()
    known = stop_checks(launches, endpoint, identifier)
    unowned, observed = [], {}
    try:
        retained = StopCustody(launches, endpoint, known, create=False).read()
        attempted = [entry["pid"] for entry, _, _ in retained[1] if entry["attempted"]] if retained else []
        observed["journal_attempted"] = set(attempted)
        namespace = require_pid_namespace(retained[0].get("pid_namespace") if retained else CURRENT_PID_NAMESPACE,
                                          attempted)
        admitted = read_running_wake(launches.base, endpoint)
        if admitted is not None:
            require_pid_namespace(running_pid_namespace(admitted), attempted)
        excluded = ancestors()
        found = session_processes(known["session"], excluded, known["host"], unowned, observed)
        require_pid_namespace(namespace)
        observed["endpoint_fence"] = fence
        running = read_running_wake(launches.base, endpoint)
        if running is not None:
            require(running["binding"] == known, "running wake belongs to another binding")
            if running["host_pid"] is None:
                observed["admission_unknown"] = True
        if running is not None and running["host_pid"] is not None:
            # The pinned producer starts this child in a new session/group. Keep that negative-only
            # discovery scope even without P's snapshot, or after P and its intermediary have exited.
            # Membership alone never supplies the live owned ancestry required by signal_process.
            retain_group(observed, running["host_pid"])
            pid = running["host_pid"]
            current = observed["census"].get(pid)
            latest = ProcessObservation("PRESENT", pid, current) if current is not None else read_process(
                pid, observed["argv_boundaries"])
            if running["snapshot"] is None:
                # Admission knows a child exists but supplied no original identity. Later readable
                # metadata cannot turn that uncertainty into signal authority or successful absence.
                if latest.kind != "CONFIRMED_ABSENT":
                    observed["candidates"][pid] = None
                    observed["initial_unavailable"][pid] = {}
                    unresolved(observed, pid, "admission", "admitted_child_identity_unavailable")
            else:
                facts = StopCustody.decode(running["snapshot"])
                expected = ProcessIdentity(**{key: facts[key] for key in ProcessIdentity._fields})
                # Reconcile this original identity after restoring committed exit proofs. A missing
                # census row must not discard its birth, and an observed replacement must latch loss
                # before another read can observe the replacement's numeric absence.
                observed["running_expected"], observed["running_observation"] = expected, latest
    except PidNamespaceUnavailable as exc:
        return 3, launches.record(endpoint, identifier, "stop", "stop_failed", **known,
                                  pids=exc.pids, error=PID_NAMESPACE_REFUSAL)
    except CustodyExitUnproven as exc:
        return 3, launches.record(endpoint, identifier, "stop", "stop_failed", **known,
                                  pids=exc.pids, error=str(exc))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        launches.refuse(endpoint, identifier, "stop", str(exc), **known)
    if observed["argv_boundaries"] != "proven":
        # Unsupported evidence must not create or rewrite custody. Retained attempts remain public
        # bookkeeping; reading their journal grants neither fresh signal authority nor an exit proof.
        try:
            retained = StopCustody(launches, endpoint, known, create=False).read()
        except CustodyExitUnproven as exc:
            return 3, launches.record(endpoint, identifier, "stop", "stop_failed", **known,
                                      pids=sorted(set(exc.pids) | observed["journal_attempted"]), error=str(exc))
        except (OSError, ValueError) as exc:
            launches.refuse(endpoint, identifier, "stop", str(exc), **known)
        attempted = sorted({entry["pid"] for entry, _, _ in retained[1] if entry["attempted"]}) if retained else []
        marker = dict(pids=attempted, argv_boundaries="unproven", reason="argv_boundaries_unavailable",
                      grace_seconds=grace, wake_marker_present=launches.mailbox.wake_marker(endpoint).exists(),
                      error="stop unsupported without proven argv boundaries; stop the host manually, preserve "
                            "retained custody, and have the owner reconcile it before retrying on a supported system")
        if set(unowned) - set(attempted):
            marker["unowned_pids"] = sorted(set(unowned) - set(attempted))
        return 3, launches.record(endpoint, identifier, "stop", "stop_failed", **known, **marker)
    with StopCustody(launches, endpoint, known) as custody:
        fence.check()
        code, record = stop_owned(launches, endpoint, identifier, known, grace, custody, (excluded, unowned, observed, found))
    if code == 0 and running is not None:
        try:
            fence.check()
            clear_running_wake(launches.base, endpoint, running)
        except (ValueError, OSError):
            return 3, launches.record(endpoint, launches.new_id(), "stop", "stop_failed", **known,
                                      pids=record["pids"], error="running wake cleanup unavailable")
    return code, record


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


def stop_owned(launches, endpoint, identifier, known, grace, custody, discovery):
    excluded, unowned, observed, found = discovery
    pids = set()
    marker = {"wake_marker_present": launches.mailbox.wake_marker(endpoint).exists(), "grace_seconds": grace}
    error = None
    try:
        observed.update(custody=custody, attempted=pids, excluded=excluded, checkpoint_pending=True)
        fresh = {key: dict(observed[key]) for key in ("candidates", "initial_unavailable", "unresolved")}
        fresh.update(argv_boundaries=observed["argv_boundaries"], census=observed["census"])
        custody.restore(observed, pids)
        expected = observed.get("running_expected")
        if expected is not None and (expected.pid, expected.start_time) not in observed.get("committed_exits", set()):
            require(expected.pid not in observed["resolved"],
                    custody_refusal(launches.base, endpoint, "running wake conflicts with committed process identity"))
            candidate = observed["candidates"].get(expected.pid)
            if candidate is None or not same_process_identity(expected, candidate):
                current = observed["census"].get(expected.pid)
                if (expected.pid not in observed["blocked"] and current is not None and
                        same_process_identity(expected, current) and
                        owns_process(current, known["session"], known["host"], observed["argv_boundaries"])):
                    # Admission proves the instance, and this fresh OWNED row supplies classification.
                    observed["candidates"][expected.pid] = current
                else:
                    observed["candidates"][expected.pid] = None
                    partial = observed["initial_unavailable"].setdefault(expected.pid, {})
                    partial.update(expected._asdict(), coherent_birth=True)
            unresolved(observed, expected.pid, "admission", "original_instance_pending")
            observed["checkpoint_pending"] = True
            latest = observed["running_observation"]
            note_identity_loss(expected, latest, observed)
            if process_state(expected, latest, observed["argv_boundaries"], known["session"], known["host"],
                             unowned, require_host=False, retained=True) == "changed":
                latch_blocked(observed, expected.pid)
        latch_census_replacements(observed)
        advance_resolved_instances(observed, fresh)
        pids = observed["attempted"]
        if observed["argv_boundaries"] != "proven":
            marker["argv_boundaries"] = "unproven"
        if found:
            signal_all(found, None, observed, known["session"], known["host"], unowned, pids)
            # Re-discover the owned groups at delivery, before terminating their ancestors. Never broadcast
            # to a group: negative selection and the complete fresh parent-chain checks still apply.
            found = refresh_stop_scope(observed, known["session"], known["host"], unowned)
            pids = observed["attempted"]
            signal_all(found, signal.SIGTERM, observed, known["session"], known["host"], unowned, pids)
        elif pids:
            signal_retained(pids, signal.SIGTERM, observed, known["session"], known["host"], unowned)
        stopped = gone_within(known["session"], excluded, pids, grace, known["host"], observed, unowned)
        # Success requires fresh discovery even when every retained instance has exited. A late group
        # member with lost ancestry remains a custody obligation, never a fresh signal authorization.
        new_found = refresh_stop_scope(observed, known["session"], known["host"], unowned)
        pids = observed["attempted"]
        signal_all(new_found, None, observed, known["session"], known["host"], unowned, pids)
        stopped = gone_within(known["session"], excluded, pids, 0, known["host"], observed, unowned)
        if not stopped:
            previous_attempts = set(pids)
            signal_all(new_found, signal.SIGTERM, observed, known["session"], known["host"], unowned, pids,
                       new_only=True)
            if pids - previous_attempts:
                stopped = gone_within(known["session"], excluded, pids, grace, known["host"], observed, unowned)
                new_found = refresh_stop_scope(observed, known["session"], known["host"], unowned)
                pids = observed["attempted"]
                signal_all(new_found, None, observed, known["session"], known["host"], unowned, pids)
                stopped = gone_within(known["session"], excluded, pids, 0, known["host"], observed, unowned)
        if not stopped and pids:
            # Only this incarnation's successful TERM attempt makes it eligible for escalation.
            signal_retained(pids, signal.SIGKILL, observed, known["session"], known["host"], unowned)
            stopped = gone_within(known["session"], excluded, pids, KILL_WAIT_SECONDS, known["host"], observed, unowned)
            final_found = refresh_stop_scope(observed, known["session"], known["host"], unowned)
            pids = observed["attempted"]
            signal_all(final_found, None, observed, known["session"], known["host"], unowned, pids)
            stopped = gone_within(known["session"], excluded, pids, 0, known["host"], observed, unowned)
        marker["wake_marker_present"] = launches.mailbox.wake_marker(endpoint).exists()
    except PidNamespaceUnavailable:
        observed["namespace_error"] = True
        error, stopped = PID_NAMESPACE_REFUSAL, False
    except PidfdUnavailable:
        error, stopped = PIDFD_REFUSAL, False
    except CustodyExitUnproven as exc:
        # A later journal edit must neither erase admission-time bookkeeping nor overwrite the
        # disputed evidence. This exits before effects; finally still closes every retained handle.
        return 3, launches.record(endpoint, identifier, "stop", "stop_failed", **known,
            pids=sorted(pids | set(exc.pids) | observed.get("journal_attempted", set())), error=str(exc))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        if not pids and not observed.get("historical_pids"):
            launches.refuse(endpoint, identifier, "stop", str(exc), **known)
        error, stopped = str(exc), False
        for pid in observed.get("candidates", {}):
            if pid not in observed["resolved"]:
                unresolved(observed, pid, "operation_error", "evidence_unavailable: " + str(exc))
    finally:
        for handle in observed.get("handles", {}).values():
            os.close(handle["fd"])
    unsupported_empty = (observed["argv_boundaries"] != "proven" and not observed["candidates"] and
                         not pids and not observed.get("historical_pids"))
    if observed["argv_boundaries"] != "proven":
        marker["argv_boundaries"] = "unproven"
        if error is None:
            error = ("stop unsupported without proven argv boundaries; stop the host manually, preserve "
                     "retained custody, and have the owner reconcile it before retrying on a supported system")
    if observed.get("admission_unknown"):
        error = "wake admission identity is unavailable; " + running_wake_recovery(launches.base, endpoint)
    # On success no more signals are needed: retain durable active custody through the immutable outcome,
    # then commit all exit proofs and terminal clear together. An intermediate resolved-active write adds
    # no recovery protection. Failures still checkpoint, and every escalation keeps its pre-effect barrier.
    # A failed checkpoint is never retried into success or allowed to erase possible attempts.
    if (not observed.get("namespace_error") and not unsupported_empty and not stopped and not observed.get("custody_error") and observed.get("checkpoint_pending", True) and
            (observed.get("owned_groups") or observed.get("candidates") or observed.get("coverage") or observed.get("retained_custody") or
             observed.get("retired_instances"))):
        try:
            persist_custody(observed)
        except CustodyUnavailable as exc:
            error = str(exc)
    # Public attempts are a union of physical incarnations, while delivery/escalation uses only current A.
    current_attempts = pids
    pids = pids | observed.get("historical_pids", set())
    spared = sorted(set(unowned) - pids)
    if spared:
        marker["unowned_pids"] = spared
    if observed.get("spared_descendants"):
        marker["spared_descendants"] = sorted(observed["spared_descendants"])
    if observed.get("possible_attempts", set()) - pids:
        marker["possible_pids"] = sorted(observed["possible_attempts"] - pids)
    if observed.get("unresolved"):
        marker["unresolved_pids"] = sorted(observed["unresolved"])
        marker["unresolved"] = [observed["unresolved"][pid] for pid in sorted(observed["unresolved"])]
    if observed.get("coverage"):
        marker["reason"] = observed["coverage"]
    if observed.get("unresolved_groups"):
        marker["unresolved_groups"] = observed["unresolved_groups"]
    if observed.get("resolved"):
        marker["absence_evidence"] = [{"pid": pid, "proof": observed["resolved"][pid]}
                                      for pid in sorted(observed["resolved"])]
    for entry in observed.get("retired_instances", {}).values():
        marker.setdefault("absence_evidence", []).append({"pid": entry["pid"], "proof": entry["resolved"]})
    if pids:
        marker["identity_check_mode"] = "start_time_recheck" if observed["numeric"] else "pidfd"
    blocked = observed.get("blocked", set()) & observed.get("unresolved", {}).keys()
    try:
        require_pid_namespace(observed.get("pid_namespace"))
    except PidNamespaceUnavailable:
        observed["namespace_error"] = True
        error, stopped = PID_NAMESPACE_REFUSAL, False
    if observed.get("chain_refusal") and not observed.get("namespace_error"):
        error, stopped = OWNING_CHAIN_REFUSAL, False
    if not stopped and blocked and not observed.get("namespace_error") and not observed.get("chain_refusal"):
        cause = "original process identity lost" if blocked & observed["identity_lost"] else "original process identity blocked"
        guidance = custody_refusal(launches.base, endpoint, cause)
        error = error + "; " + guidance if error else guidance
    if error is not None:
        marker["error"] = error
    if observed.get("namespace_error"):
        marker.pop("absence_evidence", None)
    state = "stopped" if pids else "not_running"
    if not stopped:
        state = "stop_failed"
    # Keep active custody until the immutable outcome is durable, including failure/interruption windows.
    record = launches.record(endpoint, identifier, "stop", state, **known, pids=sorted(pids), **marker)
    if (not observed.get("namespace_error") and not unsupported_empty and not observed.get("custody_error") and (stopped or observed.get("checkpoint_pending", True)) and
            (observed.get("owned_groups") or observed.get("candidates") or observed.get("coverage") or observed.get("retained_active") or
             observed.get("retired_instances"))):
        try:
            custody.save(observed, current_attempts, active=not stopped)
        except PidNamespaceUnavailable:
            marker["error"] = PID_NAMESPACE_REFUSAL
            marker.pop("absence_evidence", None)
            return 3, launches.record(endpoint, launches.new_id(), "stop", "stop_failed", **known,
                                      pids=sorted(pids), **marker)
        except (OSError, ValueError) as exc:
            # The earlier record cannot be changed. A later immutable failure prevents a terminal success
            # claim while active custody remains, including loss of the state-file commit acknowledgement.
            marker["error"] = "stop custody unavailable: " + str(exc)
            return 3, launches.record(endpoint, launches.new_id(), "stop", "stop_failed", **known,
                                      pids=sorted(pids), **marker)
    return (0 if stopped else 3), record


def portable_status_paths(base, endpoint):
    """Historical read-only compatibility; never used for admission, custody or stop evidence."""
    endpoint_parts(endpoint)
    folder, paths = safe_path(Path(base) / "launches" / quoted(endpoint)), []
    try:
        entries = os.scandir(folder)
    except FileNotFoundError:
        return paths
    with entries:
        for count, entry in enumerate(entries):
            require(count < MAX_RECORDS + 64, "launch directory entry limit reached")
            if entry.name.endswith(".json"):
                require(entry.is_file(follow_symlinks=False) and not entry.is_symlink(), "invalid launch record entry")
                require(len(paths) < MAX_RECORDS, "launch record limit reached")
                paths.append(folder / entry.name)
    return sorted(paths)


def portable_status_record(path):
    path = safe_path(path)
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 262144, "launch record exceeds evidence limit")
        raw = stream.read(262145)
        require(len(raw) <= 262144, "launch record exceeds evidence limit")
    return metadata_json(raw, "launch record")


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
        rows[name] = {"binding": None if binding is None else {key: binding[key] for key in ("host", "session", "generation")},
                      "last": None, "records": None}
        paths = []
        try:
            descriptors = launch_descriptor_capable()
            paths = launches.paths(name) if descriptors else portable_status_paths(launches.base, name)
            rows[name]["records"] = len(paths)
            if paths:
                rows[name]["last"] = (metadata_json(read_launch_record(launches.base, name, paths[-1].name), "launch record")
                                      if descriptors else portable_status_record(paths[-1]))
        except (OSError, ValueError, UnicodeError, RecursionError) as exc:
            # Enumeration and reads degrade only this endpoint. Never repeat untrusted record text.
            reasons = ("invalid launch record entry", "launch record exceeds evidence limit",
                       "launch record changed or exceeds evidence limit", "launch directory entry limit reached",
                       "launch directory changed while reading", "launch directory unreadable",
                       "launch record limit reached", "invalid launch record JSON")
            reason = ("launch record limit reached" if isinstance(exc, LaunchRecordLimit) else
                      str(exc) if str(exc) in reasons else
                      "invalid launch record JSON" if paths and isinstance(exc, ValueError) else
                      "launch history unavailable")
            rows[name].update(state="unknown", error=reason,
                              unreadable=str(paths[-1] if paths else launches.folder(name)))
    return 0, {"schema": STATUS_SCHEMA, "endpoints": rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", required=True, help="Absolute path to a provisioned initiative base")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("start").add_argument("--request", required=True, help="Absolute path to a strict JSON request")
    resumed = commands.add_parser("resume")
    resumed.add_argument("--endpoint", required=True)
    resumed.add_argument("--dry-run", action="store_true", help="Run the wake tool's dry run; launch nothing")
    worker = commands.add_parser("_resume-wake", help=argparse.SUPPRESS)
    worker.add_argument("--endpoint", required=True)
    worker.add_argument("--admission-fd", type=int, required=True)
    worker.add_argument("--admission-namespace", required=True)
    worker.add_argument("--wake-source", required=True)
    worker.add_argument("--dry-run", action="store_true")
    stopped = commands.add_parser("stop")
    stopped.add_argument("--endpoint", required=True)
    stopped.add_argument("--grace-seconds", type=int, default=5)
    stopped.add_argument("--expected-binding", help=argparse.SUPPRESS)
    commands.add_parser("status").add_argument("--endpoint")
    args = parser.parse_args(argv)
    try:
        require(args.command == "status" or os.name == "posix", "the launcher supports POSIX process groups only")
        launches = Launches(args.base)
        if args.command == "start":
            code, result = start(launches, args.request)
        elif args.command == "resume":
            code, result = resume(launches, args.endpoint, args.dry_run)
        elif args.command == "_resume-wake":
            code, result = admitted_wake(launches, args.endpoint, args.admission_fd, args.wake_source,
                                         args.dry_run, args.admission_namespace)
        elif args.command == "stop":
            expected = expected_stop_binding(args.expected_binding) if args.expected_binding is not None else NO_EXPECTED_BINDING
            code, result = stop(launches, args.endpoint, args.grace_seconds, expected)
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
