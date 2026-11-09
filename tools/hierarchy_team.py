#!/usr/bin/env python3
"""The owner's one command for a team run: init, login, root, up, request, approve, turn, status and down.

One config, `team-run.json` (aegis.team-run/v1, template in hierarchy_templates/team-run.json), replaces the real
run's shell guide and its helpers. aegis.team-run/v2 adds `hosts`, ROOT's host and the one host of every role below it;
v1 means codex-cli for both. init writes them to <base>/host-plan.json, which provision add-role and handoff check
every binding against. Every subcommand checks path safety: CODEX_HOME is the run's codex_home and
never ~/.codex or a folder inside it (by realpath), and for a plan that uses claude-code, CLAUDE_CONFIG_DIR is the run's
claude_home. On a Claude plan both homes and the resolved run folder exclude ~/.claude and ~/.codex under HOME and
the password-database home. Commands that start work require free disk at least min_free_gb;
git, bwrap and each host's command the plan uses (codex, claude) are on
PATH, and cargo and cargo-nextest on the recipes' path when a kept recipe runs them. A command that spends model
turns (login, up, approve, turn) also refuses the billing variables of each host the plan uses.

The subcommands orchestrate the existing tools as child processes (`-I -B`), or call their public functions, and
re-check nothing those tools check: a tool's refusal is passed on with its own text. The run's records are files:
<run>/team-state.json says which steps are done, and every output lands in <run>/evidence with its sha256 in
evidence/index.json. `down` copies the rest there, writes the turn ledger and SHA256SUMS.

ROOT stays the owner's session. `root` binds an existing ROOT session with its decision connection; `approve` runs
one ROOT turn whose prompt names the request id, decision and owner's reason, so no hash is pasted, then checks the
journal; the loop never wakes ROOT. `request` publishes as the coordinator, never as ROOT.

Exit codes: 0 done; 2 refused (this command changed nothing); 3 failed (a step ran and did not succeed). The result is
one JSON object on the last line of stdout, except `status --text`.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
from hierarchy_mailbox import (GIT_ID, SLUG, Mailbox, endpoint_parts, fields, matching, require,  # noqa: E402
                               strict_json, text, timestamp)
import hierarchy_hosts  # noqa: E402
import hierarchy_lifecycle  # noqa: E402
import hierarchy_native  # noqa: E402
import hierarchy_provision  # noqa: E402
import hierarchy_roles  # noqa: E402
import hierarchy_router  # noqa: E402
import hierarchy_team_view  # noqa: E402


SCHEMA = "aegis.team-run/v1"
SCHEMA_V2 = "aegis.team-run/v2"
STATE_SCHEMA = "aegis.team-run-state/v1"
INDEX_SCHEMA = "aegis.team-evidence-index/v1"
STATUS_SCHEMA = "aegis.team-run-status/v1"
LEDGER_SCHEMA = "aegis.team-turn-ledger/v1"
OK, REFUSED, FAILED = 0, 2, 3
CODEX = hierarchy_provision.CODEX
CLAUDE = hierarchy_provision.CLAUDE
V1_HOSTS = {"root": CODEX, "team": CODEX}
CLAUDE_CREDENTIALS = ".credentials.json"
# Seconds, lowerable for CLI timeout tests; never extended past the normal 60-second status deadline.
CLAUDE_AUTH_STATUS_TIMEOUT = "AEGIS_CLAUDE_AUTH_STATUS_TIMEOUT"
TURN_TIMEOUT_SECONDS = 3600
TURN_TIMEOUT_VARIABLE = "AEGIS_TEAM_TURN_TIMEOUT"
ROOT_TOOLS = ("root_decide", "team_status", "team_pending", "team_request")
CHILD_ENVIRONMENT = frozenset(("PATH", "HOME", "LANG", "TERM", "TMPDIR", "USER", "LOGNAME"))
# Managed settings can set an apiKeyHelper that --restricted still reads; login records whether the file exists.
CLAUDE_MANAGED_SETTINGS = Path("/etc/claude-code/managed-settings.json")
# A stand-in binding that never runs a host; the host plan lists it so status can say so (spec rule 6).
FRONT_DOOR_HOST = hierarchy_provision.CLAUDE
HOME_PLACEHOLDER = "/REPLACE/WITH/your/home/folder"
PLACEHOLDER = re.compile(r"REPLACE|<[^<>]*>")
DEFAULT_RECIPES = HERE / "hierarchy_templates" / "job-recipes.json"
PACKET_SCHEMA = "aegis.hierarchy-job-packet/v1"
# Written into codex_home and claude_home by init: purge deletes only a folder that carries it.
OWNER_MARK = ".aegis-team-run"
LANE_KINDS = ("implementer", "reviewer")
OPTIONAL_ROLES = hierarchy_provision.OPTIONAL_ROLES
LEASE_LANE = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")
DEFAULT_LEASE_TTL = 21600
DEFAULT_MIN_FREE_GB = 8
DEFAULT_INTERVAL = 30
LOOP_WAIT_SECONDS = 15
API_KEYS = ("OPENAI_API_KEY", "CODEX_API_KEY")
SPENDS_TURNS = ("login", "up", "approve", "turn")
INIT_STEPS = ("codex-home", "recipes", "workspace", "provision", "front-door", "policy", "lifecycle", "slots",
              "worktrees", "leases", "checkouts", "preflight")
# What init makes in the run folder; any of them already there means the folder is not fresh.
MANAGED = ("store", "lifecycle", "initiatives", "evidence", "preflight", "recipes.json", "policy.json", "worktrees",
           "loop", "loop.pid", "loop.log", "requests", "events", "inputs", "starts")
ROOT_PROMPT = ("Call team_pending, find request %s, then call root_decide once with that row's root_decide arguments, "
               "decision=%s, reason=\"owner: %s\". Do nothing else.")
ROUTER_NOTE = "the Router runs at effort %s and tier %s from the role registry; team.json cannot change it"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
# The aegis team commands read these; the run names --workspace itself, so none may redirect them.
AEGIS_OVERRIDES = ("AEGIS_WORKSPACE", "AEGIS_MANAGER_CONFIG", "AEGIS_MANAGER_CONFIG_SHA256", "GITHUB_BASE_REF")
PUBLISH_ID = re.compile(r'message_id\\*"?\s*:\s*\\*"([^"\\]+)')


# Owner-side adapters stay local until the registry can accept the reviewed successor table.

def codex_events(raw):
    for line in output_lines(raw):
        try:
            value = record_json(line, "model stdout")
        except CustodyProblem:
            raise
        except (ValueError, UnicodeError):
            value = None
        if isinstance(value, dict):
            yield value
        else:
            yield {"type": "unknown", "raw": line.decode("utf-8", "replace"), "raw_hex": line.hex()}


OWNER_ADAPTERS = {
    CODEX: {
        "program": "codex", "resume_word": b"resume", "home_attribute": "codex_home", "label": "Codex",
        "events": codex_events, "error": lambda event: event.get("type") == "turn.failed", "prefix_kind": "session_meta",
        "terminal": lambda *args: prove_codex_turn(*args), "usage": lambda raw: codex_usage(raw),
        "items": lambda raw: agent_items(raw), "log_records": lambda raw: raw_log_records(raw),
        "account": lambda *args: account_native_events(*args), "receipt_fields": {"log_span"}, "owns_receipt": True,
        "credentials": lambda run: None, "root_argv": lambda *args: codex_root_argv(*args),
        "root_validate": lambda *args: codex_root_validate(*args), "turn_profile": lambda *args: codex_turn_profile(*args),
        "resume_profile": lambda *args: codex_resume_profile(*args), "bind_root": lambda *args: codex_bind_root(*args),
        "failure": lambda *_args: None, "strict_root_tools": False, "exit_field": "codex_exit",
        "up_error": None, "allows_tmpdir": True, "isolated_homes": False, "transactional": False,
        "home_check": lambda run: safe_codex_home(run), "env_always": True, "check_home_always": True,
        "purge_flag": "purge_codex_home", "purge": lambda run: purge(run), "purge_check": lambda run: check_codex_purge(run),
        "tmpdir_error": None,
        "login_preflight": lambda run: None, "login": lambda run, _timeout: login_codex(run),
        "billing": lambda run: codex_billing(run),
        "expected_profile": lambda *args: expected_profile(*args), "check_role": lambda *args: check_role(*args),
    },
    CLAUDE: {
        "program": "claude", "resume_word": b"--resume", "home_attribute": "claude_home", "label": "Claude",
        "events": hierarchy_hosts.claude_events, "error": lambda event: event.get("type") == "result" and event.get("is_error") is True,
        "prefix_kind": None, "terminal": lambda *args: prove_claude_turn(*args), "usage": hierarchy_hosts.claude_usage,
        "items": hierarchy_hosts.claude_turn_items, "log_records": lambda raw: accounting_lines(raw),
        "account": lambda *args: account_usage_rows(*args), "receipt_fields": set(), "owns_receipt": False,
        "credentials": lambda run: claude_pin(run), "root_argv": lambda *args: claude_root_argv(*args),
        "root_validate": lambda *args: claude_root_validate(*args), "turn_profile": lambda *args: claude_turn_profile(*args),
        "resume_profile": lambda *args: claude_resume_profile(*args), "bind_root": lambda *args: claude_bind_root(*args),
        "failure": lambda *args: claude_turn_failure(*args), "strict_root_tools": True, "exit_field": "claude_exit",
        "up_error": "this team command starts claude-code team roles from T2(a) PR 6",
        "allows_tmpdir": False, "isolated_homes": True, "transactional": True,
        "home_check": lambda run: safe_claude_home(run), "env_always": False, "check_home_always": False,
        "purge_flag": "purge_claude_home", "purge": lambda run: purge_claude(run), "purge_check": lambda run: check_claude_purge(run),
        "tmpdir_error": "lane %s: tmpdir is only for a Codex writer, and this run\'s team host is claude-code",
        "login_preflight": lambda run: claude_login_preconditions(run), "login": lambda run, timeout: login_claude(run, timeout),
        "billing": lambda run: claude_billing(run),
        "expected_profile": None, "check_role": None,
    },
}
MAX_CUSTODY_INTEGER = (1 << 63) - 1
CUSTODY_RECOVERY = ("preserve this run; finish or stop its original sessions with the originating version, then init "
                    "a new run folder; do not replay")
INTERPRETER_RECOVERY = ("restore the recorded interpreter bytes or preserve this run and init a new run folder; "
                        "never repin a live run")


class CustodyProblem(ValueError):
    def __init__(self, message, reason, record, next_action=CUSTODY_RECOVERY):
        super().__init__(message)
        self.problem = {"reason": reason, "record": record, "error": message}
        self.next_action = next_action

    def detail(self):
        return {"custody_problem": self.problem, "next_action": self.next_action}


# Resource budgets bound owner memory/I/O, never truncate or rewrite provider evidence.
RECORD_BYTES = 262144
MARKER_BYTES = 16384
OUTPUT_BYTES = 16 << 20
OUTPUT_EVENTS = 65536
TURN_LOG_BYTES = 16 << 20
TRANSCRIPT_BYTES = 64 << 20
TRANSCRIPT_LINE_BYTES = 4 << 20
FRESH_BYTES = 8 << 20
FRESH_EVENTS = 1024
JSON_DEPTH = 32
UNINSPECTED = object()


def budget_problem(path, reason="byte budget"):
    return CustodyProblem("owner evidence exceeds its %s; retain the hold and preserve the original files" % reason,
                          reason, Path(path).name)


def bounded_read(stream, path, limit):
    if os.fstat(stream.fileno()).st_size > limit:
        raise budget_problem(path)
    blocks, length = [], 0
    while length <= limit:
        block = stream.read(min(1 << 20, limit + 1 - length))
        if not block:
            return b"".join(blocks)
        length += len(block)
        blocks.append(block)
    raise budget_problem(path)


def bounded_bytes(path, limit=RECORD_BYTES):
    path = Path(path)
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise CustodyProblem("owner evidence is not a regular file; retain the hold", "record type", path.name)
        return bounded_read(stream, path, limit)


def bounded_tail(path, limit):
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise CustodyProblem("owner evidence is not a regular file; retain the hold", "record type", Path(path).name)
        stream.seek(max(0, info.st_size - limit))
        return stream.read(limit)


def record_json(raw, record):
    # Check depth before json.loads allocates nested objects; quoted/escaped brackets are data.
    depth, quoted, escaped = 0, False, False
    for value in raw if isinstance(raw, bytes) else raw.encode("utf-8"):
        if quoted:
            if escaped:
                escaped = False
            elif value == 92:
                escaped = True
            elif value == 34:
                quoted = False
        elif value == 34:
            quoted = True
        elif value in (91, 123):
            depth += 1
            if depth > JSON_DEPTH:
                raise CustodyProblem("owner record exceeds the supported JSON depth", "record depth", str(record))
        elif value in (93, 125):
            depth -= 1
    try:
        return strict_json(raw)
    except RecursionError as exc:
        raise CustodyProblem("owner record exceeds the supported JSON depth", "record depth", str(record)) from exc


def read_json(path):
    return record_json(bounded_bytes(path), Path(path).name)


def environment_record(value):
    try:
        record_fields(value, {"dropped_names"}, kind="child environment")
        names = value["dropped_names"]
        require(isinstance(names, list) and len(names) <= 4096 and
                all(record_string(name, 512) and "=" not in name for name in names) and
                len(set(names)) == len(names), "invalid child environment record")
    except (ValueError, TypeError, RecursionError) as exc:
        raise CustodyProblem("invalid child environment record", "record shape", "child-environment.json") from exc
    return value


def record_line(stream, path, limit=TRANSCRIPT_LINE_BYTES):
    blocks, length = [], 0
    while length <= limit:
        block = stream.readline(min(1 << 20, limit + 1 - length))
        length += len(block)
        blocks.append(block)
        if not block or block.endswith(b"\n"):
            if length > limit:
                raise budget_problem(path)
            return b"".join(blocks)
    raise budget_problem(path)


def transcript_lines(stream, path, *, byte_limit=TRANSCRIPT_BYTES, count_limit=None):
    total = count = 0
    while True:
        line = record_line(stream, path)
        if not line:
            return
        total += len(line)
        count += 1
        if len(line) > TRANSCRIPT_LINE_BYTES or total > byte_limit:
            raise budget_problem(path)
        if count_limit is not None and count > count_limit:
            raise budget_problem(path, "event budget")
        yield line


def native_output(operation, field="stdout"):
    return bounded_bytes(operation[field], OUTPUT_BYTES)


def output_lines(raw):
    raw = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(raw) > OUTPUT_BYTES:
        raise budget_problem("model stdout")
    if raw.count(b"\n") + bool(raw and not raw.endswith(b"\n")) > OUTPUT_EVENTS:
        raise budget_problem("model stdout", "event budget")
    lines = raw.split(b"\n")
    if lines and not lines[-1]:
        lines.pop()
    for line in lines:
        if len(line) > TRANSCRIPT_LINE_BYTES:
            raise budget_problem("model stdout")
        yield line


def validate_output(raw):
    for line in output_lines(raw):
        try:
            record_json(line, "model stdout")
        except CustodyProblem:
            raise
        except (ValueError, UnicodeError):
            # Provider adapters retain their own malformed-event policy; budgets apply before decoding there.
            pass


def host_home(run, host):
    homes = getattr(run, "validated_homes", {})
    return homes.get(host, str(getattr(run, OWNER_ADAPTERS[host]["home_attribute"])))


def owner_events(host, raw):
    validate_output(raw)
    return OWNER_ADAPTERS[host]["events"](raw)


def owner_result_failed(host, raw):
    return any(OWNER_ADAPTERS[host]["error"](event) for event in owner_events(host, raw))


def bounded_integer(value, minimum=0, maximum=MAX_CUSTODY_INTEGER):
    return type(value) is int and minimum <= value <= maximum


def bounded_record_tree(value, depth=0):
    if depth > 32:
        return False
    if value is None or type(value) is bool or isinstance(value, str):
        return True
    if type(value) is int:
        return -MAX_CUSTODY_INTEGER <= value <= MAX_CUSTODY_INTEGER
    if isinstance(value, (list, dict)):
        items = value.values() if isinstance(value, dict) else value
        return len(value) <= 4096 and all(bounded_record_tree(item, depth + 1) for item in items)
    return False


def record_string(value, maximum=4096):
    return isinstance(value, str) and bool(value) and "\0" not in value and len(value) <= maximum


def record_fields(value, required, optional=(), kind="operation"):
    require(isinstance(value, dict) and required <= value.keys() and
            value.keys() <= required | set(optional), "invalid %s record" % kind)
    return value


def record_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def load_file_witness(value, kind="transcript"):
    record_fields(value, {"device", "inode", "offset", "prefix_sha256"}, kind=kind)
    require(all(bounded_integer(value[key]) for key in ("device", "inode", "offset")) and
            record_digest(value["prefix_sha256"]), "invalid %s record" % kind)
    return value


def load_operation(value, kind="operation"):
    required = {"id", "endpoint", "host", "session", "generation", "started_at", "pid", "process_scope",
                "stdout", "stderr", "transcripts", "prompt_sha256", "cwd", "turn_log", "marker", "marker_witness"}
    optional = () if kind == "active" else ("pid_start", "approval", "intent_recovery") if kind == "launch" else ("pid_start", "approval", "release", "intent_recovery")
    # An active intent may retain ROOT's approval request, but never a PID or release phase.
    if kind == "active":
        optional = ("approval",)
    record_fields(value, required, optional, kind)
    error = "invalid %s record" % kind
    require(isinstance(value["id"], str) and re.fullmatch(r"[0-9a-f]{32}", value["id"]) is not None and
            isinstance(value["host"], str) and value["host"] in OWNER_ADAPTERS and record_string(value["endpoint"]) and
            record_string(value["session"], 512) and bounded_integer(value["generation"], 1, (1 << 31) - 1) and
            all(record_string(value[key]) for key in ("started_at", "stdout", "stderr", "cwd", "turn_log")) and
            record_digest(value["prompt_sha256"]) and
            (value["pid"] is None or bounded_integer(value["pid"], 1, (1 << 31) - 1)), error)
    endpoint_parts(value["endpoint"])
    if kind == "active":
        require(value["pid"] is None, error)
    if "intent_recovery" in value:
        require(value["intent_recovery"] is True and value["pid"] is None and "pid_start" not in value, error)
    if "pid_start" in value:
        birth = value["pid_start"]
        require(birth is None or (isinstance(birth, str) and birth.isdigit() and len(birth) <= 19 and
                                  0 < int(birth) <= MAX_CUSTODY_INTEGER), error)
    scope = value["process_scope"]
    require(isinstance(scope, dict), error)
    if scope.get("state") == "UNAVAILABLE":
        require(set(scope) == {"state", "reason"} and isinstance(scope["reason"], str) and scope["reason"] in OPERATION_SCOPE_REASONS, error)
    else:
        require(set(scope) == {"boot_id", "pid_namespace", "proc_device", "proc_inode", "effective_uid"} and
                isinstance(scope["boot_id"], str) and re.fullmatch(r"[0-9a-f-]{36}", scope["boot_id"]) is not None and
                isinstance(scope["pid_namespace"], str) and re.fullmatch(r"pid:\[\d{1,20}\]", scope["pid_namespace"]) is not None and
                all(bounded_integer(scope[key]) for key in ("proc_device", "proc_inode", "effective_uid")), error)
    require(isinstance(value["transcripts"], dict) and len(value["transcripts"]) <= 128 and
            all(record_string(key) for key in value["transcripts"]), "invalid transcript record")
    for witness in value["transcripts"].values():
        load_file_witness(witness)
    marker, witness = value["marker"], value["marker_witness"]
    require((marker is None and witness is None) or (record_string(marker) and isinstance(witness, dict)), error)
    if witness is not None:
        record_fields(witness, {"device", "inode", "ctime_ns", "sha256", "operation_id"}, kind=kind)
        require(all(bounded_integer(witness[key]) for key in ("device", "inode", "ctime_ns")) and
                record_digest(witness["sha256"]) and witness["operation_id"] == value["id"], error)
    if "release" in value:
        release = value["release"]
        record_fields(release, {"accounting_sha256", "terminal_sha256"}, kind=kind)
        require(all(record_digest(item) for item in release.values()), error)
    if "approval" in value:
        approval = value["approval"]
        record_fields(approval, {"request_id", "decision", "request_sha256", "previous"}, kind=kind)
        require(record_string(approval["request_id"]) and approval["decision"] in ("approve", "deny") and
                record_digest(approval["request_sha256"]) and isinstance(approval["previous"], list) and
                all(isinstance(item, dict) and bounded_record_tree(item) for item in approval["previous"]), error)
    return value


def load_completion(value):
    record_fields(value, {"schema", "operation_id", "launch_sha256", "accounting_sha256", "files", "failed", "native_exit"},
                  kind="completion")
    require(value["schema"] == "aegis.team-owner-completion/v1" and isinstance(value["operation_id"], str) and
            re.fullmatch(r"[0-9a-f]{32}", value["operation_id"]) is not None and
            all(record_digest(value[key]) for key in ("launch_sha256", "accounting_sha256")) and
            type(value["failed"]) is bool and
            (value["native_exit"] is None or bounded_integer(value["native_exit"], -255, 255)) and
            isinstance(value["files"], dict) and len(value["files"]) <= 132 and
            all(record_string(key) for key in value["files"]), "invalid completion record")
    for witness in value["files"].values():
        load_file_witness(witness, "completion")
    return value


def load_runtime(value):
    record_fields(value, {"schema", "run", "initiative", "python", "source", "python_realpath", "custody",
                          "python_sha256", "source_commit", "source_tree"}, kind="runtime")
    require(value["schema"] == "aegis.team-owner-runtime/v1" and
            all(record_string(value[key]) for key in ("run", "initiative", "python", "source", "python_realpath")) and
            isinstance(value["custody"], dict) and bounded_record_tree(value["custody"]) and record_digest(value["python_sha256"]) and
            all(isinstance(value[key], str) and re.fullmatch(r"[0-9a-f]{40,64}", value[key]) is not None
                for key in ("source_commit", "source_tree")), "invalid runtime record")
    return value


def load_native_record(value, kind):
    # Finite layouts used by the existing native reader/fake; unknown host extensions remain HOLD, not proof.
    required = {"id"} if kind == "metadata" else {"turn_id", "cwd"}
    optional = ({"session_id", "timestamp", "cwd", "originator", "source", "cli_version", "model_provider", "git"}
                if kind == "metadata" else
                {"root_turn_id", "model", "effort", "approval_policy", "approvals_reviewer", "sandbox_policy",
                 "permission_profile", "summary", "service_tier", "multi_agent_version"})
    record_fields(value, required, optional, "Codex " + kind)
    error = "invalid Codex %s record" % kind
    require(all(record_string(value[key]) for key in required), error)
    for key, item in value.items():
        if key in ("sandbox_policy", "permission_profile", "git"):
            require(item is None or (isinstance(item, dict) and bounded_record_tree(item)), error)
        elif key == "source":
            require(isinstance(item, (str, dict)) and bounded_record_tree(item), error)
        elif key == "multi_agent_version":
            require(item is None or record_string(item) or bounded_integer(item, 0, 100), error)
        else:
            require(item is None or record_string(item), error)
    return value


def load_owner_value(name, value):
    if name == "runtime.json":
        return load_runtime(value)
    if name == "plan-issued.json":
        record_fields(value, {"schema", "plan_issued"}, kind="plan history")
        require(value["schema"] == "aegis.team-plan-issued/v1" and value["plan_issued"] is True,
                "invalid plan history record")
        return value
    if name.endswith(".exit.json"):
        return load_native_exit(value)
    if name.startswith("active-"):
        return load_operation(value, "active")
    if name.endswith(".launch.json"):
        return load_operation(value, "launch")
    return load_completion(value)



def owner_expected(run, state=UNINSPECTED):
    state = load_state(run) if state is UNINSPECTED else state
    return run.isolated_homes or bool(state and state.get("owner_custody"))


def plan_was_issued(run):
    state = load_state(run)
    folder = run.run / ".owner-custody"
    if folder.exists() or folder.is_symlink() or owner_expected(run):
        folder = owner_folder(run)
        if (folder / "plan-issued.json").exists() or (folder / "plan-issued.json").is_symlink():
            return owner_read(run, "plan-issued.json")["plan_issued"]
    if state and state.get("host_plan_issued"):
        raise CustodyProblem("this run's plan history is missing; preserve it and init a new run folder",
                             "record missing", "plan-issued.json")
    # Public evidence identifies transitional runs which issued plans before owner records existed.
    path = run.evidence / "index.json"
    value = read_json(path) if path.is_file() else {}
    return isinstance(value, dict) and isinstance(value.get("files"), dict) and hierarchy_hosts.PLAN_FILE in value["files"]


def governed_run(run):
    return run.raw["schema"] != SCHEMA or hierarchy_hosts.read_plan(run.base) is not None or plan_was_issued(run)


def legacy_environment(run):
    if run.raw["schema"] != SCHEMA or hierarchy_hosts.read_plan(run.base) is not None:
        return False
    if plan_was_issued(run):
        if init_complete(load_state(run)):
            refuse("this run's issued host plan is missing; restore host-plan.json before continuing")
        return False
    return True


class Stop(Exception):
    """A refusal or a failure with the exit code it means; detail joins the printed result."""

    def __init__(self, code, message, *, record_command=True, **detail):
        super().__init__(message)
        self.code = code
        self.detail = detail
        self.record_command = record_command


def refuse(message, **detail):
    raise Stop(REFUSED, message, **detail)


def fail(message, **detail):
    raise Stop(FAILED, message, **detail)


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def write_atomic(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    temporary.write_bytes(raw)
    os.replace(temporary, path)


def as_json(value):
    return (json.dumps(value, indent=1, sort_keys=True) + "\n").encode("utf-8")


# -- config -------------------------------------------------------------------------------------------------------------

def placeholders(value, where=""):
    if isinstance(value, str):
        if PLACEHOLDER.search(value):
            refuse("team-run.json holds a placeholder at %s: %s" % (where or "the top", value[:160]))
    elif isinstance(value, dict):
        for key, item in value.items():
            placeholders(item, key if not where else where + "." + key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            placeholders(item, "%s[%d]" % (where, index))


def absolute(value, label):
    text(value, label)
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts, "%s must be an absolute path without ..: %s" % (label, value))
    return path


def part(where, check):
    """Runs a check on part of the config and names that part in its refusal."""
    try:
        return check()
    except ValueError as exc:
        raise ValueError("%s: %s" % (where, exc)) from exc


class Lane:
    def __init__(self, run, index, value):
        where = "lanes[%d]" % index
        part(where, lambda: fields(value, {"id", "kind"}, {"worktree", "paths", "branch", "tmpdir"}))
        require(value["kind"] in LANE_KINDS, where + ": kind must be implementer or reviewer")
        self.id = part(where, lambda: matching(value["id"], SLUG, "lane id"))
        self.kind = value["kind"]
        self.endpoint = "%s/lane/%s" % (run.id, self.id)
        if self.kind == "reviewer":
            require(not {"worktree", "paths", "branch", "tmpdir"} & value.keys(),
                    where + ": a reviewer lane takes no worktree, paths, branch or tmpdir")
            self.worktree = self.paths = self.branch = self.tmpdir = self.lease = None
            return
        self.paths = value.get("paths")
        part(where, lambda: require(isinstance(self.paths, list) and self.paths and
                                    all(isinstance(p, str) and p for p in self.paths), "an implementer needs paths"))
        self.worktree = part(where, lambda: absolute(value.get("worktree", str(run.run / "worktrees" / self.id)),
                                                     "worktree"))
        self.branch = part(where, lambda: text(value.get("branch", run.branch), "branch", 255))
        self.tmpdir = None
        if "tmpdir" in value:
            tmpdir = Path(part(where, lambda: text(value["tmpdir"], "tmpdir", 255)))
            require(not tmpdir.is_absolute() and ".." not in tmpdir.parts, where + ": tmpdir must be relative to the worktree")
            self.tmpdir = self.worktree / tmpdir
        self.lease = "%s-%s" % (run.id, self.id)
        require(LEASE_LANE.fullmatch(self.lease) is not None, where + ": lease name %s is not a valid lane" % self.lease)


class Run:
    """The parsed team-run.json and the paths it implies."""

    def __init__(self, path):
        candidate = absolute(path, "--config")
        require(not candidate.is_symlink(), "symlink paths are not supported: " + str(candidate))
        self.config_path = Path(os.path.realpath(candidate))
        try:
            value = read_json(self.config_path)
        except FileNotFoundError:
            refuse("no config at %s" % self.config_path)
        require(isinstance(value, dict), "team-run.json must be a JSON object")
        placeholders(value)
        fields(value, {"schema", "run", "project", "base", "branch", "initiative", "roles", "lanes", "recipes", "limits",
                       "preflight", "team"},
               {"codex_home", "source", "live_checkouts", "base_tree", "min_free_gb", "loop", "lease_ttl_seconds",
                "hosts", "claude_home"})
        require(value["schema"] in (SCHEMA, SCHEMA_V2), "unsupported team-run schema: " + str(value["schema"])[:80])
        self.raw = value
        self.hosts = self.check_hosts()
        require(value["schema"] == SCHEMA_V2 or "claude_home" not in value, "claude_home needs schema " + SCHEMA_V2)
        self.run = absolute(value["run"], "run")
        if self.isolated_homes:
            # Preserve the reviewed owner-home diagnostics, then canonicalize safe parent aliases.
            self.run = safe_run_folder(self)
        else:
            self.run = Path(os.path.realpath(self.run))
        self.codex_home = absolute(value.get("codex_home", str(self.run / "codex-home")), "codex_home")
        # Made and checked only when the plan uses claude-code (ADR T2(a) section 3).
        self.claude_home = absolute(value.get("claude_home", str(self.run / "claude-home")), "claude_home")
        self.source = absolute(value.get("source", str(REPO)), "source")
        self.project = absolute(value["project"], "project")
        self.live = [absolute(item, "live_checkouts") for item in value.get("live_checkouts", [])]
        self.base_commit = matching(value["base"], GIT_ID, "base")
        self.base_tree = matching(value["base_tree"], GIT_ID, "base_tree") if "base_tree" in value else None
        self.branch = text(value["branch"], "branch", 255)
        self.initiative = value["initiative"]
        part("initiative", lambda: fields(self.initiative, {"id", "project", "repository", "priority", "target_branch"}))
        self.id = part("initiative", lambda: matching(self.initiative["id"], SLUG, "id"))
        self.roles = value["roles"]
        require(isinstance(self.roles, list) and len(self.roles) == len(set(self.roles)) and
                all(role in OPTIONAL_ROLES for role in self.roles), "roles may list only router and decider, once each")
        require(isinstance(value["lanes"], list) and value["lanes"], "lanes must list at least one lane")
        self.lanes = [Lane(self, index, lane) for index, lane in enumerate(value["lanes"])]
        names = [lane.id for lane in self.lanes]
        require(len(names) == len(set(names)), "lanes must have distinct ids")
        writers = [lane for lane in self.lanes if lane.kind == "implementer"]
        for index, lane in enumerate(writers):
            for other in writers[index + 1:]:
                require(lane.branch != other.branch, "lanes %s and %s share branch %s; give each implementer its own "
                        "branch" % (lane.id, other.id, lane.branch))
        self.recipes_config = value["recipes"]
        part("recipes", lambda: fields(self.recipes_config, {"keep", "python", "commit_identity"}, {"template"}))
        keep = self.recipes_config["keep"]
        require(isinstance(keep, list) and keep and len(keep) == len(set(keep)) and
                all(isinstance(name, str) and name for name in keep), "recipes.keep must list recipe names, once each")
        self.keep = keep
        self.python = str(absolute(self.recipes_config["python"], "recipes.python"))
        identity = self.recipes_config["commit_identity"]
        part("recipes.commit_identity", lambda: fields(identity, {"name", "email"}))
        part("recipes.commit_identity", lambda: (text(identity["name"], "name", 256), text(identity["email"], "email", 256)))
        self.template = absolute(self.recipes_config.get("template", str(DEFAULT_RECIPES)), "recipes.template")
        require(isinstance(value["limits"], dict), "limits must be a JSON object")
        self.limits = value["limits"]
        self.preflight = value["preflight"]
        self.check_preflight()
        self.min_free_gb = value.get("min_free_gb", DEFAULT_MIN_FREE_GB)
        require(type(self.min_free_gb) in (int, float) and self.min_free_gb > 0, "min_free_gb must be a positive number")
        loop = value.get("loop", {"interval": DEFAULT_INTERVAL})
        part("loop", lambda: fields(loop, set(), {"interval"}))
        self.interval = loop.get("interval", DEFAULT_INTERVAL)
        import hierarchy_loop
        low, high = hierarchy_loop.INTERVAL_RANGE
        require(type(self.interval) is int and low <= self.interval <= high,
                "loop.interval must be between %d and %d seconds" % (low, high))
        self.lease_ttl = value.get("lease_ttl_seconds", DEFAULT_LEASE_TTL)
        require(type(self.lease_ttl) is int and 60 <= self.lease_ttl <= 86400, "lease_ttl_seconds must be 60 to 86400")
        self.team = value["team"]
        self.check_team()
        self.base = self.run / "initiatives" / self.id
        self.mailbox_root = self.base / "mailbox"
        self.delivery = self.base / "delivery"
        self.store = self.run / "store"
        self.lifecycle = self.run / "lifecycle"
        self.evidence = self.run / "evidence"
        self.loop_state = self.run / "loop"
        self.recipes = self.run / "recipes.json"
        self.state_path = self.run / "team-state.json"
        self.pid_path = self.run / "loop.pid"
        self.log_path = self.run / "loop.log"
        self.commands_log = self.run / "team-commands.jsonl"
        self.inputs = self.run / "inputs"
        if self.isolated_homes:
            self.validated_homes = {host: adapter["home_check"](self) for host, adapter in OWNER_ADAPTERS.items()}

    def check_hosts(self):
        if self.raw["schema"] == SCHEMA:
            require("hosts" not in self.raw, "hosts needs schema " + SCHEMA_V2)
            return dict(V1_HOSTS)
        require("hosts" in self.raw, SCHEMA_V2 + " needs hosts: the root and team host kinds")
        hosts = self.raw["hosts"]
        part("hosts", lambda: fields(hosts, {"root", "team"}))
        for key in ("root", "team"):
            # Named apart from an unknown kind: provision knows native threads, and team runs start none.
            require(hosts[key] != hierarchy_hosts.NATIVE,
                    "hosts.%s is codex (native): team runs start no native threads" % key)
            require(isinstance(hosts[key], str) and hosts[key] in hierarchy_hosts.TEAM_HOSTS,
                    "hosts.%s must be claude-code or codex-cli, not %s" % (key, repr(hosts[key])[:80]))
        return {"root": hosts["root"], "team": hosts["team"]}

    def uses(self, kind):
        """Whether ROOT or the team runs on this host kind; a v1 config uses codex-cli alone."""
        return kind in self.hosts.values()


    @property
    def isolated_homes(self):
        return any(OWNER_ADAPTERS[host]["isolated_homes"] for host in set(self.hosts.values()))

    @property
    def transactional(self):
        return any(OWNER_ADAPTERS[host]["transactional"] for host in set(self.hosts.values()))

    def check_preflight(self):
        preflight = self.preflight
        part("preflight", lambda: fields(preflight, {"recipes", "expect"}, {"paths"}))
        recipes = preflight["recipes"]
        require(isinstance(recipes, list) and len(recipes) == len(set(recipes)), "preflight.recipes must list names once")
        for name in recipes:
            require(name in self.keep, "preflight recipe %s is not in recipes.keep" % name)
        require(isinstance(preflight["expect"], dict), "preflight.expect must be a JSON object")
        for name, expect in preflight["expect"].items():
            require(name in recipes, "preflight.expect names %s, which preflight.recipes does not list" % name)
            part("preflight.expect." + name, lambda: fields(expect, set(), {"state", "failed", "min_passed"}))
            require(expect.get("state", "completed") in ("completed", "failed"),
                    "preflight.expect.%s.state must be completed or failed" % name)
            for key in ("failed", "min_passed"):
                require(key not in expect or (type(expect[key]) is int and expect[key] >= 0),
                        "preflight.expect.%s.%s must be a whole number" % (name, key))
        paths = preflight.get("paths", {})
        require(isinstance(paths, dict), "preflight.paths must be a JSON object")
        for name, listed in paths.items():
            require(name in recipes and isinstance(listed, list) and listed and all(isinstance(p, str) for p in listed),
                    "preflight.paths.%s must list paths for a preflight recipe" % name)

    def check_team(self):
        team = self.team
        part("team", lambda: fields(team, {"model", "reasoning"}, {"reasoning_by_kind"}))
        text(team["model"], "team.model", 128)
        levels = ", ".join(hierarchy_provision.TEAM_LEVELS)
        require(team["reasoning"] in hierarchy_provision.TEAM_LEVELS, "team.reasoning must be one of " + levels)
        by_kind = team.get("reasoning_by_kind", {})
        require(isinstance(by_kind, dict), "team.reasoning_by_kind must be a JSON object")
        kinds = sorted(hierarchy_provision.TEAM_KINDS)
        for key, level in by_kind.items():
            require(key in kinds, "team.reasoning_by_kind: %s is not a team role kind (%s)" % (key, ", ".join(kinds)))
            require(level in hierarchy_provision.TEAM_LEVELS, "team.reasoning_by_kind.%s must be one of %s" % (key, levels))

    @property
    def implementers(self):
        return [lane for lane in self.lanes if lane.kind == "implementer"]

    @property
    def reviewers(self):
        return [lane for lane in self.lanes if lane.kind == "reviewer"]

    def endpoint(self, role):
        return "%s/%s" % (self.id, role)


# -- recipes --------------------------------------------------------------------------------------------------------------

def recipe_file(run):
    """The run's recipe file: the template with the home folder filled in, the configured python and commit identity,
    and only the kept recipes. The jobs tool validates the result (check-recipes)."""
    try:
        raw = bounded_bytes(run.template).decode("utf-8")
    except FileNotFoundError:
        refuse("the recipe template is missing: %s" % run.template)
    home = json.dumps(str(Path.home()))[1:-1]
    value = record_json(raw.replace(HOME_PLACEHOLDER, home), run.template.name)
    require(isinstance(value, dict) and isinstance(value.get("recipes"), dict),
            "the recipe template has no recipes: %s" % run.template)
    for name in run.keep:
        require(name in value["recipes"], "the recipe template has no recipe %s: %s" % (name, run.template))
    value["python"] = run.python
    value["identity"] = dict(run.recipes_config["commit_identity"])
    value["recipes"] = {name: value["recipes"][name] for name in run.keep}
    left = [word for word in json.dumps(value).split('"') if "REPLACE" in word]
    require(not left, "the recipes still hold a placeholder after filling the home folder: " + (left[0] if left else ""))
    return value


def current_recipes(run):
    return read_json(run.recipes) if run.recipes.is_file() else recipe_file(run)


def recipe_needs(recipes):
    """(a kept recipe that runs cargo, one that runs cargo nextest), each a name or None."""
    cargo = nextest = None
    for name, recipe in sorted(recipes.get("recipes", {}).items()):
        for step in recipe.get("steps", []) if isinstance(recipe, dict) else []:
            if not (isinstance(step, list) and step and isinstance(step[0], str)) or Path(step[0]).name != "cargo":
                continue
            cargo = cargo or name
            subcommand = next((word for word in step[1:] if isinstance(word, str) and not word.startswith(("-", "+"))),
                              None)
            if subcommand == "nextest":
                nextest = nextest or name
    return cargo, nextest


def recipe_path(recipes):
    return os.pathsep.join(item for item in recipes.get("path", []) if isinstance(item, str))


# -- the guard ----------------------------------------------------------------------------------------------------------

def nearest(path):
    while not path.exists() and path.parent != path:
        path = path.parent
    return path


def inside_owner(real, owner, check_identity):
    """Realpath containment, plus directory aliases such as bind mounts on Claude-bearing plans."""
    owner_real = os.path.realpath(owner)
    if real == owner_real or real.startswith(owner_real.rstrip(os.sep) + os.sep):
        return True
    if not check_identity:
        return False
    try:
        info = os.stat(owner)
    except (FileNotFoundError, NotADirectoryError):
        return False
    identity = (info.st_dev, info.st_ino)
    candidate = Path(real)
    for ancestor in (candidate, *candidate.parents):
        try:
            info = os.stat(ancestor)
        except (FileNotFoundError, NotADirectoryError):
            continue
        if (info.st_dev, info.st_ino) == identity:
            return True
    return False


def safe_home(run, home, label, variable, owners, apart=()):
    """The realpath of a run's host home, or a refusal: never an owner folder or inside one, never holding HOME, the run
    or an owner folder, apart from the run's other folders and from each (label, path) in `apart`, and no symlink."""
    real = os.path.realpath(home)
    for owner in owners:
        if inside_owner(real, owner, run.isolated_homes):
            refuse("%s %s is inside ~/%s (%s); a team run uses its own folder" % (variable, home, owner.name, owner))
    candidate = Path(real)
    def contains(parent, child):
        return parent == child or parent in child.parents
    for protected in (Path.home(), run.run, *owners):
        if contains(candidate, protected.resolve()):
            refuse("unsafe %s: it contains %s" % (label, protected))
    for protected in (run.project, run.source, run.evidence, *[run.run / name for name in MANAGED]):
        protected = protected.resolve()
        if contains(candidate, protected) or contains(protected, candidate):
            refuse("unsafe %s: it overlaps %s" % (label, protected))
    for other, path in apart:
        resolved = Path(os.path.realpath(path))
        if contains(candidate, resolved) or contains(resolved, candidate):
            refuse("unsafe %s: it overlaps %s %s" % (label, other, path))
    if home.is_symlink():
        refuse("unsafe %s: it is a symlink" % label)
    return real


def safe_codex_home(run):
    owners = owner_homes(CODEX) + owner_homes(CLAUDE)
    return safe_home(run, run.codex_home, "codex_home", "CODEX_HOME", owners)


def owner_homes(kind):
    """The owner's own folder for a host kind (~/.claude) under HOME and under the home the password database names,
    once each: a test or a shell that sets HOME must not hide the real one. It can move into the host registry later."""
    folder = hierarchy_hosts.entry(kind)["home"]["owner_folder"]
    try:
        import pwd  # POSIX only, as the rest of this command is
        real = pwd.getpwuid(os.getuid()).pw_dir
    except (ImportError, AttributeError, KeyError):
        refuse("cannot find this user's home folder in the password database, so ~/%s cannot be kept out" % folder)
    homes = []
    for home in (Path.home(), Path(real)):
        if home / folder not in homes:
            homes.append(home / folder)
    return homes


def safe_claude_home(run):
    return safe_home(run, run.claude_home, "claude_home", "CLAUDE_CONFIG_DIR", owner_homes(CLAUDE) + owner_homes(CODEX),
                     apart=[("codex_home", run.codex_home)])


def safe_run_folder(run):
    """Canonicalize safe run aliases, including /tmp on macOS, before any run write can follow them."""
    real = Path(os.path.realpath(run.run))
    for owner in owner_homes(CLAUDE) + owner_homes(CODEX):
        if inside_owner(str(real), owner, True):
            refuse("run folder %s is inside ~/%s (%s); a team run uses its own folder" %
                   (run.run, owner.name, owner))
    return real



def revalidate_homes(run):
    if not run.isolated_homes:
        return
    for host, adapter in OWNER_ADAPTERS.items():
        if adapter["home_check"](run) != run.validated_homes[host]:
            refuse("%s changed since it was validated for this command" % adapter["home_attribute"])


def revalidate_run(run):
    if run.isolated_homes and safe_run_folder(run) != run.run:
        refuse("run folder changed since it was validated for this command")


def active_adapters(run):
    return [(host, adapter) for host, adapter in OWNER_ADAPTERS.items() if run.uses(host)]


def home_environment(run):
    return {hierarchy_hosts.entry(host)["home"]["variable"]: host_home(run, host)
            for host, adapter in OWNER_ADAPTERS.items() if adapter["env_always"] or run.uses(host)}


def codex_billing(run):
    keys = [key for key in API_KEYS if key in hierarchy_hosts.billing_set(CODEX, os.environ)]
    if keys:
        refuse("unset OPENAI_API_KEY and CODEX_API_KEY: codex could bill this run to the key instead of the run's "
               "login (set: %s)" % ", ".join(keys))


def claude_billing(run):
    names = hierarchy_hosts.billing_set(CLAUDE, os.environ)
    if names:
        refuse("unset %s: claude could bill this run to them instead of the run's login" % ", ".join(names))



def guard(run, command):
    homes = [(host, adapter, adapter["home_check"](run)) for host, adapter in OWNER_ADAPTERS.items()
             if adapter["check_home_always"] or run.uses(host)]
    if command == "down":
        return {}
    for host, adapter, real in homes:
        variable = hierarchy_hosts.entry(host)["home"]["variable"]
        ambient = os.environ.get(variable)
        if ambient and os.path.realpath(ambient) != real:
            label = adapter["home_attribute"]
            refuse("%s in this shell is %s, not this run's %s %s; unset it or export the run's" %
                   (variable, ambient, label, getattr(run, label)))
    if command == "status":
        return {}
    if command == "init":
        validate_role_write_roots(run)
    probe = nearest(run.run)
    free = shutil.disk_usage(str(probe)).free / 2 ** 30
    if free < run.min_free_gb:
        refuse("only %.1f GB free at %s; this run needs min_free_gb %g" % (free, probe, run.min_free_gb))
    tools = {}
    for name in ("git", "bwrap", *[adapter["program"] for _, adapter in active_adapters(run)]):
        found = shutil.which(name)
        if found is None:
            refuse("required tool not found on PATH: " + name)
        if governed_run(run):
            validated_command(run, [found], {"PATH": os.environ.get("PATH", os.defpath)})
        tools[name] = found
    recipes = current_recipes(run)
    cargo, nextest = recipe_needs(recipes)
    path = recipe_path(recipes)
    for name, recipe, what in (("cargo", cargo, "cargo"), ("cargo-nextest", nextest, "cargo nextest")):
        if recipe is not None:
            found = shutil.which(name, path=path)
            if found is None:
                refuse("required tool not found on the recipes' path: %s (kept recipe %s runs %s)" % (name, recipe, what))
            tools[name] = found
    if command in SPENDS_TURNS:
        for _, adapter in active_adapters(run):
            adapter["billing"](run)
    return tools


# -- state, evidence and child processes ----------------------------------------------------------------------------------

def load_state(run):
    value = read_json(run.state_path) if run.state_path.is_file() else None
    require(value is None or (isinstance(value, dict) and isinstance(value.get("init"), dict) and
            isinstance(value.get("down", {}), dict)), "invalid team state record")
    return value


def custody(run):
    value = {key: run.raw.get(key) for key in ("run", "project", "source", "codex_home", "base", "branch",
                                              "initiative", "lanes", "roles")}
    # Only when given, so a v1 run's recorded custody still matches. The plan is written once at init, and changing
    # hosts during a run is out of scope (ADR T2(a) §1).
    if "hosts" in run.raw:
        value["hosts"] = run.raw["hosts"]
    if "claude_home" in run.raw:
        value["claude_home"] = run.raw["claude_home"]
    return value


def save_state(run, state):
    raw = as_json(state)
    require(len(raw) <= 262144, "team state exceeds its bounded size; preserve this run and init a new run folder")
    write_atomic(run.state_path, raw)


def update_state(run, mutate):
    """Reload/mutate/save in a short transaction; mutate must not run a child or wait for browser/model work."""
    if not run.transactional:
        state = load_state(run)
        mutate(state)
        save_state(run, state)
        return state
    # Lock order: .login.lock (when held), then .state.lock. Never acquire the login lock inside a transaction.
    revalidate_run(run)
    path = run.run / ".state.lock"
    require(not path.is_symlink(), "state lock must not be a symlink")
    descriptor = os.open(str(path), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    windows, locked = os.name == "nt", False
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                (not windows and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600))):
            refuse("state lock must be this user's regular file with one link and private permissions")
        if windows:
            import msvcrt
            os.lseek(descriptor, 0, os.SEEK_SET)
            # Windows permits locking a byte past EOF, so the empty lock file needs no unsynchronized seed write.
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = True
        state = load_state(run)
        mutate(state)
        save_state(run, state)
        return state
    finally:
        try:
            if locked:
                if windows:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def init_complete(state):
    return bool(state and state["init"].get("complete_at"))


def require_init(run, *, record_command=True, state=None):
    state = load_state(run) if state is None else state
    if not init_complete(state):
        refuse("init has not completed; run init first", record_command=record_command)
    if state.get("down", {}).get("started_at") or state.get("down", {}).get("done"):
        refuse("teardown has started; a new run needs a new run folder", record_command=record_command)
    require(isinstance(state.get("operations", {}), dict), "invalid operations record")
    return state


def index(run, *names):
    path = run.evidence / "index.json"
    value = read_json(path) if path.is_file() else {"schema": INDEX_SCHEMA, "files": {}}
    for name in names:
        value["files"][name] = {"sha256": sha_file(run.evidence / name), "at": timestamp()}
    write_atomic(path, as_json(value))


def save(run, name, value):
    path = run.evidence / name
    write_atomic(path, value if isinstance(value, bytes) else as_json(value))
    index(run, name)
    return {"path": str(path), "sha256": sha_file(path)}


def append_evidence(run, name, raw):
    path = run.evidence / name
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(path, "ab") as stream:
        stream.write(raw)
    index(run, name)
    return path


def child_env(run, path=None):
    revalidate_homes(run)
    # The owner-approved compatibility exception is exactly the historical v1/no-plan construction. A missing
    # v2 plan never opts a governed run into inheritance; Claude and all planned runs retain the allowlist.
    legacy = legacy_environment(run)
    if legacy:
        env = dict(os.environ)
    else:
        validate_owner_path(run, Path.cwd())
        env = {name: value for name, value in os.environ.items()
               if name in CHILD_ENVIRONMENT or name.startswith("LC_")}
    env.update(home_environment(run))
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if path is not None:
        env["PATH"] = path
    if not legacy:
        validate_child_environment(run, env, Path.cwd())
    run.dropped_names = getattr(run, "dropped_names", set()) | (os.environ.keys() - env.keys())
    return env



def environment_evidence(run):
    names = getattr(run, "dropped_names", None)
    if names is not None:
        name = "child-environment.json"
        path = run.evidence / name
        previous = environment_record(read_json(path)) if path.exists() else {"dropped_names": []}
        value = environment_record({"dropped_names": sorted(set(previous["dropped_names"]) | names)})
        if value != previous:
            save(run, name, value)


def last_json(stdout):
    lines = [line for line in stdout.splitlines() if line.strip()]
    if not lines:
        return {}
    try:
        value = json.loads(lines[-1])
    except ValueError:
        return {"output": stdout[-2000:]}
    return value if isinstance(value, dict) else {"output": value}


def tool(run, name, *arguments):
    """(exit code, last JSON object of stdout, process) of one hierarchy tool run as a child."""
    argv = [sys.executable, "-I", "-B", str(HERE / ("hierarchy_%s.py" % name)), *map(str, arguments)]
    env = child_env(run)
    argv = validated_command(run, argv, env)
    proc = subprocess.run(argv, capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)
    return proc.returncode, last_json(proc.stdout), proc


def checked(run, label, name, *arguments, ok=(0,)):
    code, answer, proc = tool(run, name, *arguments)
    if code not in ok:
        reason = answer.get("error") or proc.stderr.strip()[-800:] or "exit %d" % code
        (refuse if code == REFUSED else fail)("%s: %s" % (label, reason), result=answer)
    return answer


def request_file(run, name, value):
    path = run.inputs / name
    write_atomic(path, as_json(value))
    return path



def git(cwd, *arguments, ok=False, run=None):
    env = child_env(run) if run is not None and governed_run(run) else None
    argv = ["git", "-C", str(cwd), *arguments]
    if env is not None:
        argv = validated_command(run, argv, env, cwd)
    proc = subprocess.run(argv, capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)
    if not ok and proc.returncode != 0:
        raise ValueError("git %s failed in %s: %s" % (arguments[0], cwd, proc.stderr.strip()[-400:]))
    return proc if ok else proc.stdout.strip()


def aegis(run, *arguments):
    """`aegis team ...` from this checkout, isolated (-I) with the package path named, and no AEGIS_* overrides."""
    code = ("import runpy, sys; sys.path.insert(0, %r); sys.argv = ['aegis'] + sys.argv[1:]; "
            "runpy.run_module('aegis_cli', run_name='__main__')" % str(REPO))
    env = child_env(run)
    for name in AEGIS_OVERRIDES:
        env.pop(name, None)
    argv = validated_command(run, [sys.executable, "-I", "-B", "-c", code, *arguments], env, REPO)
    proc = subprocess.run(argv, cwd=str(REPO), capture_output=True,
                          text=True, env=env, stdin=subprocess.DEVNULL)
    try:
        answer = json.loads(proc.stdout)
    except ValueError:
        answer = {"output": proc.stdout[-2000:]}
    return proc.returncode, answer, proc


# -- init ---------------------------------------------------------------------------------------------------------------

def preconditions(run):
    """Checked on a fresh init only: the folders and the clone it may use. Nothing is written before these pass."""
    for name in MANAGED:
        if (run.run / name).exists():
            refuse("run folder already holds %s; init needs a fresh run folder" % name)
    if run.codex_home.exists():
        refuse("codex_home %s already exists; init needs a new folder" % run.codex_home)
    if run.isolated_homes and run.claude_home.exists():
        refuse("claude_home %s already exists; init needs a new folder" % run.claude_home)
    real = os.path.realpath(run.project)
    for live in run.live:
        mine = os.path.realpath(live)
        if real == mine or real.startswith(mine.rstrip(os.sep) + os.sep):
            refuse("project is the owner's live checkout %s; use a fresh clone" % live)
    top = git(run.project, "rev-parse", "--show-toplevel", ok=True, run=run)
    if top.returncode != 0 or os.path.realpath(top.stdout.strip()) != real:
        refuse("project %s is not the root of a git checkout" % run.project)
    head = git(run.project, "rev-parse", "HEAD", run=run)
    if head != run.base_commit:
        refuse("project HEAD is %s, not the configured base %s" % (head, run.base_commit))
    tree = git(run.project, "rev-parse", run.base_commit + "^{tree}", run=run)
    if run.base_tree is not None and tree != run.base_tree:
        refuse("base tree is %s, not the configured base_tree %s" % (tree, run.base_tree))
    if git(run.project, "status", "--porcelain", "--untracked-files=all", run=run):
        refuse("project has uncommitted changes; a run starts from a clean clone")
    for lane in run.implementers:
        if git(run.project, "rev-parse", "--verify", "--quiet", "refs/heads/" + lane.branch, ok=True, run=run).returncode == 0:
            refuse("branch %s already exists in the project" % lane.branch)
    return tree


def once(run, state, key, action):
    """Persist intent before an external command; an uncertain result must never authorize a replay."""
    done = state["init"]["done"]
    if key not in done:
        pending = state["init"].get("pending")
        if pending:
            fail("init step %s has an unresolved outcome; inspect durable records before continuing" % pending)
        state["init"]["pending"] = key
        save_state(run, state)
        value = action()
        done[key] = value if isinstance(value, dict) else {"at": timestamp()}
        state["init"].pop("pending", None)
        save_state(run, state)
    return done[key]


def make_home(run, home, label):
    """A host home with this run's owner mark; one already there must carry the mark (a resumed init)."""
    run.run.mkdir(parents=True, exist_ok=True, mode=0o700)
    if home.exists():
        ownership(run, home, label)
        return
    home.mkdir(parents=True, mode=0o700)
    os.chmod(home, 0o700)
    mark = {"run": str(run.run), "initiative": run.id, "created_at": timestamp()}
    write_atomic(home / OWNER_MARK, as_json(mark))



def step_codex_home(run, state):
    """Keep the recorded legacy step name; each active adapter supplies its home policy."""
    detail = {}
    for host, adapter in active_adapters(run):
        adapter["home_check"](run)
        home = Path(host_home(run, host))
        label = adapter["home_attribute"]
        make_home(run, home, label)
        detail[label] = str(home)
    return detail


def step_recipes(run, state):
    write_atomic(run.recipes, as_json(recipe_file(run)))
    answer = checked(run, "check-recipes", "jobs", "--store", run.store, "--recipes", run.recipes, "check-recipes")
    if answer.get("recipes_sha256") != sha_file(run.recipes):
        fail("check-recipes hashed %s, but recipes.json is %s" % (answer.get("recipes_sha256"), sha_file(run.recipes)))
    save(run, "recipes-check.json", answer)
    return {"recipes_sha256": answer["recipes_sha256"]}


def step_workspace(run, state):
    limits = request_file(run, "limits.json", run.limits)
    save(run, "workspace-init.json", checked(run, "workspace init", "workspace", "--store", run.store, "init",
                                             "--request", limits))


def initiative_record(run):
    return {**run.initiative, "checkouts": [str(run.project)], "source": "owner",
            "lanes": [lane.lease for lane in run.implementers]}


def step_provision(run, state):
    request = {"store": str(run.store), "base": str(run.base), "source": str(run.source), "python": run.python,
               "roles": run.roles, "lanes": {lane.id: lane.kind for lane in run.lanes},
               "initiative": initiative_record(run)}
    # Provision init refuses an initiative it already registered, so a failure after it (the evidence save or the plan
    # write) resumes past it on --continue instead of running it again.
    answer = once(run, state, "provision-init", lambda: checked(run, "provision init", "provision", "init", "--request",
                                                               request_file(run, "provision-init.json", request)))
    owner_runtime(run, initialize=True, provisioned=answer)
    if not (owner_folder(run) / "plan-issued.json").exists():
        owner_publish(run, "plan-issued.json", {"schema": "aegis.team-plan-issued/v1", "plan_issued": True})
    state["owner_custody"] = state["host_plan_issued"] = True
    save(run, "provision-init.json", answer)
    # Here rather than as a step of its own, so a run already past this step keeps today's unchecked bindings. Provision
    # init refuses an existing base, so the plan can only follow it, before the first add-role.
    plan = hierarchy_hosts.plan_record(hierarchy=run.id, root=run.hosts["root"], team=run.hosts["team"],
                                       stand_ins={run.endpoint("front-door"): FRONT_DOOR_HOST},
                                       config_sha256=sha_file(run.config_path))
    write_atomic(run.base / hierarchy_hosts.PLAN_FILE, as_json(plan))
    save(run, hierarchy_hosts.PLAN_FILE, plan)


def step_front_door(run, state):
    # A stand-in binding that never runs a host: the owner's front-door mail goes through the mailbox CLI.
    request = {"base": str(run.base), "endpoint": run.endpoint("front-door"), "host": FRONT_DOOR_HOST,
               "session": str(uuid.uuid4()), "cwd": str(run.run)}
    save(run, "front-door.json", checked(run, "front-door add-role", "provision", "add-role", "--request",
                                         request_file(run, "front-door.json", request)))


def policy_value(run, authority):
    roles = ["root", "router", "coordinator", "operator", "reviewer"] + (["decider"] if "decider" in run.roles else [])
    actors = {}
    for role in roles:
        router = role == "router"
        # Journal labels only: the journal hashes them, and the served model comes from team.json at `up`.
        actors[role + "-1"] = {"role": role, "generation": 1, "cap_seconds": 86400 if role == "root" else 3600,
                               "profile": {"model": run.team["model"], "effort": "medium" if router else run.team["reasoning"],
                                           "tier": "ultrafast" if router else "default",
                                           "filesystem": "workspace-write" if role == "operator" else "read-only",
                                           "tools": ["read", "decide"] if role == "root" else []}}
    commit = git(run.source, "rev-parse", "HEAD", run=run)
    tree = git(run.source, "rev-parse", "HEAD^{tree}", run=run)
    return {"schema": hierarchy_lifecycle.POLICY, "source": {"commit": commit, "tree": tree, "dirty_sha256": EMPTY_SHA256},
            "authority": [authority], "actors": actors, "current": {role: role + "-1" for role in roles},
            "successors": {}}


def step_policy(run, state):
    authority = save(run, "owner-authority.txt", ("Owner authorizes the team run %s on %s (base %s), %s.\n" % (
        run.id, run.project, run.base_commit, timestamp()[:10])).encode("utf-8"))
    policy = policy_value(run, authority)
    write_atomic(run.run / "policy.json", as_json(policy))
    save(run, "policy.json", policy)


def step_lifecycle(run, state):
    once(run, state, "lifecycle-init", lambda: save(run, "lifecycle-init.json", checked(
        run, "lifecycle init", "lifecycle", "--root", run.lifecycle, "init", "--policy", run.run / "policy.json",
        "--evidence-only")))
    once(run, state, "checkpoint-before", lambda: save(run, "checkpoint-before.json", checked(
        run, "lifecycle checkpoint", "lifecycle", "--root", run.lifecycle, "checkpoint")))


def step_slots(run, state):
    for lane in run.implementers:
        def ask(lane=lane):
            answer = checked(run, "slot request for " + lane.id, "workspace", "--store", run.store, "request",
                             "--request", request_file(run, "slot-%s.json" % lane.id, {
                                 "initiative": run.id, "kind": "writer", "holder": lane.endpoint}))
            save(run, "slot-request-%s.json" % lane.id, answer)
            return {"request_id": answer["request"]["request_id"]}
        asked = once(run, state, "slot-request:" + lane.id, ask)

        def grant(lane=lane, asked=asked):
            answer = checked(run, "slot grant for " + lane.id, "workspace", "--store", run.store, "grant-next",
                             "--kind", "writer")
            granted = answer.get("granted")
            if granted is None:
                fail("no writer slot is free for %s: %s" % (lane.endpoint, json.dumps(answer.get("waiting"))[:400]))
            if granted["request_id"] != asked["request_id"]:
                fail("the writer slot went to %s, not %s's request %s" % (granted["holder"], lane.endpoint,
                                                                          asked["request_id"]))
            save(run, "slot-grant-%s.json" % lane.id, answer)
        once(run, state, "slot-grant:" + lane.id, grant)


def step_worktrees(run, state):
    for lane in run.implementers:
        def add(lane=lane):
            lane.worktree.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            git(run.project, "worktree", "add", "-q", "-b", lane.branch, str(lane.worktree), run.base_commit, run=run)
            if lane.tmpdir is not None:
                lane.tmpdir.mkdir(parents=True, exist_ok=True, mode=0o700)
            save(run, "worktree-%s.json" % lane.id, {
                "path": str(lane.worktree), "branch": lane.branch, "head": git(lane.worktree, "rev-parse", "HEAD", run=run),
                "tmpdir": None if lane.tmpdir is None else str(lane.tmpdir)})
            return {"path": str(lane.worktree), "branch": lane.branch}
        once(run, state, "worktree:" + lane.id, add)


def step_leases(run, state):
    for lane in run.implementers:
        def claim(lane=lane):
            code, answer, proc = aegis(run, "team", "claim", lane.lease, "--workspace", str(run.project), "--paths",
                                       *lane.paths, "--ttl", str(run.lease_ttl), "--owner", lane.endpoint, "--role",
                                       "implementer", "--branch", lane.branch, "--json")
            if code != 0:
                fail("aegis team claim %s: %s" % (lane.lease, answer.get("error") or answer.get("message") or
                                                  proc.stderr.strip()[-400:] or "exit %d" % code), result=answer)
            save(run, "lease-claim-%s.json" % lane.id, answer)
            return {"lease": lane.lease, "oid": answer["oid"]}
        once(run, state, "lease:" + lane.id, claim)


def step_checkouts(run, state):
    request = {"initiative": run.id, "source": "owner",
               "checkouts": [str(run.project)] + [str(lane.worktree) for lane in run.implementers]}
    save(run, "checkouts.json", checked(run, "workspace update", "workspace", "--store", run.store, "update",
                                        "--request", request_file(run, "checkouts.json", request)))


def preflight_result(run, recipe, job, expect, recipes_sha256):
    path = run.run / "preflight" / "store" / "jobs" / (run.id + "pre") / job / "result.json"
    if not path.is_file():
        return {"recipe": recipe, "job": job, "met": False, "problem": "preflight %s: the job left no result" % recipe}
    result = read_json(path)
    tests = result.get("tests")
    row = {"recipe": recipe, "job": job, "state": result.get("state"), "tests": tests, "reason": result.get("reason"),
           "recipes_sha256": result.get("recipes_sha256"),
           "git_stub": (result.get("source_export") or {}).get("git_stub", False), "expect": expect,
           "result": {"path": str(path), "sha256": sha_file(path)}}
    want = expect.get("state", "completed")
    problem = None
    if row["state"] != want:
        problem = "expected state %s, the job ended %s%s" % (want, row["state"],
                                                            " (%s)" % row["reason"] if row["reason"] else "")
    elif ("failed" in expect or "min_passed" in expect) and not isinstance(tests, dict):
        problem = "expected test counts, the job reported none"
    elif "failed" in expect and tests["failed"] != expect["failed"]:
        problem = "expected %d failed, the job reported %d" % (expect["failed"], tests["failed"])
    elif "min_passed" in expect and tests["passed"] < expect["min_passed"]:
        problem = "expected at least %d passed, the job reported %d" % (expect["min_passed"], tests["passed"])
    elif row["recipes_sha256"] != recipes_sha256:
        problem = "the job ran under recipes %s, not the checked %s" % (row["recipes_sha256"], recipes_sha256)
    row["met"] = problem is None
    if problem:
        row["problem"] = "preflight %s: %s" % (recipe, problem)
    return row


def step_preflight(run, state):
    """The kept recipes on the base, in a store of their own, with stand-in sessions that never run."""
    pre = run.run / "preflight"
    pre_id = run.id + "pre"
    require(SLUG.fullmatch(pre_id) is not None, "initiative id %s is too long for the preflight's %s" % (run.id, pre_id))
    store, base = pre / "store", pre / "initiatives" / pre_id
    once(run, state, "preflight-store", lambda: checked(run, "preflight workspace init", "workspace", "--store", store,
                                                        "init", "--request", run.inputs / "limits.json"))
    once(run, state, "preflight-provision", lambda: checked(
        run, "preflight provision init", "provision", "init", "--request", request_file(run, "preflight-init.json", {
            "store": str(store), "base": str(base), "source": str(run.source), "python": run.python,
            "lanes": {"p": "implementer"},
            "initiative": {**run.initiative, "id": pre_id, "repository": run.initiative["repository"] + "-preflight",
                           "checkouts": [str(run.project)], "source": "owner"}})))
    roles = {}
    for role in ("orchestrator", "root"):
        roles[role] = once(run, state, "preflight-" + role, lambda role=role: checked(
            run, "preflight add-role " + role, "provision", "add-role", "--request",
            request_file(run, "preflight-%s.json" % role, {"base": str(base), "endpoint": "%s/%s" % (pre_id, role),
                                                            "host": "claude-code", "session": str(uuid.uuid4()),
                                                            "cwd": str(run.run)})))
    attempt = state["init"].get("preflight_attempt", 0) + 1
    state["init"]["preflight_attempt"] = attempt
    save_state(run, state)
    sender = roles["orchestrator"]
    tree = state["init"]["base_tree"]
    jobs = {}
    for recipe in run.preflight["recipes"]:
        packet = {"schema": PACKET_SCHEMA, "recipe": recipe, "checkout": str(run.project), "commit": run.base_commit,
                  "tree": tree}
        if recipe in run.preflight.get("paths", {}):
            packet["paths"] = run.preflight["paths"][recipe]
        job = "pre-%d-%s" % (attempt, recipe)
        message = {"message_id": job + "-packet", "from": sender["endpoint"], "to": "%s/root" % pre_id,
                   "host": sender["host"], "session": sender["session"], "binding_generation": sender["generation"],
                   "type": "info", "body": json.dumps(packet, sort_keys=True)}
        sent = checked(run, "preflight packet " + recipe, "mailbox", "--root", base / "mailbox", "publish", "--request",
                       request_file(run, "preflight-%s-packet.json" % job, message))
        message = {**message, "message_id": job, "type": "job_request", "body": "Preflight %s on the base." % recipe,
                   "brief": {"path": sent["path"], "sha256": sent["sha256"]}}
        checked(run, "preflight job request " + recipe, "mailbox", "--root", base / "mailbox", "publish", "--request",
                request_file(run, "preflight-%s.json" % job, message))
        jobs[recipe] = job
    ran = checked(run, "preflight run-open", "jobs", "--store", store, "--recipes", run.recipes, "run-open",
                  "--initiative", pre_id, ok=(0, 3))
    save(run, "preflight-run-open.json", ran)
    checked_sha = state["init"]["steps"]["recipes"]["recipes_sha256"]
    rows = [preflight_result(run, recipe, jobs[recipe], run.preflight["expect"].get(recipe, {}), checked_sha)
            for recipe in run.preflight["recipes"]]
    save(run, "preflight-results.json", {"attempt": attempt, "results": rows})
    save(run, "preflight-clean.json", checked(run, "preflight clean", "jobs", "--store", store, "--recipes", run.recipes,
                                              "clean", "--initiative", pre_id, "--finished"))
    problems = [row["problem"] for row in rows if not row["met"]]
    if problems:
        fail(problems[0], results=rows)
    return {"attempt": attempt}


STEPS = {"codex-home": step_codex_home, "recipes": step_recipes, "workspace": step_workspace,
         "provision": step_provision, "front-door": step_front_door, "policy": step_policy,
         "lifecycle": step_lifecycle, "slots": step_slots, "worktrees": step_worktrees, "leases": step_leases,
         "checkouts": step_checkouts, "preflight": step_preflight}


def next_step(state):
    if state is None:
        return INIT_STEPS[0]
    return next((step for step in INIT_STEPS if step not in state["init"]["steps"]), None)


def init(run, args):
    validate_role_write_roots(run)
    validate_owner_path(run, Path.cwd())
    if not OWNER_ADAPTERS[run.hosts["team"]]["allows_tmpdir"]:
        # Provision makes tmpdir Codex-only, so a Claude team refuses one here rather than at up (ADR T2(a) section 1).
        for lane in run.implementers:
            if lane.tmpdir is not None:
                refuse(OWNER_ADAPTERS[run.hosts["team"]]["tmpdir_error"] % lane.id)
    state = load_state(run)
    if state and (state.get("down", {}).get("started_at") or state.get("down", {}).get("done")):
        refuse("teardown has started; a new run needs a new run folder")
    if init_complete(state):
        refuse("init already completed at %s; a new run needs a new run folder" % state["init"]["complete_at"])
    if args.resume:
        if state is None:
            refuse("nothing to continue: init has not run in %s" % run.run)
    elif state is not None:
        failed = state["init"].get("failed") or {"step": next_step(state), "error": "it was interrupted"}
        refuse("init stopped at %s: %s; fix the cause, then run init --continue" % (failed["step"], failed["error"]))
    else:
        tree = preconditions(run)
        state = {"schema": STATE_SCHEMA, "created_at": timestamp(), "config": str(run.config_path),
                 "custody": custody(run),
                 "init": {"steps": {}, "done": {}, "failed": None, "complete_at": None, "base_tree": tree},
                 "root": None, "up": None, "down": {"done": {}}}
        revalidate_run(run)
        run.run.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not getattr(run, "owner_operation_locked", False):
            # The first init creates the directory that owns the lock. Reload everything under that lock before
            # its first state save too, so two initializers cannot outlive one another and erase later operations.
            with operation_lock(run):
                return init(run, args)
        owner_folder(run, create=True)
        state["owner_custody"] = True
        save_state(run, state)
    revalidate_run(run)
    ran = []
    for step in INIT_STEPS:
        if step in state["init"]["steps"]:
            continue
        try:
            detail = STEPS[step](run, state)
        except (Stop, ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
            code = exc.code if isinstance(exc, Stop) else FAILED
            extra = exc.detail if isinstance(exc, Stop) else {}
            state["init"]["failed"] = {"step": step, "error": str(exc), "at": timestamp()}
            save_state(run, state)
            raise Stop(code, str(exc), step=step, **extra) from exc
        state["init"]["steps"][step] = {"at": timestamp(), **(detail or {})}
        state["init"]["failed"] = None
        save_state(run, state)
        ran.append(step)
    state["init"]["complete_at"] = timestamp()
    save_state(run, state)
    return OK, {"init": "complete", "ran": ran, "run": str(run.run), "evidence": str(run.evidence),
                "next": "login, then root --session <your ROOT session>, then up"}


# -- login and root -------------------------------------------------------------------------------------------------------

@contextmanager
def login_lock(run, busy_message="another login is running for this run"):
    """Keep one lock inode for this run; closing releases it on every success or exception, without unlinking it."""
    import fcntl  # POSIX operations only; the module itself is imported during Windows test collection.
    revalidate_run(run)
    descriptor = os.open(str(run.run / ".login.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600):
            refuse("login lock must be this user's regular file with one link and mode 0600")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            refuse(busy_message, record_command=False)
        yield
    finally:
        os.close(descriptor)


def claude_login_preconditions(run):
    """All read-only Claude checks precede either host's interactive login in a mixed plan."""
    revalidate_homes(run)
    timeout = float(os.environ.get(CLAUDE_AUTH_STATUS_TIMEOUT, "60"))
    require(0 < timeout <= 60, CLAUDE_AUTH_STATUS_TIMEOUT + " must be greater than 0 and at most 60 seconds")
    credentials_digest(run, missing_ok=True)
    return timeout



def login(run, args):
    require_init(run)
    if not run.transactional:
        host = run.hosts["root"]
        return OK, OWNER_ADAPTERS[host]["login"](run, None)
    with login_lock(run):
        require_init(run)
        timeouts = {host: adapter["login_preflight"](run) for host, adapter in active_adapters(run)}
        logins = {}
        try:
            for host, adapter in active_adapters(run):
                logins[host] = adapter["login"](run, timeouts[host])
        except Stop as stop:
            if logins:
                stop.detail.setdefault("logins", logins)
            raise
        return OK, {"logins": logins}


def login_codex(run):
    import hierarchy_native_probe as probe
    env = child_env(run)
    proc = subprocess.run(validated_command(run, ["codex", "login"], env), env=env)
    if proc.returncode != 0:
        fail("codex login exited %d" % proc.returncode)
    revalidate_homes(run)
    home = Path(host_home(run, CODEX))
    # The probe's real-login folder rules, less its own owner mark, with this run's mark and its sessions/ allowed.
    allowed = (set(probe.EXISTING_LOGIN_ENTRIES) - {probe.OWNER_MARK}) | {OWNER_MARK, "sessions"}
    entries = sorted(os.listdir(home))
    extra = [entry for entry in entries if entry not in allowed]
    try:
        if extra:
            raise probe.Refusal("CODEX_HOME holds entries a codex login does not create: " + ", ".join(extra))
        if probe.AUTH_FILE not in entries:
            raise probe.Refusal("CODEX_HOME has no auth.json after codex login")
        auth = probe.auth_digest(home / probe.AUTH_FILE)
        probe.login_extras(home, shutil.which("codex"))
    except probe.Refusal as exc:
        refuse(str(exc))
    answer = {"codex_home": str(run.codex_home), "auth_sha256": auth, "entries": entries}
    revalidate_homes(run)
    save(run, "login.json", answer)
    return answer


def credentials_digest(run, missing_ok=False):
    """The sha256 of the Claude home's credentials file, which must be this user's one regular file with mode 0600. The
    file itself is never copied, and only its hash enters evidence."""
    path = Path(run.validated_homes[CLAUDE]) / CLAUDE_CREDENTIALS
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        refuse("claude_home has no %s after claude auth login" % CLAUDE_CREDENTIALS)
    if stat.S_ISLNK(info.st_mode):
        refuse("%s in claude_home is a symlink: %s" % (CLAUDE_CREDENTIALS, path))
    if not stat.S_ISREG(info.st_mode):
        refuse("%s in claude_home is not a regular file: %s" % (CLAUDE_CREDENTIALS, path))
    # A second link could be the owner's own ~/.claude credentials, which the run would then refresh and use.
    if info.st_nlink != 1:
        refuse("%s in claude_home has %d hard links: %s" % (CLAUDE_CREDENTIALS, info.st_nlink, path))
    if info.st_uid != os.getuid():
        refuse("%s in claude_home is not owned by this user: %s" % (CLAUDE_CREDENTIALS, path))
    if stat.S_IMODE(info.st_mode) != 0o600:
        refuse("%s in claude_home has mode %04o, not 0600: %s" % (CLAUDE_CREDENTIALS, stat.S_IMODE(info.st_mode), path))
    # O_NONBLOCK: a FIFO swapped in after the lstat would otherwise block this open forever.
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if ((opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_uid) !=
                (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid)):
            refuse("%s in claude_home changed while it was checked: %s" % (CLAUDE_CREDENTIALS, path))
        return hashlib.sha256(bounded_read(stream, path, RECORD_BYTES)).hexdigest()


def credential_observation(run):
    """Observe identity and bytes in the validated home; metadata also detects a rewrite with identical contents."""
    path = Path(run.validated_homes[CLAUDE]) / CLAUDE_CREDENTIALS
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
        return None
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if ((opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_uid) !=
                (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid)):
            refuse("%s in claude_home changed while it was observed: %s" % (CLAUDE_CREDENTIALS, path))
        digest = hashlib.sha256(bounded_read(stream, path, RECORD_BYTES)).hexdigest()
    return {"identity": (info.st_dev, info.st_ino, digest),
            "version": (info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)}


def remove_login_credentials(run, before, written):
    """Within the login lock, remove only the regular file whose device, inode and bytes this login changed."""
    if written is None or written == before:
        return False
    home = Path(run.validated_homes[CLAUDE])
    try:
        real = safe_home(run, home, "claude_home", "CLAUDE_CONFIG_DIR", owner_homes(CLAUDE) + owner_homes(CODEX))
    except Stop:
        return False
    if real != str(home):
        return False
    current = credential_observation(run)
    if current is None or current["identity"] != written["identity"]:
        return False
    (home / CLAUDE_CREDENTIALS).unlink()
    return True


def discard_claude_login_evidence(run):
    """A failed login must not leave an accepted login record or its index entry, including from an earlier login."""
    revalidate_run(run)
    (run.evidence / "login-claude.json").unlink(missing_ok=True)
    path = run.evidence / "index.json"
    if path.is_file():
        value = read_json(path)
        if "login-claude.json" in value["files"]:
            del value["files"]["login-claude.json"]
            write_atomic(path, as_json(value))


def login_claude(run, timeout, host=CLAUDE):
    """claude auth login in the run's CLAUDE_CONFIG_DIR, which the owner finishes in the browser, then its status. The
    evidence keeps the filtered auth record (no email or organization) and the credentials' hash, never the file."""
    revalidate_homes(run)
    credentials_digest(run, missing_ok=True)
    state = require_init(run)
    if host in state.get("logins", {}):
        def invalidate(current):
            require_init(run, state=current)
            current.get("logins", {}).pop(CLAUDE, None)
            revalidate_homes(run)
        update_state(run, invalidate)
    # A CLI may truncate or refresh credentials: refuse unsafe existing files before either auth command sees them.
    before = credential_observation(run)
    written = None
    try:
        env = child_env(run)
        proc = subprocess.run(validated_command(run, ["claude", "auth", "login", "--claudeai"], env), env=env)
        written = credential_observation(run)
        if proc.returncode != 0:
            fail("claude auth login exited %d" % proc.returncode)
        # A teardown completed by an older command must remain authoritative after the browser login returns.
        require_init(run, record_command=False)
        revalidate_homes(run)
        credentials_digest(run)
        env = child_env(run)
        proc = subprocess.run(validated_command(run, ["claude", "auth", "status", "--json"], env), env=env, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=timeout)
        try:
            parsed = strict_json(proc.stdout)
        except (ValueError, RecursionError):
            parsed = None
        revalidate_homes(run)
        record, problems = hierarchy_hosts.claude_auth_check(proc.returncode, parsed, run.validated_homes[CLAUDE])
        if problems:
            refuse("claude auth status does not show this run's claude.ai login: " + "; ".join(problems))
        digest = credentials_digest(run)
        answer = {"claude_home": str(run.claude_home), "auth": record, "credentials_sha256": digest,
                  "entries": sorted(os.listdir(run.validated_homes[CLAUDE])),
                  "managed_settings": CLAUDE_MANAGED_SETTINGS.exists()}
        revalidate_homes(run)
        save(run, "login-claude.json", answer)
        def accept(current):
            require_init(run, record_command=False, state=current)
            current.setdefault("logins", {})[CLAUDE] = {"credentials_sha256": digest}
            revalidate_homes(run)
        update_state(run, accept)
        return answer
    except Exception as exc:
        removed = remove_login_credentials(run, before, written)
        discard_claude_login_evidence(run)
        if removed and isinstance(exc, Stop):
            raise Stop(exc.code, str(exc) + "; removed credentials written by this login",
                       record_command=exc.record_command, **exc.detail) from exc
        # Keep TimeoutExpired intact: main maps subprocess failures to exit 3.
        raise


def adapter_tools(run, connection):
    """The tool names ROOT's own connection offers, read with tools/list over it."""
    server = read_json(Path(connection))["mcpServers"]["aegis_decision"]
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}]
    env = child_env(run)
    command = validated_command(run, [server["command"], *server["args"]], env)
    proc = subprocess.run(command, input="".join(json.dumps(f) + "\n" for f in frames),
                          capture_output=True, text=True, timeout=60, env=env)
    for line in proc.stdout.splitlines():
        reply = json.loads(line)
        if reply.get("id") == 2 and "result" in reply:
            return [entry["name"] for entry in reply["result"]["tools"]]
    fail("ROOT's connection listed no tools: %s" % (proc.stdout + proc.stderr)[-400:])


def current_actor(run, role):
    return read_json(run.run / "policy.json")["current"].get(role)


def claude_pin(run):
    revalidate_homes(run)
    pinned = (require_init(run).get("logins", {}).get(CLAUDE) or {}).get("credentials_sha256")
    require(pinned is not None and credentials_digest(run) == pinned,
            "the run's Claude login changed since `login`; run login again before starting Claude")
    for folder, directories, names in os.walk(run.validated_homes[CLAUDE], followlinks=False):
        for name in directories + names:
            require(not (Path(folder) / name).is_symlink(), "claude_home contains a symlink: " + str(Path(folder) / name))



def claude_transcript(run, session):
    found = hierarchy_hosts.transcripts(CLAUDE, run.validated_homes[CLAUDE], session)
    require(len(found) == 1, "Claude session is not confirmed by one transcript in the run's claude_home/projects")
    confirmed = False
    descriptor = os.open(str(found[0]), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), "Claude transcript must be a regular file")
        if info.st_size > TRANSCRIPT_BYTES:
            raise budget_problem(found[0])
        for line in transcript_lines(stream, found[0]):
            try:
                event = record_json(line, found[0].name)
            except CustodyProblem:
                raise
            except (ValueError, UnicodeError):
                continue
            if isinstance(event, dict) and isinstance(event.get("sessionId"), str):
                require(event["sessionId"] == session, "Claude session is not confirmed by its transcript sessionId")
                confirmed = True
    require(confirmed, "Claude session is not confirmed by its transcript sessionId")
    return found[0]


def planned_binding(run, endpoint, host):
    mailbox = Mailbox(run.mailbox_root)
    entry = hierarchy_provision.registry_role(mailbox, endpoint)
    plan = hierarchy_hosts.governing_plan(run.base, run.mailbox_root, run.id)
    if run.raw["schema"] == SCHEMA_V2:
        expected = hierarchy_hosts.plan_record(run.id, run.hosts["root"], run.hosts["team"],
            {run.endpoint("front-door"): FRONT_DOOR_HOST}, sha_file(run.config_path))
        require(plan == expected, "v2 MAIN host plan is missing or differs from team-run.json")
    if plan is None and run.raw["schema"] == SCHEMA and plan_was_issued(run):
        refuse("this run's issued host plan is missing; restore host-plan.json before continuing")
    hierarchy_hosts.require_binding(plan, endpoint, host, hierarchy_roles.writer(entry))
    return mailbox


def governed_runtime(run):
    trusted = owner_runtime(run)
    validate_role_write_roots(run)
    validate_owner_path(run, Path.cwd())
    setup = read_json(run.base / "provision.json")
    require(isinstance(setup, dict) and set(setup) == {"schema", "created_at", "store", "source", "source_commit",
            "source_tree", "python", "initiative", "mailbox_root", "delivery_dir"} and
            setup.get("schema") == hierarchy_provision.SCHEMA and isinstance(setup.get("created_at"), str),
            "invalid team provision record")
    require(setup.get("python") == run.python and setup.get("source") == str(run.source) and
            setup.get("mailbox_root") == str(run.mailbox_root) and setup.get("delivery_dir") == str(run.delivery) and
            setup.get("store") == str(run.store) and setup.get("initiative") == run.id,
            "team runtime differs from team-run.json")
    require(all(setup.get(key) == trusted[key] for key in ("source_commit", "source_tree")),
            "team runtime differs from the owner-held record")
    hierarchy_provision.hierarchy_runtime_source.verify(setup, run.base)
    return setup


def connection_spec(run, binding, setup):
    host, endpoint = binding["host"], binding["endpoint"]
    if endpoint_parts(endpoint)[1] == "root":
        request = {"lifecycle": str(run.lifecycle), "actor": current_actor(run, "root"),
                   "loop_state": str(run.loop_state), "evidence": str(run.evidence)}
        arguments = hierarchy_provision.decision_args(setup, endpoint, host, binding["session"], binding["generation"], request)
        return {"aegis_decision": {"command": setup["python"], "args": arguments}}, list(ROOT_TOOLS), request
    mailbox = Mailbox(run.mailbox_root)
    request = next((dict(value) for name, value in plan_roles(run) if name == endpoint), None)
    require(request is not None, "endpoint is outside this team's approved role plan")
    entry = hierarchy_provision.registry_role(mailbox, endpoint)
    arguments = hierarchy_provision.adapter_args(setup, endpoint, host, binding["session"], binding["generation"],
        request.get("source_repo"), hierarchy_provision.lifecycle_args(request))
    servers = {"aegis_mailbox": {"command": setup["python"], "args": arguments}}
    enabled = hierarchy_provision.MAILBOX_TOOLS + list(hierarchy_provision.role_workspace_tools(mailbox, endpoint))
    if "lifecycle" in request:
        enabled += list(hierarchy_roles.lifecycle_tools(entry))
    if request.get("source_repo"):
        enabled += list(hierarchy_roles.SOURCE_VIEW_TOOLS)
    return servers, enabled, request


def governed_connection(run, binding, connection, setup=None):
    label = OWNER_ADAPTERS[binding["host"]]["label"]
    setup = governed_runtime(run) if setup is None else setup
    canonical = run.base / "connections" / ("%s-g%d.json" %
        (binding["endpoint"].replace("/", "%2F"), binding["generation"]))
    require(str(connection) == str(canonical), label + " connection path differs from the team's canonical connection")
    servers = read_json(canonical)
    require(isinstance(servers, dict) and set(servers) == {"mcpServers"}, label + " connection has unexpected fields")
    require(isinstance(servers["mcpServers"], dict) and bool(servers["mcpServers"]) and
            all(isinstance(name, str) and isinstance(server, dict) and set(server) == {"command", "args"} and
                record_string(server["command"]) and isinstance(server["args"], list) and
                all(isinstance(word, str) and "\0" not in word for word in server["args"])
                for name, server in servers["mcpServers"].items()), "invalid " + label + " connection servers")
    expected, enabled, request = connection_spec(run, binding, setup)
    for server in servers["mcpServers"].values():
        if "--source-repo" in server["args"]:
            words = server["args"]
            offset = words.index("--source-repo")
            require(offset + 1 < len(words) and words[offset + 1] == request.get("source_repo"),
                    label + " connection names an unauthorized source repository")
    require(servers["mcpServers"] == expected, label + " connection differs from the team's provisioned servers")
    server_name = "aegis_decision" if endpoint_parts(binding["endpoint"])[1] == "root" else "aegis_mailbox"
    return ["mcp__%s__%s" % (server_name, name) for name in enabled]


def codex_resume_profile(run, binding, profile):
    setup = governed_runtime(run)
    connection = run.base / "connections" / ("%s-g%d.json" %
        (binding["endpoint"].replace("/", "%2F"), binding["generation"]))
    governed_connection(run, binding, connection, setup)
    servers, enabled, request = connection_spec(run, binding, setup)
    mailbox = Mailbox(run.mailbox_root)
    request, fixed = hierarchy_provision.fixed_profile(request, mailbox, binding["endpoint"], CODEX)
    request, _team = hierarchy_provision.team_settings(run.base, CODEX, request,
        hierarchy_provision.role_kind(mailbox, binding["endpoint"]))
    _tools, writer = hierarchy_provision.role_tools(binding["endpoint"], mailbox, None)
    expected_servers = hierarchy_provision.codex_servers(setup, servers["aegis_mailbox"]["args"], enabled)
    expected = hierarchy_provision.codex_profile(str(Path(request["cwd"]).resolve()), writer=writer,
        servers=expected_servers, options=request, endpoint=binding["endpoint"],
        role=hierarchy_roles.role_name(binding["endpoint"], mailbox.endpoint(binding["endpoint"]).get("kind")),
        session=binding["session"], generation=binding["generation"], tier=hierarchy_provision.applied_tier(fixed))
    recorded = connection.parent.parent / "profiles" / (connection.stem + ".codex.json")
    require(read_json(recorded) == expected and profile["cwd"] == expected["cwd"] and profile["prompt_via"] == "argv" and
            profile.get("mode", "print") == "print" and
            profile["argv"] == hierarchy_provision.codex_argv(expected, ["resume", binding["session"]]),
            "Codex print profile differs from the registry argv")
    # The configured worktree and optional explicit tmpdir are the only writer roots; no parent run capability.
    for root in [expected["cwd"], *expected["writable_roots"], *expected["add_dirs"],
                 *([expected["tmpdir"]] if expected["tmpdir"] else [])]:
        real = Path(root).resolve()
        control = run.run / ".owner-custody"
        require(real != control and real not in control.parents and control not in real.parents,
                "Codex sandbox includes owner custody or an ancestor")
    return profile["argv"]


def codex_root_config(run, binding, connection):
    setup = governed_runtime(run)
    governed_connection(run, binding, connection, setup)
    servers, enabled, _request = connection_spec(run, binding, setup)
    server = {**servers["aegis_decision"], "required": True, "enabled_tools": enabled,
              "tools": {name: hierarchy_provision.APPROVE for name in enabled}}
    return "mcp_servers=" + hierarchy_provision.toml_value({"aegis_decision": server})


def claude_resume_profile(run, binding, profile):
    start = next((request for endpoint, request in plan_roles(run) if endpoint == binding["endpoint"]), None)
    require(start is not None and profile["cwd"] == str(Path(start["cwd"]).resolve()),
            "Claude print profile cwd differs from the configured worktree")
    argv = profile["argv"]
    require(isinstance(argv, list) and all(isinstance(word, str) for word in argv), "invalid Claude print argv")
    connection = str(run.base / "connections" / ("%s-g%d.json" % (binding["endpoint"].replace("/", "%2F"), binding["generation"])))
    allowed = governed_connection(run, binding, connection)
    mailbox = Mailbox(run.mailbox_root)
    tool_words = [word[len("--tools="):] for word in argv if word.startswith("--tools=")]
    require(len(tool_words) == 1, "Claude print profile differs from the registry argv")
    tools, _writer = hierarchy_provision.role_tools(binding["endpoint"], mailbox, tool_words[0])
    allowed += [name for name in tools if name in hierarchy_provision.WRITE_TOOLS]
    options = {}
    for flag, key in (("--model", "model"), ("--effort", "effort")):
        if flag in argv:
            offset = argv.index(flag)
            require(offset + 1 < len(argv), "incomplete Claude print argument: " + flag)
            options[key] = argv[offset + 1]
    options, _fixed = hierarchy_provision.fixed_profile(options, mailbox, binding["endpoint"], CLAUDE)
    options, _team = hierarchy_provision.team_settings(run.base, CLAUDE, options,
                                                      hierarchy_provision.role_kind(mailbox, binding["endpoint"]))
    # The registry builder has one supported --settings payload. Never pass a profile's arbitrary JSON through.
    if "--settings" in argv and options.get("effort") == "max":
        options = {**options, "ultracode": True}
    expected = hierarchy_provision.claude_argv(["--resume", binding["session"]], connection, tools, allowed, options, None)
    require(argv == expected, "Claude print profile differs from the registry argv")
    return expected


def root(run, args):
    state = require_init(run)
    require(hierarchy_provision.SESSION.fullmatch(args.session) is not None, "invalid session: " + args.session[:80])
    host = run.hosts["root"]
    mailbox = planned_binding(run, run.endpoint("root"), host)
    if governed_run(run):
        governed_runtime(run)
    request = {"base": str(run.base), "endpoint": run.endpoint("root"), "host": host, "session": args.session,
               "lifecycle": str(run.lifecycle), "actor": current_actor(run, "root"), "loop_state": str(run.loop_state),
               "evidence": str(run.evidence)}
    history = mailbox.bindings(request["endpoint"])
    require(not history or (history[-1]["session"] == args.session and history[-1]["host"] == host),
            "endpoint is bound to another session; hand it off first")
    hierarchy_roles.require_independent_session(mailbox, request["endpoint"], host, args.session)
    adapter = OWNER_ADAPTERS[host]
    answer = adapter["bind_root"](run, request, args.session)
    try:
        tools = adapter_tools(run, answer["connection"])
    except (Stop, ValueError, OSError, subprocess.SubprocessError) as exc:
        fail("ROOT was bound but its tool probe failed: %s; binding, connection and session record retained" % exc)
    if adapter["strict_root_tools"] and tuple(tools) != ROOT_TOOLS:
        fail("ROOT tools mismatch after binding; binding and session record retained for inspection", tools=tools)
    save(run, "root-binding.json", {**answer, "tools": tools})
    binding = {"session": args.session, "generation": answer["generation"], "connection": answer["connection"],
               "mcp_config": answer["mcp_config"], "tools": tools, "at": timestamp()}
    if run.transactional:
        def bind(current):
            require_init(run, state=current)
            current["root"] = binding
        update_state(run, bind)
    else:
        state["root"] = binding
        save_state(run, state)
    return OK, {"endpoint": answer["endpoint"], "session": args.session, "generation": answer["generation"],
                "connection": answer["connection"], "mcp_config": answer["mcp_config"], "tools": tools}


# -- up -------------------------------------------------------------------------------------------------------------------

def loop_flags(run):
    return ["--lifecycle", run.lifecycle, "--store", run.store, "--recipes", run.recipes, "--state-dir", run.loop_state]


def process_alive(pid):
    try:
        with open("/proc/%d/stat" % pid, encoding="utf-8") as stream:
            # The state follows the command name, which is in parentheses and may hold spaces.
            return stream.read().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def loop_process(run):
    """(pid or None, alive, whether that process is this run's loop by its command line)."""
    try:
        pid = int(run.pid_path.read_text().strip())
    except (OSError, ValueError):
        return None, False, False
    if not process_alive(pid):
        return pid, False, False
    try:
        words = Path("/proc/%d/cmdline" % pid).read_bytes().decode("utf-8", "replace").split("\0")
    except OSError:
        return pid, False, False
    ours = any(Path(word).name == "hierarchy_loop.py" for word in words) and any(
        word == "--lifecycle" and index + 1 < len(words) and words[index + 1] == str(run.lifecycle)
        for index, word in enumerate(words))
    return pid, True, ours


def loop_state(run):
    """The loop's own lock-based liveness (hierarchy_loop.py status): running, stale or not_running."""
    if not run.lifecycle.is_dir():
        return "not_running", None
    _code, answer, _ = tool(run, "loop", *loop_flags(run), "status")
    return answer.get("state", "not_running"), answer


def plan_roles(run):
    """(endpoint, start request) in the order up starts them: router, orchestrator, decider, reviewers, implementers."""
    rows = []
    if "router" in run.roles:
        rows.append((run.endpoint("router"), {"cwd": str(run.project), "lifecycle": str(run.lifecycle)}))
    rows.append((run.endpoint("orchestrator"), {"cwd": str(run.project), "reader_shell": True}))
    if "decider" in run.roles:
        rows.append((run.endpoint("decider"), {"cwd": str(run.project), "reader_shell": True,
                                               "lifecycle": str(run.lifecycle), "actor": current_actor(run, "decider")}))
    for lane in run.reviewers:
        rows.append((lane.endpoint, {"cwd": str(run.project), "reader_shell": True}))
    for lane in run.implementers:
        request = {"cwd": str(lane.worktree)}
        if lane.tmpdir is not None:
            request["tmpdir"] = str(lane.tmpdir)
        rows.append((lane.endpoint, request))
    return rows


def expected_profile(run, mailbox, endpoint):
    """What provision builds the role's argv from: the registry's fixed profile, then team.json."""
    request, fixed = hierarchy_provision.fixed_profile({}, mailbox, endpoint, CODEX)
    options, _ = hierarchy_provision.team_settings(run.base, CODEX, request,
                                                   hierarchy_provision.role_kind(mailbox, endpoint))
    if not (options.get("model") and options.get("effort")):
        refuse("%s would start with no model or effort; team.json must give both" % endpoint)
    return {"model": options["model"], "effort": options["effort"], "tier": hierarchy_provision.applied_tier(fixed),
            "effort_from": "the role registry" if fixed is not None else "team.json"}


def find_rollout(run, endpoint, session):
    home = Path(host_home(run, CODEX))
    found = sorted((home / "sessions").glob("**/rollout-*%s.jsonl" % session))
    if len(found) != 1:
        fail("%s rollout%s for %s's session %s under %s" % ("no" if not found else str(len(found)),
                                                           "" if len(found) == 1 else "s", endpoint, session,
                                                           home / "sessions"))
    return found[0]


def stop_role(run, endpoint):
    _code, answer, _ = tool(run, "launcher", "--base", run.base, "stop", "--endpoint", endpoint)
    return answer


def check_role(run, endpoint, session, want, accept):
    """The started role's rollout: no sub-agent tools (unless accepted), and the model and effort asked for. The served
    tier is reported, not checked: whether an account is served the Router's ultrafast tier is the probe's question."""
    rollout = find_rollout(run, endpoint, session)
    try:
        catalog = hierarchy_native.multi_agent_state(str(rollout), cid=session)
    except ValueError as exc:
        stop_role(run, endpoint)
        refuse("%s tool catalog is unavailable; it was stopped: %s" % (endpoint, exc))
    offered = catalog["agent_tools"]
    if not catalog["tool_records"] or catalog.get("unknown_tools"):
        stop_role(run, endpoint)
        refuse("%s tool catalog is unavailable; it was stopped" % endpoint)
    if offered and not accept:
        stop_role(run, endpoint)
        refuse("%s was offered sub-agent tools: %s; it was stopped. Pass --accept-agent-tools to accept that, which is "
               "recorded in evidence" % (endpoint, ", ".join(offered)))
    observed = hierarchy_native.inspect_codex(str(rollout), session, requested_tier=want["tier"] or "default")
    served = observed["profile"]
    problem = None
    if served["model"] != want["model"]:
        problem = "%s was served model %s, but team.json asks for %s" % (endpoint, served["model"], want["model"])
    elif served["effort"] != want["effort"]:
        problem = "%s was served effort %s, but %s asks for %s" % (endpoint, served["effort"], want["effort_from"],
                                                                   want["effort"])
    if problem:
        stop_role(run, endpoint)
        refuse(problem)
    return {"rollout": str(rollout), "model": served["model"], "effort": served["effort"],
            "tier": observed["served_tier"], "tier_asked": want["tier"] or "default", "agent_tools": offered}


def loop_environment(run):
    recipes = read_json(run.recipes)
    cargo_recipe, _ = recipe_needs(recipes)
    env = child_env(run)
    cargo_dir = None
    if cargo_recipe is not None:
        # The roles' own cargo runs inherit the loop's PATH through the wake, so the recipes' cargo goes first.
        cargo_dir = os.path.dirname(shutil.which("cargo", path=recipe_path(recipes)))
        parts = env.get("PATH", "").split(os.pathsep)
        if parts[:1] != [cargo_dir]:
            env["PATH"] = os.pathsep.join([cargo_dir] + [p for p in parts if p])
    validate_child_environment(run, env, run.run)
    if governed_run(run):
        for program in ["git", *[OWNER_ADAPTERS[host]["program"] for host in dict.fromkeys(run.hosts.values())]]:
            validated_command(run, [program], env, run.run)
    return env, cargo_dir


def start_loop(run):
    env, cargo_dir = loop_environment(run)
    run.loop_state.mkdir(parents=True, exist_ok=True, mode=0o700)
    argv = [sys.executable, "-I", "-B", str(HERE / "hierarchy_loop.py"), *map(str, loop_flags(run)), "run",
            "--interval", str(run.interval)]
    argv = validated_command(run, argv, env, run.run)
    with open(run.log_path, "ab") as log:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env=env,
                                   cwd=str(run.run), start_new_session=True)
    write_atomic(run.pid_path, ("%d\n" % process.pid).encode("ascii"))
    time.sleep(0.5)
    if process.poll() is not None:
        tail = bounded_tail(run.log_path, 800).decode("utf-8", "replace")
        fail("the loop exited at once (exit %d); see %s: %s" % (process.returncode, run.log_path, tail))
    environ = {}
    for item in Path("/proc/%d/environ" % process.pid).read_bytes().split(b"\0"):
        key, _, value = item.decode("utf-8", "replace").partition("=")
        if key:
            environ[key] = value
    problems = []
    expected_homes = home_environment(run)
    for variable, expected in expected_homes.items():
        if environ.get(variable) != expected:
            problems.append("its %s is %s, not %s" % (variable, environ.get(variable), expected))
    if cargo_dir is not None and cargo_dir not in environ.get("PATH", "").split(os.pathsep):
        problems.append("its PATH lacks %s, where the recipes' cargo is" % cargo_dir)
    if problems:
        process.terminate()
        process.wait(timeout=LOOP_WAIT_SECONDS)
        fail("the loop (pid %d) was stopped: %s" % (process.pid, "; ".join(problems)))
    lines = "".join("%s=%s\n" % (key, environ[key]) for key in expected_homes)
    save(run, "loop-environ.txt", (lines + "PATH=%s\n" % environ.get("PATH", "")).encode("utf-8"))
    return {"state": "started", "pid": process.pid, "interval": run.interval, "log": str(run.log_path),
            "cargo_on_path": cargo_dir}


def up(run, args):
    require_init(run)
    # Before the loop status check, which runs a child: nothing is started or written for a Claude team yet.
    host = run.hosts["team"]
    adapter = OWNER_ADAPTERS[host]
    if adapter["up_error"]:
        refuse(adapter["up_error"])
    if governed_run(run):
        validate_owner_path(run, Path.cwd())
        for role_cwd in [run.project, *[lane.worktree for lane in run.implementers]]:
            validate_model_executable(run, host, [adapter["program"]], str(role_cwd))
    if not args.no_loop:
        loop_environment(run)
    pid, alive, ours = loop_process(run)
    running, _ = loop_state(run)
    if (alive and ours) or running in ("running", "stale"):
        refuse("a loop for this run is already running (pid %s); run down first" % (pid if alive and ours else "unknown"))
    mailbox = Mailbox(run.mailbox_root)
    roles = plan_roles(run)
    team_path = run.base / "team.json"
    if team_path.is_file() and read_json(team_path) != run.team and any(mailbox.bindings(e) for e, _ in roles):
        refuse("team.json differs from this config's team, and roles already started under it keep their settings; "
               "restore it or hand those roles off")
    if governed_run(run):
        governed_runtime(run)
        from hierarchy_wake import load_profile
        for endpoint, _request in roles:
            history = mailbox.bindings(endpoint)
            if history:
                binding = history[-1]
                profile_path = run.base / "profiles" / ("%s-g%d.wake.json" %
                    (endpoint.replace("/", "%2F"), binding["generation"]))
                adapter["resume_profile"](run, binding, load_profile(profile_path, endpoint, binding))
    write_atomic(team_path, as_json(run.team))
    save(run, "team.json", run.team)
    wanted = {endpoint: adapter["expected_profile"](run, mailbox, endpoint) for endpoint, _ in roles}
    rows, accepted = [], {}
    for endpoint, request in roles:
        history = mailbox.bindings(endpoint)
        if history:
            if history[-1]["host"] != host:
                refuse("%s is bound to a %s session, not a %s role the launcher starts" % (endpoint, history[-1]["host"], adapter["label"]))
            session, label = history[-1]["session"], "already_bound"
        else:
            path = request_file(run, "start-%s.json" % endpoint.replace("/", "%2F"), {"endpoint": endpoint, **request})
            code, answer, proc = tool(run, "launcher", "--base", run.base, "start", "--request", path)
            if code != 0 or answer.get("state") != "bound":
                reason = answer.get("error") or proc.stderr.strip()[-400:] or "no error was recorded"
                message = "%s did not start: %s (launcher exit %d, state %s)" % (endpoint, reason, code,
                                                                                  answer.get("state"))
                (refuse if code == REFUSED else fail)(message, record=answer)
            session, label = answer["session"], "bound"
        checked_role = adapter["check_role"](run, endpoint, session, wanted[endpoint], args.accept_agent_tools)
        if checked_role["agent_tools"]:
            accepted[endpoint] = checked_role["agent_tools"]
        rows.append({"endpoint": endpoint, "state": label, "session": session, **checked_role})
    if accepted:
        save(run, "up-agent-tools-accepted.json", {"at": timestamp(), "roles": accepted,
                                                   "note": "accepted by the owner with --accept-agent-tools"})
    save(run, "up-roles.json", rows)
    save(run, "launcher-status-start.json", checked(run, "launcher status", "launcher", "--base", run.base, "status"))
    loop = {"state": "not_started", "reason": "--no-loop"} if args.no_loop else start_loop(run)
    raised = {"at": timestamp(), "roles": [row["endpoint"] for row in rows], "loop": loop}
    def record(current):
        require_init(run, state=current)
        current["up"] = raised
    update_state(run, record)
    note = None
    if "router" in run.roles:
        profile = hierarchy_roles.role(run.endpoint("router"))["model_profile"]
        note = ROUTER_NOTE % (profile["effort"], profile["tier"])
    return OK, {"roles": rows, "router": note, "loop": loop, "team_json": str(team_path)}


# -- request, approve, turn -------------------------------------------------------------------------------------------------

def request(run, args):
    require_init(run)
    value = read_json(absolute(args.file, "--file"))
    require(isinstance(value, dict), "the request file must hold a JSON object")
    draft = "raw" in value
    if draft:
        require(value.get("schema") == hierarchy_team_view.DRAFT and isinstance(value.get("raw"), str) and
                isinstance(value.get("sha256"), str), "a draft must be an aegis.team-request/v1 object from team_request")
        require(hashlib.sha256(value["raw"].encode("utf-8")).hexdigest() == value["sha256"],
                "the draft's sha256 does not match its raw text")
        event = value.get("event")
        require(isinstance(event, dict) and isinstance(event.get("event"), dict) and
                event["event"].get("request") == {"raw": value["raw"], "sha256": value["sha256"]},
                "the draft's publish event does not carry its raw text and sha256")
        body = strict_json(value["raw"])
    else:
        body = value
    require(isinstance(body, dict), "a request must be a JSON object")
    body = dict(body)
    if "schema" in body:
        require(body.pop("schema") == hierarchy_lifecycle.REQUEST, "unsupported request schema")
    require(body.get("id") == args.id, "the request file names %s, not %s" % (body.get("id"), args.id))
    canonical = hierarchy_team_view.draft_request(hierarchy_lifecycle.Lifecycle(run.lifecycle), body)
    if draft:
        require(canonical["raw"] == value["raw"], "the draft is not canonical: draft it again with team_request")
        require(canonical["event"] == value["event"], "the draft's publish event no longer matches the journal (its "
                "coordinator or ROOT custody changed): draft it again")
    write_atomic(run.run / "requests" / (args.id + ".json"), canonical["raw"].encode("utf-8"))
    event_path = run.run / "events" / ("publish-%s.json" % args.id)
    write_atomic(event_path, as_json(canonical["event"]))
    code, answer, _ = tool(run, "lifecycle", "--root", run.lifecycle, "record", "--event", event_path, "--evidence-only")
    if code != 0:
        (refuse if code == REFUSED else fail)(answer.get("error", "lifecycle record exited %d" % code))
    save(run, "request-%s.json" % args.id, {"request_id": args.id, "sha256": canonical["sha256"], "receipt": answer})
    return OK, {"request_id": args.id, "sha256": canonical["sha256"], "published": True, "event": str(event_path)}


def agent_items(stdout):
    """What a codex --json turn did, as role_turn.py showed it: its messages and tool calls."""
    items = []
    for event in codex_events(stdout):
        item = event.get("item") if isinstance(event, dict) and event.get("type") == "item.completed" else None
        if event.get("type") == "unknown":
            items.append(event)
        if not isinstance(item, dict):
            continue
        if item.get("type") == "agent_message":
            items.append({"type": "agent_message", "text": str(item.get("text"))[:2000]})
        elif item.get("type") == "mcp_tool_call":
            items.append({"type": "mcp_tool_call", "tool": item.get("tool"), "arguments": item.get("arguments")})
    return items


@contextmanager
def operation_lock(run, busy_message="another team command is running for this run"):
    """Serialize binding, owner turns and teardown without creating a lock file on a refusal.

    Lock the stable run directory inode: team-state.json is replaced atomically, so locking that file would allow
    a second writer to lock its replacement. Browser login holds only its login lock; state transactions stay short.
    """
    import fcntl
    descriptor = os.open(str(run.run), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            refuse(busy_message, record_command=False)
        run.owner_operation_locked = True
        yield
    finally:
        run.owner_operation_locked = False
        os.close(descriptor)


def turn_deadline():
    timeout = float(os.environ.get(TURN_TIMEOUT_VARIABLE, str(TURN_TIMEOUT_SECONDS)))
    require(0 < timeout <= TURN_TIMEOUT_SECONDS,
            TURN_TIMEOUT_VARIABLE + " must be greater than 0 and at most %d seconds" % TURN_TIMEOUT_SECONDS)
    return timeout


def require_resolved(run, endpoint, *, state=None):
    current = require_init(run, state=state)
    slots = current.get("operations", {})
    require(isinstance(slots, dict), "invalid operations record")
    operation = slots.get(endpoint)
    if state is None:
        try:
            if operation is not None and owner_expected(run) and governed_run(run):
                owner_read(run, "runtime.json")
            if operation is None:
                operation = owner_pending(run, endpoint=endpoint).get(endpoint)
        except CustodyProblem as exc:
            refuse(str(exc), operation=operation, **exc.detail())
    if operation is not None:
        require(isinstance(operation, dict) and isinstance(operation.get("id"), str), "invalid operation record")
        refuse("%s has unresolved operation %s; inspect status, then use approve/turn --reconcile; never replay an "
               "unknown turn" % (endpoint, operation["id"]), operation=operation)


def process_identity(pid):
    try:
        return Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


OPERATION_SCOPE_REASONS = frozenset(component + " is " + problem
    for component in ("observer_pid", "boot_id", "pid_namespace", "proc_identity")
    for problem in ("unreadable", "invalid"))


def operation_process_scope():
    """Capture once before Popen, including unavailable evidence. Scope is not a native-wait prerequisite."""
    values = {}
    for name, read in (
            ("observer_pid", lambda: Path("/proc/self/stat").read_text(encoding="ascii").split(" ", 1)[0]),
            ("boot_id", lambda: Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()),
            ("pid_namespace", lambda: os.readlink("/proc/self/ns/pid")),
            ("proc_identity", lambda: Path("/proc").stat())):
        try:
            values[name] = read()
        except (OSError, ValueError, UnicodeError):
            return {"state": "UNAVAILABLE", "reason": name + " is unreadable"}
    if values["observer_pid"] != str(os.getpid()):
        return {"state": "UNAVAILABLE", "reason": "observer_pid is invalid"}
    boot, namespace, info = values["boot_id"], values["pid_namespace"], values["proc_identity"]
    try:
        valid_boot = str(uuid.UUID(boot)) == boot
    except (ValueError, TypeError, AttributeError):
        valid_boot = False
    if not valid_boot:
        return {"state": "UNAVAILABLE", "reason": "boot_id is invalid"}
    if not isinstance(namespace, str) or re.fullmatch(r"pid:\[\d+\]", namespace) is None:
        return {"state": "UNAVAILABLE", "reason": "pid_namespace is invalid"}
    if not stat.S_ISDIR(info.st_mode):
        return {"state": "UNAVAILABLE", "reason": "proc_identity is invalid"}
    return {"boot_id": boot, "pid_namespace": namespace, "proc_device": info.st_dev, "proc_inode": info.st_ino,
            "effective_uid": os.geteuid()}


def operation_process_observation(run, operation):
    """Only positive evidence in the original observer scope can establish that the original instance exited.

    Linux stat field 22 is birth time since boot. Require complete current-Linux records (through field 52),
    and two consistent observations. Missing/unreadable/torn identity is unavailable, never absence.
    """
    unavailable = {"state": "UNAVAILABLE"}
    try:
        witness = original_launch(run, operation)
    except CustodyProblem:
        raise
    except (OSError, ValueError):
        return {**unavailable, "reason": "launch identity differs from its durable witness"}
    operation = witness
    original_scope = operation.get("process_scope")
    if isinstance(original_scope, dict) and original_scope.get("state") == "UNAVAILABLE":
        reason = original_scope.get("reason")
        return {**unavailable, "reason": "original process scope unavailable: " + reason
                if set(original_scope) == {"state", "reason"} and isinstance(reason, str) and
                   reason in OPERATION_SCOPE_REASONS else "original process scope capture is invalid"}
    if operation.get("intent_recovery") is True:
        return bound_session_observation(run, operation)
    pid, start = operation.get("pid"), operation.get("pid_start")
    if type(pid) is not int or pid <= 0 or not isinstance(start, str) or not start.isdigit() or int(start) <= 0:
        return {**unavailable, "reason": "original process identity is missing or invalid"}
    try:
        scope = operation_process_scope()
        if scope.get("state") == "UNAVAILABLE":
            return {**unavailable, "reason": "current process scope unavailable: " + scope["reason"]}
        if operation.get("process_scope") != scope:
            return {**unavailable, "reason": "original process scope is missing or changed"}
        observed = []
        for _ in range(2):
            try:
                raw = Path("/proc/%d/stat" % pid).read_text(encoding="ascii")
            except FileNotFoundError:
                try:
                    Path("/proc/%d" % pid).stat()
                except FileNotFoundError:
                    try:
                        os.kill(pid, 0)  # Signal zero is only a kernel existence/permission probe; nothing is sent.
                    except ProcessLookupError:
                        observed.append(("absent", None))
                        continue
                    return {**unavailable, "reason": "the kernel still sees the PID despite missing proc metadata"}
                return {**unavailable, "reason": "stat is missing while the PID directory is present"}
            prefix, separator, tail = raw.rpartition(")")
            fields = tail.split()
            require(separator and prefix.startswith(str(pid) + " (") and raw.endswith("\n") and len(fields) >= 50 and
                    fields[0] in ("R", "S", "D", "Z", "T", "t", "W", "X", "x", "K", "P", "I") and
                    all(re.fullmatch(r"-?\d+", field) is not None for field in fields[1:]) and
                    fields[19].isdigit() and int(fields[19]) > 0, "malformed operation process stat")
            birth = fields[19]
            if birth == start:
                observed.append(("zombie" if fields[0] == "Z" else "present", birth))
            elif int(birth) > int(start):
                # Birth evidence alone cannot dismiss a process still naming this bound session. Consult the
                # real argv, home and cwd independently of both mutable publication records.
                live = bound_process_session(run, operation)
                observed.append(("present" if live else "later_instance", birth))
            else:
                return {**unavailable, "reason": "process birth precedes the recorded original instance"}
        if operation_process_scope() != scope or observed[0] != observed[1]:
            return {**unavailable, "reason": "process identity or scope changed during observation"}
    except (OSError, ValueError, UnicodeError, IndexError):
        return {**unavailable, "reason": "process metadata is unreadable or malformed"}
    return {"state": "PRESENT" if observed[0][0] == "present" else "CONFIRMED_ABSENT", "reason": observed[0][0]}


def bound_process_session(run, operation):
    folder = Path("/proc/%d" % operation["pid"])
    argv = folder.joinpath("cmdline").read_bytes().split(b"\0")
    adapter = OWNER_ADAPTERS[operation["host"]]
    session = operation["session"].encode("utf-8")
    if not any(argv[i:i + 2] == [adapter["resume_word"], session] for i in range(len(argv) - 1)):
        return False
    home = host_home(run, operation["host"])
    variable = hierarchy_hosts.entry(operation["host"])["home"]["variable"]
    settings = folder.joinpath("environ").read_bytes().split(b"\0")
    require((variable + "=" + home).encode("utf-8") in settings and
            os.path.realpath(os.readlink(str(folder / "cwd"))) == os.path.realpath(operation["cwd"]),
            "bound process session metadata is unavailable or conflicting")
    return True



def publication_aliases(folder, name, info):
    # The sole allowed extra link is our atomic publisher's private, UUID-named staging entry.
    # A backup/foreign hardlink, including any link outside this owner-only directory, is not an exemption.
    aliases = []
    for path in folder.glob(".owner-" + name + "-*.tmp"):
        if re.fullmatch(r"\.owner-" + re.escape(name) + r"-[0-9a-f]{32}\.tmp", path.name) is None:
            continue
        try:
            other = path.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISREG(other.st_mode) and other.st_uid == os.getuid() and stat.S_IMODE(other.st_mode) == 0o600 and
                (other.st_dev, other.st_ino) == (info.st_dev, info.st_ino)):
            aliases.append(path)
    return aliases



def model_write_roots(run):
    roots = [run.project, *[lane.worktree for lane in run.implementers]]
    for adapter in OWNER_ADAPTERS.values():
        roots.append(getattr(run, adapter["home_attribute"]))
    for lane in run.implementers:
        if lane.tmpdir is not None:
            roots.append(lane.tmpdir)
    for path, value in model_profiles(run):
        roots.extend(profile_roots(value, path.name))
    return tuple(dict.fromkeys(Path(path).absolute() for path in roots))


def model_profiles(run):
    folder = run.base / "profiles"
    paths = sorted(folder.glob("*.json")) if folder.is_dir() else []
    if len(paths) > 256:
        raise budget_problem("profiles", "event budget")
    for path in paths:
        value = read_json(path)
        if not isinstance(value, dict) or not isinstance(value.get("host"), str) or value["host"] not in OWNER_ADAPTERS:
            raise CustodyProblem("invalid role write scope", "role write scope", path.name)
        endpoint = value.get("endpoint")
        if isinstance(endpoint, str) and endpoint == run.endpoint("front-door"):
            plan = hierarchy_hosts.read_plan(run.base)
            # The sole exemption is the verified non-model front-door stand-in, never an arbitrary role/profile.
            if (plan is not None and hierarchy_hosts.plan_host(plan, endpoint)[1] and
                    re.fullmatch(re.escape(endpoint.replace("/", "%2F")) + r"-g[1-9][0-9]*\.(?:wake|codex)\.json", path.name)):
                continue
        yield path, value


def profile_roots(value, record):
    roots = []
    for key in ("cwd", "tmpdir", "writable_roots", "add_dirs"):
        entries = value.get(key, []) if key in ("writable_roots", "add_dirs") else (
            [value[key]] if value.get(key) is not None else [])
        if not isinstance(entries, list) or len(entries) > 128 or any(
                not record_string(item) or not Path(item).is_absolute() or ".." in Path(item).parts for item in entries):
            raise CustodyProblem("invalid role write roots", "role write scope", record)
        roots.extend(Path(item) for item in entries)
    return roots


def paths_overlap(first, second):
    return first == second or first in second.parents or second in first.parents


def resolve_scope(path):
    try:
        return Path(path).resolve()
    except (OSError, RuntimeError) as exc:
        raise CustodyProblem("model write or executable scope cannot be resolved; restore the approved paths",
                             "model executable scope", Path(path).name) from exc


def control_paths(run, host):
    paths = [run.evidence, run.lifecycle, run.base, run.store, run.inputs, run.loop_state,
             run.run / ".owner-custody", run.run / "requests", run.run / "events", run.run / "starts",
             run.state_path, run.commands_log, run.config_path, run.recipes, run.source, Path(run.python), resolve_scope(run.python)]
    paths.extend(getattr(run, adapter["home_attribute"]) for kind, adapter in OWNER_ADAPTERS.items() if kind != host)
    return paths


def validate_role_write_roots(run):
    requests = [(lane.endpoint, run.hosts["team"], [lane.worktree, *([lane.tmpdir] if lane.tmpdir else [])])
                for lane in run.implementers]
    for path, value in model_profiles(run):
        requests.append((value.get("endpoint", path.name), value["host"], profile_roots(value, path.name)))
    for endpoint, host, roots in requests:
        for root in roots:
            for candidate in (Path(root).absolute(), resolve_scope(root)):
                for control in control_paths(run, host):
                    for protected in (Path(control).absolute(), resolve_scope(control)):
                        if paths_overlap(candidate, protected):
                            raise CustodyProblem("role write root overlaps run control data; restore the approved worktree",
                                                 "role write scope", endpoint)


def validate_child_environment(run, env, cwd):
    if not legacy_environment(run):
        validate_owner_path(run, cwd, env)
    return env



def validate_owner_path(run, cwd, env=None):
    settings = os.environ if env is None else env
    roots = model_write_roots(run)
    directories = []
    for word in settings.get("PATH", os.defpath).split(os.pathsep):
        if not word or not Path(word).is_absolute() or ".." in Path(word).parts:
            raise CustodyProblem("PATH must contain only absolute nonempty trusted directories",
                                 "model executable scope", "PATH")
        written, resolved = Path(word).absolute(), resolve_scope(word)
        for directory in (written, resolved):
            if any(paths_overlap(directory, root) or paths_overlap(directory, resolve_scope(root)) for root in roots):
                raise CustodyProblem("PATH includes a model-writable directory or ancestor; use absolute trusted program directories",
                                     "model executable scope", "PATH")
        directories.append(str(resolved))
    path = os.pathsep.join(directories)
    if env is not None:
        env["PATH"] = path
    return path



def validated_command(run, argv, env, cwd=None):
    if not governed_run(run):
        return list(argv)
    validate_owner_path(run, cwd or Path.cwd(), env)
    selected = str(Path(argv[0]).absolute()) if Path(argv[0]).is_absolute() else shutil.which(argv[0], path=env["PATH"])
    if selected is None:
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), argv[0])
    written, executable = Path(selected).absolute(), resolve_scope(selected)
    for root in model_write_roots(run):
        for candidate in (root, resolve_scope(root)):
            if any(path == candidate or candidate in path.parents for path in (written, executable)):
                raise CustodyProblem("executable is model-writable; restore a trusted program outside role roots",
                                     "model executable scope", Path(argv[0]).name)
    info = executable.stat()
    immutable = bool(os.statvfs(executable).f_flag & os.ST_RDONLY)
    if not (stat.S_ISREG(info.st_mode) and (immutable or info.st_uid in (0, os.getuid())) and
            info.st_nlink == 1 and
            not info.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o022)):
        raise CustodyProblem("executable has unsafe ownership, links or permissions; restore a trusted executable",
                             "model executable scope", Path(argv[0]).name)
    # Keep an absolute venv interpreter spelling: resolving it for exec would lose its venv configuration.
    # Both the spelling and target are outside every model write root; no bare-name lookup remains at Popen.
    return [str(written), *argv[1:]]



def validate_model_executable(run, host, argv, cwd, env=None):
    program = OWNER_ADAPTERS[host]["program"]
    require(argv and (argv[0] == program or Path(argv[0]).is_absolute()),
            "owner turn executable differs from the host registry")
    settings = child_env(run) if env is None else env
    selected = shutil.which(program, path=validate_owner_path(run, cwd, settings))
    require(selected is not None, "host executable is unavailable; restore the trusted program on PATH")
    if Path(argv[0]).is_absolute():
        require(resolve_scope(argv[0]) == resolve_scope(selected), "owner turn executable differs from the validated host program")
    return Path(validated_command(run, [selected], settings, cwd)[0])


def bound_session_census(run, operation):
    # This veto is independent of the PID stored in any record. It observes only the original PID namespace.
    # Scope/census failures are unavailable evidence, never proof that a session ended.
    unavailable = {"state": "UNAVAILABLE", "reason": "bound session metadata is unavailable"}
    try:
        mounted = Path("/proc").stat()
        identity = (mounted.st_dev, mounted.st_ino, os.geteuid())
    except OSError:
        return unavailable
    wanted = operation["session"].encode("utf-8")
    flag = OWNER_ADAPTERS[operation["host"]]["resume_word"]
    variable = hierarchy_hosts.entry(operation["host"])["home"]["variable"].encode("utf-8") + b"="
    try:
        for folder in Path("/proc").iterdir():
            if not folder.name.isdigit():
                continue
            try:
                uid = folder.stat().st_uid
                if uid != os.geteuid():
                    if uid != 0:
                        continue
                    # Linux changes proc directory ownership for non-dumpable processes. Kernel Uid identifies
                    # their effective owner without reading another user's command/environment.
                    rows = [line.split()[1:] for line in (folder / "status").read_bytes().splitlines()
                            if line.startswith(b"Uid:")]
                    require(len(rows) == 1 and len(rows[0]) == 4 and all(item.isdigit() for item in rows[0]),
                            "invalid kernel process credentials")
                    if int(rows[0][1]) != os.geteuid():
                        continue
                words = (folder / "cmdline").read_bytes().split(b"\0")
                if not any(words[i:i + 2] == [flag, wanted] for i in range(len(words) - 1)):
                    continue
                settings = (folder / "environ").read_bytes().split(b"\0")
                homes = [word[len(variable):] for word in settings if word.startswith(variable)]
                require(len(homes) == 1, "bound session home unavailable")
                if os.path.realpath(os.fsdecode(homes[0])) != os.path.realpath(host_home(run, operation["host"])):
                    continue  # The same legacy textual session id in a positively observed different run home.
                require(os.path.realpath(os.readlink(str(folder / "cwd"))) == os.path.realpath(operation["cwd"]),
                        "bound session cwd changed")
                return {"state": "PRESENT", "reason": "bound session is running"}
            except FileNotFoundError:
                continue
        mounted = Path("/proc").stat()
        if (mounted.st_dev, mounted.st_ino, os.geteuid()) != identity:
            return unavailable
    except (OSError, ValueError, UnicodeError):
        return unavailable
    return {"state": "CONFIRMED_ABSENT", "reason": "no live bound session in the original observer scope"}


def bound_session_observation(run, operation):
    unavailable = {"state": "UNAVAILABLE", "reason": "bound session metadata is unavailable"}
    scope = operation_process_scope()
    if scope.get("state") == "UNAVAILABLE" or scope != operation["process_scope"]:
        return unavailable
    result = bound_session_census(run, operation)
    return result if operation_process_scope() == scope else unavailable


def native_wait_veto(run, operation):
    observation = bound_session_census(run, operation)
    if observation["state"] != "CONFIRMED_ABSENT":
        fail("operation %s finished its launcher but a bound host may still be running; accounting, state and marker retained" %
             operation["id"], operation=operation, spawned=True, process_observation=observation,
             next_action="let the bound session finish, then reconcile; do not replay")


def native_exit_record(run, operation, code=None):
    name = "turn-%s.exit.json" % operation["id"]
    value = {"schema": "aegis.team-native-exit/v1", "operation_id": operation["id"],
             "launch_sha256": digest_bytes(as_json(launch_identity(operation))), "native_exit": code}
    path = owner_folder(run) / name
    if code is not None and not path.exists():
        owner_publish(run, name, value)
    if not path.exists():
        return None
    observed = owner_read(run, name)
    require(observed["operation_id"] == operation["id"] and
            observed["launch_sha256"] == value["launch_sha256"] and
            (code is None or observed["native_exit"] == code), "native exit witness conflicts; retain the hold")
    return observed["native_exit"]


def load_native_exit(value):
    record_fields(value, {"schema", "operation_id", "launch_sha256", "native_exit"}, kind="native exit")
    require(value["schema"] == "aegis.team-native-exit/v1" and record_digest(value["launch_sha256"]) and
            isinstance(value["operation_id"], str) and re.fullmatch(r"[0-9a-f]{32}", value["operation_id"]) and
            bounded_integer(value["native_exit"], -255, 255), "invalid native exit record")
    return value


def reconciliation_observation(run, operation):
    original = operation_process_observation(run, operation)
    return bound_session_observation(run, operation) if original["state"] == "CONFIRMED_ABSENT" else original


def require_exited(run, operation):
    observation = reconciliation_observation(run, operation)
    if observation["state"] == "PRESENT":
        refuse("operation %s is unresolved: its process is still running" % operation["id"], operation=operation,
               process_observation=observation, next_action="let the bound session finish, then reconcile; do not replay")
    if observation["state"] != "CONFIRMED_ABSENT":
        refuse("operation %s is unresolved: its process exit cannot be confirmed; retain the hold" % operation["id"],
               operation=operation, process_observation=observation)



def owner_folder(run, create=False):
    from hierarchy_mailbox import safe_path
    folder = safe_path(run.run / ".owner-custody")
    if not folder.exists():
        if create:
            state = load_state(run)
            if state and state.get("owner_custody"):
                raise CustodyProblem("this run predates or lost owner custody records; preserve it and init a new run folder",
                                     "directory missing", ".owner-custody")
            folder.mkdir(mode=0o700)
        else:
            raise CustodyProblem("this run predates or lost owner custody records; preserve it and init a new run folder",
                                 "directory missing", ".owner-custody")
    info = folder.stat()
    if not (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700):
        raise CustodyProblem("unsafe owner-held control directory", "directory permissions", ".owner-custody")
    return folder


def owner_read(run, name):
    require(re.fullmatch(r"runtime\.json|plan-issued\.json|turn-[0-9a-f]{32}\.(?:launch|release|exit)\.json|active-[A-Za-z0-9_.%\-]+\.json", name) is not None,
            "invalid owner-held record name")
    path = owner_folder(run) / name
    try:
        descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise CustodyProblem("unsafe owner-held record: " + name, "record permissions", name)
            if info.st_nlink != 1:
                aliases = publication_aliases(path.parent, name, info)
                current = os.fstat(stream.fileno())
                if current.st_nlink != 1 and not (current.st_nlink == 2 and len(aliases) == 1):
                    raise CustodyProblem("unsafe owner-held record: " + name, "record hardlink", name)
            raw = bounded_read(stream, path, RECORD_BYTES)
        return load_owner_value(name, record_json(raw, name))
    except CustodyProblem:
        raise
    except FileNotFoundError as exc:
        raise CustodyProblem("this run predates or lost owner custody records; preserve it and init a new run folder",
                             "record missing", name) from exc
    except OSError as exc:
        if path.is_symlink():
            raise CustodyProblem("owner-held record is a symlink: " + name, "record symlink", name) from exc
        raise CustodyProblem("owner-held record is unavailable: " + name, "record unreadable", name) from exc
    except ValueError as exc:
        raise CustodyProblem(str(exc), "record shape", name) from exc


def owner_publish(run, name, value):
    load_owner_value(name, value)
    folder = owner_folder(run, create=True)
    path = folder / name
    temporary = folder / (".owner-" + name + "-" + uuid.uuid4().hex + ".tmp")
    raw = as_json(value)
    require(len(raw) <= 262144, "owner record exceeds its bounded size; preserve this run and init a new run folder")
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # Publication is complete and never replaces an existing authority record.
        os.link(temporary, path, follow_symlinks=False)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    descriptor = os.open(str(folder), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def owner_runtime(run, initialize=False, provisioned=None):
    error = "team runtime differs from the owner-held record"
    expected = {"schema": "aegis.team-owner-runtime/v1", "run": str(run.run), "initiative": run.id,
                "python": run.python, "source": str(run.source), "python_realpath": os.path.realpath(run.python),
                "custody": custody(run)}
    if initialize:
        folder = owner_folder(run, create=True)
        if not (folder / "runtime.json").exists():
            require(provisioned is not None and os.access(run.python, os.X_OK), error)
            owner_publish(run, "runtime.json", {**expected, "python_sha256": sha_file(run.python),
                "source_commit": provisioned["source_commit"], "source_tree": provisioned["source_tree"]})
    recorded = owner_read(run, "runtime.json")
    try:
        interpreter_changed = (recorded["python"] != run.python or
                               recorded["python_realpath"] != os.path.realpath(run.python) or
                               not os.access(run.python, os.X_OK) or recorded["python_sha256"] != sha_file(run.python))
    except OSError:
        interpreter_changed = True
    if interpreter_changed:
        raise CustodyProblem(error, "interpreter drift", "runtime.json", INTERPRETER_RECOVERY)
    require(all(recorded.get(key) == value for key, value in expected.items() if key not in ("python", "python_realpath")), error)
    if provisioned is not None:
        require(all(recorded[key] == provisioned.get(key) for key in ("source_commit", "source_tree")),
                "source changed during provisioning; restore the provisioned revision or init a new run folder")
    return recorded


def active_name(endpoint):
    endpoint_parts(endpoint)
    return "active-%s.json" % endpoint.replace("/", "%2F")


def intent_identity(operation):
    value = launch_identity(operation)
    value.pop("intent_recovery", None)
    value["pid"] = None
    value.pop("pid_start", None)
    return value


def owner_pending(run, *, endpoint=None, problems=None, state=UNINSPECTED):
    pending = {}
    folder = run.run / ".owner-custody"
    if not folder.exists() and not folder.is_symlink() and not owner_expected(run, state=state):
        return pending
    try:
        folder = owner_folder(run)
    except (ValueError, OSError) as exc:
        if problems is None:
            raise
        problems["_owner"] = {"error": str(exc), "next_action": CUSTODY_RECOVERY}
        return pending
    for path in folder.glob("active-*.json"):
        slot = path.name[len("active-"):-len(".json")].replace("%2F", "/")
        if endpoint is not None and slot != endpoint:
            continue
        try:
            value = owner_read(run, path.name)
            require(path.name == active_name(value["endpoint"]), "invalid active record")
            pending[value["endpoint"]] = value
        except (ValueError, OSError) as exc:
            # Listing is a snapshot. A retirement that removed this entry is not damaged custody.
            if not path.exists() and not path.is_symlink():
                continue
            if problems is None:
                raise
            problems[slot] = {"record": path.name, "error": str(exc), "next_action": CUSTODY_RECOVERY, **(exc.problem if isinstance(exc, CustodyProblem) else {})}
    return pending



def original_launch(run, operation):
    load_operation(operation)
    name = "turn-%s.launch.json" % operation["id"]
    folder = owner_folder(run)
    public = run.evidence / name
    active = owner_pending(run, endpoint=operation["endpoint"]).get(operation["endpoint"])
    if not (folder / name).exists() and not (folder / name).is_symlink():
        if public.exists() or public.is_symlink():
            raise CustodyProblem("this run predates or lost owner custody records; preserve it and init a new run folder",
                                 "record missing", name)
        require(active is not None and active == intent_identity(operation),
                "original private intent is missing or changed; retain the hold")
        require(not public.exists() and not public.is_symlink(), "untrusted launch publication without an owner witness")
        # No fabricated PID/exit. This survives only through original-scope session absence AND fresh turn proof.
        return {**active, "intent_recovery": True}
    recorded = owner_read(run, name)
    if active is not None:
        require(active == intent_identity(recorded), "active owner-held intent differs from launch publication")
    else:
        require(operation.get("release") and (folder / ("turn-%s.release.json" % operation["id"])).exists(),
                "active owner-held intent is missing")
    pending = operation.get("pid") is None and "pid_start" not in operation
    if public.exists():
        require(read_json(public) == recorded, "launch identity differs from its durable witness")
    else:
        require(pending, "durable launch publication is missing")
    expected = dict(recorded)
    if pending:
        expected["pid"] = None
        expected.pop("pid_start", None)
        if operation.get("intent_recovery") is not True:
            expected.pop("intent_recovery", None)
    require(launch_identity(operation) == expected, "launch identity differs from its durable witness")
    return recorded


def digest_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def durable_write(path, raw):
    """Accounting is a release prerequisite: sync the contents and rename before reporting it durable."""
    path = Path(path)
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    with open(temporary, "xb") as stream:
        os.chmod(temporary, 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def accounting_lines(raw):
    error = "operation accounting is incomplete or conflicting; retain the hold"
    require(not raw or raw.endswith(b"\n"), error)
    try:
        if len(raw) > TURN_LOG_BYTES:
            raise budget_problem("turn log")
        if raw.count(b"\n") > OUTPUT_EVENTS:
            raise budget_problem("turn log", "event budget")
        rows = []
        for line in raw.split(b"\n"):
            if not line:
                continue
            if len(line) > TRANSCRIPT_LINE_BYTES:
                raise budget_problem("turn log")
            rows.append(record_json(line, "turn log"))
    except CustodyProblem:
        raise
    except (ValueError, UnicodeError):
        refuse(error)
    require(all(isinstance(row, dict) for row in rows), error)
    return rows


def operation_paths(run, operation):
    """Validate persisted paths before any read or write, including recovery after a lost caller."""
    error = "operation evidence paths differ from the run's canonical paths; retain the hold"
    identifier, endpoint = operation.get("id"), operation.get("endpoint")
    require(isinstance(identifier, str) and re.fullmatch(r"[0-9a-f]{32}", identifier) is not None, error)
    hierarchy, role = endpoint_parts(endpoint)[:2]
    require(hierarchy == run.id, error)
    log = "root-turns.jsonl" if role == "root" else "role-turns-%s.jsonl" % endpoint.replace("/", "%2F")
    require(operation.get("turn_log") == log and
            operation.get("stdout") == str(run.evidence / ("turn-%s.stdout.jsonl" % identifier)) and
            operation.get("stderr") == str(run.evidence / ("turn-%s.stderr.txt" % identifier)) and
            operation.get("marker") == (None if role == "root" else str(Mailbox(run.mailbox_root).wake_marker(endpoint))), error)
    from hierarchy_mailbox import safe_path
    for path in (run.evidence / log, Path(operation["stdout"]), Path(operation["stderr"]),
                 run.evidence / ("turn-%s.accounting.json" % identifier),
                 run.evidence / ("turn-%s.launch.json" % identifier)):
        safe_path(path)


def launch_identity(operation):
    # Release bookkeeping is the only mutable part of an invocation. Retain the complete original intent and
    # observed launch identity independently of team-state, so editing one birth field cannot prove PID reuse.
    return {key: value for key, value in operation.items() if key != "release"}


def codex_usage(raw):
    return next((event.get("usage") for event in reversed(list(codex_events(raw)))
                 if event.get("type") == "turn.completed"), None)


def raw_log_records(raw):
    require(not raw or raw.endswith(b"\n"), "operation accounting is incomplete or conflicting; retain the hold")
    return []


def account_usage_rows(log, operation, before, rows, receipt, identity, usage, code, desired, receipt_path, stdout):
    error = "operation accounting is incomplete or conflicting; retain the hold"
    row = {key: identity[key] for key in ("operation_id", "endpoint", "host", "session", "started_at", "stdout")}
    row.update(exit_code=code, usage=usage)
    keys = set(row)
    require(all(set(item) == keys and isinstance(item["operation_id"], str) for item in rows), error)
    matches = [i for i, item in enumerate(rows) if item["operation_id"] == operation["id"]]
    require(len(matches) <= 1, error)
    if matches:
        old = rows[matches[0]]
        require(all(old[key] == value for key, value in row.items() if key not in ("exit_code", "usage")) and
                (old["usage"] is None or old["usage"] == usage) and
                (old["exit_code"] is None or (type(old["exit_code"]) is int and
                 (code is None or old["exit_code"] == code))), error)
        # A row may have been durably published before its receipt reply was lost. Keep a known native
        # status immutable; neither an unknown caller exit nor a transcript verdict can replace it.
        if code is None:
            code = old["exit_code"]
            row["exit_code"] = desired["exit_code"] = code
        rows[matches[0]] = row
    else:
        require(receipt is None, error)
        rows.append(row)
    raw = b"".join(as_json_line(item) for item in rows)
    if len(raw) > TURN_LOG_BYTES:
        raise budget_problem(log)
    if raw != before:
        durable_write(log, raw)
    return code


def account_native_events(log, operation, before, rows, receipt, identity, usage, code, desired, receipt_path, stdout):
    error = "operation accounting is incomplete or conflicting; retain the hold"
    # Keep the historical Codex event bytes, extending the same invocation as its output grows. A receipt
    # can precede its log write: only an exact, complete-line prefix of this stdout can finish that append.
    raw = stdout[:stdout.rfind(b"\n") + 1]
    span = receipt.get("log_span") if receipt else None
    if span is None:
        span = {"offset": len(before), "prefix_sha256": digest_bytes(before),
                "length": 0, "sha256": digest_bytes(b"")}
    else:
        require(isinstance(span, dict) and set(span) == {"offset", "prefix_sha256", "length", "sha256"} and
                type(span["offset"]) is int and span["offset"] >= 0 and type(span["length"]) is int and
                0 <= span["length"] <= len(raw) and digest_bytes(raw[:span["length"]]) == span["sha256"], error)
    offset = span["offset"]
    require(len(before) >= offset and digest_bytes(before[:offset]) == span["prefix_sha256"], error)
    require(raw.startswith(before[offset:]), error)
    if offset + len(raw) > TURN_LOG_BYTES:
        raise budget_problem(log)
    span = {**span, "length": len(raw), "sha256": digest_bytes(raw)}
    desired["log_span"] = span
    if receipt != desired:
        durable_write(receipt_path, as_json(desired))
    if not log.exists() or before[offset:] != raw:
        durable_write(log, before[:offset] + raw)
    return code


def codex_root_argv(run, binding, bound, prompt):
    argv = ["codex"]
    for feature in hierarchy_provision.CODEX_DISABLED + hierarchy_provision.CODEX_SHELL:
        argv += ["--disable", feature]
    argv += ["exec", "--ignore-user-config", "--sandbox", "read-only", "-c", 'approval_policy="never"',
             "-c", bound["mcp_config"], "--json", "-C", str(run.project), "resume", binding["session"], prompt]
    return argv, None


def claude_root_argv(run, binding, bound, prompt):
    return hierarchy_provision.claude_argv(["--resume", binding["session"]], bound["connection"], [],
                 ["mcp__aegis_decision__" + name for name in ROOT_TOOLS], {}, None), prompt


def codex_root_validate(run, binding, bound):
    if governed_run(run):
        require(tuple(bound["tools"]) == ROOT_TOOLS, "ROOT tools mismatch")
        require(bound["mcp_config"] == codex_root_config(run, binding, bound["connection"]),
                "Codex ROOT connection differs from the registry argv")


def claude_root_validate(run, binding, bound):
    claude_pin(run)
    claude_transcript(run, binding["session"])
    require(tuple(bound["tools"]) == ROOT_TOOLS, "ROOT tools mismatch")
    governed_connection(run, binding, bound["connection"])
    require(tuple(adapter_tools(run, bound["connection"])) == ROOT_TOOLS, "ROOT tools mismatch")


def codex_turn_profile(run, binding, path, profile):
    if governed_run(run):
        from hierarchy_wake import load_profile
        profile = load_profile(path, binding["endpoint"], binding)
        codex_resume_profile(run, binding, profile)
    return profile


def claude_turn_profile(run, binding, path, profile):
    from hierarchy_wake import load_profile
    profile = load_profile(path, binding["endpoint"], binding)
    claude_pin(run)
    claude_transcript(run, binding["session"])
    require(profile.get("mode", "print") == "print" and profile["prompt_via"] == "stdin",
            "a Claude owner turn requires a print profile")
    claude_resume_profile(run, binding, profile)
    return profile


def claude_turn_failure(code, raw, root=False):
    if code == 0 and not owner_result_failed(CLAUDE, raw):
        return None
    return (("Claude ROOT turn failed; journal decisions, transcript and output were retained", {"claude_exit": code})
            if root else ("Claude owner turn failed; transcript and output were retained", {}))


def codex_bind_root(run, request, session):
    with tempfile.TemporaryDirectory() as folder:
        staged = Path(folder) / "root.json"
        staged.write_bytes(as_json(request))
        code, answer, _ = tool(run, "provision", "add-role", "--request", staged)
    if code != 0:
        (refuse if code == REFUSED else fail)(answer.get("error", "provision add-role exited %d" % code))
    request_file(run, "root.json", request)
    return answer


def claude_bind_root(run, request, session):
    claude_pin(run)
    claude_transcript(run, session)
    offered = (hierarchy_provision.DECISION_TOOL, *hierarchy_roles.decision_tools(hierarchy_roles.role(request["endpoint"])))
    require(offered == ROOT_TOOLS, "ROOT tools mismatch: expected " + ", ".join(ROOT_TOOLS))
    hierarchy_provision.check_role_request(request, governed_runtime(run))
    try:
        answer = hierarchy_provision.add_role(request)
    except (ValueError, OSError) as exc:
        fail("ROOT provisioning failed: %s; inspect the retained binding, connection and session records" % exc)
    answer["mcp_config"] = answer["connection"]
    return answer


def record_turn(run, operation, stdout, code):
    """One durable invocation receipt per id, with an idempotent provider log. A null pending usage may become
    known, but a recorded charge cannot be reset or changed. Raw output remains in the invocation's own file.
    """
    validate_output(stdout)
    error = "operation accounting is incomplete or conflicting; retain the hold"
    operation_paths(run, operation)
    log = run.evidence / operation["turn_log"]
    receipt_path = run.evidence / ("turn-%s.accounting.json" % operation["id"])
    require(not log.is_symlink() and not receipt_path.is_symlink(), error)
    before = bounded_bytes(log, TURN_LOG_BYTES) if log.exists() else b""
    adapter = OWNER_ADAPTERS[operation["host"]]
    rows = adapter["log_records"](before)
    receipt = read_json(receipt_path) if receipt_path.exists() else None
    require(code is None or type(code) is int, error)
    identity = {"operation_id": operation["id"], "endpoint": operation["endpoint"], "host": operation["host"],
                "session": operation["session"], "generation": operation["generation"],
                "started_at": operation["started_at"], "stdout": operation["stdout"]}
    usage = adapter["usage"](stdout)
    if receipt is not None:
        require(isinstance(receipt, dict) and set(receipt) == {
                    "operation_id", "identity", "usage", "output_sha256", "output_bytes", "exit_code"} |
                    adapter["receipt_fields"] and
                receipt.get("operation_id") == operation["id"] and receipt.get("identity") == identity and
                type(receipt.get("output_bytes")) is int and 0 <= receipt["output_bytes"] <= len(stdout) and
                digest_bytes(stdout[:receipt["output_bytes"]]) == receipt["output_sha256"] and
                (receipt.get("exit_code") is None or (type(receipt["exit_code"]) is int and
                 (code is None or receipt["exit_code"] == code))) and
                (receipt.get("usage") is None or receipt["usage"] == usage), error)
        if code is None:
            code = receipt["exit_code"]
    desired = {"operation_id": operation["id"], "identity": identity, "usage": usage,
               "output_sha256": digest_bytes(stdout), "output_bytes": len(stdout), "exit_code": code}
    code = adapter["account"](log, operation, before, rows, receipt, identity, usage, code, desired, receipt_path, stdout)
    if not adapter["owns_receipt"] and receipt != desired:
        durable_write(receipt_path, as_json(desired))
    return code


def record_unresolved_turn(run, operation, native_exit=None):
    try:
        operation_paths(run, operation)
        record_turn(run, operation, native_output(operation), native_exit)
    except CustodyProblem as exc:
        fail("operation %s is unresolved and accounting failed: %s; team-state, marker and output retained" %
             (operation["id"], exc), operation=operation, spawned=True, **exc.detail())
    except (Stop, ValueError, OSError) as exc:
        fail("operation %s is unresolved and accounting failed: %s; team-state, marker and output retained" %
             (operation["id"], exc), operation=operation)



def marker_witness(path):
    raw = bounded_bytes(path, MARKER_BYTES)
    info = os.lstat(path)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
            stat.S_IMODE(info.st_mode) == 0o600, "unsafe owner wake marker")
    value = record_json(raw, Path(path).name)
    require(isinstance(value, dict), "unsafe owner wake marker")
    return {"device": info.st_dev, "inode": info.st_ino, "ctime_ns": info.st_ctime_ns,
            "sha256": digest_bytes(raw), "operation_id": value.get("operation_id")}


def require_owned_marker(operation):
    path = Path(operation["marker"])
    error = "operation %s wake marker changed; retain the hold and do not clear another wake" % operation["id"]
    if not path.exists() and operation.get("release"):
        return False  # A durable release intent follows terminal proof and durable accounting, never a model retry.
    try:
        observed = marker_witness(path)
    except CustodyProblem as exc:
        refuse(error, **exc.detail())
    except (OSError, ValueError, KeyError, Stop):
        refuse(error)
    require(observed == operation.get("marker_witness") and observed["operation_id"] == operation["id"], error)
    return True


def transcript_witness(path):
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if info.st_size > TRANSCRIPT_BYTES:
            raise budget_problem(path)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and bounded_integer(info.st_size),
                "unsafe operation transcript")
        digest = bounded_prefix(stream, info.st_size)
        require(digest is not None, "operation transcript was truncated; retain the hold")
        if info.st_size:
            stream.seek(info.st_size - 1)
            require(stream.read(1) == b"\n", "operation transcript has an incomplete boundary; retain the hold")
    return {"device": info.st_dev, "inode": info.st_ino, "offset": info.st_size, "prefix_sha256": digest}


def message_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list) and all(isinstance(item, dict) and item.get("type") in ("text", "input_text") and
                                         isinstance(item.get("text"), str) for item in content):
        return "".join(item["text"] for item in content)
    return None



def prove_claude_turn(events, prefix, stdout, operation, error):
    relevant = [event for event in events if event.get("type") in ("user", "assistant", "system")]
    require(all(event.get("sessionId") == operation["session"] for event in relevant), error)
    users = [event for event in relevant if event.get("type") == "user"]
    require(all(isinstance(event.get("message"), dict) for event in users), error)
    prompts = []
    for event in users:
        content = event["message"].get("content")
        if message_text(content) is not None:
            prompts.append(event)
        else:
            require(isinstance(content, list) and bool(content) and
                    all(isinstance(item, dict) and item.get("type") == "tool_result" for item in content), error)
    require(len(prompts) == 1 and relevant[0] == prompts[0] and isinstance(prompts[0].get("uuid"), str), error)
    prompt = message_text(prompts[0]["message"].get("content"))
    require(prompt is not None and digest_bytes(prompt.encode("utf-8")) == operation["prompt_sha256"], error)
    require(not any(event.get("type") == "system" and event.get("subtype") in ("turn_failed", "turn_aborted")
                    for event in relevant), error)
    terminals = [event for event in relevant if event.get("type") == "assistant" and
                 isinstance(event.get("message"), dict) and
                 event["message"].get("stop_reason") in ("end_turn", "max_tokens", "stop_sequence")]
    if not terminals:
        return None
    require(len(terminals) == 1 and relevant[-1] == terminals[0], error)
    message_id = terminals[0]["message"].get("id")
    answers = [event for event in owner_events(CLAUDE, stdout) if event.get("type") == "assistant" and
               event.get("session_id") == operation["session"] and isinstance(event.get("message"), dict)]
    require(isinstance(message_id, str) and any(event["message"].get("id") == message_id for event in answers), error)
    return False


def prove_codex_turn(events, prefix, stdout, operation, error):
    metadata = [load_native_record(event.get("payload"), "metadata") for event in prefix]
    require(len(metadata) == 1 and metadata[0]["id"] == operation["session"], error)
    users = [event.get("payload") for event in events if event.get("type") == "response_item" and
             isinstance(event.get("payload"), dict) and event["payload"].get("role") == "user"]
    require(len(users) == 1, error)
    prompt = message_text(users[0].get("content"))
    require(prompt is not None and digest_bytes(prompt.encode("utf-8")) == operation["prompt_sha256"], error)
    messages = [event["payload"] for event in events if event.get("type") == "event_msg" and
                isinstance(event.get("payload"), dict)]
    starts = [event for event in messages if event.get("type") == "task_started"]
    require(len(starts) == 1 and isinstance(starts[0].get("turn_id"), str), error)
    turn = starts[0]["turn_id"]
    contexts = [load_native_record(event.get("payload"), "context") for event in events if event.get("type") == "turn_context"]
    require(len(contexts) == 1 and contexts[0]["turn_id"] == turn and contexts[0]["cwd"] == operation["cwd"], error)
    terminals = [event for event in messages if event.get("type") in ("task_complete", "task_failed", "turn_aborted")]
    if not terminals:
        return None
    require(len(terminals) == 1 and terminals[0].get("turn_id") == turn, error)
    return terminals[0]["type"] != "task_complete"


def terminal_proof(run, operation, stdout, terminal_files=None):
    error = ("operation %s transcript cannot prove this session's submitted turn; retain the hold and do not replay"
             % operation["id"])
    proofs = []
    total_bytes = 0
    for filename, witness in operation["transcripts"].items():
        load_file_witness(witness)
        path = Path(filename)
        home = host_home(run, operation["host"])
        require(path in hierarchy_hosts.transcripts(operation["host"], home, operation["session"]),
                error + "; restore the original transcript before reconciliation")
        try:
            descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as transcript:
                info = os.fstat(transcript.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                        (info.st_dev, info.st_ino) == (witness["device"], witness["inode"]), error)
                total_bytes += info.st_size
                if total_bytes > TRANSCRIPT_BYTES:
                    raise budget_problem(path)
                digest, remaining, prefix = hashlib.sha256(), witness["offset"], []
                prefix_kind = OWNER_ADAPTERS[operation["host"]]["prefix_kind"]
                while remaining:
                    block = record_line(transcript, path, min(TRANSCRIPT_LINE_BYTES, remaining)) if prefix_kind else transcript.read(min(1 << 20, remaining))
                    require(bool(block), error)
                    if prefix_kind and len(block) > TRANSCRIPT_LINE_BYTES:
                        raise budget_problem(path)
                    digest.update(block)
                    remaining -= len(block)
                    if prefix_kind:
                        require(block.endswith(b"\n"), error)
                        event = record_json(block, path.name)
                        require(isinstance(event, dict), error)
                        if event.get("type") == prefix_kind:
                            prefix.append(event)
                require(digest.hexdigest() == witness["prefix_sha256"], error)
                events, length = [], witness["offset"]
                for line in transcript_lines(transcript, path, byte_limit=FRESH_BYTES, count_limit=FRESH_EVENTS):
                    require(line.endswith(b"\n"), error)
                    digest.update(line)
                    length += len(line)
                    event = record_json(line, path.name)
                    require(isinstance(event, dict), error)
                    events.append(event)
                after = os.fstat(transcript.fileno())
                require((after.st_dev, after.st_ino) == (info.st_dev, info.st_ino) and after.st_size == length, error)
        except CustodyProblem:
            raise
        except OSError as exc:
            raise ValueError(error + "; restore the original transcript before reconciliation") from exc
        except (ValueError, UnicodeError) as exc:
            raise ValueError(error) from exc
        if not events:
            continue
        result = OWNER_ADAPTERS[operation["host"]]["terminal"](events, prefix, stdout, operation, error)
        if result is not None:
            proofs.append(result)
        if terminal_files is not None:
            terminal_files[filename] = {"device": info.st_dev, "inode": info.st_ino, "offset": length,
                                        "prefix_sha256": digest.hexdigest()}
    require(len(proofs) == 1, "operation %s is unresolved: the transcript has no completed or failed turn; "
            "retain the hold and do not replay" % operation["id"])
    return proofs[0]


def as_json_line(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")


def operation_record(state, operation, *, pending_pid=False):
    operations = state.get("operations")
    recorded = operations.get(operation["endpoint"]) if isinstance(operations, dict) else None
    expected = dict(operation)
    if pending_pid:
        if recorded and recorded.get("intent_recovery") is not True:
            expected.pop("intent_recovery", None)
        # Only the PID transaction may replace the unpublished PID fields after Popen returns.
        expected["pid"] = None
        expected.pop("pid_start", None)
    if recorded != expected:
        fail("operation %s on %s is no longer current; team-state, output and wake marker were retained" %
             (operation["id"], operation["endpoint"]), operation=operation)
    return recorded


def file_prefix(path, limit=TRANSCRIPT_BYTES):
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and bounded_integer(info.st_size),
                "unsafe completion evidence; retain the hold")
        if info.st_size > limit:
            raise budget_problem(path)
        digest = bounded_prefix(stream, info.st_size)
    require(digest is not None, "completion evidence was truncated; retain the hold")
    return {"device": info.st_dev, "inode": info.st_ino, "offset": info.st_size, "prefix_sha256": digest}


def bounded_prefix(stream, count):
    digest, remaining = hashlib.sha256(), count
    while remaining:
        block = stream.read(min(1 << 20, remaining))
        if not block:
            return None
        digest.update(block)
        remaining -= len(block)
    return digest.hexdigest()


def sealed_transcript_status(operation, proof):
    outcome = "unchanged"
    for filename in operation["transcripts"]:
        witness = proof["files"][filename]
        try:
            descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                same = (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                        (info.st_dev, info.st_ino) == (witness["device"], witness["inode"]) and
                        bounded_prefix(stream, witness["offset"]) == witness["prefix_sha256"])
            if not same and outcome != "missing":
                outcome = "changed"
        except FileNotFoundError:
            outcome = "missing"
        except OSError:
            if outcome != "missing":
                outcome = "changed"
    return outcome


def completion_files(run, operation):
    return {operation["stdout"], operation["stderr"], str(run.evidence / operation["turn_log"]),
            *operation["transcripts"]}


def validate_completion(run, operation, proof):
    load_completion(proof)
    error = "operation completion evidence changed; retain the hold"
    require(proof["operation_id"] == operation["id"] and
            proof["launch_sha256"] == digest_bytes(as_json(launch_identity(operation))) and
            set(proof["files"]) == completion_files(run, operation), error)
    require(digest_bytes(bounded_bytes(run.evidence / ("turn-%s.accounting.json" % operation["id"]))) == proof["accounting_sha256"],
            "operation accounting changed after release intent; retain the hold")
    for filename, witness in proof["files"].items():
        limit = TRANSCRIPT_BYTES if filename in operation["transcripts"] else OUTPUT_BYTES
        if witness["offset"] > limit:
            raise budget_problem(filename)
        # Host transcripts are not authority after the seal. Their drift is audited separately, never a replay gate.
        if filename in operation["transcripts"]:
            continue
        descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            digest = bounded_prefix(stream, witness["offset"])
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                (info.st_dev, info.st_ino) == (witness["device"], witness["inode"]) and digest == witness["prefix_sha256"], error)
    expected = {"accounting_sha256": proof["accounting_sha256"], "terminal_sha256": digest_bytes(as_json(proof))}
    require(not operation.get("release") or operation["release"] == expected, error)
    return expected


def finish_operation(run, operation, stdout, code, *, pending_pid=False, outcome=None, recover_private=False,
                     terminal_files=None, observed_wait=False):
    from hierarchy_mailbox import writer_lock
    operation_paths(run, operation)
    # Lock order: owner directory -> mailbox -> short Claude state transaction. Never acquire a mailbox lock
    # from a state callback, or keep a state lock over provider/accounting I/O or any child wait.
    with writer_lock(run.mailbox_root):
        if not observed_wait:
            require_exited(run, operation)
        current = require_init(run)
        # Preserve an actually observed native status/usage even if a foreign public slot prevents retirement.
        # Accounting is keyed by this immutable invocation, not by the mutable current endpoint slot.
        original_launch(run, operation)
        sealed = (owner_folder(run) / ("turn-%s.release.json" % operation["id"])).exists()
        if not sealed:
            # Reconciliation refusals have no effects. Check the original wake before upgrading its accounting;
            # an observed native wait still records its measured exit even when later release checks fail.
            if not observed_wait and operation.get("marker"):
                require_owned_marker(operation)
            code = record_turn(run, operation, stdout, code)
        if observed_wait:
            native_wait_veto(run, operation)
        absent = current.get("operations", {}).get(operation["endpoint"]) is None
        if recover_private and absent:
            original_launch(run, intent_identity(operation))
        else:
            operation_record(current, operation, pending_pid=pending_pid)
            original_launch(run, current["operations"][operation["endpoint"]])
        name = "turn-%s.release.json" % operation["id"]
        recorded = (owner_folder(run) / name).exists()
        if recorded:
            proof = owner_read(run, name)
            release_value = validate_completion(run, operation, proof)
            require(code is None or code == proof["native_exit"], "operation native exit changed; retain the hold")
            code = proof["native_exit"]
        else:
            require(not operation.get("release"), "owner-held completion evidence is missing; retain the hold")
            # A foreign marker before a verified release remains unknown. After a durable release, recovery may
            # retire the old operation but must never unlink a replacement created by a subsequent wake.
            if operation.get("marker"):
                require_owned_marker(operation)
            public_launch = run.evidence / ("turn-%s.launch.json" % operation["id"])
            private_launch = owner_folder(run) / public_launch.name
            if operation.get("intent_recovery") is True and not private_launch.exists():
                owner_publish(run, private_launch.name, launch_identity(operation))
            if pending_pid and not public_launch.exists():
                durable_write(public_launch, as_json(launch_identity(operation)))
            require(code is not None or type(outcome) is bool, "unknown operation completion; retain the hold")
            index(run, Path(operation["stdout"]).name, Path(operation["stderr"]).name,
                  "turn-%s.accounting.json" % operation["id"], public_launch.name, operation["turn_log"])
            failed = bool(code is not None and code != 0) if outcome is None else outcome
            failed |= owner_result_failed(operation["host"], stdout)
            proof = {"schema": "aegis.team-owner-completion/v1", "operation_id": operation["id"],
                     "launch_sha256": digest_bytes(as_json(launch_identity(operation))),
                     "accounting_sha256": digest_bytes(bounded_bytes(run.evidence / ("turn-%s.accounting.json" % operation["id"]))),
                     "files": {filename: (terminal_files or {}).get(filename) or file_prefix(
                                   filename, TRANSCRIPT_BYTES if filename in operation["transcripts"] else OUTPUT_BYTES)
                               for filename in sorted(completion_files(run, operation))},
                     "failed": failed, "native_exit": code}
            owner_publish(run, name, proof)
            release_value = validate_completion(run, operation, proof)
        remove = False
        if operation.get("marker"):
            path = Path(operation["marker"])
            if path.exists() and not path.is_symlink():
                remove = marker_witness(path) == operation["marker_witness"]
        releasing = dict(operation)
        releasing["release"] = release_value
        def release(current):
            require_init(run, state=current)
            if recover_private and current.get("operations", {}).get(operation["endpoint"]) is None:
                require(owner_pending(run, endpoint=operation["endpoint"]).get(operation["endpoint"]) ==
                        intent_identity(operation), "private intent changed; retain the hold")
                current.setdefault("operations", {})[operation["endpoint"]] = releasing
            else:
                operation_record(current, operation, pending_pid=pending_pid)
                current["operations"][operation["endpoint"]] = releasing
        update_state(run, release)
        if remove:
            Path(operation["marker"]).unlink()
        active = owner_folder(run) / active_name(operation["endpoint"])
        if active.exists() or active.is_symlink():
            require(owner_read(run, active.name) == intent_identity(operation),
                    "active owner-held intent changed; retain the hold")
            active.unlink()
            descriptor = os.open(str(active.parent), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        def finish(current):
            require_init(run, state=current)
            operation_record(current, releasing)
            current["operations"].pop(operation["endpoint"])
        update_state(run, finish)
    return code




def retire_unlaunched(run, operation, endpoint, identifier, marker, witness):
    from hierarchy_mailbox import writer_lock
    with writer_lock(run.mailbox_root):
        current = load_state(run)
        slot = (current or {}).get("operations", {}).get(endpoint)
        present = operation is not None and slot == operation
        if present:
            path = run.run / ".owner-custody" / active_name(endpoint)
            if path.exists() or path.is_symlink():
                require(owner_read(run, path.name) == intent_identity(operation), "foreign owner intent was retained")
                for alias in publication_aliases(path.parent, path.name, path.stat()):
                    alias.unlink()
                path.unlink()
        if marker:
            owned = operation or {"id": identifier, "marker": str(marker), "marker_witness": witness}
            if require_owned_marker(owned):
                marker.unlink()
        if present:
            def retire(fresh):
                operation_record(fresh, operation)
                fresh["operations"].pop(endpoint)
            update_state(run, retire)
    return True



def model_turn(run, endpoint, binding, argv, cwd, prompt, timeout, marker=None, approval=None,
               operation_id=None, owned_marker=None):
    """Keep one custody identity: known no-spawn retires only its staging; any returned Popen is UNKNOWN on loss."""
    from contextlib import ExitStack
    operation = None
    identifier = operation_id or uuid.uuid4().hex
    created = []

    def unstarted(exc):
        retired = False
        try:
            retired = retire_unlaunched(run, operation, endpoint, identifier, marker, owned_marker)
            for path, device, inode in created:
                info = path.lstat()
                require((info.st_dev, info.st_ino) == (device, inode), "foreign output file was retained")
                path.unlink()
        except (Stop, ValueError, OSError):
            retired = False
        detail = {"spawned": False, "custody_retired": retired}
        if operation is not None:
            detail["operation"] = operation
        if isinstance(exc, CustodyProblem):
            detail.update(exc.detail())
        if isinstance(exc, Stop) and exc.code == REFUSED and retired:
            raise Stop(REFUSED, str(exc), **{**detail, **exc.detail})
        message = "model was not started: %s; %s" % (exc, "owned intent and marker retired" if retired else "custody retained; inspect status")
        raise Stop(REFUSED if retired else FAILED, message, **detail)

    try:
        env = child_env(run)
        if governed_run(run):
            validate_role_write_roots(run)
            argv = [str(validate_model_executable(run, binding["host"], argv, cwd, env)), *argv[1:]]
        OWNER_ADAPTERS[binding["host"]]["credentials"](run)
        home = host_home(run, binding["host"])
        transcripts = {str(path): transcript_witness(path) for path in
                       hierarchy_hosts.transcripts(binding["host"], home, binding["session"])}
        process_scope = operation_process_scope()
        owner_folder(run, create=True)
        operation = {"id": identifier, "endpoint": endpoint, "host": binding["host"], "session": binding["session"],
                     "generation": binding["generation"], "started_at": timestamp(), "pid": None,
                     "process_scope": process_scope,
                     "stdout": str(run.evidence / ("turn-%s.stdout.jsonl" % identifier)),
                     "stderr": str(run.evidence / ("turn-%s.stderr.txt" % identifier)),
                     "transcripts": transcripts,
                     "prompt_sha256": digest_bytes((prompt if prompt is not None else argv[-1]).encode("utf-8")), "cwd": cwd,
                     "turn_log": "root-turns.jsonl" if endpoint_parts(endpoint)[1] == "root" else
                                 "role-turns-%s.jsonl" % endpoint.replace("/", "%2F"),
                     "marker": str(marker) if marker else None, "marker_witness": owned_marker}
        if approval is not None:
            operation["approval"] = approval
        def intend(current):
            require_init(run, state=current)
            require_resolved(run, endpoint, state=current)
            current["owner_custody"] = True
            current.setdefault("operations", {})[endpoint] = operation
        update_state(run, intend)
        owner_publish(run, active_name(endpoint), intent_identity(operation))
    except BaseException as exc:
        unstarted(exc)

    with ExitStack() as stack:
        try:
            stdin = stack.enter_context(tempfile.TemporaryFile())
            outputs = []
            for field in ("stdout", "stderr"):
                path = Path(operation[field])
                stream = stack.enter_context(open(path, "xb"))
                info = os.fstat(stream.fileno())
                created.append((path, info.st_dev, info.st_ino))
                outputs.append(stream)
            stdout, stderr = outputs
            if prompt is not None:
                stdin.write(prompt.encode("utf-8"))
                stdin.seek(0)
        except BaseException as exc:
            # Close staged descriptors before unlinking them. No Popen was called.
            stack.close()
            unstarted(exc)
        try:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=stdin if prompt is not None else subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
        except (OSError, ValueError, Stop) as exc:
            stack.close()
            unstarted(exc)
        observed_native = None
        try:
            operation.update(pid=process.pid, pid_start=process_identity(process.pid))
            owner_publish(run, "turn-%s.launch.json" % identifier, launch_identity(operation))
            launch_path = run.evidence / ("turn-%s.launch.json" % identifier)
            if launch_path.exists() or launch_path.is_symlink():
                raise OSError("operation launch witness already exists")
            durable_write(launch_path, as_json(launch_identity(operation)))
            def record_pid(current):
                require_init(run, state=current)
                recorded = operation_record(current, operation, pending_pid=True)
                recorded.update(pid=operation["pid"], pid_start=operation["pid_start"])
            update_state(run, record_pid)
            observed_native = process.wait(timeout=timeout)
            native_exit_record(run, operation, observed_native)
        except subprocess.TimeoutExpired:
            record_unresolved_turn(run, operation)
            fail("operation %s on %s is unresolved after its deadline; process pid %d was left running, output and "
                 "team-state were retained. Inspect status, then use approve/turn --reconcile; do not replay" %
                 (identifier, endpoint, process.pid), operation=operation, spawned=True)
        except BaseException as exc:
            try:
                record_unresolved_turn(run, operation, observed_native)
            except (Stop, ValueError, OSError) as accounting:
                detail = accounting.detail if isinstance(accounting, Stop) else (
                    accounting.detail() if isinstance(accounting, CustodyProblem) else {})
                fail("operation %s is unresolved: %s; accounting unavailable: %s; team-state and output retained" %
                     (identifier, exc, accounting), **{**detail, "operation": operation, "spawned": True})
            fail("operation %s is unresolved: %s; team-state and output retained; inspect before reconciliation" %
                 (identifier, exc), operation=operation, spawned=True)
    try:
        raw, errors = native_output(operation), native_output(operation, "stderr")
        finish_operation(run, operation, raw, process.returncode, observed_wait=True)
    except (Stop, ValueError, OSError) as exc:
        if isinstance(exc, Stop) and exc.code == FAILED:
            raise
        detail = exc.detail() if isinstance(exc, CustodyProblem) else {}
        fail("operation %s finished but custody release failed: %s; state, marker, accounting and output retained" %
             (identifier, exc), operation=operation, spawned=True, **detail)
    return subprocess.CompletedProcess(argv, process.returncode, raw, errors)


def approval_journal_failed(run, operation):
    approval = operation.get("approval")
    if not approval:
        return False
    _policy, journal = hierarchy_router.locked_load(hierarchy_lifecycle.Lifecycle(run.lifecycle), 5.0)
    previous = approval["previous"]
    added = journal["decisions"][len(previous):]
    return journal["decisions"][:len(previous)] != previous or len(added) != 1 or any(
        entry["request_id"] != approval["request_id"] or entry["decision"] != approval["decision"] or
        entry["request_sha256"] != approval["request_sha256"] for entry in added)


def reconcile(run, endpoint):
    state = require_init(run)
    recover_private = state.get("operations", {}).get(endpoint) is None
    operation = state.get("operations", {}).get(endpoint)
    if operation is None:
        operation = owner_pending(run, endpoint=endpoint).get(endpoint)
    require(operation is not None, "%s has no unresolved operation" % endpoint)
    owner_folder(run)
    try:
        load_operation(operation)
    except ValueError as exc:
        refuse(str(exc), operation=operation, process_observation={"state": "UNAVAILABLE", "reason": str(exc)},
               next_action="inspect status and restore the named custody record before reconciliation; do not replay")
    require(operation["endpoint"] == endpoint, "operation endpoint differs from its custody slot; retain the hold")
    operation_paths(run, operation)
    binding = Mailbox(run.mailbox_root).current_binding(endpoint)
    require(all(operation[key] == binding.get(key) for key in ("host", "session", "generation")),
            "operation binding changed; retain the hold")
    # Positive original-instance absence is mandatory even when a perfectly formed seal is present.
    require_exited(run, operation)
    pending = operation.get("pid") is None and "pid_start" not in operation
    effective = original_launch(run, operation)
    if operation.get("release"):
        effective = {**effective, "release": operation["release"]}
    completion_path = owner_folder(run) / ("turn-%s.release.json" % operation["id"])
    if operation.get("release") or completion_path.exists():
        proof = owner_read(run, completion_path.name)
        validate_completion(run, effective, proof)
        evidence = sealed_transcript_status(effective, proof)
        failed = proof["failed"] | approval_journal_failed(run, effective)
        finish_operation(run, effective, b"", proof["native_exit"], pending_pid=pending, outcome=proof["failed"],
                         recover_private=recover_private)
        answer = {"endpoint": endpoint, "reconciled": operation["id"],
                  "outcome": "failed" if failed else "completed", "replayed": False}
        if evidence != "unchanged":
            answer["post_seal_evidence"] = evidence
        return (FAILED if failed else OK), answer
    operation = effective
    stdout = native_output(operation)
    terminal_files = {}
    failed = terminal_proof(run, operation, stdout, terminal_files)
    failed |= owner_result_failed(operation["host"], stdout) | approval_journal_failed(run, operation)
    receipt_path = run.evidence / ("turn-%s.accounting.json" % operation["id"])
    receipt = read_json(receipt_path) if receipt_path.exists() else {}
    require(isinstance(receipt, dict) and (receipt.get("exit_code") is None or type(receipt["exit_code"]) is int),
            "operation accounting has an invalid exit code; retain the hold")
    native_exit = receipt.get("exit_code")
    observed_exit = native_exit_record(run, operation)
    require(native_exit is None or observed_exit is None or native_exit == observed_exit, "native exit conflicts with accounting; retain the hold")
    if observed_exit is not None:
        native_exit = observed_exit
    failed |= native_exit is not None and native_exit != 0
    native_exit = finish_operation(run, operation, stdout, native_exit, pending_pid=pending, outcome=failed,
                                   recover_private=recover_private, terminal_files=terminal_files)
    failed |= native_exit is not None and native_exit != 0
    return (FAILED if failed else OK), {"endpoint": endpoint, "reconciled": operation["id"],
                                       "outcome": "failed" if failed else "completed", "replayed": False}


def approve(run, args):
    state = require_init(run)
    bound = state.get("root")
    if not bound:
        refuse("ROOT is not bound; run root --session <id> first")
    endpoint = run.endpoint("root")
    binding = Mailbox(run.mailbox_root).current_binding(endpoint)
    planned_binding(run, endpoint, binding["host"])
    require(binding["host"] == run.hosts["root"], "ROOT's host differs from team-run.json")
    require(all(bound[key] == binding[key] for key in ("session", "generation")), "ROOT's recorded binding changed")
    if args.reconcile:
        return reconcile(run, endpoint)
    require_resolved(run, endpoint)
    timeout = turn_deadline()
    adapter = OWNER_ADAPTERS[binding["host"]]
    adapter["root_validate"](run, binding, bound)
    reason = args.reason
    text(reason, "reason", 512)
    require(not set('"\r\n') & set(reason), "the reason may not contain double quotes or line breaks")
    decision = "deny" if args.deny else "approve"
    lifecycle = hierarchy_lifecycle.Lifecycle(run.lifecycle)
    _policy, before = hierarchy_router.locked_load(lifecycle, 5.0)
    row = next((row for row in hierarchy_team_view.pending(lifecycle)["pending"] if row["request_id"] == args.id), None)
    if row is None:
        rows = {r["request_id"]: r for r in hierarchy_team_view.status(lifecycle)["requests"]}
        existing = rows.get(args.id)
        latest = next((r for r in reversed(before["decisions"]) if r["request_id"] == args.id), None)
        if args.deny and existing and latest and latest["decision"] == "approve":
            row = existing
        else:
            refuse("request %s is not pending a ROOT decision (journal state: %s)" % (
                args.id, existing["state"] if existing else "not published"))
    text_prompt = (ROOT_PROMPT if not args.deny else ROOT_PROMPT.replace("Call team_pending", "Call team_status")) % (
        args.id, decision, reason)
    argv, prompt = adapter["root_argv"](run, binding, bound, text_prompt)
    if governed_run(run):
        validate_model_executable(run, binding["host"], argv, str(run.project))
    proc = model_turn(run, endpoint, binding, argv, str(run.project), prompt, timeout,
                      approval={"request_id": args.id, "decision": decision, "request_sha256": row["request_sha256"],
                                "previous": before["decisions"]})
    stdout = proc.stdout.decode("utf-8", "replace")
    items = adapter["items"](stdout)
    messages = [item["text"] for item in items if item["type"] == "agent_message"]
    last = messages[-1] if messages else None
    _policy, journal = hierarchy_router.locked_load(lifecycle, 5.0)
    previous = before["decisions"]
    added = journal["decisions"][len(previous):]
    if journal["decisions"][:len(previous)] != previous or any(
            entry["request_id"] != args.id or entry["decision"] != decision or
            entry["request_sha256"] != row["request_sha256"] for entry in added) or len(added) > 1:
        fail("ROOT recorded unexpected journal decisions; inspect retained journal before continuing",
             decisions=added, **{adapter["exit_field"]: proc.returncode})
    recorded = [entry for entry in journal["decisions"] if entry["request_id"] == args.id]
    if not (recorded and recorded[-1]["decision"] == decision and
            recorded[-1]["request_sha256"] == row["request_sha256"]):
        fail("ROOT did not record %s on %s (sha256 %s); its last message: %s" % (decision, args.id,
                                                                                 row["request_sha256"], last),
             root_last_message=last, **{adapter["exit_field"]: proc.returncode},
             stderr=proc.stderr.decode("utf-8", "replace")[-800:])
    failure = adapter["failure"](proc.returncode, proc.stdout, True)
    if failure:
        fail(failure[0], **failure[1])
    return OK, {"request_id": args.id, "decision": decision, "request_sha256": row["request_sha256"],
                "event_id": row["root_decide"]["event_id_" + decision], "root_last_message": last}


def turn(run, args):
    require_init(run)
    endpoint = args.endpoint
    mailbox = Mailbox(run.mailbox_root)
    mailbox.endpoint(endpoint)
    if endpoint_parts(endpoint)[1] == "root":
        refuse("ROOT's turns go through approve")
    history = mailbox.bindings(endpoint)
    if not history:
        refuse("%s is not bound; start it with up first" % endpoint)
    binding = history[-1]
    planned_binding(run, endpoint, binding["host"])
    require(isinstance(binding["host"], str) and binding["host"] in OWNER_ADAPTERS and
            binding["host"] == run.hosts["team"],
            "owner turn host differs from configured team host; restore the configured host binding")
    if args.reconcile:
        require(args.prompt is None, "--reconcile does not accept a prompt")
        return reconcile(run, endpoint)
    require_resolved(run, endpoint)
    timeout = turn_deadline()
    require(isinstance(args.prompt, str) and bool(args.prompt.strip()) and "\0" not in args.prompt, "invalid prompt")
    quoted = endpoint.replace("/", "%2F")
    generation = history[-1]["generation"]
    profile_path = run.base / "profiles" / ("%s-g%d.wake.json" % (quoted, generation))
    if not profile_path.is_file():
        refuse("%s has no wake profile for generation %d: %s" % (endpoint, generation, profile_path))
    marker = mailbox.wake_marker(endpoint)
    if marker.exists():
        refuse("a wake is running for %s (%s); try again after it ends" % (endpoint, marker))
    setup = governed_runtime(run) if governed_run(run) else read_json(run.base / "provision.json")
    unread = mailbox.delivery(setup["delivery_dir"], endpoint)["endpoints"][endpoint]["unread_count"]
    if unread:
        refuse("%s has %d unread message%s; the loop's wake reads %s, so an owner turn now would race it"
               % (endpoint, unread, "" if unread == 1 else "s", "it" if unread == 1 else "them"))
    profile = read_json(profile_path)
    require(isinstance(profile, dict) and all(profile.get(key) == binding[key] for key in ("host", "session", "generation")),
            "binding changed before owner turn; the outgoing session was not started")
    adapter = OWNER_ADAPTERS[binding["host"]]
    profile = adapter["turn_profile"](run, binding, profile_path, profile)
    if governed_run(run):
        validate_model_executable(run, binding["host"], profile["argv"], profile["cwd"])
    by_argv = profile["prompt_via"] == "argv"
    argv = profile["argv"] + ([args.prompt] if by_argv else [])
    from hierarchy_mailbox import writer_lock
    from hierarchy_wake import claim_wake
    identifier = uuid.uuid4().hex
    with writer_lock(mailbox.root):
        current = Mailbox(mailbox.root).current_binding(endpoint)
        require(all(profile[key] == current[key] for key in ("host", "session", "generation")),
                "binding changed before owner turn; the outgoing session was not started")
        marker = claim_wake(mailbox, endpoint)
        value = read_json(marker)
        value["operation_id"] = identifier
        durable_write(marker, as_json(value))
        owned_marker = marker_witness(marker)
    proc = model_turn(run, endpoint, binding, argv, profile["cwd"], None if by_argv else args.prompt, timeout, marker,
                      operation_id=identifier, owned_marker=owned_marker)
    log = run.evidence / ("role-turns-%s.jsonl" % quoted)
    items = adapter["items"]
    answer = {"endpoint": endpoint, "exit_code": proc.returncode, "items": items(proc.stdout.decode("utf-8", "replace")),
              "log": str(log)}
    unknown = sum(event.get("type") == "unknown" for event in owner_events(binding["host"], proc.stdout))
    if unknown:
        answer["unknown_events"] = unknown
    if proc.stderr:
        answer["stderr"] = proc.stderr.decode("utf-8", "replace")[-800:]
    failure = adapter["failure"](proc.returncode, proc.stdout, False)
    if failure:
        return FAILED, {**answer, "error": failure[0], **failure[1]}
    return (OK if proc.returncode == 0 else FAILED), answer


# -- status ---------------------------------------------------------------------------------------------------------------

def launcher_roles(run):
    if not (run.base / "provision.json").is_file():
        return {}
    _code, answer, _ = tool(run, "launcher", "--base", run.base, "status")
    rows = {}
    for endpoint, row in answer.get("endpoints", {}).items():
        last = row.get("last") or {}
        rows[endpoint] = {"binding": row.get("binding"), "records": row.get("records"),
                          "last": {key: last.get(key) for key in ("action", "state", "at")} if last else None}
    return rows


def custody_inspection(run, state):
    errors = {}
    pending = owner_pending(run, problems=errors, state=state)
    slots = (state or {}).get("operations", {})
    operations = {}
    if not isinstance(slots, dict):
        errors["_state"] = {"error": "invalid operations record", "next_action": CUSTODY_RECOVERY}
        slots = {}
    if init_complete(state) and (run.isolated_homes or (state or {}).get("host_plan_issued")):
        try:
            owner_read(run, "runtime.json")
        except (ValueError, OSError) as exc:
            errors["_runtime"] = {"error": str(exc), "next_action": CUSTODY_RECOVERY}
    for endpoint, raw in slots.items():
        try:
            operation = load_operation(raw)
            require(operation["endpoint"] == endpoint, "invalid operation record")
            operation_paths(run, operation)
            operations[endpoint] = operation
            original_launch(run, operation)
            exit_path = run.run / ".owner-custody" / ("turn-%s.exit.json" % operation["id"])
            if exit_path.exists() or exit_path.is_symlink():
                native_exit_record(run, operation)
            path = run.run / ".owner-custody" / ("turn-%s.release.json" % operation["id"])
            if path.exists() or path.is_symlink() or operation.get("release"):
                load_completion(owner_read(run, path.name))
        except (ValueError, OSError, Stop) as exc:
            errors[endpoint] = {"error": str(exc), "next_action": CUSTODY_RECOVERY}
    for endpoint, intent in pending.items():
        operations.setdefault(endpoint, intent)
    environment = run.evidence / "child-environment.json"
    if environment.exists() or environment.is_symlink():
        try:
            environment_record(read_json(environment))
        except (ValueError, OSError) as exc:
            errors["_environment"] = {"error": str(exc), "next_action": CUSTODY_RECOVERY, **(exc.problem if isinstance(exc, CustodyProblem) else {})}
    return operations, errors


def status(run, args):
    problems = {}
    state = getattr(run, "inspected_state", None)
    if getattr(run, "state_problem", None):
        problems["_state"] = run.state_problem
    complete = init_complete(state)
    operations, custody_errors = custody_inspection(run, state)
    problems.update(custody_errors)
    pid, alive, ours = loop_process(run)
    def inspect(name, call, default):
        try:
            return call()
        except (Stop, ValueError, OSError, KeyError, TypeError, AttributeError, OverflowError) as exc:
            problems[name] = {"error": str(exc), "next_action": "restore the named records and inspect status again"}
            return default
    running = inspect("_loop", lambda: loop_state(run)[0], "unknown") if complete else "not_running"
    answer = {"schema": STATUS_SCHEMA, "run": str(run.run), "initiative": run.id,
              "init": {"complete": complete, "next_step": None if complete else inspect("_init", lambda: next_step(state), None)},
              "root": (state or {}).get("root"),
              "loop": {"state": running, "pid": pid if alive and ours else None, "pid_alive": bool(alive and ours)},
              "roles": inspect("_roles", lambda: launcher_roles(run), {}) if complete else {}, "team": None, "pending": []}
    if operations:
        answer["unresolved_operations"] = operations
    if complete:
        lifecycle = hierarchy_lifecycle.Lifecycle(run.lifecycle)
        answer["team"] = inspect("_team", lambda: hierarchy_team_view.status(
            lifecycle, loop_state=run.loop_state, evidence=run.evidence), None)
        answer["pending"] = inspect("_pending", lambda: hierarchy_team_view.pending(lifecycle)["pending"], [])
    if problems:
        answer["custody_errors"] = problems
    if not args.text:
        return OK, answer
    print(status_text(run, answer), end="")
    return OK, None


def status_text(run, answer):
    lines = ["team %s at %s" % (run.id, run.run)]
    for slot, problem in sorted(answer.get("custody_errors", {}).items()):
        lines.append("custody: %s: %s; %s" % (slot, problem["error"], problem.get("next_action", CUSTODY_RECOVERY)))
    init_state = answer["init"]
    lines.append("init: " + ("complete" if init_state["complete"] else "next step " + str(init_state["next_step"])))
    loop = answer["loop"]
    head = "loop: " + loop["state"]
    if loop["pid"]:
        head += " (pid %d)" % loop["pid"]
    team = answer["team"] or {}
    last = team.get("loop") or {}
    if last.get("pass_id"):
        head += "; pass %s finished %s" % (last["pass_id"], last.get("finished_at"))
        if last.get("current_step"):
            head += ", step %s since %s" % (last["current_step"], last.get("step_started_at"))
    lines.append(head)
    for endpoint, operation in sorted(answer.get("unresolved_operations", {}).items()):
        lines.append("unresolved: %s operation %s pid %s since %s; inspect, then approve/turn --reconcile; do not replay" %
                     (endpoint, operation["id"], operation.get("pid"), operation["started_at"]))
    if answer["roles"]:
        lines.append("roles:")
        for endpoint, row in sorted(answer["roles"].items()):
            binding = row["binding"]
            last_record = row["last"] or {}
            lines.append("  %s: %s, last %s %s at %s" % (
                endpoint, "g%d %s" % (binding["generation"], binding["session"]) if binding else "unbound",
                last_record.get("action"), last_record.get("state"), last_record.get("at")))
    who = {"root": "ROOT must act", "owner": "the owner must act", "router": "the Router's records"}
    for act, rows in sorted((team.get("holds_by_act") or {}).items()):
        if not rows:
            continue
        lines.append("%s (%s):" % (act, who.get(act, act)))
        for row in rows:
            subject = row.get("endpoint") or row.get("request_id") or row.get("job") or ""
            lines.append("  %s %s %s: %s (seen %s times since %s)" % (row["step"], row["kind"], subject, row["detail"],
                                                                     row.get("count"), row.get("first_seen")))
    if answer["pending"]:
        lines.append("pending ROOT decisions:")
        for row in answer["pending"]:
            lines.append("  %s (%s): hierarchy_team.py --config %s approve %s --reason TEXT" % (
                row["request_id"], row["why"], run.config_path, row["request_id"]))
    else:
        lines.append("pending ROOT decisions: none")
    return "\n".join(lines) + "\n"


# -- down -----------------------------------------------------------------------------------------------------------------

def stop_loop(run, wait):
    pid, alive, ours = loop_process(run)
    if pid is None or not alive:
        return {"state": "already_stopped"}
    if not ours:
        return {"state": "already_stopped", "note": "pid %d is not this run's loop" % pid}
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if not process_alive(pid):
            return {"state": "stopped", "pid": pid}
        time.sleep(0.1)
    if not process_alive(pid):
        return {"state": "stopped", "pid": pid}
    fail("the loop (pid %d) did not stop within %d s after SIGTERM; a step may still be running. Run down again once "
         "it has stopped" % (pid, wait))


def stop_roles(run):
    started = launcher_roles(run)
    order = [endpoint for endpoint, _ in plan_roles(run)] if run.lifecycle.is_dir() else []
    names = [e for e in order if e in started] + sorted(e for e in started if e not in order)
    rows = []
    for endpoint in names:
        binding = started[endpoint]["binding"]
        # ROOT is the owner's session and the launcher never stops it; a refused ROOT start still leaves a record.
        if not binding or binding["host"] not in OWNER_ADAPTERS or endpoint_parts(endpoint)[1] == "root":
            continue
        code, answer, _ = tool(run, "launcher", "--base", run.base, "stop", "--endpoint", endpoint)
        rows.append({"endpoint": endpoint, "state": answer.get("state"), "pids": answer.get("pids", [])})
        if "unowned_pids" in answer:
            rows[-1]["unowned_pids"] = answer["unowned_pids"]
            if not isinstance(answer["unowned_pids"], list) or any(type(pid) is not int or pid <= 0 for pid in answer["unowned_pids"]):
                fail("%s returned invalid unowned_pids; resources were kept" % endpoint, roles=rows)
        if answer.get("unowned_pids"):
            fail("%s has unowned_pids; host ownership is unresolved and resources were kept" % endpoint, roles=rows)
        if code != 0:
            fail("%s could not be stopped: %s" % (endpoint, answer.get("error") or answer.get("state")), roles=rows)
    return rows


def copy_tree(source, target):
    if target.exists():
        shutil.rmtree(target)
    if source.is_dir():
        shutil.copytree(source, target, symlinks=True)
    else:
        target.mkdir(parents=True, mode=0o700)


def rollout_turns(path):
    """One rollout's turns, ported from the cost ADR's ledger (evidence/43-e2e-turn-ledger.py): each turn's token
    spend is the delta of Codex's cumulative token_count, and its publishes are the message ids passed to
    mailbox_publish, refused attempts included, so a repeated id is a retry."""
    keys = ("input_tokens", "cached_input_tokens", "output_tokens")
    rows, current, totals, named, session = [], None, dict.fromkeys(keys, 0), None, None
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "rollout must be a regular file")
        for line in transcript_lines(stream, path, count_limit=OUTPUT_EVENTS):
            try:
                event = record_json(line.decode("utf-8", "replace"), path.name)
            except CustodyProblem:
                raise
            except ValueError:
                continue
            if not isinstance(event, dict):
                continue
            payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
            kind = event.get("type")
            if kind == "session_meta" and session is None:
                session = payload.get("id")
            elif kind == "turn_context":
                if current:
                    rows.append(current)
                current = {"start": dict(totals), "end": dict(totals), "prompt": None, "publishes": []}
            elif kind == "event_msg" and payload.get("type") == "token_count" and isinstance(payload.get("info"), dict):
                usage = payload["info"].get("total_token_usage") or {}
                totals = {key: usage.get(key, 0) for key in keys}
                if current:
                    current["end"] = dict(totals)
            elif kind == "response_item" and payload.get("type") == "message" and payload.get("role") == "user":
                said = " ".join(c.get("text", "") for c in payload.get("content", []) if isinstance(c, dict))
                if "started this session for " in said:
                    named = said.split("started this session for ", 1)[1].split(" ", 1)[0].rstrip(".")
                elif said.startswith("You are ROOT"):
                    named = "ROOT"
                if current and current["prompt"] is None and not said.startswith(("<", "#")):
                    current["prompt"] = said[:48]
            elif current and kind == "response_item" and payload.get("type") in (
                    "function_call", "custom_tool_call", "mcp_tool_call") and "mailbox_publish" in json.dumps(payload):
                current["publishes"].extend(PUBLISH_ID.findall(json.dumps(payload)) or ["<unparsed>"])
    if current:
        rows.append(current)
    turns = []
    for number, row in enumerate(rows, 1):
        spent = {key: row["end"][key] - row["start"][key] for key in keys}
        retried = sorted({name for name in row["publishes"] if row["publishes"].count(name) > 1})
        turns.append({"turn": number, **spent, "prompt": row["prompt"], "publishes": row["publishes"],
                      "retried": retried})
    return session, named, turns, totals


def turn_ledger(run, state, sessions):
    names = {}
    base_launches = run.base / "launches"
    for record in sorted(base_launches.glob("*/*.json")) if base_launches.is_dir() else []:
        try:
            value = read_json(record)
        except (OSError, ValueError):
            continue
        if value.get("session"):
            names[value["session"]] = value.get("endpoint")
    if (state or {}).get("root"):
        names[state["root"]["session"]] = run.endpoint("root")
    roles, total = [], {"turns": 0, "input_tokens": 0, "cached_input_tokens": 0, "output_tokens": 0}
    for path in sorted(sessions.rglob("*.jsonl")) if sessions.is_dir() else []:
        session, named, turns, totals = rollout_turns(path)
        roles.append({"endpoint": names.get(session) or named or path.name, "session": session,
                      "rollout": str(path.relative_to(run.evidence)), "turns": turns, "totals": totals})
        total["turns"] += len(turns)
        for key in totals:
            total[key] += totals[key]
    total["all_tokens"] = total["input_tokens"] + total["output_tokens"]
    by_command = {}
    if run.commands_log.is_file():
        for line in bounded_bytes(run.commands_log, TURN_LOG_BYTES).split(b"\n"):
            if not line:
                continue
            row = record_json(line, run.commands_log.name)
            if row.get("exit") == OK:
                by_command[row["command"]] = by_command.get(row["command"], 0) + 1
    return {"schema": LEDGER_SCHEMA, "at": timestamp(), "roles": roles, "total": total,
            "owner_actions": {"by_command": by_command,
                              "model_turn_commands": by_command.get("approve", 0) + by_command.get("turn", 0)}}


def write_sums(run):
    lines = []
    for path in sorted(run.evidence.rglob("*")):
        if path.is_file() and not path.is_symlink() and path != run.evidence / "SHA256SUMS":
            lines.append("%s  %s\n" % (sha_file(path), path.relative_to(run.evidence)))
    write_atomic(run.evidence / "SHA256SUMS", "".join(lines).encode("utf-8"))
    return len(lines)


def collect(run, state):
    """Step 17 of the guide: the run's records copied into evidence, the turn ledger, then SHA256SUMS."""
    run.evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    if run.lifecycle.is_dir():
        save(run, "checkpoint-after.json", checked(run, "lifecycle checkpoint", "lifecycle", "--root", run.lifecycle,
                                                   "checkpoint"))
    if (run.base / "provision.json").is_file():
        save(run, "launcher-status-end.json", checked(run, "launcher status", "launcher", "--base", run.base, "status"))
    if run.lifecycle.is_dir() and run.store.is_dir():
        save(run, "router-end.json", checked(run, "router status", "router", "--lifecycle", run.lifecycle, "--store",
                                             run.store, "status"))
    for source, name in ((run.base / "launches", "launches"), (run.delivery, "delivery"), (run.loop_state, "loop"),
                         (run.run / "requests", "requests"), (run.run / "events", "events"),
                         (run.mailbox_root, "mailbox"), (run.store / "events", "store-events"),
                         (run.store / "jobs" / run.id, "jobs"), (run.codex_home / "sessions", "codex-sessions")):
        # T2(a) PR 6 (down) adds (run.claude_home / "projects", "claude-projects") here for a plan that uses
        # claude-code, and purge_claude then checks each copy as purge does. Nothing else of claude_home is copied:
        # never its credentials.
        copy_tree(source, run.evidence / name)
    for source, name in ((run.run / "policy.json", "policy.json"), (run.recipes, "recipes.json"),
                         (run.pid_path, "loop.pid"), (run.log_path, "loop.log"),
                         (run.commands_log, "team-commands.jsonl")):
        if source.is_file():
            shutil.copy2(source, run.evidence / name)
    ledger = turn_ledger(run, state, run.evidence / "codex-sessions")
    save(run, "turn-ledger.json", ledger)
    return {"files": write_sums(run), "turns": ledger["total"]["turns"], "tokens": ledger["total"]["all_tokens"]}


def release_leases(run, state):
    if not any(key.startswith("lease:") for key in state["init"]["done"]):
        return []
    code, listing, proc = aegis(run, "team", "list", "--workspace", str(run.project), "--json")
    if code != 0:
        fail("aegis team list: %s" % (listing.get("error") or proc.stderr.strip()[-400:]))
    live = {lease["lane"]: lease for lease in listing.get("leases", [])}
    rows = []
    for lane in run.implementers:
        if "lease:" + lane.id not in state["init"]["done"]:
            continue
        lease = live.get(lane.lease)
        if lease is None:
            if not (run.evidence / ("lease-release-%s.json" % lane.id)).is_file():
                save(run, "lease-absent-%s.json" % lane.id, listing)
            rows.append({"lane": lane.lease, "state": "already_released"})
            continue
        claimed = read_json(run.evidence / ("lease-claim-%s.json" % lane.id)).get("lease")
        identity = ("lane", "claim_id", "owner", "role", "branch", "paths")
        if not isinstance(claimed, dict) or any(lease.get(key) != claimed.get(key) for key in identity):
            fail("lease ownership changed for %s; resources were kept for inspection" % lane.lease)
        # The oid is read now: a renewal since the claim changed it, and the real run failed on a pasted placeholder.
        code, answer, proc = aegis(run, "team", "release", lane.lease, "--workspace", str(run.project), "--expect",
                                   lease["oid"], "--json")
        if code != 0:
            fail("aegis team release %s: %s" % (lane.lease, answer.get("error") or answer.get("message") or
                                                proc.stderr.strip()[-400:]), result=answer)
        save(run, "lease-release-%s.json" % lane.id, answer)
        rows.append({"lane": lane.lease, "state": "released", "oid": lease["oid"]})
    return rows


def release_slots(run, state):
    rows = []
    asked = {lane.id: state["init"]["done"].get("slot-request:" + lane.id) for lane in run.implementers}
    if not any(asked.values()):
        return rows
    held = {row["request_id"] for row in checked(run, "workspace status", "workspace", "--store", run.store,
                                                 "status")["capacity"]["writer"]["holders"]}
    for lane in run.implementers:
        if not asked[lane.id]:
            continue
        request_id = asked[lane.id]["request_id"]
        if request_id not in held:
            rows.append({"lane": lane.id, "state": "already_released"})
            continue
        proof = next((run.evidence / name for name in ("lease-release-%s.json" % lane.id, "lease-absent-%s.json" % lane.id)
                      if (run.evidence / name).is_file()), None)
        if proof is None:
            fail("the writer slot of %s is kept: its lease release has no evidence" % lane.id)
        answer = checked(run, "slot release for " + lane.id, "workspace", "--store", run.store, "release", "--request",
                         request_file(run, "slot-release-%s.json" % lane.id, {
                             "request_id": request_id, "evidence": {"path": str(proof), "sha256": sha_file(proof)}}))
        save(run, "slot-release-%s.json" % lane.id, answer)
        rows.append({"lane": lane.id, "state": "released"})
    return rows


def remove_worktrees(run, state):
    rows = []
    for lane in run.implementers:
        if "worktree:" + lane.id not in state["init"]["done"]:
            continue
        worktree = Path(state["init"]["done"]["worktree:" + lane.id]["path"])
        if not worktree.exists():
            rows.append({"lane": lane.id, "state": "already_removed", "path": str(worktree)})
            continue
        # Only this run's worktree, by path; never prune or repair, which touch every worktree of the clone.
        removed = git(run.project, "worktree", "remove", str(worktree), ok=True, run=run)
        if removed.returncode != 0:
            fail("git worktree remove refused %s: %s; clean it by hand, never with prune or repair"
                 % (worktree, removed.stderr.strip()[-400:]))
        rows.append({"lane": lane.id, "state": "removed", "path": str(worktree)})
    return rows


def remove_review_copies(run):
    rows = []
    for path in sorted(run.run.glob("review-*")) if run.run.is_dir() else []:
        if not path.is_dir() or path.is_symlink():
            continue
        if not (path / "manifest.json").is_file():
            rows.append({"path": str(path), "state": "kept: no review manifest"})
            continue
        answer = checked(run, "review remove " + path.name, "review", "remove", "--out", path)
        rows.append({"path": answer.get("removed", str(path)), "state": "removed"})
    return rows


def parsed_sums(run):
    path = run.evidence / "SHA256SUMS"
    found = {}
    for line in bounded_bytes(path, TURN_LOG_BYTES).decode("utf-8").splitlines() if path.is_file() else []:
        digest, _, name = line.partition("  ")
        found[name] = digest
    return found


def ownership(run, home=None, label="codex_home"):
    mark = (run.codex_home if home is None else home) / OWNER_MARK
    if not mark.is_file() or mark.is_symlink():
        refuse("%s was kept: it has no %s mark, so this run did not make it" % (label, OWNER_MARK))
    record = read_json(mark)
    if not isinstance(record, dict) or record.get("run") != str(run.run) or record.get("initiative") != run.id:
        refuse("%s was kept: ownership record does not match this run" % label)


def check_codex_purge(run):
    safe_codex_home(run)
    if not run.codex_home.exists():
        return False
    ownership(run)
    sessions, copies, sums = run.codex_home / "sessions", run.evidence / "codex-sessions", parsed_sums(run)
    for path in sorted(sessions.rglob("*")) if sessions.is_dir() else []:
        if path.is_dir() and not path.is_symlink():
            continue
        relative = path.relative_to(sessions)
        copy = copies / relative
        if path.is_symlink() or not path.is_file():
            refuse("codex_home was kept: sessions/%s is not a regular file" % relative)
        if not copy.is_file() or copy.is_symlink() or run.codex_home.resolve() in copy.resolve().parents:
            refuse("codex_home was kept: sessions/%s has no copy in evidence/codex-sessions" % relative)
        digest = sha_file(path)
        if sha_file(copy) != digest:
            refuse("codex_home was kept: the copy of sessions/%s in evidence/codex-sessions does not match it" % relative)
        if sums.get("codex-sessions/%s" % relative) != digest:
            refuse("codex_home was kept: SHA256SUMS does not list the copy of sessions/%s with its hash" % relative)
    return True


def check_claude_purge(run):
    """Check Claude ownership and transcript retention before either host home is deleted."""
    safe_claude_home(run)
    if not run.claude_home.exists():
        return False
    ownership(run, run.claude_home, "claude_home")
    # Until down copies projects/ to evidence (T2(a) PR 6, in collect), a transcript there would be lost, so a home
    # holding any is kept.
    projects = run.claude_home / "projects"
    if os.path.lexists(projects) and (projects.is_symlink() or not projects.is_dir() or any(projects.iterdir())):
        refuse("claude_home was kept: projects/ holds transcripts, which down copies to evidence from T2(a) PR 6")
    return True


def purge(run):
    if not check_codex_purge(run):
        return "already_purged"
    shutil.rmtree(run.codex_home)
    return "purged"


def purge_claude(run):
    """Deletes claude_home, the run's Claude login, under purge's ownership rules."""
    if not check_claude_purge(run):
        return "already_purged"
    shutil.rmtree(run.claude_home)
    return "purged"


def down(run, args):
    require(args.loop_wait >= 1, "--loop-wait must be at least 1 second")
    for host, adapter in OWNER_ADAPTERS.items():
        flag = adapter["purge_flag"]
        if getattr(args, flag) and not run.uses(host):
            refuse("--%s requires a plan that uses %s" % (flag.replace("_", "-"), host))
    if run.transactional and load_state(run) is not None:
        with login_lock(run, busy_message="a login is in progress"):
            return down_run(run, args)
    return down_run(run, args)


def down_run(run, args):
    state = load_state(run)
    if state is None:
        return OK, {"state": "nothing to take down: init has not run in %s" % run.run}

    pending, problems = custody_inspection(run, state)
    if problems:
        fail("owner custody is unavailable; resources retained; inspect status before down",
             custody_errors=problems, operations=pending, next_action=CUSTODY_RECOVERY)
    if pending:
        fail("unresolved model operations retain this run's resources; inspect status and reconcile before down",
             operations=pending)

    def persist():
        if run.transactional:
            return update_state(run, lambda current: current.update(down=state["down"]))
        save_state(run, state)
        return state

    done = state.setdefault("down", {"done": {}})["done"]
    state["down"].setdefault("started_at", timestamp())
    state = persist()
    answer = {"loop": stop_loop(run, args.loop_wait), "roles": stop_roles(run)}
    if "evidence" in done:
        answer["evidence"] = "already_collected"
    else:
        answer["evidence"] = collect(run, state)
        done["evidence"] = {"at": timestamp(), **answer["evidence"]}
        state = persist()
    if state["init"].get("pending"):
        fail("init has an unresolved outcome; resources were kept for inspection")
    if "workspace" in state["init"]["steps"] and (not run.store.is_dir() or not run.recipes.is_file()):
        fail("job cleanup inputs are unavailable; resources were kept for inspection")
    if run.store.is_dir() and run.recipes.is_file():
        cleaned = checked(run, "jobs clean", "jobs", "--store", run.store, "--recipes", run.recipes, "clean",
                          "--initiative", run.id, "--finished")
        if (not isinstance(cleaned.get("jobs"), list) or not isinstance(cleaned.get("not_finished"), list)
                or any(not isinstance(row, str) for row in cleaned["not_finished"])):
            fail("jobs clean returned invalid completion evidence; resources were kept for inspection")
        answer["jobs"] = {"cleaned": len(cleaned["jobs"]), "not_finished": cleaned["not_finished"]}
        if cleaned.get("not_finished"):
            fail("unfinished jobs retain this run's leases, slots and worktrees", jobs=answer["jobs"])
    answer["leases"] = release_leases(run, state)
    answer["slots"] = release_slots(run, state)
    answer["worktrees"] = remove_worktrees(run, state)
    answer["review_copies"] = remove_review_copies(run)
    if run.evidence.is_dir():
        answer["sha256sums"] = write_sums(run)
    # Validate every requested home before deleting either: one host's refusal must keep both homes intact.
    for host, adapter in active_adapters(run):
        if getattr(args, adapter["purge_flag"]):
            adapter["purge_check"](run)
    for host, adapter in active_adapters(run):
        answer[adapter["home_attribute"]] = adapter["purge"](run) if getattr(args, adapter["purge_flag"]) else "kept"
    done["last"] = timestamp()
    state = persist()
    return OK, answer


COMMANDS = {"init": init, "login": login, "root": root, "up": up, "request": request, "approve": approve, "turn": turn,
            "status": status, "down": down}


def log_command(run, command, code):
    try:
        # Logging is best effort and must not follow an accidentally redirected run after an init refusal.
        revalidate_run(run)
        with open(run.commands_log, "a", encoding="utf-8") as stream:
            stream.write(json.dumps({"command": command, "exit": code, "at": timestamp()}, sort_keys=True) + "\n")
    except (Stop, OSError):
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True, help="Absolute path to team-run.json (aegis.team-run/v1 or v2)")
    commands = parser.add_subparsers(dest="command", required=True)
    started = commands.add_parser("init", help="Every non-model setup step: recipes, store, provision, journal, "
                                               "worktrees, slots, leases and the preflight")
    started.add_argument("--continue", dest="resume", action="store_true", help="Resume a failed init at its first "
                                                                               "incomplete step")
    commands.add_parser("login", help="Log in each host the plan uses in the run's own home (codex login in "
                                      "CODEX_HOME, claude auth login in CLAUDE_CONFIG_DIR), then check it")
    bound = commands.add_parser("root", help="Bind the owner's existing ROOT session with its decision connection")
    bound.add_argument("--session", required=True)
    raised = commands.add_parser("up", help="Write team.json, start the roles in order, check each, start the loop")
    raised.add_argument("--accept-agent-tools", action="store_true",
                        help="Keep a role that was offered Codex sub-agent tools; recorded in evidence")
    raised.add_argument("--no-loop", action="store_true", help="Start the roles only; run loop passes yourself")
    asked = commands.add_parser("request", help="Publish a canonical request as the coordinator")
    asked.add_argument("id")
    asked.add_argument("--file", required=True, help="A team_request draft, or the request's fields")
    decided = commands.add_parser("approve", help="One ROOT turn that decides the pending request, then a journal check")
    decided.add_argument("id")
    decided.add_argument("--deny", action="store_true")
    decided.add_argument("--reason")
    decided.add_argument("--reconcile", action="store_true", help="Reconcile the unresolved ROOT turn without replaying it")
    owned = commands.add_parser("turn", help="One trusted owner turn with the role's current wake argv")
    owned.add_argument("endpoint")
    owned.add_argument("prompt", nargs="?")
    owned.add_argument("--reconcile", action="store_true", help="Reconcile this endpoint's unresolved turn without replaying it")
    commands.add_parser("status", help="Team view, loop liveness and launcher records").add_argument(
        "--text", action="store_true", help="Holds grouped by who must act, and pending ROOT decisions")
    lowered = commands.add_parser("down", help="Collect evidence, then stop and release everything the run holds")
    lowered.add_argument("--purge-codex-home", action="store_true",
                         help="Delete codex_home once every session file has a verified copy in evidence")
    lowered.add_argument("--purge-claude-home", action="store_true",
                         help="Delete claude_home, the run's Claude login, once its owner mark is checked")
    lowered.add_argument("--loop-wait", type=int, default=LOOP_WAIT_SECONDS,
                         help="Seconds to wait for the loop to stop after SIGTERM (default %d)" % LOOP_WAIT_SECONDS)
    args = parser.parse_args(argv)
    run = None
    record_command = True
    try:
        run = Run(args.config)
        try:
            state = load_state(run)
        except (ValueError, OSError) as exc:
            if args.command != "status":
                raise
            state = None
            run.state_error = str(exc)
            run.state_problem = {"error": str(exc), **(exc.problem if isinstance(exc, CustodyProblem) else {})}
        run.inspected_state = state
        if args.command != "status" and state and "custody" in state and state["custody"] != custody(run):
            refuse("run custody changed since init; restore the recorded configuration")
        guard(run, args.command)
        # All direct state writers on an initialized Codex-only run share the stable directory lock. Claude
        # login/up merge through short state transactions instead, keeping browser-login ROOT concurrency.
        serialized = args.command in ("init", "root", "approve", "turn", "down") or (
            not run.transactional and args.command == "up")
        if serialized and run.run.is_dir():
            busy = {"login": "another login is running for this run", "down": "a login is in progress"}
            with operation_lock(run, busy.get(args.command, "another team command is running for this run")):
                code, result = COMMANDS[args.command](run, args)
        else:
            code, result = COMMANDS[args.command](run, args)
    except Stop as stop:
        code, result = stop.code, {"error": str(stop), **stop.detail}
        record_command = stop.record_command
    except CustodyProblem as exc:
        code, result = REFUSED, {"error": str(exc), **exc.detail()}
    except (ValueError, KeyError, TypeError, UnicodeError, RecursionError, OverflowError, AttributeError) as exc:
        code, result = REFUSED, {"error": str(exc)}
    except (OSError, subprocess.SubprocessError) as exc:
        code, result = FAILED, {"error": str(exc)}
    if code != REFUSED and record_command and run is not None and args.command != "status" and run.run.is_dir():
        try:
            environment_evidence(run)
        except (ValueError, OSError, RecursionError, TypeError, AttributeError) as exc:
            problem = exc.problem if isinstance(exc, CustodyProblem) else {"record": "child-environment.json", "reason": "finalisation", "error": str(exc)}
            code, result = FAILED, {"error": "child environment evidence failed: %s; command effects were retained" % exc,
                                    "partial_result": result, "finalisation_error": problem}
        log_command(run, args.command, code)
    if result is not None:
        print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
