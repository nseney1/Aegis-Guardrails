"""Legacy host values with fixed, non-echoing reason/code/next_action refusals.
Argv: MAX_ARGV_ATOMS=128, MAX_ARGV_ATOM_CHARS=32768, MAX_ARGV_CHARS=131072; overflow
selects HOLD, or refuses too_large during discovery. Events: MAX_EVENT_BYTES=262144
per received line/item, MAX_STREAM_BYTES=262144 per complete text/bytes input and
MAX_EVENTS_PER_STREAM=10000 physical lines/items (blank/malformed count; terminal
newline adds no item). Readline is capped at MAX_EVENT_BYTES+1 input units (bytes
for binary, characters for text), then size-checked before decoding/parsing. Plain
iterator/list items are caller-materialised, size-checked before use, not read-bounded.
In-bound JSON keeps legacy semantics. Sizes use raw bytes or str UTF-8/surrogatepass.
Overflow refuses too_large, code 1. Discovery: MAX_TRANSCRIPT_ENTRIES=10000,
MAX_TRANSCRIPT_DEPTH=128, MAX_ROOT_CHARS=32768 before Path allocation (unsafe_path).
Transcript discovery holds descriptors; returned names grant no reopening authority.
"""
from __future__ import annotations

from functools import wraps
from fnmatch import fnmatchcase
from io import BytesIO, StringIO
import errno
import json
import os
from pathlib import Path
import re

from aegis_core.storage import confined_descriptor_supported as storage_descriptor_supported
from aegis_core.team_mailbox_primitives import MAX_BYTES, MAX_RECORDS, MailboxRefusal

__all__ = [
    "MAX_BYTES", "MAX_RECORDS", "MAX_ARGV_ATOMS", "MAX_ARGV_ATOM_CHARS", "MAX_ARGV_CHARS",
    "MAX_EVENT_BYTES", "MAX_STREAM_BYTES", "MAX_EVENTS_PER_STREAM", "MAX_TRANSCRIPT_ENTRIES",
    "MAX_TRANSCRIPT_DEPTH", "MAX_ROOT_CHARS", "HostRefusal", "guarded", "require", "SCHEMA", "CLAUDE",
    "CODEX", "NATIVE", "HOST_KINDS", "SESSION", "SESSION_UUID", "SESSION_UUID_OCCURRENCE",
    "CODEX_TRANSCRIPTS", "HOST_ENVIRONMENT", "CODEX_BILLING", "CLAUDE_SESSION_VARIABLE",
    "CODEX_SESSION_VARIABLE", "CODEX_SESSION_MARKERS", "CLAUDE_USAGE_KEYS", "CODEX_USAGE_KEYS",
    "CLAUDE_INIT_KEYS", "CLAUDE_AUTH_KEYS", "CLAUDE_AUTH_TYPES", "READER_SCOPE", "TEAM_HOSTS",
    "NODE_ARITIES", "CODEX_STOP_OPTIONS", "CLAUDE_STOP_FLAGS", "CLAUDE_STOP_VALUES", "entry", "describe",
    "child_environment", "family", "entrypoints", "matches_entrypoint", "session_verdict", "names_session",
    "matches_session", "descendant_verdict", "selects_other_session", "qualify", "billing_set",
    "descriptor_supported", "transcripts", "claude_events", "claude_init", "claude_usage", "codex_usage",
    "claude_turn_items", "claude_auth_check",
]

MAX_ARGV_ATOMS = 128
MAX_ARGV_ATOM_CHARS = 32768
MAX_ARGV_CHARS = 131072
MAX_EVENT_BYTES = MAX_BYTES
MAX_STREAM_BYTES = MAX_BYTES
MAX_EVENTS_PER_STREAM = MAX_RECORDS
MAX_TRANSCRIPT_ENTRIES = MAX_RECORDS
MAX_TRANSCRIPT_DEPTH = 128
MAX_ROOT_CHARS = 32768
_ABSENT = object()

_NEXT = {
    "unknown_host": "Choose a declared host kind.",
    "invalid_purpose": "Choose no-host or host-cli environment policy.",
    "unqualified_host": "Choose a host qualified for the requested role.",
    "invalid_session": "Supply a bounded session identifier without glob characters.",
    "invalid_record": "Correct the input against the host or session schema.",
    "too_large": "Reduce the input to the documented byte, node or entry limit.",
    "unsupported_platform": "Use descriptor-relative no-follow filesystem support.",
    "unsafe_path": "Use regular files and directories below the trusted absolute root.",
    "io": "Restore storage availability and retry the read.",
    "invalid_json": "Restore bounded, finite, duplicate-free UTF-8 JSON.",
    "plan_keys": "Supply exactly the six documented host-plan keys.",
    "plan_schema": "Use the aegis.hierarchy-host-plan/v1 schema.",
    "invalid_plan": "Correct the hierarchy, hosts, stand-ins and config digest.",
    "hierarchy_mismatch": "Choose the plan for this hierarchy.",
    "plan_mismatch": "Reconcile the base and mailbox plans before binding.",
    "host_mismatch": "Use the host assigned to the endpoint by the plan.",
    "endpoint_mismatch": "Choose an endpoint covered by the plan.",
    "session_mismatch": "Reconcile the retained session record before retrying.",
}


class HostRefusal(ValueError):
    """Fixed operational refusal, exit code 1, with an actionable recovery."""
    def __init__(self, reason):
        self.reason, self.code, self.status = reason, 1, "refused"
        self.next_action = _NEXT[reason]
        super().__init__("host refused: " + reason)

    def as_dict(self):
        return {"status": self.status, "reason": self.reason,
                "next_action": self.next_action, "code": self.code}


def guarded(function):
    """Normalize schema and I/O errors without echoing input or OS messages."""
    # These public functions have fixed positional-or-keyword parameters.
    names = function.__code__.co_varnames[:function.__code__.co_argcount]
    required = len(names) - len(function.__defaults__ or ())
    @wraps(function)
    def call(*args, **kwargs):
        require(len(args) <= len(names) and len(kwargs) <= len(names))
        require(all(name in names for name in kwargs))
        require(not any(name in kwargs for name in names[:len(args)]))
        require(all(name in kwargs for name in names[len(args):required]))
        try:
            return function(*args, **kwargs)
        except HostRefusal:
            raise
        except OSError as error:
            reason = "unsafe_path" if error.errno in (errno.ELOOP, errno.ENOTDIR) else "io"
            raise HostRefusal(reason) from None
        except MailboxRefusal as error:
            raise HostRefusal("too_large" if error.reason == "too_large" else "invalid_record") from None
        except (ValueError, KeyError, IndexError, AttributeError, RecursionError, OverflowError):
            raise HostRefusal("invalid_record") from None
    return call


def require(condition, message="", *, reason="invalid_record"):
    # Legacy labels are accepted only for pure internal calls, never displayed.
    if not condition:
        raise HostRefusal(reason)


def _iterable_shape(value):
    operation = getattr(type(value), "__iter__", _ABSENT)
    return (callable(operation) if operation is not _ABSENT else
            callable(getattr(type(value), "__getitem__", None)))


def _input_items(value):
    require(_iterable_shape(value))
    operation = getattr(value, "__iter__", _ABSENT)
    if operation is _ABSENT:
        index = 0
        while True:
            try:
                item = value[index]
            except (IndexError, StopIteration):
                return
            yield item
            index += 1
    else:
        require(callable(operation))
        cursor = operation()
        require(callable(getattr(type(cursor), "__next__", None)))
        while True:
            try:
                item = next(cursor)
            except StopIteration:
                return
            yield item


def _environment_items(value):
    operation = getattr(value, "items", None)
    require(callable(operation))
    for item in _input_items(operation()):
        require(_iterable_shape(item))
        key, content = _input_items(item)
        require(isinstance(key, str))
        yield key, content


def _contains(value, member):
    operation = getattr(type(value), "__contains__", _ABSENT)
    if operation is _ABSENT:
        return any(item == member for item in _input_items(value))
    require(callable(operation) and not isinstance(value, (bytes, bytearray)))
    return bool(operation(value, member))


def _home_value(value):
    if isinstance(value, (str, bytes)):
        return value
    operation = getattr(type(value), "__fspath__", None)
    require(callable(operation))
    result = operation(value)
    require(isinstance(result, (str, bytes)))
    return result


SCHEMA = "aegis.hierarchy-host-registry/v1"
CLAUDE = "claude-code"
CODEX = "codex-cli"
NATIVE = "codex"
HOST_KINDS = (CLAUDE, CODEX, NATIVE)
# Sessions go into glob patterns, so anything that could widen one is refused. Same pattern as hierarchy_provision.
SESSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
# UUID-shaped conflicts are distinct from the wider legacy session names accepted by provision.
SESSION_UUID = re.compile(r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
                          r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})")
# Sparing descendants may inspect embedded IDs, including modelled short options. Never use this as ownership
# evidence. Hex boundaries avoid finding a compact UUID inside a longer hash; a short option may be a hex letter.
SESSION_UUID_OCCURRENCE = re.compile(r"(?:(?<![0-9a-fA-F])|(?<=-[A-Za-z]))" + SESSION_UUID.pattern +
                                     r"(?![0-9a-fA-F])")
CODEX_TRANSCRIPTS = ("sessions/**/rollout-*{session}.jsonl", "archived_sessions/**/rollout-*{session}.jsonl")


# Retained v1 projection of the host environment catalog. Omit common Aegis
# markers, auth overrides and prefix-covered names; parity tests preserve it.
_CLAUDE_ENVIRONMENT = {
    "billing_variables": ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
                          "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"),
    "session_variable": {"name": "CLAUDE_CODE_SESSION_ID", "verified_for_mcp": False},
    "session_markers": {"names": ("CLAUDECODE", "CLAUDE_PID", "CLAUDE_EFFORT"), "prefixes": ("CLAUDE_CODE_",)}}
_CODEX_ENVIRONMENT = {
    "billing_variables": ("OPENAI_API_KEY", "CODEX_API_KEY"),
    "session_variable": {"name": "CODEX_THREAD_ID", "verified_for_mcp": False},
    "session_markers": {"names": ("CODEX_APPLY_PATCH_PRESERVE_LINE_ENDINGS", "CODEX_CI",
                                  "CODEX_SANDBOX_NETWORK_DISABLED", "CODEX_SESSION_ID", "CODEX_THREAD_ID",
                                  "CODEX_TOOL_CALL_ID", "CODEX_VERSION"), "prefixes": ()}}
_GEMINI_ENVIRONMENT = {
    "billing_variables": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    "session_variable": {"name": "", "verified_for_mcp": False},
    "session_markers": {"names": (), "prefixes": ()}}
_EMPTY_ENVIRONMENT = {
    "billing_variables": (), "session_variable": {"name": "", "verified_for_mcp": False},
    "session_markers": {"names": (), "prefixes": ()}}
HOST_ENVIRONMENT = {
    CODEX: _CODEX_ENVIRONMENT,
    CLAUDE: _CLAUDE_ENVIRONMENT,
    "claude-desktop": _CLAUDE_ENVIRONMENT,
    "antigravity": _GEMINI_ENVIRONMENT,
    "gemini-cli": _GEMINI_ENVIRONMENT,
    "kiro": _EMPTY_ENVIRONMENT,
    "cursor": _EMPTY_ENVIRONMENT,
    "copilot": _EMPTY_ENVIRONMENT,
    "windsurf": _EMPTY_ENVIRONMENT,
    NATIVE: _CODEX_ENVIRONMENT,
}
# Retained public aliases use the same projection as the legacy registry.
CODEX_BILLING = _CODEX_ENVIRONMENT["billing_variables"]
CLAUDE_SESSION_VARIABLE = _CLAUDE_ENVIRONMENT["session_variable"]
CODEX_SESSION_VARIABLE = _CODEX_ENVIRONMENT["session_variable"]
CODEX_SESSION_MARKERS = _CODEX_ENVIRONMENT["session_markers"]
CLAUDE_USAGE_KEYS = ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens")
CODEX_USAGE_KEYS = ("input_tokens", "cached_input_tokens", "output_tokens")
CLAUDE_INIT_KEYS = (("session_id", "session_id"), ("tools", "tools"), ("model", "model"),
                    ("permission_mode", "permissionMode"), ("api_key_source", "apiKeySource"),
                    ("version", "claude_code_version"), ("mcp_servers", "mcp_servers"))
# The real status also carries email, orgId, orgName, planTier, subscriptionType and storedClaudeAiLogin. Evidence
# must not hold account identity, so only these keys are recorded.
CLAUDE_AUTH_KEYS = ("loggedIn", "authMethod", "apiProvider", "configDirectory", "projectsDirectory", "loginExpiresAt")
# Exact types, so a retained key cannot smuggle identity inside a nested value (and bool is not an int here).
CLAUDE_AUTH_TYPES = {"loggedIn": (bool,), "authMethod": (str,), "apiProvider": (str,), "configDirectory": (str,),
                     "projectsDirectory": (str,), "loginExpiresAt": (str, int, type(None))}
READER_SCOPE = {"boundary": "no write tools"}
# A team run starts its sessions itself, so native threads (owner-created) are no team host.
TEAM_HOSTS = (CLAUDE, CODEX)
NODE_ARITIES = {"--loader": 1, "--experimental-loader": 1, "--import": 1, "-r": 1, "--require": 1,
                "--env-file": 1, "--conditions": 1, "-C": 1, "--title": 1, "--input-type": 1,
                "--no-warnings": 0, "--trace-warnings": 0}
# Closed stop grammar, bounded by Codex rust-v0.167.0 (086ccc833bc9cf01024ad2dd6af7dbd421b6bf9a):
# G: cli/src/main.rs:127-141, tui/src/cli.rs:66-67,128-135; E: exec/src/cli.rs:15-25;
# R: exec/src/cli.rs:172-175,205-234. No claim of complete installed-host CLI support.
# names, admitted stages, arity, repeatable, value validator. Aliases share one occurrence counter.
_SHORT_OPTION_NAMES = {"config": "c", "model": "m", "continue": "c"}


def _short_option(name):
    """Render a declared option name; catalog metadata is not a process argv."""
    return "-" + _SHORT_OPTION_NAMES[name]


CODEX_STOP_OPTIONS = (
    ((_short_option("config"), "--config"), ("G", "E", "R"), 1, True, "config"),  # utils/cli/src/config_override.rs:29-71
    (("--enable",), ("G", "E", "R"), 1, True, "atom"),  # cli/src/main.rs:958-965
    (("--disable",), ("G", "E", "R"), 1, True, "atom"),
    (("--model", _short_option("model")), ("G", "E", "R"), 1, False, "atom"),  # shared_options.rs:21-23
    (("--sandbox", "-s"), ("G", "E"), 1, False, "sandbox"),  # shared_options.rs:38-41
    (("--cd", "-C"), ("G", "E"), 1, False, "atom"),  # shared_options.rs:66-68
    (("--add-dir",), ("G", "E"), 1, True, "atom"),  # shared_options.rs:74-76
    (("--profile", "-p"), ("G", "E"), 1, False, "atom"),  # shared_options.rs:34-36
    (("--output-last-message", "-o"), ("E", "R"), 1, False, "atom"),  # exec/src/cli.rs:72-79
    (("--output-schema",), ("E", "R"), 1, False, "atom"),  # exec/src/cli.rs:52-54
    (("--json", "--experimental-json"), ("E", "R"), 0, False, None),  # exec/src/cli.rs:63-70
    (("--ignore-user-config",), ("E", "R"), 0, False, None),  # exec/src/cli.rs:44-46
    (("--skip-git-repo-check",), ("E", "R"), 0, False, None),  # exec/src/cli.rs:36-38
)
# Claude's emitted forms: hierarchy_provision.claude_argv; additional retained vocabulary is modelled.
CLAUDE_STOP_FLAGS = (("--restricted",), ("--strict-mcp-config",), ("--print", "-p"), ("--verbose",),
                     ("--disable-slash-commands",), ("--bg",))
CLAUDE_STOP_VALUES = ("--mcp-config", "--permission-mode", "--permission-prompts", "--output-format", "--name",
                      "--model", "--effort", "--settings", "--add-dir", "--agents", "--disallowedTools",
                      "--allowedTools", "--input-format", "--system-prompt", "--append-system-prompt", "--agent",
                      "--plugin-dir")

_HOSTS = {
    CLAUDE: {
        "family": "claude",
        "entrypoints": {"program_basenames": ("claude", "claude.exe", ".claude-wrapped"),
                        "node_script_basenames": ("claude", ".claude-wrapped"),
                        "node_script_suffixes": ("@anthropic-ai/claude-code/cli.js",),
                        "node_option_arities": NODE_ARITIES},
        "session_selectors": {"options": ("--resume", "--session-id"), "commands": (),
                              "grammar": {"family": "claude", "stage": "C", "flags": CLAUDE_STOP_FLAGS,
                                          "split_one": CLAUDE_STOP_VALUES, "equals_one": ("--tools",),
                                          "repeatable": ("--add-dir", "--plugin-dir"),
                                          "exclusive_modes": ("--print", "--bg")},
                              "conflicting_flags": (), "fork_flag": "--fork-session",
                              "continue_flags": ("--continue", _short_option("continue")),
                              "value_options": ("--model", "--settings", "--permission-mode", "--output-format",
                                                "--input-format", "--system-prompt", "--append-system-prompt",
                                                "--mcp-config", "--agent", "--agents", "--tools", "--allowedTools",
                                                "--disallowedTools", "--add-dir", "--plugin-dir"),
                              "prompt_options": ("-p", "--print")},
        "team_start": "print",
        "home": {"variable": "CLAUDE_CONFIG_DIR", "run_folder": "claude-home", "owner_folder": ".claude"},
        "billing_variables": _CLAUDE_ENVIRONMENT["billing_variables"],
        "session_variable": CLAUDE_SESSION_VARIABLE,
        "session_markers": _CLAUDE_ENVIRONMENT["session_markers"],
        "transcripts": ("projects/*/{session}.jsonl",),
        "usage": "claude-stream-json-result",
        "write_scope": {"boundary": "permission rules, not OS-enforced", "mechanism": "claude --restricted",
                        "os_enforced": False, "owner_decision": "teams 2026-11-07 decision 4",
                        "ends_when": "T2(b) qualifies an OS-enforced Claude write scope"},
        "qualification": {"reader": "allowed", "writer": "weaker-boundary"},
    },
    CODEX: {
        "family": "codex",
        "entrypoints": {"program_basenames": ("codex",), "node_script_basenames": ("codex", "codex.js"),
                        "node_script_suffixes": (), "node_option_arities": NODE_ARITIES},
        "session_selectors": {"options": (), "commands": (("resume",), ("exec", "resume")),
                              "grammar": {"family": "codex", "options": CODEX_STOP_OPTIONS, "exec": "exec", "resume": "resume"},
                              "conflicting_flags": (),
                              "value_options": (_short_option("config"), "--config", "--disable", "--enable", "--sandbox", "-s",
                                                "-C", "--cd", "--add-dir", "--model", _short_option("model"), "--profile", "-p",
                                                "--output-last-message", "-o", "--output-schema"),
                              "prompt_options": ()},
        "team_start": "exec",
        "home": {"variable": "CODEX_HOME", "run_folder": "codex-home", "owner_folder": ".codex"},
        "billing_variables": CODEX_BILLING,
        "session_variable": CODEX_SESSION_VARIABLE,
        "session_markers": CODEX_SESSION_MARKERS,
        "transcripts": CODEX_TRANSCRIPTS,
        "usage": "codex-token-count",
        # Unknown until T2(b) qualifies it: rule 6 reports what no run has shown as unknown, never as true.
        "write_scope": {"boundary": "OS sandbox, qualification pending T2(b)",
                        "mechanism": "codex sandbox writable_roots", "os_enforced": None},
        "qualification": {"reader": "allowed", "writer": "allowed"},
    },
    # Native threads are owner-created in the owner's shared app-server home: bind and status only, and team runs
    # start none, so every role is refused.
    NATIVE: {
        "family": "codex",
        "entrypoints": {"program_basenames": (), "node_script_basenames": (), "node_script_suffixes": (),
                        "node_option_arities": {}},
        "session_selectors": {"options": (), "commands": (), "value_options": (), "prompt_options": (),
                              "conflicting_flags": ()},
        "team_start": None,
        "home": {"variable": "CODEX_HOME", "run_folder": None, "owner_folder": ".codex"},
        "billing_variables": CODEX_BILLING,
        "session_variable": CODEX_SESSION_VARIABLE,
        "session_markers": CODEX_SESSION_MARKERS,
        "transcripts": CODEX_TRANSCRIPTS,
        "usage": None,
        "write_scope": None,
        "qualification": {"reader": "refused", "writer": "refused"},
    },
}


def _host(kind):
    if not isinstance(kind, str) or kind not in _HOSTS:
        raise HostRefusal("unknown_host")
    return _HOSTS[kind]


@guarded
def entry(kind):
    # A JSON round trip is the deep copy, and it gives entry() and describe() one form: lists, never tuples.
    return json.loads(json.dumps({"kind": kind, **_host(kind)}))


@guarded
def describe():
    return {"schema": SCHEMA, "hosts": {kind: entry(kind) for kind in HOST_KINDS}}


@guarded
def child_environment(environ, purpose):
    """Copy a child environment without inherited host sessions, and optionally without billing variables."""
    if purpose not in ("no-host", "host-cli"):
        raise HostRefusal("invalid_purpose")
    names, prefixes = set(), []
    # Include every projected row, even hosts the legacy launcher cannot run. Keep
    # describe() consumers in this union so extensions to that surface still scrub.
    for host in (*describe()["hosts"].values(), *HOST_ENVIRONMENT.values()):
        if host["session_variable"]["name"]:
            names.add(host["session_variable"]["name"])
        names.update(host["session_markers"]["names"])
        prefixes.extend(host["session_markers"]["prefixes"])
        if purpose == "no-host":
            names.update(host["billing_variables"])
    if os.name == "nt":
        names = {name.upper() for name in names}
        prefixes = [prefix.upper() for prefix in prefixes]
    prefixes = tuple(prefixes)
    return {key: value for key, value in _environment_items(environ)
            if (key.upper() if os.name == "nt" else key) not in names
            and not (key.upper() if os.name == "nt" else key).startswith(prefixes)}


@guarded
def family(kind):
    return _host(kind)["family"]


@guarded
def entrypoints(kind):
    """Process entrypoints as JSON data, or an explicit refusal for a host with none."""
    found = entry(kind)["entrypoints"]
    require(any(found.values()), "%s has no process entrypoints" % kind)
    return found


def _host_arguments(kind, argv, strict=False):
    """Host arguments after env and an optional Node interpreter, or None for another program."""
    found = _host(kind)["entrypoints"]
    require(any(found.values()), "%s has no process entrypoints" % kind)
    if not _bounded_arguments(argv):
        return False if strict else None
    if argv and Path(argv[0]).name == "env":
        argv = argv[1:]
        while argv and re.match(r"[A-Za-z_][A-Za-z0-9_]*=", argv[0]):
            argv = argv[1:]
        if strict and (not argv or argv[0].startswith("-")):
            return False
    if not argv:
        return None
    program = Path(argv[0]).name
    if program in found["program_basenames"]:
        return argv[1:]
    if program != "node" or len(argv) < 2:
        return None
    index = 1
    while index < len(argv) and argv[index].startswith("-"):
        word = argv[index]
        option, equal, _ = word.partition("=")
        index += 1
        if option == "--":
            break
        if option in ("--eval", "--print") or word.startswith(("-e", "-p")):
            return None  # These execute source text rather than a host script.
        if not equal:
            arity = found["node_option_arities"].get(option)
            if arity is None:
                return False if strict else None
            if strict and arity and (index >= len(argv) or not argv[index] or argv[index].startswith("-")):
                return False
            index += arity
        elif strict and (option not in found["node_option_arities"] or found["node_option_arities"][option] != 1 or
                         not word.partition("=")[2]):
            return False  # An entrypoint name alone does not admit an unknown interpreter option.
    if index >= len(argv):
        return None
    script = Path(argv[index])
    if script.name in found["node_script_basenames"] or any(
            script.parts[-len(Path(suffix).parts):] == Path(suffix).parts for suffix in found["node_script_suffixes"]):
        return argv[index + 1:]
    return None


def _bounded_arguments(argv):
    # Bound the container and atoms before slicing or parsing complete arguments.
    if type(argv) not in (list, tuple) or len(argv) > MAX_ARGV_ATOMS:
        return False
    total = 0
    for word in argv:
        if type(word) is not str or len(word) > MAX_ARGV_ATOM_CHARS or "\x00" in word:
            return False
        total += len(word)
        if total > MAX_ARGV_CHARS:
            return False
    return True


@guarded
def matches_entrypoint(kind, argv):
    """Whether argv names one of this host's declared programs or node-run scripts."""
    return _host_arguments(kind, argv) is not None


def _uuid_values(arguments):
    for argument in arguments:
        for word in argument.split():
            value = word.split("=", 1)[-1]
            if SESSION_UUID.fullmatch(value):
                yield value


def _selector_value(value, session):
    """Classify a complete selector value identically for ownership and descendant refusal."""
    if value is None or not value or value.startswith("-"):
        return "ambiguous"
    if value == session:
        return "bound"
    return "other" if SESSION_UUID.fullmatch(value) else "unknown"


def _stop_option(catalog, arguments, index, stage, seen):
    """Consume one declared option and one opaque value atom; an invalid transition stays HOLD."""
    word = arguments[index]
    row = next((row for row in catalog if word in row[0]), None)
    if row is None:
        return None
    names, stages, arity, repeatable, validator = row
    if stage not in stages or (not repeatable and names[0] in seen):
        return None
    seen.add(names[0])
    if arity:
        if index + 1 >= len(arguments):
            return None
        value = arguments[index + 1]
        if not value or value.startswith("-"):
            return None
        if validator == "config" and (not value.partition("=")[0] or not value.partition("=")[1] or
                                      not value.partition("=")[2]):
            return None
        if validator == "sandbox" and value not in ("read-only", "workspace-write", "danger-full-access"):
            return None
    return index + 1 + arity


def _codex_selection(selectors, arguments, session):
    grammar, stage, index, seen = selectors["grammar"], "G", 0, set()
    while stage in ("G", "E"):
        if index == len(arguments):
            return "NOT_OWNED" if stage == "E" else "HOLD"
        word = arguments[index]
        if word.startswith("-"):
            after = _stop_option(grammar["options"], arguments, index, stage, seen)
            if after is None:
                return "HOLD"
            index = after
        elif stage == "G" and word == grammar["exec"]:
            stage, index = "E", index + 1
        elif word == grammar["resume"]:
            stage, index = ("R" if stage == "E" else "DIRECT"), index + 1
        else:
            # Fresh exec has zero/one opaque prompt. A single "resume S" atom is never a command.
            return ("NOT_OWNED" if stage == "E" and index + 1 == len(arguments) else "HOLD")
    if stage == "R":
        while index < len(arguments) and arguments[index].startswith("-") and arguments[index] != "--":
            after = _stop_option(grammar["options"], arguments, index, "R", seen)
            if after is None:
                return "HOLD"
            index = after
    options = True
    if index < len(arguments) and arguments[index] == "--":
        options, index = False, index + 1
    value = arguments[index] if index < len(arguments) else None
    shape = _selector_value(value, session)
    if shape not in ("bound", "other"):
        return "HOLD"
    index += 1
    # The only remaining position is ONE owner prompt. Never scan its contents as another command/selector.
    if len(arguments) - index > 1:
        return "AMBIGUOUS_SESSION" if arguments[index] == grammar["resume"] else "HOLD"
    if index < len(arguments) and options and arguments[index].startswith("-") and arguments[index] != "-":
        return "HOLD"
    return "OWNED" if shape == "bound" else "NOT_OWNED"


def _claude_selection(selectors, arguments, session):
    grammar, index, options, prompts = selectors["grammar"], 0, True, 0
    seen, selected, explicit = set(), [], []
    forked, continued = False, False
    flags = {name: row[0] for row in grammar["flags"] for name in row}
    while index < len(arguments):
        word = arguments[index]
        if options and word == "--":
            options, index = False, index + 1
            continue
        if not options or not word.startswith("-"):
            prompts += 1
            if prompts > 1:
                return "HOLD"
            index += 1
            continue
        option, equal, value = word.partition("=")
        if option == selectors["fork_flag"]:
            if equal or forked:
                return "HOLD"
            forked = True
            index += 1
        elif option in selectors["continue_flags"]:
            if equal or continued:
                return "HOLD"
            continued = True
            index += 1
        elif option in selectors["options"]:
            if not equal:
                value = arguments[index + 1] if index + 1 < len(arguments) else None
            shape = _selector_value(value, session)
            if shape == "ambiguous":
                # A pending selector cannot consume a terminator or renew a previous S selection.
                return "AMBIGUOUS_SESSION" if "bound" in selected else "HOLD"
            selected.append(shape)
            if option == "--session-id":
                explicit.append(shape)
            index += 1 if equal else 2
        elif word in flags:
            canonical = flags[word]
            if canonical in seen:
                return "HOLD"
            seen.add(canonical)
            if all(mode in seen for mode in grammar["exclusive_modes"]):
                return "HOLD"
            index += 1
        elif option in grammar["equals_one"] and equal:
            if option in seen:
                return "HOLD"
            seen.add(option)  # --tools= is an actual builder shape, including its empty RHS.
            index += 1
        elif word in grammar["split_one"]:
            if word in seen and word not in grammar["repeatable"]:
                return "HOLD"
            seen.add(word)
            value = arguments[index + 1] if index + 1 < len(arguments) else None
            if not value or value.startswith("-"):
                return "HOLD"
            index += 2  # One complete opaque atom: prompts, quotes and UUIDs inside it are data.
        else:
            return "HOLD"
    # Fork creates the explicitly named session, not the source selected by resume/continue.
    # Defer source classification until all flags are read: either flag order is emitted by hosts.
    if forked:
        selected = explicit
    elif continued:
        return "HOLD"
    if any(shape not in ("bound", "other") for shape in selected):
        return "AMBIGUOUS_SESSION" if "bound" in selected else "HOLD"
    if "bound" in selected and "other" in selected:
        return "AMBIGUOUS_SESSION"
    return "OWNED" if selected and all(shape == "bound" for shape in selected) else "NOT_OWNED"


def _session_selection(kind, argv, session, argv_boundaries="proven"):
    """Internal reason distinguishes selector ambiguity from negative-only foreign UUID sparing."""
    selectors = _host(kind)["session_selectors"]
    if argv_boundaries != "proven":
        return "HOLD"
    if not isinstance(argv, (list, tuple)) or not all(isinstance(word, str) and "\0" not in word for word in argv):
        return "HOLD"
    arguments = _host_arguments(kind, argv, strict=True)
    if arguments is False:
        return "HOLD"
    if arguments is None:
        return "NOT_OWNED"
    family = selectors.get("grammar", {}).get("family")
    if family == "claude":
        return _claude_selection(selectors, arguments, session)
    if family == "codex":
        return _codex_selection(selectors, arguments, session)
    return "HOLD"


@guarded
def session_verdict(kind, argv, session, argv_boundaries="proven"):
    """Closed complete-atom grammar; flattened ps text never establishes first ownership."""
    if not _bounded_arguments(argv):
        return "HOLD"
    if kind is None:
        verdicts = [session_verdict(host, argv, session, argv_boundaries) for host in TEAM_HOSTS]
        return "OWNED" if "OWNED" in verdicts else "HOLD" if "HOLD" in verdicts else "NOT_OWNED"
    selection = _session_selection(kind, argv, session, argv_boundaries)
    return "HOLD" if selection == "AMBIGUOUS_SESSION" else selection


@guarded
def names_session(argv, session):
    """Discovery only: preserve whole atoms and conservatively notice glued UUID spellings too."""
    require(_bounded_arguments(argv), reason="too_large")
    if any(atom == session or any(word == session or word.partition("=")[2] == session
                                 for word in atom.split()) or
           any(found.group() == session for found in SESSION_UUID_OCCURRENCE.finditer(atom)) for atom in argv):
        return True
    # Only whole equals values with whitespace/embedded '=' can need the old ownership shortcut.
    # Unrelated rows never enter a host grammar; opaque diagnostic equals values keep their old result.
    return (any(atom.partition("=")[2] == session for atom in argv) and
            session_verdict(None, argv, session) == "OWNED")


@guarded
def matches_session(kind, argv, session, argv_boundaries="proven"):
    """Compatibility boolean: only an OWNED verdict permits signalling."""
    return session_verdict(kind, argv, session, argv_boundaries) == "OWNED"


@guarded
def descendant_verdict(argv, session):
    """Negative-only CLEAR/OTHER/HOLD: definite exclusion differs from unresolved selection."""
    if not _bounded_arguments(argv):
        return "HOLD"
    for kind in TEAM_HOSTS:
        selectors = _host(kind)["session_selectors"]
        arguments = _host_arguments(kind, argv, strict=True)
        if arguments is False:
            return "HOLD"
        if arguments is not None:
            selection = session_verdict(kind, argv, session)
            if selection == "OWNED":
                return "CLEAR"
            if selection == "HOLD":
                return "HOLD"
            # A message/job UUID is not another session. Reuse the complete ownership grammar to prove
            # that a validated host actually selects T, rather than treating a prompt/alias as exclusion.
            for word in arguments:
                for found in SESSION_UUID_OCCURRENCE.finditer(word):
                    if found.group() != session and session_verdict(kind, argv, found.group()) == "OWNED":
                        return "OTHER"
            return "HOLD"  # A separate host with no provable selector must not borrow parent authority.
    for kind in TEAM_HOSTS:
        selectors = _host(kind)["session_selectors"]
        # Unknown descendants may still carry a known ambiguous selector. This never establishes ownership.
        for index, word in enumerate(argv[1:], 1):
            option, equal, value = word.partition("=")
            if option in selectors["options"] or any(word == command[-1] for command in selectors["commands"]):
                if not equal:
                    value = argv[index + 1] if index + 1 < len(argv) else None
                    if value == "--" and selectors["commands"]:
                        value = argv[index + 2] if index + 2 < len(argv) else None
                if _selector_value(value, session) != "bound":
                    return "HOLD"
    return "CLEAR"


@guarded
def selects_other_session(argv, session):
    """Compatibility refusal predicate; neither OTHER nor HOLD grants borrowed ancestry authority."""
    return descendant_verdict(argv, session) != "CLEAR"


@guarded
def qualify(kind, writer):
    """The write-scope record a session record carries for this host and role, or a refusal."""
    host = _host(kind)
    if type(writer) is not bool:
        raise HostRefusal("invalid_record")
    role = "writer" if writer else "reader"
    if host["qualification"][role] == "refused":
        raise HostRefusal("unqualified_host")
    return dict(host["write_scope"] if writer else READER_SCOPE)


@guarded
def billing_set(kind, environ):
    # Presence is what counts, even an empty value: an empty ANTHROPIC_API_KEY still changes credential precedence
    # in some CLIs.
    return sorted(name for name in _host(kind)["billing_variables"] if _contains(environ, name))


@guarded
def descriptor_supported():
    return storage_descriptor_supported() and os.scandir in os.supports_fd


def _open_home(home):
    spelling = str(home) if isinstance(home, Path) else home
    require(type(spelling) is str and 0 < len(spelling) <= MAX_ROOT_CHARS, reason="unsafe_path")
    require("\x00" not in spelling, reason="unsafe_path")
    path = Path(spelling)
    require(path.is_absolute() and ".." not in path.parts, reason="unsafe_path")
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
            parent, fd = fd, child
            os.close(parent)
        return path, fd
    except BaseException:
        os.close(fd)
        raise


def _transcript_walk(fd, path, kind, session, depth, budget, found):
    require(depth <= MAX_TRANSCRIPT_DEPTH, reason="too_large")
    with os.scandir(fd) as entries:
        for item in entries:
            budget[0] -= 1
            require(budget[0] >= 0, reason="too_large")
            if item.is_symlink():
                continue
            if item.is_dir(follow_symlinks=False):
                # Claude's pattern has exactly two directory levels; Codex's ** is recursive.
                if (depth == 0 and item.name not in (
                        ("projects",) if kind == CLAUDE else ("sessions", "archived_sessions"))):
                    continue
                if kind == CLAUDE and depth >= 2:
                    continue
                require(depth < MAX_TRANSCRIPT_DEPTH, reason="too_large")
                child = os.open(item.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
                try:
                    _transcript_walk(child, path / item.name, kind, session, depth + 1, budget, found)
                finally:
                    os.close(child)
            elif item.is_file(follow_symlinks=False):
                matches = (depth == 2 and item.name == session + ".jsonl") if kind == CLAUDE else (
                    depth >= 1 and fnmatchcase(item.name, "rollout-*" + session + ".jsonl"))
                if matches:
                    found.add(path / item.name)


@guarded
def transcripts(kind, home, session):
    _host(kind)
    require(isinstance(session, str) and SESSION.fullmatch(session) is not None, reason="invalid_session")
    require(descriptor_supported(), reason="unsupported_platform")
    found = set()
    try:
        path, fd = _open_home(home)
    except FileNotFoundError:
        return []
    except (NotADirectoryError,):
        raise HostRefusal("unsafe_path") from None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise HostRefusal("unsafe_path") from None
        raise
    try:
        _transcript_walk(fd, path, kind, session, 0, [MAX_TRANSCRIPT_ENTRIES], found)
    finally:
        os.close(fd)
    return sorted(found)


def _check_event_bytes(value, limit):
    """Bound received bytes or str UTF-8/surrogatepass without an encoded copy."""
    size = len(value)
    require(size <= limit, reason="too_large")
    if isinstance(value, str):
        size = 0
        for char in value:
            code = ord(char)
            size += 1 if code < 128 else 2 if code < 2048 else 3 if code < 65536 else 4
            require(size <= limit, reason="too_large")
    return size


def _event_line(readline):
    """Bound one source-defined line without guessing its newline convention."""
    line = readline(MAX_EVENT_BYTES + 1)
    require(isinstance(line, (str, bytes)))
    _check_event_bytes(line, MAX_EVENT_BYTES)
    return line if line else ""


def claude_events(lines):
    """Yield bounded JSON event objects; skip malformed events as in the legacy reader."""
    require(_iterable_shape(lines))
    decode_bytes = isinstance(lines, bytes)
    if isinstance(lines, (str, bytes)):
        _check_event_bytes(lines, MAX_STREAM_BYTES)
        newline = b"\n" if decode_bytes else "\n"
        count = lines.count(newline) + bool(lines and not lines.endswith(newline))
        require(count <= MAX_EVENTS_PER_STREAM, reason="too_large")
        lines = BytesIO(lines) if decode_bytes else StringIO(lines, newline="\n")
    elif isinstance(lines, (list, tuple)):
        require(len(lines) <= MAX_EVENTS_PER_STREAM, reason="too_large")
    try:
        readline = getattr(lines, "readline", None)
        items = iter(lambda: _event_line(readline), "") if callable(readline) else _input_items(lines)
        for index, line in enumerate(items):
            require(index < MAX_EVENTS_PER_STREAM, reason="too_large")
            if not isinstance(line, (str, bytes, bytearray)):
                continue
            _check_event_bytes(line, MAX_EVENT_BYTES)
            try:
                event = json.loads(line.decode("utf-8", "replace") if decode_bytes else line)
            except (ValueError, RecursionError):
                continue
            if isinstance(event, dict):
                yield event
    except HostRefusal:
        raise
    except OSError:
        raise HostRefusal("io") from None
    except (ValueError, RecursionError, OverflowError):
        raise HostRefusal("invalid_record") from None


@guarded
def claude_init(lines):
    found = None
    for event in claude_events(lines):
        if found is None and event.get("type") == "system" and event.get("subtype") == "init":
            found = {name: event.get(source) for name, source in CLAUDE_INIT_KEYS}
    return found


def _counts(mapping, keys):
    if not isinstance(mapping, dict):
        return None
    values = [mapping.get(key) for key in keys]
    # bool is an int subclass, and True is not a token count.
    if all(type(value) is int and value >= 0 for value in values):
        return values
    return None


@guarded
def claude_usage(lines):
    """Normalized usage from the invocation's one `result` event, or None when it is missing or ambiguous.

    No result means a killed or timed-out turn; two mean the lines span more than one invocation.
    """
    results = [event for event in claude_events(lines) if event.get("type") == "result"]
    if len(results) != 1:
        return None
    result = results[0]
    usage = result.get("usage")
    found = _counts(usage, CLAUDE_USAGE_KEYS)
    if found is None:
        return None
    fresh, cache_write, cache_read, output = found
    # The ledger counts every input token once and reports cached input separately (spec "Efficiency and release
    # handoff"). Claude reports cache reads and writes outside input_tokens, so all three are input.
    return {"input_tokens": fresh + cache_write + cache_read, "cached_input_tokens": cache_read,
            "cache_write_input_tokens": cache_write, "output_tokens": output,
            "native": {"usage": usage, "total_cost_usd": result.get("total_cost_usd"),
                       "num_turns": result.get("num_turns"), "session_id": result.get("session_id")}}


@guarded
def codex_usage(totals):
    """Normalized usage from rollout_turns-style totals, or None when they are malformed."""
    found = _counts(totals, CODEX_USAGE_KEYS)
    if found is None:
        return None
    # Not summed: Codex reports cached input as a subset of input_tokens, as the turn ledger's
    # all_tokens = input + output assumes.
    total_input, cached, output = found
    if cached > total_input:
        return None
    return {"input_tokens": total_input, "cached_input_tokens": cached, "cache_write_input_tokens": None,
            "output_tokens": output, "native": dict(totals)}


@guarded
def claude_turn_items(lines):
    """What a Claude print turn did, in hierarchy_team.agent_items' shape: its messages and MCP tool calls."""
    items = []
    for event in claude_events(lines):
        message = event.get("message") if event.get("type") == "assistant" else None
        content = message.get("content") if isinstance(message, dict) else None
        for part in content if isinstance(content, list) else ():
            if not isinstance(part, dict):
                continue
            name = part.get("name")
            if part.get("type") == "text":
                items.append({"type": "agent_message", "text": str(part.get("text"))[:2000]})
            elif part.get("type") == "tool_use" and isinstance(name, str) and name.startswith("mcp__"):
                # Claude names an MCP tool mcp__<server>__<tool>; Codex items carry the tool alone. A server name
                # holding "__" would split wrongly; the team's servers (aegis_mailbox, aegis_board, aegis_decision)
                # have none.
                _, separator, tool = name[len("mcp__"):].partition("__")
                if separator and tool:
                    items.append({"type": "mcp_tool_call", "tool": tool, "arguments": part.get("input")})
    return items


@guarded
def claude_auth_check(exit_code, status, home):
    """(record, problems) for `claude auth status --json` run against a run's Claude home; no problems is OK."""
    problems = []
    if type(exit_code) is not int or exit_code != 0:
        problems.append("claude auth status exited unsuccessfully")
    if not isinstance(status, dict):
        problems.append("claude auth status printed no JSON object")
        return None, problems
    record = {}
    for key in CLAUDE_AUTH_KEYS:
        if key not in status:
            continue
        if type(status[key]) in CLAUDE_AUTH_TYPES[key]:
            record[key] = status[key]
        else:
            # The value is left out of the message too: it may be the identity this record must never hold.
            problems.append("claude auth status field %s has an unexpected type" % key)
    if status.get("loggedIn") is not True:
        problems.append("not logged in")
    # A subscription login. Any other method, including an apiKeyHelper the billing variables miss, could bill
    # elsewhere.
    if status.get("authMethod") != "claude.ai":
        problems.append("auth method is not claude.ai")
    if status.get("apiProvider") != "firstParty":
        problems.append("api provider is not firstParty")
    configured = status.get("configDirectory")
    # A relative answer would resolve against this process's cwd, not the folder the CLI actually used.
    if not (isinstance(configured, str) and os.path.isabs(configured)) or \
            os.path.realpath(configured) != os.path.realpath(_home_value(home)):
        problems.append("config directory is not the run's claude home")
    return record, problems


# -- the run's host plan and session records ------------------------------------------------------------------------------

