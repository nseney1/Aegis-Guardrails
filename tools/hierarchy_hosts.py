#!/usr/bin/env python3
"""The host registry: each host kind's mechanisms, declared once (Teams spec, binding rule 5).

A host kind is what runs a session: `claude-code`, `codex-cli` (exec) or `codex` (a native app-server thread).
For each one the registry names its contract family, team start mode, home folder, billing variables, session
variable, transcript locator, process entrypoints, usage reader, writer scope and qualification per role. It also
holds the readers for Claude's own output: stream-json events, usage, turn items and `claude auth status --json`.

It also holds a team run's host plan (aegis.hierarchy-host-plan/v1, `<base>/host-plan.json`): which host runs ROOT,
which one runs every role below it, and which bindings are stand-ins that run no host. `require_binding` is the one
check every team-run path that binds applies (spec rule 1; ADR T2(a) question A, answer A2): with a plan it fails
closed, and only a base without one keeps today's unchecked binding. `session_record` is the host-neutral record
(aegis.team-session/v1) that add-role writes beside each binding it allows.

Data and pure functions only. Nothing here starts, stops or writes anything; `transcripts` only lists the folder it is
given, and `read_plan` and `session_recorded` only read. Starting and stopping processes stay in hierarchy_provision and
hierarchy_launcher until later PRs route them through this registry. `describe()` is the declarative part as JSON
(aegis.hierarchy-host-registry/v1), so a run can record the registry it used.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys

# With -I the script directory is absent from sys.path. Add only this reviewed directory, as hierarchy_roles does.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import endpoint_parts, integer, read_json, require, text  # noqa: E402


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
CODEX_BILLING = ("OPENAI_API_KEY", "CODEX_API_KEY")
# Spec rule 3 is not enforced in T2(a) (owner decision B): no MCP child has been shown to carry either variable.
CLAUDE_SESSION_VARIABLE = {"name": "CLAUDE_CODE_SESSION_ID", "verified_for_mcp": False}
CODEX_SESSION_VARIABLE = {"name": "CODEX_THREAD_ID", "verified_for_mcp": False}
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
PLAN_SCHEMA = "aegis.hierarchy-host-plan/v1"
PLAN_FILE = "host-plan.json"
PLAN_KEYS = ("schema", "hierarchy", "root", "team", "stand_ins", "config_sha256")
SESSION_SCHEMA = "aegis.team-session/v1"
STAND_IN_SCOPE = {"boundary": "stand-in: runs no host"}
START_MODES = ("print", "background", "exec", None)
SHA256 = re.compile(r"[0-9a-f]{64}")
NODE_ARITIES = {"--loader": 1, "--experimental-loader": 1, "--import": 1, "-r": 1, "--require": 1,
                "--env-file": 1, "--conditions": 1, "-C": 1, "--title": 1, "--input-type": 1,
                "--no-warnings": 0, "--trace-warnings": 0}
# Closed stop grammar, bounded by Codex rust-v0.167.0 (086ccc833bc9cf01024ad2dd6af7dbd421b6bf9a):
# G: cli/src/main.rs:127-141, tui/src/cli.rs:66-67,128-135; E: exec/src/cli.rs:15-25;
# R: exec/src/cli.rs:172-175,205-234. No claim of complete installed-host CLI support.
# names, admitted stages, arity, repeatable, value validator. Aliases share one occurrence counter.
CODEX_STOP_OPTIONS = (
    (("-c", "--config"), ("G", "E", "R"), 1, True, "config"),  # utils/cli/src/config_override.rs:29-71
    (("--enable",), ("G", "E", "R"), 1, True, "atom"),  # cli/src/main.rs:958-965
    (("--disable",), ("G", "E", "R"), 1, True, "atom"),
    (("--model", "-m"), ("G", "E", "R"), 1, False, "atom"),  # shared_options.rs:21-23
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
                              "grammar": {"stage": "C", "flags": CLAUDE_STOP_FLAGS,
                                          "split_one": CLAUDE_STOP_VALUES, "equals_one": ("--tools",),
                                          "repeatable": ("--add-dir", "--plugin-dir"),
                                          "exclusive_modes": ("--print", "--bg")},
                              "conflicting_flags": ("--fork-session",),
                              "value_options": ("--model", "--settings", "--permission-mode", "--output-format",
                                                "--input-format", "--system-prompt", "--append-system-prompt",
                                                "--mcp-config", "--agent", "--agents", "--tools", "--allowedTools",
                                                "--disallowedTools", "--add-dir", "--plugin-dir"),
                              "prompt_options": ("-p", "--print")},
        "team_start": "print",
        "home": {"variable": "CLAUDE_CONFIG_DIR", "run_folder": "claude-home", "owner_folder": ".claude"},
        "billing_variables": ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
                              "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"),
        "session_variable": CLAUDE_SESSION_VARIABLE,
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
                              "grammar": {"options": CODEX_STOP_OPTIONS, "exec": "exec", "resume": "resume"},
                              "conflicting_flags": (),
                              "value_options": ("-c", "--config", "--disable", "--enable", "--sandbox", "-s",
                                                "-C", "--cd", "--add-dir", "--model", "-m", "--profile", "-p",
                                                "--output-last-message", "-o", "--output-schema"),
                              "prompt_options": ()},
        "team_start": "exec",
        "home": {"variable": "CODEX_HOME", "run_folder": "codex-home", "owner_folder": ".codex"},
        "billing_variables": CODEX_BILLING,
        "session_variable": CODEX_SESSION_VARIABLE,
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
        "transcripts": CODEX_TRANSCRIPTS,
        "usage": None,
        "write_scope": None,
        "qualification": {"reader": "refused", "writer": "refused"},
    },
}


def _host(kind):
    if not isinstance(kind, str) or kind not in _HOSTS:
        raise ValueError("unsupported host kind: " + repr(kind)[:80])
    return _HOSTS[kind]


def entry(kind):
    # A JSON round trip is the deep copy, and it gives entry() and describe() one form: lists, never tuples.
    return json.loads(json.dumps({"kind": kind, **_host(kind)}))


def describe():
    return {"schema": SCHEMA, "hosts": {kind: entry(kind) for kind in HOST_KINDS}}


def family(kind):
    return _host(kind)["family"]


def entrypoints(kind):
    """Process entrypoints as JSON data, or an explicit refusal for a host with none."""
    found = entry(kind)["entrypoints"]
    require(any(found.values()), "%s has no process entrypoints" % kind)
    return found


def _host_arguments(kind, argv, strict=False):
    """Host arguments after env and an optional Node interpreter, or None for another program."""
    found = entrypoints(kind)
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
        return "HOLD"
    if index < len(arguments) and options and arguments[index].startswith("-") and arguments[index] != "-":
        return "HOLD"
    return "OWNED" if shape == "bound" else "NOT_OWNED"


def _claude_selection(selectors, arguments, session):
    grammar, index, options, prompts = selectors["grammar"], 0, True, 0
    seen, selected = set(), []
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
        if option in selectors["conflicting_flags"]:
            return "NOT_OWNED"
        if option in selectors["options"]:
            if not equal:
                value = arguments[index + 1] if index + 1 < len(arguments) else None
            shape = _selector_value(value, session)
            if shape not in ("bound", "other"):
                return "HOLD"  # In particular, a pending selector cannot consume a terminator.
            selected.append(shape)
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
    return "OWNED" if selected and all(shape == "bound" for shape in selected) else "NOT_OWNED"


def session_verdict(kind, argv, session, argv_boundaries="proven"):
    """Closed complete-atom grammar; flattened ps text never establishes first ownership."""
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
    return (_claude_selection(selectors, arguments, session) if selectors["options"]
            else _codex_selection(selectors, arguments, session))


def matches_session(kind, argv, session, argv_boundaries="proven"):
    """Compatibility boolean: only an OWNED verdict permits signalling."""
    return session_verdict(kind, argv, session, argv_boundaries) == "OWNED"


def descendant_verdict(argv, session):
    """Negative-only CLEAR/OTHER/HOLD: definite exclusion differs from unresolved selection."""
    if any(found.group() != session for word in argv for found in SESSION_UUID_OCCURRENCE.finditer(word)):
        return "OTHER"
    for kind in TEAM_HOSTS:
        selectors = _host(kind)["session_selectors"]
        arguments = _host_arguments(kind, argv, strict=True)
        if arguments is False:
            return "HOLD"
        if arguments is not None:
            if any(word.partition("=")[0] in selectors["conflicting_flags"] for word in arguments):
                return "OTHER"
            if session_verdict(kind, argv, session) == "HOLD":
                return "HOLD"
            # Complete admitted host syntax already identifies command/value/prompt positions. Its opaque
            # prompt must not be rescanned for selector-looking words. UUID sparing above remains separate.
            return "CLEAR"
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


def selects_other_session(argv, session):
    """Compatibility refusal predicate; neither OTHER nor HOLD grants borrowed ancestry authority."""
    return descendant_verdict(argv, session) != "CLEAR"


def qualify(kind, writer):
    """The write-scope record a session record carries for this host and role, or a refusal."""
    host = _host(kind)
    if type(writer) is not bool:
        raise ValueError("writer must be a bool")
    role = "writer" if writer else "reader"
    if host["qualification"][role] == "refused":
        raise ValueError("%s is not qualified for a %s role in a team run" % (kind, role))
    return dict(host["write_scope"] if writer else READER_SCOPE)


def billing_set(kind, environ):
    # Presence is what counts, even an empty value: an empty ANTHROPIC_API_KEY still changes credential precedence
    # in some CLIs.
    return sorted(name for name in _host(kind)["billing_variables"] if name in environ)


def transcripts(kind, home, session):
    templates = _host(kind)["transcripts"]
    if not isinstance(session, str) or SESSION.fullmatch(session) is None:
        raise ValueError("invalid session")
    home = Path(home)
    if not home.is_dir():
        return []
    found = {path for template in templates for path in home.glob(template.format(session=session))}
    return sorted(path for path in found if _confined(home, path))


def _confined(home, path):
    """A transcript counts only as a regular file reached through no symlink below the home: a linked `projects`
    folder or rollout would otherwise point the meter, evidence and session checks at another account's history."""
    current = path
    while current != home:
        if current.is_symlink() or current == current.parent:
            return False
        current = current.parent
    try:
        path.resolve().relative_to(home.resolve())
    except ValueError:
        return False
    return path.is_file()


def claude_events(lines):
    """The JSON objects in Claude stream-json output; blank, malformed and non-object lines are skipped."""
    # A whole stdout string would otherwise be read one character at a time and yield nothing. Only "\n" ends a
    # stream-json line: splitlines() would also cut at U+2028, U+2029 and U+0085, which JSON strings may hold raw.
    if isinstance(lines, bytes):
        lines = lines.decode("utf-8", "replace")
    if isinstance(lines, str):
        lines = lines.split("\n")
    for line in lines:
        try:
            event = json.loads(line)
        except (ValueError, TypeError, RecursionError):
            continue
        if isinstance(event, dict):
            yield event


def claude_init(lines):
    for event in claude_events(lines):
        if event.get("type") == "system" and event.get("subtype") == "init":
            return {name: event.get(source) for name, source in CLAUDE_INIT_KEYS}
    return None


def _counts(mapping, keys):
    if not isinstance(mapping, dict):
        return None
    values = [mapping.get(key) for key in keys]
    # bool is an int subclass, and True is not a token count.
    if all(type(value) is int and value >= 0 for value in values):
        return values
    return None


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


def claude_auth_check(exit_code, status, home):
    """(record, problems) for `claude auth status --json` run against a run's Claude home; no problems is OK."""
    problems = []
    if type(exit_code) is not int or exit_code != 0:
        problems.append("claude auth status exited %s" % repr(exit_code)[:80])
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
        problems.append("auth method %s is not claude.ai" % repr(status.get("authMethod"))[:80])
    if status.get("apiProvider") != "firstParty":
        problems.append("api provider %s is not firstParty" % repr(status.get("apiProvider"))[:80])
    configured = status.get("configDirectory")
    # A relative answer would resolve against this process's cwd, not the folder the CLI actually used.
    if not (isinstance(configured, str) and os.path.isabs(configured)) or \
            os.path.realpath(configured) != os.path.realpath(os.fspath(home)):
        problems.append("config directory is not the run's claude home")
    return record, problems


# -- the run's host plan and session records ------------------------------------------------------------------------------

def _endpoint(name):
    try:
        return endpoint_parts(name)
    except ValueError:
        return None


def validate_plan(value):
    require(isinstance(value, dict), "host plan must be a JSON object")
    missing, extra = set(PLAN_KEYS) - value.keys(), value.keys() - set(PLAN_KEYS)
    require(not missing, "host plan is missing " + ", ".join(sorted(missing)))
    require(not extra, "host plan has unexpected fields: " + ", ".join(sorted(map(str, extra))))
    require(value["schema"] == PLAN_SCHEMA, "unsupported host plan schema: " + repr(value["schema"])[:80])
    hierarchy = value["hierarchy"]
    # Checked as an endpoint's first part, so the mailbox's reserved names are refused too.
    require(isinstance(hierarchy, str) and _endpoint(hierarchy + "/root") is not None,
            "host plan hierarchy is not a hierarchy id: " + repr(hierarchy)[:80])
    for key in ("root", "team"):
        require(isinstance(value[key], str) and value[key] in TEAM_HOSTS,
                "host plan %s must be claude-code or codex-cli, not %s" % (key, repr(value[key])[:80]))
    stand_ins = value["stand_ins"]
    require(isinstance(stand_ins, dict), "host plan stand_ins must be a JSON object")
    for name, kind in stand_ins.items():
        parts = _endpoint(name)
        require(parts is not None and parts[0] == hierarchy,
                "host plan stand-in %s is not an endpoint of %s" % (str(name)[:256], hierarchy))
        # The front door's binding is the only one that never runs a host (the owner's mail goes through the mailbox
        # CLI); any other stand-in would bind a role that does run, unqualified.
        require(parts[1] == "front-door", "only the front door may be a stand-in, not %s" % name)
        # Any host kind: a stand-in never runs, so its label is recorded, not qualified (ADR T2(a) §1).
        require(isinstance(kind, str) and kind in HOST_KINDS,
                "host plan stand-in %s has unknown host kind %s" % (name, repr(kind)[:80]))
    require(isinstance(value["config_sha256"], str) and SHA256.fullmatch(value["config_sha256"]) is not None,
            "host plan config_sha256 must be 64 lowercase hex characters")
    return value


def plan_record(hierarchy, root, team, stand_ins, config_sha256):
    record = {"schema": PLAN_SCHEMA, "hierarchy": hierarchy, "root": root, "team": team, "stand_ins": stand_ins,
              "config_sha256": config_sha256}
    validate_plan(record)
    record["stand_ins"] = dict(stand_ins)
    return record


def read_plan(base):
    """The base's validated host plan, or None when it has none: a standalone or older base keeps today's binding."""
    path = Path(base) / PLAN_FILE
    # A dangling link does not exist(), so it is refused here rather than read as "no plan".
    require(not path.is_symlink(), "host plan must not be a symlink: " + str(path))
    if not path.exists():
        return None
    try:
        value = read_json(path)
    except ValueError as exc:
        raise ValueError("invalid host plan %s: %s" % (path, exc)) from exc
    return validate_plan(value)


def base_plan(base, hierarchy):
    """The plan of a base serving `hierarchy`, or None. A base holds only its initiative's endpoints, so a plan written
    for another hierarchy is a wrong plan, refused rather than read as covering nothing."""
    plan = read_plan(base)
    if plan is not None and plan["hierarchy"] != hierarchy:
        raise ValueError("host plan is for hierarchy %s, but this base serves %s" % (plan["hierarchy"], hierarchy))
    return plan


def governing_plan(base, mailbox_root, hierarchy):
    """The plan for bindings made through `base` into `mailbox_root`, or None when neither the base nor the mailbox's own
    base has one. A provision.json copied elsewhere still names the original mailbox, so both are read; two plans must
    agree."""
    base, home = Path(base), Path(mailbox_root).parent
    plan = base_plan(base, hierarchy)
    if base.exists() and home.exists() and base.samefile(home):
        return plan
    other = base_plan(home, hierarchy)
    if plan is not None and other is not None and plan != other:
        raise ValueError("host plans in %s and %s differ" % (base, home))
    return plan if plan is not None else other


def plan_host(plan, endpoint):
    """(host kind, stand-in) the plan assigns this endpoint; (None, False) when no plan covers it."""
    if plan is None:
        return None, False
    parts = endpoint_parts(endpoint)
    if parts[0] != plan["hierarchy"]:
        return None, False
    if endpoint in plan["stand_ins"]:
        return plan["stand_ins"][endpoint], True
    return (plan["root"] if parts[1] == "root" else plan["team"]), False


def require_binding(plan, endpoint, host, writer):
    """The write scope a session on `host` gets at this endpoint under the plan, None without a plan, or a refusal.

    Called before anything binds, so a refusal leaves the endpoint as it was.
    """
    if plan is None:
        return None
    expected, stand_in = plan_host(plan, endpoint)
    if expected is None:
        raise ValueError("%s is not an endpoint of host plan hierarchy %s" % (endpoint, plan["hierarchy"]))
    if host != expected:
        raise ValueError("%s runs on %s in this run's host plan, not %s" % (endpoint, expected, host))
    if stand_in:
        # validate_plan admits only the front door, which writes no source; this holds for a plan that skipped it.
        require(type(writer) is bool, "writer must be a bool")
        require(not writer, "%s cannot be a stand-in: its role writes source" % endpoint)
        return dict(STAND_IN_SCOPE)
    return qualify(host, writer)


def team_start_mode(host_kind, stand_in, background=False):
    """How a team run starts this session: the host's team start, or Claude background mode; a stand-in has none."""
    team_start = _host(host_kind)["team_start"]
    if stand_in:
        return None
    if background:
        require(host_kind == CLAUDE, "background is only for claude-code roles")
        return "background"
    return team_start


def session_record(endpoint, role_kind, host_kind, start_mode, session, generation, stand_in, write_scope):
    endpoint_parts(endpoint)
    text(role_kind, "role_kind", 64)
    _host(host_kind)
    require(start_mode is None or (isinstance(start_mode, str) and start_mode in START_MODES), "invalid start_mode")
    # The mailbox's own limit for a bound session.
    text(session, "session", 256)
    integer(generation, "generation")
    require(type(stand_in) is bool, "invalid stand_in")
    require(isinstance(write_scope, dict) and isinstance(write_scope.get("boundary"), str), "invalid write_scope")
    roots = write_scope.get("roots", [])
    require(isinstance(roots, list) and all(isinstance(root, str) and root for root in roots), "invalid write_scope")
    return {"schema": SESSION_SCHEMA, "endpoint": endpoint, "role_kind": role_kind, "host_kind": host_kind,
            "start_mode": start_mode, "session": session, "generation": generation, "stand_in": stand_in,
            "write_scope": dict(write_scope)}


def session_record_path(base, endpoint, generation):
    endpoint_parts(endpoint)
    integer(generation, "generation")
    # Quoted as provision names connections and profiles, so one endpoint's files sort together.
    return Path(base) / "sessions" / ("%s-g%d.json" % (endpoint.replace("/", "%2F"), generation))


def session_recorded(path, record):
    """True when this record is already on file, False when none is; a different record there is refused.

    A record is written once per endpoint and generation, so a re-run never rewrites history.
    """
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return False
    if read_json(path) != record:
        raise ValueError("session record for %s generation %d differs from this binding" % (
            record["endpoint"], record["generation"]))
    return True
