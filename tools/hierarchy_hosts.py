#!/usr/bin/env python3
"""The host registry: each host kind's mechanisms, declared once (Teams spec, binding rule 5).

A host kind is what runs a session: `claude-code`, `codex-cli` (exec) or `codex` (a native app-server thread).
For each one the registry names its contract family, team start mode, home folder, billing variables, session
variable, transcript locator, usage reader, writer scope and qualification per role, and it holds the readers for
Claude's own output: stream-json events, usage, turn items and `claude auth status --json`.

Data and pure functions only. Nothing here starts, stops or writes anything, and `transcripts` only lists the folder
it is given. Starting and stopping processes stay in hierarchy_provision and hierarchy_launcher until later PRs route
them through this registry. `describe()` is the declarative part as JSON (aegis.hierarchy-host-registry/v1), so a run
can record the registry it used.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re


SCHEMA = "aegis.hierarchy-host-registry/v1"
CLAUDE = "claude-code"
CODEX = "codex-cli"
NATIVE = "codex"
HOST_KINDS = (CLAUDE, CODEX, NATIVE)
# Sessions go into glob patterns, so anything that could widen one is refused. Same pattern as hierarchy_provision.
SESSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
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

_HOSTS = {
    CLAUDE: {
        "family": "claude",
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
