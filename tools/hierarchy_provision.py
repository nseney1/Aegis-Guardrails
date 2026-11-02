#!/usr/bin/env python3
"""Set up one initiative: its mailbox root, registry entry and per-role connections and profiles.

Root runs this. It writes files and bindings only, and it never starts a host. The host flags are
the ones that worked on real Claude and Codex sessions, including these lessons:

- Claude takes its prompt on stdin, because a trailing variadic flag consumed it as an argument.
- Claude takes `--tools=<list>` as one argument, because a separate empty value failed.
- Codex needs a working directory inside a Git checkout, and it assigns its own session ID, so a
  Codex session has to exist before it can be bound.

Every adapter runs from one clean, pinned source checkout, so all roles run exact committed code.
Binding grants no authority, and a generated profile is not proof that a host will honor it.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import (SLUG, Mailbox, encoded, endpoint_parts, fields, initialize, integer,  # noqa: E402
                               matching, publish_file, read_json, require, safe_path, strings, text, timestamp,
                               writer_lock)
from hierarchy_mailbox_mcp import role_workspace_tools  # noqa: E402
from hierarchy_workspace import Store, validate_initiative  # noqa: E402


SCHEMA = "aegis.hierarchy-provision/v1"
CLAUDE = "claude-code"
CODEX = "codex-cli"
LANE_KINDS = {"implementer", "integrator", "reviewer"}
READ_TOOLS = ["Read", "Glob", "Grep"]
WRITE_TOOLS = ["Edit", "Write"]
SUPPORTED_TOOLS = set(READ_TOOLS + WRITE_TOOLS)
MAILBOX_TOOLS = ["mailbox_inbox", "mailbox_publish", "mailbox_ack_handoff"]
DEFAULT_TIMEOUT_SECONDS = 900
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
SESSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
CODEX_DISABLED = ["apps", "plugins", "remote_plugin", "multi_agent", "memories", "computer_use", "browser_use",
                  "browser_use_external", "browser_use_full_cdp_access", "goals"]
CODEX_SHELL = ["shell_tool", "unified_exec"]
ASSISTANT_ENV = ["env", "CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH=1", "CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS=2"]
ASSISTANT_BLOCKED = "Agent(general-purpose),Agent(Explore),Agent(Plan)"
ASSISTANT_NOTE = "enabled; using them needs the owner's go-ahead and a live probe"


def git(cwd, *arguments):
    return subprocess.run(["git", "-c", "core.fsmonitor=false", "--no-optional-locks", *arguments], cwd=cwd,
                          capture_output=True, text=True, timeout=60)


def pin_source(source):
    source = safe_path(text(source, "source"))
    require(source.is_dir(), "source checkout is unavailable: " + str(source))
    head = git(source, "rev-parse", "--show-toplevel", "HEAD", "HEAD^{tree}")
    require(head.returncode == 0, "source checkout is not a git checkout: " + str(source))
    top, commit, tree = head.stdout.split()
    require(Path(top).resolve() == source.resolve(), "source checkout must be the repository root: " + str(source))
    require(not git(source, "status", "--porcelain").stdout.strip(),
            "source checkout must be clean so adapters run exact committed code")
    require((source / "tools" / "hierarchy_mailbox.py").is_file(), "source checkout has no mailbox helper")
    return source, commit, tree


def init(request):
    fields(request, {"store", "base", "source", "initiative", "lanes"}, {"python"})
    base = safe_path(text(request["base"], "base"))
    lanes = request["lanes"]
    require(isinstance(lanes, dict) and lanes, "invalid lanes")
    for lane, kind in lanes.items():
        matching(lane, SLUG, "lane id")
        require(isinstance(kind, str) and kind in LANE_KINDS, "invalid lane kind")
    initiative = request["initiative"]
    fields(initiative, {"id", "project", "repository", "priority", "target_branch"},
           {"touched_paths", "blocked_by", "checkouts", "lanes", "source"})
    validate_initiative(initiative)
    python = text(request.get("python", "/usr/bin/python3"), "python")
    require(Path(python).is_absolute(), "python path must be absolute")
    source, commit, tree = pin_source(request["source"])
    store = Store(text(request["store"], "store"))
    known = store.load()
    require(initiative["id"] not in known.initiatives, "initiative already registered: " + initiative["id"])
    require(not base.exists(), "initiative base already exists: " + str(base))
    hierarchy = initiative["id"]
    endpoints = {hierarchy + "/front-door": {}, hierarchy + "/orchestrator": {}, hierarchy + "/root": {}}
    endpoints.update({hierarchy + "/lane/" + lane: {"kind": kind} for lane, kind in lanes.items()})
    base.mkdir(parents=True, mode=0o700)
    mailbox_root = base / "mailbox"
    delivery = base / "delivery"
    created = initialize(mailbox_root, {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints, "counterparts": [],
                                        "writer_limit": known.limits["writer"]})
    record = {"schema": SCHEMA, "created_at": timestamp(), "store": str(store.path), "source": str(source),
              "source_commit": commit, "source_tree": tree, "python": python, "initiative": hierarchy,
              "mailbox_root": str(mailbox_root), "delivery_dir": str(delivery)}
    publish_file(base / "provision.json", encoded(record) + b"\n")
    with store.lock():
        ledger = store.load()
        store.append(ledger, "register", {**initiative, "mailbox_root": str(mailbox_root), "delivery_dir": str(delivery)})
    return {**record, "manifest_sha256": created["manifest_sha256"], "endpoints": sorted(endpoints)}


def adapter_args(setup, endpoint, host, session, generation):
    return ["-I", "-B", str(Path(setup["source"]) / "tools" / "hierarchy_mailbox.py"), "--root", setup["mailbox_root"],
            "serve", "--endpoint", endpoint, "--host", host, "--session", session, "--generation", str(generation),
            "--delivery-dir", setup["delivery_dir"], "--workspace-store", setup["store"],
            "--initiative", setup["initiative"]]


def toml_list(values):
    return "[" + ", ".join(json.dumps(value) for value in values) + "]"


def codex_argv(cwd, *, writer, settings, tail):
    disabled = CODEX_DISABLED + ([] if writer else CODEX_SHELL)
    argv = ["codex"]
    for feature in disabled:
        argv += ["--disable", feature]
    argv += ["exec", "--ignore-user-config", "--sandbox", "workspace-write" if writer else "read-only",
             "-c", 'approval_policy="never"']
    if writer:
        argv += ["-c", "sandbox_workspace_write.writable_roots=[]", "-c", "sandbox_workspace_write.exclude_slash_tmp=true",
                 "-c", "sandbox_workspace_write.exclude_tmpdir_env_var=true",
                 "-c", "sandbox_workspace_write.network_access=false"]
    return argv + ["-c", settings, "--json", "-C", cwd, *tail]


def codex_servers(setup, endpoint, session, generation, tools):
    # Values are quoted as JSON strings, which TOML accepts unchanged, so a path cannot change the table.
    arguments = adapter_args(setup, endpoint, CODEX, session, generation)
    limits = "mailbox_inbox={output_token_limit=30000},mailbox_publish={approval_mode=\"approve\"}," \
             "mailbox_ack_handoff={approval_mode=\"approve\"}"
    return ("mcp_servers={aegis_mailbox={command=" + json.dumps(setup["python"]) + ",args=" + toml_list(arguments) +
            ",required=true,enabled_tools=" + toml_list(tools) + ",tools={" + limits + "}}}")


def claude_argv(session_flags, connection, tools, allowed, request, assistants):
    argv = list(ASSISTANT_ENV) if assistants else []
    argv += ["claude", "--restricted", "--tools=" + ",".join(tools), "--strict-mcp-config", "--mcp-config", connection,
             "--permission-mode", "manual", "--permission-prompts", "none", *session_flags, "--print",
             "--output-format", "stream-json", "--verbose", "--disable-slash-commands"]
    if "model" in request:
        argv += ["--model", request["model"]]
    if "effort" in request:
        argv += ["--effort", request["effort"]]
    for directory in request.get("add_dirs", []):
        argv += ["--add-dir", directory]
    if assistants:
        argv += ["--agents", assistants, "--disallowedTools", ASSISTANT_BLOCKED]
    return argv + ["--allowedTools", ",".join(allowed)]


def role_tools(endpoint, mailbox, requested):
    parts = endpoint_parts(endpoint)
    writer = mailbox.endpoint(endpoint).get("kind") in ("implementer", "integrator")
    if requested is not None:
        names = [name for name in text(requested, "tools").split(",") if name]
        for name in names:
            require(name in SUPPORTED_TOOLS, "unsupported tool: " + name)
        return names, writer
    if parts[1] == "front-door":
        return [], writer
    return READ_TOOLS + (WRITE_TOOLS if writer else []), writer


def assistant_catalog(setup, endpoint, mailbox):
    parts = endpoint_parts(endpoint)
    kind = mailbox.endpoint(endpoint).get("kind")
    name = parts[1] if parts[1] != "lane" else {"implementer": "builder", "integrator": "builder", "reviewer": "reviewer"}[kind]
    catalog = Path(setup["source"]) / "tools" / "hierarchy_templates" / "claude-agents" / ("assistants-" + name + ".json")
    require(catalog.is_file(), "no assistant list for this role")
    return str(catalog)


def check_role_request(request, setup):
    fields(request, {"base", "endpoint", "host"}, {"session", "cwd", "tools", "add_dirs", "model", "effort",
                                                   "timeout_seconds", "assistants"})
    host = request["host"]
    require(host in (CLAUDE, CODEX), "unsupported host: " + str(host))
    for name in ("model", "effort"):
        if name in request:
            text(request[name], name, 128)
    if "add_dirs" in request:
        strings(request["add_dirs"], "add_dirs")
        for directory in request["add_dirs"]:
            safe_path(directory)
    timeout = request.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    integer(timeout, "timeout_seconds", maximum=86400)
    assistants = request.get("assistants", False)
    require(type(assistants) is bool, "invalid assistants")
    session = request.get("session")
    is_root = endpoint_parts(request["endpoint"])[1] == "root"
    if session is not None:
        require(isinstance(session, str) and SESSION.fullmatch(session) is not None, "invalid session")
    if host == CLAUDE and session is not None and not is_root:
        require(UUID.fullmatch(session) is not None, "claude sessions need a UUID, which --session-id requires")
    if is_root:
        require(session is not None, "root needs its actual session")
        return None, timeout, assistants
    require(host != CODEX or session is not None, "codex assigns its own session ID; start it first and give the session here")
    require(not (assistants and host == CODEX), "codex assistants stay off until a live probe")
    cwd = safe_path(text(request.get("cwd", setup["source"]), "cwd"))
    require(cwd.is_dir(), "cwd is not a directory: " + str(cwd))
    if host == CODEX:
        require(git(cwd, "rev-parse", "--is-inside-work-tree").returncode == 0, "codex needs a cwd inside a git checkout")
    return cwd, timeout, assistants


def add_role(request):
    base = safe_path(text(request.get("base"), "base"))
    setup = read_json(base / "provision.json")
    mailbox = Mailbox(setup["mailbox_root"])
    endpoint = request.get("endpoint")
    mailbox.endpoint(endpoint)
    cwd, timeout, assistants = check_role_request(request, setup)
    host = request["host"]
    session = request.get("session") or str(uuid.uuid4())
    tools, writer = role_tools(endpoint, mailbox, request.get("tools"))
    root = Path(setup["mailbox_root"])
    with writer_lock(root):
        history = mailbox.bindings(endpoint)
        if history:
            require(history[-1]["session"] == session and history[-1]["host"] == host,
                    "endpoint is bound to another session; hand it off first")
            binding = history[-1]
        else:
            binding = mailbox.bind({"endpoint": endpoint, "host": host, "session": session, "expected_generation": 0})
    generation = binding["generation"]
    answer = {"endpoint": endpoint, "host": host, "session": session, "generation": generation}
    if endpoint_parts(endpoint)[1] == "root":
        return answer
    stem = endpoint.replace("/", "%2F") + "-g%d" % generation
    role_extra = role_workspace_tools(mailbox, endpoint)
    enabled = MAILBOX_TOOLS + list(role_extra)
    arguments = adapter_args(setup, endpoint, host, session, generation)
    connection = base / "connections" / (stem + ".json")
    connection.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    connection.write_text(json.dumps({"mcpServers": {"aegis_mailbox": {"command": setup["python"], "args": arguments}}},
                                     indent=2) + "\n", encoding="utf-8")
    if host == CLAUDE:
        catalog = assistant_catalog(setup, endpoint, mailbox) if assistants else None
        names = tools + (["Agent"] if assistants else [])
        allowed = ["mcp__aegis_mailbox__" + name for name in enabled] + ([name for name in tools if name in WRITE_TOOLS])
        wake_argv = claude_argv(["--resume", session], str(connection), names, allowed, request, catalog)
        answer["start_argv"] = claude_argv(["--session-id", session], str(connection), names, allowed, request, catalog)
        prompt_via = "stdin"
        if assistants:
            answer["assistants"] = ASSISTANT_NOTE
    else:
        settings = codex_servers(setup, endpoint, session, generation, enabled)
        wake_argv = codex_argv(str(cwd), writer=writer, settings=settings, tail=["resume", session])
        prompt_via = "argv"
    wake_profile = base / "profiles" / (stem + ".wake.json")
    wake_profile.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    wake_profile.write_text(json.dumps({
        "schema": "aegis.hierarchy-wake-profile/v1", "endpoint": endpoint, "host": host, "session": session,
        "generation": generation, "argv": wake_argv, "cwd": str(cwd), "timeout_seconds": timeout,
        "prompt_via": prompt_via}, indent=2) + "\n", encoding="utf-8")
    return {**answer, "connection": str(connection), "wake_profile": str(wake_profile), "cwd": str(cwd),
            "prompt_via": prompt_via}


def codex_start(request):
    fields(request, {"base", "endpoint"}, {"cwd"})
    setup = read_json(safe_path(text(request["base"], "base")) / "provision.json")
    mailbox = Mailbox(setup["mailbox_root"])
    mailbox.endpoint(request["endpoint"])
    writer = mailbox.endpoint(request["endpoint"]).get("kind") in ("implementer", "integrator")
    cwd = safe_path(text(request.get("cwd", setup["source"]), "cwd"))
    require(git(cwd, "rev-parse", "--is-inside-work-tree").returncode == 0, "codex needs a cwd inside a git checkout")
    return {"start_argv": codex_argv(str(cwd), writer=writer, settings="mcp_servers={}", tail=[]), "cwd": str(cwd),
            "prompt_via": "argv",
            "next": "Read the session ID from the first JSON event, then run add-role with that session."}


COMMANDS = {"init": init, "add-role": add_role, "codex-start": codex_start}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("--request", required=True, help="Absolute path to a strict JSON request")
    args = parser.parse_args(argv)
    try:
        result = COMMANDS[args.command](read_json(args.request))
    except (ValueError, OSError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
