#!/usr/bin/env python3
"""Set up one initiative, or move a live one: mailbox root, registry entry, connections and profiles.

Root runs this. It writes files and bindings only, and it never starts a host. The host flags are
the ones that worked on real Claude and Codex sessions, including these lessons:

- Claude takes its prompt on stdin, because a trailing variadic flag consumed it as an argument.
- Claude takes `--tools=<list>` as one argument, because a separate empty value failed.
- Codex needs a working directory inside a Git checkout, and it assigns its own session ID, so a
  Codex session has to exist before it can be bound.
- A thread hosted by Codex's app server (host label `codex`) reaches its mailbox by running the
  adapter from a flat connection file in its own shell, and root messages it directly. Its host
  mechanics do not depend on this tool, so such a session moves by getting a new connection file.

`carry` moves open work out of a live mailbox root and only reads that root. A message cannot be
moved, because its replies and history belong to the old root, so an open dispatch continues as a new
dispatch of the same brief. Old message bodies are untrusted, so the record points to them and never
copies them. `carry-check` reports mail that reached the old root afterward.

Every adapter runs from one clean, pinned source checkout, so all roles run exact committed code.
Binding grants no authority, and a generated profile is not proof that a host will honor it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import (MAX_RECORDS, SLUG, Mailbox, digest, encoded, endpoint_parts, fields, initialize, integer,  # noqa: E402
                               matching, publish_file, read_json, require, safe_path, strict_json, strings, text,
                               timestamp, writer_lock)
from hierarchy_board import TOOL_SPECS as BOARD_TOOL_SPECS, Board  # noqa: E402
from hierarchy_mailbox_mcp import role_workspace_tools  # noqa: E402
import hierarchy_roles  # noqa: E402
from hierarchy_workspace import Store, validate_initiative  # noqa: E402


SCHEMA = "aegis.hierarchy-provision/v1"
CARRY_SCHEMA = "aegis.hierarchy-carry/v1"
CLAUDE = "claude-code"
CODEX = "codex-cli"
# A thread hosted by Codex's app server. Root creates and messages it, so it has no wake profile.
NATIVE = "codex"
RECENT_MESSAGES = 20
LANE_KINDS = set(hierarchy_roles.LANE_KINDS)
READ_TOOLS = hierarchy_roles.READ_TOOLS
WRITE_TOOLS = hierarchy_roles.WRITE_TOOLS
# Endpoints init can add beyond the front door, orchestrator and root every initiative has.
OPTIONAL_ROLES = ("router", "decider")
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
BACKGROUND_NOTE = ("runs as a background session that the owner's session list shows; append the start prompt as the last "
                   "argument. After its turn the session stays idle until the next wake stops and resumes it. Proven "
                   "with a stand-in host only, so check one real session first.")

# Generic levels from ADR-TEAM-CONFIG-20261102. Claude has no "ultra" effort: it runs max with ultracode on.
TEAM_LEVELS = ("low", "medium", "high", "xhigh", "max", "ultra")
ULTRACODE_SETTINGS = json.dumps({"ultracode": True})
TEAM_KINDS = hierarchy_roles.team_kinds()


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
    fields(request, {"store", "base", "source", "initiative", "lanes"}, {"python", "board", "roles"})
    base = safe_path(text(request["base"], "base"))
    lanes = request["lanes"]
    require(isinstance(lanes, dict) and lanes, "invalid lanes")
    for lane, kind in lanes.items():
        matching(lane, SLUG, "lane id")
        require(isinstance(kind, str) and kind in LANE_KINDS, "invalid lane kind")
    roles = request.get("roles", [])
    require(isinstance(roles, list) and len(roles) == len(set(roles)) and all(r in OPTIONAL_ROLES for r in roles),
            "roles may list only " + " and ".join(OPTIONAL_ROLES) + ", once each")
    initiative = request["initiative"]
    fields(initiative, {"id", "project", "repository", "priority", "target_branch"},
           {"touched_paths", "blocked_by", "checkouts", "lanes", "source"})
    validate_initiative(initiative)
    python = text(request.get("python", "/usr/bin/python3"), "python")
    require(Path(python).is_absolute(), "python path must be absolute")
    source, commit, tree = pin_source(request["source"])
    board = request.get("board")
    if board is not None:
        Board(text(board, "board")).load()
        require((source / "aegis_core" / "redaction.py").is_file(), "the board needs the secret patterns in the source checkout")
    store = Store(text(request["store"], "store"))
    hierarchy = initiative["id"]
    endpoints = {hierarchy + "/front-door": {}, hierarchy + "/orchestrator": {}, hierarchy + "/root": {}}
    endpoints.update({hierarchy + "/" + role: {} for role in roles})
    endpoints.update({hierarchy + "/lane/" + lane: {"kind": kind} for lane, kind in lanes.items()})
    record_path = base / "provision.json"
    store.load()  # A missing store is reported as such, before the lock would fail on its absent folder.
    # Under the store lock from the start, so a busy store stops this before anything exists, and registration
    # happens in the same step as the setup it describes.
    with store.lock():
        known = store.load()
        require(hierarchy not in known.initiatives, "initiative already registered: " + hierarchy)
        if record_path.exists():
            # An earlier run set this up and stopped before registering it, so this run finishes that one.
            record = read_json(record_path)
            require(record.get("initiative") == hierarchy and record.get("store") == str(store.path),
                    "initiative base already exists: " + str(base))
        else:
            require(not base.exists(), "initiative base already exists: " + str(base))
            record = {"schema": SCHEMA, "created_at": timestamp(), "store": str(store.path), "source": str(source),
                      "source_commit": commit, "source_tree": tree, "python": python, "initiative": hierarchy,
                      "mailbox_root": str(base / "mailbox"), "delivery_dir": str(base / "delivery")}
            if board is not None:
                record["board"] = board
            build_base(base, endpoints, known.limits["writer"], record)
        store.append(known, "register", {**initiative, "mailbox_root": record["mailbox_root"], "delivery_dir": record["delivery_dir"]})
    manifest = Mailbox(record["mailbox_root"]).manifest
    return {**record, "manifest_sha256": digest(manifest), "endpoints": sorted(manifest["endpoints"])}


def build_base(base, endpoints, writer_limit, record):
    """Built beside its final place and renamed in, so a run that stops leaves nothing or a complete setup."""
    base.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    pending = base.parent / (".pending-" + uuid.uuid4().hex)
    pending.mkdir(mode=0o700)
    try:
        initialize(pending / "mailbox", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints, "counterparts": [],
                                         "writer_limit": writer_limit})
        publish_file(pending / "provision.json", encoded(record) + b"\n")
        pending.rename(base)
    except BaseException:
        shutil.rmtree(pending, ignore_errors=True)
        raise


def adapter_args(setup, endpoint, host, session, generation):
    return ["-I", "-B", str(Path(setup["source"]) / "tools" / "hierarchy_mailbox.py"), "--root", setup["mailbox_root"],
            "serve", "--endpoint", endpoint, "--host", host, "--session", session, "--generation", str(generation),
            "--delivery-dir", setup["delivery_dir"], "--workspace-store", setup["store"],
            "--initiative", setup["initiative"]]


def board_args(setup, endpoint, host, session, generation):
    """A server of its own, so a damaged board cannot take a session's mailbox with it."""
    return ["-I", "-B", str(Path(setup["source"]) / "tools" / "hierarchy_mailbox.py"), "--root", setup["mailbox_root"],
            "serve", "--endpoint", endpoint, "--host", host, "--session", session, "--generation", str(generation),
            "--board", setup["board"]]


def registry_role(mailbox, endpoint):
    return hierarchy_roles.role(endpoint, mailbox.endpoint(endpoint).get("kind"))


def takes_board(setup, mailbox, endpoint):
    # The registry keeps the board from roles whose verdict must stay independent of the other roles' posts.
    return "board" in setup and hierarchy_roles.takes_board(registry_role(mailbox, endpoint))


def toml_list(values):
    return "[" + ", ".join(json.dumps(value) for value in values) + "]"


def codex_argv(cwd, *, writer, settings, tail, options):
    disabled = CODEX_DISABLED + ([] if writer or options.get("reader_shell") else CODEX_SHELL)
    argv = ["codex"]
    for feature in disabled:
        argv += ["--disable", feature]
    argv += ["exec", "--ignore-user-config", "--sandbox", "workspace-write" if writer else "read-only",
             "-c", 'approval_policy="never"']
    if writer:
        argv += ["-c", "sandbox_workspace_write.writable_roots=" + toml_list(options.get("writable_roots", [])),
                 "-c", "sandbox_workspace_write.exclude_slash_tmp=true",
                 "-c", "sandbox_workspace_write.exclude_tmpdir_env_var=true",
                 "-c", "sandbox_workspace_write.network_access=false"]
    argv += ["-c", settings, "--json", "-C", cwd]
    for setting, name in (("model", "model"), ("model_reasoning_effort", "effort")):
        if name in options:
            argv += ["-c", setting + "=" + json.dumps(options[name])]
    if "tmpdir" in options:
        # zsh makes its here-document files from TMPPREFIX, so a writer's sandbox has to allow that path too.
        argv += ["-c", "shell_environment_policy.set.TMPDIR=" + json.dumps(options["tmpdir"]),
                 "-c", "shell_environment_policy.set.TMPPREFIX=" + json.dumps(options["tmpdir"] + "/zsh")]
    for directory in options.get("add_dirs", []):
        argv += ["--add-dir", directory]
    if options.get("skip_git_repo_check"):
        argv.append("--skip-git-repo-check")
    return argv + list(tail)


def codex_servers(setup, endpoint, session, generation, tools, board):
    # Values are quoted as JSON strings, which TOML accepts unchanged, so a path cannot change the table.
    arguments = adapter_args(setup, endpoint, CODEX, session, generation)
    limits = "mailbox_inbox={output_token_limit=30000},mailbox_publish={approval_mode=\"approve\"}," \
             "mailbox_ack_handoff={approval_mode=\"approve\"}"
    servers = ("aegis_mailbox={command=" + json.dumps(setup["python"]) + ",args=" + toml_list(arguments) +
               ",required=true,enabled_tools=" + toml_list(tools) + ",tools={" + limits + "}}")
    if board:
        # Not required, because a session must keep its mailbox even when the board is damaged.
        servers += (",aegis_board={command=" + json.dumps(setup["python"]) + ",args=" +
                    toml_list(board_args(setup, endpoint, CODEX, session, generation)) +
                    ",required=false,enabled_tools=" + toml_list(list(BOARD_TOOL_SPECS)) +
                    ",tools={board_publish={approval_mode=\"approve\"},board_disposition={approval_mode=\"approve\"}}}")
    return "mcp_servers={" + servers + "}"


def role_kind(mailbox, endpoint):
    """The key a team.json reasoning_by_kind entry uses: a lane's kind, or "orchestrator"."""
    role = endpoint_parts(endpoint)[1]
    return mailbox.endpoint(endpoint).get("kind") if role == "lane" else role


def team_settings(base, host, request, kind=None):
    """Fill the model and effort a request leaves out from the initiative's team.json.

    Returns the options to build the argv from and a record of what was resolved, or None when the file was not used.
    """
    if "model" in request and "effort" in request:
        return request, None
    path = base / "team.json"
    if not path.exists():
        return request, None
    team = read_json(path)
    fields(team, {"model", "reasoning"}, {"reasoning_by_kind"})
    model = text(team["model"], "team.json model", 128)
    by_kind = team.get("reasoning_by_kind", {})
    require(isinstance(by_kind, dict), "invalid team.json reasoning_by_kind")
    for key, level in by_kind.items():
        # A typo in a key would otherwise fall back to the default level without a word.
        require(key in TEAM_KINDS, "unknown role kind in team.json reasoning_by_kind: " + str(key)[:40])
        require(level in TEAM_LEVELS, "unknown reasoning level in team.json: " + str(level)[:40])
    require(team["reasoning"] in TEAM_LEVELS, "unknown reasoning level in team.json: " + str(team["reasoning"])[:40])
    reasoning = by_kind.get(kind, team["reasoning"])
    if "model" not in request:
        # A mismatch means team.json and the role hosts disagree, which the owner resolves; never start the role
        # anyway. A request that names its own model does not use the team's, so only the reasoning applies.
        wanted = CLAUDE if model.startswith("claude-") else CODEX
        require(wanted == host, "team.json model %s needs host %s, not %s" % (model, wanted, host))
    options = dict(request)
    record = {"model_from": "request" if "model" in request else "team.json",
              "effort_from": "request" if "effort" in request else "team.json"}
    options.setdefault("model", model)
    record["reasoning_from"] = "request" if "effort" in request else "kind" if kind in by_kind else "default"
    if "effort" in request:
        reasoning = request["effort"]
    else:
        options["effort"] = "max" if reasoning == "ultra" else reasoning
        if reasoning == "ultra" and host == CLAUDE:
            options["ultracode"] = True
        elif reasoning == "ultra":
            # Never silently lower a level: say that it ran lower and why.
            record["downgrade"] = "ultra ran as max: Codex has no ultracode"
    record.update(model=options["model"], effort=options["effort"], reasoning=reasoning)
    return options, dict(sorted(record.items()))


def claude_argv(session_flags, connection, tools, allowed, request, assistants, name=None):
    """A named session runs in the background, where the owner's session list shows it."""
    argv = list(ASSISTANT_ENV) if assistants else []
    if name is None:
        argv += ["claude", "--restricted", "--tools=" + ",".join(tools), "--strict-mcp-config", "--mcp-config", connection,
                 "--permission-mode", "manual", "--permission-prompts", "none", *session_flags, "--print",
                 "--output-format", "stream-json", "--verbose", "--disable-slash-commands"]
    else:
        # --permission-prompts only applies with --print. dontAsk denies anything outside --allowedTools
        # instead of leaving the session waiting for someone to answer a prompt.
        argv += ["claude", "--bg", "--name", name, "--restricted", "--tools=" + ",".join(tools), "--strict-mcp-config",
                 "--mcp-config", connection, "--permission-mode", "dontAsk", *session_flags, "--disable-slash-commands"]
    if "model" in request:
        argv += ["--model", request["model"]]
    if "effort" in request:
        argv += ["--effort", request["effort"]]
    if request.get("ultracode"):
        argv += ["--settings", ULTRACODE_SETTINGS]
    for directory in request.get("add_dirs", []):
        argv += ["--add-dir", directory]
    if assistants:
        argv += ["--agents", assistants, "--disallowedTools", ASSISTANT_BLOCKED]
    argv += ["--allowedTools", ",".join(allowed)]
    # The variadic --allowedTools swallowed a trailing prompt on a real host. A background start takes its
    # prompt as an argument, so the options end first.
    return argv + (["--"] if name is not None else [])


def role_tools(endpoint, mailbox, requested):
    entry = registry_role(mailbox, endpoint)
    writer = hierarchy_roles.writer(entry)
    if requested is not None:
        names = [name for name in text(requested, "tools").split(",") if name]
        for name in names:
            require(name in SUPPORTED_TOOLS, "unsupported tool: " + name)
        return names, writer
    return hierarchy_roles.file_tools(entry), writer


def assistant_catalog(setup, endpoint, mailbox):
    name = registry_role(mailbox, endpoint)["provision"]["assistants"]
    require(name is not None, "no assistant list for this role")
    catalog = Path(setup["source"]) / "tools" / "hierarchy_templates" / "claude-agents" / ("assistants-" + name + ".json")
    require(catalog.is_file(), "no assistant list for this role")
    return str(catalog)


def check_codex_options(request, mailbox, endpoint, host):
    """Real lanes run with these. Each is for one kind of role, so none can widen another role by mistake."""
    entry = registry_role(mailbox, endpoint)
    writer = hierarchy_roles.writer(entry)
    reader = entry["provision"]["reader_shell"]
    if "reader_shell" in request:
        # Codex has no file tools without its shell, so a reader of files needs one. Its sandbox stays
        # read-only with no network, and a writer already has the shell it needs.
        require(type(request["reader_shell"]) is bool and host == CODEX and reader,
                "reader_shell is only for a Codex reviewer or orchestrator")
    for name in ("writable_roots", "tmpdir"):
        if name in request:
            require(host == CODEX and writer, name + " is only for a Codex writer")
    for directory in request.get("writable_roots", []):
        require(isinstance(directory, str) and safe_path(directory).is_dir(), "writable_roots must list existing folders")
    if "writable_roots" in request:
        strings(request["writable_roots"], "writable_roots")
    if "tmpdir" in request:
        require(safe_path(text(request["tmpdir"], "tmpdir")).is_dir(), "tmpdir must be an existing folder")
    if "skip_git_repo_check" in request:
        require(type(request["skip_git_repo_check"]) is bool and host == CODEX, "skip_git_repo_check is only for Codex")


def check_role_request(request, setup):
    fields(request, {"base", "endpoint", "host"}, {"session", "cwd", "tools", "add_dirs", "model", "effort", "timeout_seconds", "assistants",
                                                   "reader_shell", "writable_roots", "tmpdir", "skip_git_repo_check", "background",
                                                   "kind"})
    host = request["host"]
    require(host in (CLAUDE, CODEX, NATIVE), "unsupported host: " + str(host))
    require(type(request.get("background", False)) is bool, "invalid background")
    if request.get("background"):
        # Root has no profile, and a Codex lane shows in its own app only as a native thread.
        require(host == CLAUDE and endpoint_parts(request["endpoint"])[1] != "root",
                "background is only for claude-code roles")
    mailbox = Mailbox(setup["mailbox_root"])
    if "kind" in request:
        mailbox.require_kind(request["endpoint"], request["kind"])
    check_codex_options(request, mailbox, request["endpoint"], host)
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
    if host == NATIVE:
        require(session is not None, "a native thread needs its actual session")
        return None, timeout, assistants
    require(host != CODEX or session is not None, "codex assigns its own session ID; start it first and give the session here")
    require(not (assistants and host == CODEX), "codex assistants stay off until a live probe")
    cwd = safe_path(text(request.get("cwd", setup["source"]), "cwd"))
    require(cwd.is_dir(), "cwd is not a directory: " + str(cwd))
    if host == CODEX and not request.get("skip_git_repo_check"):
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
    team = None
    if host in (CLAUDE, CODEX) and endpoint_parts(endpoint)[1] != "root":
        # Before binding, so a bad team.json leaves the endpoint unbound.
        request, team = team_settings(base, host, request, role_kind(mailbox, endpoint))
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
    if team is not None:
        answer["team"] = team
    if endpoint_parts(endpoint)[1] == "root":
        return answer
    stem = endpoint.replace("/", "%2F") + "-g%d" % generation
    role_extra = role_workspace_tools(mailbox, endpoint)
    enabled = MAILBOX_TOOLS + list(role_extra)
    arguments = adapter_args(setup, endpoint, host, session, generation)
    board = takes_board(setup, mailbox, endpoint)
    connection = base / "connections" / (stem + ".json")
    connection.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if host == NATIVE:
        # The flat form a native thread's own script reads, as in the live connection files.
        connection.write_text(json.dumps({"command": setup["python"], "args": arguments}, indent=2) + "\n", encoding="utf-8")
        answer.update(connection=str(connection), wake="native")
        if board:
            board_connection = base / "connections" / (stem + ".board.json")
            board_connection.write_text(json.dumps({"command": setup["python"], "args": board_args(setup, endpoint, host, session, generation)},
                                                   indent=2) + "\n", encoding="utf-8")
            answer["board_connection"] = str(board_connection)
        return answer
    servers = {"aegis_mailbox": {"command": setup["python"], "args": arguments}}
    if board:
        servers["aegis_board"] = {"command": setup["python"], "args": board_args(setup, endpoint, host, session, generation)}
    connection.write_text(json.dumps({"mcpServers": servers}, indent=2) + "\n", encoding="utf-8")
    if host == CLAUDE:
        catalog = assistant_catalog(setup, endpoint, mailbox) if assistants else None
        names = tools + (["Agent"] if assistants else [])
        allowed = (["mcp__aegis_mailbox__" + name for name in enabled] +
                   (["mcp__aegis_board__" + name for name in BOARD_TOOL_SPECS] if board else []) +
                   [name for name in tools if name in WRITE_TOOLS])
        label = endpoint + "-g%d" % generation if request.get("background") else None
        wake_argv = claude_argv(["--resume", session], str(connection), names, allowed, request, catalog, label)
        answer["start_argv"] = claude_argv(["--session-id", session], str(connection), names, allowed, request, catalog, label)
        prompt_via = "argv" if label else "stdin"
        if label:
            answer.update(start_prompt_via="argv", background=BACKGROUND_NOTE)
        if assistants:
            answer["assistants"] = ASSISTANT_NOTE
    else:
        settings = codex_servers(setup, endpoint, session, generation, enabled, board)
        wake_argv = codex_argv(str(cwd), writer=writer, settings=settings, tail=["resume", session], options=request)
        prompt_via = "argv"
    wake_profile = base / "profiles" / (stem + ".wake.json")
    wake_profile.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    profile = {"schema": "aegis.hierarchy-wake-profile/v1", "endpoint": endpoint, "host": host, "session": session,
               "generation": generation, "argv": wake_argv, "cwd": str(cwd), "timeout_seconds": timeout,
               "prompt_via": prompt_via}
    if host == CLAUDE and request.get("background"):
        profile.update(mode="background", control=["claude"])
    wake_profile.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    return {**answer, "connection": str(connection), "wake_profile": str(wake_profile), "cwd": str(cwd),
            "prompt_via": prompt_via}


def codex_start(request):
    fields(request, {"base", "endpoint"}, {"cwd", "reader_shell", "writable_roots", "tmpdir", "add_dirs", "model", "effort", "skip_git_repo_check"})
    base = safe_path(text(request["base"], "base"))
    setup = read_json(base / "provision.json")
    mailbox = Mailbox(setup["mailbox_root"])
    mailbox.endpoint(request["endpoint"])
    check_codex_options(request, mailbox, request["endpoint"], CODEX)
    options, team = team_settings(base, CODEX, request, role_kind(mailbox, request["endpoint"]))
    writer = hierarchy_roles.writer(registry_role(mailbox, request["endpoint"]))
    cwd = safe_path(text(request.get("cwd", setup["source"]), "cwd"))
    if not request.get("skip_git_repo_check"):
        require(git(cwd, "rev-parse", "--is-inside-work-tree").returncode == 0, "codex needs a cwd inside a git checkout")
    answer = {"start_argv": codex_argv(str(cwd), writer=writer, settings="mcp_servers={}", tail=[], options=options),
              "cwd": str(cwd),
              "prompt_via": "argv",
              "next": "Read the session ID from the first JSON event, then run add-role with that session."}
    return {**answer, "team": team} if team is not None else answer


def old_root_state(old_root, hierarchy):
    """Everything read from a live root, which this never writes to. A held lock means unsure, so it refuses."""
    old = Mailbox(safe_path(text(old_root, "old_root")))
    names = sorted(name for name in old.manifest["endpoints"] if name.split("/")[0] == hierarchy)
    require(bool(names), "the old root has no such hierarchy: " + str(hierarchy))
    locks = [old.root / ".write.lock", *old.root.glob(".wake-" + hierarchy + "%2F*.lock")]
    busy = [path.name for path in locks if path.exists()]
    require(not busy, "the old root is busy (%s); try again once that finishes" % ", ".join(busy))
    records = old.messages()
    closed, accepted = old.dispatch_history(records)
    acceptances = {message["in_reply_to"]: message for message in accepted}
    in_order = sorted((row for row in records.values() if row["message"]["from"] in names or row["message"]["to"] in names),
                      key=lambda row: (row["message"]["created_at"], row["message"]["message_id"]))
    dispatches = []
    for row in in_order:
        message = row["message"]
        if message["type"] == "dispatch" and message["to"] in names and message["message_id"] not in closed:
            acceptance = acceptances.get(message["message_id"])
            dispatches.append({"dispatch": message["message_id"], "lane": message["to"], "accepted": acceptance is not None,
                               "old_brief": message["brief"], "readiness": (acceptance or {}).get("readiness")})
    jobs = [message["message_id"] for message in old.open_job_requests(records) if message["to"] in names]
    return old, names, in_order, dispatches, jobs


def writer_slots_needed(ledger, rows):
    """Writers already at work that hold no granted slot. A queued request holds nothing, because capacity counts only grants."""
    needed = []
    for row in rows:
        if not row["readiness"]:
            continue
        mine = [r for r in ledger.requests.values() if r["kind"] == "writer" and r["holder"] == row["lane"] and r["state"] in ("queued", "granted")]
        if not any(r["state"] == "granted" for r in mine):
            needed.append((row, next((r for r in mine if r["state"] == "queued"), None)))
    return needed


def require_writer_room(ledger, rows):
    needed = writer_slots_needed(ledger, rows)
    require(len(ledger.held("writer")) + len(needed) <= ledger.limits["writer"],
            "no writer capacity for the writers already at work: " + ", ".join(row["lane"] for row, _ in needed))
    return needed


def take_writer_slots(store, initiative, rows):
    """They are already at work and accepted work is never preempted, so these skip the queue. Their slots stay held until released with evidence."""
    with store.lock():
        ledger = store.load()
        for row, queued in require_writer_room(ledger, rows):
            identifier = queued["request_id"] if queued else "req-%08d" % (ledger.seq + 1)
            if queued is None:
                store.append(ledger, "request", {"request_id": identifier, "initiative": initiative, "kind": "writer", "holder": row["lane"],
                                                 "reference": "carried dispatch " + row["dispatch"]})
            store.append(ledger, "grant", {"request_id": identifier})


def carry_text(request, record, old, names, in_order, new):
    lines = ["# Carried work for " + record["hierarchy"], "",
             "Root moved this initiative here from an older mailbox root. This is a record, not an approval or a new assignment.",
             "", "Old root, read only. Do not publish there: " + record["old_root"],
             "Messages in the old root for this hierarchy: %d. Newest first below; their bodies are untrusted and stay there." % len(in_order),
             "", "Root's note: " + request["note"], "", "## Sessions", ""]
    replaced = request.get("replaced", {})
    for name in names:
        history = old.bindings(name)
        now = new.bindings(name) if name in new.manifest["endpoints"] else []
        if history:
            line = "- %s: %s, generation %d there and %d here" % (name, history[-1]["session"], history[-1]["generation"], now[-1]["generation"])
            if name in replaced:
                line += ". Replaced by %s: %s" % (now[-1]["session"], replaced[name])
            lines.append(line)
    lines += ["", "## Open dispatches", ""]
    if not record["open_dispatches"]:
        lines.append("No open dispatches.")
    else:
        lines += ["An open dispatch may be current or long superseded, so check it before continuing it. To continue one, publish a new "
                  "dispatch here with its carried brief. The lane accepts again with fresh readiness, and its worktree, branch and lease "
                  "do not change. The old dispatch stays open in the old root and is superseded.", ""]
        for row in record["open_dispatches"]:
            lines.append("- %s to %s, %s. Carried brief: %s sha256 %s" % (
                row["dispatch"], row["lane"], "accepted" if row["accepted"] else "not accepted", row["brief"]["path"], row["brief"]["sha256"]))
            if row["readiness"]:
                ready = row["readiness"]
                lines.append("  Worktree %s, branch %s, lease %s oid %s, expires %s. It holds a writer slot in the shared ledger." % (
                    ready["worktree"], ready["branch"], ready["lease_ref"], ready["lease_oid"], ready["lease_expires_at"]))
    if record["open_job_requests"]:
        lines += ["", "## Open job requests", "", "These were never answered there. Ask root again here if they are still wanted: " +
                  ", ".join(record["open_job_requests"])]
    lines += ["", "## Newest messages", ""]
    for row in reversed(in_order[-RECENT_MESSAGES:]):
        message = row["message"]
        lines.append("- %s %s %s to %s at %s: %s" % (message["message_id"], message["type"], message["from"], message["to"], message["created_at"], row["path"]))
    return "\n".join(lines) + "\n"


def carry(request):
    fields(request, {"base", "old_root", "hierarchy", "note"}, {"replaced"})
    text(request["note"], "note")
    base = safe_path(text(request["base"], "base"))
    setup = read_json(base / "provision.json")
    hierarchy = request["hierarchy"]
    require(setup["initiative"] == hierarchy, "this initiative is %s, so it can only take over that hierarchy, not %s" % (setup["initiative"], hierarchy))
    # Jobs and sweeps only see registered initiatives, so a move must not finish without one.
    Store(setup["store"]).load().initiative(hierarchy)
    replaced = request.get("replaced", {})
    require(isinstance(replaced, dict) and all(isinstance(reason, str) and reason for reason in replaced.values()), "invalid replaced")
    store = Store(setup["store"])
    new = Mailbox(setup["mailbox_root"])
    root_endpoint, orchestrator = hierarchy + "/root", hierarchy + "/orchestrator"
    require(bool(new.bindings(root_endpoint)) and bool(new.bindings(orchestrator)), "bind root and the orchestrator in the new root first")
    folder = base / "carried"
    record_path = folder / "carry.json"
    if record_path.exists():
        record = strict_json(record_path.read_text(encoding="utf-8"))
        require(record["old_root"] == request["old_root"] and record["hierarchy"] == hierarchy, "this initiative was carried from somewhere else")
    else:
        old, names, in_order, dispatches, jobs = old_root_state(request["old_root"], hierarchy)
        for name in names:
            history = old.bindings(name)
            if not history:
                continue
            require(name in new.manifest["endpoints"], "the new root has no endpoint " + name)
            bound = new.bindings(name)
            require(bool(bound), name + " is bound in the old root but not in the new one; run add-role for it first")
            if bound[-1]["session"] != history[-1]["session"]:
                require(name in replaced, name + " is bound to another session in the new root; name it under replaced if that is intended")
        with store.lock():
            require_writer_room(store.load(), dispatches)
        carried = []
        for row in dispatches:
            raw = old.brief(row["old_brief"])
            sha256 = hashlib.sha256(raw).hexdigest()
            path = folder / (sha256 + ".md")
            if not path.exists():
                publish_file(path, raw)
            carried.append({key: row[key] for key in ("dispatch", "lane", "accepted", "readiness")} | {
                "brief": {"path": str(path), "sha256": sha256}, "old_brief": row["old_brief"]})
        record = {"schema": CARRY_SCHEMA, "at": timestamp(), "old_root": request["old_root"], "hierarchy": hierarchy, "endpoints": names,
                  "generations": {name: old.bindings(name)[-1]["generation"] for name in names if old.bindings(name)},
                  "message_ids": [row["message"]["message_id"] for row in in_order], "open_dispatches": carried, "open_job_requests": jobs,
                  "replaced": sorted(replaced)}
        raw_brief = carry_text(request, record, old, names, in_order, new).encode("utf-8")
        sha256 = hashlib.sha256(raw_brief).hexdigest()
        # Named by content, so a run that stopped before its record can start over and find the same file.
        brief_path = folder / ("carried-work-" + sha256 + ".md")
        if not brief_path.exists():
            publish_file(brief_path, raw_brief)
        record["brief"] = {"path": str(brief_path), "sha256": sha256}
        # Last, so a run that stopped before here simply starts over. Files above are safe to find again.
        publish_file(record_path, encoded(record) + b"\n", limit=MAX_RECORDS * 1024)
    take_writer_slots(store, hierarchy, record["open_dispatches"])
    message_id = "carried-work-" + record["brief"]["sha256"][:32]
    with writer_lock(new.root):
        current = Mailbox(new.root)
        if message_id not in current.messages():
            binding = current.current_binding(root_endpoint)
            current.publish({"message_id": message_id, "from": root_endpoint, "to": orchestrator, "host": binding["host"], "session": binding["session"],
                             "binding_generation": binding["generation"], "type": "brief", "brief": record["brief"],
                             "body": "This initiative moved to this mailbox root. The attached brief lists the work that came with it."})
    return {"hierarchy": hierarchy, "brief": record["brief"], "message_id": message_id, "old_root": record["old_root"], "replaced": record["replaced"],
            "open_dispatches": [{key: row[key] for key in ("dispatch", "lane", "accepted", "brief", "readiness")} for row in record["open_dispatches"]],
            "open_job_requests": record["open_job_requests"], "messages_seen": len(record["message_ids"])}


def move(request):
    """One idempotent command per hierarchy, so a rotating root repeats exactly what was rehearsed."""
    fields(request, {"store", "base", "source", "old_root", "hierarchy", "note", "root", "initiative"}, {"board", "python", "roles", "replaced"})
    hierarchy, note = request["hierarchy"], request["note"]
    text(note, "note")
    fields(request["root"], {"host", "session"})
    # Root rotates often, so a prepared request leaves a placeholder that must not get bound by accident.
    require(isinstance(request["root"]["session"], str) and UUID.fullmatch(request["root"]["session"]) is not None,
            "root needs the actual session ID of the active root")
    old = Mailbox(safe_path(text(request["old_root"], "old_root")))
    endpoints = {name: spec for name, spec in old.manifest["endpoints"].items() if name.split("/")[0] == hierarchy}
    require(bool(endpoints), "the old root has no such hierarchy: " + str(hierarchy))
    roles, replaced = request.get("roles", {}), request.get("replaced", {})
    require(isinstance(roles, dict) and isinstance(replaced, dict), "invalid roles or replaced")
    for name in (*roles, *replaced):
        require(name in endpoints, "the old root has no endpoint " + str(name)[:256])
    for name, replacement in replaced.items():
        fields(replacement, {"host", "session", "reason"})
        require(isinstance(replacement["session"], str) and UUID.fullmatch(replacement["session"]) is not None,
                "a replacement needs the actual session ID from its host, for " + name)
    initiative = request["initiative"]
    fields(initiative, {"project", "repository", "priority", "target_branch"}, {"touched_paths", "blocked_by", "checkouts", "lanes", "source"})
    base = safe_path(text(request["base"], "base"))
    if hierarchy not in Store(text(request["store"], "store")).load().initiatives:
        # Sets it up, or finishes registering a setup that an earlier run left unregistered.
        lanes = {name.split("/")[2]: spec["kind"] for name, spec in endpoints.items() if name.split("/")[1] == "lane"}
        init({key: request[key] for key in ("store", "base", "source") } | {
            "lanes": lanes, "initiative": {**initiative, "id": hierarchy},
            **{key: request[key] for key in ("board", "python") if key in request}})
    setup = read_json(base / "provision.json")
    new = Mailbox(setup["mailbox_root"])
    answers, needs_profile, tell = {}, [], {}
    for name in sorted(endpoints):
        history = old.bindings(name)
        if not history:
            continue
        current = replaced.get(name) or {"host": history[-1]["host"], "session": history[-1]["session"]}
        options = {"base": str(base), "endpoint": name, "host": current["host"], "session": current["session"], **roles.get(name, {})}
        if current["host"] != NATIVE and name not in roles:
            # An idle lane has no worktree to run in, and defaulting a writer to the pinned tools checkout
            # could let it edit the code every adapter runs. So it is bound now and profiled when assigned.
            with writer_lock(new.root):
                bound = Mailbox(new.root).bindings(name)
                if not bound:
                    Mailbox(new.root).bind({"endpoint": name, "host": current["host"], "session": current["session"], "expected_generation": 0})
            answers[name] = {"endpoint": name, "host": current["host"], "session": current["session"]}
            needs_profile.append(name)
            continue
        answers[name] = add_role(options)
        if current["host"] == NATIVE:
            board = answers[name].get("board_connection")
            tell[name] = ("Your mailbox moved. From now on use the connection file " + answers[name]["connection"] +
                          (" and the board connection file " + board if board else "") + ", and read your inbox there now. Use only those. " +
                          "Never publish to the old mailbox root " + request["old_root"] + ", which stays readable as history.")
    root_endpoint = hierarchy + "/root"
    answers[root_endpoint] = add_role({"base": str(base), "endpoint": root_endpoint, **request["root"]})
    moved = carry({"base": str(base), "old_root": request["old_root"], "hierarchy": hierarchy, "note": note,
                   **({"replaced": {name: row["reason"] for name, row in replaced.items()}} if replaced else {})})
    return {"hierarchy": hierarchy, "mailbox_root": setup["mailbox_root"], "delivery_dir": setup["delivery_dir"], "roles": answers,
            "needs_profile": needs_profile, "tell": tell, "carry": moved}


def carry_check(request):
    fields(request, {"base"})
    path = safe_path(text(request["base"], "base")) / "carried" / "carry.json"
    require(path.exists(), "this initiative has not been carried")
    record = strict_json(path.read_text(encoding="utf-8"))
    old = Mailbox(record["old_root"])
    names, seen = set(record["endpoints"]), set(record["message_ids"])
    late = sorted(({"message_id": identifier, "type": row["message"]["type"], "from": row["message"]["from"], "to": row["message"]["to"],
                    "created_at": row["message"]["created_at"], "path": row["path"]}
                   for identifier, row in old.messages().items()
                   if identifier not in seen and (row["message"]["from"] in names or row["message"]["to"] in names)),
                  key=lambda row: row["created_at"])
    changed = sorted(name for name in record["endpoints"]
                     if old.bindings(name) and old.bindings(name)[-1]["generation"] != record["generations"].get(name))
    return {"clean": not late and not changed, "late_messages": late, "changed_bindings": changed}


COMMANDS = {"init": init, "add-role": add_role, "codex-start": codex_start, "carry": carry, "carry-check": carry_check, "move": move}


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
    return 3 if args.command == "carry-check" and not result["clean"] else 0


if __name__ == "__main__":
    sys.exit(main())
