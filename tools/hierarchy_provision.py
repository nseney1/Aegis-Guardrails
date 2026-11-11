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
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

JSON_LIMIT_BYTES = 262144
JSON_FAILURES = (ValueError, TypeError, OverflowError, OSError, RecursionError)


def safe_value(value):
    """Bound only untrusted values after escaping; paths and surrounding instructions stay whole."""
    shown = ascii(value)
    return shown if len(shown) <= 80 else shown[:77] + "..."


class JsonProblem(ValueError):
    """A parser-hook diagnostic whose untrusted parts have already been escaped."""


def parse_json_bytes(raw, limit=JSON_LIMIT_BYTES):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise JsonProblem("duplicate JSON key " + safe_value(key))
            result[key] = value
        return result

    def nonfinite(_value):
        raise JsonProblem("non-finite JSON is not supported")

    def integer_literal(value):
        if len(value.lstrip("-")) > 128:
            raise JsonProblem("integer literal exceeds 128 digits")
        return int(value)

    def float_literal(value):
        number = float(value)
        if not math.isfinite(number):
            nonfinite(value)
        return number

    try:
        if len(raw) > limit:
            raise JsonProblem("input exceeds %d bytes" % limit)
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=nonfinite,
                          parse_int=integer_literal, parse_float=float_literal)
    except JsonProblem as exc:
        raise ValueError(str(exc)) from exc
    except UnicodeDecodeError as exc:
        raise ValueError("invalid UTF-8 JSON") from exc
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds supported limit") from exc
    except JSON_FAILURES as exc:
        raise ValueError("invalid JSON") from exc


def json_file_error(path, problem):
    return ValueError("invalid JSON file %s: %s; repair %s" % (path, problem, Path(path).name))


def bootstrap_json(path):
    # Before peer imports: bounded parsing also protects the retained-verifier entry itself.
    try:
        if not Path(path).is_file():
            raise ValueError("not a regular file")
        with Path(path).open("rb") as stream:
            raw = stream.read(JSON_LIMIT_BYTES + 1)
        return parse_json_bytes(raw)
    except JSON_FAILURES as exc:
        raise json_file_error(path, str(exc)) from exc


def check_governing_pin(setup, base):
    """Reject a copied pin before its retained verifier can select an older provisioner. Stdlib only."""
    mailbox_root = setup.get("mailbox_root") if isinstance(setup, dict) else None
    if not isinstance(mailbox_root, str) or not mailbox_root:
        return  # Ordinary provision validation retains its existing malformed-record diagnostic.
    try:
        base, home = Path(base), Path(mailbox_root).parent
        paths = (base / "host-plan.json", home / "host-plan.json")
        # No resolution without a plan: the ordinary readers retain their legacy refusal bytes.
        if not any(path.exists() or path.is_symlink() for path in paths):
            return
        if base == home or base.resolve() == home.resolve():
            return
        governing = bootstrap_json(home / "provision.json")
    except JSON_FAILURES + (RuntimeError, KeyError) as exc:
        # Never expose platform exception text, including symlink-loop RuntimeError on Python 3.12.
        raise ValueError("governing source pin check failed; use the governing base or reprovision") from exc
    if (not isinstance(governing, dict) or governing.get("schema") != "aegis.hierarchy-provision/v1" or
            governing.get("mailbox_root") != mailbox_root or governing.get("initiative") != setup.get("initiative")):
        raise ValueError("governing provision record does not match this run; reprovision the base")
    keys = ("source_commit", "source_tree")
    if not all(isinstance(governing.get(key), str) and
               re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", governing[key]) for key in keys):
        raise ValueError("governing provision record has an invalid source pin; reprovision the base")
    # Identical commit/tree pins may live at different checkout paths; both still undergo byte verification.
    if any(setup.get(key) != governing[key] for key in keys):
        raise ValueError("runtime source pin differs from governing provision; use the governing base or reprovision")


def delegated_read(label, reader, *args, **kwargs):
    """Normalize parse failures from pinned readers, keeping their ordinary ValueError contracts intact."""
    try:
        return reader(*args, **kwargs)
    except (RecursionError, OverflowError, UnicodeError, TypeError, KeyError, json.JSONDecodeError) as exc:
        problem = "JSON nesting exceeds supported limit" if isinstance(exc, RecursionError) else (
            "invalid JSON (%s)" % type(exc).__name__)
        # Never include the exception text: parser keys and values may contain attacker-controlled characters.
        raise ValueError("invalid delegated JSON read (%s): %s; repair the input" % (label, problem)) from exc

# Provisioned CLI actions must enter through the retained verifier before importing any peer module.
# A process-local marker prevents recursion; an environment variable cannot bypass verification.
if __name__ == "__main__" and getattr(sys, "_aegis_verified_runtime_entry", None) != str(Path(__file__).resolve()):
    import runpy
    early = argparse.ArgumentParser(add_help=False)
    guarded = False
    try:
        early.add_argument("command", nargs="?")
        early.add_argument("--request")
        parsed, _ = early.parse_known_args()
        if parsed.command in ("add-role", "codex-start") and parsed.request:
            request = bootstrap_json(parsed.request)
            base = Path(request["base"])
            guarded = True
        if guarded:
            provision = base / "provision.json"
            setup = bootstrap_json(provision)
            check_governing_pin(setup, base)
            verifier = base / "runtime-source.py"
            if not verifier.is_file():
                raise ValueError("runtime source verifier is missing; reprovision into a new base through the existing handoff flow")
            loaded = runpy.run_path(str(verifier))
            loaded["run"](provision, Path(setup["source"]) / "tools" / Path(__file__).name, sys.argv[1:])
            sys.exit(0)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        sys.exit(2)

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import (MAX_RECORDS, SLUG, Mailbox, digest, encoded, endpoint_parts, initialize, integer,  # noqa: E402
                               matching, publish_file, read_bytes, require, safe_path, strings, text,
                               timestamp, writer_lock)
from hierarchy_board import TOOL_SPECS as BOARD_TOOL_SPECS, Board  # noqa: E402
from hierarchy_mailbox_mcp import DECISION_TOOL, ROUTER_TAKES_NO_ACTOR, role_workspace_tools  # noqa: E402
import hierarchy_hosts  # noqa: E402
from hierarchy_hosts import SESSION  # noqa: E402
import hierarchy_roles  # noqa: E402
import hierarchy_runtime_source  # noqa: E402
from hierarchy_git import object_read_argv, object_read_env  # noqa: E402
from hierarchy_workspace import Store, validate_initiative  # noqa: E402


SCHEMA = "aegis.hierarchy-provision/v1"
CODEX_PROFILE_SCHEMA = "aegis.hierarchy-codex-profile/v1"
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
MAILBOX_TOOLS = ["mailbox_inbox", "mailbox_publish", "mailbox_ack_handoff", "mailbox_self"]
DEFAULT_TIMEOUT_SECONDS = 900
PYTHON_UNAVAILABLE = ('python interpreter is unavailable; '
                      'pass an absolute, executable "python" in the init request')
RECORDED_PYTHON_UNAVAILABLE = ('the interpreter recorded in provision.json is unavailable; '
                              'restore it, or remove the unregistered base and run init again')
REGISTERED_PYTHON_UNAVAILABLE = ('the interpreter recorded in provision.json is unavailable; '
                                'inspect the "python" field in this base\'s provision.json, '
                                'restore that exact interpreter, then retry')
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# multi_agent_v2 as well: the live M1 sessions ran with multi_agent disabled and were still offered the v2 sub-agent
# tools. Whether codex honours either flag under an account's managed settings is unverified; the native probe checks.
CODEX_DISABLED = ["apps", "plugins", "remote_plugin", "multi_agent", "multi_agent_v2", "memories", "computer_use",
                  "browser_use", "browser_use_external", "browser_use_full_cdp_access", "goals"]
CODEX_SHELL = ["shell_tool", "unified_exec"]
APPROVE = {"approval_mode": "approve"}
MAILBOX_TOOL_CONFIG = {"mailbox_inbox": {"output_token_limit": 30000}, "mailbox_publish": APPROVE,
                       "mailbox_ack_handoff": APPROVE}
# A tool that writes the journal waits for the session's approval, as a mailbox write does.
LIFECYCLE_TOOL_CONFIG = {"decider_record": APPROVE}
LIFECYCLE_PAIR = "lifecycle and actor must be given together"
ROOT_READS = "loop_state and evidence are only for ROOT's decision adapter, with its lifecycle and actor"
ASSISTANT_ENV = ["env", "CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH=1", "CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS=2"]
ASSISTANT_BLOCKED = "Agent(general-purpose),Agent(Explore),Agent(Plan)"
ASSISTANT_NOTE = "enabled; using them needs the owner's go-ahead and a live probe"
BACKGROUND_NOTE = ("runs as a background session that the owner's session list shows; append the start prompt as the last "
                   "argument. After its turn the session stays idle until the next wake stops and resumes it. Proven "
                   "with a stand-in host only, so check one real session first.")

# Generic levels from ADR-TEAM-CONFIG-20261102. Claude has no "ultra" effort: it runs max with ultracode on.
NATIVE_LEVELS = ("low", "medium", "high", "xhigh", "max")
TEAM_LEVELS = NATIVE_LEVELS + ("ultra",)
# Compatibility name only: planned resolutions use the governing setup's source, never this importer-local path.
MODEL_BINDINGS = Path(__file__).resolve().parent / "hierarchy_templates" / "model-bindings.json"
BINDINGS_FILE = "tools/hierarchy_templates/model-bindings.json"
MODEL_CLASSES = ("frontier", "coding", "scout", "mechanical")
PRODUCT_MODEL_CLASS = "coding"
EFFORT_INTENTS = ("light", "standard", "deep", "extended", "max")
ADMISSION_STATES = ("unprobed", "admitted", "rejected")
# ROOT is owner-chosen. The other unbanded seats still require host membership under a plan.
MODEL_POLICY_EXEMPT_ROLES = ("root",)
UNBANDED_MODEL_ROLES = ("front-door", "router")
PLAN_UNSET = object()
ULTRACODE_SETTINGS = json.dumps({"ultracode": True})
TEAM_KINDS = hierarchy_roles.team_kinds()
# ADR T2(a) §4: a team run's Claude roles run in print mode with no sub-agents, and the worktree as their only
# writable folder.
TEAM_CLAUDE_REFUSED = ("background", "assistants", "add_dirs")


def git(cwd, *arguments):
    return subprocess.run(object_read_argv(*arguments), cwd=cwd,
                          capture_output=True, text=True, timeout=60, env=object_read_env())


def pin_source(source):
    source = safe_path(text(source, "source"))
    require(source.is_dir(), "source checkout is unavailable: " + str(source))
    head = git(source, "rev-parse", "--show-toplevel", "HEAD", "HEAD^{tree}")
    require(head.returncode == 0, "source checkout is not a git checkout: " + str(source))
    top, commit, tree = head.stdout.splitlines()
    require(Path(top).resolve() == source.resolve(), "source checkout must be the repository root: " + str(source))
    require(not git(source, "status", "--porcelain").stdout.strip(),
            "source checkout must be clean so adapters run exact committed code")
    require((source / "tools" / "hierarchy_mailbox.py").is_file(), "source checkout has no mailbox helper")
    delegated_read("runtime source", hierarchy_runtime_source.verify,
                   {"source": str(source), "source_commit": commit, "source_tree": tree})
    return source, commit, tree


def require_interpreter(python, message=PYTHON_UNAVAILABLE, *, registered=False):
    available = False
    if isinstance(python, str) and 0 < len(python) <= 4096 and "\x00" not in python:
        try:
            available = Path(python).is_absolute() and Path(python).is_file() and os.access(python, os.X_OK)
        except (OSError, ValueError):
            available = False
    if not available and registered:
        message = REGISTERED_PYTHON_UNAVAILABLE
    require(available, message)


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
    python = request.get("python", sys.executable)
    if "python" not in request:
        require(isinstance(python, str) and bool(python), PYTHON_UNAVAILABLE)
    python = text(python, "python")
    require(Path(python).is_absolute(), "python path must be absolute")
    require_interpreter(python)
    source, commit, tree = pin_source(request["source"])
    board = request.get("board")
    if board is not None:
        delegated_read("board record", Board(text(board, "board")).load)
        require((source / "aegis_core" / "redaction.py").is_file(), "the board needs the secret patterns in the source checkout")
    store = Store(text(request["store"], "store"))
    hierarchy = initiative["id"]
    endpoints = {hierarchy + "/front-door": {}, hierarchy + "/orchestrator": {}, hierarchy + "/root": {}}
    endpoints.update({hierarchy + "/" + role: {} for role in roles})
    endpoints.update({hierarchy + "/lane/" + lane: {"kind": kind} for lane, kind in lanes.items()})
    record_path = base / "provision.json"
    # A missing store is reported as such, before the lock would fail on its absent folder.
    delegated_read("workspace record", store.load)
    # Under the store lock from the start, so a busy store stops this before anything exists, and registration
    # happens in the same step as the setup it describes.
    with store.lock():
        known = delegated_read("workspace record", store.load)
        require(hierarchy not in known.initiatives, "initiative already registered: " + hierarchy)
        if record_path.exists():
            # An earlier run set this up and stopped before registering it, so this run finishes that one.
            record = read_json(record_path)
            delegated_read("runtime source", hierarchy_runtime_source.verify, record, base)
            require(record.get("initiative") == hierarchy and record.get("store") == str(store.path),
                    "initiative base already exists: " + str(base))
            require_interpreter(record.get("python"), RECORDED_PYTHON_UNAVAILABLE)
            require("python" not in request or python == record["python"], "python does not match provision.json")
        else:
            require(not base.exists(), "initiative base already exists: " + str(base))
            record = {"schema": SCHEMA, "created_at": timestamp(), "store": str(store.path), "source": str(source),
                      "source_commit": commit, "source_tree": tree, "python": python, "initiative": hierarchy,
                      "mailbox_root": str(base / "mailbox"), "delivery_dir": str(base / "delivery")}
            if board is not None:
                record["board"] = board
            build_base(base, endpoints, known.limits["writer"], record)
        store.append(known, "register", {**initiative, "mailbox_root": record["mailbox_root"], "delivery_dir": record["delivery_dir"]})
    manifest = delegated_read("mailbox manifest", Mailbox, record["mailbox_root"]).manifest
    return {**record, "manifest_sha256": digest(manifest), "endpoints": sorted(manifest["endpoints"])}


def build_base(base, endpoints, writer_limit, record):
    """Built beside its final place and renamed in, so a run that stops leaves nothing or a complete setup."""
    base.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    pending = base.parent / (".pending-" + uuid.uuid4().hex)
    pending.mkdir(mode=0o700)
    try:
        initialize(pending / "mailbox", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints, "counterparts": [],
                                         "writer_limit": writer_limit})
        publish_file(pending / "runtime-source.py", delegated_read("runtime source", hierarchy_runtime_source.verify, record))
        publish_file(pending / "provision.json", encoded(record) + b"\n")
        pending.rename(base)
    except BaseException:
        shutil.rmtree(pending, ignore_errors=True)
        raise


def adapter_args(setup, endpoint, host, session, generation, source_repo=None, lifecycle=()):
    return hierarchy_runtime_source.entry_args(setup, "hierarchy_mailbox.py") + ["--root", setup["mailbox_root"],
            "serve", "--endpoint", endpoint, "--host", host, "--session", session, "--generation", str(generation),
            "--delivery-dir", setup["delivery_dir"], "--workspace-store", setup["store"],
            "--initiative", setup["initiative"]] + (["--source-repo", source_repo] if source_repo else []) + list(lifecycle)


def lifecycle_args(request):
    return ((["--lifecycle", request["lifecycle"]] if "lifecycle" in request else []) +
            (["--actor", request["actor"]] if "actor" in request else []))


def decision_args(setup, endpoint, host, session, generation, request):
    """ROOT's decision adapter takes the journal and its actor, and only read-only folders beside them. It runs from
    its own entry, because the pinned mailbox CLI cannot carry --loop-state and --evidence."""
    return hierarchy_runtime_source.entry_args(setup, "hierarchy_mailbox_mcp.py") + ["--root",
            setup["mailbox_root"], "serve", "--endpoint", endpoint, "--host", host, "--session", session,
            "--generation", str(generation), *lifecycle_args(request),
            *(["--loop-state", request["loop_state"]] if "loop_state" in request else []),
            *(["--evidence", request["evidence"]] if "evidence" in request else [])]


def board_args(setup, endpoint, host, session, generation):
    """A server of its own, so a damaged board cannot take a session's mailbox with it."""
    return hierarchy_runtime_source.entry_args(setup, "hierarchy_mailbox.py") + ["--root", setup["mailbox_root"],
            "serve", "--endpoint", endpoint, "--host", host, "--session", session, "--generation", str(generation),
            "--board", setup["board"]]


def registry_role(mailbox, endpoint):
    return hierarchy_roles.role(endpoint, mailbox.endpoint(endpoint).get("kind"))


def takes_board(setup, mailbox, endpoint):
    # The registry keeps the board from roles whose verdict must stay independent of the other roles' posts.
    return "board" in setup and hierarchy_roles.takes_board(registry_role(mailbox, endpoint))


def toml_list(values):
    return "[" + ", ".join(json.dumps(value) for value in values) + "]"


def toml_value(value):
    """Values are quoted as JSON strings, which TOML accepts unchanged, so a path cannot change the table."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return toml_list(value)
    return "{" + ",".join(key + "=" + toml_value(item) for key, item in value.items()) + "}"


def codex_profile(cwd, *, writer, servers, options, endpoint, role, session=None, generation=None, tier=None):
    """Everything a Codex role runs with, as an Aegis record. The argv is built from this alone."""
    return {"schema": CODEX_PROFILE_SCHEMA, "endpoint": endpoint, "role": role, "host": CODEX, "session": session,
            "generation": generation, "sandbox": "workspace-write" if writer else "read-only",
            "writable_roots": list(options.get("writable_roots", [])), "network_access": False,
            "approval_policy": "never", "ignore_user_config": True,
            "disabled_features": CODEX_DISABLED + ([] if writer or options.get("reader_shell") else CODEX_SHELL),
            "mcp_servers": servers, "model": options.get("model"), "effort": options.get("effort"),
            "service_tier": tier, "tmpdir": options.get("tmpdir"), "add_dirs": list(options.get("add_dirs", [])),
            "cwd": cwd, "skip_git_repo_check": bool(options.get("skip_git_repo_check"))}


def codex_argv(profile, tail=()):
    argv = ["codex"]
    for feature in profile["disabled_features"]:
        argv += ["--disable", feature]
    argv += ["exec"] + (["--ignore-user-config"] if profile["ignore_user_config"] else [])
    argv += ["--sandbox", profile["sandbox"], "-c", "approval_policy=" + json.dumps(profile["approval_policy"])]
    if profile["sandbox"] == "workspace-write":
        argv += ["-c", "sandbox_workspace_write.writable_roots=" + toml_list(profile["writable_roots"]),
                 "-c", "sandbox_workspace_write.exclude_slash_tmp=true",
                 "-c", "sandbox_workspace_write.exclude_tmpdir_env_var=true",
                 "-c", "sandbox_workspace_write.network_access=" + toml_value(profile["network_access"])]
    argv += ["-c", "mcp_servers=" + toml_value(profile["mcp_servers"]), "--json", "-C", profile["cwd"]]
    for setting, name in (("model", "model"), ("model_reasoning_effort", "effort"), ("service_tier", "service_tier")):
        if profile[name] is not None:
            argv += ["-c", setting + "=" + json.dumps(profile[name])]
    if profile["tmpdir"] is not None:
        # zsh makes its here-document files from TMPPREFIX, so a writer's sandbox has to allow that path too.
        argv += ["-c", "shell_environment_policy.set.TMPDIR=" + json.dumps(profile["tmpdir"]),
                 "-c", "shell_environment_policy.set.TMPPREFIX=" + json.dumps(profile["tmpdir"] + "/zsh")]
    for directory in profile["add_dirs"]:
        argv += ["--add-dir", directory]
    if profile["skip_git_repo_check"]:
        argv.append("--skip-git-repo-check")
    return argv + list(tail)


def codex_servers(setup, arguments, tools, board_arguments=None):
    tools = list(tools)
    config = {**MAILBOX_TOOL_CONFIG, **{name: LIFECYCLE_TOOL_CONFIG[name] for name in tools if name in LIFECYCLE_TOOL_CONFIG}}
    servers = {"aegis_mailbox": {"command": setup["python"], "args": arguments, "required": True, "enabled_tools": tools,
                                 "tools": config}}
    if board_arguments is not None:
        # Not required, because a session must keep its mailbox even when the board is damaged.
        servers["aegis_board"] = {"command": setup["python"], "args": board_arguments, "required": False,
                                  "enabled_tools": list(BOARD_TOOL_SPECS),
                                  "tools": {"board_publish": APPROVE, "board_disposition": APPROVE}}
    return servers


def role_kind(mailbox, endpoint):
    """The key a team.json reasoning_by_kind entry uses: a lane's kind, or "orchestrator"."""
    role = endpoint_parts(endpoint)[1]
    return mailbox.endpoint(endpoint).get("kind") if role == "lane" else role


def diagnostic_name(value):
    # Preserve existing readable identifier messages, but quote and escape everything else.
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value) else safe_value(value)


def fields(value, required, optional=()):
    require(isinstance(value, dict), "expected a JSON object")
    require(set(required) <= value.keys(), "missing fields: " + ", ".join(sorted(set(required) - value.keys())))
    extra = value.keys() - set(required) - set(optional)
    require(not extra, "unexpected fields: " + ", ".join(diagnostic_name(key) for key in sorted(extra, key=str)))


def read_json(path, limit=JSON_LIMIT_BYTES):
    try:
        if limit == JSON_LIMIT_BYTES:
            raw = read_bytes(path)  # Retain the pinned reader's regular-file and path checks.
        else:
            path = safe_path(path)
            require(path.is_file(), "input must be a regular file")
            with path.open("rb") as stream:
                raw = stream.read(limit + 1)
    except JSON_FAILURES as exc:
        raise ValueError(str(exc)) from exc
    return json_document(raw, path, limit)


def json_document(raw, path, limit=JSON_LIMIT_BYTES):
    try:
        return parse_json_bytes(raw, limit)
    except JSON_FAILURES as exc:
        raise json_file_error(path, str(exc)) from exc


def team_file_bytes(path):
    try:
        return read_bytes(path)
    except JSON_FAILURES as exc:
        raise json_file_error(path, str(exc)) from exc


def check_model_request(request):
    if "effort" in request:
        effort = request["effort"]
        require(effort != "ultra", "request effort 'ultra' is a deprecated alias accepted only in team.json; "
                "ask for max, or set team.json reasoning to ultra; allowed request efforts: " + ", ".join(NATIVE_LEVELS))
        require(isinstance(effort, str) and effort in NATIVE_LEVELS,
                "invalid request effort %s; choose one of: %s" % (safe_value(effort), ", ".join(NATIVE_LEVELS)))
    if "model" in request:
        text(request["model"], "model", 128)


def binding_keys(row, keys, label):
    require(isinstance(row, dict), label + " must be an object")
    require(not row.keys() - set(keys), "unexpected " + label + " keys")
    require(set(keys) <= row.keys(), "missing " + label + " keys")


def binding_identifier(value, label):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value) is not None,
            label + " must be a nonempty ASCII identifier")


def bindings_error(problem, path):
    return ValueError("invalid model bindings %s: %s; repair model-bindings.json" %
                      (path, problem))


def check_role_model_class(kind, model_class):
    require(model_class == PRODUCT_MODEL_CLASS, "%s requires model class %s; got %s" %
            (kind, PRODUCT_MODEL_CLASS, safe_value(model_class)))


def read_pinned_bindings(setup, base):
    """Verify and return the exact policy bytes, including for paths that waive model resolution."""
    path = Path(setup["source"]) / BINDINGS_FILE
    try:
        delegated_read("runtime source", hierarchy_runtime_source.verify, setup, base)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        raise bindings_error("source pin verification failed; restore the pinned source or reprovision", path) from exc
    try:
        path = safe_path(path)
        require(path.is_file(), "cannot read file")
        with path.open("rb") as stream:
            raw = stream.read(JSON_LIMIT_BYTES + 1)
    except JSON_FAILURES as exc:
        raise bindings_error("cannot read file", path) from exc
    try:
        committed = delegated_read("model bindings", hierarchy_runtime_source.git, setup["source"],
                                   "show", setup["source_commit"] + ":" + BINDINGS_FILE)
        require(raw == committed, "binding bytes changed after source verification")
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        raise bindings_error("source pin verification failed; restore the pinned source or reprovision", path) from exc
    return path, raw


def load_model_bindings(setup, base):
    """Read once per planned resolution; the hash describes the exact validated bytes, not a reserialization."""
    path, raw = read_pinned_bindings(setup, base)
    try:
        data = parse_json_bytes(raw)
        binding_keys(data, ("schema", "roles", "hosts"), "top-level")
        require(data["schema"] == "aegis.model-bindings/v1", "unsupported schema")
        require(isinstance(data["roles"], list), "roles must be a list")
        require(isinstance(data["hosts"], list), "hosts must be a list")
        roles, hosts, host_models = {}, {}, set()
        for row in data["roles"]:
            binding_keys(row, ("kind", "model_class", "band"), "role")
            kind, model_class, band = row["kind"], row["model_class"], row["band"]
            require(isinstance(kind, str) and kind in TEAM_KINDS, "unknown role kind " + safe_value(kind))
            require(kind not in roles, "duplicate role row")
            require(isinstance(model_class, str) and model_class in MODEL_CLASSES,
                    "unknown model class " + safe_value(model_class))
            binding_keys(band, ("floor", "default", "ceiling"), "band")
            for intent in band.values():
                require(isinstance(intent, str) and intent in EFFORT_INTENTS, "unknown intent " + safe_value(intent))
            require(EFFORT_INTENTS.index(band["floor"]) <= EFFORT_INTENTS.index(band["default"]) <=
                    EFFORT_INTENTS.index(band["ceiling"]), "band must satisfy floor <= default <= ceiling")
            roles[kind] = row
        missing_kinds = sorted(set(TEAM_KINDS) - roles.keys())
        require(not missing_kinds, "missing role kinds: " + ", ".join(missing_kinds))
        for row in data["hosts"]:
            binding_keys(row, ("host", "class", "model", "levels", "admission"), "host")
            host, model_class, levels = row["host"], row["class"], row["levels"]
            require(isinstance(host, str) and host in hierarchy_hosts.TEAM_HOSTS, "unknown host " + safe_value(host))
            require(isinstance(model_class, str) and model_class in MODEL_CLASSES,
                    "unknown model class " + safe_value(model_class))
            require((host, model_class) not in hosts, "duplicate host/class row")
            binding_identifier(row["model"], "model")
            require((host, row["model"]) not in host_models,
                    "duplicate host/model row: %s/%s" % (host, row["model"]))
            host_models.add((host, row["model"]))
            require(isinstance(levels, dict) and bool(levels) and set(levels) <= set(EFFORT_INTENTS),
                    "levels must map a nonempty subset of " + ", ".join(EFFORT_INTENTS))
            for level in levels.values():
                require(isinstance(level, str) and level in NATIVE_LEVELS, "unknown native level " + safe_value(level))
            require(len(set(levels.values())) == len(levels), "levels must map to distinct native levels")
            admission = row["admission"]
            require(isinstance(admission, dict) and set(admission) == set(levels),
                    "admission must map exactly supported intents")
            for state in admission.values():
                require(isinstance(state, str) and state in ADMISSION_STATES,
                        "unknown admission value " + safe_value(state))
            # Unprobed levels remain runnable in MR-1; only known rejected levels refuse.
            hosts[host, model_class] = row
        required_classes = {row["model_class"] for row in roles.values()}
        missing_bindings = sorted("%s/%s" % (host, model_class)
                                  for host in hierarchy_hosts.TEAM_HOSTS for model_class in required_classes
                                  if (host, model_class) not in hosts)
        require(not missing_bindings, "missing host/class rows: " + ", ".join(missing_bindings))
        for kind, policy in roles.items():
            check_role_model_class(kind, policy["model_class"])
            for host in hierarchy_hosts.TEAM_HOSTS:
                binding = hosts[host, policy["model_class"]]
                for edge in ("default", "ceiling"):
                    intent = policy["band"][edge]
                    require(intent in binding["levels"], "binding %s/%s lacks band %s %s for %s" %
                            (host, policy["model_class"], edge, intent, kind))
                    require(binding["admission"][intent] != "rejected",
                            "binding %s/%s has rejected band %s %s for %s" %
                            (host, policy["model_class"], edge, intent, kind))
        return roles, hosts, hashlib.sha256(raw).hexdigest(), path
    except JSON_FAILURES as exc:
        raise bindings_error(str(exc), path) from exc


def planned_model_settings(bindings, host, kind, options, record, fixed=None):
    if kind in MODEL_POLICY_EXEMPT_ROLES:
        return options, record
    roles, hosts, sha256, path = bindings
    row = roles.get(kind)
    if row is None and kind not in UNBANDED_MODEL_ROLES:
        raise bindings_error("no role policy for " + safe_value(kind), path)
    if row is not None:
        check_role_model_class(kind, row["model_class"])
    model_class = PRODUCT_MODEL_CLASS
    binding = hosts.get((host, model_class)) if model_class is not None else None
    if model_class is not None and binding is None:
        raise bindings_error("no %s binding for host %s" % (model_class, safe_value(host)), path)
    model = options.get("model")
    if model is None:
        require(binding is not None, "no bound model can be determined; configure the governing model bindings")
        model = binding["model"]
        options = dict(options, model=model)
        record = dict(record or {"effort": options.get("effort"), "reasoning": options.get("effort"),
                                 "effort_from": "request", "reasoning_from": "request"})
        record.update(model=model, model_from="model-bindings.json")
    require(model is not None,
            "no model: set the request model or team.json model (%s binding for %s: %s)" %
            (model_class, host, binding["model"] if binding is not None else "choose a bound model"))
    band, effort = row["band"] if row is not None else None, options.get("effort")
    if effort is None:
        if band is not None:
            raise ValueError("%s has no effort; set %s (intent %s, band default) in request effort or team.json reasoning" %
                             (kind, binding["levels"][band["default"]], band["default"]))
        raise ValueError("%s has no effort; provide request effort or team.json reasoning; "
                         "host defaults are not allowed for an unbanded role" % kind)
    bound = [item for item in hosts.values() if item["model"] == model]
    model_binding = next((item for item in bound if item["host"] == host), None)
    if model_binding is None:
        source = record["model_from"] if record is not None else "request"
        if bound:
            raise ValueError("%s model %s needs host %s, not %s" %
                             (source, diagnostic_name(model), bound[0]["host"], host))
        raise ValueError("%s model %s is not bound for host %s; choose a model bound in model-bindings.json" %
                         (source, diagnostic_name(model), host))
    require(model_binding["class"] != "frontier" or
            (kind not in UNBANDED_MODEL_ROLES and model_class != "frontier"),
            "%s model %s has class frontier; frontier models are only for isolated turns, not long-lived seats" %
            (kind, diagnostic_name(model)))
    if binding is not None:
        require(model == binding["model"], "%s model %s has class %s, requires class %s; choose model %s" %
                (kind, diagnostic_name(model), model_binding["class"], binding["class"], binding["model"]))
    else:
        binding = model_binding
    reverse = {level: intent for intent, level in binding["levels"].items()}
    require(isinstance(effort, str) and effort in reverse,
            "%s effort %s has no supported intent; supported intents: %s; choose a supported effort" %
            (kind, diagnostic_name(effort), ", ".join(intent for intent in EFFORT_INTENTS if intent in binding["levels"])))
    intent = reverse[effort]
    repair = ("; set team.json reasoning_by_kind.%s to an in-band effort" % kind
              if record is not None and record["effort_from"] == "team.json" and
              record["reasoning_from"] == "default" else "")
    if band is not None:
        require(EFFORT_INTENTS.index(band["floor"]) <= EFFORT_INTENTS.index(intent) <= EFFORT_INTENTS.index(band["ceiling"]),
                "%s effort %s maps to intent %s outside band %s..%s; choose an effort within the band" %
                (kind, effort, intent, band["floor"], band["ceiling"]) + repair)
    admission = binding["admission"][intent]
    require(admission != "rejected", "%s intent %s (effort %s) is rejected for %s; choose a different supported level" %
            (binding["model"], intent, effort, host))
    record = dict(record or {"model": model, "effort": effort, "reasoning": effort, "model_from": "request",
                             "effort_from": "request", "reasoning_from": "request"})
    record.update(model=model, effort=effort, model_class=binding["class"], intent=intent,
                  band=dict(band) if band is not None else None,
                  bindings_sha256=sha256, admission=admission)
    if record["reasoning"] == "ultra":
        record["deprecated"] = "ultra"
    if fixed is not None:
        record.update(effort_from="registry", reasoning_from="registry")
    return options, dict(sorted(record.items()))


def canonical_team_file(base, mailbox_root):
    """Use the mailbox-root input of governing_plan, whose other lookup is this same mailbox parent."""
    canonical = Path(mailbox_root).parent
    path = canonical / "team.json"
    raw = team_file_bytes(path) if path.exists() or path.is_symlink() else None
    if base.resolve() != canonical.resolve():
        local = base / "team.json"
        local_raw = team_file_bytes(local) if local.exists() or local.is_symlink() else None
        require(local_raw is None or local_raw == raw,
                "copied base team.json differs from canonical team.json; use the governing mailbox's team.json")
    return path, raw


def team_config_values(team):
    fields(team, {"model", "reasoning"}, {"reasoning_by_kind"})
    model = text(team["model"], "team.json model", 128)
    by_kind = team.get("reasoning_by_kind", {})
    require(isinstance(by_kind, dict), "invalid team.json reasoning_by_kind")
    for key, level in by_kind.items():
        # A typo in a key would otherwise fall back to the default level without a word.
        require(key in TEAM_KINDS, "unknown role kind in team.json reasoning_by_kind: " + diagnostic_name(key))
        require(level in TEAM_LEVELS, "unknown reasoning level in team.json: " + diagnostic_name(level))
    require(team["reasoning"] in TEAM_LEVELS, "unknown reasoning level in team.json: " + diagnostic_name(team["reasoning"]))
    return model, by_kind


def governing_setup(mailbox_root, plan):
    home = safe_path(Path(mailbox_root).parent)
    governing = read_json(home / "provision.json")
    require(isinstance(governing, dict) and governing.get("schema") == SCHEMA and
            governing.get("initiative") == plan["hierarchy"] and
            governing.get("mailbox_root") == str(mailbox_root),
            "governing provision record does not match this run; reprovision the base")
    require(isinstance(governing.get("source"), str) and bool(governing["source"]) and
            all(isinstance(governing.get(key), str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", governing[key])
                for key in ("source_commit", "source_tree")),
            "governing provision record has an invalid source pin; reprovision the base")
    return governing, home


def team_settings(base, host, request, kind=None, plan=PLAN_UNSET, mailbox_root=None):
    """Resolve argv options and provenance; planned settings belong to the governing mailbox, not a copied base."""
    # Direct callers (including team up's preflight) must get the same checks as actual starts. Entry points
    # also validate before applying registry-fixed effort, so invalid request intents keep their own diagnostic.
    check_model_request(request)
    if plan is PLAN_UNSET:
        setup = read_json(base / "provision.json")
        check_governing_pin(setup, base)
        require(isinstance(setup, dict) and {"mailbox_root", "initiative"} <= setup.keys(),
                "invalid provision.json: missing mailbox_root or initiative")
        mailbox_root = setup["mailbox_root"]
        plan = delegated_read("host-plan.json", hierarchy_hosts.governing_plan,
                              base, mailbox_root, setup["initiative"])
    elif plan is not None:
        check_governing_pin(read_json(base / "provision.json"), base)
    if plan is not None:
        endpoint = request.get("endpoint")
        if endpoint is None and kind == "front-door":
            endpoint = plan["hierarchy"] + "/front-door"
        if endpoint is not None:
            expected, stand_in = hierarchy_hosts.plan_host(plan, endpoint)
            require(expected is not None, "endpoint is not covered by the governing host plan")
            label = endpoint
        else:
            expected = plan["root"] if kind == "root" else plan["team"]
            stand_in = False
            label = diagnostic_name(kind) if kind is not None else "role"
        require(host == expected, "%s runs on %s in this run's host plan, not %s" %
                (label, expected, diagnostic_name(host)))
        require(not stand_in, "%s is a stand-in binding that never runs a host; use add-role to register it" % label)
        host = expected
    fixed = None
    if plan is not None:
        entry = hierarchy_roles.registry()["roles"].get(kind) if isinstance(kind, str) else None
        if entry is not None and entry["endpoint"] is not None:
            request, fixed = apply_fixed_profile(request, hierarchy_roles.fixed_model_profile(entry),
                                                 host, entry["endpoint"]["role"])
    full_request = "model" in request and "effort" in request
    if plan is None and full_request:
        return request, None
    if plan is not None:
        if mailbox_root is None:
            mailbox_root = read_json(base / "provision.json")["mailbox_root"]
        governing, home = governing_setup(mailbox_root, plan)
    if plan is not None and kind == "root":
        read_pinned_bindings(governing, home)
        # ROOT is owner-chosen, recorded rather than resolved from the team's settings. Keep complete explicit
        # requests' existing return shape; otherwise name the host defaults for dimensions the owner left out.
        if full_request:
            return request, None
        effort = request.get("effort")
        return request, {"model": request.get("model"), "model_from": "request" if "model" in request else "host-default",
                         "effort": effort, "effort_from": "request" if "effort" in request else "host-default",
                         "reasoning": effort, "reasoning_from": "request" if "effort" in request else "host-default"}
    try:
        if plan is not None:
            # Provision/start callers pass the exact mailbox_root they supplied to governing_plan. Direct callers
            # obtain that same input from the provision record, including a record copied to another folder.
            if mailbox_root is None:
                mailbox_root = read_json(base / "provision.json")["mailbox_root"]
            path, raw = canonical_team_file(base, mailbox_root)
            if raw is not None:
                team = json_document(raw, path)
                model, by_kind = team_config_values(team)
        else:
            path = base / "team.json"
            if not path.exists():
                return request, None
            team = json_document(team_file_bytes(path), path)
            model, by_kind = team_config_values(team)
    except JSON_FAILURES as exc:
        raise ValueError(str(exc)) from exc
    # No bindings read or parse without a plan; planned team files have already been strictly validated.
    bindings = None
    if plan is not None and kind not in MODEL_POLICY_EXEMPT_ROLES:
        bindings = load_model_bindings(governing, home)
    if (plan is not None and raw is None and kind in TEAM_KINDS and
            "model" not in request and "effort" not in request):
        # MR-1b waives band enforcement for banded defaults, never canonical source/policy verification.
        return request, None
    if full_request or (plan is not None and raw is None):
        return planned_model_settings(bindings, host, kind, request, None, fixed) if bindings is not None else (request, None)
    reasoning = by_kind.get(kind, team["reasoning"])
    if "model" not in request and plan is None:
        # A mismatch means team.json and the role hosts disagree, which the owner resolves; never start the role
        # anyway. A request that names its own model does not use the team's, so only the reasoning applies.
        wanted = CLAUDE if model.startswith("claude-") else CODEX
        require(wanted == host, "team.json model %s needs host %s, not %s" % (diagnostic_name(model), wanted, host))
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
    if bindings is not None:
        return planned_model_settings(bindings, host, kind, options, record, fixed)
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
    # Left out when there is nothing to allow (a reader's start, which has no MCP servers): no real host has been shown
    # to accept an empty rule word, and a separate empty --tools value already failed on one. add-role always allows
    # the mailbox tools, so its argv is unchanged.
    if allowed:
        argv += ["--allowedTools", ",".join(allowed)]
    # The variadic --allowedTools swallowed a trailing prompt on a real host. A background start takes its
    # prompt as an argument, so the options end first.
    return argv + (["--"] if name is not None else [])


def fixed_profile(request, mailbox, endpoint, host):
    """A role whose registry profile is fixed always runs at that effort, whatever team.json says.

    Codex takes the tier as service_tier. Claude has no tier flag, so there the answer says it is recorded and not
    applied. Whether a host serves the tier is a separate probe.
    """
    profile = hierarchy_roles.fixed_model_profile(registry_role(mailbox, endpoint))
    return apply_fixed_profile(request, profile, host, endpoint_parts(endpoint)[1])


def apply_fixed_profile(request, profile, host, label):
    """One fixed-effort rule for actual starts and direct planned resolver calls."""
    if profile is None:
        return request, None
    effort = profile["effort"]
    require(request.get("effort", effort) == effort,
            "the %s role runs at effort %s from the role registry" % (label, effort))
    tier = profile.get("tier")
    return {**request, "effort": effort}, {"source": "registry", "effort": effort, "tier": tier,
                                           "tier_applied": host == CODEX and tier is not None}


def applied_tier(fixed):
    return fixed["tier"] if fixed is not None and fixed["tier_applied"] else None


def role_tools(endpoint, mailbox, requested):
    entry = registry_role(mailbox, endpoint)
    writer = hierarchy_roles.writer(entry)
    if requested is not None:
        names = [name for name in text(requested, "tools").split(",") if name]
        for name in names:
            require(name in SUPPORTED_TOOLS, "unsupported tool: " + name)
        hierarchy_roles.require_file_tools(endpoint, mailbox.endpoint(endpoint).get("kind"), names)
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
                "reader_shell is only for a Codex reviewer, orchestrator or decider")
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


def journal_policy(lifecycle):
    import hierarchy_lifecycle
    path = safe_path(text(lifecycle, "lifecycle"))
    require(path.is_dir(), "lifecycle is not a journal directory: " + str(path))
    policy = delegated_read("lifecycle policy", hierarchy_lifecycle.load_json, path / "policy.json")
    return delegated_read("lifecycle policy", hierarchy_lifecycle.validate_policy, policy)


def check_lifecycle(request, mailbox, endpoint):
    """A role's journal connection follows its registry entry. ROOT's decision adapter and the Decider act as one
    policy actor; the Router reads status and acts as none. Every other role is refused the journal."""
    # By key presence, as add_role and lifecycle_args decide, so a null is checked and refused, never passed on.
    if "lifecycle" not in request and "actor" not in request:
        return
    lifecycle, actor = request.get("lifecycle"), request.get("actor")
    kind = mailbox.endpoint(endpoint).get("kind")
    entry = hierarchy_roles.role(endpoint, kind)
    tools = hierarchy_roles.lifecycle_tools(entry)
    if "router_status" in tools:
        require("actor" not in request, ROUTER_TAKES_NO_ACTOR)
        journal_policy(lifecycle)
        return
    acting = "root" if entry["provision"]["adapter"] == "decision" else "decider" if "decider_record" in tools else None
    require(acting is not None, "the %s role has no lifecycle connection" % hierarchy_roles.role_name(endpoint, kind))
    require("lifecycle" in request and "actor" in request, LIFECYCLE_PAIR)
    matching(actor, SLUG, "actor")
    found = journal_policy(lifecycle)["actors"].get(actor)
    require(found is not None and found["role"] == acting,
            "actor %s is not a %s actor in the lifecycle policy" % (actor, acting))


def check_root_reads(request, endpoint):
    """The folders ROOT's team_status reads. They need not exist yet: the loop and the evidence come after ROOT."""
    names = [name for name in ("loop_state", "evidence") if name in request]
    if not names:
        return
    require(endpoint_parts(endpoint)[1] == "root" and "lifecycle" in request and "actor" in request, ROOT_READS)
    for name in names:
        safe_path(text(request[name], name))


def check_role_request(request, setup):
    fields(request, {"base", "endpoint", "host"}, {"session", "cwd", "tools", "add_dirs", "model", "effort", "timeout_seconds", "assistants",
                                                   "reader_shell", "writable_roots", "tmpdir", "skip_git_repo_check", "background",
                                                   "kind", "source_repo", "lifecycle", "actor", "loop_state", "evidence"})
    host = request["host"]
    require(host in (CLAUDE, CODEX, NATIVE), "unsupported host: " + str(host))
    require(type(request.get("background", False)) is bool, "invalid background")
    if request.get("background"):
        # Root has no profile, and a Codex lane shows in its own app only as a native thread.
        require(host == CLAUDE and endpoint_parts(request["endpoint"])[1] != "root",
                "background is only for claude-code roles")
    mailbox = delegated_read("mailbox manifest", Mailbox, setup["mailbox_root"])
    if "kind" in request:
        mailbox.require_kind(request["endpoint"], request["kind"])
    check_codex_options(request, mailbox, request["endpoint"], host)
    check_lifecycle(request, mailbox, request["endpoint"])
    check_root_reads(request, request["endpoint"])
    if "source_repo" in request:
        # Before binding, so a refused option leaves the endpoint unbound.
        require(endpoint_parts(request["endpoint"])[1] != "root", "the ROOT decision adapter takes no source views")
        hierarchy_roles.require_source_views(request["endpoint"], mailbox.endpoint(request["endpoint"]).get("kind"))
        repository = safe_path(text(request["source_repo"], "source_repo"))
        require(repository.is_absolute() and git(repository, "rev-parse", "--show-toplevel").returncode == 0,
                "source_repo must be an absolute path to a git repository")
    check_model_request(request)
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


def write_roots(cwd, request):
    """The folders a writer's host is told it may write, as real paths, once each and in order.

    A team run's Claude role takes no writable_roots, add_dirs or tmpdir (check_codex_options, TEAM_CLAUDE_REFUSED), so
    for it this is the cwd alone.
    """
    roots = []
    for folder in [cwd, *request.get("writable_roots", []), *request.get("add_dirs", []),
                   *([request["tmpdir"]] if "tmpdir" in request else [])]:
        real = str(Path(folder).resolve())
        if real not in roots:
            roots.append(real)
    return roots


def check_host_plan(plan, request, mailbox, endpoint, cwd):
    """(write scope, stand-in) under the run's host plan, before binding, so a refusal leaves the endpoint unbound."""
    host = request["host"]
    writer = hierarchy_roles.writer(registry_role(mailbox, endpoint))
    scope = hierarchy_hosts.require_binding(plan, endpoint, host, writer)
    stand_in = hierarchy_hosts.plan_host(plan, endpoint)[1]
    if host == CLAUDE and not stand_in:
        for key in TEAM_CLAUDE_REFUSED:
            require(not request.get(key), "%s: a claude-code role in a team run takes no %s" % (endpoint, key))
    if writer and not stand_in:
        scope["roots"] = write_roots(cwd, request)
    return scope, stand_in


def planned(folder):
    path = folder / hierarchy_hosts.PLAN_FILE
    return path.exists() or path.is_symlink()


def session_folder(base):
    """<base>/sessions, made before anything binds: a record that cannot be written must not leave a bound endpoint."""
    folder = base / "sessions"
    if not folder.exists() and not folder.is_symlink():
        folder.mkdir(mode=0o700)
    require(folder.is_dir() and not folder.is_symlink(), "session records need a real folder: " + str(folder))


def write_role_file(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def generation_model_profile(request, team, configuration):
    """ADR session metadata plus the complete effective configuration that the generation freezes."""
    team = team or {}
    model, effort = request.get("model"), request.get("effort")
    return {"model_class": team.get("model_class"), "model": model, "intent": team.get("intent"),
            "native_effort": effort, "band": team.get("band"),
            "model_from": team.get("model_from", "request" if model is not None else "host-default"),
            "effort_from": team.get("effort_from", "request" if effort is not None else "host-default"),
            "reasoning_from": team.get("reasoning_from", "request" if effort is not None else "host-default"),
            "bindings_sha256": team.get("bindings_sha256"), "signals": [],
            "ultracode": bool(request.get("ultracode", False)), "launch_config": configuration}


def first_selection_provenance(profile, path):
    """Equivalent settings keep the original generation's provenance; they never rewrite history."""
    if not path.exists() and not path.is_symlink():
        return profile
    previous = delegated_read("session record", hierarchy_hosts.read_json, path)
    previous = previous.get("model_profile") if isinstance(previous, dict) else None
    sources = {"model_from": {"request", "team.json", "model-bindings.json", "host-default"},
               "effort_from": {"request", "team.json", "registry", "host-default"},
               "reasoning_from": {"request", "kind", "default", "registry", "host-default"}}
    if (not isinstance(previous, dict) or set(previous) != set(profile) or
            any(previous[key] != value for key, value in profile.items() if key not in sources) or
            any(not isinstance(previous[key], str) or previous[key] not in allowed
                for key, allowed in sources.items())):
        return profile
    return {**profile, **{key: previous[key] for key in sources}}


def add_role(request):
    base = safe_path(text(request.get("base"), "base"))
    setup = read_json(base / "provision.json")
    check_governing_pin(setup, base)
    delegated_read("runtime source", hierarchy_runtime_source.verify, setup, base)
    require_interpreter(setup.get("python"), registered=True)
    mailbox = delegated_read("mailbox manifest", Mailbox, setup["mailbox_root"])
    endpoint = request.get("endpoint")
    mailbox.endpoint(endpoint)
    cwd, timeout, assistants = check_role_request(request, setup)
    host = request["host"]
    plan = delegated_read("host-plan.json", hierarchy_hosts.governing_plan, base, setup["mailbox_root"], setup["initiative"])
    scope, stand_in = check_host_plan(plan, request, mailbox, endpoint, cwd) if plan is not None else (None, False)
    if plan is not None and (stand_in or endpoint_parts(endpoint)[1] == "root"):
        governing, home = governing_setup(setup["mailbox_root"], plan)
        read_pinned_bindings(governing, home)
    team = None
    fixed = None
    if host in (CLAUDE, CODEX) and endpoint_parts(endpoint)[1] != "root" and not stand_in:
        request, fixed = fixed_profile(request, mailbox, endpoint, host)
        # Before binding, so a bad team.json leaves the endpoint unbound.
        request, team = team_settings(base, host, request, role_kind(mailbox, endpoint), plan=plan,
                                     mailbox_root=setup["mailbox_root"])
    session = request.get("session") or str(uuid.uuid4())
    tools, writer = role_tools(endpoint, mailbox, request.get("tools"))
    profile_options = dict(setup=setup, base=base, mailbox=mailbox, endpoint=endpoint, host=host, session=session,
                           request=request, cwd=cwd, timeout=timeout, assistants=assistants, tools=tools,
                           writer=writer, fixed=fixed, stand_in=stand_in)
    prepared = None
    root = Path(setup["mailbox_root"])
    with writer_lock(root):
        # Also checked inside bind; here as well, so re-running add-role on an existing binding is checked too.
        delegated_read("mailbox records", hierarchy_roles.require_independent_session,
                       delegated_read("mailbox manifest", Mailbox, root), endpoint, host, session)
        history = delegated_read("mailbox records", mailbox.bindings, endpoint)
        if history:
            require(history[-1]["session"] == session and history[-1]["host"] == host,
                    "endpoint is bound to another session; hand it off first")
        staged = None
        if scope is not None:
            # A new binding is generation 1 (expected_generation 0). Everything is checked and the record staged before
            # binding, so a sessions folder that is not real or not writable, or a conflicting record, leaves a new
            # endpoint unbound. A handed-off successor is recorded here too, by the add-role that builds its connection
            # and profile. Beside the mailbox, whichever base names it, so each generation has one record.
            home = root.parent
            session_folder(home)
            record = hierarchy_hosts.session_record(
                endpoint, hierarchy_roles.role_name(endpoint, mailbox.endpoint(endpoint).get("kind")), host,
                hierarchy_hosts.team_start_mode(host, stand_in, request.get("background", False)), session,
                history[-1]["generation"] if history else 1, stand_in, scope)
            if not stand_in and ("model" in request or "effort" in request):
                # Freeze the same rendering that will be published, not request spelling or provenance.
                # MR-1b keeps its all-default record shape; plan-less calls create no session record.
                files = {}

                def collect(output, value):
                    files[output] = value

                profile_answer = render_role_profile(generation=record["generation"], emit=collect, **profile_options)
                prepared = profile_answer, files
                locations = ("connection", "codex_profile", "wake_profile", "board_connection")
                configuration = {
                    "runtime_pin": {key: setup[key] for key in ("source_commit", "source_tree")},
                    "launch": {key: value for key, value in profile_answer.items() if key not in locations},
                    "files": {str(output.relative_to(base)): value for output, value in files.items()}}
                record["model_profile"] = generation_model_profile(request, team, configuration)
            record_path = hierarchy_hosts.session_record_path(home, endpoint, record["generation"])
            if "model_profile" in record:
                record["model_profile"] = first_selection_provenance(record["model_profile"], record_path)
            if not delegated_read("session record", hierarchy_hosts.session_recorded, record_path, record):
                staged = record_path.with_name(".staged-%s-%s" % (uuid.uuid4().hex, record_path.name))
                publish_file(staged, encoded(record) + b"\n")
        try:
            if history:
                binding = history[-1]
            else:
                binding = delegated_read("mailbox records", mailbox.bind,
                                         {"endpoint": endpoint, "host": host, "session": session,
                                          "expected_generation": 0})
            if staged is not None:
                # A hard link publishes the whole record under its final name, and never over another one.
                os.link(staged, record_path)
        finally:
            if staged is not None:
                staged.unlink()
    generation = binding["generation"]
    answer = {"endpoint": endpoint, "host": host, "session": session, "generation": generation}
    if team is not None:
        answer["team"] = team
    if fixed is not None:
        answer["model_profile"] = fixed
    if prepared is None:
        answer.update(render_role_profile(generation=generation, emit=write_role_file, **profile_options))
    else:
        profile_answer, files = prepared
        for output, value in files.items():
            write_role_file(output, value)
        answer.update(profile_answer)
    return answer


def render_role_profile(setup, base, mailbox, endpoint, host, session, generation, request, cwd,
                        timeout, assistants, tools, writer, fixed, stand_in, emit):
    """Render every output through emit, so selected planned settings can be compared without writing."""
    answer = {"endpoint": endpoint, "host": host, "session": session, "generation": generation}
    stem = endpoint.replace("/", "%2F") + "-g%d" % generation
    connection = base / "connections" / (stem + ".json")
    if endpoint_parts(endpoint)[1] == "root":
        return root_connection(setup, connection, answer, request, emit=emit) if "lifecycle" in request else answer
    if stand_in:
        answer["stand_in"] = True
    role_extra = role_workspace_tools(mailbox, endpoint)
    source_repo = request.get("source_repo")
    entry = registry_role(mailbox, endpoint)
    enabled = (MAILBOX_TOOLS + list(role_extra) + (list(hierarchy_roles.SOURCE_VIEW_TOOLS) if source_repo else []) +
               (list(hierarchy_roles.lifecycle_tools(entry)) if "lifecycle" in request else []))
    journal = lifecycle_args(request)
    arguments = adapter_args(setup, endpoint, host, session, generation, source_repo, journal)
    board = takes_board(setup, mailbox, endpoint)
    if host == NATIVE:
        # The flat form a native thread's own script reads, as in the live connection files.
        emit(connection, {"command": setup["python"], "args": arguments})
        answer.update(connection=str(connection), wake="native")
        if board:
            board_connection = base / "connections" / (stem + ".board.json")
            emit(board_connection, {"command": setup["python"],
                                    "args": board_args(setup, endpoint, host, session, generation)})
            answer["board_connection"] = str(board_connection)
        return answer
    servers = {"aegis_mailbox": {"command": setup["python"], "args": arguments}}
    if board:
        servers["aegis_board"] = {"command": setup["python"], "args": board_args(setup, endpoint, host, session, generation)}
    emit(connection, {"mcpServers": servers})
    if stand_in:
        # Keep the registered session's connection, but never create host argv or executable profiles.
        return {**answer, "connection": str(connection), "cwd": str(cwd),
                "prompt_via": "stdin" if host == CLAUDE else "argv"}
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
        servers = codex_servers(setup, arguments, enabled,
                                board_args(setup, endpoint, CODEX, session, generation) if board else None)
        profile = codex_profile(str(cwd), writer=writer, servers=servers, options=request, endpoint=endpoint,
                                role=hierarchy_roles.role_name(endpoint, mailbox.endpoint(endpoint).get("kind")),
                                session=session, generation=generation, tier=applied_tier(fixed))
        codex_record = base / "profiles" / (stem + ".codex.json")
        emit(codex_record, profile)
        answer["codex_profile"] = str(codex_record)
        wake_argv = codex_argv(profile, ["resume", session])
        prompt_via = "argv"
    wake_profile = base / "profiles" / (stem + ".wake.json")
    profile = {"schema": "aegis.hierarchy-wake-profile/v1", "endpoint": endpoint, "host": host, "session": session,
               "generation": generation, "argv": wake_argv, "cwd": str(cwd), "timeout_seconds": timeout,
               "prompt_via": prompt_via}
    if host == CLAUDE and request.get("background"):
        profile.update(mode="background", control=["claude"])
    emit(wake_profile, profile)
    return {**answer, "connection": str(connection), "wake_profile": str(wake_profile), "cwd": str(cwd),
            "prompt_via": prompt_via}


def root_connection(setup, connection, answer, request, emit=write_role_file):
    """The supervisor never wakes ROOT, so it gets a connection and no wake profile."""
    host = answer["host"]
    arguments = decision_args(setup, answer["endpoint"], host, answer["session"], answer["generation"], request)
    server = {"command": setup["python"], "args": arguments}
    # A native thread's own script reads the flat form, as for every other role.
    written = server if host == NATIVE else {"mcpServers": {"aegis_decision": server}}
    emit(connection, written)
    answer = {**answer, "connection": str(connection)}
    if host == CODEX:
        enabled = [DECISION_TOOL, *hierarchy_roles.decision_tools(registry_role(delegated_read("mailbox manifest", Mailbox, setup["mailbox_root"]),
                                                                                answer["endpoint"]))]
        # ROOT runs with approval_policy "never", where a tool without an approve entry may be refused rather than
        # asked; the read tools get the entry too, so none depends on how the host treats readOnlyHint.
        answer["mcp_config"] = "mcp_servers=" + toml_value({"aegis_decision": {
            **server, "required": True, "enabled_tools": enabled, "tools": {name: APPROVE for name in enabled}}})
    return answer


def codex_start(request):
    fields(request, {"base", "endpoint"}, {"cwd", "reader_shell", "writable_roots", "tmpdir", "add_dirs", "model", "effort", "skip_git_repo_check"})
    base = safe_path(text(request["base"], "base"))
    setup = read_json(base / "provision.json")
    check_governing_pin(setup, base)
    delegated_read("runtime source", hierarchy_runtime_source.verify, setup, base)
    mailbox = delegated_read("mailbox manifest", Mailbox, setup["mailbox_root"])
    mailbox.endpoint(request["endpoint"])
    check_codex_options(request, mailbox, request["endpoint"], CODEX)
    check_model_request(request)
    request, fixed = fixed_profile(request, mailbox, request["endpoint"], CODEX)
    plan = delegated_read("host-plan.json", hierarchy_hosts.governing_plan, base, setup["mailbox_root"], setup["initiative"])
    options, team = team_settings(base, CODEX, request, role_kind(mailbox, request["endpoint"]), plan=plan,
                                  mailbox_root=setup["mailbox_root"])
    writer = hierarchy_roles.writer(registry_role(mailbox, request["endpoint"]))
    cwd = safe_path(text(request.get("cwd", setup["source"]), "cwd"))
    if not request.get("skip_git_repo_check"):
        require(git(cwd, "rev-parse", "--is-inside-work-tree").returncode == 0, "codex needs a cwd inside a git checkout")
    # Returned, not written: the session and its generation exist only once add-role binds it.
    profile = codex_profile(str(cwd), writer=writer, servers={}, options=options, endpoint=request["endpoint"],
                            role=hierarchy_roles.role_name(request["endpoint"], mailbox.endpoint(request["endpoint"]).get("kind")),
                            tier=applied_tier(fixed))
    answer = {"start_argv": codex_argv(profile),
              "codex_profile": profile,
              "cwd": str(cwd),
              "prompt_via": "argv",
              "next": "Read the session ID from the first JSON event, then run add-role with that session."}
    if fixed is not None:
        answer["model_profile"] = fixed
    return {**answer, "team": team} if team is not None else answer


def claude_start(request):
    """A claude-code team role's start argv: print mode under the session the caller chose, no MCP servers, and the
    prompt on stdin. Like codex_start it binds nothing: the caller confirms the session started, then runs add-role."""
    # Codex-only options are named here so that they are refused with check_codex_options' reasons, not as unknown keys.
    fields(request, {"base", "endpoint", "session"}, {"cwd", "model", "effort", "reader_shell", "writable_roots", "tmpdir",
                                                      "skip_git_repo_check", "add_dirs"})
    base = safe_path(text(request["base"], "base"))
    setup = read_json(base / "provision.json")
    check_governing_pin(setup, base)
    delegated_read("runtime source", hierarchy_runtime_source.verify, setup, base)
    mailbox = delegated_read("mailbox manifest", Mailbox, setup["mailbox_root"])
    endpoint = request["endpoint"]
    mailbox.endpoint(endpoint)
    session = request["session"]
    require(isinstance(session, str) and UUID.fullmatch(session) is not None,
            "claude sessions need a UUID, which --session-id requires")
    check_codex_options(request, mailbox, endpoint, CLAUDE)
    # ADR T2(a) §4: the worktree is a Claude role's only writable folder.
    require("add_dirs" not in request, "%s: a claude-code start takes no add_dirs" % endpoint)
    check_model_request(request)
    request, fixed = fixed_profile(request, mailbox, endpoint, CLAUDE)
    plan = delegated_read("host-plan.json", hierarchy_hosts.governing_plan, base, setup["mailbox_root"], setup["initiative"])
    options, team = team_settings(base, CLAUDE, request, role_kind(mailbox, endpoint), plan=plan,
                                  mailbox_root=setup["mailbox_root"])
    tools, _ = role_tools(endpoint, mailbox, None)
    cwd = safe_path(text(request.get("cwd", setup["source"]), "cwd"))
    # Codex's requirement, kept so both hosts start a role in the same kind of folder.
    require(git(cwd, "rev-parse", "--is-inside-work-tree").returncode == 0,
            "a claude-code start needs a cwd inside a git checkout")
    connection = base / "connections" / (endpoint.replace("/", "%2F") + ".start.json")
    connection.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    connection.write_text(json.dumps({"mcpServers": {}}, indent=2) + "\n", encoding="utf-8")
    # No mailbox tools to allow, since the start has no servers: only a writer's edit tools.
    allowed = [name for name in tools if name in WRITE_TOOLS]
    answer = {"start_argv": claude_argv(["--session-id", session], str(connection), tools, allowed, options, None, None),
              "cwd": str(cwd),
              "prompt_via": "stdin",
              "session": session,
              "next": "Send the prompt on stdin, confirm the session from the init event and its transcript, then run "
                      "add-role with that session."}
    if fixed is not None:
        answer["model_profile"] = fixed
    return {**answer, "team": team} if team is not None else answer


def old_root_state(old_root, hierarchy):
    """Everything read from a live root, which this never writes to. A held lock means unsure, so it refuses."""
    old = delegated_read("mailbox manifest", Mailbox, safe_path(text(old_root, "old_root")))
    names = sorted(name for name in old.manifest["endpoints"] if name.split("/")[0] == hierarchy)
    require(bool(names), "the old root has no such hierarchy: " + str(hierarchy))
    locks = [old.root / ".write.lock", *old.root.glob(".wake-" + hierarchy + "%2F*.lock")]
    busy = [path.name for path in locks if path.exists()]
    require(not busy, "the old root is busy (%s); try again once that finishes" % ", ".join(busy))
    records = delegated_read("mailbox records", old.messages)
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
        ledger = delegated_read("workspace record", store.load)
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
        history = delegated_read("mailbox records", old.bindings, name)
        now = delegated_read("mailbox records", new.bindings, name) if name in new.manifest["endpoints"] else []
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
        from hierarchy_mailbox import read_bytes
        lines += ["", "## Open job requests", "",
                  "These original requests have no terminal receipt. Their effects may be running, completed or uncertain; "
                  "moving the mailbox does not settle them.",
                  "Before any new request, ask the operator to identify and verify the original workspace store and reconcile "
                  "the original claims, results, receipts and reservations.",
                  "Inspect that store with tools/hierarchy_jobs.py --store <original-workspace-store> recovery-status --initiative " +
                  record["hierarchy"] + ". This report is read-only and does not settle or restart jobs.",
                  "Do not submit a new request, replay work or release reservations from missing replies or a mailbox move. "
                  "If the original store cannot be verified, hold for operator reconciliation.", ""]
        requests = {row["message"]["message_id"]: row for row in in_order}
        for identifier in record["open_job_requests"]:
            row = requests[identifier]
            sha256 = hashlib.sha256(read_bytes(row["path"])).hexdigest()
            lines.append("- %s/%s: original request %s sha256 %s" % (
                record["hierarchy"], identifier, row["path"], sha256))
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
    delegated_read("workspace record", Store(setup["store"]).load).initiative(hierarchy)
    replaced = request.get("replaced", {})
    require(isinstance(replaced, dict) and all(isinstance(reason, str) and reason for reason in replaced.values()), "invalid replaced")
    store = Store(setup["store"])
    new = delegated_read("mailbox manifest", Mailbox, setup["mailbox_root"])
    root_endpoint, orchestrator = hierarchy + "/root", hierarchy + "/orchestrator"
    require(bool(delegated_read("mailbox records", new.bindings, root_endpoint)) and
            bool(delegated_read("mailbox records", new.bindings, orchestrator)),
            "bind root and the orchestrator in the new root first")
    folder = base / "carried"
    record_path = folder / "carry.json"
    if record_path.exists():
        record = read_json(record_path, limit=MAX_RECORDS * 1024)
        require(record["old_root"] == request["old_root"] and record["hierarchy"] == hierarchy, "this initiative was carried from somewhere else")
    else:
        old, names, in_order, dispatches, jobs = old_root_state(request["old_root"], hierarchy)
        for name in names:
            history = delegated_read("mailbox records", old.bindings, name)
            if not history:
                continue
            require(name in new.manifest["endpoints"], "the new root has no endpoint " + name)
            bound = delegated_read("mailbox records", new.bindings, name)
            require(bool(bound), name + " is bound in the old root but not in the new one; run add-role for it first")
            if bound[-1]["session"] != history[-1]["session"]:
                require(name in replaced, name + " is bound to another session in the new root; name it under replaced if that is intended")
        with store.lock():
            require_writer_room(delegated_read("workspace record", store.load), dispatches)
        carried = []
        for row in dispatches:
            raw = delegated_read("mailbox records", old.brief, row["old_brief"])
            sha256 = hashlib.sha256(raw).hexdigest()
            path = folder / (sha256 + ".md")
            if not path.exists():
                publish_file(path, raw)
            carried.append({key: row[key] for key in ("dispatch", "lane", "accepted", "readiness")} | {
                "brief": {"path": str(path), "sha256": sha256}, "old_brief": row["old_brief"]})
        record = {"schema": CARRY_SCHEMA, "at": timestamp(), "old_root": request["old_root"], "hierarchy": hierarchy, "endpoints": names,
                  "generations": {name: delegated_read("mailbox records", old.bindings, name)[-1]["generation"]
                                  for name in names if delegated_read("mailbox records", old.bindings, name)},
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
        current = delegated_read("mailbox manifest", Mailbox, new.root)
        if message_id not in delegated_read("mailbox records", current.messages):
            binding = delegated_read("mailbox records", current.current_binding, root_endpoint)
            delegated_read("mailbox records", current.publish,
                           {"message_id": message_id, "from": root_endpoint, "to": orchestrator,
                             "host": binding["host"], "session": binding["session"],
                             "binding_generation": binding["generation"], "type": "brief", "brief": record["brief"],
                             "body": "This initiative moved to this mailbox root. The attached brief lists the work that came with it."})
    return {"hierarchy": hierarchy, "brief": record["brief"], "message_id": message_id, "old_root": record["old_root"], "replaced": record["replaced"],
            "open_dispatches": [{key: row[key] for key in ("dispatch", "lane", "accepted", "brief", "readiness")} for row in record["open_dispatches"]],
            "open_job_requests": record["open_job_requests"], "messages_seen": len(record["message_ids"])}


def move(request):
    """One idempotent command per hierarchy, so a rotating root repeats exactly what was rehearsed."""
    fields(request, {"store", "base", "source", "old_root", "hierarchy", "note", "root", "initiative"}, {"board", "python", "roles", "replaced"})
    if "python" in request:
        text(request["python"], "python")
    hierarchy, note = request["hierarchy"], request["note"]
    text(note, "note")
    fields(request["root"], {"host", "session"})
    # Root rotates often, so a prepared request leaves a placeholder that must not get bound by accident.
    require(isinstance(request["root"]["session"], str) and UUID.fullmatch(request["root"]["session"]) is not None,
            "root needs the actual session ID of the active root")
    old = delegated_read("mailbox manifest", Mailbox, safe_path(text(request["old_root"], "old_root")))
    # A moved base would carry no plan, so its sessions would bind unchecked: a team run starts over instead.
    require(not planned(old.root.parent), "a planned team hierarchy cannot be moved; start a new team run")
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
    # A move binds without the plan check, so it must not land where a plan governs, through the base or its mailbox.
    homes = [base]
    if (base / "provision.json").is_file():
        named = read_json(base / "provision.json")
        mailbox_root = named.get("mailbox_root") if isinstance(named, dict) else None
        require(isinstance(mailbox_root, str), "invalid provision.json in " + str(base))
        homes.append(Path(mailbox_root).parent)
    require(not any(planned(home) for home in homes),
            "a move cannot go into a planned team hierarchy; start a new team run")
    if hierarchy not in delegated_read("workspace record", Store(text(request["store"], "store")).load).initiatives:
        # Sets it up, or finishes registering a setup that an earlier run left unregistered.
        lanes = {name.split("/")[2]: spec["kind"] for name, spec in endpoints.items() if name.split("/")[1] == "lane"}
        optional = [role for role in OPTIONAL_ROLES if hierarchy + "/" + role in endpoints]
        init({key: request[key] for key in ("store", "base", "source") } | {
            "lanes": lanes, "initiative": {**initiative, "id": hierarchy},
            **({"roles": optional} if optional else {}),
            **{key: request[key] for key in ("board", "python") if key in request}})
    setup = read_json(base / "provision.json")
    require_interpreter(setup.get("python"), registered=True)
    require("python" not in request or request["python"] == setup["python"], "python does not match provision.json")
    new = delegated_read("mailbox manifest", Mailbox, setup["mailbox_root"])
    answers, needs_profile, tell = {}, [], {}
    for name in sorted(endpoints):
        history = delegated_read("mailbox records", old.bindings, name)
        if not history:
            continue
        current = replaced.get(name) or {"host": history[-1]["host"], "session": history[-1]["session"]}
        options = {"base": str(base), "endpoint": name, "host": current["host"], "session": current["session"], **roles.get(name, {})}
        if current["host"] != NATIVE and name not in roles:
            # An idle lane has no worktree to run in, and defaulting a writer to the pinned tools checkout
            # could let it edit the code every adapter runs. So it is bound now and profiled when assigned.
            with writer_lock(new.root):
                bound = delegated_read("mailbox records", delegated_read("mailbox manifest", Mailbox, new.root).bindings, name)
                if not bound:
                    delegated_read("mailbox records", delegated_read("mailbox manifest", Mailbox, new.root).bind,
                                   {"endpoint": name, "host": current["host"], "session": current["session"],
                                    "expected_generation": 0})
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
    record = read_json(path, limit=MAX_RECORDS * 1024)
    old = delegated_read("mailbox manifest", Mailbox, record["old_root"])
    names, seen = set(record["endpoints"]), set(record["message_ids"])
    late = sorted(({"message_id": identifier, "type": row["message"]["type"], "from": row["message"]["from"], "to": row["message"]["to"],
                    "created_at": row["message"]["created_at"], "path": row["path"]}
                   for identifier, row in delegated_read("mailbox records", old.messages).items()
                   if identifier not in seen and (row["message"]["from"] in names or row["message"]["to"] in names)),
                  key=lambda row: row["created_at"])
    changed = sorted(name for name in record["endpoints"]
                     if delegated_read("mailbox records", old.bindings, name) and
                     delegated_read("mailbox records", old.bindings, name)[-1]["generation"] != record["generations"].get(name))
    return {"clean": not late and not changed, "late_messages": late, "changed_bindings": changed}


COMMANDS = {"init": init, "add-role": add_role, "codex-start": codex_start, "carry": carry, "carry-check": carry_check, "move": move}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("--request", required=True, help="Absolute path to a strict JSON request")
    args = parser.parse_args(argv)
    try:
        result = COMMANDS[args.command](read_json(args.request))
    except (ValueError, OSError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 3 if args.command == "carry-check" and not result["clean"] else 0


if __name__ == "__main__":
    sys.exit(main())
