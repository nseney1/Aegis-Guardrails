"""Diagnosis for ``aegis doctor``: host rows, the PreToolUse hook rows, the findings, the enforcement
tiers and the run's diagnosis.

Hosts are asked only through the run's prober and files are read only through the run context
(``aegis_cli.doctor_base``); repairing and printing live in doctor_repair and doctor_render."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from aegis_cli import doctor_base as _base
from aegis_cli.doctor_base import (
    _Action, _Ctx, _File, _Finding, _HookStatus, _Instructions, _claude_config, _claude_dir,
    _claude_user_registered, _desktop_configs, _host_json_path, _instruction_files, _instructions, _legacy_items,
    _legacy_ranges, _list_location, _location, _path_key, _registered_roots, _removed_host_phases, _without_lines,
)
from aegis_core import human_gate
from aegis_core.pathlookup import is_bare
from aegis_core.primitives import real_key
from aegis_core.verification.ast_checks import driver_availability as _ast_driver_state


# ── Host plane: instruction files ───────────────────────────────────────────

def _claude_reads_agents(info: _Instructions) -> bool:
    return any(f.is_agents or f.imports_agents for f in info.claude)


def _claude_names(info: _Instructions) -> str:
    names = [f.name for f in info.claude]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def _claude_import_advice(info: _Instructions) -> str:
    """How to make Claude Code read AGENTS.md. aegis init adds the import only to a
    CLAUDE.md at the root, and never writes through a link."""
    root = next((f for f in info.claude if f.name == "CLAUDE.md"), None)
    if root is not None and root.link_target is not None:
        return (f"CLAUDE.md is a link to {root.link_target}, which aegis init never writes through: "
                "add an @AGENTS.md line to that file, or make CLAUDE.md a link to AGENTS.md")
    if root is not None:
        return "run aegis init to add the import"
    first = info.claude[0]
    line = "@../AGENTS.md" if first.name.startswith(".claude/") else "@AGENTS.md"
    return f"add the line {line} to {first.name} (aegis init adds it only to a CLAUDE.md at the root)"


def _budget(spec: Any, info: _Instructions) -> Dict[str, Any]:
    budget = spec.budget_bytes
    if spec.instructions == "agents_md_unless_claude_md" and info.claude:
        # Claude Code loads every one of them; AGENTS.md too when one imports it, once.
        whole = any(f.is_agents for f in info.claude)
        imported = not whole and any(f.imports_agents for f in info.claude)
        size = sum(f.size for f in info.claude) + ((info.agents_bytes or 0) if imported else 0)
        name = " + ".join(f.name + (" (= AGENTS.md)" if f.is_agents else "") for f in info.claude)
        name += " + AGENTS.md" if imported else ""
    elif spec.instructions in ("agents_md", "agents_md_unless_claude_md"):
        size, name = info.agents_bytes, "AGENTS.md"
    else:
        size, name = None, None
    within = None if size is None or budget is None else size <= budget
    return {"file": name, "bytes": size, "budget_bytes": budget, "within": within}


def _bootstrap_reaches(spec: Any, info: _Instructions) -> Optional[bool]:
    if info.bootstrap == "not_read" or spec.instructions in ("gemini_md", "none"):
        return None
    if info.bootstrap not in ("current", "outdated"):
        return False
    if spec.id in _base._READS_AGENTS_OVERRIDE and info.override:
        return False
    if spec.instructions == "agents_md_unless_claude_md":
        if _claude_reads_agents(info):
            return True
        if info.claude:
            return False
        if info.claude_outside:
            return None  # no native read; an import in a file doctor does not read is unknown
    return True


# ── Host plane: one row per host ────────────────────────────────────────────

def _identity(spec: Any, reg: Dict[str, Any]) -> Dict[str, Any]:
    client = reg.get("aegis_client")
    if reg["status"] != "registered":
        return {"status": "unknown", "aegis_client": None}
    if client == spec.id:
        return {"status": "explicit", "aegis_client": client}
    if not client:
        known = bool(spec.client_names or spec.client_prefixes)
        return {"status": "client_info" if known else "unknown", "aegis_client": None}
    if set(client) == {"*"}:
        return {"status": "unknown", "aegis_client": None}
    return {"status": "mismatch", "aegis_client": _base._clean(client, 128)}


def _any(*facts: Optional[bool]) -> Optional[bool]:
    """Three-valued or: True if one fact holds, None if none holds but one is unknown."""
    return True if True in facts else (None if None in facts else False)


def _all(*facts: Optional[bool]) -> Optional[bool]:
    """Three-valued and: False if one fact fails, None if none fails but one is unknown."""
    return False if False in facts else (None if None in facts else True)


def _mcp_loads(reg: Dict[str, Any]) -> Optional[bool]:
    """Whether the host starts the aegis server: None when doctor cannot tell."""
    if reg["status"] == "absent":
        return False
    if reg["status"] != "registered":
        return None
    if reg["command_exists"] is False or reg["enabled"] is False or reg["approval"] == "denied":
        return False
    if reg["command_exists"] is None or reg["approval"] == "unknown":
        return None
    return True


def _advisory(spec: Any, ctx: _Ctx, installed: Optional[bool], reg: Dict[str, Any], bootstrap: Optional[bool],
              workspace_registered: Optional[bool]) -> Optional[bool]:
    """Whether the advisory tier reaches this host here; None when a deciding fact is unknown.

    It needs rules to serve (a governed workspace), the host on this machine
    (``installed`` is None when its only binary sits inside the workspace) and a route
    to its agent: the server loading in the host, or the bootstrap arriving whole
    (``bootstrap`` is False when the host cuts it). A host that sends no workspace finds
    the repository only through the registry, and its bootstrap sends the agent to that
    server, so it needs this workspace registered as well.
    """
    if not ctx.governed or installed is False:
        return False
    route = _any(_mcp_loads(reg), False if spec.instructions == "none" else bootstrap)
    if spec.id in _base._REGISTRY_BOUND:
        route = _all(workspace_registered, route)
    return _all(installed, route)


def _level(advisory: Optional[bool], floor: str, governed: bool, installed: Optional[bool]) -> str:
    """The strongest tier known to be in force for one host (AD-8), never a guess.

    Nothing is enforced on a host in an ungoverned workspace or on a host that is not
    installed; whether one whose only binary doctor will not run (inside the workspace, or
    behind an empty or relative PATH entry) is installed is unknown. The local floor
    holds for every commit made through git.
    """
    if not governed or installed is False:
        return "none"
    if installed is None:
        return "unknown"
    if floor == "active":
        return "local_floor"
    if advisory is True:
        return "advisory"
    if advisory is None or floor == "unknown":
        return "unknown"
    return "none"


def _installation(spec: Any, ctx: _Ctx) -> Tuple[Optional[str], List[Any], List[str], Optional[str], Optional[bool]]:
    binary = next((found for found in (ctx.which(name) for name in spec.binaries) if found), None)
    passed = [] if binary else [hit for name in spec.binaries for hit in ctx.passed_over(name)]
    ignored = list(dict.fromkeys(hit.path for hit in passed))
    # An IDE or desktop app of the plane puts no binary on PATH; its bundle is the evidence.
    app = None if binary else _base._app(spec, ctx)
    # Installed: True, False, or None when the only binary is one doctor will not run.
    installed: Optional[bool] = True if binary or app else (None if passed else False)
    return binary, passed, ignored, app, installed


def _binary_reasons(spec: Any, binary: Optional[str], passed: List[Any], app: Optional[str],
                    add: Callable[[str, str], None], unknown: List[str]) -> None:
    from aegis_core.pathlookup import INSIDE_FENCE
    names = " or ".join(f"`{b}`" for b in spec.binaries) or "a binary"
    if passed and not app:
        unknown.append("binary")
    fenced = next((hit for hit in passed if hit.reason == INSIDE_FENCE), None) if not app else None
    relative = next((hit for hit in passed if hit.reason != INSIDE_FENCE), None) if not app else None
    if fenced is not None:
        add("binary_in_workspace", f"{names} found only at {fenced.path}, inside the workspace: doctor does not "
                                   "run programs from the repository, so it cannot tell whether the host is installed")
    if relative is not None:
        add("binary_on_relative_path", f"{names} found only at {relative.path}, through the relative PATH entry "
                                       f"{relative.entry!r}, which resolves against the directory a program starts in "
                                       "(here the workspace): doctor does not run it, so it cannot tell whether the "
                                       "host is installed")
    if binary is None and not passed and not app:
        add("missing_binary", f"no {names} on PATH")


def _registration_reasons(spec: Any, reg: Dict[str, Any], identity: Dict[str, Any], installed: Optional[bool],
                          add: Callable[[str, str], None], unknown: List[str]) -> None:
    from aegis_cli.install_hosts import launch_risk
    status = reg["status"]
    if status == "absent":
        add("not_registered", f"aegis is not registered with {spec.display_name}: run aegis init --host {spec.id}")
    elif status in ("unknown", "unavailable"):
        unknown.append("registration")
        # An installed host doctor cannot ask is never "ok": unknown is not absent either.
        if status == "unknown" or installed:
            add("registration_unverifiable", f"cannot tell whether {spec.display_name} loads aegis: {reg['detail']}")
    else:
        if reg["command_exists"] is False:
            add("command_missing", f"the registered command {reg['command'][0]} does not exist: "
                                   f"run aegis init --host {spec.id}")
        elif reg["command_exists"] is None:
            unknown.append("command_exists")
            if reg["command"]:
                cmd = reg["command"][0]
                why = (f"is a relative path, which {spec.display_name} resolves against the directory it starts "
                       "the server in" if not is_bare(cmd) else
                       "is found only through an empty or relative PATH entry or inside the workspace, where "
                       "doctor does not look")
                add("command_unverifiable", f"the registered command {cmd} {why}, so doctor cannot tell whether "
                                            f"it exists: run aegis init --host {spec.id} to register an absolute path")
        risk = launch_risk(reg["command"]) if reg["command"] else None
        if risk:
            add("unsafe_registration", f"the registered command {reg['command'][0]} is an unsafe registration: "
                                       f"{risk}: run aegis init --host {spec.id}")
        if reg["approval"] == "unknown":
            add("approval_unknown", "aegis is registered only in this project's .mcp.json, which Claude Code "
                                    "runs after an approval doctor cannot see")
        if reg["enabled"] is False:
            add("registration_disabled", reg["detail"] or f"the aegis entry is disabled in {reg['source']}")
        if identity["status"] == "mismatch":
            add("identity_mismatch", f"the registration says AEGIS_CLIENT={identity['aegis_client']}, so the "
                                     f"server would act as that host: run aegis init --host {spec.id}")
        elif identity["status"] == "unknown":
            unknown.append("identity")


def _policy_reasons(spec: Any, ctx: _Ctx, info: _Instructions, roots: Optional[set], add: Callable[[str, str], None],
                    unknown: List[str]) -> Tuple[Dict[str, Any], Optional[bool], bool, Optional[bool]]:
    budget = _budget(spec, info)
    reaches = _bootstrap_reaches(spec, info)
    # The host keeps too little of its instruction file for the bootstrap to arrive whole.
    cut = (budget["within"] is False and info.bootstrap != "missing" and spec.id in _base._TRUNCATES_TAIL
           and (info.block_end or 0) > budget["budget_bytes"])
    workspace_registered = None if roots is None else real_key(ctx.root) in roots
    if roots is None:
        unknown.append("workspace_registered")
    if not ctx.governed and ctx.is_home:
        add("workspace_not_governed", f"{ctx.root} is your home directory: its .aegis/ is your user layer, "
                                      "never a governed workspace. Run aegis doctor inside a repository")
    elif not ctx.governed:
        add("workspace_not_governed", f"{ctx.root} has no .aegis/: run {ctx.setup} there")
    else:
        if info.bootstrap in ("missing", "hand_edited", "malformed"):
            add("bootstrap_" + info.bootstrap, {
                "missing": "AGENTS.md has no Aegis bootstrap block: run aegis init",
                "hand_edited": "the Aegis block in AGENTS.md was edited by hand: run aegis init --force",
                "malformed": "the Aegis block markers in AGENTS.md are broken: fix them, then run aegis init",
            }[info.bootstrap])
        if spec.instructions == "agents_md_unless_claude_md" and info.claude and not _claude_reads_agents(info):
            verb = "exists" if len(info.claude) == 1 else "exist"
            add("claude_md_shadows_agents_md", f"{_claude_names(info)} {verb} without @AGENTS.md, so Claude Code "
                                               f"does not read AGENTS.md: {_claude_import_advice(info)}")
        elif spec.instructions == "agents_md_unless_claude_md" and reaches is None and info.claude_outside:
            unknown.append("bootstrap")
            add("claude_md_outside_workspace",
                f"{info.claude_outside[0]} is outside the workspace: Claude Code does not read AGENTS.md "
                "natively when a CLAUDE.md, CLAUDE.local.md or .claude/CLAUDE.md is in the directory it starts "
                "in or a parent, and doctor reads no file outside the workspace, so it cannot tell whether "
                "AGENTS.md reaches Claude Code: add a CLAUDE.md holding the line @AGENTS.md to the workspace")
        if spec.id in _base._READS_AGENTS_OVERRIDE and info.override:
            add("agents_override_shadows_agents_md", "AGENTS.override.md replaces AGENTS.md for Codex")
        if cut:
            add("over_budget", f"{budget['file']} is {budget['bytes']} bytes; {spec.display_name} reads "
                               f"{budget['budget_bytes']} and the Aegis block may not reach it")
        if spec.id in _base._REGISTRY_BOUND and workspace_registered is False:
            add("workspace_unregistered", f"{spec.display_name} sends no workspace, so aegis finds this "
                                          f"repository only through ~/.aegis/workspaces.json: run aegis init")
        elif spec.id in _base._REGISTRY_BOUND and workspace_registered is None:
            add("workspace_registry_unknown", f"{spec.display_name} sends no workspace and "
                                              "~/.aegis/workspaces.json cannot be read, so doctor cannot tell "
                                              "whether aegis finds this repository")
    return budget, reaches, cut, workspace_registered


def _state_from_codes(codes: set) -> str:
    if codes & {"missing_binary", "binary_in_workspace", "binary_on_relative_path"}:
        state = "missing_binary"
    elif codes & {"not_registered", "command_missing"}:
        state = "unregistered"
    elif codes & {"registration_unverifiable", "approval_unknown", "workspace_registry_unknown",
                   "claude_md_outside_workspace", "command_unverifiable"}:
        state = "auth_unknown"
    elif codes:
        state = "policy_gap"
    else:
        state = "ok"
    return state


def _host_row(spec: Any, ctx: _Ctx, info: _Instructions, roots: Optional[set], floor: str) -> Dict[str, Any]:
    binary, passed, ignored, app, installed = _installation(spec, ctx)
    reg = ctx.probe(spec, binary)
    identity = _identity(spec, reg)
    reasons: List[Dict[str, str]] = []
    unknown: List[str] = []

    def add(code: str, message: str) -> None:
        reasons.append({"code": code, "message": _base._clean(message, 1024)})

    _binary_reasons(spec, binary, passed, app, add, unknown)
    _registration_reasons(spec, reg, identity, installed, add, unknown)
    budget, reaches, cut, workspace_registered = _policy_reasons(spec, ctx, info, roots, add, unknown)
    state = _state_from_codes({r["code"] for r in reasons})

    advisory = _advisory(spec, ctx, installed, reg, False if cut else reaches, workspace_registered)
    level = _level(advisory, floor, ctx.governed, installed)
    # The PreToolUse hooks never change ``state`` or ``level``: their presence in a file is
    # not proof that the host runs them (presence never claims enforcement).
    from aegis_core.insights import host_capture_status

    hooks = _hook_row(spec, ctx)
    if hooks["status"] == "unknown":
        unknown.append("hooks")
    shown = {k: v for k, v in reg.items() if k != "aegis_client"}
    return {
        "id": spec.id,
        "display_name": spec.display_name,
        "verified_row": spec.verified,
        "experimental": not spec.verified,
        "surfaces": list(spec.surfaces),
        "state": state,
        "reasons": reasons,
        "binary": {"found": binary is not None, "path": binary, "names": list(spec.binaries), "ignored": ignored},
        "app": app,
        "registration": shown,
        "identity": identity,
        "workspace_registered": workspace_registered,
        "bootstrap": {"file": "AGENTS.md", "status": info.bootstrap, "reaches_host": reaches,
                      "stale": info.bootstrap == "outdated"},
        "budget": budget,
        "enforcement_level": level,
        "advisory": advisory,
        "hooks": hooks,
        "insight_capture": host_capture_status(spec.id, home=ctx.home),
        "trust_tier": None,
        "trust_tier_status": "unavailable",  # _diagnose fills both from the repository's human_gate tier
        "stale": False,
        "unknown": unknown,
    }


# ── Host plane: PreToolUse hooks (v4.1 §2 Doctor) ──────────────────────────

_HOOK_SCOPE_FILES = {"claude-code": (("local", (".claude", "settings.local.json")),)}
_V3_PLUGIN = (".gemini", "config", "plugins", "governance", "hooks.json")


def _hook_files(host_id: str, ctx: _Ctx) -> List[Tuple[str, Path]]:
    """(scope, path) of each file ``host_id`` reads hooks from here: the user and project
    files ``aegis hook install`` writes, plus Claude Code's local settings."""
    from aegis_cli.hooks import registrar

    found: List[Tuple[str, Path]] = []
    for scope in registrar.SCOPES:
        path = registrar.hook_file(host_id, scope, home=ctx.home, root=ctx.root, environ=ctx.environ)
        if path is not None:
            found.append((scope, path))
    found.extend((scope, ctx.root.joinpath(*rel)) for scope, rel in _HOOK_SCOPE_FILES.get(host_id, ()))
    unique: Dict[str, Tuple[str, Path]] = {}
    for scope, path in found:  # in the home directory the project file is the user file
        unique.setdefault(_path_key(path), (scope, path))
    return list(unique.values())


def _runnable(path: Optional[str]) -> bool:
    return bool(path) and os.path.isfile(path) and (os.name == "nt" or os.access(path, os.X_OK))


def _hook_row(spec: Any, ctx: _Ctx) -> Dict[str, Any]:
    """Whether an Aegis PreToolUse entry for ``spec`` is in a file the host reads, and the
    tier it would give. ``status``: registered, absent, duplicate (more than one entry),
    broken (its aegis is missing), modified (not the entry install writes, so no tier is
    claimed), unknown (a host file cannot be read), unavailable (the host cannot run the
    hook here) or none (a host without Aegis hooks)."""
    from aegis_cli.hooks import registrar

    row: Dict[str, Any] = {"status": "none", "tier": None, "evidence": None, "trust": None, "detail": None,
                           "entries": [], "files": []}
    if spec.id not in registrar.HOOK_HOSTS:
        return row
    for scope, path in _hook_files(spec.id, ctx):
        entry = ctx.file(path, as_json=True)
        item = {"scope": scope, "path": str(path), "status": "absent", "error": None}
        row["files"].append(item)
        if not entry.exists:
            continue
        if entry.error:
            item.update(status="invalid", error=entry.error)
            continue
        try:
            located = registrar.aegis_handlers(spec.id, entry.data, path, strict=True)
        except registrar.ShapeError as exc:
            item.update(status="invalid", error=f"is not in the shape {spec.display_name} reads "
                                                f"('{exc.where}' must be {exc.what})")
            continue
        item["status"] = "ok"
        for keys, group_index, _handler_index, handler in located:
            groups: Any = entry.data
            for key in keys:
                groups = groups[key]
            aegis = registrar.handler_aegis(handler)
            row["entries"].append({"scope": scope, "path": str(path), "aegis": aegis, "executable": _runnable(aegis),
                                   "modified": not registrar.matches_install(spec.id, groups[group_index], handler)})
    entries = row["entries"]
    invalid = [f for f in row["files"] if f["status"] == "invalid"]
    why = registrar.unavailable_reason(spec.id, ctx.which("aegis"))
    if why:
        row.update(status=registrar.UNAVAILABLE, tier=registrar.UNAVAILABLE, detail=why)
        return row
    if len(entries) > 1:
        status = "duplicate"
    elif entries:
        status = "broken" if not entries[0]["executable"] else "modified" if entries[0]["modified"] else "registered"
    else:
        status = "unknown" if invalid else "absent"
    row.update(status=status, tier=registrar.TIERS[spec.id], evidence=registrar.EVIDENCE[spec.id])
    if status == "unknown":
        row["detail"] = f"{ctx.label(Path(invalid[0]['path']))} {invalid[0]['error']}"
    if entries and spec.id == "codex-cli":
        row["trust"] = registrar.TRUST_UNCHECKED
    return row


def _hook_findings(ctx: _Ctx, rows: List[Dict[str, Any]]) -> List[_Finding]:
    found: List[_Finding] = []
    for row in rows:
        hooks, name, host_id = row["hooks"], row["display_name"], row["id"]
        for item in hooks["files"]:
            if item["status"] == "invalid":
                path = Path(item["path"])
                found.append(_Finding("hook_file_invalid", path,
                                      f"{ctx.label(path)} {item['error']}, so {name} may skip every hook in it, and "
                                      f"aegis hook install --host {host_id} will not edit it: fix the file"))
        entries = hooks["entries"]
        if len(entries) > 1:
            where = ", ".join(f"{ctx.label(Path(e['path']))} ({e['scope']})" for e in entries)
            times = "twice" if len(entries) == 2 else f"{len(entries)} times"
            found.append(_Finding("duplicate_hook", Path(entries[1]["path"]),
                                  f"{name} has {len(entries)} Aegis PreToolUse hook entries ({where}), so it runs "
                                  f"the handler {times} per tool call: keep one (aegis hook uninstall --host "
                                  f"{host_id} --scope user|project removes one scope's)"))
        for e in entries:
            path = Path(e["path"])
            fix = (f"remove it from that file, then run aegis hook install --host {host_id}" if e["scope"] == "local"
                   else f"run aegis hook install --host {host_id}" + (" --scope project" if e["scope"] == "project"
                                                                        else ""))
            if not e["executable"]:
                found.append(_Finding("hook_aegis_missing", path,
                                      f"{ctx.label(path)}: the Aegis hook runs {e['aegis']}, which is missing or not "
                                      f"executable, so {name} gets no Aegis check from it (it fails open): {fix}"))
            elif e["modified"]:
                found.append(_Finding("hook_entry_modified", path,
                                      f"{ctx.label(path)}: the Aegis hook entry is not the entry aegis hook install "
                                      "writes (its matcher, type, command, arguments or timeout differ), so "
                                      f"{name} may not run it as its tier says: {fix}"))
    return found + _legacy_hook_findings(ctx)


# ── Findings ────────────────────────────────────────────────────────────────

def _key_finding(ctx: _Ctx, entry: _File, code: str, keys: Tuple[str, ...], message: str,
                 fixable: bool = True, blocked: Optional[str] = None) -> _Finding:
    where = _location(keys)
    action = None
    text = f"{ctx.label(entry.path)}: {message} ({where})"
    if not fixable:
        text += f"; {blocked}" if blocked else ""
    elif entry.refusal:
        text += f"; --fix will not change it: {entry.refusal}"
    else:
        action = _Action(entry.path, "remove_keys", _base._sha256(entry.raw or b""), f"remove {where}", keys=(keys,))
        text += f". Fix: {_base._FIX_HINT}"
    return _Finding(code, entry.path, text, location=where, action=action)


def _mcp_findings(ctx: _Ctx, claude_user: bool) -> List[_Finding]:
    found: List[_Finding] = []
    files: List[Tuple[Path, str]] = []
    if ctx.home is not None:
        files.append((ctx.home / ".mcp.json", "dot_mcp"))
    files.append((ctx.root / ".mcp.json", "dot_mcp"))
    claude_cfg = _claude_config(ctx)
    if claude_cfg is not None:
        files.append((claude_cfg, "claude"))
    files.extend((p, "desktop") for p in _desktop_configs(ctx))
    for spec in ctx.selected:
        path = _host_json_path(spec, ctx)
        if path is not None:
            files.append((path, "host"))
    seen = set()
    no_user = "keep it until aegis init --host claude-code registers aegis for your user"
    for path, kind in files:
        key = _path_key(path)
        if key in seen:
            continue
        seen.add(key)
        entry = ctx.file(path, as_json=True)
        if not entry.exists:
            continue
        if entry.error:
            found.append(_Finding("unreadable_config", path, f"{ctx.label(path)} {entry.error}; doctor did not "
                                  "read it and --fix will not change it"))
            continue
        data = entry.data or {}
        servers = data.get("mcpServers") if isinstance(data.get("mcpServers"), dict) else {}
        if _base.LEGACY_SERVER in servers:
            found.append(_key_finding(ctx, entry, "legacy_mcp_entry", ("mcpServers", _base.LEGACY_SERVER),
                                      _base._LEGACY_ENTRY))
        if _base.SERVER in servers and kind == "dot_mcp":
            found.append(_key_finding(ctx, entry, "misplaced_mcp_entry", ("mcpServers", _base.SERVER),
                                      "Aegis v4 registers 'aegis' per user, never in a .mcp.json file",
                                      fixable=claude_user, blocked=no_user))
        if _base.SERVER in servers and kind == "desktop":
            found.append(_key_finding(ctx, entry, "desktop_mcp_entry", ("mcpServers", _base.SERVER),
                                      "Claude Desktop is identity only in v4 (H4); its 'aegis' entry moves out"))
        if kind == "claude" and isinstance(data.get("projects"), dict):
            for name, project in data["projects"].items():
                psrv = project.get("mcpServers") if isinstance(project, dict) else None
                if not isinstance(psrv, dict):
                    continue
                if _base.LEGACY_SERVER in psrv:
                    found.append(_key_finding(ctx, entry, "legacy_mcp_entry",
                                              ("projects", name, "mcpServers", _base.LEGACY_SERVER),
                                              _base._LEGACY_ENTRY))
                if _base.SERVER in psrv and claude_user:
                    found.append(_key_finding(ctx, entry, "misplaced_mcp_entry",
                                              ("projects", name, "mcpServers", _base.SERVER),
                                              "a local-scope 'aegis' entry shadows your user registration"))
    return found


def _budget_findings(ctx: _Ctx, info: _Instructions) -> List[_Finding]:
    found = []
    budgets = {s.id: s.budget_bytes for s in ctx.selected if s.budget_bytes}
    agent_hosts = [s for s in ctx.selected if s.budget_bytes and s.instructions in ("agents_md", "agents_md_unless_claude_md")]
    if info.agents_bytes is not None:
        over = [s.id for s in agent_hosts if info.agents_bytes > s.budget_bytes]
        if over:
            found.append(_Finding("instructions_over_budget", ctx.root / "AGENTS.md",
                                  f"AGENTS.md is {info.agents_bytes} bytes, over the budget of {', '.join(over)}; "
                                  "move text out of it (rules belong in .aegis/rules/)"))
    claude_budget = budgets.get("claude-code")
    if claude_budget:
        claude_dir = _claude_dir(ctx)
        for path in [ctx.root / "CLAUDE.md"] + ([claude_dir / "CLAUDE.md"] if claude_dir else []):
            entry = ctx.file(path)
            if entry.raw is not None and len(entry.raw) > claude_budget:
                found.append(_Finding("instructions_over_budget", path,
                                      f"{ctx.label(path)} is {len(entry.raw)} bytes, over Claude Code's "
                                      f"{claude_budget}; inlined v3 rules belong in .aegis/rules/, served by aegis_scan"))
    return found


def _workspace_findings(ctx: _Ctx, info: _Instructions) -> List[_Finding]:
    found = []
    if info.claude and not _claude_reads_agents(info):
        where = next((f for f in info.claude if f.name == "CLAUDE.md"), info.claude[0])
        verb = "does" if len(info.claude) == 1 else "do"
        found.append(_Finding("claude_md_without_agents_import", where.path,
                              f"{_claude_names(info)} {verb} not import @AGENTS.md, so Claude Code skips AGENTS.md; "
                              f"{_claude_import_advice(info)}"))
    if info.override:
        found.append(_Finding("agents_override", ctx.root / "AGENTS.override.md",
                              "AGENTS.override.md replaces AGENTS.md for Codex; move its text into AGENTS.md"))
    if info.bootstrap == "outdated":
        found.append(_Finding("bootstrap_outdated", ctx.root / "AGENTS.md",
                              "the Aegis block in AGENTS.md is from another aegis version: run aegis init",
                              severity="info"))
    return found


def _bootstrap_tool_findings(ctx: _Ctx, info: _Instructions, rows: List[Dict[str, Any]]) -> List[_Finding]:
    """Hosts found on this machine whose agent reads the bootstrap in AGENTS.md, which
    tells it to call aegis_scan, while the host has no ``aegis`` server: the field case of
    an IDE that read AGENTS.md but had no tools. Any registrable host counts, selected or
    not; a registration doctor cannot read is unknown, never absent, so it is not one."""
    from aegis_core import hosts

    if not ctx.governed or info.bootstrap not in ("current", "outdated"):
        return []
    by_id = {row["id"]: row for row in rows}
    found = []
    for spec in hosts.all_hosts(phase=1):
        if spec.registration is None or spec.retired or _bootstrap_reaches(spec, info) is not True:
            continue
        evidence = _base._plane_found(spec, ctx)
        if evidence is None:
            continue
        row = by_id.get(spec.id)
        if row is not None:
            status = row["registration"]["status"]
        else:
            binary = next((b for b in (ctx.which(name) for name in spec.binaries) if b), None)
            status = ctx.probe(spec, binary)["status"]
        if status != "absent":
            continue
        found.append(_Finding(
            "bootstrap_without_tools", ctx.root / "AGENTS.md",
            f"AGENTS.md carries the Aegis bootstrap, which tells {spec.display_name}'s agent to call the aegis "
            f"tools, but {spec.display_name} (found: {evidence}) has no Aegis MCP server: "
            f"run aegis init --host {spec.id}"))
    return found


def _worktree_ledger_findings(ctx: _Ctx) -> List[_Finding]:
    """Rows in a worktree's own ledger that the shared ledger (v4.2) does not hold: Aegis
    no longer reads them, so rules show less evidence until aegis migrate --apply merges them."""
    if ctx.is_home:
        return []
    from aegis_core import migrate
    from aegis_core.workspace.layout import WorkspaceLayout

    pending = migrate.pending_worktree_rows(ctx.root)
    if not pending:
        return []
    return [_Finding("worktree_ledger_pending", WorkspaceLayout(ctx.root).ledger_file,
                     f"{pending} outcome row(s) in per-worktree ledgers are not in the shared ledger, so rule "
                     "evidence is understated: run aegis migrate to see the merge, then aegis migrate --apply")]


def _upgrade_findings(ctx: _Ctx) -> List[_Finding]:
    """v3 state here that v4 never reads (discovery.unmigrated_state): status, scan and sync
    refuse such a workspace, and doctor, which still runs in it, must not call it healthy.
    The home directory's .aegis/ is the user plane, which aegis migrate never converts."""
    if ctx.is_home:
        return []
    from aegis_core.workspace import discovery

    found = list(discovery.unmigrated_state(ctx.root))
    if not found:
        return []
    return [_Finding("unmigrated_v3_state", ctx.root / found[0],
                     f"unmigrated v3 state: {', '.join(found)}. Aegis v4 does not read it, and aegis status, "
                     "scan and sync refuse to run until it is converted: run aegis migrate to see the "
                     "conversion, then aegis migrate --apply")]


def _home_rules_finding(ctx: _Ctx) -> List[_Finding]:
    if ctx.home is None:
        return []
    from aegis_core.workspace.layout import UserLayout

    rules = UserLayout(ctx.home).rules_dir
    if not rules.is_dir() or rules.is_symlink() or any(rules.rglob("*.md")):
        return []
    return [_Finding("home_rules_dir", rules,
                     f"{ctx.label(rules)} is empty; v3.3 created it when an MCP server started in your home "
                     "directory. v4 reads it as your personal read-only rule layer: remove it if you keep no "
                     "rules there (doctor --fix leaves directories alone)", severity="info")]


def _v3_copy_findings(ctx: _Ctx) -> List[_Finding]:
    if ctx.home is None:
        return []
    found = []
    for base in (ctx.home / ".gemini" / "config" / "rules", ctx.home / ".kiro" / "steering"):
        for directory in (base, base / ".oracles"):
            if not directory.is_dir() or directory.is_symlink():
                continue
            for path in sorted(directory.glob("*.md")):
                entry = ctx.file(path)
                if entry.is_link or entry.raw is None or _base._sha256(entry.raw) not in _base._V3_SHIPPED_RULE_SHA256:
                    continue
                message = f"{ctx.label(path)}: an unedited copy of a rule Aegis v3 shipped"
                action = None
                if entry.refusal:
                    message += f"; --fix will not change it: {entry.refusal}"
                else:
                    action = _Action(path, "delete_file", _base._sha256(entry.raw), "delete the v3 rule copy")
                    message += f". Fix: {_base._FIX_HINT}"
                found.append(_Finding("v3_rule_copy", path, message, action=action))
    return found


def _selection(root: Path, governed: bool, ctx: _Ctx) -> Tuple[Tuple[Any, ...], str, List[_Finding]]:
    from aegis_core import hosts
    from aegis_core.config import ConfigError, RepoConfig
    from aegis_core.workspace.layout import WorkspaceLayout

    config = WorkspaceLayout(root).config_file
    # An experimental row joins the default matrix only where its plane is on this machine.
    default = tuple(h for h in hosts.all_hosts(phase=1) if h.registration is not None
                    and (h.verified or _base._plane_found(h, ctx) is not None))
    if not governed:
        return default, "default", []
    try:
        chosen = RepoConfig.load(root).hosts
    except ConfigError as exc:
        return default, "default", [_Finding("unreadable_config", config, str(exc))]
    if not chosen:
        return default, "default", []
    known = {h.id: h for h in hosts.HOSTS if h.registration is not None}
    table = {h.id: h for h in hosts.HOSTS}
    named = list(dict.fromkeys(chosen))
    retired = [h for h in named if h in table and table[h].retired]
    unknown = [h for h in named if h not in known and h not in retired]
    notes = [_Finding("retired_host", config, f"{config.name} selects {h!r}, a retired host: {table[h].retired}",
                      severity="info") for h in retired]
    if unknown:
        notes.append(_Finding("unknown_host", config,
                              f"{config.name} selects {', '.join(repr(h) for h in unknown)}, which doctor "
                              "cannot check", severity="info"))
    picked = tuple(h for h in hosts.HOSTS if h.id in set(chosen) and h.id in known)
    return picked, "config", notes


# ── Legacy v3 hook & block findings (fixable by --fix) ──────────────────────

def _legacy_hook_findings(ctx: _Ctx) -> List[_Finding]:
    """v3 hook entries in every hook file of every hook host (selected or not), and the
    stale v3 Antigravity plugin."""
    from aegis_cli.hooks import registrar

    files: Dict[str, Tuple[str, Path, bool]] = {}
    for host_id in registrar.HOOK_HOSTS:
        for _scope, path in _hook_files(host_id, ctx):
            files.setdefault(_path_key(path), (host_id, path, False))
    if ctx.home is not None:
        plugin = ctx.home.joinpath(*_V3_PLUGIN)
        files.setdefault(_path_key(plugin), ("antigravity", plugin, True))
    phases = _removed_host_phases()
    found: List[_Finding] = []
    for host_id, path, is_plugin in files.values():
        entry = ctx.file(path, as_json=True)
        if entry.raw is None or entry.error or not isinstance(entry.data, dict):
            continue
        items, total, legacy = _legacy_items(host_id, entry.data, phases)
        if not items:
            continue
        where = ", ".join(_list_location(p, i) for p, i in items)
        calls = f"call {_base.LEGACY_SERVER} hook or a removed aegis hook phase"
        if is_plugin:
            code, message = "legacy_hook_plugin", f"{ctx.label(path)}: the stale v3 Antigravity plugin's hooks {calls}"
        else:
            code, message = "legacy_hook_entry", f"{ctx.label(path)}: v3 hook entries {calls}"
        message += f" ({where})"
        action = None
        if entry.refusal:
            message += f"; --fix will not change it: {entry.refusal}"
        elif is_plugin and legacy == total:
            action = _Action(path, "delete_file", _base._sha256(entry.raw), f"delete the file (it holds only v3 hooks, {where})")
            message += f"; nothing else is in it, so --fix deletes the file. Fix: {_base._FIX_HINT}"
        else:
            action = _Action(path, "remove_list_items", _base._sha256(entry.raw), f"remove the v3 hook entries ({where})",
                             items=tuple(items))
            message += f". Fix: {_base._FIX_HINT}"
        found.append(_Finding(code, path, message, location=where, action=action))
    return found


def _legacy_block_findings(ctx: _Ctx) -> List[_Finding]:
    found = []
    for path in _instruction_files(ctx):
        entry = ctx.file(path)
        if entry.raw is None:
            continue
        try:
            text = entry.raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        ranges, balanced = _legacy_ranges(text)
        if not ranges and balanced:
            continue
        label = ctx.label(path)
        where = ", ".join(f"lines {a + 1}-{b + 1}" for a, b in ranges) or None
        if not balanced:
            found.append(_Finding("legacy_block", path, f"{label}: unbalanced SOMA/AEGIS START/END markers; "
                                  "remove the old block by hand (--fix will not guess)", location=where))
            continue
        message = f"{label}: legacy Aegis/Soma rules block ({where})"
        action = None
        if entry.refusal:
            message += f"; --fix will not change it: {entry.refusal}"
        elif _without_lines(entry.raw, ranges) is None:
            # An emptied CLAUDE.md would still keep Claude Code from reading AGENTS.md, so
            # the file goes; the plan the user confirms says so.
            action = _Action(path, "delete_file", _base._sha256(entry.raw),
                             f"delete the file (it holds only the legacy block, {where})")
            message += f"; nothing else is in the file, so --fix deletes the file. Fix: {_base._FIX_HINT}"
        else:
            action = _Action(path, "remove_lines", _base._sha256(entry.raw), f"remove the legacy block ({where})",
                             lines=tuple(ranges))
            message += f". Fix: {_base._FIX_HINT}"
        found.append(_Finding("legacy_block", path, message, location=where, action=action))
    return found


# ── Enforcement tiers (AD-8) ────────────────────────────────────────────────

def _floor_status(hook: _HookStatus) -> Tuple[str, Optional[str]]:
    """The local floor's status from the run's hook_status reading, and why an installed,
    current hook never runs. The floor is active only for a hook that is installed, current
    and reached by git (hook_status ``reachable``; a status without the key predates it and
    counts as reachable). A reading that raised leaves the floor unknown."""
    st, error = hook
    if error is not None:
        return "unknown", None
    if st.get("status") == "no_git_repository":
        return "unavailable", None
    if not st.get("managed_by_aegis"):
        return "inactive", None
    if st.get("status") != "installed":
        return "outdated", None
    gone = [p for p in (st.get("interpreter"), st.get("aegis_path")) if p and not p.get("exists")]
    if gone:
        return "outdated", None
    if st.get("reachable", True) is False:
        return "inactive", _base._clean(st.get("unreachable_reason") or "git does not reach the Aegis block", 1024)
    return "active", None


_TIER_TEXT = {
    "advisory": ("Advisory", "AGENTS.md bootstrap, MCP instructions, JIT rules"),
    "best_effort": ("Best-effort", "per-host pre-tool hooks"),
    "local_floor": ("Local floor", "git pre-commit runs aegis check --hook (--no-verify bypasses it)"),
    "authoritative": ("Authoritative", "CI runs aegis check on the exact SHA; a human merges"),
}


def _tiers(rows: List[Dict[str, Any]], floor: str, governed: bool, unreached: Optional[str] = None,
           setup: str = "aegis init") -> List[Dict[str, Any]]:
    ids = [r["id"] for r in rows]
    reached = [r["id"] for r in rows if r["advisory"] is True]
    unsure = [r["id"] for r in rows if r["advisory"] is None]
    if ids and len(reached) == len(ids):
        advisory = "active"
    else:
        advisory = "partial" if reached else ("unknown" if unsure else "inactive")
    reach = f"reaches {', '.join(reached) or 'no selected host'}"
    if unsure:
        reach += f"; unknown for {', '.join(unsure)}"
    floor_detail = {
        "active": "the Aegis pre-commit hook is installed and current",
        "inactive": "no Aegis pre-commit hook: run aegis hook install",
        "outdated": "the Aegis pre-commit hook is outdated: run aegis hook install",
        "unavailable": "not a git repository",
        "unknown": "the git hooks directory could not be read",
    }[floor]
    if unreached:
        floor_detail = f"the Aegis pre-commit hook is installed but never runs: {unreached}; see aegis hook status"
    if not governed and floor != "unavailable":
        # A hook here, installed or not, has no rules to check: the floor is not in force.
        floor, floor_detail = "inactive", f"no .aegis/ here, so a pre-commit hook has nothing to enforce: run {setup}"
    return [
        {"tier": "advisory", "mechanism": _TIER_TEXT["advisory"][1], "hosts": ids, "status": advisory,
         "detail": reach},
        _best_effort(rows, governed, setup),
        {"tier": "local_floor", "mechanism": _TIER_TEXT["local_floor"][1], "hosts": ids, "status": floor,
         "detail": floor_detail},
        {"tier": "authoritative", "mechanism": _TIER_TEXT["authoritative"][1], "hosts": [], "status": "unavailable",
         "detail": "not checked: aegis doctor does not read CI runs; the trust tier says what GitHub enforces"},
    ]


def _hook_tier_text(host_id: str, hooks: Dict[str, Any]) -> str:
    text = f"{host_id}: {hooks['tier']} [{hooks['evidence']}]"
    return text + (f", {hooks['trust']}" if hooks["trust"] else "")


def _best_effort(rows: List[Dict[str, Any]], governed: bool, setup: str) -> Dict[str, Any]:
    """The per-host hook tier. Doctor reads files only, so a registered hook makes the tier
    ``unknown``, never active: whether a host runs it is out of doctor's sight."""
    tier = {"tier": "best_effort", "mechanism": _TIER_TEXT["best_effort"][1], "hosts": []}
    hooks = {row["id"]: row["hooks"] for row in rows}
    capable = [h for h, v in hooks.items() if v["status"] not in ("unavailable", "none")]
    hooked = [h for h in capable if hooks[h]["status"] in ("registered", "duplicate")]
    if not capable:
        reasons = "; ".join(v["detail"] for v in hooks.values() if v["detail"]) or "no selected host has Aegis hooks"
        return dict(tier, status="unavailable", detail=reasons)
    if not governed:
        return dict(tier, status="inactive",
                    detail=f"no .aegis/ here, so a registered hook passes every call: run {setup}")
    if hooked:
        said = "; ".join(_hook_tier_text(h, hooks[h]) for h in hooked)
        return dict(tier, hosts=hooked, status="unknown",
                    detail=f"registered for {said}. Doctor reads the host files only and cannot confirm that a host "
                           "runs them; each fails open when Aegis errors")
    unreadable = [h for h in capable if hooks[h]["status"] == "unknown"]
    if unreadable:
        return dict(tier, status="unknown",
                    detail=f"cannot tell for {', '.join(unreadable)}: a hook file cannot be read (see the warnings)")
    modified = [h for h in capable if hooks[h]["status"] == "modified"]
    if modified:
        return dict(tier, status="unknown",
                    detail=f"cannot tell for {', '.join(modified)}: its Aegis hook entry is not the one aegis hook "
                           "install writes (see the warnings)")
    absent = [h for h in capable if hooks[h]["status"] == "absent"]
    broken = [h for h in capable if hooks[h]["status"] == "broken"]
    parts = [f"no Aegis PreToolUse hook registered for {', '.join(absent)}"] if absent else []
    if broken:
        parts.append(f"the Aegis hook of {', '.join(broken)} runs a missing aegis")
    return dict(tier, status="inactive", detail="; ".join(parts) + ": run aegis hook install --host <host>")


# ── The diagnosis ───────────────────────────────────────────────────────────

def _missing_ast_extensions(ws_root: Path) -> List[str]:
    """Detected source extensions with no AST driver configured (what --fix provisions).

    An unreadable config gives none: the AST check reports it, and --fix will not
    write over a file it cannot parse.
    """
    from aegis_core.skills.slots import SlotResolutionError

    if _base._is_home(ws_root):
        return []
    try:
        return _ast_driver_state(ws_root)[1]
    except SlotResolutionError:
        return []


@dataclass
class _Diagnosis:
    ctx: _Ctx
    rows: List[Dict[str, Any]]
    tiers: List[Dict[str, Any]]
    findings: List[_Finding]
    trust: Any  # the human_gate TierReport
    modes: Any = None  # the shared state's StateModes, or None when it cannot be read


def _diagnose(root: Path, prober: Callable[[Any, Optional[str], _Ctx], Dict[str, Any]],
              hook: _HookStatus) -> _Diagnosis:
    """The run's diagnosis: ``prober`` asks each host whether aegis is registered (doctor's
    probes), ``hook`` is the run's one hook_status reading."""
    from aegis_core.workspace.layout import UserLayout, is_aegis_workspace

    layout = UserLayout.current()
    # The home directory's .aegis/ is the user plane (~/.aegis), never a workspace.
    is_home = _base._is_home(root)
    governed = is_aegis_workspace(root) and not is_home
    ctx = _Ctx(root=root, governed=governed, home=layout.home if layout else None, environ=os.environ,
               selected=(), selection="default", prober=prober, is_home=is_home,
               setup="aegis init" if governed or is_home else _base._setup_command(root))
    ctx.selected, ctx.selection, notes = _selection(root, governed, ctx)
    selected = ctx.selected
    info = _instructions(ctx)
    roots, skipped = _registered_roots(ctx)
    floor, unreached = _floor_status(hook)
    rows = [_host_row(spec, ctx, info, roots, floor) for spec in selected]
    claude_user = _claude_user_registered(ctx)
    findings = (notes + _upgrade_findings(ctx) + _worktree_ledger_findings(ctx) + _workspace_findings(ctx, info)
                + _mcp_findings(ctx, claude_user) + _legacy_block_findings(ctx) + _budget_findings(ctx, info)
                + _home_rules_finding(ctx) + _v3_copy_findings(ctx) + _hook_findings(ctx, rows)
                + _bootstrap_tool_findings(ctx, info, rows))
    if roots is None and ctx.home is not None:
        findings.append(_Finding("unreadable_config", UserLayout(ctx.home).workspaces_file,
                                 "~/.aegis/workspaces.json cannot be read as a v1 registry; doctor "
                                 "reports workspace registration as unknown"))
    for index in skipped:
        findings.append(_Finding("registry_entry_skipped", UserLayout(ctx.home).workspaces_file,
                                 f"~/.aegis/workspaces.json: entry {index} has no absolute 'root' that resolves; "
                                 "aegis skips it (run aegis init in that workspace to register it again)",
                                 location=f"workspaces[{index}]"))
    trust = human_gate.detect_tier(root)
    for row in rows:
        row["trust_tier"], row["trust_tier_status"] = trust.tier, "detected"
    return _Diagnosis(ctx, rows, _tiers(rows, floor, governed, unreached, ctx.setup), findings, trust,
                      _state_modes(root))


def _state_modes(root: Path) -> Any:
    from aegis_core import storage
    from aegis_core.errors import AegisError

    try:
        return storage.shared_state_modes(root)
    except (AegisError, OSError):
        return None
