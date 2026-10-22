"""Diagnosis and auto-repair transaction engine for ``aegis doctor``."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Sequence, Tuple

from aegis_cli.doctor_findings import (
    _Action,
    _BOM,
    _COMMAND_STARTERS,
    _Finding,
    _V3_PLUGIN,
    _bootstrap_tool_findings,
    _budget_findings,
    _fence_step,
    _home_rules_finding,
    _hook_files,
    _hook_findings,
    _host_row,
    _instructions,
    _location,
    _mcp_findings,
    _registered_roots,
    _selection,
    _upgrade_findings,
    _v3_copy_findings,
    _workspace_findings,
    _worktree_ledger_findings,
)
from aegis_core import human_gate

if TYPE_CHECKING:
    from aegis_cli.doctor import _Ctx


@dataclass
class _File:
    """One file as doctor read it, with the facts --fix needs to decide whether it may write."""

    path: Path
    raw: Optional[bytes] = None
    is_link: bool = False
    error: Optional[str] = None
    refusal: Optional[str] = None  # why --fix will not write it
    data: Any = None

    @property
    def exists(self) -> bool:
        return self.raw is not None or self.is_link or self.error is not None


def _write_refusal(path: Path, st: os.stat_result) -> Optional[str]:
    if stat.S_ISLNK(st.st_mode):
        return "it is a symlink, and Aegis never writes through a link"
    if not stat.S_ISREG(st.st_mode):
        return "it is not a regular file"
    if st.st_nlink > 1:
        return "it has another hard link, and replacing it would split the link"
    if not (st.st_mode & 0o222) or not os.access(str(path), os.W_OK):
        return "it is read-only"
    return None


def _read_file(path: Path) -> _File:
    entry = _File(path)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return entry
    except OSError as exc:
        entry.error = f"cannot be read ({exc.strerror or exc})"
        return entry
    entry.is_link = stat.S_ISLNK(st.st_mode)
    entry.refusal = _write_refusal(path, st)
    if entry.is_link and not path.is_file():
        entry.error = "is a symlink to no regular file"
        return entry
    if not entry.is_link and not stat.S_ISREG(st.st_mode):
        entry.error = "is not a regular file"
        return entry
    try:
        with open(path, "rb") as fh:
            entry.raw = fh.read()
    except OSError as exc:
        entry.error = f"cannot be read ({exc.strerror or exc})"
    return entry


def _strict_pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _parse_json(entry: _File) -> _File:
    if entry.raw is None or entry.error:
        return entry
    try:
        text = entry.raw.decode("utf-8")
        if text.startswith("\ufeff"):
            raise ValueError("starts with a byte-order mark")
        entry.data = json.loads(text, object_pairs_hook=_strict_pairs, parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        entry.error = f"is not valid JSON ({str(exc)[:120]})"
        return entry
    except RecursionError:
        # A file nested past the parser's depth (a cloned repository's .mcp.json can be)
        # is as unreadable as a malformed one; it must not abort the whole report.
        entry.error = "is not valid JSON (nested too deeply to parse)"
        return entry
    if not isinstance(entry.data, dict):
        entry.error = "is not a JSON object"
        entry.data = None
    return entry


def _claude_dir(ctx: _Ctx) -> Optional[Path]:
    custom = ctx.environ.get("CLAUDE_CONFIG_DIR")
    if custom:
        return Path(custom)
    return ctx.home / ".claude" if ctx.home else None


def _claude_config(ctx: _Ctx) -> Optional[Path]:
    # Claude Code keeps its user and local MCP scopes in .claude.json: in the home
    # directory, or in CLAUDE_CONFIG_DIR when that is set.
    custom = ctx.environ.get("CLAUDE_CONFIG_DIR")
    if custom:
        return Path(custom) / ".claude.json"
    return ctx.home / ".claude.json" if ctx.home else None


def _desktop_configs(ctx: _Ctx) -> List[Path]:
    """Every claude_desktop_config.json location: v3 wrote ~/.config/Claude on every OS."""
    from aegis_cli import doctor as _doc

    if ctx.home is None:
        return []
    found = [ctx.home / ".config" / "Claude" / "claude_desktop_config.json"]
    if _doc.sys.platform == "darwin":
        found.append(ctx.home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json")
    elif os.name == "nt":
        appdata = ctx.environ.get("APPDATA")
        if appdata:
            found.append(Path(appdata) / "Claude" / "claude_desktop_config.json")
    else:
        xdg = ctx.environ.get("XDG_CONFIG_HOME", "")
        if xdg and os.path.isabs(xdg):
            found.append(Path(xdg) / "Claude" / "claude_desktop_config.json")
    unique: Dict[str, Path] = {}
    for path in found:
        unique.setdefault(os.path.normcase(os.path.abspath(str(path))), path)
    return list(unique.values())


def _host_json_path(spec: Any, ctx: _Ctx) -> Optional[Path]:
    reg = spec.registration
    if reg is None or reg.kind != "json_file" or ctx.home is None:
        return None
    rel = reg.path[2:] if reg.path.startswith("~/") else reg.path
    return ctx.home.joinpath(*rel.split("/"))


def _claude_project_keys(ctx: _Ctx) -> List[str]:
    keys = [str(ctx.root), ctx.root.as_posix()]
    return list(dict.fromkeys(keys))


def _probe_claude(spec: Any, binary: Optional[str], ctx: _Ctx) -> Dict[str, Any]:
    from aegis_cli import doctor as _doc

    path = _claude_config(ctx)
    if path is None:
        return _doc._registration("unknown", "~/.claude.json", detail="no home directory")
    source = ctx.label(path)
    cfg = ctx.file(path, as_json=True)
    if cfg.error:
        return _doc._registration("unknown", source, detail=f"{source} {cfg.error}")
    data = cfg.data or {}
    projects = data.get("projects") if isinstance(data.get("projects"), dict) else {}
    key = next((k for k in _claude_project_keys(ctx) if isinstance(projects.get(k), dict)), None)
    project = projects[key] if key is not None else {}

    def facts_of(entry: Any) -> Dict[str, Any]:
        facts = _doc._entry_facts(entry, ctx)
        # Claude Code turns off any server this project lists, whatever its scope
        # (user, local or .mcp.json): "turned off; turn it on in /mcp".
        if _doc.SERVER in _names(project.get("disabledMcpServers")):
            facts["enabled"] = False
            facts["detail"] = (f"Claude Code turns aegis off in this project: {source} lists it in "
                               f"projects[{key}].disabledMcpServers; turn it on in Claude Code's /mcp")
        return facts

    local = _server_entry(project)
    user = _server_entry(data)
    if local is not None:
        return _doc._registration("registered", source, scope="local", **facts_of(local))
    if user is not None:
        return _doc._registration("registered", source, scope="user", **facts_of(user))
    dot_mcp = ctx.file(ctx.root / ".mcp.json", as_json=True)
    shared = _server_entry(dot_mcp.data) if not dot_mcp.error else None
    if shared is not None:
        # A project .mcp.json server runs only after the user approves it; that answer
        # lives in settings files doctor does not read, unless .claude.json records it.
        approved = _names(project.get("enabledMcpjsonServers"))
        denied = _names(project.get("disabledMcpjsonServers"))
        approval = ("approved" if _doc.SERVER in approved or project.get("enableAllProjectMcpServers") is True
                    else "denied" if _doc.SERVER in denied else "unknown")
        facts = facts_of(shared)
        if approval == "denied":
            facts["enabled"] = False
        return _doc._registration("registered", ctx.label(ctx.root / ".mcp.json"), scope="project",
                                  approval=approval, **facts)
    return _doc._registration("absent", source)


def _names(value: Any) -> List[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _server_entry(data: Any, name: str = "aegis") -> Optional[Any]:
    if not isinstance(data, dict) or not isinstance(data.get("mcpServers"), dict):
        return None
    return data["mcpServers"].get(name)


def _probe_json_host(spec: Any, binary: Optional[str], ctx: _Ctx) -> Dict[str, Any]:
    from aegis_cli import doctor as _doc

    path = _host_json_path(spec, ctx)
    if path is None:
        return _doc._registration("unknown", spec.registration.path, detail="no home directory")
    source = ctx.label(path)
    cfg = ctx.file(path, as_json=True)
    if cfg.error:
        return _doc._registration("unknown", source, detail=f"{source} {cfg.error}")
    servers = (cfg.data or {}).get(spec.registration.key)
    entry = servers.get(_doc.SERVER) if isinstance(servers, dict) else None
    if entry is None:
        return _doc._registration("absent", source)
    return _doc._registration("registered", source, scope="user", **_doc._entry_facts(entry, ctx))


# ── Legacy v3 hook & block findings (fixable by --fix) ──────────────────────

def _removed_host_phases() -> frozenset:
    """The `aegis hook <phase>` commands v3 host configs called and v4 removed (cli.py's table)."""
    from aegis_cli.cli import _HOST_HOOK, REMOVED_COMMANDS

    return frozenset(name.partition(" ")[2] for name, pointer in REMOVED_COMMANDS.items()
                     if name.startswith("hook ") and pointer == _HOST_HOOK)


def _program_name(token: str) -> str:
    name = re.split(r"[\\/]", token)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def _is_legacy_handler(handler: Any, phases: frozenset) -> bool:
    """Whether a hook handler calls the v3 CLI's hooks or a removed `aegis hook` phase,
    as the program of any command in its (shell) command line."""
    from aegis_cli import doctor as _doc

    if not isinstance(handler, dict) or not isinstance(handler.get("command"), str):
        return False
    command, args = handler["command"], handler.get("args")
    if isinstance(args, list) and args and all(isinstance(a, str) for a in args):
        tokens = [command] + args
    else:
        from aegis_cli.hooks.registrar import command_tokens

        tokens = command_tokens(command)
    starts = True
    for index, token in enumerate(tokens[:-1]):
        if starts and tokens[index + 1] == "hook":
            program = _program_name(token)
            if program == _doc.LEGACY_SERVER:
                return True
            if program == "aegis" and index + 2 < len(tokens) and tokens[index + 2].rstrip(";&|") in phases:
                return True
        starts = token in _COMMAND_STARTERS or token.endswith((";", "&", "|"))
    return False


ListItem = Tuple[Tuple[Any, ...], int]


def _legacy_items(host_id: str, data: Dict[str, Any], phases: frozenset) -> Tuple[List[ListItem], int, int]:
    """(where the v3 entries are, handlers in the file, v3 handlers). A group whose handlers
    are all v3 goes whole; otherwise only its v3 handlers go. Every event counts, not only
    PreToolUse: v3 hooked PreInvocation and Stop too."""
    if host_id == "antigravity":
        containers = [name for name, value in data.items() if isinstance(value, dict)]
    else:
        containers = ["hooks"] if isinstance(data.get("hooks"), dict) else []
    items: List[ListItem] = []
    total = legacy = 0
    for name in containers:
        for event, listed in data[name].items():
            if not isinstance(listed, list):
                continue
            for index, item in enumerate(listed):
                inner = item.get("hooks") if isinstance(item, dict) else None
                if isinstance(inner, list):
                    old = [j for j, h in enumerate(inner) if _is_legacy_handler(h, phases)]
                    total += len(inner)
                    legacy += len(old)
                    if old and len(old) == len(inner):
                        items.append(((name, event), index))
                    else:
                        items.extend(((name, event, index, "hooks"), j) for j in old)
                elif isinstance(item, dict):
                    total += 1
                    if _is_legacy_handler(item, phases):
                        legacy += 1
                        items.append(((name, event), index))
    return items, total, legacy


def _list_location(path: Tuple[Any, ...], index: int) -> str:
    from aegis_cli import doctor as _doc

    out = ""
    for part in path:
        out += f"[{part}]" if isinstance(part, int) else ("." if out else "") + _doc._clean(part)
    return f"{out}[{index}]"


def _legacy_hook_findings(ctx: _Ctx) -> List[_Finding]:
    """v3 hook entries in every hook file of every hook host (selected or not), and the
    stale v3 Antigravity plugin."""
    from aegis_cli import doctor as _doc
    from aegis_cli.hooks import registrar

    files: Dict[str, Tuple[str, Path, bool]] = {}
    for host_id in registrar.HOOK_HOSTS:
        for _scope, path in _hook_files(host_id, ctx):
            files.setdefault(os.path.normcase(os.path.abspath(str(path))), (host_id, path, False))
    if ctx.home is not None:
        plugin = ctx.home.joinpath(*_V3_PLUGIN)
        files.setdefault(os.path.normcase(os.path.abspath(str(plugin))), ("antigravity", plugin, True))
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
        calls = f"call {_doc.LEGACY_SERVER} hook or a removed aegis hook phase"
        if is_plugin:
            code, message = "legacy_hook_plugin", f"{ctx.label(path)}: the stale v3 Antigravity plugin's hooks {calls}"
        else:
            code, message = "legacy_hook_entry", f"{ctx.label(path)}: v3 hook entries {calls}"
        message += f" ({where})"
        action = None
        if entry.refusal:
            message += f"; --fix will not change it: {entry.refusal}"
        elif is_plugin and legacy == total:
            action = _Action(path, "delete_file", _doc._sha256(entry.raw), f"delete the file (it holds only v3 hooks, {where})")
            message += f"; nothing else is in it, so --fix deletes the file. Fix: {_doc._FIX_HINT}"
        else:
            action = _Action(path, "remove_list_items", _doc._sha256(entry.raw), f"remove the v3 hook entries ({where})",
                             items=tuple(items))
            message += f". Fix: {_doc._FIX_HINT}"
        found.append(_Finding(code, path, message, location=where, action=action))
    return found


_LEGACY_MARKER = re.compile(r"^<!-- (SOMA|AEGIS):(START|END) -->[ \t]*$")


def _legacy_ranges(text: str) -> Tuple[List[Tuple[int, int]], bool]:
    """(line ranges of well-formed SOMA/AEGIS START..END blocks, markers are balanced).

    Markers shown inside a fenced code block are text, not a block. Inside an open block
    the content is v3's own (rule text with its fences), so only its END marker counts.
    """
    ranges, open_at, fence = [], None, None
    for index, line in enumerate(text.splitlines(True)):
        bare = line.rstrip("\r\n")
        if index == 0 and bare.startswith(_BOM):
            bare = bare[1:]
        if open_at is None:
            inside = fence is not None
            fence = _fence_step(fence, bare)
            if inside or fence is not None:
                continue
        match = _LEGACY_MARKER.match(bare)
        if not match:
            continue
        kind, edge = match.groups()
        if edge == "START":
            if open_at is not None:
                return ranges, False
            open_at = (index, kind)
        else:
            if open_at is None or open_at[1] != kind:
                return ranges, False
            ranges.append((open_at[0], index))
            open_at = None
    return ranges, open_at is None


def _instruction_files(ctx: _Ctx) -> List[Path]:
    files = [ctx.root / name for name in ("CLAUDE.md", "AGENTS.md", "GEMINI.md")]
    claude_dir = _claude_dir(ctx)
    if claude_dir is not None:
        files.append(claude_dir / "CLAUDE.md")
    if ctx.home is not None:
        codex_home = ctx.environ.get("CODEX_HOME")
        files.append((Path(codex_home) if codex_home else ctx.home / ".codex") / "AGENTS.md")
        files.append(ctx.home / ".gemini" / "GEMINI.md")
    return files


def _legacy_block_findings(ctx: _Ctx) -> List[_Finding]:
    from aegis_cli import doctor as _doc

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
            action = _Action(path, "delete_file", _doc._sha256(entry.raw),
                             f"delete the file (it holds only the legacy block, {where})")
            message += f"; nothing else is in the file, so --fix deletes the file. Fix: {_doc._FIX_HINT}"
        else:
            action = _Action(path, "remove_lines", _doc._sha256(entry.raw), f"remove the legacy block ({where})",
                             lines=tuple(ranges))
            message += f". Fix: {_doc._FIX_HINT}"
        found.append(_Finding("legacy_block", path, message, location=where, action=action))
    return found


def _missing_ast_extensions(ws_root: Path) -> List[str]:
    """Detected source extensions with no AST driver configured (what --fix provisions).

    An unreadable config gives none: the AST check reports it, and --fix will not
    write over a file it cannot parse.
    """
    from aegis_cli import doctor as _doc
    from aegis_core.ast.detect import detect_project_languages
    from aegis_core.skills.slots import SlotRegistry, SlotResolutionError

    if _doc._is_home(ws_root):
        return []
    langs = {k: v for k, v in detect_project_languages(ws_root).items() if k != "python"}
    configured: set = set()
    try:
        registries = (SlotRegistry.load(ws_root), SlotRegistry.load_user(ws_root))
    except SlotResolutionError:
        return []
    for registry in registries:
        for name in registry.to_dict():
            if name == "ast_driver":
                configured.add("default")
            elif name.startswith("ast_driver_"):
                configured.add(f".{name[len('ast_driver_'):]}")
    if "default" in configured:
        return []
    return sorted({ext for info in langs.values() for ext in info.get("extensions", []) if ext not in configured})


# ── The diagnosis ───────────────────────────────────────────────────────────

@dataclass
class _Diagnosis:
    ctx: _Ctx
    rows: List[Dict[str, Any]]
    tiers: List[Dict[str, Any]]
    findings: List[_Finding]
    trust: Any = None  # the human_gate TierReport
    modes: Any = None  # the shared state's StateModes, or None when it cannot be read


def _diagnose(root: Path, environ: Optional[Mapping[str, str]] = None) -> _Diagnosis:
    from aegis_cli import doctor as _doc
    from aegis_cli.doctor_render import _floor_status, _tiers
    from aegis_core.workspace.layout import UserLayout, is_aegis_workspace

    environ = os.environ if environ is None else environ
    layout = UserLayout.current()
    # The home directory's .aegis/ is the user plane (~/.aegis), never a workspace.
    is_home = _doc._is_home(root)
    governed = is_aegis_workspace(root) and not is_home
    ctx = _doc._Ctx(root=root, governed=governed, home=layout.home if layout else None, environ=environ,
                    selected=(), selection="default", is_home=is_home,
                    setup="aegis init" if governed or is_home else _doc._setup_command(root))
    ctx.selected, ctx.selection, notes = _selection(root, governed, ctx)
    selected = ctx.selected
    info = _instructions(ctx)
    roots, skipped = _registered_roots(ctx)
    floor, unreached = _floor_status(root)
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


def _claude_user_registered(ctx: _Ctx) -> bool:
    path = _claude_config(ctx)
    if path is None:
        return False
    cfg = ctx.file(path, as_json=True)
    return not cfg.error and _server_entry(cfg.data) is not None


# ── --fix ───────────────────────────────────────────────────────────────────

class _Refused(Exception):
    """A fix that must not be applied; the message says why."""


def _backup_root(home: Path) -> Path:
    from aegis_cli.install_hosts import _private_dirs
    from aegis_core.workspace.layout import UserLayout

    layout = UserLayout(home)
    for path in (layout.aegis_dir, layout.backups_dir):
        if path.is_symlink():
            raise _Refused(f"{path} is a symlink; Aegis keeps backups only in a real directory")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    target = layout.backups_dir / stamp
    # mkdir(parents=True) modes only the leaf; existing directories are never re-moded.
    _private_dirs(layout.backups_dir)
    target.mkdir(mode=0o700)
    return target


def _current_bytes(path: Path, expected: Optional[str]) -> Optional[bytes]:
    """The file's bytes if it is still the regular, single-link file doctor checked."""
    from aegis_cli import doctor as _doc

    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if expected is None:
            return None
        raise _Refused("it no longer exists")
    refusal = _write_refusal(path, st)
    if refusal:
        raise _Refused(refusal)
    with open(path, "rb") as fh:
        data = fh.read()
    if expected is not None and _doc._sha256(data) != expected:
        raise _Refused("it changed since the check; re-run aegis doctor")
    return data


def _dump_like(original: bytes, data: Dict[str, Any]) -> bytes:
    """``data`` serialized the way ``original`` was: its indent, line endings and final newline."""
    text = original.decode("utf-8")
    match = re.search(r"\n([ \t]+)\"", text)
    indent: Any
    if match:
        indent = match.group(1) if "\t" in match.group(1) else len(match.group(1))
    else:
        indent = 2 if "\n" in text.strip() else None
    out = json.dumps(data, indent=indent, ensure_ascii=False)
    if "\r\n" in text:
        out = out.replace("\n", "\r\n")
    if text.endswith(("\n", "\r\n")):
        out += "\r\n" if "\r\n" in text else "\n"
    return out.encode("utf-8")


def _without_keys(raw: bytes, keys: Sequence[Tuple[str, ...]]) -> bytes:
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs, parse_constant=_reject_constant)
    for path in keys:
        node = data
        for part in path[:-1]:
            node = node.get(part) if isinstance(node, dict) else None
        if not isinstance(node, dict) or path[-1] not in node:
            raise _Refused(f"{_location(path)} is no longer there")
        del node[path[-1]]
    return _dump_like(raw, data)


def _without_lines(raw: bytes, ranges: Sequence[Tuple[int, int]]) -> Optional[bytes]:
    """The bytes with the line ranges removed, or None when nothing but whitespace is left.

    A byte-order mark stays at the start of the file even when its first line goes.
    """
    text = raw.decode("utf-8")
    bom = _BOM if text.startswith(_BOM) else ""
    lines = text[len(bom):].splitlines(True)
    drop = {i for a, b in ranges for i in range(a, b + 1)}
    kept = "".join(line for i, line in enumerate(lines) if i not in drop)
    return (bom + kept).encode("utf-8") if kept.strip(" \t\r\n") else None


def _without_list_items(raw: bytes, items: Sequence[Tuple[Tuple[Any, ...], int]]) -> bytes:
    """The JSON with the listed entries removed from their lists. ``raw`` is byte-identical
    to what doctor checked (sha256), so every path resolves; every list is found before any
    entry goes, so removing one never shifts another's index."""
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs, parse_constant=_reject_constant)
    targets: Dict[int, Tuple[list, set]] = {}
    for path, index in items:
        node: Any = data
        for part in path:
            node = node[part]
        targets.setdefault(id(node), (node, set()))[1].add(index)
    for node, indexes in targets.values():
        for index in sorted(indexes, reverse=True):
            del node[index]
    return _dump_like(raw, data)


@dataclass
class _Change:
    path: Path
    kind: str
    sha256: Optional[str]
    describe: List[str] = field(default_factory=list)
    keys: List[Tuple[str, ...]] = field(default_factory=list)
    lines: List[Tuple[int, int]] = field(default_factory=list)
    items: List[Tuple[Tuple[Any, ...], int]] = field(default_factory=list)


def _plan(findings: List[_Finding], ast_missing: List[str], root: Path) -> List[_Change]:
    changes: Dict[str, _Change] = {}
    for finding in findings:
        action = finding.action
        if action is None:
            continue
        key = os.path.normcase(os.path.abspath(str(action.path)))
        change = changes.setdefault(key, _Change(action.path, action.kind, action.sha256))
        change.describe.append(action.describe)
        change.keys.extend(action.keys)
        change.lines.extend(action.lines)
        change.items.extend(action.items)
    plan = list(changes.values())
    if ast_missing:
        from aegis_core.workspace.layout import WorkspaceLayout

        plan.append(_Change(WorkspaceLayout(root).config_file, "enable_packaged_ast_drivers", None,
                            [f"enable the packaged AST drivers for {', '.join(ast_missing)}"]))
    return plan


def _apply(plan: List[_Change], home: Optional[Path], root: Path) -> Tuple[List[Dict[str, Any]], Optional[Path]]:
    from aegis_cli import doctor as _doc
    from aegis_core.storage import atomic_write_bytes

    results: List[Dict[str, Any]] = []

    def result(change: _Change, status: str, action: str, reason: Optional[str] = None) -> None:
        results.append({"action": action, "path": str(change.path), "status": status,
                        "changes": list(change.describe), "reason": None if reason is None else _doc._clean(reason, 1024)})

    if home is None:
        for change in plan:
            result(change, "failed", change.kind, "no home directory for ~/.aegis/backups")
        return results, None
    try:
        backup = _backup_root(home)
    except (_Refused, OSError) as exc:
        for change in plan:
            result(change, "failed", change.kind, f"no backup could be made: {exc}")
        return results, None

    manifest: List[Dict[str, Any]] = []
    for index, change in enumerate(plan, 1):
        action = change.kind
        try:
            current = _current_bytes(change.path, change.sha256)
            if current is not None:
                name = f"{index:02d}-{change.path.name}"
                # Owner-only whatever the original's bits: a backup of ~/.claude.json holds tokens.
                atomic_write_bytes(backup / name, current, mode=0o600)
                manifest.append({"path": str(change.path), "backup": name, "sha256": _doc._sha256(current),
                                 "action": action})
                _write_manifest(backup, manifest)
            if change.kind == "remove_keys":
                atomic_bytes = _without_keys(current, change.keys)
                _current_bytes(change.path, change.sha256)  # compare before replace
                atomic_write_bytes(change.path, atomic_bytes, follow_links=False)
            elif change.kind == "remove_list_items":
                edited = _without_list_items(current, change.items)
                _current_bytes(change.path, change.sha256)
                atomic_write_bytes(change.path, edited, follow_links=False)
            elif change.kind == "remove_lines":
                kept = _without_lines(current, change.lines)
                if kept is None:  # the plan said "edit"; deleting would be a change nobody confirmed
                    raise _Refused("only the legacy block would be left; re-run aegis doctor")
                _current_bytes(change.path, change.sha256)
                atomic_write_bytes(change.path, kept, follow_links=False)
            elif change.kind == "delete_file":
                _current_bytes(change.path, change.sha256)
                os.unlink(change.path)
            elif change.kind == "enable_packaged_ast_drivers":
                from aegis_core.ast.detect import detect_project_languages, provision_ast_driver_slots

                provision_ast_driver_slots(root, detect_project_languages(root))
        except _Refused as exc:
            result(change, "skipped", action, str(exc))
            continue
        except Exception as exc:  # report and keep going: other files are independent
            result(change, "failed", action, str(exc))
            continue
        result(change, "applied", action)
    return results, backup


def _write_manifest(backup: Path, files: List[Dict[str, Any]]) -> None:
    from aegis_cli import doctor as _doc
    from aegis_core.storage import atomic_write_bytes

    doc = {"schema": "aegis.doctor.backup/v1", "created_at": _doc._utc_now(), "aegis_version": _doc._aegis_version(),
           "files": files}
    atomic_write_bytes(backup / "manifest.json", (json.dumps(doc, indent=2) + "\n").encode("utf-8"), mode=0o600)
