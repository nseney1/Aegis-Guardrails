"""The agent hosts Aegis knows about, as data (host-matrix spec v2, section 3.3).

A *host* is a product whose surfaces share one configuration plane: the Codex
CLI, IDE extension and desktop app all read ``~/.codex``, so they are one host.
``surfaces`` names them for people, and ``aliases`` lets ``--host`` take a surface
name (``codex-app``, ``kiro-ide``); :func:`resolve` maps it to the plane id, which is
what configs and the registry store. Vendor is metadata only. Installers, the doctor
and the MCP server read this table; a host gets real code only when it needs logic
the table cannot express.

Evidence labels in comments (v4.1 rev 3.1 research): DOC is the vendor's
documentation, SECONDARY an issue or user report, UNVERIFIED an inference neither
documented nor checked on a real install.

Rows marked ``verified=False`` describe documented behaviour that has not been
checked on a real install; ``aegis init`` warns before using them (and records an
``init_host`` event), and ``aegis doctor`` labels them experimental.

Experimental rows (cursor, copilot, kiro, windsurf; v4.2 #6): a row flips to
``verified=True`` only after 3 clean runs on real installs (ADR 0007 section 4), by hand:
a maintainer sets the flag in a commit that cites the runs, and there is no automation
that flips it. A clean run is ``aegis init --host <id>`` followed by ``aegis doctor``
reporting the host ``ok``, and the host calling ``aegis_scan`` in a session. A row still
unverified after two minor releases is a candidate for removal (the prune row for
experimental hosts, v4.1-v4.2 spec).
"""
from __future__ import annotations

__all__ = ["APP_DIRS", "GENERIC", "HOSTS", "INSTRUCTION_MODES", "HostSpec", "Registration", "all_hosts",
           "app_paths", "get", "identify", "resolve"]

from dataclasses import dataclass, field
import os
import re
from typing import List, Mapping, Optional, Tuple, Union

#: Instruction-file behaviour of a host.
#: ``agents_md``                  reads AGENTS.md natively.
#: ``agents_md_unless_claude_md`` reads AGENTS.md only when no CLAUDE.md exists
#:                                (Claude Code >= 2.1.277); a CLAUDE.md needs an
#:                                ``@AGENTS.md`` import block.
#: ``gemini_md``                  reads GEMINI.md unless settings list AGENTS.md.
#: ``none``                       has no instruction file (identity-only host).
INSTRUCTION_MODES = ("agents_md", "agents_md_unless_claude_md", "gemini_md", "none")

GENERIC = "generic"

#: Where each platform (``sys.platform``) installs desktop apps, for host detection.
#: ``~/`` is the user's home and ``%NAME%/`` an environment variable; the rest are
#: machine-wide. A host's ``apps`` names its app in these directories.
APP_DIRS = {
    "darwin": ("/Applications", "~/Applications"),
    "win32": ("%LOCALAPPDATA%/Programs",),
}


@dataclass(frozen=True)
class Registration:
    """How ``aegis init`` registers the MCP server for a host.

    ``native_cli``: run ``argv`` (``{command}`` is replaced by the absolute
    ``aegis-mcp`` command). ``json_file``: merge an ``aegis`` entry into
    ``path`` under ``key`` (``~`` is the user's home directory).
    """

    kind: str  # "native_cli" | "json_file"
    argv: Tuple[str, ...] = ()
    path: str = ""
    key: str = "mcpServers"


@dataclass(frozen=True)
class HostSpec:
    id: str
    display_name: str
    vendor: str
    client_names: Tuple[str, ...] = ()
    client_prefixes: Tuple[str, ...] = ()
    binaries: Tuple[str, ...] = ()
    #: Files or directories (``~/`` is home) whose presence shows the plane is on this
    #: machine, as an IDE or desktop app leaves no binary on PATH.
    config_paths: Tuple[str, ...] = ()
    instructions: str = "none"
    budget_bytes: Optional[int] = None
    registration: Optional[Registration] = None
    slot_profile: str = GENERIC
    phase: int = 1
    verified: bool = True
    notes: Tuple[str, ...] = field(default_factory=tuple)
    #: Why Aegis refuses a host it no longer supports, as ``aegis init --host`` prints it;
    #: empty for any other host. A retired row stays only so identify() names its client.
    retired: str = ""
    #: Workspace-relative POSIX directory the host reads project skills from
    #: (``<skills_dir>/<id>/SKILL.md``, v4.1 §3), or None when it has none.
    skills_dir: Optional[str] = None
    #: Whether ``skills_dir`` was checked on a real install. Separate from ``verified``,
    #: which covers the rest of the row.
    skills_verified: bool = False
    #: The products that read this plane (CLI, IDE extension, desktop app), for output.
    surfaces: Tuple[str, ...] = ()
    #: Surface names ``--host`` also accepts for this plane (see :func:`resolve`).
    aliases: Tuple[str, ...] = ()
    #: (``sys.platform``, app name in that platform's APP_DIRS) of the plane's desktop apps.
    apps: Tuple[Tuple[str, str], ...] = ()
    #: For a host Aegis never registers: where a surface of it that Aegis does govern goes.
    redirect: str = ""


HOSTS: Tuple[HostSpec, ...] = (
    HostSpec(
        id="codex-cli",
        display_name="Codex CLI",
        vendor="OpenAI",
        client_names=("codex-mcp-client",),
        binaries=("codex",),
        config_paths=("~/.codex",),
        instructions="agents_md",
        budget_bytes=32 * 1024,
        registration=Registration(
            kind="native_cli",
            argv=("codex", "mcp", "add", "aegis", "--env", "AEGIS_CLIENT=codex-cli", "--", "{command}"),
        ),
        slot_profile="codex-cli",
        skills_dir=".agents/skills",  # UNVERIFIED: neither documented nor probed
        # DOC: "The ChatGPT desktop app, Codex CLI, and IDE extension share this
        # configuration" ($CODEX_HOME); the IDE and the app run bundled copies of the core.
        surfaces=("Codex CLI", "Codex IDE extension", "ChatGPT desktop app (Codex mode)"),
        aliases=("codex", "codex-ide", "codex-app", "chatgpt-desktop"),
        apps=(("darwin", "Codex.app"),),  # DOC: the app's retained /Applications/Codex.app path
        notes=(
            "AGENTS.md over 32 KiB is truncated silently.",
            "Hooks need trust in /hooks and fail open on errors.",
        ),
    ),
    HostSpec(
        id="claude-code",
        display_name="Claude Code",
        vendor="Anthropic",
        client_names=("claude-code",),
        binaries=("claude",),
        config_paths=("~/.claude", "~/.claude.json"),
        instructions="agents_md_unless_claude_md",
        budget_bytes=40 * 1024,
        registration=Registration(
            kind="native_cli",
            argv=("claude", "mcp", "add", "--scope", "user", "aegis", "-e", "AEGIS_CLIENT=claude-code", "--", "{command}"),
        ),
        slot_profile="claude-code",
        skills_dir=".claude/skills",  # DOC: official docs, not probed
        notes=("PreToolUse hooks can block with exit 2.",),
        # DOC: "Desktop and CLI read the same configuration files"; the VS Code extension
        # bundles the CLI and the JetBrains plugin runs the installed one.
        surfaces=("Claude Code CLI", "Claude Code IDE extensions", "Claude desktop app (Code tab)"),
        aliases=("claude-desktop-code",),
    ),
    HostSpec(
        id="claude-desktop",
        display_name="Claude Desktop",
        vendor="Anthropic",
        client_prefixes=("local-agent-mode-",),
        instructions="none",
        slot_profile=GENERIC,
        notes=("Identity only: Aegis does not register here.",),
        # Chat and Cowork read claude_desktop_config.json, have no workspace and no AGENTS.md
        # (DOC), and the MCP roots they send are the union of open sessions (live probe).
        surfaces=("Claude desktop app (chat)", "Claude desktop app (Cowork)"),
        redirect="the Claude desktop app's Code tab shares Claude Code's configuration: use --host claude-code",
    ),
    HostSpec(
        id="antigravity",
        display_name="Antigravity",
        vendor="Google",
        client_names=("antigravity-client",),
        binaries=("agy",),
        config_paths=("~/.gemini/config", "~/.gemini/antigravity"),
        instructions="agents_md",
        budget_bytes=24000,
        registration=Registration(kind="json_file", path="~/.gemini/config/mcp_config.json", key="mcpServers"),
        slot_profile="antigravity",
        skills_dir=".agents/skills",  # DOC: official docs, not probed
        notes=("Sends no MCP roots; the workspace registry is its only binding route.",),
        # DOC for hooks, rules and AGENTS.md; the app's MCP file is UNVERIFIED (same format).
        surfaces=("Antigravity app", "Antigravity IDE", "agy CLI"),
        aliases=("antigravity-app", "antigravity-ide"),
    ),
    HostSpec(
        id="gemini-cli",
        display_name="Gemini CLI",
        vendor="Google",
        client_names=("gemini-cli-mcp-client",),
        binaries=("gemini",),
        config_paths=("~/.gemini",),
        instructions="gemini_md",
        registration=None,
        slot_profile="gemini-cli",
        phase=2,
        verified=False,
        notes=(
            "Retired: Google no longer serves Gemini CLI to individual Code Assist accounts; "
            "Antigravity is the Gemini-family host. Identity only.",
        ),
        retired=("gemini-cli is not supported: Google retired Gemini CLI for individual Code Assist "
                 "accounts; use --host antigravity."),
    ),
    HostSpec(
        id="kiro",
        display_name="Kiro",
        vendor="AWS",
        # DOC https://kiro.dev/docs/mcp/configuration/ (user ~/.kiro/settings/mcp.json,
        # workspace .kiro/settings/mcp.json, top-level mcpServers).
        # SECONDARY: a Kiro IDE 0.11 log shows clientInfo "kiro"; the Kiro CLI's name is
        # UNVERIFIED (closed source), so it is identified by AEGIS_CLIENT alone.
        client_names=("kiro",),
        binaries=("kiro-cli",),  # DOC
        # DOC: "your .kiro configuration is shared across all of them" (IDE and CLI).
        # KIRO_HOME relocates it for CLI V3 only; the IDE is not documented to honor it.
        config_paths=("~/.kiro",),
        instructions="agents_md",  # DOC: AGENTS.md is always included
        # DOC: ~/.kiro/settings/mcp.json {"mcpServers": {name: {command, args, env}}}. The
        # workspace .kiro/settings/mcp.json is not written: no committed MCP files (§3.2).
        registration=Registration(kind="json_file", path="~/.kiro/settings/mcp.json", key="mcpServers"),
        slot_profile=GENERIC,
        verified=False,
        notes=(
            "Its row follows the vendor's documentation and is not yet checked on a real install.",
            "It becomes verified only after 3 clean runs (ADR 0007 section 4).",
            "No Aegis hooks: Kiro's hook semantics for blocking are not verified.",
            "MCP support must be switched on in Kiro's settings.",
        ),
        surfaces=("Kiro IDE", "Kiro CLI"),
        aliases=("kiro-ide", "kiro-cli"),
        # darwin: UNVERIFIED (the usual bundle name); win32: SECONDARY (issue #10486 shows
        # %LOCALAPPDATA%\Programs\Kiro as the install directory).
        apps=(("darwin", "Kiro.app"), ("win32", "Kiro")),
    ),
    HostSpec(
        id="cursor",
        display_name="Cursor",
        vendor="Anysphere",
        # DOC https://cursor.com/docs/context/mcp (global ~/.cursor/mcp.json, project
        # .cursor/mcp.json, top-level mcpServers; a stdio server is command/args/env).
        # AGENTS.md at the project root: DOC https://cursor.com/docs/context/rules.
        # UNVERIFIED: Cursor's MCP clientInfo name is not documented, so none is claimed (a
        # "cursor-vscode" seen in the wild is not matched); the registration's AEGIS_CLIENT
        # names the host. The project file .cursor/mcp.json is not written: no committed MCP
        # files (host-matrix spec 3.2).
        binaries=("cursor-agent", "cursor"),
        config_paths=("~/.cursor",),
        instructions="agents_md",
        registration=Registration(kind="json_file", path="~/.cursor/mcp.json", key="mcpServers"),
        slot_profile=GENERIC,
        verified=False,
        notes=(
            "Its row follows the vendor's documentation and is not yet checked on a real install.",
            "It becomes verified only after 3 clean runs (ADR 0007 section 4).",
            "No Aegis hooks: Cursor's hook semantics are not verified.",
        ),
        surfaces=("Cursor IDE", "Cursor CLI (cursor-agent)"),
        aliases=("cursor-ide", "cursor-cli"),
        # darwin and win32 install directories: UNVERIFIED (the usual bundle and per-user
        # install names).
        apps=(("darwin", "Cursor.app"), ("win32", "cursor")),
    ),
    HostSpec(
        id="copilot",
        display_name="GitHub Copilot",
        vendor="GitHub",
        # DOC https://code.visualstudio.com/docs/copilot/customization/mcp-servers : Copilot's
        # user-scope MCP file is $COPILOT_HOME/mcp-config.json, else ~/.copilot/mcp-config.json,
        # top-level mcpServers. VS Code's own user-profile mcp.json (top-level "servers") sits in
        # an operating-system specific profile directory the page does not spell out, so it is
        # not registered. The page does not say which Copilot surfaces read ~/.copilot, nor name
        # a clientInfo; both are UNVERIFIED. AGENTS.md: UNVERIFIED (the page does not mention it).
        binaries=("copilot",),
        config_paths=("~/.copilot",),
        instructions="agents_md",
        registration=Registration(kind="json_file", path="~/.copilot/mcp-config.json", key="mcpServers"),
        slot_profile=GENERIC,
        verified=False,
        notes=(
            "Its row follows the vendor's documentation and is not yet checked on a real install.",
            "It becomes verified only after 3 clean runs (ADR 0007 section 4).",
            "Which Copilot surfaces read ~/.copilot/mcp-config.json is not documented; COPILOT_HOME moves it.",
            "No Aegis hooks: Copilot's hook semantics are not verified.",
        ),
        surfaces=("GitHub Copilot in VS Code (agent mode)", "GitHub Copilot CLI"),
        aliases=("github-copilot", "copilot-cli", "vscode-copilot"),
    ),
    HostSpec(
        id="windsurf",
        display_name="Windsurf",
        vendor="Windsurf",
        # DOC https://docs.windsurf.com/windsurf/cascade/mcp (the page now redirects to
        # https://docs.devin.ai/desktop/cascade/mcp, which documents ~/.config/devin/mcp_config.json
        # and %APPDATA%\devin\mcp_config.json for the legacy Cascade agent in Devin Desktop).
        # SECONDARY: guides and the long-standing Windsurf docs give ~/.codeium/windsurf/mcp_config.json
        # on every platform, top-level mcpServers, no project-level file. The row keeps that path
        # until a real install shows which one the current app reads. Windsurf's clientInfo name
        # and its reading of AGENTS.md are UNVERIFIED.
        binaries=("windsurf",),
        config_paths=("~/.codeium/windsurf",),
        instructions="agents_md",
        registration=Registration(kind="json_file", path="~/.codeium/windsurf/mcp_config.json", key="mcpServers"),
        slot_profile=GENERIC,
        verified=False,
        notes=(
            "Its row follows the vendor's documentation and is not yet checked on a real install.",
            "It becomes verified only after 3 clean runs (ADR 0007 section 4).",
            "The vendor's current docs name ~/.config/devin/mcp_config.json (Devin Desktop); this row uses "
            "~/.codeium/windsurf/mcp_config.json.",
            "No Aegis hooks: Windsurf's hook semantics are not verified.",
        ),
        surfaces=("Windsurf IDE",),
        aliases=("windsurf-ide",),
        # UNVERIFIED install names.
        apps=(("darwin", "Windsurf.app"), ("win32", "Windsurf")),
    ),
)

_BY_ID = {h.id: h for h in HOSTS}


def get(host_id: str) -> HostSpec:
    """Return the host with this id; raise KeyError naming the known ids."""
    try:
        return _BY_ID[host_id]
    except KeyError:
        raise KeyError(f"unknown host {host_id!r}; known hosts: {', '.join(_BY_ID)}") from None


_BY_ALIAS = {alias: h.id for h in HOSTS for alias in h.aliases}


def resolve(name: str) -> str:
    """The plane id ``name`` names: a host id, or a surface alias of one; KeyError otherwise."""
    if name in _BY_ID:
        return name
    try:
        return _BY_ALIAS[name]
    except KeyError:
        raise KeyError(f"unknown host {name!r}; known hosts: {', '.join(_BY_ID)}; "
                       f"surface aliases: {', '.join(_BY_ALIAS)}") from None


_ENV_PREFIX = re.compile(r"^%([A-Za-z_][A-Za-z0-9_]*)%/")


def _place(directory: str, home: Union[str, "os.PathLike[str]"], environ: Mapping[str, str]) -> Optional[str]:
    """``directory`` of APP_DIRS made concrete, or None when its variable names no absolute path."""
    if directory.startswith("~/"):
        return os.path.join(os.fspath(home), *directory[2:].split("/"))
    match = _ENV_PREFIX.match(directory)
    if match:
        base = environ.get(match.group(1), "")
        if not base or not os.path.isabs(base):
            return None
        return os.path.join(base, *directory[match.end():].split("/"))
    return directory


def app_paths(host: HostSpec, home: Union[str, "os.PathLike[str]"], environ: Mapping[str, str],
              platform: str) -> List[str]:
    """Where ``host``'s desktop apps would be installed on ``platform``, in APP_DIRS order."""
    names = [name for plat, name in host.apps if plat == platform]
    found = []
    for directory in APP_DIRS.get(platform, ()):
        place = _place(directory, home, environ)
        if place is not None:
            found.extend(os.path.join(place, name) for name in names)
    return found


def all_hosts(phase: Optional[int] = None) -> Tuple[HostSpec, ...]:
    """All hosts, or only those available in phases up to ``phase``."""
    if phase is None:
        return HOSTS
    return tuple(h for h in HOSTS if h.phase <= phase)


def identify(client_name: Optional[str]) -> str:
    """Map an MCP ``clientInfo.name`` to a host id; unknown clients are ``generic``.

    Matching is exact except for declared prefixes (Claude Desktop appends a
    per-install key). It never defaults to a vendor guess.
    """
    if not client_name:
        return GENERIC
    for host in HOSTS:
        if client_name in host.client_names:
            return host.id
    for host in HOSTS:
        if any(client_name.startswith(p) for p in host.client_prefixes):
            return host.id
    return GENERIC
