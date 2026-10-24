"""aegis package — write an experimental Claude Code plugin directory (v4.2 #8).

``aegis package --host claude-code [--out DIR]`` writes ``.claude-plugin/plugin.json``, the
Aegis MCP server (``.mcp.json``), the v4.1 pre-tool hook (``hooks/hooks.json``) and the
packaged skills (``skills/``), laid out as Claude Code's plugin docs describe
(aegis_core.packaging). Experimental: nothing is published, and the directory names
absolute paths on this machine. Only claude-code; the Gemini CLI is retired.

The MCP server is the absolute ``aegis-mcp`` or the isolated ``-I -c`` runner, never
``python -m`` (the same choice ``aegis init`` registers); the hook is the exec-form group
``aegis hook install`` writes, after the same ``hook run`` probe; the skills are the
Claude Code projection ``aegis skills sync`` makes. No host CLI is run.

Exit codes: 0 done, 1 the plugin cannot be built or written (nothing is written), 2 usage.
A real run in an Aegis workspace appends one ``package`` event; ``--dry-run`` writes
nothing. With --json, stdout carries only the JSON document.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

from aegis_core import primitives
from aegis_cli import resolve_root, sanitize_display
from aegis_cli.base import AegisCommand, CommandCategory
from aegis_core import hosts as host_table
from aegis_core import packaging
from aegis_core._version import __version__
from aegis_core.workspace.layout import is_aegis_workspace

__all__ = ["PackageCommand", "run_package"]

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
HOST = "claude-code"
DEFAULT_OUT = "aegis-claude-plugin"
NOTICE = "experimental: nothing is published; the directory works only on this machine"


def _envelope(root: Path, out: Any) -> Dict[str, Any]:
    return primitives.envelope("aegis package", {"workspace": str(root), "host": HOST, "out": str(out)})


def _host_problem(chosen: Optional[str]) -> Optional[str]:
    if chosen == HOST:
        return None
    shown = sanitize_display(chosen, max_len=None) if chosen else "none given"
    message = f"only --host {HOST} is supported (got {shown})"
    try:
        retired = host_table.get(chosen).retired if chosen else None
    except KeyError:
        retired = None
    return f"{message}; {retired}" if retired else message


def _build(root: Path) -> Dict[str, bytes]:
    """The plugin's files; PackagingError or InstallError says why not. Everything the
    plugin names is resolved here, once, so a refusal comes before any write."""
    from aegis_cli import install_hosts, skills_sync
    from aegis_cli.hooks import registrar
    from aegis_cli.init import packaged_dir

    aegis = registrar.aegis_command(outside=root)
    if aegis is None:
        raise packaging.PackagingError(
            "no absolute aegis found on PATH or beside this Python; install aegis-guardrails so the plugin's hook "
            "can name it")
    registrar.probe_hook_run(HOST, aegis)
    skills, errors = skills_sync._packaged_skills(packaged_dir("skills"))
    if errors:
        raise packaging.PackagingError("; ".join(errors))
    profile = host_table.get(HOST).slot_profile
    return packaging.build_plugin(
        version=__version__,
        mcp=install_hosts.mcp_entry(HOST, install_hosts.mcp_command()),
        hook_group=registrar.hook_group(HOST, aegis),
        skills={skill.id: skills_sync._render(skill, profile) for skill in skills},
    )


def _record(root: Path, out: Path, plan: List[Any]) -> Optional[str]:
    from aegis_core import events

    counts: Dict[str, int] = {}
    for _path, state in plan:
        counts[state] = counts.get(state, 0) + 1
    detail = {"out": out.as_posix(), "files": len(plan), "counts": counts, "experimental": True}
    exc = events.try_append(root, "package", "ok", detail, host=HOST)
    if exc is not None:
        return f"the package event could not be recorded ({type(exc).__name__}: {exc})"
    return None


def run_package(args: argparse.Namespace) -> int:
    root = Path(resolve_root(args))
    use_json = bool(getattr(args, "json", False))
    dry_run = bool(getattr(args, "dry_run", False))
    problem = _host_problem(getattr(args, "host", None))
    if problem:
        print(f"Error: {problem}", file=sys.stderr)
        return EXIT_USAGE
    out = Path(getattr(args, "out", None) or root / DEFAULT_OUT)
    try:
        plan = packaging.write_plugin(out, _build(root), dry_run=dry_run)
    except Exception as exc:
        from aegis_cli.install_hosts import InstallError

        if not isinstance(exc, (packaging.PackagingError, InstallError, OSError)):
            raise
        if use_json:
            print(json.dumps({**_envelope(root, out), "status": "error", "experimental": True, "error": str(exc)},
                             indent=2))
        else:
            print(f"Error: {sanitize_display(exc, max_len=None)}", file=sys.stderr)
        return EXIT_FAILED

    warnings: List[str] = []
    recorded = False
    if not dry_run and is_aegis_workspace(root):
        warning = _record(root, out, plan)
        recorded = warning is None
        if warning:
            warnings.append(warning)
    counts: Dict[str, int] = {}
    for _path, state in plan:
        counts[state] = counts.get(state, 0) + 1
    if use_json:
        doc = _envelope(root, out)
        doc.update({"status": "ok", "experimental": True, "notice": NOTICE, "dry_run": dry_run,
                    "files": [{"path": path, "result": state} for path, state in plan],
                    "counts": counts, "recorded": recorded, "warnings": warnings})
        print(json.dumps(doc, indent=2))
        return EXIT_OK
    verb = {"created": "would create", "updated": "would update"} if dry_run else {}
    for path, state in plan:
        print(f"  {verb.get(state, state)}: {sanitize_display(path, max_len=None)}")
    print(f"Claude Code plugin at {sanitize_display(out, max_len=None)}: " + ", ".join(f"{n} {k}" for k, n in counts.items()))
    print(NOTICE.capitalize() + ". Try it with: claude --plugin-dir " + sanitize_display(out, max_len=None))
    if recorded:
        print("Recorded a package event.")
    for warning in warnings:
        print(f"Warning: {sanitize_display(warning, max_len=None)}", file=sys.stderr)
    return EXIT_OK


class PackageCommand(AegisCommand):
    """Write an experimental Claude Code plugin directory."""

    name = "package"
    category = CommandCategory.SETUP
    help = "Write an experimental Claude Code plugin directory (MCP server, hook, skills); nothing is published"
    description = (
        "Write a Claude Code plugin directory: .claude-plugin/plugin.json, the Aegis MCP server (.mcp.json), the "
        "pre-tool hook (hooks/hooks.json) and the packaged skills (skills/). Experimental: nothing is published, "
        "and the directory names absolute paths on this machine, so it works only here. Only --host claude-code "
        "is supported; the Gemini CLI is retired. In an Aegis workspace a real run appends one package event."
    )

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--host", default=None, metavar="claude-code",
                            help="The host to package for; only claude-code")
        parser.add_argument("--out", default=None, metavar="DIR",
                            help=f"Where to write the plugin (default ./{DEFAULT_OUT} in the workspace); an "
                                 "existing directory must be empty or an earlier Aegis plugin")
        parser.add_argument("--dry-run", action="store_true", help="Report what would be written; write nothing")

    def execute(self, args: argparse.Namespace) -> int:
        return run_package(args)
