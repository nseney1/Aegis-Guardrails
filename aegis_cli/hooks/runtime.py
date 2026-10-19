"""`aegis hook`: manage the git pre-commit hook, run the agent-host PreToolUse hook,
and the isolated safety gate.

The commit gate itself is `aegis check --hook`, which the installed hook runs.
`aegis hook run pre-tool --host <h>` is what the per-host hook registrations call
(aegis_cli/hooks/pretool.py); ``cli.main`` dispatches that form before it parses or
attaches a workspace, so the parser below serves its help and a form with global
options first (``aegis --plain hook run ...``). Agent-side lifecycle phases (pre-invocation,
session-close, post-session, ...) were cut in v4 (ADR 0005 D15). `safety-gate`
stays as a manual check of one command (it fails closed: it asks).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from aegis_cli.base import AegisCommand, CommandCategory
from aegis_cli.hooks.management import (
    run_hook_install,
    run_hook_status,
    run_hook_uninstall,
)
from aegis_cli.hooks.safety import run_safety_gate

__all__ = ["run_hook", "HookCommand"]


def _run_safety_gate(args: Any) -> int:
    workspace = Path(args.workspace) if getattr(args, "workspace", None) else Path.cwd()
    cmd = getattr(args, "cmd", None)
    payload = None
    if cmd is None and not sys.stdin.isatty():
        try:
            raw = sys.stdin.read().strip()
            if raw:
                payload = json.loads(raw)
        except Exception:
            pass
    rc, res = run_safety_gate(cmd=cmd, payload=payload, workspace=workspace)
    print(json.dumps(res))
    return rc


def _install_description() -> str:
    from aegis_cli.hooks import registrar

    gaps = "".join(f"  - {gap}\n" for gap in registrar.KNOWN_GAPS)
    return (
        "Without --host: install the git pre-commit hook (it runs aegis check --hook).\n\n"
        f"With --host {'|'.join(registrar.HOOK_HOSTS)}: register `aegis hook run pre-tool --host <h>` as that "
        "host's PreToolUse hook, at user scope (default) or, with --scope project, in the repository's host "
        "file, which teammates' hosts will execute. The merge keeps everything else in the file, refuses "
        "unparseable, symlinked or hard-linked files, and backs the old file up to "
        "~/.aegis/backups/<stamp>/<scope>/. Codex also gets ~/.codex/rules/aegis.rules and runs the hook only "
        "after you trust it in /hooks; Antigravity hooks are unavailable on Windows. aegis doctor shows each "
        "host's entries and tier; it cannot confirm that a host runs them. " + _HOME_NOTE + "\n\n"
        f"Known gaps:\n{gaps}")


#: Every aegis command but `hook run` attaches a workspace first, and $HOME never is one.
_HOME_NOTE = ("Run it from any directory but your home directory, which Aegis never takes as a workspace, even "
              "for --scope user (which changes only your user files).")


def _uninstall_description() -> str:
    return (
        "Without --host: remove the aegis block from the git pre-commit hook.\n\n"
        "With --host: remove Aegis's PreToolUse entries and its insight capture (UserPromptSubmit) entries "
        "from that host's files at --scope (default: both scopes) and nothing else, backing each file up first; "
        "for Codex also ~/.codex/rules/aegis.rules once no Aegis Codex hook is left. " + _HOME_NOTE)


def _host_options(parser: Any, host_help: str, scope_help: str) -> None:
    from aegis_cli.hooks import registrar

    hosts = ", ".join(registrar.HOOK_HOSTS)
    parser.add_argument("--host", default=None, metavar="HOST", help=f"{host_help}: {hosts}")
    parser.add_argument("--scope", default=None, choices=registrar.SCOPES, help=scope_help)


def run_hook(args: Any) -> int:
    """Dispatch `aegis hook <action>`; no action shows the hook status."""
    action = getattr(args, "hook_action", None)
    if action in ("install", "uninstall"):
        # run_hook is public: a caller's own Namespace may predate --host and --scope.
        if getattr(args, "host", None) is None:
            if getattr(args, "scope", None) is not None:
                print(f"aegis hook {action}: --scope needs --host", file=sys.stderr)
                return 2
            return run_hook_install(args) if action == "install" else run_hook_uninstall(args)
        if getattr(args, "force", False):
            # --force lets the git hook replace a link; host files are never written through one.
            print(f"aegis hook {action}: --force applies only to the git hook; with --host nothing is "
                  "forced (a linked or unparseable host file is always refused)", file=sys.stderr)
            return 2
        from aegis_cli.hooks import registrar

        return registrar.run_host_install(args) if action == "install" else registrar.run_host_uninstall(args)
    if action == "safety-gate":
        return _run_safety_gate(args)
    if action == "run":
        # Imported here: every aegis command loads this module, and only hooks need the
        # guard, the payload normalization and the events log.
        from aegis_cli.hooks.pretool import run_hook_run

        return run_hook_run(args)
    return run_hook_status(args)


class HookCommand(AegisCommand):
    """Manage the git pre-commit hook and the agent hosts' PreToolUse hooks."""

    name = "hook"
    category = CommandCategory.PLUMBING
    help = "Install, inspect or remove the git pre-commit hook and the agent hosts' PreToolUse hooks"

    def configure_parser(self, parser: Any, parents: Any = None) -> None:
        p_hook_sub = parser.add_subparsers(dest="hook_action")
        p_parents = parents or []

        p_hook_install = p_hook_sub.add_parser(
            "install", parents=p_parents,
            help="Install the git pre-commit hook, or with --host an agent host's PreToolUse hook",
            description=_install_description(), formatter_class=argparse.RawDescriptionHelpFormatter)
        p_hook_install.add_argument("--force", action="store_true",
                                    help="Git hook only: overwrite symlinks pointing outside repository")
        p_hook_install.add_argument("--dry-run", action="store_true", help="Preview without creating or modifying hook")
        _host_options(p_hook_install, "Register the PreToolUse hook with this host instead of the git hook",
                      "With --host: user (default) or project")

        p_hook_sub.add_parser("status", parents=p_parents, help="Inspect the pre-commit hook and the interpreter it runs")

        p_hook_uninstall = p_hook_sub.add_parser(
            "uninstall", parents=p_parents,
            help="Remove the aegis block from the pre-commit hook, or with --host an agent host's PreToolUse hook "
                 "and its insight capture hook",
            description=_uninstall_description(), formatter_class=argparse.RawDescriptionHelpFormatter)
        p_hook_uninstall.add_argument("--force", action="store_true", help="Git hook only: force removal")
        p_hook_uninstall.add_argument("--dry-run", action="store_true", help="Preview without modifying disk")
        _host_options(p_hook_uninstall, "Remove Aegis's PreToolUse and insight capture hook entries from this host "
                      "instead of the git hook",
                      "With --host: only this scope (default: both)")

        p_h_run = p_hook_sub.add_parser(
            "run", parents=p_parents,
            help="Run the agent-host hook on the payload on stdin (what host hook registrations call)",
            description=(
                "Reads the host's PreToolUse JSON on stdin and never prints on stdout. Exit 0 allows, "
                "and also follows any error, a timeout, an unknown host or event and an ungoverned "
                "workspace: the hooks fail open. Exit 2 blocks on claude-code and codex-cli (reason on "
                "stderr); exit 75 blocks on antigravity, whose registration maps it to 1."
            ),
        )
        p_h_run.add_argument("event", nargs="?", default=None, metavar="EVENT", help="The hook event: pre-tool")
        p_h_run.add_argument("--host", default=None, metavar="HOST",
                             help="The host whose payload is on stdin: claude-code, codex-cli or antigravity")

        p_h_safety = p_hook_sub.add_parser("safety-gate", parents=p_parents, help="Check a shell command against the safety gate (prints a JSON decision)")
        p_h_safety.add_argument("--cmd", type=str, default=None, help="Command line to check (default: JSON payload on stdin)")

    def execute(self, args: Any) -> int:
        return run_hook(args)
