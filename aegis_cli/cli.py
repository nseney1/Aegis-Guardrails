#!/usr/bin/env python3
"""aegis — governance commands for AI coding agents.

Dispatch goes through the command registry only. Commands and aliases cut in
v4 (ADR 0005 D5, H1 hard cut) are not parsed at all: each removed name exits 2
with one line on stderr naming its replacement.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

from aegis_core import primitives
from aegis_cli.commands_table import REMOVED_COMMANDS
from aegis_cli.registry import get_default_registry
from aegis_core._version import __version__
from aegis_core.workspace.layout import LEGACY_SOMA_DIRNAME, is_aegis_workspace

__all__ = ["main", "AegisParser", "REMOVED_COMMANDS"]

PROG = "aegis"

# Global options that take a value, so the removed-name scan can skip it.
_VALUE_OPTIONS = ("--workspace",)


def _positionals(argv: List[str]) -> List[str]:
    out: List[str] = []
    skip = False
    for token in argv:
        if skip:
            skip = False
        elif token == "--":
            break
        elif token in _VALUE_OPTIONS:
            skip = True
        elif not token.startswith("-"):
            out.append(token)
    return out


def removed_command_pointer(argv: List[str]) -> Optional[str]:
    """The one-line pointer for a removed command in argv, or None.

    A name the registry still resolves is not removed: a command whose alias
    is cut in another module keeps working until that module drops it.
    """
    words = _positionals(argv)
    if not words:
        return None
    pair = " ".join(words[:2])
    if len(words) > 1 and pair in REMOVED_COMMANDS:
        name = pair
    elif words[0] in REMOVED_COMMANDS and get_default_registry().get(words[0]) is None:
        name = words[0]
    else:
        return None
    return f"{PROG} {name} was removed in v4: {REMOVED_COMMANDS[name]}"


class AegisParser(argparse.ArgumentParser):
    """ArgumentParser with the categorized top-level help and an attached OutputContext."""

    def format_help(self) -> str:
        if self.prog == PROG:
            return get_default_registry().format_categorized_help(prog=self.prog) + "\n"
        return super().format_help()

    def parse_args(self, args=None, namespace=None):
        ns = super().parse_args(args=args, namespace=namespace)
        if not hasattr(ns, "json"):
            ns.json = False
        # Only `check` keeps --format; its json value must reach code (and the
        # OutputContext below) that reads args.json alone.
        if getattr(ns, "format", None) == "json":
            ns.json = True
        if not hasattr(ns, "plain"):
            ns.plain = False
        if not hasattr(ns, "workspace"):
            ns.workspace = None
        from aegis_cli.ui.theme import OutputContext
        ns.ui = OutputContext.from_env_and_args(ns)
        return ns


def _build_parser(prog: str = PROG) -> argparse.ArgumentParser:
    common_parser = argparse.ArgumentParser(add_help=False)
    # SUPPRESS, not False: a subparser writes its defaults over the namespace
    # the top-level parser filled, so a False default here drops a `--json`
    # given before the command. parse_args sets the False fallback once.
    common_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                               help="Emit machine-readable JSON output")
    common_parser.add_argument("--plain", action="store_true", default=argparse.SUPPRESS,
                               help="Strip ANSI styling and emoji")
    common_parser.add_argument("--workspace", type=str, default=argparse.SUPPRESS,
                               help="Target workspace root")

    parser = AegisParser(
        prog=prog,
        description="Aegis Governance — make AI coding agents trustworthy",
        parents=[common_parser],
    )
    parser.add_argument("--version", action="version", version=f"{prog} {__version__}")

    sub = parser.add_subparsers(dest="command", parser_class=AegisParser)
    get_default_registry().populate_subparsers(sub, common_parser=common_parser)
    return parser


def _attach_workspace(args: argparse.Namespace) -> None:
    """Resolve the workspace the command acts on (``args.ws``, ``args._project_root``).

    The raw ``--workspace`` value stays on ``args._workspace_arg`` (``args.workspace``
    is replaced by the resolved root). Every command resolves through
    ``resolve_cli_root``: never above the target's git toplevel, never ``$HOME``, and a
    WorkspaceHold when an ``AEGIS_WORKSPACE`` pin disagrees with ``--workspace`` or,
    without it, with the cwd's workspace or repository.
    ``aegis init`` keeps its target as given but takes the same hold. An unmigrated
    ``.soma/`` on the walk (or at the pin) raises the upgrade message, except for the
    ``_LEGACY_TOLERANT_COMMANDS``; ``aegis migrate`` stops at it to convert it, and
    ``aegis init`` refuses while ``.soma/`` still holds rule files. Unmigrated v3 state
    makes status, scan and sync refuse and check warn (``_check_upgrade_state``).
    """
    from aegis_core.config import env_workspace
    from aegis_core.errors import WorkspaceNotFoundError
    from aegis_core.workspace.base import Workspace
    from aegis_core.workspace.binding import check_pin_agrees, resolve_cli_root
    from aegis_core.workspace.discovery import refuse_unmigrated_v3, unconverted_rule_files

    raw_ws = getattr(args, "workspace", None)
    args._workspace_arg = raw_ws
    pin = env_workspace()
    if args.command == "scan" and raw_ws and not os.path.exists(raw_ws):
        # scan names the missing path itself (exit 2); resolving it would name a parent.
        args.ws = None
        return
    if args.command == "init":
        if raw_ws and pin:
            check_pin_agrees(raw_ws, pin, Path.cwd())
        target = Path(os.path.expanduser(raw_ws)) if raw_ws else Path.cwd()
        if unconverted_rule_files(target):
            # .aegis/ beside them would leave their gates unserved: migrate converts them.
            refuse_unmigrated_v3(target)
        args._allow_home_fallback = True
        args.ws = Workspace.for_init(raw_ws or Path.cwd())
    elif args.command == "migrate":
        # A legacy .soma/ is a workspace to migrate too.
        root = resolve_cli_root(raw_ws, Path.cwd(), pin, accept=_migratable)
        args.ws = None
        args._project_root = root
        args.workspace = str(root)
        return
    else:
        try:
            if args.command in _LEGACY_TOLERANT_COMMANDS:
                root = resolve_cli_root(raw_ws, Path.cwd(), pin)
            else:
                root = resolve_cli_root(raw_ws, Path.cwd(), pin, accept=_refuse_legacy)
                refuse_unmigrated_v3(root)  # a pin is not walked
                _check_upgrade_state(args.command, root)
            args.ws = Workspace(root=root)
        except WorkspaceNotFoundError:
            if args.command not in _HOST_LEVEL_COMMANDS:
                raise
            # Host-level checks still run from $HOME; the command decides what a
            # workspace means there.
            args.ws = None
            start = Path(os.path.abspath(os.path.expanduser(raw_ws))) if raw_ws else Path.cwd().resolve()
            try:
                start = start.resolve()
            except (RuntimeError, ValueError):  # a symlink loop before 3.13; doctor reports the path
                pass
            args._project_root = start
            args.workspace = str(start)
            return
    args._project_root = args.ws.root
    args.workspace = str(args.ws.root)


def _check_upgrade_state(command: str, root: Path) -> None:
    """Unmigrated v3 state (a v3 ledger, aegis.conf, keys...) that v4 never reads: the
    commands that would report or derive from an empty ledger refuse, check warns."""
    from aegis_core.errors import WorkspaceError
    from aegis_core.workspace.discovery import UPGRADE_STATE_MSG, unmigrated_state

    if command not in _UPGRADE_REFUSED and command not in _UPGRADE_WARNED:
        return
    found = unmigrated_state(root)
    if not found:
        return
    message = UPGRADE_STATE_MSG.format(path=root, found=", ".join(found))
    if command in _UPGRADE_REFUSED:
        raise WorkspaceError(message)
    print(f"Warning: {message}", file=sys.stderr)


def _migratable(directory: Path) -> bool:
    return is_aegis_workspace(directory) or (directory / LEGACY_SOMA_DIRNAME).is_dir()


def _refuse_legacy(directory: Path) -> bool:
    """The walk stops at a workspace and raises the upgrade message at an unmigrated
    ``.soma/``, so a v3 repository is refused instead of read as an empty workspace
    (where ``aegis check --hook`` would pass vacuously)."""
    from aegis_core.workspace.discovery import refuse_unmigrated_v3

    if is_aegis_workspace(directory):
        return True
    refuse_unmigrated_v3(directory)
    return False


# Commands that inspect the machine (hosts, registrations) as well as a workspace.
_HOST_LEVEL_COMMANDS = frozenset({"doctor"})

# With unmigrated v3 state these refuse (sync must not derive from an empty ledger while
# a v3 one is pending) or, the gate, warn and still run.
_UPGRADE_REFUSED = frozenset({"status", "scan", "sync"})
_UPGRADE_WARNED = frozenset({"check"})

# Commands that must still work in an unmigrated v3 repository (migrate has its own
# branch): doctor diagnoses it, uninstall removes what an older version installed.
_LEGACY_TOLERANT_COMMANDS = frozenset({"doctor", "uninstall"})

# scan's exit codes are a contract (aegis_cli/scan.py): a workspace error, a hold
# included, is 2 there; every other command exits 1.
_WORKSPACE_ERROR_EXIT: Dict[str, int] = {"scan": 2}


def _print_hold(args: argparse.Namespace, exc: Exception) -> None:
    """A workspace hold: machine-readable with --json, one stderr line otherwise."""
    import json

    binding = exc.binding.as_dict()  # type: ignore[attr-defined]
    if getattr(args, "json", False):
        print(json.dumps({
            **binding,
            **primitives.envelope(f"{PROG} {args.command}", {"command": args.command, "workspace": None}),
        }, indent=2))
    else:
        print(f"Hold ({binding['reason']}): {binding['message']}", file=sys.stderr)


def main(argv: Optional[List[str]] = None, prog: str = PROG) -> int:
    # Output uses emoji. On a cp1252 stdout (Windows, redirected) printing
    # one raised UnicodeEncodeError and the command exited 1 (BUG-012).
    # stderr already defaults to errors="backslashreplace".
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:2] == ["hook", "run"] and not {"-h", "--help"} & set(argv[2:]):
        # What the agent-host hook registrations run, from any cwd ($HOME, a v3 .soma/
        # directory): the handler resolves its workspace from the payload and fails open,
        # so it must reach neither _attach_workspace (exit 1) nor a usage error (exit 2,
        # which Claude Code and Codex read as a block).
        from aegis_cli.hooks.pretool import run_hook_argv

        return run_hook_argv(argv[2:])

    pointer = removed_command_pointer(argv)
    if pointer is not None:
        print(pointer, file=sys.stderr)
        return 2

    parser = _build_parser(prog=prog)
    args = parser.parse_args(argv)
    args.prog = prog
    if args.command is None:
        parser.print_help()
        return 0

    command = get_default_registry().get(args.command)
    from aegis_core.errors import WorkspaceError
    from aegis_core.workspace.binding import WorkspaceHold

    try:
        try:
            _attach_workspace(args)
        except WorkspaceError as exc:
            if isinstance(exc, WorkspaceHold):
                _print_hold(args, exc)
            else:
                print(f"Error: {exc}", file=sys.stderr)
            return _WORKSPACE_ERROR_EXIT.get(args.command, 1)
        return command.execute(args)
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
