#!/usr/bin/env python3
"""aegis — governance commands for AI coding agents.

Dispatch goes through the command registry only. Commands and aliases cut in
v4 (ADR 0005 D5, H1 hard cut) are not parsed at all: each removed name exits 2
with one line on stderr naming its replacement.
"""
from __future__ import annotations

import argparse
from functools import partial
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


def _positionals(argv: List[str], parser: argparse.ArgumentParser) -> List[str]:
    """Skip root option values using the same option table as argparse."""
    out: List[str] = []
    skip = False
    for token in argv:
        if skip:
            skip = False
        elif token == "--":
            break
        elif token.startswith("-"):
            equals = token.find("=")
            option = token if equals < 0 else token[:equals]
            action = parser._option_string_actions.get(option)
            if action is None and parser.allow_abbrev and option.startswith("--"):
                matches = [value for flag, value in parser._option_string_actions.items()
                           if flag.startswith(option)]
                if len(matches) == 1:
                    action = matches[0]
            skip = action is not None and action.nargs != 0 and equals < 0
        else:
            out.append(token)
    return out


def removed_command_pointer(argv: List[str], *, parser=None) -> Optional[str]:
    """The one-line pointer for a removed command in argv, or None.

    A name the registry still resolves is not removed: a command whose alias
    is cut in another module keeps working until that module drops it.
    """
    words = _positionals(argv, parser if parser is not None else _build_parser())
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

    def __init__(self, *args, error_policy=None, scan_state=None, **kwargs):
        self._error_policy = error_policy
        self._scan_state = ({"entered": False, "invocation": False, "depth": 0}
                            if scan_state is None else scan_state)
        super().__init__(*args, **kwargs)

    def add_subparsers(self, **kwargs):
        factory = kwargs.get("parser_class", type(self))
        kwargs["parser_class"] = partial(factory, error_policy=self._error_policy, scan_state=self._scan_state)
        return super().add_subparsers(**kwargs)

    def _print_message(self, message, file=None):
        # Raw model invocations publish their own result, including for help and version.
        if not getattr(self._error_policy, "model_invocation", False):
            super()._print_message(message, file)

    def refuse_scoped_usage(self):
        if getattr(self._error_policy, "guards_usage", False):
            self._error_policy()

    def error(self, message: str) -> None:
        if self._error_policy is not None:
            self._error_policy()
        if self._scan_state["entered"] or self._scan_state["invocation"]:
            from aegis_core.guidance_projection import project_diagnostic

            message = project_diagnostic(message)
        super().error(message)

    def parse_known_args(self, args=None, namespace=None):
        if self._scan_state["depth"] == 0:
            self._scan_state["entered"] = False
            self._scan_state["invocation"] = False
            if getattr(self, "_scan_root", False):
                args = list(sys.argv[1:] if args is None else args)
                # Classify early root failures (including --version=value) using
                # the same option-value rules as the invocation's removed pointer.
                self._scan_state["invocation"] = _positionals(args, self)[:1] == ["scan"]
        self._scan_state["depth"] += 1
        if getattr(self, "_is_scan", False):
            self._scan_state["entered"] = True
        try:
            select = getattr(self._error_policy, "select_parser", None)
            if select is not None:
                select(getattr(self, "_model_errors", False))
            return super().parse_known_args(args=args, namespace=namespace)
        finally:
            self._scan_state["depth"] -= 1

    def parse_args(self, args=None, namespace=None):
        self._scan_state["entered"] = False
        self._scan_state["invocation"] = False
        parse = super().parse_args
        guard = getattr(self._error_policy, "parse_cli_args", None)
        ns = parse(args=args, namespace=namespace) if guard is None else guard(parse, args, namespace)
        if not hasattr(ns, "json"):
            ns.json = False
        # `check` and `msg read` have --format; its json value must reach code (and the
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


def _build_parser(prog: str = PROG, *, error_policy=None) -> argparse.ArgumentParser:
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
        error_policy=error_policy,
        description="Aegis Governance — make AI coding agents trustworthy",
        parents=[common_parser],
    )
    parser.add_argument("--version", action="version", version=f"{prog} {__version__}")

    sub = parser.add_subparsers(dest="command", parser_class=AegisParser)
    parsers = get_default_registry().populate_subparsers(sub, common_parser=common_parser)
    if "scan" in parsers:
        parser._scan_root = True
        parsers["scan"]._is_scan = True
    return parser


def _resolve_cli_binding(explicit, pin, accept=is_aegis_workspace):
    """Keep discovery provenance separate from resolve_cli_root's fallback path."""
    from aegis_core.workspace.binding import resolve_cli_root

    discovered = None

    def record(candidate):
        nonlocal discovered
        accepted = accept(candidate)
        if accepted:
            discovered = candidate
        return accepted

    root = resolve_cli_root(explicit, Path.cwd(), pin, accept=record)
    # A returned pin passed the resolver's pin checks; a walk must have accepted it.
    return root, root if pin or root == discovered else None


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
    from aegis_core.workspace.binding import check_pin_agrees
    from aegis_core.workspace.discovery import refuse_unmigrated_v3, unconverted_rule_files

    args._ordinary_binding_root = None
    raw_ws = getattr(args, "workspace", None)
    args._workspace_arg = raw_ws
    pin = env_workspace()
    args._workspace_pin = pin
    if args.command == "scan":
        from aegis_core.guidance_projection import MAX_GUIDANCE_CHARS, GuidanceProjectionError

        if any(value is not None and len(value) > MAX_GUIDANCE_CHARS for value in (raw_ws, pin)):
            args._workspace_error_display = GuidanceProjectionError.code
            raise WorkspaceNotFoundError(GuidanceProjectionError.code)
        args._workspace_cwd = str(Path.cwd())
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
        root, args._ordinary_binding_root = _resolve_cli_binding(raw_ws, pin, accept=_migratable)
        args.ws = None
        args._project_root = root
        args.workspace = str(root)
        return
    else:
        try:
            if args.command in _LEGACY_TOLERANT_COMMANDS:
                root, args._ordinary_binding_root = _resolve_cli_binding(raw_ws, pin)
            else:
                root, args._ordinary_binding_root = _resolve_cli_binding(raw_ws, pin, accept=_refuse_legacy)
                refuse_unmigrated_v3(root)  # a pin is not walked
                _check_upgrade_state(args.command, root, args=args)
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


def _check_upgrade_state(command: str, root: Path, *, args=None) -> None:
    """Unmigrated v3 state (a v3 ledger, aegis.conf, keys...) that v4 never reads: the
    commands that would report or derive from an empty ledger refuse, check warns."""
    from aegis_core.errors import WorkspaceError
    from aegis_core.workspace.discovery import UPGRADE_STATE_MSG, unmigrated_state

    if command not in _UPGRADE_REFUSED and command not in _UPGRADE_WARNED:
        return
    found = unmigrated_state(root)
    if not found:
        return
    shown = root
    if command == "scan":
        from aegis_core.guidance_projection import GuidanceProjectionError, project_diagnostic, project_error_name

        try:
            shown = project_diagnostic(project_error_name(str(root)), escaped=False)
        except GuidanceProjectionError as error:
            shown = error.code
    message = UPGRADE_STATE_MSG.format(path=shown, found=", ".join(found))
    if command in _UPGRADE_REFUSED:
        if command == "scan" and args is not None:
            args._workspace_error_display = project_diagnostic(message, escaped=False)
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
    from aegis_core.workspace.diagnostics import project_binding

    supplied = getattr(args, "_workspace_arg", getattr(args, "workspace", None))
    binding = project_binding(exc.binding, workspace=supplied, cli=True)  # type: ignore[attr-defined]
    if getattr(args, "json", False):
        print(json.dumps({
            **binding,
            **primitives.envelope(f"{PROG} {args.command}", {"command": args.command, "workspace": None}),
        }, indent=2))
    else:
        print(f"Hold ({binding['reason']}): {binding['message']}", file=sys.stderr)


# Command path -> (policy module, policy class, stop scanning at --).
# These are deliberately raw-token scopes, including option values. Successful
# parsing alone can establish an exemption from the conservative privacy policy.
_POLICY_REGISTRY = {
    ("msg",): ("aegis_cli.msg", "MsgErrorPolicy", False),
    ("team", "model"): ("aegis_cli.team", "ModelErrorPolicy", True),
    ("team", "queue"): ("aegis_cli.team_queue", "QueueErrorPolicy", False),
    ("team", "mail"): ("aegis_cli.team_mail", "MailBoardErrorPolicy", False),
    ("team", "board"): ("aegis_cli.team_mail", "MailBoardErrorPolicy", False),
}


class _DefaultErrorPolicy:
    """Ordinary argparse behavior without importing a command-specific policy."""

    def __call__(self):
        pass

    def run(self, operation):
        return operation()

    def parse(self, parser, argv):
        return parser.parse_args(argv)

    def removed_pointer(self, argv, lookup):
        return lookup(argv)

    def workspace_error(self, args, error):
        from aegis_core.errors import WorkspaceError
        from aegis_core.workspace.binding import WorkspaceHold

        if args.command != "scan" or isinstance(error, WorkspaceHold):
            return None
        from aegis_core.guidance_projection import (
            MAX_GUIDANCE_CHARS, GuidanceProjectionError, project_diagnostic,
        )
        from aegis_core.workspace.binding import WorkspaceBinding
        from aegis_core.workspace.diagnostics import project_binding

        prepared = getattr(args, "_workspace_error_display", None)
        binding = getattr(error, "binding", None)
        if prepared is not None:
            message = project_diagnostic(prepared, escaped=False)
        elif binding is not None:
            message = project_binding(binding, workspace=getattr(args, "_workspace_pin", None), cli=True)["message"]
        elif isinstance(error, OSError):
            pin = getattr(args, "_workspace_pin", None)
            target = getattr(args, "_workspace_arg", None) or getattr(args, "_workspace_cwd", None)
            kind = "pin_resolution" if pin else "target_resolution" if target else None
            binding = WorkspaceBinding("error", reason="no_workspace", kind=kind,
                                       details=(("pin", pin),) if pin else (("target", target),) if target else ())
            message = project_binding(binding, cli=True)["message"]
        elif isinstance(error, WorkspaceError):
            # Unclassified exceptions never acquire authority from their wording.
            message = GuidanceProjectionError.code if len(str(error)) > MAX_GUIDANCE_CHARS else "workspace binding refused"
        else:
            return None
        print("Error: " + message, file=sys.stderr)
        return _WORKSPACE_ERROR_EXIT["scan"]


def _invocation_policy(argv):
    """Select each scope once and compose fresh policies for this invocation."""
    from importlib import import_module

    argv = list(argv)
    scopes = {}
    factories = {}
    for path, (module, name, stop_at_separator) in _POLICY_REGISTRY.items():
        matched = 0
        for token in argv:
            if stop_at_separator and token == "--":
                break
            if token == path[matched]:
                matched += 1
                if matched == len(path):
                    break
        scopes[path] = matched == len(path)
        if scopes[path]:
            factories[path] = getattr(import_module(module), name)
    policy = factories[("msg",)](active=True) if scopes[("msg",)] else _DefaultErrorPolicy()
    model = (factories[("team", "model")](model_invocation=True)
             if scopes[("team", "model")] else None)
    if scopes[("team", "queue")]:
        options = ({"output": model.queue_output, "parser_error": model.parser_error}
                   if model is not None else {})
        policy = factories[("team", "queue")](policy, active=True, **options)
    if model is not None:
        model.fallback = policy
        policy = model
    mail_board = factories.get(("team", "mail")) or factories.get(("team", "board"))
    if mail_board is not None:
        from aegis_cli.team import ModelArgumentError
        from aegis_cli.team_queue import QueueArgumentError

        policy = mail_board(policy, (ModelArgumentError, QueueArgumentError))
    return policy


def _ordinary_bound_root(args: argparse.Namespace):
    """Only explicit successful resolution can mark an ordinary invocation."""
    return getattr(args, "_ordinary_binding_root", None)


def main(argv: Optional[List[str]] = None, prog: str = PROG) -> int:
    from aegis_core.pathlookup import ordinary_root

    argv = list(sys.argv[1:] if argv is None else argv)
    policy = _invocation_policy(argv)
    # A nested invocation must discover its own binding without the caller's fence.
    token = ordinary_root.set(None)
    try:
        return policy.run(partial(_main, argv, prog, policy))
    finally:
        ordinary_root.reset(token)


def _main(argv: List[str], prog: str, policy=None) -> int:
    # Output uses emoji. On a cp1252 stdout (Windows, redirected) printing
    # one raised UnicodeEncodeError and the command exited 1 (BUG-012).
    # stderr already defaults to errors="backslashreplace".
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    argv = list(argv)
    if policy is None:
        policy = _invocation_policy(argv)
    hook_run = argv[:2] == ["hook", "run"] and not {"-h", "--help"} & set(argv[2:])
    if hook_run:
        from aegis_cli.hooks.pretool import run_hook_argv

        # Host hooks resolve their workspace from the payload and ordinarily fail open.
        if not getattr(policy, "guards_usage", False):
            return run_hook_argv(argv[2:])

    parser = _build_parser(prog=prog, error_policy=policy)
    pointer = policy.removed_pointer(argv, partial(removed_command_pointer, parser=parser))
    if pointer is not None:
        print(pointer, file=sys.stderr)
        return 2

    args = policy.parse(parser, argv)
    if isinstance(args, int):
        return args
    if hook_run:
        return run_hook_argv(argv[2:])
    args.prog = prog
    if args.command is None:
        parser.print_help()
        return 0

    command = get_default_registry().get(args.command)
    from aegis_core import pathlookup
    from aegis_core.errors import WorkspaceError
    from aegis_core.workspace.binding import WorkspaceHold

    ordinary_token = None
    try:
        try:
            if args.command != "workspace":
                _attach_workspace(args)
        except (WorkspaceError, OSError) as exc:
            workspace_refusal = getattr(command, "workspace_refusal", None)
            if workspace_refusal is not None:
                refusal = workspace_refusal(args, exc)
                if refusal is not None:
                    return refusal
            refusal = policy.workspace_error(args, exc)
            if refusal is not None:
                return refusal
            if args.command == "scan":
                refusal = _DefaultErrorPolicy().workspace_error(args, exc)
                if refusal is not None:
                    return refusal
            if not isinstance(exc, WorkspaceError):
                raise
            if isinstance(exc, WorkspaceHold):
                _print_hold(args, exc)
            else:
                print(f"Error: {exc}", file=sys.stderr)
            return _WORKSPACE_ERROR_EXIT.get(args.command, 1)
        bound_root = _ordinary_bound_root(args)
        if bound_root is not None:
            ordinary_token = pathlookup.ordinary_root.set(os.path.normcase(os.fspath(bound_root)))
        return command.execute(args)
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        if getattr(policy, "model_invocation", False):
            return policy.operation_error()
        if args.command == "scan":
            from aegis_core.guidance_projection import project_diagnostic

            message = project_diagnostic(str(e))
        else:
            message = str(e)
        print(f"Error: {message}", file=sys.stderr)
        return 1
    finally:
        if ordinary_token is not None:
            pathlookup.ordinary_root.reset(ordinary_token)


if __name__ == "__main__":
    sys.exit(main())
