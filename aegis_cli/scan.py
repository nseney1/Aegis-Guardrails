"""aegis scan — which governance rules apply to these files.

The CLI twin of the MCP tool aegis_scan, and the command the AGENTS.md
bootstrap tells agents to run before editing (`aegis scan FILE`). A scan that ran
records one ``scan`` activity row with host ``cli`` naming the files inside the
workspace, so it satisfies the scan-before-edit hook as aegis_scan does. Exit codes
are a contract: 0 when the scan ran (matches or not), 1 when the rules cannot all
be served (a rule file cannot be loaded or the rules tree cannot be read safely: the
scan fails closed and names them), 2 for a usage or workspace error. With --json,
stdout carries only the JSON document.

${SLOT.*} placeholders in rule text are rendered as aegis_scan renders them, by the one
renderer in aegis_core.skills.slots. The CLI has no host, so it uses the generic
profile (with the user's ~/.aegis/config.json overrides); warnings go to stderr in
text mode. Text from rule files, and the errors naming them, reach the terminal without
control sequences.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List
import uuid

from aegis_cli import sanitize_display
from aegis_cli.base import AegisCommand, CommandCategory
from aegis_core.errors import WorkspaceError
from aegis_core.hosts import GENERIC
from aegis_core.workspace.layout import is_aegis_workspace

__all__ = ["ScanCommand", "run_scan"]

EXIT_SCANNED = 0
EXIT_UNSERVED = 1
EXIT_USAGE = 2


def _workspace_relative(raw: str, root: Path) -> str:
    """Rule target_paths are relative to the workspace root; the operator types paths relative to cwd."""
    path = Path(raw)
    absolute = path if path.is_absolute() else Path.cwd() / path
    try:
        return Path(os.path.normpath(absolute)).relative_to(root).as_posix()
    except ValueError:
        return raw


def run_scan(args: argparse.Namespace) -> int:
    from aegis_core.workspace.base import Workspace

    raw_ws = getattr(args, "workspace", None)
    # Discovery walks up from a missing path, so its error would name a parent.
    if raw_ws and not os.path.exists(raw_ws):
        _error(f"workspace path does not exist: {raw_ws}")
        return EXIT_USAGE
    try:
        root = Workspace.resolve(raw_ws).root.resolve()
    except WorkspaceError as exc:
        _error(str(exc))
        return EXIT_USAGE
    if not is_aegis_workspace(root):
        _error(f"not an Aegis workspace (no .aegis/ in {root}); run aegis init")
        return EXIT_USAGE

    from aegis_core.scan import scan

    from aegis_core.skills.slots import render_scan_result

    files = [_workspace_relative(f, root) for f in args.files]
    result = scan(str(root), changed_files=files)
    failed = result.get("status") == "FAIL"
    if not failed:
        result = render_scan_result(result, GENERIC, root)
        _record_scan(root, args.files)
    if args.json:  # AegisParser.parse_args always sets it
        print(json.dumps(result, indent=2, default=str))
    elif failed:
        _error(str(result.get("error")))
    else:
        print(_terminal_text(result.get("guidance", "")))
        for warning in result.get("warnings") or []:
            print(f"Warning: {sanitize_display(str(warning), max_len=1024)}", file=sys.stderr)
    return EXIT_UNSERVED if failed else EXIT_SCANNED


def _record_scan(root: Path, raw_files: List[str]) -> None:
    """One ``scan`` row (host ``cli``, a session per run) naming the files that lie inside
    the workspace, resolved as aegis_scan resolves them (``confine_path``: symlinks
    followed, workspace-relative). Telemetry never fails the scan: a failed append is a
    warning on stderr."""
    from aegis_core import scan_compliance
    from aegis_core.workspace.confinement import confine_path_internal

    inside = []
    for raw in raw_files:
        try:
            inside.append(confine_path_internal(root, os.path.join(os.getcwd(), raw))[1])
        except ValueError:  # PathTraversalError: outside the workspace or unresolvable
            continue
    if not inside:
        return
    try:
        scan_compliance.record(root, "scan", host=scan_compliance.CLI_HOST, session=uuid.uuid4().hex,
                               files=inside, basis="files")
    except Exception as exc:  # telemetry only: never fail the scan
        print("Warning: scan event not recorded: " + _terminal_text(str(exc)), file=sys.stderr)


def _error(message: str) -> None:
    # Errors name rule files and directories, which a cloned repository chooses.
    print("Error: " + _terminal_text(message), file=sys.stderr)


def _terminal_text(text: str) -> str:
    """``text`` line by line without escape or control sequences: rule files are
    repository content, and a terminal would act on them."""
    return "\n".join(sanitize_display(line, max_len=None) for line in str(text).split("\n"))


class ScanCommand(AegisCommand):
    """Show the governance rules that apply to the given files."""

    name = "scan"
    category = CommandCategory.WORKFLOW
    help = "Show which rules apply to the given files (run before editing them)"

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("files", nargs="+", metavar="FILE", help="File(s) you are about to edit")

    def execute(self, args: argparse.Namespace) -> int:
        return run_scan(args)
