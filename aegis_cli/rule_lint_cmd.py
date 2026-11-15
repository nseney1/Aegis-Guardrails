"""Report-only rule lint parser and display; never install or amend rules."""
from __future__ import annotations

from dataclasses import asdict
import json

from aegis_core.errors import WorkspaceNotFoundError
from aegis_core.rule_lint import LintFinding, LintResult, lint_workspace
from aegis_core.skills.slots import SlotRegistry, SlotResolutionError


def add_lint_parser(parser, common):
    """Create the rule action tree and its report-only lint leaf."""
    sub = parser.add_subparsers(dest="rule_action", metavar="ACTION")
    lint = sub.add_parser("lint", parents=[common], help="Report rule lint findings without changing rules")
    lint.add_argument("paths", nargs="*", default=[], metavar="PATH",
                      help="Rule files or directories below .aegis/rules (default: all rules)")
    return sub


def run_lint(args, resolve_root):
    """Every finding/refusal is reported with exit zero, including workspace errors."""
    warning = None
    try:
        root = resolve_root(args)
    except (WorkspaceNotFoundError, OSError, ValueError, RuntimeError):
        return workspace_refusal(args)
    else:
        try:
            commands = SlotRegistry.load_user(root).to_dict()
        except (SlotResolutionError, OSError, ValueError, RuntimeError):
            commands = {}
            warning = "user command mappings unavailable; built-in mappings used"
        results = lint_workspace(root, getattr(args, "paths", ()), command_slots=commands)
    return _report(args, results, warning)


def workspace_refusal(args):
    """One fixed report for handler and dispatcher workspace refusals."""
    results = (LintResult("", (LintFinding(0, "workspace", "error", "lint workspace unavailable"),)),)
    return _report(args, results)


def _report(args, results, warning=None):
    payload = {"report_only": True, "results": [{**asdict(result), "ok": result.ok} for result in results]}
    if warning:
        payload["warnings"] = [warning]
    if getattr(args, "json", False):
        print(json.dumps(payload, ensure_ascii=True, indent=2))
    else:
        for result in results:
            print(result.path or "<lint>")
            for finding in result.findings:
                suggestion = " (use " + ", ".join(finding.suggestions) + ")" if finding.suggestions else ""
                print(f"  {finding.severity} {finding.code}: {finding.message}{suggestion}")
        if not results:
            print("No rules found.")
        if warning:
            print("Warning: " + warning)
    return 0
