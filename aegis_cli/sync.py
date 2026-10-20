"""aegis sync — rebuild derived state from the rules and the ledger, and suggest transitions.

`aegis sync` writes .aegis/state/derived.json (fitness, triggers and a suggested
promote/demote/archive for every rule) and changes no rule file. `aegis sync --apply`
also applies the suggestions; it is the only command that moves rules in bulk
(ADR 0005 D1). Exit codes: 0 done, 1 a rule file cannot be loaded or applying was
refused or failed, 2 usage or workspace error. With --json, stdout carries only the
JSON document.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List

from aegis_cli import sanitize_display
from aegis_cli.base import AegisCommand, CommandCategory
from aegis_core.errors import AegisError
from aegis_core.telemetry_engine.ledger import incomplete as ledger_incomplete

__all__ = ["SyncCommand", "run_sync"]

EXIT_OK = 0
EXIT_PROBLEMS = 1
EXIT_USAGE = 2
_APPLIED_OK = frozenset({"promoted", "demoted", "archived"})
LEDGER_WARNING = (
    "⚠️  The ledger is incomplete ({}): fitness counts only the rows that could be read, "
    "so moves that rely on it (sync --apply, rule archive, tier changes) are refused"
)


def _rows(derived: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [dict(entry, id=rule_id) for rule_id, entry in sorted(derived["rules"].items())]


def _fitness_column(row: Dict[str, Any]) -> str:
    shown = row.get("reported_score")
    return f"{shown:.2f}" if isinstance(shown, (int, float)) else str(row.get("status") or "—")


def _status(result: Any) -> str:
    if result.refused:
        return "refused"
    if result.derived["errors"]:
        return "errors"
    return "applied" if result.applied else "synced"


def _print_text(args: argparse.Namespace, result: Any, rel_path: str) -> None:
    from aegis_cli.ui.table import Table
    from aegis_cli.ui.theme import OutputContext

    existing = getattr(args, "ui", None)
    ui = existing if isinstance(existing, OutputContext) else OutputContext.from_env_and_args(args)
    rows = _rows(result.derived)
    if rows:
        tbl = Table(ctx=ui)
        for column in ("Rule", "Type", "Fitness", "Triggers", "TP", "FP", "Suggestion"):
            tbl.add_column(column, no_wrap=True)
        for row in rows:
            tbl.add_row(
                sanitize_display(str(row["id"])), ui.color_rule_type(str(row["type"])), _fitness_column(row),
                str(row["triggers"]), f"{row['tp']:g}", f"{row['fp']:g}", row["suggestion"] or "—",
            )
        for line in tbl.render(ui).splitlines():
            print(f"  {line}")
    for error in result.derived["errors"]:
        print(f"  ❌ {sanitize_display(error['path'])}: {sanitize_display(error['error'], 300)}")
    for ignored in result.derived["ignored"]:
        print(f"  ⚠️  {sanitize_display(ignored['path'])}: {ignored['reason']}")
    for rule in result.derived["untargeted"]:
        print(f"  ⚠️  {sanitize_display(str(rule['id']))}: applies to no file (no target_paths)")
    missing = ledger_incomplete(result.derived["ledger"])
    if missing:
        print(f"  {LEDGER_WARNING.format(sanitize_display(missing, 300))}")
    for action in result.applied:
        detail = f" ({action['from_type']} -> {action['to_type']})" if action.get("to_type") else ""
        print(f"  {action['action']} {sanitize_display(action['rule'])}: {action['status']}{detail}")
    if result.pr is not None:
        pr_status = result.pr.get("status")
        if pr_status == "opened" and result.pr.get("url"):
            print(f"  Opened PR: {result.pr['url']}")
        elif pr_status == "failed" and result.pr.get("error"):
            print(f"  ❌ PR creation failed: {result.pr['error']}")
        elif pr_status == "no_transitions":
            print("  No decided transitions to open a PR for.")
    if result.refused:
        print(f"  ❌ {result.refused}")
    pending = sum(1 for row in rows if row["suggestion"])
    print(f"Wrote {rel_path} ({len(rows)} rules, {pending} suggested transitions).")
    if pending and not result.applied and not result.refused:
        print("Apply the suggestions with: aegis sync --apply")


def run_sync(args: argparse.Namespace, *, gh_runner: Any = None) -> int:
    from aegis_core.sync import sync
    from aegis_core.workspace.base import Workspace
    from aegis_core.workspace.layout import is_aegis_workspace

    raw_ws = getattr(args, "workspace", None) or getattr(args, "_root", None)
    if raw_ws and not os.path.exists(raw_ws):
        print(f"Error: workspace path does not exist: {raw_ws}", file=sys.stderr)
        return EXIT_USAGE
    try:
        root = Workspace.resolve(raw_ws).root.resolve()
    except AegisError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if not is_aegis_workspace(root):
        print(f"Error: not an Aegis workspace (no .aegis/ in {root}); run aegis init", file=sys.stderr)
        return EXIT_USAGE

    apply_flag = bool(getattr(args, "apply", False))
    pr_flag = bool(getattr(args, "pr", False))
    try:
        result = sync(root, apply=apply_flag, pr=pr_flag, gh_runner=gh_runner)
    except (AegisError, RuntimeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_PROBLEMS

    rel_path = result.path.relative_to(root).as_posix()
    failed = [a for a in result.applied if a["status"] not in _APPLIED_OK]
    pr_failed = bool(result.pr and result.pr.get("status") == "failed")
    rc = EXIT_PROBLEMS if (result.refused or result.derived["errors"] or failed or pr_failed) else EXIT_OK
    from aegis_core.credit import claimed_summary

    # Unwitnessed aegis_report_outcome claims: their own count, never a rule's evidence.
    claimed = claimed_summary(root)
    if getattr(args, "json", False):
        payload: Dict[str, Any] = {
            "status": _status(result),
            "path": rel_path,
            "synced_at": result.derived["synced_at"],
            "rules": _rows(result.derived),
            "applied": result.applied,
            "refused": result.refused,
            "errors": result.derived["errors"],
            "ignored": result.derived["ignored"],
            "untargeted": result.derived["untargeted"],
            "ledger": result.derived["ledger"],
            "claimed": claimed,
        }
        if result.pr is not None:
            payload["pr"] = result.pr
        print(json.dumps(payload, indent=2, default=str))
    else:
        _print_text(args, result, rel_path)
        if claimed["claimed"]:
            print(f"  {claimed['label']}: {claimed['claimed']} report(s) from {claimed['sessions']} session(s), "
                  "no rule's evidence")
    return rc


class SyncCommand(AegisCommand):
    """Rebuild derived rule state and suggest lifecycle transitions."""

    name = "sync"
    category = CommandCategory.LIFECYCLE
    help = "Rebuild rule fitness from the ledger and suggest promotions (--apply to apply them)"

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--apply", action="store_true",
            help="Apply the suggested promote/demote/archive transitions (moves rule files)",
        )
        parser.add_argument(
            "--pr", action="store_true",
            help="Apply decided transitions and open a pull request with the evidence report (never auto-merges)",
        )

    def execute(self, args: argparse.Namespace) -> int:
        return run_sync(args)
