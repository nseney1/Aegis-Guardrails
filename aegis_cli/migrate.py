"""aegis migrate: convert a v3 workspace or .soma cells to the v4 layout (dry run by default).

The work is aegis_core.migrate; this module parses flags and prints the plan.
``--apply`` also tightens the repository's shared state (``<git common dir>/aegis``) to
directories 0700 and files 0600, whatever the umask made them; the report's ``state_modes``
counts what was looser, never naming it. Exit codes: 0 done (or nothing to do), 1 refused (nothing written: an unconfined path,
the lock held by another process, files that changed between planning and applying, or
a workspace Aegis would still refuse with nothing to convert, whose blocker is named)
or something was left unmigrated (an unmapped type, a destination conflict, an
unreadable file, a customized driver), 2 usage error.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict

from aegis_cli.base import AegisCommand, CommandCategory

__all__ = ["MigrateCommand", "run_migrate"]


def _print_report(report: Dict[str, Any], applied: bool, backup: Any, tightened: bool) -> None:
    root = report["root"]
    if report["status"] == "refused":
        print(f"aegis migrate: {root}: refused: {report['refusal']}")
        return
    if report["status"] == "up_to_date":
        print(f"aegis migrate: {root} is already on the v4 layout; nothing to do.")
    elif applied:
        print(f"aegis migrate: migrated {root} (backup: {backup})")
    else:
        print(f"aegis migrate: {root} (dry run: nothing written; rerun with --apply)")
    ledger = report["ledger"]
    if ledger:
        print(
            f"  ledger: {ledger['rows']} v2 row(s) from {', '.join(ledger['sources'])} "
            f"({ledger['duplicates']} duplicate, {ledger.get('conflicts', 0)} conflicting, "
            f"{ledger['unusable_rows']} unusable, "
            f"{ledger['skipped_lines']} unreadable line(s))"
        )
    if report["config_sources"]:
        print(f"  config: .aegis/config.json from {', '.join(report['config_sources'])}")
    for move in report["rules"]:
        print(f"  rule: {move['from']} -> {move['to']} (type {move['type']})")
    for strip in report["strip"]:
        print(f"  strip: {', '.join(strip['keys'])} from {strip['path']}")
    for entry in report["retype"]:
        print(f"  type: {entry['from']} -> {entry['to']} in {entry['path']}")
    for path in report["remove"]:
        print(f"  remove (backed up first): {path}")
    for line in report["dropped"]:
        print(f"  dropped: {line}")
    for entry in report["unmapped"]:
        print(f"  ! unmapped type {entry['type']!r}: {entry['path']} left in place (no canonical type; not guessed)")
    for entry in report["conflicts"]:
        print(f"  ! {entry['to']} already exists: {entry['path']} left in place")
    for path in report["unreadable"]:
        removed_with = next((r for r in report["remove"] if path == r or path.startswith(r.rstrip("/") + "/")), None)
        if removed_with is None:
            print(f"  ! cannot read {path}: left in place")
        else:  # its directory goes, so the backup is the only copy left
            where = f"the backup {backup}" if backup else "the backup"
            print(f"  ! cannot read {path}: not converted; removed with {removed_with}, kept only in {where}")
    for entry in report["skipped"]:
        print(f"  ! {entry['path']}: {entry['reason']}")
    for path in report["already_moved"]:
        print(f"  remove (already converted, backed up first): {path}")
    for path in report["left_in_place"]:
        print(f"  note: {path} is not part of the v4 layout; left in place")
    if report.get("not_converted"):
        print("  ! not converted:")
        for entry in report["not_converted"]:
            print(f"    {entry['path']}: {entry['reason']}")
    modes = report.get("state_modes")
    if modes and modes["looser"]:
        if tightened:
            print(f"  state modes: tightened {modes['fixed']} of {modes['looser']} loose entries "
                  f"in the shared state (0700 directories, 0600 files)")
        else:
            print(f"  state modes: {modes['looser']} entries in the shared state are looser than 0700/0600 "
                  "(--apply tightens them)")
    if report["user_config"]:
        print("  For ~/.aegis/config.json (not written: a repository cannot name commands or set slots):")
        print("    " + json.dumps(report["user_config"], indent=2).replace("\n", "\n    "))


def _state_modes(root: Path, tighten: bool) -> Any:
    """The shared state's mode counts (tightened when ``tighten``), or None when unreadable."""
    from aegis_core import storage
    from aegis_core.errors import AegisError

    try:
        return storage.shared_state_modes(root, fix=tighten).as_dict()
    except (AegisError, OSError):
        return None


def run_migrate(args: argparse.Namespace) -> int:
    """CLI handler for aegis migrate."""
    from aegis_core import migrate
    from aegis_core.errors import LockTimeoutError

    root = Path(getattr(args, "workspace", None) or getattr(args, "_project_root", None) or Path.cwd())
    if not root.is_dir():
        print(f"Error: workspace path does not exist: {root}", file=sys.stderr)
        return 2
    plan = migrate.plan(root)
    apply_it = bool(getattr(args, "apply", False))
    report = plan.to_dict()  # before applying: the report describes what was planned
    backup = None
    if apply_it and not plan.refusal:
        try:
            backup = migrate.apply(plan).backup
        except (migrate.MigrationRefused, LockTimeoutError) as exc:  # raised before anything is written
            report["status"], report["refusal"] = "refused", str(exc)
    if apply_it and report["status"] == "pending":
        report["status"] = "applied"
    # An up-to-date workspace has no backup but is still tightened, so this is not "applied".
    tighten = apply_it and report["status"] != "refused"
    report["state_modes"] = _state_modes(root, tighten=tighten)
    report["backup"] = str(backup) if backup else None
    if getattr(args, "json", False):
        print(json.dumps(report, indent=2))
    else:
        _print_report(report, apply_it and backup is not None, backup, tighten)
    if report["status"] == "refused":
        return 1
    left_behind = report["unmapped"] or report["conflicts"] or report["unreadable"] or report["skipped"]
    return 1 if apply_it and left_behind else 0


class MigrateCommand(AegisCommand):
    """Convert a v3 workspace or legacy .soma cells to the v4 layout."""

    name = "migrate"
    aliases = ()
    category = CommandCategory.SETUP
    help = "Convert a v3 or .soma workspace to the v4 layout (dry run unless --apply)"
    description = (
        "Plan, then with --apply perform, the move to the v4 layout: the v3 ledger becomes "
        ".aegis/state/ledger.jsonl (v2 rows), aegis.conf/slots.yaml/config.yaml become "
        ".aegis/config.json, .soma cells move to .aegis/rules/<type>/, derived counters leave "
        "rule frontmatter and v3 runtime state is removed. Every changed file is backed up to "
        ".aegis/state/migrate-backup-<time>/ first; running it again changes nothing."
    )

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--apply", action="store_true", help="Perform the migration (default: dry run)")
        parser.add_argument("--dry-run", action="store_true", help="Only report what would change (the default)")

    def execute(self, args: argparse.Namespace) -> int:
        # Both flags are store_true options of this parser, so they are always set.
        if args.apply and args.dry_run:
            print("Error: --apply and --dry-run are mutually exclusive", file=sys.stderr)
            return 2
        return run_migrate(args)
