"""Terminal output and JSON reporting views for ``aegis init`` and ``aegis uninstall``."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone  # noqa: F401 - names the 4.3.3 public-names pin holds
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Sequence

from aegis_core import primitives
from aegis_cli.hooks.management import hook_status, work_tree_warning
from aegis_cli.install_hosts import display_command
from aegis_core.scaffolding import (
    ACTIVE_LABEL as _ACTIVE_LABEL,
    ACTIVE_STARTERS,
    CI_WORKFLOW_LABEL,
    ci_workflow,
)
from aegis_core.workspace.layout import AEGIS_DIRNAME, RULES_RELDIR

__all__ = ["Report", "Step", "report_partial"]

SCAFFOLD_LABEL = f"{AEGIS_DIRNAME}/"
_ICONS = {"failed": "❌", "manual": "👉", "kept": "⚠️ ", "skipped": "⚠️ "}
# Results that changed nothing on disk (what a failed run reports as already written).
_NO_CHANGE = {
    "unchanged", "absent", "none", "kept", "skipped", "linked", "would_run", "manual", "failed",
    "dry-run", "skipped (not a git repository)", "present", "suggested",
}
_NEXT_RULE = "    Next: add a rule for your own code with aegis rule create (aegis rule create --help)"


@dataclass
class Step:
    """One init or uninstall step and what it did (or would do, in a dry run)."""

    target: str
    result: str
    detail: str = ""
    command: Optional[List[str]] = None
    names: Sequence[str] = ()
    kept: Sequence[str] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {"target": self.target, "result": self.result, "detail": self.detail, "command": self.command}


class Report:
    """Human lines on stdout, or one JSON document at the end with --json."""

    def __init__(self, json_mode: bool, source: str) -> None:
        self.json_mode = json_mode
        self.source = source
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.muted = False  # the check pass before a real run stays quiet; the run reports

    def say(self, line: str = "") -> None:
        if not self.json_mode:
            print(line)

    def warn(self, line: str) -> None:
        if self.muted:
            return
        self.warnings.append(line)
        if not self.json_mode:
            sys.stdout.flush()  # keep the order of stdout and stderr lines in a pipe
            print(f"  ⚠️  {line}", file=sys.stderr)

    def error(self, line: str) -> None:
        self.errors.append(line)
        if not self.json_mode:
            sys.stdout.flush()  # keep the order of stdout and stderr lines in a pipe
            print(f"  ❌ {line}", file=sys.stderr)

    def finish(self, status: str, scope: Dict[str, Any], dry_run: bool, actions: Sequence[Step]) -> None:
        if not self.json_mode:
            return

        print(json.dumps({
            **primitives.envelope(self.source, scope),
            "dry_run": dry_run,
            "status": status,
            "actions": [a.as_dict() for a in actions],
            "errors": self.errors,
            "warnings": self.warnings,
        }, indent=2))


def _print_active(report: Report, action: Step, dry_run: bool, preset: str) -> None:
    """The active starter: what it enforces, or that there is none; then the next step."""
    if action.result == "skipped":
        report.say(f"  No active rule (--rules {preset}): aegis check enforces no rule until one names files.")
    elif action.names or action.kept:
        report.say(f"  Active rule in {action.target}/:")
        for name in action.names:
            desc = ACTIVE_STARTERS[name]
            report.say(f"    {'[DRY-RUN]' if dry_run else '✅'} {name}: {desc}")
        for name in action.kept:
            report.say(f"    [SKIP] {name} (a file with this name exists)")
    else:
        return  # a workspace that already had rules: nothing was seeded, nothing to say
    if not dry_run:
        report.say(_NEXT_RULE)


def _print_ci(report: Report, action: Step, dry_run: bool) -> None:
    if action.result == "present":
        report.say(f"  ✅ CI: {action.detail}")
    elif action.result == "created":
        report.say(f"  ✅ {action.target}: {'would create' if dry_run else 'created'} ({action.detail})")
    elif action.result == "kept":
        report.say(f"  {_ICONS['kept']} {action.target}: kept ({action.detail})")
    elif action.result == "unchanged":
        report.say(f"  ✅ {action.target}: unchanged")
    # "suggested": the workflow is printed after a real run (_report_ci)


def _print_actions(report: Report, actions: Sequence[Step], dry_run: bool, preset: str) -> None:
    for action in actions:
        if action.target == _ACTIVE_LABEL:
            _print_active(report, action, dry_run, preset)
            continue
        if action.target == CI_WORKFLOW_LABEL:
            _print_ci(report, action, dry_run)
            continue
        if action.target.startswith(RULES_RELDIR + "/"):
            report.say(f"  Starter rules (preset={preset}) in {action.target}/:")
            for name in action.names:
                report.say(f"    {'[DRY-RUN]' if dry_run else '✅'} {name}")
            for name in action.kept:
                report.say(f"    [SKIP] {name} (a rule with this id exists)")
            if action.names:
                report.say("    They apply to no file until you set their target_paths (aegis status lists them).")
            continue
        if action.result == "absent":
            continue  # CLAUDE.md: Aegis never creates one
        if action.target == "ast drivers":
            verb = "Would configure" if dry_run else "Configured"
            for ext in action.detail.split(", ") if action.detail else []:
                report.say(f"    ✨ {verb} AST driver (.{ext}): packaged {ext} driver")
            continue
        if action.target == "pre-commit hook" and action.result == "unchanged":
            report.say(f"    🪝 Pre-commit hook: {action.detail}")
            continue
        if action.target == "prepare-commit-msg hook" and action.result == "unchanged" and action.detail:
            report.say(f"    🪝 Prepare-commit-msg hook: {action.detail}")
            continue
        if action.target in ("pre-commit hook", "prepare-commit-msg hook", SCAFFOLD_LABEL):
            continue  # the hook is printed by _report_hook; the directories are in JSON only
        icon = _ICONS.get(action.result, "✅")
        if action.result == "manual":
            report.say(f"  {icon} {action.target}: {action.detail}; run it yourself:")
            report.say(f"       {display_command(action.command or [])}")
        elif action.command:
            result = "would run" if action.result == "would_run" else action.result
            report.say(f"  {icon} {action.target}: {result} ({display_command(action.command)})")
        else:
            detail = f" ({action.detail})" if action.detail else ""
            report.say(f"  {icon} {action.target}: {action.result}{detail}")


def report_partial(report: Report, exc: Exception, actions: Sequence[Step], done: str) -> None:
    """Report a failure in the middle of a real run with what it had already changed."""
    if isinstance(exc, OSError):
        where = f"{exc.filename}: " if exc.filename else ""
        report.error(f"{where}{exc.strerror or exc}; stopped there.")
    else:
        report.error(str(exc))
    changed = [a.target for a in actions if a.result not in _NO_CHANGE]
    if changed:
        report.error(f"Already {done}: {', '.join(changed)}. Fix the cause, then re-run (it keeps what is there).")
    else:
        report.error(f"Nothing was {done}.")


def _print_card(report: Report, root: Path) -> None:
    """The day-0 card (aegis_core.card), as `aegis check --card` prints it: what this
    repository looks like to Aegis now that it is set up. Advisory: init never fails for it."""
    if report.json_mode:
        return
    from aegis_cli import sanitize_display

    try:
        from aegis_core import card

        lines = card.build(root).text_lines()
    except Exception as exc:
        report.warn(f"the day-0 card could not be built: {type(exc).__name__}: {exc}")
        return
    for line in lines:
        report.say(sanitize_display(f"  {line}", max_len=max(len(line) + 2, 80)))
    report.say()


def _home_label(evidence: str, home: Path) -> str:
    """``evidence`` (a path that found a host) as ``~/...`` when it is under ``home``."""
    if evidence.startswith("~/"):
        return evidence
    try:
        return "~/" + Path(evidence).relative_to(home).as_posix()
    except ValueError:
        return evidence


def _report_hook(report: Report, root: Path, actions: Sequence[Step]) -> None:
    if not any(a.target == "pre-commit hook" and a.result == "installed" for a in actions):
        return
    st = hook_status(root)
    report.say(f"    🪝 Pre-commit hook installed ({st['hook_file']})")
    cm = next((a for a in actions if a.target == "prepare-commit-msg hook"), None)
    if cm is not None:
        if cm.result in ("installed", "unchanged") and st.get("git_hooks_dir"):
            cm_file = Path(st["git_hooks_dir"]) / "prepare-commit-msg"
            report.say(f"    🪝 Prepare-commit-msg hook installed ({cm_file})")
        elif cm.result == "kept":
            report.say("    ⚠️  Prepare-commit-msg hook kept (existing hook is not Aegis's; left alone)")
    if st["hooks_dir_in_work_tree"]:
        print(work_tree_warning(st["hook_file"]), file=sys.stderr)


def _report_ci(report: Report, actions: Sequence[Step]) -> None:
    """After a real run: CI is the floor. The workflow written, or the one to add."""
    step = next((a for a in actions if a.target == CI_WORKFLOW_LABEL), None)
    floor = "CI is the floor: git commit --no-verify skips the pre-commit hook, so CI must run aegis check too."
    if step is None or step.result not in ("created", "suggested"):
        return
    if step.result == "created":
        report.say(f"  {floor} Review and commit {CI_WORKFLOW_LABEL}.")
        report.say()
        return
    lead = ("No GitHub Actions workflow here runs aegis check yet." if step.names
            else "This repository has no GitHub Actions workflow yet.")
    report.say(f"  {floor}")
    report.say(f"  {lead} Save this as {CI_WORKFLOW_LABEL}, or re-run aegis init with --ci to write it:")
    report.say()
    for line in ci_workflow().splitlines():
        report.say(f"      {line}".rstrip())
    report.say()
