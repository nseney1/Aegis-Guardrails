"""Archiving: parking a rule whose ledger evidence says it misfires.

A rule is archived only by an explicit ``aegis rule archive`` or ``aegis sync --apply``
(ADR 0005 D1), and only when ``promotion.suggest`` says ``archive`` over a complete
ledger (``ledger.incomplete``: unreadable lines may hide its true positives). Archived
rules move to ``.aegis/rules/.archive/``, a hidden directory the loader never serves;
each move is logged to ``.aegis/state/lifecycle.jsonl``.
"""
from __future__ import annotations

from datetime import datetime, timezone  # noqa: F401 - names the 4.3.3 public-names pin holds
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aegis_core.fitness import for_rules
from aegis_core.primitives import utc_stamp
from aegis_core.rules import load_rules
from aegis_core.storage import append_jsonl, locked
from aegis_core.telemetry_engine import ledger
from aegis_core.workspace import literal_workspace
from aegis_core.workspace.base import Workspace
from .parsers import find_rule_file, sanitize_rule_id

__all__ = [
    "ARCHIVE_DIR",
    "archive_rule",
    "evaluate_archives",
    "evidence_line",
    "prune_rules",
    "run_rule_selection",
    "transition_candidates",
]

ARCHIVE_DIR = ".archive"


def _candidate(wanted: str, rule: Any, fit: Any, now: Optional[datetime]) -> Dict[str, Any]:
    if wanted == "archive":
        return {"rule_id": rule.id, "type": rule.type, "triggers": fit.triggers, "tp": fit.tp, "fp": fit.fp,
                "fitness": fit.score, "misfire": fit.misfire}
    from aegis_core.taxonomy import RULE_TYPES
    from .parsers import rule_age_days
    # The shape of promotion.evaluate_demotions, so the CLI's --json is the same either way.
    return {"rule_id": rule.id, "from_type": rule.type, "to_type": RULE_TYPES[rule.type].demotes_to,
            "triggers": fit.triggers, "tp": fit.tp, "fp": fit.fp, "fitness": fit.score, "misfire": fit.misfire,
            "age_days": rule_age_days(rule, now)}


def transition_candidates(
    workspace: Workspace | Path | str, wanted: str, now: Optional[datetime] = None,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """The rules whose evidence supports ``wanted`` ("archive" or "demote") and, when the CI-confirmed
    evidence was cut short, why. One projection answers both, so a listing can say why without asking
    gh again. The candidates are listed either way: acting on one re-checks the evidence and refuses."""
    from .promotion import suggest

    if wanted not in ("archive", "demote"):
        raise ValueError(f"wanted must be 'archive' or 'demote', not {wanted!r}")
    ws = literal_workspace(workspace)
    rules = list(load_rules(ws).served)
    fits = for_rules(ws, rules, now, verify_ci=True)
    cut = next((f for f in fits.values() if not f.evidence_available), None)
    error = None if cut is None else (cut.evidence_error or "the evidence is unavailable")
    return [_candidate(wanted, rule, fits[rule.id], now) for rule in rules
            if suggest(rule, fits[rule.id], now) == wanted], error


def evidence_line(error: str) -> str:
    """One bounded, printable line naming why the evidence is unavailable."""
    text = "".join(ch if ch.isprintable() else " " for ch in error)
    return f"Evidence unavailable: {text[:300]}"


def evaluate_archives(workspace: Workspace | Path | str, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Rules whose evidence supports archiving (``promotion.suggest``)."""
    return transition_candidates(workspace, "archive", now)[0]


def _park(path: Path, dest_dir: Path) -> Path:
    """Move a rule into ``dest_dir`` without replacing a rule already parked there.

    One rename (the archive is inside the rules directory, so on the same filesystem):
    it either happens or the rule stays where it was, never a half-copied file.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / path.name
    n = 1
    while os.path.lexists(dest):
        dest = dest_dir / f"{path.stem}.{n}{path.suffix}"
        n += 1
    os.replace(path, dest)
    return dest


def _archive_refusal(ws: Workspace, rule_id: str, view: Any) -> Optional[str]:
    """Why ``rule_id`` may not be archived now, or None. Credit cut short by a failed CI read
    would make a sound rule look like it misfires, so unavailable evidence refuses."""
    from .promotion import suggest

    rule = load_rules(ws).get(rule_id)
    fit = for_rules(ws, [rule], view=view, verify_ci=True)[rule_id] if rule is not None else None
    if fit is not None and not fit.evidence_available:
        return f"Rule '{rule_id}' was not archived: its evidence is unavailable ({fit.evidence_error})"
    if fit is None or suggest(rule, fit) != "archive":
        return f"Rule '{rule_id}' no longer has evidence that supports archiving it"
    return None


def archive_rule(
    workspace: Workspace | Path | str, rule_id: str, dry_run: bool = False, *, audit: bool = True,
) -> Dict[str, Any]:
    """Move one rule to ``.aegis/rules/.archive/`` and log it (``audit=False``: no log row, for a
    move that ``sync --pr`` makes only on its lifecycle branch and then undoes here).

    Only a rule whose ledger evidence supports archiving (``promotion.suggest``) moves,
    and that is checked again under the lock: evidence recorded since the caller judged
    the rule wins.
    """
    clean = sanitize_rule_id(rule_id)
    if not clean:
        return {"status": "invalid_id", "message": f"Invalid rule ID: '{rule_id}'"}
    ws = literal_workspace(workspace)
    path, rule_type = find_rule_file(ws, clean)
    if path is None:
        return {"status": "not_found", "message": f"Rule '{clean}' not found in workspace"}
    archive_dir = ws.rules_dir / ARCHIVE_DIR
    if dry_run:
        return {"status": "dry_run", "from_type": rule_type, "source_path": str(path), "target_dir": str(archive_dir)}
    with locked(ws.root):
        if not path.is_file():
            return {"status": "not_found", "message": f"Rule '{clean}' was moved or removed before the rules lock was acquired"}
        view = ledger.read(ws.root)
        if view.incomplete:
            return {
                "status": "ineligible",
                "message": f"Rule '{clean}' was not archived: the ledger is incomplete ({view.incomplete})",
            }
        refusal = _archive_refusal(ws, clean, view)
        if refusal:
            return {"status": "ineligible", "message": refusal}
        dest = _park(path, archive_dir)
        if audit:
            append_jsonl(ws.layout.lifecycle_log, [{
                "timestamp": utc_stamp(),
                "rule": clean,
                "action": "moved_to_archive",
            }])
    return {"status": "archived", "from_type": rule_type, "source_path": str(path), "target_path": str(dest)}


def run_rule_selection(workspace: Workspace | Path | str | None = None, execute: bool = False) -> int:
    """Report the rules whose evidence supports archiving; with ``execute``, archive them."""
    ws = literal_workspace(workspace)
    if not ws.rules_dir.exists():
        print("No rules directory found.")
        return 0
    candidates, unavailable = transition_candidates(ws, "archive")
    if unavailable:
        print(evidence_line(unavailable))
    if not candidates:
        print("No rules to archive.")
        return 0
    for c in candidates:
        note = " (dry run)"
        if execute:
            result = archive_rule(ws, c["rule_id"])
            note = "" if result["status"] == "archived" else f" (not archived: {result['message']})"
        print(
            f"[ARCHIVE] {c['rule_id']} (fitness {c['fitness']:.2f}, misfire bound {c['misfire']:.2f}, "
            f"tp {c['tp']:g}, fp {c['fp']:g}){note}"
        )
    return 0


def prune_rules(workspace: Workspace | Path | str | None = None, execute: bool = False) -> int:
    """Archive the rules that misfire (``run_rule_selection``)."""
    return run_rule_selection(workspace=workspace, execute=execute)
