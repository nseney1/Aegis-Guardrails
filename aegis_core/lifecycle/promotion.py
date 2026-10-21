"""Promotion, demotion and enforcement-tier transitions, judged by ledger fitness.

The lifecycle never runs by itself (ADR 0005 D1): ``suggest`` says what a rule's
evidence supports, ``aegis sync`` records it in ``.aegis/state/derived.json``, and only
``aegis sync --apply`` or ``aegis rule promote/demote/archive`` move a rule. Fitness
comes from aegis_core.fitness (the ledger); rule frontmatter is never read for it.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis_core.fitness import Fitness, for_rules
from aegis_core.rules import Rule, load_rules
from aegis_core.storage import atomic_write_and_unlink as _atomic_write_and_unlink, atomic_write_text, locked
from aegis_core.taxonomy import RULE_TYPE_DIRS, RULE_TYPES
from aegis_core.telemetry_engine import ledger
from aegis_core.workspace import literal_workspace
from aegis_core.workspace.base import Workspace
from aegis_core.yaml_engine.frontmatter import parse_rule_frontmatter
from aegis_core.yaml_engine.serializer import dump_frontmatter
from .constants import (
    DEMOTION_PATH,
    MIN_AGE_DAYS_FOR_PROMOTION,
    MIN_PROMOTION_VERDICTS,
    PROMOTION_PATH,
    PROMOTION_THRESHOLD,
    PROTECTED_RULES,
    TIER_DOWN_MISFIRE,
    TIER_UP,
)
from .parsers import _transform_frontmatter_type, find_rule_file, rule_age_days, sanitize_rule_id

__all__ = [
    "SUGGESTIONS",
    "demote_rule",
    "evaluate_rule_tiers",
    "evaluate_demotions",
    "evaluate_promotions",
    "promote_rule",
    "suggest",
]

SUGGESTIONS = ("promote", "demote", "archive")


def _protected(rule_id: str) -> bool:
    base = rule_id[5:] if rule_id.startswith("rule-") else rule_id
    return rule_id in PROTECTED_RULES or base in PROTECTED_RULES


def suggest(rule: Rule, fit: Fitness, now: Optional[datetime] = None) -> Optional[str]:
    """The transition a rule's evidence supports: ``fit.suggestion``, the one decision of
    aegis_core.fitness.compute (promote, demote, archive or None). Rules that are broken,
    expired, untyped or protected never move by evidence and get None."""
    if not rule.served or rule.type is None or _protected(rule.id):
        return None
    return fit.suggestion


def _evaluate(workspace: Workspace | Path | str, wanted: str, now: Optional[datetime]) -> List[Dict[str, Any]]:
    ws = literal_workspace(workspace)
    rules = [r for r in load_rules(ws).served]
    fits = for_rules(ws, rules, now, verify_ci=True)
    out = []
    for rule in rules:
        fit = fits[rule.id]
        if suggest(rule, fit, now) != wanted:
            continue
        spec = RULE_TYPES[rule.type]
        out.append({
            "rule_id": rule.id,
            "from_type": rule.type,
            "to_type": spec.promotes_to if wanted == "promote" else spec.demotes_to,
            "triggers": fit.triggers,
            "tp": fit.tp,
            "fp": fit.fp,
            "fitness": fit.score,
            "misfire": fit.misfire,
            "age_days": rule_age_days(rule, now),
        })
    return out


def evaluate_promotions(workspace: Workspace | Path | str, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Rules whose evidence supports promotion (see ``suggest``)."""
    return _evaluate(workspace, "promote", now)


def evaluate_demotions(workspace: Workspace | Path | str, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Rules whose evidence supports demotion (see ``suggest``)."""
    return _evaluate(workspace, "demote", now)


def _recheck_move_locked(rule_id: str, rule_path: Path, target_path: Path) -> Optional[Dict[str, Any]]:
    """Repeat the unlocked pre-move checks once the rules lock is held.

    A create into the target tier, or another promote/demote of the same rule,
    can land between the first checks and the lock: moving anyway would
    overwrite the rival rule or read a source that is already gone.
    """
    if not rule_path.is_file():
        return {
            "status": "not_found",
            "message": f"Rule '{rule_id}' was moved or removed before the rules lock was acquired",
        }
    if target_path != rule_path and target_path.exists():
        return {
            "status": "target_exists",
            "message": f"Target already exists: {target_path}",
        }
    return None


def _move(ws: Workspace, rule_id: str, source: Path, from_type: str, to_type: str,
          dry_run: bool, done: str) -> Dict[str, Any]:
    target_dir = ws.rules_dir / RULE_TYPE_DIRS[to_type]
    target_path = target_dir / f"{rule_id}.md"
    if target_path.exists():
        return {"status": "target_exists", "message": f"Target already exists: {target_path}"}
    result = {
        "status": "dry_run" if dry_run else done,
        "from_type": from_type,
        "to_type": to_type,
        "source_path": str(source),
        "target_path": str(target_path),
    }
    if dry_run:
        return result
    target_dir.mkdir(parents=True, exist_ok=True)
    with locked(ws.root):
        conflict = _recheck_move_locked(rule_id, source, target_path)
        if conflict is not None:
            return conflict
        content = source.read_text(encoding="utf-8")
        _atomic_write_and_unlink(source, target_path, _transform_frontmatter_type(content, to_type))
    return result


def promote_rule(
    workspace: Workspace | Path | str,
    rule_id: str,
    force: bool = False,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Promote a rule one tier (trap -> invariant -> gate).

    Without ``force`` the rule's ledger evidence must support it (``suggest``).
    """
    ws = literal_workspace(workspace)
    rule_path, current_type = find_rule_file(ws, rule_id)
    if rule_path is None or current_type is None:
        return {"status": "not_found", "message": f"Rule '{rule_id}' not found in workspace"}

    next_type = PROMOTION_PATH.get(current_type)
    if next_type is None:
        return {
            "status": "already_terminal",
            "current_type": current_type,
            "message": f"Rule '{rule_id}' is already at terminal level ('{current_type}')",
        }

    clean_id = sanitize_rule_id(rule_id) or rule_path.stem
    if _protected(clean_id):
        return {
            "status": "protected_rule_immutable",
            "message": f"Cannot promote a rule into the protected core rule namespace: '{rule_id}'",
        }

    if not force:
        view = ledger.read(ws.root)
        if view.incomplete:
            return {
                "status": "ineligible",
                "current_type": current_type,
                "message": f"Rule '{rule_id}' was not promoted: the ledger is incomplete ({view.incomplete})",
            }
        rule = load_rules(ws).get(clean_id)
        fit = for_rules(ws, [rule], view=view, verify_ci=True)[clean_id] if rule is not None else Fitness(clean_id)
        if rule is None or suggest(rule, fit) != "promote":
            return {
                "status": "ineligible",
                "current_type": current_type,
                "triggers": fit.triggers,
                "tp": fit.tp,
                "fitness": fit.score,
                "message": (
                    f"Rule '{rule_id}' does not meet the promotion threshold "
                    f"(fitness >= {PROMOTION_THRESHOLD} over >= {MIN_PROMOTION_VERDICTS} verdicts, "
                    f"{MIN_AGE_DAYS_FOR_PROMOTION} days old)"
                ),
            }

    return _move(ws, clean_id, rule_path, current_type, next_type, dry_run, "promoted")


def demote_rule(
    workspace: Workspace | Path | str,
    rule_id: str,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Demote a rule one tier (gate -> invariant -> trap)."""
    clean_id = sanitize_rule_id(rule_id)
    if not clean_id:
        return {"status": "invalid_id", "message": f"Invalid rule ID: '{rule_id}'"}
    if _protected(clean_id):
        raise ValueError(f"Cannot demote protected core rule: '{rule_id}'")

    ws = literal_workspace(workspace)
    rule_path, current_type = find_rule_file(ws, clean_id)
    if rule_path is None or current_type is None:
        return {"status": "not_found", "message": f"Rule '{clean_id}' not found in workspace"}

    next_type = DEMOTION_PATH.get(current_type)
    if next_type is None:
        return {
            "status": "already_base",
            "current_type": current_type,
            "message": f"Rule '{clean_id}' is at base level ('{current_type}') and cannot be demoted further",
        }
    return _move(ws, clean_id, rule_path, current_type, next_type, dry_run, "demoted")


_TIERS = ("advisory", "mechanical", "gate")


def _next_tier(enforcement: str, fit: Fitness) -> tuple[str, str]:
    """``(new tier, reason)`` for an advisory/mechanical/gate enforcement tier."""
    if enforcement not in _TIERS or not fit.has_min_n:
        return enforcement, ""
    index = _TIERS.index(enforcement)
    if index > 0 and fit.misfire > TIER_DOWN_MISFIRE[enforcement]:
        return _TIERS[index - 1], f"misfire bound {fit.misfire:.2f} > {TIER_DOWN_MISFIRE[enforcement]}"
    if index + 1 < len(_TIERS):
        min_verdicts, min_fitness = TIER_UP[enforcement]
        if fit.verdicts >= min_verdicts and fit.score >= min_fitness:
            return _TIERS[index + 1], f"fitness {fit.score:.2f} >= {min_fitness} over {fit.verdicts:g} verdicts"
    return enforcement, ""


def _rewrite_enforcement(path: Path, before: str, tier: str) -> bool:
    """Set ``enforcement: tier`` in the rule file if it still holds ``before``."""
    try:
        meta, body = parse_rule_frontmatter(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return False
    if meta.get("enforcement", "advisory") != before:
        return False
    meta["enforcement"] = tier
    atomic_write_text(path, dump_frontmatter(meta, body=body))
    return True


def evaluate_rule_tiers(workspace: Workspace | Path | str | None = None, execute: bool = False) -> Dict[str, Any]:
    """Evaluate the enforcement tier (advisory -> mechanical -> gate) of each rule from
    its ledger fitness; with ``execute``, rewrite only the ``enforcement`` key.

    Gates and invariants are always ``gate`` and are not evaluated. While the ledger is
    incomplete, or its CI evidence could not be read, the changes are reported but not
    written (``refused`` says why).
    """
    ws = literal_workspace(workspace)
    rules = [r for r in load_rules(ws).served if not RULE_TYPES[r.type].mandatory]
    view = ledger.read(ws.root)
    fits = for_rules(ws, rules, view=view, verify_ci=True)
    refused = f"not written: the ledger is incomplete ({view.incomplete})" if execute and view.incomplete else None
    unavailable = next((f.evidence_error for f in fits.values() if not f.evidence_available), None)
    if execute and not refused and unavailable:
        refused = f"not written: the evidence is unavailable ({unavailable})"
    if refused:
        execute = False
    changes: List[Dict[str, Any]] = []
    for rule in rules:
        old = rule.enforcement
        new, reason = _next_tier(old, fits[rule.id])
        if new == old:
            continue
        if execute:
            # One rule at a time under the lock, re-checked against the file on disk,
            # so a concurrent edit or move is never clobbered.
            with locked(ws.root):
                if not _rewrite_enforcement(ws.root / rule.path, old, new):
                    continue
        changes.append({"rule": rule.id, "old_tier": old, "new_tier": new, "reason": reason})
    result: Dict[str, Any] = {"evaluated": len(rules), "changes": changes}
    if refused:
        result["refused"] = refused
    return result
