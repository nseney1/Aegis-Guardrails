"""Governance: read-only governance reports over a workspace, as thin wrappers over aegis_core."""
from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Any, Optional

from aegis_core.errors import RuleParseError
from aegis_core.stats import wilson_interval
from aegis_core.taxonomy import DEFAULT_CONFIDENCE_LEVEL
from aegis_core.metrics import calculate_coverage, calculate_governance_grade
from aegis_core.outcomes.engine import get_changed_files, match_rules_to_changes
from aegis_core.rule_inventory import RuleInventoryError
from aegis_core.rules import load_rules
from aegis_core.sync import build
from aegis_core.workspace.base import Workspace

__all__ = ["Governance"]


class Governance:
    """Aegis governance reports for one workspace.

    Usage:
        from aegis_sdk import Governance
        gov = Governance(project_root='.')
        grade = gov.grade()
        coverage = gov.coverage_report()
    """

    def __init__(self, project_root: str | Path | os.PathLike[str] | Workspace = '.') -> None:
        self.workspace: Workspace = (
            project_root if isinstance(project_root, Workspace) else Workspace.resolve(project_root)
        )
        self.root: Path = self.workspace.root
        self.rules_dir: Path = self.workspace.rules_dir

    def list_rules(self, rule_type: Optional[str] = None) -> list[dict[str, Any]]:
        """List rules (frontmatter plus ``_name``/``_path``), optionally filtered by type.

        A rule file that cannot be loaded stays visible as an ``_error`` record. An
        unsafe or unreadable rules tree raises, because callers cannot tell an empty
        tree from an incomplete one.
        """
        try:
            ruleset = load_rules(self.root)
        except RuleInventoryError as exc:
            raise RuntimeError(str(exc)) from exc
        return [rule.as_dict() for rule in ruleset.rules if not rule_type or rule.type == rule_type]

    def fitness_landscape(self, bayesian: bool = False) -> list[dict[str, Any]]:
        """Ledger fitness of every rule that loads, with the lifecycle transition it suggests.

        One row per rule: ``rule`` (its id), ``path``, ``type``, ``enforcement``,
        ``hypothesis``, ``triggers``, ``tp``, ``fp``, ``last_ts``, ``score`` (aegis_core.fitness)
        and ``suggestion`` (promote, demote, archive or None). ``bayesian`` adds the 90%
        Wilson interval of the true-positive rate as ``bayesian: {lower, upper}``.
        """
        ruleset = load_rules(self.root)
        derived = build(self.root, ruleset)
        landscape = []
        for rule_id, entry in sorted(derived["rules"].items()):
            rule = ruleset.get(rule_id)
            row = {
                "rule": rule_id,
                "path": entry["path"],
                "type": entry["type"],
                "enforcement": rule.enforcement if rule is not None else None,
                "hypothesis": rule.meta.get("hypothesis", "") if rule is not None else "",
                "triggers": entry["triggers"],
                "tp": entry["tp"],
                "fp": entry["fp"],
                "last_ts": entry["last_ts"],
                "score": entry["fitness"],
                "suggestion": entry["suggestion"],
            }
            if bayesian:
                lower, upper = wilson_interval(entry["tp"], entry["tp"] + entry["fp"], DEFAULT_CONFIDENCE_LEVEL)
                row["bayesian"] = {"lower": round(lower, 4), "upper": round(upper, 4)}
            landscape.append(row)
        return landscape

    def coverage_report(self, exclude: Optional[str] = None) -> dict[str, Any]:
        """Which workspace files the rules' target_paths cover, overall and per directory."""
        return calculate_coverage(workspace=str(self.root), exclude=[exclude] if exclude else None)

    def grade(self) -> dict[str, Any]:
        """Governance report card; a fixed all-F report when no rule can be graded.

        ``rule_errors`` counts the rule files that cannot be loaded (they are not graded);
        when no rule loads because of them, the fallback's status is FAIL.
        """
        report = calculate_governance_grade(workspace=str(self.root))
        if report is None:
            errors = len(load_rules(self.root).errors)
            note = "No rules found to grade"
            if errors:
                note = f"No rule could be graded: {errors} rule file(s) cannot be loaded (aegis status lists them)"
            return {
                "coverage": {"pct": 0.0, "grade": "F"},
                "avg_fitness": {"pct": 0.0, "grade": "F", "score": 0.0},
                "diversity": {"pct": 0.0, "grade": "F"},
                "staleness": {"pct": 0.0, "grade": "F"},
                "invariant_integrity": {"pct": 0.0, "grade": "F"},
                "tiers": {},
                "overall": {"pct": 0.0, "grade": "F"},
                "status": "FAIL" if errors else "PASS",
                "note": note,
                "rule_errors": errors,
            }
        return report

    def scan(self, files: Optional[list[str]] = None) -> list[dict[str, Any]]:
        """Rules whose target_paths match ``files`` (default: the files git reports changed).

        Like aegis scan, it never presents a partial rule set as the rules for these
        files: if any rule file cannot be loaded it raises RuleParseError (an AegisError)
        naming them, with ``rule_errors`` [{path, error}].
        """
        ruleset = load_rules(self.root)
        if ruleset.errors:
            errors = [{"path": r.path, "error": r.error or ""} for r in ruleset.errors]
            listed = "; ".join(f"{e['path']}: {e['error']}" for e in errors[:5])
            more = f" (and {len(errors) - 5} more)" if len(errors) > 5 else ""
            raise RuleParseError(
                f"{len(errors)} rule file(s) cannot be served, so no partial rule set is returned: {listed}{more}",
                code="RULES_UNSERVABLE",
                rule_errors=errors,
            )
        changed = files if files is not None else get_changed_files(str(self.root))
        return match_rules_to_changes(self.root, changed, ruleset)

    def entropy(self) -> dict[str, Any]:
        """Rule population and the Shannon entropy (bits) of its type distribution."""
        rules = self.list_rules()
        if not rules:
            return {"population": {"total": 0, "active": 0, "dormant": 0}, "type_entropy": 0.0}
        type_counts: dict[str, int] = {}
        for r in rules:
            rt = str(r.get('type', 'unknown'))
            type_counts[rt] = type_counts.get(rt, 0) + 1
        total = len(rules)
        type_entropy = 0.0
        if len(type_counts) > 1:
            type_entropy = -sum((n / total) * math.log2(n / total) for n in type_counts.values() if n > 0)
        return {
            "population": {"total": total},
            "type_entropy": {"value": round(type_entropy, 4), "distribution": type_counts},
        }
