"""Rule coverage of the workspace's files and the governance report card (SDK grade/coverage_report)."""
from __future__ import annotations

import math
import os
from pathlib import Path
from typing import List, Optional, Union

from aegis_core import gitsafe
from aegis_core.workspace.layout import AEGIS_DIRNAME, LEGACY_SOMA_DIRNAME as _RETIRED_DIRNAME


def _list_workspace_files(workspace: str) -> list[str]:
    tracked = gitsafe.list_files(workspace, untracked=False)
    if tracked:
        return tracked
    ws_path = Path(workspace)
    files: list[str] = []
    if ws_path.is_dir():
        for p in sorted(ws_path.rglob("*")):
            if p.is_file():
                rel = p.relative_to(ws_path).as_posix()
                files.append(rel)
    return files


def _rules(workspace: str):
    """The workspace's rule set. Coverage and the grade use the served rules and report
    how many rule files could not be loaded (``rule_errors``) instead of dropping them unseen."""
    from aegis_core.rules import load_rules

    return load_rules(workspace)


def calculate_coverage(workspace: str, exclude: Optional[Union[List[str], str]] = None) -> dict:
    """Which workspace files the rules' target_paths cover, overall and per directory."""
    all_files = _list_workspace_files(workspace)
    EXCLUDE_PATTERNS = [f'{AEGIS_DIRNAME}/', f'{_RETIRED_DIRNAME}/', 'vendor/', '.git/', 'node_modules/']
    if exclude:
        if isinstance(exclude, str):
            EXCLUDE_PATTERNS.append(exclude)
        else:
            EXCLUDE_PATTERNS.extend(exclude)
    all_files = [f for f in all_files if not any(p in f for p in EXCLUDE_PATTERNS)]

    ruleset = _rules(workspace)
    served = ruleset.served

    covered_files = set()
    uncovered_files = set()
    coverage_map = {}
    # Weakest first. A served rule's enforcement is one of the three (rules.VALID_ENFORCEMENT),
    # so the order is all a rank needs: no numeric ranks or defaults to drift apart.
    tiers = ('none', 'advisory', 'mechanical', 'gate')
    dir_tiers = {}

    for f in all_files:
        applying = [rule for rule in served if rule.applies_to(f)]
        is_covered = bool(applying)

        if is_covered:
            covered_files.add(f)
        else:
            uncovered_files.add(f)

        d = os.path.dirname(f) or '.'
        if d not in coverage_map:
            coverage_map[d] = {'covered': 0, 'total': 0, 'tier': 'none'}
        coverage_map[d]['total'] += 1
        if is_covered:
            coverage_map[d]['covered'] += 1

        for rule in applying:
            if tiers.index(rule.enforcement) > tiers.index(dir_tiers.get(d, 'none')):
                dir_tiers[d] = rule.enforcement

        coverage_map[d]['tier'] = dir_tiers.get(d, 'none')

    total = len(all_files)
    covered = len(covered_files)
    pct = (covered / total * 100) if total > 0 else 0

    return {
        'total_files': total,
        'covered': covered,
        'uncovered': total - covered,
        'coverage_pct': round(pct, 1),
        'by_directory': coverage_map,
        'uncovered_files': sorted(uncovered_files),
        'rule_errors': len(ruleset.errors),
    }


def letter_grade(pct: float) -> str:
    """Map a percentage (0..100) to a letter grade."""
    if pct >= 97: return 'A+'
    if pct >= 93: return 'A'
    if pct >= 90: return 'A-'
    if pct >= 87: return 'B+'
    if pct >= 83: return 'B'
    if pct >= 80: return 'B-'
    if pct >= 77: return 'C+'
    if pct >= 73: return 'C'
    if pct >= 70: return 'C-'
    if pct >= 67: return 'D+'
    if pct >= 60: return 'D'
    return 'F'


def calculate_governance_grade(workspace: str) -> Optional[dict]:
    """The governance report card over the served rules (fitness from the ledger), with
    ``rule_errors``: how many rule files could not be loaded. None when no rule is served."""
    from aegis_core.fitness import for_rules

    ruleset = _rules(workspace)
    rules = list(ruleset.served)
    if not rules:
        return None
    fits = for_rules(workspace, rules)

    all_files = _list_workspace_files(workspace)
    exclude = [f'{AEGIS_DIRNAME}/', f'{_RETIRED_DIRNAME}/', 'vendor/', '.git/', 'node_modules/']
    all_files = [f for f in all_files if not any(p in f for p in exclude)]

    covered_files = {f for f in all_files if any(rule.applies_to(f) for rule in rules)}
    covered = len(covered_files)
    coverage_pct = (covered / len(all_files) * 100) if all_files else 0

    # A rule with no verdict yet has no measured fitness: it is not averaged in as zero.
    scores = [fits[r.id].score for r in rules if fits[r.id].verdicts]
    avg_fitness = (sum(scores) / len(scores)) if scores else 0
    fitness_pct = avg_fitness * 100

    type_counts = {}
    for rule in rules:
        type_counts[rule.type] = type_counts.get(rule.type, 0) + 1
    total = sum(type_counts.values())
    if len(type_counts) > 1:
        entropy = -sum((n/total) * math.log(n/total) for n in type_counts.values() if n > 0)
        max_entropy = math.log(len(type_counts))
        diversity = (entropy / max_entropy) * 100
    else:
        diversity = 0

    stale = sum(1 for r in rules if fits[r.id].triggers == 0)
    staleness_pct = 100 - (stale / len(rules) * 100)

    invariants = [r for r in rules if r.type == 'invariant']
    healthy_invariants = sum(1 for r in invariants if fits[r.id].score > 0.3)
    invariant_pct = (healthy_invariants / len(invariants) * 100) if invariants else 100

    overall_pct = (coverage_pct * 0.3 + fitness_pct * 0.25 + diversity * 0.15 + staleness_pct * 0.15 + invariant_pct * 0.15)

    tier_counts = {}
    for rule in rules:
        tier_counts[rule.enforcement] = tier_counts.get(rule.enforcement, 0) + 1

    uncovered_dirs = {}
    for f in all_files:
        if f not in covered_files:
            d = os.path.dirname(f) or '.'
            uncovered_dirs[d] = uncovered_dirs.get(d, 0) + 1
    top_gap = max(uncovered_dirs.items(), key=lambda x: x[1]) if uncovered_dirs else ('none', 0)

    return {
        'coverage': {'pct': round(coverage_pct, 1), 'grade': letter_grade(coverage_pct)},
        'avg_fitness': {'pct': round(fitness_pct, 1), 'grade': letter_grade(fitness_pct), 'score': avg_fitness},
        'diversity': {'pct': round(diversity, 1), 'grade': letter_grade(diversity)},
        'staleness': {'pct': round(staleness_pct, 1), 'grade': letter_grade(staleness_pct)},
        'invariant_integrity': {'pct': round(invariant_pct, 1), 'grade': letter_grade(invariant_pct)},
        'tiers': tier_counts,
        'overall': {'pct': round(overall_pct, 1), 'grade': letter_grade(overall_pct)},
        'top_improvement': f'Add rules for {top_gap[0]}/ ({top_gap[1]} uncovered files)',
        'top_gap_count': top_gap[1],
        'rule_errors': len(ruleset.errors),
        'details': {
            'total_rules': len(rules),
            'invariants': len(invariants),
            'healthy_invariants': healthy_invariants,
            'stale_rules': stale,
        },
        'components': {
            'coverage': round(coverage_pct, 1),
            'avg_fitness': round(fitness_pct, 1),
            'diversity': round(diversity, 1),
            'staleness': round(staleness_pct, 1),
            'invariant_strength': round(invariant_pct, 1),
        },
    }


__all__ = [
    "calculate_coverage",
    "letter_grade",
    "calculate_governance_grade",
]
