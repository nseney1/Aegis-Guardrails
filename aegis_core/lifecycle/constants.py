"""Lifecycle constants: the promotion ladder, protected rules and the evidence thresholds.

Whether a rule moves is decided by aegis_core.fitness.compute alone; the age a promotion
needs is defined there and named here for the lifecycle's readers.
"""
from __future__ import annotations

from aegis_core.fitness import MIN_AGE_DAYS_FOR_PROMOTION
from aegis_core.taxonomy import RULE_TYPES

__all__ = ["DEMOTION_PATH", "MIN_AGE_DAYS_FOR_PROMOTION", "MIN_PROMOTION_VERDICTS", "PROMOTION_PATH",
           "PROMOTION_THRESHOLD", "PROTECTED_RULES", "TIER_DOWN_MISFIRE", "TIER_UP"]

# The protected shipped rules that must never be demoted
PROTECTED_RULES = frozenset({
    "providence",
    "cost-optimization",
    "subagent-delegation",
    "architectural-tenets",
    "polyglot-standards",
    "feature-specs",
    "testing",
    "documentation",
    "destructive-ops",
    "git-workflow",
})

# The ladder trap -> invariant -> gate, read from the one rule-type table.
PROMOTION_PATH = {name: spec.promotes_to for name, spec in RULE_TYPES.items() if spec.promotes_to}
DEMOTION_PATH = {name: spec.demotes_to for name, spec in RULE_TYPES.items() if spec.demotes_to}

# Promote: enough verdicts and a high bound.
MIN_PROMOTION_VERDICTS = 20
PROMOTION_THRESHOLD = 0.85

# Enforcement tier transitions: (min verdicts, min fitness) to move up a tier, and the
# misfire bound above which a tier steps down.
TIER_UP = {"advisory": (20, 0.85), "mechanical": (50, 0.90)}
TIER_DOWN_MISFIRE = {"mechanical": 0.5, "gate": 0.3}
