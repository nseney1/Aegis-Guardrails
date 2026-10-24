"""Unit tests for aegis_core.taxonomy canonical domain constants and review hierarchy."""
from __future__ import annotations

import ast
from pathlib import Path

from aegis_core.taxonomy import (
    CANONICAL_RULE_TYPES,
    DIR_RULE_TYPES,
    ESCALATING_PROTOCOLS,
    ESCALATION_PROTOCOLS,
    GENESIS_STAGES,
    GenesisStage,
    LEGACY_REVIEW_MODE_ALIASES,
    LEGACY_REVIEW_PRONG_ALIASES,
    MCP_DEFAULT_RATE_LIMITS,
    REVIEW_MODES,
    REVIEW_MODE_RANKS,
    REVIEW_PRONGS,
    RULE_TYPE_DIRS,
    RULE_TYPES,
    ReviewMode,
    ReviewProng,
    RuleType,
    WILSON_CONFIDENCE_Z_SCORES,
    legacy_rule_type,
    normalize_review_mode,
)


def test_review_mode_hierarchy_and_ranks():
    assert REVIEW_MODES == ("patrol", "sweep", "vanguard", "bulwark", "fortress", "citadel")
    assert ESCALATION_PROTOCOLS == REVIEW_MODES
    assert ESCALATING_PROTOCOLS == ("vanguard", "bulwark", "fortress", "citadel")
    assert REVIEW_MODE_RANKS[ReviewMode.PATROL] < REVIEW_MODE_RANKS[ReviewMode.SWEEP]
    assert REVIEW_MODE_RANKS[ReviewMode.SWEEP] < REVIEW_MODE_RANKS[ReviewMode.VANGUARD]
    assert REVIEW_MODE_RANKS[ReviewMode.VANGUARD] < REVIEW_MODE_RANKS[ReviewMode.BULWARK]
    assert REVIEW_MODE_RANKS[ReviewMode.BULWARK] < REVIEW_MODE_RANKS[ReviewMode.FORTRESS]
    assert REVIEW_MODE_RANKS[ReviewMode.FORTRESS] < REVIEW_MODE_RANKS[ReviewMode.CITADEL]


def test_normalize_review_mode_canonical_and_legacy():
    assert normalize_review_mode(None) == ReviewMode.PATROL
    assert normalize_review_mode("") == ReviewMode.PATROL
    assert normalize_review_mode("  FORTRESS ") == ReviewMode.FORTRESS
    for legacy, canonical in LEGACY_REVIEW_MODE_ALIASES.items():
        assert normalize_review_mode(legacy) == canonical
        assert normalize_review_mode(legacy.upper()) == canonical


def test_review_prongs_and_genesis_stages():
    assert REVIEW_PRONGS == ("Sentry", "Trace", "Probe", "Gauntlet", "Bastion", "Debrief")
    assert LEGACY_REVIEW_PRONG_ALIASES["spores"] == ReviewProng.SENTRY
    assert LEGACY_REVIEW_PRONG_ALIASES["mulch"] == ReviewProng.DEBRIEF
    assert GENESIS_STAGES == (
        GenesisStage.PERIMETER,
        GenesisStage.CHRONOLOGY,
        GenesisStage.BLUEPRINT,
        GenesisStage.POLICY,
    )


def test_one_rule_type_table_with_six_types_and_their_directories():
    assert CANONICAL_RULE_TYPES == ("invariant", "trap", "gate", "boundary", "persona", "contract")
    assert tuple(RULE_TYPES) == CANONICAL_RULE_TYPES
    assert RULE_TYPE_DIRS == {
        "invariant": "invariants", "trap": "traps", "gate": "gates",
        "boundary": "boundaries", "persona": "personas", "contract": "contracts",
    }
    assert {d: t for t, d in RULE_TYPE_DIRS.items()} == DIR_RULE_TYPES
    # No legacy alias survives in the table: v3 names are migrate's business.
    assert not {"wall", "membrane", "genome", "walls", "membranes"} & (set(RULE_TYPE_DIRS) | set(DIR_RULE_TYPES))


def test_the_lifecycle_ladder_is_trap_invariant_gate():
    assert RULE_TYPES[RuleType.TRAP].promotes_to == RuleType.INVARIANT
    assert RULE_TYPES[RuleType.INVARIANT].promotes_to == RuleType.GATE
    assert RULE_TYPES[RuleType.GATE].promotes_to is None
    assert RULE_TYPES[RuleType.GATE].demotes_to == RuleType.INVARIANT
    assert RULE_TYPES[RuleType.INVARIANT].demotes_to == RuleType.TRAP
    assert RULE_TYPES[RuleType.TRAP].demotes_to is None
    assert {t for t, spec in RULE_TYPES.items() if spec.mandatory} == {"invariant", "gate"}


_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
_TYPE_WORDS = set(CANONICAL_RULE_TYPES) | set(RULE_TYPE_DIRS.values()) | {
    "wall", "walls", "membrane", "membranes", "genome", "vacuole", "safety-guard", "learned-trap",
}
# The table itself, which also holds the legacy-name table aegis migrate converts with.
_TABLE_OWNERS = {"aegis_core/taxonomy.py"}


def test_no_module_keeps_a_second_rule_type_vocabulary():
    """A literal dict/set/list/tuple naming three or more rule types or type dirs is a
    second vocabulary; every module reads the one table instead."""
    offenders = []
    for package in ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk"):
        for path in sorted((_ROOT / package).rglob("*.py")):
            rel = path.relative_to(_ROOT).as_posix()
            if rel in _TABLE_OWNERS:
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, (ast.Dict, ast.Set, ast.List, ast.Tuple)):
                    items = node.keys if isinstance(node, ast.Dict) else node.elts
                    words = {
                        n.value for n in items
                        if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value in _TYPE_WORDS
                    }
                    if len(words) >= 3:
                        offenders.append(f"{rel}:{node.lineno} {sorted(words)}")
    assert offenders == []


def test_statistical_and_operational_constants():
    assert 0.90 in WILSON_CONFIDENCE_Z_SCORES
    assert 0.95 in WILSON_CONFIDENCE_Z_SCORES
    assert 0.99 in WILSON_CONFIDENCE_Z_SCORES
    # Only the mutation limit is read (aegis_mcp.server._RATE_LIMITS); an unread class is dead text.
    assert set(MCP_DEFAULT_RATE_LIMITS) == {"MUTATION"}


def test_a_type_name_of_any_version_stands_for_its_v4_type():
    assert legacy_rule_type("invariant") == "invariant"
    assert legacy_rule_type(" Trap ") == "trap"  # any case and padding
    assert legacy_rule_type("walls") == "invariant"  # a v3 type directory
    assert legacy_rule_type("Vacuoles") == "trap"  # a v2 organelle
    assert legacy_rule_type("traps") == "trap"


def test_a_name_no_version_used_stands_for_no_type():
    assert legacy_rule_type("widget") is None
    assert legacy_rule_type("") is None
    assert legacy_rule_type(None) is None
    assert legacy_rule_type(3) is None
