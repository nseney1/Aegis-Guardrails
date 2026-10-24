"""Canonical domain taxonomy, review hierarchy, rule types, and tuning constants."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


# ── 1. Review Modes & Escalation Hierarchy ──────────────────────────────────
class ReviewMode:
    PATROL = "patrol"
    SWEEP = "sweep"
    VANGUARD = "vanguard"
    BULWARK = "bulwark"
    FORTRESS = "fortress"
    CITADEL = "citadel"


REVIEW_MODE_RANKS: dict[str, int] = {
    ReviewMode.PATROL: 1,
    ReviewMode.SWEEP: 2,
    ReviewMode.VANGUARD: 3,
    ReviewMode.BULWARK: 4,
    ReviewMode.FORTRESS: 5,
    ReviewMode.CITADEL: 6,
}

REVIEW_MODES: tuple[str, ...] = tuple(REVIEW_MODE_RANKS.keys())

ESCALATION_PROTOCOLS: tuple[str, ...] = REVIEW_MODES
ESCALATING_PROTOCOLS: tuple[str, ...] = (
    ReviewMode.VANGUARD,
    ReviewMode.BULWARK,
    ReviewMode.FORTRESS,
    ReviewMode.CITADEL,
)

# Backward-compatible input normalization for legacy frontmatter or external callers
LEGACY_REVIEW_MODE_ALIASES: dict[str, str] = {
    "breeze": ReviewMode.PATROL,
    "gale": ReviewMode.SWEEP,
    "trident": ReviewMode.VANGUARD,
    "maelstrom": ReviewMode.BULWARK,
    "tempest": ReviewMode.FORTRESS,
    "supercell": ReviewMode.CITADEL,
}


def normalize_review_mode(mode: str | None, default: str = ReviewMode.PATROL) -> str:
    """Normalize a review mode string (case-insensitive, mapping legacy aliases)."""
    if not mode:
        return default
    cleaned = mode.strip().lower()
    if cleaned in REVIEW_MODE_RANKS:
        return cleaned
    return LEGACY_REVIEW_MODE_ALIASES.get(cleaned, cleaned)


# ── 2. Review Prongs & Genesis Reconnaissance Stages ────────────────────────
class ReviewProng:
    SENTRY = "Sentry"
    TRACE = "Trace"
    PROBE = "Probe"
    GAUNTLET = "Gauntlet"
    BASTION = "Bastion"
    DEBRIEF = "Debrief"


REVIEW_PRONGS: tuple[str, ...] = (
    ReviewProng.SENTRY,
    ReviewProng.TRACE,
    ReviewProng.PROBE,
    ReviewProng.GAUNTLET,
    ReviewProng.BASTION,
    ReviewProng.DEBRIEF,
)

LEGACY_REVIEW_PRONG_ALIASES: dict[str, str] = {
    "spores": ReviewProng.SENTRY,
    "mycelium": ReviewProng.TRACE,
    "roots": ReviewProng.PROBE,
    "thorns": ReviewProng.GAUNTLET,
    "bedrock": ReviewProng.BASTION,
    "mulch": ReviewProng.DEBRIEF,
}


class GenesisStage:
    PERIMETER = "Perimeter"
    CHRONOLOGY = "Chronology"
    BLUEPRINT = "Blueprint"
    POLICY = "Policy"


GENESIS_STAGES: tuple[str, ...] = (
    GenesisStage.PERIMETER,
    GenesisStage.CHRONOLOGY,
    GenesisStage.BLUEPRINT,
    GenesisStage.POLICY,
)


# ── 3. Rule Types: the one table ────────────────────────────────────────────
class RuleType:
    INVARIANT = "invariant"
    TRAP = "trap"
    GATE = "gate"
    BOUNDARY = "boundary"
    PERSONA = "persona"
    CONTRACT = "contract"


@dataclass(frozen=True)
class RuleTypeSpec:
    """Everything Aegis knows about one rule type.

    ``directory`` is the one place rules of the type live (``.aegis/rules/<directory>/``).
    ``mandatory`` types are offered before advisory rules in a scan (a rule of any type
    becomes mandatory by declaring ``enforcement: gate``). ``promotes_to``/``demotes_to``
    are the lifecycle ladder trap -> invariant -> gate.
    """

    directory: str
    description: str
    label: str
    emoji: str
    mandatory: bool
    promotes_to: Optional[str]
    demotes_to: Optional[str]
    display_order: int
    style: Tuple[str, ...]


RULE_TYPES: Dict[str, RuleTypeSpec] = {
    RuleType.INVARIANT: RuleTypeSpec(
        "invariants", "Must ALWAYS hold (hard safety gate).", "INVARIANT (must not violate)", "🧱", True,
        RuleType.GATE, RuleType.TRAP, 1, ("bold", "magenta"),
    ),
    RuleType.TRAP: RuleTypeSpec(
        "traps", "A known failure mode to watch for.", "ANTI-PATTERN TRAP (watch out)", "🧫", False,
        RuleType.INVARIANT, None, 5, ("cyan",),
    ),
    RuleType.GATE: RuleTypeSpec(
        "gates", "A check that blocks a change until it passes.", "GATE", "📋", True,
        None, RuleType.INVARIANT, 6, ("bold", "red"),
    ),
    RuleType.BOUNDARY: RuleTypeSpec(
        "boundaries", "A sensitive area that needs elevated review.", "ESCALATION GATE (needs review)", "🔬", False,
        None, None, 2, ("blue",),
    ),
    RuleType.PERSONA: RuleTypeSpec(
        "personas", "An idiomatic pattern to follow.", "BEST PRACTICE (follow this pattern)", "🌿", False,
        None, None, 4, ("cyan",),
    ),
    RuleType.CONTRACT: RuleTypeSpec(
        "contracts", "An API or data-shape agreement across services.", "CONTRACT (cross-service agreement)", "🔗", False,
        None, None, 3, ("blue",),
    ),
}

# Views of RULE_TYPES; nothing else spells a rule type or its directory.
CANONICAL_RULE_TYPES: Tuple[str, ...] = tuple(RULE_TYPES)
RULE_TYPE_DIRS: Dict[str, str] = {name: spec.directory for name, spec in RULE_TYPES.items()}
DIR_RULE_TYPES: Dict[str, str] = {spec.directory: name for name, spec in RULE_TYPES.items()}


# Every legacy rule-type name a v1-v3 workspace can hold, mapped to its v4 type: the
# v3 type-normalization aliases, plus the v2 organelle names exactly as v2.1's
# `aegis migrate` mapped them (ORGANELLE_MAPPING, commit 06a7e39). Only aegis migrate
# converts legacy names; the loader looks one up only to say a rule needs migrating.
LEGACY_TYPE_NAMES = {
    "wall": "invariant", "walls": "invariant", "invariants": "invariant", "safety-guard": "invariant",
    "membrane": "boundary", "membranes": "boundary", "boundaries": "boundary",
    "escalation-boundary": "boundary",
    "traps": "trap", "patterns": "trap", "cells": "trap", "rules": "trap", "learned-trap": "trap",
    "personas": "persona", "agent-persona": "persona",
    "contracts": "contract", "contract-bridge": "contract",
    "gates": "gate",
    "vacuole": "trap", "vacuoles": "trap",
    "chloroplast": "persona", "chloroplasts": "persona",
    "plasmodesmata": "contract",
}


def legacy_rule_type(raw: Any) -> Optional[str]:
    """The v4 type that a type name or type-directory name of any version (``wall``,
    ``walls``, ``Trap``, ``invariant``) stands for, or None.

    Only migration reads legacy names; the loader asks only to say that aegis migrate
    can convert a rule it cannot serve.
    """
    if not isinstance(raw, str):
        return None
    name = raw.strip().lower()
    if name in CANONICAL_RULE_TYPES:
        return name
    return LEGACY_TYPE_NAMES.get(name)


# ── 4. Timeouts, TTLs, Retries & Rate Limits ────────────────────────────────
# Rule expiry is a repository setting with its default in aegis_core.config (D10).

# One lock guards rules and the ledger (AD-3), so its wait covers the slowest holder.
LOCK_TIMEOUT_SECONDS: float = 10.0
LOCK_RETRY_INTERVAL_SECONDS: float = 0.01
LOCK_MAX_BACKOFF_SECONDS: float = 0.05

STORAGE_MAX_RETRIES: int = 8
STORAGE_INITIAL_DELAY_SECONDS: float = 0.01

AST_RUNNER_TIMEOUT_SECONDS: float = 3.0
SUBPROCESS_DEFAULT_TIMEOUT_SECONDS: float = 10.0
VERIFY_RUNNER_TIMEOUT_SECONDS: float = 30.0

MCP_DEFAULT_RATE_LIMITS: dict[str, tuple[int, int]] = {
    "MUTATION": (5, 60),
}


# ── 5. Statistical Scoring & JIT Context Budgets ────────────────────────────
WILSON_CONFIDENCE_Z_SCORES: dict[float, float] = {
    0.90: 1.645,
    0.95: 1.960,
    0.99: 2.576,
}
DEFAULT_CONFIDENCE_LEVEL: float = 0.90
JIT_DEFAULT_MAX_TOKENS: int = 2000
JIT_DEFAULT_RULE_COUNT_BUDGET: int = 3
WORDS_TO_TOKENS_FACTOR: float = 1.35
CHARS_PER_TOKEN_ESTIMATE: int = 4

__all__ = [
    "ReviewMode",
    "REVIEW_MODE_RANKS",
    "REVIEW_MODES",
    "ESCALATION_PROTOCOLS",
    "ESCALATING_PROTOCOLS",
    "LEGACY_REVIEW_MODE_ALIASES",
    "normalize_review_mode",
    "ReviewProng",
    "REVIEW_PRONGS",
    "LEGACY_REVIEW_PRONG_ALIASES",
    "GenesisStage",
    "GENESIS_STAGES",
    "RuleType",
    "CANONICAL_RULE_TYPES",
    "RULE_TYPE_DIRS",
    "DIR_RULE_TYPES",
    "RULE_TYPES",
    "RuleTypeSpec",
    "LEGACY_TYPE_NAMES",
    "legacy_rule_type",
    "LOCK_TIMEOUT_SECONDS",
    "LOCK_RETRY_INTERVAL_SECONDS",
    "LOCK_MAX_BACKOFF_SECONDS",
    "STORAGE_MAX_RETRIES",
    "STORAGE_INITIAL_DELAY_SECONDS",
    "AST_RUNNER_TIMEOUT_SECONDS",
    "SUBPROCESS_DEFAULT_TIMEOUT_SECONDS",
    "VERIFY_RUNNER_TIMEOUT_SECONDS",
    "MCP_DEFAULT_RATE_LIMITS",
    "WILSON_CONFIDENCE_Z_SCORES",
    "DEFAULT_CONFIDENCE_LEVEL",
    "JIT_DEFAULT_MAX_TOKENS",
    "JIT_DEFAULT_RULE_COUNT_BUDGET",
    "WORDS_TO_TOKENS_FACTOR",
    "CHARS_PER_TOKEN_ESTIMATE",
]

