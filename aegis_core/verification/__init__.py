"""Verification framework shared types and risk taxonomy.

The taxonomy is the anti-collusion mechanism. Both the Spec Agent and Code Agent
must classify findings into these enumerated categories. The Arbiter then performs
pure set operations — no LLM judgment needed for comparison.
"""
from dataclasses import dataclass, field
from enum import Enum
import hashlib
from typing import Any, Optional


class RiskCategory(Enum):
    """Fixed taxonomy of risk categories.

    Both agents MUST select from this list. This is what makes the Arbiter
    deterministic — it compares enum values, not natural language.
    """
    # Structural
    PERSISTENCE_GAP = "persistence_gap"          # State mutated but not serialized
    DEAD_CODE = "dead_code"                      # Unreachable branches
    MISSING_WIRE = "missing_wire"                # Function defined but not called from entry point

    # State
    IDEMPOTENCY_VIOLATION = "idempotency"        # Repeated calls produce different results
    RACE_CONDITION = "race_condition"             # TOCTOU or concurrent mutation
    STATE_CORRUPTION = "state_corruption"        # Valid input produces invalid state

    # Contracts
    UNGUARDED_TRANSITION = "unguarded_transition" # State promotion/demotion without prerequisite
    CONTRACT_DRIFT = "contract_drift"             # Signature changed but callers not updated
    TYPE_MISMATCH = "type_mismatch"              # Returns unexpected type (None vs float, inf vs int)

    # Data
    BOUNDARY_VIOLATION = "boundary_violation"     # Cross-module dependency that shouldn't exist
    DIVISION_BY_ZERO = "division_by_zero"        # Unguarded division
    OVERFLOW = "overflow"                        # Numeric overflow or underflow

    # Testing
    TAUTOLOGICAL_TEST = "tautological_test"      # Test that passes regardless of implementation
    MISSING_COVERAGE = "missing_coverage"        # Changed code not exercised by any test

    # Security (added for Citadel review)
    CODE_INJECTION = "code_injection"            # Untrusted input in exec/eval/format
    PATH_TRAVERSAL = "path_traversal"            # User paths escape containment root
    SHELL_INJECTION = "shell_injection"          # subprocess shell=True with user input

    # Quality
    DRY_VIOLATION = "dry_violation"              # Copy-pasted logic across modules
    DOC_DRIFT = "doc_drift"                      # Documentation diverges from implementation
    CONVENTION_VIOLATION = "convention_violation" # Schema/naming doesn't match existing instances

    # Portability
    PLATFORM_INCOMPATIBLE = "platform_incompatible"  # Code fails on non-host OS


class Severity(Enum):
    CRITICAL = "critical"    # Ship blocker
    HIGH = "high"            # Should fix before ship
    MEDIUM = "medium"        # Track for next release
    LOW = "low"              # Informational


class Verdict(Enum):
    SHIP = "ship"
    BLOCK = "block"
    REVISE = "revise"


@dataclass
class Prediction:
    """Spec Agent output: what COULD go wrong (from spec + signatures only)."""
    category: RiskCategory = RiskCategory.PERSISTENCE_GAP
    severity: Severity = Severity.MEDIUM
    risk: str = ""               # One-line description
    mechanism: str = ""          # How the bug would manifest
    affected_function: str = ""  # Function name (from signatures)
    id: str = ""
    verdict_id: str = ""
    ts: float = 0.0
    tree: str = ""
    backend: str = ""
    scope: str = ""
    observable: str = "fix_touch_in_window"
    window_days: int = 14
    p: float = 0.5
    disposition: str = "logged"
    outcome: Optional[bool] = None
    resolved_at: Optional[float] = None
    resolving_commit: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.category, str):
            try:
                self.category = RiskCategory(self.category)
            except ValueError:
                pass
        if isinstance(self.severity, str):
            try:
                self.severity = Severity(self.severity)
            except ValueError:
                pass
        self.scope = self.scope or self.affected_function
        if not self.id:
            cat_val = getattr(self.category, "value", str(self.category))
            self.id = hashlib.sha256(f"{self.verdict_id}:{cat_val}:{self.scope}:{self.risk}".encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "verdict_id": self.verdict_id, "ts": self.ts, "tree": self.tree, "backend": self.backend,
            "scope": self.scope, "observable": self.observable, "window_days": self.window_days, "p": self.p,
            "disposition": self.disposition, "outcome": self.outcome, "resolved_at": self.resolved_at,
            "resolving_commit": self.resolving_commit, "category": getattr(self.category, "value", str(self.category)),
            "severity": getattr(self.severity, "value", str(self.severity)), "risk": self.risk,
            "mechanism": self.mechanism, "affected_function": self.affected_function,
        }


@dataclass
class Claim:
    """Code Agent output: what the code ACTUALLY does (from implementation only)."""
    category: RiskCategory
    claim: str              # One-line description
    evidence_file: str      # file:line citation
    evidence_line: int
    tests_covering: list[str] = field(default_factory=list)


@dataclass
class ToolEvidence:
    """Layer 1 tool output: deterministic boolean result."""
    tool: str               # Tool name
    target: str             # What was checked
    verdict: bool           # PASS=True, FAIL=False
    detail: str             # Human-readable detail
    lines: list[int] = field(default_factory=list)  # Relevant line numbers


@dataclass
class Divergence:
    """Arbiter output: a mismatch between predictions, claims, and evidence."""
    divergence_type: str    # "unmatched_prediction", "contradicted_claim", "confirmed_risk"
    category: RiskCategory
    prediction: Optional[Prediction] = None
    claim: Optional[Claim] = None
    tool_evidence: Optional[ToolEvidence] = None
    resolution: str = ""


@dataclass(frozen=True)
class ReviewGaps:
    """What a Layer 2 run left out: ``skipped_files`` as ``(path, why)``, ``why`` in test, init,
    not_python, deleted, error; ``dropped_entries`` from both replies (no known category)."""
    reviewed_files: tuple[str, ...] = ()
    skipped_files: tuple[tuple[str, str], ...] = ()
    dropped_entries: int = 0
    code_agent_failed: bool = False


@dataclass
class ArbitrationResult:
    """Final output of the two-layer verification."""
    divergences: list[Divergence] = field(default_factory=list)
    convergences: list[RiskCategory] = field(default_factory=list)   # Categories where prediction + claim + evidence align
    verdict: Verdict = Verdict.SHIP
    layer1_results: list[ToolEvidence] = field(default_factory=list)
    predictions: list[Prediction] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    layer1_verdict: str = ""
    infra_status: str = "ok"
    llm_predictions: tuple[Prediction, ...] = ()
    verdict_id: str = ""
    unverified_reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.layer1_verdict:
            self.layer1_verdict = "FAIL" if any(not e.verdict for e in self.layer1_results) else "PASS"
        if not self.verdict_id:
            raw = f"{self.layer1_verdict}:{self.verdict.value.upper()}:{len(self.predictions)}:{len(self.divergences)}"
            self.verdict_id = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


# ── Structured Output Schemas (for agent prompts) ─────────────────────────

PREDICTION_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["category", "severity", "risk", "mechanism", "affected_function"],
        "properties": {
            "category": {
                "type": "string",
                "enum": [c.value for c in RiskCategory],
                "description": "Risk category from the fixed taxonomy"
            },
            "severity": {
                "type": "string",
                "enum": [s.value for s in Severity]
            },
            "risk": {
                "type": "string",
                "description": "One-line description of what could go wrong"
            },
            "mechanism": {
                "type": "string",
                "description": "How the bug would manifest at runtime"
            },
            "affected_function": {
                "type": "string",
                "description": "Function name from the provided signatures"
            }
        }
    }
}

CLAIM_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["category", "claim", "evidence_file", "evidence_line"],
        "properties": {
            "category": {
                "type": "string",
                "enum": [c.value for c in RiskCategory],
                "description": "Category of correctness this claim addresses"
            },
            "claim": {
                "type": "string",
                "description": "One-line claim about what the code does"
            },
            "evidence_file": {
                "type": "string",
                "description": "File path containing the evidence"
            },
            "evidence_line": {
                "type": "integer",
                "description": "Line number of the evidence"
            },
            "tests_covering": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Test function names that verify this claim"
            }
        }
    }
}


__all__ = [
    "CLAIM_SCHEMA",
    "PREDICTION_SCHEMA",
    "ArbitrationResult",
    "Claim",
    "Divergence",
    "Prediction",
    "ReviewGaps",
    "RiskCategory",
    "Severity",
    "ToolEvidence",
    "Verdict",
]
