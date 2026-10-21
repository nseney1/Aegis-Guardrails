from pathlib import Path
"""TDD tests for the two-layer verification framework.

Uses v0.30 bugs as ground truth:
- last_decay_epoch persistence gap
- Dead NEW/DORMANT branches
- Tautological Bayesian tests
- Unwired apply_decay in --local

Each test constructs the exact predictions/claims/evidence that
our agents would have produced, then verifies the Arbiter catches it.
"""
import sys


REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
sys.path.insert(0, REPO_ROOT)

from aegis_core.verification import Claim, Prediction, RiskCategory, Severity, ToolEvidence, Verdict
from aegis_core.verification.arbiter import arbitrate


# ── Arbiter: Core Set Logic ───────────────────────────────────────────────

class TestArbiterSetLogic:
    """Verify the Arbiter produces correct divergences from set operations."""

    def test_full_convergence_ships(self):
        """When predictions match claims and Layer 1 passes → SHIP."""
        predictions = [
            Prediction(RiskCategory.PERSISTENCE_GAP, Severity.CRITICAL,
                       "Epoch might not persist", "In-memory only", "apply_decay")
        ]
        claims = [
            Claim(RiskCategory.PERSISTENCE_GAP,
                  "Epoch persisted via frontmatter writer",
                  "cell_promote.py", 217, ["test_idempotent"])
        ]
        evidence = [
            ToolEvidence("persistence_checker", "cell_promote.py:fitness",
                         True, "All keys serialized")
        ]

        result = arbitrate(predictions, claims, evidence)
        assert result.verdict == Verdict.SHIP
        assert RiskCategory.PERSISTENCE_GAP in result.convergences
        assert len(result.divergences) == 0

    def test_unmatched_prediction_warns(self):
        """Spec Agent predicts a risk Code Agent didn't address → REVISE."""
        predictions = [
            Prediction(RiskCategory.IDEMPOTENCY_VIOLATION, Severity.HIGH,
                       "Decay could apply twice", "No epoch guard", "apply_decay")
        ]
        claims = []  # Code Agent didn't address this
        evidence = []

        result = arbitrate(predictions, claims, evidence)
        assert result.verdict == Verdict.REVISE
        assert len(result.divergences) == 1
        assert result.divergences[0].divergence_type == "unmatched_prediction"

    def test_contradicted_claim_blocks(self):
        """Code Agent claims X, Layer 1 says ¬X → BLOCK."""
        predictions = []
        claims = [
            Claim(RiskCategory.PERSISTENCE_GAP,
                  "All fitness keys are persisted",
                  "cell_promote.py", 215, [])
        ]
        evidence = [
            ToolEvidence("persistence_checker", "cell_promote.py:fitness",
                         False, "last_decay_epoch mutated but never serialized",
                         [42, 56])
        ]

        result = arbitrate(predictions, claims, evidence)
        assert result.verdict == Verdict.BLOCK
        assert len(result.divergences) == 1
        assert result.divergences[0].divergence_type == "contradicted_claim"

    def test_confirmed_risk_blocks(self):
        """Both agents address a risk but Layer 1 confirms it's real → BLOCK."""
        predictions = [
            Prediction(RiskCategory.PERSISTENCE_GAP, Severity.CRITICAL,
                       "Epoch not persisted across CLI runs",
                       "In-memory guard bypassed on restart", "apply_decay")
        ]
        claims = [
            Claim(RiskCategory.PERSISTENCE_GAP,
                  "Epoch persisted via last_decay_epoch field",
                  "cell_promote.py", 35, ["test_consecutive_decay_is_noop"])
        ]
        evidence = [
            ToolEvidence("persistence_checker", "cell_promote.py:fitness",
                         False, "last_decay_epoch mutated at L42,56 but not serialized",
                         [42, 56])
        ]

        result = arbitrate(predictions, claims, evidence)
        assert result.verdict == Verdict.BLOCK
        assert len(result.divergences) == 1
        assert result.divergences[0].divergence_type == "confirmed_risk"
        assert result.divergences[0].tool_evidence is not None

    def test_undetected_by_both_blocks(self):
        """Neither agent caught it but Layer 1 did → BLOCK with 'undetected_by_both'."""
        predictions = []
        claims = []
        evidence = [
            ToolEvidence("persistence_checker", "cell_promote.py:fitness",
                         False, "last_decay_epoch gap", [42])
        ]

        result = arbitrate(predictions, claims, evidence)
        assert result.verdict == Verdict.BLOCK
        assert any(d.divergence_type == "undetected_by_both" for d in result.divergences)

    def test_low_severity_unmatched_ships(self):
        """Low-severity unmatched prediction should not block shipping."""
        predictions = [
            Prediction(RiskCategory.OVERFLOW, Severity.LOW,
                       "Possible overflow in trigger count", "Unlikely", "apply_decay")
        ]
        claims = []
        evidence = []

        result = arbitrate(predictions, claims, evidence)
        assert result.verdict == Verdict.SHIP

    def test_multiple_categories_mixed(self):
        """Multiple categories: some converge, some diverge."""
        predictions = [
            Prediction(RiskCategory.PERSISTENCE_GAP, Severity.CRITICAL,
                       "Epoch gap", "In-memory only", "apply_decay"),
            Prediction(RiskCategory.UNGUARDED_TRANSITION, Severity.HIGH,
                       "Zero-trigger promotion", "impact_weight inflation", "promote"),
        ]
        claims = [
            Claim(RiskCategory.PERSISTENCE_GAP,
                  "Epoch persisted", "cell_promote.py", 217, []),
            Claim(RiskCategory.UNGUARDED_TRANSITION,
                  "Triggers > 0 guard", "cell_fitness.py", 278, []),
        ]
        evidence = [
            ToolEvidence("persistence_checker", "cell_promote.py:fitness",
                         True, "All keys serialized"),
        ]

        result = arbitrate(predictions, claims, evidence)
        assert result.verdict == Verdict.SHIP
        assert RiskCategory.PERSISTENCE_GAP in result.convergences
        assert RiskCategory.UNGUARDED_TRANSITION in result.convergences


# ── Arbiter: v0.30 Ground Truth ───────────────────────────────────────────

class TestArbiterV030GroundTruth:
    """Replay the actual v0.30 bugs through the Arbiter and verify detection."""

    def test_epoch_bug_detected(self):
        """The epoch persistence bug (pre-fix) should produce BLOCK verdict."""
        # What the Spec Agent would predict from plan alone
        predictions = [
            Prediction(RiskCategory.PERSISTENCE_GAP, Severity.CRITICAL,
                       "last_decay_epoch might not survive process restart",
                       "apply_decay sets fitness['last_decay_epoch'] in memory, "
                       "but frontmatter writer only handles triggers/tp/fp/score",
                       "apply_decay"),
        ]
        # What the Code Agent would claim from reading the code
        claims = [
            Claim(RiskCategory.PERSISTENCE_GAP,
                  "Decay is idempotent via last_decay_epoch check at L31-35",
                  "enzymes/cell_promote.py", 35,
                  ["test_consecutive_decay_is_noop", "test_decay_applies_after_gap"]),
        ]
        # What the persistence_checker would produce (pre-fix)
        evidence = [
            ToolEvidence("persistence_checker", "cell_promote.py:fitness",
                         False,
                         "PERSISTENCE GAP: last_decay_epoch assigned at L42,56 "
                         "but no startswith('last_decay_epoch:') in serializer",
                         [42, 56]),
        ]

        result = arbitrate(predictions, claims, evidence)
        assert result.verdict == Verdict.BLOCK
        assert result.divergences[0].divergence_type == "confirmed_risk"
        assert result.divergences[0].prediction.category == RiskCategory.PERSISTENCE_GAP

    def test_dead_code_prediction_without_layer1_evidence_revises(self):
        """No Layer 1 tool adjudicates DEAD_CODE (branch_coverage is cut, #38): an
        undefended high-severity prediction can only REVISE, not BLOCK."""
        predictions = [
            Prediction(RiskCategory.DEAD_CODE, Severity.HIGH,
                       "NEW/DORMANT status might be unreachable",
                       "If dec_score is always not-None for zero-trigger cells, "
                       "the else branch at L189 is dead code",
                       "classify_status"),
        ]
        result = arbitrate(predictions, [], [ToolEvidence("call_graph", "cell_fitness.py", True, "wired")])
        assert result.verdict == Verdict.REVISE
        assert [d.divergence_type for d in result.divergences] == ["unmatched_prediction"]
        assert result.divergences[0].tool_evidence is None

    def test_post_fix_all_clear(self):
        """After all v0.30 fixes, the Arbiter should produce SHIP."""
        predictions = [
            Prediction(RiskCategory.PERSISTENCE_GAP, Severity.CRITICAL,
                       "Epoch persistence", "Could fail across processes", "apply_decay"),
            Prediction(RiskCategory.DEAD_CODE, Severity.HIGH,
                       "NEW/DORMANT reachability", "Could be dead", "classify_status"),
            Prediction(RiskCategory.UNGUARDED_TRANSITION, Severity.HIGH,
                       "Zero-trigger promotion", "impact_weight", "promote"),
        ]
        claims = [
            Claim(RiskCategory.PERSISTENCE_GAP,
                  "Epoch persisted at L217", "cell_promote.py", 217, ["test_idempotent"]),
            Claim(RiskCategory.DEAD_CODE,
                  "is_unobserved guard at L182", "cell_fitness.py", 182, ["test_new_status"]),
            Claim(RiskCategory.UNGUARDED_TRANSITION,
                  "triggers > 0 guard at L278", "cell_fitness.py", 278, ["test_promote"]),
        ]
        evidence = [
            ToolEvidence("persistence_checker", "cell_promote.py:fitness",
                         True, "All 5 keys serialized"),
        ]

        result = arbitrate(predictions, claims, evidence)
        assert result.verdict == Verdict.SHIP
        assert len(result.convergences) == 3


# ── Report Formatting ─────────────────────────────────────────────────────

# ── Arbiter: Fail-Closed on Spec Agent Failure ────────────────────────────

class TestArbiterFailClosed:
    """A Spec Agent failure is reported as unverified, never as a BLOCK (T6 is log-only)."""

    def test_spec_agent_failed_empty_predictions_is_unverified(self):
        """When spec_agent_failed=True and predictions are empty → unverified, not BLOCK."""
        result = arbitrate(
            predictions=[],
            claims=[],
            layer1_evidence=[
                ToolEvidence("persistence_checker", "test", True, "OK"),
            ],
            spec_agent_failed=True,
        )
        assert result.verdict != Verdict.BLOCK
        assert result.infra_status == "unverified"

    def test_spec_agent_not_failed_empty_predictions_ships(self):
        """Default spec_agent_failed=False with no predictions → SHIP (existing behavior)."""
        result = arbitrate(
            predictions=[],
            claims=[],
            layer1_evidence=[
                ToolEvidence("persistence_checker", "test", True, "OK"),
            ],
        )
        assert result.verdict == Verdict.SHIP

    def test_spec_agent_failed_false_explicit_ships(self):
        """Explicit spec_agent_failed=False with no predictions → SHIP."""
        result = arbitrate(
            predictions=[],
            claims=[],
            layer1_evidence=[],
            spec_agent_failed=False,
        )
        assert result.verdict == Verdict.SHIP



# ── Arbiter: a review that did not happen never reads as clean (R-checks-44) ──

class TestUnverifiedReasons:
    """Every structural hole yields infra_status 'unverified' with a named reason."""

    PASSING = [ToolEvidence("call_graph", "mod.py", True, "ok")]
    LOW = Prediction(RiskCategory.OVERFLOW, Severity.LOW, "overflow", "big input", "f")

    @staticmethod
    def _gaps(**kw):
        from aegis_core.verification import ReviewGaps

        return ReviewGaps(**{"reviewed_files": ("mod.py",), **kw})

    def test_a_complete_review_is_ok_with_no_reasons(self):
        result = arbitrate([self.LOW], [], self.PASSING, gaps=self._gaps())
        assert (result.infra_status, result.unverified_reasons) == ("ok", ())
        assert result.verdict == Verdict.SHIP

    def test_no_predictions_is_unverified_and_never_block(self):
        result = arbitrate([], [], self.PASSING, gaps=self._gaps())
        assert result.infra_status == "unverified"
        assert result.unverified_reasons == ("no_predictions",)
        assert result.verdict != Verdict.BLOCK

    def test_each_hole_is_named(self):
        gaps = self._gaps(reviewed_files=(), skipped_files=(("tests/test_a.py", "test"), ("README.md", "not_python")),
                          dropped_entries=2, code_agent_failed=True)
        result = arbitrate([], [], self.PASSING, spec_agent_failed=True, gaps=gaps)
        assert result.unverified_reasons == (
            "spec_agent_unparseable", "code_agent_unparseable", "no_predictions", "no_reviewed_files",
            "skipped:2", "unknown_category:2",
        )

    def test_by_design_exclusions_beside_a_reviewed_file_add_no_reason(self):
        gaps = self._gaps(skipped_files=(("tests/test_mod.py", "test"), ("README.md", "not_python")))
        assert arbitrate([self.LOW], [], self.PASSING, gaps=gaps).unverified_reasons == ()

    def test_a_file_that_failed_to_load_is_always_named(self):
        gaps = self._gaps(skipped_files=(("broken.py", "error"), ("README.md", "not_python")))
        result = arbitrate([self.LOW], [], self.PASSING, gaps=gaps)
        assert (result.infra_status, result.unverified_reasons) == ("unverified", ("skipped:2",))

    def test_without_gaps_a_library_caller_keeps_ok(self):
        result = arbitrate([self.LOW], [], self.PASSING)
        assert (result.infra_status, result.unverified_reasons) == ("ok", ())

    def test_an_infrastructure_hole_with_failing_layer1_still_blocks_on_layer1(self):
        failing = [ToolEvidence("call_graph", "mod.py", False, "unwired")]
        result = arbitrate([], [], failing, gaps=self._gaps(reviewed_files=()))
        assert result.verdict == Verdict.BLOCK
        assert result.unverified_reasons == ("no_predictions", "no_reviewed_files")
