from pathlib import Path
"""TDD tests for immune_verify.py — AUDITED ground truth.

Audit findings applied:
- test_includes_docstrings: was TAUTOLOGICAL, now checks docstring content only
- test_spec_prompt_has_no_implementation: strengthened positive assertions
- test_code_prompt_has_no_plan: removed vacuous disjunction
- test_spec/code_prompt_forces_schema: checks ALL required schema keys + all categories
- test_parse_predictions/claims: checks ALL fields, not just category
- Added missing test_full_pipeline_produces_arbitration_result
"""
import sys
import textwrap

import pytest

REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
sys.path.insert(0, REPO_ROOT)

from aegis_core.verification import (
    RiskCategory,
    Severity,
    ArbitrationResult,
    Verdict,
    ToolEvidence,
)


class TestSignatureExtractor:
    """Contract: extract_signatures returns def lines without bodies."""

    def test_extracts_function_names(self, tmp_path):
        from aegis_core.verification.adversarial_verify import extract_signatures

        src = tmp_path / "target.py"
        src.write_text(textwrap.dedent("""\
            def apply_decay(meta, session_id=None):
                \"\"\"Decay fitness data.\"\"\"
                fitness = meta.get('fitness', {})
                fitness['triggers'] = max(1, int(fitness['triggers'] * 0.95))
                return meta

            def normalize_fitness(metadata):
                fitness = metadata.get('fitness')
                if isinstance(fitness, dict):
                    return fitness
                return {'score': float(fitness) if fitness else 0.5}
        """))

        sigs = extract_signatures(str(src))
        assert len(sigs) == 2
        assert any("apply_decay" in s for s in sigs)
        assert any("normalize_fitness" in s for s in sigs)

    def test_signatures_do_not_contain_bodies(self, tmp_path):
        """Signatures must NOT leak implementation details."""
        from aegis_core.verification.adversarial_verify import extract_signatures

        src = tmp_path / "target.py"
        src.write_text(textwrap.dedent("""\
            def secret_algorithm(data):
                # This implementation detail must not leak
                result = data['x'] * 42 + data['y'] ** 2
                return result
        """))

        sigs = extract_signatures(str(src))
        sig_text = ' '.join(sigs)
        assert "42" not in sig_text, "Implementation constants must not leak"
        assert "**" not in sig_text, "Implementation operators must not leak"
        assert "secret_algorithm" in sig_text

    def test_includes_argument_names(self, tmp_path):
        """Signatures should include parameter names for context."""
        from aegis_core.verification.adversarial_verify import extract_signatures

        src = tmp_path / "target.py"
        src.write_text(textwrap.dedent("""\
            def score(tp, triggers, impact_weight=1.0):
                return (tp + 1) / (triggers + 2) * impact_weight
        """))

        sigs = extract_signatures(str(src))
        sig = sigs[0]
        assert "tp" in sig
        assert "triggers" in sig
        assert "impact_weight" in sig

    def test_includes_docstrings(self, tmp_path):
        """Signatures must include docstrings (they're part of the contract)."""
        from aegis_core.verification.adversarial_verify import extract_signatures

        src = tmp_path / "target.py"
        src.write_text(textwrap.dedent("""\
            def validate(data):
                \"\"\"Check data integrity before processing.\"\"\"
                return bool(data)
        """))

        sigs = extract_signatures(str(src))
        sig = sigs[0]
        # Must include the actual docstring content, not just the function name
        assert "Check data integrity before processing." in sig


class TestInformationPartitioning:
    """Contract: the two agents must NOT see each other's information."""

    def test_spec_prompt_has_no_implementation(self):
        """Spec prompt must contain plan and signatures, NOT code bodies."""
        from aegis_core.verification.adversarial_verify import build_spec_prompt

        plan = "Implement idempotent decay with last_decay_epoch guard"
        signatures = ["def apply_decay(meta, session_id=None):"]
        test_names = ["test_decay_idempotent", "test_decay_applies_after_gap"]

        prompt = build_spec_prompt(plan, signatures, test_names)
        # Positive: must contain plan info
        assert plan in prompt
        assert "apply_decay" in prompt
        assert "test_decay_idempotent" in prompt
        # Positive: must contain schema instructions
        assert "category" in prompt.lower()
        # Structure: must NOT contain any code-like patterns
        assert "fitness[" not in prompt
        assert "import " not in prompt or "import" in plan.lower()

    def test_code_prompt_has_no_plan(self):
        """Code prompt must contain implementation, NOT the plan or spec."""
        from aegis_core.verification.adversarial_verify import build_code_prompt

        implementation = "fitness['last_decay_epoch'] = int(time.time())"
        test_results = "test_decay: PASSED"
        layer1_output = {"persistence_checker": "PASS"}

        prompt = build_code_prompt(implementation, test_results, layer1_output)
        assert implementation in prompt
        assert "PASSED" in prompt
        assert "persistence_checker" in prompt

    def test_spec_prompt_forces_prediction_schema(self):
        """Spec prompt must include ALL required schema fields and ALL risk categories."""
        from aegis_core.verification.adversarial_verify import build_spec_prompt

        prompt = build_spec_prompt("plan", ["def f():"], ["test_f"])
        # Must reference all required schema keys
        for key in ["category", "severity", "risk", "mechanism", "affected_function"]:
            assert key in prompt, f"Missing required schema key: {key}"
        # Must include all risk categories so the agent knows the full taxonomy
        missing_cats = [c.value for c in RiskCategory if c.value not in prompt]
        assert not missing_cats, f"Prompt missing RiskCategory values: {missing_cats}"

    def test_code_prompt_forces_claim_schema(self):
        """Code prompt must include ALL required claim schema fields and ALL risk categories."""
        from aegis_core.verification.adversarial_verify import build_code_prompt

        prompt = build_code_prompt("code", "results", {})
        for key in ["category", "claim", "evidence_file", "evidence_line"]:
            assert key in prompt, f"Missing required schema key: {key}"
        missing_cats = [c.value for c in RiskCategory if c.value not in prompt]
        assert not missing_cats, f"Prompt missing RiskCategory values: {missing_cats}"


class TestParsing:
    """Contract: parse agent outputs into typed Prediction/Claim objects."""

    def test_parse_predictions_all_fields(self):
        """Parse must populate ALL fields of the Prediction dataclass."""
        from aegis_core.verification.adversarial_verify import parse_predictions

        raw = [
            {
                "category": "persistence_gap",
                "severity": "critical",
                "risk": "Epoch not persisted",
                "mechanism": "In-memory only",
                "affected_function": "apply_decay",
            }
        ]

        predictions, dropped = parse_predictions(raw)
        assert (len(predictions), dropped) == (1, 0)
        p = predictions[0]
        assert p.category == RiskCategory.PERSISTENCE_GAP
        assert p.severity == Severity.CRITICAL
        assert p.risk == "Epoch not persisted"
        assert p.mechanism == "In-memory only"
        assert p.affected_function == "apply_decay"

    def test_parse_claims_all_fields(self):
        """Parse must populate ALL fields of the Claim dataclass."""
        from aegis_core.verification.adversarial_verify import parse_claims

        raw = [
            {
                "category": "persistence_gap",
                "claim": "Epoch persisted at L217",
                "evidence_file": "cell_promote.py",
                "evidence_line": 217,
                "tests_covering": ["test_idempotent"],
            }
        ]

        claims, dropped = parse_claims(raw)
        assert (len(claims), dropped) == (1, 0)
        c = claims[0]
        assert c.category == RiskCategory.PERSISTENCE_GAP
        assert c.claim == "Epoch persisted at L217"
        assert c.evidence_file == "cell_promote.py"
        assert c.evidence_line == 217
        assert c.tests_covering == ["test_idempotent"]

    def test_parse_skips_and_counts_invalid_categories(self):
        """Unknown categories are skipped, not crashed on, and counted (R-checks-44)."""
        from aegis_core.verification.adversarial_verify import parse_predictions

        raw = [
            {
                "category": "nonexistent_category",
                "severity": "low",
                "risk": "Unknown",
                "mechanism": "Unknown",
                "affected_function": "f",
            }
        ]

        assert parse_predictions(raw) == ([], 1)

    @pytest.mark.parametrize("entry", ["not an object", 3, None, ["category"], {"severity": "low"}],
                             ids=["str", "int", "null", "list", "no-category"])
    def test_an_entry_that_is_not_a_usable_object_is_dropped_and_counted(self, entry):
        """The reply is any JSON the model chose: a bad entry is a dropped entry, never a crash."""
        from aegis_core.verification.adversarial_verify import parse_claims, parse_predictions

        good = {"category": "overflow", "severity": "low", "risk": "r", "mechanism": "m", "affected_function": "f"}
        predictions, dropped = parse_predictions([entry, good])
        assert ([p.category for p in predictions], dropped) == ([RiskCategory.OVERFLOW], 1)
        claim = {"category": "overflow", "claim": "c", "evidence_file": "f.py", "evidence_line": 1}
        claims, dropped = parse_claims([claim, entry])
        assert (len(claims), dropped) == (1, 1)


class TestEndToEnd:
    """Contract: full pipeline produces ArbitrationResult."""

    def test_full_pipeline_produces_arbitration_result(self):
        """Providing sample predictions + claims + evidence must produce ArbitrationResult."""
        from aegis_core.verification.adversarial_verify import parse_predictions, parse_claims
        from aegis_core.verification.arbiter import arbitrate

        raw_preds = [
            {
                "category": "persistence_gap",
                "severity": "critical",
                "risk": "Epoch might not persist",
                "mechanism": "In-memory only guard",
                "affected_function": "apply_decay",
            }
        ]
        raw_claims = [
            {
                "category": "persistence_gap",
                "claim": "Epoch persisted at L217",
                "evidence_file": "cell_promote.py",
                "evidence_line": 217,
                "tests_covering": ["test_idempotent"],
            }
        ]
        evidence = [
            ToolEvidence("persistence_checker", "cell_promote.py:fitness",
                         True, "All keys serialized"),
        ]

        predictions, _ = parse_predictions(raw_preds)
        claims, _ = parse_claims(raw_claims)
        result = arbitrate(predictions, claims, evidence)

        assert isinstance(result, ArbitrationResult)
        assert result.verdict == Verdict.SHIP
        assert RiskCategory.PERSISTENCE_GAP in result.convergences
        assert len(result.divergences) == 0
