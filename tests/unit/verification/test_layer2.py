"""Layer 2 orchestration through VerificationPipeline (ported from run_layer2, #31).

The pipeline wires together:
- Signature extraction (adversarial_verify.extract_signatures)
- Information-partitioned prompt construction (build_spec_prompt, build_code_prompt)
- The Layer 2 backend for the Spec Agent and the Code Agent
- Structured output parsing (parse_predictions, parse_claims), fenced JSON included
- Deterministic arbitration (arbiter.arbitrate)

Tests verify:
1. A backend is required: none is an error, never a silent skip
2. Prompt structure and information partitioning are strictly maintained (AEGIS-V01)
3. Empty predictions/claims -> SHIP; contradicted or confirmed risks -> BLOCK
4. Unmatched high-severity predictions -> REVISE; a Layer 1 failure alone -> BLOCK
5. Edge cases: markdown-fenced JSON, multiple changed files, no changed files
   (Layer 2 is not run), non-Python files, and custom test names/results.
"""
import json
import textwrap

import pytest

from aegis_core.inference_provider import MISSING_BACKEND
from aegis_core.verification import ArbitrationResult, RiskCategory, ToolEvidence, Verdict
from aegis_core.verification.pipeline import VerificationPipeline


def _layer2(changed_files, repo_root, task_plan, layer1_evidence, llm_backend, test_names=None, test_results=None):
    """The v3 run_layer2 call shape, mapped onto VerificationPipeline.run (#31)."""
    return VerificationPipeline().run(
        changed_files=changed_files,
        workspace=repo_root,
        task_plan=task_plan,
        backend=llm_backend,
        layer1_evidence=layer1_evidence,
        test_names=test_names,
        test_results=test_results,
    ).arbitration_result


class TestBackendRequired:
    def test_missing_backend_raises(self, tmp_path):
        (tmp_path / "mod.py").write_text("def f():\n    return 1\n", encoding="utf-8")
        with pytest.raises(ValueError, match=MISSING_BACKEND):
            _layer2(["mod.py"], str(tmp_path), "Implement feature", [], llm_backend=None)


class TestInformationPartitioningAndPromptDispatch:
    """Verify information partitioning between Spec Agent and Code Agent prompts."""

    def test_llm_backend_receives_correct_prompt_structure(self, tmp_path):
        """LLM backend must receive correctly partitioned prompts:
        - Spec Agent prompt contains plan, signatures, docstrings, but NO implementation bodies.
        - Code Agent prompt contains implementation source, Layer 1 output, but NO task plan.
        """
        code = textwrap.dedent('''\
            def calculate_risk(score, factor=1.5):
                """Calculate overall system risk score."""
                internal_multiplier = 42
                tax_rate = 0.05
                return score * factor * internal_multiplier * (1 + tax_rate)

            def commit_transaction(tx_id):
                """Commit transaction to database."""
                raw_sql = f"INSERT INTO transactions VALUES ({tx_id})"
                return bool(raw_sql)
        ''')
        source_file = tmp_path / "engine.py"
        source_file.write_text(code)

        recorded_prompts = []

        def recording_llm(prompt: str) -> str:
            recorded_prompts.append(prompt)
            if "Spec Agent" in prompt:
                return json.dumps([])
            elif "Code Agent" in prompt:
                return json.dumps([])
            return json.dumps([])

        plan = "Add secure risk calculation and transaction commit routines"
        evidence = [
            ToolEvidence("persistence_checker", "engine.py", True, "All state persisted")
        ]

        result = _layer2(
            changed_files=["engine.py"],
            repo_root=str(tmp_path),
            task_plan=plan,
            layer1_evidence=evidence,
            llm_backend=recording_llm,
        )

        assert len(recorded_prompts) == 2, (
            f"Expected exactly 2 prompts dispatched to LLM backend, got {len(recorded_prompts)}"
        )

        spec_prompt = next((p for p in recorded_prompts if "Spec Agent" in p), None)
        code_prompt = next((p for p in recorded_prompts if "Code Agent" in p), None)

        assert spec_prompt is not None, "Spec Agent prompt was not dispatched to LLM backend"
        assert code_prompt is not None, "Code Agent prompt was not dispatched to LLM backend"

        # --- Spec Agent Prompt Verification ---
        assert plan in spec_prompt, "Spec prompt must contain the task plan"
        assert "calculate_risk" in spec_prompt, "Spec prompt must contain function signature"
        assert "commit_transaction" in spec_prompt, "Spec prompt must contain function signature"
        assert "Calculate overall system risk score." in spec_prompt, (
            "Spec prompt must include function docstrings"
        )
        # Spec Agent must NEVER see implementation code
        assert "internal_multiplier = 42" not in spec_prompt, (
            "Spec prompt must NOT leak implementation bodies"
        )
        assert "tax_rate = 0.05" not in spec_prompt, (
            "Spec prompt must NOT leak implementation constants"
        )
        assert "raw_sql" not in spec_prompt, (
            "Spec prompt must NOT leak implementation variables"
        )

        # --- Code Agent Prompt Verification ---
        assert "internal_multiplier = 42" in code_prompt, (
            "Code prompt must contain implementation source"
        )
        assert "raw_sql" in code_prompt, (
            "Code prompt must contain implementation source"
        )
        assert "persistence_checker" in code_prompt, (
            "Code prompt must include Layer 1 evidence output"
        )
        # Code Agent must NEVER see the task plan
        assert plan not in code_prompt, (
            "Code prompt must NOT leak the task plan"
        )

        assert isinstance(result, ArbitrationResult)


class TestLayer2ArbitrationVerdicts:
    """Verify end-to-end arbitration verdicts through the pipeline."""

    def test_empty_predictions_claims_produces_ship(self, tmp_path):
        """When LLM returns empty predictions and claims and Layer 1 passes -> SHIP."""
        code = textwrap.dedent('''\
            def noop_function():
                """No-op function."""
                return True
        ''')
        source_file = tmp_path / "noop.py"
        source_file.write_text(code)

        def fake_llm(prompt: str) -> str:
            return json.dumps([])

        evidence = [
            ToolEvidence("persistence_checker", "noop.py", True, "clean"),
            ToolEvidence("call_graph", "noop.py", True, "wired"),
        ]

        result = _layer2(
            changed_files=["noop.py"],
            repo_root=str(tmp_path),
            task_plan="Create no-op utility",
            layer1_evidence=evidence,
            llm_backend=fake_llm,
        )

        assert isinstance(result, ArbitrationResult)
        assert result.verdict == Verdict.SHIP
        assert len(result.divergences) == 0
        assert result.predictions == []
        assert result.claims == []
        assert result.layer1_results == evidence

    def test_convergent_predictions_and_claims_ships(self, tmp_path):
        """When predictions match claims and Layer 1 passes -> SHIP."""
        code = textwrap.dedent('''\
            def save_state(state):
                """Serialize and persist state."""
                return True
        ''')
        source_file = tmp_path / "storage.py"
        source_file.write_text(code)

        def fake_llm(prompt: str) -> str:
            if "Spec Agent" in prompt:
                return json.dumps([
                    {
                        "category": "persistence_gap",
                        "severity": "critical",
                        "risk": "State not persisted across restarts",
                        "mechanism": "In-memory mutation without disk write",
                        "affected_function": "save_state",
                    }
                ])
            elif "Code Agent" in prompt:
                return json.dumps([
                    {
                        "category": "persistence_gap",
                        "claim": "State safely written to storage file at line 3",
                        "evidence_file": "storage.py",
                        "evidence_line": 3,
                        "tests_covering": ["test_save_state"],
                    }
                ])
            return json.dumps([])

        evidence = [
            ToolEvidence("persistence_checker", "storage.py:state", True, "All keys serialized")
        ]

        result = _layer2(
            changed_files=["storage.py"],
            repo_root=str(tmp_path),
            task_plan="Add persistent storage mechanism",
            layer1_evidence=evidence,
            llm_backend=fake_llm,
        )

        assert result.verdict == Verdict.SHIP
        assert RiskCategory.PERSISTENCE_GAP in result.convergences
        assert len(result.divergences) == 0
        assert len(result.predictions) == 1
        assert len(result.claims) == 1

    def test_contradicted_claim_blocks(self, tmp_path):
        """Code Agent claims persistence is handled, but Layer 1 disagrees -> BLOCK."""
        code = textwrap.dedent('''\
            def save_fitness(meta):
                """Save fitness values."""
                meta['score'] = 1.0
                return meta
        ''')
        source_file = tmp_path / "rule.py"
        source_file.write_text(code)

        def fake_llm(prompt: str) -> str:
            if "Spec Agent" in prompt:
                return json.dumps([])
            elif "Code Agent" in prompt:
                return json.dumps([
                    {
                        "category": "persistence_gap",
                        "claim": "All fitness keys are fully serialized",
                        "evidence_file": "rule.py",
                        "evidence_line": 3,
                        "tests_covering": [],
                    }
                ])
            return json.dumps([])

        evidence = [
            ToolEvidence(
                tool="persistence_checker",
                target="rule.py:fitness",
                verdict=False,
                detail="PERSISTENCE GAP: score mutated but not serialized",
                lines=[3],
            )
        ]

        result = _layer2(
            changed_files=["rule.py"],
            repo_root=str(tmp_path),
            task_plan="Update rule fitness calculation",
            layer1_evidence=evidence,
            llm_backend=fake_llm,
        )

        assert result.verdict == Verdict.BLOCK
        assert len(result.divergences) == 1
        assert result.divergences[0].divergence_type == "contradicted_claim"
        assert result.divergences[0].category == RiskCategory.PERSISTENCE_GAP

    def test_confirmed_risk_blocks(self, tmp_path):
        """Both agents address a risk, but Layer 1 confirms the failure -> BLOCK."""
        code = textwrap.dedent('''\
            def apply_decay(meta):
                """Apply decay rate."""
                meta['last_decay_epoch'] = 1234
                return meta
        ''')
        source_file = tmp_path / "decay.py"
        source_file.write_text(code)

        def fake_llm(prompt: str) -> str:
            if "Spec Agent" in prompt:
                return json.dumps([
                    {
                        "category": "persistence_gap",
                        "severity": "critical",
                        "risk": "last_decay_epoch not serialized",
                        "mechanism": "Only stored in memory",
                        "affected_function": "apply_decay",
                    }
                ])
            elif "Code Agent" in prompt:
                return json.dumps([
                    {
                        "category": "persistence_gap",
                        "claim": "last_decay_epoch persisted in meta dict",
                        "evidence_file": "decay.py",
                        "evidence_line": 3,
                        "tests_covering": ["test_decay"],
                    }
                ])
            return json.dumps([])

        evidence = [
            ToolEvidence(
                tool="persistence_checker",
                target="decay.py:fitness",
                verdict=False,
                detail="last_decay_epoch assigned but missing from serializer",
                lines=[3],
            )
        ]

        result = _layer2(
            changed_files=["decay.py"],
            repo_root=str(tmp_path),
            task_plan="Implement decay epochs",
            layer1_evidence=evidence,
            llm_backend=fake_llm,
        )

        assert result.verdict == Verdict.BLOCK
        assert len(result.divergences) == 1
        assert result.divergences[0].divergence_type == "confirmed_risk"
        assert result.divergences[0].category == RiskCategory.PERSISTENCE_GAP

    def test_unmatched_high_severity_prediction_revises(self, tmp_path):
        """Spec Agent predicts HIGH severity risk that Code Agent does not address -> REVISE."""
        code = textwrap.dedent('''\
            def execute_step(step_id):
                """Execute single step."""
                return step_id + 1
        ''')
        source_file = tmp_path / "step.py"
        source_file.write_text(code)

        def fake_llm(prompt: str) -> str:
            if "Spec Agent" in prompt:
                return json.dumps([
                    {
                        "category": "idempotency",
                        "severity": "high",
                        "risk": "Step execution is not idempotent",
                        "mechanism": "Repeated invocations advance state multiple times",
                        "affected_function": "execute_step",
                    }
                ])
            elif "Code Agent" in prompt:
                return json.dumps([])  # Code Agent missed it
            return json.dumps([])

        result = _layer2(
            changed_files=["step.py"],
            repo_root=str(tmp_path),
            task_plan="Add step execution",
            layer1_evidence=[],
            llm_backend=fake_llm,
        )

        assert result.verdict == Verdict.REVISE
        assert len(result.divergences) == 1
        assert result.divergences[0].divergence_type == "unmatched_prediction"
        assert result.divergences[0].category == RiskCategory.IDEMPOTENCY_VIOLATION

    def test_layer1_failure_alone_blocks(self, tmp_path):
        """Layer 1 failure with no agent findings produces BLOCK."""
        code = textwrap.dedent('''\
            def orphan_routine():
                """Unwired routine."""
                pass
        ''')
        source_file = tmp_path / "orphan.py"
        source_file.write_text(code)

        def fake_llm(prompt: str) -> str:
            return json.dumps([])

        evidence = [
            ToolEvidence(
                tool="call_graph",
                target="orphan.py",
                verdict=False,
                detail="orphan_routine has no callers",
                lines=[1],
            )
        ]

        result = _layer2(
            changed_files=["orphan.py"],
            repo_root=str(tmp_path),
            task_plan="Add orphan routine",
            layer1_evidence=evidence,
            llm_backend=fake_llm,
        )

        assert result.verdict == Verdict.BLOCK


class TestEdgeCasesAndRobustness:
    """Verify edge cases: formatting, multi-file changes, non-Python files, etc."""

    def test_handles_markdown_code_fenced_json(self, tmp_path):
        """LLM responses wrapped in ```json ... ``` code blocks must be parsed cleanly."""
        code = textwrap.dedent('''\
            def calculate_score(val):
                """Calculate score."""
                return val * 2
        ''')
        source_file = tmp_path / "score.py"
        source_file.write_text(code)

        def fenced_llm(prompt: str) -> str:
            if "Spec Agent" in prompt:
                data = [
                    {
                        "category": "dead_code",
                        "severity": "low",
                        "risk": "Possible unreachable fallback",
                        "mechanism": "Condition evaluates true in all standard configurations",
                        "affected_function": "calculate_score",
                    }
                ]
                return f"```json\n{json.dumps(data, indent=2)}\n```"
            elif "Code Agent" in prompt:
                data = [
                    {
                        "category": "dead_code",
                        "claim": "Branch is tested and covered",
                        "evidence_file": "score.py",
                        "evidence_line": 3,
                        "tests_covering": ["test_calculate_score"],
                    }
                ]
                return f"```json\n{json.dumps(data, indent=2)}\n```"
            return "```json\n[]\n```"

        result = _layer2(
            changed_files=["score.py"],
            repo_root=str(tmp_path),
            task_plan="Refactor calculate_score",
            layer1_evidence=[],
            llm_backend=fenced_llm,
        )

        assert isinstance(result, ArbitrationResult)
        assert len(result.predictions) == 1
        assert len(result.claims) == 1
        assert result.predictions[0].category == RiskCategory.DEAD_CODE
        assert result.claims[0].category == RiskCategory.DEAD_CODE

    def test_multiple_changed_files(self, tmp_path):
        """Signatures and implementations from multiple changed files must be aggregated."""
        mod_a = tmp_path / "mod_a.py"
        mod_a.write_text(textwrap.dedent('''\
            def process_a(x):
                """Process A."""
                body_a = 100
                return x + body_a
        '''))

        mod_b = tmp_path / "mod_b.py"
        mod_b.write_text(textwrap.dedent('''\
            def process_b(y):
                """Process B."""
                body_b = 200
                return y + body_b
        '''))

        dispatched_prompts = []

        def recording_llm(prompt: str) -> str:
            dispatched_prompts.append(prompt)
            return json.dumps([])

        result = _layer2(
            changed_files=["mod_a.py", "mod_b.py"],
            repo_root=str(tmp_path),
            task_plan="Implement process_a and process_b",
            layer1_evidence=[],
            llm_backend=recording_llm,
        )

        spec_prompt = next(p for p in dispatched_prompts if "Spec Agent" in p)
        code_prompt = next(p for p in dispatched_prompts if "Code Agent" in p)

        # Both signatures present in spec prompt
        assert "process_a" in spec_prompt
        assert "process_b" in spec_prompt
        assert "body_a = 100" not in spec_prompt
        assert "body_b = 200" not in spec_prompt

        # Both implementations present in code prompt
        assert "body_a = 100" in code_prompt
        assert "body_b = 200" in code_prompt

        assert isinstance(result, ArbitrationResult)

    def test_empty_changed_files_graceful(self, tmp_path):
        """No changed files: Layer 1 passes, Layer 2 is not run and the backend is never called."""
        calls = []

        def fake_llm(prompt: str) -> str:
            calls.append(prompt)
            return json.dumps([])

        res = VerificationPipeline().run(
            changed_files=[],
            workspace=str(tmp_path),
            task_plan="Documentation update only",
            backend=fake_llm,
            layer1_evidence=[],
        )

        assert res.verdict == Verdict.SHIP
        assert res.arbitration_result is None
        assert calls == []

    def test_non_python_or_missing_changed_files(self, tmp_path):
        """Non-Python files or missing files in changed_files must not raise syntax errors or crashes."""
        doc = tmp_path / "README.md"
        doc.write_text("# Project Documentation\nSome docs here.\n")

        def fake_llm(prompt: str) -> str:
            return json.dumps([])

        result = _layer2(
            changed_files=["README.md", "non_existent_file.py"],
            repo_root=str(tmp_path),
            task_plan="Update documentation",
            layer1_evidence=[],
            llm_backend=fake_llm,
        )

        assert isinstance(result, ArbitrationResult)
        assert result.verdict == Verdict.SHIP

    def test_custom_test_names_and_results_passed_through(self, tmp_path):
        """Optional test_names and test_results should be embedded in the respective prompts."""
        code = textwrap.dedent('''\
            def validate_input(val):
                """Validate input."""
                return bool(val)
        ''')
        source_file = tmp_path / "validator.py"
        source_file.write_text(code)

        dispatched_prompts = []

        def recording_llm(prompt: str) -> str:
            dispatched_prompts.append(prompt)
            return json.dumps([])

        test_names = ["test_validate_positive", "test_validate_empty"]
        test_results = "test_validate_positive: PASSED\ntest_validate_empty: PASSED"

        result = _layer2(
            changed_files=["validator.py"],
            repo_root=str(tmp_path),
            task_plan="Add validator",
            layer1_evidence=[],
            llm_backend=recording_llm,
            test_names=test_names,
            test_results=test_results,
        )

        spec_prompt = next(p for p in dispatched_prompts if "Spec Agent" in p)
        code_prompt = next(p for p in dispatched_prompts if "Code Agent" in p)

        assert "test_validate_positive" in spec_prompt
        assert "test_validate_empty" in spec_prompt
        assert test_results in code_prompt
        assert isinstance(result, ArbitrationResult)
