"""Behavioral tests for T6: Accountable Arbiter (log-only)."""
from __future__ import annotations

from pathlib import Path

import pytest

from aegis_core.verification import (
    ArbitrationResult,
    Claim,
    Prediction,
    RiskCategory,
    Severity,
    ToolEvidence,
    Verdict,
)
from aegis_core.stats import wilson_ci
from aegis_core.verification import arbiter
from aegis_core.verification.arbiter import (
    arbitrate,
    brier_skill_score,
    calibration_summary,
    score_predictions,
)


class TestSplitArbitrationResult:
    """ArbitrationResult separates Layer 1 verdict, infra status, and LLM predictions."""

    def test_split_fields_on_clean_pass(self):
        pred = Prediction(
            category=RiskCategory.PERSISTENCE_GAP,
            severity=Severity.MEDIUM,
            risk="State might not flush",
            mechanism="Missing fsync",
            affected_function="save_state",
            scope="aegis_core/state.py",
            observable="fix_touch_in_window",
            p=0.65,
        )
        claim = Claim(
            category=RiskCategory.PERSISTENCE_GAP,
            claim="Flushed via atomic_write_text",
            evidence_file="aegis_core/state.py",
            evidence_line=42,
            tests_covering=["test_save_state"],
        )
        ev = ToolEvidence(
            tool="persistence_checker",
            target="aegis_core/state.py",
            verdict=True,
            detail="All writes persisted",
        )

        res = arbitrate([pred], [claim], [ev])

        assert isinstance(res, ArbitrationResult)
        assert res.layer1_verdict == "PASS"
        assert res.infra_status == "ok"
        assert isinstance(res.llm_predictions, tuple)
        assert len(res.llm_predictions) == 1
        assert res.llm_predictions[0] == pred
        assert res.verdict == Verdict.SHIP
        assert res.predictions == [pred]
        assert isinstance(res.verdict_id, str) and len(res.verdict_id) > 0

    def test_split_fields_on_layer1_fail_and_spec_failure(self):
        ev_fail = ToolEvidence(
            tool="import_guard",
            target="aegis_core/foo.py",
            verdict=False,
            detail="Boundary violation",
        )
        res = arbitrate([], [], [ev_fail], spec_agent_failed=True)
        assert res.layer1_verdict == "FAIL"
        assert res.infra_status == "unverified"
        assert res.llm_predictions == ()
        assert res.verdict == Verdict.BLOCK


class TestExtendedPredictionSchema:
    """Prediction supports accountable calibration fields and legacy compatibility."""

    def test_prediction_defaults(self):
        p = Prediction(
            category=RiskCategory.MISSING_COVERAGE,
            severity=Severity.HIGH,
            risk="Untested branch",
            mechanism="Error path skipped",
            affected_function="parse_header",
        )
        assert p.disposition == "logged"
        assert p.window_days == 14
        assert p.observable == "fix_touch_in_window"
        assert 0.0 <= p.p <= 1.0
        assert p.scope == "parse_header"
        assert isinstance(p.id, str) and len(p.id) > 0

    @pytest.mark.parametrize("alias", ["claim_type", "target", "horizon_commits"])
    def test_the_4_3_alias_fields_are_gone(self, alias):
        """Nothing persisted predictions in 4.3.x, so no reader needs the aliases (R-checks-46)."""
        with pytest.raises(TypeError):
            Prediction(**{alias: 1 if alias == "horizon_commits" else "x"})
        assert not hasattr(Prediction(), alias)
        assert alias not in Prediction(affected_function="f").to_dict()

    def test_prediction_explicit_accountable_fields(self):
        p = Prediction(
            id="pred-001",
            verdict_id="verd-123",
            ts=1700000000.0,
            tree="abc1234",
            backend="anthropic/claude-3-5-sonnet",
            scope="aegis_core/verification/arbiter.py",
            observable="revert_in_window",
            window_days=14,
            p=0.80,
            disposition="overridden",
        )
        assert p.id == "pred-001"
        assert p.verdict_id == "verd-123"
        assert p.ts == 1700000000.0
        assert p.tree == "abc1234"
        assert p.backend == "anthropic/claude-3-5-sonnet"
        assert p.scope == "aegis_core/verification/arbiter.py"
        assert p.observable == "revert_in_window"
        assert p.window_days == 14
        assert p.p == 0.80
        assert p.disposition == "overridden"


class TestCalibrationScoring:
    """Calibration math, heeded exclusion, deduplication and thresholds."""

    def test_wilson_ci_matches_reference_formula(self):
        assert wilson_ci(0, 0) == (0.0, 1.0)
        lo, hi = wilson_ci(14, 20)
        assert 0.48 < lo < 0.49
        assert 0.85 < hi < 0.86

    def test_brier_skill_score_computation(self):
        probs = [0.9, 0.8, 0.1, 0.2]
        outcomes = [1, 1, 0, 0]
        bss = brier_skill_score(probs, outcomes)
        assert bss > 0.85

    def test_filters_heeded_and_deduplicates_scope_observable(self):
        records = [
            # Logged and resolved True
            Prediction(
                id="p1",
                scope="aegis_core/a.py",
                observable="fix_touch_in_window",
                p=0.8,
                disposition="logged",
                outcome=True,
            ),
            # Duplicate (scope, observable) — must be deduplicated in n_effective
            Prediction(
                id="p2",
                scope="aegis_core/a.py",
                observable="fix_touch_in_window",
                p=0.7,
                disposition="logged",
                outcome=True,
            ),
            # Overridden and resolved False
            Prediction(
                id="p3",
                scope="aegis_core/b.py",
                observable="revert_in_window",
                p=0.6,
                disposition="overridden",
                outcome=False,
            ),
            # Heeded — must be excluded from accuracy scoring (treatment effect confounder)
            Prediction(
                id="p4",
                scope="aegis_core/c.py",
                observable="fix_touch_in_window",
                p=0.9,
                disposition="heeded",
                outcome=False,
            ),
        ]

        scored = score_predictions(records)
        assert scored["n_heeded_excluded"] == 1
        assert scored["n_raw"] == 3
        assert scored["n_effective"] == 2
        assert scored["hits"] == 1

        summary = calibration_summary(records)
        assert summary["status"] == "insufficient (n=2/25)"
        assert "insufficient (n=2/25)" in str(summary)
        assert summary["brier_skill_score"] is None
        assert summary["lift_suppressed"] is True

    def test_calibration_summary_thresholds_25_and_100_and_base_rate(self):
        # 30 effective predictions (< 100): status is ok, but Brier skill / lift is suppressed
        records_30 = [
            {
                "id": f"p-{i}",
                "scope": f"mod_{i}.py",
                "observable": "fix_touch_in_window",
                "p": 0.75 if i % 2 == 0 else 0.25,
                "disposition": "logged",
                "outcome": (i % 2 == 0),
            }
            for i in range(30)
        ]
        sum_30 = calibration_summary(records_30)
        assert sum_30["n_effective"] == 30
        assert sum_30["status"] == "ok"
        assert sum_30["brier_skill_score"] is None
        assert sum_30["lift_suppressed"] is True
        assert len(sum_30["wilson_ci"]) == 2

        # 100 effective predictions with base rate >= 5%: Brier skill score reported
        records_100 = [
            {
                "id": f"p-{i}",
                "scope": f"mod_{i}.py",
                "observable": "fix_touch_in_window",
                "p": 0.85 if i < 20 else 0.15,
                "disposition": "logged",
                "outcome": (i < 20),
            }
            for i in range(100)
        ]
        sum_100 = calibration_summary(records_100)
        assert sum_100["n_effective"] == 100
        assert sum_100["status"] == "ok"
        assert sum_100["lift_suppressed"] is False
        assert sum_100["brier_skill_score"] is not None
        assert sum_100["brier_skill_score"] > 0.0

        # 100 effective predictions with base rate < 5% (only 2/100 = 2%): suppressed
        records_low_base = [
            {
                "id": f"p-{i}",
                "scope": f"mod_{i}.py",
                "observable": "fix_touch_in_window",
                "p": 0.85 if i < 2 else 0.05,
                "disposition": "logged",
                "outcome": (i < 2),
            }
            for i in range(100)
        ]
        sum_low_base = calibration_summary(records_low_base)
        assert sum_low_base["lift_suppressed"] is True
        assert sum_low_base["brier_skill_score"] is None


class TestDeadSurfaceIsGone:
    """R-checks-46: the T6 surface nothing called is deleted; what stays behaves as at cdb527b."""

    @pytest.mark.parametrize("name", [
        "structural_ship_gaps", "prune_predictions", "PruneResult", "check_vendor_independence", "Z95",
    ])
    def test_the_arbiter_no_longer_exposes_dead_names(self, name):
        assert not hasattr(arbiter, name)

    @pytest.mark.parametrize("kwarg", [
        "infra_status", "changed_files", "all_files", "rule_miss_counts", "arbiter_vendor", "generator_vendor",
    ])
    def test_arbitrate_refuses_the_unpassed_keywords(self, kwarg):
        with pytest.raises(TypeError):
            arbitrate([], [], [], **{kwarg: None})

    def test_results_carry_no_unread_fields(self):
        from aegis_core.verification.pipeline import VerificationPipelineResult

        res = arbitrate([], [], [])
        for gone in ("decision", "confidence", "rationale", "structural_gaps", "vendor_warning"):
            assert not hasattr(res, gone), gone
        pipe = VerificationPipelineResult([], [], True, Verdict.SHIP, True, "s")
        for gone in ("layer1_verdict", "infra_status", "llm_predictions"):
            assert not hasattr(pipe, gone), gone
        assert not hasattr(Prediction, "from_dict")

    def test_verdict_and_prediction_ids_are_unchanged_for_a_fixed_input(self):
        """Literals computed with the cdb527b formula: the id must not move when the fields go."""
        passing = ToolEvidence("call_graph", "m.py", True, "ok")
        failing = ToolEvidence("call_graph", "m.py", False, "unwired")
        pred = Prediction(category=RiskCategory.CODE_INJECTION, severity=Severity.HIGH, risk="eval",
                          mechanism="exec", affected_function="run")
        assert pred.id == "e8fc8c414303"
        assert arbitrate([], [], [passing]).verdict_id == "7fdd95ca82a4"
        assert arbitrate([pred], [], [passing]).verdict_id == "2a61761ee0ff"
        assert arbitrate([pred], [], [failing]).verdict_id == "ae2130be1c40"

    @pytest.mark.parametrize("module", ["arbiter.py", "pipeline.py"])
    def test_call_graph_finds_no_orphan_in_the_trimmed_modules(self, module):
        from aegis_core.verification import call_graph

        root = Path(__file__).resolve().parents[3]
        found = call_graph.check(str(root / "aegis_core" / "verification" / module), str(root))
        assert found.verdict is True, found.detail


class TestVerifyCalibrationCli:
    """CLI integration test for `aegis verify --calibration`."""

    def test_verify_calibration_cli_human_and_json(self, tmp_path: Path, capsys):
        import argparse
        import json
        from aegis_cli.verify import run_verify

        ws = tmp_path / "ws"
        state_dir = ws / ".aegis" / "state"
        state_dir.mkdir(parents=True)
        preds_path = state_dir / "arbiter_predictions.jsonl"
        preds_path.write_text(
            json.dumps({
                "id": "p-1",
                "scope": "aegis_core/foo.py",
                "observable": "fix_touch_in_window",
                "p": 0.75,
                "disposition": "logged",
                "outcome": True,
            })
            + "\n",
            encoding="utf-8",
        )

        args_human = argparse.Namespace(_root=ws, calibration=True, json=False)
        rc = run_verify(args_human)
        assert rc == 0
        out_human = capsys.readouterr().out
        assert "insufficient (n=1/25)" in out_human

        args_json = argparse.Namespace(_root=ws, calibration=True, json=True)
        rc_json = run_verify(args_json)
        assert rc_json == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["status"] == "insufficient (n=1/25)"
        assert payload["n_effective"] == 1
        assert payload["hits"] == 1

