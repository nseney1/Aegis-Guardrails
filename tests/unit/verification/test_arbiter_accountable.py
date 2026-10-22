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
from aegis_core.verification.arbiter import arbitrate, calibration


class TestSplitArbitrationResult:
    """ArbitrationResult separates Layer 1 verdict, infra status, and LLM predictions."""

    def test_split_fields_on_clean_pass(self):
        pred = Prediction(
            category=RiskCategory.PERSISTENCE_GAP,
            severity=Severity.MEDIUM,
            risk="State might not flush",
            mechanism="Missing fsync",
            affected_function="save_state",
            scope={"path": "aegis_core/state.py"},
            observable={"kind": "revert", "selector": "aegis_core/state.py"},
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
        assert p.disposition == "logged" and p.outcome is None
        assert p.window_days == 14
        assert p.observable == {"kind": "", "selector": ""}  # no kind resolves to void, never scored
        assert 0.0 <= p.p <= 1.0
        assert p.scope == {"path": "", "symbol": "parse_header"}  # the path is Aegis's to set
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
            backend="claude",
            scope={"path": "aegis_core/verification/arbiter.py", "symbol": "arbitrate"},
            observable={"kind": "revert", "selector": "aegis_core/verification/arbiter.py"},
            window_days=14,
            p=0.80,
            disposition="overridden",
        )
        assert p.id == "pred-001"
        assert p.verdict_id == "verd-123"
        assert p.ts == 1700000000.0
        assert p.tree == "abc1234"
        assert p.backend == "claude"
        assert p.scope == {"path": "aegis_core/verification/arbiter.py", "symbol": "arbitrate"}
        assert p.observable == {"kind": "revert", "selector": "aegis_core/verification/arbiter.py"}
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

    @staticmethod
    def _row(i, *, p=0.5, outcome="hit", disposition="landed_unchanged", backend="claude", kind="revert", rid=None):
        return {"id": rid or f"p-{i}", "backend": backend, "observable": {"kind": kind, "selector": f"m{i}.py"},
                "p": p, "disposition": disposition, "outcome": outcome}

    def test_the_brier_skill_score_needs_100_resolved_and_beats_the_base_rate(self):
        good = [self._row(i, p=0.9 if i < 20 else 0.1, outcome="hit" if i < 20 else "miss") for i in range(100)]
        assert calibration(good)["claude/revert"]["brier_skill_score"] > 0.85
        assert calibration(good[:99])["claude/revert"]["brier_skill_score"] is None
        flat = [self._row(i, outcome="hit") for i in range(100)]  # no variance: no skill to measure
        assert calibration(flat)["claude/revert"]["brier_skill_score"] is None

    def test_heeded_logged_and_void_rows_are_not_scored_and_ids_count_once(self):
        rows = [self._row(1), self._row(2, rid="p-1"), self._row(3, outcome="miss", disposition="overridden"),
                self._row(4, disposition="heeded"), self._row(5, disposition="logged"), self._row(6, outcome="void"),
                self._row(7, outcome=True), self._row(8, disposition="abandoned")]
        (group,) = calibration(rows).values()
        assert (group["n"], group["hits"], group["status"]) == (2, 1, "insufficient (n=2/25)")
        assert len(group["wilson_ci"]) == 2

    def test_the_status_says_ok_from_25_resolved_per_group(self):
        rows = [self._row(i, outcome="hit" if i % 2 else "miss") for i in range(25)]
        rows += [self._row(i, backend="gemini", kind="fix_attributed", rid=f"g-{i}") for i in range(3)]
        groups = calibration(rows)
        assert (groups["claude/revert"]["status"], groups["gemini/fix_attributed"]["status"]) == (
            "ok", "insufficient (n=3/25)")

    def test_a_p_that_is_not_a_probability_cannot_be_scored(self):
        for bad in (None, "0.5", 1.5, -0.1, True):
            with pytest.raises(ValueError):
                calibration([self._row(1, p=bad)])


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
    """`aegis check --calibration` through the real parser (it was a hand-built Namespace before 4.4.0)."""

    def test_calibration_cli_human_and_json(self, tmp_path: Path, capsys):
        import json
        from aegis_cli.cli import main

        ws = tmp_path / "ws"
        state_dir = ws / ".aegis" / "state"
        state_dir.mkdir(parents=True)
        (state_dir / "arbiter_predictions.jsonl").write_bytes((json.dumps({
            "id": "p-1", "backend": "claude", "observable": {"kind": "revert", "selector": "aegis_core/foo.py"},
            "p": 0.75, "disposition": "landed_unchanged", "outcome": "hit"}) + "\n").encode("utf-8"))

        assert main(["check", "--workspace", str(ws), "--calibration"]) == 0
        assert "insufficient (n=1/25)" in capsys.readouterr().out
        assert main(["check", "--workspace", str(ws), "--calibration", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert (payload["status"], payload["n"], payload["groups"]["claude/revert"]["hits"]) == ("insufficient (n=1/25)", 1, 1)
