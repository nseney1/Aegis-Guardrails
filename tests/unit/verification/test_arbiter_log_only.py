"""T6 is log-only (R-checks-43): a Spec Agent failure is 'unverified', never a BLOCK,
and the arbiter's Layer 1 verdict comes from the deterministic evidence alone."""
from __future__ import annotations

from aegis_core.verification import Prediction, RiskCategory, Severity, ToolEvidence, Verdict
from aegis_core.verification.arbiter import arbitrate

PASSING = ToolEvidence("call_graph", "module.py", True, "ok")
FAILING = ToolEvidence("call_graph", "module.py", False, "run() is never called")


def _prediction(severity: Severity) -> Prediction:
    return Prediction(category=RiskCategory.CODE_INJECTION, severity=severity, risk="eval",
                      mechanism="exec", affected_function="run")


def test_a_spec_agent_failure_with_passing_layer1_is_unverified_not_block():
    res = arbitrate([], [], [PASSING], spec_agent_failed=True)
    assert res.verdict != Verdict.BLOCK
    assert res.infra_status == "unverified"
    assert res.layer1_verdict == "PASS"
    assert res.llm_predictions == ()


def test_a_spec_agent_failure_with_failing_layer1_still_blocks():
    res = arbitrate([], [], [FAILING], spec_agent_failed=True)
    assert res.verdict == Verdict.BLOCK
    assert res.layer1_verdict == "FAIL"
    assert res.infra_status == "unverified"


def test_an_answered_review_is_ok_and_keeps_its_verdict():
    assert arbitrate([_prediction(Severity.CRITICAL)], [], [PASSING]).verdict == Verdict.BLOCK
    res = arbitrate([_prediction(Severity.HIGH)], [], [PASSING])
    assert res.verdict == Verdict.REVISE
    assert res.infra_status == "ok"
    assert res.layer1_verdict == "PASS"
