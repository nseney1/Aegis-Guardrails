"""format_layer2_summary prints model text as one sanitized, bounded line (R-checks-38)."""
from __future__ import annotations

import time

from aegis_cli.formatters.report import format_layer2_summary
from aegis_core.verification import (
    ArbitrationResult, Divergence, Prediction, RiskCategory, Severity, ToolEvidence, Verdict,
)

# The red phase ran at 15,000/30,000 repeats: an unsliced sanitizer took 2.7 s and 10.6 s.
SMALL, LARGE = 30000, 60000


def _summary(risk) -> str:
    pred = Prediction(category=RiskCategory.CODE_INJECTION, severity=Severity.CRITICAL, risk=risk)
    result = ArbitrationResult(
        divergences=[Divergence("unmatched_prediction", RiskCategory.CODE_INJECTION, prediction=pred)],
        verdict=Verdict.BLOCK,
        layer1_results=[ToolEvidence("call_graph", "m.py", True, "ok")],
        predictions=[pred],
    )
    return format_layer2_summary(result)


def _longest_line(text: str) -> int:
    return max(len(line) for line in text.splitlines())


def _best_of_3(risk, calls: int = 5) -> float:
    # Several calls per sample: one call takes a few ms after the fix, too short to compare alone.
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        for _ in range(calls):
            _summary(risk)
        best = min(best, time.perf_counter() - start)
    return best


def test_ordinary_risk_text_is_unchanged():
    assert "[critical] eval of untrusted input" in _summary("eval of untrusted input")


def test_long_risk_text_is_cut_to_one_bounded_line():
    out = _summary("x" * 5000)
    assert _longest_line(out) < 400
    assert "..." in out


def test_unterminated_escape_introducers_cost_the_same_at_any_length():
    for n in (SMALL, LARGE):
        assert _longest_line(_summary("\x1b]" * n)) < 400
    # The slice before sanitizing makes the cost constant; a ratio, never an absolute budget.
    assert _best_of_3("\x1b]" * LARGE) / _best_of_3("\x1b]" * SMALL) < 3
