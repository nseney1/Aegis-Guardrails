"""Arbiter: Deterministic divergence detector.

Compares Spec Agent predictions against Code Agent claims, with Layer 1
tool evidence as tiebreaker. Pure set logic — no LLM judgment.

The Arbiter answers three questions:
1. Did the Spec Agent predict a risk that the Code Agent didn't address? (blind spot)
2. Did the Code Agent claim something that Layer 1 tools contradict? (false claim)
3. Did both agree but Layer 1 shows a problem anyway? (shared blind spot)
"""
from __future__ import annotations

from typing import Any, Optional, Sequence

from aegis_core.stats import wilson_ci

from . import (
    ArbitrationResult, Claim, Divergence, Prediction,
    ReviewGaps, RiskCategory, Severity, ToolEvidence, Verdict,
)


def arbitrate(
    predictions: list[Prediction],
    claims: list[Claim],
    layer1_evidence: list[ToolEvidence],
    *,
    spec_agent_failed: bool = False,
    gaps: Optional[ReviewGaps] = None,
) -> ArbitrationResult:
    """Compare predictions vs claims vs tool evidence.

    Divergence detection is pure set operations on RiskCategory enums.
    No natural language comparison. No LLM.

    Returns ArbitrationResult with divergences, convergences, and verdict. ``gaps`` is what
    the review left out; None means it was not tracked and adds no reason.
    """
    divergences: list[Divergence] = []
    convergences: list[RiskCategory] = []

    # Index by category for O(1) lookup
    pred_by_cat: dict[RiskCategory, list[Prediction]] = {}
    for p in predictions:
        pred_by_cat.setdefault(p.category, []).append(p)

    claim_by_cat: dict[RiskCategory, list[Claim]] = {}
    for c in claims:
        claim_by_cat.setdefault(c.category, []).append(c)

    # Index Layer 1 failures by relevance (BUG-078: group by tool to prevent multi-target collisions)
    layer1_failures = [e for e in layer1_evidence if not e.verdict]
    layer1_by_tool: dict[str, list[ToolEvidence]] = {}
    for e in layer1_evidence:
        layer1_by_tool.setdefault(e.tool, []).append(e)

    # Map Layer 1 tool names to risk categories they can adjudicate
    TOOL_TO_CATEGORY = {
        "persistence_checker": RiskCategory.PERSISTENCE_GAP,
        "mutation_tester": RiskCategory.TAUTOLOGICAL_TEST,
        "call_graph": RiskCategory.MISSING_WIRE,
        "import_guard": RiskCategory.BOUNDARY_VIOLATION,
    }

    all_categories = set(pred_by_cat.keys()) | set(claim_by_cat.keys())

    for cat in all_categories:
        preds = pred_by_cat.get(cat, [])
        cls = claim_by_cat.get(cat, [])

        # Find relevant Layer 1 evidence for this category
        # If any target file failed for this tool, prioritize that failure
        relevant_evidence = None
        for tool_name, tool_cat in TOOL_TO_CATEGORY.items():
            if tool_cat == cat and tool_name in layer1_by_tool:
                tool_evs = layer1_by_tool[tool_name]
                failing = next((ev for ev in tool_evs if not ev.verdict), None)
                relevant_evidence = failing if failing else tool_evs[0]
                break

        if preds and not cls:
            # Spec Agent predicted a risk, Code Agent didn't address it
            for p in preds:
                divergences.append(Divergence(
                    divergence_type="unmatched_prediction",
                    category=cat,
                    prediction=p,
                    tool_evidence=relevant_evidence,
                    resolution="Code Agent did not address this predicted risk",
                ))

        elif cls and not preds:
            # Code Agent claimed something Spec Agent didn't worry about
            # Low concern — but check Layer 1
            if relevant_evidence and not relevant_evidence.verdict:
                for c in cls:
                    divergences.append(Divergence(
                        divergence_type="contradicted_claim",
                        category=cat,
                        claim=c,
                        tool_evidence=relevant_evidence,
                        resolution="Claim contradicted by Layer 1 tool evidence",
                    ))
            else:
                convergences.append(cat)

        elif preds and cls:
            # Both agents addressed this category
            if relevant_evidence and not relevant_evidence.verdict:
                # Layer 1 FAILS — the claim is wrong despite addressing the risk
                for p in preds:
                    divergences.append(Divergence(
                        divergence_type="confirmed_risk",
                        category=cat,
                        prediction=p,
                        claim=cls[0],
                        tool_evidence=relevant_evidence,
                        resolution="Spec Agent prediction confirmed by Layer 1 failure",
                    ))
            else:
                convergences.append(cat)

    # Check for Layer 1 failures not covered by any prediction or claim
    for evidence in layer1_failures:
        tool_cat = TOOL_TO_CATEGORY.get(evidence.tool)
        if tool_cat and tool_cat not in all_categories:
            divergences.append(Divergence(
                divergence_type="undetected_by_both",
                category=tool_cat,
                tool_evidence=evidence,
                resolution="Neither agent identified this — caught only by Layer 1 tools",
            ))

    # Verdict logic
    verdict = _compute_verdict(divergences, layer1_failures)
    l1_verdict = "FAIL" if layer1_failures else "PASS"
    reasons = _unverified_reasons(predictions, spec_agent_failed, gaps)

    return ArbitrationResult(
        divergences=divergences,
        convergences=convergences,
        verdict=verdict,
        layer1_results=layer1_evidence,
        predictions=predictions,
        claims=claims,
        layer1_verdict=l1_verdict,
        infra_status="unverified" if reasons else "ok",
        llm_predictions=tuple(predictions),
        unverified_reasons=reasons,
    )


def _unverified_reasons(
    predictions: Sequence[Prediction], spec_agent_failed: bool, gaps: Optional[ReviewGaps],
) -> tuple[str, ...]:
    """Why the review cannot be read as complete; empty means it can. These only ever make a
    run 'unverified', never BLOCK."""
    reasons = []
    if spec_agent_failed:
        reasons.append("spec_agent_unparseable")
    if gaps is not None and gaps.code_agent_failed:
        reasons.append("code_agent_unparseable")
    if not predictions:
        reasons.append("no_predictions")
    if gaps is not None:
        if not gaps.reviewed_files:
            reasons.append("no_reviewed_files")
        # Tests, __init__.py and non-Python files are excluded by design: beside a reviewed
        # file they are not a hole, or every change with a test would read 'unverified'.
        skipped = gaps.skipped_files
        if skipped and (not gaps.reviewed_files or any(why == "error" for _, why in skipped)):
            reasons.append(f"skipped:{len(skipped)}")
        if gaps.dropped_entries > 0:
            reasons.append(f"unknown_category:{gaps.dropped_entries}")
    return tuple(reasons)


# Lower-case substrings of a declared vendor or a host id. Multi-model hosts (cursor, copilot,
# windsurf, kiro) map to nothing: their generating model, so their independence, is unknown.
_VENDOR_KEYS = (
    ("openai", "openai"), ("codex", "openai"),
    ("anthropic", "anthropic"), ("claude", "anthropic"),
    ("google", "google"), ("gemini", "google"), ("antigravity", "google"),
)


def _vendor_of(label: Optional[str]) -> Optional[str]:
    low = (label or "").strip().lower()
    return next((vendor for key, vendor in _VENDOR_KEYS if low and key in low), None)


def vendor_warning(declared: Optional[str], generator_label: Optional[str]) -> str:
    """The T6 cross-vendor advisory: the user's declared arbiter vendor against the generating
    host's label. '' when nothing is declared or the two differ."""
    if not (declared or "").strip():
        return ""
    generator = _vendor_of(generator_label)
    if generator is None:
        return "Vendor independence unverified: generating host is unknown."
    if _vendor_of(declared) == generator:
        return "Same-vendor arbiter provides prompt isolation only, not model independence."
    return ""


def _compute_verdict(
    divergences: list[Divergence],
    layer1_failures: list[ToolEvidence],
) -> Verdict:
    """Deterministic verdict computation. The verdict is advisory (T6 is log-only).

    BLOCK if any Layer 1 tool FAILS or an unmatched prediction is critical.
    REVISE if an unmatched prediction is HIGH. SHIP otherwise.

    A Spec Agent failure is not a verdict: it only sets infra_status 'unverified'.
    The contradicted_claim, confirmed_risk and undetected_by_both divergences each
    need a failing Layer 1 row, so the first check already returns BLOCK for them.
    """
    if layer1_failures:
        return Verdict.BLOCK

    for d in divergences:
        if d.prediction and d.prediction.severity == Severity.CRITICAL:
            return Verdict.BLOCK

    for d in divergences:
        if d.prediction and d.prediction.severity == Severity.HIGH:
            return Verdict.REVISE

    return Verdict.SHIP


# ── T6: Calibration ───────────────────────────────────────────────────────


def _extract_prob_outcome(item: Any) -> tuple[float, Optional[bool], str, str, str, str]:
    """Return (p, outcome, disposition, scope, observable, pred_id) from Prediction or dict."""
    if isinstance(item, Prediction):
        return (
            float(item.p),
            item.outcome,
            str(item.disposition or "logged"),
            str(item.scope or item.affected_function or item.id),
            str(item.observable or "fix_touch_in_window"),
            str(item.id),
        )
    if isinstance(item, dict):
        out = item.get("outcome", item.get("correct"))
        return (
            float(item.get("p", item.get("confidence", 0.5))),
            None if out is None else bool(out),
            str(item.get("disposition", "logged")),
            str(item.get("scope") or item.get("target") or item.get("affected_function") or item.get("id") or ""),
            str(item.get("observable") or item.get("claim_type") or "fix_touch_in_window"),
            str(item.get("id", "")),
        )
    if isinstance(item, (tuple, list)) and len(item) >= 2:
        return (float(item[0]), bool(item[1]), "logged", "", "fix_touch_in_window", "")
    return (0.5, None, "logged", "", "fix_touch_in_window", "")


def brier_skill_score(predictions_or_probs: Sequence[Any], outcomes: Optional[Sequence[Any]] = None) -> float:
    """Compute Brier Skill Score (1 - BS / BS_climatology)."""
    if outcomes is not None:
        pairs = [
            (float(p), 1.0 if bool(y) else 0.0)
            for p, y in zip(predictions_or_probs, outcomes)
            if y is not None
        ]
    else:
        pairs = [
            (p, 1.0 if out else 0.0)
            for p, out, disp, *_ in map(_extract_prob_outcome, predictions_or_probs)
            if disp in ("logged", "overridden") and out is not None
        ]
    if not pairs:
        return 0.0
    n = len(pairs)
    bs = sum((p - y) ** 2 for p, y in pairs) / n
    base_rate = sum(y for _, y in pairs) / n
    bs_clim = base_rate * (1.0 - base_rate)
    if bs_clim <= 1e-12:
        return 0.0
    return 1.0 - (bs / bs_clim)


def score_predictions(records: Sequence[Any], outcomes: Optional[dict[str, bool]] = None) -> dict[str, Any]:
    """Score predictions excluding 'heeded' and deduplicating by (scope, observable)."""
    n_heeded = 0
    raw_eligible: list[tuple[float, bool, str, str, Any]] = []
    for idx, rec in enumerate(records):
        p, out, disp, scope, obs, pid = _extract_prob_outcome(rec)
        if out is None and outcomes is not None:
            if pid and pid in outcomes:
                out = bool(outcomes[pid])
            elif scope and scope in outcomes:
                out = bool(outcomes[scope])
        if disp == "heeded":
            n_heeded += 1
        elif disp in ("logged", "overridden") and out is not None:
            raw_eligible.append((p, bool(out), scope or f"__anon_{idx}", obs, rec))

    seen_keys: set[tuple[str, str]] = set()
    deduped: list[tuple[float, bool, str, str, Any]] = []
    for entry in raw_eligible:
        dedup_key = (entry[2], entry[3])
        if dedup_key not in seen_keys:
            seen_keys.add(dedup_key)
            deduped.append(entry)

    n_effective = len(deduped)
    hits = sum(1 for _, out, *_ in deduped if out)
    precision = (hits / n_effective) if n_effective > 0 else 0.0
    brier = (
        sum((p - (1.0 if out else 0.0)) ** 2 for p, out, *_ in deduped) / n_effective
        if n_effective > 0
        else None
    )
    raw_bss = (
        brier_skill_score([p for p, *_ in deduped], [out for _, out, *_ in deduped])
        if n_effective > 0
        else 0.0
    )
    lift_suppressed = bool(n_effective < 100 or precision < 0.05)
    return {
        "status": f"insufficient (n={n_effective}/25)" if n_effective < 25 else "ok",
        "n_total": len(records),
        "n_heeded_excluded": n_heeded,
        "n_raw": len(raw_eligible),
        "n_effective": n_effective,
        "hits": hits,
        "k": hits,
        "precision": precision,
        "accuracy": precision,
        "base_rate": precision,
        "wilson_ci": wilson_ci(hits, n_effective),
        "brier_score": brier,
        "brier_skill_score": None if lift_suppressed else raw_bss,
        "raw_brier_skill_score": raw_bss,
        "lift_suppressed": lift_suppressed,
        "scored_predictions": [e[4] for e in deduped],
    }


class CalibrationSummary(dict):
    def __str__(self) -> str:
        return str(self.get("summary", super().__str__()))

    def __contains__(self, item: object) -> bool:
        return super().__contains__(item) or (isinstance(item, str) and item in str(self.get("summary", "")))


def calibration_summary(records: Sequence[Any], outcomes: Optional[dict[str, bool]] = None) -> CalibrationSummary:
    """Build calibration summary with sample-size gates, Wilson 95% CI, and Brier skill score."""
    s = score_predictions(records, outcomes=outcomes)
    lo, hi = s["wilson_ci"]
    bss = s["brier_skill_score"]
    if bss is not None:
        bss_str = f"brier_skill_score={bss:.3f}"
    else:
        bss_str = "brier_skill_score=suppressed (requires n_effective>=100 and base_rate>=5%)"
    s["summary"] = (
        f"status: {s['status']} | n_effective={s['n_effective']} (n_raw={s['n_raw']}, heeded_excluded={s['n_heeded_excluded']}) | "
        f"precision={s['precision']:.1%} (Wilson 95% CI [{lo:.2f}, {hi:.2f}]) | {bss_str}"
    )
    return CalibrationSummary(s)
