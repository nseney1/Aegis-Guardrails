from __future__ import annotations

"""Arbiter: Deterministic divergence detector.

Compares Spec Agent predictions against Code Agent claims, with Layer 1
tool evidence as tiebreaker. Pure set logic — no LLM judgment.

The Arbiter answers three questions:
1. Did the Spec Agent predict a risk that the Code Agent didn't address? (blind spot)
2. Did the Code Agent claim something that Layer 1 tools contradict? (false claim)
3. Did both agree but Layer 1 shows a problem anyway? (shared blind spot)
"""
from pathlib import Path
import time
from typing import Any, Optional, Sequence

from aegis_core.match import is_test_path
from aegis_core.stats import Z95, wilson_ci

from . import (
    ArbitrationResult, Claim, Divergence, Prediction,
    RiskCategory, Severity, ToolEvidence, Verdict,
)


def arbitrate(
    predictions: list[Prediction],
    claims: list[Claim],
    layer1_evidence: list[ToolEvidence],
    *,
    spec_agent_failed: bool = False,
    infra_status: Optional[str] = None,
    changed_files: Optional[list[str]] = None,
    all_files: Optional[Sequence[str]] = None,
    rule_miss_counts: Optional[dict[str, int]] = None,
    arbiter_vendor: Optional[str] = None,
    generator_vendor: Optional[str] = None,
) -> ArbitrationResult:
    """Compare predictions vs claims vs tool evidence.

    Divergence detection is pure set operations on RiskCategory enums.
    No natural language comparison. No LLM.

    Returns ArbitrationResult with divergences, convergences, and verdict.
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
    resolved_infra = (
        infra_status
        if infra_status is not None
        else ("unverified" if spec_agent_failed else "ok")
    )
    gaps = (
        structural_ship_gaps(
            changed_files,
            all_files or (),
            rule_miss_counts=rule_miss_counts,
        )
        if changed_files is not None
        else []
    )
    vendor_warn = (
        check_vendor_independence(arbiter_vendor, generator_vendor)
        if (arbiter_vendor is not None or generator_vendor is not None)
        else ""
    )

    return ArbitrationResult(
        divergences=divergences,
        convergences=convergences,
        verdict=verdict,
        layer1_results=layer1_evidence,
        predictions=predictions,
        claims=claims,
        layer1_verdict=l1_verdict,
        infra_status=resolved_infra,
        llm_predictions=tuple(predictions),
        structural_gaps=gaps,
        vendor_warning=vendor_warn,
    )


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


# ── T6: Structural SHIP Gap Report & Calibration ──────────────────────────


def structural_ship_gaps(
    changed_files: Sequence[str],
    all_files: Sequence[str] = (),
    rule_miss_counts: Optional[dict[str, int]] = None,
    *,
    uncovered_lines: Optional[dict[str, Sequence[int] | set[int]]] = None,
    high_miss_threshold: int = 3,
) -> list[dict[str, Any]]:
    """Deterministically flag changed source files lacking tests, with high rule-miss history, or uncovered lines."""
    pool = {p.replace("\\", "/") for p in (*all_files, *changed_files)}
    test_stems: set[str] = set()
    for p in pool:
        stem = Path(p).stem
        if is_test_path(p) or stem.startswith("test_") or stem.endswith("_test"):
            test_stems.update({stem, stem.removeprefix("test_"), stem.removesuffix("_test")})
    miss_map = rule_miss_counts or {}
    uncov_map = uncovered_lines or {}
    gaps: list[dict[str, Any]] = []
    for raw_path in changed_files:
        norm = raw_path.replace("\\", "/")
        p_obj = Path(norm)
        if is_test_path(norm) or p_obj.name.startswith("test_") or p_obj.name == "__init__.py":
            continue
        reasons = [r for r, cond in (
            ("missing_test", p_obj.suffix in (".py", ".rs", ".js", ".ts", ".go") and p_obj.stem not in test_stems),
            ("high_rule_miss_history", miss_map.get(norm, miss_map.get(raw_path, 0)) >= high_miss_threshold),
            ("uncovered_changed_lines", bool(uncov_map.get(norm, uncov_map.get(raw_path, ())))),
        ) if cond]
        if reasons:
            file_uncov = sorted(uncov_map.get(norm, uncov_map.get(raw_path, ())))
            gaps.append({
                "file": norm, "path": norm, "kind": reasons[0], "reasons": reasons,
                "miss_count": miss_map.get(norm, miss_map.get(raw_path, 0)),
                "uncovered_lines": file_uncov, "detail": ", ".join(reasons),
            })
    return gaps


def _extract_prob_outcome(item: Any) -> tuple[float, Optional[bool], str, str, str, str]:
    """Return (p, outcome, disposition, scope, observable, pred_id) from Prediction or dict."""
    if isinstance(item, Prediction):
        return (
            float(item.p),
            item.outcome,
            str(item.disposition or "logged"),
            str(item.scope or item.target or item.affected_function or item.id),
            str(item.observable or item.claim_type or "fix_touch_in_window"),
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


class PruneResult(dict):
    def __iter__(self):
        yield self["kept"]
        yield self["buckets"]


def prune_predictions(records: Sequence[Any], now_ts: Optional[float] = None, max_age_days: int = 60) -> PruneResult:
    """Compact scored prediction records older than max_age_days into bucket counters."""
    cutoff = float(now_ts if now_ts is not None else time.time()) - (max_age_days * 86400.0)
    kept: list[Any] = []
    pruned_count = 0
    scored_count = 0
    hits = 0
    heeded_count = 0
    sum_brier = 0.0
    bins: dict[str, dict[str, int]] = {}
    for rec in records:
        p, out, disp, *_ = _extract_prob_outcome(rec)
        if isinstance(rec, Prediction):
            rec_ts = float(rec.ts)
        elif isinstance(rec, dict):
            rec_ts = float(rec.get("ts", rec.get("resolved_at", 0.0)) or 0.0)
        else:
            rec_ts = 0.0
        if ((out is not None) or (disp == "heeded")) and 0.0 < rec_ts < cutoff:
            pruned_count += 1
            if disp == "heeded":
                heeded_count += 1
            elif out is not None:
                scored_count += 1
                y = 1 if out else 0
                hits += y
                sum_brier += (p - y) ** 2
                idx = min(4, max(0, int(p * 5)))
                bucket = bins.setdefault(f"{idx * 0.2:.1f}-{(idx + 1) * 0.2:.1f}", {"n": 0, "hits": 0})
                bucket["n"] += 1
                bucket["hits"] += y
        else:
            kept.append(rec)
    buckets = {
        "pruned_count": pruned_count,
        "scored_count": scored_count,
        "hits": hits,
        "heeded_count": heeded_count,
        "sum_brier": sum_brier,
        "bins": bins,
    }
    return PruneResult(kept=kept, active=kept, buckets=buckets, pruned_count=pruned_count)


def _canonical_vendor(raw: Optional[str]) -> str:
    low = (raw or "").strip().lower()
    if not low or low == "unknown":
        return ""
    vendor_families = (
        ("anthropic", ("anthropic", "claude")),
        ("openai", ("openai", "gpt", "codex", "o1", "o3", "o4")),
        ("google", ("google", "gemini", "antigravity", "agy", "vertex")),
    )
    for fam, toks in vendor_families:
        if any(t in low for t in toks):
            return fam
    return low.split("/")[0].split("-")[0]


def check_vendor_independence(arbiter_vendor: Optional[str], generator_vendor: Optional[str]) -> str:
    """Warn when arbiter and generator belong to the same model vendor family or are unknown."""
    arb_fam = _canonical_vendor(arbiter_vendor)
    gen_fam = _canonical_vendor(generator_vendor)
    if not arb_fam or not gen_fam:
        return "Vendor independence unverified: arbiter or generator vendor is unknown."
    if arb_fam == gen_fam:
        return "Same-vendor arbiter provides prompt isolation only, not model independence."
    return ""
