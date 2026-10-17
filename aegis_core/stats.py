"""Shared statistical primitives (Layer 0: pure math, zero runtime dependencies)."""
from __future__ import annotations

import math
from typing import Any, Optional, Tuple

from aegis_core.taxonomy import DEFAULT_CONFIDENCE_LEVEL, WILSON_CONFIDENCE_Z_SCORES

__all__ = [
    "Z95",
    "beta_cdf",
    "beta_ppf",
    "clopper_pearson_interval",
    "clopper_pearson_lower",
    "clopper_pearson_upper",
    "regularized_incomplete_beta",
    "wilson_ci",
    "wilson_interval",
    "wilson_lower_bound",
]

Z95 = 1.959963984540054


def _num(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        try:
            value = float(value)
        except (TypeError, ValueError):
            return 0.0
    v = float(value)
    return v if math.isfinite(v) and v > 0.0 else 0.0


def _resolve_z(confidence: float, z: Optional[float]) -> float:
    if z is not None:
        return float(z)
    conf = float(confidence)
    if conf >= 1.0:
        return conf
    rounded = round(conf, 2)
    if rounded in WILSON_CONFIDENCE_Z_SCORES:
        return WILSON_CONFIDENCE_Z_SCORES[rounded]
    return Z95


def wilson_interval(
    successes: float,
    total: float,
    confidence: float = 0.95,
    *,
    z: Optional[float] = None,
) -> Tuple[float, float]:
    """Two-sided Wilson score confidence interval ``(lower, upper)`` in ``[0, 1]``."""
    n = _num(total)
    if n <= 0.0:
        return (0.0, 1.0)
    z_val = _resolve_z(confidence, z)
    p = min(_num(successes), n) / n
    z2 = z_val * z_val
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    spread = z_val * math.sqrt(max(0.0, (p * (1.0 - p) + z2 / (4.0 * n)) / n)) / denom
    return (max(0.0, center - spread), min(1.0, center + spread))


def wilson_ci(k: int, n: int, z: float = Z95) -> Tuple[float, float]:
    """Two-sided Wilson score confidence interval ``(lower, upper)`` for ``k / n``."""
    return wilson_interval(k, n, z=z)


def wilson_lower_bound(
    successes: float,
    total: float,
    confidence: float = DEFAULT_CONFIDENCE_LEVEL,
    *,
    z: Optional[float] = None,
) -> float:
    """Lower bound of the Wilson interval (0.0 when ``total <= 0``)."""
    if _num(total) <= 0.0:
        return 0.0
    return wilson_interval(successes, total, confidence, z=z)[0]


def _betacf(a: float, b: float, x: float) -> float:
    fpmin = 1.0e-300
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < fpmin:
        d = fpmin
    d = 1.0 / d
    h = d
    for m in range(1, 201):
        m2 = 2 * m
        aa_even = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa_even * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa_even / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        h *= d * c

        aa_odd = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa_odd * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa_odd / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 3.0e-14:
            break
    return h


def regularized_incomplete_beta(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta function $I_x(a, b)$."""
    if x <= 0.0 or a <= 0.0 or b <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    bt = math.exp(
        a * math.log(x)
        + b * math.log(1.0 - x)
        - (math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b))
    )
    if x < (a + 1.0) / (a + b + 2.0):
        val = bt * _betacf(a, b, x) / a
    else:
        val = 1.0 - bt * _betacf(b, a, 1.0 - x) / b
    return max(0.0, min(1.0, val))


def beta_cdf(x: float, a: float, b: float) -> float:
    """Cumulative distribution function of Beta(a, b) at x."""
    return regularized_incomplete_beta(a, b, x)


def beta_ppf(q: float, a: float, b: float) -> float:
    """Percent-point function (inverse CDF) of Beta(a, b) via 52-step bisection."""
    if q <= 0.0:
        return 0.0
    if q >= 1.0:
        return 1.0
    lo = 0.0
    hi = 1.0
    for _ in range(52):
        mid = 0.5 * (lo + hi)
        if regularized_incomplete_beta(a, b, mid) < q:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


def clopper_pearson_upper(k: float, n: float, alpha: float = 0.05) -> float:
    """One-sided Clopper-Pearson upper confidence bound at level ``1 - alpha``."""
    total = _num(n)
    succ = _num(k)
    if total <= 0.0 or succ >= total:
        return 1.0
    if alpha <= 0.0:
        return 1.0
    if alpha >= 1.0:
        return 0.0
    if succ <= 0.0:
        return max(0.0, min(1.0, 1.0 - (alpha ** (1.0 / total))))
    return max(0.0, min(1.0, beta_ppf(1.0 - alpha, succ + 1.0, total - succ)))


def clopper_pearson_lower(k: float, n: float, alpha: float = 0.05) -> float:
    """One-sided Clopper-Pearson lower confidence bound at level ``1 - alpha``."""
    total = _num(n)
    succ = min(_num(k), total)
    if total <= 0.0 or succ <= 0.0:
        return 0.0
    if alpha <= 0.0:
        return 0.0
    if alpha >= 1.0:
        return 1.0
    if succ >= total:
        return max(0.0, min(1.0, alpha ** (1.0 / total)))
    return max(0.0, min(1.0, beta_ppf(alpha, succ, total - succ + 1.0)))


def clopper_pearson_interval(
    tp: float,
    n: float,
    alpha: float = 0.10,
    *,
    prior: Optional[Tuple[float, float]] = None,
) -> Tuple[float, float]:
    """Two-sided Clopper-Pearson confidence interval ``(lower, upper)``."""
    k = _num(tp)
    total = _num(n)
    if prior is not None:
        a_raw = max(0.0, float(prior[0]))
        b_raw = max(0.0, float(prior[1]))
        mass = a_raw + b_raw
        if mass > 10.0 and mass > 0.0:
            a0 = a_raw * (10.0 / mass)
            b0 = b_raw * (10.0 / mass)
        else:
            a0 = a_raw
            b0 = b_raw
    else:
        a0 = 0.0
        b0 = 0.0
    eff_k = k + a0
    eff_fail = max(0.0, total - k) + b0
    if eff_k + eff_fail <= 0.0:
        return (0.0, 1.0)
    lo = 0.0 if eff_k <= 0.0 else beta_ppf(alpha / 2.0, eff_k, eff_fail + (1.0 if a0 == 0.0 else 0.0))
    hi = 1.0 if eff_fail <= 0.0 else beta_ppf(1.0 - alpha / 2.0, eff_k + (1.0 if b0 == 0.0 else 0.0), eff_fail)
    return (max(0.0, lo), min(1.0, hi))
