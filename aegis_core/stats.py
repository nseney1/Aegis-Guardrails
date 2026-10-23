"""Shared statistical primitives (Layer 0: pure math, zero runtime dependencies)."""
from __future__ import annotations

import math
from typing import Any, Optional, Tuple

from aegis_core.taxonomy import DEFAULT_CONFIDENCE_LEVEL, WILSON_CONFIDENCE_Z_SCORES

__all__ = [
    "Z95",
    "beta_cdf",
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
    # A z-score passed where the confidence goes (1.645, 1.96) fails here rather than reading as 95%.
    if not 0.0 < float(confidence) < 1.0:
        raise ValueError("confidence must be between 0 and 1; pass z= for a z-score")
    return float(z) if z is not None else WILSON_CONFIDENCE_Z_SCORES.get(round(float(confidence), 2), Z95)


def wilson_interval(
    successes: float,
    total: float,
    confidence: float = 0.95,
    *,
    z: Optional[float] = None,
) -> Tuple[float, float]:
    """Two-sided Wilson score confidence interval ``(lower, upper)`` in ``[0, 1]``."""
    z_val = _resolve_z(confidence, z)
    n = _num(total)
    if n <= 0.0:
        return (0.0, 1.0)
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
    z_val = _resolve_z(confidence, z)
    if _num(total) <= 0.0:
        return 0.0
    return wilson_interval(successes, total, z=z_val)[0]


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
