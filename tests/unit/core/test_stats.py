"""Unit tests for Layer 0 statistical primitives (aegis_core.stats)."""
from __future__ import annotations

import pytest

from aegis_core import stats


def test_wilson_interval_and_ci_bounds():
    lo, hi = stats.wilson_interval(0, 0)
    assert (lo, hi) == (0.0, 1.0)
    assert stats.wilson_lower_bound(0, 0) == 0.0

    lo_ci, hi_ci = stats.wilson_ci(25, 25)
    assert 0.85 < lo_ci < 1.0
    assert hi_ci == pytest.approx(1.0)
    assert stats.wilson_lower_bound(25, 25, z=stats.Z95) == pytest.approx(lo_ci)
    assert stats.wilson_lower_bound(25, 25, confidence=0.95) == pytest.approx(lo_ci, abs=1e-5)


def test_regularized_incomplete_beta_and_clopper_pearson():
    assert stats.regularized_incomplete_beta(2.0, 3.0, 0.0) == 0.0
    assert stats.regularized_incomplete_beta(2.0, 3.0, 1.0) == 1.0
    val = stats.regularized_incomplete_beta(2.0, 2.0, 0.5)
    assert val == pytest.approx(0.5, abs=1e-9)

    assert stats.clopper_pearson_upper(0, 0) == 1.0
    assert stats.clopper_pearson_lower(0, 10) == 0.0
    assert stats.clopper_pearson_upper(10, 10) == 1.0
    lo, hi = stats.clopper_pearson_interval(5, 10, alpha=0.05)
    assert 0.18 < lo < 0.5 < hi < 0.82
    assert stats.beta_ppf(0.5, 2.0, 2.0) == pytest.approx(0.5, abs=1e-6)
