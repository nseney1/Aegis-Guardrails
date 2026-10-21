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


# ── exact values from closed forms, and the clamps (R-cli-a2) ────────────────
# Each expected value is computed independently of the module; they pin the primitives that
# gate promote and demote decisions.

def test_the_wilson_lower_bound_at_k_equals_n_is_its_closed_form():
    z = stats.Z95
    expected = (1 + z * z / 50 - z * (z * z / 2500) ** 0.5) / (1 + z * z / 25)
    assert expected == pytest.approx(0.8668077490609514, abs=1e-15)
    assert stats.wilson_lower_bound(25, 25, z=z) == pytest.approx(expected, abs=1e-12)


def test_clopper_pearson_at_the_edges_is_the_power_rule():
    assert stats.clopper_pearson_lower(25, 25, alpha=0.05) == pytest.approx(0.05 ** (1 / 25), abs=1e-12)
    assert 0.05 ** (1 / 25) == pytest.approx(0.8870718549931568, abs=1e-15)
    lo, hi = stats.clopper_pearson_interval(25, 25, alpha=0.10)
    assert lo == pytest.approx(0.8870718549931568, abs=1e-12) and hi == 1.0
    assert stats.clopper_pearson_upper(0, 25, alpha=0.05) == pytest.approx(1 - 0.05 ** (1 / 25), abs=1e-12)
    assert 1 - 0.05 ** (1 / 25) == pytest.approx(0.11292814500684323, abs=1e-15)


def test_the_incomplete_beta_matches_closed_forms_and_its_symmetry():
    assert stats.regularized_incomplete_beta(1.0, 4.0, 0.3) == pytest.approx(1 - 0.7 ** 4, abs=1e-12)
    assert 1 - 0.7 ** 4 == pytest.approx(0.7599, abs=1e-15)
    assert stats.beta_cdf(0.3, 2.0, 5.0) == pytest.approx(1 - stats.beta_cdf(0.7, 5.0, 2.0), abs=1e-12)
    assert stats.beta_cdf(stats.beta_ppf(0.9, 3.0, 4.0), 3.0, 4.0) == pytest.approx(0.9, abs=1e-9)


def test_a_prior_is_capped_at_a_mass_of_ten():
    expected = (0.32008652958872397, 0.6799134704112758)
    capped = stats.clopper_pearson_interval(5, 10, prior=(100, 100))
    assert capped == stats.clopper_pearson_interval(5, 10, prior=(5, 5))
    assert capped == pytest.approx(expected, abs=1e-12)


def test_counts_out_of_range_are_clamped_not_raised():
    assert stats.wilson_interval(15, 10) == pytest.approx((0.7224598312333834, 1.0), abs=1e-12)
    assert stats.wilson_interval(15, 10) == stats.wilson_interval(10, 10)
    assert stats.wilson_interval(float("nan"), 10) == pytest.approx((0.0, 0.2775401687666165), abs=1e-12)
    assert stats.wilson_interval(float("nan"), 10) == stats.wilson_interval(0, 10)
    assert stats.wilson_interval(5, -1) == (0.0, 1.0)


@pytest.mark.parametrize("fn,alpha,expected", [
    (stats.clopper_pearson_upper, 0.0, 1.0),
    (stats.clopper_pearson_upper, 1.0, 0.0),
    (stats.clopper_pearson_lower, 0.0, 0.0),
    (stats.clopper_pearson_lower, 1.0, 1.0),
], ids=["upper-0", "upper-1", "lower-0", "lower-1"])
def test_a_degenerate_alpha_gives_the_trivial_bound(fn, alpha, expected):
    assert fn(5, 10, alpha=alpha) == expected


def test_quantiles_and_the_beta_function_clamp_at_their_domain_edges():
    assert stats.beta_ppf(0, 2.0, 3.0) == 0.0 and stats.beta_ppf(1, 2.0, 3.0) == 1.0
    assert stats.regularized_incomplete_beta(2.0, 3.0, -0.1) == 0.0
    assert stats.regularized_incomplete_beta(2.0, 3.0, 1.5) == 1.0
