"""Mathematical invariants of the one fitness estimator (seeded properties, stdlib only)."""
from __future__ import annotations

from functools import partial
import math
import random

import pytest

from aegis_core import stats
from aegis_core.fitness import compute
from aegis_core.taxonomy import DEFAULT_CONFIDENCE_LEVEL

# The fitness estimator's 90% interval: aegis_core.stats defaults to 95%.
wilson_interval = partial(stats.wilson_interval, confidence=DEFAULT_CONFIDENCE_LEVEL)
wilson_lower_bound = partial(stats.wilson_lower_bound, confidence=DEFAULT_CONFIDENCE_LEVEL)


def _pairs(seed: int, count: int, high: int):
    rng = random.Random(seed)
    for _ in range(count):
        yield rng.randint(0, high), rng.randint(0, high)


def test_the_interval_is_ordered_and_inside_the_unit_interval():
    for tp, fp in _pairs(1, 500, 1000):
        lower, upper = wilson_interval(tp, tp + fp)
        assert 0.0 <= lower <= upper <= 1.0
        if tp + fp:
            assert lower <= tp / (tp + fp) + 1e-9 <= upper + 2e-9


def test_more_data_at_the_same_rate_narrows_the_interval():
    rng = random.Random(2)
    for _ in range(300):
        tp, fp, scale = rng.randint(1, 100), rng.randint(0, 100), rng.randint(2, 5)
        lo1, hi1 = wilson_interval(tp, tp + fp)
        lo2, hi2 = wilson_interval(tp * scale, (tp + fp) * scale)
        assert hi2 - lo2 <= hi1 - lo1 + 1e-9


def test_fitness_rises_with_true_positives_and_falls_with_false_positives():
    for tp, fp in _pairs(3, 500, 2000):
        base = compute({"tp": tp, "fp": fp}).score
        assert compute({"tp": tp + 1, "fp": fp}).score >= base
        assert compute({"tp": tp, "fp": fp + 1}).score <= base


@pytest.mark.parametrize("bad", [-5, 0, 10**8, float("nan"), float("inf"), -float("inf"), None, "x", True])
def test_corrupt_counts_never_raise_and_stay_bounded(bad):
    for n in (bad, 10, 0):
        value = wilson_lower_bound(bad, n)
        assert isinstance(value, float) and 0.0 <= value <= 1.0 and not math.isnan(value)
    fit = compute({"tp": bad, "fp": bad, "triggers": 3, "last_ts": "garbage"})
    assert 0.0 <= fit.score <= 1.0 and 0.0 <= fit.misfire <= 1.0


def test_a_future_trigger_time_does_not_raise_fitness():
    totals = {"tp": 20, "fp": 0, "last_ts": "2099-01-01T00:00:00Z"}
    # Calendar time never decays a rule (R-evidence-15), so a future timestamp changes nothing.
    assert compute(totals).score == compute({**totals, "last_ts": None}).score
