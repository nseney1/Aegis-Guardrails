"""Wilson interval boundaries of the one fitness estimator (aegis_core.fitness).

Ported from the v3 bayesian_posterior tests: the interval behaviour they pinned is the
estimator every lifecycle threshold is now read against.
"""
from functools import partial

from aegis_core import stats
from aegis_core.taxonomy import DEFAULT_CONFIDENCE_LEVEL, WILSON_CONFIDENCE_Z_SCORES

# The fitness estimator's 90% interval: aegis_core.stats defaults to 95%.
wilson_interval = partial(stats.wilson_interval, confidence=DEFAULT_CONFIDENCE_LEVEL)


class TestWilsonBoundaries:
    def test_higher_confidence_widens_the_interval(self):
        lo90, hi90 = wilson_interval(10, 15, z=WILSON_CONFIDENCE_Z_SCORES[0.90])
        lo95, hi95 = wilson_interval(10, 15, z=WILSON_CONFIDENCE_Z_SCORES[0.95])
        assert hi95 - lo95 > hi90 - lo90

    def test_all_successes_have_a_high_lower_bound(self):
        lower, _ = wilson_interval(20, 20)
        assert lower > 0.85

    def test_all_failures_have_a_low_upper_bound(self):
        _, upper = wilson_interval(0, 20)
        assert upper < 0.15

    def test_balanced_evidence_is_centred(self):
        lower, upper = wilson_interval(10, 20)
        assert 0.2 < lower < 0.5 < upper < 0.8

    def test_one_observation_is_a_wide_interval(self):
        lower, upper = wilson_interval(1, 1)
        assert upper - lower > 0.3

    def test_no_observation_is_the_whole_unit_interval(self):
        assert wilson_interval(0, 0) == (0.0, 1.0)
