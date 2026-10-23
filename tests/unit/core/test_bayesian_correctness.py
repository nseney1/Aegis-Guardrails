"""Wilson score interval reference values (the one fitness estimator, aegis_core.fitness)."""
from aegis_core.stats import wilson_interval


class TestWilsonInterval:
    def test_all_successes_at_95(self):
        lower, upper = wilson_interval(10, 10, z=1.96)
        assert abs(lower - 0.7225) < 0.001
        assert abs(upper - 1.0) < 0.001

    def test_all_failures_at_95(self):
        lower, upper = wilson_interval(0, 10, z=1.96)
        assert abs(lower - 0.0) < 0.001
        assert abs(upper - 0.2775) < 0.001

    def test_half_successes_are_centred(self):
        lower, upper = wilson_interval(5, 10, z=1.645)
        assert 0.25 < lower < 0.40
        assert 0.60 < upper < 0.75

    def test_no_observations_is_full_uncertainty(self):
        assert wilson_interval(0, 0) == (0.0, 1.0)

    def test_one_success_is_not_certainty(self):
        lower, upper = wilson_interval(1, 1, z=1.96)
        assert lower < 1.0
        assert upper > 0.95

    def test_one_failure_is_not_certainty(self):
        lower, upper = wilson_interval(0, 1, z=1.96)
        assert upper > 0.0
        assert lower == 0.0
