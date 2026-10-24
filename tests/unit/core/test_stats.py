"""Unit tests for Layer 0 statistical primitives (aegis_core.stats)."""
from __future__ import annotations

import ast
from pathlib import Path
import re

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


def test_regularized_incomplete_beta_at_known_points():
    assert stats.regularized_incomplete_beta(2.0, 3.0, 0.0) == 0.0
    assert stats.regularized_incomplete_beta(2.0, 3.0, 1.0) == 1.0
    val = stats.regularized_incomplete_beta(2.0, 2.0, 0.5)
    assert val == pytest.approx(0.5, abs=1e-9)


# ── exact values from closed forms, and the clamps (R-cli-a2) ────────────────
# Each expected value is computed independently of the module; they pin the primitives that
# gate promote and demote decisions.

def test_the_wilson_lower_bound_at_k_equals_n_is_its_closed_form():
    z = stats.Z95
    expected = (1 + z * z / 50 - z * (z * z / 2500) ** 0.5) / (1 + z * z / 25)
    assert expected == pytest.approx(0.8668077490609514, abs=1e-15)
    assert stats.wilson_lower_bound(25, 25, z=z) == pytest.approx(expected, abs=1e-12)


def test_the_incomplete_beta_matches_closed_forms_and_its_symmetry():
    assert stats.regularized_incomplete_beta(1.0, 4.0, 0.3) == pytest.approx(1 - 0.7 ** 4, abs=1e-12)
    assert 1 - 0.7 ** 4 == pytest.approx(0.7599, abs=1e-15)
    assert stats.beta_cdf(0.3, 2.0, 5.0) == pytest.approx(1 - stats.beta_cdf(0.7, 5.0, 2.0), abs=1e-12)


def test_counts_out_of_range_are_clamped_not_raised():
    assert stats.wilson_interval(15, 10) == pytest.approx((0.7224598312333834, 1.0), abs=1e-12)
    assert stats.wilson_interval(15, 10) == stats.wilson_interval(10, 10)
    assert stats.wilson_interval(float("nan"), 10) == pytest.approx((0.0, 0.2775401687666165), abs=1e-12)
    assert stats.wilson_interval(float("nan"), 10) == stats.wilson_interval(0, 10)
    assert stats.wilson_interval(5, -1) == (0.0, 1.0)


def test_the_beta_function_clamps_at_its_domain_edges():
    assert stats.regularized_incomplete_beta(2.0, 3.0, -0.1) == 0.0
    assert stats.regularized_incomplete_beta(2.0, 3.0, 1.5) == 1.0


# ── R-evidence-18: one confidence convention, no Clopper-Pearson stack ───────

def test_a_z_score_passed_as_the_confidence_is_refused_and_z_is_named():
    """Given 10 of 15, When 1.645 is passed positionally (the old fitness wrapper's z), Then it is refused
    instead of silently selecting a 95% interval; z=1.645 is the 90% interval."""
    with pytest.raises(ValueError, match="pass z= for a z-score"):
        stats.wilson_interval(10, 15, 1.645)
    assert stats.wilson_interval(10, 15, z=1.645) == stats.wilson_interval(10, 15, 0.90)
    assert stats.wilson_lower_bound(10, 15, z=1.645) == stats.wilson_lower_bound(10, 15, 0.90)


@pytest.mark.parametrize("confidence", [0, 1.0, -0.5, 1.96], ids=["zero", "one", "negative", "z95"])
def test_a_confidence_outside_zero_and_one_raises_even_with_no_data(confidence):
    for successes, total in ((10, 15), (0, 0)):
        with pytest.raises(ValueError, match="confidence must be between 0 and 1"):
            stats.wilson_interval(successes, total, confidence)
        with pytest.raises(ValueError, match="confidence must be between 0 and 1"):
            stats.wilson_lower_bound(successes, total, confidence)


_REPO = Path(__file__).resolve().parents[3]


def _module(name: str) -> ast.Module:
    return ast.parse((_REPO / "aegis_core" / f"{name}.py").read_text(encoding="utf-8"))


def test_fitness_uses_every_import_and_reexports_nothing_from_stats():
    tree = _module("fitness")
    imported, from_stats = {}, set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module != "__future__":
            for alias in node.names:
                imported[alias.asname or alias.name] = node.module
                if node.module == "aegis_core.stats":
                    from_stats.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported[(alias.asname or alias.name).split(".")[0]] = alias.name
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    from aegis_core import fitness

    assert [name for name in imported if name not in used and name not in fitness.__all__] == []
    assert from_stats & set(fitness.__all__) == set()


def test_no_private_function_of_fitness_or_stats_is_dead():
    sources = "\n".join(p.read_text(encoding="utf-8") for top in ("aegis_cli", "aegis_core", "aegis_mcp", "aegis_sdk",
                                                                     "tests") for p in (_REPO / top).rglob("*.py"))
    dead = [f"{module}.{node.name}" for module in ("fitness", "stats") for node in _module(module).body
            if isinstance(node, ast.FunctionDef) and node.name.startswith("_")
            and len(re.findall(rf"\b{re.escape(node.name)}\b", sources)) < 2]
    assert dead == []


def test_the_clopper_pearson_stack_is_gone():
    for name in ("beta_ppf", "clopper_pearson_interval", "clopper_pearson_lower", "clopper_pearson_upper"):
        assert not hasattr(stats, name) and name not in stats.__all__, name
