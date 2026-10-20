"""Fitness at read time (defense #15, ADR 0005 H6): one estimator, one decay, the ledger only.

A rule's fitness is the Wilson lower bound (90%) of its true-positive rate over the
verdict rows in .aegis/state/ledger.jsonl, halved every `expiry` days (the
repository config) since its last trigger. Nothing is read from rule frontmatter.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aegis_core.fitness import Fitness, compute, for_rules, wilson_interval, wilson_lower_bound
from aegis_core.rules import load_rules
from aegis_core.telemetry_engine import ledger

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_wilson_lower_bound_known_values() -> None:
    assert wilson_lower_bound(0, 0) == 0.0
    assert wilson_lower_bound(20, 20) == pytest.approx(0.8808, abs=1e-4)
    assert wilson_lower_bound(9, 10) == pytest.approx(0.6523, abs=1e-4)
    assert wilson_lower_bound(0, 5) == 0.0
    lo, hi = wilson_interval(5, 10)
    assert 0.0 < lo < 0.5 < hi < 1.0


def test_wilson_lower_bound_is_bounded_and_monotone_in_successes() -> None:
    for n in range(1, 40):
        bounds = [wilson_lower_bound(k, n) for k in range(n + 1)]
        assert all(0.0 <= b <= 1.0 for b in bounds)
        assert bounds == sorted(bounds)
    # More evidence at the same rate is more certain.
    assert wilson_lower_bound(80, 100) > wilson_lower_bound(8, 10)
    # Fractional (credit-weighted) counts are valid input; counts are clamped to n.
    assert 0.0 < wilson_lower_bound(2.5, 3.0) < 1.0
    assert wilson_lower_bound(7, 5) == wilson_lower_bound(5, 5)


def test_fitness_is_the_wilson_bound_of_verdicts_without_decay() -> None:
    fit = compute({"triggers": 30, "tp": 18, "fp": 2, "last_ts": None}, rule="r")

    assert isinstance(fit, Fitness)
    assert (fit.rule, fit.triggers, fit.tp, fit.fp, fit.verdicts) == ("r", 30, 18, 2, 20)
    assert fit.score == pytest.approx(wilson_lower_bound(18, 20), abs=1e-4)
    assert fit.misfire == pytest.approx(wilson_lower_bound(2, 20), abs=1e-4)


def test_trigger_rows_without_a_verdict_are_not_failures() -> None:
    """A `partial` report (or a check run with no verdict) says the rule was relevant."""
    plain = compute({"triggers": 10, "tp": 10, "fp": 0})
    with_extra_triggers = compute({"triggers": 50, "tp": 10, "fp": 0})
    assert with_extra_triggers.score == plain.score


def test_a_rule_without_evidence_has_fitness_zero() -> None:
    fit = compute({})
    assert (fit.triggers, fit.tp, fit.fp, fit.last_ts, fit.score, fit.misfire) == (0, 0, 0, None, 0.0, 0.0)


@pytest.mark.parametrize(("age_days", "factor"), [(0, 1.0), (30, 0.5), (60, 0.25), (15, 0.5 ** 0.5)])
def test_fitness_halves_every_half_life_since_the_last_trigger(age_days: int, factor: float) -> None:
    totals = {"triggers": 20, "tp": 20, "fp": 0, "last_ts": _iso(NOW - timedelta(days=age_days))}
    undecayed = wilson_lower_bound(20, 20)
    fit = compute(totals, half_life_days=30, now=NOW)
    assert fit.score == pytest.approx(undecayed * factor, abs=1e-4)


def test_no_half_life_or_no_usable_timestamp_means_no_decay() -> None:
    old = {"triggers": 20, "tp": 20, "fp": 0, "last_ts": "2020-01-01T00:00:00Z"}
    assert compute(old, half_life_days=None, now=NOW).score == pytest.approx(wilson_lower_bound(20, 20), abs=1e-4)
    for ts in (None, "not a date", _iso(NOW + timedelta(days=10))):
        fit = compute(dict(old, last_ts=ts), half_life_days=30, now=NOW)
        assert fit.score == pytest.approx(wilson_lower_bound(20, 20), abs=1e-4)


def _workspace(tmp_path: Path, config: dict | None = None) -> Path:
    for rel, rule_type in (("traps/t.md", "trap"), ("invariants/i.md", "invariant")):
        path = tmp_path / ".aegis" / "rules" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        rid = Path(rel).stem
        path.write_text(
            f"---\nid: {rid}\ntype: {rule_type}\nenforcement: {'gate' if rule_type == 'invariant' else 'advisory'}\n"
            # Frontmatter counters are ignored: fitness comes from the ledger only.
            "fitness:\n  score: 0.99\n  triggers: 500\n  true_positives: 500\n---\nb\n",
            encoding="utf-8",
        )
    if config is not None:
        (tmp_path / ".aegis" / "config.json").write_text(json.dumps(config), encoding="utf-8")
    return tmp_path


def test_for_rules_reads_the_ledger_and_the_configured_half_life_per_type(tmp_path: Path) -> None:
    ws = _workspace(tmp_path, {"v": 1, "expiry": {"days": 30, "per_type": {"invariant": None}}})
    ledger.append(ws, [{"rule": "t", "outcome": "tp", "source": "manual", "key": f"k{n}"} for n in range(5)])
    ledger.append(ws, [{"rule": "i", "outcome": "tp", "source": "manual", "key": f"k{n}"} for n in range(5)])
    later = datetime.now(timezone.utc) + timedelta(days=60)

    fits = for_rules(ws, load_rules(ws).rules, now=later)

    assert set(fits) == {"t", "i"}
    assert (fits["t"].triggers, fits["t"].tp) == (5, 5)
    # The trap decays (30-day half-life, 60 days later); the invariant never expires.
    assert fits["t"].score == pytest.approx(wilson_lower_bound(5, 5) * 0.25, abs=1e-3)
    assert fits["i"].score == pytest.approx(wilson_lower_bound(5, 5), abs=1e-4)


def test_for_rules_counts_weighted_and_v1_rows(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    state = ws / ".aegis" / "state"
    state.mkdir(parents=True)
    rows = [
        {"v": 2, "seq": 1, "ts": _iso(NOW), "rule": "t", "outcome": "tp", "source": "manual", "weight": 0.5},
        {"v": 2, "seq": 2, "ts": _iso(NOW), "rule": "t", "outcome": "fp", "source": "manual"},
        {"cell": "t", "signal": "success", "source": "mcp", "timestamp": _iso(NOW)},  # v1
        # a native session verdict is a local `aegis check` run: a trigger only (R-evidence-1)
        {"v": 2, "seq": 3, "ts": _iso(NOW), "rule": "t", "outcome": "fp", "source": "session"},
    ]
    (state / "ledger.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

    fit = for_rules(ws, load_rules(ws).rules, now=NOW)["t"]

    assert (fit.triggers, fit.tp, fit.fp) == (4, 1.5, 1)
    assert fit.score == pytest.approx(wilson_lower_bound(1.5, 2.5), abs=1e-4)


def test_a_rule_with_no_ledger_rows_scores_zero_whatever_its_frontmatter_says(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    fits = for_rules(ws, load_rules(ws).rules, now=NOW)
    assert {k: (v.triggers, v.score) for k, v in fits.items()} == {"t": (0, 0.0), "i": (0, 0.0)}


# ── One minimum-sample gate (R-evidence-8, spec T4 and section 9) ─────────────
#
# Given fewer than MIN_N verdicts, When fitness is computed, Then the state is
# `insufficient`, nothing is suggested and no number is reported; Given MIN_N, Then the
# decision and the number appear. Decay-archive of a quiet trap does not need verdicts.

from aegis_core.fitness import MIN_N  # noqa: E402


@pytest.mark.parametrize(("rule_type", "tp", "fp"), [
    ("trap", 0, 3), ("gate", 0, 3), ("invariant", 1, 2), ("trap", 1, 3), ("trap", 0, MIN_N - 1),
])
def test_below_min_n_is_insufficient_with_no_suggestion_and_no_number(rule_type: str, tp: int, fp: int) -> None:
    fit = compute({"triggers": tp + fp, "tp": tp, "fp": fp}, rule_type=rule_type)
    assert (fit.state, fit.suggestion, fit.has_min_n) == ("insufficient", None, False)
    assert fit.status_label == f"insufficient (n={tp + fp})"
    assert fit.reported_score is None
    assert fit.as_dict()["reported_score"] is None and fit.as_dict()["status"] == fit.status_label


@pytest.mark.parametrize(("rule_type", "suggestion"), [("trap", "archive"), ("gate", "demote"), ("invariant", "demote")])
def test_min_n_false_positives_decide(rule_type: str, suggestion: str) -> None:
    fit = compute({"triggers": MIN_N, "tp": 0, "fp": MIN_N}, rule_type=rule_type)
    assert (fit.state, fit.suggestion, fit.has_min_n, fit.status_label) == ("decided", suggestion, True, None)
    assert fit.reported_score == fit.score == 0.0


def test_an_explicit_min_n_is_honoured() -> None:
    assert compute({"tp": 0, "fp": 5}, rule_type="gate", min_n=5).state == "decided"
    assert compute({"tp": 0, "fp": 4}, rule_type="gate", min_n=5).state == "insufficient"


def test_the_number_appears_exactly_at_min_n() -> None:
    below = compute({"tp": MIN_N - 2, "fp": 1})
    at = compute({"tp": MIN_N - 1, "fp": 1})
    assert (below.state, below.reported_score) == ("insufficient", None)
    assert at.state != "insufficient" and at.reported_score == at.score > 0.0
    # the raw score is kept for ranking and for derived.json at any n
    assert below.score > 0.0


def test_a_quiet_unpinned_trap_archives_by_decay_at_n_zero() -> None:
    fit = compute({}, rule_type="trap", eligible_sessions=60, half_life_sessions=20, epsilon=0.15)
    assert (fit.state, fit.suggestion, fit.archive_candidate) == ("decided", "archive", True)
    assert fit.reported_score is None
    assert compute({}, rule_type="trap", pinned=True, eligible_sessions=60, half_life_sessions=20,
                   epsilon=0.15).suggestion is None
