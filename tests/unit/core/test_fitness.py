"""Fitness at read time (defense #15, ADR 0005 H6): one estimator, one decay, the ledger only.

A rule's fitness is the Wilson lower bound (90%) of its true-positive rate over the
verdict rows in the ledger. Evidence decays by eligible exposure sessions,
w = 2^(-sessions / half_life_sessions), never by calendar days (R-evidence-15), and
every statistic of the posterior uses the decayed evidence. Nothing is read from rule
frontmatter.
"""
from __future__ import annotations

import json
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path

import pytest

from aegis_core import stats
from aegis_core.fitness import Fitness, compute, for_rules
from aegis_core.rules import load_rules
from aegis_core.taxonomy import DEFAULT_CONFIDENCE_LEVEL
from aegis_core.telemetry_engine import ledger

# The fitness estimator's 90% interval: aegis_core.stats defaults to 95%.
wilson_interval = partial(stats.wilson_interval, confidence=DEFAULT_CONFIDENCE_LEVEL)
wilson_lower_bound = partial(stats.wilson_lower_bound, confidence=DEFAULT_CONFIDENCE_LEVEL)

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


@pytest.mark.parametrize("age_days", [0, 1, 30, 400])
def test_calendar_days_never_decay_a_rule(age_days: int) -> None:
    totals = {"triggers": 40, "tp": 40, "fp": 0, "last_ts": _iso(NOW - timedelta(days=age_days))}
    fit = compute(totals, now=NOW)
    assert fit.effective_weight == 1.0
    assert fit.score == pytest.approx(wilson_lower_bound(40, 40), abs=1e-4)


def test_the_half_life_and_epsilon_are_defined_once() -> None:
    from aegis_core import config, fitness

    assert fitness.DEFAULT_HALF_LIFE_SESSIONS == config.DEFAULT_HALF_LIFE_SESSIONS == 30
    assert fitness.DEFAULT_ARCHIVE_EPSILON == config.DEFAULT_EPSILON == 0.01
    assert fitness.session_decay_factor(30) == pytest.approx(0.5)
    assert compute({}, eligible_sessions=30).effective_weight == pytest.approx(0.5)
    assert not hasattr(fitness, "decay_factor")


def test_the_posterior_decays_with_sessions_and_reverts_to_the_prior() -> None:
    from aegis_core.stats import beta_cdf

    def gate(sessions: int) -> Fitness:
        return compute({}, rule_type="gate", adjudicated_fp=5, min_n=5, eligible_sessions=sessions, half_life_sessions=20)

    fresh, stale = gate(0), gate(60)
    assert fresh.p_below_demote == pytest.approx(0.9993, abs=1e-4)
    assert (fresh.state, fresh.suggestion) == ("decided", "demote")
    assert stale.p_below_demote < 0.9
    assert stale.p_below_demote == pytest.approx(beta_cdf(0.7, 1.0, 1.0 + 5 * 0.125), abs=1e-4)
    assert (stale.state, stale.suggestion) != ("decided", "demote")
    path = [gate(k).p_below_demote for k in (0, 20, 60, 200, 2000)]
    assert path == sorted(path, reverse=True)
    assert path[-1] == pytest.approx(beta_cdf(0.7, 1.0, 1.0), abs=1e-3)  # the uniform prior
    assert gate(2000).fp == 5.0  # the raw count still guards the sample gate


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


def _old_verdicts(ws: Path, rule: str, n: int = 40, days_ago: int = 400) -> None:
    stamp = _iso(NOW - timedelta(days=days_ago))
    ledger.append_rows(ws, [{"v": 2, "ts": stamp, "rule": rule, "outcome": "tp", "source": "ci", "key": f"{rule}-{k}"}
                            for k in range(n)])


@pytest.mark.parametrize("days", [7, 90, None])
def test_the_expiry_config_is_accepted_and_changes_nothing(tmp_path: Path, days) -> None:
    from aegis_core.config import RepoConfig

    ws = _workspace(tmp_path, {"v": 1, "expiry": {"days": days, "per_type": {"invariant": None}}})
    assert RepoConfig.load(ws).warnings == ()
    _old_verdicts(ws, "t")
    _old_verdicts(ws, "i")

    fits = for_rules(ws, load_rules(ws).rules, now=NOW)

    for rid in ("t", "i"):
        assert (fits[rid].triggers, fits[rid].tp, fits[rid].effective_weight) == (40, 40, 1.0)
        assert fits[rid].score == pytest.approx(wilson_lower_bound(40, 40), abs=1e-4)


def test_session_decay_has_no_cliff_at_the_first_session(tmp_path: Path) -> None:
    from aegis_core import credit

    weights = []
    for sessions in (0, 1, 2, 5):
        ws = _workspace(tmp_path / f"s{sessions}")
        _old_verdicts(ws, "t")
        for k in range(sessions):
            credit.record_exposure(ws, "claude-code", f"sess-{k}", ["t"], scope_basis="match", heartbeat=True)
        weights.append(for_rules(ws, [load_rules(ws).get("t")], now=NOW)["t"].effective_weight)
    assert weights == sorted(weights, reverse=True) and weights[0] == 1.0
    assert weights[1] > 0.95


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


def _t4_row(event=None, **fields):
    return {"v": 2, "rule": "t", "ts": "2026-10-08T00:00:00Z", "event": event, **fields}


def test_for_rules_folds_every_t4_event_arm_in_ledger_order(tmp_path: Path, monkeypatch) -> None:
    from tests.helpers_adjudication import write_labels
    from tests.helpers_humangate import Home, Repo

    home = Home(tmp_path / "home")
    for name, value in home.env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home.path / ".config"))
    repo = Repo(tmp_path / "repo", home)
    ws = _workspace(repo.root)
    write_labels(ws, "t", [
        {"example_id": "reviewed-tp", "verdict": "tp", "session": "reviewed-1", "repo": "repo-1",
         "ts": "2026-10-05T00:00:00Z"},
        {"example_id": "reviewed-fp", "verdict": "fp", "session": "reviewed-2", "repo": "repo-2",
         "ts": "2026-10-07T00:00:00Z"},
    ])
    repo.git("add", ".aegis/rules/traps/t.md", ".aegis/rules/invariants/i.md", ".aegis/adjudications/t.jsonl")
    repo.git("commit", "-q", "-m", "reviewed labels")
    repo.git("update-ref", "refs/remotes/origin/main", repo.head())
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    write_labels(ws, "t", [{"example_id": "branch-fp", "verdict": "fp"}])
    rows = [
        _t4_row(outcome="tp", source="ci", ts="2026-10-02T00:00:00Z", key="legacy"),
        _t4_row("exposure", session="s1", heartbeat=True, scope_basis="match"),
        _t4_row("exposure", session="s2", heartbeat=False, scope_basis="match"),
        _t4_row("exposure", session="s3", scope_basis="fallback_unscoped"),
        _t4_row("exposure", session="s4"),
        _t4_row("exposure", session="s5", heartbeat_alive=False),
        _t4_row("exposure", session="early", ts="2026-10-04T00:00:00Z"),
        _t4_row("detection", file="a.py", pattern="eval", rev="one", disposition="leaked", ts="2026-10-03T00:00:00Z"),
        _t4_row("detection", file="a.py", pattern="eval", rev="one", disposition="caught", ts="2026-10-04T00:00:00Z"),
        _t4_row("adjudication", verdict="tp"),
        _t4_row("adjudication", verdict="fp"),
        _t4_row("detection", file="a.py", pattern="eval", rev="one", disposition="leaked", ts="2026-10-06T00:00:00Z"),
        _t4_row("detection", file="a.py", pattern="eval", rev="one", disposition="caught", ts="2026-10-01T00:00:00Z"),
        _t4_row("detection", file="b.py", pattern="exec", rev="one", disposition="leaked", ts="2026-10-09T00:00:00Z"),
        _t4_row("detection", file="a.py", pattern="eval", rev="two", disposition="leaked", ts="2026-10-10T00:00:00Z"),
        _t4_row("override"),
        _t4_row("report", check="unknown-check"),
    ]
    ledger.append_rows(ws, rows)
    rules = load_rules(ws).rules
    now = datetime(2026, 12, 1, tzinfo=timezone.utc)
    fits = for_rules(ws, rules, now)
    assert asdict(fits["t"]) == {
        "rule": "t", "triggers": 1, "tp": 2.5, "fp": 1.0, "last_ts": "2026-10-02T00:00:00Z",
        "score": 0.2943, "misfire": 0.0646, "state": "insufficient", "adjudicated_n": 2,
        "adjudicated_tp": 1, "adjudicated_fp": 1, "caught": 1, "leaked": 2, "contested": 1,
        "override_rate": 0.5, "flagged_for_review": True, "p_below_demote": 0.5907, "prior_mass": 0.0,
        "prior_disclosure": None, "mde": 0.3869, "eligible_sessions": 2, "effective_weight": 0.954842,
        "archive_candidate": False, "sessions_count": 2, "repos_count": 2, "suggestion": None,
        "evidence_available": True, "evidence_error": None, "min_n": 25,
    }
    assert fits["i"] == Fitness(rule="i")
    ledger.append_rows(ws, [_t4_row("detection", rule="unknown", disposition="caught")])
    assert for_rules(ws, rules, now) == fits
    with open(ledger.ledger_path(ws), "ab") as stream:
        stream.write(b"{unreadable json\n")
    assert for_rules(ws, rules, now) == {
        rid: replace(fit, evidence_available=False, evidence_error="1 unreadable line(s)")
        for rid, fit in fits.items()
    }


def test_for_rules_keeps_detection_and_exposure_buckets_independent(tmp_path: Path, monkeypatch) -> None:
    from aegis_core.adjudication import Adjudications

    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    ws = _workspace(tmp_path / "repo")
    ledger.append_rows(ws, [
        _t4_row("detection", file="a.py", pattern="eval", rev="one", disposition="caught", ts="2026-10-10T00:00:00Z"),
        _t4_row("detection", file="a.py", pattern="eval", rev="one", disposition="leaked", ts="2026-10-02T00:00:00Z"),
        _t4_row("detection", rule="i", file="a.py", pattern="eval", rev="one", disposition="caught", ts="2026-10-11T00:00:00Z"),
        _t4_row("exposure", session="shared", heartbeat=False, ts="2026-10-12T00:00:00Z"),
        _t4_row("exposure", session="shared", heartbeat=True, ts="2026-10-12T00:00:00Z"),
        _t4_row("exposure", rule="i", session="shared", heartbeat=True, ts="2026-10-12T00:00:00Z"),
    ])
    rules = list(load_rules(ws).rules)
    fits = for_rules(ws, rules, NOW, adjudications=Adjudications())
    assert (fits["t"].caught, fits["t"].leaked, fits["t"].eligible_sessions, fits["t"].last_ts) == (
        0, 1, 0, "2026-10-10T00:00:00Z",
    )
    assert (fits["i"].caught, fits["i"].leaked, fits["i"].eligible_sessions, fits["i"].last_ts) == (
        1, 0, 1, "2026-10-11T00:00:00Z",
    )
    assert for_rules(ws, reversed(rules), NOW, adjudications=Adjudications()) == fits


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
