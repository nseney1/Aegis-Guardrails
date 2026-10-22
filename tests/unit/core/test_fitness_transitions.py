"""One decision engine (R-evidence-7) and no promotion without labels (R-evidence-4).

``Fitness.compute`` decides a rule's transition; ``promotion.suggest`` only vetoes rules that
never move by evidence (broken, expired, untyped, protected). Every surface (``for_rules``,
``suggest``, ``sync.build``/derived.json, ``evaluate_promotions/demotions/archives``) shows
that one answer, and ``promote``/``demote``/``archive`` appear only in state ``decided``.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis_core import fitness, sync
from aegis_core.lifecycle.promotion import evaluate_demotions, evaluate_promotions, promote_rule, suggest
from aegis_core.lifecycle.selection import evaluate_archives
from aegis_core.rules import load_rules
from tests import helpers_adjudication as ha
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")
NOW = datetime.now(timezone.utc)
STATES = {"untestable", "insufficient", "inconclusive", "decided"}
MOVES = {"promote", "demote", "archive"}


def _old_rule(rule_type: str) -> SimpleNamespace:
    return SimpleNamespace(id="r", type=rule_type, served=True, meta={"created": "2020-01-01"})


def _check_cell(fit: fitness.Fitness, rule_type: str) -> str:
    assert fit.state in STATES, fit
    assert (fit.suggestion in MOVES) == (fit.state == "decided"), fit
    if fit.state == "untestable" or not fit.evidence_available:
        assert fit.suggestion is None, fit
    assert suggest(_old_rule(rule_type), fit, NOW) == fit.suggestion, fit
    return fit.suggestion or ""


@pytest.mark.parametrize("rule_type", ["trap", "invariant", "gate"])
def test_every_tp_fp_cell_shows_one_answer_and_moves_only_when_decided(rule_type: str) -> None:
    """Given every (tp, fp) in 0..40 as local totals and as labels, When compute and suggest run,
    Then they agree and a move appears exactly in state decided."""
    moves = set()
    for tp in range(41):
        for fp in range(41):
            moves.add(_check_cell(fitness.compute({"tp": tp, "fp": fp}, rule_type=rule_type), rule_type))
            moves.add(_check_cell(fitness.compute({}, rule_type=rule_type, adjudicated_tp=tp, adjudicated_fp=fp,
                                                  sessions_count=3, repos_count=2), rule_type))
    unavailable = set()
    for tp in range(0, 41, 5):
        for fp in range(0, 41, 5):
            unavailable.add(_check_cell(fitness.compute({}, rule_type=rule_type, adjudicated_tp=tp, adjudicated_fp=fp,
                                                        sessions_count=3, repos_count=2, evidence_available=False,
                                                        evidence_error="cut short"), rule_type))
    assert unavailable == {""} and "" in moves and moves & MOVES


@pytest.mark.parametrize("age,moved", [(3.0, False), (29.9, False), (30.0, True), (None, True)],
                         ids=["3-days", "29.9-days", "30-days", "no-age"])
def test_the_age_gate_lives_in_compute(age, moved) -> None:
    """Given a trap with decisive labels, When it is younger than 30 days, Then it is not decided."""
    fit = fitness.compute({}, rule_type="trap", adjudicated_tp=40, sessions_count=3, repos_count=2, age_days=age)
    assert (fit.state, fit.suggestion) == (("decided", "promote") if moved else ("inconclusive", None))


@pytest.mark.parametrize("rule_type,move", [("trap", "archive"), ("invariant", "demote"), ("gate", "demote"),
                                            ("persona", "archive")])
def test_a_confident_misfire_moves_down_the_type_ladder_or_out(rule_type: str, move: str) -> None:
    fit = fitness.compute({}, rule_type=rule_type, adjudicated_tp=1, adjudicated_fp=fitness.MIN_N)
    assert (fit.state, fit.suggestion) == ("decided", move)


def test_small_n_never_demotes_whatever_the_wilson_bound() -> None:
    """Three straight false positives clear the old Wilson bound (0.53) but not the sample gate."""
    for fp in (3, 5, fitness.MIN_N - 1):
        fit = fitness.compute({"fp": fp}, rule_type="invariant")
        assert fit.misfire > 0.5 and (fit.state, fit.suggestion) == ("insufficient", None)


def test_unavailable_evidence_is_a_flag_not_a_state() -> None:
    fit = fitness.compute({}, rule_type="trap", adjudicated_fp=30, evidence_available=False, evidence_error="gh failed")
    assert (fit.state, fit.suggestion, fit.evidence_available, fit.status_label) == (
        "inconclusive", None, False, "evidence unavailable")
    assert fitness.compute({"fp": 2}, evidence_available=False).state == "insufficient"


def test_the_age_of_a_rule_is_read_in_fitness_and_still_reachable_from_the_lifecycle() -> None:
    from aegis_core.lifecycle import constants, parsers

    assert parsers.rule_age_days is fitness.rule_age_days
    assert constants.MIN_AGE_DAYS_FOR_PROMOTION == fitness.MIN_AGE_DAYS_FOR_PROMOTION == 30
    rule = SimpleNamespace(meta={"created": (NOW - timedelta(days=12)).strftime("%Y-%m-%d")})
    assert fitness.rule_age_days(rule, NOW) == 12
    assert fitness.rule_age_days(SimpleNamespace(meta={"created": "not a date"}), NOW) == 0


# ── The surfaces agree, through the ledger and labels merged at the reviewed BASE ──

def _rule(ws: Path, rule_type: str, rule_id: str, *, age_days: int = 100, extra: str = "") -> None:
    folder = {"trap": "traps", "invariant": "invariants", "gate": "gates", "persona": "personas"}[rule_type]
    created = (NOW - timedelta(days=age_days)).strftime("%Y-%m-%d")
    enforcement = "gate" if rule_type in ("gate", "invariant") else "advisory"
    path = ws / ".aegis" / "rules" / folder / f"{rule_id}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((f"---\nid: {rule_id}\ntype: {rule_type}\nenforcement: {enforcement}\nhypothesis: h\n"
                      f"created: '{created}'\ntarget_paths: ['src/*.py']\n{extra}---\n# {rule_id}\n\nBody.\n").encode())


def _labelled(ws: Path, rule_id: str, tp: int, fp: int) -> None:
    ha.write_labels(ws, rule_id, ha.labels(rule_id, "tp", tp) + ha.labels(rule_id, "fp", fp))


SCENARIOS = [  # (type, id, tp labels, fp labels, age in days)
    ("invariant", "inv-30", 30, 0, 100),
    ("trap", "trap-25", 25, 0, 100),
    ("trap", "trap-young", 40, 0, 3),
    ("trap", "trap-1-4", 1, 4, 100),
    ("invariant", "inv-1-4", 1, 4, 100),
    ("trap", "trap-3fp", 0, 3, 100),
    ("invariant", "inv-3fp", 0, 3, 100),
    ("persona", "persona-none", 0, 0, 100),
]


@pytest.fixture
def scenario_ws(tmp_path: Path, monkeypatch) -> Path:
    ws = tmp_path / "project"
    for rule_type, rule_id, tp, fp, age in SCENARIOS:
        _rule(ws, rule_type, rule_id, age_days=age)
        if tp or fp:
            _labelled(ws, rule_id, tp, fp)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    ha.merge_to_base(ws)
    return ws


def _surfaces(ws: Path) -> dict:
    rules = load_rules(ws).served
    fits = fitness.for_rules(ws, rules, NOW, verify_ci=True)
    derived = sync.build(ws, now=NOW, verify_ci=True)["rules"]
    listed = {c["rule_id"]: "promote" for c in evaluate_promotions(ws, NOW)}
    listed.update({c["rule_id"]: "demote" for c in evaluate_demotions(ws, NOW)})
    listed.update({c["rule_id"]: "archive" for c in evaluate_archives(ws, NOW)})
    return {r.id: (fits[r.id].suggestion, suggest(r, fits[r.id], NOW), derived[r.id]["suggestion"], listed.get(r.id))
            for r in rules}


@needs_git
def test_every_surface_shows_the_engines_transition(scenario_ws: Path) -> None:
    shown = _surfaces(scenario_ws)
    assert set(shown) == {s[1] for s in SCENARIOS}
    for rule_id, answers in shown.items():
        assert len(set(answers)) == 1, (rule_id, answers)
    assert shown["trap-young"][0] is None and shown["trap-25"][0] == "promote"


@needs_git
def test_protected_and_unserved_rules_get_no_suggestion_anywhere(tmp_path: Path, monkeypatch) -> None:
    ws = tmp_path / "project"
    _rule(ws, "trap", "testing")  # a protected core rule id
    _rule(ws, "trap", "expired", extra="expired_at: '2026-01-01'\n")
    for rule_id in ("testing", "expired"):
        _labelled(ws, rule_id, 25, 0)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    ha.merge_to_base(ws)
    loaded = {r.id: r for r in load_rules(ws).rules}
    fits = fitness.for_rules(ws, loaded.values(), NOW, verify_ci=True)
    derived = sync.build(ws, now=NOW, verify_ci=True)["rules"]
    assert {rid: (suggest(rule, fits[rid], NOW), derived[rid]["suggestion"]) for rid, rule in loaded.items()} == {
        "testing": (None, None), "expired": (None, None)}
    assert evaluate_promotions(ws, NOW) == []


@needs_git
def test_an_unreadable_ledger_line_gives_no_suggestion_and_moves_nothing(tmp_path: Path, monkeypatch) -> None:
    from aegis_core.telemetry_engine import ledger

    ws = tmp_path / "project"
    _rule(ws, "trap", "trap-25")
    _labelled(ws, "trap-25", 25, 0)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    ha.merge_to_base(ws)
    assert sync.build(ws, now=NOW, verify_ci=True)["rules"]["trap-25"]["suggestion"] == "promote"
    ledger.append(ws, [{"rule": "trap-25", "outcome": "tp", "source": "ci", "key": "k1"}])
    with ledger.ledger_path(ws).open("ab") as fh:
        fh.write(b"{garbled\n")
    before = (ws / ".aegis" / "rules" / "traps" / "trap-25.md").read_bytes()
    result = sync.sync(ws, apply=True, now=NOW)
    assert result.derived["rules"]["trap-25"]["suggestion"] is None and result.applied == []
    assert result.refused.startswith("not applied: the ledger is incomplete")
    assert promote_rule(ws, "trap-25")["status"] == "ineligible"
    assert (ws / ".aegis" / "rules" / "traps" / "trap-25.md").read_bytes() == before


# ── No promotion without labels, with a breadth gate (R-evidence-4) ──────────

@pytest.mark.parametrize("sessions,repos,days,moved", [
    (3, 2, 0.0, True), (3, 0, 14.0, True),
    (3, 1, 13.99, False), (2, 2, 31.0, False), (0, 2, 31.0, False), (0, 0, 0.0, False), (3, 0, 0.0, False),
], ids=["3s-2r", "3s-14d", "1-repo-13.99d", "2-sessions", "no-session", "no-breadth", "no-repo-no-span"])
def test_labels_promote_only_with_three_sessions_and_two_repos_or_fourteen_days(sessions, repos, days, moved) -> None:
    fit = fitness.compute({}, rule_type="trap", adjudicated_tp=25, sessions_count=sessions, repos_count=repos,
                          days_span=days)
    assert (fit.state, fit.suggestion) == (("decided", "promote") if moved else ("inconclusive", None))


@pytest.mark.parametrize("tp,fp,moved", [(25, 0, True), (24, 0, False), (25, 1, False), (41, 1, True)],
                         ids=["25-labels", "24-labels", "25-and-1-fp", "41-and-1-fp"])
def test_an_invariant_promotes_to_gate_on_the_same_label_criterion(tp: int, fp: int, moved: bool) -> None:
    fit = fitness.compute({}, rule_type="invariant", adjudicated_tp=tp, adjudicated_fp=fp, sessions_count=3,
                          repos_count=2)
    assert fit.suggestion == ("promote" if moved else None)


@pytest.mark.parametrize("totals", [{"tp": 30}, {"tp": 500, "triggers": 500}], ids=["30-rows", "500-rows"])
def test_local_and_ci_verdicts_without_labels_never_promote(totals) -> None:
    for rule_type in ("trap", "invariant"):
        fit = fitness.compute(totals, rule_type=rule_type, age_days=400.0)
        assert (fit.state, fit.suggestion) == ("inconclusive", None)


def _unlabelled_ws(tmp_path: Path) -> Path:
    from aegis_core.telemetry_engine import ledger

    ws = tmp_path / "project"
    _rule(ws, "trap", "busy")
    ledger.append(ws, [{"rule": "busy", "outcome": "tp", "source": "ci", "key": f"ci{n}"} for n in range(250)])
    ledger.append(ws, [{"rule": "busy", "outcome": "tp", "source": "manual", "key": f"local{n}"} for n in range(250)])
    return ws


def test_500_local_and_ci_rows_move_nothing_by_type_or_tier(tmp_path: Path, capsys) -> None:
    from aegis_cli.cli import main
    from aegis_core.lifecycle.promotion import evaluate_rule_tiers

    ws = _unlabelled_ws(tmp_path)
    path = ws / ".aegis" / "rules" / "traps" / "busy.md"
    before = path.read_bytes()
    assert evaluate_promotions(ws, NOW) == []
    refused = promote_rule(ws, "busy")
    assert refused["status"] == "ineligible" and "adjudicated labels" in refused["message"]
    assert sync.sync(ws, apply=True, now=NOW).applied == []
    assert main(["rule", "promote", "--tier-check", "--workspace", str(ws)]) == 0
    assert "No tier changes required." in capsys.readouterr().out
    assert evaluate_rule_tiers(ws, execute=True) == {"evaluated": 1, "changes": []}
    assert path.read_bytes() == before
    assert promote_rule(ws, "busy", force=True)["status"] == "promoted"  # an explicit move still works


@needs_git
@pytest.mark.parametrize("order", ["tier-check-first", "sync-first"])
def test_one_labelled_promotion_is_one_move_never_also_a_tier_move(tmp_path: Path, monkeypatch, capsys, order) -> None:
    from aegis_cli.cli import main

    ws = tmp_path / "project"
    _rule(ws, "trap", "proven")
    _labelled(ws, "proven", 25, 0)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    ha.merge_to_base(ws)
    steps = [lambda: main(["rule", "promote", "--tier-check", "--workspace", str(ws)]),
             lambda: sync.sync(ws, apply=True, now=NOW).applied]
    results = [step() for step in (steps if order == "tier-check-first" else steps[::-1])]
    applied = next(r for r in results if isinstance(r, list))
    assert [(a["rule"], a["action"], a["status"]) for a in applied] == [("proven", "promote", "promoted")]
    assert "No tier changes required." in capsys.readouterr().out
    text = (ws / ".aegis" / "rules" / "invariants" / "proven.md").read_text(encoding="utf-8")
    assert "type: invariant" in text and "enforcement: gate" in text
    assert not (ws / ".aegis" / "rules" / "traps" / "proven.md").exists()
