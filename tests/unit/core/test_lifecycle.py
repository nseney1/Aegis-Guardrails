"""Promotion and demotion candidates from ledger fitness (aegis_core.lifecycle.promotion).

The ladder is trap -> invariant -> gate. Candidates come from the one decision engine
(aegis_core.fitness.compute):

- nothing moves below fitness.MIN_N (25) verdicts: the one sample gate (R-evidence-8);
- promote: adjudicated labels merged at the reviewed BASE, 25 with no false positive or 42
  with at most one, from 3 sessions and 2 repos or 14 days, on a rule created at least 30
  days ago; ledger verdicts alone never promote (R-evidence-4);
- demote (or archive, for a rule with no lower tier): P(precision < 0.7) >= 0.9.
"""
from __future__ import annotations

import pytest

from tests import helpers_adjudication as ha
from tests.helpers_rule import make_cell, write_evidence

from aegis_core.fitness import MIN_N
from aegis_core.lifecycle.promotion import evaluate_demotions, evaluate_promotions
from aegis_core.lifecycle.selection import evaluate_archives


def _ws(tmp_path):
    (tmp_path / ".aegis" / "rules").mkdir(parents=True, exist_ok=True)
    return tmp_path


def _trap(tmp_path, name, tp=0, fp=0, triggers=None, age=45):
    make_cell(str(tmp_path / ".aegis" / "rules"), name, cell_type="trap", created_days_ago=age)
    if tp or fp or triggers:
        write_evidence(tmp_path, name, triggers=triggers or tp + fp, tp=tp, fp=fp)


def _invariant(tmp_path, name, tp=0, fp=0, age=45):
    make_cell(str(tmp_path / ".aegis" / "rules"), name, cell_type="invariant", created_days_ago=age)
    if tp or fp:
        write_evidence(tmp_path, name, triggers=tp + fp, tp=tp, fp=fp)


def _ids(candidates):
    return [c["rule_id"] for c in candidates]


def _labelled(tmp_path, name, tp=0, fp=0, age=45, cell_type="trap"):
    """A rule and its labels in the working tree; ha.merge_to_base makes them the reviewed BASE."""
    make_cell(str(tmp_path / ".aegis" / "rules"), name, cell_type=cell_type, created_days_ago=age)
    ha.write_labels(tmp_path, name, ha.labels(name, "tp", tp) + ha.labels(name, "fp", fp))


class TestPromotion:
    @pytest.fixture(autouse=True)
    def _home(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path.parent / f"{tmp_path.name}-home"))

    def test_a_proven_trap_is_a_promotion_candidate(self, tmp_path):
        _labelled(_ws(tmp_path), "proven", tp=MIN_N)
        ha.merge_to_base(tmp_path)
        (candidate,) = evaluate_promotions(tmp_path)
        assert (candidate["rule_id"], candidate["from_type"], candidate["to_type"]) == ("proven", "trap", "invariant")
        assert candidate["tp"] == MIN_N and candidate["fitness"] > 0.85

    def test_an_invariant_promotes_to_gate(self, tmp_path):
        _labelled(_ws(tmp_path), "inv", tp=30, cell_type="invariant")
        ha.merge_to_base(tmp_path)
        assert [(c["from_type"], c["to_type"]) for c in evaluate_promotions(tmp_path)] == [("invariant", "gate")]

    def test_19_verdicts_are_not_enough_however_clean(self, tmp_path):
        _labelled(_ws(tmp_path), "few", tp=19)
        ha.merge_to_base(tmp_path)
        assert evaluate_promotions(tmp_path) == []

    def test_the_bound_not_the_raw_rate_decides(self, tmp_path):
        """24 of 25 is a 96% rate, but one false positive needs 42 labels."""
        _labelled(_ws(tmp_path), "almost", tp=24, fp=1)
        ha.merge_to_base(tmp_path)
        assert evaluate_promotions(tmp_path) == []

    def test_bare_triggers_are_not_failures(self, tmp_path):
        from aegis_core.telemetry_engine import ledger

        _labelled(_ws(tmp_path), "relevant", tp=MIN_N)
        ha.merge_to_base(tmp_path)
        ledger.append(tmp_path, [{"rule": "relevant", "outcome": "trigger", "source": "ci", "key": f"t{n}"} for n in range(60)])
        assert _ids(evaluate_promotions(tmp_path)) == ["relevant"]

    def test_age_29_is_too_young_and_30_is_old_enough(self, tmp_path):
        _ws(tmp_path)
        _labelled(tmp_path, "age-29", tp=25, age=29)
        _labelled(tmp_path, "age-30", tp=25, age=30)
        ha.merge_to_base(tmp_path)
        assert _ids(evaluate_promotions(tmp_path)) == ["age-30"]

    def test_ledger_verdicts_alone_never_promote(self, tmp_path):
        _trap(_ws(tmp_path), "busy", tp=4 * MIN_N)
        _invariant(tmp_path, "busy-inv", tp=4 * MIN_N)
        assert evaluate_promotions(tmp_path) == []

    def test_an_empty_workspace_has_no_candidates(self, tmp_path):
        _ws(tmp_path)
        assert evaluate_promotions(tmp_path) == [] and evaluate_demotions(tmp_path) == []


class TestDemotionAndArchive:
    def test_a_misfiring_invariant_is_demoted_to_trap(self, tmp_path):
        _invariant(_ws(tmp_path), "noisy", tp=6, fp=19)
        (candidate,) = evaluate_demotions(tmp_path)
        assert (candidate["rule_id"], candidate["from_type"], candidate["to_type"]) == ("noisy", "invariant", "trap")
        assert candidate["misfire"] > 0.5

    def test_a_misfiring_trap_is_archived_not_demoted(self, tmp_path):
        _trap(_ws(tmp_path), "noisy-trap", fp=MIN_N)
        assert evaluate_demotions(tmp_path) == []
        assert _ids(evaluate_archives(tmp_path)) == ["noisy-trap"]

    def test_three_straight_false_positives_are_below_the_sample_gate(self, tmp_path):
        """3/3 fp clears the misfire bound (0.526) but not MIN_N: no transition below the gate."""
        _ws(tmp_path)
        _invariant(tmp_path, "three-of-three", fp=3)
        _invariant(tmp_path, "five-of-six", tp=1, fp=5)
        _invariant(tmp_path, "all-of-min-n", fp=MIN_N)
        assert _ids(evaluate_demotions(tmp_path)) == ["all-of-min-n"]

    def test_a_healthy_rule_and_a_rule_without_evidence_are_kept(self, tmp_path):
        """v3 demoted rules with no triggers for 90 days; no evidence is not misfiring."""
        _ws(tmp_path)
        _invariant(tmp_path, "good", tp=23, fp=2)
        _invariant(tmp_path, "quiet", age=400)
        assert evaluate_demotions(tmp_path) == []
        assert evaluate_archives(tmp_path) == []


class TestMisfireBoundary:
    def test_the_engine_decides_the_misfire_and_suggest_never_redecides_from_a_bound(self, tmp_path):
        """The boundary is the posterior P(precision < 0.7) >= 0.9 over at least MIN_N verdicts:
        15 tp / 11 fp gives 0.920 (archive), 16 / 11 gives 0.897 (kept). A misfire bound handed
        to suggest without the engine's decision moves nothing."""
        from aegis_core.fitness import Fitness, compute
        from aegis_core.lifecycle.promotion import suggest
        from aegis_core.rules import load_rules

        _trap(_ws(tmp_path), "edge")
        rule = load_rules(tmp_path).get("edge")

        assert suggest(rule, compute({"tp": 15, "fp": 11}, rule="edge")) == "archive"
        assert suggest(rule, compute({"tp": 16, "fp": 11}, rule="edge")) is None
        assert suggest(rule, Fitness("edge", fp=MIN_N, misfire=0.9)) is None
        # the same bound below the sample gate moves nothing
        assert suggest(rule, Fitness("edge", fp=MIN_N - 1, misfire=0.9)) is None


def _damage_ledger(ws):
    """One complete line nobody can read: the ledger no longer holds all the evidence."""
    with open(ws / ".aegis" / "state" / "ledger.jsonl", "ab") as fh:
        fh.write(b'{"v": 2, "rule": "x", garbled\n')


class TestIncompleteLedger:
    """Moves that the ledger evidence must justify refuse while lines of it are unreadable."""

    def test_archive_refuses(self, tmp_path):
        from aegis_core.lifecycle.selection import archive_rule

        _trap(_ws(tmp_path), "noisy-trap", fp=3)
        _damage_ledger(tmp_path)

        result = archive_rule(tmp_path, "noisy-trap")

        assert result["status"] == "ineligible"
        assert result["message"] == (
            "Rule 'noisy-trap' was not archived: the ledger is incomplete (1 unreadable line(s))"
        )
        assert (tmp_path / ".aegis" / "rules" / "traps" / "noisy-trap.md").is_file()

    def test_aegis_rule_archive_moves_nothing(self, tmp_path, capsys):
        from aegis_core.lifecycle.selection import prune_rules

        _trap(_ws(tmp_path), "noisy-trap", fp=MIN_N)
        _damage_ledger(tmp_path)

        assert prune_rules(tmp_path, execute=True) == 0

        # Partial evidence decides nothing, so there is no candidate to refuse.
        assert capsys.readouterr().out == "Evidence unavailable: 1 unreadable line(s)\nNo rules to archive.\n"
        assert (tmp_path / ".aegis" / "rules" / "traps" / "noisy-trap.md").is_file()

    def test_tier_changes_are_never_proposed_and_the_refusal_is_said(self, tmp_path):
        """Ledger numbers no longer move an enforcement tier (D-tier-ladder); the refusal is still named."""
        from aegis_core.lifecycle.promotion import evaluate_rule_tiers

        _trap(_ws(tmp_path), "proven", tp=30)
        _damage_ledger(tmp_path)
        path = tmp_path / ".aegis" / "rules" / "traps" / "proven.md"
        before = path.read_bytes()

        result = evaluate_rule_tiers(tmp_path, execute=True)

        assert result["changes"] == [] and result["evaluated"] == 1
        assert result["refused"] == "not written: the ledger is incomplete (1 unreadable line(s))"
        assert path.read_bytes() == before

    def test_an_evidence_checked_promotion_is_ineligible(self, tmp_path):
        from aegis_core.lifecycle.promotion import promote_rule

        _trap(_ws(tmp_path), "proven", tp=25)
        _damage_ledger(tmp_path)

        result = promote_rule(tmp_path, "proven")

        assert result["status"] == "ineligible"
        assert "the ledger is incomplete (1 unreadable line(s))" in result["message"]
        assert (tmp_path / ".aegis" / "rules" / "traps" / "proven.md").is_file()
