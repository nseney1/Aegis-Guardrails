"""The lifecycle (aegis_core.lifecycle): suggestions from ledger fitness, and the moves.

``suggest`` reads only the ledger (through aegis_core.fitness). promote/demote move a
rule one step on the ladder trap -> invariant -> gate; nothing reads or writes a
fitness block in a rule file.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aegis_core.fitness import Fitness, compute
from aegis_core.lifecycle.parsers import find_rule_file, rule_age_days
from aegis_core.lifecycle.promotion import demote_rule, promote_rule, suggest
from aegis_core.rules import load_rules
from aegis_core.telemetry_engine import ledger

OLD = "2026-01-01"
NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / ".aegis" / "rules" / "traps").mkdir(parents=True)
    (tmp_path / ".aegis" / "rules" / "invariants").mkdir(parents=True)
    return tmp_path


def _rule(ws: Path, directory: str, rule_id: str, rule_type: str, created: str = OLD) -> Path:
    path = ws / ".aegis" / "rules" / directory / f"{rule_id}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    enforcement = "gate" if rule_type in ("invariant", "gate") else "advisory"
    path.write_text(
        f"---\nid: {rule_id}\ntype: {rule_type}\ndomain: testing\nenforcement: {enforcement}\n"
        f"created: '{created}'\n---\n# {rule_id}\nDescription here.\n",
        encoding="utf-8",
    )
    return path


def _report(ws: Path, rule_id: str, tp: int = 0, fp: int = 0) -> None:
    events = [{"rule": rule_id, "outcome": "tp", "source": "ci", "key": f"tp{i}"} for i in range(tp)]
    events += [{"rule": rule_id, "outcome": "fp", "source": "ci", "key": f"fp{i}"} for i in range(fp)]
    ledger.append(ws, events)


def _suggestion(ws: Path, rule_id: str, fit: Fitness) -> str | None:
    return suggest(load_rules(ws).get(rule_id), fit, NOW)


def _decided(ws: Path, rule_id: str, rule_type: str, tp: int = 0, fp: int = 0, labels: int = 0) -> Fitness:
    """What the one engine (fitness.compute) decides for the rule's age and these counts."""
    age = rule_age_days(load_rules(ws).get(rule_id), NOW)
    return compute({"tp": tp, "fp": fp}, rule=rule_id, rule_type=rule_type, adjudicated_tp=labels,
                   sessions_count=3 if labels else 0, repos_count=2 if labels else 0, age_days=age)


class TestSuggestions:
    def test_strong_evidence_on_an_old_enough_rule_suggests_promotion(self, workspace: Path):
        _rule(workspace, "traps", "t", "trap")
        assert _suggestion(workspace, "t", _decided(workspace, "t", "trap", labels=25)) == "promote"

    def test_too_few_verdicts_too_low_a_bound_or_too_young_is_no_promotion(self, workspace: Path):
        _rule(workspace, "traps", "t", "trap")
        _rule(workspace, "traps", "young", "trap", created=(NOW - timedelta(days=5)).strftime("%Y-%m-%d"))
        assert _suggestion(workspace, "t", _decided(workspace, "t", "trap", labels=19)) is None
        assert _suggestion(workspace, "t", _decided(workspace, "t", "trap", tp=30, fp=5)) is None
        assert _suggestion(workspace, "young", _decided(workspace, "young", "trap", labels=40)) is None

    def test_a_misfiring_rule_is_demoted_or_archived_at_the_bottom(self, workspace: Path):
        _rule(workspace, "traps", "t", "trap")
        _rule(workspace, "invariants", "i", "invariant")
        assert _suggestion(workspace, "i", _decided(workspace, "i", "invariant", fp=25)) == "demote"
        assert _suggestion(workspace, "t", _decided(workspace, "t", "trap", fp=25)) == "archive"
        assert _suggestion(workspace, "t", _decided(workspace, "t", "trap", tp=16, fp=11)) is None
        # three straight false positives clear the old Wilson bound but not MIN_N (25) verdicts (R-evidence-8)
        assert _suggestion(workspace, "i", _decided(workspace, "i", "invariant", fp=3)) is None
        # suggest never re-decides from a bound the engine did not decide on
        assert _suggestion(workspace, "i", Fitness("i", tp=0, fp=25, misfire=0.9)) is None

    def test_protected_expired_and_broken_rules_get_no_suggestion(self, workspace: Path):
        _rule(workspace, "traps", "providence", "trap")
        expired = _rule(workspace, "traps", "gone", "trap")
        expired.write_text(expired.read_text(encoding="utf-8").replace("---\n#", "expired_at: '2026-01-01'\n---\n#"), encoding="utf-8")
        ruleset = load_rules(workspace)
        assert suggest(ruleset.get("providence"), Fitness(tp=0, fp=9, misfire=0.8), NOW) is None
        assert suggest(ruleset.get("gone"), Fitness(tp=0, fp=9, misfire=0.8), NOW) is None

    def test_rule_age_comes_from_created(self, workspace: Path):
        _rule(workspace, "traps", "t", "trap", created="2026-10-05")
        assert rule_age_days(load_rules(workspace).get("t"), NOW) == 10


class TestPromoteAndDemote:
    def test_find_cell_file(self, workspace: Path):
        trap = _rule(workspace, "traps", "test-v", "trap")
        assert find_rule_file(workspace, "test-v") == (trap, "trap")
        assert find_rule_file(workspace, "../etc/passwd") == (None, None)

    def test_promotion_without_force_needs_ledger_evidence(self, workspace: Path, monkeypatch):
        """CI verdicts alone are not enough: labels merged at the reviewed BASE are (R-evidence-4)."""
        from tests import helpers_adjudication as ha

        trap = _rule(workspace, "traps", "promote-me", "trap")
        refused = promote_rule(workspace, "promote-me", force=False)
        assert refused["status"] == "ineligible" and trap.exists()

        monkeypatch.setenv("HOME", str(workspace.parent / "home"))
        ha.merge_to_base(workspace)
        _report(workspace, "promote-me", tp=25)
        refused = promote_rule(workspace, "promote-me", force=False)
        assert refused["status"] == "ineligible" and "adjudicated labels" in refused["message"] and trap.exists()

        ha.write_labels(workspace, "promote-me", ha.labels("promote-me"))
        ha.merge_to_base(workspace)
        res = promote_rule(workspace, "promote-me", force=False)

        assert (res["status"], res["from_type"], res["to_type"]) == ("promoted", "trap", "invariant")
        assert not trap.exists()
        inv_path = workspace / ".aegis" / "rules" / "invariants" / "promote-me.md"
        content = inv_path.read_text(encoding="utf-8")
        assert "type: invariant" in content and "enforcement: gate" in content
        assert "fitness" not in content

    def test_a_frontmatter_fitness_block_does_not_make_a_rule_eligible(self, workspace: Path):
        trap = _rule(workspace, "traps", "claims", "trap")
        trap.write_text(trap.read_text(encoding="utf-8").replace(
            "---\n#", "fitness:\n  triggers: 99\n  true_positives: 99\n  score: 1.0\n---\n#"), encoding="utf-8")
        assert promote_rule(workspace, "claims", force=False)["status"] == "ineligible"

    def test_an_invariant_promotes_to_a_gate_and_a_gate_is_terminal(self, workspace: Path):
        _rule(workspace, "invariants", "inv", "invariant")
        assert promote_rule(workspace, "inv", force=True)["to_type"] == "gate"
        assert (workspace / ".aegis" / "rules" / "gates" / "inv.md").is_file()
        assert promote_rule(workspace, "inv", force=True)["status"] == "already_terminal"

    def test_demote_invariant_to_trap(self, workspace: Path):
        inv = _rule(workspace, "invariants", "demote-me", "invariant")
        res = demote_rule(workspace, "demote-me")
        assert (res["status"], res["from_type"], res["to_type"]) == ("demoted", "invariant", "trap")
        trap_path = workspace / ".aegis" / "rules" / "traps" / "demote-me.md"
        assert not inv.exists() and "type: trap" in trap_path.read_text(encoding="utf-8")
        assert demote_rule(workspace, "demote-me")["status"] == "already_base"

    def test_protected_rules_cannot_be_demoted_or_promoted(self, workspace: Path):
        _rule(workspace, "invariants", "providence", "invariant")
        with pytest.raises(ValueError, match="Cannot demote protected core rule"):
            demote_rule(workspace, "providence")
        res = promote_rule(workspace, "providence", force=True)
        assert res["status"] == "protected_rule_immutable"
        assert "protected core rule" in res["message"].lower()


def test_generate_slug_names_a_rule_from_its_hypothesis():
    from aegis_core.lifecycle.parsers import generate_slug

    assert generate_slug("Never shell out from src/!") == "never-shell-out-from-src"
    assert generate_slug("!!!") == "unnamed-rule"
    assert generate_slug("ignored", id_override="explicit-id") == "explicit-id"
    with pytest.raises(ValueError, match="path traversal"):
        generate_slug("x", id_override="../escape")


@pytest.mark.parametrize("domain, tags, target_paths", [
    ("security #high", ["a: b"], ["src/*.py"]),
    ("true", ["null", "#tag"], ["it's/*.py", "**"]),
    ("12", ["- dash"], ['say "hi"/*.md']),
])
def test_create_cell_writes_every_value_back_exactly_as_given(tmp_path, domain, tags, target_paths):
    """create_rule serializes through the one frontmatter writer (defense #30): a value that
    looks like a comment, a boolean, a number or a list item is quoted, never reinterpreted."""
    from aegis_core.lifecycle.creation import create_rule

    path = create_rule(
        "trap", 'He said: "keep # this"', domain=domain, tags=tags, target_paths=target_paths,
        workspace=tmp_path, id_override="exact",
    )

    rule = load_rules(tmp_path).get("exact")
    assert rule is not None and rule.path == ".aegis/rules/traps/exact.md"
    assert (rule.meta["domain"], rule.meta["tags"], rule.meta["target_paths"]) == (domain, tags, target_paths)
    assert rule.meta["hypothesis"] == 'He said: "keep # this"'
    assert path.read_text(encoding="utf-8").startswith("---\nid: exact\ndomain: ")
