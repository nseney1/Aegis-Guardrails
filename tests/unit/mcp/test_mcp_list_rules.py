"""aegis_list_rules reports each rule's fitness from the outcome ledger, never from
the fitness block a rule file may still carry in its frontmatter, and says which
rules changed since the last `aegis sync` and which files are not rules.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_core import sync
from aegis_core.stats import wilson_lower_bound
from aegis_core.taxonomy import DEFAULT_CONFIDENCE_LEVEL
from aegis_core.telemetry_engine import ledger
from aegis_mcp.tools import execute_tool


def _rule(root: Path, name: str, fitness_block: str = "") -> None:
    folder = root / ".aegis" / "rules" / "traps"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.md").write_text(
        f"---\nid: {name}\ntype: trap\nhypothesis: h\n{fitness_block}---\nbody\n",
        encoding="utf-8",
    )


def _outcomes(root: Path, rule: str, *outcomes: str) -> None:
    ledger.append(root, [
        {"rule": rule, "outcome": outcome, "source": "ci", "key": f"{rule}-{i}"}
        for i, outcome in enumerate(outcomes)
    ])


def _by_name(result):
    return {rule["_name"]: rule for rule in result["rules"]}


@pytest.fixture
def workspace(tmp_path):
    _rule(tmp_path, "inflated", fitness_block=(
        "fitness:\n  triggers: 99\n  true_positives: 99\n  false_positives: 0\n  score: 0.99\n"
    ))
    _rule(tmp_path, "unobserved")
    _outcomes(tmp_path, "inflated", "tp", "tp", "fp")  # every outcome row is a trigger
    return tmp_path


def test_fitness_comes_from_the_ledger_not_the_frontmatter(workspace):
    rules = _by_name(execute_tool("aegis_list_rules", {"workspace": str(workspace)}))

    fitness = rules["inflated"]["fitness"]
    assert {k: fitness[k] for k in ("triggers", "tp", "fp")} == {"triggers": 3, "tp": 2, "fp": 1}
    assert fitness["score"] == pytest.approx(wilson_lower_bound(2, 3, DEFAULT_CONFIDENCE_LEVEL), abs=1e-4)
    assert fitness["score"] != 0.99
    assert isinstance(fitness["last_ts"], str)


def test_a_rule_with_no_ledger_rows_is_unobserved(workspace):
    fitness = _by_name(execute_tool("aegis_list_rules", {"workspace": str(workspace)}))["unobserved"]["fitness"]
    assert fitness == {"triggers": 0, "tp": 0, "fp": 0, "last_ts": None, "score": 0.0,
                       "reported_score": None, "status": "insufficient (n=0)"}


def test_every_outcome_row_counts_as_a_trigger(tmp_path):
    _rule(tmp_path, "reported")
    _outcomes(tmp_path, "reported", "tp", "tp", "tp", "trigger")

    fitness = _by_name(execute_tool("aegis_list_rules", {"workspace": str(tmp_path)}))["reported"]["fitness"]

    assert (fitness["triggers"], fitness["tp"], fitness["fp"]) == (4, 3, 0)
    assert 0.0 < fitness["score"] <= 1.0


def test_unreadable_ledger_rows_do_not_break_the_listing(workspace):
    path = workspace / ".aegis" / "state" / "ledger.jsonl"
    with path.open("a", encoding="utf-8") as f:
        f.write("{not json\n")
    rules = _by_name(execute_tool("aegis_list_rules", {"workspace": str(workspace)}))
    assert rules["inflated"]["fitness"]["tp"] == 2


def test_list_rules_payload_is_json_serializable(workspace):
    json.dumps(execute_tool("aegis_list_rules", {"workspace": str(workspace)}))


def test_diagnostic_records_carry_no_fitness(tmp_path):
    bad = tmp_path / ".aegis" / "rules" / "traps" / "bad.md"
    bad.parent.mkdir(parents=True)
    bad.write_bytes(b"---\nid: bad\n---\n\xff\n")

    record, = execute_tool("aegis_list_rules", {"workspace": str(tmp_path)})["rules"]

    assert "UTF-8" in record["_error"]
    assert "fitness" not in record


def test_rules_edited_since_sync_and_files_that_are_not_rules_are_listed(workspace):
    sync.sync(workspace)
    edited = workspace / ".aegis" / "rules" / "traps" / "unobserved.md"
    edited.write_text(edited.read_text(encoding="utf-8") + "more\n", encoding="utf-8")
    (workspace / ".aegis" / "rules" / "notes.md").write_text("# notes\n", encoding="utf-8")

    result = execute_tool("aegis_list_rules", {"workspace": str(workspace)})

    assert result["stale_rules"] == [{"id": "unobserved", "path": ".aegis/rules/traps/unobserved.md", "change": "edited"}]
    assert result["ignored"] == [{"path": ".aegis/rules/notes.md", "reason": "not a rule: it is not in a rule type directory"}]
    assert set(_by_name(result)) == {"inflated", "unobserved"}  # an edited rule is still listed and served


def test_the_type_filter_uses_the_rule_directory(workspace):
    inv = workspace / ".aegis" / "rules" / "invariants" / "inv.md"
    inv.parent.mkdir()
    inv.write_text("---\nid: inv\ntype: invariant\nenforcement: gate\n---\nb\n", encoding="utf-8")

    result = execute_tool("aegis_list_rules", {"workspace": str(workspace), "rule_type": "invariant"})

    assert list(_by_name(result)) == ["inv"]
