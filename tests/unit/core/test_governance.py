from pathlib import Path

import pytest

from aegis_sdk.governance import Governance

def test_governance_fitness_landscape_in_process(tmp_path):
    _populate_governed_workspace(tmp_path)
    gov = Governance(project_root=tmp_path)
    res = gov.fitness_landscape(bayesian=True)
    assert isinstance(res, list)
    assert len(res) == 5
    assert {row["rule"] for row in res} == {
        "trap-test-trap", "invariant-test-guard", "persona-test-persona",
        "boundary-test-boundary", "contract-test-bridge",
    }
    assert all(row["bayesian"] == {"lower": 0.0, "upper": 1.0} for row in res)


def _populate_governed_workspace(root: Path):
    rules_dir = root / ".aegis" / "rules"
    for d in ["traps", "invariants", "personas", "boundaries", "contracts"]:
        (rules_dir / d).mkdir(parents=True, exist_ok=True)
    (rules_dir / "traps" / "trap-test-trap.md").write_text(
        "---\ntype: trap\nhypothesis: test trap\n---\nBody\n", encoding="utf-8"
    )
    (rules_dir / "invariants" / "invariant-test-guard.md").write_text(
        "---\ntype: invariant\nhypothesis: test guard\n---\nBody\n", encoding="utf-8"
    )
    (rules_dir / "personas" / "persona-test-persona.md").write_text(
        "---\ntype: persona\nhypothesis: test persona\n---\nBody\n", encoding="utf-8"
    )
    (rules_dir / "boundaries" / "boundary-test-boundary.md").write_text(
        "---\ntype: boundary\nhypothesis: test boundary\n---\nBody\n", encoding="utf-8"
    )
    (rules_dir / "contracts" / "contract-test-bridge.md").write_text(
        "---\ntype: contract\nhypothesis: test bridge\n---\nBody\n", encoding="utf-8"
    )


def test_list_rules_with_rule_type_filter(tmp_path):
    _populate_governed_workspace(tmp_path)
    gov = Governance(project_root=tmp_path)

    # 0 args: returns all rules
    all_rules = gov.list_rules()
    assert len(all_rules) == 5

    # Filter by canonical type
    traps = gov.list_rules(rule_type="trap")
    assert len(traps) == 1
    assert traps[0]["_name"] == "trap-test-trap"


@pytest.mark.parametrize("rule_type, name", [
    ("invariant", "invariant-test-guard"),
    ("persona", "persona-test-persona"),
    ("boundary", "boundary-test-boundary"),
    ("contract", "contract-test-bridge"),
])
def test_list_rules_filters_each_canonical_type(tmp_path, rule_type, name):
    """The v1/v2 aliases (safety-guard, agent-persona, ...) are gone with the alias maps;
    only the six types of the one rule-type table filter."""
    _populate_governed_workspace(tmp_path)
    gov = Governance(project_root=tmp_path)

    assert [r["_name"] for r in gov.list_rules(rule_type=rule_type)] == [name]
    assert gov.list_rules(rule_type="safety-guard") == []


def test_list_rules_corrupted_isolation(tmp_path):
    _populate_governed_workspace(tmp_path)
    gov = Governance(project_root=tmp_path)

    # Add corrupted trap rule
    corrupted_file = tmp_path / ".aegis" / "rules" / "traps" / "corrupted_trap.md"
    corrupted_file.write_bytes(b"\xff\xfe\x00\x00")

    # Full list returns diagnostic error record
    all_rules = gov.list_rules()
    assert any(c.get("_name") == "corrupted_trap" and "_error" in c for c in all_rules)

    # Invariant filter must isolate and NOT leak corrupted trap
    inv_rules = gov.list_rules(rule_type="invariant")
    assert not any(c.get("_name") == "corrupted_trap" for c in inv_rules)
    assert len(inv_rules) == 1
    assert inv_rules[0]["_name"] == "invariant-test-guard"
