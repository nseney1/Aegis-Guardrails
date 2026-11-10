"""The one promotion ladder (trap -> invariant -> gate) in every repository.

v3 promoted invariants into a top-level rules/ in the Aegis repository itself; v4
has one ladder and never reads or writes rules outside .aegis/rules/<type>/.
"""
from __future__ import annotations

from pathlib import Path

from aegis_core.yaml_engine.serializer import dump_frontmatter
from aegis_core.yaml_engine.frontmatter import parse_frontmatter
from aegis_core.lifecycle.parsers import find_rule_file
from aegis_core.rules import load_rules
from aegis_core.lifecycle.promotion import promote_rule, demote_rule
from aegis_core.workspace.base import Workspace


def test_the_aegis_repository_promotes_on_the_same_ladder(tmp_path: Path):
    """v3 sent invariants of the Aegis repository to rules/; v4 has one ladder."""
    aegis_repo = tmp_path / "aegis"
    (aegis_repo / "aegis_core").mkdir(parents=True)
    (aegis_repo / "aegis_cli").mkdir()
    (aegis_repo / "pyproject.toml").write_text('name = "aegis-governance"\nversion = "0.120.0"\n', encoding="utf-8")
    (aegis_repo / "rules").mkdir()
    inv_dir = aegis_repo / ".aegis" / "rules" / "invariants"
    inv_dir.mkdir(parents=True)
    (inv_dir / "law.md").write_text(dump_frontmatter({"id": "law", "type": "invariant", "enforcement": "gate"}, body="Law\n"), encoding="utf-8")
    ws = Workspace(root=aegis_repo)

    res = promote_rule(ws, "law", force=True)

    assert res["status"] == "promoted" and res["to_type"] == "gate"
    assert (aegis_repo / ".aegis" / "rules" / "gates" / "law.md").is_file()
    assert list((aegis_repo / "rules").iterdir()) == []


def test_foreign_repo_local_promotion(tmp_path: Path):
    """Foreign repositories promote trap -> invariant -> gate without touching rules/."""
    repo = tmp_path / "app"
    repo.mkdir()
    traps_dir = repo / ".aegis" / "rules" / "traps"
    traps_dir.mkdir(parents=True)

    rule_file = traps_dir / "safety-check.md"
    rule_meta = {
        "id": "safety-check",
        "type": "trap",
        "enforcement": "advisory",
        "fitness": {"triggers": 25, "true_positives": 24, "false_positives": 1},
    }
    rule_file.write_text(dump_frontmatter(rule_meta, body="# Safety Rule\nMust be safe.\n"), encoding="utf-8")

    ws = Workspace(root=repo)

    # Step 1: Promote trap -> invariant
    res1 = promote_rule(ws, "safety-check", force=True)
    assert res1["status"] == "promoted"
    assert res1["from_type"] == "trap"
    assert res1["to_type"] == "invariant"
    assert not rule_file.exists()
    inv_file = repo / ".aegis" / "rules" / "invariants" / "safety-check.md"
    assert inv_file.exists()
    assert not (repo / "rules").exists()

    inv_meta = parse_frontmatter(inv_file.read_text(encoding="utf-8"))
    assert inv_meta["type"] == "invariant"
    assert inv_meta["enforcement"] == "gate"

    # Step 2: Promote invariant -> gate
    res2 = promote_rule(ws, "safety-check", force=True)
    assert res2["status"] == "promoted"
    assert res2["from_type"] == "invariant"
    assert res2["to_type"] == "gate"
    assert not inv_file.exists()
    gate_file = repo / ".aegis" / "rules" / "gates" / "safety-check.md"
    assert gate_file.exists()
    assert not (repo / "rules").exists()

    gate_meta = parse_frontmatter(gate_file.read_text(encoding="utf-8"))
    assert gate_meta["type"] == "gate"
    assert gate_meta["enforcement"] == "gate"

    # Step 3: Terminal check
    res3 = promote_rule(ws, "safety-check", force=True)
    assert res3["status"] == "already_terminal"
    assert not (repo / "rules").exists()


def test_foreign_repo_local_demotion(tmp_path: Path):
    """Foreign repositories demote gate -> invariant -> trap."""
    repo = tmp_path / "app"
    repo.mkdir()
    gates_dir = repo / ".aegis" / "rules" / "gates"
    gates_dir.mkdir(parents=True)

    rule_file = gates_dir / "strict-check.md"
    rule_meta = {
        "id": "strict-check",
        "type": "gate",
        "enforcement": "gate",
        "fitness": {"triggers": 30, "true_positives": 5, "false_positives": 25},
    }
    rule_file.write_text(dump_frontmatter(rule_meta, body="# Strict Check\n"), encoding="utf-8")

    ws = Workspace(root=repo)

    # Demote gate -> invariant
    res1 = demote_rule(ws, "strict-check")
    assert res1["status"] == "demoted"
    assert res1["from_type"] == "gate"
    assert res1["to_type"] == "invariant"
    inv_file = repo / ".aegis" / "rules" / "invariants" / "strict-check.md"
    assert inv_file.exists()
    assert not rule_file.exists()

    # Demote invariant -> trap
    res2 = demote_rule(ws, "strict-check")
    assert res2["status"] == "demoted"
    assert res2["from_type"] == "invariant"
    assert res2["to_type"] == "trap"
    trap_file = repo / ".aegis" / "rules" / "traps" / "strict-check.md"
    assert trap_file.exists()
    assert not inv_file.exists()


def test_parsers_ignore_a_rules_directory(tmp_path: Path):
    """Markdown in a project's rules/ (or any directory outside .aegis/rules) is never a rule."""
    repo = tmp_path / "bioinformatics_project"
    repo.mkdir()
    (repo / ".aegis" / "rules" / "invariants").mkdir(parents=True)

    # Foreign project happens to have a rules/ folder with markdown files
    foreign_rules = repo / "rules"
    foreign_rules.mkdir()
    foreign_rule = foreign_rules / "chromosome1.md"
    foreign_rule.write_text("---\nid: chromosome1\nnon_standard: true\n---\nDNA sequence data\n", encoding="utf-8")

    ws = Workspace(root=repo)

    # 1. find_rule_file should NOT return chromosome1
    found_path, rule_type = find_rule_file(ws, "chromosome1")
    assert found_path is None
    assert rule_type is None

    # 2. The loader never reads it
    assert load_rules(ws).rules == ()
