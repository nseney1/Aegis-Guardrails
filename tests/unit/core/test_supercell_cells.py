"""The antipattern rules derived from the Supercell (Citadel) Cycle 1 RCA.

Every one exists in this repository's .aegis/rules, loads cleanly through the one
loader (aegis_core.rules) and retains its RCA fields with the approved enforcement.
"""
from pathlib import Path

import pytest

from aegis_core.rules import load_rules

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())


# Supercell Cycle 1 RCA rules; prose-only traps became advisory in the 4.5 catalog review.
SUPERCELL_CELLS = {
    # Security antipatterns (from S1, S2)
    "trap-format-code-injection": {
        "domain": "security",
        "enforcement": "advisory",
    },
    "trap-path-traversal": {
        "domain": "security",
        "enforcement": "advisory",
    },
    # Correctness antipatterns (from C1, C2, C3)
    "trap-schema-contract-drift": {
        "domain": "correctness",
        "enforcement": "advisory",
    },
    "trap-orphaned-module": {
        "domain": "correctness",
    },
    "trap-threshold-spec-drift": {
        "domain": "correctness",
        "enforcement": "advisory",
    },
    # Quality / process antipatterns (from doc-drift RCA)
    "trap-doc-feature-drift": {
        "domain": "documentation",
        "enforcement": "advisory",
    },
    "trap-ascii-art-render": {
        "domain": "documentation",
    },
    "trap-test-coverage-horizon": {
        "domain": "testing",
    },
    # Architecture antipatterns (from C5, C6)
    "trap-layer-violation": {
        "domain": "architecture",
        "enforcement": "advisory",
    },
    "trap-shell-true-portability": {
        "domain": "portability",
        "enforcement": "advisory",
    },
}

REQUIRED_FIELDS = [
    "id", "domain", "type", "enforcement", "hypothesis",
    "prediction", "falsification", "target_paths", "triggers",
]


@pytest.fixture(scope="module")
def ruleset():
    return load_rules(REPO_ROOT)


@pytest.mark.parametrize("rule_id,spec", list(SUPERCELL_CELLS.items()))
def test_rule_loads_as_a_trap_with_the_rca_fields(ruleset, rule_id, spec):
    rule = ruleset.get(rule_id)
    assert rule is not None, f"{rule_id} is missing or cannot be loaded"
    assert rule.path == f".aegis/rules/traps/{rule_id}.md"
    assert rule.type == "trap"
    for field in REQUIRED_FIELDS:
        assert field in rule.meta, f"{rule_id} missing field: {field}"
    assert rule.meta["domain"] == spec["domain"]
    if "enforcement" in spec:
        assert rule.enforcement == spec["enforcement"]


def test_security_rules_target_python(ruleset):
    for rule_id in ("trap-format-code-injection", "trap-path-traversal"):
        targets = ruleset.get(rule_id).target_paths
        assert any("*.py" in t for t in targets), f"{rule_id} must target Python files"


def test_doc_drift_targets_docs(ruleset):
    targets = ruleset.get("trap-doc-feature-drift").target_paths
    assert any("README" in t or "*.md" in t or "CHANGELOG" in t for t in targets)
