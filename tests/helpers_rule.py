"""Shared test helpers for rule lifecycle tests.

Rules are written where the one loader reads them, ``.aegis/rules/<type dir>/<id>.md``,
and their evidence goes to the ledger, the only source of fitness (ADR 0005 H6).
"""
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from aegis_core.taxonomy import DIR_RULE_TYPES, RULE_TYPE_DIRS, RULE_TYPES
from aegis_core.yaml_engine.serializer import dump_frontmatter

__all__ = [
    "make_rule",
    "write_rule_with_fitness",
    "aegis_workspace",
    "write_evidence",
]


def _placement(rules_dir, rule_type):
    """(type directory, workspace root) for a rules root or a type directory."""
    base = Path(str(rules_dir))
    if base.name in DIR_RULE_TYPES:
        return base, base.parent.parent.parent
    return base / RULE_TYPE_DIRS[rule_type], base.parent.parent


def make_rule(rules_dir, name, rule_type="trap", created_days_ago=10,
              expiry_days=365, expiry_sessions=100):
    """Create a minimal rule file in its type directory."""
    created = (datetime.now(timezone.utc) - timedelta(days=created_days_ago)).strftime("%Y-%m-%d")
    fm = {
        'id': name,
        'type': rule_type,
        'enforcement': 'gate' if RULE_TYPES[rule_type].mandatory else 'advisory',
        'hypothesis': f'Test rule {name}',
        'prediction': 'test',
        'falsification': 'test',
        'target_paths': ['*.py'],
        'expiry_sessions': expiry_sessions,
        'expiry_days': expiry_days,
        'created': created,
    }
    folder, _ = _placement(rules_dir, rule_type)
    folder.mkdir(parents=True, exist_ok=True)
    rule_file = folder / f"{name}.md"
    rule_file.write_text(dump_frontmatter(fm, body=f"# {name}\nTest rule.\n"), encoding="utf-8")
    return str(rule_file)


def write_rule_with_fitness(rules_dir, name, enforcement="advisory",
                            triggers=0, tp=0, fp=0, rule_type="trap",
                            hypothesis=None, created_days_ago=60):
    """Write a rule file and give it ledger evidence: ``tp`` + ``fp`` verdict rows and
    ``triggers - tp - fp`` bare trigger rows."""
    folder, workspace = _placement(rules_dir, rule_type)
    folder.mkdir(parents=True, exist_ok=True)
    created = (datetime.now(timezone.utc) - timedelta(days=created_days_ago)).strftime("%Y-%m-%d")
    fm = {
        "id": name,
        "type": rule_type,
        "hypothesis": hypothesis or f"Test rule {name}",
        "enforcement": enforcement,
        "created": created,
        "target_paths": ["*.py"],
    }
    path = folder / f"{name}.md"
    path.write_text(dump_frontmatter(fm, body=f"# {name}\nContent\n"), encoding="utf-8")
    if triggers or tp or fp:
        write_evidence(workspace, name, triggers=max(triggers, tp + fp), tp=tp, fp=fp)
    return str(path)


@pytest.fixture
def aegis_workspace(tmp_path):
    """Create a minimal Aegis workspace with a rules directory."""
    workspace = tmp_path / "project"
    rules_dir = workspace / ".aegis" / "rules"
    rules_dir.mkdir(parents=True)
    return workspace


def write_evidence(workspace, rule_id, triggers=0, tp=0, fp=0):
    """Append ledger rows giving one rule ``triggers`` triggers, ``tp`` tps and ``fp`` fps.

    Each v2 outcome row is also a trigger, so the rows are tp + fp outcome rows plus
    ``triggers - tp - fp`` bare trigger rows (``triggers`` must cover tp + fp).
    """
    assert triggers >= tp + fp, "every tp/fp row is a trigger"
    ledger = os.path.join(str(workspace), ".aegis", "state", "ledger.jsonl")
    os.makedirs(os.path.dirname(ledger), exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    outcomes = ["tp"] * tp + ["fp"] * fp + ["trigger"] * (triggers - tp - fp)
    with open(ledger, "a", encoding="utf-8") as f:
        for outcome in outcomes:
            f.write(json.dumps({
                "v": 2, "ts": stamp, "rule": rule_id, "outcome": outcome, "source": "manual",
            }) + "\n")
