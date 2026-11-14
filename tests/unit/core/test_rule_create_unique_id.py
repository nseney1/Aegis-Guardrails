"""create_rule must never replace an existing rule (review finding F4, lane A2).

A rule id names one active rule. Re-creating an id silently replaced the rule
and discarded its accumulated fitness and lineage, and creating the id in a
second tier left two active rules with one id. Both are refused under the
rules lock; archived rules do not count.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from aegis_core.lifecycle.creation import create_rule
from aegis_core.yaml_engine.frontmatter import parse_frontmatter


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = tmp_path.resolve()
    (root / ".aegis" / "rules").mkdir(parents=True)
    return root


def _rules(ws: Path) -> Path:
    return ws / ".aegis" / "rules"


def _snapshot(directory: Path) -> list[tuple[str, str]]:
    out = []
    for dirpath, _dirs, files in os.walk(directory):
        for name in files:
            full = Path(dirpath) / name
            digest = "link" if full.is_symlink() else hashlib.sha256(full.read_bytes()).hexdigest()
            out.append((full.relative_to(directory).as_posix(), digest))
    return sorted(out)


def _proven_trap(ws: Path, rule_id: str) -> Path:
    path = _rules(ws) / "traps" / f"{rule_id}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"---\nid: {rule_id}\ntype: trap\nenforcement: advisory\n"
        "fitness:\n  triggers: 40\n  true_positives: 38\n  false_positives: 1\n"
        "lineage:\n  parent_id: ancestor\n  generation: 3\n"
        f"---\n# {rule_id}\nEarned body.\n",
        encoding="utf-8",
    )
    return path


def test_recreating_an_existing_id_is_refused_and_keeps_its_fitness(ws: Path) -> None:
    existing = _proven_trap(ws, "dup")
    before = _snapshot(_rules(ws))

    with pytest.raises(FileExistsError) as exc:
        create_rule("trap", "Fresh hypothesis", id_override="dup", workspace=ws)

    assert str(exc.value) == f"rule 'dup' already exists: {existing}"
    assert _snapshot(_rules(ws)) == before
    meta = parse_frontmatter(existing.read_text(encoding="utf-8")) or {}
    assert meta["fitness"]["triggers"] == 40
    assert meta["lineage"]["generation"] == 3


def test_an_id_cannot_be_created_in_a_second_tier(ws: Path) -> None:
    existing = create_rule("trap", "First", id_override="dup", workspace=ws)
    before = _snapshot(_rules(ws))

    with pytest.raises(FileExistsError) as exc:
        create_rule("invariant", "Second", id_override="dup", workspace=ws)

    assert str(exc.value) == f"rule 'dup' already exists: {existing}"
    assert _snapshot(_rules(ws)) == before
    assert not (_rules(ws) / "invariants" / "dup.md").exists()


def test_a_slug_derived_from_the_hypothesis_is_checked_too(ws: Path) -> None:
    first = create_rule("trap", "Same words", workspace=ws)

    with pytest.raises(FileExistsError, match=r"^rule '.+' already exists: "):
        create_rule("trap", "Same words", workspace=ws)

    assert [p.name for p in _rules(ws).rglob("*.md")] == [first.name]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_a_symlink_at_the_target_is_refused_and_left_alone(ws: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.md"
    outside.write_text("outside the rules tree\n", encoding="utf-8")
    link = _rules(ws) / "traps" / "linked.md"
    link.parent.mkdir(parents=True)
    os.symlink(outside, link)

    with pytest.raises(FileExistsError) as exc:
        create_rule("trap", "Through a link", id_override="linked", workspace=ws)

    assert str(exc.value) == f"rule 'linked' already exists: {link}"
    # Not os.readlink: on Windows it returns the target as an extended \\?\ path.
    assert link.is_symlink() and link.resolve() == outside.resolve()
    assert outside.read_text(encoding="utf-8") == "outside the rules tree\n"


def test_an_archived_rule_does_not_block_re_creation(ws: Path) -> None:
    archived = _rules(ws) / ".archive" / "revived.md"
    archived.parent.mkdir(parents=True)
    archived.write_text("---\nid: revived\ntype: trap\n---\nOld.\n", encoding="utf-8")

    path = create_rule("trap", "Revived", id_override="revived", workspace=ws)

    assert path == _rules(ws) / "traps" / "revived.md"
    assert archived.read_text(encoding="utf-8") == "---\nid: revived\ntype: trap\n---\nOld.\n"
