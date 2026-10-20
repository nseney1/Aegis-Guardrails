"""The scan service (aegis_core.scan): what aegis_scan and `aegis scan` return.

Same rules for the same files everywhere (one loader, one matcher), ranked by ledger
fitness, mandatory rules capped at two slots and reported when omitted, the scan
failing closed when a rule cannot be loaded, and rules edited since `aegis sync`
listed but still served.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from aegis_core import sync
from aegis_core.scan import MANDATORY_SLOT_CAP, NO_CHANGES_TEXT, RULE_CACHE, scan
from aegis_core.telemetry_engine import ledger
from tests.conftest import symlink_or_skip

_DIRS = {"trap": "traps", "invariant": "invariants", "gate": "gates", "persona": "personas"}


def _rule(ws: Path, rule_id: str, rule_type: str = "trap", targets=("src/*.py",), enforcement: str = "",
          extra: str = "") -> Path:
    path = ws / ".aegis" / "rules" / _DIRS[rule_type] / f"{rule_id}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    enforcement = enforcement or ("gate" if rule_type in ("invariant", "gate") else "advisory")
    lines = "".join(f"  - '{t}'\n" for t in targets)
    path.write_text(
        f"---\nid: {rule_id}\ntype: {rule_type}\nenforcement: {enforcement}\n"
        f"hypothesis: Hypothesis of {rule_id}\ntarget_paths:\n{lines}{extra}---\nDetail of {rule_id}.\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture(autouse=True)
def _fresh_cache():
    RULE_CACHE.invalidate()
    yield
    RULE_CACHE.invalidate()


def _names(result: dict) -> list:
    return [r["name"] for r in result["relevant_rules"]]


def test_scan_returns_the_rules_whose_patterns_match(tmp_path: Path) -> None:
    _rule(tmp_path, "trap-src", targets=("src/**/*.py",))  # **/ is zero dirs: src/a.py matches
    _rule(tmp_path, "trap-docs", targets=("docs/*.md",))

    result = scan(tmp_path, ["src/a.py"])

    assert _names(result) == ["trap-src"]
    item = result["relevant_rules"][0]
    assert item["_path"] == ".aegis/rules/traps/trap-src.md"
    assert item["matched_files"] == ["src/a.py"] and item["fitness"] is None  # no verdicts: below MIN_N
    assert "trap-src" in result["guidance"]
    assert result["stats"]["total_rules"] == 2 and result["stats"]["matched"] == 1
    assert result["omitted_mandatory"] == [] and result["stale_rules"] == []
    assert "status" not in result


def test_without_changed_files_nothing_is_staged(tmp_path: Path) -> None:
    _rule(tmp_path, "t")
    result = scan(tmp_path, [])  # not a git repository: no diff either
    assert result["guidance"] == NO_CHANGES_TEXT and result["relevant_rules"] == []


def test_mandatory_rules_take_at_most_two_slots_and_the_rest_are_reported(tmp_path: Path) -> None:
    """Three self-declared mandatory rules on `**` used to starve every advisory rule."""
    for name in ("trap-gate-a", "trap-gate-b", "trap-gate-c"):
        _rule(tmp_path, name, targets=("**",), enforcement="gate")
    _rule(tmp_path, "trap-advice")
    assert MANDATORY_SLOT_CAP == 2

    result = scan(tmp_path, ["src/a.py"], budget=3)

    assert _names(result) == ["trap-gate-a", "trap-gate-b", "trap-advice"]
    assert result["omitted_mandatory"] == [{"name": "trap-gate-c", "type": "trap", "reason": "slot_cap"}]
    assert result["stats"]["omitted_mandatory"] == 1
    assert "1 more mandatory rule applies to these files and was not shown: trap-gate-c" in result["guidance"]


def test_a_budget_below_the_cap_is_never_exceeded_by_mandatory_rules(tmp_path: Path) -> None:
    _rule(tmp_path, "gate-a", "gate")
    _rule(tmp_path, "gate-b", "gate")

    result = scan(tmp_path, ["src/a.py"], budget=1)

    assert _names(result) == ["gate-a"]
    assert result["omitted_mandatory"] == [{"name": "gate-b", "type": "gate", "reason": "slot_cap"}]


def test_with_equal_fitness_a_rule_naming_the_file_exactly_ranks_first(tmp_path: Path) -> None:
    _rule(tmp_path, "a-glob", targets=("src/*.py",))
    _rule(tmp_path, "z-exact", targets=("src/a.py",))

    result = scan(tmp_path, ["src/a.py"], budget=1)

    assert _names(result) == ["z-exact"]


def test_gates_outrank_invariants_outrank_self_declared_gates(tmp_path: Path) -> None:
    _rule(tmp_path, "a-declared", enforcement="gate")
    _rule(tmp_path, "b-invariant", "invariant")
    _rule(tmp_path, "c-gate", "gate")

    result = scan(tmp_path, ["src/a.py"], budget=3)

    assert _names(result) == ["c-gate", "b-invariant"]
    assert [o["name"] for o in result["omitted_mandatory"]] == ["a-declared"]


def test_advisory_rules_are_ranked_by_ledger_fitness_not_frontmatter(tmp_path: Path) -> None:
    # Frontmatter claims are ignored: fitness is read from the ledger.
    _rule(tmp_path, "trap-claims", extra="fitness:\n  score: 0.99\n  triggers: 100\n  true_positives: 100\n")
    _rule(tmp_path, "trap-proven")
    ledger.append(tmp_path, [
        {"rule": "trap-proven", "outcome": "tp", "source": "ci", "key": f"k{i}"} for i in range(25)
    ])

    result = scan(tmp_path, ["src/a.py"], budget=1)

    assert _names(result) == ["trap-proven"]
    assert result["relevant_rules"][0]["fitness"] > 0.7


def test_a_rule_that_cannot_be_loaded_fails_the_scan_closed(tmp_path: Path) -> None:
    _rule(tmp_path, "good")
    broken = tmp_path / ".aegis" / "rules" / "traps" / "broken.md"
    broken.write_text("---\nid: [unterminated\n---\nbody\n", encoding="utf-8")

    result = scan(tmp_path, ["src/a.py"])

    assert result["status"] == "FAIL"
    assert ".aegis/rules/traps/broken.md" in result["error"]
    assert result["rule_errors"] == [
        {"path": ".aegis/rules/traps/broken.md", "error": "malformed YAML frontmatter: unterminated flow sequence"},
    ]
    assert "relevant_rules" not in result


def test_a_v3_rule_left_in_walls_fails_the_scan_instead_of_silently_not_applying(tmp_path: Path) -> None:
    legacy = tmp_path / ".aegis" / "rules" / "walls" / "wall-x.md"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("---\nid: wall-x\ntype: wall\ntarget_paths: ['**']\n---\nb\n", encoding="utf-8")

    result = scan(tmp_path, ["src/a.py"])

    assert result["status"] == "FAIL" and "aegis migrate" in result["error"]


def test_an_unsafe_rules_tree_fails_closed(tmp_path: Path) -> None:
    _rule(tmp_path, "good")
    outside = tmp_path / "elsewhere.md"
    outside.write_text("---\nid: x\n---\n", encoding="utf-8")
    symlink_or_skip(outside, tmp_path / ".aegis" / "rules" / "traps" / "linked.md")

    result = scan(tmp_path, ["src/a.py"])

    assert result["status"] == "FAIL" and "cannot be read safely" in result["error"]


def test_expired_rules_and_files_outside_aegis_rules_are_never_served(tmp_path: Path) -> None:
    _rule(tmp_path, "trap-expired", extra="expired_at: '2026-01-01'\n")
    top = tmp_path / "rules"
    top.mkdir()
    (top / "providence.md").write_text("---\nid: providence\nnon_standard: true\n---\nAlways.\n", encoding="utf-8")

    result = scan(tmp_path, ["src/a.py"])

    assert result["relevant_rules"] == [] and result["stats"]["total_rules"] == 0


def test_markdown_that_is_not_a_rule_is_a_warning(tmp_path: Path) -> None:
    _rule(tmp_path, "t")
    (tmp_path / ".aegis" / "rules" / "notes.md").write_text("# notes\n", encoding="utf-8")

    result = scan(tmp_path, ["src/a.py"])

    assert _names(result) == ["t"]
    assert result["warnings"] == [
        "1 file under .aegis/rules is not a rule and was ignored (aegis status lists why): .aegis/rules/notes.md"
    ]


def test_many_ignored_files_cost_one_bounded_warning(tmp_path: Path) -> None:
    """A v3 init seeded presets into .aegis/rules (citadel has 18): every scan pays for the warning."""
    _rule(tmp_path, "t")
    for n in range(18):
        (tmp_path / ".aegis" / "rules" / f"preset-{n:02d}.md").write_text("# preset\n", encoding="utf-8")

    result = scan(tmp_path, ["src/a.py"])

    assert result["warnings"] == [
        "18 files under .aegis/rules are not rules and were ignored (aegis status lists why): "
        ".aegis/rules/preset-00.md, .aegis/rules/preset-01.md, .aegis/rules/preset-02.md and 15 more"
    ]


def test_rules_edited_since_sync_are_listed_and_still_served(tmp_path: Path) -> None:
    path = _rule(tmp_path, "t")
    sync.sync(tmp_path)
    path.write_text(path.read_text(encoding="utf-8").replace("Detail of t.", "Changed."), encoding="utf-8")

    result = scan(tmp_path, ["src/a.py"])

    assert _names(result) == ["t"]
    assert result["stale_rules"] == [{"id": "t", "path": ".aegis/rules/traps/t.md", "change": "edited"}]


def test_a_mandatory_rule_cut_by_the_token_budget_is_reported(tmp_path: Path) -> None:
    _rule(tmp_path, "inv", "invariant", extra="prediction: " + "x " * 400 + "\n")

    result = scan(tmp_path, ["src/a.py"], max_tokens=150)

    assert result["relevant_rules"] == []
    assert result["omitted_mandatory"] == [{"name": "inv", "type": "invariant", "reason": "token_budget"}]
    assert result["stats"]["omitted"] == 1 and result["stats"]["clamped"] is True
    assert result["stats"]["estimated_tokens"] <= 150
