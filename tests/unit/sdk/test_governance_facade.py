"""aegis_sdk is a thin, stable facade over aegis_core (ADR 0005 D9, defense #8).

Two external consumers depend on it: citadel fleet_telemetry.py calls
Governance(project_root=...).grade/coverage_report/scan/entropy, and mapleterm
telemetry.py calls Governance(ws).grade/scan. The SDK keeps exactly
Governance.{grade, coverage_report, scan, entropy, list_rules,
fitness_landscape}, parse_rule_file and __version__, with stable return shapes.

Every test drives a real scratch workspace (rules on disk, ledger rows, a git
repo for scan) - no mocks.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import aegis_sdk
from aegis_core import _version
from aegis_core.errors import AegisError, RuleNotFoundError, RuleParseError
from aegis_core.telemetry_engine.ledger import ledger_path
from aegis_sdk import Governance, parse_rule_file

KEPT_METHODS = {"grade", "coverage_report", "scan", "entropy", "list_rules", "fitness_landscape"}

TRAP = """---
id: trap-src-drift
type: trap
enforcement: advisory
hypothesis: Edits to src drift from the docs.
target_paths:
  - "src/*.py"
fitness:
  score: 0.8
  triggers: 10
  true_positives: 8
  false_positives: 2
---
Check the docs.
"""

INVARIANT = """---
id: invariant-app-pure
type: invariant
enforcement: gate
hypothesis: src/app.py stays free of import-time side effects.
target_paths:
  - src/app.py
fitness:
  score: 0.9
  triggers: 25
  true_positives: 24
  false_positives: 1
---
No work at import time.
"""


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    ).stdout


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    """A committed project: two rules, two source files, ledger rows; src/app.py then edited."""
    root = tmp_path / "proj"
    (root / ".aegis" / "rules" / "traps").mkdir(parents=True)
    (root / ".aegis" / "rules" / "invariants").mkdir(parents=True)
    (root / ".aegis" / "rules" / "traps" / "trap-src-drift.md").write_text(TRAP, encoding="utf-8")
    (root / ".aegis" / "rules" / "invariants" / "invariant-app-pure.md").write_text(INVARIANT, encoding="utf-8")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (root / "docs").mkdir()
    (root / "docs" / "notes.txt").write_text("notes\n", encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    rows = [
        {"rule_id": "trap-src-drift", "signal": "trigger", "source": "ci"},
        {"rule_id": "trap-src-drift", "signal": "tp", "source": "ci"},
        {"rule_id": "invariant-app-pure", "signal": "trigger", "source": "mcp"},
    ]
    # In a git repository the ledger is the one every worktree shares (in the common dir).
    ledger = ledger_path(root)
    ledger.parent.mkdir(parents=True)
    ledger.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    (root / "src" / "app.py").write_text("def add(a, b):\n    return b + a\n", encoding="utf-8")
    return root


# ── Public surface ─────────────────────────────────────────────────────────


def test_sdk_exports_only_the_facade() -> None:
    assert sorted(aegis_sdk.__all__) == ["Governance", "parse_rule_file"]
    # External callers read it (defense #8); it is the one version (D18).
    assert aegis_sdk.__version__ == _version.__version__


def test_governance_has_no_alias_or_writer_methods() -> None:
    public = {n for n in vars(Governance) if not n.startswith("_")}
    assert public == KEPT_METHODS


def test_constructor_accepts_keyword_and_positional_roots(ws: Path) -> None:
    """citadel passes project_root=..., mapleterm passes the workspace positionally."""
    assert Governance(project_root=ws).root == ws.resolve()
    assert Governance(str(ws)).root == ws.resolve()


# ── Behaviour of each kept method ───────────────────────────────────────────


def test_list_rules_returns_every_rule_with_name_and_path(ws: Path) -> None:
    rules = Governance(ws).list_rules()

    assert sorted(r["_name"] for r in rules) == ["invariant-app-pure", "trap-src-drift"]
    by_name = {r["_name"]: r for r in rules}
    assert by_name["trap-src-drift"]["_path"].endswith("traps/trap-src-drift.md")
    assert by_name["invariant-app-pure"]["enforcement"] == "gate"


def test_list_rules_filters_by_canonical_type(ws: Path) -> None:
    gov = Governance(ws)

    assert [r["_name"] for r in gov.list_rules("trap")] == ["trap-src-drift"]
    assert [r["_name"] for r in gov.list_rules("invariant")] == ["invariant-app-pure"]
    # The v1/v2 type names are gone (one rule-type table); aegis migrate converts old rules.
    assert gov.list_rules("learned-trap") == []


def test_list_rules_keeps_a_malformed_rule_visible_as_an_error_record(ws: Path) -> None:
    (ws / ".aegis" / "rules" / "traps" / "broken.md").write_text("---\nid: [unclosed\n---\n", encoding="utf-8")

    broken = [r for r in Governance(ws).list_rules() if r["_name"] == "broken"]

    assert broken == [{
        "type": "trap",
        "_name": "broken",
        "_path": ".aegis/rules/traps/broken.md",
        "_error": "malformed YAML frontmatter: unterminated flow sequence",
    }]


def test_grade_reports_every_component_with_a_letter(ws: Path) -> None:
    report = Governance(ws).grade()

    for key in ("coverage", "avg_fitness", "diversity", "staleness", "invariant_integrity", "overall"):
        assert set(report[key]) >= {"pct", "grade"}, key
        assert isinstance(report[key]["pct"], float)
    assert report["coverage"]["pct"] == 50.0  # src/app.py of {src/app.py, docs/notes.txt}
    assert report["tiers"] == {"advisory": 1, "gate": 1}
    assert report["details"]["total_rules"] == 2
    assert (report["details"]["invariants"], report["details"]["healthy_invariants"]) == (1, 0)
    assert set(report["details"]) == {"invariants", "healthy_invariants", "total_rules", "stale_rules"}


def test_grade_of_a_workspace_without_rules_is_the_documented_fallback(tmp_path: Path) -> None:
    (tmp_path / ".aegis" / "rules").mkdir(parents=True)

    report = Governance(tmp_path).grade()

    assert report["overall"] == {"pct": 0.0, "grade": "F"}
    assert report["status"] == "PASS"
    assert report["note"] == "No rules found to grade"
    assert report["rule_errors"] == 0


def test_grade_of_a_workspace_whose_rules_cannot_be_loaded_says_so(tmp_path: Path) -> None:
    traps = tmp_path / ".aegis" / "rules" / "traps"
    traps.mkdir(parents=True)
    (traps / "broken.md").write_text("---\nid: [unclosed\n---\n", encoding="utf-8")

    report = Governance(tmp_path).grade()

    assert report["overall"] == {"pct": 0.0, "grade": "F"}
    assert report["status"] == "FAIL" and report["rule_errors"] == 1
    assert report["note"] == "No rule could be graded: 1 rule file(s) cannot be loaded (aegis status lists them)"


def test_scan_refuses_a_rule_set_with_a_broken_rule(ws: Path) -> None:
    """A partial rule set is never returned as the rules for these files (defense #19)."""
    (ws / ".aegis" / "rules" / "traps" / "trap-src-drift-copy.md").write_text(
        "---\nid: trap-src-drift-copy\npaths: ['src/*.py']\n---\nB\n", encoding="utf-8"
    )

    with pytest.raises(RuleParseError, match="1 rule file\\(s\\) cannot be served") as raised:
        Governance(ws).scan(["src/app.py"])

    assert raised.value.rule_errors[0]["path"] == ".aegis/rules/traps/trap-src-drift-copy.md"
    assert isinstance(raised.value, AegisError)


def test_coverage_report_maps_files_to_rules(ws: Path) -> None:
    report = Governance(ws).coverage_report()

    assert (report["total_files"], report["covered"], report["uncovered"]) == (2, 1, 1)
    assert report["coverage_pct"] == 50.0
    assert report["uncovered_files"] == ["docs/notes.txt"]
    assert report["by_directory"]["src"] == {"covered": 1, "total": 1, "tier": "gate"}


def test_coverage_report_honours_an_exclude_pattern(ws: Path) -> None:
    report = Governance(ws).coverage_report(exclude="docs/")

    assert (report["total_files"], report["covered"]) == (1, 1)
    assert report["coverage_pct"] == 100.0


def test_scan_defaults_to_the_files_git_reports_changed(ws: Path) -> None:
    matched = Governance(ws).scan()

    assert sorted(m["_name"] for m in matched) == ["invariant-app-pure", "trap-src-drift"]
    assert all(m["_path"].endswith(".md") for m in matched)


def test_scan_of_explicit_files_matches_only_their_rules(ws: Path) -> None:
    gov = Governance(ws)

    assert [m["_name"] for m in gov.scan(["src/other.py"])] == ["trap-src-drift"]
    assert gov.scan(["docs/notes.txt"]) == []


def test_entropy_reports_population_and_type_distribution(ws: Path) -> None:
    result = Governance(ws).entropy()

    assert result["population"] == {"total": 2}
    assert result["type_entropy"] == {"value": 1.0, "distribution": {"invariant": 1, "trap": 1}}


def test_entropy_of_an_empty_workspace(tmp_path: Path) -> None:
    (tmp_path / ".aegis" / "rules").mkdir(parents=True)

    assert Governance(tmp_path).entropy() == {
        "population": {"total": 0, "active": 0, "dormant": 0},
        "type_entropy": 0.0,
    }


def test_fitness_landscape_scores_every_rule_from_the_ledger(ws: Path) -> None:
    landscape = {row["rule"]: row for row in Governance(ws).fitness_landscape()}

    assert set(landscape) == {"invariant-app-pure", "trap-src-drift"}
    trap = landscape["trap-src-drift"]
    # The ledger pairs the trap's v1 trigger row with its tp row (one trigger); the
    # frontmatter `fitness:` block (10 triggers, 8 tp) is a legacy counter and is ignored.
    assert (trap["type"], trap["triggers"], trap["tp"], trap["fp"]) == ("trap", 1, 1, 0)
    assert trap["path"] == ".aegis/rules/traps/trap-src-drift.md"
    assert trap["score"] == 0.2698  # the Wilson lower bound of 1 of 1
    assert trap["suggestion"] is None
    assert (landscape["invariant-app-pure"]["triggers"], landscape["invariant-app-pure"]["score"]) == (1, 0.0)
    assert "bayesian" not in trap


def test_fitness_landscape_with_bayesian_adds_the_interval(ws: Path) -> None:
    landscape = {row["rule"]: row for row in Governance(ws).fitness_landscape(bayesian=True)}

    assert landscape["trap-src-drift"]["bayesian"] == {"lower": 0.2698, "upper": 1.0}
    assert landscape["invariant-app-pure"]["bayesian"] == {"lower": 0.0, "upper": 1.0}


# ── parse_rule_file ────────────────────────────────────────────────────────


def test_parse_rule_file_returns_frontmatter_and_body(ws: Path) -> None:
    meta, body = parse_rule_file(str(ws / ".aegis" / "rules" / "traps" / "trap-src-drift.md"))

    assert meta["id"] == "trap-src-drift"
    assert meta["target_paths"] == ["src/*.py"]
    assert body == "Check the docs.\n"


def test_parse_rule_file_of_a_missing_file_raises_rule_not_found(tmp_path: Path) -> None:
    with pytest.raises(RuleNotFoundError, match="Rule file not found"):
        parse_rule_file(str(tmp_path / "absent.md"))


def test_parse_rule_file_without_frontmatter_raises_rule_parse_error(tmp_path: Path) -> None:
    path = tmp_path / "plain.md"
    path.write_text("no frontmatter here\n", encoding="utf-8")

    with pytest.raises(RuleParseError, match="Error parsing rule"):
        parse_rule_file(str(path))
    assert issubclass(RuleParseError, AegisError) and issubclass(RuleNotFoundError, AegisError)


def test_sdk_parse_rule_file_is_the_core_function() -> None:
    """One implementation: the SDK re-exports aegis_core's, it does not wrap a copy."""
    from aegis_core.yaml_engine.frontmatter import parse_rule_file as core_parse_rule_file

    assert parse_rule_file is core_parse_rule_file
