"""Every surface sees the same rules for the same files, with the same ledger fitness.

One loader (aegis_core.rules), one matcher (aegis_core.match) and one estimator
(aegis_core.fitness) mean aegis scan, the SDK, coverage, the check telemetry, aegis
status, aegis_list_rules and aegis sync cannot disagree. This test asks each of them.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from aegis_core.rules import load_rules

RULES = {
    "trap-src-any": ["src/**/*.py"],
    "trap-top-level": ["src/*.py"],
    "trap-basename": ["conftest.py"],
    "trap-docs": ["docs/**", "README.md"],
    "trap-nothing": ["nowhere/*.go"],
}
FILES = ["src/app.py", "src/pkg/deep.py", "tests/conftest.py", "docs/guide/intro.md", "README.md", "setup.cfg"]


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    from aegis_core.telemetry_engine import ledger

    traps = tmp_path / ".aegis" / "rules" / "traps"
    traps.mkdir(parents=True)
    for rule_id, patterns in RULES.items():
        paths = "".join(f"  - '{p}'\n" for p in patterns)
        (traps / f"{rule_id}.md").write_text(
            f"---\nid: {rule_id}\ntype: trap\nhypothesis: h\ntarget_paths:\n{paths}---\nBody\n", encoding="utf-8"
        )
    for rel in FILES:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x\n", encoding="utf-8")
    ledger.append(tmp_path, [
        {"rule": "trap-src-any", "outcome": o, "source": "ci", "key": f"k{n}"}
        for n, o in enumerate(["tp"] * 9 + ["fp"])
    ])
    return tmp_path


def _expected(rel: str) -> set:
    from aegis_core.match import first_match

    return {rule_id for rule_id, patterns in RULES.items() if first_match(patterns, rel) is not None}


def test_the_matcher_reference_is_what_the_patterns_say():
    assert {f: _expected(f) for f in FILES} == {
        "src/app.py": {"trap-src-any", "trap-top-level"},
        "src/pkg/deep.py": {"trap-src-any", "trap-top-level"},  # `*` crosses `/`
        "tests/conftest.py": {"trap-basename"},  # a slashless pattern matches the basename
        "docs/guide/intro.md": {"trap-docs"},
        "README.md": {"trap-docs"},
        "setup.cfg": set(),
    }


@pytest.mark.parametrize("rel", FILES)
def test_scan_sdk_and_check_telemetry_match_the_same_rules(ws: Path, rel: str):
    from aegis_core.outcomes.engine import match_rules_to_changes
    from aegis_core.outcomes.telemetry import record_verification_telemetry
    from aegis_core.scan import RULE_CACHE, scan
    from aegis_core.telemetry_engine import ledger
    from aegis_mcp.tools import execute_tool
    from aegis_sdk import Governance

    RULE_CACHE.invalidate()
    expected = _expected(rel)
    core = scan(ws, [rel], budget=len(RULES), max_tokens=100000)
    mcp = execute_tool("aegis_scan", {"workspace": str(ws), "files": [rel]})
    assert {r["name"] for r in core["relevant_rules"]} == expected
    assert {r["name"] for r in mcp["relevant_rules"]} <= expected  # the MCP default budget is 3 slots
    assert {r["_name"] for r in match_rules_to_changes(ws, [rel])} == expected
    assert {r["_name"] for r in Governance(ws).scan([rel])} == expected

    before = len(ledger.read(ws).rows)
    record_verification_telemetry(str(ws), [rel], passed=True, source="session", run_id=f"run-{rel}")
    assert {r["rule"] for r in ledger.read(ws).rows[before:]} == expected


def test_coverage_covers_exactly_the_files_some_rule_matches(ws: Path):
    from aegis_core.metrics import calculate_coverage

    report = calculate_coverage(str(ws))
    covered = {f for f in FILES if _expected(f)}
    assert set(report["uncovered_files"]) == set(FILES) - covered
    assert report["covered"] == len(covered)


def test_status_list_sync_scan_and_sdk_report_one_fitness(ws: Path, capsys):
    from aegis_cli.status import run_status
    from aegis_core.fitness import compute
    from aegis_core.scan import RULE_CACHE, scan
    from aegis_core.sync import sync
    from aegis_mcp.tools import execute_tool
    from aegis_sdk import Governance

    from aegis_core.telemetry_engine import ledger

    # 24 tp of 25 verdicts (MIN_N, R-evidence-8): the Wilson lower bound (90%) is the score everywhere.
    ledger.append(ws, [{"rule": "trap-src-any", "outcome": "tp", "source": "ci", "key": f"m{n}"} for n in range(15)])
    score = compute({"tp": 24, "fp": 1, "triggers": 25}).score
    assert score == 0.8391

    RULE_CACHE.invalidate()
    scanned = {r["name"]: r["fitness"] for r in scan(ws, ["src/app.py"], budget=5)["relevant_rules"]}
    listed = {r["_name"]: r["fitness"] for r in execute_tool("aegis_list_rules", {"workspace": str(ws)})["rules"]}
    derived = sync(ws).derived["rules"]
    landscape = {row["rule"]: row for row in Governance(ws).fitness_landscape()}
    assert run_status(argparse.Namespace(_root=ws, json=True)) == 0
    status = {r["name"]: r for r in json.loads(capsys.readouterr().out)["rules"]}

    assert scanned["trap-src-any"] == score
    assert listed["trap-src-any"] == {"triggers": 25, "tp": 24, "fp": 1, "last_ts": listed["trap-src-any"]["last_ts"],
                                      "score": score, "reported_score": score, "status": None}
    assert (derived["trap-src-any"]["fitness"], derived["trap-src-any"]["triggers"]) == (score, 25)
    assert (landscape["trap-src-any"]["score"], landscape["trap-src-any"]["tp"]) == (score, 24)
    assert (status["trap-src-any"]["score"], status["trap-src-any"]["triggers"]) == (score, 25)
    # A rule with no verdicts: 0.0 where a number is required, no number where one is shown.
    assert listed["trap-top-level"]["score"] == derived["trap-top-level"]["fitness"] == 0.0
    assert scanned["trap-top-level"] is listed["trap-top-level"]["reported_score"] is None
    assert status["trap-top-level"]["score"] is None


def test_no_rule_is_silently_dropped_by_any_surface(ws: Path):
    """Every rule the loader serves is listed, indexed by sync and visible to the SDK."""
    from aegis_core.sync import build
    from aegis_mcp.tools import execute_tool
    from aegis_sdk import Governance

    served = {r.id for r in load_rules(ws).served}
    assert served == set(RULES)
    assert {r["_name"] for r in execute_tool("aegis_list_rules", {"workspace": str(ws)})["rules"]} == served
    assert set(build(ws)["rules"]) == served
    assert {r["_name"] for r in Governance(ws).list_rules()} == served


def test_every_surface_reads_one_file_the_same_however_it_is_spelled(ws: Path):
    """An absolute path, a ./ prefix and a repeat name one file: matched once, credited once."""
    from aegis_core.outcomes.engine import match_rules_to_changes
    from aegis_core.outcomes.telemetry import record_verification_telemetry
    from aegis_core.scan import RULE_CACHE, scan
    from aegis_core.telemetry_engine import ledger
    from aegis_sdk import Governance

    spellings = [str(ws / "src" / "app.py"), "./src/app.py", "src/app.py"]
    expected = _expected("src/app.py")
    RULE_CACHE.invalidate()

    core = scan(ws, spellings, budget=len(RULES), max_tokens=100000)
    assert {r["name"]: r["matched_files"] for r in core["relevant_rules"]} == {r: ["src/app.py"] for r in expected}
    for found in (match_rules_to_changes(ws, spellings), Governance(ws).scan(spellings)):
        assert {r["_name"]: r["_matched_files"] for r in found} == {r: ["src/app.py"] for r in expected}

    before = len(ledger.read(ws).rows)
    assert record_verification_telemetry(str(ws), spellings, passed=True, run_id="spellings")
    # one file shared by two rules: half the credit each
    assert {r["rule"]: r.get("weight", 1.0) for r in ledger.read(ws).rows[before:]} == {r: 0.5 for r in expected}


def test_scan_reads_an_absolute_spelling_as_the_workspace_relative_file(ws: Path):
    """Rules that match any path (``**``, a basename) would also match an absolute path
    taken as relative: every surface first makes each file workspace-relative, once."""
    from aegis_core.outcomes.engine import match_rules_to_changes
    from aegis_core.scan import RULE_CACHE, scan

    traps = ws / ".aegis" / "rules" / "traps"
    for rule_id, pattern in (("trap-everything", "**"), ("trap-app-anywhere", "app.py")):
        (traps / f"{rule_id}.md").write_text(
            f"---\nid: {rule_id}\ntype: trap\nhypothesis: h\ntarget_paths: ['{pattern}']\n---\nB\n", encoding="utf-8"
        )
    RULE_CACHE.invalidate()
    absolute = str(ws / "src" / "app.py")

    for spellings in ([absolute], [absolute, "./src/app.py", "src/app.py"]):
        core = scan(ws, spellings, budget=10, max_tokens=100000)
        matched = {r["name"]: r["matched_files"] for r in core["relevant_rules"]}
        assert matched["trap-everything"] == matched["trap-app-anywhere"] == ["src/app.py"], spellings
        found = {r["_name"]: r["_matched_files"] for r in match_rules_to_changes(ws, spellings)}
        assert found["trap-everything"] == found["trap-app-anywhere"] == ["src/app.py"], spellings


def test_check_telemetry_records_each_rules_share_of_the_credit(ws: Path):
    """Each changed file is worth 1, split among the rules matching it; a rule's row
    weight is its summed share, clamped to 1."""
    from aegis_core.outcomes.telemetry import record_verification_telemetry
    from aegis_core.telemetry_engine import ledger

    assert record_verification_telemetry(str(ws), ["src/app.py"], passed=True, run_id="split")
    # a row stores its weight only when it is below 1
    split = {r["rule"]: r.get("weight", 1.0) for r in ledger.read(ws).rows if r.get("key") == "split"}
    assert split == {"trap-src-any": 0.5, "trap-top-level": 0.5}

    # trap-docs alone matches two files (2.0 of credit): its row weight is clamped to 1
    assert record_verification_telemetry(
        str(ws), ["docs/guide/intro.md", "README.md", "tests/conftest.py", "src/app.py"], passed=False, run_id="clamp",
    )
    clamp = {r["rule"]: (r["outcome"], r.get("weight", 1.0)) for r in ledger.read(ws).rows if r.get("key") == "clamp"}
    # A local run writes triggers (R-evidence-1); the shares are kept on the row.
    assert clamp == {
        "trap-docs": ("trigger", 1.0),
        "trap-basename": ("trigger", 1.0),
        "trap-src-any": ("trigger", 0.5),
        "trap-top-level": ("trigger", 0.5),
    }


def test_a_rule_set_that_cannot_be_served_is_never_presented_as_whole(ws: Path):
    """Serving surfaces refuse a partial rule set; reporting surfaces count what they left out."""
    from aegis_core.errors import RuleParseError
    from aegis_core.metrics import calculate_coverage, calculate_governance_grade
    from aegis_core.scan import RULE_CACHE, scan
    from aegis_sdk import Governance

    (ws / ".aegis" / "rules" / "traps" / "typo.md").write_text(
        "---\nid: typo\ntype: trap\nhypothesis: h\ntarget_path: ['src/*.py']\n---\nB\n", encoding="utf-8"
    )
    RULE_CACHE.invalidate()

    assert scan(ws, ["src/app.py"])["status"] == "FAIL"
    with pytest.raises(RuleParseError) as raised:
        Governance(ws).scan(["src/app.py"])
    assert ".aegis/rules/traps/typo.md" in str(raised.value)
    assert [e["path"] for e in raised.value.rule_errors] == [".aegis/rules/traps/typo.md"]
    assert calculate_coverage(str(ws))["rule_errors"] == 1
    assert calculate_governance_grade(str(ws))["rule_errors"] == 1
    assert Governance(ws).coverage_report()["rule_errors"] == Governance(ws).grade()["rule_errors"] == 1


# ── forbid_ast: aegis check enforces a rule exactly where the other surfaces apply it ──

FORBID_RULES = {
    "forbid-eval-anywhere": None,  # no target_paths: aegis check has always enforced it on every file
    "forbid-exec-src": ["src/**/*.py"],
    "forbid-pickle-by-name": ["loader.py"],  # a slashless pattern: that basename anywhere
    "forbid-exec-in-tests": ["tests/**/*.py"],  # names tests, so the test-file exemption does not apply
}
FORBID_SPECS = {
    "forbid-eval-anywhere": "calls: [eval]",
    "forbid-exec-src": "calls: [exec]",
    "forbid-pickle-by-name": "imports: [pickle]",
    "forbid-exec-in-tests": "calls: [exec]",
}
FORBID_FILES = ["src/app.py", "src/pkg/loader.py", "lib/loader.py", "lib/util.py", "tests/loader.py"]


@pytest.fixture
def forbid_ws(tmp_path: Path) -> Path:
    invariants = tmp_path / ".aegis" / "rules" / "invariants"
    invariants.mkdir(parents=True)
    for rule_id, patterns in FORBID_RULES.items():
        scope = "" if patterns is None else "target_paths:\n" + "".join(f"  - '{p}'\n" for p in patterns)
        (invariants / f"{rule_id}.md").write_text(
            f"---\nid: {rule_id}\nenforcement: gate\nhypothesis: h\n{scope}"
            f"forbid_ast:\n  {FORBID_SPECS[rule_id]}\n---\nB\n",
            encoding="utf-8",
        )
    for rel in FORBID_FILES:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("import pickle\n\n\ndef f(x):\n    eval(x)\n    exec(x)\n", encoding="utf-8")
    return tmp_path


def _forbid_expected(rel: str) -> set:
    """Where the patterns say, except that a gate whose patterns do not name tests skips
    test files (tests use what gates forbid)."""
    from aegis_core.match import first_match, is_test_path

    def names_tests(patterns) -> bool:
        return any("tests/" in p or "test_" in p for p in patterns or [])

    return {
        rule_id for rule_id, patterns in FORBID_RULES.items()
        if (patterns is None or first_match(patterns, rel) is not None)
        and (names_tests(patterns) or not is_test_path(rel))
    }


def test_the_forbid_ast_reference_is_what_the_patterns_say():
    assert {f: _forbid_expected(f) for f in FORBID_FILES} == {
        "src/app.py": {"forbid-eval-anywhere", "forbid-exec-src"},
        "src/pkg/loader.py": {"forbid-eval-anywhere", "forbid-exec-src", "forbid-pickle-by-name"},
        "lib/loader.py": {"forbid-eval-anywhere", "forbid-pickle-by-name"},
        "lib/util.py": {"forbid-eval-anywhere"},
        # a test file: only the rule whose patterns name tests applies, even though
        # `**` and the basename pattern loader.py match it
        "tests/loader.py": {"forbid-exec-in-tests"},
    }


@pytest.mark.parametrize("rel", FORBID_FILES)
def test_check_enforces_forbid_ast_exactly_where_scan_sdk_and_telemetry_apply_it(forbid_ws: Path, rel: str):
    from aegis_core.outcomes.telemetry import record_verification_telemetry
    from aegis_core.scan import RULE_CACHE, scan
    from aegis_core.telemetry_engine import ledger
    from aegis_core.verification.pipeline import DeterministicVerifier
    from aegis_sdk import Governance

    expected = _forbid_expected(rel)
    RULE_CACHE.invalidate()

    for spelling in (rel, f"./{rel}", str(forbid_ws / rel)):
        evidence = DeterministicVerifier(fast_mode=True).verify(changed_files=[spelling], workspace=forbid_ws)
        enforced = {e.tool.split(":", 1)[1] for e in evidence if e.tool.startswith("forbid_ast:") and e.verdict is False}
        assert enforced == expected, spelling
    core = scan(forbid_ws, [rel], budget=len(FORBID_RULES), max_tokens=100000)
    # mandatory rules take at most two slots; the rest are named in omitted_mandatory
    served = {r["name"] for r in core["relevant_rules"]} | {r["name"] for r in core["omitted_mandatory"]}
    assert served == expected
    assert {r["_name"] for r in Governance(forbid_ws).scan([rel])} == expected
    record_verification_telemetry(str(forbid_ws), [rel], passed=False, run_id=f"run-{rel}")
    assert {r["rule"] for r in ledger.read(forbid_ws).rows if r.get("key") == f"run-{rel}"} == expected


def test_a_forbid_ast_rule_without_target_paths_covers_every_file(forbid_ws: Path):
    from aegis_core.metrics import calculate_coverage

    report = calculate_coverage(str(forbid_ws))

    assert report["uncovered_files"] == [] and report["covered"] == len(FORBID_FILES)
