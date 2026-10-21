"""From Layer 1 evidence to baseline findings, and the ratchet itself (v4.2 #2).

These run the real Layer 1 tools in a throwaway repository. What is pinned: a finding is
one matched line (not one failed check), its fingerprint ignores where the line is,
the baseline grandfathers exactly what it holds (rule, path and fingerprint all equal),
and a failure that is not about a line of a checked file can never be grandfathered.
"""
from __future__ import annotations

from pathlib import Path
import shutil
from typing import List, Optional, Sequence, Tuple

import pytest

from aegis_core import baseline
from aegis_core.baseline import Baseline, Entry, Finding, Sources
from aegis_core.verification import ToolEvidence, runner
from tests.helpers_checkmodes import commit, git, init_repo, write

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

CALLS_SUBPROCESS = (
    "---\nid: no-subprocess\ntype: invariant\nenforcement: gate\n"
    "forbid_ast:\n  calls: [subprocess.run]\n---\n# No subprocess.run\n"
)
NO_PICKLE = (
    "---\nid: no-pickle\ntype: invariant\nenforcement: gate\n"
    "forbid_ast:\n  imports: [pickle]\n---\n# No pickle\n"
)
NO_DECORATOR = (
    "---\nid: no-cache\ntype: invariant\nenforcement: gate\n"
    "forbid_ast:\n  decorators: [lru_cache]\n---\n# No lru_cache\n"
)


@pytest.fixture
def repo(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    root = init_repo(tmp_path / "project")
    write(root, "keep.py", "x = 1\n")
    commit(root, "base")
    return root


def _layer1(root: Path, files: Sequence[str], fast: bool = True) -> List[Tuple[Optional[str], ToolEvidence]]:
    return baseline.run_grouped(
        lambda group: runner.run_layer1(changed_files=list(group), repo_root=str(root), fast_mode=fast), files)


def _collect(root: Path, files: Sequence[str], fast: bool = True) -> baseline.Collected:
    return baseline.collect(_layer1(root, files, fast), Sources(root))


def _apply(root: Path, files: Sequence[str], entries) -> baseline.Applied:
    return baseline.apply(_layer1(root, files), Sources(root), Baseline(frozenset(entries), "t", "working-tree"))


def _entries(root: Path, files: Sequence[str]) -> List[Entry]:
    return [f.entry for f in _collect(root, files).findings]


# ── Grouping and attribution ─────────────────────────────────────────────────

def test_files_with_distinct_names_are_one_group_in_their_order():
    assert baseline.basename_groups(["b/x.py", "a/y.py", "c/z.md"]) == [["b/x.py", "a/y.py", "c/z.md"]]


def test_files_sharing_a_name_go_to_different_groups_and_nothing_is_dropped():
    groups = baseline.basename_groups(["a/utils.py", "b/utils.py", "c/other.py", "d/utils.py", "a/utils.py"])
    assert groups == [["a/utils.py", "c/other.py"], ["b/utils.py"], ["d/utils.py"]]


def test_evidence_that_names_only_a_basename_is_attributed_to_the_right_file(repo: Path):
    write(repo, "a/utils.py", "import google.genai\n")
    write(repo, "b/utils.py", "x = 1\n")
    pairs = _layer1(repo, ["a/utils.py", "b/utils.py"])
    failing = [(path, e.tool) for path, e in pairs if not e.verdict]
    assert failing == [("a/utils.py", "import_guard")]
    # and the other way round: the same name, the failing one second
    pairs = _layer1(repo, ["b/utils.py", "a/utils.py"])
    assert [(path, e.tool) for path, e in pairs if not e.verdict] == [("a/utils.py", "import_guard")]


def test_forbid_ast_evidence_is_attributed_by_its_path(repo: Path):
    write(repo, "src/app.py", "x = eval('1')\n")
    pairs = _layer1(repo, ["src/app.py"])
    assert [(path, e.tool) for path, e in pairs if not e.verdict] == [("src/app.py", "forbid_ast:no-eval")]


def test_a_failure_about_no_checked_file_has_no_path(repo: Path):
    write(repo, ".aegis/rules/invariants/broken.md", "---\nid: broken\ntype: invariant\nforbid_ast: [eval]\n---\nx\n")
    write(repo, "app.py", "x = 1\n")
    pairs = _layer1(repo, ["app.py"])
    assert [(path, e.tool) for path, e in pairs if not e.verdict] == [(None, "forbid_ast")]


# ── Findings ─────────────────────────────────────────────────────────────────

def test_an_unguarded_import_is_one_finding_per_matched_line(repo: Path):
    write(repo, "lib/bad.py", "import os\nimport google.genai\n\n\ndef run():\n    import yaml\n    return 1\n")
    found = _collect(repo, ["lib/bad.py"]).findings
    assert [(f.rule, f.path, f.line, f.text, f.index) for f in found] == [
        ("import_guard", "lib/bad.py", 2, "import google.genai", 0),
        ("import_guard", "lib/bad.py", 6, "import yaml", 0),
    ]
    assert all("Unguarded third-party imports" in f.detail for f in found)


def test_an_orphan_function_is_a_finding_at_its_def_line(repo: Path):
    # Only the full check walks the repository for callers; the fast one cannot flag an orphan.
    write(repo, "lib/mod.py", "def _used():\n    return 1\n\n\ndef public():\n    return _used()\n\n\ndef _lonely():\n    return 2\n")
    found = _collect(repo, ["lib/mod.py"], fast=False).findings
    assert [(f.rule, f.line, f.text) for f in found] == [
        ("call_graph", 5, "def public():"), ("call_graph", 9, "def _lonely():")]


def test_forbid_ast_gives_one_finding_per_violating_call_site(repo: Path):
    write(repo, "app.py", 'a = eval("1")\nb = 2\nc = eval("3")\nd = eval("1")\n')
    found = _collect(repo, ["app.py"]).findings
    assert [(f.rule, f.line, f.text, f.index) for f in found] == [
        ("forbid_ast:no-eval", 1, 'a = eval("1")', 0),
        ("forbid_ast:no-eval", 3, 'c = eval("3")', 0),
        ("forbid_ast:no-eval", 4, 'd = eval("1")', 0),
    ]
    assert all("Forbidden call 'eval'" in f.detail for f in found)


def test_two_copies_of_one_line_are_two_findings_with_different_fingerprints(repo: Path):
    write(repo, "app.py", "x = eval(1)\ny = 2\nx = eval(1)\n")
    found = _collect(repo, ["app.py"]).findings
    assert [(f.line, f.index) for f in found] == [(1, 0), (3, 1)]
    assert found[0].fp != found[1].fp


def test_an_aliased_call_is_found_the_way_the_gate_found_it(repo: Path):
    write(repo, ".aegis/rules/invariants/no-subprocess.md", CALLS_SUBPROCESS)
    commit(repo, "the reviewed rule")  # Layer 1 enforces the base version
    write(repo, "run.py", "import subprocess as sp\n\n\ndef go():\n    sp.run(['ls'])\n    return 1\n")
    found = [f for f in _collect(repo, ["run.py"]).findings if f.rule == "forbid_ast:no-subprocess"]
    assert [(f.line, f.text) for f in found] == [(5, "sp.run(['ls'])")]


def test_a_forbidden_import_is_a_finding_at_each_import_line(repo: Path):
    write(repo, ".aegis/rules/invariants/no-pickle.md", NO_PICKLE)
    commit(repo, "the reviewed rule")  # Layer 1 enforces the base version
    write(repo, "io_.py", "import json\nimport pickle\nfrom pickle import loads\n")
    found = [f for f in _collect(repo, ["io_.py"]).findings if f.rule == "forbid_ast:no-pickle"]
    assert [(f.line, f.text) for f in found] == [(2, "import pickle"), (3, "from pickle import loads")]


def test_a_decorator_violation_has_no_line_so_it_cannot_be_baselined(repo: Path):
    write(repo, ".aegis/rules/invariants/no-cache.md", NO_DECORATOR)
    commit(repo, "the reviewed rule")  # Layer 1 enforces the base version
    write(repo, "cached.py", "from functools import lru_cache\n\n\n@lru_cache\ndef f():\n    return 1\n")
    result = _collect(repo, ["cached.py"])
    assert [f for f in result.findings if f.rule == "forbid_ast:no-cache"] == []
    assert [e.tool for e in result.blocked] == ["forbid_ast:no-cache"]


def test_a_file_that_cannot_be_parsed_fails_and_cannot_be_baselined(repo: Path):
    write(repo, "broken.py", "def (:\n")
    result = _collect(repo, ["broken.py"])
    assert result.findings == ()
    assert result.blocked and all(not e.verdict for e in result.blocked)


def test_a_failure_with_no_matched_line_is_never_a_finding(repo: Path):
    evidence = ToolEvidence(tool="mutation_tester", target="app.py::f", verdict=False, detail="2 mutants survived")
    result = baseline.collect([("app.py", evidence)], Sources(repo))
    assert (result.findings, result.blocked) == ((), (evidence,))


def test_passing_evidence_is_no_finding_and_not_blocked(repo: Path):
    write(repo, "clean.py", "def f():\n    return 1\n")
    result = _collect(repo, ["clean.py"])
    assert result.findings == () and result.blocked == ()


def test_a_line_that_is_not_in_the_file_still_makes_a_finding_without_text(repo: Path):
    evidence = ToolEvidence(tool="import_guard", target="gone.py", verdict=False, detail="x", lines=[9])
    write(repo, "gone.py", "import yaml\n")
    result = baseline.collect([("gone.py", evidence)], Sources(repo))
    assert [(f.line, f.text, f.index) for f in result.findings] == [(9, "", 0)]


def test_form_feeds_do_not_shift_the_matched_line(repo: Path):
    write(repo, "ff.py", "x = 1\n\x0c\nimport google.genai\n")
    found = _collect(repo, ["ff.py"]).findings
    assert [(f.line, f.text) for f in found] == [(3, "import google.genai")]


# ── The ratchet ──────────────────────────────────────────────────────────────

def test_everything_the_baseline_holds_is_grandfathered(repo: Path):
    write(repo, "app.py", "x = eval(1)\nimport google.genai\n")
    files = ["app.py"]
    held = _entries(repo, files)
    assert len(held) == 2
    result = _apply(repo, files, held)
    assert result.new == () and result.blocked == ()
    assert len(result.grandfathered) == 2
    assert result.passed and all(e.verdict for e in result.effective)


def test_a_grandfathered_check_says_so_in_its_detail(repo: Path):
    write(repo, "app.py", "x = eval(1)\n")
    result = _apply(repo, ["app.py"], _entries(repo, ["app.py"]))
    grandfathered = [e for e in result.effective if e.tool == "forbid_ast:no-eval"]
    assert [e.verdict for e in grandfathered] == [True]
    assert "grandfathered by the baseline: 1 finding(s)" in grandfathered[0].detail


def test_an_empty_baseline_grandfathers_nothing(repo: Path):
    write(repo, "app.py", "x = eval(1)\n")
    result = _apply(repo, ["app.py"], [])
    assert [f.line for f in result.new] == [1] and not result.passed


def test_a_finding_that_moves_is_still_grandfathered(repo: Path):
    write(repo, "app.py", "x = eval(1)\n")
    held = _entries(repo, ["app.py"])
    write(repo, "app.py", "# header\n# more\n\n\nx = eval(1)\n")
    result = _apply(repo, ["app.py"], held)
    assert result.new == () and result.passed and [f.line for f in result.grandfathered] == [5]


def test_reindenting_a_finding_keeps_it_grandfathered(repo: Path):
    write(repo, "app.py", "def f():\n    x = eval(1)\n    return x\n")
    held = _entries(repo, ["app.py"])
    write(repo, "app.py", "def f():\n        x  =  eval(1)\n        return x\n")
    assert _apply(repo, ["app.py"], held).new == ()


def test_editing_a_grandfathered_line_makes_it_new(repo: Path):
    write(repo, "app.py", "x = eval(1)\n")
    held = _entries(repo, ["app.py"])
    write(repo, "app.py", "x = eval(2)\n")
    result = _apply(repo, ["app.py"], held)
    assert [f.text for f in result.new] == ["x = eval(2)"] and not result.passed


def test_a_new_violation_in_a_file_that_already_has_one_is_new(repo: Path):
    write(repo, "app.py", "x = eval(1)\n")
    held = _entries(repo, ["app.py"])
    write(repo, "app.py", "x = eval(1)\ny = eval(2)\n")
    result = _apply(repo, ["app.py"], held)
    assert [f.text for f in result.new] == ["y = eval(2)"]
    assert [f.text for f in result.grandfathered] == ["x = eval(1)"]
    assert not result.passed


def test_a_third_copy_of_a_baselined_line_is_new(repo: Path):
    write(repo, "app.py", "x = eval(1)\nx = eval(1)\n")
    held = _entries(repo, ["app.py"])
    write(repo, "app.py", "x = eval(1)\nx = eval(1)\nx = eval(1)\n")
    result = _apply(repo, ["app.py"], held)
    assert [(f.line, f.index) for f in result.new] == [(3, 2)]


def test_the_same_line_in_another_file_is_new(repo: Path):
    write(repo, "app.py", "x = eval(1)\n")
    held = _entries(repo, ["app.py"])
    write(repo, "other.py", "x = eval(1)\n")
    result = _apply(repo, ["other.py"], held)
    assert [f.path for f in result.new] == ["other.py"]


def test_an_entry_must_match_in_rule_path_and_fingerprint(repo: Path):
    write(repo, "app.py", "x = eval(1)\n")
    (entry,) = _entries(repo, ["app.py"])
    for wrong in (Entry("other-rule", entry.path, entry.fp), Entry(entry.rule, "elsewhere.py", entry.fp),
                  Entry(entry.rule, entry.path, "f" * 16)):
        assert _apply(repo, ["app.py"], [wrong]).new, wrong


def test_a_failure_that_cannot_be_baselined_fails_whatever_the_baseline_holds(repo: Path):
    write(repo, "broken.py", "def (:\n")
    write(repo, "app.py", "x = eval(1)\n")
    held = _entries(repo, ["app.py"])
    result = _apply(repo, ["broken.py", "app.py"], held)
    assert result.blocked and not result.passed
    assert [f.path for f in result.grandfathered] == ["app.py"]


def test_a_partly_new_check_stays_failing_and_names_only_the_new_lines(repo: Path):
    write(repo, "app.py", "x = eval(1)\n")
    held = _entries(repo, ["app.py"])
    write(repo, "app.py", "x = eval(1)\ny = eval(2)\n")
    result = _apply(repo, ["app.py"], held)
    failing = [e for e in result.effective if not e.verdict]
    assert [e.tool for e in failing] == ["forbid_ast:no-eval"]
    assert "new: line 2" in failing[0].detail and "y = eval(2)" in failing[0].detail
    assert "x = eval(1)" not in failing[0].detail.split("new:", 1)[1]


def test_effective_evidence_keeps_the_order_and_count(repo: Path):
    write(repo, "app.py", "x = eval(1)\nimport google.genai\n")
    pairs = _layer1(repo, ["app.py"])
    result = baseline.apply(pairs, Sources(repo), Baseline(frozenset(), "t", "working-tree"))
    assert [(e.tool, e.target) for e in result.effective] == [(e.tool, e.target) for _, e in pairs]


# ── The index (the pre-commit hook) ──────────────────────────────────────────

def test_sources_read_the_staged_content_not_the_working_tree(repo: Path):
    write(repo, "app.py", "x = eval(1)\n")
    git(repo, "add", "app.py")
    write(repo, "app.py", "x = 1\n")  # the commit would still record the eval
    assert Sources(repo).lines("app.py") == ["x = 1", ""]
    assert Sources(repo, staged=True).lines("app.py") == ["x = eval(1)", ""]


def test_a_violation_staged_but_reverted_in_the_working_tree_is_a_finding_at_the_staged_line(repo: Path):
    write(repo, "app.py", "y = 1\nx = eval(1)\n")
    git(repo, "add", "app.py")
    write(repo, "app.py", "y = 1\n")
    pairs = baseline.run_grouped(lambda group: runner.run_layer1_on_index(list(group), str(repo)), ["app.py"])
    result = baseline.collect(pairs, Sources(repo, staged=True))
    assert [(f.line, f.text) for f in result.findings] == [(2, "x = eval(1)")]


def test_a_staged_new_violation_is_not_hidden_by_an_older_one_in_the_working_tree(repo: Path):
    write(repo, "app.py", "x = eval(1)\n")
    held = _entries(repo, ["app.py"])
    write(repo, "app.py", "x = eval(1)\ny = eval(2)\n")
    git(repo, "add", "app.py")
    write(repo, "app.py", "x = eval(1)\n")  # the new call is gone from the working tree only
    pairs = baseline.run_grouped(lambda group: runner.run_layer1_on_index(list(group), str(repo)), ["app.py"])
    result = baseline.apply(pairs, Sources(repo, staged=True), Baseline(frozenset(held), "t", "working-tree"))
    assert [f.text for f in result.new] == ["y = eval(2)"] and not result.passed
