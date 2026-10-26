"""aegis_cli.formatters.text renders the five core reports from their as_dict() documents
(R-structure-37): aegis_core returns data, aegis_cli owns terminal text.

Given a report built from fixed data, When its as_dict() document is rendered, Then the lines are
byte-identical to what the report's own text method printed before the move (recorded below).
"""
from __future__ import annotations

import ast
import io
import json
from pathlib import Path
import sys

import pytest

from aegis_cli.formatters import text
from aegis_core import card, human_gate, lane_gate, partition, release_verify

REPO = Path(__file__).resolve().parents[3]


def _card(**overrides):
    fields = dict(
        workspace="/ws", listing="git", files=3, files_analyzed=3, sample_limit=2000,
        languages=({"language": "python", "files": 2, "extensions": [".py"]},
                   {"language": "rust", "files": 1, "extensions": [".rs"]}),
        drivers=({"language": "python", "driver": "built-in (in-process)", "status": "ready", "reason": None},
                 {"language": "rust", "driver": None, "status": "not enabled", "reason": "x"}),
        rules={"total": 2, "by_type": {"invariant": 1, "trap": 1}, "served": 2, "errors": 0, "active": ["no-eval"],
               "error": None},
        layer1={"checked": 2, "passed": 1, "failed": 1, "pass_rate": 0.5, "findings": 3,
                "checks_that_could_not_run": [], "top": [{"path": "src/bad.py", "findings": 3}]},
        checked_at=0)
    fields.update(overrides)
    return card.Card(**fields)


def test_the_card_renders_its_counts_and_the_files_with_most_findings():
    assert text.render_card(_card().as_dict()) == [
        "Aegis day-0 card",
        "  workspace: /ws",
        "  files: 3 (git), all analyzed",
        "  languages: python 2, rust 1",
        "  AST drivers: python: built-in; rust: not enabled",
        "  rules: 2 (invariant 1, trap 1), 1 active (served and targeting a file)",
        "  Layer 1: 50% of 2 files pass (1 of 2); 3 finding(s) in 1 file(s)",
        "  files with the most findings:",
        "        3  src/bad.py",
    ]


def test_a_sampled_walked_card_whose_rules_cannot_be_read_says_each_note():
    built = _card(workspace="/w s", listing="walk", files=9, files_analyzed=4, sample_limit=4, languages=(),
                  drivers=(), rules={"total": 0, "by_type": {}, "served": 0, "errors": 0, "active": [],
                                     "error": "unsafe tree"},
                  layer1={"checked": 0, "passed": 0, "failed": 0, "pass_rate": None, "findings": 0,
                          "checks_that_could_not_run": ["Layer 1 could not run: OSError: boom"], "top": []})
    assert text.render_card(built.as_dict()) == [
        "Aegis day-0 card",
        "  workspace: /w s",
        "  files: 9 (walked). Sampled 4 of 9 files for Layer 1",
        "  languages: none recognized (rules are language-agnostic)",
        "  rules: cannot be read (see the note below)",
        "  Layer 1: no file to check",
        "  note: No active rule targets any file: aegis check enforces no rule until one names files.",
        "  note: The rules could not be read (unsafe tree), so no rule is counted.",
        "  note: Not a git work tree: the files were found by walking the directory, leaving out build and vendor "
        "directories.",
        "  note: Sampled 4 of 9 files (every file in an even spread of the sorted listing) for Layer 1; the languages "
        "and the rules cover all of them.",
        "  note: 1 check(s) could not run, so the pass rate does not count them (aegis check shows why).",
        "  Next: add a rule for your own code with aegis rule create (aegis rule create --help)",
    ]


def test_a_card_with_no_active_rule_names_the_next_step():
    built = _card(files=1, files_analyzed=1, languages=({"language": "python", "files": 1, "extensions": [".py"]},),
                  drivers=({"language": "python", "driver": "built-in (in-process)", "status": "ready",
                            "reason": None},),
                  rules={"total": 1, "by_type": {"trap": 1}, "served": 1, "errors": 1, "active": [], "error": None},
                  layer1={"checked": 1, "passed": 1, "failed": 0, "pass_rate": 1.0, "findings": 0,
                          "checks_that_could_not_run": [], "top": []})
    assert text.render_card(built.as_dict()) == [
        "Aegis day-0 card",
        "  workspace: /ws",
        "  files: 1 (git), all analyzed",
        "  languages: python 1",
        "  AST drivers: python: built-in",
        "  rules: 1 (trap 1), 0 active (served and targeting a file)",
        "  Layer 1: 100% of 1 files pass (1 of 1); 0 finding(s) in 0 file(s)",
        "  note: No active rule targets any file: aegis check enforces no rule until one names files.",
        "  note: 1 rule file(s) cannot be served (aegis status lists them).",
        "  Next: add a rule for your own code with aegis rule create (aegis rule create --help)",
    ]


def test_a_directory_that_is_no_aegis_workspace_renders_the_card_it_always_did(tmp_path):
    # Sad path: no .aegis/, no git, nothing to check.
    assert text.render_card(card.build(tmp_path, now=0).as_dict()) == [
        "Aegis day-0 card",
        f"  workspace: {tmp_path}",
        "  files: 0 (walked), all analyzed",
        "  languages: none recognized (rules are language-agnostic)",
        "  rules: 0, 0 active (served and targeting a file)",
        "  Layer 1: no file to check",
        "  note: No active rule targets any file: aegis check enforces no rule until one names files.",
        "  note: Not a git work tree: the files were found by walking the directory, leaving out build and vendor "
        "directories.",
        "  Next: add a rule for your own code with aegis rule create (aegis rule create --help)",
    ]


def test_the_partition_report_groups_edges_and_caps_the_files_not_analyzed():
    edge, frozen = partition.Edge, partition.Frozen
    report = partition.Report(
        workspace="/ws", listing="git", lanes={"A": ("a/**",), "B": ("b/**", "c/**")},
        lane_files={"A": 2, "B": 3}, analyzed={"A": 2, "B": 2}, languages={"python": 3, "rust": 1}, files=6,
        unassigned=1, overlap=(("x.py", ("A", "B")),),
        edges=(edge("import", "A", "B", "a/m.py", 3, "b/n.py", "helper", "b.n", 7),
               edge("call", "A", "B", "a/m.py", 9, "b/n.py", None, "b.n", None),
               edge("import", "B", "A", "b/n.py", 1, "a/m.py", "f", "a.m", 2)),
        frozen=(frozen("B", "b/n.py", "helper", 7, "def helper(x)", (("A", "a/m.py", 3), ("A", "a/m.py", 9))),),
        not_analyzed=tuple((f"z/{i}.go", "no partition support for .go files") for i in range(22)),
        checked_at=0, warnings=("event not recorded: disk full",))
    lines = text.render_partition(report.as_dict())
    assert lines[:13] == [
        "aegis check --partition: 2 lanes, 4 file(s) analyzed (3 python, 1 rust), 22 not analyzed",
        "lanes:",
        "  A: 2 file(s) [a/**]",
        "  B: 3 file(s) [b/**, c/**]",
        "overlap (matched by more than one lane; left out of the edges):",
        "  x.py (A, B)",
        "cross-lane edges: 3",
        "  A -> B: 2",
        "    import  a/m.py:3 -> b/n.py::helper  (b.n)",
        "    call    a/m.py:9 -> b/n.py  (b.n)",
        "  B -> A: 1",
        "    import  b/n.py:1 -> a/m.py::f  (a.m)",
        "not analyzed:",
    ]
    assert lines[13:33] == [f"  z/{i}.go: no partition support for .go files" for i in range(20)]
    assert lines[33:] == [
        "  ... and 2 more",
        "[FROZEN_SIGNATURES]",
        "# Do not change these while the lanes run in parallel; a change is a request to the dispatcher.",
        "b/n.py::helper  def helper(x)  (lane B; used by A: a/m.py:3, A: a/m.py:9)",
        "[/FROZEN_SIGNATURES]",
        partition.LIMITS[0],
        "warning: event not recorded: disk full",
    ]


def test_an_empty_partition_report_says_none_for_each_section():
    report = partition.Report(workspace="/ws", listing="walk", lanes={"A": ("a/**",), "B": ("b/**",)},
                              lane_files={}, analyzed={}, languages={}, files=0, unassigned=0, overlap=(), edges=(),
                              frozen=(), not_analyzed=(), checked_at=0)
    assert text.render_partition(report.as_dict()) == [
        "aegis check --partition: 2 lanes, 0 file(s) analyzed (none), 0 not analyzed",
        "lanes:",
        "  A: 0 file(s) [a/**]",
        "  B: 0 file(s) [b/**]",
        "overlap: none",
        "cross-lane edges: none",
        "[FROZEN_SIGNATURES]",
        "(none)",
        "[/FROZEN_SIGNATURES]",
        partition.LIMITS[0],
    ]


def _lane(paths_source, shared_source, changes=(), findings=(), checked=(), not_checked=(), **kw):
    return lane_gate.LaneCheck("docs", "/ws", "/ws", "main", "a" * 40, "b" * 40, "c" * 40, kw.pop("paths", ()),
                               paths_source, kw.pop("shared", ()), shared_source, changes, findings, checked,
                               not_checked, "2026-10-26T00:00:00Z", **kw)


def test_a_failed_lane_lists_each_violation_finding_and_unread_file():
    check = lane_gate.PathCheck
    result = _lane("cli", "worktree", paths=("docs/**",), shared=("shared/**",),
                   changes=(check("docs/x.md", "A", "000000", "100644", True, "docs/**", "cli", False),
                            check("src/y.py", "M", "100644", "100644", False, None, None, False),
                            check(".aegis/rules/r.md", "M", "100644", "100644", False, None, None, True)),
                   findings=(lane_gate.Finding("0123456789ab", "removed", "tests/test_a.py", "test_b",
                                               "present at the merge base, not collected at HEAD"),),
                   checked=("tests/test_a.py",), not_checked=(("tests/test_c.py", "unparseable"),),
                   warnings=("event not recorded: disk full",))
    assert text.render_lane(result.as_dict()) == [
        "aegis check --lane docs: FAILED (self-attested)",
        "  range: bbbbbbbbbbbb..cccccccccccc (from the merge base of main and HEAD), 3 changed path(s)",
        "  allowed paths from --paths: docs/**",
        "  shared from the working tree's team.json: shared/**",
        "containment: FAILED, 2 of 3 changed path(s) outside the allowed set",
        "  [FAIL] M src/y.py: outside the allowed set",
        "  [FAIL] M .aegis/rules/r.md: protected: only team.json at the base tip (--base-policy) can allow "
        ".aegis/** and .github/workflows/**",
        "test integrity (Python): FAILED, 1 finding(s); protected_changed: true",
        "  [FAIL] 0123456789ab removed tests/test_a.py: test_b (present at the merge base, not collected at HEAD)",
        "  not checked: tests/test_c.py (unparseable)",
        "warning: event not recorded: disk full",
        lane_gate.NOTE_SELF_ATTESTED,
        lane_gate.NOTE_EXEMPTION,
    ]


def test_a_witnessed_lane_names_the_base_tip_its_policy_came_from():
    check = lane_gate.PathCheck
    result = _lane("base@" + "d" * 40, "base@" + "d" * 40,
                   changes=(check("docs/x.md", "A", "000000", "100644", True, "docs/**", "base", False),),
                   checked=("tests/t.py", "tests/u.py"))
    assert text.render_lane(result.as_dict()) == [
        "aegis check --lane docs: PASSED (witnessed: base policy)",
        "  range: bbbbbbbbbbbb..cccccccccccc (from the merge base of main and HEAD), 1 changed path(s)",
        "  allowed paths from team.json at main dddddddddddd: (none)",
        "  shared from team.json at main dddddddddddd: (none)",
        "containment: passed, 1 changed path(s) inside the allowed set",
        "test integrity (Python): passed, 2 file(s) checked; protected_changed: false",
        lane_gate.NOTE_WITNESSED,
        lane_gate.NOTE_EXEMPTION,
    ]
    lease = text.render_lane(_lane("lease", "lease").as_dict())
    assert lease[2:4] == ["  allowed paths from the lane's lease: (none)", "  shared from the lane's lease: (none)"]


@pytest.mark.parametrize("report,expected", [
    (release_verify.ReleaseReport("a" * 40, False, "gh_missing", "gh (the GitHub CLI) is not installed"),
     ["UNVERIFIED (gh >= 2.93.0 required)", "  gh (the GitHub CLI) is not installed",
      "  trust tier: unknown (gh unavailable)"]),
    (release_verify.ReleaseReport("a" * 40, False, "gh_too_old", "gh 2.60.0 is older than 2.93.0",
                                  gh_version="2.60.0"),
     ["UNVERIFIED (gh >= 2.93.0 required)", "  gh 2.60.0 is older than 2.93.0",
      "  trust tier: unknown (gh unavailable)"]),
    (release_verify.ReleaseReport("a" * 40, True, "verified", "the verdict job attested it", tier="A",
                                  repository="o/r", attested=True),
     ["VERIFIED: the CI verdict for " + "a" * 40 + " is attested by o/r's .github/workflows/validate.yml",
      "  the verdict job attested it", "  trust tier: A"]),
    (release_verify.ReleaseReport("a" * 40, False, "agent_editable", "signed by o/r", tier="C",
                                  caveats=("attestation present, but the workflow is agent-editable",),
                                  attested=True),
     ["NOT VERIFIED: attestation present, but the workflow is agent-editable", "  signed by o/r",
      "  trust tier: C", "  ! attestation present, but the workflow is agent-editable"]),
    (release_verify.ReleaseReport("a" * 40, False, "rejected", "gh rejected the attestation", tier="B"),
     ["NOT VERIFIED: gh rejected the attestation", "  trust tier: B"]),
    (release_verify.ReleaseReport("a" * 40, False, "not_a_repository", "not inside a git repository"),
     ["NOT VERIFIED: not inside a git repository", "  trust tier: unknown (not a git repository)"]),
    (release_verify.ReleaseReport("a" * 40, False, "git_failed", "git exited 128"),
     ["NOT VERIFIED: git exited 128", "  trust tier: unknown (git could not answer)"]),
    (release_verify.ReleaseReport("a" * 40, False, "bad_commit", "HEAD~9 is not a commit", caveats=("one", "two")),
     ["NOT VERIFIED: HEAD~9 is not a commit", "  ! one", "  ! two"]),
], ids=["gh-missing", "gh-too-old", "verified", "agent-editable", "rejected", "no-repository", "git-failed",
        "bad-commit"])
def test_the_release_report_says_what_was_established_and_why_not_more(report, expected):
    assert text.render_release(report.as_dict("/ws")) == expected
    assert text.render_release(report.as_dict()) == expected  # the workspace is not part of the text


@pytest.mark.parametrize("report,expected", [
    (human_gate.TierReport("C", reasons=("gh is not installed", "no CODEOWNERS"), caveats=("a caveat",)),
     ["Trust tier (human_gate): C (self-attested): detection and audit only: nothing here is enforced against the "
      "agent", "  - gh is not installed", "  - no CODEOWNERS", "  ! a caveat"]),
    (human_gate.TierReport("A"),
     ["Trust tier (human_gate): A (separation of duties): governance changes need a review by someone other than "
      "their author"]),
    (human_gate.TierReport("B", caveats=("signing key on disk",)),
     ["Trust tier (human_gate): B (solo, signed): governance changes need a signature from a key listed in "
      "allowed_signers on the base branch", "  ! signing key on disk"]),
], ids=["C", "A", "B"])
def test_the_trust_tier_names_its_reasons_and_caveats(report, expected):
    assert text.render_tier(report.as_dict()) == expected


def test_the_core_reports_carry_no_text_method():
    for report in (card.Card, partition.Report, lane_gate.LaneCheck, release_verify.ReleaseReport,
                   human_gate.TierReport):
        assert not hasattr(report, "text_lines"), report.__qualname__


@pytest.mark.parametrize("module", ["aegis_core/lifecycle/selection.py", "aegis_core/outcomes/telemetry.py"])
def test_selection_and_telemetry_return_their_results_and_print_nothing(module):
    tree = ast.parse((REPO / module).read_bytes().decode("utf-8"))
    prints = [node.lineno for node in ast.walk(tree)
              if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print"]
    assert prints == []


def test_the_card_prints_unencodable_names_as_replacement_bytes(tmp_path, monkeypatch):
    """A stdout that cannot encode a path (cp1252, ascii) gets '?' for it, as before: main()
    switches stdout to errors='replace'."""
    from aegis_cli.cli import main

    ws = tmp_path / "ws"
    rules = ws / ".aegis" / "rules" / "invariants"
    rules.mkdir(parents=True)
    rules.joinpath("no-eval.md").write_bytes((REPO / "rules" / "no-eval.md").read_bytes())
    (ws / "src").mkdir()
    (ws / "src" / "café.py").write_bytes(b"x = eval('1')\n")
    expected = text.render_card(card.build(str(ws)).as_dict())
    assert "        1  " + str(Path("src") / "café.py").replace("\\", "/") in expected
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="ascii", newline="\n")
    monkeypatch.setattr(sys, "stdout", stream)
    assert main(["check", "--card", "--workspace", str(ws)]) == 0
    stream.flush()
    assert raw.getvalue() == ("\n".join(expected) + "\n").encode("ascii", "replace")
