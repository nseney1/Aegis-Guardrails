"""Adjudication labels count only when merged at the reviewed BASE (R-evidence-3, spec T4, D-adjudicate).

Given/When/Then:

- Given forged ledger ``adjudication`` rows and label rows only in the working tree or on a
  feature branch, When fitness is read, Then no label counts (``adjudicated_n == 0``) and nothing
  is suggested.
- Given 25 tp labels (3 sessions, 2 repos) merged at a review-witnessed BASE, Then the rule is
  ``decided``/``promote``; a duplicate ``example_id`` counts once (the last row wins).
- Given no BASE, an unwitnessed (local-head) BASE or a git error, Then no labels and a reason.
- Given a malformed line, a row over 64 KB or the verdict ``maybe``, Then that row is unusable
  and counted, never fatal.
- Given ``aegis rule adjudicate``, Then it writes only ``.aegis/adjudications/<rule-id>.jsonl``,
  refuses an invalid id with exit 1, and says the label counts after it is merged.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from aegis_core import adjudication, credit, fitness, gitsafe, sync
from aegis_core.rule_integrity import BaseAnchor
from aegis_core.rules import load_rules
from aegis_core.telemetry_engine import ledger
from tests import helpers_adjudication as ha
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "GIT_CONFIG_GLOBAL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    path = root / ".aegis" / "rules" / "traps" / "trap-x.md"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"---\nid: trap-x\ntype: trap\nenforcement: advisory\nhypothesis: h\ncreated: '2026-01-01'\n"
                     b"target_paths:\n  - 'src/*.py'\n---\n# trap-x\n\nBody of trap-x.\n")
    return root


def _fit(root: Path) -> fitness.Fitness:
    return fitness.for_rules(root, [load_rules(root).get("trap-x")])["trap-x"]


@needs_git
def test_forged_ledger_rows_and_working_tree_labels_count_nothing(ws: Path) -> None:
    ha.merge_to_base(ws)
    for n in range(25):
        credit.record_adjudication(ws, "trap-x", "tp", ref=f"PR-{n}", session=f"s{n % 3}", repo=f"r{n % 2}")
    ha.write_labels(ws, "trap-x", ha.labels("trap-x"))

    fit = _fit(ws)
    assert (fit.adjudicated_n, fit.suggestion, fit.state) == (0, None, "insufficient")
    assert sync.build(ws)["rules"]["trap-x"]["suggestion"] is None
    # a legacy ledger adjudication row is read, not unusable: the ledger stays complete
    assert ledger.read(ws).incomplete is None


@needs_git
def test_labels_merged_at_the_base_decide(ws: Path) -> None:
    ha.write_labels(ws, "trap-x", ha.labels("trap-x"))
    base = ha.merge_to_base(ws)

    read = adjudication.read_adjudications(ws)
    assert (read.base, read.reason, len(read.by_rule["trap-x"])) == (base, None, 25)
    fit = _fit(ws)
    assert (fit.adjudicated_tp, fit.sessions_count, fit.repos_count) == (25, 3, 2)
    assert (fit.state, fit.suggestion) == ("decided", "promote")
    assert sync.build(ws)["rules"]["trap-x"]["suggestion"] == "promote"


@needs_git
def test_labels_only_on_a_feature_branch_count_nothing(ws: Path) -> None:
    ha.merge_to_base(ws)
    ha.write_labels(ws, "trap-x", ha.labels("trap-x"))
    ha.commit_on_branch(ws, "work")

    assert adjudication.read_adjudications(ws).by_rule == {}
    assert _fit(ws).adjudicated_n == 0


@needs_git
def test_a_duplicate_example_id_counts_once_and_the_last_row_wins(ws: Path) -> None:
    rows = ha.labels("trap-x", count=24)
    rows.append(dict(rows[0], verdict="fp"))  # a later merged row corrects the first label
    ha.write_labels(ws, "trap-x", rows)
    ha.merge_to_base(ws)

    fit = _fit(ws)
    assert (fit.adjudicated_tp, fit.adjudicated_fp) == (23, 1)
    assert fit.state == "insufficient"


@needs_git
def test_unusable_rows_are_counted_and_never_fatal(ws: Path) -> None:
    path = ha.write_labels(ws, "trap-x", ha.labels("trap-x", count=2))
    with open(path, "ab") as fh:
        fh.write(b"{not json\n")
        fh.write(json.dumps({"example_id": "big", "verdict": "tp", "summary": "x" * (65 * 1024)}).encode() + b"\n")
        fh.write(json.dumps({"example_id": "maybe", "verdict": "maybe"}).encode() + b"\n")
        fh.write(json.dumps({"verdict": "tp"}).encode() + b"\n")
    ha.write_labels(ws, "sub/trap-x", ha.labels("trap-x"))  # .aegis/adjudications/sub/trap-x.jsonl
    ha.merge_to_base(ws)

    read = adjudication.read_adjudications(ws)
    assert [label["example_id"] for label in read.by_rule["trap-x"]] == ["trap-x-tp-0", "trap-x-tp-1"]
    assert read.unusable == 5  # four rows, and a file whose name is no rule id


@needs_git
def test_a_file_over_the_row_cap_is_unusable(ws: Path) -> None:
    ha.write_labels(ws, "trap-x", ha.labels("trap-x", count=adjudication.MAX_ROWS + 1))
    ha.merge_to_base(ws)
    read = adjudication.read_adjudications(ws)
    assert (read.by_rule, read.unusable) == ({}, adjudication.MAX_ROWS + 1)


def test_no_base_gives_no_labels_and_a_reason(ws: Path) -> None:
    read = adjudication.read_adjudications(ws)
    assert read.by_rule == {} and "no reviewed base" in read.reason


@needs_git
def test_an_unwitnessed_base_gives_no_labels_and_a_reason(ws: Path) -> None:
    ha.write_labels(ws, "trap-x", ha.labels("trap-x"))
    ha.merge_to_base(ws)
    ha._git(ws, "symbolic-ref", "--delete", "refs/remotes/origin/HEAD")

    read = adjudication.read_adjudications(ws)
    assert read.by_rule == {} and "local-head" in read.reason
    assert _fit(ws).adjudicated_n == 0


@needs_git
def test_a_git_error_gives_no_labels_and_a_reason(ws: Path) -> None:
    ha.merge_to_base(ws)
    bogus = BaseAnchor("origin/HEAD", "0" * 40, "origin-head", True, "merge-base of HEAD and origin/HEAD")
    read = adjudication.read_adjudications(ws, anchor=bogus)
    assert read.by_rule == {} and read.reason.startswith("labels unreadable at the base")


@needs_git
def test_the_read_is_memoized_per_base(ws: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ha.write_labels(ws, "trap-x", ha.labels("trap-x", count=3))
    ha.merge_to_base(ws)
    calls = []
    real = gitsafe.tree_blobs
    monkeypatch.setattr(gitsafe, "tree_blobs", lambda *a, **k: calls.append(a) or real(*a, **k))
    first = adjudication.read_adjudications(ws)
    assert adjudication.read_adjudications(ws) == first and len(calls) <= 1


@needs_git
def test_scan_never_reads_labels(ws: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aegis_core.scan import RULE_CACHE, scan

    ha.write_labels(ws, "trap-x", ha.labels("trap-x"))
    ha.merge_to_base(ws)
    monkeypatch.setattr(adjudication, "read_adjudications", lambda *a, **k: pytest.fail("scan read labels"))
    RULE_CACHE.invalidate()
    assert [r["name"] for r in scan(ws, ["src/app.py"])["relevant_rules"]] == ["trap-x"]


# ── `aegis rule adjudicate` ───────────────────────────────────────────────────

def _adjudicate(ws: Path, monkeypatch: pytest.MonkeyPatch, *argv: str) -> int:
    from aegis_cli.cli import main

    monkeypatch.chdir(ws)
    return main(["rule", "adjudicate", *argv])


def _files(root: Path) -> set:
    return {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}


def test_rule_adjudicate_refuses_an_invalid_id_and_writes_nothing(ws: Path, tmp_path: Path, monkeypatch, capsys) -> None:
    before = _files(tmp_path)
    for bad in ("../x", "a/b", ".hidden", "x" * 129):
        assert _adjudicate(ws, monkeypatch, bad, "tp") == 1
    assert _files(tmp_path) == before
    assert "invalid rule id" in capsys.readouterr().err


@needs_git
def test_rule_adjudicate_writes_a_label_that_counts_once_merged(ws: Path, monkeypatch, capsys) -> None:
    ha.merge_to_base(ws)
    for _ in range(2):
        assert _adjudicate(ws, monkeypatch, "trap-x", "tp", "--ref", "PR-1", "--summary", "good catch") == 0
    out = capsys.readouterr().out
    assert "after it is merged to the base branch" in out
    path = ws / ".aegis" / "adjudications" / "trap-x.jsonl"
    rows = [json.loads(line) for line in path.read_bytes().splitlines()]
    assert [(r["example_id"], r["verdict"], r["summary"]) for r in rows] == [("PR-1", "tp", "good catch")] * 2
    assert _fit(ws).adjudicated_n == 0  # only in the working tree

    ha.merge_to_base(ws)
    assert _fit(ws).adjudicated_n == 1  # both runs are one effective label

    assert _adjudicate(ws, monkeypatch, "trap-x", "fp", "--file", "src/a.py", "--line", "3", "--json") == 0
    label = json.loads(capsys.readouterr().out)["label"]
    assert label["verdict"] == "fp" and len(label["example_id"]) == 16


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_rule_adjudicate_refuses_a_symlinked_label_directory(ws: Path, tmp_path: Path, monkeypatch) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (ws / ".aegis" / "adjudications").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("the OS refused the symlink")
    assert _adjudicate(ws, monkeypatch, "trap-x", "tp") == 1
    assert list(outside.iterdir()) == []
