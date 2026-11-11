"""`aegis check --card` and `aegis check --partition` through the real CLI (v4.2 #1 and #5).

Both are reports on the whole workspace: they take no FILES, change nothing but the events
log (the card not even that), and print one JSON document with ``--json`` or
``--format json``. What they compute is tested in tests/unit/core/test_card.py and
test_partition.py; this file pins the command line around them.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Dict

import pytest

from aegis_cli.cli import main
from aegis_core import events
from aegis_core._version import __version__
from tests.helpers_checkmodes import commit, init_repo, write

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

TS = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


@pytest.fixture(autouse=True)
def _no_ci_base(monkeypatch):
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)


@pytest.fixture
def repo(tmp_path: Path, monkeypatch) -> Path:
    root = init_repo(tmp_path / "project")
    write(root, "a/api.py", "from b.svc import work\n\n\ndef run():\n    return work(1)\n")
    write(root, "b/svc.py", "def work(x, y=0):\n    return x + y\n")
    write(root, "legacy.py", "def old(x):\n    return eval(x)\n")
    commit(root, "base")
    monkeypatch.chdir(root)
    return root


def _run(capsys, *argv: str):
    try:
        rc = main(["check", *argv])
    except SystemExit as exc:  # argparse
        rc = exc.code
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _tree(root: Path) -> Dict[str, str]:
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file() and ".git" not in p.relative_to(root).parts}


# ── --card ───────────────────────────────────────────────────────────────────

def test_the_card_prints_and_exits_0_even_with_findings(repo: Path, capsys):
    rc, out, err = _run(capsys, "--card")
    assert (rc, err) == (0, "")
    lines = out.splitlines()
    assert lines[0] == "Aegis day-0 card"
    assert "  languages: python 3" in lines
    assert any(line.startswith("  Layer 1: ") and "% of 3 files without blocking findings" in line for line in lines)
    assert any(line.endswith("legacy.py") for line in lines)


def test_the_card_json_is_one_document_with_the_envelope(repo: Path, capsys):
    rc, out, _ = _run(capsys, "--card", "--json")
    payload = json.loads(out)
    assert rc == 0 and out == json.dumps(payload, indent=2) + "\n"
    assert payload["source"] == "aegis check --card" and payload["aegis_version"] == __version__
    assert TS.match(payload["checked_at"]) and payload["scope"]["workspace"] == str(repo)
    assert payload["layer1"]["findings"] == 1 and payload["top_files"] == [{"path": "legacy.py", "findings": 1}]
    assert payload["rules"]["by_type"] == {"invariant": 1}


def test_format_json_is_the_same_document(repo: Path, capsys):
    rc, out, _ = _run(capsys, "--card", "--format", "json")
    assert rc == 0 and json.loads(out)["source"] == "aegis check --card"


def test_the_card_changes_nothing(repo: Path, capsys):
    write(repo, ".aegis/baseline.json", '{"v": 1, "findings": []}\n')
    before = _tree(repo)
    assert _run(capsys, "--card")[0] == 0 and _run(capsys, "--card", "--json")[0] == 0
    assert _tree(repo) == before
    assert events.read(repo).rows == []


def test_the_card_does_not_need_git(tmp_path: Path, monkeypatch, capsys):
    root = tmp_path / "plain"
    write(root, ".aegis/rules/personas/idiom.md", "---\nid: idiom\ntype: persona\n---\n# idiom\n")
    write(root, "app.py", "x = 1\n")
    monkeypatch.chdir(root)
    rc, out, _ = _run(capsys, "--card")
    assert rc == 0
    assert "No active rule targets any file" in out and "Next: add a rule for your own code" in out


def test_the_card_follows_the_workspace_flag(repo: Path, tmp_path: Path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc, out, _ = _run(capsys, "--card", "--workspace", str(repo), "--json")
    assert rc == 0 and json.loads(out)["scope"]["workspace"] == str(repo)


@pytest.mark.skipif(os.name == "nt", reason="control characters in a file name need a POSIX checkout")
def test_the_text_card_strips_terminal_controls_from_paths(repo: Path, capsys):
    write(repo, "evil\x1b]0;pwned\x07.py", "x = eval(1)\n")
    rc, out, _ = _run(capsys, "--card")
    assert rc == 0 and "\x1b" not in out and "\x07" not in out


# ── --partition ──────────────────────────────────────────────────────────────

SPLIT = ["--split", "A=a/**", "--split", "B=b/**"]


def test_the_partition_report_prints_the_edges_and_the_frozen_block(repo: Path, capsys):
    rc, out, err = _run(capsys, "--partition", *SPLIT)
    assert (rc, err) == (0, "")  # a report: edges do not fail it
    assert "aegis check --partition: 2 lanes, 2 file(s) analyzed (2 python)" in out
    assert "call    a/api.py:5 -> b/svc.py::work  (work)" in out
    lines = out.splitlines()
    block = lines[lines.index("[FROZEN_SIGNATURES]") + 1:lines.index("[/FROZEN_SIGNATURES]")]
    assert any("b/svc.py::work  def work(x, y=0)  (lane B; used by A: a/api.py:" in line for line in block)


def test_the_partition_json_is_one_document_with_the_envelope(repo: Path, capsys):
    rc, out, _ = _run(capsys, "--partition", *SPLIT, "--json")
    payload = json.loads(out)
    assert rc == 0 and out == json.dumps(payload, indent=2) + "\n"
    assert payload["source"] == "aegis check --partition" and payload["aegis_version"] == __version__
    assert TS.match(payload["checked_at"]) and payload["scope"]["workspace"] == str(repo)
    assert [e["kind"] for e in payload["edges"]] == ["import", "call"]
    assert payload["frozen_signatures"][0]["signature"] == "def work(x, y=0)"


def test_split_is_repeatable_and_keeps_the_order_of_the_lanes(repo: Path, capsys):
    rc, out, _ = _run(capsys, "--partition", "--split", "B=b/**", "--split", "A=a/**", "--json")
    assert rc == 0 and json.loads(out)["scope"]["lanes"] == ["B", "A"]


def test_a_partition_check_event_is_written(repo: Path, capsys):
    _run(capsys, "--partition", *SPLIT)
    (row,) = events.read(repo, "partition_check").rows
    assert row["result"] == "edges" and row["detail"]["lanes"] == {"A": ["a/**"], "B": ["b/**"]}


def test_a_partition_with_one_split_is_a_usage_error_and_writes_no_event(repo: Path, capsys):
    rc, out, err = _run(capsys, "--partition", "--split", "A=a/**")
    assert rc == 2 and out == ""
    assert "Error: --partition needs at least 2 --split NAME=GLOB[,GLOB...]" in err
    assert events.read(repo, "partition_check").rows == []


def test_the_partition_changes_nothing_but_the_events_log(repo: Path, capsys):
    before = _tree(repo)
    assert _run(capsys, "--partition", *SPLIT)[0] == 0
    assert _tree(repo) == before


@pytest.mark.skipif(os.name == "nt", reason="control characters in a file name need a POSIX checkout")
def test_the_text_partition_strips_terminal_controls_from_paths(repo: Path, capsys):
    write(repo, "b/notes\x1b]0;pwned\x07.md", "# notes\n")  # listed under "not analyzed"
    rc, out, _ = _run(capsys, "--partition", *SPLIT)
    assert rc == 0 and "not analyzed:" in out and "notes" in out
    assert "\x1b" not in out and "\x07" not in out
