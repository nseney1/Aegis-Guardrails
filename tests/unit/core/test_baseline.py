"""The ratchet baseline (v4.2 #2): fingerprints, the file format, where it is read from.

A finding is a failed Layer 1 check on one file, down to the line that matched. Its
fingerprint is ``sha256(rule | path | normalized matched line | occurrence index)`` (full digest):
it survives a line moving and does not survive the line changing, and a second copy of
the same line is a different finding. The baseline is read from the base when a base is
used, never from the candidate; a base that cannot be read is an error, not an empty
baseline.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil

import pytest

from aegis_core import baseline
from aegis_core.baseline import BaselineError, BaselineUsage, Entry
from tests.helpers_checkmodes import commit, git, init_repo, write

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

GOOD_FP = "0123456789abcdef" * 4


def _doc(*entries, v=1, **extra):
    payload = {"v": v, "findings": [{"rule": r, "path": p, "fp": f} for r, p, f in entries]}
    payload.update(extra)
    return json.dumps(payload).encode()


# ── Fingerprints ─────────────────────────────────────────────────────────────

def test_a_finding_keeps_its_fingerprint_when_the_line_moves_but_not_when_it_changes():
    first = baseline.Finding("call_graph", "a.py", "def helper(x):", 0, 3, "orphan")
    moved = baseline.Finding("call_graph", "a.py", "def helper(x):", 0, 40, "orphan")
    edited = baseline.Finding("call_graph", "a.py", "def helper(x, y):", 0, 3, "orphan")
    assert first.fp == moved.fp != edited.fp
    assert first.entry == Entry("call_graph", "a.py", first.fp)


# ── The file ─────────────────────────────────────────────────────────────────

def test_render_is_sorted_deduplicated_and_ends_with_a_newline():
    entries = [Entry("r2", "b.py", GOOD_FP), Entry("r1", "b.py", GOOD_FP), Entry("r1", "a.py", GOOD_FP),
               Entry("r1", "a.py", GOOD_FP)]
    text = baseline.render(entries)
    assert text.endswith("}\n") and "\r" not in text
    assert json.loads(text) == {"v": 1, "findings": [
        {"rule": "r1", "path": "a.py", "fp": GOOD_FP},
        {"rule": "r1", "path": "b.py", "fp": GOOD_FP},
        {"rule": "r2", "path": "b.py", "fp": GOOD_FP},
    ]}
    assert baseline.render(reversed(entries)) == text


def test_an_empty_baseline_renders_and_parses():
    text = baseline.render([])
    assert json.loads(text) == {"v": 1, "findings": []}
    assert baseline.parse(text.encode()) == frozenset()


def test_parse_round_trips_render():
    entries = {Entry("forbid_ast:no-eval", "src/a.py", GOOD_FP), Entry("call_graph", "z.py", "f" * 64)}
    assert baseline.parse(baseline.render(entries).encode()) == frozenset(entries)


def test_parse_accepts_a_byte_order_mark():
    assert baseline.parse(b"\xef\xbb\xbf" + _doc(("r", "a.py", GOOD_FP))) == {Entry("r", "a.py", GOOD_FP)}


@pytest.mark.parametrize("data, reason", [
    (b"\xff\xfe", "not valid UTF-8"),
    (b"{not json", "not valid JSON"),
    (b'{"v": 1, "v": 1, "findings": []}', "duplicate key"),
    (b'{"v": NaN, "findings": []}', "not valid JSON"),
    (b"[]", "must hold a JSON object"),
    (b'{"v": 1, "findings": [], "note": "x"}', "1 unknown key(s)"),
    (b'{"findings": []}', "v must be 1"),
    (b'{"v": 2, "findings": []}', "v must be 1"),
    (b'{"v": "1", "findings": []}', "v must be 1"),
    (b'{"v": true, "findings": []}', "v must be 1"),
    (b'{"v": 1}', "findings must be a list"),
    (b'{"v": 1, "findings": {}}', "findings must be a list"),
    (b'{"v": 1, "findings": ["x"]}', "finding 1 must be an object"),
    (b'{"v": 1, "findings": [{"rule": "r", "path": "a.py"}]}', "finding 1 must have exactly rule, path and fp"),
    (b'{"v": 1, "findings": [{"rule": "r", "path": "a.py", "fp": "0123456789abcdef", "line": 3}]}',
     "finding 1 must have exactly rule, path and fp"),
    (b'{"v": 1, "findings": [{"rule": 1, "path": "a.py", "fp": "0123456789abcdef"}]}', "finding 1: rule must be text"),
    (b'{"v": 1, "findings": [{"rule": "", "path": "a.py", "fp": "0123456789abcdef"}]}', "finding 1: rule must be text"),
    (b'{"v": 1, "findings": [{"rule": "r", "path": 3, "fp": "0123456789abcdef"}]}', "finding 1: path must be a workspace-relative POSIX path"),
    (b'{"v": 1, "findings": [{"rule": "r", "path": "/etc/x", "fp": "0123456789abcdef"}]}', "finding 1: path must be a workspace-relative POSIX path"),
    (b'{"v": 1, "findings": [{"rule": "r", "path": "../x", "fp": "0123456789abcdef"}]}', "finding 1: path must be a workspace-relative POSIX path"),
    (b'{"v": 1, "findings": [{"rule": "r", "path": "a\\\\b.py", "fp": "0123456789abcdef"}]}',
     "finding 1: path must be a workspace-relative POSIX path"),
    (b'{"v": 1, "findings": [{"rule": "r", "path": "a.py", "fp": "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"}]}', "finding 1: fp must be 64 lowercase hex characters"),
    (b'{"v": 1, "findings": [{"rule": "r", "path": "a.py", "fp": "0123"}]}', "finding 1: fp must be 64 lowercase hex characters"),
    (b'{"v": 1, "findings": [{"rule": "r", "path": "a.py", "fp": 5}]}', "finding 1: fp must be 64 lowercase hex characters"),
])
def test_parse_refuses_anything_but_the_v1_format(data, reason):
    with pytest.raises(BaselineError) as info:
        baseline.parse(data)
    assert str(info.value) == f"{baseline.BASELINE_FILE}: {reason}"


def test_parse_refuses_a_file_over_the_size_cap_before_decoding_it():
    with pytest.raises(BaselineError, match="baseline.json: larger than 8 MiB"):
        baseline.parse(b" " * (baseline.MAX_BYTES + 1))


def test_an_error_never_quotes_the_file():
    with pytest.raises(BaselineError) as info:
        baseline.parse(b'{"v": 1, "findings": [{"rule": "SECRET-RULE", "path": "SECRET.py", "fp": "bad"}]}')
    assert "SECRET" not in str(info.value)


# ── Where it is read from ────────────────────────────────────────────────────

@pytest.fixture
def repo(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    root = init_repo(tmp_path / "project")
    write(root, "app.py", "x = 1\n")
    commit(root, "base")
    return root


def test_no_file_and_no_base_means_no_baseline(repo: Path):
    loaded = baseline.load(repo)
    assert (loaded.source, loaded.active, loaded.entries, loaded.label) == ("none", False, frozenset(), None)


def test_the_working_tree_baseline_is_self_attested(repo: Path):
    write(repo, baseline.BASELINE_FILE, _doc(("r", "app.py", GOOD_FP)).decode())
    loaded = baseline.load(repo)
    assert loaded.source == "working-tree" and loaded.active
    assert loaded.label == "baseline: working tree (self-attested)"
    assert loaded.entries == {Entry("r", "app.py", GOOD_FP)}
    assert loaded.commit is None


def test_an_invalid_working_tree_baseline_is_an_error_not_an_empty_baseline(repo: Path):
    write(repo, baseline.BASELINE_FILE, "{oops")
    with pytest.raises(BaselineError, match="not valid JSON"):
        baseline.load(repo)


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_a_symlinked_baseline_is_refused(repo: Path):
    (repo / "elsewhere.json").write_bytes(_doc())
    os.symlink(repo / "elsewhere.json", repo / baseline.BASELINE_FILE)
    with pytest.raises(BaselineError, match="is a symlink"):
        baseline.load(repo)


def test_a_directory_in_place_of_the_baseline_is_refused(repo: Path):
    (repo / baseline.BASELINE_FILE).mkdir()
    with pytest.raises(BaselineError, match="not a regular file"):
        baseline.load(repo)


def test_with_a_base_the_baseline_comes_from_the_base_commit(repo: Path):
    write(repo, baseline.BASELINE_FILE, _doc(("r", "app.py", GOOD_FP)).decode())
    tip = commit(repo, "baseline on main")
    git(repo, "checkout", "-q", "-b", "feature")
    write(repo, baseline.BASELINE_FILE, _doc(("r", "app.py", GOOD_FP), ("r", "new.py", "f" * 64)).decode())
    commit(repo, "candidate widens the baseline")
    loaded = baseline.load(repo, "main")
    assert loaded.source == "base" and loaded.commit == tip
    assert loaded.label == f"baseline: base@{tip}"
    assert loaded.entries == {Entry("r", "app.py", GOOD_FP)}  # not the candidate's wider file


def test_the_working_tree_file_is_ignored_when_a_base_is_used(repo: Path):
    write(repo, baseline.BASELINE_FILE, _doc(("r", "app.py", GOOD_FP)).decode())
    commit(repo, "baseline on main")
    git(repo, "checkout", "-q", "-b", "feature")
    write(repo, baseline.BASELINE_FILE, _doc(("r", "evil.py", "e" * 16)).decode())  # uncommitted edit
    assert baseline.load(repo, "main").entries == {Entry("r", "app.py", GOOD_FP)}


def test_a_baseline_absent_at_base_is_empty_even_if_the_candidate_adds_one(repo: Path):
    git(repo, "checkout", "-q", "-b", "feature")
    write(repo, baseline.BASELINE_FILE, _doc(("r", "app.py", GOOD_FP)).decode())
    commit(repo, "candidate adds a baseline")
    loaded = baseline.load(repo, "main")
    assert loaded.source == "absent" and loaded.active
    assert loaded.label == "baseline: absent at base"
    assert loaded.entries == frozenset()
    assert loaded.commit == git(repo, "rev-parse", "main")


def test_a_base_that_does_not_resolve_is_an_error_not_an_empty_baseline(repo: Path):
    write(repo, baseline.BASELINE_FILE, _doc(("r", "app.py", GOOD_FP)).decode())
    commit(repo, "baseline on the candidate")
    with pytest.raises(BaselineError) as info:
        baseline.load(repo, "origin/nope")
    assert str(info.value) == "cannot resolve the base 'origin/nope' to a commit"


@pytest.mark.parametrize("base", ["", "-x", "--output=evil"])
def test_a_base_that_is_not_a_ref_never_reaches_git(repo: Path, base):
    with pytest.raises(BaselineError, match="cannot resolve the base"):
        baseline.load(repo, base)


def test_an_invalid_baseline_at_base_is_an_error_that_names_the_base(repo: Path):
    write(repo, baseline.BASELINE_FILE, "{oops")
    commit(repo, "bad baseline on main")
    git(repo, "checkout", "-q", "-b", "feature")
    write(repo, baseline.BASELINE_FILE, _doc().decode())  # a valid candidate file does not rescue it
    commit(repo, "candidate")
    with pytest.raises(BaselineError) as info:
        baseline.load(repo, "main")
    assert str(info.value).startswith(f"{baseline.BASELINE_FILE} at main: not valid JSON")


def test_a_tag_is_a_base_too(repo: Path):
    write(repo, baseline.BASELINE_FILE, _doc(("r", "app.py", GOOD_FP)).decode())
    tip = commit(repo, "baseline")
    git(repo, "tag", "v1")
    write(repo, baseline.BASELINE_FILE, _doc().decode())
    commit(repo, "emptied")
    loaded = baseline.load(repo, "v1")
    assert loaded.commit == tip and loaded.entries == {Entry("r", "app.py", GOOD_FP)}


def test_a_workspace_below_the_repository_top_reads_its_own_baseline_at_base(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    top = init_repo(tmp_path / "mono", rules=False)
    (top / ".aegis").rmdir()
    service = top / "services" / "api"
    write(service, ".aegis/baseline.json", _doc(("r", "app.py", GOOD_FP)).decode())
    write(top, ".aegis/baseline.json", _doc(("r", "top.py", "a" * 16)).decode())  # another workspace's
    commit(top, "two workspaces")
    git(top, "checkout", "-q", "-b", "feature")
    write(service, ".aegis/baseline.json", _doc().decode())
    commit(top, "candidate empties the service baseline")
    assert baseline.load(service, "main").entries == {Entry("r", "app.py", GOOD_FP)}


def test_a_base_needs_a_git_work_tree(tmp_path: Path):
    plain = tmp_path / "plain"
    (plain / ".aegis").mkdir(parents=True)
    with pytest.raises(BaselineUsage, match="--base needs a git work tree"):
        baseline.load(plain, "main")
    assert baseline.load(plain).source == "none"  # the working tree needs no git
