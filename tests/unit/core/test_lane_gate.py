"""The post-lane gate, ``aegis_core.lane_gate`` (v4.1 spec §1, "Post-lane gate").

``check_lane`` diffs ``merge-base(base, HEAD)..HEAD`` and checks two things:

- **containment**: every listed path (deletions, type changes, both sides of a move,
  gitlinks) is inside the lane's allowed set; ``.aegis/**`` and
  ``.github/workflows/**`` only through globs read from base;
- **test integrity** (Python test files only): a test id gone at HEAD, an introduced
  skip or xfail form, or a change to pytest's collection settings is an itemized
  finding with a stable id.

The allowed set is self-attested (the live lease or ``--paths``, plus the working
tree's ``shared``) unless ``base_policy`` reads both from team.json at the base tip,
which alone earns the label ``witnessed: base policy``. Real temp git repositories
throughout; the pure AST and config readers are tested on their own below.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Dict, List, Optional

import pytest

from aegis_core import events, gitsafe, lane_gate, team

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

TESTS = (
    "import pytest\n"
    "\n\n"
    "def test_add():\n    assert 1 + 1 == 2\n"
    "\n\n"
    "def test_sub():\n    assert 2 - 1 == 1\n"
    "\n\n"
    "class TestApp:\n"
    "    def test_run(self):\n        assert True\n"
    "\n"
    "    def helper(self):\n        return 1\n"
)


def _git(root: Path, *args: str, stdin: Optional[str] = None) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=T", "-c", "commit.gpgsign=false",
         "-c", "core.autocrlf=false", *args],
        cwd=str(root), check=True, capture_output=True, text=True, input=stdin,
    ).stdout.strip()


class Repo:
    """A repository with ``main`` (the base) and the lane branch ``lane/docs`` checked out."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def write(self, path: str, text: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))

    def remove(self, path: str) -> None:
        _git(self.root, "rm", "-q", "-r", "--", path)

    def commit(self, message: str = "change") -> str:
        _git(self.root, "add", "-A")
        _git(self.root, "commit", "-q", "--allow-empty", "-m", message)
        return _git(self.root, "rev-parse", "HEAD")

    def index_entry(self, mode: str, path: str, content: Optional[str] = None, oid: Optional[str] = None) -> None:
        """Stage a symlink (120000) or gitlink (160000) without touching the file system."""
        if oid is None:
            oid = _git(self.root, "hash-object", "-w", "--stdin", stdin=content or "")
        _git(self.root, "update-index", "--add", "--cacheinfo", f"{mode},{oid},{path}")

    def commit_index(self, message: str = "index change") -> str:
        _git(self.root, "commit", "-q", "-m", message)
        return _git(self.root, "rev-parse", "HEAD")

    def on_main(self, change) -> str:
        """Commit ``change(self)`` on main, then return to the lane branch."""
        _git(self.root, "checkout", "-q", "main")
        change(self)
        sha = self.commit("on main")
        _git(self.root, "checkout", "-q", "lane/docs")
        return sha


@pytest.fixture(autouse=True)
def _no_ci_base(monkeypatch):
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    root = tmp_path / "project"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / ".aegis").mkdir()
    r = Repo(root.resolve())
    r.write("README.md", "# project\n")
    r.write("CHANGELOG.md", "# changes\n")
    r.write("docs/guide.md", "guide\n")
    r.write("src/app.py", "def app():\n    return 1\n")
    r.write("tests/test_app.py", TESTS)
    r.commit("base")
    _git(r.root, "checkout", "-q", "-b", "lane/docs")
    return r


def _gate(repo: Repo, **kwargs) -> lane_gate.LaneCheck:
    kwargs.setdefault("base", "main")
    return lane_gate.check_lane(repo.root, kwargs.pop("lane", "docs"), **kwargs)


def _sha12(kind: str, path: str, name: str) -> str:
    return hashlib.sha256(f"{kind}|{path}|{name}".encode("utf-8")).hexdigest()[:12]


def _found(result: lane_gate.LaneCheck) -> List[tuple]:
    return [(f.kind, f.path, f.name) for f in result.findings]


def _violations(result: lane_gate.LaneCheck) -> List[tuple]:
    return [(c.status, c.path) for c in result.violations]


# ── Range ────────────────────────────────────────────────────────────────────

def test_the_range_starts_at_the_merge_base_so_base_s_own_changes_are_not_the_lane_s(repo: Repo):
    fork = _git(repo.root, "rev-parse", "HEAD")
    main_tip = repo.on_main(lambda r: r.write("src/other.py", "x = 1\n"))
    repo.write("docs/guide.md", "better guide\n")
    head = repo.commit()
    result = _gate(repo, paths=["docs/**"])
    assert (result.base, result.base_commit, result.merge_base, result.head) == ("main", main_tip, fork, head)
    assert [(c.status, c.path) for c in result.changes] == [("M", "docs/guide.md")]
    assert result.passed and result.containment_passed and result.integrity_passed


def test_the_base_defaults_to_the_branch_base(repo: Repo):
    repo.write("docs/guide.md", "better guide\n")
    repo.commit()
    result = lane_gate.check_lane(repo.root, "docs", paths=["docs/**"])
    assert result.base == "main"


def test_a_base_that_does_not_resolve_needs_history(repo: Repo):
    with pytest.raises(lane_gate.LaneGateError) as exc:
        _gate(repo, base="origin/nope", paths=["docs/**"])
    assert lane_gate.NEEDS_HISTORY in str(exc.value)
    assert lane_gate.NEEDS_HISTORY == "needs history: fetch with fetch-depth 0"


def test_no_base_branch_at_all_needs_history(repo: Repo):
    _git(repo.root, "branch", "-q", "-m", "main", "trunk")
    with pytest.raises(lane_gate.LaneGateError) as exc:
        lane_gate.check_lane(repo.root, "docs", paths=["docs/**"])
    assert lane_gate.NEEDS_HISTORY in str(exc.value)


def test_unrelated_histories_need_history(repo: Repo):
    _git(repo.root, "checkout", "-q", "--orphan", "lane/other")
    repo.write("docs/new.md", "x\n")
    repo.commit("orphan")
    with pytest.raises(lane_gate.LaneGateError) as exc:
        _gate(repo, paths=["**"])
    assert lane_gate.NEEDS_HISTORY in str(exc.value)


def test_a_shallow_clone_needs_history_even_when_the_merge_base_is_present(repo: Repo, tmp_path: Path):
    for n in range(3):
        repo.on_main(lambda r, n=n: r.write(f"src/m{n}.py", f"m = {n}\n"))
    _git(repo.root, "rebase", "-q", "main")
    repo.write("docs/guide.md", "lane\n")
    repo.commit()
    repo.on_main(lambda r: r.write("src/late.py", "late = 1\n"))
    clone = tmp_path / "shallow"
    _git(tmp_path, "clone", "-q", "--depth", "2", "--no-single-branch", "--branch", "lane/docs",
         repo.root.as_uri(), str(clone))
    assert _git(clone, "rev-parse", "--is-shallow-repository") == "true"
    assert gitsafe.merge_base(clone, "origin/main", "HEAD")  # the history the range needs is there
    with pytest.raises(lane_gate.LaneGateError) as exc:
        lane_gate.check_lane(clone, "docs", base="origin/main", paths=["docs/**"])
    assert lane_gate.NEEDS_HISTORY in str(exc.value)


def test_an_unborn_head_is_an_error(tmp_path: Path):
    root = tmp_path / "empty"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    with pytest.raises(lane_gate.LaneGateError):
        lane_gate.check_lane(root, "docs", base="main", paths=["docs/**"])


def test_outside_git_is_a_usage_error(tmp_path: Path):
    with pytest.raises(lane_gate.LaneGateUsage):
        lane_gate.check_lane(tmp_path, "docs", base="main", paths=["docs/**"])


@pytest.mark.parametrize("base_moved_on", [False, True])
def test_a_head_already_in_base_has_nothing_to_check_and_says_so(repo: Repo, base_moved_on: bool):
    if base_moved_on:
        repo.on_main(lambda r: r.write("src/late.py", "late = 1\n"))
    result = _gate(repo, paths=["docs/**"])
    assert result.changes == () and result.merge_base == result.head
    assert result.passed
    warning = "HEAD is already contained in main: nothing was checked"
    assert result.warnings == (warning,)
    assert result.as_dict()["warnings"] == [warning]
    lines = result.text_lines()
    assert f"warning: {warning}" in lines
    assert lines[-2:] == [lane_gate.NOTE_SELF_ATTESTED, lane_gate.NOTE_EXEMPTION]


# ── Allowed set and provenance ───────────────────────────────────────────────

def test_default_mode_takes_the_live_lease_and_working_tree_shared(repo: Repo):
    team.claim(repo.root, "docs", ["docs/guide.md"], owner="o@h")
    repo.write("docs/guide.md", "lane\n")
    repo.write("docs/CHANGELOG.md", "nested changelog\n")
    repo.commit()
    # Only in the working tree: default mode reads shared from there, never from HEAD.
    repo.write(".aegis/team.json", json.dumps({"v": 1, "shared": ["CHANGELOG.md"]}))
    result = _gate(repo)
    assert (result.paths, result.paths_source) == (("docs/guide.md",), "lease")
    assert (result.shared, result.shared_source) == (("CHANGELOG.md",), "worktree")
    assert result.label == lane_gate.SELF_ATTESTED == "self-attested"
    by_path = {c.path: (c.allowed, c.glob, c.source) for c in result.changes}
    assert by_path["docs/guide.md"] == (True, "docs/guide.md", "lease")
    # The matcher's basename rule: shared "CHANGELOG.md" also admits docs/CHANGELOG.md.
    assert by_path["docs/CHANGELOG.md"] == (True, "CHANGELOG.md", "worktree")
    assert result.passed


def test_the_working_tree_team_json_is_read_even_when_head_has_another(repo: Repo):
    repo.write(".aegis/team.json", json.dumps({"v": 1, "shared": ["CHANGELOG.md"]}))
    repo.write("CHANGELOG.md", "lane\n")
    repo.commit()
    repo.write(".aegis/team.json", json.dumps({"v": 1}))
    result = _gate(repo, paths=["docs/**"])
    assert result.shared == ()
    assert _violations(result) == [("A", ".aegis/team.json"), ("M", "CHANGELOG.md")]


def test_paths_override_the_lease(repo: Repo):
    team.claim(repo.root, "docs", ["docs/**"], owner="o@h")
    repo.write("src/app.py", "def app():\n    return 2\n")
    repo.commit()
    result = _gate(repo, paths=["src/**"])
    assert (result.paths, result.paths_source) == (("src/**",), "cli")
    assert result.passed


def test_no_lease_and_no_paths_fails_and_says_how_to_give_paths(repo: Repo):
    repo.write("docs/guide.md", "lane\n")
    repo.commit()
    with pytest.raises(lane_gate.LaneGateError) as exc:
        _gate(repo)
    message = str(exc.value)
    assert "no live lease" in message and "--paths" in message and "--base-policy" in message


def test_an_expired_lease_is_not_used(repo: Repo):
    team.claim(repo.root, "docs", ["docs/**"], owner="o@h", ttl_s=60, now=int(time.time()) - 3600)
    repo.write("docs/guide.md", "lane\n")
    repo.commit()
    with pytest.raises(lane_gate.LaneGateError) as exc:
        _gate(repo)
    assert "expired" in str(exc.value)


def test_another_lane_s_lease_is_not_this_lane_s(repo: Repo):
    team.claim(repo.root, "api", ["**"], owner="o@h")
    repo.write("docs/guide.md", "lane\n")
    repo.commit()
    with pytest.raises(lane_gate.LaneGateError):
        _gate(repo)


def _base_policy(repo: Repo, policy: dict) -> str:
    return repo.on_main(lambda r: r.write(".aegis/team.json", json.dumps(policy)))


def test_base_policy_reads_lanes_and_shared_from_the_base_tip(repo: Repo):
    repo.write("docs/guide.md", "lane\n")
    repo.commit()
    tip = _base_policy(repo, {"v": 1, "shared": ["CHANGELOG.md"], "lanes": {"docs": ["docs/**"]}})
    result = _gate(repo, base_policy=True)
    assert (result.paths, result.paths_source) == (("docs/**",), f"base@{tip}")
    assert (result.shared, result.shared_source) == (("CHANGELOG.md",), f"base@{tip}")
    assert result.label == lane_gate.WITNESSED == "witnessed: base policy"
    assert result.passed


def test_base_policy_ignores_the_candidate_s_team_json(repo: Repo):
    _base_policy(repo, {"v": 1, "lanes": {"docs": ["docs/**"]}})
    _git(repo.root, "rebase", "-q", "main")
    repo.write(".aegis/team.json", json.dumps({"v": 1, "shared": ["**"], "lanes": {"docs": ["**"]}}))
    repo.write("src/app.py", "def app():\n    return 3\n")
    repo.commit()
    result = _gate(repo, base_policy=True)
    assert result.paths == ("docs/**",) and result.shared == ()
    assert _violations(result) == [("M", ".aegis/team.json"), ("M", "src/app.py")]
    assert not result.passed


def test_base_policy_reads_the_base_tip_not_the_merge_base(repo: Repo):
    repo.write("docs/guide.md", "lane\n")
    repo.commit()
    _base_policy(repo, {"v": 1, "lanes": {"docs": ["docs/**"]}})  # after the fork
    assert _gate(repo, base_policy=True).passed


def test_base_policy_refuses_paths(repo: Repo):
    with pytest.raises(lane_gate.LaneGateUsage) as exc:
        _gate(repo, base_policy=True, paths=["docs/**"])
    assert "--paths" in str(exc.value)


def test_base_policy_without_the_lane_s_entry_fails(repo: Repo):
    tip = _base_policy(repo, {"v": 1, "lanes": {"api": ["src/**"]}})
    with pytest.raises(lane_gate.LaneGateError) as exc:
        _gate(repo, base_policy=True)
    assert str(exc.value).startswith(f"team.json at main ({tip[:12]}) has no lanes entry for docs")


def test_base_policy_without_team_json_at_base_fails(repo: Repo):
    repo.write(".aegis/team.json", json.dumps({"v": 1, "lanes": {"docs": ["**"]}}))
    repo.commit()  # only on the candidate
    with pytest.raises(lane_gate.LaneGateError):
        _gate(repo, base_policy=True)


def test_an_invalid_working_tree_team_json_is_refused(repo: Repo):
    repo.write("docs/guide.md", "lane\n")
    repo.commit()
    repo.write(".aegis/team.json", '{"v": 2}')
    with pytest.raises(team.TeamFileError):
        _gate(repo, paths=["docs/**"])


@pytest.mark.parametrize("lane", ["Docs", "a/b", "", "x..y"])
def test_an_invalid_lane_name_is_a_usage_error(repo: Repo, lane: str):
    with pytest.raises(team.TeamUsageError):
        _gate(repo, lane=lane, paths=["docs/**"])


@pytest.mark.parametrize("paths", [[], [""], ["docs/../src/**"], ["docs/\x1b[2J"], "docs/**"])
def test_invalid_paths_are_a_usage_error(repo: Repo, paths):
    with pytest.raises(lane_gate.LaneGateUsage):
        _gate(repo, paths=paths)


def test_paths_are_normalized(repo: Repo):
    repo.write("docs/guide.md", "lane\n")
    repo.commit()
    result = _gate(repo, paths=["./docs/**", "docs/**"])
    assert result.paths == ("docs/**",)
    assert result.passed


BASE_SHA = "a" * 40


@pytest.mark.parametrize("paths_source, shared_source, label", [
    (f"base@{BASE_SHA}", f"base@{BASE_SHA}", lane_gate.WITNESSED),
    (f"base@{BASE_SHA}", "worktree", lane_gate.SELF_ATTESTED),
    ("lease", f"base@{BASE_SHA}", lane_gate.SELF_ATTESTED),
    ("cli", f"base@{BASE_SHA}", lane_gate.SELF_ATTESTED),
    ("cli", "worktree", lane_gate.SELF_ATTESTED),
])
def test_the_label_is_witnessed_only_when_every_input_came_from_base(paths_source: str, shared_source: str,
                                                                     label: str):
    # check_lane never mixes sources today; v4.2 adds modes, so the property is pinned here.
    check = lane_gate.LaneCheck(
        lane="docs", workspace="/w", repository="/w", base="main", base_commit=BASE_SHA, merge_base="b" * 40,
        head="c" * 40, paths=("docs/**",), paths_source=paths_source, shared=(), shared_source=shared_source,
        changes=(), findings=(), checked=(), not_checked=(), checked_at="2026-10-16T00:00:00Z",
    )
    assert check.label == label
    assert check.as_dict()["label"] == check.event_detail()["label"] == label
    note = lane_gate.NOTE_WITNESSED if label == lane_gate.WITNESSED else lane_gate.NOTE_SELF_ATTESTED
    assert check.as_dict()["notes"][0] == note
    assert check.text_lines()[0] == f"aegis check --lane docs: PASSED ({label})"


# ── Containment ──────────────────────────────────────────────────────────────

def test_a_path_outside_the_allowed_set_fails_containment(repo: Repo):
    repo.write("docs/guide.md", "lane\n")
    repo.write("src/extra.py", "x = 1\n")
    repo.commit()
    result = _gate(repo, paths=["docs/**"])
    assert _violations(result) == [("A", "src/extra.py")]
    assert not result.containment_passed and result.integrity_passed and not result.passed
    assert not result.protected_changed


def test_a_deletion_outside_the_allowed_set_fails_containment(repo: Repo):
    repo.remove("README.md")
    repo.commit()
    assert _violations(_gate(repo, paths=["docs/**"])) == [("D", "README.md")]


def test_both_sides_of_a_move_must_be_allowed(repo: Repo):
    _git(repo.root, "mv", "src/app.py", "docs/app.py")
    repo.commit()
    result = _gate(repo, paths=["docs/**"])
    assert _violations(result) == [("D", "src/app.py")]
    assert ("A", "docs/app.py") in [(c.status, c.path) for c in result.changes]


def test_a_type_change_outside_the_allowed_set_fails_containment(repo: Repo):
    repo.index_entry("120000", "README.md", content="docs/guide.md")
    repo.commit_index()
    (change,) = _gate(repo, paths=["docs/**"]).violations
    assert (change.status, change.path, change.old_mode, change.new_mode) == ("T", "README.md", "100644", "120000")


def test_a_gitlink_outside_the_allowed_set_fails_containment(repo: Repo):
    repo.index_entry("160000", "vendor/lib", oid=_git(repo.root, "rev-parse", "HEAD"))
    repo.commit_index()
    (change,) = _gate(repo, paths=["docs/**"]).violations
    assert (change.status, change.path, change.new_mode) == ("A", "vendor/lib", "160000")


@pytest.mark.parametrize("path", [".aegis/team.json", ".aegis/rules/invariant/x.md", ".github/workflows/ci.yml"])
def test_protected_paths_are_never_allowed_by_a_lease_or_paths(repo: Repo, path: str):
    team.claim(repo.root, "docs", ["**"], owner="o@h")
    repo.write(path, '{"v": 1}\n')
    repo.commit()
    for kwargs in ({}, {"paths": ["**", path]}):
        (change,) = _gate(repo, **kwargs).violations
        assert (change.path, change.protected, change.allowed) == (path, True, False)


def test_working_tree_shared_never_allows_a_protected_path(repo: Repo):
    repo.write(".github/workflows/ci.yml", "on: push\n")
    repo.commit()
    repo.write(".aegis/team.json", json.dumps({"v": 1, "shared": [".github/**", "**"]}))
    (change,) = _gate(repo, paths=["docs/**"]).violations
    assert change.path == ".github/workflows/ci.yml"


def test_base_policy_may_allow_a_protected_path(repo: Repo):
    tip = _base_policy(repo, {"v": 1, "shared": [".github/workflows/**"], "lanes": {"docs": [".aegis/rules/**"]}})
    repo.write(".github/workflows/ci.yml", "on: push\n")
    repo.write(".aegis/rules/invariant/x.md", "rule\n")
    repo.commit()
    result = _gate(repo, base_policy=True)
    assert result.passed
    sources = {c.path: (c.glob, c.source, c.protected) for c in result.changes}
    assert sources[".github/workflows/ci.yml"] == (".github/workflows/**", f"base@{tip}", True)
    assert sources[".aegis/rules/invariant/x.md"] == (".aegis/rules/**", f"base@{tip}", True)


@pytest.mark.parametrize("path, protected", [
    (".aegis/team.json", True),
    (".aegis", True),
    (".AEGIS/team.json", True),
    (".github/workflows/ci.yml", True),
    (".GitHub/Workflows/ci.yml", True),
    (".github/workflows", True),
    (".github", True),
    (".github/CODEOWNERS", False),
    ("docs/.aegis/x", False),
    (".aegisx/y", False),
    ("src/.github/workflows/x.yml", False),
])
def test_is_protected(path: str, protected: bool):
    assert lane_gate.is_protected(path) is protected


# ── Test integrity: removed tests ────────────────────────────────────────────

def test_a_removed_test_is_an_itemized_finding_with_a_stable_id(repo: Repo):
    repo.write("tests/test_app.py", TESTS.replace("def test_sub():\n    assert 2 - 1 == 1\n", ""))
    repo.commit()
    result = _gate(repo, paths=["tests/**"])
    (finding,) = result.findings
    assert (finding.kind, finding.path, finding.name) == ("removed", "tests/test_app.py", "test_sub")
    assert finding.id == _sha12("removed", "tests/test_app.py", "test_sub")
    assert finding.id == lane_gate.finding_id("removed", "tests/test_app.py", "test_sub")
    assert result.containment_passed and not result.integrity_passed and not result.passed
    assert result.protected_changed
    assert result.checked == ("tests/test_app.py",)


def test_finding_id_is_sha256_of_kind_path_name():
    assert lane_gate.finding_id("skip", "t/test_a.py", "x") == hashlib.sha256(b"skip|t/test_a.py|x").hexdigest()[:12]
    assert lane_gate.finding_id("skip", "t/test_a.py", "x") != lane_gate.finding_id("skip", "t/test_a.py", "y")
    assert len(lane_gate.finding_id("removed", "p", "n")) == 12


def test_finding_id_hashes_a_path_that_is_not_utf8_by_its_bytes():
    # gitsafe.diff_entries decodes a non-UTF-8 path with os.fsdecode, so byte 0xff
    # arrives as the surrogate U+DCFF; the id is the hash of the original bytes.
    path = "tests/test_\udcff.py"
    assert lane_gate.finding_id("removed", path, "test_a") == (
        hashlib.sha256(b"removed|tests/test_\xff.py|test_a").hexdigest()[:12])


def test_a_deleted_test_file_removes_every_test_id(repo: Repo):
    repo.remove("tests/test_app.py")
    repo.commit()
    assert _found(_gate(repo, paths=["tests/**"])) == [
        ("removed", "tests/test_app.py", "TestApp::test_run"),
        ("removed", "tests/test_app.py", "test_add"),
        ("removed", "tests/test_app.py", "test_sub"),
    ]


def test_a_moved_test_file_is_removed_at_its_old_path(repo: Repo):
    (repo.root / "tests" / "archive").mkdir()
    _git(repo.root, "mv", "tests/test_app.py", "tests/archive/app.py")
    repo.commit()
    found = _found(_gate(repo, paths=["tests/**"]))
    assert ("removed", "tests/test_app.py", "test_add") in found
    assert len(found) == 3


def test_a_renamed_test_or_class_is_removed(repo: Repo):
    repo.write("tests/test_app.py", TESTS.replace("def test_add", "def check_add").replace("class TestApp", "class App"))
    repo.commit()
    assert _found(_gate(repo, paths=["tests/**"])) == [
        ("removed", "tests/test_app.py", "TestApp::test_run"),
        ("removed", "tests/test_app.py", "test_add"),
    ]


def test_a_test_file_replaced_by_a_symlink_removes_its_tests(repo: Repo):
    repo.index_entry("120000", "tests/test_app.py", content="../src/app.py")
    repo.commit_index()
    assert len(_found(_gate(repo, paths=["tests/**"]))) == 3


def test_added_tests_and_untouched_helpers_are_fine(repo: Repo):
    repo.write("tests/test_app.py", TESTS.replace("        return 1\n", "        return 2\n") + "\n\ndef test_new():\n    assert 3\n")
    repo.write("tests/test_more.py", "def test_more():\n    assert 1\n")
    repo.commit()
    assert _gate(repo, paths=["tests/**"]).passed


def test_a_test_hidden_by_rebinding_is_removed(repo: Repo):
    repo.write("tests/test_app.py", TESTS + "\ntest_add = None\n")
    repo.commit()
    assert _found(_gate(repo, paths=["tests/**"])) == [("removed", "tests/test_app.py", "test_add")]


def test_a_test_class_given_a_constructor_is_no_longer_collected(repo: Repo):
    repo.write("tests/test_app.py", TESTS.replace("class TestApp:\n", "class TestApp:\n    def __init__(self):\n        pass\n\n"))
    repo.commit()
    assert _found(_gate(repo, paths=["tests/**"])) == [("removed", "tests/test_app.py", "TestApp::test_run")]


def test_a_test_turned_into_a_fixture_is_no_longer_collected(repo: Repo):
    repo.write("tests/test_app.py", TESTS.replace("def test_add", "@pytest.fixture\ndef test_add").replace(
        "    def test_run", "    @pytest.fixture(scope='class')\n    def test_run"))
    repo.commit()
    assert _found(_gate(repo, paths=["tests/**"])) == [
        ("removed", "tests/test_app.py", "TestApp::test_run"),
        ("removed", "tests/test_app.py", "test_add"),
    ]


def test_a_test_moved_under_a_condition_is_a_finding(repo: Repo):
    repo.write("tests/test_app.py", TESTS.replace("def test_add():\n    assert 1 + 1 == 2\n",
                                                  "if False:\n    def test_add():\n        assert 1 + 1 == 2\n"))
    repo.commit()
    (finding,) = _gate(repo, paths=["tests/**"]).findings
    assert (finding.kind, finding.name) == ("skip", "conditional definition in test_add")


def test_an_unparseable_test_file_at_head_is_a_finding(repo: Repo):
    repo.write("tests/test_app.py", TESTS + "\ndef broken(:\n")
    repo.commit()
    (finding,) = _gate(repo, paths=["tests/**"]).findings
    assert (finding.kind, finding.path, finding.name) == ("unparseable", "tests/test_app.py", "head")


def test_non_python_test_files_are_listed_as_not_checked(repo: Repo):
    repo.write("tests/app.test.ts", "it.skip('x', () => {})\n")
    repo.write("tests/data/fixture.json", "{}\n")
    repo.commit()
    result = _gate(repo, paths=["tests/**"])
    assert result.passed and result.findings == ()
    assert result.not_checked == (("tests/app.test.ts", "not a Python file"),
                                  ("tests/data/fixture.json", "not a Python file"))
    assert result.checked == ()


def test_a_symlinked_test_file_is_listed_as_not_checked(repo: Repo):
    repo.index_entry("120000", "tests/test_link.py", content="test_app.py")
    repo.commit_index()
    result = _gate(repo, paths=["tests/**"])
    assert result.not_checked == (("tests/test_link.py", "a symlink at HEAD"),)
    assert result.passed


def test_non_test_python_files_are_not_integrity_checked(repo: Repo):
    repo.write("src/app.py", "import pytest\n\n\ndef app():\n    pytest.skip('x')\n")
    repo.commit()
    result = _gate(repo, paths=["src/**"])
    assert result.passed and result.checked == () and result.not_checked == ()


# ── Test integrity: skip and xfail forms ─────────────────────────────────────

def test_an_introduced_skip_is_a_finding_and_an_existing_one_is_not(repo: Repo):
    base = TESTS.replace("def test_sub", "@pytest.mark.skip(reason='old')\ndef test_sub")
    repo.on_main(lambda r: r.write("tests/test_app.py", base))
    _git(repo.root, "rebase", "-q", "main")
    repo.write("tests/test_app.py", base.replace("def test_add", "@pytest.mark.xfail\ndef test_add"))
    repo.commit()
    result = _gate(repo, paths=["tests/**"])
    (finding,) = result.findings
    assert (finding.kind, finding.name) == ("skip", "pytest.mark.xfail in test_add")
    assert finding.id == _sha12("skip", "tests/test_app.py", "pytest.mark.xfail in test_add")
    assert result.protected_changed


def test_a_second_skip_of_the_same_form_in_the_same_scope_is_counted(repo: Repo):
    repo.on_main(lambda r: r.write("tests/test_x.py", "import pytest\n\n\ndef test_a():\n    pytest.skip('a')\n"))
    _git(repo.root, "rebase", "-q", "main")
    repo.write("tests/test_x.py", "import pytest\n\n\ndef test_a():\n" + "    pytest.skip('a')\n" * 3)
    repo.commit()
    assert [f.name for f in _gate(repo, paths=["tests/**"]).findings] == [
        "pytest.skip: pytest.skip('a') in test_a #2", "pytest.skip: pytest.skip('a') in test_a #3"]


def test_a_weakened_skip_condition_is_an_introduced_skip(repo: Repo):
    base = TESTS.replace("import pytest\n", "import sys\n\nimport pytest\n").replace(
        "def test_sub", "@pytest.mark.skipif(sys.platform == 'win32', reason='posix')\ndef test_sub")
    repo.on_main(lambda r: r.write("tests/test_app.py", base))
    _git(repo.root, "rebase", "-q", "main")
    repo.write("tests/test_app.py", base.replace("sys.platform == 'win32'", "True"))
    repo.commit()
    (finding,) = _gate(repo, paths=["tests/**"]).findings
    assert finding.name == "pytest.mark.skipif: pytest.mark.skipif(True, reason='posix') in test_sub"


GUARDED = TESTS.replace("import pytest\n", "import sys\n\nimport pytest\n").replace(
    "def test_add():\n", "def test_add():\n    if sys.platform == 'win32':\n        pytest.skip('win')\n")


@pytest.mark.parametrize("head, name", [
    (GUARDED.replace("    if sys.platform == 'win32':\n        pytest.skip('win')\n", "    pytest.skip('win')\n"),
     "pytest.skip: pytest.skip('win') in test_add"),
    (GUARDED.replace("if sys.platform == 'win32':", "if True:"),
     "pytest.skip: pytest.skip('win') under if True in test_add"),
    (GUARDED.replace("if sys.platform == 'win32':", "if sys.platform != 'win32':"),
     "pytest.skip: pytest.skip('win') under if sys.platform != 'win32' in test_add"),
    (GUARDED.replace("    if sys.platform == 'win32':\n        pytest.skip('win')\n",
                     "    sys.platform == 'win32' or pytest.skip('win')\n"),
     "pytest.skip: pytest.skip('win') under sys.platform == 'win32' or in test_add"),
])
def test_a_removed_or_changed_guard_around_a_skip_is_an_introduced_skip(repo: Repo, head: str, name: str):
    repo.on_main(lambda r: r.write("tests/test_app.py", GUARDED))
    _git(repo.root, "rebase", "-q", "main")
    repo.write("tests/test_app.py", GUARDED.replace("return 1", "return 2"))
    repo.commit()
    assert _gate(repo, paths=["tests/**"]).passed  # the guarded skip itself is not new
    repo.write("tests/test_app.py", head)
    repo.commit()
    (finding,) = _gate(repo, paths=["tests/**"]).findings
    assert (finding.kind, finding.name) == ("skip", name)


@pytest.mark.parametrize("line, name", [
    ("test_add.__test__ = False", "test_add.__test__ = False in <module>"),
    ("TestApp.__test__ = False", "TestApp.__test__ = False in <module>"),
    ("test_sub.pytestmark = [pytest.mark.slow]", "test_sub.pytestmark = [pytest.mark.slow] in <module>"),
])
def test_a_test_switched_off_through_an_attribute_is_a_finding(repo: Repo, line: str, name: str):
    repo.write("tests/test_app.py", TESTS + f"\n{line}\n")
    repo.commit()
    (finding,) = _gate(repo, paths=["tests/**"]).findings
    assert (finding.kind, finding.name) == ("skip", name)


def test_ending_the_run_from_a_test_is_a_finding(repo: Repo):
    repo.write("tests/test_app.py", TESTS.replace("    assert 1 + 1 == 2\n", "    pytest.exit('done', returncode=0)\n"))
    repo.commit()
    (finding,) = _gate(repo, paths=["tests/**"]).findings
    assert (finding.kind, finding.name) == ("skip", "pytest.exit: pytest.exit('done', returncode=0) in test_add")


def test_a_new_test_file_with_a_skip_is_a_finding(repo: Repo):
    repo.write("tests/test_new.py", "import pytest\n\npytestmark = pytest.mark.skip\n\n\ndef test_x():\n    assert 1\n")
    repo.commit()
    (finding,) = _gate(repo, paths=["tests/**"]).findings
    assert finding.name == "pytestmark = pytest.mark.skip in <module>"


# ── Test integrity: collection settings ──────────────────────────────────────

def test_a_conftest_collect_ignore_is_a_finding_and_a_fixture_is_not(repo: Repo):
    repo.write("tests/conftest.py", "import pytest\n\n\n@pytest.fixture\ndef app():\n    return 1\n")
    repo.commit()
    assert _gate(repo, paths=["tests/**"]).passed
    repo.write("tests/conftest.py", "import pytest\n\ncollect_ignore = ['test_app.py']\n\n\n@pytest.fixture\ndef app():\n    return 2\n")
    repo.commit()
    (finding,) = _gate(repo, paths=["tests/**"]).findings
    assert (finding.kind, finding.path, finding.name) == ("collection", "tests/conftest.py", "collect_ignore")


CONFTEST = (
    "import pytest\n\ncollect_ignore = ['test_old.py']\n\n\n"
    "def pytest_collection_modifyitems(items):\n    items.sort(key=lambda item: item.name)\n\n\n"
    "@pytest.fixture\ndef app():\n    return 1\n"
)


@pytest.mark.parametrize("old, new, name", [
    ("collect_ignore = ['test_old.py']", "collect_ignore = ['test_old.py', 'test_app.py']", "collect_ignore"),
    ("items.sort(key=lambda item: item.name)", "items[:] = items[:1]", "pytest_collection_modifyitems"),
])
def test_an_edit_to_an_existing_conftest_hook_or_collect_ignore_is_a_finding(repo: Repo, old: str, new: str,
                                                                             name: str):
    repo.on_main(lambda r: r.write("tests/conftest.py", CONFTEST))
    _git(repo.root, "rebase", "-q", "main")
    repo.write("tests/conftest.py", CONFTEST.replace("return 1", "return 2"))
    repo.commit()
    assert _gate(repo, paths=["tests/**"]).passed
    repo.write("tests/conftest.py", CONFTEST.replace(old, new))
    repo.commit()
    (finding,) = _gate(repo, paths=["tests/**"]).findings
    assert (finding.kind, finding.path, finding.name, finding.detail) == (
        "collection", "tests/conftest.py", name, "changed at HEAD")


def test_a_hook_added_to_a_plugin_module_under_tests_is_a_finding(repo: Repo):
    plugin = "import pytest_mock\n\n\ndef helper():\n    return 1\n"
    repo.on_main(lambda r: r.write("tests/plugins/cleanup.py", plugin))
    _git(repo.root, "rebase", "-q", "main")
    repo.write("tests/plugins/cleanup.py", plugin.replace("return 1", "return 2") + "import pytest_asyncio\n")
    repo.commit()
    assert _gate(repo, paths=["tests/**"]).passed  # imports of pytest plugins are not hooks
    repo.write("tests/plugins/cleanup.py", plugin + "\n\ndef pytest_collection_modifyitems(items):\n    items.clear()\n")
    repo.commit()
    (finding,) = _gate(repo, paths=["tests/**"]).findings
    assert (finding.kind, finding.path, finding.name) == (
        "collection", "tests/plugins/cleanup.py", "pytest_collection_modifyitems")


def test_a_pytest_ini_addopts_change_is_a_finding_and_markers_are_not(repo: Repo):
    repo.on_main(lambda r: r.write("pytest.ini", "[pytest]\naddopts = -q\nmarkers =\n    slow\n"))
    _git(repo.root, "rebase", "-q", "main")
    repo.write("pytest.ini", "[pytest]\naddopts = -q\nmarkers =\n    slow\n    fast\n")
    repo.commit()
    assert _gate(repo, paths=["pytest.ini"]).passed
    repo.write("pytest.ini", "[pytest]\naddopts = -q -k 'not app'\nmarkers =\n    slow\n    fast\n")
    repo.commit()
    result = _gate(repo, paths=["pytest.ini"])
    assert _found(result) == [("collection", "pytest.ini", "[pytest] addopts")]
    assert result.checked == ("pytest.ini",)


def test_a_new_pytest_ini_changes_which_config_pytest_reads(repo: Repo):
    repo.write("pytest.ini", "")
    repo.commit()
    assert _found(_gate(repo, paths=["*.ini"])) == [("collection", "pytest.ini", "pytest configuration")]


@pytest.mark.parametrize("name", ["pytest.toml", ".pytest.toml"])
def test_a_new_pytest_toml_is_a_finding(repo: Repo, name: str):
    # pytest 9 reads [pytest] from these before pytest.ini and pyproject.toml.
    assert name in lane_gate.PYTEST_CONFIG_FILES
    repo.write(name, '[pytest]\naddopts = ["--ignore=tests"]\n')
    repo.commit()
    result = _gate(repo, paths=["*.toml"])
    assert [(f.kind, f.path, f.name, f.detail) for f in result.findings] == [
        ("collection", name, "[pytest] addopts", "added at HEAD"),
        ("collection", name, "pytest configuration", "added at HEAD"),
    ]
    assert result.checked == (name,)


def test_a_pytest_toml_testpaths_change_is_a_finding(repo: Repo):
    repo.on_main(lambda r: r.write("pytest.toml", '[pytest]\ntestpaths = ["tests"]\nmarkers = ["slow"]\n'))
    _git(repo.root, "rebase", "-q", "main")
    repo.write("pytest.toml", '[pytest]\ntestpaths = ["tests"]\nmarkers = ["slow", "fast"]\n')
    repo.commit()
    assert _gate(repo, paths=["pytest.toml"]).passed
    repo.write("pytest.toml", '[pytest]\ntestpaths = ["tests/unit"]\nmarkers = ["slow", "fast"]\n')
    repo.commit()
    assert _found(_gate(repo, paths=["pytest.toml"])) == [("collection", "pytest.toml", "[pytest] testpaths")]


def test_a_pyproject_testpaths_change_is_a_finding(repo: Repo):
    repo.on_main(lambda r: r.write("pyproject.toml", '[project]\nname = "x"\n\n[tool.pytest.ini_options]\ntestpaths = ["tests"]\n'))
    _git(repo.root, "rebase", "-q", "main")
    repo.write("pyproject.toml", '[project]\nname = "y"\n\n[tool.pytest.ini_options]\ntestpaths = ["tests/unit"]\n')
    repo.commit()
    assert _found(_gate(repo, paths=["pyproject.toml"])) == [
        ("collection", "pyproject.toml", "[tool.pytest.ini_options] testpaths")]


# ── Events and output ────────────────────────────────────────────────────────

def test_a_lane_check_event_records_the_label_results_and_provenance(repo: Repo):
    repo.write("src/x.py", "x = 1\n")
    repo.write("tests/test_app.py", TESTS.replace("def test_add", "def check_add"))
    repo.commit()
    result = _gate(repo, paths=["tests/**"])
    (row,) = events.read(repo.root, "lane_check").rows
    assert row["result"] == "fail"
    detail = row["detail"]
    assert detail["lane"] == "docs"
    assert detail["label"] == "self-attested"
    assert detail["provenance"] == {"paths": "cli", "shared": "worktree"}
    assert detail["containment"] == {"passed": False, "violations": 1}
    assert detail["integrity"] == {"passed": False, "findings": [result.findings[0].id]}
    assert detail["range"] == {"base": "main", "base_commit": result.base_commit,
                               "merge_base": result.merge_base, "head": result.head}
    assert result.warnings == ()


def test_a_passing_check_records_pass(repo: Repo):
    repo.write("docs/guide.md", "lane\n")
    repo.commit()
    _gate(repo, paths=["docs/**"])
    (row,) = events.read(repo.root, "lane_check").rows
    assert row["result"] == "pass"


def test_an_event_that_cannot_be_written_is_a_warning(repo: Repo, monkeypatch):
    repo.write("docs/guide.md", "lane\n")
    repo.commit()

    def refuse(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(events, "append", refuse)
    result = _gate(repo, paths=["docs/**"])
    assert result.passed
    assert result.warnings == ("event not recorded: disk full",)
    assert "warning: event not recorded: disk full" in result.text_lines()


def test_the_report_carries_the_envelope_and_every_record(repo: Repo):
    repo.write("src/x.py", "x = 1\n")
    repo.write("tests/app.test.ts", "x\n")
    repo.write("tests/test_app.py", TESTS.replace("def test_add", "def check_add"))
    repo.commit()
    result = _gate(repo, paths=["tests/**"])
    doc = result.as_dict()
    assert doc["source"] == "aegis check --lane"
    from aegis_core._version import __version__
    assert doc["aegis_version"] == __version__
    assert doc["checked_at"] == result.checked_at and doc["checked_at"].endswith("Z")
    assert doc["scope"] == {"workspace": str(repo.root), "repository": str(gitsafe.toplevel(repo.root)),
                            "lane": "docs", "base": "main",
                            "base_commit": result.base_commit, "merge_base": result.merge_base, "head": result.head}
    assert doc["status"] == "fail"
    assert doc["label"] == "self-attested"
    assert doc["provenance"] == {"paths": "cli", "shared": "worktree"}
    assert doc["allowed"] == {"paths": ["tests/**"], "shared": []}
    assert doc["containment"]["passed"] is False
    assert doc["containment"]["violations"] == ["src/x.py"]
    assert {"path": "src/x.py", "status": "A", "old_mode": "000000", "new_mode": "100644", "allowed": False,
            "glob": None, "source": None, "protected": False} in doc["containment"]["paths"]
    integrity = doc["integrity"]
    assert integrity["passed"] is False and integrity["covered"] == ["python"]
    assert integrity["findings"] == [{"id": _sha12("removed", "tests/test_app.py", "test_add"), "kind": "removed",
                                      "path": "tests/test_app.py", "name": "test_add",
                                      "detail": "present at the merge base, not collected at HEAD"}]
    assert integrity["checked"] == ["tests/test_app.py"]
    assert integrity["not_checked"] == [{"path": "tests/app.test.ts", "reason": "not a Python file"}]
    assert integrity["limits"][0].startswith("Assert weakening is not detected")
    limits = " ".join(integrity["limits"])
    for gap in ("parametrize", "generated", "test command", "module constant", "environment variable",
                "if ...: return", "decorator", "setattr", "vars()", "os.kill"):
        assert gap in limits
    assert doc["protected_changed"] is True
    assert doc["notes"] == [lane_gate.NOTE_SELF_ATTESTED, lane_gate.NOTE_EXEMPTION]
    assert doc["warnings"] == []
    assert json.loads(json.dumps(doc)) == doc


def test_the_text_report_names_the_label_violations_and_findings(repo: Repo):
    repo.write("src/x.py", "x = 1\n")
    repo.write("tests/test_app.py", TESTS.replace("def test_add", "def check_add"))
    repo.commit()
    result = _gate(repo, paths=["tests/**"])
    text = "\n".join(result.text_lines())
    assert text.splitlines()[0] == "aegis check --lane docs: FAILED (self-attested)"
    assert "src/x.py" in text and "outside the allowed set" in text
    finding = result.findings[0]
    assert f"{finding.id} removed tests/test_app.py: test_add" in text
    assert "protected_changed: true" in text
    assert "--base-policy" in text  # how to get a witnessed result


def test_a_witnessed_pass_says_so(repo: Repo):
    tip = _base_policy(repo, {"v": 1, "shared": ["CHANGELOG.md", "README.md"], "lanes": {"docs": ["docs/**"]}})
    repo.write("docs/guide.md", "lane\n")
    repo.commit()
    result = _gate(repo, base_policy=True)
    lines = result.text_lines()
    assert lines[0] == "aegis check --lane docs: PASSED (witnessed: base policy)"
    assert lines[2] == f"  allowed paths from team.json at main {tip[:12]}: docs/**"
    assert lines[3] == f"  shared from team.json at main {tip[:12]}: CHANGELOG.md, README.md"
    assert lines[-2:] == [lane_gate.NOTE_WITNESSED, lane_gate.NOTE_EXEMPTION]
    assert result.as_dict()["notes"] == [lane_gate.NOTE_WITNESSED, lane_gate.NOTE_EXEMPTION]


def test_the_text_report_line_by_line(repo: Repo):
    repo.write("docs/guide.md", "lane\n")
    repo.write(".aegis/rules/x.md", "rule\n")
    head = repo.commit()
    result = _gate(repo, paths=["docs/**"])
    lines = result.text_lines()
    assert lines[1] == (f"  range: {result.merge_base[:12]}..{head[:12]} (from the merge base of main and HEAD), "
                        "2 changed path(s)")
    assert lines[2] == "  allowed paths from --paths: docs/**"
    assert lines[3] == "  shared from the working tree's team.json: (none)"
    assert lines[4] == "containment: FAILED, 1 of 2 changed path(s) outside the allowed set"
    assert lines[5] == ("  [FAIL] A .aegis/rules/x.md: protected: only team.json at the base tip (--base-policy) "
                        "can allow .aegis/** and .github/workflows/**")
    assert lines[6] == "test integrity (Python): passed, 0 file(s) checked; protected_changed: false"
    assert lines[-2:] == [lane_gate.NOTE_SELF_ATTESTED, lane_gate.NOTE_EXEMPTION]


def test_the_error_report_carries_the_envelope():
    doc = lane_gate.error_report("/w", "docs", "needs history: fetch with fetch-depth 0")
    assert doc["source"] == "aegis check --lane"
    assert doc["scope"] == {"workspace": "/w", "lane": "docs"}
    assert (doc["status"], doc["error"]) == ("error", "needs history: fetch with fetch-depth 0")
    assert doc["checked_at"].endswith("Z") and doc["aegis_version"]


# ── The AST readers ──────────────────────────────────────────────────────────

def test_collected_ids_follow_pytest_s_default_discovery():
    source = (
        b"import unittest\n"
        b"def test_a(): pass\n"
        b"async def test_async(): pass\n"
        b"def testlower(): pass\n"
        b"def helper(): pass\n"
        b"def _test_private(): pass\n"
        b"class TestOuter:\n"
        b"    def test_m(self): pass\n"
        b"    def other(self): pass\n"
        b"    class TestInner:\n"
        b"        def test_n(self): pass\n"
        b"class Cases(unittest.TestCase):\n"
        b"    def test_u(self): pass\n"
        b"def outer():\n"
        b"    def test_nested(): pass\n"
    )
    assert lane_gate.collected_ids(source) == {
        "test_a": True, "test_async": True, "testlower": True,
        "TestOuter::test_m": True, "TestOuter::TestInner::test_n": True, "Cases::test_u": True,
    }


def test_collected_ids_track_conditions_and_rebinding():
    source = (
        b"import sys\n"
        b"def test_a(): pass\n"
        b"def test_b(): pass\n"
        b"def test_c(): pass\n"
        b"def test_d(): pass\n"
        b"def test_e(): pass\n"
        b"if sys.platform == 'win32':\n"
        b"    def test_win(): pass\n"
        b"    del test_d\n"
        b"try:\n"
        b"    def test_try(): pass\n"
        b"except ImportError:\n"
        b"    pass\n"
        b"test_b = None\n"
        b"del test_c\n"
        b"from x import test_e\n"
        b"if True:\n"
        b"    def test_a(): pass\n"
        b"class TestK:\n"
        b"    def test_k(self): pass\n"
        b"    test_k = 1\n"
        b"class TestNew:\n"
        b"    def __new__(cls): pass\n"
        b"    def test_z(self): pass\n"
        b"class TestT:\n"
        b"    def test_t(self): pass\n"
        b"class TestT:\n"
        b"    def test_t2(self): pass\n"
    )
    assert lane_gate.collected_ids(source) == {
        "test_a": True, "test_d": False, "test_win": False, "test_try": False, "TestT::test_t2": True,
    }


def test_collected_ids_leave_out_fixtures_named_test():
    source = (
        b"import pytest\n"
        b"import pytest as pt\n"
        b"from pytest import fixture as fx\n"
        b"module_scoped = pytest.fixture(scope='module')\n"
        b"@pytest.fixture\ndef test_a(): pass\n"
        b"@pytest.fixture(autouse=True)\ndef test_b(): pass\n"
        b"@pt.yield_fixture\ndef test_c(): pass\n"
        b"@fx\ndef test_d(): pass\n"
        b"@module_scoped\ndef test_e(): pass\n"
        b"class TestK:\n"
        b"    @pytest.fixture\n    def test_k(self): pass\n"
        b"    @pytest.mark.slow\n    def test_m(self): pass\n"
        b"def test_f(): pass\n"
        b"@pytest.fixture\ndef test_f(): pass\n"
        b"@pytest.mark.parametrize('x', [1])\ndef test_g(x): pass\n"
    )
    assert lane_gate.collected_ids(source) == {"TestK::test_m": True, "test_g": True}


def test_collected_ids_follow_a_star_import_of_pytest():
    assert lane_gate.collected_ids(b"from pytest import *\n@fixture\ndef test_a(): pass\ndef test_b(): pass\n") == {
        "test_b": True}
    # Another module's fixture is not pytest's.
    assert lane_gate.collected_ids(b"from helpers import *\n@fixture\ndef test_a(): pass\n") == {"test_a": True}


def test_collected_ids_raise_for_unparseable_source():
    with pytest.raises(SyntaxError):
        lane_gate.collected_ids(b"def broken(:\n")


def _forms(source: str) -> Dict[tuple, int]:
    return lane_gate.skip_forms(source.encode("utf-8"))


def _canonical_forms(source: str) -> Dict[tuple, int]:
    """skip_forms keyed by the canonical form alone (the text before ': ')."""
    counts: Dict[tuple, int] = {}
    for (scope, form), n in _forms(source).items():
        key = (scope, form if form.startswith(("pytestmark", "__test__")) else form.partition(": ")[0])
        counts[key] = counts.get(key, 0) + n
    return counts


@pytest.mark.parametrize("source, key", [
    ("import pytest\n@pytest.mark.skip\ndef test_a(): pass\n", ("test_a", "pytest.mark.skip")),
    ("import pytest\n@pytest.mark.skip(reason='x')\ndef test_a(): pass\n", ("test_a", "pytest.mark.skip")),
    ("import pytest, sys\n@pytest.mark.skipif(sys.platform == 'x', reason='x')\ndef test_a(): pass\n",
     ("test_a", "pytest.mark.skipif")),
    ("import pytest\n@pytest.mark.xfail(strict=True)\ndef test_a(): pass\n", ("test_a", "pytest.mark.xfail")),
    ("import unittest\nclass T(unittest.TestCase):\n    @unittest.skip('x')\n    def test_a(self): pass\n",
     ("T::test_a", "unittest.skip")),
    ("import unittest\n@unittest.skipIf(True, 'x')\nclass T(unittest.TestCase): pass\n", ("T", "unittest.skipIf")),
    ("import unittest\n@unittest.skipUnless(False, 'x')\ndef test_a(): pass\n", ("test_a", "unittest.skipUnless")),
    ("import unittest\nclass T(unittest.TestCase):\n    @unittest.expectedFailure\n    def test_a(self): pass\n",
     ("T::test_a", "unittest.expectedFailure")),
    ("import pytest\npytestmark = pytest.mark.skip\n", ("<module>", "pytestmark = pytest.mark.skip")),
    ("import pytest\npytestmark = [pytest.mark.slow]\n", ("<module>", "pytestmark = [pytest.mark.slow]")),
    ("import pytest\nclass TestA:\n    pytestmark = pytest.mark.xfail\n", ("TestA", "pytestmark = pytest.mark.xfail")),
    ("import pytest\ndef test_a():\n    pytest.skip('x')\n", ("test_a", "pytest.skip")),
    ("import pytest\ndef test_a():\n    pytest.xfail('x')\n", ("test_a", "pytest.xfail")),
    ("import pytest\nnp = pytest.importorskip('numpy')\n", ("<module>", "pytest.importorskip")),
    ("class T:\n    def test_a(self):\n        self.skipTest('x')\n", ("T::test_a", "skipTest")),
    ("import unittest\ndef test_a():\n    raise unittest.SkipTest('x')\n", ("test_a", "unittest.SkipTest")),
    ("import unittest.case\ndef test_a():\n    raise unittest.case.SkipTest('x')\n", ("test_a", "unittest.SkipTest")),
    ("__test__ = False\n", ("<module>", "__test__ = False")),
    ("class TestA:\n    __test__ = False\n", ("TestA", "__test__ = False")),
    ("import pytest\n@pytest.mark.parametrize('x', [pytest.param(1, marks=pytest.mark.skip)])\ndef test_a(x): pass\n",
     ("test_a", "pytest.mark.skip")),
    ("import pytest\nasync def test_a():\n    pytest.skip('x')\n", ("test_a", "pytest.skip")),
    ("import pytest\npytestmark: list = [pytest.mark.skip]\n", ("<module>", "pytestmark: list = [pytest.mark.skip]")),
    ("import pytest\npytestmark += [pytest.mark.xfail]\n", ("<module>", "pytestmark += [pytest.mark.xfail]")),
    ("import pytest\narray = pytest.importorskip('numpy').array\n", ("<module>", "pytest.importorskip")),
])
def test_skip_forms_cover_the_plan_s_list(source: str, key: tuple):
    assert _canonical_forms(source).get(key) == 1, _forms(source)


@pytest.mark.parametrize("source, key", [
    ("import pytest as pt\n@pt.mark.skip\ndef test_a(): pass\n", ("test_a", "pytest.mark.skip")),
    ("from pytest import mark\n@mark.xfail\ndef test_a(): pass\n", ("test_a", "pytest.mark.xfail")),
    ("from pytest import mark as m\n@m.skipif(True, reason='x')\ndef test_a(): pass\n", ("test_a", "pytest.mark.skipif")),
    ("from pytest import skip\ndef test_a():\n    skip('x')\n", ("test_a", "pytest.skip")),
    ("from pytest import importorskip as ios\ndef test_a():\n    ios('x')\n", ("test_a", "pytest.importorskip")),
    ("from unittest import skip\n@skip('x')\ndef test_a(): pass\n", ("test_a", "unittest.skip")),
    ("from unittest import SkipTest\ndef test_a():\n    raise SkipTest('x')\n", ("test_a", "unittest.SkipTest")),
    ("import unittest as ut\n@ut.expectedFailure\ndef test_a(): pass\n", ("test_a", "unittest.expectedFailure")),
    ("from unittest import case\n@case.skipIf(True, 'x')\ndef test_a(): pass\n", ("test_a", "unittest.skipIf")),
    ("import pytest\nmk = pytest.mark\n@mk.skip\ndef test_a(): pass\n", ("test_a", "pytest.mark.skip")),
    ("from pytest import *\n@mark.skip\ndef test_a(): pass\n", ("test_a", "pytest.mark.skip")),
    ("from pytest import *\ndef test_a():\n    skip('x')\n", ("test_a", "pytest.skip")),
    ("from pytest import *\ndef test_a():\n    exit('done')\n", ("test_a", "pytest.exit")),
    ("from unittest import *\n@skipIf(True, 'x')\ndef test_a(): pass\n", ("test_a", "unittest.skipIf")),
    ("from unittest import *\ndef test_a():\n    raise SkipTest('x')\n", ("test_a", "unittest.SkipTest")),
    ("from unittest.case import *\n@expectedFailure\ndef test_a(): pass\n", ("test_a", "unittest.expectedFailure")),
])
def test_skip_forms_resolve_import_aliases(source: str, key: tuple):
    assert _canonical_forms(source).get(key) == 1, _forms(source)


@pytest.mark.parametrize("source", [
    "import pytest\ndef _never():\n    import unittest as pytest\n@pytest.mark.skip\ndef test_a(): pass\n",
    "import pytest, unittest\nif False:\n    pytest = unittest\n@pytest.mark.skip\ndef test_a(): pass\n",
    "import pytest\n@pytest.mark.skip\ndef test_a(): pass\nimport os as pytest\n",
    "import pytest\nfrom unittest import skip as pytest\n@pytest.mark.skip\ndef test_a(): pass\n",
])
def test_a_name_rebound_elsewhere_still_reads_as_pytest(source: str):
    # Aliases are collected from the whole module whatever the order or branch, so
    # rebinding pytest where it never runs must not hide the forms that use it.
    assert _canonical_forms(source) == {("test_a", "pytest.mark.skip"): 1}
    fixture = source.replace("@pytest.mark.skip", "@pytest.fixture")
    assert lane_gate.collected_ids(fixture.encode("utf-8")) == {}


def test_an_alias_of_an_alias_is_followed_whatever_the_order():
    forms = _forms("import pytest\nskip_win = marks.skipif(True, reason='x')\nmarks = pytest.mark\n"
                   "@skip_win\ndef test_a(): pass\n")
    assert forms == {("<module>", "pytest.mark.skipif: marks.skipif(True, reason='x')"): 1,
                     ("test_a", "pytest.mark.skipif: skip_win"): 1}


def test_a_star_import_from_another_module_binds_no_skip_form():
    assert _forms("from helpers import *\n@mark.skip\ndef test_a():\n    skip('x')\n    exit(1)\n") == {}


@pytest.mark.parametrize("source, key", [
    ("import pytest\ndef test_a():\n    pytest.exit('done', returncode=0)\n", ("test_a", "pytest.exit")),
    ("import os\ndef test_a():\n    os._exit(0)\n", ("test_a", "os._exit")),
    ("import os as o\ndef test_a():\n    o._exit(0)\n", ("test_a", "os._exit")),
    ("from os import _exit\ndef test_a():\n    _exit(0)\n", ("test_a", "os._exit")),
    ("def test_a(): pass\ntest_a.__test__ = False\n", ("<module>", "test_a.__test__ = False")),
    ("class TestA: pass\nTestA.__test__ = False\n", ("<module>", "TestA.__test__ = False")),
    ("import pytest\ndef test_a(): pass\ntest_a.pytestmark = [pytest.mark.skip]\n",
     ("<module>", "test_a.pytestmark = [pytest.mark.skip]")),
    ("def off(f):\n    f.__test__ = False\n    return f\n", ("off", "f.__test__ = False")),
])
def test_skip_forms_cover_early_exits_and_attribute_markers(source: str, key: tuple):
    assert _canonical_forms(source).get(key) == 1, _forms(source)


@pytest.mark.parametrize("statement", [
    "test_a.__test__, x = False, 1",
    "x, *test_a.pytestmark = 1, []",
    "[test_a.__test__] = [False]",
])
def test_a_marker_attribute_inside_an_unpacking_target_counts(statement: str):
    forms = _forms(f"def test_a(): pass\n{statement}\n")
    assert forms == {("<module>", ast.unparse(ast.parse(statement).body[0])): 1}


@pytest.mark.parametrize("source, form", [
    ("for x in pytest.importorskip('np').arange(3):\n    pass\n", "pytest.importorskip: pytest.importorskip('np')"),
    ("for d[pytest.skip('x')] in xs:\n    pass\n", "pytest.skip: pytest.skip('x')"),
    ("while pytest.importorskip('np'):\n    pass\n", "pytest.importorskip: pytest.importorskip('np')"),
    ("try:\n    pass\nexcept pytest.skip.Exception:\n    pass\n", "pytest.skip: pytest.skip.Exception"),
    ("with ctx(pytest.importorskip('np')):\n    pass\n", "pytest.importorskip: pytest.importorskip('np')"),
    ("None if pytest.importorskip('np') else None\n", "pytest.importorskip: pytest.importorskip('np')"),
])
def test_a_form_in_the_head_of_a_block_is_counted_outside_the_block(source: str, form: str):
    assert _forms("import pytest\n" + source) == {("<module>", form): 1}


@pytest.mark.parametrize("source, scope, form", [
    ("if X:\n    pytest.skip('x')\n", "<module>", "pytest.skip: pytest.skip('x') under if X"),
    ("if X:\n    pass\nelse:\n    pytest.skip('x')\n", "<module>", "pytest.skip: pytest.skip('x') under else of if X"),
    ("if X:\n    pass\nelif Y:\n    pytest.skip('x')\n", "<module>",
     "pytest.skip: pytest.skip('x') under else of if X > if Y"),
    ("while X:\n    pytest.skip('x')\n", "<module>", "pytest.skip: pytest.skip('x') under while X"),
    ("while X:\n    pass\nelse:\n    pytest.skip('x')\n", "<module>",
     "pytest.skip: pytest.skip('x') under else of while X"),
    ("for x in xs:\n    pytest.skip('x')\n", "<module>", "pytest.skip: pytest.skip('x') under for x in xs"),
    ("for x in xs:\n    pass\nelse:\n    pytest.skip('x')\n", "<module>",
     "pytest.skip: pytest.skip('x') under else of for x in xs"),
    ("async def f():\n    async for x in xs:\n        pytest.skip('x')\n", "f",
     "pytest.skip: pytest.skip('x') under for x in xs"),
    ("try:\n    pytest.skip('x')\nexcept ImportError:\n    pass\n", "<module>", "pytest.skip: pytest.skip('x') under try"),
    ("try:\n    pass\nexcept ImportError:\n    pytest.skip('x')\n", "<module>",
     "pytest.skip: pytest.skip('x') under except ImportError"),
    ("try:\n    pass\nexcept:\n    pytest.skip('x')\n", "<module>", "pytest.skip: pytest.skip('x') under except"),
    ("try:\n    pass\nexcept E:\n    pass\nelse:\n    pytest.skip('x')\n", "<module>",
     "pytest.skip: pytest.skip('x') under else of try"),
    ("try:\n    pass\nfinally:\n    pytest.skip('x')\n", "<module>", "pytest.skip: pytest.skip('x') under finally"),
    ("with ctx() as c, other():\n    pytest.skip('x')\n", "<module>",
     "pytest.skip: pytest.skip('x') under with ctx() as c, other()"),
    ("async def f():\n    async with ctx():\n        pytest.skip('x')\n", "f",
     "pytest.skip: pytest.skip('x') under with ctx()"),
    ("pytest.skip('x') if X else None\n", "<module>", "pytest.skip: pytest.skip('x') under if X"),
    ("None if X else pytest.skip('x')\n", "<module>", "pytest.skip: pytest.skip('x') under else of if X"),
    ("X and pytest.skip('x')\n", "<module>", "pytest.skip: pytest.skip('x') under X and"),
    ("X or Y or pytest.skip('x')\n", "<module>", "pytest.skip: pytest.skip('x') under X or > Y or"),
    ("if pytest.importorskip('np'):\n    pass\n", "<module>", "pytest.importorskip: pytest.importorskip('np')"),
    ("if X:\n    @pytest.mark.skip\n    def test_a(): pass\n", "test_a", "pytest.mark.skip under if X"),
    ("if X:\n    def test_a():\n        if Y:\n            pytest.skip('x')\n", "test_a",
     "pytest.skip: pytest.skip('x') under if X > if Y"),
    ("if X:\n    pytestmark = pytest.mark.skip\n", "<module>", "pytestmark = pytest.mark.skip under if X"),
])
def test_a_skip_is_keyed_by_the_blocks_around_it(source: str, scope: str, form: str):
    assert _forms("import pytest\n" + source) == {(scope, form): 1}


@pytest.mark.skipif(sys.version_info < (3, 10), reason="match statements need Python 3.10")
def test_a_skip_under_a_match_case_is_keyed_by_the_case():
    source = "import pytest\nmatch X:\n    case 1 if Y:\n        pytest.skip('x')\n    case _:\n        pass\n"
    assert _forms(source) == {("<module>", "pytest.skip: pytest.skip('x') under match X case 1 if Y"): 1}
    heads = ("import pytest\nmatch pytest.importorskip('np'):\n    case _ if pytest.xfail('y'):\n        pass\n")
    assert _forms(heads) == {("<module>", "pytest.importorskip: pytest.importorskip('np')"): 1,
                             ("<module>", "pytest.xfail: pytest.xfail('y')"): 1}


def test_a_reused_skip_marker_alias_counts_at_each_use():
    forms = _forms(
        "import pytest, shutil\n"
        "needs_git = pytest.mark.skipif(shutil.which('git') is None, reason='git')\n"
        "@needs_git\n"
        "def test_a(): pass\n"
        "@needs_git\n"
        "def test_b(): pass\n"
    )
    assert forms == {
        ("<module>", "pytest.mark.skipif: pytest.mark.skipif(shutil.which('git') is None, reason='git')"): 1,
        ("test_a", "pytest.mark.skipif: needs_git"): 1,
        ("test_b", "pytest.mark.skipif: needs_git"): 1,
    }


def test_each_form_is_keyed_by_its_whole_expression():
    forms = _forms(
        "import pytest\n"
        "class T:\n"
        "    @pytest.mark.skip\n"
        "    def test_a(self):\n"
        "        self.skipTest('later')\n"
        "        pytest.skip(pytest.skip.Exception)\n"
    )
    assert forms == {
        ("T::test_a", "pytest.mark.skip"): 1,
        ("T::test_a", "skipTest: self.skipTest('later')"): 1,
        ("T::test_a", "pytest.skip: pytest.skip(pytest.skip.Exception)"): 1,
        ("T::test_a", "pytest.skip: pytest.skip.Exception"): 1,
    }


def test_a_long_form_is_cut_with_a_digest():
    reason = "x" * 200
    ((scope, form),) = _forms(f"import pytest\npytest.skip('{reason}')\n")
    assert scope == "<module>" and len(form) < 160
    assert form.startswith("pytest.skip: pytest.skip('xxx") and "... sha256:" in form
    ((_, other),) = _forms(f"import pytest\npytest.skip('{reason}y')\n")
    assert other != form


@pytest.mark.parametrize("kind", ["def", "async def"])
def test_a_pytestmark_inside_a_function_is_a_local_name(kind: str):
    forms = _forms(f"import pytest\n{kind} helper():\n    pytestmark = pytest.mark.skip\n    __test__ = False\n")
    assert forms == {("helper", "pytest.mark.skip"): 1}


def test_skip_forms_ignore_look_alikes():
    forms = _forms(
        "import pytest\n"
        "# pytest.skip() in a comment\n"
        "def test_a():\n"
        "    skipped_count = 0\n"
        "    msg = 'pytest.mark.skip'\n"
        "    np = pytest.importorskip\n"  # an alias definition is one form, its uses are not more
        "    assert skipped_count == 0\n"
        "def skip(): pass\n"
        "def test_b():\n"
        "    skip()\n"
        "    pytest.mark.slow\n"
        "    pytest.mark.skipped_later\n"
    )
    assert forms == {("test_a", "pytest.importorskip"): 1}


def test_an_imported_module_is_not_a_skip_marker():
    forms = _forms("import pytest\nnp = pytest.importorskip('numpy')\ndef test_a():\n    np.array([1])\n    np.zeros(2)\n")
    assert forms == {("<module>", "pytest.importorskip: pytest.importorskip('numpy')"): 1}


def test_skip_forms_raise_for_unparseable_source():
    with pytest.raises(SyntaxError):
        lane_gate.skip_forms(b"def broken(:\n")


def test_collection_hooks_capture_the_watched_names_only():
    hooks = lane_gate.collection_hooks(
        b"import pytest\n"
        b"collect_ignore = ['a.py']\n"
        b"collect_ignore_glob = ['b*']\n"
        b"collect_ignore.append('c.py')\n"
        b"def pytest_collection_modifyitems(config, items):\n    items[:] = []\n"
        b"def pytest_ignore_collect(collection_path):\n    return True\n"
        b"pytest_plugins = ['p']\n"
        b"@pytest.fixture\ndef app():\n    return 1\n"
    )
    assert sorted(hooks) == ["collect_ignore", "collect_ignore_glob", "pytest_collection_modifyitems",
                             "pytest_ignore_collect", "pytest_plugins"]
    assert len(hooks["collect_ignore"]) == 2


def test_collection_hooks_of_a_plugin_module_are_its_hook_definitions_only():
    source = (
        b"import pytest_mock\n"
        b"collect_ignore = ['a.py']\n"
        b"def pytest_ignore_collect(collection_path):\n    return True\n"
        b"async def pytest_runtest_call(item):\n    pass\n"
        b"def helper():\n    return pytest_mock\n"
    )
    hooks = lane_gate.collection_hooks(source, hooks_only=True)
    assert sorted(hooks) == ["pytest_ignore_collect", "pytest_runtest_call"]
    assert "pytest_mock" in lane_gate.collection_hooks(source)


def test_collection_hooks_ignore_formatting_and_comments():
    first = lane_gate.collection_hooks(b"collect_ignore = ['a.py']\n")
    second = lane_gate.collection_hooks(b"# reformatted\ncollect_ignore = [\n    'a.py',\n]\n")
    assert first == second
    assert first != lane_gate.collection_hooks(b"collect_ignore = ['b.py']\n")


@pytest.mark.parametrize("name, text, expected", [
    ("pytest.ini", "[pytest]\naddopts = -q\n  -x\ntestpaths = tests\nmarkers = slow\n",
     {"[pytest] addopts": "-q\n-x", "[pytest] testpaths": "tests"}),
    (".pytest.ini", "", {}),
    ("pytest.ini", "[other]\naddopts = -q\n", {}),
    ("pytest.ini", "[pytest]\nAddopts = -x\nTESTPATHS = t\n", {}),
    ("tox.ini", "[tox]\nenvlist = py\n[pytest]\nnorecursedirs = build\n", {"[pytest] norecursedirs": "build"}),
    ("tox.ini", "[tox]\nenvlist = py\n", None),
    ("setup.cfg", "[metadata]\nname = x\n[tool:pytest]\npython_files = check_*.py\n",
     {"[tool:pytest] python_files": "check_*.py"}),
    ("setup.cfg", "[metadata]\nname = x\n[DEFAULT]\naddopts = -x\n", None),
    ("pyproject.toml", '[project]\nname = "x"\n', None),
    ("pyproject.toml", '[tool.pytest.ini_options]\nminversion = "7"\n', {}),
    ("pyproject.toml",
     '[tool.pytest.ini_options]\naddopts = "-q"  # quiet\ntestpaths = [\n  "tests",  # unit\n  "it",\n]\n'
     'python_classes = \'Check\'\n[tool.other]\naddopts = "-x"\n',
     {"[tool.pytest.ini_options] addopts": '"-q"', "[tool.pytest.ini_options] testpaths": '["tests","it",]',
      "[tool.pytest.ini_options] python_classes": "'Check'"}),
    ("pyproject.toml", '[tool.pytest]\npython_functions = ["check_*"]\n',
     {"[tool.pytest] python_functions": '["check_*"]'}),
    ("pyproject.toml", '[tool]\npytest.ini_options.addopts = "-x"\n', {"[tool.pytest.ini_options] addopts": '"-x"'}),
    ("pyproject.toml", 'tool = {pytest = {ini_options = {addopts = "-x"}}}\n',
     {"tool (inline table)": '{pytest={ini_options={addopts="-x"}}}'}),
    ("pyproject.toml", '[tool."pytest".ini_options]\naddopts = """\n-x\n"""\n',
     {"[tool.pytest.ini_options] addopts": '"""\n-x\n"""'}),
    ("pytest.toml", "", {}),
    (".pytest.toml", "# nothing yet\n", {}),
    ("pytest.toml", '[pytest]\naddopts = ["--ignore=tests"]\nmarkers = ["slow"]\n',
     {"[pytest] addopts": '["--ignore=tests"]'}),
    (".pytest.toml", 'pytest.testpaths = ["t"]\n', {"[pytest] testpaths": '["t"]'}),
    ("pytest.toml", 'pytest = {addopts = "-x"}\n', {"pytest (inline table)": '{addopts="-x"}'}),
    ("pytest.toml", '[tool.pytest]\naddopts = "-x"\n[pytest.ini_options]\naddopts = "-q"\n', {}),
])
def test_pytest_settings_read_the_collection_keys(name: str, text: str, expected):
    assert lane_gate.pytest_settings(name, text.encode("utf-8")) == expected


@pytest.mark.parametrize("name, text", [
    ("pyproject.toml", '[tool.pytest.ini_options]\naddopts = "unterminated\n'),
    ("pyproject.toml", '[tool.pytest.ini_options]\ntestpaths = ["a"\n'),
    ("pytest.ini", "addopts = -x\n"),
    ("pytest.ini", "[pytest]\naddopts = -q\naddopts = -x\n"),
    ("tox.ini", "[pytest]\naddopts = -q\n[pytest]\ntestpaths = t\n"),
    ("setup.cfg", "\xff"),
    ("pytest.toml", '[pytest]\naddopts = "unterminated\n'),
    (".pytest.toml", '[pytest\naddopts = "-x"\n'),
])
def test_unreadable_pytest_settings_raise(name: str, text: str):
    data = text.encode("latin-1") if text == "\xff" else text.encode("utf-8")
    with pytest.raises(ValueError):
        lane_gate.pytest_settings(name, data)


# ── A failed integrity gate voids the credit of the lane's tree (R-trust-65) ─

def _credited_head(repo: Repo, check_id: str = "c-lane") -> str:
    from aegis_core.telemetry_engine import ledger

    tree = _git(repo.root, "rev-parse", "HEAD^{tree}")
    stamp = "2026-10-20T00:00:00Z"
    ledger.append_rows(repo.root, [
        {"v": ledger.LEDGER_VERSION, "ts": stamp, "event": "check", "id": check_id, "tree": tree, "witness": "aegis",
         "passed": True, "tests": {"exit": 0, "passed": 1}},
        {"v": ledger.LEDGER_VERSION, "ts": stamp, "event": "report", "check": check_id, "tree": tree,
         "rule": "trap-sample", "result": "tp"},
    ])
    return tree


def _lane_cli(repo: Repo, monkeypatch, *extra: str) -> int:
    from aegis_cli.cli import main

    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(repo.root.parent / "home"))
    monkeypatch.chdir(repo.root)
    return main(["check", "--lane", "docs", "--base", "main", *extra])


def _voids(repo: Repo) -> List[tuple]:
    from aegis_core import credit

    return [(r["check"], r["reason"]) for r in credit.read_rows(repo.root) if r.get("event") == "void"]


def test_a_failed_integrity_gate_voids_the_checks_of_the_lane_tree(repo: Repo, monkeypatch):
    from aegis_core import credit

    repo.write("tests/test_app.py", TESTS.replace("def test_add():", "@pytest.mark.skip\ndef test_add():"))
    repo.commit("skip a test")
    _credited_head(repo)
    assert _lane_cli(repo, monkeypatch, "--paths", "tests/**") == 1
    assert _voids(repo) == [("c-lane", "lane_integrity")]
    derived, = credit.derive(credit.read_rows(repo.root), landed=lambda _tree, _head=None: None)
    assert (derived.state, derived.reason, derived.counts) == ("voided", "lane_integrity", False)


def test_a_clean_lane_or_a_usage_error_voids_nothing(repo: Repo, monkeypatch):
    repo.write("docs/guide.md", "guide v2\n")
    repo.commit("docs")
    _credited_head(repo)
    assert _lane_cli(repo, monkeypatch, "--paths", "docs/**") == 0
    assert _lane_cli(repo, monkeypatch, "--paths", "docs/../x") == 2
    assert _voids(repo) == []


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="POSIX permission bits, not root")
def test_a_ledger_that_cannot_be_written_keeps_the_lane_exit_code(repo: Repo, monkeypatch, capsys):
    from aegis_core.telemetry_engine import ledger

    repo.write("tests/test_app.py", TESTS.replace("def test_sub():\n    assert 2 - 1 == 1\n", ""))
    repo.commit("drop a test")
    _credited_head(repo)
    state = Path(ledger.ledger_path(repo.root)).parent
    for entry in state.iterdir():
        entry.chmod(0o444)
    state.chmod(0o555)
    try:
        capsys.readouterr()
        assert _lane_cli(repo, monkeypatch, "--paths", "tests/**") == 1
        notes = [line for line in capsys.readouterr().err.splitlines() if "void" in line]
    finally:
        state.chmod(0o755)
    assert len(notes) == 1 and _voids(repo) == []
