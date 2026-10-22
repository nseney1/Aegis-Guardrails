"""aegis_core.team metrics: lease events and merge outcomes (v4.1 spec §1, prune rows).

``event_counts`` counts claims and denials from the events log. ``merge_metrics``
walks the first-parent merges of the current branch since ``--base`` and counts
``overlapping_merge`` (both sides changed a common path since the merge base) and
``conflicting_merge`` (``git merge-tree --write-tree`` reports a conflict; "unavailable"
before git 2.38). GitHub's synthetic ``refs/pull/*/merge`` commits are excluded.

The baseline test rebuilds the plan's numbers (23 lane merges, 8 overlapping, 7
conflicting) on a fixture repository of the same shape, never on this repository.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
from typing import Dict, List, Optional

import pytest

from aegis_core import events, gitsafe, team

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

NOW = 1_760_000_000
LINES = "".join(f"line {n}\n" for n in range(1, 11))


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=T", "-c", "merge.conflictStyle=merge",
         "-c", "core.autocrlf=false", *args],
        cwd=str(repo), check=check, capture_output=True, text=True,
    )


def _out(repo: Path, *args: str) -> str:
    return _git(repo, *args).stdout.strip()


def _write(repo: Path, files: Dict[str, str]) -> None:
    for name, text in files.items():
        (repo / name).write_bytes(text.encode("utf-8"))  # LF on every platform


def _init(root: Path) -> Path:
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, {f"shared{i}.txt": LINES for i in range(8)})
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return root


def _lane(repo: Path, name: str, files: Dict[str, str], base: str = "feature") -> None:
    _git(repo, "checkout", "-q", "-b", f"lane/{name}", base)
    _write(repo, files)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", f"work on {name}")
    _git(repo, "checkout", "-q", base)


def _merge(repo: Path, name: str, into: str = "feature", resolve: Optional[Dict[str, str]] = None) -> str:
    _git(repo, "checkout", "-q", into)
    proc = _git(repo, "merge", "--no-ff", "-q", "-m", f"merge(lane/{name})", f"lane/{name}", check=False)
    if proc.returncode != 0:
        assert resolve is not None, proc.stdout + proc.stderr
        _write(repo, resolve)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "--no-edit")
    return _out(repo, "rev-parse", "HEAD")


def _line_changed(line: int, text: str) -> str:
    lines = LINES.splitlines(keepends=True)
    lines[line - 1] = text + "\n"
    return "".join(lines)


@pytest.fixture(scope="module")
def baseline(tmp_path_factory) -> dict:
    """feature/v4.0's shape at 2965be5: 23 lane merges on the first-parent history,
    8 where both sides changed a common path, 7 of those with textual conflicts."""
    repo = _init(tmp_path_factory.mktemp("baseline") / "repo")
    # A merge on main before the feature branch starts: outside "since main".
    _lane(repo, "pre", {"pre.txt": "pre\n"}, base="main")
    _merge(repo, "pre", into="main")
    _git(repo, "checkout", "-q", "-b", "feature")
    conflicting: List[str] = []
    overlapping: List[str] = []
    for i in range(7):
        # A lane with its own internal merge (not a first-parent merge of feature), started
        # before the next two merge: when it lands both sides changed files, but no common one.
        _git(repo, "checkout", "-q", "-b", f"lane/d{i}", "feature")
        _git(repo, "checkout", "-q", "feature")
        # Two lanes from the same tip edit line 1 of one file: the second merge conflicts.
        _lane(repo, f"c{i}a", {f"shared{i}.txt": _line_changed(1, f"first {i}")})
        _lane(repo, f"c{i}b", {f"shared{i}.txt": _line_changed(1, f"second {i}")})
        _merge(repo, f"c{i}a")
        merged = _merge(repo, f"c{i}b", resolve={f"shared{i}.txt": _line_changed(1, f"both {i}")})
        conflicting.append(merged)
        overlapping.append(merged)
        _git(repo, "checkout", "-q", f"lane/d{i}")
        _git(repo, "checkout", "-q", "-b", f"sub{i}")
        _write(repo, {f"d{i}-sub.txt": "sub\n"})
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "sub")
        _git(repo, "checkout", "-q", f"lane/d{i}")
        _write(repo, {f"d{i}.txt": "d\n"})
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "d")
        _git(repo, "merge", "--no-ff", "-q", "-m", "internal", f"sub{i}")
        _merge(repo, f"d{i}")
    # Two lanes edit far-apart lines of one file: overlapping, merged cleanly.
    _lane(repo, "o1a", {"shared7.txt": _line_changed(1, "top")})
    _lane(repo, "o1b", {"shared7.txt": _line_changed(10, "bottom")})
    _merge(repo, "o1a")
    overlapping.append(_merge(repo, "o1b"))
    return {"repo": repo, "conflicting": conflicting, "overlapping": overlapping}


def test_the_plan_baseline_numbers_are_reproduced_on_its_shape(baseline):
    repo = baseline["repo"]
    found = team.merge_metrics(repo, base="main")
    assert (found["count"], found["overlapping_merge"], found["conflicting_merge"]) == (23, 8, 7)
    assert found["conflicting_unavailable"] is None
    assert [m["commit"] for m in found["merges"] if m["conflicting"]] == baseline["conflicting"]
    assert [m["commit"] for m in found["merges"] if m["overlapping"]] == baseline["overlapping"]
    assert {m["conflicting"] for m in found["merges"]} == {True, False}
    assert {m["overlapping"] for m in found["merges"]} == {True, False}
    head = _out(repo, "rev-parse", "HEAD")
    assert found["range"] == {"base": "main", "base_commit": _out(repo, "rev-parse", "main"),
                              "head": head, "tip": head, "synthetic_head": False}


def test_merges_are_listed_oldest_first_with_their_parents(baseline):
    repo = baseline["repo"]
    found = team.merge_metrics(repo, base="main")
    listed = _out(repo, "rev-list", "--first-parent", "--merges", "--reverse", "--parents", "main..feature")
    assert [[m["commit"], *m["parents"]] for m in found["merges"]] == [line.split() for line in listed.splitlines()]
    assert set(found["merges"][0]) == {"commit", "parents", "overlapping", "conflicting"}


def test_the_counts_match_git_merge_tree_directly(baseline):
    repo = baseline["repo"]
    version = gitsafe.git_version(repo)
    if version is None or version[:2] < (2, 38):
        pytest.skip("git merge-tree --write-tree needs git 2.38")
    found = team.merge_metrics(repo, base="main")
    for merge in found["merges"]:
        p1, p2 = merge["parents"]
        direct = _git(repo, "merge-tree", "--write-tree", "--name-only", p1, p2, check=False).returncode
        assert merge["conflicting"] is (direct == 1)


def test_without_a_base_the_branch_base_is_resolved_as_check_lane_does(baseline, monkeypatch):
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    found = team.merge_metrics(baseline["repo"])
    assert (found["count"], found["overlapping_merge"], found["conflicting_merge"]) == (23, 8, 7)
    assert found["range"]["base"] == "main"
    assert found["range"]["base_commit"] == _out(baseline["repo"], "rev-parse", "main")


def test_with_no_base_branch_the_whole_first_parent_history_counts(baseline, tmp_path: Path, monkeypatch):
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "-q", "--no-local", "-b", "feature", str(baseline["repo"]), str(clone))
    _git(clone, "update-ref", "-d", "refs/remotes/origin/main", check=False)
    # --no-deref: deleting through the symref would remove origin/feature and leave origin/HEAD dangling.
    _git(clone, "update-ref", "--no-deref", "-d", "refs/remotes/origin/HEAD", check=False)
    found = team.merge_metrics(clone)
    assert (found["count"], found["overlapping_merge"], found["conflicting_merge"]) == (24, 8, 7)
    assert (found["range"]["base"], found["range"]["base_commit"]) == (None, None)


def test_before_git_2_38_conflicts_are_unavailable_and_overlap_still_counts(baseline, monkeypatch):
    monkeypatch.setattr(gitsafe, "git_version", lambda cwd: (2, 37, 1))
    found = team.merge_metrics(baseline["repo"], base="main")
    assert (found["count"], found["overlapping_merge"], found["conflicting_merge"]) == (23, 8, "unavailable")
    assert "2.38" in found["conflicting_unavailable"]
    assert {m["conflicting"] for m in found["merges"]} == {None}


def test_an_unresolvable_base_is_a_usage_error(baseline):
    with pytest.raises(team.TeamUsageError, match=r"\Acannot resolve --base 'nope' to a commit\Z"):
        team.merge_metrics(baseline["repo"], base="nope")
    with pytest.raises(team.TeamUsageError, match="cannot resolve --base"):
        team.merge_metrics(baseline["repo"], base="--all")


def test_a_branch_without_merges_counts_zero(tmp_path: Path):
    repo = _init(tmp_path / "repo")
    found = team.merge_metrics(repo, base="main")
    assert (found["count"], found["overlapping_merge"], found["conflicting_merge"], found["merges"]) == (0, 0, 0, [])


def test_an_unborn_branch_counts_zero(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    found = team.merge_metrics(repo)
    assert (found["count"], found["range"]["head"], found["range"]["tip"]) == (0, None, None)


@pytest.mark.parametrize("pull_ref", ["refs/pull/7/merge", "refs/remotes/pull/7/merge"])
def test_a_synthetic_pull_request_merge_is_excluded_and_its_head_is_measured(tmp_path: Path, pull_ref: str):
    repo = _init(tmp_path / "repo")
    _git(repo, "checkout", "-q", "-b", "feature")
    _lane(repo, "a", {"a.txt": "a\n"})
    first = _merge(repo, "a")
    _lane(repo, "b", {"b.txt": "b\n"})
    second = _merge(repo, "b")
    _git(repo, "checkout", "-q", "main")
    _write(repo, {"main.txt": "main moved\n"})
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "main moves on")
    # What actions/checkout gives a pull_request run: HEAD detached at GitHub's merge.
    tree = _out(repo, "merge-tree", "--write-tree", "main", "feature") if (gitsafe.git_version(repo) or (0, 0))[:2] >= (2, 38) \
        else _out(repo, "rev-parse", "feature^{tree}")
    synthetic = _out(repo, "commit-tree", tree.splitlines()[0], "-p", "main", "-p", "feature", "-m", "Merge x into y")
    _git(repo, "update-ref", pull_ref, synthetic)
    _git(repo, "checkout", "-q", "--detach", synthetic)
    found = team.merge_metrics(repo, base="main")
    assert [m["commit"] for m in found["merges"]] == [first, second]
    assert found["excluded_synthetic"] == 1
    assert found["range"]["head"] == synthetic
    assert found["range"]["tip"] == second
    assert found["range"]["synthetic_head"] is True


def test_a_pull_ref_naming_a_commit_that_is_no_merge_leaves_head_alone(tmp_path: Path):
    repo = _init(tmp_path / "repo")
    _git(repo, "checkout", "-q", "-b", "feature")
    _lane(repo, "a", {"a.txt": "a\n"})
    merged = _merge(repo, "a")
    _write(repo, {"after.txt": "after\n"})
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "after")
    head = _out(repo, "rev-parse", "HEAD")
    _git(repo, "update-ref", "refs/pull/7/merge", head)
    found = team.merge_metrics(repo, base="main")
    assert [m["commit"] for m in found["merges"]] == [merged]
    assert (found["range"]["tip"], found["range"]["synthetic_head"], found["excluded_synthetic"]) == (head, False, 0)


def test_a_merge_of_unrelated_histories_has_no_answer_and_does_not_fail(tmp_path: Path):
    repo = _init(tmp_path / "repo")
    _git(repo, "checkout", "-q", "-b", "feature")
    _git(repo, "checkout", "-q", "--orphan", "lane/orphan")
    _git(repo, "rm", "-rf", "-q", ".")
    _write(repo, {"orphan.txt": "o\n"})
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "orphan")
    _git(repo, "checkout", "-q", "feature")
    _git(repo, "merge", "--no-ff", "-q", "--allow-unrelated-histories", "-m", "merge(lane/orphan)", "lane/orphan")
    found = team.merge_metrics(repo, base="main")
    assert (found["count"], found["overlapping_merge"], found["conflicting_merge"]) == (1, 0, 0)
    assert (found["merges"][0]["overlapping"], found["merges"][0]["conflicting"]) == (None, None)


def test_a_merge_commit_that_no_pull_ref_names_is_counted(tmp_path: Path):
    repo = _init(tmp_path / "repo")
    _git(repo, "checkout", "-q", "-b", "feature")
    _lane(repo, "a", {"a.txt": "a\n"})
    merged = _merge(repo, "a")
    _git(repo, "update-ref", "refs/pull/7/head", merged)  # a head ref, not a synthetic merge
    found = team.merge_metrics(repo, base="main")
    assert ([m["commit"] for m in found["merges"]], found["excluded_synthetic"]) == ([merged], 0)


# ── Events ───────────────────────────────────────────────────────────────────

def test_event_counts_report_claims_denials_by_reason_and_lanes(tmp_path: Path):
    repo = _init(tmp_path / "repo")
    docs = team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    with pytest.raises(team.LeaseRefused):
        team.claim(repo, "api", ["docs/api/**"], owner="o@h", now=NOW)
    with pytest.raises(team.LeaseRefused):
        team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    team.release(repo, "docs", docs.oid, caller="h@d")
    team.claim(repo, "web", ["web/**"], owner="o@h", now=NOW)
    old = team.claim(repo, "ops", ["ops/**"], owner="o@h", ttl_s=60, now=NOW)
    team.claim(repo, "ops", ["ops/**"], owner="p@h", now=NOW + 60)
    counts = team.event_counts(repo)
    assert old.oid
    assert {k: counts[k] for k in ("claims", "denials", "denials_by_reason", "by_result", "lanes_claimed")} == {
        "claims": 4,
        "denials": 2,
        "denials_by_reason": {"overlap": 1, "taken": 1},
        "by_result": {"claimed": 3, "released": 1, "taken_over": 1},
        "lanes_claimed": 3,
    }
    assert counts["first"] is not None and counts["last"] >= counts["first"]
    assert (counts["unusable_rows"], counts["error"]) == (0, None)


def test_event_counts_of_an_empty_log(tmp_path: Path):
    repo = _init(tmp_path / "repo")
    assert team.event_counts(repo) == {
        "claims": 0, "denials": 0, "denials_by_reason": {}, "by_result": {}, "lanes_claimed": 0,
        "first": None, "last": None, "unusable_rows": 0, "error": None,
    }


def test_event_counts_count_unusable_rows_of_every_kind(tmp_path: Path):
    repo = _init(tmp_path / "repo")
    team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    log = events.events_path(repo)
    malformed = b'{"v":1,"ts":"2026-10-16T00:00:00Z","event":"lease_claimed","worktree":"w","result":"claimed"}\n'
    with open(log, "ab") as handle:
        handle.write(b"not json\n")  # 1 skipped
        handle.write(b'{"v":99,"event":"lease_claimed"}\n' * 2)  # 2 of another version
        handle.write(malformed * 3)  # 3 without a detail
        handle.write(b'{"v":1,"ts"')  # a torn tail
    counts = team.event_counts(repo)
    assert (counts["claims"], counts["unusable_rows"]) == (1, 7)
