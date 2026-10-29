"""R-checks-48: Aegis, not the model, computes each logged prediction's disposition and outcome from git
on read: landed_unchanged/heeded/abandoned, then hit/miss/void once the window has closed."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

from aegis_core import gitsafe
from tests import helpers_humangate as hg

pytestmark = pytest.mark.skipif(not hg.git_ok(), reason="needs git")

DAY = 86400
T0 = 1_700_000_000


def _git(root: Path, *args: str, at: int = T0) -> str:
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_DATE": f"@{at} +0000", "GIT_COMMITTER_DATE": f"@{at} +0000"}
    res = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
                          *args], cwd=str(root), check=True, capture_output=True, env=env)
    return res.stdout.decode().strip()


def _commit(root: Path, path: str, text: str, message: str, at: int) -> str:
    (root / path).write_bytes(text.encode("utf-8"))
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message, at=at)
    return _git(root, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path, monkeypatch) -> Path:
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(tmp_path / "home"))
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _commit(root, "a.py", "x = 1\n", "base", T0)
    return root


def _row(tree: str, ts: int, kind: str = "revert", path: str = "a.py", **over) -> dict:
    row = {"id": f"r-{kind}-{path}-{ts}", "verdict_id": "v", "ts": float(ts), "tree": tree, "backend": "claude",
           "scope": {"path": path, "symbol": "f"}, "observable": {"kind": kind, "selector": path},
           "window_days": 14, "p": 0.4, "disposition": "logged", "outcome": None}
    row.update(over)
    return row


def _land(repo: Path, at: int) -> tuple:
    """The reviewed change lands unchanged: (its tree, its commit)."""
    commit = _commit(repo, "a.py", "x = 2\n", "feat: two", at)
    return _git(repo, "rev-parse", "HEAD^{tree}"), commit


def _resolve(repo, rows, now):
    from aegis_core.verification import records

    return records.resolve_rows(repo, rows, now)


def test_a_landed_change_reverted_in_the_window_is_a_hit(repo):
    tree, _ = _land(repo, T0 + DAY)
    _commit(repo, "a.py", "x = 1\n", 'Revert "feat: two"', T0 + 3 * DAY)
    (row,) = _resolve(repo, [_row(tree, T0 + DAY - 60)], now=T0 + 20 * DAY)
    assert (row["disposition"], row["outcome"]) == ("landed_unchanged", "hit")


def test_a_fix_in_the_window_is_a_hit_for_fix_attributed_and_none_is_a_miss(repo):
    tree, _ = _land(repo, T0 + DAY)
    (quiet,) = _resolve(repo, [_row(tree, T0 + DAY - 60, kind="fix_attributed")], now=T0 + 20 * DAY)
    _commit(repo, "a.py", "x = 3\n", "fix(a): three", T0 + 4 * DAY)
    (fixed,) = _resolve(repo, [_row(tree, T0 + DAY - 60, kind="fix_attributed")], now=T0 + 20 * DAY)
    assert (quiet["outcome"], fixed["outcome"]) == ("miss", "hit")


def test_a_change_after_the_window_does_not_count(repo):
    tree, _ = _land(repo, T0 + DAY)
    _commit(repo, "a.py", "x = 1\n", 'Revert "feat: two"', T0 + 30 * DAY)
    (row,) = _resolve(repo, [_row(tree, T0 + DAY - 60)], now=T0 + 40 * DAY)
    assert row["outcome"] == "miss"


def test_an_open_window_leaves_the_outcome_unresolved(repo):
    tree, _ = _land(repo, T0 + DAY)
    (row,) = _resolve(repo, [_row(tree, T0 + DAY - 60)], now=T0 + 2 * DAY)
    assert (row["disposition"], row["outcome"]) == ("landed_unchanged", None)


def test_an_edit_of_the_path_instead_of_the_reviewed_tree_is_heeded_and_nothing_is_abandoned(repo):
    trees = []
    for text in (b"x = 8\n", b"x = 9\n"):  # reviewed trees that never land
        (repo / "a.py").write_bytes(text)
        _git(repo, "add", "a.py")
        trees.append(_git(repo, "write-tree"))
    _git(repo, "reset", "-q", "--hard")
    reviewed, other = trees
    _commit(repo, "a.py", "x = 5\n", "feat: five", T0 + 2 * DAY)
    heeded, abandoned = _resolve(repo, [_row(other, T0 + DAY), _row(reviewed, T0 + 40 * DAY)], now=T0 + 60 * DAY)
    assert (heeded["disposition"], heeded["outcome"]) == ("heeded", None)
    assert (abandoned["disposition"], abandoned["outcome"]) == ("abandoned", None)


@pytest.mark.parametrize("change", ["unknown-kind", "ci-kind", "no-path", "missing-commit"])
def test_what_cannot_be_resolved_is_void(repo, change):
    from aegis_core.verification import records

    tree, commit = _land(repo, T0 + DAY)
    row = _row(tree, T0 + DAY - 60, kind={"unknown-kind": "fix_touch_in_window", "ci-kind": "ci_fail_implicating"}.get(
        change, "revert"), path="" if change == "no-path" else "a.py")
    tip = _git(repo, "rev-parse", "refs/heads/main")
    landed = "0" * 40 if change == "missing-commit" else commit  # history rewritten: the commit is gone
    assert records.resolve(row, T0 + 20 * DAY, repo, tip, landed) == "void"


def test_a_shallow_clone_is_void(repo, tmp_path):
    tree, _ = _land(repo, T0 + DAY)
    _commit(repo, "a.py", "x = 1\n", 'Revert "feat: two"', T0 + 3 * DAY)
    clone = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "2", repo.as_uri(), str(clone)], check=True, capture_output=True)
    (row,) = _resolve(clone, [_row(tree, T0 + DAY - 60)], now=T0 + 20 * DAY)
    assert (row["disposition"], row["outcome"]) == ("landed_unchanged", "void")


def test_a_git_failure_is_void_never_an_exception(repo, monkeypatch):
    from aegis_core.verification import records

    tree, commit = _land(repo, T0 + DAY)
    tip = _git(repo, "rev-parse", "refs/heads/main")

    def broken(*_a, **_k):
        raise gitsafe.GitError("git is gone")
    monkeypatch.setattr(gitsafe, "run", broken)
    assert records.resolve(_row(tree, T0), T0 + 20 * DAY, repo, tip, commit) == "void"


def test_calibration_counts_only_what_git_resolved(repo, capsys, monkeypatch):
    from aegis_cli.cli import main

    tree, _ = _land(repo, T0 + DAY)
    _commit(repo, "a.py", "x = 1\n", 'Revert "feat: two"', T0 + 3 * DAY)
    rows = [_row(tree, T0 + DAY - 60), _row(tree, T0 + DAY - 50, kind="detector_fires"), _row("f" * 40, T0 + 50 * DAY)]
    state = repo / ".aegis" / "state"
    state.mkdir(parents=True)
    (state / "arbiter_predictions.jsonl").write_bytes("".join(json.dumps(r) + "\n" for r in rows).encode("utf-8"))
    monkeypatch.chdir(repo)
    assert main(["check", "--calibration", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert (doc["logged"], doc["n"], doc["groups"]) == (3, 1, {"claude/revert": {
        "n": 1, "hits": 1, "wilson_ci": doc["groups"]["claude/revert"]["wilson_ci"], "brier_skill_score": None,
        "status": "insufficient (n=1/25)"}})


def test_a_stored_resolution_is_recomputed_and_never_trusted(repo):
    """R-checks-48: a hand-written landed_unchanged/hit row whose tree never landed is abandoned, and a
    landed row's stored outcome gives way to the one git gives."""
    tree, _ = _land(repo, T0 + DAY)
    forged = _row("f" * 40, T0 + 40 * DAY, disposition="landed_unchanged", outcome="hit")  # nothing after it
    claimed = _row(tree, T0 + DAY - 60, disposition="overridden", outcome="hit")
    out = _resolve(repo, [forged, claimed], now=T0 + 20 * DAY)
    assert [(r["disposition"], r["outcome"]) for r in out] == [("abandoned", None), ("landed_unchanged", "miss")]


def test_rows_past_the_bound_are_left_unresolved_whatever_they_claim(repo, monkeypatch):
    from aegis_core.verification import records

    monkeypatch.setattr(records, "MAX_ROWS", 1)
    tree, _ = _land(repo, T0 + DAY)
    _commit(repo, "a.py", "x = 1\n", 'Revert "feat: two"', T0 + 3 * DAY)
    newest = _row(tree, T0 + DAY - 60)
    older = _row(tree, T0 + DAY - 120, disposition="landed_unchanged", outcome="hit")
    out = _resolve(repo, [older, newest], now=T0 + 20 * DAY)
    assert [(r["disposition"], r["outcome"]) for r in out] == [("logged", None), ("landed_unchanged", "hit")]


def test_outside_git_no_stored_resolution_survives(tmp_path):
    forged = _row("f" * 40, T0, disposition="landed_unchanged", outcome="hit")
    (row,) = _resolve(tmp_path, [forged], now=T0 + 20 * DAY)
    assert (row["disposition"], row["outcome"]) == ("logged", None)
