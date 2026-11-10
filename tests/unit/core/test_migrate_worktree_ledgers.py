"""`aegis migrate --apply` merges the per-worktree ledgers into the shared one (v4.2 #7).

Before v4.2 each worktree kept ``.aegis/state/ledger.jsonl``. Now a git repository has one
ledger in the common dir, so the migration reads the same workspace's file in every
worktree (``git worktree list``) and appends what the shared ledger lacks: keyed rows by
``(key, rule)``, keyless rows by their canonical row, then renumbers ``seq`` in
``(ts, worktree, seq)`` order and writes an epoch row. The old files are left as they are.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Dict, List

import pytest

from aegis_core import migrate, storage
from aegis_core.errors import PathTraversalError
from aegis_core.telemetry_engine import ledger

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

T0, T1, T2, T3, T4 = (f"2026-10-01T10:00:0{n}Z" for n in range(5))


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=T", *args],
        cwd=str(repo), check=True, capture_output=True, text=True,
    ).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / "a.txt").write_text("a\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return root


@pytest.fixture
def other(repo: Path, tmp_path: Path) -> Path:
    tree = tmp_path / "other"
    _git(repo, "worktree", "add", "-q", "-b", "lane/other", str(tree))
    return tree


def _top(path: Path) -> str:
    return Path(os.path.realpath(path)).as_posix()


def _row(seq: int, ts: str, key=None, rule="trap-x", outcome="tp", **extra) -> Dict:
    row = {"v": 2, "seq": seq, "ts": ts, "rule": rule, "outcome": outcome, "source": "mcp", "key": key}
    row.update(extra)
    return row


def _legacy(tree: Path, rows, relative: str = ".") -> Path:
    path = (tree / relative / ".aegis" / "state" / "ledger.jsonl") if relative != "." else (
        tree / ".aegis" / "state" / "ledger.jsonl")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


def _shared(root: Path) -> List[Dict]:
    path = ledger.ledger_path(root)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _two_ledgers(repo: Path, other: Path):
    """The repo's and the other worktree's own ledgers, with one key (and one keyless row) in both."""
    mine = _legacy(repo, [
        _row(1, T1, key="a1", rule="trap-a"),
        _row(2, T2, rule="trap-k", outcome="trigger"),                       # keyless
        _row(3, T3, key="shared", host="claude-code"),
    ])
    theirs = _legacy(other, [
        _row(1, T0, key="b1", rule="trap-b"),
        _row(2, T2, rule="trap-k", outcome="trigger"),                       # keyless, same content, other worktree
        _row(3, T4, key="shared", host="codex-cli"),
    ])
    return mine, theirs


# ── plan and apply ───────────────────────────────────────────────────────────

@needs_git
def test_the_plan_lists_the_ledgers_and_the_rows_to_merge_and_writes_nothing(repo: Path, other: Path):
    mine, theirs = _two_ledgers(repo, other)
    before = {p: p.read_bytes() for p in (mine, theirs)}
    plan = migrate.plan(repo)
    report = plan.to_dict()
    assert report["status"] == "pending" and report["refusal"] is None
    assert report["worktree_ledgers"] == {
        "sources": sorted([theirs.resolve().as_posix(), mine.resolve().as_posix()]),
        "rows": 5, "duplicates": 1, "conflicts": 0, "unusable_rows": 0, "skipped_lines": 0,
    }
    assert report["ledger"] is None and report["unreadable"] == [] and report["skipped"] == []
    assert not (storage.ledger_site(repo, create=False).path).exists()
    assert not (storage.ledger_site(repo, create=False).path.parent).exists()
    assert {p: p.read_bytes() for p in (mine, theirs)} == before


@needs_git
def test_apply_merges_in_ts_worktree_seq_order_and_renumbers(repo: Path, other: Path):
    mine, theirs = _two_ledgers(repo, other)
    result = migrate.apply(migrate.plan(repo))
    rows = _shared(repo)
    outcomes, epoch = rows[:-1], rows[-1]
    assert [(r["key"], r["rule"], r["ts"]) for r in outcomes] == [
        ("b1", "trap-b", T0),
        ("a1", "trap-a", T1),
        (None, "trap-k", T2),     # other's: /…/other sorts before /…/repo
        (None, "trap-k", T2),
        ("shared", "trap-x", T3),  # the earlier of the two reports of "shared"
    ]
    assert [r["worktree"] for r in outcomes] == [_top(other), _top(repo), _top(other), _top(repo), _top(repo)]
    assert outcomes[-1]["host"] == "claude-code"
    assert [r["seq"] for r in rows] == [1, 2, 3, 4, 5, 6]
    assert epoch["epoch"] == {
        "migration": "worktree-ledgers", "sources": sorted([_top(other), _top(repo)]), "rows": 5, "duplicates": 1,
    }
    assert epoch["worktree"] == _top(repo)
    assert result.merged == 5
    # The old files stay as they were; only the shared ledger was written.
    assert len(mine.read_text(encoding="utf-8").splitlines()) == 3
    assert len(theirs.read_text(encoding="utf-8").splitlines()) == 3
    view = ledger.read(other)
    assert len(view.rows) == 5 and not view.incomplete


@needs_git
def test_a_second_run_finds_nothing_and_writes_nothing(repo: Path, other: Path):
    _two_ledgers(repo, other)
    migrate.apply(migrate.plan(repo))
    shared = ledger.ledger_path(repo)
    first = shared.read_bytes()
    again = migrate.plan(repo)
    assert again.to_dict()["status"] == "up_to_date" and again.to_dict()["worktree_ledgers"] is None
    assert migrate.apply(again).merged == 0
    assert shared.read_bytes() == first
    # ... also from the other worktree: the same shared ledger, the same two sources.
    assert migrate.plan(other).to_dict()["status"] == "up_to_date"


@needs_git
def test_rows_the_shared_ledger_already_has_are_skipped_and_new_ones_follow_it(repo: Path, other: Path):
    ledger.append(repo, [{"rule": "trap-a", "outcome": "tp", "source": "mcp", "key": "a1"}])
    _two_ledgers(repo, other)
    report = migrate.plan(repo).to_dict()["worktree_ledgers"]
    assert (report["rows"], report["duplicates"]) == (4, 2)
    migrate.apply(migrate.plan(repo))
    rows = _shared(repo)
    assert [r["seq"] for r in rows] == [1, 2, 3, 4, 5, 6]
    assert [r["key"] for r in rows[:2]] == ["a1", "b1"]
    assert sum(1 for r in rows if r.get("key") == "a1") == 1


@needs_git
def test_a_row_appended_to_a_source_after_the_plan_is_merged_too(repo: Path, other: Path):
    mine, theirs = _two_ledgers(repo, other)
    plan = migrate.plan(repo)
    with theirs.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(_row(4, T4, key="late", rule="trap-l")) + "\n")
    assert migrate.apply(plan).merged == 6
    assert "late" in {r.get("key") for r in _shared(repo)}


@needs_git
def test_identical_keyless_rows_of_one_ledger_are_all_kept_and_copies_across_ledgers_are_not(repo: Path, other: Path):
    same = [_row(n, T2, rule="trap-k", outcome="trigger", worktree="/shared/wt") for n in (1, 2)]
    _legacy(repo, same)
    _legacy(other, same[:1])  # a copy of one of them (it carries the same worktree)
    migrate.apply(migrate.plan(repo))
    rows = [r for r in _shared(repo) if r.get("rule") == "trap-k"]
    assert len(rows) == 2 and {r["worktree"] for r in rows} == {"/shared/wt"}
    assert migrate.plan(repo).to_dict()["status"] == "up_to_date"


@needs_git
def test_a_worktree_already_on_a_row_is_kept_and_a_missing_one_is_its_ledgers(repo: Path, other: Path):
    _legacy(repo, [_row(1, T1, key="x", worktree="/older/place"), _row(2, T2, key="y")])
    migrate.apply(migrate.plan(repo))
    assert {r["key"]: r["worktree"] for r in _shared(repo) if r.get("key")} == {"x": "/older/place", "y": _top(repo)}


@needs_git
def test_v1_rows_in_a_worktree_ledger_are_converted_when_merged(repo: Path, other: Path):
    _legacy(other, [{"rule_id": "trap-src-drift", "signal": "tp", "source": "ci", "timestamp": T1}])
    migrate.apply(migrate.plan(repo))
    (row,) = [r for r in _shared(repo) if r.get("rule")]
    assert (row["v"], row["rule"], row["outcome"], row["source"], row["ts"]) == (2, "trap-src-drift", "tp", "ci", T1)
    assert row["worktree"] == _top(other) and row["from"] == "v1"


@needs_git
def test_unusable_rows_and_unreadable_lines_are_counted_and_not_merged(repo: Path, other: Path):
    path = _legacy(other, [_row(1, T1, key="good"), _row(2, T2, key="bad-outcome", outcome="bogus")])
    with path.open("a", encoding="utf-8") as fh:
        fh.write("not json\n")
        fh.write(json.dumps(_row(4, T3, key="after")) + "\n")
        fh.write('{"v": 2, "seq": 5')  # a torn tail is neither
    report = migrate.plan(repo).to_dict()["worktree_ledgers"]
    assert report["rows"] == 2 and report["unusable_rows"] == 1 and report["skipped_lines"] == 1
    migrate.apply(migrate.plan(repo))
    assert [r["key"] for r in _shared(repo) if r.get("key")] == ["good", "after"]


@needs_git
def test_a_nested_workspace_merges_only_its_own_ledgers(repo: Path, other: Path):
    (repo / "pkg").mkdir()
    (other / "pkg").mkdir()
    _legacy(repo, [_row(1, T1, key="root-a")])
    _legacy(other, [_row(1, T2, key="root-b")])
    _legacy(repo, [_row(1, T1, key="pkg-a")], relative="pkg")
    _legacy(other, [_row(1, T2, key="pkg-b")], relative="pkg")
    migrate.apply(migrate.plan(repo / "pkg"))
    assert [r["key"] for r in _shared(repo / "pkg") if r.get("key")] == ["pkg-a", "pkg-b"]
    assert _shared(repo) == []  # the root workspace was not migrated
    migrate.apply(migrate.plan(repo))
    assert [r["key"] for r in _shared(repo) if r.get("key")] == ["root-a", "root-b"]


@needs_git
def test_a_worktree_whose_directory_is_gone_is_skipped(repo: Path, other: Path):
    _legacy(repo, [_row(1, T1, key="a1")])
    _legacy(other, [_row(1, T2, key="b1")])
    shutil.rmtree(other)
    report = migrate.plan(repo).to_dict()
    assert report["worktree_ledgers"]["rows"] == 1 and report["unreadable"] == [] and report["skipped"] == []
    migrate.apply(migrate.plan(repo))
    assert [r["key"] for r in _shared(repo) if r.get("key")] == ["a1"]


@needs_git
def test_a_worktree_without_a_ledger_contributes_nothing(repo: Path, other: Path):
    _legacy(repo, [_row(1, T1, key="a1")])
    report = migrate.plan(repo).to_dict()["worktree_ledgers"]
    assert report["sources"] == [(repo / ".aegis" / "state" / "ledger.jsonl").resolve().as_posix()]


@needs_git
def test_with_no_ledger_anywhere_there_is_nothing_to_do(repo: Path, other: Path):
    report = migrate.plan(repo).to_dict()
    assert report["status"] == "up_to_date" and report["worktree_ledgers"] is None


def test_outside_git_there_is_no_worktree_merge(tmp_path: Path):
    _legacy(tmp_path, [_row(1, T1, key="a1")])
    report = migrate.plan(tmp_path).to_dict()
    assert report["status"] == "up_to_date" and report["worktree_ledgers"] is None
    assert migrate.apply(migrate.plan(tmp_path)).merged == 0


# ── What it refuses to read ──────────────────────────────────────────────────

def _symlink_or_skip(link: Path, target: Path, directory: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")


@needs_git
def test_a_symlinked_ledger_file_in_another_worktree_is_reported_and_not_read(repo: Path, other: Path, tmp_path: Path):
    victim = tmp_path / "victim.jsonl"
    victim.write_text(json.dumps(_row(1, T1, key="planted")) + "\n", encoding="utf-8")
    (other / ".aegis" / "state").mkdir(parents=True)
    _symlink_or_skip(other / ".aegis" / "state" / "ledger.jsonl", victim, directory=False)
    _legacy(repo, [_row(1, T2, key="mine")])
    report = migrate.plan(repo).to_dict()
    assert report["unreadable"] == [(Path(os.path.realpath(other)) / ".aegis" / "state" / "ledger.jsonl").as_posix()]
    assert report["worktree_ledgers"]["rows"] == 1
    migrate.apply(migrate.plan(repo))
    assert [r["key"] for r in _shared(repo) if r.get("key")] == ["mine"]
    assert victim.read_text(encoding="utf-8").count("planted") == 1


@needs_git
@pytest.mark.parametrize("linked", [".aegis", ".aegis/state"])
def test_a_symlinked_aegis_or_state_dir_in_another_worktree_is_skipped(repo: Path, other: Path, tmp_path: Path, linked: str):
    elsewhere = tmp_path / "elsewhere"
    _legacy(elsewhere, [_row(1, T1, key="planted")])
    if linked == ".aegis":
        _symlink_or_skip(other / ".aegis", elsewhere / ".aegis", directory=True)
    else:
        (other / ".aegis").mkdir()
        _symlink_or_skip(other / ".aegis" / "state", elsewhere / ".aegis" / "state", directory=True)
    _legacy(repo, [_row(1, T2, key="mine")])
    report = migrate.plan(repo).to_dict()
    link = Path(os.path.realpath(other)) / linked
    assert report["skipped"] == [{
        "path": link.as_posix(),
        "reason": "is a symlink; its ledger was not read (aegis migrate reads and writes only inside the workspace)",
    }]
    assert report["worktree_ledgers"]["rows"] == 1
    migrate.apply(migrate.plan(repo))
    assert [r["key"] for r in _shared(repo) if r.get("key")] == ["mine"]


@needs_git
def test_an_unconfined_shared_directory_refuses_the_whole_migration(repo: Path, tmp_path: Path):
    _legacy(repo, [_row(1, T1, key="a1")])
    outside = tmp_path / "outside"
    outside.mkdir()
    shared = Path(os.path.realpath(repo / ".git")) / "aegis"
    _symlink_or_skip(shared, outside, directory=True)
    plan = migrate.plan(repo)
    message = (f"refusing to use {shared}: it is a symlink; aegis keeps shared state only inside "
               f"{Path(os.path.realpath(repo / '.git'))}")
    assert plan.refusal == message and plan.to_dict()["status"] == "refused"
    with pytest.raises(migrate.MigrationRefused, match="it is a symlink"):
        migrate.apply(plan)
    assert list(outside.iterdir()) == []


@needs_git
def test_a_shared_directory_linked_since_the_plan_refuses_the_apply_before_anything_is_written(repo: Path, tmp_path: Path):
    _legacy(repo, [_row(1, T1, key="a1")])
    plan = migrate.plan(repo)
    assert plan.refusal is None and plan.worktree_pending == 1
    outside = tmp_path / "outside"
    outside.mkdir()
    _symlink_or_skip(Path(os.path.realpath(repo / ".git")) / "aegis", outside, directory=True)
    with pytest.raises(migrate.MigrationRefused, match="it is a symlink"):
        migrate.apply(plan)
    assert list(outside.iterdir()) == []
    assert not list((repo / ".aegis" / "state").glob("migrate-backup-*"))


# ── Together with the v3 conversion ──────────────────────────────────────────
