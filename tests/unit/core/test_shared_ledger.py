"""The worktree-shared ledger (v4.2 #7, ADR 0005 H5).

In a git repository every worktree of one repository appends to ONE ledger,
``<git common dir>/aegis/state/<ws-id>/ledger.jsonl``, where ``<ws-id>`` is the first 16
hex characters of the SHA-256 of the workspace's POSIX path relative to the git toplevel
(so each ``.aegis`` workspace has its own file, and a workspace has the same id in every
worktree). One lock in that directory, taken by every ledger writer, serializes them.
Outside git the ledger stays at ``.aegis/state/ledger.jsonl`` under the workspace lock.
"""
from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import textwrap
import time
from typing import Callable, Dict, List

import pytest

from aegis_core import storage
from aegis_core.errors import LockTimeoutError, PathTraversalError
from aegis_core.storage import LockOrderError, locked
from aegis_core.telemetry_engine import ledger
from tests import helpers_ledgerrace

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))


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
def worktree(repo: Path, tmp_path: Path) -> Path:
    other = tmp_path / "other"
    _git(repo, "worktree", "add", "-q", "-b", "lane/other", str(other))
    return other


def _common(repo: Path) -> Path:
    return Path(os.path.realpath(repo / ".git"))


def _id(relative: str) -> str:
    return hashlib.sha256(relative.encode("utf-8")).hexdigest()[:16]


def _site_dir(repo: Path, relative: str = ".") -> Path:
    return _common(repo) / "aegis" / "state" / _id(relative)


def _top(path: Path) -> str:
    return Path(os.path.realpath(path)).as_posix()


def _event(rule: str = "trap-x", outcome: str = "tp", **extra) -> Dict:
    return {"rule": rule, "outcome": outcome, "source": "mcp", **extra}


def _file_rows(path: Path) -> List[Dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _symlink_or_skip(link: Path, target: Path, directory: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")


# ── The workspace id ─────────────────────────────────────────────────────────

@needs_git
def test_the_workspace_id_is_sha256_of_the_posix_path_below_the_toplevel(repo: Path, worktree: Path):
    for tree in (repo, worktree):
        (tree / "pkg" / "app").mkdir(parents=True)
    assert storage.workspace_id(repo) == _id(".")
    assert storage.workspace_id(worktree) == _id(".")
    assert storage.workspace_id(repo / "pkg") == _id("pkg")
    assert storage.workspace_id(repo / "pkg" / "app") == _id("pkg/app")
    assert storage.workspace_id(worktree / "pkg" / "app") == _id("pkg/app")
    assert len(storage.workspace_id(repo)) == 16
    assert len({storage.workspace_id(p) for p in (repo, repo / "pkg", repo / "pkg" / "app")}) == 3


@needs_git
def test_the_id_does_not_depend_on_how_the_workspace_is_spelled(repo: Path, tmp_path: Path):
    link = tmp_path / "alias"
    _symlink_or_skip(link, repo, directory=True)
    assert storage.workspace_id(link) == storage.workspace_id(repo) == _id(".")
    assert storage.workspace_id(str(repo) + os.sep) == _id(".")


def test_outside_git_there_is_no_workspace_id(tmp_path: Path):
    assert storage.workspace_id(tmp_path) is None


# ── Where the ledger lives ───────────────────────────────────────────────────

@needs_git
def test_every_worktree_of_a_repository_has_the_same_ledger_file_in_the_common_dir(repo: Path, worktree: Path):
    expected = _site_dir(repo) / "ledger.jsonl"
    assert ledger.ledger_path(repo) == expected
    assert ledger.ledger_path(worktree) == expected
    assert ledger.ledger_path(str(repo)) == expected
    assert not (_common(repo) / "worktrees" / "other" / "aegis").exists()


@needs_git
def test_each_workspace_of_a_repository_has_its_own_ledger(repo: Path, worktree: Path):
    (repo / "pkg").mkdir()
    (worktree / "pkg").mkdir()
    assert ledger.ledger_path(repo / "pkg") == ledger.ledger_path(worktree / "pkg") == _site_dir(repo, "pkg") / "ledger.jsonl"
    assert ledger.ledger_path(repo / "pkg") != ledger.ledger_path(repo)
    ledger.append(repo, [_event(key="root")])
    ledger.append(repo / "pkg", [_event(key="pkg")])
    assert [r["key"] for r in ledger.read(repo).rows] == ["root"]
    assert [r["key"] for r in ledger.read(worktree / "pkg").rows] == ["pkg"]
    assert [r["seq"] for r in ledger.read(repo / "pkg").rows] == [1]


def test_outside_git_the_ledger_stays_in_the_workspace_state_dir(tmp_path: Path):
    expected = tmp_path.resolve() / ".aegis" / "state" / "ledger.jsonl"
    assert ledger.ledger_path(tmp_path) == expected
    (row,) = ledger.append(tmp_path, [_event(key="k")])
    assert _file_rows(expected) == [row]
    assert "worktree" not in row  # nothing is shared, so nothing to attribute


@needs_git
def test_when_git_cannot_run_the_ledger_stays_local(repo: Path, tmp_path: Path, monkeypatch):
    empty = tmp_path / "no-programs"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    assert ledger.ledger_path(repo) == repo.resolve() / ".aegis" / "state" / "ledger.jsonl"
    ledger.append(repo, [_event(key="k")])
    assert not (_common(repo) / "aegis").exists()


@needs_git
def test_reading_creates_nothing(repo: Path):
    view = ledger.read(repo)
    assert view.rows == [] and view.error is None
    assert view.path == _site_dir(repo) / "ledger.jsonl"
    assert not (_common(repo) / "aegis").exists()
    assert not (repo / ".aegis").exists()


@needs_git
@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_the_shared_directories_are_private(repo: Path):
    old = os.umask(0o022)
    try:
        ledger.append(repo, [_event(key="k")])
    finally:
        os.umask(old)
    for directory in (_common(repo) / "aegis", _common(repo) / "aegis" / "state", _site_dir(repo)):
        assert (directory.stat().st_mode & 0o777) == 0o700, directory


# ── Rows from several worktrees ──────────────────────────────────────────────

@needs_git
def test_rows_from_two_worktrees_share_one_seq_and_carry_their_worktree(repo: Path, worktree: Path):
    (first,) = ledger.append(repo, [_event(key="k1")])
    (second,) = ledger.append(worktree, [_event(key="k2")])
    epoch = ledger.append_epoch(worktree, {"note": "x"})
    (third,) = ledger.append_rows(repo, [{"v": 2, "seq": 99, "ts": "2026-01-01T00:00:00Z", "rule": "trap-x",
                                          "outcome": "fp", "source": "migrate", "key": "k3"}])
    assert [first["seq"], second["seq"], epoch["seq"], third["seq"]] == [1, 2, 3, 4]
    assert first["worktree"] == _top(repo)
    assert second["worktree"] == _top(worktree)
    assert epoch["worktree"] == _top(worktree)
    assert third["worktree"] == _top(repo)
    on_disk = _file_rows(_site_dir(repo) / "ledger.jsonl")
    assert on_disk == [first, second, epoch, third]
    assert ledger.read(repo).rows == ledger.read(worktree).rows == [first, second, third]
    assert not (repo / ".aegis" / "state" / "ledger.jsonl").exists()
    assert not (worktree / ".aegis" / "state" / "ledger.jsonl").exists()


@needs_git
def test_a_worktree_stamp_already_on_a_migrated_row_is_kept(repo: Path):
    (row,) = ledger.append_rows(repo, [{"v": 2, "ts": "2026-01-01T00:00:00Z", "rule": "trap-x", "outcome": "tp",
                                        "source": "migrate", "key": "k", "worktree": "/elsewhere/wt"}])
    assert row["worktree"] == "/elsewhere/wt"


@needs_git
def test_the_same_key_from_another_worktree_is_one_row(repo: Path, worktree: Path):
    (first,) = ledger.append(repo, [_event(key="report-1", host="claude-code", session="s1")])
    (again,) = ledger.append(worktree, [_event(key="report-1", host="codex-cli", session="s2")])
    assert again == first and again["worktree"] == _top(repo)
    assert len(_file_rows(_site_dir(repo) / "ledger.jsonl")) == 1
    with pytest.raises(ledger.EventConflictError):
        ledger.append(worktree, [_event(outcome="fp", key="report-1")])
    assert len(ledger.read(repo).rows) == 1
    (other_rule,) = ledger.append(worktree, [_event(rule="trap-z", key="report-1")])  # (key, rule) is the identity
    assert other_rule["seq"] == 2


@needs_git
def test_a_row_for_the_warm_index_of_another_worktrees_process_is_seen(repo: Path, worktree: Path):
    ledger.append(repo, [_event(key="k1")])  # warms this process's index of the shared file
    code = textwrap.dedent("""
        import sys
        from aegis_core.telemetry_engine import ledger
        ledger.append(sys.argv[1], [{"rule": "b", "outcome": "fp", "source": "ci", "key": "k2"}])
    """)
    env = dict(os.environ, PYTHONPATH=REPO_ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
    proc = subprocess.run([sys.executable, "-c", code, str(worktree)], capture_output=True, text=True,
                          env=env, cwd=REPO_ROOT, timeout=60)
    assert proc.returncode == 0, proc.stderr
    with pytest.raises(ledger.EventConflictError):
        ledger.append(repo, [_event(rule="b", outcome="tp", key="k2")])
    (row,) = ledger.append(repo, [_event(key="k3")])
    assert row["seq"] == 3


def _race(cwds: List[Path], count: int, shared_keys: List[str]) -> List[tuple]:
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(len(cwds))
    results = ctx.Queue()
    procs = [
        ctx.Process(target=helpers_ledgerrace.append_events,
                    args=(str(cwd), f"w{i}", count, shared_keys, barrier, results))
        for i, cwd in enumerate(cwds)
    ]
    for proc in procs:
        proc.start()
    try:
        return [results.get(timeout=240) for _ in procs]
    except queue.Empty:
        pytest.fail("a racer never reported")
    finally:
        for proc in procs:
            proc.join(timeout=60)
            if proc.is_alive():
                proc.terminate()


@needs_git
def test_two_worktrees_appending_concurrently_lose_and_duplicate_no_row(repo: Path, worktree: Path):
    count, shared = 25, ["shared-0", "shared-1", "shared-2"]
    racers = [repo, worktree, repo, worktree]
    outcomes = _race(racers, count, shared)
    assert [o for o in outcomes if o[1] == "error"] == []

    rows = _file_rows(_site_dir(repo) / "ledger.jsonl")
    # 4 racers x 15 own keys, 3 keys all four share, 4 keyless rows: nothing lost, nothing twice.
    assert len(rows) == 4 * count + len(shared) + 4
    assert [r["seq"] for r in rows] == list(range(1, len(rows) + 1))
    keyed = [(r["key"], r["rule"]) for r in rows if r.get("key")]
    assert len(keyed) == len(set(keyed)) == 4 * count + len(shared)
    assert sum(1 for r in rows if not r.get("key")) == 4

    owner = {f"w{i}": _top(tree) for i, tree in enumerate(racers)}
    for row in rows:
        worker = str(row.get("key", "")).split("-")[0]
        if worker in owner:
            assert row["worktree"] == owner[worker], row
        assert row["worktree"] in (_top(repo), _top(worktree))
    # Every racer saw the one row stored for a shared key, not a row of its own.
    for index, key in enumerate(shared):
        returned = {o[2][count + index] for o in outcomes}
        stored = [r["seq"] for r in rows if r.get("key") == key]
        assert len(stored) == 1 and returned == set(stored), key
    # Each racer's own appends were numbered in the order it made them.
    for _worker, _status, seqs in outcomes:
        own = seqs[:count]
        assert own == sorted(own) and len(set(own)) == count
    view = ledger.read(worktree)
    assert len(view.rows) == len(rows) and view.skipped_lines == [] and not view.incomplete
    assert ledger.aggregate(repo, "trap-x")["triggers"] == 4 * count + len(shared)


# ── One lock, taken by every writer ──────────────────────────────────────────

_HOLD = textwrap.dedent("""
    import sys
    from aegis_core.storage import ledger_locked, locked
    lock = locked(sys.argv[1]) if sys.argv[2] == "workspace" else ledger_locked(sys.argv[1])
    with lock:
        print("held", flush=True)
        sys.stdin.read()
""")


class _Holder:
    """Another process holding a lock until it is told to let go."""

    def __init__(self, ws: Path, kind: str = "ledger") -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        self.proc = subprocess.Popen(
            [sys.executable, "-c", _HOLD, str(ws), kind],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=env, cwd=REPO_ROOT,
        )

    def __enter__(self) -> "_Holder":
        assert self.proc.stdout.readline().strip() == "held", self.proc.stderr.read()
        return self

    def __exit__(self, *exc) -> None:
        self.proc.stdin.close()
        self.proc.wait(timeout=30)


_ROW = {"v": 2, "ts": "2026-01-01T00:00:00Z", "rule": "trap-x", "outcome": "tp", "source": "migrate", "key": "m"}
WRITERS: Dict[str, Callable[[Path], object]] = {
    "append": lambda ws: ledger.append(ws, [_event(key="k")]),
    "append_epoch": lambda ws: ledger.append_epoch(ws, {"note": "x"}),
    "append_rows": lambda ws: ledger.append_rows(ws, [dict(_ROW)]),
}


@needs_git
@pytest.mark.parametrize("writer", sorted(WRITERS))
@pytest.mark.timing
def test_every_ledger_writer_waits_for_the_one_common_lock(repo: Path, worktree: Path, monkeypatch, writer: str):
    monkeypatch.setattr(storage, "LOCK_TIMEOUT_SECONDS", 0.3)
    lock = _site_dir(repo) / "lock"
    with _Holder(worktree):  # a process of ANOTHER worktree holds it
        began = time.monotonic()
        with pytest.raises(LockTimeoutError) as info:
            WRITERS[writer](repo)
        waited = time.monotonic() - began
        assert not (_site_dir(repo) / "ledger.jsonl").exists()  # nothing was written meanwhile
    assert str(info.value) == (
        f"timed out after 0.3s waiting for the Aegis shared lock {lock}: another aegis process or thread holds it"
    )
    assert info.value.path == str(lock)
    assert 0.25 <= waited < 5
    WRITERS[writer](repo)  # released with the holder
    assert len(_file_rows(_site_dir(repo) / "ledger.jsonl")) == 1


@needs_git
def test_a_caller_holding_the_worktree_lock_may_write_worktree_lock_first(repo: Path):
    with locked(repo):
        ledger.append(repo, [_event(key="k")])
        ledger.append_epoch(repo, {"note": "x"})
        ledger.append_rows(repo, [dict(_ROW)])
    assert len(_file_rows(_site_dir(repo) / "ledger.jsonl")) == 3


@needs_git
def test_the_worktree_lock_is_never_taken_inside_the_ledger_lock(repo: Path):
    with storage.ledger_locked(repo) as site:
        with pytest.raises(LockOrderError) as info:
            with locked(repo, timeout=0.5):
                pytest.fail("took the worktree lock inside the ledger lock")
    assert str(info.value) == (
        f"lock order: the Aegis workspace lock is taken before a shared lock, never while holding {site.lock}"
    )


@needs_git
def test_the_ledger_lock_is_a_file_in_the_ledger_directory(repo: Path):
    with storage.ledger_locked(repo) as site:
        assert site.lock == _site_dir(repo) / "lock" and site.lock.is_file()
        assert site.path == _site_dir(repo) / "ledger.jsonl"
        assert site.shared is True and site.worktree == _top(repo)
        with storage.ledger_locked(str(repo), timeout=0.2):  # re-entrant per thread
            pass


def test_outside_git_the_ledger_lock_is_the_workspace_lock(tmp_path: Path):
    with storage.ledger_locked(tmp_path) as site:
        assert site.lock == tmp_path.resolve() / ".aegis" / "state" / "lock"
        assert site.shared is False and site.worktree is None
        with locked(tmp_path, timeout=0.2):  # the same lock: re-entrant, not a second one
            pass


# ── Confinement ──────────────────────────────────────────────────────────────

def _link_message(path: Path, base: Path) -> str:
    return f"refusing to use {path}: it is a symlink; aegis keeps shared state only inside {base}"


def _every_writer_is_refused(repo: Path, message: str) -> None:
    for name, writer in sorted(WRITERS.items()):
        with pytest.raises(PathTraversalError) as info:
            writer(repo)
        assert str(info.value) == message, name
    view = ledger.read(repo)
    assert view.rows == [] and view.error == message and view.incomplete == message
    with pytest.raises(PathTraversalError):
        ledger.ledger_path(repo)


@needs_git
@pytest.mark.parametrize("which", ["aegis", "state", "id"])
def test_a_symlinked_directory_on_the_way_is_refused_and_nothing_is_written_through_it(
    repo: Path, tmp_path: Path, which: str,
):
    site = storage.ledger_site(repo).path.parent  # creates <common>/aegis/state/<id>
    target = {"aegis": _common(repo) / "aegis", "state": _common(repo) / "aegis" / "state", "id": site}[which]
    outside = tmp_path / "outside"
    outside.mkdir()
    shutil.rmtree(target)
    _symlink_or_skip(target, outside, directory=True)
    _every_writer_is_refused(repo, _link_message(target, _common(repo)))
    assert list(outside.iterdir()) == []


@needs_git
@pytest.mark.parametrize("name", ["ledger.jsonl", "lock"])
def test_a_symlinked_ledger_or_lock_file_is_refused_and_its_target_untouched(repo: Path, tmp_path: Path, name: str):
    site = storage.ledger_site(repo).path.parent
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me\n", encoding="utf-8")
    _symlink_or_skip(site / name, victim, directory=False)
    _every_writer_is_refused(repo, _link_message(site / name, _common(repo)))
    assert victim.read_text(encoding="utf-8") == "keep me\n"


@needs_git
def test_a_directory_resolving_outside_the_common_dir_is_refused(repo: Path, tmp_path: Path, monkeypatch):
    """What a Windows junction looks like: not a symlink, but it resolves elsewhere."""
    site = storage.ledger_site(repo).path.parent
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    real = os.path.realpath

    def realpath(path, *args, **kwargs):
        resolved = real(path, *args, **kwargs)
        return str(outside) if os.path.basename(resolved) == site.name else resolved

    monkeypatch.setattr(os.path, "realpath", realpath)
    message = (f"refusing to use {site}: it resolves outside {_common(repo)}; "
               "aegis keeps shared state only inside it")
    _every_writer_is_refused(repo, message)
    assert list(outside.iterdir()) == []


@needs_git
def test_a_file_where_the_ledger_directory_belongs_is_refused(repo: Path):
    state = _common(repo) / "aegis" / "state"
    storage.shared_state_dir(repo)
    state.write_text("not a directory", encoding="utf-8")
    _every_writer_is_refused(repo, f"refusing to use {state}: it is not a directory")


@needs_git
def test_a_refused_directory_is_refused_for_reading_without_creating_anything(repo: Path, tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    shared = _common(repo) / "aegis"
    _symlink_or_skip(shared, outside, directory=True)
    view = ledger.read(repo)
    assert view.rows == [] and view.error == _link_message(shared, _common(repo))
    assert list(outside.iterdir()) == []
