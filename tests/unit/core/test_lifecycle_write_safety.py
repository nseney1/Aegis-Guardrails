"""M1 and timestamp regressions for rule-file writes in the lifecycle engine.

Invariants under test (docs/adr/0005-evidence-review.md M1):
- every rule-file mutation waits for ``storage.locked()``, the one workspace lock;
- every rule-file write is atomic: when the filesystem refuses the final
  write, the rules directory is byte-identical to before (no truncated rule,
  no stray temp file, no half-finished move);
- the tier pass writes nothing: ledger numbers never move an enforcement tier (D-tier-ladder);
- persisted lifecycle timestamps are one valid UTC ISO-8601 form;
- the existence checks that promote/demote run before taking the
  lock are repeated under it, so a rival create or move that lands in between
  is never overwritten and never crashes the second mover;
- the archive pass changes only the rules that need it and holds the lock per rule,
  not for the whole pass; archiving re-checks the rule's ledger
  evidence under the lock, never revisits a hidden directory and never overwrites a
  rule already archived under the same name.

Fitness comes only from the ledger (aegis_core.fitness), so every scenario that should
move a rule gives it ledger evidence; frontmatter counters are never read.
"""
from __future__ import annotations

import builtins
import errno
import hashlib
import io
import json
import os
import re
import subprocess
import sys
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import pytest

from conftest import REPO_ROOT

import aegis_core.lifecycle.promotion as promotion
import aegis_core.lifecycle.selection as selection
from aegis_core.lifecycle.creation import create_rule
from aegis_core.lifecycle.promotion import demote_rule, evaluate_rule_tiers, evaluate_demotions, promote_rule
from aegis_core.lifecycle.selection import evaluate_archives, run_rule_selection
from aegis_core.fitness import MIN_N
from aegis_core.telemetry_engine import ledger

_UTC_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_KEYS = iter(range(10**9))


def _rule(path: Path, rule_id: str, rule_type: str, enforcement: str = "advisory") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"---\nid: {rule_id}\ntype: {rule_type}\nenforcement: {enforcement}\nimpact_weight: 1.0\n"
        f"---\n# {rule_id}\nBody text.\n",
        encoding="utf-8",
    )
    return path


def _evidence(ws: Path, rule_id: str, tp: int = 0, fp: int = 0) -> None:
    """Append ``tp`` true-positive and ``fp`` false-positive ledger rows for ``rule_id``."""
    rows = [{"rule": rule_id, "outcome": o, "source": "ci", "key": f"run-{next(_KEYS)}"}
            for o in ["tp"] * tp + ["fp"] * fp]
    ledger.append(ws, rows)


def _misfiring(path: Path, rule_id: str, rule_type: str = "trap") -> Path:
    """A rule the ledger is confident fires wrongly: MIN_N false positives (the one sample gate,
    R-evidence-8), no true positive."""
    _rule(path, rule_id, rule_type, "gate" if rule_type in ("invariant", "gate") else "advisory")
    _evidence(path.parents[3], rule_id, fp=MIN_N)
    return path


def _snapshot(directory: Path) -> list[tuple[str, str]]:
    out = []
    for dirpath, _dirs, files in os.walk(directory):
        for name in files:
            full = Path(dirpath) / name
            out.append((full.relative_to(directory).as_posix(), hashlib.sha256(full.read_bytes()).hexdigest()))
    return sorted(out)


# ── Scenarios: (locked workspace, operation) ────────────────────────────

def _ws(tmp_path: Path, name: str = "ws") -> Path:
    ws = tmp_path / name
    (ws / ".aegis" / "rules").mkdir(parents=True)
    return ws


def _rules(ws: Path) -> Path:
    return ws / ".aegis" / "rules"


def _scenario_create(tmp_path: Path):
    ws = _ws(tmp_path)
    return ws, lambda: create_rule("trap", "Locked create", id_override="locked-create", workspace=ws)


def _scenario_archive(tmp_path: Path):
    ws = _ws(tmp_path)
    _misfiring(_rules(ws) / "traps" / "noisy.md", "noisy")
    return ws, lambda: run_rule_selection(ws, execute=True)


def _scenario_promote(tmp_path: Path):
    ws = _ws(tmp_path)
    _rule(_rules(ws) / "traps" / "rising.md", "rising", "trap")
    return ws, lambda: promote_rule(ws, "rising", force=True)


def _scenario_demote(tmp_path: Path):
    ws = _ws(tmp_path)
    _rule(_rules(ws) / "invariants" / "falling.md", "falling", "invariant", "gate")
    return ws, lambda: demote_rule(ws, "falling")


_SCENARIOS = {
    "create": _scenario_create,
    "archive": _scenario_archive,
    "promote": _scenario_promote,
    "demote": _scenario_demote,
}

_LOCK_HOLDER = r"""
import hashlib, os, sys, time
from pathlib import Path
from aegis_core.storage import locked

def snap(root):
    out = []
    for dirpath, _d, files in os.walk(root):
        for name in files:
            p = os.path.join(dirpath, name)
            with open(p, "rb") as fh:
                out.append((os.path.relpath(p, root), hashlib.sha256(fh.read()).hexdigest()))
    return sorted(out)

ws, rules, hold = Path(sys.argv[1]), sys.argv[2], float(sys.argv[3])
with locked(ws):
    before = snap(rules)
    print("locked", flush=True)
    time.sleep(hold)
    print("same" if snap(rules) == before else "changed", flush=True)
"""


@pytest.mark.parametrize("scenario", sorted(_SCENARIOS))
def test_rule_writes_wait_for_the_rules_lock(tmp_path: Path, scenario: str) -> None:
    locked_ws, operation = _SCENARIOS[scenario](tmp_path)
    rules_dir = _rules(locked_ws)
    before = _snapshot(rules_dir)
    env = dict(os.environ, PYTHONPATH=REPO_ROOT, HOME=str(tmp_path / "home"), USERPROFILE=str(tmp_path / "home"))
    proc = subprocess.Popen(
        [sys.executable, "-c", _LOCK_HOLDER, str(locked_ws), str(rules_dir), "1.0"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
    )
    try:
        # The holder exits (EOF) after its 1 s hold, so this cannot hang.
        first = proc.stdout.readline().strip()
        assert first == "locked", proc.stderr.read()
        operation()
        out, err = proc.communicate(timeout=15)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    assert out.strip() == "same", f"{scenario} wrote rules while another process held the rules lock"
    assert _snapshot(rules_dir) != before, f"{scenario} did not change the rules directory"


@pytest.mark.parametrize("scenario", sorted(_SCENARIOS))
def test_failed_final_write_leaves_rules_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scenario: str
) -> None:
    locked_ws, operation = _SCENARIOS[scenario](tmp_path)
    rules_dir = _rules(locked_ws)
    before = _snapshot(rules_dir)

    def refuse(src, dst):
        raise OSError(errno.EIO, "simulated I/O error on final rename")

    monkeypatch.setattr(os, "replace", refuse)
    with pytest.raises(OSError, match="simulated I/O error"):
        operation()
    monkeypatch.undo()

    assert _snapshot(rules_dir) == before


@pytest.mark.parametrize("scenario", sorted(_SCENARIOS))
def test_rule_files_are_never_rewritten_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scenario: str
) -> None:
    """A plain open(..., "w") on a rule truncates it first; a crash then leaves a broken rule."""
    locked_ws, operation = _SCENARIOS[scenario](tmp_path)
    rules_dir = _rules(locked_ws).resolve()
    in_place: list[tuple[str, str]] = []
    real_open = builtins.open

    def spy(file, mode="r", *args, **kwargs):
        if isinstance(file, (str, os.PathLike)) and any(flag in mode for flag in "wax+"):
            target = Path(os.fspath(file)).resolve()
            if rules_dir in target.parents:
                in_place.append((target.relative_to(rules_dir).as_posix(), mode))
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", spy)
    monkeypatch.setattr(io, "open", spy)
    operation()
    monkeypatch.undo()

    assert in_place == []


def test_the_tier_pass_never_rewrites_a_rule_from_ledger_numbers(tmp_path: Path) -> None:
    """30 of 30 verdicts once moved an advisory trap to mechanical; ledger numbers no longer move
    an enforcement tier (D-tier-ladder), and no enforcement artifact is generated."""
    ws = _ws(tmp_path)
    rule = _rule(_rules(ws) / "traps" / "proven.md", "proven", "trap")
    _evidence(ws, "proven", tp=30)
    before = rule.read_bytes()

    assert evaluate_rule_tiers(ws, execute=True) == {"evaluated": 1, "changes": []}

    assert rule.read_bytes() == before
    assert not (ws / ".aegis" / "enforcement").exists()


# ── Timestamps ─────────────────────────────────────────────────────────

def _assert_utc(ts: object) -> None:
    assert isinstance(ts, str) and _UTC_TS.match(ts), f"malformed UTC timestamp: {ts!r}"
    datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def test_archiving_logs_a_valid_utc_timestamp(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _misfiring(_rules(ws) / "traps" / "noisy.md", "noisy")

    assert run_rule_selection(ws, execute=True) == 0

    log_lines = (ws / ".aegis" / "state" / "lifecycle.jsonl").read_text(encoding="utf-8").splitlines()
    entry = json.loads(log_lines[-1])
    assert (entry["rule"], entry["action"]) == ("noisy", "moved_to_archive")
    _assert_utc(entry["timestamp"])


# ── Interleavings: a rival lands between the unlocked checks and the lock ──

def _rival_on_first_lock(monkeypatch: pytest.MonkeyPatch, rival, module=promotion) -> None:
    """Run ``rival`` just before the lifecycle engine's first rules-lock acquisition.

    This is the window a concurrent process gets between promote/demote's
    unlocked existence checks and their locked move.
    """
    real_lock = module.locked
    pending = [rival]

    @contextmanager
    def lock_after_rival(*args, **kwargs):
        if pending:
            pending.pop()()
        with real_lock(*args, **kwargs) as held:
            yield held

    monkeypatch.setattr(module, "locked", lock_after_rival)


def _rival_rule(path: Path, marker: str) -> None:
    """A rule another writer (a second Aegis process, a git checkout) lands meanwhile.

    create_rule refuses an id that is already active in any tier, so the rival
    writes the file directly.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"---\nid: {path.stem}\ntype: rival\n---\n{marker}\n", encoding="utf-8")


def test_promote_never_overwrites_a_rule_created_in_the_target_tier_meanwhile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = _ws(tmp_path)
    source = _rule(_rules(ws) / "traps" / "shared-id.md", "shared-id", "trap")
    _rival_on_first_lock(monkeypatch, lambda: _rival_rule(_rules(ws) / "invariants" / "shared-id.md", "Rival invariant"))

    res = promote_rule(ws, "shared-id", force=True)

    assert res["status"] == "target_exists"
    assert "Rival invariant" in (_rules(ws) / "invariants" / "shared-id.md").read_text(encoding="utf-8")
    assert source.is_file()


def test_concurrent_promotes_of_one_rule_promote_it_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = _ws(tmp_path)
    _rule(_rules(ws) / "traps" / "once.md", "once", "trap")
    rival: list[dict] = []
    _rival_on_first_lock(monkeypatch, lambda: rival.append(promote_rule(ws, "once", force=True)))

    res = promote_rule(ws, "once", force=True)

    assert rival[0]["status"] == "promoted"
    assert res["status"] == "not_found"
    assert (_rules(ws) / "invariants" / "once.md").is_file()
    assert not (_rules(ws) / "gates" / "once.md").exists()


def test_demote_never_overwrites_a_trap_created_meanwhile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = _ws(tmp_path)
    source = _rule(_rules(ws) / "invariants" / "guarded.md", "guarded", "invariant", "gate")
    _rival_on_first_lock(monkeypatch, lambda: _rival_rule(_rules(ws) / "traps" / "guarded.md", "Rival trap"))

    res = demote_rule(ws, "guarded")

    assert res["status"] == "target_exists"
    assert "Rival trap" in (_rules(ws) / "traps" / "guarded.md").read_text(encoding="utf-8")
    assert source.is_file()


def test_concurrent_demotes_of_one_rule_demote_it_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = _ws(tmp_path)
    _rule(_rules(ws) / "invariants" / "guarded.md", "guarded", "invariant", "gate")
    rival: list[dict] = []
    _rival_on_first_lock(monkeypatch, lambda: rival.append(demote_rule(ws, "guarded")))

    res = demote_rule(ws, "guarded")

    assert rival[0]["status"] == "demoted"
    assert res["status"] == "not_found"
    assert (_rules(ws) / "traps" / "guarded.md").is_file()


# ── Tier pass: rewrite only what changes, lock only while rewriting ─────

_LOCK_HOLDER_UNTIL_EOF = r"""
import sys
from pathlib import Path
from aegis_core.storage import locked

with locked(Path(sys.argv[1])):
    print("locked", flush=True)
    sys.stdin.read()
"""


@contextmanager
def _lock_held_by_another_process(tmp_path: Path, ws: Path):
    env = dict(os.environ, PYTHONPATH=REPO_ROOT, HOME=str(tmp_path / "home"), USERPROFILE=str(tmp_path / "home"))
    holder = subprocess.Popen(
        [sys.executable, "-c", _LOCK_HOLDER_UNTIL_EOF, str(ws)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
    )
    try:
        assert holder.stdout.readline().strip() == "locked", holder.stderr.read()
        yield
    finally:
        holder.stdin.close()
        try:
            holder.wait(timeout=15)
        finally:
            if holder.poll() is None:
                holder.kill()
                holder.wait()


def test_tier_pass_does_not_rewrite_unchanged_rules(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    rules = [_rule(_rules(ws) / "traps" / f"steady-{i}.md", f"steady-{i}", "trap") for i in range(3)]
    stamps = [(p.stat().st_ino, p.stat().st_mtime_ns) for p in rules]

    res = evaluate_rule_tiers(ws, execute=True)

    assert res == {"evaluated": 3, "changes": []}
    assert [(p.stat().st_ino, p.stat().st_mtime_ns) for p in rules] == stamps


def test_tier_pass_with_nothing_to_change_does_not_wait_for_the_rules_lock(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _rule(_rules(ws) / "traps" / "steady.md", "steady", "trap")
    before = _snapshot(_rules(ws))
    with _lock_held_by_another_process(tmp_path, ws):
        # Needing the lock here would raise LockTimeoutError after 10 s.
        res = evaluate_rule_tiers(ws, execute=True)

    assert res == {"evaluated": 1, "changes": []}
    assert _snapshot(_rules(ws)) == before


# ── Archive pass: per-rule lock, re-checked under it, no revisits, no overwrites ──

def _log_actions(ws: Path) -> list[tuple[str, str]]:
    log = ws / ".aegis" / "state" / "lifecycle.jsonl"
    if not log.exists():
        return []
    return [(e["rule"], e["action"]) for e in map(json.loads, log.read_text(encoding="utf-8").splitlines())]


def test_archive_pass_with_nothing_to_change_does_not_wait_for_the_rules_lock(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _rule(_rules(ws) / "traps" / "strong.md", "strong", "trap")
    _evidence(ws, "strong", tp=10)
    _rule(_rules(ws) / "traps" / "unproven.md", "unproven", "trap")
    before = _snapshot(_rules(ws))
    with _lock_held_by_another_process(tmp_path, ws):
        # Needing the lock here would raise LockTimeoutError after 10 s.
        rc = run_rule_selection(ws, execute=True)

    assert rc == 0
    assert _snapshot(_rules(ws)) == before
    assert _log_actions(ws) == []


def test_archive_pass_takes_the_rules_lock_once_per_changed_rule(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A pass over hundreds of rules must not hold the lock across all of them (finding F5)."""
    ws = _ws(tmp_path)
    for name in ("quiet-a", "quiet-b", "quiet-c"):
        _misfiring(_rules(ws) / "traps" / f"{name}.md", name)
    _rule(_rules(ws) / "traps" / "strong.md", "strong", "trap")
    _evidence(ws, "strong", tp=10)
    real_lock = selection.locked
    depth: list[int] = []
    held = [0]

    @contextmanager
    def counting_lock(*args, **kwargs):
        held[0] += 1
        depth.append(held[0])
        try:
            with real_lock(*args, **kwargs) as h:
                yield h
        finally:
            held[0] -= 1

    monkeypatch.setattr(selection, "locked", counting_lock)

    assert run_rule_selection(ws, execute=True) == 0

    assert depth == [1, 1, 1]
    assert sorted(_log_actions(ws)) == [(f"quiet-{x}", "moved_to_archive") for x in "abc"]
    assert (_rules(ws) / "traps" / "strong.md").is_file()


def test_archiving_acts_on_the_evidence_as_it_is_under_the_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """The rule is judged unlocked; true positives recorded before the lock must win."""
    ws = _ws(tmp_path)
    rule = _misfiring(_rules(ws) / "traps" / "revived.md", "revived")
    _rival_on_first_lock(monkeypatch, lambda: _evidence(ws, "revived", tp=4 * MIN_N), module=selection)

    assert run_rule_selection(ws, execute=True) == 0

    out = capsys.readouterr().out
    assert "[ARCHIVE] revived" in out
    assert "(not archived: Rule 'revived' no longer has evidence that supports archiving it)" in out
    assert rule.is_file(), "a rule whose evidence recovered before the lock must not be archived"
    assert not (_rules(ws) / ".archive" / "revived.md").exists()
    assert _log_actions(ws) == []


def test_archiving_skips_a_rule_moved_away_meanwhile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = _ws(tmp_path)
    rule = _misfiring(_rules(ws) / "traps" / "doomed.md", "doomed")
    moved = _rules(ws) / "invariants" / "doomed.md"

    def move_away() -> None:
        moved.parent.mkdir(parents=True, exist_ok=True)
        rule.rename(moved)

    _rival_on_first_lock(monkeypatch, move_away, module=selection)

    assert run_rule_selection(ws, execute=True) == 0

    assert moved.is_file()
    assert not (_rules(ws) / ".archive" / "doomed.md").exists()
    assert _log_actions(ws) == []


def test_a_misfiring_invariant_is_a_demotion_candidate_not_archived(tmp_path: Path) -> None:
    """Archiving is for rules with no lower tier; a gate or invariant steps down first."""
    ws = _ws(tmp_path)
    rule = _misfiring(_rules(ws) / "invariants" / "noisy-inv.md", "noisy-inv", "invariant")
    before = rule.read_bytes()

    assert evaluate_archives(ws) == []
    assert run_rule_selection(ws, execute=True) == 0

    assert rule.read_bytes() == before
    assert [c["rule_id"] for c in evaluate_demotions(ws)] == ["noisy-inv"]
    assert _log_actions(ws) == []


def test_archiving_never_revisits_a_legacy_last_gasp_queue(tmp_path: Path, capsys) -> None:
    """Rules a v3 selection pass parked in .last_gasp_queue are not loaded, so never moved."""
    ws = _ws(tmp_path)
    queue = _rules(ws) / ".last_gasp_queue"
    waiting = _misfiring(queue / "waiting.md", "waiting")
    queued = _snapshot(queue)

    run_rule_selection(ws, execute=True)

    assert _snapshot(queue) == queued
    assert waiting.is_file()
    assert _log_actions(ws) == []
    assert "waiting" not in capsys.readouterr().out


def test_archiving_never_overwrites_a_rule_already_archived_under_the_same_name(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    earlier = _rules(ws) / ".archive" / "reused.md"
    earlier.parent.mkdir(parents=True)
    earlier.write_text("---\nid: reused\ntype: trap\n---\nThe earlier rule.\n", encoding="utf-8")
    current = _misfiring(_rules(ws) / "traps" / "reused.md", "reused")
    current_text = current.read_text(encoding="utf-8")

    run_rule_selection(ws, execute=True)

    assert not current.exists()
    assert earlier.read_text(encoding="utf-8") == "---\nid: reused\ntype: trap\n---\nThe earlier rule.\n"
    assert (_rules(ws) / ".archive" / "reused.1.md").read_text(encoding="utf-8") == current_text
    assert _log_actions(ws) == [("reused", "moved_to_archive")]


def test_archiving_runs_in_a_workspace_whose_path_contains_archive(tmp_path: Path) -> None:
    ws = _ws(tmp_path / "old.archive", "ws")
    rule = _misfiring(_rules(ws) / "traps" / "quiet.md", "quiet")

    run_rule_selection(ws, execute=True)

    assert not rule.exists()
    assert (_rules(ws) / ".archive" / "quiet.md").is_file()
    assert _log_actions(ws) == [("quiet", "moved_to_archive")]
