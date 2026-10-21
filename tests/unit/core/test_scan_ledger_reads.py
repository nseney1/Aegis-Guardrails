"""One ledger read per call (R-structure-5, R-evidence-19): totals, credits and T4 events of a
``for_rules`` call come from one snapshot; only ``record_exposure``'s locked dedup read is separate.

Read-only opens of the ledger file are counted at ``storage._open_regular`` (the one opener every
ledger reader uses), so the count is the same on every OS. Nothing is timed.
"""
from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
import subprocess
from typing import Callable, Dict, List

import pytest

from aegis_core import credit, fitness, storage
from aegis_core.rules import load_rules
from aegis_core.telemetry_engine import ledger

RULE = ("---\nid: {rid}\ntype: trap\nenforcement: advisory\nhypothesis: h\ntarget_paths:\n  - src/*.py\n---\n"
        "# {rid}\n\nBody long enough to be a rule body.\n")


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=T", *args], cwd=str(cwd), check=True,
                   capture_output=True)


@pytest.fixture
def ws(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "AEGIS_WORKSPACE", "CLAUDE_PROJECT_DIR"):
        monkeypatch.delenv(name, raising=False)
    root = (tmp_path / "repo").resolve()
    for rid in ("trap-a", "trap-b"):
        path = root / ".aegis" / "rules" / "traps" / f"{rid}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(RULE.format(rid=rid), encoding="utf-8")
    (root / "src").mkdir()
    (root / "src" / "foo.py").write_text("x = 1\n", encoding="utf-8")
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    _seed(root)
    return root


def _row(**fields) -> Dict:
    return {"v": ledger.LEDGER_VERSION, "ts": "2026-10-01T00:00:00Z", **fields}


def _seed(root: Path) -> None:
    ledger.append(root, [{"rule": "trap-a", "outcome": "tp", "source": "ci", "key": f"o{i}"} for i in range(3)])
    ledger.append(root, [{"rule": "trap-b", "outcome": "fp", "source": "ci", "key": "o-b"}])
    ledger.append_rows(root, [
        _row(event="exposure", rule="trap-a", session="s0", host="h", paths=["src/foo.py"], rev=None),
        _row(event="detection", rule="trap-b", file="src/foo.py", pattern="eval", disposition="caught",
             branch="main", rev="r1", fix_rev="r2", weight=0.5),
        _row(event="adjudication", rule="trap-a", verdict="tp", adjudicator="human", ref="pr-1"),
    ])
    with open(ledger.ledger_path(root), "a", encoding="utf-8", newline="\n") as fh:  # an N-1 v1 row
        fh.write(json.dumps({"rule_id": "trap-a", "signal": "tp", "source": "mcp",
                             "timestamp": "2026-09-01T00:00:00Z", "event_id": "v1-1"}) + "\n")


def _reads(monkeypatch, root: Path, fn: Callable[[], object]) -> int:
    """Read-only opens of ``root``'s ledger while ``fn`` runs."""
    target = os.path.normcase(os.path.realpath(ledger.ledger_path(root)))
    seen: List[int] = []
    real = storage._open_regular

    def opener(path, flags, *rest, **kwargs):
        if not flags & (os.O_WRONLY | os.O_RDWR) and os.path.normcase(os.path.realpath(path)) == target:
            seen.append(1)
        return real(path, flags, *rest, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(storage, "_open_regular", opener)
        fn()
    return len(seen)


def _served(root: Path):
    return load_rules(root).served


def _mcp_scan(root: Path, session: str = "s1") -> Dict:
    from aegis_mcp.handlers.core import handle_scan

    res = handle_scan({"workspace": str(root), "files": ["src/foo.py"], "_session": session, "_host": "claude-code"})
    assert sorted(r["name"] for r in res["relevant_rules"]) == ["trap-a", "trap-b"], res
    return res


def test_an_mcp_scan_reads_the_ledger_at_most_twice_and_once_when_its_exposures_are_kept(ws, monkeypatch):
    assert _reads(monkeypatch, ws, lambda: _mcp_scan(ws)) <= 2
    assert _reads(monkeypatch, ws, lambda: _mcp_scan(ws)) == 1


def test_fitness_reads_the_ledger_once_and_not_at_all_from_a_view(ws, monkeypatch):
    rules = _served(ws)
    assert _reads(monkeypatch, ws, lambda: fitness.for_rules(ws, rules)) == 1
    view = ledger.read(ws)
    assert _reads(monkeypatch, ws, lambda: fitness.for_rules(ws, rules, view=view)) == 0


def test_a_view_is_one_instant_and_a_fresh_call_sees_what_was_added(ws):
    rules = _served(ws)
    before = fitness.for_rules(ws, rules)
    view = ledger.read(ws)
    credit.record_detection(ws, "trap-a", "src/foo.py", "exec", disposition="leaked", rev="r9")
    ledger.append(ws, [{"rule": "trap-a", "outcome": "tp", "source": "ci", "key": "o-new"}])
    assert fitness.for_rules(ws, rules, view=view) == before
    after = fitness.for_rules(ws, rules)["trap-a"]
    assert after.leaked == before["trap-a"].leaked + 1
    assert after.triggers == before["trap-a"].triggers + 1 and after.tp == before["trap-a"].tp + 1


@pytest.mark.parametrize("damaged", [False, True], ids=["clean", "unreadable-line"])
def test_the_numbers_from_one_snapshot_equal_those_from_separate_reads(ws, damaged):
    if damaged:
        with open(ledger.ledger_path(ws), "ab") as fh:
            fh.write(b"{not json\n")
    rules = _served(ws)
    view = ledger.read(ws)
    threaded = fitness.for_rules(ws, rules, view=view)
    separate = fitness.for_rules(ws, rules, view=dataclasses.replace(view, raw_rows=None))
    assert {k: dataclasses.asdict(v) for k, v in threaded.items()} == {k: dataclasses.asdict(v) for k, v in separate.items()}
    if damaged:
        assert {(f.evidence_available, f.evidence_error) for f in threaded.values()} == {(False, "1 unreadable line(s)")}


def test_status_reads_the_ledger_at_most_twice(ws, monkeypatch, capsys):
    from aegis_cli.cli import main

    assert _reads(monkeypatch, ws, lambda: main(["status", "--json", "--workspace", str(ws)])) <= 2
    assert "trap-a" in capsys.readouterr().out


def test_every_t4_event_arm_reads_as_before(ws):
    rows = [
        {"rule": "trap-a", "outcome": "tp", "source": "session", "key": "amb-1"},  # ambient: a trigger
    ]
    ledger.append(ws, rows)
    ledger.append_rows(ws, [
        _row(ts="2026-10-02T00:00:00Z", event="exposure", rule="trap-a", session="s1", host="h", paths=[], rev=None,
             heartbeat=False),
        _row(ts="2026-10-03T00:00:00Z", event="exposure", rule="trap-a", session="s2", host="h", paths=[], rev=None,
             heartbeat=True),
        _row(ts="2026-10-04T00:00:00Z", event="detection", rule="trap-a", file="src/foo.py", pattern="exec",
             disposition="leaked", branch="main", rev="r5", fix_rev=None, weight=1.0),
        _row(ts="2026-10-05T00:00:00Z", event="detection", rule="trap-a", file="src/foo.py", pattern="exec",
             disposition="caught", branch="main", rev="r5", fix_rev="r6", weight=0.5),
        _row(ts="2026-10-06T00:00:00Z", event="override", rule="trap-b", session="s3"),
        _row(ts="2026-10-07T00:00:00Z", event="report", witness="aegis", check="no-such-check", tree="t", rule="trap-a",
             for_rule="trap-a", result="tp", key="credit:no-such-check:trap-a"),
        _row(event="exposure", rule="unknown-rule", session="s9", host="h", paths=[], rev=None),
    ])
    with open(ledger.ledger_path(ws), "a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps({"cell": "trap-b", "signal": "success", "source": "mcp", "timestamp": "2026-10-08T00:00:00Z",
                             "event_id": "v1-alias"}) + "\n")
    now = fitness._parse_ts("2026-10-20T00:00:00Z")
    got = {rid: (f.triggers, f.tp, f.fp, f.caught, f.leaked, f.contested, f.eligible_sessions, f.adjudicated_n)
           for rid, f in fitness.for_rules(ws, _served(ws), now=now).items()}
    assert got == {"trap-a": (5, 4.5, 0.0, 1, 0, 0, 0, 0), "trap-b": (2, 1.5, 1.0, 1, 0, 1, 0, 0)}
