"""A capture or a prompt parses only the insight rows it needs (R-structure-12).

The fixture buries the rows a point read looks for under 2,500 rows of other sessions
(about 1.8 MB, past any tail window), so a recency window would miss them.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from aegis_core import storage
from aegis_core.insights import (
    add_insight,
    capture_suggestion,
    insights_path,
    read_insight_rows,
    record_decision,
    record_hook_prompt,
)

RULE = (
    "---\nid: trap-scale\ntype: trap\nenforcement: advisory\nhypothesis: Scale.\n"
    "target_paths:\n  - src/*.py\n---\n# trap-scale\n\nNever parse the whole log.\n"
)
QUOTE = "stop rewriting the parser module"


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("USERPROFILE", str(h))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    return h


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = (tmp_path / "ws").resolve()
    (root / ".aegis" / "rules" / "traps").mkdir(parents=True)
    (root / ".aegis" / "rules" / "traps" / "trap-scale.md").write_text(RULE, encoding="utf-8")
    (root / ".aegis" / ".gitignore").write_text("state/\n", encoding="utf-8")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    for args in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "init"]):
        subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=T", *args],
                       cwd=str(root), check=True, capture_output=True)
    return root


def _prompt(ws: Path, home: Path, text: str, session: str) -> dict:
    return record_hook_prompt("claude-code", {"prompt": text, "session_id": session, "cwd": str(ws)}, home=home)


def _bury(ws: Path, home: Path, count: int = 2500) -> None:
    pad = "other session filler text " * 24
    rows = []
    for i in range(count):
        hs = f"{i:032x}"
        if i % 2:
            rows.append({"v": 1, "ts": "2026-10-20T00:00:00Z", "event": "insight", "id": f"ins-{i:012x}",
                         "level": "W2", "text": f"{QUOTE} {pad}", "paths": [], "psrc": "dirty",
                         "host": "claude-code", "hs": hs})
        else:
            rows.append({"v": 1, "ts": "2026-10-20T00:00:00Z", "event": "heartbeat", "host": "claude-code",
                         "hs": hs, "cue": False, "inv": "0" * 16, "note": pad})
    storage.append_jsonl(insights_path(ws, home=home), rows)
    assert insights_path(ws, home=home).stat().st_size > 1_500_000


@pytest.fixture
def json_parses(monkeypatch: pytest.MonkeyPatch) -> list:
    calls: list = []
    real = json.loads
    monkeypatch.setattr(json, "loads", lambda *a, **k: calls.append(1) or real(*a, **k))
    return calls


def test_a_buried_hook_prompt_still_corroborates_its_hosts_capture(ws: Path, home: Path):
    hook = _prompt(ws, home, f"No, {QUOTE} again!", "S1")
    assert hook["event"] == "insight"
    _bury(ws, home)
    corroborated = capture_suggestion(ws, QUOTE, host="claude-code", session="S2", home=home)
    assert (corroborated["level"], corroborated["corroborated_by"]) == ("suggestion", hook["id"])
    other = capture_suggestion(ws, QUOTE, host="codex-cli", session="S1", home=home)
    assert other["level"] == "suggestion" and "corroborated_by" not in other


def test_buried_heartbeat_and_inventory_rows_are_not_duplicated(ws: Path, home: Path):
    _prompt(ws, home, "Please run the tests.", "S1")
    _bury(ws, home)
    for _ in range(2):
        _prompt(ws, home, "Please run the tests.", "S1")
    rows = read_insight_rows(ws, home=home)
    assert len([r for r in rows if r.get("event") == "inventory"]) == 1
    real_inv = next(r["inv"] for r in rows if r.get("event") == "inventory")
    assert len([r for r in rows if r.get("event") == "heartbeat" and r.get("inv") == real_inv]) == 3


@pytest.mark.parametrize("call", ["add_insight", "record_decision", "capture_suggestion", "hook_prompt"])
def test_a_write_parses_at_most_25_rows(ws: Path, home: Path, json_parses: list, call: str):
    _prompt(ws, home, "Please run the tests.", "S1")
    _bury(ws, home)
    json_parses.clear()
    if call == "add_insight":
        add_insight(ws, "Never parse the whole log in src/app.py", paths=["src/app.py"], home=home)
    elif call == "record_decision":
        record_decision(ws, cluster_id="cluster-x", decision="noise", insight_ids=["ins-1"], home=home)
    elif call == "capture_suggestion":
        capture_suggestion(ws, QUOTE, paths=["src/app.py"], host="claude-code", session="S1", home=home)
    else:
        _prompt(ws, home, "Please run the tests.", "S1")
    assert len(json_parses) <= 25


def test_read_jsonl_contains_filters_lines_before_parsing(tmp_path: Path):
    path = tmp_path / "rows.jsonl"
    path.write_bytes(b'{"k":"a1"}\n{"k":"b"}\nnot json a1\n{"k":"a1","n":2}\n{"k":"a1"')
    found = storage.read_jsonl(path, contains=b"a1")
    assert found.rows == [{"k": "a1"}, {"k": "a1", "n": 2}]
    assert found.line_numbers == [1, 4]
    assert found.skipped_lines == [3]
    assert found.torn_tail is True
    assert storage.read_jsonl(path, contains=b"zz") == storage.JsonlRead([], [], [])
    assert len(storage.read_jsonl(path).rows) == 3


def test_read_jsonl_contains_ignores_a_torn_tail_without_the_bytes(tmp_path: Path):
    path = tmp_path / "rows.jsonl"
    path.write_bytes(b'{"k":"a1"}\n{"k":"b"')
    found = storage.read_jsonl(path, contains=b"a1")
    assert (found.rows, found.skipped_lines, found.torn_tail) == ([{"k": "a1"}], [], False)
