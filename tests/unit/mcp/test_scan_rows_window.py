"""aegis_scan scan rows for the scan-before-edit hook (v4.1 spec §2 "Behaviour" 1,
prerequisites (a) and (c)).

(a) A rescan of the same files in the same aegis-mcp session writes a new row once the
    previous row is older than half of ``jit.scan_window_s``. Otherwise a long session
    (aegis-mcp outlives Claude ``/clear``) could never satisfy the hook again: the hook
    asks for a scan, and the scan would write nothing.
(c) A file that does not exist yet can be scanned, so creating it can be scanned first.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from aegis_core import scan_compliance
import aegis_mcp.server as server
from aegis_core.workspace.binding import Registry
from aegis_core.yaml_engine.serializer import dump_frontmatter


@pytest.fixture
def ws(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    root = tmp_path / "ws"
    rules = root / ".aegis" / "rules" / "traps"
    rules.mkdir(parents=True)
    fm = {"id": "trap-x", "type": "trap", "target_paths": ["src/*.py"], "hypothesis": "h", "prediction": "p"}
    (rules / "trap-x.md").write_text(dump_frontmatter(fm, body="Body\n"), encoding="utf-8")
    (root / "src").mkdir()
    (root / "src" / "a.py").write_text("a\n", encoding="utf-8")
    return root.resolve()


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock(monkeypatch):
    """The wall clock the activity rows are stamped with, moved by hand. aegis-mcp's
    re-record decision must read the same clock: the hook compares the rows' stamps."""
    moved = _Clock()
    monkeypatch.setattr(scan_compliance, "utc_now", lambda: moved.now)
    return moved


def _initialize(client="claude-code"):
    server.handle_request({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                           "params": {"clientInfo": {"name": client, "version": "1"}}})
    return server._session_id


def _scan(files, req_id=1):
    response = server.handle_request({"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
                                      "params": {"name": "aegis_scan", "arguments": {"files": files}}})
    return response["result"]["isError"], json.loads(response["result"]["content"][0]["text"])


def _rows(ws: Path) -> list:
    path = ws / ".aegis" / "state" / "activity.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _pin(monkeypatch, ws: Path) -> None:
    monkeypatch.setattr(server, "_canonical_workspace", str(ws))


# ── (a) re-record after half the window ──────────────────────────────────────

def test_a_rescan_writes_a_new_row_after_half_the_default_window(ws, monkeypatch, clock):
    _pin(monkeypatch, ws)
    session = _initialize()
    _scan(["src/a.py"])
    clock.advance(1799)
    _scan(["src/a.py"], 2)
    assert len(_rows(ws)) == 1
    clock.advance(1)
    _scan(["src/a.py"], 3)
    rows = _rows(ws)
    assert [(r["event"], r["session"], r["files"]) for r in rows] == [("scan", session, ["src/a.py"])] * 2
    clock.advance(10)
    _scan(["./src/a.py"], 4)
    assert len(_rows(ws)) == 2  # the new row restarts the half window


def test_a_rescan_after_a_suspend_writes_a_row_the_hook_counts(ws, monkeypatch, clock):
    """A laptop sleeps for hours: the wall clock jumps, a monotonic clock would not. The
    old row has left the window, so the scan the hook asks for must write a new one."""
    _pin(monkeypatch, ws)
    _initialize()
    _scan(["src/a.py"])
    clock.advance(3 * 3600)
    assert not scan_compliance.scan_covers(ws, ["src/a.py"], 3600, clock.now)
    _scan(["src/a.py"], 2)
    assert len(_rows(ws)) == 2
    assert scan_compliance.scan_covers(ws, ["src/a.py"], 3600, clock.now)


def test_a_wall_clock_set_back_writes_a_row_again(ws, monkeypatch, clock):
    """The previous row now lies in the future, where the hook does not count it."""
    _pin(monkeypatch, ws)
    _initialize()
    _scan(["src/a.py"])
    clock.advance(-2 * 3600)
    _scan(["src/a.py"], 2)
    assert len(_rows(ws)) == 2
    assert scan_compliance.scan_covers(ws, ["src/a.py"], 3600, clock.now)


def test_the_half_window_follows_jit_scan_window_s(ws, monkeypatch, clock):
    (ws / ".aegis" / "config.json").write_text(json.dumps({"jit": {"scan_window_s": 120}}), encoding="utf-8")
    _pin(monkeypatch, ws)
    _initialize()
    _scan(["src/a.py"])
    clock.advance(59)
    _scan(["src/a.py"], 2)
    assert len(_rows(ws)) == 1
    clock.advance(1)
    _scan(["src/a.py"], 3)
    assert len(_rows(ws)) == 2


def test_other_files_or_another_session_are_recorded_at_once(ws, monkeypatch, clock):
    _pin(monkeypatch, ws)
    first = _initialize()
    _scan(["src/a.py"])
    _scan(["src/a.py", "src/b.py"], 2)
    second = _initialize()
    _scan(["src/a.py"], 3)
    assert [(r["session"], r["files"]) for r in _rows(ws)] == [
        (first, ["src/a.py"]), (first, ["src/a.py", "src/b.py"]), (second, ["src/a.py"]),
    ]


def test_a_row_that_failed_to_write_is_retried_on_the_next_scan(ws, monkeypatch, clock, capsys):
    _pin(monkeypatch, ws)
    state = ws / ".aegis" / "state"
    state.mkdir(parents=True)
    (state / "activity.jsonl").mkdir()  # cannot be appended to
    _initialize()
    is_error, _ = _scan(["src/a.py"])
    assert not is_error and "scan event not recorded" in capsys.readouterr().err
    (state / "activity.jsonl").rmdir()
    _scan(["src/a.py"], 2)
    assert len(_rows(ws)) == 1


# ── a bounded map of recorded scans (R-evidence-53 e) ───────────────────────

@pytest.fixture
def small_map(monkeypatch):
    """The re-record map holds two keys: a third evicts the one recorded longest ago."""
    from aegis_mcp.handlers import core

    monkeypatch.setattr(core, "_MAX_RECORDED", 2)
    monkeypatch.setattr(core, "_RECORDED", {})
    return core


def test_a_forgotten_key_costs_one_row_never_the_scan(ws, monkeypatch, clock, small_map):
    _pin(monkeypatch, ws)
    _initialize()
    for i, name in enumerate(("src/a.py", "src/b.py", "src/c.py")):
        _scan([name], i)
    assert len(_rows(ws)) == 3 and len(small_map._RECORDED) == 2
    _scan(["src/c.py"], 4)
    _scan(["src/b.py"], 5)
    assert len(_rows(ws)) == 3
    is_error, payload = _scan(["src/a.py"], 6)
    assert not is_error and [r["name"] for r in payload["relevant_rules"]] == ["trap-x"]
    assert [r["files"] for r in _rows(ws)][-1] == ["src/a.py"] and len(_rows(ws)) == 4


def test_a_re_recorded_key_is_the_newest(ws, monkeypatch, clock, small_map):
    _pin(monkeypatch, ws)
    _initialize()
    _scan(["src/a.py"])
    clock.advance(600)
    _scan(["src/b.py"], 2)
    clock.advance(1200)
    _scan(["src/a.py"], 3)  # half the default window has passed: a is recorded again, newest
    _scan(["src/c.py"], 4)  # evicts b, not a
    assert len(_rows(ws)) == 4
    _scan(["src/a.py"], 5)
    assert len(_rows(ws)) == 4
    _scan(["src/b.py"], 6)  # live (1200 s old) but forgotten: one extra row
    assert len(_rows(ws)) == 5


# ── (c) a file that does not exist yet ───────────────────────────────────────

@pytest.mark.parametrize("name", ["src/new.py", "newdir/deeper/new.py"])
def test_a_pinned_session_scans_and_records_a_file_that_does_not_exist_yet(ws, monkeypatch, name):
    _pin(monkeypatch, ws)
    _initialize()
    is_error, payload = _scan([name])
    assert not is_error, payload
    assert [r["files"] for r in _rows(ws)] == [[name]]
    assert not (ws / name).exists()


def test_claude_project_dir_sessions_scan_a_new_file_relative_or_absolute(ws, monkeypatch):
    monkeypatch.setattr(server, "_claude_project_dir", str(ws))
    _initialize("claude-code")
    assert _scan(["src/new.py"])[0] is False
    assert _scan([str(ws / "src" / "other.py")], 2)[0] is False
    assert [(r["binding"], r["files"]) for r in _rows(ws)] == [
        ("claude_project_dir", ["src/new.py"]), ("claude_project_dir", ["src/other.py"]),
    ]


def test_a_server_started_in_the_workspace_scans_a_new_file(ws, monkeypatch):
    monkeypatch.setattr(server, "_server_cwd", str(ws / "src"))
    _initialize("codex-mcp-client")
    is_error, payload = _scan(["src/new.py"])
    assert not is_error, payload
    assert [(r["binding"], r["files"]) for r in _rows(ws)] == [("walk_up", ["src/new.py"])]


def test_a_registered_workspace_is_chosen_by_an_absolute_new_file(ws, monkeypatch, tmp_path):
    """A server started outside every repository (agy) binds through the registry; an
    absolute path selects it even before the file exists."""
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    monkeypatch.setattr(server, "_server_cwd", str(outside))
    monkeypatch.setattr(server, "_registry", lambda: Registry((ws,)))
    _initialize("antigravity")
    is_error, payload = _scan([str(ws / "src" / "new.py")])
    assert not is_error, payload
    assert [(r["binding"], r["files"]) for r in _rows(ws)] == [("registry", ["src/new.py"])]


def test_a_new_file_outside_the_workspace_is_still_refused(ws, monkeypatch):
    _pin(monkeypatch, ws)
    _initialize()
    is_error, payload = _scan(["../outside/new.py"])
    assert is_error and "path traversal blocked" in payload["error"]
    assert _rows(ws) == []
