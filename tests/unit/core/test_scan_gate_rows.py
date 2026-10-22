"""The scan rows the scan-before-edit hook reads (v4.1 spec §2 "Behaviour" 1).

``scan_compliance.scan_covers(workspace, paths, window_s, now)``: True when one ``scan``
row of ``.aegis/state/activity.jsonl``, from any host or session (the ``aegis scan`` CLI's
host ``cli`` included), names every path and was written within the window. It keys on
workspace and exact workspace-relative path, never on a session id. ``report()`` (status
--compliance) does not count the CLI's rows: they carry no host session.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path

import pytest

from aegis_core import scan_compliance
from aegis_core.scan_compliance import CLI_HOST, scan_covers

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
WINDOW = 3600


def _ts(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _row(files, *, ago=0, event="scan", host="claude-code", session="s-1", **extra):
    return {"v": 1, "ts": _ts(NOW - timedelta(seconds=ago)), "event": event, "host": host,
            "session": session, "files": files, **extra}


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    (root / ".aegis" / "state").mkdir(parents=True)
    return root


def _write(ws: Path, *rows) -> Path:
    path = ws / ".aegis" / "state" / "activity.jsonl"
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write((row if isinstance(row, str) else json.dumps(row)) + "\n")
    return path


def test_a_row_naming_every_path_within_the_window_covers_them(ws: Path):
    _write(ws, _row(["src/a.py", "src/b.py", "README.md"], ago=WINDOW))
    assert scan_covers(ws, ["src/a.py", "src/b.py"], WINDOW, NOW)
    assert scan_covers(ws, ["src/a.py"], WINDOW, NOW)


def test_a_row_older_than_the_window_does_not(ws: Path):
    _write(ws, _row(["src/a.py"], ago=WINDOW + 1))
    assert not scan_covers(ws, ["src/a.py"], WINDOW, NOW)
    assert scan_covers(ws, ["src/a.py"], WINDOW + 1, NOW)


def test_one_row_must_name_every_path(ws: Path):
    """Coverage is per row: separate scans of a and b do not cover an edit of both."""
    _write(ws, _row(["src/a.py"]), _row(["src/b.py"]))
    assert not scan_covers(ws, ["src/a.py", "src/b.py"], WINDOW, NOW)
    assert scan_covers(ws, ["src/b.py"], WINDOW, NOW)


def test_paths_match_exactly_never_as_a_directory_or_by_case(ws: Path):
    _write(ws, _row(["src", "Docs/x.md"]))
    assert not scan_covers(ws, ["src/a.py"], WINDOW, NOW)
    assert not scan_covers(ws, ["docs/x.md"], WINDOW, NOW)


def test_paths_are_compared_in_posix_spelling(ws: Path):
    _write(ws, _row(["src/pkg/a.py"]))
    assert scan_covers(ws, [os.path.join("src", "pkg", "a.py")], WINDOW, NOW)


@pytest.mark.parametrize("host,session", [("codex-cli", "other"), (CLI_HOST, "c-1"), ("antigravity", "x")])
def test_any_host_or_session_counts(ws: Path, host, session):
    assert CLI_HOST == "cli"
    _write(ws, _row(["src/a.py"], host=host, session=session))
    assert scan_covers(ws, ["src/a.py"], WINDOW, NOW)


def test_edit_rows_and_unusable_rows_never_cover(ws: Path):
    _write(
        ws,
        _row(["src/a.py"], event="edit"),
        {**_row(["src/a.py"]), "v": 2},
        {**_row(["src/a.py"]), "ts": "yesterday"},
        {**_row(["src/a.py"]), "session": ""},
        {**_row(["src/a.py"]), "files": "src/a.py"},
        "not json",
        "[1, 2]",
    )
    assert not scan_covers(ws, ["src/a.py"], WINDOW, NOW)


def test_a_row_far_in_the_future_does_not_cover(ws: Path):
    """A clock up to five minutes ahead is tolerated; a forged far-future row is not."""
    _write(ws, _row(["src/a.py"], ago=-300))
    assert scan_covers(ws, ["src/a.py"], WINDOW, NOW)
    _write(ws, _row(["src/a.py"], ago=-301))
    assert not scan_covers(ws, ["src/a.py"], WINDOW, NOW)


def test_no_activity_log_covers_nothing(ws: Path, tmp_path: Path):
    assert not scan_covers(ws, ["src/a.py"], WINDOW, NOW)
    assert not scan_covers(tmp_path / "missing", ["src/a.py"], WINDOW, NOW)


def test_nothing_to_cover_is_covered(ws: Path):
    assert scan_covers(ws, [], WINDOW, NOW)


def test_a_torn_last_line_is_skipped(ws: Path):
    path = _write(ws, _row(["src/a.py"]))
    with open(path, "a", encoding="utf-8") as fh:
        fh.write('{"v": 1, "ts": "2026')
    assert scan_covers(ws, ["src/a.py"], WINDOW, NOW)


def test_a_symlinked_activity_log_is_not_read(ws: Path, tmp_path: Path):
    from tests.conftest import symlink_or_skip

    outside = tmp_path / "outside.jsonl"
    outside.write_text(json.dumps(_row(["src/a.py"])) + "\n", encoding="utf-8")
    symlink_or_skip(outside, ws / ".aegis" / "state" / "activity.jsonl")
    assert not scan_covers(ws, ["src/a.py"], WINDOW, NOW)


def test_only_the_tail_of_a_large_log_is_read(ws: Path, monkeypatch):
    """The hook runs on every edit and the log only grows: it reads the last
    GATE_TAIL_BYTES, which hold every row of any window in practice."""
    monkeypatch.setattr(scan_compliance, "GATE_TAIL_BYTES", 2048)
    old = _row(["src/old.py"], ago=10)
    filler = [_row([f"src/f{i}.py"], ago=5) for i in range(40)]
    _write(ws, old, *filler, _row(["src/a.py"], ago=1))
    assert (ws / ".aegis" / "state" / "activity.jsonl").stat().st_size > 2048
    assert scan_covers(ws, ["src/a.py"], WINDOW, NOW)
    assert scan_covers(ws, ["src/f39.py"], WINDOW, NOW)
    assert not scan_covers(ws, ["src/old.py"], WINDOW, NOW)


@pytest.mark.parametrize("ensure_ascii", [True, False])
def test_a_non_ascii_path_is_covered_however_the_row_spells_it(ws: Path, ensure_ascii):
    path = ws / ".aegis" / "state" / "activity.jsonl"
    path.write_text(json.dumps(_row(["src/é ü.py"]), ensure_ascii=ensure_ascii) + "\n", encoding="utf-8")
    assert scan_covers(ws, ["src/é ü.py"], WINDOW, NOW)
    assert not scan_covers(ws, ["src/e u.py"], WINDOW, NOW)


def test_the_real_writer_rows_are_covered(ws: Path, monkeypatch):
    monkeypatch.setattr(scan_compliance, "utc_now", lambda: NOW - timedelta(seconds=5))
    scan_compliance.record(ws, "scan", host="cli", session="c", files=["src/ü.py", 'src/q"uote.py'])
    assert scan_covers(ws, ["src/ü.py", 'src/q"uote.py'], WINDOW, NOW)


def _big_log(ws: Path, rows: int, covering_ago: int, others_ago: int) -> Path:
    """``rows`` scans of other files after one scan of src/a.py, in the compact form the
    writer uses (about 4 MiB for 20,000 rows)."""
    path = ws / ".aegis" / "state" / "activity.jsonl"
    compact = {"separators": (",", ":")}
    lines = [json.dumps(_row(["src/a.py"], ago=covering_ago), **compact)]
    for i in range(rows):
        lines.append(json.dumps(_row([f"src/pkg{i % 97}/module_{i}.py", f"tests/test_{i}.py"],
                                     ago=others_ago, session=f"s-{i % 50}"), **compact))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _best_of(times: int, fn) -> float:
    import time

    best = float("inf")
    for _ in range(times):
        started = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.timing
@pytest.mark.parametrize("others_ago", [10, WINDOW * 3])
def test_a_full_tail_is_judged_fast(ws: Path, others_ago):
    """The hook runs on every edit and the log is never rotated: a 4 MiB tail, busy or
    old, must cost far less than the hook's 300 ms budget (Python start is ~100 ms)."""
    path = _big_log(ws, 27000, covering_ago=60, others_ago=others_ago)
    assert path.stat().st_size > 3.5 * 1024 * 1024
    if others_ago > WINDOW:  # appended in time order: the recent scan comes last
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(_row(["src/a.py"], ago=60)) + "\n")
    assert scan_covers(ws, ["src/a.py"], WINDOW, NOW)
    assert not scan_covers(ws, ["src/missing.py"], WINDOW, NOW)
    elapsed = _best_of(3, lambda: scan_covers(ws, ["src/missing.py"], WINDOW, NOW))
    assert elapsed < 0.1, f"scan_covers took {elapsed * 1000:.0f} ms on a full tail"


def test_a_covering_row_deep_in_a_busy_tail_is_found(ws: Path):
    _big_log(ws, 27000, covering_ago=1800, others_ago=10)
    assert scan_covers(ws, ["src/a.py"], WINDOW, NOW)
    assert scan_covers(ws, ["src/pkg3/module_26484.py", "tests/test_26484.py"], WINDOW, NOW)


def test_the_search_from_the_end_stops_at_a_row_older_than_the_window(ws: Path):
    """Rows are appended in time order, so the first row naming the path that is older
    than the window (less FUTURE_SKEW_SECONDS of slack for reordered appends) ends the
    search: a row written before it is outside the window too, in an ordered log."""
    skew = scan_compliance.FUTURE_SKEW_SECONDS
    _write(ws, _row(["src/a.py"], ago=10), _row(["src/a.py", "src/b.py"], ago=WINDOW + skew + 1), _row(["src/c.py"], ago=5))
    assert not scan_covers(ws, ["src/a.py"], WINDOW, NOW)  # behind an old row: never reached
    assert scan_covers(ws, ["src/c.py"], WINDOW, NOW)
    _write(ws, _row(["src/a.py"], ago=10), _row(["src/a.py", "src/b.py"], ago=WINDOW + skew), _row(["src/c.py"], ago=5))
    assert scan_covers(ws, ["src/a.py"], WINDOW, NOW)  # within the slack: the search goes on
    _write(ws, _row(["src/a.py"], ago=10), _row(["src/b.py"], ago=WINDOW * 2), _row(["src/c.py"], ago=5))
    assert scan_covers(ws, ["src/a.py"], WINDOW, NOW)  # an old row about other files is skipped


def test_a_path_named_outside_the_files_of_a_row_is_not_coverage(ws: Path):
    _write(ws, _row(["src/x.py"], session="src/a.py"), _row(["src/x.py"], note=["src/a.py"]))
    assert not scan_covers(ws, ["src/a.py"], WINDOW, NOW)


def test_every_wanted_path_is_checked_whichever_is_searched_for(ws: Path):
    _write(ws, _row(["src/a.py"]), _row(["src/b.py"]), _row(["src/z.py"]))
    for paths in (["src/a.py", "src/z.py"], ["src/z.py", "src/a.py"], ["src/b.py", "src/a.py"]):
        assert not scan_covers(ws, paths, WINDOW, NOW)
    _write(ws, _row(["src/a.py", "src/z.py"]), _row(["src/z.py"]))
    assert scan_covers(ws, ["src/z.py", "src/a.py"], WINDOW, NOW)


def test_scan_covers_reads_only(ws: Path):
    path = _write(ws, _row(["src/a.py"]))
    before = (path.read_bytes(), sorted(p.name for p in (ws / ".aegis" / "state").iterdir()))
    scan_covers(ws, ["src/a.py"], WINDOW, NOW)
    assert (path.read_bytes(), sorted(p.name for p in (ws / ".aegis" / "state").iterdir())) == before


# ── status --compliance leaves the CLI's rows out ────────────────────────────

def test_the_compliance_report_does_not_count_cli_scans(ws: Path):
    _write(
        ws,
        _row(["src/a.py"], host="claude-code", session="s-1", ago=100),
        _row(["src/a.py"], host="claude-code", session="s-1", event="edit", ago=50),
        _row(["src/b.py"], host=CLI_HOST, session="c-1", ago=80),
        _row(["src/b.py"], host=CLI_HOST, session="c-2", ago=10),
    )
    report = scan_compliance.report(ws, now=NOW)
    assert report["scope"]["hosts"] == ["claude-code"]
    assert report["scope"]["sessions"] == ["s-1"]
    assert [h["host"] for h in report["hosts"]] == ["claude-code"]
    assert report["activity"]["rows"] == 4
    assert any("aegis scan" in limit and "cli" in limit for limit in report["heuristic"]["limits"])


def test_a_cli_scan_never_makes_a_commit_ambiguous(tmp_path: Path):
    """A commit inside one host session's window is that session's edit even when an
    `aegis scan` ran around it: CLI rows open no session window."""
    import subprocess

    from tests.conftest import run

    root = tmp_path / "repo"
    (root / ".aegis" / "state").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "src").mkdir()
    (root / "src" / "a.py").write_text("x\n", encoding="utf-8")
    env = {"GIT_AUTHOR_DATE": "2026-10-16T11:58:00Z", "GIT_COMMITTER_DATE": "2026-10-16T11:58:00Z",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
    assert run(["git", "add", "src/a.py"], cwd=str(root), env=env).returncode == 0
    assert run(["git", "commit", "-q", "-m", "a"], cwd=str(root), env=env).returncode == 0
    _write(
        root,
        _row(["src/a.py"], host="claude-code", session="s-1", ago=300),
        _row(["src/a.py"], host=CLI_HOST, session="c-1", ago=150),
    )
    report = scan_compliance.report(root, now=NOW)
    (session,) = report["sessions"]
    assert report["git"]["status"] == "used" and report["git"]["ambiguous_edits"] == 0
    assert (session["session"], session["edits_observed"], session["scanned_before_edit"]) == ("s-1", 1, 1)
