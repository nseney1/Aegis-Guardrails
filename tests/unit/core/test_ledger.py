"""The v2 outcome ledger, .aegis/state/ledger.jsonl (build-sheet D13, defense #15, v4.3 §10.4)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

from aegis_core.telemetry_engine import ledger

REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))


def _path(ws: Path) -> Path:
    return ws / ".aegis" / "state" / "ledger.jsonl"


def _rows(ws: Path) -> list:
    path = _path(ws)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _event(rule="trap-x", outcome="tp", **extra):
    return {"rule": rule, "outcome": outcome, "source": "mcp", **extra}


def _child_env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return env


# ── Row shape ────────────────────────────────────────────────────────────────

def test_append_writes_a_v2_row_under_state(tmp_path: Path):
    row, = ledger.append(tmp_path, [_event(host="claude-code", session="s1", key="k1", meta={"notes": "n"})])
    assert row == _rows(tmp_path)[0]
    assert list(row)[:9] == ["v", "seq", "ts", "rule", "outcome", "source", "host", "session", "key"]
    assert (row["v"], row["seq"], row["rule"], row["outcome"], row["source"]) == (2, 1, "trap-x", "tp", "mcp")
    assert (row["host"], row["session"], row["key"], row["meta"]) == ("claude-code", "s1", "k1", {"notes": "n"})
    assert row["ts"].endswith("Z") and len(row["ts"]) == 20
    assert "weight" not in row  # 1 is the default and is not written
    assert not (tmp_path / ".aegis" / "evidence").exists()


def test_seq_increases_by_one_per_row_across_calls(tmp_path: Path):
    ledger.append(tmp_path, [_event("a"), _event("b")])
    ledger.append(tmp_path, [_event("c")])
    assert [r["seq"] for r in _rows(tmp_path)] == [1, 2, 3]


@pytest.mark.parametrize("event, message", [
    ({"rule": "", "outcome": "tp", "source": "mcp"}, "rule must be a non-empty string"),
    ({"rule": "r", "outcome": "success", "source": "mcp"}, "outcome must be one of ['tp', 'fp', 'trigger']"),
    ({"rule": "r", "outcome": "tp", "source": "agent"}, "source must be one of"),
    ({"rule": "r", "outcome": "tp", "source": "mcp", "weight": 1.5}, "weight must be between 0 and 1"),
    ({"rule": "r", "outcome": "tp", "source": "mcp", "weight": float("nan")}, "weight must be between 0 and 1"),
    ({"rule": "r", "outcome": "tp", "source": "mcp", "weight": True}, "weight must be a number"),
    ({"rule": "r", "outcome": "tp", "source": "mcp", "meta": {"x": object()}}, "meta must be JSON serializable"),
    ({"rule": "r", "outcome": "tp", "source": "mcp", "key": 7}, "key must be a string or None"),
])
def test_invalid_events_write_nothing(tmp_path: Path, event: dict, message: str):
    with pytest.raises(ValueError, match=message.replace("[", r"\[").replace("]", r"\]")):
        ledger.append(tmp_path, [_event("ok"), event])
    assert _rows(tmp_path) == []


# ── Idempotency: the identity is (key, rule) ─────────────────────────────────

def test_one_report_naming_n_rules_writes_n_rows(tmp_path: Path):
    rows = ledger.append(tmp_path, [_event(r, key="report-1") for r in ("a", "b", "c")])
    assert [r["rule"] for r in _rows(tmp_path)] == ["a", "b", "c"]
    assert [r["key"] for r in rows] == ["report-1"] * 3


def test_a_retry_writes_nothing_and_returns_the_stored_rows(tmp_path: Path):
    first = ledger.append(tmp_path, [_event(r, key="report-1", session="s1") for r in ("a", "b")])
    # a retry after a reconnect: same payload, new session
    again = ledger.append(tmp_path, [_event(r, key="report-1", session="s2") for r in ("a", "b")])
    assert again == first
    assert len(_rows(tmp_path)) == 2
    assert {r["session"] for r in _rows(tmp_path)} == {"s1"}


def test_a_key_reused_for_a_different_payload_conflicts_and_writes_nothing(tmp_path: Path):
    ledger.append(tmp_path, [_event("a", key="k")])
    with pytest.raises(ledger.EventConflictError, match="key 'k' is already recorded for rule 'a'"):
        ledger.append(tmp_path, [_event("b", key="k"), _event("a", outcome="fp", key="k")])
    assert [(r["rule"], r["outcome"]) for r in _rows(tmp_path)] == [("a", "tp")]


def test_a_duplicate_inside_one_call_is_written_once(tmp_path: Path):
    rows = ledger.append(tmp_path, [_event("a", key="k"), _event("a", key="k")])
    assert rows[0] is rows[1] or rows[0] == rows[1]
    assert len(_rows(tmp_path)) == 1


def test_rows_without_a_key_are_never_deduplicated(tmp_path: Path):
    ledger.append(tmp_path, [_event("a"), _event("a")])
    assert len(_rows(tmp_path)) == 2


def test_the_identity_index_is_rebuilt_from_disk_in_a_new_process(tmp_path: Path):
    ledger.append(tmp_path, [_event("a", key="cross-process")])
    code = textwrap.dedent("""
        import json, sys
        from aegis_core.telemetry_engine import ledger
        rows = ledger.append(sys.argv[1], [{"rule": "a", "outcome": "tp", "source": "mcp", "key": "cross-process"}])
        print(json.dumps(rows))
    """)
    proc = subprocess.run([sys.executable, "-c", code, str(tmp_path)], capture_output=True, text=True,
                          env=_child_env(), cwd=REPO_ROOT, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)[0]["seq"] == 1
    assert len(_rows(tmp_path)) == 1


def test_an_append_from_another_process_is_seen_by_a_cached_index(tmp_path: Path):
    ledger.append(tmp_path, [_event("a", key="k1")])  # warms this process's index
    code = textwrap.dedent("""
        import sys
        from aegis_core.telemetry_engine import ledger
        ledger.append(sys.argv[1], [{"rule": "b", "outcome": "fp", "source": "ci", "key": "k2"}])
    """)
    proc = subprocess.run([sys.executable, "-c", code, str(tmp_path)], capture_output=True, text=True,
                          env=_child_env(), cwd=REPO_ROOT, timeout=60)
    assert proc.returncode == 0, proc.stderr
    with pytest.raises(ledger.EventConflictError):
        ledger.append(tmp_path, [_event("b", outcome="tp", key="k2")])
    ledger.append(tmp_path, [_event("c")])
    assert [r["seq"] for r in _rows(tmp_path)] == [1, 2, 3]


# ── Concurrency and crash safety ─────────────────────────────────────────────

_APPEND_WORKER = textwrap.dedent("""
    import sys
    from aegis_core.telemetry_engine import ledger
    ws, worker = sys.argv[1], sys.argv[2]
    for i in range(40):
        ledger.append(ws, [{"rule": "trap-x", "outcome": "tp", "source": "ci", "key": f"{worker}-{i}"}])
""")


def test_three_processes_times_forty_appends_give_exactly_120_rows(tmp_path: Path):
    procs = [
        subprocess.Popen([sys.executable, "-c", _APPEND_WORKER, str(tmp_path), f"w{n}"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         env=_child_env(), cwd=REPO_ROOT)
        for n in range(3)
    ]
    for proc in procs:
        _out, err = proc.communicate(timeout=180)
        assert proc.returncode == 0, err
    rows = _rows(tmp_path)
    assert len(rows) == 120
    assert sorted(r["seq"] for r in rows) == list(range(1, 121))
    assert len({r["key"] for r in rows}) == 120
    assert ledger.aggregate(tmp_path, "trap-x")["triggers"] == 120


def test_append_terminates_a_torn_tail_and_never_rewrites_rows(tmp_path: Path):
    path = _path(tmp_path)
    path.parent.mkdir(parents=True)
    first = b'{"v":2,"seq":1,"ts":"2026-10-01T00:00:00Z","rule":"a","outcome":"tp","source":"ci"}\n'
    path.write_bytes(first + b'{"v":2,"seq":2,"rule":"a","outc')
    ledger.append(tmp_path, [_event("b")])
    data = path.read_bytes()
    assert data.startswith(first + b'{"v":2,"seq":2,"rule":"a","outc\n')
    view = ledger.read(tmp_path)
    assert [r["rule"] for r in view.rows] == ["a", "b"]
    assert view.skipped_lines == [2]
    assert view.rows[1]["seq"] == 2


def test_unreadable_lines_are_skipped_and_counted(tmp_path: Path):
    path = _path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_bytes(
        b'{"v":2,"seq":1,"ts":"t","rule":"a","outcome":"tp","source":"ci"}\n'
        b"garbage\n"
        b'{"v":2,"seq":2,"ts":"t","rule":"a","outcome":"maybe","source":"ci"}\n'
        b'\xff\xfe\n'
    )
    view = ledger.read(tmp_path)
    assert [r["rule"] for r in view.rows] == ["a"]
    assert view.skipped_lines == [2, 4]
    assert view.unusable_rows == 1


def test_a_v2_row_with_only_a_rule_or_only_an_outcome_is_unusable(tmp_path: Path):
    # Only a row with neither (an epoch) is bookkeeping; half an outcome is a broken row.
    path = _path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(
        '{"v":2,"seq":1,"ts":"t","rule":"a","source":"ci"}\n'
        '{"v":2,"seq":2,"ts":"t","outcome":"tp","source":"ci"}\n'
        '{"v":2,"seq":3,"ts":"t","migrated_from":[],"rows":0}\n',
        encoding="utf-8",
    )
    view = ledger.read(tmp_path)
    assert (view.rows, view.skipped_lines, view.unusable_rows) == ([], [], 2)


def test_every_credit_event_row_is_skipped_not_counted_unusable():
    """Given a v2 row of each credit.EVENTS kind (no outcome), When rows are normalized, Then each is
    skipped: the ledger's skip list cannot miss a kind credit writes."""
    from aegis_core import credit

    for kind in credit.EVENTS:
        assert ledger.normalize_rows([{"v": 2, "event": kind, "rule": "r"}]) == ([], 0), kind


@pytest.mark.parametrize("kind", ["check_confirm", "human_label", "claim", "transition"])
def test_a_row_of_a_kind_no_code_writes_is_one_unusable_row(kind):
    assert ledger.normalize_rows([{"v": 2, "event": kind, "rule": "r"}]) == ([], 1)


def _append_unterminated(ws: Path, row: dict) -> None:
    """A complete row whose newline never reached the disk (a crash cut the write there)."""
    with open(_path(ws), "ab") as fh:
        fh.write(json.dumps(row, separators=(",", ":")).encode("ascii"))


_UNTERMINATED = {"v": 2, "seq": 2, "ts": "2026-10-15T00:00:00Z", "rule": "trap-x", "outcome": "tp",
                 "source": "mcp", "host": None, "session": None, "key": "kk"}


def test_a_complete_last_row_without_a_newline_counts_for_a_warm_index(tmp_path: Path):
    ledger.append(tmp_path, [_event(key="k1")])  # this process now indexes up to the end of row 1
    _append_unterminated(tmp_path, _UNTERMINATED)

    returned = ledger.append(tmp_path, [_event(key="kk"), _event(key="k3")])
    assert [r["seq"] for r in returned] == [2, 3]  # kk is the stored row, not a second copy
    assert ledger.append(tmp_path, [_event(key="kk")])[0]["seq"] == 2

    assert [(r["key"], r["seq"]) for r in _rows(tmp_path)] == [("k1", 1), ("kk", 2), ("k3", 3)]
    assert ledger.aggregate(tmp_path, "trap-x")["tp"] == 3


def test_a_complete_last_row_without_a_newline_counts_in_a_new_process(tmp_path: Path):
    ledger.append(tmp_path, [_event(key="k1")])
    _append_unterminated(tmp_path, _UNTERMINATED)
    code = textwrap.dedent("""
        import json, sys
        from aegis_core.telemetry_engine import ledger
        events = [{"rule": "trap-x", "outcome": "tp", "source": "mcp", "key": k} for k in ("kk", "k3")]
        print(json.dumps([r["seq"] for r in ledger.append(sys.argv[1], events)]))
    """)
    proc = subprocess.run([sys.executable, "-c", code, str(tmp_path)], capture_output=True, text=True,
                          env=_child_env(), cwd=REPO_ROOT, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == [2, 3]
    assert [(r["key"], r["seq"]) for r in _rows(tmp_path)] == [("k1", 1), ("kk", 2), ("k3", 3)]


@pytest.mark.parametrize("how", ["rewritten in place", "deleted and recreated"])
def test_a_ledger_replaced_under_a_warm_index_is_read_again(tmp_path: Path, how: str):
    """A long-lived process (the MCP server) must not trust its index for a different file."""
    ledger.append(tmp_path, [_event(key=f"old-{i}") for i in range(3)])
    path = _path(tmp_path)
    replacement = "".join(
        json.dumps({"v": 2, "seq": i + 1, "ts": "2026-10-15T00:00:00Z", "rule": "trap-y", "outcome": "fp",
                    "source": "ci", "key": f"new-{i}"}) + "\n"
        for i in range(10)
    ).encode("ascii")
    assert len(replacement) > path.stat().st_size
    if how == "rewritten in place":  # same inode, at least as large as what was indexed
        with open(path, "r+b") as fh:
            fh.truncate(0)
            fh.write(replacement)
    else:  # the filesystem may hand the new file the old inode
        path.unlink()
        path.write_bytes(replacement)

    returned = ledger.append(tmp_path, [_event(key="old-1")])

    assert returned[0]["seq"] == 11
    rows = _rows(tmp_path)
    assert len(rows) == 11 and rows[-1]["key"] == "old-1"


# ── Aggregation (#15: every outcome row is a trigger) ────────────────────────

def test_aggregate_counts_every_outcome_row_as_a_trigger(tmp_path: Path):
    ledger.append(tmp_path, [
        _event("a", "tp"), _event("a", "tp", weight=0.5), _event("a", "fp"), _event("a", "trigger"),
        _event("b", "fp", weight=0.25),
    ])
    assert ledger.aggregate(tmp_path, "a") == {
        "triggers": 4, "tp": 1.5, "fp": 1, "last_ts": _rows(tmp_path)[0]["ts"],
    }
    totals = ledger.aggregate(tmp_path)
    assert sorted(totals) == ["a", "b"]
    assert (totals["b"]["triggers"], totals["b"]["tp"], totals["b"]["fp"]) == (1, 0, 0.25)


def test_aggregate_of_an_unknown_rule_is_zero(tmp_path: Path):
    assert ledger.aggregate(tmp_path, "nope") == {"triggers": 0, "tp": 0, "fp": 0, "last_ts": None}


def test_last_ts_is_the_latest_row_time(tmp_path: Path):
    path = _path(tmp_path)
    path.parent.mkdir(parents=True)
    rows = [
        {"v": 2, "seq": 1, "ts": "2026-10-02T00:00:00Z", "rule": "a", "outcome": "tp", "source": "ci"},
        {"v": 2, "seq": 2, "ts": "2026-10-05T00:00:00Z", "rule": "a", "outcome": "trigger", "source": "ci"},
        {"v": 2, "seq": 3, "ts": "2026-10-03T00:00:00Z", "rule": "a", "outcome": "fp", "source": "ci"},
    ]
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    assert ledger.aggregate(tmp_path, "a")["last_ts"] == "2026-10-05T00:00:00Z"


def test_epoch_rows_are_not_outcomes_and_seq_continues(tmp_path: Path):
    ledger.append(tmp_path, [_event("a")])
    epoch = ledger.append_epoch(tmp_path, {"migrated_from": ["evidence/signals.jsonl"], "rows": 0})
    ledger.append(tmp_path, [_event("a")])
    assert epoch["seq"] == 2 and "rule" not in epoch
    assert [r["seq"] for r in _rows(tmp_path)] == [1, 2, 3]
    view = ledger.read(tmp_path)
    assert (len(view.rows), view.unusable_rows) == (2, 0)
    assert ledger.aggregate(tmp_path, "a")["triggers"] == 2


def test_notes_with_surrogates_round_trip(tmp_path: Path):
    ledger.append(tmp_path, [_event("a", meta={"notes": "café \ud800"})])
    _path(tmp_path).read_bytes().decode("utf-8")
    assert ledger.read(tmp_path).rows[0]["meta"]["notes"] == "café \ud800"


# ── v1 rows are read in memory, never rewritten ──────────────────────────────

def _v1(cell, signal, ts, **extra):
    row = {"timestamp": ts, "rule_id": cell, "cell": cell, "signal": signal, "source": "session",
           "event_id": f"{cell}-{signal}-{ts}", "payload_digest": "d", "generation": 1}
    row.update(extra)
    return row


def test_v1_rows_are_converted_in_memory_without_rewriting_the_file(tmp_path: Path):
    path = _path(tmp_path)
    path.parent.mkdir(parents=True)
    rows = [
        # v3 `aegis check`: a trigger row and an outcome row per rule and run
        _v1("contract-x", "trigger", "2026-10-15T05:15:22Z", metadata={"credit_weight": 1.0, "target_files": ["a.py"]}),
        _v1("contract-x", "tp", "2026-10-15T05:15:22Z", metadata={"credit_weight": 0.3333333333333333, "passed": True}),
        _v1("contract-x", "trigger", "2026-10-15T06:00:00Z", metadata={"credit_weight": 1.0}),
        _v1("contract-x", "tp", "2026-10-15T06:00:00Z", metadata={"credit_weight": 1.0}),
        # v3 MCP report: an outcome row without a trigger row, cell only
        {"timestamp": "2026-10-15T07:00:00Z", "cell": "trap-y", "signal": "fp", "source": "mcp",
         "metadata": {"host": "claude", "session": "s9"}},
        # v3 MCP "partial": a trigger row alone
        {"timestamp": "2026-10-15T08:00:00Z", "cell": "trap-y", "signal": "trigger", "source": "mcp"},
        {"timestamp": "2026-10-15T09:00:00Z", "cell": "trap-z", "signal": "success", "source": "ci"},
        {"timestamp": "2026-10-15T09:00:00Z", "signal": "tp", "source": "ci"},  # no rule: unusable
    ]
    raw = "".join(json.dumps(r) + "\n" for r in rows).encode("utf-8")
    path.write_bytes(raw)

    totals = ledger.aggregate(tmp_path)
    assert totals["contract-x"] == {"triggers": 2, "tp": pytest.approx(4 / 3), "fp": 0, "last_ts": "2026-10-15T06:00:00Z"}
    assert totals["trap-y"] == {"triggers": 2, "tp": 0, "fp": 1, "last_ts": "2026-10-15T08:00:00Z"}
    assert totals["trap-z"]["tp"] == 1
    view = ledger.read(tmp_path)
    assert view.unusable_rows == 1
    mcp_row = next(r for r in view.rows if r["rule"] == "trap-y" and r["outcome"] == "fp")
    assert (mcp_row["host"], mcp_row["session"], mcp_row["from"]) == ("claude", "s9", "v1")

    ledger.append(tmp_path, [_event("contract-x")])
    assert path.read_bytes().startswith(raw)
    assert _rows(tmp_path)[-1]["seq"] == 1  # v1 rows carry no seq
