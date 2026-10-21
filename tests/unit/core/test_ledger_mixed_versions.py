"""ARCH-3: one ledger file written by v1, 4.3.3 and 4.4.0 writers stays readable in full.

The readers are strict-equal on ``v`` (``ledger.normalize_rows``, ``credit._read_ledger_events``), so a
version bump or a changed required field would hide 4.3.x rows. The 4.4.0 side is simulated by
additive keys until a wave adds a real one. ``_n1_accepts`` is a frozen model of what a 4.3.3
reader requires: every row the current public writers emit must satisfy it, so a later wave that
changes a row shape fails here.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping

import pytest

from aegis_core import checkrun, credit, sync
from aegis_core.storage import ledger_site, read_jsonl
from aegis_core.telemetry_engine import ledger
from tests import helpers_humangate as hg
from tests import helpers_verified as hv

TREE = "ab" * 20
COMMIT = "cd" * 20
EVENTS_433 = ("check", "claimed", "report", "ci", "void", "exposure", "detection", "adjudication", "override")
OUTCOMES_433 = ("tp", "fp", "trigger")


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "GIT_CONFIG_GLOBAL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


def _n1_accepts(row: Mapping[str, Any]) -> bool:
    """The 4.3.3 reader's contract for one ledger row (frozen; do not track the current code)."""
    if row.get("v") != 2:
        return False
    if "event" in row:
        return row["event"] in EVENTS_433
    if "epoch" in row and "rule" not in row and "outcome" not in row:
        return True
    if not isinstance(row.get("rule"), str) or not row["rule"] or row.get("outcome") not in OUTCOMES_433:
        return False
    weight = row.get("weight", 1)
    if isinstance(weight, bool):
        return False
    try:
        number = Decimal(str(weight))
    except (InvalidOperation, ValueError):
        return False
    return number.is_finite() and 0 <= number <= 10


def _v2(**fields: Any) -> Dict[str, Any]:
    return {"v": 2, "ts": "2026-10-01T00:00:00Z", **fields}


def _mixed_ledger(ws: Path) -> Path:
    rows: List[Dict[str, Any]] = [
        # (i) legacy v1, converted in memory
        {"cell": "trap-a", "signal": "success", "timestamp": "2026-01-01T00:00:00Z", "source": "ci", "event_id": "v1-1"},
        # (ii) v2 outcome row as 4.3.3 ledger.append writes it
        _v2(seq=1, rule="trap-a", outcome="tp", source="ci", host=None, session=None, key="k-tp"),
        # (iv) v2 outcome row with keys a 4.4.0 writer may add
        _v2(seq=2, rule="trap-a", outcome="fp", source="ci", host=None, session=None, key="k-fp",
            detected_at="2026-10-01T00:00:00Z", x_future={"a": 1}),
        # (iii) v2 credit event rows as 4.3.3 writes them
        _v2(event="check", witness="aegis", source="aegis check --record", tree=TREE, head=COMMIT, base=COMMIT,
            tree_algo="v1", cmd_digest="d", passed=True, exit=0, partial=False, gitlinks=[], id="c1"),
        _v2(event="report", witness="aegis", check="c1", tree=TREE, rule="trap-a", for_rule="trap-a", result="tp",
            source="mcp", session="s", host="claude-code", key="credit:c1:trap-a", report_key="claude-code/s/k"),
        _v2(event="ci", commit=COMMIT, workflow="validate.yml", ci_conclusion="success", run_id=10, ci_run_attempt=1),
        _v2(event="ci", commit=COMMIT, workflow="validate.yml", ci_conclusion="success", run_id=10, ci_run_attempt=2,
            replay={"tip": COMMIT}),
        # (v) a future row version: no 4.4.0 reader may count it
        {"v": 3, "ts": "2026-10-01T00:00:00Z", "rule": "trap-a", "outcome": "tp", "source": "ci", "key": "k-v3"},
    ]
    path = ledger_site(ws, create=True).path
    body = b"".join(json.dumps(r).encode("utf-8") + b"\n" for r in rows)
    path.write_bytes(body + b'{"v": 2, "rule": "trap-a", "outc')  # (vi) a torn final line
    return path


def test_compatibility_versions_are_pinned():
    assert ledger.LEDGER_VERSION == 2
    assert sync.DERIVED_VERSION == 1
    assert ledger.OUTCOMES == OUTCOMES_433
    assert set(EVENTS_433) <= set(credit.EVENTS)


def test_a_mixed_version_ledger_is_read_in_full(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    _mixed_ledger(ws)

    view = ledger.read(ws)
    assert sorted((r["rule"], r["outcome"], str(r.get("from"))) for r in view.rows) == [
        ("trap-a", "fp", "None"), ("trap-a", "tp", "None"), ("trap-a", "tp", "v1")]
    assert next(r for r in view.rows if r["outcome"] == "fp")["x_future"] == {"a": 1}
    totals = ledger.aggregate(ws)["trap-a"]
    assert (totals["triggers"], totals["tp"], totals["fp"]) == (3, 2, 1)
    assert view.unusable_rows == 1 and view.torn_tail is True and view.skipped_lines == []
    assert ledger.incomplete(view.health()) == "1 unusable row(s)"

    events = credit.read_rows(ws)
    assert [r["event"] for r in events] == ["check", "report", "ci", "ci"]
    assert all(r["v"] == 2 for r in events)
    assert events[-1]["replay"] == {"tip": COMMIT} and events[-1]["ci_run_attempt"] == 2


def test_the_frozen_n1_model_rejects_what_a_433_reader_cannot_use():
    assert not _n1_accepts({"v": 3, "rule": "r", "outcome": "tp"})
    assert not _n1_accepts({"v": 2, "rule": "r", "outcome": "maybe"})
    assert not _n1_accepts({"v": 2, "rule": "", "outcome": "tp"})
    assert not _n1_accepts({"v": 2, "rule": "r", "outcome": "tp", "weight": 11})
    assert not _n1_accepts({"v": 2, "event": "verdict"})
    assert _n1_accepts({"v": 2, "rule": "r", "outcome": "tp", "weight": 0.5, "extra": 1})


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
def test_every_row_the_current_writers_emit_is_readable_by_a_433_reader(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    root = repo.root
    repo.write("src/app.py", "def app():\n    return 2\n")
    hv.mcp_call("aegis_scan", root, session="s1", files=["src/app.py"])
    hv.mcp_call("aegis_report_outcome", root, session="s1", outcome="success", rules_used=["trap-sample"], idempotency_key="k0")
    assert checkrun.record(root, tests=True, base="main").status == "recorded"
    hv.mcp_call("aegis_report_outcome", root, session="s1", outcome="success", rules_used=["trap-sample"], idempotency_key="k1")
    commit = repo.commit("work")
    repo.git("branch", "-f", "main", commit)
    credit.confirm(root, client=hv.FakeCI([hv.ci_run(commit)]), workflow=hv.CI_WORKFLOW)
    check_id = hv.rows_of(root, "check")[0]["id"]
    credit.record_void(root, check_id, "test")
    credit.record_detection(root, "trap-sample", "src/app.py", "eval", disposition="caught", rev=commit)
    credit.record_adjudication(root, "trap-sample", "tp", ref="PR-1")
    credit.record_override(root, "trap-sample", "src/app.py", 1, "ok", rev=commit)
    ledger.append(root, [{"rule": "trap-sample", "outcome": "fp", "source": "ci", "key": "k-fp", "weight": 0.5}])
    ledger.append_epoch(root, {"note": "test"})

    rows = list(read_jsonl(ledger.ledger_path(root)).rows)
    kinds = {r.get("event") or ("epoch" if "epoch" in r else "outcome") for r in rows}
    assert {"exposure", "claimed", "check", "report", "ci", "void", "detection", "adjudication", "override",
            "outcome", "epoch"} <= kinds
    assert [r for r in rows if not _n1_accepts(r)] == []
    assert ledger.read(root).unusable_rows == 0
