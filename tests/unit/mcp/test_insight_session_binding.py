"""Insight joins across the MCP server and the host hook (R-evidence-36, R-evidence-37).

aegis-mcp names its session with a uuid minted per ``initialize``; the hook names it with the
host's own session id. Nothing links the two, so an insight meets an exposure on the host, a
time window and the rule revision, never on a session string.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Dict, List

import pytest

from aegis_core import credit
from aegis_core.insights import (
    JOIN_WINDOW_S,
    insights_path,
    record_hook_prompt,
    review_insights,
)
from aegis_core.rules import load_rules
from aegis_core.scan_compliance import activity_path, record as record_activity
from aegis_core.storage import append_jsonl
from aegis_core.telemetry_engine import ledger
import aegis_mcp.server as server

RULES = {
    "trap-r0": "Never pass shell=True to subprocess calls in src modules.",
    "trap-r1": "Never call eval or exec on dynamic strings in src modules.",
    "trap-r2": "Do not deserialize pickle payloads from untrusted sockets.",
    "trap-r3": "Never mutate global os.environ inside worker threads.",
}
PROMPTS = {
    "trap-r0": "No, do not pass shell=True to subprocess calls in src/app.py",
    "trap-r1": "Never call eval or exec on dynamic strings in src/app.py",
    "trap-r2": "Do not deserialize pickle payloads from untrusted sockets in src/app.py",
    "trap-r3": "Stop mutating global os.environ inside worker threads",
}


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("USERPROFILE", str(h))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "CLAUDE_PROJECT_DIR", "AEGIS_CLIENT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(credit, "_EXPOSED", {})
    monkeypatch.setattr(credit, "_PERSISTED", set())
    return h


def _repo(tmp_path: Path, rules: Dict[str, str]) -> Path:
    root = (tmp_path / "repo").resolve()
    traps = root / ".aegis" / "rules" / "traps"
    traps.mkdir(parents=True)
    (root / ".aegis" / ".gitignore").write_bytes(b"state/\n")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_bytes(b"x = 1\n")
    for rid, body in rules.items():
        (traps / f"{rid}.md").write_bytes(
            (f"---\nid: {rid}\ntype: trap\nenforcement: advisory\nhypothesis: Prevent {rid}.\n"
             f"target_paths:\n  - src/*.py\n---\n# {rid}\n\n{body}\n").encode("utf-8"))
    for args in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "init"]):
        subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=T", *args],
                       cwd=str(root), check=True, capture_output=True)
    (root / "src" / "app.py").write_bytes(b"x = 2\n")  # the hook takes its paths from the dirty set
    return root


def _rev(repo: Path, rid: str) -> str:
    return load_rules(repo).get(rid).digest[:16]


def _stamp(delta_s: float = 0.0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=delta_s)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hook(repo: Path, home: Path, text: str, session: str, host: str = "claude-code") -> Dict[str, Any]:
    row = record_hook_prompt(host, {"prompt": text, "session_id": session, "cwd": str(repo)}, workspace=repo, home=home)
    assert row.get("event") == "insight", text
    return row


def _expose(repo: Path, rid: str, *, host: str = "claude-code", session: str = "agent-1",
            rev: Any = "current", delta_s: float = 0.0) -> None:
    revs = {rid: _rev(repo, rid) if rev == "current" else rev}
    credit.record_exposure(repo, host, session, [rid], revs=revs, ts=_stamp(delta_s))


def _statuses(repo: Path, home: Path) -> Dict[str, str]:
    return {e["match"]["rule"]: e["match"]["status"] for e in review_insights(repo, home=home)["insights"]}


def _call(i: int, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    response = server.handle_request({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                                      "params": {"name": name, "arguments": arguments}})
    assert response["result"]["isError"] is False, response
    return json.loads(response["result"]["content"][0]["text"])


# ── R-evidence-36: host + window + rev ─────────────────────────────────────────

def test_a_server_scan_and_a_same_host_hook_insight_in_the_window_are_exposed_and_ignored(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
):
    repo = _repo(tmp_path, {"trap-r0": RULES["trap-r0"]})
    monkeypatch.setattr(server, "_canonical_workspace", str(repo))
    server.handle_request({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                           "params": {"clientInfo": {"name": "claude-code", "version": "1.0"}}})
    scan = _call(1, "aegis_scan", {"files": ["src/app.py"]})
    assert [r["name"] for r in scan["relevant_rules"]] == ["trap-r0"]
    exposure, = [r for r in credit.read_rows(repo) if r["event"] == "exposure"]
    assert exposure["rev"] == _rev(repo, "trap-r0")
    assert exposure["session"] != "host-session-1"  # the server's uuid, not the host's id

    _hook(repo, home, PROMPTS["trap-r0"], "host-session-1")
    credit._EXPOSED.clear()  # review runs in another process: only the persisted row joins
    assert _statuses(repo, home) == {"trap-r0": "exposed_and_ignored"}


@pytest.mark.parametrize("case", ["other-host", "31-min-before", "31-min-after", "other-rev"])
def test_an_exposure_that_misses_the_join_is_not_exposed(tmp_path: Path, home: Path, case: str):
    repo = _repo(tmp_path, {"trap-r0": RULES["trap-r0"]})
    if case == "other-host":
        _expose(repo, "trap-r0", host="codex-cli")
    elif case == "other-rev":
        _expose(repo, "trap-r0", rev="0123456789abcdef")
    else:
        _expose(repo, "trap-r0", delta_s=(-1 if case.endswith("before") else 1) * (JOIN_WINDOW_S + 60))
    _hook(repo, home, PROMPTS["trap-r0"], "host-session-1")
    assert _statuses(repo, home) == {"trap-r0": "not_exposed"}


@pytest.mark.parametrize("rev", ["current", None], ids=["rev", "legacy-none"])
def test_an_exposure_29_minutes_away_with_the_rule_rev_or_none_matches(tmp_path: Path, home: Path, rev: Any):
    repo = _repo(tmp_path, {"trap-r0": RULES["trap-r0"]})
    _expose(repo, "trap-r0", rev=rev, delta_s=-(JOIN_WINDOW_S - 60))
    _hook(repo, home, PROMPTS["trap-r0"], "host-session-1")
    assert _statuses(repo, home) == {"trap-r0": "exposed_and_ignored"}


def test_an_exposure_this_process_did_not_persist_never_counts(tmp_path: Path, home: Path):
    repo = _repo(tmp_path, {"trap-r0": RULES["trap-r0"]})
    credit.record_exposure(repo, "claude-code", "agent-1", ["trap-r0"], revs={"trap-r0": _rev(repo, "trap-r0")},
                           persist=False)
    _hook(repo, home, PROMPTS["trap-r0"], "host-session-1")
    assert _statuses(repo, home) == {"trap-r0": "not_exposed"}


def test_an_agent_outcome_report_and_a_scan_row_are_not_an_exposure(tmp_path: Path, home: Path):
    repo = _repo(tmp_path, {"trap-r0": RULES["trap-r0"]})
    record_activity(repo, "scan", host="claude-code", session="host-session-1", files=["src/app.py"])
    ledger.append(repo, [{"rule": "trap-r0", "outcome": "trigger", "source": "mcp", "host": "claude-code",
                          "session": "host-session-1", "meta": {"rev": _rev(repo, "trap-r0"), "paths": ["src/app.py"]}}])
    _hook(repo, home, PROMPTS["trap-r0"], "host-session-1")
    assert _statuses(repo, home) == {"trap-r0": "not_exposed"}


def test_a_cli_insight_never_joins_an_agent_hosts_exposure(tmp_path: Path, home: Path):
    from aegis_core.insights import add_insight

    repo = _repo(tmp_path, {"trap-r0": RULES["trap-r0"]})
    _expose(repo, "trap-r0")
    add_insight(repo, PROMPTS["trap-r0"], paths=["src/app.py"], home=home)
    assert _statuses(repo, home) == {"trap-r0": "not_exposed"}


def _scale_fixture(tmp_path: Path, home: Path) -> Path:
    repo = _repo(tmp_path, RULES)
    for i in range(30):
        record_activity(repo, "scan", host="claude-code", session=f"s{i % 4}" if i < 4 else f"filler-{i}",
                        files=["src/app.py"])
    ledger.append(repo, [{"rule": f"trap-r{i % 4}", "outcome": "trigger", "source": "mcp", "host": "claude-code",
                          "session": f"s{i % 4}", "meta": {"paths": ["src/app.py"]}} for i in range(40)])
    _expose(repo, "trap-r0", session="s0")
    for i, rid in enumerate(RULES):
        _hook(repo, home, PROMPTS[rid], f"s{i}")
    return repo


EXPECTED = {"trap-r0": "exposed_and_ignored", "trap-r1": "not_exposed", "trap-r2": "not_exposed",
            "trap-r3": "not_exposed"}


def test_a_review_opens_the_ledger_at_most_twice_and_reads_no_activity_log_more_than_once(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
):
    repo = _scale_fixture(tmp_path, home)
    watched = {"ledger": os.path.normcase(str(ledger.ledger_path(repo))),
               "activity": os.path.normcase(str(activity_path(repo)))}
    opens: List[str] = []
    real_open = os.open

    def spy(path: Any, *args: Any, **kwargs: Any) -> int:
        name = os.path.normcase(os.fspath(path))
        opens.extend(k for k, v in watched.items() if v == name)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", spy)
    assert _statuses(repo, home) == EXPECTED
    assert 1 <= opens.count("ledger") <= 2  # the exposure index is read, once
    assert opens.count("activity") <= 1


def test_a_torn_ledger_line_leaves_the_statuses_unchanged(tmp_path: Path, home: Path):
    repo = _scale_fixture(tmp_path, home)
    with open(ledger.ledger_path(repo), "ab") as fh:
        fh.write(b'{"v": 2, "event": "exposure", "rule": "trap-r1", "host": "claude-code", "ts": "')
    assert _statuses(repo, home) == EXPECTED


def test_record_exposure_stores_each_rules_own_rev(tmp_path: Path, home: Path):
    repo = _repo(tmp_path, {"trap-r0": RULES["trap-r0"], "trap-r1": RULES["trap-r1"]})
    rows = credit.record_exposure(repo, "claude-code", "agent-1", ["trap-r0", "trap-r1"],
                                  revs={"trap-r0": "aaaaaaaaaaaaaaaa"}, rev="bbbbbbbbbbbbbbbb")
    assert {r["rule"]: r["rev"] for r in rows} == {"trap-r0": "aaaaaaaaaaaaaaaa", "trap-r1": "bbbbbbbbbbbbbbbb"}


def test_an_unreadable_ledger_site_still_records_the_exposure_in_memory_with_one_call(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
):
    from aegis_core import storage
    from aegis_mcp.handlers.core import handle_scan

    repo = _repo(tmp_path, {"trap-r0": RULES["trap-r0"]})
    calls: List[Dict[str, Any]] = []
    real = credit.record_exposure

    def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(kwargs)
        return real(*args, **kwargs)

    def broken(*_a: Any, **_k: Any) -> Any:
        raise OSError("no ledger site")

    monkeypatch.setattr(credit, "record_exposure", spy)
    monkeypatch.setattr(storage, "ledger_site", broken)
    res = handle_scan({"workspace": str(repo), "files": ["src/app.py"], "_session": "s-1", "_host": "codex-cli",
                       "_binding": "mcp_roots"})
    assert res.get("status") != "FAIL"
    assert [c["persist"] for c in calls] == [False]
    assert calls[0]["revs"] == {"trap-r0": _rev(repo, "trap-r0")}
    assert "aegis-mcp: exposure record not written: no ledger site" in capsys.readouterr().err
    assert credit.witnessed_exposed_rules(repo, "codex-cli", "s-1") == {"trap-r0"}



# ── R-evidence-37: a capture annotates the hook row it corroborates, never counts ──────

HOOK_PROMPT = "No, stop rewriting the parser module without running its tests again!"
QUOTE = "stop rewriting the parser module"


def _rows(repo: Path, home: Path) -> List[Dict[str, Any]]:
    return [json.loads(line) for line in insights_path(repo, home=home).read_bytes().splitlines() if line.strip()]


def _capture(repo: Path, home: Path, quote: str, session: str = "agent-uuid-1", host: str = "claude-code"):
    from aegis_core.insights import capture_suggestion

    return capture_suggestion(repo, quote, paths=["src/app.py"], host=host, session=session, home=home)


def _counted(review: Dict[str, Any]) -> List[Dict[str, Any]]:
    # One entry per counted insight (4.4.0 lists insights, not clusters).
    return [{"count": 1, "corroborated": e["corroborated"]} for e in review["insights"]]


def test_rows_carry_their_source(tmp_path: Path, home: Path):
    from aegis_core.insights import add_insight

    repo = _repo(tmp_path, {})
    _hook(repo, home, HOOK_PROMPT, "host-session-1")
    add_insight(repo, "Never skip the parser tests in src/app.py", paths=["src/app.py"], home=home)
    _capture(repo, home, "prefer small parser functions")
    assert [r.get("source") for r in _rows(repo, home) if r["event"] == "insight"] == ["hook", "cli", "mcp"]


def test_a_corroborated_capture_stays_a_suggestion_and_the_correction_counts_once(tmp_path: Path, home: Path):
    repo = _repo(tmp_path, {})
    hook = _hook(repo, home, HOOK_PROMPT, "host-session-1")
    cap = _capture(repo, home, QUOTE)
    assert (cap["level"], cap["corroborated_by"], cap["source"]) == ("suggestion", hook["id"], "mcp")
    assert "confirmed_by" not in cap
    review = review_insights(repo, home=home)
    assert _counted(review) == [{"count": 1, "corroborated": [cap["id"]]}]
    assert review["suggestions"] == []


def test_four_chained_captures_still_count_once(tmp_path: Path, home: Path):
    repo = _repo(tmp_path, {})
    _hook(repo, home, HOOK_PROMPT, "host-session-1")
    quotes = [QUOTE, "rewriting the parser module", "the parser module without", "parser modul"]  # 12 chars
    caps = [_capture(repo, home, q, session=f"agent-{i}") for i, q in enumerate(quotes)]
    assert {c["level"] for c in caps} == {"suggestion"}
    assert _counted(review_insights(repo, home=home)) == [{"count": 1, "corroborated": [c["id"] for c in caps]}]


def test_a_capture_made_before_its_hook_prompt_counts_nothing_and_is_annotated_later(tmp_path: Path, home: Path):
    repo = _repo(tmp_path, {})
    cap = _capture(repo, home, QUOTE)
    assert cap["level"] == "suggestion" and "corroborated_by" not in cap
    before = review_insights(repo, home=home)
    assert before["insights"] == [] and [s["id"] for s in before["suggestions"]] == [cap["id"]]
    _hook(repo, home, HOOK_PROMPT, "host-session-1")
    assert _counted(review_insights(repo, home=home)) == [{"count": 1, "corroborated": [cap["id"]]}]


@pytest.mark.parametrize("case", ["11-chars", "other-host", "31-min-ago"])
def test_a_capture_outside_the_join_is_never_corroborated(tmp_path: Path, home: Path, case: str):
    repo = _repo(tmp_path, {})
    if case == "31-min-ago":
        append_jsonl(insights_path(repo, home=home), [{
            "v": 1, "ts": _stamp(-(JOIN_WINDOW_S + 60)), "event": "insight", "id": "ins-0000000000aa",
            "level": "W2", "text": HOOK_PROMPT.lower(), "paths": ["src/app.py"], "psrc": "dirty",
            "host": "claude-code", "source": "hook"}])
    else:
        _hook(repo, home, HOOK_PROMPT, "host-session-1")
    quote = "parser modu" if case == "11-chars" else QUOTE
    cap = _capture(repo, home, quote, host="codex-cli" if case == "other-host" else "claude-code")
    assert cap["level"] == "suggestion" and "corroborated_by" not in cap
    review = review_insights(repo, home=home)
    assert len(review["insights"]) == 1
    assert review["insights"][0]["corroborated"] == []
    assert [s["id"] for s in review["suggestions"]] == [cap["id"]]


def test_a_4_3_upgraded_w2_row_is_read_as_a_suggestion_and_never_counted(tmp_path: Path, home: Path):
    repo = _repo(tmp_path, {})
    hook = _hook(repo, home, HOOK_PROMPT, "host-session-1")
    legacy = {"v": 1, "ts": _stamp(), "event": "insight", "id": "ins-0000000000bb", "level": "W2",
              "text": QUOTE, "paths": ["src/app.py"], "psrc": "explicit", "host": "claude-code",
              "hs": "f" * 32, "confirmed_by": hook["id"]}
    append_jsonl(insights_path(repo, home=home), [legacy])
    review = review_insights(repo, home=home)
    assert _counted(review) == [{"count": 1, "corroborated": [legacy["id"]]}]
    assert review["insights"][0]["id"] == hook["id"]


def test_a_server_capture_with_its_own_session_is_corroborated_by_the_hosts_hook_prompt(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
):
    repo = _repo(tmp_path, {})
    monkeypatch.setattr(server, "_canonical_workspace", str(repo))
    server.handle_request({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                           "params": {"clientInfo": {"name": "claude-code", "version": "1.0"}}})
    hook = _hook(repo, home, HOOK_PROMPT, "host-session-1")
    res = _call(1, "aegis_capture_insight", {"quote": QUOTE, "paths": ["src/app.py"]})
    assert set(res) == {"status", "id", "level", "text", "paths", "psrc"}
    assert res["level"] == "suggestion"
    stored, = [r for r in _rows(repo, home) if r.get("id") == res["id"]]
    assert (stored["level"], stored["corroborated_by"], stored["source"]) == ("suggestion", hook["id"], "mcp")
