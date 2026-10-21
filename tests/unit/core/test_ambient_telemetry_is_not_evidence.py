"""A local `aegis check` is a trigger, never a verdict (R-evidence-1, spec T1/section 1).

Given/When/Then:

- Given a no-eval gate and a 30-day trap, When `aegis check` runs 12 times failing and 25
  times passing, Then fitness has tp == fp == 0, every run is a trigger, nothing is
  suggested, `check_rule_fitness` reports nothing and the gate still exits 1.
- Given a ledger already holding native session tp/fp rows (no ``from``), When it is read,
  Then they are triggers; the same rows with ``from`` (what `aegis migrate` writes) and a
  ``source: "ci"`` row still count, and only the migrated tp resets session decay.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aegis_core import credit, sync
from aegis_core.fitness import for_rules
from aegis_core.lifecycle.promotion import suggest
from aegis_core.outcomes.telemetry import record_verification_telemetry
from aegis_core.rules import load_rules
from aegis_core.telemetry_engine import ledger
from aegis_core.verification.checkpoint_checks import check_rule_fitness

OLD = (datetime.now(timezone.utc) - timedelta(days=60)).strftime("%Y-%m-%d")


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


def _rule(ws: Path, folder: str, rid: str, rtype: str, extra: str = "") -> None:
    path = ws / ".aegis" / "rules" / folder / f"{rid}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    enforcement = "gate" if rtype in ("gate", "invariant") else "advisory"
    path.write_bytes(
        (f"---\nid: {rid}\ntype: {rtype}\nenforcement: {enforcement}\nhypothesis: h\ncreated: '{OLD}'\n"
         f"target_paths:\n  - 'src/*.py'\n{extra}---\n# {rid}\n\nBody of {rid}.\n").encode("utf-8")
    )


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    _rule(root, "gates", "gate-no-eval", "gate", "forbid_ast:\n  calls: [eval]\n")
    _rule(root, "traps", "trap-old", "trap")
    (root / "src").mkdir()
    return root


def _check(ws: Path, source: str) -> int:
    from aegis_cli.verify import run_verify

    (ws / "src" / "app.py").write_bytes(source.encode("utf-8"))
    return run_verify(argparse.Namespace(
        files=["src/app.py"], layer1_only=True, dry_run=False, repo_root=str(ws), workspace=str(ws),
        plan=None, plan_file=None, provider=None,
    ))


def test_local_check_runs_are_triggers_and_suggest_nothing(ws: Path) -> None:
    assert _check(ws, "def f(x):\n    return eval(x)\n") == 1
    assert _check(ws, "def f(x):\n    return int(x)\n") == 0
    # The rest of the runs through the same writer `aegis check` calls.
    for n in range(11):
        assert record_verification_telemetry(str(ws), ["src/app.py"], passed=False, source="session")
    for n in range(24):
        assert record_verification_telemetry(str(ws), ["src/app.py"], passed=True, source="session")

    rules = {r.id: r for r in load_rules(ws).served}
    fits = for_rules(ws, list(rules.values()))
    for rid in ("gate-no-eval", "trap-old"):
        assert (fits[rid].tp, fits[rid].fp, fits[rid].triggers) == (0, 0, 37)
        assert fits[rid].suggestion is None
        assert suggest(rules[rid], fits[rid]) is None
    assert all(e["suggestion"] is None for e in sync.build(ws)["rules"].values())
    assert check_rule_fitness(ws) == []
    assert all(r["outcome"] == "trigger" for r in ledger.read(ws).rows)
    # The gate still blocks: the trigger rows change no verdict.
    assert _check(ws, "def f(x):\n    return eval(x)\n") == 1


def _session_rows(rule: str, outcome: str, count: int, *, origin: object = None, prefix: str = "") -> list:
    rows = []
    for n in range(count):
        row = {"v": 2, "ts": "2026-10-01T00:00:00Z", "rule": rule, "outcome": outcome, "source": "session",
               "key": f"{prefix}{outcome}-{n}"}
        if origin is not None:
            row["from"] = origin
        rows.append(row)
    return rows


def test_native_session_verdicts_already_written_read_as_triggers(ws: Path) -> None:
    ledger.append_rows(ws, _session_rows("gate-no-eval", "fp", 36) + _session_rows("trap-old", "tp", 25))

    totals = ledger.aggregate(ws)
    assert (totals["gate-no-eval"]["fp"], totals["gate-no-eval"]["triggers"]) == (0, 36)
    assert (totals["trap-old"]["tp"], totals["trap-old"]["triggers"]) == (0, 25)
    assert check_rule_fitness(ws) == []
    assert all(e["suggestion"] is None for e in sync.build(ws)["rules"].values())
    raw = (ws / ".aegis" / "state" / "ledger.jsonl").read_bytes()
    assert raw.count(b'"outcome": "fp"') + raw.count(b'"outcome":"fp"') == 36  # the file is never rewritten


def test_migrated_and_ci_rows_keep_counting(ws: Path) -> None:
    origin = {"v": 1, "file": ".aegis/signals.jsonl", "line": 3}
    ledger.append_rows(ws, _session_rows("gate-no-eval", "fp", 36, origin=origin)
                       + _session_rows("trap-old", "tp", 25, origin=origin))
    ledger.append(ws, [{"rule": "trap-old", "outcome": "tp", "source": "ci", "key": "ci-1"}])

    totals = ledger.aggregate(ws)
    assert totals["gate-no-eval"]["fp"] == 36
    assert totals["trap-old"]["tp"] == 26
    assert [i["rule"] for i in check_rule_fitness(ws) if i.get("rule")] == ["gate-no-eval"]


def _eligible_after(ws: Path, reinforcing: dict) -> int:
    for s in range(4):
        credit.record_exposure(ws, "claude-code", f"s{s}", ["trap-old"], paths=["src/app.py"],
                               scope_basis="match", heartbeat=True)
    ledger.append_rows(ws, [reinforcing])
    rule = load_rules(ws).get("trap-old")
    return for_rules(ws, [rule])["trap-old"].eligible_sessions


def test_only_a_migrated_session_tp_resets_session_decay(ws: Path, tmp_path: Path) -> None:
    # The catch must post-date the exposures it clears: an older catch leaves newer sessions counting.
    later = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    native = {"v": 2, "ts": later, "rule": "trap-old", "outcome": "tp", "source": "session",
              "key": "native-tp"}
    assert _eligible_after(ws, native) == 4

    other = tmp_path / "other"
    _rule(other, "traps", "trap-old", "trap")
    assert _eligible_after(other, dict(native, key="migrated-tp", **{"from": {"v": 1, "file": "s", "line": 1}})) == 0
