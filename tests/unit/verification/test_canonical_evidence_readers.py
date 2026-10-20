"""Cross-reader contract tests: every reader takes rule totals from the one ledger."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aegis_core.yaml_engine.serializer import dump_frontmatter

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
ENZYMES = ROOT / "enzymes"
if str(ENZYMES) not in sys.path:
    sys.path.insert(0, str(ENZYMES))


def _ledger(root: Path) -> Path:
    return root / ".aegis" / "state" / "ledger.jsonl"


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")


def _signal(cell: str, signal: str, timestamp: str = "2026-01-01T00:00:00Z", weight=None) -> dict:
    record = {"cell": cell, "signal": signal, "timestamp": timestamp}
    if weight is not None:
        record["metadata"] = {"credit_weight": weight}
    return record


def _cell(path: Path, cell_id: str, cell_type: str = "trap", age_days: int = 45) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    created = (datetime.now(timezone.utc) - timedelta(days=age_days)).strftime("%Y-%m-%d")
    metadata = {
        "id": cell_id,
        "domain": "testing",
        "type": cell_type,
        "enforcement": "gate" if cell_type in ("gate", "invariant") else "advisory",
        "created": created,
        "expiry_days": 365,
        "expiry_sessions": 365,
    }
    path.write_text(dump_frontmatter(metadata, body=f"# {cell_id}\n"), encoding="utf-8")


def test_ledger_reader_reports_bad_lines_and_keeps_weights(tmp_path):
    from aegis_core.telemetry_engine import ledger

    path = _ledger(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(_signal("outcome-only", "tp", weight="0.25")) + "\n"
        + json.dumps(_signal("outcome-only", "fp", weight="0.5")) + "\n"
        + json.dumps(_signal("triggered", "trigger")) + "\n"
        + "{malformed}\n",
        encoding="utf-8",
    )
    legacy = tmp_path / ".aegis" / "evidence"
    _write_jsonl(legacy / "fitness.jsonl", [{"cell_id": "legacy", "triggered_at": "x"}])
    _write_jsonl(legacy / "signals.jsonl", [_signal("legacy", "tp")])

    totals = ledger.aggregate(tmp_path)
    # Every outcome row is also a trigger (#15).
    assert totals["outcome-only"] == {"triggers": 2, "tp": 0.25, "fp": 0.5, "last_ts": "2026-01-01T00:00:00Z"}
    assert totals["triggered"]["triggers"] == 1
    assert "legacy" not in totals  # v3 files are read only by `aegis migrate`
    assert ledger.read(tmp_path).skipped_lines == [4]


def test_status_uses_ledger_triggers(tmp_path, capsys):
    from aegis_cli.status import run_status

    # A workspace rule: status lists core rules only in the Aegis checkout they ship from.
    traps = tmp_path / ".aegis" / "rules" / "traps"
    traps.mkdir(parents=True)
    (traps / "canonical.md").write_text("---\nid: canonical\ntarget_paths: ['*.py']\n---\n# canonical\n",
                                        encoding="utf-8")
    _write_jsonl(_ledger(tmp_path), [
        _signal("canonical", "trigger", "2026-01-01T00:00:00Z"),
        _signal("canonical", "trigger", "2026-01-01T00:01:00Z"),
    ])
    _write_jsonl(tmp_path / ".aegis" / "evidence" / "signals.jsonl", [_signal("canonical", "trigger")] * 5)

    assert run_status(argparse.Namespace(_root=tmp_path)) == 0
    status_output = capsys.readouterr().out
    canonical_line = next(line for line in status_output.splitlines() if "canonical" in line)
    assert canonical_line.split()[1] == "2"


def test_lifecycle_uses_weighted_ledger_rows(tmp_path):
    from aegis_core.lifecycle.promotion import evaluate_promotions

    cells = tmp_path / ".aegis" / "rules" / "traps"
    _cell(cells / "canonical.md", "canonical")

    recent = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")  # no decay

    def rows(n):
        return [
            {"v": 2, "seq": i + 1, "ts": recent, "rule": "canonical", "outcome": "tp", "source": "ci", "weight": 0.85}
            for i in range(n)
        ]

    # 25 rows weigh 21.25 verdicts: fewer than the MIN_N (25) a transition needs (R-evidence-8).
    _write_jsonl(_ledger(tmp_path), rows(25))
    assert evaluate_promotions(str(tmp_path)) == []

    _write_jsonl(_ledger(tmp_path), rows(30))
    candidates = evaluate_promotions(str(tmp_path))
    assert [(c["rule_id"], c["tp"], c["triggers"]) for c in candidates] == [("canonical", 25.5, 30)]


def test_checkpoint_fails_closed_and_uses_weighted_outcomes(tmp_path):
    from aegis_core.verification.checkpoint_checks import check_rule_fitness

    path = _ledger(tmp_path)
    path.parent.mkdir(parents=True)
    # Counted at full weight the tps would make this 25 false positives of 50 verdicts,
    # which is not confidently a misfire; at weight 0 it is 25 of 25 (MIN_N, R-evidence-8).
    path.write_text(
        "".join(json.dumps(_signal("weighted", "tp", weight="0")) + "\n" for _ in range(25))
        + "".join(json.dumps(_signal("weighted", "fp", weight="1")) + "\n" for _ in range(25))
        + "not-json\n",
        encoding="utf-8",
    )

    issues = check_rule_fitness(tmp_path)
    assert any("line 51 is not a JSON object row" in issue["message"] for issue in issues)
    assert [issue["message"] for issue in issues if issue.get("rule") == "weighted"] == [
        "Rule 'weighted' misfires: 25 of 25 verdicts are false positives (misfire bound 0.90 > 0.5); "
        "aegis sync suggests demoting or archiving it"
    ]


def test_owned_production_has_no_active_legacy_evidence_paths():
    production = [
        p for p in [
            ROOT / "aegis_cli" / "sync.py", ROOT / "aegis_cli" / "report.py", ROOT / "aegis_cli" / "status.py",
            ROOT / "aegis_core" / "verification" / "checkpoint_checks.py",
            ROOT / "aegis_core" / "lifecycle.py",
        ]
        if p.exists()
    ]
    forbidden = (".aegis/evidence/fitness.jsonl", ".aegis/evidence/outcomes.jsonl", ".aegis/evidence/sessions_processed.jsonl")
    offenders = {
        path.relative_to(ROOT).as_posix(): needle
        for path in production
        for needle in forbidden
        if needle in path.read_text(encoding="utf-8").replace("', 'evidence', '", "/evidence/").replace('\", \"evidence\", \"', "/evidence/")
    }
    assert offenders == {}


def test_lifecycle_does_not_demote_a_rule_with_outcome_only_rows(tmp_path):
    from aegis_core.lifecycle.promotion import evaluate_demotions

    cell = tmp_path / ".aegis" / "rules" / "invariants" / "outcome-only.md"
    _cell(cell, "outcome-only", cell_type="invariant", age_days=120)
    # A v1 outcome row with no trigger row is still a trigger and a verdict: not a misfire.
    recent = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _write_jsonl(_ledger(tmp_path), [_signal("outcome-only", "tp", recent, weight="0.5")])

    assert evaluate_demotions(str(tmp_path)) == []


def test_invalid_weights_make_a_row_unusable_and_the_checkpoint_says_so(tmp_path):
    from aegis_core.telemetry_engine import ledger
    from aegis_core.verification.checkpoint_checks import check_rule_fitness

    _write_jsonl(_ledger(tmp_path), [
        _signal("bad-weight", "tp", weight="NaN"),
        _signal("cell-neg", "tp", weight=-1.5),
        _signal("cell-huge", "tp", weight=50),
        _signal("fine", "tp", weight=1),
    ])

    view = ledger.read(tmp_path)
    assert [r["rule"] for r in view.rows] == ["fine"]
    assert view.unusable_rows == 3
    assert any("3 row(s) lack a rule, a valid outcome or a valid weight" in i["message"] for i in check_rule_fitness(tmp_path))
