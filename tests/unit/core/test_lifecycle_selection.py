"""aegis_core.lifecycle.selection.run_rule_selection: report misfiring rules; archive only on request.

It returns what it found and did (aegis rule archive prints it, tests/unit/cli/test_cli_rule.py)."""
from __future__ import annotations

from pathlib import Path

from aegis_core.fitness import MIN_N
from aegis_core.lifecycle.selection import run_rule_selection
from aegis_core.telemetry_engine import ledger


def _misfiring(tmp_path: Path) -> tuple[Path, Path]:
    """A workspace whose trap the ledger is confident misfires: MIN_N false positives (the one
    sample gate, R-evidence-8), no true one."""
    ws = tmp_path / "ws"
    rule = ws / ".aegis" / "rules" / "traps" / "noisy.md"
    rule.parent.mkdir(parents=True)
    rule.write_text("---\nid: noisy\ntype: trap\nenforcement: advisory\n---\nBody.\n", encoding="utf-8")
    ledger.append(ws, [{"rule": "noisy", "outcome": "fp", "source": "ci", "key": f"run-{i}"} for i in range(MIN_N)])
    return ws, rule


def test_by_default_a_misfiring_rule_is_reported_as_a_dry_run_and_kept(tmp_path: Path, capsys):
    ws, rule = _misfiring(tmp_path)

    result = run_rule_selection(ws)

    assert (result["status"], result["unavailable"]) == ("candidates", None)
    (row,) = result["candidates"]
    assert (row["rule_id"], row["tp"], row["fp"], row["archive"]) == ("noisy", 0, MIN_N, None)
    assert capsys.readouterr() == ("", "")
    assert rule.is_file()
    assert not (ws / ".aegis" / "rules" / ".archive").exists()


def test_with_execute_the_misfiring_rule_is_archived(tmp_path: Path, capsys):
    ws, rule = _misfiring(tmp_path)

    result = run_rule_selection(ws, execute=True)

    (row,) = result["candidates"]
    assert (row["rule_id"], row["archive"]["status"]) == ("noisy", "archived")
    assert capsys.readouterr() == ("", "")
    assert not rule.exists()
    assert (ws / ".aegis" / "rules" / ".archive" / "noisy.md").is_file()


def test_a_workspace_without_a_rules_directory_has_nothing_to_select(tmp_path: Path, capsys):
    (tmp_path / ".aegis").mkdir()

    assert run_rule_selection(tmp_path, execute=True) == {
        "status": "no_rules_directory", "unavailable": None, "candidates": []}
    assert capsys.readouterr() == ("", "")


def test_rules_without_misfire_evidence_leave_nothing_to_archive(tmp_path: Path):
    ws, rule = _misfiring(tmp_path)
    ledger.append(ws, [{"rule": "noisy", "outcome": "tp", "source": "ci", "key": f"hit-{i}"} for i in range(4 * MIN_N)])

    assert run_rule_selection(ws, execute=True) == {
        "status": "nothing_to_archive", "unavailable": None, "candidates": []}
    assert rule.is_file()
