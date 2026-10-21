"""Frontmatter is not an evidence channel (R-evidence-16, ADR 0005 H6, spec T4).

Given/When/Then:

- Given rule frontmatter naming ``prior``, ``pack_prior``, ``trigger_rate_per_day`` or
  ``expected_triggers_per_day``, When fitness is read, Then none of them changes it: the
  trigger volume (and so the MDE and the ``untestable`` state) is measured from the ledger,
  from the rule's earliest ledger row.
- Given a rule observed for fewer than MIN_OBSERVATION_DAYS, Then no MDE is computed.
- Given a decided transition, Then it wins over ``untestable``.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

import pytest

from aegis_core import credit, fitness
from aegis_core.rules import load_rules
from aegis_core.telemetry_engine import ledger

NOW = datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


def _iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rule(ws: Path, rid: str, rtype: str = "trap", extra: str = "") -> None:
    folder = {"trap": "traps", "gate": "gates", "invariant": "invariants"}[rtype]
    path = ws / ".aegis" / "rules" / folder / f"{rid}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    enforcement = "gate" if rtype in ("gate", "invariant") else "advisory"
    created = (NOW - timedelta(days=400)).strftime("%Y-%m-%d")
    path.write_bytes((f"---\nid: {rid}\ntype: {rtype}\nenforcement: {enforcement}\nhypothesis: h\n"
                      f"created: '{created}'\ntarget_paths:\n  - 'src/*.py'\n{extra}---\nBody.\n").encode("utf-8"))


def _verdicts(ws: Path, rid: str, outcome: str, count: int, first_days_ago: float) -> None:
    """``count`` CI verdict rows, the first ``first_days_ago`` days ago, the rest today."""
    ledger.append_rows(ws, [
        {"v": 2, "ts": _iso(first_days_ago if n == 0 else 0), "rule": rid, "outcome": outcome, "source": "ci",
         "key": f"{rid}-{outcome}-{n}"}
        for n in range(count)
    ])


def _fit(ws: Path, rid: str) -> fitness.Fitness:
    return fitness.for_rules(ws, [load_rules(ws).get(rid)], now=NOW)[rid]


def test_frontmatter_trigger_rate_is_ignored_and_the_ledger_volume_decides(tmp_path: Path) -> None:
    _rule(tmp_path, "trap-busy", extra="trigger_rate_per_day: 0.001\n")
    _verdicts(tmp_path, "trap-busy", "tp", 120, first_days_ago=60)
    busy = _fit(tmp_path, "trap-busy")
    assert busy.mde == pytest.approx(0.0655, abs=1e-4)
    assert (busy.state, busy.suggestion) == ("decided", "promote")

    _rule(tmp_path, "trap-rare", extra="expected_triggers_per_day: 50\n")
    _verdicts(tmp_path, "trap-rare", "tp", 4, first_days_ago=200)
    rare = _fit(tmp_path, "trap-rare")
    assert rare.mde == pytest.approx(0.6552, abs=1e-4)
    assert rare.state == "untestable"


@pytest.mark.parametrize(("days_ago", "state"), [(None, "insufficient"), (10, "insufficient"),
                                                 (41, "insufficient"), (43, "untestable")])
def test_volume_is_measured_only_after_the_minimum_observation(tmp_path: Path, days_ago: Optional[int],
                                                               state: str) -> None:
    _rule(tmp_path, "trap-new")
    if days_ago is not None:
        credit.record_exposure(tmp_path, "claude-code", "s1", ["trap-new"], scope_basis="match", heartbeat=True,
                               ts=_iso(days_ago))
    fit = _fit(tmp_path, "trap-new")
    assert fit.state == state
    assert (fit.mde is None) is (state == "insufficient")
    assert fitness.MIN_OBSERVATION_DAYS == 42.0


def test_a_decided_transition_beats_untestable() -> None:
    fit = fitness.compute({"triggers": 12, "tp": 0, "fp": 12}, rule_type="trap", min_n=10, observed_days=600)
    assert fit.mde is not None and fit.mde > fitness.MDE_UNTESTABLE_THRESHOLD
    assert (fit.state, fit.suggestion) == ("decided", "archive")


@pytest.mark.parametrize("key", ["prior", "pack_prior"])
def test_a_frontmatter_prior_is_ignored(tmp_path: Path, key: str) -> None:
    _rule(tmp_path, "gate-plain", "gate")
    _rule(tmp_path, "gate-primed", "gate", extra=f"{key}:\n  alpha: 10\n  beta: 0\n")
    fits: List[fitness.Fitness] = []
    for rid in ("gate-plain", "gate-primed"):
        _verdicts(tmp_path, rid, "tp", 6, first_days_ago=1)
        _verdicts(tmp_path, rid, "fp", 6, first_days_ago=1)
        fits.append(_fit(tmp_path, rid))
    plain, primed = fits
    assert primed.prior_mass == 0.0 and primed.prior_disclosure is None
    assert (primed.p_below_demote, primed.score) == (plain.p_below_demote, plain.score)
    # an explicit prior is still honoured by compute itself
    assert fitness.compute({"tp": 6, "fp": 6}, prior=(10, 0)).prior_mass == 10.0
