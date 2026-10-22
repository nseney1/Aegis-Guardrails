"""Integration test: `aegis rule promote --tier-check` never re-tiers enforcement from ledger numbers.

An evidence-backed promotion is a type move, which sets the enforcement the new type needs, so
the tier check changes no rule (decision D-tier-ladder): it reports the rules it evaluated and,
without --dry-run, why a write would be refused. It never writes a fitness block either.
"""
from __future__ import annotations

import json

import pytest

from aegis_cli.cli import main
from aegis_core.yaml_engine.frontmatter import parse_frontmatter
from tests.helpers_rule import soma_workspace, write_cell_with_fitness  # noqa: F401  (fixture)


def _tier_check(workspace, *extra: str) -> int:
    return main(["rule", "promote", "--tier-check", "--workspace", str(workspace), *extra])


def _meta(path):
    return parse_frontmatter(open(path, encoding="utf-8").read()) or {}


@pytest.fixture(autouse=True)
def _no_workspace_pin(monkeypatch):
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)


class TestTierCheck:
    def test_a_proven_advisory_rule_keeps_its_tier_and_its_bytes(self, soma_workspace, capsys):
        rules = soma_workspace / ".aegis" / "rules"
        path = write_cell_with_fitness(rules, "proven", "advisory", 25, 25, 0)
        before = open(path, "rb").read()

        assert _tier_check(soma_workspace) == 0

        assert open(path, "rb").read() == before
        assert _meta(path)["enforcement"] == "advisory"
        assert "No tier changes required." in capsys.readouterr().out

    def test_a_self_declared_gate_that_misfires_keeps_its_tier(self, soma_workspace, capsys):
        rules = soma_workspace / ".aegis" / "rules"
        path = write_cell_with_fitness(rules, "noisy-gate", "gate", 25, 5, 20)

        assert _tier_check(soma_workspace, "--json") == 0

        assert json.loads(capsys.readouterr().out) == {"evaluated": 1, "changes": []}
        assert _meta(path)["enforcement"] == "gate"

    def test_a_solid_gate_and_the_mandatory_types_keep_their_tier(self, soma_workspace, capsys):
        rules = soma_workspace / ".aegis" / "rules"
        solid = write_cell_with_fitness(rules, "solid-gate", "gate", 100, 95, 5)
        invariant = write_cell_with_fitness(rules, "noisy-invariant", "gate", 10, 0, 10, cell_type="invariant")

        assert _tier_check(soma_workspace) == 0

        assert _meta(solid)["enforcement"] == "gate"
        assert _meta(invariant)["enforcement"] == "gate"  # invariants are always gates

    def test_dry_run_changes_nothing(self, soma_workspace, capsys):
        rules = soma_workspace / ".aegis" / "rules"
        path = write_cell_with_fitness(rules, "dry-run-rule", "advisory", 25, 25, 0)
        before = open(path, "rb").read()

        assert _tier_check(soma_workspace, "--dry-run") == 0

        assert open(path, "rb").read() == before
        assert "No tier changes required." in capsys.readouterr().out

    def test_consecutive_runs_converge(self, soma_workspace, capsys):
        rules = soma_workspace / ".aegis" / "rules"
        path = write_cell_with_fitness(rules, "steady", "advisory", 25, 25, 0)

        assert _tier_check(soma_workspace) == 0
        first = open(path, "rb").read()
        assert _tier_check(soma_workspace) == 0

        assert open(path, "rb").read() == first

    def test_an_incomplete_ledger_is_named_and_nothing_is_rewritten(self, soma_workspace, capsys):
        rules = soma_workspace / ".aegis" / "rules"
        path = write_cell_with_fitness(rules, "proven", "advisory", 25, 25, 0)
        with open(soma_workspace / ".aegis" / "state" / "ledger.jsonl", "ab") as fh:
            fh.write(b"{garbled\n")
        before = open(path, "rb").read()

        assert _tier_check(soma_workspace) == 1

        out = capsys.readouterr().out
        assert "No tier changes required." in out
        assert "not written: the ledger is incomplete (1 unreadable line(s))" in out
        assert open(path, "rb").read() == before
