"""Tests for soma status — Phase C test gate.

All tests use tmp_path to avoid touching the real filesystem.
"""
import argparse
from datetime import date, timedelta
import json


from pathlib import Path

from aegis_cli.status import run_status

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())


class TestStatus:
    """Test suite for the soma status subcommand."""

    def test_status_no_rules(self, tmp_path, capsys):
        """Empty dirs → '0 active' and helpful message."""
        (tmp_path / "genome").mkdir()
        (tmp_path / ".aegis" / "rules").mkdir(parents=True)
        args = argparse.Namespace(_root=tmp_path)
        ret = run_status(args)
        assert ret == 0
        captured = capsys.readouterr()
        assert "0 active" in captured.out
        assert "No rules found" in captured.out

    def test_status_counts_core_rules(self, capsys):
        """In the Aegis checkout, core rules are the shipped ones: what init's one locator sees."""
        from aegis_cli.init import packaged_rules

        args = argparse.Namespace(_root=REPO_ROOT, json=True)
        assert run_status(args) in (0, 1)  # the checkout's own rules may need attention
        payload = json.loads(capsys.readouterr().out)
        assert payload["core_rules"] == len(packaged_rules()) == 12
        core = {r["name"] for r in payload["rules"] if r["type"] == "core"}
        assert {"providence", "testing", "tdd-protocol"} <= core and "META" not in core

    def test_a_workspaces_own_rules_or_genome_dir_is_never_listed_as_core(self, tmp_path, capsys):
        """Release review: status read <workspace>/rules (or genome/) as Aegis's shipped
        rules, so a project's own markdown was listed and counted as active core rules."""
        marker = tmp_path / "PLANTED_RAN"
        for name in ("rules", "genome"):
            (tmp_path / name).mkdir()
            (tmp_path / name / "pricing.md").write_text("# Pricing\n" + "x" * 400)
            (tmp_path / name / "__init__.py").write_text(f"open({str(marker)!r}, 'w').write('x')\n")
        (tmp_path / ".aegis" / "rules").mkdir(parents=True)
        assert run_status(argparse.Namespace(_root=tmp_path)) == 0
        out = capsys.readouterr().out
        assert "Core rules:     0 active" in out and "pricing" not in out
        assert "~0 tokens" in out
        assert not marker.exists()

    def test_status_counts_adaptive_rules(self, tmp_path, capsys):
        """Rules in their type directories are counted; other markdown is listed as not a rule."""
        rules = tmp_path / ".aegis" / "rules"
        (rules / "traps").mkdir(parents=True)
        (rules / "invariants").mkdir()
        (rules / "traps" / "rule1.md").write_text("---\nid: rule1\n---\n# Rule 1\n")
        (rules / "invariants" / "rule2.md").write_text("---\nid: rule2\nenforcement: gate\n---\n# Rule 2\n")
        (rules / "notes.md").write_text("# Not a rule\n")
        (rules / "README.md").write_text("# Ignore me\n")

        args = argparse.Namespace(_root=tmp_path)
        ret = run_status(args)
        assert ret == 0
        captured = capsys.readouterr()
        assert "Adaptive rules: 2 (traps/patterns)" in captured.out
        assert ".aegis/rules/notes.md: not a rule: it is not in a rule type directory" in captured.out
        assert "README" not in captured.out

    def test_status_lists_rules_that_cannot_be_loaded_and_exits_1(self, tmp_path, capsys):
        """Nothing is excluded unseen: scan refuses these, so status names them."""
        rules = tmp_path / ".aegis" / "rules"
        (rules / "traps").mkdir(parents=True)
        (rules / "walls").mkdir()
        (rules / "traps" / "ok.md").write_text("---\nid: ok\n---\n")
        (rules / "walls" / "old.md").write_text("---\nid: old\ntype: wall\n---\n")

        assert run_status(argparse.Namespace(_root=tmp_path)) == 1
        out = capsys.readouterr().out
        assert "1 rule file(s) cannot be loaded; aegis scan fails until they are fixed:" in out
        assert ".aegis/rules/walls/old.md: not served: walls/ is not a rule type directory" in out
        assert "Adaptive rules: 1 (traps/patterns)" in out

    def test_status_names_rules_that_still_carry_derived_counters(self, tmp_path, capsys):
        rules = tmp_path / ".aegis" / "rules" / "traps"
        rules.mkdir(parents=True)
        (rules / "legacy.md").write_text("---\nid: legacy\nfitness:\n  score: 0.9\ntriggers: 12\n---\n")

        assert run_status(argparse.Namespace(_root=tmp_path, json=True)) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["needs_migrate"] == [{"path": ".aegis/rules/traps/legacy.md", "keys": ["fitness", "triggers"]}]
        assert [r["score"] for r in payload["rules"]] == [None]  # never the frontmatter 0.9

        assert run_status(argparse.Namespace(_root=tmp_path)) == 0
        assert "run aegis migrate --apply to strip them" in capsys.readouterr().out

    def test_status_names_rules_that_still_carry_a_retired_v3_key(self, tmp_path, capsys):
        """v3 tier escalation wrote enforcement_artifact; v4 serves the rule and ignores the key."""
        rules = tmp_path / ".aegis" / "rules" / "gates"
        rules.mkdir(parents=True)
        (rules / "g.md").write_text("---\nid: g\nenforcement: gate\nenforcement_artifact: .aegis/enforcement/g.py\n---\n")

        assert run_status(argparse.Namespace(_root=tmp_path, json=True)) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["needs_migrate"] == [{"path": ".aegis/rules/gates/g.md", "keys": ["enforcement_artifact"]}]
        assert payload["rule_errors"] == [] and [r["name"] for r in payload["rules"]] == ["g"]

    def test_status_reports_rules_edited_since_the_last_sync(self, tmp_path, capsys):
        from aegis_core.sync import sync

        rules = tmp_path / ".aegis" / "rules" / "traps"
        rules.mkdir(parents=True)
        (rules / "edited.md").write_text("---\nid: edited\n---\nBefore\n")
        assert run_status(argparse.Namespace(_root=tmp_path, json=True)) == 0
        assert json.loads(capsys.readouterr().out)["last_sync"] is None

        sync(tmp_path)
        (rules / "edited.md").write_text("---\nid: edited\n---\nAfter\n")

        assert run_status(argparse.Namespace(_root=tmp_path, json=True)) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["stale_rules"] == [{"id": "edited", "path": ".aegis/rules/traps/edited.md", "change": "edited"}]
        assert payload["last_sync"] is not None
        assert run_status(argparse.Namespace(_root=tmp_path)) == 0
        assert "1 rule(s) changed since the last aegis sync:" in capsys.readouterr().out

    def test_status_names_an_incomplete_ledger_and_rules_that_apply_to_no_file(self, tmp_path, capsys):
        """Fitness from a ledger with unreadable lines is partial, and a rule without
        target_paths is never served: both are shown, never left for the reader to guess."""
        from aegis_core.telemetry_engine import ledger

        rules = tmp_path / ".aegis" / "rules" / "traps"
        rules.mkdir(parents=True)
        (rules / "scoped.md").write_text("---\nid: scoped\ntarget_paths: ['src/*.py']\n---\n")
        (rules / "nowhere.md").write_text("---\nid: nowhere\n---\n")
        ledger.append(tmp_path, [{"rule": "scoped", "outcome": "tp", "source": "ci", "key": f"k{i}"} for i in range(2)])
        with ledger.ledger_path(tmp_path).open("ab") as fh:
            fh.write(b"{garbled\n")
        ledger.append(tmp_path, [{"rule": "scoped", "outcome": "fp", "source": "ci", "key": "k-fp"}])

        assert run_status(argparse.Namespace(_root=tmp_path, json=True)) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["ledger"] == {"skipped_lines": [3], "unusable_rows": 0, "error": None, "torn_tail": False}
        assert payload["untargeted"] == [{"id": "nowhere", "path": ".aegis/rules/traps/nowhere.md"}]
        assert {r["name"]: (r["triggers"]) for r in payload["rules"]} == {"scoped": 3, "nowhere": 0}

        assert run_status(argparse.Namespace(_root=tmp_path)) == 0
        out = capsys.readouterr().out
        assert (
            "⚠️  The ledger is incomplete (1 unreadable line(s)): fitness counts only the rows "
            "that could be read, so moves that rely on it (sync --apply, rule archive, tier changes) "
            "are refused" in out
        )
        assert "1 rule(s) apply to no file (no target_paths), so scan and check never serve them:" in out
        assert "nowhere: .aegis/rules/traps/nowhere.md" in out

    def test_status_reads_trigger_counts(self, tmp_path, capsys):
        """Ledger rows win over contradictory legacy evidence."""
        traps = tmp_path / ".aegis" / "rules" / "traps"
        traps.mkdir(parents=True)
        for name in ("rule-a", "rule-b"):
            (traps / f"{name}.md").write_text(f"---\nid: {name}\ntarget_paths: ['*.py']\n---\n# {name}\n")

        evidence = tmp_path / ".aegis" / "evidence"
        evidence.mkdir(parents=True)
        records = [
            {"cell": "rule-a", "signal": "trigger", "timestamp": "2026-09-30T12:00:00Z"},
            {"cell": "rule-a", "signal": "trigger", "timestamp": "2026-09-30T12:01:00Z"},
            {"cell": "rule-a", "signal": "trigger", "timestamp": "2026-09-30T12:02:00Z"},
            {"cell": "rule-b", "signal": "trigger", "timestamp": "2026-09-30T12:03:00Z"},
        ]
        state = tmp_path / ".aegis" / "state"
        state.mkdir(parents=True)
        (state / "ledger.jsonl").write_text(
            "\n".join(json.dumps(r) for r in records) + "\n"
        )
        legacy_records = [
            {"cell_id": "rule-a"},
            {"cell_id": "rule-b"},
            {"cell_id": "rule-b"},
            {"cell_id": "rule-b"},
        ]
        (evidence / "fitness.jsonl").write_text(
            "\n".join(json.dumps(r) for r in legacy_records) + "\n"
        )

        args = argparse.Namespace(_root=tmp_path)
        ret = run_status(args)
        assert ret == 0
        captured = capsys.readouterr()

        lines = captured.out.splitlines()
        rule_a_line = next((line for line in lines if "rule-a" in line), None)
        rule_b_line = next((line for line in lines if "rule-b" in line), None)
        assert rule_a_line is not None
        assert rule_b_line is not None

        # Verify exact counts associated with the rules
        cols_a = rule_a_line.split()
        cols_b = rule_b_line.split()
        assert cols_a[0] == "rule-a"
        assert cols_a[1] == "3"
        assert cols_b[0] == "rule-b"
        assert cols_b[1] == "1"

    def test_status_output_no_biology_terms(self, tmp_path, capsys):
        """Capture output, assert no 'enzyme', 'vacuole', 'genome', 'cell' in output."""
        (tmp_path / ".aegis" / "rules" / "traps").mkdir(parents=True)
        (tmp_path / ".aegis" / "rules" / "traps" / "rule-a.md").write_text("---\nid: rule-a\n---\n# Rule A\n")
        cells = tmp_path / ".aegis" / "rules"
        (cells / "rule-b.md").write_text(
            "---\ncreated: 2026-09-01\nexpiry_days: 30\n---\n# Rule B\n"
        )

        state = tmp_path / ".aegis" / "state"
        state.mkdir(parents=True)
        (state / "ledger.jsonl").write_text(
            json.dumps(
                {
                    "cell": "rule-a",
                    "signal": "trigger",
                    "timestamp": "2026-09-30T12:00:00Z",
                }
            ) + "\n"
        )

        args = argparse.Namespace(_root=tmp_path)
        ret = run_status(args)
        assert ret == 0
        captured = capsys.readouterr()

        out_lower = captured.out.lower()
        for term in ["enzyme", "vacuole", "genome", "cell"]:
            assert term not in out_lower, (
                f"Biology term '{term}' found in user output:\n{captured.out}"
            )

    def test_status_returns_zero(self, tmp_path):
        """run_status returns 0."""
        args = argparse.Namespace(_root=tmp_path)
        assert run_status(args) == 0

    def test_status_oracle_rules_counted(self, capsys):
        """Core rules include the shipped rules/.oracles/ files."""
        args = argparse.Namespace(_root=REPO_ROOT, json=True)
        run_status(args)
        payload = json.loads(capsys.readouterr().out)
        core = {r["name"] for r in payload["rules"] if r["type"] == "core"}
        assert {"providence", "architectural-tenets", "polyglot-standards"} <= core

    def test_status_context_load_calculation(self, tmp_path, capsys):
        """Approximate context overhead divides total chars by 4."""
        traps = tmp_path / ".aegis" / "rules" / "traps"
        traps.mkdir(parents=True)
        head = "---\nid: rule1\n---\n"
        (traps / "rule1.md").write_text(head + "x" * (400 - len(head)))

        args = argparse.Namespace(_root=tmp_path)
        ret = run_status(args)
        assert ret == 0
        captured = capsys.readouterr()
        assert "~100 tokens (pre-JIT max)" in captured.out

    def test_status_adaptive_rule_expiry_active(self, tmp_path, capsys):
        """Active adaptive rules show remaining days."""
        cells = tmp_path / ".aegis" / "rules" / "traps"
        cells.mkdir(parents=True)
        created = (date.today() - timedelta(days=10)).isoformat()
        (cells / "pattern.md").write_text(
            f"---\ncreated: {created}\nexpiry_days: 30\n---\n# Pattern\n"
        )

        args = argparse.Namespace(_root=tmp_path)
        ret = run_status(args)
        assert ret == 0
        captured = capsys.readouterr()
        # 30 - 10 = 20 days remaining
        assert "20d" in captured.out

    def test_status_adaptive_rule_expiry_expired(self, tmp_path, capsys):
        """Expired adaptive rules show 'expired'."""
        cells = tmp_path / ".aegis" / "rules" / "traps"
        cells.mkdir(parents=True)
        created = (date.today() - timedelta(days=40)).isoformat()
        (cells / "stale.md").write_text(
            f"---\ncreated: {created}\nexpiry_days: 30\n---\n# Stale\n"
        )

        args = argparse.Namespace(_root=tmp_path)
        ret = run_status(args)
        assert ret == 0
        captured = capsys.readouterr()
        assert "expired" in captured.out

    def test_status_command_contract(self):
        from unittest.mock import patch
        from aegis_cli.status import StatusCommand
        cmd = StatusCommand()
        parser = argparse.ArgumentParser()
        cmd.configure_parser(parser)
        parsed = parser.parse_args([])

        with patch("aegis_cli.status.run_status", return_value=0) as mock_run:
            assert cmd.execute(parsed) == 0
            mock_run.assert_called_once_with(parsed)

    def test_status_branded_aegis_header_and_no_soma(self, tmp_path, capsys):
        """v3.0.0: status prints Aegis Workspace Status, token budget bar, and zero 'Soma' references."""
        (tmp_path / "rules").mkdir()
        (tmp_path / ".aegis" / "rules").mkdir(parents=True)
        args = argparse.Namespace(_root=tmp_path)
        ret = run_status(args)
        assert ret == 0
        out = capsys.readouterr().out
        assert "Aegis Workspace Status" in out
        assert "Token budget:" in out
        assert "soma" not in out.lower()
        assert "aegis init" in out

    def test_status_groups_rules_by_type_and_colors_fitness(self, tmp_path, capsys):
        """v3.0.0: rules are grouped by modern rule type with colored fitness in TTY and zero ANSI in plain mode."""
        from aegis_cli.ui.theme import OutputContext

        rules_dir = tmp_path / ".aegis" / "rules"
        (rules_dir / "invariants").mkdir(parents=True)
        (rules_dir / "traps").mkdir(parents=True)
        # The frontmatter `fitness:` blocks are legacy counters: the ledger decides the scores.
        (rules_dir / "invariants" / "inv-auth.md").write_text(
            "---\nid: inv-auth\ntype: invariant\nenforcement: gate\nfitness:\n  score: 0.11\n---\n# Auth Invariant\n",
            encoding="utf-8",
        )
        (rules_dir / "traps" / "trap-retry.md").write_text(
            "---\nid: trap-retry\ntype: trap\nfitness:\n  score: 0.13\n---\n# Retry Trap\n",
            encoding="utf-8",
        )
        state = tmp_path / ".aegis" / "state"
        state.mkdir(parents=True)
        rows = [{"v": 2, "rule": "inv-auth", "outcome": "tp", "source": "ci"}] * 30
        rows += [{"v": 2, "rule": "trap-retry", "outcome": o, "source": "ci"} for o in ["tp"] * 8 + ["fp"] * 2]
        (state / "ledger.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

        tty_ui = OutputContext(color_enabled=True, emoji_enabled=True, plain=False)
        args_tty = argparse.Namespace(_root=tmp_path, ui=tty_ui)
        assert run_status(args_tty) == 0
        out_tty = capsys.readouterr().out
        assert "🛡️ Aegis Workspace Status" in out_tty
        assert "\x1b[" in out_tty
        assert "0.92" in out_tty  # Wilson lower bound of 30 of 30
        # 8 of 10 is below the one sample gate (MIN_N = 25, R-evidence-8): a label, never 0.54
        assert "insufficient (n=10)" in out_tty and "0.54" not in out_tty
        assert "0.11" not in out_tty and "0.13" not in out_tty
        assert "wall" not in out_tty.lower()
        assert "vacuole" not in out_tty.lower()

        plain_ui = OutputContext(color_enabled=False, emoji_enabled=False, plain=True)
        args_plain = argparse.Namespace(_root=tmp_path, plain=True, ui=plain_ui)
        assert run_status(args_plain) == 0
        out_plain = capsys.readouterr().out
        assert "\x1b[" not in out_plain
        assert "soma" not in out_plain.lower()




# ── `aegis status --compliance` through main() (more in test_status_compliance.py) ──


def _compliance_workspace(tmp_path, monkeypatch, *rows):
    root = tmp_path / "ws"
    (root / ".aegis" / "rules" / "traps").mkdir(parents=True)
    if rows:
        (root / ".aegis" / "state").mkdir()
        (root / ".aegis" / "state" / "activity.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    monkeypatch.chdir(root)
    return root


def _activity(event, session, host, files, ts):
    return {"v": 1, "ts": ts, "event": event, "host": host, "session": session, "files": files,
            "client": {"name": host, "version": "1"}}


class TestStatusComplianceCLI:
    def test_json_is_the_compliance_report_as_one_two_space_indented_document(self, tmp_path, monkeypatch, capsys):
        from aegis_cli.cli import main

        _compliance_workspace(tmp_path, monkeypatch)
        assert main(["status", "--compliance", "--json"]) == 0
        out = capsys.readouterr().out
        assert out == json.dumps(json.loads(out), indent=2) + "\n"
        assert json.loads(out)["schema"] == "aegis.compliance/v1"

    def test_outside_a_workspace_fails_cleanly(self, tmp_path, monkeypatch, capsys):
        from aegis_cli.cli import main

        plain = tmp_path / "plain"
        plain.mkdir()
        monkeypatch.chdir(plain)
        assert main(["status", "--compliance", "--json"]) == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert f"not an Aegis workspace (no .aegis/ in {plain.resolve()})" in captured.err

    def test_the_text_view_says_when_commits_were_not_read(self, tmp_path, monkeypatch, capsys):
        from aegis_cli.cli import main
        from aegis_core import gitsafe

        monkeypatch.setattr(gitsafe, "toplevel", lambda cwd: None)
        _compliance_workspace(tmp_path, monkeypatch,
                              _activity("scan", "s1", "claude-code", ["a.py"], "2026-10-15T10:00:00Z"))
        assert main(["status", "--compliance"]) == 0
        assert "Commits were not read (no git repository or git unavailable)" in capsys.readouterr().out

    def test_a_long_host_name_is_cut_to_keep_the_columns_aligned(self, tmp_path, monkeypatch, capsys):
        from aegis_cli.cli import main

        host = "h" * 30
        _compliance_workspace(tmp_path, monkeypatch,
                              _activity("scan", "s1", host, ["a.py"], "2026-10-15T10:00:00Z"),
                              _activity("edit", "s1", host, ["a.py"], "2026-10-15T10:01:00Z"))
        assert main(["status", "--compliance"]) == 0
        lines = capsys.readouterr().out.splitlines()
        header = next(line for line in lines if line.lstrip().startswith("Host"))
        row = next(line for line in lines if "hhh" in line)
        assert row.startswith("  " + "h" * 13 + "...")
        assert len(row) == len(header)
        assert row.endswith("100%")
