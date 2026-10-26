"""Unit tests for aegis rule command (aegis_cli/rule.py) and BUG-067."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegis_cli.rule import (
    RuleCommand,
    _force_demote,
    _force_promote,
    run_demote,
    run_promote,
    run_rule,
)


def test_demote_core_rule_fails(tmp_path, capsys):
    """BUG-067: demoting a protected core rule must fail closed."""
    args = argparse.Namespace(
        rule_action="demote",
        rule_id="cost-optimization",
        workspace=str(tmp_path),
        dry_run=False,
        json=False,
    )
    rc = run_rule(args)
    assert rc == 1
    out = capsys.readouterr().out
    assert "Cannot demote core rule" in out or "error" in out.lower()


def test_rule_list_empty(tmp_path, capsys):
    args = argparse.Namespace(
        rule_action="list",
        workspace=str(tmp_path),
        json=False,
        type=None,
        min_fitness=None,
    )
    rc = run_rule(args)
    assert rc == 0
    out = capsys.readouterr().out
    assert "No rules directory found" in out


def test_rule_list_with_rules(tmp_path, capsys):
    rules_dir = tmp_path / ".aegis" / "rules" / "invariants"
    rules_dir.mkdir(parents=True)
    rule_file = rules_dir / "inv-test.md"
    rule_file.write_text(
        "---\nid: inv-test\ntype: invariant\nenforcement: gate\n---\nRule body\n",
        encoding="utf-8",
    )
    (rules_dir / "inv-young.md").write_text("---\nid: inv-young\nenforcement: gate\n---\n", encoding="utf-8")
    state = tmp_path / ".aegis" / "state"
    state.mkdir()
    # Fitness is the ledger's: 30 of 30 verdicts are true positives (Wilson bound 0.92).
    (state / "ledger.jsonl").write_text(
        '{"v": 2, "rule": "inv-test", "outcome": "tp", "source": "ci"}\n' * 30, encoding="utf-8"
    )

    args = argparse.Namespace(
        rule_action="list",
        workspace=str(tmp_path),
        json=False,
        type="invariant",
        min_fitness=0.9,
    )
    rc = run_rule(args)
    assert rc == 0
    out = capsys.readouterr().out
    assert "inv-test" in out and "0.92" in out
    assert "inv-young" not in out  # no verdicts yet: below --min-fitness 0.9


def test_rule_list_flags_rules_edited_since_the_last_sync(tmp_path, capsys):
    """The CLI twin of aegis_list_rules' stale_rules: listed, never excluded."""
    from aegis_core.sync import sync

    traps = tmp_path / ".aegis" / "rules" / "traps"
    traps.mkdir(parents=True)
    (traps / "edited.md").write_text("---\nid: edited\n---\nBefore\n", encoding="utf-8")
    (traps / "steady.md").write_text("---\nid: steady\n---\nSame\n", encoding="utf-8")
    sync(tmp_path)
    (traps / "edited.md").write_text("---\nid: edited\n---\nAfter\n", encoding="utf-8")
    (traps / "added.md").write_text("---\nid: added\n---\nNew\n", encoding="utf-8")

    def listed(use_json):
        args = argparse.Namespace(rule_action="list", workspace=str(tmp_path), json=use_json, type=None, min_fitness=None)
        assert run_rule(args) == 0
        return capsys.readouterr().out

    rows = {r["id"]: r for r in json.loads(listed(True))}
    assert set(rows) == {"added", "edited", "steady"}
    assert (rows["edited"]["stale"], rows["added"]["stale"]) == ("edited", "new")
    assert "stale" not in rows["steady"]

    out = listed(False)
    assert "2 rule(s) changed since the last aegis sync: added (new), edited (edited)" in out


def test_rule_list_text_never_prints_terminal_escapes_from_rule_names(tmp_path, capsys):
    traps = tmp_path / ".aegis" / "rules" / "traps"
    traps.mkdir(parents=True)
    try:
        (traps / "evil\x1b]0;pwned\x07.md").write_text("---\ntype: trap\n---\n", encoding="utf-8")
    except (OSError, ValueError):
        pytest.skip("this filesystem refuses control characters in file names")

    args = argparse.Namespace(rule_action="list", workspace=str(tmp_path), json=False, type=None, min_fitness=None, plain=True)
    assert run_rule(args) == 0

    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "evil" in out


def test_rule_promote_and_force_promote(tmp_path, capsys):
    with patch("aegis_cli.rule.promote_rule", return_value={"status": "already_terminal", "current_type": "invariant"}):
        args = argparse.Namespace(
            rule_action="promote",
            rule_id="inv-test",
            workspace=str(tmp_path),
            dry_run=False,
            json=False,
        )
        rc = run_rule(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "already at terminal" in out

        # Test _force_promote helper
        rc2 = _force_promote(tmp_path, "inv-test")
        assert rc2 == 0


def test_rule_demote_and_force_demote(tmp_path, capsys):
    with patch("aegis_cli.rule.demote_rule", return_value={"status": "already_base", "current_type": "trap"}):
        args = argparse.Namespace(
            rule_action="demote",
            rule_id="trap-test",
            workspace=str(tmp_path),
            dry_run=False,
            json=False,
        )
        rc = run_rule(args)
        assert rc == 1
        out = capsys.readouterr().out
        assert "already at base" in out

        # Test _force_demote helper
        rc2 = _force_demote(tmp_path, "trap-test")
        assert rc2 == 1


def test_rule_archive(tmp_path, capsys):
    nothing = {"status": "nothing_to_archive", "unavailable": None, "candidates": []}
    with patch("aegis_cli.rule.prune_rules", return_value=nothing) as mock_prune:
        args = argparse.Namespace(
            rule_action="archive",
            workspace=str(tmp_path),
            dry_run=False,
        )
        rc = run_rule(args)
        assert rc == 0
        mock_prune.assert_called_once_with(workspace=tmp_path, execute=True)
    assert capsys.readouterr().out == "No rules to archive.\n"


def _misfiring_trap(ws):
    from aegis_core.fitness import MIN_N
    from aegis_core.telemetry_engine import ledger

    rule = ws / ".aegis" / "rules" / "traps" / "noisy.md"
    rule.parent.mkdir(parents=True)
    rule.write_bytes(b"---\nid: noisy\ntype: trap\nenforcement: advisory\n---\nBody.\n")
    ledger.append(ws, [{"rule": "noisy", "outcome": "fp", "source": "ci", "key": f"run-{i}"} for i in range(MIN_N)])
    return rule


@pytest.mark.parametrize("dry_run", [True, False], ids=["dry-run", "archive"])
def test_rule_archive_prints_each_candidate_and_what_archiving_did(tmp_path, capsys, dry_run):
    """Given a trap the ledger says misfires, When aegis rule archive runs, Then it prints one
    [ARCHIVE] line per candidate, marked (dry run) when nothing moved."""
    from aegis_core.fitness import MIN_N

    rule = _misfiring_trap(tmp_path)
    assert run_rule(argparse.Namespace(rule_action="archive", workspace=str(tmp_path), dry_run=dry_run)) == 0
    note = " (dry run)" if dry_run else ""
    assert capsys.readouterr().out == (
        f"[ARCHIVE] noisy (fitness 0.00, misfire bound 0.90, tp 0, fp {MIN_N}){note}\n")
    assert rule.is_file() is dry_run


def test_rule_archive_says_why_a_candidate_was_not_archived(tmp_path, capsys, monkeypatch):
    from aegis_core.lifecycle import selection

    _misfiring_trap(tmp_path)
    monkeypatch.setattr(selection, "archive_rule", lambda ws, rule_id: {"status": "ineligible", "message": "it recovered"})
    assert run_rule(argparse.Namespace(rule_action="archive", workspace=str(tmp_path), dry_run=False)) == 0
    assert capsys.readouterr().out.endswith(" (not archived: it recovered)\n")


@pytest.mark.parametrize("rules_dir,expected", [(False, "No rules directory found.\n"),
                                                 (True, "No rules to archive.\n")], ids=["no-rules-dir", "nothing"])
def test_rule_archive_names_the_empty_states(tmp_path, capsys, rules_dir, expected):
    (tmp_path / ".aegis" / ("rules" if rules_dir else "state")).mkdir(parents=True)
    assert run_rule(argparse.Namespace(rule_action="archive", workspace=str(tmp_path), dry_run=False)) == 0
    assert capsys.readouterr().out == expected


def test_rule_list_long_id_not_truncated_and_colored(tmp_path, capsys):
    """v3.0.0: long rule IDs (>36 chars) are never truncated and Table uses OutputContext."""
    from aegis_cli.ui.theme import OutputContext

    rules_dir = tmp_path / ".aegis" / "rules" / "invariants"
    rules_dir.mkdir(parents=True)
    long_id = "invariant-very-long-identifier-exceeding-thirty-six-characters-limit"
    (rules_dir / f"{long_id}.md").write_text(
        f"---\nid: {long_id}\ntype: invariant\nenforcement: gate\nfitness:\n  score: 0.91\n---\nBody\n",
        encoding="utf-8",
    )

    tty_ui = OutputContext(color_enabled=True, emoji_enabled=True, plain=False)
    args_tty = argparse.Namespace(
        rule_action="list",
        workspace=str(tmp_path),
        json=False,
        type=None,
        min_fitness=None,
        ui=tty_ui,
    )
    assert run_rule(args_tty) == 0
    out_tty = capsys.readouterr().out
    assert long_id in out_tty
    assert "\x1b[" in out_tty

    plain_ui = OutputContext(color_enabled=False, emoji_enabled=False, plain=True)
    args_plain = argparse.Namespace(
        rule_action="list",
        workspace=str(tmp_path),
        json=False,
        type=None,
        min_fitness=None,
        plain=True,
        ui=plain_ui,
    )
    assert run_rule(args_plain) == 0
    out_plain = capsys.readouterr().out
    assert long_id in out_plain
    assert "\x1b[" not in out_plain


def test_rule_parser_rejects_legacy_cell_flag():
    """v3.0.0: --cell flag is removed from aegis rule subcommands."""
    cmd = RuleCommand()
    parser = argparse.ArgumentParser()
    cmd.configure_parser(parser)
    with pytest.raises(SystemExit):
        parser.parse_args(["promote", "--cell", "old-id"])
    with pytest.raises(SystemExit):
        parser.parse_args(["demote", "--cell", "old-id"])



def test_an_unknown_action_is_reported_on_stderr_and_exits_1(tmp_path, capsys):
    args = argparse.Namespace(rule_action="graduate", workspace=str(tmp_path), json=False)
    assert run_rule(args) == 1
    captured = capsys.readouterr()
    assert captured.err == "Unknown rule subcommand: graduate\n"
    assert captured.out == ""


# ── `aegis rule <action> [options]` through main(): the parser binds each option ──


def _two_rule_workspace(root: Path) -> Path:
    for folder, rule_id, extra in (("traps", "old-trap", "expired_at: 2026-01-01\n"), ("invariants", "inv", "")):
        directory = root / ".aegis" / "rules" / folder
        directory.mkdir(parents=True)
        (directory / f"{rule_id}.md").write_text(
            f"---\nid: {rule_id}\ntype: {folder[:-1]}\n{extra}---\nBody\n", encoding="utf-8")
    return root


def _listed(capsys, *argv) -> dict:
    from aegis_cli.cli import main

    assert main(["rule", "list", "--json", *argv]) == 0
    return {row["id"]: row for row in json.loads(capsys.readouterr().out)}


def test_rule_list_takes_workspace_after_the_action(tmp_path, monkeypatch, capsys):
    ws = _two_rule_workspace(tmp_path / "ws")
    monkeypatch.chdir(tmp_path)
    assert set(_listed(capsys, "--workspace", str(ws))) == {"old-trap", "inv"}


def test_rule_list_marks_only_expired_rules(tmp_path, monkeypatch, capsys):
    ws = _two_rule_workspace(tmp_path / "ws")
    monkeypatch.chdir(tmp_path)
    rows = _listed(capsys, "--workspace", str(ws))
    assert rows["old-trap"]["expired"] is True
    assert "expired" not in rows["inv"]


def test_rule_list_type_filters_and_rejects_an_unknown_type(tmp_path, monkeypatch, capsys):
    from aegis_cli.cli import main

    ws = _two_rule_workspace(tmp_path / "ws")
    monkeypatch.chdir(tmp_path)
    assert set(_listed(capsys, "--type", "invariant", "--workspace", str(ws))) == {"inv"}
    with pytest.raises(SystemExit) as exc:
        main(["rule", "list", "--type", "rumor", "--workspace", str(ws)])
    assert exc.value.code == 2
    assert "invalid choice: 'rumor'" in capsys.readouterr().err


def test_rule_create_binds_type_body_file_and_workspace(tmp_path, monkeypatch, capsys):
    from aegis_cli.cli import main
    from aegis_core.yaml_engine.frontmatter import parse_frontmatter

    ws = _two_rule_workspace(tmp_path / "ws")
    body = tmp_path / "body.md"
    body.write_text("## Detail\n\nUse argv lists.\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = main(["rule", "create", "--json", "-t", "invariant", "--id", "argv-lists", "--hypothesis", "No shell strings",
               "--body-file", str(body), "--workspace", str(ws)])
    assert rc == 0
    created = Path(json.loads(capsys.readouterr().out)["path"])
    assert created == ws / ".aegis" / "rules" / "invariants" / "argv-lists.md"
    text = created.read_text(encoding="utf-8")
    assert parse_frontmatter(text)["type"] == "invariant"
    assert text.endswith("---\n## Detail\n\nUse argv lists.\n")


def test_rule_create_without_type_makes_a_trap(tmp_path, monkeypatch, capsys):
    from aegis_cli.cli import main

    ws = _two_rule_workspace(tmp_path / "ws")
    monkeypatch.chdir(tmp_path)
    assert main(["rule", "create", "--json", "--id", "plain", "--hypothesis", "h", "--workspace", str(ws)]) == 0
    assert (ws / ".aegis" / "rules" / "traps" / "plain.md").is_file()


# ── R-cli-5: `rule adjudicate` labels only a rule that loads cleanly ──────────

def _files(root: Path) -> dict:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def _adjudicate(ws: Path, *argv: str) -> int:
    from aegis_cli.cli import main

    return main(["rule", "adjudicate", "--workspace", str(ws), *argv])


def _labels(ws: Path, rule_id: str) -> list:
    path = ws / ".aegis" / "adjudications" / f"{rule_id}.jsonl"
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def test_adjudicate_records_a_label_for_a_served_rule_and_for_an_expired_one(tmp_path, capsys):
    ws = _two_rule_workspace(tmp_path / "ws")
    assert _adjudicate(ws, "--json", "--ref", "PR-7", "inv", "tp") == 0
    assert json.loads(capsys.readouterr().out)["status"] == "recorded"
    assert [(r["example_id"], r["verdict"]) for r in _labels(ws, "inv")] == [("PR-7", "tp")]
    for _ in range(2):
        assert _adjudicate(ws, "--json", "--ref", "PR-7", "old-trap", "fp") == 0
    capsys.readouterr()
    assert {(r["example_id"], r["verdict"]) for r in _labels(ws, "old-trap")} == {("PR-7", "fp")}


@pytest.mark.parametrize("rule_id,says", [
    ("trap-nope", "no rule"), ("inv.md", "no rule"), ("INV", "no rule"),
    ("../../x", "invalid rule id"), ("a/b", "invalid rule id"), ("..\\..\\x", "invalid rule id"),
    (" inv", "invalid rule id"), ("", "invalid rule id"), ("inv\x1b[2J", "invalid rule id"),
], ids=["unknown", "dot-md", "case", "dotdot", "slash", "backslash", "space", "empty", "escape"])
def test_adjudicate_refuses_an_id_that_names_no_loaded_rule_and_writes_nothing(tmp_path, capsys, rule_id, says):
    ws = _two_rule_workspace(tmp_path / "ws")
    before = _files(tmp_path)
    assert _adjudicate(ws, "--json", rule_id, "tp") == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "error" and says in payload["error"]
    assert "\x1b" not in captured.out and "\x1b" not in captured.err
    assert _files(tmp_path) == before


def test_adjudicate_names_the_unknown_rule_on_stderr_in_text_mode(tmp_path, capsys):
    ws = _two_rule_workspace(tmp_path / "ws")
    before = _files(tmp_path)
    assert _adjudicate(ws, "trap-nope", "tp") == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("Error: no rule 'trap-nope' that loads cleanly in this workspace")
    assert "aegis rule list" in captured.err
    assert _files(tmp_path) == before


def test_adjudicate_refuses_a_broken_rule_and_an_archived_one(tmp_path, capsys):
    ws = _two_rule_workspace(tmp_path / "ws")
    (ws / ".aegis" / "rules" / "traps" / "trap-broken.md").write_text("no frontmatter here\n", encoding="utf-8")
    archived = ws / ".aegis" / "rules" / ".archive" / "traps"
    archived.mkdir(parents=True)
    (archived / "trap-gone.md").write_text("---\nid: trap-gone\ntype: trap\n---\nBody\n", encoding="utf-8")
    before = _files(tmp_path)
    for rule_id in ("trap-broken", "trap-gone"):
        assert _adjudicate(ws, "--json", rule_id, "tp") == 1
        assert "no rule" in json.loads(capsys.readouterr().out)["error"]
    assert _files(tmp_path) == before


def test_adjudicate_fails_closed_when_the_rules_tree_holds_a_symlink(tmp_path, capsys):
    ws = _two_rule_workspace(tmp_path / "ws")
    real = tmp_path / "elsewhere.md"
    real.write_text("---\nid: trap-linked\ntype: trap\n---\nBody\n", encoding="utf-8")
    try:
        (ws / ".aegis" / "rules" / "traps" / "trap-linked.md").symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    before = _files(tmp_path)
    assert _adjudicate(ws, "--json", "inv", "tp") == 1
    assert "symlink" in json.loads(capsys.readouterr().out)["error"]
    assert _files(tmp_path) == before
