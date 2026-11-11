"""`aegis sync [--apply] [--json]` (ADR 0005 D1): rebuild derived state, suggest, apply on request.

Exit codes: 0 when the view was rebuilt (and every requested move applied), 1 when a
rule file cannot be loaded or applying was refused or failed, 2 for a usage or
workspace error. With --json, stdout carries only the JSON document.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_cli.cli import main
from aegis_core.telemetry_engine import ledger


@pytest.mark.parametrize("plain, tty", [(True, True), (False, False), (False, True)])
def test_public_sync_warning_badges_respect_output_context(ws, monkeypatch, capsys, plain, tty):
    import sys

    monkeypatch.delenv("TERM", raising=False)
    path = ws / ".aegis" / "rules" / "traps" / "nowhere.md"
    path.write_text("---\nid: nowhere\nhypothesis: h\n---\nB\n", encoding="utf-8")
    monkeypatch.setattr(sys.stdout, "isatty", lambda: tty)
    assert main(["sync", *(["--plain"] if plain else [])]) == 0
    output = capsys.readouterr().out
    if plain or not tty:
        assert "[WARN] nowhere: applies to no file" in output
        assert not any(icon in output for icon in ("✅", "❌", "⚠", "ℹ"))
    else:
        assert "⚠️  nowhere: applies to no file" in output


@pytest.mark.parametrize("plain, tty", [(True, True), (False, False)])
def test_sync_error_and_advisory_paths_keep_plain_badges(ws, monkeypatch, capsys, plain, tty):
    import sys

    traps = ws / ".aegis" / "rules" / "traps"
    caller_name = "⚠️  caller ✅.md"
    (traps / caller_name).write_text("---\nid: [x\n---\n", encoding="utf-8")
    (ws / ".aegis" / "rules" / "note.md").write_text("A caller's note\n", encoding="utf-8")
    (ws / ".aegis" / "config.json").write_text('{"v":1,"expiry":{"days":7}}', encoding="utf-8")
    with ledger.ledger_path(ws).open("ab") as handle:
        handle.write(b"not json\n")
    monkeypatch.setattr(sys.stdout, "isatty", lambda: tty)
    assert main(["sync", "--apply", *(["--plain"] if plain else [])]) == 1
    output = capsys.readouterr().out
    assert f"[FAIL] .aegis/rules/traps/{caller_name}:" in output
    assert "[WARN] .aegis/rules/note.md:" in output
    assert "[WARN] The ledger is incomplete" in output
    assert "[FAIL] not applied:" in output
    assert "[INFO] expiry.days" in output
    assert "⚠️" not in output.replace(caller_name, "")


@pytest.mark.parametrize("failure", ["refusal", "pr-error"])
def test_sync_keeps_long_next_actions_and_redacts_diagnostics(tmp_path, monkeypatch, capsys, failure):
    import argparse
    import shutil
    from types import SimpleNamespace
    from aegis_cli.sync import run_sync
    from aegis_core import gitsafe
    from tests import helpers_syncpr as hs

    if shutil.which("git") is None:
        pytest.skip("git is required for the public sync PR flow")
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GIT_CONFIG_GLOBAL", "CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    repo = hs.make(tmp_path)
    credential = "ghp_" + "A" * 20 + "\x1b[31m" + "B" * 16
    action = "set branch.main.remote to origin or push the branch yourself"
    diagnostic = "diagnostic detail " * 30 + credential + "; " + action
    assert 300 < len(diagnostic) < 4096
    calls = []

    def gh(argv, cwd=None):
        calls.append(list(argv))
        return SimpleNamespace(returncode=1, stdout="", stderr=diagnostic)

    if failure == "refusal":
        real_run = gitsafe.run

        def git_boundary(argv, *args, **kwargs):
            if argv == ["config", "--get", "branch.main.remote"]:
                raise gitsafe.GitError(diagnostic)
            return real_run(argv, *args, **kwargs)

        monkeypatch.setattr(gitsafe, "run", git_boundary)
    before = repo.rule_path.read_bytes()
    assert run_sync(argparse.Namespace(_root=repo.root, pr=True, plain=True), gh_runner=gh) == 1
    output = capsys.readouterr().out
    assert action in output
    assert "REDACTED" in output and "A" * 10 not in output and "B" * 10 not in output
    assert "\x1b" not in output
    if failure == "refusal":
        assert "[FAIL] no pull request opened:" in output
        assert not calls and repo.rule_path.read_bytes() == before
    else:
        assert "[FAIL] PR creation failed:" in output
        assert len(calls) == 1 and calls[0][:2] == ["pr", "create"]


def _rule(ws: Path, directory: str, rule_type: str, rule_id: str) -> Path:
    path = ws / ".aegis" / "rules" / directory / f"{rule_id}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    enforcement = "gate" if rule_type == "invariant" else "advisory"
    path.write_text(
        f"---\nid: {rule_id}\ntype: {rule_type}\nenforcement: {enforcement}\nhypothesis: h\n"
        "created: '2026-01-01'\ntarget_paths: ['src/*.py']\n---\nBody.\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def ws(tmp_path, monkeypatch):
    root = tmp_path / "project"
    _rule(root, "traps", "trap", "trap-good")
    _rule(root, "personas", "persona", "persona-quiet")
    ledger.append(root, [{"rule": "trap-good", "outcome": "tp", "source": "ci", "key": f"k{i}"} for i in range(25)])
    monkeypatch.chdir(root)
    return root


@pytest.fixture
def labelled(tmp_path, monkeypatch):
    """``ws`` whose trap also has 25 tp labels merged at the reviewed BASE: only labels promote (R-evidence-4)."""
    from tests import helpers_adjudication as ha

    root = tmp_path / "project"
    _rule(root, "traps", "trap", "trap-good")
    _rule(root, "personas", "persona", "persona-quiet")
    ha.write_labels(root, "trap-good", ha.labels("trap-good"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    ha.merge_to_base(root)
    ledger.append(root, [{"rule": "trap-good", "outcome": "tp", "source": "ci", "key": f"k{i}"} for i in range(25)])
    monkeypatch.chdir(root)
    return root


def _rule_files(ws: Path) -> dict:
    rules = ws / ".aegis" / "rules"
    return {p.relative_to(rules).as_posix(): p.read_bytes() for p in sorted(rules.rglob("*.md"))}


def test_sync_prints_a_table_of_suggestions_and_writes_derived_state(labelled, capsys):
    ws = labelled
    before = _rule_files(ws)

    rc = main(["sync"])

    out = capsys.readouterr().out
    assert rc == 0
    for column in ("Rule", "Type", "State", "n", "Weight", "Score", "Suggestion"):
        assert column in out
    assert "trap-good" in out and "promote" in out and "persona-quiet" in out
    assert "aegis sync --apply" in out
    assert (ws / ".aegis" / "state" / "derived.json").is_file()
    assert _rule_files(ws) == before


def test_ci_verdicts_without_labels_suggest_nothing(ws, capsys):
    assert main(["sync", "--json"]) == 0
    rows = {r["id"]: r for r in json.loads(capsys.readouterr().out)["rules"]}
    assert (rows["trap-good"]["suggestion"], rows["trap-good"]["tp"]) == (None, 25)


def test_sync_json_is_machine_readable(labelled, capsys):
    rc = main(["sync", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["status"] == "synced"
    assert payload["path"] == ".aegis/state/derived.json"
    rows = {r["id"]: r for r in payload["rules"]}
    assert rows["trap-good"]["suggestion"] == "promote" and rows["trap-good"]["triggers"] == 25
    assert rows["persona-quiet"]["suggestion"] is None
    assert payload["applied"] == [] and payload["errors"] == [] and payload["ignored"] == []


def test_sync_json_is_one_two_space_indented_document(ws, capsys):
    assert main(["sync", "--json"]) == 0
    out = capsys.readouterr().out
    assert out == json.dumps(json.loads(out), indent=2) + "\n"


def test_apply_moves_the_suggested_rules(labelled, capsys):
    ws = labelled
    rc = main(["sync", "--apply", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0 and payload["status"] == "applied"
    assert [(a["rule"], a["action"], a["status"]) for a in payload["applied"]] == [("trap-good", "promote", "promoted")]
    assert (ws / ".aegis" / "rules" / "invariants" / "trap-good.md").is_file()


def test_apply_text_mode_reports_each_move(labelled, capsys):
    rc = main(["sync", "--apply"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "promote trap-good: promoted (trap -> invariant)" in out


def test_a_broken_rule_is_reported_and_exits_1(ws, capsys):
    (ws / ".aegis" / "rules" / "traps" / "broken.md").write_text("---\nid: [x\n---\n", encoding="utf-8")

    rc = main(["sync", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 1 and payload["status"] == "errors"
    assert payload["errors"] == [{"path": ".aegis/rules/traps/broken.md", "error": "malformed YAML frontmatter: unterminated flow sequence"}]


def test_apply_with_a_broken_rule_is_refused_and_moves_nothing(ws, capsys):
    (ws / ".aegis" / "rules" / "traps" / "broken.md").write_text("---\nid: [x\n---\n", encoding="utf-8")
    before = _rule_files(ws)

    rc = main(["sync", "--apply"])

    captured = capsys.readouterr()
    assert rc == 1
    assert "not applied" in captured.out + captured.err
    assert _rule_files(ws) == before


def test_outside_an_aegis_workspace_sync_exits_2(tmp_path, monkeypatch, capsys):
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.chdir(plain)

    rc = main(["sync", "--workspace", str(plain)])

    assert rc == 2
    assert "not an Aegis workspace" in capsys.readouterr().err


def test_sync_text_never_prints_terminal_escapes_from_rule_files(ws, capsys):
    traps = ws / ".aegis" / "rules" / "traps"
    try:
        (traps / "evil\x1b]0;pwned\x07.md").write_text("---\ntype: trap\n---\n", encoding="utf-8")
    except (OSError, ValueError):
        pytest.skip("this filesystem refuses control characters in file names")
    (traps / "broken.md").write_text("---\nid: [x\n---\n", encoding="utf-8")

    assert main(["sync"]) == 1

    out = capsys.readouterr().out
    assert "\x1b]" not in out and "\x07" not in out
    assert "evil" in out and "broken.md" in out


def test_an_incomplete_ledger_is_named_and_apply_is_refused(ws, capsys):
    with ledger.ledger_path(ws).open("ab") as fh:
        fh.write(b"{garbled\n")
    before = _rule_files(ws)

    rc = main(["sync", "--apply"])

    out = capsys.readouterr().out
    assert rc == 1
    assert "The ledger is incomplete (1 unreadable line(s)): fitness counts only the rows that could be read" in out
    assert "not applied: the ledger is incomplete (1 unreadable line(s))" in out
    assert _rule_files(ws) == before

    assert main(["sync", "--json"]) == 0  # rebuilding the view is fine; only moves are refused
    payload = json.loads(capsys.readouterr().out)
    assert payload["ledger"] == {"skipped_lines": [26], "unusable_rows": 0, "error": None, "torn_tail": False}


def test_rules_that_apply_to_no_file_are_named(ws, capsys):
    (ws / ".aegis" / "rules" / "traps" / "nowhere.md").write_text("---\nid: nowhere\nhypothesis: h\n---\nB\n", encoding="utf-8")

    assert main(["sync"]) == 0
    assert "[WARN] nowhere: applies to no file (no target_paths)" in capsys.readouterr().out

    assert main(["sync", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["untargeted"] == [{"id": "nowhere", "path": ".aegis/rules/traps/nowhere.md"}]


# ── One minimum-sample gate (R-evidence-8): no number and no transition below MIN_N ──

def test_the_fitness_column_shows_insufficient_below_min_n_and_json_keeps_the_raw_number(ws, capsys):
    from aegis_core.fitness import MIN_N

    _rule(ws, "traps", "trap", "trap-twelve")
    ledger.append(ws, [{"rule": "trap-twelve", "outcome": "tp", "source": "ci", "key": f"t{i}"} for i in range(12)])

    assert main(["sync"]) == 0
    line = next(ln for ln in capsys.readouterr().out.splitlines() if "trap-twelve" in ln)
    assert "insufficient (n=12)" in line and "0." not in line

    assert main(["sync", "--json"]) == 0
    rows = {r["id"]: r for r in json.loads(capsys.readouterr().out)["rules"]}
    assert rows["trap-twelve"]["reported_score"] is None and rows["trap-twelve"]["fitness"] > 0.5
    assert rows["trap-good"]["reported_score"] == rows["trap-good"]["fitness"]
    assert rows["trap-good"]["tp"] == MIN_N


def test_apply_moves_only_the_rule_with_min_n_verdicts(tmp_path, monkeypatch, capsys):
    from aegis_core.fitness import MIN_N

    root = tmp_path / "project"
    for directory, rule_type, rule_id, fps in (("traps", "trap", "trap-three", 3),
                                               ("invariants", "invariant", "invariant-three", 3),
                                               ("traps", "trap", "trap-enough", MIN_N)):
        _rule(root, directory, rule_type, rule_id)
        ledger.append(root, [{"rule": rule_id, "outcome": "fp", "source": "ci", "key": f"{rule_id}-{i}"}
                             for i in range(fps)])
    monkeypatch.chdir(root)

    assert main(["sync", "--apply", "--json"]) == 0
    applied = json.loads(capsys.readouterr().out)["applied"]
    assert [(a["rule"], a["action"], a["status"]) for a in applied] == [("trap-enough", "archive", "archived")]
    assert (root / ".aegis" / "rules" / "traps" / "trap-three.md").is_file()
    assert (root / ".aegis" / "rules" / "invariants" / "invariant-three.md").is_file()


def test_sync_names_the_inert_day_expiry_once(ws, capsys):
    """R-evidence-15: `expiry.days`/`per_type` still load, change no fitness, and sync says so once."""
    assert main(["sync"]) == 0
    assert "no longer change fitness" not in capsys.readouterr().out

    (ws / ".aegis" / "config.json").write_text(json.dumps({"v": 1, "expiry": {"days": 7}}), encoding="utf-8")
    assert main(["sync"]) == 0
    out = capsys.readouterr().out
    assert out.count("expiry.days and expiry.per_type in .aegis/config.json no longer change fitness") == 1
    assert main(["sync", "--json"]) == 0
    rows = {r["id"]: r for r in json.loads(capsys.readouterr().out)["rules"]}
    assert rows["trap-good"]["fitness"] > 0.85  # 25 tp with no calendar decay
