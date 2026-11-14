"""Tests for aegis status — Phase C test gate.

All tests use tmp_path to avoid touching the real filesystem.
"""
import argparse
from datetime import date, timedelta
import errno
import json
import os
import re

import pytest

from pathlib import Path

from aegis_cli.status import run_status

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
_STATUS_TODAY = date(2026, 11, 10)


@pytest.fixture(autouse=True)
def _freeze_status_today(monkeypatch):
    """Freeze only the status clock, preserving the real date type."""
    monkeypatch.setattr("aegis_cli.status._today", lambda: _STATUS_TODAY)


@pytest.fixture
def mixed_service_states(tmp_path, monkeypatch):
    """One workspace lists served, retired, untargeted and shipped guidance."""
    import aegis_cli.init as init_module

    rules = tmp_path / ".aegis" / "rules" / "traps"
    rules.mkdir(parents=True)
    texts = {
        "served": "---\nid: served\ntarget_paths: ['*.py']\n---\n# Apply café\n",
        "retired": "---\nid: retired\ntarget_paths: ['*.py']\nexpired_at: 2026-01-01\n---\n" + "R" * 800,
        "untargeted": "---\nid: untargeted\n---\n" + "U" * 1200,
    }
    for name, text in texts.items():
        (rules / f"{name}.md").write_bytes(text.encode("utf-8-sig"))
    core = tmp_path / "rules"
    core.mkdir()
    guide = core / "guide.md"
    guide.write_text("---\nid: guide\n---\n" + "G" * 1600, encoding="utf-8")
    monkeypatch.setattr(init_module, "packaged_dir", lambda name: core)
    monkeypatch.setattr(init_module, "packaged_rules", lambda: {"guide": guide})
    return tmp_path, texts["served"]


@pytest.mark.parametrize("json_output", [False, True], ids=["text", "json"])
@pytest.mark.parametrize("has_served", [True, False], ids=["mixed", "none-served"])
def test_status_cli_counts_only_served_rules(mixed_service_states, capsys, json_output, has_served):
    from aegis_cli.cli import main
    from aegis_core.taxonomy import CHARS_PER_TOKEN_ESTIMATE

    workspace, served_text = mixed_service_states
    if not has_served:
        (workspace / ".aegis" / "rules" / "traps" / "served.md").unlink()
    expected_count = int(has_served)
    expected_tokens = len(served_text) // CHARS_PER_TOKEN_ESTIMATE if has_served else 0
    states = {"guide": "not_loaded", "retired": "retired", "untargeted": "untargeted"}
    if has_served:
        states["served"] = "served"
    argv = ["status", "--workspace", str(workspace), "--plain"]
    if json_output:
        argv.append("--json")

    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    if json_output:
        payload = json.loads(captured.out)
        assert payload["estimated_tokens"] == expected_tokens
        assert payload["core_rules"] == 0
        assert payload["adaptive_rules"] == expected_count
        assert payload["core_rules_shown"] == 1
        assert payload["adaptive_rules_shown"] == 2 + expected_count
        assert {r["name"]: r["service_state"] for r in payload["rules"]} == states
    else:
        assert "Core rules:     1 shown, 0 served" in captured.out
        assert f"Adaptive rules: {2 + expected_count} shown, {expected_count} served" in captured.out
        assert f"Context load:   ~{expected_tokens:,} tokens (pre-JIT max)" in captured.out
        budget = next(line for line in captured.out.splitlines() if "Token budget:" in line)
        assert f"{expected_tokens:,}/2,000" in budget
        for name, state in states.items():
            row = next(line for line in captured.out.splitlines() if line.lstrip().startswith(name + " "))
            assert re.split(r" {2,}", row.strip())[-2] == state


@pytest.fixture
def status_policy_repo(tmp_path, monkeypatch):
    """Build our own reviewed history; never depend on checkout history."""
    from tests import helpers_humangate as hg

    if not hg.git_ok():
        pytest.skip("needs git")
    home = hg.Home(tmp_path / "home")
    for name, value in home.env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    repo = hg.Repo(tmp_path / "project", home)
    text = "---\nid: reviewed\nenforcement: gate\ntarget_paths: ['src/*.py']\n---\n# Reviewed\n"
    repo.write(".aegis/rules/invariants/reviewed.md", text)
    repo.write("src/app.py", "value = 1\n")
    repo.commit("reviewed fixture policy")
    repo.git("update-ref", "refs/remotes/origin/main", repo.head())
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    return repo, text


@pytest.mark.parametrize("json_output", [False, True], ids=["text", "json"])
@pytest.mark.parametrize("change", ["untargeted", "new-mandatory", "removed", "rewritten"])
def test_status_cli_uses_reviewed_policy(status_policy_repo, capsys, json_output, change):
    from aegis_cli.cli import main

    repo, reviewed = status_policy_repo
    path = ".aegis/rules/invariants/reviewed.md"
    if change == "untargeted":
        repo.write(path, reviewed.replace("target_paths: ['src/*.py']\n", ""))
    elif change == "new-mandatory":
        repo.write(".aegis/rules/invariants/pending.md", reviewed.replace("reviewed", "pending") + "pending\n" * 50)
    elif change == "removed":
        (repo.root / path).unlink()
    else:
        repo.write(path, reviewed + "branch-local body\n" * 50)
    assert main(["scan", str(repo.root / "src/app.py"), "--workspace", str(repo.root), "--json"]) == 0
    scan = json.loads(capsys.readouterr().out)
    assert [r["name"] for r in scan["relevant_rules"]] == ["reviewed"]
    expected_shown = 2 if change == "new-mandatory" else 0 if change == "removed" else 1
    expected_tokens = len(reviewed) // 4
    argv = ["status", "--workspace", str(repo.root), "--plain"] + (["--json"] if json_output else [])
    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    if json_output:
        payload = json.loads(captured.out)
        assert payload["adaptive_rules"] == 1
        assert payload["adaptive_rules_shown"] == expected_shown
        assert payload["estimated_tokens"] == expected_tokens
        assert payload["rules_base"] == scan["rules_base"]
        expected_counts = {"new": 0, "changed": 0, "broken": 0, "removed": 0}
        expected_counts[{"untargeted": "changed", "new-mandatory": "new",
                         "removed": "removed", "rewritten": "changed"}[change]] = 1
        assert payload["unreviewed_counts"] == expected_counts
        assert "unreviewed_rules" not in payload
        assert payload["unreviewed_total"] == len(scan["unreviewed_rules"])
        assert payload["next_action"] == "Review rule changes with `aegis check --ci`."
        expected_states = {} if change == "removed" else {"reviewed": "served"}
        if change == "new-mandatory":
            expected_states["pending"] = "not_loaded"
        assert {r["name"]: r["service_state"] for r in payload["rules"]} == expected_states
        assert payload["untargeted"] == []
    else:
        assert f"Adaptive rules: {expected_shown} shown, 1 served" in captured.out
        assert f"Context load:   ~{expected_tokens} tokens (pre-JIT max)" in captured.out
        assert scan["rules_base"]["commit"] in captured.out
        assert "Unreviewed rules: 1 total" in captured.out
        assert "Unreviewed rule:" not in captured.out
        assert "No rules found" not in captured.out
        assert "rule(s) apply to no file" not in captured.out


@pytest.mark.parametrize("json_output", [False, True], ids=["text", "json"])
def test_status_cli_without_repository_uses_workspace_policy(tmp_path, capsys, json_output):
    from aegis_cli.cli import main

    rules = tmp_path / ".aegis/rules/invariants"
    rules.mkdir(parents=True)
    text = "---\nid: local\nenforcement: gate\ntarget_paths: ['*.py']\n---\n# Local\n"
    (rules / "local.md").write_bytes(text.encode("utf-8"))
    argv = ["status", "--workspace", str(tmp_path), "--plain"] + (["--json"] if json_output else [])
    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    if json_output:
        payload = json.loads(captured.out)
        assert payload["adaptive_rules"] == payload["adaptive_rules_shown"] == 1
        assert payload["estimated_tokens"] == len(text) // 4
        assert payload["rules"][0]["service_state"] == "served"
        assert "rules_base" not in payload and "unreviewed_counts" not in payload
    else:
        assert "Adaptive rules: 1 shown, 1 served" in captured.out
        assert f"Context load:   ~{len(text) // 4} tokens (pre-JIT max)" in captured.out


@pytest.mark.parametrize("json_output", [False, True], ids=["text", "json"])
@pytest.mark.parametrize("detail", ["cannot read object", "git command timed out"])
def test_status_cli_refuses_unreadable_reviewed_policy(status_policy_repo, monkeypatch, capsys, json_output, detail):
    from types import SimpleNamespace
    from aegis_cli.cli import main
    from aegis_core import gitsafe, rule_integrity

    repo, reviewed = status_policy_repo
    repo.write(".aegis/rules/invariants/reviewed.md", reviewed + "working text\n")

    def refuse(*args, **kwargs):
        raise gitsafe.GitError(detail)

    monkeypatch.setattr(rule_integrity, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "read_blobs": refuse}))
    expected = "the reviewed (base) version of the rules cannot be read, so none is served: " + detail
    argv = ["status", "--workspace", str(repo.root), "--plain"] + (["--json"] if json_output else [])
    assert main(argv) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    if json_output:
        payload = json.loads(captured.out)
        assert payload["status"] == "FAIL"
        assert payload["error"] == expected
        assert payload["adaptive_rules"] == payload["estimated_tokens"] == 0
        assert payload["adaptive_rules_shown"] == 1
        assert payload["rules"][0]["service_state"] == "not_loaded"
    else:
        assert expected in captured.out
        assert "Adaptive rules: 1 shown, 0 served" in captured.out
        assert "Context load:   ~0 tokens (pre-JIT max)" in captured.out


@pytest.mark.parametrize("json_output", [False, True], ids=["text", "json"])
def test_status_cli_rule_error_serves_no_partial_policy(status_policy_repo, capsys, json_output):
    from aegis_cli.cli import main

    repo, reviewed = status_policy_repo
    repo.write(".aegis/rules/invariants/broken.md", reviewed.replace("reviewed", "broken").replace(
        "enforcement: gate\n", "enforcement: gate\nexpired_at: 2026-01-01\n"))
    assert main(["scan", str(repo.root / "src/app.py"), "--workspace", str(repo.root), "--json"]) == 1
    scan = json.loads(capsys.readouterr().out)
    assert scan["rule_errors"][0]["error"] == (
        "expired_at is not allowed on a rank 2+ rule (a gate, an invariant or enforcement: gate): "
        "retire it with a reviewed change, not by expiry"
    )
    argv = ["status", "--workspace", str(repo.root), "--plain"] + (["--json"] if json_output else [])
    assert main(argv) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    if json_output:
        payload = json.loads(captured.out)
        assert payload["adaptive_rules"] == payload["estimated_tokens"] == 0
        assert payload["adaptive_rules_shown"] == 1
        assert payload["rule_errors"] == scan["rule_errors"]
        assert payload["status"] == "FAIL" and payload["error"] == scan["error"]
        assert payload["rules"][0]["service_state"] == "not_loaded"
    else:
        assert "Adaptive rules: 1 shown, 0 served" in captured.out
        assert "Context load:   ~0 tokens (pre-JIT max)" in captured.out
        assert "rule file(s) cannot be loaded" in captured.out


@pytest.mark.parametrize("json_output", [False, True], ids=["text", "json"])
def test_status_cli_redacts_policy_diagnostics_before_truncation(status_policy_repo, monkeypatch, capsys, json_output):
    from types import SimpleNamespace
    from aegis_cli.cli import main
    from aegis_core import gitsafe, rule_integrity

    repo, reviewed = status_policy_repo
    repo.write(".aegis/rules/invariants/pending.md", reviewed.replace("reviewed", "pending").replace(
        "# Reviewed", "# " + "A" * 68 + " token=ghp_" + "B" * 30))
    argv = ["status", "--workspace", str(repo.root), "--plain"] + (["--json"] if json_output else [])
    assert main(argv) == 0
    captured = capsys.readouterr()
    if json_output:
        payload = json.loads(captured.out)
        assert payload["unreviewed_counts"] == {"new": 1, "changed": 0, "broken": 0, "removed": 0}
        assert "unreviewed_rules" not in payload
    else:
        assert "Unreviewed rules: 1 total (new: 1, changed: 0, broken: 0, removed: 0)" in captured.out
    assert "A" * 68 not in captured.out
    assert "ghp_" not in captured.out

    def refuse(*args, **kwargs):
        raise gitsafe.GitError("cannot read object: password=\x1b[31mfixture-secret\x1b[0m " + "Z" * 1200)

    monkeypatch.setattr(rule_integrity, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "read_blobs": refuse}))
    assert main(argv) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "fixture-secret" not in captured.out and "\\u001b" not in captured.out and "\x1b" not in captured.out
    error = json.loads(captured.out)["error"] if json_output else next(
        line.strip().removeprefix("❌ ") for line in captured.out.splitlines() if "cannot read object" in line
    )
    assert error.startswith("the reviewed (base) version of the rules cannot be read, so none is served: "
                            "cannot read object: password=REDACTED ")
    assert len(error) == 1024 and error.endswith("...")


@pytest.mark.parametrize("json_output", [False, True], ids=["text", "json"])
@pytest.mark.parametrize("extra_pending", [0, 10], ids=["short", "over-display-limit"])
def test_status_cli_omits_all_unreviewed_rule_text(
    status_policy_repo, capsys, json_output, extra_pending
):
    from aegis_cli.cli import main

    repo, reviewed = status_policy_repo
    token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    # This is precisely the producer's lossy ESC -> space spelling. The printable
    # filename also exercises the same path on Windows, where ESC names are invalid.
    unsafe_id = "[31m" + token + " [0m"
    removed_path = ".aegis/rules/invariants/" + unsafe_id + ".md"
    repo.write(removed_path, reviewed.replace("id: reviewed\n", ""))
    repo.commit("reviewed rule with unsafe diagnostic identity")
    repo.git("update-ref", "refs/remotes/origin/main", repo.head())
    (repo.root / removed_path).unlink()
    for rule_id in ["Pending_84.v2"] + [f"pending-{index:02}" for index in range(extra_pending)]:
        repo.write(".aegis/rules/invariants/" + rule_id + ".md", reviewed.replace(
            "id: reviewed", "id: " + rule_id).replace("# Reviewed", "# \x1b[31m" + token + "\x1b[0m"))

    argv = ["status", "--workspace", str(repo.root), "--plain"] + (["--json"] if json_output else [])
    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert token not in captured.out
    assert unsafe_id not in captured.out
    assert "\x1b" not in captured.out and "\\u001b" not in captured.out
    if json_output:
        payload = json.loads(captured.out)
        assert payload["unreviewed_total"] == extra_pending + 2
        assert payload["unreviewed_counts"] == {"new": extra_pending + 1, "changed": 0, "broken": 0, "removed": 1}
        assert "unreviewed_rules" not in payload
        assert "unreviewed_unnamed" not in payload
        assert payload["next_action"] == "Review rule changes with `aegis check --ci`."
        assert payload["adaptive_rules"] == 2
        assert payload["adaptive_rules_shown"] == extra_pending + 2
    else:
        assert (f"Unreviewed rules: {extra_pending + 2} total "
                f"(new: {extra_pending + 1}, changed: 0, broken: 0, removed: 1)") in captured.out
        assert "Next action: Review rule changes with `aegis check --ci`." in captured.out
        assert "Unreviewed rule:" not in captured.out


@pytest.mark.parametrize("json_output", [False, True], ids=["text", "json"])
@pytest.mark.parametrize("unsafe_id", ["Well_formed-84.v2", "_leading", "embedded space", "pending+suffix", "A" * 81,
                                       "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"])
def test_status_cli_counts_removed_rules_without_identifiers(status_policy_repo, capsys, json_output, unsafe_id):
    from aegis_cli.cli import main

    repo, reviewed = status_policy_repo
    path = ".aegis/rules/invariants/" + unsafe_id + ".md"
    repo.write(path, reviewed.replace("id: reviewed\n", ""))
    repo.commit("reviewed diagnostic identity")
    repo.git("update-ref", "refs/remotes/origin/main", repo.head())
    (repo.root / path).unlink()
    argv = ["status", "--workspace", str(repo.root), "--plain"] + (["--json"] if json_output else [])

    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert unsafe_id not in captured.out
    if json_output:
        payload = json.loads(captured.out)
        assert "unreviewed_rules" not in payload
        assert payload["unreviewed_total"] == 1
        assert payload["unreviewed_counts"] == {"new": 0, "changed": 0, "broken": 0, "removed": 1}
        assert payload["next_action"] == "Review rule changes with `aegis check --ci`."
    else:
        assert "Unreviewed rule:" not in captured.out
        assert "Unreviewed rules: 1 total (new: 0, changed: 0, broken: 0, removed: 1)" in captured.out
        assert "Next action: Review rule changes with `aegis check --ci`." in captured.out


@pytest.mark.parametrize("json_output", [False, True], ids=["text", "json"])
@pytest.mark.parametrize("escape", ["M", "c"], ids=["reverse-index", "reset"])
def test_status_cli_omits_esc_filename_in_removed_diagnostic(status_policy_repo, capsys, json_output, escape):
    from aegis_cli.cli import main

    if os.name == "nt":
        pytest.skip("Windows forbids ESC in filenames")
    repo, reviewed = status_policy_repo
    token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    path = ".aegis/rules/invariants/\x1b" + escape + token + ".md"
    try:
        repo.write(path, reviewed.replace("id: reviewed\n", ""))
    except OSError as exc:
        if exc.errno in (errno.EINVAL, errno.ENOTSUP):
            pytest.skip("filesystem forbids ESC in filenames")
        raise
    repo.commit("reviewed ESC filename fixture")
    repo.git("update-ref", "refs/remotes/origin/main", repo.head())
    (repo.root / path).unlink()
    argv = ["status", "--workspace", str(repo.root), "--plain"] + (["--json"] if json_output else [])

    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "ghp_" not in captured.out
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" not in captured.out
    assert "\x1b" not in captured.out and "\\u001b" not in captured.out
    if json_output:
        payload = json.loads(captured.out)
        assert "unreviewed_rules" not in payload
        assert payload["unreviewed_counts"] == {"new": 0, "changed": 0, "broken": 0, "removed": 1}
        assert payload["unreviewed_total"] == 1
        assert payload["next_action"] == "Review rule changes with `aegis check --ci`."
        assert payload["adaptive_rules"] == 2
        assert payload["adaptive_rules_shown"] == 1
    else:
        assert "Unreviewed rules: 1 total (new: 0, changed: 0, broken: 0, removed: 1)" in captured.out
        assert "Next action: Review rule changes with `aegis check --ci`." in captured.out


@pytest.mark.parametrize("json_output", [False, True], ids=["text", "json"])
def test_status_cli_counts_every_unreviewed_state_without_titles(status_policy_repo, capsys, json_output):
    from aegis_cli.cli import main

    repo, reviewed = status_policy_repo
    token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    fixture_text = reviewed.replace("id: reviewed\n", "").replace("# Reviewed", "# \x1b[31m" + token + "\x1b[0m")
    for name in ("changed", "broken", "removed"):
        repo.write(f".aegis/rules/invariants/{name}.md", fixture_text)
    repo.commit("reviewed diagnostic state fixtures")
    repo.git("update-ref", "refs/remotes/origin/main", repo.head())
    repo.write(".aegis/rules/invariants/changed.md", fixture_text + "branch-local addition\n")
    repo.write(".aegis/rules/invariants/pending.md", fixture_text)
    (repo.root / ".aegis/rules/invariants/broken.md").write_bytes(b"\xff")
    (repo.root / ".aegis/rules/invariants/removed.md").unlink()
    argv = ["status", "--workspace", str(repo.root), "--plain"] + (["--json"] if json_output else [])

    assert main(argv) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "ghp_" not in captured.out
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" not in captured.out
    if json_output:
        payload = json.loads(captured.out)
        assert "unreviewed_rules" not in payload
        assert payload["unreviewed_counts"] == {"new": 1, "changed": 1, "broken": 1, "removed": 1}
        assert payload["unreviewed_total"] == 4
        assert payload["next_action"] == "Review rule changes with `aegis check --ci`."
        assert payload["status"] == "FAIL"
        assert payload["adaptive_rules"] == payload["estimated_tokens"] == 0
        assert "invalid UTF-8" in payload["error"]
    else:
        assert "Unreviewed rules: 4 total (new: 1, changed: 1, broken: 1, removed: 1)" in captured.out
        assert "Unreviewed rule:" not in captured.out
        assert "Next action: Review rule changes with `aegis check --ci`." in captured.out


@pytest.mark.parametrize("json_output", [False, True], ids=["text", "json"])
@pytest.mark.parametrize(
    "metadata,service_state,calendar_expiry,legacy_expiry",
    [
        ("created: 2020-01-01\nexpiry_days: 30\n", "served", "overdue (2475d)", "overdue (2475d)"),
        ("created: 2026-11-10\nexpiry_days: 30\nexpired_at: 2026-01-01\n",
         "retired", "30d", "expired"),
        ("expiry_days: 30\n", "served", "—", "—"),
        ("created: not-a-date\nexpiry_days: 30\n", "served", "—", "—"),
        ("created: 20200101\nexpiry_days: 30\n", "served", "—", "—"),
        ("created: 20200101.0\nexpiry_days: 30\n", "served", "—", "—"),
        ("created: true\nexpiry_days: 30\n", "served", "—", "—"),
        ("created: [2020-01-01]\nexpiry_days: 30\n", "served", "—", "—"),
        ("created: {year: 2020}\nexpiry_days: 30\n", "served", "—", "—"),
        ("created: '20200101'\nexpiry_days: 30\n", "served", "—", "—"),
        ("created: '2020-W01-1'\nexpiry_days: 30\n", "served", "—", "—"),
        ("created: '2026-11-10T11:59:11Z'\nexpiry_days: 30\n", "served", "30d", "30d"),
        ("created: 2026-11-10\nexpiry_days: '30'\n", "served", "30d", "30d"),
        ("created: 2026-11-10\nexpiry_days: 0\n", "served", "0d", "0d"),
        ("created: 2026-11-10\nexpiry_days: yes\n", "served", "—", "—"),
        ("created: 2026-11-10\nexpiry_days: false\n", "served", "—", "—"),
        ("created: 2026-11-10\nexpiry_days: 30.0\n", "served", "—", "—"),
        ("created: 2026-11-10\nexpiry_days: 30.5\n", "served", "—", "—"),
        ("created: 2026-11-10\nexpiry_days: [30]\n", "served", "—", "—"),
        ("created: 2026-11-10\nexpiry_days: {days: 30}\n", "served", "—", "—"),
        ("created: 2026-11-10\nexpiry_days: -1\n", "served", "—", "—"),
        ("created: 2026-11-10\nexpiry_days: '-1'\n", "served", "—", "—"),
        ("created: 2026-11-10\nexpiry_days: '30days'\n", "served", "—", "—"),
        ("created: 2026-11-10\nexpiry_days: '3_0'\n", "served", "—", "—"),
        ("created: 2026-11-10\nexpiry_days: ''\n", "served", "—", "—"),
        ("created: 2026-11-10\nexpiry_days: '²'\n", "served", "—", "—"),
        ("created: 2020-01-01\nexpiry_days: invalid\n", "served", "—", "—"),
        ("created: 2020-01-01\nexpiry_days: 1.0e+999\nexpired_at: 2026-01-01\n",
         "retired", "—", "expired"),
        ("expiry_days: 30\n", "untargeted", "—", "—"),
    ],
    ids=["old-but-served", "retired", "missing-date", "malformed-date", "integer-date", "float-date", "bool-date",
         "list-date", "mapping-date", "compact-date", "week-date", "timestamp-date", "string-days", "zero-days",
         "bool-days", "false-days", "float-days", "fractional-days", "list-days", "mapping-days", "negative-days",
         "negative-string-days", "non-digit-days", "underscore-days", "empty-days", "non-decimal-days",
         "malformed-days", "retired-overflow",
         "untargeted"],
)
def test_status_cli_service_state_is_independent_of_calendar(
    tmp_path, capsys, json_output, metadata, service_state, calendar_expiry, legacy_expiry
):
    from aegis_cli.cli import main

    rules = tmp_path / ".aegis" / "rules" / "traps"
    rules.mkdir(parents=True)
    targets = "" if service_state == "untargeted" else "target_paths: ['*.py']\n"
    (rules / "example.md").write_text(
        "---\nid: example\n" + targets + metadata + "---\n# Example\n",
        encoding="utf-8",
    )
    argv = ["status", "--workspace", str(tmp_path), "--plain"]
    if json_output:
        argv.append("--json")
    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    if json_output:
        (rule,) = json.loads(captured.out)["rules"]
        assert rule["service_state"] == service_state
        assert rule["calendar_expiry"] == calendar_expiry
        assert rule["expiry"] == legacy_expiry  # Only retirement uses "expired".
        assert rule["state"] == "insufficient"  # Fitness state remains separate.
    else:
        header = next(line for line in captured.out.splitlines() if line.lstrip().startswith("Rule "))
        assert re.split(r" {2,}", header.strip())[-2:] == ["Service state", "Calendar (meta)"]
        row = next(line for line in captured.out.splitlines() if line.lstrip().startswith("example "))
        assert re.split(r" {2,}", row.strip())[-2:] == [service_state, calendar_expiry]
        if service_state == "served":
            assert "expired" not in row


@pytest.mark.parametrize("json_output", [False, True], ids=["text", "json"])
def test_status_cli_packaged_guidance_is_not_loaded(tmp_path, monkeypatch, capsys, json_output):
    from aegis_cli.cli import main
    import aegis_cli.init as init_module

    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    core = tmp_path / "rules"
    core.mkdir()
    (core / "guide.md").write_text("---\nid: guide\n---\n# Guidance\n", encoding="utf-8")
    monkeypatch.setattr(init_module, "packaged_dir", lambda name: core)
    monkeypatch.setattr(init_module, "packaged_rules", lambda: {"guide": core / "guide.md"})
    argv = ["status", "--workspace", str(tmp_path), "--plain"]
    if json_output:
        argv.append("--json")
    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    if json_output:
        (rule,) = json.loads(captured.out)["rules"]
        assert rule["service_state"] == "not_loaded"
        assert rule["calendar_expiry"] == rule["expiry"] == "∞ (core)"
    else:
        assert "Core rules:     1 shown, 0 served (shipped; not_loaded: scan and check do not read them)" in captured.out
        row = next(line for line in captured.out.splitlines() if line.lstrip().startswith("guide "))
        assert re.split(r" {2,}", row.strip())[-2:] == ["not_loaded", "∞ (core)"]


def test_status_cli_project_summary_explains_omitted_core_rules(tmp_path, monkeypatch, capsys):
    from aegis_cli.cli import main
    import aegis_cli.init as init_module

    workspace = tmp_path / "project"
    (workspace / ".aegis" / "rules").mkdir(parents=True)
    packaged = tmp_path / "package" / "rules"
    packaged.mkdir(parents=True)
    guide = packaged / "guide.md"
    guide.write_text("---\nid: guide\n---\n# Guidance\n", encoding="utf-8")
    monkeypatch.setattr(init_module, "packaged_dir", lambda name: packaged)
    monkeypatch.setattr(init_module, "packaged_rules", lambda: {"guide": guide})

    assert main(["status", "--workspace", str(workspace), "--plain"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    summary = next(line for line in captured.out.splitlines() if "Core rules:" in line)
    assert summary == "  Core rules:     listed only in the Aegis checkout (scan and check do not read them)"


@pytest.mark.parametrize("json_output", [False, True], ids=["text", "json"])
def test_status_cli_calendar_uses_current_clock_on_each_call(tmp_path, monkeypatch, capsys, json_output):
    from aegis_cli.cli import main

    rules = tmp_path / ".aegis" / "rules" / "traps"
    rules.mkdir(parents=True)
    (rules / "example.md").write_text(
        "---\nid: example\ntarget_paths: ['*.py']\ncreated: 2030-01-31\nexpiry_days: 30\n---\n# Example\n",
        encoding="utf-8",
    )
    argv = ["status", "--workspace", str(tmp_path), "--plain"]
    if json_output:
        argv.append("--json")
    for today, expected in [(date(2030, 2, 1), "29d"), (date(2030, 2, 2), "28d")]:
        monkeypatch.setattr("aegis_cli.status._today", lambda: today)
        assert main(argv) == 0
        captured = capsys.readouterr()
        assert captured.err == ""
        if json_output:
            (rule,) = json.loads(captured.out)["rules"]
            assert rule["calendar_expiry"] == rule["expiry"] == expected
            assert rule["service_state"] == "served"
        else:
            row = next(line for line in captured.out.splitlines() if line.lstrip().startswith("example "))
            assert re.split(r" {2,}", row.strip())[-2:] == ["served", expected]


class TestStatus:
    """Test suite for the aegis status subcommand."""

    def test_status_output_no_biology_terms(self, tmp_path, capsys):
        from aegis_core.telemetry_engine import ledger
        from tests.contract.test_legacy_ratchet import REQUIRED_WORDS, _word_counts

        rules = tmp_path / ".aegis/rules/traps"
        rules.mkdir(parents=True)
        (rules / "rule-a.md").write_text("---\nid: rule-a\ntype: trap\n---\nBody\n")
        ledger.append(tmp_path, [{"rule": "rule-a", "outcome": "tp", "source": "ci", "key": "k1"}])
        assert run_status(argparse.Namespace(_root=tmp_path)) == 0
        out = capsys.readouterr().out
        assert "Aegis Workspace Status" in out and "rule-a" in out
        assert not any(_word_counts([out], REQUIRED_WORDS).values()), out

    def test_status_no_rules(self, tmp_path, capsys):
        """Empty projects explain where core rules are listed and give a helpful message."""
        (tmp_path / "rules").mkdir()
        (tmp_path / ".aegis" / "rules").mkdir(parents=True)
        args = argparse.Namespace(_root=tmp_path)
        ret = run_status(args)
        assert ret == 0
        captured = capsys.readouterr()
        assert "Core rules:     listed only in the Aegis checkout (scan and check do not read them)" in captured.out
        assert "No rules found" in captured.out

    def test_status_counts_core_rules(self, capsys):
        """In the Aegis checkout, core rules are the shipped ones: what init's one locator sees."""
        from aegis_cli.init import packaged_rules

        args = argparse.Namespace(_root=REPO_ROOT, json=True)
        assert run_status(args) in (0, 1)  # the checkout's own rules may need attention
        payload = json.loads(capsys.readouterr().out)
        assert payload["core_rules"] == 0 and payload["core_rules_shown"] == len(packaged_rules()) == 12
        core = {r["name"] for r in payload["rules"] if r["type"] == "core"}
        assert {"providence", "testing", "tdd-protocol"} <= core and "META" not in core

    def test_a_workspaces_own_rule_directories_are_never_listed_as_core(self, tmp_path, capsys):
        """Release review: status read <workspace>/rules (or rules/) as Aegis's shipped
        rules, so a project's own markdown was listed and counted as active core rules."""
        marker = tmp_path / "PLANTED_RAN"
        for name in ("rules", "project_rules"):
            (tmp_path / name).mkdir()
            (tmp_path / name / "pricing.md").write_text("# Pricing\n" + "x" * 400)
            (tmp_path / name / "__init__.py").write_text(f"open({str(marker)!r}, 'w').write('x')\n")
        (tmp_path / ".aegis" / "rules").mkdir(parents=True)
        assert run_status(argparse.Namespace(_root=tmp_path)) == 0
        out = capsys.readouterr().out
        assert "Core rules:     listed only in the Aegis checkout (scan and check do not read them)" in out
        assert "pricing" not in out
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
        assert "Adaptive rules: 2 shown, 0 served" in captured.out
        assert ".aegis/rules/notes.md: not a rule: it is not in a rule type directory" in captured.out
        assert "README" not in captured.out

    def test_status_lists_rules_that_cannot_be_loaded_and_exits_1(self, tmp_path, capsys):
        """Nothing is excluded unseen: scan refuses these, so status names them."""
        rules = tmp_path / ".aegis" / "rules"
        (rules / "traps").mkdir(parents=True)
        (rules / "unsupported").mkdir()
        (rules / "traps" / "ok.md").write_text("---\nid: ok\n---\n")
        (rules / "unsupported" / "old.md").write_text("---\nid: old\ntype: invariant\n---\n")

        assert run_status(argparse.Namespace(_root=tmp_path)) == 1
        out = capsys.readouterr().out
        assert "1 rule file(s) cannot be loaded; aegis scan fails until they are fixed:" in out
        assert ".aegis/rules/unsupported/old.md: not served: unsupported/ is not a rule type directory" in out
        assert "Adaptive rules: 1 shown, 0 served" in out

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
            {"rule_id": "rule-a", "signal": "trigger", "timestamp": "2026-09-30T12:00:00Z"},
            {"rule_id": "rule-a", "signal": "trigger", "timestamp": "2026-09-30T12:01:00Z"},
            {"rule_id": "rule-a", "signal": "trigger", "timestamp": "2026-09-30T12:02:00Z"},
            {"rule_id": "rule-b", "signal": "trigger", "timestamp": "2026-09-30T12:03:00Z"},
        ]
        state = tmp_path / ".aegis" / "state"
        state.mkdir(parents=True)
        (state / "ledger.jsonl").write_text(
            "\n".join(json.dumps(r) for r in records) + "\n"
        )
        legacy_records = [
            {"rule_id": "rule-a"},
            {"rule_id": "rule-b"},
            {"rule_id": "rule-b"},
            {"rule_id": "rule-b"},
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
        assert "~0 tokens (pre-JIT max)" in captured.out

    def test_status_adaptive_rule_expiry_active(self, tmp_path, capsys):
        """Active adaptive rules show service state; JSON keeps calendar metadata."""
        rules = tmp_path / ".aegis" / "rules" / "traps"
        rules.mkdir(parents=True)
        created = (_STATUS_TODAY - timedelta(days=10)).isoformat()
        (rules / "pattern.md").write_text(
            f"---\ncreated: {created}\nexpiry_days: 30\ntarget_paths: ['*.py']\n---\n# Pattern\n"
        )

        args = argparse.Namespace(_root=tmp_path)
        ret = run_status(args)
        assert ret == 0
        captured = capsys.readouterr()
        row = next(line for line in captured.out.splitlines() if line.lstrip().startswith("pattern "))
        assert re.split(r" {2,}", row.strip())[-2:] == ["served", "20d"]
        assert run_status(argparse.Namespace(_root=tmp_path, json=True)) == 0
        (rule,) = json.loads(capsys.readouterr().out)["rules"]
        assert rule["calendar_expiry"] == rule["expiry"] == "20d"

    def test_status_adaptive_rule_past_calendar_expiry_is_still_served(self, tmp_path, capsys):
        """A past calendar deadline does not retire an adaptive rule."""
        rules = tmp_path / ".aegis" / "rules" / "traps"
        rules.mkdir(parents=True)
        created = (_STATUS_TODAY - timedelta(days=40)).isoformat()
        (rules / "stale.md").write_text(
            f"---\ncreated: {created}\nexpiry_days: 30\ntarget_paths: ['*.py']\n---\n# Stale\n"
        )

        args = argparse.Namespace(_root=tmp_path)
        ret = run_status(args)
        assert ret == 0
        captured = capsys.readouterr()
        row = next(line for line in captured.out.splitlines() if line.lstrip().startswith("stale "))
        assert re.split(r" {2,}", row.strip())[-2:] == ["served", "overdue (10d)"]
        assert "expired" not in captured.out

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

    def test_status_branded_aegis_header(self, tmp_path, capsys):
        """Status prints the Aegis header and token bar using current terminology."""
        from tests.contract.test_legacy_ratchet import REQUIRED_WORDS, _word_counts
        (tmp_path / "rules").mkdir()
        (tmp_path / ".aegis" / "rules").mkdir(parents=True)
        args = argparse.Namespace(_root=tmp_path)
        ret = run_status(args)
        assert ret == 0
        out = capsys.readouterr().out
        assert "Aegis Workspace Status" in out
        assert "Token budget:" in out
        assert not any(_word_counts([out], REQUIRED_WORDS).values())
        assert "aegis init" in out

    def test_status_groups_rules_by_type_and_colors_fitness(self, tmp_path, capsys):
        """v3.0.0: rules are grouped by modern rule type with colored fitness in TTY and zero ANSI in plain mode."""
        from aegis_cli.ui.theme import OutputContext
        from tests.contract.test_legacy_ratchet import REQUIRED_WORDS, _word_counts

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
        assert not any(_word_counts([out_tty], REQUIRED_WORDS).values())

        plain_ui = OutputContext(color_enabled=False, emoji_enabled=False, plain=True)
        args_plain = argparse.Namespace(_root=tmp_path, plain=True, ui=plain_ui)
        assert run_status(args_plain) == 0
        out_plain = capsys.readouterr().out
        assert "\x1b[" not in out_plain
        assert not any(_word_counts([out_plain], REQUIRED_WORDS).values())


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


# ── Pins: what run_status prints, in order (R-cli-a1; goldens recorded before the split) ──


def _pinned_workspace(tmp_path, monkeypatch):
    """PIN-1's workspace: the old-but-served traps t-one and t-two, the gate invariant i-one, the trap
    legacy with derived counters, invariants/old.md, notes.md, blocked guard events for claude-code
    twice and codex-cli once plus one recorded event, ledger rows, a claimed report, an agent
    suggestion in the user's insights log and one core rule."""
    import aegis_cli.init as init_module
    from aegis_core import events
    from aegis_core.insights import insights_path
    from aegis_core.telemetry_engine import ledger

    ws = tmp_path / "ws"
    rules = ws / ".aegis" / "rules"
    for kind in ("traps", "invariants", "unsupported"):
        (rules / kind).mkdir(parents=True)
    (rules / "traps" / "t-one.md").write_bytes(
        b"---\nid: t-one\ncreated: 2020-01-01\nexpiry_days: 30\ntarget_paths: ['src/*.py']\n---\n# One\n")
    (rules / "traps" / "t-two.md").write_bytes(b"---\nid: t-two\ncreated: 2020-01-01\nexpiry_days: 30\n---\n# Two\n")
    (rules / "invariants" / "i-one.md").write_bytes(
        b"---\nid: i-one\nenforcement: gate\ntarget_paths: ['src/*.py']\n---\n# Gate\n")
    (rules / "traps" / "legacy.md").write_bytes(b"---\nid: legacy\nfitness:\n  score: 0.9\ntriggers: 12\n---\n# Old\n")
    (rules / "unsupported" / "old.md").write_bytes(b"---\nid: old\ntype: invariant\n---\n")
    (rules / "notes.md").write_bytes(b"# Not a rule\n")
    for host in ("claude-code", "claude-code", "codex-cli"):
        events.append(ws, "guard_match", "block", {"rule": "git-safety", "tier": "block", "action": "block"}, host=host)
    events.append(ws, "guard_match", "record", {"rule": "git-safety", "tier": "record", "action": "record"},
                  host="claude-code")
    # The core rule is looked up by its id before its file name: two rows count, not one.
    ledger.append(ws, [{"rule": "core-one", "outcome": "tp", "source": "ci", "key": "c1"},
                       {"rule": "core-one", "outcome": "tp", "source": "ci", "key": "c2"},
                       {"rule": "core-file", "outcome": "tp", "source": "ci", "key": "c3"},
                       {"rule": "t-two", "outcome": "tp", "source": "ci", "key": "t1"}])
    ledger.append_rows(ws, [{"v": ledger.LEDGER_VERSION, "ts": "2026-10-01T00:00:00Z", "event": "claimed",
                             "witness": "self", "tree": "a" * 40, "source": "mcp", "session": "s1",
                             "host": "claude-code", "key": "claim:claude-code/s1:" + "a" * 40,
                             "report_key": "mcp:claude-code/s1:r1", "result": "success"}])
    log = insights_path(ws)
    log.parent.mkdir(parents=True)
    log.write_bytes(b'{"v": 1, "event": "insight", "source": "mcp", "id": "s-1"}\n')
    # Core rules are listed only in the checkout they ship from; this workspace stands in for it.
    core = ws / "rules"
    core.mkdir()
    (core / "core-file.md").write_bytes(b"---\nid: core-one\n---\n# Core\n")
    monkeypatch.setattr(init_module, "packaged_dir", lambda name: core)
    monkeypatch.setattr(init_module, "packaged_rules", lambda: {"core-one": core / "core-file.md"})
    monkeypatch.setenv("COLUMNS", "120")
    return ws


def _adaptive(name: str, kind: str, triggers: int, expiry: str, service_state: str) -> dict:
    """One adaptive rule of the pinned JSON, every key in the order run_status writes them."""
    return {"name": name, "type": kind, "score": None, "state": "insufficient",
            "status_label": f"insufficient (n={triggers})", "evidence_available": True, "evidence_error": None,
            "contested": 0, "override_rate": 0.0, "flagged_for_review": False, "triggers": triggers,
            "expiry": expiry, "is_core": False, "service_state": service_state, "calendar_expiry": expiry}


_PIN_RULE_REFUSAL = (
    "1 rule file(s) cannot be served, so no partial rule set is returned: "
    ".aegis/rules/unsupported/old.md: not served: unsupported/ is not a rule type directory "
    "(expected .aegis/rules/<boundaries, contracts, gates, invariants, personas, traps>/<id>.md). "
    "Fix or move them; `aegis status` lists them."
)


PIN_TEXT = (
    "Aegis Workspace Status\n"
    "\n"
    "  Core rules:     1 shown, 0 served (shipped; not_loaded: scan and check do not read them)\n"
    "  Adaptive rules: 4 shown, 0 served\n"
    "  Context load:   ~0 tokens (pre-JIT max)\n"
    "  Token budget:   [--------------------] 0/2,000 (0%)\n"
    "  Last sync:      never (run aegis sync)\n"
    "\n"
    "  1 unconfirmed agent suggestions (not counted)\n"
    "\n"
    "  Blocked cmds:   3 (hook-observed: claude-code: 2, codex-cli: 1)\n"
    "\n"
    "  claimed (unwitnessed): 1 report(s) from 1 session(s), no rule's evidence\n"
    "\n"
    f"  ❌ {_PIN_RULE_REFUSAL}\n"
    "  ❌ 1 rule file(s) cannot be loaded; aegis scan fails until they are fixed:\n"
    "     .aegis/rules/unsupported/old.md: not served: unsupported/ is not a rule type directory (expected .aegis/rules/...\n"
    "  ⚠️  1 rule file(s) still carry derived counters or retired v3 keys (ignored; run aegis migrate --apply to "
    "strip them):\n"
    "     .aegis/rules/traps/legacy.md: fitness, triggers\n"
    "  ℹ️  1 file(s) under .aegis/rules are not rules:\n"
    "     .aegis/rules/notes.md: not a rule: it is not in a rule type directory\n"
    "\n"
    "  Rule      Triggers  Type       Fitness             Service state  Calendar (meta)\n"
    "  --------  --------  ---------  ------------------  -------------  ---------------\n"
    "  core-one  2         core       —                   not_loaded     ∞ (core)       \n"
    "  --------  --------  ---------  ------------------  -------------  ---------------\n"
    "  i-one     0         invariant  insufficient (n=0)  not_loaded     —              \n"
    "  --------  --------  ---------  ------------------  -------------  ---------------\n"
    "  t-two     1         trap       insufficient (n=1)  not_loaded     overdue (2475d)\n"
    "  legacy    0         trap       insufficient (n=0)  not_loaded     —              \n"
    "  t-one     0         trap       insufficient (n=0)  not_loaded     overdue (2475d)\n"
)

PIN_JSON = {
    "core_rules": 0,
    "adaptive_rules": 0,
    "estimated_tokens": 0,
    "rules": [
        {"name": "core-one", "type": "core", "score": None, "triggers": 2, "expiry": "∞ (core)", "is_core": True,
         "service_state": "not_loaded", "calendar_expiry": "∞ (core)"},
        _adaptive("i-one", "invariant", 0, "—", "not_loaded"),
        _adaptive("t-two", "trap", 1, "overdue (2475d)", "not_loaded"),
        _adaptive("legacy", "trap", 0, "—", "not_loaded"),
        _adaptive("t-one", "trap", 0, "overdue (2475d)", "not_loaded"),
    ],
    "last_sync": None,
    "inventory_error": None,
    "ledger": {"skipped_lines": [], "unusable_rows": 0, "error": None, "torn_tail": False},
    "claimed": {"label": "claimed (unwitnessed)", "claimed": 1, "sessions": 1},
    "blocked_commands": {"total": 3, "by_host": {"claude-code": 2, "codex-cli": 1}, "source": "hook-observed",
                         "label": "hook-observed"},
    "insights": {"rules": [], "unconfirmed_suggestions": 1,
                 "denominator": "sessions = all heartbeat-alive sessions in this workspace (not scope-filtered)"},
    "rule_errors": [{"path": ".aegis/rules/unsupported/old.md",
                     "error": "not served: unsupported/ is not a rule type directory "
                              "(expected .aegis/rules/<boundaries, contracts, gates, invariants, personas, traps>/<id>.md)"}],
    "ignored": [{"path": ".aegis/rules/notes.md", "reason": "not a rule: it is not in a rule type directory"}],
    "stale_rules": [],
    "needs_migrate": [{"path": ".aegis/rules/traps/legacy.md", "keys": ["fitness", "triggers"]}],
    "untargeted": [],
    "core_rules_shown": 1,
    "adaptive_rules_shown": 4,
    "status": "FAIL",
    "error": _PIN_RULE_REFUSAL,
}

PIN_EMPTY_TEXT = (
    "Aegis Workspace Status\n"
    "\n"
    "  Core rules:     listed only in the Aegis checkout (scan and check do not read them)\n"
    "  Adaptive rules: 0 shown, 0 served\n"
    "  Context load:   ~0 tokens (pre-JIT max)\n"
    "  Token budget:   [--------------------] 0/2,000 (0%)\n"
    "  Last sync:      never (run aegis sync)\n"
    "\n"
    "  No rules found. Run 'aegis init' to set up governance rules.\n"
)


class TestStatusPins:
    """Characterization pins, updated for RF-45's service-state column and additive JSON fields."""

    def test_the_text_view_prints_every_section_in_its_fixed_order(self, tmp_path, monkeypatch, capsys):
        ws = _pinned_workspace(tmp_path, monkeypatch)
        assert run_status(argparse.Namespace(_root=ws, plain=True)) == 1
        captured = capsys.readouterr()
        assert captured.out == PIN_TEXT
        assert captured.err == ""

    def test_json_keeps_its_key_order_and_never_reads_an_input_of_the_text_view(self, tmp_path, monkeypatch, capsys):
        ws = _pinned_workspace(tmp_path, monkeypatch)

        def text_view_only(*args, **kwargs):
            raise AssertionError("the JSON view read an input of the text view")

        monkeypatch.setattr("aegis_core.config.jit_max_tokens", text_view_only)
        monkeypatch.setattr("aegis_cli.ui.theme.OutputContext.from_env_and_args", text_view_only)
        assert run_status(argparse.Namespace(_root=ws, json=True)) == 1
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert list(payload) == ["core_rules", "adaptive_rules", "estimated_tokens", "rules", "last_sync",
                                 "inventory_error", "ledger", "claimed", "blocked_commands", "insights",
                                 "rule_errors", "ignored", "stale_rules", "needs_migrate", "untargeted",
                                 "core_rules_shown", "adaptive_rules_shown", "status", "error"]
        assert [r["name"] for r in payload["rules"]] == ["core-one", "i-one", "t-two", "legacy", "t-one"]
        assert captured.out == json.dumps(PIN_JSON, indent=2) + "\n"
        assert captured.err == ""

    def test_an_empty_rules_directory_says_no_rules_found_and_exits_0(self, tmp_path, monkeypatch, capsys):
        (tmp_path / ".aegis" / "rules").mkdir(parents=True)
        monkeypatch.setenv("COLUMNS", "120")
        assert run_status(argparse.Namespace(_root=tmp_path, plain=True)) == 0
        assert capsys.readouterr().out == PIN_EMPTY_TEXT

    def test_a_symlinked_rule_type_directory_is_an_inventory_error_in_both_views(self, tmp_path, capsys):
        from conftest import symlink_or_skip

        rules = tmp_path / ".aegis" / "rules"
        rules.mkdir(parents=True)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "t-out.md").write_bytes(b"---\nid: t-out\n---\n# Out\n")
        symlink_or_skip(elsewhere, rules / "traps", target_is_directory=True)

        assert run_status(argparse.Namespace(_root=tmp_path, plain=True)) == 1
        lines = capsys.readouterr().out.splitlines()
        (error,) = [line for line in lines if "cannot be read safely" in line]
        assert error.startswith("  ❌ The rules directory cannot be read safely: ")
        assert lines.index(error) > lines.index("  Last sync:      never (run aegis sync)")
        assert lines[-1] == "  No rules found. Run 'aegis init' to set up governance rules."
        assert "t-out" not in "\n".join(lines)

        assert run_status(argparse.Namespace(_root=tmp_path, json=True)) == 1
        payload = json.loads(capsys.readouterr().out)
        assert isinstance(payload["inventory_error"], str) and payload["inventory_error"]
        assert (payload["adaptive_rules"], payload["rules"], payload["rule_errors"]) == (0, [], [])

    def test_a_claimed_report_alone_prints_the_claimed_line_and_no_blocked_line(self, tmp_path, capsys):
        from aegis_core.telemetry_engine import ledger

        (tmp_path / ".aegis" / "rules").mkdir(parents=True)
        ledger.append_rows(tmp_path, [{"v": ledger.LEDGER_VERSION, "ts": "2026-10-01T00:00:00Z", "event": "claimed",
                                       "witness": "self", "tree": "b" * 40, "source": "mcp", "session": "s2",
                                       "host": "codex-cli", "key": "claim:codex-cli/s2:" + "b" * 40,
                                       "report_key": "mcp:codex-cli/s2:r1", "result": "failure"}])
        assert run_status(argparse.Namespace(_root=tmp_path, plain=True)) == 0
        lines = capsys.readouterr().out.splitlines()
        claimed = "  claimed (unwitnessed): 1 report(s) from 1 session(s), no rule's evidence"
        assert lines[lines.index(claimed) - 2:lines.index(claimed) + 2] == [
            "  Last sync:      never (run aegis sync)", "", claimed, ""]
        assert not [line for line in lines if "Blocked cmds:" in line]

    def test_blocked_commands_print_before_the_claimed_line(self, tmp_path, capsys):
        from aegis_core import events
        from aegis_core.telemetry_engine import ledger

        (tmp_path / ".aegis" / "rules").mkdir(parents=True)
        events.append(tmp_path, "guard_match", "block", {"rule": "git-safety", "tier": "block", "action": "block"},
                      host="codex-cli")
        ledger.append_rows(tmp_path, [{"v": ledger.LEDGER_VERSION, "ts": "2026-10-01T00:00:00Z", "event": "claimed",
                                       "witness": "self", "tree": "c" * 40, "source": "mcp", "session": "s3",
                                       "host": "codex-cli", "key": "claim:codex-cli/s3:" + "c" * 40,
                                       "report_key": "mcp:codex-cli/s3:r1", "result": "success"}])
        assert run_status(argparse.Namespace(_root=tmp_path, plain=True)) == 0
        lines = capsys.readouterr().out.splitlines()
        start = lines.index("  Last sync:      never (run aegis sync)")
        assert lines[start + 1:start + 6] == [
            "", "  Blocked cmds:   1 (hook-observed: codex-cli: 1)", "",
            "  claimed (unwitnessed): 1 report(s) from 1 session(s), no rule's evidence", ""]

    def test_an_incomplete_ledger_is_named_before_the_rule_table(self, tmp_path, monkeypatch, capsys):
        from aegis_core.telemetry_engine import ledger

        traps = tmp_path / ".aegis" / "rules" / "traps"
        traps.mkdir(parents=True)
        (traps / "t-one.md").write_bytes(b"---\nid: t-one\ntarget_paths: ['src/*.py']\n---\n# One\n")
        ledger.append(tmp_path, [{"rule": "t-one", "outcome": "tp", "source": "ci", "key": "k1"}])
        with ledger.ledger_path(tmp_path).open("ab") as fh:
            fh.write(b"{garbled\n")
        monkeypatch.setenv("COLUMNS", "120")
        assert run_status(argparse.Namespace(_root=tmp_path, plain=True)) == 0
        lines = capsys.readouterr().out.splitlines()
        start = lines.index("  Last sync:      never (run aegis sync)")
        assert lines[start + 1:] == [
            "",
            "  ⚠️  The ledger is incomplete (1 unreadable line(s)): fitness counts only the rows that could be read, "
            "so moves that rely on it (sync --apply, rule archive, tier changes) are refused",
            "",
            "  Rule   Triggers  Type  Fitness               Service state  Calendar (meta)",
            "  -----  --------  ----  --------------------  -------------  ---------------",
            "  t-one  1         trap  evidence unavailable  served         —              ",
        ]
