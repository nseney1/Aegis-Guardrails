"""The supported migration CLI preserves its state-mode reporting."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat

import pytest

from aegis_cli.cli import main


def test_migrate_help_preserves_the_deferred_cli_contract(capsys):
    snapshot = Path(__file__).resolve().parents[2] / "contract/cli_tree.json"
    description = json.loads(snapshot.read_text())["parser"]["commands"]["migrate"]["description"]
    with pytest.raises(SystemExit) as status:
        main(["migrate", "--help"])
    assert status.value.code == 0
    text = " ".join(capsys.readouterr().out.split())
    assert " ".join(description.split()) in text


def test_refusal_documentation_allows_state_lock_bookkeeping():
    from aegis_cli import migrate

    assert "1 refused (no rule, config.json or .aegis/.gitignore was changed:" in migrate.__doc__
    assert "state directory and its lock may be created" in migrate.__doc__


def test_config_that_grows_before_apply_refuses_with_exit_1(tmp_path, monkeypatch, capsys):
    from aegis_core import migrate
    from aegis_core.config import MAX_CONFIG_BYTES

    source = tmp_path / ".aegis/rules/traps/t.md"
    source.parent.mkdir(parents=True)
    original = b"---\nid: t\ntype: trap\nscore: 0.4\n---\nBody\n"
    source.write_bytes(original)
    real_plan = migrate.plan

    def grow_after_planning(root):
        planned = real_plan(root)
        (tmp_path / ".aegis/config.json").write_bytes(b"x" * (MAX_CONFIG_BYTES + 1))
        return planned

    monkeypatch.setattr(migrate, "plan", grow_after_planning)
    assert main(["migrate", "--json", "--workspace", str(tmp_path), "--apply"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "refused"
    assert report["refusal"] == (
        f".aegis/config.json exceeds {MAX_CONFIG_BYTES} bytes; "
        "no rule, config.json or .aegis/.gitignore was changed"
    )
    assert source.read_bytes() == original


def test_config_read_failure_during_apply_is_a_refusal_without_echo(tmp_path, monkeypatch, capsys):
    source = tmp_path / ".aegis/rules/traps/t.md"
    source.parent.mkdir(parents=True)
    original = b"---\nid: t\ntype: trap\nscore: 0.4\n---\nBody\n"
    source.write_bytes(original)
    config = tmp_path / ".aegis/config.json"
    config.write_text('{"v": 1}', encoding="utf-8")
    real_open = os.open

    def deny_config(path, *args, **kwargs):
        if Path(path) == config:
            raise PermissionError("HOSTILE_MARKER")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", deny_config)
    assert main(["migrate", "--json", "--workspace", str(tmp_path), "--apply"]) == 1
    output = capsys.readouterr().out
    report = json.loads(output)
    assert "HOSTILE_MARKER" not in output
    assert report["status"] == "refused"
    assert report["refusal"] == (
        "workspace inputs could not be read; no rule, config.json or .aegis/.gitignore was changed"
    )
    assert source.read_bytes() == original


def test_default_pending_dry_run_writes_nothing_then_apply_is_idempotent(tmp_path, capsys):
    source = tmp_path / ".aegis/rules/traps/t.md"
    source.parent.mkdir(parents=True)
    original = b"---\nid: t\ntype: trap\nscore: 0.4\n---\nBody\n"
    source.write_bytes(original)
    before = {path.relative_to(tmp_path).as_posix(): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert main(["migrate", "--workspace", str(tmp_path)]) == 0
    assert "dry run: nothing written" in capsys.readouterr().out
    assert {path.relative_to(tmp_path).as_posix(): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()} == before
    assert main(["migrate", "--json", "--workspace", str(tmp_path), "--apply"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "applied" and report["config"] == {"v": 1}
    assert json.loads((tmp_path / ".aegis/config.json").read_text()) == {"v": 1}
    assert source.read_bytes() == original.replace(b"score: 0.4\n", b"")
    backups = list((tmp_path / ".aegis/state").glob("migrate-backup-*"))
    assert len(backups) == 1
    assert main(["migrate", "--json", "--workspace", str(tmp_path), "--apply"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "up_to_date"
    assert list((tmp_path / ".aegis/state").glob("migrate-backup-*")) == backups


def test_state_entry_link_refuses_both_cli_modes_with_nothing_pending(tmp_path, capsys):
    from tests.conftest import symlink_or_skip

    state = tmp_path / ".aegis/state"
    state.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_text("unchanged")
    symlink_or_skip(outside, state / "entry")
    for flags in ([], ["--apply"]):
        assert main(["migrate", "--json", "--workspace", str(tmp_path), *flags]) == 1
        report = json.loads(capsys.readouterr().out)
        assert report["status"] == "refused" and ".aegis/state/entry is a symlink" in report["refusal"]


def test_apply_and_dry_run_together_is_a_usage_error(tmp_path, capsys):
    (tmp_path / ".aegis/rules").mkdir(parents=True)
    assert main(["migrate", "--workspace", str(tmp_path), "--apply", "--dry-run"]) == 2
    assert "mutually exclusive" in capsys.readouterr().err
    assert not (tmp_path / ".aegis/state").exists()


def test_a_refusal_found_only_when_applying_is_a_json_report_and_exit_1(tmp_path, capsys, monkeypatch):
    from aegis_core import migrate
    from tests.conftest import symlink_or_skip

    root = tmp_path / "repo"
    rule = root / ".aegis/rules/traps/t.md"
    rule.parent.mkdir(parents=True)
    rule.write_text("---\nid: t\ntype: trap\nscore: 0.4\n---\nBody\n")
    before = rule.read_bytes()
    outside = tmp_path / "outside"
    outside.mkdir()
    real_plan = migrate.plan

    def plan_then_a_link_is_planted(workspace):
        planned = real_plan(workspace)
        state = root / ".aegis/state"
        state.mkdir()
        symlink_or_skip(outside / "lock", state / "lock")
        return planned

    monkeypatch.setattr(migrate, "plan", plan_then_a_link_is_planted)
    assert main(["--json", "migrate", "--workspace", str(root), "--apply"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "refused" and "lock: it is a symlink" in report["refusal"]
    assert list(outside.iterdir()) == []
    assert rule.read_bytes() == before


def test_modern_workspace_dry_run_is_idempotent(tmp_path, capsys):
    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    for flags in ([], ["--dry-run"], ["--apply"]):
        assert main(["migrate", "--json", "--workspace", str(tmp_path), *flags]) == 0
        report = json.loads(capsys.readouterr().out)
        assert report["status"] == "up_to_date"
        assert report["backup"] is None
        assert report["rules"] == []


def test_applied_worktree_merge_reports_its_backup_and_preserves_the_ignore_file(tmp_path, capsys):
    from tests import helpers_humangate as hg
    from aegis_core.telemetry_engine import ledger

    repo = hg.make_repo(tmp_path)
    source = repo.root / ".aegis" / "state" / "ledger.jsonl"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(json.dumps({"v": 2, "ts": "2026-10-01T00:00:00Z", "seq": 1,
                                  "rule": "trap-x", "outcome": "tp", "source": "ci", "key": "k1"}) + "\n")
    ignore = repo.root / ".aegis" / ".gitignore"
    before = b"# user notes\n"
    ignore.write_bytes(before)

    assert main(["migrate", "--workspace", str(repo.root), "--apply"]) == 0

    out = capsys.readouterr().out
    assert "migrated" in out and "backup:" in out and "dry run" not in out
    (backup,) = source.parent.glob("migrate-backup-*")
    assert (backup / ".aegis" / ".gitignore").read_bytes() == before
    assert "state/" in ignore.read_text()
    assert [(row["rule"], row["key"]) for row in ledger.read(repo.root).rows] == [("trap-x", "k1")]


# ── R-cli-38: --apply reports the modes it tightened ─────────────────────────

posix_git = pytest.mark.skipif(os.name == "nt" or shutil.which("git") is None,
                               reason="POSIX permission bits and git")


@pytest.fixture
def loose_ledger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Given a v4 git workspace whose shared ledger is 0666."""
    from aegis_core import storage
    from tests import helpers_humangate as hg

    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(tmp_path / "home"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    repo = hg.make_repo(tmp_path)
    site = storage.ledger_site(repo.root)
    storage.append_jsonl(site.path, [{"v": 2}])
    os.chmod(site.path, 0o666)
    return repo.root, site.path


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@posix_git
def test_apply_says_it_tightened_the_loose_state_and_a_second_apply_says_nothing(loose_ledger, capsys):
    root, ledger = loose_ledger
    assert main(["migrate", "--workspace", str(root), "--apply"]) == 0
    out = capsys.readouterr().out
    assert _mode(ledger) == 0o600
    assert "state modes: tightened 1 of 1 loose entries" in out
    assert "looser" not in out and "tightens them" not in out

    assert main(["migrate", "--workspace", str(root), "--apply"]) == 0
    assert "state modes" not in capsys.readouterr().out


@posix_git
def test_a_dry_run_offers_to_tighten_and_changes_no_mode(loose_ledger, capsys):
    root, ledger = loose_ledger
    assert main(["migrate", "--workspace", str(root)]) == 0
    out = capsys.readouterr().out
    assert "state modes: 1 entries in the shared state are looser than 0700/0600 (--apply tightens them)" in out
    assert _mode(ledger) == 0o666


@posix_git
def test_a_chmod_that_fails_is_reported_as_not_tightened(loose_ledger, capsys, monkeypatch):
    from aegis_core import storage

    root, ledger = loose_ledger
    monkeypatch.setattr(storage, "_chmod_exact", lambda path, mode, is_dir: False)
    assert main(["migrate", "--workspace", str(root), "--apply"]) == 0
    out = capsys.readouterr().out
    assert "state modes: tightened 0 of 1 loose entries" in out and "tightens them" not in out
    assert _mode(ledger) == 0o666
