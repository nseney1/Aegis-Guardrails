"""`aegis migrate` from the command line: dry run by default, --apply, --json, exit codes."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat

import pytest

from aegis_cli.cli import main
from aegis_core.workspace.discovery import LEGACY_SOMA_UPGRADE_MSG


def _soma_workspace(root: Path) -> Path:
    cell = root / ".soma" / "cells" / "vacuoles" / "trap-x.md"
    cell.parent.mkdir(parents=True)
    cell.write_text("---\ntype: vacuole\nfitness:\n  triggers: 2\n---\nBody\n", encoding="utf-8")
    odd = root / ".soma" / "cells" / "ribosomes" / "ribosome-y.md"
    odd.parent.mkdir(parents=True)
    odd.write_text("---\ntype: ribosome\n---\nBody\n", encoding="utf-8")
    return root


def _tree(root: Path) -> dict:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def test_dry_run_is_the_default_and_writes_nothing(tmp_path: Path, capsys):
    root = _soma_workspace(tmp_path)
    before = _tree(root)

    assert main(["migrate", "--workspace", str(root)]) == 0

    out = capsys.readouterr().out
    assert "dry run: nothing written; rerun with --apply" in out
    assert "rule: .soma/cells/vacuoles/trap-x.md -> .aegis/rules/traps/trap-x.md (type trap)" in out
    assert "unmapped type 'ribosome': .soma/cells/ribosomes/ribosome-y.md left in place" in out
    assert _tree(root) == before
    assert main(["migrate", "--workspace", str(root), "--dry-run"]) == 0


def test_apply_converts_and_exits_1_when_something_was_left_behind(tmp_path: Path, capsys):
    root = _soma_workspace(tmp_path)

    assert main(["migrate", "--workspace", str(root), "--apply"]) == 1

    out = capsys.readouterr().out
    assert "migrated" in out and "backup:" in out
    assert (root / ".aegis" / "rules" / "traps" / "trap-x.md").read_text(encoding="utf-8") == "---\ntype: trap\n---\nBody\n"
    assert (root / ".soma" / "cells" / "ribosomes" / "ribosome-y.md").is_file()


def test_json_report_and_idempotent_second_apply(tmp_path: Path, capsys):
    root = tmp_path / "ws"
    cell = root / ".soma" / "cells" / "walls" / "wall-a.md"
    cell.parent.mkdir(parents=True)
    cell.write_text("---\ntype: wall\n---\nBody\n", encoding="utf-8")

    assert main(["--json", "migrate", "--workspace", str(root), "--apply"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["status"] == "applied"
    assert first["rules"] == [{"from": ".soma/cells/walls/wall-a.md", "to": ".aegis/rules/invariants/wall-a.md",
                               "type": "invariant"}]
    assert "migrate-backup-" in first["backup"]
    assert first["config"] == {"v": 1}  # the report describes what the apply wrote

    assert main(["--json", "migrate", "--workspace", str(root), "--apply"]) == 0
    second = json.loads(capsys.readouterr().out)
    assert second["status"] == "up_to_date" and second["backup"] is None


def test_apply_and_dry_run_together_is_a_usage_error(tmp_path: Path, capsys):
    assert main(["migrate", "--workspace", str(tmp_path), "--apply", "--dry-run"]) == 2
    assert "mutually exclusive" in capsys.readouterr().err


def test_the_legacy_sentinel_points_at_migrate(tmp_path: Path):
    assert "aegis migrate --apply" in LEGACY_SOMA_UPGRADE_MSG


def test_the_report_lists_the_v3_manifest_for_removal(tmp_path: Path, capsys):
    """The signed v3 manifest is v3 state (D3): backed up and removed, never re-attested."""
    root = tmp_path / "ws"
    rules = root / ".aegis" / "rules" / "traps"
    rules.mkdir(parents=True)
    for name in ("trap-a", "trap-b"):
        (rules / f"{name}.md").write_text(f"---\nid: {name}\nfitness:\n  triggers: 2\n---\nBody\n", encoding="utf-8")
    (root / ".aegis" / "rules" / "manifest.json").write_text('{"cells": {}}', encoding="utf-8")

    assert main(["migrate", "--workspace", str(root)]) == 0

    out = capsys.readouterr().out
    assert "  remove (backed up first): .aegis/rules/manifest.json" in out
    assert "  strip: fitness from .aegis/rules/traps/trap-a.md" in out
    assert "manifest: " not in out and "re-attest" not in out


def test_a_rule_edited_between_plan_and_apply_is_reported_and_nothing_changes(tmp_path: Path, capsys, monkeypatch):
    from aegis_core import migrate

    root = _soma_workspace(tmp_path)
    cell = root / ".soma" / "cells" / "vacuoles" / "trap-x.md"
    real_plan = migrate.plan

    def plan_then_someone_saves(workspace):
        planned = real_plan(workspace)
        cell.write_text(cell.read_text(encoding="utf-8") + "Saved by an editor meanwhile.\n", encoding="utf-8")
        return planned

    monkeypatch.setattr(migrate, "plan", plan_then_someone_saves)

    assert main(["--json", "migrate", "--workspace", str(root), "--apply"]) == 1

    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "refused"
    assert ".soma/cells/vacuoles/trap-x.md changed since the plan was made" in report["refusal"]
    assert report["backup"] is None
    assert cell.read_text(encoding="utf-8").endswith("Saved by an editor meanwhile.\n")
    assert not (root / ".aegis" / "rules").exists()


def test_a_refusal_found_only_when_applying_is_a_json_report_and_exit_1(tmp_path: Path, capsys, monkeypatch):
    from aegis_core import migrate

    root = _soma_workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    real_plan = migrate.plan

    def plan_then_a_link_is_planted(workspace):
        planned = real_plan(workspace)
        (root / ".aegis" / "state").mkdir(parents=True)
        try:
            (root / ".aegis" / "state" / "lock").symlink_to(outside / "lock")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable")
        return planned

    monkeypatch.setattr(migrate, "plan", plan_then_a_link_is_planted)

    assert main(["--json", "migrate", "--workspace", str(root), "--apply"]) == 1

    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "refused" and "lock: it is a symlink" in report["refusal"]
    assert list(outside.iterdir()) == []


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
