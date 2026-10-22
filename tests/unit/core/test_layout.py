"""aegis_core.workspace.layout: the one module that spells Aegis paths (build-sheet D12)."""
from __future__ import annotations

from pathlib import Path

import pytest

from aegis_core.workspace.layout import (
    GITIGNORE_ENTRIES,
    UserLayout,
    WorkspaceLayout,
    has_rules_dir,
    is_aegis_workspace,
)


def test_repository_plane_paths(tmp_path: Path):
    layout = WorkspaceLayout(root=str(tmp_path))
    aegis = tmp_path.resolve() / ".aegis"
    assert layout.root == tmp_path.resolve()
    assert layout.aegis_dir == aegis
    assert layout.config_file == aegis / "config.json"
    assert layout.rules_dir == aegis / "rules"
    assert layout.state_dir == aegis / "state"
    assert layout.ledger_file == aegis / "state" / "ledger.jsonl"
    assert layout.derived_file == aegis / "state" / "derived.json"
    assert layout.lock_file == aegis / "state" / "lock"
    assert layout.migrate_backup_dir("20261015T120000Z") == aegis / "state" / "migrate-backup-20261015T120000Z"


def test_every_machine_local_file_lives_under_state(tmp_path: Path):
    layout = WorkspaceLayout(tmp_path)
    assert layout.predictions_log == layout.state_dir / "arbiter_predictions.jsonl"
    for path in (layout.ledger_file, layout.derived_file, layout.lock_file, layout.lifecycle_log, layout.gate_log,
                 layout.predictions_log):
        assert layout.state_dir in path.parents
    assert GITIGNORE_ENTRIES == ("state/",)


def test_user_plane_paths(tmp_path: Path):
    user = UserLayout(tmp_path)
    assert user.aegis_dir == tmp_path / ".aegis"
    assert user.rules_dir == tmp_path / ".aegis" / "rules"
    assert user.workspaces_file == tmp_path / ".aegis" / "workspaces.json"
    assert user.config_file == tmp_path / ".aegis" / "config.json"
    assert user.backups_dir == tmp_path / ".aegis" / "backups"


def test_user_plane_of_the_running_user(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert UserLayout.current() == UserLayout(tmp_path)


def test_this_repository_never_tracks_machine_local_state():
    """D13 L1: the v3 outcome ledgers were wiped and untracked; the v4 state dir stays out of git."""
    import shutil
    import subprocess

    import pytest

    repo = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
    if shutil.which("git") is None or not (repo / ".git").exists():
        pytest.skip("needs a git checkout of the repository")

    def git(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)

    for rel in (".aegis/state/ledger.jsonl", ".aegis/state/lock", ".aegis/evidence/outcomes.jsonl"):
        assert git("check-ignore", "-q", "--no-index", rel).returncode == 0, f"{rel} is not git-ignored"
    tracked = git("ls-files", "--", ".aegis/state", ".aegis/evidence")
    assert tracked.returncode == 0 and tracked.stdout.strip() == ""


@pytest.mark.parametrize("made, workspace, rules", [
    ((), False, False),
    ((".aegis",), True, False),
    ((".aegis", ".aegis/rules"), True, True),
])
def test_workspace_markers_are_directories_under_the_given_root(tmp_path: Path, made, workspace, rules):
    for rel in made:
        (tmp_path / rel).mkdir()
    assert (is_aegis_workspace(tmp_path), has_rules_dir(str(tmp_path))) == (workspace, rules)


def test_a_marker_that_is_a_file_does_not_count(tmp_path: Path):
    (tmp_path / ".aegis").write_text("", encoding="utf-8")
    other = tmp_path / "other"
    (other / ".aegis").mkdir(parents=True)
    (other / ".aegis" / "rules").write_text("", encoding="utf-8")
    assert (is_aegis_workspace(tmp_path), has_rules_dir(other)) == (False, False)
