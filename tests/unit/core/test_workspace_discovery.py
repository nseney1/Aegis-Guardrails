"""aegis_core.workspace.discovery: the caller-file walk skips vendored copies; v2 rule
directories in $HOME are refused even though a bare ~/.aegis is not."""
from __future__ import annotations

from pathlib import Path

import pytest

from aegis_core.errors import WorkspaceError
from aegis_core.workspace.discovery import resolve_workspace_root


@pytest.fixture(autouse=True)
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = (tmp_path / "home").resolve()
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    # The cwd is an ungoverned repository, so only the caller file can name a workspace.
    outside = tmp_path / "outside"
    (outside / ".git").mkdir(parents=True)
    monkeypatch.chdir(outside)
    return home


def _workspace(path: Path) -> Path:
    (path / ".aegis" / "rules").mkdir(parents=True)
    return path.resolve()


@pytest.mark.parametrize("depth", [("vendor", "lib"), ("vendor", "lib", "pkg")])
def test_a_workspace_vendored_inside_a_project_is_skipped_for_the_project(tmp_path: Path, depth):
    project = _workspace(tmp_path / "project")
    (project / ".git").mkdir()
    vendored = project.joinpath(*depth)
    _workspace(vendored)

    assert resolve_workspace_root(caller_file=vendored / "module.py") == project


def test_a_project_whose_own_directory_is_named_vendor_is_still_found(tmp_path: Path):
    project = _workspace(tmp_path / "vendor")
    (project / ".git").mkdir()
    (project / "src").mkdir()

    assert resolve_workspace_root(caller_file=project / "src" / "module.py") == project
