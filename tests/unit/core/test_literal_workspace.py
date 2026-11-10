"""literal_workspace: the one literal coercion helper (defense #26 step a).

The 12 lifecycle and telemetry entry points spelled the same inline idiom,
``Workspace(root=Path(x).resolve())``. A literal path means exactly that directory:
no AEGIS_WORKSPACE override, no walk-up to an ancestor workspace, and no requirement
that rules already exist. A symlinked path is accepted and resolved.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from aegis_core.workspace import literal_workspace
from aegis_core.workspace.base import Workspace


@pytest.fixture
def nested(tmp_path: Path) -> Path:
    outer = tmp_path / "outer"
    (outer / ".aegis" / "rules").mkdir(parents=True)
    inner = outer / "pkg" / "inner"
    inner.mkdir(parents=True)
    return inner


def test_a_path_is_taken_literally_without_walking_up(nested: Path):
    assert literal_workspace(nested).root == nested.resolve()
    assert literal_workspace(str(nested)).root == nested.resolve()


def test_the_environment_pin_does_not_redirect_an_explicit_path(nested: Path, tmp_path: Path, monkeypatch):
    other = tmp_path / "other"
    (other / ".aegis" / "rules").mkdir(parents=True)
    monkeypatch.setenv("AEGIS_WORKSPACE", str(other))
    assert literal_workspace(nested).root == nested.resolve()


def test_an_uninitialized_literal_directory_does_not_create_state(tmp_path: Path):
    assert literal_workspace(tmp_path).root == tmp_path.resolve()
    assert not (tmp_path / ".aegis").exists()


def test_a_symlinked_path_is_accepted_and_resolved(tmp_path: Path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert literal_workspace(link).root == real.resolve()


def test_a_workspace_is_returned_as_is(tmp_path: Path):
    ws = Workspace(root=tmp_path)
    assert literal_workspace(ws) is ws


def test_no_path_falls_back_to_discovery(nested: Path, monkeypatch):
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    monkeypatch.chdir(nested)
    assert literal_workspace(None).root == nested.parents[1].resolve()
    assert literal_workspace("").root == nested.parents[1].resolve()
