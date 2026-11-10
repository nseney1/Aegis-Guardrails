"""aegis_core.workspace.confinement.validate_workspace_path: what a caller may name as a workspace."""
from __future__ import annotations

from pathlib import Path

import pytest

from aegis_core.errors import WorkspaceError
from aegis_core.workspace.confinement import validate_workspace_path


def test_a_v4_workspace_validates_to_its_root(tmp_path: Path):
    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    assert validate_workspace_path(str(tmp_path)).samefile(tmp_path)


def test_a_directory_without_the_supported_rules_layout_is_refused(tmp_path: Path):
    (tmp_path / ".obsolete" / "rules").mkdir(parents=True)
    with pytest.raises(WorkspaceError, match=r"^not a valid Aegis workspace \(missing \.aegis/rules\): "):
        validate_workspace_path(str(tmp_path))
