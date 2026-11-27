"""Unit tests for aegis_core.workspace (Layer 0 Core)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from aegis_core.errors import WorkspaceError
from aegis_core.workspace.base import Workspace
from aegis_core.rules import validate_rule_names
from aegis_core.workspace import (
    confine_path,
    resolve_workspace,
)


class TestWorkspaceCore:
    def test_resolve_workspace_with_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        ws = tmp_path / "my_project"
        rules = ws / ".aegis" / "rules"
        rules.mkdir(parents=True)

        monkeypatch.setenv("AEGIS_WORKSPACE", str(ws))
        resolved = resolve_workspace()
        assert resolved == str(ws.resolve())

        # Test strict_env behavior
        monkeypatch.setenv("AEGIS_WORKSPACE", str(tmp_path / "nonexistent"))
        with pytest.raises(ValueError, match="no .aegis/rules found"):
            resolve_workspace(strict_env=True)

    def test_resolve_workspace_walkup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)

        ws = tmp_path / "root"
        (ws / ".aegis" / "rules").mkdir(parents=True)
        sub = ws / "subdir" / "deep"
        sub.mkdir(parents=True)

        resolved = resolve_workspace(start=sub)
        assert resolved == str(ws.resolve())

        resolved_p = Workspace.resolve(start=sub).root
        assert resolved_p == ws.resolve()
        assert isinstance(resolved_p, Path)

    def test_directory_helpers(self, tmp_path: Path):
        ws = Workspace(root=tmp_path / "repo")
        assert ws.aegis_dir == tmp_path / "repo" / ".aegis"
        assert ws.rules_dir == tmp_path / "repo" / ".aegis" / "rules"
        assert ws.layout.ledger_file == tmp_path / "repo" / ".aegis" / "state" / "ledger.jsonl"

    def test_confine_workspace(self, tmp_path: Path):
        ws = tmp_path / "valid"
        (ws / ".aegis" / "rules").mkdir(parents=True)
        assert str(Workspace.confine(str(ws)).root) == str(ws.resolve())

        with pytest.raises(ValueError, match="missing .aegis/rules"):
            str(Workspace.confine(str(tmp_path)).root)


    def test_confine_path(self, tmp_path: Path):
        ws = tmp_path / "sandbox"
        (ws / ".aegis" / "rules").mkdir(parents=True)
        target = ws / "sub" / "file.txt"
        target.parent.mkdir(parents=True)
        target.write_text("ok")

        abs_p, rel_p = confine_path("sub/file.txt", ws)
        assert abs_p == str(target.resolve())
        assert rel_p == os.path.join("sub", "file.txt")

        # Path traversal rejection
        with pytest.raises(ValueError, match="path traversal blocked"):
            confine_path("../outside.txt", ws)

    @pytest.mark.parametrize("name", ["loop", "loop/x.py"])
    def test_confine_path_through_a_symlink_loop_never_escapes_as_runtime_error(self, tmp_path: Path, name: str):
        """Before 3.13 resolve() raises RuntimeError on a loop; callers catch ValueError only."""
        from aegis_core.errors import PathTraversalError

        ws = tmp_path / "sandbox"
        (ws / ".aegis" / "rules").mkdir(parents=True)
        try:
            os.symlink(ws / "loop", ws / "loop")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable")

        if sys.version_info < (3, 13) and os.name != "nt":
            with pytest.raises(PathTraversalError, match=r"cannot be resolved"):
                confine_path(name, ws)
            return
        # 3.13+ and Windows may resolve a loop leniently; either way nothing escapes as
        # RuntimeError and what comes back stays inside the workspace.
        try:
            _, rel_p = confine_path(name, ws)
        except PathTraversalError as exc:
            assert "cannot be resolved" in str(exc)
        else:
            assert not Path(rel_p).is_absolute() and ".." not in Path(rel_p).parts

    def test_validate_rule_names(self, tmp_path: Path):
        ws = tmp_path / "rules_ws"
        rules_dir = ws / ".aegis" / "rules" / "invariants"
        rules_dir.mkdir(parents=True)
        (rules_dir / "invariant-alpha.md").write_text("---\nid: invariant-alpha\n---\n# Rule")
        (rules_dir / "invariant-beta.md").write_text("---\nid: invariant-beta\n---\n# Rule")
        (rules_dir / "invariant-broken.md").write_text("# no frontmatter: the loader cannot serve it")

        invalid = validate_rule_names(["invariant-alpha", "invariant-beta"], ws)
        assert invalid == []

        invalid = validate_rule_names(["invariant-alpha", "invariant-gamma", "invariant-broken"], ws)
        assert invalid == ["invariant-gamma", "invariant-broken"]
