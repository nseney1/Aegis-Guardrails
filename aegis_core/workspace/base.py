"""Strongly-typed Workspace value object for Aegis (Layer 0 Core).

Implements os.PathLike[str] for seamless interoperability with open(),
Path(), and os.path routines. Strictly zero-dependency (Python standard library only).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from aegis_core.errors import WorkspaceError
from aegis_core.workspace.confinement import confine_path_internal, validate_workspace_path
from aegis_core.workspace.discovery import resolve_workspace_root
from aegis_core.workspace.hooks import _find_git_dirs, resolve_git_hooks_dir

if TYPE_CHECKING:
    from aegis_core.workspace.layout import WorkspaceLayout


@dataclass(frozen=True, eq=False)
class Workspace(os.PathLike[str]):
    """Immutable, strongly-typed representation of an Aegis project workspace.

    Implements os.PathLike[str] for seamless interoperability with open(),
    Path(), and os.path routines.
    """

    root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root).resolve())

    @property
    def is_worktree(self) -> bool:
        """True if the root is a linked git worktree (its ``.git`` is a file)."""
        return (self.root / ".git").is_file()

    @property
    def git_hooks_dir(self) -> Path | None:
        """The hooks directory of the repository rooted here, or None (asks git; not cached)."""
        return resolve_git_hooks_dir(self.root)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Workspace):
            return self.root == other.root
        if isinstance(other, (str, Path, os.PathLike)):
            try:
                return self.root == Path(os.fspath(other)).resolve()
            except (TypeError, ValueError, OSError):
                return False
        return False

    def __hash__(self) -> int:
        return hash(self.root)

    @property
    def layout(self) -> WorkspaceLayout:
        """Canonical WorkspaceLayout for this workspace root."""
        from aegis_core.workspace.layout import WorkspaceLayout

        return WorkspaceLayout(root=self.root)

    @property
    def aegis_dir(self) -> Path:
        """Path to .aegis directory."""
        return self.layout.aegis_dir

    @property
    def rules_dir(self) -> Path:
        """Path to active rules directory (.aegis/rules)."""
        return self.layout.rules_dir

    @property
    def is_git(self) -> bool:
        """True if the root is inside a git repository or worktree that git itself would accept."""
        return _find_git_dirs(self.root)[0] is not None

    def __fspath__(self) -> str:
        return str(self.root)

    def __str__(self) -> str:
        return str(self.root)

    def __repr__(self) -> str:
        return f"Workspace(root={self.root!r}, is_worktree={self.is_worktree})"

    def __truediv__(self, other: str | Path | os.PathLike[str]) -> Path:
        return self.root / other

    @classmethod
    def for_init(cls, path: str | Path | os.PathLike[str]) -> Workspace:
        """Construct a Workspace for initialization without requiring pre-existing .aegis directory.

        Guards against symlink traversal escapes and non-directory files.
        """
        p = Path(path)
        if p.is_symlink():
            raise WorkspaceError(f"Workspace path cannot be a symlink: {p}")
        resolved = p.resolve()
        if resolved.is_file():
            raise WorkspaceError(f"Workspace path must be a directory, not a file: {resolved}")
        return cls(root=resolved)

    def scaffold(self, minimal: bool = False, dry_run: bool = False) -> list[Path]:
        """Create the D12 directories (.aegis/rules/<type>/, .aegis/state/); refuse bare repos."""
        # Imported here: scaffold writes through aegis_core.storage, which imports the
        # workspace package's layout module, so a module-level import would be circular.
        from aegis_core.workspace.scaffold import scaffold_workspace

        return scaffold_workspace(self.layout, minimal=minimal, dry_run=dry_run)

    @classmethod
    def resolve(
        cls,
        start: str | Path | os.PathLike[str] | Workspace | None = None,
        caller_file: str | Path | os.PathLike[str] | None = None,
        strict_env: bool = False,
    ) -> Workspace:
        """Find the project root containing .aegis/rules/ or .aegis/."""
        if isinstance(start, Workspace):
            return start
        cand_root = resolve_workspace_root(
            start=start,
            caller_file=caller_file,
            strict_env=strict_env,
        )
        return cls(root=cand_root.resolve())

    @classmethod
    def confine(
        cls,
        untrusted_workspace: str | Path | os.PathLike[str] | Workspace,
    ) -> Workspace:
        """Validate and confine a workspace path.

        A valid workspace must exist as a directory and contain .aegis/rules/.
        """
        if isinstance(untrusted_workspace, Workspace):
            return untrusted_workspace
        return cls(root=validate_workspace_path(untrusted_workspace))

    def confine_path(self, untrusted_path: str | Path | os.PathLike[str]) -> tuple[str, str]:
        """Resolve and confine a file path within this workspace.

        Returns (resolved_absolute, relative_to_workspace).
        Raises PathTraversalError if the path escapes the workspace boundary.
        """
        return confine_path_internal(self.root, untrusted_path)


__all__ = ["Workspace"]
