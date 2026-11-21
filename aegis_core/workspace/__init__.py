"""Workspace resolution helpers over the Workspace value object (aegis_core.workspace.base).

Submodules own the rest: base (Workspace), discovery, confinement, scaffold, hooks
and layout. Import those names from there. This package's own import loads nothing:
layout (L0) is imported by storage and config, which base's own imports depend on.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

from aegis_core.errors import PathTraversalError

if TYPE_CHECKING:
    from aegis_core.workspace.base import Workspace


def resolve_workspace(
    start: str | Path | os.PathLike[str] | Workspace | None = None,
    caller_file: str | Path | os.PathLike[str] | None = None,
    strict_env: bool = False,
) -> str:
    """Find the project root containing .aegis/rules/ or .aegis/."""
    from aegis_core.workspace.base import Workspace

    return str(Workspace.resolve(start=start, caller_file=caller_file, strict_env=strict_env).root)


def as_workspace(workspace: str | Path | os.PathLike[str] | Workspace | None = None) -> Workspace:
    """Coerce any workspace representation into a strongly-typed Workspace value object."""
    from aegis_core.workspace.base import Workspace

    if isinstance(workspace, Workspace):
        return workspace
    if workspace:
        return Workspace.resolve(start=workspace)
    return Workspace.resolve()


def literal_workspace(workspace: str | Path | os.PathLike[str] | Workspace | None = None) -> Workspace:
    """The workspace an explicit argument names, taken literally (defense #26 step a).

    A Workspace is returned as is. A path names exactly that directory (resolved, so a
    symlink is accepted): no AEGIS_WORKSPACE override, no walk-up to an enclosing
    workspace, or layout check. Only a missing argument falls back to
    discovery (``Workspace.resolve()``).
    """
    from aegis_core.workspace.base import Workspace

    if isinstance(workspace, Workspace):
        return workspace
    if workspace:
        return Workspace(root=Path(os.fspath(workspace)).resolve())
    return Workspace.resolve()


def confine_path(
    untrusted_path: str | Path | os.PathLike[str],
    workspace: str | Path | os.PathLike[str] | Workspace,
) -> tuple[str, str]:
    """Resolve and confine a file path within a workspace."""
    from aegis_core.workspace.base import Workspace

    if isinstance(workspace, Workspace):
        return workspace.confine_path(untrusted_path)
    p_str = str(untrusted_path) if untrusted_path is not None else ""
    if not p_str or not p_str.strip():
        raise PathTraversalError("file path must not be empty")
    return Workspace.resolve(start=workspace).confine_path(untrusted_path)


__all__ = [
    "as_workspace",
    "confine_path",
    "literal_workspace",
    "resolve_workspace",
]
