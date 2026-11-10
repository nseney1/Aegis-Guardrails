"""Workspace discovery for Aegis (Layer 0 Core).

Discovers project roots via the AEGIS_WORKSPACE pin, upward directory walks, and callers.
Strictly zero-dependency: uses only Python standard library.
"""
from __future__ import annotations

import os
from pathlib import Path

from aegis_core.config import env_workspace
from aegis_core.errors import WorkspaceError, WorkspaceNotFoundError
from aegis_core.workspace.binding import bounded_walk_up, denial
from aegis_core.workspace.layout import (
    AEGIS_DIRNAME,
    LEGACY_REPO_CONFS,
    LEGACY_UPGRADE_MARKERS,
    WorkspaceLayout,
    has_rules_dir,
    is_aegis_workspace,
)


def _home_str() -> str:
    try:
        return str(Path.home())
    except Exception:
        return ""


def _real_home() -> Path | None:
    """The account's own home as the password database names it (POSIX), or None.

    ``$HOME`` is routinely overridden (``make test``, CI, sandboxes) while the start
    folder still sits under the real home, whose ``~/.aegis`` is the user plane. The
    binding denylist only knows ``$HOME``, so the walk-up latched onto the real home and
    bound the whole of it as the workspace (ROOT C2's 2026-11-02 suite hang). The real
    home gets the same refusal as ``$HOME``."""
    try:
        import pwd

        pw_dir = pwd.getpwuid(os.getuid()).pw_dir
    except (ImportError, AttributeError, KeyError):  # Windows, or a uid with no entry
        return None
    if not pw_dir:  # Path("").resolve() would be the cwd
        return None
    try:
        return Path(pw_dir).resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def _at_or_above_real_home(d: Path) -> bool:
    """``d`` is the real home or encloses it: where a walk-up must stop, as at ``$HOME``."""
    real = _real_home()
    return real is not None and (d == real or d in real.parents)


UPGRADE_STATE_MSG = (
    "Unsupported v3 state at {path}: {found}. Archive these paths outside the workspace, "
    "preserving any settings or evidence you need. Then configure .aegis/config.json "
    "with the supported settings before running Aegis again; aegis migrate does not convert these paths."
)


def unmigrated_state(d: str | Path | os.PathLike[str]) -> list[str]:
    """Retired state that must be archived manually, in a fixed repo-relative order.

    These paths are never converted by the v4-only maintenance command.
    """
    layout = WorkspaceLayout(Path(d))
    found = [f"{AEGIS_DIRNAME}/{rel}" for rel in LEGACY_UPGRADE_MARKERS if os.path.lexists(layout.legacy(rel))]
    found += [name for name in LEGACY_REPO_CONFS if os.path.lexists(layout.root / name)]
    return found


def unconverted_rule_files(d: str | Path | os.PathLike[str]) -> list[Path]:
    """Compatibility entry point for the CLI pending its command-surface removal."""
    return []


def refuse_unmigrated_v3(d: str | Path | os.PathLike[str]) -> None:
    """Compatibility entry point for the CLI pending its command-surface removal."""


def _denied(d: str | Path | os.PathLike[str]) -> str | None:
    """Why ``d`` can never be a workspace ("home_directory", "filesystem_root"), or None.
    A path that cannot be resolved is denied as well: it is never bound."""
    try:
        path = Path(d).resolve()
        denied = denial(path)
    except (OSError, RuntimeError, ValueError):
        return "unresolvable"
    if denied is None and path == _real_home():
        return "home_directory"
    return denied


def _is_workspace_dir(d: str) -> bool:
    """Check if directory contains a valid Aegis workspace marker (.aegis/rules or .aegis).

    Never ``$HOME`` or the filesystem root (AD-4): ``~/.aegis/rules`` is the personal
    read-only rule layer and ``~/.aegis`` the user plane, so neither marks a workspace.
    """
    if _denied(d):
        return False
    if has_rules_dir(d):
        return True
    return d not in ("/tmp", "/var/tmp") and is_aegis_workspace(d)


def resolve_workspace_root(
    start: str | Path | os.PathLike[str] | None = None,
    caller_file: str | Path | os.PathLike[str] | None = None,
    strict_env: bool = False,
) -> Path:
    """Find the project root containing .aegis/rules/ or .aegis/."""
    # 1. AEGIS_WORKSPACE, the operator's pin (D11): final, and never $HOME or the root
    aegis_ws = env_workspace()
    if aegis_ws:
        denied = _denied(aegis_ws)
        if denied:
            raise WorkspaceNotFoundError(
                f"AEGIS_WORKSPACE is set to {aegis_ws}, which is the {denied.replace('_', ' ')}"
                if denied != "unresolvable" else f"AEGIS_WORKSPACE is set to {aegis_ws}, which cannot be resolved"
            )
        if has_rules_dir(aegis_ws):
            return Path(aegis_ws).resolve()
        elif strict_env:
            raise WorkspaceNotFoundError(
                f"AEGIS_WORKSPACE is set to {aegis_ws} but no .aegis/rules found there (missing valid rules)."
            )
        elif os.path.isdir(aegis_ws):
            return Path(aegis_ws).resolve()

    # 3. Explicit start path walk-up, bounded like every walk below (see _walk_up)
    if start is not None:
        cand = os.path.abspath(str(start))
        d = cand if os.path.isdir(cand) else os.path.dirname(cand)
        found = _walk_up(d)
        return found if found is not None else Path(d).resolve()

    # 4-5. The cwd, then up from it
    cwd = os.getcwd()
    found = _walk_up(cwd)
    if found is not None:
        return found

    # 6. Walk up from caller_file (skipping vendor/ directories)
    if caller_file is not None:
        def _not_vendored(d: Path) -> bool:
            if _at_or_above_real_home(d):
                return False
            return _is_workspace_dir(str(d)) and "vendor" not in d.parts[:-1]

        found = bounded_walk_up(os.path.dirname(os.path.abspath(str(caller_file))), accept=_not_vendored)
        if found is not None:
            return found

    # 7. Fallback to CWD
    return Path(cwd).resolve()


def _walk_up(start: str) -> Path | None:
    """The nearest workspace from ``start`` upwards (AD-4's bounded walk-up): never above
    the git toplevel around ``start``, never ``$HOME``, the real home or the filesystem root."""

    def accept(d: Path) -> bool:
        if _at_or_above_real_home(d):
            return False  # never the real home or above it, even with $HOME overridden
        if _is_workspace_dir(str(d)):
            return True
        return False

    return bounded_walk_up(start, accept=accept)


__all__ = [
    "UPGRADE_STATE_MSG",
    "_is_workspace_dir",
    "refuse_unmigrated_v3",
    "resolve_workspace_root",
    "unconverted_rule_files",
    "unmigrated_state",
]
