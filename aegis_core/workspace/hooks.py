"""Git hook directory resolution and worktree awareness (Layer 0 Core).

Handles standard Git repositories (.git directory), Git worktrees (.git pointer file),
and custom core.hooksPath configuration via git CLI or pure Python fallback.
Strictly zero-dependency: uses only Python standard library.
"""
from __future__ import annotations

import os
from pathlib import Path

from aegis_core.workspace.binding import git_discovery_paths


def _git_dirs_at(curr: Path) -> tuple[Path, Path] | None:
    """(git_dir, git_common_dir) named by ``curr/.git`` (directory or gitfile), unvalidated."""
    dot_git = curr / ".git"
    if dot_git.is_dir():
        return dot_git, dot_git
    if dot_git.is_file():
        try:
            content = dot_git.read_text(encoding="utf-8", errors="replace").strip()
            if content.startswith("gitdir:"):
                gitdir_path = Path(content[7:].strip())
                if not gitdir_path.is_absolute():
                    gitdir_path = (curr / gitdir_path).resolve()
                commondir_file = gitdir_path / "commondir"
                if commondir_file.is_file():
                    common_rel = commondir_file.read_text(encoding="utf-8").strip()
                    return gitdir_path, (gitdir_path / common_rel).resolve()
                if gitdir_path.parent.name == "worktrees" and gitdir_path.parent.parent.is_dir():
                    return gitdir_path, gitdir_path.parent.parent
                return gitdir_path, gitdir_path
        except (OSError, UnicodeError, ValueError):
            pass
    return None


def _is_git_repository(git_dir: Path, common_dir: Path) -> bool:
    """Git's own acceptance test (setup.c is_git_directory): HEAD in the gitdir,
    objects/ and refs/ in the common dir."""
    return (
        (git_dir / "HEAD").is_file()
        and (common_dir / "objects").is_dir()
        and (common_dir / "refs").is_dir()
    )


def _find_git_dirs(root: Path) -> tuple[Path | None, Path | None]:
    """Find (git_dir, git_common_dir) for a workspace root, walking up if necessary.

    A ``.git`` at ``root`` itself is taken as given: it is the project's own marker and
    the root-anchored hook resolution relies on it. An ancestor's ``.git`` only counts
    when git would accept it as a repository; otherwise a stray empty ``/tmp/.git`` or
    ``$HOME/.git`` turns every directory below it into a git workspace that git itself
    does not recognize, and the walk continues upward as git's discovery does,
    stopping before GIT_CEILING_DIRECTORIES ancestors.
    """
    start = root.resolve()
    for curr in git_discovery_paths(start):
        found = _git_dirs_at(curr)
        if found is not None and (curr == start or _is_git_repository(*found)):
            return found
    return None, None


def resolve_git_hooks_dir(project_root: str | Path | os.PathLike[str] | None = None) -> Path | None:
    """Resolve the git hooks directory for a project root or worktree.

    Handles:
    1. Standard repository (.git is a directory -> .git/hooks)
    2. Git worktree (.git is a file containing 'gitdir: <path>')
       Resolves common_dir or parent .git/hooks.
    3. ``git rev-parse --git-path hooks`` (via aegis_core.gitsafe) when git is available.

    Returns Path to hooks directory, or None if not inside a git repository.
    """
    root = Path(project_root or Path.cwd()).resolve()

    dot_git = root / ".git"
    if not dot_git.exists():
        return None

    # 1. Ask git (honours core.hooksPath and worktrees), through the hardened runner
    from aegis_core import gitsafe

    hooks_path = gitsafe.git_path(root, "hooks")
    if hooks_path is not None:
        return hooks_path

    # 2. Pure Python fallback (zero external CLI dependencies)
    _git_dir, common_dir = _find_git_dirs(root)
    if common_dir is not None:
        return common_dir / "hooks"

    return None


__all__ = [
    "_find_git_dirs",
    "resolve_git_hooks_dir",
]
