"""Path confinement and security boundaries for Aegis workspaces (Layer 0 Core).

Enforces cross-platform confinement, blocks directory traversal escapes, null bytes,
extended device namespace paths, alternate data streams, and Windows reserved device names.
Strictly zero-dependency: uses only Python standard library.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from aegis_core.errors import PathTraversalError, WorkspaceError, WorkspaceNotFoundError
from aegis_core.primitives import is_within
from aegis_core.workspace.layout import has_rules_dir

_WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)


def confine_path_internal(
    workspace_root: Path,
    untrusted_path: str | Path | os.PathLike[str],
) -> tuple[str, str]:
    """Resolve and confine a file path within a workspace boundary.

    Returns (resolved_absolute, relative_to_workspace).
    Raises PathTraversalError if the path escapes the workspace boundary.
    """
    p_str = str(untrusted_path) if untrusted_path is not None else ""
    if not p_str or not p_str.strip():
        raise PathTraversalError("file path must not be empty")

    if "\x00" in p_str:
        raise PathTraversalError("null bytes are not permitted in file paths")

    if p_str.startswith(("\\\\?\\", "\\\\.\\", "//?/", "//./")):
        raise PathTraversalError("extended device namespace paths are not permitted")

    # Reject alternate data streams (e.g. file.txt:stream)
    if ":" in p_str:
        has_drive = re.match(r"^[a-zA-Z]:[\\/]", p_str)
        rest = p_str[2:] if has_drive else p_str
        if ":" in rest:
            raise PathTraversalError(f"alternate data stream syntax (':') is not permitted: {p_str!r}")

    # Reject reserved Windows device names
    for seg in re.split(r"[\\/]", p_str):
        if not seg:
            continue
        base = seg.rstrip(". ").split(".")[0].upper()
        if base in _WINDOWS_DEVICE_NAMES:
            raise PathTraversalError(f"reserved Windows device name not permitted: {p_str!r}")

    try:
        resolved_root = workspace_root.resolve()
        candidate = Path(os.path.join(str(resolved_root), p_str)).resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        # A symlink loop raises RuntimeError before Python 3.13; callers (the MCP tool
        # handlers among them) handle confinement failures as ValueError only.
        raise PathTraversalError(f"{p_str} cannot be resolved: {exc}") from exc

    if candidate == resolved_root:
        raise PathTraversalError("refusing to treat the workspace root as a file")

    try:
        relative = candidate.relative_to(resolved_root)
    except ValueError:
        raise PathTraversalError(
            f"path traversal blocked: {p_str!r} resolves to {candidate} "
            f"which is outside the workspace {resolved_root}"
        )

    return str(candidate), str(relative)


def validate_workspace_path(
    untrusted_workspace: str | Path | os.PathLike[str],
) -> Path:
    """Validate that an untrusted workspace path exists and contains .aegis/rules/.

    Returns the resolved Path object.
    Raises WorkspaceError / WorkspaceNotFoundError on invalid or malicious input.
    """
    if not untrusted_workspace or not str(untrusted_workspace).strip():
        raise WorkspaceError("workspace path must not be empty")

    resolved = os.path.realpath(str(untrusted_workspace))
    if not os.path.isdir(resolved):
        raise WorkspaceNotFoundError(f"workspace does not exist or is not a directory: {resolved}")

    if not has_rules_dir(resolved):
        raise WorkspaceError(f"not a valid Aegis workspace (missing .aegis/rules): {resolved}")

    return Path(resolved)


def read_confined_bytes(root: Path, path: Path, error_type=PathTraversalError, missing_ok: bool = True,
                        max_bytes: int | None = None):
    """Read a regular confined file, optionally capped, or None when absent."""
    if not is_within(path, root, unresolvable=False) or any(
        parent.is_symlink() for parent in (path, *path.parents) if root in parent.parents
    ):
        raise error_type(f"{path.relative_to(root)} is a symlink or outside the workspace; no rule, config.json or .aegis/.gitignore was changed")
    if not os.path.lexists(path):
        if missing_ok:
            return None
        raise FileNotFoundError(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise error_type(f"{path.relative_to(root)} is not a regular file; no rule, config.json or .aegis/.gitignore was changed")
        if max_bytes is not None:
            data = stream.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise error_type(f"{path.relative_to(root)} exceeds {max_bytes} bytes; no rule, config.json or .aegis/.gitignore was changed")
            return data
        return stream.read()


def iter_confined_files(root: Path, directory: Path, suffix: str = ".md"):
    """Yield (path, problem) without descending links or paths outside root.

    Unsafe entries and listing failures are yielded for the caller to report; they
    are never read. Missing directories contain no files.
    """
    if directory.is_symlink() or not is_within(directory, root, unresolvable=False):
        yield directory, "a symlink or outside the workspace; not followed"
        return
    if not directory.exists():
        return
    failures = []
    for folder, dirs, files in os.walk(directory, followlinks=False, onerror=failures.append):
        dirs.sort()
        for name in list(dirs):
            path = Path(folder, name)
            if path.is_symlink() or not is_within(path, root, unresolvable=False):
                dirs.remove(name)
                yield path, "a symlink or outside the workspace; not followed"
        for name in sorted(files):
            if name.lower().endswith(suffix):
                path = Path(folder, name)
                problem = "a symlink or outside the workspace; not followed" if path.is_symlink() or not is_within(path, root, unresolvable=False) else None
                yield path, problem
    for error in failures:
        yield Path(error.filename or directory), str(error)


def finish_file_move(source: Path, target: Path) -> None:
    """Remove the old same-named entry; normalize directory case only for aliases.

    Distinct directories are never renamed over one another. A source directory
    holding notes or other files stays; an empty one is removed.
    """
    if os.path.samefile(source.parent, target.parent):
        if str(source.parent) != str(target.parent):
            source.parent.rename(target.parent)
    else:
        source.unlink()
        if not any(source.parent.iterdir()):
            source.parent.rmdir()


__all__ = [
    "_WINDOWS_DEVICE_NAMES",
    "confine_path_internal",
    "validate_workspace_path",
    "iter_confined_files",
    "finish_file_move",
    "read_confined_bytes",
]
