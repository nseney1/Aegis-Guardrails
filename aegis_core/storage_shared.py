"""L0 storage I/O results and shared-state implementations.

Every shared-state implementation receives ``deps`` from storage at call time. Collaborators,
including calls between helpers, are resolved through that namespace; this module
never imports storage. Patch aegis_core.storage.<name> to affect the moved code.
Explicit callbacks expose private helper wiring to the call-graph checker.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

__all__ = [
    "AppendResult",
    "FileReport",
    "RowsResult",
    "SHARED_DIR_MODE",
    "StateModes",
    "confined",
    "confined_shared",
    "local_state_dir",
    "shared_errors",
    "shared_link_error",
    "shared_lock_name",
    "shared_outside_error",
    "state_modes",
]

SHARED_DIR_MODE = 0o700


def shared_link_error(deps: Any, path: Path, base: Path) -> Exception:
    return deps.PathTraversalError(
        f"refusing to use {path}: it is a symlink; aegis keeps shared state only inside {base}",
        path=str(path),
    )


def shared_outside_error(deps: Any, path: Path, base: Path) -> Exception:
    return deps.PathTraversalError(
        f"refusing to use {path}: it resolves outside {base}; aegis keeps shared state only inside it",
        path=str(path),
    )


def confined(deps: Any, directory: Path, base: Path, link_error, outside_error, entries: bool = True) -> None:
    """Refuse ``directory`` when it is a symlink, is not a directory, or resolves outside
    ``base``, and (``entries``) when an entry directly inside it is a symlink or a
    directory that resolves outside ``base``. A missing ``directory`` passes."""
    if directory.is_symlink():
        raise link_error(directory)
    if not deps.os.path.lexists(directory):
        return
    if not deps.is_within(directory, base, unresolvable=False):  # a Windows junction is not a symlink
        raise outside_error(directory)
    if not directory.is_dir():
        raise deps.PathTraversalError(f"refusing to use {directory}: it is not a directory", path=str(directory))
    if not entries:
        return
    with deps.os.scandir(directory) as found:
        for entry in found:
            if entry.is_symlink():
                raise link_error(deps.Path(entry.path))
            if entry.is_dir(follow_symlinks=False) and not deps.is_within(deps.Path(entry.path), base, unresolvable=False):
                raise outside_error(deps.Path(entry.path))


class StateModes(NamedTuple):
    """What ``state_modes`` found: ``checked`` entries (directories and files) in the
    shared state, ``looser`` of them with any group or other permission bit, ``fixed`` of
    those tightened. Counts only: a name in a report would leak what the state holds."""

    checked: int
    looser: int
    fixed: int
    supported: bool

    def as_dict(self) -> Dict[str, Any]:
        return {"checked": self.checked, "looser": self.looser, "fixed": self.fixed, "supported": self.supported}


def state_modes(deps: Any, workspace: Any, fix: bool = False, *, chmod_exact) -> StateModes:
    """Count the entries of ``<git common dir>/aegis`` looser than 0o700 (directories) and
    0o600 (files); with ``fix`` set them to exactly that. Nothing is created.

    Outside a git repository (or when git cannot run) there is no shared state, so nothing
    is checked: the workspace-local ``.aegis/state`` is not held to the shared standard.
    A symlink is never followed or changed. Raises what ``shared_state_dir`` raises for an
    unconfined directory. Without POSIX permission bits (Windows) nothing is checked and
    ``supported`` is False.
    """
    if deps.os.name == "nt":
        return deps.StateModes(0, 0, 0, False)
    common = deps.gitsafe.common_dir(deps.Path(deps.os.fspath(workspace)).resolve())
    if common is None:
        return deps.StateModes(0, 0, 0, True)
    top = deps._shared_dir(deps.Path(deps.real_path(common)), create=False)
    if not deps.os.path.lexists(top):
        return deps.StateModes(0, 0, 0, True)
    checked = looser = fixed = 0
    pending = [(top, True)]
    while pending:
        path, is_dir = pending.pop()
        checked += 1
        if deps.stat.S_IMODE(deps.os.lstat(path).st_mode) & 0o077:
            looser += 1
            if fix and chmod_exact(path, deps._SHARED_DIR_MODE if is_dir else deps._PRIVATE_FILE_MODE, is_dir):
                fixed += 1
        if is_dir:
            with deps.os.scandir(path) as found:
                pending.extend((deps.Path(e.path), e.is_dir(follow_symlinks=False)) for e in found if not e.is_symlink())
    return deps.StateModes(checked, looser, fixed, True)


def local_state_dir(deps: Any, root: Path, create: bool, *, confined) -> Path:
    """Local state with storage's refusals; ``create=False`` creates nothing."""
    if create:
        return deps.state_dir(root)
    layout = deps.WorkspaceLayout(root)
    confined(layout.aegis_dir, layout.root, deps._link_error, deps._outside_error, entries=False)
    confined(layout.state_dir, layout.root, deps._link_error, deps._outside_error)
    return layout.state_dir


def shared_errors(deps: Any, base: Path, *, link_error, outside_error):
    def confined_link_error(path: Path) -> Exception:
        return link_error(path, base)

    def confined_outside_error(path: Path) -> Exception:
        return outside_error(path, base)

    return confined_link_error, confined_outside_error


def confined_shared(deps: Any, directory: Path, base: Path, create: bool, *, shared_errors) -> None:
    """``confined`` for a directory of the shared state under ``base`` (the resolved common
    dir); with ``create`` a missing one is made private and checked again."""
    link_error, outside_error = shared_errors(base)
    deps._confined(directory, base, link_error, outside_error)
    if create and not deps.os.path.lexists(directory):
        try:
            directory.mkdir(mode=deps._SHARED_DIR_MODE)
            deps.os.chmod(directory, deps._SHARED_DIR_MODE)  # mkdir's mode passes through the umask; this is exact
        except FileExistsError:
            pass  # another worktree's process made it first; checked again below
        deps._confined(directory, base, link_error, outside_error)


def shared_lock_name(deps: Any, name: object) -> str:
    ok = (
        isinstance(name, str)
        and name.endswith(".lock")
        and name != ".lock"
        and not any(ch in name for ch in "/\\\0")
        and name not in (".", "..")
    )
    if not ok:
        raise ValueError(f"a shared lock is one file name ending in .lock, got {name!r}")
    return name  # type: ignore[return-value]


@dataclass(frozen=True)
class FileReport:
    """Descriptor identity, size and generation; optional filesystem read-start evidence."""

    identity: Tuple[int, int]
    size: int
    added: int = 0
    mtime_ns: int = 0
    ctime_ns: int = 0
    started_ns: Optional[int] = None


@dataclass(frozen=True)
class AppendResult:
    """An appended-row count and optional evidence from its write descriptor."""

    count: int
    report: Optional[FileReport] = None


@dataclass(frozen=True)
class RowsResult:
    """Rows and optional evidence from the descriptor that read or wrote them."""

    rows: List[Dict[str, Any]]
    report: Optional[FileReport] = None
