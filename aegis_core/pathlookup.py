"""The one lookup of a program on PATH (L0: standard library only).

Aegis runs what this finds (a host CLI, ``python3``) and writes the ``aegis-mcp`` it
finds into a host's user config, from inside a repository the user may just have
cloned (host-matrix §3.7). So only absolute PATH entries count:

- an empty or relative entry names a directory relative to the current directory,
  where the repository can plant a program;
- ``shutil.which`` on Windows searches the current directory first whatever its
  ``path=`` says, so it is not used;
- an absolute entry inside ``outside`` (doctor passes the workspace) is the
  repository's own.

The result is the PATH entry joined with the file's name as the directory spells it,
never resolved: version managers (Volta, mise, asdf) install a tool as a link to one
dispatcher that picks the tool from the name it is run under. On Windows, PATHEXT
candidates are matched case-insensitively against the directory listing, so the
command run (or written into a config) carries the file's own spelling.

``only_skipped`` says where a program is reachable when ``which`` refused every place,
so a caller can report such a host as unknown rather than absent.
"""
from __future__ import annotations

import ntpath
import os
import sys
from typing import List, NamedTuple, Optional, Union

from aegis_core.primitives import key_within, real_key

__all__ = ["Hit", "INSIDE_FENCE", "RELATIVE_ENTRY", "is_bare", "only_skipped", "which"]

PathLike = Union[str, "os.PathLike[str]"]

#: The PATH entry is empty or relative: it resolves against the current directory.
RELATIVE_ENTRY = "relative_entry"
#: The PATH entry is absolute but inside the fence (``outside``).
INSIDE_FENCE = "inside_fence"


class Hit(NamedTuple):
    """A program ``which`` passed over: where it is, the PATH entry as written, and why."""

    path: str
    entry: str
    reason: str


def is_bare(name: str, *, windows: bool = os.name == "nt") -> bool:
    """A name with no directory or drive; the explicit platform keeps both rules testable."""
    return "/" not in name and (not windows or ("\\" not in name and not ntpath.splitdrive(name)[0]))


def _candidates(name: str) -> List[str]:
    if sys.platform != "win32":
        return [name]
    exts = [e for e in (os.environ.get("PATHEXT") or ".COM;.EXE;.BAT;.CMD").split(os.pathsep) if e]
    if os.path.splitext(name)[1].upper() in {e.upper() for e in exts}:
        return [name]
    return [name + e for e in exts]


def _spelled(directory: str, candidates: List[str]) -> List[str]:
    """The candidates ``directory`` holds, in candidate order, spelled as it holds them.

    Windows matches names case-insensitively and PATHEXT spells extensions in capitals,
    so ``codex.EXE`` opens ``codex.exe``. Elsewhere names are taken as given.
    """
    if sys.platform != "win32":
        return candidates
    try:
        names = {n.lower(): n for n in os.listdir(directory)}
    except OSError:
        return candidates
    return [names[c.lower()] for c in candidates if c.lower() in names]


def _programs(directory: str, name: str) -> List[str]:
    found = []
    for candidate in _spelled(directory, _candidates(name)):
        full = os.path.join(directory, candidate)
        if os.path.isfile(full) and os.access(full, os.X_OK):
            found.append(full)
    return found


def _inside(entry: str, fence: str) -> bool:
    """Whether ``entry`` (resolved through links) is ``fence`` or below it. An entry
    that cannot be resolved is treated as inside: it is never searched."""
    key = real_key(entry)
    return key is None or key_within(key, fence)


def _search(path: Optional[str]) -> List[str]:
    return (os.environ.get("PATH", os.defpath) if path is None else path).split(os.pathsep)


def _fence(outside: Optional[PathLike]) -> Optional[str]:
    if outside is None:
        return None
    # A fence that cannot be resolved still fences its spelling.
    return real_key(os.fspath(outside)) or os.path.normcase(os.path.abspath(os.fspath(outside)))


def which(name: str, path: Optional[str] = None, outside: Optional[PathLike] = None) -> Optional[str]:
    """The first program ``name`` in an absolute entry of ``path`` (default ``$PATH``)
    that is not inside ``outside``, or None."""
    if not is_bare(name):
        return None
    fence = _fence(outside)
    for entry in _search(path):
        if not entry or not os.path.isabs(entry):
            continue
        if fence is not None and _inside(entry, fence):
            continue
        found = _programs(entry, name)
        if found:
            return found[0]
    return None


def only_skipped(name: str, path: Optional[str] = None, outside: Optional[PathLike] = None,
                 base: Optional[PathLike] = None) -> List[Hit]:
    """Where ``name`` is reachable when ``which`` finds it nowhere: [] when ``which``
    finds it (or it is nowhere at all), else every program it passed over, once, in
    PATH order.

    A relative or empty entry resolves against ``base`` (default: the current
    directory), where a host started from that directory would look. Nothing found
    here is ever to be run.
    """
    if not is_bare(name) or which(name, path, outside) is not None:
        return []
    fence = _fence(outside)
    root = os.fspath(base) if base is not None else os.getcwd()
    hits: List[Hit] = []
    seen = set()
    for entry in _search(path):
        if not entry or not os.path.isabs(entry):
            directory, reason = os.path.normpath(os.path.join(root, entry)), RELATIVE_ENTRY
        elif fence is not None and _inside(entry, fence):
            directory, reason = entry, INSIDE_FENCE
        else:
            continue
        for full in _programs(directory, name):
            if full not in seen:
                seen.add(full)
                hits.append(Hit(full, entry, reason))
    return hits
