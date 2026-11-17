"""The one lookup of a program on PATH (L0: standard library only).

Aegis runs what this finds (a host CLI, ``python3``) and writes the ``aegis-mcp`` it
finds into a host's user config, from inside a repository the user may just have
cloned (host-matrix §3.7). So only absolute PATH entries count:

- an empty or relative entry names a directory relative to the current directory,
  where the repository can plant a program;
- ``shutil.which`` on Windows searches the current directory first whatever its
  ``path=`` says, so it is not used;
- an absolute entry inside ``outside`` (doctor passes the workspace) is the
  repository's own. So is an entry whose resolution visits ``outside``: every
  literal component of the spelling and of each symlink target is walked with
  no-follow metadata, and ``..`` applies to that walked path;
- with ``fence_program=True``, a program whose walk visits ``outside`` is excluded
  even when its PATH entry is outside. Its spelling stays unresolved.

The result is the PATH entry joined with the file's name as the directory spells it,
never resolved: version managers (Volta, mise, asdf) install a tool as a link to one
dispatcher that picks the tool from the name it is run under. On Windows, PATHEXT
candidates are matched case-insensitively against the directory listing, so the
command run (or written into a config) carries the file's own spelling.

``only_skipped`` says where a program is reachable when ``which`` refused every place,
so a caller can report such a host as unknown rather than absent.
"""
from __future__ import annotations

import errno
import ntpath
import os
import stat
import sys
import threading
from typing import List, NamedTuple, Optional, Union

from aegis_core.primitives import key_within, real_key, sanitize_display
from aegis_core.redaction import redact_insight_text

__all__ = ["Hit", "INSIDE_FENCE", "RELATIVE_ENTRY", "descriptor_fence_supported", "GitCache",
           "git_fence", "is_bare", "only_skipped", "which"]

_MAX_FENCE_CHARS = 16384
_MAX_COMPONENTS = 512
_MAX_LINK_HOPS = 40

PathLike = Union[str, "os.PathLike[str]"]


class _PathSpelling:
    """Platform separators and raw path operations; never collapse ``..``."""

    @staticmethod
    def separators():
        return os.sep + (os.altsep or "")

    @classmethod
    def trim(cls, text):
        return text.rstrip(cls.separators())

    @staticmethod
    def join(*parts):
        return os.path.join(*parts)

    @staticmethod
    def drive(text):
        return os.path.splitdrive(text)

    @staticmethod
    def root(drive=""):
        return drive + os.sep

    @classmethod
    def parent(cls, text):
        return os.path.dirname(cls.trim(text)) or text

    @classmethod
    def split(cls, text):
        """Bounded components, retaining ``..`` and dropping empty and ``.``."""
        parts, buf = [], []
        separators = cls.separators()
        for char in text:
            if char in separators:
                part = "".join(buf)
                buf = []
                if part not in ("", "."):
                    parts.append(part)
                    if len(parts) > _MAX_COMPONENTS:
                        return None
                continue
            buf.append(char)
        tail = "".join(buf)
        if tail not in ("", "."):
            parts.append(tail)
        return None if len(parts) > _MAX_COMPONENTS else parts


class _ClosedFence(str):
    """An unproven discovery keeps its displayed volume and refuses every drive."""

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
        full = _PathSpelling.join(directory, candidate)
        if os.path.isfile(full) and os.access(full, os.X_OK):
            found.append(full)
    return found


def _inside(entry: str, fence: str, *, descriptors=None) -> bool:
    """Whether resolving ``entry`` visits ``fence``. An unproven walk is inside.

    Each literal component of the spelling and of every symlink target is walked
    with no-follow metadata. ``..`` moves on that walked path and is never collapsed
    out of the spelling first, so a detour through ``fence`` cannot hide behind it.
    """
    return _provenance_inside(entry, fence, descriptors=descriptors)


def _inside_program(entry: str, fence: str, *, descriptors=None) -> bool:
    """Program spellings use the same provenance predicate as their directories."""
    return _inside(entry, fence, descriptors=descriptors)


def _search(path: Optional[str]) -> List[str]:
    return (os.environ.get("PATH", os.defpath) if path is None else path).split(os.pathsep)


def _fence(outside: Optional[PathLike]) -> Optional[str]:
    if outside is None:
        return None
    if isinstance(outside, _ClosedFence):
        return outside
    # A fence that cannot be resolved still fences its spelling.
    return real_key(os.fspath(outside)) or os.path.normcase(os.path.abspath(os.fspath(outside)))


def _visible(programs: List[str], fence: Optional[str], *, descriptors=None) -> List[str]:
    """Programs whose resolved path is outside ``fence``. No fence keeps every program."""
    if fence is None:
        return programs
    return [program for program in programs if not _inside_program(program, fence, descriptors=descriptors)]


def which(name: str, path: Optional[str] = None, outside: Optional[PathLike] = None,
          *, fence_program: bool = False, descriptors=None) -> Optional[str]:
    """The first program ``name`` in an absolute entry of ``path`` (default ``$PATH``)
    that is not inside ``outside``, or None.

    ``fence_program`` checks both program spellings and resolved paths. Strict transports
    retain the default entry-only fence and apply their own typed program refusal.
    """
    if not is_bare(name):
        return None
    fence = _fence(outside)
    for entry in _search(path):
        if not _absolute_entry(entry):
            continue
        if fence is not None and (_inside_program(entry, fence, descriptors=descriptors) if fence_program else _inside(entry, fence, descriptors=descriptors)):
            continue
        found = _programs(entry, name)
        if fence_program:
            found = _visible(found, fence, descriptors=descriptors)
        if found:
            return found[0]
    return None


def only_skipped(name: str, path: Optional[str] = None, outside: Optional[PathLike] = None,
                 base: Optional[PathLike] = None, *, fence_program: bool = False) -> List[Hit]:
    """Where ``name`` is reachable when ``which`` finds it nowhere: [] when ``which``
    finds it (or it is nowhere at all), else every program it passed over, once, in
    PATH order.

    A relative or empty entry resolves against ``base`` (default: the current
    directory), where a host started from that directory would look. Nothing found
    here is ever to be run.
    """
    if not is_bare(name) or which(name, path, outside, fence_program=fence_program) is not None:
        return []
    fence = _fence(outside)
    root = os.fspath(base) if base is not None else os.getcwd()
    hits: List[Hit] = []
    seen = set()
    for entry in _search(path):
        if not _absolute_entry(entry):
            programs = _programs(os.path.normpath(_PathSpelling.join(root, entry)), name)
            reason = RELATIVE_ENTRY
        elif fence is not None and (_inside_program(entry, fence) if fence_program else _inside(entry, fence)):
            programs = _programs(entry, name)
            reason = INSIDE_FENCE
        elif fence_program and fence is not None:
            programs = [full for full in _programs(entry, name) if _inside_program(full, fence)]
            reason = INSIDE_FENCE
        else:
            continue
        for full in programs:
            if full not in seen:
                seen.add(full)
                hits.append(Hit(full, entry, reason))
    return hits


def _is_root(path: str) -> bool:
    _drive, rest = _PathSpelling.drive(path)
    return not rest or (len(rest) == 1 and rest in _PathSpelling.separators())


def _component_budget(text: str) -> bool:
    """Count components without allocating a split list or resolving any path."""
    separators = _PathSpelling.separators()
    return sum(character not in separators and (index == 0 or text[index - 1] in separators)
               for index, character in enumerate(text)) <= _MAX_COMPONENTS


def _fence_text(start) -> Optional[str]:
    """Bound cwd bytes before decoding. Trusted caller protocol exceptions propagate."""
    try:
        if start is None:
            start = os.getcwd()
    except (OSError, ValueError, RuntimeError):
        return None
    if not isinstance(start, (str, bytes)):
        if not isinstance(start, os.PathLike):
            return None
        start = start.__fspath__()
    if not isinstance(start, (str, bytes)) or not start or len(start) > _MAX_FENCE_CHARS:
        return None
    text = os.fsdecode(start) if isinstance(start, bytes) else start
    return text if _bounded_text(text) else None

def descriptor_fence_supported() -> bool:
    """True when a directory can be opened from the root without following links."""
    if os.name != "posix":
        return False
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        return False
    # Names only. A descriptor operation used as a value is a forbidden reference.
    dir_fd_names = {entry.__name__ for entry in getattr(os, "supports_dir_fd", ())}
    if not {"open", "stat"} <= dir_fd_names:
        return False
    follow_names = {entry.__name__ for entry in getattr(os, "supports_follow_symlinks", ())}
    if "stat" not in follow_names:
        return False
    locator = "/proc/self/fd" if os.path.isdir("/proc/self/fd") else "/dev/fd"
    if not os.path.isdir(locator):
        return False
    fd = None
    try:
        fd = _open_directory(None, _PathSpelling.root())
        return os.path.realpath(_PathSpelling.join(locator, str(fd))) == os.path.realpath(os.sep)
    except (OSError, ValueError, RuntimeError):
        return False
    finally:
        _close_fd(fd)


def _close_fd(fd: Optional[int]) -> None:
    if fd is not None:
        os.close(fd)


def _open_directory(parent, name):
    from aegis_core.pathlookup_fence import open_directory
    return open_directory(parent, name)

def _open_leaf(parent, name):
    from aegis_core.pathlookup_fence import open_leaf
    return open_leaf(parent, name)

def _replace_fd(current: Optional[int], opened: int) -> int:
    """Own ``opened`` in place of ``current``. A failed close closes ``opened`` too."""
    try:
        if current is not None:
            os.close(current)
    except OSError:
        _close_fd(opened)
        raise
    return opened


def _walk_descriptors() -> bool:
    """True when a PATH walk can open each component from a held parent descriptor."""
    names = {entry.__name__ for entry in getattr(os, "supports_dir_fd", ())}
    return descriptor_fence_supported() and "readlink" in names


def _compare_key(path: str) -> str:
    """One spelling for fence checks, including Windows extended-length prefixes.

    A non-root trailing separator is not a different directory.
    """
    folded = os.path.normcase(path)
    if os.name == "nt" and (folded.startswith("\\\\?\\") or folded.startswith("\\\\.\\")):
        folded = folded[4:]
        if folded.startswith("unc\\"):
            folded = "\\\\" + folded[4:]
    if not _is_root(folded):
        folded = _PathSpelling.trim(folded)
    return folded


def _component_inside(path: str, fence: str) -> bool:
    return key_within(_compare_key(path), _compare_key(fence))


def _bounded_text(text: str) -> bool:
    return isinstance(text, str) and bool(text) and len(text) <= _MAX_FENCE_CHARS and "\0" not in text and _component_budget(text)


def _current_drive() -> Optional[str]:
    """Drive letter or UNC root of the cwd. Windows resolves ``\\ws\\bin`` on that drive."""
    try:
        drive = _PathSpelling.drive(os.getcwd())[0]
    except OSError:
        return None
    return drive or None


def _drive_less_rooted(path: str) -> bool:
    """``\\ws\\bin`` on Windows. ``ntpath.isabs`` is false for that spelling on 3.13."""
    if os.name != "nt" or not isinstance(path, str) or not path:
        return False
    drive, rest = _PathSpelling.drive(path)
    if drive or not rest or rest[0] not in _PathSpelling.separators():
        return False
    return len(rest) == 1 or rest[1] not in _PathSpelling.separators()


def _absolute_entry(entry: str) -> bool:
    """An absolute PATH entry, including a drive-less Windows root."""
    return bool(entry) and (os.path.isabs(entry) or _drive_less_rooted(entry))


def _literal_parts(path: str):
    """``(drive, parts)`` for an absolute spelling, or None when it cannot be walked.

    A drive-less root such as ``\\ws\\bin`` uses the current drive. Symlink targets
    that are drive-less bind to the walked drive in ``_splice_target`` instead.
    """
    if not _bounded_text(path):
        return None
    source = _compare_key(path) if os.name == "nt" else path
    if not os.path.isabs(source) and not _drive_less_rooted(source):
        return None
    drive, rest = _PathSpelling.drive(source)
    if not drive and os.name == "nt":
        drive = _current_drive()
        if not drive:
            return None
    parts = _PathSpelling.split(rest)
    if parts is None:
        return None
    return drive, parts


def _relative_parts(target: str):
    """Components of a relative link target. Drive-relative ``C:sub`` is rejected."""
    if not _bounded_text(target):
        return None
    if os.name == "nt":
        letter, _rest = _PathSpelling.drive(target)
        if letter or _drive_less_rooted(target):
            return None
    elif os.path.isabs(target):
        return None
    if os.path.isabs(target):
        return None
    return _PathSpelling.split(target)


def _path_text(drive: str, parts) -> str:
    root = _PathSpelling.root(drive)
    size = len(root) + sum(len(part) + 1 for part in parts)
    if len(parts) > _MAX_COMPONENTS or size > _MAX_FENCE_CHARS + 1:
        raise OSError(errno.ENAMETOOLONG, "walk path budget")
    if not parts:
        return root
    return _PathSpelling.join(root, *parts)


def _provenance_inside(path: str, fence: str, *, descriptors=None) -> bool:
    """True when ``path`` visits ``fence`` or either predicate cannot prove it does not.

    The component walk and ``real_key`` must both say outside. On Windows a
    non-``\\\\?\\`` spelling is also walked after ``abspath`` so Win32 ``..``
    collapse cannot hide a fence visit. ``real_key`` None refuses.
    """
    if isinstance(fence, _ClosedFence) or not _bounded_text(path) or not _bounded_text(fence):
        return True
    try:
        if not _proven_outside(path, fence, descriptors=descriptors):
            return True
        if os.name == "nt" and not os.path.normcase(path).startswith("\\\\?\\"):
            collapsed = os.path.abspath(path)
            if os.path.normcase(collapsed) != os.path.normcase(path):
                if not _proven_outside(collapsed, fence, descriptors=descriptors):
                    return True
        key, base = _observed_real_key(path), _observed_real_key(fence)
        if key is None or base is None:
            return True
        return key_within(key, base)
    except (OSError, ValueError, RuntimeError):
        return True


def _proven_outside(path: str, fence: str, *, descriptors) -> bool:
    """True when the component walk stays outside ``fence``. Unproven is false."""
    # descriptors=False is the metadata walk: same component provenance, no os.open.
    use_descriptors = _walk_descriptors() if descriptors is not False else False
    return _descriptor_outside(path, fence) if use_descriptors else _metadata_outside(path, fence)


# Tests on platforms without junctions replace this with a callable(text) -> kind or None.
_reparse_observer = None
# Tests inject canonical keys the host cannot produce (8.3, trailing dots). None refuses.
# Return ``_REAL_KEY_FALLBACK`` to use ``real_key``.
_real_key_observer = None
_REAL_KEY_FALLBACK = object()


def _observed_real_key(path: str):
    observer = _real_key_observer
    if observer is not None:
        observed = observer(path)
        if observed is not _REAL_KEY_FALLBACK:
            return observed
    return real_key(path)


def _classify(text: str):
    """No-follow kind of ``text``: ``node``, ``link``, ``special``, ``unsupported``, or None."""
    observer = _reparse_observer
    if observer is not None:
        observed = observer(text)
        if observed is not None:
            return observed
    return _classify_platform(text)


def _reparse_link(info, text: str):
    """Windows junction or symlink target. Other reparse tags are unsupported. POSIX is None."""
    if os.name != "nt":
        return None
    attributes = getattr(info, "st_file_attributes", 0) or 0
    if not attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        return None
    tag = getattr(info, "st_reparse_tag", 0) or 0
    supported = (
        getattr(stat, "IO_REPARSE_TAG_SYMLINK", 0xA000000C),
        getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003),
    )
    if tag not in supported:
        return ("unsupported", None)
    try:
        return ("link", os.readlink(text))
    except OSError:
        return ("unsupported", None)


def _classify_platform(text: str):
    try:
        info = os.lstat(text)
    except OSError:
        return None
    mode = info.st_mode
    if stat.S_ISLNK(mode):
        try:
            return ("link", os.readlink(text))
        except OSError:
            return None
    reparse = _reparse_link(info, text)
    if reparse is not None:
        return reparse
    if stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return ("special", None)
    if stat.S_ISDIR(mode):
        return ("dir", None)
    if stat.S_ISREG(mode):
        return ("file", None)
    return ("special", None)


def _literal_root(physical, drive):
    """Accept only the same normalized volume root, never a canonical alias."""
    parsed = _literal_parts(physical)
    if parsed is None or parsed != _literal_parts(_PathSpelling.root(drive)):
        return None
    return parsed


def _walk_root(drive, fence, markers):
    """Prove a literal root before any starting or reset component is visited."""
    if len(drive) + 1 > _MAX_FENCE_CHARS:
        return None
    physical = _observed_real_key(_PathSpelling.root(drive))
    parsed = _literal_root(physical, drive)
    if parsed is None or (fence is not None and _component_inside(physical, fence)):
        return None
    _note(parsed[0], parsed[1], markers)
    return parsed


def _walk_state(path: str, fence: Optional[str], markers=None) -> Optional[str]:
    """Physical spelling of ``path``, or None when unproven or when a component enters ``fence``.

    One state: the physical component stack, the remaining components, and the hop count.
    A link splices its target in front of the remainder. Nothing recursive returns a location.
    ``markers`` records each physical directory that carries a repository marker.
    A non-directory with components left is unproven: ``..`` cannot back out of a file.
    """
    parsed = _literal_parts(path)
    if parsed is None:
        return None
    drive, remaining = parsed
    root = _walk_root(drive, fence, markers)
    if root is None:
        return None
    drive, stack = root
    remaining = list(remaining)
    hops = 0
    while remaining:
        part = remaining.pop(0)
        if part == "..":
            if stack:
                stack.pop()
            if fence is not None and _component_inside(_path_text(drive, stack), fence):
                return None
            _note(drive, stack, markers)
            continue
        text = _path_text(drive, stack + [part])
        if fence is not None and _component_inside(text, fence):
            return None
        kind = _classify(text)
        if kind is None or kind[0] in ("special", "unsupported"):
            return None
        if kind[0] == "link":
            if hops >= _MAX_LINK_HOPS:
                return None
            hops += 1
            spliced = _splice_target(kind[1], remaining, drive)
            if spliced is None:
                return None
            new_drive, parts, absolute = spliced
            remaining = parts
            if absolute:
                root = _walk_root(new_drive, fence, markers)
                if root is None:
                    return None
                drive, stack = root
            continue
        if kind[0] != "dir" and remaining:
            return None
        if kind[0] == "dir":
            physical = _observed_real_key(text)
            parsed = _literal_parts(physical) if physical is not None else None
            if parsed is None or (fence is not None and _component_inside(physical, fence)):
                return None
            drive, stack = parsed
            _note(drive, stack, markers)
            continue
        stack.append(part)
    if fence is not None and _component_inside(_path_text(drive, stack), fence):
        return None
    return _path_text(drive, stack)


def _metadata_outside(path: str, fence: str) -> bool:
    return _walk_state(path, fence) is not None


def _splice_target(target, pending, drive=""):
    """Splice ``target`` in front of ``pending``. A drive-less root binds to ``drive``."""
    if isinstance(target, bytes):
        if len(target) > _MAX_FENCE_CHARS:
            return None
        target = os.fsdecode(target)
    if not isinstance(target, str) or not _bounded_text(target):
        return None
    if _drive_less_rooted(target):
        parts = _PathSpelling.split(_PathSpelling.drive(target)[1])
        if parts is None or not drive or len(parts) + len(pending) > _MAX_COMPONENTS:
            return None
        return drive, parts + pending, True
    if os.path.isabs(target):
        parsed = _literal_parts(target)
        if parsed is None or len(parsed[1]) + len(pending) > _MAX_COMPONENTS:
            return None
        return parsed[0], parsed[1] + pending, True
    parts = _relative_parts(target)
    if parts is None or len(parts) + len(pending) > _MAX_COMPONENTS:
        return None
    return None, parts + pending, False


def _dirfd_kind(dir_fd, part):
    from aegis_core.pathlookup_fence import directory_kind
    return directory_kind(dir_fd, part)

def _descriptor_outside(path: str, fence: str) -> bool:
    from aegis_core.pathlookup_fence import proven_outside
    return proven_outside(path, fence, _FenceHost())

def _fd_location(fd):
    from aegis_core.pathlookup_fence import fd_location
    return fd_location(fd, _FenceHost())

def _marker(dirfd: int) -> bool:
    """Inspect marker metadata without opening repository content (including FIFOs)."""
    try:
        os.stat(".git", dir_fd=dirfd, follow_symlinks=False)
        return True
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return False
        raise


def _fence_raw(start: str):
    """Join the raw cwd without collapsing parent traversal or drive-relative input."""
    if _absolute_entry(start):
        return start
    if _PathSpelling.drive(start)[0]:
        return None
    cwd = os.getcwd()
    if not isinstance(cwd, str) or not cwd or len(cwd) > _MAX_FENCE_CHARS:
        return None
    base = _PathSpelling.trim(cwd)
    if len(base) + 1 + len(start) > _MAX_FENCE_CHARS:
        return None
    return _PathSpelling.join(cwd, start)

def _record_markers(path: str, markers) -> None:
    """Inspect every canonical physical ancestor; unreadable metadata is unproven."""
    canonical = _observed_real_key(path)
    if not _bounded_text(canonical):
        raise OSError(errno.EXDEV, "unproven marker location")
    probe = _compare_key(canonical)
    checked = getattr(markers, "checked", None)
    for _ in range(_MAX_COMPONENTS + 1):
        if checked is not None:
            if probe in checked:
                return
            checked.add(probe)
        try:
            os.stat(_PathSpelling.join(probe, ".git"), follow_symlinks=False)
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                raise
        else:
            markers.add(probe)
        if _is_root(probe):
            return
        probe = _PathSpelling.parent(probe)
    raise OSError(errno.ELOOP, "marker ancestors")


def _note(drive: str, stack, markers) -> None:
    if markers is not None:
        _record_markers(_path_text(drive, stack), markers)


class _MarkerSet(set):
    """Markers and the physical ancestors already inspected during this walk."""

    def __init__(self):
        super().__init__()
        self.checked = set()



class _FenceHost:
    """Descriptor discovery calls these. Each lookup uses this module's globals."""

    def normcase(self, path):
        return os.path.normcase(path)

    def raw(self, path):
        return _fence_raw(path)

    def markers(self):
        return _MarkerSet()

    def canonical(self, path):
        return _observed_real_key(path)

    def inside(self, path, fence):
        return _component_inside(path, fence)

    def bounded(self, path):
        return _bounded_text(path)

    def max_chars(self):
        return _MAX_FENCE_CHARS

    def open_leaf(self, parent, name):
        return _open_leaf(parent, name)

    def splitdrive(self, path):
        return _PathSpelling.drive(path)

    def root(self, drive):
        return _PathSpelling.root(drive)

    def join(self, *parts):
        return _PathSpelling.join(*parts)

    def separators(self):
        return _PathSpelling.separators()

    def closed(self, start):
        return _fence_closed(start)

    def record(self, path, markers):
        _record_markers(path, markers)

    def literal(self, path):
        return _literal_parts(path)

    def literal_root(self, path, drive):
        return _literal_root(path, drive) is not None

    def open_directory(self, parent, name):
        return _open_directory(parent, name)

    def fd_location(self, fd):
        return _fd_location(fd)

    def close(self, fd):
        _close_fd(fd)

    def replace(self, current, opened):
        return _replace_fd(current, opened)

    def kind(self, dir_fd, part):
        return _dirfd_kind(dir_fd, part)

    def readlink(self, part, dir_fd):
        return os.readlink(part, dir_fd=dir_fd)

    def splice(self, target, pending, drive):
        return _splice_target(target, pending, drive)

    def marker(self, dirfd):
        return _marker(dirfd)

    def max_hops(self):
        return _MAX_LINK_HOPS

    def choose(self, markers, physical, start):
        return _choose_fence(markers, physical, start)


def _choose_fence(markers, physical, start: str) -> str:
    if not markers:
        return os.path.normcase(physical)
    for marker in markers:
        if all(key_within(_compare_key(other), _compare_key(marker)) for other in markers):
            return os.path.normcase(marker)
    return _fence_closed(start)

def _fence_lexical(start: str) -> str:
    """The raw metadata walk records all visited physical and spelling ancestors."""
    raw = _fence_raw(start)
    if raw is None:
        return _fence_closed(start)
    markers = _MarkerSet()
    physical = _walk_state(raw, None, markers)
    if physical is None:
        return _fence_closed(start)
    canonical = _observed_real_key(raw)
    if not _bounded_text(canonical):
        return _fence_closed(start)
    if _compare_key(canonical) != _compare_key(physical):
        physical = _walk_state(canonical, None, markers)
        if physical is None:
            return _fence_closed(start)
    if os.path.isfile(physical) and not os.path.islink(physical):
        physical = _PathSpelling.parent(physical)
    return _choose_fence(markers, physical, start)

def _fence_descriptors(start: str) -> str:
    """Outermost marker on the raw descriptor walk, or the volume when unproven."""
    from aegis_core.pathlookup_fence import discover_descriptors
    return discover_descriptors(start, _FenceHost())


def _fence_closed(start: str) -> str:
    """Fence the entire volume when discovery fails; a subdirectory is not a safe root."""
    try:
        drive, _rest = _PathSpelling.drive(os.path.abspath(start))
        return _ClosedFence(os.path.normcase(_PathSpelling.root(drive)))
    except (OSError, ValueError, RuntimeError):
        return _ClosedFence(os.path.normcase(os.path.abspath(os.sep)))


def _fence_discover(text: str) -> str:
    if descriptor_fence_supported():
        return _fence_descriptors(text)
    return _fence_lexical(text)


def git_fence(start=None, *, descriptors=None) -> str:
    """Outermost marked ancestor of ``start`` (default: cwd), or start itself.

    Directory, gitfile and symlink markers count without reading their contents.
    Git discovery ceilings cannot narrow this security fence. A marker at the
    filesystem root fences the entire volume, without a special exception.
    Unusable starts and discovery errors fence the entire volume, so ordinary Git
    resolution refuses rather than trusting a smaller, unverified workspace.
    ``descriptors=False`` uses the metadata walk so ordinary resolution does not
    spend a component ``os.open`` per directory on the hook path.
    """
    text = _fence_text(start)
    if text is None:
        return _fence_closed(os.sep)
    try:
        if descriptors is False:
            return _fence_lexical(text)
        return _fence_discover(text)
    except (OSError, ValueError, RuntimeError):
        return _fence_closed(text)


class _RootCache:
    """``store`` with each key prefixed by the fence captured for this call."""

    __slots__ = ("_store", "fence")

    def __init__(self, store, fence: Optional[str]) -> None:
        self._store = store
        self.fence = fence

    def get(self, key, default=None):
        with self._store._lock:
            found = self._store.get((self.fence, key), default)
        # Revalidate outside the lock: a walk must not run while the lock is held.
        if found and self.fence is not None and _inside_program(found, self.fence, descriptors=False):
            return default
        return found

    def __setitem__(self, key, value) -> None:
        with self._store._lock:
            self._store[(self.fence, key)] = value

    def clear(self) -> None:
        """Drop this fence's partition. ``GitCache.clear`` still drops every fence."""
        with self._store._lock:
            fence = self.fence
            keys = [key for key in self._store if isinstance(key, tuple) and key[:1] == (fence,)]
            for key in keys:
                self._store.pop(key, None)

    def error(self, error):
        """Keep the ordinary refusal type/code and name its enclosing fence safely."""
        def refuse(message, **details):
            canonical = sanitize_display(self.fence, max_len=None)
            redacted = redact_insight_text(canonical, max_len=max(1, len(canonical)))
            shown = sanitize_display(redacted, max_len=256)
            return error(message + "; excluding enclosing checkout " + shown, **details)
        return refuse


class _FenceCacheStore(dict):
    """One reentrant lock for cache operations; iterators are stable snapshots."""

    def __init__(self, *args, **kwargs):
        self._lock = threading.RLock()
        super().__init__(*args, **kwargs)

    def __getitem__(self, key):
        with self._lock:
            return super().__getitem__(key)

    def __setitem__(self, key, value):
        with self._lock:
            super().__setitem__(key, value)

    def __delitem__(self, key):
        with self._lock:
            super().__delitem__(key)

    def __contains__(self, key):
        with self._lock:
            return super().__contains__(key)

    def __len__(self):
        with self._lock:
            return super().__len__()

    def __iter__(self):
        with self._lock:
            return iter(tuple(super().keys()))

    def get(self, key, default=None):
        with self._lock:
            return super().get(key, default)

    def pop(self, key, *default):
        with self._lock:
            return super().pop(key, *default)

    def popitem(self):
        with self._lock:
            return super().popitem()

    def setdefault(self, key, default=None):
        with self._lock:
            return super().setdefault(key, default)

    def clear(self):
        with self._lock:
            super().clear()

    def copy(self):
        with self._lock:
            return super().copy()

    def keys(self):
        with self._lock:
            return tuple(super().keys())

    def items(self):
        with self._lock:
            return tuple(super().items())

    def values(self):
        with self._lock:
            return tuple(super().values())

    def update(self, *args, **kwargs):
        if len(args) == 1 and isinstance(args[0], _FenceCacheStore):
            incoming = args[0].copy()
            incoming.update(kwargs)
        else:
            incoming = dict(*args, **kwargs)
        with self._lock:
            super().update(incoming)

    def __ior__(self, other):
        self.update(other)
        return self



class GitCache(_FenceCacheStore):
    """Ordinary executable cache partitioned by each call's discovered workspace."""

    def for_cwd(self, cwd=None) -> _RootCache:
        # Metadata fence: the descriptor walk's component opens exceed the hook budget.
        return _RootCache(self, _fence(git_fence(cwd, descriptors=False)))
