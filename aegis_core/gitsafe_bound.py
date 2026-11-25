"""Held checkout inputs for the read-only Git metadata queries."""
from __future__ import annotations

from collections import deque
from contextlib import ExitStack
import os
from pathlib import Path
import stat
import struct
import sys
import time
import unicodedata

from aegis_core import gitsafe_run
from aegis_core.gitsafe_policy import GitError

__all__ = ["bound_git_metadata", "discover_linux", "discover_pathname"]


def _metadata_unavailable(**details):
    return GitError("Git metadata path is unavailable.", code="git_path_unavailable", **details)


def _metadata_fd_root():
    if sys.platform == "linux" and os.path.isdir("/proc/self/fd"):
        return Path("/proc", str(os.getpid()), "fd")
    return None


def _metadata_stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_ctime_ns, info.st_mtime_ns)


def _metadata_entries(checkout_fd, marker_fd):
    checkout, marker = os.fstat(checkout_fd), os.fstat(marker_fd)
    visible = os.stat(".git", dir_fd=checkout_fd, follow_symlinks=False)
    if (
        not stat.S_ISDIR(checkout.st_mode)
        or not (stat.S_ISDIR(marker.st_mode) or stat.S_ISREG(marker.st_mode))
        or not checkout.st_ino or not marker.st_ino
        or _metadata_stamp(visible) != _metadata_stamp(marker)
    ):
        raise _metadata_unavailable()
    return checkout, marker


def _sealed_gitfile(marker_fd, marker, checkout, fd_root, stack):
    """Freeze the validated bytes; Git retains authority over both pointer targets."""
    import fcntl
    from aegis_core.git_path_codec import MAX_PATH_BYTES

    prefix = b"gitdir: "
    if os.pread(marker_fd, len(prefix), 0) != prefix:
        raise _metadata_unavailable()
    if marker.st_size > MAX_PATH_BYTES:
        raise GitError("Git path output exceeds its byte limit.", code="git_path_limit")
    raw = os.pread(marker_fd, marker.st_size + 1, 0)
    if len(raw) != marker.st_size or _metadata_stamp(os.fstat(marker_fd)) != _metadata_stamp(marker):
        raise _metadata_unavailable()
    target = gitsafe_run.path_text(raw, gitfile=True)
    if not target.startswith("/"):
        raw = prefix + os.fsencode(checkout) + b"/" + raw[len(prefix):]
    copy = os.memfd_create("aegis-gitfile", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        stack.callback(os.close, copy)
    except BaseException:
        os.close(copy)
        raise
    if os.write(copy, raw) != len(raw):
        raise _metadata_unavailable()
    seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    fcntl.fcntl(copy, fcntl.F_ADD_SEALS, seals)
    return fd_root / str(copy)


def _bound_metadata_answers(program, checkout, git_dir, query, deadline, verify):
    invoke = gitsafe_run.bound_metadata_reader(program, checkout, git_dir, deadline)

    def read(args):
        if verify is not None:
            verify()
        try:
            result = invoke(args)
        except GitError:
            raise _metadata_unavailable() from None
        if result.returncode:
            no_repository = result.returncode == 128 and result.stderr.startswith(b"fatal: not a git repository:")
            raise _metadata_unavailable(repository_missing=no_repository)
        try:
            answer = gitsafe_run.path_text(result.stdout) if result.stdout.endswith(b"\n") else None
        except GitError:
            raise _metadata_unavailable() from None
        if not answer:
            raise _metadata_unavailable()
        return Path(answer)

    if query == "hooks":
        options = ("--git-path", "hooks")
        # Git's absolute formatter resolves even an explicitly configured absolute alias.
        # Preserve that spelling as the ordinary hooks API does.
        answer = read(options)
        if answer.is_absolute() and not answer.is_relative_to(checkout.parent):
            return answer
        answers = (read(("--path-format=absolute", *options)),)
    else:
        answers = (read(("--path-format=absolute", "--git-dir")),
                   read(("--path-format=absolute", "--git-common-dir")))
    if any(not answer.is_absolute() or answer.is_relative_to(checkout.parent) for answer in answers):
        raise _metadata_unavailable()
    return answers[0] if query == "hooks" else answers


def bound_git_metadata(checkout_fd, marker_fd, query, *, executable, timeout, verify):
    """Linux descriptor transport for two closed, read-only Git queries."""
    fd_root = _metadata_fd_root()
    if fd_root is None or gitsafe_run.custody_active() or query not in ("hooks", "dirs") or any(
        type(fd) is not int or not 0 <= fd <= 2147483647 for fd in (checkout_fd, marker_fd)
    ):
        raise _metadata_unavailable()
    deadline = time.monotonic() + timeout
    checkout = fd_root / str(checkout_fd)
    try:
        original = _metadata_entries(checkout_fd, marker_fd)
        stamps = tuple(map(_metadata_stamp, original))
        checkout_spelling = os.readlink(checkout)
        marker = fd_root / str(marker_fd)
        with ExitStack() as stack:
            git_dir = marker if stat.S_ISDIR(original[1].st_mode) else _sealed_gitfile(
                marker_fd, original[1], checkout, fd_root, stack,
            )
            try:
                program = executable(cwd=checkout, missing_ok=True)
            except GitError:
                raise _metadata_unavailable() from None
            if program is None:
                raise _metadata_unavailable(executable_missing=True)
            answer = _bound_metadata_answers(program, checkout, git_dir, query, deadline, verify)
            if os.readlink(checkout) != checkout_spelling or tuple(
                map(_metadata_stamp, _metadata_entries(checkout_fd, marker_fd))
            ) != stamps:
                raise _metadata_unavailable()
    except (AttributeError, ImportError, OSError, ValueError, RuntimeError):
        raise _metadata_unavailable() from None
    return answer


_IN_MODIFY = 0x00000002
_IN_ATTRIB = 0x00000004
_IN_CLOSE_WRITE = 0x00000008
_IN_ENTRY_CHANGES = 0x000003C0  # IN_MOVED_FROM, IN_MOVED_TO, IN_CREATE, IN_DELETE
_IN_SELF_CHANGES = 0x00000C00  # IN_DELETE_SELF, IN_MOVE_SELF
_IN_LOST = 0x0000E000  # IN_UNMOUNT, IN_Q_OVERFLOW, IN_IGNORED
_IN_EVENT = struct.Struct("iIII")
_MAX_PATH = 32768
_MAX_COMPONENTS = 512
_MAX_EDGES = 4 * _MAX_COMPONENTS
_LOCAL_FILESYSTEMS = frozenset({
    0xEF53,      # ext2/ext3/ext4
    0x01021994,  # tmpfs
    0x9123683E,  # btrfs
    0x58465342,  # xfs
    0x794C7630,  # overlayfs
})


def _directory_identity(info):
    if not stat.S_ISDIR(info.st_mode) or not info.st_dev or not info.st_ino:
        raise OSError
    return info.st_dev, info.st_ino


def _entry_stamp(info):
    if info is None:
        return None
    if stat.S_ISDIR(info.st_mode):
        return _directory_identity(info)
    return _metadata_stamp(info)


def _event_name(name):
    # Conservatively cover equivalent spellings on casefold-enabled volumes.
    return unicodedata.normalize("NFC", os.fsdecode(name)).casefold()


def _filesystem_supported(statfs, buffer, fd):
    # The first word of the native Linux statfs structure is f_type.
    # Refuse filesystems where a quiet local inotify queue may miss remote changes.
    return statfs(fd, buffer) == 0 and buffer[0] in _LOCAL_FILESYSTEMS


class _Namespace:
    """Keep directory identities and separately remember each observed namespace edge."""

    def __init__(self, stack):
        import ctypes

        self.stack = stack
        libc = ctypes.CDLL(None)
        init, self.add_watch = libc.inotify_init1, libc.inotify_add_watch
        init.argtypes, init.restype = (ctypes.c_int,), ctypes.c_int
        self.add_watch.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32)
        self.add_watch.restype = ctypes.c_int
        self.statfs = libc.fstatfs
        self.statfs.argtypes, self.statfs.restype = (ctypes.c_int, ctypes.c_void_p), ctypes.c_int
        self.fs_buffer = (ctypes.c_ulong * 32)()
        self.events = init(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.events < 0:
            raise OSError
        self._own(self.events)
        self.edges = {}
        self.directories = {}
        self.watches = {}
        self.names = {}
        self.root = self._own(os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC))
        if not _filesystem_supported(self.statfs, self.fs_buffer, self.root):
            raise OSError
        self.root_identity = _directory_identity(os.fstat(self.root))
        self.directories[self.root_identity] = self.root

    def _own(self, fd):
        try:
            self.stack.callback(os.close, fd)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _watch(self, fd, *, directory):
        wd = self.watches.get(fd)
        if wd is None:
            mutation = _IN_ENTRY_CHANGES if directory else _IN_MODIFY | _IN_CLOSE_WRITE
            wd = self.add_watch(self.events, os.fsencode(f"/proc/self/fd/{fd}"),
                                mutation | _IN_SELF_CHANGES | _IN_ATTRIB)
            if wd < 0 or wd in self.names:
                raise OSError
            self.watches[fd] = wd
            self.names[wd] = set()
        return self.names[wd]

    def _visible(self, parent, name):
        try:
            return os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def entry(self, parent, name):
        # Arm the parent watch and register the name before the first observation.
        edge = (parent, name)
        if edge not in self.edges and len(self.edges) >= _MAX_EDGES:
            raise OSError
        self._watch(parent, directory=True).add(_event_name(name))
        seen = self._visible(parent, name)
        stamp = _entry_stamp(seen)
        if self.edges.setdefault(edge, stamp) != stamp:
            raise OSError
        return seen

    def directory(self, parent, name, entry):
        identity = _directory_identity(entry)
        fd = self.directories.get(identity)
        if fd is None:
            if len(self.directories) >= _MAX_COMPONENTS:
                raise OSError
            fd = self._own(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                   dir_fd=parent))
            if not _filesystem_supported(self.statfs, self.fs_buffer, fd):
                raise OSError
            self.directories[identity] = fd
        if _directory_identity(os.fstat(fd)) != identity:
            raise OSError
        return fd

    def parent(self, child, expected):
        if child is not None and expected is not None and (
            _directory_identity(os.stat("..", dir_fd=child, follow_symlinks=False))
            != _directory_identity(os.fstat(expected))
        ):
            raise OSError

    def regular_marker(self, checkout, entry):
        if not stat.S_ISREG(entry.st_mode) or not entry.st_dev or not entry.st_ino:
            raise OSError
        fd = self._own(os.open(".git", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                               dir_fd=checkout))
        if not _filesystem_supported(self.statfs, self.fs_buffer, fd):
            raise OSError
        self._watch(fd, directory=False)
        if _metadata_stamp(os.fstat(fd)) != _metadata_stamp(entry):
            raise OSError
        prefix_size = len(b"gitdir: ")
        prefix = os.pread(fd, min(entry.st_size + 1, prefix_size), 0)
        if len(prefix) != min(entry.st_size, prefix_size):
            raise OSError
        return fd if prefix == b"gitdir: " else None

    def _check_events(self):
        # Read after Git and the final edge checks. The kernel queues changes
        # made by completed operations even when their original names return.
        for _ in range(16):
            try:
                data = os.read(self.events, 65536)
            except BlockingIOError:
                return
            if not data:
                raise OSError
            offset = 0
            while offset + _IN_EVENT.size <= len(data):
                wd, mask, _, size = _IN_EVENT.unpack_from(data, offset)
                offset += _IN_EVENT.size
                if size > len(data) - offset or mask & (_IN_LOST | _IN_SELF_CHANGES) or wd not in self.names:
                    raise OSError
                name = data[offset:offset + size].partition(b"\0")[0]
                if not name or _event_name(name) in self.names[wd]:
                    raise OSError
                offset += size
            if offset != len(data):
                raise OSError
        raise OSError

    def verify(self):
        if _directory_identity(os.stat("/", follow_symlinks=False)) != self.root_identity:
            raise OSError
        for (parent, name), stamp in self.edges.items():
            if _entry_stamp(self._visible(parent, name)) != stamp:
                raise OSError
        self._check_events()


def _components(raw):
    if not raw or len(raw) > _MAX_PATH or raw.count("/") > _MAX_COMPONENTS or "\0" in raw:
        raise OSError
    if raw.startswith("//") and not raw.startswith("///"):
        raise OSError
    parts = [name for name in raw.split("/") if name not in ("", ".")]
    if any(len(name) > 255 or len(os.fsencode(name)) > 255 for name in parts):
        raise OSError
    return parts


def _walk_checkout(namespace, raw):
    pending = deque(_components(raw))
    chain = [(Path("/"), namespace.root)]
    links = 0
    missing = terminal_link = False
    while pending:
        path, parent = chain[-1]
        name = pending.popleft()
        if name == "..":
            if len(chain) > 1:
                namespace.parent(parent, chain[-2][1])
                chain.pop()
            continue
        if len(chain) >= _MAX_COMPONENTS or len(os.fspath(path)) + len(name) + 1 > _MAX_PATH:
            raise OSError
        entry = namespace.entry(parent, name) if parent is not None else None
        if entry is None:
            missing = True
            chain.append((path / name, None))
        elif stat.S_ISLNK(entry.st_mode):
            links += 1
            if links > 40:
                raise OSError
            target = os.readlink(name, dir_fd=parent)
            parts = _components(target)
            terminal_link |= not pending
            if len(parts) + len(pending) > _MAX_COMPONENTS:
                raise OSError
            pending.extendleft(reversed(parts))
            if target.startswith("/"):
                del chain[1:]
        else:
            chain.append((path / name, namespace.directory(parent, name, entry)))
    if missing and terminal_link:
        raise OSError
    return chain, missing


def _has_layout(namespace, marker):
    for name, expected in (("HEAD", stat.S_ISREG), ("objects", stat.S_ISDIR), ("refs", stat.S_ISDIR)):
        entry = namespace.entry(marker, name)
        if entry is None:
            return False
        if stat.S_ISLNK(entry.st_mode):
            try:
                entry = os.stat(name, dir_fd=marker)
            except FileNotFoundError:
                return False
        if not expected(entry.st_mode):
            return False
    return True


def _inspect(namespace, location, query, bound, *, at_start, entry):
    path, checkout = location
    if entry is None:
        return None
    if not stat.S_ISDIR(entry.st_mode):
        marker = namespace.regular_marker(checkout, entry)
        return bound(checkout, marker, query, verify=namespace.verify) if marker is not None else None
    marker = namespace.directory(checkout, ".git", entry)
    dot_git = path / ".git"
    if query == "dirs":
        return (dot_git, dot_git) if at_start or _has_layout(namespace, marker) else None
    try:
        return bound(checkout, marker, "hooks", verify=namespace.verify)
    except GitError as exc:
        if getattr(exc, "executable_missing", False):
            return dot_git / "hooks" if at_start or _has_layout(namespace, marker) else None
        if getattr(exc, "repository_missing", False):
            return dot_git / "hooks" if at_start else None
        raise


def _discover(namespace, chain, query, bound, discovery_paths, *, search, missing):
    first = chain[-1][0]
    candidates = iter(discovery_paths(first) if search else (first,))
    previous = None
    for index, location in enumerate(reversed(chain)):
        candidate = next(candidates, None)
        if candidate is None:
            if index == 0:
                raise OSError
            break
        path, checkout = location
        if candidate != path:
            raise OSError
        namespace.parent(previous, checkout)
        previous = checkout
        if index == 0 and missing:
            if query == "hooks" or not search:
                break
            continue
        entry = namespace.entry(checkout, ".git") if checkout is not None else None
        if index == 0 and query == "hooks" and entry is None:
            break
        found = _inspect(namespace, location, query, bound, at_start=index == 0, entry=entry)
        if found is not None:
            return found
    return None


def discover_linux(raw, query, bound, discovery_paths, *, search, descriptors):
    """Resolve an absolute checkout while holding its observed Git inputs."""
    if not isinstance(raw, str) or not raw.startswith("/") or not descriptors or _metadata_fd_root() is None:
        raise _metadata_unavailable()
    try:
        with ExitStack() as stack:
            namespace = _Namespace(stack)
            chain, missing = _walk_checkout(namespace, raw)
            try:
                answer = _discover(namespace, chain, query, bound, discovery_paths, search=search, missing=missing)
            except GitError:
                namespace.verify()
                raise
            namespace.verify()
            return answer
    except (AttributeError, ImportError, OSError, RuntimeError, ValueError):
        raise _metadata_unavailable() from None


def _read_pathname_record(path):
    from aegis_core.git_path_codec import MAX_PATH_BYTES

    with path.open("rb") as record:
        return record.read(MAX_PATH_BYTES + 1)


def _pathname_dirs(checkout):
    marker = checkout / ".git"
    if marker.is_dir():
        return marker, marker
    if not marker.is_file():
        return None
    try:
        raw = _read_pathname_record(marker)
        if not raw.startswith(b"gitdir: "):
            return None
        from aegis_core.git_path_codec import path_text

        git_dir = Path(path_text(raw, gitfile=True))
        if not git_dir.is_absolute():
            git_dir = (checkout / git_dir).resolve()
        common = git_dir / "commondir"
        if common.is_file():
            return git_dir, (git_dir / path_text(_read_pathname_record(common), record=True)).resolve()
        if git_dir.parent.name == "worktrees" and git_dir.parent.parent.is_dir():
            return git_dir, git_dir.parent.parent
        return git_dir, git_dir
    except (OSError, ValueError):
        return None


def discover_pathname(root, query, git_path, discovery_paths, *, search):
    """Preserve pathname-based discovery on macOS, FreeBSD and Windows.

    Concurrent metadata changes can affect the Git answer and fallback reads.
    HOOKS-GITFILE-POSIX-BOUND-ROUTE and HOOKS-GITFILE-WINDOWS-BOUND-ROUTE
    track binding Git to the held checkout and marker on these platforms.
    """
    if not search:
        return _pathname_dirs(root)
    start = Path(root or Path.cwd()).resolve()
    if query == "hooks":
        if not (start / ".git").exists():
            return None
        hooks = git_path(start, "hooks")
        if hooks is not None:
            return hooks
    for candidate in discovery_paths(start):
        found = _pathname_dirs(candidate)
        if found is not None:
            git_dir, common = found
            if candidate == start or (
                (git_dir / "HEAD").is_file()
                and (common / "objects").is_dir()
                and (common / "refs").is_dir()
            ):
                return common / "hooks" if query == "hooks" else found
    return None
