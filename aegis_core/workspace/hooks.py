"""Git hook directory resolution and worktree awareness (Layer 0 Core).

Handles standard Git repositories (.git directory), Git worktrees (.git pointer file),
and custom core.hooksPath configuration via git CLI or pure Python fallback.
Strictly zero-dependency: uses only Python standard library.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import os
from pathlib import Path
import stat
import sys

from aegis_core.gitsafe_policy import GitError
from aegis_core.workspace.binding import git_discovery_paths


_GITFILE_PREFIX = b"gitdir: "
_MAX_COMPONENT_LEN = 255
_MAX_DIRECTORY_COMPONENTS = 512
_MAX_JUNCTION_DEPTH = 16
_MAX_PATH_CHARS = 32768
_NATIVE_PATH = type(Path("."))
_NATIVE_REALPATH = os.path.realpath
_WINDOWS_INVALID_CHARS = frozenset('<>:"/\\|?*')
_WINDOWS_DEVICES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{n}" for n in (*range(1, 10), "\xb9", "\xb2", "\xb3")}
    | {f"LPT{n}" for n in (*range(1, 10), "\xb9", "\xb2", "\xb3")}
)


def _native_path(value) -> Path:
    return value if type(value) is _NATIVE_PATH else _NATIVE_PATH(os.fspath(value))


def _sep() -> str:
    return "\\" if os.name == "nt" else "/"


def _seps() -> str:
    return "/\\" if os.name == "nt" else "/"


def _join_child(base_str: str, child: str) -> str:
    return (base_str if base_str[-1] in _seps() else base_str + _sep()) + child


def _dotdot_spelling(curr_str: str) -> str:
    return _join_child(str(curr_str), "..")


def _real_windows_path(raw: str) -> str:
    if raw[:4].replace("/", "\\") in ("\\\\?\\", "\\\\.\\"):
        raise OSError
    real = os.path.realpath(raw)
    if real.startswith(("\\\\?\\UNC\\", "\\\\?\\unc\\")):
        real = "\\\\" + real[8:]
    elif real.startswith("\\\\?\\"):
        real = real[4:]
    if os.path.islink(real):
        raise OSError
    return real


def _valid_identity(info) -> bool:
    dev = getattr(info, "st_dev", 0)
    ino = getattr(info, "st_ino", 0)
    return type(dev) is int and type(ino) is int and dev != 0 and ino != 0


def _same_identity(left, right) -> bool:
    return _valid_identity(left) and _valid_identity(right) and (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _is_reparse_point(info) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _is_windows_junction(info) -> bool:
    return (
        os.name == "nt" and stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
        and _is_reparse_point(info)
        and getattr(info, "st_reparse_tag", 0) == getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003)
    )


def _is_plain_directory(info) -> bool:
    return stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and not _is_reparse_point(info) and _valid_identity(info)


def _validate_component(component: str, windows: bool) -> None:
    if not component or len(component) > _MAX_COMPONENT_LEN or "\x00" in component or "/" in component:
        raise OSError
    if windows:
        if (
            "\\" in component
            or component[-1] in ". "
            or any(ord(ch) < 32 or ch in _WINDOWS_INVALID_CHARS for ch in component)
        ):
            raise OSError
        try:
            if len(component.encode("utf-16-le")) > _MAX_COMPONENT_LEN * 2:
                raise OSError
        except UnicodeError:
            raise OSError from None
        if component.split(".", 1)[0].rstrip(" ").upper() in _WINDOWS_DEVICES:
            raise OSError
    else:
        try:
            if len(os.fsencode(component)) > _MAX_COMPONENT_LEN:
                raise OSError
        except UnicodeError:
            raise OSError from None


def _parse_unc_root(raw: str) -> tuple[str, str]:
    if len(raw) < 2 or raw[1] not in "/\\" or (len(raw) > 2 and raw[2] in "/\\"):
        raise OSError
    tail = raw[2:]
    slash = min((i for i in (tail.find("\\"), tail.find("/")) if i >= 0), default=-1)
    if slash <= 0:
        raise OSError
    server, after_server = tail[:slash], tail[slash + 1 :]
    if not after_server or after_server[0] in "/\\" or server in (".", "..", "?"):
        raise OSError
    next_slash = min((i for i in (after_server.find("\\"), after_server.find("/")) if i >= 0), default=-1)
    share = after_server if next_slash < 0 else after_server[:next_slash]
    rest = "" if next_slash < 0 else after_server[next_slash + 1 :]
    if share in ("", ".", ".."):
        raise OSError
    _validate_component(server, True)
    _validate_component(share, True)
    return f"\\\\{server}\\{share}\\", rest


def _parse_target(raw: str, *, require_absolute: bool = False) -> tuple[str | None, list[str]]:
    windows = os.name == "nt"
    if not isinstance(raw, str) or not raw or len(raw) > _MAX_PATH_CHARS or "\x00" in raw:
        raise OSError
    if raw.count("/") + (raw.count("\\") if windows else 0) > _MAX_DIRECTORY_COMPONENTS:
        raise OSError
    root: str | None = None
    rest = raw
    if windows:
        if raw[:4].replace("/", "\\") in ("\\\\?\\", "\\\\.\\"):
            raise OSError
        if raw[0] in "/\\":
            root, rest = _parse_unc_root(raw)
        elif len(raw) >= 3 and raw[0].isascii() and raw[0].isalpha() and raw[1] == ":" and raw[2] in "/\\":
            root, rest = raw[:2] + "\\", raw[3:]
        elif ":" in raw:
            raise OSError
    elif raw.startswith("/"):
        if raw.startswith("//") and not raw.startswith("///"):
            raise OSError
        root, rest = "/", raw.lstrip("/")

    if require_absolute and root is None:
        raise OSError

    raw_parts = rest.replace("/", "\\").split("\\") if windows and rest else (rest.split("/") if rest else [])
    components: list[str] = []
    for part in raw_parts:
        if part in ("", "."):
            continue
        if part != "..":
            _validate_component(part, windows)
        components.append(part)
        if len(components) > _MAX_DIRECTORY_COMPONENTS:
            raise OSError
    return root, components


def _observe_portable_dir(path_str: str):
    entry = os.lstat(path_str)
    if _is_plain_directory(entry):
        return entry, entry
    if not _is_windows_junction(entry) or not _valid_identity(entry):
        raise OSError
    try:
        target = os.stat(path_str)
    except FileNotFoundError:
        raise OSError from None
    if not _is_plain_directory(target):
        raise OSError
    after = os.lstat(path_str)
    if not _is_windows_junction(after) or not _same_identity(entry, after):
        raise OSError
    return entry, target


def _same_obs(expected, current) -> bool:
    exp_entry, exp_target = expected
    cur_entry, cur_target = current
    return (
        _is_reparse_point(exp_entry) == _is_reparse_point(cur_entry)
        and _same_identity(exp_entry, cur_entry)
        and _same_identity(exp_target, cur_target)
    )


def _observe_descriptor_root(root_str: str, fd: int, seen=None):
    opened = os.fstat(fd)
    after = os.stat(root_str, follow_symlinks=False)
    if (
        not _is_plain_directory(opened) or not _is_plain_directory(after)
        or not _same_identity(opened, after) or (seen is not None and not _same_identity(seen, opened))
    ):
        raise OSError
    return after, opened


def _observe_descriptor_child(parent_fd: int, name: str, child_fd: int, seen):
    opened = os.fstat(child_fd)
    after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        not _is_plain_directory(opened) or not _is_plain_directory(after)
        or not _same_identity(seen, opened) or not _same_identity(opened, after)
    ):
        raise OSError
    return after, opened


def _verify_descriptor_edge(parent_fd: int, name: str, child_fd: int, expected_obs) -> None:
    visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    opened = os.fstat(child_fd)
    if (
        not _is_plain_directory(visible) or not _is_plain_directory(opened)
        or not _same_identity(visible, expected_obs[0]) or not _same_identity(opened, expected_obs[1])
    ):
        raise OSError


def _track_fd(fd: int, stack: ExitStack) -> int:
    try:
        stack.callback(os.close, fd)
    except BaseException:
        os.close(fd)
        raise
    return fd


class _Witness:
    def __init__(self, root_str: str | None, root_obs, steps: list, nodes: list) -> None:
        self.root_str = root_str
        self.root_obs = root_obs
        self.steps = steps
        self.nodes = nodes


def _same_witness(first: _Witness, second: _Witness) -> bool:
    if first.root_str != second.root_str or len(first.steps) != len(second.steps):
        return False
    if first.root_str is not None and not _same_obs(first.root_obs, second.root_obs):
        return False
    for (k1, l1, o1, s1), (k2, l2, o2, s2) in zip(first.steps, second.steps):
        if k1 != k2 or l1 != l2 or not _same_obs(o1, o2):
            return False
        if (s1 is None) != (s2 is None) or (s1 is not None and not _same_witness(s1, s2)):
            return False
    return True


class _Chain:
    def __init__(self, descriptor: bool, nodes: list, edges: list) -> None:
        self.descriptor = descriptor
        self.nodes = nodes
        self.edges = edges

    @property
    def path_str(self) -> str:
        return self.nodes[-1][0]

    @property
    def parent_name(self) -> str:
        return self.nodes[-2][1] if len(self.nodes) >= 2 else ""

    @property
    def fd(self) -> int | None:
        return self.nodes[-1][2]


class _Session:
    def __init__(self, descriptor: bool, stack: ExitStack) -> None:
        self.descriptor = descriptor
        self.stack = stack
        self.roots: dict[str, tuple] = {}
        self.children: dict[tuple[int, str], tuple] = {}
        self.chains: list[_Chain] = []
        self.entries: list[tuple[str, object]] = []
        self.absent: list[tuple[str, str]] = []
        self.generations: list[tuple[_Chain, tuple]] = []
        self._gen_keys: set[str] = set()
        self.records: list[tuple[_Chain, str, object]] = []
        self._rec_keys: set[tuple[str, str]] = set()

    def watch_entry(self, raw: str, expected_leaf) -> None:
        self.entries.append((raw, expected_leaf))

    def watch_absent(self, raw: str, expected_resolved: str) -> None:
        self.absent.append((raw, expected_resolved))

    def watch_generation(self, chain: _Chain) -> None:
        if chain.path_str not in self._gen_keys:
            self._gen_keys.add(chain.path_str)
            self.generations.append((chain, _directory_generation(chain)))

    def watch_record(self, chain: _Chain, name: str, entry) -> None:
        key = (chain.path_str, name)
        if key not in self._rec_keys:
            self._rec_keys.add(key)
            self.records.append((chain, name, entry))

    def verify(self) -> None:
        for raw, expected_resolved in self.absent:
            if os.path.lexists(raw) or _resolve_path_text(raw) != expected_resolved:
                raise OSError
        for raw, expected_leaf in self.entries:
            current = os.stat(raw)
            if not _is_plain_directory(current) or not _same_identity(expected_leaf, current):
                raise OSError
        seen_roots: set[str] = set()
        seen_edges: set[tuple] = set()
        for chain in self.chains:
            root_str, _r_name, root_fd, root_obs = chain.nodes[0]
            if root_str not in seen_roots:
                seen_roots.add(root_str)
                if self.descriptor:
                    if not _same_obs(root_obs, _observe_descriptor_root(root_str, root_fd, root_obs[1])):
                        raise OSError
                elif not _same_obs(root_obs, _observe_portable_dir(root_str)):
                    raise OSError
            if self.descriptor:
                for (_p_s, _p_n, p_fd, _p_o), (_c_s, c_name, c_fd, c_obs) in zip(chain.nodes, chain.nodes[1:]):
                    ekey = (p_fd, c_name, c_fd)
                    if ekey not in seen_edges:
                        seen_edges.add(ekey)
                        _verify_descriptor_edge(p_fd, c_name, c_fd, c_obs)
                for p_fd, _p_str, name, c_fd, exp_obs in chain.edges:
                    ekey = (p_fd, name, c_fd)
                    if ekey not in seen_edges:
                        seen_edges.add(ekey)
                        _verify_descriptor_edge(p_fd, name, c_fd, exp_obs)
            else:
                for n_str, _name, _fd, n_obs in chain.nodes[1:]:
                    if n_str not in seen_roots:
                        seen_roots.add(n_str)
                        if not _same_obs(n_obs, _observe_portable_dir(n_str)):
                            raise OSError
                for _p_fd, p_str, _name, _c_fd, exp_obs in chain.edges:
                    if p_str not in seen_roots:
                        seen_roots.add(p_str)
                        if not _same_obs(exp_obs, _observe_portable_dir(p_str)):
                            raise OSError
        for chain, expected_gen in self.generations:
            if _directory_generation(chain) != expected_gen:
                raise OSError
        for chain, name, expected_entry in self.records:
            _check_record(expected_entry, _record_entry(chain, name))


def _witness_root(session: _Session, root_str: str):
    if session.descriptor:
        if root_str in session.roots:
            _, _, r_fd, r_obs = session.roots[root_str]
            return r_fd, _observe_descriptor_root(root_str, r_fd, r_obs[1])
        seen = os.stat(root_str, follow_symlinks=False)
        if not _is_plain_directory(seen):
            raise OSError
        return None, (seen, seen)
    return None, _observe_portable_dir(root_str)


def _witness_step_descriptor(session: _Session, curr_str: str, curr_fd: int | None, comp: str):
    if curr_fd is not None and (curr_fd, comp) in session.children:
        _, _, c_fd, c_obs = session.children[(curr_fd, comp)]
        _verify_descriptor_edge(curr_fd, comp, c_fd, c_obs)
        return c_fd, c_obs
    child_str = _join_child(curr_str, comp)
    seen = (
        os.stat(comp, dir_fd=curr_fd, follow_symlinks=False)
        if curr_fd is not None
        else os.stat(child_str, follow_symlinks=False)
    )
    if not _is_plain_directory(seen):
        raise OSError
    return None, (seen, seen)


def _witness_target(
    session: _Session,
    raw: str,
    *,
    base: _Chain | None = None,
    resolve_junctions: bool = True,
    expected_entry=None,
    expected_leaf=None,
    depth: int = 0,
) -> _Witness:
    if depth > _MAX_JUNCTION_DEPTH:
        raise OSError
    root_str, components = _parse_target(raw, require_absolute=base is None)
    if root_str is not None:
        r_fd, root_obs = _witness_root(session, root_str)
        w_nodes = [(root_str, "", r_fd, root_obs)]
    else:
        root_obs = None
        w_nodes = list(base.nodes)

    steps: list[tuple] = []
    for comp in components:
        curr_str, _curr_name, curr_fd, _curr_obs = w_nodes[-1]
        if comp == "..":
            expected = w_nodes[-2] if len(w_nodes) > 1 else w_nodes[0]
            dotdot = _dotdot_spelling(curr_str)
            if session.descriptor:
                if curr_fd is not None and expected[2] is not None:
                    _verify_descriptor_edge(curr_fd, "..", expected[2], expected[3])
                else:
                    dd = (
                        os.stat("..", dir_fd=curr_fd, follow_symlinks=False)
                        if curr_fd is not None
                        else os.stat(dotdot, follow_symlinks=False)
                    )
                    if not _is_plain_directory(dd) or not _same_identity(dd, expected[3][1]):
                        raise OSError
            elif not _same_obs(expected[3], _observe_portable_dir(dotdot)):
                raise OSError
            steps.append(("up", dotdot, expected[3], None))
            if len(w_nodes) > 1:
                w_nodes.pop()
            continue

        if len(w_nodes) >= _MAX_DIRECTORY_COMPONENTS:
            raise OSError
        child_str = _join_child(curr_str, comp)
        if session.descriptor:
            next_fd, obs = _witness_step_descriptor(session, curr_str, curr_fd, comp)
            steps.append(("child", comp, obs, None))
            w_nodes.append((child_str, comp, next_fd, obs))
        else:
            obs = _observe_portable_dir(child_str)
            if resolve_junctions and _is_reparse_point(obs[0]):
                sub = _witness_target(
                    session, _real_windows_path(child_str), resolve_junctions=True,
                    expected_leaf=obs[1], depth=depth + 1,
                )
                if not _same_obs(obs, _observe_portable_dir(child_str)):
                    raise OSError
                steps.append(("junc", child_str, obs, sub))
                w_nodes = list(sub.nodes)
            else:
                steps.append(("child", comp, obs, None))
                w_nodes.append((child_str, comp, None, obs))

    leaf_entry, leaf_target = w_nodes[-1][3]
    if expected_entry is not None and not _same_identity(expected_entry, leaf_entry):
        raise OSError
    if expected_leaf is not None and not _same_identity(expected_leaf, leaf_target):
        raise OSError
    return _Witness(root_str, root_obs, steps, w_nodes)


def _bind_portable_subwitness(witness: _Witness, edges: list) -> list:
    root_obs = _observe_portable_dir(witness.root_str)
    if not _same_obs(witness.root_obs, root_obs):
        raise OSError
    nodes = [(witness.root_str, "", None, root_obs)]
    for kind, label, exp_obs, sub in witness.steps:
        curr_str = nodes[-1][0]
        if kind == "up":
            if not _same_obs(exp_obs, _observe_portable_dir(label)):
                raise OSError
            if len(nodes) > 1:
                c_str, c_name, _, c_obs = nodes.pop()
                edges.append((None, c_str, c_name, None, c_obs))
            edges.append((None, label, "..", None, exp_obs))
        elif kind == "junc":
            cur_junc = _observe_portable_dir(label)
            if not _same_obs(exp_obs, cur_junc):
                raise OSError
            for n_str, n_name, _n_fd, n_obs in nodes:
                edges.append((None, n_str, n_name, None, n_obs))
            edges.append((None, label, "", None, cur_junc))
            nodes = _bind_portable_subwitness(sub, edges)
        else:
            child_str = _join_child(curr_str, label)
            child_obs = _observe_portable_dir(child_str)
            if not _same_obs(exp_obs, child_obs):
                raise OSError
            nodes.append((child_str, label, None, child_obs))
    return nodes


def _watch_directory(session: _Session, witness: _Witness, base: _Chain | None = None) -> _Chain:
    """Bind a witnessed target namespace, reusing live session descriptors without duplicate opens."""
    edges: list[tuple] = []
    if witness.root_str is not None:
        if session.descriptor:
            if witness.root_str in session.roots:
                _, _, root_fd, cached_root = session.roots[witness.root_str]
                if not _same_obs(cached_root, witness.root_obs):
                    raise OSError
                root_obs = _observe_descriptor_root(witness.root_str, root_fd, witness.root_obs[1])
            else:
                root_fd = _track_fd(
                    os.open(witness.root_str, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)),
                    session.stack,
                )
                root_obs = _observe_descriptor_root(witness.root_str, root_fd, witness.root_obs[1])
                session.roots[witness.root_str] = (witness.root_str, "", root_fd, root_obs)
        else:
            root_fd, root_obs = None, _observe_portable_dir(witness.root_str)
            if not _same_obs(witness.root_obs, root_obs):
                raise OSError
        nodes = [(witness.root_str, "", root_fd, root_obs)]
    else:
        nodes = list(base.nodes)

    for kind, label, exp_obs, sub in witness.steps:
        curr_str, _curr_name, curr_fd, _curr_obs = nodes[-1]
        if kind == "up":
            expected = nodes[-2] if len(nodes) > 1 else nodes[0]
            if session.descriptor:
                _verify_descriptor_edge(curr_fd, "..", expected[2], exp_obs)
                if len(nodes) > 1:
                    c_str, c_name, c_fd, c_obs = nodes.pop()
                    edges.append((expected[2], c_str, c_name, c_fd, c_obs))
                edges.append((curr_fd, "", "..", expected[2], exp_obs))
            else:
                if not _same_obs(exp_obs, _observe_portable_dir(label)):
                    raise OSError
                if len(nodes) > 1:
                    c_str, c_name, _, c_obs = nodes.pop()
                    edges.append((None, c_str, c_name, None, c_obs))
                edges.append((None, label, "..", None, exp_obs))
        elif kind == "junc":
            cur_junc = _observe_portable_dir(label)
            if not _same_obs(exp_obs, cur_junc):
                raise OSError
            for n_str, n_name, _n_fd, n_obs in nodes:
                edges.append((None, n_str, n_name, None, n_obs))
            edges.append((None, label, "", None, cur_junc))
            nodes = _bind_portable_subwitness(sub, edges)
        else:
            child_str = _join_child(curr_str, label)
            if session.descriptor:
                if (curr_fd, label) in session.children:
                    _, _, child_fd, cached_obs = session.children[(curr_fd, label)]
                    if not _same_obs(cached_obs, exp_obs):
                        raise OSError
                    _verify_descriptor_edge(curr_fd, label, child_fd, exp_obs)
                    child_obs = cached_obs
                else:
                    child_fd = _track_fd(
                        os.open(label, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=curr_fd),
                        session.stack,
                    )
                    child_obs = _observe_descriptor_child(curr_fd, label, child_fd, exp_obs[1])
                    session.children[(curr_fd, label)] = (child_str, label, child_fd, child_obs)
            else:
                child_fd, child_obs = None, _observe_portable_dir(child_str)
                if not _same_obs(exp_obs, child_obs):
                    raise OSError
            nodes.append((child_str, label, child_fd, child_obs))

    chain = _Chain(session.descriptor, nodes, edges)
    session.chains.append(chain)
    return chain


def _select_target(session: _Session, *, discover, confirm=None, base: _Chain | None = None) -> _Chain:
    witness = discover()
    if confirm is not None:
        confirm()
    return _watch_directory(session, witness, base=base)


def descriptor_supported() -> bool:
    return (
        os.name == "posix"
        and bool(getattr(os, "O_NOFOLLOW", 0))
        and bool(getattr(os, "O_DIRECTORY", 0))
        and {"open", "stat"} <= {fn.__name__ for fn in getattr(os, "supports_dir_fd", ())}
        and "stat" in {fn.__name__ for fn in getattr(os, "supports_follow_symlinks", ())}
    )


def _record_entry(chain: _Chain, name: str):
    try:
        if chain.fd is None:
            return os.lstat(_join_child(chain.path_str, name))
        return os.stat(name, dir_fd=chain.fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _file_generation(info):
    # On Windows path lstat() reports NTFS creation time in st_ctime_ns while
    # os.fstat(fd) reports last-change time (see aegis_core.storage.file_generation).
    return (info.st_size, info.st_mtime_ns, 0 if os.name == "nt" else info.st_ctime_ns)


def _directory_generation(chain: _Chain):
    info = os.fstat(chain.fd) if chain.fd is not None else os.stat(chain.path_str)
    if not _is_plain_directory(info):
        raise OSError
    return (info.st_dev, info.st_ino, info.st_mtime_ns, 0 if os.name == "nt" else info.st_ctime_ns)


def _check_record(seen, current) -> None:
    if seen is None and current is None:
        return
    if (
        seen is None or current is None
        or not stat.S_ISREG(seen.st_mode) or not stat.S_ISREG(current.st_mode)
        or stat.S_ISLNK(seen.st_mode) or stat.S_ISLNK(current.st_mode)
        or _is_reparse_point(seen) or _is_reparse_point(current)
        or not _same_identity(seen, current) or _file_generation(seen) != _file_generation(current)
    ):
        raise OSError


def _path_limit():
    raise GitError("Git path output exceeds its byte limit.", code="git_path_limit")


@contextmanager
def _read_git_record(chain: _Chain, name: str, seen, check_state, *, expected_prefix: bytes = b""):
    """Read one bounded Git metadata record, verifying prefix and exact opened size."""
    if not stat.S_ISREG(seen.st_mode) or stat.S_ISLNK(seen.st_mode) or _is_reparse_point(seen) or not _valid_identity(seen):
        raise OSError
    if chain.fd is None:
        fd = os.open(
            _join_child(chain.path_str, name),
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    else:
        fd = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=chain.fd,
        )
    try:
        opened = os.fstat(fd)
        if opened.st_size < 0:
            raise OSError
        _check_record(seen, opened)
        check_state()
        prefix = bytearray()
        if expected_prefix:
            target_prefix = min(opened.st_size, len(expected_prefix))
            read_goal = len(expected_prefix) if opened.st_size >= len(expected_prefix) else opened.st_size + 1
            while len(prefix) < read_goal:
                chunk = os.read(fd, read_goal - len(prefix))
                if not chunk:
                    break
                prefix.extend(chunk)
            if len(prefix) != target_prefix:
                raise OSError
        raw = None
        if bytes(prefix) == expected_prefix:
            from aegis_core.git_path_codec import MAX_PATH_BYTES

            if opened.st_size > MAX_PATH_BYTES:
                _path_limit()
            data = bytearray(prefix)
            while len(data) <= MAX_PATH_BYTES:
                chunk = os.read(fd, min(8192, MAX_PATH_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > MAX_PATH_BYTES:
                _path_limit()
            if len(data) != opened.st_size:
                raise OSError
            raw = bytes(data)
        _check_record(seen, os.fstat(fd))
        _check_record(seen, _record_entry(chain, name))
        check_state()
        yield raw
    finally:
        os.close(fd)
    _check_record(seen, _record_entry(chain, name))
    check_state()


def _raw_path_text(project_root) -> str:
    raw = os.getcwd() if project_root is None else os.fspath(project_root)
    if isinstance(raw, bytes):
        raw = os.fsdecode(raw)
    if not isinstance(raw, str) or not raw or len(raw) > _MAX_PATH_CHARS or "\x00" in raw:
        raise OSError
    if os.name == "nt" and raw[:4].replace("/", "\\") in ("\\\\?\\", "\\\\.\\"):
        raise OSError
    return raw


def _resolve_path_text(raw: str) -> str:
    if os.name == "nt":
        return _real_windows_path(raw)
    real = os.path.realpath(raw)
    if os.path.islink(real):
        raise OSError
    return real


def _open_checkout(session: _Session, project_root) -> _Chain | None:
    raw = _raw_path_text(project_root)
    try:
        leaf_stat = os.stat(raw)
    except FileNotFoundError:
        if os.path.lexists(raw):
            raise OSError from None
        _resolve_path_text(raw)
        return None
    if not _is_plain_directory(leaf_stat):
        raise OSError
    session.watch_entry(raw, leaf_stat)
    return _select_target(
        session,
        discover=lambda: _witness_target(session, _resolve_path_text(raw), expected_leaf=leaf_stat),
        confirm=session.verify,
    )


def _select_record_target(
    session: _Session, base_chain: _Chain, record_name: str, entry, *, is_gitfile: bool,
) -> _Chain | None:
    expected_prefix = _GITFILE_PREFIX if is_gitfile else b""
    holder: dict[str, object] = {}
    with _read_git_record(
        base_chain, record_name, entry, session.verify, expected_prefix=expected_prefix
    ) as discovery:
        holder["raw"] = discovery
        if discovery is not None:
            from aegis_core.git_path_codec import path_text

            candidate = path_text(discovery, gitfile=is_gitfile, record=True)
            holder["candidate"] = candidate
            holder["witness"] = _witness_target(session, candidate, base=base_chain)
    if "witness" in holder and not _same_witness(
        holder["witness"], _witness_target(session, holder["candidate"], base=base_chain)
    ):
        raise OSError
    if holder["raw"] is None:
        with _read_git_record(
            base_chain, record_name, entry, session.verify, expected_prefix=expected_prefix
        ) as confirmed:
            if confirmed is not None:
                raise OSError
        return None

    def confirm_record() -> None:
        with _read_git_record(
            base_chain, record_name, entry, session.verify, expected_prefix=expected_prefix
        ) as confirmed:
            if confirmed != holder["raw"]:
                raise OSError

    return _select_target(
        session, base=base_chain, discover=lambda: holder["witness"], confirm=confirm_record
    )


def _inspect_git_at(session: _Session, checkout: _Chain, *, pre_seen=None) -> tuple[_Chain, _Chain] | None:
    seen = _record_entry(checkout, ".git") if pre_seen is None else pre_seen
    if seen is None:
        session.watch_record(checkout, ".git", None)
        session.verify()
        return None

    session.watch_generation(checkout)
    if stat.S_ISDIR(seen.st_mode) and not stat.S_ISLNK(seen.st_mode):
        dot_git_chain = _select_target(
            session,
            base=checkout,
            discover=lambda: _witness_target(
                session, ".git", base=checkout, resolve_junctions=False, expected_entry=seen
            ),
            confirm=session.verify,
        )
        session.verify()
        return dot_git_chain, dot_git_chain

    session.watch_record(checkout, ".git", seen)
    admin_chain = _select_record_target(session, checkout, ".git", seen, is_gitfile=True)
    if admin_chain is None:
        session.verify()
        return None

    session.watch_generation(admin_chain)
    common_entry = _record_entry(admin_chain, "commondir")
    session.watch_record(admin_chain, "commondir", common_entry)
    if common_entry is None:
        if admin_chain.parent_name != "worktrees":
            session.verify()
            return admin_chain, admin_chain
        common_chain = _select_target(
            session,
            base=admin_chain,
            discover=lambda: _witness_target(session, "../..", base=admin_chain),
            confirm=session.verify,
        )
    else:
        common_chain = _select_record_target(session, admin_chain, "commondir", common_entry, is_gitfile=False)
    session.verify()
    return admin_chain, common_chain


def _uses_linux_metadata() -> bool:
    return sys.platform == "linux" and os.name == "posix"


def _uses_pathname_metadata() -> bool:
    return (os.name == "nt" and sys.platform == "win32") or (os.name == "posix" and sys.platform != "linux")


def _platform_git_paths(project_root, query, *, search):
    from aegis_core import gitsafe, gitsafe_bound

    if _uses_pathname_metadata():
        return gitsafe_bound.discover_pathname(project_root, query, gitsafe.git_path, git_discovery_paths, search=search)
    return gitsafe_bound.discover_linux(
        _raw_path_text("." if project_root is None else project_root),
        query, gitsafe.bound_git_metadata, git_discovery_paths,
        search=search, descriptors=descriptor_supported(),
    )


def _git_dirs_at(curr: Path) -> tuple[Path, Path] | None:
    """Read the local Git marker, refusing unsafe or changed metadata with GitError."""
    try:
        if _uses_linux_metadata() or _uses_pathname_metadata():
            return _platform_git_paths(curr, "dirs", search=False)
        with ExitStack() as stack:
            session = _Session(descriptor_supported(), stack)
            checkout = _open_checkout(session, curr)
            if checkout is None:
                return None
            found = _inspect_git_at(session, checkout)
            if found is None:
                return None
            return _native_path(found[0].path_str), _native_path(found[1].path_str)
    except GitError:
        raise
    except (OSError, ValueError, RuntimeError):
        raise GitError("Git metadata path is unavailable.", code="git_path_unavailable") from None


def _has_git_layout(git_chain: _Chain, common_chain: _Chain) -> bool:
    """Git's own acceptance test (setup.c is_git_directory): HEAD in the gitdir,
    objects/ and refs/ in the common dir."""
    if git_chain.fd is not None and common_chain.fd is not None:
        try:
            head_st = os.stat("HEAD", dir_fd=git_chain.fd)
            obj_st = os.stat("objects", dir_fd=common_chain.fd)
            ref_st = os.stat("refs", dir_fd=common_chain.fd)
        except OSError:
            return False
        return stat.S_ISREG(head_st.st_mode) and stat.S_ISDIR(obj_st.st_mode) and stat.S_ISDIR(ref_st.st_mode)
    return (
        os.path.isfile(_join_child(git_chain.path_str, "HEAD"))
        and os.path.isdir(_join_child(common_chain.path_str, "objects"))
        and os.path.isdir(_join_child(common_chain.path_str, "refs"))
    )


def _discovery_steps(start_str: str, nodes_len: int) -> int:
    if os.path.realpath is _NATIVE_REALPATH and str(Path("a") / "b") == f"a{_sep()}b":
        paths = tuple(git_discovery_paths(Path(start_str)))
        if not paths or os.path.normcase(str(paths[0])) != os.path.normcase(start_str):
            raise OSError
        return len(paths) - 1
    return nodes_len - 1


def _ancestor_candidates(resolved: str):
    if os.path.realpath is _NATIVE_REALPATH and str(Path("a") / "b") == f"a{_sep()}b":
        return tuple(git_discovery_paths(Path(resolved)))[1:]
    r_root, r_comps = _parse_target(resolved, require_absolute=True)
    return tuple(r_root + _sep().join(r_comps[:idx]) for idx in range(len(r_comps) - 1, -1, -1))


def _discover_from_chain(
    session: _Session, start_chain: _Chain, *, is_start: bool = True, pre_seen=None,
) -> tuple[_Chain, _Chain] | None:
    steps = _discovery_steps(start_chain.path_str, len(start_chain.nodes))
    curr = start_chain
    for idx in range(steps + 1):
        at_start = is_start and idx == 0
        found = _inspect_git_at(session, curr, pre_seen=pre_seen if idx == 0 else None)
        if found is not None:
            ok = at_start or _has_git_layout(found[0], found[1])
            session.verify()
            if ok:
                return found
        if idx < steps:
            curr = _select_target(
                session, base=curr,
                discover=lambda c=curr: _witness_target(session, "..", base=c),
                confirm=session.verify,
            )
    return None


def _find_git_dirs(root: Path) -> tuple[Path | None, Path | None]:
    """Find (git_dir, git_common_dir) for a workspace root, walking up if necessary."""
    try:
        if _uses_linux_metadata() or _uses_pathname_metadata():
            return _platform_git_paths(root, "dirs", search=True) or (None, None)
        with ExitStack() as stack:
            session = _Session(descriptor_supported(), stack)
            checkout = _open_checkout(session, root)
            is_start = True
            if checkout is None:
                is_start = False
                raw_root = _raw_path_text(root)
                resolved = _resolve_path_text(raw_root)
                session.watch_absent(raw_root, resolved)
                for candidate in _ancestor_candidates(resolved):
                    checkout = _open_checkout(session, candidate)
                    if checkout is not None:
                        break
            if checkout is None:
                return None, None
            found = _discover_from_chain(session, checkout, is_start=is_start)
            if found is None:
                return None, None
            return _native_path(found[0].path_str), _native_path(found[1].path_str)
    except GitError:
        raise
    except (OSError, ValueError, RuntimeError):
        raise GitError("Git metadata path is unavailable.", code="git_path_unavailable") from None


def resolve_git_hooks_dir(project_root: str | Path | os.PathLike[str] | None = None) -> Path | None:
    """Resolve the git hooks directory for a project root or worktree."""
    try:
        if _uses_linux_metadata() or _uses_pathname_metadata():
            return _platform_git_paths(project_root, "hooks", search=True)
        with ExitStack() as stack:
            session = _Session(descriptor_supported(), stack)
            checkout = _open_checkout(session, project_root)
            if checkout is None:
                return None
            seen_marker = _record_entry(checkout, ".git")
            if seen_marker is None:
                session.watch_record(checkout, ".git", None)
                session.verify()
                return None

            session.watch_generation(checkout)
            marker_chain: _Chain | None = None
            if stat.S_ISDIR(seen_marker.st_mode) and not stat.S_ISLNK(seen_marker.st_mode):
                marker_chain = _select_target(
                    session,
                    base=checkout,
                    discover=lambda: _witness_target(
                        session, ".git", base=checkout, resolve_junctions=False, expected_entry=seen_marker
                    ),
                    confirm=session.verify,
                )
            elif (
                not stat.S_ISREG(seen_marker.st_mode)
                or stat.S_ISLNK(seen_marker.st_mode)
                or _is_reparse_point(seen_marker)
                or not _valid_identity(seen_marker)
            ):
                raise OSError
            else:
                session.watch_record(checkout, ".git", seen_marker)

            from aegis_core import gitsafe

            hooks_path = gitsafe.git_path(_native_path(checkout.path_str), "hooks")
            session.verify()
            if hooks_path is not None:
                return _native_path(hooks_path)
            if marker_chain is not None:
                return _native_path(_join_child(marker_chain.path_str, "hooks"))

            found = _discover_from_chain(session, checkout, is_start=True, pre_seen=seen_marker)
            if found is not None:
                return _native_path(_join_child(found[1].path_str, "hooks"))
            return None
    except GitError:
        raise
    except (OSError, ValueError, RuntimeError):
        raise GitError("Git metadata path is unavailable.", code="git_path_unavailable") from None


__all__ = [
    "_find_git_dirs",
    "descriptor_supported",
    "resolve_git_hooks_dir",
]
