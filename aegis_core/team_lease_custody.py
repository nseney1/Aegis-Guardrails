"""CLI lease observations and writes share repository identity and private scratch.

POSIX holds nofollow directory descriptors through both phases. Windows keeps
the same metadata location and checks its identity before mutation, but pathname
opens retain the platform's authorized rename race residual. This module is lazy:
ordinary team service users and hooks do not enter or import this CLI boundary.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack, redirect_stderr, redirect_stdout
from contextvars import ContextVar
import io
import os
from pathlib import Path
import stat
import sys

from aegis_core import gitsafe, gitsafe_run, storage_confined

__all__ = ["custody", "verify", "next_action", "descriptor_supported", "operation"]

_ACTIVE = ContextVar("aegis_lease_repository", default=None)
_SCRATCH = "aegis-lease-scratch"
_LIMIT = 65536
_OUTPUT_LIMIT = 2 * 1024 * 1024
_SELECTORS = (gitsafe_run.LOCAL_ENV - {"GIT_NO_REPLACE_OBJECTS"}) | {"GIT_NAMESPACE"}


def next_action(reason):
    """Closed recovery text; no repository, environment or exception text escapes."""
    return {"ambient_git_environment": "Unset Git repository selectors, then retry.",
            "lease_branch_missing": "Restore the recorded branch, then retry.",
            "liveness_unknown": "Restore private Git metadata, then retry."}.get(reason, "")


def _refuse(reason="liveness_unknown"):
    raise gitsafe.GitError(reason, code="ambient_git_environment" if reason == "ambient_git_environment"
                          else "git_failed", next_action=next_action(reason)) from None


def _ambient():
    # Check counts and individual bounds before copying. Repository selectors are
    # refused, rather than silently changing which repository the caller selected.
    if len(os.environ) > 512:
        _refuse("ambient_git_environment")
    frozen = {}
    for key, value in os.environ.items():
        if len(key) > 128 or len(value) > 65536:
            _refuse("ambient_git_environment")
        upper = key.upper()
        if upper in _SELECTORS or upper.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
            _refuse("ambient_git_environment")
        if upper.startswith("GIT_") or upper in ("PATH", "HOME", "USERPROFILE", "XDG_CONFIG_HOME"):
            if len(frozen) >= 56:
                _refuse("ambient_git_environment")
            frozen[key] = value
    # A ceiling cannot redirect an explicitly bound repository. Never inherit it.
    frozen.update(GIT_NAMESPACE="", GIT_CEILING_DIRECTORIES="")
    return frozen


def _absolute(root):
    if not isinstance(root, (str, Path)):
        _refuse()
    raw = os.fspath(root)
    if (not isinstance(raw, str) or not 0 < len(raw) <= 16384 or any(c in raw for c in "\0\r\n")
            or len(Path(raw).parts) > 128 or ".." in Path(raw).parts):
        _refuse()
    result = os.path.abspath(raw)
    if len(result) > 16384:
        _refuse()
    return result


def _fd_prefix():
    return "/proc/{}/fd".format(os.getpid())


def descriptor_supported():
    """Git must address held parent fds; child-only /dev/fd cannot carry them."""
    return storage_confined.descriptor_supported() and os.path.isdir("/proc/self/fd")


def _identity(info):
    return info.st_dev, info.st_ino


def _owned_directory(info, *, private=False, owner=True):
    if (not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
        _refuse()
    if owner and hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        _refuse()
    if os.name == "posix" and private and stat.S_IMODE(info.st_mode) != 0o700:
        _refuse()


@contextmanager
def _directory(path):
    # Same-package borrowing, also used by team_gitops: storage owns the parent
    # descriptor, walks every ancestor without links, and closes on every exit.
    with storage_confined.confined_file(path, (".git",)) as handle:
        yield handle._parent


def _child(directory, name, stack):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
    stack.callback(os.close, fd)
    return fd


def _descriptor_record(directory, name, limit):
    try:
        return storage_confined.ConfinedFile(directory, name).read_bytes(limit)
    except storage_confined.ConfinedFileError as exc:
        if exc.reason == "missing":
            raise FileNotFoundError() from None
        _refuse()


def _discover(root, cwd, environment):
    # No stdin means bounded discovery never opens scratch. Before the common
    # directory is known, use the volume anchor rather than a checkout path.
    with gitsafe.custody(scratch=Path(root).anchor, env=environment,
                         stdout_limit=_LIMIT, stderr_limit=_LIMIT):
        result = gitsafe.run(["rev-parse", "--absolute-git-dir", "--git-common-dir",
                              "--is-bare-repository", "--show-toplevel"], cwd, stdin=None)
    data = result.stdout
    if len(data) > _LIMIT or not data.endswith(b"\n"):
        _refuse()
    fields = [field.removesuffix(b"\r") for field in data[:-1].split(b"\n")]
    # Git emits the first three answers before --show-toplevel refuses a bare
    # repository or a cwd inside Git metadata. Neither needs a worktree binding.
    if ((result.returncode == 0 and len(fields) != 4)
            or (result.returncode != 0 and (result.returncode != 128 or len(fields) != 3))):
        _refuse()
    if fields[2] not in (b"true", b"false"):
        _refuse()
    git = _discovery_path(fields[0], root)
    common = _discovery_path(fields[1], root, relative=True)
    tree = _discovery_path(fields[3], root) if len(fields) == 4 else None
    return (git, common), tree


def _descriptor_workspace(root, workspace_fd, stack):
    current = stack.enter_context(_directory(root))
    identity = _identity(os.fstat(workspace_fd))
    if _identity(os.fstat(current)) != identity:
        _refuse()
    return identity


def _descriptor_facts(directories, tree, stack):
    git, common = directories
    git_fd = stack.enter_context(_directory(git))
    common_fd = stack.enter_context(_directory(common))
    root_fd = stack.enter_context(_directory(tree)) if tree is not None else None
    if not _descriptor_record(git_fd, "HEAD", 4096):
        _refuse()
    _owned_directory(os.fstat(common_fd))
    for name in ("objects", "refs"):
        _child(common_fd, name, stack)
    return {"dirs": (git, common), "fds": (git_fd, common_fd, root_fd),
            "identity": tuple(_identity(os.fstat(fd)) if fd is not None else None
                              for fd in (git_fd, common_fd, root_fd))}


def _descriptor_binding(root, stack, environment):
    workspace_fd = stack.enter_context(_directory(root))
    directories, tree = _discover(root, str(Path(_fd_prefix()) / str(workspace_fd)), environment)
    facts = _descriptor_facts(directories, tree, stack)
    git_fd, common_fd, root_fd = facts["fds"]
    workspace_identity = _descriptor_workspace(root, workspace_fd, stack)
    _owned_directory(os.fstat(common_fd))
    try:
        os.mkdir(_SCRATCH, 0o700, dir_fd=common_fd)
    except FileExistsError:
        pass  # Reuse only after opening and validating the actual directory.
    scratch_fd = _child(common_fd, _SCRATCH, stack)
    _owned_directory(os.fstat(scratch_fd), private=True)
    prefix = _fd_prefix()
    paths = [str(Path(prefix) / str(fd)) if fd is not None else None
             for fd in (git_fd, common_fd, root_fd, scratch_fd)]
    environment = dict(GIT_DIR=paths[0], GIT_COMMON_DIR=paths[1])
    if tree is not None:
        environment["GIT_WORK_TREE"] = paths[2]
    return {"root": root, "tree": tree, "workspace_identity": workspace_identity,
            "facts": facts, "scratch": Path(paths[3]), "env": environment}


def _record(path, limit):
    """Bounded Windows pathname read; no fdopen ownership handoff can leak an fd."""
    info = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_size > limit
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
        _refuse()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > limit or _identity(opened) != _identity(info):
            _refuse()
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            _refuse()
        return data
    finally:
        os.close(fd)


def _discovery_path(data, root, *, relative=False):
    if not 0 < len(data) <= 16384 or any(c in data for c in (b"\0", b"\n", b"\r")):
        _refuse()
    value = os.fsdecode(data)
    if not os.path.isabs(value):
        if not relative or len(root) + 1 + len(value) > 16384:
            _refuse()
        value = os.path.join(root, value)
    return _absolute(os.path.normpath(value))


def _pathname_facts(directories, tree):
    git, common = directories
    _owned_directory(os.stat(git, follow_symlinks=False))
    if not _record(os.path.join(git, "HEAD"), 4096):
        _refuse()
    _owned_directory(os.stat(common, follow_symlinks=False))
    if tree is not None:
        _owned_directory(os.stat(tree, follow_symlinks=False), owner=False)
    return {"dirs": (git, common), "identity": tuple(_identity(os.stat(p, follow_symlinks=False))
            if p is not None else None for p in (git, common, tree))}


def _pathname_workspace(root):
    info = os.stat(root, follow_symlinks=False)
    _owned_directory(info)
    return _identity(info)


def _pathname_binding(root, environment):
    workspace_identity = _pathname_workspace(root)
    directories, tree = _discover(root, root, environment)
    facts = _pathname_facts(directories, tree)
    if workspace_identity != _pathname_workspace(root):
        _refuse()
    git, common = facts["dirs"]
    scratch = os.path.join(common, _SCRATCH)
    try:
        os.mkdir(scratch, 0o700)
    except FileExistsError:
        pass
    _owned_directory(os.stat(scratch, follow_symlinks=False), private=True)
    environment = dict(GIT_DIR=git, GIT_COMMON_DIR=common)
    if tree is not None:
        environment["GIT_WORK_TREE"] = tree
    return {"root": root, "tree": tree, "workspace_identity": workspace_identity,
            "facts": facts, "scratch": Path(scratch), "env": environment}


@contextmanager
def _resources():
    try:
        with ExitStack() as stack:
            yield stack
    except (OSError, storage_confined.ConfinedFileError):
        _refuse()


@contextmanager
def custody(root, limit=2 * _LIMIT):
    """Bind once; nested observations only narrow capture limits, never rebind."""
    with _resources() as stack:
        try:
            if type(limit) is not int or not 0 <= limit <= 2 * _LIMIT:
                _refuse()
            root = _absolute(root)
            binding = _ACTIVE.get()
            if binding is None:
                environment = _ambient()
                descriptors = descriptor_supported()
                binding = (_descriptor_binding(root, stack, environment) if descriptors
                           else _pathname_binding(root, environment))
                binding["env"] = {**environment, **binding["env"]}
                binding["descriptors"] = descriptors
                token = _ACTIVE.set(binding)
                stack.callback(_ACTIVE.reset, token)
            elif root != binding["root"]:
                _refuse()
        except gitsafe.GitError as exc:
            _refuse("ambient_git_environment" if exc.code == "ambient_git_environment" else "liveness_unknown")
        except (OSError, ValueError, RuntimeError):
            _refuse()
        try:
            with gitsafe.custody(scratch=binding["scratch"], env=binding["env"],
                                 stdout_limit=limit, stderr_limit=_LIMIT):
                yield
        except OSError:
            _refuse()


def verify(root):
    """Recheck the original namespace immediately before the CLI's mutation."""
    try:
        _ambient()
        binding = _ACTIVE.get()
        if binding is None or _absolute(root) != binding["root"]:
            _refuse()
        if binding["descriptors"]:
            with ExitStack() as stack:
                workspace_fd = stack.enter_context(_directory(binding["root"]))
                facts = _descriptor_facts(binding["facts"]["dirs"], binding["tree"], stack)
                workspace_identity = _identity(os.fstat(workspace_fd))
                identity = facts["identity"]
        else:
            workspace_identity = _pathname_workspace(binding["root"])
            identity = _pathname_facts(binding["facts"]["dirs"], binding["tree"])["identity"]
        if identity != binding["facts"]["identity"] or workspace_identity != binding["workspace_identity"]:
            _refuse()
    except gitsafe.GitError as exc:
        _refuse("ambient_git_environment" if exc.code == "ambient_git_environment" else "liveness_unknown")
    except (OSError, ValueError, RuntimeError):
        _refuse()


class _Output(io.StringIO):
    def write(self, value):
        if len(value) > _OUTPUT_LIMIT - self.tell():
            raise gitsafe.GitError("liveness_unknown", code="git_output_limit")
        return super().write(value)


def operation(root, handler, args, now, *, refused=None, refusal_type=()):
    """Publish one bounded result after descriptor cleanup has succeeded."""
    with _Output() as output, _Output() as errors:
        with redirect_stdout(output), redirect_stderr(errors):
            with custody(root):
                try:
                    result = handler(args, root, now)
                except refusal_type as exc:
                    try:
                        result = refused(args, root, now, exc)
                    except Exception:
                        _refuse()  # Rendering failure still produces one typed refusal.
        sys.stdout.write(output.getvalue())
        sys.stderr.write(errors.getvalue())
        return result
