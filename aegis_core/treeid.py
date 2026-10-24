"""Tree identity, ``tree_algo`` v1 (v4.3 spec §3 T1): the git tree a work tree would commit.

A ``check`` row is bound to a tree, not to a path or a timestamp, so the question "is this the
code that was verified" is answered by a hash. The recipe computes that hash without touching
the repository's index, refs, work tree or object store:

1. The work tree root is the git top level of the workspace; its git directory is resolved from
   ``<root>/.git`` (a directory, or a ``gitdir:`` file of a linked worktree).
2. Every ``GIT_*`` variable is scrubbed from the environment (``rev-parse --local-env-vars``,
   ``GIT_CONFIG_PARAMETERS``/``COUNT``, ``GIT_EXTERNAL_DIFF``, ``GIT_SSH*``, ``GIT_TRACE*``,
   ``GIT_ATTR_SOURCE``, ``GIT_EXEC_PATH`` and the rest), then ``GIT_DIR``/``GIT_WORK_TREE`` are set
   explicitly. ``GIT_CONFIG_GLOBAL``, ``GIT_CONFIG_SYSTEM`` and ``GIT_CONFIG_NOSYSTEM`` stay: they
   name the user's and the system's config files, whose drivers step 5 runs as the user's git does.
3. The real index is copied, mtime preserved, into a private 0700 directory and used as
   ``GIT_INDEX_FILE``, so git's racy-timestamp logic judges the same stat data the real one would.
4. ``ls-files -v`` is audited: an assume-unchanged or skip-worktree entry whose path exists on
   disk lets a file change without git seeing it, so the tree is ``unbindable``.
5. Every filter driver that the config of the work tree or of a checked-out submodule below it
   (16 deep at most) defines outside the user's and the system's config is neutralised on the
   commands that hash content (``filter.<d>.clean=``, ``smudge=``, ``process=``,
   ``required=false``): a clean filter is a program the repository chose. A driver of the user's
   or the system's config (git-lfs, say) runs as in any git command the user types, so the tree is
   the one a commit records; a name the repository also defines is neutralised everywhere, and a
   git without ``config --show-scope`` (before 2.26) neutralises every driver. ``git add`` runs
   ``git status`` in each submodule under that submodule's own config, and the ``-c`` options reach
   it, so its drivers are named there too. A driver ``-c`` cannot name (it splits at the first
   ``=``), a deeper chain or an unreadable config makes the tree ``unbindable``.
6. A private object directory takes the writes, with the real store as its alternate.
7. ``git add -A -- . ':(exclude,glob)**/.aegis/state/**'`` then ``git write-tree``.
8. An empty tree is refused when HEAD is not empty (an unreadable work tree must not look clean).
9. Gitlinks are listed; a submodule whose HEAD or work tree differs from the recorded commit makes
   the result ``partial``: the tree names the pointer, not the submodule's content. The submodule
   is read under the same switches (its own drivers named), with no variable of the work tree's
   environment and with replace refs ignored.

``bind`` keeps the private index for as long as the caller needs it (the snapshot export and the
diff against the base read it); ``tree_of`` is the one-shot form.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple

from aegis_core import gitsafe
from aegis_core.errors import AegisError

__all__ = [
    "TREE_ALGO",
    "BoundTree",
    "TreeBinding",
    "TreeError",
    "bind",
    "named_paths",
    "tree_files",
    "tree_of",
]

TREE_ALGO = "v1"
GIT_TIMEOUT_SECONDS = 300.0
#: How many paths a reason names; the rest are counted.
_NAMED = 5
_EXCLUDE_STATE = ":(exclude,glob)**/.aegis/state/**"
_GITLINK_MODE = "160000"
_SYMLINK_MODE = "120000"
_FILTER_VARS = ("clean", "smudge", "process")
_STABLE_CONFIG = (
    "core.fsmonitor=false", f"core.hooksPath={os.devnull}", "core.splitIndex=false",
    "core.untrackedCache=false", "gc.auto=0", "maintenance.auto=false",
    "core.trustctime=true", "core.checkStat=default", "protocol.allow=never", "credential.helper=",
    "core.sshCommand=false",
)
#: Checked-out submodules below the work tree whose drivers are named; a deeper chain is unbindable.
_MAX_SUBMODULE_DEPTH = 16


class TreeError(AegisError):
    """The tree cannot be computed at all (no git, not a work tree, git failed unexpectedly)."""


@dataclass(frozen=True)
class TreeBinding:
    """The outcome of the recipe: ``ok``, ``partial`` (a dirty submodule) or ``unbindable``."""

    status: str
    tree: Optional[str]
    reason: str = ""
    gitlinks: Tuple[str, ...] = ()
    algo: str = TREE_ALGO

    @property
    def bound(self) -> bool:
        return self.status in ("ok", "partial") and bool(self.tree)

    def as_dict(self) -> Dict[str, object]:
        return {"tree_algo": self.algo, "status": self.status, "tree": self.tree, "reason": self.reason,
                "gitlinks": list(self.gitlinks)}


def named_paths(paths: Sequence[str]) -> str:
    """The first five of ``paths``, then how many more."""
    shown = ", ".join(paths[:_NAMED])
    return shown + (f" and {len(paths) - _NAMED} more" if len(paths) > _NAMED else "")


def _locate(root: Path) -> Tuple[Path, Path, Path]:
    """(work tree top, git directory, real object directory) of the work tree holding ``root``."""
    with gitsafe.scrubbed():  # the one git call here that runs outside BoundTree.env
        top = gitsafe.toplevel(root)
    if top is None:
        raise TreeError(f"{root} is not inside a git work tree")
    dotgit = top / ".git"
    if dotgit.is_dir():
        gitdir = dotgit
    elif dotgit.is_file():
        first = dotgit.read_text(encoding="utf-8", errors="replace").splitlines()[:1]
        if not first or not first[0].startswith("gitdir:"):
            raise TreeError(f"{dotgit} is not a gitdir file")
        gitdir = Path(first[0][len("gitdir:"):].strip())
        if not gitdir.is_absolute():
            gitdir = top / gitdir
    else:
        raise TreeError(f"{top} has no .git: the work tree's git directory cannot be resolved")
    gitdir = Path(os.path.realpath(gitdir))
    common = gitdir
    pointer = gitdir / "commondir"
    if pointer.is_file():
        text = pointer.read_text(encoding="utf-8", errors="replace").strip()
        common = Path(os.path.realpath(gitdir / text if not os.path.isabs(text) else text))
    return top, gitdir, common / "objects"


_CONFIG_SCOPES = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM")


def _scrubbed_environment() -> Dict[str, str]:
    return {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_") or k.upper() in _CONFIG_SCOPES}


def _submodule_environment() -> Dict[str, str]:
    """git inside a submodule: nothing of the work tree's environment reaches it (``GIT_DIR`` or
    ``GIT_INDEX_FILE`` would make it read the work tree's repository instead)."""
    env = _scrubbed_environment()
    env.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
    return env


def _spawn(flags: Sequence[str], args: Sequence[str], cwd: Path, env: Dict[str, str],
           stdin: Optional[bytes] = None, timeout: float = GIT_TIMEOUT_SECONDS) -> subprocess.CompletedProcess:
    try:
        argv = [gitsafe.git_executable(), *flags, *args]
    except gitsafe.GitError as exc:  # a sibling of TreeError, the only error tree_of turns into an answer
        raise TreeError(str(exc)) from exc
    try:
        return subprocess.run(argv, cwd=str(cwd), env=env, input=stdin,
                              stdin=None if stdin is not None else subprocess.DEVNULL,
                              capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise TreeError(f"git {args[0] if args else ''} timed out after {timeout:g}s") from exc
    except OSError as exc:
        raise TreeError(f"cannot run git: {exc}") from exc


def _parse_entries(stdout: bytes) -> List[Tuple[str, str, str]]:
    """``(mode, oid, path)`` of each ``ls-files -s -z`` record."""
    found = []
    for item in stdout.split(b"\0"):
        meta, _, path = item.partition(b"\t")
        parts = meta.split()
        if len(parts) == 3:
            found.append((parts[0].decode("ascii"), parts[1].decode("ascii"), os.fsdecode(path)))
    return found


def _stable_flags() -> List[str]:
    return [arg for setting in _STABLE_CONFIG for arg in ("-c", setting)]


def _neutralising_flags(drivers: Sequence[str]) -> List[str]:
    flags: List[str] = []
    for driver in drivers:
        flags += [arg for var in _FILTER_VARS for arg in ("-c", f"filter.{driver}.{var}=")]
        flags += ["-c", f"filter.{driver}.required=false"]
    return flags


def _config_keys(repo: Path, env: Dict[str, str]) -> Optional[List[Tuple[str, str]]]:
    """``(scope, key)`` of each config entry git reads in ``repo``, or None when it cannot list them.
    A git before 2.26 has no ``--show-scope``: every scope then reads ``""``, which is not trusted."""
    listed = _spawn(_stable_flags(), ["config", "--list", "--show-scope", "--name-only", "-z"], repo, env)
    if listed.returncode == 0:
        fields = listed.stdout.decode("utf-8", "replace").split("\0")
        return list(zip(fields[0::2], fields[1::2]))
    listed = _spawn(_stable_flags(), ["config", "--list", "--name-only", "-z"], repo, env)
    if listed.returncode != 0:
        return None
    return [("", key) for key in listed.stdout.decode("utf-8", "replace").split("\0")]


def _filter_drivers(repo: Path, env: Dict[str, str]) -> Tuple[List[str], str]:
    """The filter drivers that the configuration of ``repo`` (read under ``env``) and of each
    checked-out submodule below it defines outside ``gitsafe.TRUSTED_SCOPES``, and why that list
    cannot be relied on (``""`` when it can).

    The ``-c`` options of the outer ``git add`` reach the ``git status`` it runs in a submodule
    (``GIT_CONFIG_PARAMETERS``), so naming a submodule's drivers there switches them off.
    """
    drivers: List[str] = []
    seen: Set[str] = set()
    pending = [(repo, 0)]
    while pending:
        here, depth = pending.pop()
        real = os.path.realpath(here)
        if real in seen:
            continue
        seen.add(real)
        if depth > _MAX_SUBMODULE_DEPTH:
            return drivers, f"submodules are nested more than {_MAX_SUBMODULE_DEPTH} deep"
        here_env = env if depth == 0 else _submodule_environment()
        keys = _config_keys(here, here_env)
        if keys is None:
            if depth == 0:
                return drivers, "git config --list failed, so its filter drivers cannot be switched off"
            continue  # git cannot read this submodule's config, so it runs nothing from it
        for scope, key in keys:
            lowered = key.lower()
            if scope not in gitsafe.TRUSTED_SCOPES and lowered.startswith("filter.") \
                    and lowered.rsplit(".", 1)[-1] in (*_FILTER_VARS, "required"):
                driver = key[len("filter."):].rsplit(".", 1)[0]
                if "=" in driver or "\ufffd" in driver:  # -c splits at the first "="; undecodable bytes
                    return drivers, f"filter driver {driver!r} has a name git -c cannot carry: it cannot be switched off"
                if driver and driver not in drivers:
                    drivers.append(driver)
        listing = _spawn(_stable_flags(), ["ls-files", "-s", "-z"], here, here_env)
        if listing.returncode == 0:
            pending += [(here / path, depth + 1) for mode, _oid, path in _parse_entries(listing.stdout)
                        if mode == _GITLINK_MODE and (here / path / ".git").exists()]
    return drivers, ""


class BoundTree:
    """A computed tree plus the private index and object directory that hold it.

    Only valid inside the ``bind`` block that made it.
    """

    def __init__(self, top: Path, gitdir: Path, objects: Path, temp: Path) -> None:
        self.top = top
        self.gitdir = gitdir
        self.temp = temp
        self.index = temp / "index"
        self.private_objects = temp / "objects"
        self.private_objects.mkdir(mode=0o700)
        self.env = _scrubbed_environment()
        self.env.update({
            "GIT_DIR": str(gitdir), "GIT_WORK_TREE": str(top), "GIT_INDEX_FILE": str(self.index),
            "GIT_OBJECT_DIRECTORY": str(self.private_objects), "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(objects),
            "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        })
        self._flags: List[str] = []
        self._refusal = ""
        self.binding = TreeBinding("unbindable", None, "not computed")

    # git -------------------------------------------------------------------

    def run(self, args: Sequence[str], stdin: Optional[bytes] = None, cwd: Optional[Path] = None,
            timeout: float = GIT_TIMEOUT_SECONDS) -> subprocess.CompletedProcess:
        return _spawn(self._flags, args, cwd or self.top, self.env, stdin, timeout)

    def _text(self, args: Sequence[str]) -> str:
        res = self.run(args)
        if res.returncode != 0:
            raise TreeError(f"git {args[0]} failed: {res.stderr.decode('utf-8', 'replace').strip()[:300]}")
        return res.stdout.decode("utf-8", "replace").strip()

    def prepare(self) -> None:
        drivers, self._refusal = _filter_drivers(self.top, self.env)
        self._flags = [*_stable_flags(), *_neutralising_flags(drivers)]

    # views of the private index --------------------------------------------

    def entries(self) -> List[Tuple[str, str, str]]:
        """``(mode, oid, path)`` of every index entry (``ls-files -s``)."""
        out = self.run(["ls-files", "-s", "-z"])
        if out.returncode != 0:
            raise TreeError("git ls-files -s failed")
        return _parse_entries(out.stdout)

    def files(self) -> List[str]:
        return sorted(path for _mode, _oid, path in self.entries())

    def symlinks(self) -> List[str]:
        return [path for mode, _oid, path in self.entries() if mode == _SYMLINK_MODE]

    def diff_entries(self, base_commit: str) -> List[Tuple[str, str]]:
        """``(status, path)`` of every path that differs between ``base_commit`` and the tree."""
        tree = self.binding.tree
        if not tree:
            raise TreeError("no tree to compare")
        base_tree = self._text(["rev-parse", "--verify", "--quiet", f"{base_commit}^{{tree}}"])
        res = self.run(["diff-tree", "-r", "-z", "--raw", "--no-renames", "--ignore-submodules=none", base_tree, tree])
        if res.returncode != 0:
            raise TreeError("git diff-tree failed")
        return [
            (status[:1], new_path if new_path is not None else path)
            for status, path, new_path in gitsafe.parse_name_status_z(res.stdout)
        ]

    def export(self, destination: Path) -> None:
        """Write the tree's files below ``destination`` (``checkout-index -a --prefix``)."""
        destination.mkdir(parents=True, exist_ok=True)
        # Sparse-checkout bits would make checkout-index skip entries that are part of the tree.
        listing = self.run(["ls-files", "-v", "-z"])
        marked = [os.fsdecode(item[2:]) for item in listing.stdout.split(b"\0") if item[:1] == b"S"]
        if marked:
            self.run(["update-index", "--no-skip-worktree", "-z", "--stdin"],
                     stdin=b"".join(os.fsencode(p) + b"\0" for p in marked))
        prefix = str(destination).rstrip("/\\") + os.sep
        # The flags gitsafe.export_tree uses, on this command only: in _STABLE_CONFIG they would reach
        # the tree recipe's `add -A` and change tree ids (tree_algo v1).
        res = self.run(["-c", "core.autocrlf=false", "-c", "core.symlinks=false", "-c", "core.sparseCheckout=false",
                        "checkout-index", "-a", "-f", f"--prefix={prefix}"])
        if res.returncode != 0:
            raise TreeError(f"git checkout-index failed: {res.stderr.decode('utf-8', 'replace').strip()[:300]}")

    # the recipe ------------------------------------------------------------

    def compute(self) -> TreeBinding:
        audit = self._refusal or self._audit()
        if audit:
            self.binding = TreeBinding("unbindable", None, audit)
            return self.binding
        added = self.run(["add", "-A", "--", ".", _EXCLUDE_STATE])
        if added.returncode != 0:
            reason = added.stderr.decode("utf-8", "replace").strip().splitlines()
            self.binding = TreeBinding("unbindable", None, "git add failed: " + (reason[-1][:200] if reason else ""))
            return self.binding
        written = self.run(["write-tree"])
        if written.returncode != 0:
            self.binding = TreeBinding("unbindable", None, "git write-tree failed: "
                                       + written.stderr.decode("utf-8", "replace").strip()[:200])
            return self.binding
        tree = written.stdout.decode("ascii", "replace").strip()
        empty = self._text_or_none(["hash-object", "-t", "tree", "--stdin"], stdin=b"")
        if tree == empty and self._head_tree() not in (None, empty):
            self.binding = TreeBinding("unbindable", None, "the work tree reads as empty while HEAD is not")
            return self.binding
        links = {path: oid for mode, oid, path in self.entries() if mode == _GITLINK_MODE}
        gitlinks = tuple(sorted(links))
        dirty = [path for path in gitlinks if self._dirty_submodule(path, links[path])]
        if dirty:
            self.binding = TreeBinding("partial", tree,
                                       f"submodule(s) differ from the recorded commit: {named_paths(dirty)}", gitlinks)
        else:
            self.binding = TreeBinding("ok", tree, "", gitlinks)
        return self.binding

    def _text_or_none(self, args: Sequence[str], stdin: Optional[bytes] = None) -> Optional[str]:
        res = self.run(args, stdin=stdin)
        return res.stdout.decode("ascii", "replace").strip() if res.returncode == 0 else None

    def _head_tree(self) -> Optional[str]:
        return self._text_or_none(["rev-parse", "--verify", "--quiet", "HEAD^{tree}"])

    def _audit(self) -> str:
        listing = self.run(["ls-files", "-v", "-z"])
        if listing.returncode != 0:
            return "git ls-files failed: " + listing.stderr.decode("utf-8", "replace").strip()[:200]
        assume: List[str] = []
        sparse: List[str] = []
        unmerged: List[str] = []
        for item in listing.stdout.split(b"\0"):
            if len(item) < 3:
                continue
            tag, path = item[:1].decode("ascii", "replace"), os.fsdecode(item[2:])
            if tag == "M":
                unmerged.append(path)
            elif tag.islower() and os.path.lexists(self.top / path):
                assume.append(path)
            elif tag == "S" and os.path.lexists(self.top / path):
                sparse.append(path)
        if unmerged:
            return f"unmerged entries (resolve the conflict first): {named_paths(unmerged)}"
        if assume:
            return f"assume-unchanged entries exist on disk, so git cannot see their changes: {named_paths(assume)}"
        if sparse:
            return f"skip-worktree entries exist on disk, so git cannot see their changes: {named_paths(sparse)}"
        return ""

    def _dirty_submodule(self, path: str, recorded: str) -> bool:
        sub = self.top / path
        if not (sub / ".git").exists():
            return False  # not checked out: the pointer is all there is to know
        env = _submodule_environment()
        try:
            # Walked again from here: `git add -A` may have just recorded an embedded repository.
            drivers, refusal = _filter_drivers(sub, env)
            if refusal:
                return True  # not read at all: the tree names the pointer, which is what "partial" says
            flags = [*_stable_flags(), *_neutralising_flags(drivers)]
            head = _spawn(flags, ["rev-parse", "HEAD"], sub, env)
            status = _spawn(flags, ["status", "--porcelain", "--untracked-files=normal"], sub, env)
        except TreeError:
            return True
        if head.returncode != 0 or status.returncode != 0:
            return True
        return head.stdout.decode("ascii", "replace").strip() != recorded or bool(status.stdout.strip())


@contextmanager
def bind(root: object) -> Iterator[BoundTree]:
    """Compute the tree of the work tree holding ``root``; the private index lives for the block.

    Raises TreeError when git or the work tree cannot be used at all; every ordinary reason for
    having no tree (a hidden change, an empty read) is a ``TreeBinding`` with status ``unbindable``.
    """
    top, gitdir, objects = _locate(Path(os.fspath(root)).resolve())
    temp = Path(tempfile.mkdtemp(prefix="aegis-tree-"))
    try:
        os.chmod(temp, 0o700)
        bound = BoundTree(top, gitdir, objects, temp)
        real_index = gitdir / "index"
        if real_index.is_file():
            shutil.copy2(real_index, bound.index)
        bound.prepare()
        bound.compute()
        yield bound
    finally:
        shutil.rmtree(temp, ignore_errors=True)


def tree_of(root: object) -> TreeBinding:
    """The binding of the work tree holding ``root``. Never raises: a work tree that cannot be
    read is an ``unbindable`` binding that says why."""
    try:
        with bind(root) as bound:
            return bound.binding
    except (TreeError, OSError) as exc:
        return TreeBinding("unbindable", None, str(exc))


def tree_files(root: object) -> List[str]:
    """The paths in the tree ``root``'s work tree would commit (for tests and reports)."""
    with bind(root) as bound:
        return bound.files()
