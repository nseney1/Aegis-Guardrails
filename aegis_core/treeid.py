"""Tree identity, ``tree_algo`` v1 (v4.3 spec §3 T1): the git tree a work tree would commit.

A ``check`` row is bound to a tree, not to a path or a timestamp, so the question "is this the
code that was verified" is answered by a hash. The recipe computes that hash without touching
the repository's index, refs, work tree or object store:

1. The work tree root is the git top level of the workspace; its git directory is resolved from
   ``<root>/.git`` (a directory, or a ``gitdir:`` file of a linked worktree).
2. Every ``GIT_*`` variable is scrubbed from the environment (``rev-parse --local-env-vars``,
   ``GIT_CONFIG_*``, ``GIT_EXTERNAL_DIFF``, ``GIT_SSH*``, ``GIT_TRACE*``, ``GIT_ATTR_SOURCE``,
   ``GIT_EXEC_PATH`` and the rest), then ``GIT_DIR``/``GIT_WORK_TREE`` are set explicitly.
3. The real index is copied, mtime preserved, into a private 0700 directory and used as
   ``GIT_INDEX_FILE``, so git's racy-timestamp logic judges the same stat data the real one would.
4. ``ls-files -v`` is audited: an assume-unchanged or skip-worktree entry whose path exists on
   disk lets a file change without git seeing it, so the tree is ``unbindable``.
5. Every filter driver the configuration names is neutralised on the commands that hash content
   (``filter.<d>.clean=``, ``smudge=``, ``process=``, ``required=false``): a clean filter is a
   program the repository chose.
6. A private object directory takes the writes, with the real store as its alternate.
7. ``git add -A -- . ':(exclude,glob)**/.aegis/state/**'`` then ``git write-tree``.
8. An empty tree is refused when HEAD is not empty (an unreadable work tree must not look clean).
9. Gitlinks are listed; a submodule whose HEAD or work tree differs from the recorded commit makes
   the result ``partial``: the tree names the pointer, not the submodule's content.

``bind`` keeps the private index for as long as the caller needs it (the snapshot export and the
diff against the base read it); ``tree_of`` is the one-shot form.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

from aegis_core import gitsafe, pathlookup
from aegis_core.errors import AegisError

__all__ = [
    "TREE_ALGO",
    "BoundTree",
    "TreeBinding",
    "TreeError",
    "bind",
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
    "core.trustctime=true", "core.checkStat=default",
)


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


def _named(paths: Sequence[str]) -> str:
    shown = ", ".join(paths[:_NAMED])
    return shown + (f" and {len(paths) - _NAMED} more" if len(paths) > _NAMED else "")


def _git_executable() -> str:
    found = pathlookup.which("git")
    if not found:
        raise TreeError("git is not installed or not on PATH")
    return found


def _locate(root: Path) -> Tuple[Path, Path, Path]:
    """(work tree top, git directory, real object directory) of the work tree holding ``root``."""
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


def _scrubbed_environment() -> Dict[str, str]:
    return {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}


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
        self.binding = TreeBinding("unbindable", None, "not computed")

    # git -------------------------------------------------------------------

    def run(self, args: Sequence[str], stdin: Optional[bytes] = None, cwd: Optional[Path] = None,
            timeout: float = GIT_TIMEOUT_SECONDS) -> subprocess.CompletedProcess:
        argv = [_git_executable(), *self._flags, *args]
        try:
            return subprocess.run(argv, cwd=str(cwd or self.top), env=self.env, input=stdin,
                                  stdin=None if stdin is not None else subprocess.DEVNULL,
                                  capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise TreeError(f"git {args[0] if args else ''} timed out after {timeout:g}s") from exc
        except OSError as exc:
            raise TreeError(f"cannot run git: {exc}") from exc

    def _text(self, args: Sequence[str]) -> str:
        res = self.run(args)
        if res.returncode != 0:
            raise TreeError(f"git {args[0]} failed: {res.stderr.decode('utf-8', 'replace').strip()[:300]}")
        return res.stdout.decode("utf-8", "replace").strip()

    def _configured_filters(self) -> List[str]:
        res = subprocess.run([_git_executable(), "config", "--list", "--name-only", "-z"], cwd=str(self.top),
                             env=self.env, stdin=subprocess.DEVNULL, capture_output=True,
                             timeout=GIT_TIMEOUT_SECONDS, check=False)
        names: List[str] = []
        for key in res.stdout.decode("utf-8", "replace").split("\0"):
            lowered = key.lower()
            if lowered.startswith("filter.") and lowered.rsplit(".", 1)[-1] in (*_FILTER_VARS, "required"):
                driver = key[len("filter."):].rsplit(".", 1)[0]
                if driver and driver not in names:
                    names.append(driver)
        return names

    def prepare(self) -> None:
        flags: List[str] = []
        for setting in _STABLE_CONFIG:
            flags += ["-c", setting]
        for driver in self._configured_filters():
            for var in _FILTER_VARS:
                flags += ["-c", f"filter.{driver}.{var}="]
            flags += ["-c", f"filter.{driver}.required=false"]
        self._flags = flags

    # views of the private index --------------------------------------------

    def entries(self) -> List[Tuple[str, str, str]]:
        """``(mode, oid, path)`` of every index entry (``ls-files -s``)."""
        out = self.run(["ls-files", "-s", "-z"])
        if out.returncode != 0:
            raise TreeError("git ls-files -s failed")
        found = []
        for item in out.stdout.split(b"\0"):
            if not item:
                continue
            meta, _, path = item.partition(b"\t")
            parts = meta.split()
            if len(parts) == 3:
                found.append((parts[0].decode("ascii"), parts[1].decode("ascii"), os.fsdecode(path)))
        return found

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
        res = self.run(["checkout-index", "-a", "-f", f"--prefix={prefix}"])
        if res.returncode != 0:
            raise TreeError(f"git checkout-index failed: {res.stderr.decode('utf-8', 'replace').strip()[:300]}")

    # the recipe ------------------------------------------------------------

    def compute(self) -> TreeBinding:
        audit = self._audit()
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
        gitlinks = tuple(sorted(path for mode, _oid, path in self.entries() if mode == _GITLINK_MODE))
        dirty = [path for path in gitlinks if self._dirty_submodule(path)]
        if dirty:
            self.binding = TreeBinding("partial", tree, f"submodule(s) differ from the recorded commit: {_named(dirty)}",
                                       gitlinks)
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
            return f"unmerged entries (resolve the conflict first): {_named(unmerged)}"
        if assume:
            return f"assume-unchanged entries exist on disk, so git cannot see their changes: {_named(assume)}"
        if sparse:
            return f"skip-worktree entries exist on disk, so git cannot see their changes: {_named(sparse)}"
        return ""

    def _dirty_submodule(self, path: str) -> bool:
        sub = self.top / path
        if not (sub / ".git").exists():
            return False  # not checked out: the pointer is all there is to know
        recorded = next((oid for mode, oid, p in self.entries() if mode == _GITLINK_MODE and p == path), None)
        env = _scrubbed_environment()
        env.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
        try:
            head = subprocess.run([_git_executable(), "-c", "core.fsmonitor=false", "rev-parse", "HEAD"],
                                  cwd=str(sub), env=env, stdin=subprocess.DEVNULL, capture_output=True,
                                  timeout=GIT_TIMEOUT_SECONDS, check=False)
            status = subprocess.run([_git_executable(), "-c", "core.fsmonitor=false", "status", "--porcelain",
                                     "--untracked-files=normal"], cwd=str(sub), env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=GIT_TIMEOUT_SECONDS, check=False)
        except (subprocess.TimeoutExpired, OSError):
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
