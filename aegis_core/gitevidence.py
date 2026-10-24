"""Repository facts the evidence readers share (ARCH-1): read-only, no network, no policy.

``repo_facts`` answers where the work tree is and what HEAD, origin/HEAD and the protected
branch's refs name, in three git calls; inside a ``gitsafe.memo()`` scope (a scan) every caller
shares that one answer, and nothing about a ref outlives the scope. What is kept across requests
is keyed by full object ids only, whose answers cannot change: a merge base, a commit list and
an ancestry seen once. A shallow repository can deepen, so its merge bases and commit lists are
asked every time; an ancestry seen there stays seen.
"""
from __future__ import annotations

from collections import OrderedDict
import os
import re
import threading
import time
from typing import Any, Mapping, NamedTuple, Optional, Sequence, Tuple

from aegis_core import gitsafe

__all__ = ["RepoFacts", "branch_tips", "commit_tree", "commits", "fetch_age", "is_ancestor", "is_ancestor_at",
           "merge_base_with", "protected_branch", "repo_facts"]

ORIGIN_HEAD = "refs/remotes/origin/HEAD"
_PROBED = (ORIGIN_HEAD, "refs/remotes/origin/main", "refs/remotes/origin/master", "refs/heads/main", "refs/heads/master")
_LEGACY = ("main", "master")
_FULL_OID = re.compile(r"[0-9a-f]{40,64}")
_REF_FORMAT = "--format=%(refname)%00%(objectname)%00%(symref)"


class RepoFacts(NamedTuple):
    top: Optional[str]  # None in a bare repository or inside .git
    common_dir: str  # absolute
    prefix: str
    shallow: bool
    head: Optional[str]  # HEAD's commit, None when unborn
    origin_head_ref: Optional[str]  # the ref origin/HEAD names, only when that ref exists
    refs: Mapping[str, str]  # each probed ref that exists -> its object id


class _Lru:
    def __init__(self, size: int) -> None:
        self.size = size
        self.items: "OrderedDict[Any, Any]" = OrderedDict()
        self.lock = threading.Lock()

    def get(self, key: Any) -> Any:
        with self.lock:
            if key not in self.items:
                return None
            self.items.move_to_end(key)
            return self.items[key]

    def put(self, key: Any, value: Any) -> None:
        with self.lock:
            self.items[key] = value
            self.items.move_to_end(key)
            while len(self.items) > self.size:
                self.items.popitem(last=False)


_MERGE_BASES = _Lru(256)
_COMMITS = _Lru(4)  # a 5,000-commit list is about 1.1 MB
_TREES = _Lru(1024)
_ANCESTORS: "set[Tuple[str, str, str]]" = set()
_MAX_ANCESTORS = 20_000


def _reset_for_tests() -> None:
    _MERGE_BASES.items.clear()
    _COMMITS.items.clear()
    _TREES.items.clear()
    _ANCESTORS.clear()


def _git(facts: RepoFacts, args: Sequence[str]) -> Optional[bytes]:
    try:
        res = gitsafe.run(list(args), facts.top or facts.common_dir)
    except gitsafe.GitError:
        return None
    return res.stdout if res.returncode == 0 else None


def _refs(cwd: Any, names: Sequence[str]) -> Tuple[Optional[Mapping[str, str]], Optional[str]]:
    """``{name: oid}`` of the named refs that exist and the target of origin/HEAD. for-each-ref
    omits a dangling symbolic ref and matches a prefix up to a slash, so names are kept exactly."""
    try:
        res = gitsafe.run(["for-each-ref", _REF_FORMAT, *names], cwd)
    except gitsafe.GitError:
        return None, None
    if res.returncode != 0:
        return None, None
    found, target = {}, None
    for line in os.fsdecode(res.stdout).splitlines():
        fields = line.split("\0")
        if len(fields) == 3 and fields[0] in names and _FULL_OID.fullmatch(fields[1]):
            found[fields[0]] = fields[1]
            if fields[0] == ORIGIN_HEAD and fields[2]:
                target = fields[2]
    return found, target


def _facts(cwd: Any) -> Optional[RepoFacts]:
    layout = gitsafe.layout(cwd)
    if layout is None:
        return None
    common = layout.common_dir if os.path.isabs(layout.common_dir) else os.path.join(os.path.abspath(cwd),
                                                                                  layout.common_dir)
    refs, target = _refs(cwd, _PROBED)
    return RepoFacts(layout.top, common, layout.prefix, layout.shallow, gitsafe.head_commit(cwd), target, refs or {})


def repo_facts(cwd: Any) -> Optional[RepoFacts]:
    """The facts of the repository holding ``cwd``, or None outside any repository."""
    return gitsafe.memoized((os.path.realpath(cwd), "gitevidence.repo_facts"), lambda: _facts(cwd))


def protected_branch(facts: Optional[RepoFacts]) -> Optional[str]:
    """The branch origin/HEAD names, else main, else master (local or origin's); None outside a work tree."""
    if facts is None or facts.top is None:
        return None
    target = facts.origin_head_ref or ""
    if target.startswith("refs/remotes/origin/"):
        branch = target[len("refs/remotes/origin/"):].strip()
        if branch and branch != "HEAD":
            return branch
    return next((b for b in _LEGACY if {f"refs/remotes/origin/{b}", f"refs/heads/{b}"} & set(facts.refs)), None)


def _key(facts: RepoFacts, *parts: Any) -> Tuple[Any, ...]:
    return (os.path.realpath(facts.common_dir), *parts)


def merge_base_with(facts: Optional[RepoFacts], ref: str = ORIGIN_HEAD) -> Optional[str]:
    """The merge base of HEAD and ``ref`` (a probed ref or a full commit id), or None."""
    if facts is None or not facts.head:
        return None
    other = facts.refs.get(ref) or (ref if _FULL_OID.fullmatch(ref) else None)
    if other is None:
        return None
    if other == facts.head:
        return other
    key = _key(facts, facts.head, other)
    found = None if facts.shallow else _MERGE_BASES.get(key)
    if found is None:
        text = os.fsdecode((_git(facts, ["merge-base", facts.head, other]) or b"").strip())
        found = text if _FULL_OID.fullmatch(text) else None
        if found and not facts.shallow:
            _MERGE_BASES.put(key, found)
    return found


def branch_tips(facts: Optional[RepoFacts], branch: str) -> Tuple[str, ...]:
    """The object ids of ``refs/remotes/origin/<branch>`` and ``refs/heads/<branch>`` that exist."""
    if facts is None or not branch or branch.startswith("-"):
        return ()
    names = (f"refs/remotes/origin/{branch}", f"refs/heads/{branch}")
    if branch in _LEGACY:
        found: Optional[Mapping[str, str]] = facts.refs
    else:
        where = facts.top or facts.common_dir
        found = gitsafe.memoized((os.path.realpath(where), "gitevidence.tips", branch), lambda: _refs(where, names)[0])
    return tuple(found[n] for n in names if found and n in found)


def commits(facts: Optional[RepoFacts], tips: Sequence[str], limit: int) -> Tuple[Tuple[str, str], ...]:
    """``(commit, tree)`` reachable from ``tips``, newest first, at most ``limit``; () when git fails."""
    wanted = tuple(dict.fromkeys(t for t in tips if isinstance(t, str) and _FULL_OID.fullmatch(t)))
    if facts is None or not wanted:
        return ()
    key = _key(facts, wanted, int(limit))
    cached = None if facts.shallow else _COMMITS.get(key)
    if cached is not None:
        return cached
    out = _git(facts, ["rev-list", f"--max-count={int(limit)}", "--format=%T", *wanted])
    if out is None:
        return ()
    found, commit = [], None
    for line in out.decode("ascii", "replace").splitlines():
        if line.startswith("commit "):
            commit = line.split()[1]
        elif commit and line.strip():
            found.append((commit, line.strip()))
            commit = None
    result = tuple(found)
    if not facts.shallow:
        _COMMITS.put(key, result)
    return result


def commit_tree(cwd: Any, commit: Any) -> Optional[str]:
    """The tree of ``commit`` (a full object id) in the repository at ``cwd``, or None when git names
    none (or ``commit`` is anything else, which never reaches git). Raises GitError when git cannot
    run. Only an answer is remembered: a commit's tree never changes, a missing commit may be fetched."""
    if not (isinstance(commit, str) and _FULL_OID.fullmatch(commit)):
        return None
    key = (os.path.realpath(cwd), commit)
    found = _TREES.get(key)
    if found is None:
        res = gitsafe.run(["rev-parse", "--verify", "--quiet", f"{commit}^{{tree}}"], cwd)
        text = os.fsdecode(res.stdout.strip()) if res.returncode == 0 else ""
        found = text if _FULL_OID.fullmatch(text) else None
        if found:
            _TREES.put(key, found)
    return found


def is_ancestor(facts: Optional[RepoFacts], ancestor: Any, descendant: Any) -> bool:
    """Whether ``ancestor`` is an ancestor of ``descendant``. Only full object ids reach git (a
    ledger row names them, and ledger rows are agent-writable); only a yes is remembered."""
    return facts is not None and _ancestry(facts.top or facts.common_dir, _key(facts), ancestor, descendant)


def is_ancestor_at(cwd: Any, ancestor: Any, descendant: Any) -> bool:
    """``is_ancestor`` for a caller that holds no RepoFacts (which cost three git calls to read), in
    the repository at ``cwd``; the same rules."""
    return _ancestry(cwd, (os.path.realpath(cwd),), ancestor, descendant)


def _ancestry(cwd: Any, where: Tuple[Any, ...], ancestor: Any, descendant: Any) -> bool:
    if not all(isinstance(v, str) and _FULL_OID.fullmatch(v) for v in (ancestor, descendant)):
        return False
    key = (*where, ancestor, descendant)
    if key in _ANCESTORS:
        return True
    try:
        res = gitsafe.run(["merge-base", "--is-ancestor", ancestor, descendant], cwd)
    except gitsafe.GitError:
        return False
    if res.returncode != 0:
        return False
    if len(_ANCESTORS) >= _MAX_ANCESTORS:
        _ANCESTORS.clear()
    _ANCESTORS.add(key)
    return True


def fetch_age(cwd: Any) -> Optional[float]:
    """Seconds since the newest FETCH_HEAD of ``cwd``'s repository was written, or None (not a
    repository, git unavailable, never fetched). FETCH_HEAD is per work tree, so a fetch run in
    another work tree of the repository is read from the common dir. Aegis never fetches: this
    only says how old origin/HEAD, and so the BASE anchor, may be."""
    common = gitsafe.common_dir(cwd)
    stamps = []
    for path in (gitsafe.git_path(cwd, "FETCH_HEAD"), common / "FETCH_HEAD" if common is not None else None):
        try:
            if path is not None:
                stamps.append(os.stat(str(path)).st_mtime)
        except OSError:
            continue
    return max(0.0, time.time() - max(stamps)) if stamps else None
