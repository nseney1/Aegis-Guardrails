"""Every git subprocess Aegis runs (D20, host-matrix §3.7, v4.3 spec §10.1).

A repository's own config is attacker-controlled: ``core.fsmonitor`` names a program
that ``git status``/``git diff`` run, hooks run on many commands, a clean filter
(``filter.<driver>.clean``) runs whenever git hashes a working-tree file that
``.gitattributes`` assigns to that driver, and remotes can prompt for credentials. So
every call here:

- runs ``git`` as an argv list (no shell) with a timeout;
- passes ``-c core.fsmonitor=false -c core.hooksPath=<devnull> -c protocol.allow=never
  -c core.sshCommand=false -c credential.helper= -c log.showSignature=false`` and points the
  signature programs (``gpg.program``, ``gpg.openpgp.program``, ``gpg.x509.program``) at
  <devnull> (command-line config beats repo config);
- sets ``GIT_TERMINAL_PROMPT=0 GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 LC_ALL=C``.
  The system config is read, as git reads it: the machine's administrator writes it,
  and Git for Windows keeps ``core.autocrlf=true`` there, without which every file of a
  Windows checkout (CRLF in the work tree, LF in the repository) looks modified;
- uses plumbing: ``rev-parse``, ``merge-base``, ``diff-tree``, ``diff-index``,
  ``ls-tree``, ``ls-files``, ``cat-file --batch``/``--batch-check``, ``for-each-ref``,
  ``check-ref-format``, ``hash-object``, ``version`` and ``config`` (reads only). It
  writes in four places only, never to the work tree, the index, a branch or a tag:
  ``hash-object -w`` stores a blob, ``update-ref --no-deref --stdin`` creates, swaps
  or deletes one ref under compare-and-swap, always under ``refs/aegis/`` (the team's
  leases; ``update_ref`` refuses any other name), and ``merge-tree --write-tree``
  stores the objects of a trial merge that nothing references (git's gc collects
  them), and ``interpret-trailers --in-place`` edits the prepare-commit-msg hook's message
  file, with no repository config read (its ``trailer.*`` commands). ``diff-index`` without ``--cached``, ``ls-files --others`` and
  ``hash-object --stdin-paths`` read the working tree, which is where an fsmonitor or
  a clean filter would run; they are needed (no plumbing lists changed or untracked
  files otherwise, and only git knows its line-ending conversion). The forced
  ``core.fsmonitor=false`` keeps them inert, every filter driver the repository's own
  config defines is switched off for them (a driver from the user's or the system's
  config, git-lfs say, still runs, as in any git command the user types), and
  ``diff-index`` does not look inside a dirty submodule, where it would run ``git
  status`` under the submodule's own config.

Blob content read through ``cat-file`` is checked against the object id it was asked
for, so a replaced or corrupted object is an error rather than silent input.

The query helpers answer None when git cannot answer. The ref, object, diff and merge
primitives the team lanes use (``write_blob``, ``update_ref``, ``read_ref``,
``list_refs``, ``read_object``, ``diff_entries``, ``merge_tree_conflicted``) raise
GitError instead, so "git could not say" is never mistaken for "nothing there".
``merge-tree`` runs merge drivers and, with ``merge.renormalize``, filters: a merge
driver the repository's own config defines makes it unavailable, and the repository's
filter drivers and renormalization are switched off for it.
"""
from __future__ import annotations

from contextlib import contextmanager
import contextvars
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, NamedTuple, Optional, Sequence, Tuple, Union

from aegis_core import pathlookup
from aegis_core.errors import AegisError

__all__ = [
    "CHANGE_MODES",
    "GIT_TIMEOUT_SECONDS",
    "MERGE_TREE_MIN_VERSION",
    "UPDATE_REF_ATTEMPTS",
    "UPDATE_REF_BACKOFF_SECONDS",
    "GitError",
    "Layout",
    "MergeTreeUnavailable",
    "RefConflict",
    "RefNameError",
    "TRUSTED_SCOPES",
    "add_trailer",
    "blob_id",
    "blob_oid",
    "changed_files",
    "common_dir",
    "diff_entries",
    "export_tree",
    "filter_overrides",
    "git_executable",
    "git_path",
    "git_version",
    "head_commit",
    "in_memo",
    "layout",
    "list_files",
    "list_refs",
    "merge_base",
    "memo",
    "memoized",
    "merge_tree_conflicted",
    "parse_name_status_z",
    "read_blob",
    "read_blobs",
    "read_object",
    "read_ref",
    "relative_to_prefix",
    "resolve_base_ref",
    "resolve_commit",
    "run",
    "show_prefix",
    "toplevel",
    "tree_blobs",
    "update_ref",
    "write_blob",
]

GIT_TIMEOUT_SECONDS = 10.0
CHANGE_MODES = ("working", "staged", "head", "range")
#: A failed update_ref whose ref still holds the expected value is retried this many
#: times in all, sleeping 0.05 s, 0.1 s, 0.2 s and 0.4 s between attempts.
UPDATE_REF_ATTEMPTS = 5
UPDATE_REF_BACKOFF_SECONDS = 0.05
MERGE_TREE_MIN_VERSION = (2, 38)
#: The only ref hierarchy update_ref writes: never a branch, a tag or a remote ref.
_WRITABLE_REFS = "refs/aegis/"
_ACMR = "--diff-filter=ACMR"
# git takes a signature's format from its armor, so a PGP or X.509 signature runs gpg.program
# or gpg.x509.program, which repository config can set (log.showSignature makes plain ``git
# log`` check them). Aegis checks SSH signatures only, through the gpg.ssh.program human_gate
# pins. <devnull>, not a bare ``false``: git looks a bare name up on PATH, where a relative or
# empty entry finds a program planted in the work tree.
_HARDENING_KEEP_HOOKS_PATH = (
    "-c", "core.fsmonitor=false",
    "-c", "protocol.allow=never",
    "-c", "core.sshCommand=false",
    "-c", "credential.helper=",
    "-c", "log.showSignature=false",
    "-c", f"gpg.program={os.devnull}",
    "-c", f"gpg.openpgp.program={os.devnull}",
    "-c", f"gpg.x509.program={os.devnull}",
)
_HARDENING = ("-c", f"core.hooksPath={os.devnull}", *_HARDENING_KEEP_HOOKS_PATH)
_ENV = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "LC_ALL": "C",
}


class GitError(AegisError):
    """git is missing, timed out, or gave an answer that cannot be trusted."""


class RefNameError(GitError):
    """A ref name (or ref hierarchy) git would not accept, or one update_ref may not write
    (anything outside ``refs/aegis/``); refused before anything is written."""


class RefConflict(GitError):
    """A compare-and-swap ``update_ref`` lost: the ref holds something other than the
    caller expected. ``expected`` and ``current`` are object ids, None meaning absent.

    ``current`` equal to the value the caller tried to write means its own write landed
    and only git's acknowledgement was lost.
    """

    def __init__(self, message: str = "", ref: str = "", expected: Optional[str] = None,
                 current: Optional[str] = None, **kwargs) -> None:
        super().__init__(message, ref=ref, expected=expected, current=current, **kwargs)


class MergeTreeUnavailable(GitError):
    """``git merge-tree --write-tree`` cannot answer here (git older than 2.38, or a merge
    driver from the repository's own config it would run)."""


_GIT_FOUND: Dict[Tuple[Optional[str], ...], str] = {}


def _reset_for_tests() -> None:
    _GIT_FOUND.clear()


def git_executable() -> str:
    """The git ``run`` starts, looked up once per PATH value; a git removed since raises GitError."""
    # Absolute PATH entries only: an empty or relative entry names the cwd (the
    # repository, where a clone can plant a git), and so does the current directory
    # the standard library's lookup searches first on Windows.
    key = (os.environ.get("PATH"), os.environ.get("PATHEXT"))
    found = _GIT_FOUND.get(key)
    if not (found and os.path.isfile(found) and os.access(found, os.X_OK)):
        _GIT_FOUND.clear()
        found = pathlookup.which("git")
        if not found:
            raise GitError("git is not installed or not on PATH")
        _GIT_FOUND[key] = found
    return found


def run(
    args: Sequence[str],
    cwd: Path | str,
    timeout: float = GIT_TIMEOUT_SECONDS,
    stdin: Optional[bytes] = None,
    _hardening: Sequence[str] = _HARDENING,
    _env: Optional[Mapping[str, str]] = None,
    tty: bool = False,
) -> subprocess.CompletedProcess:
    """Run ``git <args>`` hardened as described above; return the completed process (bytes).

    A non-zero exit is returned, not raised. Raises GitError when git cannot be started
    or exceeds ``timeout``. ``tty``: git (and a signing program it runs) reads the caller's stdin.
    """
    argv = [git_executable(), *_hardening, *args]
    env = dict(os.environ)
    env.update(_ENV)
    if _env is not None:
        env.update(_env)
    try:
        return subprocess.run(
            argv,
            cwd=str(cwd),
            env=env,
            input=stdin,
            stdin=None if stdin is not None or tty else subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {args[0] if args else ''} timed out after {timeout:g}s") from exc
    except OSError as exc:
        raise GitError(f"cannot run git: {exc}") from exc


def add_trailer(message_file: Path | str, trailer: str) -> bool:
    """Put ``trailer`` in a commit message file, replacing its key; False when git cannot. No repository
    config is read (its ``trailer.*`` commands are programs; a linked worktree's hook inherits GIT_DIR)."""
    target = os.path.abspath(message_file)  # git hands a hook a relative .git/COMMIT_EDITMSG
    try:
        with tempfile.TemporaryDirectory(prefix="aegis-trailer-") as scratch:
            res = run(["interpret-trailers", "--in-place", "--if-exists", "replace", "--trailer", trailer, target],
                      scratch, _env={"GIT_DIR": scratch, "GIT_COMMON_DIR": scratch})
    except OSError as exc:
        raise GitError(f"cannot make a directory for git: {exc}") from exc
    return res.returncode == 0


def _completed(args: Sequence[str], cwd: Path | str, **kwargs) -> Optional[subprocess.CompletedProcess]:
    """The completed call, or None (git is missing or timed out)."""
    try:
        return run(args, cwd, **kwargs)
    except GitError:
        return None


def _out(args: Sequence[str], cwd: Path | str, **kwargs) -> Optional[bytes]:
    """stdout of a successful call, or None (git failed, is missing or timed out)."""
    res = _completed(args, cwd, **kwargs)
    return res.stdout if res is not None and res.returncode == 0 else None


def _text(args: Sequence[str], cwd: Path | str, **kwargs) -> Optional[str]:
    out = _out(args, cwd, **kwargs)
    if out is None:
        return None
    text = os.fsdecode(out.strip())
    return text or None


def _z_paths(out: Optional[bytes]) -> Optional[List[str]]:
    if out is None:
        return None
    return [os.fsdecode(p) for p in out.split(b"\0") if p]


# ── Repository facts ─────────────────────────────────────────────────────────

# One request's answers (a scan): None outside a scope. Only ``layout`` and gitevidence read it,
# and nothing in it outlives the scope, so a ref that moves is seen by the next request.
_MEMO: "contextvars.ContextVar[Optional[Dict[Any, Any]]]" = contextvars.ContextVar("aegis_git_memo", default=None)


@contextmanager
def memo() -> Iterator[None]:
    """Remember repository facts until the outermost scope exits (an inner one shares it)."""
    token = _MEMO.set({}) if _MEMO.get() is None else None
    try:
        yield
    finally:
        if token is not None:
            _MEMO.reset(token)


def in_memo() -> bool:
    return _MEMO.get() is not None


def memoized(key: Tuple[Any, ...], produce: Callable[[], Any]) -> Any:
    """``produce()`` once per scope for ``key`` (which starts with the realpath of the cwd it is
    about), None answers included; outside a scope every call computes."""
    store = _MEMO.get()
    if store is None:
        return produce()
    if key not in store:
        store[key] = produce()
    return store[key]


class Layout(NamedTuple):
    """Where ``cwd`` sits: ``common_dir`` as git names it (maybe relative to cwd), ``prefix`` below the
    top level, whether the repository is shallow, and the top level (None outside a work tree)."""

    common_dir: str
    prefix: str
    shallow: bool
    top: Optional[str]


def _layout(cwd: Path | str) -> Optional[Layout]:
    try:
        res = run(["rev-parse", "--git-common-dir", "--show-prefix", "--is-shallow-repository", "--show-toplevel"], cwd)
    except GitError:
        return None
    # In a bare repository or inside .git, git dies on --show-toplevel after the first three lines.
    lines = [os.fsdecode(line) for line in res.stdout.split(b"\n")[:-1]]
    if len(lines) == (4 if res.returncode == 0 else 3):
        # An old git echoes the flag it does not know: read as shallow, the side that caches nothing.
        # git prints C:/x on Windows; normpath gives the separators Path and the callers use.
        top = lines[3].strip() if len(lines) == 4 else ""
        return Layout(lines[0].strip(), lines[1].rstrip("\r"), lines[2].strip() != "false", os.path.normpath(top) if top else None)
    common = _text(["rev-parse", "--git-common-dir"], cwd) if lines else None
    if common is None:
        return None
    # A path holding a newline cannot be split by line: each question alone, as before the combined
    # call, and shallow assumed so that nothing about it is kept beyond the request.
    prefix = _out(["rev-parse", "--show-prefix"], cwd) or b""
    top = _text(["rev-parse", "--show-toplevel"], cwd)
    return Layout(common, os.fsdecode(prefix.rstrip(b"\r\n")), True, os.path.normpath(top) if top else None)


def layout(cwd: Path | str) -> Optional[Layout]:
    """``cwd``'s Layout in one git call (memoized in a scope), or None outside any repository."""
    return memoized((os.path.realpath(cwd), "layout"), lambda: _layout(cwd))


def toplevel(cwd: Path | str) -> Optional[Path]:
    """The work tree root containing ``cwd``, or None outside a work tree."""
    found = layout(cwd)
    return Path(found.top) if found is not None and found.top else None


def show_prefix(cwd: Path | str) -> str:
    """``cwd`` below the work tree root (``rev-parse --show-prefix``): POSIX, ending in ``/``,
    ``""`` at the top level. Raises GitError when git cannot place ``cwd``: tree listings and
    diffs name top-level paths, so guessing a frame would silently drop or misplace them."""
    res = run(["rev-parse", "--show-prefix"], cwd)
    if res.returncode != 0:
        detail = " ".join(res.stderr.decode("utf-8", "replace").split())[:200]
        raise GitError(f"git rev-parse --show-prefix failed: {detail}")
    return os.fsdecode(res.stdout.rstrip(b"\r\n"))


def relative_to_prefix(prefix: str, path: str) -> Optional[str]:
    """A top-level ``path`` relative to the directory at ``prefix`` (from ``show_prefix``), or
    None when it lies outside that directory."""
    if not prefix:
        return path
    return path[len(prefix):] if path.startswith(prefix) and len(path) > len(prefix) else None


def common_dir(cwd: Path | str) -> Optional[Path]:
    """The repository's common git directory (``rev-parse --git-common-dir``) as an
    absolute path, links unresolved; None outside a repository.

    Every worktree of a repository answers the same directory (the main ``.git``), unlike
    ``--git-path``, which answers ``.git/worktrees/<name>/...`` in a linked worktree.
    """
    found = layout(cwd)
    if found is None or not found.common_dir:
        return None
    path = Path(found.common_dir)
    # git names it relative to the directory it ran in (e.g. "../.git" from a subdirectory).
    return path if path.is_absolute() else Path(os.path.abspath(cwd)) / path


_VERSION = re.compile(rb"git version (\d+)\.(\d+)(?:\.(\d+))?")


def git_version(cwd: Path | str) -> Optional[Tuple[int, int, int]]:
    """The running git's (major, minor, patch), or None when git cannot say."""
    found = _VERSION.match((_out(["version"], cwd) or b"").strip())
    if found is None:
        return None
    return int(found.group(1)), int(found.group(2)), int(found.group(3) or 0)


def git_path(cwd: Path | str, name: str) -> Optional[Path]:
    """``git rev-parse --git-path <name>`` as an absolute path (e.g. the hooks dir), or None.

    This one call omits the ``core.hooksPath`` override: it asks where hooks live, and
    rev-parse runs no hook.
    """
    text = _text(["rev-parse", "--git-path", name], cwd, _hardening=_HARDENING_KEEP_HOOKS_PATH)
    if not text:
        return None
    path = Path(text)
    return path if path.is_absolute() else (Path(cwd) / path).resolve()


def resolve_commit(cwd: Path | str, ref: str) -> Optional[str]:
    """The commit id ``ref`` names, or None. ``ref`` never reaches git as an option."""
    if not ref or ref.startswith("-"):
        return None
    return _text(["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], cwd)


def head_commit(cwd: Path | str) -> Optional[str]:
    """HEAD's commit id, or None (unborn branch, not a repository)."""
    return resolve_commit(cwd, "HEAD")


def merge_base(cwd: Path | str, a: str, b: str = "HEAD") -> Optional[str]:
    """The best common ancestor of two commits, or None. A full object id goes to git as is
    (two of them cost one call); anything else is resolved first, ``a`` before ``b``."""
    first = a if isinstance(a, str) and _OID.match(a) else resolve_commit(cwd, a)
    second = (b if isinstance(b, str) and _OID.match(b) else resolve_commit(cwd, b)) if first else None
    if not first or not second:
        return None
    return _text(["merge-base", first, second], cwd)


def resolve_base_ref(cwd: Path | str, environ: Optional[dict] = None) -> Optional[str]:
    """The base branch a change is measured against: the first that resolves of
    ``origin/$GITHUB_BASE_REF``, ``$GITHUB_BASE_REF``, ``origin/main``, ``main``,
    ``origin/develop``, ``develop``. Returns the ref name, or None."""
    env = os.environ if environ is None else environ
    candidates: List[str] = []
    base = (env.get("GITHUB_BASE_REF") or "").strip()  # set by GitHub Actions on pull requests
    if base:
        candidates += [f"origin/{base}", base]
    candidates += ["origin/main", "main", "origin/develop", "develop"]
    for ref in candidates:
        if resolve_commit(cwd, ref):
            return ref
    return None


def _empty_tree(cwd: Path | str) -> Optional[str]:
    # hash-object writes nothing without -w; it answers in the repository's hash format.
    return _text(["hash-object", "-t", "tree", "--stdin"], cwd, stdin=b"")


def _head_or_empty_tree(cwd: Path | str) -> Optional[str]:
    return head_commit(cwd) or _empty_tree(cwd)


# ── Changed and listed files ─────────────────────────────────────────────────

def blob_id(data: bytes, oid_length: int = 40) -> str:
    """The git blob object id of ``data`` (40-char SHA-1 or 64-char SHA-256)."""
    header = b"blob %d\0" % len(data)
    digest = hashlib.sha256 if oid_length == 64 else hashlib.sha1
    return digest(header + data).hexdigest()


_blob_id = blob_id


# Config scopes the user or the machine's administrator wrote. A filter driver defined in
# any other scope (the repository's .git/config or config.worktree, or a file either
# includes) is switched off before git reads working-tree files.
TRUSTED_SCOPES = frozenset({"system", "global", "command"})
_FILTER_COMMANDS = ("clean", "smudge", "process")
_REGULAR_MODES = frozenset({"100644", "100755"})
_LINK_MODE = "120000"


def filter_overrides(cwd: Path | str, scope: str = "untrusted") -> Optional[Tuple[str, ...]]:
    """``-c`` options that switch off every filter driver the repository's config defines
    (``scope="all"``: every configured driver, whoever wrote it), or None when git cannot
    list them or a driver's name cannot be given to ``-c`` (it splits at the first ``=``)."""
    listing = ["config", "--null", "--name-only", "--get-regexp", r"^filter\."]
    res = _completed([listing[0], "--show-scope", *listing[1:]] if scope == "untrusted" else listing, cwd)
    if res is None:
        return None
    if res.returncode == 1:  # no filter driver is configured anywhere
        return ()
    if res.returncode != 0:  # git before 2.26 has no --show-scope: switch off every driver
        return filter_overrides(cwd, "all") if scope == "untrusted" else None
    fields = res.stdout.split(b"\0")
    keys = [key for key in fields if key] if scope != "untrusted" else [
        key for where, key in zip(fields[0::2], fields[1::2])
        if key and where.decode("ascii", "replace") not in TRUSTED_SCOPES]
    overrides: List[str] = []
    for driver in dict.fromkeys(os.fsdecode(key)[len("filter."):].rpartition(".")[0] for key in keys):
        if not driver:
            continue  # "filter.<key>" without a driver name configures nothing
        if "=" in driver:
            return None
        for command in _FILTER_COMMANDS:
            overrides += ["-c", f"filter.{driver}.{command}="]
        overrides += ["-c", f"filter.{driver}.required=false"]
    return tuple(overrides)


def _work_tree_bytes(path: Path, mode: str) -> Tuple[Optional[bytes], bool]:
    """What git hashes for the work-tree entry at ``path`` (None if there is nothing it
    could), and whether that entry is a regular file.

    A symlink entry is its target, which is what git stores for one; a regular file is
    its content (also where core.symlinks=false checked a symlink out as a file).
    Nothing is read through a link and nothing but a regular file is opened.
    """
    try:
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode):
            return (os.fsencode(os.readlink(path)) if mode == _LINK_MODE else None), False
        if stat.S_ISREG(st.st_mode):
            return path.read_bytes(), True
    except OSError:
        pass
    return None, False


def _c_quoted(path: str) -> bytes:
    """``path`` as one C-quoted line, which ``hash-object --stdin-paths`` unquotes."""
    quoted = bytearray(b'"')
    for byte in os.fsencode(path):
        if byte in b'"\\':
            quoted += b"\\" + bytes([byte])
        elif byte < 0x20 or byte == 0x7F:
            quoted += b"\\%03o" % byte
        else:
            quoted.append(byte)
    return bytes(quoted + b'"')


def _clean_blob_ids(root: Path, paths: Sequence[str], hardening: Sequence[str]) -> Optional[List[str]]:
    """The blob ids ``git add`` would store for these work-tree files, after git's clean
    conversion (core.autocrlf and core.eol, the text, eol, ident and
    working-tree-encoding attributes); None when git cannot say. Writes nothing."""
    stdin = b"".join(_c_quoted(path) + b"\n" for path in paths)
    out = _out(["hash-object", "--stdin-paths"], root, stdin=stdin, _hardening=hardening)
    ids = None if out is None else out.decode("ascii", "replace").split()
    return ids if ids is not None and len(ids) == len(paths) else None


def _working_changes(cwd: Path | str, tree: str) -> Optional[List[str]]:
    """Files whose working-tree content differs from ``tree`` (added, copied, modified).

    diff-index lists every file whose stat data is stale, so a listed file is kept only
    if git would store something else for it: a ``touch`` is not a change, and neither
    is a line-ending difference git's clean conversion removes (a CRLF checkout of LF
    blobs under core.autocrlf or ``text``). Its own bytes are compared first; only a
    regular file that differs is hashed by git.
    """
    overrides = filter_overrides(cwd)
    if overrides is None:
        return None
    hardening = (*_HARDENING, *overrides)
    out = _out(["diff-index", "-z", "--raw", "--no-renames", "--ignore-submodules=dirty", _ACMR, tree],
               cwd, _hardening=hardening)
    if out is None:
        return None
    fields = out.split(b"\0")
    root = toplevel(cwd) or Path(cwd)  # diff-index names paths from the top of the work tree
    listed: List[str] = []
    to_convert: Dict[str, str] = {}  # regular files whose bytes differ: path -> the tree's blob id
    for meta, raw_path in zip(fields[0::2], fields[1::2]):
        parts = meta.split()
        if len(parts) < 5 or not raw_path:
            continue
        old_mode, old_oid = parts[0].lstrip(b":").decode("ascii"), parts[2].decode("ascii")
        path = os.fsdecode(raw_path)
        if set(old_oid) != {"0"}:  # all zeros: not in the tree, so added
            data, is_file = _work_tree_bytes(root / path, old_mode)
            if data is not None and _blob_id(data, len(old_oid)) == old_oid:
                continue
            if is_file and old_mode in _REGULAR_MODES:
                to_convert[path] = old_oid
        listed.append(path)
    if to_convert:
        ids = _clean_blob_ids(root, list(to_convert), hardening)
        if ids is not None:  # otherwise every one of them stays listed
            unchanged = {path for (path, old), new in zip(to_convert.items(), ids) if new == old}
            listed = [path for path in listed if path not in unchanged]
    return listed


def changed_files(
    cwd: Path | str,
    mode: str = "working",
    base: Optional[str] = None,
    untracked: bool = False,
) -> Optional[List[str]]:
    """Repo-relative paths added, copied or modified (deletions are not listed).

    - ``working``: working tree and index against HEAD (``git diff HEAD`` plus
      ``git diff --cached``); with ``untracked=True`` also untracked, not ignored files.
    - ``staged``: index against HEAD (what a commit would contain).
    - ``head``: the last commit against its parent (or the root commit's files).
    - ``range``: HEAD against its merge base with ``base`` (``git diff base...HEAD``).

    An unborn HEAD compares against the empty tree. Returns None when git cannot answer
    (not a repository, git missing, ``base`` unknown).
    """
    if mode not in CHANGE_MODES:
        raise ValueError(f"mode must be one of {list(CHANGE_MODES)}, got {mode!r}")
    if mode == "range":
        if not base:
            raise ValueError("mode 'range' needs a base")
        start = merge_base(cwd, base)
        end = head_commit(cwd)
        if not start or not end:
            return None
        return _z_paths(_out(["diff-tree", "-r", "-z", "--name-only", "--no-renames", _ACMR, start, end], cwd))
    if mode == "head":
        head = head_commit(cwd)
        if not head:
            return None
        parent = resolve_commit(cwd, f"{head}~1")
        args = [parent, head] if parent else ["--root", head]
        return _z_paths(_out(["diff-tree", "-r", "-z", "--name-only", "--no-renames", "--no-commit-id", _ACMR, *args], cwd))

    tree = _head_or_empty_tree(cwd)
    if not tree:
        return None
    staged = _z_paths(_out(["diff-index", "--cached", "-z", "--name-only", "--no-renames", _ACMR, tree], cwd))
    if staged is None or mode == "staged":
        return staged
    working = _working_changes(cwd, tree)
    if working is None:
        return None
    files = list(dict.fromkeys(working + staged))
    if untracked:
        others = list_files(cwd, tracked=False, untracked=True)
        if others is None:
            return None
        files = list(dict.fromkeys(files + others))
    return files


def list_files(
    cwd: Path | str,
    paths: Iterable[str] = (),
    tracked: bool = True,
    untracked: bool = True,
) -> Optional[List[str]]:
    """Files git knows about under ``paths`` (all when empty), relative to ``cwd`` (the workspace,
    not the repository top): tracked and/or untracked, not ignored. None when git cannot answer."""
    args = ["ls-files", "-z"]
    if tracked:
        args.append("--cached")
    if untracked:
        args += ["--others", "--exclude-standard"]
    args.append("--")
    args += list(paths)
    found = _z_paths(_out(args, cwd))
    return None if found is None else list(dict.fromkeys(found))


# ── Reading blobs ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class _TreeEntry:
    mode: str
    kind: str
    oid: str


def _tree_entry(cwd: Path | str, commit: str, path: str) -> Optional[_TreeEntry]:
    out = _out(["ls-tree", "-z", "--full-tree", commit, "--", path], cwd)
    if not out:
        return None
    meta, _, _ = out.split(b"\0", 1)[0].partition(b"\t")
    parts = meta.split()
    if len(parts) != 3:
        return None
    return _TreeEntry(*(p.decode("ascii") for p in parts))


def read_blob(cwd: Path | str, rev: str, path: str) -> Optional[bytes]:
    """The bytes of ``path`` (repo-relative, POSIX) at commit ``rev``; None if it is absent.

    Raises GitError when git returns content that does not hash to the object id it
    named (a replaced or corrupt object).
    """
    commit = resolve_commit(cwd, rev)
    if not commit:
        return None
    entry = _tree_entry(cwd, commit, path)
    if entry is None or entry.kind != "blob":
        return None
    out = _out(["cat-file", "--batch"], cwd, stdin=entry.oid.encode("ascii") + b"\n")
    if not out:
        return None
    header, _, rest = out.partition(b"\n")
    fields = header.split()
    if len(fields) != 3 or fields[1] != b"blob":
        return None
    size = int(fields[2])
    data = rest[:size]
    if len(data) != size or _blob_id(data, len(entry.oid)) != entry.oid:
        raise GitError(f"git returned content for {path} at {rev} that does not match object {entry.oid}")
    return data


def _parse_cat_file_batch(out: bytes, wanted: Sequence[str]) -> Dict[str, bytes]:
    blobs: Dict[str, bytes] = {}
    position = 0
    for oid in wanted:
        end = out.find(b"\n", position)
        header = out[position:end].split() if end >= 0 else []
        if (
            len(header) != 3
            or header[0].decode("ascii", "replace") != oid
            or header[1] != b"blob"
            or not header[2].isdigit()
        ):
            raise GitError(f"git cannot read object {oid}")
        size = int(header[2])
        data = out[end + 1 : end + 1 + size]
        if len(data) != size or blob_id(data, len(oid)) != oid:
            raise GitError(f"git returned content for {oid} that does not match the object id")
        blobs[oid] = data
        position = end + 1 + size + 1
    return blobs


def read_blobs(
    cwd: Union[str, os.PathLike[str]],
    oids: Iterable[str],
    *,
    timeout: float = 60.0,
) -> Dict[str, bytes]:
    """Batch-read git blob objects via ``cat-file --batch``, verifying each object's type, size, and hash."""
    wanted = list(dict.fromkeys(oids))
    if not wanted:
        return {}
    stdin = ("\n".join(wanted) + "\n").encode("ascii")
    res = run(["cat-file", "--batch"], cwd, timeout=timeout, stdin=stdin)
    if res.returncode != 0:
        detail = " ".join(res.stderr.decode("utf-8", "replace").split())[:200]
        raise GitError(f"git cat-file failed: {detail}")
    return _parse_cat_file_batch(res.stdout, wanted)


def tree_blobs(
    cwd: Union[str, os.PathLike[str]],
    rev: str,
    *,
    paths: Sequence[str] = (),
    include_symlinks: bool = False,
    timeout: float = 60.0,
) -> Dict[str, Tuple[str, str]]:
    """List blob entries in ``rev`` via ``ls-tree -r -z --full-tree`` as ``{path: (mode, oid)}``."""
    if not isinstance(rev, str) or not rev or rev.startswith("-"):
        raise GitError(f"invalid revision {rev!r}")
    args = ["ls-tree", "-r", "-z", "--full-tree", rev]
    if paths:
        args.append("--")
        args.extend(paths)
    res = run(args, cwd, timeout=timeout)
    if res.returncode != 0:
        detail = " ".join(res.stderr.decode("utf-8", "replace").split())[:200]
        raise GitError(f"git ls-tree failed: {detail}")
    found: Dict[str, Tuple[str, str]] = {}
    for record in res.stdout.split(b"\0"):
        if not record:
            continue
        meta, sep, raw_path = record.partition(b"\t")
        if not sep or not raw_path:
            continue
        fields = meta.split()
        if len(fields) != 3:
            continue
        mode, kind, oid = (field.decode("ascii", "replace") for field in fields)
        if kind == "blob" and (include_symlinks or mode != _LINK_MODE):
            found[os.fsdecode(raw_path)] = (mode, oid)
    return found


def parse_name_status_z(raw: bytes) -> List[Tuple[str, str, Optional[str]]]:
    """Parse NUL-delimited ``--name-status -z`` (or ``--raw -z``) output into
    ``(status, path, new_path)`` records without desynchronizing on 3-token ``R*``/``C*`` records.
    """
    if not raw:
        return []
    fields = raw.split(b"\0")
    records: List[Tuple[str, str, Optional[str]]] = []
    index = 0
    total = len(fields)
    while index < total:
        token = fields[index]
        if not token:
            index += 1
            continue
        parts = token.split()
        if not parts:
            index += 1
            continue
        status = parts[-1].decode("ascii", "replace")
        kind = status[:1]
        if kind in ("R", "C"):
            if index + 2 >= total or not fields[index + 1] or not fields[index + 2]:
                break
            old_path = os.fsdecode(fields[index + 1])
            new_path = os.fsdecode(fields[index + 2])
            records.append((status, old_path, new_path))
            index += 3
        else:
            if index + 1 >= total or not fields[index + 1]:
                break
            path = os.fsdecode(fields[index + 1])
            records.append((status, path, None))
            index += 2
    return records


def _on_windows() -> bool:
    return os.name == "nt"


def _safe_export_target(destination: Path, rel_path: str) -> Optional[Path]:
    # On Windows ":" makes a part drive-relative (D:x) or a stream; on POSIX a:b.py is a plain file.
    if not isinstance(rel_path, str) or not rel_path:
        return None
    parts = rel_path.replace("\\", "/").split("/")
    if any(part in ("", ".", "..") or (_on_windows() and ":" in part) for part in parts):
        return None
    target = destination.joinpath(*parts)
    base = os.path.abspath(destination)
    try:
        return target if os.path.commonpath([os.path.abspath(target), base]) == base else None
    except ValueError:  # another drive
        return None


def export_tree(
    cwd: Union[str, os.PathLike[str]],
    tree_or_commit: str,
    destination: Union[str, os.PathLike[str]],
    *,
    overlay: Optional[Mapping[str, bytes]] = None,
    timeout: float = 60.0,
) -> None:
    """Export ``tree_or_commit`` into ``destination`` using a temporary ``GIT_INDEX_FILE`` and
    ``checkout-index -a -f --prefix``, falling back to ``tree_blobs`` + ``read_blobs`` if needed,
    then write any ``overlay`` files via ``atomic_write_bytes``.
    """
    from aegis_core.storage import atomic_write_bytes

    tree = _tree_of(cwd, tree_or_commit)
    dest = Path(destination).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    root = toplevel(cwd) or Path(cwd).resolve()

    exported = False
    overrides = filter_overrides(root)
    if overrides is not None:
        temp_dir = Path(tempfile.mkdtemp(prefix="aegis-export-"))
        try:
            os.chmod(temp_dir, 0o700)
            index_file = temp_dir / "index"
            hardening = (
                *_HARDENING,
                "-c", "core.symlinks=false",
                "-c", "core.sparseCheckout=false",
                "-c", "core.autocrlf=false",
                *overrides,
            )
            env_extra = {"GIT_INDEX_FILE": str(index_file)}
            read_res = run(["read-tree", tree], root, timeout=timeout, _hardening=hardening, _env=env_extra)
            if read_res.returncode == 0:
                prefix = str(dest).rstrip("/\\") + os.sep
                checkout_res = run(
                    ["checkout-index", "-a", "-f", f"--prefix={prefix}"],
                    root,
                    timeout=timeout,
                    _hardening=hardening,
                    _env=env_extra,
                )
                if checkout_res.returncode == 0:
                    exported = True
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    if not exported:
        entries = tree_blobs(cwd, tree, timeout=timeout)
        blobs = read_blobs(cwd, (oid for _mode, oid in entries.values()), timeout=timeout)
        for rel_path, (mode, oid) in entries.items():
            target = _safe_export_target(dest, rel_path)
            if target is None or oid not in blobs:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            file_mode = 0o755 if (mode == "100755" and os.name != "nt") else None
            atomic_write_bytes(target, blobs[oid], mode=file_mode)

    if overlay:
        for rel_path, content in overlay.items():
            target = _safe_export_target(dest, rel_path)
            if target is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(target, content)



# ── Objects and refs (the team leases, v4.1 §1) ──────────────────────────────

_OID = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def _full_oid(value: object) -> str:
    if not isinstance(value, str) or not _OID.match(value):
        raise ValueError(f"not a full object id (40 or 64 lowercase hex characters): {value!r}")
    return value


def _hashed_blob(cwd: Path | str, data: bytes, write: bool) -> str:
    # From stdin with no --path, hash-object applies no attribute, filter or line-ending
    # conversion: the blob is exactly ``data``, named in the repository's hash format.
    args = ["hash-object", *(["-w"] if write else []), "--no-filters", "--stdin"]
    out = _out(args, cwd, stdin=bytes(data))
    oid = (out or b"").strip().decode("ascii", "replace")
    if not _OID.match(oid):
        raise GitError(f"git hash-object {'-w ' if write else ''}failed in {cwd}")
    if _blob_id(bytes(data), len(oid)) != oid:
        raise GitError(f"git named the blob {oid}, which does not hash its content")
    return oid


def blob_oid(cwd: Path | str, data: bytes) -> str:
    """The object id ``data`` gets as a blob in this repository; writes nothing.

    A writer computes it first, so after an error it can tell whether a ref ended up
    holding its own blob (a lost acknowledgement). Raises GitError.
    """
    return _hashed_blob(cwd, data, write=False)


def write_blob(cwd: Path | str, data: bytes) -> str:
    """Store ``data`` as a blob (``hash-object -w --stdin``) and return its object id.

    The bytes are stored as given (no filters or line-ending conversion). Raises GitError
    when git cannot store it (not a repository, git missing).
    """
    return _hashed_blob(cwd, data, write=True)


def _check_ref_name(cwd: Path | str, ref: object, what: str = "ref name") -> str:
    """``ref`` when it is a full ref under ``refs/`` that ``git check-ref-format``
    accepts; RefNameError otherwise. Nothing that git could read as an option, a
    pattern or a stdin record separator gets through."""
    ok = (
        isinstance(ref, str)
        and ref.startswith("refs/")
        and not any(ch in ref for ch in "\0\n\r")
    )
    if ok:
        res = _completed(["check-ref-format", ref], cwd)
        if res is None:
            raise GitError(f"git cannot check the {what} {ref!r}")
        ok = res.returncode == 0
    if not ok:
        raise RefNameError(f"invalid {what}: {ref!r}")
    return ref  # type: ignore[return-value]


_REF_FORMAT = "--format=%(objectname)%00%(symref)%00%(refname)"


def _refs_under(cwd: Path | str, pattern: str) -> Optional[List[Tuple[str, str]]]:
    """(ref, oid) of every ref equal to ``pattern`` or inside it as a hierarchy; None
    when git cannot answer. Raises GitError for a symbolic ref or unreadable output."""
    out = _out(["for-each-ref", _REF_FORMAT, pattern], cwd)
    if out is None:
        return None
    found: List[Tuple[str, str]] = []
    for line in out.split(b"\n"):
        if not line:
            continue
        parts = line.split(b"\0")
        if len(parts) != 3:
            raise GitError(f"git for-each-ref gave an unreadable line under {pattern}")
        oid, symref, name = (os.fsdecode(part) for part in parts)
        if name != pattern and not name.startswith(pattern + "/"):
            continue  # for-each-ref also matches by glob; a validated pattern has none
        if symref:
            raise GitError(f"{name} is a symbolic ref (to {symref}); aegis never reads or writes through one")
        found.append((name, oid))
    return found


def read_ref(cwd: Path | str, ref: str) -> Optional[str]:
    """The object id ``ref`` holds, or None when it does not exist.

    The name is exact: unlike ``rev-parse``, ``refs/aegis/lanes/x`` never resolves to
    ``refs/heads/refs/aegis/lanes/x``. Raises RefNameError for an invalid name, and
    GitError when git cannot answer or the ref is symbolic.
    """
    _check_ref_name(cwd, ref)
    found = _refs_under(cwd, ref)
    if found is None:
        raise GitError(f"cannot read {ref}: git for-each-ref failed in {cwd}")
    return next((oid for name, oid in found if name == ref), None)


def list_refs(cwd: Path | str, prefix: str) -> List[Tuple[str, str]]:
    """(ref, oid) for every ref in the hierarchy ``prefix`` (``refs/aegis/lanes`` lists
    ``refs/aegis/lanes/<x>``, never ``refs/aegis/lanesx/...``), sorted by name.

    Raises RefNameError for a prefix that is not a ref hierarchy, and GitError when git
    cannot answer or a listed ref is symbolic.
    """
    pattern = prefix.rstrip("/") if isinstance(prefix, str) else prefix
    _check_ref_name(cwd, pattern, what="ref hierarchy")
    found = _refs_under(cwd, pattern)
    if found is None:
        raise GitError(f"cannot list {pattern}: git for-each-ref failed in {cwd}")
    return found


def _has_object(cwd: Path | str, oid: str) -> Optional[bool]:
    """Whether the repository has object ``oid`` (an id of the other hash format is
    missing); None when git cannot answer."""
    out = _out(["cat-file", "--batch-check"], cwd, stdin=oid.encode("ascii") + b"\n")
    if out is None:
        return None
    return out.strip().split()[1:] != [b"missing"]


def _never_writable(cwd: Path | str, ref: str, new: Optional[str]) -> Optional[str]:
    """Why a write that failed while ``ref`` still held the expected value can never
    succeed, judged by the repository's state (never by git's message); None when
    nothing permanent is in the way, such as another writer's lock."""
    if new is not None and _has_object(cwd, new) is False:
        return f"{new} is not an object in this repository"
    try:
        existing = _refs_under(cwd, _WRITABLE_REFS.rstrip("/")) or []
    except GitError:  # a link elsewhere in refs/aegis: cannot tell, so the retries decide
        existing = []
    for name, _oid in existing:
        if name.startswith(ref + "/") or ref.startswith(name + "/"):
            return f"{ref} cannot exist alongside {name}"
    return None


def update_ref(cwd: Path | str, ref: str, new: Optional[str], old: Optional[str]) -> None:
    """Compare-and-swap ``ref`` from ``old`` to ``new`` (object ids; None means absent).

    - ``old`` None, ``new`` set: create; fails if the ref exists.
    - both set: update; fails unless the ref holds ``old``.
    - ``new`` None, ``old`` set: delete; fails unless the ref holds ``old``.

    ``ref`` must be under ``refs/aegis/``: a branch, a tag or any other ref is refused.
    One ``update-ref --no-deref --stdin`` transaction with the ``create``, ``update`` or
    ``delete`` verb, so no all-zero id is spelled and SHA-1 and SHA-256 repositories
    behave alike. A symbolic ref is never written through: an update or delete of one
    is refused (GitError), and a link that appears after that check, or a dangling one
    a create meets, is replaced by a direct ref, its target left alone. After a failure
    the ref is read again and the failure classified by state, never by git's message:

    - it holds something other than ``old`` (another oid, or absent when ``old`` was
      set): RefConflict, with ``current`` (which equals ``new`` when this write landed
      and only its acknowledgement was lost);
    - it still holds ``old`` (absent for a create) but can never take ``new``, because
      ``new`` is not an object in this repository (absent, or of the other hash format)
      or a ref in the same hierarchy is in the way (``refs/aegis/x`` versus
      ``refs/aegis/x/y``): GitError at once;
    - otherwise transient, such as another writer's ref lock: retried up to
      UPDATE_REF_ATTEMPTS times with doubling sleeps, then GitError.

    Raises RefNameError for an invalid name or one outside ``refs/aegis/`` (nothing is
    written), ValueError for a malformed object id or for ``new`` and ``old`` both None
    (an unconditional write is no CAS).
    """
    if new is None and old is None:
        raise ValueError("update_ref needs a new value, an expected old value, or both")
    if new is not None:
        _full_oid(new)
    if old is not None:
        _full_oid(old)
    _check_ref_name(cwd, ref)
    if not ref.startswith(_WRITABLE_REFS):
        raise RefNameError(f"refusing to write {ref!r}: aegis writes only refs under {_WRITABLE_REFS}")
    if old is not None:
        # ``old`` cannot have been read from a link (read_ref refuses one), yet git would
        # compare it with the link's target. This read refuses a symbolic ref; one that
        # appears after it is replaced under --no-deref, never written through.
        read_ref(cwd, ref)
    name = os.fsencode(ref)
    if new is not None and old is not None:
        command = b"update " + name + b"\0" + new.encode() + b"\0" + old.encode() + b"\0"
    elif new is not None:
        command = b"create " + name + b"\0" + new.encode() + b"\0"
    else:
        command = b"delete " + name + b"\0" + old.encode() + b"\0"  # type: ignore[union-attr]

    delay = UPDATE_REF_BACKOFF_SECONDS
    detail = ""
    for attempt in range(UPDATE_REF_ATTEMPTS):
        res = _completed(["update-ref", "--no-deref", "-z", "--stdin"], cwd, stdin=command)
        if res is not None and res.returncode == 0:
            return
        current = read_ref(cwd, ref)
        if current != old:
            raise RefConflict(
                f"{ref} holds {current or 'nothing'}, not {old or 'nothing'} as expected",
                ref=ref, expected=old, current=current,
            )
        permanent = _never_writable(cwd, ref, new)
        if permanent:
            raise GitError(f"git update-ref {ref} failed: {permanent}")
        # Kept for the person reading the final error; it never decides anything.
        lines = (res.stderr if res is not None else b"timed out").strip().splitlines()
        detail = os.fsdecode(lines[-1]) if lines else ""
        if attempt + 1 < UPDATE_REF_ATTEMPTS:
            time.sleep(delay)
            delay *= 2
    raise GitError(
        f"git update-ref {ref} failed {UPDATE_REF_ATTEMPTS} times while the ref still held the "
        f"expected value" + (f": {detail}" if detail else "")
    )


def read_object(cwd: Path | str, oid: str, max_bytes: int) -> bytes:
    """The content of blob ``oid`` (a full object id, never a revision expression).

    Raises ValueError for a malformed id or a negative cap, and GitError when the object
    is missing, is not a blob, is larger than ``max_bytes`` (checked before its content
    is read) or comes back with content that does not hash to ``oid``.
    """
    _full_oid(oid)
    if max_bytes < 0:
        raise ValueError(f"max_bytes must be at least 0, got {max_bytes}")
    request = oid.encode("ascii") + b"\n"
    checked = _out(["cat-file", "--batch-check"], cwd, stdin=request)
    if checked is None:
        raise GitError(f"git cannot describe object {oid} in {cwd}")
    header = checked.strip().split()
    if len(header) == 2 and header[1] == b"missing":
        raise GitError(f"object {oid} is missing")
    if len(header) != 3 or header[0].decode("ascii", "replace") != oid or not header[2].isdigit():
        raise GitError(f"git cannot describe object {oid} in {cwd}")
    kind, size = header[1].decode("ascii", "replace"), int(header[2])
    if kind != "blob":
        raise GitError(f"object {oid} is a {kind}, not a blob")
    if size > max_bytes:
        raise GitError(f"object {oid} is {size} bytes, over the {max_bytes}-byte cap")
    out = _out(["cat-file", "--batch"], cwd, stdin=request)
    if out is None:
        raise GitError(f"git cannot read object {oid} in {cwd}")
    head, _, rest = out.partition(b"\n")
    data = rest[:size]
    if head.split()[1:] != [b"blob", str(size).encode()] or len(data) != size or _blob_id(data, len(oid)) != oid:
        raise GitError(f"git returned content for {oid} that does not match the object id")
    return data


def _tree_of(cwd: Path | str, rev: str) -> str:
    tree = None
    if isinstance(rev, str) and rev and not rev.startswith("-"):
        tree = _text(["rev-parse", "--verify", "--quiet", f"{rev}^{{tree}}"], cwd)
    if not tree:
        raise GitError(f"cannot resolve {rev!r} to a tree in {cwd}")
    return tree


def diff_entries(cwd: Path | str, a: str, b: str) -> List[Tuple[str, str, str, str]]:
    """Every path that differs between tree-ishes ``a`` and ``b``, as
    (status, old_mode, new_mode, path) in git's order.

    ``diff-tree -r -z --raw --no-renames`` with no ``--diff-filter``: additions (A),
    deletions (D), modifications (M, a mode change included), type changes (T, such as a
    file becoming a symlink) and gitlinks (mode 160000) are all listed; a move is a D
    and an A. A side that has no entry has mode ``000000``. Paths are repo-relative
    POSIX. Raises GitError when a revision cannot be resolved or git fails.
    """
    first, second = _tree_of(cwd, a), _tree_of(cwd, b)
    out = _out(["diff-tree", "-r", "-z", "--raw", "--no-renames", "--ignore-submodules=none", first, second], cwd)
    if out is None:
        raise GitError(f"git diff-tree failed for {a}..{b} in {cwd}")
    fields = out.split(b"\0")
    entries: List[Tuple[str, str, str, str]] = []
    for meta, raw_path in zip(fields[0::2], fields[1::2]):
        parts = meta.lstrip(b":").split()
        if len(parts) != 5 or not raw_path:
            raise GitError(f"git diff-tree gave an unreadable entry for {a}..{b}")
        old_mode, new_mode, status = (p.decode("ascii", "replace") for p in (parts[0], parts[1], parts[4]))
        entries.append((status[:1], old_mode, new_mode, os.fsdecode(raw_path)))
    return entries


def _repository_merge_drivers(cwd: Path | str) -> Optional[List[str]]:
    """Names of merge drivers defined outside the user's and the system's config (the
    repository's own, which a clone or a hostile commit's setup may control); None when
    git cannot list them."""
    res = _completed(["config", "--show-scope", "--null", "--name-only", "--get-regexp", r"^merge\..+\.driver$"], cwd)
    if res is None or res.returncode not in (0, 1):
        return None
    fields = res.stdout.split(b"\0") if res.returncode == 0 else []
    names = [
        os.fsdecode(key)[len("merge."):-len(".driver")]
        for scope, key in zip(fields[0::2], fields[1::2])
        if key and scope.decode("ascii", "replace") not in TRUSTED_SCOPES
    ]
    return list(dict.fromkeys(names))


def merge_tree_conflicted(cwd: Path | str, p1: str, p2: str) -> bool:
    """Whether merging commits ``p1`` and ``p2`` has textual conflicts
    (``merge-tree --write-tree --name-only``: exit 1 is a conflict, 0 is clean).

    Needs git 2.38 or later; raises MergeTreeUnavailable otherwise, and when the
    repository's own config defines a merge driver (merge-tree would run it) or its
    filter drivers cannot be switched off. Raises GitError when a commit cannot be
    resolved or git fails. The trial merge's objects are written but referenced by
    nothing.
    """
    version = git_version(cwd)
    if version is None:
        raise MergeTreeUnavailable("cannot tell which git version runs; git merge-tree --write-tree needs git 2.38 or later")
    if version[:2] < MERGE_TREE_MIN_VERSION:
        raise MergeTreeUnavailable(
            "git merge-tree --write-tree needs git 2.38 or later; this git is " + ".".join(map(str, version))
        )
    first, second = resolve_commit(cwd, p1), resolve_commit(cwd, p2)
    if not first or not second:
        raise GitError(f"cannot resolve {p1 if not first else p2!r} to a commit in {cwd}")
    drivers = _repository_merge_drivers(cwd)
    if drivers is None:
        raise MergeTreeUnavailable("git cannot list the repository's merge drivers; the merge metric is unavailable here")
    if drivers:
        raise MergeTreeUnavailable(
            f"the repository config defines merge driver {', '.join(drivers)}, which git merge-tree would run; "
            "the merge metric is unavailable here"
        )
    overrides = filter_overrides(cwd)
    if overrides is None:
        raise MergeTreeUnavailable("cannot switch off the repository's filter drivers; the merge metric is unavailable here")
    hardening = (*_HARDENING, "-c", "merge.renormalize=false", *overrides)
    res = _completed(["merge-tree", "--write-tree", "--name-only", first, second], cwd, _hardening=hardening)
    if res is None or res.returncode not in (0, 1):
        code = "timed out" if res is None else f"exit {res.returncode}"
        raise GitError(f"git merge-tree failed ({code}) for {p1} and {p2} in {cwd}")
    return res.returncode == 1
