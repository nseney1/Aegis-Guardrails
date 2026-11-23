"""Read-only target observations, with a separate bounded diagnostic wire format.

HEAD belongs to the target worktree at observation time. It does not attest the
server runtime, served rules, permissions, or coherence across the Git reads.

Identity is reported only when the nearest ``.git`` entry at or above the bound
root (found on the filesystem, without Git) sits at Git's toplevel and names the
repository Git answered with: a ``.git`` directory that is the common directory,
or a ``.git`` file naming a linked-worktree admin directory under that common
directory whose ``gitdir`` file links back. Any other pointer (a forged one, a
``.git`` Git skipped, a ``--separate-git-dir`` checkout, a submodule) is
``unverified_git_link``. A toplevel that is not the root or one of its parents is
``root_mismatch``. HEAD is resolved literally: the exact ref a symbolic HEAD
names, or a detached HEAD's object id, which must be a commit; never Git's
revision-name fallback (refs/HEAD, refs/tags/HEAD, ...). Text that is not valid
Unicode (undecodable path bytes) is never emitted: the field becomes null with
``path_unrepresentable``.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import copy
import json
import os
from pathlib import Path
import re
import stat
from time import monotonic
from typing import Any, Dict, Optional, Tuple

from aegis_core import gitsafe, pathlookup_fence, storage_confined
from aegis_core.primitives import utc_stamp
from aegis_core.workspace.binding import WorkspaceBinding

__all__ = ["encode_target", "observe_target", "target_error"]

_MAX_BYTES = 65536
_GIT_BYTES = 8192
_DEADLINE_SECONDS = 10.0
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
# A .git file, commondir, or admin gitdir file is one path record.
_LINK_BYTES = 8192
_UNREPRESENTABLE = "Target diagnostic text is not valid Unicode and is not shown."
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_REF = re.compile(rb"refs/[^\x00-\x20\x7f~^:?*\[\\]+\n\Z")
_fsdecode = os.fsdecode  # the one decoder of Git and filesystem bytes (tests inject faults here)
_lstat = os.lstat  # the pre-read identity seam
_open_directory = pathlookup_fence.open_directory
_open_leaf = pathlookup_fence.open_leaf
_fstat = os.fstat
_read = os.read


def _canonical(path) -> Path:
    """Validate the original components before returning their canonical spelling."""
    with _path_descriptor(path, directory=True) as (_, canonical, _):
        return canonical


def _identity(info):
    return info.st_dev, info.st_ino


def _kind(info, directory):
    required = stat.S_ISDIR if directory else stat.S_ISREG
    return required(info.st_mode) and not getattr(info, "st_file_attributes", 0) & _REPARSE_POINT


@contextmanager
def _path_descriptor(path, *, directory):
    """Walk original components from the volume root, never erasing a traversal.

    '..' must still name the held parent after any concurrent reparenting.
    Every opened descriptor belongs to the context's stack.
    """
    raw = os.fspath(path)
    if (not isinstance(raw, str) or not 0 < len(raw) <= 16384 or "\0" in raw
            or not raw.startswith(os.sep) or raw.count(os.sep) > 512):
        raise ValueError("Target path cannot be verified.")
    components = raw.split(os.sep)
    if not directory and components[-1] in ("", ".", ".."):
        raise ValueError("Target path cannot be verified.")
    with ExitStack() as owned:
        root = _open_directory(None, os.sep)
        owned.callback(os.close, root)
        if not _kind(_fstat(root), True):
            raise ValueError("Target path cannot be verified.")
        parents, spelling = [root], []
        for part in components[1:] if directory else components[1:-1]:
            if part in ("", "."):
                continue
            if part == "..":
                actual = _open_directory(parents[-1], "..")
                owned.callback(os.close, actual)
                expected = parents[-2] if spelling else parents[-1]
                info = _fstat(actual)
                if not _kind(info, True) or _identity(info) != _identity(_fstat(expected)):
                    raise ValueError("Target parent changed during traversal.")
                if spelling:
                    parents.pop()
                    spelling.pop()
                continue
            child = _open_directory(parents[-1], part)
            owned.callback(os.close, child)
            if not _kind(_fstat(child), True):
                raise ValueError("Target path cannot be verified.")
            parents.append(child)
            spelling.append(part)
        if directory:
            yield parents[-1], Path(os.sep, *spelling), _fstat(parents[-1])
        else:
            leaf = components[-1]
            seen = os.stat(leaf, dir_fd=parents[-1], follow_symlinks=False)
            if not _kind(seen, False):
                raise ValueError("Target metadata cannot be verified.")
            fd = _open_leaf(parents[-1], leaf)
            owned.callback(os.close, fd)
            opened = _fstat(fd)
            if not _kind(opened, False) or _identity(seen) != _identity(opened):
                raise ValueError("Target metadata cannot be verified.")
            yield fd, Path(os.sep, *spelling, leaf), opened


def _same_file(left, right) -> bool:
    with _path_descriptor(left, directory=False) as (_, _, first):
        with _path_descriptor(right, directory=False) as (_, _, second):
            return bool(first.st_ino and _identity(first) == _identity(second))


def _decode(raw: bytes) -> Optional[str]:
    """``raw`` as text, or None when it is not representable (never an exception).

    On Windows os.fsdecode raises for bytes that are not UTF-8; on POSIX it yields
    lone surrogates. Both are the same condition here.
    """
    try:
        value = _fsdecode(raw)
    except (UnicodeDecodeError, ValueError):
        return None
    return value if _representable(value) else None


def _representable(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:  # a lone surrogate from undecodable bytes
        return False
    return True


def _clean(value: Any) -> Tuple[Any, bool]:
    """``value`` with every unrepresentable string replaced by None, and whether one was."""
    if isinstance(value, str):
        return (value, False) if _representable(value) else (None, True)
    if isinstance(value, dict):
        cleaned: Dict[Any, Any] = {}
        hit = False
        for key, item in value.items():
            if isinstance(key, str) and not _representable(key):
                return None, True
            cleaned[key], found = _clean(item)
            hit = hit or found
        return cleaned, hit
    if isinstance(value, (list, tuple)):
        items = [_clean(item) for item in value]
        return [item for item, _ in items], any(found for _, found in items)
    return value, False


def _document(status: str, reason: Optional[str], binding: Optional[dict],
              error: Optional[str] = None) -> Dict[str, Any]:
    document: Dict[str, Any] = {
        "schema": "aegis.target/v1", "status": status, "reason": reason,
        "observed_at": utc_stamp(), "binding": binding,
        "repository": {"status": "unknown", "reason": "not_bound",
                       "common_dir": None, "worktree_root": None},
        "head": {"status": "unknown", "reason": "not_bound", "oid": None},
    }
    if error is not None:
        document["error"] = error
    return document


def target_error(reason: str, message: str) -> Dict[str, Any]:
    """A diagnostic failure without a resolved binding; never an ambient lookup."""
    return _document("error", reason, None, message)


def _overflow() -> Dict[str, Any]:
    document = _document("overflow", "diagnostic_limit_exceeded", None,
                         "Target diagnostic exceeds its limits.")
    document["repository"]["reason"] = document["head"]["reason"] = "diagnostic_limit_exceeded"
    return document


def _unrepresentable(binding: Optional[dict]) -> Dict[str, Any]:
    document = _document("error", "path_unrepresentable", binding, _UNREPRESENTABLE)
    document["repository"]["reason"] = document["head"]["reason"] = "path_unrepresentable"
    return document


def _representable_document(document: Dict[str, Any]) -> Dict[str, Any]:
    """Fail closed on text a strict JSON parser rejects (lone surrogates).

    An unrepresentable binding or error makes the whole diagnostic an error; an
    unrepresentable repository path makes the Git identity unknown.
    """
    binding, bad_binding = _clean(document.get("binding"))
    _, bad_error = _clean(document.get("error"))
    if bad_binding or bad_error:
        return _unrepresentable(binding)
    repository = document.get("repository") or {}
    _, bad_paths = _clean([repository.get("common_dir"), repository.get("worktree_root")])
    if bad_paths:
        document = copy.deepcopy(document)
        document["repository"] = {"status": "unknown", "reason": "path_unrepresentable",
                                  "common_dir": None, "worktree_root": None}
        document["head"] = {"status": "unknown", "reason": "path_unrepresentable", "oid": None}
        if document.get("status") in ("observed", "unknown"):
            document["status"], document["reason"] = "unknown", "path_unrepresentable"
    if _clean(document)[1]:
        return target_error("path_unrepresentable", _UNREPRESENTABLE)
    return document


def _wire(document: dict) -> str:
    return json.dumps(document, ensure_ascii=True, separators=(",", ":")) + "\n"


def _text(value: Any, limit: int, *, nullable: bool = True) -> bool:
    return (value is None and nullable) or (
        isinstance(value, str) and len(value) <= limit and len(json.dumps(value, ensure_ascii=True)) <= limit)


def _json_cost(value: Any, remaining: int = _MAX_BYTES - 1, depth: int = 0) -> Optional[int]:
    """Bound every allocation before copying, cleaning or serializing a document."""
    if depth > 8 or remaining < 0:
        return None
    if value is None:
        cost = 4
    elif isinstance(value, str):
        if not _text(value, 4096):
            return None
        cost = len(json.dumps(value, ensure_ascii=True))
    elif isinstance(value, (dict, list, tuple)):
        if len(value) > remaining:
            return None
        cost = 2 + max(0, len(value) - 1)
        items = value.items() if isinstance(value, dict) else ((None, item) for item in value)
        for key, item in items:
            if isinstance(value, dict):
                if not isinstance(key, str):
                    return None
                key_cost = _json_cost(key, remaining - cost, depth + 1)
                if key_cost is None:
                    return None
                cost += key_cost + 1
            item_cost = _json_cost(item, remaining - cost, depth + 1)
            if item_cost is None:
                return None
            cost += item_cost
    else:
        return None
    return cost if cost <= remaining else None


def _bounded_binding(binding: WorkspaceBinding) -> bool:
    if not all(_text(v, n) for v, n in (
        (str(binding.root) if binding.root is not None else None, 4096),
        (binding.source, 64), (binding.confidence, 64), (binding.reason, 128), (binding.message, 4096),
    )):
        return False
    if not isinstance(binding.details, (list, tuple)) or len(binding.details) > 16:
        return False
    for pair in binding.details:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            return False
        key, value = pair
        if not _text(key, 64, nullable=False):
            return False
        if isinstance(value, (list, tuple)):
            if len(value) > 32 or not all(_text(item, 4096, nullable=False) for item in value):
                return False
        elif not _text(value, 4096, nullable=False):
            return False
    return _json_cost(binding.as_dict()) is not None


def encode_target(document: Dict[str, Any]) -> str:
    """One ASCII JSON document, including its newline, within the diagnostic cap.

    This limit covers this diagnostic only, not MCP framing or subprocess memory.
    Never truncate a path, message or list into a misleading partial identity.
    """
    if _json_cost(document) is None:
        return _wire(_overflow())
    document = _representable_document(document)
    if not _text(document.get("error"), 4096):
        return _wire(_overflow())
    for value in (document["repository"]["common_dir"], document["repository"]["worktree_root"]):
        if not _text(value, 4096):
            return _wire(_overflow())
    wire = _wire(document)
    if len(wire) > _MAX_BYTES:
        return _wire(_overflow())
    return wire


def _git_failure(exc: gitsafe.GitError) -> str:
    code = getattr(exc, "code", None)
    return {"git_output_limit": "diagnostic_limit_exceeded",
            "git_timeout": "git_timeout"}.get(code, "git_unavailable")


def _run(args, root: Path, deadline: float):
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise gitsafe.GitError("Target observation deadline exceeded.", code="git_timeout")
    result = gitsafe.run(args, root, timeout=remaining)
    # Defense for injected runners as well as the transport's bounded pipes.
    if len(result.stdout) > _GIT_BYTES or len(result.stderr) > _GIT_BYTES:
        raise gitsafe.GitError("Target Git output exceeds its limit.", code="git_output_limit")
    if monotonic() >= deadline:
        raise gitsafe.GitError("Target observation deadline exceeded.", code="git_timeout")
    return result


def _git_path(root: Path, flag: str, unavailable: str, deadline: float) -> Tuple[Optional[Path], Optional[str]]:
    # Remove exactly Git's final LF; other whitespace belongs to the path.
    try:
        result = _run(["rev-parse", flag], root, deadline)
    except gitsafe.GitError as exc:
        return None, _git_failure(exc)
    if result.returncode != 0:
        if b"detected dubious ownership" in result.stderr:
            return None, "unsafe_repository"
        return None, unavailable
    raw = result.stdout
    if not raw.endswith(b"\n") or not raw[:-1] or b"\0" in raw:
        return None, "invalid_git_identity"
    value = _decode(raw[:-1])
    if value is None:
        return None, "path_unrepresentable"
    if not _text(value, 4096, nullable=False):
        return None, "diagnostic_limit_exceeded"
    try:
        spelling = _joined(root, value)
        # Inspect before canonicalization can erase a symlink or junction.
        if not _directory(spelling):
            return None, "unverified_git_link"
        path = _canonical(spelling)
    except (OSError, RuntimeError, ValueError):
        return None, "unverified_git_link"
    if not _representable(str(path)):
        return None, "path_unrepresentable"
    if not _text(str(path), 4096, nullable=False):
        return None, "diagnostic_limit_exceeded"
    return path, None


def _directory(path) -> bool:
    seen = _lstat(path)
    if not _kind(seen, True):
        return False
    with _path_descriptor(path, directory=True) as (_, _, opened):
        return _identity(seen) == _identity(opened)


def _read_metadata(path: Path) -> Optional[bytes]:
    """Read bounded metadata only from the descriptor matching the pre-read lstat."""
    try:
        seen = _lstat(path)
        if not _kind(seen, False):
            return None
        with _path_descriptor(path, directory=False) as (fd, _, opened):
            if not seen.st_ino or _identity(seen) != _identity(opened) or opened.st_size > _LINK_BYTES:
                return None
            raw = bytearray()
            while len(raw) <= _LINK_BYTES:
                chunk = _read(fd, min(8192, _LINK_BYTES + 1 - len(raw)))
                if not chunk:
                    return bytes(raw)
                raw.extend(chunk)
            return None
    except (OSError, ValueError):
        return None


def _link_value(raw: Optional[bytes], prefix: bytes = b"") -> Optional[str]:
    """Decode one gitfile or admin path record, or None when the shared codec refuses it.

    Git strips a trailing CR/LF run and then accepts a remaining CR or LF as
    part of the name. This decoder strips that same run, then refuses a
    remaining CR or LF. gitfile framing applies only to the ``gitdir: ``
    prefix. commondir and the admin gitdir back-pointer are records. The
    bounded reader stays outside.
    """
    if raw is None:
        return None
    from aegis_core.git_path_codec import path_text

    gitfile = prefix == b"gitdir: "
    if prefix and not gitfile:
        return None
    try:
        text = path_text(raw, gitfile=True) if gitfile else path_text(raw, record=True)
    except gitsafe.GitError:
        return None
    if not isinstance(text, str) or not text:
        return None
    # The codec accepted the line. The module seam still refuses an injected
    # undecodable value of those same bytes.
    try:
        encoded = os.fsencode(text)
    except UnicodeEncodeError:
        return None
    decoded = _decode(encoded)
    return decoded if decoded == text else None


def _read_link(path: Path, prefix: bytes = b"") -> Optional[str]:
    """A bounded no-follow path record, decoded by the shared Git path codec."""
    return _link_value(_read_metadata(path), prefix)


def _valid_head(admin: Path) -> bool:
    raw = _read_metadata(admin / "HEAD")
    if raw is None:
        return False
    if raw.startswith(b"ref: "):
        return _REF.fullmatch(raw[5:]) is not None
    return bool(raw.endswith(b"\n") and _OID.fullmatch(raw[:-1].decode("ascii", "replace")))


def _joined(base: Path, value: str) -> str:
    # os.path.join preserves the original component sequence, including dot-dot.
    return os.path.join(os.fspath(base), value)


def _marker(root: Path) -> Optional[Path]:
    """The directory of the nearest ``.git`` entry (of any kind) at or above ``root``."""
    for directory in (root, *root.parents):
        try:
            _lstat(directory / ".git")
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            return directory  # an entry that cannot be inspected still selects; it fails verification
        return directory
    return None


def _unsafe_marker(top: Optional[Path]) -> bool:
    """Reject unsafe selecting metadata even when Git itself refuses discovery.

    Malformed markers still reach Git for not_a_repository/nearest-marker
    classification. Original path traversals must exist and be descriptor safe.
    """
    if top is None:
        return False
    try:
        dotgit = top / ".git"
        seen = _lstat(dotgit)
        if getattr(seen, "st_file_attributes", 0) & _REPARSE_POINT:
            return True
        if stat.S_ISDIR(seen.st_mode):
            admin = dotgit
        elif stat.S_ISREG(seen.st_mode):
            pointer = _read_link(dotgit, b"gitdir: ")
            if pointer is None:
                return False
            admin = _canonical(_joined(top, pointer))
        else:
            return True
        try:
            if not _directory(admin):
                return True
        except FileNotFoundError:
            return True
        for name in ("HEAD", "commondir", "gitdir"):
            try:
                _lstat(admin / name)
            except FileNotFoundError:
                continue
            raw = _read_metadata(admin / name)
            if raw is None:
                return True
            if name in ("commondir", "gitdir"):
                value = _link_value(raw)
                if value is None:
                    return True
                if name == "commondir":
                    _canonical(_joined(admin, value))
                elif stat.S_ISREG(seen.st_mode) and not _same_file(_joined(admin, value), dotgit):
                    return True
        return not _directory(admin)
    except (OSError, RuntimeError, ValueError):
        return True


def _linked(top: Optional[Path], common: Path) -> bool:
    """Validate every selecting admin record, including HEAD and commondir."""
    if top is None:
        return False
    dotgit = top / ".git"
    try:
        seen = _lstat(dotgit)
        if getattr(seen, "st_file_attributes", 0) & _REPARSE_POINT:
            return False
        if stat.S_ISDIR(seen.st_mode):
            if not _directory(dotgit) or _canonical(dotgit) != common:
                return False
            # A common directory must not redirect Git to another common dir.
            try:
                _lstat(dotgit / "commondir")
            except FileNotFoundError:
                return _valid_head(dotgit)
            return False
        if not stat.S_ISREG(seen.st_mode):
            return False
        pointer = _read_link(dotgit, b"gitdir: ")
        if pointer is None:
            return False
        admin = _canonical(_joined(top, pointer))
        if admin.parent != common / "worktrees" or not _directory(admin):
            return False
        shared = _read_link(admin / "commondir")
        if shared is None or _canonical(_joined(admin, shared)) != common:
            return False
        if not _directory(common) or not _valid_head(admin):
            return False
        back = _read_link(admin / "gitdir")
        return back is not None and _same_file(_joined(admin, back), dotgit)
    except (OSError, RuntimeError, ValueError):
        return False


def _head(root: Path, deadline: float) -> Tuple[Optional[str], Optional[str]]:
    """HEAD's commit id resolved literally, or (None, reason). At most three Git calls.

    ``rev-parse HEAD^{commit}`` would fall back to refs/HEAD, refs/tags/HEAD,
    refs/heads/HEAD, refs/remotes/HEAD... when HEAD's branch is unborn, so the
    symbolic target is read first and then shown by its exact full name.
    """
    try:
        symbolic = _run(["symbolic-ref", "-q", "HEAD"], root, deadline)
        if symbolic.returncode == 0:
            if not _REF.match(symbolic.stdout):
                return None, "head_unresolved"
            ref = _decode(symbolic.stdout[:-1])
            if ref is None:
                return None, "head_unresolved"
        elif symbolic.returncode == 1 and not symbolic.stdout:
            ref = "HEAD"  # detached: HEAD itself holds the object id
        else:
            return None, "head_unresolved"
        shown = _run(["show-ref", "--verify", "--hash", ref], root, deadline)
        if shown.returncode != 0:
            return None, "head_unresolved"  # an unborn or dangling branch
        oid = shown.stdout[:-1].decode("ascii", "replace") if shown.stdout.endswith(b"\n") else ""
        if not _OID.fullmatch(oid):
            return None, "invalid_git_identity"
        # A full object id is never read as a ref name; the tip must be a commit itself.
        peeled = _run(["rev-parse", "--verify", "--quiet", oid + "^{commit}"], root, deadline)
    except gitsafe.GitError as exc:
        return None, _git_failure(exc)
    if peeled.returncode != 0 or peeled.stdout != oid.encode("ascii") + b"\n":
        return None, "head_unresolved"
    return oid, None


def observe_target(binding: Optional[WorkspaceBinding]) -> Dict[str, Any]:
    """Observe exactly the supplied binding. Nonbound roots are never probed.

    All Git pipes are capped and share one deadline. No HEAD answer is cached.
    Unsupported descriptor platforms fail closed before probing Git.
    """
    if not isinstance(binding, WorkspaceBinding) or binding.status not in ("bound", "unbound", "hold", "error"):
        return target_error("server_binding_required", "aegis_target requires a server-resolved binding.")
    if binding.bound and (not isinstance(binding.root, Path) or not binding.root.is_absolute()
                          or ".." in binding.root.parts or "\0" in str(binding.root)):
        return target_error("server_binding_required", "aegis_target requires a server-resolved binding.")
    if not _bounded_binding(binding):
        return _overflow()
    if _clean(binding.as_dict())[1]:
        return _unrepresentable(_clean(binding.as_dict())[0])
    status = {"bound": "unknown", "unbound": "not_governed", "hold": "hold", "error": "error"}[binding.status]
    reason = {"bound": None, "unbound": "binding_unbound", "hold": "binding_hold", "error": "binding_error"}[binding.status]
    error = (binding.message or None) if not binding.bound else None
    document = _document(status, reason, binding.as_dict(), error)
    if _json_cost(document) is None:
        return _overflow()
    if not binding.bound:
        # A refusal remains a refusal even if the resolver supplied no prose.
        document["error"] = binding.message or "No governed workspace is bound to this call."
        return document

    repository = document["repository"]
    head = document["head"]
    repository["reason"] = head["reason"] = "git_unavailable"
    if not storage_confined.descriptor_supported():
        repository["reason"] = head["reason"] = document["reason"] = "unsupported_platform"
        return document
    deadline = monotonic() + _DEADLINE_SECONDS
    marker = _marker(binding.root)  # filesystem only, before any Git answer
    if _unsafe_marker(marker):
        repository["reason"] = head["reason"] = document["reason"] = "unverified_git_link"
        return document
    with gitsafe.scrubbed(), gitsafe.memo(), gitsafe.custody(
            scratch=Path(binding.root.anchor), env={"GIT_NAMESPACE": ""},
            stdout_limit=_GIT_BYTES, stderr_limit=_GIT_BYTES):
        common, reason = _git_path(binding.root, "--git-common-dir", "not_a_repository", deadline)
        if reason is None:
            top, reason = _git_path(binding.root, "--show-toplevel", "worktree_unavailable", deadline)
        else:
            top = None
        if reason == "diagnostic_limit_exceeded":
            return _overflow()
        if reason is not None:
            repository["reason"] = head["reason"] = reason
        elif top is not None and top != binding.root and top not in binding.root.parents:
            repository["reason"] = head["reason"] = "root_mismatch"
        elif marker is None or (top is not None and marker != top) or not _linked(marker, common):
            # The .git that selects this root must be the one at Git's toplevel, verified.
            repository["reason"] = head["reason"] = "unverified_git_link"
        else:
            repository.update(common_dir=str(common), worktree_root=str(top) if top is not None else None)
            repository["status"] = "observed" if top is not None else "unknown"
            repository["reason"] = reason
            oid, why = _head(binding.root, deadline)
            if why == "diagnostic_limit_exceeded":
                return _overflow()
            if oid is not None:
                head.update(status="observed", reason=None, oid=oid)
            else:
                head["reason"] = why
    document["status"] = "observed" if repository["status"] == head["status"] == "observed" else "unknown"
    document["reason"] = repository["reason"] or head["reason"]
    return json.loads(encode_target(document))
