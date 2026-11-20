"""Canonical, race-detecting byte snapshot of the rule files (aegis_core.rules projects it)."""
from __future__ import annotations

import codecs
import errno
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Collection, Dict, Iterable, List, Optional, Tuple

from aegis_core.storage import file_generation
from aegis_core.workspace.layout import WorkspaceLayout

# The hook path must not load yaml_engine; a parity test guards the parser's literal.
ZERO_WIDTH_CHARS = ("\ufeff", "\u200b", "\u200c", "\u200d")

# A 64 KiB lifecycle body plus room for frontmatter.
MAX_RULE_BYTES = 128 * 1024
_CLOSING_DELIM_RE = re.compile(r"(?m)^---[ \t]*\r?$")


def split_frontmatter(content: str) -> Tuple[str, Optional[str], str]:
    """The one frontmatter delimiter scanner: ``(status, frontmatter text, body)``.

    ``status`` is ``"ok"``, ``"none"`` (the text does not start with ``---``; the body is
    the whole text) or ``"unterminated"`` (no closing ``---`` line). Leading zero-width
    characters (a BOM) are not part of the text. The façades below keep their own
    failure contracts on top of it (defense #30).
    """
    for zw in ZERO_WIDTH_CHARS:
        if content.startswith(zw):
            content = content[len(zw):]
    if not content.startswith("---"):
        return "none", None, content
    # Partitioned rather than offset: '^' matches where ``rest`` starts, no index to miscount.
    _opening, newline, rest = content.partition("\n")
    if not newline:
        return "unterminated", None, content
    m = _CLOSING_DELIM_RE.search(rest)
    if not m:
        return "unterminated", None, content
    return "ok", rest[: m.start()], rest[m.end():]


def descriptor_supported() -> bool:
    """Load the descriptor backend only when inventory actually opens a rule."""
    from aegis_core.storage_confined import descriptor_supported as supported

    return supported()


@dataclass(frozen=True)
class RuleInventoryEntry:
    """A bounded snapshot. Oversized entries have empty content and a prefix.

    Their digest hashes a separate domain, actual size and bounded prefix, never
    the whole file. Stat identity is race evidence, not fingerprint input.
    """

    relative_path: str
    absolute_path: str
    content: bytes
    digest: str
    size: int
    prefix: bytes = field(default=b"", repr=False)
    stat_identity: Optional[Tuple[int, ...]] = field(default=None, compare=False)


def captured_entry(relative_path: str, absolute_path: str, data: bytes, *,
                   size: Optional[int] = None, stat_identity: Optional[Tuple[int, ...]] = None) -> RuleInventoryEntry:
    """Normalize bounded working bytes and historical blobs identically.

    Historical blob materialization belongs to the Git reader; this function
    retains only the prefix when the supplied bytes exceed the rule limit.
    """
    size = len(data) if size is None else size
    if size > MAX_RULE_BYTES:
        prefix = data[:MAX_RULE_BYTES + 1]
        digest = hashlib.sha256(b"aegis-rule-oversized-v1\0" + str(size).encode("ascii") + b"\0" + prefix).hexdigest()
        return RuleInventoryEntry(relative_path, absolute_path, b"", digest, size, prefix, stat_identity)
    return RuleInventoryEntry(relative_path, absolute_path, data, hashlib.sha256(data).hexdigest(), size,
                              stat_identity=stat_identity)


def classification_prefix(data: bytes, max_rule_bytes: int = MAX_RULE_BYTES) -> Optional[bytes]:
    """Complete bounded metadata, or empty headerless text, from captured UTF-8.

    An incomplete final codepoint is expected at the capture boundary. Invalid
    captured bytes still fail classification; bytes beyond capture are irrelevant.
    """
    data = data[:max_rule_bytes + 1]
    decoder = codecs.getincrementaldecoder("utf-8-sig")()
    try:
        text = decoder.decode(data[:max_rule_bytes], final=False)
        end = min(len(data), max_rule_bytes) - len(decoder.getstate()[0])
        status, _, body = split_frontmatter(text)
        if status == "unterminated":
            return None
        if status == "ok":
            if not body.startswith("\n") and end < len(data):
                return None
            end -= len(body.encode("utf-8")) - int(body.startswith("\n"))
        else:
            end = 0
        decoder.decode(data[max_rule_bytes:], final=False)
    except UnicodeError:
        return None
    return data[:end]


@dataclass(frozen=True)
class RuleInventory:
    """Stable entries and their aggregate content fingerprint."""

    entries: Tuple[RuleInventoryEntry, ...]
    fingerprint: str


class RuleInventoryError(RuntimeError):
    """The rule tree could not be inventoried safely and consistently."""

    def __init__(
        self,
        operation: str,
        path: str,
        message: str,
        cause: Optional[BaseException] = None,
        *, code: Optional[str] = None,
    ) -> None:
        self.operation = operation
        self.path = os.path.abspath(path)
        self.cause = cause
        self.code = code or "RULE_INVENTORY_ERROR"
        super().__init__(message if code else f"rule inventory {operation} failed for {self.path}: {message}")


class _RuleSizeLimitExceeded(ValueError):
    """A regular rule exceeds MAX_RULE_BYTES."""


def _stat_signature(info: os.stat_result) -> Tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        *file_generation(info.st_size, info.st_mtime_ns, info.st_ctime_ns),
    )


def _identity_signature(info: os.stat_result) -> Tuple[int, int, int]:
    """Identity fields used for ancestors whose unrelated contents may change."""
    return (info.st_dev, info.st_ino, info.st_mode)


def _stat_path(path: str, operation: str = "stat") -> os.stat_result:
    try:
        return os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise RuleInventoryError(operation, path, str(exc), exc) from exc


def _optional_stat(path: str) -> Optional[os.stat_result]:
    try:
        return os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RuleInventoryError("stat", path, str(exc), exc) from exc


def _require_directory(path: str, info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode):
        raise RuleInventoryError("validate", path, "symlinked directory is not allowed")
    if not stat.S_ISDIR(info.st_mode):
        raise RuleInventoryError("validate", path, "expected a directory")


def _read_stable_file(path: str, before: os.stat_result,
                      identities: Dict[str, Tuple[int, int, int]], root: str, listed: Collection[str],
                      *, relative_parts: Optional[Tuple[str, ...]] = None, direct: bool = False) -> bytes:
    if stat.S_ISLNK(before.st_mode):
        raise RuleInventoryError("validate", path, "symlinked .md rule is not allowed")
    if not stat.S_ISREG(before.st_mode):
        raise RuleInventoryError("validate", path, ".md rule is not a regular file")

    flags = os.O_RDONLY
    # Without O_BINARY, Windows opens in text mode: os.read() turns CRLF into
    # LF and stops at 0x1A, so the snapshot would not be the bytes on disk.
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    # The owner-selected root is trusted. Only descendants belong to the hostile
    # rule tree; opening ancestors separately would reject trusted aliases and
    # require read permission on otherwise traversable, execute-only parents.
    descendants = Path(os.path.relpath(path, root)).parts if relative_parts is None else relative_parts
    parts = (path,) if direct or not descriptor_supported() else (root, *descendants)
    # Traversal-only parents need search permission. Without O_PATH (including
    # macOS), these parents still require read permission; listed directories
    # always need it, so retain O_RDONLY there.
    directory_flags = (getattr(os, "O_DIRECTORY", 0)
                       | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    fd, parent, spelling = None, None, ""
    try:
        try:
            for index, part in enumerate(parts):
                leaf = index == len(parts) - 1
                spelling = os.path.join(spelling, part)
                mode = os.O_RDONLY if spelling in listed else getattr(os, "O_PATH", os.O_RDONLY)
                open_flags = flags if leaf else directory_flags | mode
                opened_fd = os.open(part, open_flags, dir_fd=parent)
                if leaf:
                    fd = opened_fd
                    break
                previous, parent = parent, opened_fd
                if previous is not None:
                    os.close(previous)
                if spelling in identities:
                    try:
                        info = os.fstat(parent)
                    except OSError as exc:
                        raise RuleInventoryError("stat", path, "directory stat failed", exc) from exc
                    if _identity_signature(info) != identities[spelling]:
                        raise RuleInventoryError("read", path, "ancestor changed before file open")
        except OSError as exc:
            raise RuleInventoryError("open", path, str(exc), exc) from exc
        try:
            opened = os.fstat(fd)
        except OSError as exc:
            raise RuleInventoryError("stat", path, str(exc), exc) from exc
        if _stat_signature(opened) != _stat_signature(before):
            raise RuleInventoryError("read", path, "file changed before it was opened")

        chunks = []  # type: List[bytes]
        remaining = MAX_RULE_BYTES + 1
        while remaining:
            try:
                chunk = os.read(fd, min(65536, remaining))
            except OSError as exc:
                raise RuleInventoryError("read", path, str(exc), exc) from exc
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)

        try:
            after_read = os.fstat(fd)
        except OSError as exc:
            raise RuleInventoryError("stat", path, str(exc), exc) from exc
        if _stat_signature(after_read) != _stat_signature(opened):
            raise RuleInventoryError("read", path, "file changed while it was read")
    finally:
        try:
            if fd is not None:
                os.close(fd)
        except OSError:
            pass
        finally:
            if parent is not None:
                try:
                    os.close(parent)
                except OSError as exc:
                    raise RuleInventoryError("read", path, "directory close failed", exc) from exc

    after_path = _stat_path(path)
    if _stat_signature(after_path) != _stat_signature(before):
        raise RuleInventoryError("read", path, "file changed during inventory")
    data = b"".join(chunks)
    if len(data) != min(before.st_size, MAX_RULE_BYTES + 1):
        raise RuleInventoryError("read", path, "file size disagrees with captured bytes")
    return data


def fingerprint(entries: Iterable[RuleInventoryEntry]) -> str:
    """The aggregate fingerprint of ``entries``, in their order: the one definition for a working-tree
    inventory and a commit's (aegis_core.rule_integrity), so equal rules always compare equal."""
    aggregate = hashlib.sha256(b"aegis-rule-inventory-v1\0")
    for entry in entries:
        aggregate.update(entry.relative_path.encode("utf-8") + b"\0" + bytes.fromhex(entry.digest) + b"\0")
    return aggregate.hexdigest()


def _empty_inventory() -> RuleInventory:
    return RuleInventory(entries=(), fingerprint=fingerprint(()))


def _original_rule_parts(path: str, root: str) -> Tuple[str, ...]:
    """Check the anchor lexically, preserving zero-depth dots in descendants."""
    Path(path).relative_to(root)
    _drive, tail = os.path.splitdrive(path)
    parts = tuple(part for part in re.split(r"[\\/]" if os.path.altsep else "/", tail) if part)
    remaining, index = len(Path(root).parts) - 1, 0
    while remaining:
        if parts[index] != ".":
            remaining -= 1
        index += 1
    return parts[index:]


def _rule_read_location(path, root, canonicalize_parent):
    """Retain original rooted components or an opaque adapter's exact result."""
    if root is None and not canonicalize_parent:
        return str(path), None, (os.path.basename(path),)
    absolute = os.path.join(os.path.abspath("."), path)
    if root is None:
        anchor = os.path.realpath(os.path.dirname(absolute))
        absolute = os.path.join(anchor, os.path.basename(absolute))
    else:
        anchor = os.path.abspath(root)
    return absolute, anchor, _original_rule_parts(absolute, anchor)


def read_rule_file(path: str | Path, *, root: str | Path | None = None,
                   missing_ok: bool = False, error_type=RuleInventoryError,
                   preserve_os_errors: bool = False, source: str | Path | None = None,
                   canonicalize_parent: bool = True) -> Optional[bytes]:
    """Capture one regular rule using the inventory reader, refusing above its cap.

    With ``root``, the workspace is trusted and original descendant components
    are walked without following symlinks, including components before '..'.
    Descendant directories must be readable, as for inventory listing; a refusal
    keeps its legacy PermissionError when requested. Ancestors above the trusted
    root are not opened separately and may need only search permission.
    Without ``root``, the caller trusts the path up to its parent: canonicalize
    that parent, then open the canonical file directly in one call, never opening
    a directory. With ``canonicalize_parent=False``, an opaque adapter owns
    containment and resolution: open exactly its returned path once, without
    canonicalizing or rebuilding it, or separately inspecting its parent.
    The final component is never resolved or followed; descriptor regular-file,
    byte-cap and identity checks apply in both modes.
    Refusal messages are fixed, with separate advice for files above the cap.
    RULE_FILE_NOT_FOUND distinguishes absence from RULE_FILE_READ_REFUSED.
    OS failures remain available as ``cause``; legacy boundaries opt into raising
    them with ``preserve_os_errors``. ``source`` must identify the captured file
    both before and after reading, before a caller records it as provenance.
    The inventory's non-descriptor fallback is retained on unsupported platforms.
    """
    try:
        values = (path, *(value for value in (root, source) if value is not None))
        for value in values:
            if not isinstance(value, (str, Path)) or not 1 <= len(str(value)) <= 32768 or "\x00" in str(value):
                raise ValueError("invalid rule path")
        absolute, anchor, relative_parts = _rule_read_location(path, root, canonicalize_parent)
        if not relative_parts:
            raise ValueError("rule path is a directory")
        identities = {}
        spelling, depth = anchor, 0
        for component in (None, *relative_parts[:-1]) if anchor is not None else ():
            if component is not None:
                depth += 0 if component == "." else -1 if component == ".." else 1
                if depth < 0:
                    raise ValueError("rule path escapes root")
                spelling = os.path.join(spelling, component)
            info = _stat_path(spelling)
            _require_directory(spelling, info)
            identities[spelling] = _identity_signature(info)
        if relative_parts[-1] in (".", ".."):
            raise ValueError("rule path is a directory")
        before = _stat_path(absolute)
        if stat.S_ISREG(before.st_mode) and before.st_size > MAX_RULE_BYTES:
            raise _RuleSizeLimitExceeded
        if source is not None and _stat_signature(_stat_path(str(source))) != _stat_signature(before):
            raise ValueError("rule source differs from captured file")
        root_identity = identities.get(anchor)
        listed = {name for name, identity in identities.items() if identity != root_identity}
        data = _read_stable_file(absolute, before, identities, anchor or ".", listed,
                                 relative_parts=relative_parts, direct=root is None)
        if len(data) > MAX_RULE_BYTES:
            raise _RuleSizeLimitExceeded
        for parent, expected in identities.items():
            if _identity_signature(_stat_path(parent)) != expected:
                raise ValueError("rule ancestor changed")
        if source is not None and _stat_signature(_stat_path(str(source))) != _stat_signature(before):
            raise ValueError("rule source changed during capture")
        return data
    except (RuleInventoryError, OSError, ValueError) as exc:
        cause = exc.cause if isinstance(exc, RuleInventoryError) else exc
        missing = isinstance(cause, FileNotFoundError)
        if missing and missing_ok:
            return None
        code = "RULE_FILE_NOT_FOUND" if missing else "RULE_FILE_READ_REFUSED"
        os_cause = cause if isinstance(cause, OSError) and cause.errno not in (errno.ELOOP, errno.ENOTDIR) else None
        if preserve_os_errors and os_cause is not None and not missing:
            if os_cause.filename is not None:
                os_cause.filename = str(path)
            raise os_cause from None
        message = (f"Rule file exceeds the {MAX_RULE_BYTES}-byte size limit"
                   if isinstance(exc, _RuleSizeLimitExceeded) else "Rule file read refused")
        if error_type is RuleInventoryError:
            raise RuleInventoryError("read", ".", message, os_cause, code=code) from None
        raise error_type(message, code=code) from None


def inventory_rules(workspace: str) -> RuleInventory:
    """Capture every ``.md`` below ``.aegis/rules`` without following links.

    Ordinary content and fingerprints retain their byte-for-byte definition.
    Oversized files retain only a bounded prefix and actual size; their digest
    is domain-separated from full-file digests. Each read is capped before
    allocation. Metadata before/after capture detects concurrent changes.
    """
    from aegis_core.primitives import real_path

    workspace_abs = real_path(os.path.abspath(os.fspath(workspace)))
    layout = WorkspaceLayout(Path(workspace_abs))
    parent_dir = str(layout.aegis_dir)
    rules_root = str(layout.rules_dir)

    workspace_info = _optional_stat(workspace_abs)
    if workspace_info is None:
        return _empty_inventory()
    _require_directory(workspace_abs, workspace_info)

    parent_info = _optional_stat(parent_dir)
    if parent_info is None:
        return _empty_inventory()
    _require_directory(parent_dir, parent_info)

    rules_info = _optional_stat(rules_root)
    if rules_info is None:
        return _empty_inventory()
    _require_directory(rules_root, rules_info)

    ancestor_identities = {
        workspace_abs: _identity_signature(workspace_info),
        parent_dir: _identity_signature(parent_info),
    }
    directory_signatures = {}  # type: dict[str, Tuple[int, int, int, int, int, int]]
    rule_paths = []  # type: List[str]

    def walk_error(exc: OSError) -> None:
        path = getattr(exc, "filename", None) or rules_root
        raise RuleInventoryError("list", path, str(exc), exc)

    # os.walk's defaults: top down, so each directory's children are validated (a
    # symlinked one raises) before any is entered, and links are never followed. A
    # listing error reaches walk_error; nothing else in the loop raises OSError.
    for dirpath, dirnames, filenames in os.walk(rules_root, onerror=walk_error):
        dir_info = _stat_path(dirpath)
        _require_directory(dirpath, dir_info)
        directory_signatures[dirpath] = _stat_signature(dir_info)

        dirnames.sort()
        for dirname in dirnames:
            child = os.path.join(dirpath, dirname)
            child_info = _stat_path(child)
            if stat.S_ISLNK(child_info.st_mode):
                raise RuleInventoryError(
                    "validate", child, "symlinked directory is not allowed"
                )
            if not stat.S_ISDIR(child_info.st_mode):
                raise RuleInventoryError("validate", child, "expected a directory")

        for filename in sorted(filenames):
            # Any case of the extension: the loader reports a rule named x.MD instead
            # of letting it go unseen.
            if filename.lower().endswith(".md"):
                rule_paths.append(os.path.join(dirpath, filename))

    entries = []  # type: List[RuleInventoryEntry]
    directory_identities = {**ancestor_identities, **{path: info[:3] for path, info in directory_signatures.items()}}
    for path in sorted(rule_paths):
        before = _stat_path(path)
        content = _read_stable_file(path, before, directory_identities, workspace_abs, directory_signatures)
        relative = os.path.relpath(path, workspace_abs).replace(os.sep, "/")
        entries.append(captured_entry(
            relative_path=relative,
            absolute_path=os.path.abspath(path),
            data=content,
            size=before.st_size,
            stat_identity=_stat_signature(before),
        ))

    for path, expected in ancestor_identities.items():
        current = _stat_path(path)
        if _identity_signature(current) != expected:
            raise RuleInventoryError("list", path, "ancestor changed during inventory")
    for path, expected in directory_signatures.items():
        current = _stat_path(path)
        if _stat_signature(current) != expected:
            raise RuleInventoryError("list", path, "directory changed during inventory")

    return RuleInventory(entries=tuple(entries), fingerprint=fingerprint(entries))


__all__ = [
    "MAX_RULE_BYTES",
    "RuleInventory",
    "RuleInventoryEntry",
    "RuleInventoryError",
    "captured_entry",
    "classification_prefix",
    "fingerprint",
    "inventory_rules",
    "read_rule_file",
    "split_frontmatter",
]
