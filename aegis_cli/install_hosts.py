"""The host plane writers behind `aegis init` and `aegis uninstall` (host-matrix spec §3.2-3.4).

Everything here edits a file the user owns, so every writer follows one contract: it
never writes through a symlink (it refuses instead), it refuses input it cannot parse
instead of repairing or replacing it, it writes atomically, it re-reads the file just
before replacing it and refuses if the file changed meanwhile, and on any refusal the
bytes on disk are left as they were. ``dry_run`` runs every check and writes nothing.

**Managed blocks** (AGENTS.md bootstrap, CLAUDE.md ``@AGENTS.md`` shim)::

    <!-- aegis:begin id=<id> v=1 sha=<12 hex> -->
    ...text Aegis owns...
    <!-- aegis:end id=<id> -->

``sha`` is the first 12 hex digits of the sha256 of the text between the markers with
line endings normalized to LF, so a CRLF checkout is not mistaken for a hand edit. A
writer touches only blocks of its own id; it refuses a block whose text no longer
matches its sha (a hand edit) unless forced, and a file with malformed markers of its
id. The block takes the file's line ending, and the bytes around it are kept as they
are (BOM included).

**MCP registration** uses each host's row in :mod:`aegis_core.hosts`: a native CLI
(``codex mcp add``, ``claude mcp add --scope user``) run as an argv with no shell, or a
JSON merge into the host's config file (Antigravity's ``~/.gemini/config/mcp_config.json``,
Kiro's ``~/.kiro/settings/mcp.json``, and the other experimental rows' files: Cursor's
``~/.cursor/mcp.json``, Copilot's ``~/.copilot/mcp-config.json``, Windsurf's
``~/.codeium/windsurf/mcp_config.json``), whose previous bytes are first copied, owner-only,
to ``~/.aegis/backups/<UTC stamp>/``.
A host whose row is unverified (aegis_core.hosts: experimental) is warned about by
`aegis init`, and each real run that selects it appends an ``init_host`` event to the events
log (:func:`record_init_host`); a metric never fails the run.
Host CLIs and ``aegis-mcp`` are looked up only in absolute ``PATH`` entries, never in
the current directory (the repository being set up). A host CLI is run by the path found
there, not the file a link there points to: version managers (Volta, mise, asdf) install
it as a link to one dispatcher that picks the tool from the name it is run under.
The server is always registered as ``aegis``, with an absolute command and the env
``AEGIS_CLIENT=<host id>`` (plus ``AEGIS_WORKSPACE`` only for an explicit pin).
Unregistering removes ``aegis`` and the legacy ``soma`` entry and nothing else.

**The workspace registry**, ``~/.aegis/workspaces.json`` (ADR 0005 AD-4)::

    {"v": 1,
     "workspaces": [{"root": "/abs/path/to/repo",
                     "added_at": "2026-10-15T12:00:00Z",
                     "added_by": "aegis init",
                     "hosts": ["codex-cli", "antigravity"]}]}

- Ownership: `aegis init` and `aegis uninstall` are its only writers. The MCP server
  and `aegis doctor` only read it. Unknown top-level keys and unknown entry keys are
  kept as they are.
- Membership: a workspace is registered when an entry's ``root`` is its absolute,
  resolved directory; roots are compared after resolving links (and case-folding on
  Windows), so one directory has at most one entry. A tool call's file paths may only
  *select among* registered roots; they never add one. ``$HOME`` and the filesystem
  root are never registered.
- ``hosts`` lists the hosts `aegis init` registered for that workspace on this machine,
  in host-table order. `aegis uninstall` unregisters a host only when no other
  registered workspace still lists it, unless the host is named with ``--host``.
- ``v`` is the schema version. A reader that finds another version refuses the file
  instead of guessing.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from aegis_core import hosts as host_table
from aegis_core.config import ENV_CLIENT, ENV_WORKSPACE
from aegis_core.pathlookup import which
from aegis_core.primitives import real_key
from aegis_core.storage import atomic_write_bytes
from aegis_core.workspace.layout import AEGIS_DIRNAME, UserLayout

__all__ = [
    "BLOCK_VERSION",
    "HostAction",
    "InstallError",
    "LEGACY_SERVER_NAME",
    "REGISTRY_LABEL",
    "REGISTRY_VERSION",
    "backup_dir",
    "SERVER_NAME",
    "detect_hosts",
    "detection_evidence",
    "find_workspace",
    "display_command",
    "has_block_marker",
    "is_denied_root",
    "launch_risk",
    "mcp_command",
    "mcp_entry",
    "ordered_hosts",
    "merge_mcp_json",
    "parse_hosts",
    "plane_evidence",
    "read_registry",
    "record_init_host",
    "register_argv",
    "register_host",
    "register_workspace",
    "registrable_hosts",
    "remove_managed_block",
    "remove_mcp_json",
    "unregister_argv",
    "unregister_host",
    "unregister_workspace",
    "workspace_hosts",
    "write_managed_block",
]

SERVER_NAME = "aegis"
# How output names the registry file (the path itself comes from UserLayout).
REGISTRY_LABEL = f"~/{AEGIS_DIRNAME}/workspaces.json"
LEGACY_SERVER_NAME = "soma"
BLOCK_VERSION = 1
REGISTRY_VERSION = 1
CLI_TIMEOUT_SECONDS = 60


class InstallError(Exception):
    """A user-owned file cannot be changed safely; nothing was written to it."""


# ── Safe file access ─────────────────────────────────────────────────────────

def _lstat(path: Path) -> Optional[os.stat_result]:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InstallError(f"{path}: cannot be read ({exc.strerror or exc}); left unchanged") from exc


def _check_target(path: Path, *, allow_hard_links: bool = False) -> Optional[os.stat_result]:
    """The lstat of ``path`` when it is a regular file we may replace, None when missing."""
    st = _lstat(path)
    if st is None:
        return None
    if stat.S_ISLNK(st.st_mode):
        raise InstallError(
            f"{path}: is a symlink; Aegis never writes through a link (it could point anywhere). "
            "Replace it with a regular file, then re-run.")
    if not stat.S_ISREG(st.st_mode):
        raise InstallError(f"{path}: is not a regular file; left unchanged")
    if st.st_nlink > 1 and not allow_hard_links:
        raise InstallError(
            f"{path}: has another hard link; replacing it would silently split the link. "
            "Make it a single file, then re-run.")
    return st


def _read(path: Path) -> Optional[bytes]:
    """Bytes of the regular file at ``path`` (None when missing); refuses links and specials."""
    if _check_target(path) is None:
        return None
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise InstallError(f"{path}: cannot be read ({exc.strerror or exc}); left unchanged") from exc


def _is_read_only(path: Path) -> bool:
    # os.replace swaps a file regardless of its own mode, so the read-only bit is honored
    # explicitly; root passes every os.access test, hence the mode bits too.
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return not (mode & 0o222) or not os.access(path, os.W_OK)


def _writable_dir(path: Path, *, creating: bool) -> None:
    """Refuse when the directory that holds (or will hold) ``path`` cannot take a new file:
    the atomic write creates its temporary file there, and a missing directory is made
    under the nearest one that exists."""
    parent = path.parent
    while not os.path.lexists(parent) and parent.parent != parent:
        parent = parent.parent
    if not parent.is_dir() or not os.access(parent, os.W_OK | os.X_OK):
        raise InstallError(f"{path}: cannot be {'created' if creating else 'replaced'} ({parent} is not a "
                           "writable directory); left unchanged")


def _preflight(path: Path, expected: Optional[bytes]) -> None:
    """Every check a write of ``path`` makes before it changes a byte. A dry run (init's
    check pass) runs exactly these, so whatever the write would refuse is refused first."""
    if _check_target(path) is not None and _is_read_only(path):
        raise InstallError(f"{path}: is read-only; left unchanged. Make it writable, then re-run.")
    _writable_dir(path, creating=expected is None)
    if _read(path) != expected:
        raise InstallError(f"{path}: changed while Aegis was updating it; left unchanged. Re-run.")


def _replace(path: Path, expected: Optional[bytes], data: bytes, *, dry_run: bool = False) -> None:
    """Atomically write ``data`` if ``path`` still holds ``expected`` (None: still missing);
    with ``dry_run`` only check that it could."""
    _preflight(path, expected)
    if dry_run:
        return
    try:
        atomic_write_bytes(path, data, follow_links=False)
    except OSError as exc:
        raise InstallError(f"{path}: cannot be written ({exc.strerror or exc}); left unchanged") from exc


def _decode(path: Path, data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InstallError(f"{path}: is not UTF-8 text ({exc.reason}); left unchanged") from exc


# ── Managed blocks ───────────────────────────────────────────────────────────

_MARKER = re.compile(r"^<!-- aegis:(begin|end)\b(.*?)-->[ \t]*$")
_BEGIN_FIELDS = re.compile(r"^ id=(\S+) v=(\S+) sha=(\S+) $")
_END_FIELDS = re.compile(r"^ id=(\S+) $")
_HEX12 = re.compile(r"^[0-9a-f]{12}$")
_BLOCK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _digest(body: str) -> str:
    return hashlib.sha256(body.replace("\r\n", "\n").encode("utf-8")).hexdigest()[:12]


def _render(block_id: str, text: str, eol: str) -> List[str]:
    body = text if text.endswith("\n") else text + "\n"
    body_lines = [line + eol for line in body[:-1].split("\n")]
    return ([f"<!-- aegis:begin id={block_id} v={BLOCK_VERSION} sha={_digest(body)} -->{eol}"]
            + body_lines + [f"<!-- aegis:end id={block_id} -->{eol}"])


@dataclass(frozen=True)
class _Block:
    begin: int  # line index of the begin marker
    end: int    # line index of the end marker
    sha: str
    body: str   # text between the markers, as it is in the file


def _find_block(path: Path, lines: List[str], block_id: str) -> Optional[_Block]:
    """The one block of ``block_id`` in ``lines``; refuses malformed or repeated markers."""
    found: List[_Block] = []
    open_at: Optional[Tuple[int, str]] = None
    for index, line in enumerate(lines):
        match = _MARKER.match(line.rstrip("\r\n"))
        if not match:
            continue
        kind, fields = match.groups()
        if kind == "begin":
            parsed = _BEGIN_FIELDS.match(fields)
            if not parsed or parsed.group(1) != block_id:
                if f"id={block_id} " in fields + " ":
                    raise InstallError(f"{path}: unrecognised Aegis marker for {block_id!r} on line "
                                       f"{index + 1}; left unchanged. Fix or remove it, then re-run.")
                continue
            version, sha = parsed.group(2), parsed.group(3)
            if version != str(BLOCK_VERSION) or not _HEX12.match(sha):
                raise InstallError(f"{path}: Aegis block {block_id!r} on line {index + 1} has an unknown "
                                   f"format (v={version}); left unchanged. A newer aegis may own it.")
            if open_at is not None:
                raise InstallError(f"{path}: Aegis block {block_id!r} opens twice (lines {open_at[0] + 1} "
                                   f"and {index + 1}); left unchanged")
            open_at = (index, sha)
        else:
            parsed = _END_FIELDS.match(fields)
            if not parsed or parsed.group(1) != block_id:
                continue
            if open_at is None:
                raise InstallError(f"{path}: Aegis block {block_id!r} closes on line {index + 1} without "
                                   "opening; left unchanged")
            begin, sha = open_at
            found.append(_Block(begin, index, sha, "".join(lines[begin + 1:index])))
            open_at = None
    if open_at is not None:
        raise InstallError(f"{path}: Aegis block {block_id!r} on line {open_at[0] + 1} never closes; "
                           "left unchanged")
    if len(found) > 1:
        raise InstallError(f"{path}: holds {len(found)} Aegis blocks {block_id!r}; left unchanged. "
                           "Keep one, then re-run.")
    return found[0] if found else None


def _hand_edited(path: Path, block: _Block, block_id: str, force: bool) -> None:
    if block.sha != _digest(block.body) and not force:
        raise InstallError(
            f"{path}: the Aegis block {block_id!r} was edited by hand; left unchanged. "
            "Move your text outside the block, or re-run with --force to replace it.")


def write_managed_block(path: Union[str, Path], block_id: str, text: str, *, force: bool = False,
                        create: bool = True, dry_run: bool = False) -> str:
    """Write ``text`` as the managed block ``block_id`` of ``path``; return what happened.

    ``created`` (new file), ``added`` (appended after the existing text, one blank line
    between), ``updated`` (the block replaced in place), ``unchanged`` or ``absent``
    (``create`` is False and there is no file). Raises InstallError on a symlink, a hard
    link, a non-regular or non-UTF-8 file, malformed markers of ``block_id``, or a
    hand-edited block (unless ``force``).
    """
    if not _BLOCK_ID.match(block_id):
        raise ValueError(f"invalid block id {block_id!r}")
    path = Path(path)
    raw = _read(path)
    if raw is None:
        if not create:
            return "absent"
        _replace(path, None, "".join(_render(block_id, text, "\n")).encode("utf-8"), dry_run=dry_run)
        return "created"
    content = _decode(path, raw)
    eol = "\r\n" if "\r\n" in content else "\n"
    lines = content.splitlines(True)
    block = _find_block(path, lines, block_id)
    new_block = _render(block_id, text, eol)
    if block is None:
        prefix = content
        if prefix.strip("﻿"):
            if not prefix.endswith("\n"):
                prefix += eol
            prefix += eol
        new_content, status = prefix + "".join(new_block), "added"
    else:
        _hand_edited(path, block, block_id, force)
        if "".join(lines[block.begin:block.end + 1]).replace("\r\n", "\n") == "".join(new_block).replace("\r\n", "\n"):
            return "unchanged"
        new_content = "".join(lines[:block.begin] + new_block + lines[block.end + 1:])
        status = "updated"
    _replace(path, raw, new_content.encode("utf-8"), dry_run=dry_run)
    return status


def remove_managed_block(path: Union[str, Path], block_id: str, *, force: bool = False,
                         dry_run: bool = False, delete_if_empty: bool = False) -> str:
    """Remove the managed block ``block_id`` and the blank line written before it.

    Returns ``removed``, ``deleted`` (nothing else was left and ``delete_if_empty``) or
    ``absent``. A hand-edited block is refused unless ``force``.
    """
    path = Path(path)
    raw = _read(path)
    if raw is None:
        return "absent"
    content = _decode(path, raw)
    lines = content.splitlines(True)
    block = _find_block(path, lines, block_id)
    if block is None:
        return "absent"
    _hand_edited(path, block, block_id, force)
    start = block.begin
    # The writer put one blank line between the user's text and the block.
    if start >= 2 and not lines[start - 1].strip("\r\n") and lines[start - 2].strip("\r\n﻿"):
        start -= 1
    remaining = "".join(lines[:start] + lines[block.end + 1:])
    if delete_if_empty and remaining == "":
        _preflight(path, raw)
        if not dry_run:
            try:
                path.unlink()
            except OSError as exc:
                raise InstallError(f"{path}: cannot be deleted ({exc.strerror or exc}); left unchanged") from exc
        return "deleted"
    _replace(path, raw, remaining.encode("utf-8"), dry_run=dry_run)
    return "removed"


def has_block_marker(path: Union[str, Path], block_id: str) -> bool:
    """Whether the file at ``path``, read through any link, has an Aegis marker of ``block_id``.

    Read only, for deciding what a link means: the writers above never follow one. A
    missing, unreadable or non-regular target has no marker.
    """
    try:
        if not os.path.isfile(path):
            return False
        with open(path, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
    except OSError:
        return False
    for line in text.splitlines():
        match = _MARKER.match(line)
        if match and f"id={block_id} " in match.group(2) + " ":
            return True
    return False


# ── JSON configs ─────────────────────────────────────────────────────────────

def _reject_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    seen: Dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r}")
        seen[key] = value
    return seen


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def _load_json_object(path: Path) -> Tuple[Optional[bytes], Dict[str, Any]]:
    """(raw bytes or None, the JSON object in ``path``); refuses anything it cannot round-trip."""
    raw = _read(path)
    if raw is None:
        return None, {}
    if raw.startswith(b"\xef\xbb\xbf"):
        raise InstallError(f"{path}: starts with a UTF-8 BOM; left unchanged. Save it without the BOM, then re-run.")
    text = _decode(path, raw)
    if not text.strip():
        return raw, {}
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise InstallError(
            f"{path}: is not valid JSON ({exc.msg} at line {exc.lineno} column {exc.colno}); left unchanged. "
            "Comments and trailing commas are not supported: fix the file or move it aside, then re-run."
        ) from exc
    except (ValueError, RecursionError) as exc:
        message = str(exc)
        if "duplicate key" not in message:
            message = f"is not valid JSON ({message})"
        raise InstallError(f"{path}: {message}; left unchanged. Fix the file, then re-run.") from exc
    if not isinstance(data, dict):
        raise InstallError(f"{path}: must hold a JSON object; left unchanged")
    try:
        _dump(data)
    except UnicodeEncodeError as exc:
        # json.loads turns an escape such as "\ud800" into a lone surrogate, which no UTF-8
        # file can hold: writing the file back would fail after other files were written.
        raise InstallError(f"{path}: holds an unpaired surrogate escape "
                           f"({exc.object[exc.start:exc.end].encode('unicode_escape').decode()}) that cannot be "
                           "written back as UTF-8; left unchanged. Fix the file, then re-run.") from exc
    except ValueError as exc:
        # json.loads reads a number such as 1e999 as inf without calling parse_constant;
        # dumped, it would be the non-JSON literal Infinity.
        raise InstallError(f"{path}: holds a number too large for a float (such as 1e999), which "
                           "cannot be written back as JSON; left unchanged. Fix the file, then re-run.") from exc
    return raw, data


def _servers(path: Path, data: Dict[str, Any], key: str) -> Dict[str, Any]:
    servers = data.get(key)
    if servers is None:
        servers = data[key] = {}
    if not isinstance(servers, dict):
        raise InstallError(f"{path}: '{key}' must be a JSON object; left unchanged")
    return servers


def _dump(data: Dict[str, Any]) -> bytes:
    return (json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def _private_dirs(directory: Path) -> None:
    """Create ``directory`` and its missing parents owner-only (0700)."""
    missing = []
    while not os.path.lexists(directory) and directory.parent != directory:
        missing.append(directory)
        directory = directory.parent
    for path in reversed(missing):
        path.mkdir(mode=0o700, exist_ok=True)


def _rewrite_config(path: Path, raw: Optional[bytes], data: Dict[str, Any], backup_dir: Optional[Path],
                    dry_run: bool) -> None:
    """Replace a user's config, copying its current bytes into ``backup_dir`` first.

    The backup is written only once the replacement is known to be allowed, and owner-only
    (file 0600 in 0700 directories): it holds whatever secrets the config holds, such as
    other MCP servers' API keys.
    """
    payload = _dump(data)
    _preflight(path, raw)
    if raw is not None and backup_dir is not None:
        copy = Path(backup_dir) / path.name
        _writable_dir(copy, creating=True)
        if not dry_run:
            try:
                _private_dirs(Path(backup_dir))
                atomic_write_bytes(copy, raw, mode=0o600)
            except OSError as exc:
                raise InstallError(f"{path}: cannot back it up to {backup_dir} ({exc.strerror or exc}); "
                                   "left unchanged") from exc
    _replace(path, raw, payload, dry_run=dry_run)


def backup_dir(home: Union[str, Path]) -> Path:
    """A fresh ``~/.aegis/backups/<UTC stamp>/`` for the user configs one run rewrites."""
    layout = UserLayout(Path(home))
    if layout.aegis_dir.is_symlink():
        raise InstallError(f"{layout.aegis_dir}: is a symlink; Aegis keeps its user files only in a real "
                           "directory. Replace the link, then re-run.")
    return layout.backups_dir / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")


def merge_mcp_json(path: Union[str, Path], name: str, entry: Dict[str, Any], *, key: str = "mcpServers",
                   dry_run: bool = False, backup_dir: Optional[Path] = None) -> str:
    """Set ``key[name] = entry`` in the JSON file at ``path``, keeping everything else.

    Returns ``added``, ``updated`` or ``unchanged``. Raises InstallError for a symlink,
    a read-only file, invalid JSON (JSONC, trailing commas, NaN, duplicate keys), a BOM,
    or a non-object ``key``; the file is then left as it was.
    """
    path = Path(path)
    raw, data = _load_json_object(path)
    servers = _servers(path, data, key)
    if servers.get(name) == entry:
        return "unchanged"
    status = "updated" if name in servers else "added"
    servers[name] = entry
    _rewrite_config(path, raw, data, backup_dir, dry_run)
    return status


def remove_mcp_json(path: Union[str, Path], names: Sequence[str], *, key: str = "mcpServers",
                    dry_run: bool = False, backup_dir: Optional[Path] = None) -> str:
    """Delete ``names`` from ``key`` in the JSON file at ``path``; ``removed`` or ``absent``."""
    path = Path(path)
    raw, data = _load_json_object(path)
    if raw is None:
        return "absent"
    servers = _servers(path, data, key) if data.get(key) is not None else {}
    present = [n for n in names if n in servers]
    if not present:
        return "absent"
    for n in present:
        del servers[n]
    _rewrite_config(path, raw, data, backup_dir, dry_run)
    return "removed"


# ── Workspace registry ───────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stored_key(root: str) -> Optional[str]:
    """The key of a root read from the registry, or None for one the server's reader skips:
    a relative root would resolve against the current directory, and the server cannot
    resolve a NUL byte. Such an entry never matches (a None key equals nothing), and stays
    in the file as it is."""
    return real_key(root) if os.path.isabs(root) else None


def is_denied_root(root: Union[str, Path], home: Union[str, Path]) -> bool:
    """True for the home directory and a filesystem root: never a workspace (AD-4)."""
    key = real_key(root)  # one that cannot be resolved is never a workspace either
    return key is None or key == real_key(home) or os.path.dirname(key) == key


def _registry_file(home: Union[str, Path]) -> Path:
    layout = UserLayout(Path(home))
    if layout.aegis_dir.is_symlink():
        raise InstallError(f"{layout.aegis_dir}: is a symlink; Aegis keeps its user files only in a real "
                           "directory. Replace the link, then re-run.")
    return layout.workspaces_file


def _load_registry(path: Path) -> Tuple[Optional[bytes], Dict[str, Any]]:
    raw, data = _load_json_object(path)
    if raw is None or not data:
        return raw, {"v": REGISTRY_VERSION, "workspaces": []}
    if data.get("v") != REGISTRY_VERSION:
        raise InstallError(f"{path}: has schema version {data.get('v')!r}; this aegis reads version "
                           f"{REGISTRY_VERSION}. Left unchanged.")
    entries = data.get("workspaces")
    if not isinstance(entries, list):
        raise InstallError(f"{path}: 'workspaces' must be a list; left unchanged")
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("root"), str) or not entry["root"]:
            raise InstallError(f"{path}: every workspace needs a 'root' path; left unchanged")
    return raw, data


def read_registry(home: Union[str, Path]) -> Dict[str, Any]:
    """The registry document (``{"v": 1, "workspaces": []}`` when there is none)."""
    return _load_registry(_registry_file(home))[1]


def ordered_hosts(names: Sequence[str]) -> List[str]:
    """``names`` once each, in host-table order (unknown names last, sorted)."""
    known = [h.id for h in host_table.all_hosts()]
    unique = set(names)
    return [h for h in known if h in unique] + sorted(unique - set(known))


def record_init_host(root: Union[str, Path], hosts: Sequence[str]) -> None:
    """Append an ``init_host`` event for each of ``hosts`` whose row is unverified
    (experimental; aegis_core.hosts), in host-table order. A host the table does not know,
    a verified one and a host without a registration are skipped. A metric never fails
    `aegis init`: an event that cannot be written is reported on stderr and init goes on."""
    from aegis_core import events

    for name in ordered_hosts(hosts):
        try:
            spec = host_table.get(name)
        except KeyError:
            continue
        if spec.verified or spec.registration is None:
            continue
        detail = {"host": spec.id, "verified": False, "surfaces": list(spec.surfaces)}
        try:
            events.append(root, "init_host", "experimental", detail, host=spec.id)
        except Exception as exc:  # events.append documents what it raises; none of it may stop init
            print(f"aegis: the init_host event for {spec.id} could not be recorded ({type(exc).__name__}: {exc})",
                  file=sys.stderr)


def register_workspace(home: Union[str, Path], root: Union[str, Path], hosts: Sequence[str], *,
                       dry_run: bool = False, now: Optional[str] = None) -> str:
    """Add ``root`` (with ``hosts``) to the registry; ``added``, ``updated`` or ``unchanged``.

    This is `aegis init` recording the hosts it set up for ``root``, so a real run (not a
    dry run) also notes each experimental host among ``hosts`` in the events log
    (:func:`record_init_host`), whether or not the registry entry changed."""
    status = _update_registry(home, root, hosts, dry_run=dry_run, now=now)
    if not dry_run:
        record_init_host(root, hosts)
    return status


def _update_registry(home: Union[str, Path], root: Union[str, Path], hosts: Sequence[str], *,
                     dry_run: bool, now: Optional[str]) -> str:
    path = _registry_file(home)
    raw, data = _load_registry(path)
    key = real_key(root)
    if key is None:
        raise InstallError(f"{root}: cannot be resolved, so it cannot be registered; left unchanged")
    entries = data["workspaces"]
    entry = next((e for e in entries if _stored_key(e["root"]) == key), None)
    if entry is None:
        entries.append({"root": os.path.realpath(os.fspath(root)), "added_at": now or _utc_now(),
                        "added_by": "aegis init", "hosts": ordered_hosts(hosts)})
        status = "added"
    else:
        current = entry.get("hosts") if isinstance(entry.get("hosts"), list) else []
        merged = ordered_hosts([h for h in current if isinstance(h, str)] + list(hosts))
        if merged == current:
            return "unchanged"
        entry["hosts"] = merged
        status = "updated"
    _replace(path, raw, _dump({"v": data.pop("v"), **data}), dry_run=dry_run)
    return status


def unregister_workspace(home: Union[str, Path], root: Union[str, Path], *,
                         dry_run: bool = False) -> Tuple[str, List[Dict[str, Any]]]:
    """Remove ``root`` from the registry; (``removed`` or ``absent``, the remaining entries)."""
    path = _registry_file(home)
    raw, data = _load_registry(path)
    key = real_key(root)
    remaining = [e for e in data["workspaces"] if key is None or _stored_key(e["root"]) != key]
    if len(remaining) == len(data["workspaces"]):
        return "absent", remaining
    data["workspaces"] = remaining
    _replace(path, raw, _dump(data), dry_run=dry_run)
    return "removed", remaining


def workspace_hosts(entry: Optional[Dict[str, Any]]) -> List[str]:
    hosts = entry.get("hosts") if entry else None
    return [h for h in hosts if isinstance(h, str)] if isinstance(hosts, list) else []


def find_workspace(registry: Dict[str, Any], root: Union[str, Path]) -> Optional[Dict[str, Any]]:
    key = real_key(root)
    return next((e for e in registry.get("workspaces", []) if key is not None and _stored_key(e["root"]) == key), None)


# ── Hosts ────────────────────────────────────────────────────────────────────

def _never_registered(host: host_table.HostSpec) -> str:
    """Why Aegis never registers ``host`` (retired, or identity only), or '' if it may."""
    if host.retired:
        return host.retired
    if host.registration is None:
        why = f"{host.id} is identity only: Aegis does not register there (ADR 0005 H4)"
        return f"{why}; {host.redirect}" if host.redirect else why
    return ""


def registrable_hosts() -> Tuple[host_table.HostSpec, ...]:
    """Hosts `aegis init` can register in this phase (they have a registration row)."""
    return tuple(h for h in host_table.all_hosts(phase=1) if h.registration is not None)


def _user_dir(home: Path, spec: str) -> Path:
    return home / spec[2:] if spec.startswith("~/") else Path(spec)


def plane_evidence(host: host_table.HostSpec, home: Union[str, Path], path: Optional[str] = None,
                   environ: Optional[Mapping[str, str]] = None, platform: Optional[str] = None) -> Optional[str]:
    """What shows ``host``'s config plane is on this machine, or None: its binary on PATH,
    one of its config paths (as the table writes it), or its desktop app (an IDE or a
    desktop app puts nothing on PATH). App bundles are directories; anything else there
    is not an app."""
    home = Path(home)
    for name in host.binaries:
        found = which(name, path)
        if found:
            return found
    for spec in host.config_paths:
        if os.path.exists(_user_dir(home, spec)):
            return spec
    environ = os.environ if environ is None else environ
    for app in host_table.app_paths(host, home, environ, sys.platform if platform is None else platform):
        if os.path.isdir(app):
            return app
    return None


def detection_evidence(home: Union[str, Path], path: Optional[str] = None,
                       environ: Optional[Mapping[str, str]] = None,
                       platform: Optional[str] = None) -> Dict[str, str]:
    """{host id: what found it} for every host `aegis init` can register, in table order."""
    found = {}
    for host in registrable_hosts():
        evidence = plane_evidence(host, home, path, environ, platform)
        if evidence is not None:
            found[host.id] = evidence
    return found


def detect_hosts(home: Union[str, Path], path: Optional[str] = None,
                 environ: Optional[Mapping[str, str]] = None, platform: Optional[str] = None) -> List[str]:
    """Hosts that look installed (a binary on PATH, a config path or a desktop app); a proposal only."""
    return list(detection_evidence(home, path, environ, platform))


def parse_hosts(value: str) -> Union[str, List[str]]:
    """``auto``, or the plane ids of the comma-separated host ids and surface aliases
    (``codex-app`` is ``codex-cli``), once each in host-table order; ValueError otherwise."""
    names = [v.strip() for v in value.split(",") if v.strip()]
    if not names:
        raise ValueError("no host given; use --host auto or a comma-separated list of host ids")
    if "auto" in names:
        if names != ["auto"]:
            raise ValueError("'auto' cannot be combined with host ids")
        return "auto"
    registrable = {h.id for h in registrable_hosts()}
    planes = []
    for name in names:
        try:
            spec = host_table.get(host_table.resolve(name))
        except KeyError as exc:
            aliases = sorted(a for h in registrable_hosts() for a in h.aliases)
            raise ValueError(f"unknown host {name!r}; hosts: {', '.join(sorted(registrable))} "
                             f"(or a surface: {', '.join(aliases)})") from exc
        refusal = _never_registered(spec)
        if refusal:
            raise ValueError(refusal)
        if spec.id not in registrable:
            raise ValueError(f"{name}: Aegis does not register this host in this release; "
                             f"hosts now: {', '.join(sorted(registrable))}")
        planes.append(spec.id)
    return ordered_hosts(planes)


MCP_SCRIPT = "aegis-mcp"
# The last-resort launcher, shaped like the pre-commit hook's runner: -I keeps the
# directory the host starts the server in (the project, which a cloned repository
# controls), PYTHON* variables and user site-packages off sys.path; the one directory
# aegis_mcp was installed in comes in as sys.argv[1]. `python -m aegis_mcp` would import
# whatever aegis_mcp (or aegis_core) package sits in that start directory.
MCP_RUNNER = "import sys; sys.path.insert(0, sys.argv[1]); from aegis_mcp.server import main; main()"


def _mcp_import_root() -> str:
    """The directory aegis_cli was imported from: the wheel installs aegis_mcp beside it.
    Located through aegis_cli, never by looking aegis_mcp up on sys.path, where the
    current directory (a repository) can come first; aegis_cli does not import aegis_mcp
    (ADR 0005 AD-3)."""
    import aegis_cli

    return str(Path(aegis_cli.__file__).resolve().parent.parent)


def _installed_script(scripts_dirs: Optional[Sequence[str]]) -> Optional[str]:
    """The aegis-mcp console script pip installed with this interpreter, if any: the
    scheme's scripts directory (a venv's bin/, which pipx and unactivated venvs leave off
    PATH) or the user scheme's (pip --user), as ``aegis_cli.pathcheck`` finds them."""
    from aegis_cli import pathcheck

    dirs = pathcheck.default_candidates() if scripts_dirs is None else list(scripts_dirs)
    directory = pathcheck.scripts_dir(dirs, cmd_name=MCP_SCRIPT)
    if directory is None or not os.path.isabs(directory):
        return None
    for name in (MCP_SCRIPT + ".exe", MCP_SCRIPT) if os.name == "nt" else (MCP_SCRIPT,):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and (os.name == "nt" or os.access(candidate, os.X_OK)):
            return candidate
    return None


def mcp_command(path: Optional[str] = None, scripts_dirs: Optional[Sequence[str]] = None) -> List[str]:
    """The absolute command that starts the Aegis MCP server, in this order:

    1. the aegis-mcp found in an absolute PATH entry, under that name (not a link's
       target, which may be a dispatcher);
    2. the aegis-mcp script installed with this interpreter (``scripts_dirs``, default
       its sysconfig scripts directories, the user scheme's included);
    3. this interpreter in isolated mode (``-I -c``) importing aegis_mcp from the
       directory it is installed in.

    Never ``python -m aegis_mcp``: hosts start the server in the project directory, and
    ``-m`` imports from there first. ``launch_risk`` of the result is always None.
    """
    exe = which(MCP_SCRIPT, path)
    if exe:
        return [exe]
    script = _installed_script(scripts_dirs)
    if script:
        return [script]
    return [sys.executable, "-I", "-c", MCP_RUNNER, _mcp_import_root()]


# Interpreter options whose value follows them (attached or as the next argument).
_PY_VALUE_OPTIONS = "WX"
# python, python3, python3.12, python3.13t, pythonw, pypy3 and the Windows py launcher.
_PYTHON_NAME = re.compile(r"(?:python|pypy)(?:\d+(?:\.\d+)*)?[tw]?|pyw?")
# env options whose value is the next argument unless attached (GNU -u -C, BSD -P -L).
_ENV_VALUE_LETTERS = "uCPL"
_ENV_VALUE_LONG = ("--unset", "--chdir")
_ENV_SPLIT = "it runs env -S, whose command line Aegis does not parse"


def _program(path: str) -> str:
    name = os.path.basename(path).lower()
    return name[:-4] if name.endswith(".exe") else name


def _through_env(args: Sequence[str]) -> Optional[str]:
    """launch_risk of the command ``env`` runs, after its options and NAME=VALUE pairs."""
    rest = list(args)
    while rest:
        arg = rest[0]
        if arg == "--":
            rest = rest[1:]
            break
        if arg.startswith("--"):
            name = arg.split("=", 1)[0]
            if name == "--split-string":
                return _ENV_SPLIT
            rest = rest[2:] if name in _ENV_VALUE_LONG and "=" not in arg else rest[1:]
            continue
        if arg.startswith("-"):
            skip = 1
            for at, letter in enumerate(arg[1:]):
                if letter == "S":
                    return _ENV_SPLIT
                if letter in _ENV_VALUE_LETTERS:
                    skip += at == len(arg) - 2  # the value is the next argument
                    break
            rest = rest[skip:]
            continue
        if "=" not in arg:
            break
        rest = rest[1:]
    risk = launch_risk(rest)
    return f"through env: {risk}" if risk else None


def _script_risk(script: str, python: bool) -> Optional[str]:
    if python and script and not os.path.isabs(script):
        return f"it runs the script {script}, a path relative to the directory the host starts it in"
    return None  # an absolute script, or a non-interpreter's arguments


def launch_risk(argv: Sequence[str]) -> Optional[str]:
    """Why ``argv`` could run code from the directory a host starts it in, or None.

    A command that is not an absolute path resolves against that directory or a PATH
    Aegis cannot see. For a Python interpreter, ``-m``, ``-c`` and a program read from
    stdin (``-``) without ``-I`` (or ``-P``) put that directory first on sys.path, so a
    repository holding an ``aegis_mcp`` package runs its own code; and a script named by
    a relative path is a file in that directory. ``env`` is judged by the command it runs.
    """
    if not argv or not os.path.isabs(argv[0]):
        return "the command is not an absolute path"
    program = _program(argv[0])
    if program == "env":
        return _through_env(argv[1:])
    python = _PYTHON_NAME.fullmatch(program) is not None
    flags = set()
    rest = iter(argv[1:])
    for arg in rest:
        if arg == "--":
            return _script_risk(next(rest, ""), python)
        if arg.startswith("--"):
            if arg == "--check-hash-based-pycs":
                next(rest, None)
            continue
        isolated = "I" in flags or "P" in flags
        if arg == "-":
            return None if isolated else (
                "it reads its program from stdin without -I, which imports from the directory the host starts it in")
        if not arg.startswith("-"):
            return _script_risk(arg, python)
        body = arg[1:]
        for at, letter in enumerate(body):
            if letter in ("m", "c"):
                if "I" in flags or "P" in flags:
                    return None
                what = "the module " if letter == "m" else ""
                return f"it runs -{letter} without -I, which imports {what}from the directory the host starts it in"
            if letter in _PY_VALUE_OPTIONS:
                if at == len(body) - 1:
                    next(rest, None)
                break
            flags.add(letter)
    return None


def _env(host_id: str, pin: Optional[str]) -> Dict[str, str]:
    env = {ENV_CLIENT: host_id}
    if pin:
        env[ENV_WORKSPACE] = pin
    return env


def mcp_entry(host_id: str, command: Sequence[str], pin: Optional[str] = None) -> Dict[str, Any]:
    """The JSON server entry for a ``json_file`` host."""
    return {"command": command[0], "args": list(command[1:]), "env": _env(host_id, pin)}


def register_argv(host: host_table.HostSpec, command: Sequence[str], pin: Optional[str] = None) -> List[str]:
    """The host's native registration argv with the command spliced in (and the pin env)."""
    argv = list(host.registration.argv)  # type: ignore[union-attr]
    at = argv.index("{command}")
    argv[at:at + 1] = list(command)
    if pin:
        client = next(i for i, a in enumerate(argv) if a.startswith(f"{ENV_CLIENT}="))
        argv[client + 1:client + 1] = [argv[client - 1], f"{ENV_WORKSPACE}={pin}"]
    return argv


def unregister_argv(host: host_table.HostSpec, name: str = SERVER_NAME) -> List[str]:
    """The host's native removal argv (``... mcp remove [scope] <name>``)."""
    template = list(host.registration.argv)  # type: ignore[union-attr]
    head = template[:template.index(SERVER_NAME)]
    return ["remove" if a == "add" else a for a in head] + [name]


def display_command(argv: Sequence[str]) -> str:
    """``argv`` as one line to paste into this platform's shell."""
    if os.name == "nt":
        return subprocess.list2cmdline(list(argv))
    import shlex
    return " ".join(shlex.quote(a) for a in argv)


def _run_cli(argv: List[str]) -> "subprocess.CompletedProcess[str]":
    """Run a host CLI: no shell, no stdin, a neutral cwd (a repository's own host config
    must not redirect a user-scope registration), bounded time."""
    with tempfile.TemporaryDirectory(prefix="aegis-host-") as cwd:
        return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, encoding="utf-8",
                              errors="replace", timeout=CLI_TIMEOUT_SECONDS, cwd=cwd, check=False)


@dataclass(frozen=True)
class HostAction:
    """What registering or unregistering one host did.

    ``result``: registered, unchanged, would_run, manual (the host CLI is not installed;
    ``command`` is what the user should run), failed, removed or absent.
    """

    host: str
    result: str
    command: Optional[List[str]] = None
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"host": self.host, "result": self.result, "command": self.command, "detail": self.detail}


def _call(argv: List[str]) -> Tuple[int, str]:
    try:
        proc = _run_cli(argv)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)
    tail = (proc.stderr or proc.stdout or "").strip().splitlines()
    return proc.returncode, tail[-1] if tail else ""


def _native(host: host_table.HostSpec, steps: List[List[str]], path: Optional[str], dry_run: bool,
            done: str) -> HostAction:
    binary = which(steps[-1][0], path)
    if binary is None:
        return HostAction(host.id, "manual", steps[-1], f"{steps[-1][0]} is not on PATH")
    if dry_run:
        return HostAction(host.id, "would_run", steps[-1])
    code, detail = 0, ""
    for step in steps:
        code, detail = _call([binary, *step[1:]])
    if code != 0:
        return HostAction(host.id, "failed", steps[-1], f"exit {code}: {detail}".rstrip(": "))
    return HostAction(host.id, done, steps[-1])


def _json_path(host: host_table.HostSpec, home: Path) -> Path:
    return _user_dir(home, host.registration.path)  # type: ignore[union-attr]


def register_host(host_id: str, *, home: Union[str, Path], command: Sequence[str], pin: Optional[str] = None,
                  path: Optional[str] = None, dry_run: bool = False) -> HostAction:
    """Register the ``aegis`` MCP server with one host.

    A native CLI is run remove-then-add (Claude refuses to add an existing name; Codex
    overwrites it), so a re-run converges. A ``json_file`` host is merged in place and
    refused (InstallError) when its file cannot be merged safely.
    """
    host = host_table.get(host_id)
    reg = host.registration
    if reg is None or host.retired:
        raise InstallError(_never_registered(host))
    if reg.kind == "json_file":
        status = merge_mcp_json(_json_path(host, Path(home)), SERVER_NAME, mcp_entry(host_id, command, pin),
                                key=reg.key, dry_run=dry_run, backup_dir=backup_dir(home))
        result = "unchanged" if status == "unchanged" else ("would_run" if dry_run else "registered")
        return HostAction(host_id, result, None, str(_json_path(host, Path(home))))
    return _native(host, [unregister_argv(host), register_argv(host, command, pin)], path, dry_run, "registered")


def unregister_host(host_id: str, *, home: Union[str, Path], path: Optional[str] = None,
                    dry_run: bool = False) -> HostAction:
    """Remove the ``aegis`` and legacy ``soma`` registrations from one host."""
    host = host_table.get(host_id)
    reg = host.registration
    if reg is None or host.retired:
        raise InstallError(_never_registered(host))
    if reg.kind == "json_file":
        target = _json_path(host, Path(home))
        status = remove_mcp_json(target, (SERVER_NAME, LEGACY_SERVER_NAME), key=reg.key, dry_run=dry_run,
                                 backup_dir=backup_dir(home))
        result = "absent" if status == "absent" else ("would_run" if dry_run else "removed")
        return HostAction(host_id, result, None, str(target))
    steps = [unregister_argv(host, SERVER_NAME), unregister_argv(host, LEGACY_SERVER_NAME)]
    binary = which(steps[0][0], path)
    if binary is None:
        return HostAction(host_id, "manual", steps[0], f"{steps[0][0]} is not on PATH")
    if dry_run:
        return HostAction(host_id, "would_run", steps[0])
    code, detail = _call([binary, *steps[0][1:]])
    _call([binary, *steps[1][1:]])  # the legacy name is usually absent; its failure is expected
    # A host CLI exits non-zero for a name it does not hold, so a failure is reported, not fatal.
    return HostAction(host_id, "removed" if code == 0 else "absent", steps[0],
                      "" if code == 0 else f"exit {code}: {detail}".rstrip(": "))
