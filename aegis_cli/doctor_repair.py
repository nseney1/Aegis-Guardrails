"""Repair for ``aegis doctor --fix``: the plan, its backup and manifest, and the transaction that
applies it. Nothing is written that a finding did not report, through a link, or after the file
changed since the check (aegis_cli.doctor_base reads and parses; this module only writes)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Dict, List, Optional, Sequence, Tuple

from aegis_cli.doctor_base import (
    _Finding, _aegis_version, _clean, _location, _path_key, _sha256, _without_lines, _write_refusal,
)
from aegis_core.primitives import strict_loads, utc_stamp


# ── --fix ───────────────────────────────────────────────────────────────────

class _Refused(Exception):
    """A fix that must not be applied; the message says why."""


def _backup_root(home: Path) -> Path:
    from aegis_cli.install_hosts import private_dirs
    from aegis_core.workspace.layout import UserLayout

    layout = UserLayout(home)
    for path in (layout.aegis_dir, layout.backups_dir):
        if path.is_symlink():
            raise _Refused(f"{path} is a symlink; Aegis keeps backups only in a real directory")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    target = layout.backups_dir / stamp
    # mkdir(parents=True) modes only the leaf; existing directories are never re-moded.
    private_dirs(layout.backups_dir)
    target.mkdir(mode=0o700)
    return target


def _current_bytes(path: Path, expected: Optional[str]) -> Tuple[Optional[bytes], Optional[int]]:
    """The file's bytes and permission bits if it is still the regular, single-link file
    doctor checked."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if expected is None:
            return None, None
        raise _Refused("it no longer exists")
    refusal = _write_refusal(path, st)
    if refusal:
        raise _Refused(refusal)
    with open(path, "rb") as fh:
        data = fh.read()
    if expected is not None and _sha256(data) != expected:
        raise _Refused("it changed since the check; re-run aegis doctor")
    return data, stat.S_IMODE(st.st_mode)


def _dump_like(original: bytes, data: Dict[str, Any]) -> bytes:
    """``data`` serialized the way ``original`` was: its indent, line endings and final newline."""
    text = original.decode("utf-8")
    match = re.search(r"\n([ \t]+)\"", text)
    indent: Any
    if match:
        indent = match.group(1) if "\t" in match.group(1) else len(match.group(1))
    else:
        indent = 2 if "\n" in text.strip() else None
    out = json.dumps(data, indent=indent, ensure_ascii=False, allow_nan=False)  # never the literal Infinity
    if "\r\n" in text:
        out = out.replace("\n", "\r\n")
    if text.endswith(("\n", "\r\n")):
        out += "\r\n" if "\r\n" in text else "\n"
    return out.encode("utf-8")


def _without_keys(raw: bytes, keys: Sequence[Tuple[str, ...]]) -> bytes:
    data = strict_loads(raw.decode("utf-8"))
    for path in keys:
        node = data
        for part in path[:-1]:
            node = node.get(part) if isinstance(node, dict) else None
        if not isinstance(node, dict) or path[-1] not in node:
            raise _Refused(f"{_location(path)} is no longer there")
        del node[path[-1]]
    return _dump_like(raw, data)


def _without_list_items(raw: bytes, items: Sequence[Tuple[Tuple[Any, ...], int]]) -> bytes:
    """The JSON with the listed entries removed from their lists. ``raw`` is byte-identical
    to what doctor checked (sha256), so every path resolves; every list is found before any
    entry goes, so removing one never shifts another's index."""
    data = strict_loads(raw.decode("utf-8"))
    targets: Dict[int, Tuple[list, set]] = {}
    for path, index in items:
        node: Any = data
        for part in path:
            node = node[part]
        targets.setdefault(id(node), (node, set()))[1].add(index)
    for node, indexes in targets.values():
        for index in sorted(indexes, reverse=True):
            del node[index]
    return _dump_like(raw, data)


@dataclass
class _Change:
    path: Path
    kind: str
    sha256: Optional[str]
    describe: List[str] = field(default_factory=list)
    keys: List[Tuple[str, ...]] = field(default_factory=list)
    lines: List[Tuple[int, int]] = field(default_factory=list)
    items: List[Tuple[Tuple[Any, ...], int]] = field(default_factory=list)


def _plan(findings: List[_Finding], ast_missing: List[str], root: Path) -> List[_Change]:
    changes: Dict[str, _Change] = {}
    for finding in findings:
        action = finding.action
        if action is None:
            continue
        key = _path_key(action.path)
        change = changes.setdefault(key, _Change(action.path, action.kind, action.sha256))
        change.describe.append(action.describe)
        change.keys.extend(action.keys)
        change.lines.extend(action.lines)
        change.items.extend(action.items)
    plan = list(changes.values())
    if ast_missing:
        from aegis_core.workspace.layout import WorkspaceLayout

        plan.append(_Change(WorkspaceLayout(root).config_file, "enable_packaged_ast_drivers", None,
                            [f"enable the packaged AST drivers for {', '.join(ast_missing)}"]))
    return plan


def _apply(plan: List[_Change], home: Optional[Path], root: Path) -> Tuple[List[Dict[str, Any]], Optional[Path]]:
    from aegis_core.storage import atomic_write_bytes

    results: List[Dict[str, Any]] = []

    def result(change: _Change, status: str, action: str, reason: Optional[str] = None) -> None:
        results.append({"action": action, "path": str(change.path), "status": status,
                        "changes": list(change.describe), "reason": None if reason is None else _clean(reason, 1024)})

    if home is None:
        for change in plan:
            result(change, "failed", change.kind, "no home directory for ~/.aegis/backups")
        return results, None
    try:
        backup = _backup_root(home)
    except (_Refused, OSError) as exc:
        for change in plan:
            result(change, "failed", change.kind, f"no backup could be made: {exc}")
        return results, None

    manifest: List[Dict[str, Any]] = []
    for index, change in enumerate(plan, 1):
        action = change.kind
        try:
            current, _ = _current_bytes(change.path, change.sha256)
            if current is not None:
                name = f"{index:02d}-{change.path.name}"
                # Owner-only whatever the original's bits: a backup of ~/.claude.json holds tokens.
                atomic_write_bytes(backup / name, current, mode=0o600)
                manifest.append({"path": str(change.path), "backup": name, "sha256": _sha256(current),
                                 "action": action})
                _write_manifest(backup, manifest)
            # The bits the last check saw are passed on: a link swapped in after it lends none,
            # so without them a 0600 config holding tokens would come back 0o666 & ~umask.
            if change.kind == "remove_keys":
                atomic_bytes = _without_keys(current, change.keys)
                _, bits = _current_bytes(change.path, change.sha256)  # compare before replace
                atomic_write_bytes(change.path, atomic_bytes, mode=bits, follow_links=False)
            elif change.kind == "remove_list_items":
                edited = _without_list_items(current, change.items)
                _, bits = _current_bytes(change.path, change.sha256)
                atomic_write_bytes(change.path, edited, mode=bits, follow_links=False)
            elif change.kind == "remove_lines":
                kept = _without_lines(current, change.lines)
                if kept is None:  # the plan said "edit"; deleting would be a change nobody confirmed
                    raise _Refused("only the legacy block would be left; re-run aegis doctor")
                _, bits = _current_bytes(change.path, change.sha256)
                atomic_write_bytes(change.path, kept, mode=bits, follow_links=False)
            elif change.kind == "delete_file":
                _current_bytes(change.path, change.sha256)
                os.unlink(change.path)
            elif change.kind == "enable_packaged_ast_drivers":
                from aegis_core.ast.detect import detect_project_languages, provision_ast_driver_slots

                provision_ast_driver_slots(root, detect_project_languages(root))
        except _Refused as exc:
            result(change, "skipped", action, str(exc))
            continue
        except Exception as exc:  # report and keep going: other files are independent
            result(change, "failed", action, str(exc))
            continue
        result(change, "applied", action)
    return results, backup


def _write_manifest(backup: Path, files: List[Dict[str, Any]]) -> None:
    from aegis_core.storage import atomic_write_bytes

    doc = {"schema": "aegis.doctor.backup/v1", "created_at": utc_stamp(), "aegis_version": _aegis_version(),
           "files": files}
    atomic_write_bytes(backup / "manifest.json", (json.dumps(doc, indent=2) + "\n").encode("utf-8"), mode=0o600)
