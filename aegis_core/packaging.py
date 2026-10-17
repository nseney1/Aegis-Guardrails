"""The Claude Code plugin directory ``aegis package --host claude-code`` writes (v4.2 #8).

Experimental, and nothing is published: the directory is a local artifact built for this
machine. Layout (Claude Code plugin docs, https://code.claude.com/docs/en/plugins and
.../plugins-reference): ``.claude-plugin/plugin.json`` is the only file in
``.claude-plugin/``; ``.mcp.json``, ``hooks/hooks.json`` and ``skills/<id>/SKILL.md`` sit at
the plugin root, where Claude Code loads them without manifest keys.

This module is pure: the caller (``aegis_cli.package``) resolves the absolute commands and
renders the skills, and passes them in. The commands are checked here again, because a
relative one, or ``python -m`` (which imports from the directory a host starts the server
in), would let a repository run its own code.
"""
from __future__ import annotations

import json
import os
from pathlib import Path, PureWindowsPath
import re
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from aegis_core.storage import atomic_write_bytes, read_json_dict

__all__ = ["MANIFEST", "PLUGIN_NAME", "PackagingError", "build_plugin", "write_plugin"]

PLUGIN_NAME = "aegis-guardrails"
MANIFEST = ".claude-plugin/plugin.json"
HOMEPAGE = "https://github.com/nseney1/Aegis-Guardrails"
DESCRIPTION = ("Experimental: Aegis Guardrails for Claude Code - the Aegis MCP server, the pre-tool hook "
               "and the packaged skills. Built for one machine; not published.")
_SKILL_ID = re.compile(r"[a-z0-9-]+")
_README = """# Aegis Guardrails (Claude Code plugin, experimental)

Written by `aegis package --host claude-code`. Nothing here is published: it is not published to any marketplace.

The MCP server and the hook name absolute paths on this machine, so this directory works
only on this machine, the one that wrote it. Run `aegis package` again after upgrading or moving Aegis.

Try it with `claude --plugin-dir <this directory>`. It carries:

- `.mcp.json`: the `aegis` MCP server (`aegis_scan`, `aegis_report_outcome`, `aegis_create_rule`, `aegis_list_rules`)
- `hooks/hooks.json`: the PreToolUse hook (`aegis hook run pre-tool`)
- `skills/`: the packaged skills
"""


class PackagingError(Exception):
    """The plugin cannot be built or written; the message says why."""


def _absolute(command: Any) -> bool:
    return isinstance(command, str) and bool(command) and (
        os.path.isabs(command) or PureWindowsPath(command).is_absolute())


def _json(doc: Mapping[str, Any]) -> bytes:
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _check_mcp(mcp: Mapping[str, Any]) -> None:
    command = mcp.get("command")
    if not _absolute(command):
        raise PackagingError(f"the MCP server command {command!r} is not an absolute path")
    args = list(mcp.get("args") or [])
    if "-m" in args and "-I" not in args:
        raise PackagingError("the MCP server entry runs python -m, which imports from the directory the host "
                             "starts it in; use the aegis-mcp script or the isolated -I -c runner")


def _check_hook(group: Mapping[str, Any]) -> None:
    for handler in group.get("hooks") or []:
        command = handler.get("command")
        if not _absolute(command):
            raise PackagingError(f"the hook command {command!r} is not an absolute path")


def build_plugin(*, version: str, mcp: Mapping[str, Any], hook_group: Mapping[str, Any],
                 skills: Mapping[str, bytes]) -> Dict[str, bytes]:
    """The plugin's files: POSIX path under the plugin root -> bytes. PackagingError for a
    command that is not absolute, ``python -m``, no skills or a skill id outside [a-z0-9-]."""
    _check_mcp(mcp)
    _check_hook(hook_group)
    if not skills:
        raise PackagingError("there are no skills to package")
    files: Dict[str, bytes] = {
        MANIFEST: _json({"name": PLUGIN_NAME, "version": version, "description": DESCRIPTION,
                         "homepage": HOMEPAGE}),
        ".mcp.json": _json({"mcpServers": {"aegis": dict(mcp)}}),
        "hooks/hooks.json": _json({"hooks": {"PreToolUse": [dict(hook_group)]}}),
        "README.md": _README.encode("utf-8"),
    }
    for skill_id, data in skills.items():
        if not _SKILL_ID.fullmatch(skill_id):
            raise PackagingError(f"skill id {skill_id!r} is not [a-z0-9-]")
        files[f"skills/{skill_id}/SKILL.md"] = data
    return files


def _is_ours(out: Path) -> bool:
    manifest = read_json_dict(out / MANIFEST)
    return isinstance(manifest, dict) and manifest.get("name") == PLUGIN_NAME


def write_plugin(out: Any, files: Mapping[str, bytes], dry_run: bool = False) -> List[Tuple[str, str]]:
    """Write ``files`` under ``out``: ``(path, created|updated|unchanged)`` in path order.

    ``out`` may be missing, empty or an earlier Aegis plugin (its manifest names it), and is
    never a link; nothing is written through a link inside it. Every refusal comes before
    the first write, and each file is replaced atomically."""
    root = Path(out)
    if root.is_symlink():
        raise PackagingError(f"{root} is a symbolic link; name the real directory")
    if root.exists():
        if not root.is_dir():
            raise PackagingError(f"{root} exists and is not a directory")
        if any(root.iterdir()) and not _is_ours(root):
            raise PackagingError(f"{root} is not empty and is not an Aegis plugin directory; choose another --out")
    plan: List[Tuple[str, str]] = []
    for rel in sorted(files):
        target = root.joinpath(*rel.split("/"))
        for part in [target, *target.parents]:
            if part == root.parent:
                break
            if part.is_symlink():
                raise PackagingError(f"{part} is a symbolic link; Aegis does not write through links")
        if target.is_dir():
            raise PackagingError(f"{target} is a directory; a file belongs there")
        if not target.exists():
            state = "created"
        else:
            state = "unchanged" if target.read_bytes() == files[rel] else "updated"
        plan.append((rel, state))
    if not dry_run:
        for rel, state in plan:
            if state != "unchanged":
                atomic_write_bytes(root.joinpath(*rel.split("/")), files[rel])
    return plan
