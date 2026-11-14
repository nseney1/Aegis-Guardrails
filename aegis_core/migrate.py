"""Maintain v4 rules and merge their per-worktree ledgers; retired formats are refused."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import partial
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from aegis_core.config import ConfigError, MAX_CONFIG_BYTES, RepoConfig, update_repo_config
from aegis_core.errors import PathTraversalError, WorkspaceError
from aegis_core.primitives import is_within
from aegis_core.rules import is_legacy_key
from aegis_core.storage import atomic_write_bytes, ledger_site, locked, state_dir
from aegis_core.taxonomy import DIR_RULE_TYPES, RULE_TYPE_DIRS, legacy_rule_type
from aegis_core.telemetry_engine import ledger
from aegis_core.telemetry_engine.ledger import pending_worktree_rows
from aegis_core.workspace.confinement import finish_file_move, iter_confined_files, read_confined_bytes
from aegis_core.workspace.discovery import UPGRADE_STATE_MSG, unmigrated_state
from aegis_core.workspace.layout import WorkspaceLayout
from aegis_core.yaml_engine.frontmatter import parse_frontmatter

_TOP_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*:")
_TYPE_LINE = re.compile(r"^type[ \t]*:")
__all__ = ["MigrationPlan", "MigrationRefused", "MigrationResult", "apply", "frontmatter_span", "plan", "strip_derived"]


class MigrationRefused(WorkspaceError):
    """Maintenance could not be completed without crossing a safety boundary."""


@dataclass
class _RuleChange:
    path: Path
    content: Optional[str]
    target: Optional[Path] = None
    keys: List[str] = field(default_factory=list)
    retype: Optional[Tuple[str, str]] = None


@dataclass
class MigrationPlan(ledger.WorktreeMergePlan):
    """A read-only plan with exact inputs checked again under the apply lock."""

    moves: List[_RuleChange] = field(default_factory=list)
    strips: List[_RuleChange] = field(default_factory=list)
    inputs: Dict[str, Optional[bytes]] = field(default_factory=dict)
    conflicts: List[Dict[str, str]] = field(default_factory=list)
    unmapped: List[Dict[str, str]] = field(default_factory=list)

    @property
    def pending(self) -> bool:
        return not self.refusal and bool(self.moves or self.strips or self.worktree_pending)

    def _rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": "refused" if self.refusal else "pending" if self.pending else "up_to_date",
            "refusal": self.refusal, "root": str(self.root), "ledger": None,
            "worktree_ledgers": dict(self.worktree_stats) if self.worktree_pending else None,
            "config": {"v": 1} if self.pending and not WorkspaceLayout(self.root).config_file.exists() else None,
            "config_sources": [], "user_config": {}, "dropped": [],
            "rules": [{"from": self._rel(m.path), "to": self._rel(m.target), "type": DIR_RULE_TYPES[m.target.parent.name]} for m in self.moves if m.content is not None],
            "strip": [{"path": self._rel(s.path), "keys": s.keys} for s in self.strips if s.keys],
            "retype": [{"path": self._rel(s.path), "from": s.retype[0], "to": s.retype[1]} for s in self.strips if s.retype],
            "unmapped": self.unmapped, "conflicts": self.conflicts, "unreadable": self.unreadable, "skipped": self.skipped,
            "already_moved": [self._rel(m.path) for m in self.moves if m.content is None], "remove": [], "left_in_place": [], "not_converted": [],
        }


@dataclass
class MigrationResult:
    plan: MigrationPlan
    backup: Optional[Path] = None
    written: List[str] = field(default_factory=list)
    merged: int = 0


def frontmatter_span(lines: List[str]) -> Optional[Tuple[int, int]]:
    if not lines or lines[0].rstrip("\r\n").strip() != "---":
        return None
    for end in range(1, len(lines)):
        if lines[end].rstrip("\r\n").strip() == "---":
            return 1, end
    return None


def strip_derived(text: str) -> Tuple[str, List[str]]:
    """Remove derived and retired top-level keys (and their nested lines) from the frontmatter.

    A ``fitness`` block's ``impact_weight`` is a property, not a counter: it moves to the
    top level when the rule has none there. Every other byte is kept.
    """
    if text.startswith("\ufeff"):
        stripped, keys = strip_derived(text[1:])
        return "\ufeff" + stripped, keys
    lines = text.splitlines(keepends=True)
    span = frontmatter_span(lines)
    if span is None:
        return text, []
    start, end = span
    meta = parse_frontmatter(text) or {}
    fitness = meta.get("fitness") if isinstance(meta, dict) else None
    hoist = None
    if isinstance(fitness, dict) and "impact_weight" in fitness and "impact_weight" not in meta:
        hoist = fitness["impact_weight"]
    eol = "\r\n" if lines[0].endswith("\r\n") else "\n"
    kept: List[str] = []
    removed: List[str] = []
    i = start
    while i < end:
        match = _TOP_KEY.match(lines[i])
        if match and isinstance(meta, dict) and match.group(1) in meta and is_legacy_key(match.group(1), meta[match.group(1)]):
            key = match.group(1)
            removed.append(key)
            i += 1
            while i < end and (lines[i][:1] in (" ", "\t") or lines[i].startswith("- ") or lines[i].rstrip("\r\n") == "-"):
                i += 1
            if key == "fitness" and hoist is not None:
                kept.append(f"impact_weight: {hoist}{eol}")
            continue
        kept.append(lines[i])
        i += 1
    if not removed:
        return text, []
    return "".join(lines[:start] + kept + lines[end:]), sorted(set(removed))


def _set_type(text: str, rule_type: str) -> str:
    prefix = "\ufeff" if text.startswith("\ufeff") else ""
    lines = text[len(prefix):].splitlines(keepends=True)
    span = frontmatter_span(lines)
    if span is not None:
        start, end = span
        for index in range(start, end):
            if _TYPE_LINE.match(lines[index]):
                lines[index] = f"type: {rule_type}" + lines[index][len(lines[index].rstrip("\r\n")):]
                break
        else:
            lines.insert(start, f"type: {rule_type}" + ("\r\n" if lines[0].endswith("\r\n") else "\n"))
    return prefix + "".join(lines)


_input = partial(read_confined_bytes, error_type=MigrationRefused)


def _plan_rules(result: MigrationPlan, layout: WorkspaceLayout) -> None:
    targets = set()
    for path, problem in iter_confined_files(layout.root, layout.rules_dir):
        if problem:
            result.skipped.append({"path": result._rel(path), "reason": problem})
            continue
        if path in targets or path.name.lower() == "readme.md":
            continue
        try:
            raw = _input(layout.root, path, missing_ok=False)
            text = raw.decode("utf-8")
        except (MigrationRefused, OSError, UnicodeError) as exc:
            if isinstance(exc, MigrationRefused):
                result.skipped.append({"path": result._rel(path), "reason": str(exc)})
            else:
                result.unreadable.append(result._rel(path))
            continue
        parts = path.relative_to(layout.rules_dir).parts
        meta = parse_frontmatter(text)
        declared = meta.get("type") if isinstance(meta, dict) else None
        moving = len(parts) == 2 and parts[0] not in DIR_RULE_TYPES and legacy_rule_type(parts[0]) is not None and meta != {}
        kind = legacy_rule_type(declared or parts[0]) if moving else DIR_RULE_TYPES.get(parts[0]) if len(parts) == 2 else None
        if moving and kind is None:
            result.unmapped.append({"path": result._rel(path), "type": str(declared)})
            continue
        retype = (declared, kind) if not moving and kind and declared != kind and legacy_rule_type(declared) == kind else None
        content, keys = strip_derived(_set_type(text, kind) if moving or retype else text)
        change = _RuleChange(path, content, keys=keys, retype=retype)
        if moving:
            change.target = layout.rules_dir / RULE_TYPE_DIRS[kind] / path.name
            try:
                current = _input(layout.root, change.target)
            except (MigrationRefused, OSError) as exc:
                result.skipped.append({"path": result._rel(path), "reason": str(exc)})
                continue
            if change.target in targets or current is not None and not os.path.samefile(path, change.target) and current != content.encode("utf-8"):
                result.conflicts.append({"path": result._rel(path), "to": result._rel(change.target)})
                continue
            if current == content.encode("utf-8"):
                change.content = None
            targets.add(change.target)
            result.moves.append(change)
            result.inputs[result._rel(change.target)] = current
        elif keys or retype:
            result.strips.append(change)
        else:
            continue
        result.inputs[result._rel(path)] = raw


def plan(root: Any) -> MigrationPlan:
    """Plan only v4 maintenance; no source is converted or written here."""
    layout = WorkspaceLayout(Path(os.fspath(root)).resolve())
    result = MigrationPlan(root=layout.root)
    try:
        for path in (layout.aegis_dir, layout.state_dir, layout.config_file,
                     *(layout.state_dir.iterdir() if layout.state_dir.is_dir() and not layout.state_dir.is_symlink()
                       and not layout.aegis_dir.is_symlink() and is_within(layout.state_dir, layout.root, unresolvable=False) else ())):
            if path.is_symlink() or not is_within(path, layout.root, unresolvable=False):
                raise MigrationRefused(f"{result._rel(path)} is a symlink; aegis migrate reads and writes only inside the workspace")
        retired = unmigrated_state(layout.root)
        if retired:
            raise MigrationRefused(UPGRADE_STATE_MSG.format(path=layout.root, found=", ".join(retired)))
        try:
            RepoConfig.load(layout.root)
        except ConfigError:
            result.unreadable.append(result._rel(layout.config_file))
        _plan_rules(result, layout)
        ledger.plan_worktree_merge(result)
    except (MigrationRefused, OSError, UnicodeError) as exc:
        result.refusal = str(exc)
    return result


def apply(migration: MigrationPlan) -> MigrationResult:
    """Recheck the plan, back up each affected file, then perform v4 maintenance."""
    from aegis_core.workspace.scaffold import ensure_runtime_gitignore

    result = MigrationResult(plan=migration)
    if migration.refusal:
        raise MigrationRefused(migration.refusal)
    if not migration.pending:
        return result
    layout = WorkspaceLayout(migration.root)
    try:
        state_dir(layout.root)
        ledger_site(layout.root, create=False)
        _input(layout.root, layout.config_file, max_bytes=MAX_CONFIG_BYTES)
    except (PathTraversalError, OSError) as exc:
        raise MigrationRefused(str(exc) if isinstance(exc, PathTraversalError) else "workspace inputs could not be read; no rule, config.json or .aegis/.gitignore was changed") from exc
    with locked(layout.root):
        retired = unmigrated_state(layout.root)
        if retired:
            raise MigrationRefused(UPGRADE_STATE_MSG.format(path=layout.root, found=", ".join(retired)))
        changed = [rel for rel, original in migration.inputs.items() if _input(layout.root, layout.root / rel) != original]
        if changed:
            raise MigrationRefused(f"{', '.join(changed)} changed since the plan was made; no rule, config.json or .aegis/.gitignore was changed. Run aegis migrate again.")
        result.backup = Path(tempfile.mkdtemp(prefix=f"migrate-backup-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-", dir=layout.state_dir))
        os.chmod(result.backup, 0o700)
        ignore = layout.aegis_dir / ".gitignore"
        touched = [layout.root / rel for rel, raw in migration.inputs.items() if raw is not None]
        if ensure_runtime_gitignore(layout.aegis_dir, dry_run=True) == "dry-run" and ignore.is_file():
            touched.append(ignore)
        for path in touched:
            atomic_write_bytes(result.backup / path.relative_to(layout.root), path.read_bytes(), mode=stat.S_IMODE(path.stat().st_mode))
        ensure_runtime_gitignore(layout.aegis_dir)
        if not layout.config_file.exists():
            update_repo_config(layout.root, lambda data: None)
        for item in [*migration.strips, *migration.moves]:
            try:
                target = item.target or item.path
                if item.content is not None:
                    atomic_write_bytes(target, item.content.encode("utf-8"))
                    result.written.append(target.relative_to(layout.root).as_posix())
                if item.target:
                    finish_file_move(item.path, item.target)
            except OSError as exc:
                migration.skipped.append({"path": migration._rel(item.path), "reason": str(exc)})
        if migration.worktree_pending:
            result.merged = ledger.merge_worktree_ledgers(layout.root, migration.worktree_sources)
    return result
