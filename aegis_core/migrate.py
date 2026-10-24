"""`aegis migrate`: v3 workspaces and .soma cells to the v4 layout (D10, D12, D13, D21).

``plan(root)`` reads and decides; it writes nothing, and records a digest of every file
it converts. ``apply(plan)`` executes under the workspace lock: it first re-reads those
files and, if any changed since planning (an editor saved a rule, a v3 process appended a
row, a rule appeared at a destination), refuses with MigrationRefused and changes
nothing, so plan-time bytes never overwrite a newer edit. It then copies every file it
will change or remove to ``.aegis/state/migrate-backup-<UTC stamp>/`` (same relative
paths, same permission bits, in a 0o700 directory: the copies include keys and receipts)
before touching it. A second run finds nothing to do and writes nothing.

What a plan converts:
- **Ledger**: ``.aegis/evidence/signals.jsonl`` and its ``telemetry/`` compaction copy,
  the monthly ``archive/*.jsonl.gz`` files v3.3 compaction moved older rows into beside
  each, and the v1/v2 ``.soma/evidence/signals.jsonl`` (decoded as v3 wrote them, with
  ``surrogatepass``; deduplicated by event id, or by identical row for rows without one
  against the first ledger present) become v2 rows
  appended to ``.aegis/state/ledger.jsonl`` with provenance (``from``: v3 file and line),
  followed by one epoch row. Existing rows are never rewritten (v4.3 §10.4). What is not
  converted (compaction rollups, ``steering.conf``, ``~/.aegis/slots.yaml``) is listed.
- **Config**: ``aegis.conf``/``soma.conf``, ``.aegis/slots.yaml`` and ``.aegis/config.yaml``
  become ``.aegis/config.json``. Command-like values (driver commands, slots) go to a
  printed note for ``~/.aegis/config.json``, never into the repository; keys v4 no longer
  has are reported as dropped.
- **Rules**: ``.soma/cells/<type>/*.md`` and ``.soma/rules/<type>/*.md`` (v2.0, v2.1),
  and the rules v3.1-v3.3 kept in a v3 type
  directory of ``.aegis/rules`` (``walls/``, ``membranes/``…; notes there stay), move
  to ``.aegis/rules/<canonical type>/`` through the legacy type-name table
  (taxonomy.LEGACY_TYPE_NAMES: the v1-v3 aliases and the v2.1 organelle names); a type it does
  not map is reported and left in place, never guessed. A v3 type name in a canonical
  directory (``type: wall`` in ``invariants/``) is rewritten to the v4 name. Derived
  counters (``fitness``, ``triggers``, ``score``…) and keys v4 never reads
  (``enforcement_artifact``) are stripped from every rule's frontmatter, line by line,
  so every other byte stays (v4.3 §10.2).
- **Manifest**: the v3 integrity manifest (``.aegis/rules/manifest.json``, or the older
  ``.aegis/manifest.json``) and its HMAC key are v3 state: v4 keeps an unsigned index in
  ``.aegis/state/derived.json``, written by ``aegis sync`` (D3), so they are removed with
  the other state below.
- **State**: the v3 runtime files (layout.LEGACY_STATE_ENTRIES) are removed, except
  files under ``drivers/`` that are not the driver copies `aegis init` staged there
  byte for byte (a copy that differs from every version aegis shipped may hold the
  user's changes), or that a printed driver command names: those are left in place and
  reported.

- **Worktree ledgers** (v4.2): in a git repository the ledger is ONE file shared by every
  worktree (``aegis_core.storage.ledger_site``), so the ledgers the worktrees kept in
  ``.aegis/state/ledger.jsonl`` before are merged into it: the same workspace's file in
  every worktree ``git worktree list`` names, deduplicated (a keyed row by ``(key, rule)``,
  a keyless one by its canonical row), appended in ``(ts, worktree, seq)`` order with a
  fresh ``seq``, then one epoch row. Those files are read, never changed or removed, so a
  second run finds nothing to merge; they are re-read when applying, under the ledger
  lock, so rows appended since the plan are merged too. A source that is a symlink, or
  inside a symlinked ``.aegis`` or ``.aegis/state``, is reported and not read.

A workspace the upgrade sentinel (aegis_core.workspace.discovery) would still refuse
after the plan, with nothing to apply, gets a refusal naming what blocks it and how to
clear it: never "nothing to do".
"""
from __future__ import annotations

from collections import Counter
import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
from typing import Any, Dict, List, Optional, Tuple
import zlib

from aegis_core import gitsafe
from aegis_core.errors import PathTraversalError, WorkspaceError
from aegis_core.primitives import is_within
from aegis_core.rules import is_legacy_key
from aegis_core.storage import (
    JsonlRead,
    atomic_write_bytes,
    atomic_write_text,
    ledger_site,
    locked,
    read_jsonl,
    state_dir,
    workspace_relative,
    worktree_label,
)
from aegis_core.taxonomy import DIR_RULE_TYPES, RULE_TYPE_DIRS, legacy_rule_type
from aegis_core.workspace.layout import (
    LEGACY_CONFIG_ENTRIES,
    LEGACY_LEDGER_ARCHIVE,
    LEGACY_LEDGER_ARCHIVE_GLOB,
    LEGACY_LEDGER_FILES,
    LEGACY_LEDGER_ROLLUP,
    LEGACY_REPO_CONFS,
    LEGACY_STATE_ENTRIES,
    LEGACY_STEERING_CONF,
    UserLayout,
    WorkspaceLayout,
)

__all__ = ["MigrationPlan", "MigrationRefused", "MigrationResult", "apply", "plan"]

# A compaction archive larger than this decompressed is reported unreadable, not read.
_ARCHIVE_LIMIT = 256 * 1024 * 1024
_V4_ENTRIES = frozenset({"config.json", ".gitignore", "rules", "state"})
_TOP_KEY = re.compile(r"^([A-Za-z_][\w\-]*)[ \t]*:")
_TYPE_LINE = re.compile(r"^type[ \t]*:[ \t]*(['\"]?)([A-Za-z_][\w\-]*)\1[ \t]*(#.*)?$")
_CONF_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*(.*?)\s*$")
_DROPPED_CONF = {
    "AEGIS_INFERENCE_PROVIDER": "Layer 2 runs one command: pass --llm-cmd or set AEGIS_LLM_CMD",
    "TEAM_REPO": "team sync was removed in v4",
    "TEAM_MEMBER_ID": "team sync was removed in v4",
    "METRICS_REPO": "team metrics were removed in v4",
    "TOTAL_SESSIONS": "v4 has no session count setting",
}


class MigrationRefused(WorkspaceError):
    """The workspace cannot be migrated safely (for example, .aegis is a symlink)."""


@dataclass
class _RuleMove:
    source: Path
    target: Path
    rule_type: str
    content: str


@dataclass
class _RuleStrip:
    """A rule rewritten in place: legacy ``keys`` stripped and/or a v3 type name renamed."""

    path: Path
    keys: List[str]
    content: str
    original: bytes  # the bytes the plan read
    retype: Optional[Tuple[str, str]] = None  # (v3 type name, v4 type)


@dataclass
class MigrationPlan:
    """What ``apply`` will do. ``to_dict()`` is the machine-readable report."""

    root: Path
    ledger_sources: List[str] = field(default_factory=list)
    ledger_rows: List[Dict[str, Any]] = field(default_factory=list)
    ledger_stats: Dict[str, Any] = field(default_factory=dict)
    # Per-worktree ledgers to merge into the shared one: (worktree label, that worktree's
    # workspace root) of each that holds a readable ledger, how many rows the shared ledger
    # lacks, and the report's counts (empty when nothing is to be merged).
    worktree_sources: List[Tuple[str, Path]] = field(default_factory=list)
    worktree_pending: int = 0
    worktree_stats: Dict[str, Any] = field(default_factory=dict)
    config_sources: List[str] = field(default_factory=list)
    config: Optional[Dict[str, Any]] = None
    # Only what the legacy files contribute: apply() merges it into config.json as it is
    # then (a value already there wins), so a write since planning is never lost.
    config_changes: Dict[str, Any] = field(default_factory=dict)
    user_config: Dict[str, Dict[str, str]] = field(default_factory=dict)
    dropped: List[str] = field(default_factory=list)
    moves: List[_RuleMove] = field(default_factory=list)
    strips: List[_RuleStrip] = field(default_factory=list)
    unmapped: List[Dict[str, str]] = field(default_factory=list)
    conflicts: List[Dict[str, str]] = field(default_factory=list)
    unreadable: List[str] = field(default_factory=list)
    removals: List[str] = field(default_factory=list)
    left_in_place: List[str] = field(default_factory=list)
    # v3 data with no v4 form: {"path", "reason"}; reported, never a failure.
    not_converted: List[Dict[str, str]] = field(default_factory=list)
    skipped: List[Dict[str, str]] = field(default_factory=list)
    already_moved: List[Path] = field(default_factory=list)
    refusal: Optional[str] = None
    # Every file whose bytes the plan converts, rewrites, removes for its content, or
    # expects absent (a rule destination): repo-relative POSIX path -> _fingerprint.
    inputs: Dict[str, Optional[str]] = field(default_factory=dict)

    @property
    def creates_config(self) -> bool:
        """Applying writes .aegis/config.json because the v4 layout has none yet."""
        return not WorkspaceLayout(self.root).config_file.exists()

    @property
    def pending(self) -> bool:
        if self.refusal:
            return False
        return bool(
            self.ledger_sources or self.config_sources or self.moves or self.strips
            or self.removals or self.already_moved or self.worktree_pending
        )

    def _rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def to_dict(self) -> Dict[str, Any]:
        status = "refused" if self.refusal else ("pending" if self.pending else "up_to_date")
        return {
            "status": status,
            "refusal": self.refusal,
            "root": str(self.root),
            "ledger": dict(self.ledger_stats, sources=self.ledger_sources) if self.ledger_sources else None,
            "worktree_ledgers": dict(self.worktree_stats) if self.worktree_pending else None,
            "config": self.config if self.pending and (self.config_sources or self.creates_config) else None,
            "config_sources": self.config_sources,
            "user_config": self.user_config,
            "dropped": self.dropped,
            "rules": [
                {"from": self._rel(m.source), "to": self._rel(m.target), "type": m.rule_type} for m in self.moves
            ],
            "strip": [{"path": self._rel(strip.path), "keys": strip.keys} for strip in self.strips if strip.keys],
            "retype": [
                {"path": self._rel(strip.path), "from": strip.retype[0], "to": strip.retype[1]}
                for strip in self.strips if strip.retype
            ],
            "unmapped": self.unmapped,
            "conflicts": self.conflicts,
            "unreadable": self.unreadable,
            "skipped": self.skipped,
            "already_moved": [self._rel(path) for path in self.already_moved],
            "remove": self.removals,
            "left_in_place": self.left_in_place,
            "not_converted": self.not_converted,
        }


@dataclass
class MigrationResult:
    plan: MigrationPlan
    backup: Optional[Path] = None
    written: List[str] = field(default_factory=list)
    # Rows merged into the shared ledger from the other worktrees' ledgers.
    merged: int = 0


# ── Frontmatter line editing ─────────────────────────────────────────────────

def _frontmatter_span(lines: List[str]) -> Optional[Tuple[int, int]]:
    if not lines or lines[0].rstrip("\r\n").strip() != "---":
        return None
    for end in range(1, len(lines)):
        if lines[end].rstrip("\r\n").strip() == "---":
            return 1, end
    return None


def _eol(lines: List[str]) -> str:
    return "\r\n" if lines and lines[0].endswith("\r\n") else "\n"


def _strip_derived(text: str) -> Tuple[str, List[str]]:
    """Remove derived and retired top-level keys (and their nested lines) from the frontmatter.

    A ``fitness`` block's ``impact_weight`` is a property, not a counter: it moves to the
    top level when the rule has none there. Every other byte is kept.
    """
    from aegis_core.yaml_engine.frontmatter import parse_frontmatter

    if text.startswith("\ufeff"):
        stripped, keys = _strip_derived(text[1:])
        return "\ufeff" + stripped, keys
    lines = text.splitlines(keepends=True)
    span = _frontmatter_span(lines)
    if span is None:
        return text, []
    start, end = span
    meta = parse_frontmatter(text) or {}
    fitness = meta.get("fitness") if isinstance(meta, dict) else None
    hoist = None
    if isinstance(fitness, dict) and "impact_weight" in fitness and "impact_weight" not in meta:
        hoist = fitness["impact_weight"]
    eol = _eol(lines)
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
    if text.startswith("\ufeff"):
        return "\ufeff" + _set_type(text[1:], rule_type)
    lines = text.splitlines(keepends=True)
    span = _frontmatter_span(lines)
    if span is None:
        return text
    start, end = span
    eol = _eol(lines)
    for i in range(start, end):
        if _TYPE_LINE.match(lines[i].rstrip("\r\n")):
            ending = lines[i][len(lines[i].rstrip("\r\n")):]
            lines[i] = f"type: {rule_type}{ending}"
            return "".join(lines)
    lines.insert(start, f"type: {rule_type}{eol}")
    return "".join(lines)


def _merge_missing(current: Dict[str, Any], changes: Dict[str, Any]) -> None:
    """Add to ``current`` what ``changes`` has and it lacks: a value already in
    ``current`` wins, nested objects merge, and lists gain only the items they lack."""
    for key, value in changes.items():
        if key not in current:
            current[key] = copy.deepcopy(value)
        elif isinstance(current[key], dict) and isinstance(value, dict):
            _merge_missing(current[key], value)
        elif isinstance(current[key], list) and isinstance(value, list):
            current[key] = current[key] + [item for item in value if item not in current[key]]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fingerprint(path: Path) -> Optional[str]:
    """What ``path`` is now: None when absent, "symlink" for a link (never followed),
    else the SHA-256 of its bytes."""
    if not os.path.lexists(path):
        return None
    if os.path.islink(path):
        return "symlink"
    try:
        return _sha256(path.read_bytes())
    except OSError as exc:
        return f"unreadable: {exc.strerror or exc}"


def _record(result: "MigrationPlan", path: Path, data: Optional[bytes] = None) -> None:
    """Note ``path`` as a plan input: ``data`` is the bytes the plan read (taken before
    any parsing, so a later append is a change), or read now when omitted."""
    result.inputs[result._rel(path)] = _fingerprint(path) if data is None else _sha256(data)


# ── Planning ─────────────────────────────────────────────────────────────────

def _jsonl_row(raw: bytes, errors: str) -> Optional[Dict[str, Any]]:
    try:
        value = json.loads(raw.decode("utf-8-sig", errors))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _jsonl_rows(data: bytes, errors: str) -> JsonlRead:
    """Parse JSONL ``data`` as storage.read_jsonl parses a file (same lines, numbers, tail)."""
    rows: List[Dict[str, Any]] = []
    numbers: List[int] = []
    skipped: List[int] = []
    torn = False
    lines = data.split(b"\n")
    last = len(lines) - 1
    for index, raw in enumerate(lines):
        if index == last and not raw:
            break
        raw = raw.rstrip(b"\r")
        if not raw.strip():
            continue
        row = _jsonl_row(raw, errors)
        if row is not None:
            rows.append(row)
            numbers.append(index + 1)
        elif index == last:
            torn = True
        else:
            skipped.append(index + 1)
    return JsonlRead(rows, numbers, skipped, torn_tail=torn)


def _read_archive(path: Path) -> Tuple[Optional[bytes], JsonlRead]:
    """A v3.3 compaction archive: (its bytes as read, for the plan's fingerprint; its rows).
    A link, a damaged or oversized file reads as no rows with ``error`` set."""
    if path.is_symlink() or not path.is_file():
        return None, JsonlRead([], [], [], error=f"cannot read {path}: not a regular file")
    try:
        raw = path.read_bytes()
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as fh:
            data = fh.read(_ARCHIVE_LIMIT + 1)
    except (OSError, EOFError, ValueError, zlib.error) as exc:  # zlib.error: a damaged deflate stream
        return None, JsonlRead([], [], [], error=f"cannot read {path}: {exc}")
    if len(data) > _ARCHIVE_LIMIT:
        return raw, JsonlRead([], [], [], error=f"cannot read {path}: larger than {_ARCHIVE_LIMIT >> 20} MiB")
    return raw, _jsonl_rows(data, "surrogatepass")


def _ledger_families(layout: WorkspaceLayout) -> List[List[Path]]:
    """The ledger copies with what they hold, first one first: each v3 ledger file followed
    by the compaction archives beside it, then the v1/v2 ledger. Only files that exist."""
    families: List[List[Path]] = []
    for rel in LEGACY_LEDGER_FILES:
        live = layout.legacy(rel)
        archive = live.parent / LEGACY_LEDGER_ARCHIVE
        family = [live] if live.is_file() or live.is_symlink() else []
        if archive.is_dir() and not archive.is_symlink():
            family += sorted(archive.glob(LEGACY_LEDGER_ARCHIVE_GLOB))
        families.append(family)
    predecessor = layout.legacy_predecessor_ledger
    families.append([predecessor] if predecessor.is_file() or predecessor.is_symlink() else [])
    return [family for family in families if family]


def _plan_ledger(result: MigrationPlan, layout: WorkspaceLayout) -> None:
    from aegis_core.telemetry_engine import ledger

    families = _ledger_families(layout)
    if not families:
        return
    rows: List[Dict[str, Any]] = []
    origins: List[Dict[str, Any]] = []
    seen_ids = set()
    primary_rows: Counter = Counter()
    stats = {"rows": 0, "duplicates": 0, "unusable_rows": 0, "skipped_lines": 0, "torn_tail": False}
    for index, family in enumerate(families):
        for source in family:
            rel = result._rel(source)
            result.ledger_sources.append(rel)
            if source.name.endswith(".gz"):
                raw, read = _read_archive(source)
                if raw is not None:
                    _record(result, source, raw)
                else:
                    _record(result, source)
            else:
                _record(result, source)  # before reading: a row appended meanwhile is a change
                # v3 wrote these with errors="surrogatepass" (a lone surrogate from a non-UTF-8
                # file name); strict decoding would drop such a row as unreadable.
                read = read_jsonl(source, errors="surrogatepass")
            if read.error:
                result.unreadable.append(rel)
            stats["skipped_lines"] += read.skipped
            stats["torn_tail"] = stats["torn_tail"] or read.torn_tail
            for line_no, row in zip(read.line_numbers, read.rows):
                identity = row.get("event_id")
                text = json.dumps(row, sort_keys=True)
                if isinstance(identity, str) and identity:
                    if identity in seen_ids:
                        stats["duplicates"] += 1
                        continue
                    seen_ids.add(identity)
                elif index > 0 and primary_rows[text] > 0:
                    primary_rows[text] -= 1  # a copy of a row the first ledger has
                    stats["duplicates"] += 1
                    continue
                elif index == 0:
                    primary_rows[text] += 1
                rows.append(row)
                origins.append({"v": 1, "file": rel, "line": line_no})
    if layout.legacy_predecessor_ledger in families[-1]:
        # Under .soma/, which no v3 state entry covers: removed here once converted.
        result.removals.append(result._rel(layout.legacy_predecessor_ledger))
    converted, unusable = ledger.normalize_rows(rows, origins)
    for row in converted:
        if not row.get("key"):
            origin = row.get("from") or {}
            seed = f"{origin.get('file')}:{origin.get('line')}:{row.get('rule')}:{row.get('outcome')}:{row.get('ts')}"
            row["key"] = "v1:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]
    stats["rows"] = len(converted)
    stats["unusable_rows"] = unusable
    result.ledger_rows = converted
    result.ledger_stats = stats


@dataclass
class _WorktreeLedger:
    """One worktree's own ledger as read for the merge: its usable rows (each with the
    ``worktree`` it came from) and what could not be used, or why it was not read."""

    label: str
    workspace: Path
    path: Path
    rows: List[Dict[str, Any]] = field(default_factory=list)
    skipped_lines: int = 0
    unusable_rows: int = 0
    problem: Optional[Tuple[str, str, str]] = None  # (unreadable|skipped, path, reason)


def _listed_worktrees(root: Path) -> List[Path]:
    """The work trees ``git worktree list`` names (a bare repository has none)."""
    for args, sep in ((["worktree", "list", "--porcelain", "-z"], b"\0"), (["worktree", "list", "--porcelain"], b"\n")):
        try:
            done = gitsafe.run(args, root)
        except gitsafe.GitError:
            return []
        if done.returncode == 0:  # -z needs git 2.36; older git exits 129 and the second form answers
            break
    else:
        return []
    paths: List[Path] = []
    for token in done.stdout.split(sep):
        if token.startswith(b"worktree "):
            paths.append(Path(os.fsdecode(token[len(b"worktree "):])))
        elif token == b"bare" and paths:
            paths.pop()
    return paths


def _worktree_roots(root: Path) -> List[Tuple[str, Path]]:
    """(label, workspace root) of ``root`` in every worktree of its repository, this one
    included, sorted by label; only worktrees whose directory exists. Empty outside git."""
    top = gitsafe.toplevel(root)
    relative = workspace_relative(root)
    if top is None or relative is None:
        return []
    found: Dict[str, Path] = {}
    for tree in [top, *_listed_worktrees(root)]:
        resolved = Path(os.path.realpath(tree))
        if not resolved.is_dir():
            continue  # a worktree whose directory was removed (git calls it prunable)
        found[worktree_label(resolved)] = resolved if relative == "." else resolved.joinpath(*relative.split("/"))
    return sorted(found.items())


def _read_worktree_ledger(label: str, workspace: Path) -> Optional[_WorktreeLedger]:
    """The ledger ``workspace`` (the workspace root inside one worktree) keeps, or None when
    it has none. Read only, and never through a link: another worktree's ``.aegis`` or
    ``.aegis/state`` is whatever its commits put there."""
    from aegis_core.telemetry_engine import ledger

    layout = WorkspaceLayout(workspace)
    source = _WorktreeLedger(label, workspace, layout.ledger_file)
    for directory in (layout.aegis_dir, layout.state_dir):
        outside = os.path.lexists(directory) and not is_within(directory, workspace, unresolvable=False)
        if directory.is_symlink() or outside:
            why = "is a symlink" if directory.is_symlink() else "resolves outside the workspace"
            source.problem = ("skipped", directory.as_posix(),
                              f"{why}; its ledger was not read (aegis migrate reads and writes only inside the workspace)")
            return source
    if not os.path.lexists(layout.ledger_file):
        return None
    read = read_jsonl(layout.ledger_file)
    if read.error:
        source.problem = ("unreadable", layout.ledger_file.as_posix(), read.error)
        return source
    rows, unusable = ledger.normalize_rows(read.rows)
    for row in rows:
        stamp = row["worktree"] if isinstance(row.get("worktree"), str) and row["worktree"] else label
        source.rows.append(dict(row, worktree=stamp))
    source.skipped_lines = read.skipped
    source.unusable_rows = unusable
    return source


def _plan_worktree_ledgers(result: MigrationPlan, layout: WorkspaceLayout) -> None:
    from aegis_core.telemetry_engine import ledger

    roots = _worktree_roots(layout.root)
    if not roots:
        return  # not in git: the ledger is .aegis/state/ledger.jsonl and nothing is shared
    try:
        ledger_site(layout.root, create=False)
    except PathTraversalError as exc:
        result.refusal = str(exc)
        return
    except OSError as exc:
        result.refusal = f"cannot use the shared ledger directory: {exc.strerror or exc}"
        return
    sources: List[_WorktreeLedger] = []
    for label, workspace in roots:
        found = _read_worktree_ledger(label, workspace)
        if found is None:
            continue
        if found.problem is not None:
            kind, path, reason = found.problem
            if kind == "unreadable":
                result.unreadable.append(path)
            else:
                result.skipped.append({"path": path, "reason": reason})
            continue
        sources.append(found)
    if not sources:
        return
    shared = ledger.read(layout.root)
    if shared.error:
        result.refusal = f"cannot merge into the shared ledger: {shared.error}"
        return
    added, duplicates, conflicts = ledger.plan_merge_report(shared.rows, [source.rows for source in sources])
    result.worktree_sources = [(source.label, source.workspace) for source in sources]
    result.worktree_pending = len(added)
    result.worktree_stats = {
        "sources": [source.path.as_posix() for source in sources],
        "rows": len(added),
        "duplicates": duplicates,
        "conflicts": conflicts,
        "unusable_rows": sum(source.unusable_rows for source in sources),
        "skipped_lines": sum(source.skipped_lines for source in sources),
    }


def _plan_not_converted(result: MigrationPlan, layout: WorkspaceLayout) -> None:
    """List the v3 data that has no v4 form, so dropping it is never silent."""
    for rel in LEGACY_LEDGER_FILES:
        archive = layout.legacy(rel).parent / LEGACY_LEDGER_ARCHIVE
        if archive.is_symlink():
            result.not_converted.append({
                "path": result._rel(archive),
                "reason": "a symlink, never followed: the rows behind it are not converted; the link is removed",
            })
        rollup = layout.legacy(rel).parent / LEGACY_LEDGER_ROLLUP
        if os.path.lexists(rollup):
            result.not_converted.append({
                "path": result._rel(rollup),
                "reason": "per-rule totals from v3.3 compaction; v4 keeps no rollup (the archived rows "
                          "it summed are converted where archive/ still holds them); removed, backed up first",
            })
    steering = layout.root / LEGACY_STEERING_CONF
    if os.path.lexists(steering):
        result.not_converted.append({"path": result._rel(steering), "reason": "no v4 setting; left in place"})
    user = UserLayout.current()
    if user is not None and os.path.lexists(user.legacy_slots_file):
        result.not_converted.append({
            "path": "~/" + user.legacy_slots_file.relative_to(user.home).as_posix(),
            "reason": "no v4 setting (a driver or slot command now goes in ~/.aegis/config.json); left in place",
        })


def _parse_conf(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _CONF_LINE.match(line)
        if match:
            values[match.group(1)] = match.group(2).strip().strip("\"'")
    return values


def _plan_config(result: MigrationPlan, layout: WorkspaceLayout) -> None:
    from aegis_core.ast.detect import names_packaged_driver, packaged_driver_for_extension
    from aegis_core.config import ConfigError, _read_json
    from aegis_core.yaml_engine.frontmatter import AegisYAML
    from aegis_core.yaml_engine.parser import parse_yaml_subset

    config: Dict[str, Any] = {"v": 1}
    try:
        existing = _read_json(layout.config_file, "config.json")
    except ConfigError:
        existing = None
        if layout.config_file.exists():
            result.unreadable.append(result._rel(layout.config_file))
    if existing:
        config.update(existing)
    changes: Dict[str, Any] = {}
    drivers: Dict[str, str] = {}
    slots: Dict[str, str] = {}

    def setting(path: Tuple[str, ...], value: Any) -> None:
        # setdefault: the first legacy file to set a value wins (config.json wins at merge)
        node = changes
        for part in path[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                child = node[part] = {}
            node = child
        node.setdefault(path[-1], value)

    for name in LEGACY_REPO_CONFS:
        conf = layout.root / name
        if not conf.is_file():
            continue
        rel = result._rel(conf)
        result.config_sources.append(rel)
        result.removals.append(rel)
        _record(result, conf)
        for key, value in _parse_conf(conf).items():
            upper = key.upper()
            if upper == "MAX_JIT_TOKENS" and value.isdigit() and int(value) > 0:
                setting(("jit", "max_tokens"), int(value))
            elif upper in ("RULE_EXPIRY_DAYS", "CELL_TELOMERE_DAYS"):
                days = None if value.lower() == "null" else (int(value) if value.isdigit() else "bad")
                if days == "bad":
                    result.dropped.append(f"{rel}: {key} (not a number of days)")
                else:
                    setting(("expiry", "days"), days)
            elif upper.startswith(("RULE_EXPIRY_", "CELL_TELOMERE_")):
                rule_type = legacy_rule_type(upper.split("_", 2)[-1].lower())
                if rule_type and (value.isdigit() or value.lower() == "null"):
                    setting(("expiry", "per_type", rule_type), None if value.lower() == "null" else int(value))
                else:
                    result.dropped.append(f"{rel}: {key} (unknown rule type or value)")
            elif upper == "AEGIS_LLM_CMD":
                result.dropped.append(f"{rel}: {key} (set AEGIS_LLM_CMD in your environment; a repository never chooses commands)")
            elif upper in _DROPPED_CONF:
                result.dropped.append(f"{rel}: {key} ({_DROPPED_CONF[upper]})")
            else:
                result.dropped.append(f"{rel}: {key} (no v4 setting)")

    slots_file = layout.legacy("slots.yaml")
    if slots_file.is_file():
        rel = result._rel(slots_file)
        result.config_sources.append(rel)
        _record(result, slots_file)
        try:
            raw = AegisYAML.parse_text(slots_file.read_text(encoding="utf-8-sig")).get("slots") or {}
        except Exception:
            raw = None
            result.unreadable.append(rel)
        if raw is not None:
            result.removals.append(rel)
        packaged: List[str] = []
        for key, value in (raw or {}).items():
            key, value = str(key), str(value)
            if key.startswith("ast_driver_"):
                ext = key[len("ast_driver_"):].strip().lower().lstrip(".")
                packaged_config = packaged_driver_for_extension(ext)
                if packaged_config is not None and names_packaged_driver(value, packaged_config):
                    if ext not in packaged:
                        packaged.append(ext)
                else:
                    drivers[ext] = value
            elif key == "ast_driver":
                result.dropped.append(f"{rel}: ast_driver (a catch-all driver; name one per extension in ~/.aegis/config.json drivers)")
            else:
                slots[key] = value
        if packaged:
            changes.setdefault("ast", {})["packaged_drivers"] = packaged

    other = layout.legacy("config.yaml")
    if other.is_file():
        rel = result._rel(other)
        result.config_sources.append(rel)
        result.removals.append(rel)
        _record(result, other)
        try:
            # The parser itself, not AegisYAML: an AegisDocument adds rule defaults (type,
            # target_paths, decay) the file never held.
            keys = sorted(map(str, (parse_yaml_subset(other.read_text(encoding="utf-8-sig")) or {}).keys()))
        except Exception:
            keys = ["(unparseable)"]
        for key in keys:
            result.dropped.append(f"{rel}: {key} (no v4 setting)")

    _merge_missing(config, changes)
    result.config = config
    result.config_changes = changes
    if drivers:
        result.user_config["drivers"] = drivers
    if slots:
        result.user_config["slots"] = slots


def _plan_moves(
    result: MigrationPlan, layout: WorkspaceLayout, source_dir: Path, planned_targets: set, notes_stay: bool,
) -> List[Path]:
    """Plan moving the rules under ``source_dir`` (a v3 type directory) to their canonical
    directory; return the sources planned. With ``notes_stay``, a file without
    frontmatter is a note and stays where it is (the loader reports it as ignored)."""
    from aegis_core.yaml_engine.frontmatter import parse_frontmatter

    sources: List[Path] = []
    for source in sorted(source_dir.rglob("*.md")):
        if source.name.lower() == "readme.md" or any(part.startswith(".") for part in source.relative_to(source_dir).parts):
            continue
        rel = result._rel(source)
        if source.is_symlink() or not is_within(source, layout.root, unresolvable=False):
            result.skipped.append({"path": rel, "reason": "a symlink or outside the workspace; not followed"})
            continue
        try:
            raw = source.read_bytes()
            text = raw.decode("utf-8-sig")  # bytes: keep CRLF as it is
        except (OSError, UnicodeError):
            result.unreadable.append(rel)
            continue
        meta = parse_frontmatter(text)
        if notes_stay and meta == {}:
            continue  # no frontmatter: a note (frontmatter that cannot be read still moves)
        raw_type = meta.get("type") if isinstance(meta, dict) and meta.get("type") else source.parent.name
        rule_type = legacy_rule_type(raw_type)
        if rule_type is None:
            result.unmapped.append({"path": rel, "type": str(raw_type)})
            continue
        target = layout.rules_dir / RULE_TYPE_DIRS[rule_type] / source.name
        content, _keys = _strip_derived(_set_type(text, rule_type))
        if not is_within(target.parent, layout.root, unresolvable=False):
            result.skipped.append({"path": rel, "reason": f"{result._rel(target.parent)} resolves outside the workspace"})
            continue
        sources.append(source)
        if os.path.lexists(target) or target in planned_targets:
            if _same_text(target, content):
                result.already_moved.append(source)  # an interrupted apply: only the source is left
                _record(result, source, raw)
                _record(result, target, content.encode("utf-8"))
            else:
                result.conflicts.append({"path": rel, "to": result._rel(target)})
            continue
        planned_targets.add(target)
        result.moves.append(_RuleMove(source, target, rule_type, content))
        _record(result, source, raw)
        result.inputs[result._rel(target)] = None  # must still be absent when applying
    return sources


def _v3_type_dirs(layout: WorkspaceLayout) -> List[Path]:
    """Directories of .aegis/rules named for a v3 type (``walls/``, ``membranes/``…)."""
    if not layout.rules_dir.is_dir():
        return []
    return [
        child for child in sorted(layout.rules_dir.iterdir())
        if child.is_dir() and not child.is_symlink() and not child.name.startswith(".")
        and child.name not in DIR_RULE_TYPES and legacy_rule_type(child.name) is not None
    ]


def _retype(text: str, directory: str) -> Optional[Tuple[str, str]]:
    """(v3 name, v4 type) when a rule in a canonical directory spells its own type the
    v3 way (``type: wall`` in invariants/, ``type: Trap`` in traps/). A name for some
    other type contradicts the directory: the loader reports it, migrate never guesses."""
    from aegis_core.yaml_engine.frontmatter import parse_frontmatter

    rule_type = DIR_RULE_TYPES.get(directory)
    meta = parse_frontmatter(text)
    declared = meta.get("type") if isinstance(meta, dict) else None
    if rule_type is None or not isinstance(declared, str) or declared == rule_type:
        return None
    return (declared, rule_type) if legacy_rule_type(declared) == rule_type else None


def _plan_rules(result: MigrationPlan, layout: WorkspaceLayout) -> None:
    planned_targets: set = set()
    moving: set = set()
    for folder in layout.legacy_rule_dirs:
        if folder.is_dir() and not folder.is_symlink():
            _plan_moves(result, layout, folder, planned_targets, notes_stay=False)
    for directory in _v3_type_dirs(layout):
        moving.update(_plan_moves(result, layout, directory, planned_targets, notes_stay=True))

    if layout.rules_dir.is_dir():
        for path in sorted(layout.rules_dir.rglob("*.md")):
            if path.name == "README.md" or path in moving:
                continue  # a moved rule is stripped on its way
            if path.is_symlink() or not is_within(path, layout.root, unresolvable=False):
                result.skipped.append({"path": result._rel(path), "reason": "a symlink or outside the workspace; not rewritten"})
                continue
            try:
                raw = path.read_bytes()
                text = raw.decode("utf-8")
            except (OSError, UnicodeError):
                result.unreadable.append(result._rel(path))
                continue
            in_type_dir = path.parent.parent == layout.rules_dir
            retype = _retype(text, path.parent.name) if in_type_dir else None
            new_text = _set_type(text, retype[1]) if retype else text
            new_text, keys = _strip_derived(new_text)
            if keys or retype:
                result.strips.append(_RuleStrip(path, keys, new_text, raw, retype))
                _record(result, path, raw)


def _plan_blocker(result: MigrationPlan, layout: WorkspaceLayout) -> None:
    """With nothing to apply, refuse with what keeps the upgrade sentinel refusing the
    workspace and how to clear it, instead of reporting it as up to date."""
    from aegis_core.workspace.discovery import refuse_unmigrated_v3, unconverted_rule_files

    if result.refusal or result.pending:
        return
    try:
        refuse_unmigrated_v3(layout.root)
        return  # the sentinel lets it through: up to date
    except WorkspaceError:
        pass
    old_dir = result._rel(layout.legacy_soma_dir)
    reasons: Dict[str, str] = {}
    for entry in result.unmapped:
        reasons[entry["path"]] = f"unmapped type {entry['type']!r}"
    for entry in result.conflicts:
        reasons[entry["path"]] = f"{entry['to']} already exists"
    for entry in result.skipped:
        reasons[entry["path"]] = entry["reason"]
    for rel in result.unreadable:
        reasons.setdefault(rel, "cannot be read")
    left = [result._rel(path) for path in unconverted_rule_files(layout.root)]
    if left:
        listed = ", ".join(f"{rel} ({reasons.get(rel, 'not converted')})" for rel in left)
        result.refusal = (
            f"{len(left)} rule file(s) in {old_dir}/ cannot be converted: {listed}. Aegis refuses this workspace "
            f"while they remain: give each a v4 type or move it into .aegis/rules/<type>/ yourself and run "
            f"aegis migrate again, or, if you no longer need them, rename or remove {old_dir}/"
        )
        return
    result.refusal = (
        f"{old_dir}/ holds nothing aegis migrate converts, and Aegis refuses a directory with {old_dir}/ but no "
        f".aegis/. Check what it holds, then rename or remove it (for example: mv {old_dir} {old_dir}.old), "
        "and run aegis init"
    )


def _same_text(path: Path, content: str) -> bool:
    try:
        return not path.is_symlink() and path.read_bytes() == content.encode("utf-8")
    except OSError:
        return False


# SHA-256 (LF line endings) of every packaged driver template aegis v1.1 through v3.3
# shipped, which v3 `aegis init` copied (shutil.copy2) into .aegis/drivers/. Computed
# from the release tags; the current template is compared at run time as well.
_SHIPPED_DRIVER_SHA256: Dict[str, frozenset] = {
    "rust_ast.py": frozenset({"e8fd2ae38db27d78b48f10e64f3386a304f732c2f00c093fc1604d41957c704b"}),
    "ts_ast.js": frozenset({
        "59a020774d842d23fb1b5ab2969db0d82e0aeab88f6a3821ca3abf4c68a4d5ed",  # v1.1.0-v1.2.1
        "358950b81971ea7d6e2029d3e5e429cfaa53050b324e03742cc9fdb2d8aaad2d",  # v1.3.0-v3.3.0
    }),
    "go_ast.go": frozenset({"5e671a8f8c4fbd00b89c595c720fad4cf4f3c90b67757ab4625ff5df669680e1"}),
}


def _is_shipped_driver(name: str, data: bytes) -> bool:
    """True when ``data`` is byte for byte a driver aegis shipped as ``name`` (CRLF from a
    Windows checkout counts as LF)."""
    from aegis_core.ast.drivers import templates

    digest = _sha256(data.replace(b"\r\n", b"\n"))
    if digest in _SHIPPED_DRIVER_SHA256.get(name, frozenset()):
        return True
    try:
        current = (Path(templates.__file__).resolve().parent / name).read_bytes()
    except OSError:
        return False
    return digest == _sha256(current.replace(b"\r\n", b"\n"))


def _plan_drivers(result: MigrationPlan, drivers: Path) -> None:
    """v3 `aegis init` staged copies of the packaged drivers in .aegis/drivers/; v4 runs
    the templates inside aegis. Only those copies go: unmodified (byte for byte a version
    aegis shipped) and named by no printed driver command. Anything else there is the
    user's and stays; a staged name with other content is reported, since v4 never runs
    it."""
    from aegis_core.ast.detect import LANGUAGE_DEFINITIONS

    if drivers.is_symlink() or not drivers.is_dir():
        result.removals.append(result._rel(drivers))  # a link is removed, never followed
        return
    staged = {c["driver_filename"] for c in LANGUAGE_DEFINITIONS.values() if c.get("driver_filename")}
    commands = [str(value).replace("\\", "/") for section in result.user_config.values() for value in section.values()]
    removable: List[str] = []
    kept: List[str] = []
    customized: List[str] = []
    for item in sorted(p for p in drivers.rglob("*") if p.is_file() or p.is_symlink()):
        rel = result._rel(item)
        named = any(rel in command for command in commands)
        if item.parent != drivers or item.name not in staged or named:
            kept.append(rel)
            continue
        if item.is_symlink():
            removable.append(rel)  # the link goes; what it points at is never read
            _record(result, item)
            continue
        try:
            data = item.read_bytes()
        except OSError:
            result.unreadable.append(rel)
            kept.append(rel)
            continue
        if _is_shipped_driver(item.name, data):
            removable.append(rel)
            _record(result, item, data)
        else:
            customized.append(rel)
            result.skipped.append({
                "path": rel,
                "reason": (
                    f"differs from every {item.name} aegis shipped, so it may hold your changes; left in "
                    "place. v4 runs only its packaged driver for this selector, never a driver file in the "
                    "repository (a driver of your own goes in ~/.aegis/config.json drivers)"
                ),
            })
    if kept or customized:
        result.removals.extend(removable)
        result.left_in_place.extend(kept)
    else:
        result.removals.append(result._rel(drivers))


def _plan_state(result: MigrationPlan, layout: WorkspaceLayout) -> None:
    if not layout.aegis_dir.is_dir():
        return
    known = set()
    for entry in LEGACY_STATE_ENTRIES:
        name = entry.rstrip("/")
        known.add(name)
        if not os.path.lexists(layout.legacy(name)):
            continue
        if name == "drivers":
            _plan_drivers(result, layout.legacy(name))
        else:
            result.removals.append(result._rel(layout.legacy(name)))
    known |= set(LEGACY_CONFIG_ENTRIES)
    for child in sorted(layout.aegis_dir.iterdir()):
        if child.name not in known and child.name not in _V4_ENTRIES:
            result.left_in_place.append(result._rel(child))


def plan(root: Any) -> MigrationPlan:
    """Read the workspace at ``root`` and decide what ``apply`` would do. Writes nothing."""
    layout = WorkspaceLayout(Path(os.fspath(root)).resolve())
    result = MigrationPlan(root=layout.root)
    for directory in (layout.aegis_dir, layout.legacy_soma_dir, layout.state_dir):
        if directory.is_symlink() or not is_within(directory, layout.root, unresolvable=False):
            why = "is a symlink" if directory.is_symlink() else "resolves outside the workspace"
            result.refusal = f"{result._rel(directory)} {why}; aegis migrate reads and writes only inside the workspace"
            return result
    # The lock, the ledger and backups are written in state/; config.json is merged in place.
    entries = sorted(layout.state_dir.iterdir()) if layout.state_dir.is_dir() else []
    for path in entries + [layout.config_file]:
        if path.is_symlink():
            result.refusal = f"{result._rel(path)} is a symlink; aegis migrate reads and writes only inside the workspace"
            return result
    _plan_worktree_ledgers(result, layout)
    if result.refusal:
        return result
    _plan_ledger(result, layout)
    _plan_config(result, layout)
    _plan_rules(result, layout)
    _plan_state(result, layout)
    _plan_not_converted(result, layout)
    result.removals = sorted(set(result.removals))
    _plan_blocker(result, layout)
    return result


# ── Applying ─────────────────────────────────────────────────────────────────

def _backup_dir(layout: WorkspaceLayout) -> Path:
    """Create a new, empty backup directory, 0o700: it will hold copies of keys and receipts."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = 0
    while True:
        candidate = layout.migrate_backup_dir(f"{stamp}-{suffix}" if suffix else stamp)
        try:
            os.mkdir(candidate, 0o700)
        except FileExistsError:  # including a dangling link of that name: never reused
            suffix += 1
            continue
        os.chmod(candidate, 0o700)  # mkdir's mode passes through the umask; this is exact
        return candidate


def _backup(root: Path, backup: Path, path: Path) -> None:
    targets = [path] if path.is_file() or path.is_symlink() else sorted(p for p in path.rglob("*") if p.is_file())
    for item in targets:
        if item.is_symlink():
            continue  # the link itself is removed; what it points at is not ours to copy
        # copy2 semantics for the permission bits: a 0600 key stays 0600 in the backup
        mode = stat.S_IMODE(os.stat(item).st_mode)
        atomic_write_bytes(backup / item.relative_to(root), item.read_bytes(), mode=mode)


def _remove(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif os.path.lexists(path):
        path.unlink()


def _merge_worktree_ledgers(root: Path, sources: List[Tuple[str, Path]]) -> int:
    """Merge the ledgers ``sources`` name into the shared ledger of ``root``, reading them
    again now: a row appended since the plan is merged too. Returns the rows written."""
    from aegis_core.telemetry_engine import ledger

    read: List[_WorktreeLedger] = []
    for label, workspace in sources:
        found = _read_worktree_ledger(label, workspace)
        if found is not None and found.problem is None:
            read.append(found)
    written, duplicates, conflicts = ledger.merge_rows_report(root, [found.rows for found in read])
    if written:
        ledger.append_epoch(root, {
            "migration": "worktree-ledgers",
            "sources": sorted(found.label for found in read),
            "rows": len(written),
            "duplicates": duplicates,
            **({"conflicts": conflicts} if conflicts else {}),
        })
    return len(written)


def apply(migration: MigrationPlan) -> MigrationResult:
    """Execute a plan: back up, write the v4 files, then remove what was converted."""
    from aegis_core.config import update_repo_config
    from aegis_core.telemetry_engine import ledger
    from aegis_core.workspace.scaffold import ensure_runtime_gitignore

    result = MigrationResult(plan=migration)
    if migration.refusal:
        raise MigrationRefused(migration.refusal)
    if not migration.pending:
        return result
    layout = WorkspaceLayout(migration.root)
    root = layout.root
    try:
        state_dir(root)  # what locked() checks first: a link planted since planning refuses here
        ledger_site(root, create=False)  # likewise the shared ledger directory, before anything is written
    except PathTraversalError as exc:
        raise MigrationRefused(str(exc)) from exc
    with locked(root):
        changed = sorted(rel for rel, seen in migration.inputs.items() if _fingerprint(root / rel) != seen)
        if changed:
            raise MigrationRefused(
                f"{', '.join(changed)} changed since the plan was made; nothing was migrated. "
                "Run `aegis migrate` again to plan from the files as they are now."
            )
        writes_config = migration.config is not None and (migration.config_sources or migration.creates_config)
        if writes_config and layout.config_file.is_symlink():
            raise MigrationRefused(
                f"{migration._rel(layout.config_file)} is a symlink; aegis migrate reads and writes only inside the workspace"
            )
        gitignore = layout.aegis_dir / ".gitignore"
        backup = _backup_dir(layout)
        touched = [root / rel for rel in migration.removals]
        touched += [move.source for move in migration.moves] + list(migration.already_moved)
        touched += [strip.path for strip in migration.strips]
        if writes_config:
            touched.append(layout.config_file)  # merged in place below
        if ensure_runtime_gitignore(layout.aegis_dir, dry_run=True) == "dry-run":
            touched.append(gitignore)  # gains "state/" below
        for path in touched:
            if os.path.lexists(path):
                _backup(root, backup, path)
        result.backup = backup

        ensure_runtime_gitignore(layout.aegis_dir)
        if writes_config:
            changes = migration.config_changes
            update_repo_config(root, lambda data: _merge_missing(data, changes))
            result.written.append(layout.config_file.relative_to(root).as_posix())

        if migration.ledger_rows or migration.ledger_sources:
            written = ledger.append_rows(root, migration.ledger_rows)
            ledger.append_epoch(root, {
                "migration": "v3-to-v4",
                "sources": migration.ledger_sources,
                "rows": len(written),
                "backup": backup.relative_to(root).as_posix(),
            })

        if migration.worktree_pending:
            result.merged = _merge_worktree_ledgers(root, migration.worktree_sources)

        moved: List[_RuleMove] = []
        for move in migration.moves:
            if os.path.lexists(move.target):
                continue  # appeared since the check above: never overwrite, keep the source
            atomic_write_text(move.target, move.content)
            moved.append(move)
        for strip in migration.strips:
            atomic_write_bytes(strip.path, strip.content.encode("utf-8"))

        for move in moved:
            if os.path.lexists(move.source):
                move.source.unlink()
        for source in migration.already_moved:
            if os.path.lexists(source):
                source.unlink()
        for rel in migration.removals:
            _remove(root / rel)
    return result


def pending_worktree_rows(root: Any) -> int:
    """How many rows in per-worktree ledgers the shared ledger lacks (0 outside git or when
    nothing is pending); ``aegis migrate --apply`` merges them. Read only."""
    layout = WorkspaceLayout(Path(os.fspath(root)).resolve())
    result = MigrationPlan(root=layout.root)
    try:
        _plan_worktree_ledgers(result, layout)
    except OSError:
        return 0
    return result.worktree_pending
