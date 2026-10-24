"""Unsigned rule packs: `aegis rule export` and `aegis rule import` (v4.2 #3).

A pack is one JSON document::

    {"v": 1,
     "rules": [{"path": "traps/my-rule.md", "text": "<the rule file>", "sha256": "<of text>"}],
     "sha256": "<digest of the bundle>"}

It carries rule text only: no ledger rows, no fitness, no signature. The digests prove the
pack was not altered after export; they say nothing about who made it, so nothing in a pack
is trusted, and the import is built around that:

- **The path is parsed, never joined.** Each ``path`` must be exactly ``<type dir>/<id>.md``
  (a directory of ``taxonomy.RULE_TYPES``, an id that is a portable file name, lowercase
  ``.md``). Anything else refuses the whole pack. The write target is rebuilt from the
  parsed parts as ``.aegis/rules/<type dir>/<id>.md``; the raw string is never used again.
- **The one loader judges the text.** The entries are loaded as a staged inventory
  (``load_rules(..., inventory=...)``, nothing on disk), and each must yield exactly one
  error-free, unexpired rule with no derived or retired keys, whose id and type are its
  path's.
- **A collision is refused**, and so is the whole pack: an id some rule of the workspace
  already has would make both records errors and every scan fail closed. ``rename`` gives
  the incoming rule a free id (``<id>-imported``, ``-imported-2``, ...) and rewrites its
  frontmatter ``id``; it never hides a pack that contradicts itself (the staged check runs
  before and after).
- **All or nothing.** The plan and the writes happen under the workspace lock; a failed
  write removes what the import created. ``dry_run`` takes no lock and writes nothing.

Export refuses a rule that has derived or retired keys (the stripper is the one
``aegis migrate`` uses): the text that leaves the repository is the file as it is.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from aegis_core import events
from aegis_core.fitness import for_rules
from aegis_core.lifecycle.creation import _require_servable_id
from aegis_core.lifecycle.parsers import validate_rule_id
from aegis_core.migrate import _frontmatter_span, _strip_derived
from aegis_core.primitives import real_key, real_path, strict_loads
from aegis_core.rule_inventory import RuleInventory, RuleInventoryEntry, RuleInventoryError
from aegis_core.rules import Rule, load_rules, workspace_root
from aegis_core.storage import atomic_write_bytes, locked
from aegis_core.taxonomy import DIR_RULE_TYPES, RULE_TYPE_DIRS
from aegis_core.workspace.layout import RULES_RELDIR, WorkspaceLayout, is_aegis_workspace

__all__ = [
    "MAX_ID_LENGTH",
    "MAX_PACK_BYTES",
    "MAX_PACK_RULES",
    "MAX_RULE_BYTES",
    "PACK_VERSION",
    "ImportResult",
    "ImportedRule",
    "PackEntry",
    "PackError",
    "PackPath",
    "PackPathError",
    "Selection",
    "build_pack",
    "bundle_digest",
    "dump_pack",
    "import_pack",
    "load_pack",
    "parse_pack_path",
    "select_rules",
    "text_digest",
    "validate_pack",
]

PACK_VERSION = 1
MAX_PACK_BYTES = 8 * 1024 * 1024
MAX_PACK_RULES = 500
# A rule body is capped at 64 KiB elsewhere (lifecycle.creation); the frontmatter has room on top.
MAX_RULE_BYTES = 128 * 1024
MAX_ID_LENGTH = 128
_BUNDLE_DOMAIN = b"aegis-rule-pack-v1\0"
_BAD_PATH_CHARS = re.compile(r"[\\:\x00-\x1f\x7f]")
_ID_CHARS = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_ID_LINE = re.compile(r"^id[ \t]*:")
# Windows opens CON.md, nul.v2.md... as the device, whatever the extension.
_DEVICE_NAMES = frozenset(
    {"con", "prn", "aux", "nul"} | {f"com{n}" for n in range(1, 10)} | {f"lpt{n}" for n in range(1, 10)}
)
_ENTRY_KEYS = frozenset({"path", "text", "sha256"})
_PACK_KEYS = frozenset({"v", "rules", "sha256"})
_RENAME_SUFFIX = "-imported"
_RENAME_ATTEMPTS = 1000


class PackError(ValueError):
    """A pack that cannot be exported or imported. ``problems`` lists every reason, in order."""

    def __init__(self, problems: Iterable[str]) -> None:
        self.problems: Tuple[str, ...] = tuple(problems)
        super().__init__("; ".join(self.problems))


class PackPathError(ValueError):
    """A pack ``path`` that is not exactly ``<type dir>/<id>.md``."""


@dataclass(frozen=True)
class PackPath:
    """A pack path taken apart: the type directory, its rule type and the rule id."""

    directory: str
    type: str
    id: str


@dataclass(frozen=True)
class PackEntry:
    """One validated pack entry."""

    index: int
    path: str
    parsed: PackPath
    text: str


@dataclass(frozen=True)
class Selection:
    """The rules an export takes, and the ``(id, reason)`` of those it leaves out."""

    rules: Tuple[Rule, ...]
    skipped: Tuple[Tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ImportedRule:
    """One rule an import wrote (or, in a dry run, would write)."""

    path: str  # workspace-relative POSIX
    id: str
    type: str
    renamed_from: Optional[str]
    sha256: str  # of the text as written


@dataclass(frozen=True)
class ImportResult:
    rules: Tuple[ImportedRule, ...]
    dry_run: bool
    pack_sha256: str
    warnings: Tuple[str, ...] = ()


# ── digests ──────────────────────────────────────────────────────────────────

def text_digest(text: str) -> str:
    """sha256 of ``text`` as UTF-8: the digest of a pack entry."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def bundle_digest(entries: Sequence[Mapping[str, Any]]) -> str:
    """The digest of a pack's entries, in order: path, text and entry digest of each."""
    canonical = json.dumps([[e["path"], e["text"], e["sha256"]] for e in entries],
                           ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(_BUNDLE_DOMAIN + canonical.encode("ascii")).hexdigest()


# ── the path ─────────────────────────────────────────────────────────────────

def _check_id(rule_id: str) -> None:
    try:
        _require_servable_id(rule_id)  # README and hidden names are never served
    except ValueError as exc:
        raise PackPathError(str(exc)) from None
    try:
        validate_rule_id(rule_id)  # the lifecycle's own rule: no separator, no '..'
    except ValueError:
        raise PackPathError(f"the id {rule_id!r} contains a path separator or '..' (path traversal)") from None
    if len(rule_id) > MAX_ID_LENGTH or not _ID_CHARS.fullmatch(rule_id):
        raise PackPathError(
            f"the id {rule_id!r} is not a usable rule id: use 1 to {MAX_ID_LENGTH} characters from "
            "A-Z a-z 0-9 . _ - that start with a letter or digit")
    if rule_id.split(".")[0].lower() in _DEVICE_NAMES:
        raise PackPathError(f"the id {rule_id!r} is a reserved device name on Windows")


def parse_pack_path(path: Any) -> PackPath:
    """``<type dir>/<id>.md`` taken apart; PackPathError says why any other shape is refused."""
    if not isinstance(path, str):
        raise PackPathError(f"the path must be a string, not {type(path).__name__}")
    if not path:
        raise PackPathError("the path is empty")
    if _BAD_PATH_CHARS.search(path):
        raise PackPathError("the path contains a backslash, a colon or a control character")
    parts = path.split("/")
    if len(parts) != 2 or not all(parts) or "." in parts or ".." in parts:
        raise PackPathError("the path must be exactly <type dir>/<id>.md (two segments)")
    directory, name = parts
    rule_type = DIR_RULE_TYPES.get(directory)
    if rule_type is None:
        raise PackPathError(
            f"unknown type directory {directory!r} (expected one of {', '.join(sorted(DIR_RULE_TYPES))})")
    if not name.endswith(".md"):
        raise PackPathError("the file name must end in lowercase .md")
    rule_id = name[:-len(".md")]
    _check_id(rule_id)
    return PackPath(directory, rule_type, rule_id)


# ── export ───────────────────────────────────────────────────────────────────

def select_rules(
    workspace: Any, types: Optional[Iterable[str]] = None, min_fitness: Optional[float] = None,
) -> Selection:
    """The rules to export from ``workspace``: those of ``types`` and, with ``min_fitness``,
    those whose fitness in this repository's ledger reaches it (a rule that cannot load has
    none, as in ``aegis rule list``). An expired rule is left out and reported; a rule that
    cannot be served stops the export, so nothing leaves the repository half-checked."""
    root = workspace_root(workspace)
    try:
        ruleset = load_rules(root)
    except RuleInventoryError as exc:
        raise PackError([f"the rules directory cannot be read safely: {exc}"]) from None
    wanted = set(types) if types else None
    candidates = [r for r in ruleset.rules if wanted is None or r.type in wanted]
    if min_fitness is not None:
        fits = for_rules(root, [r for r in candidates if r.ok])
        candidates = [r for r in candidates if r.ok and fits[r.id].score >= min_fitness]
    broken = [f"{r.path}: {r.error}; fix or move it, then export again" for r in candidates if r.error]
    if broken:
        raise PackError(broken)
    chosen = tuple(r for r in candidates if not r.expired)
    if not chosen:
        raise PackError(["no rules to export: none matches the type and fitness filters"])
    return Selection(chosen, tuple((r.id, "expired") for r in candidates if r.expired))


def _export_entry(rule: Rule) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """``(entry, None)`` for a rule that can travel, else ``(None, why not)``."""
    if rule.type not in RULE_TYPE_DIRS:
        return None, f"{rule.path}: it is not in a rule type directory"
    relative = f"{RULE_TYPE_DIRS[rule.type]}/{rule.id}.md"
    try:
        parse_pack_path(relative)
    except PackPathError as exc:
        return None, f"{relative}: {exc}"
    text = rule.raw.decode("utf-8")
    _stripped, removed = _strip_derived(text)
    keys = sorted(set(rule.legacy_keys) | set(removed))
    if keys:
        return None, (f"{relative} still has derived or retired keys ({', '.join(keys)}): "
                      "run aegis migrate --apply, then export again")
    size = len(text.encode("utf-8"))
    if size > MAX_RULE_BYTES:
        return None, f"{relative}: {size} bytes exceeds the {MAX_RULE_BYTES} byte limit"
    return {"path": relative, "text": text, "sha256": text_digest(text)}, None


def build_pack(rules: Iterable[Rule]) -> Dict[str, Any]:
    """The pack for ``rules`` (loaded, unexpired rules): entries in path order, each with the
    digest of its text. PackError lists every rule that cannot travel: an id the importer
    would refuse, derived or retired keys (the text that leaves is the file as it is, so run
    ``aegis migrate`` first) or a rule too large to import."""
    entries: List[Dict[str, Any]] = []
    problems: List[str] = []
    for rule in rules:
        entry, problem = _export_entry(rule)
        if entry is not None:
            entries.append(entry)
        else:
            problems.append(str(problem))
    if problems:
        raise PackError(problems)
    entries.sort(key=lambda entry: entry["path"])
    return {"v": PACK_VERSION, "rules": entries, "sha256": bundle_digest(entries)}


def dump_pack(pack: Mapping[str, Any]) -> bytes:
    """The pack as the bytes `aegis rule export` writes: ASCII JSON, indented, one trailing newline."""
    return (json.dumps(pack, indent=2, ensure_ascii=True) + "\n").encode("ascii")


# ── reading a pack ───────────────────────────────────────────────────────────

def _shape_problem() -> str:
    return 'a pack is a JSON object with exactly the keys "v", "rules" and "sha256"'


def _content_problem(label: str, shown: str, text: Any, digest: Any) -> List[str]:
    """What is wrong with an entry's text and digest, as messages (empty when nothing is).
    ``label`` names the entry for a wrong type, ``shown`` (the path too, when it parsed) for
    a wrong content."""
    if not isinstance(text, str):
        return [f'{label}: "text" must be a string']
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        return [f'{label}: "sha256" must be 64 lowercase hex digits']
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError:
        return [f"{shown}: the text is not valid UTF-8"]
    found = []
    if len(encoded) > MAX_RULE_BYTES:
        found.append(f"{shown}: {len(encoded)} bytes exceeds the {MAX_RULE_BYTES} byte limit")
    if hashlib.sha256(encoded).hexdigest() != digest:
        found.append(f"{shown}: the text does not match its sha256")
    return found


def validate_pack(pack: Any) -> List[PackEntry]:
    """The entries of ``pack``, or PackError listing everything wrong with it: its keys and
    version, the shape, path, size and digest of every entry, repeated paths and ids, and the
    bundle digest."""
    if not isinstance(pack, dict) or set(pack) != _PACK_KEYS:
        raise PackError([_shape_problem()])
    version = pack["v"]
    if type(version) is not int or version != PACK_VERSION:
        raise PackError([f"unsupported pack version {version!r}: this aegis reads version {PACK_VERSION}"])
    rules = pack["rules"]
    if not isinstance(rules, list):
        raise PackError(['"rules" must be a list'])
    if not rules:
        raise PackError(["the pack holds no rules"])
    if len(rules) > MAX_PACK_RULES:
        raise PackError([f"the pack holds more than {MAX_PACK_RULES} rules"])

    problems: List[str] = []
    entries: List[PackEntry] = []
    by_path: Dict[str, int] = {}
    by_id: Dict[str, str] = {}
    hashable = True
    for index, entry in enumerate(rules):
        label = f"rules[{index}]"
        if not isinstance(entry, dict) or set(entry) != _ENTRY_KEYS:
            problems.append(f'{label}: an entry is an object with exactly the keys "path", "text" and "sha256"')
            hashable = False
            continue
        path, text, digest = entry["path"], entry["text"], entry["sha256"]
        hashable = hashable and all(isinstance(entry[k], str) for k in _ENTRY_KEYS)
        parsed: Optional[PackPath] = None
        shown = label
        try:
            parsed = parse_pack_path(path)
            shown = f"{label} ({path})"
        except PackPathError as exc:
            problems.append(f"{label} ({path!r}): {exc}")
        content = _content_problem(label, shown, text, digest)
        if content:
            problems.extend(content)
        elif parsed is not None:
            # Casefolded: on a case-insensitive file system Foo.md and foo.md are one file.
            folded = parsed.id.casefold()
            if path in by_path:
                problems.append(f"{shown}: the path appears twice in the pack")
            elif folded in by_id:
                problems.append(f"{shown}: the id {parsed.id!r} is also used by {by_id[folded]}")
            else:
                by_path[path] = index
                by_id[folded] = path
                entries.append(PackEntry(index, path, parsed, text))
    if hashable and bundle_digest(rules) != pack["sha256"]:
        problems.append("the pack sha256 does not match its rules: it was altered after export")
    if problems:
        raise PackError(problems)
    return entries


def load_pack(data: bytes) -> Dict[str, Any]:
    """Parse and validate the bytes of a pack file; PackError lists why it is refused."""
    if len(data) > MAX_PACK_BYTES:
        raise PackError([f"the pack exceeds {MAX_PACK_BYTES} bytes"])
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise PackError(["the pack is not valid UTF-8"]) from None
    try:
        pack = strict_loads(text)  # a second value would let the digest cover one reading and the importer another
    except RecursionError:
        raise PackError(["the pack is not valid JSON: nested too deeply"]) from None
    except ValueError as exc:
        raise PackError([f"the pack is not valid JSON: {exc}"]) from None
    validate_pack(pack)
    return pack


# ── import ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class _Planned:
    index: int
    source: str  # the pack's path, for messages
    directory: str
    type: str
    id: str
    text: str
    renamed_from: Optional[str] = None

    @property
    def relative(self) -> str:
        return f"{RULES_RELDIR}/{self.directory}/{self.id}.md"

    @property
    def data(self) -> bytes:
        return self.text.encode("utf-8")


def _with_id(text: str, new_id: str) -> str:
    """``text`` with its top-level frontmatter ``id`` line set to ``new_id`` (a rule without
    one takes its id from its file name); every other byte stays."""
    if text.startswith("﻿"):
        return "﻿" + _with_id(text[1:], new_id)
    lines = text.splitlines(keepends=True)
    span = _frontmatter_span(lines)
    if span is None:
        return text
    start, end = span
    for i in range(start, end):
        bare = lines[i].rstrip("\r\n")
        if _ID_LINE.match(bare):
            lines[i] = f"id: {new_id}{lines[i][len(bare):]}"
            return "".join(lines)
    return text


def _staged_problems(root: str, planned: Sequence[_Planned]) -> List[str]:
    """What the one loader says of ``planned`` loaded as a staged inventory: each entry must
    be exactly one error-free, unexpired rule with no derived or retired keys, carrying the
    id and type of its path."""
    staged = []
    for item in planned:
        data = item.data
        staged.append(RuleInventoryEntry(
            relative_path=item.relative,
            absolute_path=os.path.join(root, *item.relative.split("/")),
            content=data,
            digest=hashlib.sha256(data).hexdigest(),
            size=len(data),
        ))
    staged.sort(key=lambda entry: entry.relative_path)
    ruleset = load_rules(root, inventory=RuleInventory(entries=tuple(staged), fingerprint="staged"))
    found: Dict[str, List[Rule]] = {}
    for rule in ruleset.rules:
        found.setdefault(rule.path, []).append(rule)
    problems = []
    for item in planned:
        label = f"rules[{item.index}] ({item.source})"
        rules = found.get(item.relative, [])
        if len(rules) != 1:
            problems.append(f"{label}: the loader found {len(rules)} rules for it, expected exactly one")
            continue
        rule = rules[0]
        if rule.error:
            problems.append(f"{label}: {rule.error}")
        elif rule.legacy_keys:
            problems.append(f"{label}: the rule still has derived or retired keys ({', '.join(rule.legacy_keys)}): "
                            "run aegis migrate on the exporting repository")
        elif rule.expired:
            problems.append(f"{label}: the rule is expired (expired_at), so it would not be served")
        elif rule.id != item.id or rule.type != item.type:
            problems.append(f"{label}: it loads as {rule.type} {rule.id}, not {item.type} {item.id}")
    return problems


def _free_id(rule_id: str, taken: set) -> Optional[str]:
    """``<id>-imported``, then ``-imported-2``..., the first whose casefold is not in ``taken``
    (casefolded ids); None when none is usable."""
    for attempt in range(1, _RENAME_ATTEMPTS + 1):
        candidate = rule_id + _RENAME_SUFFIX + ("" if attempt == 1 else f"-{attempt}")
        if len(candidate) > MAX_ID_LENGTH:
            return None
        if candidate.casefold() not in taken:
            return candidate
    return None


def _plan(root: str, entries: Sequence[PackEntry], rename: bool) -> List[_Planned]:
    planned = [_Planned(e.index, e.path, e.parsed.directory, e.parsed.type, e.parsed.id, e.text) for e in entries]
    invalid = _staged_problems(root, planned)
    if invalid:
        raise PackError(invalid)
    try:
        existing = load_rules(root)
    except RuleInventoryError as exc:
        raise PackError([f"the rules directory cannot be read safely: {exc}"]) from None
    holders: Dict[str, str] = {}
    for rule in existing.rules:
        holders.setdefault(rule.id.casefold(), rule.path)
    taken = set(holders) | {item.id.casefold() for item in planned}
    final: List[_Planned] = []
    refused: List[str] = []
    for item in planned:
        label = f"rules[{item.index}] ({item.source})"
        holder = holders.get(item.id.casefold())
        if holder is None:
            final.append(item)
        elif not rename:
            refused.append(f"{label}: the id {item.id!r} is already used by {holder}; "
                           "import with --rename to keep both")
        else:
            fresh = _free_id(item.id, taken)
            if fresh is None:
                if len(item.id) + len(_RENAME_SUFFIX) > MAX_ID_LENGTH:
                    why = f"{item.id + _RENAME_SUFFIX!r} is longer than {MAX_ID_LENGTH} characters"
                else:
                    why = f"{_RENAME_ATTEMPTS} candidates are taken"
                refused.append(f"{label}: no usable renamed id: {why}")
            else:
                taken.add(fresh.casefold())
                final.append(_Planned(item.index, item.source, item.directory, item.type, fresh,
                                      _with_id(item.text, fresh), renamed_from=item.id))
    if refused:
        raise PackError(refused)
    if any(item.renamed_from for item in final):
        # The rewrite is checked like the pack was: it must not leave a rule the loader refuses.
        broken = _staged_problems(root, final)
        if broken:
            raise PackError(broken)
    final.sort(key=lambda item: item.relative)
    return final


def _write(root: str, planned: Sequence[_Planned]) -> None:
    """Write every planned rule under the held workspace lock, or none: a failure removes the
    files and the directories this call created."""
    rules_dir = WorkspaceLayout(Path(root)).rules_dir
    real_rules = real_path(rules_dir)
    created_files: List[Path] = []
    created_dirs: List[Path] = []

    def make_dir(directory: Path) -> None:
        missing = []
        probe = directory
        while not os.path.lexists(probe):
            missing.append(probe)
            probe = probe.parent
        for path in reversed(missing):
            path.mkdir()
            created_dirs.append(path)

    try:
        for item in planned:
            directory = rules_dir / item.directory
            target = directory / f"{item.id}.md"
            if os.path.lexists(target):
                raise PackError([f"rules[{item.index}] ({item.source}): {item.relative} already exists"])
            make_dir(directory)
            if real_key(directory) != os.path.normcase(os.path.join(real_rules, item.directory)):  # None: refused
                raise PackError([f"rules[{item.index}] ({item.source}): refusing to write outside {RULES_RELDIR}/"])
            try:
                atomic_write_bytes(target, item.data)
            except OSError as exc:
                raise PackError([f"writing {item.relative} failed ({exc.strerror or exc}); "
                                 "no rule was imported"]) from None
            created_files.append(target)
    except BaseException:
        for path in created_files:
            try:
                os.unlink(path)
            except OSError:
                pass
        for path in reversed(created_dirs):
            try:
                path.rmdir()
            except OSError:
                pass
        raise


def _result(planned: Sequence[_Planned], pack: Mapping[str, Any], dry_run: bool,
            warnings: Sequence[str] = ()) -> ImportResult:
    rules = tuple(ImportedRule(item.relative, item.id, item.type, item.renamed_from, text_digest(item.text))
                  for item in planned)
    return ImportResult(rules, dry_run, pack["sha256"], tuple(warnings))


def import_pack(workspace: Any, pack: Mapping[str, Any], *, rename: bool = False,
                dry_run: bool = False) -> ImportResult:
    """Import ``pack`` (as `load_pack` returns it) into the Aegis workspace ``workspace``.

    PackError (nothing written) lists why the pack is refused. A real import appends one
    ``pack_import`` event; a failed append is a warning on the result, never an undone import.
    """
    root = Path(os.fspath(workspace)).resolve()
    if not is_aegis_workspace(root):
        raise PackError([f"not an Aegis workspace (no .aegis/ in {root}); run aegis init"])
    entries = validate_pack(pack)
    # Planned once without the lock, so a refused import leaves no trace (taking the lock
    # creates .aegis/state), and again under it, the plan that counts.
    planned = _plan(str(root), entries, rename)
    if dry_run:
        return _result(planned, pack, dry_run=True)
    with locked(root):
        planned = _plan(str(root), entries, rename)
        _write(str(root), planned)
    types = Counter(item.type for item in planned)
    detail = {"rules": len(planned), "renamed": sum(1 for i in planned if i.renamed_from),
              "types": dict(sorted(types.items())), "pack_sha256": pack["sha256"]}
    warnings: List[str] = []
    try:
        events.append(root, "pack_import", "imported", detail)
    except Exception as exc:  # a metric never undoes an import
        warnings.append(f"the pack_import event could not be recorded ({type(exc).__name__}: {exc})")
    return _result(planned, pack, dry_run=False, warnings=warnings)
