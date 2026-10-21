"""The one rule loader (ADR 0005 AD-3 L1, defense #19, v4.3 spec §10.3).

``load_rules(workspace)`` is how every part of Aegis reads rules: aegis scan, aegis
check, status, sync, list, lifecycle and the SDK. It is a projection of
``rule_inventory.inventory_rules`` (the race-detecting byte snapshot, which stays the
fingerprint), so it never reads a rule file twice and never follows a link.

One policy, applied everywhere:

- A rule is ``.aegis/rules/<type dir>/<id>.md``, where the directory is one of the six
  of ``taxonomy.RULE_TYPES``. Its id is the file stem; its type is its directory.
- Anything under a hidden directory (``.archive``) is out of service and skipped.
- A markdown file that is never served (one outside a type directory, a ``README.md``,
  a hidden file, a ``.MD`` extension) is an error record if it looks like a rule (a
  ``type``, ``target_paths`` or ``forbid_ast`` key, or frontmatter that cannot be read),
  so a rule left in a v3 directory such as ``walls/`` cannot silently stop applying.
  Otherwise a README is documentation and is skipped; anything else is reported as
  ignored.
- A file that cannot be decoded or parsed, whose frontmatter ``id`` or ``type``
  disagrees with its name or directory, whose id another rule also uses, that spells
  an enforcement key in a way v4 does not read (``paths``, ``globs``, ``target_path``,
  ``enforce``, ...) or that sets ``expired_at`` on a rank 2+ rule (a gate, an invariant, or
  any rule declaring ``enforcement: gate``: such a rule is retired by a reviewed change, never
  by expiry) becomes a record carrying ``error``. Callers that serve rules (scan,
  check, the SDK scan) fail closed on error records; listing callers show them, and
  reporting callers count them. Nothing is dropped silently.
- Derived counters (``fitness``, ``triggers: 12``, ...) and keys v3 tooling wrote that
  v4 never reads (``enforcement_artifact``) are not rule content: they are removed from
  ``meta`` and listed in ``legacy_keys`` (``aegis migrate`` strips them).
- A rule with ``expired_at`` is loaded but not served (``Rule.expired``).
- ``applies_to`` is a known key (v4.4 scopes rules with it). Until then a rule carrying it is
  served as an unscoped rule: only ``target_paths`` decide where it applies.
- A ``forbid_ast`` rule without ``target_paths`` applies to every file (``**``).
- Where a rule applies is ``Rule.applies_to``: its target_paths through the one matcher,
  except that a ``forbid_ast`` gate skips test files unless its patterns name tests.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import hashlib
import os
import threading
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

from aegis_core.match import first_match, is_test_path, matching_files
from aegis_core.rule_inventory import RuleInventory, RuleInventoryEntry, inventory_rules
from aegis_core.taxonomy import DIR_RULE_TYPES, RULE_TYPES, legacy_rule_type
from aegis_core.workspace import as_workspace
from aegis_core.workspace.layout import RULES_RELDIR
from aegis_core.yaml_engine.frontmatter import split_frontmatter
from aegis_core.yaml_engine.parser import AegisYAMLError, parse_yaml_subset

__all__ = [
    "DERIVED_KEYS",
    "ENFORCEMENT_KEYS",
    "RETIRED_KEYS",
    "VALID_ENFORCEMENT",
    "rank_of",
    "Ignored",
    "Rule",
    "RuleCache",
    "RuleSet",
    "is_derived",
    "is_legacy_key",
    "load_rules",
    "lf_digest",
    "validate_rule_names",
    "workspace_root",
]

VALID_ENFORCEMENT = ("advisory", "mechanical", "gate")

# Keys that decide what a rule enforces and where.
ENFORCEMENT_KEYS = frozenset({"type", "enforcement", "target_paths", "forbid_ast", "expired_at", "applies_to"})
# Spellings of an enforcement key that v4 does not read, with the key to use instead. A
# rule using one would apply in the wrong place or nowhere, so it is an error. Compared
# case-insensitively without "-" and "_" (``targetPaths``, ``Target-Paths``), and any such
# variant of an ENFORCEMENT_KEYS name counts too. Only these: a key that merely mentions
# a path or enforcement (``source_path``, ``enforcement_notes``) is descriptive.
_ENFORCEMENT_ALIASES = {
    "target_paths": (
        "paths", "path", "glob", "globs", "applyto", "targets", "targetpath",
        "targetglob", "targetglobs", "targetfile", "targetfiles", "targetpattern",
        "targetpatterns", "filepatterns", "pathpatterns", "patterns", "files", "include",
        "includes",
    ),
    "enforcement": ("enforce", "enforced", "enforcementlevel", "enforcementtier", "enforcementmode"),
    "forbid_ast": ("forbid", "forbidden", "forbiddenast", "forbidasts", "astforbid"),
    "expired_at": ("expired", "expiredon", "expireddate"),
}
# Enforcement keys v4 no longer reads (D14): a rule relying on one would never apply.
_RETIRED_ENFORCEMENT_KEYS = frozenset({"ast_triggers", "planned_symbols"})
_RETIRED_HINT = "no longer read: v4 matches files by target_paths and gates code with forbid_ast"


def _squash(key: str) -> str:
    return key.lower().replace("-", "").replace("_", "")


_ALIAS_TARGET = {
    **{_squash(key): key for key in ENFORCEMENT_KEYS},
    **{alias: key for key, aliases in _ENFORCEMENT_ALIASES.items() for alias in aliases},
}
_RETIRED_SQUASHED = {_squash(key) for key in _RETIRED_ENFORCEMENT_KEYS}

# Keys v3 tooling wrote into rule files that v4 never reads (v3 tier escalation recorded
# the gate script it generated). Like derived counters they are ignored, reported for
# migrate and stripped by it, so a v3 rule keeps being served.
RETIRED_KEYS = frozenset({"enforcement_artifact"})

# Frontmatter keys derived from the ledger; rule files never carry them (v4.3 §10.2).
DERIVED_KEYS = frozenset({
    "fitness", "triggers", "true_positives", "false_positives", "last_trigger_date",
    "last_triggered", "score", "fitness_score", "tp", "fp", "tp_rate", "fp_rate",
})
_TIMESTAMP_KEYS = frozenset({"last_trigger_date", "last_triggered"})
_RULE_SIGNAL_KEYS = ("type", "target_paths", "forbid_ast")
_NO_FRONTMATTER = "no frontmatter metadata"
_UNTERMINATED = "unterminated YAML frontmatter (no closing --- line)"


def rank_of(rule_type: Optional[str], enforcement: Any) -> int:
    """How strongly a rule binds: 3 for a ``gate`` type, 2 for an ``invariant`` type or any
    rule declaring ``enforcement: gate``, 1 otherwise. Rank 2+ rules are the ones git (the
    reviewed BASE) witnesses (``aegis_core.rule_integrity``) and that never expire."""
    if rule_type == "gate":
        return 3
    if rule_type == "invariant" or enforcement == "gate":
        return 2
    return 1


def is_derived(key: str, value: Any) -> bool:
    """Whether ``key: value`` is a ledger-derived counter. Only counter-shaped values count:
    ``triggers: [documentation_edit]`` is a rule's list of trigger keywords, and stays."""
    if key not in DERIVED_KEYS:
        return False
    if key == "fitness":
        return isinstance(value, (dict, int, float)) or value is None
    if key in _TIMESTAMP_KEYS:
        return value is None or isinstance(value, str) or hasattr(value, "isoformat")
    if isinstance(value, bool):
        return False
    if value is None or isinstance(value, (int, float)):
        return True
    try:
        float(str(value))
        return True
    except ValueError:
        return False


def is_legacy_key(key: str, value: Any) -> bool:
    """Whether ``key: value`` is not rule content: a derived counter or a RETIRED_KEYS key."""
    return key in RETIRED_KEYS or is_derived(key, value)


def lf_digest(content: bytes) -> str:
    """sha256 of ``content`` with CRLF normalized to LF: the same rule hashes the same on
    a Windows checkout (core.autocrlf) and a Linux one."""
    return hashlib.sha256(content.replace(b"\r\n", b"\n")).hexdigest()


@dataclass(frozen=True)
class Rule:
    """One rule file as loaded. ``error`` is set when it cannot be served as written."""

    id: str
    path: str  # workspace-relative POSIX path
    type: Optional[str]  # from its directory; None outside a rule type directory
    meta: Mapping[str, Any]  # frontmatter without derived counters
    body: str
    digest: str  # lf_digest of the file bytes
    error: Optional[str] = None
    legacy_keys: Tuple[str, ...] = ()  # derived counters and retired keys the file still has
    raw: bytes = field(default=b"", repr=False, compare=False)

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def expired(self) -> bool:
        return bool(self.meta.get("expired_at"))

    @property
    def served(self) -> bool:
        """Loaded cleanly and not expired: scan and check apply it."""
        return self.ok and not self.expired

    @property
    def target_paths(self) -> Tuple[str, ...]:
        """The patterns of the files this rule applies to, as every surface matches them.

        A forbid_ast rule that names none applies to every file (``**``): that is where
        aegis check has always enforced it, so scan, telemetry and coverage say so too.
        Any other rule without target_paths matches no file.
        """
        value = self.meta.get("target_paths")
        if isinstance(value, str):
            patterns: Tuple[str, ...] = (value,) if value.strip() else ()
        elif isinstance(value, (list, tuple)):
            patterns = tuple(p for p in value if isinstance(p, str) and p.strip())
        else:
            patterns = ()
        if not patterns and "forbid_ast" in self.meta:
            return ("**",)
        return patterns

    @property
    def skips_tests(self) -> bool:
        """A forbid_ast gate does not apply to test files unless its patterns name tests:
        tests exercise what gates forbid (an ``eval`` in the test of an eval guard)."""
        if "forbid_ast" not in self.meta:
            return False
        return not any("tests/" in p.replace("\\", "/") or "test_" in p for p in self.target_paths)

    def applies_to(self, path: str) -> bool:
        """Whether this rule applies to the workspace-relative ``path``: the one answer
        aegis check, scan, telemetry, coverage and the grade all use."""
        if self.skips_tests and is_test_path(path):
            return False
        return first_match(self.target_paths, path) is not None

    def matching_files(self, files: Iterable[str]) -> List[str]:
        """The ``files`` this rule applies to, normalized, in order, each once."""
        found = matching_files(self.target_paths, files)
        return [f for f in found if not is_test_path(f)] if self.skips_tests else found

    @property
    def enforcement(self) -> str:
        value = self.meta.get("enforcement")
        return value if isinstance(value, str) and value else "advisory"

    @property
    def rank(self) -> int:
        """1, 2 or 3: see ``rank_of``."""
        return rank_of(self.type, self.meta.get("enforcement"))

    @property
    def mandatory(self) -> bool:
        """Gates and invariants by type, and any rule that declares ``enforcement: gate``."""
        spec = RULE_TYPES.get(self.type or "")
        return bool(spec and spec.mandatory) or self.enforcement == "gate"

    def as_dict(self) -> Dict[str, Any]:
        """The frontmatter plus ``type``, ``_name``/``_path`` (and ``_error``), as list payloads show it."""
        data: Dict[str, Any] = dict(self.meta)
        if self.type is not None:
            data["type"] = self.type  # its directory: a rule need not repeat it in frontmatter
        data["_name"] = self.id
        data["_path"] = self.path
        if self.error is not None:
            data["_error"] = self.error
        return data


@dataclass(frozen=True)
class Ignored:
    """A markdown file under ``.aegis/rules`` that is not a rule, and why."""

    path: str
    reason: str


@dataclass(frozen=True)
class RuleSet:
    """Every rule record of a workspace, plus the files that are not rules."""

    rules: Tuple[Rule, ...]
    ignored: Tuple[Ignored, ...] = ()
    fingerprint: str = ""

    def __iter__(self) -> Iterator[Rule]:
        return iter(self.rules)

    def __len__(self) -> int:
        return len(self.rules)

    @property
    def errors(self) -> Tuple[Rule, ...]:
        return tuple(r for r in self.rules if not r.ok)

    @property
    def served(self) -> Tuple[Rule, ...]:
        return tuple(r for r in self.rules if r.served)

    @property
    def needs_migrate(self) -> Tuple[Rule, ...]:
        """Rules whose files still carry derived counters or retired keys (``aegis migrate`` strips them)."""
        return tuple(r for r in self.rules if r.legacy_keys)

    def get(self, rule_id: str) -> Optional[Rule]:
        """The rule with ``rule_id`` that loaded cleanly, or None."""
        for rule in self.rules:
            if rule.ok and rule.id == rule_id:
                return rule
        return None


def workspace_root(workspace: Any) -> str:
    """The absolute root of ``workspace``: a path, a string or a Workspace."""
    if not isinstance(workspace, (str, os.PathLike)):
        workspace = workspace.root
    return os.path.abspath(os.fspath(workspace))


def _stem(relative: str) -> str:
    return os.path.splitext(relative.rsplit("/", 1)[-1])[0]


def _target_paths_error(value: Any) -> Optional[str]:
    if value is None or isinstance(value, str):
        return None
    if isinstance(value, list) and all(isinstance(p, str) for p in value):
        return None
    return "target_paths must be a glob pattern or a list of glob patterns"


def _unknown_enforcement_keys(meta: Mapping[str, Any]) -> List[str]:
    """Each alias or retired enforcement key of ``meta``, with what to do about it."""
    found = []
    for key in meta:
        # A leading underscore marks a tool's own annotation (_path, _name), never a setting.
        if not isinstance(key, str) or key in ENFORCEMENT_KEYS or key.startswith("_"):
            continue
        squashed = _squash(key)
        if squashed in _RETIRED_SQUASHED:
            found.append(f"{key!r} ({_RETIRED_HINT})")
        elif squashed in _ALIAS_TARGET:
            found.append(f"{key!r} (use {_ALIAS_TARGET[squashed]})")
    return sorted(found)


def _parse(entry: RuleInventoryEntry, rule_type: Optional[str], directory: str) -> Rule:
    relative = entry.relative_path
    stem = _stem(relative)
    digest = lf_digest(entry.content)

    def broken(message: str, meta: Optional[Mapping[str, Any]] = None) -> Rule:
        return Rule(stem, relative, rule_type, dict(meta or {}), "", digest, message, raw=entry.content)

    try:
        text = entry.content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        return broken(f"invalid UTF-8: {exc}")
    status, fm_text, body = split_frontmatter(text)
    if status == "unterminated":
        return broken(_UNTERMINATED)
    if status == "none" or not (fm_text or "").strip():
        return broken(_NO_FRONTMATTER)
    try:
        meta = parse_yaml_subset(fm_text.strip())
    except (AegisYAMLError, RecursionError) as exc:
        return broken(f"malformed YAML frontmatter: {exc}")
    if not isinstance(meta, dict) or not meta:
        return broken(_NO_FRONTMATTER)

    counters = tuple(sorted(k for k, v in meta.items() if is_legacy_key(k, v)))
    clean = {k: v for k, v in meta.items() if k not in counters}
    problems: List[str] = []
    declared_id = clean.get("id")
    if declared_id is not None and declared_id != stem:
        problems.append(f"id {declared_id!r} does not match the file name {stem!r}")
    declared_type = clean.get("type")
    if rule_type is not None and declared_type is not None and declared_type != rule_type:
        problem = f"type {declared_type!r} does not match its directory {directory!r} ({rule_type})"
        if legacy_rule_type(declared_type) == rule_type:
            problem += f"; aegis migrate rewrites it to {rule_type!r}"
        problems.append(problem)
    enforcement = clean.get("enforcement")
    if enforcement is not None and enforcement not in VALID_ENFORCEMENT:
        problems.append(f"unknown enforcement {enforcement!r} (expected one of {', '.join(VALID_ENFORCEMENT)})")
    paths_error = _target_paths_error(clean.get("target_paths"))
    if paths_error:
        problems.append(paths_error)
    unknown = _unknown_enforcement_keys(clean)
    if unknown:
        problems.append(f"unknown enforcement-relevant key(s) {', '.join(unknown)}")
    if clean.get("expired_at") and rank_of(rule_type, enforcement) >= 2:
        problems.append("expired_at is not allowed on a rank 2+ rule (a gate, an invariant or enforcement: gate): "
                        "retire it with a reviewed change, not by expiry")
    return Rule(
        id=stem,
        path=relative,
        type=rule_type,
        meta=clean,
        body=body.strip(),
        digest=digest,
        error="; ".join(problems) or None,
        legacy_keys=counters,
        raw=entry.content,
    )


def _looks_like_rule(rule: Rule, any_frontmatter: bool = False) -> bool:
    # A file with no frontmatter at all is a note. Frontmatter that cannot be read may
    # hold any key, so it counts as a rule; so does any frontmatter in a v3 type
    # directory, where v3 served every file as a rule of that directory's type.
    if rule.error == _NO_FRONTMATTER:
        return False
    if any_frontmatter or not rule.ok:
        return True
    return any(key in rule.meta for key in _RULE_SIGNAL_KEYS)


def _unserved(
    entry: RuleInventoryEntry, directory: str, why: str, fix: str, ignored: bool = True,
    any_frontmatter: bool = False,
) -> Tuple[Optional[Rule], Optional[Ignored]]:
    """A markdown file the loader never serves: an error record when it looks like a rule;
    otherwise an ``Ignored`` record, or nothing when ``ignored`` is False (a README)."""
    rule = _parse(entry, None, directory)
    if _looks_like_rule(rule, any_frontmatter):
        message = f"not served: {why} ({fix})"
        if not rule.ok:
            message = f"{message}; {rule.error}"
        return Rule(rule.id, rule.path, None, rule.meta, rule.body, rule.digest, message, rule.legacy_keys, rule.raw), None
    return None, (Ignored(entry.relative_path, f"not a rule: {why}") if ignored else None)


def _classify(entry: RuleInventoryEntry, parts: List[str]) -> Tuple[Optional[Rule], Optional[Ignored], Optional[str]]:
    """Where a file under .aegis/rules stands: (error record, ignored record, rule type).
    A rule type means the file is a rule of that type, to be parsed."""
    name = parts[-1]
    expected = f"expected {RULES_RELDIR}/<{', '.join(sorted(DIR_RULE_TYPES))}>/<id>.md"
    if name.lower() == "readme.md":
        rule, _ = _unserved(entry, parts[0], "a README is documentation, never a rule",
                            "rename it to <id>.md", ignored=False)
        return rule, None, None
    if name.startswith("."):
        return _unserved(entry, parts[0], "a hidden file is never a rule",
                         f"rename it, or move it to {RULES_RELDIR}/.archive/ to retire it") + (None,)
    if not name.endswith(".md"):
        return _unserved(entry, parts[0], "rule files end in lowercase .md",
                         f"rename it to {os.path.splitext(name)[0]}.md") + (None,)
    rule_type = DIR_RULE_TYPES.get(parts[0]) if len(parts) == 2 else None
    if rule_type is not None:
        return None, None, rule_type
    if len(parts) == 1:
        return _unserved(entry, "", "it is not in a rule type directory", expected) + (None,)
    if parts[0] in DIR_RULE_TYPES:
        return _unserved(entry, parts[0], f"rules are not loaded from subdirectories of {parts[0]}/", expected) + (None,)
    legacy = legacy_rule_type(parts[0])
    if legacy is not None:
        fix = f"a v3 type directory: aegis migrate moves its rules to {RULES_RELDIR}/{RULE_TYPES[legacy].directory}/"
        return _unserved(entry, parts[0], f"{parts[0]}/ is not a rule type directory", fix,
                         any_frontmatter=True) + (None,)
    return _unserved(entry, parts[0], f"{parts[0]}/ is not a rule type directory", expected) + (None,)


def load_rules(workspace: Any, inventory: Optional[RuleInventory] = None) -> RuleSet:
    """Load every rule of ``workspace`` (a path or a Workspace).

    Raises RuleInventoryError when the rules tree cannot be read safely (a symlink, an
    unreadable directory, a file changed mid-read): no partial set is ever returned.
    """
    root = workspace_root(workspace)
    snapshot = inventory if inventory is not None else inventory_rules(root)
    prefix = RULES_RELDIR + "/"
    loaded: List[Rule] = []
    ignored: List[Ignored] = []
    for entry in snapshot.entries:
        relative = entry.relative_path
        if not relative.startswith(prefix):
            continue
        parts = relative[len(prefix):].split("/")
        if any(p.startswith(".") for p in parts[:-1]):
            continue  # a hidden directory (.archive) keeps rules out of service on purpose
        rule, skipped, rule_type = _classify(entry, parts)
        if rule_type is not None:
            rule = _parse(entry, rule_type, parts[0])
        if rule is not None:
            loaded.append(rule)
        if skipped is not None:
            ignored.append(skipped)

    by_id: Dict[str, List[int]] = {}
    for index, rule in enumerate(loaded):
        by_id.setdefault(rule.id, []).append(index)
    for rule_id, indexes in by_id.items():
        if len(indexes) < 2:
            continue
        paths = [loaded[i].path for i in indexes]
        for i in indexes:
            rule = loaded[i]
            others = ", ".join(p for p in paths if p != rule.path)
            message = f"duplicate rule id {rule_id!r} (also {others})"
            if rule.error:
                message = f"{message}; {rule.error}"
            loaded[i] = Rule(rule.id, rule.path, rule.type, rule.meta, rule.body, rule.digest, message,
                             rule.legacy_keys, rule.raw)
    return RuleSet(tuple(loaded), tuple(ignored), snapshot.fingerprint)


def validate_rule_names(rule_names: List[str], workspace: Any) -> List[str]:
    """The names in ``rule_names`` that are not the id of a rule that loads cleanly, in
    order (empty when every name is valid). ``workspace`` is a Workspace, or a path the
    workspace is resolved from."""
    ws = as_workspace(workspace)
    if not rule_names:
        return []
    known = {rule.id for rule in load_rules(ws).rules if rule.ok}
    return [name for name in rule_names if name not in known]


class RuleCache:
    """Parsed rules per workspace, reused while the inventory fingerprint is unchanged.

    The inventory (the byte snapshot) is taken on every call, so an edit is always seen;
    only parsing is skipped. A rule is never excluded here: what load_rules returns, the
    cache returns.
    """

    _MAX_WORKSPACES = 8
    _MAX_LISTINGS = 16
    _MAX_BLOB_BYTES = 8 * 1024 * 1024

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: Dict[str, Tuple[str, RuleSet]] = {}
        self._bases: Dict[Tuple[str, ...], Optional[RuleSet]] = {}
        # What BASE serving reads from git, keyed by ids that never change: the rule listing of a
        # commit, blob bytes by object id (verified when read) and the RuleSet of a BASE inventory.
        self._base_sets: Dict[Tuple[str, str], RuleSet] = {}
        self._listings: "OrderedDict[Tuple[str, str], Dict[str, str]]" = OrderedDict()
        self._blobs: "OrderedDict[str, bytes]" = OrderedDict()
        self._blob_bytes = 0

    def get(self, workspace: Any) -> RuleSet:
        return self.snapshot(workspace)[1]

    def snapshot(self, workspace: Any) -> Tuple[RuleInventory, RuleSet]:
        """The byte snapshot taken now and the rules parsed from it (reused while the
        fingerprint is unchanged), for a caller that also compares the bytes."""
        key = workspace_root(workspace)
        snapshot = inventory_rules(key)
        with self._lock:
            cached = self._entries.get(key)
            if cached is not None and cached[0] == snapshot.fingerprint:
                return snapshot, cached[1]
        ruleset = load_rules(key, inventory=snapshot)
        with self._lock:
            if key not in self._entries and len(self._entries) >= self._MAX_WORKSPACES:
                self._entries.pop(next(iter(self._entries)))
            self._entries[key] = (snapshot.fingerprint, ruleset)
        return snapshot, ruleset

    def _memo(self, store: Dict[Any, Any], key: Any, load: Callable[[], Any]) -> Any:
        with self._lock:
            if key in store:
                return store[key]
        value = load()
        with self._lock:
            if key not in store and len(store) >= self._MAX_WORKSPACES:
                store.pop(next(iter(store)))
            store[key] = value
        return value

    def base(self, key: Tuple[str, ...], load: Callable[[], Optional[RuleSet]]) -> Optional[RuleSet]:
        """``load()`` memoised on ``key``, which must name every input it reads (aegis_core.rule_integrity
        keys the parsed BASE rules on the workspace, the anchor commit and the working fingerprint)."""
        return self._memo(self._bases, key, load)

    def base_rules(self, root: str, inventory: RuleInventory, load: Callable[[], RuleSet]) -> RuleSet:
        """``load()``, the rules parsed from a BASE ``inventory``, once per inventory fingerprint."""
        return self._memo(self._base_sets, (root, inventory.fingerprint), load)

    def listing(self, key: Tuple[str, str], load: Callable[[], Dict[str, str]]) -> Dict[str, str]:
        """``load()`` (a commit's ``{path: blob id}``), kept for the last 16 keys."""
        with self._lock:
            if key in self._listings:
                self._listings.move_to_end(key)
                return dict(self._listings[key])
        found = load()
        with self._lock:
            self._listings[key] = dict(found)
            while len(self._listings) > self._MAX_LISTINGS:
                self._listings.popitem(last=False)
        return found

    def blobs(self, oids: Sequence[str], load: Callable[[List[str]], Dict[str, bytes]]) -> Dict[str, bytes]:
        """The bytes of ``oids``; ``load`` (which verifies them) is asked only for those not kept."""
        wanted = list(dict.fromkeys(oids))
        with self._lock:
            found = {oid: self._blobs[oid] for oid in wanted if oid in self._blobs}
            for oid in found:
                self._blobs.move_to_end(oid)
        missing = [oid for oid in wanted if oid not in found]
        if missing:
            read = load(missing)
            found.update(read)
            with self._lock:
                for oid in missing:
                    if oid in read and oid not in self._blobs and len(read[oid]) <= self._MAX_BLOB_BYTES:
                        self._blobs[oid] = read[oid]
                        self._blob_bytes += len(read[oid])
                while self._blob_bytes > self._MAX_BLOB_BYTES:
                    self._blob_bytes -= len(self._blobs.popitem(last=False)[1])
        return found

    def invalidate(self) -> None:
        with self._lock:
            self._entries.clear()
            self._bases.clear()
            self._base_sets.clear()
            self._listings.clear()
            self._blobs.clear()
            self._blob_bytes = 0
