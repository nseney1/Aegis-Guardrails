"""Rule integrity: git is the witness (v4.3 spec T3)."""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import os
from typing import Any, Callable, Dict, Iterable, List, Mapping, NamedTuple, Optional, Sequence, Tuple

from aegis_core import gitevidence, gitsafe, governance
from aegis_core.config import read_user_config
from aegis_core.errors import AegisError
from aegis_core.lane_ast import pytest_config_view
from aegis_core.match import normalize_path, sets_overlap
from aegis_core.rule_inventory import RuleInventory, RuleInventoryEntry, inventory_rules
from aegis_core.rules import ENFORCEMENT_KEYS, Rule, RuleCache, RuleSet, VALID_ENFORCEMENT, load_rules, workspace_root
from aegis_core.workspace.layout import RULES_RELDIR

__all__ = [
    "BENIGN_KEYS",
    "BaseAnchor",
    "CiReport",
    "EXCLUDED_KEYS",
    "Effective",
    "IntegrityError",
    "LOCAL_HEAD_LABEL",
    "MANDATORY_SLOT_CAP",
    "Unreviewed",
    "Weakening",
    "check_ci",
    "effective",
    "effective_ruleset",
    "policy_view",
    "resolve_base",
    "weakenings",
]

SCHEMA, SOURCE = "aegis.rule_integrity/v1", "aegis check --ci"
LOCAL_HEAD_LABEL, MANDATORY_SLOT_CAP = "local-head, not review-witnessed", 2

EXCLUDED_KEYS = frozenset({"minimum_mode", "impact_weight", "expiry_days", "expiry_sessions", "expired_at"})
BENIGN_KEYS = frozenset({
    "id", "name", "description", "domain", "hypothesis", "prediction", "falsification", "created", "tags",
    "lineage", "triggers", "persona_name", "origin", "expertise", "expertise_domain", "promotion_threshold", "demotion_threshold",
})
_CHECKED_KEYS = frozenset({"detect", "applies_to"})
_KNOWN_KEYS = ENFORCEMENT_KEYS | EXCLUDED_KEYS | BENIGN_KEYS | _CHECKED_KEYS
_FORBID_KINDS = ("imports", "calls", "decorators")
_ENFORCEMENT_ORDER = {name: index for index, name in enumerate(VALID_ENFORCEMENT)}
_GIT_TIMEOUT, _MD, _MISSING = 60.0, ".md", object()


class IntegrityError(AegisError):
    """The base cannot be read, or a blob does not hash to its object id."""


@dataclass(frozen=True)
class BaseAnchor:
    ref: str
    commit: str
    source: str
    witnessed: bool
    label: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ref": self.ref,
            "commit": self.commit,
            "source": self.source,
            "witnessed": self.witnessed,
            "label": self.label,
        }


def _user_base_ref(root: str) -> Optional[str]:
    data = read_user_config(root)
    rules = data.get("rules") if data else None
    ref = rules.get("base_ref") if isinstance(rules, dict) else None
    if isinstance(ref, str) and ref.strip() and not ref.strip().startswith("-"):
        return ref.strip()
    return None


def _origin_merge_base(root: str) -> str:
    # Constant refs need no option guard, and one merge-base resolves both: a failure (no
    # origin/HEAD, no common history, not a repository) means no origin anchor.
    try:
        res = gitsafe.run(["merge-base", "refs/remotes/origin/HEAD", "HEAD"], root)
    except gitsafe.GitError:
        return ""
    return os.fsdecode(res.stdout.strip()) if res.returncode == 0 else ""


def resolve_base(workspace: Any) -> Optional[BaseAnchor]:
    root = workspace_root(workspace)
    # Inside a request (a scan) every reader shares one set of repository facts and the merge base
    # is kept by object id across requests; a lone call asks git only the question it needs.
    shared = gitsafe.in_memo()
    facts = gitevidence.repo_facts(root) if shared else None
    if shared and facts is None:
        return None
    ref = _user_base_ref(root)
    if ref:
        tip = gitsafe.resolve_commit(root, ref)
        if tip:
            # The fork point, as check --ci and the origin/HEAD anchor compare: a rule the ref changed
            # after the branch forked is not an edit of this branch.
            fork = gitevidence.merge_base_with(facts, tip) if shared else gitsafe.merge_base(root, tip, "HEAD")
            note = "" if fork else "; no common history with HEAD, using its tip"
            return BaseAnchor(ref, fork or tip, "user-config", True, f"rules.base_ref {ref} (user config{note})")
    reviewed = gitevidence.merge_base_with(facts) if shared else _origin_merge_base(root)
    if reviewed:
        return BaseAnchor("origin/HEAD", reviewed, "origin-head", True, "merge-base of HEAD and origin/HEAD")
    head = facts.head if facts is not None else gitsafe.head_commit(root)
    if head:
        return BaseAnchor("HEAD", head, "local-head", False, LOCAL_HEAD_LABEL)
    return None


def _run(cwd: str, args: Sequence[str], stdin: Optional[bytes] = None) -> bytes:
    try:
        res = gitsafe.run(list(args), cwd, timeout=_GIT_TIMEOUT, stdin=stdin)
    except gitsafe.GitError as exc:
        raise IntegrityError(str(exc)) from exc
    if res.returncode != 0:
        detail = " ".join(res.stderr.decode("utf-8", "replace").split())[:200]
        raise IntegrityError(f"git {args[0]} failed: {detail}")
    return res.stdout


_DEFAULT_RUN = _run


def _prefix(root: str) -> str:
    try:
        return gitsafe.show_prefix(root)
    except gitsafe.GitError as exc:
        raise IntegrityError(str(exc)) from exc


def _rule_blobs(cwd: str, commit: str) -> Dict[str, str]:
    # Without --full-tree, ls-tree takes and names paths relative to its cwd, the workspace root:
    # a nested workspace needs no prefix lookup. Symlinks and gitlinks are not rules.
    if not commit or commit.startswith("-"):
        raise IntegrityError(f"invalid revision {commit!r}")
    found: Dict[str, str] = {}
    for record in _run(cwd, ["ls-tree", "-r", "-z", commit, "--", RULES_RELDIR]).split(b"\0"):
        meta, sep, raw_path = record.partition(b"\t")
        fields = meta.split()
        path = os.fsdecode(raw_path)
        if sep and len(fields) == 3 and fields[1] == b"blob" and fields[0] != b"120000" and path.lower().endswith(_MD):
            found[path] = fields[2].decode("ascii", "replace")
    return found


def _read_blobs(cwd: str, oids: Iterable[str]) -> Dict[str, bytes]:
    try:
        if _run is not _DEFAULT_RUN:
            wanted = list(dict.fromkeys(oids))
            if not wanted:
                return {}
            out = _run(cwd, ["cat-file", "--batch"], stdin=("\n".join(wanted) + "\n").encode("ascii"))
            return gitsafe._parse_cat_file_batch(out, wanted)
        return gitsafe.read_blobs(cwd, oids, timeout=_GIT_TIMEOUT)
    except gitsafe.GitError as exc:
        raise IntegrityError(str(exc)) from exc


def _fingerprint(entries: Sequence[RuleInventoryEntry]) -> str:
    aggregate = hashlib.sha256(b"aegis-rule-inventory-v1\0")
    for entry in entries:
        aggregate.update(entry.relative_path.encode("utf-8") + b"\0" + bytes.fromhex(entry.digest) + b"\0")
    return aggregate.hexdigest()


def _same_blob(data: bytes, oid: str) -> bool:
    # A CRLF checkout (core.autocrlf) of an LF blob is the reviewed rule: policy_view ignores line endings.
    if gitsafe.blob_id(data, len(oid)) == oid:
        return True
    return b"\r\n" in data and gitsafe.blob_id(data.replace(b"\r\n", b"\n"), len(oid)) == oid


def _inventory_at(root: str, commit: str, working: Optional[RuleInventory] = None,
                  cache: Optional[RuleCache] = None) -> RuleInventory:
    # A commit's listing and a blob's bytes never change; a replaced git seam (tests) reads afresh.
    if cache is not None and _run is _DEFAULT_RUN:
        blobs = cache.listing((os.path.realpath(root), commit), lambda: _rule_blobs(root, commit))
        read = lambda oids: cache.blobs(list(oids), lambda missing: _read_blobs(root, missing))  # noqa: E731
    else:
        blobs, read = _rule_blobs(root, commit), lambda oids: _read_blobs(root, oids)
    present = {e.relative_path: e for e in working.entries} if working is not None else {}
    entries: List[RuleInventoryEntry] = []
    missing: List[Tuple[str, str]] = []
    for path, oid in sorted(blobs.items()):
        local = present.get(path)
        if local is not None and _same_blob(local.content, oid):
            entries.append(local)
        else:
            missing.append((path, oid))
    contents = read([oid for _path, oid in missing])
    for path, oid in missing:
        data = contents[oid]
        entries.append(
            RuleInventoryEntry(
                path,
                os.path.join(root, *path.split("/")),
                data,
                hashlib.sha256(data).hexdigest(),
                len(data),
            )
        )
    entries.sort(key=lambda e: e.relative_path)
    return RuleInventory(tuple(entries), _fingerprint(entries))


def _tree_files(root: str, commit: str) -> List[str]:
    out = _run(root, ["ls-tree", "-r", "-z", "--name-only", commit])
    return sorted(os.fsdecode(p) for p in out.split(b"\0") if p)


def policy_view(rule: Rule) -> Tuple[Any, Any, Any]:
    return (rule.type, dict(rule.meta), rule.body.replace("\r\n", "\n"))


def title_of(rule: Rule) -> str:
    text = rule.id
    for line in rule.body.splitlines():
        stripped = line.strip().lstrip("#").strip()
        if line.lstrip().startswith("#") and stripped:
            text = stripped
            break
    return _one_line(text)


def _one_line(text: str) -> str:
    """Branch-local text an agent reads: one printable line of at most 80 characters."""
    cleaned = " ".join("".join(ch if ch.isprintable() else " " for ch in text).split())
    return cleaned[:77] + "..." if len(cleaned) > 80 else cleaned


@dataclass(frozen=True)
class Weakening:
    code: str
    rule: str
    path: str
    message: str

    def as_dict(self) -> Dict[str, str]:
        return {
            "code": self.code,
            "rule": self.rule,
            "path": self.path,
            "message": self.message,
        }


class _Tree:
    def __init__(self, renames: Optional[Mapping[str, str]] = None) -> None:
        self.renames = renames or {}


def _dotted_covers(kind: str, broad: str, narrow: str) -> bool:
    if broad == narrow:
        return True
    if kind == "imports":
        return narrow.startswith(broad + ".")
    return narrow.endswith("." + broad)


def _forbid_tokens(spec: Any, kind: str = "calls") -> List[str]:
    from aegis_core.ast.schema import _normalize_ast_token

    values = spec.get(kind) if isinstance(spec, Mapping) else spec
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple)):
        return []
    raw = (
        v
        if isinstance(v, str)
        else (str(v.get("name") or "") if isinstance(v, Mapping) else "")
        for v in values
    )
    return [t for t in (_normalize_ast_token(r) for r in raw if r) if t]


_forbid_patterns = _forbid_tokens

class _CallEntry(NamedTuple):
    name: str
    where: Optional[Mapping[str, Any]]
    builtin: bool


def _call_entries(spec: Any) -> List[_CallEntry]:
    """The ``calls`` entries as ``ast.policy._eval_call_entry`` reads them."""
    from aegis_core.ast.schema import _normalize_ast_token

    values = spec.get("calls") if isinstance(spec, Mapping) else spec
    if isinstance(values, str):
        values = [values]
    entries: List[_CallEntry] = []
    for value in values if isinstance(values, (list, tuple)) else ():
        if isinstance(value, str):
            entry = _CallEntry(_normalize_ast_token(value), None, False)
        elif isinstance(value, Mapping):
            where = value.get("where")
            entry = _CallEntry(
                _normalize_ast_token(str(value.get("name") or "")),
                where if isinstance(where, Mapping) and where else None,
                bool(value.get("builtin")),
            )
        else:
            continue
        if entry.name:
            entries.append(entry)
    return entries


def _same_value(a: Any, b: Any) -> bool:
    # Type-strict: YAML ``true`` and ``1`` match different call sites.
    if isinstance(a, Mapping) and isinstance(b, Mapping):
        return set(a) == set(b) and all(_same_value(a[k], b[k]) for k in a)
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(_same_value(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def _call_covers(head: _CallEntry, base: _CallEntry) -> bool:
    if not _dotted_covers("calls", head.name, base.name):
        return False
    if head.builtin and not base.builtin:
        return False
    # A where is a conjunction: a head that keeps a subset of the base conjuncts matches more sites.
    return head.where is None or (
        base.where is not None
        and all(k in base.where and _same_value(c, base.where[k]) for k, c in head.where.items())
    )


def _is_superset(before: Any, after: Any) -> bool:
    if before is None:
        return True
    if after is None:
        return False
    if isinstance(before, (list, tuple)) and isinstance(after, (list, tuple)):
        return all(item in after for item in before)
    return before == after


def _forbid_findings(base: Rule, head: Rule) -> List[str]:
    before, after = base.meta.get("forbid_ast"), head.meta.get("forbid_ast")
    if before is None:
        return []
    if not isinstance(after, dict):
        return ["forbid_ast was removed"]
    lost: List[str] = []
    for kind in _FORBID_KINDS:
        if kind == "calls":
            heads = _call_entries(after)
            for entry in _call_entries(before):
                if not any(_call_covers(other, entry) for other in heads):
                    named = any(_dotted_covers(kind, other.name, entry.name) for other in heads)
                    lost.append(f"call {entry.name!r} is no longer forbidden" + (
                        " everywhere it was (its where or builtin was narrowed)" if named else ""))
            continue
        kept = _forbid_patterns(after, kind)
        for pattern in _forbid_patterns(before, kind):
            if not any(_dotted_covers(kind, other, pattern) for other in kept):
                lost.append(f"{kind[:-1]} {pattern!r} is no longer forbidden")
    return lost


def _level(rule: Rule) -> Tuple[int, int]:
    return rule.rank, _ENFORCEMENT_ORDER.get(rule.enforcement, 0)


_TEST_FILES = "test files"


def _reach_dropped(base: Rule, head: Rule) -> List[str]:
    # target_paths is a union of positive globs, so keeping every base pattern (and not newly
    # skipping tests) is a superset of reach over every file, including ones not yet written.
    kept = {normalize_path(p) for p in head.target_paths}
    dropped = [p for p in base.target_paths if normalize_path(p) not in kept]
    return dropped + ([_TEST_FILES] if head.skips_tests and not base.skips_tests else [])


def _coverage_lost(base: Rule, head: Rule, tree: _Tree) -> List[str]:
    dropped = _reach_dropped(base, head)
    if dropped:
        return [
            "it no longer applies to test files, which the reviewed version covered" if p == _TEST_FILES
            else f"target pattern {p!r} is no longer kept; files it covered, including files this branch adds, "
            "may lose the rule"
            for p in dropped
        ]
    lost = {new for old, new in tree.renames.items() if base.applies_to(old) and not head.applies_to(new)}
    return [f"no longer applies to {path}, which the reviewed version covered" for path in sorted(lost)]


def _key_changes(base: Rule, head: Rule) -> List[str]:
    return sorted(
        str(k)
        for k, v in head.meta.items()
        if k not in _KNOWN_KEYS and not str(k).startswith("_") and base.meta.get(k, _MISSING) != v
    )


def weakenings(base: Rule, head: Optional[Rule], tree: Optional[_Tree] = None) -> List[Weakening]:
    if head is None or not head.ok:
        why = "the rule is gone from the branch" if head is None else f"the rule no longer loads: {head.error}"
        return [
            Weakening(
                "deleted",
                base.id,
                base.path,
                f"{why} (a deletion or an archive, with no same-id rule in its place)",
            )
        ]
    found: List[Weakening] = []
    if _level(head)[0] < _level(base)[0] or _level(head)[1] < _level(base)[1]:
        found.append(
            Weakening(
                "rank",
                base.id,
                head.path,
                f"binds less: rank {base.rank} ({base.enforcement}) became rank {head.rank} ({head.enforcement})",
            )
        )
    for key in _key_changes(base, head):
        found.append(
            Weakening(
                "unknown_key",
                base.id,
                head.path,
                f"new or changed key {key!r} is not one Aegis knows, so it is treated as a weakening",
            )
        )
    for message in _forbid_findings(base, head):
        found.append(Weakening("forbid_ast", base.id, head.path, message))
    if ("detect" in base.meta or "detect" in head.meta) and not _is_superset(
        base.meta.get("detect"), head.meta.get("detect")
    ):
        found.append(
            Weakening("detect", base.id, head.path, "detect is not an exact superset of the reviewed version")
        )
    for message in _coverage_lost(base, head, tree or _Tree()):
        found.append(Weakening("coverage", base.id, head.path, message))
    if base.meta.get("applies_to") != head.meta.get("applies_to"):
        found.append(Weakening("applies_to", base.id, head.path, "applies_to changed"))
    return found


def _stricter(base: Rule, head: Rule) -> bool:
    if weakenings(base, head, None):
        return False
    return (
        any(base.meta.get(k) != head.meta.get(k) for k in ("target_paths", "forbid_ast", "enforcement"))
        or base.type != head.type
    )


@dataclass(frozen=True)
class Unreviewed:
    id: str
    title: str
    change: str
    path: str = ""

    def as_dict(self) -> Dict[str, str]:
        return {
            "id": _one_line(self.id),
            "title": self.title,
            "change": self.change,
        }


@dataclass(frozen=True)
class Effective:
    ruleset: RuleSet
    anchor: Optional[BaseAnchor]
    unreviewed: Tuple[Unreviewed, ...] = ()


def _compose(root: str, head: RuleSet, base: RuleSet, anchor: BaseAnchor) -> Effective:
    base_all = {r.id: r for r in base.rules if r.ok}
    binding = {rule_id: r for rule_id, r in base_all.items() if r.rank >= 2}
    served: List[Rule] = []
    unreviewed: List[Unreviewed] = []
    widened: List[Tuple[int, Rule, Tuple[str, ...]]] = []
    seen_ok, seen_any = set(), set()
    for rule in head.rules:
        seen_any.add(rule.id)
        if not rule.ok:
            served.append(rule)
            continue
        seen_ok.add(rule.id)
        reviewed = binding.get(rule.id)
        if reviewed is None:
            if rule.rank < 2:
                served.append(rule)
            elif rule.id in base_all:
                served.append(base_all[rule.id])
                unreviewed.append(Unreviewed(rule.id, title_of(rule), "changed", rule.path))
            else:
                unreviewed.append(Unreviewed(rule.id, title_of(rule), "new", rule.path))
            continue
        if policy_view(reviewed) == policy_view(rule):
            served.append(rule)
        elif _stricter(reviewed, rule):
            merged = replace(
                reviewed,
                type=rule.type,
                path=rule.path,
                meta={
                    **reviewed.meta,
                    **{k: rule.meta[k] for k in ("target_paths", "forbid_ast", "enforcement") if k in rule.meta},
                },
            )
            kept = {normalize_path(p) for p in reviewed.target_paths}
            added = tuple(p for p in merged.target_paths if normalize_path(p) not in kept)
            if merged.mandatory and added:
                widened.append((len(served), reviewed, added))
            served.append(merged)
            unreviewed.append(Unreviewed(rule.id, title_of(rule), "changed", rule.path))
        else:
            served.append(reviewed)
            unreviewed.append(Unreviewed(rule.id, title_of(rule), "changed", rule.path))
    for rule_id, reviewed in binding.items():
        if rule_id not in seen_ok:
            served.append(reviewed)
            unreviewed.append(
                Unreviewed(
                    rule_id,
                    title_of(reviewed),
                    "broken" if rule_id in seen_any else "removed",
                    reviewed.path,
                )
            )
    # Widening onto paths that may already hold the cap of mandatory rules would crowd one out of
    # a scan (CI flags it as mandatory_cap): serve the reviewed version until that is approved.
    for index, reviewed, added in widened:
        others = [r for r in served if r.ok and r.mandatory and r.id != reviewed.id]
        if sum(1 for o in others if sets_overlap(added, o.target_paths)) >= MANDATORY_SLOT_CAP:
            served[index] = reviewed
    return Effective(
        RuleSet(tuple(served), head.ignored, f"{head.fingerprint}@{anchor.commit}"),
        anchor,
        tuple(unreviewed),
    )


def effective(workspace: Any, cache: Optional[RuleCache] = None) -> Effective:
    root = workspace_root(workspace)
    if cache is not None:
        inventory, head = cache.snapshot(root)
    else:
        inventory = inventory_rules(root)
        head = load_rules(root, inventory=inventory)
    anchor = resolve_base(root)
    if anchor is None:
        return Effective(head, None)

    def load_base() -> Optional[RuleSet]:
        base_inventory = _inventory_at(root, anchor.commit, inventory, cache)
        if base_inventory.fingerprint == inventory.fingerprint:
            return None  # the working rules are the reviewed ones
        if cache is not None and _run is _DEFAULT_RUN:
            return cache.base_rules(root, base_inventory, lambda: load_rules(root, inventory=base_inventory))
        return load_rules(root, inventory=base_inventory)

    # A commit's tree never changes, so these inputs fix the parsed BASE set.
    key = (root, anchor.commit, inventory.fingerprint)
    base = cache.base(key, load_base) if cache is not None else load_base()
    return Effective(head, anchor) if base is None else _compose(root, head, base, anchor)


def effective_ruleset(workspace: Any, cache: Optional[RuleCache] = None) -> RuleSet:
    return effective(workspace, cache).ruleset


@dataclass(frozen=True)
class CiReport:
    base: str
    head: str
    merge_base: str
    rules_checked: int
    weakenings: Tuple[Weakening, ...]
    approval: Optional[Any]
    governance_categories: Tuple[str, ...] = ()
    governance_paths: Tuple[Tuple[str, str], ...] = ()
    signers_at_base: int = 0

    @property
    def governance_gated(self) -> bool:
        """A governance change needs the approval only when the base lists a key to sign it with."""
        return bool(self.governance_categories) and self.signers_at_base > 0

    @property
    def passed(self) -> bool:
        if not self.weakenings and not self.governance_gated:
            return True
        return self.approval is not None and self.approval.valid

    def as_dict(self, workspace: Any = None) -> Dict[str, Any]:
        from datetime import datetime, timezone
        from aegis_core._version import __version__

        return {
            "source": SOURCE,
            "aegis_version": __version__,
            "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scope": {
                "machine": "local",
                "workspace": None if workspace is None else str(workspace),
                "mode": "ci",
                "base": self.base,
                "head": self.head,
                "merge_base": self.merge_base,
            },
            "schema": SCHEMA,
            "status": "pass" if self.passed else "fail",
            "rules_checked": self.rules_checked,
            "weakenings": [w.as_dict() for w in self.weakenings],
            "approval": None if self.approval is None else self.approval.as_dict(workspace),
            "governance": {
                "categories": list(self.governance_categories),
                "paths": [{"path": path, "category": category} for path, category in self.governance_paths],
                "enforced": self.governance_gated,
                "approved": self.governance_gated and self.passed,
            },
        }


def _diff(root: str, base: str, head: str, prefix: Optional[str] = None) -> Tuple[Dict[str, str], List[str]]:
    prefix = _prefix(root) if prefix is None else prefix
    raw = _run(root, ["diff-tree", "-r", "-z", "--name-status", "--no-commit-id", "-M50%", base, head])
    renames: Dict[str, str] = {}
    deleted: List[str] = []
    for status, path, new_path in gitsafe.parse_name_status_z(raw):
        kind, old = status[:1], gitsafe.relative_to_prefix(prefix, path)
        if old is None:
            continue  # outside the workspace (a move into it is an addition)
        new = None if new_path is None else gitsafe.relative_to_prefix(prefix, new_path)
        if kind == "R" and new is not None:
            renames[old] = new
        elif kind in ("D", "R"):
            deleted.append(old)
    return renames, deleted


renamed_rules = _diff


def _cap_findings(head: RuleSet, base: RuleSet, files: Callable[[], List[str]]) -> List[Weakening]:
    already = {r.id: r for r in base.served if r.mandatory}
    mandatory = [r for r in head.served if r.mandatory]
    found: List[Weakening] = []
    for rule in sorted(mandatory, key=lambda r: r.id):
        prior = already.get(rule.id)
        if prior is not None and (prior.target_paths, prior.skips_tests) == (rule.target_paths, rule.skips_tests):
            continue
        for path in rule.matching_files(files()):
            if prior is not None and prior.applies_to(path):
                continue  # only where its reach is new
            crowd = [
                o
                for o in mandatory
                if o.id != rule.id and o.applies_to(path) and (o.id in already or o.id < rule.id)
            ]
            if len(crowd) + 1 > MANDATORY_SLOT_CAP:
                found.append(
                    Weakening(
                        "mandatory_cap",
                        rule.id,
                        rule.path,
                        f"a mandatory rule added where {len(crowd)} already apply (to {path}); a scan gives mandatory rules "
                        f"at most {MANDATORY_SLOT_CAP} slots, so this one crowds out the others",
                    )
                )
                break
    return found


_PYTEST_SECTION_FILES = ("pyproject.toml", "setup.cfg", "tox.ini")
_REGULAR_MODES = ("100644", "100755")


def _same_pytest_view(root: str, merge: str, head: str, path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    before, after = gitsafe.read_blob(root, merge, path), gitsafe.read_blob(root, head, path)
    if before is None or after is None:
        return False
    try:
        return pytest_config_view(name, before) == pytest_config_view(name, after)
    except ValueError:
        return False


def _governance_paths(root: str, merge: str, head: str, prefix: str) -> Tuple[Tuple[str, str], ...]:
    """(path, category) for each changed governance path a signed approval must cover. Edits to the
    checked workspace's own rules (``prefix`` + RULES_RELDIR) are left to the weakening check;
    pyproject.toml, setup.cfg and tox.ini modified as regular files on both sides count only when
    their pytest view differs (a missing or unreadable side counts). --no-renames: a moved
    governance file shows its old name as deleted."""
    own_rules = f"{prefix}{RULES_RELDIR}/"
    found: List[Tuple[str, str]] = []
    for status, old_mode, new_mode, path in gitsafe.diff_entries(root, merge, head):
        gone = status == "D"
        category = governance.category_of(path, deleted=gone)
        if category is None:
            continue
        # Exact case: the weakening check reads the tree by this name, while the category is
        # case-folded (``.AEGIS/rules`` is another workspace's, or a case-insensitive checkout's, rules).
        if category == "rules" and path.startswith(own_rules):
            continue
        # A symlink's blob is its link text, not the file pytest follows the link to, so any side
        # that is not a regular file (a T status, a link, a gitlink) counts whole.
        if (
            status == "M"
            and old_mode in _REGULAR_MODES
            and new_mode in _REGULAR_MODES
            and path.rsplit("/", 1)[-1] in _PYTEST_SECTION_FILES
            and _same_pytest_view(root, merge, head, path)
        ):
            continue
        found.append((path, str(category)))
    return tuple(found)


def check_ci(workspace: Any, base: str, head: str = "HEAD") -> CiReport:
    from aegis_core import human_gate

    root = workspace_root(workspace)
    base_commit = gitsafe.resolve_commit(root, base)
    head_commit = gitsafe.resolve_commit(root, head)
    if not base_commit:
        raise IntegrityError(
            f"cannot resolve the base {base!r} to a commit (fetch it, or with a shallow clone fetch the full history)"
        )
    if not head_commit:
        raise IntegrityError(f"cannot resolve the head {head!r} to a commit")
    merge = gitsafe.merge_base(root, base_commit, head_commit)
    if not merge:
        raise IntegrityError(f"{base!r} and {head!r} share no history (a shallow clone needs fetch-depth: 0)")
    prefix = _prefix(root)
    base_rules = load_rules(root, inventory=_inventory_at(root, merge))
    head_rules = load_rules(root, inventory=_inventory_at(root, head_commit))
    renames, _deleted = _diff(root, merge, head_commit, prefix)
    tree = _Tree(renames)

    found: List[Weakening] = []
    checked = 0
    for rule in base_rules.rules:
        if rule.ok and rule.rank >= 2:
            checked += 1
            found += weakenings(rule, head_rules.get(rule.id), tree)
    reported = {(w.rule, w.code) for w in found}
    for rule in head_rules.rules:
        reviewed = base_rules.get(rule.id)
        reviewed_applies = reviewed.meta.get("applies_to") if reviewed else None
        if (
            rule.ok
            and (rule.id, "applies_to") not in reported
            and reviewed_applies != rule.meta.get("applies_to")
        ):
            found.append(Weakening("applies_to", rule.id, rule.path, "applies_to changed"))
    head_files: List[str] = []

    def files() -> List[str]:
        if not head_files:
            head_files.extend(_tree_files(root, head_commit))
        return head_files

    found += _cap_findings(head_rules, base_rules, files)
    paths = _governance_paths(root, merge, head_commit, prefix)
    order = [name for name, _patterns in governance.CATEGORIES] + [governance.DELETED_TESTS]
    categories = tuple(c for c in order if c in {category for _path, category in paths})
    signers = human_gate.signing_keys_at(root, base_commit) if categories else 0
    approval = None
    if found or (categories and signers):
        try:
            approval = human_gate.find_approval(root, head_commit, base_commit)
        except (human_gate.HumanGateError, gitsafe.GitError):
            approval = None
    return CiReport(base_commit, head_commit, merge, checked, tuple(found), approval, categories, paths, signers)
