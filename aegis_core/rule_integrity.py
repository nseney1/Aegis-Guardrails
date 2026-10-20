"""Rule integrity: git is the witness (v4.3 spec T3)."""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import os
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from aegis_core import gitsafe
from aegis_core.config import read_user_config
from aegis_core.errors import AegisError
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


def resolve_base(workspace: Any) -> Optional[BaseAnchor]:
    root = workspace_root(workspace)
    if gitsafe.toplevel(root) is None:
        return None
    ref = _user_base_ref(root)
    if ref:
        commit = gitsafe.resolve_commit(root, ref)
        if commit:
            return BaseAnchor(ref, commit, "user-config", True, f"rules.base_ref {ref} (user config)")
    reviewed = gitsafe.merge_base(root, "refs/remotes/origin/HEAD", "HEAD")
    if reviewed:
        return BaseAnchor("origin/HEAD", reviewed, "origin-head", True, "merge-base of HEAD and origin/HEAD")
    head = gitsafe.head_commit(root)
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


def _rule_blobs(cwd: str, commit: str) -> Dict[str, str]:
    try:
        entries = gitsafe.tree_blobs(cwd, commit, paths=(RULES_RELDIR,), timeout=_GIT_TIMEOUT)
    except gitsafe.GitError as exc:
        raise IntegrityError(str(exc)) from exc
    return {
        path: oid
        for path, (_mode, oid) in entries.items()
        if path.lower().endswith(_MD)
    }


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


def _inventory_at(root: str, commit: str, working: Optional[RuleInventory] = None) -> RuleInventory:
    blobs = _rule_blobs(root, commit)
    present = {e.relative_path: e for e in working.entries} if working is not None else {}
    entries: List[RuleInventoryEntry] = []
    missing: List[Tuple[str, str]] = []
    for path, oid in sorted(blobs.items()):
        local = present.get(path)
        if local is not None and gitsafe.blob_id(local.content, len(oid)) == oid:
            entries.append(local)
        else:
            missing.append((path, oid))
    contents = _read_blobs(root, (oid for _path, oid in missing))
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
    def __init__(
        self,
        root: Optional[str],
        commit: Optional[str],
        renames: Optional[Mapping[str, str]] = None,
        deleted: Iterable[str] = (),
    ) -> None:
        self._root = root
        self._commit = commit
        self._files: Optional[List[str]] = None
        self.renames = renames or {}
        self.deleted = frozenset(deleted)

    @property
    def files(self) -> List[str]:
        if self._files is None:
            self._files = _tree_files(self._root, self._commit) if self._root and self._commit else []
        return self._files

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
        else (str(v.get("name") or v.get("call") or "") if isinstance(v, Mapping) else "")
        for v in values
    )
    return [t for t in (_normalize_ast_token(r) for r in raw if r) if t]


_forbid_patterns = _forbid_tokens


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
        kept = _forbid_patterns(after, kind)
        for pattern in _forbid_patterns(before, kind):
            if not any(_dotted_covers(kind, other, pattern) for other in kept):
                lost.append(f"{kind[:-1]} {pattern!r} is no longer forbidden")
    if isinstance(before, dict):
        for kind in sorted(k for k in before if k not in _FORBID_KINDS):
            if not _is_superset(before.get(kind), after.get(kind)):
                lost.append(f"forbid_ast option {kind!r} is not an exact superset")
    return lost


def _level(rule: Rule) -> Tuple[int, int]:
    return rule.rank, _ENFORCEMENT_ORDER.get(rule.enforcement, 0)


def _coverage_lost(base: Rule, head: Rule, tree: _Tree) -> List[str]:
    if base.target_paths == head.target_paths and base.skips_tests == head.skips_tests:
        candidates: Iterable[str] = list(tree.renames)
    else:
        candidates = tree.files
    lost: List[str] = []
    for old in candidates:
        if old in tree.deleted and old not in tree.renames:
            continue
        new = tree.renames.get(old, old)
        if base.applies_to(old) and not head.applies_to(new):
            lost.append(new)
    return sorted(set(lost))


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
    for path in _coverage_lost(base, head, tree or _Tree(None, None)):
        found.append(
            Weakening(
                "coverage",
                base.id,
                head.path,
                f"no longer applies to {path}, which the reviewed version covered",
            )
        )
    if base.meta.get("applies_to") != head.meta.get("applies_to"):
        found.append(Weakening("applies_to", base.id, head.path, "applies_to changed"))
    return found


def _stricter(base: Rule, head: Rule, tree: _Tree) -> bool:
    if weakenings(base, head, tree):
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
            "id": self.id,
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
    tree = _Tree(root, anchor.commit)
    served: List[Rule] = []
    unreviewed: List[Unreviewed] = []
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
        elif _stricter(reviewed, rule, tree):
            merged = replace(
                reviewed,
                type=rule.type,
                path=rule.path,
                meta={
                    **reviewed.meta,
                    **{k: rule.meta[k] for k in ("target_paths", "forbid_ast", "enforcement") if k in rule.meta},
                },
            )
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
    base_inventory = _inventory_at(root, anchor.commit, inventory)
    if base_inventory.fingerprint == inventory.fingerprint:
        return Effective(head, anchor)
    return _compose(root, head, load_rules(root, inventory=base_inventory), anchor)


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

    @property
    def passed(self) -> bool:
        return not self.weakenings or (self.approval is not None and self.approval.valid)

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
        }


def _diff(root: str, base: str, head: str) -> Tuple[Dict[str, str], List[str]]:
    raw = _run(root, ["diff-tree", "-r", "-z", "--name-status", "--no-commit-id", "-M50%", base, head])
    renames: Dict[str, str] = {}
    deleted: List[str] = []
    for status, path, new_path in gitsafe.parse_name_status_z(raw):
        kind = status[:1]
        if kind == "R" and new_path is not None:
            renames[path] = new_path
        elif kind == "D":
            deleted.append(path)
    return renames, deleted


renamed_rules = _diff


def _cap_findings(head: RuleSet, base: RuleSet, files: Callable[[], List[str]]) -> List[Weakening]:
    already = {r.id for r in base.served if r.mandatory}
    mandatory = [r for r in head.served if r.mandatory]
    found: List[Weakening] = []
    for rule in sorted(mandatory, key=lambda r: r.id):
        if rule.id in already:
            continue
        for path in rule.matching_files(files()):
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
    base_rules = load_rules(root, inventory=_inventory_at(root, merge))
    head_rules = load_rules(root, inventory=_inventory_at(root, head_commit))
    renames, deleted = _diff(root, merge, head_commit)
    tree = _Tree(root, merge, renames, deleted)

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
    approval = None
    if found:
        try:
            approval = human_gate.find_approval(root, head_commit, base_commit)
        except (human_gate.HumanGateError, gitsafe.GitError):
            approval = None
    return CiReport(base_commit, head_commit, merge, checked, tuple(found), approval)
