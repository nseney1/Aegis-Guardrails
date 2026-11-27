"""Approval modes anchored in a resolved base commit, with a candidate-only tightening ratchet.

The candidate is validated independently. Unknown targets and unmatched branches
use the strictest declared mode; no map preserves the legacy gate.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Mapping, Optional

from aegis_core import gitsafe, human_gate, primitives
from aegis_core.diagnostic_messages import (
    MESSAGE_TEMPLATES, MESSAGE_OWNERS, GuidanceMessage, MessageRow, finding_message,
    clip_rendered_text, guidance_value, receipt_value,
)
from aegis_core.redaction import MAX_GUIDANCE_CHARS, command_token as command_token
from aegis_core.workspace.layout import AEGIS_DIRNAME

__all__ = ["BaseUnavailable", "InvalidApprovalPolicy", "PolicyUnavailable", "Policy", "parse_policy", "mode_for", "read_policy",
           "resolve_policy", "BaseResolution", "resolve_comparison", "resolve_base", "policy_present", "push_base",
           "guidance_value", "GuidanceMessage", "MessageRow", "finding_message", "receipt_value", "MESSAGE_TEMPLATES",
           "MESSAGE_OWNERS", "clip_rendered_text", "ungated_targets"]

CONFIG_PATH = f"{AEGIS_DIRNAME}/config.json"
MAX_CONFIG_BYTES = 64 * 1024
MAX_PATTERNS = 256
_MAX_BASE_CHARS = MAX_GUIDANCE_CHARS
_MAX_REMOTE_BYTES = 64 * 1024
_MAX_REMOTE_NAMES = 256
MODES = ("none", "review", "signature")
PERMITTED_MODES = ("none", "review")
FULL_OID = re.compile(r"[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?")
_TARGET_TABLE = (("refs/heads/", "branch"), ("refs/remotes/", "remote"))
INVALID_DETAIL = (f"invalid_approval_policy: {CONFIG_PATH} key 'approvals' must be a non-empty object "
                  "of branch names, prefix/** or * mapped to none, review or signature "
                  "(at most 256 entries, 255 characters per branch); next_action: fix the committed configuration")
BASE_UNAVAILABLE_ACTION = "fetch the push's before commit (fetch-depth) and re-run"
BASE_UNAVAILABLE_DETAIL = f"base_unavailable: {BASE_UNAVAILABLE_ACTION}"
EXPLICIT_BASE_UNAVAILABLE_DETAIL = "base_unavailable: explicit base cannot resolve to a commit"
COMPARISON_UNAVAILABLE_DETAIL = "comparison_unavailable: comparison must include changes before the head"
POLICY_UNAVAILABLE_ACTION = "fetch or repair the repository objects and re-run"
POLICY_UNAVAILABLE_DETAIL = f"invalid_approval_policy: cannot read {CONFIG_PATH}; next_action: {POLICY_UNAVAILABLE_ACTION}"


def unresolved_base_hint(selector: str) -> str:
    """Describe a failed comparison without introducing shell-active data."""
    label = guidance_value(selector, prose=True)
    origin = "fetch origin. " if selector.startswith(("origin/", "refs/remotes/origin/")) else ""
    if not command_token(selector, MAX_GUIDANCE_CHARS) or selector != label:
        return f"cannot resolve the base. {origin}fetch it or pass the full commit id. Base selector: {label}."
    return f"cannot resolve the base {label}; {origin}fetch it or pass the full commit id"


class BaseUnavailable(ValueError):
    """A comparison cannot establish a usable pinned base."""

    def __init__(self, detail=BASE_UNAVAILABLE_DETAIL, *, explicit_base=None, comparison_base=None, code="base_unavailable"):
        super().__init__(detail)
        self.explicit_base = explicit_base
        self.comparison_base = comparison_base
        self.code = code


class InvalidApprovalPolicy(ValueError):
    """Fixed refusal; repository-selected keys, values and parser errors are never echoed."""


class PolicyUnavailable(InvalidApprovalPolicy):
    """Git I/O cannot establish either a policy or the absence of one."""


def _target_name(name: Any) -> Optional[str]:
    """HEAD is a ref indirection, never a proven landing branch."""
    return name if human_gate.is_branch_name(name) and name != "HEAD" else None


def _remote_branch(root: Any, tail: str) -> Optional[str]:
    """Use the uniquely longest configured remote prefix, including slash names."""
    result = gitsafe.run(["remote"], root)
    data = result.stdout
    if result.returncode != 0 or len(data) > _MAX_REMOTE_BYTES:
        raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL)
    if not data:
        return None
    if not data.endswith(b"\n") or data.count(b"\n") > _MAX_REMOTE_NAMES:
        raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL)
    names = []
    for raw in data[:-1].split(b"\n"):
        if len(raw) > _MAX_BASE_CHARS:
            raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL)
        raw = raw.removesuffix(b"\r")  # Git may use CRLF on Windows.
        if not raw or b"\0" in raw or b"\r" in raw:
            raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL)
        name = raw.decode("utf-8")
        if gitsafe.run(["check-ref-format", "refs/remotes/" + name + "/branch"], root).returncode != 0:
            raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL)
        names.append(name)
    matches = [name for name in names if tail.startswith(name + "/")]
    if not matches:
        return None
    longest = max(map(len, matches))
    best = [name for name in matches if len(name) == longest]
    return tail[len(best[0]) + 1:] if len(best) == 1 else None


def parse_policy(raw: Mapping[str, Any]) -> Optional[dict[str, str]]:
    if "approvals" not in raw:
        return None
    value = raw["approvals"]
    if not isinstance(value, dict) or not value or len(value) > MAX_PATTERNS:
        raise InvalidApprovalPolicy(INVALID_DETAIL)
    for pattern, mode in value.items():
        if not isinstance(pattern, str) or len(pattern) > 258 or not isinstance(mode, str) or mode not in MODES:
            raise InvalidApprovalPolicy(INVALID_DETAIL)
        branch = pattern[:-3] if pattern.endswith("/**") else pattern
        if pattern != "*" and not human_gate.is_branch_name(branch):
            raise InvalidApprovalPolicy(INVALID_DETAIL)
    return dict(value)


def _branch_commit(root: Any, ref: str) -> Optional[str]:
    """Exact branch refs only; Git's DWIM tag lookup is never evidence of a branch."""
    try:
        result = gitsafe.run(["symbolic-ref", "-q", ref], root)
        if result.returncode == 0:
            if len(result.stdout) > _MAX_BASE_CHARS:
                raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL)
            target = result.stdout.removesuffix(b"\n").removesuffix(b"\r")
            if b"\0" in target or b"\n" in target or b"\r" in target or not target.startswith(tuple(prefix.encode("ascii") for prefix, _kind in _TARGET_TABLE)):
                raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL)
            ref = target.decode("utf-8")
        oid = gitsafe.read_ref(root, ref)
    except gitsafe.RefNameError:
        return None
    except (gitsafe.GitError, UnicodeError) as exc:
        raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL) from exc
    return gitsafe.resolve_commit(root, oid) if oid else None


@dataclass(frozen=True)
class BaseResolution:
    commit: Optional[str] = None
    target: Optional[str] = None
    kind: str = "unavailable"
    ref: Optional[str] = None


def resolve_comparison(root: Any, selector: Any, *, discovered: bool = False,
                       commit: Optional[str] = None) -> BaseResolution:
    """Pin once, then map Git's full ref through the sole target table.

    Explicit inputs retain Git revision semantics. Discovery may select only
    qualified branches or an event's full commit identity; only a discovered
    origin/BRANCH may fall back to its local branch, with unknown identity.
    """
    if not isinstance(selector, str) or not selector or len(selector) > _MAX_BASE_CHARS:
        return BaseResolution()
    if "\0" in selector:
        return BaseResolution()
    try:
        selector.encode("utf-8")
    except UnicodeError:
        return BaseResolution()
    full_oid = FULL_OID.fullmatch(selector)
    # An exact, Git-verified object identity is named as an object expression:
    # a coincidental branch named after its hash must not upgrade UNKNOWN later.
    named, fallback = selector + "^{commit}" if full_oid else selector, False
    try:
        if commit is not None:
            if not isinstance(commit, str) or not FULL_OID.fullmatch(commit):
                return BaseResolution()
            pinned = gitsafe.resolve_commit(root, commit)
            if pinned != commit:
                return BaseResolution()
        elif discovered and not full_oid:
            if selector.startswith("origin/"):
                refs = ("refs/remotes/" + selector, "refs/heads/" + selector[len("origin/"):])
            elif selector.startswith(tuple(prefix for prefix, _kind in _TARGET_TABLE)):
                refs = (selector,)
            elif not selector.startswith("refs/"):
                refs = ("refs/heads/" + selector,)
            else:
                return BaseResolution()
            pinned = None
            for index, ref in enumerate(refs):
                pinned = _branch_commit(root, ref)
                if pinned:
                    named, fallback = ref, index > 0
                    break
        else:
            pinned = gitsafe.resolve_commit(root, selector)
        if not pinned:
            return BaseResolution()
        if not isinstance(pinned, str) or not FULL_OID.fullmatch(pinned):
            raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL)
        if full_oid and pinned.lower() != selector.lower():
            return BaseResolution()
        result = gitsafe.run(["rev-parse", "--symbolic-full-name", "--verify", "--end-of-options", named], root)
        if len(result.stdout) > _MAX_BASE_CHARS:
            raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL)
        raw = result.stdout.removesuffix(b"\n").removesuffix(b"\r")
        if not raw:
            return BaseResolution(pinned, kind="revision")
        if result.returncode != 0 or b"\0" in raw or b"\n" in raw or b"\r" in raw:
            raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL)
        ref = raw.decode("utf-8")
        if not ref.startswith("refs/"):
            # Some Git versions name pseudorefs literally. Let Git confirm the
            # same commit, then normalize them to the table's unknown row.
            if gitsafe.resolve_commit(root, ref) == pinned:
                return BaseResolution(pinned, kind="revision")
            raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL)
        if gitsafe.run(["check-ref-format", ref], root).returncode != 0:
            raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL)
        kind, target = ("tag" if ref.startswith("refs/tags/") else "other"), None
        for prefix, ref_kind in _TARGET_TABLE:
            if ref.startswith(prefix):
                kind = ref_kind
                name = ref[len(prefix):]
                name = _target_name(_remote_branch(root, name) if kind == "remote" else name)
                if not fallback and name is not None and _branch_commit(root, ref) == pinned:
                    target = name
                break
        return BaseResolution(pinned, target, "fallback" if fallback else kind, ref)
    except (gitsafe.GitError, UnicodeError) as exc:
        raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL) from exc


def resolve_base(root: Any, base: Any, *, discovered: bool = False) -> Optional[str]:
    """Compatibility entry point for callers needing only the pinned commit."""
    return resolve_comparison(root, base, discovered=discovered).commit


def mode_for(policy: Mapping[str, str], target: Optional[str]) -> str:
    target = _target_name(target)
    if target is not None:
        if target in policy:
            return policy[target]
        prefixes = [key for key in policy if key.endswith("/**") and target.startswith(key[:-2])]
        if prefixes:
            return policy[max(prefixes, key=len)]
        if "*" in policy:
            return policy["*"]
    return max(policy.values(), key=MODES.index)


def _decode_policy(data: bytes, strict: bool) -> Optional[dict[str, str]]:
    try:
        raw = primitives.strict_loads(data.decode("utf-8-sig"))
    except (UnicodeError, ValueError, RecursionError) as exc:
        if not strict:
            # Duplicate/nonfinite JSON can still declare a map. Recognize that
            # declaration without accepting the permissive decoder's result.
            try:
                candidate = json.loads(data.decode("utf-8-sig"))
            except (UnicodeError, ValueError, RecursionError):
                return None
            if not isinstance(candidate, dict) or "approvals" not in candidate:
                return None
        raise InvalidApprovalPolicy(INVALID_DETAIL) from exc
    if not isinstance(raw, dict):
        if strict:
            raise InvalidApprovalPolicy(INVALID_DETAIL)
        return None
    return parse_policy(raw)


def _commit_read(root, commit, key, produce):
    """Only successful reads keyed by immutable objects may survive within a run."""
    if not isinstance(commit, str) or not FULL_OID.fullmatch(commit):
        return produce()
    return gitsafe.memoized((str(root), commit, "approval_policy", *key), produce)


def read_policy(root: Any, commit: str, *, strict: bool = True) -> Optional[dict[str, str]]:
    """Read only immutable Git objects; bound the blob before allocating or parsing it.

    Git failures also become the documented policy refusal, without raw Git output.
    No candidate-controlled filesystem path is opened.
    """
    try:
        entries = _commit_read(root, commit, ("tree",),
                               lambda: gitsafe.tree_blobs(root, commit, paths=(CONFIG_PATH,), include_symlinks=True))
    except gitsafe.GitError as exc:
        raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL) from exc
    entry = entries.get(CONFIG_PATH)
    if entry is None:
        return None
    mode, oid = entry
    if mode not in ("100644", "100755"):
        if strict:
            raise InvalidApprovalPolicy(INVALID_DETAIL)
        return None
    try:
        data = _commit_read(root, commit, ("blob", oid), lambda: gitsafe.read_object(root, oid, MAX_CONFIG_BYTES))
    except gitsafe.GitError as exc:
        try:
            oversized = gitsafe.blob_sizes(root, (oid,))[oid] > MAX_CONFIG_BYTES
        except (gitsafe.GitError, KeyError):
            raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL) from exc
        if oversized:
            if strict:
                raise InvalidApprovalPolicy(INVALID_DETAIL) from exc
            return None  # known oversized bytes cannot introduce an effective legacy policy
        raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL) from exc
    return _decode_policy(data, strict)


def policy_present(root: Any, revision: Any) -> bool:
    """Only a declared map (valid or malformed), never unusable legacy bytes, selects policy mode."""
    commit = (gitsafe.resolve_commit(root, revision) if isinstance(revision, str) and len(revision) <= 64
              and FULL_OID.fullmatch(revision) else resolve_base(root, revision))
    if commit and isinstance(revision, str) and FULL_OID.fullmatch(revision) \
            and commit.lower() != revision.lower():
        raise PolicyUnavailable(POLICY_UNAVAILABLE_DETAIL)
    return policy_present_at(root, commit)


def policy_present_at(root: Any, commit: Optional[str]) -> bool:
    """The presence probe for a commit already pinned by the caller."""
    if not commit:
        return False
    try:
        return read_policy(root, commit, strict=False) is not None
    except PolicyUnavailable:
        raise
    except InvalidApprovalPolicy:
        return True


def push_base(root: Any, before: Any, fallback: Any, head: Any, *, explicit: bool = False, label: Any = None,
              resolved: Optional[BaseResolution] = None, pinned_head: Optional[str] = None) -> Any:
    """Pin a policy-enabled push's base; a missing predecessor cannot authorize itself at HEAD."""
    creation = isinstance(before, str) and FULL_OID.fullmatch(before) and not before.strip("0")
    if creation and not explicit:
        return fallback  # explicitly permitted branch-creation fallback
    previous = (gitsafe.resolve_commit(root, before) if not explicit and isinstance(before, str)
                and FULL_OID.fullmatch(before) else None)
    prior_policy = policy_present_at(root, previous)
    fallback_commit = resolved.commit if resolved is not None else resolve_base(root, fallback)
    if creation and fallback_commit:
        return fallback_commit  # explicit branch-creation fallback is pinned too
    head_commit = pinned_head or (gitsafe.resolve_commit(root, head) if isinstance(head, str) else None)
    candidate = fallback_commit if explicit else previous
    in_play = prior_policy or policy_present_at(root, head_commit) or policy_present_at(root, fallback_commit)
    if not in_play:
        return fallback
    comparison = gitsafe.merge_base(root, candidate, head_commit) if candidate and head_commit else None
    if not candidate:
        raise BaseUnavailable(EXPLICIT_BASE_UNAVAILABLE_DETAIL if explicit else BASE_UNAVAILABLE_DETAIL,
                              explicit_base=(label if label is not None else fallback) if explicit else None)
    if not comparison or comparison == head_commit:
        raise BaseUnavailable(COMPARISON_UNAVAILABLE_DETAIL, code="comparison_unavailable",
                              explicit_base=(label if label is not None else fallback) if explicit else None)
    return candidate


@dataclass(frozen=True)
class Policy:
    mode: Optional[str] = None
    target: Optional[str] = None
    error: Optional[str] = None
    source: str = "base"

    @property
    def permits_unsigned(self) -> bool:
        return self.mode in PERMITTED_MODES

    def as_dict(self, display=None) -> dict[str, Any]:
        fields = {}
        if self.mode is not None:
            target = display(self.target, 255, identifier=True) if display and self.target is not None else self.target
            fields = {"approval_mode": self.mode, "approval_target": target,
                      "owner_review_required": self.mode == "review", "policy_source": self.source}
            if self.target is None:
                fields["approval_policy_hint"] = "pass --base origin/<branch>"
        if self.error:
            fields["approval_policy_error"] = self.error
        return fields


def ungated_targets(policy: Any):
    """Sorted targets that lose the gate, using only Policy.permits_unsigned.

    None and an empty map name no target. A value that is not a plain dict, exceeds
    MAX_PATTERNS, or holds a non-string, empty, overlong, or unknown-mode entry is
    refused before the predicate is constructed. The refusal is the fixed invalid-policy detail.
    Names up to 512 characters stay eligible so a later display digest is not a parse error.
    """
    if policy is None:
        return ()
    if type(policy) is not dict or len(policy) > MAX_PATTERNS:
        raise InvalidApprovalPolicy(INVALID_DETAIL)
    items = tuple(policy.items())
    for target, mode in items:
        if (type(target) is not str or type(mode) is not str
                or not 0 < len(target) <= 512 or mode not in MODES):
            raise InvalidApprovalPolicy(INVALID_DETAIL)
    found = []
    for target, mode in items:
        if Policy(mode=mode).permits_unsigned:
            found.append((target, mode))
    return tuple(sorted(found))


def resolve_policy(root: Any, base: str, head: str, target: Optional[str]) -> Policy:
    """An absent base map is legacy; a head map can only tighten an existing base policy."""
    error = None
    try:
        policy = read_policy(root, base, strict=False)
    except PolicyUnavailable:
        raise
    except InvalidApprovalPolicy:
        policy, error = None, INVALID_DETAIL
    candidate = read_policy(root, head, strict=policy is not None)
    if policy is None:
        return Policy(error=error)
    target = _target_name(target)
    mode = mode_for(policy, target)
    if candidate is not None and MODES.index(mode_for(candidate, target)) > MODES.index(mode):
        return Policy(mode_for(candidate, target), target, source="head")
    return Policy(mode, target)


def _region_mode(policy: Mapping[str, str], pattern: str) -> str:
    """Compare every exact/prefix/default region, including deleted patterns.

    A prefix region excludes its more specific children, which are compared
    independently. No invented branch name or finite set of example names can
    stand in for this partition of the policy's complete target space.
    """
    if pattern != "*" and not pattern.endswith("/**"):
        return mode_for(policy, pattern)
    parents = [key for key in policy if key.endswith("/**") and pattern != "*"
               and pattern[:-2].startswith(key[:-2])]
    if parents:
        return policy[max(parents, key=len)]
    return policy.get("*", max(policy.values(), key=MODES.index))


def owner_review_changes(root: Any, base: str, head: str) -> tuple[dict[str, Any], ...]:
    """Detection only; the caller excludes bases with signing keys."""
    try:
        before = read_policy(root, base, strict=False)
    except PolicyUnavailable:
        raise
    except InvalidApprovalPolicy:
        before = None
    after = read_policy(root, head, strict=before is not None)
    if before is None:
        return ({"code": "approval_policy_introduced", "rule": "approvals", "path": CONFIG_PATH,
                 "message": GuidanceMessage("approval_policy_introduced",
                     MESSAGE_TEMPLATES["approval_policy_introduced"], {})},) if after else ()
    # Removing the whole map restores the legacy gate; it is not a mode lowering.
    if after is None:
        return ()
    found = []
    for pattern in sorted(set(before) | set(after) | {"*"}):
        prior, candidate = _region_mode(before, pattern), _region_mode(after, pattern)
        if MODES.index(candidate) < MODES.index(prior):
            found.append({"code": "approval_mode_lowered", "rule": pattern, "path": CONFIG_PATH,
                          "message": GuidanceMessage("approval_mode_lowered",
                              MESSAGE_TEMPLATES["approval_mode_lowered"],
                              {"prior": prior, "candidate": candidate})})
    return tuple(found)
