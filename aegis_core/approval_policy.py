"""Approval modes anchored in a resolved base commit, with a candidate-only tightening ratchet.

The candidate is validated independently. Unknown targets and unmatched branches
use the strictest declared mode; no map preserves the legacy gate.
"""
from __future__ import annotations

from dataclasses import dataclass, field as field
from functools import lru_cache
import json
import re
from string import Formatter
import unicodedata as unicodedata
from types import MappingProxyType
from typing import Any, Mapping, Optional

from aegis_core import gitsafe, human_gate, primitives
from aegis_core.redaction import (
    MAX_GUIDANCE_CHARS, clip_rendered_text as _clip_rendered_text, command_token as command_token,
    GUIDANCE_ESCAPE_PATTERN, guidance_field, guidance_value as _guidance_value,
    receipt_value as _receipt_value, unresolved_base_hint as _unresolved_base_hint,
)
from aegis_core.workspace.layout import AEGIS_DIRNAME

__all__ = ["BaseUnavailable", "InvalidApprovalPolicy", "PolicyUnavailable", "Policy", "parse_policy", "mode_for", "read_policy",
           "resolve_policy", "BaseResolution", "resolve_comparison", "resolve_base", "policy_present", "push_base",
           "guidance_value", "GuidanceMessage", "MessageRow", "finding_message", "receipt_value", "MESSAGE_TEMPLATES",
           "MESSAGE_OWNERS", "clip_rendered_text"]

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


# Source-owned message frames; decoded documents cannot supply templates.
MESSAGE_TEMPLATES = MappingProxyType({
    "approval_policy_introduced": "approval policy introduced without base signers; owner review required",
    "approval_mode_lowered": "approval mode lowered from {prior} to {candidate}; owner review required",
    "coverage": "no longer applies to {path}, which the reviewed version covered",
    "forbid_ast": "forbid_ast was removed",
    "deleted": "the rule is gone from the branch (a deletion or an archive, with no same-id rule in its place)",
    "deleted_2": "the rule no longer loads: {error} (a deletion or an archive, with no same-id rule in its place)",
    "legacy_value": "{detail}",
    "coverage_2": "it no longer applies to test files, which the reviewed version covered",
    "coverage_3": "target pattern '{pattern}' is no longer kept; files it covered, including files this branch adds, may lose the rule",
    "rank": "binds less: rank {prior_rank} ({prior}) became rank {rank} ({mode})",
    "unknown_key": "new or changed key '{key}' is not one Aegis knows, so it is treated as a weakening",
    "detect": "detect is not an exact superset of the reviewed version",
    "forbid_ast_2": "{kind} '{pattern}' is no longer forbidden",
    "applies_to": "applies_to changed",
    "mandatory_cap": "a mandatory rule added where {count} already apply (to {path}); a scan gives mandatory rules at most {cap} slots, so this one crowds out the others",
    "forbid_ast_3": "call '{name}' is no longer forbidden everywhere it was (its where or builtin was narrowed)",
    "forbid_ast_4": "call '{name}' is no longer forbidden",
    "git_failed": "git could not list the working tree's changes",
    "not_git": "{root} is not inside a git work tree",
    "no_head": "the repository has no commit yet",
    "no_base": "no base branch found (origin/$GITHUB_BASE_REF, the branch origin/HEAD names, main, develop or master); pass --base",
    "no_common_history": "the resolved base and HEAD share no history; pass a base from HEAD's history",
    "staged": "changes are staged: an approval commit stays empty, so commit or unstage them first",
    "uncommitted": "governance files have uncommitted changes ({paths}): commit them first, then approve the committed state",
    "no_key": "{detail}. Set it up with: git config --global gpg.format ssh; git config --global user.signingkey <your key>",
    "no_terminal": "an approval needs a terminal and a typed y: a person has to look at what is approved, so this does not run from a script or an agent's shell",
    "declined": "No approval made.",
    "not_required": "this target does not require a signed governance approval; next_action: review and merge through the target branch's owner policy",
    "nothing": "nothing governance-related changed since {base}: there is nothing to approve",
    "unresolved": "cannot resolve {commit} to a commit in {root}",
    "git_failed_2": "base commit is too large to review (limit {limit} bytes)",
    "invalid_approval_policy": "invalid_approval_policy: cannot read .aegis/config.json; next_action: fetch or repair the repository objects and re-run",
    "sign_failed": "{detail}",
    "git_failed_3": "git could not list governance paths for review",
    "base_unavailable": "fetch the push's before commit (fetch-depth) and re-run",
    "comparison_unavailable": "pass --base that is a proper ancestor of the head",
    "invalid_ci_event": "invalid_ci_event: invalid event data; next_action: provide a valid CI event or run locally with --base",
    "layer1": "{detail}",
    "layer1_forbidden_call": "Forbidden {name}() call",
    "strict_no_driver": "Strict mode: no-driver coverage blocks; a verification driver is unavailable.",
    "regression_prefix": "fix commit {commit} ({subject})",
    "regression_unverified": ": regression tests unverified ({reason})",
    "regression_rejected": " (its test exemption was rejected: {exemption})",
    "regression_note": " (Aegis-No-Test: '{note}' is an explanation only; exemption requires human_gate approval)",
    "regression_timeout": ": the test run timed out",
    "regression_no_test_changes": " modifies source without adding or updating a test",
    "regression_no_tests_collected": ": no tests were collected from the changed test files",
    "regression_failed_on_head": ": the changed test files failed or errored on the pull request head",
    "regression_passed_on_base": ": no test failed on base and passed on head (tests passed on base too)",
})


# A frame belongs to a producer and finding kind, never to matching text alone.
# Producer names are supplied by the rendering call site/document path, not by
# a field in an ingested row. Free-value frames provide no reconstructable text.
MESSAGE_OWNERS = MappingProxyType({
    "approval_policy_introduced": ("owner_review_required", "approval_policy_introduced"),
    "approval_mode_lowered": ("owner_review_required", "approval_mode_lowered"),
    "coverage": ("weakenings", "coverage"),
    "forbid_ast": ("weakenings", "forbid_ast"),
    "deleted": ("weakenings", "deleted"),
    "deleted_2": ("weakenings", "deleted"),
    "legacy_value": ("weakenings", None),
    "coverage_2": ("weakenings", "coverage"),
    "coverage_3": ("weakenings", "coverage"),
    "rank": ("weakenings", "rank"),
    "unknown_key": ("weakenings", "unknown_key"),
    "detect": ("weakenings", "detect"),
    "forbid_ast_2": ("weakenings", "forbid_ast"),
    "applies_to": ("weakenings", "applies_to"),
    "mandatory_cap": ("weakenings", "mandatory_cap"),
    "forbid_ast_3": ("weakenings", "forbid_ast"),
    "forbid_ast_4": ("weakenings", "forbid_ast"),
    "git_failed": ("approve", "git_failed"),
    "not_git": ("approve", "not_git"),
    "no_head": ("approve", "no_head"),
    "no_base": ("approve", "no_base"),
    "no_common_history": ("approve", "no_common_history"),
    "staged": ("approve", "staged"),
    "uncommitted": ("approve", "uncommitted"),
    "no_key": ("approve", "no_key"),
    "no_terminal": ("approve", "no_terminal"),
    "declined": ("approve", "declined"),
    "not_required": ("approve", "not_required"),
    "nothing": ("approve", "nothing"),
    "unresolved": ("approve", "unresolved"),
    "git_failed_2": ("approve", "git_failed"),
    "invalid_approval_policy": ("approve", "invalid_approval_policy"),
    "sign_failed": ("approve", "sign_failed"),
    "git_failed_3": ("approve", "git_failed"),
    "base_unavailable": ("ci", "base_unavailable"),
    "comparison_unavailable": ("ci", "comparison_unavailable"),
    "invalid_ci_event": ("ci", "invalid_ci_event"),
    "layer1": ("layer1", "layer1"),
    "layer1_forbidden_call": ("layer1", "layer1_forbidden_call"),
    "strict_no_driver": ("findings", "strict:no-driver"),
    "regression_prefix": ("regression", "regression_prefix"),
    "regression_unverified": ("regression", "regression_unverified"),
    "regression_rejected": ("regression", "regression_rejected"),
    "regression_note": ("regression", "regression_note"),
    "regression_timeout": ("regression", "regression_timeout"),
    "regression_no_test_changes": ("regression", "regression_no_test_changes"),
    "regression_no_tests_collected": ("regression", "regression_no_tests_collected"),
    "regression_failed_on_head": ("regression", "regression_failed_on_head"),
    "regression_passed_on_base": ("regression", "regression_passed_on_base"),
})


def clip_rendered_text(value: str, limit: int = 400, *, ellipsis: bool = True) -> str:
    """Cap finished text by wire characters, preserving its template and atoms.

    Callers render/redact their data fields before interpolation. This boundary
    never escapes template text; it re-redacts cuts that create a new match.
    Oversized input is omitted before sanitization or unit-list allocation.
    """
    return _clip_rendered_text(value, limit, ellipsis=ellipsis, canonicalize=primitives.sanitize_display)


def guidance_value(value: str, limit: int = 400, *, prose: bool = False) -> str:
    """One inert guidance field: bound input, canonicalize, redact, truncate, escape.

    At most 8192 logical units (81920 wire characters) enter the pipeline.
    Escaping expands each retained unit by at most ten ASCII characters; no value
    is wrapped in shell quotes. Sentence values escape execution/chain syntax
    and surviving control/format characters; their other punctuation is kept.
    This formats values only, never completed sentences or protocol properties.
    """
    return _guidance_value(value, limit, prose=prose, canonicalize=primitives.sanitize_display)


def receipt_value(value: str, limit: int = 120, *, identifier: bool = False, canonicalize=None) -> str:
    """Bound, canonicalize, redact and clip receipt fields at stable mask units."""
    return _receipt_value(value, limit, identifier=identifier, canonicalize=canonicalize,
                          default_canonicalize=primitives.sanitize_display)


def unresolved_base_hint(selector: str) -> str:
    """Describe a failed comparison without introducing shell-active data."""
    return _unresolved_base_hint(selector, canonicalize=primitives.sanitize_display)


@dataclass(frozen=True)
class GuidanceMessage:
    """Trusted wording and unrendered data, kept separate until a human boundary.

    Templates are source literals. Values never become part of a template and
    are formatted exactly once, independently of the surrounding punctuation.
    Machine identities are stored by findings separately from this message.
    """
    kind: str
    template: str
    values: Mapping[str, Any]

    def render(self) -> str:
        return self.template.format_map({key: _frame_list_value(value, self.template)
                                         if isinstance(value, (list, tuple)) else _frame_value(str(value), self.template)
                                         for key, value in self.values.items()})


def _frame_list_value(values, template):
    """Bound before joining, then render the entire list as one scalar field."""
    size = 2 * max(0, len(values) - 1)
    if size > _MAX_BASE_CHARS:  # Separators alone already exceed the logical limit.
        return _frame_value("diagnostic_omitted_too_large", template)
    parts = []
    for value in values:
        text = str(value)
        size += len(text)
        if size > 10 * _MAX_BASE_CHARS:
            return _frame_value("diagnostic_omitted_too_large", template)
        parts.append(text)
    return _frame_value(", ".join(parts), template)


@lru_cache(maxsize=64)
def _frame_separators(template):
    """Only separators which prose could otherwise reproduce need disarming."""
    parts = list(Formatter().parse(template))
    tokens = {literal.strip() for index, (literal, field, _spec, _conversion) in enumerate(parts)
              if index and field is not None and parts[index - 1][1] is not None and literal.strip()
              and guidance_value(literal.strip(), prose=True) == literal.strip()}
    return tuple(sorted(tokens, key=lambda value: (-len(value), value)))


def _frame_value(value, template):
    """Render a value using only this source frame's separators."""
    return guidance_field(value, _frame_separators(template), canonicalize=primitives.sanitize_display)


class MessageRow(dict):
    """A serialized finding whose message has crossed the rendering boundary.

    The marker stays out of JSON. Formatters receiving legacy plain dictionaries
    instead treat their free-text message as data, rather than trusting it as a
    source template. Identity properties remain ordinary unchanged dict values.
    """


@lru_cache(maxsize=1)
def _message_patterns():
    # These are bounded source-owned frames, never templates from a document.
    # Escape tokens have a unique spelling and raw execution characters cannot
    # enter a capture. Each capture is limited to one displayed field's units.
    char = r"[^\s$`\\;&|<>!()'\"\x00-\x1f\x7f-\x9f]"
    unit = "(?:" + GUIDANCE_ESCAPE_PATTERN + "|" + char + r"| (?! ))"
    # Empty is canonical too. Nonempty captures cannot start/end with a space
    # or contain double spaces; the engine must select a canonical partition.
    patterns = []
    for name, template in MESSAGE_TEMPLATES.items():
        parts = list(Formatter().parse(template))
        if not any(literal for literal, _field, _spec, _conversion in parts):
            continue  # A free-text field provides no trusted framing.
        forbidden = "|".join(re.escape(token) for token in (*_frame_separators(template), "::"))
        canonical_unit = "(?!(?:" + forbidden + "))" + unit
        capture = "((?:(?! )(?:" + canonical_unit + r"){1,400}(?<! ))?)"
        pattern = "".join(re.escape(literal) + (capture if field is not None else "")
                          for literal, field, _spec, _conversion in parts)
        patterns.append((*MESSAGE_OWNERS[name], template, re.compile(pattern)))
    return tuple(patterns)


def finding_message(row: Mapping[str, Any], *, producer: Optional[str] = None, display=None) -> str:
    message = row["message"]
    # JSON drops the Python marker. Recognize only exact source-owned frames
    # with already inert value captures, preserving their literal punctuation.
    # Bound the complete message before applying any of the bounded patterns.
    if producer is not None and len(message) <= 64 * 1024:
        kind = row.get("rule" if producer == "findings" else "code")
        for owner, owned_kind, template, pattern in _message_patterns():
            if (producer, kind) != (owner, owned_kind):
                continue
            match = pattern.fullmatch(message)
            if match is not None and all(_frame_value(value, template) == value for value in match.groups()):
                return message
    return display(message) if display is not None else guidance_value(message, prose=True)


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
