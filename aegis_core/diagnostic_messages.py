"""Source-owned diagnostic frames and rendering, independent of approval decisions."""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import re
from string import Formatter
from types import MappingProxyType
from typing import Any, Mapping, NamedTuple, Optional

from aegis_core import primitives
from aegis_core.redaction import (
    MAX_GUIDANCE_CHARS, GUIDANCE_ESCAPE_PATTERN, clip_rendered_text as _clip_rendered_text,
    guidance_field, guidance_value as _guidance_value, receipt_value as _receipt_value,
)

__all__ = [
    "MESSAGE_CATALOGUE", "MESSAGE_TEMPLATES", "MESSAGE_OWNERS", "GuidanceMessage",
    "MessageRow", "finding_message", "clip_rendered_text", "guidance_value", "receipt_value",
]

_MAX_VALUE_CHARS = MAX_GUIDANCE_CHARS


class MessageFrame(NamedTuple):
    """One immutable binding of trusted wording to its producer and finding kind."""
    template: str
    producer: str
    kind: Optional[str]


# Producer names come from trusted call sites, never fields in decoded documents.
# Free-value frames carry no source framing that can be reconstructed.
MESSAGE_CATALOGUE = MappingProxyType({
    "approval_policy_introduced": MessageFrame("approval policy introduced without base signers; owner review required", "owner_review_required", "approval_policy_introduced"),
    "approval_mode_lowered": MessageFrame("approval mode lowered from {prior} to {candidate}; owner review required", "owner_review_required", "approval_mode_lowered"),
    "coverage": MessageFrame("no longer applies to {path}, which the reviewed version covered", "weakenings", "coverage"),
    "forbid_ast": MessageFrame("forbid_ast was removed", "weakenings", "forbid_ast"),
    "deleted": MessageFrame("the rule is gone from the branch (a deletion or an archive, with no same-id rule in its place)", "weakenings", "deleted"),
    "deleted_2": MessageFrame("the rule no longer loads: {error} (a deletion or an archive, with no same-id rule in its place)", "weakenings", "deleted"),
    "legacy_value": MessageFrame("{detail}", "weakenings", None),
    "coverage_2": MessageFrame("it no longer applies to test files, which the reviewed version covered", "weakenings", "coverage"),
    "coverage_3": MessageFrame("target pattern '{pattern}' is no longer kept; files it covered, including files this branch adds, may lose the rule", "weakenings", "coverage"),
    "rank": MessageFrame("binds less: rank {prior_rank} ({prior}) became rank {rank} ({mode})", "weakenings", "rank"),
    "unknown_key": MessageFrame("new or changed key '{key}' is not one Aegis knows, so it is treated as a weakening", "weakenings", "unknown_key"),
    "detect": MessageFrame("detect is not an exact superset of the reviewed version", "weakenings", "detect"),
    "forbid_ast_2": MessageFrame("{kind} '{pattern}' is no longer forbidden", "weakenings", "forbid_ast"),
    "applies_to": MessageFrame("applies_to changed", "weakenings", "applies_to"),
    "mandatory_cap": MessageFrame("a mandatory rule added where {count} already apply (to {path}); a scan gives mandatory rules at most {cap} slots, so this one crowds out the others", "weakenings", "mandatory_cap"),
    "forbid_ast_3": MessageFrame("call '{name}' is no longer forbidden everywhere it was (its where or builtin was narrowed)", "weakenings", "forbid_ast"),
    "forbid_ast_4": MessageFrame("call '{name}' is no longer forbidden", "weakenings", "forbid_ast"),
    "git_failed": MessageFrame("git could not list the working tree's changes", "approve", "git_failed"),
    "not_git": MessageFrame("{root} is not inside a git work tree", "approve", "not_git"),
    "no_head": MessageFrame("the repository has no commit yet", "approve", "no_head"),
    "no_base": MessageFrame("no base branch found (origin/$GITHUB_BASE_REF, the branch origin/HEAD names, main, develop or master); pass --base", "approve", "no_base"),
    "no_common_history": MessageFrame("the resolved base and HEAD share no history; pass a base from HEAD's history", "approve", "no_common_history"),
    "staged": MessageFrame("changes are staged: an approval commit stays empty, so commit or unstage them first", "approve", "staged"),
    "uncommitted": MessageFrame("governance files have uncommitted changes ({paths}): commit them first, then approve the committed state", "approve", "uncommitted"),
    "no_key": MessageFrame("{detail}. Set it up with: git config --global gpg.format ssh; git config --global user.signingkey <your key>", "approve", "no_key"),
    "no_terminal": MessageFrame("an approval needs a terminal and a typed y: a person has to look at what is approved, so this does not run from a script or an agent's shell", "approve", "no_terminal"),
    "declined": MessageFrame("No approval made.", "approve", "declined"),
    "not_required": MessageFrame("this target does not require a signed governance approval; next_action: review and merge through the target branch's owner policy", "approve", "not_required"),
    "nothing": MessageFrame("nothing governance-related changed since {base}: there is nothing to approve", "approve", "nothing"),
    "unresolved": MessageFrame("cannot resolve {commit} to a commit in {root}", "approve", "unresolved"),
    "git_failed_2": MessageFrame("base commit is too large to review (limit {limit} bytes)", "approve", "git_failed"),
    "invalid_approval_policy": MessageFrame("invalid_approval_policy: cannot read .aegis/config.json; next_action: fetch or repair the repository objects and re-run", "approve", "invalid_approval_policy"),
    "sign_failed": MessageFrame("{detail}", "approve", "sign_failed"),
    "git_failed_3": MessageFrame("git could not list governance paths for review", "approve", "git_failed"),
    "base_unavailable": MessageFrame("fetch the push's before commit (fetch-depth) and re-run", "ci", "base_unavailable"),
    "comparison_unavailable": MessageFrame("pass --base that is a proper ancestor of the head", "ci", "comparison_unavailable"),
    "invalid_ci_event": MessageFrame("invalid_ci_event: invalid event data; next_action: provide a valid CI event or run locally with --base", "ci", "invalid_ci_event"),
    "layer1": MessageFrame("{detail}", "layer1", "layer1"),
    "layer1_forbidden_call": MessageFrame("Forbidden {name}() call", "layer1", "layer1_forbidden_call"),
    "strict_no_driver": MessageFrame("Strict mode: no-driver coverage blocks; a verification driver is unavailable.", "findings", "strict:no-driver"),
    "regression_prefix": MessageFrame("fix commit {commit} ({subject})", "regression", "regression_prefix"),
    "regression_unverified": MessageFrame(": regression tests unverified ({reason})", "regression", "regression_unverified"),
    "regression_rejected": MessageFrame(" (its test exemption was rejected: {exemption})", "regression", "regression_rejected"),
    "regression_note": MessageFrame(" (Aegis-No-Test: '{note}' is an explanation only; exemption requires human_gate approval)", "regression", "regression_note"),
    "regression_timeout": MessageFrame(": the test run timed out", "regression", "regression_timeout"),
    "regression_no_test_changes": MessageFrame(" modifies source without adding or updating a test", "regression", "regression_no_test_changes"),
    "regression_no_tests_collected": MessageFrame(": no tests were collected from the changed test files", "regression", "regression_no_tests_collected"),
    "regression_failed_on_head": MessageFrame(": the changed test files failed or errored on the pull request head", "regression", "regression_failed_on_head"),
    "regression_passed_on_base": MessageFrame(": no test failed on base and passed on head (tests passed on base too)", "regression", "regression_passed_on_base"),
})

# Compatibility views are derived from the catalogue; they own no separate rows.
MESSAGE_TEMPLATES = MappingProxyType({name: frame.template for name, frame in MESSAGE_CATALOGUE.items()})
MESSAGE_OWNERS = MappingProxyType({name: (frame.producer, frame.kind) for name, frame in MESSAGE_CATALOGUE.items()})


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
    if size > _MAX_VALUE_CHARS:  # Separators alone already exceed the logical limit.
        return _frame_value("diagnostic_omitted_too_large", template)
    parts = []
    for value in values:
        text = str(value)
        size += len(text)
        if size > 10 * _MAX_VALUE_CHARS:
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
    for frame in MESSAGE_CATALOGUE.values():
        template = frame.template
        parts = list(Formatter().parse(template))
        if not any(literal for literal, _field, _spec, _conversion in parts):
            continue  # A free-text field provides no trusted framing.
        forbidden = "|".join(re.escape(token) for token in (*_frame_separators(template), "::"))
        canonical_unit = "(?!(?:" + forbidden + "))" + unit
        capture = "((?:(?! )(?:" + canonical_unit + r"){1,400}(?<! ))?)"
        pattern = "".join(re.escape(literal) + (capture if field is not None else "")
                          for literal, field, _spec, _conversion in parts)
        patterns.append((frame.producer, frame.kind, template, re.compile(pattern)))
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


