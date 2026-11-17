"""Pure guidance structure, bounded clean-text redaction and rendered budgets."""
from __future__ import annotations

from abc import ABC, abstractmethod
from bisect import bisect_right
import json
import math
import re
import unicodedata
from typing import Any, Dict, Optional, Protocol

from aegis_core.guidance_grammar import (
    bounded_rule_text, clip_redacted, copy_retained_items, guidance_token_estimate,
    heading_has_slot, raw_do_instruction_span, raw_evidence_span, redact_labeled,
)
from aegis_core.taxonomy import JIT_DEFAULT_MAX_TOKENS, RULE_TYPES, WORDS_TO_TOKENS_FACTOR

__all__ = ["CONTROL_GUIDANCE", "GuidanceProjectionError", "GuidanceResult", "MAX_GUIDANCE_CHARS",
           "SLOT_REF_PATTERN", "WITHHELD_GUIDANCE", "checked_result_copy", "projection_refusal_copy",
           "assembled_text", "project_assembled", "contains_control_characters", "estimate_tokens", "field_text", "finish_payload",
           "instruction_body", "normalize_layout", "redact_clean_text", "project_detail", "detail_instruction_visible", "project_display_data",
           "project_envelope_fields", "project_field", "project_identifier", "project_rule_entries",
           "project_text", "project_diagnostic", "project_display_text", "project_error_name", "raw_rule_text"]

MAX_GUIDANCE_CHARS = 1024 * 1024
MAX_GUIDANCE_ITEMS = 256
ASCII_CHARS_PER_TOKEN = 4
SLOT_REF_PATTERN = re.compile(r"\$\{(?:SLOT|RULE)\.([A-Za-z0-9_\-]+)\}|\$\{([A-Za-z0-9_\-]+)\}")
WITHHELD_GUIDANCE = "guidance withheld: ambiguous structure"
CONTROL_GUIDANCE = "guidance withheld: control characters"
MAX_IDENTIFIER_ITEMS = 4096
_MAX_ERROR_NAME_PASSES = 32
_IDENTIFIER_FIELDS = frozenset({"id", "name", "path", "_path", "matched_files", "files"})
_CONTROL_CANDIDATES = re.compile(r"[^\t\n\r\x20-\x7e]")
_DIAGNOSTIC_ESCAPES = re.compile(
    r"(?<!\\)(?:(?P<slashes>(?:\\\\)*\\)(?:(?P<space>[tnrvf])|(?P<point>x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})"
    r"|N\{(?P<name>[^{}]*)(?P<closed>\}|(?=\{)|$))|\\+)"
)


class _Slots(Protocol):
    def get(self, key: str, default: Optional[str] = None) -> Optional[str]: ...


class GuidanceResult(dict, ABC):
    """A JSON-compatible result that can reproject its captured input snapshot."""

    @abstractmethod
    def with_registry(self, registry: _Slots) -> Dict[str, Any]:
        """Render original inputs with one registry, without reading source files."""

    def exposure_rule_ids(self) -> tuple[str, ...]:
        """Canonical identities for trusted telemetry only; never mapping fields."""
        return ()

    def staged_mandatory_count(self) -> int:
        """Mandatory entries in this selection, separate from replay inputs."""
        return _compatibility_mandatory_count(self.get("relevant_rules", []))


class GuidanceProjectionError(ValueError):
    """A fixed-code refusal while projecting untrusted guidance."""

    code = "guidance_projection_limit"


class _InvalidField(GuidanceProjectionError):
    code = "guidance_projection_invalid_field"


def _check_size(size: int) -> None:
    if size > MAX_GUIDANCE_CHARS:
        raise GuidanceProjectionError("guidance_projection_limit")


class _ControlCharacters(GuidanceProjectionError):
    code = CONTROL_GUIDANCE


def contains_control_characters(text: str, start: int = 0, end: Optional[int] = None) -> bool:
    """The one refusal predicate, before any layout normalization or redaction."""
    stop = len(text) if end is None else end
    # Preserve range/index semantics for negative or out-of-range bounds,
    # including short-circuiting before an otherwise invalid index is reached.
    if start < 0 or stop > len(text):
        return any(contains_control_characters(text[i]) for i in range(start, stop))
    return any(unicodedata.category(match[0]) in {"Cc", "Cf", "Cs"}
               for match in _CONTROL_CANDIDATES.finditer(text, start, stop))


def normalize_layout(text: str, *, single_line: bool = False) -> str:
    _check_size(len(text))
    if contains_control_characters(text):
        raise _ControlCharacters(CONTROL_GUIDANCE)
    if single_line:
        return " ".join(text.split())
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\u2028", " ").replace("\u2029", " ")


def raw_rule_text(raw, splitter):
    return bounded_rule_text(raw, splitter, contains_control_characters, MAX_GUIDANCE_CHARS,
                             4 * MAX_GUIDANCE_CHARS, WITHHELD_GUIDANCE, CONTROL_GUIDANCE)


def _retained_items(items):
    decision, index, end = raw_evidence_span(items, heading_has_slot, contains_control_characters)
    if decision == -3:
        raise _ControlCharacters(CONTROL_GUIDANCE)
    if decision == -1:
        return [WITHHELD_GUIDANCE], None
    if decision == -2:
        raise _InvalidField("guidance_projection_invalid_field")
    count = index + bool(end) if decision else len(items)
    if count > MAX_GUIDANCE_ITEMS:
        raise GuidanceProjectionError("guidance_projection_limit")
    size = sum(len(items[i]) for i in range(count)) + max(0, count - 1)
    if decision and end:
        size -= len(items[index]) - end
    _check_size(size)
    retained = copy_retained_items(items, count, end, bool(decision))
    if any(contains_control_characters(item) for item in retained):
        raise _ControlCharacters(CONTROL_GUIDANCE)
    return retained, bool(decision)


def _expanded_text(text, registry=None, *, body=True, max_chars=MAX_GUIDANCE_CHARS):
    if type(text) is not str:
        raise _InvalidField("guidance_projection_invalid_field")
    if body:
        retained, cut = _retained_items([text])
        if cut is None:
            return WITHHELD_GUIDANCE
        text = retained[0] if retained else ""
    else:
        text = normalize_layout(text)
    if registry is None:
        return normalize_layout(text)
    replacements, size = [], len(text)
    refused = getattr(registry, "control_refused", lambda key: False)
    for match in SLOT_REF_PATTERN.finditer(text):
        key = match.group(1) or match.group(2)
        if refused(key):
            raise _ControlCharacters(CONTROL_GUIDANCE)
        value = registry.get(key)
        if value is None:
            continue
        if type(value) is not str:
            raise _InvalidField("guidance_projection_invalid_field")
        if contains_control_characters(value):
            raise _ControlCharacters(CONTROL_GUIDANCE)
        size += len(value) - len(match[0])
        _check_size(size)
        replacements.append((match.start(), match.end(), value))
    _check_size(size + MAX_GUIDANCE_CHARS - max_chars)
    parts, end = [], 0
    for start, stop, value in replacements:
        parts.extend((text[end:start], value))
        end = stop
    parts.append(text[end:])
    expanded = normalize_layout("".join(parts))
    if body and replacements:
        decision, _, _ = raw_evidence_span([expanded], heading_has_slot)
        if decision:
            return WITHHELD_GUIDANCE
    return expanded


def instruction_body(body: str) -> str:
    """Stop at raw Evidence before limits and the shared control refusal."""
    try:
        retained, _ = _retained_items([body])
        return normalize_layout(retained[0] if retained else "")
    except _ControlCharacters:
        return CONTROL_GUIDANCE


def _redact_labeled(text, labels):
    try:
        return redact_labeled(text, labels, MAX_GUIDANCE_CHARS)
    except ValueError:
        raise GuidanceProjectionError("guidance_projection_limit") from None


def redact_clean_text(text: str) -> str:
    """One bounded pass over the shared redactor's public replacement table."""
    _check_size(len(text))
    if contains_control_characters(text):
        raise _ControlCharacters(CONTROL_GUIDANCE)
    return _redact_labeled(text, None)[0]


def project_text(text: str, registry: Optional[_Slots] = None) -> str:
    try:
        return redact_clean_text(_expanded_text(text, registry))
    except _ControlCharacters:
        return CONTROL_GUIDANCE


def project_detail(body: str, registry: Optional[_Slots] = None) -> str:
    """Redact the complete flattened instruction before the eight-line/300 cut."""
    try:
        text = _expanded_text(body, registry).strip()
    except _ControlCharacters:
        return CONTROL_GUIDANCE
    pieces, labels = [], []
    for number, line in enumerate(text.split("\n")):
        if pieces:
            pieces.append(" ")
            labels.append(number)
        fragment = line.strip()
        pieces.append(fragment)
        labels.extend([number] * len(fragment))
    shown, labels = _redact_labeled("".join(pieces), labels)
    boundary = next((i for i, label in enumerate(labels) if label >= 8), len(shown))
    return shown[:boundary][:300]


def detail_instruction_visible(body: str, prefix: Optional[str], registry: Optional[_Slots] = None) -> bool:
    """Whether scan serves the complete prefix ending at the first instruction.

    Require raw and rendered grammar decisions to select the same source span,
    then render the uncapped prefix with Detail's exact flattening and cleaning
    semantics and compare against the normal served Detail. Missing instructions,
    divergence, structural/control refusals and resource/type limits return False.
    Neither input nor exception text is returned.
    """
    if prefix is None:
        return False
    try:
        raw_span = raw_do_instruction_span([prefix], heading_has_slot, contains_control_characters)
        if raw_span[0] != 1:
            return False
        text = _expanded_text(prefix, registry)
        if text in {WITHHELD_GUIDANCE, CONTROL_GUIDANCE}:
            return False
        span = raw_do_instruction_span([text], heading_has_slot, contains_control_characters)
        if span[:2] != raw_span[:2]:
            return False
        # Map each rendered boundary back to its raw boundary by transforming
        # the complete raw prefix at that boundary. Prefix equality proves the
        # attribution without duplicating expansion or layout transformations.
        mapped = tuple(raw_offset if _expanded_text(prefix[:raw_offset], registry) == text[:offset] else -1
                       for offset, raw_offset in zip(span[2:], raw_span[2:]))
        if (span[0], span[1], *mapped) != raw_span:
            return False
        instruction_line = text.count("\n", 0, span[2])
        text = text.rstrip()
        pieces, labels = [], []
        for number, line in enumerate(text.split("\n")):
            fragment = line.strip()
            if not pieces and not fragment:
                continue
            if pieces:
                pieces.append(" ")
                labels.append(number)
            pieces.append(fragment)
            labels.extend([number] * len(fragment))
        required, labels = _redact_labeled("".join(pieces), labels)
        if not any(label == instruction_line and not char.isspace() for char, label in zip(required, labels)):
            return False
        detail = project_detail(body, registry)
        return bool(required) and detail not in {WITHHELD_GUIDANCE, CONTROL_GUIDANCE} and detail.startswith(required)
    except GuidanceProjectionError:
        return False


def project_field(value: Any, registry: Optional[_Slots] = None, *, body: bool = False) -> str | list[str]:
    if value is None:
        return ""
    if isinstance(value, str):
        return project_text(value, registry)
    if not isinstance(value, list):
        raise _InvalidField("guidance_projection_invalid_field")
    try:
        retained, _ = _retained_items(value)
        raw = "\n".join(retained)
        boundaries, offset = [], 0
        for item in retained[:-1]:
            offset += len(item) + 1
            boundaries.append(offset - 1)
        for match in re.finditer(r"\$\{[^}]*\}", raw):
            boundary = bisect_right(boundaries, match.start())
            if boundary < len(boundaries) and boundaries[boundary] < match.end():
                raise _InvalidField("guidance_projection_invalid_field")
        expanded, size = [], 0
        for item in retained:
            size += bool(expanded)
            _check_size(size)
            shown = _expanded_text(item, registry, body=False, max_chars=MAX_GUIDANCE_CHARS - size)
            expanded.append(shown)
            size += len(shown)
        joined, labels = [], []
        for number, item in enumerate(expanded):
            if joined:
                joined.append("\n")
                labels.append(None)
            joined.append(item)
            labels.extend([number] * len(item))
        if not expanded:
            return []
        decision, _, _ = raw_evidence_span(["\n".join(expanded)], heading_has_slot)
        if decision:
            return [WITHHELD_GUIDANCE]
        shown, labels = _redact_labeled("".join(joined), labels)
        buckets = [[] for _ in expanded]
        for char, label in zip(shown, labels):
            if label is not None:
                buckets[label].append(char)
        return ["".join(bucket) if bucket or not expanded[i] else "REDACTED"
                for i, bucket in enumerate(buckets)]
    except _ControlCharacters:
        return [CONTROL_GUIDANCE]


def project_display_text(text: str, max_len: Optional[int] = 1024) -> str:
    try:
        if type(text) is not str:
            raise _InvalidField("guidance_projection_invalid_field")
        shown = project_text(text)
        if max_len is None:
            return shown
        if type(max_len) is not int or max_len < 3:
            raise _InvalidField("guidance_projection_invalid_field")
        if len(shown) <= max_len:
            return shown
        return clip_redacted(shown, max_len - 3) + "..."
    except GuidanceProjectionError as exc:
        return exc.code


def _diagnostic_space(char: str) -> bool:
    """Use repr's non-printable boundary, together with diagnostic whitespace."""
    return char.isspace() or not char.isprintable()


def _diagnostic_escape(match) -> str:
    """Preserve repr's literal pairs; only an odd trailing slash can escape."""
    slashes = match["slashes"]
    if slashes is None:
        # A literal run must not consume a following apparent escape body.
        return match[0]
    literal = slashes[:-1]
    if match["space"] is not None:
        return literal + " "
    if match["point"] is not None:
        point = int(match["point"][1:], 16)
        if point > 0x10FFFF:
            return match[0]
        char = chr(point)
    else:
        if match["closed"] != "}" or "\\" in match["name"] or not match["name"].isascii():
            raise _InvalidField(_InvalidField.code)
        try:
            char = unicodedata.lookup(match["name"])
        except KeyError:
            raise _InvalidField(_InvalidField.code) from None
    return literal + " " if any(_diagnostic_space(c) for c in char) else match[0]


def project_diagnostic(text: str, *, escaped: bool = True) -> str:
    """Bound, canonicalize, redact and clip diagnostics; literal parts use escaped=False."""
    if type(text) is not str or type(escaped) is not bool:
        return "guidance_projection_invalid_field"
    if len(text) > MAX_GUIDANCE_CHARS:
        return GuidanceProjectionError.code
    try:
        canonical = "".join(" " if _diagnostic_space(ch) else ch for ch in text)
        canonical = " ".join(canonical.split())
        # Each run starts once; named escapes end at the next brace or input end.
        literal = _DIAGNOSTIC_ESCAPES.sub(_diagnostic_escape, canonical) if escaped else canonical
        if escaped:
            literal = " ".join(literal.split())
        # Malformed nesting may create a fresh escape. Refuse it rather than recursively reparsing.
        if escaped and any(_diagnostic_escape(match) != match[0] for match in _DIAGNOSTIC_ESCAPES.finditer(literal)):
            return "guidance_projection_invalid_field"
        # Canonicalization and escape replacement only remove characters or
        # replace non-printables with spaces: size/control preflights still hold.
        shown = _redact_labeled(literal, None)[0]
        return shown if len(shown) <= 1024 else clip_redacted(shown, 1021) + "..."
    except GuidanceProjectionError as error:
        return error.code


def assembled_text(value: str) -> str:
    """Check a product assembly of projected components; return a plain string."""
    if type(value) is not str:
        raise _InvalidField(_InvalidField.code)
    _check_size(len(value))
    return CONTROL_GUIDANCE if contains_control_characters(value) else value


def _identifier_source(value, *, max_chars=MAX_GUIDANCE_CHARS):
    if type(value) is not str or not value:
        raise _InvalidField(_InvalidField.code)
    _check_size(len(value) + MAX_GUIDANCE_CHARS - max_chars)
    if any(c in value for c in "\t\n\r\u2028\u2029") or contains_control_characters(value):
        raise _InvalidField(_InvalidField.code)
    return value


def project_identifier(value: Any, registry: Optional[_Slots] = None) -> str:
    """Redact a literal identifier; registry never substitutes identifier text."""
    return redact_clean_text(_identifier_source(value))


def project_error_name(value: Any) -> str:
    """Return a fixed point within 32 passes, or the fixed invalid-field refusal."""
    try:
        # Bounded token rows can expose another match on each whole-name pass.
        # Count the equality check too; never publish an unconfirmed fixed point.
        for _ in range(_MAX_ERROR_NAME_PASSES):
            projected = project_identifier(value)
            if projected == value:
                return projected
            value = projected
    except _InvalidField:
        return _InvalidField.code
    return _InvalidField.code


# Schemas admit structure only at these envelope keys. Unknown keys are text,
# even inside a known record; they never grant another arbitrary JSON container.
_RECORD_FIELDS = frozenset({"relevant_rules", "invariant_warnings", "omitted_mandatory",
                            "stale_rules", "unreviewed_rules", "rule_errors"})
_OBJECT_FIELDS = frozenset({"stats", "rules_base", "user_layer"})
_NUMERIC_FIELDS = {
    "stats": frozenset({"total_rules", "matched", "budget", "changed_files", "estimated_tokens",
                        "max_tokens_budget", "clamped", "omitted", "omitted_mandatory"}),
    "rules_base": frozenset({"witnessed"}), "user_layer": frozenset({"rules"}),
    "record": frozenset({"fitness"}), "root": frozenset({"rules_staged", "unreviewed_total"}),
}


def _field_kind(key, context, fields):
    if key == "path" and (context == "user_layer" or context == "stale_rules"
                          and type(fields.get("change")) is str and fields["change"] == "removed"):
        return "nullable_identifier"
    if key in _IDENTIFIER_FIELDS or context == "rules_base" and key in {"ref", "commit"}:
        return "identifiers" if key in {"files", "matched_files"} else "identifier"
    numeric_context = "record" if context in _RECORD_FIELDS else context
    if key in _NUMERIC_FIELDS.get(numeric_context, ()):
        return "number"
    if context == "root" and key in _RECORD_FIELDS:
        return "records"
    if context == "root" and key in _OBJECT_FIELDS:
        return "object"
    if key in {"guidance", "body", "hypothesis", "prediction", "detail"}:
        return "text"
    return "auxiliary"


def _identifier_items(value, *, max_chars=MAX_GUIDANCE_CHARS):
    if type(value) is not list:
        raise _InvalidField(_InvalidField.code)
    if len(value) > MAX_IDENTIFIER_ITEMS:
        raise GuidanceProjectionError(GuidanceProjectionError.code)
    size = 0
    for item in value:
        if type(item) is not str or not item:
            raise _InvalidField(_InvalidField.code)
        size += len(item)
        _check_size(size + MAX_GUIDANCE_CHARS - max_chars)
    for item in value:
        _identifier_source(item)
    return value


def _retained_value(value, *, auxiliary=False):
    is_list = type(value) is list
    if auxiliary and not (type(value) is str or is_list and all(type(x) is str for x in value)):
        return [WITHHELD_GUIDANCE] if is_list else WITHHELD_GUIDANCE
    if value is None and not auxiliary:
        return ""
    if not (type(value) is str or is_list):
        raise _InvalidField(_InvalidField.code)
    try:
        retained, _ = _retained_items(value if is_list else [value])
    except _ControlCharacters:
        return [CONTROL_GUIDANCE] if is_list else CONTROL_GUIDANCE
    return retained if is_list else retained[0] if retained else ""


def project_assembled(value, registry=None, *, warnings=False):
    """An incoming assembly is untrusted text, without presentation protection."""
    return project_field(_retained_value(value, auxiliary=warnings), None if warnings else registry)


def _project_auxiliary(value):
    return project_field(_retained_value(value, auxiliary=True))


def _project_mapping(value, registry, context="root"):
    rendered = {}
    for key, item in value.items():
        kind = _field_kind(key, context, value)
        if kind == "nullable_identifier" and item is None:
            shown = None
        elif kind in {"identifier", "nullable_identifier"}:
            shown = project_identifier(item)
        elif kind == "identifiers":
            shown = [project_identifier(x) for x in _identifier_items(item)]
        elif kind == "number":
            shown = item
        elif kind == "records":
            shown = [_project_mapping(x, registry, key) for x in item]
        elif kind == "object":
            shown = _project_mapping(item, registry, key)
        elif kind == "text":
            shown = project_field(item, registry)
        else:
            shown = _project_auxiliary(item)
        rendered[key] = shown
    return rendered


def project_rule_entries(value: Any, registry: _Slots) -> list[Dict[str, Any]]:
    snapshot = checked_result_copy({"relevant_rules": value}, registry)
    return _project_mapping(snapshot, registry)["relevant_rules"]


def project_display_data(value: Any, registry: Optional[_Slots] = None) -> Any:
    if type(value) is dict:
        return _project_mapping(checked_result_copy(value, registry), registry)
    return _project_auxiliary(value)


def project_envelope_fields(result: Dict[str, Any], registry: _Slots) -> None:
    """Kinds are selected from keys before projection, including nested records."""
    auxiliary = {k: v for k, v in result.items() if k not in ("guidance", "relevant_rules", "invariant_warnings")}
    result.update(project_display_data(auxiliary, registry))


def field_text(value: str | list[str]) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        raise _InvalidField("guidance_projection_invalid_field")
    if len(value) > MAX_GUIDANCE_ITEMS:
        raise GuidanceProjectionError("guidance_projection_limit")
    if any(not isinstance(item, str) for item in value):
        raise _InvalidField("guidance_projection_invalid_field")
    _check_size(sum(len(item) for item in value) + 2 * max(0, len(value) - 1))
    return "; ".join(value)


def estimate_tokens(text: object | None) -> int:
    return guidance_token_estimate(text, ASCII_CHARS_PER_TOKEN, WORDS_TO_TOKENS_FACTOR)


def checked_result_copy(result: Dict[str, Any], registry: Optional[_Slots]) -> Dict[str, Any]:
    """Bound schema wrappers and retained text before copying or expansion.

    Structural nodes have a 4096 budget. Identifier-list leaves have their own
    per-list 4096 budget, plus the envelope character budget; a full list does
    not consume its wrappers' allowance.
    """
    nodes, source_chars, rendered_chars = 0, 0, 0

    def charge(value, *, instruction):
        nonlocal source_chars, rendered_chars
        source_chars += len(value)
        _check_size(source_chars)
        try:
            expanded = _expanded_text(value, registry if instruction else None, body=False,
                                      max_chars=MAX_GUIDANCE_CHARS - rendered_chars)
            rendered_chars += len(expanded)
        except _ControlCharacters:
            rendered_chars += len(CONTROL_GUIDANCE)
        _check_size(rendered_chars)

    def node():
        nonlocal nodes
        nodes += 1
        if nodes > 4096:
            raise GuidanceProjectionError(GuidanceProjectionError.code)

    def mapping(value, context="root"):
        nonlocal source_chars, rendered_chars
        node()
        if type(value) is not dict:
            raise _InvalidField(_InvalidField.code)
        if len(value) > 4096:
            raise GuidanceProjectionError(GuidanceProjectionError.code)
        copied = {}
        for key, item in value.items():
            node()
            if type(key) is not str:
                raise _InvalidField(_InvalidField.code)
            source_chars += len(key)
            rendered_chars += len(key)
            _check_size(source_chars)
            _check_size(rendered_chars)
            if project_identifier(key) != key:
                raise _InvalidField(_InvalidField.code)
            kind = _field_kind(key, context, value)
            node()
            if kind == "nullable_identifier" and item is None:
                copied[key] = None
            elif kind in {"identifier", "identifiers", "nullable_identifier"}:
                remaining = min(MAX_GUIDANCE_CHARS - source_chars, MAX_GUIDANCE_CHARS - rendered_chars)
                values = _identifier_items(item, max_chars=remaining) if kind == "identifiers" else [item]
                for identifier in values:
                    # Identifiers are literal; both budgets charge their raw size.
                    remaining = min(MAX_GUIDANCE_CHARS - source_chars, MAX_GUIDANCE_CHARS - rendered_chars)
                    literal = _identifier_source(identifier, max_chars=remaining)
                    source_chars += len(literal)
                    rendered_chars += len(literal)
                copied[key] = list(values) if kind == "identifiers" else item
            elif kind == "number":
                if not (item is None and key == "fitness" or type(item) is bool and key != "fitness"
                        or type(item) is int and item.bit_length() <= 4096
                        or type(item) is float and math.isfinite(item)):
                    raise _InvalidField(_InvalidField.code)
                copied[key] = item
            elif kind == "object":
                copied[key] = mapping(item, key)
            elif kind == "records":
                if type(item) is not list:
                    raise _InvalidField(_InvalidField.code)
                cap = MAX_GUIDANCE_ITEMS if key in {"relevant_rules", "invariant_warnings"} else 4096
                if len(item) > cap:
                    raise GuidanceProjectionError(GuidanceProjectionError.code)
                copied[key] = [mapping(x, key) for x in item]
            else:
                retained = _retained_value(item, auxiliary=kind == "auxiliary")
                for text in retained if type(retained) is list else [retained]:
                    node()
                    charge(text, instruction=kind == "text")
                copied[key] = retained
        return copied

    return mapping(result)


def projection_refusal_copy(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Recognize a bounded canonical refusal before compatibility budgeting.

    Plain/JSON copies have no private marker. Only the exact refusal shape,
    fixed field/reason tokens and already projected paths receive the exemption.
    Other envelopes still take the ordinary projection and budgeting route.
    """
    if type(result) is not dict or len(result) not in (2, 3):
        return None
    if any(type(key) is not str for key in result):
        return None
    if set(result) not in ({"status", "error"}, {"status", "error", "rule_errors"}):
        return None
    if type(result["status"]) is not str or type(result["error"]) is not str:
        return None
    if result["status"] != "FAIL" or result["error"] not in {
            "guidance_projection_invalid_field", "guidance_projection_limit"}:
        return None
    snapshot = checked_result_copy(result, None)
    reasons = {field + ": " + reason for field in ("hypothesis", "prediction", "detail", "matched_files")
               for reason in ("invalid_field", "limit")}
    # Bounds/type validation precedes inspection; eligibility uses the original
    # reason so Evidence removal cannot manufacture a canonical refusal token.
    for row in result.get("rule_errors", []):
        if (set(row) != {"path", "error"} or type(row["error"]) is not str
                or row["error"] not in reasons or project_error_name(row["path"]) != row["path"]):
            return None
    return snapshot


def _stamp_tokens(result: Dict[str, Any]) -> int:
    stats = result.get("stats")
    if isinstance(stats, dict):
        stats["estimated_tokens"] = 0
        for _ in range(8):
            tokens = estimate_tokens(json.dumps(result))
            if stats["estimated_tokens"] == tokens:
                return tokens
            stats["estimated_tokens"] = tokens
        raise GuidanceProjectionError("guidance_projection_limit")
    return estimate_tokens(json.dumps(result))


def _reserve_warning_budget(result: Dict[str, Any], budget: int) -> Optional[Dict[str, Any]]:
    def fits(candidate: Dict[str, Any]) -> bool:
        if _stamp_tokens(candidate) > budget:
            return False
        reserved = dict(candidate, warnings=["scan warning"])
        if isinstance(candidate.get("stats"), dict):
            reserved["stats"] = dict(candidate["stats"])
        return _stamp_tokens(reserved) <= budget

    if fits(result):
        return result
    compact = dict(result)
    if isinstance(result.get("stats"), dict):
        optional = {"total_rules", "matched", "budget", "changed_files", "clamped"}
        compact["stats"] = {key: value for key, value in result["stats"].items() if key not in optional}
    if result.get("warnings"):
        compact["warnings"] = ["scan warning"]
    return compact if fits(compact) else None


def _compatibility_mandatory_count(entries) -> int:
    """Count unknown policy as mandatory; display labels cannot prove advisory."""
    if type(entries) is not list or any(type(entry) is not dict for entry in entries):
        raise _InvalidField(_InvalidField.code)
    count = 0
    for entry in entries:
        kind = entry.get("type")
        spec = RULE_TYPES.get(kind) if type(kind) is str else None
        enforcement = entry.get("enforcement")
        advisory = (spec is not None and not spec.mandatory and type(enforcement) is str
                    and enforcement in ("advisory", "mechanical"))
        count += not advisory
    return count


def _discarded_selection_stats(result, stats, mandatory_count):
    entries = result.get("relevant_rules", [])
    if type(entries) is not list:
        raise _InvalidField(_InvalidField.code)
    if not entries:
        return stats
    if mandatory_count is None:
        mandatory_count = _compatibility_mandatory_count(entries)
    if type(mandatory_count) is not int or not 0 <= mandatory_count <= len(entries):
        raise _InvalidField(_InvalidField.code)
    updated = dict(stats or {})
    for key, amount in (("omitted", len(entries)), ("omitted_mandatory", mandatory_count)):
        previous = updated.get(key, 0)
        if type(previous) is not int or previous < 0:
            raise _InvalidField(_InvalidField.code)
        updated[key] = previous + amount
    return updated


def finish_payload(result: Dict[str, Any], *, preserve_omissions: bool = False,
                   reserve_warning: bool = False,
                   staged_mandatory_count: Optional[int] = None) -> Dict[str, Any]:
    """Measure an owned result; bound opaque overflow by a fixed budget refusal."""
    stats = result.get("stats")
    if stats is not None and not isinstance(stats, dict):
        raise _InvalidField("guidance_projection_invalid_field")
    budget = stats.get("max_tokens_budget", JIT_DEFAULT_MAX_TOKENS) if stats is not None else JIT_DEFAULT_MAX_TOKENS
    if type(budget) is not int or budget <= 0:
        raise _InvalidField("guidance_projection_invalid_field")
    if reserve_warning:
        compact = _reserve_warning_budget(result, budget)
        if compact is not None:
            return compact
    elif _stamp_tokens(result) <= budget:
        return result
    # Every remaining branch discards all staged entries. Record that loss
    # once; warning/statistics-only compaction above retains the selection.
    stats = _discarded_selection_stats(result, stats, staged_mandatory_count)
    if preserve_omissions and stats is not None and "omitted_mandatory" in stats:
        # Retain omission counts even when only a minimal fixed envelope fits.
        compact = {"guidance": "Guidance omitted.", "relevant_rules": [], "stats": {
            "max_tokens_budget": budget, "estimated_tokens": 0,
            "omitted": stats.get("omitted", 0), "omitted_mandatory": stats["omitted_mandatory"],
        }}
        if result.get("warnings"):
            compact["warnings"] = ["scan warning"]
        if "status" in result:
            compact["status"] = result["status"]
        # Reserve warning capacity so a slot warning cannot change scan status.
        reserved = dict(compact, stats=dict(compact["stats"]), warnings=["scan warning"])
        if _stamp_tokens(reserved) > budget:
            refusal = {"status": "FAIL", "error": "guidance_projection_budget", "stats": compact["stats"]}
            _stamp_tokens(refusal)
            return refusal
        _stamp_tokens(compact)
        return compact
    refusal = {"status": "FAIL", "error": "guidance_projection_budget",
               "stats": {"max_tokens_budget": budget, "estimated_tokens": 0}}
    if stats is not None:
        for key in ("omitted", "omitted_mandatory"):
            if type(stats.get(key)) is int:
                refusal["stats"][key] = stats[key]
    if _stamp_tokens(refusal) <= budget:
        return refusal
    if "omitted_mandatory" in refusal["stats"]:
        return refusal  # the fixed refusal envelope must retain the known count
    # A budget below even the refusal's fixed envelope cannot carry statistics.
    return {"status": "FAIL", "error": "guidance_projection_budget"}


