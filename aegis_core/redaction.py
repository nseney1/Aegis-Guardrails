"""The one secret-redaction table and its entry points (L0: the standard library only).

Every text Aegis persists or echoes goes through this table: the hook command log
(``redact_command_secrets``, through aegis_cli.hooks.redaction), stored insight text
(``redact_insight_text``) and the snippet of a secret finding (aegis_core.verification.scanners
masks with ``TOKEN_REDACTIONS`` and ``is_high_entropy_secret``). URL credential removal
(``remove_url_credentials``) and atomic clipping (``clip_atomic_text``) live here as well.
"""
from __future__ import annotations

import collections
from dataclasses import dataclass, field
import math
import re
import unicodedata
from typing import Any

__all__ = [
    "CANDIDATE_TOKEN_RE",
    "MAX_EXCERPT_CHARS",
    "MAX_LINE_LENGTH",
    "REDACTION_MASK_RE",
    "SECRET_REPLACEMENTS",
    "TOKEN_REDACTIONS",
    "is_high_entropy_secret",
    "mask_secret",
    "redact_command_secrets",
    "redact_insight_text",
    "shannon_entropy",
    "MAX_GUIDANCE_CHARS",
    "clip_rendered_text",
    "clip_atomic_text",
    "remove_url_credentials",
    "REDACTION_MARKER_RE",
    "RedactionRefusal",
    "command_token",
    "GUIDANCE_ESCAPE_PATTERN",
    "guidance_field",
    "guidance_value",
    "receipt_value",
]

# The longest text handled whole: redact_insight_text keeps a whole-word head of a longer one
# (at least this many characters), and a scanner finding on a longer line shows the masked token alone.
MAX_LINE_LENGTH = 4096
MAX_EXCERPT_CHARS = 300

_NB = r"(?<![A-Za-z0-9])"
_PEM_HEAD = r"-----BEGIN (?P<pem_label>(?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?)-----"
_PEM_TAIL = r"-----END (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----"
_KEYS = ("(?:password|passwd|pwd|secret|token|api_?key|access_?key|private_?key|client_?secret|credential|"
         "authorization|auth(?![A-Za-z]))")
_SCHEMES = "(?:basic|digest|token|negotiate)"
# Built by concatenation, never as an rf-string: f-string formatting turns a {4,} quantifier
# into the tuple "(4,)". Token quantifiers are bounded; PEM consumes once to its END or EOF.
_SECRET_REDACTIONS: tuple[tuple[re.Pattern[str], str, str], ...] = tuple(
    (re.compile(pattern), hook, text) for pattern, hook, text in (
        # Only the BEGIN label's own END closes a key; otherwise the suffix stays untrusted. EOF matches,
        # so repeated BEGIN markers cannot retry scans over the same unterminated body.
        (_PEM_HEAD + r"[\s\S]*?(?:-----END (?P=pem_label)-----|\Z)", "[REDACTED_PEM]", "[REDACTED_PEM]"),
        # The scheme is optional because Tier A blocks a bare "://user:<password>@host" too.
        ("(?i)((?:" + _NB + "[a-z][a-z0-9+.-]{0,31})?://[^\\s:/@]{1,128}:)[^\\s@/]{1,512}@", r"\1[REDACTED]@",
         r"\1[REDACTED]@"),
        (_NB + r"eyJ[A-Za-z0-9_-]{8,512}\.[A-Za-z0-9_-]{4,1024}\.[A-Za-z0-9_-]{4,512}", "[REDACTED_JWT]",
         "[REDACTED_JWT]"),
        (_NB + "AKIA[0-9A-Z]{16}", "AKIA_REDACTED", "[REDACTED_AWS]"),
        (_NB + "ASIA[0-9A-Z]{16}", "ASIA_REDACTED", "[REDACTED_AWS]"),
        (_NB + "(?:AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}", "[REDACTED_AWS]", "[REDACTED_AWS]"),
        (_NB + "ghp_[A-Za-z0-9]{20,255}", "ghp_REDACTED", "[REDACTED_VCS_TOKEN]"),
        (_NB + "gh[ousr]_[A-Za-z0-9]{20,255}", "gh_token_REDACTED", "[REDACTED_VCS_TOKEN]"),
        (_NB + "github_pat_[A-Za-z0-9_]{20,255}", "github_pat_REDACTED", "[REDACTED_VCS_TOKEN]"),
        (_NB + "glpat-[A-Za-z0-9_-]{16,255}", "[REDACTED_VCS_TOKEN]", "[REDACTED_VCS_TOKEN]"),
        (_NB + "(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,99}", "[REDACTED_API_KEY]", "[REDACTED_API_KEY]"),
        (_NB + "sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,255}", "sk-REDACTED", "[REDACTED_API_KEY]"),
        (_NB + "AIza[A-Za-z0-9_-]{25,255}", "AIzaSy_REDACTED", "[REDACTED_TOKEN]"),
        (_NB + "(?:xox[abprs]-[A-Za-z0-9-]{10,255}|npm_[A-Za-z0-9]{20,255}|pypi-[A-Za-z0-9_-]{20,255})",
         "[REDACTED_TOKEN]", "[REDACTED_TOKEN]"),
        ("(?i)" + _NB + r"Bearer\s{1,8}[A-Za-z0-9._~+/=-]{16,1024}", "Bearer REDACTED", "Bearer [REDACTED]"),
        # key=value and key: value; an Authorization scheme word is kept and its credential goes.
        ("(?i)(" + _NB + "[A-Za-z0-9_]{0,32}" + _KEYS + "[A-Za-z0-9_]{0,32}[\"']?\\s{0,8}(?:=|:)\\s{0,8}[\"']?"
         "(?:" + _SCHEMES + "\\s{1,8})?)(?!" + _SCHEMES + "\\b)([^\\s\"',;]{4,512})", r"\1REDACTED", r"\1[REDACTED]"),
        # "the password is hunter2": the narrow keys only, so "the auth is broken" stays.
        ("(?i)(" + _NB + "(?:password|passwd|pwd|secret|token|api key|private key)\\s{1,8}is\\s{1,8}[\"']?)"
         "([^\\s\"',;]{6,512})", r"\1REDACTED", r"\1[REDACTED]"),
    ))
#: The hook-log form of the table: (pattern, replacement), applied in order.
SECRET_REPLACEMENTS: list[tuple[re.Pattern[str], str]] = [(p, hook) for p, hook, _ in _SECRET_REDACTIONS]
#: Personal data, scrubbed from stored insights only: the hook log keeps paths and addresses.
_PII_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,63}(?![A-Za-z0-9])"),
     "[REDACTED_EMAIL]"),
    (re.compile(r"(?<=/home/)[^/\s]{1,255}|(?<=/Users/)[^/\s]{1,255}|(?<=C:\\Users\\)[^\\\s]{1,255}"), "~user"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED_IP]"),
)
_TEXT_REDACTIONS = tuple((p, text) for p, _, text in _SECRET_REDACTIONS) + _PII_REDACTIONS
# The single-token rows, safe over a snippet that already carries masks: PEM spans lines, and the URL
# userinfo and keyed rows (the ones with a backreference) rewrite whatever follows, masks included.
TOKEN_REDACTIONS = tuple((p, text) for p, _, text in _SECRET_REDACTIONS if "\\1" not in text and text != "[REDACTED_PEM]")
_HEX_UUID_RE = re.compile(r"^(?:[0-9a-fA-F]{7,64}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")
CANDIDATE_TOKEN_RE = re.compile(r"[A-Za-z0-9+_=-]{20,}")
_HIGH_ENTROPY_MASK = "[REDACTED_HIENT]"


def _mask_grammar():
    """Derive literal masks from the shared replacements, without their context."""
    masks = {_HIGH_ENTROPY_MASK}
    for replacement in (*[hook for _pattern, hook, _text in _SECRET_REDACTIONS],
                        *[text for _pattern, text in _TEXT_REDACTIONS]):
        if replacement.startswith(r"\1"):
            replacement = replacement[2:]
            if replacement.endswith("@"):
                replacement = replacement[:-1]
        # Bearer is fixed context; only its final opaque token is a mask.
        # No mask identity includes whitespace separating it from context.
        masks.add(replacement.split()[-1])
    return re.compile("|".join(re.escape(mask) for mask in sorted(masks, key=lambda value: (-len(value), value))))


# Public grammar over logical text. Consumers decode inert literal escapes only
# for matching, then carry these spans with the original units through clipping.
REDACTION_MASK_RE = _mask_grammar()


def mask_secret(secret: str) -> str:
    if len(secret) <= 6:
        return f"{secret[:2]}..." if len(secret) > 2 else "***"
    return f"{secret[:4]}...{secret[-2:]}"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = collections.Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_high_entropy_secret(tok: str, threshold: float = 3.8) -> bool:
    if "REDACTED" in tok or _HEX_UUID_RE.match(tok) or not any(c.isdigit() for c in tok):
        return False
    classes = int(any(c.islower() for c in tok)) + int(any(c.isupper() for c in tok)) + 1
    if classes < 2:
        return False
    return shannon_entropy(tok) >= threshold


def redact_command_secrets(cmd: str) -> str:
    """Mask known secret patterns in command strings before logging."""
    for pattern, replacement in SECRET_REPLACEMENTS:
        cmd = pattern.sub(replacement, cmd)
    return cmd


def _bounded_head(text: str, limit: int) -> str:
    """The whole words of ``text`` up to about ``limit`` characters. A secret cut in half
    would no longer match its pattern, so a word the cut splits is dropped, as is a trailing
    PEM header whose END lies past the cut."""
    raw = text[: limit + 1]
    words = raw.split()
    if words and not raw[-1].isspace():
        words.pop()
    head = " ".join(words)
    begin = head.rfind("-----BEGIN")
    # Drop the trailing incomplete block before redaction; only a whole END marker closes it.
    # The join turned newlines into single spaces.
    return head[:begin].rstrip() if begin != -1 and not re.search(_PEM_TAIL, head[begin:]) else head


def _sub_replacements(pattern, replacement, text, on_replacements):
    """Substitute once and report only changed spans, never matched secrets.

    Only explicit backreference context stays outside a replacement interval.
    Equal characters at a mask edge are still secret source units, not context.
    """
    spans = []

    def substitute(match):
        before = match.group(0)
        after = replacement(match) if callable(replacement) else match.expand(replacement)
        if before != after:
            start, end, payload = match.start(), match.end(), after
            if isinstance(replacement, str) and replacement.startswith(r"\1"):
                start = match.end(1)
                payload = match.expand(replacement[2:])
                if replacement.endswith("@"):
                    end -= 1
                    payload = payload[:-1]
            spans.append((start, end, payload))
        return after

    out = pattern.sub(substitute, text)
    if spans:
        on_replacements(tuple(spans))
    return out


def redact_insight_text(text: str, max_len: int = MAX_EXCERPT_CHARS, *, on_replacements=None) -> str:
    """Scrub secrets, PII, paths, IPs, and high-entropy tokens from insight text; past
    ``max(MAX_LINE_LENGTH, 4 * max_len)`` characters only a whole-word head is kept.

    An optional callback receives ordered (start, end, replacement) tuples after
    each substitution pass, relative to that pass's bounded input. Only changed
    intervals are reported. Initial bounding and final whitespace/excerpt
    formatting are not events. Callback failures propagate without a result.
    """
    if not isinstance(text, str) or not text:
        return ""
    limit = max(MAX_LINE_LENGTH, 4 * max_len)
    out = text if len(text) <= limit else _bounded_head(text, limit)
    for pat, repl in _TEXT_REDACTIONS:
        out = pat.sub(repl, out) if on_replacements is None else _sub_replacements(pat, repl, out, on_replacements)
    entropy = lambda m: _HIGH_ENTROPY_MASK if is_high_entropy_secret(m.group(0)) else m.group(0)
    out = CANDIDATE_TOKEN_RE.sub(entropy, out) if on_replacements is None else \
        _sub_replacements(CANDIDATE_TOKEN_RE, entropy, out, on_replacements)
    out = " ".join(out.split())
    if max_len > 0 and len(out) > max_len:
        sliced = out[:max_len]
        last_open = sliced.rfind("[REDACTED")
        if last_open != -1 and "]" not in sliced[last_open:]:
            out = sliced[:last_open].rstrip()
        else:
            out = sliced
    return out


MAX_GUIDANCE_CHARS = 8 * 1024
_COMMAND_TOKEN = re.compile(r"[A-Za-z0-9._/@+-]+")
_HEX_ESCAPE = re.compile(r"\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U(?:000[0-9a-fA-F]{5}|0010[0-9a-fA-F]{4}))")
GUIDANCE_ESCAPE_PATTERN = _HEX_ESCAPE.pattern


def command_token(value: Any, limit: int = 400) -> bool:
    """A bounded unchanged token safe to copy in POSIX, PowerShell and cmd."""
    return (isinstance(value, str) and 0 < len(value) <= limit and not value.startswith("-")
            and _COMMAND_TOKEN.fullmatch(value) is not None)


@dataclass(frozen=True)
class _DisplayUnit:
    text: str
    escaped: bool = False
    # A replacement's identity travels with its units. Equality compares output
    # units, so a redactor reporting the same bytes cannot prevent convergence.
    mask: Any = field(default=None, compare=False)
    escape_atom: Any = field(default=None, compare=False)

    def __iter__(self):
        yield self.text
        yield self.escaped


def _escape_units(value: str):
    """Walk literal escapes atomically; never decode them into shell syntax."""
    offset = 0
    while offset < len(value):
        match = _HEX_ESCAPE.match(value, offset)
        end = match.end() if match is not None else offset + 1
        yield _DisplayUnit(value[offset:end], match is not None)
        offset = end


def _literal_escape_units(units):
    """Keep preserved non-hex forms atomic without changing the matching shadow."""
    index = 0
    while index < len(units):
        unit = units[index]
        if unit.escaped or unit.text != "\\":
            index += 1
            continue
        end = min(index + 2, len(units))
        if end == index + 2 and not units[index + 1].escaped and units[index + 1].text in ("x", "u", "U"):
            bound = min(len(units), index + 2 + {"x": 2, "u": 4, "U": 8}[units[index + 1].text])
            while end < bound and not units[end].escaped and units[end].text in "0123456789abcdefABCDEF":
                end += 1
        atom = object()
        for offset in range(index, end):
            current = units[offset]
            units[offset] = _DisplayUnit(current.text, current.escaped, current.mask, atom)
        index = end  # Strictly increases; at most len(units) groups are visited.
    return units


def _shares_atom(left, right):
    return ((left.mask is not None and left.mask is right.mask)
            or (left.escape_atom is not None and left.escape_atom is right.escape_atom))


def _safe_cut_tail(units, *, escape=True):
    """Do not let a cut prefix and its next atom spell a newly valid escape."""
    # A preserved hex spelling has at most ten logical characters. Only the
    # rightmost raw slash can start an escape completed by the following atom.
    for index in range(len(units) - 1, max(-1, len(units) - 11), -1):
        unit = units[index]
        if unit.escaped or unit.text != "\\":
            continue
        tail = units[index + 1:]
        raw = "".join(part.text for part in tail) if not any(part.escaped for part in tail) else None
        partial = raw is not None and (not raw or raw.isspace() or (
            raw[0] in ("x", "u", "U") and len(raw) <= {"x": 2, "u": 4, "U": 8}[raw[0]]
            and all(char in "0123456789abcdefABCDEF" for char in raw[1:])))
        if partial:
            if not escape:
                while index and _shares_atom(units[index - 1], units[index]):
                    index -= 1
                return units[:index]
            units = list(units)
            units[index] = _DisplayUnit(r"\x5c", True, unit.mask, unit.escape_atom)
        return units
    return units


def _unit_shadow(units):
    """Decode for matching only; retain opaque non-whitespace control classes.

    Hex spelling must not create new entropy candidates on a second pass.
    The decoded shadow is used only by the redactor, never by a shell or by
    the output path. Opaque non-whitespace controls retain inert markers;
    escaped whitespace keeps its character class for every redaction pattern.
    """
    chars = [chr(int(unit[2:], 16)) if escaped else unit for unit, escaped in units]
    used = set(chars)
    next_marker = 0xf0000
    for index, ((unit, escaped), char) in enumerate(zip(units, chars)):
        if escaped and not char.isspace() and (not char.isprintable() or unicodedata.category(char) == "Cf"):
            while chr(next_marker) in used:
                next_marker += 1
            marker = chr(next_marker)
            next_marker += 1
            used.add(marker)
            chars[index] = marker
    return "".join(chars)


def _apply_replacements(units, spans):
    # Coordinates refer to this pass's shadow (one character per unit). Only
    # unchanged intervals reuse source units; every replacement is a fresh atom.
    retained, cursor, torn = [], 0, False
    for start, end, replacement in spans:
        # A later rule can rewrite only part of an earlier mask. That destroys
        # its carried boundary; the caller must omit the entire value rather
        # than expose an orphaned fragment or infer a new boundary from text.
        torn |= (0 < start < len(units) and units[start].mask is not None
                 and units[start - 1].mask is units[start].mask)
        torn |= (0 < end < len(units) and units[end - 1].mask is not None
                 and units[end - 1].mask is units[end].mask)
        retained.extend(units[cursor:start])
        mask = object()
        end_token = len(replacement.rstrip())
        tokens = replacement.split()
        start_token = end_token - len(tokens[-1]) if tokens else end_token
        retained.extend(_DisplayUnit(char, mask=mask if start_token <= index < end_token else None)
                        for index, char in enumerate(replacement))
        cursor = end
    retained.extend(units[cursor:])
    units[:] = retained
    return torn


def _existing_mask_units(units):
    """Attach the redactor's mask spans before any clipping, retaining spelling."""
    for match in REDACTION_MASK_RE.finditer(_unit_shadow(units)):
        mask = object()
        for index in range(match.start(), match.end()):
            unit = units[index]
            units[index] = _DisplayUnit(unit.text, unit.escaped, mask, unit.escape_atom)
    return units


def _redact_units(units):
    """Use reported secret spans; never infer mask structure from its spelling."""
    units = list(units)
    torn = [False]

    def apply(spans):
        if _apply_replacements(units, spans):
            torn[0] = True

    redact_insight_text(_unit_shadow(units), max_len=10 * MAX_GUIDANCE_CHARS,
                        on_replacements=apply)
    return None if torn[0] else units


def _identifier_units(units):
    """The existing receipt rules, with replacement atoms for bounded clipping."""
    units = list(units)
    shadow = _unit_shadow(units)
    for pattern, replacement in (*TOKEN_REDACTIONS, *SECRET_REPLACEMENTS):
        spans = []

        def substitute(match):
            after = match.expand(replacement)
            if after != match.group(0):
                start, end, payload = match.start(), match.end(), after
                if replacement.startswith(r"\1"):
                    start = match.end(1)
                    payload = match.expand(replacement[2:])
                    if replacement.endswith("@"):
                        end -= 1
                        payload = payload[:-1]
                spans.append((start, end, payload))
            return after

        shadow = pattern.sub(substitute, shadow)
        if _apply_replacements(units, spans):
            return None
    return units


def _clip_units(units, limit):
    """Keep a cut replacement whole, reserving room without tearing prior atoms."""
    if not 0 < limit < len(units):
        return units[:limit]
    if not _shares_atom(units[limit - 1], units[limit]):
        return _safe_cut_tail(units[:limit])
    start, end = limit, limit
    # Each scan strictly consumes an index within the bounded unit list. Shared
    # escape/mask edges also preserve overlapping atoms as one connected range.
    while start and _shares_atom(units[start - 1], units[start]):
        start -= 1
    while end < len(units) and _shares_atom(units[end - 1], units[end]):
        end += 1
    if end - start > limit:
        return _safe_cut_tail(units[:start])
    boundary = limit - (end - start)
    while boundary and _shares_atom(units[boundary - 1], units[boundary]):
        boundary -= 1
    return _safe_cut_tail(units[:boundary]) + units[start:end]


def _stable_units(canonical, limit, redact):
    """Clip and re-redact with finite fuel; exhaustion returns no source text.

    The strictly decreasing measure is the remaining pass budget (16 down to
    zero), not a claim that mask text is opaque to every future rule. Even an
    adversarial/nonconverging redactor therefore fails closed within 17 calls.
    """
    units = redact(_existing_mask_units(_literal_escape_units(list(_escape_units(canonical)))))
    if units is None:
        return None
    for _remaining in range(16, 0, -1):
        clipped = _clip_units(units, limit)
        redacted = redact(clipped)
        if redacted is None:
            return None
        if redacted == clipped:
            return clipped
        units = redacted
    return None


def _redacted_units(canonical: str, limit: int):
    return _stable_units(canonical, limit, _redact_units)


def clip_rendered_text(value: str, limit: int = 400, *, ellipsis: bool = True, canonicalize) -> str:
    """Cap finished text by wire characters, preserving its template and atoms.

    Callers render/redact their data fields before interpolation. This boundary
    never escapes template text; it re-redacts cuts that create a new match.
    Oversized input is omitted before sanitization or unit-list allocation.
    """
    limit = min(MAX_GUIDANCE_CHARS, max(0, limit))
    if len(value) > 10 * MAX_GUIDANCE_CHARS or (len(value) > MAX_GUIDANCE_CHARS
            and any(index >= MAX_GUIDANCE_CHARS for index, _unit in enumerate(_escape_units(value)))):
        return "diagnostic_omitted_too_large"[:limit]
    canonical = canonicalize(value, max_len=None)
    if len(canonical) <= limit:
        return canonical
    suffix = "." * min(3, limit) if ellipsis else ""
    units = _existing_mask_units(_literal_escape_units(list(_escape_units(canonical))))
    # A cut can create a redaction match even in already rendered fields, for
    # example by dropping the x from 1.2.3.4x. The strictly decreasing measure
    # is the remaining pass budget; exhaustion omits the value within 16 calls.
    for _remaining in range(16, 0, -1):
        if sum(len(unit.text) for unit in units) > limit:
            boundary, size = 0, 0
            budget = limit - len(suffix)
            # Strictly increasing indices, bounded by the input and wire budget.
            while boundary < len(units) and size + len(units[boundary].text) <= budget:
                size += len(units[boundary].text)
                boundary += 1
            # Keep connected escape/mask atoms whole without splicing in later
            # units. Drop a pending escape rather than expand past the budget.
            while boundary and boundary < len(units) and _shares_atom(units[boundary - 1], units[boundary]):
                boundary -= 1
            units = _safe_cut_tail(units[:boundary], escape=False) + list(_escape_units(suffix))
        redacted = _redact_units(units)
        if redacted is None:
            break
        if redacted == units:
            return "".join(unit.text for unit in units)
        units = redacted
    return "diagnostic_omitted_too_large"[:limit]


def guidance_value(value: str, limit: int = 400, *, prose: bool = False, canonicalize) -> str:
    """One inert guidance field: bound input, canonicalize, redact, truncate, escape.

    At most 8192 logical units (81920 wire characters) enter the pipeline.
    Escaping expands each retained unit by at most ten ASCII characters; no value
    is wrapped in shell quotes. Sentence values escape execution/chain syntax
    and surviving control/format characters; their other punctuation is kept.
    This formats values only, never completed sentences or protocol properties.
    """
    limit = min(MAX_GUIDANCE_CHARS, max(0, limit))
    # Bound wire size before lexing, and logical size before canonicalization.
    # This also accepts the bounded expansion of our own previously shown value.
    if len(value) > 10 * MAX_GUIDANCE_CHARS or (len(value) > MAX_GUIDANCE_CHARS
            and any(index >= MAX_GUIDANCE_CHARS for index, _unit in enumerate(_escape_units(value)))):
        return "diagnostic_omitted_too_large"[:max(0, limit)]
    canonical = " ".join(canonicalize(value, max_len=None).split())
    units = _redacted_units(canonical, limit)
    if units is None:
        return "diagnostic_omitted_too_large"[:limit]
    shown = []
    for index, (char, escaped) in enumerate(units):
        if escaped:
            # Preserved \xHH, \uHHHH and valid \UHHHHHHHH spellings are inert
            # text, never decoded on output. No raw execution character can
            # survive this display path, including in a Unicode escape.
            shown.append(char)
            continue
        allowed = (char not in "$`\\;&|<>!()'\"" and char.isprintable()
                   and unicodedata.category(char) != "Cf") if prose else _COMMAND_TOKEN.fullmatch(char)
        if allowed and not (not prose and index == 0 and char == "-"):
            shown.append(char)
        else:
            codepoint = ord(char)
            shown.append(f"\\x{codepoint:02x}" if codepoint <= 0xff else
                         f"\\u{codepoint:04x}" if codepoint <= 0xffff else f"\\U{codepoint:08x}")
    # A cut after a canonical space must not leave a new trailing space for the
    # next canonicalization pass to remove.
    rendered = "".join(shown).rstrip()
    return re.sub(r":(?=:)", r"\\x3a", rendered)


def receipt_value(value: str, limit: int = 120, *, identifier: bool = False, canonicalize=None,
                  default_canonicalize) -> str:
    """Bound, canonicalize, redact and clip receipt fields at stable mask units."""
    limit = min(MAX_GUIDANCE_CHARS, max(0, limit))
    omitted = "[diagnostic omitted: too_large]"
    if len(value) > 10 * MAX_GUIDANCE_CHARS or (len(value) > MAX_GUIDANCE_CHARS
            and any(index >= MAX_GUIDANCE_CHARS for index, _unit in enumerate(_escape_units(value)))):
        return omitted if len(omitted) <= limit else ""
    canonical = (canonicalize or default_canonicalize)(value, max_len=None)
    if not identifier:
        canonical = " ".join(canonical.split())
    units = _stable_units(canonical, limit, _identifier_units if identifier else _redact_units)
    if units is None:
        return omitted if len(omitted) <= limit else ""
    shown = []
    for char, escaped in units:
        if not escaped and (not char.isprintable() or unicodedata.category(char) == "Cf"):
            codepoint = ord(char)
            char = (f"\\x{codepoint:02x}" if codepoint <= 0xff else
                    f"\\u{codepoint:04x}" if codepoint <= 0xffff else f"\\U{codepoint:08x}")
        shown.append(char)
    return "".join(shown).rstrip() if not identifier else "".join(shown)


def guidance_field(value, separators=(), *, canonicalize):
    """Render data once, then prevent it from impersonating a field separator."""
    shown = guidance_value(value, prose=True, canonicalize=canonicalize)
    if not separators:
        return shown
    pattern = re.compile("|".join(re.escape(token) for token in separators))

    def encode(raw):
        # Check each source position, including overlapping separators. Existing
        # inert escapes are separate units and never edited as literal text.
        parts = []
        for index, char in enumerate(raw):
            if pattern.match(raw, index):
                codepoint = ord(char)
                char = (f"\\x{codepoint:02x}" if codepoint <= 0xff else
                        f"\\u{codepoint:04x}" if codepoint <= 0xffff else f"\\U{codepoint:08x}")
            parts.append(char)
        return "".join(parts)

    result, literal = [], []
    for char, escaped in _escape_units(shown):
        if escaped:
            result.extend((encode("".join(literal)), char))
            literal.clear()
        else:
            literal.append(char)
    result.append(encode("".join(literal)))
    return "".join(result)


# Bound the shared helpers before tokenization or matching. Proposal callers
# additionally enforce their smaller MAX_TEXT input and expansion budgets.
_CLEANER_INPUT_MAX = max(MAX_LINE_LENGTH, MAX_GUIDANCE_CHARS)
_CLEANER_GUIDANCE_INPUT_MAX = 1024 * 1024
_URL_CLOSERS = ")]}>.,;:!?`'\""


class RedactionRefusal(ValueError):
    """Shared-cleaner refusal. The message is ``invalid`` or ``too_large``, never input."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


# Complete ``[REDACTED...]`` atoms. Clipping and proposal parameter stripping share it.
REDACTION_MARKER_RE = re.compile(r"\[REDACTED(?:_[A-Z]+)*\]")


def _refuse_cleaner(code):
    raise RedactionRefusal(code)


def _check_cleaner(value, limit, policy):
    if (type(value) is not str or type(limit) is not int or limit < 0
            or type(policy) is not str or policy not in ("proposal", "guidance")):
        _refuse_cleaner("invalid")
    ceiling = _CLEANER_GUIDANCE_INPUT_MAX if policy == "guidance" else _CLEANER_INPUT_MAX
    if len(value) > ceiling:
        _refuse_cleaner("too_large")


def _ambiguous_url_authority(authority):
    """Recognize indeterminate hosts without parsing or changing their spelling."""
    host = authority.rsplit("@", 1)[-1]
    # Shared masks are opaque host atoms, not malformed IPv6 brackets.
    host = REDACTION_MARKER_RE.sub("masked", host)
    # A final IPv6 bracket belongs to the host. URL query punctuation below has
    # a different closer set; sharing that set would change legacy host parsing.
    host = host.rstrip(")}>.,;:!?`'\"")
    if not host:
        return True
    if host.startswith("["):
        close = host.find("]")
        if close <= 1 or "[" in host[1:close]:
            return True
        tail = host[close + 1:].rstrip("]")
        return bool(tail and (not tail.startswith(":") or not tail[1:].isdigit()))
    host = host.rstrip("]")
    return not host or host.startswith(":") or "[" in host or "]" in host or host.count(":") > 1


def remove_url_credentials(value, *, limit, policy="proposal"):
    """Apply the caller's URL policy alongside shared-table masking.

    The proposal policy drops userinfo/query/fragment and joins whitespace.
    Guidance retains URL structure and whitespace byte for byte. Input is
    bounded before tokenization; the result is bounded before publication.
    Unknown policies, non-string values and invalid limits refuse as invalid.
    This boundary never formats signed trailers.
    """
    _check_cleaner(value, limit, policy)
    if policy == "guidance":
        if len(value) > limit:
            _refuse_cleaner("too_large")
        return value

    def token(raw):
        marker = raw.find("://")
        if marker < 0:
            return raw
        start = marker + 3
        boundaries = [position for position in (raw.find("/", start), raw.find("?", start),
                                                raw.find("#", start)) if position >= 0]
        authority_end = min(boundaries, default=len(raw))
        if raw.count("://") > 1 or _ambiguous_url_authority(raw[start:authority_end]):
            return "[REDACTED_URL]"
        cuts = [position for position in (raw.find("?", start), raw.find("#", start)) if position >= 0]
        cut = min(cuts, default=len(raw))
        end = len(raw)
        if cuts:
            while end > cut and raw[end - 1] in _URL_CLOSERS:
                # A mask's closing bracket belongs to its opaque atom, not to
                # the punctuation restored after a removed query/fragment.
                opening = raw.rfind("[", cut, end)
                if opening >= cut and REDACTION_MARKER_RE.fullmatch(raw[opening:end]):
                    break
                end -= 1
            # A restored '?' would introduce another query on the next pass.
            end = max(end, raw.rfind("?", cut) + 1)
        at = raw.rfind("@", start, authority_end)
        head = raw[:cut] if at < 0 else raw[:start] + raw[at + 1:cut]
        return head + raw[end:]

    parts, size = [], 0
    for word in value.split():
        cleaned = token(word)
        size += len(cleaned) + bool(parts)
        if size > limit:
            _refuse_cleaner("too_large")
        parts.append(cleaned)
    return " ".join(parts)


def clip_atomic_text(value, limit, *, policy="proposal"):
    """Clip with the caller's existing mask grammar and whitespace policy.

    Proposal cuts preserve literal escape prefixes and strip trailing space.
    Guidance cuts retain whitespace and the shared table's replacement atoms.
    Input is bounded before allocating pattern lists or matching.
    """
    _check_cleaner(value, limit, policy)
    patterns = (tuple(pattern for pattern, _ in SECRET_REPLACEMENTS) + (REDACTION_MASK_RE,)
                if policy == "guidance" else (REDACTION_MARKER_RE,))
    cut = min(limit, len(value))
    for pattern in patterns:
        for marker in pattern.finditer(value):
            if marker.start() < cut < marker.end():
                cut = marker.start()
    return value[:cut] if policy == "guidance" else value[:cut].rstrip()
