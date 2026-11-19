"""The primitives every layer shares, one home each (layer 0): path
containment, strict JSON, UTC timestamps and the line identity of a finding. Copies of these
disagreed at their edges (a looped path inside or outside, ``1e999`` read as infinity, a naive
datetime read as local time or UTC).
"""
from __future__ import annotations

import bisect
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from aegis_core._version import __version__
from aegis_core.redaction_patterns import (
    CONTROL_RE as _DISPLAY_CONTROLS,
    RedactionRefusal, bound_redaction_spans, SECRET_REPLACEMENTS as _DISPLAY_HOOK_SECRETS,
    TOKEN_REDACTIONS as _DISPLAY_TOKEN_SECRETS, PII_REDACTIONS as _DISPLAY_PRIVACY,
)

__all__ = [
    "DuplicateKeyError",
    "LineIndex",
    "TS_FORMAT",
    "envelope",
    "fingerprint",
    "aegis_import_root",
    "is_within",
    "json_preflight",
    "key_within",
    "normalize_text",
    "occurrence_index",
    "parse_utc",
    "real_key",
    "real_path",
    "safe_parts",
    "redact_display_secrets",
    "sanitize_display",
    "split_lines",
    "strict_loads",
    "utc_stamp",
]

_EXTENDED = "\\\\?\\"
_EXTENDED_UNC = "\\\\?\\UNC\\"

PathArg = Union[str, "os.PathLike[str]"]


# ── Paths ────────────────────────────────────────────────────────────────────

def real_path(path: PathArg) -> str:
    """``path`` with every link resolved and without the Windows extended-length prefix.

    realpath, not Path.resolve(): it never raises on a loop (3.9's resolve does) and it resolves
    Windows junctions. Windows realpath answers ``\\\\?\\C:\\...`` when the path appears or
    disappears while it resolves; that prefix is dropped (``\\\\?\\UNC\\x`` becomes ``\\\\x``).
    """
    real = os.path.realpath(path)
    if real.startswith(_EXTENDED_UNC):
        return "\\\\" + real[len(_EXTENDED_UNC):]
    if real.startswith(_EXTENDED):
        return real[len(_EXTENDED):]
    return real


def real_key(path: PathArg) -> Optional[str]:
    """``path`` resolved in one spelling per location (normcase folds the case Windows ignores), or
    None when it cannot be resolved: a NUL byte, an OS error, or a final component that is still a
    link after realpath (a loop: realpath hands the loop back and no file sits there)."""
    try:
        text = os.fsdecode(path)
        # Checked here: Windows realpath on 3.12+ returns a NUL path unchanged (gh-106242).
        if "\0" in text:
            return None
        real = real_path(text)
        if os.path.islink(real):
            return None
        return os.path.normcase(real)
    except (OSError, ValueError, RuntimeError):
        return None


def key_within(key: str, root_key: str) -> bool:
    """Whether the key ``key`` is ``root_key`` or below it (both from ``real_key``)."""
    return key == root_key or key.startswith(root_key.rstrip(os.sep) + os.sep)


def is_within(path: PathArg, root: PathArg, *, unresolvable: bool) -> bool:
    """Whether ``path`` resolves to ``root`` or below it. When either side cannot be resolved the
    answer is ``unresolvable``, which has no default: pass False where the caller requires the path
    inside (refusing on False) and True where it requires the path outside (refusing on True)."""
    key, base = real_key(path), real_key(root)
    if key is None or base is None:
        return unresolvable
    return key_within(key, base)


def safe_parts(rel: object, *, windows: bool = os.name == "nt") -> Optional[Tuple[str, ...]]:
    """The parts of a relative POSIX path that stays below wherever it is joined, or None: not a
    string, empty, a leading ``/``, or an empty, ``.`` or ``..`` part. With ``windows`` also None
    for a backslash or a ``:`` anywhere (a drive prefix ``D:x`` or a stream); POSIX keeps
    ``a:b.py`` and ``a\\b.py``, which are plain file names there."""
    if not isinstance(rel, str) or not rel or rel.startswith("/"):
        return None
    if windows and ("\\" in rel or ":" in rel):
        return None
    parts = tuple(rel.split("/"))
    if any(part in ("", ".", "..") for part in parts):
        return None
    return parts


# ── Strict JSON ──────────────────────────────────────────────────────────────

class DuplicateKeyError(ValueError):
    """A JSON object names one key twice: a second value would let one reader see one value
    and another reader the other."""


def _unique_object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    found: Dict[str, Any] = {}
    for key, value in pairs:
        if key in found:
            raise DuplicateKeyError(f"duplicate key {key!r}")
        found[key] = value
    return found


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not allowed")


def _finite(literal: str) -> float:
    value = float(literal)
    if not math.isfinite(value):
        # Cut: a refusal that echoes this message must not echo a megabyte of digits.
        raise ValueError(f"{literal[:40]} is not allowed")
    return value


def strict_loads(text: Union[str, bytes]) -> Any:
    """``json.loads`` that refuses a duplicate key (DuplicateKeyError), NaN and Infinity, and a
    number that overflows to infinity (``1e999``, which json reads as inf without calling
    parse_constant and which nothing can write back as JSON). The messages are fixed
    (``duplicate key 'k'``, ``NaN is not allowed``): readers echo them in their refusals.
    RecursionError passes through."""
    return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_no_constant, parse_float=_finite)


def _json_text(raw: Union[str, bytes], max_bytes: int) -> str:
    if type(raw) not in (str, bytes):
        raise ValueError("invalid")
    if len(raw) > max_bytes:
        raise ValueError("size")
    if type(raw) is bytes:
        # Strict UTF-8 has one canonical encoding: the checked raw length is
        # already the UTF-8 byte count. Do not encode or recount decoded bytes.
        try:
            return raw.decode("utf-8")
        except UnicodeError:
            raise ValueError("invalid") from None
    size = 0
    for char in raw:
        code = ord(char)
        if 0xD800 <= code <= 0xDFFF:
            raise ValueError("invalid")
        size += 1 if code < 128 else 2 if code < 2048 else 3 if code < 65536 else 4
        if size > max_bytes:
            raise ValueError("size")
    return raw


def json_preflight(raw: Union[str, bytes], *, max_bytes: int, max_depth: int,
                   max_nodes: int, max_items: int, max_string: int,
                   string_units: str = "escaped", max_atom: Optional[int] = None) -> str:
    """Bound JSON before parsing; return text, without allocating a JSON tree.

    ValueError reasons are fixed: invalid, size, nesting, nodes, container,
    string, atom. Syntax remains the parser's responsibility. ``escaped``
    counts each escape as one string unit; ``source`` counts every source
    character after the opening quote, including the closing quote. These
    retain the profile and queue lexical policies, including malformed input.
    """
    text = _json_text(raw, max_bytes)
    if string_units not in ("escaped", "source"):
        raise ValueError("invalid")
    depth, nodes, chars, unicode_left, atom_chars = 0, 0, 0, 0, 0
    quoted, escaped, atom = False, False, False
    containers = []  # [entry count, awaiting first token of the next entry]
    for char in text:
        if not quoted and containers and containers[-1][1] and char not in " \t\r\n]}":
            containers[-1][0] += 1
            containers[-1][1] = False
            if containers[-1][0] > max_items:
                raise ValueError("container")
        if quoted:
            if string_units == "source":
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
                chars += 1
            elif unicode_left:
                unicode_left -= 1
            elif escaped:
                escaped = False
                if char == "u":
                    unicode_left = 4
            elif char == "\\":
                escaped = True
                chars += 1
            elif char == '"':
                quoted = False
            else:
                chars += 1
            if chars > max_string:
                raise ValueError("string")
        elif char == '"':
            quoted, atom, chars = True, False, 0
            nodes += 1
        elif char in "[{":
            nodes += 1
            atom = False
            depth += 1
            if depth > max_depth:
                raise ValueError("nesting")
            containers.append([0, True])
        elif char in "]}":
            depth -= 1
            atom = False
            if containers:
                containers.pop()
        elif char in " \t\r\n,:":
            atom = False
            if char == "," and containers:
                containers[-1][1] = True
        elif not atom:
            nodes += 1
            atom = True
            atom_chars = 1
        else:
            atom_chars += 1
            if max_atom is not None and atom_chars > max_atom:
                raise ValueError("atom")
        if nodes > max_nodes:
            raise ValueError("nodes")
    return text


# ── Finding identity (the baseline fingerprint) ──────────────────────────────

_LINE_BREAK = re.compile(r"\r\n|\r|\n")


def normalize_text(line: str) -> str:
    """A line as the fingerprint reads it: leading and trailing whitespace dropped, inner
    runs of whitespace collapsed to one space. Indentation and a CRLF checkout therefore
    do not change a fingerprint; any other edit does."""
    return " ".join(line.split())


def split_lines(text: str) -> List[str]:
    """``text`` split where CPython counts lines (``\\n``, ``\\r\\n``, ``\\r``) and nowhere
    else. ``str.splitlines`` also splits at form feeds and vertical tabs, which the
    tokenizer does not, so the line numbers of an AST would index the wrong lines."""
    return _LINE_BREAK.split(text)


class LineIndex:
    """The normalized text of a file's lines and, for each text, where it occurs."""

    def __init__(self, lines: List[str]) -> None:
        self.texts = [normalize_text(line) for line in lines]
        self._where: Dict[str, List[int]] = {}
        for number, text in enumerate(self.texts, 1):
            self._where.setdefault(text, []).append(number)

    def text(self, number: int) -> str:
        return self.texts[number - 1] if 1 <= number <= len(self.texts) else ""

    def index(self, number: int) -> int:
        if not 1 <= number <= len(self.texts):
            return 0
        return bisect.bisect_left(self._where[self.texts[number - 1]], number)


def occurrence_index(lines: List[str], number: int) -> int:
    """How many earlier lines of ``lines`` have the same normalized text as line ``number``
    (1-based); 0 for a line that does not exist."""
    return LineIndex(lines).index(number)


def fingerprint(rule: str, path: str, text: str, index: int) -> str:
    joined = "|".join((rule, path, text, str(index)))
    return hashlib.sha256(joined.encode("utf-8", "surrogatepass")).hexdigest()


# ── UTC timestamps ───────────────────────────────────────────────────────────

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_CANONICAL_TS = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z", re.ASCII)


def utc_stamp(moment: Union[None, datetime, int, float] = None) -> str:
    """``moment`` in TS_FORMAT: None is now, a naive datetime is read as UTC, an aware one is
    converted, an int or float is a POSIX time. Anything else (a bool included) is a TypeError."""
    if moment is None:
        when = datetime.now(timezone.utc)
    elif isinstance(moment, datetime):
        when = moment.replace(tzinfo=timezone.utc) if moment.utcoffset() is None else moment.astimezone(timezone.utc)
    elif isinstance(moment, (int, float)) and not isinstance(moment, bool):
        when = datetime.fromtimestamp(moment, timezone.utc)
    else:
        raise TypeError(f"a timestamp is a datetime or a POSIX time, not {type(moment).__name__}")
    return when.strftime(TS_FORMAT)


def parse_utc(value: object, *, lenient: bool = False) -> Optional[datetime]:
    """``value`` as an aware UTC datetime, or None.

    Strict reads exactly what ``datetime.strptime(value, TS_FORMAT)`` reads. That includes a
    lower-case ``z`` or ``t`` and any Unicode decimal digit: pinned on purpose, because every
    copy this replaced read stamps that way and tightening it would drop rows that count today.
    The writers' own spelling is read without strptime, whose first call imports ``_strptime``
    and builds locale tables (the pre-tool hook reads stamps on every run).

    Lenient is ``datetime.fromisoformat`` with ``Z`` read as ``+00:00`` and a naive value read
    as UTC; what it accepts depends on the Python version (before 3.11, fractions of 3 or 6
    digits only).
    """
    if not isinstance(value, str) or not value:
        return None
    if lenient:
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
        except ValueError:
            return None
        return parsed.replace(tzinfo=timezone.utc) if parsed.utcoffset() is None else parsed.astimezone(timezone.utc)
    found = _CANONICAL_TS.fullmatch(value)
    if found:
        try:
            return datetime(*map(int, found.groups()), tzinfo=timezone.utc)
        except ValueError:
            return None
    try:
        return datetime.strptime(value, TS_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def envelope(source: str, scope: Dict[str, Any], *, schema: Optional[str] = None,
             now: Union[None, int, float, datetime] = None,
             checked_at: Optional[str] = None) -> Dict[str, Any]:
    """The machine-readable head, keeping a caller's already captured stamp verbatim."""
    if now is not None and checked_at is not None:
        raise TypeError("give now or checked_at, not both")
    # A stored stamp is not a request to read the clock again or to reinterpret its text.
    head = {} if schema is None else {"schema": schema}
    head.update(source=source, aegis_version=__version__,
                checked_at=utc_stamp(now) if checked_at is None else checked_at, scope=scope)
    return head


def aegis_import_root() -> str:
    """The installed packages' parent, never a lookup on the caller's sys.path."""
    return str(Path(__file__).resolve().parent.parent)


_DISPLAY_PLAIN = re.compile(r'[^\x00-\x1f\x7f-\x9f]+')
_DISPLAY_PARAMETERS = re.compile(r'[\x30-\x3f]+')
_DISPLAY_INTERMEDIATES = re.compile(r'[\x20-\x2f]+')
_DISPLAY_COMPLETE_CSI = re.compile(r'(?:\x1b\[|\x9b)[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]')
_DISPLAY_IGNORED = re.compile(r'[\x00-\x08\x0b-\x17\x19\x1c-\x1f\x7f-\x8f\x91-\x97\x99-\x9a\x9c]+')
_DISPLAY_ESCAPE_KINDS = {'[': 'csi', 'P': 'dcs', ']': 'osc', 'X': 'sos', '^': 'pm', '_': 'apc'}
_DISPLAY_C1_KINDS = dict(zip('\x90\x98\x9b\x9d\x9e\x9f', ('dcs', 'sos', 'csi', 'osc', 'pm', 'apc')))
_DISPLAY_SECRET_RULES = tuple(
    (pattern, re.compile(pattern.pattern.replace(r'(?<![A-Za-z0-9])', '')),
     replacement.replace(r'\1REDACTED', r'\1[REDACTED]'))
    for pattern, replacement in dict((*_DISPLAY_HOOK_SECRETS, *_DISPLAY_TOKEN_SECRETS)).items()
)
_DISPLAY_PEM_PATTERN = next(pattern for pattern, _relaxed, replacement in _DISPLAY_SECRET_RULES
                            if replacement == '[REDACTED_PEM]')
# Derive both bounded marker grammars from the shared rule's BEGIN grammar.
_DISPLAY_PEM_BEGIN = re.compile(_DISPLAY_PEM_PATTERN.pattern.partition(r'[\s\S]*?')[0])
_DISPLAY_PEM_END = re.compile(_DISPLAY_PEM_BEGIN.pattern.replace('-----BEGIN ', '-----END ', 1))
# A single C-level probe avoids one Python call per rule at every carried ']'
# in abandoned strings. Global case folding makes this a conservative superset;
# each actual rule still validates its candidates with its own flags below.
_DISPLAY_BOUNDARY_CANDIDATE = re.compile('|'.join(
    '(?:' + relaxed.pattern.replace('(?i)', '') + ')'
    for _pattern, relaxed, replacement in _DISPLAY_SECRET_RULES if replacement != '[REDACTED_PEM]'), re.IGNORECASE)
# Searches may start at the core key word or bare ://: optional word/scheme
# context is irrelevant to existence, and backtracking over it dominates long
# non-secret runs. Anchored probes and actual rules retain that context above.
_DISPLAY_SEARCH_CANDIDATE = re.compile('|'.join(
    '(?:' + relaxed.pattern.replace('(?i)', '').replace(r'[A-Za-z0-9_]{0,32}', '', 1)
    .replace(r'(?:[a-z][a-z0-9+.-]{0,31})?', '') + ')'
    for _pattern, relaxed, replacement in _DISPLAY_SECRET_RULES if replacement != '[REDACTED_PEM]'), re.IGNORECASE)
_DISPLAY_SEGMENT_CANDIDATE = re.compile(
    _DISPLAY_SEARCH_CANDIDATE.pattern + '|(?:' + _DISPLAY_PEM_BEGIN.pattern + ')', re.IGNORECASE)


def _display_matches(original, relaxed, text, boundaries, *, pos=0, endpos=None, charge=None):
    """Merge ordinary and carried starts once, retaining bounded overlaps."""
    endpos = len(text) if endpos is None else endpos
    if charge is None:
        ordinary = iter(original.finditer(text, pos, endpos))
    else:
        from aegis_core.display_attribution import overlapping_matches

        ordinary = overlapping_matches(original, text, pos, endpos, charge)
    candidate = next(ordinary, None)
    last_start = -1
    for boundary in boundaries:
        while candidate is not None and candidate.start() <= boundary:
            last_start = candidate.start()
            yield candidate
            candidate = next(ordinary, None)
        if boundary == last_start:
            continue
        if charge is not None and not charge(endpos - boundary + 1):
            return
        carried = relaxed.match(text, boundary, endpos)
        if carried is not None:
            last_start = carried.start()
            yield carried
    if candidate is not None:
        yield candidate
    yield from ordinary


def _display_pem_spans(text, pos, endpos):
    """Each BEGIN gets its own label's next END, or the detection segment's end."""
    ends = {}
    for marker in _DISPLAY_PEM_END.finditer(text, pos, endpos):
        ends.setdefault(marker.group('pem_label'), []).append((marker.start(), marker.end()))
    for marker in _DISPLAY_PEM_BEGIN.finditer(text, pos, endpos):
        matches = ends.get(marker.group('pem_label'), ())
        index = bisect.bisect_left(matches, (marker.end(),))
        end = matches[index][1] if index < len(matches) else endpos
        yield marker.start(), end, '[REDACTED_PEM]'


def _display_secret_spans(text, boundaries, *, pos=0, endpos=None, include_pem=True, charge=None):
    """Detect before masking, keeping backreference context outside secret spans."""
    endpos = len(text) if endpos is None else endpos
    probe = (_DISPLAY_SEGMENT_CANDIDATE if include_pem else _DISPLAY_SEARCH_CANDIDATE).search(text, pos, endpos)
    if probe is None:
        return
    if include_pem and probe.group('pem_label') is not None and _DISPLAY_SEARCH_CANDIDATE.search(text, pos, endpos) is None:
        yield from _display_pem_spans(text, pos, endpos)
        return
    boundaries = [start for start in boundaries if pos <= start < endpos
                  and _DISPLAY_BOUNDARY_CANDIDATE.match(text, start, endpos) is not None]
    for original, relaxed, replacement in _DISPLAY_SECRET_RULES:
        if replacement == '[REDACTED_PEM]':
            if include_pem:
                yield from _display_pem_spans(text, pos, endpos)
            continue
        for candidate in _display_matches(original, relaxed, text, boundaries, pos=pos, endpos=endpos, charge=charge):
            start, end = candidate.span()
            payload = candidate.expand(replacement)
            if replacement.startswith(r'\1'):
                start = candidate.end(1)
                payload = candidate.expand(replacement[2:])
                if replacement.endswith('@'):
                    end -= 1
                    payload = payload[:-1]
            if end - start != len(payload) or not text.startswith(payload, start, end):
                yield start, end, payload


def _display_segmented_secret_spans(text, boundaries, segments):
    """Hard separators and sealed strings cannot be consumed by any rule."""
    if _DISPLAY_SEGMENT_CANDIDATE.search(text) is None:
        return
    for start, end in segments:
        # Reject irrelevant runs with one bounded C-level probe, preserving the
        # abandoned-string deadline without copying a run or suffix to match.
        if _DISPLAY_SEGMENT_CANDIDATE.search(text, start, end) is None:
            continue
        left = bisect.bisect_left(boundaries, start)
        right = bisect.bisect_left(boundaries, end)
        starts = boundaries[left:right]
        if not starts or starts[0] != start:
            starts.insert(0, start)
        yield from _display_secret_spans(text, starts, pos=start, endpos=end)


def _display_mapped_secret_spans(text, boundaries, source_map, *, segments=None, include_pem=True, pos=0, charge=None,
                                 scan_text=None):
    """Map a detection view's spans back through its compressed source runs."""
    offsets = [row[1] for row in source_map]

    def to_source(position):
        index = bisect.bisect_right(offsets, position) - 1
        return source_map[index][0] + position - offsets[index]

    spans = (scan_text(text) if scan_text is not None else
             _display_secret_spans(text, boundaries, include_pem=include_pem, pos=pos, charge=charge)
             if segments is None else _display_segmented_secret_spans(text, boundaries, segments))
    for start, end, payload in spans:
        yield to_source(start), to_source(end - 1) + 1, payload


def _display_secret_masks(canonical, deleted, separator_segments, deleted_segments, attributable, *, source,
                          source_spans=False, raw_spans=(), extra_spans=(), scan_text=None):
    """Keep secret-material coverage and disjoint privacy; known masks own their bytes."""
    text, boundaries, source_map = canonical
    if not text and not source_spans:
        return text
    source_starts = [row[0] for row in source_map]
    output_starts = [row[1] for row in source_map]

    def to_output(position):
        index = bisect.bisect_right(source_starts, position) - 1
        return 0 if index < 0 else output_starts[index] + min(position - source_starts[index], source_map[index][2])

    spans = list(_display_mapped_secret_spans(text, boundaries, source_map))
    if not source_spans and any(start == source_starts[0] and end == source_map[-1][0] + source_map[-1][2]
                               and payload == '[REDACTED_PEM]' for start, end, payload in spans):
        return '[REDACTED_PEM]'
    spans.extend(_display_mapped_secret_spans(*deleted, segments=separator_segments))
    if separator_segments != deleted_segments and (deleted != canonical or len(deleted_segments) > 1):
        spans.extend(_display_mapped_secret_spans(*deleted, segments=deleted_segments))
    if attributable and text:
        extra, _stats = _display_attribution(*source, canonical)
        spans.extend(extra)
    if source_spans:
        known_count = len(spans)
        spans.extend(extra_spans)
        if scan_text is not None:
            for view in (canonical, deleted):
                spans.extend(_display_mapped_secret_spans(*view, scan_text=scan_text))
        expanded = []
        for start, end, payload in spans:
            if payload != '[REDACTED_PEM]' and to_output(start) < to_output(end):
                # Suppressed header edges must not consume replacement bytes.
                left = bisect.bisect_right(source_starts, start) - 1
                start = min(start, source_starts[left] + source_map[left][2]) if left >= 0 else 0
                right = bisect.bisect_right(source_starts, end - 1) - 1
                if right < 0 or end > source_starts[right] + source_map[right][2]:
                    end = source_starts[right + 1] if right + 1 < len(source_starts) else len(source[0])
            expanded.append((start, end, payload))
        spans, extra_spans = expanded[:known_count] + list(raw_spans), expanded[known_count:]

    def merge(candidates):
        merged = []
        for start, end, payload in sorted(candidates, key=lambda span: (span[0], -span[1])):
            if merged and start < merged[-1][1]:
                if end > merged[-1][1]:
                    merged[-1] = (merged[-1][0], end, '[REDACTED]')
            else:
                merged.append((start, end, payload))
        return merged

    merged = merge(spans)
    if source_spans:
        additional, ends, privacy = [], [span[1] for span in merged], {mask for _pattern, mask in _DISPLAY_PRIVACY}
        for start, end, payload in extra_spans:
            index = bisect.bisect_right(ends, start)
            if payload in privacy and index < len(merged) and merged[index][0] < end:
                continue
            while index < len(merged) and merged[index][0] < end:
                left, right, _known = merged[index]
                if start < left:
                    additional.append((start, left, payload))
                start = max(start, right)
                index += 1
            if start < end:
                additional.append((start, end, payload))
        return tuple(sorted((*merged, *merge(additional))))
    shown, cursor = [], 0
    for start, end, payload in merged:
        start, end = to_output(start), to_output(end)
        if start == end:
            continue
        shown.extend((text[cursor:start], payload))
        cursor = end
    shown.append(text[cursor:])
    return ''.join(shown)


def redact_display_secrets(text, *, limit, on_replacements=None, bound=False, extra_spans=(), protected_spans=(), scan_text=None,
                           tail_candidates=None):
    """Bound before parsing; union original-coordinate spans before one replacement.

    ``bound`` means the caller supplied an input head, not a complete field.
    The word, unfinished-family and PEM guards all constrain the same source cut.
    The trusted ``tail_candidates`` callback selects a deleted-view token, then
    parser maps carry its first character back to the bounded original source.
    Initial withholding is separate from replacement events. The observer sees
    only changed spans that survive the cut, once, before any replacement.
    """
    if type(bound) is not bool or type(text) is not str or type(limit) is not int or limit < 0 or len(text) > limit:
        raise RedactionRefusal('too_large' if type(text) is str and type(limit) is int
                               and limit >= 0 and len(text) > limit else 'invalid')
    if tail_candidates is not None and (not bound or not callable(tail_candidates)):
        raise RedactionRefusal('invalid')
    for group in (extra_spans, protected_spans):
        if type(group) is tuple and (len(group) > 32 * len(text) or any(
                type(row) is tuple and len(row) == 3 and type(row[2]) is str and len(row[2]) > 128 for row in group)):
            raise RedactionRefusal('too_large')
        if type(group) is not tuple or any(type(row) is not tuple or len(row) != 3 or
                type(row[0]) is not int or type(row[1]) is not int or type(row[2]) is not str or
                not 0 <= row[0] < row[1] <= len(text) for row in group):
            raise RedactionRefusal('invalid')
    raw_spans = (*_display_secret_spans(text, ()), *protected_spans)
    control = _DISPLAY_CONTROLS.search(text)
    if control is None and not bound and not raw_spans and not extra_spans:
        return text
    index = control.start() if control is not None else len(text)
    views = _display_views(text, index)
    detection_views = _display_views(text, index, detection=True)
    for view, segments in ((detection_views[0], None), (detection_views[1], detection_views[3])):
        raw_spans = (*raw_spans, *_display_mapped_secret_spans(*view, segments=segments))
        if scan_text is not None:
            extra_spans = (*extra_spans, *_display_mapped_secret_spans(*view, scan_text=scan_text))
    spans = _display_secret_masks(*views, source=(text, index), source_spans=True,
                                  raw_spans=raw_spans, extra_spans=extra_spans, scan_text=scan_text)
    stop, marker = len(text), ''
    if bound:
        stop, marker = bound_redaction_spans(text, spans,
            (*detection_views[:2], views[0], views[1], (text, (), [(0, 0, len(text))])), _display_matches,
            _display_render_spans(text, index, detection=True), tail_candidates)
        spans = tuple(span for span in spans if span[1] <= stop)
    spans = tuple(span for span in spans if text[span[0]:span[1]] != span[2])
    if on_replacements is not None and spans:
        on_replacements(spans)
    parts, cursor = [], 0
    for start, end, payload in spans:
        parts.extend((text[cursor:start], payload))
        cursor = end
    return (''.join((*parts, text[cursor:stop])) if spans else text[:stop]) + marker


_DISPLAY_ATTRIBUTION_RATE = 1024
_DISPLAY_ATTRIBUTION_CEILING = 4194304
# The existing PEM row is unbounded, but PEM attribution remains out of scope.
# Any unbounded row contributes this documented radius instead of infinity.
_DISPLAY_ATTRIBUTION_UNBOUNDED_CAP = 2048


@lru_cache(maxsize=1)
def _display_attribution_width():
    """Window geometry needs widths, never the optional attribution graph."""
    from aegis_core.display_attribution import max_match_width

    return max_match_width((pattern for pattern, _relaxed, _replacement in _DISPLAY_SECRET_RULES),
                           unbounded_cap=_DISPLAY_ATTRIBUTION_UNBOUNDED_CAP)


@lru_cache(maxsize=1)
def _display_attribution_tables():
    """Compile only when a window needs the conservative graph proof."""
    from aegis_core.display_attribution import compile_possible, may_match_visible

    graph = compile_possible((pattern for pattern, _relaxed, replacement in _DISPLAY_SECRET_RULES
                              if replacement != '[REDACTED_PEM]'),
                             carried_patterns=(relaxed for _pattern, relaxed, replacement in _DISPLAY_SECRET_RULES
                                               if replacement != '[REDACTED_PEM]'))
    return _display_attribution_width(), graph, may_match_visible


def _display_attribution_possible(runs, text, stats):
    _width, graph, may_match_visible = _display_attribution_tables()
    possible = may_match_visible(graph, text, runs, lambda amount: _display_attribution_charge(stats, amount),
                                 start_at=int(runs[0][0] < stats['start']))
    if not stats['exhausted']:
        stats['coverage'] = 'possible' if possible else 'no_match'
    return possible


def _display_attribution_charge(stats, amount):
    """Charge before allocation or regex work; never overshoot the ceiling."""
    if stats['exhausted'] or amount > stats['limit'] - stats['steps']:
        stats['exhausted'] = True
        stats['coverage'] = 'exhausted'
        return False
    stats['steps'] += amount
    return True


def _display_attribution_view(text, runs, variant):
    """An interpretation with the same ordinary/carried starts as the renderer."""
    chunks, boundaries, source_map = [], [], []
    offset, bit, previous_end, previous_kind = 0, 0, -1, None
    for start, end, kind, visible, replacement, _sealed in runs:
        if not visible:
            selected = variant & (1 << bit)
            bit += 1
            if not selected:
                continue
        chunks.append(text[start:end] if replacement is None else replacement)
        source_map.append((start, offset, end - start))
        if start != previous_end or kind != previous_kind:
            boundaries.append(offset)
        offset += end - start
        previous_end, previous_kind = end, kind
    return ''.join(chunks), boundaries, source_map


def _display_attribute_segment(text, start, end, runs, stats):
    """Explore shared-rule interpretations, or mask only this window.

    A step is a source unit inspected/copied or a charged regex input unit.
    Each variant reserves source length times every ordinary/carried rule
    probe before construction. Shared non-PEM regex widths are bounded; PEM
    label attribution is deliberately outside this search's contract.
    """
    size = end - start
    stats['limit'] = min(_DISPLAY_ATTRIBUTION_CEILING, stats['limit'] + _DISPLAY_ATTRIBUTION_RATE * size)
    refused = (start, end, '[REDACTED]')
    if not _display_attribution_charge(stats, size + (len(runs) if runs is not None else 0)):
        return refused
    if runs is None:
        stats['coverage'] = 'possible'
        return refused
    rules = sum(replacement != '[REDACTED_PEM]' for _original, _relaxed, replacement in _DISPLAY_SECRET_RULES)
    # The run count bounds carried starts; no regex or candidate string is
    # built until the complete search fits. Never construct an enormous 2**n.
    cost = size * (2 + rules * (2 + len(runs)))
    maximum = (stats['limit'] - stats['steps']) // cost
    variants = 1
    for _start, _end, _kind, visible, _replacement, _sealed in runs:
        if not visible:
            if variants > maximum // 2:
                return refused if _display_attribution_possible(runs, text, stats) else None
            variants *= 2
    if variants > maximum:
        return refused if _display_attribution_possible(runs, text, stats) else None
    found = None
    for variant in range(variants):
        if not _display_attribution_charge(stats, cost):
            return refused
        view = _display_attribution_view(text, runs, variant)
        if not view[0]:
            continue
        # One context character prevents a clipped plain run from acquiring
        # a new ordinary/carried start. It can never begin a secret span.
        pos = int(runs[0][0] < start)
        charge = lambda amount: _display_attribution_charge(stats, amount)
        for left, right, payload in _display_mapped_secret_spans(*view, include_pem=False, pos=pos, charge=charge):
            if found is None:
                found = left, right, payload
            else:
                # One envelope per candidate: disjoint attribution intervals
                # and PEM labels remain outside the admitted contract.
                found = (min(left, found[0]), max(right, found[1]),
                         payload if payload == found[2] else '[REDACTED]')
        if stats['exhausted']:
            return refused
    stats['coverage'] = 'complete'
    return found


def _display_attribution_windows(text, index, source_map):
    """Merge windows in kept-character space; seals remain hard boundaries."""
    from aegis_core.display_attribution import project_window

    width = _display_attribution_width()
    begin, offset, pending = 0, 0, None
    for start, end, kind, visible, _replacement, sealed in _display_render_spans(text, index):
        if sealed:
            if pending is not None:
                yield project_window(pending, offset, source_map)
            begin, pending = offset, None
        elif kind == 4 and not visible:
            left, right = max(begin, offset - width), offset + width
            if pending is not None and left <= pending[1]:
                pending = pending[0], right, pending[2], end
            else:
                if pending is not None:
                    yield project_window(pending, offset, source_map)
                pending = left, right, start, end
        if visible:
            offset += end - start
    if pending is not None:
        yield project_window(pending, offset, source_map)


def _display_attribution(text, index, canonical=None):
    """Each merged window owns a budget; exhaustion cannot affect its peers."""
    canonical = _display_views(text, index)[0] if canonical is None else canonical
    spans, budgets = [], []
    rows = iter(_display_render_spans(text, index))
    row = next(rows, None)
    for begin, end, detection_start, detection_end in _display_attribution_windows(text, index, canonical[2]):
        runs = [] if end - begin <= _DISPLAY_ATTRIBUTION_CEILING else None
        while row is not None and row[0] < end:
            start, stop, kind, visible, replacement, sealed = row
            if stop > begin and runs is not None and (visible or (kind == 4 and not sealed)):
                if start < begin and visible and replacement is None:
                    runs.append((begin - 1, begin, kind, True, None, 0))
                runs.append((max(start, begin), min(stop, end), kind, visible, replacement, sealed))
            if stop > end:
                break
            row = next(rows, None)
        stats = {'steps': 0, 'limit': 0, 'exhausted': False, 'coverage': 'pending', 'start': begin, 'end': end,
                 'source_length': end - begin, 'detection_start': detection_start, 'detection_end': detection_end}
        span = _display_attribute_segment(text, begin, end, runs, stats)
        budgets.append(stats)
        if span is not None:
            spans.append(span)
    return spans, {'steps': sum(b['steps'] for b in budgets), 'limit': sum(b['limit'] for b in budgets),
                   'exhausted': any(b['exhausted'] for b in budgets), 'windows': budgets}


def _display_escape_limit(text, index, literal_until):
    """Legacy suppression and string state, decided once at an ESC."""
    size = len(text)
    if index + 1 < size:
        kind = text[index + 1]
        if kind in (']', 'P') and index >= literal_until:
            end = index + 2
            while end < size and text[end] != '\n':
                if text[end] == '\x07':
                    return end + 1, end + 1, literal_until
                if text[end] == '\x1b' and end + 1 < size and text[end + 1] == '\\':
                    return end + 2, end + 2, literal_until
                end += 1
            # Nested abandoned strings share the already inspected suffix.
            literal_until = end
        if kind == '[':
            end = index + 2
            while end < size and text[end] in '0123456789;?':
                end += 1
            if end < size and ('a' <= text[end] <= 'z' or 'A' <= text[end] <= 'Z'):
                return end + 1, 0, literal_until
        if kind in '=><NOM78c':
            return index + 2, 0, literal_until
    return index + 1, 0, literal_until


def _display_header_run(text, index, limit, mode, phase):
    """Advance the renderer's header state and identify this printable run."""
    char = text[index]
    if mode == 'escape' and phase == 1 and char in _DISPLAY_ESCAPE_KINDS:
        return index + 1, 1, _DISPLAY_ESCAPE_KINDS[char], 1
    if mode not in (None, 'escape') and phase <= 2:
        run = _DISPLAY_PARAMETERS.match(text, index, limit)
        if run is not None:
            return run.end(), 2, mode, 2
    if mode is not None:
        run = _DISPLAY_INTERMEDIATES.match(text, index, limit)
        if run is not None:
            return run.end(), 3, mode, 3
        if ((mode == 'escape' and '\x30' <= char <= '\x7e') or
                (mode in ('csi', 'dcs') and '\x40' <= char <= '\x7e')):
            return index + 1, 4, None, 0
    return _DISPLAY_PLAIN.match(text, index, limit).end(), 0, None, 0


def _display_render_spans(text, index, *, detection=False):
    """Emit (start, end, provenance, visible, replacement, sealed-string end).

    Plain=0, introducer=1, parameter=2, intermediate=3, final=4, control=5.
    """
    if index:
        yield 0, index, 0, True, None, 0
    size = len(text)
    literal_until = string_until = drop_until = 0
    mode, phase = None, 0
    while index < size:
        if string_until and index >= string_until:
            string_until, mode, phase = 0, None, 0
        char = text[index]
        csi = _DISPLAY_COMPLETE_CSI.match(text, index) if detection and not string_until else None
        if csi is not None:
            yield index, csi.end(), 1, False, None, 0
            index, mode, phase = csi.end(), None, 0
            continue
        if char == '\x1b' and not string_until:
            drop_until, string_until, literal_until = _display_escape_limit(text, index, literal_until)
            mode, phase = 'escape', 1
            yield index, index + 1, 1, False, None, string_until
            index += 1
            continue
        if char in _DISPLAY_C1_KINDS and not string_until:
            mode, phase = _DISPLAY_C1_KINDS[char], 1
            yield index, index + 1, 1, False, None, 0
            index += 1
            continue
        if ord(char) < 32 or 127 <= ord(char) <= 159:
            if char in ('\n', '\t'):
                if char == '\n' and mode in ('osc', 'dcs', 'sos', 'pm', 'apc'):
                    mode, phase = None, 0
                yield index, index + 1, 5, index >= drop_until, ' ', string_until
                index += 1
            else:
                if char in ('\x18', '\x1a'):
                    mode, phase = None, 0
                run = _DISPLAY_IGNORED.match(text, index, string_until or size)
                end = run.end() if run is not None else index + 1
                yield index, end, 5, False, None, string_until
                index = end
            continue
        limit = string_until or size
        end, kind, mode, phase = _display_header_run(text, index, limit, mode, phase)
        yield index, end, kind, index >= drop_until, None, string_until
        index = end


def _display_views(text, index, *, detection=False):
    """Build canonical/deleted views and their maps from renderer events once."""
    shown, boundaries, source_map = [], [], []
    deleted, deleted_boundaries, deleted_map = [], [], []
    separator_segments, deleted_segments = [], []
    previous_seal, deleted_split = 0, True
    offset = deleted_offset = 0
    previous_end = deleted_end = -1
    previous_kind = deleted_kind = None
    attributable = False
    for start, end, kind, visible, replacement, sealed in _display_render_spans(text, index, detection=detection):
        attributable = attributable or (kind == 4 and not visible and not sealed)
        if sealed != previous_seal:
            deleted_split = True
        printable = replacement is None and ord(text[start]) >= 32 and not 127 <= ord(text[start]) <= 159
        chunk = text[start:end] if printable else replacement
        if visible:
            shown.append(chunk)
            source_map.append((start, offset, end - start))
            if start != previous_end or kind != previous_kind:
                boundaries.append(offset)
            offset += end - start
            previous_end, previous_kind = end, kind
        if printable or visible:
            deleted.append(chunk)
            deleted_map.append((start, deleted_offset, end - start))
            if start != deleted_end or kind != deleted_kind or deleted_split:
                deleted_boundaries.append(deleted_offset)
            if separator_segments and start == deleted_end and sealed == previous_seal:
                separator_segments[-1] = (separator_segments[-1][0], deleted_offset + end - start)
            else:
                separator_segments.append((deleted_offset, deleted_offset + end - start))
            if deleted_split:
                deleted_segments.append((deleted_offset, deleted_offset + end - start))
                deleted_split = False
            else:
                deleted_segments[-1] = (deleted_segments[-1][0], deleted_offset + end - start)
            deleted_offset += end - start
            deleted_end, deleted_kind = end, kind
        previous_seal = sealed
    return ((''.join(shown), boundaries, source_map),
            (''.join(deleted), deleted_boundaries, deleted_map), separator_segments, deleted_segments, attributable)


def _display_text_views(text, index):
    """Probe non-secret output without allocating maps/segments for every run."""
    shown, deleted = [], []
    attributable = False
    for start, end, kind, visible, replacement, sealed in _display_render_spans(text, index):
        attributable = attributable or (kind == 4 and not visible and not sealed)
        printable = replacement is None and ord(text[start]) >= 32 and not 127 <= ord(text[start]) <= 159
        if printable:
            chunk = text[start:end]
            deleted.append(chunk)
            if visible:
                shown.append(chunk)
        elif visible:
            shown.append(replacement)
            deleted.append(replacement)
    return ''.join(shown), ''.join(deleted), attributable


def sanitize_display(text: object, max_len: Optional[int] = 80) -> str:
    """Keep legacy non-secret display bytes; mask control-adjacent secrets before clipping.

    A newline or end-of-input abandons an unterminated OSC/DCS string. Its
    printable kind and payload stay visible, but cannot hide a secret's left
    boundary. Control scans are linear; repeated removed controls share one
    boundary rather than allocating state for every input character.
    Plain text retains the existing fast path and downstream redaction policy.
    """
    text = str(text)
    first_control = _DISPLAY_CONTROLS.search(text)
    if first_control is not None:
        index = first_control.start()
        if _DISPLAY_SEGMENT_CANDIDATE.match(text) is None:
            canonical, deleted, attributable = _display_text_views(text, index)
            # The relaxed probe also covers matches within a source segment:
            # hard separators cannot contribute any part of a credential.
            if (not attributable and _DISPLAY_SEGMENT_CANDIDATE.search(canonical) is None
                    and _DISPLAY_SEGMENT_CANDIDATE.search(deleted) is None):
                text = canonical
            else:
                text = _display_secret_masks(*_display_views(text, index), source=(text, index))
        else:
            text = _display_secret_masks(*_display_views(text, index), source=(text, index))
    if max_len is not None and len(text) > max_len:
        text = text[:max_len - 3] + '...'
    return text
