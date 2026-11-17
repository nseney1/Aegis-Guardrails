"""Pure raw guidance blocks, bounded source decoding and redaction clipping."""
from __future__ import annotations

import codecs
from bisect import bisect_right
import re
from aegis_core.redaction import (
    SECRET_REPLACEMENTS, URL_USERINFO_RE, RedactionRefusal, check_guidance_text, clip_atomic_text,
    guidance_url_plan,
    remove_url_credentials as remove_url_credentials,  # Retain the existing import identity contract.
)

__all__ = ["bounded_rule_text", "clip_redacted", "copy_retained_items",
           "guidance_token_estimate", "heading_has_slot", "raw_evidence_span", "raw_do_instruction_span", "redact_labeled"]


def clip_redacted(text, limit):
    """Apply the shared cleaner with the existing guidance clipping policy."""
    try:
        return clip_atomic_text(text, limit, policy="guidance")
    except RedactionRefusal:
        raise ValueError("guidance_projection_limit") from None


def _remap_atoms(atoms, edits):
    """Move interval endpoints through edits; never rediscover URL syntax."""
    if not atoms:
        return atoms
    starts, ends, shifts = [e[0] for e in edits], [e[1] for e in edits], [0]
    for lo, hi, shown, _prefix, _atomic in edits:
        shifts.append(shifts[-1] + len(shown) - (hi - lo))

    def point(position, right):
        index = bisect_right(ends, position)
        if index < len(edits) and starts[index] < position:
            return starts[index] + shifts[index] + (len(edits[index][2]) if right else 0)
        return position + shifts[index]

    moved = []
    for lo, hi, plan, marker in atoms:
        first, last = point(lo, False), point(hi, True)
        # Carry the original owning marker through shifts, without parsing the
        # rewritten URL. An edit consuming it retires that identity.
        if marker is not None:
            position = lo + marker
            index = bisect_right(ends, position)
            marker = (None if index < len(edits) and starts[index] <= position
                      else point(position, False) - first)
        index = bisect_right(ends, lo)
        if index < len(edits) and starts[index] < hi:
            plan = None
        if moved and first < moved[-1][1]:
            previous = moved.pop()
            first, last, plan, marker = previous[0], max(last, previous[1]), None, None
        moved.append((first, last, plan, marker))
    return moved


def _apply_edits(text, labels, atoms, edits, limit):
    if not edits:
        return text, labels, atoms
    if len(text) + sum(len(shown) - (hi - lo) for lo, hi, shown, _p, _a in edits) > limit:
        raise ValueError("guidance_projection_limit")
    parts, attributed, end = [], [], 0
    for lo, hi, shown, prefix, _atomic in edits:
        parts.extend((text[end:lo], shown))
        if labels is not None:
            attributed.extend(labels[end:lo])
            if prefix is not None:
                first, last = prefix
                attributed.extend(labels[first:last])
                attributed.extend([labels[min(last, len(labels) - 1)]] * (len(shown) - (last - first)))
            elif shown:
                attributed.extend([labels[lo]] * len(shown))
        end = hi
    parts.append(text[end:])
    if labels is not None:
        attributed.extend(labels[end:])
    return "".join(parts), attributed if labels is not None else None, _remap_atoms(atoms, edits)


def _mask_labeled(text, labels, limit, atoms):
    """Shared matches touching URLs consume the entire connected URL union."""
    for pattern, replacement in SECRET_REPLACEMENTS:
        edits, index = [], 0
        for match in pattern.finditer(text):
            lo, hi = match.span()
            if edits and edits[-1][4] and hi <= edits[-1][1]:
                continue
            while index < len(atoms) and atoms[index][1] < lo:
                index += 1
            touches = index < len(atoms) and atoms[index][0] <= hi
            # Userinfo belongs to the dedicated original-byte URL policy.
            if touches and pattern.pattern == URL_USERINFO_RE.pattern:
                containing = index + (atoms[index][1] == lo)
                if (containing < len(atoms) and atoms[containing][0] <= lo
                        and hi <= atoms[containing][1]
                        and atoms[containing][3] is not None
                        and match.start(1) + match.group(1).find("://")
                        == atoms[containing][0] + atoms[containing][3]):
                    continue
            if touches:
                first = index
                while first > 0 and atoms[first - 1][1] >= atoms[first][0]:
                    first -= 1
                lo = min(lo, atoms[first][0])
                last = first
                while last < len(atoms) and atoms[last][0] <= hi:
                    hi = max(hi, atoms[last][1])
                    last += 1
                shown, prefix, atomic = "[REDACTED_URL]", None, True
            else:
                shown = match.expand(replacement)
                prefix = match.span(1) if replacement.startswith(r"\1") else None
                atomic = False
            while edits and lo <= edits[-1][1] and (atomic or edits[-1][4]):
                previous = edits.pop()
                lo, hi = min(lo, previous[0]), max(hi, previous[1])
                shown, prefix, atomic = "[REDACTED_URL]", None, True
            edits.append((lo, hi, shown, prefix, atomic))
        text, labels, atoms = _apply_edits(text, labels, atoms, edits, limit)
    return text, labels, atoms


def redact_labeled(text, labels, limit):
    """Parse original URLs once, then mask and rewrite their atomic intervals."""
    try:
        check_guidance_text(text, limit=limit)
        if labels is not None and (type(labels) is not list or len(labels) != len(text)):
            raise ValueError("guidance_projection_limit")
        atoms = [(lo, hi, (lo, changes), marker - lo)
                 for lo, hi, changes, marker in guidance_url_plan(text, limit=limit)]
    except RedactionRefusal:
        raise ValueError("guidance_projection_limit") from None
    text, labels, atoms = _mask_labeled(text, labels, limit, atoms)
    edits = []
    for lo, _hi, plan, _marker in atoms:
        if plan is not None:
            origin, changes = plan
            edits.extend((lo + first - origin, lo + last - origin, shown, None, False)
                         for first, last, shown in changes)
    text, labels, atoms = _apply_edits(text, labels, atoms, edits, limit)
    if edits:
        text, labels, atoms = _mask_labeled(text, labels, limit, atoms)
    return text, labels


def copy_retained_items(items, count, end, cut, *, trim=True):
    """Copy spans only after the caller's item and character preflight."""
    retained = list(items[:count])
    if cut and end:
        retained[-1] = retained[-1][:end]
    if cut and trim:
        while retained and not retained[-1].rstrip():
            retained.pop()
        if retained:
            retained[-1] = retained[-1].rstrip()
    return retained


_ATX = re.compile(r"#{1,6}(?:[ \t]+|$)(.*)\Z")
_FENCE_RUN = re.compile(r"`{3,}|~{3,}")
_FENCE = re.compile(r" {0,3}(`{3,}|~{3,})(.*)")
_HTML_TAG = re.compile(r"</?([A-Za-z][A-Za-z0-9-]*)(?=[ />\t]|$)")
_HTML_BLOCK_TAGS = frozenset((
    "address article aside base basefont blockquote body caption center col colgroup dd details dialog dir div dl dt "
    "fieldset figcaption figure footer form frame frameset h1 h2 h3 h4 h5 h6 head header hr html iframe legend li "
    "link main menu menuitem nav noframes ol optgroup option p param search section summary table tbody td tfoot th "
    "thead title tr track ul"
).split())
_MAX_HTML_NAME = max(map(len, _HTML_BLOCK_TAGS))
_RAW_LINES = re.compile(r"[^\r\n]*(?:\r\n?|\n|$)")
_BLANK = re.compile(r"\s*")
_SPACES = re.compile(r"[ \t]*")
_GENERIC_HTML = re.compile(r"</?[A-Za-z][^<>]*>[ \t]*")


def _content_start(text, start, end):
    index = start
    while index < end:
        if text[index].isspace() or text[index] in ">-+*":
            index += 1
        elif "0" <= text[index] <= "9":
            stop = index + 1
            while stop < end and "0" <= text[stop] <= "9":
                stop += 1
            if stop == end or text[stop] not in ".)":
                break
            index = stop + 1
        else:
            break
    return index


def _heading_span(text, start, end):
    """One contained ATX recognizer with ASCII-only closing-title trimming."""
    heading = _ATX.match(text, _content_start(text, start, end), end)
    if not heading:
        return None
    left, right = heading.span(1)
    while right > left and text[right - 1] in " #\t":
        right -= 1
    level = 0
    while heading.start() + level < left and text[heading.start() + level] == "#":
        level += 1
    return level, left, right


def _evidence_like(text, start, end):
    heading = _heading_span(text, start, end)
    if heading is None:
        return False
    _, left, right = heading
    return right - left == 8 and text[left:right].casefold() == "evidence"


def _html_end(text, start, end):
    if not text.startswith("<", start, end):
        return None
    for opening, ending in (("<!--", "-->"), ("<?", "?>"), ("<![CDATA[", "]]>")):
        if text.startswith(opening, start, end):
            return ending
    if end - start >= 3 and text[start:start + 2] == "<!" and "A" <= text[start + 2] <= "Z":
        return ">"
    tag = _HTML_TAG.match(text, start, end)
    if tag:
        first, last = tag.span(1)
        name = text[first:last].lower() if last - first <= _MAX_HTML_NAME else ""
        if name in ("pre", "script", "style", "textarea"):
            return "</" + name + ">"
        if name in _HTML_BLOCK_TAGS or _GENERIC_HTML.fullmatch(text, start, end):
            return ""
    return None


class _RawBlocks:
    """One block-state scanner; line views never allocate an unbounded slice."""

    def __init__(self):
        self.marker, self.length, self.html, self.ambiguous = "", 0, None, False

    def line(self, text, start, end, slot_open):
        column_zero = start < end and text[start] == "#"
        if (column_zero and not self.marker and self.html is None and slot_open is not None
                and slot_open(text, start, end)):
            return -1
        if _evidence_like(text, start, end):
            return 1 if column_zero and not self.marker and self.html is None and not self.ambiguous else -1
        content = _content_start(text, start, end)
        if not self.marker and content > start and _FENCE_RUN.match(text, content, end):
            self.ambiguous = True
        fence = _FENCE.fullmatch(text, start, end)
        if self.html is not None:
            if ((self.html and re.compile(re.escape(self.html), re.IGNORECASE).search(text, start, end))
                    or not self.html and _BLANK.fullmatch(text, start, end)):
                self.html = None
        elif self.marker:
            if fence:
                first, last = fence.span(1)
                if text[first] == self.marker and last - first >= self.length and _SPACES.fullmatch(text, *fence.span(2)):
                    self.marker = ""
        else:
            self.html = _html_end(text, start, end)
            if self.html is not None:
                if ((self.html and re.compile(re.escape(self.html), re.IGNORECASE).search(text, start, end))
                        or not self.html and _BLANK.fullmatch(text, start, end)):
                    self.html = None
            elif start < end and text[start] in ("`", "~") and fence:
                first, last = fence.span(1)
                if text[first] == "~" or text.find("`", *fence.span(2)) < 0:
                    self.marker, self.length = text[first], last - first
        return 0


def raw_evidence_span(items, slot_open=None, controls=None):
    """Return (decision, item, offset): boundary=1, ambiguous=-1, mixed=-2."""
    blocks, index, end = _RawBlocks(), 0, 0
    for index, text in enumerate(items):
        if type(text) is not str:
            return -2, index, 0
        for line in _RAW_LINES.finditer(text):
            start, end = line.span()
            if start == end == len(text) and text and text[-1] not in "\r\n":
                continue
            while end > start and text[end - 1] in "\r\n":
                end -= 1
            decision = blocks.line(text, start, end, slot_open)
            if decision != 1 and controls is not None and controls(text, start, end):
                return -3, index, start
            if decision:
                return decision, index, start
        end = len(text)
    return 0, index, end


def heading_has_slot(text, start, end):
    return bool(_ATX.match(text, start, end) and text.find(chr(36) + "{", start, end) >= 0)


def raw_do_instruction_span(items, slot_open=None, controls=None, *, max_chars=1024 * 1024):
    """Return (decision, item, start, end) under a column-zero ## Do heading.

    Call with retained guidance: at most 256 items and max_chars characters,
    including item separators. Codes: 1 found, 0 absent, -1 ambiguous, -2 invalid
    field/callback, -3 controls, -4 limit. Offsets exclude line endings. Evidence
    ends discovery; the shared block scanner still validates later retained
    lines, so a later structural/control refusal invalidates an earlier span.
    """
    if type(items) not in (list, tuple):
        return -2, 0, 0, 0
    if (type(max_chars) is not int or not 0 <= max_chars <= 1024 * 1024 or len(items) > 256):
        return -4, 0, 0, 0
    if any(callback is not None and not callable(callback) for callback in (slot_open, controls)):
        return -2, 0, 0, 0
    size = 0
    for index, text in enumerate(items):
        if type(text) is not str:
            return -2, index, 0, 0
        size += len(text) + bool(index)
        if size > max_chars:
            return -4, index, 0, 0
    blocks, found, in_do, index, end = _RawBlocks(), None, False, 0, 0
    for index, text in enumerate(items):
        for line in _RAW_LINES.finditer(text):
            start, end = line.span()
            if start == end == len(text) and text and text[-1] not in "\r\n":
                continue
            while end > start and text[end - 1] in "\r\n":
                end -= 1
            blocked = bool(blocks.marker or blocks.html is not None or blocks.ambiguous)
            decision = blocks.line(text, start, end, slot_open)
            if decision != 1 and controls is not None and controls(text, start, end):
                return -3, index, start, start
            if decision == 1:
                return found if found is not None else (0, index, start, start)
            if decision:
                return decision, index, start, start
            if blocked or blocks.marker or blocks.html is not None or blocks.ambiguous:
                continue
            heading = _heading_span(text, start, end)
            if heading is not None:
                level, left, right = heading
                if level <= 2:
                    in_do = text[start] == "#" and level == 2 and right - left == 2 and text[left:right].casefold() == "do"
                continue
            if not in_do or found is not None:
                continue
            indent = 0
            for position in range(start, _SPACES.match(text, start, end).end()):
                indent += 4 - indent % 4 if text[position] == "\t" else 1
                if indent >= 4:
                    break
            if indent < 4 and _content_start(text, start, end) < end:
                found = 1, index, start, end
        end = len(text)
    return found if found is not None else (0, index, end, end)


def _decode_source_line(raw, start, end, byte_limit, char_limit):
    if end - start > byte_limit:
        raise ValueError("guidance_projection_limit")
    decoder = codecs.getincrementaldecoder("utf-8-sig" if start == 0 else "utf-8")()
    parts, size = [], 0
    for cursor in range(start, end, 4096):
        stop = min(end, cursor + 4096)
        fragment = decoder.decode(memoryview(raw)[cursor:stop], final=stop == end)
        size += len(fragment)
        if size > char_limit:
            raise ValueError("guidance_projection_limit")
        parts.append(fragment)
    return "".join(parts)


def bounded_rule_text(raw, splitter, controls, limit, byte_limit, withheld, control_notice):
    """Decode bounded retained lines; excluded Evidence bytes are never decoded."""
    header, body, header_text = [], [], None
    used_bytes, used_chars = 0, 0
    blocks = _RawBlocks()
    for match in re.finditer(rb"[^\r\n]*(?:\r\n?|\n|$)", raw):
        start, end = match.span()
        if start == end:
            continue
        extra_bytes, extra_chars = (1024, 256) if header_text is not None else (0, 0)
        try:
            line = _decode_source_line(raw, start, end,
                                       min(byte_limit, byte_limit - used_bytes + extra_bytes),
                                       min(limit, limit - used_chars + extra_chars))
        except UnicodeError:
            return None if header_text is None else header_text + withheld
        if header_text is None:
            used_bytes += end - start
            used_chars += len(line)
            header.append(line)
            if len(header) == 1:
                if splitter(line)[0] == "none":
                    return None
            elif splitter("---\n" + line)[0] == "ok":
                header_text = "".join(header)
                status, frontmatter, initial_body = splitter(header_text)
                if status != "ok" or not frontmatter or not frontmatter.strip():
                    return None
                used_chars = len(initial_body)
            continue
        decision = blocks.line(line, 0, len(line.rstrip("\r\n")), heading_has_slot)
        if decision == 1:
            return header_text + "".join(body).rstrip()
        if controls(line):
            return header_text + control_notice
        if decision < 0:
            return header_text + withheld
        used_bytes += end - start
        used_chars += len(line)
        if used_bytes > byte_limit or used_chars > limit:
            raise ValueError("guidance_projection_limit")
        body.append(line)
    return None if header_text is None else header_text + "".join(body)


def guidance_token_estimate(text, ascii_per_token, words_factor):
    if text is None:
        return 0
    if not isinstance(text, str):
        try:
            text = str(text)
        except Exception:
            return 0
    ascii_chars = len(text.encode("ascii", "ignore"))
    by_chars = -(-ascii_chars // ascii_per_token) + (len(text) - ascii_chars)
    by_words = int(len(text.split()) * words_factor)
    return max(by_words, by_chars)


