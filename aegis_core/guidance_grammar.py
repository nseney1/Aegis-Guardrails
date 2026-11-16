"""Pure raw guidance blocks, bounded source decoding and redaction clipping."""
from __future__ import annotations

import codecs
import re
from aegis_core.redaction import (
    SECRET_REPLACEMENTS, RedactionRefusal, clip_atomic_text, remove_url_credentials,
)

__all__ = ["bounded_rule_text", "clip_redacted", "copy_retained_items",
           "guidance_token_estimate", "heading_has_slot", "raw_evidence_span", "redact_labeled"]


def clip_redacted(text, limit):
    """Apply the shared cleaner with the existing guidance clipping policy."""
    try:
        return clip_atomic_text(text, limit, policy="guidance")
    except RedactionRefusal:
        raise ValueError("guidance_projection_limit") from None


def redact_labeled(text, labels, limit):
    """One canonical redaction pass; retain only line/item attribution."""
    try:
        text = remove_url_credentials(text, limit=limit, policy="guidance")
    except RedactionRefusal:
        raise ValueError("guidance_projection_limit") from None
    for pattern, replacement in SECRET_REPLACEMENTS:
        parts, attributed, end, size = [], [], 0, 0
        for match in pattern.finditer(text):
            shown = match.expand(replacement)
            size += match.start() - end + len(shown)
            if size > limit:
                raise ValueError("guidance_projection_limit")
            parts.extend((text[end:match.start()], shown))
            if labels is None:
                end = match.end()
                continue
            attributed.extend(labels[end:match.start()])
            if replacement.startswith(r"\1"):
                first, last = match.span(1)
                attributed.extend(labels[first:last])
                suffix = len(shown) - (last - first)
                attributed.extend([labels[min(last, len(labels) - 1)]] * suffix)
            else:
                attributed.extend([labels[match.start()]] * len(shown))
            end = match.end()
        if not parts:
            continue
        if size + len(text) - end > limit:
            raise ValueError("guidance_projection_limit")
        parts.append(text[end:])
        if labels is not None:
            attributed.extend(labels[end:])
        text, labels = "".join(parts), attributed if labels is not None else None
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


def _evidence_like(text, start, end):
    heading = _ATX.match(text, _content_start(text, start, end), end)
    if not heading:
        return False
    left, right = heading.span(1)
    while right > left and text[right - 1] in " #\t":
        right -= 1
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


