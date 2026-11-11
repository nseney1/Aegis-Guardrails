"""Fail-closed trailer shapes shared by signed approvals."""
from __future__ import annotations

import re
from typing import Optional, Pattern, Tuple

__all__ = ["MAX_MESSAGE_BYTES", "MAX_LINE_LENGTH", "bounds_refusal", "has_authority_line", "refusal"]

MAX_MESSAGE_BYTES = 65536
MAX_LINE_LENGTH = 8192

_AEGIS_LINE = re.compile(r"^[ \t]*aegis-", re.IGNORECASE | re.MULTILINE)
_AUTHORITY_LINE = re.compile(
    r"^[ \t]*aegis-(?:approve(?:-insight)?|exempt-test|manager-approve)[ \t]*:", re.I | re.M)
# Non-authority metadata produced by credit.format_trailer / hooks.commitmsg.
_CHECK_LINE = re.compile(
    r"[ \t]*aegis-check:[ \t]*tree=(?:[0-9a-f]{40}|[0-9a-f]{64})[ \t]+exit=-?[0-9]+[ \t]*", re.I)
_TRAILER_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")


def bounds_refusal(message: str) -> Optional[Tuple[str, str]]:
    """Bound characters before encoding, then bytes and lines before any regex.

    A UTF-8 character occupies at least one byte, so the character preflight caps
    the encoding allocation too. Surrogatepass also bounds losslessly decoded text.
    """
    if len(message) > MAX_MESSAGE_BYTES or len(message.encode("utf-8", "surrogatepass")) > MAX_MESSAGE_BYTES:
        return "message_too_large", "approval message exceeds the byte limit"
    start = 0
    while start < len(message):
        end = message.find("\n", start)
        end = len(message) if end < 0 else end
        if end - start > MAX_LINE_LENGTH:
            return "message_line_too_long", "approval message exceeds the line length limit"
        start = end + 1
    return None


def has_authority_line(message: str) -> bool:
    """Check authority markers only; hook callers bound the raw bytes first."""
    return _AUTHORITY_LINE.search(message) is not None


def _tail_is_metadata(message: str, start: int) -> bool:
    while start < len(message):
        end = message.find("\n", start)
        end = len(message) if end < 0 else end
        line = message[start:end]
        if line.strip(" \t"):
            key, separator, value = line.partition(":")
            if not separator or _TRAILER_KEY.fullmatch(key) is None or not all(
                    char.isprintable() for char in value.lstrip(" \t")):
                return False
        start = end + 1
    return True


def refusal(message: str, trailer: Pattern[str], name: str) -> Optional[Tuple[str, str]]:
    """Return a stable refusal for extra authority or a continued signed value.

    Subjects and preceding prose stay compatible within these limits. Exactly
    one authority line is allowed; Aegis-Check and ordinary trailers may accompany it.
    Bounds precede all regexes. Callers retain their existing missing-trailer and
    target-mismatch refusal precedence for messages within those limits.
    """
    if limit := bounds_refusal(message):
        return limit
    value_error = ("invalid_message_shape", f"the {name} value must be one printable line")
    matches = trailer.finditer(message)
    match = next(matches, None)
    if match is None:
        return value_error
    if next(matches, None) is not None:
        return "multiple_trailers", f"more than one {name} trailer"
    for line in _AEGIS_LINE.finditer(message):
        if line.start() == match.start():
            continue
        end = message.find("\n", line.start())
        end = len(message) if end < 0 else end
        if _CHECK_LINE.fullmatch(message, line.start(), end) is not None:
            continue
        kind = "another Aegis authority" if _AUTHORITY_LINE.match(message, line.start()) else "an unknown Aegis"
        number = message.count("\n", 0, line.start()) + 1
        return "invalid_message_shape", f"{kind} line is present (line {number})"
    if not _tail_is_metadata(message, match.end()) or any(
            not char.isprintable() for group in range(1, (match.lastindex or 0) + 1)
            for char in (match.group(group) or "").rstrip(" \t")):
        return value_error
    return None
