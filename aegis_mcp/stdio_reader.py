"""Bounded LF-delimited UTF-8 input, shared by both MCP dispatch modes.

Budgets include whitespace and the LF (or CRLF) delimiter. EOF accepts a final
unterminated frame; empty EOF produces no frame. Invalid UTF-8 refuses one whole
frame. Oversize is detected before decoding or JSON parsing, including for
notifications: discard at most MAX_DISCARD_BYTES to reach LF/EOF, otherwise end
the session. No discarded fragment may become a subsequent request.

The server maps FrameError to -32700 with a null id and a fixed message. A
terminal error (including an unreadable or closed stream) ends the loop; other
errors leave it aligned at the next frame.
"""
from __future__ import annotations

import io

from aegis_core.message_codec_format import MAX_BYTES as MESSAGE_CONTENT_MAX_BYTES


# aegis_msg_write carries content JSON inside a JSON-RPC string. Its UTF-8
# bytes can each expand to six bytes when escaped; keep separate room for the
# request envelope and other fields, without reducing the tool content limit.
JSON_STRING_MAX_EXPANSION = 6
REPOSITORY_ENVELOPE_BYTES = 64 * 1024
REPOSITORY_MAX_BYTES = JSON_STRING_MAX_EXPANSION * MESSAGE_CONTENT_MAX_BYTES + REPOSITORY_ENVELOPE_BYTES
MANAGER_MAX_BYTES = 262144
MAX_DISCARD_BYTES = 1048576
_CHUNK_BYTES = 4096


class FrameError(ValueError):
    """A framing refusal, with no input text in the diagnostic."""

    def __init__(self, *, terminal=False):
        super().__init__("Parse error")
        self.terminal = terminal


class _TextReader:
    """Bounded UTF-8 adapter for text-only embeddings (not process stdin).

    Read at most a small chunk of characters before encoding; retain at most
    three bytes when a multibyte character straddles the requested byte count.
    """

    def __init__(self, stream):
        self.stream = stream
        self.pending = b""

    def readline(self, size):
        raw = bytearray()
        while len(raw) < size:
            remaining = size - len(raw)
            if self.pending:
                part = self.pending
                self.pending = b""
            else:
                chars = self.stream.readline(max(1, min(_CHUNK_BYTES // 4, remaining // 4)))
                if not chars:
                    break
                part = chars.encode("utf-8")
            raw.extend(part[:remaining])
            self.pending = part[remaining:]
            if raw.endswith(b"\n"):
                break
        return bytes(raw)


def input_stream(stdin):
    """Prefer raw bytes, independent of the process locale or text error policy."""
    stream = getattr(stdin, "buffer", stdin)
    return _TextReader(stream) if isinstance(stream, io.TextIOBase) else stream


def _readline(stream, size):
    read = getattr(stream, "readline", None)
    if not callable(read):
        raise FrameError(terminal=True)
    try:
        raw = read(size)
    except (OSError, ValueError):
        raise FrameError(terminal=True) from None
    if not isinstance(raw, bytes) or len(raw) > size:
        raise FrameError(terminal=True)
    return raw


def _discard_line(stream):
    """Return whether LF/EOF was reached within the additional byte budget."""
    remaining = MAX_DISCARD_BYTES
    while remaining:
        raw = _readline(stream, min(_CHUNK_BYTES, remaining))
        if not raw or raw.endswith(b"\n"):
            return True
        remaining -= len(raw)
    return False


def read_frame(stream, max_bytes):
    """Read one bounded frame, or None at EOF; raise FrameError on refusal."""
    raw = _readline(stream, max_bytes + 1)
    if not raw:
        return None
    if len(raw) > max_bytes:
        aligned = raw.endswith(b"\n")
        del raw
        if not aligned:
            aligned = _discard_line(stream)
        raise FrameError(terminal=not aligned)
    try:
        return raw.decode("utf-8")
    except UnicodeError:
        raise FrameError() from None


def check_text_size(text, max_bytes, message):
    """Retain direct decoder limits without allocating an unbounded UTF-8 copy."""
    if len(text) > max_bytes:
        raise ValueError(message)
    size = 0
    for start in range(0, len(text), _CHUNK_BYTES // 4):
        size += len(text[start:start + _CHUNK_BYTES // 4].encode("utf-8"))
        if size > max_bytes:
            raise ValueError(message)
