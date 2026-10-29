"""Python source decoding shared by the schema and driver."""
from __future__ import annotations

import functools
import io
from pathlib import Path
import tokenize
from typing import Union

__all__ = ["decode_python_source", "read_python_source"]


@functools.lru_cache(maxsize=None)
def _decodes_ascii_as_itself(encoding: str) -> bool:
    """True when every ASCII byte decodes to itself in any context under ``encoding``.

    Every two-byte ASCII sequence is probed, so a stateful codec's shift sequence
    (utf-7 ``+``, hz ``~{``, iso2022 ESC, unicode_escape ``\\``) shows up as a change,
    plus an IDNA A-label: idna is the one stdlib codec whose trigger is longer than two
    bytes. A codec that fails the probe in any way counts as not transparent (fail closed).
    """
    probe = bytes(b for hi in range(128) for lo in range(128) for b in (hi, lo)) + b".xn--ls8h."
    try:
        return probe.decode(encoding) == probe.decode("ascii")
    except (LookupError, ValueError, TypeError):
        return False


def decode_python_source(data: bytes) -> str:
    """Decode Python source bytes with the encoding CPython chooses for them.

    Honours a UTF-8 BOM and a PEP 263 coding cookie on line 1 or 2. Line endings are
    normalised before the cookie search because CPython counts ``\\r`` and ``\\r\\n`` as
    line breaks there; ``tokenize.open`` splits on ``\\n`` only, so it would honour a cookie
    CPython ignores (a CR-only file whose fourth line declares utf-7) and decode different
    code than CPython runs. Raises SyntaxError for an unknown or conflicting declaration,
    UnicodeDecodeError for bytes the encoding cannot decode, and UnicodeError for an
    encoding that does not decode ASCII to itself (utf-7, hz, iso2022, unicode_escape,
    utf-16, EBCDIC): there the code's meaning depends on the decoder, so it is refused.
    """
    universal = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    encoding, _ = tokenize.detect_encoding(io.BytesIO(universal).readline)
    if encoding not in ("utf-8", "utf-8-sig") and not _decodes_ascii_as_itself(encoding):
        raise UnicodeError(f"source encoding {encoding!r} does not decode ASCII to itself")
    return data.decode(encoding)


def read_python_source(path: Union[str, Path]) -> str:
    """Read a Python file using the same safe decoder as historical source blobs."""
    return decode_python_source(Path(path).read_bytes())
