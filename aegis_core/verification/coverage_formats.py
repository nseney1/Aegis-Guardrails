"""Pure, bounded LCOV and Go coverprofile readers.

Paths are returned verbatim: callers must map and confine them before using them.
Go blocks cover their inclusive line span, even with a zero statement count.
Duplicate records union coverage; a positive hit never becomes uncovered later.
Input is capped at 8 MiB of UTF-8 and one million expanded line units. Every
record charges its span, including overlaps, so repeated large ranges stay bounded.
Numeric fields fit nonnegative signed 64-bit values; source positions are positive.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

__all__ = ["CoverageFormatError", "LineCoverage", "parse_lcov", "parse_go_coverprofile"]

_MAX_BYTES = 8 * 1024 * 1024
_MAX_LINES = 1_000_000
_MAX_INTEGER = (1 << 63) - 1
_LCOV_COUNTS = frozenset({"FNF", "FNH", "BRF", "BRH"})
_LCOV_IGNORED = _LCOV_COUNTS | {"FN", "FNDA", "BRDA", "VER"}


class CoverageFormatError(ValueError):
    """The report is malformed, incomplete or beyond the reader's bounds."""


@dataclass(frozen=True)
class LineCoverage:
    executable: frozenset[int]
    covered: frozenset[int]


def _lines(text: str) -> Iterator[tuple[int, str]]:
    if not isinstance(text, str):
        raise CoverageFormatError("coverage report must be text")
    if len(text) > _MAX_BYTES:
        raise CoverageFormatError("coverage report exceeds 8 MiB")
    if "\x00" in text:
        raise CoverageFormatError("coverage report contains NUL")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise CoverageFormatError("coverage report is not valid Unicode") from exc
    if size > _MAX_BYTES:
        raise CoverageFormatError("coverage report exceeds 8 MiB")
    for number, raw in enumerate(text.split("\n"), 1):
        line = raw[:-1] if raw.endswith("\r") else raw
        if line:
            yield number, line


def _number(value: str, field: str, where: str, *, positive: bool = False) -> int:
    if not value or not value.isascii() or not value.isdigit():
        raise CoverageFormatError(f"{where}: invalid {field}")
    digits = value.lstrip("0") or "0"
    if len(digits) > 19:
        raise CoverageFormatError(f"{where}: invalid {field}")
    number = int(digits)
    if number > _MAX_INTEGER or (positive and number == 0):
        raise CoverageFormatError(f"{where}: invalid {field}")
    return number


def _charge(used: int, count: int) -> int:
    if count > _MAX_LINES - used:
        raise CoverageFormatError("coverage report exceeds 1000000 expanded lines")
    return used + count


def _freeze(rows: dict[str, tuple[set[int], set[int]]]) -> dict[str, LineCoverage]:
    return {path: LineCoverage(frozenset(executable), frozenset(covered))
            for path, (executable, covered) in rows.items()}


def _lcov_metadata(kind: str, value: str, where: str) -> None:
    if kind in _LCOV_COUNTS:
        _number(value, f"{kind} count", where)
    elif kind in {"FN", "FNDA"}:
        count, comma, name = value.partition(",")
        if not comma or not name:
            raise CoverageFormatError(f"{where}: malformed {kind} record")
        _number(count, "function line" if kind == "FN" else "function hit count",
                where, positive=kind == "FN")
    elif kind == "BRDA":
        fields = value.split(",", 3)
        if len(fields) != 4 or not all(fields):
            raise CoverageFormatError(f"{where}: malformed BRDA record")
        _number(fields[0], "branch line", where, positive=True)
        if fields[3] != "-":
            _number(fields[3], "branch hit count", where)


def parse_lcov(text: str) -> dict[str, LineCoverage]:
    """Read complete SF/DA/end_of_record sections, preserving original paths.

    Optional LF/LH summaries must agree with the section's unique DA lines.
    Function, branch and version records do not contribute executable lines.
    """
    rows: dict[str, tuple[set[int], set[int]]] = {}
    current = None
    executable: set[int] = set()
    covered: set[int] = set()
    summaries: dict[str, int] = {}
    used = 0
    for number, line in _lines(text):
        where = f"LCOV line {number}"
        if line == "end_of_record":
            if current is None:
                raise CoverageFormatError(f"{where}: end_of_record outside a source record")
            for kind, actual in (("LF", len(executable)), ("LH", len(covered))):
                if kind in summaries and summaries[kind] != actual:
                    raise CoverageFormatError(f"{where}: {kind} does not match DA records")
            all_lines, hit_lines = rows.setdefault(current, (set(), set()))
            all_lines.update(executable)
            hit_lines.update(covered)
            current = None
            continue
        kind, colon, value = line.partition(":")
        if not colon:
            raise CoverageFormatError(f"{where}: malformed record")
        if kind == "TN":
            if current is not None:
                raise CoverageFormatError(f"{where}: test name before end_of_record")
            continue
        if kind == "SF":
            if current is not None:
                raise CoverageFormatError(f"{where}: source record before end_of_record")
            if not value:
                raise CoverageFormatError(f"{where}: empty source path")
            current, executable, covered, summaries = value, set(), set(), {}
            continue
        if kind not in {"DA", "LF", "LH"} | _LCOV_IGNORED:
            raise CoverageFormatError(f"{where}: unsupported record {kind}")
        if current is None:
            raise CoverageFormatError(f"{where}: {kind} outside a source record")
        if kind == "DA":
            fields = value.split(",")
            if len(fields) not in (2, 3) or not all(fields):
                raise CoverageFormatError(f"{where}: malformed DA record")
            position = _number(fields[0], "line number", where, positive=True)
            hits = _number(fields[1], "hit count", where)
            used = _charge(used, 1)
            executable.add(position)
            if hits > 0:
                covered.add(position)
        elif kind in {"LF", "LH"}:
            count = _number(value, f"{kind} count", where)
            if kind in summaries and summaries[kind] != count:
                raise CoverageFormatError(f"{where}: conflicting {kind} records")
            summaries[kind] = count
        else:
            _lcov_metadata(kind, value, where)
    if current is not None:
        raise CoverageFormatError("LCOV source record is missing end_of_record")
    if not rows:
        raise CoverageFormatError("LCOV report contains no source records")
    return _freeze(rows)


def _go_location(block: str, where: str) -> tuple[str, int, int]:
    path, colon, location = block.rpartition(":")
    spans = location.split(",")
    if not colon or len(spans) != 2 or any(len(part.split(".")) != 2 for part in spans):
        raise CoverageFormatError(f"{where}: malformed coverage location")
    if not path:
        raise CoverageFormatError(f"{where}: empty source path")
    start, end = (part.split(".") for part in spans)
    start_line = _number(start[0], "start line", where, positive=True)
    start_col = _number(start[1], "start column", where, positive=True)
    end_line = _number(end[0], "end line", where, positive=True)
    end_col = _number(end[1], "end column", where, positive=True)
    if (end_line, end_col) <= (start_line, start_col):
        raise CoverageFormatError(f"{where}: invalid coverage range")
    return path, start_line, end_line


def parse_go_coverprofile(text: str) -> dict[str, LineCoverage]:
    """Read set/count/atomic profiles; a mode-only profile reports no paths."""
    rows: dict[str, tuple[set[int], set[int]]] = {}
    lines = iter(_lines(text))
    header = next(lines, None)
    if header is None or not header[1].startswith("mode: ") or not header[1][6:]:
        raise CoverageFormatError("Go coverprofile is missing its mode header")
    mode = header[1][6:]
    if mode not in {"set", "count", "atomic"}:
        raise CoverageFormatError(f"Go line {header[0]}: unsupported mode {mode}")
    used = 0
    for number, line in lines:
        where = f"Go line {number}"
        if line.startswith("mode:"):
            raise CoverageFormatError(f"{where}: duplicate mode header")
        fields = line.rsplit(None, 2)
        if len(fields) != 3:
            raise CoverageFormatError(f"{where}: malformed coverage block")
        path, start, end = _go_location(fields[0], where)
        _number(fields[1], "statement count", where)
        hits = _number(fields[2], "hit count", where)
        used = _charge(used, end - start + 1)
        executable, covered = rows.setdefault(path, (set(), set()))
        executable.update(range(start, end + 1))
        if hits > 0:
            covered.update(range(start, end + 1))
    return _freeze(rows)
