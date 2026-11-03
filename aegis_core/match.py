"""The one target_paths matcher (ADR 0005 AD-3 L1, defense #23).

Every place that asks "does this rule apply to this file?" calls ``matches``:
aegis scan, the ``aegis check`` telemetry and forbid_ast gates, credit assignment,
coverage and the grade. One pattern therefore means the same thing everywhere.

Semantics are a superset of posix ``fnmatch.fnmatchcase`` on workspace-relative
POSIX paths:

- ``*`` crosses ``/`` (as in fnmatch): ``aegis_core/*.py`` matches
  ``aegis_core/lifecycle/promotion.py``. Shipped rules rely on this.
- ``**/`` is zero or more directories: ``src/**/*.py`` matches ``src/a.py``, which
  fnmatch alone does not.
- A pattern without ``/`` also matches the basename: ``Makefile`` matches
  ``tools/Makefile``.
- There is no substring glob: ``src`` never matches ``src/a.py`` and ``aegis`` never
  matches ``aegis_core/x.py``.
- Matching is case-sensitive on every platform (``fnmatch.fnmatch`` is not on
  Windows), so the same rule set selects the same rules on every host.

Patterns and file names both come from the repository, which may be hostile, so a
match never backtracks: a regex with k unbounded wildcards can take n**k steps
(``*a*a*a*a*a*a*a*b`` against a 60-character name took 8 s; eight stars or a chain of
``**/a`` hung for minutes). Instead a pattern is cut at its wildcards into fixed-width
pieces, placed left to right while keeping only the set of positions reachable so
far: each piece costs at most one pass over the name.
"""
from __future__ import annotations

from dataclasses import dataclass
import functools
import os
from pathlib import Path
import posixpath
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple, Union

__all__ = [
    "credit_weights",
    "split_credit",
    "first_match",
    "is_test_path",
    "matches",
    "matching_files",
    "may_overlap",
    "normalize_path",
    "sets_overlap",
    "workspace_files",
]

Patterns = Union[str, Iterable[object], None]

_TEST_SUFFIXES = ("_test.py", "_test.go") + tuple(
    f".{kind}.{extension}"
    for kind in ("test", "spec")
    for extension in ("ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs")
)


def normalize_path(path: str) -> str:
    """A path or pattern as workspace-relative POSIX: ``/`` separators, no leading
    ``./`` or ``/``. A leading dot that belongs to a name (``.aegis``) is kept."""
    text = path.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def _class(body: str) -> str:
    """A ``[...]`` body as a regex class, the way fnmatch reads it."""
    body = body.replace("\\", "\\\\")
    body = re.sub(r"([&~|])", r"\\\1", body)
    if body.startswith("!"):
        return "[^" + body[1:] + "]"
    if body.startswith("^"):
        return "[\\" + body + "]"
    return "[" + body + "]"


_STAR = "*"  # any run of characters, "/" included
_DSTAR = "**/"  # nothing, or any run of characters that ends with "/"


def _tokens(pattern: str) -> List[str]:
    """The pattern as wildcards (_STAR, _DSTAR) and one-character regex atoms."""
    out: List[str] = []
    i, n = 0, len(pattern)
    while i < n:
        if pattern.startswith("**/", i):
            out.append(_DSTAR)
            i += 3
            continue
        char = pattern[i]
        if char == "*":
            while i < n and pattern[i] == "*":
                i += 1
            out.append(_STAR)
            continue
        if char == "?":
            out.append(".")
            i += 1
            continue
        if char == "[":
            j = i + 1
            if j < n and pattern[j] == "!":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j < n:
                body = pattern[i + 1:j]
                piece = _class(body) if body not in ("", "!") else ("(?!)" if not body else ".")
                try:
                    re.compile(piece)
                except re.error:
                    # A class fnmatch would treat as empty (a reversed range) matches nothing.
                    piece = "(?!)"
                out.append(piece)
                i = j + 1
                continue
            out.append("\\[")
            i += 1
            continue
        out.append(re.escape(char))
        i += 1
    return out


@dataclass(frozen=True)
class _Piece:
    """The pattern between two wildcards: fixed width, one character per atom."""

    regex: Optional["re.Pattern[str]"]  # None for the empty piece
    width: int

    def at(self, text: str, pos: int) -> bool:
        return self.regex is None or self.regex.match(text, pos) is not None

    def next_start(self, text: str, pos: int) -> Optional[int]:
        """Where the piece next occurs at or after ``pos`` (fixed width: leftmost is exact)."""
        if self.regex is None:
            return pos if pos <= len(text) else None
        found = self.regex.search(text, pos)
        return found.start() if found is not None else None


@dataclass(frozen=True)
class _Glob:
    head: _Piece
    steps: Tuple[Tuple[str, _Piece], ...]  # (wildcard, the piece after it)


def _piece(atoms: List[str]) -> _Piece:
    if not atoms:
        return _Piece(None, 0)
    return _Piece(re.compile("(?s:" + "".join(atoms) + ")"), len(atoms))


@functools.lru_cache(maxsize=4096)
def _compile(pattern: str) -> _Glob:
    pieces: List[List[str]] = [[]]
    wildcards: List[str] = []
    for token in _tokens(pattern):
        if token not in (_STAR, _DSTAR):
            pieces[-1].append(token)
        elif wildcards and not pieces[-1]:
            # Adjacent wildcards are one, and only "**/" can come first ("*" is read as a
            # whole run of stars): "**/*" is "*" and "**/**/" is "**/".
            wildcards[-1] = token
        else:
            wildcards.append(token)
            pieces.append([])
    return _Glob(_piece(pieces[0]), tuple(zip(wildcards, (_piece(p) for p in pieces[1:]))))


def _ends(kind: str, piece: _Piece, text: str, reach: Set[int], lo: int, first_only: bool) -> List[int]:
    """The positions, ascending, where ``piece`` can end after wildcard ``kind`` entered
    at any of ``reach`` (whose least is ``lo``)."""
    if kind == _STAR:  # "*" from lo reaches every position from lo on
        ends: List[int] = []
        start = piece.next_start(text, lo)
        while start is not None:
            ends.append(start + piece.width)
            if first_only:
                break
            start = piece.next_start(text, start + 1)
        return ends
    # "**/" entered at r reaches r and every position just after a "/" at or beyond r.
    starts = set(reach)
    slash = text.find("/", lo)
    while slash != -1:
        starts.add(slash + 1)
        slash = text.find("/", slash + 1)
    ends = [start + piece.width for start in sorted(starts) if piece.at(text, start)]
    return ends[:1] if first_only else ends


def _glob_match(glob: _Glob, text: str) -> bool:
    n = len(text)
    if not glob.head.at(text, 0):
        return False
    if not glob.steps:
        return glob.head.width == n
    reach: Set[int] = {glob.head.width}
    lo = glob.head.width
    last = len(glob.steps) - 1
    for index, (kind, piece) in enumerate(glob.steps):
        if index == last:  # the last piece ends the name
            start = n - piece.width
            if start < lo or not piece.at(text, start):
                return False
            return kind == _STAR or start in reach or text[start - 1] == "/"
        # Before a "*" only the least end matters: the "*" absorbs whatever follows it.
        ends = _ends(kind, piece, text, reach, lo, first_only=glob.steps[index + 1][0] == _STAR)
        if not ends:
            return False
        reach, lo = set(ends), ends[0]
    return False


def matches(pattern: str, path: str) -> bool:
    """Whether target_paths ``pattern`` applies to the workspace-relative ``path``."""
    if not isinstance(pattern, str) or not isinstance(path, str):
        return False
    pat, rel = normalize_path(pattern), normalize_path(path)
    if not pat or not rel:
        return False
    glob = _compile(pat)
    if _glob_match(glob, rel):
        return True
    return "/" not in pat and _glob_match(glob, rel.rsplit("/", 1)[-1])


_WILDCARD = re.compile(r"[*?\[]")


def _literal_prefix(glob: object) -> Optional[str]:
    """The text every path ``glob`` matches starts with, casefolded; None when ``glob``
    matches nothing (not a string, or empty after normalizing)."""
    if not isinstance(glob, str):
        return None
    pattern = normalize_path(glob)
    if not pattern:
        return None
    if "/" not in pattern:
        return ""  # the basename rule lets it match at any depth
    found = _WILDCARD.search(pattern)
    return (pattern if found is None else pattern[:found.start()]).casefold()


def may_overlap(a: str, b: str) -> bool:
    """Whether some path could match both globs (the lease overlap test, v4.1 §1).

    Conservative: a path ``matches`` both only if it starts with both literal prefixes
    (the text before the first ``*``, ``?`` or ``[``; ``""`` for a slashless glob, which
    also matches basenames), so one prefix must be a string prefix of the other. The
    prefixes compare casefolded, because on a case-insensitive file system ``Docs/`` and
    ``docs/`` are one directory. "True" therefore means "unsure", never "proven"; "False"
    is proof that no path matches both. A glob that matches nothing never overlaps.
    """
    first, second = _literal_prefix(a), _literal_prefix(b)
    if first is None or second is None:
        return False
    return first.startswith(second) or second.startswith(first)


def sets_overlap(first: Patterns, second: Patterns) -> bool:
    """Whether any glob of ``first`` may overlap any glob of ``second`` (lists, or one
    glob as a string)."""
    others = _as_list(second)
    return any(may_overlap(a, b) for a in _as_list(first) for b in others)


def _as_list(patterns: Patterns) -> List[object]:
    if patterns is None:
        return []
    if isinstance(patterns, str):
        return [patterns]
    return list(patterns)


def first_match(patterns: Patterns, path: str) -> Optional[str]:
    """The first of ``patterns`` (a list, or one pattern string) that matches ``path``."""
    for pattern in _as_list(patterns):
        if isinstance(pattern, str) and matches(pattern, path):
            return pattern
    return None


def _unique(files: Iterable[str]) -> List[str]:
    """``files`` normalized, in order, each once: ``./src/a.py`` and ``src/a.py`` are one file."""
    return list(dict.fromkeys(normalize_path(f) for f in files if isinstance(f, str)))


def workspace_files(root: Any, files: Iterable[str]) -> List[str]:
    """``files`` as the workspace-relative POSIX paths rules are matched against, each once.

    An absolute path inside ``root`` is made relative to it (both resolved, so a
    symlinked temp dir or a Windows drive spelling compares equal). A path outside the
    workspace, absolute or climbing out with ``..``, is no workspace file: no rule
    applies to it, so it is dropped.
    """
    base: Optional[Path] = None
    out: List[str] = []
    for raw in files:
        if not isinstance(raw, str) or not raw:
            continue
        if os.path.isabs(raw):
            if base is None:
                base = Path(os.fspath(root)).resolve()
            try:
                rel = Path(raw).resolve().relative_to(base).as_posix()
            except (ValueError, OSError):
                continue
        else:
            rel = posixpath.normpath(normalize_path(raw))
        if rel in ("", ".") or rel == ".." or rel.startswith("../"):
            continue
        out.append(rel)
    return _unique(out)


def matching_files(patterns: Patterns, files: Iterable[str]) -> List[str]:
    """The ``files`` some pattern matches, normalized, in order and without duplicates."""
    pats = _as_list(patterns)
    return [f for f in _unique(files) if first_match(pats, f) is not None]


def split_credit(applies: Mapping[str, Iterable[str]]) -> Dict[str, float]:
    """Split one outcome's credit over the rules, file by file.

    ``applies`` maps a rule id to the changed files it applies to. Each file is worth
    1.0, shared equally by the rules that apply to it; a rule's weight is the sum over
    its files (callers that record a ledger weight clamp it to 1). A rule applying to
    no changed file gets 0.0.
    """
    files = {rule: _unique(found) for rule, found in applies.items()}
    sharers: Dict[str, int] = {}
    for found in files.values():
        for path in found:
            sharers[path] = sharers.get(path, 0) + 1
    return {rule: sum(1.0 / sharers[path] for path in found) for rule, found in files.items()}


def credit_weights(rules: Mapping[str, Patterns], files: Iterable[str]) -> Dict[str, float]:
    """``split_credit`` for rules given by their target_paths (``rules`` maps a rule id
    to its patterns)."""
    changed = _unique(files)
    return split_credit({
        rule: [path for path in changed if first_match(_as_list(pats), path) is not None]
        for rule, pats in rules.items()
    })


def is_test_path(path: str) -> bool:
    """Whether ``path`` is a test file: under ``tests/`` or ``__tests__/``, ``test_*``,
    ``conftest.py``, or a ``*_test.py``/``*_test.go``/``*.test.ts``/``*.spec.js`` style name.

    The one test-file predicate (defense #25); callers that also skip support files
    (``__init__.py``) add that themselves.
    """
    rel = normalize_path(path)
    parts = rel.split("/")
    base = parts[-1]
    return (
        any(part in ("tests", "__tests__") for part in parts[:-1])
        or base.startswith("test_")
        or base == "conftest.py"
        or base.endswith(_TEST_SUFFIXES)
    )
