"""The ratchet baseline (v4.2 #2): adopt ``aegis check`` in a repository that already has findings.

``aegis check --write-baseline`` records every current Layer 1 finding in
``.aegis/baseline.json``::

    {"v": 1, "findings": [{"rule": "forbid_ast:no-eval", "path": "src/a.py", "fp": "0123456789abcdef"}]}

``aegis check`` then fails only on findings the baseline does not hold. A finding is one
failed Layer 1 check on one file, down to the line that matched; its fingerprint is
``fp = sha256(rule | path | normalized matched line | occurrence index)`` (the full 64-hex digest), where the
occurrence index counts the earlier lines of the file with the same normalized text.
The fingerprint therefore survives a line moving (an insertion above it), does not
survive the line changing, and tells two copies of one line apart. Nothing in it is a
line number.

**Provenance.** The baseline decides which failures are ignored, so whoever controls it
controls the gate. With ``--base <ref>`` it is read from the commit ``<ref>`` names, with
``gitsafe.read_blob``, and the candidate's own file is never consulted: a baseline absent
at base is empty (``baseline: absent at base``), a base that does not resolve or a
baseline at base that does not parse is an error, and neither falls back to the working
tree. Without ``--base`` the working tree's file is used and the result says so
(``baseline: working tree (self-attested)``). There is no CI detection.

**What can be baselined.** The findings of call_graph and import_guard (each has the
lines it matched) and of forbid_ast (one per violating call or import site). A failure
that is not about a line of a checked file stays failing whatever the baseline holds:
a rule that cannot load, a file that cannot be parsed or read, a surviving mutant, a
decorator violation that has no line.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import tempfile
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, NamedTuple, Optional, Sequence, Tuple

from aegis_core import gitsafe, primitives
from aegis_core.errors import AegisError
from aegis_core.primitives import DuplicateKeyError, is_within, safe_parts, strict_loads
from aegis_core.storage import atomic_write_text
from aegis_core.verification import ToolEvidence
from aegis_core.workspace.layout import AEGIS_DIRNAME

__all__ = [
    "BASELINE_FILE",
    "BASELINE_VERSION",
    "LABEL_ABSENT",
    "LABEL_WORKING",
    "MAX_BYTES",
    "Applied",
    "Baseline",
    "BaselineError",
    "BaselineFileError",
    "BaselineUsage",
    "Collected",
    "Entry",
    "Finding",
    "Sources",
    "apply",
    "basename_groups",
    "checkable",
    "collect",
    "fingerprint",
    "label_base",
    "list_files",
    "load",
    "normalize_text",
    "occurrence_index",
    "parse",
    "render",
    "run_fast",
    "run_grouped",
    "split_lines",
    "write",
]

BASELINE_FILE = f"{AEGIS_DIRNAME}/baseline.json"  # workspace-relative POSIX, as git names it
BASELINE_VERSION = 1
MAX_BYTES = 8 * 1024 * 1024
LABEL_WORKING = "baseline: working tree (self-attested)"
LABEL_ABSENT = "baseline: absent at base"
_KEYS = ("rule", "path", "fp")
_FP = re.compile(r"\A[0-9a-f]{64}\Z")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_LINE_BREAK = re.compile(r"\r\n|\r|\n")


def label_base(commit: str) -> str:
    return f"baseline: base@{commit}"


# ── Errors ───────────────────────────────────────────────────────────────────

class BaselineError(AegisError):
    """The baseline cannot be used: an unreadable file, a base that does not resolve."""


class BaselineFileError(BaselineError):
    """The baseline file is invalid. The message is ``<where>: <reason>`` and never quotes
    the file: its rules and paths are repository-chosen."""

    def __init__(self, reason: str, where: str = BASELINE_FILE) -> None:
        super().__init__(f"{where}: {reason}")
        self.reason = reason


class BaselineUsage(BaselineError):
    """A usage error: the question cannot be asked here (``--base`` outside git)."""


# ── Fingerprints ─────────────────────────────────────────────────────────────

class Entry(NamedTuple):
    """One baseline row. All three fields must match for a finding to be grandfathered."""

    rule: str
    path: str
    fp: str


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


class _Lines:
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
    return _Lines(lines).index(number)


def fingerprint(rule: str, path: str, text: str, index: int) -> str:
    joined = "|".join((rule, path, text, str(index)))
    return hashlib.sha256(joined.encode("utf-8", "surrogatepass")).hexdigest()


@dataclass(frozen=True)
class Finding:
    """One finding: ``rule`` is the Layer 1 tool (``forbid_ast:<rule id>``, ``call_graph``,
    ``import_guard``), ``text`` the normalized matched line (the violation's message when
    the finding has no line), ``index`` its occurrence index, ``line`` where it was seen
    (0 when unknown; it is not part of the fingerprint)."""

    rule: str
    path: str
    text: str
    index: int
    line: int
    detail: str

    @property
    def fp(self) -> str:
        return fingerprint(self.rule, self.path, self.text, self.index)

    @property
    def entry(self) -> Entry:
        return Entry(self.rule, self.path, self.fp)

    def as_dict(self) -> Dict[str, Any]:
        row: Dict[str, Any] = {"rule": self.rule, "path": self.path, "fp": self.fp}
        if self.line:
            row["line"] = self.line
        row["text"] = self.text
        row["detail"] = self.detail
        return row


# ── The file ─────────────────────────────────────────────────────────────────

def render(entries: Iterable[Entry]) -> str:
    """The file's text: sorted by path, rule and fingerprint, each entry once, ending in
    a newline, so the same findings always give the same bytes."""
    rows = sorted({(e.path, e.rule, e.fp) for e in entries})
    document = {"v": BASELINE_VERSION, "findings": [{"rule": r, "path": p, "fp": f} for p, r, f in rows]}
    return json.dumps(document, indent=2) + "\n"


def _path_ok(value: object) -> bool:
    # The part rule of every platform (windows=False): a v1 file that holds a:b.py reads the same anywhere.
    return isinstance(value, str) and not _CONTROL.search(value) and "\\" not in value \
        and safe_parts(value, windows=False) is not None


def parse(data: bytes) -> FrozenSet[Entry]:
    """The entries in ``data`` (the bytes of a baseline.json). Raises BaselineFileError for
    a file over MAX_BYTES, invalid UTF-8 or JSON (a duplicated key, NaN), a non-object, an
    unknown key, ``v`` other than the integer 1, or a finding that is not exactly a rule
    (text), a workspace-relative POSIX path and a 64-character lowercase hex ``fp``. A
    UTF-8 byte order mark is accepted, as in config.json."""
    if len(data) > MAX_BYTES:
        raise BaselineFileError(f"larger than {MAX_BYTES // (1024 * 1024)} MiB")
    try:
        text = bytes(data).decode("utf-8-sig")
    except UnicodeDecodeError:
        raise BaselineFileError("not valid UTF-8") from None
    try:
        value = strict_loads(text)
    except DuplicateKeyError:  # before ValueError, which it is
        raise BaselineFileError("duplicate key") from None
    except (ValueError, RecursionError):
        raise BaselineFileError("not valid JSON") from None
    if not isinstance(value, dict):
        raise BaselineFileError("must hold a JSON object")
    unknown = [key for key in value if key not in ("v", "findings")]
    if unknown:
        raise BaselineFileError(f"{len(unknown)} unknown key(s)")
    version = value.get("v")
    if type(version) is not int or version != BASELINE_VERSION:  # True == 1, but is no version
        raise BaselineFileError(f"v must be {BASELINE_VERSION}")
    findings = value.get("findings")
    if not isinstance(findings, list):
        raise BaselineFileError("findings must be a list")
    entries: List[Entry] = []
    for ordinal, row in enumerate(findings, 1):
        if not isinstance(row, dict):
            raise BaselineFileError(f"finding {ordinal} must be an object")
        if sorted(row) != sorted(_KEYS):
            raise BaselineFileError(f"finding {ordinal} must have exactly rule, path and fp")
        rule, path, fp = row["rule"], row["path"], row["fp"]
        if not isinstance(rule, str) or not rule or _CONTROL.search(rule):
            raise BaselineFileError(f"finding {ordinal}: rule must be text")
        if not _path_ok(path):
            raise BaselineFileError(f"finding {ordinal}: path must be a workspace-relative POSIX path")
        if not isinstance(fp, str) or not _FP.match(fp):
            raise BaselineFileError(f"finding {ordinal}: fp must be 64 lowercase hex characters")
        entries.append(Entry(rule, path, fp))
    return frozenset(entries)


# ── Where it is read from ────────────────────────────────────────────────────

@dataclass(frozen=True)
class Baseline:
    """The baseline in force and where it came from.

    ``source`` is ``none`` (no baseline: ``aegis check`` behaves as without the feature),
    ``working-tree`` (self-attested), ``base`` (read from ``commit``) or ``absent`` (a
    base that has no baseline: empty). ``label`` is the text the report shows."""

    entries: FrozenSet[Entry]
    label: Optional[str]
    source: str
    commit: Optional[str] = None

    @property
    def active(self) -> bool:
        return self.source != "none"

    def as_dict(self) -> Dict[str, Any]:
        return {"label": self.label, "source": self.source, "commit": self.commit, "path": BASELINE_FILE,
                "entries": len(self.entries)}


def _read_working(root: Path) -> Optional[bytes]:
    """The working tree's baseline bytes, or None when there is no file. A symlink, a file
    that resolves outside the workspace and anything but a regular file are refused (a
    FIFO is never waited on)."""
    path = root / BASELINE_FILE
    try:
        info = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError:
        raise BaselineFileError("cannot be read") from None
    if stat.S_ISLNK(info.st_mode):
        raise BaselineFileError("is a symlink")
    if not stat.S_ISREG(info.st_mode):
        raise BaselineFileError("not a regular file")
    if not is_within(path, root, unresolvable=False):
        raise BaselineFileError("resolves outside the workspace")
    if info.st_size > MAX_BYTES:
        raise BaselineFileError(f"larger than {MAX_BYTES // (1024 * 1024)} MiB")
    try:
        with open(path, "rb") as handle:
            return handle.read(MAX_BYTES + 1)
    except OSError:
        raise BaselineFileError("cannot be read") from None


def _repo_path(root: Path, top: Path) -> str:
    """The baseline's path as git names it: relative to the repository top."""
    try:
        below = os.path.relpath(os.path.realpath(root), os.path.realpath(top)).replace(os.sep, "/")
    except ValueError:  # another drive on Windows
        raise BaselineUsage("the workspace is not inside the repository's work tree") from None
    if below.startswith("..") or os.path.isabs(below):
        raise BaselineUsage("the workspace is not inside the repository's work tree")
    return BASELINE_FILE if below == "." else f"{below}/{BASELINE_FILE}"


def load(root: Any, base: Optional[str] = None) -> Baseline:
    """The baseline for ``root``: from the working tree, or from ``base`` when one is given.

    With a base, only that commit is read: the working tree's file is not looked at and
    nothing falls back to it. Raises BaselineUsage outside a git work tree, BaselineError
    for a base that names no commit or content git cannot return, BaselineFileError for
    an invalid file (at base: ``<file> at <base>: <reason>``).
    """
    workspace = Path(os.fspath(root))
    if base is None:
        data = _read_working(workspace)
        if data is None:
            return Baseline(frozenset(), None, "none")
        return Baseline(parse(data), LABEL_WORKING, "working-tree")
    top = gitsafe.toplevel(workspace)
    if top is None:
        raise BaselineUsage("--base needs a git work tree: the baseline is read from the base commit")
    # Resolve first: read_blob answers None for a revision that names nothing, which would
    # read as "no baseline at base" and so turn a typo into an empty (strict) gate silently.
    commit = gitsafe.resolve_commit(top, base) if isinstance(base, str) and base else None
    if not commit:
        raise BaselineError(f"cannot resolve the base {base!r} to a commit")
    try:
        data = gitsafe.read_blob(top, commit, _repo_path(workspace, top))
    except gitsafe.GitError as exc:
        raise BaselineError(f"{BASELINE_FILE} at {base}: {exc}") from None
    if data is None:
        return Baseline(frozenset(), LABEL_ABSENT, "absent", commit)
    try:
        entries = parse(data)
    except BaselineFileError as exc:
        raise BaselineFileError(exc.reason, where=f"{BASELINE_FILE} at {base}") from None
    return Baseline(entries, label_base(commit), "base", commit)


def write(root: Any, entries: Iterable[Entry]) -> Path:
    """Replace the working tree's ``.aegis/baseline.json`` with ``entries`` (atomically) and
    return its path. Raises BaselineFileError when the file or ``.aegis`` is a symlink."""
    workspace = Path(os.fspath(root))
    target = workspace / BASELINE_FILE
    if os.path.islink(workspace / AEGIS_DIRNAME) or os.path.islink(target):
        raise BaselineFileError("is a symlink: refusing to write through it")
    atomic_write_text(target, render(entries))
    return target


# ── Layer 1 evidence by file ─────────────────────────────────────────────────

def _norm(path: str, root: Any = None) -> str:
    """A target file as workspace-relative POSIX (an absolute path inside ``root`` made relative)."""
    if root is not None and os.path.isabs(path):
        try:
            path = os.path.relpath(path, os.fspath(root))
        except ValueError:  # another drive on Windows
            pass
    return posixpath.normpath(path.replace("\\", "/"))


def basename_groups(files: Sequence[str]) -> List[List[str]]:
    """``files`` (each once) split into groups, in order, so that no group holds two files
    with the same basename. call_graph and import_guard name their target by basename
    only; within a group a basename identifies the file."""
    groups: List[List[str]] = []
    names: List[set] = []
    for path in dict.fromkeys(files):
        base = posixpath.basename(path.replace("\\", "/"))
        for group, seen in zip(groups, names):
            if base not in seen:
                group.append(path)
                seen.add(base)
                break
        else:
            groups.append([path])
            names.append({base})
    return groups


def run_grouped(
    run: Callable[[List[str]], List[ToolEvidence]], files: Sequence[str], root: Any = None,
) -> List[Tuple[Optional[str], ToolEvidence]]:
    """Run Layer 1 (``run(group)``) on ``files`` one basename-distinct group at a time and
    pair each piece of evidence with the file it is about (workspace-relative POSIX), or
    None when it is about no checked file (a rule that cannot load)."""
    pairs: List[Tuple[Optional[str], ToolEvidence]] = []
    for group in basename_groups(files):
        by_path = {_norm(path, root): path for path in group}
        by_base: Dict[str, str] = {}
        for path in by_path:
            by_base[posixpath.basename(path)] = path
        for evidence in run(list(group)):
            target = evidence.target.replace("\\", "/")
            if evidence.tool.startswith("forbid_ast"):
                owner = target if target in by_path else None
            else:
                owner = target if target in by_path else by_base.get(target)
            pairs.append((owner, evidence))
    return pairs


# ── Findings ─────────────────────────────────────────────────────────────────

class Sources:
    """The text and syntax trees the findings are read from: the working tree, or the
    index (``staged``) when the pre-commit hook checks what a commit would record.
    ``reviewed`` as in ``runner.run_layer1``: which version of the gate rules was enforced."""

    def __init__(self, root: Any, staged: bool = False, reviewed: bool = True) -> None:
        self.root = Path(os.fspath(root))
        self.staged = staged
        self.reviewed = reviewed
        self._texts: Dict[str, Optional[str]] = {}
        self._lines: Dict[str, _Lines] = {}
        self._trees: Dict[str, Any] = {}
        self._sites: Dict[Tuple[str, str, str, str], List[int]] = {}
        self._index: Optional[Dict[str, str]] = None
        self._runner: Any = None
        self._rules: Any = None  # rule id -> the forbid_ast the gate enforced, once; False when unreadable

    def _staged_oid(self, path: str) -> Optional[str]:
        if self._index is None:
            self._index = {}
            res = gitsafe.run(["ls-files", "-s", "-z"], self.root)
            if res.returncode == 0:
                for record in res.stdout.split(b"\0"):
                    meta, sep, name = record.partition(b"\t")
                    parts = meta.split()
                    if sep and len(parts) == 3 and parts[2] == b"0" and parts[0] in (b"100644", b"100755"):
                        self._index[os.fsdecode(name)] = parts[1].decode("ascii")
        return self._index.get(path)

    def _read(self, path: str) -> Optional[bytes]:
        try:
            if self.staged:
                oid = self._staged_oid(path)
                return None if oid is None else gitsafe.read_object(self.root, oid, MAX_BYTES)
            full = self.root / path
            if not is_within(full, self.root, unresolvable=False) or os.path.getsize(full) > MAX_BYTES:
                return None
            return full.read_bytes()
        except (OSError, ValueError, gitsafe.GitError):
            return None

    def text(self, path: str) -> Optional[str]:
        """The decoded text of ``path`` (undecodable bytes replaced), or None when it cannot be read."""
        if path not in self._texts:
            data = self._read(path)
            self._texts[path] = None if data is None else data.decode("utf-8-sig", "replace")
        return self._texts[path]

    def lines(self, path: str) -> List[str]:
        text = self.text(path)
        return [] if text is None else split_lines(text)

    def _normalized(self, path: str) -> _Lines:
        if path not in self._lines:
            self._lines[path] = _Lines(self.lines(path))
        return self._lines[path]

    def line_text(self, path: str, number: int) -> str:
        return self._normalized(path).text(number)

    def occurrence(self, path: str, number: int) -> int:
        return self._normalized(path).index(number)

    def _ast(self, path: str) -> Any:
        if path in self._trees:
            return self._trees[path]
        from aegis_core.ast.policy import extract_normalized_ast
        from aegis_core.ast.runner import ASTDriverRunner

        tree = None
        try:
            if self.staged:
                text = self.text(path)
                if text is not None and path.endswith(".py"):
                    tree = extract_normalized_ast(path, code=text)
                elif text is not None:
                    self._runner = self._runner or ASTDriverRunner()
                    with tempfile.TemporaryDirectory(prefix="aegis-baseline-") as scratch:
                        copy = os.path.join(scratch, posixpath.basename(path))
                        with open(copy, "wb") as handle:
                            handle.write(text.encode("utf-8"))
                        tree = extract_normalized_ast(copy, workspace_root=self.root, ast_runner=self._runner,
                                                      confine_root=scratch)
            else:
                self._runner = self._runner or ASTDriverRunner()
                tree = extract_normalized_ast(str(self.root / path), workspace_root=self.root, ast_runner=self._runner)
        except Exception:  # a tree that cannot be read has no sites: the check stays failing
            tree = None
        self._trees[path] = tree
        return tree

    def _forbid_spec(self, rule_id: str) -> Optional[dict]:
        """The ``forbid_ast`` of ``rule_id`` as the gate enforced it: the runner's own discovery
        (the reviewed base version), never the working tree's or the index's copy, which the
        change under check can narrow to hide a new site. None when it is not enforced."""
        if self._rules is None:
            from aegis_core.verification import runner

            root = os.fspath(self.root)
            try:
                found, _broken = runner._discover_forbid_ast_rules(*((root,) if self.reviewed else (root, False)))
                self._rules = {rule.id: spec for rule, spec in found}
            except Exception:
                self._rules = False
        spec = self._rules.get(rule_id) if self._rules else None
        return spec if isinstance(spec, dict) else None

    def sites(self, path: str, kind: str, pattern: str, rule_id: str) -> List[int]:
        """The lines of ``path`` where the ``forbid_ast`` rule ``rule_id`` reports ``pattern`` as a
        ``call`` or ``import``: its whole spec on the full tree with the file's allow comments,
        as the gate evaluated it, so an allowed or benign site is never a finding. A decorator has
        no line, and a rule that cannot be loaded has no sites: the answer is empty."""
        key = (path, kind, pattern, rule_id)
        if key in self._sites:
            return self._sites[key]
        from aegis_core.ast.policy import evaluate_forbid_ast_structured

        spec, tree = self._forbid_spec(rule_id), self._ast(path)
        try:
            found = [] if spec is None or tree is None or kind == "decorator" else evaluate_forbid_ast_structured(
                tree, spec, rule_id=rule_id, source=self.text(path) or "")
        except Exception:
            found = []
        self._sites[key] = sorted({f["line"] for f in found if f["kind"] == f"{kind}s" and f["pattern"] == pattern
                                   and not f["unknown"] and f["override"] is None and f["line"] > 0})
        return self._sites[key]


_VIOLATION = re.compile(r"Forbidden (import|call|decorator) '(.+)' matched rule forbid_ast\.(?:imports|calls|decorators)")
_LINE_TOOLS = ("call_graph", "import_guard")


def _violations(detail: str) -> Optional[List[Tuple[str, str, str]]]:
    """(kind, pattern, message) for each violation a forbid_ast check reports; None when
    the detail says anything else (the check failed to run, not a violation)."""
    found: List[Tuple[str, str, str]] = []
    for part in detail.split("; "):
        match = _VIOLATION.fullmatch(part)
        if match is None:
            return None
        found.append((match.group(1), match.group(2), part))
    return found


def _findings_of(path: Optional[str], evidence: ToolEvidence, sources: Sources) -> Optional[List[Finding]]:
    """The findings of one failed check, or None when it cannot be baselined."""
    if path is None or sources.text(path) is None:
        return None
    found: List[Finding] = []
    if evidence.tool in _LINE_TOOLS:
        for number in sorted(set(evidence.lines)):
            found.append(Finding(evidence.tool, path, sources.line_text(path, number),
                                 sources.occurrence(path, number), number, evidence.detail))
    elif evidence.tool.startswith("forbid_ast:"):
        violations = _violations(evidence.detail)
        if violations is None:
            return None
        if len(violations) == 1 and violations[0][0] != "decorator" and evidence.lines:
            _, _, message = violations[0]
            for number in sorted(set(evidence.lines)):
                found.append(Finding(evidence.tool, path, sources.line_text(path, number),
                                     sources.occurrence(path, number), number, message))
        else:
            rule_id = evidence.tool.partition(":")[2]
            covered: set = set()
            for kind, pattern, message in violations:
                lines = sources.sites(path, kind, pattern, rule_id)
                if not lines:
                    return None
                covered.update(lines)
                for number in lines:
                    found.append(Finding(evidence.tool, path, sources.line_text(path, number),
                                         sources.occurrence(path, number), number, message))
            if covered != set(evidence.lines):  # sites the gate did not report, or a reported site left out
                return None
    return found or None


@dataclass(frozen=True)
class Collected:
    """``findings``: every baselinable finding. ``by_evidence``: for each (path, evidence)
    pair, its findings; None when the pair passed or cannot be baselined. ``blocked``: the
    failed checks that cannot be baselined."""

    findings: Tuple[Finding, ...]
    by_evidence: Tuple[Optional[Tuple[Finding, ...]], ...]
    blocked: Tuple[ToolEvidence, ...]


def collect(pairs: Sequence[Tuple[Optional[str], ToolEvidence]], sources: Sources) -> Collected:
    findings: List[Finding] = []
    per: List[Optional[Tuple[Finding, ...]]] = []
    blocked: List[ToolEvidence] = []
    for path, evidence in pairs:
        if evidence.verdict:
            per.append(None)
            continue
        found = _findings_of(path, evidence, sources)
        if found is None:
            per.append(None)
            blocked.append(evidence)
            continue
        per.append(tuple(found))
        findings.extend(found)
    return Collected(tuple(findings), tuple(per), tuple(blocked))


@dataclass(frozen=True)
class Applied:
    """A baseline applied to Layer 1 evidence. ``effective`` is the evidence as the gate
    sees it: a check whose findings the baseline all holds passes, in the same position.
    ``new`` are findings the baseline does not hold, ``blocked`` the failed checks that
    cannot be baselined."""

    effective: Tuple[ToolEvidence, ...]
    grandfathered: Tuple[Finding, ...]
    new: Tuple[Finding, ...]
    blocked: Tuple[ToolEvidence, ...]

    @property
    def passed(self) -> bool:
        return all(e.verdict for e in self.effective)


def apply(pairs: Sequence[Tuple[Optional[str], ToolEvidence]], sources: Sources, held: Baseline) -> Applied:
    """Judge ``pairs`` against ``held``: a finding is grandfathered only when the baseline
    holds an entry equal to it in rule, path and fingerprint."""
    collected = collect(pairs, sources)
    effective: List[ToolEvidence] = []
    grandfathered: List[Finding] = []
    new: List[Finding] = []
    for (_path, evidence), found in zip(pairs, collected.by_evidence):
        if found is None:  # passing, or failing and not baselinable
            effective.append(evidence)
            continue
        old = [f for f in found if f.entry in held.entries]
        fresh = [f for f in found if f.entry not in held.entries]
        grandfathered.extend(old)
        new.extend(fresh)
        if not fresh:
            effective.append(ToolEvidence(
                tool=evidence.tool, target=evidence.target, verdict=True, lines=list(evidence.lines),
                detail=f"{evidence.detail} [grandfathered by the baseline: {len(old)} finding(s)]"))
        elif old:
            shown = "; ".join(f"line {f.line}: {f.text}" for f in fresh)
            effective.append(ToolEvidence(
                tool=evidence.tool, target=evidence.target, verdict=False, lines=list(evidence.lines),
                detail=f"{evidence.detail} (new: {shown}; {len(old)} grandfathered by the baseline)"))
        else:
            effective.append(evidence)
    return Applied(tuple(effective), tuple(grandfathered), tuple(new), collected.blocked)


# ── The files a whole-workspace mode looks at ────────────────────────────────

def list_files(root: Any) -> Tuple[List[str], str]:
    """The files of the workspace as workspace-relative POSIX paths, sorted, and where the
    list came from (``git``: tracked and untracked files git does not ignore, which exist
    as regular files; ``walk``: outside git, every file below ``root`` except the build
    and vendor directories). Symbolic links are left out: they hold no content of their own."""
    base = Path(os.fspath(root))
    listed = gitsafe.list_files(base)
    if listed is not None:
        found = [p for p in listed if os.path.isfile(base / p) and not os.path.islink(base / p)]
        return sorted(set(found)), "git"
    from aegis_core.ast.detect import _SKIP_DIRS  # the one list of directories no scan descends into

    walked: List[str] = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.isfile(full) and not os.path.islink(full):
                walked.append(os.path.relpath(full, base).replace(os.sep, "/"))
    return sorted(walked), "walk"


def checkable(root: Any, files: Iterable[str]) -> List[str]:
    """The ``files`` Layer 1 has something to say about: Python, and every extension an AST
    driver is enabled for in this workspace."""
    from aegis_core.ast.runner import ASTDriverRunner

    registry = ASTDriverRunner().registry
    known: Dict[str, bool] = {".py": True}
    out: List[str] = []
    for path in files:
        ext = posixpath.splitext(path)[1].lower()
        if ext not in known:
            try:
                known[ext] = bool(ext) and bool(registry.resolve_driver(ext, workspace_root=os.fspath(root)))
            except Exception:  # a driver that cannot even be planned: let Layer 1 report it
                known[ext] = True
        if known[ext]:
            out.append(path)
    return out


def run_fast(root: Any, files: Sequence[str], *, reviewed: bool = True, git_root: Optional[str] = None,
             diff_base: Optional[str] = None) -> Tuple[List[Tuple[Optional[str], ToolEvidence]], Sources]:
    """Layer 1 as ``aegis check`` runs it by default (no model, no mutation testing) on
    ``files`` of the working tree, each piece of evidence paired with its file. ``reviewed``,
    ``git_root`` (the history of an exported tree) and ``diff_base`` as in ``runner.run_layer1``."""
    from aegis_core.verification import runner

    base = os.fspath(root)
    pairs = run_grouped(
        lambda group: runner.run_layer1(changed_files=list(group), repo_root=base, fast_mode=True, reviewed=reviewed,
                                        git_root=git_root, diff_base=diff_base),
        files, root=base)
    return pairs, Sources(base, reviewed=reviewed)
