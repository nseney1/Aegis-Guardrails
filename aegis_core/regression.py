"""Regression discipline: git is the registry.

A pull request is judged once against its head: changed test files present at the head run on head
and on the merge base with the head's tests overlaid. Each affected language executes at most once
per snapshot, with a shared native test-command deadline. A user-scoped global command takes
precedence and executes once per snapshot. Metadata preparation has its own bounded tool probes.
A Python test id ``classname::name`` belongs to test file ``F`` when its classname is
``F``'s dotted path or starts with it and a dot; a collection error names the dotted path. An id is
fail-to-pass when it passed at head and failed on base, or its module failed collection on base. A fix
commit passes when one of its own test files holds such an id and none of them failed at head (a
suite-level error on the head run fails every commit). Native identities retain their package,
target or file namespaces; infrastructure errors never supply failed test identities.
"""
from __future__ import annotations

from dataclasses import dataclass
import functools
import os
from pathlib import Path
import posixpath
import re
import shutil
import tempfile
import time
from typing import Any, Callable, Dict, Iterable, List, NamedTuple, Optional, Sequence, Set, Tuple

from aegis_core import approval_shape, gitsafe, governance, human_gate, match, testexec
from aegis_core.errors import AegisError
from aegis_core.rules import workspace_root
from aegis_core.verification.regression_commands import run_configured_snapshot
from aegis_core.verification.regression_identity import test_language
from aegis_core.verification.regression_languages import (
    UNVERIFIED_CODES as _NATIVE_UNVERIFIED_CODES,
    language_evidence,
    run_native_regressions,
)

__all__ = ["RegressionError", "check_ci_regressions", "is_source_file"]

SCHEMA = "aegis.regression/v1"
DEFAULT_TIER = "warning"
DEFAULT_TIMEOUT_S = 120.0
_GIT_TIMEOUT_S = 60.0
# Diagnostic content only: fail closed before loading more than this total per report.
_REFUSAL_READ_LIMIT = 16 * 1024 * 1024
_REFUSAL_TARGET = re.compile(
    r"^[ \t]*Aegis-Exempt-Test:[ \t]*([0-9a-f]{40}(?:[0-9a-f]{24})?)[ \t]+", re.I | re.M)
EXEMPT_SCOPES = frozenset({"ci", "build", "docs", "deps", "release", "chore", "tests"})
_DOC_DIRS = frozenset({"docs", "doc"})
_DOC_EXTENSIONS = frozenset({".md", ".rst", ".txt", ".adoc", ".html", ".pdf", ".png", ".svg", ".jpg", ".jpeg", ".gif"})
_DOC_TEXT_EXTENSIONS = frozenset({"", ".md", ".rst", ".txt", ".adoc"})
_DOC_BASENAMES = frozenset({
    "readme", "changelog", "changes", "history", "license", "copying",
    "authors", "contributors", "code_of_conduct", "security", "notice", "patents",
})
# Finding codes that say a check could not run, not that a fix failed.
UNVERIFIED_CODES = _NATIVE_UNVERIFIED_CODES
_CONFIG_EXTENSIONS = frozenset({".toml", ".yaml", ".yml", ".json", ".ini", ".cfg", ".conf", ".lock", ".env", ".pth"})
_CONFIG_BASENAMES = frozenset({
    "makefile", "dockerfile", "containerfile", "justfile", "vagrantfile", "procfile", "manifest.in",
    "requirements.txt", "requirements-dev.txt", "pipfile", "tox.ini", "setup.cfg", "pyproject.toml",
    "pytest.ini", ".pytest.ini", "pytest.toml", ".pytest.toml", "allowed_signers", "codeowners", "conftest.py", "sitecustomize.py",
})
_CONVENTIONAL_RE = re.compile(r"\A([a-zA-Z]+)(?:\(([^)]*)\))?(!)?:\s*(.*)\Z")


class RegressionError(AegisError):
    """The commit range, repository trees or test command cannot be used."""


def is_test_file(path: str) -> bool:
    return bool(isinstance(path, str) and path and (match.is_test_path(path) or test_language(path) == "ts"))


def is_python_test_file(path: str) -> bool:
    if not isinstance(path, str) or not path:
        return False
    rel = match.normalize_path(path)
    return match.is_test_path(rel) and rel.endswith(".py") and posixpath.basename(rel) not in ("conftest.py", "__init__.py")


def is_doc_file(path: str) -> bool:
    if not isinstance(path, str) or not path:
        return False
    parts = [p.lower() for p in match.normalize_path(path).split("/") if p]
    if not parts:
        return False
    stem, ext = posixpath.splitext(parts[-1])
    # A document name only counts with a text extension (src/security.py is code), and only a
    # top-level docs/ or doc/ directory holds documentation (src/doc/parser.py is code).
    return ((len(parts) > 1 and parts[0] in _DOC_DIRS) or (stem in _DOC_BASENAMES and ext in _DOC_TEXT_EXTENSIONS)
            or ext in _DOC_EXTENSIONS)


def is_config_file(path: str) -> bool:
    if not isinstance(path, str) or not path:
        return False
    rel = match.normalize_path(path)
    parts = [p for p in rel.split("/") if p]
    if not parts:
        return False
    base = parts[-1].lower()
    return (
        governance.category_of(rel) is not None
        or any(p.startswith(".") for p in parts)
        or base in _CONFIG_BASENAMES
        or posixpath.splitext(base)[1] in _CONFIG_EXTENSIONS
    )


def is_source_file(path: str) -> bool:
    return bool(
        isinstance(path, str)
        and path
        and not is_test_file(path)
        and not is_doc_file(path)
        and not is_config_file(path)
    )


def parse_fix_subject(subject: str) -> Tuple[bool, Optional[str]]:
    first_line = (subject or "").splitlines()[0].strip() if subject else ""
    found = _CONVENTIONAL_RE.match(first_line)
    if not found:
        return False, None
    kind = found.group(1).strip().lower()
    raw_scope = found.group(2)
    scope = raw_scope.strip().lower() if raw_scope is not None and raw_scope.strip() else None
    return (kind == "fix" and scope not in EXEMPT_SCOPES), scope


def is_fix_commit(subject: str, fixes_trailers: Sequence[str], changed_files: Sequence[str]) -> bool:
    fix_subject, scope = parse_fix_subject(subject)
    has_fix_signal = fix_subject or any(str(t).strip() for t in fixes_trailers)
    return scope not in EXEMPT_SCOPES and has_fix_signal and any(is_source_file(p) for p in changed_files)


@dataclass(frozen=True)
class RegressionFinding:
    code: str
    commit: str
    path: str
    message: str
    no_test_reason: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "code": self.code,
            "commit": self.commit,
            "path": self.path,
            "message": self.message,
        }
        if self.no_test_reason is not None:
            out["no_test_reason"] = self.no_test_reason
        return out


@dataclass(frozen=True)
class CommitRegression:
    commit: str
    subject: str
    status: str
    reason: str
    fail_to_pass_tests: Tuple[str, ...] = ()
    no_test_reason: Optional[str] = None
    approval: Optional[Any] = None
    exemption_code: Optional[str] = None
    languages: Tuple[Any, ...] = ()

    @property
    def passed(self) -> bool:
        return self.status in ("passed", "exempted", "unverifiable")

    def as_dict(self, workspace: Any = None) -> Dict[str, Any]:
        result = {
            "commit": self.commit,
            "subject": self.subject,
            "status": self.status,
            "reason": self.reason,
            "fail_to_pass_tests": list(self.fail_to_pass_tests),
            "no_test_reason": self.no_test_reason,
            "approval": None if self.approval is None else self.approval.as_dict(workspace),
            "exemption_code": self.exemption_code,
        }
        if self.languages:
            result["languages"] = list(self.languages)
        return result


class UntestedChange(NamedTuple):
    commit: str
    subject: str
    source_files: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "commit": self.commit,
            "subject": self.subject,
            "source_files": list(self.source_files),
        }


@dataclass(frozen=True)
class RegressionReport:
    tier: str = DEFAULT_TIER
    commits: Tuple[CommitRegression, ...] = ()
    findings: Tuple[RegressionFinding, ...] = ()
    untested_changes: Tuple[UntestedChange, ...] = ()

    @property
    def total_fix_commits(self) -> int:
        return len(self.commits)

    @property
    def exempted_count(self) -> int:
        return sum(1 for c in self.commits if c.status == "exempted")

    @property
    def exemption_rate(self) -> float:
        return round(self.exempted_count / len(self.commits), 4) if self.commits else 0.0

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.commits)

    @property
    def blocking(self) -> bool:
        return self.tier == "gate" and not self.passed

    @property
    def status(self) -> str:
        if self.passed:
            return "pass"
        return "fail" if self.tier == "gate" else "warning"

    def as_dict(self, workspace: Any = None) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "tier": self.tier,
            "status": self.status,
            "passed": self.passed,
            "blocking": self.blocking,
            "total_fix_commits": self.total_fix_commits,
            "exempted_count": self.exempted_count,
            "exemption_rate": self.exemption_rate,
            "commits": [c.as_dict(workspace) for c in self.commits],
            "findings": [f.as_dict() for f in self.findings],
            "untested_changes": [u.as_dict() for u in self.untested_changes],
        }


def _tree_blobs(cwd: str, commit: str) -> Dict[str, Tuple[str, str]]:
    return gitsafe.tree_blobs(cwd, commit, timeout=_GIT_TIMEOUT_S)


class _CommitMeta(NamedTuple):
    oid: str
    subject: str
    fixes: Tuple[str, ...]
    no_test_reason: Optional[str]
    changed_files: Tuple[str, ...]
    present_files: Tuple[str, ...]


# rev-list prints "commit <oid>" before each record and a newline after it, both absorbed into the first
# field. rev-list --format, unlike git log, never verifies a signature (no gpg.program runs). Only the
# trailer block is read (spec §3 T5): a Fixes: or Aegis-No-Test: line in the prose above it is prose.
_META_FORMAT = "%H%x00%s%x00%(trailers:key=Fixes,valueonly)%x00%(trailers:key=Aegis-No-Test,valueonly)%x00"
_META_FIELDS = 4
_OID_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_STATUS_RE = re.compile(rb"[A-Z]")


def _paths_by_commit(cwd: str, oids: Sequence[str]) -> Dict[str, Tuple[List[str], List[str]]]:
    """(changed, present) paths per commit from one ``diff-tree --stdin`` (an empty diff is absent). Read
    by position: an oid, then (status, path) pairs (no rename detection, so a move is a D and an A); a
    token in a path position is a path even if it looks like an oid."""
    tokens = gitsafe.run_checked(["diff-tree", "--stdin", "-r", "-z", "--name-status", "--no-renames", "--root"], cwd,
                                 timeout=_GIT_TIMEOUT_S, stdin="".join(f"{oid}\n" for oid in oids).encode("ascii")
                                 ).stdout.split(b"\0")
    if tokens[-1]:
        raise RegressionError("git diff-tree output ended inside a record")
    wanted: Set[str] = set(oids)
    out: Dict[str, Tuple[Dict[str, None], Dict[str, None]]] = {}
    current: Optional[Tuple[Dict[str, None], Dict[str, None]]] = None
    index = 0
    while index < len(tokens) - 1:
        token, name = tokens[index], tokens[index + 1]
        if current is not None and _STATUS_RE.fullmatch(token) and name:
            path = match.normalize_path(os.fsdecode(name))
            if path:
                current[0][path] = None
                if token != b"D":
                    current[1][path] = None
            index += 2
        elif token.decode("ascii", "replace") in wanted:
            current = out.setdefault(token.decode("ascii"), ({}, {}))
            index += 1
        else:
            raise RegressionError("git diff-tree printed a record it does not write")
    return {oid: (list(changed), list(present)) for oid, (changed, present) in out.items()}


def _commits_meta(cwd: str, merge_commit: str, head_commit: str) -> List[_CommitMeta]:
    """The non-merge commits of ``merge_commit..head_commit``, oldest first, in two git calls."""
    fields = gitsafe.run_checked(["rev-list", "--reverse", "--no-merges", f"--format={_META_FORMAT}",
                                  f"{merge_commit}..{head_commit}"], cwd, timeout=_GIT_TIMEOUT_S
                                 ).stdout.decode("utf-8", "replace").split("\0")
    records = [fields[i:i + _META_FIELDS] for i in range(0, len(fields) - 1, _META_FIELDS)]
    oids = [(r[0].split() or [""])[-1] for r in records]
    if len(fields) % _META_FIELDS != 1 or fields[-1].strip() or not all(_OID_RE.fullmatch(o) for o in oids):
        raise RegressionError("git rev-list printed a record it does not write")
    paths = _paths_by_commit(cwd, oids) if oids else {}
    metas: List[_CommitMeta] = []
    for oid, (_oid, subject, fixes, no_test) in zip(oids, records):
        reasons = [ln.strip() for ln in no_test.splitlines() if ln.strip()]
        changed, present = paths.get(oid, ([], []))
        metas.append(_CommitMeta(oid, subject.strip(), tuple(dict.fromkeys(f.strip() for f in fixes.splitlines() if f.strip())),
                                 reasons[0] if reasons else None, tuple(changed), tuple(present)))
    return metas


def _resolve_commit_exemption(meta: _CommitMeta, find: Callable[[str], Optional[human_gate.Approval]]) -> Tuple[Optional[human_gate.Approval], Optional[str]]:
    """(the valid exemption, None), or (None, the code of a rejected one naming this commit)."""
    try:
        found = find(meta.oid)
    except (human_gate.HumanGateError, gitsafe.GitError):
        return None, None
    return (found, None) if found is None or found.valid else (None, found.code)


def _diagnostic_object_ids(raw: bytes) -> List[str]:
    # Bound before decoding or splitting, including a possible final newline.
    if len(raw) > human_gate.MAX_SCANNED_COMMITS * 65:
        raise gitsafe.GitError("exemption diagnostic index exceeds its limit")
    ids = raw.decode("ascii", "replace").splitlines()
    if (len(ids) > human_gate.MAX_SCANNED_COMMITS or len(set(ids)) != len(ids)
            or any(_OID_RE.fullmatch(oid) is None for oid in ids)):
        raise gitsafe.GitError("exemption diagnostic index contains an invalid object id")
    return ids


def _diagnostic_refusal_verdicts(ids: List[str], run: Callable[..., Any]) -> Dict[Tuple[str, str], human_gate.Approval]:
    """Read each candidate once; memoise bounds refusals per (approval oid, target oid).

    Bounded-message refusals are already handled by normal discovery. This index only
    recovers the public bounds_refusal codes it skips, and cannot grant approval.
    """
    if not ids:
        return {}
    sizes = []
    total = 0
    for oid in ids:
        described = run(["cat-file", "-s", oid]).stdout
        if len(described) > 21:
            raise gitsafe.GitError("exemption diagnostic object size is invalid")
        size = described.rstrip(b"\n")
        if not size or len(size) > 20 or not size.isdigit():
            raise gitsafe.GitError("exemption diagnostic object size is invalid")
        count = int(size)
        total += count
        if total > _REFUSAL_READ_LIMIT:
            raise gitsafe.GitError("exemption diagnostic content exceeds its report limit")
        sizes.append(count)
    verdicts: Dict[Tuple[str, str], human_gate.Approval] = {}
    for oid, size in zip(ids, sizes):
        raw = run(["cat-file", "commit", oid]).stdout
        if len(raw) != size:
            raise gitsafe.GitError("exemption diagnostic object size changed")
        message = raw.partition(b"\n\n")[2].decode("utf-8", "replace")
        if refusal := approval_shape.bounds_refusal(message):
            verdict = human_gate.Approval(False, refusal[0], refusal[1], oid)
            for match in _REFUSAL_TARGET.finditer(message):
                target = match.group(1).lower()
                if target != oid:
                    key = (oid, target)
                    if key not in verdicts and len(verdicts) >= human_gate.MAX_SCANNED_COMMITS ** 2:
                        raise gitsafe.GitError("exemption diagnostic verdict index exceeds its limit")
                    verdicts[key] = verdict
        del raw, message
    return verdicts


def _refused_exemption_finder(root: str, head: str,
                             merge_commit: str) -> Callable[[str, Optional[human_gate.Approval]], Optional[human_gate.Approval]]:
    """One candidate filter and one read per candidate under a shared diagnostic deadline."""
    deadline = time.monotonic() + _GIT_TIMEOUT_S

    def remaining() -> float:
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise gitsafe.GitError("exemption diagnostic deadline expired")
        return seconds

    def run(args: List[str], *, stdin: Optional[bytes] = None) -> Any:
        result = gitsafe.run_checked(args, root, timeout=remaining(), stdin=stdin)
        remaining()
        return result

    window = _diagnostic_object_ids(run(
        ["log", "--no-patch", "--no-show-signature", "--no-notes", "--format=%H",
         f"--max-count={human_gate.MAX_SCANNED_COMMITS}", f"{merge_commit}..{head}"]).stdout)
    request = "".join(f"{oid}\n" for oid in window).encode("ascii")
    ids = _diagnostic_object_ids(run(
        ["log", "--no-patch", "--no-show-signature", "--no-notes", "--format=%H", "--no-walk=unsorted",
         "--regexp-ignore-case", "--extended-regexp", "--grep=^[[:blank:]]*Aegis-Exempt-Test:", "--stdin"],
        stdin=request).stdout) if window else []
    if not set(ids).issubset(window):
        raise gitsafe.GitError("exemption diagnostic candidate is outside the window")
    verdicts = _diagnostic_refusal_verdicts(ids, run)

    @functools.lru_cache(maxsize=human_gate.MAX_SCANNED_COMMITS)
    def find(fix: str, prior: Optional[human_gate.Approval]) -> Optional[human_gate.Approval]:
        if _OID_RE.fullmatch(fix) is None:
            return None
        for oid in window:
            if prior is not None and oid == prior.commit:
                return prior
            verdict = verdicts.get((oid, fix))
            if verdict is not None:
                return verdict
        return prior

    return find


def _report_exemption_finder(root: str, head: str, base: str,
                            merge_commit: str) -> Callable[[str], Optional[human_gate.Approval]]:
    """Latch discovery and diagnostic failures independently; preserve per-fix verification."""
    primary_failed = False
    diagnostic_failed = False

    @functools.lru_cache(maxsize=1)
    def primary() -> Callable[[str], Optional[human_gate.Approval]]:
        return human_gate.exemption_finder(root, head, base)

    @functools.lru_cache(maxsize=1)
    def diagnostic() -> Callable[[str, Optional[human_gate.Approval]], Optional[human_gate.Approval]]:
        return _refused_exemption_finder(root, head, merge_commit)

    def find(fix: str) -> Optional[human_gate.Approval]:
        nonlocal primary_failed, diagnostic_failed
        if primary_failed:
            return None
        try:
            finder = primary()
        except (human_gate.HumanGateError, gitsafe.GitError):
            primary_failed = True
            return None
        found = finder(fix)
        if (found is not None and found.valid) or diagnostic_failed:
            return found
        try:
            return diagnostic()(fix, found)
        except (human_gate.HumanGateError, gitsafe.GitError):
            diagnostic_failed = True
            return found

    return find


def _run_pr_level(root: str, workspace: Path, merge_commit: str, head_commit: str, tests: Iterable[str],
                  timeout: float, progress: Callable[[str], None],
                  command: Optional[Sequence[str]] = None) -> Optional[Tuple[Any, Any]]:
    """(head run, base run) of ``testexec.run_pytest_snapshot`` for the ``tests`` present at head, on the
    head and on the merge base with the head's copies of those tests overlaid; None when none is present."""
    head_tree = _tree_blobs(root, head_commit)
    present = sorted(p for p in set(tests) if p in head_tree)
    if not present and command is None:
        return None
    blobs = gitsafe.read_blobs(root, {head_tree[p][1] for p in present}, timeout=_GIT_TIMEOUT_S)
    overlay = {p: blobs[head_tree[p][1]] for p in present if head_tree[p][1] in blobs}
    scratch = Path(tempfile.mkdtemp(prefix="aegis-regression-"))
    try:
        os.chmod(scratch, 0o700)
        runs = []
        for k, (name, label, commit, layer) in enumerate(
                (("head", "the pull request head", head_commit, None), ("base", "the merge base", merge_commit, overlay)), 1):
            gitsafe.export_tree(root, commit, scratch / f"{name}_snap", overlay=layer, timeout=_GIT_TIMEOUT_S)
            progress(f"Regression test run {k} of 2: pytest on {label} {commit[:10]} ({len(present)} test file(s))")
            started = time.monotonic()
            if command is None:
                runs.append(testexec.run_pytest_snapshot(scratch / f"{name}_snap", present, workspace, scratch / f"{name}_run",
                                                         timeout))
            else:
                selected = [file for file in present if is_python_test_file(file)]
                runs.append(run_configured_snapshot(command, scratch / f"{name}_snap", selected, workspace,
                                                     scratch / f"{name}_run", timeout))
            outcome = "timed out" if runs[-1].timed_out else f"pytest exit {runs[-1].exit_code}"
            progress(f"Regression test run {k} of 2: {outcome} after {time.monotonic() - started:.1f}s")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return runs[0], runs[1]


_DETAILS = {
    "timeout": ": the test run timed out", "no_test_changes": " modifies source without adding or updating a test",
    "no_tests_collected": ": no tests were collected from the changed test files",
    "failed_on_head": ": the changed test files failed or errored on the pull request head",
    "passed_on_base": ": no test failed on base and passed on head (tests passed on base too)",
}


class _ModulePrefixes:
    """A radix trie with O(modules) nodes and compressed substring edge labels."""

    def __init__(self, modules: Iterable[str]):
        self.root: Dict[str, Any] = {}
        for module in modules:
            self._add(module)
        # Construction uses source spans so repeated edge splits never copy a long
        # suffix repeatedly. Materialize each final label only once, without recursion.
        pending = [self.root]
        while pending:
            for edge in pending.pop().values():
                text, start, end, value, children = edge
                edge[:] = [text[start:end], value, children]
                if children:
                    pending.append(children)

    def _add(self, module: str) -> None:
        children, start = self.root, 0
        while True:
            end = module.find(".", start)
            end = len(module) if end < 0 else end
            key = module[start:end]
            edge = children.get(key)
            if edge is None:
                children[key] = [module, start, len(module), module, {}]
                return
            text, left, right, value, descendants = edge
            here, there = end, left + end - start
            while here < len(module) and there < right:
                next_here = module.find(".", here + 1)
                next_here = len(module) if next_here < 0 else next_here
                next_there = text.find(".", there + 1, right)
                next_there = right if next_there < 0 else next_there
                if next_here - here != next_there - there or not module.startswith(text[there + 1:next_there], here + 1):
                    break
                here, there = next_here, next_there
            if there == right:
                if here == len(module):
                    edge[3] = module
                    return
                children, start = descendants, here + 1
                continue
            split = there + 1
            dot = text.find(".", split, right)
            children = {text[split:right if dot < 0 else dot]: [text, split, right, value, descendants]}
            edge[2:] = [there, module if here == len(module) else None, children]
            if here == len(module):
                return
            start = here + 1

    def matches(self, classname: str) -> Iterable[str]:
        children, start = self.root, 0
        while children:
            if len(children) == 1:
                label, value, children = next(iter(children.values()))
            else:
                end = classname.find(".", start)
                edge = children.get(classname[start:len(classname) if end < 0 else end])
                if edge is None:
                    return
                label, value, children = edge
            if not classname.startswith(label, start):
                return
            start += len(label)
            if start < len(classname) and classname[start] != ".":
                return
            if value is not None:
                yield value
            if start == len(classname):
                return
            start += 1


class _PythonResults:
    """Attribute shared snapshot identities only to the wanted test modules."""

    def __init__(self, head: Any, base: Any, wanted: Set[str]):
        self.head, self.base = head, base
        self.suite_error = any(error.startswith("<suite:") for error in head.collection_errors)
        self.passed: Dict[str, Set[str]] = {}
        self.failed: Dict[str, Set[str]] = {}
        self.f2p: Dict[str, Set[str]] = {}
        # Radix nodes are O(errors + wanted modules), with substring labels; the
        # classname cache holds O(unique classnames + actual wanted associations).
        modules, errors = _ModulePrefixes(wanted), None
        attribution: Dict[str, Tuple[Set[str], bool]] = {}
        for ids, index in ((head.passed_ids, self.passed), (head.failed_ids, self.failed)):
            for identity in ids:
                module = identity.partition("::")[0]
                if module not in attribution:
                    prefixes = set(modules.matches(module))
                    if prefixes and errors is None:
                        errors = _ModulePrefixes(base.collection_errors)
                    collection_failed = bool(prefixes) and next(iter(errors.matches(module)), None) is not None
                    attribution[module] = prefixes, collection_failed
                prefixes, collection_failed = attribution[module]
                if not prefixes:
                    continue
                f2p = index is self.passed and (identity in base.failed_ids or collection_failed)
                for prefix in prefixes:
                    index.setdefault(prefix, set()).add(identity)
                    if f2p:
                        self.f2p.setdefault(prefix, set()).add(identity)

    @staticmethod
    def select(index: Dict[str, Set[str]], modules: Set[str]) -> Set[str]:
        return set().union(*(index.get(module, ()) for module in modules))


def _judge(test_files: Sequence[str], results: _PythonResults) -> Tuple[str, Tuple[str, ...]]:
    """(reason, fail-to-pass ids) of one commit's Python test files in the head and base runs."""
    head, base = results.head, results.base
    for run in (head, base):
        if getattr(run, "reason", None):
            return ("timeout" if head.timed_out or base.timed_out else run.reason), ()
    modules = {p[:-3].replace("/", ".") for p in test_files}
    passed = results.select(results.passed, modules)
    failed = results.select(results.failed, modules)
    f2p = tuple(sorted(results.select(results.f2p, modules)))
    seen = passed | failed | (modules & head.collection_errors)
    bad = bool(failed or modules & head.collection_errors or results.suite_error)
    if head.timed_out or base.timed_out:
        reason = "timeout"
    else:
        reason = "ok" if f2p and not bad else "failed_on_head" if seen and bad else "passed_on_base" if seen else "no_tests_collected"
    return reason, f2p


def _evaluate_fix_commit(meta: _CommitMeta, find: Callable[[str], Optional[human_gate.Approval]],
                         runs: Optional[_PythonResults], native: Optional[Dict[str, Any]] = None,
                         configured: bool = False) -> Tuple[CommitRegression, Optional[RegressionFinding]]:
    source_files = tuple(p for p in meta.changed_files if is_source_file(p))
    test_files = tuple(p for p in meta.present_files if is_python_test_file(p))
    other_tests = tuple(p for p in meta.present_files if test_language(p) is not None)
    rows = []
    for language, outcome in (native or {}).items():
        mine = tuple(p for p in other_tests if test_language(p) == language)
        if mine:
            row = language_evidence(outcome, mine)
            if row["reason"] != "no_test_changes":
                rows.append(row)
    reasons, f2p = [], ()
    if configured and not test_files and runs and getattr(runs.head, "reason", None):
        reasons.append(runs.head.reason)
    if test_files:
        py_reason, f2p = ("no_tests_collected", ()) if runs is None else _judge(test_files, runs)
        reasons.append(py_reason)
    if configured and other_tests:
        reasons.append("tests_runner_unsupported")
    reasons.extend(row["reason"] for row in rows)
    reason = next((value for value in reasons if value != "ok"), "ok" if reasons else "no_test_changes")
    if reason == "ok":
        return CommitRegression(meta.oid, meta.subject, "passed", "ok", f2p, meta.no_test_reason, languages=tuple(rows)), None
    approval, rejected = _resolve_commit_exemption(meta, find)
    nt_note = f" (its test exemption was rejected: {rejected})" if rejected else ""
    if meta.no_test_reason:
        nt_note += f" (Aegis-No-Test: {meta.no_test_reason!r} is an explanation only; exemption requires human_gate approval)"
    named = f"fix commit {meta.oid[:10]} ({meta.subject})"
    if reason in UNVERIFIED_CODES:
        return (CommitRegression(meta.oid, meta.subject, "unverifiable", reason, f2p, meta.no_test_reason,
                                 exemption_code=rejected, languages=tuple(rows)),
                RegressionFinding(reason, meta.oid, (other_tests or test_files or source_files or ("",))[0],
                                  f"{named}: regression tests unverified ({reason}){nt_note}", meta.no_test_reason))
    if approval is not None and approval.valid:
        return CommitRegression(meta.oid, meta.subject, "exempted", "exempted", f2p, meta.no_test_reason, approval, languages=tuple(rows)), None
    return (CommitRegression(meta.oid, meta.subject, "failed", reason, f2p, meta.no_test_reason, exemption_code=rejected, languages=tuple(rows)),
            RegressionFinding(reason, meta.oid, (test_files or other_tests or source_files or ("",))[0], f"{named}{_DETAILS[reason]}{nt_note}",
                              meta.no_test_reason))


@gitsafe.scrubbed()
def check_ci_regressions(
    workspace: Any,
    base: str,
    head: str = "HEAD",
    *,
    timeout: float = DEFAULT_TIMEOUT_S,
    progress: Optional[Callable[[str], None]] = None,
) -> RegressionReport:
    """Judge each fix's changed tests through a shared head/base pair per language.

    ``progress`` reports test execution on stderr through ``aegis check --ci``.
    """
    root = workspace_root(workspace)
    workspace_path = Path(root).resolve()
    base_commit = gitsafe.resolve_commit(root, base)
    head_commit = gitsafe.resolve_commit(root, head)
    if not base_commit:
        raise RegressionError(f"cannot resolve the base {base!r} to a commit")
    if not head_commit:
        raise RegressionError(f"cannot resolve the head {head!r} to a commit")
    merge_commit = gitsafe.merge_base(root, base_commit, head_commit)
    if not merge_commit:
        raise RegressionError(f"{base!r} and {head!r} share no history (fetch with fetch-depth: 0)")

    fix_metas: List[_CommitMeta] = []
    untested: List[UntestedChange] = []
    for meta in _commits_meta(root, merge_commit, head_commit):
        if is_fix_commit(meta.subject, meta.fixes, meta.changed_files):
            fix_metas.append(meta)
        else:
            src = tuple(p for p in meta.changed_files if is_source_file(p))
            if src and not any(is_test_file(p) for p in meta.changed_files):
                untested.append(UntestedChange(meta.oid, meta.subject, src))
    # The user-authorized global command takes precedence and runs just once per snapshot.
    try:
        command = testexec.user_test_command(workspace_path)
    except ValueError:
        raise RegressionError("invalid tests.command") from None
    judged = [p for m in fix_metas for p in m.present_files if is_python_test_file(p)]
    groups = {}
    for meta in fix_metas:
        for file in meta.present_files:
            language = test_language(file)
            if language is not None:
                groups.setdefault(language, []).append(file)
    say = progress or (lambda _line: None)
    selected = judged + [file for files in groups.values() for file in files if is_test_file(file)] if command else judged
    runs = (_run_pr_level(root, workspace_path, merge_commit, head_commit, selected, timeout, say, command)
            if selected else None)
    native = (run_native_regressions(root, workspace_path, merge_commit, head_commit, groups, say,
                                    timeout=timeout if timeout != DEFAULT_TIMEOUT_S else None) if groups and command is None else {})
    find_exemption = _report_exemption_finder(root, head_commit, base_commit, merge_commit)

    wanted = {path[:-3].replace("/", ".") for path in judged}
    indexed = _PythonResults(*runs, wanted) if runs is not None else None
    results = [_evaluate_fix_commit(meta, find_exemption, indexed, native, command is not None)
               for meta in fix_metas]
    return RegressionReport(DEFAULT_TIER, tuple(res for res, _finding in results),
                            tuple(f for _res, f in results if f is not None), tuple(untested))
