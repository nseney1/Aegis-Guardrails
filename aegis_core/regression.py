"""Regression discipline: git is the registry (v4.3 spec §3 T5).

A pull request is judged once against its head: the Python test files its fix commits changed that are
present at the head run on an export of the head and on an export of the merge base with the head's
copies overlaid. That is at most two pytest runs whatever the number of fix commits, so the check takes
at most ``2 x timeout``. A test id ``classname::name`` belongs to test file ``F`` when its classname is
``F``'s dotted path or starts with it and a dot; a collection error names the dotted path. An id is
fail-to-pass when it passed at head and failed on base, or its module failed collection on base. A fix
commit passes when one of its own test files holds such an id and none of them failed at head (a
suite-level error on the head run fails every commit). T5 is a report at warning tier in 4.4.0.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import posixpath
import re
import shutil
import tempfile
import time
from typing import Any, Callable, Dict, Iterable, List, NamedTuple, Optional, Sequence, Set, Tuple

from aegis_core import gitsafe, governance, human_gate, match, testexec
from aegis_core.errors import AegisError
from aegis_core.rules import workspace_root

__all__ = ["RegressionError", "check_ci_regressions", "is_source_file"]

SCHEMA = "aegis.regression/v1"
DEFAULT_TIER = "warning"
DEFAULT_TIMEOUT_S = 120.0
_GIT_TIMEOUT_S = 60.0
EXEMPT_SCOPES = frozenset({"ci", "build", "docs", "deps", "release", "chore", "tests"})
_DOC_DIRS = frozenset({"docs", "doc"})
_DOC_EXTENSIONS = frozenset({".md", ".rst", ".txt", ".adoc", ".html", ".pdf", ".png", ".svg", ".jpg", ".jpeg", ".gif"})
_DOC_TEXT_EXTENSIONS = frozenset({"", ".md", ".rst", ".txt", ".adoc"})
_DOC_BASENAMES = frozenset({
    "readme", "changelog", "changes", "history", "license", "copying",
    "authors", "contributors", "code_of_conduct", "security", "notice", "patents",
})
# Languages Aegis has AST drivers for: a changed test in one of them is a test pytest cannot run.
_OTHER_LANGUAGE_TESTS = frozenset({".go", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".rs"})
# Finding codes that say a check could not run, not that a fix failed.
UNVERIFIED_CODES = frozenset({"tests_not_pytest"})
_CONFIG_EXTENSIONS = frozenset({".toml", ".yaml", ".yml", ".json", ".ini", ".cfg", ".conf", ".lock", ".env", ".pth"})
_CONFIG_BASENAMES = frozenset({
    "makefile", "dockerfile", "containerfile", "justfile", "vagrantfile", "procfile", "manifest.in",
    "requirements.txt", "requirements-dev.txt", "pipfile", "tox.ini", "setup.cfg", "pyproject.toml",
    "pytest.ini", ".pytest.ini", "pytest.toml", ".pytest.toml", "allowed_signers", "codeowners", "conftest.py", "sitecustomize.py",
})
_CONVENTIONAL_RE = re.compile(r"\A([a-zA-Z]+)(?:\(([^)]*)\))?(!)?:\s*(.*)\Z")


class RegressionError(AegisError):
    """The commit range or repository trees cannot be read."""


def is_test_file(path: str) -> bool:
    return bool(isinstance(path, str) and path and match.is_test_path(path))


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

    @property
    def passed(self) -> bool:
        return self.status in ("passed", "exempted", "unverifiable")

    def as_dict(self, workspace: Any = None) -> Dict[str, Any]:
        return {
            "commit": self.commit,
            "subject": self.subject,
            "status": self.status,
            "reason": self.reason,
            "fail_to_pass_tests": list(self.fail_to_pass_tests),
            "no_test_reason": self.no_test_reason,
            "approval": None if self.approval is None else self.approval.as_dict(workspace),
            "exemption_code": self.exemption_code,
        }


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


def _resolve_commit_exemption(root: str, head_commit: str, base_commit: str, meta: _CommitMeta) -> Tuple[Optional[human_gate.Approval], Optional[str]]:
    """(the valid exemption, None), or (None, the code of a rejected one naming this commit)."""
    try:
        found = human_gate.find_test_exemption(root, head_commit, base_commit, meta.oid)
    except (human_gate.HumanGateError, gitsafe.GitError):
        return None, None
    return (found, None) if found is None or found.valid else (None, found.code)


def _run_pr_level(root: str, workspace: Path, merge_commit: str, head_commit: str, tests: Iterable[str],
                  timeout: float, progress: Callable[[str], None]) -> Optional[Tuple[Any, Any]]:
    """(head run, base run) of ``testexec.run_pytest_snapshot`` for the ``tests`` present at head, on the
    head and on the merge base with the head's copies of those tests overlaid; None when none is present."""
    head_tree = _tree_blobs(root, head_commit)
    present = sorted(p for p in set(tests) if p in head_tree)
    if not present:
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
            runs.append(testexec.run_pytest_snapshot(scratch / f"{name}_snap", present, workspace, scratch / f"{name}_run",
                                                     timeout))
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


def _belongs(test_id: str, module: str) -> bool:
    cls = test_id.partition("::")[0]
    return cls == module or cls.startswith(module + ".")


def _judge(test_files: Sequence[str], head: Any, base: Any) -> Tuple[str, Tuple[str, ...]]:
    """(reason, fail-to-pass ids) of one commit's Python test files in the head and base runs."""
    modules = {p[:-3].replace("/", ".") for p in test_files}
    mine = lambda ids: {i for i in ids if any(_belongs(i, m) for m in modules)}  # noqa: E731
    f2p = tuple(sorted(i for i in mine(head.passed_ids)
                       if i in base.failed_ids or any(_belongs(i, e) for e in base.collection_errors)))
    seen = mine(head.passed_ids) | mine(head.failed_ids) | (modules & head.collection_errors)
    bad = bool(mine(head.failed_ids) or modules & head.collection_errors
               or any(e.startswith("<suite:") for e in head.collection_errors))
    if head.timed_out or base.timed_out:
        reason = "timeout"
    else:
        reason = "ok" if f2p and not bad else "failed_on_head" if seen and bad else "passed_on_base" if seen else "no_tests_collected"
    return reason, f2p


def _evaluate_fix_commit(root: str, meta: _CommitMeta, head_commit: str, base_commit: str,
                         runs: Optional[Tuple[Any, Any]]) -> Tuple[CommitRegression, Optional[RegressionFinding]]:
    source_files = tuple(p for p in meta.changed_files if is_source_file(p))
    test_files = tuple(p for p in meta.present_files if is_python_test_file(p))
    other_tests = () if test_files else tuple(
        p for p in meta.present_files if is_test_file(p) and posixpath.splitext(p)[1] in _OTHER_LANGUAGE_TESTS)
    reason, f2p = (("tests_not_pytest", ()) if other_tests else ("no_test_changes", ()) if not test_files
                   else ("no_tests_collected", ()) if runs is None else _judge(test_files, *runs))
    if reason == "ok":
        return CommitRegression(meta.oid, meta.subject, "passed", "ok", f2p, meta.no_test_reason), None
    # Only a commit that did not pass needs its exemption: each lookup rescans the whole range.
    approval, rejected = _resolve_commit_exemption(root, head_commit, base_commit, meta)
    nt_note = f" (its test exemption was rejected: {rejected})" if rejected else ""
    if meta.no_test_reason:
        nt_note += f" (Aegis-No-Test: {meta.no_test_reason!r} is an explanation only; exemption requires human_gate approval)"
    named = f"fix commit {meta.oid[:10]} ({meta.subject})"
    if other_tests:
        msg = f"{named} changes tests pytest cannot run ({', '.join(other_tests[:5])}): the fail-to-pass check is unverified{nt_note}"
        return (CommitRegression(meta.oid, meta.subject, "unverifiable", "tests_not_pytest", (), meta.no_test_reason),
                RegressionFinding("tests_not_pytest", meta.oid, other_tests[0], msg, meta.no_test_reason))
    if approval is not None and approval.valid:
        return CommitRegression(meta.oid, meta.subject, "exempted", "exempted", f2p, meta.no_test_reason, approval), None
    return (CommitRegression(meta.oid, meta.subject, "failed", reason, f2p, meta.no_test_reason, exemption_code=rejected),
            RegressionFinding(reason, meta.oid, (test_files or source_files or ("",))[0], f"{named}{_DETAILS[reason]}{nt_note}",
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
    """``progress`` gets one line before and one after each pytest run (``aegis check --ci`` prints them
    on stderr)."""
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
    # One PR-level pass judges every fix commit's Python tests at once.
    judged = [p for m in fix_metas for p in m.present_files if is_python_test_file(p)]
    runs = (_run_pr_level(root, workspace_path, merge_commit, head_commit, judged, timeout, progress or (lambda _line: None))
            if judged else None)
    results = [_evaluate_fix_commit(root, meta, head_commit, base_commit, runs) for meta in fix_metas]
    return RegressionReport(DEFAULT_TIER, tuple(res for res, _finding in results),
                            tuple(f for _res, f in results if f is not None), tuple(untested))
