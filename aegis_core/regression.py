"""Regression discipline: git is the registry (v4.3 spec §3 T5)."""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import sys
import tempfile
from typing import Any, Dict, FrozenSet, Iterable, List, NamedTuple, Optional, Sequence, Set, Tuple

from aegis_core import checkrun, gitsafe, governance, human_gate, match
from aegis_core.config import _is_within
from aegis_core.errors import AegisError
from aegis_core.rules import workspace_root

__all__ = [
    "CommitRegression",
    "DEFAULT_TIER",
    "DEFAULT_TIMEOUT_S",
    "EXEMPT_SCOPES",
    "PRUNE_BOX_EXEMPTION_RATE",
    "RegressionError",
    "RegressionFinding",
    "RegressionReport",
    "SCHEMA",
    "SOURCE",
    "UNVERIFIED_CODES",
    "UntestedChange",
    "check_ci_regressions",
    "is_config_file",
    "is_doc_file",
    "is_fix_commit",
    "is_python_test_file",
    "is_source_file",
    "is_test_file",
    "parse_fix_subject",
]

SCHEMA = "aegis.regression/v1"
SOURCE = "aegis check --ci"
DEFAULT_TIER = "warning"
PRUNE_BOX_EXEMPTION_RATE = 0.25
DEFAULT_TIMEOUT_S = 120.0
_GIT_TIMEOUT_S = 60.0
EXEMPT_SCOPES = frozenset({"ci", "build", "docs", "deps", "release", "chore", "tests", "test", "doc"})
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
_FIXES_LINE_RE = re.compile(r"^[ \t]*(?:fixes|closes)[ \t]*:[ \t]*(\S.*)$", re.IGNORECASE | re.MULTILINE)
_NO_TEST_LINE_RE = re.compile(r"^[ \t]*aegis-no-test[ \t]*:[ \t]*(\S.*)$", re.IGNORECASE | re.MULTILINE)
_PYTHON_FLAGS = ("-I", "-S", "-B", "--check-hash-based-pycs", "always")
_PYTEST_FLAGS = ("-p", "no:cacheprovider", "-o", "addopts=")
_SNAPSHOT_RUNNER = (
    "import json, os, sys\n"
    "snap, ws, ext = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2]), json.loads(sys.argv[3])\n"
    "within = lambda p, d: os.path.normcase(os.path.abspath(p)) == os.path.normcase(d) or os.path.normcase(os.path.abspath(p)).startswith(os.path.normcase(d) + os.sep)\n"
    "sys.path[:] = [snap] + [p for p in (*sys.path, *ext) if p and p != snap and (within(p, snap) or not within(p, ws))]\n"
    "import pytest\n"
    "raise SystemExit(pytest.main(sys.argv[4:]))\n"
)


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
    failed_on_base: bool
    passed_on_head: bool
    fail_to_pass_tests: Tuple[str, ...] = ()
    source_files: Tuple[str, ...] = ()
    test_files: Tuple[str, ...] = ()
    fixes: Tuple[str, ...] = ()
    no_test_reason: Optional[str] = None
    exempted: bool = False
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
            "passed": self.passed,
            "failed_on_base": self.failed_on_base,
            "passed_on_head": self.passed_on_head,
            "fail_to_pass_tests": list(self.fail_to_pass_tests),
            "source_files": list(self.source_files),
            "test_files": list(self.test_files),
            "fixes": list(self.fixes),
            "no_test_reason": self.no_test_reason,
            "exempted": self.exempted,
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
    base: str
    head: str
    merge_base: str
    tier: str = DEFAULT_TIER
    commits: Tuple[CommitRegression, ...] = ()
    findings: Tuple[RegressionFinding, ...] = ()
    untested_changes: Tuple[UntestedChange, ...] = ()
    approval: Optional[Any] = None

    @property
    def total_fix_commits(self) -> int:
        return len(self.commits)

    @property
    def fix_commits(self) -> Tuple[CommitRegression, ...]:
        return self.commits

    @property
    def passed_count(self) -> int:
        return sum(1 for c in self.commits if c.status == "passed")

    @property
    def failed_count(self) -> int:
        return sum(1 for c in self.commits if c.status == "failed")

    @property
    def exempted_count(self) -> int:
        return sum(1 for c in self.commits if c.exempted)

    @property
    def exemption_rate(self) -> float:
        return round(self.exempted_count / len(self.commits), 4) if self.commits else 0.0

    @property
    def prune_box_exceeded(self) -> bool:
        return self.exemption_rate > PRUNE_BOX_EXEMPTION_RATE

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
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "exempted_count": self.exempted_count,
            "exemption_rate": self.exemption_rate,
            "prune_box_exceeded": self.prune_box_exceeded,
            "commits": [c.as_dict(workspace) for c in self.commits],
            "findings": [f.as_dict() for f in self.findings],
            "untested_changes": [u.as_dict() for u in self.untested_changes],
            "approval": None if self.approval is None else self.approval.as_dict(workspace),
        }


def _git_run(cwd: str, args: Sequence[str], stdin: Optional[bytes] = None) -> bytes:
    try:
        res = gitsafe.run(list(args), cwd, timeout=_GIT_TIMEOUT_S, stdin=stdin)
    except gitsafe.GitError as exc:
        raise RegressionError(str(exc)) from exc
    if res.returncode != 0:
        detail = " ".join(res.stderr.decode("utf-8", "replace").split())[:200]
        raise RegressionError(f"git {args[0]} failed: {detail}")
    return res.stdout


def _tree_blobs(cwd: str, commit: str) -> Dict[str, Tuple[str, str]]:
    try:
        return gitsafe.tree_blobs(cwd, commit, timeout=_GIT_TIMEOUT_S)
    except gitsafe.GitError as exc:
        raise RegressionError(str(exc)) from exc


def _read_blobs(cwd: str, oids: Iterable[str]) -> Dict[str, bytes]:
    try:
        return gitsafe.read_blobs(cwd, oids, timeout=_GIT_TIMEOUT_S)
    except gitsafe.GitError as exc:
        raise RegressionError(str(exc)) from exc


class _CommitMeta(NamedTuple):
    oid: str
    parent: Optional[str]
    subject: str
    fixes: Tuple[str, ...]
    no_test_reason: Optional[str]
    changed_files: Tuple[str, ...]
    present_files: Tuple[str, ...]


def _commit_meta(cwd: str, oid: str, default_parent: str) -> _CommitMeta:
    fmt = "%P%x00%s%x00%(trailers:key=Fixes,valueonly)%x00%(trailers:key=Closes,valueonly)%x00%(trailers:key=Aegis-No-Test,valueonly)%x00%B"
    raw_log = _git_run(cwd, ["log", "-1", f"--format={fmt}", oid]).decode("utf-8", "replace")
    parts = (raw_log.split("\0", 5) + [""] * 6)[:6]
    parent = parts[0].split()[0] if parts[0].strip() else default_parent
    subject = parts[1].strip()
    body_after = parts[5].partition("\n")[2]
    fix_candidates = [
        *parts[2].splitlines(),
        *parts[3].splitlines(),
        *_FIXES_LINE_RE.findall(body_after),
    ]
    fixes = list(dict.fromkeys(ln.strip() for ln in fix_candidates if ln.strip()))
    nt_lines = [ln.strip() for ln in parts[4].splitlines() if ln.strip()]
    if nt_lines:
        no_test: Optional[str] = nt_lines[0]
    else:
        body_nt = _NO_TEST_LINE_RE.findall(body_after)
        no_test = body_nt[-1] if body_nt else None

    raw_diff = _git_run(cwd, ["diff-tree", "--no-commit-id", "-r", "-z", "--name-status", "--root", oid])
    changed: List[str] = []
    present: List[str] = []
    for status, old_path, new_path in gitsafe.parse_name_status_z(raw_diff):
        kind = status[:1]
        norm_old = match.normalize_path(old_path)
        if norm_old and norm_old not in changed:
            changed.append(norm_old)
        if kind in ("R", "C") and new_path is not None:
            norm_new = match.normalize_path(new_path)
            if norm_new and norm_new not in changed:
                changed.append(norm_new)
            if norm_new and norm_new not in present:
                present.append(norm_new)
        elif kind != "D":
            if norm_old and norm_old not in present:
                present.append(norm_old)
    cleaned_no_test = no_test.strip() if isinstance(no_test, str) else None
    return _CommitMeta(
        oid,
        parent,
        subject,
        tuple(fixes),
        cleaned_no_test,
        tuple(changed),
        tuple(present),
    )


class _PytestOutcome(NamedTuple):
    exit_code: int
    timed_out: bool
    passed_ids: FrozenSet[str]
    failed_ids: FrozenSet[str]
    collection_errors: FrozenSet[str]


def _parse_junit(path: Path) -> Tuple[Set[str], Set[str], Set[str]]:
    passed, failed, col_errors = checkrun.parse_junit_cases(path)
    return passed, failed, set(col_errors)


def _run_pytest_in_snapshot(
    snapshot: Path, test_files: Sequence[str], workspace: Path, scratch: Path, timeout: float
) -> _PytestOutcome:
    home = scratch / "home"
    tmp = scratch / "tmp"
    junit = scratch / "junit.xml"
    output = scratch / "output.txt"
    home.mkdir(parents=True, exist_ok=True)
    tmp.mkdir(parents=True, exist_ok=True)
    ws = workspace.resolve()
    ext_dirs = [
        str(Path(p).resolve())
        for p in sys.path
        if p and Path(p).is_dir() and not _is_within(Path(p).resolve(), ws)
    ]
    pytest_args = [*_PYTEST_FLAGS, f"--junitxml={junit}", "--", *test_files]
    argv = [
        sys.executable,
        *_PYTHON_FLAGS,
        "-c",
        _SNAPSHOT_RUNNER,
        str(snapshot.resolve()),
        str(ws),
        json.dumps(ext_dirs),
        *pytest_args,
    ]
    res = checkrun.run_tests(argv, snapshot, checkrun._hermetic_env(home, tmp), timeout, junit, output)
    passed, failed, col_errors = _parse_junit(junit)
    return _PytestOutcome(
        res.exit,
        res.timed_out,
        frozenset(passed),
        frozenset(failed),
        frozenset(col_errors),
    )


def _cached_tree(root: str, c_oid: str, tree_cache: Dict[str, Dict[str, Tuple[str, str]]]) -> Dict[str, Tuple[str, str]]:
    if c_oid not in tree_cache:
        tree_cache[c_oid] = _tree_blobs(root, c_oid)
    return tree_cache[c_oid]


def _resolve_commit_exemption(root: str, head_commit: str, base_commit: str, meta: _CommitMeta) -> Tuple[Optional[human_gate.Approval], Optional[str]]:
    """(the valid exemption, None), or (None, the code of a rejected one naming this commit)."""
    try:
        found = human_gate.find_test_exemption(root, head_commit, base_commit, meta.oid)
    except (human_gate.HumanGateError, gitsafe.GitError):
        return None, None
    return (found, None) if found is None or found.valid else (None, found.code)


def _run_fail_to_pass_snapshots(
    root: str,
    workspace: Path,
    meta: _CommitMeta,
    merge_commit: str,
    test_files: Sequence[str],
    tree_cache: Dict[str, Dict[str, Tuple[str, str]]],
    timeout: float,
) -> Tuple[_PytestOutcome, _PytestOutcome]:
    base_tree = _cached_tree(root, merge_commit, tree_cache)
    commit_tree = _cached_tree(root, meta.oid, tree_cache)
    parent_tree = (
        _cached_tree(root, meta.parent, tree_cache)
        if (meta.parent and meta.parent != merge_commit)
        else base_tree
    )
    overlay_oids = {p: commit_tree[p][1] for p in test_files if p in commit_tree}
    blobs = _read_blobs(root, overlay_oids.values())
    overlay_blobs = {path: blobs[oid] for path, oid in overlay_oids.items() if oid in blobs}

    scratch = Path(tempfile.mkdtemp(prefix="aegis-regression-"))
    try:
        os.chmod(scratch, 0o700)
        try:
            gitsafe.export_tree(root, meta.oid, scratch / "head_snap", timeout=_GIT_TIMEOUT_S)
            head_run = _run_pytest_in_snapshot(scratch / "head_snap", test_files, workspace, scratch / "head_run", timeout)
            gitsafe.export_tree(root, merge_commit, scratch / "base_snap", overlay=overlay_blobs, timeout=_GIT_TIMEOUT_S)
            base_run = _run_pytest_in_snapshot(scratch / "base_snap", test_files, workspace, scratch / "base_run", timeout)
            if not (base_run.failed_ids & head_run.passed_ids) and parent_tree is not base_tree and meta.parent:
                gitsafe.export_tree(root, meta.parent, scratch / "parent_snap", overlay=overlay_blobs, timeout=_GIT_TIMEOUT_S)
                parent_run = _run_pytest_in_snapshot(
                    scratch / "parent_snap", test_files, workspace, scratch / "parent_run", timeout
                )
                if parent_run.failed_ids & head_run.passed_ids:
                    base_run = parent_run
        except gitsafe.GitError as exc:
            raise RegressionError(str(exc)) from exc
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return base_run, head_run


def _classify_regression_outcome(
    meta: _CommitMeta,
    source_files: Tuple[str, ...],
    test_files: Tuple[str, ...],
    primary_path: str,
    base_run: _PytestOutcome,
    head_run: _PytestOutcome,
    approval: Optional[human_gate.Approval],
    nt_note: str,
) -> Tuple[CommitRegression, Optional[RegressionFinding]]:
    passed_on_head = (
        head_run.exit_code == 0
        and not head_run.timed_out
        and bool(head_run.passed_ids)
        and not head_run.failed_ids
        and not head_run.collection_errors
    )
    f2p = tuple(sorted(base_run.failed_ids & head_run.passed_ids)) if passed_on_head else ()
    failed_on_base = bool(base_run.failed_ids) and not base_run.collection_errors

    if passed_on_head and f2p:
        return (
            CommitRegression(
                meta.oid, meta.subject, "passed", "ok", True, True,
                f2p, source_files, test_files, meta.fixes, meta.no_test_reason, False, None,
            ),
            None,
        )
    if approval is not None and approval.valid:
        return (
            CommitRegression(
                meta.oid, meta.subject, "exempted", "exempted", failed_on_base, passed_on_head,
                f2p, source_files, test_files, meta.fixes, meta.no_test_reason, True, approval,
            ),
            None,
        )

    if not head_run.passed_ids and not head_run.failed_ids and not head_run.collection_errors:
        reason = "no_tests_collected"
        detail = "no tests were collected from the changed test files"
    elif not passed_on_head:
        reason = "failed_on_head"
        detail = "the changed test files failed or errored on head"
    elif base_run.collection_errors and not base_run.failed_ids:
        reason = "collection_error_on_base"
        detail = "the changed test files failed collection on base instead of failing a test assertion"
    else:
        reason = "passed_on_base"
        detail = "no test failed on base and passed on head (tests passed on base too)"
    finding = RegressionFinding(
        reason,
        meta.oid,
        primary_path,
        f"fix commit {meta.oid[:10]} ({meta.subject}): {detail}{nt_note}",
        meta.no_test_reason,
    )
    return (
        CommitRegression(
            meta.oid, meta.subject, "failed", reason, failed_on_base, passed_on_head,
            f2p, source_files, test_files, meta.fixes, meta.no_test_reason, False, None,
        ),
        finding,
    )


def _evaluate_fix_commit(
    root: str,
    workspace: Path,
    meta: _CommitMeta,
    merge_commit: str,
    head_commit: str,
    base_commit: str,
    tree_cache: Dict[str, Dict[str, Tuple[str, str]]],
    timeout: float,
) -> Tuple[CommitRegression, Optional[RegressionFinding]]:
    source_files = tuple(p for p in meta.changed_files if is_source_file(p))
    test_files = tuple(p for p in meta.present_files if is_python_test_file(p))
    primary_path = test_files[0] if test_files else (source_files[0] if source_files else "")
    approval, rejected = _resolve_commit_exemption(root, head_commit, base_commit, meta)
    nt_note = f" (its test exemption was rejected: {rejected})" if rejected else ""
    if meta.no_test_reason:
        nt_note += f" (Aegis-No-Test: {meta.no_test_reason!r} is an explanation only; exemption requires human_gate approval)"

    other_tests = () if test_files else tuple(
        p for p in meta.present_files if is_test_file(p) and posixpath.splitext(p)[1] in _OTHER_LANGUAGE_TESTS)
    if other_tests:
        msg = (f"fix commit {meta.oid[:10]} ({meta.subject}) changes tests pytest cannot run "
               f"({', '.join(other_tests[:5])}): the fail-to-pass check is unverified{nt_note}")
        return (
            CommitRegression(
                meta.oid, meta.subject, "unverifiable", "tests_not_pytest", False, False,
                (), source_files, other_tests, meta.fixes, meta.no_test_reason, False, None,
            ),
            RegressionFinding("tests_not_pytest", meta.oid, other_tests[0], msg, meta.no_test_reason),
        )
    if not test_files:
        if approval is not None and approval.valid:
            return (
                CommitRegression(
                    meta.oid, meta.subject, "exempted", "exempted", False, False,
                    (), source_files, test_files, meta.fixes, meta.no_test_reason, True, approval,
                ),
                None,
            )
        msg = f"fix commit {meta.oid[:10]} ({meta.subject}) modifies source without adding or updating a test{nt_note}"
        return (
            CommitRegression(
                meta.oid, meta.subject, "failed", "no_test_changes", False, False,
                (), source_files, test_files, meta.fixes, meta.no_test_reason, False, None, rejected,
            ),
            RegressionFinding("no_test_changes", meta.oid, primary_path, msg, meta.no_test_reason),
        )

    base_run, head_run = _run_fail_to_pass_snapshots(root, workspace, meta, merge_commit, test_files, tree_cache, timeout)
    res, finding = _classify_regression_outcome(meta, source_files, test_files, primary_path, base_run, head_run, approval, nt_note)
    return (replace(res, exemption_code=rejected) if res.status == "failed" else res), finding


def check_ci_regressions(
    workspace: Any,
    base: str,
    head: str = "HEAD",
    *,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> RegressionReport:
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

    rev_out = _git_run(root, ["rev-list", "--no-merges", "--reverse", f"{merge_commit}..{head_commit}"])
    fix_metas: List[_CommitMeta] = []
    untested: List[UntestedChange] = []
    for oid in (o for o in rev_out.decode("ascii", "replace").split() if o):
        meta = _commit_meta(root, oid, merge_commit)
        if is_fix_commit(meta.subject, meta.fixes, meta.changed_files):
            fix_metas.append(meta)
        else:
            src = tuple(p for p in meta.changed_files if is_source_file(p))
            if src and not any(is_test_file(p) for p in meta.changed_files):
                untested.append(UntestedChange(meta.oid, meta.subject, src))
    if not fix_metas:
        return RegressionReport(base_commit, head_commit, merge_commit, DEFAULT_TIER, (), (), tuple(untested), None)

    tree_cache: Dict[str, Dict[str, Tuple[str, str]]] = {}
    evaluated: List[CommitRegression] = []
    findings: List[RegressionFinding] = []
    for meta in fix_metas:
        res, finding = _evaluate_fix_commit(root, workspace_path, meta, merge_commit, head_commit, base_commit, tree_cache, timeout)
        evaluated.append(res)
        if finding is not None:
            findings.append(finding)
    first_exemption = next((c.approval for c in evaluated if c.approval is not None), None)
    return RegressionReport(
        base_commit,
        head_commit,
        merge_commit,
        DEFAULT_TIER,
        tuple(evaluated),
        tuple(findings),
        tuple(untested),
        first_exemption,
    )
