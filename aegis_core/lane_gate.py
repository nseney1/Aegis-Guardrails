"""The post-lane gate, ``aegis check --lane`` (v4.1 spec §1, ADR 0005 AD-7).

**Range.** ``merge-base(<base>, HEAD)..HEAD`` through ``gitsafe.diff_entries``, which
lists every path: additions, deletions, type changes, both sides of a move (git's
rename detection is off) and gitlinks. ``<base>`` is the caller's or
``gitsafe.resolve_base_ref()``. A shallow clone, a base that does not resolve and a
base with no history in common with HEAD all fail with ``needs history: fetch with
fetch-depth 0``: a cut history can hide the true merge base. Only committed changes
count.

**Allowed set and provenance.** Self-attested by default: the lane's live lease (or
``paths``, given on the command line) plus ``shared`` from the working tree's
``.aegis/team.json``. With ``base_policy``, ``lanes[<lane>]`` and ``shared`` come from
team.json at the base tip (never the merge base, never the candidate) and the lane's
paths cannot be given. Each input's source is recorded (``lease``, ``cli``,
``worktree`` or ``base@<sha>``); the label is ``witnessed: base policy`` only when
every input came from base. team.json is read at the repository's top level, where
``team.load_team_at`` reads it.

**Containment.** Every listed path must match an allowed glob, with the one matcher's
semantics (``shared: ["CHANGELOG.md"]`` also admits ``docs/CHANGELOG.md``).
``.aegis/**`` and ``.github/workflows/**`` (and those directories themselves, case
folded, as a case-insensitive checkout sees them) are allowed only by a glob read
from base.

**Test integrity**, for Python test files (``match.is_test_path`` and ``.py``) and
pytest's config files; other test files are listed as not checked. Each finding has
a stable id, the first 12 hex characters of sha256(``kind|path|name``):

- ``removed``: a test id (``name``, ``Class::name``, ``Outer::Inner::name``: functions
  and methods named ``test*``, as pytest's default discovery collects them) present
  at the merge base and not collected at HEAD. A deleted, moved or symlinked file
  loses all of its ids; so does a class that gains ``__init__`` or ``__new__``, a
  test name rebound or deleted after its ``def``, and a test made a fixture
  (``@pytest.fixture``), which pytest does not collect.
- ``skip``: an occurrence introduced at HEAD, per scope, of ``pytest.mark.skip``,
  ``skipif`` or ``xfail``; ``unittest.skip``, ``skipIf``, ``skipUnless`` or
  ``expectedFailure``; a module- or class-level ``pytestmark`` or ``__test__``, or
  either set as an attribute (``test_x.__test__ = False``); ``pytest.skip``,
  ``pytest.xfail`` or ``pytest.importorskip``; ``.skipTest``; ``unittest.SkipTest``;
  or ``pytest.exit`` and ``os._exit``, which end the run early. Import aliases (star
  imports from pytest, unittest and os too) and simple assignments are followed
  (``needs_git = pytest.mark.skipif(...)`` makes each ``@needs_git`` count), every
  binding anywhere in the module, so rebinding ``pytest`` where it never runs adds a
  reading and hides none. An
  occurrence is its whole expression and the blocks around it (``if``, ``while``,
  ``for``, ``try``, ``with``, ``match``, a conditional expression, ``and``/``or``), so
  a weakened condition or a removed or changed guard is a new skip. A test that
  moves under a condition (``if``, ``try``, a loop) is a ``skip`` finding too.
- ``collection``: in a ``conftest.py``, any change to ``collect_ignore``,
  ``collect_ignore_glob`` or a ``pytest_*`` name (the hooks, such as
  ``pytest_collection_modifyitems``, and ``pytest_plugins``); in any other Python
  test file, a change to a ``pytest_*`` hook it defines (a plugin module); in
  ``pytest.toml`` or ``.pytest.toml`` (``[pytest]``), ``pytest.ini``, ``.pytest.ini``,
  ``pyproject.toml`` (``[tool.pytest.ini_options]``, ``[tool.pytest]``), ``setup.cfg``
  (``[tool:pytest]``) or ``tox.ini`` (``[pytest]``), a change to
  ``addopts``, ``testpaths``, ``python_files``, ``python_classes``,
  ``python_functions`` or ``norecursedirs``, or a pytest configuration appearing or
  disappearing (which changes the file pytest reads).
- ``unparseable``: a side of such a file that cannot be parsed.

Any finding fails the check and sets ``protected_changed``. There is no exemption:
the reviewer or the person merging decides with the findings in view. LIMITS lists
what is not detected, assert weakening first.

Every check appends a ``lane_check`` event with the label, both results and the
provenance record; an event that cannot be written is a warning, never a failure. A
HEAD already contained in the base leaves nothing to check: it passes with a warning.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import datetime, timezone  # noqa: F401 - names the 4.3.3 public-names pin holds
import hashlib
import os
from pathlib import Path
import posixpath
import re
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from aegis_core import primitives
from aegis_core import events, gitsafe, team
from aegis_core.errors import AegisError, AegisValidationError
from aegis_core.lane_ast import (
    COLLECTION_KEYS,
    COVERED,
    LIMITS,
    PYTEST_CONFIG_FILES,
    collected_ids,
    collection_hooks,
    pytest_settings,
    skip_forms,
)
from aegis_core.match import is_test_path, matches, normalize_path
from aegis_core.primitives import utc_stamp
from aegis_core.workspace.layout import AEGIS_DIRNAME

__all__ = [
    "COLLECTION_KEYS",
    "COVERED",
    "KINDS",
    "LIMITS",
    "NEEDS_HISTORY",
    "PROTECTED",
    "PYTEST_CONFIG_FILES",
    "SELF_ATTESTED",
    "SOURCE",
    "WITNESSED",
    "Finding",
    "LaneCheck",
    "LaneGateError",
    "LaneGateUsage",
    "PathCheck",
    "check_lane",
    "collected_ids",
    "collection_hooks",
    "error_report",
    "finding_id",
    "is_protected",
    "pytest_settings",
    "skip_forms",
]

SOURCE = "aegis check --lane"
NEEDS_HISTORY = "needs history: fetch with fetch-depth 0"
WITNESSED = "witnessed: base policy"
SELF_ATTESTED = "self-attested"
PROTECTED = (f"{AEGIS_DIRNAME}/**", ".github/workflows/**")
KINDS = ("removed", "skip", "collection", "unparseable")
MAX_FILE_BYTES = 8 * 1024 * 1024
NOTE_SELF_ATTESTED = (
    "self-attested: the allowed paths came from the lane's lease, --paths or the working tree's team.json, "
    "all of which the lane can write. --base-policy reads them from team.json at the base tip instead."
)
NOTE_WITNESSED = (
    "witnessed: base policy: every allowed path came from team.json at the base tip. A witness is only as "
    "strong as the protection on .github/** and on the base branch."
)
NOTE_EXEMPTION = (
    "Assert weakening is not detected. Any finding fails the check; there is no exemption flag: the reviewer "
    "or the person merging decides with the itemized findings in view."
)

_REGULAR = ("100644", "100755")
_OID = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_PARSE_ERRORS = (SyntaxError, ValueError, RecursionError)


# ── Errors and records ───────────────────────────────────────────────────────

class LaneGateError(AegisError):
    """The gate could not check the lane (no usable history, no allowed paths, no policy
    for the lane at base); nothing was decided. The CLI exits 1."""


class LaneGateUsage(AegisValidationError):
    """Arguments the gate cannot use (``--paths`` with base policy, an invalid glob, no git
    work tree). The CLI exits 2."""


def finding_id(kind: str, path: str, name: str) -> str:
    """The stable id of a finding: sha256 of ``kind|path|name``, first 12 hex characters."""
    text = f"{kind}|{path}|{name}".encode("utf-8", "surrogateescape")
    return hashlib.sha256(text).hexdigest()[:12]


@dataclass(frozen=True)
class Finding:
    """One test-integrity finding (``kind`` is one of KINDS)."""

    id: str
    kind: str
    path: str
    name: str
    detail: str

    def as_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "path": self.path, "name": self.name, "detail": self.detail}


def _finding(kind: str, path: str, name: str, detail: str) -> Finding:
    return Finding(finding_id(kind, path, name), kind, path, name, detail)


@dataclass(frozen=True)
class PathCheck:
    """One listed path: git's status and modes, whether an allowed glob admits it, which
    glob from which source, and whether it is a protected path."""

    path: str
    status: str
    old_mode: str
    new_mode: str
    allowed: bool
    glob: Optional[str]
    source: Optional[str]
    protected: bool

    def as_dict(self) -> Dict[str, Any]:
        return {"path": self.path, "status": self.status, "old_mode": self.old_mode, "new_mode": self.new_mode,
                "allowed": self.allowed, "glob": self.glob, "source": self.source, "protected": self.protected}


def _source_label(source: str, base: str) -> str:
    if source.startswith("base@"):
        return f"team.json at {base} {source[len('base@'):][:12]}"
    return {"lease": "the lane's lease", "cli": "--paths", "worktree": "the working tree's team.json"}[source]


@dataclass(frozen=True)
class LaneCheck:
    """The outcome of one gate run. ``changes`` lists every path in git's order,
    ``findings`` are sorted by path, kind and name, ``not_checked`` pairs a test file
    with why it was not read."""

    lane: str
    workspace: str
    repository: str
    base: str
    base_commit: str
    merge_base: str
    head: str
    paths: Tuple[str, ...]
    paths_source: str
    shared: Tuple[str, ...]
    shared_source: str
    changes: Tuple[PathCheck, ...]
    findings: Tuple[Finding, ...]
    checked: Tuple[str, ...]
    not_checked: Tuple[Tuple[str, str], ...]
    checked_at: str
    warnings: Tuple[str, ...] = ()

    @property
    def label(self) -> str:
        from_base = all(s.startswith("base@") for s in (self.paths_source, self.shared_source))
        return WITNESSED if from_base else SELF_ATTESTED

    @property
    def violations(self) -> Tuple[PathCheck, ...]:
        return tuple(change for change in self.changes if not change.allowed)

    @property
    def containment_passed(self) -> bool:
        return not self.violations

    @property
    def integrity_passed(self) -> bool:
        return not self.findings

    @property
    def passed(self) -> bool:
        return self.containment_passed and self.integrity_passed

    @property
    def protected_changed(self) -> bool:
        return bool(self.findings)

    def _range(self) -> Dict[str, str]:
        return {"base": self.base, "base_commit": self.base_commit, "merge_base": self.merge_base, "head": self.head}

    def event_detail(self) -> Dict[str, Any]:
        """The ``lane_check`` event's detail: the label, both results and the provenance."""
        return {
            "lane": self.lane,
            "label": self.label,
            "provenance": {"paths": self.paths_source, "shared": self.shared_source},
            "containment": {"passed": self.containment_passed, "violations": len(self.violations)},
            "integrity": {"passed": self.integrity_passed, "findings": [f.id for f in self.findings]},
            "range": self._range(),
        }

    def as_dict(self) -> Dict[str, Any]:
        """The ``--json`` document."""
        return {
            **primitives.envelope(SOURCE, {"workspace": self.workspace, "repository": self.repository, "lane": self.lane, **self._range()}, checked_at=self.checked_at),
            "status": "pass" if self.passed else "fail",
            "label": self.label,
            "provenance": {"paths": self.paths_source, "shared": self.shared_source},
            "allowed": {"paths": list(self.paths), "shared": list(self.shared)},
            "containment": {
                "passed": self.containment_passed,
                "paths": [change.as_dict() for change in self.changes],
                "violations": [change.path for change in self.violations],
            },
            "integrity": {
                "passed": self.integrity_passed,
                "covered": list(COVERED),
                "checked": list(self.checked),
                "not_checked": [{"path": path, "reason": reason} for path, reason in self.not_checked],
                "findings": [f.as_dict() for f in self.findings],
                "limits": list(LIMITS),
            },
            "protected_changed": self.protected_changed,
            "notes": [NOTE_WITNESSED if self.label == WITNESSED else NOTE_SELF_ATTESTED, NOTE_EXEMPTION],
            "warnings": list(self.warnings),
        }

    def text_lines(self) -> List[str]:
        """The text report, one line per item; repository text is not sanitized here."""
        verdict = "PASSED" if self.passed else "FAILED"
        lines = [
            f"{SOURCE} {self.lane}: {verdict} ({self.label})",
            f"  range: {self.merge_base[:12]}..{self.head[:12]} (from the merge base of {self.base} and HEAD), "
            f"{len(self.changes)} changed path(s)",
            f"  allowed paths from {_source_label(self.paths_source, self.base)}: {', '.join(self.paths) or '(none)'}",
            f"  shared from {_source_label(self.shared_source, self.base)}: {', '.join(self.shared) or '(none)'}",
        ]
        if self.violations:
            lines.append(f"containment: FAILED, {len(self.violations)} of {len(self.changes)} changed path(s) "
                         "outside the allowed set")
            for change in self.violations:
                why = ("protected: only team.json at the base tip (--base-policy) can allow "
                       + " and ".join(PROTECTED)) if change.protected else "outside the allowed set"
                lines.append(f"  [FAIL] {change.status} {change.path}: {why}")
        else:
            lines.append(f"containment: passed, {len(self.changes)} changed path(s) inside the allowed set")
        if self.findings:
            lines.append(f"test integrity (Python): FAILED, {len(self.findings)} finding(s); protected_changed: true")
            for f in self.findings:
                lines.append(f"  [FAIL] {f.id} {f.kind} {f.path}: {f.name} ({f.detail})")
        else:
            lines.append(f"test integrity (Python): passed, {len(self.checked)} file(s) checked; "
                         "protected_changed: false")
        for path, reason in self.not_checked:
            lines.append(f"  not checked: {path} ({reason})")
        lines.extend(f"warning: {warning}" for warning in self.warnings)
        lines.append(NOTE_WITNESSED if self.label == WITNESSED else NOTE_SELF_ATTESTED)
        lines.append(NOTE_EXEMPTION)
        return lines


def error_report(workspace: Any, lane: str, message: str, now: Optional[int] = None) -> Dict[str, Any]:
    """The ``--json`` document of a gate that could not run."""
    return {
        **primitives.envelope(SOURCE, {"workspace": str(workspace), "lane": lane}, now=now),
        "status": "error",
        "error": message,
    }


# ── The gate ─────────────────────────────────────────────────────────────────

def is_protected(path: str) -> bool:
    """Whether ``path`` is under ``.aegis/`` or ``.github/workflows/`` (or is one of those
    directories, or ``.github``), compared case-folded: on a case-insensitive checkout
    ``.AEGIS/team.json`` is ``.aegis/team.json``."""
    folded = normalize_path(path).casefold()
    if folded == ".github":
        return True
    return any(folded == root or folded.startswith(root + "/") for root in (AEGIS_DIRNAME, ".github/workflows"))


def _cli_globs(paths: object) -> Tuple[str, ...]:
    if not isinstance(paths, (list, tuple)):  # a lone string is one glob's characters
        raise LaneGateUsage("--paths: give a list of globs")
    if not paths:
        raise LaneGateUsage("--paths: give at least one glob")
    out: List[str] = []
    for ordinal, glob in enumerate(paths, 1):
        problem = team.glob_problem(glob)
        if problem:
            message = {"not_text": "is not text without control characters",
                       "control": "is not text without control characters", "empty": "is empty",
                       "climbs": "climbs out of the repository with '..'"}[problem]
            raise LaneGateUsage(f"--paths: glob {ordinal} {message}")
        clean = normalize_path(glob)
        if clean not in out:
            out.append(clean)
    return tuple(out)


def _commit_range(top: Path, base: Optional[str]) -> Tuple[str, str, str, str]:
    """(base ref, base commit, merge base, HEAD), or LaneGateError."""
    shallow = gitsafe.run(["rev-parse", "--is-shallow-repository"], top)
    answer = shallow.stdout.strip()
    if shallow.returncode != 0 or answer not in (b"true", b"false"):
        raise gitsafe.GitError(f"git cannot say whether {top} is a shallow clone")
    if answer == b"true":
        raise LaneGateError(f"{NEEDS_HISTORY} (this is a shallow clone)")
    ref = base if base is not None else gitsafe.resolve_base_ref(top)
    if ref is None:
        raise LaneGateError(f"{NEEDS_HISTORY} (no base branch: none of origin/$GITHUB_BASE_REF, the branch "
                            "origin/HEAD names, main, develop or master exists; pass --base)")
    base_commit = gitsafe.resolve_commit(top, ref)
    if not base_commit:
        raise LaneGateError(f"{NEEDS_HISTORY} (cannot resolve the base {ref!r})")
    head = gitsafe.head_commit(top)
    if not head:
        raise LaneGateError("HEAD names no commit yet: there is nothing to check")
    merge_base = gitsafe.merge_base(top, base_commit, head)
    if not merge_base:
        raise LaneGateError(f"{NEEDS_HISTORY} ({ref!r} and HEAD share no history)")
    return ref, base_commit, merge_base, head


def _lease_paths(top: Path, lane: str, now: int) -> Tuple[str, ...]:
    found = team.read_leases(top)
    lease = found.get(lane)
    if lease is not None and not lease.expired(now):
        return lease.paths
    if lease is not None:
        why = f"its lease expired at {utc_stamp(lease.expires_at)}"
    elif found.unreadable_lane(lane) is not None:
        why = "its lease is unreadable"
    else:
        why = "it holds no lease"
    raise LaneGateError(f"lane {lane} has no live lease ({why}): claim it with aegis team claim, "
                        "give its globs with --paths, or read them from base with --base-policy")


def _contain(entry: Tuple[str, str, str, str], allowed: Sequence[Tuple[str, str]]) -> PathCheck:
    status, old_mode, new_mode, path = entry
    protected = is_protected(path)
    for glob, source in allowed:
        if protected and not source.startswith("base@"):
            continue
        if matches(glob, path):
            return PathCheck(path, status, old_mode, new_mode, True, glob, source, protected)
    return PathCheck(path, status, old_mode, new_mode, False, None, None, protected)


def _read(top: Path, commit: str, path: str, mode: str) -> Optional[bytes]:
    """The blob at ``commit:path`` when ``mode`` is a regular file's, else None. The
    revision syntax names the path literally (no pathspec magic); the content is
    checked against its object id."""
    if mode not in _REGULAR:
        return None
    res = gitsafe.run(["rev-parse", "--verify", "--quiet", f"{commit}:{path}"], top)
    oid = os.fsdecode(res.stdout).strip() if res.returncode == 0 else ""
    if not _OID.match(oid):
        raise gitsafe.GitError(f"cannot find {path!r} at {commit}")
    return gitsafe.read_object(top, oid, MAX_FILE_BYTES)


def _irregular(old_mode: str, new_mode: str) -> str:
    side, mode = ("HEAD", new_mode) if new_mode != "000000" else ("the merge base", old_mode)
    what = {"120000": "a symlink", "160000": "a submodule"}.get(mode, f"mode {mode}")
    return f"{what} at {side}"


def _python_findings(path: str, before: Optional[bytes], after: Optional[bytes]) -> List[Finding]:
    conftest = posixpath.basename(path) == "conftest.py"
    facts = []
    errors = []
    for side, data in (("base", before), ("head", after)):
        try:
            if data is None:
                facts.append(({}, {}, {}))
            else:
                facts.append((collected_ids(data), skip_forms(data), collection_hooks(data, hooks_only=not conftest)))
        except _PARSE_ERRORS as exc:
            where = "the merge base" if side == "base" else "HEAD"
            errors.append(_finding("unparseable", path, side, f"cannot parse the file at {where}: {type(exc).__name__}"))
    if errors:
        return errors
    (base_ids, base_forms, base_hooks), (head_ids, head_forms, head_hooks) = facts
    out: List[Finding] = []
    for test_id, unconditional in base_ids.items():
        if test_id not in head_ids:
            out.append(_finding("removed", path, test_id, "present at the merge base, not collected at HEAD"))
        elif unconditional and not head_ids[test_id]:
            out.append(_finding("skip", path, f"conditional definition in {test_id}",
                                "defined only under a condition at HEAD"))
    for (scope, form), count in head_forms.items():
        for occurrence in range(base_forms.get((scope, form), 0) + 1, count + 1):
            name = f"{form} in {scope}" + (f" #{occurrence}" if occurrence > 1 else "")
            out.append(_finding("skip", path, name, "introduced at HEAD"))
    for hook in set(base_hooks) | set(head_hooks):
        if base_hooks.get(hook) != head_hooks.get(hook):
            out.append(_finding("collection", path, hook, _changed(hook in base_hooks, hook in head_hooks)))
    return out


def _changed(before: bool, after: bool) -> str:
    if before and after:
        return "changed at HEAD"
    return "added at HEAD" if after else "removed at HEAD"


def _config_findings(path: str, before: Optional[bytes], after: Optional[bytes]) -> List[Finding]:
    name = posixpath.basename(path)
    sides: List[Optional[Dict[str, str]]] = []
    errors = []
    for side, data in (("base", before), ("head", after)):
        try:
            sides.append(None if data is None else pytest_settings(name, data))
        except ValueError as exc:
            where = "the merge base" if side == "base" else "HEAD"
            errors.append(_finding("unparseable", path, side, f"cannot read the file at {where}: {exc}"))
    if errors:
        return errors
    old, new = sides
    out: List[Finding] = []
    if (old is None) != (new is None):
        out.append(_finding("collection", path, "pytest configuration", _changed(old is not None, new is not None)))
    old, new = old or {}, new or {}
    for key in set(old) | set(new):
        if old.get(key) != new.get(key):
            out.append(_finding("collection", path, key, _changed(key in old, key in new)))
    return out


def _integrity(top: Path, merge_base: str, head: str, entries: Sequence[Tuple[str, str, str, str]]):
    findings: List[Finding] = []
    checked: List[str] = []
    not_checked: List[Tuple[str, str]] = []
    for _status, old_mode, new_mode, path in entries:
        python_test = is_test_path(path) and path.endswith(".py")
        config = posixpath.basename(path) in PYTEST_CONFIG_FILES
        if not (python_test or config):
            if is_test_path(path):
                not_checked.append((path, "not a Python file"))
            continue
        before = _read(top, merge_base, path, old_mode)
        after = _read(top, head, path, new_mode)
        if before is None and after is None:
            not_checked.append((path, _irregular(old_mode, new_mode)))
            continue
        checked.append(path)
        findings.extend(_python_findings(path, before, after) if python_test else _config_findings(path, before, after))
    findings.sort(key=lambda f: (f.path, f.kind, f.name))
    return tuple(findings), tuple(checked), tuple(not_checked)


def _record(top: Path, result: LaneCheck) -> Tuple[str, ...]:
    exc = events.try_append(top, "lane_check", "pass" if result.passed else "fail", result.event_detail())
    if exc is not None:
        return (f"event not recorded: {exc}",)
    return ()


def check_lane(root: Any, lane: str, base: Optional[str] = None, paths: Optional[Sequence[str]] = None,
               base_policy: bool = False, now: Optional[int] = None) -> LaneCheck:
    """Check what ``lane`` changed since ``merge-base(base, HEAD)`` (see the module
    docstring) and append a ``lane_check`` event.

    Raises TeamUsageError for an invalid lane name; LaneGateUsage for ``paths`` with
    ``base_policy``, an invalid glob or no git work tree; TeamFileError for an unusable
    team.json; LaneGateError when there is no usable history, no live lease (without
    ``paths``) or no ``lanes`` entry at base (with ``base_policy``); GitError when git
    fails.
    """
    team.lane_ref(lane)
    if base_policy and paths is not None:
        raise LaneGateUsage("--paths cannot be combined with --base-policy: the lane's paths then come only "
                            "from team.json at the base tip")
    cli_paths = _cli_globs(paths) if paths is not None else None
    workspace = Path(os.fspath(root))
    top = gitsafe.toplevel(workspace)
    if top is None:
        raise LaneGateUsage("not in a git work tree: the lane gate checks git history")
    moment = int(time.time()) if now is None else int(now)
    ref, base_commit, merge_base, head = _commit_range(top, base)
    if base_policy:
        policy = team.load_team_at(top, base_commit)
        if policy.lanes is None or lane not in policy.lanes:
            raise LaneGateError(f"team.json at {ref} ({base_commit[:12]}) has no lanes entry for {lane}: "
                                "--base-policy takes the lane's paths only from there")
        lane_paths, paths_source = policy.lanes[lane], f"base@{base_commit}"
        shared, shared_source = policy.shared, f"base@{base_commit}"
    else:
        if cli_paths is not None:
            lane_paths, paths_source = cli_paths, "cli"
        else:
            lane_paths, paths_source = _lease_paths(top, lane, moment), "lease"
        shared, shared_source = team.load_team(top).shared, "worktree"
    allowed = [(glob, paths_source) for glob in lane_paths] + [(glob, shared_source) for glob in shared]
    entries = gitsafe.diff_entries(top, merge_base, head)
    findings, checked, not_checked = _integrity(top, merge_base, head, entries)
    # Passing is right (the lane changed nothing), but a reader of "PASSED" should know why.
    empty = (f"HEAD is already contained in {ref}: nothing was checked",) if merge_base == head else ()
    result = LaneCheck(
        lane=lane, workspace=str(workspace), repository=str(top), base=ref, base_commit=base_commit,
        merge_base=merge_base, head=head, paths=tuple(lane_paths), paths_source=paths_source,
        shared=tuple(shared), shared_source=shared_source,
        changes=tuple(_contain(entry, allowed) for entry in entries),
        findings=findings, checked=checked, not_checked=not_checked, checked_at=utc_stamp(moment), warnings=empty,
    )
    return dataclasses.replace(result, warnings=empty + _record(top, result))
