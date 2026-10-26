"""Opt-in diff coverage over changed lines (v4.3 spec T9): a report, never a verdict.

The figure is the share of the executable lines changed from merge-base(base, head) to head that the
user-scope test command (``tests.command``, pytest-based only) executes under ``coverage``. Whatever keeps
it from being measured is ``unverified`` with a reason, never 0% and never 100%, and it never changes the
exit code; that includes a work tree that is not a clean checkout of head (GitHub's default pull request
checkout is a merge commit). The tests run with the caller's environment on purpose (the project's dependencies need it):
the figure is report-only, so forging it gains nothing. Scratch files live in a private directory under
the confined state directory, and the repository's ``.coveragerc`` and ``coverage.json`` are never read.
"""
from __future__ import annotations

import itertools
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Optional

from aegis_core import gitsafe, storage, testexec
from aegis_core.errors import PathTraversalError
from aegis_core.verification.test_runner import run_external_cmd

_GIT_TIMEOUT_S = 120.0
_JSON_TIMEOUT_S = 60.0
_HUNK_RE = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_ESCAPE_RE = re.compile(rb'\\([0-7]{3}|[abfnrtv"\\])')
_ESCAPES = {b"a": b"\a", b"b": b"\b", b"f": b"\f", b"n": b"\n", b"r": b"\r", b"t": b"\t", b"v": b"\v", b'"': b'"', b"\\": b"\\"}


def _unquote_git_path(token: str) -> str:
    """A header path git C-quoted (``"b/caf\\303\\251.py"``) as its name; an unquoted token is returned as
    is, and an escape git never writes stays literal."""
    if len(token) < 2 or token[0] != '"' or token[-1] != '"':
        return token
    raw = _ESCAPE_RE.sub(lambda m: bytes([int(m[1], 8) & 0xFF]) if m[1][:1].isdigit() else _ESCAPES[m[1]],
                         token[1:-1].encode("utf-8", "surrogateescape"))
    try:
        return os.fsdecode(raw)
    except UnicodeError:
        return raw.decode("utf-8", "replace")


def _to_ranges(lines: Any) -> list[list[int]]:
    runs = itertools.groupby(enumerate(sorted(set(lines))), lambda pair: pair[1] - pair[0])
    return [[group[0][1], group[-1][1]] for group in (list(items) for _key, items in runs)]


def parse_changed_lines(diff_text: str) -> dict[str, set[int]]:
    """``{path: added line numbers}`` of a unified diff (``git diff-tree -p -U0``). Inside a hunk every
    line is content, whatever it starts with; file headers are read only between hunks."""
    changed: dict[str, set[int]] = {}
    current_file: Optional[str] = None
    cur_line, old_left, new_left = 0, 0, 0
    for raw in diff_text.split("\n"):
        hunk = _HUNK_RE.match(raw)
        if raw.startswith("diff --git "):
            current_file, old_left, new_left = None, 0, 0
        elif hunk:  # a missing count is 1; a hunk with no file before it is skipped
            old_left, cur_line, new_left = (1 if g is None else int(g) for g in hunk.groups())
            old_left, new_left = (old_left, new_left) if current_file is not None else (0, 0)
        elif old_left > 0 or new_left > 0:
            if raw.startswith("+"):
                changed.setdefault(current_file, set()).add(cur_line)  # type: ignore[arg-type]
                cur_line, new_left = cur_line + 1, new_left - 1
            elif raw.startswith("-"):
                old_left -= 1
            elif raw.startswith(" "):
                cur_line, old_left, new_left = cur_line + 1, old_left - 1, new_left - 1
        elif raw.startswith("+++ "):
            target = _unquote_git_path(raw[4:].strip())
            current_file = None if target == "/dev/null" else (target[2:] if target.startswith("b/") else target).replace("\\", "/")
    return changed


def changed_lines(root: Any, base: str, head: str) -> Optional[dict[str, set[int]]]:
    """Added lines of the ``.py`` files changed from merge-base(base, head) to head; None when git cannot say."""
    try:
        merge, tip = gitsafe.merge_base(root, base, head), gitsafe.resolve_commit(root, head)
        res = gitsafe.run(["diff-tree", "-r", "-p", "-U0", "--no-ext-diff", "--no-textconv", merge, tip], root,
                          timeout=_GIT_TIMEOUT_S) if merge and tip else None
    except gitsafe.GitError:
        return None
    if res is None or res.returncode != 0:
        return None
    return {k: v for k, v in parse_changed_lines(res.stdout.decode("utf-8", "replace")).items() if k.endswith(".py")}


def _z_names(root: Path, args: list[str]) -> Optional[list[str]]:
    try:
        res = gitsafe.run(args, root, timeout=_GIT_TIMEOUT_S)
    except gitsafe.GitError:
        return None
    return None if res.returncode != 0 else [os.fsdecode(p) for p in res.stdout.split(b"\0") if p]


def _checkout_mismatch(root: Path, head: str) -> Optional[str]:
    """Why the work tree ``coverage run`` measures is not ``head``'s tree, or None. Untracked files do not
    count: a checkout routinely holds some (a virtualenv, build output), and the figure is a report."""
    tip = gitsafe.resolve_commit(root, head)
    if not tip or gitsafe.head_commit(root) != tip:
        return f"the checkout is not {(tip or head)[:12]}; check out the pull request head"
    edited = gitsafe.changed_files(root, "working")
    # changed_files lists no deletion: ls-files reads the index against the work tree, diff-index a `git rm`.
    gone = _z_names(root, ["ls-files", "-z", "--deleted", "--"])
    removed = _z_names(root, ["diff-index", "--cached", "-z", "--name-only", "--no-renames", "--diff-filter=D", tip, "--"])
    if edited is None or gone is None or removed is None:
        return "cannot tell whether the work tree matches the checkout"
    dirty = list(dict.fromkeys([*edited, *gone, *removed]))
    if not dirty:
        return None
    more = f" and {len(dirty) - 3} more" if len(dirty) > 3 else ""
    return f"the work tree has uncommitted changes to tracked files: {', '.join(dirty[:3])}{more}"


def _result(status: str, reason: str, covered: int = 0, total: int = 0, ranges: Optional[dict] = None,
            unmeasured: Optional[list] = None) -> dict[str, Any]:
    return {"status": status, "reason": " ".join(reason.split())[:200], "covered_lines": covered,
            "executable_lines": total, "ratio": covered / total if total else None,
            "uncovered_ranges": ranges or {}, "unmeasured": unmeasured or []}


def run_diff_coverage(root: Any, base: str, head: str) -> dict[str, Any]:
    """Measure the changed lines of ``base..head`` (see the module docstring)."""
    root = Path(root).resolve()
    args = testexec.pytest_args(testexec.user_test_command(root) or list(testexec.DEFAULT_COMMAND))
    if args is None:
        return _result("unverified", "tests.command is not pytest-based")
    changed = changed_lines(root, base, head)
    if changed is None:
        return _result("unverified", f"cannot diff {base}..{head}")
    if not changed:
        return _result("reported", "no Python line changed")
    mismatch = _checkout_mismatch(root, head)
    if mismatch is not None:
        return _result("unverified", mismatch)
    try:
        scratch = tempfile.TemporaryDirectory(dir=storage.state_dir(root))
    except (PathTraversalError, OSError) as exc:
        return _result("unverified", f"cannot use the state directory: {exc}")
    with scratch as tmp:
        rcfile, report = Path(tmp) / "empty.coveragerc", Path(tmp) / "coverage.json"
        storage.atomic_write_bytes(rcfile, b"")
        env = {**os.environ, "COVERAGE_FILE": str(Path(tmp) / ".coverage")}
        if sys.version_info >= (3, 12):
            env["COVERAGE_CORE"] = "sysmon"
        coverage = [sys.executable, "-m", "coverage"]
        run = run_external_cmd([*coverage, "run", f"--rcfile={rcfile}", "-m", "pytest", *args, "-p", "no:cacheprovider",
                                "-o", "addopts="], cwd=root, env=env, timeout=testexec.DEFAULT_TIMEOUT_S)
        if run.get("timed_out"):
            return _result("unverified", "the coverage run timed out")
        dump = run_external_cmd([*coverage, "json", f"--rcfile={rcfile}", "-o", str(report)], cwd=root, env=env,
                                timeout=_JSON_TIMEOUT_S)
        try:
            files = {str(k).replace("\\", "/"): v for k, v in json.loads(report.read_text(encoding="utf-8"))["files"].items()}
            covered = total = 0
            ranges: dict[str, list[list[int]]] = {}
            unmeasured: list[str] = []
            for path, lines in sorted(changed.items()):
                if not isinstance(files.get(path), dict):
                    unmeasured.append(path)
                    continue
                executed = set(files[path].get("executed_lines") or ())
                candidates = lines & (executed | set(files[path].get("missing_lines") or ()))
                covered, total = covered + len(candidates & executed), total + len(candidates)
                if candidates - executed:
                    ranges[path] = _to_ranges(candidates - executed)
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            last = (run.get("stderr") or dump.get("stderr") or "").strip().splitlines()
            return _result("unverified", "the coverage json timed out" if dump.get("timed_out")
                           else last[-1] if last else "coverage wrote no readable report")
    reason = "" if run.get("returncode") == 0 else f"pytest exited {run.get('returncode')}"
    return _result("reported", reason, covered, total, ranges, unmeasured)
