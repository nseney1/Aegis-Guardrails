"""``aegis check --record``: the hermetic snapshot run and the ledger ``check`` row (v4.3 spec §3 T1).

One run is bound to one tree (``aegis_core.treeid``). The files of that tree are exported to a
private snapshot and Layer 1 and, with ``tests=True``, the project's tests run *there*, so a file
swapped in the work tree mid-run, or an ignored file the tests quietly import, cannot change what
was verified. A tree holding any symbolic link is refused (``unbindable``, no row): a link can
point the run back at files outside the snapshot. What it records is a **label**: a same-uid
agent can write any row, so a ``check`` row is evidence only once CI on the landing commit
confirms it (``aegis_core.credit``).

The test command comes from the **user-scope** config (``~/.aegis/config.json``
``tests.command``, a string or an argv list), never from the repository: a repository must not
choose what the verifier executes. The default is ``python -m pytest``. A command whose first word
is a Python interpreter is run with the absolute interpreter that runs Aegis and
``-s --check-hash-based-pycs always``; a pytest run also gets ``-p no:cacheprovider -o addopts=``
and a JUnit file. Everything runs with a fixed environment (no ``PYTHON*``, no ``PYTEST_*``, a
redirected ``HOME``), no stdin, closed descriptors and a process-group timeout; the group is
killed when the run ends, so nothing it left behind keeps writing.

``exit 5`` (no tests collected) and ``passed == 0`` are never evidence, and neither is a run that
timed out or a Layer 1 finding.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple, Union

from aegis_core import gitsafe, governance, treeid
from aegis_core._version import __version__
from aegis_core.config import read_user_config
from aegis_core.errors import AegisError
from aegis_core.storage import ledger_locked, read_jsonl, read_tail_bytes
from aegis_core.telemetry_engine import ledger

__all__ = [
    "DEFAULT_TIMEOUT_S",
    "CheckOutcome",
    "TestsRun",
    "env_class",
    "hermetic_env",
    "kill_group",
    "parse_junit",
    "parse_junit_cases",
    "plan_command",
    "record",
    "rerun_commit_snapshot",
    "user_test_command",
    "verify_commit_trailers",
]

DEFAULT_TIMEOUT_S = 1800.0
DEFAULT_COMMAND = ("python", "-m", "pytest")
_PYTHON_FLAGS = ("-s", "--check-hash-based-pycs", "always")
_PYTEST_FLAGS = ("-p", "no:cacheprovider", "-o", "addopts=")
_HERMETIC = "hermetic-v1"
_MAX_JUNIT_BYTES = 8 * 1024 * 1024
_TAIL_BYTES = 256 * 1024
_PYTHON_NAME = re.compile(r"python[0-9.]*(?:\.exe)?", re.IGNORECASE)
_COUNT = re.compile(r"(\d+) (passed|failed|errors?|skipped|deselected|xfailed|xpassed)")


@dataclass(frozen=True)
class TestsRun:
    """What one test run produced."""

    __test__ = False  # not a pytest class

    exit: int
    timed_out: bool = False
    collected: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    deselected: int = 0
    nodeid_digest: Optional[str] = None
    duration_s: float = 0.0

    @property
    def evidence(self) -> bool:
        """A run is evidence only when it exited 0 in time and at least one test passed."""
        return self.exit == 0 and not self.timed_out and self.passed > 0

    def as_dict(self) -> Dict[str, Any]:
        return {"exit": self.exit, "timed_out": self.timed_out, "collected": self.collected, "passed": self.passed,
                "failed": self.failed, "skipped": self.skipped, "deselected": self.deselected,
                "nodeid_digest": self.nodeid_digest, "duration_s": round(self.duration_s, 3)}


@dataclass
class CheckOutcome:
    """``recorded`` (a row was written; ``row`` holds it), ``unbindable`` (no tree, no row) or
    ``error`` (nothing could be run or written)."""

    status: str
    row: Optional[Dict[str, Any]] = None
    reason: str = ""
    binding: Optional[treeid.TreeBinding] = None


# ── The command ──────────────────────────────────────────────────────────────

def user_test_command(workspace: Path) -> Optional[List[str]]:
    """``tests.command`` of the user-scope config as an argv list, or None when unset or unusable."""
    raw = read_user_config(workspace)
    tests = raw.get("tests") if raw else None
    command = tests.get("command") if isinstance(tests, dict) else None
    if isinstance(command, str) and command.strip():
        try:
            words = shlex.split(command, posix=os.name != "nt")
        except ValueError:
            return None
        return words or None
    if isinstance(command, list) and command and all(isinstance(w, str) and w for w in command):
        return list(command)
    return None


def plan_command(logical: Optional[Sequence[str]], junit: Optional[Path] = None) -> Tuple[List[str], List[str]]:
    """``(argv to execute, logical command)``: the logical command is machine-independent (the
    digest is taken from it), the argv has the absolute interpreter and the fixed flags."""
    words = list(logical) if logical else list(DEFAULT_COMMAND)
    argv = list(words)
    if _PYTHON_NAME.fullmatch(os.path.basename(words[0])):
        argv = [sys.executable, *_PYTHON_FLAGS, *words[1:]]
        if "-m" in words and words[words.index("-m") + 1:words.index("-m") + 2] == ["pytest"]:
            argv += list(_PYTEST_FLAGS)
            if junit is not None:
                argv.append(f"--junitxml={junit}")
    return argv, words


def command_digest(logical: Sequence[str]) -> str:
    blob = json.dumps([_HERMETIC, list(logical)], ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


def env_class() -> str:
    """The kind of machine the run happened on: runs on different classes are not the same experiment."""
    import platform

    return f"{platform.system().lower()}-py{sys.version_info[0]}.{sys.version_info[1]}"


def _hermetic_env(
    home: Union[str, os.PathLike[str]],
    scratch: Optional[Union[str, os.PathLike[str]]] = None,
) -> Dict[str, str]:
    home_str = os.fspath(home)
    scratch_str = os.fspath(scratch) if scratch is not None else home_str
    if os.name == "nt":
        system = os.environ.get("SystemRoot", r"C:\Windows")
        return {
            "PATH": rf"{system}\System32;{system}",
            "SystemRoot": system,
            "HOME": home_str,
            "USERPROFILE": home_str,
            "TEMP": scratch_str,
            "TMP": scratch_str,
        }
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": home_str,
        "TMPDIR": scratch_str,
        "LC_ALL": "C",
    }


hermetic_env = _hermetic_env


# ── Running it ───────────────────────────────────────────────────────────────

def _kill_group(proc: "subprocess.Popen[Any]") -> None:
    if os.name == "nt":
        if getattr(proc, "poll", lambda: None)() is not None:
            return
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True, check=False)
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


kill_group = _kill_group


def _tail(path: Path) -> str:
    return read_tail_bytes(path, _TAIL_BYTES).decode("utf-8", "replace")


def _summary(text: str) -> Dict[str, int]:
    for line in reversed(text.splitlines()):
        if not re.search(r"\bin [0-9.]+s\b", line):
            continue
        counts: Dict[str, int] = {}
        for number, word in _COUNT.findall(line):
            word = "failed" if word.startswith("error") else word
            counts[word] = counts.get(word, 0) + int(number)
        if counts or "no tests ran" in line:
            return counts
    return {}


def _inspect_junit(
    path: Path,
) -> Optional[Tuple[int, int, int, int, str, Set[str], Set[str], List[str]]]:
    try:
        if not path.is_file() or path.stat().st_size > _MAX_JUNIT_BYTES:
            return None
        raw = path.read_bytes()
        if len(raw) > _MAX_JUNIT_BYTES:
            return None
        root = ET.fromstring(raw)
    except (OSError, ET.ParseError):
        return None
    col_errors: List[str] = []
    suites = [root] if root.tag == "testsuite" else []
    suites.extend(el for el in root.iter("testsuite") if el is not root)
    for suite in suites:
        if suite.find("error") is not None or suite.find("failure") is not None:
            col_errors.append(f"<suite:{suite.attrib.get('name', 'testsuite')}>")
    cases = list(root.iter("testcase"))
    failed_count = 0
    skipped_count = 0
    ids: List[str] = []
    passed_ids: Set[str] = set()
    failed_ids: Set[str] = set()
    for case in cases:
        raw_cls = case.get("classname", "")
        raw_name = case.get("name", "")
        ids.append(f"{raw_cls}::{raw_name}")
        cls = (raw_cls or "").strip()
        name = (raw_name or "").strip()
        err = case.find("error")
        fail = case.find("failure")
        skip = case.find("skipped")
        if fail is not None or err is not None:
            failed_count += 1
        elif skip is not None:
            skipped_count += 1
        if err is not None and (not cls or err.get("message") == "collection failure"):
            col_errors.append(name or cls or "<collection>")
        elif name and (fail is not None or err is not None or skip is None):
            nodeid = f"{cls}::{name}" if cls else name
            if fail is not None or err is not None:
                failed_ids.add(nodeid)
            else:
                passed_ids.add(nodeid)
    digest = hashlib.sha256("\n".join(sorted(ids)).encode("utf-8", "replace")).hexdigest()
    passed_count = len(cases) - failed_count - skipped_count
    return len(cases), passed_count, failed_count, skipped_count, digest, passed_ids, failed_ids, col_errors


def _parse_junit(path: Path) -> Optional[Tuple[int, int, int, int, str]]:
    """``(tests, passed, failed, skipped, nodeid digest)`` from a JUnit file, or None."""
    inspected = _inspect_junit(path)
    if inspected is None:
        return None
    return inspected[:5]


_junit = _parse_junit
parse_junit = _parse_junit


def parse_junit_cases(path: Path) -> Tuple[Set[str], Set[str], List[str]]:
    """``(passed_ids, failed_ids, collection_errors)`` from a JUnit file."""
    inspected = _inspect_junit(path)
    if inspected is None:
        return set(), set(), []
    return inspected[5], inspected[6], inspected[7]


def run_tests(argv: Sequence[str], cwd: Path, env: Mapping[str, str], timeout: float, junit: Path,
              output: Path) -> TestsRun:
    """Run ``argv`` in ``cwd`` with ``env`` and nothing else inherited; kill the process group at
    the end, whatever happened."""
    started = datetime.now(timezone.utc)
    if shutil.which(argv[0], path=env.get("PATH")) is None and not os.path.isabs(argv[0]):
        return TestsRun(exit=127)
    kwargs: Dict[str, Any] = {}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    timed_out = False
    with open(output, "wb") as sink:
        try:
            proc = subprocess.Popen(list(argv), cwd=str(cwd), env=dict(env), stdin=subprocess.DEVNULL, stdout=sink,
                                    stderr=subprocess.STDOUT, close_fds=True, **kwargs)
        except OSError:
            return TestsRun(exit=127)
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(proc)
            code = proc.wait()
        finally:
            _kill_group(proc)
    text = _tail(output)
    counts = _summary(text)
    parsed = _parse_junit(junit) if junit.is_file() else None
    if parsed is not None:
        collected, passed, failed, skipped, digest = parsed
    else:
        passed, failed, skipped = counts.get("passed", 0), counts.get("failed", 0), counts.get("skipped", 0)
        collected = passed + failed + skipped + counts.get("xfailed", 0) + counts.get("xpassed", 0)
        digest = None
    seconds = (datetime.now(timezone.utc) - started).total_seconds()
    return TestsRun(exit=code, timed_out=timed_out, collected=collected, passed=passed, failed=failed,
                    skipped=skipped, deselected=counts.get("deselected", 0), nodeid_digest=digest, duration_s=seconds)


# ── The record ───────────────────────────────────────────────────────────────

def _stamp(moment: Optional[datetime]) -> str:
    return (moment or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _layer1(snapshot: Path, changed: Sequence[str]) -> Dict[str, int]:
    from aegis_core import baseline

    targets = baseline.checkable(snapshot, [p for p in changed if (snapshot / p).is_file()])
    if not targets:
        return {"findings": 0, "files": 0}
    pairs, _sources = baseline.run_fast(snapshot, targets)
    return {"findings": sum(1 for _path, evidence in pairs if not evidence.verdict), "files": len(targets)}


def record(root: object, *, tests: bool = False, base: Optional[str] = None, timeout: Optional[float] = None,
           now: Optional[datetime] = None) -> CheckOutcome:
    """Bind the work tree of ``root`` to a tree, run the checks on its snapshot, write one ``check``
    row to the ledger. See the module docstring for what the row is worth."""
    workspace = Path(os.fspath(root)).resolve()
    try:
        with treeid.bind(workspace) as bound:
            binding = bound.binding
            if not binding.bound:
                return CheckOutcome("unbindable", None, binding.reason, binding)
            links = sorted(bound.symlinks())
            if links:
                named = ", ".join(links[:5]) + (f" and {len(links) - 5} more" if len(links) > 5 else "")
                return CheckOutcome("unbindable", None, f"the tree holds symbolic links, which the snapshot refuses: "
                                    f"{named}", binding)
            top = bound.top
            head = gitsafe.head_commit(top)
            if not head:
                return CheckOutcome("error", None, "the repository has no commit yet", binding)
            base_ref = base or gitsafe.resolve_base_ref(top)
            if not base_ref:
                return CheckOutcome("error", None, "no base branch found (origin/main, main, origin/develop, "
                                    "develop); pass --base", binding)
            base_commit = gitsafe.merge_base(top, base_ref, "HEAD")
            if not base_commit:
                return CheckOutcome("error", None, f"HEAD shares no history with {base_ref}: fetch with "
                                    "fetch-depth 0", binding)
            entries = bound.diff_entries(base_commit)
            changed = [path for status, path in entries if status != "D"]
            protected = governance.touches_governance(changed, [path for status, path in entries if status == "D"])
            scratch = Path(tempfile.mkdtemp(prefix="aegis-check-"))
            try:
                snapshot = scratch / "snapshot"
                bound.export(snapshot)
                layer1 = _layer1(snapshot, changed)
                run: Optional[TestsRun] = None
                logical = list(DEFAULT_COMMAND)
                if tests:
                    junit = scratch / "junit.xml"
                    argv, logical = plan_command(user_test_command(workspace), junit)
                    home = scratch / "home"
                    tmp = scratch / "tmp"
                    home.mkdir(mode=0o700)
                    tmp.mkdir(mode=0o700)
                    run = run_tests(argv, snapshot, _hermetic_env(home, tmp),
                                    DEFAULT_TIMEOUT_S if timeout is None else timeout, junit, scratch / "output.txt")
            finally:
                shutil.rmtree(scratch, ignore_errors=True)
    except treeid.TreeError as exc:
        return CheckOutcome("error", None, str(exc))
    except gitsafe.GitError as exc:
        return CheckOutcome("error", None, str(exc))

    stamp = _stamp(now)
    layer1_ok = layer1["findings"] == 0
    tests_ok = run is None or run.evidence
    passed = layer1_ok and tests_ok
    exit_code = run.exit if run is not None else 0
    if exit_code == 0 and not layer1_ok:
        exit_code = 1
    digest = command_digest(logical) if tests else command_digest(["layer1"])
    row: Dict[str, Any] = {
        "v": ledger.LEDGER_VERSION, "ts": stamp, "event": "check", "witness": "aegis",
        "source": "aegis check --record", "aegis_version": __version__, "checked_at": stamp,
        "scope": {"tree": binding.tree, "base": base_commit},
        "tree": binding.tree, "head": head, "base": base_commit, "tree_algo": treeid.TREE_ALGO,
        "cmd_digest": digest, "layer1": layer1, "tests": run.as_dict() if run is not None else None,
        "env_class": env_class(), "protected_changed": bool(protected), "protected": protected,
        "partial": binding.status == "partial", "gitlinks": list(binding.gitlinks),
        "passed": passed, "exit": exit_code,
    }
    with ledger_locked(workspace):
        earlier = [r for r in read_jsonl(ledger.ledger_path(workspace)).rows
                   if r.get("event") == "check" and r.get("tree") == binding.tree and r.get("cmd_digest") == digest]
        row["run_ordinal"] = len(earlier) + 1
        # The ordinal keeps two runs of one tree in one second apart; the id is how reports name a check.
        identity = f"{binding.tree}|{digest}|{row['run_ordinal']}|{stamp}|{head}"
        row["id"] = hashlib.sha256(identity.encode("ascii")).hexdigest()[:16]
        ledger.append_rows(workspace, [row])
    return CheckOutcome("recorded", row, "", binding)


def rerun_commit_snapshot(
    root: object, commit: str, base_ref: str, *, timeout: Optional[float] = None,
) -> Dict[str, Any]:
    """Export ``commit``'s tree into an isolated snapshot and rerun Layer 1 and snapshot tests."""
    from aegis_core import regression

    workspace = Path(os.fspath(root)).resolve()
    top = gitsafe.toplevel(workspace)
    commit = gitsafe.resolve_commit(top, commit) if top is not None else None  # only an oid reaches git argv
    if commit is None:
        return {"tree": "", "exit": 1}
    commit_tree = gitsafe.run(["rev-parse", f"{commit}^{{tree}}"], top).stdout.decode("ascii", "replace").strip()
    base_commit = gitsafe.merge_base(top, base_ref, commit) or gitsafe.resolve_commit(top, base_ref) or commit
    entries = gitsafe.diff_entries(top, base_commit, commit)
    changed = [p for s, _o, _n, p in entries if s != "D"]
    tree_entries = gitsafe.tree_blobs(top, commit)
    scratch = Path(tempfile.mkdtemp(prefix="aegis-trailer-rerun-"))
    try:
        snapshot = scratch / "snapshot"
        gitsafe.export_tree(top, commit, snapshot)
        layer1 = _layer1(snapshot, changed)
        user_cmd = user_test_command(workspace)
        tests_ok = True
        raw_exit = 0
        if user_cmd is not None:
            junit = scratch / "junit.xml"
            home = scratch / "home"
            tmp = scratch / "tmp"
            home.mkdir(mode=0o700)
            tmp.mkdir(mode=0o700)
            argv, _ = plan_command(user_cmd, junit)
            run = run_tests(argv, snapshot, _hermetic_env(home, tmp), timeout or 120.0, junit, scratch / "output.txt")
            tests_ok = run.evidence
            raw_exit = run.exit
        else:
            t_files = sorted(p for p in tree_entries if regression.is_test_file(p) and (snapshot / p).is_file())
            if t_files:
                out = regression._run_pytest_in_snapshot(snapshot, t_files, workspace, scratch, timeout or 120.0)
                tests_ok = out.exit_code == 0 and bool(out.passed_ids) and not out.failed_ids and not out.collection_errors
                raw_exit = out.exit_code
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    passed = layer1["findings"] == 0 and tests_ok
    return {"tree": commit_tree, "exit": 0 if passed else (raw_exit if raw_exit != 0 else 1)}


def verify_commit_trailers(
    root: object, base: str, head: str = "HEAD", *,
    rerun_fn: Optional[ Any ] = None, timeout: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """Verify ``Aegis-Check`` trailers on commits in ``base..head`` by rerunning each commit's snapshot."""
    from aegis_core import credit

    runner = rerun_fn or (lambda c, _t: rerun_commit_snapshot(root, c, base, timeout=timeout))
    return credit.verify_commit_trailers(root, base, head, rerun_fn=runner)
