"""Running the user's test command hermetically: the one test-execution service shared by
``aegis check --record`` and its trailer rerun (``aegis_core.checkrun``), T5's fail-to-pass runs
(``aegis_core.regression``), mutation testing and diff coverage.

The test command comes from the **user-scope** config (``~/.aegis/config.json``
``tests.command``, a string or an argv list), never from the repository: a repository must not
choose what the verifier executes. The default is ``python -m pytest``. A command whose first word
is a Python interpreter runs under that interpreter when the word is an absolute path, else under
the interpreter that runs Aegis; a first word ``pytest`` (or ``py.test``, any path) runs as
``python -m pytest`` under the interpreter that runs Aegis. Either way the interpreter gets
``-s --check-hash-based-pycs always`` (its own site dirs stay visible, the user site does not), and
a pytest run also gets ``-p no:cacheprovider -o addopts=`` and a JUnit file. Everything runs with a
fixed environment (no ``PYTHON*``, no ``PYTEST_*``, a redirected ``HOME``), no stdin, closed
descriptors and a process-group timeout; on POSIX the group is killed when the run ends, so nothing
it left behind keeps writing. On Windows the group is killed while the run is alive; descendants a
test run leaves behind after a normal exit are not swept.
"""
from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Any, Dict, FrozenSet, List, Mapping, NamedTuple, Optional, Sequence, Set, Tuple, Union

from aegis_core.config import read_user_config
from aegis_core.primitives import is_within
from aegis_core.storage import read_tail_bytes

__all__ = [
    "DEFAULT_COMMAND",
    "DEFAULT_TIMEOUT_S",
    "PytestOutcome",
    "TestsRun",
    "command_digest",
    "env_class",
    "hermetic_env",
    "kill_group",
    "parse_junit_cases",
    "plan_command",
    "python_module_index",
    "pytest_args",
    "run_pytest_snapshot",
    "run_tests",
    "user_test_command",
]

DEFAULT_TIMEOUT_S = 1800.0
DEFAULT_COMMAND = ("python", "-m", "pytest")
_PYTHON_FLAGS = ("-s", "--check-hash-based-pycs", "always")
_PYTEST_FLAGS = ("-p", "no:cacheprovider", "-o", "addopts=")
_HERMETIC = "hermetic-v1"
_MAX_JUNIT_BYTES = 8 * 1024 * 1024
_TAIL_BYTES = 256 * 1024
_PYTHON_NAME = re.compile(r"python[0-9.]*(?:\.exe)?", re.IGNORECASE)
_PYTEST_NAME = re.compile(r"py\.?test(?:\.exe)?", re.IGNORECASE)
_NO_PYTEST = re.compile(r"No module named '?pytest'?")
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
    pytest_missing: bool = False  # not recorded: it only feeds the ``hint`` of ``aegis check --record``
    complete: bool = True

    @property
    def evidence(self) -> bool:
        """Evidence needs a complete structured report, a clean exit and at least one pass."""
        return self.complete and self.exit == 0 and not self.timed_out and self.passed > 0 and self.failed == 0

    def as_dict(self) -> Dict[str, Any]:
        return {"exit": self.exit, "timed_out": self.timed_out, "collected": self.collected, "passed": self.passed,
                "failed": self.failed, "skipped": self.skipped, "deselected": self.deselected,
                "nodeid_digest": self.nodeid_digest, "duration_s": round(self.duration_s, 3),
                "complete": self.complete}


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


def python_module_index(words: Sequence[str]) -> int:
    """Actual ``-m`` index in interpreter arguments (excluding the executable), or -1.

    Stop at a script, code, stdin, ``--`` or an unknown option; consume values of
    supported argument-bearing options before looking for the module selector.
    """
    index = 0
    while index < len(words):
        word = words[index]
        if word == "-m":
            return index
        if word in ("-c", "--", "-") or not word.startswith("-"):
            break
        if word in ("-W", "-X", "--check-hash-based-pycs"):
            index += 2
        elif word.startswith(("-W", "-X", "--check-hash-based-pycs=")) or word in (
                "-b", "-bb", "-B", "-d", "-E", "-i", "-I", "-O", "-OO", "-P", "-q", "-R", "-s", "-S",
                "-u", "-v", "-vv", "-x"):
            index += 1
        else:
            break
    return -1


def plan_command(logical: Optional[Sequence[str]], junit: Optional[Path] = None) -> Tuple[List[str], List[str]]:
    """``(argv to execute, logical command)``: the logical command is machine-independent (the
    digest is taken from it), the argv has the absolute interpreter and the fixed flags."""
    words = list(logical) if logical else list(DEFAULT_COMMAND)
    expanded = [word.replace("{junit}", str(junit)) if junit is not None else word for word in words]
    first = os.path.basename(words[0].replace("\\", "/"))
    if _PYTEST_NAME.fullmatch(first):
        # A pytest launcher (even an absolute venv one) runs under Aegis's interpreter: guessing a
        # sibling python from its path would let the path choose the interpreter.
        python, rest = sys.executable, ["-m", "pytest", *expanded[1:]]
    elif _PYTHON_NAME.fullmatch(first):
        # Only the user-scope config reaches here, so an absolute interpreter is the user's choice.
        python, rest = (expanded[0] if os.path.isabs(expanded[0]) else sys.executable), expanded[1:]
    else:
        return expanded, words
    module_at = python_module_index(rest)
    module_name = rest[module_at + 1:module_at + 2] if module_at >= 0 else []
    if junit is not None and module_name == ["unittest"]:
        from aegis_core import unittest_runner

        rest = [*rest[:module_at], "-I", str(Path(unittest_runner.__file__).resolve()), str(junit),
                *rest[module_at + 2:]]
    argv = [python, *_PYTHON_FLAGS, *rest]
    if module_name == ["pytest"]:
        argv += list(_PYTEST_FLAGS)
        if junit is not None:
            argv.append(f"--junitxml={junit}")
    return argv, words


def pytest_args(words: Sequence[str]) -> Optional[List[str]]:
    """The arguments a pytest-based command gives pytest (after ``-m pytest``, or after a first word
    ``pytest``/``py.test``); None for any other command."""
    first = os.path.basename(words[0].replace("\\", "/")) if words else ""
    if _PYTEST_NAME.fullmatch(first):
        return list(words[1:])
    rest = list(words[1:])
    at = python_module_index(rest)
    return rest[at + 2:] if _PYTHON_NAME.fullmatch(first) and at >= 0 and rest[at + 1:at + 2] == ["pytest"] else None


def command_digest(logical: Sequence[str]) -> str:
    blob = json.dumps([_HERMETIC, list(logical)], ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


def env_class() -> str:
    """The kind of machine the run happened on: runs on different classes are not the same experiment."""
    import platform

    return f"{platform.system().lower()}-py{sys.version_info[0]}.{sys.version_info[1]}"


def hermetic_env(
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


# ── Running it ───────────────────────────────────────────────────────────────

def _taskkill() -> str:
    root = os.environ.get("SystemRoot", "")
    return ntpath.join(root if ntpath.isabs(root) else "C:\\Windows", "System32", "taskkill.exe")


def kill_group(proc: "subprocess.Popen[Any]") -> None:
    if os.name == "nt":
        # taskkill /T addresses a pid, which is reusable once the root has exited, so an exited
        # root is left alone and its orphans are not swept (documented in the module docstring).
        if getattr(proc, "poll", lambda: None)() is not None:
            return
        subprocess.run([_taskkill(), "/T", "/F", "/PID", str(proc.pid)], capture_output=True, check=False)
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


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


@dataclass(frozen=True)
class _JunitReport:
    tests: int
    passed: int
    failed: int
    skipped: int
    digest: str
    passed_ids: Set[str]
    failed_ids: Set[str]
    collection_errors: List[str]
    complete: bool
    structurally_valid: bool


def _junit_complete(root: ET.Element, cases: List[ET.Element]) -> bool:
    """Check declared counts, identities and terminal states before certifying a report."""
    ids = [f"{case.get('classname', '').strip()}::{case.get('name', '').strip()}"
           if case.get('classname', '').strip() else case.get('name', '').strip() for case in cases]
    if root.tag not in ("testsuite", "testsuites") or len(ids) != len(set(ids)):
        return False
    parents = {child: parent for parent in root.iter() for child in parent}
    for case in cases:
        terminal = [child.tag for child in case if child.tag in ("failure", "error", "skipped")]
        if (not case.get("name", "").strip() or len(terminal) > 1
                or case.get("status", "") not in ("", "run") or parents[case].tag != "testsuite"):
            return False
    for suite in root.iter():
        if suite.tag not in ("testsuite", "testsuites"):
            continue
        if suite is not root and (suite.tag == "testsuites" or parents[suite].tag not in ("testsuite", "testsuites")):
            return False
        if suite.tag == "testsuite" and suite.get("tests") is None:
            return False
        children = list(suite.iter("testcase"))
        suite_errors = {tag: sum(len(s.findall(tag)) for s in suite.iter("testsuite"))
                        for tag in ("failure", "error")}
        totals = [len(children), *(sum(case.find(status) is not None for case in children) + suite_errors.get(status, 0)
                                  for status in ("failure", "error", "skipped"))]
        for attr, total in zip(("tests", "failures", "errors", "skipped"), totals):
            value = suite.get(attr)
            if value is not None and (not value.isascii() or not value.isdecimal()
                                      or len(value) > 7 or int(value) != total):
                return False
    return True


def _inspect_junit(path: Path) -> Optional[_JunitReport]:
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > _MAX_JUNIT_BYTES
                or getattr(before, "st_file_attributes", 0) & 0x400):
            return None
        flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_BINARY", 0))
        with os.fdopen(os.open(path, flags), "rb") as source:
            opened = os.fstat(source.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
                return None
            raw = source.read(_MAX_JUNIT_BYTES + 1)
        if len(raw) > _MAX_JUNIT_BYTES:
            return None
        parser = ET.XMLPullParser(events=("start", "end"))
        root, depth, elements = None, 0, 0
        for offset in range(0, len(raw), 8192):
            parser.feed(raw[offset:offset + 8192])
            for event, element in parser.read_events():
                if event == "start":
                    root = element if root is None else root
                    depth, elements = depth + 1, elements + 1
                    if depth > 128 or elements > 100_000:
                        return None
                else:
                    depth -= 1
        parser.close()
        if root is None:
            return None
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
    valid = _junit_complete(root, cases)
    return _JunitReport(len(cases), passed_count, failed_count, skipped_count, digest, passed_ids, failed_ids,
                        col_errors, not col_errors and valid, valid)


def parse_junit_cases(path: Path) -> Tuple[Set[str], Set[str], List[str]]:
    """Export identities only from structurally valid reports, including collection failures."""
    report = _inspect_junit(path)
    if report is None or not report.structurally_valid:
        return set(), set(), []
    return report.passed_ids, report.failed_ids, report.collection_errors


def run_tests(argv: Sequence[str], cwd: Path, env: Mapping[str, str], timeout: float, junit: Path,
              output: Path, *, stderr_output: Optional[Path] = None) -> TestsRun:
    """Run ``argv`` in ``cwd`` with ``env`` and nothing else inherited; kill the process group at
    the end, whatever happened (on Windows only while the root is alive, see the module docstring).
    Diagnostics remain merged unless a separate stderr output path is supplied."""
    started = datetime.now(timezone.utc)
    if shutil.which(argv[0], path=env.get("PATH")) is None and not os.path.isabs(argv[0]):
        return TestsRun(exit=127, complete=False)
    kwargs: Dict[str, Any] = {}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    timed_out = False
    with open(output, "wb") as sink, (
            open(stderr_output, "wb") if stderr_output is not None else nullcontext(subprocess.STDOUT)) as errors:
        try:
            proc = subprocess.Popen(list(argv), cwd=str(cwd), env=dict(env), stdin=subprocess.DEVNULL, stdout=sink,
                                    stderr=errors, close_fds=True, **kwargs)
        except OSError:
            return TestsRun(exit=127, complete=False)
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            kill_group(proc)
            code = proc.wait()
        finally:
            kill_group(proc)
    text = _tail(output)
    counts = _summary(text)
    report = _inspect_junit(junit) if junit.is_file() else None
    if report is not None:
        collected, passed, failed, skipped, digest = (report.tests, report.passed, report.failed, report.skipped,
                                                      report.digest)
    else:
        passed, failed, skipped = counts.get("passed", 0), counts.get("failed", 0), counts.get("skipped", 0)
        collected = passed + failed + skipped + counts.get("xfailed", 0) + counts.get("xpassed", 0)
        digest = None
    seconds = (datetime.now(timezone.utc) - started).total_seconds()
    return TestsRun(exit=code, timed_out=timed_out, collected=collected, passed=passed, failed=failed,
                    skipped=skipped, deselected=counts.get("deselected", 0), nodeid_digest=digest, duration_s=seconds,
                    pytest_missing=bool(_NO_PYTEST.search(text)), complete=report is not None and report.complete)


class PytestOutcome(NamedTuple):
    exit_code: int
    timed_out: bool
    passed_ids: FrozenSet[str]
    failed_ids: FrozenSet[str]
    collection_errors: FrozenSet[str]
    reason: Optional[str] = None


# T5's run (aegis_core.regression): pytest from the interpreter that runs Aegis, isolated (-I -S), on a
# snapshot. Without --continue-on-collection-errors one module that cannot import on base stops the whole
# session and hides every other module's base result.
_SNAPSHOT_PYTHON_FLAGS = ("-I", "-S", "-B", "--check-hash-based-pycs", "always")
_SNAPSHOT_PYTEST_FLAGS = ("-p", "no:cacheprovider", "-o", "addopts=", "--continue-on-collection-errors")
# ``within`` is primitives.key_within over realpath keys: the -I -S child cannot import aegis.
_SNAPSHOT_RUNNER = (
    "import json, os, sys\n"
    "snap, ws, ext = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2]), json.loads(sys.argv[3])\n"
    "key = lambda p: os.path.normcase(os.path.realpath(p))\n"
    "within = lambda p, d: key(p) == key(d) or key(p).startswith(key(d).rstrip(os.sep) + os.sep)\n"
    "sys.path[:] = [snap] + [p for p in (*sys.path, *ext) if p and p != snap and (within(p, snap) or not within(p, ws))]\n"
    "import pytest\n"
    "raise SystemExit(pytest.main(sys.argv[4:]))\n"
)


def run_pytest_snapshot(snapshot: Path, test_files: Sequence[str], workspace: Path, scratch: Path,
                        timeout: float) -> PytestOutcome:
    """Run pytest on ``test_files`` of ``snapshot`` with the hermetic environment: this interpreter's
    ``sys.path`` entries stay importable (pytest itself) except those inside ``workspace`` (an editable
    install of the live tree), so the snapshot's copy of the code is the one imported."""
    home, tmp, junit = scratch / "home", scratch / "tmp", scratch / "junit.xml"
    home.mkdir(parents=True, exist_ok=True)
    tmp.mkdir(parents=True, exist_ok=True)
    ws, snap = workspace.resolve(), snapshot.resolve()
    ext_dirs = [d for d in (str(Path(p).resolve()) for p in sys.path if p and Path(p).is_dir())
                if not is_within(d, ws, unresolvable=True)]
    # The snapshot as rootdir makes a test's JUnit classname its dotted path from the tree root. The cwd is
    # the same string: Windows keeps a cwd as spelled (an 8.3 short TEMP), and pytest cannot relate a test
    # path under a second spelling to the rootdir, so the classname would come out empty.
    argv = [sys.executable, *_SNAPSHOT_PYTHON_FLAGS, "-c", _SNAPSHOT_RUNNER, str(snap), str(ws), json.dumps(ext_dirs),
            *_SNAPSHOT_PYTEST_FLAGS, f"--rootdir={snap}", f"--junitxml={junit}", "--", *test_files]
    res = run_tests(argv, snap, hermetic_env(home, tmp), timeout, junit, scratch / "output.txt")
    passed, failed, col_errors = parse_junit_cases(junit)
    reason = "incomplete_test_output" if not res.complete and not col_errors else None
    return PytestOutcome(res.exit, res.timed_out, frozenset(passed), frozenset(failed), frozenset(col_errors), reason)
