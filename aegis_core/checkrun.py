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
is a Python interpreter runs under that interpreter when the word is an absolute path, else under
the interpreter that runs Aegis; a first word ``pytest`` (or ``py.test``, any path) runs as
``python -m pytest`` under the interpreter that runs Aegis. Either way the interpreter gets
``-s --check-hash-based-pycs always`` (its own site dirs stay visible, the user site does not), and
a pytest run also gets ``-p no:cacheprovider -o addopts=`` and a JUnit file. Everything runs with a
fixed environment (no ``PYTHON*``, no ``PYTEST_*``, a redirected ``HOME``), no stdin, closed
descriptors and a process-group timeout; on POSIX the group is killed when the run ends, so nothing
it left behind keeps writing. On Windows the group is killed while the run is alive; descendants a
test run leaves behind after a normal exit are not swept.

``exit 5`` (no tests collected) and ``passed == 0`` are never evidence, and neither is a run that
timed out or a Layer 1 finding.
"""
from __future__ import annotations

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
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple, Union

from aegis_core import gitsafe, governance, treeid
from aegis_core._version import __version__
from aegis_core.config import read_user_config
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
    "pytest_args",
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
    hint: str = ""


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
    first = os.path.basename(words[0].replace("\\", "/"))
    if _PYTEST_NAME.fullmatch(first):
        # A pytest launcher (even an absolute venv one) runs under Aegis's interpreter: guessing a
        # sibling python from its path would let the path choose the interpreter.
        python, rest = sys.executable, ["-m", "pytest", *words[1:]]
    elif _PYTHON_NAME.fullmatch(first):
        # Only the user-scope config reaches here, so an absolute interpreter is the user's choice.
        python, rest = (words[0] if os.path.isabs(words[0]) else sys.executable), words[1:]
    else:
        return list(words), words
    argv = [python, *_PYTHON_FLAGS, *rest]
    if "-m" in rest and rest[rest.index("-m") + 1:rest.index("-m") + 2] == ["pytest"]:
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
    at = rest.index("-m") if "-m" in rest else -1
    return rest[at + 2:] if _PYTHON_NAME.fullmatch(first) and at >= 0 and rest[at + 1:at + 2] == ["pytest"] else None


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

def _taskkill() -> str:
    root = os.environ.get("SystemRoot", "")
    return ntpath.join(root if ntpath.isabs(root) else "C:\\Windows", "System32", "taskkill.exe")


def _kill_group(proc: "subprocess.Popen[Any]") -> None:
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
    the end, whatever happened (on Windows only while the root is alive, see the module docstring)."""
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
                    skipped=skipped, deselected=counts.get("deselected", 0), nodeid_digest=digest, duration_s=seconds,
                    pytest_missing=bool(_NO_PYTEST.search(text)))


# ── The record ───────────────────────────────────────────────────────────────

def _stamp(moment: Optional[datetime]) -> str:
    return (moment or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _layer1(snapshot: Path, changed: Sequence[str]) -> Dict[str, int]:
    from aegis_core import baseline

    targets = baseline.checkable(snapshot, [p for p in changed if (snapshot / p).is_file()])
    if not targets:
        return {"findings": 0, "files": 0}
    # The snapshot is a plain directory: git would answer for whatever repository encloses the temp dir,
    # so the snapshot's own rules are enforced (CI's check --ci guards their weakening).
    pairs, _sources = baseline.run_fast(snapshot, targets, reviewed=False)
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
                return CheckOutcome("error", None, "no base branch found (origin/$GITHUB_BASE_REF, the branch "
                                    "origin/HEAD names, main, master or develop); pass --base", binding)
            base_commit = gitsafe.merge_base(top, base_ref, "HEAD")
            if not base_commit:
                return CheckOutcome("error", None, f"HEAD shares no history with {base_ref}: fetch with "
                                    "fetch-depth 0", binding)
            entries = bound.diff_entries(base_commit)
            changed = [path for status, path in entries if status != "D"]
            protected = governance.touches_governance(changed, [path for status, path in entries if status == "D"])
            layer1, run, logical = _snapshot_check(workspace, bound.export, changed, tests, timeout)
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
    hint = ""
    if run is not None and run.collected == 0 and run.pytest_missing:
        hint = ('set "tests.command" in ~/.aegis/config.json to your project\'s Python, for example '
                '["/path/to/.venv/bin/python", "-m", "pytest"]')
    return CheckOutcome("recorded", row, "", binding, hint)


def _snapshot_check(workspace: Path, export_fn: Any, changed: Sequence[str], tests: bool,
                    timeout: Optional[float]) -> Tuple[Dict[str, int], Optional[TestsRun], List[str]]:
    """Export a tree with ``export_fn`` and run Layer 1 and, with ``tests``, the user's test command
    on it: the one recipe ``record`` and the trailer rerun share, so CI falsifies the same check."""
    scratch = Path(tempfile.mkdtemp(prefix="aegis-check-"))
    try:
        snapshot = scratch / "snapshot"
        export_fn(snapshot)
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
        return layer1, run, logical
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def rerun_commit_snapshot(
    root: object, commit: str, base_ref: str, *, timeout: Optional[float] = None,
) -> Dict[str, Any]:
    """Rerun ``record --tests`` on ``commit``'s tree: ``{"tree", "exit"}``, or ``{"tree",
    "inconclusive": True, "reason"}`` when git could not answer or the run timed out."""
    workspace = Path(os.fspath(root)).resolve()
    top = gitsafe.toplevel(workspace)
    commit = gitsafe.resolve_commit(top, commit) if top is not None else None  # only an oid reaches git argv
    if commit is None:
        return {"tree": "", "exit": 1}
    try:
        res = gitsafe.run(["rev-parse", "--verify", "--quiet", f"{commit}^{{tree}}"], top)
        if res.returncode != 0:
            return {"tree": "", "inconclusive": True, "reason": f"could not read the tree of {commit[:12]}"}
        commit_tree = res.stdout.decode("ascii", "replace").strip()
        base_commit = gitsafe.merge_base(top, base_ref, commit)
        if not base_commit:
            return {"tree": "", "inconclusive": True, "reason": f"found no merge-base with {commit[:12]}"}
        changed = [p for s, _o, _n, p in gitsafe.diff_entries(top, base_commit, commit) if s != "D"]
        layer1, run, _logical = _snapshot_check(
            workspace, lambda dest: gitsafe.export_tree(top, commit, dest), changed, True, timeout)
    except gitsafe.GitError as exc:
        return {"tree": "", "inconclusive": True, "reason": f"git could not answer: {exc}"}
    if run is not None and run.timed_out:
        return {"tree": commit_tree, "inconclusive": True, "reason": "timed out"}
    if layer1["findings"] == 0 and run is not None and run.evidence:
        return {"tree": commit_tree, "exit": 0}
    return {"tree": commit_tree, "exit": run.exit if run is not None and run.exit != 0 else 1}


def verify_commit_trailers(
    root: object, base: str, head: str = "HEAD", *,
    rerun_fn: Optional[ Any ] = None, timeout: Optional[float] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> List[Dict[str, Any]]:
    """Verify the ``Aegis-Check`` trailer of the head commit by rerunning its snapshot with the
    ``record --tests`` recipe (``DEFAULT_TIMEOUT_S`` unless ``timeout`` is given). ``progress`` gets one
    line before and one after each rerun (there are at most two)."""
    from aegis_core import credit

    runner = rerun_fn or (lambda c, _t: rerun_commit_snapshot(root, c, base, timeout=timeout))
    say, done = progress or (lambda _line: None), []  # type: Callable[[str], None], List[Mapping[str, Any]]

    def reported(commit: str, tree: str) -> Mapping[str, Any]:
        say(f"Aegis-Check rerun {len(done) + 1} of up to 2: tests.command on commit {commit[:10]} (the whole tree)")
        started = time.monotonic()
        done.append(runner(commit, tree))
        say(f"Aegis-Check rerun {len(done)} of up to 2: {done[-1].get('reason') or 'exit %s' % done[-1].get('exit')} "
            f"after {time.monotonic() - started:.1f}s")
        return done[-1]

    return credit.verify_commit_trailers(root, base, head, rerun_fn=reported)
