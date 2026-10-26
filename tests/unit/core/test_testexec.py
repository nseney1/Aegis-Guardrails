"""The hermetic test run (``aegis_core.testexec``, R-structure-29): the user-scope command and its
digest, the fixed environment, the process-group timeout and the JUnit reader that ``aegis check
--record``, its trailer rerun, T5, mutation testing and diff coverage share."""
from __future__ import annotations

import os
import sys
import time

import pytest

from aegis_core import testexec
from tests import helpers_humangate as hg
from tests import helpers_verified as hv

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")
posix_only = pytest.mark.skipif(os.name == "nt", reason="process groups are POSIX here")


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)


# ── the command ──────────────────────────────────────────────────────────────

@needs_git
def test_the_user_config_command_may_be_an_argv_list_and_the_digest_is_machine_independent(tmp_path):
    repo = hv.make_project(tmp_path)
    hv.write_user_config(repo.home.path, tests={"command": ["python", "run_checks.py"]})
    assert testexec.user_test_command(repo.root) == ["python", "run_checks.py"]
    first = testexec.command_digest(["python", "run_checks.py"])
    argv, logical = testexec.plan_command(["python", "run_checks.py"])
    assert argv[0] == sys.executable and logical == ["python", "run_checks.py"]
    assert testexec.command_digest(logical) == first


def test_a_bare_pytest_runs_as_python_m_pytest_with_every_hermetic_flag(tmp_path):
    junit = tmp_path / "junit.xml"
    argv, logical = testexec.plan_command(["pytest", "-q"], junit)
    assert argv[:6] == [sys.executable, "-s", "--check-hash-based-pycs", "always", "-m", "pytest"]
    at = argv.index("-p")
    assert argv[at:at + 4] == ["-p", "no:cacheprovider", "-o", "addopts="]
    assert f"--junitxml={junit}" in argv and "-q" in argv
    assert logical == ["pytest", "-q"]


@pytest.mark.parametrize("word", ["/opt/venv/bin/pytest", "py.test", "PYTEST.EXE"])
def test_any_pytest_program_runs_under_the_aegis_interpreter(word):
    argv, logical = testexec.plan_command([word, "-q"])
    assert argv[0] == sys.executable and argv[4:6] == ["-m", "pytest"] and "addopts=" in argv
    assert logical == [word, "-q"]


def test_only_an_absolute_python_first_word_is_kept_as_the_interpreter(tmp_path):
    python = tmp_path / "python3"
    python.write_text("#!/bin/sh\nexit 0\n")
    python.chmod(0o755)
    argv, _ = testexec.plan_command([str(python), "-m", "pytest"])
    assert argv[:4] == [str(python), "-s", "--check-hash-based-pycs", "always"] and "addopts=" in argv
    assert testexec.plan_command(["python", "-m", "pytest"])[0][0] == sys.executable
    tool = str(tmp_path / "runtests")
    assert testexec.plan_command([tool, "-x"])[0] == [tool, "-x"]


def test_a_missing_absolute_interpreter_exits_127(tmp_path):
    junit = tmp_path / "junit.xml"
    argv, _ = testexec.plan_command([str(tmp_path / "nowhere" / "python3"), "-m", "pytest"], junit)
    run = testexec.run_tests(argv, tmp_path, testexec.hermetic_env(tmp_path), 60.0, junit, tmp_path / "out.txt")
    assert run.exit == 127 and not run.evidence


def test_the_default_command_keeps_its_digest():
    _argv, logical = testexec.plan_command(None)
    assert testexec.command_digest(logical) == "982597b8a8141596e8015b5c60700b600e69fc8873640cb98a23585cfff5b8ea"


@needs_git
@pytest.mark.parametrize("config", ["not json", '{"tests": {"command": 5}}', '{"tests": {"command": ""}}', "[]"])
def test_an_unusable_user_config_falls_back_to_the_default(tmp_path, config):
    repo = hv.make_project(tmp_path)
    path = repo.home.path / ".aegis" / "config.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(config)
    assert testexec.user_test_command(repo.root) is None


@needs_git
def test_a_user_command_whose_config_file_is_inside_the_workspace_is_refused(tmp_path, monkeypatch):
    """Given a HOME inside the repository, so ~/.aegis/config.json is a file the repository holds,
    When the test command is read, Then it is refused (the default runs), while the same command in
    a config outside the workspace is honoured: a repository never chooses what the verifier runs."""
    repo = hv.make_project(tmp_path)
    hv.write_user_config(repo.home.path, tests={"command": ["python", "run_checks.py"]})
    assert testexec.user_test_command(repo.root) == ["python", "run_checks.py"]
    inside = repo.root / "home"
    hv.write_user_config(inside, tests={"command": ["python", "run_checks.py"]})
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(inside))
    assert testexec.user_test_command(repo.root) is None


# ── running it ───────────────────────────────────────────────────────────────

@posix_only
def test_a_command_that_forks_a_hanging_child_is_killed_with_its_group_after_the_timeout(tmp_path):
    """Given a command that starts a child which hangs and then hangs itself, When the timeout
    passes, Then the run is timed out and the child, in the same process group, is gone too."""
    pidfile = tmp_path / "child.pid"
    script = ("import subprocess, sys, time\n"
              "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
              f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n"
              "time.sleep(60)\n")
    run = testexec.run_tests([sys.executable, "-c", script], tmp_path, testexec.hermetic_env(tmp_path), 2.0,
                             tmp_path / "junit.xml", tmp_path / "out.txt")
    assert run.timed_out is True and not run.evidence
    pid = int(pidfile.read_text())
    deadline = time.monotonic() + 5  # a hang ceiling for the reaper, not a time budget
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_the_process_group_killer_a_caller_patches_is_the_one_a_run_uses(tmp_path, monkeypatch):
    killed = []
    monkeypatch.setattr(testexec, "kill_group", lambda proc: killed.append(proc.pid))
    testexec.run_tests([sys.executable, "-c", "pass"], tmp_path, testexec.hermetic_env(tmp_path), 60.0,
                       tmp_path / "junit.xml", tmp_path / "out.txt")
    assert len(killed) == 1


# ── the JUnit reader (R-trust-50) ────────────────────────────────────────────

_JUNIT = b"""<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" tests="5"><error message="suite setup">boom</error>
<testcase classname="tests.test_a" name="test_one"/>
<testcase classname="tests.test_a" name="test_two"/>
<testcase classname="tests.test_a" name="test_three"/>
<testcase classname="tests.test_a" name="test_bad"><failure message="no">x</failure></testcase>
<testcase classname="tests.test_a" name="test_skip"><skipped message="later"/></testcase>
</testsuite></testsuites>
"""
_SUMMARY = "import sys; print('2 passed, 1 failed in 0.01s'); sys.exit(1)"


def test_a_junit_file_is_counted_case_by_case(tmp_path):
    import hashlib

    junit = tmp_path / "junit.xml"
    junit.write_bytes(_JUNIT)
    run = testexec.run_tests([sys.executable, "-c", _SUMMARY], tmp_path, testexec.hermetic_env(tmp_path), 60.0, junit,
                             tmp_path / "out.txt")
    ids = sorted(f"tests.test_a::{n}" for n in ("test_one", "test_two", "test_three", "test_bad", "test_skip"))
    assert (run.collected, run.passed, run.failed, run.skipped) == (5, 3, 1, 1)
    assert run.nodeid_digest == hashlib.sha256("\n".join(ids).encode("utf-8")).hexdigest()
    passed, failed, errors = testexec.parse_junit_cases(junit)
    assert passed == {"tests.test_a::test_one", "tests.test_a::test_two", "tests.test_a::test_three"}
    assert failed == {"tests.test_a::test_bad"} and errors == ["<suite:pytest>"]


@pytest.mark.parametrize("junit_bytes", [b"<testsuite><testcase", None], ids=["malformed", "oversized"])
def test_an_unreadable_junit_file_falls_back_to_the_summary_line(tmp_path, monkeypatch, junit_bytes):
    junit = tmp_path / "junit.xml"
    if junit_bytes is None:
        monkeypatch.setattr(testexec, "_MAX_JUNIT_BYTES", 64)
        junit_bytes = _JUNIT
    junit.write_bytes(junit_bytes)
    run = testexec.run_tests([sys.executable, "-c", _SUMMARY], tmp_path, testexec.hermetic_env(tmp_path), 60.0, junit,
                             tmp_path / "out.txt")
    assert (run.collected, run.passed, run.failed, run.nodeid_digest) == (3, 2, 1, None)
    assert testexec.parse_junit_cases(junit) == (set(), set(), [])


def test_a_run_that_writes_no_junit_file_is_counted_from_its_summary_and_names_no_test(tmp_path):
    """The record run's fallback: without a JUnit file the counts come from pytest's summary line and
    no node-id digest is recorded; the reader finds no test id in the missing file."""
    junit = tmp_path / "never-written.xml"
    run = testexec.run_tests([sys.executable, "-c", _SUMMARY], tmp_path, testexec.hermetic_env(tmp_path), 60.0, junit,
                             tmp_path / "out.txt")
    assert (run.exit, run.collected, run.passed, run.failed, run.nodeid_digest) == (1, 3, 2, 1, None)
    assert not junit.exists() and testexec.parse_junit_cases(junit) == (set(), set(), [])


def test_a_snapshot_run_that_leaves_no_junit_file_passes_no_test_id(tmp_path, monkeypatch):
    """Given a snapshot run that exits 0 with a passing summary but writes no JUnit file, When T5 reads
    it, Then no test id passed or failed: ids come only from the JUnit file, so such a run is
    unverified and can never make a fix commit fail-to-pass."""
    seen = []

    def no_junit(argv, cwd, env, timeout, junit, output):
        seen.append(junit)
        return testexec.TestsRun(exit=0, collected=3, passed=3)

    monkeypatch.setattr(testexec, "run_tests", no_junit)
    snapshot, workspace = tmp_path / "snap", tmp_path / "ws"
    (snapshot / "tests").mkdir(parents=True)
    workspace.mkdir()
    (snapshot / "tests" / "test_x.py").write_bytes(b"def test_ok():\n    assert True\n")
    outcome = testexec.run_pytest_snapshot(snapshot, ["tests/test_x.py"], workspace, tmp_path / "run", 60.0)
    assert len(seen) == 1 and not seen[0].exists()
    assert (outcome.exit_code, outcome.timed_out) == (0, False)
    assert (outcome.passed_ids, outcome.failed_ids, outcome.collection_errors) == (frozenset(), frozenset(), frozenset())
