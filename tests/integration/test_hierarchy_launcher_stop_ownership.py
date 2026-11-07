"""Stop owns a host program naming the session, never a diagnostic naming the same UUID."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import uuid

import pytest

from tests.integration.test_hierarchy_launcher import Launch, REVIEW, wait_until
from tests.integration.test_hierarchy_launcher_hosts import Hosts


pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="these process argv tests need Linux")
CHILD = """
import os, time
with open(os.environ["STOP_OWNERSHIP_READY"], "w") as ready:
    ready.write("ready")
time.sleep(5)
"""


@pytest.fixture
def launch(tmp_path):
    built = Launch(tmp_path)
    built.init()
    return built


@pytest.fixture
def children(tmp_path):
    """Real Python children with the argv of a host or wrapper; no installed host or Node is run."""
    running = []
    for name in ("sleeper.py", "claude", "codex", "K=V"):
        (tmp_path / name).write_text(CHILD, encoding="utf-8")

    def spawn(*argv):
        ready = tmp_path / ("ready-%d" % len(running))
        process = subprocess.Popen(argv, executable=sys.executable, cwd=str(tmp_path),
                                   env={**os.environ, "STOP_OWNERSHIP_READY": str(ready)},
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   start_new_session=True)
        running.append(process)
        wait_until(lambda: ready.exists() or process.poll() is not None)
        assert process.poll() is None, "the fake process exited before it was ready"
        assert Path("/proc/%d/cmdline" % process.pid).read_bytes().split(b"\0")[:-1] == [
            os.fsencode(word) for word in argv]
        return process

    try:
        yield spawn
    finally:
        for process in running:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


@pytest.mark.parametrize("host,program", [
    ("codex-cli", ("codex", "sleeper.py")),
    ("claude-code", ("claude", "sleeper.py")),
    ("claude-code", ("env", "K=V", "claude")),
    ("claude-code", ("env", "K=V", "OTHER=value", "claude")),
    ("claude-code", ("node", "claude")),
    ("claude-code", ("env", "K=V", "node", "claude")),
])
def test_stop_matches_the_bound_hosts_program(launch, children, host, program):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, host, session=session, cwd=str(launch.tmp))
    argv = [str(launch.tmp / word) if "=" not in word else word for word in program]
    owned = children(*argv, "--resume", session)

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)

    assert stopped["state"] == "stopped" and stopped["pids"] == [owned.pid]
    assert stopped["host"] == host and stopped["session"] == session
    assert owned.wait(timeout=5) == -signal.SIGTERM


@pytest.mark.parametrize("with_host", [False, True])
def test_stop_spares_a_diagnostic_naming_the_session(launch, children, with_host):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "codex-cli", session=session)
    diagnostic = children(sys.executable, "-c", CHILD, session)
    owned = children(str(launch.tmp / "codex"), "-c", CHILD, session) if with_host else None

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)

    assert diagnostic.poll() is None, "a diagnostic command naming the session must never be signalled"
    assert stopped["state"] == ("stopped" if with_host else "not_running")
    assert stopped["pids"] == ([owned.pid] if with_host else [])
    if owned is not None:
        assert owned.wait(timeout=5) == -signal.SIGTERM


def test_stop_spares_a_program_for_a_different_host(launch, children):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "codex-cli", session=session)
    other = children(str(launch.tmp / "claude"), "-c", CHILD, session)

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)

    assert other.poll() is None, "a claude process does not belong to a codex-cli binding"
    assert stopped["state"] == "not_running" and stopped["pids"] == []


@pytest.mark.parametrize("argument", ["prefix-%s", "%s-suffix"])
def test_stop_requires_the_session_as_a_whole_argument(launch, children, argument):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "codex-cli", session=session)
    other = children(str(launch.tmp / "codex"), "-c", CHILD, argument % session)

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)

    assert other.poll() is None
    assert stopped["state"] == "not_running" and stopped["pids"] == []


@pytest.mark.parametrize("program,host", [("codex", "codex-cli"), ("claude", "claude-code")])
def test_real_harness_wrapper_presents_the_hosts_program_name(tmp_path, program, host):
    hosts = Hosts(tmp_path)
    hosts.init()
    session = str(uuid.uuid4())
    binding = hosts.add_role(REVIEW, host, session=session, cwd=str(hosts.source))
    argv = binding["start_argv"] if program == "claude" else ["codex", "exec", "--json", "hold", session]
    prompt, output = tmp_path / "wrapped.prompt", tmp_path / "wrapped.stdout"
    prompt.write_text("Wait.\n", encoding="utf-8")
    with prompt.open("rb") as stdin, output.open("wb") as stdout:
        held = subprocess.Popen(argv, cwd=str(hosts.source), stdin=stdin, stdout=stdout, stderr=subprocess.DEVNULL,
                                env=hosts.env(FAKE_CODEX_MODE="hang", FAKE_CODEX_THREAD=session,
                                              FAKE_CLAUDE_MODE="hang"), start_new_session=True)
    try:
        marker = b'"subtype": "init"' if program == "claude" else b'"type": "thread.started"'
        wait_until(lambda: marker in output.read_bytes() or held.poll() is not None)
        assert held.poll() is None, "the harness wrapper must keep the fake host running"
        shown = subprocess.run(["ps", "-ww", "-o", "args=", "-p", str(held.pid)],
                               capture_output=True, text=True, timeout=5, check=True)
        assert Path(shown.stdout.split()[0]).name == program
        assert session in shown.stdout.split()
        stopped = hosts.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)
        assert stopped["state"] == "stopped" and stopped["pids"] == [held.pid]
        assert held.wait(timeout=5) == -signal.SIGTERM
    finally:
        if held.poll() is None:
            os.killpg(held.pid, signal.SIGKILL)
        held.wait(timeout=5)
