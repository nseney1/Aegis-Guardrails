"""Stop owns a host program naming the session, never a diagnostic naming the same UUID."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import uuid

import pytest

from tests.integration.test_hierarchy_launcher import Launch, REVIEW, launcher_module, wait_until
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
        argv = list(argv)
        if argv[0] != sys.executable:
            binary = Path(argv[0]).parent / "interpreters" / Path(argv[0]).name
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.symlink_to(sys.executable)
            argv[0] = str(binary)
        ready = tmp_path / ("ready-%d" % len(running))
        process = subprocess.Popen(argv, cwd=str(tmp_path),
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
    assert stopped["unowned_pids"] == [diagnostic.pid]
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
    assert stopped["unowned_pids"] == [other.pid]
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
        binary = Path(os.fsdecode(Path("/proc/%d/cmdline" % held.pid).read_bytes().split(b"\0")[0]))
        assert binary.is_symlink() and binary.resolve() == Path(sys.executable).resolve()
        assert tmp_path in binary.parents
        stopped = hosts.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)
        assert stopped["state"] == "stopped" and stopped["pids"] == [held.pid]
        assert held.wait(timeout=5) == -signal.SIGTERM
    finally:
        if held.poll() is None:
            os.killpg(held.pid, signal.SIGKILL)
        held.wait(timeout=5)


@pytest.mark.parametrize("host,program,script", [
    ("claude-code", "claude.exe", None),
    ("claude-code", ".claude-wrapped", None),
    ("claude-code", "host tools/claude", None),
    ("claude-code", "node", "node_modules/@anthropic-ai/claude-code/cli.js"),
    ("claude-code", "host tools/node", "host scripts/@anthropic-ai/claude-code/cli.js"),
    ("codex-cli", "host tools/codex", None),
    ("codex-cli", "vendor/platform/bin/codex", None),
    ("codex-cli", "node", "host scripts/codex"),
])
def test_stop_accepts_validated_host_entrypoints(launch, children, host, program, script):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, host, session=session)
    if script is None:
        arguments = ["-c", CHILD]
    else:
        target = launch.tmp / script
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(CHILD, encoding="utf-8")
        arguments = [str(target)]
    held = children(str(launch.tmp / program), *arguments, "--resume", session)

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)

    assert stopped["state"] == "stopped" and stopped["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGTERM


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
def test_stop_rejects_an_arbitrary_cli_js(launch, children, host):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, host, session=session)
    script = launch.tmp / "unrelated" / "cli.js"
    script.parent.mkdir()
    script.write_text(CHILD, encoding="utf-8")
    other = children(str(launch.tmp / "node"), str(script), "--resume", session)

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)

    assert other.poll() is None
    assert stopped["pids"] == [] and stopped["unowned_pids"] == [other.pid]


def test_stop_does_not_split_a_session_out_of_a_single_argument(launch, children):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "codex-cli", session=session)
    other = children(str(launch.tmp / "codex"), "-c", CHILD, "diagnostic %s text" % session)

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)

    assert other.poll() is None
    assert stopped["state"] == "not_running" and stopped["pids"] == []


def test_linux_matcher_reads_proc_without_a_ps_census(launch, children, monkeypatch):
    session = str(uuid.uuid4())
    held = children(str(launch.tmp / "codex"), "-c", CHILD, session)
    module = launcher_module()

    def no_ps(*args, **kwargs):
        raise AssertionError("a Linux process census must read /proc")

    monkeypatch.setattr(module.subprocess, "run", no_ps)
    assert module.session_processes(session, set()) == [(held.pid, os.getpgid(held.pid))]


def test_ps_fallback_preserves_quoted_executable_paths(monkeypatch):
    from types import SimpleNamespace

    module = launcher_module()
    session = str(uuid.uuid4())
    is_dir = Path.is_dir
    monkeypatch.setattr(Path, "is_dir", lambda path: False if str(path) == "/proc" else is_dir(path))
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        returncode=0, stdout="123 123 S '/opt/host tools/codex' exec resume %s\n" % session))

    assert module.session_processes(session, set()) == [(123, 123)]


@pytest.mark.parametrize("kind", ["probe", "rollout", "team", "direct-rollout"])
def test_rollout_launch_paths_present_the_host_program(tmp_path, kind):
    from tests.integration.test_hierarchy_fake_codex_rollouts import FAKE_CODEX, Fake, codex_argv
    from tests.integration.test_hierarchy_native_probe import Probe
    from tests.integration.test_hierarchy_team import fake_codex

    runtime = Fake(tmp_path)
    runtime.write_script({"mode": "hang", "commands": []})
    session = str(uuid.uuid4())
    argv = codex_argv(runtime.profile(), [session])
    env = runtime.env(FAKE_CODEX_THREAD=session)
    if kind == "probe":
        folder = tmp_path / "probe-harness"
        folder.mkdir()
        probe = Probe(folder)
        argv[0] = str(probe.codex)
    elif kind == "team":
        folder = tmp_path / "team-bin"
        folder.mkdir()
        argv[0] = str(fake_codex(folder))
        env["FAKE_TEAM_LOG"] = str(tmp_path / "team.log")
    elif kind == "direct-rollout":
        argv = [sys.executable, str(FAKE_CODEX), *argv[1:]]
    output = tmp_path / "rollout.stdout"
    with output.open("wb") as stdout:
        held = subprocess.Popen(argv, cwd=runtime.work, env=env, stdin=subprocess.DEVNULL,
                                stdout=stdout, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        wait_until(lambda: b'"type": "turn.started"' in output.read_bytes() or held.poll() is not None)
        assert held.poll() is None
        assert held.pid in {pid for pid, _ in launcher_module().session_processes(session, set())}
    finally:
        if held.poll() is None:
            os.killpg(held.pid, signal.SIGKILL)
        held.wait(timeout=5)
