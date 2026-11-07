"""Stop owns a host program naming the session, never a diagnostic naming the same UUID."""
import os
import json
from pathlib import Path
import signal
import subprocess
import sys
import uuid

import pytest

from tests.integration.test_hierarchy_launcher import Launch, REVIEW, launcher_module, wait_until
from tests.integration.test_hierarchy_launcher_hosts import Hosts
from tests.integration.test_hierarchy_mailbox import git


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
    # The role owns this checkout; no ancestor repository may supply its cwd validation.
    role_cwd = launch.tmp / "role-cwd"
    role_cwd.mkdir()
    git(role_cwd, "init", "-q", "-b", "test")
    git(role_cwd, "config", "--local", "user.name", "Test")
    git(role_cwd, "config", "--local", "user.email", "test@example.invalid")
    git(role_cwd, "commit", "--allow-empty", "-qm", "role cwd")
    assert Path(git(role_cwd, "rev-parse", "--show-toplevel")).resolve() == role_cwd.resolve()
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, host, session=session, cwd=str(role_cwd))
    argv = [str(launch.tmp / word) if "=" not in word else word for word in program]
    if host == "codex-cli":
        argv = [argv[0], "-c", CHILD]
    owned = children(*argv, "resume" if host == "codex-cli" else "--resume", session)

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)

    assert stopped["state"] == "stopped" and stopped["pids"] == [owned.pid]
    assert stopped["host"] == host and stopped["session"] == session
    assert owned.wait(timeout=5) == -signal.SIGTERM


@pytest.mark.parametrize("with_host", [False, True])
def test_stop_spares_a_diagnostic_naming_the_session(launch, children, with_host):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "codex-cli", session=session)
    diagnostic = children(sys.executable, "-c", CHILD, session)
    owned = children(str(launch.tmp / "codex"), "-c", CHILD, "resume", session) if with_host else None

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
    argv = binding["start_argv"] if program == "claude" else ["codex", "exec", "--json", "resume", session]
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
    ("claude-code", "node", "nix/store/claude-code/bin/.claude-wrapped"),
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
    held = children(str(launch.tmp / program), *arguments, "resume" if host == "codex-cli" else "--resume", session)

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
    held = children(str(launch.tmp / "codex"), "-c", CHILD, "resume", session)
    module = launcher_module()

    def no_ps(*args, **kwargs):
        raise AssertionError("a Linux process census must read /proc")

    monkeypatch.setattr(module.subprocess, "run", no_ps)
    assert module.session_processes(session, set()) == [(held.pid, os.getpgid(held.pid))]


@pytest.mark.parametrize("noise", ["Bob's.txt", 'an unmatched " quote', "the other role's contract"])
def test_ps_fallback_ignores_unrelated_quotes(monkeypatch, noise):
    from types import SimpleNamespace

    module = launcher_module()
    session = str(uuid.uuid4())
    is_dir = Path.is_dir
    monkeypatch.setattr(Path, "is_dir", lambda path: False if str(path) == "/proc" else is_dir(path))
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        returncode=0, stdout=("99 99 1 {uid} {uid} S Sat Nov 7 12:00:00 2026 less {noise}\n"
                             "123 123 1 {uid} {uid} S Sat Nov 7 12:00:00 2026 /opt/codex exec resume {session} {noise}\n").format(
                                 uid=os.geteuid(), noise=noise, session=session)))

    assert module.session_processes(session, set()) == [(123, 123)]


def test_ps_fallback_does_not_reconstruct_paths_with_spaces(monkeypatch):
    from types import SimpleNamespace

    module = launcher_module()
    session = str(uuid.uuid4())
    is_dir = Path.is_dir
    monkeypatch.setattr(Path, "is_dir", lambda path: False if str(path) == "/proc" else is_dir(path))
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        returncode=0, stdout="123 123 1 %d %d S Sat Nov 7 12:00:00 2026 /opt/host tools/codex exec resume %s\n" %
                            (os.geteuid(), os.geteuid(), session)))
    unowned = []

    assert module.session_processes(session, set(), "codex-cli", unowned) == []
    assert unowned == [123]


@pytest.mark.parametrize("argv,matched", [
    (["claude", "--resume", "<uuid>"], True),
    (["claude", "-p", "--output-format", "stream-json", "--resume", "<uuid>", "--verbose"], True),
    (["/home/u/.local/share/fnm/node-versions/v24.21.0/installation/lib/node_modules/"
      "@anthropic-ai/claude-code/bin/claude.exe", "--session-id", "<uuid>", "--print"], True),
    (["claude bg-pty-host", "--bg-pty-host", "/tmp/claude.sock"], False),
    (["claude bg-spare", "--bg-spare"], False),
    (["node", "/nix/store/claude-code/bin/.claude-wrapped", "--resume", "<uuid>"], True),
])
def test_observed_claude_argv_shapes(monkeypatch, argv, matched):
    # The owner supplied these NUL-split argv shapes from Claude Code 2.1.319, plus the Nix entrypoint.
    module = launcher_module()
    session = str(uuid.uuid4())
    argv = [session if word == "<uuid>" else word for word in argv]
    row = module.ProcessSnapshot(123, 123, "S", os.geteuid(), "1", b"\0".join(os.fsencode(a) for a in argv), tuple(argv),
                                 1, os.geteuid())
    monkeypatch.setattr(module, "process_census", lambda _session: module.ProcessCensus([row], "proven"))

    assert module.session_processes(session, set(), "claude-code") == ([(123, 123)] if matched else [])


def test_wrapper_symlink_creation_is_safe_when_callers_race(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from tests.integration.hierarchy_fake_wrapper import python_argv

    barrier = Barrier(2)
    symlink_to = Path.symlink_to

    def simultaneous(path, target, *args, **kwargs):
        barrier.wait(timeout=5)
        return symlink_to(path, target, *args, **kwargs)

    monkeypatch.setattr(Path, "symlink_to", simultaneous)
    script = tmp_path / "host.py"
    script.write_text("pass\n", encoding="utf-8")
    with ThreadPoolExecutor(max_workers=2) as pool:
        calls = [pool.submit(python_argv, "codex", script, tmp_path) for _ in range(2)]
        commands = [call.result(timeout=5) for call in calls]

    binary = tmp_path / ".python" / "codex"
    assert all(command[0] == str(binary) for command in commands)
    assert binary.is_symlink() and binary.resolve() == Path(sys.executable).resolve()
    assert list(binary.parent.iterdir()) == [binary]


def test_wrapper_imports_only_its_folder_and_python_libraries(tmp_path, monkeypatch):
    from tests.integration.hierarchy_fake_wrapper import python_argv
    from tests.integration.test_hierarchy_mailbox import ROOT

    work, folder = tmp_path / "work", tmp_path / "wrapper"
    work.mkdir()
    folder.mkdir()
    for name in ("runpy.py", "pkgutil.py"):
        (work / name).write_text('raise RuntimeError("working directory imported")\n', encoding="utf-8")
    script = folder / "host.py"
    script.write_text("import json, pkgutil, sys\nprint(json.dumps({'paths': sys.path, 'python': sys.executable}))\n",
                      encoding="utf-8")
    monkeypatch.setattr(sys, "path", ["", str(work), *sys.path])
    command = python_argv("codex", script, tmp_path)
    ran = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)

    assert ran.returncode == 0, ran.stderr
    found = json.loads(ran.stdout)
    assert found["paths"][0] == str(folder)
    assert "" not in found["paths"] and str(work) not in found["paths"] and str(ROOT) not in found["paths"]
    assert found["python"] == sys.executable


@pytest.mark.parametrize("kind", ["probe", "rollout", "team", "direct-rollout"])
def test_rollout_launch_paths_present_the_host_program(tmp_path, kind):
    from tests.integration.test_hierarchy_fake_codex_rollouts import FAKE_CODEX, Fake, codex_argv
    from tests.integration.test_hierarchy_native_probe import Probe
    from tests.integration.test_hierarchy_team import fake_codex

    runtime = Fake(tmp_path)
    session = str(uuid.uuid4())
    runtime.write_script({"commands": []})
    runtime.start(FAKE_CODEX_THREAD=session)
    runtime.write_script({"mode": "hang", "commands": []})
    argv = codex_argv(runtime.profile(), ["resume", session, "hold"])
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


def test_stop_spares_another_sessions_prompt(launch, children):
    session, other = str(uuid.uuid4()), str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--session-id", other, "--print", session)

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "0", timeout=5)

    assert held.poll() is None
    assert stopped["pids"] == [] and stopped["unowned_pids"] == [held.pid]


def test_stop_spares_another_users_matching_process(launch, children, monkeypatch, capsys):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session)
    module, read = launcher_module(), Path.read_bytes

    def other_uid(path):
        value = read(path)
        if str(path) == "/proc/%d/status" % held.pid:
            return status_uids(value, os.geteuid() + 1, os.geteuid() + 1)
        return value

    monkeypatch.setattr(Path, "read_bytes", other_uid)
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "0"]) == 0
    stopped = json.loads(capsys.readouterr().out)
    assert held.poll() is None
    assert stopped["pids"] == [] and stopped["unowned_pids"] == [held.pid]


@pytest.mark.parametrize("changed", ["cmdline", "stat"])
def test_stop_rechecks_the_census_before_signalling(launch, children, monkeypatch, capsys, changed):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session)
    module, read, reads = launcher_module(), Path.read_bytes, []
    target = "/proc/%d/%s" % (held.pid, changed)

    def replaced(path):
        value = read(path)
        if str(path) == target:
            reads.append(value)
            if len(reads) > 1:
                if changed == "cmdline":
                    return value.replace(session.encode(), b"different-session")
                prefix, _, suffix = value.rpartition(b")")
                words = suffix.split()
                words[19] = str(int(words[19]) + 1).encode()
                return prefix + b") " + b" ".join(words)
        return value

    monkeypatch.setattr(Path, "read_bytes", replaced)
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "0"]) == 0
    stopped = json.loads(capsys.readouterr().out)
    assert held.poll() is None
    assert "unowned_pids" not in stopped and stopped["pids"] == []


@pytest.mark.skipif(not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"),
                    reason="pidfd signalling is unavailable")
def test_stop_opens_a_pidfd_then_verifies_then_signals(launch, children, monkeypatch, capsys):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session)
    module, events, handles = launcher_module(), [], {}
    opening, sending, reading = os.pidfd_open, signal.pidfd_send_signal, Path.read_bytes

    def opened(pid, *args):
        fd = opening(pid, *args)
        handles[fd] = pid
        if pid == held.pid:
            events.append("open")
        return fd

    def read(path):
        if str(path) == "/proc/%d/cmdline" % held.pid:
            events.append("read")
        return reading(path)

    def sent(fd, *args):
        if handles[fd] == held.pid:
            events.append("signal")
        return sending(fd, *args)

    monkeypatch.setattr(os, "pidfd_open", opened)
    monkeypatch.setattr(signal, "pidfd_send_signal", sent)
    monkeypatch.setattr(Path, "read_bytes", read)
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "stopped"
    assert "open" in events and "signal" in events
    assert "read" in events[events.index("open") + 1:events.index("signal")]
    assert held.wait(timeout=5) == -signal.SIGTERM


def test_fallback_records_unproven_argument_boundaries(launch, monkeypatch, capsys):
    from types import SimpleNamespace

    launch.add_role(REVIEW, "claude-code", session=str(uuid.uuid4()))
    module, is_dir = launcher_module(), Path.is_dir
    monkeypatch.setattr(Path, "is_dir", lambda path: False if str(path) == "/proc" else is_dir(path))
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=""))
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW]) == 0
    assert json.loads(capsys.readouterr().out)["argv_boundaries"] == "unproven"


@pytest.mark.parametrize("uid_offset,arguments,matched", [
    (0, "claude --resume={session}", True),
    (0, "claude --session-id other --print {session}", False),
    (0, "claude --resume {session} --session-id other", False),
    (1, "claude --resume {session}", False),
])
def test_ps_fallback_checks_uid_and_positional_selectors(monkeypatch, uid_offset, arguments, matched):
    from types import SimpleNamespace

    module, session, is_dir = launcher_module(), str(uuid.uuid4()), Path.is_dir
    monkeypatch.setattr(Path, "is_dir", lambda path: False if str(path) == "/proc" else is_dir(path))
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0,
        stdout="123 123 1 %d %d S Sat Nov 7 12:00:00 2026 %s\n" %
               (os.geteuid() + uid_offset, os.geteuid() + uid_offset, arguments.format(session=session))))
    unowned = []
    assert module.session_processes(session, set(), "claude-code", unowned) == ([(123, 123)] if matched else [])
    assert unowned == ([] if matched else [123])


@pytest.mark.parametrize("uid_offset", [0, 1])
def test_stop_spares_an_unowned_member_of_an_owned_group(launch, children, monkeypatch, capsys, uid_offset):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    leader = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session)
    other = children(sys.executable, "-c", CHILD, session)
    module = launcher_module()
    read = module.read_process

    def group_member(pid, *args):
        row = read(pid, *args)
        # OS boundary: the other real child stands in for a diagnostic in the leader's process group.
        return row._replace(pgid=leader.pid, uid=os.geteuid() + uid_offset) if row and pid == other.pid else row

    monkeypatch.setattr(module, "read_process", group_member)
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 0
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["state"] == "stopped" and stopped["pids"] == [leader.pid]
    assert stopped["unowned_pids"] == [other.pid]
    assert leader.wait(timeout=5) == -signal.SIGTERM
    assert other.poll() is None


def test_stop_records_a_signal_permission_failure(launch, children, monkeypatch, capsys):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session)
    module = launcher_module()

    def denied(*args):
        raise PermissionError("signal denied")

    if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
        monkeypatch.setattr(signal, "pidfd_send_signal", denied)
    else:
        monkeypatch.setattr(os, "kill", denied)
    monkeypatch.setattr(module, "KILL_WAIT_SECONDS", 0)
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "0"]) == 3
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["state"] == "stop_failed" and stopped["pids"] == [held.pid]
    assert held.poll() is None


def status_uids(value, real, effective):
    return b"\n".join(b"Uid:\t%d\t%d\t%d\t%d" % (real, effective, effective, effective)
                      if line.startswith(b"Uid:") else line for line in value.split(b"\n"))


def present_argv(monkeypatch, process, argv):
    """Keep a real held child, replacing only its kernel argv at the OS boundary."""
    read = Path.read_bytes

    def shown(path):
        if str(path) == "/proc/%d/cmdline" % process.pid:
            return b"\0".join(os.fsencode(word) for word in argv) + b"\0"
        return read(path)

    monkeypatch.setattr(Path, "read_bytes", shown)


@pytest.mark.parametrize("host,other", [("codex-cli", False), ("codex-cli", True),
                                       ("claude-code", False), ("claude-code", True)])
def test_fallback_matches_the_launchers_real_argv(launch, children, monkeypatch, capsys, host, other):
    from types import SimpleNamespace
    from hierarchy_provision import codex_argv

    session = str(uuid.uuid4())
    role = launch.add_role(REVIEW, host, session=session)
    selected = str(uuid.uuid4()) if other else session
    if host == "codex-cli":
        profile = json.loads(Path(role["codex_profile"]).read_text())
        argv = codex_argv(profile, ["resume", selected, session])
    else:
        argv = [selected if word == session else word for word in role["start_argv"]] + [session]
    held = children(sys.executable, "-c", CHILD)
    module, is_dir = launcher_module(), Path.is_dir
    monkeypatch.setattr(module, "ancestors", lambda: {os.getpid()})
    monkeypatch.setattr(Path, "is_dir", lambda path: False if str(path) == "/proc" else is_dir(path))

    def ps(command, **options):
        if held.poll() is not None:
            return SimpleNamespace(returncode=1 if "-p" in command else 0, stdout="")
        columns = command[command.index("-o") + 1].replace("=", "").split(",")
        values = {"pid": str(held.pid), "pgid": str(held.pid), "ppid": str(os.getpid()),
                  "uid": str(os.geteuid()), "ruid": str(os.geteuid()), "stat": "S",
                  "lstart": "Sat Nov 7 12:00:00 2026", "args": " ".join(argv)}
        return SimpleNamespace(returncode=0, stdout=" ".join(values[column] for column in columns) + "\n")

    monkeypatch.setattr(module.subprocess, "run", ps)
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 0
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["argv_boundaries"] == "unproven"
    assert stopped["state"] == ("not_running" if other else "stopped")
    assert stopped["pids"] == ([] if other else [held.pid])
    if other:
        assert stopped["unowned_pids"] == [held.pid] and held.poll() is None
    else:
        assert held.wait(timeout=5) == -signal.SIGTERM


def test_stop_matches_codex_after_an_option_terminator(launch, children):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "codex-cli", session=session)
    held = children(str(launch.tmp / "codex"), "-c", CHILD, "exec", "resume", "--", session, "prompt")
    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)
    assert stopped["state"] == "stopped" and stopped["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGTERM


@pytest.mark.parametrize("option", ["--loader", "--experimental-loader", "--import", "-r", "--require",
                                  "--env-file", "--conditions", "-C", "--title", "--input-type"])
def test_stop_matches_node_options_with_separate_values(launch, children, monkeypatch, capsys, option):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(sys.executable, "-c", CHILD)
    present_argv(monkeypatch, held, ["node", option, "/opt/l.mjs", "/lib/@anthropic-ai/claude-code/cli.js",
                                    "--resume", session])
    module = launcher_module()
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 0
    assert json.loads(capsys.readouterr().out)["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGTERM


def test_stop_spares_an_unknown_node_option_value(launch, children, monkeypatch, capsys):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(sys.executable, "-c", CHILD)
    present_argv(monkeypatch, held, ["node", "--unknown-option", "/lib/@anthropic-ai/claude-code/cli.js",
                                    "--resume", session])
    module = launcher_module()
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW]) == 0
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["pids"] == [] and stopped["unowned_pids"] == [held.pid]
    assert held.poll() is None


@pytest.mark.parametrize("error", [1, 38, 5])
def test_stop_falls_back_when_pidfd_open_is_unavailable(launch, children, monkeypatch, capsys, error):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session)

    def unavailable(pid):
        raise OSError(error, "pidfd unavailable")

    monkeypatch.setattr(os, "pidfd_open", unavailable, raising=False)
    monkeypatch.setattr(signal, "pidfd_send_signal", lambda *args: pytest.fail("unopened pidfd signalled"), raising=False)
    module = launcher_module()
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 0
    assert json.loads(capsys.readouterr().out)["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGTERM


def test_stop_spares_a_forked_claude_session(launch, children):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session, "--fork-session")
    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)
    assert stopped["pids"] == [] and stopped["unowned_pids"] == [held.pid]
    assert held.poll() is None


@pytest.mark.parametrize("changed", ["directory", "real", "effective", "missing"])
def test_stop_uses_real_and_effective_status_uids(launch, children, monkeypatch, capsys, changed):
    from types import SimpleNamespace

    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session)
    read, stat = Path.read_bytes, os.stat

    def status(path):
        value = read(path)
        if str(path) == "/proc/%d/status" % held.pid:
            if changed == "missing":
                return b"\n".join(line for line in value.split(b"\n") if not line.startswith(b"Uid:"))
            return status_uids(value, os.geteuid() + (changed == "real"), os.geteuid() + (changed == "effective"))
        return value

    def owner(path, *args, **kwargs):
        if changed == "directory" and os.fspath(path) == "/proc/%d" % held.pid:
            return SimpleNamespace(st_uid=os.geteuid() + 1)
        return stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", status)
    monkeypatch.setattr(os, "stat", owner)
    module = launcher_module()
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 0
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["pids"] == ([held.pid] if changed == "directory" else [])
    if changed == "directory":
        assert held.wait(timeout=5) == -signal.SIGTERM
    else:
        assert stopped["unowned_pids"] == [held.pid] and held.poll() is None


def present_family(monkeypatch, family, change=None):
    """Real children, with group and parent relationships supplied by the kernel boundary."""
    read, counts = Path.read_bytes, {}

    def stat(path):
        value = read(path)
        if path.name == "stat" and path.parent.name.isdigit() and int(path.parent.name) in family:
            pid = int(path.parent.name)
            pgid, ppid = family[pid]
            counts[pid] = counts.get(pid, 0) + 1
            prefix, _, tail = value.rpartition(b")")
            fields = tail.split()
            fields[1], fields[2] = str(ppid).encode(), str(pgid).encode()
            if change is not None and counts[pid] > 1:
                change(pid, fields)
            return prefix + b") " + b" ".join(fields)
        return value

    monkeypatch.setattr(Path, "read_bytes", stat)


@pytest.mark.parametrize("parent_owned", [False, True])
def test_stop_spares_a_group_member_selecting_another_session(launch, children, monkeypatch, capsys, parent_owned):
    session, other_session = str(uuid.uuid4()), str(uuid.uuid4())
    launch.add_role(REVIEW, "codex-cli", session=session)
    leader = children(str(launch.tmp / "codex"), "-c", CHILD, "exec", "resume", session)
    shell = children(str(launch.tmp / "sh"), "-c", CHILD)
    other = children(str(launch.tmp / "other-host" / "codex"), "-c", CHILD, "exec", "resume", other_session)
    present_family(monkeypatch, {other.pid: (leader.pid, leader.pid if parent_owned else shell.pid)})
    module = launcher_module()
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 0
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["pids"] == [leader.pid] and "unowned_pids" not in stopped
    assert leader.wait(timeout=5) == -signal.SIGTERM
    assert other.poll() is None and shell.poll() is None


@pytest.mark.parametrize("changed", [None, "ppid", "birth"])
def test_stop_checks_the_descendants_entire_parent_chain(launch, children, monkeypatch, capsys, changed):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    leader = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session)
    middle = children(sys.executable, "-c", CHILD)
    worker = children(sys.executable, "-c", CHILD)

    def retarget(pid, fields):
        if pid == middle.pid and changed == "ppid":
            fields[1] = str(os.getpid()).encode()
        if pid == middle.pid and changed == "birth":
            fields[19] = str(int(fields[19]) + 1).encode()

    present_family(monkeypatch, {middle.pid: (leader.pid, leader.pid), worker.pid: (leader.pid, middle.pid)}, retarget)
    module = launcher_module()
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 0
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["pids"] == [leader.pid] and "unowned_pids" not in stopped
    assert leader.wait(timeout=5) == -signal.SIGTERM
    if changed is None:
        assert middle.wait(timeout=5) == worker.wait(timeout=5) == -signal.SIGTERM
    else:
        assert middle.poll() is None and worker.poll() is None


@pytest.mark.parametrize("changed", ["cmdline", "uid"])
def test_stop_does_not_report_non_session_group_members_as_unowned(launch, children, monkeypatch, capsys, changed):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    leader = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session)
    member = children(sys.executable, "-c", CHILD)
    present_family(monkeypatch, {member.pid: (leader.pid, leader.pid)})
    read, counts = Path.read_bytes, []
    target = "/proc/%d/%s" % (member.pid, "status" if changed == "uid" else "cmdline")

    def replaced(path):
        value = read(path)
        if str(path) == target:
            counts.append(value)
            if len(counts) > 1:
                return status_uids(value, os.geteuid() + 1, os.geteuid() + 1) if changed == "uid" else value + b"changed\0"
        return value

    monkeypatch.setattr(Path, "read_bytes", replaced)
    module = launcher_module()
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 0
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["pids"] == [leader.pid] and "unowned_pids" not in stopped
    assert leader.wait(timeout=5) == -signal.SIGTERM
    assert member.poll() is None
