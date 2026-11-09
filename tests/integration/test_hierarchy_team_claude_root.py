"""PR6 part 1 through the CLI and sealed test hosts; no real host qualification is claimed."""
import json
import hashlib
import builtins
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager

import pytest

from tests.integration.hierarchy_fake_claude import BILLING, HERE as FAKE_CLAUDE
from tests.integration.test_hierarchy_team import REVIEWER, TEAM, git, in_process
from tests.integration.test_hierarchy_team_homes import (CLAUDE, CODEX, ROOT_TRANSACTION, HomesRun, files,
                                                        proc_environ, state, team_module)


pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="team process custody reads /proc")
ROOT_TOOLS = ["root_decide", "team_status", "team_pending", "team_request"]


class LaneRun(HomesRun):
    """Put fake controls in the fake executables, outside the production environment allowlist."""
    def __init__(self, tmp, monkeypatch, root=CLAUDE, team=CODEX):
        super().__init__(tmp, monkeypatch, root, team)
        self.codex_script = (self.bin / "codex").read_text()
        self.codex_script = self.codex_script.replace(
            "def root(argv, server):", "def root(argv, server):\n    __import__('time').sleep(float(os.environ.get('FAKE_TEAM_DELAY', '0')))")
        # Model the native response_item user record in this test wrapper; the shared Codex fake stays pinned.
        self.codex_script = self.codex_script.replace(
            '    code = subprocess.run([sys.executable, FAKE, *argv], env=env).returncode',
            '''    if "resume" in argv:
        session = argv[argv.index("resume") + 1]
        [transcript] = (Path(env["CODEX_HOME"]) / "sessions").glob("**/rollout-*-" + session + ".jsonl")
        with open(transcript, "a", encoding="utf-8") as stream:
            stream.write(json.dumps({"type": "response_item", "payload": {"role": "user", "content": argv[-1]}}) + "\\n")
    code = subprocess.run([sys.executable, FAKE, *argv], env=env).returncode''')

    def env(self, **extra):
        env = super().env(**extra)
        knobs = {key: value for key, value in env.items() if key.startswith(("FAKE_", "WRAP_"))}
        (self.bin / "codex").write_text(self.codex_script.replace(
            "from pathlib import Path", "from pathlib import Path\nos.environ.update(%r)" % knobs, 1))
        claude = (
            "#!%s\nimport os, runpy\nos.environ.update(%r)\nrunpy.run_path(%r, run_name='__main__')\n"
            % (sys.executable, knobs, str(FAKE_CLAUDE)))
        native_exit = getattr(self, "claude_exit_after_reply", None)
        if native_exit is not None:
            # A test-owned process can exit nonzero after a supported reply. This models an OS exit status,
            # independently of the transcript's terminal evidence, without any production environment escape.
            claude = ("#!%s\nimport os, runpy\nos.environ.update(%r)\ntry:\n"
                      "    runpy.run_path(%r, run_name='__main__')\nexcept SystemExit as stopped:\n"
                      "    raise SystemExit(%r if stopped.code == 0 else stopped.code)\n"
                      % (sys.executable, knobs, str(FAKE_CLAUDE), native_exit))
        after_reply = getattr(self, "claude_after_reply", None)
        if after_reply is not None:
            # Run the actual test fake once, then keep its original process alive after its supported reply.
            # Error-result variants model the documented result field, never an invented transcript terminal.
            claude = ("#!%s\nimport contextlib, io, json, os, runpy, sys, time\nfrom pathlib import Path\n"
                      "os.environ.update(%r)\noutput = io.StringIO()\ncode = 0\ntry:\n"
                      "    with contextlib.redirect_stdout(output):\n"
                      "        runpy.run_path(%r, run_name='__main__')\nexcept SystemExit as stopped:\n"
                      "    code = stopped.code\n"
                      "events = [json.loads(line) for line in output.getvalue().splitlines()]\n"
                      "if %r:\n    events[-1].update(is_error=True, subtype='error_during_execution')\n"
                      "sys.stdout.write(''.join(json.dumps(event) + '\\n' for event in events))\n"
                      "sys.stdout.flush()\ngate = Path(%r)\n"
                      "gate.with_name(gate.name + '.ready').write_text('ready')\n"
                      "deadline = time.monotonic() + 20\n"
                      "while not gate.exists() and time.monotonic() < deadline:\n    time.sleep(0.01)\n"
                      "sys.exit(code if gate.exists() else 89)\n"
                      % (sys.executable, knobs, str(FAKE_CLAUDE), after_reply["error"], str(after_reply["gate"])))
        (self.bin / "claude").write_text(claude)
        return env

    def prepare(self, session=None):
        self.team("init")
        self.team("login")
        session = session or str(uuid.uuid4())
        if self.config["hosts"]["root"] == CLAUDE:
            self.seed(session)
        self.team("root", "--session", session)
        self.team("request", "feature-1", "--file", str(self.write("request.json", self.request())))
        return session

    def seed(self, session):
        team = team_module()
        connection = self.write("empty-servers.json", {"mcpServers": {}})
        argv = team.hierarchy_provision.claude_argv(["--session-id", session], str(connection), [], [], {}, None)
        proc = subprocess.run(argv, cwd=str(self.project), env=self.env(CLAUDE_CONFIG_DIR=str(self.claude_home)),
                              input="Ready.", capture_output=True, text=True, timeout=2)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        [path] = team.hierarchy_hosts.transcripts(CLAUDE, self.claude_home, session)
        return path

    def role(self):
        """Part 1 does not start Claude roles with up: provision an existing test conversation."""
        self.team("init")
        self.team("login")
        session = str(uuid.uuid4())
        self.seed_path = self.seed(session)
        team = team_module()
        request = self.write("role.json", {"base": str(self.base_dir), "endpoint": REVIEWER, "host": CLAUDE,
                                           "session": session, "cwd": str(self.project)})
        argv = [sys.executable, "-I", "-B", str(team.HERE / "hierarchy_provision.py"), "add-role", "--request", str(request)]
        # Setup verifies a committed runtime and durably publishes a binding. A two-second total command cap
        # killed a valid staged publication under load. Observe this one process in waits of at most two seconds;
        # never retry provisioning or a model call. Owner-turn/ROOT concurrency deadlines stay unchanged.
        output, errors = self.tmp / "fixture-add-role.stdout", self.tmp / "fixture-add-role.stderr"
        with output.open("wb") as stdout, errors.open("wb") as stderr:
            process = subprocess.Popen(argv, env=self.env(), stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            deadline = time.monotonic() + 60
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(argv, 60)
                    try:
                        process.wait(timeout=min(2, remaining))
                        break
                    except subprocess.TimeoutExpired:
                        pass  # Wait for the same test-owned setup process, without replaying any effects.
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
        tails = []
        for path in (output, errors):
            with path.open("rb") as stream:
                stream.seek(max(0, path.stat().st_size - 65536))
                tails.append(stream.read(65536).decode("utf-8", "replace"))
        proc = subprocess.CompletedProcess(argv, process.returncode, *tails)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return session


@pytest.fixture
def make(tmp_path, monkeypatch, request):
    built = []
    (tmp_path / ".keep").touch()

    def factory(root=CLAUDE, team=CODEX):
        run = LaneRun(tmp_path, monkeypatch, root, team)
        built.append(run)
        return run

    yield factory
    for run in built:
        if (run.run / "team-state.json").exists():
            operations = state(run).get("operations", {})
            for operation in operations.values() if isinstance(operations, dict) else ():
                if not isinstance(operation, dict):
                    continue
                pid = operation.get("pid")
                if type(pid) is int and 0 < pid < 2 ** 31 and team_module().process_alive(pid):
                    os.kill(pid, signal.SIGTERM)
        # Mutation checks deliberately remove the no-replay guard. Even then, clean up every test fake, including
        # an older process whose operation was overwritten by the mutant. Never signal a pid reused by another job.
        for call in run.claude_calls():
            pid = call["pid"]
            try:
                argv = Path("/proc/%d/cmdline" % pid).read_bytes().split(b"\0")
                if os.fsencode(str(run.bin / "claude")) in argv:
                    os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except FileNotFoundError:
                pass


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.mark.parametrize("message", ["tool_result", None, [], 7])
def test_fix6_claude_transcript_user_shapes(make, message):
    run = make(CODEX, CLAUDE)
    operation, gate = held_after_supported_reply(run)
    finish_fake(run, operation, gate)
    events = rows(run.seed_path)
    if message == "tool_result":
        events.insert(-1, {"type": "user", "sessionId": operation["session"], "uuid": str(uuid.uuid4()),
                           "message": {"role": "user", "content": [{"type": "tool_result", "content": "ok"}]}})
    else:
        events[-2]["message"] = message
    run.seed_path.write_text("".join(json.dumps(event) + "\n" for event in events))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=0 if message == "tool_result" else 2)
    if message == "tool_result":
        assert answer["reconciled"] == operation["id"] and answer["replayed"] is False
        assert not run.mailbox().wake_marker(REVIEWER).exists()
    else:
        assert answer["error"] == ("operation %s transcript cannot prove this session's submitted turn; "
                                   "retain the hold and do not replay" % operation["id"])
        assert files(run.run) == before and state(run)["operations"][REVIEWER] == operation
        assert run.mailbox().wake_marker(REVIEWER).exists()
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1


def test_fix6_forged_birth_cannot_release_live_original(make):
    run = make(CODEX, CLAUDE)
    operation, gate = held_after_supported_reply(run)
    saved = state(run)
    saved["operations"][REVIEWER]["pid_start"] = "1"
    (run.run / "team-state.json").write_text(json.dumps(saved))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
    assert answer["process_observation"] == {"state": "UNAVAILABLE", "reason": "launch identity differs from its durable witness"}
    assert files(run.run) == before and run.mailbox().wake_marker(REVIEWER).exists()
    assert team_module().process_alive(operation["pid"])
    assert run.team("turn", REVIEWER, "Again.", expect=2)["operation"] == saved["operations"][REVIEWER]
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1
    finish_fake(run, operation, gate)


def test_fix6_accounting_cannot_escape_after_caller_cancellation(make):
    run = make(CODEX, CLAUDE)
    run.role()
    gate = run.tmp / "fix6-cancel-gate"
    caller = cancellation_caller(run, gate)
    try:
        gate_ready(gate)
        deadline = time.monotonic() + 2
        while state(run)["operations"][REVIEWER].get("pid") is None and time.monotonic() < deadline:
            time.sleep(0.01)
        operation = state(run)["operations"][REVIEWER]
        assert operation["pid"] is not None
        caller.terminate()
        caller.communicate(timeout=2)
        assert caller.returncode == -signal.SIGTERM
        assert not (run.evidence / ("turn-%s.accounting.json" % operation["id"])).exists()
        finish_fake(run, operation, gate)
        outside = run.tmp / "outside-accounting.jsonl"
        outside.write_bytes(b"")
        saved = state(run)
        saved["operations"][REVIEWER]["turn_log"] = str(outside)
        (run.run / "team-state.json").write_text(json.dumps(saved))
        before = files(run.run)
        answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
        assert answer["error"] == "operation evidence paths differ from the run's canonical paths; retain the hold"
        assert outside.read_bytes() == b"" and files(run.run) == before
        assert run.mailbox().wake_marker(REVIEWER).exists()
        assert run.team("turn", REVIEWER, "Again.", expect=2)["operation"] == saved["operations"][REVIEWER]
    finally:
        if caller.poll() is None:
            caller.terminate()
            caller.communicate(timeout=2)


@pytest.mark.parametrize("field", ["python", "source", "bootstrap"])
def test_fix6_mcp_bootstrap_is_checked_before_probe(make, field):
    run = make()
    run.prepare()
    setup_path = run.base_dir / "provision.json"
    setup = json.loads(setup_path.read_text())
    connection = Path(state(run)["root"]["connection"])
    servers = json.loads(connection.read_text())
    marker = run.tmp / "untrusted-probe-executed"
    attacker = run.tmp / "untrusted-python"
    attacker.write_text("#!%s\nfrom pathlib import Path\nPath(%r).write_text('executed')\n" % (sys.executable, str(marker)))
    attacker.chmod(0o700)
    if field == "python":
        setup["python"] = str(attacker)
        servers["mcpServers"]["aegis_decision"]["command"] = str(attacker)
    elif field == "source":
        setup["source"] = str(run.tmp)
        args = servers["mcpServers"]["aegis_decision"]["args"]
        args[args.index("--entry") + 1] = str(run.tmp / "tools" / "hierarchy_mailbox_mcp.py")
    else:
        (run.base_dir / "runtime-source.py").write_text("raise RuntimeError('untrusted bootstrap')\n")
    setup_path.write_text(json.dumps(setup))
    connection.write_text(json.dumps(servers))
    before = files(run.run)
    answer = run.team("approve", "feature-1", "--reason", "agreed", expect=2)
    assert "runtime" in answer["error"] or "bootstrap" in answer["error"]
    assert not marker.exists() and files(run.run) == before
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 0


def test_fix6_root_bind_checks_runtime_before_binding_or_probe(make):
    run = make()
    run.team("init")
    run.team("login")
    session = str(uuid.uuid4())
    run.seed(session)
    path = run.base_dir / "provision.json"
    setup = json.loads(path.read_text())
    setup["python"] = str(run.tmp / "untrusted-interpreter")
    path.write_text(json.dumps(setup))
    before = files(run.run)
    answer = run.team("root", "--session", session, expect=2)
    assert answer["error"] == "team runtime differs from team-run.json"
    assert files(run.run) == before and run.mailbox().bindings("pilot/root") == []


@pytest.mark.parametrize("change", ["missing", "assignment"])
def test_fix6_v2_requires_main_host_plan(make, change):
    run = make()
    run.prepare()
    path = run.base_dir / "host-plan.json"
    if change == "missing":
        path.unlink()
    else:
        plan = json.loads(path.read_text())
        plan["team"] = CLAUDE
        path.write_text(json.dumps(plan))
    before = files(run.run)
    answer = run.team("approve", "feature-1", "--reason", "agreed", expect=2)
    assert answer["error"] == "v2 MAIN host plan is missing or differs from team-run.json"
    assert files(run.run) == before
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 0


def test_fix6_legacy_no_plan_preserves_proxy_and_certificate_settings(make, monkeypatch, capsys):
    inherited = {"HTTPS_PROXY": "http://fixture.invalid:8080", "SSL_CERT_FILE": "/fixture-ca.pem",
                 "LEGACY_OWNER_SETTING": "fixture-value", "AWS_PROFILE": "fixture-profile", "AWS_REGION": "fixture-region"}
    inherited.update({name: "fixture-protected-value" for name in
        ("CLAUDECODE", "CLAUDE_PID", "CLAUDE_CODE_SESSION_TOKEN", "GROQ_API_KEY", "SSH_AUTH_SOCK", "WRAP_SECRET")})
    for name, value in inherited.items():
        monkeypatch.setenv(name, value)
    run, words, _endpoint = legacy_owner_without_plan(make, "turn")
    captured = []
    original = subprocess.Popen.__init__

    def initialize(process, argv, *args, **kwargs):
        if Path(argv[0]).name == "codex":
            captured.append(dict(kwargs["env"]))
        return original(process, argv, *args, **kwargs)

    monkeypatch.setattr(subprocess.Popen, "__init__", initialize)
    code, _answer = in_process(run, *words, capsys=capsys)
    assert len(captured) == 1, "legacy Codex process observer did not fire"
    assert code == 0 and len(captured) == 1
    assert {name: captured[0][name] for name in inherited} == inherited
    for name in ("HTTPS_PROXY", "SSL_CERT_FILE", "LEGACY_OWNER_SETTING"):
        assert captured[0][name] == os.environ[name]
    baseline = dict(os.environ)
    baseline.update(CODEX_HOME=str(run.codex_home), PYTHONDONTWRITEBYTECODE="1")
    assert captured[0] == baseline


@pytest.mark.parametrize("prefix", [False, True])
def test_fix6_codex_accounting_grows_after_deadline(make, prefix):
    run = make(CODEX, CODEX)
    run.ready("--no-loop")
    # Gate actual fake output before its first event, or after thread.started. No timing assumption about how
    # quickly the owner CLI returns, and no production fixture switch. The fake executes exactly once.
    gate = run.tmp / "fix6-output-gate"
    staged = ("    native = subprocess.Popen([sys.executable, FAKE, *argv], env=env, stdout=subprocess.PIPE)\n"
              "    first = native.stdout.readline()\n"
              "    if %r:\n        sys.stdout.buffer.write(first)\n        sys.stdout.flush()\n"
              "    import time\n    gate = Path(%r)\n"
              "    gate.with_name(gate.name + '.ready').write_text('ready')\n"
              "    deadline = time.monotonic() + 20\n"
              "    while not gate.exists() and time.monotonic() < deadline:\n        time.sleep(0.01)\n"
              "    if not %r:\n        sys.stdout.buffer.write(first)\n"
              "    sys.stdout.buffer.write(native.stdout.read())\n    sys.stdout.flush()\n"
              "    code = native.wait(timeout=2)" % (prefix, str(gate), prefix))
    run.codex_script = run.codex_script.replace(
        "    code = subprocess.run([sys.executable, FAKE, *argv], env=env).returncode", staged)
    answer = run.team("turn", REVIEWER, "Check in.", expect=3, AEGIS_TEAM_TURN_TIMEOUT="0.2")
    operation = answer["operation"]
    gate_ready(gate)
    initial = Path(operation["stdout"]).read_bytes()
    assert bool(initial) is prefix
    finish_fake(run, operation, gate)
    final = Path(operation["stdout"]).read_bytes()
    assert len(final) > len(initial)
    result = run.team("turn", REVIEWER, "--reconcile")
    assert result["reconciled"] == operation["id"] and result["replayed"] is False
    assert (run.evidence / operation["turn_log"]).read_bytes() == final
    receipt = json.loads((run.evidence / ("turn-%s.accounting.json" % operation["id"])).read_text())
    assert receipt["log_span"]["length"] == len(final) and receipt["usage"] == {"input_tokens": 1, "output_tokens": 1}
    assert run.team("turn", REVIEWER, "--reconcile", expect=2)["error"] == REVIEWER + " has no unresolved operation"


def gate_ready(gate):
    ready = gate.with_name(gate.name + ".ready")
    deadline = time.monotonic() + 2
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ready.exists()


def cancellation_caller(run, gate):
    # CLI validation/probing is setup, before the cancellation scenario starts. Signal the actual model spawn
    # boundary from this test-owned caller; retain the existing two-second fake-readiness and completion checks.
    launching = gate.with_name(gate.name + ".launching")
    script = ("import runpy, subprocess, sys\nfrom pathlib import Path\n"
              "original = subprocess.Popen.__init__\n"
              "def initialize(process, argv, *args, **kwargs):\n"
              "    original(process, argv, *args, **kwargs)\n"
              "    if Path(argv[0]).name == 'claude' and '--resume' in argv:\n"
              "        Path(%r).write_text('launched')\n"
              "subprocess.Popen.__init__ = initialize\n"
              "sys.argv = sys.argv[1:]\nrunpy.run_path(sys.argv[0], run_name='__main__')\n" % str(launching))
    output, errors = gate.with_name(gate.name + ".stdout"), gate.with_name(gate.name + ".stderr")
    with output.open("wb") as stdout, errors.open("wb") as stderr:
        caller = subprocess.Popen([sys.executable, "-I", "-B", "-c", script, str(TEAM), "--config", str(run.config_path),
                                   "turn", REVIEWER, "Check in."], env=run.env(FAKE_CLAUDE_GATE=str(gate)),
                                  stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
    deadline = time.monotonic() + 60
    while not launching.exists() and caller.poll() is None and time.monotonic() < deadline:
        try:
            caller.wait(timeout=min(0.05, max(0.001, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            pass  # Observe this same setup process; never repeat a model invocation.
    if not launching.exists():
        if caller.poll() is None:
            caller.terminate()
            caller.wait(timeout=2)
        tails = []
        for path in (output, errors):
            with path.open("rb") as stream:
                stream.seek(max(0, path.stat().st_size - 65536))
                tails.append(stream.read(65536).decode("utf-8", "replace"))
        pytest.fail("caller did not launch the test fake; exit=%r; stdout=%r; stderr=%r" %
                    (caller.returncode, *tails))
    return caller


def test_fix7_coordinated_interpreter_changes_do_not_authorize_a_probe(make):
    run = make()
    run.prepare()
    invoked = run.tmp / "forged-interpreter-executed"
    attacker = run.tmp / "forged-interpreter"
    attacker.write_text("#!%s\nimport json,sys\nfrom pathlib import Path\nPath(%r).write_text('executed')\n"
                        "for line in sys.stdin:\n    request=json.loads(line)\n"
                        "    tools=[{'name':name} for name in %r]\n"
                        "    print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':{'tools':tools}}),flush=True)\n"
                        % (sys.executable, str(invoked), ROOT_TOOLS))
    attacker.chmod(0o700)
    run.config["recipes"]["python"] = str(attacker)
    run.save()
    setup_path = run.base_dir / "provision.json"
    setup = json.loads(setup_path.read_text())
    setup["python"] = str(attacker)
    setup_path.write_text(json.dumps(setup))
    connection = Path(state(run)["root"]["connection"])
    servers = json.loads(connection.read_text())
    servers["mcpServers"]["aegis_decision"]["command"] = str(attacker)
    connection.write_text(json.dumps(servers))
    plan_path = run.base_dir / "host-plan.json"
    plan = json.loads(plan_path.read_text())
    plan["config_sha256"] = team_module().sha_file(run.config_path)
    plan_path.write_text(json.dumps(plan))
    before = files(run.run)
    answer = run.team("approve", "feature-1", "--reason", "agreed", expect=2)
    assert answer["error"] == "team runtime differs from the owner-held record"
    assert not invoked.exists() and files(run.run) == before
    assert not [call for call in run.claude_calls() if "--resume" in call["argv"]]


@pytest.mark.parametrize("change", ["revision", "custody"])
def test_fix7_runtime_authority_is_not_redefined_by_mutable_publications(make, change):
    run = make() if change == "revision" else make(CODEX, CLAUDE)
    invoked = run.tmp / "changed-source-executed"
    if change == "revision":
        run.prepare()
        entry = run.source / "tools" / "hierarchy_mailbox_mcp.py"
        entry.write_text("import json,sys\nfrom pathlib import Path\nPath(%r).write_text('executed')\n"
                         "for line in sys.stdin:\n    request=json.loads(line)\n"
                         "    print(json.dumps({'id':request['id'],'result':{'tools':[{'name':name} for name in %r]}}),flush=True)\n"
                         % (str(invoked), ROOT_TOOLS))
        git(run.source, "add", "tools/hierarchy_mailbox_mcp.py")
        git(run.source, "commit", "-qm", "fixture changed runtime")
        path = run.base_dir / "provision.json"
        setup = json.loads(path.read_text())
        setup.update(source_commit=git(run.source, "rev-parse", "HEAD"), source_tree=git(run.source, "rev-parse", "HEAD^{tree}"))
        path.write_text(json.dumps(setup))
        words = ("approve", "feature-1", "--reason", "agreed")
    else:
        run.role()
        run.config["project"] = str(run.source)
        run.save()
        saved = state(run)
        saved["custody"]["project"] = str(run.source)
        (run.run / "team-state.json").write_text(json.dumps(saved))
        path = run.base_dir / "host-plan.json"
        plan = json.loads(path.read_text())
        plan["config_sha256"] = team_module().sha_file(run.config_path)
        path.write_text(json.dumps(plan))
        path = run.base_dir / "profiles" / "pilot%2Flane%2Freview-g1.wake.json"
        profile = json.loads(path.read_text())
        profile["cwd"] = str(run.source)
        path.write_text(json.dumps(profile))
        words = ("turn", REVIEWER, "Check in.")
    before = files(run.run)
    answer = run.team(*words, expect=2)
    assert answer["error"] == "team runtime differs from the owner-held record"
    assert files(run.run) == before and not invoked.exists()
    assert not [call for call in run.claude_calls() if "--resume" in call["argv"]]


def test_fix7_coordinated_launch_forgery_keeps_the_live_session_held(make):
    run = make(CODEX, CLAUDE)
    operation, gate = held_after_supported_reply(run)
    saved = state(run)
    saved["operations"][REVIEWER]["pid_start"] = "1"
    (run.run / "team-state.json").write_text(json.dumps(saved))
    launch_path = run.evidence / ("turn-%s.launch.json" % operation["id"])
    launch = json.loads(launch_path.read_text())
    launch["pid_start"] = "1"
    launch_path.write_text(json.dumps(launch))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
    assert answer["process_observation"]["state"] == "UNAVAILABLE"
    assert answer["operation"] == saved["operations"][REVIEWER]
    assert files(run.run) == before and run.mailbox().wake_marker(REVIEWER).exists()
    assert team_module().process_alive(operation["pid"])
    assert run.team("turn", REVIEWER, "Again.", expect=2)["operation"] == saved["operations"][REVIEWER]
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1
    finish_fake(run, operation, gate)


def test_fix7_live_session_corroborates_a_changed_birth_observation(make, monkeypatch, capsys):
    run = make(CODEX, CLAUDE)
    operation, gate = held_after_supported_reply(run)
    target = Path("/proc/%d/stat" % operation["pid"])
    snapshot = target.read_text()
    prefix, tail = snapshot.rsplit(")", 1)
    fields = tail.split()
    fields[19] = str(int(fields[19]) + 1)
    changed = prefix + ") " + " ".join(fields) + "\n"
    original = Path.read_text
    before = files(run.run)
    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_text", lambda path, *a, **kw: changed if path == target else original(path, *a, **kw))
        code, answer = in_process(run, "turn", REVIEWER, "--reconcile", capsys=capsys)
    assert code == 2 and answer["error"] == "operation %s is unresolved: its process is still running" % operation["id"]
    assert files(run.run) == before and run.mailbox().wake_marker(REVIEWER).exists()
    assert team_module().process_alive(operation["pid"])
    finish_fake(run, operation, gate)


def test_fix7_owner_intent_survives_lost_mutable_state_and_marker(make):
    run = make(CODEX, CLAUDE)
    operation, gate = held_after_supported_reply(run)
    saved = state(run)
    saved["operations"].clear()
    (run.run / "team-state.json").write_text(json.dumps(saved))
    run.mailbox().wake_marker(REVIEWER).unlink()
    run.claude_after_reply = None
    status = run.team("status")
    assert status["unresolved_operations"][REVIEWER]["id"] == operation["id"]
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "Again.", expect=2, AEGIS_TEAM_TURN_TIMEOUT="0.2")
    assert answer["operation"]["id"] == operation["id"] and files(run.run) == before
    down = run.team("down", expect=3)
    assert operation["id"] in json.dumps(down) and team_module().process_alive(operation["pid"])
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1
    finish_fake(run, operation, gate)


def test_fix7_conflicting_owner_intent_does_not_release_an_operation(make):
    run = make(CODEX, CLAUDE)
    operation, gate = held_after_supported_reply(run)
    finish_fake(run, operation, gate)
    path = run.run / ".owner-custody" / "active-pilot%2Flane%2Freview.json"
    value = {**operation, "id": uuid.uuid4().hex, "pid": None}
    value.pop("pid_start")
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
    assert answer["error"] == "invalid active record"
    assert answer["custody_problem"]["reason"] == "record shape"
    assert files(run.run) == before and run.mailbox().wake_marker(REVIEWER).exists()


@pytest.mark.parametrize("fault", ["permissions", "symlink", "shape", "directory", "hardlink"])
def test_fix7_owner_runtime_record_is_checked_before_model_effects(make, fault):
    run = make(CODEX, CLAUDE)
    run.role()
    path = run.run / ".owner-custody" / "runtime.json"
    assert path.is_file()
    if fault == "permissions":
        path.chmod(0o644)
    elif fault == "directory":
        path.parent.chmod(0o755)
    elif fault == "hardlink":
        os.link(path, run.tmp / "aliased-owner-runtime.json")
    elif fault == "symlink":
        foreign = run.tmp / "foreign-owner-record.json"
        path.rename(foreign)
        path.symlink_to(foreign)
    else:
        path.write_text("null")
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "Check in.", expect=2)
    assert answer["custody_problem"]["reason"] == {
        "permissions": "record permissions", "symlink": "record symlink", "shape": "record shape",
        "directory": "directory permissions", "hardlink": "record hardlink"}[fault]
    assert files(run.run) == before and not run.mailbox().wake_marker(REVIEWER).exists()


def test_fix7_connection_cannot_grant_another_repository(make):
    run = make(CODEX, CLAUDE)
    run.role()
    path = run.base_dir / "profiles" / "pilot%2Flane%2Freview-g1.wake.json"
    profile = json.loads(path.read_text())
    argv = profile["argv"]
    connection = Path(argv[argv.index("--mcp-config") + 1])
    servers = json.loads(connection.read_text())
    servers["mcpServers"]["aegis_mailbox"]["args"] += ["--source-repo", str(run.source)]
    connection.write_text(json.dumps(servers))
    index = argv.index("--allowedTools") + 1
    argv[index] += ",mcp__aegis_mailbox__source_show,mcp__aegis_mailbox__source_grep"
    path.write_text(json.dumps(profile))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "Check in.", expect=2)
    assert answer["error"] == "Claude connection names an unauthorized source repository"
    assert files(run.run) == before and not run.mailbox().wake_marker(REVIEWER).exists()
    assert not [call for call in run.claude_calls() if "--resume" in call["argv"]]


@pytest.mark.parametrize("servers", [None, [], {"aegis_mailbox": None},
    {"aegis_mailbox": {"command": "python", "args": None}},
    {"aegis_mailbox": {"command": "python", "args": [None]}}])
def test_fix7_malformed_connection_refuses_before_effects(make, servers):
    run = make(CODEX, CLAUDE)
    run.role()
    profile = json.loads((run.base_dir / "profiles" / "pilot%2Flane%2Freview-g1.wake.json").read_text())
    path = Path(profile["argv"][profile["argv"].index("--mcp-config") + 1])
    path.write_text(json.dumps({"mcpServers": servers}))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "Check in.", expect=2)
    assert answer["error"] == "invalid Claude connection servers"
    assert files(run.run) == before and not run.mailbox().wake_marker(REVIEWER).exists()


@pytest.mark.parametrize("value", [None, [], "extra"])
def test_fix7_malformed_team_provision_refuses_before_model_effects(make, value):
    run = make(CODEX, CLAUDE)
    run.role()
    path = run.base_dir / "provision.json"
    if value == "extra":
        record = json.loads(path.read_text())
        record["board"] = None  # The team-run configuration does not authorize a board, even an empty one.
        value = record
    path.write_text(json.dumps(value))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "Check in.", expect=2)
    assert answer["error"] == "invalid team provision record"
    assert files(run.run) == before and not run.mailbox().wake_marker(REVIEWER).exists()


@pytest.mark.parametrize("value", [None, []])
def test_fix7_malformed_replacement_marker_keeps_custody(make, value):
    run = make(CODEX, CLAUDE)
    operation, gate = held_after_supported_reply(run)
    finish_fake(run, operation, gate)
    marker = run.mailbox().wake_marker(REVIEWER)
    marker.write_text(json.dumps(value))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
    assert answer["error"] == "operation %s wake marker changed; retain the hold and do not clear another wake" % operation["id"]
    assert files(run.run) == before and state(run)["operations"][REVIEWER] == operation


def test_fix7_root_release_recovery_still_checks_the_approval_journal(make, monkeypatch, capsys):
    run = make()
    run.prepare()
    endpoint = "pilot/root"
    original_init, original_replace = subprocess.Popen.__init__, os.replace
    controls = run.env()
    knobs = {name: value for name, value in controls.items() if name.startswith(("FAKE_", "WRAP_"))}
    wrapper = ("#!%s\nimport os,runpy\nos.environ.update(%r)\n"
               "module=runpy.run_path(%r,run_name='fixture_no_decision')\n"
               "module['main'].__globals__['decide']=lambda *args:None\nraise SystemExit(module['main']())\n"
               % (sys.executable, knobs, str(FAKE_CLAUDE)))
    invoked, lost = [], []

    def initialize(process, argv, *args, **kwargs):
        if Path(str(argv[0])).name == "claude" and "--resume" in argv and "--print" in argv:
            invoked.append(True)
            (run.bin / "claude").write_text(wrapper)
        return original_init(process, argv, *args, **kwargs)

    def replace(source, destination, *args, **kwargs):
        if Path(destination) == run.run / "team-state.json" and not lost:
            old = state(run).get("operations", {}).get(endpoint)
            new = json.loads(Path(source).read_text()).get("operations", {}).get(endpoint)
            if old and old.get("release") and new is None:
                lost.append(True)
                raise OSError("fixture: ROOT release retirement reply lost")
        return original_replace(source, destination, *args, **kwargs)

    for name, value in controls.items():
        monkeypatch.setenv(name, value)
    with monkeypatch.context() as patch:
        patch.setattr(subprocess.Popen, "__init__", initialize)
        patch.setattr(os, "replace", replace)
        code, answer = in_process(run, "approve", "feature-1", "--reason", "agreed", capsys=capsys)
    assert code == 3 and invoked == [True] and lost == [True]
    operation = state(run)["operations"][endpoint]
    assert operation["id"] == answer["operation"]["id"] and "release" in operation
    log = run.evidence / "root-turns.jsonl"
    before = log.read_bytes()
    assert rows(log)[0]["exit_code"] == 0
    result = run.team("approve", "feature-1", "--reconcile", expect=3)
    assert result == {"endpoint": endpoint, "reconciled": operation["id"], "outcome": "failed", "replayed": False}
    assert log.read_bytes() == before and rows(log)[0]["exit_code"] == 0
    assert state(run)["operations"] == {}
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1


@pytest.mark.parametrize("change", [None, "prompt", "birth"])
def test_fix7_launch_publication_recovers_only_the_original_pending_intent(make, monkeypatch, capsys, change):
    run = make(CODEX, CLAUDE)
    run.role()
    gate = run.tmp / "finish-after-pending-pid"
    original = os.replace
    lost = []

    def replace(source, destination, *args, **kwargs):
        if Path(destination) == run.run / "team-state.json" and not lost:
            operation = json.loads(Path(source).read_text()).get("operations", {}).get(REVIEWER)
            if operation and operation.get("pid"):
                lost.append(operation)
                raise OSError("fixture: PID transaction reply lost before publication")
        return original(source, destination, *args, **kwargs)

    for name, value in run.env(FAKE_CLAUDE_GATE=str(gate)).items():
        monkeypatch.setenv(name, value)
    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", replace)
        code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 3 and len(lost) == 1 and answer["operation"]["pid"] == lost[0]["pid"]
    operation = lost[0]
    pending = state(run)["operations"][REVIEWER]
    assert pending["pid"] is None and "pid_start" not in pending
    gate_ready(gate)
    finish_fake(run, operation, gate)
    if change:
        if change == "prompt":
            saved = state(run)
            saved["operations"][REVIEWER]["prompt_sha256"] = "0" * 64
            (run.run / "team-state.json").write_text(json.dumps(saved))
        else:
            path = run.evidence / ("turn-%s.launch.json" % operation["id"])
            launch = json.loads(path.read_text())
            launch["pid_start"] = "1"
            path.write_text(json.dumps(launch))
        before = files(run.run)
        result = run.team("turn", REVIEWER, "--reconcile", expect=2)
        assert result["process_observation"]["state"] == "UNAVAILABLE" and files(run.run) == before
        assert run.mailbox().wake_marker(REVIEWER).exists()
    else:
        result = run.team("turn", REVIEWER, "--reconcile")
        assert result == {"endpoint": REVIEWER, "reconciled": operation["id"], "outcome": "completed", "replayed": False}
        assert state(run)["operations"] == {} and not run.mailbox().wake_marker(REVIEWER).exists()
        [row] = rows(run.evidence / operation["turn_log"])
        assert row["operation_id"] == operation["id"] and row["exit_code"] is None
        assert run.team("turn", REVIEWER, "--reconcile", expect=2)["error"] == REVIEWER + " has no unresolved operation"
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1


def fixture_cli(run, name, *arguments):
    argv = [sys.executable, "-I", "-B", str(TEAM.parent / name), *map(str, arguments)]
    prefix = "fixture-" + uuid.uuid4().hex
    output, errors = run.tmp / (prefix + ".stdout"), run.tmp / (prefix + ".stderr")
    with output.open("wb") as stdout, errors.open("wb") as stderr:
        process = subprocess.Popen(argv, env=run.env(CLAUDE_CONFIG_DIR=str(run.claude_home)),
                                   stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
        deadline = time.monotonic() + 60
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, 60)
                try:
                    process.wait(timeout=min(2, remaining))
                    break
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
    return subprocess.CompletedProcess(argv, process.returncode, output.read_text(), errors.read_text())


@pytest.mark.parametrize("keep_foreign_marker", [False, True, "prefix", "replace", "truncate", "missing", "hardlink"])
def test_fix7_release_recovery_is_bounded_before_a_later_public_wake(make, monkeypatch, capsys, keep_foreign_marker):
    run = make(CODEX, CLAUDE)
    run.role()
    sender_session = str(uuid.uuid4())
    run.seed(sender_session)
    sender = run.write("sender.json", {"base": str(run.base_dir), "endpoint": "pilot/orchestrator", "host": CLAUDE,
                                      "session": sender_session, "cwd": str(run.project)})
    added = fixture_cli(run, "hierarchy_provision.py", "add-role", "--request", sender)
    assert added.returncode == 0, added.stdout + added.stderr
    marker = run.mailbox().wake_marker(REVIEWER)
    original = os.unlink
    lost = []
    run.claude_exit_after_reply = 1

    def unlink(path, *args, **kwargs):
        if Path(path) == marker and not lost:
            original(path, *args, **kwargs)
            lost.append(True)
            raise OSError("fixture: release reply lost after unlink")
        return original(path, *args, **kwargs)

    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    with monkeypatch.context() as patch:
        patch.setattr(os, "unlink", unlink)
        code, answer = in_process(run, "turn", REVIEWER, "Original owner turn.", capsys=capsys)
    assert code == 3 and lost == [True] and not marker.exists()
    operation = state(run)["operations"][REVIEWER]
    assert "release" in operation and operation["id"] == answer["operation"]["id"]
    log = run.evidence / operation["turn_log"]
    accounting = run.evidence / ("turn-%s.accounting.json" % operation["id"])
    accounted = (log.read_bytes(), accounting.read_bytes())
    run.claude_exit_after_reply = None
    binding = run.mailbox().current_binding("pilot/orchestrator")
    note = run.write("later-mail.json", {"message_id": "later-note", "from": "pilot/orchestrator", "to": REVIEWER,
        "host": binding["host"], "session": binding["session"], "binding_generation": binding["generation"],
        "type": "info", "body": "Later wake."})
    publish = fixture_cli(run, "hierarchy_mailbox.py", "--root", run.base_dir / "mailbox", "publish", "--request", note)
    assert publish.returncode == 0, publish.stdout + publish.stderr
    profile = run.base_dir / "profiles" / "pilot%2Flane%2Freview-g1.wake.json"
    woke = fixture_cli(run, "hierarchy_wake.py", "--root", run.base_dir / "mailbox", "--delivery-dir",
                       run.base_dir / "delivery", "--endpoint", REVIEWER, "--profile", profile)
    assert woke.returncode in (0, 3), woke.stdout + woke.stderr
    assert json.loads(woke.stdout)["exit_code"] == 0
    assert len([row for row in rows(run.seed_path) if row.get("type") == "user"]) == 3
    if isinstance(keep_foreign_marker, str):
        raw = run.seed_path.read_bytes()
        if keep_foreign_marker == "prefix":
            run.seed_path.write_bytes(b"X" + raw[1:])
        elif keep_foreign_marker == "replace":
            run.seed_path.rename(run.tmp / "original-released-transcript")
            run.seed_path.write_bytes(raw)
        elif keep_foreign_marker == "truncate":
            run.seed_path.write_bytes(raw[:operation["transcripts"][str(run.seed_path)]["offset"]])
        elif keep_foreign_marker == "missing":
            run.seed_path.unlink()
        else:
            os.link(run.seed_path, run.tmp / "hardlinked-transcript")
        result = run.team("turn", REVIEWER, "--reconcile", expect=3)
        assert result == {"endpoint": REVIEWER, "reconciled": operation["id"], "outcome": "failed", "replayed": False,
                          "post_seal_evidence": "missing" if keep_foreign_marker == "missing" else "changed"}
        assert state(run)["operations"] == {} and not marker.exists()
        assert (log.read_bytes(), accounting.read_bytes()) == accounted
        assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 2
        return
    if keep_foreign_marker is True:
        from hierarchy_mailbox import writer_lock
        from hierarchy_wake import claim_wake
        with writer_lock(run.base_dir / "mailbox"):
            claim_wake(run.mailbox(), REVIEWER)
        foreign = marker.read_bytes()
    result = run.team("turn", REVIEWER, "--reconcile", expect=3)
    assert result == {"endpoint": REVIEWER, "reconciled": operation["id"], "outcome": "failed", "replayed": False}
    assert state(run)["operations"] == {} and (log.read_bytes(), accounting.read_bytes()) == accounted
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 2
    if keep_foreign_marker:
        assert marker.read_bytes() == foreign
    else:
        assert not marker.exists()


def test_claude_root_binds_decides_and_records_usage(make):
    run = make()
    session = run.prepare()
    assert state(run)["root"]["tools"] == ROOT_TOOLS
    record = json.loads((run.base_dir / "sessions" / "pilot%2Froot-g1.json").read_text())
    assert (record["schema"], record["host_kind"], record["session"]) == (
        "aegis.team-session/v1", CLAUDE, session)
    assert run.team("approve", "feature-1", "--reason", "agreed")["decision"] == "approve"
    [turn] = rows(run.evidence / "root-turns.jsonl")
    assert turn["usage"]["input_tokens"] == 1203
    assert turn["usage"]["cached_input_tokens"] == 1000
    assert turn["usage"]["cache_write_input_tokens"] == 200
    assert turn["usage"]["output_tokens"] == 40
    call = run.claude_calls()[-1]
    assert call["config_dir"] == str(run.claude_home) and call["billing"] == []
    assert call["argv"][call["argv"].index("--resume") + 1] == session
    assert all(flag in call["argv"] for flag in ("--restricted", "--strict-mcp-config", "--print"))
    assert "--model" not in call["argv"]
    assert session not in (run.run / "team-commands.jsonl").read_text()


@pytest.mark.parametrize("mode", ["", "no-result"])
def test_codex_root_claude_role_turn(make, mode):
    run = make(CODEX, CLAUDE)
    session = run.role()
    run.team("root", "--session", "codex-root")
    answer = run.team("turn", REVIEWER, "Check in.", FAKE_CLAUDE_MODE=mode)
    assert answer["exit_code"] == 0 and answer["items"][-1]["text"] == "done"
    [turn] = rows(Path(answer["log"]))
    assert turn["session"] == session
    assert (turn["usage"] is None) == (mode == "no-result")
    assert len(rows(run.seed_path)) > 1


@pytest.mark.parametrize("name", BILLING)
def test_billing_refusal_has_no_effect(make, name):
    run = make()
    run.prepare()
    before, calls = files(run.run), run.claude_calls()
    answer = run.team("approve", "feature-1", "--reason", "agreed", expect=2, **{name: "fixture"})
    assert name in answer["error"]
    assert files(run.run) == before and run.claude_calls() == calls


def test_changed_credentials_refuse_before_spawn(make):
    run = make()
    run.prepare()
    (run.claude_home / ".credentials.json").write_text("changed login")
    before, calls = files(run.run), run.claude_calls()
    answer = run.team("approve", "feature-1", "--reason", "agreed", expect=2)
    assert "the run's Claude login changed since `login`" in answer["error"]
    assert files(run.run) == before and run.claude_calls() == calls


def test_root_unconfirmed_session_refuses_without_writes(make):
    run = make()
    run.team("init")
    run.team("login")
    before = files(run.run)
    answer = run.team("root", "--session", str(uuid.uuid4()), expect=2)
    assert "not confirmed" in answer["error"]
    assert files(run.run) == before
    assert run.mailbox().status()["bindings"]["pilot/root"] is None


def test_root_tools_mismatch_refuses_before_binding(make, monkeypatch, capsys):
    run = make()
    run.team("init")
    run.team("login")
    session = str(uuid.uuid4())
    run.seed(session)
    team = team_module()
    original = team.hierarchy_roles.decision_tools
    monkeypatch.setattr(team.hierarchy_roles, "decision_tools", lambda entry: list(original(entry)) + ["unexpected"])
    before = files(run.run)
    code, answer = in_process(run, "root", "--session", session, capsys=capsys)
    assert code == 2 and "ROOT tools mismatch" in answer["error"]
    assert files(run.run) == before


def test_wrong_host_plan_refuses_owner_turn(make):
    run = make(CODEX, CLAUDE)
    run.role()
    path = run.base_dir / "host-plan.json"
    value = json.loads(path.read_text())
    value["team"] = CODEX
    path.write_text(json.dumps(value))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "Check in.", expect=2)
    assert "host plan" in answer["error"]
    assert files(run.run) == before


def test_changed_claude_profile_refuses_before_wake_marker(make):
    run = make(CODEX, CLAUDE)
    run.role()
    path = run.base_dir / "profiles" / "pilot%2Flane%2Freview-g1.wake.json"
    profile = json.loads(path.read_text())
    profile["argv"].remove("--restricted")
    path.write_text(json.dumps(profile))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "Check in.", expect=2)
    assert "Claude print profile differs" in answer["error"]
    assert files(run.run) == before and not run.mailbox().wake_marker(REVIEWER).exists()


@pytest.mark.parametrize("change", ["cwd", "extra"])
def test_claude_profile_cannot_change_worktree_or_schema(make, change):
    run = make(CODEX, CLAUDE)
    run.role()
    path = run.base_dir / "profiles" / "pilot%2Flane%2Freview-g1.wake.json"
    profile = json.loads(path.read_text())
    if change == "cwd":
        profile["cwd"] = str(run.tmp)
    else:
        profile["unexpected"] = True
    path.write_text(json.dumps(profile))
    before, calls = files(run.run), run.claude_calls()
    answer = run.team("turn", REVIEWER, "Check in.", expect=2)
    if change == "cwd":
        assert answer["error"] == "PATH includes a model-writable directory or ancestor; use absolute trusted program directories"
        assert answer["custody_problem"]["reason"] == "model executable scope"
    else:
        assert "unexpected fields" in answer["error"]
    assert files(run.run) == before and run.claude_calls() == calls


@pytest.mark.parametrize("mode,expect", [("", 0), ("fail", 2), ("no-result", 0)])
def test_claude_role_deadline_reconciles_completed_or_failed_turn(make, mode, expect):
    run = make(CODEX, CLAUDE)
    run.role()
    gate = run.tmp / "finish-turn"
    run.team("turn", REVIEWER, "Check in.", expect=3, AEGIS_TEAM_TURN_TIMEOUT="0.25",
             FAKE_CLAUDE_GATE=str(gate), FAKE_CLAUDE_MODE=mode)
    gate_ready(gate)
    operation = state(run)["operations"][REVIEWER]
    marker = run.mailbox().wake_marker(REVIEWER)
    assert marker.exists() and team_module().process_alive(operation["pid"])
    before = files(run.run)
    assert "unresolved" in run.team("turn", REVIEWER, "Again.", expect=2)["error"]
    assert "still running" in run.team("turn", REVIEWER, "--reconcile", expect=2)["error"]
    assert files(run.run) == before
    gate.write_text("finish")
    limit = time.monotonic() + 2
    while team_module().process_alive(operation["pid"]) and time.monotonic() < limit:
        time.sleep(0.02)
    assert not team_module().process_alive(operation["pid"])
    finished = files(run.run)
    result = run.team("turn", REVIEWER, "--reconcile", expect=expect)
    if mode == "fail":
        assert result["error"] == (
            "operation %s is unresolved: the transcript has no completed or failed turn; "
            "retain the hold and do not replay" % operation["id"])
        assert state(run)["operations"][REVIEWER] == operation and marker.exists()
        assert files(run.run) == finished
        assert run.team("turn", REVIEWER, "Again.", expect=2)["operation"] == operation
        assert team_module().hierarchy_hosts.claude_usage(Path(operation["stdout"]).read_bytes())["input_tokens"] == 1203
        assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1
    else:
        assert result["replayed"] is False and not marker.exists()
    assert len(rows(run.evidence / ("role-turns-%s.jsonl" % REVIEWER.replace("/", "%2F")))) == 1


@pytest.mark.parametrize("command", ["approve", "turn"])
def test_codex_deadline_never_kills_or_replays(make, command):
    run = make(CODEX, CODEX)
    if command == "approve":
        run.prepare("codex-root")
        words = ("approve", "feature-1", "--reason", "agreed")
        endpoint = "pilot/root"
        extra = {}
    else:
        run.ready("--no-loop")
        words, endpoint = ("turn", REVIEWER, "Check in."), REVIEWER
        script = run.write("script.json", {"turns": [{"match": "Check in.", "context_delay": 0}]})
        extra = {"FAKE_CODEX_SCRIPT": str(script)}
    # Keep the actual fake process alive until both public commands returned; fixed sleeps raced slow bookkeeping.
    gate = run.tmp / "codex-deadline-finish"
    run.codex_script = run.codex_script.replace(
        "from pathlib import Path",
        "from pathlib import Path\nif 'resume' in sys.argv:\n"
        "    import time\n    gate=Path(%r)\n"
        "    until=time.monotonic()+20\n"
        "    while not gate.exists() and time.monotonic()<until:\n        time.sleep(0.01)" % str(gate), 1)
    run.team(*words, expect=3, AEGIS_TEAM_TURN_TIMEOUT="0.25", **extra)
    operation = state(run)["operations"][endpoint]
    assert team_module().process_alive(operation["pid"])
    run.team(*words, expect=2)
    gate.write_text("finish")
    limit = time.monotonic() + 2
    while team_module().process_alive(operation["pid"]) and time.monotonic() < limit:
        time.sleep(0.02)
    assert not team_module().process_alive(operation["pid"])
    if command == "turn":
        assert run.team("turn", endpoint, "--reconcile")["replayed"] is False
    else:
        # The old Codex ROOT test fake emits stream events but no rollout. Process exit cannot clear that hold.
        assert "no completed or failed turn" in run.team("approve", "feature-1", "--reconcile", expect=2)["error"]


def test_deadline_holds_live_root_then_reconciles_without_replay(make):
    run = make()
    run.prepare()
    gate = run.tmp / "finish-approve"
    answer = run.team("approve", "feature-1", "--reason", "agreed", expect=3,
                      AEGIS_TEAM_TURN_TIMEOUT="0.3", FAKE_CLAUDE_GATE=str(gate))
    gate_ready(gate)
    operation = state(run)["operations"]["pilot/root"]
    assert operation["id"] and operation["started_at"] and operation["endpoint"] == "pilot/root"
    assert team_module().process_alive(operation["pid"])
    assert "unresolved" in answer["error"]
    before = files(run.run)
    assert "unresolved" in run.team("approve", "feature-1", "--reason", "again", expect=2)["error"]
    assert files(run.run) == before
    assert "pilot/root" in run.team("status")["unresolved_operations"]
    gate.write_text("finish")
    limit = time.monotonic() + 2
    while team_module().process_alive(operation["pid"]) and time.monotonic() < limit:
        time.sleep(0.02)
    assert not team_module().process_alive(operation["pid"])
    assert run.team("approve", "feature-1", "--reconcile")["reconciled"] == operation["id"]
    assert state(run).get("operations", {}) == {}
    assert len(rows(run.evidence / "root-turns.jsonl")) == 1


def test_allowlist_drops_names_without_values(make):
    run = make()
    run.prepare()
    secret_names = ("CLAUDE_CODE_SESSION_ID", "CLAUDE_NEW_TOKEN", "GOOGLE_API_KEY", "SSH_AUTH_SOCK")
    run.team("approve", "feature-1", "--reason", "agreed", **dict.fromkeys(secret_names, "private-fixture-value"))
    call = run.claude_calls()[-1]
    assert not set(call["environment_names"]) & set(secret_names)
    evidence = (run.evidence / "child-environment.json").read_text()
    assert all(name in evidence for name in secret_names)
    assert "private-fixture-value" not in evidence


@pytest.mark.parametrize("surface", ["child", "loop"])
def test_codex_only_drops_the_ambient_claude_home(make, monkeypatch, surface):
    run = make(CODEX, CODEX)
    elsewhere = str(run.tmp / "elsewhere")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", elsewhere)
    run.team("init", CLAUDE_CONFIG_DIR=elsewhere)
    team = team_module()
    parsed = team.Run(str(run.config_path))
    if surface == "child":
        assert "CLAUDE_CONFIG_DIR" not in team.child_env(parsed)
    else:
        loop = team.start_loop(parsed)
        try:
            environ = proc_environ(loop["pid"])
            assert "CLAUDE_CONFIG_DIR" not in environ
        finally:
            team.stop_loop(parsed, 2)
    evidence = json.loads((run.evidence / "child-environment.json").read_text())
    assert "CLAUDE_CONFIG_DIR" in evidence["dropped_names"]
    assert elsewhere not in (run.evidence / "child-environment.json").read_text()


def test_codex_home_uses_the_password_database_guard(make, monkeypatch, capsys):
    from types import SimpleNamespace
    import pwd
    run = make(CODEX, CODEX)
    owner = run.tmp / "password-home"
    owner.mkdir()
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=str(owner)))
    run.config["codex_home"] = str(owner / ".codex" / "run-home")
    run.save()
    code, answer = in_process(run, "init", capsys=capsys)
    assert code == 2 and "inside ~/.codex" in answer["error"]
    assert list(owner.iterdir()) == [] and not run.run.exists()


def test_a_symlink_below_the_claude_home_refuses_before_spawn(make):
    run = make()
    run.prepare()
    (run.claude_home / "linked-history").symlink_to(run.project)
    before, calls = files(run.run), run.claude_calls()
    answer = run.team("approve", "feature-1", "--reason", "agreed", expect=2)
    assert "claude_home contains a symlink" in answer["error"]
    assert files(run.run) == before and run.claude_calls() == calls


def test_process_exit_without_terminal_transcript_keeps_the_hold(make):
    run = make(CODEX, CLAUDE)
    run.role()
    run.team("turn", REVIEWER, "Check in.", expect=3, AEGIS_TEAM_TURN_TIMEOUT="0.3", FAKE_CLAUDE_MODE="hang")
    operation = state(run)["operations"][REVIEWER]
    os.kill(operation["pid"], signal.SIGTERM)
    limit = time.monotonic() + 2
    while team_module().process_alive(operation["pid"]) and time.monotonic() < limit:
        time.sleep(0.02)
    assert not team_module().process_alive(operation["pid"])
    before = files(run.run)
    assert "no completed or failed turn" in run.team("turn", REVIEWER, "--reconcile", expect=2)["error"]
    assert files(run.run) == before and run.mailbox().wake_marker(REVIEWER).exists()


def test_stop_carries_unowned_pids_and_holds_resources(make, monkeypatch, capsys):
    run = make()
    run.team("init")
    team = team_module()
    monkeypatch.setattr(team, "launcher_roles", lambda run: {REVIEWER: {"binding": {"host": CODEX}}})
    original = team.tool

    def stop(run, name, *args):
        if name == "launcher" and "stop" in args:
            return 0, {"state": "not_running", "pids": [], "unowned_pids": [12345]}, None
        return original(run, name, *args)

    monkeypatch.setattr(team, "tool", stop)
    code, answer = in_process(run, "down", capsys=capsys)
    assert code == 3
    assert answer["roles"][0]["unowned_pids"] == [12345]
    assert (run.run / "worktrees" / "f2").is_dir()


@pytest.mark.parametrize("phase", ["pid", "finish"])
def test_model_state_saves_preserve_a_concurrent_failed_login(make, monkeypatch, capsys, phase):
    run = make(CLAUDE, CLAUDE)
    session = run.prepare()
    state_path = run.run / "team-state.json"
    gate = run.tmp / "model-completion"
    event_path = run.tmp / "login-state-event"
    os.mkfifo(event_path, 0o600)
    event = os.open(event_path, os.O_RDWR | os.O_NONBLOCK)
    login_script = ROOT_TRANSACTION.replace('"root", "--session", "root-after-login-read"', '"login"')
    original_spawn, original_replace = subprocess.Popen, os.replace
    children, interleavings = [], []

    def spawn(argv, *args, **kwargs):
        process = original_spawn(argv, *args, **kwargs)
        if Path(str(argv[0])).name == "claude" and "--print" in argv:
            gate_ready(gate)
            if phase == "pid":
                answer = run.team("login", expect=3, stderr="fake claude: login failed\n", FAKE_CLAUDE_LOGIN="fail")
                assert answer["error"] == "claude auth login exited 1"
                interleavings.append("login-before-pid-save")
            gate.write_text("finish")
        return process

    def replace(source, destination, *args, **kwargs):
        if (phase == "finish" and Path(destination) == state_path and not children and
                json.loads(Path(source).read_text()).get("operations") == {}):
            child = original_spawn([sys.executable, "-I", "-B", "-c", login_script, str(TEAM),
                                    str(run.config_path), str(state_path), str(event_path)],
                                   env=run.env(FAKE_CLAUDE_LOGIN="fail"), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
            children.append(child)
            assert select.select([event], [], [], 2)[0], "login neither saved nor reached the state lock"
            signal = os.read(event, 1)
            assert signal in (b"B", b"S")
            interleavings.append(signal)
        return original_replace(source, destination, *args, **kwargs)

    for name, value in run.env(FAKE_CLAUDE_GATE=str(gate)).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(subprocess, "Popen", spawn)
    monkeypatch.setattr(os, "replace", replace)
    try:
        code, answer = in_process(run, "approve", "feature-1", "--reason", "agreed", capsys=capsys)
        assert code == 0, answer
        for child in children:
            stdout, stderr = child.communicate(timeout=2)
            assert child.returncode == 3 and stderr == "fake claude: login failed\n", stdout + stderr
            assert json.loads(stdout.splitlines()[-1])["error"] == "claude auth login exited 1"
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=2)
        os.close(event)
    assert len(interleavings) == 1
    current = state(run)
    assert CLAUDE not in current.get("logins", {}), "a model state save restored the rejected login"
    assert current["root"]["session"] == session and current["operations"] == {}


@pytest.mark.parametrize("phase", ["start", "final_reload"])
def test_up_keeps_root_bound_during_role_start(make, monkeypatch, capsys, phase):
    run = make(CLAUDE, CODEX)
    run.team("init")
    run.team("login")
    session = str(uuid.uuid4())
    run.seed(session)
    original = subprocess.run
    original_replace = os.replace
    injected, children = [], []
    state_path = run.run / "team-state.json"
    event_path = run.tmp / "up-root-state-event"
    os.mkfifo(event_path, 0o600)
    event = os.open(event_path, os.O_RDWR | os.O_NONBLOCK)

    def bind_during_start(argv, *args, **kwargs):
        result = original(argv, *args, **kwargs)
        if (phase == "start" and not injected and "start" in argv and
                any(str(word).endswith("hierarchy_launcher.py") for word in argv)):
            injected.append(run.team("root", "--session", session))
        return result

    def bind_after_reload(source, destination, *args, **kwargs):
        if (phase == "final_reload" and Path(destination) == state_path and not children and
                json.loads(Path(source).read_text()).get("up") is not None):
            script = ROOT_TRANSACTION.replace('"root-after-login-read"', repr(session))
            child = subprocess.Popen([sys.executable, "-I", "-B", "-c", script, str(TEAM),
                                      str(run.config_path), str(state_path), str(event_path)],
                                     env=run.env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            children.append(child)
            assert select.select([event], [], [], 2)[0], "ROOT neither saved nor reached the state lock"
            assert os.read(event, 1) in (b"B", b"S")
        return original_replace(source, destination, *args, **kwargs)

    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(subprocess, "run", bind_during_start)
    monkeypatch.setattr(os, "replace", bind_after_reload)
    try:
        code, answer = in_process(run, "up", "--no-loop", capsys=capsys)
        assert code == 0, answer
        for child in children:
            stdout, stderr = child.communicate(timeout=2)
            assert child.returncode == 0 and stderr == "", stdout + stderr
            assert json.loads(stdout.splitlines()[-1])["session"] == session
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=2)
        os.close(event)
    assert len(injected) + len(children) == 1
    if injected:
        assert injected[0]["session"] == session
    current = state(run)
    assert current["root"] is not None, "up overwrote the ROOT binding saved during role startup"
    assert current["root"]["session"] == session
    assert current["up"]["roles"] == [row["endpoint"] for row in answer["roles"]]


@pytest.mark.parametrize("changed", ["id", "pid", "session"])
def test_completion_never_discards_a_different_unresolved_operation(make, monkeypatch, capsys, changed):
    run = make(CODEX, CLAUDE)
    run.role()
    state_path = run.run / "team-state.json"
    original = subprocess.Popen
    replacements = []

    def spawn(argv, *args, **kwargs):
        process = original(argv, *args, **kwargs)
        if Path(str(argv[0])).name == "claude" and "--print" in argv:
            wait = process.wait

            def replace_custody(*args, **kwargs):
                code = wait(*args, **kwargs)
                current = json.loads(state_path.read_text())
                previous = current["operations"][REVIEWER]
                replacement = {**previous, changed: 0 if changed == "pid" else uuid.uuid4().hex}
                current["operations"][REVIEWER] = replacement
                state_path.write_text(json.dumps(current))
                replacements.append((previous, replacement))
                return code

            process.wait = replace_custody
        return process

    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(subprocess, "Popen", spawn)
    code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 3
    assert len(replacements) == 1
    previous, replacement = replacements[0]
    assert answer["error"] == ("operation %s on %s is no longer current; team-state, output and wake marker were retained"
                               % (previous["id"], REVIEWER))
    assert state(run)["operations"][REVIEWER] == replacement
    assert run.mailbox().wake_marker(REVIEWER).exists()
    code, held = in_process(run, "turn", REVIEWER, "Again.", capsys=capsys)
    assert code == 2 and held["operation"] == replacement
    assert len(replacements) == 1


@pytest.mark.parametrize("phase", ["intent", "pid"])
def test_codex_up_cannot_overwrite_an_owner_operation(make, monkeypatch, capsys, phase):
    run = make(CODEX, CODEX)
    run.prepare("root-with-up-race")
    # The nested public up command must finish while this exact fake is still live. A fixed model delay is
    # insufficient on a loaded machine; gate only this test executable until all original custody checks finish.
    gate = run.tmp / "finish-codex-up-interleave"
    run.codex_script = run.codex_script.replace("def root(argv, server):", (
        "def root(argv, server):\n    import time\n    gate = Path(%r)\n"
        "    deadline = time.monotonic() + 20\n"
        "    while not gate.exists() and time.monotonic() < deadline:\n        time.sleep(0.01)" % str(gate)))
    original = os.replace
    competing = []

    def competing_up(source, destination, *args, **kwargs):
        if Path(destination) == run.run / "team-state.json" and not competing:
            operation = json.loads(Path(source).read_text()).get("operations", {}).get("pilot/root")
            if operation and ((operation["pid"] is None) == (phase == "intent")):
                competing.append(run.team("up", "--no-loop", expect=2))
        return original(source, destination, *args, **kwargs)

    for name, value in run.env(FAKE_TEAM_DELAY="0.8", AEGIS_TEAM_TURN_TIMEOUT="0.15").items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(os, "replace", competing_up)
    code, answer = in_process(run, "approve", "feature-1", "--reason", "agreed", capsys=capsys)
    assert code == 3 and len(competing) == 1
    assert competing == [{"error": "another team command is running for this run"}]
    assert state(run)["operations"]["pilot/root"] == answer["operation"]
    assert team_module().process_alive(answer["operation"]["pid"])
    run.team("approve", "feature-1", "--reason", "again", expect=2)
    assert "unresolved model operations" in run.team("down", expect=3)["error"]
    assert not (run.run / ".state.lock").exists()
    gate.write_text("finish")


def finish_fake(run, operation, gate):
    gate.write_text("finish")
    deadline = time.monotonic() + 2
    while team_module().process_alive(operation["pid"]) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not team_module().process_alive(operation["pid"])


def held_claude_turn(run):
    run.role()
    gate = run.tmp / "complete-owned-turn"
    answer = run.team("turn", REVIEWER, "Check in.", expect=3, AEGIS_TEAM_TURN_TIMEOUT="0.2",
                      FAKE_CLAUDE_GATE=str(gate))
    gate_ready(gate)
    return answer["operation"], gate


def test_reconcile_preserves_a_replacement_wake_marker(make):
    run = make(CODEX, CLAUDE)
    operation, gate = held_claude_turn(run)
    finish_fake(run, operation, gate)
    marker = run.mailbox().wake_marker(REVIEWER)
    # Same inode and original pid/time are insufficient: a later wake has different custody content.
    replacement = {**json.loads(marker.read_text()), "operation_id": uuid.uuid4().hex}
    marker.write_text(json.dumps(replacement))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
    assert answer["error"] == "operation %s wake marker changed; retain the hold and do not clear another wake" % operation["id"]
    assert json.loads(marker.read_text()) == replacement
    assert files(run.run) == before and state(run)["operations"][REVIEWER] == operation


@pytest.mark.parametrize("change", ["wrong_session", "replace", "truncate", "foreign_turn", "prefix", "prompt", "duplicate_session"])
def test_reconcile_requires_the_original_session_and_turn_transcript(make, change):
    run = make(CODEX, CLAUDE)
    operation, gate = held_claude_turn(run)
    finish_fake(run, operation, gate)
    path = run.seed_path
    original = path.read_bytes()
    events = rows(path)
    if change == "wrong_session":
        events[-1]["sessionId"] = str(uuid.uuid4())
        path.write_text("".join(json.dumps(row) + "\n" for row in events))
    elif change == "replace":
        replacement = path.with_suffix(".replacement")
        replacement.write_bytes(original)
        replacement.replace(path)
    elif change == "truncate":
        path.write_text(json.dumps(events[-1]) + "\n")
    elif change == "foreign_turn":
        events[-1]["message"]["id"] = "msg_foreign"
        path.write_text("".join(json.dumps(row) + "\n" for row in events))
    elif change == "duplicate_session":
        last = json.dumps(events[-1]).replace('"sessionId":', '"sessionId": "foreign", "sessionId":', 1)
        path.write_text("".join(json.dumps(row) + "\n" for row in events[:-1]) + last + "\n")
    else:
        if change == "prefix":
            events[0]["timestamp"] = "changed-before-launch"
        else:
            events[-2]["message"]["content"] = "A different owner's prompt."
        path.write_text("".join(json.dumps(row) + "\n" for row in events))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
    assert "transcript" in answer["error"] and "retain the hold" in answer["error"]
    assert files(run.run) == before and state(run)["operations"][REVIEWER] == operation
    assert run.mailbox().wake_marker(REVIEWER).exists()


def test_cancelled_caller_is_accounted_once_before_reconcile_releases(make):
    run = make(CODEX, CLAUDE)
    run.role()
    gate = run.tmp / "finish-after-caller-cancellation"
    caller = cancellation_caller(run, gate)
    try:
        gate_ready(gate)
        deadline = time.monotonic() + 2
        while state(run)["operations"][REVIEWER].get("pid") is None and time.monotonic() < deadline:
            time.sleep(0.01)
        operation = state(run)["operations"][REVIEWER]
        assert operation["pid"] is not None and operation["pid_start"] is not None
        # Signal only the test-owned CLI. The fake model owns its separate process group and stays live.
        caller.terminate()
        caller.communicate(timeout=2)
        assert caller.returncode == -signal.SIGTERM
        assert team_module().process_alive(operation["pid"])
        assert run.mailbox().wake_marker(REVIEWER).exists()
        finish_fake(run, operation, gate)
        result = run.team("turn", REVIEWER, "--reconcile")
        assert result["reconciled"] == operation["id"] and result["replayed"] is False
        [usage] = rows(run.evidence / operation["turn_log"])
        assert usage["operation_id"] == operation["id"] and usage["usage"]["input_tokens"] == 1203
        receipt = json.loads((run.evidence / ("turn-%s.accounting.json" % operation["id"])).read_text())
        assert receipt["operation_id"] == operation["id"]
        before = files(run.run)
        assert "has no unresolved operation" in run.team("turn", REVIEWER, "--reconcile", expect=2)["error"]
        assert files(run.run) == before
        assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1
    finally:
        if caller.poll() is None:
            caller.terminate()
            caller.communicate(timeout=2)


@pytest.mark.parametrize("corruption", [b'{"operation_id":', b'{"operation_id":"conflict"}\n', "missing_newline", "duplicate_key"])
def test_incomplete_or_conflicting_accounting_retains_custody(make, corruption):
    run = make(CODEX, CLAUDE)
    operation, gate = held_claude_turn(run)
    finish_fake(run, operation, gate)
    log = run.evidence / operation["turn_log"]
    if corruption == "duplicate_key":
        corruption = log.read_bytes().replace(b'"operation_id":', b'"operation_id": "foreign", "operation_id":', 1)
    log.write_bytes(log.read_bytes().rstrip(b"\n") if corruption == "missing_newline" else corruption)
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
    assert "accounting" in answer["error"] and "retain the hold" in answer["error"]
    assert files(run.run) == before and state(run)["operations"][REVIEWER] == operation
    assert run.mailbox().wake_marker(REVIEWER).exists()


@pytest.mark.parametrize("inject", [False, True])
def test_claude_ultra_profile_accepts_only_the_supported_setting(make, inject):
    run = make(CODEX, CLAUDE)
    run.team("init")
    run.team("login")
    run.write("unused.json", {})
    (run.base_dir / "team.json").write_text(json.dumps({"model": "claude-opus-4-6", "reasoning": "ultra"}))
    session = str(uuid.uuid4())
    run.seed(session)
    request = run.write("ultra-role.json", {"base": str(run.base_dir), "endpoint": REVIEWER, "host": CLAUDE,
                                           "session": session, "cwd": str(run.project)})
    result = fixture_cli(run, "hierarchy_provision.py", "add-role", "--request", request)
    assert result.returncode == 0, result.stdout + result.stderr
    path = run.base_dir / "profiles" / "pilot%2Flane%2Freview-g1.wake.json"
    profile = json.loads(path.read_text())
    setting = profile["argv"].index("--settings") + 1
    assert json.loads(profile["argv"][setting]) == {"ultracode": True}
    if inject:
        profile["argv"][setting] = json.dumps({"ultracode": True, "apiKeyHelper": "unapproved"})
        path.write_text(json.dumps(profile))
    before, calls = files(run.run), run.claude_calls()
    answer = run.team("turn", REVIEWER, "Check in.", expect=2 if inject else 0)
    if inject:
        assert answer["error"] == "Claude print profile differs from the registry argv"
        assert files(run.run) == before and run.claude_calls() == calls
    else:
        assert answer["exit_code"] == 0
        argv = run.claude_calls()[-1]["argv"]
        assert json.loads(argv[argv.index("--settings") + 1]) == {"ultracode": True}


def test_long_codex_owner_prompt_without_host_plan_keeps_exact_argv(make):
    run = make(CODEX, CODEX)
    run.config["schema"] = "aegis.team-run/v1"
    run.config.pop("hosts", None)
    run.config.pop("claude_home", None)
    run.save()
    run.ready("--no-loop")
    prompt = "long prompt\n" + "x" * 8192
    path = run.base_dir / "profiles" / "pilot%2Flane%2Freview-g1.wake.json"
    profile = json.loads(path.read_text())
    call_log = run.tmp / "long-prompt-call.jsonl"
    answer = run.team("turn", REVIEWER, prompt, FAKE_CODEX_LOG=str(call_log))
    assert answer["exit_code"] == 0
    [call] = rows(call_log)
    assert call["argv"][-1].encode("utf-8") == prompt.encode("utf-8")
    assert profile["argv"][1:] + [prompt] == call["argv"]


def test_lost_accounting_reply_does_not_append_or_charge_twice(make, monkeypatch, capsys):
    run = make(CODEX, CLAUDE)
    run.role()
    log = run.evidence / ("role-turns-%s.jsonl" % REVIEWER.replace("/", "%2F"))
    original = os.replace
    lost = []

    def lose_append_reply(source, destination, *args, **kwargs):
        result = original(source, destination, *args, **kwargs)
        if Path(destination) == log and not lost:
            lost.append(log.read_bytes())
            raise OSError("fixture: accounting reply lost after row publish")
        return result

    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(os, "replace", lose_append_reply)
    code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 3 and "accounting reply lost after row publish" in answer["error"]
    operation = answer["operation"]
    assert state(run)["operations"][REVIEWER] == operation and run.mailbox().wake_marker(REVIEWER).exists()
    assert len(rows(log)) == 1
    result = run.team("turn", REVIEWER, "--reconcile")
    assert result["reconciled"] == operation["id"] and result["replayed"] is False
    assert log.read_bytes() == lost[0]
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1


@pytest.mark.parametrize("field", ["operation_id", "output_sha256", "exit_code", "not_object"])
def test_changed_accounting_receipt_is_never_overwritten(make, field):
    run = make(CODEX, CLAUDE)
    operation, gate = held_claude_turn(run)
    finish_fake(run, operation, gate)
    receipt = run.evidence / ("turn-%s.accounting.json" % operation["id"])
    value = json.loads(receipt.read_text())
    if field == "not_object":
        value = []
    else:
        value[field] = "conflicting-custody"
    receipt.write_text(json.dumps(value))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
    assert "accounting" in answer["error"] and "retain the hold" in answer["error"]
    assert files(run.run) == before and run.mailbox().wake_marker(REVIEWER).exists()


def test_owner_marker_release_holds_the_public_mailbox_writer_lock(make, monkeypatch, capsys):
    run = make(CODEX, CLAUDE)
    operation, gate = held_claude_turn(run)
    finish_fake(run, operation, gate)
    marker = run.mailbox().wake_marker(REVIEWER)
    original = os.unlink
    observed = []

    def unlink(path, *args, **kwargs):
        if Path(path) == marker:
            observed.append((run.mailbox().root / ".write.lock").is_file())
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", unlink)
    code, answer = in_process(run, "turn", REVIEWER, "--reconcile", capsys=capsys)
    assert code == 0 and answer["replayed"] is False
    assert observed == [True]


@pytest.mark.parametrize("change", ["terminal", "prompt"])
def test_codex_reconcile_binds_terminal_to_the_submitted_turn(make, change):
    run = make(CODEX, CODEX)
    run.ready("--no-loop")
    script = run.write("delayed-turn.json", {"turns": [{"match": "Check in.", "context_delay": 0.8}]})
    answer = run.team("turn", REVIEWER, "Check in.", expect=3, AEGIS_TEAM_TURN_TIMEOUT="0.2",
                      FAKE_CODEX_SCRIPT=str(script))
    operation = answer["operation"]
    deadline = time.monotonic() + 2
    while team_module().process_alive(operation["pid"]) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not team_module().process_alive(operation["pid"])
    [filename] = operation["transcripts"]
    path = Path(filename)
    events = rows(path)
    if change == "terminal":
        event = next(row["payload"] for row in reversed(events) if row.get("payload", {}).get("type") == "task_complete")
        event["turn_id"] = "another-turn"
    else:
        event = next(row["payload"] for row in reversed(events) if row.get("payload", {}).get("role") == "user")
        event["content"] = "Another prompt."
    path.write_text("".join(json.dumps(row) + "\n" for row in events))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
    assert "transcript" in answer["error"] and "retain the hold" in answer["error"]
    assert files(run.run) == before and run.mailbox().wake_marker(REVIEWER).exists()


def test_initial_codex_state_writer_also_holds_the_operation_lock(make, monkeypatch, capsys):
    run = make(CODEX, CODEX)
    original = os.replace
    competing = []

    def compete(source, destination, *args, **kwargs):
        if Path(destination) == run.run / "team-state.json" and not competing:
            competing.append(run.team("init", expect=2))
        return original(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, "replace", compete)
    code, answer = in_process(run, "init", capsys=capsys)
    assert code == 0, answer
    assert competing == [{"error": "another team command is running for this run"}]
    assert not (run.run / ".state.lock").exists()


@pytest.mark.parametrize("words", [(), ("",), ("bad\0prompt",), ("Check in.", "--reconcile")])
def test_optional_owner_prompt_refuses_ambiguity_before_any_effect(make, capsys, words):
    run = make(CODEX, CODEX)
    run.ready("--no-loop")
    before = files(run.run)
    code, answer = in_process(run, "turn", REVIEWER, *words, capsys=capsys)
    assert code == 2
    assert answer["error"] == ("--reconcile does not accept a prompt" if "--reconcile" in words else "invalid prompt")
    assert files(run.run) == before


def test_accounting_failure_after_spawn_is_failed_with_custody(make, monkeypatch, capsys):
    run = make(CODEX, CLAUDE)
    run.role()
    original = subprocess.Popen
    gate = run.tmp / "late-accounting-failure"
    log = run.evidence / ("role-turns-%s.jsonl" % REVIEWER.replace("/", "%2F"))

    def corrupt_after_spawn(argv, *args, **kwargs):
        process = original(argv, *args, **kwargs)
        if Path(str(argv[0])).name == "claude" and "--print" in argv:
            log.write_bytes(b'{"operation_id":')
        return process

    for name, value in run.env(FAKE_CLAUDE_GATE=str(gate), AEGIS_TEAM_TURN_TIMEOUT="0.2").items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(subprocess, "Popen", corrupt_after_spawn)
    code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 3 and "accounting" in answer["error"]
    assert state(run)["operations"][REVIEWER] == answer["operation"]
    assert run.mailbox().wake_marker(REVIEWER).exists()
    assert team_module().process_alive(answer["operation"]["pid"])


@pytest.mark.parametrize("after_unlink", [False, True])
def test_failed_turn_release_retry_keeps_the_recorded_native_exit(make, monkeypatch, capsys, after_unlink):
    run = make(CODEX, CLAUDE)
    run.role()
    marker = run.mailbox().wake_marker(REVIEWER)
    original = os.unlink
    lost = []
    run.claude_exit_after_reply = 1

    def interrupted_release(path, *args, **kwargs):
        if Path(path) == marker and not lost:
            lost.append(True)
            if after_unlink:
                original(path, *args, **kwargs)
            raise OSError("fixture: release reply lost")
        return original(path, *args, **kwargs)

    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(os, "unlink", interrupted_release)
    code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 3 and "release reply lost" in answer["error"]
    operation = state(run)["operations"][REVIEWER]
    assert operation["id"] == answer["operation"]["id"] and "release" in operation
    log = run.evidence / operation["turn_log"]
    before = log.read_bytes()
    result = run.team("turn", REVIEWER, "--reconcile", expect=3)
    assert result == {"endpoint": REVIEWER, "reconciled": operation["id"], "outcome": "failed", "replayed": False}
    assert log.read_bytes() == before and rows(log)[0]["exit_code"] == 1
    assert not marker.exists() and state(run)["operations"] == {}
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1


def test_reconcile_never_reads_through_an_accounting_symlink(make, monkeypatch, capsys):
    run = make(CODEX, CLAUDE)
    operation, gate = held_claude_turn(run)
    finish_fake(run, operation, gate)
    receipt = run.evidence / ("turn-%s.accounting.json" % operation["id"])
    target = run.tmp / "foreign-accounting.json"
    receipt.rename(target)
    receipt.symlink_to(target)
    before = target.read_bytes()
    original = Path.open

    def opened(path, *args, **kwargs):
        assert path != receipt, "reconciliation followed an accounting symlink before refusing"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", opened)
    code, answer = in_process(run, "turn", REVIEWER, "--reconcile", capsys=capsys)
    assert code == 2 and answer["error"] == "symlink paths are not supported: " + str(receipt)
    assert state(run)["operations"][REVIEWER] == operation and run.mailbox().wake_marker(REVIEWER).exists()
    assert target.read_bytes() == before and receipt.is_symlink()


@pytest.mark.parametrize("subtype,wrong_session,supported_reply", [("turn_failed", False, False),
    ("turn_aborted", False, False), ("turn_failed", True, False), ("turn_failed", False, True)])
def test_pseudo_failure_rows_never_prove_the_submitted_turn_ended(make, subtype, wrong_session, supported_reply):
    run = make(CODEX, CLAUDE)
    run.role()
    gate = run.tmp / "finish-without-supported-terminal"
    started = run.team("turn", REVIEWER, "Check in.", expect=3, AEGIS_TEAM_TURN_TIMEOUT="0.2",
                       FAKE_CLAUDE_GATE=str(gate), FAKE_CLAUDE_MODE="" if supported_reply else "fail")
    gate_ready(gate)
    operation = started["operation"]
    finish_fake(run, operation, gate)
    # The real temporary file carries a deliberately modelled row. It is not a captured native terminal shape.
    transcript = rows(run.seed_path)
    transcript = [event for event in transcript if not (event.get("type") == "system" and
                  event.get("subtype") in ("turn_failed", "turn_aborted"))]
    pseudo = {"type": "system", "subtype": subtype,
              "sessionId": str(uuid.uuid4()) if wrong_session else operation["session"]}
    transcript.insert(len(transcript) - 1 if supported_reply else len(transcript), pseudo)
    run.seed_path.write_text("".join(json.dumps(event) + "\n" for event in transcript))
    raw = Path(operation["stdout"]).read_bytes()
    assert rows(Path(operation["stdout"]))[-1]["is_error"] is (not supported_reply)
    assert team_module().hierarchy_hosts.claude_usage(raw)["input_tokens"] == 1203
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
    assert "transcript" in answer["error"] and "retain the hold" in answer["error"]
    assert state(run)["operations"][REVIEWER] == operation
    assert run.mailbox().wake_marker(REVIEWER).exists() and files(run.run) == before
    assert run.team("turn", REVIEWER, "Again.", expect=2)["operation"] == operation
    assert "unresolved model operations" in run.team("down", expect=3)["error"]
    assert len(rows(run.evidence / operation["turn_log"])) == 1
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1


def test_observed_error_exit_accounts_once_without_inventing_a_transcript_terminal(make):
    run = make(CODEX, CLAUDE)
    run.role()
    initial = len(rows(run.seed_path))
    answer = run.team("turn", REVIEWER, "Check in.", expect=3, FAKE_CLAUDE_MODE="fail")
    [usage] = rows(Path(answer["log"]))
    assert usage["exit_code"] == 1 and usage["usage"]["input_tokens"] == 1203
    receipt = json.loads((run.evidence / ("turn-%s.accounting.json" % usage["operation_id"])).read_text())
    assert receipt["operation_id"] == usage["operation_id"] and receipt["exit_code"] == 1
    assert receipt["usage"] == usage["usage"]
    assert [event["type"] for event in rows(run.seed_path)[initial:]] == ["user"]
    assert rows(Path(usage["stdout"]))[-1]["is_error"] is True
    assert state(run)["operations"] == {} and not run.mailbox().wake_marker(REVIEWER).exists()
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1


def held_after_supported_reply(run, *, error=False):
    run.role()
    gate = run.tmp / "original-process-after-supported-reply"
    run.claude_after_reply = {"gate": gate, "error": error}
    answer = run.team("turn", REVIEWER, "Check in.", expect=3, AEGIS_TEAM_TURN_TIMEOUT="0.2")
    gate_ready(gate)
    operation = answer["operation"]
    assert state(run)["operations"][REVIEWER] == operation
    assert team_module().process_alive(operation["pid"])
    assert rows(run.seed_path)[-1]["message"]["stop_reason"] == "end_turn"
    assert rows(Path(operation["stdout"]))[-1]["is_error"] is error
    (run.tmp / ".keep").touch()
    return operation, gate


@pytest.mark.parametrize("fault", ["stat_permission", "stat_missing", "hidden_stat", "identity_permission", "malformed_stat", "torn_stat",
                                   "missing_start", "scope_permission"])
def test_reconcile_cannot_infer_live_original_exit_from_unavailable_identity(make, monkeypatch, capsys, fault):
    run = make(CODEX, CLAUDE)
    operation, gate = held_after_supported_reply(run)
    target = Path("/proc/%d/stat" % operation["pid"])
    original_text, original_open, original_link, original_stat = Path.read_text, builtins.open, os.readlink, Path.stat
    snapshot = target.read_text()
    before = files(run.run)

    def read_text(path, *args, **kwargs):
        if path == target:
            if fault in ("stat_permission", "identity_permission"):
                raise PermissionError("fixture: original process identity unavailable")
            if fault in ("stat_missing", "hidden_stat"):
                raise FileNotFoundError("fixture: stat missing while original PID directory is present")
            if fault == "malformed_stat":
                return "malformed process stat"
            if fault == "torn_stat":
                return snapshot[:snapshot.rfind(")") + 1]
            if fault == "missing_start":
                return snapshot.rsplit(")", 1)[0] + ") S 1 1 1"
        return original_text(path, *args, **kwargs)

    def opened(path, *args, **kwargs):
        if fault == "stat_permission" and Path(path) == target:
            raise PermissionError("fixture: original process stat unavailable")
        if fault in ("stat_missing", "hidden_stat") and Path(path) == target:
            raise FileNotFoundError("fixture: original process stat missing")
        return original_open(path, *args, **kwargs)

    def readlink(path, *args, **kwargs):
        if fault == "scope_permission" and str(path) == "/proc/self/ns/pid":
            raise PermissionError("fixture: process namespace unavailable")
        return original_link(path, *args, **kwargs)

    def stat_path(path, *args, **kwargs):
        if fault == "hidden_stat" and path == target.parent:
            raise FileNotFoundError("fixture: original PID is hidden from proc")
        return original_stat(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_text", read_text)
        patch.setattr(builtins, "open", opened)
        patch.setattr(os, "readlink", readlink)
        patch.setattr(Path, "stat", stat_path)
        code, answer = in_process(run, "turn", REVIEWER, "--reconcile", capsys=capsys)
    assert code == 2 and answer["error"] == (
        "operation %s is unresolved: its process exit cannot be confirmed; retain the hold" % operation["id"])
    assert answer["process_observation"]["state"] == "UNAVAILABLE"
    assert answer["operation"] == operation
    assert files(run.run) == before
    assert run.mailbox().wake_marker(REVIEWER).exists() and team_module().process_alive(operation["pid"])
    assert run.team("turn", REVIEWER, "Again.", expect=2)["operation"] == operation
    assert files(run.run) == before
    assert len(rows(run.evidence / operation["turn_log"])) == 1
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1
    finish_fake(run, operation, gate)


@pytest.mark.parametrize("change", ["missing", "pid_namespace", "boot_id", "earlier_birth"])
def test_reconcile_requires_the_original_scope_and_valid_birth_witness(make, monkeypatch, capsys, change):
    run = make(CODEX, CLAUDE)
    operation, gate = held_after_supported_reply(run)
    stat_path = Path("/proc/%d/stat" % operation["pid"])
    snapshot = stat_path.read_text()
    finish_fake(run, operation, gate)
    value = state(run)
    operation = value["operations"][REVIEWER]
    if change == "missing":
        operation.pop("process_scope", None)
    elif change == "earlier_birth":
        prefix, fields = snapshot.rsplit(")", 1)
        fields = fields.split()
        fields[0], fields[19] = "S", str(int(operation["pid_start"]) - 1)
        snapshot = prefix + ") " + " ".join(fields) + "\n"
    else:
        operation.setdefault("process_scope", {})[change] = "foreign scope"
    (run.run / "team-state.json").write_text(json.dumps(value))
    before = files(run.run)
    original = Path.read_text

    def read_text(path, *args, **kwargs):
        return snapshot if change == "earlier_birth" and path == stat_path else original(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_text", read_text)
        code, answer = in_process(run, "turn", REVIEWER, "--reconcile", capsys=capsys)
    assert code == 2 and answer["error"] == (
        "operation %s is unresolved: its process exit cannot be confirmed; retain the hold" % operation["id"]
        if change == "earlier_birth" else "invalid operation record")
    assert answer["operation"] == operation and answer["process_observation"]["state"] == "UNAVAILABLE"
    assert state(run)["operations"][REVIEWER] == operation and run.mailbox().wake_marker(REVIEWER).exists()
    assert files(run.run) == before
    assert run.team("turn", REVIEWER, "Again.", expect=2)["operation"] == operation
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1


@pytest.mark.parametrize("error,expected", [(False, 0), (True, 3)])
def test_reconcile_keeps_unobserved_native_exit_null_separate_from_result(make, error, expected):
    run = make(CODEX, CLAUDE)
    operation, gate = held_after_supported_reply(run, error=error)
    finish_fake(run, operation, gate)
    receipt_path = run.evidence / ("turn-%s.accounting.json" % operation["id"])
    log = run.evidence / operation["turn_log"]
    [before] = rows(log)
    assert json.loads(receipt_path.read_text())["exit_code"] is None
    assert rows(log)[0]["exit_code"] is None
    result = run.team("turn", REVIEWER, "--reconcile", expect=expected)
    assert result == {"endpoint": REVIEWER, "reconciled": operation["id"],
                      "outcome": "failed" if error else "completed", "replayed": False}
    assert json.loads(receipt_path.read_text())["exit_code"] is None
    [usage] = rows(log)
    assert usage["operation_id"] == operation["id"] and usage["exit_code"] is None
    # The deadline may precede the reply. Null usage may become known once; identity and native exit stay exact.
    assert usage["usage"]["input_tokens"] == 1203
    assert all(usage[key] == value for key, value in before.items() if key != "usage")
    assert before["usage"] is None or before["usage"] == usage["usage"]
    assert state(run)["operations"] == {} and not run.mailbox().wake_marker(REVIEWER).exists()
    finished = files(run.run)
    assert run.team("turn", REVIEWER, "--reconcile", expect=2) == {
        "error": "%s has no unresolved operation" % REVIEWER}
    assert files(run.run) == finished
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1


def legacy_owner_without_plan(make, command):
    run = make(CODEX, CODEX)
    run.config["schema"] = "aegis.team-run/v1"
    run.config.pop("hosts", None)
    run.config.pop("claude_home", None)
    run.save()
    run.ready("--no-loop")
    # Model a supported legacy base with no host plan; never alter a product/fixture source file.
    (run.base_dir / "host-plan.json").unlink()
    # Model a genuine pre-custody/no-plan base, not a governed base whose plan was deleted. All data is test-owned.
    folder = run.run / ".owner-custody"
    if folder.exists():
        for path in folder.iterdir():
            path.unlink()
        folder.rmdir()
    saved = state(run)
    saved.pop("owner_custody", None)
    saved.pop("host_plan_issued", None)
    (run.run / "team-state.json").write_text(json.dumps(saved))
    evidence_index = run.evidence / "index.json"
    contents = json.loads(evidence_index.read_text())
    contents["files"].pop("host-plan.json", None)
    evidence_index.write_text(json.dumps(contents))
    assert team_module().hierarchy_hosts.read_plan(run.base_dir) is None
    assert state(run)["init"]["complete_at"] is not None
    if command == "approve":
        run.team("request", "feature-1", "--file", str(run.write("scope-request.json", run.request())))
        return run, ("approve", "feature-1", "--reason", "scope observation unavailable"), "pilot/root"
    return run, ("turn", REVIEWER, "Owner bytes: scope unavailable.\nCheck in."), REVIEWER


@contextmanager
def original_scope_os_fault(monkeypatch, field, *, fail=True):
    reads = []
    original_text, original_link = Path.read_text, os.readlink

    def read_text(path, *args, **kwargs):
        if field == "boot_id" and path == Path("/proc/sys/kernel/random/boot_id"):
            reads.append(field)
            if fail == "invalid":
                return "malformed boot identity"
            if fail:
                raise PermissionError("fixture: boot ID unavailable")
        return original_text(path, *args, **kwargs)

    def readlink(path, *args, **kwargs):
        if field == "pid_namespace" and str(path) == "/proc/self/ns/pid":
            reads.append(field)
            if fail == "invalid":
                return "malformed PID namespace"
            if fail:
                raise PermissionError("fixture: PID namespace unavailable")
        return original_link(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_text", read_text)
        patch.setattr(os, "readlink", readlink)
        yield reads


@contextmanager
def observe_owner_model_boundary(run, endpoint, monkeypatch, *, lose_reply=False):
    started, lost = [], []
    original_init, original_wait = subprocess.Popen.__init__, subprocess.Popen.wait

    def initialize(process, argv, *args, **kwargs):
        model = Path(str(argv[0])).name in ("codex", "claude") and ("resume" in argv or "--resume" in argv)
        if model:
            started.append({"operation": json.loads(json.dumps(state(run)["operations"][endpoint])),
                            "argv": list(argv), "env": dict(kwargs["env"]), "process": process})
        return original_init(process, argv, *args, **kwargs)

    def wait(process, *args, **kwargs):
        code = original_wait(process, *args, **kwargs)
        if lose_reply and started and process is started[0]["process"] and not lost:
            lost.append(code)
            raise OSError("fixture: supported native wait reply lost")
        return code

    with monkeypatch.context() as patch:
        patch.setattr(subprocess.Popen, "__init__", initialize)
        patch.setattr(subprocess.Popen, "wait", wait)
        yield started, lost


@pytest.mark.parametrize("command", ["approve", "turn", "claude_turn"])
@pytest.mark.parametrize("field", ["boot_id", "pid_namespace"])
@pytest.mark.parametrize("kind", ["unreadable", "invalid"])
def test_unavailable_original_scope_normal_native_wait_stays_supported(make, monkeypatch, capsys, command, field, kind):
    if command == "claude_turn":
        run = make(CODEX, CLAUDE)
        run.role()
        words, endpoint = ("turn", REVIEWER, "Scope observation unavailable."), REVIEWER
    else:
        run, words, endpoint = legacy_owner_without_plan(make, command)
    log = run.tmp / "scope-native-call.jsonl"
    for name, value in run.env(FAKE_CODEX_LOG=str(log), AEGIS_TEAM_TURN_TIMEOUT="2").items():
        monkeypatch.setenv(name, value)
    (run.tmp / ".keep").touch()
    with original_scope_os_fault(monkeypatch, field, fail="invalid" if kind == "invalid" else True) as reads:
        with observe_owner_model_boundary(run, endpoint, monkeypatch) as (started, lost):
            code, answer = in_process(run, *words, capsys=capsys)
    assert code == 0, answer
    assert reads == [field] and not lost and len(started) == 1
    [call] = started
    operation = call["operation"]
    assert operation["pid"] is None
    assert operation["process_scope"] == {"state": "UNAVAILABLE", "reason": field + " is " + kind}
    assert call["process"].returncode == 0
    assert call["env"]["HOME"] == str(run.home) and call["env"]["PATH"] == str(run.bin)
    assert call["env"]["CODEX_HOME"] == str(run.codex_home)
    receipt = json.loads((run.evidence / ("turn-%s.accounting.json" % operation["id"])).read_text())
    assert receipt["operation_id"] == operation["id"] and receipt["exit_code"] == 0
    assert state(run)["operations"] == {} and not run.mailbox().wake_marker(endpoint).exists()
    if command == "approve":
        assert answer["decision"] == "approve" and answer["root_last_message"] == "Recorded."
        [native] = run.calls("root")
        assert native["argv"] == call["argv"][1:]
        assert native["argv"][-1] == team_module().ROOT_PROMPT % ("feature-1", "approve", words[-1])
    else:
        profile = json.loads((run.base_dir / "profiles" / "pilot%2Flane%2Freview-g1.wake.json").read_text())
        assert answer["exit_code"] == 0 and answer["items"][-1]["text"] == ("done" if command == "claude_turn" else "DONE")
        if command == "claude_turn":
            assert len([row for row in run.claude_calls() if "--resume" in row["argv"]]) == 1
            assert len(rows(run.evidence / operation["turn_log"])) == 1
        else:
            [native] = rows(log)
            assert native["argv"] == profile["argv"][1:] + [words[-1]] == call["argv"][1:]
            assert native["argv"][-1].encode("utf-8") == words[-1].encode("utf-8")


@pytest.mark.parametrize("command", ["approve", "turn"])
@pytest.mark.parametrize("field", ["boot_id", "pid_namespace"])
@pytest.mark.parametrize("loss", ["deadline", "lost_reply"])
def test_unavailable_original_scope_loss_retains_custody_without_recapture(make, monkeypatch, capsys, command, field, loss):
    run, words, endpoint = legacy_owner_without_plan(make, command)
    log = run.tmp / "scope-lost-native-call.jsonl"
    extra = {"FAKE_CODEX_LOG": str(log), "AEGIS_TEAM_TURN_TIMEOUT": "0.2" if loss == "deadline" else "2"}
    if loss == "deadline":
        if command == "approve":
            extra["FAKE_TEAM_DELAY"] = "0.8"
        else:
            script = run.write("scope-delayed-turn.json", {"turns": [{"match": words[-1], "context_delay": 0.8}]})
            extra["FAKE_CODEX_SCRIPT"] = str(script)
    for name, value in run.env(**extra).items():
        monkeypatch.setenv(name, value)
    (run.tmp / ".keep").touch()
    started = []
    try:
        with original_scope_os_fault(monkeypatch, field) as reads:
            with observe_owner_model_boundary(run, endpoint, monkeypatch, lose_reply=loss == "lost_reply") as (started, lost):
                code, answer = in_process(run, *words, capsys=capsys)
        assert code == 3 and len(started) == 1, answer
        assert reads == [field] and lost == ([] if loss == "deadline" else [0])
        operation = state(run)["operations"][endpoint]
        expected = {"state": "UNAVAILABLE", "reason": field + " is unreadable"}
        assert operation == answer["operation"] and operation["process_scope"] == expected
        assert started[0]["operation"]["pid"] is None and started[0]["operation"]["process_scope"] == expected
        assert started[0]["process"].wait(timeout=2) == 0
        receipt_path = run.evidence / ("turn-%s.accounting.json" % operation["id"])
        assert json.loads(receipt_path.read_text())["exit_code"] is None
        if command == "turn":
            assert run.mailbox().wake_marker(endpoint).exists()
        before = files(run.run)
        # Metadata is available again, but original capture failure is immutable; never retry it as original proof.
        with original_scope_os_fault(monkeypatch, field, fail=False) as recaptures:
            code, held = in_process(run, words[0], words[1], "--reconcile", capsys=capsys)
        assert code == 2 and held["operation"] == operation
        assert held["error"] == "operation %s is unresolved: its process exit cannot be confirmed; retain the hold" % operation["id"]
        assert recaptures == []
        assert held["process_observation"] == {"state": "UNAVAILABLE", "reason": "original process scope unavailable: " + expected["reason"]}
        assert files(run.run) == before
        assert run.team(*words, expect=2)["operation"] == operation
        assert state(run)["operations"][endpoint] == operation and files(run.run) == before
        if command == "turn":
            assert run.mailbox().wake_marker(endpoint).exists() and len(rows(log)) == 1
        else:
            assert len(run.calls("root")) == 1
    finally:
        for call in started:
            call["process"].wait(timeout=2)


# fix8: hostile publications, known-no-spawn failures and post-seal recovery use the real CLI/OS boundary.
@pytest.mark.parametrize("fault", ["active_fsync", "active_unlink", "owner_mkdir"])
def test_fix8_known_no_spawn_retires_only_its_intent(make, monkeypatch, capsys, fault):
    if fault == "owner_mkdir":
        run, words, endpoint = legacy_owner_without_plan(make, "turn")
    else:
        run = make(CODEX, CLAUDE)
        run.role()
        words, endpoint = ("turn", REVIEWER, "Check in."), REVIEWER
    original_sync, original_mkdir, original_unlink = os.fsync, Path.mkdir, os.unlink
    observed = []
    for name, value in run.env().items():
        monkeypatch.setenv(name, value)

    def sync(fd):
        path = os.readlink("/proc/self/fd/%d" % fd)
        if fault == "active_fsync" and ".owner-custody/" in path and "active-" in path and not observed:
            observed.append({"visible": (run.run / ".owner-custody" / "active-pilot%2Flane%2Freview.json").exists()})
            raise OSError("fixture: owner intent sync failed")
        return original_sync(fd)

    def mkdir(path, *args, **kwargs):
        if path == run.run / ".owner-custody" and not observed:
            observed.append({"visible": False})
            raise OSError("fixture: owner directory creation failed")
        return original_mkdir(path, *args, **kwargs)

    def unlink(path, *args, **kwargs):
        if fault == "active_unlink" and Path(path).name.startswith(".owner-active-") and not observed:
            observed.append({"visible": True})
            raise OSError("fixture: publication staging unlink failed")
        return original_unlink(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", sync)
        patch.setattr(Path, "mkdir", mkdir)
        patch.setattr(os, "unlink", unlink)
        code, answer = in_process(run, *words, capsys=capsys)
    assert code == 2 and observed == [{"visible": fault == "active_unlink"}]
    assert answer["spawned"] is False and answer["custody_retired"] is True
    assert not state(run).get("operations", {}) and not run.mailbox().wake_marker(endpoint).exists()
    assert not list((run.run / ".owner-custody").glob("active-*.json"))
    assert not list((run.run / ".owner-custody").glob(".owner-active-*.tmp"))
    assert not [call for call in run.claude_calls() if "--resume" in call["argv"]]
    result = run.team(*words)
    assert result["exit_code"] == 0


@pytest.mark.parametrize("fault", ["shape", "permissions", "disappears", "directory"])
def test_fix8_status_localizes_bad_owner_records(make, monkeypatch, capsys, fault):
    run = make(CODEX, CLAUDE)
    run.role()
    folder = run.run / ".owner-custody"
    path = folder / "active-pilot%2Frouter.json"
    path.write_text("null")
    path.chmod(0o600)
    if fault == "permissions":
        path.chmod(0o644)
    elif fault == "directory":
        folder.chmod(0o755)
    original = os.open

    def opening(name, *args, **kwargs):
        if fault == "disappears" and str(name) == str(path) and path.exists():
            path.unlink()
        return original(name, *args, **kwargs)

    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    with monkeypatch.context() as patch:
        patch.setattr(os, "open", opening)
        code, answer = in_process(run, "status", capsys=capsys)
    assert code == 0 and answer["schema"] == "aegis.team-run-status/v1"
    if fault == "disappears":
        assert not answer.get("custody_errors")
    else:
        assert answer["custody_errors"]
    if fault != "directory":
        run.team("turn", REVIEWER, "Unaffected endpoint.")


def test_fix8_v1_issued_plan_cannot_be_deleted_to_inherit_secrets(make):
    run = make(CODEX, CODEX)
    run.config["schema"] = "aegis.team-run/v1"
    run.config.pop("hosts")
    run.save()
    run.ready("--no-loop")
    (run.base_dir / "host-plan.json").unlink()
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "Check in.", expect=2, SSH_AUTH_SOCK="fixture-secret-agent")
    assert answer["error"] == "this run's issued host plan is missing; restore host-plan.json before continuing"
    assert files(run.run) == before


def test_fix8_legacy_run_below_a_symlinked_parent_keeps_working(make, monkeypatch, capsys):
    run, words, _endpoint = legacy_owner_without_plan(make, "turn")
    alias = run.tmp / "temporary-alias"
    alias.symlink_to(run.tmp, target_is_directory=True)
    saved = state(run)
    run.config["run"] = str(alias / "run")
    run.save()
    saved["custody"]["run"] = run.config["run"]
    (run.run / "team-state.json").write_text(json.dumps(saved))
    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    code, answer = in_process(run, *words, capsys=capsys)
    assert code == 0 and answer["exit_code"] == 0
    assert not (run.run / ".state.lock").exists()


def forged_completion(run, operation):
    # An attacker can compute hashes. These are forged records, never provider exit/terminal evidence.
    witnesses = {}
    for filename in [operation["stdout"], operation["stderr"], str(run.evidence / operation["turn_log"]),
                     *operation["transcripts"]]:
        path = Path(filename)
        info = path.stat()
        raw = path.read_bytes()
        witnesses[filename] = {"device": info.st_dev, "inode": info.st_ino, "offset": len(raw),
                               "prefix_sha256": hashlib.sha256(raw).hexdigest()}
    def encode(value):
        return (json.dumps(value, indent=1, sort_keys=True) + "\n").encode()
    proof = {"schema": "aegis.team-owner-completion/v1", "operation_id": operation["id"],
             "launch_sha256": hashlib.sha256(encode(operation)).hexdigest(),
             "accounting_sha256": hashlib.sha256((run.evidence / ("turn-%s.accounting.json" % operation["id"])).read_bytes()).hexdigest(),
             "files": witnesses, "failed": False, "native_exit": None}
    path = run.run / ".owner-custody" / ("turn-%s.release.json" % operation["id"])
    path.write_bytes(encode(proof))
    path.chmod(0o600)
    saved = state(run)
    saved["operations"][REVIEWER]["release"] = {
        "accounting_sha256": proof["accounting_sha256"], "terminal_sha256": hashlib.sha256(encode(proof)).hexdigest()}
    (run.run / "team-state.json").write_text(json.dumps(saved))
    return saved["operations"][REVIEWER]


@pytest.mark.parametrize("identity", ["original", "forged"])
def test_fix8_a_forged_seal_never_retires_a_live_bound_process(make, identity):
    run = make(CODEX, CLAUDE)
    operation, gate = held_after_supported_reply(run)
    forged_launch = dict(operation)
    if identity == "forged":
        # Forge every PID publication with a positively observed, exited test-owned instance. The real session
        # is still live under its original PID; no guessed PID or fabricated native exit is used as evidence.
        child = subprocess.Popen([sys.executable, "-I", "-S", "-c", "pass"],
            env={"PATH": str(run.bin), "HOME": str(run.home), "PYTHONDONTWRITEBYTECODE": "1"},
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        birth = Path("/proc/%d/stat" % child.pid).read_text().rsplit(")", 1)[1].split()[19]
        assert child.wait(timeout=2) == 0
        forged_launch.update(pid=child.pid, pid_start=birth)
        for path in (run.evidence / ("turn-%s.launch.json" % operation["id"]),
                     run.run / ".owner-custody" / ("turn-%s.launch.json" % operation["id"])):
            path.write_text(json.dumps(forged_launch))
        saved = state(run)
        saved["operations"][REVIEWER] = forged_launch
        (run.run / "team-state.json").write_text(json.dumps(saved))
    forged = forged_completion(run, forged_launch)
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
    assert answer["error"] == "operation %s is unresolved: its process is still running" % operation["id"]
    assert files(run.run) == before and state(run)["operations"][REVIEWER] == forged
    assert run.mailbox().wake_marker(REVIEWER).exists() and team_module().process_alive(operation["pid"])
    assert run.team("turn", REVIEWER, "Again.", expect=2)["operation"]["id"] == operation["id"]
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1
    finish_fake(run, operation, gate)


def sealed_owner_turn(make, monkeypatch, capsys):
    run = make(CODEX, CLAUDE)
    run.role()
    marker = run.mailbox().wake_marker(REVIEWER)
    original = os.unlink
    lost = []
    run.claude_exit_after_reply = 1

    def unlink(path, *args, **kwargs):
        if Path(path) == marker and not lost:
            original(path, *args, **kwargs)
            lost.append(True)
            raise OSError("fixture: sealed release reply lost")
        return original(path, *args, **kwargs)

    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    with monkeypatch.context() as patch:
        patch.setattr(os, "unlink", unlink)
        code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 3 and lost == [True]
    operation = state(run)["operations"][REVIEWER]
    assert "release" in operation and operation["id"] == answer["operation"]["id"]
    return run, operation


def test_fix8_private_intent_recovers_a_lost_public_operation(make, monkeypatch, capsys):
    run, operation = sealed_owner_turn(make, monkeypatch, capsys)
    log = run.evidence / operation["turn_log"]
    receipt = run.evidence / ("turn-%s.accounting.json" % operation["id"])
    before = log.read_bytes(), receipt.read_bytes()
    saved = state(run)
    saved["operations"] = {}
    (run.run / "team-state.json").write_text(json.dumps(saved))
    answer = run.team("turn", REVIEWER, "--reconcile", expect=3)
    assert answer == {"endpoint": REVIEWER, "reconciled": operation["id"], "outcome": "failed", "replayed": False}
    assert state(run)["operations"] == {} and (log.read_bytes(), receipt.read_bytes()) == before
    assert rows(log)[0]["exit_code"] == 1
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1
    assert run.team("turn", REVIEWER, "--reconcile", expect=2)["error"] == REVIEWER + " has no unresolved operation"


@pytest.mark.parametrize("missing", ["directory", "runtime", "launch"])
def test_fix8_old_custody_has_an_actionable_hold(make, missing):
    run = make(CODEX, CLAUDE)
    operation, gate = held_after_supported_reply(run)
    folder = run.run / ".owner-custody"
    if missing == "directory":
        for path in folder.iterdir():
            path.unlink()
        folder.rmdir()
    else:
        (folder / ("runtime.json" if missing == "runtime" else "turn-%s.launch.json" % operation["id"])).unlink()
    before = files(run.run)
    command = ("turn", REVIEWER, "--reconcile") if missing == "launch" else ("turn", REVIEWER, "Again.")
    answer = run.team(*command, expect=2)
    assert answer["next_action"] == "preserve this run; finish or stop its original sessions with the originating version, then init a new run folder; do not replay"
    assert files(run.run) == before and run.mailbox().wake_marker(REVIEWER).exists()
    assert run.team("status")["custody_errors"]
    assert run.team("down", expect=3)["error"]
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1
    finish_fake(run, operation, gate)


def test_fix8_source_pin_is_taken_from_the_provision_answer(make, monkeypatch, capsys):
    run = make()
    original = subprocess.Popen.__init__
    changed = []

    def initialize(process, argv, *args, **kwargs):
        if any(str(word).endswith("/hierarchy_provision.py") for word in argv) and "init" in argv and not changed:
            (run.source / "provision-time-note").write_text("new owner revision before provision")
            git(run.source, "add", ".")
            git(run.source, "commit", "-qm", "provision-time source")
            changed.append(True)
        return original(process, argv, *args, **kwargs)

    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    with monkeypatch.context() as patch:
        patch.setattr(subprocess.Popen, "__init__", initialize)
        code, answer = in_process(run, "init", capsys=capsys)
    assert code == 0 and answer["init"] == "complete" and changed == [True]
    owner = json.loads((run.run / ".owner-custody/runtime.json").read_text())
    setup = json.loads((run.base_dir / "provision.json").read_text())
    assert {key: owner[key] for key in ("source_commit", "source_tree")} == {
        key: setup[key] for key in ("source_commit", "source_tree")}
    run.team("login")
    session = str(uuid.uuid4())
    run.seed(session)
    run.team("root", "--session", session)


@pytest.mark.parametrize("change", ["missing", "replace", "truncate", "hardlink"])
def test_fix8_before_seal_changed_transcripts_keep_original_custody(make, change):
    run = make(CODEX, CLAUDE)
    operation, gate = held_after_supported_reply(run)
    finish_fake(run, operation, gate)
    [filename] = operation["transcripts"]
    path = Path(filename)
    raw = path.read_bytes()
    if change == "missing":
        path.unlink()
    elif change == "replace":
        path.rename(run.tmp / "pre-seal-original")
        path.write_bytes(raw)
    elif change == "hardlink":
        os.link(path, run.tmp / "pre-seal-link")
    else:
        path.write_bytes(raw[:operation["transcripts"][filename]["offset"]])
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
    assert "transcript" in answer["error"] and "retain the hold" in answer["error"]
    assert files(run.run) == before and state(run)["operations"][REVIEWER] == operation
    assert run.mailbox().wake_marker(REVIEWER).exists()
    assert run.team("turn", REVIEWER, "Again.", expect=2)["operation"]["id"] == operation["id"]
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1


@pytest.mark.parametrize("change", ["argv", "connection", "delivery", "source", "sandbox", "host_path"])
def test_fix8_governed_codex_is_validated_before_any_model_effect(make, change):
    run = make(CODEX, CODEX)
    run.ready("--no-loop")
    path = run.base_dir / "profiles/pilot%2Flane%2Freview-g1.wake.json"
    profile = json.loads(path.read_text())
    marker = run.tmp / "forged-model-started"
    executable = run.tmp / "forged-model"
    executable.write_text("#!%s\nfrom pathlib import Path\nPath(%r).write_text('started')\n" % (sys.executable, str(marker)))
    executable.chmod(0o700)
    extra = {}
    if change == "argv":
        profile["argv"][0] = str(executable)
        path.write_text(json.dumps(profile))
    elif change == "sandbox":
        profile["argv"][profile["argv"].index("--sandbox") + 1] = "danger-full-access"
        path.write_text(json.dumps(profile))
    elif change == "connection":
        connection = run.base_dir / "connections/pilot%2Flane%2Freview-g1.json"
        data = json.loads(connection.read_text())
        data["mcpServers"]["aegis_mailbox"]["command"] = str(executable)
        connection.write_text(json.dumps(data))
    elif change == "host_path":
        copied = run.run / "worktrees/f2/codex"
        copied.write_bytes((run.bin / "codex").read_bytes())
        copied.chmod(0o700)
        extra["PATH"] = str(copied.parent) + os.pathsep + str(run.bin)
    else:
        provision = run.base_dir / "provision.json"
        data = json.loads(provision.read_text())
        if change == "delivery":
            foreign = run.tmp / "foreign-delivery"
            foreign.mkdir(mode=0o700)
            assert run.mailbox().delivery(str(foreign), REVIEWER)["endpoints"][REVIEWER]["unread_count"] == 0
            data["delivery_dir"] = str(foreign)
        else:
            data["source"] = str(run.tmp)
        provision.write_text(json.dumps(data))
    calls = run.tmp / "fix8-codex-calls.jsonl"
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "Check in.", expect=2, FAKE_CODEX_LOG=str(calls), **extra)
    assert answer["error"] and not marker.exists()
    assert files(run.run) == before and not calls.exists()
    assert not run.mailbox().wake_marker(REVIEWER).exists()


@pytest.mark.parametrize("record", ["operation", "launch", "active", "completion", "transcript"])
@pytest.mark.parametrize("fault", ["type", "huge", "missing", "extra"])
def test_fix8_nested_custody_records_are_typed_and_bounded(make, monkeypatch, capsys, record, fault):
    run, operation = sealed_owner_turn(make, monkeypatch, capsys)
    saved = state(run)
    if record == "operation":
        value = saved["operations"][REVIEWER]
        filename = run.run / "team-state.json"
    elif record == "transcript":
        value = next(iter(saved["operations"][REVIEWER]["transcripts"].values()))
        filename = run.run / "team-state.json"
    else:
        filename = run.run / ".owner-custody" / (
            "active-pilot%2Flane%2Freview.json" if record == "active" else
            "turn-%s.%s.json" % (operation["id"], "release" if record == "completion" else "launch"))
        value = json.loads(filename.read_text())
    if fault == "type":
        replacement = []
    else:
        replacement = dict(value)
        key = "offset" if record == "transcript" else "native_exit" if record == "completion" else "pid"
        if fault == "huge":
            replacement[key] = 10 ** 100
        elif fault == "extra":
            replacement["unexpected"] = "hostile"
        else:
            replacement.pop("inode" if record == "transcript" else "operation_id" if record == "completion" else "id")
    if record == "operation":
        saved["operations"][REVIEWER] = replacement
    elif record == "transcript":
        [key] = saved["operations"][REVIEWER]["transcripts"]
        saved["operations"][REVIEWER]["transcripts"][key] = replacement
    else:
        filename.write_text(json.dumps(replacement))
    if record in ("operation", "transcript"):
        filename.write_text(json.dumps(saved))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
    assert "invalid " + record + " record" in answer["error"]
    assert files(run.run) == before
    assert run.team("status")["custody_errors"]
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1


def test_fix8_malformed_operations_never_crashes_status_or_reconcile(make):
    run = make(CODEX, CLAUDE)
    run.role()
    saved = state(run)
    saved["operations"] = []
    (run.run / "team-state.json").write_text(json.dumps(saved))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
    assert answer["error"] == "invalid operations record"
    assert run.team("status")["custody_errors"]
    assert files(run.run) == before
    assert not [call for call in run.claude_calls() if "--resume" in call["argv"]]


@pytest.mark.parametrize("host", [CODEX, CLAUDE])
def test_fix8_governed_permissions_exclude_owner_custody_and_ancestors(make, host):
    run = make(CODEX, host)
    if host == CLAUDE:
        run.role()
    else:
        run.ready("--no-loop")
    profile = json.loads((run.base_dir / "profiles/pilot%2Flane%2Freview-g1.wake.json").read_text())
    argv = profile["argv"]
    if host == CLAUDE:
        assert "--restricted" in argv and "--strict-mcp-config" in argv
        assert argv[argv.index("--permission-mode") + 1] == "manual"
        assert not any(word in argv for word in ("--add-dir", "--dangerously-skip-permissions"))
        tools = next(word.split("=", 1)[1] for word in argv if word.startswith("--tools="))
        assert not {"Bash", "Write", "Edit", "NotebookEdit"}.intersection(tools.split(","))
    else:
        assert argv[argv.index("--sandbox") + 1] == "read-only"
        assert "--ignore-user-config" in argv and "--add-dir" not in argv
    assert Path(profile["cwd"]).resolve() == run.project.resolve()
    assert run.run.resolve() != run.project.resolve() and run.run.resolve() not in run.project.resolve().parents
    # Also inspect a writer's generated profile, without enabling Claude up or sending an owner turn.
    worktree = (run.run / "worktrees/f2").resolve()
    control = (run.run / ".owner-custody").resolve()
    if host == CLAUDE:
        session = str(uuid.uuid4())
        run.seed(session)
        request = run.write("writer-start.json", {"base": str(run.base_dir), "endpoint": "pilot/lane/f2",
                                                "cwd": str(worktree), "session": session, "host": CLAUDE})
        command = [sys.executable, "-I", "-B", str(team_module().HERE / "hierarchy_provision.py"),
                   "add-role", "--request", str(request)]
        prepared = subprocess.run(command, env=run.env(), capture_output=True, text=True, timeout=2)
        assert prepared.returncode == 0, prepared.stdout + prepared.stderr
        writer = json.loads((run.base_dir / "profiles/pilot%2Flane%2Ff2-g1.wake.json").read_text())
        argv = writer["argv"]
        assert "--restricted" in argv and "--add-dir" not in argv
        assert argv[argv.index("--permission-mode") + 1] == "manual"
        assert writer["cwd"] == str(worktree)
        roots = [worktree]
    else:
        writer = json.loads((run.base_dir / "profiles/pilot%2Flane%2Ff2-g1.codex.json").read_text())
        argv = json.loads((run.base_dir / "profiles/pilot%2Flane%2Ff2-g1.wake.json").read_text())["argv"]
        assert writer["sandbox"] == "workspace-write" and writer["cwd"] == str(worktree)
        assert "sandbox_workspace_write.exclude_slash_tmp=true" in argv
        assert "sandbox_workspace_write.exclude_tmpdir_env_var=true" in argv
        assert not writer["network_access"] and writer["approval_policy"] == "never"
        roots = [worktree, *map(Path, writer["writable_roots"]), *map(Path, writer["add_dirs"])]
    assert all(root.resolve() != control and root.resolve() not in control.parents for root in roots)


def test_fix8_interpreter_drift_names_the_next_action(make):
    run = make(CODEX, CLAUDE)
    interpreter = run.tmp / "owner-python"
    interpreter.write_text("#!%s\nimport os,sys\nos.execv(%r,[%r,*sys.argv[1:]])\n" %
                           (sys.executable, sys.executable, sys.executable))
    interpreter.chmod(0o700)
    run.config["recipes"]["python"] = str(interpreter)
    run.save()
    run.role()
    interpreter.write_text(interpreter.read_text() + "# simulated owner OS update\n")
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "Check in.", expect=2)
    assert answer["error"] == "team runtime differs from the owner-held record"
    assert answer["next_action"] == "restore the recorded interpreter bytes or preserve this run and init a new run folder; never repin a live run"
    assert files(run.run) == before and not run.mailbox().wake_marker(REVIEWER).exists()
    assert not [call for call in run.claude_calls() if "--resume" in call["argv"]]


@pytest.mark.parametrize("kind", ["metadata", "context"])
@pytest.mark.parametrize("fault", ["type", "huge", "missing", "extra"])
def test_fix8_native_codex_records_refuse_malformed_payloads(make, monkeypatch, capsys, kind, fault):
    run = make(CODEX, CODEX)
    run.ready("--no-loop")
    binding = run.mailbox().current_binding(REVIEWER)
    [path] = list(run.codex_home.joinpath("sessions").glob("**/rollout-*%s.jsonl" % binding["session"]))

    def corrupt():
        raw = path.read_bytes().splitlines(keepends=True)
        indices = [i for i, line in enumerate(raw) if json.loads(line)["type"] ==
                   ("session_meta" if kind == "metadata" else "turn_context")]
        index = indices[0] if kind == "metadata" else indices[-1]
        event = json.loads(raw[index])
        value = event["payload"]
        key = "id" if kind == "metadata" else "turn_id"
        if fault == "type":
            event["payload"] = []
        elif fault == "huge":
            value[key] = 10 ** 100
        elif fault == "missing":
            value.pop(key)
        else:
            value["unexpected"] = "hostile"
        raw[index] = (json.dumps(event) + "\n").encode()
        path.write_bytes(b"".join(raw))

    if kind == "metadata":
        corrupt()
    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    with observe_owner_model_boundary(run, REVIEWER, monkeypatch, lose_reply=True) as (started, lost):
        code, answer = in_process(run, "turn", REVIEWER, "Owner native payload check.", capsys=capsys)
    assert code == 3 and len(started) == 1 and lost == [0]
    operation = answer["operation"]
    if kind == "context":
        corrupt()
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
    assert answer["error"] == "invalid Codex %s record" % kind
    assert files(run.run) == before and state(run)["operations"][REVIEWER] == operation
    assert run.mailbox().wake_marker(REVIEWER).exists()
    assert run.team("turn", REVIEWER, "Again.", expect=2)["operation"]["id"] == operation["id"]


def test_fix8_codex_accounting_ignores_foreign_provider_result_events(make, monkeypatch, capsys):
    run = make(CODEX, CODEX)
    run.ready("--no-loop")
    run.codex_script = run.codex_script.replace(
        "    code = subprocess.run([sys.executable, FAKE, *argv], env=env).returncode",
        "    code = subprocess.run([sys.executable, FAKE, *argv], env=env).returncode\n"
        "    print(json.dumps({'type':'result','is_error':True}), flush=True)")
    original = os.unlink
    marker = run.mailbox().wake_marker(REVIEWER)
    lost = []

    def unlink(path, *args, **kwargs):
        if Path(path) == marker and not lost:
            original(path, *args, **kwargs)
            lost.append(True)
            raise OSError("fixture: Codex seal reply lost")
        return original(path, *args, **kwargs)

    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    with monkeypatch.context() as patch:
        patch.setattr(os, "unlink", unlink)
        code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 3 and lost == [True]
    operation = answer["operation"]
    proof = json.loads((run.run / ".owner-custody" / ("turn-%s.release.json" % operation["id"])).read_text())
    assert proof["native_exit"] == 0 and proof["failed"] is False
    log = run.evidence / operation["turn_log"]
    before = log.read_bytes()
    assert run.team("turn", REVIEWER, "--reconcile") == {
        "endpoint": REVIEWER, "reconciled": operation["id"], "outcome": "completed", "replayed": False}
    assert log.read_bytes() == before


def test_fix8_mixed_codex_liveness_uses_its_actual_child_home(make, monkeypatch, capsys):
    run = make(CLAUDE, CODEX)
    alias = run.tmp / "host-home-parent"
    alias.symlink_to(run.tmp, target_is_directory=True)
    run.codex_home = alias / "run/codex-home"
    run.config["codex_home"] = str(run.codex_home)
    run.save()
    run.prepare()
    run.team("up", "--no-loop")
    gate = run.tmp / "codex-wrapper-finish"
    run.codex_script = run.codex_script.replace(
        "    code = subprocess.run([sys.executable, FAKE, *argv], env=env).returncode",
        "    code = subprocess.run([sys.executable, FAKE, *argv], env=env).returncode\n"
        "    import time\n    gate=Path(%r)\n"
        "    gate.with_name(gate.name+'.ready').write_text('ready')\n"
        "    until=time.monotonic()+20\n"
        "    while not gate.exists() and time.monotonic()<until:\n        time.sleep(0.01)" % str(gate))
    answer = run.team("turn", REVIEWER, "Check in.", expect=3, AEGIS_TEAM_TURN_TIMEOUT="0.2")
    operation = answer["operation"]
    gate_ready(gate)
    target = Path("/proc/%d/stat" % operation["pid"])
    prefix, tail = target.read_text().rsplit(")", 1)
    fields = tail.split()
    fields[19] = str(int(fields[19]) + 1)
    changed = prefix + ") " + " ".join(fields) + "\n"
    original = Path.read_text
    before = files(run.run)
    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_text", lambda p, *a, **kw: changed if p == target else original(p, *a, **kw))
        code, answer = in_process(run, "turn", REVIEWER, "--reconcile", capsys=capsys)
    assert code == 2 and answer["error"] == "operation %s is unresolved: its process is still running" % operation["id"]
    assert files(run.run) == before and run.mailbox().wake_marker(REVIEWER).exists()
    finish_fake(run, operation, gate)


@pytest.mark.parametrize("host", ["unlisted-host", "claude-code", "codex"])
def test_fix8_legacy_unsupported_host_refuses_before_claiming_a_marker(make, host):
    run, words, _endpoint = legacy_owner_without_plan(make, "turn")
    path = run.base_dir / "mailbox/bindings" / REVIEWER / "000001.json"
    binding = json.loads(path.read_text())
    binding["host"] = host
    path.write_text(json.dumps(binding))
    path = run.base_dir / "profiles/pilot%2Flane%2Freview-g1.wake.json"
    profile = json.loads(path.read_text())
    profile["host"] = host
    path.write_text(json.dumps(profile))
    before = files(run.run)
    answer = run.team(*words, expect=2)
    assert answer["error"] == "owner turn host differs from configured team host; restore the configured host binding"
    assert files(run.run) == before and not run.mailbox().wake_marker(REVIEWER).exists()


def test_fix8_observed_native_exit_survives_a_foreign_state_slot(make, monkeypatch, capsys):
    run = make(CODEX, CLAUDE)
    run.role()
    run.claude_exit_after_reply = 1
    original_init, original_wait = subprocess.Popen.__init__, subprocess.Popen.wait
    models, changed = [], []

    def initialize(process, argv, *args, **kwargs):
        original_init(process, argv, *args, **kwargs)
        if Path(str(argv[0])).name == "claude" and "--resume" in argv:
            models.append(process)

    def wait(process, *args, **kwargs):
        code = original_wait(process, *args, **kwargs)
        if process in models and not changed:
            saved = state(run)
            old = saved["operations"][REVIEWER]
            foreign = {**old, "id": uuid.uuid4().hex}
            saved["operations"][REVIEWER] = foreign
            (run.run / "team-state.json").write_text(json.dumps(saved))
            changed.append((old, foreign, code))
        return code

    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    with monkeypatch.context() as patch:
        patch.setattr(subprocess.Popen, "__init__", initialize)
        patch.setattr(subprocess.Popen, "wait", wait)
        code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 3 and len(changed) == 1 and changed[0][2] == 1
    operation, foreign, _native = changed[0]
    receipt = run.evidence / ("turn-%s.accounting.json" % operation["id"])
    assert receipt.is_file() and json.loads(receipt.read_text())["exit_code"] == 1
    [usage] = rows(run.evidence / operation["turn_log"])
    assert usage["operation_id"] == operation["id"] and usage["exit_code"] == 1
    assert state(run)["operations"][REVIEWER] == foreign and run.mailbox().wake_marker(REVIEWER).exists()
    assert run.team("turn", REVIEWER, "Again.", expect=2)["operation"] == foreign
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1


def test_fix8_transcript_snapshot_uses_bounded_reads(make, monkeypatch, capsys):
    run = make(CODEX, CLAUDE)
    run.role()
    # A history larger than a hash chunk distinguishes streaming from read(file_size).
    with run.seed_path.open("ab") as stream:
        stream.write((json.dumps({"type": "progress", "sessionId": run.seed_path.stem,
                                  "data": "x" * (2 << 20)}) + "\n").encode("utf-8"))
    original = os.fdopen
    reads = []

    class BoundedStream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def __iter__(self):
            return iter(self.stream)

        def readline(self, size=-1):
            reads.append(size)
            if not 0 <= size <= 1 << 20:
                raise OSError("fixture: unbounded host transcript record read")
            return self.stream.readline(size)

        def read(self, size=-1):
            reads.append(size)
            if not 0 <= size <= 1 << 20:
                raise OSError("fixture: unbounded host transcript snapshot")
            return self.stream.read(size)

    def opening(fd, *args, **kwargs):
        stream = original(fd, *args, **kwargs)
        return BoundedStream(stream) if os.readlink("/proc/self/fd/%d" % fd) == str(run.seed_path) else stream

    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    with monkeypatch.context() as patch:
        patch.setattr(os, "fdopen", opening)
        code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 0, answer
    assert reads and all(0 <= size <= 1 << 20 for size in reads)
    assert not state(run)["operations"] and not run.mailbox().wake_marker(REVIEWER).exists()
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1


# fix9: public regressions at the OS/process boundary. All host executables below are sealed test fakes.
@pytest.mark.parametrize("case", ["relative", "empty", "ancestor", "written_alias", "resolved_sdk", "home"])
def test_fix9_governed_path_and_executable_share_all_write_roots(make, case):
    run = make(CODEX, CODEX)
    run.ready("--no-loop")
    extra = {}
    if case == "relative":
        prefix = os.path.relpath(run.bin, Path.cwd())
    elif case == "empty":
        prefix = ""
    elif case == "ancestor":
        prefix = str(run.tmp)
    elif case == "home":
        prefix = str(run.codex_home)
    elif case == "written_alias":
        lookup = run.run / "worktrees/f2/lookup"
        lookup.symlink_to(run.bin, target_is_directory=True)
        prefix = str(lookup)
    else:
        target = run.run / "worktrees/f2/model-sdk"
        target.write_bytes((run.bin / "codex").read_bytes())
        target.chmod(0o700)
        (run.bin / "codex").unlink()
        (run.bin / "codex").symlink_to(target)
        prefix = str(run.bin)
    extra["PATH"] = prefix + os.pathsep + str(run.bin)
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "Check in.", expect=2, **extra)
    assert answer["custody_problem"]["reason"] == "model executable scope"
    assert files(run.run) == before and not run.mailbox().wake_marker(REVIEWER).exists()


def test_fix9_model_executes_the_validated_absolute_path(make, monkeypatch, capsys):
    run = make(CODEX, CODEX)
    run.ready("--no-loop")
    calls = []
    original = subprocess.Popen.__init__

    def initialize(process, argv, *args, **kwargs):
        if "resume" in argv:
            calls.append(list(argv))
        return original(process, argv, *args, **kwargs)

    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    with monkeypatch.context() as patch:
        patch.setattr(subprocess.Popen, "__init__", initialize)
        code, answer = in_process(run, "turn", REVIEWER, "Exact bytes.", capsys=capsys)
    assert code == 0, answer
    assert len(calls) == 1 and calls[0][0] == str((run.bin / "codex").resolve())
    assert calls[0][-1] == "Exact bytes."


@pytest.mark.parametrize("control", ["evidence", "lifecycle", "base", "codex_home", "owner", "ancestor"])
def test_fix9_provision_refuses_write_roots_overlapping_control(make, control):
    run = make(CLAUDE, CODEX)
    paths = {"evidence": run.run / "evidence/writer", "lifecycle": run.run / "lifecycle/writer",
             "base": run.run / "initiatives/pilot/writer", "codex_home": run.run / "claude-home/writer",
             "owner": run.run / ".owner-custody/writer", "ancestor": run.tmp}
    run.config["lanes"][0]["worktree"] = str(paths[control])
    run.save()
    answer = run.team("init", expect=2)
    assert answer["custody_problem"]["reason"] == "role write scope"
    assert not (run.run / "team-state.json").exists()
    assert not (run.run / ".owner-custody").exists()


@pytest.mark.parametrize("fault", ["temporary", "stdout", "stdin_write", "popen_os", "popen_value", "intend"])
def test_fix9_definite_no_spawn_retires_without_unknown_custody(make, monkeypatch, capsys, fault):
    run = make(CODEX, CLAUDE)
    run.role()
    original_open, original_temp, original_init, original_replace = builtins.open, team_module().tempfile.TemporaryFile, subprocess.Popen.__init__, os.replace
    injected, calls = [], []
    for name, value in run.env().items():
        monkeypatch.setenv(name, value)

    def opening(path, mode="r", *args, **kwargs):
        if fault == "stdout" and str(path).endswith(".stdout.jsonl") and ("w" in mode or "x" in mode) and not injected:
            injected.append(True)
            raise PermissionError("fixture: output creation refused")
        return original_open(path, mode, *args, **kwargs)

    class InputFailure:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def write(self, raw):
            injected.append(True)
            raise OSError("fixture: prompt staging has no space")

    def temporary(*args, **kwargs):
        if fault == "temporary":
            injected.append(True)
            raise OSError("fixture: temporary creation has no space")
        return InputFailure() if fault == "stdin_write" else original_temp(*args, **kwargs)

    def initialize(process, argv, *args, **kwargs):
        if Path(str(argv[0])).name == "claude" and "--resume" in argv:
            if fault in ("popen_os", "popen_value"):
                injected.append(True)
                raise (FileNotFoundError("fixture: exec absent") if fault == "popen_os" else ValueError("fixture: invalid exec"))
            calls.append(True)
        return original_init(process, argv, *args, **kwargs)

    def replace(source, destination, *args, **kwargs):
        if fault == "intend" and Path(destination) == run.run / "team-state.json" and not injected:
            candidate = json.loads(Path(source).read_text())
            if candidate.get("operations"):
                current = state(run)
                current["down"]["started_at"] = "fixture-teardown"
                original_tempfile = Path(destination).with_name("fixture-competing-state.json")
                original_tempfile.write_text(json.dumps(current))
                original_replace(original_tempfile, destination)
                injected.append(True)
                raise team_module().Stop(2, "fixture: concurrent teardown refused intent")
        return original_replace(source, destination, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", opening)
        patch.setattr(team_module().tempfile, "TemporaryFile", temporary)
        patch.setattr(subprocess.Popen, "__init__", initialize)
        patch.setattr(os, "replace", replace)
        code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 2 and injected and not calls, answer
    assert answer["spawned"] is False and answer["custody_retired"] is True
    assert not run.mailbox().wake_marker(REVIEWER).exists()
    assert not state(run).get("operations", {})
    assert not list((run.run / ".owner-custody").glob("active-*.json"))
    if fault == "intend":
        assert answer["error"] == "fixture: concurrent teardown refused intent"
        assert state(run)["down"]["started_at"] == "fixture-teardown"
    else:
        assert run.team("turn", REVIEWER, "The original request is definitely unstarted.")["exit_code"] == 0


@pytest.mark.parametrize("exception", ["os", "value", "stop"])
def test_fix9_launched_without_launch_publication_recovers_original_intent(make, monkeypatch, capsys, exception):
    run = make(CODEX, CLAUDE)
    run.role()
    gate = run.tmp / "fix9-launch-gap"
    run.claude_after_reply = {"gate": gate, "error": False}
    original = os.link
    injected = []
    for name, value in run.env().items():
        monkeypatch.setenv(name, value)

    def linking(source, destination, *args, **kwargs):
        if str(destination).endswith(".launch.json") and not injected:
            injected.append(True)
            raise {"os": OSError("fixture: launch publication failed"),
                   "value": ValueError("fixture: launch publication invalid"),
                   "stop": team_module().Stop(2, "fixture: launch publication refused")}[exception]
        return original(source, destination, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "link", linking)
        code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 3 and injected and answer["spawned"] is True, answer
    operation = state(run)["operations"][REVIEWER]
    gate_ready(gate)
    assert run.mailbox().wake_marker(REVIEWER).exists()
    assert run.team("turn", REVIEWER, "--reconcile", expect=2)["operation"]["id"] == operation["id"]
    assert run.team("turn", REVIEWER, "Again.", expect=2)["operation"]["id"] == operation["id"]
    gate.write_text("finish")
    [call] = [row for row in run.claude_calls() if "--resume" in row["argv"]]
    finish_fake(run, {"pid": call["pid"]}, gate)
    result = run.team("turn", REVIEWER, "--reconcile")
    assert result["reconciled"] == operation["id"] and result["replayed"] is False
    assert not state(run)["operations"] and not run.mailbox().wake_marker(REVIEWER).exists()
    [usage] = rows(run.evidence / operation["turn_log"])
    assert usage["operation_id"] == operation["id"] and usage["exit_code"] is None
    assert len([row for row in run.claude_calls() if "--resume" in row["argv"]]) == 1


@pytest.mark.parametrize("kind", ["missing", "realpath", "bytes"])
def test_fix9_interpreter_drift_has_one_actionable_classifier(make, kind):
    run = make(CODEX, CLAUDE)
    original = run.tmp / "python-original"
    alternate = run.tmp / "python-alternate"
    script = "#!%s\nimport os,sys\nos.execv(%r,[%r,*sys.argv[1:]])\n" % (sys.executable, sys.executable, sys.executable)
    original.write_text(script)
    alternate.write_text(script)
    original.chmod(0o700)
    alternate.chmod(0o700)
    selected = run.tmp / "python-selected"
    selected.symlink_to(original)
    run.config["recipes"]["python"] = str(selected)
    run.save()
    run.role()
    if kind == "missing":
        original.unlink()
    elif kind == "realpath":
        selected.unlink()
        selected.symlink_to(alternate)
    else:
        original.write_text(script + "# changed interpreter bytes\n")
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "Check in.", expect=2)
    assert answer["custody_problem"]["reason"] == "interpreter drift"
    assert answer["next_action"] == team_module().INTERPRETER_RECOVERY
    assert files(run.run) == before and not run.mailbox().wake_marker(REVIEWER).exists()
    assert not [call for call in run.claude_calls() if "--resume" in call["argv"]]


@pytest.mark.parametrize("value", [[], {"dropped_names": None}, {"dropped_names": [7]}, {"dropped_names": ["SAFE"], "extra": 1}])
def test_fix9_finalisation_is_typed_and_keeps_completed_result(make, value):
    run = make(CODEX, CLAUDE)
    run.role()
    (run.evidence / "child-environment.json").write_text(json.dumps(value))
    answer = run.team("turn", REVIEWER, "Check in.", expect=3)
    assert answer["partial_result"]["exit_code"] == 0
    assert answer["finalisation_error"]["record"] == "child-environment.json"
    assert answer["finalisation_error"]["reason"] == "record shape"
    assert not state(run)["operations"] and not run.mailbox().wake_marker(REVIEWER).exists()
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1


@pytest.mark.parametrize("record", ["state", "active", "environment"])
@pytest.mark.parametrize("depth", [40, 1200])
def test_fix9_deep_json_is_a_local_custody_problem(make, record, depth):
    if record == "state":
        run, _words, _endpoint = legacy_owner_without_plan(make, "turn")
    else:
        run = make(CODEX, CLAUDE)
        run.role()
    deep = "[" * depth + "0" + "]" * depth
    path = (run.run / "team-state.json" if record == "state" else run.evidence / "child-environment.json"
            if record == "environment" else run.run / ".owner-custody/active-pilot%2Flane%2Fother.json")
    previous = path.read_bytes() if path.exists() else None
    path.write_text(deep)
    path.chmod(0o600)
    try:
        answer = run.team("status")
        assert answer["schema"] == "aegis.team-run-status/v1" and answer["custody_errors"]
        assert any(item.get("reason") == "record depth" for item in answer["custody_errors"].values())
        assert path.read_text() == deep
    finally:
        if previous is not None:
            path.write_bytes(previous)
        else:
            path.unlink()


def test_fix9_codex_byte_line_boundaries_and_unknown_events_are_preserved(make):
    run = make(CODEX, CODEX)
    run.ready("--no-loop")
    run.codex_script = run.codex_script.replace(
        "def role(argv):",
        "def role(argv):\n    print(json.dumps({'type':'item.completed','item':{'type':'agent_message','text':'a\\u2028b\\u0085c'}}),flush=True)\n    print('not json',flush=True)")
    answer = run.team("turn", REVIEWER, "Check in.")
    assert any(item.get("text") == "a\u2028b\u0085c" for item in answer["items"])
    assert any(item["type"] == "unknown" and item["raw"] == "not json" for item in answer["items"])
    assert answer["unknown_events"] == 1


def test_fix9_orchestration_has_no_host_comparisons_outside_adapters():
    import ast
    source = Path(TEAM).read_text()
    tree = ast.parse(source)
    table = next(node.value for node in tree.body if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == "OWNER_ADAPTERS" for target in node.targets))
    allowed = {id(node) for node in ast.walk(table)}
    offending = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Compare) and id(node) not in allowed
                 and any(isinstance(item, ast.Name) and item.id in ("CODEX", "CLAUDE")
                         for item in [node.left, *node.comparators])]
    assert offending == [], "host comparisons outside owner adapters: %r" % offending


@pytest.mark.parametrize("host", [CODEX, CLAUDE])
def test_fix9_observed_exit_keeps_live_bound_descendant_held(make, monkeypatch, capsys, host):
    run = make(CODEX, host)
    if host == CLAUDE:
        run.role()
    else:
        run.ready("--no-loop")
    binding = run.mailbox().current_binding(REVIEWER)
    gate = run.tmp / "descendant-finish"
    pidfile = run.tmp / "descendant-pid"
    child = run.tmp / "owned-descendant.py"
    child.write_text("import os,time\nfrom pathlib import Path\nPath(%r).write_text(str(os.getpid()))\n"
                     "until=time.monotonic()+30\n"
                     "while not Path(%r).exists() and time.monotonic()<until: time.sleep(0.01)\n" %
                     (str(pidfile), str(gate)))
    original = subprocess.Popen.__init__
    model_calls = []
    for name, value in run.env().items():
        monkeypatch.setenv(name, value)

    def initialize(process, argv, *args, **kwargs):
        name = Path(str(argv[0])).name
        if name in ("claude", "codex") and ("--resume" in argv or "resume" in argv):
            model_calls.append(list(argv))
            executable = run.bin / name
            script = executable.read_text()
            descendant = [sys.executable, str(child), "--resume" if host == CLAUDE else "resume", binding["session"]]
            executable.write_text("#!%s\nimport subprocess,sys,time\nfrom pathlib import Path\n"
                                  "try:\n    exec(compile(%r,%r,'exec'),{'__name__':'__main__'})\n"
                                  "except SystemExit:\n    pass\n"
                                  "subprocess.Popen(%r,stdin=subprocess.DEVNULL)\n"
                                  "until=time.monotonic()+2\n"
                                  "while not Path(%r).exists() and time.monotonic()<until: time.sleep(0.01)\n"
                                  "raise SystemExit(1)\n" %
                                  (sys.executable, script, str(executable), descendant, str(pidfile)))
        return original(process, argv, *args, **kwargs)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(subprocess.Popen, "__init__", initialize)
            code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
        assert code == 3 and len(model_calls) == 1, answer
        operation = state(run)["operations"][REVIEWER]
        assert run.mailbox().wake_marker(REVIEWER).exists() and pidfile.exists()
        assert answer["process_observation"]["state"] == "PRESENT"
        receipt = run.evidence / ("turn-%s.accounting.json" % operation["id"])
        assert json.loads(receipt.read_text())["exit_code"] == 1
        assert not list((run.run / ".owner-custody").glob("*.release.json"))
        assert run.team("turn", REVIEWER, "Again.", expect=2)["operation"] == operation
        gate.write_text("finish")
        finish_fake(run, {"pid": int(pidfile.read_text())}, gate)
        result = run.team("turn", REVIEWER, "--reconcile", expect=3)
        assert result["reconciled"] == operation["id"] and result["replayed"] is False
        assert not state(run)["operations"] and not run.mailbox().wake_marker(REVIEWER).exists()
        assert json.loads(receipt.read_text())["exit_code"] == 1
    finally:
        gate.write_text("finish")


@pytest.mark.parametrize("kind", ["confirmation_line", "recovery_line", "fresh_count", "fresh_total", "stdout", "turn_log", "marker"])
def test_fix9_recovery_budgets_hold_without_effects_or_replay(make, kind):
    run = make(CODEX, CLAUDE)
    if kind == "confirmation_line":
        run.role()
        with run.seed_path.open("ab") as stream:
            stream.write((json.dumps({"type": "progress", "sessionId": run.seed_path.stem,
                                      "text": "x" * (5 << 20)}) + "\n").encode())
        before = files(run.run)
        answer = run.team("turn", REVIEWER, "Check in.", expect=2)
        assert answer["custody_problem"]["reason"] == "byte budget"
        assert files(run.run) == before and not run.mailbox().wake_marker(REVIEWER).exists()
        assert not [call for call in run.claude_calls() if "--resume" in call["argv"]]
        return
    operation, gate = held_after_supported_reply(run)
    finish_fake(run, operation, gate)
    if kind in ("recovery_line", "fresh_count", "fresh_total"):
        count, size = (1, 5 << 20) if kind == "recovery_line" else (1100, 4) if kind == "fresh_count" else (10, 1 << 20)
        with run.seed_path.open("ab") as stream:
            for _ in range(count):
                stream.write((json.dumps({"type": "progress", "sessionId": operation["session"],
                                          "text": "x" * size}) + "\n").encode())
    else:
        path = Path(operation["stdout"]) if kind == "stdout" else run.evidence / operation["turn_log"] if kind == "turn_log" else Path(operation["marker"])
        with path.open("ab") as stream:
            if kind == "stdout":
                # Exceed the total byte limit with individually small records, below the event-count budget.
                stream.write((json.dumps({"type": "progress", "text": "x" * 1000}) + "\n").encode() * 17000)
            else:
                stream.write(b"x" * ((17 << 10) if kind == "marker" else (17 << 20)) + b"\n")
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "--reconcile", expect=2)
    assert answer["custody_problem"]["reason"] == ("event budget" if kind == "fresh_count" else "byte budget")
    assert state(run)["operations"][REVIEWER] == operation and files(run.run) == before
    assert run.mailbox().wake_marker(REVIEWER).exists()
    assert run.team("turn", REVIEWER, "Again.", expect=2)["operation"]["id"] == operation["id"]
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1


def test_fix9_fifo_marker_cannot_block_the_public_writer_lock(make, monkeypatch, capsys):
    run = make(CODEX, CLAUDE)
    operation, gate = held_after_supported_reply(run)
    finish_fake(run, operation, gate)
    path = run.mailbox().wake_marker(REVIEWER)
    path.unlink()
    os.mkfifo(path, 0o600)
    original = os.open
    accesses = []

    def opening(filename, flags, *args, **kwargs):
        if Path(filename) == path:
            accesses.append(flags)
            assert flags & os.O_NONBLOCK, "marker FIFO must be opened nonblocking"
        return original(filename, flags, *args, **kwargs)

    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    before = files(run.run)
    with monkeypatch.context() as patch:
        patch.setattr(os, "open", opening)
        code, answer = in_process(run, "turn", REVIEWER, "--reconcile", capsys=capsys)
    assert code == 2 and accesses
    assert answer["custody_problem"]["reason"] == "record type"
    assert files(run.run) == before and state(run)["operations"][REVIEWER] == operation
    assert path.stat().st_mode & 0o170000 == 0o010000


def test_fix9_loop_validates_the_final_recipes_path_before_spawn(make):
    run = make(CODEX, CODEX)
    run.team("init")
    run.team("login")
    cargo = run.run / "worktrees/f2/tools"
    cargo.mkdir()
    for name in ("cargo", "cargo-nextest"):
        (cargo / name).write_bytes((run.cargo / name).read_bytes())
        (cargo / name).chmod(0o700)
    recipe = json.loads((run.run / "recipes.json").read_text())
    recipe["path"] = [str(cargo)]
    (run.run / "recipes.json").write_text(json.dumps(recipe))
    before = files(run.run)
    answer = run.team("up", expect=2)
    assert answer["custody_problem"]["reason"] == "model executable scope"
    assert files(run.run) == before and not (run.run / "loop.pid").exists()


@pytest.mark.parametrize("command", ["login", "git"])
def test_fix9_non_turn_spawns_cannot_run_model_writable_executables(make, command):
    run = make(CODEX, CODEX)
    if command == "login":
        run.ready("--no-loop")
        original = run.bin / "codex"
        target = run.run / "worktrees/f2/owned-sdk"
        target.write_bytes(original.read_bytes())
        target.chmod(0o700)
        original.unlink()
        original.symlink_to(target)
        words = ("login",)
    else:
        marker = run.tmp / "unsafe-git-ran"
        target = run.project / "owned-git"
        target.write_text("#!%s\nimport os,sys\nfrom pathlib import Path\nPath(%r).write_text('ran')\nos.execv('/usr/bin/git',['git',*sys.argv[1:]])\n" %
                          (sys.executable, str(marker)))
        target.chmod(0o700)
        (run.bin / "git").unlink()
        (run.bin / "git").symlink_to(target)
        words = ("init",)
    before = files(run.run)
    answer = run.team(*words, expect=2)
    assert answer["custody_problem"]["reason"] == "model executable scope"
    assert files(run.run) == before
    if command == "git":
        assert not marker.exists()


@pytest.mark.parametrize("concurrent", ["teardown", "operation"])
def test_fix9_intend_preserves_actual_refusal_and_foreign_state(make, monkeypatch, capsys, concurrent):
    run = make(CODEX, CODEX)
    run.ready("--no-loop")
    original = os.open
    inserted = []
    foreign = {"id": uuid.uuid4().hex}
    for name, value in run.env().items():
        monkeypatch.setenv(name, value)

    def opening(path, flags, *args, **kwargs):
        if (Path(path) == run.run / "team-state.json" and run.mailbox().wake_marker(REVIEWER).exists()
                and not inserted and not flags & (os.O_WRONLY | os.O_RDWR)):
            inserted.append(True)
            current = state(run)
            if concurrent == "teardown":
                current["down"]["started_at"] = "fixture-teardown"
            else:
                current["operations"] = {REVIEWER: foreign}
            (run.run / "team-state.json").write_text(json.dumps(current))
        return original(path, flags, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", opening)
        code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 2 and inserted and answer["spawned"] is False and answer["custody_retired"] is True
    assert not run.mailbox().wake_marker(REVIEWER).exists()
    if concurrent == "teardown":
        assert answer["error"] == "teardown has started; a new run needs a new run folder"
        assert state(run)["down"]["started_at"] == "fixture-teardown"
    else:
        assert answer["error"] == ("%s has unresolved operation %s; inspect status, then use approve/turn --reconcile; "
                                   "never replay an unknown turn" % (REVIEWER, foreign["id"]))
        assert answer["operation"] == foreign and state(run)["operations"][REVIEWER] == foreign


def test_fix9_output_reads_have_fixed_io_chunks(make, monkeypatch, capsys):
    run = make(CODEX, CLAUDE)
    run.role()
    original = os.fdopen
    sizes = []

    class OutputReader:
        def __init__(self, stream):
            self.stream = stream
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return self.stream.__exit__(*args)
        def __getattr__(self, name):
            return getattr(self.stream, name)
        def read(self, size=-1):
            sizes.append(size)
            assert 0 <= size <= 1 << 20, "owner stdout reads must use fixed bounded chunks"
            return self.stream.read(size)

    def opening(fd, *args, **kwargs):
        stream = original(fd, *args, **kwargs)
        return OutputReader(stream) if os.readlink("/proc/self/fd/%d" % fd).endswith(".stdout.jsonl") else stream

    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    with monkeypatch.context() as patch:
        patch.setattr(os, "fdopen", opening)
        code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 0 and sizes, answer
    assert not state(run)["operations"]


def test_fix9_large_credential_record_refuses_before_a_spawn(make):
    run = make(CODEX, CLAUDE)
    run.role()
    path = run.claude_home / ".credentials.json"
    with path.open("ab") as stream:
        stream.write(b" " * (1 << 20))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "Check in.", expect=2)
    assert answer["custody_problem"]["reason"] == "byte budget"
    assert files(run.run) == before and not run.mailbox().wake_marker(REVIEWER).exists()
    assert not [call for call in run.claude_calls() if "--resume" in call["argv"]]


@pytest.mark.parametrize("field", ["cwd", "writable_roots", "add_dirs", "tmpdir"])
@pytest.mark.parametrize("control", [False, True])
def test_fix9_every_profile_root_participates_in_owner_scope(make, field, control):
    run = make(CODEX, CODEX)
    run.ready("--no-loop")
    path = run.base_dir / "profiles/pilot%2Flane%2Freview-g1.wake.json"
    profile = json.loads(path.read_text())
    root = run.evidence / "writer" if control else run.tmp / "extra-role-scope"
    root.mkdir()
    profile[field] = [str(root)] if field in ("writable_roots", "add_dirs") else str(root)
    path.write_text(json.dumps(profile))
    before = files(run.run)
    extra = {} if control else {"PATH": str(root) + os.pathsep + str(run.bin)}
    answer = run.team("turn", REVIEWER, "Check in.", expect=2, **extra)
    assert answer["custody_problem"]["reason"] == ("role write scope" if control else "model executable scope")
    assert files(run.run) == before and not run.mailbox().wake_marker(REVIEWER).exists()


@pytest.mark.parametrize("kind", ["depth", "count"])
def test_fix9_output_structure_budgets_keep_observed_exit_and_custody(make, monkeypatch, capsys, kind):
    run = make(CODEX, CODEX)
    run.ready("--no-loop")
    text = ("[" * 40 + "0" + "]" * 40) if kind == "depth" else "\n" * 65537
    run.codex_script = run.codex_script.replace(
        "def role(argv):", "def role(argv):\n    print(%r,flush=True)" % text)
    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 3, (code, answer.get("error"))
    assert answer["spawned"] is True
    assert answer["custody_problem"]["reason"] == ("record depth" if kind == "depth" else "event budget")
    operation = answer["operation"]
    assert state(run)["operations"][REVIEWER] == operation and run.mailbox().wake_marker(REVIEWER).exists()
    witness = json.loads((run.run / ".owner-custody" / ("turn-%s.exit.json" % operation["id"])).read_text())
    assert witness["native_exit"] == 0
    assert run.team("turn", REVIEWER, "Again.", expect=2)["operation"]["id"] == operation["id"]


def test_fix9_unresolvable_role_scope_refuses_before_effects(make):
    run = make(CODEX, CODEX)
    run.ready("--no-loop")
    loop = run.tmp / "cyclic-role-scope"
    loop.symlink_to(loop)
    path = run.base_dir / "profiles/pilot%2Flane%2Freview-g1.wake.json"
    profile = json.loads(path.read_text())
    profile["add_dirs"] = [str(loop)]
    path.write_text(json.dumps(profile))
    before = files(run.run)
    answer = run.team("turn", REVIEWER, "Check in.", expect=2)
    assert answer["custody_problem"]["reason"] == "model executable scope"
    assert files(run.run) == before and not run.mailbox().wake_marker(REVIEWER).exists()


@pytest.mark.parametrize("native_exit", [0, 1])
def test_fix9_observed_native_exit_survives_exit_witness_publication_failure(make, monkeypatch, capsys, native_exit):
    run = make(CODEX, CLAUDE)
    run.role()
    run.claude_exit_after_reply = native_exit
    original = os.link
    lost = []

    def linking(source, destination, *args, **kwargs):
        if str(destination).endswith(".exit.json") and not lost:
            lost.append(True)
            raise OSError("fixture: measured exit publication reply lost")
        return original(source, destination, *args, **kwargs)

    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    with monkeypatch.context() as patch:
        patch.setattr(os, "link", linking)
        code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 3 and lost == [True] and answer["spawned"] is True
    operation = answer["operation"]
    receipt = run.evidence / ("turn-%s.accounting.json" % operation["id"])
    assert json.loads(receipt.read_text())["exit_code"] == native_exit
    assert state(run)["operations"][REVIEWER] == operation and run.mailbox().wake_marker(REVIEWER).exists()
    log = run.evidence / operation["turn_log"]
    before = (receipt.read_bytes(), log.read_bytes())
    result = run.team("turn", REVIEWER, "--reconcile", expect=0 if native_exit == 0 else 3)
    assert result == {"endpoint": REVIEWER, "reconciled": operation["id"],
                      "outcome": "completed" if native_exit == 0 else "failed", "replayed": False}
    assert (receipt.read_bytes(), log.read_bytes()) == before
    assert not state(run)["operations"] and not run.mailbox().wake_marker(REVIEWER).exists()
    assert len([call for call in run.claude_calls() if "--resume" in call["argv"]]) == 1


def test_fix9_readonly_mount_does_not_exempt_an_executable_alias(make, monkeypatch, capsys):
    run = make(CODEX, CODEX)
    run.ready("--no-loop")
    executable = run.bin / "codex"
    alias = run.run / "worktrees/f2/sdk-alias"
    os.link(executable, alias)
    assert executable.stat().st_ino == alias.stat().st_ino and executable.stat().st_nlink == 2
    original = os.statvfs

    def filesystem(path):
        value = original(path)
        if Path(path) == executable:
            # Model a read-only mount view at the OS metadata boundary; the hardlink itself is real.
            fields = list(value)
            fields[8] |= os.ST_RDONLY
            return os.statvfs_result(fields)
        return value

    for name, value in run.env().items():
        monkeypatch.setenv(name, value)
    before = files(run.run)
    with monkeypatch.context() as patch:
        patch.setattr(os, "statvfs", filesystem)
        code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 2, (code, answer.get("error"))
    assert answer["custody_problem"]["reason"] == "model executable scope"
    assert files(run.run) == before and not run.mailbox().wake_marker(REVIEWER).exists()
