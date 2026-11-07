"""hierarchy_team.py, the owner's one command for a team run, on fixtures.

Every subcommand runs as a child process with a sealed PATH: the fake binaries only (a `codex` wrapper around the
repo's fake codex and fake host, links to git and ps, and a bwrap stub that is never run, because the fixture recipes
use `sandbox: none`). A test-session guard checks every process a test spawns and fails it if a `codex` that is not a
test fake would be reachable from its PATH. HOME and CODEX_HOME are temporary, so no real model can start and
nothing reads ~/.codex.

The fake `codex` here only adds what the repo's fakes cannot play: `codex login` (it writes the files a real login
leaves), ROOT's turn (it calls team_pending and root_decide over ROOT's own decision connection, as the approve prompt
asks), a served model or effort other than the argv asked for, and a role offered sub-agent tools (the additional_tools
record from tests/fixtures/hierarchy_native_multi_agent). Every other call runs hierarchy_fake_codex.py in rollout
mode. These tests show the tool carries the run's steps together on fixtures, not that real sessions behave this way.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time

import pytest

from tests.integration.hierarchy_fake_wrapper import shell_exec
from tests.integration.test_hierarchy_mailbox import ROOT, git


pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="the loop and run-open read /proc and the wake supports POSIX process groups only")
TEAM = ROOT / "tools" / "hierarchy_team.py"
TEMPLATE = ROOT / "tools" / "hierarchy_templates" / "team-run.json"
FAKE_CODEX = Path(__file__).with_name("hierarchy_fake_codex.py")
AGENT_TOOLS = ROOT / "tests" / "fixtures" / "hierarchy_native_multi_agent" / "v2.jsonl"
# What makes a `codex` on PATH a test fake: the repo's fake codex, a wrapper naming it, or the fake host.
FAKE_MARKS = (b"hierarchy_fake_codex.py", b"A stand-in for the claude and codex commands")
IMPLEMENTER, REVIEWER = "pilot/lane/f2", "pilot/lane/review"
BRANCH = "feature/pilot-f2"
ROLE_ORDER = ["pilot/router", "pilot/orchestrator", "pilot/decider", REVIEWER, IMPLEMENTER]
TEAM_SETTINGS = {"model": "gpt-6.1-sol", "reasoning": "high",
                 "reasoning_by_kind": {"orchestrator": "medium", "decider": "medium", "implementer": "high",
                                       "reviewer": "high"}}
DISABLED = ["apps", "plugins", "remote_plugin", "multi_agent", "multi_agent_v2", "memories", "computer_use",
            "browser_use", "browser_use_external", "browser_use_full_cdp_access", "goals", "shell_tool", "unified_exec"]
EMPTY = hashlib.sha256(b"").hexdigest()
# The targeted-tests recipe's step: each named file's test_* functions, counted into junit. A stand-in for pytest.
RUNNER = r'''
import importlib.util, os, sys
junit, paths = sys.argv[1], sys.argv[2:]
cases = []
for path in paths:
    spec = importlib.util.spec_from_file_location(path.replace("/", "_")[:-3], path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name in sorted(n for n in vars(module) if n.startswith("test_")):
        try:
            getattr(module, name)()
            cases.append(False)
        except AssertionError:
            cases.append(True)
failed = sum(cases)
os.makedirs(os.path.dirname(junit), exist_ok=True)
with open(junit, "w", encoding="utf-8") as stream:
    stream.write('<testsuite name="t" tests="%d" failures="%d" errors="0" skipped="0">%s</testsuite>'
                 % (len(cases), failed, "<testcase classname='c' name='n'/>" * len(cases)))
sys.exit(1 if failed else 0)
'''
CODEX_WRAPPER = r'''
import json, os, re, runpy, subprocess, sys, uuid
from pathlib import Path

FAKE = %(fake)r
AGENT_RECORD = %(agent)r
python_argv = runpy.run_path(str(Path(FAKE).with_name("hierarchy_fake_wrapper.py")))["python_argv"]


def emit(event):
    print(json.dumps(event), flush=True)


def servers(argv):
    try:
        import tomllib
    except ModuleNotFoundError:  # Python < 3.11, where pytest itself depends on tomli
        import tomli as tomllib
    for index, word in enumerate(argv[:-1]):
        if word == "-c" and argv[index + 1].startswith("mcp_servers="):
            return tomllib.loads(argv[index + 1])["mcp_servers"]
    return {}


def login():
    home = Path(os.environ["CODEX_HOME"])
    with open(os.environ["FAKE_TEAM_LOG"], "a", encoding="utf-8") as log:
        log.write(json.dumps({"kind": "login", "argv": sys.argv[1:], "codex_home": str(home)}) + "\n")
    mode = os.environ.get("FAKE_TEAM_LOGIN", "")
    if mode == "fail":
        sys.stderr.write("login failed\n")
        sys.exit(5)
    descriptor = os.open(home / "auth.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(descriptor, b'{"tokens": "fixture"}\n')
    os.close(descriptor)
    if mode == "loose":
        os.chmod(home / "auth.json", 0o644)
    if mode == "extra":
        (home / "config.toml").write_text("model = 'other'\n", encoding="utf-8")
    (home / "log").mkdir(exist_ok=True)
    (home / "log" / "codex-login.log").write_text("logged in\n", encoding="utf-8")
    print("Successfully logged in")


def root(argv, server):
    with open(os.environ["FAKE_TEAM_LOG"], "a", encoding="utf-8") as log:
        log.write(json.dumps({"kind": "root", "argv": argv, "cwd": os.getcwd(),
                              "codex_home": os.environ.get("CODEX_HOME")}) + "\n")
    prompt, thread = argv[-1], argv[argv.index("resume") + 1]
    emit({"type": "thread.started", "thread_id": thread})
    emit({"type": "turn.started"})
    mode = os.environ.get("FAKE_TEAM_ROOT", "")
    message = "Recorded."
    if mode == "silent":
        message = "I could not find that request, so I decided nothing."
    else:
        adapter = subprocess.Popen([server["command"], *server["args"]], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, text=True)

        def call(number, method, params=None):
            adapter.stdin.write(json.dumps({"jsonrpc": "2.0", "id": number, "method": method,
                                            "params": params or {}}) + "\n")
            adapter.stdin.flush()
            return json.loads(adapter.stdout.readline())

        def tool(number, name, arguments):
            answer = json.loads(call(number, "tools/call", {"name": name, "arguments": arguments})
                                ["result"]["content"][0]["text"])
            emit({"type": "item.completed", "item": {"id": "item_%%d" %% number, "type": "mcp_tool_call",
                                                     "server": "aegis_decision", "tool": name,
                                                     "arguments": arguments, "status": "completed"}})
            return answer

        call(1, "initialize")
        pending = tool(2, "team_pending", {})
        wanted = re.search(r"find request (\S+), then", prompt).group(1)
        decision = re.search(r"decision=(approve|deny)", prompt).group(1)
        reason = re.search(r'reason="(.*)"\. Do nothing else\.$', prompt).group(1)
        row = next((row for row in pending["pending"] if row["request_id"] == wanted), None)
        if row is None and decision == "deny":
            status = tool(5, "team_status", {})
            row = next(row for row in status["requests"] if row["request_id"] == wanted)
            row["root_decide"] = {"request_sha256": row["request_sha256"],
                                  "event_id_deny": "root-" + wanted + "-deny"}
        arguments = {"event_id": row["root_decide"]["event_id_" + decision], "request_id": wanted,
                     "request_sha256": row["root_decide"]["request_sha256"], "decision": decision, "reason": reason}
        if mode == "wrong-sha":
            arguments["request_sha256"] = "0" * 64
        answer = tool(3, "root_decide", arguments)
        if mode == "extra-decision":
            other = next(row for row in pending["pending"] if row["request_id"] != wanted)
            tool(4, "root_decide", {"event_id": other["root_decide"]["event_id_approve"],
                                   "request_id": other["request_id"], "request_sha256": other["request_sha256"],
                                   "decision": "approve", "reason": "unexpected"})
        adapter.stdin.close()
        adapter.wait(timeout=20)
        adapter.stdout.close()
        if "error" in answer:
            message = "root_decide refused: " + answer["error"]
    emit({"type": "item.completed", "item": {"id": "item_msg", "type": "agent_message", "text": message}})
    emit({"type": "turn.completed", "usage": {"input_tokens": 1, "cached_input_tokens": 0, "output_tokens": 1}})


def role(argv):
    argv = list(argv)
    for index, word in enumerate(argv[:-1]):
        for setting, variable in (("model=", "FAKE_TEAM_SERVED_MODEL"), ("model_reasoning_effort=", "FAKE_TEAM_SERVED_EFFORT")):
            if word == "-c" and argv[index + 1].startswith(setting) and os.environ.get(variable):
                argv[index + 1] = setting + json.dumps(os.environ[variable])
    env = dict(os.environ)
    thread = None
    if "resume" not in argv:
        thread = env.get("FAKE_CODEX_THREAD") or str(uuid.uuid4())
        env["FAKE_CODEX_THREAD"] = thread
    code = subprocess.run([*python_argv("codex", FAKE, Path(sys.argv[0]).parent.parent), *argv], env=env).returncode
    if thread and os.environ.get("FAKE_TEAM_NO_CATALOG"):
        for path in (Path(env["CODEX_HOME"]) / "sessions").glob("**/*%%s.jsonl" %% thread):
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            rows = [row for row in rows if row.get("payload", {}).get("type") != "additional_tools"]
            mode = os.environ["FAKE_TEAM_NO_CATALOG"]
            if mode != "missing":
                tools = None if mode == "malformed" else [{"type": "namespace", "name": "workers",
                                                          "tools": [{"name": "launch"}]}]
                rows.append({"type": "response_item", "payload": {"type": "additional_tools", "tools": tools}})
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    wanted = os.environ.get("FAKE_TEAM_AGENT_TOOLS")
    if thread and wanted and "for %%s as" %% wanted in argv[-1]:
        [rollout] = Path(env["CODEX_HOME"]).glob("sessions/*/*/*/rollout-*-%%s.jsonl" %% thread)
        record = Path(AGENT_RECORD).read_text(encoding="utf-8").splitlines()[2]
        with open(rollout, "a", encoding="utf-8") as stream:
            stream.write(record + "\n")
    sys.exit(code)


def main():
    argv = sys.argv[1:]
    if argv[:1] == ["login"]:
        return login()
    found = servers(argv)
    if "aegis_decision" in found and "resume" in argv:
        return root(argv, found["aegis_decision"])
    return role(argv)


main()
'''


def real_codex_on(path_value):
    """The first `codex` on this PATH that is not a test fake, or None."""
    for folder in path_value.split(os.pathsep):
        candidate = Path(folder or ".") / "codex"
        if candidate.is_file():
            with open(candidate, "rb") as stream:
                head = stream.read(65536)
            if not any(mark in head for mark in FAKE_MARKS):
                return str(candidate)
    return None


def seal_spawns(monkeypatch, folder):
    """This test's PATH is `folder` alone, and every process the test spawns is checked: a codex reachable from the
    PATH it gets must be a test fake. An earlier lane's test once ran the real codex because PATH kept it."""
    assert real_codex_on(str(folder)) is None, "the sealed folder itself holds a real codex"
    monkeypatch.setenv("PATH", str(folder))
    original = subprocess.Popen.__init__

    def checked(self, args, *rest, **options):
        env = options.get("env")
        found = real_codex_on((os.environ if env is None else env).get("PATH", os.defpath))
        if found is not None:
            raise AssertionError("a real codex is reachable from a spawned PATH: %s (argv %r)" % (found, args))
        return original(self, args, *rest, **options)

    monkeypatch.setattr(subprocess.Popen, "__init__", checked)


def fake_codex(folder, log=None):
    """The test's `codex`: the wrapper above around the repo's fake codex."""
    path = folder / "codex"
    script = folder / "codex-wrapper.py"
    script.write_text(CODEX_WRAPPER % {"fake": str(FAKE_CODEX), "agent": str(AGENT_TOOLS)}, encoding="utf-8")
    path.write_text("#!/bin/sh\n# hierarchy_fake_codex.py\n%s \"$@\"\n" % shell_exec("codex", script, folder.parent),
                    encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def stub(folder, name, body="exit 0\n"):
    path = folder / name
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def command(argv, **extra):
    return {"kind": "command", "heavy": False, "sandbox": "none", "timeout_seconds": 60, "steps": [argv], **extra}


class Run:
    """One team run on fixtures: a committed Aegis source copy, a project clone on `develop`, a recipe template with
    the home-folder placeholder, the run folder and its config."""

    def __init__(self, tmp_path, monkeypatch):
        self.tmp = tmp_path
        self.monkeypatch = monkeypatch
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.bin = tmp_path / "fake-bin"
        self.bin.mkdir()
        for tool in ("git", "ps"):
            found = shutil.which(tool)
            assert found, tool + " is needed by the tools under test"
            (self.bin / tool).symlink_to(found)
        fake_codex(self.bin)
        stub(self.bin, "bwrap", 'echo "bwrap stub: the fixture recipes use sandbox none" >&2\nexit 1\n')
        seal_spawns(monkeypatch, self.bin)
        monkeypatch.setenv("HOME", str(self.home))
        for name in ("CODEX_HOME", "OPENAI_API_KEY", "CODEX_API_KEY"):
            monkeypatch.delenv(name, raising=False)
        self.cargo = self.home / ".cargo" / "bin"
        self.cargo.mkdir(parents=True)
        stub(self.cargo, "cargo")
        stub(self.cargo, "cargo-nextest")
        self.source = self.make_source()
        self.project = self.make_project()
        self.base = git(self.project, "rev-parse", "HEAD")
        self.template = tmp_path / "recipes-template.json"
        self.template.write_text(json.dumps({
            "schema": "aegis.hierarchy-job-recipes/v1", "python": "/REPLACE/WITH/dev-venv/bin/python",
            "path": ["/REPLACE/WITH/your/home/folder/.cargo/bin", "/usr/bin", "/bin"],
            "identity": {"name": "Aegis hierarchy root", "email": "root@example.invalid"},
            "recipes": {
                "targeted-tests": command(["$python", "-B", "-c", RUNNER, "$scratch/junit.xml", "$paths"], heavy=True,
                                          require_clean=True, expects_tests=True, keep=["run/junit.xml"]),
                "lint": command(["$python", "-c", "print('lint ok')"]),
                "cargo-tests": command(["cargo", "nextest", "run"], heavy=True, heavy_tests=True),
                "commit": {"kind": "commit", "sandbox": "none", "timeout_seconds": 60}}}), encoding="utf-8")
        self.run = tmp_path / "run"
        self.codex_home = self.run / "codex-home"
        self.config_path = tmp_path / "team-run.json"
        self.log = tmp_path / "fake-team.log"
        self.host_log = tmp_path / "fake-host.log"
        self.plan_path = tmp_path / "fake-host-plan.json"
        self.plan_path.write_text("{}", encoding="utf-8")
        self.config = {
            "schema": "aegis.team-run/v1", "run": str(self.run), "source": str(self.source), "project": str(self.project),
            "base": self.base, "branch": BRANCH,
            "initiative": {"id": "pilot", "project": "aegis", "repository": "aegis", "priority": 5,
                           "target_branch": "develop"},
            "roles": ["router", "decider"],
            "lanes": [{"id": "f2", "kind": "implementer", "paths": ["src/**", "tests/**"], "tmpdir": "target/aegis-tmp"},
                      {"id": "review", "kind": "reviewer"}],
            "recipes": {"keep": ["targeted-tests", "lint", "cargo-tests", "commit"], "python": sys.executable,
                        "commit_identity": {"name": "Aegis Pilot Implementer", "email": "pilot@localhost"},
                        "template": str(self.template)},
            "limits": {"writer_limit": 3, "heavy_limit": 3, "heavy_tests_limit": 1},
            "preflight": {"recipes": ["targeted-tests", "lint"],
                          "expect": {"targeted-tests": {"state": "completed", "failed": 0, "min_passed": 1},
                                     "lint": {"state": "completed"}},
                          "paths": {"targeted-tests": ["tests/test_app.py"]}},
            "min_free_gb": 1, "loop": {"interval": 5}, "team": json.loads(json.dumps(TEAM_SETTINGS))}
        self.save()

    def make_source(self):
        source = self.tmp / "source"
        (source / "tools").mkdir(parents=True)
        for path in (ROOT / "tools").glob("hierarchy_*.py"):
            shutil.copy(path, source / "tools" / path.name)
        shutil.copytree(ROOT / "tools" / "hierarchy_templates", source / "tools" / "hierarchy_templates")
        git(source, "init", "-q", "-b", "develop")
        git(source, "add", ".")
        git(source, "commit", "-qm", "pinned source")
        return source

    def make_project(self):
        project = self.tmp / "project"
        for path, body in {".gitignore": "target/\n", "src/app.py": "value = 1\n",
                           "tests/test_app.py": "def test_app():\n    assert True\n"}.items():
            (project / path).parent.mkdir(parents=True, exist_ok=True)
            (project / path).write_text(body, encoding="utf-8")
        git(project, "init", "-q", "-b", "develop")
        git(project, "add", ".")
        git(project, "commit", "-qm", "base")
        return project

    def save(self):
        self.config_path.write_text(json.dumps(self.config, indent=1), encoding="utf-8")

    @property
    def base_dir(self):
        return self.run / "initiatives" / "pilot"

    @property
    def evidence(self):
        return self.run / "evidence"

    def env(self, **extra):
        return {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "FAKE_CODEX_ROLLOUT": "1", "FAKE_TEAM_LOG": str(self.log),
                "FAKE_HOST_LOG": str(self.host_log), "FAKE_HOST_PLAN": str(self.plan_path),
                "CLAUDE_CONFIG_DIR": str(self.tmp / "claude-home"), **extra}

    def team(self, *words, expect=0, stderr="", **extra):
        proc = subprocess.run([sys.executable, "-I", "-B", str(TEAM), "--config", str(self.config_path), *words],
                              capture_output=True, text=True, timeout=600, env=self.env(**extra))
        assert proc.returncode == expect, proc.stdout[-6000:] + proc.stderr[-3000:]
        assert proc.stderr == stderr, proc.stderr
        return json.loads(proc.stdout.splitlines()[-1])

    def calls(self, kind):
        return [row for row in map(json.loads, self.log.read_text().splitlines()) if row["kind"] == kind] \
            if self.log.exists() else []

    def journal(self):
        sys.path.insert(0, str(ROOT / "tools"))
        import hierarchy_lifecycle
        return hierarchy_lifecycle.Lifecycle(self.run / "lifecycle").status()

    def mailbox(self):
        sys.path.insert(0, str(ROOT / "tools"))
        from hierarchy_mailbox import Mailbox
        return Mailbox(self.base_dir / "mailbox")

    def leases(self):
        proc = subprocess.run([sys.executable, "-B", "-m", "aegis_cli", "team", "list", "--workspace", str(self.project),
                               "--json"], cwd=ROOT, capture_output=True, text=True, timeout=60,
                              env={**os.environ, "PYTHONPATH": str(ROOT)})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return {lease["lane"]: lease for lease in json.loads(proc.stdout)["leases"]}

    def workspace(self, *words):
        proc = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "tools" / "hierarchy_workspace.py"), "--store",
                               str(self.run / "store"), *words], capture_output=True, text=True, timeout=60,
                              env=self.env())
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return json.loads(proc.stdout)

    def request(self, identifier="feature-1", **changes):
        value = {"id": identifier, "version": 1, "team": "pilot", "owner": "pilot/orchestrator",
                 "next_decision": "implement the feature", "phase": "implementation", "operation": "feature",
                 "source": {"commit": self.base, "tree": git(self.project, "rev-parse", "HEAD^{tree}"),
                            "dirty_sha256": EMPTY},
                 "paths": [str(self.run / "worktrees" / "f2" / "src")], "prerequisites": [], "authority": identifier,
                 "continuation": {"members": [], "max_starts": 1, "expires_at": "2099-01-01T00:00:00Z"}}
        value.update(changes)
        return value

    def write(self, name, value):
        path = self.tmp / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def ready(self, *up_flags):
        """init, root and up: the state every later subcommand starts from."""
        self.team("init")
        self.team("root", "--session", "root-session")
        return self.team("up", *up_flags)


@pytest.fixture
def run(tmp_path, monkeypatch):
    built = Run(tmp_path, monkeypatch)
    yield built
    # A loop left by a failed test would keep running against a deleted folder.
    pid_file = built.run / "loop.pid"
    if pid_file.exists():
        try:
            os.kill(int(pid_file.read_text().strip()), signal.SIGKILL)
        except (ValueError, ProcessLookupError):
            pass


def in_process(run, *words, capsys):
    """main() in this process, so a test can replace a boundary (shutil.disk_usage) the way a child cannot."""
    sys.path.insert(0, str(ROOT / "tools"))
    import hierarchy_team
    capsys.readouterr()
    code = hierarchy_team.main(["--config", str(run.config_path), *words])
    out = capsys.readouterr().out
    return code, json.loads(out.splitlines()[-1])


# -- config and the guard ----------------------------------------------------------------------------------------------

def test_the_shipped_template_is_refused_until_its_placeholders_are_filled(run, capsys):
    run.config_path.write_text(TEMPLATE.read_text(encoding="utf-8"), encoding="utf-8")
    code, answer = in_process(run, "status", capsys=capsys)
    assert code == 2
    assert answer["error"] == "team-run.json holds a placeholder at run: /REPLACE/WITH/an/empty/run/folder"
    template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    assert template["team"] == TEAM_SETTINGS, "cost choice 6: coordination roles lower effort, same model"


@pytest.mark.parametrize("change,error", [
    (lambda c: c["lanes"][0].update(paths=["<the paths>"]),
     "team-run.json holds a placeholder at lanes[0].paths[0]: <the paths>"),
    (lambda c: c.update(extra=1), "unexpected fields: extra"),
    (lambda c: c["lanes"].append({"id": "f3", "kind": "integrator"}), "lanes[2]: kind must be implementer or reviewer"),
    (lambda c: c["preflight"]["recipes"].append("full-suite"),
     "preflight recipe full-suite is not in recipes.keep"),
    (lambda c: c["team"]["reasoning_by_kind"].update(router="low"),
     "team.reasoning_by_kind: router is not a team role kind (decider, implementer, integrator, orchestrator, reviewer)"),
])
def test_a_config_outside_the_schema_is_refused(run, capsys, change, error):
    change(run.config)
    run.save()
    assert in_process(run, "status", capsys=capsys) == (2, {"error": error})


@pytest.mark.parametrize("where", ["exact", "inside", "symlink"])
def test_codex_home_in_the_owners_codex_folder_is_refused_by_every_subcommand(run, capsys, where):
    owner = run.home / ".codex"
    owner.mkdir()
    if where == "exact":
        home = owner
    elif where == "inside":
        home = owner / "team"
    else:
        home = run.tmp / "alias"
        home.symlink_to(owner)
    run.config["codex_home"] = str(home)
    run.save()
    for words in (("init",), ("status",), ("login",), ("down",)):
        code, answer = in_process(run, *words, capsys=capsys)
        assert code == 2
        assert answer["error"] == "CODEX_HOME %s is inside ~/.codex (%s); a team run uses its own folder" % (home, owner)
    assert not run.run.exists(), "nothing was written"


def test_a_shell_codex_home_other_than_the_runs_is_refused(run, capsys):
    run.monkeypatch.setenv("CODEX_HOME", str(run.tmp / "elsewhere"))
    code, answer = in_process(run, "status", capsys=capsys)
    assert code == 2
    assert answer["error"] == ("CODEX_HOME in this shell is %s, not this run's codex_home %s; unset it or export the "
                               "run's" % (run.tmp / "elsewhere", run.codex_home))


def test_low_disk_is_refused(run, capsys):
    run.config["min_free_gb"] = 8
    run.save()
    seen = []

    def disk_usage(path):
        seen.append(path)
        return shutil._ntuple_diskusage(100 * 2 ** 30, 98 * 2 ** 30, 2 * 2 ** 30)

    run.monkeypatch.setattr(shutil, "disk_usage", disk_usage)
    code, answer = in_process(run, "init", capsys=capsys)
    assert code == 2
    # The run folder does not exist yet, so the nearest existing folder above it is measured.
    assert answer["error"] == "only 2.0 GB free at %s; this run needs min_free_gb 8" % run.tmp
    assert seen == [str(run.tmp)] and not run.run.exists()


@pytest.mark.parametrize("missing,error", [
    ("bwrap", "required tool not found on PATH: bwrap"),
    ("codex", "required tool not found on PATH: codex"),
    ("cargo-nextest", "required tool not found on the recipes' path: cargo-nextest (kept recipe cargo-tests runs "
                      "cargo nextest)"),
])
def test_a_missing_tool_is_refused(run, capsys, missing, error):
    if missing == "cargo-nextest":
        (run.cargo / "cargo-nextest").unlink()
    else:
        (run.bin / missing).unlink()
    code, answer = in_process(run, "init", capsys=capsys)
    assert (code, answer) == (2, {"error": error})
    assert not run.run.exists()


def test_cargo_nextest_is_needed_only_when_a_kept_recipe_runs_it(run, capsys):
    (run.cargo / "cargo-nextest").unlink()
    run.config["recipes"]["keep"].remove("cargo-tests")
    run.save()
    code, answer = in_process(run, "status", capsys=capsys)
    assert code == 0, answer
    assert answer["init"] == {"complete": False, "next_step": "codex-home"}


# -- init ---------------------------------------------------------------------------------------------------------------

def test_init_runs_every_setup_step_and_indexes_each_output(run):
    answer = run.team("init")

    assert answer["init"] == "complete"
    assert answer["ran"] == ["codex-home", "recipes", "workspace", "provision", "front-door", "policy", "lifecycle",
                             "slots", "worktrees", "leases", "checkouts", "preflight"]
    index = json.loads((run.evidence / "index.json").read_text())
    assert {"recipes-check.json", "workspace-init.json", "provision-init.json", "front-door.json", "policy.json",
            "lifecycle-init.json", "checkpoint-before.json", "slot-request-f2.json", "slot-grant-f2.json",
            "worktree-f2.json", "lease-claim-f2.json", "checkouts.json", "preflight-run-open.json",
            "preflight-results.json", "owner-authority.txt"} <= set(index["files"])
    for name, row in index["files"].items():
        assert sha(run.evidence / name) == row["sha256"], name

    recipes = json.loads((run.run / "recipes.json").read_text())
    assert sorted(recipes["recipes"]) == ["cargo-tests", "commit", "lint", "targeted-tests"]
    assert recipes["python"] == sys.executable and recipes["path"][0] == str(run.cargo)
    assert recipes["identity"] == {"name": "Aegis Pilot Implementer", "email": "pilot@localhost"}
    assert "REPLACE" not in json.dumps(recipes)
    check = json.loads((run.evidence / "recipes-check.json").read_text())
    assert check["recipes_sha256"] == sha(run.run / "recipes.json")

    assert json.loads((run.codex_home / ".aegis-team-run").read_text())["run"] == str(run.run)
    assert stat.S_IMODE(run.codex_home.stat().st_mode) == 0o700
    status = run.mailbox().status()
    assert status["bindings"]["pilot/front-door"]["host"] == "claude-code"
    assert status["bindings"]["pilot/root"] is None, "ROOT is bound by `root`, after init"
    assert run.journal()["current"] == {"root": "root-1", "router": "router-1", "coordinator": "coordinator-1",
                                        "operator": "operator-1", "reviewer": "reviewer-1", "decider": "decider-1"}
    policy = json.loads((run.run / "policy.json").read_text())
    assert policy["source"]["commit"] == git(run.source, "rev-parse", "HEAD")
    assert policy["actors"]["router-1"]["profile"]["effort"] == "medium"

    worktree = run.run / "worktrees" / "f2"
    assert git(worktree, "branch", "--show-current") == BRANCH and git(worktree, "rev-parse", "HEAD") == run.base
    assert (worktree / "target" / "aegis-tmp").is_dir()
    lease = run.leases()["pilot-f2"]
    assert (lease["paths"], lease["owner"], lease["role"], lease["branch"]) == (
        ["src/**", "tests/**"], IMPLEMENTER, "implementer", BRANCH)
    assert json.loads((run.evidence / "lease-claim-f2.json").read_text())["oid"] == lease["oid"]
    initiative = run.workspace("status")["initiatives"]["pilot"]
    assert initiative["checkouts"] == [str(run.project), str(worktree)] and initiative["lanes"] == ["pilot-f2"]
    grant = json.loads((run.evidence / "slot-grant-f2.json").read_text())["granted"]
    assert (grant["holder"], grant["kind"], grant["state"]) == (IMPLEMENTER, "writer", "granted")

    [row] = [r for r in json.loads((run.evidence / "preflight-results.json").read_text())["results"]
             if r["recipe"] == "targeted-tests"]
    assert row["state"] == "completed" and row["tests"]["passed"] == 1 and row["tests"]["failed"] == 0
    assert row["recipes_sha256"] == check["recipes_sha256"] and row["met"] is True
    assert not (run.run / "preflight" / "store" / "jobs" / "pilotpre" / "pre-1-targeted-tests" / "scratch").exists()


def test_init_rerun_is_refused_and_a_failed_init_continues_from_its_first_incomplete_step(run):
    run.config["preflight"]["expect"]["targeted-tests"]["min_passed"] = 5
    run.save()
    failed = run.team("init", expect=3)
    assert failed["error"] == "preflight targeted-tests: expected at least 5 passed, the job reported 1"
    assert failed["step"] == "preflight"
    before = json.loads((run.evidence / "index.json").read_text())["files"]

    refused = run.team("init", expect=2)
    assert refused["error"] == ("init stopped at preflight: preflight targeted-tests: expected at least 5 passed, the "
                                "job reported 1; fix the cause, then run init --continue")

    run.config["preflight"]["expect"]["targeted-tests"]["min_passed"] = 1
    run.save()
    resumed = run.team("init", "--continue")
    assert resumed["ran"] == ["preflight"] and resumed["init"] == "complete"
    after = json.loads((run.evidence / "index.json").read_text())["files"]
    for name in ("lease-claim-f2.json", "slot-grant-f2.json", "provision-init.json"):
        assert after[name] == before[name], "an earlier step did not run again: " + name

    again = run.team("init", expect=2)
    assert again["error"].startswith("init already completed at ")
    assert run.team("init", "--continue", expect=2)["error"] == again["error"]


def test_init_continue_without_a_started_init_is_refused(run):
    assert run.team("init", "--continue", expect=2)["error"] == "nothing to continue: init has not run in " + str(run.run)


@pytest.mark.parametrize("case", ["live", "head", "dirty", "branch", "tree", "busy-run"])
def test_init_refuses_a_project_or_run_folder_it_must_not_use(run, case):
    if case == "live":
        run.config["live_checkouts"] = [str(run.project)]
        error = "project is the owner's live checkout %s; use a fresh clone" % run.project
    elif case == "head":
        (run.project / "src" / "app.py").write_text("value = 2\n")
        git(run.project, "commit", "-qam", "moved")
        error = "project HEAD is %s, not the configured base %s" % (git(run.project, "rev-parse", "HEAD"), run.base)
    elif case == "dirty":
        (run.project / "src" / "app.py").write_text("value = 3\n")
        error = "project has uncommitted changes; a run starts from a clean clone"
    elif case == "branch":
        git(run.project, "branch", BRANCH)
        error = "branch %s already exists in the project" % BRANCH
    elif case == "tree":
        run.config["base_tree"] = "f" * 40
        error = "base tree is %s, not the configured base_tree %s" % (git(run.project, "rev-parse", "HEAD^{tree}"),
                                                                     "f" * 40)
    else:
        (run.run / "store").mkdir(parents=True)
        error = "run folder already holds store; init needs a fresh run folder"
    run.save()
    assert run.team("init", expect=2) == {"error": error}
    assert not (run.run / "team-state.json").exists()


# -- login and root ----------------------------------------------------------------------------------------------------

def test_login_runs_codex_login_in_the_runs_codex_home_and_checks_the_folder(run):
    run.team("init")
    answer = run.team("login")
    [call] = run.calls("login")
    assert call["argv"] == ["login"] and call["codex_home"] == str(run.codex_home)
    assert answer["auth_sha256"] == sha(run.codex_home / "auth.json")
    assert answer["entries"] == [".aegis-team-run", "auth.json", "log"]


@pytest.mark.parametrize("mode,error", [
    ("extra", "CODEX_HOME holds entries a codex login does not create: config.toml"),
    ("loose", "auth.json in CODEX_HOME is readable by group or others (mode 0644): %s"),
    ("fail", "codex login exited 5"),
])
def test_login_refuses_a_folder_a_real_login_would_not_leave(run, mode, error):
    run.team("init")
    expect = 3 if mode == "fail" else 2
    # codex login runs in the owner's terminal, so what it prints is not captured.
    answer = run.team("login", expect=expect, stderr="login failed\n" if mode == "fail" else "", FAKE_TEAM_LOGIN=mode)
    assert answer["error"] == (error % (run.codex_home / "auth.json") if "%s" in error else error)


def test_login_refuses_an_api_key_in_the_environment(run):
    run.team("init")
    answer = run.team("login", expect=2, OPENAI_API_KEY="sk-fixture")
    assert answer["error"] == ("unset OPENAI_API_KEY and CODEX_API_KEY: codex could bill this run to the key instead "
                               "of the run's login (set: OPENAI_API_KEY)")
    assert run.calls("login") == []


def test_root_binds_the_owners_session_with_its_read_tools(run):
    run.team("init")
    answer = run.team("root", "--session", "root-session")

    assert (answer["endpoint"], answer["session"], answer["generation"]) == ("pilot/root", "root-session", 1)
    assert answer["tools"] == ["root_decide", "team_status", "team_pending", "team_request"]
    server = json.loads(Path(answer["connection"]).read_text())["mcpServers"]["aegis_decision"]
    args = server["args"]
    assert args[args.index("--loop-state") + 1] == str(run.run / "loop")
    assert args[args.index("--evidence") + 1] == str(run.evidence)
    assert args[args.index("--actor") + 1] == "root-1"
    assert run.mailbox().status()["bindings"]["pilot/root"]["session"] == "root-session"
    assert run.team("root", "--session", "root-session")["session"] == "root-session", "the same session again is a no-op"
    other = run.team("root", "--session", "other-session", expect=2)
    assert other["error"] == "endpoint is bound to another session; hand it off first"


def test_commands_after_init_refuse_before_init(run):
    for words in (("root", "--session", "s"), ("up",), ("approve", "x", "--reason", "r"), ("turn", IMPLEMENTER, "hi"),
                  ("request", "x", "--file", str(run.tmp / "none.json"))):
        assert run.team(*words, expect=2) == {"error": "init has not completed; run init first"}, words


# -- up -----------------------------------------------------------------------------------------------------------------

def test_up_writes_team_json_starts_each_role_checks_its_rollout_and_starts_the_loop(run):
    run.team("init")
    run.team("root", "--session", "root-session")
    answer = run.team("up")

    assert json.loads((run.base_dir / "team.json").read_text()) == TEAM_SETTINGS
    assert [row["endpoint"] for row in answer["roles"]] == ROLE_ORDER
    served = {row["endpoint"]: (row["model"], row["effort"]) for row in answer["roles"]}
    assert served == {"pilot/router": ("gpt-6.1-sol", "medium"), "pilot/orchestrator": ("gpt-6.1-sol", "medium"),
                      "pilot/decider": ("gpt-6.1-sol", "medium"), REVIEWER: ("gpt-6.1-sol", "high"),
                      IMPLEMENTER: ("gpt-6.1-sol", "high")}
    assert all(row["state"] == "bound" and row["agent_tools"] == [] for row in answer["roles"])
    tiers = {row["endpoint"]: (row["tier"], row["tier_asked"]) for row in answer["roles"]}
    assert tiers == {e: ("ultrafast", "ultrafast") if e == "pilot/router" else ("default", "default")
                     for e in ROLE_ORDER}, "reported, not checked: whether a tier is served is the probe's question"
    assert answer["router"] == ("the Router runs at effort medium and tier ultrafast from the role registry; team.json "
                                "cannot change it")
    status = json.loads(subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "hierarchy_launcher.py"), "--base",
                                        str(run.base_dir), "status"], capture_output=True, text=True,
                                       env=run.env()).stdout)["endpoints"]
    starts = sorted((status[e]["last"]["at"], e) for e in ROLE_ORDER)
    assert [e for _, e in starts] == ROLE_ORDER, "router, orchestrator, decider, reviewer lanes, then implementers"
    assert status[IMPLEMENTER]["last"]["cwd"] == str(run.run / "worktrees" / "f2")

    loop = answer["loop"]
    pid = int((run.run / "loop.pid").read_text())
    assert loop["pid"] == pid and Path("/proc/%d" % pid).exists()
    environ = dict(line.split("=", 1) for line in
                   Path("/proc/%d/environ" % pid).read_bytes().decode().split("\0") if "=" in line)
    assert environ["CODEX_HOME"] == str(run.codex_home)
    assert environ["PATH"].split(os.pathsep)[0] == str(run.cargo), "a kept recipe runs cargo"
    assert (run.evidence / "loop-environ.txt").read_text() == "CODEX_HOME=%s\nPATH=%s\n" % (
        run.codex_home, environ["PATH"])

    again = run.team("up", expect=2)
    assert again["error"] == "a loop for this run is already running (pid %d); run down first" % pid
    down = run.team("down")
    assert down["loop"]["state"] == "stopped" and not Path("/proc/%d" % pid).exists()


def test_up_refuses_a_role_offered_sub_agent_tools_unless_accepted(run):
    run.team("init")
    refused = run.team("up", expect=2, FAKE_TEAM_AGENT_TOOLS="pilot/orchestrator")
    tools = ["collaboration.followup_task", "collaboration.interrupt_agent", "collaboration.list_agents",
             "collaboration.send_message", "collaboration.spawn_agent", "collaboration.wait_agent"]
    assert refused["error"] == ("pilot/orchestrator was offered sub-agent tools: %s; it was stopped. Pass "
                                "--accept-agent-tools to accept that, which is recorded in evidence" % ", ".join(tools))
    status = run.mailbox().status()["bindings"]
    assert status["pilot/decider"] is None, "up stops at the first refusal"
    records = sorted((run.base_dir / "launches" / "pilot%2Forchestrator").glob("*.json"))
    assert [json.loads(p.read_text())["action"] for p in records] == ["start", "stop"]
    assert not (run.run / "loop.pid").exists()

    accepted = run.team("up", "--accept-agent-tools", "--no-loop")
    rows = {row["endpoint"]: row for row in accepted["roles"]}
    assert rows["pilot/orchestrator"]["state"] == "already_bound" and rows["pilot/orchestrator"]["agent_tools"] == tools
    assert rows["pilot/decider"]["state"] == "bound"
    record = json.loads((run.evidence / "up-agent-tools-accepted.json").read_text())
    assert record["roles"] == {"pilot/orchestrator": tools}
    assert accepted["loop"] == {"state": "not_started", "reason": "--no-loop"}


@pytest.mark.parametrize("variable,value,error", [
    ("FAKE_TEAM_SERVED_MODEL", "gpt-other", "pilot/router was served model gpt-other, but team.json asks for "
                                            "gpt-6.1-sol"),
    ("FAKE_TEAM_SERVED_EFFORT", "low", "pilot/router was served effort low, but the role registry asks for medium"),
])
def test_up_refuses_a_served_model_or_effort_other_than_asked(run, variable, value, error):
    run.team("init")
    refused = run.team("up", expect=2, **{variable: value})
    assert refused["error"] == error
    assert run.mailbox().status()["bindings"]["pilot/orchestrator"] is None
    assert not (run.run / "loop.pid").exists()


# -- request, approve, turn, status ------------------------------------------------------------------------------------

def test_request_publishes_bare_fields_or_a_team_request_draft_as_the_coordinator(run):
    run.ready("--no-loop")
    bare = run.team("request", "feature-1", "--file", str(run.write("bare.json", run.request())))
    row = run.journal()["requests"]["feature-1"]
    assert bare == {"request_id": "feature-1", "sha256": row["raw"]["sha256"], "published": True,
                    "event": str(run.run / "events" / "publish-feature-1.json")}
    assert row["publisher"] == "coordinator-1"
    assert (run.run / "requests" / "feature-1.json").read_text() == row["raw"]["raw"]

    sys.path.insert(0, str(ROOT / "tools"))
    import hierarchy_lifecycle
    import hierarchy_team_view
    draft = hierarchy_team_view.draft_request(hierarchy_lifecycle.Lifecycle(run.run / "lifecycle"),
                                              run.request("feature-2"))
    answer = run.team("request", "feature-2", "--file", str(run.write("draft.json", draft)))
    assert answer["sha256"] == draft["sha256"] == run.journal()["requests"]["feature-2"]["raw"]["sha256"]

    assert run.team("request", "feature-3", "--file", str(run.write("named.json", run.request("feature-4"))),
                    expect=2) == {"error": "the request file names feature-4, not feature-3"}
    tampered = {**draft, "raw": draft["raw"].replace("implement", "Implement")}
    assert run.team("request", "feature-2", "--file", str(run.write("bad.json", tampered)), expect=2) == {
        "error": "the draft's sha256 does not match its raw text"}
    changed = run.request("feature-1", next_decision="something else")
    assert run.team("request", "feature-1", "--file", str(run.write("changed.json", changed)), expect=2) == {
        "error": "event id conflicts with different bytes"}


def test_approve_runs_one_root_turn_and_checks_the_journal_for_the_decision(run):
    run.ready("--no-loop")
    published = run.team("request", "feature-1", "--file", str(run.write("bare.json", run.request())))
    answer = run.team("approve", "feature-1", "--reason", "agreed in chat")

    [call] = run.calls("root")
    root = run.team("status")["root"]
    expected = [word for pair in (("--disable", name) for name in DISABLED) for word in pair]
    assert call["argv"] == expected + [
        "exec", "--ignore-user-config", "--sandbox", "read-only", "-c", 'approval_policy="never"',
        "-c", root["mcp_config"], "--json", "-C", str(run.project), "resume", "root-session",
        'Call team_pending, find request feature-1, then call root_decide once with that row\'s root_decide arguments, '
        'decision=approve, reason="owner: agreed in chat". Do nothing else.']
    assert call["cwd"] == str(run.project) and call["codex_home"] == str(run.codex_home)
    assert answer == {"request_id": "feature-1", "decision": "approve", "request_sha256": published["sha256"],
                      "event_id": "root-feature-1-approve", "root_last_message": "Recorded."}
    [decision] = run.journal()["decisions"]
    assert (decision["request_id"], decision["request_sha256"], decision["decision"], decision["reason"]) == (
        "feature-1", published["sha256"], "approve", "owner: agreed in chat")
    lines = (run.evidence / "root-turns.jsonl").read_text().splitlines()
    assert json.loads(lines[0]) == {"type": "thread.started", "thread_id": "root-session"}
    assert json.loads((run.evidence / "index.json").read_text())["files"]["root-turns.jsonl"]["sha256"] == sha(
        run.evidence / "root-turns.jsonl")

    again = run.team("approve", "feature-1", "--reason", "twice", expect=2)
    assert again["error"] == "request feature-1 is not pending a ROOT decision (journal state: approved)"
    assert len(run.calls("root")) == 1, "a refused approve spends no turn"


def test_approve_detects_a_second_request_decided_in_the_same_turn(run):
    run.ready("--no-loop")
    for name in ("feature-1", "feature-2"):
        run.team("request", name, "--file", str(run.write(name + ".json", run.request(name))))
    answer = run.team("approve", "feature-1", "--reason", "one only", expect=3, FAKE_TEAM_ROOT="extra-decision")
    assert "unexpected journal decisions" in answer["error"]
    assert len(run.journal()["decisions"]) == 2, "reporting a failure must retain completed effects"


@pytest.mark.parametrize("folder", ["run", "home", "source", "project", "evidence", "unmarked"])
def test_init_refuses_unsafe_codex_home_without_claiming_it(run, folder):
    path = {"run": run.run, "home": run.home, "source": run.source, "project": run.project,
            "evidence": run.run / "evidence", "unmarked": run.tmp / "existing"}[folder]
    path.mkdir(parents=True, exist_ok=True)
    sentinel = path / "keep.txt"
    sentinel.write_text("keep")
    run.config["codex_home"] = str(path)
    run.save()
    answer = run.team("init", expect=2)
    assert "codex_home" in answer["error"]
    assert sentinel.read_text() == "keep"
    assert not (path / ".aegis-team-run").exists()


def test_status_and_down_remain_available_with_low_disk(run, capsys):
    run.team("init")
    run.config["min_free_gb"] = 10 ** 9
    run.save()
    assert in_process(run, "status", capsys=capsys)[0] == 0
    assert in_process(run, "down", capsys=capsys)[0] == 0


def test_purge_checks_the_ownership_record_not_just_its_presence(run):
    run.team("init")
    mark = run.codex_home / ".aegis-team-run"
    mark.write_text(json.dumps({"run": str(run.tmp / "other"), "initiative": "other"}))
    answer = run.team("down", "--purge-codex-home", expect=2)
    assert "ownership" in answer["error"]
    assert mark.exists()


def test_init_refuses_an_empty_preexisting_codex_home(run):
    run.codex_home.mkdir(parents=True)
    answer = run.team("init", expect=2)
    assert "already exists" in answer["error"]
    assert list(run.codex_home.iterdir()) == []


@pytest.mark.parametrize("catalog", ["missing", "unknown", "malformed"])
def test_up_refuses_missing_tool_catalog_even_when_agent_tools_are_accepted(run, catalog):
    run.team("init")
    run.team("login")
    run.team("root", "--session", "root-session")
    answer = run.team("up", "--no-loop", "--accept-agent-tools", expect=2, FAKE_TEAM_NO_CATALOG=catalog)
    assert "tool catalog is unavailable" in answer["error"]
    assert run.team("status")["roles"]["pilot/router"]["last"]["action"] == "stop"


def test_deny_can_revoke_a_previously_approved_request(run):
    run.ready("--no-loop")
    run.team("request", "feature-1", "--file", str(run.write("bare.json", run.request())))
    run.team("approve", "feature-1", "--reason", "approved")
    answer = run.team("approve", "feature-1", "--deny", "--reason", "revoked")
    assert answer["decision"] == "deny"
    assert [row["decision"] for row in run.journal()["decisions"]] == ["approve", "deny"]


def test_owner_turn_holds_the_wake_marker_until_its_process_finishes(run, capsys):
    run.ready("--no-loop")
    original = subprocess.run
    marker = run.mailbox().wake_marker(REVIEWER)
    seen = []
    def inspect(argv, **kwargs):
        if argv[0] == "codex":
            seen.append(marker.exists())
        return original(argv, **kwargs)
    run.monkeypatch.setattr(subprocess, "run", inspect)
    for key, value in run.env().items():
        run.monkeypatch.setenv(key, value)
    code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 0, answer
    assert seen == [True]
    assert not marker.exists()


def test_down_preserves_a_transferred_lease(run):
    run.team("init")
    old = run.leases()["pilot-f2"]["oid"]
    proc = subprocess.run([sys.executable, "-B", "-m", "aegis_cli", "team", "transfer", "pilot-f2",
                           "--workspace", str(run.project), "--expect", old, "--owner", "other-session", "--json"],
                          cwd=ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(ROOT)})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    answer = run.team("down", expect=3)
    assert "lease ownership changed" in answer["error"]
    assert run.leases()["pilot-f2"]["owner"] == "other-session"
    assert (run.run / "worktrees" / "f2").exists()


@pytest.mark.parametrize("mode", ["silent", "wrong-sha"])
def test_approve_fails_when_root_records_no_decision(run, mode):
    run.ready("--no-loop")
    published = run.team("request", "feature-1", "--file", str(run.write("bare.json", run.request())))
    answer = run.team("approve", "feature-1", "--deny", "--reason", "not now", expect=3, FAKE_TEAM_ROOT=mode)
    last = ("I could not find that request, so I decided nothing." if mode == "silent"
            else "root_decide refused: request sha256 mismatch")
    assert answer["error"] == "ROOT did not record deny on feature-1 (sha256 %s); its last message: %s" % (
        published["sha256"], last)
    assert answer["root_last_message"] == last
    assert run.journal()["decisions"] == []
    assert run.team("approve", "feature-1", "--reason", 'say "yes"', expect=2) == {
        "error": "the reason may not contain double quotes or line breaks"}


def test_turn_runs_the_roles_wake_argv_and_refuses_while_a_wake_runs_or_mail_is_unread(run):
    run.ready("--no-loop")
    mailbox = run.mailbox()
    marker = mailbox.wake_marker(REVIEWER)
    marker.write_text("fixture wake")
    assert run.team("turn", REVIEWER, "Check in.", expect=2) == {
        "error": "a wake is running for %s (%s); try again after it ends" % (REVIEWER, marker)}
    marker.unlink()
    binding = mailbox.status()["bindings"]["pilot/orchestrator"]
    note = run.write("note.json", {"message_id": "note", "from": "pilot/orchestrator", "to": REVIEWER,
                                   "host": binding["host"], "session": binding["session"],
                                   "binding_generation": binding["generation"], "type": "info", "body": "A note."})
    published = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "tools" / "hierarchy_mailbox.py"), "--root",
                                str(run.base_dir / "mailbox"), "publish", "--request", str(note)],
                               capture_output=True, text=True, timeout=60, env=run.env())
    assert published.returncode == 0, published.stdout + published.stderr
    assert run.team("turn", REVIEWER, "Check in.", expect=2) == {
        "error": "%s has 1 unread message; the loop's wake reads it, so an owner turn now would race it" % REVIEWER}
    assert run.team("turn", "pilot/root", "Hi.", expect=2) == {"error": "ROOT's turns go through approve"}

    answer = run.team("turn", "pilot/orchestrator", "Owner check: reply with your role.")
    profile = json.loads((run.base_dir / "profiles" / "pilot%2Forchestrator-g1.wake.json").read_text())
    [launch] = [json.loads(line) for line in run.host_log.read_text().splitlines()]
    assert launch["endpoint"] == "pilot/orchestrator"
    assert launch["argv"] == profile["argv"][1:] + ["Owner check: reply with your role."]
    assert answer["endpoint"] == "pilot/orchestrator" and answer["exit_code"] == 0
    assert answer["items"][-1] == {"type": "agent_message", "text": "DONE"}
    assert (run.evidence / "role-turns-pilot%2Forchestrator.jsonl").read_text().count("thread.started") == 1


def test_status_reads_the_team_view_the_loop_and_the_launcher(run):
    run.ready("--no-loop")
    run.team("request", "feature-1", "--file", str(run.write("bare.json", run.request())))
    answer = run.team("status")

    assert answer["init"] == {"complete": True, "next_step": None}
    assert answer["root"]["session"] == "root-session"
    assert answer["loop"] == {"state": "not_running", "pid": None, "pid_alive": False}
    assert answer["team"]["schema"] == "aegis.team-status/v1" and answer["team"]["pending"] == ["feature-1"]
    assert {e: row["binding"]["generation"] for e, row in answer["roles"].items()} == {e: 1 for e in ROLE_ORDER}
    text = subprocess.run([sys.executable, "-I", "-B", str(TEAM), "--config", str(run.config_path), "status", "--text"],
                          capture_output=True, text=True, timeout=60, env=run.env())
    assert text.returncode == 0, text.stdout + text.stderr
    assert "loop: not_running" in text.stdout
    assert ("pending ROOT decisions:\n  feature-1 (awaiting_decision): hierarchy_team.py --config %s approve feature-1 "
            "--reason TEXT" % run.config_path) in text.stdout


# -- down ---------------------------------------------------------------------------------------------------------------

def test_down_collects_evidence_releases_the_live_lease_cleans_up_and_is_idempotent(run):
    run.ready()
    old = run.leases()["pilot-f2"]["oid"]
    renewed = subprocess.run([sys.executable, "-B", "-m", "aegis_cli", "team", "renew", "pilot-f2", "--workspace",
                              str(run.project), "--expect", old, "--ttl", "7200", "--json"], cwd=ROOT,
                             capture_output=True, text=True, timeout=60, env={**os.environ, "PYTHONPATH": str(ROOT)})
    assert renewed.returncode == 0, renewed.stdout + renewed.stderr
    live = run.leases()["pilot-f2"]["oid"]
    assert live != old
    (run.run / "review-c2").mkdir()
    worktree = run.run / "worktrees" / "f2"

    answer = run.team("down")

    assert answer["loop"]["state"] == "stopped"
    assert {row["endpoint"]: row["state"] for row in answer["roles"]} == {e: "not_running" for e in ROLE_ORDER}
    assert answer["leases"] == [{"lane": "pilot-f2", "state": "released", "oid": live}]
    assert "pilot-f2" not in run.leases()
    assert answer["slots"] == [{"lane": "f2", "state": "released"}]
    assert answer["worktrees"] == [{"lane": "f2", "state": "removed", "path": str(worktree)}]
    assert not worktree.exists() and git(run.project, "branch", "--list", BRANCH).strip().endswith(BRANCH)
    assert answer["review_copies"] == [{"path": str(run.run / "review-c2"), "state": "kept: no review manifest"}]
    assert answer["codex_home"] == "kept"

    for name in ("checkpoint-after.json", "launcher-status-end.json", "router-end.json", "policy.json", "recipes.json",
                 "loop.log", "loop.pid", "turn-ledger.json"):
        assert (run.evidence / name).is_file(), name
    for folder in ("launches", "delivery", "loop", "requests", "events", "mailbox", "store-events", "codex-sessions"):
        assert (run.evidence / folder).is_dir(), folder
    sums = (run.evidence / "SHA256SUMS").read_text().splitlines()
    listed = {line.split("  ", 1)[1]: line.split("  ", 1)[0] for line in sums}
    files = {str(p.relative_to(run.evidence)) for p in run.evidence.rglob("*") if p.is_file() and p.name != "SHA256SUMS"}
    assert set(listed) == files
    assert all(sha(run.evidence / name) == digest for name, digest in listed.items())
    ledger = json.loads((run.evidence / "turn-ledger.json").read_text())
    assert ledger["schema"] == "aegis.team-turn-ledger/v1"
    assert sorted(row["endpoint"] for row in ledger["roles"]) == sorted(ROLE_ORDER)
    assert all(len(row["turns"]) == 1 for row in ledger["roles"]), "the start turn; nothing woke a role"
    assert ledger["total"]["turns"] == 5 and ledger["owner_actions"]["by_command"]["up"] == 1
    release = json.loads((run.evidence / "lease-release-f2.json").read_text())
    assert release["previous"] == live

    again = run.team("down")
    assert again["loop"]["state"] == "already_stopped"
    assert again["evidence"] == "already_collected"
    assert again["leases"] == [{"lane": "pilot-f2", "state": "already_released"}]
    assert again["slots"] == [{"lane": "f2", "state": "already_released"}]
    assert again["worktrees"] == [{"lane": "f2", "state": "already_removed", "path": str(worktree)}]


def test_purge_deletes_codex_home_only_after_verifying_the_session_copies(run):
    run.ready("--no-loop")
    run.team("down")
    [copy] = sorted((run.evidence / "codex-sessions").rglob("*.jsonl"))[:1]
    original = copy.read_bytes()
    copy.write_bytes(original + b"\n")
    relative = copy.relative_to(run.evidence / "codex-sessions")

    refused = run.team("down", "--purge-codex-home", expect=2)
    assert refused["error"] == ("codex_home was kept: the copy of sessions/%s in evidence/codex-sessions does not match "
                                "it" % relative)
    assert run.codex_home.is_dir()

    copy.write_bytes(original)
    (run.codex_home / "sessions" / "late.jsonl").write_text("{}\n")
    late = run.team("down", "--purge-codex-home", expect=2)
    assert late["error"] == "codex_home was kept: sessions/late.jsonl has no copy in evidence/codex-sessions"
    (run.codex_home / "sessions" / "late.jsonl").unlink()

    purged = run.team("down", "--purge-codex-home")
    assert purged["codex_home"] == "purged" and not run.codex_home.exists()
    assert run.team("down", "--purge-codex-home")["codex_home"] == "already_purged"


def test_down_refuses_to_go_on_while_the_loop_process_outlives_sigterm(run):
    run.ready("--no-loop")
    stubborn = subprocess.Popen([sys.executable, "-I", "-c", "import signal, time\nsignal.signal(signal.SIGTERM, "
                                 "signal.SIG_IGN)\ntime.sleep(60)", str(ROOT / "tools" / "hierarchy_loop.py"),
                                 "--lifecycle", str(run.run / "lifecycle")], env=run.env())
    try:
        (run.run / "loop.pid").write_text("%d\n" % stubborn.pid)
        time.sleep(0.3)
        answer = run.team("down", "--loop-wait", "1", expect=3)
        assert answer["error"] == ("the loop (pid %d) did not stop within 1 s after SIGTERM; a step may still be "
                                   "running. Run down again once it has stopped" % stubborn.pid)
        assert "pilot-f2" in run.leases(), "nothing was released"
        assert stubborn.poll() is None
    finally:
        stubborn.kill()
        stubborn.wait()
        (run.run / "loop.pid").unlink()
    assert run.team("down")["loop"]["state"] == "already_stopped"


def test_down_never_signals_a_pid_that_is_not_this_runs_loop(run):
    run.ready("--no-loop")
    other = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(60)"], env=run.env())
    try:
        (run.run / "loop.pid").write_text("%d\n" % other.pid)
        answer = run.team("down")
        assert answer["loop"] == {"state": "already_stopped", "note": "pid %d is not this run's loop" % other.pid}
        assert other.poll() is None, "the unrelated process was left alone"
    finally:
        other.kill()
        other.wait()
