"""hierarchy_team.py's per-host homes, login, billing guard and loop environment (T2(a) PR 5), on fixtures.

These reuse test_hierarchy_team.py's harness: a sealed PATH of fakes only and a temporary HOME, with the fake `claude`
(hierarchy_fake_claude.py) installed beside the fake codex for a plan that uses claude-code. The real ~/.claude is never
touched: the refusals that need an owner folder replace the password database and HOME in this process.

`root` and `up` refuse a Claude plan until T2(a) PR 6, so no `up` can start the loop for one. The loop's environment is
checked by calling start_loop in this process after a real init (the same function `up` calls), then read back through
/proc, loop-environ.txt and `status`, and the loop is stopped with `down`.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import sys
import types

import pytest

from tests.integration.hierarchy_fake_claude import BILLING, HERE as FAKE_CLAUDE, install, require_fake
from tests.integration.test_hierarchy_mailbox import ROOT
from tests.integration.test_hierarchy_team import ROLE_ORDER, Run, in_process, sha


pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="the loop and run-open read /proc and the wake supports POSIX process groups only")
CLAUDE, CODEX = "claude-code", "codex-cli"
V2 = "aegis.team-run/v2"
MARK = ".aegis-team-run"
INIT_RAN = ["codex-home", "recipes", "workspace", "provision", "front-door", "policy", "lifecycle", "slots", "worktrees",
            "leases", "checkouts", "preflight"]
MANAGED_SETTINGS = Path("/etc/claude-code/managed-settings.json")
# The fake's account values: evidence must never hold them.
IDENTITY = (b"fake@example.invalid", b"fake-org-id", b"Fake Org (test fake)", b"fake-subscription")
NOT_TRUSTED = "claude auth status does not show this run's claude.ai login: "
# A `claude` that runs the test fake, then plays what a real login could leave behind: a credentials file looser than
# 0600, or a stored API key that the status call sees although the guard saw none in the owner's shell.
WRAPPER = r'''#!%(python)s
import os, subprocess, sys
argv = sys.argv[1:]
env = dict(os.environ)
if argv[:2] == ["auth", "status"] and os.environ.get("WRAP_STATUS_API_KEY"):
    env["ANTHROPIC_API_KEY"] = "sk-ant-fixture"
code = subprocess.call([sys.executable, %(fake)r, *argv], env=env)
if argv[:2] == ["auth", "login"] and os.environ.get("WRAP_LOOSE_CREDENTIALS"):
    os.chmod(os.path.join(os.environ["CLAUDE_CONFIG_DIR"], ".credentials.json"), 0o644)
sys.exit(code)
'''


class HomesRun(Run):
    """test_hierarchy_team's run on an aegis.team-run/v2 plan, with the fake claude on its sealed PATH and an owner
    shell that has no CLAUDE_CONFIG_DIR and no Claude billing variable unless a test sets one."""

    def __init__(self, tmp_path, monkeypatch, root, team):
        super().__init__(tmp_path, monkeypatch)
        install(self.bin)
        require_fake(str(self.bin))
        for name in BILLING + ("CLAUDE_CONFIG_DIR",):
            monkeypatch.delenv(name, raising=False)
        self.claude_home = self.run / "claude-home"
        self.claude_log = tmp_path / "fake-claude.log"
        self.config.update(schema=V2, hosts={"root": root, "team": team})
        if team == CLAUDE:
            # Provision makes tmpdir Codex-only, so init refuses one in a Claude team (ADR T2(a) section 1).
            del self.config["lanes"][0]["tmpdir"]
        self.save()

    def env(self, **extra):
        env = super().env(FAKE_CLAUDE_LOG=str(self.claude_log), **extra)
        if "CLAUDE_CONFIG_DIR" not in extra:
            del env["CLAUDE_CONFIG_DIR"]
        return env

    def claude_calls(self):
        if not self.claude_log.exists():
            return []
        return [json.loads(line) for line in self.claude_log.read_text().splitlines()]

    def wrap_claude(self):
        path = self.bin / "claude"
        path.write_text(WRAPPER % {"python": sys.executable, "fake": str(FAKE_CLAUDE)}, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        require_fake(str(self.bin))


@pytest.fixture
def make(tmp_path, monkeypatch):
    built = []

    def factory(root=CODEX, team=CLAUDE, v1=False):
        run = Run(tmp_path, monkeypatch) if v1 else HomesRun(tmp_path, monkeypatch, root, team)
        built.append(run)
        return run

    yield factory
    for run in built:
        # A loop left by a failed test would keep running against a deleted folder.
        pid_file = run.run / "loop.pid"
        if pid_file.exists():
            try:
                os.kill(int(pid_file.read_text().strip()), signal.SIGKILL)
            except (ValueError, ProcessLookupError):
                pass


def team_module():
    sys.path.insert(0, str(ROOT / "tools"))
    import hierarchy_team
    return hierarchy_team


def proc_environ(pid):
    raw = Path("/proc/%d/environ" % pid).read_bytes().decode("utf-8", "replace")
    return dict(item.split("=", 1) for item in raw.split("\0") if "=" in item)


def files(folder):
    """Every file under the run folder with its sha256, less the command log every command appends to."""
    return {str(path.relative_to(folder)): sha(path) for path in sorted(folder.rglob("*"))
            if path.is_file() and not path.is_symlink() and path.name != "team-commands.jsonl"}


def state(run):
    return json.loads((run.run / "team-state.json").read_text(encoding="utf-8"))


def assert_home(run, home):
    assert stat.S_IMODE(os.lstat(home).st_mode) == 0o700 and not home.is_symlink()
    mark = json.loads((home / MARK).read_text(encoding="utf-8"))
    assert set(mark) == {"run", "initiative", "created_at"}
    assert (mark["run"], mark["initiative"]) == (str(run.run), "pilot")


def assert_no_secrets(run, credentials_sha256):
    for path in run.evidence.rglob("*"):
        if path.is_file():
            raw = path.read_bytes()
            assert path.name != ".credentials.json" and sha(path) != credentials_sha256, path
            assert not any(value in raw for value in IDENTITY), path


# -- init and the homes ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("root,team", [(CODEX, CLAUDE), (CLAUDE, CLAUDE), (CLAUDE, CODEX)])
def test_init_makes_each_home_the_plan_uses_with_this_runs_mark(make, root, team):
    run = make(root, team)
    claude_only = CODEX not in (root, team)
    if claude_only:
        # A Claude-only plan needs no codex, and may name its claude_home anywhere safe.
        (run.bin / "codex").unlink()
        run.claude_home = run.tmp / "claude-run-home"
        run.config["claude_home"] = str(run.claude_home)
        run.save()

    answer = run.team("init")

    assert answer["init"] == "complete" and answer["ran"] == INIT_RAN
    assert_home(run, run.claude_home)
    detail = state(run)["init"]["steps"]["codex-home"]
    assert detail["claude_home"] == str(run.claude_home)
    if claude_only:
        assert not run.codex_home.exists() and set(detail) == {"at", "claude_home"}
    else:
        assert_home(run, run.codex_home)
        assert set(detail) == {"at", "codex_home", "claude_home"} and detail["codex_home"] == str(run.codex_home)
    plan = json.loads((run.base_dir / "host-plan.json").read_text(encoding="utf-8"))
    assert (plan["root"], plan["team"]) == (root, team)
    assert run.team("status")["init"] == {"complete": True, "next_step": None}
    if claude_only:
        run.config["claude_home"] = str(run.tmp / "another-home")
        run.save()
        assert run.team("login", expect=2) == {"error": "run custody changed since init; restore the recorded "
                                                        "configuration"}


def test_init_refuses_an_existing_claude_home(make):
    run = make()
    run.claude_home.mkdir(parents=True)
    assert run.team("init", expect=2) == {"error": "claude_home %s already exists; init needs a new folder"
                                                   % run.claude_home}
    assert list(run.claude_home.iterdir()) == [] and not (run.run / "team-state.json").exists()


def test_init_refuses_an_implementer_tmpdir_in_a_claude_team_and_writes_nothing(make):
    run = make(CODEX, CLAUDE)
    run.config["lanes"][0]["tmpdir"] = "target/aegis-tmp"
    run.save()
    assert run.team("init", expect=2) == {"error": "lane f2: tmpdir is only for a Codex writer, and this run's team host "
                                                   "is claude-code"}
    assert not run.run.exists()


@pytest.mark.parametrize("source", ["password database", "HOME"])
@pytest.mark.parametrize("where", ["exact", "inside", "symlink"])
def test_claude_home_in_the_owners_claude_folder_is_refused_by_every_subcommand(make, capsys, source, where):
    run = make()
    # The password database names a home other than the test's HOME, as a test HOME would hide the real one.
    real_home = run.tmp / "real-home"
    real_home.mkdir()
    import pwd
    run.monkeypatch.setattr(pwd, "getpwuid", lambda uid: types.SimpleNamespace(pw_dir=str(real_home)))
    owner = (real_home if source == "password database" else run.home) / ".claude"
    owner.mkdir()
    if where == "exact":
        home = owner
    elif where == "inside":
        home = owner / "team"
    else:
        home = run.tmp / "alias"
        home.symlink_to(owner)
    run.config["claude_home"] = str(home)
    run.save()
    for words in (("init",), ("status",), ("login",), ("down",)):
        assert in_process(run, *words, capsys=capsys) == (2, {
            "error": "CLAUDE_CONFIG_DIR %s is inside ~/.claude (%s); a team run uses its own folder" % (home, owner)})
    assert not run.run.exists() and list(owner.iterdir()) == []


def test_a_user_missing_from_the_password_database_is_refused(make, capsys):
    run = make()
    import pwd

    def missing(uid):
        raise KeyError("getpwuid(): uid not found: %d" % uid)

    run.monkeypatch.setattr(pwd, "getpwuid", missing)
    assert in_process(run, "status", capsys=capsys) == (2, {
        "error": "cannot find this user's home folder in the password database, so ~/.claude cannot be kept out"})


@pytest.mark.parametrize("case", ["codex-same", "codex-inside", "codex-around", "symlink", "run", "home", "project",
                                  "source", "evidence"])
def test_an_unsafe_claude_home_is_refused_before_anything_is_written(make, capsys, case):
    run = make()
    if case == "codex-same":
        home, error = run.codex_home, "it overlaps codex_home %s" % run.codex_home
    elif case == "codex-inside":
        home, error = run.codex_home / "claude", "it overlaps codex_home %s" % run.codex_home
    elif case == "codex-around":
        codex_home = run.run / "homes" / "codex"
        run.config["codex_home"] = str(codex_home)
        home, error = run.run / "homes", "it overlaps codex_home %s" % codex_home
    elif case == "symlink":
        (run.tmp / "target").mkdir()
        home = run.tmp / "alias"
        home.symlink_to(run.tmp / "target")
        error = "it is a symlink"
    elif case in ("run", "home"):
        home = run.run if case == "run" else run.home
        error = "it contains %s" % home
    else:
        home = {"project": run.project, "source": run.source, "evidence": run.run / "evidence"}[case]
        error = "it overlaps %s" % home.resolve()
    run.config["claude_home"] = str(home)
    run.save()
    assert in_process(run, "init", capsys=capsys) == (2, {"error": "unsafe claude_home: " + error})
    assert not run.run.exists() or case == "run"
    assert not (home / MARK).exists() and not run.codex_home.exists()


def test_a_v1_config_takes_no_claude_home(make, capsys):
    run = make(v1=True)
    run.config["claude_home"] = str(run.tmp / "claude-run-home")
    run.save()
    assert in_process(run, "status", capsys=capsys) == (2, {"error": "claude_home needs schema aegis.team-run/v2"})


# -- the guard ------------------------------------------------------------------------------------------------------------

def test_a_shell_claude_config_dir_other_than_the_runs_is_refused(make):
    run = make()
    elsewhere = run.tmp / "elsewhere"
    assert run.team("status", expect=2, CLAUDE_CONFIG_DIR=str(elsewhere)) == {
        "error": "CLAUDE_CONFIG_DIR in this shell is %s, not this run's claude_home %s; unset it or export the run's"
                 % (elsewhere, run.claude_home)}
    exported = run.team("status", CLAUDE_CONFIG_DIR=str(run.claude_home))
    assert exported["init"] == {"complete": False, "next_step": "codex-home"}


@pytest.mark.parametrize("words", [("login",), ("up",)])
@pytest.mark.parametrize("names", [("ANTHROPIC_API_KEY",), ("CLAUDE_CODE_OAUTH_TOKEN",),
                                   ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY")])
def test_a_command_that_spends_turns_refuses_claude_billing_variables(make, words, names):
    run = make()
    # Presence counts, even empty: an empty key can still change a CLI's credential precedence.
    answer = run.team(*words, expect=2, **{name: "" if index else "fixture" for index, name in enumerate(names)})
    assert answer == {"error": "unset %s: claude could bill this run to them instead of the run's login"
                               % ", ".join(sorted(names))}
    assert run.claude_calls() == [] and not run.run.exists()


@pytest.mark.parametrize("root,team,missing,error", [
    (CODEX, CLAUDE, "claude", "required tool not found on PATH: claude"),
    (CODEX, CLAUDE, "codex", "required tool not found on PATH: codex"),
    (CLAUDE, CLAUDE, "codex", None),
    (CODEX, CODEX, "claude", None),
])
def test_each_host_tool_is_required_only_by_a_plan_that_uses_it(make, root, team, missing, error):
    run = make(root, team)
    (run.bin / missing).unlink()
    # login passes the guard and then needs a completed init, so its refusal says which check stopped it.
    assert run.team("login", expect=2) == {"error": error or "init has not completed; run init first"}


# -- login ----------------------------------------------------------------------------------------------------------------

def test_login_logs_claude_in_to_the_runs_home_and_records_no_identity(make):
    run = make(CLAUDE, CLAUDE)
    run.team("init")

    answer = run.team("login")

    record = json.loads((run.evidence / "login-claude.json").read_text(encoding="utf-8"))
    assert answer == {"logins": {CLAUDE: record}}
    credentials = run.claude_home / ".credentials.json"
    assert record == {"claude_home": str(run.claude_home),
                      "auth": {"loggedIn": True, "authMethod": "claude.ai", "apiProvider": "firstParty",
                               "configDirectory": str(run.claude_home),
                               "projectsDirectory": str(run.claude_home / "projects"), "loginExpiresAt": None},
                      "credentials_sha256": sha(credentials),
                      "entries": [MARK, ".claude.json", ".credentials.json"],
                      "managed_settings": MANAGED_SETTINGS.exists()}
    assert [(call["argv"], call["config_dir"], call["billing"]) for call in run.claude_calls()] == [
        (["auth", "login"], str(run.claude_home), []), (["auth", "status", "--json"], str(run.claude_home), [])]
    index = json.loads((run.evidence / "index.json").read_text(encoding="utf-8"))["files"]
    assert index["login-claude.json"]["sha256"] == sha(run.evidence / "login-claude.json")
    assert stat.S_IMODE(credentials.stat().st_mode) == 0o600
    assert_no_secrets(run, sha(credentials))
    assert run.calls("login") == [] and not (run.evidence / "login.json").exists(), "no codex login in this plan"


def test_login_logs_in_each_host_the_plan_uses(make):
    run = make(CODEX, CLAUDE)
    run.team("init")

    answer = run.team("login")

    assert set(answer) == {"logins"} and set(answer["logins"]) == {CODEX, CLAUDE}
    codex = json.loads((run.evidence / "login.json").read_text(encoding="utf-8"))
    assert answer["logins"][CODEX] == codex == {"codex_home": str(run.codex_home),
                                                "auth_sha256": sha(run.codex_home / "auth.json"),
                                                "entries": [MARK, "auth.json", "log"]}
    assert answer["logins"][CLAUDE] == json.loads((run.evidence / "login-claude.json").read_text(encoding="utf-8"))
    [call] = run.calls("login")
    assert call["codex_home"] == str(run.codex_home)
    assert [call["config_dir"] for call in run.claude_calls()] == [str(run.claude_home)] * 2


def test_login_refuses_a_claude_login_the_run_cannot_trust(make):
    run = make(CLAUDE, CLAUDE)
    run.wrap_claude()
    run.team("init")
    credentials = run.claude_home / ".credentials.json"

    failed = run.team("login", expect=3, stderr="fake claude: login failed\n", FAKE_CLAUDE_LOGIN="fail")
    assert failed == {"error": "claude auth login exited 1"}
    assert not credentials.exists()

    elsewhere = run.tmp / "other-claude-home"
    answer = run.team("login", expect=2, FAKE_CLAUDE_STATUS_DIR=str(elsewhere))
    assert answer == {"error": NOT_TRUSTED + "config directory is not the run's claude home"}

    # A key the owner's shell does not hold, which the guard cannot see: the auth method still catches it.
    answer = run.team("login", expect=2, WRAP_STATUS_API_KEY="1")
    assert answer == {"error": NOT_TRUSTED + "auth method 'api_key' is not claude.ai"}
    assert run.claude_calls()[-1]["billing"] == ["ANTHROPIC_API_KEY"]

    answer = run.team("login", expect=2, WRAP_LOOSE_CREDENTIALS="1")
    assert answer == {"error": ".credentials.json in claude_home has mode 0644, not 0600: %s" % credentials}
    assert not (run.evidence / "login-claude.json").exists()

    assert run.team("login")["logins"][CLAUDE]["auth"]["authMethod"] == "claude.ai"


# -- child processes and the loop -----------------------------------------------------------------------------------------

def test_child_processes_and_the_loop_get_the_runs_claude_home(make):
    run = make(CODEX, CLAUDE)
    run.team("init")
    team = team_module()
    parsed = team.Run(str(run.config_path))
    env = team.child_env(parsed)
    assert (env["CLAUDE_CONFIG_DIR"], env["CODEX_HOME"]) == (str(run.claude_home), str(run.codex_home))

    # A loop whose CLAUDE_CONFIG_DIR is not the run's is stopped, not left running.
    working = team.child_env
    run.monkeypatch.setattr(team, "child_env", lambda *a, **k: {
        key: value for key, value in working(*a, **k).items() if key != "CLAUDE_CONFIG_DIR"})
    with pytest.raises(team.Stop) as stopped:
        team.start_loop(parsed)
    pid = int((run.run / "loop.pid").read_text())
    assert str(stopped.value) == "the loop (pid %d) was stopped: its CLAUDE_CONFIG_DIR is None, not %s" % (
        pid, run.claude_home)
    assert not team.process_alive(pid)
    # Only this patch: undo() would also drop the sealed PATH and HOME the harness set.
    run.monkeypatch.setattr(team, "child_env", working)

    loop = team.start_loop(parsed)

    environ = proc_environ(loop["pid"])
    assert (environ["CLAUDE_CONFIG_DIR"], environ["CODEX_HOME"]) == (str(run.claude_home), str(run.codex_home))
    assert (run.evidence / "loop-environ.txt").read_text() == "CODEX_HOME=%s\nCLAUDE_CONFIG_DIR=%s\nPATH=%s\n" % (
        run.codex_home, run.claude_home, environ["PATH"])
    status = run.team("status")
    assert status["loop"]["pid"] == loop["pid"] and status["loop"]["pid_alive"] is True
    down = run.team("down")
    assert down["loop"] == {"state": "stopped", "pid": loop["pid"]} and down["roles"] == []
    assert down["claude_home"] == "kept" and down["codex_home"] == "kept"


# -- root and up ----------------------------------------------------------------------------------------------------------

def test_root_refuses_a_claude_root_without_writing_and_up_still_starts_a_codex_team(make):
    run = make(CLAUDE, CODEX)
    run.team("init")
    before = files(run.run)

    answer = run.team("root", "--session", "root-session", expect=2)

    assert answer == {"error": "this team command binds a claude-code ROOT from T2(a) PR 6"}
    assert files(run.run) == before and run.mailbox().status()["bindings"]["pilot/root"] is None
    started = run.team("up", "--no-loop")
    assert [row["endpoint"] for row in started["roles"]] == ROLE_ORDER
    down = run.team("down")
    assert {row["endpoint"]: row["state"] for row in down["roles"]} == {e: "not_running" for e in ROLE_ORDER}


def test_up_refuses_a_claude_team_without_writing_and_root_binds_a_codex_root(make):
    run = make(CODEX, CLAUDE)
    run.team("init")
    assert run.team("root", "--session", "root-session")["endpoint"] == "pilot/root"
    before = files(run.run)

    for words in (("up",), ("up", "--no-loop")):
        assert run.team(*words, expect=2) == {"error": "this team command starts claude-code team roles from "
                                                       "T2(a) PR 6"}
    assert files(run.run) == before and not (run.base_dir / "team.json").exists()
    assert state(run)["up"] is None


# -- down -----------------------------------------------------------------------------------------------------------------

def test_down_purges_the_claude_home_only_with_this_runs_mark_and_copies_no_credentials(make):
    run = make(CLAUDE, CLAUDE)
    run.team("init")
    run.team("login")
    credentials = sha(run.claude_home / ".credentials.json")

    kept = run.team("down")
    assert kept["roles"] == [] and kept["claude_home"] == "kept" and "codex_home" not in kept

    mark = run.claude_home / MARK
    original = mark.read_bytes()
    mark.write_text(json.dumps({"run": str(run.tmp / "other"), "initiative": "other"}))
    assert run.team("down", "--purge-claude-home", expect=2) == {
        "error": "claude_home was kept: ownership record does not match this run"}
    mark.unlink()
    assert run.team("down", "--purge-claude-home", expect=2) == {
        "error": "claude_home was kept: it has no .aegis-team-run mark, so this run did not make it"}
    mark.write_bytes(original)
    transcript = run.claude_home / "projects" / "-tmp-project" / "session.jsonl"
    transcript.parent.mkdir(parents=True)
    transcript.write_text("{}\n")
    assert run.team("down", "--purge-claude-home", expect=2) == {
        "error": "claude_home was kept: projects/ holds transcripts, which down copies to evidence from T2(a) PR 6"}
    assert transcript.is_file()
    shutil.rmtree(run.claude_home / "projects")

    purged = run.team("down", "--purge-claude-home")
    assert purged["claude_home"] == "purged" and not run.claude_home.exists()
    assert run.team("down", "--purge-claude-home")["claude_home"] == "already_purged"
    assert_no_secrets(run, credentials)


# -- Codex-only runs ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("schema", ["v1", "v2"])
def test_a_codex_only_run_ignores_claude_and_writes_what_it_wrote_before(make, schema):
    run = make(v1=True)
    if schema == "v2":
        run.config.update(schema=V2, hosts={"root": CODEX, "team": CODEX})
        run.save()
    # No claude on PATH, every Claude billing variable set, and a CLAUDE_CONFIG_DIR that is not <run>/claude-home.
    for name in BILLING:
        run.monkeypatch.setenv(name, "fixture")
    elsewhere = str(run.tmp / "elsewhere")
    run.monkeypatch.setenv("CLAUDE_CONFIG_DIR", elsewhere)

    assert run.team("init", CLAUDE_CONFIG_DIR=elsewhere)["ran"] == INIT_RAN
    detail = state(run)["init"]["steps"]["codex-home"]
    assert set(detail) == {"at", "codex_home"} and detail["codex_home"] == str(run.codex_home)
    assert not (run.run / "claude-home").exists()

    login = run.team("login", CLAUDE_CONFIG_DIR=elsewhere)
    assert login == json.loads((run.evidence / "login.json").read_text(encoding="utf-8")) == {
        "codex_home": str(run.codex_home), "auth_sha256": sha(run.codex_home / "auth.json"),
        "entries": [MARK, "auth.json", "log"]}
    assert not (run.evidence / "login-claude.json").exists()

    team = team_module()
    parsed = team.Run(str(run.config_path))
    assert team.child_env(parsed)["CLAUDE_CONFIG_DIR"] == elsewhere, "left as the shell has it"
    loop = team.start_loop(parsed)
    environ = proc_environ(loop["pid"])
    assert environ["CLAUDE_CONFIG_DIR"] == elsewhere
    assert (run.evidence / "loop-environ.txt").read_text() == "CODEX_HOME=%s\nPATH=%s\n" % (run.codex_home,
                                                                                           environ["PATH"])
    down = run.team("down", CLAUDE_CONFIG_DIR=elsewhere)
    assert down["loop"]["state"] == "stopped" and down["codex_home"] == "kept" and "claude_home" not in down
