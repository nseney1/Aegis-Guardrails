"""hierarchy_team.py's per-host homes, login, billing guard and loop environment (T2(a) PR 5), on fixtures.

These reuse test_hierarchy_team.py's harness: a sealed PATH of fakes only and a temporary HOME, with the fake `claude`
(hierarchy_fake_claude.py) installed beside the fake codex for a plan that uses claude-code. The real ~/.claude is never
touched: the refusals that need an owner folder replace the password database and HOME in this process.

`root` and `up` refuse a Claude plan until T2(a) PR 6, so no `up` can start the loop for one. The loop's environment is
checked by calling start_loop in this process after a real init (the same function `up` calls), then read back through
/proc, loop-environ.txt and `status`, and the loop is stopped with `down`.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import select
import shutil
import signal
import stat
import subprocess
import sys
import types

import pytest

from tests.integration.hierarchy_fake_claude import BILLING, HERE as FAKE_CLAUDE, install, require_fake
from tests.integration.test_hierarchy_mailbox import ROOT
from tests.integration.test_hierarchy_team import FAKE_CONTROL_LOADER, ROLE_ORDER, TEAM, Run, in_process, sha


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
CLEANED = "; removed credentials written by this login"
# A `claude` that runs the test fake, then plays what a real login could leave behind: a credentials file looser than
# 0600, or a stored API key that the status call sees although the guard saw none in the owner's shell.
WRAPPER = r'''#!%(python)s
import json, os, select, subprocess, sys, time
from pathlib import Path
%(controls)s
argv = sys.argv[1:]
env = dict(os.environ)
home = Path(env["CLAUDE_CONFIG_DIR"])
credentials = home / ".credentials.json"
if argv[:2] == ["auth", "login"] and env.get("WRAP_GATE"):
    with open(env["WRAP_GATE"] + "-ready", "wb", buffering=0) as stream:
        stream.write(b"1")
    with open(env["WRAP_GATE"] + "-release", "rb", buffering=0) as stream:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not select.select([stream], [], [], 0.2)[0]:
            pass
        if time.monotonic() >= deadline or stream.read(1) != b"1":
            sys.exit(89)
if argv[:2] == ["auth", "login"] and env.get("WRAP_KEEP_CREDENTIALS"):
    sys.exit(0)
if argv[:2] == ["auth", "status"] and os.environ.get("WRAP_STATUS_API_KEY"):
    env["ANTHROPIC_API_KEY"] = "sk-ant-fixture"
if argv[:2] == ["auth", "status"] and env.get("WRAP_STATUS"):
    mode = env["WRAP_STATUS"]
    if mode == "timeout":
        time.sleep(0.5)
    proc = subprocess.run([sys.executable, %(fake)r, *argv], env=env, capture_output=True, text=True)
    answer = json.loads(proc.stdout)
    if mode == "method":
        answer["authMethod"] = "api_key"
    if mode == "nul":
        answer["configDirectory"] = "/fixture/\0"
    if mode == "unicode":
        sys.stdout.buffer.write(b"\xff")
        sys.exit(0)
    if mode == "replaced-credential":
        credentials.write_text("credential changed after login", encoding="utf-8")
    if mode == "rehome":
        alias = Path(env["WRAP_HOME_ALIAS"])
        alias.unlink()
        alias.symlink_to(env["WRAP_OWNER_HOME"])
    print("{" if mode == "malformed" else json.dumps(answer))
    sys.exit(7 if mode in ("exit", "replaced-credential") else proc.returncode)
code = subprocess.call([sys.executable, %(fake)r, *argv], env=env)
if argv[:2] == ["auth", "login"]:
    if env.get("WRAP_REMOVE_EXECUTABLE"):
        Path(sys.argv[0]).unlink()
    if env.get("WRAP_REHOME_AFTER_LOGIN"):
        alias = Path(env["WRAP_HOME_ALIAS"])
        alias.unlink()
        alias.symlink_to(env["WRAP_OWNER_HOME"])
    mode = env.get("WRAP_CREDENTIALS")
    if mode in ("missing", "symlink", "hard-link", "fifo"):
        credentials.unlink()
        if mode == "symlink":
            credentials.symlink_to(env["WRAP_TARGET"])
        elif mode == "hard-link":
            os.link(env["WRAP_TARGET"], credentials)
        elif mode == "fifo":
            os.mkfifo(credentials, 0o600)
    if mode in ("group-readable", "world-readable") or env.get("WRAP_LOOSE_CREDENTIALS"):
        credentials.chmod({"group-readable": 0o640, "world-readable": 0o604}.get(mode, 0o644))
sys.exit(code)
'''


class HomesRun(Run):
    """test_hierarchy_team's run on an aegis.team-run/v2 plan, with the fake claude on its sealed PATH and an owner
    shell that has no CLAUDE_CONFIG_DIR and no Claude billing variable unless a test sets one."""

    def __init__(self, tmp_path, monkeypatch, root, team):
        super().__init__(tmp_path, monkeypatch)
        install(self.bin)
        (self.bin / "claude").write_text(
            "#!%s\nimport json, os, runpy\nfrom pathlib import Path\n%s\nrunpy.run_path(%r, run_name='__main__')\n"
            % (sys.executable, FAKE_CONTROL_LOADER, str(FAKE_CLAUDE)), encoding="utf-8")
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
        path.write_text(WRAPPER % {"python": sys.executable, "fake": str(FAKE_CLAUDE),
                                  "controls": FAKE_CONTROL_LOADER}, encoding="utf-8")
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


def test_claude_only_init_refuses_an_existing_codex_home(make):
    run = make(CLAUDE, CLAUDE)
    run.codex_home.mkdir(parents=True)
    transcript = run.codex_home / "sessions" / "prior.jsonl"
    transcript.parent.mkdir()
    transcript.write_bytes(b"prior run\n")
    before = files(run.run)
    assert run.team("init", expect=2) == {
        "error": "codex_home %s already exists; init needs a new folder" % run.codex_home}
    assert files(run.run) == before and not run.claude_home.exists()


@pytest.mark.parametrize("root,team", [(CLAUDE, CLAUDE), (CLAUDE, CODEX), (CODEX, CLAUDE)])
@pytest.mark.parametrize("tree", [".claude", ".codex"])
@pytest.mark.parametrize("where", ["exact", "inside", "ancestor-alias", "owner-alias"])
def test_run_destination_in_either_owner_tree_is_refused_without_writes(make, root, team, tree, where):
    run = make(root, team)
    owner = run.home / tree
    owner.mkdir()
    (owner / "owner.txt").write_bytes(b"owner bytes\n")
    alias = run.tmp / "alias"
    alias.symlink_to(owner)
    if where == "owner-alias":
        backing = run.tmp / "owner-backing"
        owner.rename(backing)
        owner.symlink_to(backing)
        destination = backing / "run"
    else:
        destination = {"exact": alias, "inside": alias / "run", "ancestor-alias": alias / "new" / "run"}[where]
    run.config.update(run=str(destination), codex_home=str(run.tmp / "isolated-codex"),
                      claude_home=str(run.tmp / "isolated-claude"))
    run.save()
    before = files(owner)
    for words in (("init",), ("login",), ("down",), ("status",)):
        assert run.team(*words, expect=2) == {
            "error": "run folder %s is inside ~/%s (%s); a team run uses its own folder" %
                     (destination, tree, owner)}
    assert files(owner) == before and not (owner / "team-commands.jsonl").exists()
    assert not (run.tmp / "isolated-codex").exists() and not (run.tmp / "isolated-claude").exists()


@pytest.mark.parametrize("tree", [".claude", ".codex"])
def test_run_destination_checks_the_password_database_home(make, capsys, tree):
    run = make()
    import pwd
    password_home = run.tmp / "password-home"
    owner = password_home / tree
    owner.mkdir(parents=True)
    alias = run.tmp / "password-alias"
    alias.symlink_to(password_home)
    run.monkeypatch.setattr(pwd, "getpwuid", lambda uid: types.SimpleNamespace(pw_dir=str(alias)))
    run.config.update(run=str(owner / "run"), codex_home=str(run.tmp / "isolated-codex"),
                      claude_home=str(run.tmp / "isolated-claude"))
    run.save()
    assert in_process(run, "init", capsys=capsys) == (2, {
        "error": "run folder %s is inside ~/%s (%s); a team run uses its own folder" %
                 (owner / "run", tree, alias / tree)})
    assert list(owner.iterdir()) == []


def test_a_safe_symlink_ancestor_of_the_run_still_works(make):
    run = make(CLAUDE, CLAUDE)
    backing = run.tmp / "private-tmp"
    backing.mkdir()
    alias = run.tmp / "tmp-alias"
    alias.symlink_to(backing)
    run.run = alias / "run"
    run.claude_home = run.run / "claude-home"
    run.codex_home = run.run / "codex-home"
    run.config["run"] = str(run.run)
    run.save()
    assert run.team("init")["init"] == "complete"
    assert run.team("login")["logins"][CLAUDE]["credentials_sha256"] == sha(run.claude_home / ".credentials.json")
    assert run.team("down", "--purge-claude-home")["claude_home"] == "purged"


@pytest.mark.parametrize("source", ["HOME", "password database"])
@pytest.mark.parametrize("field,tree,variable", [("claude_home", ".codex", "CLAUDE_CONFIG_DIR"),
                                                ("codex_home", ".claude", "CODEX_HOME"),
                                                ("codex_home", ".codex", "CODEX_HOME")])
@pytest.mark.parametrize("where", ["exact", "inside", "alias", "owner-alias"])
def test_both_homes_exclude_both_owner_trees_on_claude_plans(make, capsys, source, field, tree, variable, where):
    run = make()
    import pwd
    password_home = run.tmp / "password-home"
    password_home.mkdir()
    run.monkeypatch.setattr(pwd, "getpwuid", lambda uid: types.SimpleNamespace(pw_dir=str(password_home)))
    owner = (run.home if source == "HOME" else password_home) / tree
    owner.mkdir()
    home = owner if where == "exact" else owner / "run-home"
    if where == "alias":
        alias = run.tmp / "home-alias"
        alias.symlink_to(owner)
        home = alias / "run-home"
    elif where == "owner-alias":
        backing = run.tmp / "owner-backing"
        owner.rename(backing)
        owner.symlink_to(backing)
        home = backing / "run-home"
    run.config[field] = str(home)
    run.save()
    for words in (("init",), ("login",), ("down",), ("status",)):
        assert in_process(run, *words, capsys=capsys) == (2, {
            "error": "%s %s is inside ~/%s (%s); a team run uses its own folder" % (variable, home, tree, owner)})
    assert list(owner.iterdir()) == [] and not run.run.exists()


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
        (["auth", "login", "--claudeai"], str(run.claude_home), []),
        (["auth", "status", "--json"], str(run.claude_home), [])]
    assert state(run)["logins"][CLAUDE]["credentials_sha256"] == sha(credentials)
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
    assert answer == {"error": NOT_TRUSTED + "config directory is not the run's claude home" + CLEANED}
    assert not credentials.exists()

    # A key the owner's shell does not hold, which the guard cannot see: the auth method still catches it.
    answer = run.team("login", expect=2, WRAP_STATUS_API_KEY="1")
    assert answer == {"error": NOT_TRUSTED + "auth method 'api_key' is not claude.ai" + CLEANED}
    assert not credentials.exists()
    assert run.claude_calls()[-1]["billing"] == ["ANTHROPIC_API_KEY"]

    answer = run.team("login", expect=2, WRAP_LOOSE_CREDENTIALS="1")
    assert answer == {"error": ".credentials.json in claude_home has mode 0644, not 0600: %s" % credentials + CLEANED}
    assert not (run.evidence / "login-claude.json").exists()

    assert run.team("login")["logins"][CLAUDE]["auth"]["authMethod"] == "claude.ai"


def credential_cases():
    return [
        ("symlink", ".credentials.json in claude_home is a symlink: {credentials}"),
        ("hard-link", ".credentials.json in claude_home has 2 hard links: {credentials}"),
        ("fifo", ".credentials.json in claude_home is not a regular file: {credentials}"),
        ("directory", ".credentials.json in claude_home is not a regular file: {credentials}"),
        ("group-readable", ".credentials.json in claude_home has mode 0640, not 0600: {credentials}"),
        ("world-readable", ".credentials.json in claude_home has mode 0604, not 0600: {credentials}"),
    ]


@pytest.mark.parametrize("case,error", credential_cases())
def test_existing_unsafe_credentials_refuse_before_auth_and_preserve_link_targets(make, case, error):
    run = make(CLAUDE, CLAUDE)
    run.team("init")
    credentials = run.claude_home / ".credentials.json"
    target = run.tmp / "owner-credentials"
    target.write_bytes(b"untouched owner credentials\n")
    target.chmod(0o600)
    if case == "symlink":
        credentials.symlink_to(target)
    elif case == "hard-link":
        os.link(target, credentials)
    elif case == "fifo":
        os.mkfifo(credentials, 0o600)
        # A stand-in login leaves the FIFO alone, so a missing precheck fails promptly rather than blocking open().
        run.wrap_claude()
    elif case == "directory":
        credentials.mkdir()
    else:
        credentials.write_bytes(b"old credentials\n")
        credentials.chmod(0o640 if case == "group-readable" else 0o604)
    assert run.team("login", expect=2, WRAP_KEEP_CREDENTIALS="1" if case == "fifo" else "") == {
        "error": error.format(credentials=credentials)}
    assert target.read_bytes() == b"untouched owner credentials\n" and run.claude_calls() == []
    assert not (run.evidence / "login-claude.json").exists()


def test_existing_credentials_owned_by_another_user_are_refused_before_auth(make, capsys):
    run = make(CLAUDE, CLAUDE)
    run.team("init")
    credentials = run.claude_home / ".credentials.json"
    credentials.write_bytes(b"other user's credentials\n")
    credentials.chmod(0o600)
    original = os.lstat

    def other_owner(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if Path(path) == credentials:
            values = list(info)
            values[4] = os.getuid() + 1
            return os.stat_result(values)
        return info

    run.monkeypatch.setattr(os, "lstat", other_owner)
    assert in_process(run, "login", capsys=capsys) == (2, {
        "error": ".credentials.json in claude_home is not owned by this user: %s" % credentials})
    assert credentials.read_bytes() == b"other user's credentials\n" and run.claude_calls() == []


@pytest.mark.parametrize("case,error", [("missing", "claude_home has no .credentials.json after claude auth login")]
                         + [row for row in credential_cases() if row[0] != "directory"])
def test_credentials_are_checked_again_before_status(make, case, error):
    run = make(CLAUDE, CLAUDE)
    run.wrap_claude()
    run.team("init")
    target = run.tmp / "owner-credentials"
    target.write_bytes(b"owner bytes\n")
    target.chmod(0o600)
    answer = run.team("login", expect=2, WRAP_CREDENTIALS=case, WRAP_TARGET=str(target))
    suffix = CLEANED if case in ("group-readable", "world-readable") else ""
    assert answer == {"error": error.format(credentials=run.claude_home / ".credentials.json") + suffix}
    assert [call["argv"] for call in run.claude_calls()] == [["auth", "login", "--claudeai"]]
    assert target.read_bytes() == b"owner bytes\n"
    assert not (run.evidence / "login-claude.json").exists()


@pytest.mark.parametrize("mode,error", [
    ("malformed", "claude auth status printed no JSON object"),
    ("exit", "claude auth status exited 7"),
    ("method", "auth method 'api_key' is not claude.ai"),
])
@pytest.mark.parametrize("existing", [False, True])
def test_status_refusals_remove_only_credentials_written_by_this_login(make, mode, error, existing):
    run = make(CLAUDE, CLAUDE)
    run.wrap_claude()
    run.team("init")
    credentials = run.claude_home / ".credentials.json"
    if existing:
        run.team("login")
        # A failed re-login must invalidate the previously accepted state digest too.
        assert state(run)["logins"][CLAUDE]["credentials_sha256"] == sha(credentials)
    answer = run.team("login", expect=2, WRAP_STATUS=mode)
    assert answer == {"error": NOT_TRUSTED + error + CLEANED}
    assert not os.path.lexists(credentials) and CLAUDE not in state(run).get("logins", {})


def test_status_refusal_preserves_a_credential_the_login_did_not_change(make):
    run = make(CLAUDE, CLAUDE)
    run.wrap_claude()
    run.team("init")
    run.team("login")
    credentials = run.claude_home / ".credentials.json"
    before = credentials.read_bytes()
    assert run.team("login", expect=2, WRAP_KEEP_CREDENTIALS="1", WRAP_STATUS="method") == {
        "error": NOT_TRUSTED + "auth method 'api_key' is not claude.ai"}
    assert credentials.read_bytes() == before and CLAUDE not in state(run).get("logins", {})


def test_status_timeout_is_a_cli_failure_and_removes_the_new_credential(make):
    run = make(CLAUDE, CLAUDE)
    run.wrap_claude()
    run.team("init")
    answer = run.team("login", expect=3, WRAP_STATUS="timeout", AEGIS_CLAUDE_AUTH_STATUS_TIMEOUT="0.1")
    assert "timed out after 0.1 seconds" in answer["error"]
    assert not (run.claude_home / ".credentials.json").exists()
    assert CLAUDE not in state(run).get("logins", {})


# -- review round 2: login custody and path revalidation -----------------------------------------------------------------

def cli_environment(run, **extra):
    """Use the subprocess CLI's fake-host environment when exercising main() with an OS boundary hook."""
    for name, value in run.env(**extra).items():
        run.monkeypatch.setenv(name, value)


def home_alias(run, kind):
    """An ancestor alias initially pointing to an isolated host home, plus a temporary owner's untouched credentials."""
    folder, field = (".claude", "claude_home") if kind == CLAUDE else (".codex", "codex_home")
    backing = run.tmp / (field + "-backing")
    backing.mkdir()
    alias = run.tmp / (field + "-alias")
    alias.symlink_to(backing)
    configured = alias / folder
    setattr(run, field, configured)
    run.config[field] = str(configured)
    run.save()
    owner = run.home / folder
    owner.mkdir(mode=0o700)
    credential = owner / (".credentials.json" if kind == CLAUDE else "auth.json")
    credential.write_bytes(b"untouched owner credential\n")
    credential.chmod(0o600)
    return alias, backing / folder, owner, credential


@pytest.mark.parametrize("outcome", ["success", "refused", "failed"])
def test_round2_a_second_login_is_refused_without_affecting_the_first(make, outcome):
    run = make(CLAUDE, CLAUDE)
    run.wrap_claude()
    run.team("init")
    gate = str(run.tmp / "login-gate")
    for suffix in ("-ready", "-release"):
        os.mkfifo(gate + suffix, 0o600)
    ready = os.open(gate + "-ready", os.O_RDWR | os.O_NONBLOCK)
    release = os.open(gate + "-release", os.O_RDWR | os.O_NONBLOCK)
    first = subprocess.Popen([sys.executable, "-I", "-B", str(TEAM), "--config", str(run.config_path), "login"],
                             env=run.env(WRAP_GATE=gate, WRAP_STATUS="method" if outcome == "refused" else "",
                                         FAKE_CLAUDE_LOGIN="fail" if outcome == "failed" else ""),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([ready], [], [], 2)[0], "the first auth child did not reach the gate"
        assert os.read(ready, 1) == b"1"
        before = files(run.run), (run.run / "team-commands.jsonl").read_bytes()
        extra = {"AEGIS_CLAUDE_AUTH_STATUS_TIMEOUT": "0"} if outcome == "refused" else {}
        answer = run.team("login", expect=2, **extra)
        assert answer == {"error": "another login is running for this run"}
        assert files(run.run) == before[0]
        assert (run.run / "team-commands.jsonl").read_bytes() == before[1]
        assert not run.claude_calls() and not (run.claude_home / ".credentials.json").exists()
    finally:
        os.write(release, b"1")
        try:
            stdout, stderr = first.communicate(timeout=2)
        finally:
            if first.poll() is None:
                first.kill()
                first.communicate(timeout=2)
            os.close(ready)
            os.close(release)
    assert stderr == ("fake claude: login failed\n" if outcome == "failed" else "")
    answer = json.loads(stdout.splitlines()[-1])
    credentials = run.claude_home / ".credentials.json"
    if outcome == "success":
        assert first.returncode == 0
        assert answer["logins"][CLAUDE]["credentials_sha256"] == sha(credentials)
        assert state(run)["logins"][CLAUDE]["credentials_sha256"] == sha(credentials)
    elif outcome == "refused":
        assert first.returncode == 2
        assert answer == {"error": NOT_TRUSTED + "auth method 'api_key' is not claude.ai" + CLEANED}
        assert not credentials.exists() and CLAUDE not in state(run).get("logins", {})
    else:
        assert first.returncode == 3 and answer == {"error": "claude auth login exited 1"}
        assert not credentials.exists() and CLAUDE not in state(run).get("logins", {})
    # A completed or refused login releases its lock.
    assert run.team("login")["logins"][CLAUDE]["credentials_sha256"] == sha(credentials)


@pytest.mark.parametrize("case", ["timeout-zero", "timeout-invalid", "hard-link", "home-symlink"])
def test_round2_mixed_plan_claude_prechecks_run_before_codex_login(make, case):
    run = make()
    run.team("init")
    credentials = run.claude_home / ".credentials.json"
    extra = {}
    if case.startswith("timeout"):
        extra["AEGIS_CLAUDE_AUTH_STATUS_TIMEOUT"] = "0" if case == "timeout-zero" else "invalid"
        error = ("AEGIS_CLAUDE_AUTH_STATUS_TIMEOUT must be greater than 0 and at most 60 seconds"
                 if case == "timeout-zero" else "could not convert string to float: 'invalid'")
    elif case == "hard-link":
        target = run.tmp / "owner-credential"
        target.write_bytes(b"unchanged owner\n")
        target.chmod(0o600)
        os.link(target, credentials)
        error = ".credentials.json in claude_home has 2 hard links: %s" % credentials
    else:
        backing = run.tmp / "moved-claude-home"
        run.claude_home.rename(backing)
        run.claude_home.symlink_to(backing)
        error = "unsafe claude_home: it is a symlink"
    before = files(run.run)
    assert run.team("login", expect=2, **extra) == {"error": error}
    assert not run.calls("login") and not run.claude_calls()
    assert not (run.codex_home / "auth.json").exists()
    after = files(run.run)
    # The persistent lock is bookkeeping, never login evidence or an accepted credential.
    assert {name: digest for name, digest in after.items() if name != ".login.lock"} == before
    if case == "hard-link":
        assert target.read_bytes() == b"unchanged owner\n"


@pytest.mark.parametrize("mode,code,error", [
    ("unicode", 2, "'utf-8' codec can't decode byte 0xff"),
    ("nul", 2, "embedded null byte"),
    ("missing-executable", 3, "No such file or directory"),
])
def test_round2_every_status_exception_cleans_up_the_login_credential(make, mode, code, error):
    run = make(CLAUDE, CLAUDE)
    run.wrap_claude()
    run.team("init")
    extra = {"WRAP_REMOVE_EXECUTABLE": "1"} if mode == "missing-executable" else {"WRAP_STATUS": mode}
    answer = run.team("login", expect=code, **extra)
    assert error in answer["error"]
    assert not (run.claude_home / ".credentials.json").exists()
    assert CLAUDE not in state(run).get("logins", {})
    run.wrap_claude()
    assert run.team("login")["logins"][CLAUDE]["auth"]["loggedIn"] is True


@pytest.mark.parametrize("stage", ["evidence", "state"])
def test_round2_errors_saving_login_evidence_or_state_also_clean_up(make, capsys, stage):
    run = make(CLAUDE, CLAUDE)
    run.team("init")
    cli_environment(run)
    original = os.replace

    def cannot_save(source, destination, *args, **kwargs):
        path = Path(destination)
        if ((stage == "evidence" and path == run.evidence / "login-claude.json") or
                (stage == "state" and path == run.run / "team-state.json" and
                 CLAUDE in json.loads(Path(source).read_text()).get("logins", {}))):
            raise OSError("fixture: login %s write failed" % stage)
        return original(source, destination, *args, **kwargs)

    run.monkeypatch.setattr(os, "replace", cannot_save)
    assert in_process(run, "login", capsys=capsys) == (3, {"error": "fixture: login %s write failed" % stage})
    assert not (run.claude_home / ".credentials.json").exists()
    assert CLAUDE not in state(run).get("logins", {})


def test_round2_cleanup_keeps_a_credential_changed_after_the_login_observation(make):
    run = make(CLAUDE, CLAUDE)
    run.wrap_claude()
    run.team("init")
    assert run.team("login", expect=2, WRAP_STATUS="replaced-credential") == {
        "error": NOT_TRUSTED + "claude auth status exited 7"}
    assert (run.claude_home / ".credentials.json").read_text() == "credential changed after login"
    assert CLAUDE not in state(run).get("logins", {})


@pytest.mark.parametrize("kind", [CLAUDE, CODEX])
def test_round2_a_home_swap_after_the_initial_check_refuses_before_any_host_spawn(make, capsys, kind):
    run = make()
    alias, home, owner, credential = home_alias(run, kind)
    run.team("init")
    cli_environment(run)
    original = shutil.disk_usage

    def rehome(path):
        result = original(path)
        alias.unlink()
        alias.symlink_to(run.home)
        return result

    run.monkeypatch.setattr(shutil, "disk_usage", rehome)
    code, answer = in_process(run, "login", capsys=capsys)
    assert code == 2 and "inside ~/%s" % owner.name in answer["error"]
    assert credential.read_bytes() == b"untouched owner credential\n"
    assert not run.calls("login") and not run.claude_calls()


@pytest.mark.parametrize("kind", [CLAUDE, CODEX])
def test_round2_a_home_swap_after_codex_login_is_caught_before_evidence_or_claude_spawn(make, capsys, kind):
    run = make()
    alias, home, owner, credential = home_alias(run, kind)
    run.team("init")
    cli_environment(run)
    original = subprocess.run
    invoked = []

    def rehome(argv, *args, **kwargs):
        result = original(argv, *args, **kwargs)
        if os.path.basename(argv[0]) == "codex" and list(argv[1:2]) == ["login"]:
            invoked.append(argv[0])
            alias.unlink()
            alias.symlink_to(run.home)
        return result

    run.monkeypatch.setattr(subprocess, "run", rehome)
    code, answer = in_process(run, "login", capsys=capsys)
    assert len(invoked) == 1 and os.path.isabs(invoked[0])
    assert code == 2 and "inside ~/%s" % owner.name in answer["error"]
    assert credential.read_bytes() == b"untouched owner credential\n" and not run.claude_calls()
    assert not (run.evidence / "login.json").exists()


@pytest.mark.parametrize("stage", ["login", "status", "state"])
def test_round2_a_claude_home_swap_is_caught_before_status_or_state_save(make, capsys, stage):
    run = make(CLAUDE, CLAUDE)
    alias, home, owner, credential = home_alias(run, CLAUDE)
    run.wrap_claude()
    run.team("init")
    extra = {"WRAP_HOME_ALIAS": str(alias), "WRAP_OWNER_HOME": str(run.home)}
    if stage == "state":
        cli_environment(run)
        original = os.replace

        def rehome(source, destination, *args, **kwargs):
            result = original(source, destination, *args, **kwargs)
            if Path(destination) == run.evidence / "login-claude.json":
                alias.unlink()
                alias.symlink_to(run.home)
            return result

        run.monkeypatch.setattr(os, "replace", rehome)
        code, answer = in_process(run, "login", capsys=capsys)
    else:
        extra.update({"WRAP_REHOME_AFTER_LOGIN": "1"} if stage == "login" else {"WRAP_STATUS": "rehome"})
        code, answer = 2, run.team("login", expect=2, **extra)
    assert code == 2 and "inside ~/.claude" in answer["error"]
    assert credential.read_bytes() == b"untouched owner credential\n"
    assert not (home / ".credentials.json").exists()
    assert CLAUDE not in state(run).get("logins", {})
    assert not (run.evidence / "login-claude.json").exists()
    assert "login-claude.json" not in json.loads((run.evidence / "index.json").read_text())["files"]
    if stage == "login":
        assert [call["argv"][:2] for call in run.claude_calls()] == [["auth", "login"]]


def test_round2_child_environments_use_the_validated_canonical_homes(make):
    run = make()
    _, claude_home, _, _ = home_alias(run, CLAUDE)
    _, codex_home, _, _ = home_alias(run, CODEX)
    run.team("init")
    run.team("login")
    assert [call["config_dir"] for call in run.claude_calls()] == [str(claude_home)] * 2
    assert run.calls("login")[0]["codex_home"] == str(codex_home)


@pytest.mark.parametrize("field", ["run", "claude_home", "codex_home"])
@pytest.mark.parametrize("tree", [".claude", ".codex"])
def test_round2_owner_inode_aliases_are_refused_for_every_existing_ancestor(make, capsys, field, tree):
    run = make()
    owner = run.home / tree
    owner.mkdir()
    identity = owner.stat()
    alias = run.tmp / "inode-alias"
    alias.mkdir()
    run.config[field] = str(alias / "not-created" / "candidate")
    run.save()
    original = os.stat

    # CPython 3.9/3.10 pathlib retains the os.stat callable it saw at import time.
    run.monkeypatch.setattr(Path, "stat", lambda path, **kwargs: original(path, **kwargs))

    def same_directory(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if str(path) == str(alias):
            values = list(info)
            values[1:3] = [identity.st_ino, identity.st_dev]
            return os.stat_result(values)
        return info

    # A bind mount or a case-insensitive alias has the owner's directory identity without a symlink.
    run.monkeypatch.setattr(os, "stat", same_directory)
    code, answer = in_process(run, "init", capsys=capsys)
    assert code == 2 and "inside ~/%s" % tree in answer["error"]
    assert list(alias.iterdir()) == [] and list(owner.iterdir()) == [] and not run.run.exists()


def test_round2_codex_only_owner_checks_do_not_gain_inode_alias_handling(make, capsys):
    run = make(CODEX, CODEX)
    owner = run.home / ".codex"
    owner.mkdir()
    identity = owner.stat()
    alias = run.tmp / "inode-alias"
    alias.mkdir()
    run.config["codex_home"] = str(alias / "candidate")
    run.save()
    original = os.stat

    def same_directory(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if str(path) == str(alias):
            values = list(info)
            values[1:3] = [identity.st_ino, identity.st_dev]
            return os.stat_result(values)
        return info

    run.monkeypatch.setattr(os, "stat", same_directory)
    code, answer = in_process(run, "status", capsys=capsys)
    assert code == 0 and answer["init"]["complete"] is False


def test_round2_init_rechecks_the_run_destination_immediately_before_its_first_write(make, capsys):
    run = make()
    run.run.mkdir()
    owner = run.home / ".claude"
    owner.mkdir()
    (owner / "owner.txt").write_bytes(b"owner bytes\n")
    before = files(owner)
    original = subprocess.run

    def redirect_after_git(argv, *args, **kwargs):
        result = original(argv, *args, **kwargs)
        if "--verify" in argv and any(str(word).startswith("refs/heads/") for word in argv):
            run.run.rename(run.tmp / "original-run")
            run.run.symlink_to(owner)
        return result

    run.monkeypatch.setattr(subprocess, "run", redirect_after_git)
    code, answer = in_process(run, "init", capsys=capsys)
    assert code == 2 and answer["error"].startswith("run folder ")
    assert files(owner) == before and sorted(path.name for path in owner.iterdir()) == ["owner.txt"]


# -- review round 3: portable imports, loop homes, and concurrent state writers -------------------------------------------

@contextmanager
def paused_claude_login(run):
    """Pause the real CLI's fake auth child using FIFOs; always release and reap it, including on assertion failure."""
    gate = str(run.tmp / "round3-gate")
    for suffix in ("-ready", "-release"):
        os.mkfifo(gate + suffix, 0o600)
    ready = os.open(gate + "-ready", os.O_RDWR | os.O_NONBLOCK)
    release = os.open(gate + "-release", os.O_RDWR | os.O_NONBLOCK)
    process = subprocess.Popen([sys.executable, "-I", "-B", str(TEAM), "--config", str(run.config_path), "login"],
                               env=run.env(WRAP_GATE=gate), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    result = {}
    try:
        assert select.select([ready], [], [], 2)[0], "the auth child did not reach the gate"
        assert os.read(ready, 1) == b"1"
        yield result
    finally:
        os.write(release, b"1")
        try:
            stdout, stderr = process.communicate(timeout=2)
            result.update(code=process.returncode, stdout=stdout, stderr=stderr)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=2)
            os.close(ready)
            os.close(release)


def test_round3_the_team_module_imports_when_fcntl_is_unavailable(make):
    run = make()
    script = ("import sys; sys.modules['fcntl'] = None; sys.path.insert(0, sys.argv[1]); "
              "import hierarchy_team; print(hierarchy_team.SCHEMA)")
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROOT / "tools")],
                          capture_output=True, text=True, timeout=2, env=run.env())
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "aegis.team-run/v1"


def test_round3_up_keeps_the_loop_with_both_homes_under_safe_ancestor_aliases(make):
    run = make(CLAUDE, CODEX)
    _, claude_home, _, _ = home_alias(run, CLAUDE)
    _, codex_home, _, _ = home_alias(run, CODEX)
    run.team("init")
    run.team("login")
    try:
        answer = run.team("up")
        assert [row["endpoint"] for row in answer["roles"]] == ROLE_ORDER
        assert answer["loop"]["state"] == "started"
        env = proc_environ(answer["loop"]["pid"])
        assert env["CODEX_HOME"] == str(codex_home)
        assert env["CLAUDE_CONFIG_DIR"] == str(claude_home)
        assert run.team("status")["loop"]["pid_alive"] is True
    finally:
        run.team("down")


def test_round3_a_root_binding_saved_during_login_is_preserved(make):
    run = make()
    run.wrap_claude()
    run.team("init")
    with paused_claude_login(run) as login:
        bound = run.team("root", "--session", "root-during-login")
        root_record = state(run)["root"]
        assert root_record["session"] == bound["session"] == "root-during-login"
    assert login["code"] == 0 and login["stderr"] == ""
    assert state(run)["root"] == root_record
    assert state(run)["logins"][CLAUDE]["credentials_sha256"] == sha(run.claude_home / ".credentials.json")


def test_round3_down_during_login_refuses_without_writing_or_releasing_resources(make):
    run = make(CLAUDE, CLAUDE)
    run.wrap_claude()
    run.team("init")
    with paused_claude_login(run) as login:
        before = files(run.run), (run.run / "team-commands.jsonl").read_bytes()
        assert run.team("down", expect=2) == {"error": "a login is in progress"}
        assert files(run.run) == before[0]
        assert (run.run / "team-commands.jsonl").read_bytes() == before[1]
        assert (run.run / "worktrees" / "f2").is_dir()
    assert login["code"] == 0 and login["stderr"] == ""
    assert not state(run)["down"].get("started_at")
    assert run.team("down")["claude_home"] == "kept"


def test_round3_a_login_finishing_after_a_completed_down_refuses_and_keeps_teardown_state(make, capsys):
    run = make(CLAUDE, CLAUDE)
    run.team("init")
    state_path = run.run / "team-state.json"
    initialized = state_path.read_bytes()
    run.team("down")
    completed = state_path.read_bytes()
    assert state(run)["down"]["done"]["last"]
    # Replay a down completed by an older command without the login lock while the browser login was active.
    state_path.write_bytes(initialized)
    cli_environment(run)
    original = subprocess.run
    after_down = {}
    invoked = []

    def finish_down_after_auth(argv, *args, **kwargs):
        result = original(argv, *args, **kwargs)
        if os.path.basename(argv[0]) == "claude" and list(argv[1:3]) == ["auth", "login"]:
            invoked.append(argv[0])
            state_path.write_bytes(completed)
            after_down.update(files=files(run.run), commands=(run.run / "team-commands.jsonl").read_bytes())
        return result

    run.monkeypatch.setattr(subprocess, "run", finish_down_after_auth)
    code, answer = in_process(run, "login", capsys=capsys)
    assert len(invoked) == 1 and os.path.isabs(invoked[0])
    assert code == 2 and answer == {"error": "teardown has started; a new run needs a new run folder" + CLEANED}
    assert state_path.read_bytes() == completed
    assert not (run.claude_home / ".credentials.json").exists()
    expected = {name: digest for name, digest in after_down["files"].items()
                if name != "claude-home/.credentials.json"}
    assert files(run.run) == expected
    assert (run.run / "team-commands.jsonl").read_bytes() == after_down["commands"]


@pytest.mark.parametrize("existing_lock", [False, True])
def test_round3_codex_only_login_preserves_the_legacy_lock_file_behaviour(make, existing_lock):
    run = make(v1=True)
    run.team("init")
    lock = run.run / ".login.lock"
    if existing_lock:
        lock.write_bytes(b"unrelated legacy file\n")
        lock.chmod(0o644)
    answer = run.team("login")
    assert answer["auth_sha256"] == sha(run.codex_home / "auth.json")
    if existing_lock:
        assert lock.read_bytes() == b"unrelated legacy file\n" and stat.S_IMODE(lock.stat().st_mode) == 0o644
    else:
        assert not lock.exists()


# -- review round 4: serialize state reload/mutate/save without blocking browser or model work ----------------------------

# Run ROOT through the public CLI. Report either a completed legacy write or contention on the new state lock,
# so login's test hook can resume without a sleep or a deadlock while it holds the transaction lock.
ROOT_TRANSACTION = r'''
import fcntl, os, runpy, sys
# Python 3.9's pathlib accessor must capture native os.open, before the hook becomes a bound method.
from pathlib import Path
team, config, state, event = sys.argv[1:]
lock = os.path.join(os.path.dirname(state), ".state.lock")
state_descriptors = set()
open_file, flock, replace = os.open, fcntl.flock, os.replace

def signal(value):
    with open(event, "wb", buffering=0) as stream:
        stream.write(value)

def opened(path, *args, **kwargs):
    descriptor = open_file(path, *args, **kwargs)
    if str(path) == lock:
        state_descriptors.add(descriptor)
    return descriptor

def locked(descriptor, operation):
    if descriptor in state_descriptors and operation == fcntl.LOCK_EX:
        try:
            return flock(descriptor, operation | fcntl.LOCK_NB)
        except BlockingIOError:
            signal(b"B")
    return flock(descriptor, operation)

def replaced(source, destination, *args, **kwargs):
    result = replace(source, destination, *args, **kwargs)
    if str(destination) == state:
        signal(b"S")
    return result

os.open, fcntl.flock, os.replace = opened, locked, replaced
sys.argv = [team, "--config", config, "root", "--session", "root-after-login-read"]
runpy.run_path(team, run_name="__main__")
'''


@pytest.mark.parametrize("fail_login_save", [False, True])
def test_round4_root_competing_after_logins_final_reload_keeps_both_bindings(make, capsys, fail_login_save):
    run = make()
    run.team("init")
    cli_environment(run)
    state_path = run.run / "team-state.json"
    event_path = run.tmp / "root-state-event"
    os.mkfifo(event_path, 0o600)
    event = os.open(event_path, os.O_RDWR | os.O_NONBLOCK)
    original = os.replace
    roots = []
    signals = []
    child_evidence = run.tmp / "root-child-evidence"
    child_evidence.mkdir(mode=0o700)
    (child_evidence / ".keep").touch(mode=0o600)
    stdout_path, stderr_path = child_evidence / "stdout", child_evidence / "stderr"
    diagnostic_path = child_evidence / "diagnostics.json"
    diagnostic_path.touch(mode=0o600)
    observations = []

    def child_diagnostic(process, phase):
        detail = {"phase": phase, "pid": process.pid, "exit_status": process.poll(),
                  "signals": [value.decode("ascii") for value in signals]}
        for name, path in (("stdout", stdout_path), ("stderr", stderr_path)):
            # A separate reader leaves the live child's output descriptor offset untouched.
            with path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                stream.seek(max(0, stream.tell() - 4096))
                detail[name + "_tail"] = stream.read(4096).decode("utf-8", "replace")
        observations.append(detail)
        diagnostic_path.write_text(json.dumps(observations, indent=2), encoding="utf-8")
        return json.dumps(detail, sort_keys=True)

    def root_after_reload(source, destination, *args, **kwargs):
        if (Path(destination) == state_path and not roots and
                CLAUDE in json.loads(Path(source).read_text()).get("logins", {})):
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            with os.fdopen(os.open(stdout_path, flags, 0o600), "wb") as stdout, \
                    os.fdopen(os.open(stderr_path, flags, 0o600), "wb") as stderr:
                process = subprocess.Popen([sys.executable, "-I", "-B", "-c", ROOT_TRANSACTION,
                                            str(TEAM), str(run.config_path), str(state_path), str(event_path)],
                                           env=run.env(), stdout=stdout, stderr=stderr, text=True)
            roots.append(process)
            assert select.select([event], [], [], 2)[0], (
                "ROOT neither saved nor reached the state lock; " + child_diagnostic(process, "readiness"))
            signals.append(os.read(event, 1))
            assert signals[-1] in (b"B", b"S")
            if fail_login_save:
                raise OSError("fixture: final login state write failed")
        return original(source, destination, *args, **kwargs)

    run.monkeypatch.setattr(os, "replace", root_after_reload)
    try:
        code, answer = in_process(run, "login", capsys=capsys)
        assert roots, "login did not reach its final state write"
        try:
            roots[0].wait(timeout=2)
        except subprocess.TimeoutExpired:
            pytest.fail("ROOT did not finish within two seconds; " + child_diagnostic(roots[0], "completion-timeout"))
        detail = child_diagnostic(roots[0], "completed")
        stdout, stderr = stdout_path.read_text(encoding="utf-8"), stderr_path.read_text(encoding="utf-8")
        assert roots[0].returncode == 0 and stderr == "", detail
        assert json.loads(stdout.splitlines()[-1])["session"] == "root-after-login-read"
    finally:
        for process in roots:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            child_diagnostic(process, "cleanup")
        os.close(event)
    current = state(run)
    assert current["root"] is not None, "login overwrote the ROOT binding saved after its final state reload"
    assert current["root"]["session"] == "root-after-login-read"
    if fail_login_save:
        assert code == 3 and answer == {"error": "fixture: final login state write failed"}
        assert CLAUDE not in current.get("logins", {})
        assert not (run.claude_home / ".credentials.json").exists()
        assert not (run.evidence / "login-claude.json").exists()
    else:
        assert code == 0
        assert current["logins"][CLAUDE]["credentials_sha256"] == sha(run.claude_home / ".credentials.json")
        assert answer["logins"][CLAUDE]["credentials_sha256"] == current["logins"][CLAUDE]["credentials_sha256"]


@pytest.mark.parametrize("existing_lock", [False, True])
def test_round4_codex_only_commands_do_not_create_or_consult_a_state_lock(make, existing_lock):
    run = make(v1=True)
    run.team("init")
    lock = run.run / ".state.lock"
    if existing_lock:
        lock.write_bytes(b"unrelated legacy state file\n")
        lock.chmod(0o644)
    answer = run.team("login")
    assert answer == {"codex_home": str(run.codex_home), "auth_sha256": sha(run.codex_home / "auth.json"),
                      "entries": [MARK, "auth.json", "log"]}
    assert run.team("root", "--session", "legacy-root")["session"] == "legacy-root"
    assert state(run)["root"]["session"] == "legacy-root"
    assert run.team("down")["codex_home"] == "kept"
    assert not (run.run / ".login.lock").exists()
    if existing_lock:
        assert lock.read_bytes() == b"unrelated legacy state file\n" and stat.S_IMODE(lock.stat().st_mode) == 0o644
    else:
        assert not lock.exists()



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
    run.team("login")
    transcript = run.claude_home / "projects" / "fixture-root" / "root-session.jsonl"
    transcript.parent.mkdir(parents=True)
    transcript.write_text(json.dumps({"type": "assistant", "sessionId": "root-session",
                                      "message": {"stop_reason": "end_turn"}}) + "\n")

    answer = run.team("root", "--session", "root-session")

    assert answer["endpoint"] == "pilot/root" and answer["session"] == "root-session"
    assert answer["tools"] == ["root_decide", "team_status", "team_pending", "team_request"]
    assert run.mailbox().status()["bindings"]["pilot/root"]["host"] == CLAUDE
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


@pytest.mark.parametrize("case,error", [
    ("claude-mark", "claude_home was kept: ownership record does not match this run"),
    ("claude-projects", "claude_home was kept: projects/ holds transcripts, which down copies to evidence from T2(a) PR 6"),
    ("codex-mark", "codex_home was kept: ownership record does not match this run"),
    ("codex-sessions", "codex_home was kept: the copy of sessions/session.jsonl in evidence/codex-sessions does not match it"),
])
def test_both_purges_are_validated_before_either_home_is_deleted(make, case, error):
    run = make()
    run.team("init")
    if case.endswith("mark"):
        home = run.claude_home if case.startswith("claude") else run.codex_home
        (home / MARK).write_text(json.dumps({"run": "other", "initiative": "pilot"}))
    elif case == "claude-projects":
        projects = run.claude_home / "projects"
        projects.mkdir()
        (projects / "session.jsonl").write_bytes(b"transcript\n")
    else:
        sessions = run.codex_home / "sessions"
        sessions.mkdir()
        (sessions / "session.jsonl").write_bytes(b"transcript\n")
        run.team("down")
        (run.evidence / "codex-sessions" / "session.jsonl").write_bytes(b"bad copy\n")
    before = files(run.codex_home), files(run.claude_home)
    assert run.team("down", "--purge-codex-home", "--purge-claude-home", expect=2) == {"error": error}
    assert run.codex_home.is_dir() and run.claude_home.is_dir()
    assert (files(run.codex_home), files(run.claude_home)) == before


@pytest.mark.parametrize("host,flag", [(CLAUDE, "--purge-codex-home"), (CODEX, "--purge-claude-home")])
def test_a_purge_flag_for_an_unused_host_is_refused_before_teardown(make, host, flag):
    run = make(host, host)
    run.team("init")
    before = files(run.run)
    assert run.team("down", flag, expect=2) == {"error": "%s requires a plan that uses %s" %
                                               (flag, CODEX if host == CLAUDE else CLAUDE)}
    assert files(run.run) == before


def test_both_homes_are_purged_when_both_preconditions_pass(make):
    run = make()
    run.team("init")
    answer = run.team("down", "--purge-codex-home", "--purge-claude-home")
    assert answer["codex_home"] == answer["claude_home"] == "purged"
    assert not run.codex_home.exists() and not run.claude_home.exists()


# -- Codex-only runs ------------------------------------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason="T2(a) follow-up: Codex-only run folder destination check")
def test_codex_only_run_destinations_must_not_write_into_an_owner_tree(make):
    run = make(CODEX, CODEX)
    owner = run.home / ".claude"
    owner.mkdir()
    run.run.symlink_to(owner)
    run.config["codex_home"] = str(run.tmp / "isolated-codex")
    run.save()
    answer = run.team("init", expect=2)
    assert list(owner.iterdir()) == []
    assert "error" in answer


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
    assert "CLAUDE_CONFIG_DIR" not in team.child_env(parsed)
    assert "CLAUDE_CONFIG_DIR" in json.loads((run.evidence / "child-environment.json").read_text())["dropped_names"]
    loop = team.start_loop(parsed)
    environ = proc_environ(loop["pid"])
    assert "CLAUDE_CONFIG_DIR" not in environ
    assert elsewhere not in (run.evidence / "child-environment.json").read_text()
    assert (run.evidence / "loop-environ.txt").read_text() == "CODEX_HOME=%s\nPATH=%s\n" % (run.codex_home,
                                                                                           environ["PATH"])
    down = run.team("down", CLAUDE_CONFIG_DIR=elsewhere)
    assert down["loop"]["state"] == "stopped" and down["codex_home"] == "kept" and "claude_home" not in down
