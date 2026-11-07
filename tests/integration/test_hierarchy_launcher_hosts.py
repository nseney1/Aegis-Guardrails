"""The launcher starts each role on the host the run's host plan assigns (ADR T2(a) §1, §4, PR order item 4).

A claude-code start: the launcher chooses the session, sends the role contract rendered for the `claude` family on
stdin from a prompt file it keeps, confirms the session from the stream-json init event and from its transcript under
CLAUDE_CONFIG_DIR, and only then binds through add-role. A codex-cli plan, or no plan, keeps today's Codex start.

Every launcher process runs on a sealed PATH: the fake codex, the fake claude (found through its PATH guard) and links
to git and ps, nothing else. CLAUDE_CONFIG_DIR is a temporary home the fake has logged in to. These tests show the tools
work together on fakes, not that a real host behaves this way.
"""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import uuid

import pytest

from tests.integration import hierarchy_fake_claude as fake
from tests.integration.test_hierarchy_launcher import (CONTRACT_FILES, REVIEW, START_FOOTER, START_HEADER, Launch,
                                                       census, contract_path, lane_rules, launcher_module,
                                                       references, start_prompt as codex_prompt, wait_until)
from tests.integration.test_hierarchy_mailbox import ROOT
from tests.integration.test_hierarchy_provision import provision


sys.path.insert(0, str(ROOT / "tools"))
import hierarchy_hosts  # noqa: E402


pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="the fake claude is a POSIX shell wrapper and the launcher needs process groups")
CLAUDE, CODEX, NATIVE = "claude-code", "codex-cli", "codex"
IMPLEMENTER = "pilot/lane/f2"
WAKE = ROOT / "tools" / "hierarchy_wake.py"
OTHER_SESSION = "0b1f7c52-5d2e-4e07-9a41-3c8e2f9d6a10"
HOME_UNSET = "a claude-code start needs CLAUDE_CONFIG_DIR set to the run's claude home"
NATIVE_START = "a native codex thread is started by its own app, not the launcher"
CLAUDE_WRITER = "permission rules, not OS-enforced"
# Today's launch record keys: a Codex record must gain none.
CODEX_BOUND_KEYS = {"schema", "at", "action", "state", "endpoint", "host", "session", "generation", "argv", "cwd",
                    "contract", "contracts", "start_timeout_seconds", "exit_code", "timed_out", "connection",
                    "wake_profile", "codex_profile"}
CODEX_REFUSED_KEYS = {"schema", "at", "action", "state", "endpoint", "host", "session", "generation", "error"}
ROLES = {IMPLEMENTER: "implementer", REVIEW: "reviewer"}
FILE_TOOLS = {"implementer": "Read,Glob,Grep,Edit,Write", "reviewer": "Read,Glob,Grep"}
ALLOWED = {"implementer": "Edit,Write", "reviewer": ""}


class Hosts(Launch):
    """The launcher harness with the fake claude beside the fake codex, on a PATH that holds nothing else."""

    def __init__(self, tmp_path):
        super().__init__(tmp_path)
        fake.install(self.bin)
        for tool in ("git", "ps"):
            found = shutil.which(tool)
            assert found, tool + " is needed by the tools under test"
            (self.bin / tool).symlink_to(found)
        self.claude_home = tmp_path / "claude-home"
        self.claude_home.mkdir(mode=0o700)
        self.claude_log = tmp_path / "fake-claude.log"
        self.login(self.claude_home)

    def env(self, **extra):
        """Like the Codex harness, but PATH is sealed and this session's own Claude variables stay out. None drops a
        variable."""
        ambient = {key: value for key, value in os.environ.items() if not key.startswith(("CLAUDE", "ANTHROPIC"))}
        env = {**ambient, "PATH": str(self.bin), "PYTHONDONTWRITEBYTECODE": "1",
               "CODEX_HOME": str(self.tmp / "codex-home"), "FAKE_CODEX_LOG": str(self.codex_log),
               "FAKE_HOST_LOG": str(self.host_log), "FAKE_HOST_PLAN": str(self.plan),
               "CLAUDE_CONFIG_DIR": str(self.claude_home), "FAKE_CLAUDE_LOG": str(self.claude_log), **extra}
        return {key: value for key, value in env.items() if value is not None}

    def login(self, home):
        done = subprocess.run([fake.require_fake(str(self.bin)), "auth", "login"], capture_output=True, text=True,
                              timeout=60, env=self.env(CLAUDE_CONFIG_DIR=str(home), FAKE_CLAUDE_LOG=None))
        assert done.returncode == 0, done.stderr

    def claude_calls(self):
        return [json.loads(line) for line in self.claude_log.read_text().splitlines()] if self.claude_log.exists() else []

    def wrap_claude(self, body):
        """Put a shell wrapper around the fake on the sealed PATH; the PATH guard still finds the fake in it."""
        path = self.bin / "claude"
        path.unlink()
        path.write_text("#!/bin/sh\n" + body % {"python": shlex.quote(sys.executable), "fake": shlex.quote(str(fake.HERE))}
                        + "\n", encoding="utf-8")
        path.chmod(0o700)
        fake.require_fake(str(self.bin))


def write_plan(hosts, team):
    """The plan a team run's init writes for the base's own initiative: the front door is a claude-code stand-in, as
    in hierarchy_team."""
    plan = hierarchy_hosts.plan_record("pilot", CODEX, team, {"pilot/front-door": CLAUDE}, "0" * 64)
    (hosts.base / "host-plan.json").write_text(json.dumps(plan), encoding="utf-8")


@pytest.fixture
def hosts(tmp_path):
    built = Hosts(tmp_path)
    built.init()
    return built


@pytest.fixture
def claude_team(hosts):
    write_plan(hosts, CLAUDE)
    return hosts


def quoted(endpoint):
    return endpoint.replace("/", "%2F")


def for_family(text, family):
    """A contract as a role of this family reads it: every block marked for another family and every marker left out."""
    kept, skipping = [], False
    for line in text.splitlines():
        if line.strip().startswith("<!-- host:"):
            skipping = line.strip() != "<!-- host:%s -->" % family
        elif line.strip() == "<!-- /host -->":
            skipping = False
        elif not skipping:
            kept.append(line)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(kept)).strip()


def claude_prompt(hosts, endpoint, role):
    names = CONTRACT_FILES[role]
    parts = [for_family(contract_path(hosts, name).read_text(encoding="utf-8"), "claude") for name in names]
    if len(names) > 1:
        parts[0] = lane_rules(parts[0], role)
    return "\n\n".join([START_HEADER % (endpoint, role), *parts, START_FOOTER])


def chosen(answer):
    argv = answer["argv"]
    return argv[argv.index("--session-id") + 1]


def unbound(hosts, endpoint):
    return hosts.binding(endpoint) is None


# -- a claude-code team ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("endpoint", [IMPLEMENTER, REVIEW])
def test_a_claude_team_starts_each_role_on_claude_with_the_session_the_launcher_chose(claude_team, endpoint):
    role = ROLES[endpoint]
    answer = claude_team.start(endpoint=endpoint)
    assert answer["state"] == "bound" and answer["host"] == CLAUDE, answer
    session = answer["session"]
    assert str(uuid.UUID(session)) == session and answer["generation"] == 1 and answer["exit_code"] == 0
    connection = claude_team.base / "connections" / (quoted(endpoint) + ".start.json")
    # The start turn has no MCP servers, as a Codex start has none.
    assert json.loads(connection.read_text()) == {"mcpServers": {}}
    assert answer["argv"] == [
        "claude", "--restricted", "--tools=" + FILE_TOOLS[role], "--strict-mcp-config", "--mcp-config", str(connection),
        "--permission-mode", "manual", "--permission-prompts", "none", "--session-id", session, "--print",
        "--output-format", "stream-json", "--verbose", "--disable-slash-commands", "--allowedTools", ALLOWED[role]]
    [call] = claude_team.claude_calls()
    assert (call["argv"], call["cwd"], call["config_dir"]) == (answer["argv"][1:], str(claude_team.source),
                                                                str(claude_team.claude_home))
    assert not claude_team.codex_log.exists()

    # The prompt went on stdin from a kept file beside the start's logs, rendered for the claude family.
    prompt_file = Path(answer["prompt_file"])
    assert answer["prompt_via"] == "stdin" and prompt_file == Path(answer["log"]["stdout"]).with_suffix(".prompt")
    prompt = prompt_file.read_text(encoding="utf-8")
    assert prompt == claude_prompt(claude_team, endpoint, role)
    assert 'claude stop "${CLAUDE_CODE_SESSION_ID:0:8}"' in prompt
    assert "Never run a command to stop a session" not in prompt
    assert "<!-- host:" not in prompt and "<!-- /host -->" not in prompt
    assert answer["contracts"] == references(claude_team, role) and answer["contract"] == answer["contracts"][-1]
    [transcript] = hierarchy_hosts.transcripts(CLAUDE, claude_team.claude_home, session)
    first = json.loads(transcript.read_text().splitlines()[0])
    assert first["type"] == "user" and first["message"]["content"] == prompt

    binding = claude_team.binding(endpoint)
    assert (binding["host"], binding["session"]) == (CLAUDE, session)
    wake = json.loads(Path(answer["wake_profile"]).read_text())
    assert wake["host"] == CLAUDE and wake["prompt_via"] == "stdin" and wake["session"] == session
    assert wake["argv"][wake["argv"].index("--resume") + 1] == session and "--session-id" not in wake["argv"]
    recorded = json.loads((claude_team.base / "sessions" / (quoted(endpoint) + "-g1.json")).read_text())
    assert (recorded["host_kind"], recorded["start_mode"], recorded["session"]) == (CLAUDE, "print", session)
    assert recorded["write_scope"]["boundary"] == (CLAUDE_WRITER if role == "implementer" else "no write tools")

    [record] = claude_team.records(endpoint)
    assert record == {key: value for key, value in answer.items() if key != "log"}
    assert "codex_profile" not in record
    folder = claude_team.base / "launches" / quoted(endpoint)
    assert sorted(path.suffix for path in (folder / "logs").iterdir()) == [".prompt", ".stderr", ".stdout"]


def test_a_claude_team_starts_an_implementer_and_a_reviewer_as_separate_sessions(claude_team):
    first, second = claude_team.start(endpoint=IMPLEMENTER), claude_team.start(endpoint=REVIEW)
    assert (first["state"], second["state"]) == ("bound", "bound")
    assert first["session"] != second["session"]
    assert [call["argv"][call["argv"].index("--session-id") + 1] for call in claude_team.claude_calls()] == [
        first["session"], second["session"]]


# -- refusals and failed starts: each recorded, the endpoint left unbound ---------------------------------------------

def test_a_claude_start_without_claude_config_dir_is_refused_before_anything_runs(claude_team):
    refused = claude_team.start(expect=2, endpoint=IMPLEMENTER, environment={"CLAUDE_CONFIG_DIR": None})
    assert refused["error"] == HOME_UNSET
    assert (refused["state"], refused["host"], refused["session"]) == ("refused", CLAUDE, None)
    assert [row["state"] for row in claude_team.records(IMPLEMENTER)] == ["refused"]
    assert claude_team.claude_calls() == [] and unbound(claude_team, IMPLEMENTER)


def test_a_stand_in_is_refused_at_start(claude_team):
    refused = claude_team.start(expect=2, endpoint="pilot/front-door")
    assert refused["error"] == "pilot/front-door is a stand-in and runs no host"
    assert (refused["state"], refused["host"]) == ("refused", CLAUDE)
    assert [row["state"] for row in claude_team.records("pilot/front-door")] == ["refused"]
    assert claude_team.claude_calls() == [] and unbound(claude_team, "pilot/front-door")


def test_a_native_host_is_refused_at_start(hosts, monkeypatch, capsys):
    # A validated plan never assigns native codex below ROOT, so the launcher's own check is shown with a plan reader
    # that skips validation. PATH is sealed here too, so even a launcher that ignored the plan reached only fakes.
    monkeypatch.setenv("PATH", str(hosts.bin))
    for key in [key for key in os.environ if key.startswith(("CLAUDE", "ANTHROPIC"))]:
        monkeypatch.delenv(key)
    monkeypatch.setenv("FAKE_CODEX_LOG", str(hosts.codex_log))
    monkeypatch.setenv("FAKE_CODEX_THREAD", "019a6c3e-1111-7222-8333-444455556666")
    monkeypatch.setattr(hierarchy_hosts, "read_plan",
                        lambda base: {"hierarchy": "pilot", "root": CODEX, "team": NATIVE, "stand_ins": {}})
    module = launcher_module()
    code = module.main(["--base", str(hosts.base), "start", "--request", str(hosts.start_request(endpoint=REVIEW))])
    monkeypatch.undo()
    refused = json.loads(capsys.readouterr().out)
    assert code == 2 and refused["error"] == NATIVE_START
    assert (refused["state"], refused["host"]) == ("refused", NATIVE)
    assert not hosts.codex_log.exists() and hosts.claude_calls() == [] and unbound(hosts, REVIEW)


def test_an_init_event_that_reports_another_session_is_a_failed_start(claude_team):
    # sed by its absolute path: the sealed PATH holds no sed.
    claude_team.wrap_claude("%%(python)s %%(fake)s \"$@\" | %s 's/\"session_id\": \"[^\"]*\"/\"session_id\": \"%s\"/g'"
                            % (shlex.quote(shutil.which("sed")), OTHER_SESSION))
    answer = claude_team.start(expect=3, endpoint=IMPLEMENTER)
    assert answer["state"] == "failed_to_start" and answer["session"] is None
    assert answer["error"] == "the start reported session %s, not the session the launcher chose: %s" % (
        OTHER_SESSION, chosen(answer))
    assert [row["state"] for row in claude_team.records(IMPLEMENTER)] == ["failed_to_start"]
    assert unbound(claude_team, IMPLEMENTER)


def test_a_start_whose_transcript_is_not_under_the_runs_claude_home_is_a_failed_start(claude_team, tmp_path):
    elsewhere = tmp_path / "other-claude-home"
    elsewhere.mkdir(mode=0o700)
    claude_team.login(elsewhere)
    claude_team.wrap_claude("CLAUDE_CONFIG_DIR=%s exec %%(python)s %%(fake)s \"$@\"" % shlex.quote(str(elsewhere)))
    answer = claude_team.start(expect=3, endpoint=IMPLEMENTER)
    session = chosen(answer)
    assert answer["state"] == "failed_to_start" and answer["session"] is None and answer["exit_code"] == 0
    assert answer["error"] == "no transcript for session %s under CLAUDE_CONFIG_DIR %s" % (session,
                                                                                            claude_team.claude_home)
    assert hierarchy_hosts.transcripts(CLAUDE, elsewhere, session)
    assert [row["state"] for row in claude_team.records(IMPLEMENTER)] == ["failed_to_start"]
    assert unbound(claude_team, IMPLEMENTER)


@pytest.mark.parametrize("mode,timeout,timed_out", [("fail", 300, False), ("hang", 1, True)])
def test_a_claude_start_that_reports_its_session_but_does_not_finish_is_incomplete(claude_team, mode, timeout,
                                                                                    timed_out):
    answer = claude_team.start(expect=3, endpoint=IMPLEMENTER, start_timeout_seconds=timeout,
                               environment={"FAKE_CLAUDE_MODE": mode})
    session = chosen(answer)
    assert answer["state"] == "start_incomplete" and answer["session"] == session
    assert answer["timed_out"] is timed_out and (answer["exit_code"] == 1 if mode == "fail" else answer["exit_code"] < 0)
    assert unbound(claude_team, IMPLEMENTER) and census(session) == []
    assert [row["state"] for row in claude_team.records(IMPLEMENTER)] == ["start_incomplete"]


@pytest.mark.parametrize("change,error", [
    ({"tmpdir": "TMP"}, "tmpdir is only for a Codex writer"),
    ({"skip_git_repo_check": True}, "skip_git_repo_check is only for Codex"),
    ({"reader_shell": True}, "reader_shell is only for a Codex reviewer, orchestrator or decider"),
    ({"add_dirs": ["TMP"]}, "pilot/lane/f2: a claude-code start takes no add_dirs"),
])
def test_codex_only_start_options_are_refused_for_a_claude_start(claude_team, change, error):
    change = {key: (str(claude_team.tmp) if value == "TMP" else [str(claude_team.tmp)] if value == ["TMP"] else value)
              for key, value in change.items()}
    refused = claude_team.start(expect=2, endpoint=IMPLEMENTER, **change)
    assert refused["error"] == error and (refused["state"], refused["host"]) == ("refused", CLAUDE)
    assert claude_team.claude_calls() == [] and unbound(claude_team, IMPLEMENTER)


def test_a_held_start_lock_refuses_a_claude_start_under_its_host(claude_team):
    lock = claude_team.base / "launches" / quoted(IMPLEMENTER) / ".start.lock"
    lock.parent.mkdir(parents=True)
    lock.write_text('{"pid": 1}')
    refused = claude_team.start(expect=2, endpoint=IMPLEMENTER)
    assert refused["error"].startswith("a start is already running for pilot/lane/f2")
    assert (refused["state"], refused["host"]) == ("refused", CLAUDE) and claude_team.claude_calls() == []


# -- stop and resume of a Claude-started role -------------------------------------------------------------------------

def test_stop_ends_a_hung_turn_of_a_claude_started_role(claude_team, tmp_path):
    answer = claude_team.start(endpoint=IMPLEMENTER)
    session = answer["session"]
    wake = json.loads(Path(answer["wake_profile"]).read_text())
    out = tmp_path / "hung.stdout"
    # The role's own wake argv, as a wake would run it, left hanging after its init event.
    with open(answer["prompt_file"], "rb") as prompt, open(out, "wb") as stdout:
        hung = subprocess.Popen(wake["argv"], cwd=wake["cwd"], stdin=prompt, stdout=stdout, stderr=subprocess.DEVNULL,
                                env=claude_team.env(FAKE_CLAUDE_MODE="hang"), start_new_session=True)
    try:
        # After init, the fake's MCP probes (which also name the session) have ended; only the turn is left.
        wait_until(lambda: '"subtype": "init"' in out.read_text(), 30)
        wait_until(lambda: census(session) == [hung.pid])
        stopped = claude_team.run("stop", "--endpoint", IMPLEMENTER, "--grace-seconds", "2")
        assert stopped["state"] == "stopped" and stopped["pids"] == [hung.pid]
        assert (stopped["host"], stopped["session"]) == (CLAUDE, session)
        assert hung.wait(timeout=5) < 0
        assert [row["state"] for row in claude_team.records(IMPLEMENTER)] == ["bound", "stopped"]
    finally:
        if hung.poll() is None:
            os.killpg(hung.pid, 9)
            hung.wait(timeout=5)


def test_resume_dry_run_of_a_claude_started_role_runs_the_claude_wake_argv(claude_team):
    answer = claude_team.start(endpoint=IMPLEMENTER)
    session = answer["session"]
    claude_team.publish_to(IMPLEMENTER, "for-f2")
    resumed = claude_team.run("resume", "--endpoint", IMPLEMENTER, "--dry-run")
    assert resumed["state"] == "resumed" and resumed["dry_run"] is True and resumed["wake"]["state"] == "dry_run"
    assert (resumed["host"], resumed["session"], resumed["generation"]) == (CLAUDE, session, 1)
    assert not claude_team.host_log.exists() and len(claude_team.claude_calls()) == 1
    # The launch record keeps the wake's state; the wake tool's own dry run on the same profile shows its argv.
    setup = json.loads((claude_team.base / "provision.json").read_text())
    shown = subprocess.run([sys.executable, "-I", str(WAKE), "--root", setup["mailbox_root"], "--delivery-dir",
                            setup["delivery_dir"], "--endpoint", IMPLEMENTER, "--profile", answer["wake_profile"],
                            "--dry-run"], capture_output=True, text=True, timeout=60, env=claude_team.env())
    assert shown.returncode == 0, shown.stdout + shown.stderr
    argv = json.loads(shown.stdout)["argv"]
    assert argv[0] == "claude" and argv[argv.index("--resume") + 1] == session and "--print" in argv
    assert argv[argv.index("--mcp-config") + 1] == answer["connection"] and "--session-id" not in argv


# -- Codex: a codex-cli plan, or none, starts exactly as today ---------------------------------------------------------

@pytest.mark.parametrize("plan", [None, CODEX])
def test_a_codex_plan_or_no_plan_starts_codex_exactly_as_today(hosts, plan):
    if plan is not None:
        write_plan(hosts, plan)
    thread = "019a6c3e-1111-7222-8333-444455556666"
    answer = hosts.start(thread=thread, cwd=str(hosts.source))
    built = provision("codex-start", hosts.request(base=str(hosts.base), endpoint=REVIEW, cwd=str(hosts.source)))
    argv = built["start_argv"] + [codex_prompt(hosts, REVIEW, "reviewer")]
    assert (answer["state"], answer["host"], answer["session"]) == ("bound", CODEX, thread)
    assert answer["argv"] == argv and answer["contracts"] == references(hosts, "reviewer")
    assert set(answer) - {"log"} == CODEX_BOUND_KEYS
    [started] = [json.loads(line) for line in hosts.codex_log.read_text().splitlines()]
    assert started["argv"] == argv[1:] and hosts.claude_calls() == []
    assert not Path(answer["log"]["stdout"]).with_suffix(".prompt").exists()
    refused = hosts.start(expect=2)
    assert set(refused) == CODEX_REFUSED_KEYS and refused["host"] == CODEX
    assert [row["state"] for row in hosts.records()] == ["bound", "refused"]


def test_a_codex_team_refuses_its_stand_in_at_start(hosts):
    write_plan(hosts, CODEX)
    refused = hosts.start(expect=2, endpoint="pilot/front-door")
    assert refused["error"] == "pilot/front-door is a stand-in and runs no host" and refused["host"] == CLAUDE
    assert not hosts.codex_log.exists() and unbound(hosts, "pilot/front-door")


def test_an_invalid_host_plan_refuses_the_start_before_anything_runs(hosts):
    (hosts.base / "host-plan.json").write_text("{}", encoding="utf-8")
    refused = hosts.start(expect=2)
    assert refused["state"] == "refused" and refused["host"] is None
    assert refused["error"].startswith("host plan is missing ")
    assert not hosts.codex_log.exists() and unbound(hosts, REVIEW)


def test_the_harness_path_holds_only_the_fakes_and_the_linked_tools(hosts):
    assert sorted(path.name for path in hosts.bin.iterdir()) == ["claude", "codex", "git", "ps"]
    assert fake.require_fake(hosts.env()["PATH"])
