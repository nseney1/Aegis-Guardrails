"""The fake `claude` (hierarchy_fake_claude.py): what it models for Claude team runs, and how it refuses the rest.

Every case runs the installed wrapper, found through the PATH guard, with an environment built from scratch: PATH is
the wrapper's folder alone, HOME and CLAUDE_CONFIG_DIR are temporary. A test run inside Claude Code therefore neither
reaches a real `claude` or ~/.claude nor hands its own CLAUDECODE or CLAUDE_CODE_* variables to the fake. These tests
pin the fake's behaviour; they say nothing about how a real host behaves.
"""
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid

import pytest

from tests.integration import hierarchy_fake_claude as fake
from tools import hierarchy_meter


pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="the fake is installed as a POSIX shell wrapper, as the team-run tests use it")
READER = ["Read", "Glob", "Grep"]
WRITER = READER + ["Edit", "Write"]
DEFAULT_USAGE = {"input_tokens": 3, "cache_creation_input_tokens": 200, "cache_read_input_tokens": 1000,
                 "output_tokens": 40}
ACCOUNT_KEYS = {"email", "orgId", "orgName", "planTier", "subscriptionType", "storedClaudeAiLogin"}
SESSION = "0b1f7c52-5d2e-4e07-9a41-3c8e2f9d6a10"
NO_CONFIG = "fake claude: CLAUDE_CONFIG_DIR must name an existing folder\n"
ONE_SESSION = "fake claude: give exactly one of --session-id or --resume\n"
# What a real outer Claude Code session puts in its children's environment. None of it may reach the fake's children.
OUTER_SESSION = {"CLAUDECODE": "1", "CLAUDE_PID": "4242", "CLAUDE_CODE_SESSION_ID": "outer-session",
                 "CLAUDE_CODE_CHILD_SESSION": "1", "CLAUDE_CODE_BRIDGE_SESSION_ID": "outer-bridge",
                 "CLAUDE_CODE_MESSAGING_TOKEN": "outer-token", "CLAUDE_CODE_MESSAGING_SOCKET": "/tmp/outer.sock",
                 "CLAUDE_CODE_ENTRYPOINT": "cli", "CLAUDE_CODE_EXECPATH": "/outer/claude",
                 "CLAUDE_CODE_SESSION_ATTENDED": "1"}
# A server that appends its pid to the file named first, then never answers. Later words are ignored.
SLEEPER = "import os, sys, time; open(sys.argv[1], 'a').write(str(os.getpid()) + '\\n'); time.sleep(30)"
# A stdio MCP server that appends the environment of each start as a JSON line and offers a comma list of tools. It
# answers any tool call with an empty object, enough for the fake host's inbox read. Later words are ignored, so a case
# can add the --endpoint the fake host looks for.
PROBE = r'''
import json, os, sys
record, tools = sys.argv[1], [name for name in sys.argv[2].split(",") if name]
with open(record, "a", encoding="utf-8") as stream:
    stream.write(json.dumps(dict(os.environ)) + "\n")
for line in sys.stdin:
    request = json.loads(line)
    if "id" not in request:
        continue
    if request["method"] == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "probe", "version": "1"}}
    elif request["method"] == "tools/list":
        result = {"tools": [{"name": name, "inputSchema": {"type": "object"}} for name in tools]}
    else:
        result = {"content": [{"type": "text", "text": "{}"}]}
    print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
'''


class Run:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.bin, self.home, self.config, self.cwd = (tmp_path / name for name in ("bin", "home", "claude-home", "work"))
        for folder in (self.bin, self.home, self.config, self.cwd):
            folder.mkdir()
        self.log = tmp_path / "claude-calls.jsonl"
        fake.install(self.bin)

    def env(self, **changes):
        """From scratch, never os.environ. A None value leaves the variable out."""
        env = {"PATH": str(self.bin), "HOME": str(self.home), "CLAUDE_CONFIG_DIR": str(self.config),
               "FAKE_CLAUDE_LOG": str(self.log), "PYTHONDONTWRITEBYTECODE": "1"}
        env.update(changes)
        return {key: value for key, value in env.items() if value is not None}

    def command(self):
        return fake.require_fake(str(self.bin))

    def claude(self, *argv, expect=0, stdin="Do the work.", cwd=None, timeout=60, **changes):
        result = subprocess.run([self.command(), *argv], input=stdin, capture_output=True, text=True, timeout=timeout,
                                cwd=str(cwd or self.cwd), env=self.env(**changes))
        assert result.returncode == expect, (result.returncode, result.stdout, result.stderr)
        return result

    def login(self):
        self.claude("auth", "login", "--claudeai")
        return self

    def status(self, expect=0, **changes):
        return json.loads(self.claude("auth", "status", "--json", expect=expect, **changes).stdout)

    def probe(self, name, tools):
        record = self.tmp / (name + "-env.json")
        script = self.tmp / "probe_server.py"
        script.write_text(PROBE, encoding="utf-8")
        return {"command": sys.executable, "args": [str(script), str(record), ",".join(tools)]}, record

    def connection(self, servers):
        path = self.tmp / ("connection-%s.json" % uuid.uuid4().hex)
        path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
        return path

    def transcript(self, session, cwd=None):
        return self.config / "projects" / slug(cwd or self.cwd) / (session + ".jsonl")

    def calls(self):
        return lines(self.log)


@pytest.fixture
def fresh(tmp_path):
    return Run(tmp_path)


@pytest.fixture
def run(fresh):
    return fresh.login()


def slug(path):
    return re.sub(r"[^A-Za-z0-9]", "-", str(path))


def lines(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]


def events(result):
    return [json.loads(line) for line in (result if isinstance(result, str) else result.stdout).splitlines()]


def provision_argv(session_flags, connection, tools=READER, *, allowed=("mcp__aegis_mailbox__mailbox_inbox",),
                   request=None, assistants=None, name=None):
    """The exact words hierarchy_provision.claude_argv gives a role, without the program and any `env` prefix."""
    # Imported here: provision loads the mailbox modules, which only these Linux-only cases need.
    from tools import hierarchy_provision
    argv = hierarchy_provision.claude_argv(list(session_flags), str(connection), list(tools), list(allowed),
                                           dict(request or {}), assistants, name)
    return argv[argv.index("claude") + 1:]


def gone(pid, wait=5.0):
    """True once the process is reaped or a zombie, so it can no longer act."""
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        try:
            state = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()[0]
        except (OSError, IndexError):
            return True
        if state == "Z":
            return True
        time.sleep(0.05)
    return False


def print_argv(*extra, session=SESSION):
    return ["-p", "--session-id", session, "--output-format", "stream-json", "--verbose", *extra]


# PATH guard

def test_the_path_guard_accepts_the_installed_wrapper(tmp_path):
    folder = tmp_path / "bin"
    folder.mkdir()
    wrapper = fake.install(folder)
    assert wrapper == folder / "claude"
    assert fake.require_fake(str(folder)) == str(wrapper)
    assert wrapper.stat().st_mode & stat.S_IXUSR and fake.MARK in wrapper.read_bytes()


def test_the_path_guard_refuses_a_claude_that_is_not_the_fake(tmp_path):
    fakes, other, empty = tmp_path / "bin", tmp_path / "other", tmp_path / "empty"
    for folder in (fakes, other, empty):
        folder.mkdir()
    fake.install(fakes)
    impostor = other / "claude"
    impostor.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    impostor.chmod(0o755)
    with pytest.raises(AssertionError) as caught:
        fake.require_fake(os.pathsep.join([str(other), str(fakes)]))
    assert str(caught.value) == "claude on PATH is not the test fake: " + str(impostor)
    with pytest.raises(AssertionError) as caught:
        fake.require_fake(str(empty))
    assert str(caught.value) == "claude on PATH is not the test fake: None"


# CLAUDE_CONFIG_DIR

@pytest.mark.parametrize("kind", ["unset", "relative", "absent"])
def test_every_command_needs_an_existing_absolute_config_dir(fresh, kind):
    (fresh.cwd / "relative-home").mkdir()
    value = {"unset": None, "relative": "relative-home", "absent": str(fresh.tmp / "absent")}[kind]
    for argv in (["auth", "status", "--json"], ["auth", "login"], print_argv()):
        refused = fresh.claude(*argv, expect=2, CLAUDE_CONFIG_DIR=value)
        assert refused.stderr == NO_CONFIG and refused.stdout == ""
    assert [call["config_dir"] for call in fresh.calls()] == [value] * 3, "a refused call is still logged"
    assert not (fresh.home / ".claude").exists() and not (fresh.cwd / "relative-home" / ".credentials.json").exists()


@pytest.mark.parametrize("where", ["exact", "inside", "symlink"])
def test_the_real_users_claude_folder_is_refused_even_under_a_test_home(tmp_path, monkeypatch, capsys, where):
    import pwd
    owner = tmp_path / "owner"
    real = owner / ".claude"
    (real / "nested").mkdir(parents=True)
    (tmp_path / "link").symlink_to(real)
    # The seam is pwd in this process, so the fake runs in-process here; never the real folder.
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=str(owner)))
    monkeypatch.setenv("HOME", str(tmp_path / "test-home"))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str({"exact": real, "inside": real / "nested", "symlink": tmp_path / "link"}[where]))
    monkeypatch.delenv("FAKE_CLAUDE_LOG", raising=False)
    monkeypatch.setattr(sys, "argv", ["claude", "auth", "status", "--json"])
    assert fake.main() == 2
    assert capsys.readouterr() == ("", "fake claude: CLAUDE_CONFIG_DIR is the real ~/.claude\n")
    assert [path.name for path in real.iterdir()] == ["nested"]


def test_a_folder_beside_the_real_users_claude_folder_is_allowed(tmp_path, monkeypatch):
    import pwd
    beside = tmp_path / "owner" / ".claude-work"
    beside.mkdir(parents=True)
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=str(tmp_path / "owner")))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(beside))
    assert fake.config_dir() == beside


# auth

def test_status_on_an_empty_config_dir_says_not_logged_in_and_creates_the_state_file(fresh):
    assert fresh.status(expect=1) == {"loggedIn": False, "authMethod": "none", "apiProvider": "firstParty",
                                      "analyticsDisabled": False, "projectsDirectory": str(fresh.config / "projects"),
                                      "configDirectory": str(fresh.config), "loginExpiresAt": None}
    assert (fresh.config / ".claude.json").is_file()
    fresh.claude("auth", "status", "--text", expect=1)


def test_login_writes_private_credentials_and_status_then_reports_a_claude_ai_login(fresh):
    assert fresh.claude("auth", "login", "--claudeai").returncode == 0
    credentials = fresh.config / ".credentials.json"
    assert stat.S_IMODE(credentials.stat().st_mode) == 0o600
    status = fresh.status()
    assert (status["loggedIn"], status["authMethod"], status["apiProvider"]) == (True, "claude.ai", "firstParty")
    assert status["configDirectory"] == str(fresh.config)
    assert ACCOUNT_KEYS <= set(status) and status["email"] == "fake@example.invalid"
    for flags in (["--console"], ["--sso"], ["--email", "someone@example.invalid"], []):
        fresh.claude("auth", "login", *flags)
    assert stat.S_IMODE(credentials.stat().st_mode) == 0o600


def test_a_login_over_a_loose_credentials_file_makes_it_private(fresh):
    credentials = fresh.config / ".credentials.json"
    credentials.write_text("{}", encoding="utf-8")
    credentials.chmod(0o644)
    fresh.claude("auth", "login")
    assert stat.S_IMODE(credentials.stat().st_mode) == 0o600


def test_a_failed_login_writes_no_credentials(fresh):
    refused = fresh.claude("auth", "login", expect=1, FAKE_CLAUDE_LOGIN="fail")
    assert refused.stderr == "fake claude: login failed\n"
    assert not (fresh.config / ".credentials.json").exists()
    assert fresh.status(expect=1)["loggedIn"] is False


@pytest.mark.parametrize("variables,method,provider", [
    ({"ANTHROPIC_API_KEY": "sk-fake"}, "api_key", "firstParty"),
    ({"ANTHROPIC_AUTH_TOKEN": "fake"}, "api_key", "firstParty"),
    ({"CLAUDE_CODE_OAUTH_TOKEN": "fake"}, "oauth_token", "firstParty"),
    ({"CLAUDE_CODE_USE_BEDROCK": "1"}, "third_party", "bedrock"),
    ({"CLAUDE_CODE_USE_VERTEX": "1"}, "third_party", "vertex"),
    ({"CLAUDE_CODE_USE_FOUNDRY": "1"}, "third_party", "foundry"),
    ({"CLAUDE_CODE_USE_BEDROCK": "1", "ANTHROPIC_API_KEY": "sk-fake"}, "third_party", "bedrock"),
    ({"ANTHROPIC_API_KEY": "sk-fake", "CLAUDE_CODE_OAUTH_TOKEN": "fake"}, "api_key", "firstParty"),
])
def test_billing_variables_win_over_the_login_in_the_documented_order(run, variables, method, provider):
    status = run.status(**variables)
    assert (status["loggedIn"], status["authMethod"], status["apiProvider"]) == (True, method, provider)
    assert not ACCOUNT_KEYS & set(status), "account details belong to the claude.ai login only"
    assert run.calls()[-1]["billing"] == sorted(variables)


def test_a_billing_variable_alone_counts_as_logged_in(fresh):
    assert fresh.status(ANTHROPIC_API_KEY="sk-fake")["authMethod"] == "api_key"


def test_the_reported_config_dir_can_be_made_wrong_for_a_refusal_test(run):
    elsewhere = str(run.tmp / "elsewhere")
    status = run.status(FAKE_CLAUDE_STATUS_DIR=elsewhere)
    assert status["configDirectory"] == elsewhere and status["projectsDirectory"] == elsewhere + "/projects"
    assert status["authMethod"] == "claude.ai"


def test_unmodelled_auth_commands_and_options_are_refused(run):
    assert run.claude("auth", "logout", expect=2).stderr == "fake claude: auth logout is not modelled\n"
    assert run.claude("auth", "status", "--all", expect=2).stderr == "fake claude: unknown option --all\n"
    assert run.claude("auth", "login", "--email", expect=2).stderr == "fake claude: --email needs a value\n"


# print mode with the argv provision builds

def test_the_start_and_wake_argv_provision_builds_run_end_to_end(run):
    server, _ = run.probe("aegis_mailbox", ("mailbox_inbox", "mailbox_publish"))
    connection = run.connection({"aegis_mailbox": server})
    session = str(uuid.uuid4())
    request = {"model": "claude-opus-5-5", "effort": "max", "ultracode": True, "add_dirs": [str(run.tmp)]}
    assistants = json.dumps({"helper": {"description": "A helper.", "prompt": "Help."}})
    start = provision_argv(["--session-id", session], connection, WRITER + ["Agent"], request=request,
                           assistants=assistants, allowed=("mcp__aegis_mailbox__mailbox_inbox", "Edit", "Write"))
    assert "--agents" in start and "--disallowedTools" in start and "--settings" in start and "--add-dir" in start

    started = events(run.claude(*start, stdin="Start."))
    assert [event["type"] for event in started] == ["system", "assistant", "result"]
    init, reply, result = started
    assert init["subtype"] == "init" and init["session_id"] == session and init["cwd"] == str(run.cwd)
    assert init["tools"] == WRITER + ["Agent", "mcp__aegis_mailbox__mailbox_inbox", "mcp__aegis_mailbox__mailbox_publish"]
    assert init["mcp_servers"] == [{"name": "aegis_mailbox", "status": "connected"}]
    assert (init["model"], init["permissionMode"], init["apiKeySource"], init["claude_code_version"]) == (
        "claude-opus-5-5", "manual", "none", "0.0.0-fake")
    assert reply["session_id"] == session
    assert reply["message"]["content"] == [{"type": "text", "text": "done"}]
    assert (reply["message"]["role"], reply["message"]["model"], reply["message"]["usage"]) == (
        "assistant", "claude-opus-5-5", DEFAULT_USAGE)
    assert result == {"type": "result", "subtype": "success", "is_error": False, "num_turns": 1, "session_id": session,
                      "total_cost_usd": 0.0, "usage": DEFAULT_USAGE}

    transcript = run.transcript(session)
    records = lines(transcript)
    assert [record["type"] for record in records] == ["user", "assistant"]
    assert records[0]["message"] == {"role": "user", "content": "Start."}
    assert (records[0]["sessionId"], records[0]["cwd"]) == (session, str(run.cwd))
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z", records[0]["timestamp"])
    assert uuid.UUID(records[0]["uuid"])
    assert records[1]["message"] == reply["message"] and records[1]["sessionId"] == session

    wake = provision_argv(["--resume", session], connection, WRITER, request={"model": "claude-opus-5-5"})
    woke = events(run.claude(*wake, stdin="Wake."))
    assert [event["type"] for event in woke] == ["system", "assistant", "result"]
    assert all(event["session_id"] == session for event in woke)
    records = lines(transcript)
    assert [record["type"] for record in records] == ["user", "assistant", "user", "assistant"]
    assert records[2]["message"]["content"] == "Wake."
    assert list((run.config / "projects").glob("*/*.jsonl")) == [transcript]
    assert [(call["argv"], call["cwd"], call["config_dir"], call["billing"]) for call in run.calls()[-2:]] == [
        (start, str(run.cwd), str(run.config), []), (wake, str(run.cwd), str(run.config), [])]


def test_the_meter_counts_one_turn_per_invocation_from_the_fake_transcript(run, monkeypatch):
    connection = run.connection({})
    session = str(uuid.uuid4())
    run.claude(*provision_argv(["--session-id", session], connection))
    run.claude(*provision_argv(["--resume", session], connection))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(run.config))
    transcript = run.transcript(session)
    assert hierarchy_meter.find_transcript("claude-code", session) == transcript
    measured = hierarchy_meter.measure("claude-code", session)
    assert (measured["turns"], measured["open_turn"], measured["unknown_intervals"], measured["malformed_lines"],
            measured["state"], measured["transcript"]) == (2, False, [], 0, "ok", str(transcript))
    # A failed turn leaves a prompt with no reply, which the meter keeps as unknown instead of inventing an end.
    run.claude(*provision_argv(["--resume", session], connection), expect=1, FAKE_CLAUDE_MODE="fail")
    measured = hierarchy_meter.measure("claude-code", session)
    assert (measured["turns"], measured["open_turn"], len(measured["unknown_intervals"])) == (2, True, 1)


def test_a_session_id_already_used_in_any_project_folder_is_refused(run):
    connection = run.connection({})
    run.claude(*provision_argv(["--session-id", SESSION], connection))
    other = run.tmp / "other"
    other.mkdir()
    refused = run.claude(*provision_argv(["--session-id", SESSION], connection), expect=1, cwd=other)
    assert refused.stderr == "fake claude: session %s is already in use\n" % SESSION and refused.stdout == ""
    assert not (run.config / "projects" / slug(other)).exists()
    assert len(lines(run.transcript(SESSION))) == 2


def test_resume_looks_only_in_the_cwd_project_folder(run):
    connection = run.connection({})
    run.claude(*provision_argv(["--session-id", SESSION], connection))
    other = run.tmp / "other"
    other.mkdir()
    refused = run.claude(*provision_argv(["--resume", SESSION], connection), expect=1, cwd=other)
    assert refused.stderr == "fake claude: no conversation found for session %s in %s\n" % (
        SESSION, run.config / "projects" / slug(other))
    unknown = str(uuid.uuid4())
    refused = run.claude(*provision_argv(["--resume", unknown], connection), expect=1)
    assert refused.stderr == "fake claude: no conversation found for session %s in %s\n" % (
        unknown, run.config / "projects" / slug(run.cwd))
    # From another cwd, a relative climb into the first cwd's folder would reach the real transcript.
    traversal = "../%s/%s" % (slug(run.cwd), SESSION)
    refused = run.claude(*provision_argv(["--resume", traversal], connection), expect=1, cwd=other)
    assert refused.stderr == "fake claude: no conversation found for session %s in %s\n" % (
        traversal, run.config / "projects" / slug(other))
    assert not (run.config / "projects" / slug(other)).exists()
    assert len(lines(run.transcript(SESSION))) == 2


@pytest.mark.parametrize("flags,stderr", [
    ([], ONE_SESSION),
    (["--session-id", SESSION, "--resume", SESSION], ONE_SESSION),
    (["--session-id", SESSION.upper()], "fake claude: --session-id must be a canonical UUID: %s\n" % SESSION.upper()),
    (["--session-id", SESSION.replace("-", "")],
     "fake claude: --session-id must be a canonical UUID: %s\n" % SESSION.replace("-", "")),
    (["--session-id", "pilot-orchestrator"], "fake claude: --session-id must be a canonical UUID: pilot-orchestrator\n"),
])
def test_a_print_turn_needs_exactly_one_well_formed_session(run, flags, stderr):
    refused = run.claude(*provision_argv(flags, run.connection({})), expect=1)
    assert refused.stderr == stderr and refused.stdout == ""
    assert not (run.config / "projects").exists()


def test_print_mode_needs_a_login_and_writes_nothing_without_one(fresh):
    refused = fresh.claude(*provision_argv(["--session-id", SESSION], fresh.connection({})), expect=1)
    assert refused.stderr == "fake claude: not logged in\n" and refused.stdout == ""
    assert not (fresh.config / "projects").exists()


def test_stream_json_without_verbose_is_refused(run):
    argv = provision_argv(["--session-id", SESSION], run.connection({}))
    argv.remove("--verbose")
    refused = run.claude(*argv, expect=1)
    assert refused.stderr == "fake claude: --output-format stream-json with --print needs --verbose\n"
    assert not (run.config / "projects").exists()


@pytest.mark.parametrize("change,stderr", [
    (lambda argv: argv + ["--dangerously-skip-permissions"], "fake claude: unknown option --dangerously-skip-permissions\n"),
    (lambda argv: ["prompt-as-argument"] + argv, "fake claude: unknown option prompt-as-argument\n"),
    (lambda argv: argv + ["--model"], "fake claude: --model needs a value\n"),
    (lambda argv: [word for word in argv if word not in ("--print", "-p")],
     "fake claude: only print mode (-p) and auth are modelled\n"),
    (lambda argv: [("text" if word == "stream-json" else word) for word in argv],
     "fake claude: only --output-format stream-json is modelled\n"),
    (lambda argv: ["--background"] + argv, "fake claude: background mode is not modelled\n"),
    (lambda argv: argv + ["--name", "pilot/orchestrator-g1"], "fake claude: --name is not modelled\n"),
    (lambda argv: argv + ["-n", "pilot/orchestrator-g1"], "fake claude: -n is not modelled\n"),
])
def test_unmodelled_print_options_are_refused(run, change, stderr):
    refused = run.claude(*change(provision_argv(["--session-id", SESSION], run.connection({}))), expect=2)
    assert refused.stderr == stderr and refused.stdout == ""
    assert not (run.config / "projects").exists()


def test_the_background_argv_provision_builds_is_refused(run):
    argv = provision_argv(["--session-id", SESSION], run.connection({}), name="pilot/orchestrator-g1")
    assert argv[0] == "--bg"
    refused = run.claude(*argv, expect=2)
    assert refused.stderr == "fake claude: background mode is not modelled\n"


def test_words_after_a_bare_double_dash_are_the_prompt_and_variadic_lists_stop_at_options(run):
    connection = run.connection({})
    first, second = str(uuid.uuid4()), str(uuid.uuid4())
    run.claude(*provision_argv(["--session-id", first], connection), "--", "Read", "the", "brief.", stdin="ignored")
    assert lines(run.transcript(first))[0]["message"]["content"] == "Read the brief."
    # Without `--`, the trailing variadic --allowedTools swallows following words, as it did on a real host.
    argv = provision_argv(["--session-id", second], connection) + ["swallowed"]
    run.claude(*argv, "--allowed-tools", "Edit", "--disallowedTools", "Bash", "--disallowed-tools", "Write",
               stdin="From stdin.")
    assert lines(run.transcript(second))[0]["message"]["content"] == "From stdin."


def test_variadic_lists_stop_at_any_option_word(run):
    argv = ["--session-id", SESSION, "--output-format", "stream-json", "--verbose", "--allowedTools", "Read", "Edit",
            "-p", "--disallowedTools", "Bash", "-r"]
    refused = run.claude(*argv, expect=2)
    assert refused.stderr == "fake claude: -r needs a value\n", "-p and -r were options, not tool names"
    started = events(run.claude(*argv[:-1]))
    assert [event["type"] for event in started] == ["system", "assistant", "result"]


@pytest.mark.parametrize("stdin,words", [("", []), (" \n", []), ("ignored", ["--"]), ("ignored", ["--", " "])])
def test_an_empty_prompt_is_refused(run, stdin, words):
    refused = run.claude(*provision_argv(["--session-id", SESSION], run.connection({})), *words, stdin=stdin, expect=2)
    assert refused.stderr == "fake claude: empty prompt\n" and refused.stdout == ""
    assert not (run.config / "projects").exists()


# init event

@pytest.mark.parametrize("extra,tools", [
    (["--restricted"], ["Edit", "Glob", "Grep", "Read", "Write"]),
    ([], ["Bash", "Edit", "Glob", "Grep", "Read", "Write"]),
    (["--tools", "Read,Grep"], ["Read", "Grep"]),
    (["--tools=Read,Grep"], ["Read", "Grep"]),
    (["--tools="], []),
    (["--tools", ""], []),
])
def test_offered_tools_follow_the_tools_option(run, extra, tools):
    init = events(run.claude(*print_argv(*extra)))[0]
    assert init["tools"] == tools and init["mcp_servers"] == []


def test_extra_tools_and_a_served_model_show_in_init(run):
    started = events(run.claude(*print_argv("--tools=Read", "--model", "claude-opus-5-5"),
                                FAKE_CLAUDE_EXTRA_TOOLS="Bash,Agent", FAKE_CLAUDE_SERVED_MODEL="claude-other"))
    init, reply = started[0], started[1]
    assert init["tools"] == ["Read", "Bash", "Agent"]
    assert init["model"] == reply["message"]["model"] == "claude-other"
    assert init["permissionMode"] == "default"
    session = str(uuid.uuid4())
    assert events(run.claude(*print_argv(session=session)))[0]["model"] == "claude-fake-default"


def test_mcp_tools_are_listed_and_mcp_children_never_see_a_session_variable(run):
    server, record = run.probe("probe", ("echo", "ping"))
    broken = {"command": sys.executable, "args": ["-c", "import sys; sys.exit(3)"]}
    connection = run.connection({"probe": server, "broken": broken, "remote": {"type": "http", "url": "http://x.invalid"}})
    init = events(run.claude(*provision_argv(["--session-id", SESSION], connection),
                             CLAUDE_CODE_SESSION_ID="leaked-session", CLAUDECODE="1", FAKE_PROBE_PASSTHROUGH="kept"))[0]
    assert init["mcp_servers"] == [{"name": "probe", "status": "connected"}, {"name": "broken", "status": "failed"},
                                   {"name": "remote", "status": "failed"}]
    assert init["tools"] == READER + ["mcp__probe__echo", "mcp__probe__ping"]
    [seen] = lines(record)
    assert "CLAUDE_CODE_SESSION_ID" not in seen and "CLAUDECODE" not in seen
    assert seen["FAKE_PROBE_PASSTHROUGH"] == "kept" and seen["CLAUDE_CONFIG_DIR"] == str(run.config)


def test_no_outer_session_variable_reaches_an_mcp_child_or_the_fake_host(run, tmp_path):
    server, record = run.probe("aegis_mailbox", ("mailbox_inbox",))
    server["args"] += ["--endpoint", "pilot/x"]
    plan, host_log = tmp_path / "plan.json", tmp_path / "host.jsonl"
    plan.write_text(json.dumps({"pilot/x": {}}), encoding="utf-8")
    run.claude(*provision_argv(["--session-id", SESSION], run.connection({"aegis_mailbox": server})),
               FAKE_HOST_PLAN=str(plan), FAKE_HOST_LOG=str(host_log), FAKE_PROBE_PASSTHROUGH="kept", **OUTER_SESSION)
    assert lines(host_log)[0]["endpoint"] == "pilot/x"
    # The fake's own tools/list start, then the adapter the fake host started with the environment it was given.
    probed, hosted = lines(record)
    for seen in (probed, hosted):
        assert not set(OUTER_SESSION) & set(seen), sorted(set(OUTER_SESSION) & set(seen))
        assert seen["FAKE_PROBE_PASSTHROUGH"] == "kept" and seen["CLAUDE_CONFIG_DIR"] == str(run.config)


def test_an_mcp_server_that_never_answers_is_failed_after_the_probe_timeout(run):
    pids = run.tmp / "silent.pids"
    connection = run.connection({"silent": {"command": sys.executable, "args": ["-c", SLEEPER, str(pids)]}})
    started = time.monotonic()
    init = events(run.claude(*provision_argv(["--session-id", SESSION], connection), FAKE_CLAUDE_MCP_TIMEOUT="0.5"))[0]
    assert init["mcp_servers"] == [{"name": "silent", "status": "failed"}]
    assert time.monotonic() - started < 10, "the probe waited longer than its timeout"
    assert all(gone(int(pid)) for pid in pids.read_text().split())


@pytest.mark.parametrize("body", [None, "not json", '{"servers": {}}'])
def test_an_unreadable_mcp_config_is_refused_before_init(run, body):
    path = run.tmp / "connection.json"
    if body is not None:
        path.write_text(body, encoding="utf-8")
    refused = run.claude(*provision_argv(["--session-id", SESSION], path), expect=1)
    assert refused.stderr == "fake claude: cannot read --mcp-config %s\n" % path and refused.stdout == ""
    assert not (run.config / "projects").exists()


# turn shapes

def test_reply_and_usage_come_from_the_environment(run):
    usage = {"input_tokens": 7, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 50, "output_tokens": 9}
    started = events(run.claude(*print_argv(), FAKE_CLAUDE_REPLY="READY", FAKE_CLAUDE_USAGE=json.dumps(usage)))
    assert started[1]["message"]["content"] == [{"type": "text", "text": "READY"}]
    assert started[1]["message"]["usage"] == started[2]["usage"] == usage


@pytest.mark.parametrize("variables,stderr", [
    ({"FAKE_CLAUDE_USAGE": '{"input_tokens": 1}'},
     "fake claude: FAKE_CLAUDE_USAGE must be a JSON object with exactly input_tokens, cache_creation_input_tokens, "
     "cache_read_input_tokens, output_tokens\n"),
    ({"FAKE_CLAUDE_USAGE": "not json"},
     "fake claude: FAKE_CLAUDE_USAGE must be a JSON object with exactly input_tokens, cache_creation_input_tokens, "
     "cache_read_input_tokens, output_tokens\n"),
    ({"FAKE_CLAUDE_MODE": "explode"}, "fake claude: unknown FAKE_CLAUDE_MODE explode\n"),
    ({"FAKE_CLAUDE_MCP_TIMEOUT": "0"}, "fake claude: FAKE_CLAUDE_MCP_TIMEOUT must be a positive number of seconds\n"),
    ({"FAKE_CLAUDE_MCP_TIMEOUT": "soon"},
     "fake claude: FAKE_CLAUDE_MCP_TIMEOUT must be a positive number of seconds\n"),
    ({"FAKE_CLAUDE_TURN_TIMEOUT": "-1"},
     "fake claude: FAKE_CLAUDE_TURN_TIMEOUT must be a positive number of seconds\n"),
    ({"FAKE_CLAUDE_TURN_TIMEOUT": "nan"},
     "fake claude: FAKE_CLAUDE_TURN_TIMEOUT must be a positive number of seconds\n"),
])
def test_malformed_knobs_are_refused_before_the_turn(run, variables, stderr):
    refused = run.claude(*print_argv(), expect=2, **variables)
    assert refused.stderr == stderr and refused.stdout == ""
    assert not (run.config / "projects").exists()


def test_no_result_mode_ends_without_a_result_like_a_killed_turn(run):
    started = events(run.claude(*print_argv(), FAKE_CLAUDE_MODE="no-result"))
    assert [event["type"] for event in started] == ["system", "assistant"]
    assert [record["type"] for record in lines(run.transcript(SESSION))] == ["user", "assistant"]


def test_fail_mode_reports_an_error_result_and_no_reply(run):
    started = events(run.claude(*print_argv(), expect=1, FAKE_CLAUDE_MODE="fail"))
    assert [event["type"] for event in started] == ["system", "result"]
    assert (started[1]["subtype"], started[1]["is_error"], started[1]["session_id"]) == (
        "error_during_execution", True, SESSION)
    assert [record["type"] for record in lines(run.transcript(SESSION))] == ["user"]


def test_hang_mode_emits_init_and_then_waits_until_killed(run):
    process = subprocess.Popen([run.command(), *print_argv()], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, cwd=str(run.cwd),
                               env=run.env(FAKE_CLAUDE_MODE="hang"))
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            process.communicate("Wait.", timeout=2)
    finally:
        process.kill()
    stdout, _ = process.communicate(timeout=10)
    assert process.returncode == -9
    assert [event["type"] for event in events(stdout)] == ["system"]
    assert [record["type"] for record in lines(run.transcript(SESSION))] == ["user"]


# the real mailbox adapter

def test_the_fake_drives_the_real_mailbox_adapter_through_the_fake_host(run, tmp_path, monkeypatch):
    # The provision helper's own subprocesses copy os.environ; keep this session's Claude variables out of them too.
    for key in [key for key in os.environ if key.startswith("CLAUDE")]:
        monkeypatch.delenv(key)
    # The adapter checks its pinned source with git before it answers, so the sealed folder links git, as the team
    # tests do.
    found = shutil.which("git")
    assert found, "git is needed by the adapter under test"
    (run.bin / "git").symlink_to(found)
    from tests.integration.test_hierarchy_mailbox import invoke
    from tests.integration.test_hierarchy_provision import Setup
    (tmp_path / "team").mkdir()
    setup = Setup(tmp_path / "team")
    setup.init()
    role = setup.add_role("pilot/orchestrator", cwd=str(run.cwd))
    invoke(setup.root, "bind", {"endpoint": "pilot/front-door", "host": "h", "session": "fd", "expected_generation": 0})
    argv = role["start_argv"][role["start_argv"].index("claude") + 1:]
    plan, host_log = tmp_path / "plan.json", tmp_path / "host.jsonl"
    plan.write_text(json.dumps({"pilot/orchestrator": {"send": [
        {"message_id": "hello", "to": "pilot/front-door", "type": "info", "body": "Hello from the fake claude."}]}}),
        encoding="utf-8")
    started = events(run.claude(*argv, stdin="Start.", FAKE_HOST_PLAN=str(plan), FAKE_HOST_LOG=str(host_log)))
    assert [event["type"] for event in started] == ["system", "assistant", "result"]
    assert started[0]["session_id"] == role["session"]
    assert started[0]["mcp_servers"] == [{"name": "aegis_mailbox", "status": "connected"}]
    assert "mcp__aegis_mailbox__mailbox_publish" in started[0]["tools"]
    [hosted] = lines(host_log)
    assert (hosted["endpoint"], hosted["argv"], hosted["stdin"], hosted["cwd"]) == (
        "pilot/orchestrator", argv, "Start.", str(run.cwd))
    [published] = lines(str(host_log) + ".published")
    assert published["endpoint"] == "pilot/orchestrator" and "error" not in published["result"], published
    [delivered] = invoke(setup.root, "inbox", endpoint="pilot/front-door")["messages"]
    assert (delivered["message"]["message_id"], delivered["message"]["from"], delivered["message"]["host"],
            delivered["message"]["session"]) == ("hello", "pilot/orchestrator", "claude-code", role["session"])
    assert [record["type"] for record in lines(run.transcript(role["session"]))] == ["user", "assistant"]


def test_a_failing_fake_host_turn_sets_the_exit_code_after_the_events(run, tmp_path):
    server, _ = run.probe("aegis_mailbox", ("mailbox_inbox",))
    connection = run.connection({"aegis_mailbox": {**server, "args": server["args"] + ["--endpoint", "pilot/x"]}})
    plan, host_log = tmp_path / "plan.json", tmp_path / "host.jsonl"
    plan.write_text(json.dumps({"pilot/x": {"exit": 5}}), encoding="utf-8")
    result = run.claude(*provision_argv(["--session-id", SESSION], connection), expect=5,
                        FAKE_HOST_PLAN=str(plan), FAKE_HOST_LOG=str(host_log))
    assert [event["type"] for event in events(result)] == ["system", "assistant", "result"]
    assert lines(host_log)[0]["endpoint"] == "pilot/x"
    # Without a plan there is no mailbox turn at all.
    run.claude(*provision_argv(["--session-id", str(uuid.uuid4())], connection), FAKE_HOST_LOG=str(host_log))
    assert len(lines(host_log)) == 1


def hanging_turn(run, tmp_path):
    """A connection whose adapter never answers, and a plan that sends the fake host to it."""
    pids, plan, host_log = tmp_path / "adapter.pids", tmp_path / "plan.json", tmp_path / "host.jsonl"
    server = {"command": sys.executable, "args": ["-c", SLEEPER, str(pids), "--endpoint", "pilot/x"]}
    plan.write_text(json.dumps({"pilot/x": {}}), encoding="utf-8")
    argv = provision_argv(["--session-id", SESSION], run.connection({"aegis_mailbox": server}))
    return argv, pids, {"FAKE_HOST_PLAN": str(plan), "FAKE_HOST_LOG": str(host_log), "FAKE_CLAUDE_MCP_TIMEOUT": "0.5"}


def test_a_fake_host_turn_that_overruns_is_killed_with_its_process_group(run, tmp_path):
    argv, pids, knobs = hanging_turn(run, tmp_path)
    started = time.monotonic()
    refused = run.claude(*argv, expect=1, timeout=20, FAKE_CLAUDE_TURN_TIMEOUT="1", **knobs)
    assert refused.stderr == "fake claude: turn timed out\n"
    assert [event["type"] for event in events(refused)] == ["system"]
    assert time.monotonic() - started < 15
    # The probe's start, then the host's adapter, which the kill of the host's group must have taken too.
    assert len(pids.read_text().split()) == 2
    assert all(gone(int(pid)) for pid in pids.read_text().split())


def test_a_stop_sent_to_the_fake_reaches_the_fake_host_in_its_own_group(run, tmp_path):
    argv, pids, knobs = hanging_turn(run, tmp_path)
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Wait.", encoding="utf-8")
    with open(prompt, encoding="utf-8") as stdin:
        process = subprocess.Popen([run.command(), *argv], stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, cwd=str(run.cwd), start_new_session=True, env=run.env(**knobs))
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and (not pids.exists() or len(pids.read_text().split()) < 2):
            time.sleep(0.05)
        assert len(pids.read_text().split()) == 2, "the fake host never started its adapter"
        # As the wake stops a turn: a SIGTERM to the fake's own group, which the host has left.
        os.killpg(process.pid, 15)
        process.wait(timeout=10)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, 9)
        process.communicate(timeout=10)
    assert process.returncode == -15
    assert all(gone(int(pid)) for pid in pids.read_text().split())
