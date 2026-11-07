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
import signal
import subprocess
import sys
from types import SimpleNamespace
import uuid

import pytest

from tests.integration import hierarchy_fake_claude as fake
from tests.integration.test_hierarchy_launcher import (CONTRACT_FILES, REVIEW, START_FOOTER, START_HEADER, Launch,
                                                       alive, census, contract_path, lane_rules, launcher_module,
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
HOME_INVALID = "CLAUDE_CONFIG_DIR must be an absolute path to an existing folder: "
HOME_OWNERS = "CLAUDE_CONFIG_DIR is the owner's ~/.claude; a team run uses its own claude home"
HOME_LINK = "%s is a symlink; a team run's claude home keeps its own files"
NO_TRANSCRIPT = "no transcript for session %s under CLAUDE_CONFIG_DIR %s"
# Moves the newest start's transcript (or its project folder) out of the home and links it back, as a host following a
# link planted after the launcher looked would leave it.
RELINK = r"""
import os, sys
from pathlib import Path
home, outside, what = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
[transcript] = home.glob("projects/*/*.jsonl")
moved = transcript if what == "file" else transcript.parent
os.replace(moved, outside / moved.name)
moved.symlink_to(outside / moved.name, target_is_directory=what != "file")
"""
NATIVE_START = "a native codex thread is started by its own app, not the launcher"
CLAUDE_WRITER = "permission rules, not OS-enforced"
# Today's launch record keys: a Codex record must gain none.
CODEX_BOUND_KEYS = {"schema", "at", "action", "state", "endpoint", "host", "session", "generation", "argv", "cwd",
                    "contract", "contracts", "start_timeout_seconds", "exit_code", "timed_out", "connection",
                    "wake_profile", "codex_profile"}
CODEX_REFUSED_KEYS = {"schema", "at", "action", "state", "endpoint", "host", "session", "generation", "error"}
ROLES = {IMPLEMENTER: "implementer", REVIEW: "reviewer"}
FILE_TOOLS = {"implementer": "Read,Glob,Grep,Edit,Write", "reviewer": "Read,Glob,Grep"}
# A reader has nothing to allow at start, so its start argv carries no --allowedTools at all.
ALLOWED = {"implementer": ["--allowedTools", "Edit,Write"], "reviewer": []}


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
        path.write_text("#!/bin/bash\n" + body % {"python": shlex.quote(sys.executable),
                                                  "host": fake.shell_exec("claude", fake.HERE, self.tmp)}
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


def family_only_lines(hosts, role):
    """(claude-only, codex-only): the non-blank lines of the role's contract files that only one family's rendering
    has, rendered by the launcher's own host_view. Taken from the contract source, so no wording is pinned here."""
    module = launcher_module()
    views = {}
    for family in ("claude", "codex"):
        names = CONTRACT_FILES[role]
        parts = [module.host_view(contract_path(hosts, name).read_text(encoding="utf-8"), family,
                                  contract_path(hosts, name)) for name in names]
        if len(names) > 1:
            parts[0] = lane_rules(parts[0], role)
        views[family] = {line for part in parts for line in part.splitlines() if line.strip()}
    return views["claude"] - views["codex"], views["codex"] - views["claude"]


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
        "--output-format", "stream-json", "--verbose", "--disable-slash-commands", *ALLOWED[role]]
    [call] = claude_team.claude_calls()
    assert (call["argv"], call["cwd"], call["config_dir"]) == (answer["argv"][1:], str(claude_team.source),
                                                                str(claude_team.claude_home))
    assert not claude_team.codex_log.exists()

    # The prompt went on stdin from a kept file beside the start's logs, rendered for the claude family.
    prompt_file = Path(answer["prompt_file"])
    assert answer["prompt_via"] == "stdin" and prompt_file == Path(answer["log"]["stdout"]).with_suffix(".prompt")
    prompt = prompt_file.read_text(encoding="utf-8")
    assert prompt == claude_prompt(claude_team, endpoint, role)
    claude_only, codex_only = family_only_lines(claude_team, role)
    lines = set(prompt.splitlines())
    # Both non-empty, so neither check can pass vacuously.
    assert claude_only and codex_only
    assert claude_only <= lines and not codex_only & lines
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


@pytest.mark.parametrize("value", ["claude-home", "ABSENT"])
def test_a_relative_or_missing_claude_config_dir_is_refused_before_anything_runs(claude_team, value):
    value = str(claude_team.tmp / "absent-claude-home") if value == "ABSENT" else value
    refused = claude_team.start(expect=2, endpoint=IMPLEMENTER, environment={"CLAUDE_CONFIG_DIR": value})
    assert refused["error"] == HOME_INVALID + value
    assert (refused["state"], refused["host"], refused["session"]) == ("refused", CLAUDE, None)
    assert claude_team.claude_calls() == [] and unbound(claude_team, IMPLEMENTER)


def start_as_owner(hosts, monkeypatch, capsys, owner, claude_home):
    """(exit code, answer) of an in-process claude start whose owner's home is `owner`.

    The owner's home comes from the password database, which is patched to a temporary folder: the real ~/.claude is
    never named, read or written. HOME points elsewhere, since it must not be what the launcher trusts.
    """
    write_plan(hosts, CLAUDE)
    import pwd
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=str(owner)))
    for key in [key for key in os.environ if key.startswith(("CLAUDE", "ANTHROPIC"))]:
        monkeypatch.delenv(key)
    for key, setting in hosts.env(CLAUDE_CONFIG_DIR=str(claude_home), HOME=str(hosts.tmp)).items():
        monkeypatch.setenv(key, setting)
    module = launcher_module()
    code = module.main(["--base", str(hosts.base), "start", "--request",
                        str(hosts.start_request(endpoint=IMPLEMENTER))])
    monkeypatch.undo()
    return code, json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("where", ["itself", "inside", "through a link"])
def test_the_owners_own_claude_home_is_refused_before_anything_runs(hosts, monkeypatch, capsys, where):
    owner = hosts.tmp / "owner"
    (owner / ".claude" / "inside").mkdir(parents=True)
    value = {"itself": owner / ".claude", "inside": owner / ".claude" / "inside", "through a link": hosts.tmp / "link"}
    if where == "through a link":
        value[where].symlink_to(owner / ".claude", target_is_directory=True)
    code, refused = start_as_owner(hosts, monkeypatch, capsys, owner, value[where])
    assert code == 2 and refused["error"] == HOME_OWNERS
    assert (refused["state"], refused["host"], refused["session"]) == ("refused", CLAUDE, None)
    assert [row["state"] for row in hosts.records(IMPLEMENTER)] == ["refused"]
    assert hosts.claude_calls() == [] and unbound(hosts, IMPLEMENTER)


@pytest.mark.parametrize("name", ["projects", ".claude.json", "sessions", ".credentials.json",
                                  "projects/-elsewhere-project"])
def test_a_run_home_entry_linked_into_the_owners_claude_home_is_refused_before_anything_runs(hosts, monkeypatch,
                                                                                             capsys, name):
    # A separate folder, logged in, so that without the check the start would run and write its transcript through
    # the link into the owner's own history.
    owner = hosts.tmp / "owner"
    for folder in ("projects/-elsewhere-project", "sessions"):
        (owner / ".claude" / folder).mkdir(parents=True)
    for file in (".claude.json", ".credentials.json"):
        (owner / ".claude" / file).write_text("{}", encoding="utf-8")
    run_home = hosts.tmp / "run-claude-home"
    run_home.mkdir(mode=0o700)
    hosts.login(run_home)
    linked = run_home / name
    if linked.exists():
        linked.unlink()
    linked.parent.mkdir(exist_ok=True)
    linked.symlink_to(owner / ".claude" / name, target_is_directory=(owner / ".claude" / name).is_dir())
    before = sorted(owner.rglob("*"))
    code, refused = start_as_owner(hosts, monkeypatch, capsys, owner, run_home)
    assert code == 2 and refused["error"] == HOME_LINK % linked, refused
    assert (refused["state"], refused["host"], refused["session"]) == ("refused", CLAUDE, None)
    assert [row["state"] for row in hosts.records(IMPLEMENTER)] == ["refused"]
    assert hosts.claude_calls() == [] and unbound(hosts, IMPLEMENTER)
    assert sorted(owner.rglob("*")) == before


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
    claude_team.wrap_claude("(%%(host)s \"$@\") | %s 's/\"session_id\": \"[^\"]*\"/\"session_id\": \"%s\"/g'"
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
    claude_team.wrap_claude("CLAUDE_CONFIG_DIR=%s %%(host)s \"$@\"" % shlex.quote(str(elsewhere)))
    answer = claude_team.start(expect=3, endpoint=IMPLEMENTER)
    session = chosen(answer)
    assert answer["state"] == "failed_to_start" and answer["session"] is None and answer["exit_code"] == 0
    assert answer["error"] == "no transcript for session %s under CLAUDE_CONFIG_DIR %s" % (session,
                                                                                            claude_team.claude_home)
    assert hierarchy_hosts.transcripts(CLAUDE, elsewhere, session)
    assert [row["state"] for row in claude_team.records(IMPLEMENTER)] == ["failed_to_start"]
    assert unbound(claude_team, IMPLEMENTER)


@pytest.mark.parametrize("what", ["file", "folder"])
def test_a_transcript_that_is_a_symlink_or_resolves_outside_the_home_does_not_confirm_a_start(claude_team, tmp_path,
                                                                                              what):
    outside, relink = tmp_path / "outside", tmp_path / "relink.py"
    outside.mkdir()
    relink.write_text(RELINK, encoding="utf-8")
    claude_team.wrap_claude("(%%(host)s \"$@\")\ncode=$?\n%%(python)s -I %s \"$CLAUDE_CONFIG_DIR\" %s %s\n"
                            "exit $code" % (shlex.quote(str(relink)), shlex.quote(str(outside)), what))
    answer = claude_team.start(expect=3, endpoint=IMPLEMENTER)
    session = chosen(answer)
    # Found by a plain glob, which follows links: the shared locator, hierarchy_hosts.transcripts, skips them.
    [found] = claude_team.claude_home.glob("projects/*/%s.jsonl" % session)
    assert (found.is_symlink(), found.parent.is_symlink()) == (what == "file", what == "folder")
    assert found.is_file() and claude_team.claude_home.resolve() not in found.resolve().parents
    assert hierarchy_hosts.transcripts(CLAUDE, claude_team.claude_home, session) == []
    # So the run's home holds no transcript that counts, and the start is not confirmed.
    assert answer["state"] == "failed_to_start" and answer["session"] is None and answer["exit_code"] == 0
    assert answer["error"] == NO_TRANSCRIPT % (session, claude_team.claude_home)
    assert [row["state"] for row in claude_team.records(IMPLEMENTER)] == ["failed_to_start"]
    assert unbound(claude_team, IMPLEMENTER)


def test_a_start_whose_output_has_no_init_event_is_a_failed_start(claude_team):
    # grep by its absolute path: the sealed PATH holds no grep.
    claude_team.wrap_claude("(%%(host)s \"$@\") | %s -v '\"subtype\": \"init\"'"
                            % shlex.quote(shutil.which("grep")))
    answer = claude_team.start(expect=3, endpoint=IMPLEMENTER)
    assert answer["state"] == "failed_to_start" and answer["session"] is None and answer["exit_code"] == 0
    assert "error" not in answer and '"type": "result"' in Path(answer["log"]["stdout"]).read_text()
    assert [row["state"] for row in claude_team.records(IMPLEMENTER)] == ["failed_to_start"]
    assert unbound(claude_team, IMPLEMENTER)


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root writes into a read-only folder")
def test_a_prompt_file_that_cannot_be_written_refuses_the_start_before_anything_runs(claude_team):
    logs = claude_team.base / "launches" / quoted(IMPLEMENTER) / "logs"
    logs.mkdir(parents=True, mode=0o700)
    logs.chmod(0o500)
    try:
        refused = claude_team.start(expect=2, endpoint=IMPLEMENTER)
    finally:
        logs.chmod(0o700)
    assert refused["error"].startswith("[Errno 13] Permission denied: ") and refused["error"].endswith(".prompt'")
    assert (refused["state"], refused["host"], refused["session"]) == ("refused", CLAUDE, None)
    assert list(logs.iterdir()) == [] and claude_team.claude_calls() == [] and unbound(claude_team, IMPLEMENTER)


def test_an_interrupted_claude_start_is_stopped_and_recorded(claude_team):
    logs = claude_team.base / "launches" / quoted(IMPLEMENTER) / "logs"
    request = claude_team.start_request(endpoint=IMPLEMENTER)
    running = subprocess.Popen(claude_team.argv("start", "--request", str(request)), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, env=claude_team.env(FAKE_CLAUDE_MODE="hang"))
    try:
        wait_until(lambda: any('"subtype": "init"' in path.read_text() for path in logs.glob("*.stdout")), 30)
        [call] = claude_team.claude_calls()
        running.send_signal(signal.SIGTERM)
        out, err = running.communicate(timeout=20)
        assert running.returncode == 3 and err == "", out + err
        answer = json.loads(out)
        assert answer["state"] == "start_incomplete" and answer["error"] == "the launcher was interrupted"
        assert answer["session"] == chosen(answer) and not alive(call["pid"])
        assert [row["state"] for row in claude_team.records(IMPLEMENTER)] == ["start_incomplete"]
        assert not (logs.parent / ".start.lock").exists() and unbound(claude_team, IMPLEMENTER)
    finally:
        if running.poll() is None:
            running.kill()
            running.wait(timeout=5)


@pytest.mark.parametrize("mode,timeout,timed_out", [("fail", 300, False), ("hang", 5, True)])
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
        wait_until(lambda: launcher_module().session_processes(session, set(), CLAUDE) == [(hung.pid, hung.pid)])
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


def test_a_host_plan_nested_too_deep_to_read_is_a_recorded_refusal(hosts):
    depth = 100000
    (hosts.base / "host-plan.json").write_text("[" * depth + "]" * depth, encoding="utf-8")
    refused = hosts.start(expect=2)
    assert (refused["state"], refused["host"], refused["session"]) == ("refused", None, None)
    assert "recursion" in refused["error"]
    assert [row["state"] for row in hosts.records()] == ["refused"]
    assert not hosts.codex_log.exists() and unbound(hosts, REVIEW)


def test_the_harness_path_holds_only_the_fakes_and_the_linked_tools(hosts):
    assert sorted(path.name for path in hosts.bin.iterdir()) == ["claude", "codex", "git", "ps"]
    assert fake.require_fake(hosts.env()["PATH"])
