"""Provisioning builds a working initiative: real adapter connections and wake profiles per role.

Generated connections are started through the real adapter here. Host CLIs are not run, so these
tests show the profiles are well formed and match the flags that worked on real hosts, not that a
host accepts them today.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

import pytest

from tests.integration.test_hierarchy_mailbox import HELPER, ROOT, git, invoke
from tests.integration.test_hierarchy_workspace import Workspace


# Generated profiles use POSIX paths and the wake tool needs POSIX process groups.
pytestmark = pytest.mark.skipif(os.name == "nt", reason="generated profiles and wakes are POSIX only")
PROVISION = ROOT / "tools" / "hierarchy_provision.py"
WAKE = ROOT / "tools" / "hierarchy_wake.py"
INITIATIVE = {"id": "pilot", "project": "aegis", "repository": "aegis", "priority": 5, "target_branch": "develop"}
LANES = {"f2": "implementer", "integration": "integrator", "review": "reviewer"}
MAILBOX_TOOLS = {"mailbox_inbox", "mailbox_publish", "mailbox_ack_handoff", "mailbox_self"}


def provision(command, request, *, expect=0):
    path = Path(request.pop("_request_path"))
    path.write_text(json.dumps(request), encoding="utf-8")
    result = subprocess.run([sys.executable, "-I", str(PROVISION), command, "--request", str(path)], capture_output=True,
                            text=True, timeout=60, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert not result.stderr, result.stderr
    assert result.returncode == expect, result.stdout
    return json.loads(result.stdout)


class Setup:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.base = tmp_path / "initiatives" / "pilot"
        self.workspace = Workspace(tmp_path)
        self.workspace.run("init", {"writer_limit": 3, "heavy_limit": 3})
        self.source = tmp_path / "source"
        (self.source / "tools").mkdir(parents=True)
        for path in (ROOT / "tools").glob("hierarchy_*.py"):
            shutil.copy(path, self.source / "tools" / path.name)
        templates = self.source / "tools" / "hierarchy_templates"
        shutil.copytree(ROOT / "tools" / "hierarchy_templates", templates)
        git(self.source, "init", "-q", "-b", "develop")
        git(self.source, "add", ".")
        git(self.source, "commit", "-qm", "pinned source")

    def request(self, **body):
        return {"_request_path": str(self.tmp / ("request-%s.json" % uuid.uuid4().hex)), **body}

    def init_request(self, **changes):
        return self.request(store=str(self.workspace.store), base=str(self.base), source=str(self.source),
                            initiative=dict(INITIATIVE), lanes=LANES, **changes)

    def init(self):
        return provision("init", self.init_request())

    def add_role(self, endpoint, host="claude-code", *, expect=0, **changes):
        return provision("add-role", self.request(base=str(self.base), endpoint=endpoint, host=host, **changes), expect=expect)

    @property
    def root(self):
        return self.base / "mailbox"


@pytest.fixture
def setup(tmp_path):
    built = Setup(tmp_path)
    built.init()
    return built


def test_init_builds_the_mailbox_registers_the_initiative_and_pins_the_source(setup):
    manifest = json.loads((setup.root / "manifest.json").read_text())
    assert set(manifest["endpoints"]) == {"pilot/front-door", "pilot/orchestrator", "pilot/root", "pilot/lane/f2",
                                          "pilot/lane/integration", "pilot/lane/review"}
    assert manifest["endpoints"]["pilot/lane/review"] == {"kind": "reviewer"}
    assert manifest["writer_limit"] == 3
    record = setup.workspace.run("status")["initiatives"]["pilot"]
    assert record["mailbox_root"] == str(setup.root) and record["delivery_dir"] == str(setup.base / "delivery")
    pinned = json.loads((setup.base / "provision.json").read_text())
    assert pinned["source_commit"] == git(setup.source, "rev-parse", "HEAD")
    assert pinned["source_tree"] == git(setup.source, "rev-parse", "HEAD^{tree}")


def test_init_refuses_an_existing_base(setup):
    request = setup.init_request()
    request["initiative"] = {**INITIATIVE, "id": "second"}
    refused = provision("init", request, expect=2)
    assert refused["error"] == "initiative base already exists: " + str(setup.base)
    assert "second" not in setup.workspace.run("status")["initiatives"]


def test_a_dirty_source_is_refused_because_every_adapter_runs_from_it(tmp_path):
    built = Setup(tmp_path)
    (built.source / "uncommitted.txt").write_text("not pinned")
    refused = provision("init", built.init_request(), expect=2)
    assert refused["error"] == "source checkout must be clean so adapters run exact committed code"
    assert not built.base.exists()


def test_a_source_that_is_not_a_checkout_is_refused(tmp_path):
    built = Setup(tmp_path)
    source = tmp_path / "never-a-checkout"
    source.mkdir()
    request = built.init_request()
    request["source"] = str(source)
    assert provision("init", request, expect=2)["error"] == "source checkout is not a git checkout: " + str(source)
    assert not built.base.exists()


def test_a_duplicate_initiative_or_missing_store_creates_nothing(tmp_path):
    built = Setup(tmp_path)
    built.workspace.register("pilot")
    assert provision("init", built.init_request(), expect=2)["error"] == "initiative already registered: pilot"
    assert not built.base.exists()
    request = built.init_request()
    request["store"] = str(tmp_path / "absent-store")
    assert provision("init", request, expect=2)["error"] == "workspace store is not initialized"
    assert not built.base.exists()


@pytest.mark.parametrize("change,error", [
    ({"base": "relative/base"}, "path must be absolute"),
    ({"lanes": {"f2": "wizard"}}, "invalid lane kind"),
    ({"lanes": {"../escape": "implementer"}}, "invalid lane id"),
    ({"initiative": {**INITIATIVE, "priority": 0}}, "invalid priority"),
    ({"initiative": {**INITIATIVE, "mailbox_root": "/set/by/the/tool"}}, "unexpected fields"),
    ({"run": "rm -rf /"}, "unexpected fields"),
])
def test_malformed_init_requests_are_refused(tmp_path, change, error):
    built = Setup(tmp_path)
    assert error in provision("init", {**built.init_request(), **change}, expect=2)["error"]
    assert not built.base.exists()


def start_connection(connection, server="aegis_mailbox"):
    definition = json.loads(Path(connection).read_text())["mcpServers"][server]
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    result = subprocess.run([definition["command"], *definition["args"]], input="".join(json.dumps(f) + "\n" for f in frames),
                            capture_output=True, text=True, timeout=20, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0, result.stdout + result.stderr
    return {tool["name"] for tool in json.loads(result.stdout.splitlines()[1])["result"]["tools"]}


@pytest.mark.parametrize("endpoint,extra", [
    ("pilot/front-door", {"workspace_initiative"}),
    ("pilot/orchestrator", {"workspace_capacity", "workspace_initiative"}),
    ("pilot/lane/f2", {"workspace_path_overlap"}),
    ("pilot/lane/integration", {"workspace_path_overlap"}),
    ("pilot/lane/review", set()),
])
def test_each_role_gets_a_working_connection_with_only_its_tools(setup, endpoint, extra):
    role = setup.add_role(endpoint, cwd=str(setup.tmp))
    assert uuid.UUID(role["session"])
    assert role["generation"] == 1
    assert start_connection(role["connection"]) == MAILBOX_TOOLS | extra
    definition = json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_mailbox"]
    assert str(setup.source / "tools" / "hierarchy_mailbox.py") in definition["args"]
    assert str(setup.base / "delivery") in definition["args"]


def test_a_claude_profile_uses_the_flags_that_worked_on_a_real_host(setup):
    role = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp), model="claude-opus-5-5", effort="max",
                          add_dirs=[str(setup.source)], timeout_seconds=600)
    wake = json.loads(Path(role["wake_profile"]).read_text())
    argv = wake["argv"]
    assert wake["prompt_via"] == "stdin", "a trailing variadic flag consumed the prompt on the real host"
    assert wake["timeout_seconds"] == 600 and wake["cwd"] == str(setup.tmp)
    assert argv[0] == "claude" and "--restricted" in argv and "--strict-mcp-config" in argv and "--print" in argv
    assert "--tools=Read,Glob,Grep" in argv, "the separate empty --tools argument failed on the real host"
    assert argv[argv.index("--resume") + 1] == role["session"]
    assert argv[argv.index("--permission-mode") + 1] == "manual"
    assert argv[argv.index("--permission-prompts") + 1] == "none"
    assert argv[argv.index("--mcp-config") + 1] == role["connection"]
    assert argv[argv.index("--model") + 1] == "claude-opus-5-5"
    assert argv[argv.index("--add-dir") + 1] == str(setup.source)
    allowed = argv[argv.index("--allowedTools") + 1].split(",")
    assert set(allowed) == {"mcp__aegis_mailbox__" + name for name in MAILBOX_TOOLS | {"workspace_capacity", "workspace_initiative"}}
    start = role["start_argv"]
    assert start[start.index("--session-id") + 1] == role["session"] and "--resume" not in start


@pytest.mark.parametrize("endpoint,tools", [
    ("pilot/front-door", "--tools="),
    ("pilot/orchestrator", "--tools=Read,Glob,Grep"),
    ("pilot/lane/review", "--tools=Read,Glob,Grep"),
    ("pilot/lane/f2", "--tools=Read,Glob,Grep,Edit,Write"),
    ("pilot/lane/integration", "--tools=Read,Glob,Grep,Edit,Write"),
])
def test_claude_roles_get_only_their_default_tools(setup, endpoint, tools):
    role = setup.add_role(endpoint, cwd=str(setup.tmp))
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert tools in argv
    allowed = argv[argv.index("--allowedTools") + 1].split(",")
    assert ("Edit" in allowed) == endpoint.endswith(("f2", "integration"))


def test_the_generated_wake_profile_is_accepted_by_the_wake_tool(setup):
    role = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp))
    invoke(setup.root, "bind", {"endpoint": "pilot/front-door", "host": "h", "session": "fd", "expected_generation": 0})
    invoke(setup.root, "publish", {"message_id": "hello", "from": "pilot/front-door", "to": "pilot/orchestrator", "host": "h",
                                   "session": "fd", "binding_generation": 1, "type": "info", "body": "Hello."})
    result = subprocess.run([sys.executable, "-I", str(WAKE), "--root", str(setup.root), "--delivery-dir",
                             str(setup.base / "delivery"), "--endpoint", "pilot/orchestrator", "--profile",
                             role["wake_profile"], "--dry-run"], capture_output=True, text=True, timeout=20,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["would_wake"] == ["hello"]


def test_a_native_thread_gets_a_flat_connection_and_no_wake_profile(setup):
    role = setup.add_role("pilot/orchestrator", "codex", session="01a19a9d-b1ad-7b22-bec1-5e465d490ae6")
    assert role["wake"] == "native" and "wake_profile" not in role and "start_argv" not in role
    definition = json.loads(Path(role["connection"]).read_text())
    assert definition["command"] == "/usr/bin/python3" or Path(definition["command"]).is_absolute()
    arguments = definition["args"]
    assert arguments[arguments.index("--host") + 1] == "codex"
    assert arguments[arguments.index("--session") + 1] == "01a19a9d-b1ad-7b22-bec1-5e465d490ae6"
    assert not list((setup.base / "profiles").glob("*")) if (setup.base / "profiles").exists() else True
    frame = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    done = subprocess.run([definition["command"], *arguments], input=json.dumps(frame) + "\n", capture_output=True, text=True, timeout=20,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert {"mailbox_inbox", "mailbox_publish", "workspace_capacity"} <= {tool["name"] for tool in json.loads(done.stdout)["result"]["tools"]}


def test_a_native_thread_needs_its_actual_session(setup):
    assert "actual session" in setup.add_role("pilot/orchestrator", "codex", expect=2)["error"]


def test_root_may_be_a_native_thread(setup):
    role = setup.add_role("pilot/root", "codex", session="01a19a8e-3073-7af2-b5c0-d0c41fe82ada")
    assert role["host"] == "codex" and "connection" not in role


def test_a_moved_writer_keeps_its_real_sandbox_options(setup, tmp_path):
    writable, tmp = tmp_path / "integration", tmp_path / "private-tmp"
    writable.mkdir()
    tmp.mkdir()
    role = setup.add_role("pilot/lane/f2", "codex-cli", session="01a19969-41df-7631-8ecd-57add111e96b", cwd=str(setup.source), writable_roots=[str(writable)],
                          add_dirs=[str(writable)], tmpdir=str(tmp), effort="medium", skip_git_repo_check=True)
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    settings = [argv[index + 1] for index, word in enumerate(argv) if word == "-c"]
    assert 'sandbox_workspace_write.writable_roots=["%s"]' % writable in settings
    assert 'shell_environment_policy.set.TMPDIR="%s"' % tmp in settings
    assert 'shell_environment_policy.set.TMPPREFIX="%s/zsh"' % tmp in settings
    assert 'model_reasoning_effort="medium"' in settings
    assert argv[argv.index("--add-dir") + 1] == str(writable)
    assert "--skip-git-repo-check" in argv
    assert argv[-2:] == ["resume", "01a19969-41df-7631-8ecd-57add111e96b"]


def test_writer_options_are_checked(setup, tmp_path):
    missing = str(tmp_path / "no-such-folder")
    options = {"session": "writer-session", "cwd": str(setup.source)}
    assert "writable_roots" in setup.add_role("pilot/lane/f2", "codex-cli", writable_roots=[missing], expect=2, **options)["error"]
    assert "tmpdir" in setup.add_role("pilot/lane/f2", "codex-cli", tmpdir=missing, expect=2, **options)["error"]
    assert "writable_roots" in setup.add_role("pilot/orchestrator", "codex-cli", writable_roots=[str(tmp_path)], expect=2, **options)["error"]
    assert "skip_git_repo_check" in setup.add_role("pilot/lane/f2", "claude-code", skip_git_repo_check=True, cwd=str(tmp_path), expect=2)["error"]


def test_codex_needs_a_git_cwd_unless_a_real_lane_says_otherwise(setup, tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert "git checkout" in setup.add_role("pilot/lane/f2", "codex-cli", session="writer-session", cwd=str(plain), expect=2)["error"]
    assert setup.add_role("pilot/lane/f2", "codex-cli", session="writer-session", cwd=str(plain), skip_git_repo_check=True)["cwd"] == str(plain)


def codex_config(argv):
    tomllib = pytest.importorskip("tomllib", reason="Codex settings are read with tomllib, Python 3.11+")

    def merge(into, new):
        for key, value in new.items():
            if isinstance(value, dict) and isinstance(into.get(key), dict):
                merge(into[key], value)
            else:
                into[key] = value

    parsed = {}
    for value in [argv[index + 1] for index, word in enumerate(argv) if word == "-c"]:
        merge(parsed, tomllib.loads(value))
    return parsed


def test_a_read_only_codex_role_matches_the_profile_that_worked_on_a_real_host(setup):
    role = setup.add_role("pilot/orchestrator", "codex-cli", session="01a19a29-d635-7411-8529-9efedafc0881",
                          cwd=str(setup.source))
    wake = json.loads(Path(role["wake_profile"]).read_text())
    argv = wake["argv"]
    assert wake["prompt_via"] == "argv"
    assert argv[0] == "codex" and argv[-2:] == ["resume", "01a19a29-d635-7411-8529-9efedafc0881"]
    assert argv[argv.index("-C") + 1] == str(setup.source)
    assert argv[argv.index("--sandbox") + 1] == "read-only"
    assert "--ignore-user-config" in argv and "--json" in argv
    # multi_agent_v2 too: run 1's sessions were offered the v2 agent tools with only multi_agent disabled.
    for feature in ("shell_tool", "unified_exec", "multi_agent", "multi_agent_v2", "apps", "plugins", "memories", "goals"):
        assert feature in [argv[index + 1] for index, word in enumerate(argv) if word == "--disable"]
    config = codex_config(argv)
    assert config["approval_policy"] == "never"
    server = config["mcp_servers"]["aegis_mailbox"]
    assert server["required"] is True and server["command"] == sys.executable or server["command"].endswith("python3")
    assert set(server["enabled_tools"]) == MAILBOX_TOOLS | {"workspace_capacity", "workspace_initiative"}
    assert "--endpoint" in server["args"] and "pilot/orchestrator" in server["args"]
    assert server["tools"]["mailbox_publish"]["approval_mode"] == "approve"
    assert "start_argv" not in role, "Codex assigns its own session ID, so a session must exist before this step"


def test_a_codex_writer_gets_its_own_worktree_and_no_network(setup):
    role = setup.add_role("pilot/lane/f2", "codex-cli", session="01a19a29-d635-7411-8529-9efedafc0882", cwd=str(setup.source))
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert argv[argv.index("--sandbox") + 1] == "workspace-write"
    assert "shell_tool" not in [argv[index + 1] for index, word in enumerate(argv) if word == "--disable"]
    settings = codex_config(argv)["sandbox_workspace_write"]
    assert settings == {"writable_roots": [], "exclude_slash_tmp": True, "exclude_tmpdir_env_var": True, "network_access": False}


def test_codex_needs_a_session_and_a_git_checkout(setup):
    missing = setup.add_role("pilot/orchestrator", "codex-cli", cwd=str(setup.source), expect=2)
    assert missing["error"] == "codex assigns its own session ID; start it first and give the session here"
    outside = setup.add_role("pilot/orchestrator", "codex-cli", session="abc", cwd=str(setup.tmp), expect=2)
    assert outside["error"] == "codex needs a cwd inside a git checkout"
    assert invoke(setup.root, "status")["bindings"]["pilot/orchestrator"] is None


def test_root_gets_a_binding_but_no_connection_or_profile(setup):
    role = setup.add_role("pilot/root", "codex-cli", session="root-session-1")
    assert role["generation"] == 1 and "connection" not in role and "wake_profile" not in role
    assert invoke(setup.root, "status")["bindings"]["pilot/root"]["session"] == "root-session-1"
    assert not list((setup.base / "connections").glob("*root*"))


def test_add_role_with_the_manifest_kind_is_accepted(setup):
    assert setup.add_role("pilot/lane/f2", cwd=str(setup.tmp), kind="implementer")["generation"] == 1


@pytest.mark.parametrize("endpoint,kind,error", [
    ("pilot/lane/f2", "reviewer", "kind 'reviewer' does not match the manifest kind 'implementer' of pilot/lane/f2"),
    ("pilot/orchestrator", "implementer", "kind 'implementer' does not match the manifest kind (none) of pilot/orchestrator"),
    ("pilot/lane/review", 7, "invalid kind"),
])
def test_add_role_with_another_kind_is_refused_and_binds_nothing(setup, endpoint, kind, error):
    assert setup.add_role(endpoint, cwd=str(setup.tmp), kind=kind, expect=2)["error"] == error
    assert not (setup.root / "bindings" / endpoint).exists()


def test_adding_a_role_again_keeps_its_session_and_a_different_session_is_refused(setup):
    first = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp))
    again = setup.add_role("pilot/orchestrator", session=first["session"], cwd=str(setup.tmp))
    assert again["generation"] == 1 and again["connection"] == first["connection"]
    refused = setup.add_role("pilot/orchestrator", session=str(uuid.uuid4()), cwd=str(setup.tmp), expect=2)
    assert refused["error"] == "endpoint is bound to another session; hand it off first"


def test_after_a_handoff_new_files_are_written_and_the_old_ones_are_kept(setup):
    first = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp))
    brief = setup.base / "brief.md"
    brief.write_bytes(b"Handoff.\n")
    successor = str(uuid.uuid4())
    invoke(setup.root, "bind", invoke(setup.root, "draft-handoff", {
        "endpoint": "pilot/orchestrator", "host": "claude-code", "session": successor, "outgoing_stopped": True,
        "briefs": [{"path": str(brief), "sha256": hashlib.sha256(b"Handoff.\n").hexdigest()}]}))
    second = setup.add_role("pilot/orchestrator", session=successor, cwd=str(setup.tmp))
    assert second["generation"] == 2 and second["connection"] != first["connection"]
    assert Path(first["connection"]).exists() and Path(second["connection"]).exists()
    assert "--generation" in json.loads(Path(second["connection"]).read_text())["mcpServers"]["aegis_mailbox"]["args"]
    assert start_connection(second["connection"]) == MAILBOX_TOOLS | {"workspace_capacity", "workspace_initiative"}


@pytest.mark.parametrize("endpoint,host,changes,error", [
    ("pilot/lane/none", "claude-code", {}, "unknown endpoint"),
    ("pilot/orchestrator", "gemini", {}, "unsupported host"),
    ("pilot/orchestrator", "claude-code", {"session": "not-a-uuid"}, "claude sessions need a UUID"),
    ("pilot/orchestrator", "claude-code", {"cwd": "relative"}, "path must be absolute"),
    ("pilot/orchestrator", "claude-code", {"cwd": "/no/such/directory"}, "cwd is not a directory"),
    ("pilot/orchestrator", "claude-code", {"tools": "Read,Bash"}, "unsupported tool: Bash"),
    ("pilot/orchestrator", "claude-code", {"add_dirs": ["relative"]}, "path must be absolute"),
    ("pilot/orchestrator", "claude-code", {"timeout_seconds": 0}, "invalid timeout_seconds"),
    ("pilot/orchestrator", "claude-code", {"assistants": "yes"}, "invalid assistants"),
    ("pilot/orchestrator", "claude-code", {"run": "x"}, "unexpected fields"),
])
def test_malformed_roles_are_refused_and_bind_nothing(setup, endpoint, host, changes, error):
    request = {"cwd": str(setup.tmp), **changes}
    refused = setup.add_role(endpoint, host, expect=2, **request)
    assert error in refused["error"]
    assert invoke(setup.root, "status")["bindings"]["pilot/orchestrator"] is None


def test_assistants_are_off_by_default_and_never_offered_on_codex(setup):
    plain = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp))
    argv = json.loads(Path(plain["wake_profile"]).read_text())["argv"]
    assert "--agents" not in argv and not any("Agent" in word for word in argv)
    refused = setup.add_role("pilot/lane/f2", "codex-cli", session="abc", cwd=str(setup.source), assistants=True, expect=2)
    assert refused["error"] == "codex assistants stay off until a live probe"


@pytest.mark.parametrize("endpoint,catalog", [
    ("pilot/front-door", "assistants-front-door.json"), ("pilot/orchestrator", "assistants-orchestrator.json"),
    ("pilot/lane/f2", "assistants-builder.json"), ("pilot/lane/integration", "assistants-builder.json"),
    ("pilot/lane/review", "assistants-reviewer.json"),
])
def test_claude_assistants_are_limited_to_the_roles_own_list(setup, endpoint, catalog):
    role = setup.add_role(endpoint, cwd=str(setup.tmp), assistants=True)
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert argv[:3] == ["env", "CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH=1", "CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS=2"]
    assert argv[argv.index("--agents") + 1].endswith(catalog)
    tools = next(word for word in argv if word.startswith("--tools="))
    assert tools.split("=")[1].split(",")[-1] == "Agent"
    denied = argv[argv.index("--disallowedTools") + 1]
    assert "Agent(general-purpose)" in denied and "Agent(Explore)" in denied
    assert role["assistants"] == "enabled; using them needs the owner's go-ahead and a live probe"


def test_the_codex_start_command_matches_the_real_startup(setup):
    path = setup.tmp / "start.json"
    path.write_text(json.dumps({"base": str(setup.base), "endpoint": "pilot/orchestrator", "cwd": str(setup.source)}))
    result = subprocess.run([sys.executable, "-I", str(PROVISION), "codex-start", "--request", str(path)], capture_output=True,
                            text=True, timeout=20, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0, result.stdout + result.stderr
    argv = json.loads(result.stdout)["start_argv"]
    assert "resume" not in argv and codex_config(argv)["mcp_servers"] == {}
    assert argv[argv.index("-C") + 1] == str(setup.source) and argv[argv.index("--sandbox") + 1] == "read-only"
    assert json.loads(result.stdout)["prompt_via"] == "argv"
    assert HELPER.exists()


CODEX_SESSION = "01a19969-41df-7631-8ecd-57add111e96b"


def write_team(setup, **team):
    (setup.base / "team.json").write_text(json.dumps(team), encoding="utf-8")


def flag(argv, name):
    return argv[argv.index(name) + 1] if name in argv else None


def codex_start(setup, expect=0, **changes):
    return provision("codex-start", setup.request(base=str(setup.base), endpoint="pilot/orchestrator",
                                                  cwd=str(setup.source), **changes), expect=expect)


def test_a_claude_role_takes_model_and_reasoning_from_team_config(setup):
    write_team(setup, model="claude-opus-5-5", reasoning="max")
    role = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp))
    for argv in (json.loads(Path(role["wake_profile"]).read_text())["argv"], role["start_argv"]):
        assert flag(argv, "--model") == "claude-opus-5-5" and flag(argv, "--effort") == "max"
        assert "--settings" not in argv
    assert role["team"] == {"model": "claude-opus-5-5", "effort": "max", "reasoning": "max",
                            "model_from": "team.json", "effort_from": "team.json", "reasoning_from": "default"}


def test_request_values_win_over_team_config(setup):
    write_team(setup, model="claude-opus-5-5", reasoning="max")
    role = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp), model="claude-sonnet-5-5")
    assert flag(role["start_argv"], "--model") == "claude-sonnet-5-5" and flag(role["start_argv"], "--effort") == "max"
    assert role["team"]["model_from"] == "request" and role["team"]["effort_from"] == "team.json"
    explicit = setup.add_role("pilot/lane/review", cwd=str(setup.tmp), model="claude-haiku-5-5", effort="low")
    assert flag(explicit["start_argv"], "--effort") == "low" and "team" not in explicit


def test_ultra_reasoning_runs_claude_at_max_effort_with_ultracode(setup):
    write_team(setup, model="claude-opus-5-5", reasoning="ultra")
    role = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp), background=True)
    for argv in (json.loads(Path(role["wake_profile"]).read_text())["argv"], role["start_argv"]):
        assert flag(argv, "--effort") == "max" and json.loads(flag(argv, "--settings")) == {"ultracode": True}
        assert argv[-1] == "--", "the settings stay before the end of options"
    assert role["team"]["reasoning"] == "ultra" and role["team"]["effort"] == "max"


def test_a_codex_role_maps_team_reasoning_and_records_the_ultra_downgrade(setup):
    write_team(setup, model="gpt-5.5-codex", reasoning="ultra")
    role = setup.add_role("pilot/lane/f2", "codex-cli", session=CODEX_SESSION, cwd=str(setup.source))
    settings = codex_config(json.loads(Path(role["wake_profile"]).read_text())["argv"])
    assert settings["model"] == "gpt-5.5-codex" and settings["model_reasoning_effort"] == "max"
    assert role["team"]["reasoning"] == "ultra" and role["team"]["effort"] == "max"
    assert "no ultracode" in role["team"]["downgrade"]


def test_codex_start_takes_team_config_too(setup):
    write_team(setup, model="gpt-5.5-codex", reasoning="high")
    started = codex_start(setup)
    settings = codex_config(started["start_argv"])
    assert settings["model"] == "gpt-5.5-codex" and settings["model_reasoning_effort"] == "high"
    assert started["team"] == {"model": "gpt-5.5-codex", "effort": "high", "reasoning": "high",
                               "model_from": "team.json", "effort_from": "team.json", "reasoning_from": "default"}


@pytest.mark.parametrize("team,host,error", [
    ({"model": "claude-opus-5-5", "reasoning": "turbo"}, "claude-code", "unknown reasoning level in team.json: turbo"),
    ({"model": "claude-opus-5-5", "reasoning": "max"}, "codex-cli", "team.json model claude-opus-5-5 needs host claude-code"),
    ({"model": "gpt-5.5-codex", "reasoning": "max"}, "claude-code", "team.json model gpt-5.5-codex needs host codex-cli"),
    ({"model": "claude-opus-5-5"}, "claude-code", "missing"),
    ({"model": "claude-opus-5-5", "reasoning": "max", "effort": "low"}, "claude-code", "unexpected"),
])
def test_a_bad_team_config_is_refused_before_anything_binds(setup, team, host, error):
    write_team(setup, **team)
    changes = {"session": CODEX_SESSION, "cwd": str(setup.source)} if host == "codex-cli" else {"cwd": str(setup.tmp)}
    endpoint = "pilot/lane/f2" if host == "codex-cli" else "pilot/orchestrator"
    result = setup.add_role(endpoint, host, expect=2, **changes)
    assert error in result["error"], result
    assert not list((setup.base / "profiles").glob("*.wake.json")) if (setup.base / "profiles").exists() else True


def test_codex_start_refuses_a_claude_team_model(setup):
    write_team(setup, model="claude-opus-5-5", reasoning="max")
    assert "needs host claude-code" in codex_start(setup, expect=2)["error"]


def test_a_request_model_for_another_host_still_takes_the_team_reasoning(setup):
    # The team's model is not used, so its host does not bind this role; its reasoning still does (review r2 R1).
    write_team(setup, model="claude-opus-5-5", reasoning="high")
    role = setup.add_role("pilot/lane/f2", "codex-cli", session=CODEX_SESSION, cwd=str(setup.source),
                          model="gpt-5.5-codex")
    settings = codex_config(json.loads(Path(role["wake_profile"]).read_text())["argv"])
    assert settings["model"] == "gpt-5.5-codex" and settings["model_reasoning_effort"] == "high"
    assert role["team"]["model_from"] == "request" and role["team"]["effort_from"] == "team.json"


def test_a_full_request_does_not_read_team_config(setup):
    (setup.base / "team.json").write_text("not json", encoding="utf-8")
    role = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp), model="claude-opus-5-5", effort="high")
    assert flag(role["start_argv"], "--effort") == "high" and "team" not in role


def test_no_team_config_keeps_the_host_defaults(setup):
    role = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp))
    assert "--model" not in role["start_argv"] and "--effort" not in role["start_argv"] and "team" not in role


BY_KIND = {"model": "claude-opus-5-5", "reasoning": "max", "reasoning_by_kind": {"implementer": "xhigh"}}


@pytest.mark.parametrize("endpoint,effort,source", [
    ("pilot/lane/f2", "xhigh", "kind"),
    ("pilot/lane/review", "max", "default"),
    ("pilot/orchestrator", "max", "default"),
])
def test_team_reasoning_can_differ_by_role_kind(setup, endpoint, effort, source):
    write_team(setup, **BY_KIND)
    role = setup.add_role(endpoint, cwd=str(setup.tmp))
    assert flag(role["start_argv"], "--effort") == effort
    assert role["team"]["reasoning"] == effort and role["team"]["reasoning_from"] == source


def test_an_explicit_effort_wins_over_the_role_kind_map(setup):
    write_team(setup, **BY_KIND)
    role = setup.add_role("pilot/lane/f2", cwd=str(setup.tmp), effort="low")
    assert flag(role["start_argv"], "--effort") == "low"
    assert role["team"]["reasoning_from"] == "request" and role["team"]["model_from"] == "team.json"


def test_codex_start_uses_the_orchestrator_entry_of_the_role_kind_map(setup):
    write_team(setup, model="gpt-5.5-codex", reasoning="max", reasoning_by_kind={"orchestrator": "high"})
    started = codex_start(setup)
    assert codex_config(started["start_argv"])["model_reasoning_effort"] == "high"
    assert started["team"]["reasoning_from"] == "kind"


@pytest.mark.parametrize("by_kind,error", [
    ({"implementer": "turbo"}, "unknown reasoning level in team.json: turbo"),
    ({"implementor": "xhigh"}, "unknown role kind in team.json reasoning_by_kind: implementor"),
    (["xhigh"], "invalid team.json reasoning_by_kind"),
])
def test_a_bad_role_kind_map_is_refused(setup, by_kind, error):
    write_team(setup, model="claude-opus-5-5", reasoning="max", reasoning_by_kind=by_kind)
    result = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp), expect=2)
    assert error in result["error"], result


# Lifecycle connections, the Router's tier and the Codex profile record (M1 item 4)


ROOT_SESSION = "root-session-1"
REVIEW_SESSION = "01a19a29-d635-7411-8529-9efedafc0885"
NO_LIFECYCLE = "the %s role has no lifecycle connection"
PAIR = "lifecycle and actor must be given together"
ROUTER_ACTOR = "the router session takes no lifecycle actor; routing is the router tool's"


@pytest.fixture
def team(tmp_path):
    """A provisioned initiative with a Router and a Decider, and a lifecycle journal whose policy has both."""
    from tests.integration.test_hierarchy_decider import Decider
    built = Setup(tmp_path)
    provision("init", built.init_request(roles=["router", "decider"]))
    (tmp_path / "journal").mkdir()
    built.ledger = Decider(tmp_path / "journal")
    built.lifecycle = str(built.ledger.path)
    return built


def unbound(setup, endpoint):
    return invoke(setup.root, "status")["bindings"][endpoint] is None


# MR-1: claude_start is a public launcher function, not a provision CLI subcommand.
def mr1_provision(command, request, expect=0):
    if command != "claude-start":
        return provision(command, request, expect=expect)
    sys.path.insert(0, str(ROOT / "tools"))
    import hierarchy_provision
    request.pop("_request_path")
    if expect == 2:
        with pytest.raises(ValueError) as caught:
            hierarchy_provision.claude_start(request)
        return {"error": str(caught.value)}
    return hierarchy_provision.claude_start(request)


# Exercise the JSON entry point in-process where the data-file OS boundary is patched.
@pytest.fixture
def mr1_cli(capsys):
    sys.path.insert(0, str(ROOT / "tools"))
    import hierarchy_provision

    def call(command, request, expect=0):
        if command == "claude-start":
            return mr1_provision(command, request, expect=expect)
        path = Path(request.pop("_request_path"))
        path.write_text(json.dumps(request), encoding="utf-8")
        code = hierarchy_provision.main([command, "--request", str(path)])
        captured = capsys.readouterr()
        assert not captured.err, captured.err
        answer = json.loads(captured.out)
        assert code == expect, answer
        return answer

    return hierarchy_provision, call


def mr1_plan(setup, host="claude-code"):
    (setup.base / "host-plan.json").write_text(json.dumps({
        "schema": "aegis.hierarchy-host-plan/v1", "hierarchy": "pilot", "root": "codex-cli",
        "team": host, "stand_ins": {}, "config_sha256": "ab" * 32}), encoding="utf-8")


def mr1_request(setup, command, endpoint="pilot/orchestrator", host="claude-code", **changes):
    body = {"base": str(setup.base), "endpoint": endpoint, "cwd": str(setup.source)}
    if command == "add-role":
        body.update(host=host, session=CODEX_SESSION if host == "codex-cli" else str(uuid.uuid4()))
    elif command == "claude-start":
        body["session"] = str(uuid.uuid4())
    return setup.request(**dict(body, **changes))


MR1_BAD_EFFORTS = ["bogus", "ultra", "ULTRA", "High", " high", "high\n", "", None, 7, ["high"],
                   "x" * 129, "ｈｉｇｈ", "\x01"]


@pytest.mark.parametrize("command", ["add-role", "codex-start", "claude-start"])
@pytest.mark.parametrize("value", MR1_BAD_EFFORTS)
def test_mr1_request_effort_refusals_leave_endpoint_unbound(setup, command, value):
    shown = ascii(value)
    shown = shown if len(shown) <= 80 else shown[:77] + "..."
    error = ("request effort 'ultra' is a deprecated alias accepted only in team.json; "
             "ask for max, or set team.json reasoning to ultra; allowed request efforts: low, medium, high, xhigh, max"
             if value == "ultra" else
             "invalid request effort %s; choose one of: low, medium, high, xhigh, max" % shown)
    refused = mr1_provision(command, mr1_request(setup, command, model="claude-opus-5-5", effort=value), expect=2)
    assert refused == {"error": error}
    assert refused["error"].isascii() and "\n" not in refused["error"] and "\x01" not in refused["error"]
    assert unbound(setup, "pilot/orchestrator")


def mr1_bindings():
    levels = dict(zip(("light", "standard", "deep", "extended", "max"), ("low", "medium", "high", "xhigh", "max")))
    return {"schema": "aegis.model-bindings/v1", "roles": [
        {"kind": kind, "model_class": "coding", "band": dict(zip(("floor", "default", "ceiling"), band))}
        for kind, band in [("orchestrator", ("light", "standard", "standard")),
                           ("decider", ("light", "standard", "standard")),
                           ("implementer", ("standard", "deep", "max")),
                           ("integrator", ("standard", "deep", "max")),
                           ("reviewer", ("deep", "deep", "max"))]], "hosts": [
        {"host": host, "class": cls, "model": model, "levels": dict(levels),
         "admission": {intent: "unprobed" for intent in levels}}
        for host, models in [("claude-code", ["claude-opus-5-5", "claude-fable-5-1", "claude-sonnet-5-5", "claude-haiku-5-5"]),
                             ("codex-cli", ["gpt-6.1-sol", "gpt-6-astra", "gpt-6.1-terra", "gpt-6-luna"])]
        for cls, model in zip(("coding", "frontier", "scout", "mechanical"), models)]}


@pytest.mark.parametrize("case,problem", [
    ("missing", "cannot read file"), ("json", "invalid JSON"), ("duplicate-key", "duplicate JSON key 'schema'"),
    ("schema", "unsupported schema"), ("top-key", "unexpected top-level keys"),
    ("kind", "unknown role kind 'wizard'"), ("class", "unknown model class 'wizard'"),
    ("intent", "unknown intent 'ultra'"), ("order", "band must satisfy floor <= default <= ceiling"),
    ("native", "unknown native level 'ultra'"), ("duplicate-host", "duplicate host/class row"),
    ("missing-intent", "binding claude-code/coding lacks band ceiling max for implementer"),
    ("role-key", "unexpected role keys"), ("host-key", "unexpected host keys"),
    ("duplicate-role", "duplicate role row"), ("band-key", "unexpected band keys"),
    ("ceiling", "band must satisfy floor <= default <= ceiling"),
    ("duplicate-level", "levels must map to distinct native levels"),
    ("host", "unknown host 'other'"), ("shape", "top-level must be an object"),
    ("roles-shape", "roles must be a list"), ("hosts-shape", "hosts must be a list"),
    ("model-type", "model must be a nonempty ASCII identifier"),
    ("admission-type", "admission must map exactly supported intents"),
    ("missing-coding", "missing host/class rows: claude-code/coding"),
    ("missing-codex-coding", "missing host/class rows: codex-cli/coding"),
    ("duplicate-model", "duplicate host/model row: claude-code/claude-opus-5-5"),
    ("missing-orchestrator", "missing role kinds: orchestrator"),
    ("missing-decider", "missing role kinds: decider"),
    ("missing-implementer", "missing role kinds: implementer"),
    ("missing-integrator", "missing role kinds: integrator"),
    ("missing-reviewer", "missing role kinds: reviewer"),
    ("empty-roles", "missing role kinds: decider, implementer, integrator, orchestrator, reviewer"),
    ("missing-scout", "missing host/class rows: codex-cli/scout"),
])
def test_mr1_broken_bindings_refuse_before_binding(setup, mr1_cli, monkeypatch, case, problem):
    module, call = mr1_cli
    mr1_plan(setup)
    data = mr1_bindings()
    if case == "schema":
        data["schema"] = "v2"
    elif case == "top-key":
        data["extra"] = True
    elif case == "kind":
        data["roles"][0]["kind"] = "wizard"
    elif case == "class":
        data["hosts"][0]["class"] = "wizard"
    elif case == "intent":
        data["roles"][0]["band"]["floor"] = "ultra"
    elif case == "order":
        data["roles"][0]["band"]["floor"] = "deep"
    elif case == "native":
        data["hosts"][0]["levels"]["max"] = "ultra"
    elif case == "duplicate-host":
        data["hosts"].append(data["hosts"][0])
    elif case == "missing-intent":
        del data["hosts"][0]["levels"]["max"]
        del data["hosts"][0]["admission"]["max"]
    elif case == "role-key":
        data["roles"][0]["extra"] = True
    elif case == "host-key":
        data["hosts"][0]["extra"] = True
    elif case == "duplicate-role":
        data["roles"].append(data["roles"][0])
    elif case == "band-key":
        data["roles"][0]["band"]["extra"] = True
    elif case == "ceiling":
        data["roles"][0]["band"]["ceiling"] = "light"
    elif case == "duplicate-level":
        data["hosts"][0]["levels"]["max"] = "high"
    elif case == "host":
        data["hosts"][0]["host"] = "other"
    elif case == "shape":
        data = []
    elif case == "roles-shape":
        data["roles"] = {}
    elif case == "hosts-shape":
        data["hosts"] = {}
    elif case == "model-type":
        data["hosts"][0]["model"] = ["bad"]
    elif case == "admission-type":
        data["hosts"][0]["admission"] = None
    elif case == "missing-coding":
        data["hosts"].pop(0)
    elif case == "missing-codex-coding":
        data["hosts"] = [row for row in data["hosts"] if (row["host"], row["class"]) != ("codex-cli", "coding")]
    elif case == "duplicate-model":
        data["hosts"][1]["model"] = data["hosts"][0]["model"]
    elif case.startswith("missing-") and case[8:] in {row["kind"] for row in data["roles"]}:
        data["roles"] = [row for row in data["roles"] if row["kind"] != case[8:]]
    elif case == "empty-roles":
        data["roles"] = []
    elif case == "missing-scout":
        data["roles"][0]["model_class"] = "scout"
        data["hosts"] = [row for row in data["hosts"] if (row["host"], row["class"]) != ("codex-cli", "scout")]
    path = setup.tmp / "model-bindings.json"
    if case != "missing":
        raw = "{" if case == "json" else '{"schema":1,"schema":2}' if case == "duplicate-key" else json.dumps(data)
        path.write_text(raw, encoding="utf-8")
    monkeypatch.setattr(module, "MODEL_BINDINGS", path, raising=False)
    refused = call("add-role", mr1_request(setup, "add-role", model="claude-opus-5-5", effort="medium"), expect=2)
    assert refused == {"error": "invalid model bindings %s: %s; repair model-bindings.json" % (path, problem)}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("command", ["add-role", "codex-start", "claude-start"])
@pytest.mark.parametrize("endpoint,effort,intent,band", [
    ("pilot/orchestrator", "high", "deep", "light..standard"),
    ("pilot/lane/review", "medium", "standard", "deep..max"),
    ("pilot/lane/f2", "low", "light", "standard..max"),
    ("pilot/lane/integration", "low", "light", "standard..max"),
])
def test_mr1_plan_bands_check_explicit_requests_before_binding(setup, command, endpoint, effort, intent, band):
    host = "codex-cli" if command == "codex-start" else "claude-code"
    model = "gpt-6.1-sol" if host == "codex-cli" else "claude-opus-5-5"
    mr1_plan(setup, host)
    kind = {"f2": "implementer", "review": "reviewer", "integration": "integrator"}.get(endpoint.split("/")[-1], "orchestrator")
    refused = mr1_provision(command, mr1_request(setup, command, endpoint, host, model=model, effort=effort), expect=2)
    assert refused == {"error": "%s effort %s maps to intent %s outside band %s; choose an effort within the band" %
                       (kind, effort, intent, band)}
    assert unbound(setup, endpoint)


@pytest.mark.parametrize("by_kind", [False, True])
def test_mr1_plan_refuses_team_ultra_above_orchestrator_band(setup, by_kind):
    mr1_plan(setup)
    write_team(setup, model="claude-opus-5-5", reasoning="medium" if by_kind else "ultra",
               **({"reasoning_by_kind": {"orchestrator": "ultra"}} if by_kind else {}))
    refused = setup.add_role("pilot/orchestrator", cwd=str(setup.source), expect=2)
    assert refused == {"error": "orchestrator effort max maps to intent max outside band light..standard; "
                       "choose an effort within the band" +
                       ("; set team.json reasoning_by_kind.orchestrator to an in-band effort" if not by_kind else "")}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("host,model", [("claude-code", "claude-opus-5-5"), ("codex-cli", "gpt-6.1-sol")])
@pytest.mark.parametrize("endpoint,effort,intent,band", [
    ("pilot/orchestrator", "low", "light", ("light", "standard", "standard")),
    ("pilot/lane/f2", "medium", "standard", ("standard", "deep", "max")),
    ("pilot/lane/integration", "xhigh", "extended", ("standard", "deep", "max")),
    ("pilot/lane/review", "high", "deep", ("deep", "deep", "max")),
    ("pilot/lane/review", "max", "max", ("deep", "deep", "max")),
])
def test_mr1_in_band_requests_record_provenance(setup, host, model, endpoint, effort, intent, band):
    mr1_plan(setup, host)
    answer = provision("add-role", mr1_request(setup, "add-role", endpoint, host, model=model, effort=effort))
    assert answer["team"] == {"model": model, "effort": effort, "reasoning": effort, "model_from": "request",
                              "effort_from": "request", "reasoning_from": "request", "model_class": "coding",
                              "intent": intent, "band": dict(zip(("floor", "default", "ceiling"), band)),
                              "bindings_sha256": hashlib.sha256((ROOT / "tools/hierarchy_templates/model-bindings.json").read_bytes()).hexdigest(),
                              "admission": "unprobed"}


@pytest.mark.parametrize("host,model", [("claude-code", "claude-opus-5-5"), ("codex-cli", "gpt-6.1-sol")])
def test_mr1_team_ultra_keeps_argv_and_records_deprecation_under_plan(setup, host, model):
    write_team(setup, model=model, reasoning="ultra")
    command = "claude-start" if host == "claude-code" else "codex-start"
    request = mr1_request(setup, command, "pilot/lane/f2", host)
    before = mr1_provision(command, dict(request))
    mr1_plan(setup, host)
    after = mr1_provision(command, dict(request))
    assert after["start_argv"] == before["start_argv"]
    assert after["team"]["deprecated"] == "ultra" and after["team"]["intent"] == "max"
    assert {key: after["team"][key] for key in before["team"]} == before["team"]


@pytest.mark.parametrize("model,error", [
    ("unknown", "model unknown is not bound for host claude-code; choose a model bound in model-bindings.json"),
    ("gpt-6.1-sol", "team.json model gpt-6.1-sol needs host codex-cli, not claude-code"),
    ("bad\nｘ", "model 'bad\\n\\uff58' is not bound for host claude-code; choose a model bound in model-bindings.json"),
])
@pytest.mark.parametrize("source", ["request", "team.json"])
def test_mr1_plan_refuses_models_outside_host_bindings(setup, source, model, error):
    mr1_plan(setup)
    write_team(setup, model=model, reasoning="medium")
    changes = {"model": model, "effort": "medium"} if source == "request" else {}
    refused = setup.add_role("pilot/orchestrator", cwd=str(setup.source), expect=2, **changes)
    if error.startswith("model "):
        error = source + " " + error
    if source == "request":
        error = error.replace("team.json model ", "request model ")
    assert refused == {"error": error}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("command", ["add-role", "codex-start", "claude-start"])
def test_mr1_planless_does_not_open_bindings_and_preserves_answers(setup, mr1_cli, monkeypatch, command):
    module, call = mr1_cli
    request = mr1_request(setup, command, model="gpt-5.5-codex" if command == "codex-start" else "claude-opus-5-5",
                          effort="high")
    before = call(command, dict(request))
    garbage = setup.tmp / "garbage.json"
    garbage.write_text("not JSON", encoding="utf-8")
    monkeypatch.setattr(module, "MODEL_BINDINGS", garbage, raising=False)
    original = Path.open

    def open_file(path, *args, **kwargs):
        assert path != garbage, "plan-less provision must never open the bindings file"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_file)
    assert call(command, dict(request)) == before
    assert "team" not in before


@pytest.mark.parametrize("endpoint", ["pilot/orchestrator", "pilot/lane/f2", "pilot/lane/integration", "pilot/lane/review"])
def test_mr1_shipped_defaults_have_identical_argv_with_and_without_plan(setup, endpoint):
    defaults = json.loads((ROOT / "tools/hierarchy_templates/team-run.json").read_text())["team"]
    write_team(setup, **defaults)
    request = mr1_request(setup, "codex-start", endpoint, "codex-cli")
    before = provision("codex-start", dict(request))
    mr1_plan(setup, "codex-cli")
    after = provision("codex-start", dict(request))
    assert after["start_argv"] == before["start_argv"]
    assert after["codex_profile"] == before["codex_profile"]
    assert after["team"]["model_class"] == "coding"
    assert {key: after["team"][key] for key in before["team"]} == before["team"]


def test_mr1_binding_bytes_and_generic_rows_drive_resolution(setup, mr1_cli, monkeypatch):
    module, call = mr1_cli
    mr1_plan(setup)
    data = mr1_bindings()
    data["hosts"][0]["model"] = "custom-code"
    data["hosts"][0]["levels"].update(standard="high", deep="medium")
    path = setup.tmp / "recalibrated.json"
    raw = (json.dumps(data, indent=3) + "\n\n").encode("utf-8")
    path.write_bytes(raw)
    monkeypatch.setattr(module, "MODEL_BINDINGS", path, raising=False)
    answer = call("add-role", mr1_request(setup, "add-role", model="custom-code", effort="high"))
    assert flag(answer["start_argv"], "--model") == "custom-code"
    assert flag(answer["start_argv"], "--effort") == "high"
    assert answer["team"]["intent"] == "standard"
    assert answer["team"]["bindings_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("value,shown", [(None, "None"), (["high"], "['high']"),
                                         ("ｈｉｇｈ", "'\\uff48\\uff49\\uff47\\uff48'"), ("high\n", "'high\\n'")])
def test_mr1_bad_team_reasoning_has_safe_refusal_before_binding(setup, value, shown):
    mr1_plan(setup)
    write_team(setup, model="claude-opus-5-5", reasoning=value)
    refused = setup.add_role("pilot/orchestrator", cwd=str(setup.source), expect=2)
    assert refused == {"error": "unknown reasoning level in team.json: " + shown}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("endpoint,effort", [("pilot/front-door", "max"), ("pilot/router", "medium")])
@pytest.mark.parametrize("model", ["claude-opus-5-5", "unbound-model"])
def test_mr1_unbanded_roles_keep_legacy_model_and_effort(team, endpoint, effort, model):
    mr1_plan(team)
    request = mr1_request(team, "add-role", endpoint, model=model, effort=effort)
    answer = provision("add-role", request)
    assert flag(answer["start_argv"], "--effort") == effort
    assert "team" not in answer


@pytest.mark.parametrize("effort", ["low", "medium", "high"])
def test_mr1_decider_uses_coordination_band(team, effort):
    mr1_plan(team)
    request = mr1_request(team, "add-role", "pilot/decider", model="claude-opus-5-5", effort=effort)
    if effort == "high":
        refused = provision("add-role", request, expect=2)
        assert refused == {"error": "decider effort high maps to intent deep outside band light..standard; "
                           "choose an effort within the band"}
        assert unbound(team, "pilot/decider")
    else:
        answer = provision("add-role", request)
        assert answer["team"]["band"] == {"floor": "light", "default": "standard", "ceiling": "standard"}


@pytest.mark.parametrize("raw", ['{"model":"claude-opus-5-5","reasoning":"medium","bad\\nｘ":0}',
                                '{"model":"claude-opus-5-5","reasoning":"medium","bad\\nｘ":0,"bad\\nｘ":1}'])
def test_mr1_malformed_team_keys_never_reach_errors_raw(setup, raw):
    mr1_plan(setup)
    (setup.base / "team.json").write_text(raw, encoding="utf-8")
    refused = setup.add_role("pilot/orchestrator", cwd=str(setup.source), expect=2)
    assert refused["error"].isascii() and "\n" not in refused["error"]
    assert "\\n" in refused["error"] and "\\uff58" in refused["error"]
    assert unbound(setup, "pilot/orchestrator")


@pytest.fixture
def mr1_r2_setup(tmp_path):
    built = Setup(tmp_path)
    provision("init", built.init_request(roles=["decider", "router"]))
    return built


MR1_R2_ENTRY_POINTS = [("add-role", "claude-code"), ("add-role", "codex-cli"),
                    ("claude-start", "claude-code"), ("codex-start", "codex-cli")]
MR1_R2_BANDED_ROLES = [("orchestrator", "pilot/orchestrator", "medium"), ("decider", "pilot/decider", "medium"),
                    ("implementer", "pilot/lane/f2", "high"), ("integrator", "pilot/lane/integration", "high"),
                    ("reviewer", "pilot/lane/review", "high")]


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("kind,endpoint,effort", MR1_R2_BANDED_ROLES)
@pytest.mark.parametrize("model_class", ["frontier", "scout", "mechanical"])
@pytest.mark.parametrize("source", ["team.json", "request"])
def test_mr1_r2_every_banded_role_refuses_models_of_other_classes(mr1_r2_setup, mr1_cli, command, host, kind, endpoint,
                                                             effort, model_class, source):
    setup = mr1_r2_setup
    _, call = mr1_cli
    mr1_plan(setup, host)
    rows = [row for row in mr1_bindings()["hosts"] if row["host"] == host]
    model = next(row["model"] for row in rows if row["class"] == model_class)
    coding_model = next(row["model"] for row in rows if row["class"] == "coding")
    write_team(setup, model=model if source == "team.json" else coding_model, reasoning=effort)
    changes = {"model": model, "effort": effort} if source == "request" else {}
    refused = call(command, mr1_request(setup, command, endpoint, host, **changes), expect=2)
    assert refused == {"error": "%s model %s has class %s, requires class coding; choose model %s" %
                       (kind, model, model_class, coding_model)}
    assert unbound(setup, endpoint)


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("endpoint,effort", [("pilot/root", "max"), ("pilot/front-door", "max"),
                                            ("pilot/router", "medium")])
def test_mr1_r2_exempt_roles_keep_exact_answers_even_with_broken_bindings(mr1_r2_setup, mr1_cli, monkeypatch,
                                                                     command, host, endpoint, effort):
    setup = mr1_r2_setup
    module, call = mr1_cli
    request = mr1_request(setup, command, endpoint, host, model="outside-bindings", effort=effort)
    before = call(command, dict(request))
    mr1_plan(setup, host)
    # ROOT follows its own plan host; only the model policy is being tested here.
    plan_path = setup.base / "host-plan.json"
    plan = json.loads(plan_path.read_text())
    plan["root"] = host
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    garbage = setup.tmp / "broken-bindings.json"
    garbage.write_text("not JSON", encoding="utf-8")
    monkeypatch.setattr(module, "MODEL_BINDINGS", garbage)
    assert call(command, dict(request)) == before
    assert "team" not in before




def test_mr1_r2_provenance_and_levels_come_from_validated_class_binding(setup, mr1_cli, monkeypatch):
    module, call = mr1_cli
    mr1_plan(setup)
    data = mr1_bindings()
    next(row for row in data["roles"] if row["kind"] == "implementer")["model_class"] = "scout"
    scout = next(row for row in data["hosts"] if row["host"] == "claude-code" and row["class"] == "scout")
    scout["levels"].update(light="high", deep="low")
    scout["admission"]["deep"] = "admitted"
    path = setup.tmp / "class-bindings.json"
    raw = json.dumps(data, indent=1).encode("utf-8")
    path.write_bytes(raw)
    monkeypatch.setattr(module, "MODEL_BINDINGS", path)
    answer = call("add-role", mr1_request(setup, "add-role", "pilot/lane/f2", model=scout["model"], effort="low"))
    assert flag(answer["start_argv"], "--effort") == "low"
    assert answer["team"]["model_class"] == "scout" and answer["team"]["intent"] == "deep"
    assert answer["team"]["admission"] == "admitted"
    assert answer["team"]["bindings_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
@pytest.mark.parametrize("kind", [None, "unexpected-kind"])
def test_mr1_r2_unknown_policy_kind_never_gets_an_implicit_exemption(setup, mr1_cli, host, kind):
    module, _ = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    plan = module.hierarchy_hosts.governing_plan(setup.base, setup.root, "pilot")
    with pytest.raises(ValueError) as caught:
        module.team_settings(setup.base, host, {"model": model, "effort": "medium"}, kind=kind, plan=plan)
    assert str(caught.value) == "invalid model bindings %s: no role policy for %s; repair model-bindings.json" % (
        module.MODEL_BINDINGS, ascii(kind))
    assert unbound(setup, "pilot/orchestrator")






@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("source", ["request", "team.json"])
def test_mr1_r3_cross_host_model_refusal_names_its_source(setup, mr1_cli, command, host, source):
    _, call = mr1_cli
    mr1_plan(setup, host)
    own = next(row for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    other = next(row for row in mr1_bindings()["hosts"] if row["host"] != host and row["class"] == "coding")
    write_team(setup, model=other["model"] if source == "team.json" else own["model"], reasoning="medium")
    changes = {"model": other["model"], "effort": "medium"} if source == "request" else {}
    refused = call(command, mr1_request(setup, command, host=host, **changes), expect=2)
    assert refused == {"error": "%s model %s needs host %s, not %s" % (source, other["model"], other["host"], host)}
    assert unbound(setup, "pilot/orchestrator")


def test_mr1_r3_exemptions_equal_registry_endpoints_without_team_policy(mr1_cli):
    module, _ = mr1_cli
    roles = json.loads((ROOT / "tools/hierarchy_templates/role-registry.json").read_text(encoding="utf-8"))["roles"]
    expected = {name for name, row in roles.items() if row["endpoint"] is not None and row["provision"]["team_kind"] is False}
    assert set(module.MODEL_POLICY_EXEMPT_ROLES) == expected


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("shape,error", [("empty", "missing fields: model, reasoning"),
                                         ("model-only", "missing fields: reasoning"),
                                         ("reasoning-only", "missing fields: model")])
def test_mr1_r3_present_incomplete_team_file_is_never_host_defaults(setup, mr1_cli, command, host, shape, error):
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    team = {"model": model} if shape == "model-only" else {"reasoning": "medium"} if shape == "reasoning-only" else {}
    write_team(setup, **team)
    refused = call(command, mr1_request(setup, command, host=host), expect=2)
    assert refused == {"error": error}
    assert unbound(setup, "pilot/orchestrator")


def mr1_r4_copy_base(setup, tmp_path_factory):
    copied = tmp_path_factory.mktemp("mr1-copy-" + uuid.uuid4().hex)
    for name in ("provision.json", "runtime-source.py"):
        shutil.copyfile(setup.base / name, copied / name)
    return copied


def mr1_r4_request(setup, copied, command, host, **changes):
    request = mr1_request(setup, command, host=host, **changes)
    request["base"] = str(copied)
    if command in ("add-role", "claude-start"):
        request["session"] = str(uuid.uuid4())
    return request


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("case", ["out-of-band", "malformed", "differing", "format-only", "copy-only"])
def test_mr1_r4_copied_base_cannot_replace_canonical_policy(setup, mr1_cli, tmp_path_factory, command, host, case):
    _, call = mr1_cli
    mr1_plan(setup, host)
    copied = mr1_r4_copy_base(setup, tmp_path_factory)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    team = {"model": model, "reasoning": "high" if case == "out-of-band" else "medium"}
    if case == "malformed":
        (setup.base / "team.json").write_text("not JSON", encoding="utf-8")
        error = "invalid JSON file %s: invalid JSON; repair team.json" % (setup.base / "team.json")
    elif case == "out-of-band":
        write_team(setup, **team)
        error = ("orchestrator effort high maps to intent deep outside band light..standard; "
                 "choose an effort within the band; set team.json reasoning_by_kind.orchestrator to an in-band effort")
    else:
        if case != "copy-only":
            write_team(setup, **team)
        local = dict(team, reasoning="low") if case == "differing" else team
        (copied / "team.json").write_text(json.dumps(local, indent=3), encoding="utf-8")
        error = "copied base team.json differs from canonical team.json; use the governing mailbox's team.json"
    refused = call(command, mr1_r4_request(setup, copied, command, host), expect=2)
    assert refused == {"error": error}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("copy_team", [False, True])
def test_mr1_r4_copied_base_uses_canonical_resolution_and_provenance(setup, mr1_cli, tmp_path_factory,
                                                                  command, host, copy_team):
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    write_team(setup, model=model, reasoning="max", reasoning_by_kind={"orchestrator": "medium"})
    copied = mr1_r4_copy_base(setup, tmp_path_factory)
    if copy_team:
        (copied / "team.json").write_bytes((setup.base / "team.json").read_bytes())
    answer = call(command, mr1_r4_request(setup, copied, command, host))
    assert answer["team"]["model"] == model and answer["team"]["effort"] == "medium"
    assert answer["team"]["reasoning_from"] == "kind" and answer["team"]["intent"] == "standard"
    assert answer["team"]["admission"] == "unprobed"
    argv = json.loads(Path(answer["wake_profile"]).read_text())["argv"] if command == "add-role" else answer["start_argv"]
    if host == "codex-cli":
        assert codex_config(argv)["model"] == model and codex_config(argv)["model_reasoning_effort"] == "medium"
    else:
        assert flag(argv, "--model") == model and flag(argv, "--effort") == "medium"




@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("copied_base", [False, True])
@pytest.mark.parametrize("full_request", [False, True])
@pytest.mark.parametrize("shape", ["invalid-json", "empty-file", "directory", "dangling-symlink"])
def test_mr1_r4_present_canonical_team_is_always_validated(setup, mr1_cli, tmp_path_factory, command, host,
                                                        copied_base, full_request, shape):
    _, call = mr1_cli
    mr1_plan(setup, host)
    path = setup.base / "team.json"
    if shape in ("invalid-json", "empty-file"):
        path.write_text("not JSON" if shape == "invalid-json" else "", encoding="utf-8")
        error = "invalid JSON"
    elif shape == "directory":
        path.mkdir()
        error = "input must be a regular file"
    else:
        target = tmp_path_factory.mktemp("mr1-missing-" + uuid.uuid4().hex) / (uuid.uuid4().hex + ".json")
        path.symlink_to(target)
        error = "symlink paths are not supported: " + str(path)
    base = mr1_r4_copy_base(setup, tmp_path_factory) if copied_base else setup.base
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    options = {"model": model, "effort": "medium"} if full_request else {}
    refused = call(command, mr1_r4_request(setup, base, command, host, **options), expect=2)
    assert refused == {"error": "invalid JSON file %s: %s; repair team.json" % (path, error)}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
def test_mr1_r4_full_request_cannot_ignore_conflicting_local_team(setup, mr1_cli, tmp_path_factory, command, host):
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    write_team(setup, model=model, reasoning="medium")
    copied = mr1_r4_copy_base(setup, tmp_path_factory)
    (copied / "team.json").write_text("not JSON", encoding="utf-8")
    refused = call(command, mr1_r4_request(setup, copied, command, host, model=model, effort="medium"), expect=2)
    assert refused == {"error": "copied base team.json differs from canonical team.json; use the governing mailbox's team.json"}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("source", ["request", "team.json"])
def test_mr1_r4_unbound_model_message_names_its_source(setup, mr1_cli, command, host, source):
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    write_team(setup, model="unbound-model" if source == "team.json" else model, reasoning="medium")
    options = {"model": "unbound-model", "effort": "medium"} if source == "request" else {}
    refused = call(command, mr1_r4_request(setup, setup.base, command, host, **options), expect=2)
    assert refused == {"error": "%s model unbound-model is not bound for host %s; choose a model bound in model-bindings.json" %
                       (source, host)}
    assert unbound(setup, "pilot/orchestrator")


MR1_R5_BAD_JSON = [
    pytest.param(b'{"unused_probe": 1e9999}', "non-finite JSON is not supported", id="overflow-positive"),
    pytest.param(b'{"unused_probe": -1e9999}', "non-finite JSON is not supported", id="overflow-negative"),
    pytest.param(b'{"unused_probe": 1e400}', "non-finite JSON is not supported", id="overflow-small-exponent"),
    pytest.param(b"[" * 10000, "JSON nesting exceeds supported limit", id="deep-array"),
    pytest.param(b"{" * 10000, "invalid JSON", id="deep-object"),
    pytest.param(b"\xff", "invalid UTF-8 JSON", id="invalid-utf8"),
    pytest.param(b"\xef\xbb\xbf{}", "invalid JSON", id="bom"),
    pytest.param(b"NaN", "non-finite JSON is not supported", id="nan"),
    pytest.param(b"Infinity", "non-finite JSON is not supported", id="infinity"),
    pytest.param(b"-Infinity", "non-finite JSON is not supported", id="negative-infinity"),
    pytest.param(b"9" * 10000, "integer literal exceeds 128 digits", id="huge-integer"),
    pytest.param(b" " * 262145, "input exceeds 262144 bytes", id="oversize"),
]


@pytest.mark.parametrize("token", ["1e9999", "-1e9999", "1e400"])
@pytest.mark.parametrize("location", ["bootstrap-request", "bootstrap-provision", "ordinary-record", "carry-record"])
def test_mr1_r6_overflow_numbers_refuse_at_every_record_boundary(setup, mr1_cli, token, location):
    module, _ = mr1_cli
    request = mr1_r4_request(setup, setup.base, "codex-start", "codex-cli")
    request_path = Path(request.pop("_request_path"))
    request_path.write_text(json.dumps(request), encoding="utf-8")
    path = setup.base / "provision.json"
    if location == "bootstrap-request":
        path = request_path
    elif location == "carry-record":
        path = setup.base / "carried" / "carry.json"
        path.parent.mkdir()
        path.write_text(json.dumps({"old_root": str(setup.root), "endpoints": [], "message_ids": [],
                                    "generations": {}}), encoding="utf-8")
    value = json.loads(path.read_text())
    value["unused_probe"] = "OVERFLOW_TOKEN"
    path.write_text(json.dumps(value).replace('"OVERFLOW_TOKEN"', token), encoding="utf-8")
    expected = "invalid JSON file %s: non-finite JSON is not supported; repair %s" % (path, path.name)
    if location == "ordinary-record":
        with pytest.raises(ValueError) as caught:
            module.codex_start(request)
        assert str(caught.value) == expected
    else:
        command = "carry-check" if location == "carry-record" else "codex-start"
        if location == "carry-record":
            request_path.write_text(json.dumps({"base": str(setup.base)}), encoding="utf-8")
        done = subprocess.run([sys.executable, "-I", str(PROVISION), command, "--request", str(request_path)],
                              capture_output=True, text=True, timeout=10)
        assert not done.stderr
        assert done.returncode == 2, done.stdout
        assert json.loads(done.stdout) == {"error": expected}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO boundary")
def test_mr1_r6_bootstrap_refuses_fifo_without_waiting_for_a_writer(setup):
    path = setup.tmp / ("fifo-" + uuid.uuid4().hex)
    os.mkfifo(path)
    done = subprocess.run([sys.executable, "-I", str(PROVISION), "codex-start", "--request", str(path)],
                          capture_output=True, text=True, timeout=3)
    assert not done.stderr
    assert done.returncode == 2
    assert json.loads(done.stdout) == {"error": "invalid JSON file %s: not a regular file; repair %s" % (path, path.name)}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("reader", ["host-plan.json", "mailbox manifest"])
def test_mr1_r6_delegated_deep_json_refuses_before_binding(setup, mr1_cli, command, host, reader):
    _, call = mr1_cli
    mr1_plan(setup, host)
    path = setup.base / "host-plan.json" if reader == "host-plan.json" else setup.root / "manifest.json"
    original = path.read_bytes()
    path.write_bytes(b"[" * 10000)
    try:
        refused = call(command, mr1_r4_request(setup, setup.base, command, host), expect=2)
        assert refused == {"error": "invalid delegated JSON read (%s): JSON nesting exceeds supported limit; repair the input" % reader}
    finally:
        path.write_bytes(original)
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("reader", ["session record", "lifecycle policy"])
def test_mr1_r6_other_delegated_readers_refuse_deep_json(setup, mr1_cli, reader):
    module, call = mr1_cli
    mr1_plan(setup, "codex-cli")
    endpoint = "pilot/orchestrator" if reader == "session record" else "pilot/root"
    options = {"model": "gpt-6.1-sol", "effort": "medium"}
    if reader == "session record":
        path = module.hierarchy_hosts.session_record_path(setup.base, endpoint, 1)
    else:
        journal = setup.tmp / ("journal-" + uuid.uuid4().hex)
        options.update(lifecycle=str(journal), actor="root")
        path = journal / "policy.json"
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(b"[" * 10000)
    refused = call("add-role", mr1_r4_request(setup, setup.base, "add-role", "codex-cli",
                                            endpoint=endpoint, **options), expect=2)
    assert refused == {"error": "invalid delegated JSON read (%s): JSON nesting exceeds supported limit; repair the input" % reader}
    assert unbound(setup, endpoint)


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
def test_mr1_r6_copied_base_launcher_records_delegated_plan_refusal(tmp_path_factory, host):
    from tests.integration.test_hierarchy_launcher_hosts import Hosts
    launch = Hosts(tmp_path_factory.mktemp("mr1-r6-launch-" + uuid.uuid4().hex))
    launch.init()
    mr1_plan(launch, host)
    (launch.base / "host-plan.json").write_bytes(b"[" * 10000)
    original_root = launch.root
    launch.base = mr1_r4_copy_base(launch, tmp_path_factory)
    refused = launch.start(endpoint="pilot/lane/f2", expect=2)
    assert refused["state"] == "refused"
    assert refused["error"] == "invalid delegated JSON read (host-plan.json): JSON nesting exceeds supported limit; repair the input"
    assert launch.records("pilot/lane/f2") == [refused]
    assert invoke(original_root, "status")["bindings"]["pilot/lane/f2"] is None
    assert not launch.codex_log.exists() and not launch.claude_log.exists()


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("planned", [False, True])
@pytest.mark.parametrize("raw,problem", MR1_R5_BAD_JSON)
def test_mr1_r5_team_parse_failures_are_normal_refusals(setup, mr1_cli, command, host, planned, raw, problem):
    _, call = mr1_cli
    if planned:
        mr1_plan(setup, host)
    path = setup.base / "team.json"
    path.write_bytes(raw)
    refused = call(command, mr1_r4_request(setup, setup.base, command, host), expect=2)
    assert refused == {"error": "invalid JSON file %s: %s; repair team.json" % (path, problem)}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("raw,problem", MR1_R5_BAD_JSON)
def test_mr1_r5_bindings_parse_failures_are_normal_refusals(setup, mr1_cli, monkeypatch, command, host, raw, problem):
    module, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    write_team(setup, model=model, reasoning="medium")
    path = setup.tmp / (uuid.uuid4().hex + "-bindings.json")
    path.write_bytes(raw)
    monkeypatch.setattr(module, "MODEL_BINDINGS", path)
    refused = call(command, mr1_r4_request(setup, setup.base, command, host), expect=2)
    assert refused == {"error": "invalid model bindings %s: %s; repair model-bindings.json" % (path, problem)}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
def test_mr1_r5_launcher_records_deep_team_parse_refusal(tmp_path_factory, host):
    from tests.integration.test_hierarchy_launcher_hosts import Hosts
    launch = Hosts(tmp_path_factory.mktemp("mr1-launch-" + uuid.uuid4().hex))
    launch.init()
    mr1_plan(launch, host)
    path = launch.base / "team.json"
    path.write_bytes(b"[" * 10000)
    refused = launch.start(endpoint="pilot/lane/f2", expect=2)
    assert refused["state"] == "refused"
    assert refused["error"] == "invalid JSON file %s: JSON nesting exceeds supported limit; repair team.json" % path
    assert launch.records("pilot/lane/f2") == [refused]
    assert launch.binding("pilot/lane/f2") is None
    assert not launch.codex_log.exists() and not launch.claude_log.exists()


@pytest.mark.parametrize("case,problem", [
    ("missing-admission", "admission must map exactly supported intents"),
    ("extra-admission", "admission must map exactly supported intents"),
    ("unknown-admission", "unknown admission value 'allowed'"),
    ("typed-admission", "unknown admission value 7"),
    ("empty-levels", "levels must map a nonempty subset of light, standard, deep, extended, max"),
    ("unknown-intent", "levels must map a nonempty subset of light, standard, deep, extended, max"),
    ("missing-default", "binding claude-code/coding lacks band default standard for orchestrator"),
    ("missing-ceiling", "binding claude-code/coding lacks band ceiling max for implementer"),
    ("rejected-default", "binding claude-code/coding has rejected band default standard for orchestrator"),
    ("rejected-ceiling", "binding claude-code/coding has rejected band ceiling max for implementer"),
])
def test_mr1_r5_admission_and_partial_levels_fail_closed(setup, mr1_cli, monkeypatch, case, problem):
    module, call = mr1_cli
    mr1_plan(setup)
    data = mr1_bindings()
    row = data["hosts"][0]
    if case == "missing-admission":
        del row["admission"]["deep"]
    elif case == "extra-admission":
        row["admission"]["other"] = "unprobed"
    elif case == "unknown-admission":
        row["admission"]["standard"] = "allowed"
    elif case == "typed-admission":
        row["admission"]["standard"] = 7
    elif case.startswith("rejected-"):
        row["admission"]["standard" if case == "rejected-default" else "max"] = "rejected"
    elif case == "empty-levels":
        row["levels"] = {}
        row["admission"] = {}
    elif case == "unknown-intent":
        row["levels"]["other"] = "high"
        row["admission"]["other"] = "unprobed"
    else:
        intent = "standard" if case == "missing-default" else "max"
        del row["levels"][intent]
        del row["admission"][intent]
    path = setup.tmp / (uuid.uuid4().hex + ".json")
    path.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(module, "MODEL_BINDINGS", path)
    refused = call("add-role", mr1_r4_request(setup, setup.base, "add-role", "claude-code",
                                            model="claude-opus-5-5", effort="medium"), expect=2)
    assert refused == {"error": "invalid model bindings %s: %s; repair model-bindings.json" % (path, problem)}
    assert unbound(setup, "pilot/orchestrator")


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("state", ["unprobed", "admitted", "rejected"])
def test_mr1_r5_selected_admission_is_recorded_or_refused(setup, mr1_cli, monkeypatch, command, host, state):
    module, call = mr1_cli
    mr1_plan(setup, host)
    data = mr1_bindings()
    row = next(row for row in data["hosts"] if row["host"] == host and row["class"] == "coding")
    row["admission"]["extended"] = state
    row["admission"]["light"] = "rejected"  # Neither a required default nor ceiling.
    path = setup.tmp / (uuid.uuid4().hex + ".json")
    path.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(module, "MODEL_BINDINGS", path)
    request = mr1_r4_request(setup, setup.base, command, host, endpoint="pilot/lane/f2",
                             model=row["model"], effort="xhigh")
    answer = call(command, request, expect=2 if state == "rejected" else 0)
    if state == "rejected":
        assert answer == {"error": "%s intent extended (effort xhigh) is rejected for %s; choose a different supported level" %
                          (row["model"], host)}
        assert unbound(setup, "pilot/lane/f2")
    else:
        assert answer["team"]["admission"] == state and answer["team"]["intent"] == "extended"


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("effort", ["low", "medium"])
def test_mr1_r5_partial_binding_accepts_supported_levels_and_names_unsupported_ones(setup, mr1_cli, monkeypatch,
                                                                                command, host, effort):
    module, call = mr1_cli
    mr1_plan(setup, host)
    data = mr1_bindings()
    for row in data["hosts"]:
        intents = ("standard", "deep", "max") if row["class"] == "coding" else ("deep",)
        row["levels"] = {key: row["levels"][key] for key in intents}
        row["admission"] = {key: "unprobed" for key in intents}
    row = next(row for row in data["hosts"] if row["host"] == host and row["class"] == "coding")
    path = setup.tmp / (uuid.uuid4().hex + ".json")
    path.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(module, "MODEL_BINDINGS", path)
    answer = call(command, mr1_r4_request(setup, setup.base, command, host, model=row["model"], effort=effort),
                  expect=2 if effort == "low" else 0)
    if effort == "low":
        assert answer == {"error": "orchestrator effort low has no supported intent; supported intents: standard, deep, max; "
                          "choose a supported effort"}
        assert unbound(setup, "pilot/orchestrator")
    else:
        assert answer["team"]["intent"] == "standard" and answer["team"]["effort"] == "medium"


@pytest.mark.parametrize("which", ["team", "bindings"])
def test_mr1_r5_unicode_paths_and_repair_text_survive_refusals(tmp_path_factory, mr1_cli, monkeypatch, which):
    module, call = mr1_cli
    folder = tmp_path_factory.mktemp("mr1-unicode-" + uuid.uuid4().hex) / "José"
    folder.mkdir()
    setup = Setup(folder)
    setup.init()
    mr1_plan(setup)
    if which == "team":
        path = setup.base / "team.json"
        path.write_text('{"bad-ｘ":1,"bad-ｘ":2}', encoding="utf-8")
        error = "invalid JSON file %s: duplicate JSON key 'bad-\\uff58'; repair team.json" % path
    else:
        path = folder / "model-bindings.json"
        data = mr1_bindings()
        data["hosts"][0]["class"] = "ｘ" * 100
        path.write_text(json.dumps(data), encoding="utf-8")
        monkeypatch.setattr(module, "MODEL_BINDINGS", path)
        shown = ascii("ｘ" * 100)[:77] + "..."
        error = "invalid model bindings %s: unknown model class %s; repair model-bindings.json" % (path, shown)
    refused = call("add-role", mr1_r4_request(setup, setup.base, "add-role", "claude-code",
                                            model="claude-opus-5-5", effort="medium"), expect=2)
    assert refused == {"error": error}
    assert str(path) in refused["error"] and "José" in refused["error"] and "ｘ" not in refused["error"]
    assert unbound(setup, "pilot/orchestrator")





@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("kind,endpoint,default", MR1_R2_BANDED_ROLES)
def test_mr1_r2_missing_effort_names_band_default_without_applying_it(mr1_r2_setup, mr1_cli, command, host, kind, endpoint,
                                                                  default):
    setup = mr1_r2_setup
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    refused = call(command, mr1_request(setup, command, endpoint, host, model=model), expect=2)
    intent = "standard" if default == "medium" else "deep"
    assert refused == {"error": "%s has no effort; set %s (intent %s, band default) in request effort or team.json reasoning" %
                       (kind, default, intent)}
    assert unbound(setup, endpoint)


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("kind,endpoint,effort", MR1_R2_BANDED_ROLES)
def test_mr1_r3_host_defaults_keep_exact_answers_without_policy_provenance(mr1_r2_setup, mr1_cli, monkeypatch,
                                                                        command, host, kind, endpoint, effort):
    setup = mr1_r2_setup
    module, call = mr1_cli
    request = mr1_request(setup, command, endpoint, host)
    before = call(command, dict(request))
    mr1_plan(setup, host)
    garbage = setup.tmp / "unused-bindings.json"
    garbage.write_text("not JSON", encoding="utf-8")
    monkeypatch.setattr(module, "MODEL_BINDINGS", garbage)
    after = call(command, dict(request))
    assert after == before
    assert "team" not in after
    argv = json.loads(Path(after["wake_profile"]).read_text())["argv"] if command == "add-role" else after["start_argv"]
    if host == "codex-cli":
        config = codex_config(argv)
        assert "model" not in config and "model_reasoning_effort" not in config
    else:
        assert "--model" not in argv and "--effort" not in argv


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("kind,endpoint,effort", MR1_R2_BANDED_ROLES)
def test_mr1_r3_effort_without_model_refuses_with_binding_instruction(mr1_r2_setup, mr1_cli, command, host,
                                                                   kind, endpoint, effort):
    setup = mr1_r2_setup
    _, call = mr1_cli
    mr1_plan(setup, host)
    model = next(row["model"] for row in mr1_bindings()["hosts"] if row["host"] == host and row["class"] == "coding")
    refused = call(command, mr1_request(setup, command, endpoint, host, effort=effort), expect=2)
    assert refused == {"error": "no model: set the request model or team.json model (coding binding for %s: %s)" %
                       (host, model)}
    assert unbound(setup, endpoint)


@pytest.mark.parametrize("command,host", MR1_R2_ENTRY_POINTS)
@pytest.mark.parametrize("planned", [False, True])
def test_mr1_r4_copy_without_any_team_file_keeps_host_defaults(setup, mr1_cli, tmp_path_factory, command, host, planned):
    _, call = mr1_cli
    copied = mr1_r4_copy_base(setup, tmp_path_factory)
    request = mr1_r4_request(setup, copied, command, host)
    before = call(command, dict(request))
    if planned:
        mr1_plan(setup, host)
    else:
        # Without a plan only the caller's own team.json applies, as before.
        (setup.base / "team.json").write_text("not JSON", encoding="utf-8")
    assert call(command, dict(request)) == before
    assert "team" not in before


ROOT_TOOLS = ["root_decide", "team_status", "team_pending", "team_request"]
ROOT_READS = "loop_state and evidence are only for ROOT's decision adapter, with its lifecycle and actor"


def root_args(setup, host, session=ROOT_SESSION, actor="root-1", reads=()):
    # ROOT's own entry, which also carries the read-only --loop-state and --evidence the pinned mailbox CLI cannot.
    return ["-I", "-B", str(setup.base / "runtime-source.py"), "--provision", str(setup.base / "provision.json"),
            "--entry", str(setup.source / "tools" / "hierarchy_mailbox_mcp.py"), "--", "--root", str(setup.root), "serve",
            "--endpoint", "pilot/root", "--host", host, "--session", session, "--generation", "1",
            "--lifecycle", setup.lifecycle, "--actor", actor, *reads]


def call_server(definition, calls):
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}]
    frames += [{"jsonrpc": "2.0", "id": index + 2, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
               for index, (name, arguments) in enumerate(calls)]
    result = subprocess.run([definition["command"], *definition["args"]], input="".join(json.dumps(f) + "\n" for f in frames),
                            capture_output=True, text=True, timeout=20, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0, result.stdout + result.stderr
    return [json.loads(line) for line in result.stdout.splitlines()][1:]


def test_root_with_a_journal_gets_a_decision_connection_that_records_root_decide(team):
    from tests.integration.test_hierarchy_lifecycle import raw_request, request as lifecycle_request
    role = team.add_role("pilot/root", session=ROOT_SESSION, lifecycle=team.lifecycle, actor="root-1")
    assert "wake_profile" not in role and "start_argv" not in role and "mcp_config" not in role
    assert not (team.base / "profiles").exists() or not list((team.base / "profiles").glob("*root*"))
    definition = json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_decision"]
    assert definition == {"command": "/usr/bin/python3", "args": root_args(team, "claude-code")}
    assert Path(role["connection"]).name == "pilot%2Froot-g1.json"
    assert start_connection(role["connection"], "aegis_decision") == set(ROOT_TOOLS)
    value = lifecycle_request("feature-1")
    team.ledger.publish(value)
    [answer] = call_server(definition, [("root_decide", {
        "event_id": "root-decision-1", "request_id": "feature-1", "request_sha256": raw_request(value)["sha256"],
        "decision": "approve", "reason": "the owner agreed this feature"})])
    assert answer["result"].get("isError") is not True, answer
    assert [(d["request_id"], d["decision"], d["actor"]) for d in team.ledger.status()["decisions"]] == [
        ("feature-1", "approve", "root-1")]


def test_a_codex_root_gets_the_decision_server_inline_and_a_native_root_a_flat_file(team, tmp_path):
    tomllib = pytest.importorskip("tomllib", reason="Codex settings are read with tomllib, Python 3.11+")
    role = team.add_role("pilot/root", "codex-cli", session=ROOT_SESSION, lifecycle=team.lifecycle, actor="root-1")
    # ROOT runs with approval_policy "never", so each enabled tool, the read tools too, carries its approve entry.
    assert tomllib.loads(role["mcp_config"]) == {"mcp_servers": {"aegis_decision": {
        "command": "/usr/bin/python3", "args": root_args(team, "codex-cli"), "required": True,
        "enabled_tools": ROOT_TOOLS, "tools": {name: {"approval_mode": "approve"} for name in ROOT_TOOLS}}}}
    assert json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_decision"]["args"] == root_args(team, "codex-cli")
    (tmp_path / "native").mkdir()
    native = Setup(tmp_path / "native")
    native.init()
    native.lifecycle = team.lifecycle
    flat = native.add_role("pilot/root", "codex", session=ROOT_SESSION, lifecycle=team.lifecycle, actor="root-1")
    assert json.loads(Path(flat["connection"]).read_text()) == {"command": "/usr/bin/python3", "args": root_args(native, "codex")}
    assert "mcp_config" not in flat


def test_root_without_a_journal_keeps_its_binding_only_answer(team):
    role = team.add_role("pilot/root", session=ROOT_SESSION)
    assert role == {"endpoint": "pilot/root", "host": "claude-code", "session": ROOT_SESSION, "generation": 1}


def test_roots_enabled_tools_are_its_adapters_own_list(team):
    """The Codex allow-list and the adapter's tools/list come from the same registry entry, so neither drifts."""
    tomllib = pytest.importorskip("tomllib", reason="Codex settings are read with tomllib, Python 3.11+")
    role = team.add_role("pilot/root", "codex-cli", session=ROOT_SESSION, lifecycle=team.lifecycle, actor="root-1")
    enabled = tomllib.loads(role["mcp_config"])["mcp_servers"]["aegis_decision"]["enabled_tools"]
    definition = json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_decision"]
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    listed = subprocess.run([definition["command"], *definition["args"]], capture_output=True, text=True, timeout=20,
                            input="".join(json.dumps(f) + "\n" for f in frames),
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert enabled == [tool["name"] for tool in json.loads(listed.stdout.splitlines()[1])["result"]["tools"]]


def test_root_given_the_loop_state_and_evidence_reads_them_through_its_connection(team, tmp_path):
    state_dir, evidence = tmp_path / "loop", tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "init.json").write_text("{}")
    role = team.add_role("pilot/root", "codex-cli", session=ROOT_SESSION, lifecycle=team.lifecycle, actor="root-1",
                         loop_state=str(state_dir), evidence=str(evidence))
    definition = json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_decision"]
    assert definition["args"] == root_args(team, "codex-cli", reads=["--loop-state", str(state_dir),
                                                                     "--evidence", str(evidence)])
    [answer] = call_server(definition, [("team_status", {})])
    status = json.loads(answer["result"]["content"][0]["text"])
    # The loop has not run yet, so its folder has no status file; the evidence folder holds one file.
    assert status["loop"]["state"] == "absent"
    assert (status["evidence"]["present"], status["evidence"]["files"]) == (True, 1)
    assert not state_dir.exists()


@pytest.mark.parametrize("endpoint,changes,error", [
    ("pilot/root", {"loop_state": "<loop>"}, ROOT_READS),
    ("pilot/root", {"evidence": "<loop>"}, ROOT_READS),
    ("pilot/root", {"lifecycle": "<journal>", "actor": "root-1", "loop_state": "relative/loop"},
     "path must be absolute without traversal"),
    ("pilot/root", {"lifecycle": "<journal>", "actor": "root-1", "evidence": 7}, "invalid evidence"),
    ("pilot/root", {"lifecycle": "<journal>", "actor": "root-1", "loop_state": ""}, "invalid loop_state"),
    ("pilot/orchestrator", {"loop_state": "<loop>"}, ROOT_READS),
    ("pilot/decider", {"lifecycle": "<journal>", "actor": "decider-1", "evidence": "<loop>"}, ROOT_READS),
    ("pilot/router", {"lifecycle": "<journal>", "loop_state": "<loop>"}, ROOT_READS),
])
def test_loop_state_and_evidence_go_only_to_roots_decision_adapter(team, endpoint, changes, error):
    swap = {"<journal>": team.lifecycle, "<loop>": str(team.tmp / "loop")}
    changes = {key: swap.get(value, value) if isinstance(value, str) else value for key, value in changes.items()}
    session = ROOT_SESSION if endpoint == "pilot/root" else str(uuid.uuid4())
    refused = team.add_role(endpoint, session=session, cwd=str(team.tmp), expect=2, **changes)
    assert refused["error"] == error
    assert unbound(team, endpoint) and not (team.base / "connections").exists()


@pytest.mark.parametrize("changes,error", [
    ({"lifecycle": "<journal>"}, PAIR),
    ({"actor": "root-1"}, PAIR),
    ({"lifecycle": "<journal>", "actor": "router-1"}, "actor router-1 is not a root actor in the lifecycle policy"),
    ({"lifecycle": "<journal>", "actor": "absent-1"}, "actor absent-1 is not a root actor in the lifecycle policy"),
    ({"lifecycle": "<journal>", "actor": "../root"}, "invalid actor"),
    ({"lifecycle": "relative/journal", "actor": "root-1"}, "path must be absolute without traversal"),
])
def test_root_lifecycle_keys_are_checked_before_binding(team, changes, error):
    changes = {key: team.lifecycle if value == "<journal>" else value for key, value in changes.items()}
    refused = team.add_role("pilot/root", session=ROOT_SESSION, expect=2, **changes)
    assert refused["error"] == error
    assert unbound(team, "pilot/root") and not (team.base / "connections").exists()


def test_a_router_with_the_journal_gets_router_status(team):
    role = team.add_role("pilot/router", cwd=str(team.tmp), lifecycle=team.lifecycle)
    arguments = json.loads(Path(role["connection"]).read_text())["mcpServers"]["aegis_mailbox"]["args"]
    assert arguments[-2:] == ["--lifecycle", team.lifecycle] and "--actor" not in arguments
    assert "router_status" in start_connection(role["connection"])
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert "mcp__aegis_mailbox__router_status" in flag(argv, "--allowedTools").split(",")


def test_a_codex_router_enables_router_status_and_without_the_journal_does_not(team, tmp_path):
    role = team.add_role("pilot/router", "codex-cli", session=REVIEW_SESSION, cwd=str(team.source), lifecycle=team.lifecycle)
    server = codex_config(json.loads(Path(role["wake_profile"]).read_text())["argv"])["mcp_servers"]["aegis_mailbox"]
    assert server["enabled_tools"][-1] == "router_status" and "router_status" not in server["tools"]
    (tmp_path / "plain").mkdir()
    plain = Setup(tmp_path / "plain")
    provision("init", plain.init_request(roles=["router"]))
    without = plain.add_role("pilot/router", cwd=str(plain.tmp))
    assert "router_status" not in start_connection(without["connection"])


def test_the_router_session_is_refused_an_actor(team):
    refused = team.add_role("pilot/router", cwd=str(team.tmp), lifecycle=team.lifecycle, actor="router-1", expect=2)
    assert refused["error"] == ROUTER_ACTOR
    refused = team.add_role("pilot/router", cwd=str(team.tmp), actor="router-1", expect=2)
    assert refused["error"] == ROUTER_ACTOR
    assert unbound(team, "pilot/router")


def test_a_decider_with_the_journal_and_its_actor_gets_decider_record(team):
    role = team.add_role("pilot/decider", "codex-cli", session=REVIEW_SESSION, cwd=str(team.source), reader_shell=True,
                         lifecycle=team.lifecycle, actor="decider-1")
    server = codex_config(json.loads(Path(role["wake_profile"]).read_text())["argv"])["mcp_servers"]["aegis_mailbox"]
    assert server["args"][-4:] == ["--lifecycle", team.lifecycle, "--actor", "decider-1"]
    assert server["enabled_tools"][-1] == "decider_record"
    assert server["tools"]["decider_record"] == {"approval_mode": "approve"}
    (team.tmp / "claude").mkdir()
    claude = Setup(team.tmp / "claude")
    provision("init", claude.init_request(roles=["decider"]))
    plain = claude.add_role("pilot/decider", cwd=str(claude.tmp), lifecycle=team.lifecycle, actor="decider-1")
    assert "decider_record" in start_connection(plain["connection"])
    argv = json.loads(Path(plain["wake_profile"]).read_text())["argv"]
    assert "mcp__aegis_mailbox__decider_record" in flag(argv, "--allowedTools").split(",")


@pytest.mark.parametrize("changes,error", [
    ({"lifecycle": "<journal>"}, PAIR),
    ({"actor": "decider-1"}, PAIR),
    ({"lifecycle": "<journal>", "actor": "root-1"}, "actor root-1 is not a decider actor in the lifecycle policy"),
])
def test_decider_lifecycle_keys_are_checked_before_binding(team, changes, error):
    changes = {key: team.lifecycle if value == "<journal>" else value for key, value in changes.items()}
    refused = team.add_role("pilot/decider", cwd=str(team.tmp), expect=2, **changes)
    assert refused["error"] == error
    assert unbound(team, "pilot/decider")


@pytest.mark.parametrize("endpoint,role,key", [
    ("pilot/orchestrator", "orchestrator", "lifecycle"), ("pilot/lane/f2", "implementer", "actor"),
    ("pilot/lane/review", "reviewer", "lifecycle"), ("pilot/front-door", "front-door", "actor"),
])
def test_other_roles_have_no_lifecycle_connection(team, endpoint, role, key):
    refused = team.add_role(endpoint, cwd=str(team.tmp), expect=2, **{key: team.lifecycle if key == "lifecycle" else "root-1"})
    assert refused["error"] == NO_LIFECYCLE % role
    assert unbound(team, endpoint)


@pytest.mark.parametrize("journal,error", [
    ("<missing>", "lifecycle is not a journal directory: <missing>"),
    ("<file>", "lifecycle is not a journal directory: <file>"),
    (None, "invalid lifecycle"),
    (7, "invalid lifecycle"),
])
def test_a_router_journal_that_is_not_a_journal_is_refused_before_binding(team, journal, error):
    paths = {"<missing>": str(team.tmp / "no-journal"), "<file>": str(team.tmp / "journal-file")}
    (team.tmp / "journal-file").write_text("{}")
    journal = paths.get(journal, journal)
    for name, path in paths.items():
        error = error.replace(name, path)
    refused = team.add_role("pilot/router", cwd=str(team.tmp), lifecycle=journal, expect=2)
    assert refused["error"] == error
    assert unbound(team, "pilot/router") and not (team.base / "connections").exists()


@pytest.mark.parametrize("endpoint,changes,error", [
    ("pilot/orchestrator", {"lifecycle": None}, NO_LIFECYCLE % "orchestrator"),
    ("pilot/orchestrator", {"actor": None}, NO_LIFECYCLE % "orchestrator"),
    ("pilot/router", {"actor": None}, ROUTER_ACTOR),
    ("pilot/router", {"lifecycle": "<journal>", "actor": None}, ROUTER_ACTOR),
    ("pilot/root", {"lifecycle": None, "actor": None}, "invalid actor"),
    ("pilot/root", {"lifecycle": None, "actor": "root-1"}, "invalid lifecycle"),
    ("pilot/root", {"lifecycle": "<journal>", "actor": None}, "invalid actor"),
    ("pilot/root", {"lifecycle": "<journal>"}, PAIR),
    ("pilot/decider", {"lifecycle": "<journal>", "actor": None}, "invalid actor"),
    ("pilot/decider", {"lifecycle": ["<journal>"], "actor": "decider-1"}, "invalid lifecycle"),
    ("pilot/decider", {"actor": None}, PAIR),
])
def test_a_null_or_non_string_lifecycle_key_is_refused_before_binding(team, endpoint, changes, error):
    changes = {key: team.lifecycle if value == "<journal>" else value for key, value in changes.items()}
    extra = {"session": ROOT_SESSION} if endpoint == "pilot/root" else {"cwd": str(team.tmp)}
    refused = team.add_role(endpoint, expect=2, **extra, **changes)
    assert refused["error"] == error
    assert unbound(team, endpoint) and not (team.base / "connections").exists()


def test_a_codex_router_applies_its_registry_tier(team):
    role = team.add_role("pilot/router", "codex-cli", session=REVIEW_SESSION, cwd=str(team.source))
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    settings = [argv[index + 1] for index, word in enumerate(argv) if word == "-c"]
    effort = settings.index('model_reasoning_effort="medium"')
    assert settings[effort + 1] == 'service_tier="ultrafast"'
    assert role["model_profile"] == {"source": "registry", "effort": "medium", "tier": "ultrafast", "tier_applied": True}
    profile = json.loads(Path(role["codex_profile"]).read_text())
    assert profile["service_tier"] == "ultrafast" and profile["effort"] == "medium"


def test_a_claude_router_records_its_tier_without_a_flag(team):
    role = team.add_role("pilot/router", cwd=str(team.tmp))
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert not any("ultrafast" in word for word in argv) and "codex_profile" not in role
    assert role["model_profile"]["tier_applied"] is False


def disabled(argv):
    return [argv[index + 1] for index, word in enumerate(argv) if word == "--disable"]


def assert_argv_follows_profile(argv, profile):
    config = codex_config(argv)
    assert disabled(argv) == profile["disabled_features"]
    assert flag(argv, "--sandbox") == profile["sandbox"] and flag(argv, "-C") == profile["cwd"]
    assert ("--ignore-user-config" in argv) is profile["ignore_user_config"]
    assert config["approval_policy"] == profile["approval_policy"]
    assert config["mcp_servers"] == profile["mcp_servers"]
    for setting, key in (("model", "model"), ("model_reasoning_effort", "effort"), ("service_tier", "service_tier")):
        assert config.get(setting) == profile[key], setting
    if profile["sandbox"] == "workspace-write":
        assert config["sandbox_workspace_write"]["writable_roots"] == profile["writable_roots"]
        assert config["sandbox_workspace_write"]["network_access"] is profile["network_access"]
    else:
        assert "sandbox_workspace_write" not in config
    assert [argv[index + 1] for index, word in enumerate(argv) if word == "--add-dir"] == profile["add_dirs"]
    assert ("--skip-git-repo-check" in argv) is profile["skip_git_repo_check"]
    tmpdir = (config.get("shell_environment_policy") or {}).get("set", {}).get("TMPDIR")
    assert tmpdir == profile["tmpdir"]


def test_a_codex_reviewer_profile_is_recorded_and_its_argv_is_built_from_it(setup):
    role = setup.add_role("pilot/lane/review", "codex-cli", session=REVIEW_SESSION, cwd=str(setup.source))
    assert Path(role["codex_profile"]) == setup.base / "profiles" / "pilot%2Flane%2Freview-g1.codex.json"
    profile = json.loads(Path(role["codex_profile"]).read_text())
    assert {key: profile[key] for key in ("schema", "endpoint", "role", "host", "session", "generation", "sandbox",
                                          "writable_roots", "network_access", "approval_policy", "ignore_user_config",
                                          "cwd", "skip_git_repo_check", "model", "effort", "service_tier", "tmpdir",
                                          "add_dirs")} == {
        "schema": "aegis.hierarchy-codex-profile/v1", "endpoint": "pilot/lane/review", "role": "reviewer",
        "host": "codex-cli", "session": REVIEW_SESSION, "generation": 1, "sandbox": "read-only", "writable_roots": [],
        "network_access": False, "approval_policy": "never", "ignore_user_config": True, "cwd": str(setup.source),
        "skip_git_repo_check": False, "model": None, "effort": None, "service_tier": None, "tmpdir": None, "add_dirs": []}
    assert "shell_tool" in profile["disabled_features"]
    server = profile["mcp_servers"]["aegis_mailbox"]
    # The reviewer's registry entry reads no workspace view, so it has the mailbox tools alone.
    assert server["enabled_tools"] == ["mailbox_inbox", "mailbox_publish", "mailbox_ack_handoff", "mailbox_self"]
    assert server["required"] is True and server["command"] == "/usr/bin/python3"
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert argv[-2:] == ["resume", REVIEW_SESSION]
    assert_argv_follows_profile(argv, profile)


def test_a_codex_implementer_profile_writes_only_its_roots(setup, tmp_path):
    writable, private = tmp_path / "worktree", tmp_path / "private-tmp"
    writable.mkdir()
    private.mkdir()
    role = setup.add_role("pilot/lane/f2", "codex-cli", session=CODEX_SESSION, cwd=str(setup.source),
                          writable_roots=[str(writable)], tmpdir=str(private), add_dirs=[str(writable)],
                          model="gpt-5.5-codex", effort="high", skip_git_repo_check=True)
    profile = json.loads(Path(role["codex_profile"]).read_text())
    assert profile["role"] == "implementer" and profile["sandbox"] == "workspace-write"
    assert profile["writable_roots"] == [str(writable)] and profile["network_access"] is False
    assert profile["approval_policy"] == "never" and "shell_tool" not in profile["disabled_features"]
    assert (profile["model"], profile["effort"], profile["tmpdir"]) == ("gpt-5.5-codex", "high", str(private))
    assert_argv_follows_profile(json.loads(Path(role["wake_profile"]).read_text())["argv"], profile)


def test_codex_start_returns_the_profile_without_writing_it(team):
    started = provision("codex-start", team.request(base=str(team.base), endpoint="pilot/router", cwd=str(team.source)))
    profile = started["codex_profile"]
    assert (profile["session"], profile["generation"], profile["mcp_servers"]) == (None, None, {})
    assert profile["role"] == "router" and profile["service_tier"] == "ultrafast"
    assert_argv_follows_profile(started["start_argv"], profile)
    assert not (team.base / "profiles").exists()


def test_a_launched_codex_role_records_its_codex_profile(tmp_path):
    from tests.integration.test_hierarchy_launcher import Launch
    launch = Launch(tmp_path)
    launch.init()
    thread = "019a6c3e-1111-7222-8333-444455556677"
    answer = launch.start(thread=thread, cwd=str(launch.source))
    assert answer["state"] == "bound"
    profile = json.loads(Path(answer["codex_profile"]).read_text())
    assert profile["session"] == thread and profile["role"] == "reviewer"
    assert_argv_follows_profile(json.loads(Path(answer["wake_profile"]).read_text())["argv"], profile)
