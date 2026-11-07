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
