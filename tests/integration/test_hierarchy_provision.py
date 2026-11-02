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
MAILBOX_TOOLS = {"mailbox_inbox", "mailbox_publish", "mailbox_ack_handoff"}


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
    shutil.rmtree(built.source / ".git")
    assert "source checkout" in provision("init", built.init_request(), expect=2)["error"]
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
    for feature in ("shell_tool", "unified_exec", "multi_agent", "apps", "plugins", "memories", "goals"):
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
