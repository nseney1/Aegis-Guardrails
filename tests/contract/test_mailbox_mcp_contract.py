"""Mailbox tools/list contracts, separated by connection kind.

Regenerate every connection kind, optional role tool, and validated host-plan variant.
Setup is shared per module, per xdist worker; discovery uses a fresh stdio process per surface:

    PYTHONPATH=. python3 tests/contract/test_mailbox_mcp_contract.py --write
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory

import pytest

SNAPSHOT = Path(__file__).with_name("mailbox_mcp_tools.json")
REPO = Path(__file__).resolve().parents[2]
PROFILES = {
    "role": ("a/orchestrator", ()),
    "role_source": ("a/orchestrator", ("source",)),
    "router_lifecycle": ("a/router", ("workspace", "lifecycle")),
    "decider_lifecycle": ("a/decider", ("lifecycle",)),
    "workspace_orchestrator": ("a/orchestrator", ("workspace",)),
    "workspace_implementer": ("a/lane/writer", ("workspace",)),
    "front_door": ("a/front-door", ("workspace",)),
    "orchestrator_provisioned": ("a/orchestrator", ("workspace", "source")),
    "decider_provisioned": ("a/decider", ("workspace", "source", "lifecycle")),
    "reviewer": ("a/lane/review", ("workspace", "source")),
    "integrator": ("a/lane/integration", ("workspace",)),
    "board": ("a/orchestrator", ("board",)),
    "root": ("a/root", ("lifecycle",)),
}
CASES = {profile if profile in {"board", "root"} else profile + ("_planned" if planned else "_legacy"):
         (profile, planned) for profile in PROFILES
         for planned in ((False,) if profile in {"board", "root"} else (False, True))}
EXPECTED_EXTRAS = {
    "role_source": {"source_show", "source_grep"},
    "router_lifecycle": {"router_status"},
    "decider_lifecycle": {"decider_record"},
    "workspace_orchestrator": {"workspace_capacity", "workspace_initiative"},
    "workspace_implementer": {"workspace_path_overlap"},
    "front_door": {"workspace_initiative"},
    "orchestrator_provisioned": {"workspace_capacity", "workspace_initiative", "source_show", "source_grep"},
    "decider_provisioned": {"source_show", "source_grep", "decider_record"},
    "reviewer": {"source_show", "source_grep"},
    "integrator": {"workspace_path_overlap"},
}
LANE_ENDPOINTS = {"a/lane/writer": "implementer", "a/lane/review": "reviewer", "a/lane/integration": "integrator"}
# Entries without session endpoints have no mailbox MCP adapter, including hats/services.
ROLE_PROFILES = {
    "root": "root", "router": "router_lifecycle", "orchestrator": "orchestrator_provisioned",
    "reviewer": "reviewer", "decider": "decider_provisioned", "implementer": "workspace_implementer",
    "integrator": "integrator", "front-door": "front_door",
    "test-author": None, "owner": None, "watch-supervisor": None, "provider-bridge": None,
    "job-executor": None, "architect": None, "validation-operator": None,
    "specialist-reviewer": None, "release-operator": None,
}
FORBIDDEN_OPTIONS = {
    ("root", "source"): "the ROOT decision adapter takes no source views",
    ("root", "board"): "the ROOT decision adapter takes no mailbox, workspace or board options",
    ("root", "workspace"): "the ROOT decision adapter takes no mailbox, workspace or board options",
    **{(role, "source"): "the %s role has no source views: they are for roles that read source and write none" % role
       for role in ("router", "implementer", "integrator", "front-door")},
    **{(role, "board"): "the %s role has no board access" % role for role in ("router", "reviewer", "decider")},
    **{(role, "lifecycle"): "the %s role has no lifecycle connection" % role
       for role in ("orchestrator", "reviewer", "implementer", "integrator", "front-door")},
}
REFUSAL_CASES = {"refused_" + role + "_" + option: (role, option, error)
                 for (role, option), error in FORBIDDEN_OPTIONS.items()}
PYTHON_RUNS = 0


def run_python(*arguments, input=None, expected_returncode=0):
    global PYTHON_RUNS
    PYTHON_RUNS += 1
    process = subprocess.run(
        [sys.executable, "-I", "-B", *map(str, arguments)],
        cwd=REPO, input=input, capture_output=True, text=True, encoding="utf-8", timeout=30,
        check=False)
    assert process.returncode == expected_returncode, process.stdout + process.stderr
    assert not process.stderr, process.stderr
    return process.stdout


def run_tool(script, *arguments, input=None, expected_returncode=0):
    return run_python(REPO / "tools" / script, *arguments, input=input, expected_returncode=expected_returncode)


def build_source_repository(directory):
    repository = directory / "source"
    repository.mkdir()
    (repository / "contract.txt").write_text("contract fixture\n", encoding="utf-8")
    hooks = directory / "empty-hooks"
    hooks.mkdir()
    # -C does not override inherited index, worktree, object-store or config selectors.
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    environment.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
    for arguments in (("init", "-q", "-b", "main"), ("add", "contract.txt"), ("commit", "-qm", "contract fixture")):
        process = subprocess.run(
            ["git", "-C", str(repository), "-c", "core.fsmonitor=false", "-c", "core.autocrlf=false",
             "-c", "core.hooksPath=" + str(hooks), "-c", "commit.gpgsign=false",
             "-c", "user.name=contract", "-c", "user.email=contract@example.invalid", *arguments],
            env=environment,
            capture_output=True, text=True, encoding="utf-8", timeout=30, check=False)
        assert process.returncode == 0, process.stdout + process.stderr
        assert not process.stderr, process.stderr


def write_request(directory, value):
    path = directory / "request.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def root_policy(directory):
    # Synthetic configuration for discovery only; no decision or execution is requested.
    evidence = directory / "authority.txt"
    evidence.write_bytes(b"contract fixture\n")
    actors = {}
    for role in ("root", "router", "coordinator", "operator", "reviewer", "decider"):
        actors[role + "-1"] = {
            "role": role, "generation": 1, "cap_seconds": 60,
            "profile": {"model": "contract-fixture", "effort": "medium", "tier": "ultrafast",
                        "filesystem": "read-only" if role == "root" else "workspace-write", "tools": []}}
    return {"schema": "aegis.lifecycle-policy/v1",
            "source": {"commit": "a" * 40, "tree": "b" * 40, "dirty_sha256": "c" * 64},
            "authority": [{"path": str(evidence), "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest()}],
            "actors": actors, "current": {role: role + "-1" for role in
                                           ("root", "router", "coordinator", "operator", "reviewer", "decider")},
            "successors": {}}


def build_base(directory):
    directory = directory.resolve()
    standalone = directory / "standalone"
    standalone.mkdir()
    mailbox = standalone / "mailbox"
    endpoints = {endpoint: {} for endpoint, _ in PROFILES.values()}
    endpoints.update({endpoint: {"kind": kind} for endpoint, kind in LANE_ENDPOINTS.items()})
    manifest = {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints,
                "counterparts": [], "writer_limit": 1}
    run_tool("hierarchy_mailbox.py", "--root", mailbox, "init", "--request", write_request(directory, manifest))
    for endpoint in dict.fromkeys(endpoint for endpoint, _ in PROFILES.values()):
        run_tool("hierarchy_mailbox.py", "--root", mailbox, "bind", "--request",
                 write_request(directory, {"endpoint": endpoint, "host": "contract-host",
                                           "session": endpoint, "expected_generation": 0}))
    run_tool("hierarchy_board.py", "--board", directory / "board", "init")
    store = directory / "workspace"
    run_tool("hierarchy_workspace.py", "--store", store, "init", "--request",
             write_request(directory, {"writer_limit": 1, "heavy_limit": 1}))
    run_tool("hierarchy_workspace.py", "--store", store, "register", "--request",
             write_request(directory, {"id": "contract", "project": "contract", "repository": "contract",
                                       "priority": 1, "target_branch": "main"}))
    # Discovery only validates policy; no POSIX-only lifecycle mutation is needed.
    lifecycle = directory / "lifecycle"
    lifecycle.mkdir()
    (lifecycle / "policy.json").write_text(json.dumps(root_policy(directory)), encoding="utf-8")
    build_source_repository(directory)
    # Use the same validated constructor as the integration host-plan fixtures, isolated from pytest imports.
    code = ("import json,sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); "
            "import hierarchy_hosts as hosts; plan=hosts.plan_record('a',sys.argv[3],sys.argv[3],{},'0'*64); "
            "(Path(sys.argv[2])/hosts.PLAN_FILE).write_text(json.dumps(plan),encoding='utf-8')")
    for host in ("codex-cli", "claude-code"):
        planned = directory / ("planned-" + host)
        planned.mkdir()
        shutil.copytree(mailbox, planned / "mailbox")
        run_python("-c", code, REPO / "tools", planned, host)
    return directory


def connection_result(directory, profile, *, planned=False, plan_host="codex-cli", enabled=None, expected_returncode=0):
    endpoint, configured = PROFILES[profile]
    if enabled is None:
        enabled = configured
    mailbox = directory / ("planned-" + plan_host if planned else "standalone") / "mailbox"
    script = "hierarchy_mailbox_mcp.py" if profile == "root" else "hierarchy_mailbox.py"
    options = []
    if "board" in enabled:
        options += ["--board", directory / "board"]
    if "workspace" in enabled:
        options += ["--workspace-store", directory / "workspace", "--initiative", "contract"]
    if "source" in enabled:
        options += ["--source-repo", directory / "source"]
    if "lifecycle" in enabled:
        options += ["--lifecycle", directory / "lifecycle"]
        if profile != "router_lifecycle":
            options += ["--actor", "root-1" if profile == "root" else "decider-1"]
    requests = [{"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    output = run_tool(script, "--root", mailbox, "serve", "--endpoint", endpoint,
                      "--host", "contract-host", "--session", endpoint, "--generation", "1",
                      *options, input="".join(json.dumps(request) + "\n" for request in requests),
                      expected_returncode=expected_returncode)
    if expected_returncode:
        return json.loads(output)
    frames = [json.loads(line) for line in output.splitlines()]
    assert len(frames) == 2, output
    assert frames[0]["id"] == 1
    assert frames[0]["result"]["serverInfo"]["name"] == "aegis-hierarchy-mailbox"
    assert frames[1]["id"] == 2
    return frames[1]["result"]


def live_tools_list(directory, case, *, plan_host="codex-cli"):
    profile, planned = CASES[case]
    return connection_result(directory, profile, planned=planned, plan_host=plan_host)


def refused_tools_list(directory, case):
    role, option, _ = REFUSAL_CASES[case]
    # Isolate the rejected option from any otherwise-permitted role options.
    enabled = ("lifecycle", option) if role == "root" else (option,)
    return connection_result(directory, ROLE_PROFILES[role], enabled=enabled, expected_returncode=2)


def base_bytes(directory):
    return {path.relative_to(directory): path.read_bytes() for path in directory.rglob("*") if path.is_file()}


@pytest.fixture(scope="module")
def contract_base(tmp_path_factory):
    directory = build_base(tmp_path_factory.mktemp("mailbox-mcp-contract"))
    before = base_bytes(directory)
    yield directory
    assert base_bytes(directory) == before, "discovery mutated the shared contract base"


@pytest.mark.parametrize("case", CASES)
def test_mailbox_tools_match_their_connection_contract(contract_base, case):
    actual = live_tools_list(contract_base, case)
    profile, planned = CASES[case]
    tools = {tool["name"]: tool for tool in actual["tools"]}
    optional = set().union(*EXPECTED_EXTRAS.values())
    assert tools.keys() & optional == EXPECTED_EXTRAS.get(profile, set())
    if profile not in {"board", "root"}:
        properties = tools["mailbox_inbox"]["inputSchema"]["properties"]
        assert properties.keys() & {"order", "since", "briefs"} == ({"order", "since", "briefs"} if planned else set())
    else:
        assert "mailbox_inbox" not in tools
    assert SNAPSHOT.is_file(), "regenerate the mailbox MCP contract snapshot with --write"
    expected = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert set(expected) == set(CASES) | set(REFUSAL_CASES)
    assert actual == expected[case]
    if planned:
        assert live_tools_list(contract_base, case, plan_host="claude-code") == actual, "host plan changed tools/list"


def snapshot_tool_lists():
    for surface in json.loads(SNAPSHOT.read_text(encoding="utf-8")).values():
        if "tools" in surface:
            yield surface["tools"]


def test_snapshot_covers_optional_role_tools():
    names = {tool["name"] for tools in snapshot_tool_lists() for tool in tools}
    assert {"source_show", "source_grep", "router_status", "decider_record"} <= names


def test_snapshot_covers_planned_inbox_schema():
    inboxes = [tool for tools in snapshot_tool_lists() for tool in tools if tool["name"] == "mailbox_inbox"]
    assert any({"order", "since", "briefs"} <= tool["inputSchema"]["properties"].keys() for tool in inboxes)


def test_profiles_cover_every_registry_role():
    roles = json.loads((REPO / "tools/hierarchy_templates/role-registry.json").read_text(encoding="utf-8"))["roles"]
    expected = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert set(ROLE_PROFILES) == set(roles)
    for name, entry in roles.items():
        profile = ROLE_PROFILES[name]
        if entry["endpoint"] is None:
            assert profile is None and entry["provision"] is None
        else:
            assert profile in PROFILES, "registry role has no MCP contract profile: " + name
            endpoint = PROFILES[profile][0]
            assert endpoint.split("/")[1] == entry["endpoint"]["role"], name
            if "lane_kind" in entry["endpoint"]:
                assert LANE_ENDPOINTS[endpoint] == entry["endpoint"]["lane_kind"], name
            assert any(case in expected for case, (candidate, _) in CASES.items() if candidate == profile), name


def test_forbidden_option_cases_cover_the_registry_gates():
    roles = json.loads((REPO / "tools/hierarchy_templates/role-registry.json").read_text(encoding="utf-8"))["roles"]
    forbidden = set()
    for name, entry in roles.items():
        if entry["endpoint"] is None:
            continue
        decision = entry["provision"]["adapter"] == "decision"
        permitted = {"source": not decision and "source" in entry["reads"] and "source" not in entry["writes"],
                     "workspace": not decision, "board": not decision and "board" in entry["reads"],
                     "lifecycle": decision or bool(entry["provision"]["lifecycle_tools"])}
        forbidden.update((name, option) for option, allowed in permitted.items() if not allowed)
    assert set(FORBIDDEN_OPTIONS) == forbidden


@pytest.mark.parametrize("case", REFUSAL_CASES)
def test_forbidden_options_match_their_refusal_contract(contract_base, case):
    actual = refused_tools_list(contract_base, case)
    expected = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert actual == expected[case]


def test_snapshot_covers_forbidden_options():
    expected = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert REFUSAL_CASES.keys() <= expected.keys()
    for case, (_, _, error) in REFUSAL_CASES.items():
        assert expected[case] == {"error": error}


@pytest.mark.parametrize("profile,extras", [
    ("front_door", ["workspace_initiative"]),
    ("orchestrator_provisioned", ["workspace_capacity", "workspace_initiative", "source_show", "source_grep"]),
    ("decider_provisioned", ["source_show", "source_grep", "decider_record"]),
])
def test_snapshot_covers_provisioned_tool_order(profile, extras):
    expected = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    for suffix in ("_legacy", "_planned"):
        case = profile + suffix
        assert case in expected, "missing provisioned connection contract: " + case
        assert [tool["name"] for tool in expected[case]["tools"]] == [
            "mailbox_inbox", "mailbox_publish", "mailbox_ack_handoff", "mailbox_self", *extras]


def test_setup_preserves_the_callers_git_index(tmp_path, monkeypatch):
    # Use a real empty index in a disposable caller repository; never point the
    # regression at the developer's index, including during the initial RED run.
    for name in tuple(os.environ):
        if name.startswith("GIT_"):
            monkeypatch.delenv(name)
    environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    caller = tmp_path / "caller"
    caller.mkdir()
    subprocess.run(["git", "-C", str(caller), "init", "-q"], env=environment,
                   capture_output=True, check=True, timeout=30)
    index = tmp_path / "caller.index"
    subprocess.run(["git", "-C", str(caller), "read-tree", "--empty"],
                   env={**environment, "GIT_INDEX_FILE": str(index)}, capture_output=True, check=True, timeout=30)
    before = index.read_bytes()
    monkeypatch.setenv("GIT_INDEX_FILE", str(index))
    directory = tmp_path / "contract"
    directory.mkdir()
    base = build_base(directory)
    assert index.read_bytes() == before, "contract setup mutated the caller's Git index"
    expected = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    for case in ("orchestrator_provisioned_legacy", "orchestrator_provisioned_planned"):
        assert live_tools_list(base, case) == expected[case]
    assert index.read_bytes() == before, "contract discovery mutated the caller's Git index"


if __name__ == "__main__":
    if sys.argv[1:] != ["--write"]:
        sys.exit("usage: PYTHONPATH=. python3 tests/contract/test_mailbox_mcp_contract.py --write")
    with TemporaryDirectory(prefix="mailbox-mcp-contract-") as temporary:
        directory = build_base(Path(temporary))
        setup_runs = PYTHON_RUNS
        before = base_bytes(directory)
        surfaces = {case: live_tools_list(directory, case) for case in CASES}
        surfaces.update({case: refused_tools_list(directory, case) for case in REFUSAL_CASES})
        assert base_bytes(directory) == before, "discovery mutated the shared contract base"
    SNAPSHOT.write_text(json.dumps(surfaces, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {SNAPSHOT} ({PYTHON_RUNS} interpreters: {setup_runs} setup, {len(surfaces)} serves)")
