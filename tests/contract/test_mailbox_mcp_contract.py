"""Mailbox tools/list contracts, separated by connection kind.

Regenerate every connection kind, optional role tool, and validated host-plan variant.
Setup is shared per module, per xdist worker; discovery uses a fresh stdio process per surface:

    PYTHONPATH=. python3 tests/contract/test_mailbox_mcp_contract.py --write
"""
from __future__ import annotations

import hashlib
import ast
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


@pytest.fixture(scope="module")
def legacy_tools_result(contract_base):
    return live_tools_list(contract_base, "role_legacy")


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
    assert_matches_snapshot(actual, case)
    if planned:
        assert live_tools_list(contract_base, case, plan_host="claude-code") == actual, "host plan changed tools/list"


def assert_matches_snapshot(actual, case):
    assert SNAPSHOT.is_file(), "regenerate the mailbox MCP contract snapshot with --write"
    expected = read_snapshot()
    assert set(expected) == set(CASES) | set(REFUSAL_CASES)
    for tool, expected_tool in zip(actual["tools"], expected[case]["tools"]):
        assert canonical_json(tool) == canonical_json(expected_tool), (
            "MCP tool changed: " + tool["name"] + " (snapshot: " + expected_tool["name"] + ")")
    assert actual == expected[case], "MCP surface changed: " + case + " live=" + repr([
        tool["name"] for tool in actual["tools"]]) + " snapshot=" + repr([
        tool["name"] for tool in expected[case]["tools"]])


def read_snapshot():
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    return {case: {"tools": [snapshot["tools"][name][variant] for name, variant in surface]}
            if isinstance(surface, list) else surface for case, surface in snapshot["cases"].items()}


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def compact_snapshot(surfaces):
    tools, cases, variant_indices = {}, {}, {}
    for case, surface in surfaces.items():
        if "tools" not in surface:
            cases[case] = surface
            continue
        assert set(surface) == {"tools"}, case
        references = []
        for tool in surface["tools"]:
            name = tool["name"]
            variants = tools.setdefault(name, [])
            indices = variant_indices.setdefault(name, {})
            key = canonical_json(tool)
            if key not in indices:
                indices[key] = len(variants)
                variants.append(tool)
            references.append([name, indices[key]])
        cases[case] = references
    return {"tools": tools, "cases": cases}


def snapshot_tool_lists():
    for surface in read_snapshot().values():
        if "tools" in surface:
            yield surface["tools"]


def test_snapshot_stores_each_tool_variant_once():
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert set(snapshot) == {"tools", "cases"}
    assert set(snapshot["cases"]) == set(CASES) | set(REFUSAL_CASES)
    referenced = set()
    for case, surface in snapshot["cases"].items():
        if case in REFUSAL_CASES:
            assert surface == {"error": REFUSAL_CASES[case][2]}
            continue
        for name, variant in surface:
            assert isinstance(variant, int) and 0 <= variant < len(snapshot["tools"][name]), name
            assert snapshot["tools"][name][variant]["name"] == name
            referenced.add((name, variant))
    for name, variants in snapshot["tools"].items():
        assert variants, name
        assert len({json.dumps(tool, sort_keys=True) for tool in variants}) == len(variants), name
        assert {(name, variant) for variant in range(len(variants))} <= referenced, name


def test_compaction_preserves_json_types_and_ignores_key_order():
    tools = [{"name": "typed", "inputSchema": {"default": value}} for value in (True, 1, 1.0)]
    surfaces = {str(index): {"tools": [tool]} for index, tool in enumerate(tools)}
    surfaces["reordered"] = {"tools": [{"inputSchema": {"default": True}, "name": "typed"}]}
    snapshot = compact_snapshot(surfaces)
    assert json.dumps(snapshot["tools"]["typed"], sort_keys=True) == json.dumps(tools, sort_keys=True)
    assert snapshot["cases"] == {"0": [["typed", 0]], "1": [["typed", 1]],
                                 "2": [["typed", 2]], "reordered": [["typed", 0]]}


@pytest.mark.parametrize("change", ["description", "inputSchema", "annotations", "name", "extra", "order", "missing", "added"])
def test_changed_tool_still_fails_with_its_name(legacy_tools_result, tmp_path, monkeypatch, change):
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    references = snapshot["cases"]["role_legacy"]
    if change == "order":
        references[1], references[2] = references[2], references[1]
    elif change == "missing":
        references.pop(1)
    elif change == "added":
        references.append(["source_show", 0])
    else:
        snapshot["tools"]["mailbox_publish"][0][change] = "changed"
    path = tmp_path / "changed-snapshot.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    monkeypatch.setitem(globals(), "SNAPSHOT", path)
    with pytest.raises(AssertionError) as failure:
        assert_matches_snapshot(legacy_tools_result, "role_legacy")
    if change == "added":
        live_names = ["mailbox_inbox", "mailbox_publish", "mailbox_ack_handoff", "mailbox_self"]
        message = "MCP surface changed: role_legacy live=" + repr(live_names) + " snapshot=" + repr(live_names + ["source_show"])
    else:
        expected_name = ("changed" if change == "name" else
                         "mailbox_ack_handoff" if change in {"order", "missing"} else "mailbox_publish")
        message = "MCP tool changed: mailbox_publish (snapshot: " + expected_name + ")"
    assert str(failure.value).splitlines()[0] == message


def test_snapshot_covers_optional_role_tools():
    names = {tool["name"] for tools in snapshot_tool_lists() for tool in tools}
    assert {"source_show", "source_grep", "router_status", "decider_record"} <= names


def test_snapshot_covers_planned_inbox_schema():
    inboxes = [tool for tools in snapshot_tool_lists() for tool in tools if tool["name"] == "mailbox_inbox"]
    assert any({"order", "since", "briefs"} <= tool["inputSchema"]["properties"].keys() for tool in inboxes)


def test_opt_in_records_preserve_legacy_definitions_and_have_closed_schemas():
    sys.path.insert(0, str(REPO / "tools"))
    import hierarchy_mailbox_mcp as mailbox_mcp
    legacy = mailbox_mcp.definitions()
    adopted = mailbox_mcp.definitions(records=True)
    assert adopted[:len(legacy)] == legacy
    tools = {tool["name"]: tool for tool in adopted[len(legacy):]}
    assert set(tools) == {"mailbox_publish_record", "mailbox_read_record", "mailbox_digest"}
    for name, tool in tools.items():
        schema = tool["inputSchema"]
        assert schema["additionalProperties"] is False
        assert not {"root", "store", "from", "host", "session", "meta", "spans"} & schema["properties"].keys()
        assert tool["annotations"]["readOnlyHint"] is (name != "mailbox_publish_record")
        assert "untrusted" in tool["description"] and "findings.*.{id,severity,file,line}" in tool["description"]
        if name in {"mailbox_read_record", "mailbox_digest"}:
            assert schema["properties"]["expand"] == {"type": "array", "maxItems": 64,
                "items": {"type": "string", "maxLength": 64, "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$"}}
            assert "one level" in tool["description"]
            assert "refs_withheld" in tool["description"] and "outline-only" in tool["description"]
            assert "explicit refs selectors" in tool["description"]
            if name == "mailbox_digest":
                assert "inbox rows" in tool["description"]
            assert schema["properties"]["outline"] == {"type": "boolean"}
            reference = {"type": "string", "minLength": 64, "maxLength": 64, "pattern": "^[0-9a-f]{64}$"}
            if name == "mailbox_read_record":
                assert schema["properties"]["ref"] == reference
            else:
                assert schema["properties"]["refs"] == {"type": "array", "maxItems": 64, "items": reference}


def test_record_transaction_uses_the_single_pinned_publish_write_boundary():
    source = REPO / "tools" / "hierarchy_mailbox.py"
    assert hashlib.sha256(source.read_bytes()).hexdigest() == "472c96ab7959f5fbcfdee2e3d3a11a78864b0eb7a708029a1e419f410825a905"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    [mailbox] = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Mailbox"]
    [publish] = [node for node in mailbox.body if isinstance(node, ast.FunctionDef) and node.name == "publish"]
    writes = [node for node in ast.walk(publish) if isinstance(node, ast.Call)
              and isinstance(node.func, ast.Name) and node.func.id == "publish_file"]
    assert len(writes) == 1
    assert [ast.unparse(argument) for argument in writes[0].args] == ["path", "raw"]
    assert writes[0].keywords == []
    assert publish.body[-2].value is writes[0]


def test_profiles_cover_every_registry_role():
    roles = json.loads((REPO / "tools/hierarchy_templates/role-registry.json").read_text(encoding="utf-8"))["roles"]
    expected = read_snapshot()
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
    expected = read_snapshot()
    assert actual == expected[case]


def test_snapshot_covers_forbidden_options():
    expected = read_snapshot()
    assert REFUSAL_CASES.keys() <= expected.keys()
    for case, (_, _, error) in REFUSAL_CASES.items():
        assert expected[case] == {"error": error}


@pytest.mark.parametrize("profile,extras", [
    ("front_door", ["workspace_initiative"]),
    ("orchestrator_provisioned", ["workspace_capacity", "workspace_initiative", "source_show", "source_grep"]),
    ("decider_provisioned", ["source_show", "source_grep", "decider_record"]),
])
def test_snapshot_covers_provisioned_tool_order(profile, extras):
    expected = read_snapshot()
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
    expected = read_snapshot()
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
    SNAPSHOT.write_text(json.dumps(compact_snapshot(surfaces), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {SNAPSHOT} ({PYTHON_RUNS} interpreters: {setup_runs} setup, {len(surfaces)} serves)")
