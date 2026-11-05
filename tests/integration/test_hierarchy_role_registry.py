"""The role registry is the one record of what each role may do, and enforcement reads it.

Each M1 role from the approved definition has an entry. These tests show the registry refuses
contradictions, agrees with the lifecycle journal's permissions, and that the Router and Decider
endpoints get only what their entries allow.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT, invoke, message
from tests.integration.test_hierarchy_provision import MAILBOX_TOOLS, Setup, codex_config, provision, start_connection
from tests.integration.test_hierarchy_carry import UUID_B, Move, move_request


sys.path.insert(0, str(ROOT / "tools"))
import hierarchy_lifecycle  # noqa: E402
import hierarchy_roles  # noqa: E402


# Provision writes generated profiles and wakes, which are POSIX only (as in test_hierarchy_provision).
posix_only = pytest.mark.skipif(os.name == "nt", reason="generated profiles and wakes are POSIX only")
REGISTRY = json.loads((ROOT / "tools" / "hierarchy_templates" / "role-registry.json").read_text())
# The roles table of the approved M1 definition (aegis-guides/v5.0-m1-definition-20261105.md).
DEFINITION = {
    "root": ("global", "loop"), "router": ("global", "loop"), "orchestrator": ("per-team", "loop"),
    "reviewer": ("per-team", "loop"), "decider": ("per-team", "loop"), "implementer": ("on-demand", "loop"),
    "test-author": ("on-demand", "hat"), "owner": ("on-demand", "loop"), "watch-supervisor": ("service", "loop"),
    "provider-bridge": ("service", "loop"), "job-executor": ("service", "loop"), "architect": ("on-demand", "later"),
    "validation-operator": ("on-demand", "later"), "integrator": ("on-demand", "later"),
    "specialist-reviewer": ("on-demand", "later"), "release-operator": ("on-demand", "m6"),
}


def changed(change):
    registry = copy.deepcopy(REGISTRY)
    change(registry)
    return registry


def refusal(registry):
    with pytest.raises(ValueError) as caught:
        hierarchy_roles.validate(registry)
    return str(caught.value)


def test_the_registry_holds_every_m1_role_and_the_legacy_front_door():
    roles = hierarchy_roles.registry()["roles"]
    assert set(roles) == set(DEFINITION) | {"front-door"}
    for name, (kind, use) in DEFINITION.items():
        assert (roles[name]["kind"], roles[name]["m1"]) == (kind, use), name
    assert roles["front-door"]["kind"] == roles["front-door"]["m1"] == "legacy"


def test_services_have_no_endpoint_and_name_a_module_that_exists():
    for name, role in hierarchy_roles.registry()["roles"].items():
        if role["kind"] == "service":
            assert role["endpoint"] is None and role["model_profile"] == {"source": "none"}, name
            assert (ROOT / role["service"]).is_file(), name


def test_hats_use_the_endpoint_of_the_role_they_are_worn_on():
    roles = hierarchy_roles.registry()["roles"]
    assert roles["test-author"]["hat_of"] == "implementer"
    assert roles["specialist-reviewer"]["hat_of"] == "reviewer"


def test_independence_needs_a_separate_session_where_the_definition_says_so():
    roles = hierarchy_roles.registry()["roles"]
    assert roles["reviewer"]["independence"] == {"rule": "not-author", "separate_session": True}
    for name in ("decider", "root"):
        assert roles[name]["independence"] == {"rule": "not-requester", "separate_session": True}


def test_every_named_assistant_list_exists():
    for role in hierarchy_roles.registry()["roles"].values():
        if role["provision"] and role["provision"]["assistants"]:
            name = "assistants-" + role["provision"]["assistants"] + ".json"
            assert (ROOT / "tools" / "hierarchy_templates" / "claude-agents" / name).is_file()


def test_lifecycle_events_agree_with_the_journals_own_permissions():
    roles = hierarchy_roles.registry()["roles"].values()
    for event, allowed in hierarchy_lifecycle.PERMISSIONS.items():
        listed = {role["lifecycle_role"] for role in roles if "lifecycle:" + event in role["writes"] + role["approvals"]}
        assert listed == allowed, event


def test_only_root_and_the_router_may_never_execute_and_root_alone_decides():
    roles = hierarchy_roles.registry()["roles"]
    for name in ("root", "router"):
        assert {"job:run", "session:start", "mailbox:dispatch"} <= set(roles[name]["prohibitions"]["calls"])
        assert "source" in roles[name]["prohibitions"]["writes"]
    assert [name for name, role in roles.items() if "lifecycle:decision" in role["approvals"]] == ["root"]
    assert "lifecycle:decision" in roles["router"]["prohibitions"]["approvals"]


@pytest.mark.parametrize("change,error", [
    (lambda r: r["roles"]["router"]["calls"].append("job:launch"), "role router lists an unknown calls action: job:launch"),
    (lambda r: r["roles"]["router"]["writes"].append("source"), "role router both allows and prohibits writes: source"),
    (lambda r: r["roles"]["router"].update(wizard=True), "unexpected fields: wizard"),
    (lambda r: r["roles"]["implementer"]["writes"].append("lifecycle:route"),
     "role implementer records lifecycle events without a lifecycle role"),
    (lambda r: r["roles"]["architect"].update(endpoint={"role": "router"},
                                              provision={**r["roles"]["router"]["provision"], "lifecycle_tools": []}),
     "two roles claim endpoint router"),
    (lambda r: r["roles"]["test-author"].update(hat_of="owner"),
     "role test-author is a hat, so it uses the endpoint of the role it is worn on"),
    (lambda r: r["roles"]["root"]["writes"].append("mailbox"), "role root both allows and prohibits writes: mailbox"),
    (lambda r: r["roles"]["root"]["prohibitions"]["writes"].remove("board") or r["roles"]["root"]["writes"].append("board"),
     "role root: the decision adapter cannot carry write access"),
    (lambda r: r["roles"]["decider"].update(endpoint=None, provision=None),
     "registry endpoint roles differ from the mailbox endpoint grammar"),
    (lambda r: r["routes"].append(["router", "lane"]), "registry routes differ from the mailbox vertical routes"),
    (lambda r: r["routes"].pop(), "registry routes differ from the mailbox vertical routes"),
    (lambda r: r["roles"]["reviewer"].update(reports_to="nobody"),
     "role reviewer reports_to names an unknown role"),
    (lambda r: r["roles"]["router"]["model_profile"].update(source="guess"), "role router has an invalid model profile"),
    (lambda r: r.update(schema="aegis.role-registry/v2"), "unsupported role registry schema"),
    (lambda r: r["roles"]["router"]["independence"].update(rule="sometimes"), "role router has an invalid independence rule"),
    (lambda r: r["roles"]["router"].update(service="tools/x.py"),
     "role router: only a service without an endpoint names a service module"),
    (lambda r: r["roles"]["router"]["endpoint"].update(lane_kind="reviewer"),
     "role router: only a lane endpoint names a lane kind"),
    (lambda r: r["roles"]["router"]["provision"].update(adapter="shell"), "role router has an unknown adapter"),
    (lambda r: r["roles"]["router"]["provision"].update(assistants="everyone"),
     "role router names an unknown assistant list"),
    (lambda r: r["roles"]["implementer"]["provision"].update(reader_shell=True),
     "role implementer: a reader shell is only for a role that reads source and writes none"),
    (lambda r: r["roles"]["owner"].update(provision=r["roles"]["router"]["provision"]),
     "role owner has provisioning but no endpoint"),
    (lambda r: r["roles"]["router"]["reads"].append("mailbox"), "role router reads must be a list without repeats"),
    (lambda r: r["roles"]["integrator"]["endpoint"].update(lane_kind="builder"),
     "registry lane kinds differ from the mailbox lane kinds"),
])
def test_a_contradictory_or_drifted_registry_is_refused(change, error):
    assert refusal(changed(change)) == error


def test_the_provider_bridge_may_bind_an_endpoint_but_never_write_mail():
    # The launcher's start publishes the binding record through add-role, and nothing else in the mailbox.
    roles = hierarchy_roles.registry()["roles"]
    bridge = roles["provider-bridge"]
    assert bridge["writes"] == ["mailbox:bind"]
    assert "mailbox" in bridge["prohibitions"]["writes"]
    assert {name for name, entry in roles.items() if "mailbox:bind" in entry["writes"]} == {"provider-bridge"}
    assert refusal(changed(lambda r: r["roles"]["provider-bridge"]["writes"].append("mailbox"))) == (
        "role provider-bridge both allows and prohibits writes: mailbox")
    assert refusal(changed(lambda r: r["roles"]["provider-bridge"]["writes"].append("mailbox:post"))) == (
        "role provider-bridge lists an unknown writes action: mailbox:post")


TRIGGERS = {"router:route", "jobs:run-open"}


def test_the_watch_supervisor_may_trigger_routing_and_open_jobs_but_writes_nothing():
    # The loop service only starts the router and jobs tools as children, which keep their own checks, so the
    # role gains two trigger calls and no write, job run or mail of its own.
    supervisor = hierarchy_roles.registry()["roles"]["watch-supervisor"]
    assert supervisor["service"] == "tools/hierarchy_loop.py"
    assert supervisor["calls"] == ["session:wake", "router:route", "jobs:run-open"]
    assert supervisor["writes"] == []
    assert {"lifecycle", "mailbox", "workspace_initiative"} <= set(supervisor["reads"])
    refused = supervisor["prohibitions"]
    assert {"mailbox:dispatch", "job:run", "merge", "publish_release"} <= set(refused["calls"])
    assert {"source", "mailbox", "board", "governance"} <= set(refused["writes"])
    assert set(refused["approvals"]) == hierarchy_roles.VOCABULARY["approvals"]
    assert supervisor["lifecycle_role"] is None


def test_no_other_role_may_trigger_routing_or_open_jobs():
    roles = hierarchy_roles.registry()["roles"]
    assert TRIGGERS <= hierarchy_roles.VOCABULARY["calls"]
    assert {name for name, entry in roles.items() if TRIGGERS & set(entry["calls"])} == {"watch-supervisor"}


@pytest.mark.parametrize("change,error", [
    (lambda r: r["roles"]["watch-supervisor"]["calls"].append("job:run"),
     "role watch-supervisor both allows and prohibits calls: job:run"),
    (lambda r: r["roles"]["watch-supervisor"]["writes"].append("mailbox"),
     "role watch-supervisor both allows and prohibits writes: mailbox"),
    (lambda r: r["roles"]["watch-supervisor"]["calls"].append("jobs:run"),
     "role watch-supervisor lists an unknown calls action: jobs:run"),
    (lambda r: r["roles"]["watch-supervisor"]["calls"].append("router:succeed"),
     "role watch-supervisor lists an unknown calls action: router:succeed"),
    (lambda r: r["roles"]["watch-supervisor"]["writes"].append("router:route"),
     "role watch-supervisor lists an unknown writes action: router:route"),
])
def test_the_watch_supervisor_cannot_widen_past_its_triggers(change, error):
    assert refusal(changed(change)) == error


def test_the_registry_path_is_fixed_beside_the_loader():
    assert hierarchy_roles.PATH == ROOT / "tools" / "hierarchy_templates" / "role-registry.json"


# Router and Decider endpoints


@pytest.fixture
def setup(tmp_path):
    built = Setup(tmp_path)
    provision("init", built.init_request(roles=["router", "decider"]))
    return built


def bind_all(setup):
    for endpoint in sorted(json.loads((setup.root / "manifest.json").read_text())["endpoints"]):
        invoke(setup.root, "bind", {"endpoint": endpoint, "host": "h", "session": endpoint.replace("/", "-"),
                                    "expected_generation": 0})


def mail(sender, recipient, **extra):
    return {**message(sender, recipient, **extra), "host": "h", "session": sender.replace("/", "-")}


@posix_only
def test_init_adds_router_and_decider_only_when_asked(tmp_path, setup):
    manifest = json.loads((setup.root / "manifest.json").read_text())
    assert {"pilot/router", "pilot/decider"} <= set(manifest["endpoints"])
    (tmp_path / "plain").mkdir()
    plain = Setup(tmp_path / "plain")
    provision("init", plain.init_request())
    assert not {"pilot/router", "pilot/decider"} & set(json.loads((plain.root / "manifest.json").read_text())["endpoints"])


@posix_only
@pytest.mark.parametrize("roles,error", [
    (["router", "router"], "roles may list only router and decider, once each"),
    (["reviewer"], "roles may list only router and decider, once each"),
    ("router", "roles may list only router and decider, once each"),
])
def test_init_refuses_other_optional_roles(tmp_path, roles, error):
    built = Setup(tmp_path)
    assert provision("init", built.init_request(roles=roles), expect=2)["error"] == error
    assert not built.base.exists()


@posix_only
@pytest.mark.parametrize("endpoint,tools,extra", [
    ("pilot/router", "--tools=", set()),
    ("pilot/decider", "--tools=Read,Glob,Grep", set()),
])
def test_router_and_decider_get_only_mail_and_their_file_tools(setup, endpoint, tools, extra):
    role = setup.add_role(endpoint, cwd=str(setup.tmp))
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert tools in argv
    allowed = argv[argv.index("--allowedTools") + 1].split(",")
    assert not {"Edit", "Write"} & set(allowed)
    assert start_connection(role["connection"]) == MAILBOX_TOOLS | extra


@posix_only
@pytest.mark.parametrize("endpoint", ["pilot/router", "pilot/decider"])
def test_router_and_decider_run_read_only_on_codex_without_a_shell(setup, endpoint):
    role = setup.add_role(endpoint, "codex-cli", session="01a19a29-d635-7411-8529-9efedafc0899", cwd=str(setup.source))
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert argv[argv.index("--sandbox") + 1] == "read-only"
    assert "shell_tool" in [argv[index + 1] for index, word in enumerate(argv) if word == "--disable"]
    assert set(codex_config(argv)["mcp_servers"]["aegis_mailbox"]["enabled_tools"]) == MAILBOX_TOOLS


@posix_only
@pytest.mark.parametrize("endpoint,change,error", [
    ("pilot/router", {"reader_shell": True}, "reader_shell is only for a Codex reviewer, orchestrator or decider"),
    ("pilot/router", {"writable_roots": []}, "writable_roots is only for a Codex writer"),
    ("pilot/decider", {"writable_roots": []}, "writable_roots is only for a Codex writer"),
])
def test_router_and_decider_cannot_widen_their_codex_sandbox(setup, endpoint, change, error):
    refused = setup.add_role(endpoint, "codex-cli", session="abc", cwd=str(setup.source), expect=2, **change)
    assert refused["error"] == error


@posix_only
@pytest.mark.parametrize("endpoint", ["pilot/router", "pilot/decider"])
def test_router_and_decider_have_no_assistants(setup, endpoint):
    assert setup.add_role(endpoint, cwd=str(setup.tmp), assistants=True, expect=2)["error"] == "no assistant list for this role"


@posix_only
@pytest.mark.parametrize("kind,accepted", [("decider", True), ("router", False)])
def test_team_reasoning_covers_the_decider_but_not_the_global_router(setup, kind, accepted):
    (setup.base / "team.json").write_text(json.dumps({"model": "claude-opus-5-5", "reasoning": "high",
                                                      "reasoning_by_kind": {kind: "low"}}))
    result = setup.add_role("pilot/decider", cwd=str(setup.tmp), expect=0 if accepted else 2)
    if accepted:
        assert result["team"]["effort"] == "low" and result["team"]["reasoning_from"] == "kind"
    else:
        assert result["error"] == "unknown role kind in team.json reasoning_by_kind: router"


# ROOT itself never sends: its only adapter records decisions. These routes let the Router and the
# Decider reach it; the mailbox CLI on root's endpoint is an operator tool, not a ROOT session.
@posix_only
@pytest.mark.parametrize("sender,recipient", [
    ("pilot/router", "pilot/root"),
    ("pilot/router", "pilot/orchestrator"), ("pilot/orchestrator", "pilot/router"),
    ("pilot/decider", "pilot/orchestrator"), ("pilot/orchestrator", "pilot/decider"),
    ("pilot/decider", "pilot/root"),
])
def test_router_and_decider_routes(setup, sender, recipient):
    bind_all(setup)
    invoke(setup.root, "publish", mail(sender, recipient))
    assert [row["message"]["message_id"] for row in invoke(setup.root, "inbox", endpoint=recipient)["messages"]] == ["dispatch-1"]


@posix_only
@pytest.mark.parametrize("sender,recipient", [
    ("pilot/router", "pilot/lane/f2"), ("pilot/lane/f2", "pilot/router"), ("pilot/decider", "pilot/lane/review"),
    ("pilot/router", "pilot/decider"), ("pilot/front-door", "pilot/router"), ("pilot/decider", "pilot/front-door"),
])
def test_router_and_decider_cannot_reach_lanes_or_each_other(setup, sender, recipient):
    bind_all(setup)
    refused = invoke(setup.root, "publish", mail(sender, recipient), ok=False)
    assert refused["error"] == "route is not vertical or an explicit counterpart"


@posix_only
@pytest.mark.parametrize("sender,kind,error", [
    ("pilot/router", "job_request", "only an orchestrator can request a job from its own root"),
    ("pilot/decider", "job_request", "only an orchestrator can request a job from its own root"),
])
def test_router_and_decider_cannot_request_jobs(setup, tmp_path, sender, kind, error):
    bind_all(setup)
    brief = setup.base / "packet.md"
    brief.write_bytes(b"Run it.\n")
    packet = {"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}
    refused = invoke(setup.root, "publish", mail(sender, "pilot/root", kind=kind, brief=packet), ok=False)
    assert refused["error"] == error


@pytest.mark.parametrize("role", ["router", "decider", "root"])
def test_router_decider_and_root_cannot_be_counterparts(tmp_path, role):
    endpoints = {h + "/" + name: {} for h in ("a", "b") for name in ("front-door", "orchestrator", role)}
    manifest = {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints,
                "counterparts": [["a/" + role, "b/" + role]], "writer_limit": 3}
    refused = invoke(tmp_path / "mailbox", "init", manifest, ok=False)["error"]
    assert refused == ("root endpoints cannot be counterparts" if role == "root"
                       else "only front doors, orchestrators and lanes can be counterparts")


@posix_only
def test_the_router_cannot_reach_the_decision_adapter(setup):
    bind_all(setup)
    result = subprocess.run([sys.executable, "-I", str(setup.source / "tools" / "hierarchy_mailbox.py"), "--root",
                             str(setup.root), "serve", "--endpoint", "pilot/router", "--host", "h", "--session",
                             "pilot-router", "--generation", "1", "--lifecycle", str(setup.tmp), "--actor", "root-1"],
                            input="", capture_output=True, text=True, timeout=20,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == "the router session takes no lifecycle actor; routing is the router tool's"


@posix_only
@pytest.mark.parametrize("endpoint,role", [("pilot/orchestrator", "orchestrator"), ("pilot/lane/f2", "implementer")])
def test_a_role_without_lifecycle_tools_is_refused_the_journal(setup, endpoint, role):
    bind_all(setup)
    result = subprocess.run([sys.executable, "-I", str(setup.source / "tools" / "hierarchy_mailbox.py"), "--root",
                             str(setup.root), "serve", "--endpoint", endpoint, "--host", "h", "--session",
                             endpoint.replace("/", "-"), "--generation", "1", "--lifecycle", str(setup.tmp)],
                            input="", capture_output=True, text=True, timeout=20,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == "the %s role has no lifecycle connection" % role


@posix_only
def test_a_codex_decider_may_take_a_read_only_shell_to_read_source(setup):
    role = setup.add_role("pilot/decider", "codex-cli", session="01a19a29-d635-7411-8529-9efedafc0898",
                          cwd=str(setup.source), reader_shell=True)
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert argv[argv.index("--sandbox") + 1] == "read-only"
    assert "shell_tool" not in [argv[index + 1] for index, word in enumerate(argv) if word == "--disable"]


@posix_only
def test_the_router_always_runs_at_its_registry_effort(setup):
    (setup.base / "team.json").write_text(json.dumps({"model": "claude-opus-5-5", "reasoning": "max"}))
    role = setup.add_role("pilot/router", cwd=str(setup.tmp))
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert argv[argv.index("--effort") + 1] == "medium"
    assert role["model_profile"] == {"source": "registry", "effort": "medium", "tier": "ultrafast", "tier_applied": False}
    assert "codex_profile" not in role and not any("service_tier" in word for word in argv), "Claude has no tier flag"
    refused = setup.add_role("pilot/router", cwd=str(setup.tmp), session=role["session"], effort="max", expect=2)
    assert refused["error"] == "the router role runs at effort medium from the role registry"


@posix_only
def test_codex_start_applies_the_routers_registry_effort(setup):
    started = provision("codex-start", setup.request(base=str(setup.base), endpoint="pilot/router", cwd=str(setup.source)))
    config = codex_config(started["start_argv"])
    assert config["model_reasoning_effort"] == "medium" and config["service_tier"] == "ultrafast"
    assert started["model_profile"] == {"source": "registry", "effort": "medium", "tier": "ultrafast", "tier_applied": True}


@posix_only
@pytest.mark.parametrize("first,second,independent", [
    ("pilot/lane/f2", "pilot/lane/review", "pilot/lane/review"),
    ("pilot/lane/review", "pilot/lane/f2", "pilot/lane/review"),
    ("pilot/orchestrator", "pilot/decider", "pilot/decider"),
    ("pilot/decider", "pilot/lane/f2", "pilot/decider"),
])
def test_one_session_cannot_hold_both_sides_of_an_independence_rule(setup, first, second, independent):
    session = str(uuid.uuid4())
    setup.add_role(first, cwd=str(setup.tmp), session=session)
    refused = setup.add_role(second, cwd=str(setup.tmp), session=session, expect=2)
    assert refused["error"] == ("session %s already holds %s; the role registry needs a separate session for %s"
                                % (session, first, independent))
    assert invoke(setup.root, "status")["bindings"][second] is None


@posix_only
def test_one_session_may_hold_roles_without_an_independence_rule(setup):
    session = str(uuid.uuid4())
    setup.add_role("pilot/front-door", cwd=str(setup.tmp), session=session)
    assert setup.add_role("pilot/orchestrator", cwd=str(setup.tmp), session=session)["generation"] == 1


@pytest.mark.parametrize("name", ["router", "decider", "reviewer", "specialist-reviewer"])
def test_roles_that_must_stay_independent_of_team_posts_never_get_the_board(name):
    entry = hierarchy_roles.registry()["roles"][name]
    assert "board" in entry["prohibitions"]["reads"] and not hierarchy_roles.takes_board(entry)


@posix_only
def test_moving_a_hierarchy_keeps_its_router_and_decider(tmp_path):
    built = Move.__new__(Move)
    Setup.__init__(built, tmp_path)
    (tmp_path / "old").mkdir()
    built.old = tmp_path / "old" / "mailbox"
    endpoints = {"a/front-door": {}, "a/orchestrator": {}, "a/router": {}, "a/decider": {},
                 "a/lane/build": {"kind": "implementer"}}
    invoke(built.old, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints, "writer_limit": 3,
                               "counterparts": []})
    for endpoint, session in (("a/orchestrator", "native-orchestrator"), ("a/router", "native-router"),
                              ("a/decider", "native-decider")):
        invoke(built.old, "bind", {"endpoint": endpoint, "host": "codex", "session": session, "expected_generation": 0})
    result = provision("move", move_request(built))
    assert {"a/router", "a/decider"} <= set(result["roles"])
    assert result["roles"]["a/root"]["session"] == UUID_B
    manifest = json.loads((Path(result["mailbox_root"]) / "manifest.json").read_text())
    assert {"a/router", "a/decider"} <= set(manifest["endpoints"])
