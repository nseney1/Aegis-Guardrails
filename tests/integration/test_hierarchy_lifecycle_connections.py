"""Lifecycle connections follow the role registry: the Router reads status, the Decider records within a delegation.

ROOT keeps its decision adapter. Every other role is refused --lifecycle and --actor. The Router's
router_status and the Decider's decider_record are configuration-bound: the actor is whatever the
connection was given, and the journal checks every event it is asked to record. These tests drive
`hierarchy_mailbox.py serve` over stdio and assert what it offers, records and refuses.
"""
import hashlib
import json
import os
import subprocess
import sys
import threading

import pytest

from tests.integration.test_hierarchy_decider import Decider, decider_policy, delegation, merge
from tests.integration.test_hierarchy_lifecycle import raw_request
from tests.integration.test_hierarchy_mailbox import HELPER, ROOT, invoke
from tests.integration.test_hierarchy_mailbox_mcp import payload
from tests.integration.test_hierarchy_provision import MAILBOX_TOOLS
from tests.integration.test_hierarchy_role_registry import REGISTRY, changed, refusal
from tests.integration.test_hierarchy_router import TEAM_ENDPOINTS, Loop


sys.path.insert(0, str(ROOT / "tools"))
import hierarchy_roles  # noqa: E402


posix_only = pytest.mark.skipif(os.name != "posix", reason="durable lifecycle mutation requires POSIX directory fsync")
ENDPOINTS = TEAM_ENDPOINTS + ("decider",)
ROUTER_ACTOR = "the router session takes no lifecycle actor; routing is the router tool's"
DECIDER_PAIR = "the decider takes --lifecycle and --actor together"


@pytest.fixture
def team(tmp_path):
    policy = decider_policy(tmp_path)
    loop = Loop(tmp_path, policy_changes={key: policy[key] for key in ("actors", "current", "successors")})
    loop.ledger.__class__ = Decider
    loop.team("engine", endpoints=ENDPOINTS, bound=ENDPOINTS)
    return loop


def options(loop, *, lifecycle=False, actor=None, store=False):
    argv = ["--lifecycle", str(loop.ledger.path)] if lifecycle else []
    argv += ["--actor", actor] if actor else []
    argv += ["--workspace-store", str(loop.workspace.store), "--initiative", "engine"] if store else []
    return argv


def frames(calls):
    sent = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    sent += [{"jsonrpc": "2.0", "id": index + 3, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
             for index, (name, arguments) in enumerate(calls)]
    return "".join(json.dumps(frame) + "\n" for frame in sent)


def argv(loop, endpoint, session, generation, extra):
    return [sys.executable, "-I", str(HELPER), "--root", str(loop.mailboxes["engine"]), "serve", "--endpoint",
            "engine/" + endpoint, "--host", "host-one", "--session", session or "engine-" + endpoint,
            "--generation", str(generation), *extra]


def serve(loop, endpoint, calls=(), *, session=None, generation=1, **kwargs):
    return subprocess.run(argv(loop, endpoint, session, generation, options(loop, **kwargs)), input=frames(calls),
                          capture_output=True, text=True, timeout=20, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})


def responses(result):
    assert result.returncode == 0, result.stdout + result.stderr
    assert not result.stderr
    return [json.loads(line) for line in result.stdout.splitlines()]


def refused_at_startup(result):
    assert result.returncode == 2, result.stdout + result.stderr
    return json.loads(result.stdout)["error"]


def tool_error(response):
    assert response["result"]["isError"] is True
    return payload(response)["error"]


def rebind(loop, endpoint, session):
    brief = loop.mailboxes["engine"].parent / "decider-handoff.md"
    brief.write_bytes(b"Decider handoff.\n")
    checkpoint = {"outgoing_stopped": True, "sources": [], "lease_refs": [], "completed_checks": [],
                  "pending_message_ids": [], "last_acknowledgment_ids": [],
                  "briefs": [{"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}]}
    return invoke(loop.mailboxes["engine"], "bind", {"endpoint": "engine/" + endpoint, "host": "host-one",
                                                    "session": session, "expected_generation": 1,
                                                    "checkpoint": checkpoint})


def record(loop, target, granted, choice="approve", event_id="decider-event-1", **changes):
    body = {"event_id": event_id, "request_id": target["id"], "request_sha256": raw_request(target)["sha256"],
            "delegation_id": granted["id"], "delegation_sha256": raw_request(granted)["sha256"],
            "commit": target["source"]["commit"], "review": loop.ledger.evidence, "decision": choice,
            "reason": "fixture " + choice}
    return ("decider_record", {**body, **changes})


def decider(loop, calls=(), **kwargs):
    return serve(loop, "decider", calls, lifecycle=True, actor=kwargs.pop("actor", "decider-1"), **kwargs)


def delegated(loop):
    granted = loop.ledger.delegate()
    target = merge()
    loop.ledger.publish(target)
    return granted, target


# Registry


def test_each_provisioned_role_names_its_lifecycle_tools_in_registry_order():
    tools = {name: hierarchy_roles.lifecycle_tools(entry)
             for name, entry in hierarchy_roles.registry()["roles"].items() if entry["provision"] is not None}
    assert tools == {"root": (), "router": ("router_status",), "orchestrator": (), "reviewer": (),
                     "decider": ("decider_record",), "implementer": (), "integrator": (), "front-door": ()}
    assert hierarchy_roles.LIFECYCLE_TOOLS == ("router_status", "decider_record")


def test_the_provider_bridge_is_the_launcher():
    bridge = hierarchy_roles.registry()["roles"]["provider-bridge"]
    assert bridge["service"] == "tools/hierarchy_launcher.py"
    assert bridge["responsibility"] == "Starts, attaches and stops sessions on a host"


@pytest.mark.parametrize("change,error", [
    (lambda r: r["roles"]["router"]["provision"].update(lifecycle_tools=["router_status", "route_now"]),
     "role router names an unknown lifecycle tool: route_now"),
    (lambda r: r["roles"]["orchestrator"]["provision"].update(lifecycle_tools=["router_status"]),
     "role orchestrator: router_status is for the router, which reads the lifecycle journal"),
    (lambda r: r["roles"]["router"]["reads"].remove("lifecycle"),
     "role router: router_status is for the router, which reads the lifecycle journal"),
    (lambda r: r["roles"]["router"]["provision"].update(lifecycle_tools=["decider_record"]),
     "role router: decider_record is for the decider, which approves within a delegation"),
    (lambda r: r["roles"]["decider"]["approvals"].remove("lifecycle:delegated_decision"),
     "role decider: decider_record is for the decider, which approves within a delegation"),
    (lambda r: r["roles"]["reviewer"]["provision"].update(lifecycle_tools=["decider_record"]),
     "role reviewer: decider_record is for the decider, which approves within a delegation"),
    (lambda r: r["roles"]["root"]["provision"].update(lifecycle_tools=["router_status"]),
     "role root: the decision adapter offers only root_decide"),
    (lambda r: r["roles"]["router"]["provision"].pop("lifecycle_tools"), "missing fields: lifecycle_tools"),
])
def test_a_lifecycle_tool_outside_its_role_is_refused(change, error):
    assert refusal(changed(change)) == error


def test_the_shipped_registry_carries_lifecycle_tools_on_every_provisioned_role():
    for name, entry in REGISTRY["roles"].items():
        if entry["provision"] is not None:
            assert "lifecycle_tools" in entry["provision"], name


# Router


@posix_only
def test_the_router_reads_status_and_escalations_from_the_journal(team):
    granted = team.ledger.delegate()
    inside, outside = merge("merge-1"), merge("merge-2", paths=["/fixture/other"])
    for value in (inside, outside):
        team.ledger.publish(value)
    team.ledger.decide(inside, granted)
    team.ledger.decide(outside, granted, "escalate", reason="path outside the delegation")
    before = team.ledger.files()
    opened, listed, status, own = responses(serve(team, "router", [("router_status", {}), ("mailbox_self", {})],
                                                  lifecycle=True, store=True))
    [tool] = [tool for tool in listed["result"]["tools"] if tool["name"] == "router_status"]
    assert tool["annotations"]["readOnlyHint"] is True
    assert tool["inputSchema"] == {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
    assert {t["name"] for t in listed["result"]["tools"]} == MAILBOX_TOOLS | {"router_status"}
    answer = payload(status)
    expected = team.run("status")
    assert answer["schema"] == "aegis.router-status/v1"
    assert answer["escalations"] == expected["escalations"]
    assert [row["request_id"] for row in answer["escalations"]] == ["merge-2"]
    assert [row["request_id"] for row in answer["requests"]] == [row["request_id"] for row in expected["requests"]]
    assert (answer["authenticated"], answer["execution_enabled"]) == (False, False)
    assert "router_status" in payload(own)["tools"]
    assert team.ledger.files() == before


@posix_only
def test_without_a_lifecycle_journal_the_router_has_only_its_mail(team):
    _, listed = responses(serve(team, "router", store=True))
    assert {tool["name"] for tool in listed["result"]["tools"]} == MAILBOX_TOOLS
    refused = responses(serve(team, "router", [("router_status", {})], store=True))[-1]
    assert tool_error(refused) == "unknown mailbox tool: router_status"


@posix_only
@pytest.mark.parametrize("kwargs,error", [
    ({"lifecycle": True, "actor": "router-1", "store": True}, ROUTER_ACTOR),
    ({"actor": "router-1"}, ROUTER_ACTOR),
    ({"lifecycle": True}, "router_status needs --lifecycle and --workspace-store together"),
])
def test_the_router_takes_the_journal_without_an_actor_and_with_the_store(team, kwargs, error):
    assert refused_at_startup(serve(team, "router", **kwargs)) == error


@posix_only
def test_a_replaced_router_session_is_refused_router_status_at_call_time(team):
    process = subprocess.Popen(argv(team, "router", None, 1, options(team, lifecycle=True, store=True)),
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    try:
        def status(identifier):
            process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
                                            "params": {"name": "router_status", "arguments": {}}}) + "\n")
            process.stdin.flush()
            return json.loads(process.stdout.readline())
        assert payload(status(1))["schema"] == "aegis.router-status/v1"
        rebind(team, "router", "engine-router-2")
        assert tool_error(status(2)) == "stale or mismatched sender binding"
    finally:
        process.stdin.close()
        process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


@posix_only
def test_a_busy_journal_is_named_as_the_journal_in_router_status(team):
    lock = team.ledger.path / ".write.lock"
    lock.write_text("{}")
    try:
        refused = responses(serve(team, "router", [("router_status", {})], lifecycle=True, store=True))[-1]
    finally:
        lock.unlink()
    assert tool_error(refused) == "lifecycle journal writer is busy; inspect an abandoned %s before retrying" % lock


@posix_only
def test_router_status_takes_no_arguments(team):
    refused = responses(serve(team, "router", [("router_status", {"team": "engine"})], lifecycle=True, store=True))[-1]
    assert tool_error(refused) == "unexpected fields: team"


# Decider


@posix_only
def test_the_decider_records_an_approval_within_its_delegation(team):
    granted, target = delegated(team)
    opened, listed, answer = responses(decider(team, [record(team, target, granted)]))
    [tool] = [tool for tool in listed["result"]["tools"] if tool["name"] == "decider_record"]
    assert tool["annotations"]["readOnlyHint"] is False and tool["inputSchema"]["additionalProperties"] is False
    assert set(tool["inputSchema"]["required"]) == {"event_id", "request_id", "request_sha256", "delegation_id",
                                                    "delegation_sha256", "commit", "review", "decision", "reason"}
    assert tool["inputSchema"]["properties"]["decision"]["enum"] == ["approve", "escalate"]
    result = payload(answer)
    assert (result["identity"], result["authenticated"], result["execution_enabled"]) == ("configured", False, False)
    assert result["receipt"]["event_id"] == "decider-event-1"
    [entry] = team.ledger.status()["delegated_decisions"]
    assert (entry["request_id"], entry["delegation_id"], entry["decision"], entry["actor"]) == (
        "merge-1", "delegation-1", "approve", "decider-1")
    assert entry["review"] == team.ledger.evidence
    assert [d["request_id"] for d in team.ledger.status()["decisions"]] == ["delegation-1"]


@posix_only
def test_an_out_of_scope_approval_is_refused_by_the_journal_and_an_escalation_is_recorded(team):
    granted = team.ledger.delegate()
    target = merge(paths=["/fixture/other"])
    team.ledger.publish(target)
    before = team.ledger.files()
    refused = responses(decider(team, [record(team, target, granted)]))[-1]
    assert tool_error(refused) == "target path is outside the delegation's paths"
    assert team.ledger.files() == before
    responses(decider(team, [record(team, target, granted, "escalate", event_id="decider-event-2")]))
    assert [d["decision"] for d in team.ledger.status()["delegated_decisions"]] == ["escalate"]


@posix_only
def test_a_replaced_decider_session_is_refused_at_call_time(team):
    granted, target = delegated(team)
    before = team.ledger.files()
    process = subprocess.Popen(argv(team, "decider", None, 1, options(team, lifecycle=True, actor="decider-1")),
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    try:
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n")
        process.stdin.flush()
        assert "decider_record" in {tool["name"] for tool in json.loads(process.stdout.readline())["result"]["tools"]}
        rebind(team, "decider", "engine-decider-2")
        name, arguments = record(team, target, granted)
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                        "params": {"name": name, "arguments": arguments}}) + "\n")
        process.stdin.flush()
        assert tool_error(json.loads(process.stdout.readline())) == "stale or mismatched sender binding"
    finally:
        process.stdin.close()
        process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()
    assert team.ledger.files() == before


@posix_only
def test_a_decider_successor_that_has_not_acknowledged_its_handoff_cannot_record(team):
    granted, target = delegated(team)
    rebind(team, "decider", "engine-decider-2")
    before = team.ledger.files()
    refused = responses(decider(team, [record(team, target, granted)], session="engine-decider-2", generation=2))[-1]
    assert tool_error(refused) == "handoff checkpoint has not been acknowledged"
    assert team.ledger.files() == before


@posix_only
@pytest.mark.parametrize("actor,error", [
    ("router-1", "actor router-1 is not a decider actor in the lifecycle policy"),
    ("root-1", "actor root-1 is not a decider actor in the lifecycle policy"),
    ("nobody-1", "actor nobody-1 is not a decider actor in the lifecycle policy"),
    ("../x", "invalid actor"),
])
def test_only_a_configured_decider_actor_starts(team, actor, error):
    assert refused_at_startup(decider(team, actor=actor)) == error


@posix_only
@pytest.mark.parametrize("change,error", [
    ({"review": []}, "evidence requires bounded nonempty references"),
    ({"review": [{"path": "/fixture/x"}]}, "missing fields: sha256"),
    ({"review": "all good"}, "evidence requires bounded nonempty references"),
    ({"review": [{"path": "/fixture/x", "sha256": "z" * 64}]}, "invalid evidence sha256"),
    ({"commit": 7}, "invalid reviewed commit"),
    ({"decision": "deny"}, "decision must be approve or escalate"),
    ({"decision": ["approve"]}, "decision must be approve or escalate"),
    ({"request_sha256": "0" * 63}, "invalid request sha256"),
    ({"delegation_sha256": None}, "invalid delegation sha256"),
    ({"delegation_id": "../up"}, "invalid delegation id"),
    ({"event_id": "x" * 81}, "invalid event id"),
    ({"reason": "x" * 1025}, "invalid delegated decision reason"),
    ({"actor": "decider-2"}, "unexpected fields: actor"),
])
def test_a_malformed_record_is_refused_before_the_journal(team, change, error):
    granted, target = delegated(team)
    before = team.ledger.files()
    # A held journal lock would make any call that reached the journal answer busy.
    lock = team.ledger.path / ".write.lock"
    lock.write_text("{}")
    try:
        refused = responses(decider(team, [record(team, target, granted, **change)]))[-1]
    finally:
        lock.unlink()
    assert tool_error(refused) == error
    assert team.ledger.files() == before


@posix_only
def test_a_busy_journal_is_named_as_the_journal(team):
    granted, target = delegated(team)
    lock = team.ledger.path / ".write.lock"
    lock.write_text("{}")
    try:
        refused = responses(decider(team, [record(team, target, granted)]))[-1]
    finally:
        lock.unlink()
    assert tool_error(refused).startswith("lifecycle journal writer is busy; inspect an abandoned " + str(lock))


@posix_only
def test_a_moment_of_journal_contention_at_the_record_is_waited_out(team, monkeypatch):
    # In process, because the contention must land between the replay and the record, which only the record sees.
    import hierarchy_lifecycle
    import hierarchy_mailbox_mcp
    granted, target = delegated(team)
    lock = team.ledger.path / ".write.lock"
    original = hierarchy_lifecycle.Lifecycle.record
    held = []

    def contended(self, envelope):
        if not held:
            lock.write_text("{}")
            held.append(threading.Timer(0.3, lock.unlink))
            held[0].start()
        return original(self, envelope)

    monkeypatch.setattr(hierarchy_lifecycle.Lifecycle, "record", contended)
    connection = hierarchy_mailbox_mcp.Connection(team.mailboxes["engine"], "engine/decider", "host-one",
                                                  "engine-decider", 1, lifecycle=team.ledger.path, actor="decider-1")
    try:
        result = connection.call(*record(team, target, granted))
    finally:
        held[0].join(timeout=5)
    assert result["receipt"]["event_id"] == "decider-event-1"
    assert [d["decision"] for d in team.ledger.status()["delegated_decisions"]] == ["approve"]


@posix_only
def test_the_decider_is_told_a_retry_returns_its_receipt_only_while_root_custody_is_unchanged(team):
    _, listed = responses(decider(team))
    [description] = [tool["description"] for tool in listed["result"]["tools"] if tool["name"] == "decider_record"]
    assert ("returns the original receipt while ROOT custody is unchanged; after a ROOT succession, record with a new "
            "event_id.") in description


@posix_only
@pytest.mark.parametrize("kwargs", [{"lifecycle": True}, {"actor": "decider-1"}])
def test_the_decider_takes_the_journal_and_its_actor_together(team, kwargs):
    assert refused_at_startup(serve(team, "decider", **kwargs)) == DECIDER_PAIR


@posix_only
def test_without_a_lifecycle_journal_the_decider_has_only_its_mail(team):
    _, listed = responses(serve(team, "decider"))
    assert {tool["name"] for tool in listed["result"]["tools"]} == MAILBOX_TOOLS


@posix_only
@pytest.mark.parametrize("endpoint,kwargs,role", [
    ("orchestrator", {"lifecycle": True}, "orchestrator"),
    ("orchestrator", {"lifecycle": True, "actor": "coordinator-1"}, "orchestrator"),
    ("front-door", {"actor": "coordinator-1"}, "front-door"),
])
def test_roles_without_lifecycle_tools_have_no_lifecycle_connection(team, endpoint, kwargs, role):
    assert refused_at_startup(serve(team, endpoint, **kwargs)) == "the %s role has no lifecycle connection" % role
