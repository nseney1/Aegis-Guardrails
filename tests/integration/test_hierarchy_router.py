"""The Router's model-free code: route ROOT-approved canonical requests to the team's orchestrator.

A team is a registered workspace initiative, and its orchestrator is `<team>/orchestrator` in that
initiative's mailbox. The router actor and the borrowed `<team>/router` binding are configuration, not
authenticated identities. These tests show what the code delivers, records and refuses on fixtures; they
make no claim about what a real host lets a Router session do.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from tests.integration.test_hierarchy_lifecycle import Ledger, raw_request, request
from tests.integration.test_hierarchy_mailbox import ROOT, invoke, mailbox_snapshot
from tests.integration.test_hierarchy_workspace import Workspace


pytestmark = pytest.mark.skipif(os.name != "posix", reason="durable lifecycle mutation requires POSIX directory fsync")
TOOL = ROOT / "tools" / "hierarchy_router.py"
TEAM_ENDPOINTS = ("front-door", "orchestrator", "root", "router")


def team_mailbox(tmp_path, team, endpoints=TEAM_ENDPOINTS, bound=TEAM_ENDPOINTS):
    root = tmp_path / team / "mailbox"
    root.parent.mkdir(parents=True, exist_ok=True)
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": {team + "/" + e: {} for e in endpoints},
                          "counterparts": [], "writer_limit": 3})
    for endpoint in bound:
        invoke(root, "bind", {"endpoint": team + "/" + endpoint, "host": "host-one", "session": team + "-" + endpoint,
                              "expected_generation": 0})
    return root


class Loop:
    def __init__(self, tmp_path, policy_changes=None):
        self.tmp = tmp_path
        self.ledger = Ledger(tmp_path, policy_changes=policy_changes)
        self.workspace = Workspace(tmp_path)
        self.workspace.run("init", {"writer_limit": 3, "heavy_limit": 1})
        self.mailboxes = {}

    def team(self, team, **options):
        self.mailboxes[team] = team_mailbox(self.tmp, team, **options)
        self.workspace.register(team, mailbox_root=str(self.mailboxes[team]))
        return self.mailboxes[team]

    def approved(self, value):
        self.ledger.publish(value)
        self.ledger.approve(value)
        return value

    def run(self, command, *args, expect=0):
        proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "--lifecycle", str(self.ledger.path),
                               "--store", str(self.workspace.store), command, *args],
                              capture_output=True, text=True, timeout=30,
                              env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        assert not proc.stderr, proc.stderr
        assert proc.returncode == expect, proc.stdout
        return json.loads(proc.stdout)

    def route(self, *args, actor="router-1", expect=0):
        return self.run("route", "--actor", actor, "--evidence-only", "--wait", "0.2", *args, expect=expect)

    def status(self):
        return {row["request_id"]: row for row in self.run("status")["requests"]}

    def inbox(self, team, endpoint="orchestrator"):
        return invoke(self.mailboxes[team], "inbox", endpoint=team + "/" + endpoint)["messages"]

    def row(self, value):
        return self.ledger.status()["requests"][value["id"]]


@pytest.fixture
def loop(tmp_path):
    space = Loop(tmp_path)
    space.team("engine")
    return space


def test_an_approved_request_reaches_the_team_orchestrator_with_its_exact_bytes(loop):
    value = loop.approved(request("feature-1"))
    target = raw_request(value)
    assert loop.status()["feature-1"]["state"] == "ready"

    result = loop.route()

    assert [r["request_id"] for r in result["routed"]] == ["feature-1"]
    assert result["execution_enabled"] is False
    messages = loop.inbox("engine")
    assert len(messages) == 1
    message = messages[0]["message"]
    assert (message["from"], message["to"], message["type"]) == ("engine/router", "engine/orchestrator", "info")
    assert message["message_id"] == "route-" + target["sha256"]
    body = json.loads(message["body"])
    assert body == {"schema": "aegis.routed-request/v1", "request_id": "feature-1",
                    "request_sha256": target["sha256"], "request": target}
    routed = loop.row(value)["routed"]
    assert (routed["actor"], routed["generation"], routed["to"]) == ("router-1", 1, "engine/orchestrator")
    status = loop.status()["feature-1"]
    assert (status["state"], status["to"], status["team"]) == ("routed", "engine/orchestrator", "engine")


def test_routing_again_delivers_nothing_new_and_records_nothing(loop):
    loop.approved(request("feature-1"))
    loop.route()
    journal, mailbox = loop.ledger.files(), mailbox_snapshot(loop.mailboxes["engine"])

    again = loop.route()

    assert again["routed"] == []
    assert loop.ledger.files() == journal
    assert mailbox_snapshot(loop.mailboxes["engine"]) == mailbox


def test_a_busy_journal_refuses_the_run_before_anything_is_delivered(loop):
    loop.approved(request("feature-1"))
    lock = loop.ledger.path / ".write.lock"
    lock.write_text("{}")
    try:
        result = loop.route(expect=2)
    finally:
        lock.unlink()

    assert "busy" in result["error"]
    assert loop.inbox("engine") == []
    assert loop.status()["feature-1"]["state"] == "ready"


def test_a_busy_team_mailbox_holds_only_that_request(loop):
    loop.team("docs")
    loop.approved(request("feature-1"))
    loop.approved(request("feature-2", team="docs"))
    lock = loop.mailboxes["engine"] / ".write.lock"
    lock.write_text("{}")
    try:
        result = loop.route()
    finally:
        lock.unlink()

    assert [r["request_id"] for r in result["routed"]] == ["feature-2"]
    held = {row["request_id"]: row for row in result["requests"]}["feature-1"]
    assert (held["state"], held["reason"]) == ("held", "delivery_error")
    assert "busy" in held["detail"]
    assert loop.inbox("engine") == []
    assert [r["request_id"] for r in loop.route()["routed"]] == ["feature-1"]


def test_a_lost_journal_write_after_delivery_is_finished_by_the_next_run_without_a_second_message(loop):
    value = loop.approved(request("feature-1"))
    published = deliver_without_recording(loop, value)
    assert loop.row(value)["routed"] is None

    result = loop.route()

    assert [r["request_id"] for r in result["routed"]] == ["feature-1"]
    assert [m["message"]["message_id"] for m in loop.inbox("engine")] == [published]
    assert loop.row(value)["routed"]["to"] == "engine/orchestrator"


def deliver_without_recording(loop, value):
    """Publish exactly what the router would, as its borrowed binding, and stop before the journal write."""
    sys.path.insert(0, str(ROOT / "tools"))
    import hierarchy_router  # noqa: E402
    target = raw_request(value)
    identifier = hierarchy_router.route_id(target["sha256"])
    invoke(loop.mailboxes["engine"], "publish", {
        "message_id": identifier, "from": "engine/router", "to": "engine/orchestrator", "host": "host-one",
        "session": "engine-router", "binding_generation": 1, "type": "info",
        "body": hierarchy_router.route_body(value["id"], target)})
    return identifier


def test_a_message_id_that_names_different_content_is_held_and_not_recorded(loop):
    value = loop.approved(request("feature-1"))
    identifier = "route-" + raw_request(value)["sha256"]
    invoke(loop.mailboxes["engine"], "publish", {
        "message_id": identifier, "from": "engine/router", "to": "engine/orchestrator", "host": "host-one",
        "session": "engine-router", "binding_generation": 1, "type": "info", "body": "something else"})

    result = loop.route()

    assert result["routed"] == []
    row = loop.status()["feature-1"]
    assert (row["state"], row["reason"]) == ("held", "route_message_conflict")
    assert loop.row(value)["routed"] is None


def test_only_approved_live_authority_requests_are_routed(loop):
    pending = request("pending-1")
    loop.ledger.publish(pending)
    denied = request("denied-1")
    loop.ledger.publish(denied)
    loop.ledger.event("decision", actor="root-1", decision="deny", reason="no", **loop.ledger.target(denied))
    withdrawn = loop.approved(request("withdrawn-1"))
    loop.ledger.event("decision", actor="root-1", decision="deny", reason="withdrawn", **loop.ledger.target(withdrawn))

    result = loop.route()

    assert result["routed"] == []
    assert loop.inbox("engine") == []
    states = {key: row["state"] for key, row in loop.status().items()}
    assert states == {"pending-1": "awaiting_decision", "denied-1": "denied", "withdrawn-1": "denied"}


def test_an_expired_approval_is_held(loop):
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 2))
    value = request("feature-1", continuation={"members": [], "max_starts": 1, "expires_at": expires})
    loop.approved(value)
    time.sleep(2.2)

    result = loop.route()

    assert result["routed"] == []
    row = loop.status()["feature-1"]
    assert (row["state"], row["reason"]) == ("held", "approval_expired")
    assert loop.inbox("engine") == []


def test_a_deny_after_routing_stays_routed_and_is_reported(loop):
    value = loop.approved(request("feature-1"))
    loop.route()
    loop.ledger.event("decision", actor="root-1", decision="deny", reason="withdrawn", **loop.ledger.target(value))

    again = loop.route()

    assert again["routed"] == []
    row = loop.status()["feature-1"]
    assert (row["state"], row["revoked_after_route"]) == ("routed", True)
    assert len(loop.inbox("engine")) == 1


def test_a_continuation_member_is_not_routed_on_its_own(loop):
    member = request("member-1", authority="feature-1")
    member_raw = raw_request(member)
    parent = request("feature-1", continuation={"members": [{"id": "member-1", "sha256": member_raw["sha256"],
                                                             "phase": member["phase"], "operation": member["operation"]}],
                                                "max_starts": 2, "expires_at": "2099-01-01T00:00:00Z"})
    loop.approved(parent)
    loop.ledger.publish(member)

    result = loop.route()

    assert [r["request_id"] for r in result["routed"]] == ["feature-1"]
    assert set(loop.status()) == {"feature-1"}


def test_each_team_gets_its_own_requests(loop):
    loop.team("docs")
    loop.approved(request("feature-1"))
    loop.approved(request("feature-2", team="docs"))

    loop.route()

    assert [m["message"]["to"] for m in loop.inbox("engine")] == ["engine/orchestrator"]
    assert [json.loads(m["message"]["body"])["request_id"] for m in loop.inbox("docs")] == ["feature-2"]


def test_request_filter_routes_only_the_named_request(loop):
    loop.approved(request("feature-1"))
    loop.approved(request("feature-2"))

    result = loop.route("--request", "feature-2")

    assert [r["request_id"] for r in result["routed"]] == ["feature-2"]
    assert loop.status()["feature-1"]["state"] == "ready"


@pytest.mark.parametrize("setup,reason", [
    ("unregistered", "team_unregistered"),
    ("paused", "team_inactive"),
    ("done", "team_inactive"),
    ("no-mailbox", "team_has_no_mailbox"),
    ("no-router-endpoint", "router_endpoint_missing"),
    ("router-unbound", "router_unbound"),
    ("orchestrator-unbound", "orchestrator_unbound"),
    ("router-unacknowledged", "router_handoff_unacknowledged"),
])
def test_an_unroutable_team_is_held_with_a_reason_and_nothing_is_written(tmp_path, setup, reason):
    loop = Loop(tmp_path)
    if setup == "paused" or setup == "done":
        loop.team("engine")
        loop.workspace.run("update", {"initiative": "engine", "source": "owner", "state": setup})
    elif setup == "no-mailbox":
        loop.workspace.register("engine")
    elif setup == "no-router-endpoint":
        loop.team("engine", endpoints=("front-door", "orchestrator", "root"), bound=("front-door", "orchestrator", "root"))
    elif setup == "router-unbound":
        loop.team("engine", bound=("front-door", "orchestrator", "root"))
    elif setup == "orchestrator-unbound":
        loop.team("engine", bound=("front-door", "root", "router"))
    elif setup == "router-unacknowledged":
        root = loop.team("engine")
        brief = root.parent / "router-handoff.md"
        brief.write_bytes(b"Router handoff.\n")
        checkpoint = {"outgoing_stopped": True, "sources": [], "lease_refs": [], "completed_checks": [],
                      "pending_message_ids": [], "last_acknowledgment_ids": [],
                      "briefs": [{"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}]}
        invoke(root, "bind", {"endpoint": "engine/router", "host": "host-one", "session": "engine-router-2",
                              "expected_generation": 1, "checkpoint": checkpoint})
    loop.approved(request("feature-1"))
    journal = loop.ledger.files()
    mailboxes = {team: mailbox_snapshot(root) for team, root in loop.mailboxes.items()}

    result = loop.route()

    assert result["routed"] == []
    row = loop.status()["feature-1"]
    assert (row["state"], row["reason"]) == ("held", reason)
    assert loop.ledger.files() == journal
    assert {team: mailbox_snapshot(root) for team, root in loop.mailboxes.items()} == mailboxes


@pytest.mark.parametrize("actor,error", [
    ("router-9", "router actor is not in the lifecycle policy: router-9"),
    ("coordinator-1", "actor coordinator-1 is a coordinator, not a router"),
])
def test_a_wrong_router_actor_is_refused_before_anything_is_written(loop, actor, error):
    loop.approved(request("feature-1"))
    journal, mailbox = loop.ledger.files(), mailbox_snapshot(loop.mailboxes["engine"])

    result = loop.route(actor=actor, expect=2)

    assert result == {"state": "hold", "execution_enabled": False, "error": error}
    assert loop.ledger.files() == journal
    assert mailbox_snapshot(loop.mailboxes["engine"]) == mailbox


def test_a_superseded_router_actor_is_refused(tmp_path):
    (tmp_path / "probe").mkdir()
    policy = Ledger(tmp_path / "probe", initialize=False).policy
    actors = {**policy["actors"], "router-2": {**policy["actors"]["router-1"], "generation": 2}}
    loop = Loop(tmp_path, {"actors": actors, "successors": {**policy["successors"], "router-1": "router-2"}})
    loop.team("engine")
    loop.approved(request("feature-1"))
    checkpoint = loop.ledger.cli("checkpoint")["sha256"]
    loop.ledger.event("succeed", actor="router-2", predecessor="router-1", checkpoint_sha256=checkpoint)

    result = loop.route(actor="router-1", expect=2)

    assert result["error"] == "router actor router-1 is not the current router (router-2)"
    assert loop.inbox("engine") == []
    assert [r["request_id"] for r in loop.route(actor="router-2")["routed"]] == ["feature-1"]


def test_route_requires_evidence_only(loop):
    loop.approved(request("feature-1"))

    result = loop.run("route", "--actor", "router-1", expect=2)

    assert result["error"] == "routing requires --evidence-only; the router is configuration-bound and unauthenticated"
    assert loop.inbox("engine") == []


def test_the_router_actor_cannot_approve_or_execute_in_the_journal(loop):
    value = request("feature-1")
    loop.ledger.publish(value)
    target = loop.ledger.target(value)
    for kind, body in (("decision", {"decision": "approve", "reason": "self-approval"}),
                       ("intent", {"intent_id": "attempt-1"}),
                       ("start", {"intent_id": "attempt-1"})):
        refused = loop.ledger.event(kind, actor="router-1", expect=2, **target, **body)
        assert refused["error"] == "role router cannot record " + kind


def test_the_router_endpoint_cannot_dispatch_or_request_jobs(loop):
    root = loop.mailboxes["engine"]
    for kind, extra in (("dispatch", {"brief": {"path": str(loop.tmp / "brief.md"), "sha256": "a" * 64}}),
                        ("job_request", {})):
        refused = invoke(root, "publish", {"message_id": kind.replace("_", "-") + "-1", "from": "engine/router",
                                           "to": "engine/orchestrator", "host": "host-one", "session": "engine-router",
                                           "binding_generation": 1, "type": kind, "body": "run it", **extra}, ok=False)
        assert "error" in refused
    assert loop.inbox("engine") == []


def test_the_router_loads_no_execution_code():
    probe = ("import sys; sys.path.insert(0, %r); import hierarchy_router; "
             "print(sorted(m for m in sys.modules if m.startswith('hierarchy_')))" % str(ROOT / "tools"))
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", probe], capture_output=True, text=True, timeout=15)
    assert proc.returncode == 0, proc.stderr
    loaded = set(json.loads(proc.stdout.replace("'", '"')))
    assert loaded.isdisjoint({"hierarchy_jobs", "hierarchy_wake", "hierarchy_operator", "hierarchy_provision",
                              "hierarchy_sweep", "hierarchy_watch_supervisor"}), loaded


def test_status_changes_nothing(loop):
    loop.approved(request("feature-1"))
    journal, mailbox = loop.ledger.files(), mailbox_snapshot(loop.mailboxes["engine"])
    store = {p: p.read_bytes() for p in Path(loop.workspace.store).rglob("*") if p.is_file()}

    result = loop.run("status")

    assert result["schema"] == "aegis.router-status/v1"
    assert result["execution_enabled"] is False
    assert loop.ledger.files() == journal
    assert mailbox_snapshot(loop.mailboxes["engine"]) == mailbox
    assert {p: p.read_bytes() for p in Path(loop.workspace.store).rglob("*") if p.is_file()} == store
