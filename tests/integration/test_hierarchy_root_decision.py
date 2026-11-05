"""ROOT's decision-only adapter: approve or deny an existing canonical request, and nothing else.

The ROOT actor is configuration, not an authenticated identity. These tests show what the adapter
records and refuses; they make no claim about what a real host lets a ROOT session do.
"""
import hashlib
import json
import os
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_lifecycle import Ledger, raw_request, request
from tests.integration.test_hierarchy_mailbox import HELPER, invoke, message
from tests.integration.test_hierarchy_mailbox_mcp import payload
from tests.integration.test_hierarchy_root_role import ENDPOINTS


pytestmark = pytest.mark.skipif(os.name != "posix", reason="durable lifecycle mutation requires POSIX directory fsync")
TOOL = "root_decide"


@pytest.fixture
def loop(tmp_path):
    root = tmp_path / "mailbox"
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": ENDPOINTS, "counterparts": [],
                          "writer_limit": 3})
    for endpoint in ENDPOINTS:
        invoke(root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint, "expected_generation": 0})
    ledger = Ledger(tmp_path)
    value = request("feature-1")
    ledger.publish(value)
    return root, ledger, value


def rebind(root, host):
    brief = root.parent / "root-handoff.md"
    brief.write_bytes(b"ROOT handoff.\n")
    checkpoint = {"outgoing_stopped": True, "sources": [], "lease_refs": [], "completed_checks": [],
                  "pending_message_ids": [], "last_acknowledgment_ids": [],
                  "briefs": [{"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}]}
    return invoke(root, "bind", {"endpoint": "a/root", "host": host, "session": "root-2", "expected_generation": 1,
                                 "checkpoint": checkpoint})


def serve(root, ledger, calls=(), *, endpoint="a/root", actor="root-1", session=None, generation=1, extra=(),
          lifecycle=True):
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    frames += [{"jsonrpc": "2.0", "id": index + 3, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
               for index, (name, arguments) in enumerate(calls)]
    options = ["--lifecycle", str(ledger.path), "--actor", actor] if lifecycle else []
    return subprocess.run([sys.executable, "-I", str(HELPER), "--root", str(root), "serve", "--endpoint", endpoint,
                           "--host", "host-one", "--session", session or endpoint, "--generation", str(generation),
                           *options, *extra],
                          input="".join(json.dumps(frame) + "\n" for frame in frames), capture_output=True, text=True,
                          timeout=20, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})


def responses(result):
    assert result.returncode == 0, result.stdout + result.stderr
    assert not result.stderr
    return [json.loads(line) for line in result.stdout.splitlines()]


def decision(value, event_id="root-decision-1", verdict="approve", reason="the owner agreed this feature"):
    return {"event_id": event_id, "request_id": value["id"], "request_sha256": raw_request(value)["sha256"],
            "decision": verdict, "reason": reason}


def decisions(ledger):
    return [(d["request_id"], d["decision"], d["actor"]) for d in ledger.status()["decisions"]]


def test_root_is_offered_only_the_decision_tool_and_told_it_is_not_authenticated(loop):
    root, ledger, _ = loop
    opened, listed = responses(serve(root, ledger))
    assert "not authenticated" in opened["result"]["instructions"]
    tools = listed["result"]["tools"]
    assert [tool["name"] for tool in tools] == [TOOL]
    schema = tools[0]["inputSchema"]
    assert set(schema["properties"]) == {"event_id", "request_id", "request_sha256", "decision", "reason"}
    assert schema["properties"]["decision"]["enum"] == ["approve", "deny"]
    assert schema["additionalProperties"] is False and tools[0]["annotations"]["readOnlyHint"] is False


@pytest.mark.parametrize("verdict", ["approve", "deny"])
def test_root_records_a_decision_on_an_existing_request_under_its_configured_actor(loop, verdict):
    root, ledger, value = loop
    answer = payload(responses(serve(root, ledger, [(TOOL, decision(value, verdict=verdict))]))[-1])
    assert answer["identity"] == "configured" and answer["authenticated"] is False
    assert answer["execution_enabled"] is False and answer["receipt"]["execution_enabled"] is False
    assert answer["receipt"]["event_id"] == "root-decision-1"
    assert decisions(ledger) == [("feature-1", verdict, "root-1")]


def test_a_lost_reply_is_recovered_by_retrying_the_same_decision(loop):
    root, ledger, value = loop
    first = payload(responses(serve(root, ledger, [(TOOL, decision(value))]))[-1])
    before = ledger.files()
    again = payload(responses(serve(root, ledger, [(TOOL, decision(value))]))[-1])
    assert again["receipt"] == first["receipt"]
    assert ledger.files() == before


def test_a_reused_event_id_with_another_decision_is_refused(loop):
    root, ledger, value = loop
    responses(serve(root, ledger, [(TOOL, decision(value))]))
    before = ledger.files()
    refused = responses(serve(root, ledger, [(TOOL, decision(value, verdict="deny"))]))[-1]
    assert refused["result"]["isError"] is True
    assert payload(refused)["error"] == "event id conflicts with different bytes"
    assert ledger.files() == before


@pytest.mark.parametrize("change,error", [
    ({"request_id": "never-published"}, "unknown request id"),
    ({"request_sha256": "0" * 64}, "request sha256 mismatch"),
    ({"decision": "admit"}, "decision must be approve or deny"),
    ({"reason": ""}, "invalid decision reason"),
    ({"event_id": "../escape"}, "invalid event id"),
    ({"actor": "operator-1"}, "unexpected fields"),
    ({"custody": {"cid": "root-1", "generation": 1}}, "unexpected fields"),
])
def test_malformed_or_unknown_decisions_record_nothing(loop, change, error):
    root, ledger, value = loop
    before = ledger.files()
    refused = responses(serve(root, ledger, [(TOOL, {**decision(value), **change})]))[-1]
    assert refused["result"]["isError"] is True
    assert error in payload(refused)["error"]
    assert ledger.files() == before


@pytest.mark.parametrize("name,arguments", [
    ("mailbox_publish", {"message_id": "go", "to": "a/orchestrator", "type": "info", "body": "Run it."}),
    ("mailbox_inbox", {}),
    ("workspace_capacity", {}),
    ("board_publish", {}),
])
def test_root_attempts_to_reach_mail_or_execution_tools_are_refused(loop, name, arguments):
    root, ledger, _ = loop
    before = ledger.files()
    refused = responses(serve(root, ledger, [(name, arguments)]))[-1]
    assert refused["result"]["isError"] is True
    assert payload(refused)["error"] == "unknown ROOT tool: %s; ROOT only records decisions" % name
    assert ledger.files() == before
    assert invoke(root, "inbox", endpoint="a/orchestrator")["messages"] == []


def test_a_replaced_root_session_is_refused_before_anything_is_recorded(loop):
    root, ledger, value = loop
    rebind(root, "host-two")
    before = ledger.files()
    stale = serve(root, ledger, [(TOOL, decision(value))])
    assert stale.returncode == 2
    assert json.loads(stale.stdout)["error"] == "stale or mismatched sender binding"
    assert ledger.files() == before


def test_a_successor_that_has_not_acknowledged_its_handoff_cannot_decide(loop):
    root, ledger, value = loop
    rebind(root, "host-one")
    before = ledger.files()
    waiting = serve(root, ledger, [(TOOL, decision(value))], session="root-2", generation=2)
    assert waiting.returncode == 2
    assert json.loads(waiting.stdout)["error"] == "handoff checkpoint has not been acknowledged"
    assert ledger.files() == before


def test_a_root_actor_fenced_by_succession_is_refused(loop):
    root, ledger, value = loop
    checkpoint = ledger.cli("checkpoint")
    ledger.event("succeed", actor="root-2", predecessor="root-1", checkpoint_sha256=checkpoint["sha256"])
    before = ledger.files()
    refused = responses(serve(root, ledger, [(TOOL, decision(value))]))[-1]
    assert refused["result"]["isError"] is True
    assert payload(refused)["error"] == "stale ROOT custody"
    assert ledger.files() == before


@pytest.mark.parametrize("actor,error", [
    ("router-1", "actor router-1 is not a ROOT actor in the lifecycle policy"),
    ("nobody-1", "actor nobody-1 is not a ROOT actor in the lifecycle policy"),
    ("../x", "invalid actor"),
])
def test_only_a_configured_root_actor_starts(loop, actor, error):
    root, ledger, _ = loop
    result = serve(root, ledger, actor=actor)
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == error


def test_root_without_a_lifecycle_journal_gets_no_adapter(loop):
    root, ledger, _ = loop
    result = serve(root, ledger, lifecycle=False)
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == ("ROOT takes only the decision adapter: give --lifecycle and --actor; "
                                                  "operational controller access is forbidden")


@pytest.mark.parametrize("flag", ["--delivery-dir", "--workspace-store", "--board"])
def test_root_takes_no_mailbox_workspace_or_board_options(loop, tmp_path, flag):
    root, ledger, _ = loop
    result = serve(root, ledger, extra=[flag, str(tmp_path)])
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == "the ROOT decision adapter takes no mailbox, workspace or board options"


@pytest.mark.parametrize("endpoint", ["a/orchestrator", "a/front-door", "a/lane/f2", "a/lane/review"])
def test_no_other_role_gets_the_decision_adapter(loop, endpoint):
    root, ledger, value = loop
    result = serve(root, ledger, endpoint=endpoint)
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == "only ROOT takes --lifecycle and --actor"
    assert decisions(ledger) == []


def test_the_decision_is_what_lets_the_operator_admit_the_request(loop):
    root, ledger, value = loop
    assert "no approved bounded authority" in ledger.status()["continuation_holds"]["feature-1"]
    responses(serve(root, ledger, [(TOOL, decision(value))]))
    assert ledger.status()["continuation_candidates"] == ["feature-1"]
    ledger.admit(value)


def test_mailbox_traffic_cannot_stand_in_for_a_decision(loop):
    root, ledger, value = loop
    invoke(root, "publish", message("a/orchestrator", "a/root", identifier="please-approve"))
    assert decisions(ledger) == []
    assert "no approved bounded authority" in ledger.status()["continuation_holds"]["feature-1"]
