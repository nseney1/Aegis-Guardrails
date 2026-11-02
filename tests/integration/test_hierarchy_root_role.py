"""Root is a real endpoint with one route, and job requests stay separate from grants."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_mailbox import HELPER, invoke, message, published
from tests.integration.test_hierarchy_mailbox_mcp import exchange, payload


ENDPOINTS = {
    "a/front-door": {}, "a/orchestrator": {}, "a/root": {},
    "a/lane/f2": {"kind": "implementer"}, "a/lane/review": {"kind": "reviewer"},
    "b/front-door": {}, "b/orchestrator": {}, "b/root": {},
}
EVIDENCE = [{"path": "/absolute/evidence/job-1.json", "sha256": "a" * 64}]
COMPLETED = {"state": "completed", "exit_code": 0, "evidence": EVIDENCE}


@pytest.fixture
def team(tmp_path):
    root = tmp_path / "mailbox"
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": ENDPOINTS,
                          "counterparts": [["a/orchestrator", "b/orchestrator"]], "writer_limit": 3})
    for endpoint in ENDPOINTS:
        invoke(root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint,
                              "expected_generation": 0})
    packet = tmp_path / "job-packet.md"
    packet.write_bytes(b"Run the hierarchy suite on the exact tree.\n")
    return root, {"path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}


def request(packet, identifier="job-1", sender="a/orchestrator", recipient="a/root"):
    return message(sender, recipient, identifier=identifier, kind="job_request", brief=packet)


def receipt(body=COMPLETED, identifier="receipt-1", reply_to="job-1", sender="a/root", recipient="a/orchestrator"):
    return message(sender, recipient, identifier=identifier, kind="job_receipt", in_reply_to=reply_to, receipt=body)


@pytest.mark.parametrize("sender,recipient", [("a/orchestrator", "a/root"), ("a/root", "a/orchestrator")])
def test_root_and_its_orchestrator_can_exchange_messages(team, sender, recipient):
    root, _ = team
    result = invoke(root, "publish", message(sender, recipient))
    assert Path(result["path"]).parent == root / "a" / recipient.split("/")[1]
    assert [r["message"]["message_id"] for r in invoke(root, "inbox", endpoint=recipient)["messages"]] == ["dispatch-1"]


@pytest.mark.parametrize("sender,recipient", [
    ("a/root", "a/lane/f2"), ("a/lane/f2", "a/root"), ("a/root", "a/lane/review"),
    ("a/root", "a/front-door"), ("a/front-door", "a/root"),
    ("a/orchestrator", "b/root"), ("b/root", "a/orchestrator"), ("a/root", "b/root"),
])
def test_every_other_root_route_is_refused(team, sender, recipient):
    root, _ = team
    refused = invoke(root, "publish", message(sender, recipient), ok=False)
    assert refused["error"] == "route is not vertical or an explicit counterpart"
    assert published(root) == []


def manifest(endpoints, counterparts=()):
    return {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints, "counterparts": list(counterparts),
            "writer_limit": 3}


def test_root_cannot_be_a_counterpart(tmp_path):
    endpoints = {"a/front-door": {}, "a/orchestrator": {}, "a/root": {},
                 "b/front-door": {}, "b/orchestrator": {}, "b/root": {}}
    refused = invoke(tmp_path / "mailbox", "init", manifest(endpoints, [["a/root", "b/root"]]), ok=False)
    assert refused["error"] == "root endpoints cannot be counterparts"
    assert not (tmp_path / "mailbox").exists()


@pytest.mark.parametrize("endpoints,error", [
    ({"a/front-door": {}, "a/orchestrator": {}, "a/root/extra": {}}, "invalid endpoint"),
    ({"a/front-door": {}, "a/orchestrator": {}, "a/root": {"kind": "implementer"}}, "unexpected fields"),
    ({"a/orchestrator": {}, "a/root": {}}, "each hierarchy requires a front door and orchestrator"),
])
def test_malformed_root_manifests_are_refused(tmp_path, endpoints, error):
    assert error in invoke(tmp_path / "mailbox", "init", manifest(endpoints), ok=False)["error"]


def test_a_manifest_without_root_keeps_working_and_has_no_root_route(tmp_path):
    root = tmp_path / "mailbox"
    endpoints = {"a/front-door": {}, "a/orchestrator": {}}
    invoke(root, "init", manifest(endpoints))
    for endpoint in endpoints:
        invoke(root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint,
                              "expected_generation": 0})
    assert invoke(root, "publish", message("a/orchestrator", "a/front-door"))["path"]
    refused = invoke(root, "publish", message("a/orchestrator", "a/root", identifier="x"), ok=False)
    assert refused["error"] == "unknown endpoint: a/root"


def test_a_job_request_is_hash_bound_and_information_only(team):
    root, packet = team
    result = invoke(root, "publish", request(packet))
    assert result["message"]["authority"] == "information_only"
    assert result["message"]["brief"] == packet
    row = invoke(root, "inbox", endpoint="a/root", include_briefs=True)["messages"][0]
    assert row["brief_text"].startswith("Run the hierarchy suite")


def test_a_job_request_needs_its_packet_and_rejects_a_changed_one(team):
    root, packet = team
    missing = message("a/orchestrator", "a/root", identifier="job-1", kind="job_request")
    assert invoke(root, "publish", missing, ok=False)["error"] == "job request requires a hash-bound packet"
    Path(packet["path"]).write_bytes(b"changed after hashing\n")
    assert invoke(root, "publish", request(packet), ok=False)["error"] == "brief sha256 mismatch"
    assert published(root) == []


@pytest.mark.parametrize("sender,recipient", [
    ("a/front-door", "a/orchestrator"), ("a/root", "a/orchestrator"),
    ("a/orchestrator", "a/lane/f2"), ("a/lane/f2", "a/orchestrator"),
])
def test_only_an_orchestrator_can_request_a_job_from_its_root(team, sender, recipient):
    root, packet = team
    refused = invoke(root, "publish", request(packet, sender=sender, recipient=recipient), ok=False)
    assert refused["error"] == "only an orchestrator can request a job from its own root"
    assert published(root) == []


def test_a_receipt_must_come_from_root_and_reply_to_a_job_request(team):
    root, packet = team
    invoke(root, "publish", message("a/orchestrator", "a/root", identifier="note"))
    wrong_reply = receipt(reply_to="note")
    assert invoke(root, "publish", wrong_reply, ok=False)["error"] == "job receipt must reply to a job request"
    invoke(root, "publish", request(packet))
    unreferenced = message("a/root", "a/orchestrator", identifier="receipt-1", kind="job_receipt", receipt=COMPLETED)
    refused = invoke(root, "publish", unreferenced, ok=False)
    assert refused["error"] == "job receipt must come from root and reply to a job request"
    forged = receipt(sender="a/orchestrator", recipient="a/root")
    refused = invoke(root, "publish", forged, ok=False)
    assert refused["error"] == "job receipt must come from root and reply to a job request"


@pytest.mark.parametrize("body,error", [
    ({"state": "approved"}, "invalid job state"),
    ({"state": "completed", "exit_code": 0}, "job receipt requires evidence"),
    ({"state": "completed", "exit_code": 1, "evidence": EVIDENCE}, "completed job requires exit code 0"),
    ({"state": "completed", "evidence": EVIDENCE}, "completed job requires exit code 0"),
    ({"state": "failed", "exit_code": 0, "evidence": EVIDENCE}, "failed job requires a nonzero exit code"),
    ({"state": "failed", "exit_code": 1}, "job receipt requires evidence"),
    ({"state": "refused"}, "job receipt requires a reason"),
    ({"state": "unknown"}, "job receipt requires a reason"),
    ({"state": "completed", "exit_code": 0, "evidence": [{"path": "/x", "sha256": "short"}]}, "invalid evidence sha256"),
    ({"state": "completed", "exit_code": 0, "evidence": [{"path": "relative", "sha256": "a" * 64}]}, "evidence path must be absolute"),
    ({"state": "completed", "exit_code": True, "evidence": EVIDENCE}, "completed job requires exit code 0"),
    ({"state": "started", "approved": True}, "unexpected fields"),
    ("not-an-object", "expected a JSON object"),
    (None, "expected a JSON object"),
])
def test_malformed_receipts_are_refused(team, body, error):
    root, packet = team
    invoke(root, "publish", request(packet))
    assert error in invoke(root, "publish", receipt(body), ok=False)["error"]
    assert len(published(root)) == 1


def test_a_receipt_field_needs_the_receipt_type(team):
    root, _ = team
    refused = invoke(root, "publish", message("a/root", "a/orchestrator", receipt=COMPLETED), ok=False)
    assert refused["error"] == "receipt field requires job_receipt type"


def test_interim_receipts_are_allowed_and_a_terminal_one_closes_the_job(team):
    root, packet = team
    invoke(root, "publish", request(packet))
    assert invoke(root, "status")["open_job_requests"] == [
        {"message_id": "job-1", "from": "a/orchestrator", "to": "a/root",
         "created_at": invoke(root, "inbox", endpoint="a/root")["messages"][0]["message"]["created_at"]}]
    invoke(root, "publish", receipt({"state": "started"}, identifier="started"))
    invoke(root, "publish", receipt({"state": "unknown", "reason": "host lost the process"}, identifier="unsure"))
    assert [row["message_id"] for row in invoke(root, "status")["open_job_requests"]] == ["job-1"]
    invoke(root, "publish", receipt())
    assert invoke(root, "status")["open_job_requests"] == []
    second = receipt({"state": "failed", "exit_code": 2, "evidence": EVIDENCE}, identifier="second")
    assert invoke(root, "publish", second, ok=False)["error"] == "job request already has a terminal receipt"


def test_a_refusal_needs_no_evidence_and_closes_the_job(team):
    root, packet = team
    invoke(root, "publish", request(packet))
    invoke(root, "publish", receipt({"state": "refused", "reason": "heavy slot is busy"}))
    assert invoke(root, "status")["open_job_requests"] == []


def test_a_receipt_is_still_only_a_claim(team):
    root, packet = team
    invoke(root, "publish", request(packet))
    stored = invoke(root, "publish", receipt())["message"]
    assert stored["authority"] == "information_only"
    assert stored["verification"]["tests"] == "sender_claim"
    assert stored["verification"]["human_approval"] == "not_established"
    assert stored["verification"]["fitness_credit"] == 0


def test_evidence_references_are_inert(team, tmp_path):
    root, packet = team
    invoke(root, "publish", request(packet))
    sentinel = tmp_path / "must-not-be-read"
    body = {"state": "completed", "exit_code": 0,
            "evidence": [{"path": str(tmp_path / "does-not-exist.json"), "sha256": "b" * 64},
                         {"path": str(sentinel), "sha256": "c" * 64}]}
    invoke(root, "publish", receipt(body))
    assert not sentinel.exists()


def test_jobs_do_not_count_as_writers(team):
    root, packet = team
    invoke(root, "publish", request(packet))
    assert invoke(root, "status")["accepted_writers"] == []


def rotated_root(root, packet, checkpoint_changes=None):
    checkpoint = {"outgoing_stopped": True, "briefs": [packet], "sources": [], "lease_refs": [],
                  "completed_checks": [], "pending_message_ids": ["job-1"], "last_acknowledgment_ids": []}
    checkpoint.update(checkpoint_changes or {})
    return {"endpoint": "a/root", "host": "host-two", "session": "new-root", "expected_generation": 1,
            "checkpoint": checkpoint}


def test_root_rotates_like_other_control_roles_and_keeps_its_open_job(team):
    root, packet = team
    invoke(root, "publish", request(packet))
    refused = invoke(root, "bind", rotated_root(root, packet, {"pending_message_ids": []}), ok=False)
    assert refused["error"] == "checkpoint omits open job request"
    draft = invoke(root, "draft-handoff", {"endpoint": "a/root", "host": "host-two", "session": "new-root",
                                           "outgoing_stopped": True})
    assert draft["checkpoint"]["pending_message_ids"] == ["job-1"]
    assert draft["checkpoint"]["briefs"] == [packet]
    binding = invoke(root, "bind", draft)
    assert binding["generation"] == 2 and binding["ready"] is False
    stale = invoke(root, "publish", receipt(), ok=False)
    assert stale["error"] == "stale or mismatched sender binding"
    current = {**receipt(), "host": "host-two", "session": "new-root", "binding_generation": 2}
    assert invoke(root, "publish", current, ok=False)["error"] == "handoff checkpoint has not been acknowledged"
    invoke(root, "ack-handoff", {"endpoint": "a/root", "session": "new-root", "generation": 2,
                                 "checkpoint_sha256": binding["checkpoint_sha256"]})
    invoke(root, "publish", current)
    assert invoke(root, "status")["open_job_requests"] == []


def test_the_orchestrator_handoff_also_keeps_its_open_job(team):
    root, packet = team
    invoke(root, "publish", request(packet))
    draft = invoke(root, "draft-handoff", {"endpoint": "a/orchestrator", "host": "host-two", "session": "new",
                                           "outgoing_stopped": True})
    assert draft["checkpoint"]["pending_message_ids"] == ["job-1"]


def test_a_job_can_be_requested_and_answered_through_the_scoped_adapter(team):
    root, packet = team
    tools = {tool["name"]: tool for tool in exchange(root, endpoint="a/orchestrator")[1]["result"]["tools"]}
    publish_schema = tools["mailbox_publish"]["inputSchema"]["properties"]
    assert {"job_request", "job_receipt"} <= set(publish_schema["type"]["enum"])
    assert "receipt" in publish_schema
    asked = exchange(root, [("mailbox_publish", {"message_id": "job-1", "to": "a/root", "type": "job_request",
                                                 "body": "Run it.", "brief": packet})], endpoint="a/orchestrator")
    assert payload(asked[-1])["message"]["from"] == "a/orchestrator"
    assert invoke(root, "publish", receipt())["message"]["receipt"] == COMPLETED
    delivered = payload(exchange(root, [("mailbox_inbox", {})], endpoint="a/orchestrator")[-1])["messages"]
    assert delivered[0]["message"]["receipt"] == COMPLETED
    denied = exchange(root, [("mailbox_publish", {"message_id": "job-2", "to": "a/root", "type": "job_request",
                                                  "body": "Run it.", "brief": packet})], endpoint="a/lane/f2")
    assert denied[-1]["result"]["isError"] is True
    assert "route is not vertical" in payload(denied[-1])["error"]


def test_root_gets_no_mailbox_adapter_because_it_uses_the_controller(team):
    root, _ = team
    result = subprocess.run([sys.executable, "-I", str(HELPER), "--root", str(root), "serve", "--endpoint", "a/root",
                             "--host", "host-one", "--session", "a/root", "--generation", "1"],
                            input="", capture_output=True, text=True, timeout=15,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == "root uses the controller, not the mailbox adapter"


def test_stored_job_messages_survive_a_fresh_read(team):
    root, packet = team
    invoke(root, "publish", request(packet))
    invoke(root, "publish", receipt())
    rows = invoke(root, "inbox", endpoint="a/orchestrator")["messages"]
    assert rows[0]["message"]["receipt"] == json.loads(json.dumps(COMPLETED))
