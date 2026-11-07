"""Fresh-thread checkpoints retain every unread obligation or refuse without rotating."""
import hashlib
from pathlib import Path

import pytest

from tests.integration.test_hierarchy_delivery import Pilot, TARGET, posix_only
from tests.integration.test_hierarchy_handoff import draft, mailbox_files
from tests.integration.test_hierarchy_mailbox import (  # noqa: F401
    INBOX_WIRE_BUDGET, cli_inbox_wire, invoke, message, pilot,
)
from tests.integration.test_hierarchy_mailbox_mcp import exchange, mcp_inbox_wire, payload


def brief_at(path, text):
    path.write_text(text, encoding="utf-8")
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def publish_notes(root, count):
    identifiers = ["note-%03d" % index for index in range(count)]
    # Use the public scoped adapter in bounded batches; no hand-written mailbox history.
    for start in range(0, count, 32):
        calls = [("mailbox_publish", {"message_id": identifier, "to": TARGET, "type": "info",
                                      "body": "Pending work reference."})
                 for identifier in identifiers[start:start + 32]]
        responses = exchange(root, calls, endpoint="a/orchestrator")[2:]
        assert len(responses) == len(calls)
        for response in responses:
            assert not response["result"].get("isError"), response
            assert payload(response)["sha256"]
    return identifiers


@pytest.mark.parametrize("count", [101, 256])
def test_draft_and_binding_retain_all_unread_ids_beyond_the_delivery_summary(pilot, tmp_path, count):  # noqa: F811
    root, brief = pilot
    identifiers = publish_notes(root, count)
    delivery = tmp_path / "delivery"
    summary = invoke(root, "delivery", delivery_dir=delivery, endpoint=TARGET)["endpoints"][TARGET]
    assert summary["unread_count"] == count and len(summary["unread"]) == 100
    request = invoke(root, "draft-handoff", draft(root, endpoint=TARGET, briefs=[brief],
                                                  delivery_dir=str(delivery)))
    assert request["checkpoint"]["pending_message_ids"] == identifiers
    binding = invoke(root, "bind", request)
    assert binding["generation"] == 2 and binding["ready"] is False
    assert binding["checkpoint"]["pending_message_ids"] == identifiers


def test_pending_overflow_refuses_without_changing_the_old_binding(pilot, tmp_path):  # noqa: F811
    root, brief = pilot
    publish_notes(root, 257)
    before = mailbox_files(root)
    refused = invoke(root, "draft-handoff", draft(root, endpoint=TARGET, briefs=[brief],
                                                  delivery_dir=str(tmp_path / "delivery")), ok=False)
    assert refused["error"] == "handoff exceeds 256 pending messages"
    assert mailbox_files(root) == before
    assert invoke(root, "status")["bindings"][TARGET]["generation"] == 1


@posix_only
def test_active_dispatch_is_not_duplicated_and_woken_mail_stays_pending(tmp_path):
    team = Pilot(tmp_path)
    brief = brief_at(tmp_path / "assignment.md", "Review the existing bounded assignment.\n")
    team.publish("already-read")
    assert team.read_inbox()["messages"][0]["message"]["message_id"] == "already-read"
    invoke(team.root, "publish", message(recipient=TARGET, identifier="review-work", kind="dispatch", brief=brief))
    accepted = exchange(team.root, [("mailbox_publish", {
        "message_id": "review-accepted", "to": "a/orchestrator", "type": "ack", "body": "Accepted.",
        "in_reply_to": "review-work", "acknowledgment": "accepted"})], session=team.session)[-1]
    assert not accepted["result"].get("isError"), accepted
    team.publish("woken-note")
    code, wake = team.wake(team.profile(mode="ignore"))
    assert code == 3 and wake["state"] == "woken_unread"
    assert team.state("woken-note")["state"] == "woken"
    team.publish("published-note")
    assert team.state("published-note")["state"] == "published"
    request = invoke(team.root, "draft-handoff", draft(team.root, endpoint=TARGET,
                                                       delivery_dir=str(team.delivery)))
    assert request["checkpoint"]["pending_message_ids"] == ["review-work", "woken-note", "published-note"]
    assert request["checkpoint"]["briefs"] == [brief]


@pytest.mark.parametrize("inherited", [False, True])
def test_optional_or_inherited_brief_overflow_refuses_instead_of_dropping_references(pilot, tmp_path, inherited):  # noqa: F811
    root, _ = pilot
    briefs = [brief_at(tmp_path / ("brief-%03d.md" % index), "Evidence reference %d.\n" % index)
              for index in range(257)]
    if inherited:
        first = invoke(root, "draft-handoff", draft(root, endpoint=TARGET, briefs=briefs[:256]))
        assert invoke(root, "bind", first)["generation"] == 2
    before = mailbox_files(root)
    refused = invoke(root, "draft-handoff", draft(root, endpoint=TARGET, session="third-session",
                                                  briefs=[briefs[-1]] if inherited else briefs), ok=False)
    assert refused["error"] == "handoff exceeds 256 brief references"
    assert mailbox_files(root) == before
    assert invoke(root, "status")["bindings"][TARGET]["generation"] == (2 if inherited else 1)


def test_successor_reads_every_unread_brief_with_its_original_hash_and_text(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    older = brief_at(tmp_path / "older.md", "Earlier dependency evidence.\n")
    newer = brief_at(tmp_path / "newer.md", "Later evidence.\n")
    for identifier, brief in (("older-note", older), ("newer-note", newer)):
        invoke(root, "publish", message(recipient=TARGET, identifier=identifier, brief=brief))
    request = invoke(root, "draft-handoff", draft(root, endpoint=TARGET, delivery_dir=str(tmp_path / "delivery")))
    assert request["checkpoint"]["pending_message_ids"] == ["older-note", "newer-note"]
    assert invoke(root, "bind", request)["ready"] is False
    cursor = None
    for identifier, brief in (("older-note", older), ("newer-note", newer)):
        arguments = {"include_briefs": True, "limit": 1}
        if cursor is not None:
            arguments["after_message_id"] = cursor
        response = exchange(root, [("mailbox_inbox", arguments)], host="host-two", session="successor",
                            generation=2, delivery=tmp_path / "delivery")[-1]
        assert not response["result"].get("isError"), response
        page = payload(response)
        assert len(page["messages"]) == 1
        received = page["messages"][0]
        assert received["message"]["message_id"] == identifier
        assert received["message"]["brief"] == brief
        assert received["brief_text"] == Path(brief["path"]).read_text(encoding="utf-8")
        assert page["binding"]["ready"] is False
        cursor = page["next_after"]
    assert page["remaining"] == 0 and cursor is None
    delivery = invoke(root, "delivery", delivery_dir=tmp_path / "delivery", endpoint=TARGET)["endpoints"][TARGET]
    assert delivery["unread_count"] == 0
    assert invoke(root, "status")["bindings"][TARGET]["ready"] is False


def test_failed_successor_read_of_a_corrupt_brief_records_neither_read_nor_acknowledgment(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    older = brief_at(tmp_path / "older.md", "Earlier dependency evidence.\n")
    newer = brief_at(tmp_path / "newer.md", "Later evidence.\n")
    for identifier, brief in (("older-note", older), ("newer-note", newer)):
        invoke(root, "publish", message(recipient=TARGET, identifier=identifier, brief=brief))
    request = invoke(root, "draft-handoff", draft(root, endpoint=TARGET, delivery_dir=str(tmp_path / "delivery")))
    assert invoke(root, "bind", request)["ready"] is False
    Path(older["path"]).write_text("Changed after publication.\n", encoding="utf-8")
    before = mailbox_files(root)
    refused = exchange(root, [("mailbox_inbox", {"include_briefs": True})], host="host-two", session="successor",
                       generation=2, delivery=tmp_path / "delivery")[-1]
    assert refused["result"]["isError"] is True
    assert payload(refused) == {"error": "brief sha256 mismatch"}
    assert mailbox_files(root) == before
    state = invoke(root, "status")["bindings"][TARGET]
    assert state["generation"] == 2 and state["ready"] is False
    assert not list((tmp_path / "delivery").glob("reads/**/*.json"))
    delivery = invoke(root, "delivery", delivery_dir=tmp_path / "delivery", endpoint=TARGET)["endpoints"][TARGET]
    assert delivery["unread_count"] == 2


@pytest.mark.parametrize("transport", ["cli", "mcp"])
def test_large_unread_briefs_remain_losslessly_pageable_after_handoff(pilot, tmp_path, transport):  # noqa: F811
    root, _ = pilot
    expected = []
    for index in range(20):
        identifier = "large-note-%02d" % index
        text = ("Evidence %02d.\n" % index).ljust(250000, "x")
        brief = brief_at(tmp_path / (identifier + ".md"), text)
        invoke(root, "publish", message(recipient=TARGET, identifier=identifier, brief=brief))
        expected.append((identifier, brief, text))
    assert sum(len(text.encode("utf-8")) for _, _, text in expected) > INBOX_WIRE_BUDGET
    request = invoke(root, "draft-handoff", draft(root, endpoint=TARGET, delivery_dir=str(tmp_path / "delivery")))
    assert request["checkpoint"]["pending_message_ids"] == [identifier for identifier, _, _ in expected]
    assert invoke(root, "bind", request)["ready"] is False
    received, cursor = [], None
    for page_number in range(len(expected)):
        if transport == "cli":
            raw, page = cli_inbox_wire(root, endpoint=TARGET, include_briefs=True, after=cursor)
        else:
            arguments = {"include_briefs": True}
            if cursor is not None:
                arguments["after_message_id"] = cursor
            raw, response = mcp_inbox_wire(root, arguments, endpoint=TARGET, host="host-two", session="successor",
                                          generation=2)
            assert not response["result"].get("isError"), response
            page = payload(response)
        assert len(raw) <= INBOX_WIRE_BUDGET
        assert page["binding"]["ready"] is False
        if page_number == 0:
            assert 0 < len(page["messages"]) < len(expected)
        received.extend((row["message"]["message_id"], row["message"]["brief"], row["brief_text"])
                        for row in page["messages"])
        assert page["remaining"] == len(expected) - len(received)
        if not page["remaining"]:
            assert page["next_after"] is None
            break
        assert page["next_after"] == received[-1][0] and page["next_after"] != cursor
        cursor = page["next_after"]
    assert received == expected
