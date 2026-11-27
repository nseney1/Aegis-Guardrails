"""Fresh-thread checkpoints retain every unread obligation or refuse without rotating."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_delivery import Pilot, TARGET, posix_only
from tests.integration.test_hierarchy_handoff import HANDOFF, draft, handoff, mailbox_files
from tests.integration.test_hierarchy_mailbox import (  # noqa: F401
    INBOX_WIRE_BUDGET, cli_inbox_wire, invoke, message, pilot,
)
from tests.integration.test_hierarchy_mailbox_mcp import exchange, mcp_inbox_wire, payload


def brief_at(path, text):
    # Bytes, not write_text: on Windows write_text stores "\r\n", which the mailbox returns
    # losslessly and which then differs from the "\n" text the tests expect.
    path.write_bytes(text.encode("utf-8"))
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def publish_notes(root, count):
    identifiers = ["note-%03d" % index for index in range(count)]
    # Use the public scoped adapter in bounded batches; no hand-written mailbox history. Each publish re-validates the
    # stored history, so a batch's cost grows with the mailbox: 32 per exchange outran exchange()'s 15 s timeout near
    # note-191 on hosted Windows 3.12 (run 42412233402). Batches of 8 stay well inside it.
    for start in range(0, count, 8):
        calls = [("mailbox_publish", {"message_id": identifier, "to": TARGET, "type": "info",
                                      "body": "Pending work reference."})
                 for identifier in identifiers[start:start + 8]]
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

    # Compare digests first: with CI set, pytest prints a failed comparison of these 20
    # 250 kB texts in full (about 6 MB per parameter), and the hosted runner took about two
    # minutes per such line, so one mismatch outlasted the test-windows timeout.
    def digest(rows):
        return [(identifier, brief, len(text), hashlib.sha256(text.encode("utf-8")).hexdigest())
                for identifier, brief, text in rows]

    assert digest(received) == digest(expected)
    assert received == expected


@pytest.fixture
def pruning_case(tmp_path):
    root = tmp_path / "mailbox"
    endpoints = {name: {} for name in ("a/front-door", "a/root", "a/orchestrator", "a/lane/review")}
    endpoints["a/lane/review"] = {"kind": "reviewer"}
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints,
                          "counterparts": [], "writer_limit": 3})
    for endpoint in endpoints:
        invoke(root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint,
                              "expected_generation": 0})
    briefs = [brief_at(tmp_path / ("inherited-%02d.md" % index), "Scope %d.\n" % index)
              for index in range(74)]
    request = invoke(root, "draft-handoff", draft(root, endpoint="a/orchestrator", host="host-one",
                                                  session="incumbent", briefs=briefs))
    binding = invoke(root, "bind", request)
    invoke(root, "ack-handoff", {"endpoint": "a/orchestrator", "session": "incumbent", "generation": 2,
                                 "checkpoint_sha256": binding["checkpoint_sha256"]})
    (tmp_path / "provision.json").write_text(json.dumps({"mailbox_root": str(root), "initiative": "a"}),
                                            encoding="utf-8")
    (tmp_path / "host-plan.json").write_text(json.dumps({
        "schema": "aegis.hierarchy-host-plan/v1", "hierarchy": "a", "root": "codex-cli", "team": "codex-cli",
        "stand_ins": {}, "config_sha256": "0" * 64}), encoding="utf-8")
    return root, briefs


def pruning_message(identifier, kind="info", **changes):
    return {**message(recipient="a/lane/review", identifier=identifier, kind=kind),
            "session": "incumbent", "binding_generation": 2, **changes}


def pruning_spec(root, **changes):
    return {"schema": "aegis.hierarchy-handoff/v1", "host": "codex-cli", "session": "successor",
            "outgoing_stopped": True,
            "entries": [{"root": str(root), "endpoint": "a/orchestrator", **changes}]}


def pruned_binding(root):
    return json.loads((root / "bindings" / "a" / "orchestrator" / "000003.json").read_text(encoding="utf-8"))


def test_handoff_prunes_74_inherited_briefs_to_active_and_last_touching(pruning_case, tmp_path):
    root, briefs = pruning_case
    for index in (2, 9):
        invoke(root, "publish", pruning_message("active-%d" % index, "dispatch", brief=briefs[index]))
    invoke(root, "publish", message("a/lane/review", "a/orchestrator", identifier="last-brief", brief=briefs[40]))
    # A later message without a brief must not erase the most recent touching brief.
    invoke(root, "publish", message("a/lane/review", "a/orchestrator", identifier="unread-note"))
    entry = {"delivery_dir": str(tmp_path / "delivery"), "completed_checks": ["review complete"]}
    baseline = invoke(root, "draft-handoff", draft(root, endpoint="a/orchestrator", **entry))["checkpoint"]
    assert len(baseline["briefs"]) == 74
    spec = pruning_spec(root, **entry)
    result = handoff(tmp_path, spec, 0)
    binding = pruned_binding(root)
    expected = {**baseline, "briefs": [briefs[2], briefs[9], briefs[40]]}
    assert binding["checkpoint"] == expected
    assert len(binding["checkpoint"]) == 7
    encoded = json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    assert binding["checkpoint_sha256"] == hashlib.sha256(encoded).hexdigest()
    assert "unread-note" in binding["checkpoint"]["pending_message_ids"]
    assert invoke(root, "ack-handoff", result["entries"][0]["acknowledge"])["ready"] is True
    before = mailbox_files(root)
    repeated = handoff(tmp_path, spec, 0)
    assert repeated["entries"][0]["already_bound"] is True
    assert repeated["entries"][0]["checkpoint_sha256"] == binding["checkpoint_sha256"]
    assert mailbox_files(root) == before


@pytest.mark.parametrize("touching", [False, True])
def test_handoff_with_no_active_work_keeps_exactly_one_brief(pruning_case, tmp_path, touching):
    root, briefs = pruning_case
    if touching:
        invoke(root, "publish", pruning_message("last-touch", brief=briefs[12]))
    result = handoff(tmp_path, pruning_spec(root), 0)
    assert pruned_binding(root)["checkpoint"]["briefs"] == [briefs[12] if touching else briefs[-1]]
    assert invoke(root, "ack-handoff", result["entries"][0]["acknowledge"])["ready"] is True


def test_handoff_keeps_requested_briefs_in_draft_order(pruning_case, tmp_path):
    root, briefs = pruning_case
    extra = brief_at(tmp_path / "requested.md", "Explicit next scope.\n")
    invoke(root, "publish", pruning_message("last-touch", brief=briefs[12]))
    handoff(tmp_path, pruning_spec(root, briefs=[briefs[50], extra, briefs[50]]), 0)
    assert pruned_binding(root)["checkpoint"]["briefs"] == [briefs[50], extra, briefs[12]]


@pytest.mark.parametrize("endpoint", ["a/orchestrator", "a/root"])
def test_handoff_keeps_an_open_jobs_brief_at_either_endpoint(pruning_case, tmp_path, endpoint):
    root, briefs = pruning_case
    if endpoint == "a/root":
        request = invoke(root, "draft-handoff", draft(root, endpoint=endpoint, host="host-one",
                                                      session="root-incumbent", briefs=briefs))
        binding = invoke(root, "bind", request)
        invoke(root, "ack-handoff", {"endpoint": endpoint, "session": "root-incumbent", "generation": 2,
                                     "checkpoint_sha256": binding["checkpoint_sha256"]})
    invoke(root, "publish", pruning_message("open-job", "job_request", to="a/root", brief=briefs[7]))
    invoke(root, "publish", pruning_message("last-touch", to="a/root", brief=briefs[12]))
    spec = pruning_spec(root)
    spec["entries"][0]["endpoint"] = endpoint
    result = handoff(tmp_path, spec, 0)
    path = root / "bindings" / Path(endpoint) / "000003.json"
    checkpoint = json.loads(path.read_text(encoding="utf-8"))["checkpoint"]
    assert checkpoint["briefs"] == [briefs[7], briefs[12]]
    assert checkpoint["pending_message_ids"] == ["open-job"]
    assert invoke(root, "ack-handoff", result["entries"][0]["acknowledge"])["ready"] is True


@pytest.mark.parametrize("boundary", ["draft_handoff", "bind"])
def test_handoff_refuses_a_concurrent_dispatch_then_retries(pruning_case, tmp_path, capsys, boundary):
    root, _ = pruning_case
    module_spec = importlib.util.spec_from_file_location("mb4_handoff", HANDOFF)
    control = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(control)
    original = control.Mailbox
    late = brief_at(tmp_path / "late.md", "Concurrent assignment.\n")
    new_dispatch = pruning_message("late-dispatch", "dispatch", brief=late)

    class ChangingMailbox(original):
        def draft_handoff(self, request):
            result = super().draft_handoff(request)
            if boundary == "draft_handoff":
                self.publish(new_dispatch)
            return result

        def bind(self, request):
            if boundary == "bind":
                self.publish(new_dispatch)
            return super().bind(request)

    # This test owns the freshly loaded module, which is not installed in sys.modules.
    # Change its consumer reference only; the shared mailbox class and OS globals stay intact.
    control.Mailbox = ChangingMailbox
    path = tmp_path / "handoff-spec.json"
    path.write_text(json.dumps(pruning_spec(root)), encoding="utf-8")
    before = mailbox_files(root / "bindings")
    try:
        assert control.main(["--spec", str(path)]) == 3
    finally:
        control.Mailbox = original
    captured = capsys.readouterr()
    assert not captured.err
    assert json.loads(captured.out)["entries"][0]["error"] == "checkpoint omits active dispatch"
    assert mailbox_files(root / "bindings") == before
    assert not (root / ".write.lock").exists()
    result = handoff(tmp_path, pruning_spec(root), 0)
    assert pruned_binding(root)["checkpoint"]["briefs"] == [late]
    assert invoke(root, "ack-handoff", result["entries"][0]["acknowledge"])["ready"] is True


def test_no_plan_codex_handoff_preserves_checkpoint_hash_and_acknowledgment(pilot, tmp_path):  # noqa: F811
    root, first = pilot
    second = brief_at(tmp_path / "standing.md", "Standing owner intent.\n")
    initial = invoke(root, "draft-handoff", draft(root, endpoint="a/orchestrator", host="codex-cli",
                                                session="incumbent", briefs=[first, second]))
    binding = invoke(root, "bind", initial)
    invoke(root, "ack-handoff", {"endpoint": "a/orchestrator", "session": "incumbent", "generation": 2,
                                 "checkpoint_sha256": binding["checkpoint_sha256"]})
    assert not (tmp_path / "host-plan.json").exists()
    baseline = invoke(root, "draft-handoff", draft(root, endpoint="a/orchestrator", host="codex-cli"))["checkpoint"]
    assert baseline["briefs"] == [first, second]
    expected_hash = hashlib.sha256(json.dumps(baseline, sort_keys=True, separators=(",", ":"),
                                             ensure_ascii=True).encode("utf-8")).hexdigest()
    spec = pruning_spec(root)
    result = handoff(tmp_path, spec, 0)
    actual = pruned_binding(root)
    assert actual["checkpoint"] == baseline
    assert actual["checkpoint_sha256"] == expected_hash
    expected_ack = {"endpoint": "a/orchestrator", "session": "successor", "generation": 3,
                    "checkpoint_sha256": expected_hash}
    assert result["entries"][0]["acknowledge"] == expected_ack
    assert invoke(root, "ack-handoff", expected_ack)["ready"] is True
    before = mailbox_files(root)
    assert handoff(tmp_path, spec, 0)["entries"][0]["acknowledge"] == expected_ack
    assert mailbox_files(root) == before


def test_planned_handoff_drops_completed_dispatch_and_terminal_job_briefs(pruning_case, tmp_path):
    root, briefs = pruning_case
    invoke(root, "publish", pruning_message("finished-dispatch", "dispatch", brief=briefs[2]))
    invoke(root, "publish", message("a/lane/review", "a/orchestrator", identifier="accepted", kind="ack",
                                    in_reply_to="finished-dispatch", acknowledgment="accepted"))
    invoke(root, "publish", message("a/lane/review", "a/orchestrator", identifier="reviewed", kind="review",
                                    in_reply_to="finished-dispatch", result={
                                        "source_revision": "a" * 40, "source_tree": "b" * 40,
                                        "checks": [{"check": "read diff", "outcome": "pass", "reference": "review"}]}))
    invoke(root, "publish", pruning_message("finished-job", "job_request", to="a/root", brief=briefs[7]))
    invoke(root, "publish", message("a/root", "a/orchestrator", identifier="job-done", kind="job_receipt",
                                    in_reply_to="finished-job", receipt={"state": "refused", "reason": "closed"}))
    invoke(root, "publish", pruning_message("last-touch", brief=briefs[12]))
    result = handoff(tmp_path, pruning_spec(root), 0)
    checkpoint = pruned_binding(root)["checkpoint"]
    assert briefs[2] not in checkpoint["briefs"]
    assert briefs[7] not in checkpoint["briefs"]
    assert checkpoint["briefs"] == [briefs[12]]
    assert checkpoint["pending_message_ids"] == []
    assert invoke(root, "ack-handoff", result["entries"][0]["acknowledge"])["ready"] is True


def test_planned_handoff_wrong_host_refuses_then_retries(pruning_case, tmp_path):
    root, briefs = pruning_case
    spec = pruning_spec(root)
    before = mailbox_files(root)
    refused = handoff(tmp_path, {**spec, "host": "claude-code"}, 3)
    assert refused["entries"][0]["error"] == "a/orchestrator runs on codex-cli in this run's host plan, not claude-code"
    assert mailbox_files(root) == before
    handoff(tmp_path, spec, 0)
    assert pruned_binding(root)["checkpoint"]["briefs"] == [briefs[-1]]


def test_handoff_help_explains_planned_pruning_and_legacy_carry_forward():
    result = subprocess.run([sys.executable, "-I", str(HANDOFF), "--help"],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0 and not result.stderr
    assert "with a governing host plan" in result.stdout
    assert "entries[].briefs" in result.stdout
    assert "without a plan, briefs carry forward unchanged" in result.stdout
