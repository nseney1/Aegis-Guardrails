"""A mailbox move preserves job identity and directs reconciliation before any replacement request."""
import hashlib
from pathlib import Path

import pytest

from tests.integration.test_hierarchy_carry import move  # noqa: F401
from tests.integration.test_hierarchy_carry import pytestmark as pytestmark
from tests.integration.test_hierarchy_mailbox import invoke, mailbox_snapshot


def original_job(move):
    packet = move.send(move.old, "a/orchestrator", "a/root", "job-packet", "info")
    return move.send(move.old, "a/orchestrator", "a/root", "job-1", "job_request",
                     brief={"path": packet["path"], "sha256": packet["sha256"]})


def files_at(root):
    return {str(path.relative_to(root)): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in root.rglob("*") if path.is_file()}


def job_section(text):
    return text.split("## Open job requests\n", 1)[1].split("## Newest messages\n", 1)[0]


@pytest.mark.parametrize("receipt_state", [None, "started", "unknown"])
def test_carry_requires_original_job_reconciliation_without_replaying_or_settling_it(move, receipt_state):
    original = original_job(move)
    if receipt_state is not None:
        receipt = {"state": receipt_state}
        if receipt_state == "unknown":
            receipt["reason"] = "The runner reply was lost."
        move.send(move.old, "a/root", "a/orchestrator", "job-receipt", "job_receipt",
                  in_reply_to="job-1", receipt=receipt)
    move.workspace.run("request", {"initiative": "a", "kind": "heavy", "holder": "job:a/job-1"})
    move.workspace.run("grant-next", kind="heavy")
    retained = move.workspace.store / "jobs/a/job-1/step-1.log"
    retained.parent.mkdir(parents=True)
    retained.write_text("Retained output; absence of a terminal receipt proves no execution state.\n")
    move.bind_new()
    mailbox_before = mailbox_snapshot(move.old)
    store_before = files_at(move.workspace.store)

    carried = move.carry()
    assert carried["open_job_requests"] == ["job-1"]
    section = job_section(move.carried_message()["brief_text"])
    assert "a/job-1" in section
    assert "%s sha256 %s" % (original["path"], original["sha256"]) in section
    assert hashlib.sha256(Path(original["path"]).read_bytes()).hexdigest() == original["sha256"]
    assert "no terminal receipt" in section
    assert "running, completed or uncertain" in section
    assert "original workspace store" in section
    assert "claims, results, receipts and reservations" in section
    assert "--store <original-workspace-store> recovery-status --initiative a" in section
    assert "Do not submit a new request, replay work or release reservations" in section
    assert "never answered" not in section and "Ask root again" not in section
    assert mailbox_snapshot(move.old) == mailbox_before
    assert files_at(move.workspace.store) == store_before
    assert invoke(move.root, "status")["open_job_requests"] == []
    assert move.workspace.run("status")["capacity"]["heavy"]["used"] == 1
    assert move.carry()["brief"] == carried["brief"]
    assert mailbox_snapshot(move.old) == mailbox_before
    assert files_at(move.workspace.store) == store_before


def test_old_open_jobs_keep_hash_bound_references_outside_the_recent_message_window(move):
    original = original_job(move)
    # More than the documented recent-message window; the job itself must remain in the complete open-work list.
    for number in range(25):
        move.send(move.old, "a/front-door", "a/orchestrator", "later-%02d" % number)
    move.bind_new()
    move.carry()
    text = move.carried_message()["brief_text"]
    section = job_section(text)
    assert "a/job-1" in section
    assert "%s sha256 %s" % (original["path"], original["sha256"]) in section
    assert "job-1" not in text.split("## Newest messages\n", 1)[1]


def test_a_terminal_receipt_keeps_a_closed_job_out_of_the_open_job_guidance(move):
    original_job(move)
    move.send(move.old, "a/root", "a/orchestrator", "job-refused", "job_receipt",
              in_reply_to="job-1", receipt={"state": "refused", "reason": "The packet was not admitted."})
    move.bind_new()
    before = mailbox_snapshot(move.old)
    assert move.carry()["open_job_requests"] == []
    assert "## Open job requests" not in move.carried_message()["brief_text"]
    assert mailbox_snapshot(move.old) == before
    assert invoke(move.root, "status")["open_job_requests"] == []
