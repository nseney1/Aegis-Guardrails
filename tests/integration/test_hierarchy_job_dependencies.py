"""Pre-submitted fixed-source checks progress from durable evidence, without a relay turn."""
import hashlib
import json

import pytest

from tests.integration.test_hierarchy_jobs import shop, verified_evidence  # noqa: F401
from tests.integration.test_hierarchy_jobs import pytestmark as pytestmark
from tests.integration.test_hierarchy_mailbox import git
from tests.integration.test_hierarchy_mailbox_fence import unacked_successor


SCHEMA = "aegis.hierarchy-job-packet/v2"


def dependent(shop, parent, identifier="next-check", **changes):
    packet = {"schema": SCHEMA, "recipe": "touch", **shop.head(),
              "recipes_sha256": hashlib.sha256(shop.recipes_path.read_bytes()).hexdigest(),
              "after": {"message_id": "first-check", "sha256": parent["sha256"]}, **changes}
    return shop.request_job(identifier, "touch", raw=json.dumps(packet))


def row(answer, identifier="next-check"):
    return next(r for r in answer["rows"] if r.get("job") == "pilot/" + identifier)


def test_pre_submitted_check_waits_then_executes_exactly_once(shop):
    parent = shop.request_job("first-check", "ok")
    dependent(shop, parent)
    first = shop.run_open(expect=3)
    assert row(first)["state"] == "waiting"
    assert row(first)["reason"] == "dependency_pending"
    assert not (shop.workspace.store / "jobs/pilot/next-check").exists()
    assert not shop.sentinel.exists()

    assert row(shop.run_open())["state"] == "completed"
    assert shop.sentinel.read_text() == "ran\n"
    assert shop.states("next-check") == ["started", "completed"]
    assert shop.run_open()["rows"] == []
    assert shop.sentinel.read_text() == "ran\n"
    retained = (shop.workspace.store / "jobs/pilot/next-check/packet.md").read_text()
    assert SCHEMA in retained and '"after"' in retained
    evidence = verified_evidence(shop.receipts("next-check")[-1])
    assert json.loads(evidence["result.json"].read_text())["after"]["source_revision"] == shop.head()["commit"]
    recovery = shop.jobs("recovery-status")
    recovered = next(r for r in recovery["jobs"] if r["job"] == "pilot/next-check")
    assert recovered["state"] == "finished"
    assert recovered["source"]["state"] == "match"


@pytest.mark.parametrize("broken", ["request_hash", "recipes", "failed", "result", "log", "claim"])
def test_uncertain_or_failed_predecessor_holds_without_claiming_child(shop, broken):
    parent = shop.request_job("first-check", "fail" if broken == "failed" else "ok")
    shop.run_open()
    changes = {}
    if broken == "request_hash":
        changes["after"] = {"message_id": "first-check", "sha256": "0" * 64}
    elif broken == "recipes":
        changes["recipes_sha256"] = "0" * 64
    elif broken == "result":
        (shop.workspace.store / "jobs/pilot/first-check/result.json").write_text("{}")
    elif broken == "log":
        (shop.workspace.store / "jobs/pilot/first-check/step-1.log").write_text("changed evidence")
    elif broken == "claim":
        path = shop.workspace.store / "jobs/pilot/first-check/claim.json"
        value = json.loads(path.read_text())
        value["process_scope"] = {}
        path.write_text(json.dumps(value))
    dependent(shop, parent, **changes)
    shop.request_job("independent", "ok")
    result = shop.run_open(expect=3)
    assert row(result)["state"] == "waiting"
    assert row(result)["reason"] == "dependency_held"
    assert row(result, "independent")["state"] == "completed"
    assert not (shop.workspace.store / "jobs/pilot/next-check").exists()
    assert not shop.sentinel.exists()
    assert shop.states("next-check") == []


def test_missing_predecessor_is_bounded_waiting(shop):
    dependent(shop, {"sha256": "0" * 64})
    result = row(shop.run_open(expect=3))
    assert result["state"] == "waiting" and result["reason"] == "dependency_pending"
    assert result["detail"] == "predecessor request is not present"
    assert not shop.sentinel.exists()


def test_source_drift_after_predecessor_never_runs_the_next_check(shop):
    parent = shop.request_job("first-check", "ok")
    shop.run_open()
    dependent(shop, parent)
    (shop.checkout / "src/app.py").write_text("changed = True\n")
    result = row(shop.run_open())
    assert result["state"] == "refused"
    assert result["reason"] == "source does not match the packet"
    assert not shop.sentinel.exists()


def test_predecessor_on_another_source_does_not_satisfy_dependency(shop):
    parent = shop.request_job("first-check", "ok")
    shop.run_open()
    (shop.checkout / "src/app.py").write_text("changed = True\n")
    git(shop.checkout, "add", ".")
    git(shop.checkout, "commit", "-qm", "incoming work")
    dependent(shop, parent)
    result = row(shop.run_open(expect=3))
    assert result["reason"] == "dependency_held"
    assert "predecessor source differs" in result["detail"]
    assert not shop.sentinel.exists()


def test_lost_terminal_receipt_is_reconciled_before_dependent_execution(shop):
    parent = shop.request_job("first-check", "ok")
    shop.run_open()
    # A removed delivery is the real filesystem boundary for a lost receipt.
    for path in (shop.root / "pilot/orchestrator").glob("*.md"):
        header = json.loads(path.read_text()[4:].split("\n---\n\n", 1)[0])
        if header.get("in_reply_to") == "first-check" and header.get("receipt", {}).get("state") == "completed":
            path.unlink()
    dependent(shop, parent)
    answer = shop.run_open()
    assert row(answer)["state"] == "completed"
    assert shop.states("first-check") == ["started", "completed"]
    assert shop.sentinel.read_text() == "ran\n"
    assert shop.run_open()["rows"] == []


def test_self_dependency_is_refused_without_execution(shop):
    dependent(shop, {"sha256": "0" * 64}, after={"message_id": "next-check", "sha256": "0" * 64})
    answer = row(shop.run_open())
    assert answer["state"] == "refused"
    assert answer["reason"] == "a job cannot depend on itself"
    assert not shop.sentinel.exists()


def test_old_packet_cannot_silently_opt_into_dependencies(shop):
    parent = shop.request_job("first-check", "ok")
    dependent(shop, parent, schema="aegis.hierarchy-job-packet/v1")
    answer = row(shop.run_open())
    assert answer["state"] == "refused"
    assert answer["reason"] == "unexpected fields: after, recipes_sha256"
    assert not shop.sentinel.exists()


@pytest.mark.parametrize("recipe", [[], {}])
def test_malformed_predecessor_packet_holds_without_aborting_other_jobs(shop, recipe):
    parent = shop.request_job("first-check", "ok", raw=json.dumps({
        "schema": "aegis.hierarchy-job-packet/v1", "recipe": recipe, **shop.head()}))
    dependent(shop, parent)
    shop.request_job("independent", "ok")
    answer = shop.run_open(expect=3)
    assert row(answer)["reason"] == "dependency_held"
    assert row(answer)["detail"] == "predecessor must be a command check"
    assert row(answer, "independent")["state"] == "completed"
    assert not shop.sentinel.exists()


def test_successor_binding_does_not_implicitly_authorize_old_dependent_request(shop):
    parent = shop.request_job("first-check", "ok")
    shop.run_open()
    dependent(shop, parent)
    unacked_successor(shop.root, "pilot/orchestrator", "successor", shop.root.parent)
    answer = row(shop.run_open(expect=3))
    assert answer["reason"] == "dependency_held"
    assert answer["detail"] == "stale or mismatched sender binding"
    assert not (shop.workspace.store / "jobs/pilot/next-check").exists()
    assert not shop.sentinel.exists()


def test_evidence_is_rechecked_after_admission_before_execution_claim(shop):
    log = shop.workspace.store / "jobs/pilot/first-check/step-1.log"
    shop.recipes["recipes"]["tamper"] = shop.command([
        "$python", "-c", "open(%r, 'a').write('changed')" % str(log)])
    shop.save_recipes()
    parent = shop.request_job("first-check", "ok")
    shop.run_open()
    shop.request_job("independent", "tamper")
    dependent(shop, parent)
    answer = shop.run_open(expect=3)
    assert row(answer, "independent")["state"] == "completed"
    assert row(answer)["reason"] == "dependency_held"
    assert row(answer)["detail"] == "predecessor terminal receipt does not match retained evidence"
    assert not (shop.workspace.store / "jobs/pilot/next-check").exists()
    assert not shop.sentinel.exists()


def test_changed_recipe_file_holds_pre_submitted_request(shop):
    parent = shop.request_job("first-check", "ok")
    shop.run_open()
    dependent(shop, parent)
    shop.recipes_path.write_text(shop.recipes_path.read_text() + "\n")
    answer = row(shop.run_open(expect=3))
    assert answer["reason"] == "dependency_held"
    assert answer["detail"] == "dependent recipe file changed"
    assert not (shop.workspace.store / "jobs/pilot/next-check").exists()
    assert not shop.sentinel.exists()


def test_completed_receipt_does_not_override_unsettled_reservation(shop):
    lock = shop.workspace.store / ".write.lock"
    shop.recipes["recipes"]["locks"] = shop.command([
        "$python", "-c", "open(%r, 'x').close()" % str(lock)], heavy=True)
    shop.save_recipes()
    parent = shop.request_job("first-check", "locks")
    dependent(shop, parent)
    try:
        shop.run_open(lock_wait=0, expect=3)
        assert shop.states("first-check") == ["started", "completed"]
        answer = row(shop.run_open(lock_wait=0, expect=3))
        assert answer["reason"] == "dependency_held"
        assert answer["detail"] == "predecessor reservation is not settled"
        assert shop.heavy()["used"] == 1
        assert not (shop.workspace.store / "jobs/pilot/next-check").exists()
        assert not shop.sentinel.exists()
    finally:
        if lock.exists():
            lock.unlink()
    assert row(shop.run_open())["state"] == "completed"
    assert shop.heavy()["used"] == 0
    assert shop.sentinel.read_text() == "ran\n"


def test_informational_message_cannot_satisfy_a_dependency(shop):
    parent = shop.publish("first-check", "info", "Everything passed.")
    dependent(shop, parent)
    answer = row(shop.run_open(expect=3))
    assert answer["reason"] == "dependency_held"
    assert answer["detail"] == "predecessor must have the same requester and recipient"
    assert not shop.sentinel.exists()


@pytest.mark.parametrize("digest", [None, "0" * 64])
def test_predecessor_claim_recipe_pin_must_agree_with_result(shop, digest):
    parent = shop.request_job("first-check", "ok")
    shop.run_open()
    claim = shop.workspace.store / "jobs/pilot/first-check/claim.json"
    value = json.loads(claim.read_text())
    value["recipes_sha256"] = digest
    claim.write_text(json.dumps(value))
    dependent(shop, parent)
    answer = row(shop.run_open(expect=3))
    assert answer["reason"] == "dependency_held"
    assert answer["detail"] == "predecessor claim recipe provenance mismatch"
    assert not shop.sentinel.exists()
    assert shop.states("next-check") == []


@pytest.mark.parametrize("stage", ["queued", "granted"])
def test_dependency_drift_after_capacity_admission_refuses_without_running_or_leaking_capacity(shop, stage):
    log = shop.workspace.store / "jobs/pilot/first-check/step-1.log"
    shop.recipes["recipes"]["touch"]["heavy"] = True
    shop.recipes["recipes"]["tamper"] = shop.command([
        "$python", "-c", "open(%r, 'a').write('changed')" % str(log)])
    shop.save_recipes()
    parent = shop.request_job("first-check", "ok")
    shop.run_open()
    if stage == "granted":
        shop.request_job("tamper-evidence", "tamper")
    dependent(shop, parent)
    if stage == "queued":
        waiting = row(shop.run_open(census=[101, 102, 103], expect=3))
        assert waiting["reason"] == "capacity_full"
        log.write_text("changed")
    shop.request_job("independent", "heavy")
    answer = shop.run_open()
    refused = row(answer)
    assert refused["state"] == "refused"
    assert refused["reason"] == (
        "dependency changed after capacity admission: predecessor terminal receipt does not match retained evidence")
    assert row(answer, "independent")["state"] == "completed"
    assert shop.states("next-check") == ["refused"]
    assert not shop.sentinel.exists()
    result = json.loads((shop.workspace.store / "jobs/pilot/next-check/result.json").read_text())
    assert result["steps"] == [] and result["exit_code"] is None
    assert shop.heavy()["used"] == 0
    assert shop.run_open()["rows"] == []
