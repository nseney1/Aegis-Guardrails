"""Small-change execution evidence through the public journal, without model turns."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os

import pytest

from tests.integration.test_hierarchy_lifecycle import Ledger, SOURCE, raw_request
from tests.integration.test_hierarchy_small_change_admission import SmallChange, digest
from tests.integration.test_hierarchy_watch_bridge import Provider
from tools import hierarchy_lifecycle as lifecycle
from tools.hierarchy_watch_bridge import OperatorBridge
from tools.hierarchy_watch_supervisor import Supervisor, initialize


pytestmark = pytest.mark.skipif(os.name != "posix", reason="lifecycle mutation requires POSIX directory fsync")


def admitted(tmp_path):
    change = SmallChange(Ledger(tmp_path))
    change.register()
    change.decide()
    change.admit()
    return change


def reviewer_successor_ledger(tmp_path):
    seed = Ledger(tmp_path, initialize=False)
    actors = copy.deepcopy(seed.policy["actors"])
    actors["reviewer-2"] = {**copy.deepcopy(actors["reviewer-1"]), "generation": 2}
    return Ledger(tmp_path, policy_changes={"actors": actors,
                  "successors": {**seed.policy["successors"], "reviewer-1": "reviewer-2"}})


def succeed(ledger, role):
    checkpoint = ledger.cli("checkpoint")
    ledger.event("succeed", actor=role + "-2", predecessor=role + "-1",
                 checkpoint_sha256=checkpoint["sha256"])


def body(change, kind):
    if kind == "route":
        return {"to": change.value["team"] + "/lane/fix"}
    if kind in {"intent", "start"}:
        return {"intent_id": "attempt-1"}
    terminal = change.row()["terminal"]
    return {"result_sha256": terminal["sha256"] if terminal else "0" * 64,
            "source": SOURCE, "verdict": "accept", "evidence": change.ledger.evidence}


def actor(change, kind):
    return {"route": "router-1", "review": "reviewer-1"}.get(kind, change.ledger.operator)


def event(change, kind, **kwargs):
    return change.ledger.event(kind, actor=actor(change, kind), **body(change, kind),
                               **change.ledger.target(change.value), **kwargs)


def prepare(change, kind):
    """Stop immediately before the operation being tested."""
    if kind in {"start", "review"}:
        event(change, "intent")
    if kind == "review":
        event(change, "start")
        change.ledger.terminal(change.value)


def complete(change, *, expect=0):
    return change.ledger.event("disposition", status="FINAL",
                               resolution={"kind": "complete", "evidence": change.ledger.evidence},
                               **change.ledger.target(change.value), expect=expect)


def test_admitted_intent_needs_no_canonical_approval_or_legacy_admission(tmp_path):
    change = admitted(tmp_path)
    event(change, "intent")
    state = change.ledger.status()
    row = state["requests"][change.value["id"]]
    assert state["decisions"] == [] and row["admission"] is None
    assert row["intent"]["actor"] == "operator-1"
    assert state["consumed"] == {change.value["id"]: 1}


def test_happy_path_completes_with_base_source_and_new_commit_only_in_evidence(tmp_path):
    change = admitted(tmp_path)
    ledger = change.ledger
    before = ledger.status()
    admission = change.row()["small_change"]["admission"]
    assert before["continuation_candidates"] == []
    assert before["small_change_ready"] == [change.value["id"]]
    assert before["continuation_holds"] == {change.value["id"]: "small-change requires the T1 dispatcher"}
    assert before["consumed"] == {}
    event(change, "route")
    assert change.row()["routed"]["to"] == "engine/lane/fix"
    event(change, "intent")
    event(change, "start")
    evidence_path = ledger.tmp / "writer-result.json"
    evidence_path.write_text(json.dumps({"commit": "e" * 40, "tree": "f" * 40}))
    ledger.evidence = [{"path": str(evidence_path), "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest()}]
    ledger.terminal(change.value)
    event(change, "review")
    ledger.event("delivery", evidence=ledger.evidence, **ledger.target(change.value))
    complete(change)
    state = ledger.status()
    row = state["requests"][change.value["id"]]
    assert state["work_complete"] is True and state["obligations"] == []
    assert row["resolution"]["kind"] == "complete"
    assert row["terminal"]["value"]["source"] == row["review"]["source"] == SOURCE
    assert row["small_change"]["admission"] == admission
    assert row["admission"] is None and state["decisions"] == []
    assert state["consumed"] == {change.value["id"]: 1}
    assert state["execution_enabled"] is False
    envelopes = [json.loads(path.read_text())["envelope"] for path in sorted((ledger.path / "events").iterdir())]
    assert [item["event"]["type"] for item in envelopes] == [
        "publish", "small_change_plan", "small_change_decision", "small_change_admit",
        "route", "intent", "start", "terminal", "review", "delivery", "disposition"]
    assert all("orchestrator" not in item["actor"] and "decider" not in item["actor"] for item in envelopes)


@pytest.mark.parametrize("canonical_approval", [False, True])
def test_evidence_only_watch_retains_a_stable_hold_without_dispatch(tmp_path, canonical_approval):
    change = admitted(tmp_path)
    ledger = change.ledger
    if canonical_approval:
        ledger.approve(change.value)
    provider = Provider(ledger)
    bridge = OperatorBridge(ledger.path, provider, ledger.operator, 1, evidence_only=True)
    root = tmp_path / "small-change-watch"
    initialize(root, ledger.path, "small-change-watch", evidence_only=True)
    before = ledger.files()
    for iteration in range(1, 4):
        # Reopen the public supervisor each time to verify the durable hold.
        state = Supervisor(root).step(1, bridge)
        assert state["attempts"] == []
        assert state["history"] == []
        assert state["holds"] == {change.value["id"]: "small-change requires the T1 dispatcher"}
        assert state["iterations"] == iteration
        assert state["work_complete"] is False and state["evidence_only"] is True
        assert provider.effects == 0 and ledger.files() == before
    state = ledger.status()
    assert state["continuation_candidates"] == []
    assert state["small_change_ready"] == [change.value["id"]]


def test_canonical_status_keeps_its_existing_continuation_projection(tmp_path):
    ledger = Ledger(tmp_path)
    value = ledger.ready()
    state = ledger.status()
    assert state["continuation_candidates"] == [value["id"]]
    assert state["continuation_holds"] == {}
    assert "small_change_ready" not in state


@pytest.mark.parametrize("stage", ["registered", "started", "reviewer-rotated", "without-canonical-approval"])
def test_small_change_cannot_enter_the_canonical_provider_contract(tmp_path, stage):
    ledger = reviewer_successor_ledger(tmp_path)
    change = SmallChange(ledger)
    change.register()
    change.decide()
    change.admit()
    if stage != "without-canonical-approval":
        ledger.approve(change.value)
    if stage != "registered":
        event(change, "intent")
        event(change, "start")
    if stage == "reviewer-rotated":
        succeed(ledger, "reviewer")
    state = ledger.status()
    row = change.row()
    decisions = state["decisions"]
    association = {"schema": "aegis.provider-association/v1", **ledger.target(change.value),
                   "intent_id": "attempt-1", "source": SOURCE, "authority": change.value["authority"],
                   "authority_sha256": row["raw"]["sha256"],
                   "decision_sha256": digest(decisions[-1]) if decisions else "0" * 64,
                   "admission_sha256": digest(None), "original_actor": ledger.operator,
                   "original_generation": 1, "original_cap_seconds": 3600,
                   "authority_expires_at": change.value["continuation"]["expires_at"],
                   "provider": "fixture", "endpoint_id": "endpoint-1", "thread_id": "thread-1",
                   "client_id": "client-attempt-1",
                   "deadline": (datetime.now(timezone.utc) + timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    assert row["admission"] is None
    before = ledger.files()
    refused = ledger.event("associate", actor=ledger.operator, association=association,
                            **ledger.target(change.value), expect=2)
    assert refused["error"] == "canonical provider association is unavailable for small-change rows"
    assert ledger.files() == before
    assert ledger.status() == state


@pytest.mark.parametrize("recipient", ["engine/orchestrator", "engine/lane/other", "other/lane/fix", "engine/lane/fix/extra"])
def test_route_cannot_leave_the_approved_lane(tmp_path, recipient):
    change = admitted(tmp_path)
    before = change.ledger.files()
    refused = change.ledger.event("route", actor="router-1", to=recipient,
                                  **change.ledger.target(change.value), expect=2)
    assert refused["error"] == "small-change route must target the approved lane"
    assert change.ledger.files() == before


@pytest.mark.parametrize("kind", ["route", "intent", "start", "review"])
def test_unadmitted_plan_cannot_execute(tmp_path, kind):
    change = SmallChange(Ledger(tmp_path))
    change.register()
    change.decide()
    before = change.ledger.files()
    assert event(change, kind, expect=2)["error"] == "small-change plan lacks admission"
    assert change.ledger.files() == before
    state = change.ledger.status()
    assert state["continuation_candidates"] == []
    assert state["continuation_holds"][change.value["id"]] == "small-change plan lacks admission"


@pytest.mark.parametrize("kind", ["route", "intent", "start", "review"])
def test_plan_denial_vetoes_admitted_execution(tmp_path, kind):
    change = admitted(tmp_path)
    change.decide("deny")
    before = change.ledger.files()
    assert event(change, kind, expect=2)["error"] == "small-change plan lacks approval"
    assert change.ledger.files() == before
    assert change.ledger.status()["continuation_candidates"] == []


@pytest.mark.parametrize("kind", ["route", "intent", "start", "review"])
def test_canonical_denial_vetoes_admitted_execution(tmp_path, kind):
    change = admitted(tmp_path)
    prepare(change, kind)
    ledger = change.ledger
    ledger.event("decision", actor=ledger.root_actor, decision="deny", reason="revoked",
                 **ledger.target(change.value))
    before = ledger.files()
    assert event(change, kind, expect=2)["error"] == "canonical request is denied"
    assert ledger.files() == before
    assert ledger.status()["continuation_candidates"] == []


@pytest.mark.parametrize("kind", ["route", "intent", "start"])
def test_expired_admission_cannot_execute(tmp_path, monkeypatch, kind):
    change = admitted(tmp_path)
    prepare(change, kind)
    ledger = change.ledger
    # Freeze the accrued meter before advancing the clock, isolating authority
    # expiry from the independent cumulative actor-cap refusal.
    ledger.event("meter", actor=ledger.operator, subject=ledger.operator, active_seconds=120, open_since=None)
    envelope = {"id": "expired-operation", "actor": actor(change, kind), "generation": 1,
                "custody": {"cid": ledger.root_actor, "generation": 1},
                "event": {"type": kind, **ledger.target(change.value), **body(change, kind)}}
    before = ledger.files()
    # The OS clock is the only substituted boundary; all durable evidence is real.
    monkeypatch.setattr(lifecycle, "timestamp", lambda: "2099-01-01T00:00:00Z")
    reader = lifecycle.Lifecycle(ledger.path)
    with pytest.raises(ValueError, match="^bounded authority expired$"):
        reader.record(envelope)
    state = reader.status()
    assert state["continuation_candidates"] == []
    if kind in {"route", "intent"}:
        assert state["continuation_holds"][change.value["id"]] == "bounded authority expired"
    assert ledger.files() == before


@pytest.mark.parametrize("participant", ["operator", "reviewer"])
@pytest.mark.parametrize("kind", ["route", "intent", "start"])
def test_succession_fences_the_admitted_plan(tmp_path, participant, kind):
    # Include a real registered Reviewer successor, following the policy contract.
    ledger = reviewer_successor_ledger(tmp_path)
    change = SmallChange(ledger)
    change.register()
    change.decide()
    change.admit()
    prepare(change, kind)
    succeed(ledger, participant)
    operation_actor = participant + "-2" if actor(change, kind) == participant + "-1" else actor(change, kind)
    before = ledger.files()
    assert ledger.event(kind, actor=operation_actor, **body(change, kind), **ledger.target(change.value),
                        expect=2)["error"] == "small-change participant is no longer current"
    assert ledger.files() == before
    assert ledger.status()["continuation_candidates"] == []


@pytest.mark.parametrize("situation", ["expired", "writer-rotated", "expired-and-writer-rotated"])
@pytest.mark.parametrize("outcome", ["passed", "unknown"])
def test_terminal_review_survives_expiry_and_writer_rotation(tmp_path, monkeypatch, situation, outcome):
    change = admitted(tmp_path)
    ledger = change.ledger
    event(change, "intent")
    event(change, "start")
    admission = change.row()["small_change"]["admission"]
    if "expired" in situation:
        monkeypatch.setattr(lifecycle, "timestamp", lambda: "2099-01-01T00:00:00Z")
    reader = lifecycle.Lifecycle(ledger.path)

    def record(kind, cid="coordinator-1", **payload):
        return reader.record({"id": "late-" + kind, "actor": cid, "generation": 1,
                              "custody": {"cid": ledger.root_actor, "generation": 1},
                              "event": {"type": kind, **ledger.target(change.value), **payload}})

    # Terminal evidence may arrive after expiry; it never starts new work.
    result = {"request_sha256": ledger.target(change.value)["request_sha256"], "intent_id": "attempt-1",
              "outcome": outcome, "exit_code": 0 if outcome == "passed" else None,
              "source": SOURCE, "evidence": ledger.evidence}
    record("terminal", ledger.operator, result=raw_request(result))
    if "rotated" in situation:
        # Succession binds the exact checkpoint including that terminal.
        policy, state = reader.load()
        reader.record({"id": "late-succeed", "actor": "operator-2", "generation": 2,
                       "custody": {"cid": ledger.root_actor, "generation": 1},
                       "event": {"type": "succeed", "predecessor": "operator-1",
                                 "checkpoint_sha256": lifecycle.checkpoint(policy, state)["sha256"]}})
    record("review", "reviewer-1", **body(change, "review"))
    record("delivery", evidence=ledger.evidence)
    before = ledger.files()
    resolution = {"kind": "complete", "evidence": ledger.evidence}
    if outcome == "unknown":
        with pytest.raises(ValueError, match="^unknown effect prevents closure$"):
            record("disposition", status="FINAL", resolution=resolution)
        assert ledger.files() == before
    else:
        record("disposition", status="FINAL", resolution=resolution)
    state = reader.status()
    row = state["requests"][change.value["id"]]
    assert row["intent"]["actor"] == "operator-1" and row["review"]["actor"] == "reviewer-1"
    assert row["small_change"]["admission"] == admission
    assert row["review"]["source"] == row["terminal"]["value"]["source"] == SOURCE
    assert state["consumed"] == {change.value["id"]: 1}
    assert state["work_complete"] is (outcome == "passed")
    if outcome == "unknown":
        assert state["obligations"][0]["state"] == "unknown_effect" and row["resolution"] is None


@pytest.mark.parametrize("reviewer,generation,error", [
    ("reviewer-2", 2, "small-change participant is no longer current"),
    ("reviewer-1", 1, "actor generation is fenced"),
    ("reviewer-2", 1, "stale actor generation"),
])
def test_terminal_review_still_requires_the_current_plan_reviewer(tmp_path, reviewer, generation, error):
    change = SmallChange(reviewer_successor_ledger(tmp_path))
    change.register()
    change.decide()
    change.admit()
    prepare(change, "review")
    succeed(change.ledger, "reviewer")
    before = change.ledger.files()
    assert change.ledger.event("review", actor=reviewer, generation=generation, **body(change, "review"),
                               **change.ledger.target(change.value), expect=2)["error"] == error
    assert change.ledger.files() == before


def test_small_change_review_requires_recorded_terminal_evidence(tmp_path):
    change = admitted(tmp_path)
    event(change, "intent")
    event(change, "start")
    before = change.ledger.files()
    assert event(change, "review", expect=2)["error"] == "review result sha256 mismatch"
    assert change.ledger.files() == before


def test_intent_before_expiry_cannot_become_terminal_after_expiry_without_start(tmp_path, monkeypatch):
    change = admitted(tmp_path)
    ledger = change.ledger
    reader = lifecycle.Lifecycle(ledger.path)

    def record(kind, cid="coordinator-1", **payload):
        return reader.record({"id": "unstarted-" + kind, "actor": cid, "generation": 1,
                              "custody": {"cid": ledger.root_actor, "generation": 1},
                              "event": {"type": kind, **ledger.target(change.value), **payload}})

    monkeypatch.setattr(lifecycle, "timestamp", lambda: "2098-12-31T23:59:59Z")
    record("intent", ledger.operator, intent_id="attempt-1")
    before = ledger.files()
    monkeypatch.setattr(lifecycle, "timestamp", lambda: "2099-01-01T00:00:01Z")
    result = {"request_sha256": ledger.target(change.value)["request_sha256"], "intent_id": "attempt-1",
              "outcome": "passed", "exit_code": 0, "source": SOURCE, "evidence": ledger.evidence}
    with pytest.raises(ValueError, match="^small-change evidence requires a recorded matching start$"):
        record("terminal", ledger.operator, result=raw_request(result))
    with pytest.raises(ValueError, match="^small-change evidence requires a recorded matching start$"):
        record("review", "reviewer-1", **body(change, "review"))
    with pytest.raises(ValueError, match="^delivery requires independent acceptance$"):
        record("delivery", evidence=ledger.evidence)
    with pytest.raises(ValueError, match="^unknown effect prevents closure$"):
        record("disposition", status="FINAL", resolution={"kind": "complete", "evidence": ledger.evidence})
    assert ledger.files() == before
    state = reader.status()
    row = state["requests"][change.value["id"]]
    assert row["start"] is row["terminal"] is row["review"] is row["resolution"] is None
    assert state["work_complete"] is False and state["obligations"][0]["state"] == "unknown_effect"
    assert state["consumed"] == {change.value["id"]: 1}
    assert state["continuation_candidates"] == state["small_change_ready"] == []


@pytest.mark.parametrize("started", [False, True])
def test_writer_successor_cannot_publish_terminal_for_the_original_intent(tmp_path, started):
    change = admitted(tmp_path)
    ledger = change.ledger
    event(change, "intent")
    if started:
        event(change, "start")
    succeed(ledger, "operator")
    ledger.operator = "operator-2"
    before = ledger.files()
    error = ("small-change terminal requires starting writer operator-1 generation 1" if started
             else "small-change evidence requires a recorded matching start")
    assert ledger.terminal(change.value, expect=2)["error"] == error
    review_error = "review result sha256 mismatch" if started else "small-change evidence requires a recorded matching start"
    assert event(change, "review", expect=2)["error"] == review_error
    assert ledger.event("delivery", evidence=ledger.evidence, **ledger.target(change.value),
                        expect=2)["error"] == "delivery requires independent acceptance"
    assert complete(change, expect=2)["error"] == "unknown effect prevents closure"
    assert ledger.files() == before
    state = ledger.status()
    row = state["requests"][change.value["id"]]
    assert row["terminal"] is row["review"] is row["resolution"] is None
    assert state["work_complete"] is False and state["obligations"][0]["state"] == "unknown_effect"
    assert state["consumed"] == {change.value["id"]: 1}
    assert state["continuation_candidates"] == state["small_change_ready"] == []
    assert state["continuation_holds"][change.value["id"]] == (
        "small-change interrupted writer operator-1 generation 1; T1 dispatcher resume required")


@pytest.mark.parametrize("started", [False, True])
def test_interrupted_writer_hold_is_visible_before_a_successor_attempts_terminal(tmp_path, started):
    change = admitted(tmp_path)
    ledger = change.ledger
    event(change, "intent")
    if started:
        event(change, "start")
    succeed(ledger, "operator")
    before = ledger.files()
    state = ledger.status()
    assert state["continuation_holds"].get(change.value["id"]) == (
        "small-change interrupted writer operator-1 generation 1; T1 dispatcher resume required")
    assert state["continuation_candidates"] == state["small_change_ready"] == []
    assert state["obligations"][0]["state"] == "unknown_effect" and state["work_complete"] is False
    assert ledger.files() == before


def test_small_change_review_requires_the_start_even_before_terminal(tmp_path):
    change = admitted(tmp_path)
    event(change, "intent")
    before = change.ledger.files()
    assert event(change, "review", expect=2)["error"] == "small-change evidence requires a recorded matching start"
    assert change.ledger.files() == before


def test_small_change_terminal_requires_the_starting_writers_generation(tmp_path):
    change = admitted(tmp_path)
    event(change, "intent")
    event(change, "start")
    before = change.ledger.files()
    assert change.ledger.terminal(change.value, generation=2, expect=2)["error"] == "stale actor generation"
    assert change.ledger.files() == before


@pytest.mark.parametrize("kind", ["intent", "start"])
def test_a_second_intent_or_start_cannot_spend_another_start(tmp_path, kind):
    change = admitted(tmp_path)
    event(change, "intent")
    if kind == "start":
        event(change, "start")
    before = change.ledger.files()
    refused = (change.ledger.intent(change.value, intent_id="attempt-2", expect=2) if kind == "intent"
               else event(change, "start", expect=2))
    assert refused["error"] == ("request already has an intent; settle its unknown effect" if kind == "intent"
                                else "start requires its original current operator and an unresolved unstarted intent")
    assert change.ledger.files() == before
    assert change.ledger.status()["consumed"] == {change.value["id"]: 1}


@pytest.mark.parametrize("kind", ["route", "intent", "start", "terminal", "review", "delivery", "disposition"])
def test_exact_event_replay_recovers_receipt_and_changed_bytes_refuse(tmp_path, kind):
    change = admitted(tmp_path)
    ledger = change.ledger
    actions = [lambda: event(change, "route", identifier="stable-route"),
               lambda: event(change, "intent", identifier="stable-intent"),
               lambda: event(change, "start", identifier="stable-start"),
               lambda: ledger.terminal(change.value, identifier="stable-terminal"),
               lambda: event(change, "review", identifier="stable-review"),
               lambda: ledger.event("delivery", evidence=ledger.evidence, identifier="stable-delivery",
                                    **ledger.target(change.value)),
               lambda: ledger.event("disposition", status="FINAL", identifier="stable-disposition",
                                    resolution={"kind": "complete", "evidence": ledger.evidence},
                                    **ledger.target(change.value))]
    kinds = ["route", "intent", "start", "terminal", "review", "delivery", "disposition"]
    for step, action in zip(kinds, actions):
        receipt = action()
        if step == kind:
            original = json.loads((ledger.tmp / "event.json").read_text())
            break
    # Recovery still works after later journal entries and closure.
    for action in actions[kinds.index(kind) + 1:]:
        action()
    before = ledger.files()
    path = ledger.tmp / "replay.json"
    path.write_text(json.dumps(original))
    assert ledger.cli("record", "--event", str(path), "--evidence-only") == receipt
    changed = copy.deepcopy(original)
    changed["event"]["request_sha256"] = "0" * 64
    path.write_text(json.dumps(changed))
    assert ledger.cli("record", "--event", str(path), "--evidence-only", expect=2)["error"] == "event id conflicts with different bytes"
    assert ledger.files() == before
    assert ledger.status()["consumed"] == {change.value["id"]: 1}


@pytest.mark.parametrize("kind,unregistered,error", [
    ("intent", "coordinator-1", "role coordinator cannot record intent"),
    ("intent", "operator-2", "actor generation is fenced"),
    ("start", "coordinator-1", "role coordinator cannot record start"),
    ("start", "operator-2", "actor generation is fenced"),
    ("review", "coordinator-1", "role coordinator cannot record review"),
    ("review", "operator-1", "role operator cannot record review"),
])
def test_non_writer_and_non_reviewer_events_refuse(tmp_path, kind, unregistered, error):
    change = admitted(tmp_path)
    prepare(change, kind)
    before = change.ledger.files()
    assert change.ledger.event(kind, actor=unregistered, **body(change, kind), **change.ledger.target(change.value),
                               expect=2)["error"] == error
    assert change.ledger.files() == before


def test_unknown_terminal_blocks_closure_and_retains_accounting_and_admission(tmp_path):
    change = admitted(tmp_path)
    ledger = change.ledger
    event(change, "intent")
    event(change, "start")
    ledger.terminal(change.value, outcome="unknown")
    event(change, "review")
    ledger.event("delivery", evidence=ledger.evidence, **ledger.target(change.value))
    before = ledger.files()
    state = ledger.status()
    assert complete(change, expect=2)["error"] == "unknown effect prevents closure"
    assert ledger.files() == before
    after = ledger.status()
    assert after["work_complete"] is False
    assert after["obligations"][0]["state"] == "unknown_effect"
    for key in ("consumed", "meters", "requests"):
        assert after[key] == state[key]
    assert after["consumed"] == {change.value["id"]: 1}
    assert after["continuation_candidates"] == []
    assert change.row()["small_change"]["admission"] is not None
    assert change.row()["resolution"] is None
    # Reconciliation adds exact terminal evidence without replaying the operation.
    ledger.terminal(change.value)
    assert change.row()["review"] is change.row()["delivery"] is None
    ledger.accepted_delivery(change.value)
    complete(change)
    assert ledger.status()["work_complete"] is True
    assert ledger.status()["consumed"] == {change.value["id"]: 1}


@pytest.mark.parametrize("kind", ["terminal", "review"])
def test_execution_cannot_replace_the_requests_base_source(tmp_path, kind):
    change = admitted(tmp_path)
    event(change, "intent")
    event(change, "start")
    ledger = change.ledger
    if kind == "review":
        ledger.terminal(change.value)
    before = ledger.files()
    if kind == "terminal":
        result = {"request_sha256": ledger.target(change.value)["request_sha256"], "intent_id": "attempt-1",
                  "outcome": "passed", "exit_code": 0, "source": {**SOURCE, "commit": "e" * 40},
                  "evidence": ledger.evidence}
        refused = ledger.event("terminal", actor=ledger.operator, result=raw_request(result),
                                **ledger.target(change.value), expect=2)
    else:
        review = body(change, "review")
        review["source"] = {**SOURCE, "commit": "e" * 40}
        refused = ledger.event("review", actor="reviewer-1", **review, **ledger.target(change.value), expect=2)
    assert refused["error"] == kind + " source mismatch"
    assert ledger.files() == before
