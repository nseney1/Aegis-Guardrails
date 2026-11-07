"""Public pre-dispatch contracts; configured identities grant no native authority."""
import copy
import hashlib
import json
import os

import pytest

from tests.integration.test_hierarchy_lifecycle import Ledger, SOURCE, raw_request, request
from tests.integration.test_hierarchy_small_change_reader import proposal
from tests.integration.test_hierarchy_router import Loop, deliver_without_recording


pytestmark = pytest.mark.skipif(os.name != "posix", reason="lifecycle mutation requires POSIX directory fsync")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


class SmallChange:
    def __init__(self, ledger, value=None):
        self.ledger = ledger
        self.value = value or request()
        self.plan = proposal()
        self.plan["request"] = raw_request(self.value)
        self.plan["plan"].update(request_sha256=self.plan["request"]["sha256"],
                                  writing_lanes=[{"lane": "fix", "writer": "operator-1"}])
        self.participants = {role: {"cid": cid, "generation": 1}
                             for role, cid in (("writer", "operator-1"), ("reviewer", "reviewer-1"))}
        ledger.publish(self.value)

    def register(self, **kwargs):
        return self.ledger.event("small_change_plan", proposal=raw_request(self.plan), participants=self.participants,
                                 **self.ledger.target(self.value), **kwargs)

    def decide(self, decision="approve", **kwargs):
        return self.ledger.event("small_change_decision", actor=self.ledger.root_actor,
                                 plan_sha256=raw_request(self.plan)["sha256"], decision=decision, reason="fixture decision",
                                 **self.ledger.target(self.value), **kwargs)

    def row(self):
        return self.ledger.status()["requests"][self.value["id"]]

    def admission(self):
        return {"plan_sha256": raw_request(self.plan)["sha256"],
                "decision_sha256": digest(self.row()["small_change"]["decisions"][-1]),
                "source": SOURCE, "participants": self.participants,
                "checks": [{"check": "focused-tests", "recipe": "focused", "recipes_sha256": "d" * 64,
                            "evidence": self.ledger.evidence}],
                "gates": {name: self.ledger.evidence for name in
                          ("source", "capability", "lease", "capacity", "observer", "job", "reviewer")}}

    def admit(self, body=None, **kwargs):
        return self.ledger.event("small_change_admit", actor=self.ledger.operator,
                                 **(self.admission() if body is None else body),
                                 **self.ledger.target(self.value), **kwargs)


def test_plan_approval_and_admission_are_separate_and_never_enable_execution(tmp_path):
    ledger = Ledger(tmp_path)
    change = SmallChange(ledger)
    change.register()
    ledger.approve(change.value)
    before = ledger.files()
    assert change.admit({"plan_sha256": raw_request(change.plan)["sha256"], "decision_sha256": "0" * 64,
                         "source": SOURCE, "participants": change.participants, "checks": [], "gates": {}},
                        expect=2)["error"] == "small-change plan lacks approval"
    assert ledger.files() == before
    change.decide()
    state = ledger.status()
    assert state["consumed"] == {} and change.row()["admission"] is None
    assert change.row()["small_change"]["admission"] is None
    change.admit()
    state = ledger.status()
    row = change.row()
    assert row["small_change"]["admission"]["checks"][0]["recipe"] == "focused"
    assert row["intent"] is row["admission"] is None
    assert state["execution_enabled"] is False and state["consumed"] == {}
    assert state["continuation_holds"][change.value["id"]] == "small-change dispatch is not activated"
    before = ledger.files()
    for action in (ledger.admit, ledger.intent):
        assert action(change.value, expect=2)["error"] == "small-change dispatch is not activated"
    assert ledger.files() == before


@pytest.mark.parametrize("field,value,reason", [
    ("shared_interface_change", True, "shared_interface_change"), ("migration", True, "migration"),
    ("governance_change", True, "governance_change"), ("budget_expansion", True, "budget_expansion"),
    ("scope_certain", False, "uncertain_scope"), ("checks", [], "checks_missing"),
    ("writing_lanes", [{"lane": "a", "writer": "operator-1"}, {"lane": "b", "writer": "operator-2"}],
     "writing_lane_count"), ("reviewer", "operator-1", "writer_reviewer_conflict"),
    ("path_scopes", [["/fixture/other"]], "path_scope_mismatch"),
    ("projects", ["engine", "other"], "project_count"),
])
def test_escalation_never_registers_a_small_change(tmp_path, field, value, reason):
    change = SmallChange(Ledger(tmp_path))
    change.plan["plan"][field] = value
    before = change.ledger.files()
    assert change.register(expect=2)["error"] == "small-change requires full planning: " + reason
    assert change.ledger.files() == before


@pytest.mark.parametrize("part,field,value,error", [
    ("writer", "cid", "coordinator-1", "small-change writer mismatch"),
    ("reviewer", "cid", "root-1", "small-change reviewer mismatch"),
    ("writer", "generation", 2, "small-change participant generation mismatch"),
    ("reviewer", "generation", True, "invalid small-change participant generation"),
])
def test_participants_must_match_current_configured_roles(tmp_path, part, field, value, error):
    change = SmallChange(Ledger(tmp_path))
    change.participants[part][field] = value
    before = change.ledger.files()
    assert change.register(expect=2)["error"] == error
    assert change.ledger.files() == before


@pytest.mark.parametrize("field", ["checks", "reviewer", "path_scopes", "source", "raw"])
def test_changed_plan_cannot_reuse_approval(tmp_path, field):
    change = SmallChange(Ledger(tmp_path))
    change.register()
    change.decide()
    before = change.ledger.files()
    if field == "source":
        value = copy.deepcopy(change.value)
        value["source"]["tree"] = "e" * 40
        change.plan["request"] = raw_request(value)
        change.plan["plan"]["request_sha256"] = change.plan["request"]["sha256"]
    elif field == "raw":
        # Equivalent JSON with different original bytes is a different plan.
        change.plan["plan"]["checks"].reverse()
        raw = raw_request(change.plan)
        raw["raw"] += " "
        raw["sha256"] = hashlib.sha256(raw["raw"].encode()).hexdigest()
        assert change.ledger.event("small_change_plan", proposal=raw, participants=change.participants,
                                    **change.ledger.target(change.value), expect=2)["error"] == "small-change plan already registered"
        assert change.ledger.files() == before
        return
    else:
        change.plan["plan"][field] = {"checks": ["other"], "reviewer": "reviewer-2",
                                      "path_scopes": [["/fixture/other"]]}[field]
    assert change.decide(expect=2)["error"] == "small-change plan sha256 mismatch"
    assert change.ledger.files() == before


@pytest.mark.parametrize("field,value,error", [
    ("plan_sha256", "0" * 64, "small-change plan sha256 mismatch"),
    ("decision_sha256", "0" * 64, "small-change decision sha256 mismatch"),
    ("source", {**SOURCE, "tree": "e" * 40}, "small-change admission source mismatch"),
    ("checks", [], "small-change checks mismatch"),
    ("checks", "bad", "invalid small-change checks"),
    ("participants", {}, "small-change admission participants mismatch"),
    ("gates", {}, "missing fields: capability, capacity, job, lease, observer, reviewer, source"),
])
def test_admission_refuses_mismatched_or_malformed_evidence_atomically(tmp_path, field, value, error):
    change = SmallChange(Ledger(tmp_path))
    change.register()
    change.decide()
    body = change.admission()
    body[field] = value
    before = change.ledger.files()
    assert change.admit(body, expect=2)["error"] == error
    assert change.ledger.files() == before


def test_deny_preserves_admission_but_prevents_new_admission(tmp_path):
    change = SmallChange(Ledger(tmp_path))
    change.register()
    change.decide()
    change.admit()
    admission = change.row()["small_change"]["admission"]
    change.decide("deny")
    before = change.ledger.files()
    assert change.admit(expect=2)["error"] == "small-change plan lacks approval"
    assert change.row()["small_change"]["admission"] == admission
    assert change.ledger.files() == before


@pytest.mark.parametrize("stage", ["approval", "admission"])
def test_canonical_denial_vetoes_plan_approval_and_admission(tmp_path, stage):
    ledger = Ledger(tmp_path)
    change = SmallChange(ledger)
    change.register()
    if stage == "admission":
        change.decide()
    ledger.event("decision", actor=ledger.root_actor, decision="deny", reason="owner revoked request",
                 **ledger.target(change.value))
    before = ledger.files()
    action = change.decide if stage == "approval" else change.admit
    assert action(expect=2)["error"] == "canonical request is denied"
    assert ledger.files() == before


def test_duplicate_and_lost_replies_recover_exact_receipts_without_accounting_changes(tmp_path):
    change = SmallChange(Ledger(tmp_path))
    for action in (change.register, change.decide, change.admit):
        receipt = action(identifier="stable-" + action.__name__)
        before = change.ledger.files()
        assert action(identifier="stable-" + action.__name__) == receipt
        assert change.ledger.files() == before
    before = change.ledger.files()
    assert change.decide("deny", identifier="stable-decide", expect=2)["error"] == "event id conflicts with different bytes"
    assert change.ledger.files() == before
    state = change.ledger.status()
    assert state["consumed"] == {} and state["meters"]["operator-1"]["active_seconds"] == 0


def test_successor_cannot_admit_old_participant_bindings(tmp_path):
    ledger = Ledger(tmp_path)
    change = SmallChange(ledger)
    change.register()
    change.decide()
    checkpoint = ledger.cli("checkpoint")
    ledger.event("succeed", actor="operator-2", predecessor="operator-1", checkpoint_sha256=checkpoint["sha256"])
    ledger.operator = "operator-2"
    before = ledger.files()
    assert change.admit(expect=2)["error"] == "small-change participant is no longer current"
    assert ledger.files() == before


def test_unknown_effect_cannot_be_replanned_or_released(tmp_path):
    ledger = Ledger(tmp_path)
    value = ledger.ready()
    ledger.intent(value)
    ledger.event("start", actor=ledger.operator, intent_id="attempt-1", **ledger.target(value))
    ledger.terminal(value, outcome="unknown")
    change = SmallChange.__new__(SmallChange)
    change.ledger, change.value = ledger, value
    change.plan = proposal()
    change.participants = {}
    before = ledger.files()
    state = ledger.status()
    assert change.register(expect=2)["error"] == "small-change plan requires an untouched request"
    assert ledger.files() == before and ledger.status() == state
    assert state["obligations"][0]["state"] == "unknown_effect"


def test_registered_plan_is_held_before_routing_and_cannot_bypass_via_route_event(tmp_path):
    loop = Loop(tmp_path)
    loop.team("engine")
    change = SmallChange(loop.ledger)
    change.register()
    loop.ledger.approve(change.value)
    change.decide()
    change.admit()
    before = loop.ledger.files()
    assert loop.status()[change.value["id"]]["reason"] == "small_change_dispatch_unavailable"
    assert loop.route()["routed"] == []
    assert loop.inbox("engine") == []
    assert loop.ledger.event("route", actor="router-1", to="engine/orchestrator",
                             **loop.ledger.target(change.value), expect=2)["error"] == "small-change dispatch is not activated"
    assert loop.ledger.files() == before


def test_lost_legacy_delivery_is_visible_and_held_without_duplicate_after_plan_registration(tmp_path):
    loop = Loop(tmp_path)
    loop.team("engine")
    change = SmallChange(loop.ledger)
    loop.ledger.approve(change.value)
    published = deliver_without_recording(loop, change.value)
    change.register()
    before = loop.ledger.files()
    # The existing delivery cannot be recalled. Keep it visible and held; never send it again.
    assert loop.route()["routed"] == []
    assert [m["message"]["message_id"] for m in loop.inbox("engine")] == [published]
    assert loop.status()[change.value["id"]]["state"] == "delivered_unrecorded"
    assert loop.ledger.files() == before


@pytest.mark.parametrize("kind,actor,role", [("small_change_plan", "root-1", "root"),
                                           ("small_change_decision", "operator-1", "operator"),
                                           ("small_change_admit", "root-1", "root"),
                                           ("small_change_admit", "router-1", "router")])
def test_role_boundaries_refuse_before_payload_validation(tmp_path, kind, actor, role):
    ledger = Ledger(tmp_path)
    before = ledger.files()
    assert ledger.event(kind, actor=actor, expect=2)["error"] == "role %s cannot record %s" % (role, kind)
    assert ledger.files() == before


@pytest.mark.parametrize("mutation,error", [
    ("raw_hash", "raw request sha256 mismatch"),
    ("request_bytes", "small-change request bytes mismatch"),
    ("unknown", "unexpected fields: unknown"),
    ("missing", "missing fields: reviewer"),
    ("nonboolean", "invalid plan migration"),
])
def test_malformed_plan_registration_is_atomic(tmp_path, mutation, error):
    change = SmallChange(Ledger(tmp_path))
    if mutation == "raw_hash":
        change.plan["request"]["raw"] += " "
    elif mutation == "request_bytes":
        other = {**change.value, "owner": "other-owner"}
        change.plan["request"] = raw_request(other)
        change.plan["plan"]["request_sha256"] = change.plan["request"]["sha256"]
    elif mutation == "unknown":
        change.plan["plan"]["unknown"] = True
    elif mutation == "missing":
        del change.plan["plan"]["reviewer"]
    else:
        change.plan["plan"]["migration"] = 1
    before = change.ledger.files()
    assert change.register(expect=2)["error"] == error
    assert change.ledger.files() == before


def test_expired_plan_cannot_receive_approval(tmp_path):
    change = SmallChange(Ledger(tmp_path), request(continuation={"members": [], "max_starts": 1,
                                                                "expires_at": "2000-01-01T00:00:00Z"}))
    change.register()
    before = change.ledger.files()
    assert change.decide(expect=2)["error"] == "bounded authority expired"
    assert change.ledger.files() == before


def test_admission_at_expiry_refuses_but_retains_approval_receipt(tmp_path, monkeypatch):
    from tools import hierarchy_lifecycle
    change = SmallChange(Ledger(tmp_path))
    change.register()
    receipt = change.decide(identifier="retained-plan-approval")
    ledger = change.ledger
    body = change.admission()
    envelope = {"id": "admit-at-expiry", "actor": ledger.operator, "generation": 1,
                "custody": {"cid": ledger.root_actor, "generation": 1},
                "event": {"type": "small_change_admit", **ledger.target(change.value), **body}}
    monkeypatch.setattr(hierarchy_lifecycle, "timestamp", lambda: "2099-01-01T00:00:00Z")
    before = ledger.files()
    with pytest.raises(ValueError, match="^bounded authority expired$"):
        hierarchy_lifecycle.Lifecycle(ledger.path).record(envelope)
    assert ledger.files() == before
    assert ledger.status()["receipts"]["retained-plan-approval"] == receipt


@pytest.mark.parametrize("change_request", [{"continuation": {"members": [], "max_starts": 2,
                                                               "expires_at": "2099-01-01T00:00:00Z"}},
                                          {"authority": "parent"}, {"operation": "delegate-merge"}])
def test_small_change_cannot_extend_continuing_authority(tmp_path, change_request):
    change = SmallChange(Ledger(tmp_path), request(**change_request))
    before = change.ledger.files()
    assert change.register(expect=2)["error"] == "small-change requires a single bounded request"
    assert change.ledger.files() == before


@pytest.mark.parametrize("mutation,error", [("duplicate", "small-change checks mismatch"),
                                           ("unknown", "small-change checks mismatch"),
                                           ("malformed_hash", "invalid small-change recipes sha256"),
                                           ("extra_field", "unexpected fields: argv")])
def test_check_bindings_are_closed_and_exact(tmp_path, mutation, error):
    change = SmallChange(Ledger(tmp_path))
    change.register()
    change.decide()
    body = change.admission()
    if mutation == "duplicate":
        body["checks"] *= 2
    elif mutation == "unknown":
        body["checks"][0]["check"] = "other"
    elif mutation == "malformed_hash":
        body["checks"][0]["recipes_sha256"] = "bad"
    else:
        body["checks"][0]["argv"] = ["sh"]
    before = change.ledger.files()
    assert change.admit(body, expect=2)["error"] == error
    assert change.ledger.files() == before
