"""Public evidence-ledger behavior. Fixture identities never establish native authority."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


pytestmark = pytest.mark.skipif(os.name != "posix", reason="durable lifecycle mutation requires POSIX directory fsync")
ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hierarchy_lifecycle.py"
SOURCE = {"commit": "a" * 40, "tree": "b" * 40, "dirty_sha256": "c" * 64}


def raw_request(request):
    raw = json.dumps(request, sort_keys=True) + "\n"
    return {"raw": raw, "sha256": hashlib.sha256(raw.encode()).hexdigest()}


def request(identifier="engine-partial", **changes):
    value = {"schema": "aegis.lifecycle-request/v1", "id": identifier, "version": 1,
             "team": "engine", "owner": "engine/coordinator", "next_decision": "review retained failure evidence",
             "phase": "validation", "operation": "targeted-tests", "source": SOURCE,
             "paths": ["/fixture/engine/tests"], "prerequisites": [], "authority": identifier,
             "continuation": {"members": [], "max_starts": 1, "expires_at": "2099-01-01T00:00:00Z"}}
    value.update(changes)
    return value


class Ledger:
    def __init__(self, tmp_path, *, initialize=True, policy_changes=None):
        self.tmp = tmp_path
        self.path = tmp_path / "lifecycle"
        self.counter = 0
        self.root_actor = "root-1"
        self.operator = "operator-1"
        self.generation = 1
        self.evidence_path = tmp_path / "retained-failure.json"
        self.evidence_path.write_text('{"fixture": "retained failure"}\n')
        self.evidence = [{"path": str(self.evidence_path),
                          "sha256": hashlib.sha256(self.evidence_path.read_bytes()).hexdigest()}]
        actors = {}
        for role in ("root", "router", "coordinator", "operator", "reviewer"):
            actors[role + "-1"] = {"role": role, "generation": 1, "cap_seconds": 3600,
                                  "profile": {"model": "fixture-model", "effort": "medium" if role == "router" else "max",
                                              "tier": "ultrafast", "filesystem": "read-only" if role == "root" else "workspace-write",
                                              "tools": ["read", "decide", "attest"] if role == "root" else []}}
        actors["operator-2"] = {**copy.deepcopy(actors["operator-1"]), "generation": 2}
        actors["root-2"] = {**copy.deepcopy(actors["root-1"]), "generation": 2}
        self.policy = {"schema": "aegis.lifecycle-policy/v1", "source": SOURCE, "authority": self.evidence,
                       "actors": actors, "current": {role: role + "-1" for role in
                                                       ("root", "router", "coordinator", "operator", "reviewer")},
                       "successors": {"operator-1": "operator-2", "root-1": "root-2"}}
        self.policy.update(policy_changes or {})
        self.policy_path = tmp_path / "policy.json"
        self.policy_path.write_text(json.dumps(self.policy))
        if initialize:
            self.cli("init", "--policy", str(self.policy_path), "--evidence-only")

    def cli(self, *args, expect=0):
        proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "--root", str(self.path), *args],
                              capture_output=True, text=True, timeout=15,
                              env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        assert proc.returncode == expect, proc.stdout + proc.stderr
        assert not proc.stderr, proc.stderr
        return json.loads(proc.stdout)

    def event(self, kind, *, actor="coordinator-1", identifier=None, generation=None, custody=None, expect=0, **body):
        self.counter += 1
        event = {"id": identifier or "event-%d" % self.counter, "actor": actor,
                 "generation": generation or (2 if actor.endswith("-2") else 1),
                 "custody": custody or {"cid": self.root_actor, "generation": 2 if self.root_actor.endswith("-2") else 1},
                 "event": {"type": kind, **body}}
        path = self.tmp / "event.json"
        path.write_text(json.dumps(event))
        return self.cli("record", "--event", str(path), "--evidence-only", expect=expect)

    def publish(self, value=None, **kwargs):
        value = value or request()
        return self.event("publish", request=raw_request(value), **kwargs)

    def target(self, value):
        return {"request_id": value["id"], "request_sha256": raw_request(value)["sha256"]}

    def approve(self, value, **kwargs):
        return self.event("decision", actor=self.root_actor, decision="approve", reason="bounded fixture approval",
                          **self.target(value), **kwargs)

    def admit(self, value, **kwargs):
        return self.event("admit", actor=self.operator, source=SOURCE,
                          gates={name: self.evidence for name in ("source", "capability", "lease", "capacity", "observer", "job")},
                          **self.target(value), **kwargs)

    def intent(self, value, intent_id="attempt-1", **kwargs):
        return self.event("intent", actor=self.operator, intent_id=intent_id, **self.target(value), **kwargs)

    def terminal(self, value, outcome="passed", **kwargs):
        result = {"request_sha256": self.target(value)["request_sha256"], "intent_id": "attempt-1",
                  "outcome": outcome, "exit_code": 0 if outcome == "passed" else 1,
                  "source": SOURCE, "evidence": self.evidence}
        return self.event("terminal", actor=self.operator, result=raw_request(result), **self.target(value), **kwargs)

    def accepted_delivery(self, value):
        result_hash = self.status()["requests"][value["id"]]["terminal"]["sha256"]
        self.event("review", actor="reviewer-1", result_sha256=result_hash, source=SOURCE,
                   verdict="accept", evidence=self.evidence, **self.target(value))
        self.event("delivery", evidence=self.evidence, **self.target(value))

    def ready(self, value=None):
        value = value or request()
        self.publish(value)
        self.approve(value)
        self.admit(value)
        return value

    def status(self):
        return self.cli("status")

    def files(self):
        return {str(p.relative_to(self.path)): p.read_bytes() for p in self.path.rglob("*") if p.is_file()}


@pytest.fixture
def ledger(tmp_path):
    return Ledger(tmp_path)


def test_fixture_mutations_are_explicit_and_never_enable_native_execution(tmp_path):
    ledger = Ledger(tmp_path, initialize=False)
    refused = ledger.cli("init", "--policy", str(ledger.policy_path), expect=2)
    assert refused["error"] == "mutation requires --evidence-only; native adapter is unqualified"
    assert not ledger.path.exists()
    ledger.cli("init", "--policy", str(ledger.policy_path), "--evidence-only")
    status = ledger.status()
    assert status["execution_enabled"] is False and status["native_enforcement"] == "unqualified"
    assert status["work_complete"] is False and status["state"] == "untracked"


@pytest.mark.parametrize("kind", ["FINAL", "HOLD"])
def test_engine_partial_cannot_disappear_behind_bare_final_or_hold(ledger, kind):
    value = request()
    ledger.publish(value)
    before = ledger.files()
    refused = ledger.event("disposition", status=kind, **ledger.target(value), expect=2)
    assert refused["error"] == "missing fields: resolution"
    assert ledger.files() == before
    assert ledger.status()["obligations"][0]["request_id"] == "engine-partial"
    assert ledger.status()["work_complete"] is False


def test_owned_blocker_preserves_engine_failures_with_no_open_jobs(ledger):
    value = request()
    ledger.publish(value)
    ledger.event("disposition", status="HOLD", resolution={"kind": "blocked", "owner": "engine/coordinator",
                 "next_decision": "authorize the 13 missing cases and P1 fixes", "condition": "P1s fixed and controls reviewed",
                 "evidence": ledger.evidence}, **ledger.target(value))
    row = ledger.status()["obligations"][0]
    assert row["state"] == "blocked" and row["owner"] == "engine/coordinator"
    assert row["next_decision"] == "authorize the 13 missing cases and P1 fixes"
    assert ledger.status()["work_complete"] is False


def test_final_atomically_publishes_the_exact_next_request_with_an_accountable_owner(ledger):
    first, next_value = request(), request("engine-controls", owner="engine/recovery", next_decision="review P1 fixes")
    ledger.publish(first)
    ledger.event("disposition", status="FINAL", resolution={"kind": "next", "request": raw_request(next_value),
                 "evidence": ledger.evidence}, **ledger.target(first))
    state = ledger.status()
    assert list(state["requests"]) == ["engine-controls", "engine-partial"]
    assert state["requests"][first["id"]]["resolution"]["request_sha256"] == raw_request(next_value)["sha256"]
    assert [(r["request_id"], r["owner"], r["next_decision"]) for r in state["obligations"]] == [
        ("engine-controls", "engine/recovery", "review P1 fixes")]


@pytest.mark.parametrize("field,value,error", [("owner", "", "invalid owner"),
                                             ("next_decision", "", "invalid next_decision"),
                                             ("sha256", "0" * 64, "raw request sha256 mismatch")])
def test_invalid_next_request_refuses_atomically(ledger, field, value, error):
    first, following = request(), request("engine-controls")
    ledger.publish(first)
    if field == "sha256":
        following_raw = {**raw_request(following), "sha256": value}
    else:
        following[field] = value
        following_raw = raw_request(following)
    before = ledger.files()
    refused = ledger.event("disposition", status="FINAL", resolution={"kind": "next", "request": following_raw,
                           "evidence": ledger.evidence}, **ledger.target(first), expect=2)
    assert refused["error"] == error
    assert ledger.files() == before


def test_duplicate_lost_publication_reply_returns_receipt_and_conflicting_bytes_fail(ledger):
    first = ledger.publish(identifier="stable-event")
    before = ledger.files()
    assert ledger.publish(identifier="stable-event") == first
    assert ledger.files() == before
    refused = ledger.publish(request(owner="someone-else"), identifier="stable-event", expect=2)
    assert refused["error"] == "event id conflicts with different bytes"
    refused = ledger.publish(request(owner="someone-else"), expect=2)
    assert refused["error"] == "request id conflicts with different bytes"
    assert ledger.files() == before


@pytest.mark.parametrize("actor", ["root-1", "router-1"])
@pytest.mark.parametrize("kind", ["admit", "intent", "start", "terminal", "disposition", "meter"])
def test_root_and_router_cannot_record_operator_or_coordinator_actions(ledger, actor, kind):
    before = ledger.files()
    refused = ledger.event(kind, actor=actor, expect=2)
    assert refused["error"] == "role %s cannot record %s" % (actor.split("-")[0], kind)
    assert ledger.files() == before


@pytest.mark.parametrize("change,error", [({"generation": 2}, "stale actor generation"),
                                         ({"custody": {"cid": "root-2", "generation": 2}}, "stale ROOT custody")])
def test_stale_generation_and_custody_refuse_before_publication(ledger, change, error):
    before = ledger.files()
    refused = ledger.publish(expect=2, **change)
    assert refused["error"] == error and ledger.files() == before


def test_changed_request_hash_and_approval_without_authority_are_refused(ledger):
    value = request()
    ledger.publish(value)
    refused = ledger.event("decision", actor="root-1", request_id=value["id"], request_sha256="0" * 64,
                           decision="approve", reason="fixture", expect=2)
    assert refused["error"] == "request sha256 mismatch"
    refused = ledger.admit(value, expect=2)
    assert refused["error"] == "no approved bounded authority"


def test_approved_continuation_admits_a_late_arrival_without_another_root_decision(ledger):
    late = request("engine-controls", authority="engine-partial", prerequisites=["engine-partial"])
    first = request(continuation={"members": [{"id": late["id"], "sha256": raw_request(late)["sha256"],
                                                "phase": late["phase"], "operation": late["operation"]}],
                                 "max_starts": 2, "expires_at": "2099-01-01T00:00:00Z"})
    ledger.ready(first)
    ledger.intent(first)
    ledger.terminal(first)
    ledger.accepted_delivery(first)
    ledger.event("disposition", status="FINAL", resolution={"kind": "complete", "evidence": ledger.evidence},
                 **ledger.target(first))
    assert ledger.status()["work_complete"] is True
    ledger.publish(late)
    assert ledger.status()["work_complete"] is False
    ledger.admit(late)
    ledger.intent(late, intent_id="attempt-2")
    state = ledger.status()
    assert len(state["decisions"]) == 1
    assert state["consumed"][first["id"]] == 2
    assert state["requests"][late["id"]]["intent"]["id"] == "attempt-2"
    assert state["execution_enabled"] is False


def test_restart_after_intent_preserves_unknown_effect_and_refuses_second_attempt(ledger):
    value = ledger.ready()
    receipt = ledger.intent(value, identifier="intent-event")
    before = ledger.files()
    assert ledger.intent(value, identifier="intent-event") == receipt
    assert ledger.status()["obligations"][0]["state"] == "unknown_effect"
    refused = ledger.intent(value, intent_id="duplicate-attempt", expect=2)
    assert refused["error"] == "request already has an intent; settle its unknown effect"
    refused = ledger.event("disposition", status="FINAL", resolution={"kind": "complete", "evidence": ledger.evidence},
                           **ledger.target(value), expect=2)
    assert refused["error"] == "unknown effect prevents closure"
    assert ledger.files() == before


def test_terminal_success_requires_independent_exact_review_and_delivery_before_completion(ledger):
    value = ledger.ready()
    ledger.intent(value)
    ledger.event("start", actor=ledger.operator, intent_id="attempt-1", **ledger.target(value))
    ledger.terminal(value)
    refused = ledger.event("disposition", status="FINAL", resolution={"kind": "complete", "evidence": ledger.evidence},
                           **ledger.target(value), expect=2)
    assert refused["error"] == "completion requires independent acceptance and delivery"
    ledger.accepted_delivery(value)
    ledger.event("disposition", status="FINAL", resolution={"kind": "complete", "evidence": ledger.evidence},
                 **ledger.target(value))
    state = ledger.status()
    assert state["work_complete"] is True and state["obligations"] == []
    row = state["requests"][value["id"]]
    assert row["read"] is None and row["routed"] is None
    assert row["admission"] and row["start"] and row["terminal"] and row["review"] and row["delivery"]


def test_settling_unknown_result_cannot_reuse_review_or_delivery_of_old_bytes(ledger):
    value = ledger.ready()
    ledger.intent(value)
    ledger.terminal(value, outcome="unknown")
    ledger.accepted_delivery(value)
    ledger.terminal(value)
    refused = ledger.event("disposition", status="FINAL", resolution={"kind": "complete", "evidence": ledger.evidence},
                           **ledger.target(value), expect=2)
    assert refused["error"] == "completion requires independent acceptance and delivery"
    assert ledger.status()["requests"][value["id"]]["review"] is None
    ledger.accepted_delivery(value)
    ledger.event("disposition", status="FINAL", resolution={"kind": "complete", "evidence": ledger.evidence},
                 **ledger.target(value))
    assert ledger.status()["work_complete"] is True


def test_completed_request_is_immutable_and_a_review_change_needs_a_new_request_version(ledger):
    value = ledger.ready()
    ledger.intent(value)
    ledger.terminal(value)
    ledger.accepted_delivery(value)
    ledger.event("disposition", status="FINAL", resolution={"kind": "complete", "evidence": ledger.evidence},
                 **ledger.target(value))
    result_hash = ledger.status()["requests"][value["id"]]["terminal"]["sha256"]
    before = ledger.files()
    refused = ledger.event("review", actor="reviewer-1", result_sha256=result_hash, source=SOURCE, verdict="reject",
                           evidence=ledger.evidence, **ledger.target(value), expect=2)
    assert refused["error"] == "closed request requires a new immutable version"
    assert ledger.files() == before


def test_a_capped_operator_has_no_continuation_candidate_or_new_intent(ledger):
    value = ledger.ready()
    ledger.event("meter", actor=ledger.operator, subject=ledger.operator, active_seconds=3600, open_since=None)
    refused = ledger.intent(value, expect=2)
    assert refused["error"] == "actor cumulative active cap reached"
    assert ledger.status()["continuation_candidates"] == []


@pytest.mark.parametrize("decision", ["deny", "expired", "exhausted", "outside-scope"])
def test_bounded_authority_stops_at_denial_expiry_budget_or_exact_scope(ledger, decision, monkeypatch):
    child = request("unapproved-late", authority="engine-partial")
    scope = {"members": [], "max_starts": 1, "expires_at": "2099-01-01T00:00:00Z"}
    if decision == "exhausted":
        scope["members"] = [{"id": child["id"], "sha256": raw_request(child)["sha256"],
                             "phase": child["phase"], "operation": child["operation"]}]
    value = request(continuation=scope)
    ledger.publish(value)
    ledger.approve(value)
    if decision == "deny":
        ledger.event("decision", actor="root-1", decision="deny", reason="owner revocation", **ledger.target(value))
        error = "no approved bounded authority"
    elif decision == "exhausted":
        ledger.admit(value)
        ledger.intent(value)
        ledger.publish(child)
        value = child
        error = "bounded authority exhausted"
    elif decision == "outside-scope":
        ledger.publish(child)
        value = child
        error = "request is outside approved continuation"
    else:
        error = "bounded authority expired"
    before = ledger.files()
    if decision == "expired":
        from tools import hierarchy_lifecycle
        # Approval was valid. Advance only the external clock for fresh admission.
        monkeypatch.setattr(hierarchy_lifecycle, "timestamp", lambda: "2100-01-01T00:00:00Z")
        envelope = {"id": "expired-admission", "actor": ledger.operator, "generation": 1,
                    "custody": {"cid": ledger.root_actor, "generation": 1},
                    "event": {"type": "admit", "source": SOURCE,
                              "gates": {name: ledger.evidence for name in
                                        ("source", "capability", "lease", "capacity", "observer", "job")},
                              **ledger.target(value)}}
        with pytest.raises(ValueError, match="^bounded authority expired$"):
            hierarchy_lifecycle.Lifecycle(ledger.path).record(envelope)
    else:
        refused = ledger.admit(value, expect=2)
        assert refused["error"] == error
    assert ledger.files() == before


def test_new_expired_approval_refuses_without_changing_the_journal(ledger):
    value = request(continuation={"members": [], "max_starts": 1, "expires_at": "2000-01-01T00:00:00Z"})
    ledger.publish(value)
    before = ledger.files()
    refused = ledger.approve(value, expect=2)
    assert refused["error"] == "bounded authority expired"
    assert ledger.files() == before
    assert ledger.status()["requests"][value["id"]]["raw"] == raw_request(value)
    assert ledger.status()["decisions"] == []


@pytest.mark.parametrize("at", ["2099-01-01T00:00:00Z", "2099-01-01T00:00:00.000001Z"])
def test_new_approval_at_or_after_expiry_is_refused_atomically(ledger, monkeypatch, at):
    from tools import hierarchy_lifecycle
    value = request()
    ledger.publish(value)
    envelope = {"id": "at-expiry-approval", "actor": ledger.root_actor, "generation": 1,
                "custody": {"cid": ledger.root_actor, "generation": 1},
                "event": {"type": "decision", "decision": "approve", "reason": "bounded fixture approval",
                          **ledger.target(value)}}
    monkeypatch.setattr(hierarchy_lifecycle, "timestamp", lambda: at)
    before = ledger.files()
    with pytest.raises(ValueError, match="^bounded authority expired$"):
        hierarchy_lifecycle.Lifecycle(ledger.path).record(envelope)
    assert ledger.files() == before


def test_approval_receipt_survives_expiry_and_root_succession_without_new_authority(ledger, monkeypatch):
    from tools import hierarchy_lifecycle
    value = request()
    ledger.publish(value)
    approval = {"id": "retained-approval", "actor": ledger.root_actor, "generation": 1,
                "custody": {"cid": ledger.root_actor, "generation": 1},
                "event": {"type": "decision", "decision": "approve", "reason": "bounded fixture approval",
                          **ledger.target(value)}}
    lifecycle = hierarchy_lifecycle.Lifecycle(ledger.path)
    monkeypatch.setattr(hierarchy_lifecycle, "timestamp", lambda: "2098-01-01T00:00:00Z")
    receipt = lifecycle.record(approval)
    monkeypatch.setattr(hierarchy_lifecycle, "timestamp", lambda: "2100-01-01T00:00:00Z")
    policy, state = lifecycle.load()
    lifecycle.record({"id": "successor-after-expiry", "actor": "root-2", "generation": 2,
                      "custody": {"cid": "root-1", "generation": 1},
                      "event": {"type": "succeed", "predecessor": "root-1",
                                "checkpoint_sha256": hierarchy_lifecycle.checkpoint(policy, state)["sha256"]}})
    before = ledger.files()
    assert lifecycle.record(approval) == receipt
    assert ledger.files() == before
    changed = copy.deepcopy(approval)
    changed["event"]["reason"] = "conflicting receipt bytes"
    with pytest.raises(ValueError, match="^event id conflicts with different bytes$"):
        lifecycle.record(changed)
    assert ledger.files() == before
    denial = {"id": "deny-after-expiry", "actor": "root-2", "generation": 2,
              "custody": {"cid": "root-2", "generation": 2},
              "event": {"type": "decision", "decision": "deny", "reason": "revoke after expiry",
                        **ledger.target(value)}}
    lifecycle.record(denial)
    assert [d["decision"] for d in lifecycle.load()[1]["decisions"]] == ["approve", "deny"]


def test_old_expired_approval_journal_replays_unchanged_and_still_allows_denial(ledger):
    from tools.hierarchy_mailbox import digest, encoded
    value = request(continuation={"members": [], "max_starts": 1, "expires_at": "2000-01-01T00:00:00Z"})
    ledger.publish(value)
    first = json.loads((ledger.path / "events" / "000001.json").read_text())
    # Historical v1 journal shape accepted at ce812358: an expired approval was
    # committed. Construct archived bytes without using new-event admission.
    envelope = {"id": "legacy-expired-approval", "actor": "root-1", "generation": 1,
                "custody": {"cid": "root-1", "generation": 1},
                "event": {"type": "decision", "decision": "approve", "reason": "bounded fixture approval",
                          **ledger.target(value)}}
    archived = {"schema": "aegis.lifecycle-event/v1", "sequence": 2, "previous": digest(first),
                "policy_sha256": first["policy_sha256"], "at": "2001-01-01T00:00:00Z",
                "envelope": envelope, "event_sha256": digest(envelope)}
    (ledger.path / "events" / "000002.json").write_bytes(encoded(archived) + b"\n")
    before = ledger.files()
    status = ledger.status()
    assert [d["decision"] for d in status["decisions"]] == ["approve"]
    assert status["requests"][value["id"]]["raw"] == raw_request(value)
    checkpoint = ledger.cli("checkpoint")
    assert checkpoint["state"]["head"] == digest(archived)
    assert ledger.approve(value, identifier="legacy-expired-approval") == status["receipts"]["legacy-expired-approval"]
    assert ledger.files() == before
    ledger.event("decision", actor="root-1", decision="deny", reason="historical approval revoked",
                 **ledger.target(value))
    assert [d["decision"] for d in ledger.status()["decisions"]] == ["approve", "deny"]


def test_blocker_resolution_requires_exact_blocker_hash_and_advances_to_an_owned_request(ledger):
    value = request()
    ledger.publish(value)
    ledger.event("disposition", status="HOLD", resolution={"kind": "blocked", "owner": "engine/coordinator",
                 "next_decision": "review P1 fixes", "condition": "fix reviewed", "evidence": ledger.evidence},
                 **ledger.target(value))
    resolution = {"kind": "next", "request": raw_request(request("engine-controls")), "evidence": ledger.evidence}
    refused = ledger.event("resolve", blocker_sha256="0" * 64, resolution=resolution, **ledger.target(value), expect=2)
    assert refused["error"] == "blocker sha256 mismatch"
    blocker = ledger.status()["requests"][value["id"]]["resolution"]
    raw = json.dumps(blocker, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ledger.event("resolve", blocker_sha256=hashlib.sha256(raw).hexdigest(), resolution=resolution, **ledger.target(value))
    assert [row["request_id"] for row in ledger.status()["obligations"]] == ["engine-controls"]


def test_lost_reply_can_be_recovered_after_root_succession_without_reauthorizing_the_event(ledger):
    receipt = ledger.publish(identifier="lost-reply")
    old_custody = {"cid": "root-1", "generation": 1}
    cp = ledger.cli("checkpoint")
    ledger.event("succeed", actor="root-2", predecessor="root-1", checkpoint_sha256=cp["sha256"])
    before = ledger.files()
    assert ledger.publish(identifier="lost-reply", custody=old_custody) == receipt
    assert ledger.files() == before
    refused = ledger.publish(request("new-request"), custody=old_custody, expect=2)
    assert refused["error"] == "stale ROOT custody"


@pytest.mark.parametrize("kind,error", [("admit", "admission source mismatch"),
                                         ("terminal", "terminal source mismatch"),
                                         ("review", "review source mismatch")])
def test_source_witness_must_match_at_admission_result_and_independent_review(ledger, kind, error):
    value = ledger.ready()
    changed = {**SOURCE, "tree": "d" * 40}
    if kind == "admit":
        refused = ledger.event("admit", actor=ledger.operator, source=changed, gates={}, **ledger.target(value), expect=2)
    else:
        ledger.intent(value)
        if kind == "terminal":
            result = {"request_sha256": raw_request(value)["sha256"], "intent_id": "attempt-1", "outcome": "passed",
                      "exit_code": 0, "source": changed, "evidence": ledger.evidence}
            refused = ledger.event("terminal", actor=ledger.operator, result=raw_request(result), **ledger.target(value), expect=2)
        else:
            ledger.terminal(value)
            result_hash = ledger.status()["requests"][value["id"]]["terminal"]["sha256"]
            refused = ledger.event("review", actor="reviewer-1", source=changed, result_sha256=result_hash,
                                   verdict="accept", evidence=ledger.evidence, **ledger.target(value), expect=2)
    assert refused["error"] == error


def test_revocation_after_intent_prevents_start_without_clearing_the_unknown_effect(ledger):
    value = ledger.ready()
    ledger.intent(value)
    ledger.event("decision", actor="root-1", decision="deny", reason="revoke remaining operations", **ledger.target(value))
    refused = ledger.event("start", actor=ledger.operator, intent_id="attempt-1", **ledger.target(value), expect=2)
    assert refused["error"] == "authority revoked before start"
    status = ledger.status()
    assert [d["decision"] for d in status["decisions"]] == ["approve", "deny"]
    assert status["consumed"][value["id"]] == 1 and status["obligations"][0]["state"] == "unknown_effect"


def test_successor_attestation_cannot_be_impersonated_by_the_predecessor(ledger):
    cp = ledger.cli("checkpoint")
    refused = ledger.event("succeed", actor="operator-1", predecessor="operator-1", checkpoint_sha256=cp["sha256"], expect=2)
    assert refused["error"] == "incoming actor must attest its own approved succession"


def test_policy_rejects_a_writable_root_and_an_unapproved_successor_profile_change(tmp_path):
    ledger = Ledger(tmp_path, initialize=False)
    ledger.policy["actors"]["root-1"]["profile"]["filesystem"] = "workspace-write"
    ledger.policy_path.write_text(json.dumps(ledger.policy))
    refused = ledger.cli("init", "--policy", str(ledger.policy_path), "--evidence-only", expect=2)
    assert refused["error"] == "ROOT requires a read-only decision profile; effective enforcement remains unqualified"
    assert not ledger.path.exists()
    ledger.policy["actors"]["root-1"]["profile"]["filesystem"] = "read-only"
    ledger.policy["actors"]["operator-2"]["profile"]["effort"] = "high"
    ledger.policy_path.write_text(json.dumps(ledger.policy))
    refused = ledger.cli("init", "--policy", str(ledger.policy_path), "--evidence-only", expect=2)
    assert refused["error"] == "succession cannot change profile or cap policy"


def test_lost_process_result_keeps_a_null_exit_code_and_unknown_fence(ledger):
    value = ledger.ready()
    ledger.intent(value)
    result = {"request_sha256": raw_request(value)["sha256"], "intent_id": "attempt-1", "outcome": "unknown",
              "exit_code": None, "source": SOURCE, "evidence": ledger.evidence}
    ledger.event("terminal", actor=ledger.operator, result=raw_request(result), **ledger.target(value))
    state = ledger.status()
    assert state["requests"][value["id"]]["terminal"]["value"]["exit_code"] is None
    assert state["obligations"][0]["state"] == "unknown_effect"


@pytest.mark.parametrize("resolution", [None, "done", []])
def test_malformed_blocker_resolution_returns_structured_hold_without_a_traceback(ledger, resolution):
    value = request()
    ledger.publish(value)
    ledger.event("disposition", status="HOLD", resolution={"kind": "blocked", "owner": "engine/coordinator",
                 "next_decision": "review P1 fixes", "condition": "fix reviewed", "evidence": ledger.evidence},
                 **ledger.target(value))
    blocker = ledger.status()["requests"][value["id"]]["resolution"]
    raw = json.dumps(blocker, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    before = ledger.files()
    refused = ledger.event("resolve", blocker_sha256=hashlib.sha256(raw).hexdigest(), resolution=resolution,
                           **ledger.target(value), expect=2)
    assert refused["error"] == "invalid resolution"
    assert ledger.files() == before


def test_cap_and_open_wait_are_carried_into_exact_self_attested_successor_checkpoint(ledger):
    value = ledger.ready()
    ledger.intent(value)
    ledger.event("wait", actor=ledger.operator, reason="host reply lost", **ledger.target(value))
    ledger.event("meter", actor=ledger.operator, subject=ledger.operator, active_seconds=3600, open_since=None)
    checkpoint = ledger.cli("checkpoint")
    assert checkpoint["state"]["meters"][ledger.operator]["active_seconds"] == 3600
    assert checkpoint["state"]["requests"][value["id"]]["wait"]["reason"] == "host reply lost"
    refused = ledger.event("succeed", actor="operator-2", predecessor="operator-1", checkpoint_sha256="0" * 64,
                           expect=2)
    assert refused["error"] == "checkpoint sha256 mismatch"
    ledger.event("succeed", actor="operator-2", predecessor="operator-1", checkpoint_sha256=checkpoint["sha256"])
    before = ledger.files()
    refused = ledger.intent(value, intent_id="old-generation", expect=2)
    assert refused["error"] == "actor generation is fenced"
    assert ledger.files() == before
    ledger.operator = "operator-2"
    refused = ledger.intent(value, intent_id="new-generation", expect=2)
    assert refused["error"] == "request already has an intent; settle its unknown effect"
    assert ledger.status()["requests"][value["id"]]["intent"]["actor"] == "operator-1"


@pytest.mark.parametrize("corruption", ["gap", "truncated", "changed", "pending"])
def test_corrupt_or_partial_journals_hold_without_repair(ledger, corruption):
    ledger.publish()
    first = ledger.path / "events" / "000001.json"
    if corruption == "gap":
        first.rename(first.with_name("000002.json"))
    elif corruption == "truncated":
        first.write_text('{"schema":')
    elif corruption == "changed":
        value = json.loads(first.read_text())
        value["event_sha256"] = "0" * 64
        first.write_text(json.dumps(value))
    else:
        first.with_name(".pending-interrupted").write_text("partial evidence")
    before = ledger.files()
    result = ledger.cli("status", expect=2)
    assert result["state"] == "hold" and result["work_complete"] is False
    assert ledger.files() == before


def test_malformed_json_and_missing_event_files_fail_with_exact_errors(ledger):
    path = ledger.tmp / "bad-event.json"
    path.write_text('{"id":')
    result = ledger.cli("record", "--event", str(path), "--evidence-only", expect=2)
    assert result["error"] == "malformed JSON"
    result = ledger.cli("record", "--event", str(ledger.tmp / "missing.json"), "--evidence-only", expect=2)
    assert "No such file" in result["error"]
