"""Public evidence-ledger behavior. Fixture identities never establish native authority."""
import copy
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
import socket
import stat
import struct
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

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


@pytest.mark.parametrize("ordinary_event", [False, True])
def test_initial_bootstrap_snapshot_refuses_legacy_history_without_mutation(ledger,
                                                                          ordinary_event):
    """An evidence-only history cannot supply an INITIAL bootstrap receipt.

    The initial failure is FEATURE_ABSENT at the real public read method. This
    case does not claim an authenticated H constructor or a semantic guard RED.
    """
    from tools import hierarchy_lifecycle as lifecycle

    if ordinary_event:
        ledger.publish()
    before = ledger.files()
    reader = lifecycle.Lifecycle(ledger.path)
    with pytest.raises(ValueError, match="^initial bootstrap genesis missing$"):
        reader.initial_bootstrap()
    assert ledger.files() == before
    assert ledger.status()["sequence"] == int(ordinary_event)


def _initial_control_frame(value):
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


def _initial_control_digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _initial_file_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@contextmanager
def initial_runtime_boundary(api, tmp_path, monkeypatch, fault=None, *, actor_count=6):
    """Stand in for external Rust/kernel readback, with real owned sockets/pipes.

    Copied from H test8bd6a78b, with an absent canonical root and a planned
    successor. H constructors/guards and N1 loaders are actual production code.
    This fixture may execute only in a fresh serialized test window.
    """
    if sys.platform != "linux":
        pytest.skip("first protected constructor requires Linux peer/procfs readback")
    from tools import hierarchy_lifecycle as lifecycle

    assert Path(lifecycle.__file__).parent == Path(api.__file__).parent
    uid = os.geteuid()
    executable = Path(os.readlink("/proc/self/exe"))
    peer_pid = os.getpid() + 1000000  # Only the actual OS readback is mocked.
    actual_stat, actual_fstat = os.stat, os.fstat
    actual_readlink = os.readlink
    actual_read_bytes, actual_read_text = Path.read_bytes, Path.read_text
    actual_getsockopt = socket.socket.getsockopt
    proc_stat = Path("/proc/self/stat").read_text()
    proc_tail = proc_stat[proc_stat.rfind(")") + 2:]
    start_ticks = int(proc_tail.split()[19])
    process = {"boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
               "pid_namespace": actual_stat("/proc/self/ns/pid").st_ino,
               "pid": peer_pid, "start_ticks": start_ticks}
    roles = ("root", "router", "coordinator", "operator", "reviewer")
    actors = {}
    for role in roles:
        actors["fixture-" + role] = {
            "role": role, "generation": 1, "cap_seconds": 60,
            "profile": {"model": "gpt-6.1-sol",
                        "effort": "medium" if role == "router" else "ultra",
                        "tier": "ultrafast" if role == "router" else "default",
                        "filesystem": "read-only" if role == "root" else "restricted",
                        "tools": ["read"]}}
    assert type(actor_count) is int and 5 <= actor_count <= 128
    successors = {}
    previous = "fixture-root"
    for generation in range(2, actor_count - 3):
        cid = "fixture-root-next" if generation == 2 else "fixture-root-%d" % generation
        actors[cid] = {**copy.deepcopy(actors["fixture-root"]), "generation": generation}
        successors[previous] = cid
        previous = cid
    plan_body = {"source": {"commit": "c3471723d32706852a8c182de0eef8cce87e7465",
                            "tree": "69691322f217818108577f3bb54546e7ae7de5b1",
                            "dirty_sha256": "0" * 64},
                 "actors": actors, "current": {r: "fixture-" + r for r in roles},
                 "successors": successors}
    plan = tmp_path / "accepted-plan.json"
    plan.write_text(json.dumps(plan_body, sort_keys=True))
    plan_ref = {"path": str(plan), "sha256": _initial_file_digest(plan)}
    canonical = tmp_path / "canonical"
    # Protected N1 public genesis owns creation of this absent canonical root.
    assert not canonical.exists()
    ceiling = tmp_path / "role-ceiling.json"
    ceiling.write_text(json.dumps({role: [] for role in roles}))
    endpoint_home = None
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client, peer, wire = None, None, None
    streams, thread, requests, errors = [], None, [], []
    peer_read, peer_write = None, None
    try:
        # Match H's reviewed external-fixture repair: pytest case paths may
        # exceed sockaddr_un's limit before any production constructor runs.
        endpoint_home = tempfile.TemporaryDirectory(prefix="hc-")
        endpoint = Path(endpoint_home.name) / "c"
        listener.bind(str(endpoint))
        os.chmod(endpoint, 0o600)
        listener.listen(1)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(endpoint))
        peer, _ = listener.accept()
        peer.settimeout(2)
        peer_read, host_write = os.pipe()
        host_read, peer_write = os.pipe()
        reader, writer = os.fdopen(host_read, "rb", 0), os.fdopen(host_write, "wb", 0)
        streams.extend((reader, writer))
        closure = [{"path": str(Path(api.__file__).resolve()),
                    "sha256": _initial_file_digest(api.__file__)}]
        deployment = tmp_path / "deployment.json"
        deployment.write_text(json.dumps({
            "schema": "aegis.protected-host-deployment/v1",
            "runtime_uid": uid, "host_uid": uid, "model_uid": uid + 1,
            "runtime_executable": {"path": str(executable),
                                   "sha256": _initial_file_digest(executable)},
            "host_source_closure": closure, "canonical_root": str(canonical),
            "runtime_control_endpoint": str(endpoint),
            "role_ceiling_ref": {"path": str(ceiling), "sha256": _initial_file_digest(ceiling)}}))
        channel = {"schema": "aegis.host-channel-witness/v1",
                   "runtime_instance": dict(process), "appserver_instance": dict(process),
                   "control_peer_instance": dict(process),
                   "read_pipe_inode": actual_fstat(peer_write).st_ino,
                   "write_pipe_inode": actual_fstat(peer_read).st_ino,
                   "epoch": 17, "deployment_sha256": _initial_file_digest(deployment),
                   "runtime_executable_sha256": _initial_file_digest(executable),
                   "host_source_closure_sha256": _initial_control_digest(closure),
                   "role_ceiling_sha256": _initial_file_digest(ceiling)}
        reservations = [{
            "schema": "aegis.host-reservation-witness/v1",
            "channel_instance_sha256": _initial_control_digest(channel),
            "approved_plan_sha256": plan_ref["sha256"], "actor_cid": cid,
            "role": actor["role"], "generation": actor["generation"],
            "profile_sha256": _initial_control_digest(actor["profile"]),
            "cap_seconds": actor["cap_seconds"], "reservation_sequence": index,
            "expires_monotonic_ns": time.monotonic_ns() + 5000000000}
            for index, (cid, actor) in enumerate(sorted(actors.items()), 1)]

        def protected_metadata(value):
            # Actual OS provenance is the mocked boundary; file contents are real.
            data = list(value)
            # Confined source-test namespaces expose host-root as overflow UID.
            observed_uid = value.st_uid
            if fault == "foreign-file-owner" and stat.S_ISREG(value.st_mode):
                observed_uid = uid + 77
            data[4] = uid if observed_uid == 65534 else observed_uid
            if stat.S_ISDIR(value.st_mode) or stat.S_ISREG(value.st_mode):
                data[0] &= ~0o022
            return os.stat_result(data)

        def map_proc(path):
            text = os.fspath(path)
            prefix = "/proc/%s/" % peer_pid
            return "/proc/self/" + text[len(prefix):] if text.startswith(prefix) else text

        def kernel_stat(path, *args, **kwargs):
            if os.fspath(path) == "/proc/%s/fd/0" % peer_pid:
                return protected_metadata(actual_fstat(peer_read))
            if os.fspath(path) == "/proc/%s/fd/1" % peer_pid:
                return protected_metadata(actual_fstat(peer_write))
            return protected_metadata(actual_stat(map_proc(path), *args, **kwargs))

        def kernel_readlink(path, *args, **kwargs):
            value = os.fspath(path)
            if value == "/proc/%s/fd/0" % peer_pid:
                return "pipe:[%s]" % actual_fstat(peer_read).st_ino
            if value == "/proc/%s/fd/1" % peer_pid:
                return "pipe:[%s]" % actual_fstat(peer_write).st_ino
            return actual_readlink(map_proc(path), *args, **kwargs)

        def kernel_bytes(path):
            if str(path) == "/proc/%s/stat" % peer_pid:
                return ("%s (mock-rust) " % peer_pid + proc_tail).encode()
            return actual_read_bytes(Path(map_proc(path)))

        def kernel_text(path, *args, **kwargs):
            if str(path) == "/proc/%s/stat" % peer_pid:
                return "%s (mock-rust) " % peer_pid + proc_tail
            return actual_read_text(Path(map_proc(path)), *args, **kwargs)

        def peer_credentials(sock, level, option, *args):
            if level == socket.SOL_SOCKET and option == socket.SO_PEERCRED:
                peer_uid = uid + 77 if fault == "foreign-peer" else uid
                return struct.pack("3i", peer_pid, peer_uid, uid)
            return actual_getsockopt(sock, level, option, *args)

        with monkeypatch.context() as boundary:
            boundary.setattr(os, "stat", kernel_stat)
            boundary.setattr(os, "fstat", lambda fd: protected_metadata(actual_fstat(fd)))
            boundary.setattr(os, "readlink", kernel_readlink)
            boundary.setattr(Path, "read_bytes", kernel_bytes)
            boundary.setattr(Path, "read_text", kernel_text)
            boundary.setattr(socket.socket, "getsockopt", peer_credentials)
            wire = peer.makefile("rwb", buffering=0)

            def rust_control():
                try:
                    for raw in wire:
                        request = json.loads(raw)
                        requests.append(request)
                        assert set(request) == {"schema", "id", "epoch", "nonce", "method", "params"}
                        assert request["schema"] == "aegis.protected-initial-control/v1"
                        assert len(request["nonce"]) == 64
                        if request["method"] == "describe":
                            assert request["id"] == 1 and request["epoch"] == 0
                            assert request["params"] == {}
                            result = {"channel_witness": channel}
                        else:
                            assert request["method"] == "reserve_initial"
                            assert request["epoch"] == 17
                            assert request["params"] == {"approved_plan": plan_ref}
                            result = {"reservations": reservations}
                        nonce = "0" * 64 if fault == "wrong-nonce" else request["nonce"]
                        wire.write(_initial_control_frame({"schema": request["schema"], "id": request["id"],
                                          "epoch": 17, "nonce": nonce, "result": result}))
                except Exception as error:
                    errors.append(error)

            thread = threading.Thread(target=rust_control, daemon=True)
            thread.start()
            yield client, reader, writer, deployment, plan_ref, requests
    finally:
        # Every close/reap runs even if another cleanup operation raises.
        # LIFO closes H's ends, interrupts Rust's read, joins, then closes peers.
        with ExitStack() as cleanup:
            if endpoint_home is not None:
                cleanup.callback(endpoint_home.cleanup)
            for fd in (peer_read, peer_write):
                if fd is not None:
                    cleanup.callback(os.close, fd)
            cleanup.callback(listener.close)
            if peer is not None:
                cleanup.callback(peer.close)
            if wire is not None:
                cleanup.callback(wire.close)
            if thread is not None:
                cleanup.callback(thread.join, timeout=3)
            if peer is not None:
                cleanup.callback(peer.shutdown, socket.SHUT_RDWR)
            for stream in streams:
                cleanup.callback(stream.close)
            if client is not None:
                cleanup.callback(client.close)
        assert thread is None or not thread.is_alive(), "external Rust stand-in did not stop"
        assert not errors, errors




def test_initial_constructor_preserves_foreign_file_owner_refusal(tmp_path, monkeypatch):
    from tools import hierarchy_host_authority as host

    with initial_runtime_boundary(host, tmp_path, monkeypatch, "foreign-file-owner") as inputs:
        control, reader, writer, deployment, _, requests = inputs
        with pytest.raises(host.HostAuthorityError) as caught:
            host.OwnedHostBinding.from_owned_channels(control, reader, writer, deployment)
        assert caught.value.code == "UNPROTECTED_DEPLOYMENT"
        assert caught.value.reason == "unprotected host deployment"
        assert requests == []
        assert control.fileno() == -1 and reader.closed and writer.closed
        assert not (tmp_path / "canonical").exists()


@pytest.fixture
def initial_owned_runtime(tmp_path, monkeypatch, request):
    """Use real H objects; only the external Rust/OS peer is a stand-in."""
    from tools import hierarchy_host_authority as host
    from tools import hierarchy_lifecycle as lifecycle

    writer_type = lifecycle.ProtectedCanonicalEnrollmentWriter
    factory = host.OwnedHostBinding.from_owned_channels
    with initial_runtime_boundary(host, tmp_path, monkeypatch,
                                  actor_count=getattr(request, "param", 6)) as inputs:
        control, reader, writer, deployment, plan_ref, requests = inputs
        binding = factory(control, reader, writer, deployment)
        try:
            reservations = binding.reserve_initial(plan_ref)
            canonical = tmp_path / "canonical"
            yield lifecycle, binding, reservations, canonical, plan_ref, requests, writer_type
        finally:
            binding.close()


@pytest.fixture
def initial_bootstrap_runtime(initial_owned_runtime):
    lifecycle, binding, reservations, canonical, plan_ref, requests, writer_type = initial_owned_runtime
    receipt = writer_type(canonical, binding.authority).initialize_reserved_genesis(
        binding.owned_runtime, reservations, plan_ref)
    return lifecycle, binding, reservations, canonical, receipt, requests


def test_initial_creation_requires_protected_marker_before_receipt(initial_owned_runtime):
    lifecycle, binding, reservations, canonical, plan_ref, requests, _ = initial_owned_runtime
    lifecycle.initialize(canonical, binding.policy)  # Real legacy public genesis.
    target = next(row for row in reservations if row.actor_cid == "fixture-root")
    before = {str(p.relative_to(canonical)): p.read_bytes()
              for p in canonical.rglob("*") if p.is_file()}
    with binding.authority.initial_creation_fence(binding.owned_runtime, plan_ref, target) as guard:
        answer = lifecycle.ProtectedCanonicalBootstrapWriter(canonical).commit_initial_creation(
            guard, target)
    assert (answer["state"], answer["effect"], answer["code"]) == (
        "refused", "none", "INITIAL_GENESIS_REQUIRED")
    assert answer["receipt"] is None
    assert {str(p.relative_to(canonical)): p.read_bytes()
            for p in canonical.rglob("*") if p.is_file()} == before
    assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


def test_reserved_genesis_reconstructs_full_set_and_original_prefix(initial_bootstrap_runtime):
    lifecycle, binding, reservations, canonical, receipt, requests = initial_bootstrap_runtime
    reader = lifecycle.Lifecycle(canonical)
    policy, state = reader.load()
    original = reader.initial_bootstrap()
    assert set(receipt) == {"schema", "policy_sha256", "checkpoint_sha256", "enrollments"}
    assert receipt["schema"] == "aegis.protected-reserved-enrollment-receipt/v1"
    assert set(original) == {"schema", "policy_sha256", "genesis_checkpoint",
                             "genesis_receipt", "reservations", "creations"}
    assert original["schema"] == "aegis.initial-bootstrap-snapshot/v1"
    assert receipt["policy_sha256"] == original["policy_sha256"] == lifecycle.digest(policy)
    assert receipt["checkpoint_sha256"] == original["genesis_checkpoint"]["sha256"]
    assert original["genesis_checkpoint"]["state"]["sequence"] == state["sequence"] == 1
    assert original["genesis_receipt"]["event_id"] == "initial-genesis"
    assert original["creations"] == []
    cids = [row.actor_cid for row in reservations]
    assert cids == sorted(policy["actors"]) == [
        "fixture-coordinator", "fixture-operator", "fixture-reviewer",
        "fixture-root", "fixture-root-next", "fixture-router"]
    assert [row["actor_cid"] for row in receipt["enrollments"]] == cids
    assert [row["actor_cid"] for row in original["reservations"]] == cids
    for enrollment, witness in zip(receipt["enrollments"], original["reservations"]):
        assert set(enrollment) == {"actor_cid", "role", "generation", "profile_sha256",
                                   "cap_seconds", "channel_instance_sha256",
                                   "reservation_witness_sha256"}
        assert enrollment["reservation_witness_sha256"] == lifecycle.digest(witness)
        for name in ("actor_cid", "role", "generation", "profile_sha256",
                     "cap_seconds", "channel_instance_sha256"):
            assert enrollment[name] == witness[name]
    assert set(state["current"].values()) == set(cids) - {"fixture-root-next"}
    assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


def test_initial_creation_replay_keeps_original_receipt_and_prefix(initial_bootstrap_runtime):
    lifecycle, binding, reservations, canonical, genesis, requests = initial_bootstrap_runtime
    target = next(row for row in reservations if row.actor_cid == "fixture-root")
    plan_ref = json.loads((canonical / "policy.json").read_text())["authority"][0]
    writer = lifecycle.ProtectedCanonicalBootstrapWriter(canonical)
    with binding.authority.initial_creation_fence(binding.owned_runtime, plan_ref, target) as guard:
        first = writer.commit_initial_creation(guard, target)
        original_files = {p.name: p.read_bytes() for p in (canonical / "events").iterdir()}
        replay = writer.commit_initial_creation(guard, target)
    assert set(first) == {"schema", "state", "effect", "code", "reason",
                          "actor_cid", "event_id", "receipt", "native_qualified"}
    assert first["schema"] == "aegis.initial-creation-result/v1"
    assert (first["state"], first["effect"], first["code"], first["reason"]) == (
        "recorded", "canonical_initial_creation", None, None)
    assert (replay["state"], replay["effect"]) == ("recovered", "none")
    assert replay["receipt"] == first["receipt"]
    assert replay["event_id"] == first["event_id"]
    assert first["receipt"]["sequence"] == 2
    assert first["receipt"]["execution_enabled"] is False
    assert first["native_qualified"] is replay["native_qualified"] is False
    assert {p.name: p.read_bytes() for p in (canonical / "events").iterdir()} == original_files
    reader = lifecycle.Lifecycle(canonical)
    snapshot = reader.initial_bootstrap()
    assert snapshot["genesis_checkpoint"]["sha256"] == genesis["checkpoint_sha256"]
    assert snapshot["genesis_checkpoint"]["state"]["sequence"] == 1
    assert reader.load()[1]["sequence"] == 2
    assert snapshot["creations"] == [{
        "actor_cid": target.actor_cid,
        "envelope": json.loads(original_files["000002.json"])["envelope"],
        "receipt": first["receipt"]}]
    assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


def test_planned_successor_cannot_receive_initial_creation(initial_bootstrap_runtime):
    lifecycle, binding, reservations, canonical, _, requests = initial_bootstrap_runtime
    target = next(row for row in reservations if row.actor_cid == "fixture-root-next")
    plan_ref = json.loads((canonical / "policy.json").read_text())["authority"][0]
    before = {p.name: p.read_bytes() for p in (canonical / "events").iterdir()}
    with binding.authority.initial_creation_fence(binding.owned_runtime, plan_ref, target) as guard:
        answer = lifecycle.ProtectedCanonicalBootstrapWriter(canonical).commit_initial_creation(
            guard, target)
    assert (answer["state"], answer["effect"], answer["code"]) == (
        "refused", "none", "INITIAL_CREATION_FORBIDDEN")
    assert answer["receipt"] is None and answer["native_qualified"] is False
    assert {p.name: p.read_bytes() for p in (canonical / "events").iterdir()} == before
    assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


def test_initial_creation_publication_unknown_retains_original_for_explicit_recovery(
        initial_bootstrap_runtime, monkeypatch):
    lifecycle, binding, reservations, canonical, _, requests = initial_bootstrap_runtime
    target = next(row for row in reservations if row.actor_cid == "fixture-root")
    plan_ref = json.loads((canonical / "policy.json").read_text())["authority"][0]
    writer = lifecycle.ProtectedCanonicalBootstrapWriter(canonical)
    real_publish = lifecycle.publish_file

    def lose_persistence_reply(path, payload, *, limit):
        real_publish(path, payload, limit=limit)
        raise OSError("fixture lost publication reply")

    with binding.authority.initial_creation_fence(binding.owned_runtime, plan_ref, target) as guard:
        with monkeypatch.context() as persistence:
            persistence.setattr(lifecycle, "publish_file", lose_persistence_reply)
            unknown = writer.commit_initial_creation(guard, target)
    assert (unknown["state"], unknown["effect"], unknown["code"]) == (
        "unknown", "possible", "INITIAL_CREATION_PUBLICATION_UNKNOWN")
    assert unknown["receipt"] is None and unknown["native_qualified"] is False
    before = {p.name: p.read_bytes() for p in (canonical / "events").iterdir()}
    with binding.authority.initial_creation_fence(binding.owned_runtime, plan_ref, target) as guard:
        recovered = writer.commit_initial_creation(guard, target)
    assert (recovered["state"], recovered["effect"]) == ("recovered", "none")
    assert recovered["event_id"] == unknown["event_id"]
    assert recovered["receipt"]["sequence"] == 2
    assert {p.name: p.read_bytes() for p in (canonical / "events").iterdir()} == before
    assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


@pytest.mark.parametrize("failure", ["root_claim", "policy_reply", "marker_reply",
                                     "events_fsync", "canonical_fence_exit"])
def test_reserved_genesis_ambiguity_retains_claim_without_retry(initial_owned_runtime,
                                                              monkeypatch, failure):
    lifecycle, binding, reservations, canonical, plan_ref, requests, writer_type = initial_owned_runtime
    real_mkdir, real_unlink = Path.mkdir, os.unlink
    real_publish, real_sync = lifecycle.publish_file, lifecycle.sync_directory
    injected = []

    def mkdir_then_lose_reply(path, *args, **kwargs):
        answer = real_mkdir(path, *args, **kwargs)
        if failure == "root_claim" and path == canonical:
            injected.append(failure)
            raise OSError("fixture lost exclusive root claim reply")
        return answer

    def publish_then_lose_reply(path, payload, *, limit):
        real_publish(path, payload, limit=limit)
        if ((failure == "policy_reply" and path == canonical / "policy.json")
                or (failure == "marker_reply" and path == canonical / "events" / "000001.json")):
            injected.append(failure)
            raise OSError("fixture lost canonical publication reply")

    def fsync_then_lose_reply(path):
        real_sync(path)
        if failure == "events_fsync" and path == canonical / "events":
            injected.append(failure)
            raise OSError("fixture lost events directory fsync reply")

    def unlink_then_lose_reply(path, *args, **kwargs):
        answer = real_unlink(path, *args, **kwargs)
        if failure == "canonical_fence_exit" and Path(path) == canonical / ".write.lock":
            injected.append(failure)
            raise OSError("fixture lost canonical fence release reply")
        return answer

    with monkeypatch.context() as persistence:
        persistence.setattr(Path, "mkdir", mkdir_then_lose_reply)
        persistence.setattr(lifecycle, "publish_file", publish_then_lose_reply)
        persistence.setattr(lifecycle, "sync_directory", fsync_then_lose_reply)
        persistence.setattr(os, "unlink", unlink_then_lose_reply)
        with pytest.raises(lifecycle.CanonicalGenesisError) as caught:
            writer_type(canonical, binding.authority).initialize_reserved_genesis(
                binding.owned_runtime, reservations, plan_ref)
    assert injected == [failure]
    assert (caught.value.state, caught.value.effect, caught.value.code) == (
        "unknown", "possible", "GENESIS_PUBLICATION_UNKNOWN")
    assert canonical.is_dir(), "UNKNOWN must retain its original root claim"
    assert not (canonical / ".write.lock").exists()
    if failure == "root_claim":
        assert list(canonical.iterdir()) == []
    elif failure == "policy_reply":
        with pytest.raises(ValueError, match="^initial bootstrap genesis missing$"):
            lifecycle.Lifecycle(canonical).initial_bootstrap()
    else:
        original = lifecycle.Lifecycle(canonical).initial_bootstrap()
        assert original["genesis_receipt"]["event_id"] == "initial-genesis"
        assert original["genesis_receipt"]["sequence"] == 1
        assert len(original["reservations"]) == len(reservations) == 6
        assert original["creations"] == []
    assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


def test_initial_creation_canonical_fence_exit_unknown_recovers_original_only(
        initial_bootstrap_runtime, monkeypatch):
    lifecycle, binding, reservations, canonical, _, requests = initial_bootstrap_runtime
    target = next(row for row in reservations if row.actor_cid == "fixture-root")
    plan_ref = json.loads((canonical / "policy.json").read_text())["authority"][0]
    writer = lifecycle.ProtectedCanonicalBootstrapWriter(canonical)
    real_unlink = os.unlink
    releases = []

    def unlink_then_lose_reply(path, *args, **kwargs):
        answer = real_unlink(path, *args, **kwargs)
        if Path(path) == canonical / ".write.lock":
            releases.append(str(path))
            raise OSError("fixture lost canonical fence release reply")
        return answer

    with binding.authority.initial_creation_fence(binding.owned_runtime, plan_ref, target) as guard:
        with monkeypatch.context() as persistence:
            persistence.setattr(os, "unlink", unlink_then_lose_reply)
            unknown = writer.commit_initial_creation(guard, target)
    assert len(releases) == 1
    assert (unknown["state"], unknown["effect"], unknown["code"]) == (
        "unknown", "possible", "INITIAL_CREATION_PUBLICATION_UNKNOWN")
    assert unknown["receipt"] is None
    before = {p.name: p.read_bytes() for p in (canonical / "events").iterdir()}
    with binding.authority.initial_creation_fence(binding.owned_runtime, plan_ref, target) as guard:
        recovered = writer.commit_initial_creation(guard, target)
    assert (recovered["state"], recovered["effect"]) == ("recovered", "none")
    assert recovered["event_id"] == unknown["event_id"]
    assert recovered["receipt"]["sequence"] == 2
    assert {p.name: p.read_bytes() for p in (canonical / "events").iterdir()} == before
    assert not (canonical / ".write.lock").exists()
    assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


def test_expired_initial_receipt_recovery_does_not_renew_new_creation_or_current_budget(
        initial_bootstrap_runtime, monkeypatch):
    lifecycle, binding, reservations, canonical, _, requests = initial_bootstrap_runtime
    target = next(row for row in reservations if row.actor_cid == "fixture-root")
    unused = next(row for row in reservations if row.actor_cid == "fixture-operator")
    plan_ref = json.loads((canonical / "policy.json").read_text())["authority"][0]
    writer = lifecycle.ProtectedCanonicalBootstrapWriter(canonical)
    with binding.authority.initial_creation_fence(binding.owned_runtime, plan_ref, target) as guard:
        recorded = writer.commit_initial_creation(guard, target)
    assert recorded["state"] == "recorded"
    before = {p.name: p.read_bytes() for p in (canonical / "events").iterdir()}
    real_ns, real_seconds = time.monotonic_ns, time.monotonic
    offset_ns = 6000000000  # Reservation deadline is five seconds in the external fixture.
    with monkeypatch.context() as clock:
        clock.setattr(time, "monotonic_ns", lambda: real_ns() + offset_ns)
        clock.setattr(time, "monotonic", lambda: real_seconds() + offset_ns / 1000000000)
        with binding.authority.initial_creation_fence(binding.owned_runtime, plan_ref, target) as guard:
            recovered = writer.commit_initial_creation(guard, target)
        assert (recovered["state"], recovered["effect"]) == ("recovered", "none")
        assert recovered["receipt"] == recorded["receipt"]
        with binding.authority.initial_creation_fence(binding.owned_runtime, plan_ref, unused) as guard:
            expired_new = writer.commit_initial_creation(guard, unused)
        assert (expired_new["state"], expired_new["effect"], expired_new["code"]) == (
            "refused", "none", "HOST_AUTHORITY_REFUSED")
        with binding.authority.initial_creation_fence(binding.owned_runtime, plan_ref, target) as guard:
            offset_ns += 6000000000  # Expire this actual lexical operation's budget too.
            stale_read = writer.commit_initial_creation(guard, target)
        assert (stale_read["state"], stale_read["effect"], stale_read["code"]) == (
            "refused", "none", "HOST_AUTHORITY_REFUSED")
        assert stale_read["receipt"] is None
    assert {p.name: p.read_bytes() for p in (canonical / "events").iterdir()} == before
    assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


def test_original_prefix_snapshot_is_detached_and_forged_journal_digest_refuses(
        initial_bootstrap_runtime):
    lifecycle, _, _, canonical, receipt, _ = initial_bootstrap_runtime
    reader = lifecycle.Lifecycle(canonical)
    original = reader.initial_bootstrap()
    altered = reader.initial_bootstrap()
    altered["genesis_checkpoint"]["sha256"] = "f" * 64
    altered["genesis_checkpoint"]["state"]["current"]["root"] = "forged-root"
    assert reader.initial_bootstrap() == original
    assert original["genesis_checkpoint"]["sha256"] == receipt["checkpoint_sha256"]
    # Tamper only with disposable persisted bytes, not a private append/context.
    path = canonical / "events" / "000001.json"
    event = json.loads(path.read_text())
    event["event_sha256"] = "f" * 64
    path.write_text(json.dumps(event))
    forged_bytes = path.read_bytes()
    with pytest.raises(ValueError, match="^journal event sha256 mismatch$"):
        reader.initial_bootstrap()
    assert path.read_bytes() == forged_bytes, "refusal must not repair persisted evidence"


@pytest.mark.parametrize("row_kind", ["genesis", "creation"])
def test_initial_creation_guard_rejects_forged_original_row(initial_bootstrap_runtime, row_kind):
    from tools import hierarchy_host_authority as host

    lifecycle, binding, reservations, canonical, _, requests = initial_bootstrap_runtime
    target = next(row for row in reservations if row.actor_cid == "fixture-root")
    plan_ref = json.loads((canonical / "policy.json").read_text())["authority"][0]
    writer = lifecycle.ProtectedCanonicalBootstrapWriter(canonical)
    if row_kind == "creation":
        with binding.authority.initial_creation_fence(binding.owned_runtime, plan_ref, target) as guard:
            assert writer.commit_initial_creation(guard, target)["state"] == "recorded"
    reader = lifecycle.Lifecycle(canonical)
    before = {p.name: p.read_bytes() for p in (canonical / "events").iterdir()}
    with pytest.raises(host.HostAuthorityError) as caught:
        with binding.authority.initial_creation_fence(binding.owned_runtime, plan_ref, target) as guard:
            guard.require_initial_identity_current(target)
            with lifecycle.writer_lock(canonical):
                guard.require_initial_identity_current(target)
                policy, state = reader.load()
                snapshot = reader.initial_bootstrap()
                if row_kind == "creation":
                    original = next(row for row in snapshot["creations"] if row["actor_cid"] == target.actor_cid)
                    forged = copy.deepcopy(original)
                    forged["receipt"]["sequence"] += 1
                else:
                    original = next(row for row in snapshot["reservations"] if row["actor_cid"] == target.actor_cid)
                    forged = copy.deepcopy(original)
                    forged["profile_sha256"] = "f" * 64
                guard.require_initial_creation_current(target, policy, state, None)
                guard.require_initial_creation_current(target, policy, state, original)
                guard.require_initial_creation_current(target, policy, state, forged)
    assert caught.value.code == "CANONICAL_CORRELATION_MISMATCH"
    assert {p.name: p.read_bytes() for p in (canonical / "events").iterdir()} == before
    assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


@pytest.mark.parametrize("initial_owned_runtime", [5, 128], indirect=True)
def test_reserved_genesis_complete_capacity_boundaries(initial_owned_runtime):
    lifecycle, binding, reservations, canonical, plan_ref, requests, writer_type = initial_owned_runtime
    receipt = writer_type(canonical, binding.authority).initialize_reserved_genesis(
        binding.owned_runtime, reservations, plan_ref)
    reader = lifecycle.Lifecycle(canonical)
    policy, state = reader.load()
    snapshot = reader.initial_bootstrap()
    assert len(receipt["enrollments"]) == len(snapshot["reservations"]) == len(policy["actors"])
    assert len(policy["actors"]) in {5, 128}
    assert [row["actor_cid"] for row in snapshot["reservations"]] == sorted(policy["actors"])
    assert receipt["checkpoint_sha256"] == snapshot["genesis_checkpoint"]["sha256"]
    assert state["sequence"] == 1 and snapshot["creations"] == []
    assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


def test_reserved_genesis_guard_exit_deadline_keeps_publication_unknown(initial_owned_runtime,
                                                                     monkeypatch):
    lifecycle, binding, reservations, canonical, plan_ref, requests, writer_type = initial_owned_runtime
    real_unlink = os.unlink
    real_ns, real_seconds = time.monotonic_ns, time.monotonic
    offset_ns = 0
    releases = []

    def expire_after_canonical_release(path, *args, **kwargs):
        nonlocal offset_ns
        answer = real_unlink(path, *args, **kwargs)
        if Path(path) == canonical / ".write.lock":
            releases.append(str(path))
            # Real publication and the last in-lock identity check already ran.
            # Only the external clock changes before the actual H fence exits.
            offset_ns = 6000000000
        return answer

    with monkeypatch.context() as clock:
        clock.setattr(time, "monotonic_ns", lambda: real_ns() + offset_ns)
        clock.setattr(time, "monotonic", lambda: real_seconds() + offset_ns / 1000000000)
        clock.setattr(os, "unlink", expire_after_canonical_release)
        with pytest.raises(lifecycle.CanonicalGenesisError) as caught:
            writer_type(canonical, binding.authority).initialize_reserved_genesis(
                binding.owned_runtime, reservations, plan_ref)
    assert releases == [str(canonical / ".write.lock")]
    assert (caught.value.state, caught.value.effect, caught.value.code) == (
        "unknown", "possible", "GENESIS_PUBLICATION_UNKNOWN")
    snapshot = lifecycle.Lifecycle(canonical).initial_bootstrap()
    assert snapshot["genesis_receipt"]["sequence"] == 1
    assert len(snapshot["reservations"]) == 6 and snapshot["creations"] == []
    assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


def test_initial_creation_late_canonical_exit_budget_recovers_original(
        initial_bootstrap_runtime, monkeypatch):
    lifecycle, binding, reservations, canonical, _, requests = initial_bootstrap_runtime
    target = next(row for row in reservations if row.actor_cid == "fixture-root")
    plan_ref = json.loads((canonical / "policy.json").read_text())["authority"][0]
    writer = lifecycle.ProtectedCanonicalBootstrapWriter(canonical)
    real_unlink = os.unlink
    real_ns, real_seconds = time.monotonic_ns, time.monotonic
    offset_ns = 0
    releases = []

    def expire_after_canonical_release(path, *args, **kwargs):
        nonlocal offset_ns
        answer = real_unlink(path, *args, **kwargs)
        if Path(path) == canonical / ".write.lock":
            releases.append(str(path))
            offset_ns = 6000000000
        return answer

    with monkeypatch.context() as clock:
        clock.setattr(time, "monotonic_ns", lambda: real_ns() + offset_ns)
        clock.setattr(time, "monotonic", lambda: real_seconds() + offset_ns / 1000000000)
        with monkeypatch.context() as persistence:
            persistence.setattr(os, "unlink", expire_after_canonical_release)
            with binding.authority.initial_creation_fence(binding.owned_runtime, plan_ref, target) as guard:
                unknown = writer.commit_initial_creation(guard, target)
        assert (unknown["state"], unknown["effect"], unknown["code"]) == (
            "unknown", "possible", "INITIAL_CREATION_PUBLICATION_UNKNOWN")
        assert unknown["receipt"] is None
        before = {p.name: p.read_bytes() for p in (canonical / "events").iterdir()}
        original = lifecycle.Lifecycle(canonical).initial_bootstrap()["creations"][0]["receipt"]
        # A new real H scope has a current operation budget; the original
        # reservation is still expired and can supply only its original receipt.
        with binding.authority.initial_creation_fence(binding.owned_runtime, plan_ref, target) as guard:
            recovered = writer.commit_initial_creation(guard, target)
    assert releases == [str(canonical / ".write.lock")]
    assert (recovered["state"], recovered["effect"]) == ("recovered", "none")
    assert recovered["event_id"] == unknown["event_id"]
    assert recovered["receipt"] == original
    assert {p.name: p.read_bytes() for p in (canonical / "events").iterdir()} == before
    assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


@pytest.mark.parametrize(("change", "missing", "correlations"), [
    (None, None, (None, None, None)),
    ([], None, (None, None, None)),
    ({}, "event_id", (None, "request-one", "a" * 64)),
    ({"actor_cid": "fixture-root"}, None, ("decision-one", "request-one", "a" * 64)),
    ({"event_id": True}, None, (None, "request-one", "a" * 64)),
    ({"event_id": "UPPER"}, None, (None, "request-one", "a" * 64)),
    ({"event_id": "a" * 81}, None, (None, "request-one", "a" * 64)),
    ({"request_id": ""}, None, ("decision-one", None, "a" * 64)),
    ({"request_id": False}, None, ("decision-one", None, "a" * 64)),
    ({"request_sha256": "A" * 64}, None, ("decision-one", "request-one", None)),
    ({"request_sha256": "a" * 63}, None, ("decision-one", "request-one", None)),
    ({"request_sha256": True}, None, ("decision-one", "request-one", None)),
    ({"decision": "APPROVE"}, None, ("decision-one", "request-one", "a" * 64)),
    ({"decision": True}, None, ("decision-one", "request-one", "a" * 64)),
    ({"reason": ""}, None, ("decision-one", "request-one", "a" * 64)),
    ({"reason": "a" * 1025}, None, ("decision-one", "request-one", "a" * 64)),
    ({"reason": "invalid\0reason"}, None, ("decision-one", "request-one", "a" * 64)),
    ({"reason": False}, None, ("decision-one", "request-one", "a" * 64)),
], ids=["null", "list", "missing-event", "extra-actor", "boolean-event",
        "uppercase-event", "long-event", "empty-request", "boolean-request",
        "uppercase-hash", "short-hash", "boolean-hash", "uppercase-decision",
        "boolean-decision", "empty-reason", "long-reason", "nul-reason", "boolean-reason"])
def test_protected_decision_malformed_command_precedes_authority(
        initial_bootstrap_runtime, change, missing, correlations):
    """A missing LIVE invocation cannot mask malformed inert command data."""
    lifecycle, binding, _, canonical, _, requests = initial_bootstrap_runtime
    command = {"event_id": "decision-one", "request_id": "request-one",
               "request_sha256": "a" * 64, "decision": "approve", "reason": "owner decision"}
    if type(change) is dict:
        command.update(change)
        if missing is not None:
            del command[missing]
    else:
        command = change
    before = {str(path.relative_to(canonical)): path.read_bytes()
              for path in canonical.rglob("*") if path.is_file()}
    # This is the proposed public producer, deliberately absent until its
    # actual LIVE H dependency exists. None is only a negative invocation.
    writer = lifecycle.ProtectedCanonicalDecisionWriter(canonical, binding.authority)
    answer = writer.commit_decision(None, command)
    event_id, request_id, request_sha256 = correlations
    assert type(answer) is dict
    assert answer == {"schema": "aegis.protected-decision-commit/v1",
                      "state": "refused", "effect": "none", "code": "INVALID_DECISION_INPUT",
                      "reason": "invalid decision command", "event_id": event_id,
                      "request_id": request_id, "request_sha256": request_sha256,
                      "receipt": None, "native_qualified": False}
    assert {str(path.relative_to(canonical)): path.read_bytes()
            for path in canonical.rglob("*") if path.is_file()} == before
    assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


def test_protected_decision_reserved_root_is_not_live_authority(initial_bootstrap_runtime):
    """A real ROOT reservation cannot authorize a LIVE decision or target read."""
    lifecycle, binding, reservations, canonical, _, requests = initial_bootstrap_runtime
    root_reservation = next(row for row in reservations if row.actor_cid == "fixture-root")
    command = {"event_id": "reserved-root-decision", "request_id": "unpublished-authority",
               "request_sha256": "a" * 64, "decision": "approve", "reason": "owner decision"}
    before = {str(path.relative_to(canonical)): path.read_bytes()
              for path in canonical.rglob("*") if path.is_file()}
    writer = lifecycle.ProtectedCanonicalDecisionWriter(canonical, binding.authority)
    answer = writer.commit_decision(root_reservation, command)
    # Current live identity must be checked before UNKNOWN_REQUEST or a receipt
    # can be disclosed, even though this reservation names the real ROOT role.
    assert type(answer) is dict
    assert answer == {"schema": "aegis.protected-decision-commit/v1",
                      "state": "refused", "effect": "none", "code": "UNAUTHORIZED_ROLE",
                      "reason": "decision requires a current ROOT HostInvocation",
                      "event_id": command["event_id"], "request_id": command["request_id"],
                      "request_sha256": command["request_sha256"], "receipt": None,
                      "native_qualified": False}
    assert lifecycle.Lifecycle(canonical).load()[1]["decisions"] == []
    assert {str(path.relative_to(canonical)): path.read_bytes()
            for path in canonical.rglob("*") if path.is_file()} == before
    assert [row["method"] for row in requests] == ["describe", "reserve_initial"]


@contextmanager
def canonical_live_decision(tmp_path, monkeypatch, *, changes=None, seed=False,
                            expired=False, capped=False, future=False):
    """Real H/canonical objects; only external appserver bytes and UTC clock vary."""
    from tools import hierarchy_host_authority as host
    from tests.integration.test_hierarchy_host_authority import live_control_runtime

    with live_control_runtime(host, tmp_path, monkeypatch) as (lifecycle, binding, requests):
        ledger = lifecycle.Lifecycle(binding.canonical_root)
        policy, state = ledger.load()
        identifier = "fixture-authority"
        if expired:
            identifier = "expired-authority"
            value = copy.deepcopy(state["requests"]["fixture-authority"]["request"])
            value["id"] = value["authority"] = identifier
            value["continuation"]["expires_at"] = "2000-01-01T00:00:00Z"
            ledger.record({"id": "publish-expired-authority", "actor": "fixture-coordinator",
                           "generation": 1, "custody": {"cid": "fixture-root", "generation": 1},
                           "event": {"type": "publish", "request": raw_request(value)}})
            _, state = ledger.load()
        command = {"event_id": "live-decision-1", "request_id": identifier,
                   "request_sha256": state["requests"][identifier]["raw"]["sha256"],
                   "decision": "approve", "reason": "reviewed"}
        original = None
        if seed:
            original = ledger.record({
                "id": command["event_id"], "actor": "fixture-root", "generation": 1,
                "custody": {"cid": "fixture-root", "generation": 1},
                "event": {"type": "decision", **{k: command[k] for k in
                          ("request_id", "request_sha256", "decision", "reason")}}})
        if capped:
            ledger.record({"id": "meter-root-cap", "actor": "fixture-operator", "generation": 1,
                           "custody": {"cid": "fixture-root", "generation": 1},
                           "event": {"type": "meter", "subject": "fixture-root",
                                     "active_seconds": policy["actors"]["fixture-root"]["cap_seconds"],
                                     "open_since": None}})
        command.update(changes or {})
        # New public constructor is observed after real INITIAL, before LIVE.
        writer = lifecycle.ProtectedCanonicalDecisionWriter(binding.canonical_root, binding.authority)
        observed = []
        real_write = os.write

        def external_appserver_bytes(fd, data):
            # Interpose actual external stdio bytes, never H authority or a loader.
            if b'"item/tool/call"' in data:
                frame = json.loads(data)
                assert frame["method"] == "item/tool/call"
                frame["params"]["arguments"] = copy.deepcopy(command)
                observed.append(copy.deepcopy(command))
                data = (json.dumps(frame, separators=(",", ":")) + "\n").encode()
            return real_write(fd, data)

        with monkeypatch.context() as wire:
            wire.setattr(os, "write", external_appserver_bytes)
            session = binding.open_live_session("fixture-root")
            invocation = session.receive_invocation()
            assert type(invocation) is host.HostInvocation
            assert invocation.actor_cid == "fixture-root"
            assert type(invocation.rpc_id) is int and invocation.rpc_id == 0
            assert invocation.event_id == command["event_id"]
            assert invocation.decision_recovery_event_id is None
            assert observed == [command]
            if future:
                # This is the real UTC clock API used by the journal, not a
                # mocked permission predicate or canonical reducer.
                import datetime as utc
                clock = sys.modules[lifecycle.timestamp.__module__]
                real_datetime = utc.datetime

                class FutureUTC(real_datetime):
                    @classmethod
                    def now(cls, tz=None):
                        return real_datetime(2100, 1, 1, tzinfo=tz or utc.timezone.utc)

                wire.setattr(clock, "datetime", FutureUTC)
            yield lifecycle, binding, session, invocation, command, original, requests, writer


def canonical_files(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def assert_decision_result(answer, command, state, effect, code, reason, receipt=None):
    assert type(answer) is dict
    assert answer == {"schema": "aegis.protected-decision-commit/v1", "state": state,
                      "effect": effect, "code": code, "reason": reason,
                      "event_id": command["event_id"], "request_id": command["request_id"],
                      "request_sha256": command["request_sha256"], "receipt": receipt,
                      "native_qualified": False}


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_protected_decision_real_current_root_records_canonical_once(tmp_path, monkeypatch, decision):
    with canonical_live_decision(tmp_path, monkeypatch, changes={"decision": decision}) as values:
        lifecycle, binding, _, invocation, command, _, requests, writer = values
        before = lifecycle.Lifecycle(binding.canonical_root).load()[1]
        original_raw = copy.deepcopy(before["requests"]["fixture-authority"]["raw"])
        answer = writer.commit_decision(invocation, command)
        after = lifecycle.Lifecycle(binding.canonical_root).load()[1]
        receipt = after["receipts"][command["event_id"]]
        assert_decision_result(answer, command, "recorded", "canonical_decision", None,
                               "canonical decision recorded", receipt)
        assert after["sequence"] == before["sequence"] + 1
        assert receipt["sequence"] == after["sequence"] and receipt["execution_enabled"] is False
        assert len(after["decisions"]) == 1 and after["decisions"][0]["decision"] == decision
        assert after["requests"]["fixture-authority"]["raw"] == original_raw
        assert after["requests"]["fixture-authority"]["intent"] is None
        assert [row["method"] for row in requests] == [
            "describe", "reserve_initial", "bind_initial", "start_initial",
            "describe_live", "enroll_live", "pending_call"]


@pytest.mark.parametrize("capped,future", [(False, False), (True, False),
                                         (False, True), (True, True)])
def test_protected_decision_original_receipt_read_bypasses_only_new_checks(
        tmp_path, monkeypatch, capped, future):
    with canonical_live_decision(tmp_path, monkeypatch, seed=True,
                                 capped=capped, future=future) as values:
        lifecycle, binding, _, invocation, command, original, _, writer = values
        before = canonical_files(binding.canonical_root)
        answer = writer.commit_decision(invocation, command)
        assert_decision_result(answer, command, "recovered", "none", None,
                               "original canonical receipt recovered", original)
        assert canonical_files(binding.canonical_root) == before


@pytest.mark.parametrize("changes", [
    {"request_id": "another-authority"}, {"request_sha256": "f" * 64},
    {"decision": "deny"}, {"reason": "changed incoming reason"},
], ids=["request", "hash", "decision", "reason"])
def test_protected_decision_original_row_precedes_changed_incoming_payload(
        tmp_path, monkeypatch, changes):
    with canonical_live_decision(tmp_path, monkeypatch, seed=True, changes=changes) as values:
        lifecycle, binding, _, invocation, command, _, _, writer = values
        before = canonical_files(binding.canonical_root)
        answer = writer.commit_decision(invocation, command)
        assert_decision_result(answer, command, "refused", "none", "REPLAY_CONFLICT",
                               "event id conflicts with different decision payload")
        assert canonical_files(binding.canonical_root) == before


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_protected_decision_new_approve_and_deny_require_current_canonical_cap(
        tmp_path, monkeypatch, decision):
    with canonical_live_decision(tmp_path, monkeypatch, capped=True,
                                 changes={"decision": decision}) as values:
        lifecycle, binding, _, invocation, command, _, _, writer = values
        before = canonical_files(binding.canonical_root)
        answer = writer.commit_decision(invocation, command)
        assert_decision_result(answer, command, "refused", "none", "CAP_REACHED",
                               "actor cumulative active cap reached")
        assert canonical_files(binding.canonical_root) == before


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_protected_decision_new_expiry_applies_only_to_approval(tmp_path, monkeypatch, decision):
    with canonical_live_decision(tmp_path, monkeypatch, expired=True,
                                 changes={"decision": decision}) as values:
        lifecycle, binding, _, invocation, command, _, _, writer = values
        before = canonical_files(binding.canonical_root)
        answer = writer.commit_decision(invocation, command)
        if decision == "approve":
            assert_decision_result(answer, command, "refused", "none", "BOUNDED_AUTHORITY_EXPIRED",
                                   "bounded authority expired")
            assert canonical_files(binding.canonical_root) == before
        else:
            receipt = lifecycle.Lifecycle(binding.canonical_root).load()[1]["receipts"][command["event_id"]]
            assert_decision_result(answer, command, "recorded", "canonical_decision", None,
                                   "canonical decision recorded", receipt)


@pytest.mark.parametrize("cut", ["before-link", "after-link", "canonical-exit", "late-clock"])
def test_protected_decision_publication_and_scope_exit_keep_original_unknown(
        tmp_path, monkeypatch, cut):
    with canonical_live_decision(tmp_path, monkeypatch) as values:
        lifecycle, binding, _, invocation, command, _, _, writer = values
        before = lifecycle.Lifecycle(binding.canonical_root).load()[1]
        destination = binding.canonical_root / "events" / ("%06d.json" % (before["sequence"] + 1))
        real_link, real_unlink = os.link, os.unlink
        real_ns, real_seconds = time.monotonic_ns, time.monotonic
        offset = 0

        def publication(source, target, *args, **kwargs):
            if Path(target) == destination:
                if cut == "before-link":
                    raise OSError("external link boundary failed")
                result = real_link(source, target, *args, **kwargs)
                if cut == "after-link":
                    raise OSError("external link reply lost")
                return result
            return real_link(source, target, *args, **kwargs)

        def scope_exit(path, *args, **kwargs):
            nonlocal offset
            result = real_unlink(path, *args, **kwargs)
            if Path(path) == binding.canonical_root / ".write.lock":
                if cut == "canonical-exit":
                    raise OSError("external canonical unlock reply lost")
                if cut == "late-clock":
                    offset = 6000000000
            return result

        with monkeypatch.context() as boundary:
            boundary.setattr(os, "link", publication)
            boundary.setattr(os, "unlink", scope_exit)
            boundary.setattr(time, "monotonic_ns", lambda: real_ns() + offset)
            boundary.setattr(time, "monotonic", lambda: real_seconds() + offset / 1000000000)
            answer = writer.commit_decision(invocation, command)
        assert_decision_result(answer, command, "unknown", "possible", "PUBLICATION_UNKNOWN",
                               "canonical decision publication is unresolved")
        if cut == "before-link":
            assert not destination.exists()
        else:
            assert destination.is_file()
            assert lifecycle.Lifecycle(binding.canonical_root).load()[1]["receipts"][command["event_id"]]


@pytest.mark.parametrize("field,changed", [
    ("event_id", "changed-event"), ("request_id", "changed-request"),
    ("request_sha256", "f" * 64), ("decision", "deny"),
    ("reason", "changed after actual receive"),
])
def test_public_direct_writer_cannot_change_actual_owned_frame_command(
        tmp_path, monkeypatch, field, changed):
    with canonical_live_decision(tmp_path, monkeypatch) as values:
        lifecycle, binding, _, invocation, command, _, requests, writer = values
        before = canonical_files(binding.canonical_root)
        methods = [row["method"] for row in requests]
        supplied = dict(command, **{field: changed})
        # Change only the direct public input AFTER actual owned receive.
        # Incoming stdio/control bytes, invocation and authority stay original.
        answer = writer.commit_decision(invocation, supplied)
        assert_decision_result(answer, supplied, "refused", "none", "STALE_INVOCATION",
                               "decision invocation is stale")
        assert canonical_files(binding.canonical_root) == before
        assert [row["method"] for row in requests] == methods


@pytest.mark.parametrize("branch", ["exact-original", "changed-reason"])
def test_public_direct_writer_after_successful_guard_history_keeps_unknown(
        tmp_path, monkeypatch, branch):
    from tools import hierarchy_host_authority as host

    with canonical_live_decision(tmp_path, monkeypatch) as values:
        lifecycle, binding, session, invocation, submitted, _, requests, writer = values
        ledger = lifecycle.Lifecycle(binding.canonical_root)
        before = ledger.load()
        before_files = canonical_files(binding.canonical_root)
        methods = [row["method"] for row in requests]
        original_event_id = invocation.event_id
        assert original_event_id == submitted["event_id"]

        with session.authority.effect_fence(invocation, "decision"):
            with lifecycle.writer_lock(binding.canonical_root):
                policy, state = ledger.load()
                session.authority.require_current(invocation, policy, state, None)
                session.authority.require_current(
                    invocation, policy, state, state["requests"][submitted["request_id"]])
        assert ledger.load() == before
        assert canonical_files(binding.canonical_root) == before_files
        assert [row["method"] for row in requests] == methods

        command = dict(submitted)
        if branch == "changed-reason":
            command["reason"] = "changed after successful original guard exit"
        answer = writer.commit_decision(invocation, command)
        after = ledger.load()
        after_files = canonical_files(binding.canonical_root)
        direct_methods = [row["method"] for row in requests]

        # Observe public lifecycle before fixture-finally closes the binding.
        with pytest.raises(host.HostAuthorityError) as no_completion:
            session.reply(invocation, {"success": False, "contentItems": [
                {"type": "inputText", "text": "unresolved"}]})
        assert no_completion.value.code == "STALE_INVOCATION"
        assert [row["method"] for row in requests] == direct_methods

        assert_decision_result(answer, command, "unknown", "possible",
                               "PUBLICATION_UNKNOWN",
                               "canonical decision publication is unresolved")
        assert invocation.event_id == original_event_id
        assert after == before
        assert after_files == before_files
        assert ledger.load() == before
        assert canonical_files(binding.canonical_root) == before_files
        assert direct_methods == methods
        assert methods[-1] == "pending_call"
        assert not any(row["method"] == "retire_call" for row in requests)
