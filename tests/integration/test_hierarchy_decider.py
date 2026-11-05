"""The team Decider approves within an explicit delegation and escalates everything else (option A).

A delegation is an ordinary canonical request (`operation: delegate-merge`) that ROOT approves. The
Decider records `delegated_decision`, which never admits work: it never touches `decisions`,
`consumed` or `approved_authority`. Actor identities are configuration-bound here, as for every
journal actor; these tests show what the journal accepts and refuses, not what a host enforces.
"""
import copy
import os
import sys
import time

import pytest

from tests.integration.test_hierarchy_lifecycle import SOURCE, Ledger, raw_request, request
from tests.integration.test_hierarchy_mailbox import ROOT


sys.path.insert(0, str(ROOT / "tools"))
import hierarchy_lifecycle  # noqa: E402
import hierarchy_roles  # noqa: E402


pytestmark = pytest.mark.skipif(os.name != "posix", reason="durable lifecycle mutation requires POSIX directory fsync")
FUTURE = "2099-01-01T00:00:00Z"
LEGACY_STATE_KEYS = {"sequence", "head", "current", "requests", "decisions", "consumed", "receipts", "meters",
                     "successions"}


def decider_policy(tmp_path):
    (tmp_path / "probe").mkdir(exist_ok=True)
    policy = Ledger(tmp_path / "probe", initialize=False).policy
    decider = {**copy.deepcopy(policy["actors"]["reviewer-1"]), "role": "decider"}
    policy["actors"]["decider-1"] = decider
    policy["actors"]["decider-2"] = {**copy.deepcopy(decider), "generation": 2}
    policy["current"]["decider"] = "decider-1"
    policy["successors"]["decider-1"] = "decider-2"
    return policy


def delegation(identifier="delegation-1", max_starts=2, expires_at=FUTURE, **changes):
    fields = {"operation": "delegate-merge", "phase": "integration", "paths": ["/fixture/engine"],
              "next_decision": "approve in-scope merges",
              "continuation": {"members": [], "max_starts": max_starts, "expires_at": expires_at}}
    return request(identifier, **{**fields, **changes})


def merge(identifier="merge-1", **changes):
    return request(identifier, **{"operation": "merge", "phase": "integration", **changes})


class Decider(Ledger):
    def __init__(self, tmp_path):
        policy = decider_policy(tmp_path)
        super().__init__(tmp_path, policy_changes={key: policy[key] for key in ("actors", "current", "successors")})

    def delegate(self, value=None):
        value = value or delegation()
        self.publish(value)
        self.approve(value)
        return value

    def decide(self, target, granted, choice="approve", actor="decider-1", commit=None, expect=0, **changes):
        body = {"request_id": target["id"], "request_sha256": raw_request(target)["sha256"],
                "delegation_id": granted["id"], "delegation_sha256": raw_request(granted)["sha256"],
                "commit": commit or target["source"]["commit"], "review": self.evidence,
                "decision": choice, "reason": "fixture " + choice}
        body.update(changes)
        return self.event("delegated_decision", actor=actor, expect=expect, **body)

    def refused(self, target, granted, choice="approve", **kwargs):
        before = self.files()
        result = self.decide(target, granted, choice, expect=2, **kwargs)
        assert self.files() == before
        return result["error"]


@pytest.fixture
def decider(tmp_path):
    return Decider(tmp_path)


def test_an_approval_within_the_delegation_is_recorded_without_admitting_anything(decider):
    granted = decider.delegate()
    target = merge()
    decider.publish(target)
    before = decider.status()
    decider.decide(target, granted)
    status = decider.status()
    [entry] = status["delegated_decisions"]
    assert entry["decision"] == "approve" and entry["actor"] == "decider-1"
    assert (entry["request_id"], entry["delegation_id"], entry["commit"]) == ("merge-1", "delegation-1", "a" * 40)
    assert entry["review"] == decider.evidence
    # Non-admitting: ROOT's decisions, the consumed budgets and admission are exactly as before.
    assert status["decisions"] == before["decisions"] and status["consumed"] == before["consumed"] == {}
    assert status["continuation_holds"]["merge-1"] == "no approved bounded authority"
    decider.admit(target, expect=2)


def test_an_approval_under_a_parent_path_and_on_replay_survives_restart(decider):
    granted = decider.delegate(delegation(paths=["/fixture/engine", "/fixture/docs"]))
    target = merge(paths=["/fixture/engine/tests", "/fixture/docs"])
    decider.publish(target)
    decider.decide(target, granted)
    first = decider.cli("checkpoint")
    assert decider.cli("checkpoint") == first
    assert [d["request_id"] for d in first["state"]["delegated_decisions"]] == ["merge-1"]


@pytest.mark.parametrize("change,error", [
    ({"paths": ["/fixture/other"]}, "target path is outside the delegation's paths"),
    ({"paths": ["/fixture/engine-two"]}, "target path is outside the delegation's paths"),
    ({"paths": ["/fixture/engine/tests", "/elsewhere"]}, "target path is outside the delegation's paths"),
    ({"team": "docs"}, "delegation is for another team"),
])
def test_an_out_of_scope_target_can_only_be_escalated(decider, change, error):
    granted = decider.delegate()
    target = merge(**change)
    decider.publish(target)
    assert decider.refused(target, granted) == error
    decider.decide(target, granted, "escalate")
    assert [d["decision"] for d in decider.status()["delegated_decisions"]] == ["escalate"]


def test_an_expired_delegation_is_refused_and_can_only_escalate(decider):
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3))
    granted = decider.delegate(delegation(expires_at=expires))
    target = merge()
    decider.publish(target)
    time.sleep(3.5)
    assert decider.refused(target, granted) == "delegation expired"
    decider.decide(target, granted, "escalate")


def test_an_exhausted_delegation_is_refused_and_escalations_do_not_count(decider):
    granted = decider.delegate(delegation(max_starts=1))
    first, second, third = merge("merge-1"), merge("merge-2"), merge("merge-3")
    for value in (first, second, third):
        decider.publish(value)
    decider.decide(first, granted, "escalate")
    decider.decide(second, granted)
    assert decider.refused(third, granted) == "delegation has no approvals left"
    decider.decide(third, granted, "escalate")


def test_a_revoked_or_undecided_delegation_is_refused(decider):
    pending = delegation("delegation-2")
    decider.publish(pending)
    granted = decider.delegate()
    target = merge()
    decider.publish(target)
    assert decider.refused(target, pending) == "delegation is not approved by ROOT"
    decider.event("decision", actor="root-1", decision="deny", reason="delegation withdrawn", **decider.target(granted))
    assert decider.refused(target, granted) == "delegation is not approved by ROOT"
    decider.decide(target, granted, "escalate")


@pytest.mark.parametrize("change,error", [
    ({"operation": "merge"}, "delegation must be a delegate-merge authority request"),
    ({"authority": "other-authority"}, "delegation must be a delegate-merge authority request"),
])
def test_only_a_delegate_merge_authority_request_delegates(decider, change, error):
    granted = delegation(**change)
    decider.publish(granted)
    if granted["authority"] == granted["id"]:
        decider.approve(granted)
    target = merge()
    decider.publish(target)
    assert decider.refused(target, granted) == error


def test_the_approval_must_name_the_targets_exact_source_commit(decider):
    granted = decider.delegate()
    target = merge()
    decider.publish(target)
    assert decider.refused(target, granted, commit="d" * 40) == "reviewed commit is not the target's source commit"


@pytest.mark.parametrize("field,value,error", [
    ("request_sha256", "e" * 64, "request sha256 mismatch"),
    ("delegation_sha256", "e" * 64, "delegation sha256 mismatch"),
    ("delegation_id", "missing-delegation", "unknown delegation id"),
    ("decision", "deny", "delegated decision must be approve or escalate"),
    ("review", [], "evidence requires bounded nonempty references"),
])
def test_malformed_delegated_decisions_are_refused(decider, field, value, error):
    granted = decider.delegate()
    target = merge()
    decider.publish(target)
    assert decider.refused(target, granted, "escalate", **{field: value}) == error


def test_a_target_gets_one_delegated_decision_and_none_once_root_decided(decider):
    granted = decider.delegate()
    target, decided = merge("merge-1"), merge("merge-2")
    decider.publish(target)
    decider.publish(decided)
    decider.decide(target, granted)
    assert decider.refused(target, granted, "escalate") == "target already has a delegated decision"
    decider.approve(decided)
    assert decider.refused(decided, granted) == "ROOT already decided the target"
    assert decider.refused(granted, granted) == "a delegation cannot be its own target"


def test_the_decider_cannot_decide_a_request_it_published(decider, tmp_path):
    # Only the coordinator and router can publish, so the journal never produces this state; the
    # check is the not-requester rule held in the journal itself, shown on a forged state.
    granted = decider.delegate()
    target = merge()
    decider.publish(target)
    policy, state = hierarchy_lifecycle.Lifecycle(decider.path).load()
    state["requests"]["merge-1"]["publisher"] = "decider-1"
    envelope = {"id": "forged", "actor": "decider-1", "generation": 1, "custody": {"cid": "root-1", "generation": 1},
                "event": {"type": "delegated_decision", "request_id": "merge-1",
                          "request_sha256": raw_request(target)["sha256"], "delegation_id": granted["id"],
                          "delegation_sha256": raw_request(granted)["sha256"], "commit": SOURCE["commit"],
                          "review": decider.evidence, "decision": "approve", "reason": "forged"}}
    with pytest.raises(ValueError, match="the decider cannot decide a request it published"):
        hierarchy_lifecycle.reduce_event(policy, state, envelope, "2030-01-01T00:00:00Z")


@pytest.mark.parametrize("kind,body", [
    ("decision", {"decision": "approve", "reason": "self approval"}),
    ("admit", {"source": SOURCE, "gates": {}}),
    ("intent", {"intent_id": "attempt-1"}),
    ("publish", None),
])
def test_the_decider_cannot_decide_admit_start_or_publish(decider, kind, body):
    target = merge()
    decider.publish(target)
    payload = {"request": raw_request(merge("merge-2"))} if body is None else {**decider.target(target), **body}
    result = decider.event(kind, actor="decider-1", expect=2, **payload)
    assert result["error"] == "role decider cannot record " + kind


@pytest.mark.parametrize("actor", ["root-1", "coordinator-1", "router-1", "reviewer-1", "operator-1"])
def test_only_the_decider_records_delegated_decisions(decider, actor):
    granted = decider.delegate()
    target = merge()
    decider.publish(target)
    role = actor.split("-")[0]
    assert decider.refused(target, granted, "escalate", actor=actor) == "role %s cannot record delegated_decision" % role


def test_a_succeeded_decider_is_fenced(decider):
    granted = decider.delegate()
    target = merge()
    decider.publish(target)
    checkpoint = decider.cli("checkpoint")["sha256"]
    decider.event("succeed", actor="decider-2", predecessor="decider-1", checkpoint_sha256=checkpoint)
    assert decider.refused(target, granted, "escalate") == "actor generation is fenced"
    decider.decide(target, granted, actor="decider-2")


def test_a_policy_without_a_decider_fences_every_decider_actor(tmp_path):
    policy = decider_policy(tmp_path)
    del policy["current"]["decider"]
    del policy["successors"]["decider-1"]
    ledger = Ledger(tmp_path, policy_changes={key: policy[key] for key in ("actors", "current", "successors")})
    target = merge()
    ledger.publish(target)
    result = ledger.event("delegated_decision", actor="decider-1", expect=2, **ledger.target(target),
                          delegation_id="x", delegation_sha256="e" * 64, commit="a" * 40, review=ledger.evidence,
                          decision="escalate", reason="no decider configured")
    assert result["error"] == "actor generation is fenced"


# Legacy compatibility: a five-role journal recorded before this change, replayed by the new code.
# The checkpoint hash was computed by the journal code at bfb8721, before the decider existed.
LEGACY_CHECKPOINT_SHA256 = "7b2cc0d9d0fc7fb46ba8ac51691961aca4ef62139b4a50e2af9e99f8e50cb5ee"


def legacy_journal(root):
    from tools.hierarchy_mailbox import digest, encoded
    evidence = [{"path": "/fixture/authority.json", "sha256": "f" * 64}]
    actors = {}
    for role in ("root", "router", "coordinator", "operator", "reviewer"):
        actors[role + "-1"] = {"role": role, "generation": 1, "cap_seconds": 3600,
                               "profile": {"model": "fixture-model", "effort": "medium" if role == "router" else "max",
                                           "tier": "ultrafast",
                                           "filesystem": "read-only" if role == "root" else "workspace-write",
                                           "tools": ["read", "decide", "attest"] if role == "root" else []}}
    policy = {"schema": "aegis.lifecycle-policy/v1", "source": SOURCE, "authority": evidence, "actors": actors,
              "current": {role: role + "-1" for role in ("root", "router", "coordinator", "operator", "reviewer")},
              "successors": {}}
    (root / "events").mkdir(parents=True)
    (root / "policy.json").write_bytes(encoded(policy) + b"\n")
    value = request()
    envelopes = [("coordinator-1", {"type": "publish", "request": raw_request(value)}),
                 ("root-1", {"type": "decision", "decision": "approve", "reason": "legacy approval",
                             "request_id": value["id"], "request_sha256": raw_request(value)["sha256"]}),
                 ("router-1", {"type": "route", "to": "engine/orchestrator", "request_id": value["id"],
                               "request_sha256": raw_request(value)["sha256"]})]
    previous = "0" * 64
    for sequence, (actor, event) in enumerate(envelopes, 1):
        envelope = {"id": "legacy-%d" % sequence, "actor": actor, "generation": 1,
                    "custody": {"cid": "root-1", "generation": 1}, "event": event}
        record = {"schema": "aegis.lifecycle-event/v1", "sequence": sequence, "previous": previous,
                  "policy_sha256": digest(policy), "at": "2026-11-01T00:00:0%dZ" % sequence,
                  "envelope": envelope, "event_sha256": digest(envelope)}
        (root / "events" / ("%06d.json" % sequence)).write_bytes(encoded(record) + b"\n")
        previous = digest(record)


def test_a_legacy_five_role_journal_replays_to_the_same_checkpoint(tmp_path):
    legacy_journal(tmp_path / "lifecycle")
    checkpoint = hierarchy_lifecycle.checkpoint(*hierarchy_lifecycle.Lifecycle(tmp_path / "lifecycle").load())
    assert set(checkpoint["state"]) == LEGACY_STATE_KEYS
    assert checkpoint["sha256"] == LEGACY_CHECKPOINT_SHA256


def test_a_decider_policy_adds_no_state_until_a_delegated_decision_is_recorded(decider):
    decider.delegate()
    assert set(decider.cli("checkpoint")["state"]) == LEGACY_STATE_KEYS


def test_the_registry_gives_the_decider_its_journal_role():
    entry = hierarchy_roles.registry()["roles"]["decider"]
    assert entry["lifecycle_role"] == "decider"
    assert entry["approvals"] == ["lifecycle:delegated_decision"]
    assert "lifecycle:decision" in entry["prohibitions"]["approvals"]
    assert hierarchy_lifecycle.PERMISSIONS["delegated_decision"] == {"decider"}
    assert "decider" not in hierarchy_lifecycle.PERMISSIONS["decision"] | hierarchy_lifecycle.PERMISSIONS["admit"]


def test_the_router_status_lists_each_escalation_for_root(tmp_path):
    from tests.integration.test_hierarchy_router import Loop
    policy = decider_policy(tmp_path)
    loop = Loop(tmp_path, policy_changes={key: policy[key] for key in ("actors", "current", "successors")})
    loop.ledger.__class__ = Decider
    granted = loop.ledger.delegate()
    inside, outside = merge("merge-1"), merge("merge-2", paths=["/fixture/other"])
    for value in (inside, outside):
        loop.ledger.publish(value)
    loop.ledger.decide(inside, granted)
    loop.ledger.decide(outside, granted, "escalate", reason="path outside the delegation")
    [escalation] = loop.run("status")["escalations"]
    at = escalation.pop("at")
    assert hierarchy_lifecycle.parse_time(at)
    assert escalation == {"request_id": "merge-2", "request_sha256": raw_request(outside)["sha256"],
                          "team": "engine", "delegation_id": "delegation-1", "actor": "decider-1",
                          "reason": "path outside the delegation", "root_decision": None}
    loop.ledger.approve(outside)
    assert loop.run("status")["escalations"][0]["root_decision"] == "approve"
