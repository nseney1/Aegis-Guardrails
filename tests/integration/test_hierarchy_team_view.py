"""ROOT's read model of the team: what ROOT owes a decision on, where the team stands, and a publish draft.

Every answer comes from the journal read under its lock, the loop's status file and the evidence folder. Nothing
here writes or starts anything, so each test also checks that the journal and the folders it read are unchanged.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import sys

import pytest

from tests.integration.test_hierarchy_decider import Decider, delegation, merge
from tests.integration.test_hierarchy_lifecycle import SOURCE, raw_request, request
from tests.integration.test_hierarchy_mailbox import ROOT


sys.path.insert(0, str(ROOT / "tools"))
import hierarchy_lifecycle  # noqa: E402
import hierarchy_team_view  # noqa: E402


pytestmark = pytest.mark.skipif(os.name != "posix", reason="durable lifecycle mutation requires POSIX directory fsync")
WAIT = 2.0
ACTS = {"root": [], "owner": [], "router": []}


@pytest.fixture
def ledger(tmp_path):
    return Decider(tmp_path)


def journal(ledger):
    return hierarchy_lifecycle.Lifecycle(ledger.path)


def pending(ledger):
    before = ledger.files()
    answer = hierarchy_team_view.pending(journal(ledger), WAIT)
    assert ledger.files() == before
    assert answer["schema"] == "aegis.team-pending/v1"
    return answer["pending"]


def status(ledger, **kwargs):
    before = ledger.files()
    answer = hierarchy_team_view.status(journal(ledger), wait=WAIT, **kwargs)
    assert ledger.files() == before
    assert answer["schema"] == "aegis.team-status/v1"
    return answer


def draft(ledger, fields, **kwargs):
    before = ledger.files()
    try:
        return hierarchy_team_view.draft_request(journal(ledger), fields, wait=WAIT, **kwargs)
    finally:
        assert ledger.files() == before


def refused_draft(ledger, fields, **kwargs):
    with pytest.raises(ValueError) as caught:
        draft(ledger, fields, **kwargs)
    return str(caught.value)


def fields_of(value):
    return {key: item for key, item in value.items() if key != "schema"}


def route(ledger, value):
    ledger.event("route", actor="router-1", to=value["team"] + "/orchestrator", **ledger.target(value))


def deny(ledger, value):
    ledger.event("decision", actor="root-1", decision="deny", reason="the owner said no", **ledger.target(value))


def escalated(ledger):
    """A delegation, one merge the Decider approved inside it and one it escalated to ROOT."""
    granted = ledger.delegate()
    inside, outside = merge("merge-1"), merge("merge-2", paths=["/fixture/other"])
    for value in (inside, outside):
        ledger.publish(value)
    ledger.decide(inside, granted)
    ledger.decide(outside, granted, "escalate", reason="path outside the delegation")
    return granted, inside, outside


def stamp(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def loop_file(folder, *, finished, interval=30, holds=(), current_step=None, step_started=None):
    folder.mkdir(exist_ok=True)
    value = {"schema": "aegis.loop-status/v1", "pass_id": 7, "started_at": finished, "finished_at": finished,
             "interval": interval, "steps": [], "holds": list(holds), "stopped": False,
             "consecutive_journal_unavailable": 0, "current_step": current_step, "step_started_at": step_started}
    (folder / "status.json").write_text(json.dumps(value), encoding="utf-8")
    return folder


def hold(act, kind, **where):
    seen = "2026-11-06T10:00:00.000000Z"
    return {"step": "sweep", "kind": kind, "detail": kind + " detail", "act": act, "first_seen": seen,
            "last_seen": seen, "count": 2, **where}


def snapshot(folder):
    return {str(path.relative_to(folder)): path.read_bytes() for path in folder.rglob("*") if path.is_file()}


# pending


def test_a_published_request_is_owed_with_the_exact_root_decide_arguments(ledger):
    value = request("feature-1")
    ledger.publish(value)
    sha = raw_request(value)["sha256"]
    assert pending(ledger) == [{
        "request_id": "feature-1", "request_sha256": sha, "team": "engine", "operation": "targeted-tests",
        "phase": "validation", "owner": "engine/coordinator", "paths": ["/fixture/engine/tests"], "source": SOURCE,
        "why": "awaiting_decision",
        "root_decide": {"request_id": "feature-1", "request_sha256": sha, "event_id_approve": "root-feature-1-approve",
                        "event_id_deny": "root-feature-1-deny"}}]


def test_the_root_decide_arguments_record_as_given_and_the_request_is_no_longer_owed(ledger):
    value = request("feature-1")
    ledger.publish(value)
    [row] = pending(ledger)
    arguments = row["root_decide"]
    ledger.event("decision", actor="root-1", identifier=arguments["event_id_approve"], decision="approve",
                 reason="the owner agreed", request_id=arguments["request_id"],
                 request_sha256=arguments["request_sha256"])
    assert pending(ledger) == []
    assert [d["request_id"] for d in ledger.status()["decisions"]] == ["feature-1"]


@pytest.mark.parametrize("settle", ["routed", "denied", "approved", "member"])
def test_a_routed_denied_approved_or_member_request_is_not_owed(ledger, settle):
    owed = request("feature-open")
    ledger.publish(owed)
    if settle == "member":
        # A continuation member is named inside its authority's bytes and never takes a ROOT decision.
        ledger.publish(request("member-1", authority="authority-1"))
    else:
        value = request("feature-" + settle)
        ledger.publish(value)
        if settle == "routed":
            route(ledger, value)
        elif settle == "denied":
            deny(ledger, value)
        else:
            ledger.approve(value)
    assert [row["request_id"] for row in pending(ledger)] == ["feature-open"]


def test_an_approval_revoked_by_a_later_deny_is_not_owed(ledger):
    value = request("feature-1")
    ledger.publish(value)
    ledger.approve(value)
    deny(ledger, value)
    assert pending(ledger) == []


def test_an_escalation_is_owed_with_its_delegation_and_reason(ledger):
    _granted, _inside, outside = escalated(ledger)
    sha = raw_request(outside)["sha256"]
    [row] = pending(ledger)
    assert row["request_id"] == "merge-2" and row["request_sha256"] == sha
    assert (row["why"], row["delegation_id"], row["escalation_reason"]) == (
        "escalated", "delegation-1", "path outside the delegation")
    assert row["paths"] == ["/fixture/other"] and row["operation"] == "merge"
    assert row["root_decide"] == {"request_id": "merge-2", "request_sha256": sha,
                                  "event_id_approve": "root-merge-2-approve", "event_id_deny": "root-merge-2-deny"}


def test_a_merge_the_decider_approved_inside_its_delegation_is_not_owed(ledger):
    escalated(ledger)
    assert "merge-1" not in [row["request_id"] for row in pending(ledger)]


@pytest.mark.parametrize("verdict", ["approve", "deny"])
def test_a_later_root_decision_on_the_escalation_clears_it(ledger, verdict):
    _granted, _inside, outside = escalated(ledger)
    ledger.event("decision", actor="root-1", decision=verdict, reason="ROOT decided the escalation",
                 **ledger.target(outside))
    assert pending(ledger) == []


def test_an_undecided_merge_inside_a_live_delegation_is_listed_as_the_deciders(ledger):
    """Still listed, so ROOT sees it, but marked: the Decider owns it until it escalates or the delegation lapses."""
    ledger.delegate()
    value = merge("merge-3")
    ledger.publish(value)
    sha = raw_request(value)["sha256"]
    [row] = pending(ledger)
    assert (row["request_id"], row["why"], row.get("delegation_id")) == ("merge-3", "within_delegation", "delegation-1")
    assert "escalation_reason" not in row
    assert row["root_decide"] == {"request_id": "merge-3", "request_sha256": sha,
                                  "event_id_approve": "root-merge-3-approve", "event_id_deny": "root-merge-3-deny"}
    answer = status(ledger)
    assert answer["pending"] == ["merge-3"]
    assert {"request_id": "merge-3", "state": "within_delegation"} in answer["requests"]


def test_the_deciders_escalation_of_a_merge_inside_its_delegation_is_escalated(ledger):
    granted = ledger.delegate()
    value = merge("merge-3")
    ledger.publish(value)
    ledger.decide(value, granted, "escalate", reason="the review failed")
    [row] = pending(ledger)
    assert (row["request_id"], row["why"], row["delegation_id"], row["escalation_reason"]) == (
        "merge-3", "escalated", "delegation-1", "the review failed")


@pytest.mark.parametrize("case", ["expired", "exhausted", "unapproved", "denied", "other_team", "outside",
                                  "not_a_merge"])
def test_a_merge_the_delegation_cannot_take_is_awaiting_roots_decision(ledger, monkeypatch, case):
    if case == "expired":
        ends = datetime.now(timezone.utc) + timedelta(hours=1)
        ledger.delegate(delegation(expires_at=stamp(ends)))
        monkeypatch.setattr(hierarchy_team_view, "timestamp", lambda: stamp(ends + timedelta(seconds=1)))
    elif case == "exhausted":
        granted = ledger.delegate(delegation(max_starts=1))
        used = merge("merge-1")
        ledger.publish(used)
        ledger.decide(used, granted)
    elif case == "unapproved":
        ledger.publish(delegation())
    elif case == "denied":
        refused = delegation()
        ledger.publish(refused)
        deny(ledger, refused)
    else:
        ledger.delegate()
    changes = {"other_team": {"team": "forge"}, "outside": {"paths": ["/fixture/other"]},
               "not_a_merge": {"operation": "targeted-tests"}}.get(case, {})
    ledger.publish(merge("merge-3", **changes))
    rows = {row["request_id"]: row for row in pending(ledger)}
    assert rows["merge-3"]["why"] == "awaiting_decision" and "delegation_id" not in rows["merge-3"]


def test_a_request_id_too_long_for_the_event_id_gets_its_hash_instead(ledger):
    value = request("r" * 80)
    ledger.publish(value)
    sha = raw_request(value)["sha256"]
    [row] = pending(ledger)
    assert row["root_decide"]["event_id_approve"] == "root-%s-approve" % sha[:32]
    assert row["root_decide"]["event_id_deny"] == "root-%s-deny" % sha[:32]


def test_a_busy_journal_is_waited_for_and_then_refused(ledger):
    lock = ledger.path / ".write.lock"
    lock.write_text("{}")
    try:
        with pytest.raises(ValueError) as caught:
            hierarchy_team_view.pending(journal(ledger), 0.2)
    finally:
        lock.unlink()
    assert str(caught.value) == "mailbox writer is busy; inspect an abandoned lock before retrying"


# status


def test_status_without_loop_state_or_evidence_reads_the_journal_alone(ledger):
    escalated(ledger)
    open_request = request("feature-1")
    ledger.publish(open_request)
    answer = status(ledger)
    assert answer["loop"] is None and answer["evidence"] is None
    assert answer["holds_by_act"] == ACTS
    assert answer["pending"] == ["feature-1", "merge-2"]
    assert answer["requests"] == [
        {"request_id": "delegation-1", "state": "delegation"}, {"request_id": "feature-1", "state": "awaiting_decision"},
        {"request_id": "merge-1", "state": "delegated_approved"}, {"request_id": "merge-2", "state": "escalated"}]
    assert [(row["request_id"], row["delegation_id"], row["decision"], row["reason"], row["actor"], row["root_decision"])
            for row in answer["delegated_decisions"]] == [
        ("merge-1", "delegation-1", "approve", "fixture approve", "decider-1", None),
        ("merge-2", "delegation-1", "escalate", "path outside the delegation", "decider-1", None)]
    assert answer["execution_enabled"] is False


def test_status_names_routed_denied_approved_and_member_requests(ledger):
    for name in ("routed", "denied", "approved"):
        ledger.publish(request("feature-" + name))
    route(ledger, request("feature-routed"))
    deny(ledger, request("feature-denied"))
    ledger.approve(request("feature-approved"))
    ledger.publish(request("member-1", authority="authority-1"))
    assert status(ledger)["requests"] == [
        {"request_id": "feature-approved", "state": "approved"}, {"request_id": "feature-denied", "state": "denied"},
        {"request_id": "feature-routed", "state": "routed"}, {"request_id": "member-1", "state": "continuation_member"}]


def test_status_after_root_decides_the_escalation_shows_the_decision(ledger):
    _granted, _inside, outside = escalated(ledger)
    ledger.approve(outside)
    answer = status(ledger)
    assert answer["pending"] == []
    assert {row["request_id"]: row["state"] for row in answer["requests"]}["merge-2"] == "approved"
    assert answer["delegated_decisions"][-1]["root_decision"] == "approve"


def test_a_stale_loop_is_named_and_its_holds_are_grouped_by_who_must_act(ledger, tmp_path):
    hour_ago = stamp(datetime.now(timezone.utc) - timedelta(hours=1))
    rows = [hold("root", "root_queue", endpoint="a/root", initiative="a"), hold("owner", "start_failed", endpoint="a/lane/f2"),
            hold("router", "route_held")]
    state_dir = loop_file(tmp_path / "loop", finished=hour_ago, holds=rows)
    before = snapshot(state_dir)
    answer = status(ledger, loop_state=state_dir)
    assert answer["loop"] == {"state": "stale", "pass_id": 7, "finished_at": hour_ago, "current_step": None,
                              "step_started_at": None, "interval": 30}
    assert answer["holds_by_act"] == {"root": [rows[0]], "owner": [rows[1]], "router": [rows[2]]}
    assert snapshot(state_dir) == before


def test_a_loop_that_finished_a_pass_within_its_interval_is_fresh(ledger, tmp_path):
    now = stamp(datetime.now(timezone.utc))
    answer = status(ledger, loop_state=loop_file(tmp_path / "loop", finished=now))
    assert answer["loop"]["state"] == "fresh" and answer["loop"]["finished_at"] == now
    assert answer["holds_by_act"] == ACTS


def test_a_long_step_that_started_within_the_interval_is_fresh_and_named(ledger, tmp_path):
    now = datetime.now(timezone.utc)
    started = stamp(now - timedelta(seconds=5))
    answer = status(ledger, loop_state=loop_file(tmp_path / "loop", finished=stamp(now - timedelta(hours=1)),
                                                 current_step="run_open", step_started=started))
    assert (answer["loop"]["state"], answer["loop"]["current_step"], answer["loop"]["step_started_at"]) == (
        "fresh", "run_open", started)


def test_a_loop_state_folder_without_a_status_file_reads_absent(ledger, tmp_path):
    (tmp_path / "loop").mkdir()
    assert status(ledger, loop_state=tmp_path / "loop")["loop"] == {
        "state": "absent", "pass_id": None, "finished_at": None, "current_step": None, "step_started_at": None,
        "interval": None}


def test_a_malformed_loop_status_is_refused_with_the_loops_own_text(ledger, tmp_path):
    state_dir = tmp_path / "loop"
    loop_file(state_dir, finished=stamp(datetime.now(timezone.utc)))
    value = json.loads((state_dir / "status.json").read_text())
    value["holds"] = "none"
    (state_dir / "status.json").write_text(json.dumps(value))
    with pytest.raises(ValueError) as caught:
        status(ledger, loop_state=state_dir)
    assert str(caught.value) == "status file has a bad holds: " + str(state_dir / "status.json")


def test_evidence_is_counted_and_its_sha256sums_named(ledger, tmp_path):
    folder = tmp_path / "evidence"
    (folder / "nested").mkdir(parents=True)
    (folder / "init.json").write_text("{}")
    (folder / "nested" / "preflight.txt").write_text("ok")
    (folder / "SHA256SUMS").write_text("%s  init.json\n%s  nested/preflight.txt\n" % ("a" * 64, "b" * 64))
    before = snapshot(folder)
    assert status(ledger, evidence=folder)["evidence"] == {
        "directory": str(folder), "present": True, "files": 3, "sha256sums": str(folder / "SHA256SUMS"), "listed": 2}
    assert snapshot(folder) == before


def test_evidence_without_sha256sums_or_without_the_folder(ledger, tmp_path):
    folder = tmp_path / "evidence"
    folder.mkdir()
    (folder / "init.json").write_text("{}")
    assert status(ledger, evidence=folder)["evidence"] == {
        "directory": str(folder), "present": True, "files": 1, "sha256sums": None, "listed": None}
    absent = tmp_path / "never"
    assert status(ledger, evidence=absent)["evidence"] == {
        "directory": str(absent), "present": False, "files": 0, "sha256sums": None, "listed": None}


# draft_request


def test_a_draft_is_the_canonical_request_its_hash_and_the_exact_publish_event(ledger):
    fields = fields_of(request("feature-9"))
    answer = draft(ledger, fields)
    raw = answer["raw"]
    assert json.loads(raw) == {"schema": "aegis.lifecycle-request/v1", **fields}
    assert raw == json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":"))
    assert answer["sha256"] == hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert answer["request_id"] == "feature-9" and answer["published"] is False
    assert answer["event"] == {"id": "publish-feature-9", "actor": "coordinator-1", "generation": 1,
                               "custody": {"cid": "root-1", "generation": 1},
                               "event": {"type": "publish", "request": {"raw": raw, "sha256": answer["sha256"]}}}
    assert answer["schema"] == "aegis.team-request/v1"


def test_the_draft_event_publishes_as_given_and_is_then_owed_by_its_hash(ledger, tmp_path):
    answer = draft(ledger, fields_of(request("feature-9")))
    event = tmp_path / "publish.json"
    event.write_text(json.dumps(answer["event"]))
    ledger.cli("record", "--event", str(event), "--evidence-only")
    [row] = pending(ledger)
    assert (row["request_id"], row["request_sha256"]) == ("feature-9", answer["sha256"])
    again = draft(ledger, fields_of(request("feature-9")))
    assert again["published"] is True and again["sha256"] == answer["sha256"]


@pytest.mark.parametrize("change,error", [
    ({"paths": []}, "invalid request paths"),
    ({"source": {**SOURCE, "commit": "xyz"}}, "invalid source commit"),
    ({"id": "Bad Id"}, "invalid id"),
    ({"version": 0}, "invalid request version"),
    ({"continuation": {"members": [], "max_starts": 1, "expires_at": "tomorrow"}}, "invalid UTC timestamp"),
    ({"prerequisites": ["feature-9"]}, "request cannot depend on itself"),
    ({"color": "red"}, "unexpected fields: color"),
    ({"schema": "aegis.lifecycle-request/v2"}, "unsupported request schema"),
])
def test_invalid_fields_are_refused_with_the_lifecycles_own_text(ledger, change, error):
    bad = {**request("feature-9"), **change}
    assert refused_draft(ledger, fields_of(bad) if "schema" not in change else bad) == error
    assert ledger.publish(bad, expect=2)["error"] == error


def test_a_missing_field_is_refused_with_the_lifecycles_own_text(ledger):
    fields = fields_of(request("feature-9"))
    del fields["owner"]
    assert refused_draft(ledger, fields) == "missing fields: owner"


def test_a_draft_reusing_a_published_id_with_other_bytes_is_refused(ledger):
    ledger.publish(request("feature-1"))
    changed = fields_of(request("feature-1", paths=["/fixture/elsewhere"]))
    assert refused_draft(ledger, changed) == "request id conflicts with different bytes"


@pytest.mark.parametrize("actor,error", [
    ("router-1", "actor router-1 is not a coordinator actor in the lifecycle policy"),
    ("nobody-1", "actor nobody-1 is not a coordinator actor in the lifecycle policy"),
])
def test_a_draft_names_only_a_coordinator(ledger, actor, error):
    assert refused_draft(ledger, fields_of(request("feature-9")), coordinator=actor) == error


def test_a_draft_that_is_not_an_object_is_refused(ledger):
    assert refused_draft(ledger, ["feature-9"]) == "expected a JSON object"
