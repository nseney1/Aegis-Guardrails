"""Public evidence contract for review observations."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import shutil
from threading import Barrier
from types import MappingProxyType

import pytest

from aegis_core import team_profile, team_review as review
from tests.helpers_team_git import git, queue_seed_env


TREE = "a" * 40
OTHER_TREE = "b" * 40
OBJECT = "review-1"
REPORT = b"VERDICT: ACCEPT\n"
MARKER = "MARKER-UNTRUSTED-9f3a"
USAGE = {"invalid_input", "limit_exceeded", "multiline_signed_value", "not_provenance_bound"}
RECORD_KEYS = {
    "schema", "review_object", "generation", "manual_flag", "qualification_voided",
    "rounds", "history", "holds", "votes", "attempts",
}
ROUND_KEYS = {
    "review_object", "round_id", "number", "owner", "tree", "report_sha256", "launch",
    "parsed_verdict", "parse_note", "authorized_waiver", "waiver_history", "effective_gate",
    "gate_reason", "findings", "follow_ups", "counted", "eligible_retry", "preferred_independent",
    "copy_ok", "copy_evidence", "qualification_retained", "obsolete", "evidence_version",
}


def _launch(**changes):
    return dict({
        "family": "alpha", "model": "model-a", "host": "primary", "fallback": None,
        "lens": "gating", "state": "completed", "brief_seen": True,
    }, **changes)


def _round(number=1, generation=0, **changes):
    return dict({
        "review_object": OBJECT, "round_id": f"round-{number}", "owner": "owner-a",
        "number": number, "expected_generation": generation,
    }, **changes)


def _bind(ledger, report=REPORT, *, launch=None, tree=TREE, identity=None, **kwargs):
    return review.bind_report(
        ledger, _launch() if launch is None else launch, tree, report,
        _round() if identity is None else identity, **kwargs,
    )


def _refused(result, code):
    assert (result["refused"], result["reason"], result["effect"]) == (True, code, "refused")
    assert result["exit_code"] == (2 if code in USAGE else 1)
    assert result["next_action"] == review.NEXT[code]
    assert result["record"] is result["round"] is None
    assert MARKER not in json.dumps(result)


def _observed(result, verdict, reason="evidence_only"):
    assert (result["refused"], result["reason"], result["exit_code"]) == (False, "", 0)
    record, observed = result["record"], result["round"]
    assert record.keys() == RECORD_KEYS
    assert record["schema"] == "aegis.team.review.record/v1"
    assert record["manual_flag"] is record["qualification_voided"] is False
    assert record["votes"] == record["holds"] == record["history"] == []
    assert observed.keys() == ROUND_KEYS
    assert observed["parsed_verdict"] == verdict
    assert observed["gate_reason"] == reason
    assert observed["effective_gate"] == ("refuse" if reason == "refuse" else "hold")
    assert observed["counted"] is observed["eligible_retry"] is observed["preferred_independent"] is False
    assert observed["obsolete"] is False
    assert observed["findings"] == observed["follow_ups"] == observed["waiver_history"] == []
    assert observed["authorized_waiver"] is None
    assert MARKER not in json.dumps(result)
    assert result["next_action"] == review.GATE_NEXT[reason]
    assert "coordinator" in result["next_action"].lower()
    return observed


def _waive(ledger, **changes):
    values = dict(
        review_object=OBJECT, round_id="round-1", owner="owner-a", report_sha256=hashlib.sha256(REPORT).hexdigest(),
        tree=TREE, ruling="defer all findings", deferred_items=["task-a"], known_items=["task-a"],
        covers="both", expected_generation=1,
    )
    values.update(changes)
    return review.authorize_waiver(ledger, **values)


@pytest.mark.parametrize("line, verdict, reason", [
    (b"VERDICT: ACCEPT", "accept", "evidence_only"),
    (b"VERDICT: REQUEST CHANGES", "request_changes", "refuse"),
    (b"VERDICT: FIX FIRST", "request_changes", "refuse"),
    (b"VERDICT: INCOMPLETE", "incomplete", "evidence_only"),
])
@pytest.mark.parametrize("ending", [b"", b"\n"])
def test_observes_only_the_canonical_verdict_forms(line, verdict, reason, ending):
    ledger = review.ReviewLedger()
    report = line + ending
    result = _bind(ledger, report)
    row = _observed(result, verdict, reason)
    assert result["schema"] == "aegis.team.review.bind/v1"
    assert result["effect"] == "bound"
    assert result["record"]["generation"] == 1
    assert row["report_sha256"] == hashlib.sha256(report).hexdigest()
    assert review.review_record(ledger, OBJECT)["record"] == result["record"]


@pytest.mark.parametrize("report", [
    b"", b"> VERDICT: REQUEST CHANGES", b"Review finished.", b"verdict_parser.py:42",
])
def test_noncanonical_text_is_unscored_as_a_whole(report):
    row = _observed(_bind(review.ReviewLedger(), report), "incomplete")
    assert row["parse_note"] in ("empty", "no_verdict")
    assert row["report_sha256"] == hashlib.sha256(report).hexdigest()


@pytest.mark.parametrize("state, verdict", [
    ("unavailable", "unavailable"), ("error", "unavailable"),
    ("timeout", "timeout"), ("content_filter", "content_filter"),
])
def test_failed_launches_remain_uncounted_observations(state, verdict):
    ledger = review.ReviewLedger()
    launch = _launch(state=state, model=None)
    result = _bind(ledger, b"VERDICT: REQUEST CHANGES\n", launch=launch)
    row = _observed(result, verdict, "policy_stop" if state == "content_filter" else "evidence_only")
    assert row["launch"] == launch
    assert row["parse_note"] == "not_scored"
    assert result["record"]["attempts"] == [{
        "family": "alpha", "model": None, "round_id": "round-1", "tree": TREE,
        "lens": "gating", "state": verdict,
    }]
    identity, = review.served_identity(ledger, TREE)["identities"]
    assert identity["counted"] is False


def test_unseen_launch_does_not_observe_a_verdict():
    row = _observed(_bind(
        review.ReviewLedger(), b"VERDICT: REQUEST CHANGES\n", launch=_launch(brief_seen=False),
    ), "incomplete")
    assert row["parse_note"] == "brief_unseen"


@pytest.mark.parametrize("lens, enabled", [
    ("gating", False), ("advisory", False), ("advisory", True),
    ("second_family", False), ("second_family", True),
])
def test_valid_policy_copy_and_qualification_are_evidence_only(lens, enabled):
    ledger = review.ReviewLedger()
    assert review.DEFAULT_POLICY["advisory_prereview"] is False
    assert review.DEFAULT_POLICY["second_family_reviewer"] is False
    policy = dict(review.DEFAULT_POLICY, mode="delta", review_cap=1, require_cross_family=True,
                  advisory_prereview=enabled, second_family_reviewer=enabled)
    copy = {"ok": False, "tree": TREE, "manifest_sha256": "d" * 64}
    qualification = {"tree": TREE, "review_object": OBJECT, "lens": lens, "qualified": True}
    row = _observed(_bind(
        ledger, launch=_launch(lens=lens), policy=policy, copy_evidence=copy, qualification=qualification,
        verified={"tree": TREE, "verified": True}, unchanged_lines=[1],
    ), "accept")
    assert row["qualification_retained"] is True
    assert row["copy_ok"] is False
    assert row["copy_evidence"] == copy


def test_another_owner_and_family_never_unlocks_an_observation():
    ledger = review.ReviewLedger()
    first = _bind(ledger, b"VERDICT: REQUEST CHANGES\n")
    _observed(first, "request_changes", "refuse")
    peer = _bind(
        ledger, launch=_launch(family="beta"),
        identity=_round(generation=1, round_id="peer", owner="owner-b"),
    )
    _observed(peer, "accept")
    assert peer["record"]["rounds"][1] == first["round"]
    assert len(review.served_identity(ledger, TREE)["identities"]) == 2
    assert all(not row["counted"] for row in review.served_identity(ledger, TREE)["identities"])


def test_served_identity_and_read_preserve_a_detached_snapshot():
    ledger = review.ReviewLedger()
    host, family, model = "h" * 128, "f" * 128, "_" + "m" * 127
    fallback = {"family": "beta", "model": ".model-b", "reason": "capacity"}
    launch = _launch(host=host, family=family, model=model, fallback=fallback)
    bound = _bind(ledger, launch=launch)
    _observed(bound, "accept")
    actual = review.served_identity(ledger, TREE)
    assert actual["schema"] == "aegis.team.review.read/v1"
    assert actual["tree"] == TREE
    assert actual["identities"] == [{
        "family": family, "model": model, "host": host, "fallback": fallback,
        "round_id": "round-1", "review_object": OBJECT, "lens": "gating", "counted": False,
    }]
    launch["host"] = "changed"
    fallback["model"] = "changed"
    bound["record"]["rounds"][0]["launch"]["model"] = "changed"
    actual["identities"][0]["fallback"]["family"] = "changed"
    read = review.review_record(ledger, OBJECT)
    assert read["effect"] == "read"
    assert read["round"]["launch"]["host"] == host
    assert read["round"]["launch"]["model"] == model
    assert read["round"]["launch"]["fallback"] == {"family": "beta", "model": ".model-b", "reason": "capacity"}


@pytest.mark.parametrize("arguments, reason", [
    ({"report": b"VERDICT: INCOMPLETE\n"}, "stale_report"),
    ({"launch": _launch(family="beta")}, "stale_report"),
    ({"tree": OTHER_TREE}, "stale_report"),
    ({"policy": dict(review.DEFAULT_POLICY, mode="delta")}, "stale_report"),
    ({"copy_evidence": {"ok": True, "tree": TREE, "manifest_sha256": "d" * 64}}, "stale_report"),
    ({"verified": {"tree": TREE, "verified": True}}, "stale_report"),
    ({"unchanged_lines": [10]}, "stale_report"),
    ({"qualification": {"tree": TREE, "review_object": OBJECT, "lens": "gating", "qualified": True}},
     "stale_report"),
    ({"identity": _round(2, 1, round_id="round-1")}, "stale_report"),
    ({"identity": _round(generation=1, owner="owner-b")}, "hold_mismatch"),
])
def test_conflicting_reuse_does_not_replace_an_observation(arguments, reason):
    ledger = review.ReviewLedger()
    initial = _bind(ledger)
    assert initial["effect"] == "bound"
    _refused(_bind(ledger, **{"identity": _round(generation=1), **arguments}), reason)
    assert review.review_record(ledger, OBJECT)["record"] == initial["record"]
    assert len(review.served_identity(ledger, TREE)["identities"]) == 1


def test_current_exact_replay_is_idempotent_and_lower_round_replay_is_stale():
    ledger = review.ReviewLedger()
    first = _bind(ledger)
    assert _bind(ledger)["effect"] == "already"
    assert _bind(ledger, identity=_round(generation=1))["record"] == first["record"]
    _refused(_bind(ledger, identity=_round(2, 0)), "stale_report")
    second = _bind(ledger, identity=_round(2, 1))
    assert second["record"]["generation"] == 2
    _refused(_bind(ledger, identity=_round(generation=2)), "stale_report")
    assert review.review_record(ledger, OBJECT)["record"] == second["record"]


def test_object_and_tree_indexes_are_scoped_independently():
    ledger = review.ReviewLedger()
    first = _bind(ledger)
    other = _bind(ledger, tree=OTHER_TREE, identity=_round(review_object="other-review"))
    assert first["record"]["generation"] == other["record"]["generation"] == 1
    assert first["round"]["evidence_version"] != other["round"]["evidence_version"]
    assert [row["review_object"] for row in review.served_identity(ledger, TREE)["identities"]] == [OBJECT]
    assert [row["review_object"] for row in review.served_identity(ledger, OTHER_TREE)["identities"]] == ["other-review"]
    _refused(review.review_record(ledger, "unknown"), "unknown_review")


@pytest.mark.parametrize("reuse_id", [False, True])
def test_concurrent_conflicting_binds_have_one_winner(reuse_id):
    ledger = review.ReviewLedger()
    barrier = Barrier(2)

    def bind(index):
        barrier.wait(timeout=5)
        return _bind(
            ledger, REPORT if index == 0 else b"VERDICT: REQUEST CHANGES\n",
            identity=_round(round_id="shared" if reuse_id else f"attempt-{index}"),
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(bind, (0, 1)))
    accepted, = [result for result in results if not result["refused"]]
    rejected, = [result for result in results if result["refused"]]
    assert accepted["effect"] == "bound"
    _refused(rejected, "stale_report")
    current = review.review_record(ledger, OBJECT)
    assert current["record"] == accepted["record"]
    assert current["record"]["generation"] == 1


@pytest.mark.parametrize("changes, reason", [
    ({"report": b"\xff" + MARKER.encode()}, "malformed_report"),
    ({"report": b"VERDICT: ACCEPT\x00\n"}, "malformed_report"),
    ({"report": b"\xff" * 5, "policy": dict(review.DEFAULT_POLICY, max_report_bytes=4)}, "limit_exceeded"),
    ({"report": bytearray(REPORT)}, "invalid_input"),
    ({"launch": _launch(model=None)}, "not_provenance_bound"),
    ({"launch": _launch(host="h" * 129)}, "invalid_input"),
    ({"identity": _round(number=True)}, "invalid_input"),
    ({"identity": _round(generation=-1)}, "invalid_input"),
    ({"identity": _round(generation=1)}, "stale_report"),
    ({"tree": "../outside"}, "invalid_input"),
    ({"copy_evidence": {"ok": False, "tree": OTHER_TREE, "manifest_sha256": "d" * 64}}, "stale_report"),
    ({"unchanged_lines": [1] * 10001}, "limit_exceeded"),
])
def test_bind_validation_refuses_before_mutation(changes, reason):
    ledger = review.ReviewLedger()
    _refused(_bind(ledger, **changes), reason)
    _refused(review.review_record(ledger, OBJECT), "unknown_review")
    assert review.served_identity(ledger, TREE)["identities"] == []


@pytest.mark.parametrize("field", ["review_object", "family", "fallback_model"])
def test_credential_shaped_metadata_is_refused_without_echo(field):
    unsafe = "-".join(("sk", MARKER))
    arguments = {
        "review_object": {"identity": _round(review_object=unsafe)},
        "family": {"launch": _launch(family=unsafe)},
        "fallback_model": {"launch": _launch(fallback={"family": "beta", "model": unsafe, "reason": "capacity"})},
    }
    ledger = review.ReviewLedger()
    _refused(_bind(ledger, **arguments[field]), "invalid_input")
    assert review.served_identity(ledger, TREE)["identities"] == []


@pytest.mark.parametrize("has_binding", [False, True])
def test_valid_control_calls_are_refused_without_mutation(has_binding):
    ledger = review.ReviewLedger()
    initial = _bind(ledger) if has_binding else None
    version = initial["round"]["evidence_version"] if initial else "d" * 64
    before = review.review_record(ledger, OBJECT)["record"]
    for covers in ("cap", "cross_family", "both"):
        _refused(_waive(ledger, covers=covers, evidence_version=version), "unauthorized_waiver")
    for action in (review.notify_waiter, review.release_hold):
        for incarnation in (None, 1):
            _refused(action(ledger, OBJECT, "round-1", "owner-a", 1, incarnation=incarnation), "hold_mismatch")
    assert review.review_record(ledger, OBJECT)["record"] == before


@pytest.mark.parametrize("changes, reason", [
    ({"ruling": "first\nsecond"}, "multiline_signed_value"),
    ({"ruling": "first\u2028second"}, "multiline_signed_value"),
    ({"ruling": "a" * 201}, "limit_exceeded"),
    ({"report_sha256": "a" * 63}, "invalid_input"),
    ({"evidence_version": MARKER}, "invalid_input"),
    ({"covers": []}, "invalid_input"),
    ({"known_items": ["task-a"] * 65}, "limit_exceeded"),
    ({"deferred_items": ["task-a", "task-a"]}, "invalid_input"),
    ({"expected_generation": True}, "invalid_input"),
])
def test_waiver_decline_preserves_validation_errors(changes, reason):
    ledger = review.ReviewLedger()
    before = _bind(ledger)["record"]
    _refused(_waive(ledger, **changes), reason)
    assert review.review_record(ledger, OBJECT)["record"] == before


@pytest.mark.parametrize("action", [review.notify_waiter, review.release_hold])
@pytest.mark.parametrize("generation, incarnation", [(-1, None), (0, True), (0, 321)])
def test_waiter_decline_preserves_validation_errors(action, generation, incarnation):
    ledger = review.ReviewLedger()
    _refused(action(ledger, OBJECT, "round-1", "owner-a", generation, incarnation=incarnation), "invalid_input")
    _refused(review.review_record(ledger, OBJECT), "unknown_review")


def test_round_capacity_leaves_existing_observations_intact():
    ledger = review.ReviewLedger()
    for number in range(1, 33):
        last = _bind(ledger, identity=_round(number, number - 1))
        assert last["effect"] == "bound"
    _refused(_bind(ledger, identity=_round(33, 32)), "limit_exceeded")
    assert review.review_record(ledger, OBJECT)["record"] == last["record"]


@pytest.mark.parametrize("launch", [_launch(brief_seen=False), _launch(state="unavailable", model=None)])
def test_unscored_launch_still_requires_well_formed_report_bytes(launch):
    ledger = review.ReviewLedger()
    _refused(_bind(ledger, b"\xff" + MARKER.encode(), launch=launch), "malformed_report")
    _refused(review.review_record(ledger, OBJECT), "unknown_review")


def test_failed_copy_can_be_observed_and_cannot_be_repaired_in_place():
    ledger = review.ReviewLedger()
    copy = {"ok": False, "tree": TREE, "manifest_sha256": "d" * 64}
    before = _bind(ledger, b"VERDICT: REQUEST CHANGES", copy_evidence=copy)
    row = _observed(before, "request_changes", "refuse")
    assert row["copy_evidence"] == copy
    _refused(_bind(
        ledger, b"VERDICT: REQUEST CHANGES", copy_evidence={**copy, "ok": True},
        identity=_round(generation=1),
    ), "stale_report")
    assert review.review_record(ledger, OBJECT)["record"] == before["record"]


def test_object_capacity_does_not_prevent_exact_replay():
    ledger = review.ReviewLedger()
    for index in range(128):
        result = _bind(ledger, identity=_round(review_object=f"review-{index}"))
        assert result["effect"] == "bound"
    _refused(_bind(ledger, identity=_round(review_object="overflow")), "limit_exceeded")
    _refused(review.review_record(ledger, "overflow"), "unknown_review")
    assert _bind(ledger)["effect"] == "already"
    assert len(review.served_identity(ledger, TREE)["identities"]) == 128


def test_same_number_peers_have_separate_records_and_exact_replay():
    ledger = review.ReviewLedger()
    first = _bind(ledger, identity=_round(round_id="z-first"))
    second = _bind(ledger, identity=_round(generation=1, round_id="a-second"))
    _observed(second, "accept")
    assert second["record"]["generation"] == 2
    assert review.review_record(ledger, OBJECT)["round"]["round_id"] == "a-second"
    replay = _bind(ledger, identity=_round(round_id="z-first"))
    assert replay["effect"] == "already"
    assert replay["round"] == first["round"]
    assert replay["record"] == second["record"]


@pytest.mark.parametrize("expected, allowed", [(0, False), (1, True), (2, False), (3, False), (4, True), (999, False)])
def test_replay_requires_origin_or_current_generation(expected, allowed):
    ledger = review.ReviewLedger()
    assert _bind(ledger)["effect"] == "bound"
    target = _bind(ledger, identity=_round(generation=1, round_id="target"))
    _observed(target, "accept")
    assert target["effect"] == "bound"
    assert _bind(ledger, identity=_round(generation=2, round_id="peer-b"))["effect"] == "bound"
    assert _bind(ledger, identity=_round(generation=3, round_id="peer-c"))["effect"] == "bound"
    before = review.review_record(ledger, OBJECT)["record"]
    replay = _bind(ledger, identity=_round(generation=expected, round_id="target"))
    if allowed:
        _observed(replay, "accept")
        assert replay["effect"] == "already"
        assert replay["round"] == target["round"]
        assert replay["record"] == before
    else:
        _refused(replay, "stale_report")
    assert review.review_record(ledger, OBJECT)["record"] == before
    assert len(review.served_identity(ledger, TREE)["identities"]) == 4


def test_reused_id_checks_owner_before_number():
    ledger = review.ReviewLedger()
    before = _bind(ledger)["record"]
    _refused(_bind(ledger, identity=_round(2, 1, round_id="round-1", owner="owner-b")), "hold_mismatch")
    _refused(_bind(ledger, identity=_round(2, 1, round_id="round-1")), "stale_report")
    assert review.review_record(ledger, OBJECT)["record"] == before


@pytest.mark.parametrize("changes, reason", [
    ({"report": b"\xff", "copy_evidence": {"ok": 1, "tree": OTHER_TREE, "manifest_sha256": "d" * 64}},
     "invalid_input"),
    ({"copy_evidence": {"ok": True, "tree": OTHER_TREE, "manifest_sha256": MARKER}}, "invalid_input"),
    ({"copy_evidence": {"ok": True, "tree": OTHER_TREE, "manifest_sha256": "d" * 64},
      "qualification": {"tree": TREE, "review_object": OBJECT, "lens": "gating", "qualified": 1}},
     "invalid_input"),
    ({"copy_evidence": {"ok": True, "tree": OTHER_TREE, "manifest_sha256": "d" * 64},
      "verified": {"tree": TREE, "verified": 1}}, "invalid_input"),
    ({"verified": {"tree": OTHER_TREE, "verified": False}, "unchanged_lines": [0]}, "invalid_input"),
    ({"verified": {"tree": OTHER_TREE, "verified": 1}}, "invalid_input"),
    ({"report": b"\xff", "unchanged_lines": [1] * 10001}, "limit_exceeded"),
    ({"report": b"\xff", "qualification": {"tree": TREE}}, "invalid_input"),
    ({"launch": _launch(model=None, host=42)}, "invalid_input"),
    ({"launch": _launch(model=None, family=42)}, "invalid_input"),
    ({"launch": _launch(model=None, brief_seen=1)}, "invalid_input"),
    ({"launch": _launch(model=None, fallback={"family": "beta", "model": 42, "reason": "capacity"})}, "invalid_input"),
    ({"launch": _launch(family=None, model=42)}, "invalid_input"),
    ({"launch": _launch(family=None), "unchanged_lines": [1] * 10001}, "limit_exceeded"),
    ({"launch": _launch(family=None)}, "not_provenance_bound"),
    ({"launch": _launch(model=None)}, "not_provenance_bound"),
    ({"launch": {key: value for key, value in _launch().items() if key != "family"}}, "not_provenance_bound"),
    ({"launch": {key: value for key, value in _launch().items() if key != "model"}}, "not_provenance_bound"),
    ({"launch": _launch(family="", model=None)}, "invalid_input"),
    ({"launch": _launch(state="timeout", family=None, model=None)}, "invalid_input"),
])
def test_bind_usage_precedes_semantic_refusal(changes, reason):
    ledger = review.ReviewLedger()
    before = _bind(ledger)["record"]
    _refused(_bind(ledger, identity=_round(2, 1), **changes), reason)
    assert review.review_record(ledger, OBJECT)["record"] == before
    assert len(review.served_identity(ledger, TREE)["identities"]) == 1


@pytest.mark.parametrize("deferred, known, reason", [
    ([], ["task-a"] * 65, "limit_exceeded"),
    (["task-a"] * 33, [], "limit_exceeded"),
    ([], [42], "invalid_input"),
    ([], ["../task"], "invalid_input"),
    (["task-a", "task-a"], ["task-a"], "invalid_input"),
    (["task-a"], [42], "invalid_input"),
    ([], ["task-a"], "unauthorized_waiver"),
    (["task-a"], ["task-a"] * 64, "unauthorized_waiver"),
    ([f"task-{index}" for index in range(32)], [f"task-{index}" for index in range(32)], "unauthorized_waiver"),
])
def test_waiver_usage_precedes_decline(deferred, known, reason):
    ledger = review.ReviewLedger()
    before = _bind(ledger)["record"]
    _refused(_waive(ledger, deferred_items=deferred, known_items=known), reason)
    assert review.review_record(ledger, OBJECT)["record"] == before


def test_exported_default_matches_omitted_policy():
    ledger = review.ReviewLedger()
    default = _bind(ledger)
    _observed(default, "accept")
    for policy in (review.DEFAULT_POLICY, dict(review.DEFAULT_POLICY)):
        replay = _bind(ledger, policy=policy)
        assert replay["effect"] == "already"
        assert replay["record"] == default["record"]
    _refused(_bind(ledger, policy=MappingProxyType(dict(review.DEFAULT_POLICY))), "invalid_input")
    assert review.review_record(ledger, OBJECT)["record"] == default["record"]


RICH_REPORT = b"Reviewed the repository input.\n**Verdict:** ACCEPT\nChecked-Site: crate-api\n"
PROOF = {"tree": TREE, "verified": True}
SITES = ("crate-api",)


def _bind_checked(ledger, report=REPORT, *, verified=PROOF, **kwargs):
    return _bind(ledger, report, verified=verified, expected_sites=SITES, **kwargs)


def _vote(ledger, bound, *, sites=SITES, **changes):
    row = bound["round"]
    values = dict(review_object=row["review_object"], round_id=row["round_id"], owner=row["owner"],
                  evidence_version=row["evidence_version"], expected_generation=bound["record"]["generation"],
                  checked_sites=sites)
    return review.authorize_vote(ledger, **{**values, **changes})


def _repair(ledger, bound, proof, **changes):
    row = bound["round"]
    values = dict(review_object=row["review_object"], round_id=row["round_id"], owner=row["owner"],
                  evidence_version=row["evidence_version"], expected_generation=bound["record"]["generation"],
                  copy_evidence=proof)
    return review.repair_copy(ledger, **{**values, **changes})


@pytest.mark.parametrize("report, verdict, note", [
    (b"VERDICT: ACCEPT\r\n", "accept", "unanimous"),
    (b"VERDICT: ACCEPT\n\n", "accept", "unanimous"),
    (b"VERDICT: ACCEPT ", "accept", "unanimous"),
    (b"VERDICT:  ACCEPT", "accept", "unanimous"),
    (b"Verdict: ACCEPT", "accept", "unanimous"),
    (b"VERDICT: accept", "accept", "unanimous"),
    (b"**VERDICT: ACCEPT**", "accept", "unanimous"),
    (b"\xef\xbb\xbfVERDICT: ACCEPT", "accept", "unanimous"),
    ("VERDICT: ACCEPT\u2028".encode(), "accept", "unanimous"),
    (b"VERDICT: ACCEPT\nverdict_parser.py:42\n", "accept", "unanimous"),
    (b"VERDICT: ACCEPT\n" + MARKER.encode(), "accept", "unanimous"),
    (b"## Verdict: Request Changes\n- P1 line 12: missing guard\n", "request_changes", "unanimous"),
    (b"VERDICT: REQUEST CHANGES\n- P1 line 12: missing guard\n", "request_changes", "unanimous"),
    (b"VERDICT = ACCEPT", "ambiguous", "unparsed_block"),
    (b"VERDICT: REQUEST_CHANGES", "ambiguous", "unparsed_block"),
    (b"VERDICT: ACCEPT; VERDICT: REQUEST CHANGES", "ambiguous", "unparsed_block"),
    (b"VERDICT: ACCEPT\nVERDICT: REQUEST CHANGES\n", "ambiguous", "conflict"),
    (RICH_REPORT + b"**Verdict** - FIX_FIRST\n", "ambiguous", "unparsed_block"),
    (RICH_REPORT + b"Details mention Verdict = REQUEST_CHANGES.\n", "ambiguous", "unparsed_block"),
    (RICH_REPORT + b"VERDICT REQUEST_CHANGES\n", "ambiguous", "unparsed_block"),
    (b"> VERDICT: ACCEPT\nVerdict: FIX FIRST - detail\n", "request_changes", "unanimous"),
])
def test_rich_verdicts_are_bounded_unambiguous_and_keep_prose_private(report, verdict, note):
    ledger = review.ReviewLedger()
    result = _bind(ledger, report)
    row = result["round"]
    assert result["record"]["votes"] == []
    assert row["report_sha256"] == hashlib.sha256(report).hexdigest()
    assert (row["parsed_verdict"], row["parse_note"]) == (verdict, note)
    assert row["effective_gate"] == "hold"
    assert MARKER not in json.dumps(result)
    assert _bind(ledger, report)["record"] == result["record"]


@pytest.mark.parametrize("report, proof, expected, sites, code", [
    (REPORT, PROOF, None, SITES, "incomplete_evidence"),
    (REPORT, None, SITES, SITES, "incomplete_evidence"),
    (REPORT, {**PROOF, "verified": False}, SITES, SITES, "incomplete_evidence"),
    (RICH_REPORT + b"Checked-Site: crate-io\n", PROOF, SITES, SITES, "incomplete_evidence"),
    (RICH_REPORT + b"Checked-Site: crate-api\n", PROOF, SITES, SITES, "incomplete_evidence"),
    (RICH_REPORT.replace(b"crate-api", b"../outside"), PROOF, SITES, SITES, "incomplete_evidence"),
    (RICH_REPORT + b"- P1 line 12: missing guard\n", PROOF, SITES, SITES, "incomplete_evidence"),
    (RICH_REPORT + MARKER.encode(), PROOF, SITES, SITES, "incomplete_evidence"),
    (REPORT, PROOF, SITES, (), "incomplete_evidence"),
    (REPORT, PROOF, SITES, ("crate-io",), "incomplete_evidence"),
    (REPORT, PROOF, SITES, ("crate-api", "crate-api"), "invalid_input"),
    (REPORT, PROOF, SITES, (MARKER,) * 65, "limit_exceeded"),
])
def test_accept_without_exact_checked_evidence_stays_incomplete(report, proof, expected, sites, code):
    ledger = review.ReviewLedger()
    bound = _bind(ledger, report, verified=proof, expected_sites=expected)
    for _ in range(2):
        _refused(_vote(ledger, bound, sites=sites), code)
        assert review.review_record(ledger, OBJECT)["record"] == bound["record"]
    assert bound["round"]["effective_gate"] == "hold"
    assert bound["record"]["votes"] == []
    assert MARKER not in json.dumps(bound)


def test_window_does_not_promote_an_accept_with_an_unread_suffix():
    ledger = review.ReviewLedger()
    policy = dict(review.DEFAULT_POLICY, window_lines=3)
    bound = _bind_checked(ledger, RICH_REPORT + b"Verdict: REQUEST CHANGES\n", policy=policy)
    _refused(_vote(ledger, bound), "incomplete_evidence")
    assert bound["round"]["effective_gate"] == "hold"
    assert bound["round"]["parse_note"] == "window_exceeded"
    _refused(_bind_checked(ledger, RICH_REPORT, policy=policy), "stale_report")


def test_neutral_repository_counts_independent_served_families(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("needs git")
    repo = tmp_path / "work"
    repo.mkdir()
    env = queue_seed_env(repo)
    git(repo, "init", "-q", "-b", "workbench/spring", env=env)
    (repo / "orchard.txt").write_bytes(b"orchard\n")
    git(repo, "add", "--", "orchard.txt", env=env)
    tree = git(repo, "write-tree", env=env).decode().strip()
    assert git(repo, "symbolic-ref", "--short", "HEAD", env=env).decode().strip() == "workbench/spring"
    document = {
        "version": 1, "preset": "ci-only", "policy": {"review": {"require_cross_family": True}},
        "model_settings": {
            "hosts": {"writer-host": {"kind": "codex-cli"}, "reader-host": {"kind": "claude-code"}},
            "roles": {"writer": {"hosts": ["writer-host"]}, "reviewer.correctness": {"hosts": ["reader-host"]}},
        },
    }
    document["policy"]["landing"] = {"target_branch": "workbench/spring"}
    profile_path = repo.joinpath(*team_profile.REPO_PATH)
    profile_path.parent.mkdir(parents=True)
    profile_path.write_text(json.dumps(document), encoding="utf-8")
    profile = team_profile.resolve(repo=json.loads(profile_path.read_text(encoding="utf-8")))["profile"]
    assert profile["policy"]["landing"]["registries"] == []
    policy = dict(review.DEFAULT_POLICY, require_cross_family=profile["policy"]["review"]["require_cross_family"])
    ledger = review.ReviewLedger()
    verified = {"tree": tree, "verified": True}
    first = _bind_checked(ledger, tree=tree, launch=_launch(family="cedar"), verified=verified, policy=policy)
    counted = _vote(ledger, first)
    assert counted["round"]["counted"] is True
    assert counted["round"]["effective_gate"] == "hold"
    assert _vote(ledger, first)["record"] == counted["record"]
    duplicate = _bind_checked(
        ledger, tree=tree, launch=_launch(family="cedar", model="alternate"),
        identity=_round(generation=2, round_id="duplicate"), verified=verified, policy=policy,
    )
    _refused(_vote(ledger, duplicate, evidence_version=first["round"]["evidence_version"]), "stale_report")
    same_family = _vote(ledger, duplicate)
    assert [vote["family"] for vote in same_family["record"]["votes"]] == ["cedar"]
    assert same_family["round"]["effective_gate"] == "hold"
    _refused(_bind_checked(
        ledger, tree=tree, identity=_round(generation=4, round_id="weakened"),
        verified=verified, policy={**policy, "require_cross_family": False},
    ), "stale_report")
    fallback = {"family": "cedar", "model": "first", "reason": "capacity"}
    peer = _bind_checked(
        ledger, tree=tree, launch=_launch(family="birch", fallback=fallback),
        identity=_round(generation=4, round_id="peer", owner="operator-b"), verified=verified, policy=policy,
    )
    _refused(_vote(ledger, peer, owner="owner-a"), "hold_mismatch")
    done = _vote(ledger, peer)
    assert done["round"]["effective_gate"] == "pass"
    assert {(vote["family"], vote["round_id"]) for vote in done["record"]["votes"]} == {
        ("cedar", "duplicate"), ("birch", "peer"),
    }
    assert next(v for v in done["record"]["votes"] if v["family"] == "birch")["fallback"] == fallback
    assert _vote(ledger, peer)["effect"] == "already"
    done["record"]["votes"][0]["checked_sites"].clear()
    assert all(v["checked_sites"] == ["crate-api"] for v in review.review_record(ledger, OBJECT)["record"]["votes"])


def test_prose_refusal_preserves_findings_and_holds_checked_peer():
    ledger = review.ReviewLedger()
    first = _bind_checked(ledger)
    passed = _vote(ledger, first)
    assert passed["round"]["effective_gate"] == "pass"
    different = _round(generation=2, round_id="wrong-tree")
    _refused(_bind(ledger, REPORT, tree=OTHER_TREE, identity=different), "stale_report")
    pending = _bind(
        ledger, b"Review complete.\nVERDICT: REQUEST CHANGES\n- P1 line 12: " + MARKER.encode(),
        identity=_round(generation=2, round_id="pending", owner="owner-b"), launch=_launch(family="beta"),
    )
    assert pending["round"]["findings"] == [{"severity": "p1", "line": 12}]
    assert pending["round"]["parsed_verdict"] == "request_changes"
    assert pending["round"]["effective_gate"] == "hold"
    assert pending["record"]["votes"] == passed["record"]["votes"]
    assert MARKER not in json.dumps(pending)
    identities = review.served_identity(ledger, TREE)["identities"]
    assert {identity["round_id"]: identity["counted"] for identity in identities} == {"pending": False, "round-1": True}
    replay = _bind_checked(ledger)
    assert replay["effect"] == "already"
    assert (replay["round"]["effective_gate"], replay["round"]["gate_reason"]) == ("hold", "check_incomplete")
    moved = _bind(ledger, REPORT, tree=OTHER_TREE, identity=_round(2, 3))
    _refused(_vote(ledger, first, expected_generation=4), "stale_report")
    _refused(_bind_checked(ledger), "stale_report")
    assert review.review_record(ledger, OBJECT)["record"] == moved["record"]


def test_same_id_correction_appends_and_requires_its_own_authorization():
    ledger = review.ReviewLedger()
    first = _bind_checked(ledger)
    assert _vote(ledger, first)["round"]["effective_gate"] == "pass"
    original = first["round"]["evidence_version"]
    refused = _bind(ledger, b"VERDICT: FIX FIRST", identity=_round(generation=2), replaces=original)
    assert refused["effect"] == "corrected"
    assert refused["round"]["effective_gate"] == "refuse"
    assert refused["record"]["votes"] == []
    assert refused["record"]["history"][0]["evidence_version"] == original
    version = refused["round"]["evidence_version"]
    corrected = _bind_checked(ledger, identity=_round(generation=3), replaces=version)
    assert corrected["round"]["evidence_version"] != original
    assert corrected["round"]["effective_gate"] == "refuse"
    _refused(_vote(ledger, first, expected_generation=4), "stale_report")
    _refused(_bind(ledger, REPORT, tree=OTHER_TREE, identity=_round(generation=4), replaces=version), "stale_report")
    assert _bind_checked(ledger, identity=_round(generation=3), replaces=version)["effect"] == "already"
    assert review.review_record(ledger, OBJECT)["record"] == corrected["record"]
    restored = _vote(ledger, corrected)
    assert restored["round"]["effective_gate"] == "pass"
    assert restored["record"]["votes"][0]["evidence_version"] == corrected["round"]["evidence_version"]


def test_policy_stop_is_terminal_and_unavailability_never_counts():
    ledger = review.ReviewLedger()
    qualified = {"tree": TREE, "review_object": OBJECT, "lens": "gating", "qualified": True}
    first = _bind_checked(ledger, qualification=qualified)
    assert _vote(ledger, first)["round"]["effective_gate"] == "pass"
    stop_launch = _launch(state="content_filter", model=None, family="beta")
    stopped = _bind(ledger, REPORT, identity=_round(generation=2, round_id="stopped"),
                    launch=stop_launch, qualification=qualified)
    assert stopped["record"]["votes"] == []
    assert stopped["round"]["parsed_verdict"] == "content_filter"
    assert stopped["round"]["qualification_retained"] is True
    _refused(_bind_checked(ledger, identity=_round(generation=3, round_id="stopped"),
                           replaces=stopped["round"]["evidence_version"]), "stale_report")
    peer = _bind_checked(ledger, identity=_round(generation=3, round_id="peer"),
                         launch=_launch(family="gamma"))
    checked = _vote(ledger, peer)
    assert (checked["round"]["effective_gate"], checked["round"]["gate_reason"]) == ("hold", "policy_stop")
    assert checked["record"]["holds"] == []
    assert all(not r["eligible_retry"] for r in checked["record"]["rounds"])
    assert [r["state"] for r in checked["record"]["attempts"]] == ["content_filter"]
    later = _bind(ledger, REPORT, identity=_round(2, 5), launch=_launch(state="unavailable", model=None))
    assert later["round"]["effective_gate"] == "hold"
    assert later["record"]["votes"] == []
    _refused(_vote(ledger, later), "incomplete_evidence")
    assert review.review_record(ledger, OBJECT)["record"] == later["record"]


def test_policy_stop_requires_disposition_on_the_same_tree_even_in_a_later_round():
    ledger = review.ReviewLedger()
    stopped = _bind(ledger, REPORT, launch=_launch(state="content_filter", model=None))
    assert stopped["round"]["gate_reason"] == "policy_stop"
    later = _bind_checked(ledger, identity=_round(2, 1), launch=_launch(family="beta"))
    checked = _vote(ledger, later)
    assert (checked["round"]["effective_gate"], checked["round"]["gate_reason"]) == ("hold", "policy_stop")
    assert checked["record"]["votes"] == []
    changed = _bind_checked(ledger, tree=OTHER_TREE, verified={**PROOF, "tree": OTHER_TREE}, identity=_round(3, 3))
    assert _vote(ledger, changed)["round"]["effective_gate"] == "pass"
    still_recorded, = checked["record"]["attempts"]
    assert still_recorded["state"] == "content_filter"


@pytest.mark.parametrize("historical", [False, True])
def test_copy_repair_preserves_provenance_and_cannot_restore_stale_authority(historical):
    ledger = review.ReviewLedger()
    copy = {"ok": False, "tree": TREE, "manifest_sha256": "d" * 64}
    proof = {**copy, "ok": True}
    first = _bind_checked(ledger, copy_evidence=copy)
    _refused(_vote(ledger, first), "incomplete_evidence")
    if historical:
        current = _bind(ledger, REPORT, tree=OTHER_TREE, identity=_round(2, 1))
        generation = current["record"]["generation"]
    else:
        generation = 1
    before = review.review_record(ledger, OBJECT)["record"]
    _refused(_repair(ledger, first, {**proof, "manifest_sha256": "e" * 64}, expected_generation=generation),
             "stale_report")
    _refused(_repair(ledger, first, proof, expected_generation=generation, owner="other"), "hold_mismatch")
    assert review.review_record(ledger, OBJECT)["record"] == before
    repaired = _repair(ledger, first, proof, expected_generation=generation)
    assert repaired["effect"] == "repaired"
    assert repaired["round"]["copy_evidence"] == proof
    assert repaired["round"]["report_sha256"] == first["round"]["report_sha256"]
    assert repaired["round"]["launch"] == first["round"]["launch"]
    assert repaired["round"]["evidence_version"] != first["round"]["evidence_version"]
    assert repaired["record"]["votes"] == []
    assert _repair(ledger, first, proof, expected_generation=generation)["effect"] == "already"
    assert repaired["record"]["history"][0]["copy_evidence"] == copy
    transition = next(item for item in repaired["record"]["history"] if item["operation"] == "repaired")
    assert transition["previous"] == first["round"]["evidence_version"]
    assert transition["evidence_version"] == repaired["round"]["evidence_version"]
    assert review.review_record(ledger, OBJECT)["round"]["tree"] == (OTHER_TREE if historical else TREE)
    _refused(_vote(ledger, first, expected_generation=generation + 1), "stale_report")
    if historical:
        _refused(_vote(ledger, repaired), "stale_report")
    else:
        assert _vote(ledger, repaired)["round"]["effective_gate"] == "pass"


@pytest.mark.parametrize("operation", ["vote", "repair", "correction"])
def test_concurrent_exact_replays_produce_one_receipt(operation):
    ledger = review.ReviewLedger()
    copy = {"ok": False, "tree": TREE, "manifest_sha256": "d" * 64}
    initial = _bind_checked(ledger, copy_evidence=copy if operation == "repair" else None)
    barrier = Barrier(2)

    def deliver():
        barrier.wait(timeout=5)
        if operation == "vote":
            return _vote(ledger, initial)
        if operation == "repair":
            return _repair(ledger, initial, {**copy, "ok": True})
        return _bind(ledger, b"VERDICT: INCOMPLETE", identity=_round(generation=1),
                     replaces=initial["round"]["evidence_version"])

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(deliver) for _ in range(2)]
        first, second = [future.result(timeout=5) for future in futures]
    assert first["record"] == second["record"] == review.review_record(ledger, OBJECT)["record"]
    assert first["record"]["generation"] == 2
    assert {first["effect"], second["effect"]} == {"already", {
        "vote": "authorized", "repair": "repaired", "correction": "corrected",
    }[operation]}


def test_conflicting_corrections_race_without_replacing_winner_or_provenance():
    ledger = review.ReviewLedger()
    original = _bind_checked(ledger)
    version = original["round"]["evidence_version"]
    barrier = Barrier(2)

    def correct(report):
        barrier.wait(timeout=5)
        return _bind(ledger, report, identity=_round(generation=1), replaces=version)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(correct, (b"VERDICT: REQUEST CHANGES", b"VERDICT: INCOMPLETE")))
    winner, = [r for r in results if not r["refused"]]
    loser, = [r for r in results if r["refused"]]
    _refused(loser, "stale_report")
    _refused(_bind_checked(ledger, REPORT[:-1], identity=_round(generation=2), replaces=version),
             "stale_report")
    assert winner["effect"] == "corrected"
    assert winner["record"]["generation"] == 2
    assert review.review_record(ledger, OBJECT)["record"] == winner["record"]


@pytest.mark.parametrize("lens, enabled, counts", [
    ("advisory", True, False), ("second_family", False, False), ("second_family", True, True),
])
def test_only_voting_lenses_can_authorize_current_evidence(lens, enabled, counts):
    ledger = review.ReviewLedger()
    policy = dict(review.DEFAULT_POLICY, advisory_prereview=enabled, second_family_reviewer=enabled)
    bound = _bind_checked(ledger, launch=_launch(lens=lens), policy=policy)
    result = _vote(ledger, bound)
    if counts:
        assert result["round"]["counted"] is True
        assert result["round"]["effective_gate"] == "hold"
    else:
        _refused(result, "incomplete_evidence")
        assert review.review_record(ledger, OBJECT)["record"] == bound["record"]


def test_unavailable_newer_receipt_holds_prior_vote_until_independent_check():
    ledger = review.ReviewLedger()
    first = _bind_checked(ledger)
    assert _vote(ledger, first)["round"]["effective_gate"] == "pass"
    second = _bind(ledger, REPORT, launch=_launch(state="error", model=None, family="beta"),
                   identity=_round(generation=2, round_id="second"))
    _refused(_vote(ledger, second), "incomplete_evidence")
    assert second["round"]["parsed_verdict"] == "unavailable"
    assert second["round"]["effective_gate"] == "hold"
    assert _bind_checked(ledger)["round"]["gate_reason"] == "check_incomplete"
    third = _bind_checked(ledger, launch=_launch(family="gamma"),
                          identity=_round(generation=3, round_id="third"))
    assert _vote(ledger, third)["round"]["effective_gate"] == "pass"
    assert review.review_record(ledger, OBJECT)["record"]["attempts"] == second["record"]["attempts"]


@pytest.mark.parametrize("header", [b"**Verdict**: **ACCEPT**", b"**Verdict:** **ACCEPT**"])
def test_emphasized_verdict_and_hyphenated_filename_keep_an_observed_accept(header):
    ledger = review.ReviewLedger()
    report = b"verdict-parser.py:42\n" + header + b"\nChecked-Site: crate-api\n"
    bound = _bind_checked(ledger, report)
    assert bound["round"]["parsed_verdict"] == "accept"
    assert bound["round"]["effective_gate"] == "hold"
    _refused(_vote(ledger, bound), "incomplete_evidence")


@pytest.mark.parametrize("label", [
    b"| Verdict | REQUEST CHANGES |\n",
    b"***Verdict***: REQUEST CHANGES\n",
    b"`Verdict`: REQUEST CHANGES\n",
    "Verdict\u00a0: REQUEST CHANGES\n".encode(),
    b"**Verdict** REQUEST CHANGES\n",
])
@pytest.mark.parametrize("refusal_first", [True, False])
def test_hidden_verdict_conflict_is_held_in_both_orders(label, refusal_first):
    ledger = review.ReviewLedger()
    sections = (label, RICH_REPORT) if refusal_first else (RICH_REPORT, label)
    result = _bind_checked(ledger, b"".join(sections))
    assert result["round"]["parsed_verdict"] == "ambiguous"
    assert result["round"]["effective_gate"] == "hold"
    _refused(_vote(ledger, result), "incomplete_evidence")
    assert review.review_record(ledger, OBJECT)["record"] == result["record"]


@pytest.mark.parametrize("verdict", [b"ACCEPT", b"REQUEST CHANGES"])
@pytest.mark.parametrize("sites_first", [True, False])
def test_table_and_decorated_sites_withhold_votes_even_with_complete_coverage(verdict, sites_first):
    ledger = review.ReviewLedger()
    sites = b"**Checked-Site:** crate-api\n| Checked-Site | crate-io |\n"
    decision = b"| Verdict | " + verdict + b" |\n"
    report = b"| Field | Value |\n| --- | --- |\n" + (sites + decision if sites_first else decision + sites)
    bound = _bind(ledger, report, verified=PROOF, expected_sites=("crate-io", "crate-api"))
    _refused(_vote(ledger, bound), "incomplete_evidence")
    _refused(_vote(ledger, bound, sites=("crate-io", "crate-api")), "incomplete_evidence")
    assert bound["round"]["effective_gate"] == "hold"


@pytest.mark.parametrize("extra", [
    b"**Checked-Site:** ../outside\n", b"| Checked-Site | invalid value |\n",
    b"`Checked_Site`: unknown\n", b"| Checked-Site | crate-io | extra |\n",
])
@pytest.mark.parametrize("verdict", [b"ACCEPT", b"REQUEST CHANGES"])
def test_malformed_site_withholds_authority_for_any_verdict(extra, verdict):
    ledger = review.ReviewLedger()
    report = extra + b"Checked-Site: crate-api\nVerdict: " + verdict
    bound = _bind_checked(ledger, report)
    _refused(_vote(ledger, bound), "incomplete_evidence")
    assert bound["round"]["effective_gate"] == "hold"
    assert review.review_record(ledger, OBJECT)["record"] == bound["record"]


@pytest.mark.parametrize("pending", ["overflow", "no_visible_verdict", "copy", "finding", "verification", "incomplete"])
@pytest.mark.parametrize("pending_first", [True, False])
def test_completed_pending_evidence_holds_checked_peer_in_both_orders(pending, pending_first):
    ledger = review.ReviewLedger()
    policy = dict(review.DEFAULT_POLICY, window_lines=4)
    unread = b"\nVerdict: REQUEST CHANGES\n"
    report = {
        "overflow": RICH_REPORT + b"\n" + unread,
        "no_visible_verdict": b"Reviewed.\n\n\n\n" + unread,
        "copy": REPORT, "finding": REPORT + b"- P0 line 12: bug\n",
        "verification": REPORT, "incomplete": b"Verdict: INCOMPLETE\n",
    }[pending]
    copy = {"ok": False, "tree": TREE, "manifest_sha256": "d" * 64} if pending == "copy" else None

    def bind_pending(generation):
        proof = None if pending == "verification" else PROOF
        return _bind_checked(ledger, report, identity=_round(generation=generation), policy=policy,
                             verified=proof, copy_evidence=copy)

    def bind_peer(generation):
        return _bind_checked(ledger, identity=_round(generation=generation, round_id="peer"),
                             launch=_launch(family="beta"), policy=policy)

    if pending_first:
        bind_pending(0)
        result = _vote(ledger, bind_peer(1))
    else:
        peer = bind_peer(0)
        assert _vote(ledger, peer)["round"]["effective_gate"] == "pass"
        result = bind_pending(2)
    peer, = [row for row in result["record"]["rounds"] if row["round_id"] == "peer"]
    assert (peer["effective_gate"], peer["gate_reason"]) == ("hold", "check_incomplete")


@pytest.mark.parametrize("claim", ["ambiguous", "overflow"])
def test_unchecked_same_id_correction_preserves_unresolved_claim(claim):
    ledger = review.ReviewLedger()
    policy = dict(review.DEFAULT_POLICY, window_lines=3)
    report = (b"Verdict: ACCEPT\nVerdict: REQUEST CHANGES\n" if claim == "ambiguous"
              else b"Reviewed.\n\n\nVerdict: REQUEST CHANGES\n")
    before = _bind(ledger, report, policy=policy)
    middle = _bind(ledger, b"Verdict: INCOMPLETE", identity=_round(generation=1), policy=policy,
                   replaces=before["round"]["evidence_version"])
    peer = _bind_checked(ledger, identity=_round(generation=2, round_id="peer"),
                         launch=_launch(family="beta"), policy=policy)
    checked = _vote(ledger, peer)
    assert checked["round"]["effective_gate"] == "hold"
    corrected = _bind_checked(ledger, identity=_round(generation=4), policy=policy,
                              replaces=middle["round"]["evidence_version"])
    assert _vote(ledger, corrected)["round"]["effective_gate"] == "pass"


def test_superseded_same_family_repair_keeps_bind_order_and_cannot_reenter_voting():
    ledger = review.ReviewLedger()
    copy = {"ok": False, "tree": TREE, "manifest_sha256": "d" * 64}
    older = _bind_checked(ledger, copy_evidence=copy)
    newer = _bind_checked(ledger, identity=_round(generation=1, round_id="newer"))
    counted = _vote(ledger, newer)
    generation = counted["record"]["generation"]
    _refused(_bind_checked(ledger, REPORT[:-1], copy_evidence=copy,
                           identity=_round(generation=generation), replaces=older["round"]["evidence_version"]),
             "stale_report")
    repaired = _repair(ledger, older, {**copy, "ok": True}, expected_generation=generation)
    assert repaired["effect"] == "repaired"
    assert repaired["record"]["history"][0]["copy_evidence"] == copy
    assert review.review_record(ledger, OBJECT)["round"]["round_id"] == "newer"
    assert [v["round_id"] for v in repaired["record"]["votes"]] == ["newer"]
    _refused(_vote(ledger, repaired), "stale_report")


@pytest.mark.parametrize("recovery", ["same_id", "same_family", "other_lens"])
def test_unavailable_gating_requires_fresh_independent_gating(recovery):
    ledger = review.ReviewLedger()
    policy = dict(review.DEFAULT_POLICY, second_family_reviewer=True)
    initial = _bind_checked(ledger, policy=policy)
    assert _vote(ledger, initial)["round"]["effective_gate"] == "pass"
    qualified = {"tree": TREE, "review_object": OBJECT, "lens": "gating", "qualified": True}
    failed = _bind(ledger, REPORT, launch=_launch(family="beta", state="error", model=None),
                   identity=_round(generation=2, round_id="failed"), qualification=qualified, policy=policy)
    if recovery == "same_id":
        candidate = _bind_checked(ledger, REPORT[:-1], policy=policy, identity=_round(generation=3),
                                  replaces=initial["round"]["evidence_version"])
    else:
        launch = _launch() if recovery == "same_family" else _launch(family="extra", lens="second_family")
        candidate = _bind_checked(ledger, launch=launch, policy=policy,
                                  identity=_round(generation=3, round_id="repeat"))
    checked = _vote(ledger, candidate)
    assert (checked["round"]["effective_gate"], checked["round"]["gate_reason"]) == ("hold", "check_incomplete")
    fresh = _bind_checked(ledger, policy=policy, launch=_launch(family="gamma"),
                          identity=_round(generation=5, round_id="fresh"))
    done = _vote(ledger, fresh)
    assert done["round"]["effective_gate"] == "pass"
    assert done["record"]["attempts"] == failed["record"]["attempts"]
    assert next(row for row in done["record"]["rounds"] if row["round_id"] == "failed")["qualification_retained"]


@pytest.mark.parametrize("generation", [1, 2])
def test_correction_cannot_replay_a_repair(generation):
    ledger = review.ReviewLedger()
    copy = {"ok": False, "tree": TREE, "manifest_sha256": "d" * 64}
    prior = _bind_checked(ledger, copy_evidence=copy)
    proof = {**copy, "ok": True}
    repaired = _repair(ledger, prior, proof)
    _refused(_bind_checked(ledger, copy_evidence=proof,
                           identity=_round(generation=generation), replaces=prior["round"]["evidence_version"]),
             "stale_report")
    assert _repair(ledger, prior, proof, expected_generation=generation)["effect"] == "already"
    assert review.review_record(ledger, OBJECT)["record"] == repaired["record"]


def test_correction_and_repair_race_on_one_predecessor():
    ledger = review.ReviewLedger()
    copy = {"ok": False, "tree": TREE, "manifest_sha256": "d" * 64}
    original = _bind_checked(ledger, copy_evidence=copy)
    barrier = Barrier(2)

    def deliver(repair):
        barrier.wait(timeout=5)
        if repair:
            return _repair(ledger, original, {**copy, "ok": True})
        return _bind_checked(ledger, REPORT[:-1], copy_evidence=copy,
                             identity=_round(generation=1), replaces=original["round"]["evidence_version"])

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(deliver, repair) for repair in (True, False)]
        repaired, corrected = [future.result(timeout=5) for future in futures]
    winner, = [result for result in (repaired, corrected) if not result["refused"]]
    loser, = [result for result in (repaired, corrected) if result["refused"]]
    _refused(loser, "stale_report")
    assert winner["record"]["generation"] == 2
    assert winner["record"]["history"][0]["copy_evidence"] == copy
    assert review.review_record(ledger, OBJECT)["record"] == winner["record"]


def test_authorized_same_id_disposition_survives_same_family_supersession():
    ledger = review.ReviewLedger()
    ambiguous = _bind(ledger, b"Verdict: ACCEPT\nVerdict: REQUEST CHANGES\n")
    fixed = _bind_checked(ledger, identity=_round(generation=1),
                          replaces=ambiguous["round"]["evidence_version"])
    assert _vote(ledger, fixed)["round"]["effective_gate"] == "pass"
    newer = _bind_checked(ledger, identity=_round(generation=3, round_id="newer"))
    checked = _vote(ledger, newer)
    assert checked["round"]["effective_gate"] == "pass"
    assert [vote["round_id"] for vote in checked["record"]["votes"]] == ["newer"]


def test_unread_refusal_survives_same_family_supersession():
    ledger = review.ReviewLedger()
    policy = dict(review.DEFAULT_POLICY, window_lines=3)
    unread = _bind(ledger, b"Reviewed.\n\n\nVerdict: REQUEST CHANGES\n", policy=policy)
    assert unread["round"]["parse_note"] == "window_exceeded"
    newer = _bind_checked(ledger, identity=_round(generation=1, round_id="newer"), policy=policy)
    checked = _vote(ledger, newer)
    assert checked["round"]["effective_gate"] == "hold"
    assert checked["round"]["gate_reason"] == "check_incomplete"
    next_round = _bind_checked(ledger, identity=_round(2, 3), policy=policy)
    assert _vote(ledger, next_round)["round"]["effective_gate"] == "pass"


@pytest.mark.parametrize("extra", [
    b"## Verdict\nOTHER\n",
    b"## **Decision**\nMaintain the hold\n",
    b"**Verdict** **OTHER**\n",
    b"Verdict `OTHER`\n",
    b"| Verdict OTHER |\n",
    b"| Field | Value |\n| --- | --- |\n| Decision | **Verdict** OTHER |\n",
    b"| notes | longer row | **_Verdict_** | **OTHER** | extra |\n",
    b"Decision | detail | `OTHER` | extra\n",
    "Recommendation — **OTHER**\n".encode(),
    b"Earlier recommendation was LOWER.\n",
    b"| Notes | _Decision_ | **Maintain the hold** | extra |\n",
    b"Earlier assessment, **Outcome:** maintain the hold.\n",
    b"__Verdict__ = OTHER\n",
    b"**_Verdict_**: OTHER\n",
    b"**_Verdict_: VALID**\n",
    b"| _Verdict_ | OTHER | extra |\n",
    b"| **_Verdict_** | VALID |\n",
    b"> VERDICT: OTHER\n",
    b"_Checked_Site_: crate-other\n",
    b"| **_Checked-Site_** | crate-other |\n",
    b"| checked site | detail | **_crate-other_** |\n",
])
@pytest.mark.parametrize("verdict, other", [(b"ACCEPT", b"REQUEST CHANGES"), (b"REQUEST CHANGES", b"ACCEPT")])
@pytest.mark.parametrize("extra_first", [True, False])
def test_unsupported_report_claims_never_authorize(extra, verdict, other, extra_first):
    ledger = review.ReviewLedger()
    extra = extra.replace(b"OTHER", other).replace(b"VALID", verdict).replace(b"LOWER", other.lower())
    checked = b"Verdict: " + verdict + b"\nChecked-Site: crate-api\n"
    report = extra + checked if extra_first else checked + extra
    bound = _bind_checked(ledger, report)
    _refused(_vote(ledger, bound), "incomplete_evidence")
    assert bound["record"]["votes"] == []
    assert review.review_record(ledger, OBJECT)["record"] == bound["record"]


@pytest.mark.parametrize("extra", [
    MARKER.encode(), b"> Additional review", b"- P1 line 12: missing guard",
    b"| Notes | source reviewed | additional context |",
])
@pytest.mark.parametrize("verdict", [b"ACCEPT", b"REQUEST CHANGES"])
@pytest.mark.parametrize("sites_first", [True, False])
@pytest.mark.parametrize("trailing", [True, False])
def test_both_claim_orders_withhold_authority_for_unchecked_text(extra, verdict, sites_first, trailing):
    ledger = review.ReviewLedger()
    claims = [b"Verdict: " + verdict, b"Checked-Site: crate-api"]
    if sites_first:
        claims.reverse()
    claims.insert(2 if trailing else 1, extra)
    bound = _bind_checked(ledger, b"\n".join(claims))
    _refused(_vote(ledger, bound), "incomplete_evidence")
    assert bound["round"]["effective_gate"] == "hold"
    assert bound["record"]["votes"] == []
    assert MARKER not in json.dumps(bound)


@pytest.mark.parametrize("value, observed", [
    (b"REQUEST CHANGES. Verdict ACCEPT", "ambiguous"),
    (b"REQUEST CHANGES: see notes. **_Verdict_** **ACCEPT**", "ambiguous"),
    (b"FIX FIRST - see notes | Details | ACCEPT | extra |", "ambiguous"),
    (b"FIX FIRST - the recommendation was accept", "ambiguous"),
    (b"FIX FIRST - earlier assessment, **Outcome:** maintain the hold", "ambiguous"),
    (b"REQUEST CHANGES. See check details", "request_changes"),
    (b"REQUEST CHANGES. The parser should accept a dash.", "request_changes"),
    (b"FIX FIRST: explanation _Checked_Site_: crate-other", "request_changes"),
])
@pytest.mark.parametrize("sites_first", [True, False])
def test_refusal_value_is_checked_past_the_recognized_prefix(value, observed, sites_first):
    ledger = review.ReviewLedger()
    claims = (b"Verdict: " + value, b"Checked-Site: crate-api")
    bound = _bind_checked(ledger, b"\n".join(reversed(claims) if sites_first else claims))
    assert bound["round"]["parsed_verdict"] == observed
    assert bound["round"]["effective_gate"] == "hold"
    _refused(_vote(ledger, bound), "incomplete_evidence")


@pytest.mark.parametrize("verdict", [b"ACCEPT", b"REQUEST CHANGES"])
@pytest.mark.parametrize("sites_first", [True, False])
def test_unread_text_withholds_both_votes_in_both_claim_orders(verdict, sites_first):
    ledger = review.ReviewLedger()
    claims = (b"Verdict: " + verdict, b"Checked-Site: crate-api")
    visible = b"\n".join(reversed(claims) if sites_first else claims)
    policy = dict(review.DEFAULT_POLICY, window_lines=2)
    bound = _bind_checked(ledger, visible + b"\n" + MARKER.encode(), policy=policy)
    _refused(_vote(ledger, bound), "incomplete_evidence")
    assert bound["record"]["votes"] == []


@pytest.mark.parametrize("decision", [
    b"VERDICT: VOTE", b"## Verdict: VOTE", b"- **Verdict:** **VOTE**",
    b"**Verdict: VOTE**", b"| **Verdict** | **VOTE** |", b"**Verdict**: **VOTE**",
    b"| **Verdict:** | VOTE |", b"| **Verdict**: | VOTE |",
])
@pytest.mark.parametrize("verdict, observed", [
    (b"ACCEPT", "accept"), (b"REQUEST CHANGES", "request_changes"), (b"FIX FIRST", "request_changes"),
])
def test_rich_report_forms_remain_observations(decision, verdict, observed):
    ledger = review.ReviewLedger()
    report = (b"Reviewed how clients accept input and discussed the decision process.\nverdict-parser.py:42\n"
              b"| Field | Value |\n| --- | --- |\n"
              b"| Checked-Site | crate-api |\n" + decision.replace(b"VOTE", verdict))
    bound = _bind_checked(ledger, report)
    assert (bound["round"]["parsed_verdict"], bound["round"]["effective_gate"]) == (observed, "hold")
    _refused(_vote(ledger, bound), "incomplete_evidence")


@pytest.mark.parametrize("transition", ["authorization", "correction", "repair"])
@pytest.mark.parametrize("lens", ["gating", "second_family"])
@pytest.mark.parametrize("failure_first", [True, False])
def test_failure_uses_original_bind_order_of_checked_served_families(transition, lens, failure_first):
    ledger = review.ReviewLedger()
    policy = dict(review.DEFAULT_POLICY, second_family_reviewer=True)
    copy = {"ok": False, "tree": TREE, "manifest_sha256": "d" * 64} if transition == "repair" else None
    report = b"VERDICT: INCOMPLETE" if transition == "correction" else REPORT
    first = _bind_checked(ledger, report, launch=_launch(lens=lens), policy=policy, copy_evidence=copy)
    qualified = {"tree": TREE, "review_object": OBJECT, "lens": "gating", "qualified": True}

    def fail(generation):
        return _bind(ledger, launch=_launch(family="beta", state="timeout", model=None), policy=policy,
                     identity=_round(generation=generation, round_id="failed"), qualification=qualified)

    def check(generation):
        receipt = first
        if transition == "correction":
            receipt = _bind_checked(ledger, launch=_launch(lens=lens), policy=policy,
                                    identity=_round(generation=generation), replaces=first["round"]["evidence_version"])
            generation = receipt["record"]["generation"]
        elif transition == "repair":
            receipt = _repair(ledger, first, {**copy, "ok": True}, expected_generation=generation)
            generation = receipt["record"]["generation"]
        result = _vote(ledger, receipt, expected_generation=generation)
        assert result["round"]["counted"] is True
        replay = _vote(ledger, receipt, expected_generation=generation)
        assert (replay["effect"], replay["record"]) == ("already", result["record"])
        return result

    if failure_first:
        failed = fail(1)
        last = check(failed["record"]["generation"])
    else:
        checked = check(1)
        failed = last = fail(checked["record"]["generation"])
    repeat = _bind_checked(ledger, policy=policy,
                           identity=_round(generation=last["record"]["generation"], round_id="repeat"))
    _refused(_vote(ledger, first, expected_generation=repeat["record"]["generation"]), "stale_report")
    latest = _vote(ledger, repeat)
    assert (latest["round"]["effective_gate"], latest["round"]["gate_reason"]) == ("hold", "check_incomplete")
    assert [vote["round_id"] for vote in latest["record"]["votes"]] == ["repeat"]
    fresh = _bind_checked(ledger, policy=policy, launch=_launch(family="gamma"),
                          identity=_round(generation=latest["record"]["generation"], round_id="fresh"))
    recovered = _vote(ledger, fresh)
    assert recovered["round"]["effective_gate"] == "pass"
    assert recovered["record"]["attempts"] == failed["record"]["attempts"]
    assert next(row for row in recovered["record"]["rounds"] if row["round_id"] == "failed")["qualification_retained"]


@pytest.mark.parametrize("lens", ["advisory", "second_family"])
def test_ineligible_lenses_do_not_add_success_or_failure_history(lens):
    ledger = review.ReviewLedger()
    policy = dict(review.DEFAULT_POLICY, advisory_prereview=True)
    ineligible = _bind_checked(ledger, launch=_launch(lens=lens), policy=policy)
    _refused(_vote(ledger, ineligible), "incomplete_evidence")
    failed = _bind(ledger, launch=_launch(family="beta", state="error", model=None), policy=policy,
                   identity=_round(generation=1, round_id="failed"))
    other = _bind(ledger, launch=_launch(lens=lens, state="unavailable", model=None), policy=policy,
                  identity=_round(generation=2, round_id="other"))
    fresh = _bind_checked(ledger, policy=policy,
                          identity=_round(generation=3, round_id="fresh"))
    recovered = _vote(ledger, fresh)
    assert recovered["round"]["effective_gate"] == "pass"
    assert len(other["record"]["attempts"]) == 2
    assert next(row for row in recovered["record"]["attempts"] if row["round_id"] == "failed") == failed["record"]["attempts"][0]


def test_each_outstanding_failed_gating_attempt_requires_independent_recovery():
    ledger = review.ReviewLedger()
    early = _bind_checked(ledger)
    _bind(ledger, launch=_launch(family="beta", state="unavailable", model=None),
          identity=_round(generation=1, round_id="unavailable"))
    _vote(ledger, early, expected_generation=2)
    after_failures = _bind(ledger, launch=_launch(family="gamma", state="error", model=None),
                           identity=_round(generation=3, round_id="error"))
    repeat = _bind_checked(ledger, identity=_round(generation=4, round_id="repeat"))
    _vote(ledger, repeat)
    partial = _bind_checked(ledger, launch=_launch(family="beta"),
                            identity=_round(generation=6, round_id="partial"))
    still_held = _vote(ledger, partial)
    assert (still_held["round"]["effective_gate"], still_held["round"]["gate_reason"]) == ("hold", "check_incomplete")
    fresh = _bind_checked(ledger, launch=_launch(family="delta"),
                          identity=_round(generation=8, round_id="fresh"))
    recovered = _vote(ledger, fresh)
    assert recovered["round"]["effective_gate"] == "pass"
    assert recovered["record"]["attempts"] == after_failures["record"]["attempts"]


@pytest.mark.parametrize("extra", [
    b"Checked-Sites: crate-other\n", b"Checked_Sites: crate-other\n", b"Checked sites: crate-other\n",
    b"**Checked Sites:** crate-other\n", b"| Checked Sites | crate-other |\n", b"CheckedSite: crate-other\n",
    b"Earlier recommendation was **incomplete**.\n", b"Decision - incomplete\n",
    b"Outcome was **incomplete**\n", b"## Final decision\nReject\n", b"| Result | Reject |\n",
    b"**Decision** **accept**\n",
])
@pytest.mark.parametrize("verdict", [b"ACCEPT", b"REQUEST CHANGES"])
@pytest.mark.parametrize("extra_first", [True, False])
@pytest.mark.parametrize("expected", [None, SITES], ids=["legacy", "structured"])
def test_legacy_report_text_cannot_supply_a_vote(extra, verdict, extra_first, expected):
    ledger = review.ReviewLedger()
    claims = b"VERDICT: " + verdict + b"\nChecked-Site: crate-api\n"
    report = extra + claims if extra_first else claims + extra
    bound = _bind(ledger, report, verified=PROOF, expected_sites=expected)
    _refused(_vote(ledger, bound), "incomplete_evidence")
    assert bound["record"]["votes"] == []
    assert review.review_record(ledger, OBJECT)["record"] == bound["record"]


@pytest.mark.parametrize("example", [
    b"Example from the previous tree:\n\n    VERDICT: VOTE\n    Checked-Site: crate-api\n",
    b"```text\nVERDICT: VOTE\nChecked-Site: crate-api\n",
    b"```text\nVERDICT: VOTE\nChecked-Site: crate-api\n```\n",
    b"> VERDICT: VOTE\n> Checked-Site: crate-api\n",
])
@pytest.mark.parametrize("verdict", [b"ACCEPT", b"REQUEST CHANGES"])
@pytest.mark.parametrize("expected", [None, SITES], ids=["legacy", "structured"])
def test_report_examples_cannot_supply_a_vote(example, verdict, expected):
    ledger = review.ReviewLedger()
    bound = _bind(ledger, example.replace(b"VOTE", verdict), verified=PROOF, expected_sites=expected)
    _refused(_vote(ledger, bound), "incomplete_evidence")
    assert bound["record"]["votes"] == []


@pytest.mark.parametrize("line, verdict, gate", [
    (b"VERDICT: ACCEPT", "accept", "pass"),
    (b"VERDICT: REQUEST CHANGES", "request_changes", "refuse"),
])
@pytest.mark.parametrize("ending", [b"", b"\n"])
def test_canonical_vote_requires_exact_structured_sites(line, verdict, gate, ending):
    ledger = review.ReviewLedger()
    bound = _bind(ledger, line + ending, verified=PROOF, expected_sites=("crate-io", "crate-api"))
    assert set(bound["round"]) == ROUND_KEYS
    for sites in ((), ("crate-api",), ("crate-api", "crate-io", "crate-other")):
        _refused(_vote(ledger, bound, sites=sites), "incomplete_evidence")
        assert review.review_record(ledger, OBJECT)["record"] == bound["record"]
    voted = _vote(ledger, bound, sites=("crate-io", "crate-api"))
    assert voted["round"]["effective_gate"] == gate
    vote, = voted["record"]["votes"]
    assert (vote["verdict"], vote["checked_sites"]) == (verdict, ["crate-api", "crate-io"])
    assert _vote(ledger, bound, sites=("crate-api", "crate-io"))["effect"] == "already"


@pytest.mark.parametrize("form", [
    b"VERDICT: VOTE\r\n", b"VERDICT: VOTE\r", b"VERDICT: VOTE\n\n", b"VERDICT: VOTE ",
    b" VERDICT: VOTE", b"VERDICT:  VOTE", b"Verdict: VOTE", b"VERDICT:\tVOTE",
    b"\xef\xbb\xbfVERDICT: VOTE", "VERDICT: VOTE\u2028".encode(),
    b"VERDICT: VOTE\nChecked-Site: crate-api", b"Checked-Site: crate-api\nVERDICT: VOTE",
    b"Some prose\nVERDICT: VOTE", b"VERDICT: VOTE\nSome prose",
    b"## Verdict: VOTE", b"**VERDICT: VOTE**", b"| Verdict | VOTE |",
    b"    VERDICT: VOTE", b"```\nVERDICT: VOTE", b"> VERDICT: VOTE",
])
@pytest.mark.parametrize("verdict", [b"ACCEPT", b"REQUEST CHANGES"])
def test_structured_sites_never_authorize_noncanonical_bytes(form, verdict):
    ledger = review.ReviewLedger()
    bound = _bind(ledger, form.replace(b"VOTE", verdict), verified=PROOF, expected_sites=("crate-api",))
    _refused(_vote(ledger, bound), "incomplete_evidence")
    assert bound["record"]["votes"] == []
    assert review.review_record(ledger, OBJECT)["record"] == bound["record"]


@pytest.mark.parametrize("line, verdict, gate", [
    (b"VERDICT: FIX FIRST", "request_changes", "refuse"),
    (b"VERDICT: INCOMPLETE", "incomplete", "hold"),
])
def test_exact_nonvoting_observations_keep_their_read_disposition(line, verdict, gate):
    ledger = review.ReviewLedger()
    bound = _bind(ledger, line, verified=PROOF, expected_sites=("crate-api",))
    assert (bound["round"]["parsed_verdict"], bound["round"]["effective_gate"]) == (verdict, gate)
    _refused(_vote(ledger, bound), "incomplete_evidence")


@pytest.mark.parametrize("sites, reason", [
    ("crate-api", "invalid_input"), (["crate-api", "crate-api"], "invalid_input"),
    (["crate-api\ncrate-io"], "invalid_input"), (["../outside"], "invalid_input"),
    ([MARKER + "x" * 64], "invalid_input"), ([MARKER] * 65, "limit_exceeded"),
])
def test_expected_sites_use_bounded_receipt_identifiers(sites, reason):
    ledger = review.ReviewLedger()
    _refused(_bind(ledger, verified=PROOF, expected_sites=sites), reason)
    _refused(review.review_record(ledger, OBJECT), "unknown_review")


def test_maximum_expected_sites_can_be_checked_in_any_order():
    ledger = review.ReviewLedger()
    sites = tuple(f"crate-{number:02d}" for number in range(64))
    bound = _bind(ledger, verified=PROOF, expected_sites=sites)
    voted = _vote(ledger, bound, sites=sites[::-1])
    vote, = voted["record"]["votes"]
    assert vote["checked_sites"] == list(sites)


def test_expected_sites_are_bound_to_the_version_and_correction():
    ledger = review.ReviewLedger()
    sites = ["crate-io", "crate-api"]
    first = _bind(ledger, verified=PROOF, expected_sites=sites)
    version = first["round"]["evidence_version"]
    sites.clear()
    replay = _bind(ledger, verified=PROOF, expected_sites=("crate-api", "crate-io"))
    assert (replay["effect"], replay["record"]) == ("already", first["record"])
    _refused(_bind(ledger, verified=PROOF, expected_sites=("crate-api",), identity=_round(generation=1)),
             "stale_report")
    assert _vote(ledger, first, sites=("crate-api", "crate-io"))["round"]["effective_gate"] == "pass"
    corrected = _bind(ledger, verified=PROOF, expected_sites=("crate-io",), identity=_round(generation=2),
                      replaces=version)
    assert corrected["round"]["evidence_version"] != version
    assert corrected["round"]["report_sha256"] == first["round"]["report_sha256"]
    assert corrected["record"]["votes"] == []
    _refused(_vote(ledger, first, expected_generation=3), "stale_report")
    _refused(_vote(ledger, corrected, sites=("crate-api", "crate-io")), "incomplete_evidence")
    assert _vote(ledger, corrected, sites=("crate-io",))["round"]["effective_gate"] == "pass"
    missing = _bind(ledger, verified=PROOF, identity=_round(generation=4),
                    replaces=corrected["round"]["evidence_version"])
    _refused(_vote(ledger, missing, sites=("crate-io",)), "incomplete_evidence")
    assert missing["record"]["votes"] == []


@pytest.mark.parametrize("missing", [None, ()])
def test_missing_expected_sites_need_a_new_binding(missing):
    ledger = review.ReviewLedger()
    first = _bind(ledger, verified=PROOF, expected_sites=missing)
    _refused(_vote(ledger, first), "incomplete_evidence")
    corrected = _bind(ledger, verified=PROOF, expected_sites=("crate-api",), identity=_round(generation=1),
                      replaces=first["round"]["evidence_version"])
    assert _vote(ledger, corrected)["round"]["effective_gate"] == "pass"


@pytest.mark.parametrize("report, parsed, refuses", [
    (b"Example from the previous tree:\n\n    VERDICT: REQUEST CHANGES\n    Checked-Site: crate-api\n",
     "request_changes", False),
    (b"```text\nVERDICT: REQUEST CHANGES\n```\n", "request_changes", False),
    (b"```text\nVERDICT: REQUEST CHANGES\n", "request_changes", False),
    (b"> VERDICT: REQUEST CHANGES\n", "incomplete", False),
    (b"Review complete.\nVERDICT: REQUEST CHANGES\n- P1 line 12: missing guard\n", "request_changes", False),
    (b"VERDICT: ACCEPT\nVERDICT: REQUEST CHANGES\n", "ambiguous", False),
    (b"VERDICT: REQUEST CHANGES\r\n", "request_changes", False),
    (b"VERDICT: FIX FIRST\n\n", "request_changes", False),
    (b"VERDICT: REQUEST CHANGES", "request_changes", True),
    (b"VERDICT: REQUEST CHANGES\n", "request_changes", True),
    (b"VERDICT: FIX FIRST", "request_changes", True),
    (b"VERDICT: FIX FIRST\n", "request_changes", True),
], ids=["indented", "fenced", "open_fence", "quote", "prose", "conflict", "crlf", "extra_lf",
        "request_changes", "request_changes_lf", "fix_first", "fix_first_lf"])
@pytest.mark.parametrize("report_first", [True, False])
def test_report_disposition_controls_peer_count_in_both_orders(report, parsed, refuses, report_first):
    ledger = review.ReviewLedger()
    report_generation = 0 if report_first else 2
    peer_generation = 1 if report_first else 0

    def bind_report():
        return _bind_checked(ledger, report, launch=_launch(family="beta"),
                             identity=_round(generation=report_generation, round_id="report"))

    if report_first:
        bound = bind_report()
    peer = _bind_checked(ledger, identity=_round(generation=peer_generation))
    checked = _vote(ledger, peer)
    if not report_first:
        assert checked["round"]["effective_gate"] == "pass"
        bound = bind_report()

    record = review.review_record(ledger, OBJECT)["record"]
    rows = {row["round_id"]: row for row in record["rounds"]}
    assert rows["report"]["parsed_verdict"] == parsed
    assert rows["report"]["effective_gate"] == ("refuse" if refuses else "hold")
    assert rows["round-1"]["effective_gate"] == "hold"
    assert rows["round-1"]["gate_reason"] == ("peer_refusal" if refuses else "check_incomplete")
    assert rows["round-1"]["counted"] is (not refuses)
    assert [vote["round_id"] for vote in record["votes"]] == ([] if refuses else ["round-1"])
    identities = review.served_identity(ledger, TREE)["identities"]
    assert {identity["round_id"]: identity["counted"] for identity in identities} == {
        "report": False, "round-1": not refuses,
    }
    replay = bind_report()
    assert (replay["effect"], replay["record"]) == ("already", record)
    replay = _vote(ledger, peer)
    assert (replay["effect"], replay["record"]) == ("already", record)
    if not refuses or report.startswith(b"VERDICT: FIX FIRST"):
        _refused(_vote(ledger, bound, expected_generation=record["generation"]), "incomplete_evidence")


@pytest.mark.parametrize("report, refuses", [
    (b"Review complete.\nVERDICT: REQUEST CHANGES\n", False),
    (b"VERDICT: REQUEST CHANGES\n", True),
], ids=["prose", "canonical"])
def test_report_disposition_survives_repair_and_requires_same_id_correction(report, refuses):
    ledger = review.ReviewLedger()
    peer = _bind_checked(ledger)
    assert _vote(ledger, peer)["round"]["effective_gate"] == "pass"
    copy = {"ok": False, "tree": TREE, "manifest_sha256": "d" * 64}
    launch = _launch(family="beta")
    bound = _bind_checked(ledger, report, launch=launch, copy_evidence=copy,
                          identity=_round(generation=2, round_id="report"))
    repaired = _repair(ledger, bound, {**copy, "ok": True})
    gate = "refuse" if refuses else "hold"
    assert repaired["round"]["effective_gate"] == gate
    previous = next(event for event in repaired["record"]["history"] if event["operation"] == "bound")
    assert previous["evidence_version"] == bound["round"]["evidence_version"]
    assert previous["effective_gate"] == gate
    assert _repair(ledger, bound, {**copy, "ok": True})["record"] == repaired["record"]
    if not refuses:
        _refused(_vote(ledger, repaired), "incomplete_evidence")

    corrected = _bind_checked(ledger, launch=launch, copy_evidence={**copy, "ok": True},
                              identity=_round(generation=4, round_id="report"),
                              replaces=repaired["round"]["evidence_version"])
    record = corrected["record"]
    rows = {row["round_id"]: row for row in record["rounds"]}
    assert rows["round-1"]["gate_reason"] == ("peer_refusal" if refuses else "check_incomplete")
    assert rows["round-1"]["counted"] is (not refuses)
    assert corrected["round"]["effective_gate"] == gate
    history = next(event for event in record["history"] if event["evidence_version"] == repaired["round"]["evidence_version"])
    assert history["effective_gate"] == gate
    _refused(_vote(ledger, repaired, expected_generation=record["generation"]), "stale_report")
    authorized = _vote(ledger, corrected)
    assert authorized["round"]["effective_gate"] == "pass"
    assert {vote["round_id"] for vote in authorized["record"]["votes"]} == {"round-1", "report"}
    assert _vote(ledger, corrected)["record"] == authorized["record"]


@pytest.mark.parametrize("report", [b"VERDICT: REQUEST CHANGES", b"VERDICT: FIX FIRST\n"])
@pytest.mark.parametrize("launch, parsed", [
    (_launch(brief_seen=False), "incomplete"),
    (_launch(state="timeout", model=None), "timeout"),
])
def test_canonical_refusal_requires_completed_brief_seen_launch(report, launch, parsed):
    ledger = review.ReviewLedger()
    bound = _bind_checked(ledger, report, launch=launch)
    assert (bound["round"]["parsed_verdict"], bound["round"]["effective_gate"]) == (parsed, "hold")
    _refused(_vote(ledger, bound), "incomplete_evidence")
