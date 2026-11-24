"""Public evidence contract for review observations."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from threading import Barrier
from types import MappingProxyType

import pytest

from aegis_core import team_review as review


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
    b"", b"VERDICT: ACCEPT\r\n", b"VERDICT: ACCEPT\n\n", b"VERDICT: ACCEPT ",
    b"VERDICT:  ACCEPT", b"Verdict: ACCEPT", b"VERDICT: accept", b"VERDICT = ACCEPT",
    b"VERDICT: REQUEST_CHANGES", b"**VERDICT: ACCEPT**", b"> VERDICT: REQUEST CHANGES",
    b"VERDICT: ACCEPT; VERDICT: REQUEST CHANGES", b"VERDICT: ACCEPT\nVERDICT: REQUEST CHANGES\n",
    b"VERDICT: REQUEST CHANGES\n- P1 line 12: missing guard\n", b"VERDICT: ACCEPT\nverdict_parser.py:42\n",
    b"\xef\xbb\xbfVERDICT: ACCEPT", "VERDICT: ACCEPT\u2028".encode(),
    b"VERDICT: ACCEPT\n" + MARKER.encode(),
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
    row = _observed(result, verdict)
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
