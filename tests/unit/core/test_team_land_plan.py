"""Read-only landing order: newest attempt, guard class, FIFO, and refusals.

Records and policy text are untrusted. These tests use repository-neutral
names and do not read Git history or open repository paths.
"""
from concurrent.futures import ThreadPoolExecutor

import pytest

from aegis_core import team_land_plan as plan


def _policy(**over):
    value = {"target_branch": "release", "strategy": "batch", "batch_max": 4,
             "registries": [], "jobs": {}}
    value.update(over)
    return value


def _attempt(**over):
    value = {"lane": "alpha", "attempt": 1, "ready_at": 10, "target": "release",
             "guard": False, "evidence": ("tree-pass",), "head": "a" * 40}
    value.update(over)
    return value


def _lanes(result):
    return [item.lane for item in result.order]


class _Boom:
    """Any use is a test failure: limits must refuse before reading the item."""

    def __len__(self):
        raise AssertionError("touched")

    def __str__(self):
        raise AssertionError("touched")

    def __repr__(self):
        raise AssertionError("touched")

    def __bool__(self):
        raise AssertionError("touched")


class _EqBoom(_Boom):
    """Equality must not run: a non-text strategy is a refusal, not a comparison."""

    def __eq__(self, _other):
        raise AssertionError("touched")

    def __hash__(self):
        raise AssertionError("touched")


def test_superseded_attempt_keeps_only_the_newest_per_lane():
    older = _attempt(attempt=1, ready_at=10, head="a" * 40)
    newer = _attempt(attempt=2, ready_at=30, head="b" * 40)
    other = _attempt(lane="beta", attempt=1, ready_at=20, head="c" * 40)
    result = plan.order_ready([older, newer, other], _policy())
    assert [(item.lane, item.attempt) for item in result.order] == [("beta", 1), ("alpha", 2)]
    superseded = [item for item in result.findings if item.code == "superseded"]
    assert [(item.lane, item.attempt) for item in superseded] == [("alpha", 1)]
    assert superseded[0].reason == plan.REFUSALS["superseded"]
    assert superseded[0].refused is False


def test_newer_ineligible_attempt_is_not_replaced_by_a_stale_one():
    stale = _attempt(attempt=1, target="release")
    newest = _attempt(attempt=2, target="elsewhere", ready_at=11, head="b" * 40)
    result = plan.order_ready([stale, newest], _policy(target_branch="release"))
    assert result.order == ()
    assert {item.code for item in result.findings} == {"superseded", "changed_target"}
    assert any(item.code == "changed_target" and item.attempt == 2 for item in result.findings)


def test_competing_lanes_place_eligible_guards_first_and_keep_fifo():
    records = [
        _attempt(lane="zulu", ready_at=2, guard=False),
        _attempt(lane="late", ready_at=8, guard=True, head="b" * 40),
        _attempt(lane="alpha", ready_at=4, guard=False, head="c" * 40),
        _attempt(lane="early", ready_at=3, guard=True, head="d" * 40),
    ]
    result = plan.order_ready(records, _policy(batch_max=1, strategy="direct"))
    assert _lanes(result) == ["early", "late", "zulu", "alpha"]
    assert result.batch_max == 1
    assert result.strategy == "direct"
    assert result.target == "release"
    assert result.schema == plan.SCHEMA
    # Same ready time follows supplied order, not lane-name order.
    tied = plan.order_ready(
        [_attempt(lane="zulu", ready_at=5), _attempt(lane="alpha", ready_at=5, head="b" * 40)],
        _policy())
    assert _lanes(tied) == ["zulu", "alpha"]


def test_ineligible_guard_does_not_precede_an_ordinary_lane():
    result = plan.order_ready(
        [_attempt(lane="guard", guard=True, evidence=(), ready_at=1),
         _attempt(lane="plain", ready_at=9, head="b" * 40)],
        _policy())
    assert _lanes(result) == ["plain"]
    assert any(item.code == "missing_evidence" and item.lane == "guard" for item in result.findings)


def test_missing_evidence_returns_its_refusal_and_skips_the_lane():
    result = plan.order_ready(
        [_attempt(lane="bare", evidence=()), _attempt(lane="kept", head="b" * 40)],
        _policy())
    assert _lanes(result) == ["kept"]
    finding = next(item for item in result.findings if item.lane == "bare")
    assert finding.code == "missing_evidence"
    assert finding.refused is True
    assert finding.reason == plan.REFUSALS["missing_evidence"]
    assert finding.next_action["actor"] == "owner"
    assert finding.next_action["command"] == finding.reason
    assert "bare" not in finding.reason


def test_changed_target_follows_policy_and_is_not_a_fixed_branch():
    result = plan.order_ready(
        [_attempt(lane="keep", target="integration"),
         _attempt(lane="drop", target="main", head="b" * 40)],
        _policy(target_branch="integration"))
    assert _lanes(result) == ["keep"]
    assert result.target == "integration"
    finding = next(item for item in result.findings if item.lane == "drop")
    assert finding.code == "changed_target"
    assert finding.reason == plan.REFUSALS["changed_target"]
    assert "main" not in finding.reason
    assert finding.next_action["lane"] == "drop"


def test_short_targets_with_slashes_are_matched_literally():
    result = plan.order_ready(
        [_attempt(target="release/v1"), _attempt(lane="beta", target="release/v2")],
        _policy(target_branch="release/v1"))
    assert result.target == "release/v1"
    assert [item.target for item in result.order] == ["release/v1"]
    assert result.findings == (plan.Finding("changed_target", "beta", 1),)


@pytest.mark.parametrize("target", ["HEAD", "refs/heads/release", "refs/tags/release", "refs/custom"],
                         ids=["head", "heads_ref", "tag_ref", "custom_ref"])
def test_attempt_refuses_reserved_targets_before_matching(target):
    record = _attempt(target=target)
    with pytest.raises(plan.LandPlanRefused) as caught:
        plan.order_ready([record], _policy())
    assert caught.value.code == "invalid_request"
    assert str(caught.value) == plan.REFUSALS["invalid_request"]
    with pytest.raises(plan.LandPlanRefused) as typed:
        plan.ReadyAttempt(**record)
    assert typed.value.code == "invalid_request"


@pytest.mark.parametrize("target", ["HEAD", "refs/heads/release", "refs/tags/release", "refs/custom"],
                         ids=["head", "heads_ref", "tag_ref", "custom_ref"])
def test_policy_refuses_reserved_targets_before_matching(target):
    with pytest.raises(plan.LandPlanRefused) as caught:
        plan.order_ready([_attempt()], _policy(target_branch=target))
    assert caught.value.code == "policy_unavailable"
    assert str(caught.value) == plan.REFUSALS["policy_unavailable"]


def test_ambiguous_supersession_is_flagged_and_excludes_the_lane():
    first = _attempt(attempt=4, head="a" * 40, ready_at=10)
    other = _attempt(attempt=4, head="b" * 40, ready_at=11)
    older = _attempt(attempt=3, head="c" * 40, ready_at=1)
    rival = _attempt(lane="beta", ready_at=5, head="d" * 40)
    result = plan.order_ready([older, first, other, rival], _policy())
    assert _lanes(result) == ["beta"]
    assert result.ambiguous_lanes == ("alpha",)
    ambiguous = [item for item in result.findings if item.code == "ambiguous_supersession"]
    assert {item.attempt for item in ambiguous} == {4}
    assert all(item.lane == "alpha" and item.refused is True for item in ambiguous)
    assert any(item.code == "superseded" and item.attempt == 3 for item in result.findings)


def test_replays_return_one_finding_per_code_lane_and_attempt():
    older = _attempt(attempt=2)
    latest = _attempt(attempt=4, guard=True)
    stale = _attempt(lane="zulu", attempt=2)
    records = [
        stale, older, latest, _attempt(lane="zulu", attempt=3, target="elsewhere"),
        dict(older), _attempt(attempt=2, head="b" * 40), _attempt(attempt=1),
        dict(latest), dict(latest, guard=False), dict(stale),
        _attempt(lane="gamma", evidence=()), _attempt(lane="beta"),
    ]
    result = plan.order_ready(records, _policy())
    assert _lanes(result) == ["beta"]
    assert result.ambiguous_lanes == ("alpha",)
    assert result.findings == (
        plan.Finding("superseded", "alpha", 1),
        plan.Finding("superseded", "alpha", 2),
        plan.Finding("ambiguous_supersession", "alpha", 4),
        plan.Finding("missing_evidence", "gamma", 1),
        plan.Finding("superseded", "zulu", 2),
        plan.Finding("changed_target", "zulu", 3),
    )
    assert plan.order_ready(list(reversed(records)), _policy()) == result


def test_identical_newest_duplicate_collapses_without_an_ambiguity_flag():
    one = _attempt(attempt=2, ready_at=4, head="b" * 40)
    result = plan.order_ready([_attempt(), one, dict(one)], _policy())
    assert [(item.lane, item.attempt) for item in result.order] == [("alpha", 2)]
    assert [item.code for item in result.findings] == ["superseded"]


def test_identical_newest_rows_keep_the_first_newest_fifo_position():
    newest = _attempt(lane="zulu", attempt=2)
    result = plan.order_ready(
        [_attempt(lane="zulu"), _attempt(lane="beta"), newest, _attempt(), dict(newest)],
        _policy())
    assert _lanes(result) == ["beta", "zulu", "alpha"]
    assert result.findings == (plan.Finding("superseded", "zulu", 1),)


def test_retry_withdraws_the_newest_then_restores_it():
    older = _attempt(attempt=1, ready_at=10, head="a" * 40)
    newer = _attempt(attempt=2, ready_at=12, head="b" * 40)
    policy = _policy()
    first = plan.order_ready([older, newer], policy)
    withdrawn = plan.order_ready([older], policy)
    restored = plan.order_ready((older, newer), policy)
    assert [item.attempt for item in first.order] == [2]
    assert [item.attempt for item in withdrawn.order] == [1]
    assert withdrawn.findings == ()
    assert restored == first


def test_failed_call_does_not_poison_the_next_order():
    with pytest.raises(plan.LandPlanRefused) as caught:
        plan.order_ready([_attempt(lane="bad lane")], _policy())
    assert caught.value.code == "invalid_request"
    assert caught.value.refused is True
    assert caught.value.reason == plan.REFUSALS["invalid_request"]
    assert "bad lane" not in str(caught.value)
    result = plan.order_ready([_attempt()], _policy())
    assert _lanes(result) == ["alpha"]


def test_concurrent_orders_agree_and_leave_inputs_unchanged():
    records = [
        _attempt(lane="zulu", ready_at=2),
        _attempt(lane="early", ready_at=3, guard=True, head="b" * 40),
        _attempt(lane="alpha", attempt=1, ready_at=1, head="c" * 40),
        _attempt(lane="alpha", attempt=2, ready_at=4, head="d" * 40),
    ]
    policy = _policy()
    before = [dict(item) for item in records]

    def run(_index):
        return plan.order_ready(records, policy)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(run, range(8)))
    assert all(result == results[0] for result in results)
    assert _lanes(results[0]) == ["early", "zulu", "alpha"]
    assert records == before


def test_missing_policy_target_is_policy_unavailable_without_echo():
    marker = "NOT-ECHOED"
    with pytest.raises(plan.LandPlanRefused) as caught:
        plan.order_ready([_attempt()], {"strategy": "batch", "note": marker})
    assert caught.value.code == "policy_unavailable"
    assert marker not in str(caught.value)
    assert marker not in repr(caught.value)
    assert caught.value.next_action["command"] == caught.value.reason
    assert caught.value.exit_code == 1
    with pytest.raises(plan.LandPlanRefused) as strategy:
        plan.order_ready([_attempt()], {"target_branch": "release", "strategy": "fast"})
    assert strategy.value.code == "policy_unavailable"
    with pytest.raises(plan.LandPlanRefused) as boolean:
        plan.order_ready([_attempt()], {"target_branch": "release", "batch_max": True})
    assert boolean.value.code == "policy_unavailable"
    with pytest.raises(plan.LandPlanRefused) as traversal:
        plan.order_ready([_attempt()], {"target_branch": "release/../other"})
    assert traversal.value.code == "policy_unavailable"
    with pytest.raises(plan.LandPlanRefused) as hostile:
        plan.order_ready([_attempt()], {"target_branch": "release", "strategy": _EqBoom()})
    assert hostile.value.code == "policy_unavailable"
    with pytest.raises(plan.LandPlanRefused) as keys:
        plan.order_ready([_attempt()], {"target_branch": "release", _Boom(): "unused"})
    assert keys.value.code == "policy_unavailable"
    kept = plan.order_ready([_attempt()], {"target_branch": "release", "ignored": _Boom()})
    assert _lanes(kept) == ["alpha"]


def test_multiline_fields_are_refused_not_joined():
    marker = "NOT-ECHOED"
    joined = "rel" + marker
    with pytest.raises(plan.LandPlanRefused) as caught:
        plan.order_ready([_attempt(target="rel\n" + marker)], _policy())
    assert caught.value.code == "invalid_request"
    assert marker not in str(caught.value)
    assert marker not in repr(caught.value)
    assert joined not in str(caught.value)
    with pytest.raises(plan.LandPlanRefused) as evidence:
        plan.order_ready([_attempt(evidence="tree\n" + marker)], _policy())
    assert evidence.value.code == "invalid_request"
    # The joined spelling is a legal target. Only an actual one-line value may use it.
    accepted = plan.order_ready([_attempt(target=joined)], _policy(target_branch=joined))
    assert accepted.target == joined


def test_target_limit_refuses_instead_of_truncating():
    bounded = "n" * 255
    accepted = plan.order_ready([_attempt(target=bounded)], {"target_branch": bounded})
    assert accepted.target == bounded
    assert accepted.strategy == "combined-full"
    assert accepted.batch_max == 1
    with pytest.raises(plan.LandPlanRefused) as caught:
        plan.order_ready([_attempt()], {"target_branch": "n" * 256})
    assert caught.value.code == "policy_unavailable"
    assert caught.value.reason == plan.REFUSALS["policy_unavailable"]
    assert "nnnn" not in str(caught.value)


@pytest.mark.parametrize("construct", [True, False], ids=["constructor", "mapping"])
def test_maximum_length_evidence_refuses_redactor_changes(construct):
    token = "a" * 114 + "-token:" + "REDA..."
    assert len(token) == 128
    record = _attempt(evidence=(token,))
    with pytest.raises(plan.LandPlanRefused) as caught:
        if construct:
            plan.ReadyAttempt(**record)
        else:
            plan.order_ready([record], _policy())
    refused = caught.value
    reason = "landing plan request is malformed or oversized"
    assert refused.code == "invalid_request"
    assert str(refused) == refused.reason == reason
    assert refused.next_action == {"actor": "owner", "command": reason}
    assert token not in repr(refused)


def test_unchanged_maximum_length_evidence_is_preserved():
    token = "a" * 125 + "..."
    record = _attempt(evidence=(token,))
    typed = plan.ReadyAttempt(**record)
    assert typed.evidence == (token,)
    assert plan.order_ready([record], _policy()).order == (typed,)
    assert plan.order_ready([typed], _policy()).order == (typed,)


@pytest.mark.parametrize("field, value", [
    ("lane", "a" * 64),
    ("target", "a" * 256),
    ("head", "a" * 65),
    ("evidence", ("a" * 129,)),
], ids=["lane_length", "target_length", "head_length", "token_length"])
def test_order_ready_refuses_oversized_attempt_fields(field, value):
    with pytest.raises(plan.LandPlanRefused) as caught:
        plan.order_ready([_attempt(**{field: value})], _policy())
    assert caught.value.code == "invalid_request"
    assert str(caught.value) == plan.REFUSALS["invalid_request"]


def test_order_ready_rechecks_typed_attempt_evidence_count(monkeypatch):
    limit = plan.MAX_EVIDENCE
    typed = plan.ReadyAttempt(**_attempt(evidence=("tree-pass",) * limit))
    assert plan.order_ready([typed], _policy()).order == (typed,)

    monkeypatch.setattr(plan, "MAX_EVIDENCE", limit - 1)
    with pytest.raises(plan.LandPlanRefused) as caught:
        plan.order_ready([typed], _policy())
    assert caught.value.code == "invalid_request"
    assert str(caught.value) == plan.REFUSALS["invalid_request"]


def test_over_limit_input_is_refused_before_its_items_are_read():
    with pytest.raises(plan.LandPlanRefused) as records:
        plan.order_ready([_Boom()] * (plan.MAX_RECORDS + 1), _policy())
    assert records.value.code == "invalid_request"
    with pytest.raises(plan.LandPlanRefused) as evidence:
        plan.order_ready([_attempt(evidence=[_Boom()] * (plan.MAX_EVIDENCE + 1))], _policy())
    assert evidence.value.code == "invalid_request"
    with pytest.raises(plan.LandPlanRefused) as policy:
        plan.order_ready([_attempt()], {"target_branch": "n" * 256})
    assert policy.value.code == "policy_unavailable"


def test_unbounded_iterator_and_extra_keys_are_invalid_requests():
    def _generate():
        yield _attempt()
        raise AssertionError("consumed")

    with pytest.raises(plan.LandPlanRefused) as generated:
        plan.order_ready(_generate(), _policy())
    assert generated.value.code == "invalid_request"
    extra = _attempt()
    extra["note"] = "NOT-ECHOED"
    with pytest.raises(plan.LandPlanRefused) as caught:
        plan.order_ready([extra], _policy())
    assert caught.value.code == "invalid_request"
    assert "NOT-ECHOED" not in str(caught.value)


def test_empty_ready_set_is_a_stable_order():
    result = plan.order_ready((), _policy())
    assert result.order == ()
    assert result.findings == ()
    assert plan.order_ready([], _policy()) == result
