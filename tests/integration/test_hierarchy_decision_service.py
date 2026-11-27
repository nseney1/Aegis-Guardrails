"""Public decision boundary contracts; inert result data is never authority.

These tests do not fake a writer, HostAuthority or a positive LIVE invocation.
The service's real H/N1 composition remains a separate required source gate.
"""
import copy
import importlib

import pytest


ERRORS = {
    "INVALID_DECISION_INPUT": "invalid decision command",
    "HOST_AUTHORITY_UNAVAILABLE": "protected host authority is unavailable",
    "UNAUTHORIZED_ROLE": "decision requires a current ROOT HostInvocation",
    "STALE_INVOCATION": "decision invocation is stale",
    "STALE_GENERATION_OR_CUSTODY": "current canonical generation or custody changed",
    "SOURCE_MISMATCH": "protected canonical source binding mismatch",
    "REQUEST_HASH_MISMATCH": "request sha256 mismatch",
    "UNKNOWN_REQUEST": "unknown request id",
    "BOUNDED_AUTHORITY_EXPIRED": "bounded authority expired",
    "REPLAY_CONFLICT": "event id conflicts with different decision payload",
    "DECISION_CONFLICT": "decision requires an authority request and a valid first approve/deny or approve-to-deny transition",
    "CAP_REACHED": "actor cumulative active cap reached",
    "CANONICAL_WRITER_BUSY": "mailbox writer is busy; inspect an abandoned lock before retrying",
    "PUBLICATION_UNKNOWN": "canonical decision publication is unresolved",
}


def service_module():
    # ModuleNotFoundError here is FEATURE_ABSENT until the new public module is
    # implemented. It is not a semantic RED or a passing dependency skip.
    return importlib.import_module("tools.hierarchy_decision_service")


def command(**changes):
    result = {"event_id": "decision-one", "request_id": "request-one",
              "request_sha256": "a" * 64, "decision": "approve", "reason": "owner decision"}
    result.update(changes)
    return result


def result_data(state="recorded", code=None):
    """Inert ten-field DATA example, not a mocked producer call or grant."""
    receipt = {"event_id": "decision-one", "sequence": 7,
               "event_sha256": "b" * 64, "execution_enabled": False}
    if state in ("recorded", "recovered"):
        effect = "canonical_decision" if state == "recorded" else "none"
        reason = "canonical decision recorded" if state == "recorded" else "original canonical receipt recovered"
    else:
        effect = "possible" if state == "unknown" else "none"
        code = code or ("PUBLICATION_UNKNOWN" if state == "unknown" else "STALE_INVOCATION")
        reason, receipt = ERRORS[code], None
    return {"schema": "aegis.protected-decision-commit/v1", "state": state,
            "effect": effect, "code": code, "reason": reason, "event_id": "decision-one",
            "request_id": "request-one", "request_sha256": "a" * 64,
            "receipt": receipt, "native_qualified": False}


def test_command_validation_preserves_exact_data_and_returns_a_copy():
    supplied = command(reason=" é owner decision \n")
    before = copy.deepcopy(supplied)
    validated = service_module().validate_command(supplied)
    assert validated == before and type(validated) is dict
    assert validated is not supplied
    validated["reason"] = "changed consumer copy"
    assert supplied == before


@pytest.mark.parametrize("changes", [
    {"event_id": "0"}, {"event_id": "a" * 80}, {"request_id": "r_1-end"},
    {"decision": "deny"}, {"reason": " "}, {"reason": "x" * 1024},
])
def test_command_validation_accepts_exact_boundary_values(changes):
    supplied = command(**changes)
    assert service_module().validate_command(supplied) == supplied


@pytest.mark.parametrize("changes", [
    {"event_id": True}, {"event_id": "A"}, {"event_id": "a" * 81},
    {"event_id": "event\n"}, {"request_id": None}, {"request_id": False},
    {"request_id": ""}, {"request_id": "a/b"}, {"request_sha256": "A" * 64},
    {"request_sha256": "a" * 63}, {"request_sha256": "a" * 65},
    {"request_sha256": True}, {"request_sha256": 1},
    {"decision": "APPROVE"}, {"decision": "execute"}, {"decision": True},
    {"decision": []}, {"reason": ""}, {"reason": "x" * 1025},
    {"reason": "bad\0reason"}, {"reason": False}, {"reason": {}},
    {"actor": "root"}, {"generation": 2}, {"custody": {}},
    {"source": {}}, {"raw": "{}"}, {"native_qualified": True},
    {"decision_recovery_event_id": "decision-one"},
])
def test_command_validation_rejects_malformed_or_authority_fields(changes):
    with pytest.raises(ValueError, match="^invalid decision command$"):
        service_module().validate_command(command(**changes))


@pytest.mark.parametrize("key", ["event_id", "request_id", "request_sha256", "decision", "reason"])
def test_command_validation_requires_all_five_fields(key):
    supplied = command()
    del supplied[key]
    with pytest.raises(ValueError, match="^invalid decision command$"):
        service_module().validate_command(supplied)


@pytest.mark.parametrize("supplied", [None, [], (), "{}", True, 1])
def test_command_validation_refuses_non_objects(supplied):
    with pytest.raises(ValueError, match="^invalid decision command$"):
        service_module().validate_command(supplied)


def test_command_validation_does_not_execute_mapping_or_string_overrides():
    class HostileDict(dict):
        def keys(self):
            raise AssertionError("custom mapping must not be evaluated")

    class HostileString(str):
        def __eq__(self, other):
            raise AssertionError("custom scalar must not be evaluated")

    for supplied in (HostileDict(command()), command(reason=HostileString("owner decision"))):
        with pytest.raises(ValueError, match="^invalid decision command$"):
            service_module().validate_command(supplied)


@pytest.mark.parametrize("state", ["recorded", "recovered", "refused", "unknown"])
def test_projection_drops_only_event_id_and_replaces_schema_without_mutation(state):
    supplied = result_data(state)
    before = copy.deepcopy(supplied)
    projected = service_module().project_commit_result(supplied, command=command())
    expected = {key: value for key, value in before.items() if key != "event_id"}
    expected["schema"] = "aegis.decision-service-result/v1"
    assert projected == expected
    assert set(projected) == {"schema", "state", "effect", "code", "reason", "request_id",
                              "request_sha256", "receipt", "native_qualified"}
    assert projected["native_qualified"] is False
    assert supplied == before
    if projected["receipt"] is not None:
        projected["receipt"]["sequence"] = 999
        assert supplied == before


@pytest.mark.parametrize("code", [key for key in ERRORS if key != "PUBLICATION_UNKNOWN"])
def test_projection_preserves_closed_refusal_codes_and_exact_reasons(code):
    supplied = result_data("refused", code)
    submitted = command(reason="") if code == "INVALID_DECISION_INPUT" else command()
    projected = service_module().project_commit_result(supplied, command=submitted)
    assert projected["code"] == code and projected["reason"] == ERRORS[code]
    assert projected["receipt"] is None and projected["effect"] == "none"


@pytest.mark.parametrize("key", ["event_id", "request_id", "request_sha256"])
def test_projection_preserves_invalid_correlation_nulls_without_coercion(key):
    submitted = command(**{key: True})
    supplied = result_data("refused", "INVALID_DECISION_INPUT")
    supplied[key] = None
    projected = service_module().project_commit_result(supplied, command=submitted)
    assert projected["code"] == "INVALID_DECISION_INPUT"
    assert "event_id" not in projected
    if key != "event_id":
        assert projected[key] is None


@pytest.mark.parametrize("key,value", [
    ("schema", "wrong"), ("state", "accepted"), ("state", []),
    ("effect", "possible"), ("code", "PUBLICATION_UNKNOWN"),
    ("reason", "a rewritten success"), ("native_qualified", True),
    ("native_qualified", 0), ("event_id", "different"),
    ("request_id", "different"), ("request_sha256", "c" * 64),
    ("receipt", None), ("extra", "caller data"),
])
def test_projection_rejects_malformed_or_cross_request_producer_data(key, value):
    supplied = result_data()
    supplied[key] = value
    with pytest.raises(ValueError, match="^invalid canonical decision result$"):
        service_module().project_commit_result(supplied, command=command())


@pytest.mark.parametrize("key,value", [
    ("event_id", "different"), ("sequence", True), ("sequence", 0),
    ("sequence", 1.0), ("event_sha256", "A" * 64),
    ("execution_enabled", True), ("execution_enabled", 0), ("extra", "grant"),
])
def test_projection_rejects_changed_or_noncanonical_receipt_shapes(key, value):
    supplied = result_data()
    supplied["receipt"][key] = value
    with pytest.raises(ValueError, match="^invalid canonical decision result$"):
        service_module().project_commit_result(supplied, command=command())


@pytest.mark.parametrize("key", list(result_data()))
def test_projection_requires_all_ten_producer_fields(key):
    supplied = result_data()
    del supplied[key]
    with pytest.raises(ValueError, match="^invalid canonical decision result$"):
        service_module().project_commit_result(supplied, command=command())


@pytest.mark.parametrize("state,code", [("unknown", "STALE_INVOCATION"),
                                        ("refused", "PUBLICATION_UNKNOWN")])
def test_projection_cannot_reclassify_publication_ambiguity_as_no_effect(state, code):
    supplied = result_data(state, code)
    with pytest.raises(ValueError, match="^invalid canonical decision result$"):
        service_module().project_commit_result(supplied, command=command())


def test_projection_cannot_attach_a_receipt_to_unknown():
    supplied = result_data("unknown")
    supplied["receipt"] = result_data()["receipt"]
    with pytest.raises(ValueError, match="^invalid canonical decision result$"):
        service_module().project_commit_result(supplied, command=command())


def test_projection_cannot_turn_invalid_input_into_a_recorded_decision():
    with pytest.raises(ValueError, match="^invalid canonical decision result$"):
        service_module().project_commit_result(result_data(), command=command(decision=True))


def test_projection_rejects_invalid_input_code_for_an_exact_valid_command():
    supplied = result_data("refused", "INVALID_DECISION_INPUT")
    with pytest.raises(ValueError, match="^invalid canonical decision result$"):
        service_module().project_commit_result(supplied, command=command())


@pytest.mark.parametrize("state,code", [("refused", "STALE_INVOCATION"),
                                        ("unknown", "PUBLICATION_UNKNOWN")])
def test_projection_rejects_later_authority_or_publication_outcome_for_invalid_input(state, code):
    supplied = result_data(state, code)
    with pytest.raises(ValueError, match="^invalid canonical decision result$"):
        service_module().project_commit_result(supplied, command=command(reason=""))


@pytest.mark.parametrize("submitted", [None, [], {}, {"event_id": True}])
def test_projection_accepts_invalid_input_with_all_individually_invalid_correlations_null(submitted):
    supplied = result_data("refused", "INVALID_DECISION_INPUT")
    for key in ("event_id", "request_id", "request_sha256"):
        supplied[key] = None
    projected = service_module().project_commit_result(supplied, command=submitted)
    assert projected["request_id"] is None and projected["request_sha256"] is None
    assert projected["code"] == "INVALID_DECISION_INPUT" and projected["receipt"] is None


@pytest.mark.parametrize("supplied", [None, [], (), "{}", True, 1])
def test_projection_rejects_non_objects(supplied):
    with pytest.raises(ValueError, match="^invalid canonical decision result$"):
        service_module().project_commit_result(supplied, command=command())


def test_projection_refuses_mapping_scalar_and_receipt_overrides_without_evaluating_them():
    class HostileDict(dict):
        def keys(self):
            raise AssertionError("custom result mapping must not be evaluated")

    class HostileString(str):
        def __eq__(self, other):
            raise AssertionError("custom result scalar must not be evaluated")

    mapping = HostileDict(result_data())
    scalar = result_data()
    scalar["state"] = HostileString("recorded")
    receipt = result_data()
    receipt["receipt"] = HostileDict(receipt["receipt"])
    for supplied in (mapping, scalar, receipt):
        with pytest.raises(ValueError, match="^invalid canonical decision result$"):
            service_module().project_commit_result(supplied, command=command())


def test_full_service_public_api_remains_required_beyond_inert_boundary():
    module = service_module()
    assert callable(module.DecisionService.handle)
    assert callable(module.CanonicalDecisionBackend.commit)


def public_service(session):
    module = service_module()
    return module.DecisionService(module.CanonicalDecisionBackend(session))


def assert_service_result(answer, submitted, state, effect, code, reason, receipt=None):
    assert answer == {"schema": "aegis.decision-service-result/v1", "state": state,
                      "effect": effect, "code": code, "reason": reason,
                      "request_id": submitted["request_id"],
                      "request_sha256": submitted["request_sha256"],
                      "receipt": receipt, "native_qualified": False}


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_service_public_real_root_records_once_through_fixed_dispatch(
        tmp_path, monkeypatch, decision):
    from tests.integration.test_hierarchy_lifecycle import canonical_live_decision

    with canonical_live_decision(tmp_path, monkeypatch, changes={"decision": decision}) as values:
        lifecycle, binding, session, invocation, submitted, _, requests, _ = values
        ledger = lifecycle.Lifecycle(binding.canonical_root)
        before = ledger.load()[1]
        service = public_service(session)  # Observe missing API after real H/INITIAL/LIVE.
        answer = service.handle(invocation, submitted)
        after = ledger.load()[1]
        assert_service_result(answer, submitted, "recorded", "canonical_decision", None,
                              "canonical decision recorded", after["receipts"][submitted["event_id"]])
        assert after["sequence"] == before["sequence"] + 1
        assert len(after["decisions"]) == 1
        assert after["decisions"][0]["decision"] == decision
        assert after["decisions"][0]["reason"] == submitted["reason"]
        assert after["requests"] == before["requests"]
        assert [row["method"] for row in requests] == [
            "describe", "reserve_initial", "bind_initial", "start_initial",
            "describe_live", "enroll_live", "pending_call"]


@pytest.mark.parametrize("field,changed", [
    ("event_id", "changed-event"), ("request_id", "changed-request"),
    ("request_sha256", "f" * 64), ("decision", "deny"),
    ("reason", "changed after actual receive"),
])
def test_service_public_all_five_inputs_match_actual_received_frame(
        tmp_path, monkeypatch, field, changed):
    from tests.integration.test_hierarchy_lifecycle import canonical_live_decision, canonical_files

    with canonical_live_decision(tmp_path, monkeypatch) as values:
        _, binding, session, invocation, submitted, _, requests, _ = values
        service = public_service(session)
        before, methods = canonical_files(binding.canonical_root), [r["method"] for r in requests]
        supplied = dict(submitted, **{field: changed})
        answer = service.handle(invocation, supplied)
        assert_service_result(answer, supplied, "refused", "none", "STALE_INVOCATION",
                              "decision invocation is stale")
        assert canonical_files(binding.canonical_root) == before
        assert [row["method"] for row in requests] == methods


@pytest.mark.parametrize("changes", [{"reason": ""}, {"decision": True}, {"extra": "authority"}])
def test_service_public_invalid_data_precedes_real_reserved_context(
        tmp_path, monkeypatch, changes):
    from tests.integration.test_hierarchy_lifecycle import canonical_live_decision, canonical_files

    with canonical_live_decision(tmp_path, monkeypatch) as values:
        _, binding, session, _, submitted, _, requests, _ = values
        service = public_service(session)
        before, methods = canonical_files(binding.canonical_root), [r["method"] for r in requests]
        supplied = dict(submitted, **changes)
        answer = service.handle(binding.reservations[0], supplied)
        assert_service_result(answer, supplied, "refused", "none", "INVALID_DECISION_INPUT",
                              "invalid decision command")
        assert canonical_files(binding.canonical_root) == before
        assert [row["method"] for row in requests] == methods


def test_service_public_valid_data_cannot_promote_actual_reservation(tmp_path, monkeypatch):
    from tests.integration.test_hierarchy_lifecycle import canonical_live_decision, canonical_files

    with canonical_live_decision(tmp_path, monkeypatch) as values:
        _, binding, session, _, submitted, _, requests, _ = values
        service = public_service(session)
        before, methods = canonical_files(binding.canonical_root), [r["method"] for r in requests]
        answer = service.handle(binding.reservations[0], submitted)
        assert_service_result(answer, submitted, "refused", "none", "UNAUTHORIZED_ROLE",
                              "decision requires a current ROOT HostInvocation")
        assert canonical_files(binding.canonical_root) == before
        assert [row["method"] for row in requests] == methods


def test_service_public_second_handle_cannot_append_again(tmp_path, monkeypatch):
    from tests.integration.test_hierarchy_lifecycle import canonical_live_decision, canonical_files

    with canonical_live_decision(tmp_path, monkeypatch) as values:
        _, binding, session, invocation, submitted, _, _, _ = values
        service = public_service(session)
        assert service.handle(invocation, submitted)["state"] == "recorded"
        before = canonical_files(binding.canonical_root)
        answer = service.handle(invocation, submitted)
        assert_service_result(answer, submitted, "refused", "none", "STALE_INVOCATION",
                              "decision invocation is stale")
        assert canonical_files(binding.canonical_root) == before


@pytest.mark.parametrize("capped,future", [(False, False), (True, True)])
def test_service_public_recovers_original_receipt_without_new_budget(
        tmp_path, monkeypatch, capped, future):
    from tests.integration.test_hierarchy_lifecycle import canonical_live_decision, canonical_files

    with canonical_live_decision(tmp_path, monkeypatch, seed=True,
                                 capped=capped, future=future) as values:
        _, binding, session, invocation, submitted, receipt, _, _ = values
        service = public_service(session)
        before = canonical_files(binding.canonical_root)
        answer = service.handle(invocation, submitted)
        assert_service_result(answer, submitted, "recovered", "none", None,
                              "original canonical receipt recovered", receipt)
        assert canonical_files(binding.canonical_root) == before


@pytest.mark.parametrize("changes", [
    {"request_id": "another-authority"}, {"request_sha256": "f" * 64},
    {"decision": "deny"}, {"reason": "changed incoming reason"},
])
def test_service_public_journal_conflict_differs_from_changed_direct_input(
        tmp_path, monkeypatch, changes):
    from tests.integration.test_hierarchy_lifecycle import canonical_live_decision, canonical_files

    with canonical_live_decision(tmp_path, monkeypatch, seed=True, changes=changes) as values:
        _, binding, session, invocation, submitted, _, _, _ = values
        service = public_service(session)
        before = canonical_files(binding.canonical_root)
        answer = service.handle(invocation, submitted)
        assert_service_result(answer, submitted, "refused", "none", "REPLAY_CONFLICT",
                              "event id conflicts with different decision payload")
        assert canonical_files(binding.canonical_root) == before


@pytest.mark.parametrize("cut", ["before-link", "after-link"])
def test_service_public_possible_publication_stays_unknown(tmp_path, monkeypatch, cut):
    import os
    from pathlib import Path
    from tests.integration.test_hierarchy_lifecycle import canonical_live_decision

    with canonical_live_decision(tmp_path, monkeypatch) as values:
        lifecycle, binding, session, invocation, submitted, _, _, _ = values
        ledger = lifecycle.Lifecycle(binding.canonical_root)
        before = ledger.load()[1]
        destination = binding.canonical_root / "events" / ("%06d.json" % (before["sequence"] + 1))
        service = public_service(session)
        real_link = os.link

        def publication(source, target, *args, **kwargs):
            if Path(target) == destination:
                if cut == "before-link":
                    raise OSError("external decision link boundary failed")
                real_link(source, target, *args, **kwargs)
                raise OSError("external decision link reply lost")
            return real_link(source, target, *args, **kwargs)

        with monkeypatch.context() as boundary:
            boundary.setattr(os, "link", publication)
            answer = service.handle(invocation, submitted)
        assert_service_result(answer, submitted, "unknown", "possible", "PUBLICATION_UNKNOWN",
                              "canonical decision publication is unresolved")
        assert destination.exists() is (cut == "after-link")


def test_service_public_constructors_reject_actual_reservation_types(tmp_path, monkeypatch):
    from tests.integration.test_hierarchy_lifecycle import canonical_live_decision

    with canonical_live_decision(tmp_path, monkeypatch) as values:
        _, binding, _, _, _, _, _, _ = values
        module = service_module()
        for invalid in (None, {}, binding.reservations[0]):
            with pytest.raises(TypeError, match="^backend requires an owned HostSession$"):
                module.CanonicalDecisionBackend(invalid)
            with pytest.raises(TypeError, match="^service requires a CanonicalDecisionBackend$"):
                module.DecisionService(invalid)


@pytest.mark.parametrize("branch", ["changed-command", "exact-original-command"])
def test_service_prior_guard_history_cannot_project_no_effect_refusal(
        tmp_path, monkeypatch, branch):
    from tools import hierarchy_host_authority as host
    from tests.integration.test_hierarchy_lifecycle import canonical_live_decision

    with canonical_live_decision(tmp_path, monkeypatch) as values:
        lifecycle, binding, session, invocation, submitted, _, requests, _ = values
        ledger = lifecycle.Lifecycle(binding.canonical_root)
        service = public_service(session)
        before = ledger.load()
        original_event_id = invocation.event_id
        assert original_event_id == submitted["event_id"]

        # Keep real H, its present N1 producer and the canonical row. Only
        # public scopes are used; this setup does not dispatch a decision.
        with session.authority.effect_fence(invocation, "decision"):
            with lifecycle.writer_lock(binding.canonical_root):
                policy, state = ledger.load()
                session.authority.require_current(invocation, policy, state, None)
                session.authority.require_current(
                    invocation, policy, state, state["requests"][submitted["request_id"]])
        assert ledger.load() == before
        command = dict(submitted)
        if branch == "changed-command":
            command["reason"] = "changed after original guard exit"

        answer = service.handle(invocation, command)
        assert_service_result(answer, command, "unknown", "possible", "PUBLICATION_UNKNOWN",
                              "canonical decision publication is unresolved")
        assert invocation.event_id == original_event_id
        assert ledger.load() == before
        assert requests[-1]["method"] == "pending_call"
        assert not any(row["method"] == "retire_call" for row in requests)

        for attempt in (
                lambda: session.dispatch_decision(invocation, command),
                lambda: session.reply(invocation, {"success": False, "contentItems": [
                    {"type": "inputText", "text": "unresolved"}]}),
                session.receive_invocation):
            with pytest.raises(host.HostAuthorityError) as stale:
                attempt()
            assert stale.value.code == "STALE_INVOCATION"
        assert not any(row["method"] == "retire_call" for row in requests)
        assert ledger.load() == before
