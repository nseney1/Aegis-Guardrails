"""Recoverable unclaim transitions through the public queue service."""
from concurrent.futures import ProcessPoolExecutor
import json
import os
import shutil
import subprocess
import time
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import events, gitsafe, storage, team, team_claims, team_queue as queue


@pytest.fixture
def make_store(tmp_path):
    if not queue.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    if shutil.which("git") is None:
        pytest.skip("requires git")
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / ".aegis").mkdir()
    (root / ".aegis" / "team.json").write_text(json.dumps({
        "v": 1, "lanes": {"alpha": ["src/**"], "beta": ["docs/**"]}}), encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    os.environ.update(HOME=str(home), USERPROFILE=str(home))
    return root


def held(root):
    added = queue.add(root, {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}, now=100)
    claimed = queue.claim(root, "ONE", expect=added["item"]["revision"], lane="alpha", now=101, caller="owner")
    assert not claimed["refused"], claimed
    lease = team.claim(root, "alpha", ["src/**"], owner="owner", now=100)
    return claimed["item"]["revision"], lease.oid


def unclaim(root, revision, **kwargs):
    return queue.unclaim(root, "ONE", expect=revision, lane=kwargs.pop("lane", "alpha"),
                         now=kwargs.pop("now", 102), caller="owner", writer_stopped=True, **kwargs)


def receipts(root):
    return [row for row in events.read(root).rows if row["detail"].get("action") == "unclaim"]


def test_unclaim_releases_intersecting_lease_and_records_once(make_store):
    revision, oid = held(make_store)
    unrelated = team.claim(make_store, "beta", ["docs/**"], owner="owner", now=100)
    before = queue.list(make_store, now=102)["claimable_fingerprint"]
    result = unclaim(make_store, revision, reason="Waiting for review")
    assert not result["refused"], result
    assert result["item"]["state"] == "queued" and result["released_lease_ids"] == [oid]
    assert team.read_leases(make_store).get("alpha") is None
    assert team.read_leases(make_store).get("beta").oid == unrelated.oid
    rows = receipts(make_store)
    assert len(rows) == 1
    assert rows[0]["detail"]["reason"] == "Waiting for review"
    assert rows[0]["detail"]["released_lease_ids"] == [oid]
    assert rows[0]["detail"]["lane"] == "alpha"
    assert rows[0]["detail"]["writer_stopped"] is True and rows[0]["detail"]["caller"] == "owner"
    assert queue.list(make_store, now=102)["claimable_fingerprint"] != before
    assert unclaim(make_store, revision)["reason"] == "stale_revision"
    assert len(receipts(make_store)) == 1


@pytest.mark.parametrize("case,reason", [("stale", "stale_revision"), ("lane", "lane_mismatch"),
                                        ("expired-lane", "lane_mismatch"), ("done", "item_done")])
def test_unclaim_refusals_preserve_queue_and_leases(make_store, case, reason):
    revision, oid = held(make_store)
    if case == "done":
        revision = queue.done(make_store, "ONE", expect=revision, lane="alpha", now=102)["item"]["revision"]
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = unclaim(make_store, "0" * 64 if case == "stale" else revision,
                     lane="beta" if "lane" in case else "alpha", now=10000 if case == "expired-lane" else 103)
    assert result["reason"] == reason and result["exit_code"] == 1
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid
    assert receipts(make_store) == []


@pytest.mark.parametrize("reason,code", [("token=private-value", "credential_like_text"),
    ("private-value\ntrailer", "invalid_item"), ("x" * (queue.MAX_TEXT + 1), "invalid_item")])
def test_unclaim_reason_is_bounded_single_line_and_private(make_store, reason, code):
    revision, oid = held(make_store)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = unclaim(make_store, revision, reason=reason)
    assert result["reason"] == code and result["exit_code"] == 2
    assert "private-value" not in json.dumps(result)
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid


@pytest.mark.parametrize("case", ["foreign-owner", "foreign-lane", "unreadable"])
def test_unclaim_lease_preflight_refuses_without_changes(make_store, case):
    revision, oid = held(make_store)
    if case == "foreign-owner":
        team.transfer(make_store, "alpha", oid, owner="someone-else", now=102)
    elif case == "foreign-lane":
        team.release(make_store, "alpha", oid, caller="owner")
        team.claim(make_store, "beta", ["src/**"], owner="someone-else", now=100)
    else:
        bad = gitsafe.write_blob(make_store, b"{}")
        gitsafe.update_ref(make_store, team.lane_ref("alpha"), bad, oid)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before, refs = path.read_bytes(), gitsafe.list_refs(make_store, team.LANES_REF)
    for _ in range(2):
        result = unclaim(make_store, revision)
        assert result["reason"] == "unclaim_lease_refused" and result["exit_code"] == 1
        assert result["blockers"][0]["lease_oid"] and "aegis team release" in result["blockers"][0]["next_action"]
        assert path.read_bytes() == before and gitsafe.list_refs(make_store, team.LANES_REF) == refs


def test_unclaim_without_covering_lease_preserves_unrelated_lease(make_store):
    revision, oid = held(make_store)
    team.release(make_store, "alpha", oid, caller="owner")
    unrelated = team.claim(make_store, "alpha", ["docs/**"], owner="owner", now=100)
    result = unclaim(make_store, revision)
    assert not result["refused"] and result["released_lease_ids"] == []
    assert team.read_leases(make_store).get("alpha").oid == unrelated.oid


def test_unclaim_moved_oid_is_refused_before_any_change(make_store, monkeypatch):
    revision, oid = held(make_store)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before, original = path.read_bytes(), team_claims._release_lease

    def move_then_release(root, lane, expected, **kwargs):
        team.renew(root, lane, expected, now=102)
        return original(root, lane, expected, **kwargs)

    monkeypatch.setattr(team_claims, "_release_lease", move_then_release)
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_lease_refused" and result["exit_code"] == 1
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid != oid
    assert receipts(make_store) == []


@pytest.mark.parametrize("phase", ["before-release", "after-release", "after-event"])
def test_crash_recovery_blocks_other_transitions_and_records_once(make_store, monkeypatch, phase):
    revision, _ = held(make_store)
    original_release, original_publish = team_claims._release_lease, queue._publish

    def crash_release(*args, **kwargs):
        if phase == "after-release":
            original_release(*args, **kwargs)
        raise OSError("private-value")

    def crash_publish(root, state, **kwargs):
        if "unclaim" not in state:
            raise OSError("private-value")
        return original_publish(root, state, **kwargs)

    if phase == "after-event":
        monkeypatch.setattr(queue, "_publish", crash_publish)
    else:
        monkeypatch.setattr(team_claims, "_release_lease", crash_release)
    result = unclaim(make_store, revision)
    monkeypatch.setattr(queue, "_publish", original_publish)
    monkeypatch.setattr(team_claims, "_release_lease", original_release)
    assert result["reason"] == "unclaim_recovery_required" and result["exit_code"] == 1
    assert "private-value" not in json.dumps(result) and "unclaim" in result["next_action"]
    for verb in ("claim", "release", "done"):
        result = getattr(queue, verb)(make_store, "ONE", expect=revision, lane="alpha", now=10000)
        assert result["reason"] == "unclaim_recovery_required"
    recovered = unclaim(make_store, revision)
    assert not recovered["refused"] and recovered["item"]["state"] == "queued"
    assert team.read_leases(make_store).get("alpha") is None and len(receipts(make_store)) == 1


def race_unclaim(arguments):
    return unclaim(*arguments)


def test_concurrent_unclaims_have_one_recorded_winner(make_store):
    revision, _ = held(make_store)
    with ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(race_unclaim, [(make_store, revision)] * 2, timeout=30))
    assert sorted(row["refused"] for row in results) == [False, True]
    assert next(row for row in results if row["refused"])["reason"] == "stale_revision"
    assert len(receipts(make_store)) == 1


def test_unclaim_unsupported_platform_is_fixed(tmp_path, monkeypatch):
    monkeypatch.setattr(queue, "descriptor_supported", lambda: False)
    result = unclaim(tmp_path, "0" * 64)
    assert result["reason"] == "unsupported_platform" and result["exit_code"] == 1


def test_oversized_receipt_log_refuses_before_releasing(make_store, monkeypatch):
    revision, oid = held(make_store)
    monkeypatch.setattr(team_claims, "MAX_EVENT_BYTES", 32)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_event_unavailable" and result["exit_code"] == 1
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid


def test_event_failure_after_release_can_be_retried(make_store, monkeypatch):
    revision, _ = held(make_store)
    monkeypatch.setattr(team_claims, "events", SimpleNamespace(**{**vars(events), "try_append": lambda *a, **kw: OSError("private-value")}))
    result = unclaim(make_store, revision)
    monkeypatch.setattr(team_claims, "events", events)
    assert result["reason"] == "unclaim_recovery_required" and "private-value" not in json.dumps(result)
    assert not unclaim(make_store, revision)["refused"]
    assert len(receipts(make_store)) == 1


@pytest.mark.parametrize("phase", ["before-publication", "after-publication"])
def test_intent_publication_failure_returns_recovery_step(make_store, monkeypatch, phase):
    revision, oid = held(make_store)
    original = queue._publish

    def failed(root, state, **kwargs):
        if phase == "after-publication":
            original(root, state, **kwargs)
        raise OSError("private-value")

    monkeypatch.setattr(queue, "_publish", failed)
    result = unclaim(make_store, revision)
    monkeypatch.setattr(queue, "_publish", original)
    assert result["reason"] == "unclaim_recovery_required" and result["exit_code"] == 1
    assert "private-value" not in json.dumps(result)
    assert team.read_leases(make_store).get("alpha").oid == oid
    assert not unclaim(make_store, revision)["refused"]
    assert len(receipts(make_store)) == 1


def test_symlink_receipt_log_refuses_without_echo_or_changes(make_store, tmp_path):
    revision, oid = held(make_store)
    outside = tmp_path / "private-value"
    outside.write_text("token=private-value", encoding="utf-8")
    log = events.events_path(make_store)
    log.rename(log.with_name("retained-events"))
    symlink_or_skip(outside, log)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_event_unavailable" and result["exit_code"] == 1
    assert "private-value" not in json.dumps(result)
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid


def test_fingerprint_changes_when_a_lease_expires(make_store):
    held(make_store)
    before = queue.list(make_store, now=102)["claimable_fingerprint"]
    after = queue.list(make_store, now=86500)["claimable_fingerprint"]
    assert before != after
    assert queue.list(make_store, now=86501)["claimable_fingerprint"] == after


def test_fingerprint_tracks_holds_leases_and_completion_without_clock_noise(make_store):
    revision, oid = held(make_store)
    fingerprint = lambda now=102: queue.list(make_store, now=now)["claimable_fingerprint"]
    initial = fingerprint()
    assert fingerprint(103) == initial
    team.release(make_store, "alpha", oid, caller="owner")
    freed = fingerprint()
    assert freed != initial
    queue.done(make_store, "ONE", expect=revision, lane="alpha", now=104)
    assert fingerprint() != freed
    added = queue.add(make_store, {"id": "TWO", "title": "Held", "paths": ["docs/**"],
        "capabilities": [], "hold_until": [{"kind": "milestone", "name": "landed"}]}, now=105)
    assert not added["refused"]
    held_fingerprint = fingerprint()
    path = make_store / ".aegis" / "state" / "team-queue.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    state["milestones"] = ["landed"]
    path.write_text(json.dumps(state), encoding="utf-8")
    assert fingerprint() != held_fingerprint
    assert queue.list(make_store, capabilities=["other"], include_done=True, now=102)["claimable_fingerprint"] == fingerprint()


def test_operator_must_acknowledge_stopped_writer(make_store):
    revision, oid = held(make_store)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = queue.unclaim(make_store, "ONE", expect=revision, lane="alpha", now=102, caller="owner")
    assert result["refused"] and result["reason"] == "writer_not_stopped"
    assert result["exit_code"] == 1 and "--writer-stopped" in result["next_action"]
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid


def test_recovery_keeps_intent_when_a_new_lane_lease_appears(make_store, monkeypatch):
    revision, oid = held(make_store)
    original = team_claims._release_lease

    def released_then_crashed(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("lost acknowledgement")

    monkeypatch.setattr(team_claims, "_release_lease", released_then_crashed)
    assert unclaim(make_store, revision)["reason"] == "unclaim_recovery_required"
    monkeypatch.setattr(team_claims, "_release_lease", original)
    newer = team.claim(make_store, "alpha", ["docs/**"], owner="owner", now=103)
    assert newer.oid != oid
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_recovery_required"
    assert path.read_bytes() == before and "unclaim" in json.loads(before)


def test_event_capacity_is_checked_before_any_change(make_store, monkeypatch):
    revision, oid = held(make_store)
    monkeypatch.setattr(team_claims, "MAX_EVENT_BYTES", events.events_path(make_store).stat().st_size + 1)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_event_unavailable"
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid


def test_non_git_lease_free_hold_remains_unmet(make_store, tmp_path):
    result = queue.add(make_store, {"id": "ONE", "title": "Held", "paths": ["src/**"],
        "capabilities": [], "hold_until": [{"kind": "lease_free", "paths": ["src/**"]}]}, now=100)
    assert not result["refused"]
    (make_store / ".git").rename(tmp_path / "retained-git")
    os.environ["GIT_CEILING_DIRECTORIES"] = str(make_store.parent)
    assert gitsafe.run(["rev-parse", "--is-inside-work-tree"], make_store).returncode != 0
    listed = queue.list(make_store, now=102)
    assert not listed["refused"], listed
    assert listed["items"][0]["conditions_met"] is False
    assert listed["items"][0]["blockers"][0]["reason"] == "lease_free"


@pytest.mark.parametrize("case", ["capacity", "lane", "invalid-profile"])
def test_fingerprint_tracks_every_claim_policy_change(make_store, case):
    held(make_store)
    added = queue.add(make_store, {"id": "TWO", "title": "Work", "paths": ["docs/**"], "capabilities": []}, now=100)
    assert not added["refused"]
    profile = make_store / ".aegis" / "team" / "profile.json"
    profile.parent.mkdir(exist_ok=True)
    if case == "invalid-profile":
        profile.write_text("{}", encoding="utf-8")
    elif case == "lane":
        profile.write_text(json.dumps({"version": 1, "run_config": {"limits": {"writers_max": 2}}}), encoding="utf-8")
    lane = "gamma" if case == "lane" else "beta"
    result = queue.claim(make_store, "TWO", expect=added["item"]["revision"], lane=lane, now=102)
    assert result["reason"] == {"lane": "blocked", "capacity": "capacity_full", "invalid-profile": "profile_unavailable"}[case]
    before = queue.list(make_store, now=102)["claimable_fingerprint"]
    if case == "lane":
        config = make_store / ".aegis" / "team.json"
        value = json.loads(config.read_text())
        value["lanes"]["gamma"] = ["docs/**"]
        config.write_text(json.dumps(value), encoding="utf-8")
    else:
        profile.write_text(json.dumps({"version": 1, "run_config": {"limits": {"writers_max": 2}}}), encoding="utf-8")
    assert queue.list(make_store, now=102)["claimable_fingerprint"] != before
    assert not queue.claim(make_store, "TWO", expect=added["item"]["revision"], lane=lane, now=104)["refused"]


def mutate_lease(root, mutation):
    current = team.read_leases(root).get("alpha")
    if mutation in ("removed", "same-lane", "foreign") and current is not None:
        team.release(root, "alpha", current.oid, caller="external")
    if mutation == "same-lane":
        team.claim(root, "alpha", ["docs/**"], owner="owner", now=103)
    elif mutation == "foreign":
        team.claim(root, "beta", ["src/**"], owner="external", now=103)
    elif mutation == "unreadable":
        bad = gitsafe.write_blob(root, b"{}")
        gitsafe.update_ref(root, team.lane_ref("beta"), bad, None)


@pytest.mark.parametrize("phase", ["before-intent", "after-intent", "after-release", "after-receipt", "before-final"])
@pytest.mark.parametrize("mutation", ["unchanged", "removed", "same-lane", "foreign", "unreadable"])
def test_crash_and_lease_state_matrix(make_store, monkeypatch, record_property, phase, mutation):
    revision, _ = held(make_store)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    # A rollback must preserve formatting as well as decoded scheduling facts.
    path.write_text(json.dumps(json.loads(path.read_text()), indent=2) + "\n", encoding="utf-8")
    original_bytes = path.read_bytes()
    original_publish, original_release, original_append = queue._publish, team_claims._release_lease, events.try_append
    armed, removed_by_us = [True], []

    def publication(root, state, **kwargs):
        if armed[0] and phase == "before-intent":
            raise OSError("injected before intent")
        if armed[0] and phase == "before-final" and "unclaim" not in state:
            raise OSError("injected before final")
        result = original_publish(root, state, **kwargs)
        if armed[0] and phase == "after-intent":
            raise OSError("injected after intent")
        return result

    def releasing(root, lane, oid, **kwargs):
        result = original_release(root, lane, oid, **kwargs)
        if result:
            removed_by_us.append(oid)
        if armed[0] and phase == "after-release":
            raise OSError("injected after release")
        return result

    def appending(root, kind, result, detail, **kwargs):
        outcome = original_append(root, kind, result, detail, **kwargs)
        if armed[0] and phase == "after-receipt" and result == "queue_unclaim":
            raise OSError("injected after receipt")
        return outcome

    monkeypatch.setattr(queue, "_publish", publication)
    monkeypatch.setattr(team_claims, "_release_lease", releasing)
    monkeypatch.setattr(team_claims, "events", SimpleNamespace(**{**vars(events), "try_append": appending}))
    first = unclaim(make_store, revision)
    assert first["reason"] == "unclaim_recovery_required"
    # Every blocked recovery in this matrix is an injected I/O failure. The cause
    # entry is present on the first refusal, before the lease mutation on retry.
    assert [row["reason"] for row in first["blockers"]] == [
        "unclaim_recovery_required", "queue_io_unavailable"], first
    assert set(first["blockers"][1]) == {"refused", "reason", "next_action"}, first
    assert "injected" not in json.dumps(first["blockers"])
    fault_bytes = path.read_bytes()
    pending = "unclaim" in json.loads(fault_bytes)
    assert pending is (phase != "before-intent")
    if not pending:
        assert fault_bytes == original_bytes
    armed[0] = False
    mutate_lease(make_store, mutation)
    before_retry = path.read_bytes()
    result = unclaim(make_store, revision)
    after_retry = path.read_bytes()
    rows = receipts(make_store)
    evidence = {"phase": phase, "mutation": mutation, "original_bytes": original_bytes.decode(),
        "fault_bytes": fault_bytes.decode(), "intent": json.loads(fault_bytes).get("unclaim"),
        "before_retry_bytes": before_retry.decode(), "after_retry_bytes": after_retry.decode(),
        "receipt": rows, "refusal": result.get("reason"), "our_releases": removed_by_us}
    record_property("transition_matrix", json.dumps(evidence, sort_keys=True))
    if pending and mutation in ("same-lane", "foreign", "unreadable"):
        assert result["reason"] == "unclaim_recovery_required", evidence
        assert result["exit_code"] == 1, evidence
        assert after_retry == before_retry and "unclaim" in json.loads(after_retry), evidence
        # The recovery command stays first. The second entry is only the sanitized cause.
        assert [row["reason"] for row in result["blockers"]] == [
            "unclaim_recovery_required", "unclaim_lease_refused"], evidence
        cause = result["blockers"][1]
        assert set(cause) == {"refused", "reason", "lane", "lease_oid", "next_action"}, evidence
        assert cause["lane"] == ("alpha" if mutation == "same-lane" else "beta"), evidence
        assert cause["lease_oid"] and len(cause["lease_oid"]) in (40, 64), evidence
        assert all(character in "0123456789abcdef" for character in cause["lease_oid"]), evidence
        assert "aegis team release " + cause["lane"] in cause["next_action"], evidence
        assert cause["lease_oid"] in cause["next_action"], evidence
    elif not pending and mutation in ("foreign", "unreadable"):
        assert result["reason"] == "unclaim_lease_refused" and result["exit_code"] == 1, evidence
        assert after_retry == original_bytes, evidence
        assert [row["reason"] for row in result["blockers"]] == ["unclaim_lease_refused"], evidence
    else:
        assert not result["refused"] and result["item"]["state"] == "queued", evidence
        assert "unclaim" not in json.loads(after_retry), evidence
        assert set(result["released_lease_ids"]) <= set(removed_by_us), evidence
    assert len(rows) <= 1, evidence
    for row in rows:
        assert row["detail"]["writer_stopped"] is True, evidence
        assert set(row["detail"]["released_lease_ids"]) <= set(removed_by_us), evidence


@pytest.mark.parametrize("mutation", ["same-lane", "foreign", "unreadable"])
def test_initial_lease_less_race_restores_exact_bytes(make_store, monkeypatch, mutation):
    revision, oid = held(make_store)
    team.release(make_store, "alpha", oid, caller="external")
    path = make_store / ".aegis" / "state" / "team-queue.json"
    path.write_text(json.dumps(json.loads(path.read_text()), indent=2) + "\n", encoding="utf-8")
    before, original, changed = path.read_bytes(), queue._publish, []

    def publication(root, state, **kwargs):
        original(root, state, **kwargs)
        if not changed:
            changed.append(True)
            if mutation == "same-lane":
                team.claim(root, "alpha", ["src/**"], owner="owner", now=103)
            else:
                mutate_lease(root, mutation)

    monkeypatch.setattr(queue, "_publish", publication)
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_lease_refused"
    assert path.read_bytes() == before and receipts(make_store) == []


def test_externally_removed_lease_is_not_attested(make_store, monkeypatch):
    revision, oid = held(make_store)
    original, changed = queue._publish, []
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()

    def publication(root, state, **kwargs):
        original(root, state, **kwargs)
        if not changed:
            changed.append(True)
            team.release(root, "alpha", oid, caller="external")

    monkeypatch.setattr(queue, "_publish", publication)
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_lease_refused"
    assert path.read_bytes() == before and receipts(make_store) == []


@pytest.mark.parametrize("mutation", ["same-lane", "foreign", "unreadable"])
def test_last_publication_guard_refuses_a_new_lease(make_store, monkeypatch, mutation):
    revision, _ = held(make_store)
    original = queue._publish

    def publication(root, state, **kwargs):
        if "unclaim" not in state:
            mutate_lease(root, mutation)
        return original(root, state, **kwargs)

    monkeypatch.setattr(queue, "_publish", publication)
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_recovery_required"
    state = json.loads((make_store / ".aegis" / "state" / "team-queue.json").read_text())
    assert "unclaim" in state and state["items"]["ONE"]["state"] == "claimed"


@pytest.mark.parametrize("offset,admitted", [(0, True), (-1, True), (1, False), (16383, False), (16384, False)])
def test_event_reservation_boundaries(make_store, monkeypatch, offset, admitted):
    revision, oid = held(make_store)
    log = events.events_path(make_store)
    # The reserved region includes both bounded events; padding is valid JSONL whitespace.
    monkeypatch.setattr(team_claims, "MAX_EVENT_BYTES", 32768)
    monkeypatch.setattr(team_claims, "EVENT_MARGIN", 16384)
    target = team_claims.MAX_EVENT_BYTES - team_claims.EVENT_MARGIN + offset
    log.write_bytes(log.read_bytes() + b" " * (target - log.stat().st_size - 1) + b"\n")
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = unclaim(make_store, revision)
    assert result["refused"] is not admitted
    if admitted:
        assert result["released_lease_ids"] == [oid]
    else:
        assert result["reason"] == "unclaim_event_unavailable"
        assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid


@pytest.mark.parametrize("failure", ["start", "timeout", "nonzero"])
def test_git_observation_failure_never_clears_holds(make_store, monkeypatch, failure):
    held(make_store)

    def failed(*args, **kwargs):
        if failure == "nonzero":
            return SimpleNamespace(returncode=128, stdout=b"", stderr=b"private-value")
        raise gitsafe.GitError("private-value " + failure)

    monkeypatch.setattr(team_claims, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "run": failed}))
    result = queue.list(make_store, now=102)
    assert result["reason"] == "queue_io_unavailable" and result["exit_code"] == 1
    assert "private-value" not in json.dumps(result) and "claimable_fingerprint" not in result


def test_recovery_blockers_and_returned_hold_view(make_store, monkeypatch):
    revision, _ = held(make_store)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    state = json.loads(path.read_text())
    state["items"]["ONE"]["item"]["hold_until"] = [{"kind": "lease_free", "paths": ["docs/**"]}]
    path.write_text(json.dumps(state), encoding="utf-8")
    original = team_claims._release_lease

    def failed(*args, **kwargs):
        raise OSError("private-value")

    monkeypatch.setattr(team_claims, "_release_lease", failed)
    first = unclaim(make_store, revision, reason="Waiting for review")
    monkeypatch.setattr(team_claims, "_release_lease", original)
    assert [row["reason"] for row in first["blockers"]] == [
        "unclaim_recovery_required", "queue_io_unavailable"]
    assert set(first["blockers"][1]) == {"refused", "reason", "next_action"}
    assert "private-value" not in json.dumps(first)
    for result in (first, queue.list(make_store, now=102), queue.audit(make_store, now=102)):
        blocker = result["blockers"][0]
        assert (blocker["item_id"], blocker["lane"], blocker["revision"], blocker["caller"]) == (
            "ONE", "alpha", revision, "owner")
        assert revision in blocker["next_action"] and "--writer-stopped" in blocker["next_action"]
        assert blocker["reason_text"] == "Waiting for review"
    for result in (queue.list(make_store, now=102), queue.audit(make_store, now=102)):
        assert [row["reason"] for row in result["blockers"]] == ["unclaim_recovery_required"]
    result = unclaim(make_store, revision)
    assert not result["refused"] and result["item"]["conditions_met"] is False
    assert result["item"]["blockers"][0]["reason"] == "lease_free"


def test_initial_receipt_log_is_read_once(make_store, monkeypatch):
    revision, _ = held(make_store)
    opened = []
    original = storage.confined_file

    def counted(*args, **kwargs):
        opened.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(team_claims, "storage", SimpleNamespace(**{**vars(storage), "confined_file": counted}))
    assert not unclaim(make_store, revision)["refused"]
    assert len(opened) == 1


def test_recovery_reads_bounded_event_slack(make_store, monkeypatch):
    revision, _ = held(make_store)
    monkeypatch.setattr(team_claims, "MAX_EVENT_BYTES", 32768)
    monkeypatch.setattr(team_claims, "EVENT_MARGIN", 16384)
    original_append, original_publish = events.try_append, queue._publish

    def appended_after_other_events(root, kind, result, detail, **kwargs):
        if result == "queue_unclaim":
            log = events.events_path(root)
            padding = team_claims.MAX_EVENT_BYTES + 100 - log.stat().st_size
            log.write_bytes(log.read_bytes() + b" " * (padding - 1) + b"\n")
        return original_append(root, kind, result, detail, **kwargs)

    def publication(root, state, **kwargs):
        if "unclaim" not in state:
            raise OSError("injected before final")
        return original_publish(root, state, **kwargs)

    monkeypatch.setattr(team_claims, "events", SimpleNamespace(**{**vars(events), "try_append": appended_after_other_events}))
    monkeypatch.setattr(queue, "_publish", publication)
    assert unclaim(make_store, revision)["reason"] == "unclaim_recovery_required"
    monkeypatch.setattr(team_claims, "events", events)
    monkeypatch.setattr(queue, "_publish", original_publish)
    assert events.events_path(make_store).stat().st_size > team_claims.MAX_EVENT_BYTES
    assert not unclaim(make_store, revision)["refused"] and len(receipts(make_store)) == 1


def test_retry_release_cas_refusal_retains_intent(make_store, monkeypatch):
    revision, _ = held(make_store)
    original = team_claims._release_lease

    def unavailable(*args, **kwargs):
        raise OSError("injected before release")

    monkeypatch.setattr(team_claims, "_release_lease", unavailable)
    assert unclaim(make_store, revision)["reason"] == "unclaim_recovery_required"
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()

    def moved(root, lane, oid, **kwargs):
        team.renew(root, lane, oid, now=103)
        return original(root, lane, oid, **kwargs)

    monkeypatch.setattr(team_claims, "_release_lease", moved)
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_recovery_required"
    assert path.read_bytes() == before and "unclaim" in json.loads(before)


def test_maximum_reason_keeps_a_complete_retry_command(make_store, monkeypatch):
    revision, _ = held(make_store)
    reason = "A" * queue.MAX_TEXT
    original = team_claims._release_lease

    def failed(*args, **kwargs):
        raise OSError("injected before release")

    monkeypatch.setattr(team_claims, "_release_lease", failed)
    result = unclaim(make_store, revision, reason=reason)
    blocker = result["blockers"][0]
    assert blocker["next_action"].endswith("--writer-stopped")
    assert blocker["reason_text"] == reason
    monkeypatch.setattr(team_claims, "_release_lease", original)
    assert not unclaim(make_store, revision)["refused"]


def test_initial_io_refusal_before_release_restores_exact_bytes(make_store, monkeypatch):
    revision, oid = held(make_store)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    path.write_text(json.dumps(json.loads(path.read_text()), indent=2) + "\n", encoding="utf-8")
    before, original, reads = path.read_bytes(), team.read_leases, []

    def failed(root):
        reads.append(True)
        if len(reads) > 1:
            raise gitsafe.GitError("private-value")
        return original(root)

    monkeypatch.setattr(team_claims, "team", SimpleNamespace(**{**vars(team), "read_leases": failed}))
    result = unclaim(make_store, revision)
    assert result["reason"] == "queue_io_unavailable" and "private-value" not in json.dumps(result)
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid


def test_external_delete_inside_cas_is_never_attested(make_store, monkeypatch):
    revision, oid = held(make_store)
    original, removed = gitsafe.update_ref, []

    def external_delete(root, ref, new, old, **kwargs):
        if new is None and ref == team.lane_ref("alpha") and not removed:
            original(root, ref, None, old, single_attempt=True)
            removed.append(old)
        return original(root, ref, new, old, **kwargs)

    proxy = SimpleNamespace(**{**vars(gitsafe), "update_ref": external_delete})
    monkeypatch.setattr(team, "gitsafe", proxy)
    monkeypatch.setattr(team_claims, "gitsafe", proxy)
    result = unclaim(make_store, revision)
    assert oid not in result.get("released_lease_ids", [])
    assert all(oid not in row["detail"]["released_lease_ids"] for row in receipts(make_store))
    monkeypatch.setattr(team, "gitsafe", gitsafe)
    monkeypatch.setattr(team_claims, "gitsafe", gitsafe)
    if result["refused"]:
        assert result["reason"] == "unclaim_recovery_required"
        result = unclaim(make_store, revision)
    assert not result["refused"] and result["released_lease_ids"] == []


def pad_queue(root, target):
    path = root / ".aegis" / "state" / "team-queue.json"
    state = json.loads(path.read_bytes())
    state["items"]["PAD"] = {"item": {"id": "PAD", "title": "Retained work", "paths": ["pad/**"],
        "capabilities": [], "invariants": []}, "state": "done", "revision": "1" * 64,
        "lane": None, "expires_at": None}
    state["items"]["ONE"]["item"]["invariants"] = []
    remaining = target - len(json.dumps(state, separators=(",", ":")).encode("ascii"))
    for identifier in ("ONE", "PAD"):
        values = state["items"][identifier]["item"]["invariants"]
        while remaining and len(values) < queue.MAX_FIELDS:
            length = min(queue.MAX_TEXT, remaining - 2 - bool(values))
            assert length >= 0
            values.append("x" * length)
            remaining -= length + 2 + (len(values) > 1)
    assert remaining == 0
    raw = json.dumps(state, separators=(",", ":")).encode("ascii")
    assert len(raw) == target <= queue.MAX_BYTES
    path.write_bytes(raw)
    assert not queue.list(root, now=102)["refused"]
    return path, raw


@pytest.mark.parametrize("phase", ["intent", "released-ids"])
def test_unclaim_queue_size_failure_preserves_phase_and_compact_guidance(make_store, phase):
    revision, oid = held(make_store)
    intent = {"id": "ONE", "revision": revision, "lane": "alpha", "caller": "owner", "reason": "",
        "lease_oid": oid, "to_revision": "0" * 64, "writer_stopped": True, "released_lease_ids": []}
    overhead = len(',"unclaim":' + json.dumps(intent, separators=(",", ":")))
    target = queue.MAX_BYTES - 1 - (overhead if phase == "released-ids" else 0)
    path, before = pad_queue(make_store, target)
    result = unclaim(make_store, revision)
    assert result["refused"] and result["exit_code"] == 1
    assert result["reason"] == ("queue_size_limit" if phase == "intent" else "unclaim_recovery_required")
    assert "aegis team queue compact" in json.dumps(result)
    if phase == "released-ids":
        assert [row["reason"] for row in result["blockers"]] == [
            "unclaim_recovery_required", "queue_size_limit"]
        assert set(result["blockers"][1]) == {"refused", "reason", "next_action"}
    assert receipts(make_store) == []
    if phase == "intent":
        assert path.read_bytes() == before
        assert team.read_leases(make_store).get("alpha").oid == oid
    else:
        pending = json.loads(path.read_bytes())["unclaim"]
        assert pending["released_lease_ids"] == [] and pending["lease_oid"] == oid
        assert team.read_leases(make_store).get("alpha") is None
        recovered = unclaim(make_store, revision)
        assert not recovered["refused"] and recovered["item"]["state"] == "queued"
        assert recovered["released_lease_ids"] == []
        assert len(receipts(make_store)) == 1 and "unclaim" not in json.loads(path.read_bytes())


@pytest.mark.timing
@pytest.mark.parametrize("case", ["holds", "foreign-lease"])
def test_large_fingerprint_observation_has_linear_evaluation_budget(make_store, monkeypatch, record_property, case):
    count, lane_count, holds = 128, 4000, 64 if case == "holds" else 0
    config = {"v": 1, "lanes": {"l%04d" % index: [] for index in range(lane_count)}}
    config_raw = json.dumps(config, separators=(",", ":")).encode("ascii")
    assert len(config_raw) < 65536
    (make_store / ".aegis" / "team.json").write_bytes(config_raw)
    state = {"version": 1, "items": {}, "milestones": [], "completed": {}}
    for index in range(count):
        identifier = "I%03d" % index
        state["items"][identifier] = {"item": {"id": identifier, "title": "Work", "paths": ["src/**"],
            "capabilities": [], "hold_until": [{"kind": "lease_free", "paths": ["src/**"]}] * holds},
            "state": "queued", "revision": "%064x" % index, "lane": None, "expires_at": None}
    path = make_store / ".aegis" / "state" / "team-queue.json"
    path.parent.mkdir()
    raw = json.dumps(state, separators=(",", ":")).encode("ascii")
    assert len(raw) <= queue.MAX_BYTES
    path.write_bytes(raw)
    lease = team.claim(make_store, "l3999", ["src/**"], owner="owner", now=100)
    counts = {"items": 0, "holds": 0, "overlaps": 0, "live_checks": 0}
    original_blockers, original_live, paths = queue._blockers, queue._live, queue.team_paths

    def blockers(item, *args, **kwargs):
        counts["items"] += 1
        counts["holds"] += len(item.get("hold_until", []))
        assert counts["items"] <= count, counts
        return original_blockers(item, *args, **kwargs)

    def overlap(*args):
        counts["overlaps"] += 1
        assert counts["overlaps"] <= count * (holds + 2), counts
        return paths.overlap(*args)

    def live(*args):
        counts["live_checks"] += 1
        assert counts["live_checks"] <= 4 * (count * holds + count * lane_count), counts
        return original_live(*args)

    monkeypatch.setattr(queue, "_blockers", blockers)
    monkeypatch.setattr(queue, "_live", live)
    monkeypatch.setattr(queue, "team_paths", SimpleNamespace(**{**vars(paths), "overlap": overlap}))
    started = time.monotonic()
    result = queue.list(make_store, now=102)
    elapsed = time.monotonic() - started
    assert not result["refused"] and len(result["items"]) == count
    assert counts["holds"] == count * holds
    assert elapsed < 30, (elapsed, counts)
    record_property("observation_budget", json.dumps({**counts, "seconds": elapsed,
        "config_bytes": len(config_raw), "queue_bytes": len(raw), "lanes": lane_count, "items": count}))
    monkeypatch.setattr(queue, "_blockers", original_blockers)
    monkeypatch.setattr(queue, "_live", original_live)
    monkeypatch.setattr(queue, "team_paths", paths)
    revision = result["items"][0]["revision"]
    claimed = queue.claim(make_store, "I000", expect=revision, lane="l3999", now=102)
    assert claimed["refused"] is (case == "holds")
    assert team.read_leases(make_store).get("l3999").oid == lease.oid


# Captured through queue.list before the round-three eligibility refactor.
ROUND_TWO_FINGERPRINTS = {
    "capacity": "162258c7ce5dec555aadf8aaa186679e6cb9c5baac7373d50668d67d274c63c6",
    "completed": "8e7ebcd88a45c3c3ab060b099b5e9cf52f99b53bceddde0b5c1927f37b3592e3",
    "dependency": "909972b8569e17b9200e90358cec22f9daef4fc295b642380e5e22ae9d4561db",
    "expired": "79cf67effd83b5ae8597ebe36054f3c72d9bdee0b22ad2ef2d63e6d7fc27f09c",
    "foreign-lease": "162258c7ce5dec555aadf8aaa186679e6cb9c5baac7373d50668d67d274c63c6",
    "invalid-profile": "b6630774f47e0b674f8eb26fe4a5182bdad6adfbc63696c29a0a2b44c59a9d75",
    "judgment": "35d1c4885b682e0066582224aef744ed8584e34b4351f0261ab1166b10d37cb8",
    "live": "9b7b500941401d0b9fa63401d40e4b27fed98ca25c75ecc2c5e770ba7eb53487",
    "milestone": "abfe5e4310590811dece721310638e8fa43eff91ece1520165eeab16872f530c",
    "no-lanes": "598998c636df61cba70010c24d5c326496a8154f69d12203e53645cf2c91cf0d",
    "own-lease": "370934775538b01d7cfba28903c45685c0baf710e5af4997fd8c590151cbfb28",
    "queued": "512658d25aa593fd9f0dbcbdfb26a4d5e5ea9f3e7c44a6986ecc3a501bac5aa6",
    "unreadable": "1b4401d55ed4f8f8f109c3c8bfbc549765ac9d3a8f998b84cd7e2c17e43e24c4",
}


@pytest.mark.parametrize("case", ROUND_TWO_FINGERPRINTS)
def test_round_two_fingerprint_golden(make_store, monkeypatch, record_property, case):
    row = {"item": {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []},
        "state": "queued", "revision": "1" * 64, "lane": None, "expires_at": None}
    state = {"version": 1, "items": {"ONE": row}, "milestones": [], "completed": {}}
    found = team.LeaseSet()
    if case == "judgment":
        row["item"]["hold"] = "Review"
    elif case == "dependency":
        row["item"]["after"] = ["PRE"]
    elif case == "milestone":
        row["item"]["hold_until"] = [{"kind": "milestone", "name": "landed"}]
    elif case in ("live", "expired"):
        row.update(state="claimed", lane="alpha", expires_at=103 if case == "live" else 102)
    elif case in ("own-lease", "foreign-lease", "capacity"):
        lane = "alpha" if case == "own-lease" else "foreign"
        paths = ("docs/**",) if case == "capacity" else ("src/**",)
        found = team.LeaseSet((team.Lease(lane, "implementer", "owner", "0" * 16, 1,
                                        None, paths, 100, 3600, "a" * 40),), ())
    elif case == "unreadable":
        found = team.LeaseSet((), (team.Unreadable("foreign", team.lane_ref("foreign"), "b" * 40, "invalid"),))
    elif case == "invalid-profile":
        profile = make_store / ".aegis" / "team" / "profile.json"
        profile.parent.mkdir()
        profile.write_text("{}", encoding="utf-8")
    elif case == "no-lanes":
        (make_store / ".aegis" / "team.json").write_text('{"v":1,"lanes":{}}', encoding="utf-8")
    elif case == "completed":
        state["completed"]["PRE"] = True
        row["item"]["after"] = ["PRE"]
    path = make_store / ".aegis" / "state" / "team-queue.json"
    path.parent.mkdir()
    path.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
    monkeypatch.setattr(team_claims, "observe_leases", lambda root: (found, True))
    result = queue.list(make_store, now=102)
    assert not result["refused"], result
    record_property("round_two_golden", json.dumps({case: result["claimable_fingerprint"]}))
    assert result["claimable_fingerprint"] == ROUND_TWO_FINGERPRINTS[case]


def plant_pending(root, monkeypatch):
    """Publish one pending unclaim, then fail before the lease release."""
    revision, oid = held(root)
    original = queue._publish

    def fail_after(store, state, **kwargs):
        original(store, state, **kwargs)
        if "unclaim" in state:
            raise OSError("injected")

    monkeypatch.setattr(queue, "_publish", fail_after)
    failed = unclaim(root, revision)
    monkeypatch.setattr(queue, "_publish", original)
    assert failed["reason"] == "unclaim_recovery_required", failed
    path = root / ".aegis" / "state" / "team-queue.json"
    assert "unclaim" in json.loads(path.read_bytes())
    return revision, oid, path


def cause_of(result):
    assert result["reason"] == "unclaim_recovery_required" and result["exit_code"] == 1, result
    assert result["blockers"][0]["reason"] == "unclaim_recovery_required"
    return result["blockers"][1]


def test_initial_event_refusal_restores_queue_bytes(make_store):
    revision, oid = held(make_store)
    log = events.events_path(make_store)
    original_log = log.read_bytes()
    log.write_bytes(original_log + b'{"token":"private-value"\n')
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_event_unavailable" and result["exit_code"] == 1
    assert "private-value" not in json.dumps(result)
    assert path.read_bytes() == before and "unclaim" not in json.loads(before)
    assert team.read_leases(make_store).get("alpha").oid == oid
    log.write_bytes(original_log)
    assert not unclaim(make_store, revision)["refused"]


def test_initial_duplicate_rows_are_not_a_receipt_conflict(make_store):
    revision, _ = held(make_store)
    log = events.events_path(make_store)
    row = (b'{"event":"lease_claimed","result":"queue_unclaim","detail":{"unclaim_id":"'
           + b"ab" * 32 + b'"}}\n')
    log.write_bytes(log.read_bytes() + row + row)
    assert not unclaim(make_store, revision)["refused"]


@pytest.mark.parametrize("blocker", ["foreign", "unreadable", "missing-newline", "torn-row",
    "malformed", "duplicate"])
def test_recovery_cause_names_the_blocker_and_retries(make_store, monkeypatch, blocker):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()
    log = events.events_path(make_store)
    original_log = log.read_bytes()
    pending = json.loads(before)["unclaim"]
    if blocker == "foreign":
        # A second src/** lease cannot be claimed while alpha's live lease overlaps it.
        team.release(make_store, "alpha", oid, caller="external")
        team.claim(make_store, "beta", ["src/**"], owner="someone-else", now=100)
    elif blocker == "unreadable":
        bad = gitsafe.write_blob(make_store, b'{"token":"private-value"}')
        gitsafe.update_ref(make_store, team.lane_ref("beta"), bad, None)
    elif blocker == "missing-newline":
        log.write_bytes(original_log + b'{"token":"private-value"')
    elif blocker == "torn-row":
        log.write_bytes(original_log + b'{"token":"private-value"\n')
    elif blocker == "malformed":
        log.write_bytes(original_log + b'"private-value"\n')
    else:
        receipt = (json.dumps({"event": "lease_claimed", "result": "queue_unclaim", "detail": {
            "unclaim_id": pending["to_revision"], "note": "private-value"}},
            separators=(",", ":")).encode("ascii") + b"\n")
        log.write_bytes(original_log + receipt + receipt)
    for _ in range(2):
        result = unclaim(make_store, revision)
        cause = cause_of(result)
        assert path.read_bytes() == before
        assert "private-value" not in json.dumps(result)
        assert "\n" not in json.dumps(cause)
        if blocker in ("foreign", "unreadable"):
            assert cause["reason"] == "unclaim_lease_refused"
            assert cause["lane"] == "beta" and cause["lease_oid"]
            assert "aegis team release beta --expect " + cause["lease_oid"] == cause["next_action"].split(": ", 1)[1]
        else:
            assert cause["reason"] == "unclaim_event_unavailable"
            assert set(cause) == {"refused", "reason", "next_action"}
    if blocker == "foreign":
        foreign = team.read_leases(make_store).get("beta")
        team.release(make_store, "beta", foreign.oid, caller="someone-else")
    elif blocker == "unreadable":
        team.release(make_store, "beta", bad, caller="owner")
    else:
        log.write_bytes(original_log)
    recovered = unclaim(make_store, revision)
    assert not recovered["refused"], recovered
    assert recovered["item"]["state"] == "queued"
    assert team.read_leases(make_store).get("alpha") is None
    if blocker == "foreign":
        assert recovered["released_lease_ids"] == []
    else:
        assert oid in recovered["released_lease_ids"]


def test_recovery_cause_omits_unsanitized_lease_facts(make_store, monkeypatch):
    revision, _, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()

    def hostile(root):
        return SimpleNamespace(leases=(), unreadable=(SimpleNamespace(
            lane="beta\nprivate-value", oid="not-an-oid/private-value"),))

    monkeypatch.setattr(team_claims, "team", SimpleNamespace(**{**vars(team), "read_leases": hostile}))
    result = unclaim(make_store, revision)
    cause = cause_of(result)
    assert cause["reason"] == "unclaim_lease_refused"
    assert "lane" not in cause and "lease_oid" not in cause
    assert cause["next_action"] == "aegis team list --json; ask the coordinator to repair the unreadable ref"
    assert "private-value" not in json.dumps(result)
    assert "beta private-value" not in json.dumps(result)
    assert path.read_bytes() == before


def test_recovery_lease_refusal_omits_exception_text(make_store, monkeypatch):
    revision, _, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()
    current = "ab" * 20

    def leaked(*args, **kwargs):
        raise team.LeaseRefused("leak private-value /tmp/secret", "stale", "alpha", current=current)

    monkeypatch.setattr(team_claims, "_release_lease", leaked)
    result = unclaim(make_store, revision)
    cause = cause_of(result)
    assert cause["reason"] == "unclaim_lease_refused"
    assert cause["lane"] == "alpha" and cause["lease_oid"] == current
    assert "private-value" not in json.dumps(result) and "/tmp/secret" not in json.dumps(result)
    assert path.read_bytes() == before


def test_concurrent_recovery_retries_keep_one_lease_cause(make_store, monkeypatch):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()
    team.release(make_store, "alpha", oid, caller="external")
    team.claim(make_store, "beta", ["src/**"], owner="someone-else", now=100)
    with ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(race_unclaim, [(make_store, revision)] * 2, timeout=30))
    assert path.read_bytes() == before
    assert [result["reason"] for result in results] == ["unclaim_recovery_required"] * 2
    for result in results:
        cause = cause_of(result)
        assert cause["reason"] == "unclaim_lease_refused" and cause["lane"] == "beta"
        assert "private-value" not in json.dumps(result)
    foreign = team.read_leases(make_store).get("beta")
    team.release(make_store, "beta", foreign.oid, caller="someone-else")
    recovered = unclaim(make_store, revision)
    assert not recovered["refused"], recovered
    assert recovered["released_lease_ids"] == []


def _receipt_row(token, **detail):
    body = {"unclaim_id": token, "writer_stopped": True, "released_lease_ids": []}
    body.update(detail)
    return json.dumps({"event": "lease_claimed", "result": "queue_unclaim", "detail": body},
                      separators=(",", ":")).encode("ascii")


def _parity_log(case):
    token = "ab" * 32
    row = _receipt_row(token)
    other = b'{"event":"lease_claimed","result":"released","detail":{}}'
    if case == "lf":
        raw = other + b"\n" + row + b"\n"
    elif case == "crlf":
        raw = other + b"\r\n" + row + b"\r\n"
    elif case == "blank-rows":
        raw = b"\n \n\t\n\v\n\f\n\r\n" + row + b"\n\n"
    elif case == "missing-trailing-newline":
        raw = row
    elif case == "torn-last-row":
        raw = row + b"\n" + b'{"event":"private-value"\n'
    elif case == "duplicate-receipt":
        raw = (row + b"\n") * 2
    elif case == "cr-terminated":
        raw = other + b"\r" + row + b"\n"
    elif case in ("boundary-exact", "boundary-over"):
        boundary = team_claims.MAX_EVENT_BYTES - team_claims.EVENT_MARGIN
        line = row + b"\n"
        extra = 0 if case == "boundary-exact" else 1
        raw = line + (b" " * (boundary + extra - len(line) - 1)) + b"\n"
        assert len(raw) == boundary + extra and raw.endswith(b"\n")
    else:
        raise AssertionError(case)
    return token, raw


def _oracle_scan(raw, correlation, decode):
    if correlation is None and len(raw) > team_claims.MAX_EVENT_BYTES - team_claims.EVENT_MARGIN:
        raise team_claims.ClaimRefusal("unclaim_event_unavailable")
    if raw and not raw.endswith(b"\n"):
        raise team_claims.ClaimRefusal("unclaim_event_unavailable")
    receipt = None
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            row = decode(line, "invalid_queue_state")
        except ValueError:
            raise team_claims.ClaimRefusal("unclaim_event_unavailable") from None
        if type(row) is not dict:
            raise team_claims.ClaimRefusal("unclaim_event_unavailable")
        detail = row.get("detail")
        if (correlation is not None and row.get("event") == "lease_claimed" and
                row.get("result") == "queue_unclaim" and type(detail) is dict and
                detail.get("unclaim_id") == correlation):
            if receipt is not None:
                raise team_claims.ClaimRefusal("unclaim_event_unavailable")
            receipt = detail
    return receipt


def _scan_outcome(raw, correlation, decode):
    try:
        return ("ok", team_claims._scan_event_log(raw, correlation, decode))
    except team_claims.ClaimRefusal as error:
        return ("refuse", error.reason)


def _oracle_outcome(raw, correlation, decode):
    try:
        return ("ok", _oracle_scan(raw, correlation, decode))
    except team_claims.ClaimRefusal as error:
        return ("refuse", error.reason)


@pytest.mark.parametrize("case", ["lf", "crlf", "blank-rows", "missing-trailing-newline", "torn-last-row",
    "duplicate-receipt", "boundary-exact", "boundary-over", "cr-terminated"])
def test_event_log_decoder_matches_splitlines_parity(case):
    token, raw = _parity_log(case)
    expected_lines = [line for line in raw.splitlines() if line.strip()]
    assert list(team_claims._iter_event_rows(raw)) == expected_lines
    correlation = None if case == "boundary-over" else token
    assert _scan_outcome(raw, correlation, queue._json) == _oracle_outcome(raw, correlation, queue._json)
    if case == "boundary-exact":
        assert _scan_outcome(raw, None, queue._json) == ("ok", None)
        assert _oracle_outcome(raw, None, queue._json) == ("ok", None)
    if case == "boundary-over":
        seen = []

        def decode(line, reason):
            seen.append(line)
            return queue._json(line, reason)

        assert _scan_outcome(raw, None, decode) == ("refuse", "unclaim_event_unavailable")
        assert seen == []
    if case in ("missing-trailing-newline", "torn-last-row", "duplicate-receipt"):
        assert _scan_outcome(raw, token, queue._json)[0] == "refuse"
        rendered = json.dumps(_scan_outcome(raw, token, queue._json))
        assert "private-value" not in rendered


def test_overlong_event_row_is_refused_before_decode():
    raw = b"{" + (b"x" * team_claims._EVENT_ROW_BYTES) + b"}\n"
    assert team_claims._EVENT_ROW_BYTES == queue.MAX_BYTES
    seen = []

    def decode(line, reason):
        seen.append(len(line))
        raise AssertionError("decoded an overlong row")

    with pytest.raises(team_claims.ClaimRefusal) as caught:
        team_claims._scan_event_log(raw, "ab" * 32, decode)
    assert caught.value.reason == "unclaim_event_unavailable" and caught.value.blockers is None
    assert seen == []
    assert "x" * 32 not in str(caught.value)


def test_receipt_scan_memory_is_one_row():
    import tracemalloc
    token = "cd" * 32
    rows = [b'{"event":"lease_denied","result":"refused","detail":{"n":%d}}\n' % index
            for index in range(6000)]
    rows.append(_receipt_row(token) + b"\n")
    raw = b"".join(rows)
    assert len(raw) > 256 * 1024
    team_claims._scan_event_log(_receipt_row(token) + b"\n", token, queue._json)
    tracemalloc.start()
    found = team_claims._scan_event_log(raw, token, queue._json)
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert found["unclaim_id"] == token
    assert peak < 128 * 1024, peak


class CountingBuffer(bytes):
    """Bytes whose ``find`` reports how many bytes each delimiter search examines."""

    def __new__(cls, data, budget):
        obj = bytes.__new__(cls, data)
        obj.examined = 0
        obj.budget = budget
        return obj

    def find(self, sub, start=0, end=None):
        if end is None:
            end = len(self)
        if start < 0:
            start = max(0, len(self) + start)
        found = bytes.find(self, sub, start, end)
        span = (end - start) if found < 0 else (found - start + len(sub))
        self.examined += span
        if self.examined > self.budget:
            raise RuntimeError("delimiter search exceeded the linear budget: %s > %s" % (
                self.examined, self.budget))
        return found


def _budget_log(case):
    cap = team_claims.MAX_EVENT_BYTES - team_claims.EVENT_MARGIN
    if case == "lf-rows":
        row = b'{"event":"lease_denied","result":"refused","detail":{}}\n'
        raw = row * (cap // len(row))
    elif case == "blank-lf":
        raw = b"\n" * 15728640
    elif case == "cr-rows":
        unit = b"{}\r"
        raw = unit * ((cap - 1) // len(unit)) + b"\n"
    else:
        raise AssertionError(case)
    assert 0 < len(raw) <= cap or case == "blank-lf"
    if case == "blank-lf":
        assert len(raw) == 15728640
    else:
        assert len(raw) > cap - 80
    return raw


@pytest.mark.parametrize("case", ["lf-rows", "blank-lf", "cr-rows"])
def test_event_row_delimiter_search_is_linear(case):
    raw = _budget_log(case)
    rows = raw.count(b"\n") + raw.count(b"\r")
    # Two full scans plus a few bytes of bookkeeping per row. A suffix rescan
    # exceeds this on the third row and aborts, so the quadratic shape cannot
    # run to the end of a 15 MiB log.
    budget = 2 * len(raw) + 8 * rows
    buf = CountingBuffer(raw, budget)
    produced = 0
    for _line in team_claims._iter_event_rows(buf):
        produced += 1
    assert buf.examined <= budget
    assert buf.examined >= len(raw)
    if case == "blank-lf":
        assert produced == 0
    elif case == "lf-rows":
        assert produced == raw.count(b"\n")
    else:
        assert produced == raw.count(b"\r")


@pytest.mark.timing
def test_blank_lf_receipt_scan_finishes_within_the_lock_timeout():
    raw = b"\n" * 15728640
    started = time.monotonic()
    assert list(team_claims._iter_event_rows(raw)) == []
    assert time.monotonic() - started < 5.0


def _assert_recovery_cause(result, category, *, lane=None, lease_oid=None):
    assert result["reason"] == "unclaim_recovery_required" and result["exit_code"] == 1, result
    assert [row["reason"] for row in result["blockers"]] == [
        "unclaim_recovery_required", category], result
    cause = result["blockers"][1]
    rendered = json.dumps(result)
    assert "private-value" not in rendered and "/tmp/" not in rendered
    assert "\n" not in json.dumps(cause)
    if category == "unclaim_lease_refused":
        assert cause["lane"] == lane and cause["lease_oid"] == lease_oid
        assert set(cause) == {"refused", "reason", "lane", "lease_oid", "next_action"}
        command = "aegis team release " + lane + " --expect " + lease_oid
        assert cause["next_action"].split(": ", 1)[1] == command
        assert "unreadable" not in cause["next_action"]
    else:
        assert set(cause) == {"refused", "reason", "next_action"}
    return cause


def _append_correlated(root, pending, **overrides):
    body = {"unclaim_id": pending["to_revision"], "writer_stopped": True,
            "released_lease_ids": list(pending.get("released_lease_ids", []))}
    body.update(overrides)
    row = json.dumps({"event": "lease_claimed", "result": "queue_unclaim", "detail": body,
                      "note": "private-value"}, separators=(",", ":")).encode("ascii") + b"\n"
    log = events.events_path(root)
    original = log.read_bytes()
    log.write_bytes(original + row)
    return log, original


def _patch_gitsafe(monkeypatch, **methods):
    monkeypatch.setattr(team_claims, "gitsafe", SimpleNamespace(**{**vars(gitsafe), **methods}))


def _finish_without_attestation(root, path, revision, recovered):
    assert not recovered["refused"], recovered
    assert recovered["item"]["state"] == "queued"
    assert recovered["released_lease_ids"] == []
    assert "unclaim" not in json.loads(path.read_bytes())
    assert "private-value" not in json.dumps(recovered) and "/tmp/" not in json.dumps(recovered)
    rows = receipts(root)
    assert len(rows) == 1 and rows[0]["detail"]["released_lease_ids"] == []
    after = path.read_bytes()
    again = unclaim(root, recovered["item"]["revision"])
    assert again["reason"] == "not_claimed" and again["exit_code"] == 1
    assert path.read_bytes() == after
    assert team.read_leases(root).get("alpha") is None


@pytest.mark.parametrize("defect", ["writer-stopped", "released-ids"])
def test_inconsistent_receipt_names_event_cause(make_store, monkeypatch, defect):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()
    pending = json.loads(before)["unclaim"]
    if defect == "writer-stopped":
        log, original = _append_correlated(make_store, pending, writer_stopped=False)
    else:
        log, original = _append_correlated(make_store, pending, released_lease_ids=["ab" * 20])
    for _ in range(2):
        result = unclaim(make_store, revision)
        _assert_recovery_cause(result, "unclaim_event_unavailable")
        assert path.read_bytes() == before
        assert "ab" * 20 not in json.dumps(result["blockers"])
    log.write_bytes(original)
    recovered = unclaim(make_store, revision)
    assert not recovered["refused"], recovered
    assert oid in recovered["released_lease_ids"]
    assert team.read_leases(make_store).get("alpha") is None


def test_concurrent_inconsistent_receipts_keep_the_event_cause(make_store, monkeypatch):
    revision, _oid, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()
    pending = json.loads(before)["unclaim"]
    log, original = _append_correlated(make_store, pending, writer_stopped=False)
    with ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(race_unclaim, [(make_store, revision)] * 2, timeout=30))
    assert path.read_bytes() == before
    assert [result["reason"] for result in results] == ["unclaim_recovery_required"] * 2
    for result in results:
        _assert_recovery_cause(result, "unclaim_event_unavailable")
    log.write_bytes(original)
    recovered = unclaim(make_store, revision)
    assert not recovered["refused"], recovered


def test_receipt_while_lease_held_names_observed_oid(make_store, monkeypatch):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()
    pending = json.loads(before)["unclaim"]
    log, original = _append_correlated(make_store, pending)
    for _ in range(2):
        result = unclaim(make_store, revision)
        _assert_recovery_cause(result, "unclaim_lease_refused", lane="alpha", lease_oid=oid)
        assert path.read_bytes() == before
    log.write_bytes(original)
    recovered = unclaim(make_store, revision)
    assert not recovered["refused"], recovered
    assert recovered["released_lease_ids"] == [oid]


def test_unconfirmed_release_names_lease_cause(make_store, monkeypatch):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()

    def already(root, ref, new, old, single_attempt=False):
        return "already"

    _patch_gitsafe(monkeypatch, update_ref=already)
    for _ in range(2):
        result = unclaim(make_store, revision)
        _assert_recovery_cause(result, "unclaim_lease_refused", lane="alpha", lease_oid=oid)
        assert path.read_bytes() == before
        assert "already" not in json.dumps(result["blockers"])
    monkeypatch.setattr(team_claims, "gitsafe", gitsafe)
    recovered = unclaim(make_store, revision)
    assert not recovered["refused"], recovered
    assert recovered["released_lease_ids"] == [oid]


def test_absent_ref_between_release_reads_attests_nothing(make_store, monkeypatch):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    real_read, real_update = gitsafe.read_ref, gitsafe.update_ref
    calls = {"n": 0}

    def read_ref(root, ref):
        if ref != team.lane_ref("alpha"):
            return real_read(root, ref)
        calls["n"] += 1
        if calls["n"] < 3:
            return real_read(root, ref)
        if calls["n"] == 3:
            real_update(root, ref, None, oid, single_attempt=True)
        return None

    _patch_gitsafe(monkeypatch, read_ref=read_ref)
    recovered = unclaim(make_store, revision)
    assert calls["n"] >= 3
    _finish_without_attestation(make_store, path, revision, recovered)


def test_refconflict_absent_ref_attests_nothing(make_store, monkeypatch):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    real_update = gitsafe.update_ref

    def update_ref(root, ref, new, old, single_attempt=False):
        if ref == team.lane_ref("alpha") and new is None:
            real_update(root, ref, None, old, single_attempt=True)
            raise gitsafe.RefConflict("private-value /tmp/secret", ref=ref, expected=old, current=None)
        return real_update(root, ref, new, old, single_attempt=single_attempt)

    _patch_gitsafe(monkeypatch, update_ref=update_ref)
    recovered = unclaim(make_store, revision)
    _finish_without_attestation(make_store, path, revision, recovered)


def test_owner_release_between_reads_attests_nothing(make_store, monkeypatch):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    real_read = gitsafe.read_ref
    calls = {"n": 0, "released": 0}

    def read_ref(root, ref):
        if ref != team.lane_ref("alpha"):
            return real_read(root, ref)
        calls["n"] += 1
        if calls["n"] < 3:
            return real_read(root, ref)
        if calls["n"] == 3:
            team.release(root, "alpha", oid, caller="owner")
            calls["released"] += 1
        return None

    _patch_gitsafe(monkeypatch, read_ref=read_ref)
    recovered = unclaim(make_store, revision)
    assert calls["released"] == 1 and calls["n"] >= 3
    _finish_without_attestation(make_store, path, revision, recovered)


def test_absent_lease_refusal_keeps_intent_oid(make_store, monkeypatch):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()

    original = team_claims._release_lease

    def missing(*args, **kwargs):
        raise team.LeaseRefused("leak private-value /tmp/secret", "absent", "alpha", current=None)

    monkeypatch.setattr(team_claims, "_release_lease", missing)
    for _ in range(2):
        result = unclaim(make_store, revision)
        _assert_recovery_cause(result, "unclaim_lease_refused", lane="alpha", lease_oid=oid)
        assert path.read_bytes() == before
    monkeypatch.setattr(team_claims, "_release_lease", original)
    recovered = unclaim(make_store, revision)
    assert not recovered["refused"], recovered
    assert recovered["released_lease_ids"] == [oid]
