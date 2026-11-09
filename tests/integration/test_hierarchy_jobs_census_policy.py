"""Reviewed recipes control outside load; ledger reservations always retain their slots."""
import hashlib
import json
import os

import pytest

from tests.integration.test_hierarchy_jobs import load_jobs_module, shop  # noqa: F401
from tests.integration.test_hierarchy_jobs import pytestmark as pytestmark


KINDS = ("heavy", "heavy-tests")
PIDS = [103, 101, 102]
POLICY_ERROR = "invalid census_outside_policy: expected count, report or ignore"


def request_heavy_jobs(shop, kind, policy=None, count=1):
    if policy is not None:
        shop.recipes["census_outside_policy"] = policy
    shop.recipes["recipes"]["heavy"]["heavy_tests"] = kind == "heavy-tests"
    shop.save_recipes()
    for number in range(1, count + 1):
        shop.request_job("job-%d" % number, "heavy")


def outside_rows(pids, kind):
    return [{"pid": pid, "class": "pytest" if kind == "heavy" else "cargo"} for pid in sorted(pids)]


@pytest.mark.parametrize("kind", KINDS)
def test_absent_policy_preserves_recipe_bytes_hash_and_waiting_capacity(shop, kind):
    request_heavy_jobs(shop, kind)
    raw = shop.recipes_path.read_bytes() + b"\n\n"
    shop.recipes_path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    # No injected default, normalization or reserialization of the bytes being pinned.
    assert load_jobs_module().load_recipes(shop.recipes_path) == {**json.loads(raw), "recipes_sha256": digest}
    assert shop.jobs("check-recipes")["recipes_sha256"] == digest
    before = shop.workspace.run("status")["capacity"][kind]
    result = shop.run_open(census={"external_roots": {kind: PIDS}}, expect=3)
    assert result == {"rows": [{"job": "pilot/job-1", "state": "waiting", "kind": kind,
                                "reason": "capacity_full", "capacity": {
                                    "limit": before["limit"], "held": 0,
                                    "external_roots": sorted(PIDS), "census": "fixture"}}]}
    assert shop.recipes_path.read_bytes() == raw
    assert shop.receipts("job-1") == []


@pytest.mark.parametrize("kind", KINDS)
def test_explicit_count_preserves_counting_and_records_outside_rows(shop, kind):
    request_heavy_jobs(shop, kind, "count")
    limit = shop.workspace.run("status")["capacity"][kind]["limit"]
    row = shop.run_open(census={"external_roots": {kind: PIDS}}, expect=3)["rows"][0]
    assert (row["state"], row["reason"]) == ("waiting", "capacity_full")
    assert row["capacity"] == {"limit": limit, "held": 0, "external_roots": sorted(PIDS), "census": "fixture",
                               "outside_policy": "count", "outside": outside_rows(PIDS, kind)}
    assert shop.receipts("job-1") == []


@pytest.mark.parametrize("kind", KINDS)
def test_report_grants_despite_outside_load_and_records_it_on_the_waiting_row(shop, kind):
    request_heavy_jobs(shop, kind, "report", count=2)
    limit = shop.workspace.run("status")["capacity"][kind]["limit"]
    rows = shop.run_open("--max-jobs", "1", census={"external_roots": {kind: PIDS}}, expect=3)["rows"]
    assert [(row["job"], row["state"]) for row in rows] == [
        ("pilot/job-1", "completed"), ("pilot/job-2", "waiting")]
    assert rows[1]["reason"] == "job_limit"
    assert rows[1]["capacity"] == {"limit": limit, "held": 0, "external_roots": [], "census": "fixture",
                                   "outside_policy": "report", "outside": outside_rows(PIDS, kind)}
    assert shop.states("job-1") == ["started", "completed"]
    assert sum(event["kind"] == "grant" for event in shop.events()) == 1


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("fixture", [{"external_roots": {"heavy": PIDS, "heavy-tests": PIDS}},
                                    {"not_a_census": "must never be read"}])
def test_ignore_grants_without_reading_outside_census_or_recording_outside_rows(shop, kind, fixture):
    request_heavy_jobs(shop, kind, "ignore", count=2)
    limit = shop.workspace.run("status")["capacity"][kind]["limit"]
    rows = shop.run_open("--max-jobs", "1", census=fixture, expect=3)["rows"]
    assert [(row["job"], row["state"]) for row in rows] == [
        ("pilot/job-1", "completed"), ("pilot/job-2", "waiting")]
    # A malformed fixture would refuse if any outside census were attempted.
    assert rows[1]["capacity"] == {"limit": limit, "held": 0, "external_roots": [], "census": "fixture",
                                   "outside_policy": "ignore"}
    assert shop.states("job-1") == ["started", "completed"]


@pytest.mark.parametrize("policy", [None, "count", "report"])
def test_observing_policies_refuse_an_unreadable_outside_fixture(shop, policy):
    request_heavy_jobs(shop, "heavy", policy)
    assert shop.run_open(census={"not_a_census": "must be checked"}, expect=2) == {
        "error": "missing fields: external_roots"}
    assert shop.states("job-1") == []


@pytest.mark.parametrize("policy", ["count", "report"])
@pytest.mark.parametrize("pid", ["/private/not-a-pid", True, 1.5, 0, -1])
def test_outside_rows_refuse_non_positive_or_non_integer_fixture_pids(shop, policy, pid):
    request_heavy_jobs(shop, "heavy", policy)
    assert shop.run_open(census=[pid], expect=2) == {"error": "invalid census fixture pid"}
    assert shop.states("job-1") == []


@pytest.mark.parametrize("policy", [None, "count", "report", "ignore"])
@pytest.mark.parametrize("kind", KINDS)
def test_only_ignore_skips_proc_enumeration_and_recovery_still_observes_raw_census(
        shop, monkeypatch, capsys, policy, kind):
    limit = shop.workspace.run("status")["capacity"][kind]["limit"]
    for number in range(limit):
        shop.workspace.run("request", {"initiative": "pilot", "kind": kind, "holder": "held-%d" % number})
        shop.workspace.run("grant-next", kind=kind)
    request_heavy_jobs(shop, kind, policy)
    jobs = load_jobs_module()
    original = os.scandir

    def scan(path):
        if str(path) == "/proc":
            raise PermissionError("outside census denied by fixture")
        return original(path)

    # Mock only the OS enumeration boundary, never outside_roots or census.
    monkeypatch.setattr(os, "scandir", scan)
    code = jobs.main(shop.argv("run-open", census=None)[3:])
    answer = json.loads(capsys.readouterr().out)
    if policy == "ignore":
        assert code == 3
        assert answer == {"rows": [{"job": "pilot/job-1", "state": "waiting", "kind": kind,
                                    "reason": "capacity_full", "capacity": {
                                        "limit": limit, "held": limit, "external_roots": [],
                                        "census": "proc", "outside_policy": "ignore"}}]}
    else:
        assert code == 2
        assert answer == {"error": "cannot enumerate process table: outside census denied by fixture"}
    # recovery-status has no recipes policy, even when --recipes names an ignore file.
    assert jobs.main(shop.argv("recovery-status", census=None)[3:]) == 3
    recovered = json.loads(capsys.readouterr().out)
    for observed in recovered["process_census"].values():
        assert observed == {"state": "unavailable", "admission_free": None,
                            "error": "cannot enumerate process table: outside census denied by fixture"}
    assert shop.states("job-1") == []


@pytest.mark.parametrize("policy", ["COUNT", "off", "", None, False, 1, [], {}, ["ignore"]])
@pytest.mark.parametrize("command", ["check-recipes", "run-open"])
def test_unknown_or_non_string_policy_refuses_exactly_before_jobs_run(shop, policy, command):
    shop.recipes["census_outside_policy"] = policy
    shop.save_recipes()
    shop.request_job("job-1", "touch")
    assert shop.jobs(command, expect=2) == {"error": POLICY_ERROR}
    assert not shop.sentinel.exists()
    assert shop.states("job-1") == []


@pytest.mark.parametrize("command", ["check-recipes", "run-open"])
def test_misspelled_policy_key_refuses_exactly_before_jobs_run(shop, command):
    shop.recipes["census_outside_polciy"] = "ignore"
    shop.save_recipes()
    shop.request_job("job-1", "touch")
    assert shop.jobs(command, expect=2) == {"error": "unexpected fields: census_outside_polciy"}
    assert not shop.sentinel.exists()
    assert shop.states("job-1") == []


@pytest.mark.parametrize("policy", [None, "count", "report", "ignore"])
@pytest.mark.parametrize("kind", KINDS)
def test_policy_never_exceeds_the_limit_for_ledger_held_jobs(shop, policy, kind):
    before = shop.workspace.run("status")["capacity"][kind]
    for number in range(before["limit"]):
        shop.workspace.run("request", {"initiative": "pilot", "kind": kind,
                                        "holder": "job:pilot/held-%d" % number})
        shop.workspace.run("grant-next", kind=kind)
    held = shop.workspace.run("status")["capacity"][kind]
    request_heavy_jobs(shop, kind, policy)
    row = shop.run_open(census={"external_roots": {kind: PIDS}}, expect=3)["rows"][0]
    assert (row["state"], row["reason"]) == ("waiting", "capacity_full")
    assert row["capacity"]["held"] == row["capacity"]["limit"] == before["limit"]
    assert shop.workspace.run("status")["capacity"][kind] == held
    assert shop.states("job-1") == []


@pytest.mark.parametrize("policy", ["count", "report"])
@pytest.mark.parametrize("kind", KINDS)
def test_outside_rows_are_bounded_without_changing_the_count(shop, policy, kind):
    request_heavy_jobs(shop, kind, policy)
    # Hold the ledger full so report also leaves an observable waiting capacity.
    limit = shop.workspace.run("status")["capacity"][kind]["limit"]
    for number in range(limit):
        shop.workspace.run("request", {"initiative": "pilot", "kind": kind, "holder": "held-%d" % number})
        shop.workspace.run("grant-next", kind=kind)
    pids = list(range(170, 100, -1))
    capacity = shop.run_open(census={"external_roots": {kind: pids}}, expect=3)["rows"][0]["capacity"]
    assert capacity == {"limit": limit, "held": limit, "census": "fixture", "outside_policy": policy,
                        "external_roots": sorted(pids) if policy == "count" else [],
                        "outside": outside_rows(pids, kind)[:64], "outside_truncated": 6}


@pytest.mark.parametrize("policy", ["count", "report", "ignore"])
@pytest.mark.parametrize("reason", ["low_disk", "store_busy"])
def test_policy_preserves_low_disk_and_busy_store_holds(shop, policy, reason):
    request_heavy_jobs(shop, "heavy", policy)
    if reason == "low_disk":
        shop.recipes["min_free_gigabytes"] = 1000000
        shop.save_recipes()
    else:
        (shop.workspace.store / ".write.lock").write_text("fixture active writer")
    assert shop.run_open(lock_wait=0.1, expect=3) == {"rows": [
        {"job": "pilot/job-1", "state": "waiting", "kind": "heavy", "reason": reason}]}
    assert shop.states("job-1") == []


@pytest.mark.parametrize("unreviewed", ["report", "ignore"])
def test_environment_cannot_disable_default_counting(shop, unreviewed):
    request_heavy_jobs(shop, "heavy")
    env = {**shop.env(), "CENSUS_OUTSIDE_POLICY": unreviewed, "AEGIS_CENSUS_OUTSIDE_POLICY": unreviewed}
    row = shop.run_open(census=PIDS, env=env, expect=3)["rows"][0]
    assert row["reason"] == "capacity_full"
    assert row["capacity"] == {"limit": 3, "held": 0, "external_roots": sorted(PIDS), "census": "fixture"}


@pytest.mark.parametrize("policy", ["count", "report", "ignore"])
def test_policy_is_covered_by_the_exact_recipe_bytes_hash(shop, policy):
    before = shop.jobs("check-recipes")["recipes_sha256"]
    request_heavy_jobs(shop, "heavy", policy)
    raw = shop.recipes_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest != before
    assert shop.jobs("check-recipes")["recipes_sha256"] == digest
    shop.run_open()
    result = json.loads((shop.workspace.store / "jobs" / "pilot" / "job-1" / "result.json").read_text())
    assert result["recipes_sha256"] == digest
