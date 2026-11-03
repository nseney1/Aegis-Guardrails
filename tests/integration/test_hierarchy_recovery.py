"""Recovery through public job/workspace commands and real disposable stores.

The staged files represent interrupted OS writes, not native actor qualification.
Only process visibility is faked; receipts, ledgers, Git and mailboxes are real.
"""
import hashlib
import json
import os
from pathlib import Path

import pytest

from tests.integration.test_hierarchy_jobs import Shop, commit_request, verified_evidence
from tests.integration.test_hierarchy_jobs import pytestmark as pytestmark
from tests.integration.test_hierarchy_workspace import write_lease


@pytest.fixture
def shop(tmp_path):
    return Shop(tmp_path)


def visible_processes(shop, monkeypatch, *pids):
    table = shop.tmp / "process-table"
    for pid in (*pids, os.getpid()):
        (table / str(pid)).mkdir(parents=True)
    original = os.scandir

    def scan(path):
        return original(table if str(path) == "/proc" else path)

    monkeypatch.setattr(os, "scandir", scan)


def stage_interrupted_job(shop, *, result=None, claim=True):
    shop.request_job("engine-partial", "heavy")
    request_id = shop.workspace.ask("pilot", "heavy", "job:pilot/engine-partial")
    shop.workspace.grant("heavy")
    folder = shop.workspace.store / "jobs" / "pilot" / "engine-partial"
    folder.mkdir(parents=True)
    if claim:
        (folder / "claim.json").write_text(json.dumps({
            "pid": 81001, "start": "1", "job": "pilot/engine-partial", "at": "2000-01-01T00:00:00Z",
            "process_scope": {"boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                              "pid_namespace": os.readlink("/proc/self/ns/pid")}}))
    if result is not None:
        (folder / "result.json").write_text(json.dumps({
            "schema": "aegis.hierarchy-job-result/v1", "job": "pilot/engine-partial",
            "state": "completed", "exit_code": 0, "reason": None, "recipe": "heavy",
            "steps": [], "before": None, "after": None, "commit": None,
            "finished_at": "2000-01-01T00:00:00Z", **result}))
    return folder, request_id


def test_existing_receipt_id_must_correlate_to_the_exact_terminal_evidence(shop):
    identifier = "receipt-" + hashlib.sha256(b"engine-partial").hexdigest()[:24] + "-completed"
    shop.publish(identifier, "info", "Unrelated information with a colliding ID.")
    stage_interrupted_job(shop, result={})
    row = shop.run_open(expect=3)["rows"][0]
    assert row["state"] == "settle_pending"
    assert row["error"] == "receipt id already names different evidence: " + identifier
    assert shop.heavy()["used"] == 1
    assert not any(event["kind"] == "release" for event in shop.events())


def test_a_result_for_another_job_cannot_release_the_original_reservation(shop):
    stage_interrupted_job(shop, result={"job": "pilot/another-job"})
    row = shop.run_open(expect=3)["rows"][0]
    assert row["state"] == "settle_pending"
    assert row["error"] == "result does not belong to job: pilot/engine-partial"
    assert shop.heavy()["used"] == 1
    assert shop.receipts("engine-partial") == []


@pytest.mark.parametrize("record", [None, {"step": 1, "group": 81001}])
def test_missing_process_records_cannot_settle_executed_steps_without_stop_evidence(shop, record):
    folder, _ = stage_interrupted_job(shop, result={"steps": [{"argv": ["pytest"], "exit_code": 0}] * 2})
    if record is not None:
        (folder / "process.json").write_text(json.dumps(record))
    row = shop.run_open(expect=3)["rows"][0]
    assert row["state"] == "settle_pending"
    assert row["error"] == "executed steps lack process stop evidence: pilot/engine-partial"
    assert shop.heavy()["used"] == 1
    assert shop.receipts("engine-partial") == []


def test_missing_claim_never_becomes_stopped_just_because_its_ttl_elapsed(shop):
    folder, request_id = stage_interrupted_job(shop, claim=False)
    os.utime(folder, (1, 1))
    before = shop.events()
    refused = shop.jobs("resolve", "--job", "pilot/engine-partial", "--reason", "No visible runner", expect=2)
    assert refused["error"] == "runner visibility is unknown: pilot/engine-partial"
    assert shop.heavy()["holders"][0]["request_id"] == request_id
    assert shop.events() == before
    assert not (folder / "result.json").exists()


def test_process_read_denial_is_unknown_and_cannot_release_capacity(shop, monkeypatch, capsys):
    from tools import hierarchy_jobs

    stage_interrupted_job(shop)
    original = Path.read_text

    def read(path, *args, **kwargs):
        if str(path) == "/proc/81001/stat":
            raise PermissionError("visibility denied")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    code = hierarchy_jobs.main(["--store", str(shop.workspace.store), "resolve", "--job", "pilot/engine-partial",
                                "--reason", "A missing process listing is not a stopped process"])
    answer = json.loads(capsys.readouterr().out)
    assert code == 2, answer
    assert answer["error"] == "cannot observe process 81001: visibility denied"
    assert shop.heavy()["used"] == 1


def test_unreadable_group_member_cannot_be_treated_as_a_stopped_group(shop, monkeypatch, capsys):
    from tools import hierarchy_jobs

    folder, _ = stage_interrupted_job(shop)
    (folder / "process.json").write_text(json.dumps({"group": 82002, "step": 1}))
    (folder / "step-1.log").write_text("partial Engine output\n")
    visible_processes(shop, monkeypatch, 82003)
    original_glob, original_read = Path.glob, Path.read_text

    def glob(path, pattern):
        if str(path) == "/proc" and pattern == "[0-9]*/stat":
            return iter([Path("/proc/82003/stat")])
        return original_glob(path, pattern)

    def read(path, *args, **kwargs):
        if str(path) == "/proc/82003/stat":
            raise PermissionError("visibility denied")
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "glob", glob)
    monkeypatch.setattr(Path, "read_text", read)
    code = hierarchy_jobs.main(["--store", str(shop.workspace.store), "resolve", "--job", "pilot/engine-partial",
                                "--reason", "A hidden group member is not stopped"])
    answer = json.loads(capsys.readouterr().out)
    assert code == 2, answer
    assert answer["error"] == "cannot observe process group 82002: visibility denied"
    assert shop.heavy()["used"] == 1


def test_failed_process_census_cannot_admit_a_new_heavy_job(shop, monkeypatch, capsys):
    from tools import hierarchy_jobs

    shop.request_job("engine-partial", "heavy")
    visible_processes(shop, monkeypatch, 82003)
    original_glob, original_read = Path.glob, Path.read_bytes

    def glob(path, pattern):
        if str(path) == "/proc" and pattern == "[0-9]*/cmdline":
            return iter([Path("/proc/82003/cmdline")])
        return original_glob(path, pattern)

    def read(path, *args, **kwargs):
        if str(path) == "/proc/82003/cmdline":
            raise PermissionError("visibility denied")
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "glob", glob)
    monkeypatch.setattr(Path, "read_bytes", read)
    code = hierarchy_jobs.main(["--store", str(shop.workspace.store), "--recipes", str(shop.recipes_path), "run-open"])
    answer = json.loads(capsys.readouterr().out)
    assert code == 2, answer
    assert answer["error"] == "cannot census process 82003: visibility denied"
    assert shop.heavy()["used"] == 0
    assert shop.states("engine-partial") == []


def test_pid_reuse_does_not_hide_an_unowned_runner_from_capacity(shop, monkeypatch, capsys):
    from tools import hierarchy_jobs

    stage_interrupted_job(shop)
    shop.workspace.run("set-limits", {"heavy_limit": 2, "source": "disposable fixture"})
    shop.request_job("next-job", "heavy")
    visible_processes(shop, monkeypatch, 81001)
    original_glob, original_text, original_bytes = Path.glob, Path.read_text, Path.read_bytes
    # /proc stat fields after the command: state, ppid, pgrp, ... start ticks.
    fake_stat = "81001 (pytest) " + " ".join(["S", "0", "81001"] + ["0"] * 16 + ["2"])

    def glob(path, pattern):
        if str(path) == "/proc" and pattern == "[0-9]*/cmdline":
            return iter([Path("/proc/81001/cmdline")])
        return original_glob(path, pattern)

    def read_text(path, *args, **kwargs):
        return fake_stat if str(path) == "/proc/81001/stat" else original_text(path, *args, **kwargs)

    def read_bytes(path, *args, **kwargs):
        return b"pytest\0tests\0" if str(path) == "/proc/81001/cmdline" else original_bytes(path, *args, **kwargs)

    monkeypatch.setattr(Path, "glob", glob)
    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    code = hierarchy_jobs.main(["--store", str(shop.workspace.store), "--recipes", str(shop.recipes_path), "run-open"])
    answer = json.loads(capsys.readouterr().out)
    assert code == 3, answer
    rows = {row["job"]: row for row in answer["rows"]}
    assert rows["pilot/next-job"]["state"] == "waiting"
    assert rows["pilot/next-job"]["reason"] == "capacity_full"
    assert 81001 in rows["pilot/next-job"]["capacity"]["external_roots"]
    assert shop.heavy()["used"] == 1
    _, report = hierarchy_jobs.recovery_status(str(shop.workspace.store))
    assert 81001 in report["process_census"]["heavy"]["external_roots"]
    assert report["process_census"]["heavy"]["admission_free"] == 0


def snapshot(root):
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def test_unavailable_stop_observation_keeps_effect_unknown_without_terminal_result(shop, monkeypatch, capsys):
    from tools import hierarchy_jobs

    shop.request_job("engine-partial", "heavy")
    argv = shop.argv("run-open", census=[])[3:]
    original = os.scandir

    def scan(path):
        if str(path) == "/proc":
            raise PermissionError("stop observation denied")
        return original(path)

    monkeypatch.setattr(os, "scandir", scan)
    code = hierarchy_jobs.main(argv)
    answer = json.loads(capsys.readouterr().out)
    assert code == 3, answer
    assert answer["rows"][0]["state"] == "abandoned"
    assert "cannot enumerate process table: stop observation denied" in answer["rows"][0]["error"]
    assert shop.heavy()["used"] == 1
    assert not (shop.workspace.store / "jobs" / "pilot" / "engine-partial" / "result.json").exists()
    assert shop.states("engine-partial") == ["started"]


def test_recovery_inventory_is_read_only_and_carries_every_team_obligation(shop):
    folder, request_id = stage_interrupted_job(shop, claim=False)
    for team in ("content", "campaign", "b1"):
        shop.workspace.register(team, project="shared-project", blocked_by=["pilot"])
    before = snapshot(shop.workspace.store), snapshot(shop.root)
    report = shop.jobs("recovery-status", expect=3)
    assert report["schema"] == "aegis.hierarchy-recovery-status/v1"
    assert report["read_only"] is True
    assert {row["id"] for row in report["initiatives"]} == {"pilot", "content", "campaign", "b1"}
    row = next(row for row in report["jobs"] if row["job"] == "pilot/engine-partial")
    assert row["state"] == "unknown_effect"
    assert row["claim"] is None and row["runner_alive"] is None
    assert row["reservations"][0]["request_id"] == request_id
    assert report["capacity"]["heavy"]["used"] == 1
    assert all(blocker["owner"] and blocker["next_action"] for blocker in report["blockers"])
    assert (snapshot(shop.workspace.store), snapshot(shop.root)) == before
    assert not (folder / "result.json").exists()


def test_recovery_reports_changed_source_without_rewriting_the_original_claim(shop):
    folder, _ = stage_interrupted_job(shop)
    (folder / "packet.md").write_text(json.dumps({"schema": "aegis.hierarchy-job-packet/v1", "recipe": "heavy",
                                                **shop.head()}))
    original_claim = (folder / "claim.json").read_bytes()
    (shop.checkout / "src" / "app.py").write_text("value = 99\n")
    report = shop.jobs("recovery-status", "--initiative", "pilot", expect=3)
    row = report["jobs"][0]
    assert row["source"]["state"] == "changed"
    assert (folder / "claim.json").read_bytes() == original_claim
    assert report["capacity"]["heavy"]["used"] == 1


def test_crash_after_grant_before_claim_reuses_one_grant_and_one_execution(shop):
    shop.recipes["recipes"]["heavy-touch"] = shop.command(
        ["$python", "-c", "open(%r, 'a').write('ran\\n')" % str(shop.sentinel)], heavy=True)
    shop.save_recipes()
    shop.request_job("engine-partial", "heavy-touch")
    original = shop.workspace.ask("pilot", "heavy", "job:pilot/engine-partial")
    shop.workspace.grant("heavy")
    report = shop.jobs("recovery-status", expect=3)
    assert report["jobs"][0]["state"] == "reserved_not_started"
    assert report["jobs"][0]["reservations"][0]["request_id"] == original
    shop.run_open()
    shop.run_open()
    assert shop.sentinel.read_text() == "ran\n"
    assert [event["kind"] for event in shop.events() if event["kind"] in ("request", "grant", "release")] == [
        "request", "grant", "release"]


def test_writer_reservation_keeps_paths_owned_after_lease_expiry(shop):
    peer = shop.make_checkout("content-checkout")
    shop.workspace.register("content", project="aegis", touched_paths=["src/**"], checkouts=[str(peer)], lanes=["content-writer"])
    held = shop.workspace.ask("content", "writer", "content/original-generation")
    shop.workspace.grant("writer")
    write_lease(peer, "content-writer", ["src/**"], ts=1, ttl=1)
    answer = shop.workspace.run("check-paths", {"initiative": "pilot", "paths": ["src/app.py"]}, expect=3)
    assert answer["conflict"] is True
    assert answer["reserved_conflicts"][0]["request_id"] == held
    assert answer["reserved_conflicts"][0]["holder"] == "content/original-generation"
    shop.workspace.release(held)
    assert shop.workspace.run("check-paths", {"initiative": "pilot", "paths": ["src/app.py"]})["conflict"] is False


def test_successor_declaration_does_not_erase_original_reserved_paths(shop):
    shop.workspace.register("content", project="aegis", touched_paths=["src/**"])
    request_id = shop.workspace.ask("content", "writer", "content/original-generation")
    shop.workspace.grant("writer")
    shop.workspace.run("update", {"initiative": "content", "source": "successor planning", "touched_paths": ["docs/**"]})
    report = shop.workspace.run("check-paths", {"initiative": "pilot", "paths": ["src/app.py"]}, expect=3)
    assert report["reserved_conflicts"] == [{"request_id": request_id, "initiative": "content",
                                              "holder": "content/original-generation", "paths": ["src/**"]}]


def test_a_lease_acquired_after_admission_is_rechecked_before_a_commit(shop, monkeypatch, capsys):
    from tools import hierarchy_jobs

    peer = shop.make_checkout("peer")
    shop.workspace.register("content", project="aegis", checkouts=[str(peer)], lanes=["content-writer"])
    commit_request(shop)
    before = shop.head()
    original = os.mkdir
    job_folder = shop.workspace.store / "jobs" / "pilot" / "job-1"

    def mkdir(path, *args, **kwargs):
        if Path(path) == job_folder:
            write_lease(peer, "content-writer", ["src/**"])
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "mkdir", mkdir)
    code = hierarchy_jobs.main(["--store", str(shop.workspace.store), "--recipes", str(shop.recipes_path), "run-open"])
    answer = json.loads(capsys.readouterr().out)
    assert code == 0, answer
    assert answer["rows"][0]["state"] == "refused"
    assert answer["rows"][0]["reason"].startswith("path ownership changed before execution: ")
    assert shop.head() == before
    assert shop.states("job-1") == ["refused"]


def test_failed_outputs_survive_reconnect_and_receipts_remain_exact(shop):
    script = ("import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.mkdir(); "
              "(p/'failure.txt').write_text('Engine partial failure'); sys.exit(7)")
    shop.recipes["recipes"]["failed-kept"] = shop.command(["$python", "-c", script, "$scratch"],
                                                          heavy=True, keep=["run/failure.txt"])
    shop.save_recipes()
    shop.request_job("engine-partial", "failed-kept")
    shop.run_open()
    result = json.loads(verified_evidence(shop.receipts("engine-partial")[-1])["result.json"].read_text())
    copied = Path(result["kept"][0]["copy"])
    assert copied.read_text() == "Engine partial failure"
    original = snapshot(shop.workspace.store)
    report = shop.jobs("recovery-status")
    assert report["jobs"][0]["result"]["state"] == "failed"
    assert report["jobs"][0]["receipt"] == "match"
    assert report["jobs"][0]["retained_outputs"] == result["kept"]
    assert shop.run_open()["rows"] == []
    assert snapshot(shop.workspace.store) == original
    assert len([event for event in shop.events() if event["kind"] == "release"]) == 1


@pytest.mark.parametrize("scope", [None, {"boot_id": "another-boot", "pid_namespace": "pid:[another-namespace]"}])
def test_reconnect_cannot_resolve_a_claim_outside_the_observed_process_scope(shop, scope):
    folder, request_id = stage_interrupted_job(shop)
    path = folder / "claim.json"
    claim = json.loads(path.read_text())
    if scope is None:
        claim.pop("process_scope")
    else:
        claim["process_scope"] = scope
    path.write_text(json.dumps(claim))
    original = path.read_bytes()
    answer = shop.jobs("resolve", "--job", "pilot/engine-partial", "--reason", "Reconnected observer", expect=2)
    assert answer["error"] == "runner visibility is unknown: pilot/engine-partial"
    assert shop.heavy()["holders"][0]["request_id"] == request_id
    assert path.read_bytes() == original


@pytest.mark.parametrize("failure", ["enumeration", "self-witness", "empty"])
def test_an_unavailable_process_table_cannot_release_a_reservation(shop, monkeypatch, capsys, failure):
    from tools import hierarchy_jobs

    folder, _ = stage_interrupted_job(shop)
    (folder / "process.json").write_text(json.dumps({"group": 82002, "step": 1}))
    (folder / "step-1.log").write_text("unfinished\n")
    original_scan, original_read = os.scandir, Path.read_text
    empty = shop.tmp / "empty-process-table"
    empty.mkdir()

    def scan(path):
        if str(path) == "/proc" and failure == "enumeration":
            raise PermissionError("visibility denied")
        if str(path) == "/proc" and failure == "empty":
            return original_scan(empty)
        return original_scan(path)

    def read(path, *args, **kwargs):
        if str(path) == "/proc/self/stat" and failure == "self-witness":
            raise FileNotFoundError("self witness missing")
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(os, "scandir", scan)
    monkeypatch.setattr(Path, "read_text", read)
    code = hierarchy_jobs.main(["--store", str(shop.workspace.store), "resolve", "--job", "pilot/engine-partial",
                                "--reason", "Unavailable process table"])
    answer = json.loads(capsys.readouterr().out)
    assert code == 2, answer
    assert answer["error"] == {"enumeration": "cannot enumerate process table: visibility denied",
                               "self-witness": "cannot establish process scope: self witness missing",
                               "empty": "process table does not include its self witness"}[failure]
    assert shop.heavy()["used"] == 1


def test_a_matching_result_does_not_release_a_still_running_process_group(shop, monkeypatch, capsys, tmp_path):
    from tools import hierarchy_jobs

    folder, _ = stage_interrupted_job(shop, result={})
    (folder / "process.json").write_text(json.dumps({"group": 82002, "step": 1}))
    (folder / "step-1.log").write_text("unfinished output\n")
    table = tmp_path / "fake-proc"
    (table / "82003").mkdir(parents=True)
    (table / str(os.getpid())).mkdir()
    original_scan, original_glob, original_read = os.scandir, Path.glob, Path.read_text

    def scan(path):
        return original_scan(table if str(path) == "/proc" else path)

    def glob(path, pattern):
        if str(path) == "/proc" and pattern == "[0-9]*/stat":
            return iter([Path("/proc/82003/stat")])
        return original_glob(path, pattern)

    def read(path, *args, **kwargs):
        if str(path) == "/proc/82003/stat":
            return "82003 (worker) S 0 82002 " + "0 " * 17
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(os, "scandir", scan)
    monkeypatch.setattr(Path, "glob", glob)
    monkeypatch.setattr(Path, "read_text", read)
    code = hierarchy_jobs.main(["--store", str(shop.workspace.store), "--recipes", str(shop.recipes_path), "run-open"])
    answer = json.loads(capsys.readouterr().out)
    assert code == 3, answer
    assert answer["rows"][0]["state"] == "settle_pending"
    assert answer["rows"][0]["error"] == "job process group is still running: 82002"
    assert shop.heavy()["used"] == 1
    assert shop.states("engine-partial") == []
    _, report = hierarchy_jobs.recovery_status(str(shop.workspace.store))
    assert report["jobs"][0]["state"] == "evidence_error"
    assert report["jobs"][0]["error"] == "job process group is still running: 82002"


def test_status_does_not_offer_free_capacity_when_the_census_is_unavailable(shop, monkeypatch, capsys):
    from tools import hierarchy_jobs

    original = os.scandir

    def scan(path):
        if str(path) == "/proc":
            raise PermissionError("visibility denied")
        return original(path)

    monkeypatch.setattr(os, "scandir", scan)
    code = hierarchy_jobs.main(["--store", str(shop.workspace.store), "recovery-status"])
    report = json.loads(capsys.readouterr().out)
    assert code == 3, report
    assert report["capacity_scope"] == "ledger_only"
    assert report["process_census"]["heavy"]["state"] == "unavailable"
    assert report["process_census"]["heavy"]["admission_free"] is None
    assert any(row["reason"] == "census_unavailable" for row in report["blockers"])


@pytest.mark.parametrize("scope", [None, {"boot_id": "old-boot", "pid_namespace": "old-namespace"}])
def test_unknown_process_scope_preserves_failed_result_outputs_and_receipt_in_status(shop, scope):
    script = ("import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.mkdir(); "
              "(p/'failure.txt').write_text('Engine partial failure'); sys.exit(7)")
    shop.recipes["recipes"]["failed-kept"] = shop.command(["$python", "-c", script, "$scratch"],
                                                          heavy=True, keep=["run/failure.txt"])
    shop.save_recipes()
    shop.request_job("engine-partial", "failed-kept")
    shop.run_open()
    folder = shop.workspace.store / "jobs" / "pilot" / "engine-partial"
    result = json.loads((folder / "result.json").read_text())
    claim_path = folder / "claim.json"
    claim = json.loads(claim_path.read_text())
    if scope is None:
        claim.pop("process_scope")
    else:
        claim["process_scope"] = scope
    claim_path.write_text(json.dumps(claim))
    before = snapshot(shop.workspace.store), snapshot(shop.root)

    report = shop.jobs("recovery-status", expect=3)
    row = report["jobs"][0]
    assert row["state"] == "evidence_error"
    assert row["error"] == "job process scope is unknown: pilot/engine-partial"
    assert row.get("result") == {"path": str(folder / "result.json"),
                                 "sha256": hashlib.sha256((folder / "result.json").read_bytes()).hexdigest(),
                                 "state": "failed", "exit_code": 7}
    assert row["retained_outputs"] == result["kept"]
    assert row["receipt"] == "match"
    assert (snapshot(shop.workspace.store), snapshot(shop.root)) == before


def test_unknown_process_scope_keeps_unsettled_result_visible_and_capacity_held(shop):
    folder, request_id = stage_interrupted_job(shop, result={"state": "failed", "exit_code": 7})
    claim_path = folder / "claim.json"
    claim = json.loads(claim_path.read_text())
    claim.pop("process_scope")
    claim_path.write_text(json.dumps(claim))
    before = snapshot(shop.workspace.store), snapshot(shop.root)

    report = shop.jobs("recovery-status", expect=3)
    row = report["jobs"][0]
    assert row["state"] == "evidence_error"
    assert row.get("result", {}).get("state") == "failed"
    assert row["receipt"] == "not_published"
    assert report["capacity"]["heavy"]["holders"][0]["request_id"] == request_id
    assert (snapshot(shop.workspace.store), snapshot(shop.root)) == before
