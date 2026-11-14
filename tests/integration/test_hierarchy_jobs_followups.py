"""JOBS-2b: observations never authorize a second execution or invent custody."""
import ast
import errno
import hashlib
import json
import os
from pathlib import Path
import re
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from tests.conftest import symlink_or_skip
from tests.integration import test_hierarchy_jobs as job_fixtures
from tests.integration.test_hierarchy_jobs import pytestmark as pytestmark
from tests.integration.test_hierarchy_jobs_derive import host_plan


kind_shop = job_fixtures.kind_shop
jobs2_fresh_cache = job_fixtures.jobs2_fresh_cache
jobs = job_fixtures.jobs2_module
PROCESS_FAULTS = ("text", "zero", "negative", "bool", "float", "oversized", "directory", "symlink", "unsupported")
PROCESS_REPAIR_ACTION = ("Root: repair or remove the job's process.json; revalidate stopped-process evidence "
                         "before retrying recovery or settlement.")
PROCESS_REPAIR_ERROR = "job process metadata unverified; " + PROCESS_REPAIR_ACTION
ADMISSION_UNVERIFIED_ACTION = ("Root: supply trusted recipe bytes with tools/hierarchy_jobs.py --store "
                               "<original-workspace-store> --recipes <trusted-recipes-file> recovery-status; "
                               "revalidate admission before run-open; do not derive again.")
PROVENANCE_REPAIR_ACTION = ("Root: preserve admitted.json and derivation.json; repair the provenance binding, "
                            "revalidate stopped-process evidence, then retry resolve.")


def test_job_class_boundary_is_explicit(tmp_path):
    assert issubclass(jobs.PlannedJob, jobs.Job)
    (tmp_path / jobs.hierarchy_hosts.PLAN_FILE).write_text("{}")
    initiative = {"id": "pilot", "mailbox_root": str(tmp_path / "mailbox")}
    message = {"message_id": "boundary"}
    assert jobs.Job(tmp_path / "store", initiative, message).planned is False
    assert jobs.PlannedJob(tmp_path / "store", {"id": "pilot"}, message).planned is True
    tree = ast.parse(Path(jobs.__file__).read_text(encoding="utf-8"))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
               and node.name in ("Job", "PlannedJob")]
    planned = next(cls for cls in classes if cls.name == "PlannedJob")
    methods = {node.name for node in planned.body if isinstance(node, ast.FunctionDef)}
    for name in ("recorded_execution_fence", "observe_fence", "metadata_kind", "observe_result",
                 "observe_existing_fence", "validated_admission", "runner_alive", "result", "claim",
                 "take_execution", "process_record", "process_group"):
        assert name in methods
    assert not [(node.lineno, node.attr) for cls in classes for node in ast.walk(cls)
                if isinstance(node, ast.Attribute) and node.attr == "planned"]


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("planned", [False, True], ids=["legacy", "planned"])
def test_job_class_public_dispatch_uses_explicit_type(kind_shop, capsys, planned):
    shop = kind_shop
    if planned:
        host_plan(shop)
    shop.request_job("job-1", "ok")
    expected = jobs.PlannedJob if planned else jobs.Job
    original, captured = jobs.run_job, []

    def run(store, job, *args, **kwargs):
        captured.append(type(job))
        return original(store, job, *args, **kwargs)

    with patch.object(jobs, "run_job", run):
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 0
        assert job_fixtures.job_row(json.loads(capsys.readouterr().out))["state"] == "completed"
    assert captured == [expected]
    # Completed work remains settled on retry, including recovery's independently constructed job.
    assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 0
    assert capsys.readouterr().out == '{"rows": []}\n'
    assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 0
    report = json.loads(capsys.readouterr().out)
    assert next(row for row in report["jobs"] if row["job"] == "pilot/job-1")["state"] == "finished"


@pytest.mark.parametrize("planned", [False, True], ids=["legacy", "planned"])
@pytest.mark.parametrize("shape", ["absent", "valid", "schema", "malformed", "oversized"])
def test_job_class_result_golden(tmp_path, planned, shape):
    """Capture each reader's public result and refusal before separating the classes."""
    if planned:
        (tmp_path / jobs.hierarchy_hosts.PLAN_FILE).write_text("{}")
    initiative = {"id": "pilot", "mailbox_root": str(tmp_path / "mailbox")}
    job = (jobs.PlannedJob if planned else jobs.Job)(tmp_path / "store", initiative, {"message_id": "golden"})
    job.folder.mkdir(parents=True)
    result = {"schema": jobs.RESULT_SCHEMA, "job": job.id, "state": "completed", "exit_code": 0, "steps": []}
    payloads = {"valid": json.dumps(result).encode(), "schema": b"{}", "malformed": b"{",
                "oversized": b" " * (jobs.MAX_RESULT_BYTES + 1)}
    if shape != "absent":
        job.result_path.write_bytes(payloads[shape])
    for _ in range(2):
        if shape in ("absent", "valid"):
            assert job.result() == (result if shape == "valid" else None)
        else:
            error = ("result is not a readable file within its limit" if shape == "oversized" else
                     "invalid job result schema" if planned or shape == "schema" else
                     "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)")
            error_type = json.JSONDecodeError if not planned and shape == "malformed" else ValueError
            with pytest.raises(error_type) as caught:
                job.result()
            assert type(caught.value) is error_type and str(caught.value) == error


@pytest.mark.parametrize("planned", [False, True], ids=["legacy", "planned"])
@pytest.mark.parametrize("surface", ["run-open", "resolve", "clean", "clean-finished"])
def test_job_class_cli_refusal_golden(kind_shop, capsys, planned, surface):
    shop = kind_shop
    if planned:
        host_plan(shop)
    flags, error = {
        "run-open": (("--max-jobs", "0"), "invalid max-jobs"),
        "resolve": (("--job", "pilot/absent", "--reason", "checked"), "no running job here: pilot/absent"),
        "clean": (("--job", "pilot/absent"), "no job here: pilot/absent"),
        "clean-finished": (("--initiative", "invalid/id", "--finished"), "invalid initiative"),
    }[surface]
    command = "clean" if surface == "clean-finished" else surface
    for _ in range(2):
        assert jobs.main(shop.argv(command, *flags, census=[], lock_wait=0)[3:]) == 2
        assert capsys.readouterr().out == json.dumps({"error": error}, sort_keys=True) + "\n"


def recovery_admission_case(shop, terminal):
    """Retain a real staged admission, optionally execute or settle a fixture failure."""
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    if terminal == "completed":
        assert job_fixtures.job_row(shop.run_open())["state"] == "completed"
    elif terminal == "failed":
        ledger = jobs.Store(shop.workspace.store).load()
        message = jobs.Mailbox(shop.root).messages()["job-1"]["message"]
        job = jobs.PlannedJob(shop.workspace.store, ledger.initiative("pilot"), message)
        derived = json.loads((folder / "derivation.json").read_bytes())
        jobs.write_result(job, "failed", 7, reason="fixture execution failure", recipe="commit-exact",
                          process_stopped_confirmed=True, **derived)
        assert job_fixtures.job_row(shop.run_open())["state"] == "failed"
    return folder


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("terminal", ["completed", "failed", None], ids=["finished", "failed", "unsettled"])
@pytest.mark.parametrize("recipes", ["match", "mismatch", "absent"])
@pytest.mark.parametrize("placement", ["before", "after"])
def test_recovery_admission_recipe_matrix(kind_shop, capsys, terminal, recipes, placement):
    shop = kind_shop
    folder = recovery_admission_case(shop, terminal)
    if recipes == "mismatch":
        shop.recipes["recipes"]["ok"]["timeout_seconds"] += 1
        shop.save_recipes()
    argv = ["--store", str(shop.workspace.store)]
    recipe_args = [] if recipes == "absent" else ["--recipes", str(shop.recipes_path)]
    argv += recipe_args + ["recovery-status"] if placement == "before" else ["recovery-status"] + recipe_args
    before = {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()}
    expected = "finished" if terminal else {"match": "admitted", "mismatch": "evidence_error",
                                            "absent": "admission_unverified"}[recipes]
    # Completing the commit also changes first-check's incoming source; that independent blocker remains.
    assert jobs.main(argv) == (3 if terminal == "completed" or terminal is None else 0)
    report = json.loads(capsys.readouterr().out)
    row = next(row for row in report["jobs"] if row["job"] == "pilot/job-1")
    assert row["state"] == expected, row
    if terminal:
        assert row["result"]["state"] == terminal and row["receipt"] == "match"
        assert "error" not in row and "detail" not in row
        assert not any(blocker.get("job") == row["job"] for blocker in report["blockers"])
    elif recipes == "absent":
        assert row["source"] == {"state": "unavailable", "reason": "planned recipe bytes unavailable",
                                 "recipe_bytes_unavailable": True}
        assert row["next_action"] == ADMISSION_UNVERIFIED_ACTION
        assert [blocker["reason"] for blocker in report["blockers"] if blocker.get("job") == row["job"]] == ["admission_unverified"]
        assert "error" not in row and "detail" not in row
    elif recipes == "mismatch":
        assert row["error"] == row["detail"] == "recipes changed after admission"
    assert {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()} == before


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_recovery_after_team_init_keeps_settled_result_and_run_open_behavior(kind_shop, capsys):
    shop = kind_shop
    folder = recovery_admission_case(shop, "completed")
    before, receipts = (folder / "result.json").read_bytes(), shop.receipts("job-1")
    # Regenerating the init recipe file changes its bytes without changing historical results.
    shop.recipes["recipes"]["ok"]["timeout_seconds"] += 1
    shop.save_recipes()
    assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 0
    assert json.loads(capsys.readouterr().out) == {"rows": []}
    for recipe_args in ([], ["--recipes", str(shop.recipes_path)]):
        assert jobs.main(["--store", str(shop.workspace.store), *recipe_args, "recovery-status"]) == 3
        row = next(row for row in json.loads(capsys.readouterr().out)["jobs"] if row["job"] == "pilot/job-1")
        assert row["state"] == "finished" and row["source"]["state"] == "match"
    assert (folder / "result.json").read_bytes() == before and shop.receipts("job-1") == receipts


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("first", ["live", "null"])
def test_recovery_row_uses_one_process_snapshot(kind_shop, capsys, first):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    process, group = folder / "process.json", os.getpgrp()
    if first == "live":
        for log in folder.glob("step-*.log"):
            log.unlink()
    process.write_text(json.dumps({"step": 1, "group": group if first == "live" else None}))
    original, captured = job_fixtures.jobs2_fresh_brief._read_reference, []

    def read_reference(path, **kwargs):
        answer = original(path, **kwargs)
        if path == process:
            captured.append(True)
            process.write_text(json.dumps({"step": 1, "group": None if first == "live" else group}))
        return answer

    with patch.object(job_fixtures.jobs2_fresh_brief, "_read_reference", read_reference):
        assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
    row = next(row for row in json.loads(capsys.readouterr().out)["jobs"] if row["job"] == "pilot/job-1")
    assert row["state"] == "evidence_error", row
    expected = ("job process group is still running: " + str(group) if first == "live" else
                "job has an unrecorded process effect: pilot/job-1")
    assert row["error"] == expected and captured == [True]
    assert row["process_alive"] is (True if first == "live" else None)


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("available", [False, True], ids=["unavailable", "available"])
def test_recovery_report_uses_one_recipe_snapshot(kind_shop, capsys, available):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    shop.request_job("job-2", "commit-exact", raw=jobs.packet_text((folder / "packet.md").read_bytes()))
    second = folder.with_name("job-2")
    second.mkdir()
    for path in folder.iterdir():
        if path.is_file():
            (second / path.name).write_bytes(path.read_bytes())
    claim = json.loads((second / "claim.json").read_bytes())
    claim["job"] = "pilot/job-2"
    (second / "claim.json").write_text(json.dumps(claim))
    mailbox = jobs.Mailbox(shop.root)
    raw = mailbox.brief(mailbox.messages()["job-2"]["message"]["brief"])
    (second / "packet.md").write_bytes(raw)
    reference = json.loads((second / "admitted.json").read_bytes())
    reference["packet_sha256"] = hashlib.sha256(raw).hexdigest()
    (second / "admitted.json").write_text(json.dumps(reference))
    original, captured = job_fixtures.jobs2_fresh_brief._read_reference, []
    replacement = shop.tmp / "new-recipes.json"
    replacement.write_bytes(shop.recipes_path.read_bytes() + b"\n")
    if not available:
        shop.recipes_path.unlink()

    def read_reference(path, **kwargs):
        if path != shop.recipes_path:
            return original(path, **kwargs)
        captured.append(True)
        try:
            return original(path, **kwargs)
        finally:
            if replacement.exists():
                replacement.replace(shop.recipes_path)

    with patch.object(job_fixtures.jobs2_fresh_brief, "_read_reference", read_reference):
        assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
    report = json.loads(capsys.readouterr().out)
    rows = [row for row in report["jobs"] if row["job"] in ("pilot/job-1", "pilot/job-2")]
    assert [row["state"] for row in rows] == ["admitted" if available else "admission_unverified"] * 2, rows
    assert captured == [True]
    # A fresh report observes the new version and refuses both unsettled admissions.
    assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
    report = json.loads(capsys.readouterr().out)
    assert [row["state"] for row in report["jobs"] if row["job"] in ("pilot/job-1", "pilot/job-2")] == ["evidence_error"] * 2


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("terminal", ["completed", "failed"])
def test_settled_recovery_never_acquires_current_recipes(kind_shop, capsys, terminal):
    shop = kind_shop
    recovery_admission_case(shop, terminal)
    original = job_fixtures.jobs2_fresh_brief._read_reference

    def read_reference(path, **kwargs):
        if path == shop.recipes_path:
            pytest.fail("settled reporting acquired current recipe bytes")
        return original(path, **kwargs)

    with patch.object(job_fixtures.jobs2_fresh_brief, "_read_reference", read_reference):
        assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == (3 if terminal == "completed" else 0)
    row = next(row for row in json.loads(capsys.readouterr().out)["jobs"] if row["job"] == "pilot/job-1")
    assert row["state"] == "finished" and row["result"]["state"] == terminal


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("digest", ["untrusted-group\nsecond-line", ["untrusted-group"], "untrusted-group" * 1000],
                         ids=["multiline", "array", "oversized"])
def test_terminal_source_digest_is_opaque_when_unverified(kind_shop, capsys, digest):
    shop = kind_shop
    folder = recovery_admission_case(shop, "failed")
    path = folder / "result.json"
    result = json.loads(path.read_bytes())
    result["dirty_content_sha256"] = digest
    path.write_text(json.dumps(result))
    assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
    output = capsys.readouterr().out
    row = next(row for row in json.loads(output)["jobs"] if row["job"] == "pilot/job-1")
    assert row["source"] == {"state": "unavailable", "reason": "terminal source digest unverified",
                             "terminal_source_unverified": True}
    assert "untrusted-group" not in output and "second-line" not in output


def unsettled_recovery_obligation(shop, custody):
    folder = recovery_admission_case(shop, None)
    if custody == "reservation":
        identifier = shop.workspace.ask("pilot", "writer", "job:pilot/job-1")
        assert shop.workspace.grant("writer")["request_id"] == identifier
    else:
        assert custody == "live-runner"
        path = folder / "claim.json"
        claim = json.loads(path.read_bytes())
        claim.update(pid=os.getpid(), start=jobs.process_start(os.getpid()))
        path.write_text(json.dumps(claim))
    return folder


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("custody", ["reservation", "live-runner"])
@pytest.mark.parametrize("recipes", ["absent", "match", "mismatch"])
def test_unsettled_admission_is_always_a_recovery_blocker(kind_shop, capsys, custody, recipes):
    shop = kind_shop
    folder = unsettled_recovery_obligation(shop, custody)
    if recipes == "mismatch":
        shop.recipes["recipes"]["ok"]["timeout_seconds"] += 1
        shop.save_recipes()
    args = [] if recipes == "absent" else ["--recipes", str(shop.recipes_path)]
    before = {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()}
    assert jobs.main(["--store", str(shop.workspace.store), *args, "recovery-status"]) == 3
    report = json.loads(capsys.readouterr().out)
    row = next(row for row in report["jobs"] if row["job"] == "pilot/job-1")
    expected = {"absent": "admission_unverified", "match": "admitted", "mismatch": "evidence_error"}[recipes]
    assert row["state"] == expected
    blocker = next(blocker for blocker in report["blockers"] if blocker.get("job") == row["job"])
    assert blocker["reason"] == expected and blocker["next_action"] == row["next_action"]
    if recipes == "absent":
        assert row["source"]["recipe_bytes_unavailable"] is True
        assert row["next_action"] == ADMISSION_UNVERIFIED_ACTION
        assert "error" not in row and "detail" not in row
    else:
        assert "recipe_bytes_unavailable" not in row["source"]
    assert row["runner_alive"] is (custody == "live-runner")
    if custody == "reservation":
        assert row["reservations"][0]["state"] == "granted"
    assert {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()} == before
    assert not (folder / "result.json").exists() and not (folder / "execution.json").exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("fault", ["unbound", "bound-dirty", "bound-host", "unbound-duplicate", "bound-duplicate",
                                 "bound-tree", "bound-paths"])
def test_resolve_validates_bound_derivation_before_persisting(kind_shop, capsys, fault):
    shop = kind_shop
    folder = unsettled_recovery_obligation(shop, "reservation")
    path, marker = folder / "derivation.json", folder / "admitted.json"
    derived = json.loads(path.read_bytes())
    if fault == "bound-host":
        derived["host_plan"]["sha256"] = "untrusted-group\nsecond-line"
    elif fault == "bound-tree":
        derived["expected_tree"] = "not-a-tree"
    elif fault == "bound-paths":
        derived["changed_paths"] = [False]
    else:
        derived["dirty_content_sha256"] = "not-a-digest"
    raw = (b'{"untrusted-group":1,"untrusted-group":2}' if "duplicate" in fault else
           json.dumps(derived).encode())
    path.write_bytes(raw)
    if fault.startswith("bound-"):
        reference = json.loads(marker.read_bytes())
        reference["derivation_sha256"] = hashlib.sha256(raw).hexdigest()
        marker.write_text(json.dumps(reference))
    original, parsed = jobs.strict_json, []

    def parse(value):
        if value.encode() == raw:
            parsed.append(True)
        return original(value)

    with ExitStack() as active:
        active.enter_context(patch.object(jobs, "strict_json", parse))
        assert jobs.main(shop.argv("resolve", "--job", "pilot/job-1", "--reason", "owner reconciliation",
                                   "--process-stopped", census=[], lock_wait=0)[3:]) == 2
    output = capsys.readouterr().out
    assert json.loads(output) == {"error": "derivation provenance unverified", "next_action": PROVENANCE_REPAIR_ACTION}
    assert "not-a-digest" not in output and "untrusted-group" not in output and "second-line" not in output
    if fault in ("unbound", "unbound-duplicate"):
        assert parsed == [], "unbound or unavailable bytes reached parsing"
    assert not (folder / "result.json").exists() and shop.receipts("job-1") == []
    assert next(iter(job_fixtures.ledger_rows(shop, holder="job:pilot/job-1").values()))["state"] == "granted"


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("fault", ["digest", "syntax"])
def test_resolve_captured_invalid_binding_refuses_even_when_derivation_is_missing(kind_shop, capsys, fault):
    shop = kind_shop
    folder = unsettled_recovery_obligation(shop, "reservation")
    path = folder / "admitted.json"
    if fault == "digest":
        reference = json.loads(path.read_bytes())
        reference["derivation_sha256"] = "not-a-digest"
        path.write_text(json.dumps(reference))
    else:
        path.write_bytes(b"{")
    (folder / "derivation.json").unlink()
    assert jobs.main(shop.argv("resolve", "--job", "pilot/job-1", "--reason", "owner reconciliation",
                               "--process-stopped", census=[], lock_wait=0)[3:]) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "derivation provenance unverified",
                                                "next_action": PROVENANCE_REPAIR_ACTION}
    assert not (folder / "result.json").exists() and shop.receipts("job-1") == []
    assert next(iter(job_fixtures.ledger_rows(shop, holder="job:pilot/job-1").values()))["state"] == "granted"


def orphaned_staging_case(shop, route):
    if route == "after-stage":
        folder = unsettled_recovery_obligation(shop, "reservation")
        (folder / "admitted.json").unlink()
        return folder
    from tests.integration.test_hierarchy_jobs_derive import edit_source

    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    edit_source(shop)
    shop.request_job("job-1", "commit-exact", derive="runner", paths=["src/missing.py"], message="fix: missing")
    folder = shop.workspace.store / "jobs/pilot/job-1"
    publish, write_result, stat_node = jobs.publish_file, jobs.write_result, os.stat
    published, failed = [], []

    def publish_file(path, *args, **kwargs):
        answer = publish(path, *args, **kwargs)
        if path == folder / "derivation.json":
            published.append(True)
            if route == "after-failure-publish":
                failed.append(True)
                raise OSError(errno.EIO, "fixture staging publication interrupted")
        return answer

    def result(job, state, *args, **kwargs):
        if route == "refuse-write-failure" and job.id == "pilot/job-1" and state == "refused":
            failed.append(True)
            raise OSError(errno.EIO, "fixture refusal publication interrupted")
        return write_result(job, state, *args, **kwargs)

    def stat(path, *args, **kwargs):
        if (route == "uncertain-owner" and published and str(path) == "admitted.json"
                and kwargs.get("dir_fd") is not None):
            failed.append(True)
            raise OSError(errno.EIO, "fixture admission observation unavailable")
        return stat_node(path, *args, **kwargs)

    with patch.object(jobs, "publish_file", publish_file), patch.object(jobs, "write_result", result):
        with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "stat": stat})):
            code, _ = jobs.run_open(shop.workspace.store, shop.recipes_path, (), 1, None, 0)
    assert code == 3 and published == [True] and failed
    assert not (folder / "admitted.json").exists() and not (folder / "result.json").exists()
    # The fixture's writer has ended. Retain its real stopped steps while making its runner claim stale.
    path = folder / "claim.json"
    claim = json.loads(path.read_bytes())
    claim["start"] = "0"
    path.write_text(json.dumps(claim))
    identifier = shop.workspace.ask("pilot", "writer", "job:pilot/job-1")
    assert shop.workspace.grant("writer")["request_id"] == identifier
    return folder


def missing_derivation_publication_case(shop, route):
    """Reach the real stopped staging/publication boundary with a clean matching checkout."""
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    shop.request_job("job-1", "commit-exact", derive="runner", paths=["src/app.py"], message="fix: staged fixture")
    folder = shop.workspace.store / "jobs/pilot/job-1"
    identifier = shop.workspace.ask("pilot", "writer", "job:pilot/job-1")
    assert shop.workspace.grant("writer")["request_id"] == identifier
    original, interrupted = jobs.publish_file, []

    def publish(path, *args, **kwargs):
        if path == folder / "derivation.json":
            interrupted.append(True)
            if route == "kill":
                raise SystemExit("fixture interrupted before derivation publication")
            raise OSError(errno.EIO, "fixture derivation publication unavailable")
        return original(path, *args, **kwargs)

    with patch.object(jobs, "publish_file", publish):
        if route == "kill":
            with pytest.raises(SystemExit, match="^fixture interrupted before derivation publication$"):
                jobs.run_open(shop.workspace.store, shop.recipes_path, (), 1, None, 0)
        else:
            assert route == "refusal"
            code, report = jobs.run_open(shop.workspace.store, shop.recipes_path, (), 1, None, 0)
            assert code == 0 and job_fixtures.job_row(report)["state"] == "refused"
    assert interrupted == [True]
    assert not (folder / "derivation.json").exists() and not (folder / "admitted.json").exists()
    if route == "kill":
        assert not (folder / "result.json").exists()
        claim = json.loads((folder / "claim.json").read_bytes())
        claim["start"] = "0"
        (folder / "claim.json").write_text(json.dumps(claim))
    return folder


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("route", ["kill", "refusal"])
def test_missing_derivation_publication_remains_unverified(kind_shop, capsys, route):
    shop = kind_shop
    head = shop.head()
    folder = missing_derivation_publication_case(shop, route)
    if route == "kill":
        assert jobs.main(shop.argv("resolve", "--job", "pilot/job-1", "--reason", "owner reconciliation",
                                   "--process-stopped", census=[], lock_wait=0)[3:]) == 0
        assert json.loads(capsys.readouterr().out)["state"] == "failed"
    result = json.loads((folder / "result.json").read_bytes())
    assert result["provenance_unverified"] is True
    assert not {"derived_by", "dirty_content_sha256", "expected_tree", "host_plan", "changed_paths"}.intersection(result)
    assert next(iter(job_fixtures.ledger_rows(shop, holder="job:pilot/job-1").values()))["state"] == "released"
    receipt = shop.receipts("job-1")[-1]["receipt"]
    assert any(Path(item["path"]).name == "result.json" for item in receipt["evidence"])
    assert all(Path(item["path"]).name != "derivation.json" for item in receipt["evidence"])
    assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
    report = json.loads(capsys.readouterr().out)
    row = next(row for row in report["jobs"] if row["job"] == "pilot/job-1")
    assert row["state"] == "finished" and row["receipt"] == "match"
    assert row["source"] == {"state": "unavailable", "reason": "derivation provenance unverified",
                             "terminal_source_unverified": True}
    blocker = next(blocker for blocker in report["blockers"] if blocker.get("job") == row["job"])
    assert blocker["reason"] == "source_unavailable" and blocker["next_action"] == row["next_action"]
    # Later filesystem contents cannot change the unverified receipt projection.
    (folder / "derivation.json").write_bytes(b"{}")
    assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
    row = next(row for row in json.loads(capsys.readouterr().out)["jobs"] if row["job"] == "pilot/job-1")
    assert row["state"] == "finished" and row["receipt"] == "match"
    assert shop.head() == head


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_planned_nonderive_resolution_without_metadata_keeps_clean_inventory(kind_shop, capsys):
    shop = kind_shop
    host_plan(shop)
    shop.request_job("job-1", "ok")
    folder = shop.workspace.store / "jobs/pilot/job-1"
    folder.mkdir(parents=True)
    claim = job_fixtures.live_claim(jobs, os.getpid(), "pilot/job-1")
    claim["start"] = "0"
    (folder / "claim.json").write_text(json.dumps(claim))
    identifier = shop.workspace.ask("pilot", "writer", "job:pilot/job-1")
    assert shop.workspace.grant("writer")["request_id"] == identifier
    assert jobs.main(shop.argv("resolve", "--job", "pilot/job-1", "--reason", "owner reconciliation",
                               "--process-stopped", census=[], lock_wait=0)[3:]) == 0
    capsys.readouterr()
    result = json.loads((folder / "result.json").read_bytes())
    assert "provenance_unverified" not in result and "dirty_content_sha256" not in result
    assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 0
    row = next(row for row in json.loads(capsys.readouterr().out)["jobs"] if row["job"] == "pilot/job-1")
    assert row["state"] == "finished" and row["source"]["state"] == "match"


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("fault", ["oversized", "symlink", "changed-hash", "unsupported"])
def test_request_derivation_classification_refuses_unverified_bytes_before_parsing(kind_shop, fault):
    shop = kind_shop
    host_plan(shop)
    shop.request_job("job-1", "ok")
    ledger = jobs.Store(shop.workspace.store).load()
    message = jobs.Mailbox(shop.root).messages()["job-1"]["message"]
    job = jobs.PlannedJob(shop.workspace.store, ledger.initiative("pilot"), message)
    path = Path(message["brief"]["path"])
    if fault == "oversized":
        path.write_bytes(b" " * (jobs.MAX_BYTES + 1))
    elif fault == "symlink":
        saved = shop.tmp / "foreign-original-request.md"
        path.rename(saved)
        symlink_or_skip(saved, path)
    elif fault == "changed-hash":
        path.write_bytes(path.read_bytes() + b"\nuntrusted-group")

    def parse(value):
        pytest.fail("unverified request bytes reached the derivation classifier parser")

    with ExitStack() as active:
        active.enter_context(patch.object(jobs, "strict_json", parse))
        if fault == "unsupported":
            active.enter_context(patch.object(job_fixtures.jobs2_fresh_brief, "_reference_descriptors", lambda: False))
        assert jobs.planned_request_derives(job) is None


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("route", ["after-stage", "after-failure-publish", "refuse-write-failure", "uncertain-owner"])
def test_resolve_closes_orphaned_staging_without_copying_provenance(kind_shop, capsys, route):
    shop = kind_shop
    folder = orphaned_staging_case(shop, route)
    before = (folder / "derivation.json").read_bytes()
    assert jobs.main(shop.argv("resolve", "--job", "pilot/job-1", "--reason", "owner reconciliation",
                               "--process-stopped", census=[], lock_wait=0)[3:]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "failed"
    result = json.loads((folder / "result.json").read_bytes())
    assert result["provenance_unverified"] is True
    assert not {"derived_by", "dirty_content_sha256", "expected_tree", "host_plan", "changed_paths"}.intersection(result)
    assert (folder / "derivation.json").read_bytes() == before and shop.receipts("job-1")
    assert next(iter(job_fixtures.ledger_rows(shop, holder="job:pilot/job-1").values()))["state"] == "released"
    assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
    report = json.loads(capsys.readouterr().out)
    row = next(row for row in report["jobs"] if row["job"] == "pilot/job-1")
    assert row["state"] == "finished" and row["receipt"] == "match"
    assert row["source"] == {"state": "unavailable", "reason": "derivation provenance unverified",
                             "terminal_source_unverified": True}
    blocker = next(blocker for blocker in report["blockers"] if blocker.get("job") == row["job"])
    assert blocker["reason"] == "source_unavailable" and blocker["next_action"] == row["next_action"]
    assert "reconcile terminal source evidence" in row["next_action"]


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("fault", ["missing", "oversized", "symlink", "directory", "read-error", "binding-probe", "unbound-poison"])
def test_resolve_omits_unavailable_provenance_from_result_and_receipt(kind_shop, capsys, fault):
    shop = kind_shop
    folder = unsettled_recovery_obligation(shop, "reservation")
    path = folder / "derivation.json"
    if fault == "missing":
        path.unlink()
    elif fault == "oversized":
        path.write_bytes(b" " * (jobs.MAX_BYTES + 1))
    elif fault == "symlink":
        target = shop.tmp / "foreign-provenance.json"
        path.rename(target)
        symlink_or_skip(target, path)
    elif fault == "directory":
        path.unlink()
        path.mkdir()
    elif fault == "unbound-poison":
        (folder / "admitted.json").unlink()
        path.write_text('{"untrusted-group":1,"untrusted-group":2}')
    original, refused = job_fixtures.jobs2_fresh_brief._read_reference, []
    original_stat = os.stat

    def read_reference(node, **kwargs):
        if fault == "read-error" and node == path:
            refused.append(True)
            raise OSError(errno.EIO, "fixture provenance acquisition unavailable")
        return original(node, **kwargs)

    def stat(node, *args, **kwargs):
        if fault == "binding-probe" and str(node) == "admitted.json" and kwargs.get("dir_fd") is not None:
            # One refusal in the provenance phase, after the runner's independent custody probe.
            refused.append(True)
            if len(refused) == 2:
                raise OSError(errno.EIO, "fixture binding observation unavailable")
        return original_stat(node, *args, **kwargs)

    with patch.object(job_fixtures.jobs2_fresh_brief, "_read_reference", read_reference):
        with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "stat": stat})):
            assert jobs.main(shop.argv("resolve", "--job", "pilot/job-1", "--reason", "owner reconciliation",
                                       "--process-stopped", census=[], lock_wait=0)[3:]) == 0
    output = capsys.readouterr().out
    assert "untrusted-group" not in output
    result = json.loads((folder / "result.json").read_bytes())
    assert result["provenance_unverified"] is True and "dirty_content_sha256" not in result
    receipt = shop.receipts("job-1")[-1]["receipt"]
    assert all(Path(item["path"]).name != "derivation.json" for item in receipt["evidence"])
    assert next(iter(job_fixtures.ledger_rows(shop, holder="job:pilot/job-1").values()))["state"] == "released"
    if fault in ("read-error", "binding-probe"):
        assert refused


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("pending", ["unpublished", "held", "mismatch"])
def test_pending_invalid_terminal_digest_keeps_settlement_guidance(kind_shop, capsys, pending):
    shop = kind_shop
    folder = recovery_admission_case(shop, None)
    ledger = jobs.Store(shop.workspace.store).load()
    message = jobs.Mailbox(shop.root).messages()["job-1"]["message"]
    job = jobs.PlannedJob(shop.workspace.store, ledger.initiative("pilot"), message)
    derived = json.loads((folder / "derivation.json").read_bytes())
    if pending == "mismatch":
        jobs.write_result(job, "failed", 7, reason="historical result", process_stopped_confirmed=True, **derived)
        assert job_fixtures.job_row(shop.run_open())["state"] == "failed"
        result_path = folder / "result.json"
        result = json.loads(result_path.read_bytes())
        result["dirty_content_sha256"] = "not-a-digest"
        result_path.write_text(json.dumps(result))
    else:
        derived["dirty_content_sha256"] = "not-a-digest"
        jobs.write_result(job, "failed", 7, reason="historical result", process_stopped_confirmed=True, **derived)
    if pending == "held":
        assert job_fixtures.job_row(shop.run_open())["state"] == "failed"
        identifier = shop.workspace.ask("pilot", "writer", "job:pilot/job-1")
        assert shop.workspace.grant("writer")["request_id"] == identifier
    assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
    report = json.loads(capsys.readouterr().out)
    row = next(row for row in report["jobs"] if row["job"] == "pilot/job-1")
    assert row["state"] == "settle_pending" and row["source"]["terminal_source_unverified"] is True
    assert row["next_action"] == "Reconcile the exact receipt and result; run-open may settle without rerunning the job."
    blocker = next(blocker for blocker in report["blockers"] if blocker.get("job") == row["job"])
    assert blocker["reason"] == "settle_pending" and blocker["next_action"] == row["next_action"]


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("value", [False, None, "untrusted-group\nsecond-line"], ids=["false", "null", "text"])
def test_planned_result_refuses_invalid_provenance_marker(kind_shop, capsys, value):
    shop = kind_shop
    folder = recovery_admission_case(shop, "failed")
    path = folder / "result.json"
    result = json.loads(path.read_bytes())
    result["provenance_unverified"] = value
    path.write_text(json.dumps(result))
    assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
    output = capsys.readouterr().out
    row = next(row for row in json.loads(output)["jobs"] if row["job"] == "pilot/job-1")
    assert row["state"] == "evidence_error" and row["error"] == "invalid job result provenance_unverified"
    assert "untrusted-group" not in output and "second-line" not in output


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("resolve", [False, True], ids=["strict", "resolve"])
def test_planned_provenance_unsupported_descriptors_refuses_before_io(kind_shop, resolve):
    shop = kind_shop
    recovery_admission_case(shop, None)
    ledger = jobs.Store(shop.workspace.store).load()
    message = jobs.Mailbox(shop.root).messages()["job-1"]["message"]
    job = jobs.PlannedJob(shop.workspace.store, ledger.initiative("pilot"), message)

    def read_reference(*args, **kwargs):
        pytest.fail("unsupported provenance reader reached reference IO")

    with patch.object(job_fixtures.jobs2_fresh_brief, "_reference_descriptors", lambda: False):
        with patch.object(job_fixtures.jobs2_fresh_brief, "_read_reference", read_reference):
            if resolve:
                assert jobs.derivation_provenance(job, allow_unverified=True) == {"provenance_unverified": True}
            else:
                with pytest.raises(ValueError, match="^derivation provenance unverified$"):
                    jobs.derivation_provenance(job)


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_resolve_uses_captured_hash_bound_derivation(kind_shop, capsys):
    shop = kind_shop
    folder = recovery_admission_case(shop, None)
    derivation = folder / "derivation.json"
    original, changed = job_fixtures.jobs2_fresh_brief._read_reference, []

    def read_reference(path, **kwargs):
        answer = original(path, **kwargs)
        if path == derivation and not changed:
            derivation.write_bytes(b'{"untrusted-group":1,"untrusted-group":2}')
            changed.append(True)
        return answer

    with patch.object(job_fixtures.jobs2_fresh_brief, "_read_reference", read_reference):
        assert jobs.main(shop.argv("resolve", "--job", "pilot/job-1", "--reason", "owner reconciliation",
                                   "--process-stopped", census=[], lock_wait=0)[3:]) == 0
    assert changed == [True]
    assert json.loads(capsys.readouterr().out)["state"] == "failed"
    result = json.loads((folder / "result.json").read_bytes())
    assert len(result["dirty_content_sha256"]) == 64 and "untrusted-group" not in json.dumps(result)


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("changed", [False, True], ids=["same-source", "changed-source"])
@pytest.mark.parametrize("recipes", ["absent", "match", "mismatch"])
def test_settled_invalid_terminal_digest_remains_unavailable_evidence(kind_shop, capsys, changed, recipes):
    shop = kind_shop
    folder = recovery_admission_case(shop, None)
    ledger = jobs.Store(shop.workspace.store).load()
    message = jobs.Mailbox(shop.root).messages()["job-1"]["message"]
    job = jobs.PlannedJob(shop.workspace.store, ledger.initiative("pilot"), message)
    # Model a previously persisted bad result before a matching receipt is published.
    derived = json.loads((folder / "derivation.json").read_bytes())
    derived["dirty_content_sha256"] = "not-a-digest"
    jobs.write_result(job, "failed", 7, reason="historical result", process_stopped_confirmed=True, **derived)
    assert job_fixtures.job_row(shop.run_open())["state"] == "failed"
    if changed:
        (shop.checkout / "src/app.py").write_text("value = 3\n")
    if recipes == "mismatch":
        shop.recipes["recipes"]["ok"]["timeout_seconds"] += 1
        shop.save_recipes()
    args = [] if recipes == "absent" else ["--recipes", str(shop.recipes_path)]
    assert jobs.main(["--store", str(shop.workspace.store), *args, "recovery-status"]) == 3
    row_report = json.loads(capsys.readouterr().out)
    row = next(row for row in row_report["jobs"] if row["job"] == "pilot/job-1")
    assert row["state"] == "finished" and row["receipt"] == "match"
    assert row["source"] == {"state": "unavailable", "reason": "terminal source digest unverified",
                             "terminal_source_unverified": True}
    blocker = next(blocker for blocker in row_report["blockers"] if blocker.get("job") == row["job"])
    assert blocker["reason"] == "source_unavailable" and blocker["next_action"] == row["next_action"]
    assert "--recipes" not in row["next_action"]


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_planned_staging_refusal_keeps_computed_provenance(kind_shop, capsys):
    from tests.integration.test_hierarchy_jobs_derive import edit_source

    shop = kind_shop
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    edit_source(shop)
    digest = job_fixtures.source_digest(shop)["dirty_content_sha256"]
    shop.request_job("job-1", "commit-exact", derive="runner", paths=["src/missing.py"], message="fix: missing")
    assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 0
    assert job_fixtures.job_row(json.loads(capsys.readouterr().out))["state"] == "refused"
    folder = shop.workspace.store / "jobs/pilot/job-1"
    result = json.loads((folder / "result.json").read_bytes())
    assert result["derived_by"] == "runner" and result["dirty_content_sha256"] == digest
    assert result["expected_tree"] is None and not (folder / "admitted.json").exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_recovery_never_parses_unbound_staging_provenance(kind_shop, capsys):
    shop = kind_shop
    folder = recovery_admission_case(shop, None)
    (folder / "admitted.json").unlink()
    poison = '{"untrusted-group":1,"untrusted-group":2}'
    (folder / "derivation.json").write_text(poison)
    original = jobs.strict_json

    def parse(value):
        if value == poison:
            pytest.fail("unbound staging provenance reached parsing")
        return original(value)

    with patch.object(jobs, "strict_json", parse):
        assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
    output = capsys.readouterr().out
    row = next(row for row in json.loads(output)["jobs"] if row["job"] == "pilot/job-1")
    assert row["state"] == "unknown_effect"
    assert row["source"] == {"state": "unavailable", "reason": "derivation provenance unverified"}
    assert "untrusted-group" not in output


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_computed_staging_provenance_cannot_bypass_lost_admission_binding(kind_shop, capsys):
    from tests.integration.test_hierarchy_jobs_derive import edit_source, request_derive

    shop = kind_shop
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    edit_source(shop)
    request_derive(shop)
    folder = shop.workspace.store / "jobs/pilot/job-1"
    original, changed = os.link, []
    head = shop.head()

    def link(source, destination, *args, **kwargs):
        answer = original(source, destination, *args, **kwargs)
        if destination == "execution.json" and kwargs.get("dst_dir_fd") is not None and not changed:
            (folder / "admitted.json").unlink()
            changed.append(True)
        return answer

    with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "link": link})):
        code = jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:])
    output = capsys.readouterr().out
    assert changed == [True]
    assert code == 3
    assert "derivation provenance unverified" in output
    assert shop.head() == head and not (folder / "result.json").exists() and shop.receipts("job-1") == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("missing", ["request", "mailbox", "marker-directory", "marker-absent"])
@pytest.mark.parametrize("recipes", ["match", "absent"])
def test_nonrecipe_source_unavailability_keeps_prior_blocking_state(kind_shop, capsys, missing, recipes):
    shop = kind_shop
    folder = recovery_admission_case(shop, None)
    if missing == "request":
        record = jobs.Mailbox(shop.root).messages()["job-1"]
        Path(record["path"]).rename(shop.tmp / "retained-original-request.md")
    elif missing == "mailbox":
        shop.root.rename(shop.tmp / "retained-original-mailbox")
    marker = folder / "admitted.json"
    original, probes, changed = os.stat, [], []

    def stat_node(path, *args, **kwargs):
        matched = str(path) == "admitted.json" and kwargs.get("dir_fd") is not None
        if matched:
            probes.append(True)
        answer = original(path, *args, **kwargs)
        # The first probe belongs to runner census, the second to the row's admission classification.
        if matched and len(probes) == 2 and missing.startswith("marker-"):
            marker.rename(shop.tmp / "retained-original-admission.json")
            if missing == "marker-directory":
                marker.mkdir()
            changed.append(True)
        return answer

    args = [] if recipes == "absent" else ["--recipes", str(shop.recipes_path)]
    with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "stat": stat_node})):
        assert jobs.main(["--store", str(shop.workspace.store), *args, "recovery-status"]) == 3
    report = json.loads(capsys.readouterr().out)
    row = next(row for row in report["jobs"] if row["job"] == "pilot/job-1")
    assert row["state"] == "admitted", row
    assert "recipe_bytes_unavailable" not in row["source"]
    assert row["next_action"] == "Recheck the persisted admission with run-open; do not derive again."
    assert [blocker["reason"] for blocker in report["blockers"] if blocker.get("job") == row["job"]] == ["admitted"]
    if missing.startswith("marker-"):
        assert changed == [True]
    if missing != "marker-absent":
        reason = "admission marker unverified" if missing == "marker-directory" else "original mailbox request is unavailable"
        assert row["source"] == {"state": "unavailable", "reason": reason}
    assert not (folder / "result.json").exists() and not (folder / "execution.json").exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_live_legacy_group_text_keeps_historical_bytes(kind_shop, capsys):
    shop = kind_shop
    shop.request_job("job-0", "ok")
    folder = shop.workspace.store / "jobs/pilot/job-0"
    folder.mkdir(parents=True)
    (folder / "claim.json").write_text(json.dumps(job_fixtures.live_claim(jobs, os.getpid(), "pilot/job-0")))
    (folder / "process.json").write_text(json.dumps({"group": "untrusted-group\nsecond-line"}))
    for _ in range(2):
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        expected = {"rows": [{"job": "pilot/job-0", "state": "running",
                              "process_group": "untrusted-group\nsecond-line"}]}
        assert capsys.readouterr().out == json.dumps(expected, sort_keys=True) + "\n"
        assert shop.receipts("job-0") == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_recovery_directory_admission_retains_unknown_custody(kind_shop, capsys):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    (folder / "admitted.json").unlink()
    (folder / "admitted.json").mkdir()
    for _ in range(2):
        assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
        report = json.loads(capsys.readouterr().out)
        row = next(row for row in report["jobs"] if row["job"] == "pilot/job-1")
        assert row["state"] == "unknown_effect", row
        assert row["source"] == {"state": "unavailable", "reason": "admission marker unverified"}
        assert "error" not in row
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        row = job_fixtures.job_row(json.loads(capsys.readouterr().out))
        assert row["reason"] == "execution_custody_unknown" and row["process_alive"] is None
        assert shop.receipts("job-1") == [] and not (folder / "execution.json").exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_failed_admission_revalidation_keeps_fixed_detail(kind_shop, capsys):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    shop.recipes["recipes"]["ok"]["timeout_seconds"] += 1
    shop.save_recipes()
    before = (folder / "admitted.json").read_bytes()
    for _ in range(2):
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        row = job_fixtures.job_row(json.loads(capsys.readouterr().out))
        assert row["reason"] == "execution_custody_unknown"
        assert row["detail"] == "recipes changed after admission"
        assert (folder / "admitted.json").read_bytes() == before
        assert shop.receipts("job-1") == [] and not (folder / "execution.json").exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_result_first_probe_of_vanished_directory_retains_uncertainty(kind_shop):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    ledger = jobs.Store(shop.workspace.store).load()
    message = jobs.Mailbox(shop.root).messages()["job-1"]["message"]
    job = jobs.PlannedJob(shop.workspace.store, ledger.initiative("pilot"), message)
    job.validated_admission()
    saved = shop.tmp / "vanished-result-first-job"
    folder.rename(saved)
    try:
        for _ in range(2):
            assert job.result() is None
            assert job.result_decision() == "unknown"
            assert job.recorded_execution_fence() is None and job.metadata_uncertain
    finally:
        saved.rename(folder)


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("fault", PROCESS_FAULTS)
def test_process_consumers_refuse_untrusted_groups(kind_shop, capsys, fault):
    shop = kind_shop
    host_plan(shop)
    shop.request_job("job-0", "ok")
    store = jobs.Store(shop.workspace.store)
    message = jobs.Mailbox(shop.root).messages()["job-0"]["message"]
    job = jobs.PlannedJob(store.path, store.load().initiative("pilot"), message)
    job.folder.mkdir(parents=True)
    claim = job_fixtures.live_claim(jobs, os.getpid(), job.id)
    job.claim_path.write_text(json.dumps(claim))
    group = {"text": "untrusted-group\nsecond-line", "zero": 0, "negative": -1,
             "bool": True, "float": 1.5}.get(fault, 2147483647)
    if fault == "directory":
        job.process_path.mkdir()
    elif fault == "symlink":
        decoy = shop.tmp / "foreign-process.json"
        decoy.write_text(json.dumps({"step": 1, "group": group}))
        symlink_or_skip(decoy, job.process_path)
    elif fault == "oversized":
        job.process_path.write_bytes(b" " * (jobs.MAX_BYTES + 1))
    else:
        job.process_path.write_text(json.dumps({"step": 1, "group": group}))
    (job.folder / "step-1.log").write_bytes(b"")
    with ExitStack() as active:
        if fault == "unsupported":
            active.enter_context(patch.object(job_fixtures.jobs2_fresh_brief, "_reference_descriptors", lambda: False))
        for _ in range(2):
            assert job.process_group() is None
            assert job.staging_process_group() is None
            assert job.unrecorded_step() == 1
            assert jobs.census_owner(store.path, {"holder": job.holder, "initiative": "pilot"}, job.initiative) is None
            # Both a claim loser and a refusal loser must keep their row shape and opacity.
            assert jobs.taken_execution_row(store, job, None, 0)["process_group"] is None
            assert jobs.refuse(store, job, "owner refusal", 0)["process_group"] is None
            with pytest.raises(ValueError, match="^" + re.escape(PROCESS_REPAIR_ERROR) + "$"):
                jobs.check_settlement_processes(job, {"steps": []})
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            assert json.loads(capsys.readouterr().out)["rows"][0]["process_group"] is None
            assert shop.receipts("job-0") == [] and not job.result_path.exists()
    # A stopped claimant must never turn a malformed group into stopped-process evidence.
    claim["start"] = "0"
    job.claim_path.write_text(json.dumps(claim))
    for _ in range(2):
        if fault == "unsupported":
            # Keep the same unsupported-platform observation for the recovery/resolve routes.
            context = patch.object(job_fixtures.jobs2_fresh_brief, "_reference_descriptors", lambda: False)
        else:
            context = ExitStack()
        with context:
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            row = json.loads(capsys.readouterr().out)["rows"][0]
            assert row["process_group"] is None and row["process_alive"] is None
            assert PROCESS_REPAIR_ACTION in row["next_action"]
            assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
            row = next(row for row in report["jobs"] if row["job"] == job.id)
            assert row["process_group"] is None and row["process_alive"] is None
            assert jobs.main(shop.argv("resolve", "--job", job.id, "--reason", "owner checked")[3:]) == 2
            assert json.loads(capsys.readouterr().out) == {"error": PROCESS_REPAIR_ERROR}
        assert shop.receipts("job-0") == [] and not job.result_path.exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("replacement", ["absent", "valid"])
def test_process_refusal_survives_concurrent_replacement(kind_shop, replacement):
    shop = kind_shop
    host_plan(shop)
    shop.request_job("job-0", "ok")
    store = jobs.Store(shop.workspace.store)
    message = jobs.Mailbox(shop.root).messages()["job-0"]["message"]
    job = jobs.PlannedJob(store.path, store.load().initiative("pilot"), message)
    job.folder.mkdir(parents=True)
    job.claim_path.write_text(json.dumps(job_fixtures.live_claim(jobs, os.getpid(), job.id)))
    job.process_path.write_text(json.dumps({"step": 1, "group": "untrusted-group\nsecond-line"}))
    original = jobs.PlannedJob.process_record
    changed = []

    def record(current):
        answer = original(current)
        if not changed:
            current.process_path.unlink()
            if replacement == "valid":
                current.process_path.write_text(json.dumps({"step": 1, "group": 2147483647}))
            changed.append(True)
        return answer

    with patch.object(jobs.PlannedJob, "process_record", record):
        for _ in range(2):
            with pytest.raises(ValueError, match="^" + re.escape(PROCESS_REPAIR_ERROR) + "$"):
                jobs.check_settlement_processes(job, {"steps": []})
    assert changed == [True] and shop.receipts("job-0") == []
    # A new attempt can use independently verified repaired evidence.
    repaired = jobs.PlannedJob(store.path, job.initiative, message)
    jobs.check_settlement_processes(repaired, {"steps": []})


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("surface", ["settlement", "resolve", "run-open"])
def test_final_process_probe_refusal_cannot_be_bypassed(kind_shop, capsys, surface):
    shop = kind_shop
    host_plan(shop)
    shop.request_job("job-0", "ok")
    store = jobs.Store(shop.workspace.store)
    message = jobs.Mailbox(shop.root).messages()["job-0"]["message"]
    job = jobs.PlannedJob(store.path, store.load().initiative("pilot"), message)
    job.folder.mkdir(parents=True)
    claim = job_fixtures.live_claim(jobs, os.getpid(), job.id)
    claim["start"] = "0"
    job.claim_path.write_text(json.dumps(claim))
    (job.folder / "step-1.log").write_bytes(b"")
    original = jobs.PlannedJob.process_record
    probes = []

    def record(current):
        answer = original(current)
        probes.append(True)
        current.process_path.write_text(json.dumps({"step": 1, "group": 2147483647}))
        return answer

    for _ in range(2):
        probes.clear()
        job = jobs.PlannedJob(store.path, job.initiative, message)
        job.process_path.write_text(json.dumps({"step": 1, "group": "untrusted-group\nsecond-line"}))
        with patch.object(jobs.PlannedJob, "process_record", record):
            if surface == "settlement":
                with pytest.raises(ValueError, match="^" + re.escape(PROCESS_REPAIR_ERROR) + "$"):
                    jobs.check_settlement_processes(job, {"steps": [], "process_stopped_confirmed": True})
            else:
                flags = ("--job", job.id, "--reason", "owner checked", "--process-stopped") if surface == "resolve" else ()
                assert jobs.main(shop.argv(surface, *flags, census=[], lock_wait=0)[3:]) == (2 if surface == "resolve" else 3)
                report = json.loads(capsys.readouterr().out)
                if surface == "resolve":
                    assert report == {"error": PROCESS_REPAIR_ERROR}
                else:
                    row = report["rows"][0]
                    assert row["reason"] == "execution_custody_unknown" and row["process_alive"] is None
                    assert PROCESS_REPAIR_ACTION in row["next_action"]
        assert probes == [True]
        assert not job.result_path.exists() and shop.receipts("job-0") == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("failure", ["open", "fstat", "read", "close"])
def test_process_descriptor_failures_close_every_owned_handle(kind_shop, failure):
    shop = kind_shop
    host_plan(shop)
    shop.request_job("job-0", "ok")
    store = jobs.Store(shop.workspace.store)
    message = jobs.Mailbox(shop.root).messages()["job-0"]["message"]
    job = jobs.PlannedJob(store.path, store.load().initiative("pilot"), message)
    job.folder.mkdir(parents=True)
    job.process_path.write_text(json.dumps({"step": 1, "group": 2147483647}))
    owned, process_handles, refused = set(), set(), []
    original_open, original_close, original_fstat = os.open, os.close, os.fstat

    def fail():
        refused.append(failure)
        raise OSError(errno.EIO, "untrusted-group\nsecond-line")

    def open_node(path, *args, **kwargs):
        process_node = str(path) == "process.json" and kwargs.get("dir_fd") is not None
        if process_node and failure == "open":
            fail()
        descriptor = original_open(path, *args, **kwargs)
        owned.add(descriptor)
        if process_node:
            process_handles.add(descriptor)
        return descriptor

    def fstat(descriptor):
        if descriptor in process_handles and failure == "fstat":
            fail()
        return original_fstat(descriptor)

    def read(descriptor, amount):
        if descriptor in process_handles and failure == "read":
            fail()
        return os.read(descriptor, amount)

    def close(descriptor):
        process_node = descriptor in process_handles
        original_close(descriptor)
        owned.remove(descriptor)
        process_handles.discard(descriptor)
        with pytest.raises(OSError) as gone:
            original_fstat(descriptor)
        assert gone.value.errno == errno.EBADF
        if process_node and failure == "close":
            fail()

    local_os = SimpleNamespace(**{**vars(os), "open": open_node, "close": close, "read": read, "fstat": fstat})
    with patch.object(job_fixtures.jobs2_fresh_brief, "os", local_os):
        for _ in range(2):
            assert job.process_group() is None and job.process_unverified
            assert owned == process_handles == set()
    assert refused == [failure, failure]


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("change", ["packet-hash", "fields", "derivation-hash", "derivation-duplicate", "admission-duplicate"])
def test_admission_content_failure_detail_is_fixed_and_non_echoing(kind_shop, capsys, change):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    marker = folder / "admitted.json"
    reference = json.loads(marker.read_bytes())
    hostile = "untrusted-group\nsecond-line"
    duplicate = b'{"a":1,"untrusted-group\\nsecond-line":1,"untrusted-group\\nsecond-line":2}'
    if change == "derivation-duplicate":
        (folder / "derivation.json").write_bytes(duplicate)
    elif change == "fields":
        reference[hostile] = hostile
    elif change != "admission-duplicate":
        reference["packet_sha256" if change == "packet-hash" else "derivation_sha256"] = hostile
    marker.write_bytes(duplicate if change == "admission-duplicate" else json.dumps(reference).encode())
    before = marker.read_bytes()
    for _ in range(2):
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        output = capsys.readouterr().out
        row = job_fixtures.job_row(json.loads(output))
        if change == "admission-duplicate":
            # As with the retained malformed-marker test, parsing establishes no admission content.
            assert "detail" not in row
        else:
            assert row["detail"] == "persisted admission revalidation failed"
        assert row["reason"] == "execution_custody_unknown"
        assert "untrusted-group" not in output and "second-line" not in output
        assert marker.read_bytes() == before
        assert shop.receipts("job-1") == [] and not (folder / "execution.json").exists()
        assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
        output = capsys.readouterr().out
        row = next(row for row in json.loads(output)["jobs"] if row["job"] == "pilot/job-1")
        assert row["state"] == "evidence_error"
        assert row["error"] == "persisted admission revalidation failed"
        assert "untrusted-group" not in output and "second-line" not in output


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("shape", ["duplicate", "utf8", "syntax", "depth", "array", "scalar"])
@pytest.mark.parametrize("name", ["admitted.json", "derivation.json"])
def test_planned_admission_decode_failures_have_one_fixed_message(kind_shop, capsys, name, shape):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    store = jobs.Store(shop.workspace.store)
    message = jobs.Mailbox(shop.root).messages()["job-1"]["message"]
    job = jobs.PlannedJob(store.path, store.load().initiative("pilot"), message)
    raw = (folder / "packet.md").read_bytes()
    marker = folder / "admitted.json"
    reference = json.loads(marker.read_bytes())
    recipes = reference["recipes_sha256"]
    poison = {"duplicate": b'{"untrusted-group\\nsecond-line":1,"untrusted-group\\nsecond-line":2}',
              "utf8": b"\xff", "syntax": b"{", "depth": b"[" * 2000 + b"]" * 2000,
              "array": b"[]", "scalar": b"null"}[shape]
    (folder / name).write_bytes(poison)
    if name == "derivation.json":
        # The test owner binds these bytes, exercising parsing only after successful hash verification.
        reference["derivation_sha256"] = hashlib.sha256(poison).hexdigest()
        marker.write_text(json.dumps(reference))
    for _ in range(2):
        with pytest.raises(ValueError, match="^persisted admission revalidation failed$"):
            jobs.admitted_derivation(job, raw, recipes)
        assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
        output = capsys.readouterr().out
        row = next(row for row in json.loads(output)["jobs"] if row["job"] == "pilot/job-1")
        assert row["error"] == "persisted admission revalidation failed"
        assert "untrusted-group" not in output and "second-line" not in output
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        output = capsys.readouterr().out
        row = job_fixtures.job_row(json.loads(output))
        assert row["reason"] == "execution_custody_unknown"
        if name == "derivation.json":
            assert row["detail"] == "persisted admission revalidation failed"
        else:
            assert "detail" not in row
        assert "untrusted-group" not in output and "second-line" not in output
        assert shop.receipts("job-1") == [] and not (folder / "execution.json").exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_recipe_revalidation_precedes_unbound_derivation_parse(kind_shop, capsys):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    (folder / "derivation.json").write_bytes(b'{"untrusted-group\\nsecond-line":1,"untrusted-group\\nsecond-line":2}')
    shop.recipes["recipes"]["ok"]["timeout_seconds"] += 1
    shop.save_recipes()
    for _ in range(2):
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        output = capsys.readouterr().out
        row = job_fixtures.job_row(json.loads(output))
        assert row["detail"] == "recipes changed after admission"
        assert "untrusted-group" not in output and "second-line" not in output


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_unbound_derivation_bytes_never_reach_the_parser(kind_shop):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    store = jobs.Store(shop.workspace.store)
    message = jobs.Mailbox(shop.root).messages()["job-1"]["message"]
    job = jobs.PlannedJob(store.path, store.load().initiative("pilot"), message)
    raw = (folder / "packet.md").read_bytes()
    recipes = json.loads((folder / "admitted.json").read_bytes())["recipes_sha256"]
    poison = '{"untrusted-group\\nsecond-line":1,"untrusted-group\\nsecond-line":2}'
    (folder / "derivation.json").write_text(poison)
    original = jobs.strict_json

    def parse(value):
        if value == poison:
            pytest.fail("unbound derivation reached the parser")
        return original(value)

    with patch.object(jobs, "strict_json", parse):
        for _ in range(2):
            with pytest.raises(ValueError, match="^persisted admission revalidation failed$"):
                jobs.admitted_derivation(job, raw, recipes)
            assert job.admission_detail == "persisted admission revalidation failed"


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_captured_derivation_is_bound_across_concurrent_replacement(kind_shop, capsys):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    derivation = folder / "derivation.json"
    original_bytes = derivation.read_bytes()
    original_read, original_parse = job_fixtures.jobs2_fresh_brief._read_reference, jobs.strict_json
    poison = b'{"untrusted-group\\nsecond-line":1,"untrusted-group\\nsecond-line":2}'
    changed = []

    def read_reference(path, **kwargs):
        answer = original_read(path, **kwargs)
        if path == derivation and not changed:
            assert answer[1] == original_bytes
            derivation.write_bytes(poison)
            changed.append(True)
        return answer

    def parse(value):
        if value == poison.decode():
            pytest.fail("concurrently replaced unbound bytes reached the parser")
        return original_parse(value)

    with patch.object(job_fixtures.jobs2_fresh_brief, "_read_reference", read_reference):
        with patch.object(jobs, "strict_json", parse):
            for _ in range(2):
                assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
                output = capsys.readouterr().out
                row = job_fixtures.job_row(json.loads(output))
                assert row["reason"] == "execution_custody_unknown", row
                assert row["detail"] == "persisted admission revalidation failed"
                assert "untrusted-group" not in output and "second-line" not in output
                assert shop.receipts("job-1") == [] and not (folder / "execution.json").exists()
    assert changed == [True]


def install_process_fault(shop, process, fault):
    if process.is_symlink() or process.is_file():
        process.unlink()
    elif process.is_dir():
        process.rmdir()
    group = {"text": "untrusted-group\nsecond-line", "zero": 0, "negative": -1,
             "bool": True, "float": 1.5}.get(fault, 2147483647)
    if fault == "directory":
        process.mkdir()
    elif fault == "symlink":
        decoy = shop.tmp / (process.parent.name + "-foreign-process.json")
        decoy.write_text(json.dumps({"step": 1, "group": group}))
        symlink_or_skip(decoy, process)
    elif fault == "oversized":
        process.write_bytes(b" " * (jobs.MAX_BYTES + 1))
    else:
        process.write_text(json.dumps({"step": 1, "group": group}))


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_failed_mailbox_binding_cannot_fall_back_to_saved_packet(kind_shop, capsys):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    packet, marker = folder / "packet.md", folder / "admitted.json"
    changed = packet.read_bytes() + b"\n"
    packet.write_bytes(changed)
    reference = json.loads(marker.read_bytes())
    reference["packet_sha256"] = hashlib.sha256(changed).hexdigest()
    marker.write_text(json.dumps(reference))
    reservation = shop.workspace.ask("pilot", "writer", "job:pilot/job-1")
    assert shop.workspace.grant("writer")["request_id"] == reservation
    before = {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()}
    for _ in range(2):
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        row = job_fixtures.job_row(json.loads(capsys.readouterr().out))
        assert row["reason"] == "execution_custody_unknown", row
        assert row["detail"] == "persisted admission revalidation failed"
        assert not (folder / "execution.json").exists() and not (folder / "result.json").exists()
        assert shop.receipts("job-1") == []
        assert job_fixtures.ledger_rows(shop, holder="job:pilot/job-1")[reservation]["state"] == "granted"
        assert {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()} == before


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("first", ["null", "live"])
def test_settlement_uses_one_process_snapshot(kind_shop, first):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    store = jobs.Store(shop.workspace.store)
    message = jobs.Mailbox(shop.root).messages()["job-1"]["message"]
    initiative = store.load().initiative("pilot")
    process = folder / "process.json"
    jobs.write_result(jobs.PlannedJob(store.path, initiative, message), "refused", None, reason="fixture terminal refusal")
    original, captured = jobs.PlannedJob.process_record, []
    group = os.getpgrp()

    def record(job):
        answer = original(job)
        captured.append(True)
        process.write_text(json.dumps({"step": 1, "group": group if first == "null" else None}))
        return answer

    for _ in range(2):
        captured.clear()
        process.write_text(json.dumps({"step": 1, "group": None if first == "null" else group}))
        with patch.object(jobs.PlannedJob, "process_record", record):
            expected = ("job has an unrecorded process effect: pilot/job-1" if first == "null" else
                        "job process group is still running: " + str(group))
            with pytest.raises(ValueError, match="^" + re.escape(expected) + "$"):
                jobs.settle(store, jobs.PlannedJob(store.path, initiative, message), 0)
        assert captured == [True]
        assert shop.receipts("job-1") == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_process_disappearance_during_acquisition_is_not_initial_absence(kind_shop, capsys):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    process = folder / "process.json"
    saved = process.read_bytes()
    original_open, changed = os.open, []

    def open_node(path, *args, **kwargs):
        if str(path) == "process.json" and kwargs.get("dir_fd") is not None:
            process.unlink()
            changed.append(True)
        return original_open(path, *args, **kwargs)

    for _ in range(2):
        changed.clear()
        process.write_bytes(saved)
        with patch.object(job_fixtures.jobs2_fresh_brief, "os", SimpleNamespace(**{**vars(os), "open": open_node})):
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            row = job_fixtures.job_row(json.loads(capsys.readouterr().out))
            assert row["state"] == "settle_pending" and row["error"] == PROCESS_REPAIR_ERROR, row
        assert changed == [True]
        assert shop.receipts("job-1") == [] and not (folder / "execution.json").exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("value", ["untrusted-group\nsecond-line", "A" * 64, "b" * 64], ids=["malformed", "uppercase", "mismatch"])
def test_recovery_recipe_digest_comes_from_actual_bytes(kind_shop, capsys, value):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    marker = folder / "admitted.json"
    reference = json.loads(marker.read_bytes())
    reference["recipes_sha256"] = value
    marker.write_text(json.dumps(reference))
    for _ in range(2):
        assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
        output = capsys.readouterr().out
        row = next(row for row in json.loads(output)["jobs"] if row["job"] == "pilot/job-1")
        expected = "recipes changed after admission" if value == "b" * 64 else "persisted admission revalidation failed"
        assert row["state"] == "evidence_error", row
        assert row["error"] == row["detail"] == expected
        assert row["source"]["state"] == "unavailable"
        assert "untrusted-group" not in output and "second-line" not in output
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        row = job_fixtures.job_row(json.loads(capsys.readouterr().out))
        assert row["detail"] == expected and row["reason"] == "execution_custody_unknown"
        assert shop.receipts("job-1") == [] and not (folder / "execution.json").exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_planned_recovery_requires_recipe_bytes_without_changing_legacy(kind_shop, capsys):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    argv = shop.argv("recovery-status", census=[], lock_wait=0)[3:]
    position = argv.index("--recipes")
    del argv[position:position + 2]
    for _ in range(2):
        assert jobs.main(argv) == 3
        report = json.loads(capsys.readouterr().out)
        row = next(row for row in report["jobs"] if row["job"] == "pilot/job-1")
        assert row["state"] == "admission_unverified"
        assert row["source"] == {"state": "unavailable", "reason": "planned recipe bytes unavailable",
                                 "recipe_bytes_unavailable": True}
        assert row["next_action"] == ADMISSION_UNVERIFIED_ACTION
        assert "error" not in row and "detail" not in row
    assert shop.receipts("job-1") == [] and not (folder / "execution.json").exists()
    plan = shop.base / "host-plan.json"
    saved_plan = plan.read_bytes()
    plan.unlink()
    try:
        assert jobs.main(argv) == 3
        report = json.loads(capsys.readouterr().out)
        row = next(row for row in report["jobs"] if row["job"] == "pilot/job-1")
        assert row["state"] == "admitted" and row["source"]["state"] == "match"
    finally:
        plan.write_bytes(saved_plan)


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("fault", ["missing", "oversized", "symlink", "unsupported", "leaf-swap", "ancestor-swap"])
def test_recovery_recipe_acquisition_is_bounded_and_anchored(kind_shop, capsys, fault):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    store = jobs.Store(shop.workspace.store)
    mailbox = jobs.Mailbox(shop.root)
    message = mailbox.messages()["job-1"]["message"]
    job = jobs.PlannedJob(store.path, store.load().initiative("pilot"), message)
    root = shop.tmp / "recipe-root"
    root.mkdir()
    recipe = root / "recipes.json"
    recipe.write_bytes(shop.recipes_path.read_bytes())
    saved, decoy = shop.tmp / "retained-recipe-node", shop.tmp / "foreign-recipe-node"
    if fault == "ancestor-swap":
        decoy.mkdir()
        (decoy / recipe.name).write_bytes(recipe.read_bytes())
    else:
        decoy.write_bytes(recipe.read_bytes())
    if fault == "missing":
        recipe.unlink()
    elif fault == "oversized":
        recipe.write_bytes(b" " * (jobs.MAX_BYTES + 1))
    elif fault == "symlink":
        recipe.unlink()
        symlink_or_skip(decoy, recipe)
    original_open, changed = os.open, []

    def open_node(path, *args, **kwargs):
        if str(path) == recipe.name and kwargs.get("dir_fd") is not None and not changed:
            node = root if fault == "ancestor-swap" else recipe
            if fault in ("leaf-swap", "ancestor-swap"):
                node.rename(saved)
                symlink_or_skip(decoy, node, target_is_directory=fault == "ancestor-swap")
            changed.append(True)
        return original_open(path, *args, **kwargs)

    for _ in range(2):
        changed.clear()
        try:
            with ExitStack() as active:
                active.enter_context(patch.object(job_fixtures.jobs2_fresh_brief, "os",
                                                 SimpleNamespace(**{**vars(os), "open": open_node})))
                if fault == "unsupported":
                    active.enter_context(patch.object(job_fixtures.jobs2_fresh_brief, "_reference_descriptors", lambda: False))
                unavailable = {"state": "unavailable", "reason": "planned recipe bytes unavailable",
                               "recipe_bytes_unavailable": True}
                assert jobs.recovery_source(job, mailbox, None, recipe) == unavailable
                if fault != "unsupported":
                    argv = shop.argv("recovery-status", census=[], lock_wait=0)[3:]
                    argv[argv.index("--recipes") + 1] = str(recipe)
                    assert jobs.main(argv) == 3
                    row = next(row for row in json.loads(capsys.readouterr().out)["jobs"] if row["job"] == "pilot/job-1")
                    assert row["state"] == "admission_unverified" and row["source"] == unavailable
                    assert row["next_action"] == ADMISSION_UNVERIFIED_ACTION
                    assert "error" not in row and "detail" not in row
                assert not job.admission_validated and job.admission_detail is None
            if fault in ("leaf-swap", "ancestor-swap"):
                assert changed == [True]
            else:
                assert changed == []
        finally:
            node = root if fault == "ancestor-swap" else recipe
            if fault in ("leaf-swap", "ancestor-swap") and node.is_symlink():
                node.unlink()
            if saved.exists():
                saved.rename(node)
    assert shop.receipts("job-1") == [] and not (folder / "execution.json").exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("fault", PROCESS_FAULTS)
def test_admitted_and_result_consumers_refuse_hostile_groups(kind_shop, capsys, fault):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    store = jobs.Store(shop.workspace.store)
    message = jobs.Mailbox(shop.root).messages()["job-1"]["message"]
    initiative = store.load().initiative("pilot")
    raw = (folder / "packet.md").read_bytes()
    recipes = json.loads((folder / "admitted.json").read_bytes())["recipes_sha256"]
    install_process_fault(shop, folder / "process.json", fault)
    with ExitStack() as active:
        if fault == "unsupported":
            active.enter_context(patch.object(job_fixtures.jobs2_fresh_brief, "_reference_descriptors", lambda: False))
        for _ in range(2):
            job = jobs.PlannedJob(store.path, initiative, message)
            expected = ("admission metadata requires directory descriptor support" if fault == "unsupported"
                        else PROCESS_REPAIR_ERROR)
            with pytest.raises(ValueError, match="^" + re.escape(expected) + "$"):
                job.take_execution(raw, recipes)
            assert not (folder / "execution.json").exists()
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            output = capsys.readouterr().out
            row = job_fixtures.job_row(json.loads(output))
            assert row["state"] == "settle_pending" and row["error"] == PROCESS_REPAIR_ERROR
            assert "untrusted-group" not in output and "second-line" not in output
            assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
            output = capsys.readouterr().out
            row = next(row for row in json.loads(output)["jobs"] if row["job"] == "pilot/job-1")
            assert row["state"] == "evidence_error" and row["error"] == PROCESS_REPAIR_ERROR
            assert row["process_group"] is None and row["process_alive"] is None
            assert "untrusted-group" not in output and "second-line" not in output
        # A syntactically valid terminal result cannot release custody with malformed process evidence.
        job = jobs.PlannedJob(store.path, initiative, message)
        jobs.write_result(job, "refused", None, reason="fixture terminal refusal", process_stopped_confirmed=True)
        before = (folder / "result.json").read_bytes()
        for _ in range(2):
            with pytest.raises(ValueError, match="^" + re.escape(PROCESS_REPAIR_ERROR) + "$"):
                jobs.settle(store, jobs.PlannedJob(store.path, initiative, message), 0)
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            row = job_fixtures.job_row(json.loads(capsys.readouterr().out))
            assert row["state"] == "settle_pending" and row["error"] == PROCESS_REPAIR_ERROR
            assert (folder / "result.json").read_bytes() == before
        assert shop.receipts("job-1") == []
        # A closed request with retained capacity reaches finish_closed_jobs' separate settlement entry.
        reservation = shop.workspace.ask("pilot", "writer", "job:pilot/job-1")
        assert shop.workspace.grant("writer")["request_id"] == reservation
        shop.publish("job-1-owner-closed", "job_receipt", "Owner closed this request.", sender="pilot/root",
                     to="pilot/orchestrator", in_reply_to="job-1", receipt={"state": "refused", "reason": "owner closed"})
        receipts = shop.receipts("job-1")
        for _ in range(2):
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            row = job_fixtures.job_row(json.loads(capsys.readouterr().out))
            assert row["state"] == "settle_pending" and row["error"] == PROCESS_REPAIR_ERROR
            assert shop.receipts("job-1") == receipts
            assert job_fixtures.ledger_rows(shop, holder="job:pilot/job-1")[reservation]["state"] == "granted"
            assert (folder / "result.json").read_bytes() == before


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("fault", PROCESS_FAULTS)
def test_derivation_stopped_refusal_row_is_opaque_and_actionable(kind_shop, capsys, fault):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    # Keep the admitted predecessor from executing before the separate staging request is inspected.
    install_process_fault(shop, folder / "process.json", "text" if fault == "unsupported" else fault)
    shop.request_job("job-2", "commit-exact", raw=jobs.packet_text((folder / "packet.md").read_bytes()))
    original = jobs.record_process
    injected = []

    def record_process(job, record, suffix):
        if job.id != "pilot/job-2":
            return original(job, record, suffix)
        # The process-record filesystem publication boundary fails after hostile metadata appears.
        install_process_fault(shop, job.process_path, fault)
        if fault == "unsupported":
            active.enter_context(patch.object(job_fixtures.jobs2_fresh_brief, "_reference_descriptors", lambda: False))
        injected.append(True)
        raise OSError(errno.EIO, "process metadata publication unavailable")

    with ExitStack() as active:
        active.enter_context(patch.object(jobs, "record_process", record_process))
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        output = capsys.readouterr().out
        row = job_fixtures.job_row(json.loads(output), "job-2")
        assert injected == [True], row
        assert row["state"] == "abandoned" and row["process_group"] is None and row["process_alive"] is None
        assert "staging stop is unconfirmed" in row["reason"] and PROCESS_REPAIR_ACTION in row["reason"]
        assert "untrusted-group" not in output and "second-line" not in output
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        output = capsys.readouterr().out
        row = job_fixtures.job_row(json.loads(output), "job-2")
        assert row["process_group"] is None
        assert "untrusted-group" not in output and "second-line" not in output
    target = shop.workspace.store / "jobs/pilot/job-2"
    assert not (target / "result.json").exists() and shop.receipts("job-2") == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("name", ["admitted.json", "packet.md", "derivation.json"])
def test_planned_admission_size_limit_precedes_open_and_parse(kind_shop, name):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    store = jobs.Store(shop.workspace.store)
    message = jobs.Mailbox(shop.root).messages()["job-1"]["message"]
    job = jobs.PlannedJob(store.path, store.load().initiative("pilot"), message)
    raw = (folder / "packet.md").read_bytes()
    recipes = json.loads((folder / "admitted.json").read_bytes())["recipes_sha256"]
    (folder / name).write_bytes(b" " * (jobs.MAX_BYTES + 1))
    original_open = os.open
    opened = []

    def open_node(path, *args, **kwargs):
        if str(path) == name and kwargs.get("dir_fd") is not None:
            opened.append(True)
        return original_open(path, *args, **kwargs)

    def parse(_):
        pytest.fail("oversized admission metadata reached the parser")

    with patch.object(jobs, "strict_json", parse):
        with patch.object(job_fixtures.jobs2_fresh_brief, "os", SimpleNamespace(**{**vars(os), "open": open_node})):
            for _ in range(2):
                with pytest.raises(ValueError, match="^input exceeds 262144 bytes$"):
                    jobs.admitted_derivation(job, raw, recipes)
                assert job.admission_detail is None and not job.admission_validated
    assert opened == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_planned_recovery_does_not_fall_back_to_path_only_marker_reads(kind_shop, capsys):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    original = jobs.read_json

    def read_json(path):
        if path == folder / "admitted.json":
            raise PermissionError(errno.EACCES, "path-only metadata access unavailable")
        return original(path)

    with patch.object(jobs, "read_json", read_json):
        for _ in range(2):
            assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
            row = next(row for row in report["jobs"] if row["job"] == "pilot/job-1")
            assert row["state"] == "admitted" and row["source"]["state"] == "match"
            assert "error" not in row


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_planned_admission_unsupported_descriptors_refuses_before_io(kind_shop):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    store = jobs.Store(shop.workspace.store)
    message = jobs.Mailbox(shop.root).messages()["job-1"]["message"]
    job = jobs.PlannedJob(store.path, store.load().initiative("pilot"), message)
    raw = (folder / "packet.md").read_bytes()
    recipes = json.loads((folder / "admitted.json").read_bytes())["recipes_sha256"]

    def read_reference(*args, **kwargs):
        pytest.fail("unsupported descriptor acquisition reached metadata IO")

    with patch.object(job_fixtures.jobs2_fresh_brief, "_reference_descriptors", lambda: False):
        with patch.object(job_fixtures.jobs2_fresh_brief, "_read_reference", read_reference):
            for _ in range(2):
                with pytest.raises(ValueError, match="^admission metadata requires directory descriptor support$"):
                    jobs.admitted_derivation(job, raw, recipes)
                assert job.admission_detail is None and not job.admission_validated


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("component", ["leaf", "ancestor"])
def test_planned_admission_rejects_concurrent_node_replacement(kind_shop, capsys, component):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    marker = folder / "admitted.json"
    node = marker if component == "leaf" else folder
    saved = shop.tmp / "retained-admission-node"
    decoy = shop.tmp / "foreign-admission-node"
    if component == "ancestor":
        decoy.mkdir()
        (decoy / "admitted.json").write_bytes(b"{}")
    else:
        decoy.write_bytes(b"{}")
    original_open = os.open
    changed = []

    def open_node(path, *args, **kwargs):
        if str(path) == "admitted.json" and kwargs.get("dir_fd") is not None and not changed:
            node.rename(saved)
            symlink_or_skip(decoy, node, target_is_directory=component == "ancestor")
            changed.append(True)
        return original_open(path, *args, **kwargs)

    for _ in range(2):
        changed.clear()
        try:
            local_os = SimpleNamespace(**{**vars(os), "open": open_node})
            with patch.object(job_fixtures.jobs2_fresh_brief, "os", local_os):
                assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
                row = job_fixtures.job_row(json.loads(capsys.readouterr().out))
            assert changed == [True]
            assert row["reason"] == "execution_custody_unknown" and row["process_alive"] is None
            assert "detail" not in row
            assert shop.receipts("job-1") == []
        finally:
            if node.is_symlink():
                node.unlink()
            if saved.exists():
                saved.rename(node)
        assert not (folder / "execution.json").exists() and not (folder / "result.json").exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("first", ["regular", "directory"])
@pytest.mark.parametrize("second", ["absent", "descriptor-refusal"])
def test_first_result_snapshot_blocks_derived_readmission(kind_shop, capsys, first, second):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    result = folder / "result.json"
    if first == "regular":
        result.write_bytes(b"{}")
    else:
        result.mkdir()
    before = {name: (folder / name).read_bytes()
              for name in ("admitted.json", "claim.json", "packet.md", "derivation.json")}
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()
    original = jobs.PlannedJob.observe_existing_fence
    captured = []

    def existing(job):
        nodes = original(job)
        if job.id == "pilot/job-1":
            assert nodes["result"] == ("regular" if first == "regular" else "other")
            captured.append(job)
            if first == "regular":
                result.unlink()
            else:
                result.rmdir()
            if second == "descriptor-refusal":
                active.enter_context(patch.object(job_fixtures.jobs2_fresh_brief,
                                                 "require_secure_publication", unavailable))
        return nodes

    def unavailable():
        raise ValueError("secure brief publication requires directory descriptor support")

    # Recreate the race on retry: neither pass may re-admit or execute the job.
    for attempt in range(2):
        if attempt:
            if first == "regular":
                result.write_bytes(b"{}")
            else:
                result.mkdir()
        with ExitStack() as active:
            active.enter_context(patch.object(jobs.PlannedJob, "observe_existing_fence", existing))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
        row = job_fixtures.job_row(report)
        assert row["state"] == "settle_pending", report
        if second == "absent":
            assert row["error"] == "job has no validated terminal result"
        else:
            assert row["error"] == "secure brief publication requires directory descriptor support"
        if first == "regular":
            assert row["next_action"] == job_fixtures.JOBS2_OBSERVED_RESULT_ACTION
        assert captured[-1].settlement_attempted and not captured[-1].execution_owned
        assert captured[-1].recorded_execution_fence() is not True
        assert captured[-1].result_observed is (first == "regular")
        assert not (folder / "execution.json").exists()
        assert not result.exists() and shop.receipts("job-1") == []
        assert {name: (folder / name).read_bytes() for name in before} == before
        assert shop.head() == head and (shop.checkout / ".git/index").read_bytes() == index


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("shape", ["symlink", "dangling", "directory", "probe-refusal"])
@pytest.mark.parametrize("live", [False, True])
@pytest.mark.parametrize("validated_before_swap", [False, True])
def test_unverified_admission_never_promotes_staging_claim(kind_shop, capsys, shape, live, validated_before_swap):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    marker = folder / "admitted.json"
    saved = shop.tmp / "retained-admission.json"
    saved.write_bytes(marker.read_bytes())
    marker.unlink()
    if shape == "directory":
        marker.mkdir()
    elif shape == "probe-refusal":
        marker.write_bytes(saved.read_bytes())
    else:
        symlink_or_skip(saved if shape == "symlink" else shop.tmp / "missing-admission", marker)
    if live:
        (folder / "claim.json").write_text(json.dumps(job_fixtures.live_claim(jobs, os.getpid(), "pilot/job-1")))
    claim = (folder / "claim.json").read_bytes()
    group = json.loads((folder / "process.json").read_bytes())["group"]
    original_stat = os.stat
    refused, captured = [], []
    original_visit = jobs.visit_existing

    def stat_node(path, *args, **kwargs):
        if str(path) == "admitted.json" and kwargs.get("dir_fd") is not None:
            refused.append(True)
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), "admitted.json")
        return original_stat(path, *args, **kwargs)

    def visit(store, job, wait):
        if job.id == "pilot/job-1" and validated_before_swap:
            job.validated_admission()
        row = original_visit(store, job, wait)
        if job.id == "pilot/job-1":
            captured.append(job)
        return row

    with patch.object(jobs, "visit_existing", visit):
        with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "stat": stat_node if shape == "probe-refusal" else original_stat})):
            for _ in range(2):
                assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
                report = json.loads(capsys.readouterr().out)
                if live:
                    assert report == {"rows": [{"job": "pilot/job-1", "state": "running", "process_group": group}]}
                else:
                    expected = job_fixtures.jobs2_2m_unknown_report("job-1", job_fixtures.JOBS2_UNVERIFIED_ACTION)
                    expected["rows"][0]["process_group"] = group
                    assert report == expected
                assert captured[-1].recorded_execution_fence() is None
                assert not captured[-1].settlement_attempted and not captured[-1].execution_owned
                assert shop.receipts("job-1") == [] and not (folder / "result.json").exists()
                assert not (folder / "execution.json").exists()
                assert (folder / "claim.json").read_bytes() == claim
    if shape == "probe-refusal":
        assert refused


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("live", [False, True])
def test_unverified_admission_does_not_echo_malformed_process_groups(kind_shop, capsys, live):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    (folder / "admitted.json").unlink()
    (folder / "admitted.json").mkdir()
    if live:
        (folder / "claim.json").write_text(json.dumps(job_fixtures.live_claim(jobs, os.getpid(), "pilot/job-1")))
    process = folder / "process.json"
    record = json.loads(process.read_bytes())
    expected = ({"rows": [{"job": "pilot/job-1", "state": "running", "process_group": None}]} if live else
                job_fixtures.jobs2_2m_unknown_report("job-1", job_fixtures.JOBS2_UNVERIFIED_ACTION))
    for group in ("untrusted-group\nsecond-line", {"untrusted": "group"}, ["untrusted"], True, 0, -1):
        process.write_text(json.dumps({**record, "group": group}))
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        assert json.loads(capsys.readouterr().out) == expected
        assert shop.receipts("job-1") == [] and not (folder / "execution.json").exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("live", [False, True])
@pytest.mark.parametrize("fault", ["unsupported", "oversized", "leaf-swap", "ancestor-swap"])
def test_staging_group_read_refuses_unverified_paths(kind_shop, capsys, live, fault):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    (folder / "admitted.json").unlink()
    (folder / "admitted.json").mkdir()
    if live:
        (folder / "claim.json").write_text(json.dumps(job_fixtures.live_claim(jobs, os.getpid(), "pilot/job-1")))
    process = folder / "process.json"
    saved = shop.tmp / "original-process-node"
    decoy = shop.tmp / "foreign-process-node"
    if fault == "ancestor-swap":
        decoy.mkdir()
        (decoy / "process.json").write_text(json.dumps({"group": 424242}))
    else:
        decoy.write_text(json.dumps({"group": 424242}))
    if fault == "oversized":
        process.write_bytes(b" " * (jobs.MAX_BYTES + 1))
    original_open = os.open
    opened, swapped = [], []

    def open_process(path, *args, **kwargs):
        if str(path) == "process.json" and kwargs.get("dir_fd") is not None:
            opened.append(True)
            if fault in ("leaf-swap", "ancestor-swap") and not swapped:
                (folder if fault == "ancestor-swap" else process).rename(saved)
                symlink_or_skip(decoy, folder if fault == "ancestor-swap" else process,
                                target_is_directory=fault == "ancestor-swap")
                swapped.append(True)
        return original_open(path, *args, **kwargs)

    try:
        with ExitStack() as active:
            active.enter_context(patch.object(job_fixtures.jobs2_fresh_brief, "os",
                                              SimpleNamespace(**{**vars(os), "open": open_process})))
            if fault == "unsupported":
                active.enter_context(patch.object(job_fixtures.jobs2_fresh_brief, "_reference_descriptors", lambda: False))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
        expected = ({"rows": [{"job": "pilot/job-1", "state": "running", "process_group": None}]}
                    if live and fault != "ancestor-swap" else
                    job_fixtures.jobs2_2m_unknown_report("job-1", job_fixtures.JOBS2_UNVERIFIED_ACTION))
        assert report == expected
        assert shop.receipts("job-1") == []
        if fault in ("leaf-swap", "ancestor-swap"):
            assert opened and swapped == [True]
        else:
            assert opened == [], "refuse unsupported or oversized metadata before opening it"
    finally:
        node = folder if fault == "ancestor-swap" else process
        if node.is_symlink():
            node.unlink()
        if saved.exists():
            saved.rename(node)


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("component", ["job", "ancestor"])
@pytest.mark.parametrize("number", [errno.ENOENT, errno.EACCES, errno.EIO])
def test_no_plan_directory_acquisition_preserves_result_os_bytes(kind_shop, capsys, component, number):
    shop = kind_shop
    _, folder, _, _ = job_fixtures.jobs2_2l_result_setup(shop, "existing", "directory", False)
    result = folder / "result.json"
    result.rmdir()
    result.write_bytes(b"{}")
    original = jobs.Job.result
    original_stat, original_open = os.stat, os.open
    injected, active_result = [], []

    def read_result(job):
        active_result.append(True)
        try:
            return original(job)
        finally:
            active_result.pop()

    def stat_node(path, *args, **kwargs):
        if active_result and component == "job" and str(path) == folder.name and kwargs.get("dir_fd") is not None:
            injected.append(True)
            raise OSError(number, os.strerror(number), folder.name)
        return original_stat(path, *args, **kwargs)

    def open_node(path, *args, **kwargs):
        if active_result and component == "ancestor" and str(path) == "jobs" and kwargs.get("dir_fd") is not None:
            injected.append(True)
            raise OSError(number, os.strerror(number), "jobs")
        return original_open(path, *args, **kwargs)

    with patch.object(jobs.Job, "result", read_result):
        with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "stat": stat_node})):
            with patch.object(job_fixtures.jobs2_fresh_brief, "os", SimpleNamespace(**{**vars(os), "open": open_node})):
                for _ in range(2):
                    assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
                    output = capsys.readouterr().out
                    error = str(OSError(number, os.strerror(number), str(result)))
                    expected = {"rows": [{"job": "pilot/job-0", "state": "settle_pending", "error": error}]}
                    assert output.encode() == (json.dumps(expected, sort_keys=True) + "\n").encode()
    assert injected == [True, True] and result.read_bytes() == b"{}"


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("node", ["dangling", "directory"])
def test_no_plan_post_execution_result_gate_keeps_exists_semantics(kind_shop, node):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    (shop.base / "host-plan.json").unlink()
    job = jobs.Job(shop.workspace.store, {"id": "pilot", "mailbox_root": str(shop.root)}, {"message_id": "job-1"})
    recipes_sha256 = json.loads((folder / "admitted.json").read_bytes())["recipes_sha256"]
    original = jobs.Job.publish_execution_claim
    captured = []

    def publish(job, raw):
        original(job, raw)
        captured.append(job)
        job_fixtures.jobs2_2l_result_node(shop, job.result_path, node)

    with patch.object(jobs.Job, "publish_execution_claim", publish):
        assert job.take_execution((folder / "packet.md").read_bytes(), recipes_sha256) is (node == "dangling")
    assert not job.execution_owned and shop.receipts("job-1") == []
    assert len(captured) == 1 and (folder / "execution.json").is_file()


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_nonderived_claim_loser_with_unresolvable_directory_reports_exact_row(kind_shop, capsys):
    shop = kind_shop
    host_plan(shop)
    shop.request_job("job-1", "touch")
    folder = shop.workspace.store / "jobs/pilot/job-1"
    folder.mkdir(parents=True)
    (folder / "claim.json").write_text(json.dumps(job_fixtures.live_claim(jobs, os.getpid(), "pilot/job-1")))
    saved = shop.tmp / "peer-job"
    original_run, original_claim = jobs.run_job, jobs.PlannedJob.claim
    captured = []

    def claim(job, *args, **kwargs):
        answer = original_claim(job, *args, **kwargs)
        assert answer is False and job.recorded_execution_fence() is True
        folder.rename(saved)
        symlink_or_skip(shop.tmp / "missing-peer", folder, target_is_directory=True)
        captured.append(job)
        return answer

    def run(store, job, *args, **kwargs):
        # Publish the peer claim after admission so this pass loses claim(), not visit_existing().
        saved.rename(folder)
        return original_run(store, job, *args, **kwargs)

    folder.rename(saved)
    try:
        with patch.object(jobs, "run_job", run), patch.object(jobs.PlannedJob, "claim", claim):
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
        assert report == job_fixtures.jobs2_2m_unknown_report("job-1", job_fixtures.JOBS2_2M_FENCED_UNKNOWN_ACTION)
        assert len(captured) == 1 and not captured[0].settlement_attempted and not captured[0].execution_owned
        assert not shop.sentinel.exists() and shop.receipts("job-1") == []
    finally:
        if folder.is_symlink():
            folder.unlink()
        if saved.exists():
            saved.rename(folder)


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("failure", ["read", "fstat", "fdopen", "close"])
def test_no_plan_descriptor_errors_without_filename_keep_literal_bytes(kind_shop, capsys, failure):
    shop = kind_shop
    _, folder, _, _ = job_fixtures.jobs2_2l_result_setup(shop, "existing", "directory", False)
    result = folder / "result.json"
    result.rmdir()
    result.write_bytes(b"{}")
    original_open, original_fstat, original_fdopen, original_close = os.open, os.fstat, os.fdopen, os.close
    descriptors, refused, closed = set(), [], []

    def fail():
        refused.append(failure)
        raise OSError(errno.EIO, os.strerror(errno.EIO))

    def open_result(path, *args, **kwargs):
        descriptor = original_open(path, *args, **kwargs)
        if str(path) == "result.json" and kwargs.get("dir_fd") is not None:
            descriptors.add(descriptor)
        return descriptor

    def fstat(descriptor):
        if descriptor in descriptors and failure == "fstat":
            fail()
        return original_fstat(descriptor)

    @contextmanager
    def fdopen(descriptor, *args, **kwargs):
        if descriptor in descriptors and failure == "fdopen":
            fail()
        with original_fdopen(descriptor, *args, **kwargs) as stream:
            if descriptor in descriptors and failure == "read":
                yield SimpleNamespace(read=lambda *args: fail())
            else:
                yield stream

    def close(descriptor):
        result_descriptor = descriptor in descriptors
        original_close(descriptor)
        if result_descriptor:
            descriptors.remove(descriptor)
            with pytest.raises(OSError) as gone:
                original_fstat(descriptor)
            assert gone.value.errno == errno.EBADF
            closed.append(True)
            if failure == "close":
                fail()

    test_os = SimpleNamespace(**{**vars(os), "open": open_result, "fstat": fstat,
                                 "fdopen": fdopen, "close": close})
    with patch.object(jobs, "os", test_os):
        for _ in range(2):
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            expected = {"rows": [{"job": "pilot/job-0", "state": "settle_pending",
                                  "error": str(OSError(errno.EIO, os.strerror(errno.EIO)))}]}
            assert capsys.readouterr().out.encode() == (json.dumps(expected, sort_keys=True) + "\n").encode()
    assert refused == [failure, failure] and closed == [True, True] and not descriptors
    assert result.read_bytes() == b"{}" and shop.receipts("job-0") == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_uncertain_first_result_snapshot_cannot_readmit_after_disappearance(kind_shop, capsys):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    result = folder / "result.json"
    before = {name: (folder / name).read_bytes()
              for name in ("admitted.json", "claim.json", "packet.md", "derivation.json")}
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()
    original_stat, original_existing = os.stat, jobs.PlannedJob.observe_existing_fence
    refused, captured = [], []

    def existing(job):
        if job.id != "pilot/job-1":
            return original_existing(job)
        failed = []

        def stat_node(path, *args, **kwargs):
            if str(path) == "result.json" and kwargs.get("dir_fd") is not None and not failed:
                failed.append(True)
                raise OSError(errno.EIO, os.strerror(errno.EIO), "result.json")
            return original_stat(path, *args, **kwargs)

        with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "stat": stat_node})):
            nodes = original_existing(job)
        assert nodes["folder"] == "directory" and nodes["result"] == "uncertain"
        assert failed == [True]
        result.unlink()
        refused.append(True)
        captured.append(job)
        return nodes

    for _ in range(2):
        result.write_bytes(b"{}")
        with patch.object(jobs.PlannedJob, "observe_existing_fence", existing):
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            assert json.loads(capsys.readouterr().out) == job_fixtures.jobs2_2m_unknown_report(
                "job-1", job_fixtures.JOBS2_UNVERIFIED_ACTION)
        assert captured[-1].metadata_uncertain and captured[-1].recorded_execution_fence() is None
        assert not captured[-1].settlement_attempted and not captured[-1].execution_owned
        assert not result.exists() and not (folder / "execution.json").exists()
        assert shop.receipts("job-1") == []
        assert {name: (folder / name).read_bytes() for name in before} == before
        assert shop.head() == head and (shop.checkout / ".git/index").read_bytes() == index
    assert refused == [True, True]


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("boundary", ["admission", "execution"])
@pytest.mark.parametrize("node", ["result", "admitted", "execution", "folder", "execution-vanishes"])
def test_recorded_metadata_uncertainty_refuses_admission_and_execution(kind_shop, capsys, boundary, node):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    before = {name: (folder / name).read_bytes()
              for name in ("admitted.json", "claim.json", "packet.md", "derivation.json")}
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()
    original_admit, original_run, original_stat = jobs.admit, jobs.run_job, os.stat
    captured, rejected = [], []

    def uncertain(job):
        if node == "execution-vanishes":
            execution = folder / "execution.json"
            execution.mkdir()
            original_fence = jobs.PlannedJob.observe_fence
            removed = []

            def fence(current, name=None, directory=None):
                selected = current.execution_claim_name if name is None else name
                if current is job and selected == "execution.json" and directory is not None and not removed:
                    execution.rmdir()
                    removed.append(True)
                return original_fence(current, name, directory)

            with patch.object(jobs.PlannedJob, "observe_fence", fence):
                nodes = job.observe_existing_fence()
            assert nodes["execution"] == "other" and removed == [True]
            captured.append(job)
            return
        refused = []
        filename = folder.name if node == "folder" else node + ".json"

        def stat_node(path, *args, **kwargs):
            if str(path) == filename and kwargs.get("dir_fd") is not None and not refused:
                refused.append(True)
                raise OSError(errno.EIO, os.strerror(errno.EIO), filename)
            return original_stat(path, *args, **kwargs)

        with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "stat": stat_node})):
            nodes = job.observe_existing_fence()
        assert refused == [True] and nodes[node] == "uncertain"
        captured.append(job)

    def reject(operation, *args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except ValueError as exc:
            assert str(exc) == "job metadata observation unverified"
            rejected.append(boundary)
            raise

    def admit(ledger, initiative, message, mailbox, recipes, store=None, job=None):
        if boundary == "admission" and job is not None and job.id == "pilot/job-1":
            uncertain(job)
            return reject(original_admit, ledger, initiative, message, mailbox, recipes, store, job)
        return original_admit(ledger, initiative, message, mailbox, recipes, store, job)

    def run(store, job, *args, **kwargs):
        if boundary == "execution" and job.id == "pilot/job-1":
            uncertain(job)
            return reject(original_run, store, job, *args, **kwargs)
        return original_run(store, job, *args, **kwargs)

    with patch.object(jobs, "admit", admit), patch.object(jobs, "run_job", run):
        for _ in range(2):
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            assert json.loads(capsys.readouterr().out) == job_fixtures.jobs2_2m_unknown_report(
                "job-1", job_fixtures.JOBS2_UNVERIFIED_ACTION)
            assert captured[-1].metadata_uncertain and not captured[-1].execution_owned
            assert not (folder / "execution.json").exists() and not (folder / "result.json").exists()
            assert shop.receipts("job-1") == []
            assert {name: (folder / name).read_bytes() for name in before} == before
            assert shop.head() == head and (shop.checkout / ".git/index").read_bytes() == index
    assert rejected == [boundary, boundary]


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("component", ["job", "ancestor"])
def test_no_plan_non_directory_component_keeps_enotdir_bytes(kind_shop, capsys, component):
    shop = kind_shop
    _, folder, _, _ = job_fixtures.jobs2_2l_result_setup(shop, "existing", "directory", False)
    result = folder / "result.json"
    result.rmdir()
    result.write_bytes(b"{}")
    original = jobs.Job.directory_descriptor
    node = folder if component == "job" else folder.parent
    saved = shop.tmp / "retained-nondirectory-component"
    replaced = []

    @contextmanager
    def directory(job, **kwargs):
        if not kwargs.get("legacy_result"):
            with original(job, **kwargs) as descriptor:
                yield descriptor
            return
        node.rename(saved)
        node.write_bytes(b"not a directory")
        replaced.append(component)
        try:
            with original(job, **kwargs) as descriptor:
                yield descriptor
        finally:
            node.unlink()
            saved.rename(node)

    with patch.object(jobs.Job, "directory_descriptor", directory):
        for _ in range(2):
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            error = str(NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(result)))
            expected = {"rows": [{"job": "pilot/job-0", "state": "settle_pending", "error": error}]}
            assert capsys.readouterr().out.encode() == (json.dumps(expected, sort_keys=True) + "\n").encode()
    assert replaced == [component, component] and result.read_bytes() == b"{}"


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_live_uncertain_admission_pins_exact_running_recovery_action(kind_shop, capsys):
    shop = kind_shop
    host_plan(shop)
    shop.request_job("job-0", "ok")
    shop.request_job("job-1", "heavy")
    store = shop.workspace.store
    folder = store / "jobs/pilot/job-0"
    folder.mkdir(parents=True)
    (folder / "claim.json").write_text(json.dumps(job_fixtures.live_claim(jobs, os.getpid(), "pilot/job-0")))
    (folder / "admitted.json").mkdir()
    original_grant, original_load = jobs.grant_next, jobs.Store.load
    retained = shop.tmp / "retained-running-action-store"
    granted, swapped = [], []

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0:
            granted.append(True)
        return answer

    def load(current):
        if granted and not swapped:
            store.rename(retained)
            symlink_or_skip(retained, store, target_is_directory=True)
            swapped.append(True)
        return original_load(current)

    try:
        with patch.object(jobs, "grant_next", grant), patch.object(jobs.Store, "load", load):
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    owned = [row for row in report["rows"] if row.get("job") == "pilot/job-0"]
    assert owned[0] == {"job": "pilot/job-0", "state": "running", "process_group": None}
    assert owned[-1]["next_action"] == (
        "Root: repair store or audit access; preserve the running job's staging runner and reservation; "
        "inspect recovery-status and establish execution custody before settlement or retry. Do not rerun it.")
    assert swapped == [True] and shop.receipts("job-0") == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("entry", ["closed", "taken"])
def test_argon_uncertain_first_result_snapshot_preserves_sibling_rows(kind_shop, capsys, entry):
    shop = kind_shop
    if entry == "closed":
        identifier, folder, _, reservation = job_fixtures.jobs2_2l_result_setup(shop, "closed", "directory", True)
        (folder / "result.json").rmdir()
        (folder / "result.json").write_bytes(b"{}")
    else:
        identifier = "job-1"
        folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
        reservation = None
    target = "pilot/" + identifier
    result = folder / "result.json"
    before = {path.name: path.read_bytes() for path in folder.iterdir() if path.is_file() and path != result}
    receipts, head = shop.receipts(identifier), shop.head()
    index = (shop.checkout / ".git/index").read_bytes()
    original_existing, original_stat, original_run = jobs.PlannedJob.observe_existing_fence, os.stat, jobs.run_job
    armed, captured, peer = [], [], []

    def existing(job):
        if job.id != target or (entry == "taken" and not armed):
            return original_existing(job)
        failed = []

        def stat_node(path, *args, **kwargs):
            if str(path) == "result.json" and kwargs.get("dir_fd") is not None and not failed:
                failed.append(True)
                raise OSError(errno.EIO, os.strerror(errno.EIO), "result.json")
            return original_stat(path, *args, **kwargs)

        with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "stat": stat_node})):
            nodes = original_existing(job)
        assert failed == [True] and nodes["result"] == "uncertain"
        result.unlink()
        captured.append(job)
        return nodes

    def run(store, job, *args, **kwargs):
        if entry == "taken" and job.id == target:
            execution = json.dumps(job_fixtures.live_claim(jobs, os.getpid(), target)).encode()
            (folder / "execution.json").write_bytes(execution)
            result.write_bytes(b"{}")
            peer.append(execution)
            armed.append(True)
        return original_run(store, job, *args, **kwargs)

    expected = job_fixtures.jobs2_2m_unknown_report(identifier, job_fixtures.JOBS2_2M_FENCED_UNKNOWN_ACTION)
    if entry == "taken":
        expected["rows"][0]["process_group"] = json.loads(before["process.json"])["group"]
    with patch.object(jobs.PlannedJob, "observe_existing_fence", existing), patch.object(jobs, "run_job", run):
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        assert json.loads(capsys.readouterr().out) == expected
    assert len(captured) == 1 and captured[0].recorded_execution_fence() is None
    assert captured[0].fence_observations[captured[0].execution_claim_name].state == jobs.FENCE_VERIFIED
    assert captured[0].metadata_uncertain and not captured[0].settlement_attempted
    assert not captured[0].execution_owned and not result.exists()
    assert {name: (folder / name).read_bytes() for name in before} == before
    assert shop.receipts(identifier) == receipts and shop.head() == head
    assert (shop.checkout / ".git/index").read_bytes() == index
    if reservation is not None:
        assert job_fixtures.ledger_rows(shop, holder="job:" + target)[reservation]["state"] == "granted"
    else:
        assert peer == [(folder / "execution.json").read_bytes()]


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("route", ["run_job", "refuse"])
def test_attempt_uncertainty_can_settle_a_later_valid_terminal_result(kind_shop, capsys, route):
    shop = kind_shop
    host_plan(shop)
    shop.request_job("job-1", "touch")
    if route == "refuse":
        shop.recipes["recipes"].pop("touch")
        shop.save_recipes()
    folder = shop.workspace.store / "jobs/pilot/job-1"
    original_route, original_claim, original_stat = getattr(jobs, route), jobs.PlannedJob.claim, os.stat
    captured, refused, peer = [], [], {}
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()

    def enter(store, job, *args, **kwargs):
        folder.mkdir(parents=True)
        (folder / "claim.json").write_text(json.dumps(job_fixtures.live_claim(jobs, os.getpid(), job.id)))
        return original_route(store, job, *args, **kwargs)

    def stat_node(path, *args, **kwargs):
        if str(path) == "result.json" and kwargs.get("dir_fd") is not None and not refused:
            refused.append(True)
            raise OSError(errno.EIO, os.strerror(errno.EIO), "result.json")
        return original_stat(path, *args, **kwargs)

    def claim(job, *args, **kwargs):
        with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "stat": stat_node})):
            answer = original_claim(job, *args, **kwargs)
        assert answer is False and refused == [True]
        jobs.write_result(job, "refused", None, reason="peer refusal")
        peer.update({path.name: path.read_bytes() for path in folder.iterdir() if path.is_file()})
        captured.append(job)
        return answer

    with ExitStack() as active:
        if route == "run_job":
            active.enter_context(patch.object(jobs, "run_job", enter))
        else:
            active.enter_context(patch.object(jobs, "refuse", enter))
        active.enter_context(patch.object(jobs.PlannedJob, "claim", claim))
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 0
        report = json.loads(capsys.readouterr().out)
    assert report == {"rows": [{"job": "pilot/job-1", "state": "refused", "exit_code": None,
                               "result": str(folder / "result.json"), "reason": "peer refusal"}]}
    assert len(captured) == 1 and captured[0].terminal_observed and captured[0].settlement_attempted
    assert not captured[0].execution_owned and shop.states("job-1") == ["refused"]
    assert {name: (folder / name).read_bytes() for name in peer} == peer
    assert not shop.sentinel.exists() and shop.head() == head
    assert (shop.checkout / ".git/index").read_bytes() == index


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_attempt_retains_result_from_execution_publication_probe(kind_shop, capsys):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    result = folder / "result.json"
    original_publish, original_observe = jobs.PlannedJob.publish_execution_claim, jobs.PlannedJob.observe_result
    captured, vanished, claim_bytes = [], [], []
    preserved = {name: (folder / name).read_bytes()
                 for name in ("admitted.json", "claim.json", "packet.md", "derivation.json")}
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()

    def publish(job, raw):
        answer = original_publish(job, raw)
        result.write_bytes(b"{}")
        claim_bytes.append(raw)
        return answer

    def observe(job, directory=None):
        observed = original_observe(job, directory)
        if job.id == "pilot/job-1" and claim_bytes and observed == "regular" and not vanished:
            result.unlink()
            vanished.append(True)
            captured.append(job)
        return observed

    with patch.object(jobs.PlannedJob, "publish_execution_claim", publish), patch.object(jobs.PlannedJob, "observe_result", observe):
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        report = json.loads(capsys.readouterr().out)
    assert report == {"rows": [{"job": "pilot/job-1", "state": "settle_pending",
                               "error": "job has no validated terminal result",
                               "next_action": job_fixtures.JOBS2_BLOCKED_ACTION}]}
    assert len(captured) == 1 and vanished == [True]
    assert captured[0].settlement_attempted and not captured[0].execution_owned
    assert claim_bytes == [(folder / "execution.json").read_bytes()] and not result.exists()
    assert {name: (folder / name).read_bytes() for name in preserved} == preserved
    assert shop.receipts("job-1") == [] and not shop.sentinel.exists() and shop.head() == head
    assert (shop.checkout / ".git/index").read_bytes() == index


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("live", [False, True])
def test_argon_failed_directory_classification_never_verifies_staging_as_execution(kind_shop, capsys, live):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    if live:
        (folder / "claim.json").write_text(json.dumps(job_fixtures.live_claim(jobs, os.getpid(), "pilot/job-1")))
    before = {name: (folder / name).read_bytes()
              for name in ("admitted.json", "claim.json", "packet.md", "derivation.json")}
    original_existing, original_stat = jobs.PlannedJob.observe_existing_fence, os.stat
    captured = []

    def existing(job):
        if job.id != "pilot/job-1":
            return original_existing(job)
        refused = []

        def stat_node(path, *args, **kwargs):
            if str(path) == folder.name and kwargs.get("dir_fd") is not None and not refused:
                refused.append(True)
                raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), folder.name)
            return original_stat(path, *args, **kwargs)

        with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "stat": stat_node})):
            nodes = original_existing(job)
        assert refused == [True] and nodes["folder"] == "uncertain"
        captured.append(job)
        return nodes

    with patch.object(jobs.PlannedJob, "observe_existing_fence", existing):
        for _ in range(2):
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            assert json.loads(capsys.readouterr().out) == job_fixtures.jobs2_2m_unknown_report(
                "job-1", job_fixtures.JOBS2_UNVERIFIED_ACTION)
            assert captured[-1].recorded_execution_fence() is None
            assert not captured[-1].execution_owned and not captured[-1].settlement_attempted
            assert {name: (folder / name).read_bytes() for name in before} == before
            assert shop.receipts("job-1") == [] and not (folder / "execution.json").exists()


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("shape", ["regular", "directory"])
def test_argon_disappearing_execution_candidate_retains_unknown_recovery_guidance(kind_shop, capsys, shape):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    shop.request_job("job-2", "heavy", dirty_content_sha256=job_fixtures.source_digest(shop)["dirty_content_sha256"])
    execution = folder / "execution.json"
    if shape == "regular":
        execution.write_bytes(b"{}")
    else:
        execution.mkdir()
    original_fence, original_existing = jobs.PlannedJob.observe_fence, jobs.PlannedJob.observe_existing_fence
    original_grant, original_load = jobs.grant_next, jobs.Store.load
    store, retained = shop.workspace.store, shop.tmp / "retained-execution-candidate-store"
    vanished, captured, granted, swapped = [], [], [], []

    def fence(job, name=None, directory=None):
        selected = job.execution_claim_name if name is None else name
        if job.id == "pilot/job-1" and selected == "execution.json" and directory is not None and not vanished:
            execution.unlink() if shape == "regular" else execution.rmdir()
            vanished.append(True)
        return original_fence(job, name, directory)

    def existing(job):
        nodes = original_existing(job)
        if job.id == "pilot/job-1":
            assert nodes["execution"] == ("regular" if shape == "regular" else "other")
            captured.append(job)
        return nodes

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0:
            granted.append(True)
        return answer

    def load(current):
        if granted and not swapped:
            store.rename(retained)
            symlink_or_skip(retained, store, target_is_directory=True)
            swapped.append(True)
        return original_load(current)

    try:
        with ExitStack() as active:
            active.enter_context(patch.object(jobs.PlannedJob, "observe_fence", fence))
            active.enter_context(patch.object(jobs.PlannedJob, "observe_existing_fence", existing))
            active.enter_context(patch.object(jobs, "grant_next", grant))
            active.enter_context(patch.object(jobs.Store, "load", load))
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if store.is_symlink():
            store.unlink()
        if retained.exists():
            retained.rename(store)
    owned = [row for row in report["rows"] if row.get("job") == "pilot/job-1"]
    assert owned[-1]["next_action"] == job_fixtures.JOBS2_UNVERIFIED_ACTION
    assert len(captured) == 1 and captured[0].recorded_execution_fence() is None
    assert "execution.json" in captured[0].claim_candidates
    assert vanished == swapped == [True] and not execution.exists()
    assert not captured[0].execution_owned and not captured[0].settlement_attempted
    assert not (folder / "result.json").exists() and shop.receipts("job-1") == []


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("first", ["uncertain", "regular"])
def test_attempt_retains_released_peer_entry_result(kind_shop, capsys, first):
    shop = kind_shop
    host_plan(shop)
    job_fixtures.request_kind_job(shop, "heavy")
    folder = shop.workspace.store / "jobs/pilot/job-1"
    result = folder / "result.json"
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()
    original_grant, original_existing, original_stat = jobs.grant_next, jobs.PlannedJob.observe_existing_fence, os.stat
    released, captured, preserved = [], [], {}

    def grant(*args, **kwargs):
        answer = original_grant(*args, **kwargs)
        if answer[0] == 0 and not released:
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "claim.json").write_text(json.dumps(job_fixtures.live_claim(jobs, os.getpid(), "pilot/job-1")))
            result.write_bytes(b"{}")
            preserved.update({path.name: path.read_bytes() for path in folder.iterdir()
                              if path.is_file() and path != result})
            released.append(answer[1]["granted"]["request_id"])
            shop.workspace.release(released[0])
        return answer

    def existing(job):
        if job.id != "pilot/job-1" or not released or captured:
            return original_existing(job)
        failed = []

        def stat_node(path, *args, **kwargs):
            if str(path) == "result.json" and kwargs.get("dir_fd") is not None and not failed:
                failed.append(True)
                raise OSError(errno.EIO, os.strerror(errno.EIO), "result.json")
            return original_stat(path, *args, **kwargs)

        if first == "uncertain":
            with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "stat": stat_node})):
                nodes = original_existing(job)
            assert failed == [True]
        else:
            nodes = original_existing(job)
        assert nodes["result"] == first
        result.unlink()
        captured.append(job)
        return nodes

    with patch.object(jobs, "grant_next", grant), patch.object(jobs.PlannedJob, "observe_existing_fence", existing):
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        report = json.loads(capsys.readouterr().out)
    assert len(released) == len(captured) == 1
    job = captured[0]
    if first == "uncertain":
        expected = job_fixtures.jobs2_2m_unknown_report("job-1", job_fixtures.JOBS2_2M_FENCED_UNKNOWN_ACTION)
        expected["rows"][0]["process_group"] = job.process_group()
        assert report == expected
        assert not job.settlement_attempted and job.recorded_execution_fence() is None
    else:
        assert report == {"rows": [{"job": "pilot/job-1", "state": "settle_pending",
                                   "error": "job has no validated terminal result",
                                   "next_action": job_fixtures.JOBS2_BLOCKED_ACTION}]}
        assert job.settlement_attempted
    assert not job.execution_owned and not result.exists() and shop.receipts("job-1") == []
    assert {name: (folder / name).read_bytes() for name in preserved} == preserved
    assert job_fixtures.requests_of(shop, "heavy") == {released[0]: "released"}
    assert not shop.sentinel.exists() and shop.head() == head
    assert (shop.checkout / ".git/index").read_bytes() == index


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("route", ["run_job", "refuse"])
@pytest.mark.parametrize("first", ["uncertain", "regular"])
@pytest.mark.parametrize("planned", [False, True], ids=["legacy-bytes", "planned"])
@pytest.mark.parametrize("group", [None, "untrusted-group\nsecond-line"], ids=["no-group", "invalid-group"])
def test_attempt_retains_nonderived_claim_loser_result(kind_shop, capsys, route, first, planned, group):
    shop = kind_shop
    if planned:
        host_plan(shop)
    shop.request_job("job-1", "touch")
    folder = shop.workspace.store / "jobs/pilot/job-1"
    result = folder / "result.json"
    original_route, original_claim, original_stat = getattr(jobs, route), (jobs.PlannedJob if planned else jobs.Job).claim, os.stat
    peer, captured = [], []
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()

    def enter(store, job, *args, **kwargs):
        folder.mkdir(parents=True)
        raw = json.dumps(job_fixtures.live_claim(jobs, os.getpid(), job.id)).encode()
        (folder / "claim.json").write_bytes(raw)
        if group is not None:
            (folder / "process.json").write_text(json.dumps({"group": group}))
        result.write_bytes(b"{}")
        peer.append(raw)
        return original_route(store, job, *args, **kwargs)

    def claim(job, *args, **kwargs):
        failed = []

        def stat_node(path, *args, **kwargs):
            if str(path) == "result.json" and kwargs.get("dir_fd") is not None and not failed:
                failed.append(True)
                raise OSError(errno.EIO, os.strerror(errno.EIO), "result.json")
            return original_stat(path, *args, **kwargs)

        if first == "uncertain":
            with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "stat": stat_node})):
                answer = original_claim(job, *args, **kwargs)
            assert failed == [True]
        else:
            answer = original_claim(job, *args, **kwargs)
        assert answer is False
        result.unlink()
        captured.append(job)
        return answer

    # A malformed recipe reference takes the real admission-refusal route.
    if route == "refuse":
        shop.recipes["recipes"].pop("touch")
        shop.save_recipes()
    with ExitStack() as active:
        if route == "run_job":
            active.enter_context(patch.object(jobs, "run_job", enter))
        else:
            active.enter_context(patch.object(jobs, "refuse", enter))
        if planned:
            active.enter_context(patch.object(jobs.PlannedJob, "claim", claim))
        else:
            active.enter_context(patch.object(jobs.Job, "claim", claim))
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        output = capsys.readouterr().out
        report = json.loads(output)
    assert len(captured) == len(peer) == 1
    job = captured[0]
    if not planned:
        expected = {"rows": [{"job": "pilot/job-1", "state": "running", "process_group": group}]}
        assert output.encode() == (json.dumps(expected, sort_keys=True) + "\n").encode()
        assert not job.settlement_attempted and job.recorded_execution_fence() is True
    elif first == "uncertain":
        assert report == job_fixtures.jobs2_2m_unknown_report("job-1", job_fixtures.JOBS2_2M_FENCED_UNKNOWN_ACTION)
        assert not job.settlement_attempted and job.recorded_execution_fence() is None
    else:
        assert report == {"rows": [{"job": "pilot/job-1", "state": "settle_pending",
                                   "error": "job has no validated terminal result",
                                   "next_action": job_fixtures.JOBS2_BLOCKED_ACTION}]}
        assert job.settlement_attempted
    assert (folder / "claim.json").read_bytes() == peer[0]
    assert not job.execution_owned and not result.exists() and not shop.sentinel.exists()
    assert shop.receipts("job-1") == [] and shop.head() == head
    assert (shop.checkout / ".git/index").read_bytes() == index


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("derived", [False, True])
def test_attempt_prior_result_blocks_take_execution(kind_shop, capsys, derived):
    shop = kind_shop
    if derived:
        folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    else:
        host_plan(shop)
        shop.request_job("job-1", "touch")
        folder = shop.workspace.store / "jobs/pilot/job-1"
    original = jobs.run_job
    captured = []
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()
    preserved = {path.name: path.read_bytes() for path in folder.iterdir() if path.is_file()} if derived else {}

    def run(store, job, *args, **kwargs):
        folder.mkdir(parents=True, exist_ok=True)
        result = folder / "result.json"
        result.write_bytes(b"{}")
        assert job.observe_result() == "regular"
        result.unlink()
        if not derived:
            folder.rmdir()
        captured.append(job)
        return original(store, job, *args, **kwargs)

    with patch.object(jobs, "run_job", run):
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        report = json.loads(capsys.readouterr().out)
    assert report == {"rows": [{"job": "pilot/job-1", "state": "settle_pending",
                               "error": "job has no validated terminal result",
                               "next_action": job_fixtures.JOBS2_OBSERVED_RESULT_ACTION}]}
    assert len(captured) == 1 and captured[0].settlement_attempted and not captured[0].execution_owned
    assert not (folder / "execution.json").exists() and not (folder / "result.json").exists()
    if derived:
        assert {path.name: path.read_bytes() for path in folder.iterdir() if path.is_file()} == preserved
    else:
        assert not folder.exists()
    assert shop.receipts("job-1") == [] and not shop.sentinel.exists() and shop.head() == head
    assert (shop.checkout / ".git/index").read_bytes() == index


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_argon_addendum_admissionheld_retains_admission_role(kind_shop, capsys):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    marker = folder / "admitted.json"
    before = {name: (folder / name).read_bytes()
              for name in ("claim.json", "packet.md", "derivation.json", "process.json")}
    group = json.loads(before["process.json"])["group"]
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()
    original_kind, original_admit = jobs.PlannedJob.metadata_kind, jobs.admit
    vanished, held, captured = [], [], []

    def kind(job, name):
        if job.id == "pilot/job-1" and name == "admitted.json" and not vanished:
            assert job.execution_claim_name == "execution.json" and job.admission_unverified
            marker.unlink()
            vanished.append(True)
            captured.append(job)
        return original_kind(job, name)

    def admit(*args, **kwargs):
        try:
            return original_admit(*args, **kwargs)
        except jobs.AdmissionHeld:
            held.append(True)
            raise

    with patch.object(jobs.PlannedJob, "metadata_kind", kind), patch.object(jobs, "admit", admit):
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        report = json.loads(capsys.readouterr().out)
    expected = job_fixtures.jobs2_2m_unknown_report("job-1", job_fixtures.JOBS2_UNVERIFIED_ACTION)
    expected["rows"][0]["process_group"] = group
    assert report == expected
    assert vanished == held == [True] and len(captured) == 1
    job = captured[0]
    assert job.execution_claim_name == "execution.json" and job.recorded_execution_fence() is None
    assert "claim.json" not in job.fence_observations
    assert not job.execution_owned and not job.settlement_attempted
    assert not marker.exists() and not (folder / "execution.json").exists() and not (folder / "result.json").exists()
    assert {name: (folder / name).read_bytes() for name in before} == before
    assert shop.receipts("job-1") == [] and shop.head() == head
    assert (shop.checkout / ".git/index").read_bytes() == index


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("node", ["regular", "directory"])
@pytest.mark.parametrize("loss", ["leaf", "folder"])
def test_argon_addendum_prior_execution_candidate_cannot_be_republished(kind_shop, capsys, node, loss):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    execution = folder / "execution.json"
    saved = shop.tmp / "retained-prior-execution-directory"
    original = jobs.run_job
    captured = []
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()
    before = {name: (folder / name).read_bytes()
              for name in ("claim.json", "packet.md", "derivation.json", "admitted.json", "process.json")}

    def run(store, job, *args, **kwargs):
        if node == "regular":
            execution.write_text(json.dumps(job_fixtures.live_claim(jobs, os.getpid(), job.id)))
        else:
            execution.mkdir()
        nodes = job.observe_existing_fence()
        assert nodes["execution"] == ("regular" if node == "regular" else "other")
        if loss == "leaf":
            execution.unlink() if node == "regular" else execution.rmdir()
        else:
            folder.rename(saved)
        captured.append(job)
        return original(store, job, *args, **kwargs)

    try:
        with patch.object(jobs, "run_job", run):
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    finally:
        if saved.exists():
            assert not folder.exists(), "a retained execution observation must not recreate its directory"
            saved.rename(folder)
    action = job_fixtures.JOBS2_2M_FENCED_UNKNOWN_ACTION if node == "regular" else job_fixtures.JOBS2_UNVERIFIED_ACTION
    expected = job_fixtures.jobs2_2m_unknown_report("job-1", action)
    if node == "regular" and loss == "leaf":
        expected["rows"][0]["process_group"] = json.loads(before["process.json"])["group"]
    assert report == expected
    assert len(captured) == 1 and not captured[0].execution_owned and not captured[0].settlement_attempted
    assert captured[0].execution_claim_name == "execution.json" and captured[0].recorded_execution_fence() is None
    assert execution.exists() is (loss == "folder")
    assert not (folder / "result.json").exists()
    assert {name: (folder / name).read_bytes() for name in before} == before
    assert shop.receipts("job-1") == [] and shop.head() == head
    assert (shop.checkout / ".git/index").read_bytes() == index


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("live", [False, True])
@pytest.mark.parametrize("node", ["admitted.json", "execution.json"])
@pytest.mark.parametrize("surface", ["run-open", "recovery-status", "resolve"])
def test_argon_addendum_metadata_uncertainty_cannot_use_verified_liveness(kind_shop, capsys, live, node, surface):
    shop = kind_shop
    host_plan(shop)
    shop.request_job("job-0", "ok")
    folder = shop.workspace.store / "jobs/pilot/job-0"
    folder.mkdir(parents=True)
    claim = job_fixtures.live_claim(jobs, os.getpid(), "pilot/job-0")
    if not live:
        claim["start"] = "0"
    for name in ("claim.json", "execution.json"):
        (folder / name).write_text(json.dumps(claim))
    before = {name: (folder / name).read_bytes() for name in ("claim.json", "execution.json")}
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()
    original_stat = os.stat
    refused = []

    def stat_node(path, *args, **kwargs):
        if str(path) == node and kwargs.get("dir_fd") is not None and not refused:
            refused.append(True)
            raise OSError(errno.EIO, os.strerror(errno.EIO), node)
        return original_stat(path, *args, **kwargs)

    flags = ("--job", "pilot/job-0", "--reason", "root recovery") if surface == "resolve" else ()
    with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "stat": stat_node})):
        code = jobs.main(shop.argv(surface, *flags, census=[], lock_wait=0)[3:])
        report = json.loads(capsys.readouterr().out)
    assert refused == [True]
    if surface == "resolve":
        assert code == 2 and report == {"error": "runner visibility is unknown: pilot/job-0"}
    elif surface == "recovery-status":
        assert code == 3
        row = next(row for row in report["jobs"] if row["job"] == "pilot/job-0")
        assert row["state"] == "unknown_effect" and row["runner_alive"] is None
    else:
        assert code == 3
        assert report == job_fixtures.jobs2_2m_unknown_report("job-0", job_fixtures.JOBS2_2M_FENCED_UNKNOWN_ACTION)
    assert not (folder / "result.json").exists() and shop.receipts("job-0") == []
    assert {name: (folder / name).read_bytes() for name in before} == before
    assert shop.head() == head and (shop.checkout / ".git/index").read_bytes() == index


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_argon_addendum_validated_admission_disappearance_keeps_custody_unknown(kind_shop, capsys):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    marker = folder / "admitted.json"
    original = jobs.admitted_derivation
    captured = []
    before = {name: (folder / name).read_bytes()
              for name in ("claim.json", "packet.md", "derivation.json", "process.json")}
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()

    def admitted(job, *args, **kwargs):
        answer = original(job, *args, **kwargs)
        assert job.admission_validated
        marker.unlink()
        captured.append(job)
        return answer

    with patch.object(jobs, "admitted_derivation", admitted):
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        report = json.loads(capsys.readouterr().out)
    expected = job_fixtures.jobs2_2m_unknown_report("job-1", job_fixtures.JOBS2_UNVERIFIED_ACTION)
    expected["rows"][0]["process_group"] = json.loads(before["process.json"])["group"]
    assert report == expected
    assert len(captured) == 1 and captured[0].recorded_execution_fence() is None
    assert captured[0].execution_claim_name == "execution.json" and captured[0].metadata_uncertain
    assert not captured[0].execution_owned and not captured[0].settlement_attempted
    assert not marker.exists() and not (folder / "execution.json").exists() and not (folder / "result.json").exists()
    assert {name: (folder / name).read_bytes() for name in before} == before
    assert shop.receipts("job-1") == [] and shop.head() == head
    assert (shop.checkout / ".git/index").read_bytes() == index


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("node", ["admitted.json", "execution.json"])
def test_attempt_retained_result_does_not_certify_uncertain_metadata(kind_shop, capsys, node):
    shop = kind_shop
    _, folder, claim, _ = job_fixtures.jobs2_2l_result_setup(shop, "existing", "directory", True)
    (folder / "result.json").rmdir()
    (folder / "result.json").write_bytes(b"{}")
    (folder / "execution.json").write_text(json.dumps(claim))
    before = {name: (folder / name).read_bytes() for name in ("claim.json", "execution.json", "result.json")}
    original_stat, original_existing = os.stat, jobs.PlannedJob.observe_existing_fence
    refused, captured = [], []
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()

    def stat_node(path, *args, **kwargs):
        if str(path) == node and kwargs.get("dir_fd") is not None and not refused:
            refused.append(True)
            raise OSError(errno.EIO, os.strerror(errno.EIO), node)
        return original_stat(path, *args, **kwargs)

    def existing(job):
        answer = original_existing(job)
        captured.append(job)
        return answer

    with patch.object(jobs.PlannedJob, "observe_existing_fence", existing):
        with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "stat": stat_node})):
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
    assert refused == [True] and len(captured) == 1
    assert report == {"rows": [{"job": "pilot/job-0", "state": "settle_pending",
                               "error": "invalid job result schema",
                               "next_action": job_fixtures.JOBS2_OBSERVED_RESULT_ACTION}]}
    assert captured[0].recorded_execution_fence() is None and captured[0].settlement_attempted
    assert captured[0].fence_observations["execution.json"].state == jobs.FENCE_VERIFIED
    assert not captured[0].execution_owned and shop.receipts("job-0") == []
    assert {name: (folder / name).read_bytes() for name in before} == before
    assert shop.head() == head and (shop.checkout / ".git/index").read_bytes() == index


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("change", ["vanishes", "malformed", "directory", "probe-refusal"])
def test_attempt_first_metadata_kind_probe_retains_admission_custody(kind_shop, capsys, change):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    marker = folder / "admitted.json"
    before = {name: (folder / name).read_bytes()
              for name in ("claim.json", "packet.md", "derivation.json", "process.json")}
    saved = shop.tmp / "peer-admission-published-after-visit"
    folder.rename(saved)
    original_kind, original_stat = jobs.PlannedJob.metadata_kind, os.stat
    captured, refused = [], []
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()

    def stat_node(path, *args, **kwargs):
        if str(path) == "admitted.json" and kwargs.get("dir_fd") is not None and not refused:
            refused.append(True)
            raise OSError(errno.EIO, os.strerror(errno.EIO), "admitted.json")
        return original_stat(path, *args, **kwargs)

    def kind(job, name):
        if job.id != "pilot/job-1" or name != "admitted.json" or captured:
            return original_kind(job, name)
        # The peer publishes after visit_existing observed an absent directory.
        saved.rename(folder)
        captured.append(job)
        if change == "probe-refusal":
            with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "stat": stat_node})):
                answer = original_kind(job, name)
            assert answer == "uncertain" and refused == [True]
        else:
            answer = original_kind(job, name)
            assert answer == "regular"
            marker.unlink()
            if change == "malformed":
                marker.write_bytes(b"{")
            elif change == "directory":
                marker.mkdir()
        return answer

    with patch.object(jobs.PlannedJob, "metadata_kind", kind):
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        report = json.loads(capsys.readouterr().out)
    expected = job_fixtures.jobs2_2m_unknown_report("job-1", job_fixtures.JOBS2_UNVERIFIED_ACTION)
    if change == "vanishes":
        expected["rows"][0]["process_group"] = json.loads(before["process.json"])["group"]
    assert report == expected
    assert len(captured) == 1 and captured[0].recorded_execution_fence() is None
    assert captured[0].execution_claim_name == "execution.json"
    assert not captured[0].execution_owned and not captured[0].settlement_attempted
    assert "claim.json" not in captured[0].fence_observations
    assert not (folder / "execution.json").exists() and not (folder / "result.json").exists()
    assert {name: (folder / name).read_bytes() for name in before} == before
    assert shop.receipts("job-1") == [] and shop.head() == head
    assert (shop.checkout / ".git/index").read_bytes() == index


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_attempt_valid_terminal_predecessor_keeps_stopped_runner_evidence(kind_shop, capsys):
    shop = kind_shop
    host_plan(shop)
    parent = shop.request_job("first-check", "ok")
    assert job_fixtures.job_row(shop.run_open(), "first-check")["state"] == "completed"
    job_fixtures.request_dependent(shop, parent, "job-1")
    assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 0
    report = json.loads(capsys.readouterr().out)
    assert job_fixtures.job_row(report)["state"] == "completed"
    assert shop.states("job-1") == ["started", "completed"]
    assert shop.sentinel.read_text() == "ran\n"


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("observation", ["regular", "uncertain"])
def test_attempt_resolve_refuses_result_first_observed_during_liveness(kind_shop, capsys, observation):
    shop = kind_shop
    _, folder, claim, _ = job_fixtures.jobs2_2l_result_setup(shop, "existing", "directory", True)
    result = folder / "result.json"
    result.rmdir()
    claim["start"] = "0"
    (folder / "claim.json").write_text(json.dumps(claim))
    before, head = (folder / "claim.json").read_bytes(), shop.head()
    original, original_stat = jobs.PlannedJob.observe_existing_fence, os.stat
    captured, refused = [], []

    def stat_node(path, *args, **kwargs):
        if str(path) == "result.json" and kwargs.get("dir_fd") is not None and not refused:
            refused.append(True)
            raise OSError(errno.EIO, os.strerror(errno.EIO), "result.json")
        return original_stat(path, *args, **kwargs)

    def existing(job):
        if job.id == "pilot/job-0" and not captured:
            captured.append(job)
            if observation == "regular":
                result.write_bytes(b"{}")
            else:
                with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "stat": stat_node})):
                    return original(job)
        return original(job)

    with patch.object(jobs.PlannedJob, "observe_existing_fence", existing):
        assert jobs.main(shop.argv("resolve", "--job", "pilot/job-0", "--reason", "root recovery",
                                   census=[], lock_wait=0)[3:]) == 2
        error = ("job is already finished: pilot/job-0" if observation == "regular"
                 else "runner visibility is unknown: pilot/job-0")
        assert json.loads(capsys.readouterr().out) == {"error": error}
    assert len(captured) == 1 and not captured[0].execution_owned
    if observation == "regular":
        assert result.read_bytes() == b"{}"
    else:
        assert refused == [True] and not result.exists()
    assert (folder / "claim.json").read_bytes() == before
    assert shop.receipts("job-0") == [] and shop.head() == head


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("race", ["disappears-before-open", "appears-during-liveness"])
def test_attempt_recovery_reports_retained_result_as_unvalidated_evidence(kind_shop, capsys, race):
    shop = kind_shop
    _, folder, _, _ = job_fixtures.jobs2_2l_result_setup(shop, "existing", "directory", True)
    result = folder / "result.json"
    result.rmdir()
    if race == "disappears-before-open":
        result.write_bytes(b"{}")
    before, head = (folder / "claim.json").read_bytes(), shop.head()
    original_observe, original_existing = jobs.PlannedJob.observe_result, jobs.PlannedJob.observe_existing_fence
    captured = []

    def observe(job, directory=None, **kwargs):
        answer = original_observe(job, directory, **kwargs)
        if (race == "disappears-before-open" and job.id == "pilot/job-0"
                and answer == "regular" and not captured):
            result.unlink()
            captured.append(job)
        return answer

    def existing(job):
        if race == "appears-during-liveness" and job.id == "pilot/job-0" and not captured:
            result.write_bytes(b"{}")
            captured.append(job)
        return original_existing(job)

    with patch.object(jobs.PlannedJob, "observe_result", observe), patch.object(jobs.PlannedJob, "observe_existing_fence", existing):
        assert jobs.main(shop.argv("recovery-status", census=[], lock_wait=0)[3:]) == 3
        report = json.loads(capsys.readouterr().out)
    row = next(row for row in report["jobs"] if row["job"] == "pilot/job-0")
    assert row["state"] == "evidence_error" and row["error"] == "job has no validated terminal result"
    assert len(captured) == 1 and not captured[0].execution_owned
    assert (folder / "claim.json").read_bytes() == before and shop.receipts("job-0") == []
    assert shop.head() == head
    assert result.exists() is (race == "appears-during-liveness")


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("entry", ["visit", "execution"])
@pytest.mark.parametrize("shape", ["regular", "directory"])
def test_attempt_result_stat_survives_descriptor_cleanup_failure(kind_shop, capsys, entry, shape):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    result = folder / "result.json"
    before = {name: (folder / name).read_bytes()
              for name in ("claim.json", "packet.md", "derivation.json", "admitted.json")}
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()
    original_existing, original_publish = jobs.PlannedJob.observe_existing_fence, jobs.PlannedJob.publish_execution_claim
    original_observe, original_close = jobs.PlannedJob.observe_result, os.close
    armed, failed, captured, closed = [], [], [], []

    def publish_result():
        result.write_bytes(b"{}") if shape == "regular" else result.mkdir()
        armed.append(True)

    def existing(job):
        nodes = original_existing(job)
        if entry == "visit" and job.id == "pilot/job-1" and not armed:
            assert nodes["result"] == "absent"
            publish_result()
        return nodes

    def publish(job, raw):
        answer = original_publish(job, raw)
        if entry == "execution" and job.id == "pilot/job-1":
            publish_result()
        return answer

    def close(descriptor):
        original_close(descriptor)
        with pytest.raises(OSError) as error:
            os.fstat(descriptor)
        assert error.value.errno == errno.EBADF
        closed.append(descriptor)
        if not failed:
            failed.append(True)
            result.unlink() if shape == "regular" else result.rmdir()
            raise OSError(errno.EIO, os.strerror(errno.EIO))

    def observe(job, directory=None, **kwargs):
        if job.id == "pilot/job-1" and directory is None and armed and not failed:
            captured.append(job)
            with patch.object(jobs, "os", SimpleNamespace(**{**vars(os), "close": close})):
                return original_observe(job, directory, **kwargs)
        return original_observe(job, directory, **kwargs)

    with ExitStack() as active:
        active.enter_context(patch.object(jobs.PlannedJob, "observe_existing_fence", existing))
        active.enter_context(patch.object(jobs.PlannedJob, "publish_execution_claim", publish))
        active.enter_context(patch.object(jobs.PlannedJob, "observe_result", observe))
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        report = json.loads(capsys.readouterr().out)
    action = job_fixtures.JOBS2_OBSERVED_RESULT_ACTION if shape == "regular" else job_fixtures.JOBS2_BLOCKED_ACTION
    assert report == {"rows": [{"job": "pilot/job-1", "state": "settle_pending",
                               "error": "job has no validated terminal result", "next_action": action}]}
    assert armed == failed == [True] and len(captured) == 1 and closed
    assert captured[0].result_observed is (shape == "regular")
    assert captured[0].settlement_attempted and not captured[0].execution_owned
    assert {name: (folder / name).read_bytes() for name in before} == before
    assert not result.exists() and shop.receipts("job-1") == [] and shop.head() == head
    assert (shop.checkout / ".git/index").read_bytes() == index
    assert (folder / "execution.json").exists() is (entry == "execution")


@pytest.mark.usefixtures("jobs2_fresh_cache")
@pytest.mark.parametrize("verified", [False, True])
def test_attempt_claim_never_recreates_an_observed_peer_candidate(kind_shop, capsys, verified):
    shop = kind_shop
    host_plan(shop)
    shop.request_job("job-1", "touch")
    folder = shop.workspace.store / "jobs/pilot/job-1"
    original = jobs.PlannedJob.claim
    captured = []
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()

    def claim(job, *args, **kwargs):
        if job.id == "pilot/job-1" and not captured:
            folder.mkdir(parents=True)
            candidate = folder / "claim.json"
            if verified:
                candidate.write_text(json.dumps(job_fixtures.live_claim(jobs, os.getpid(), job.id)))
            else:
                candidate.mkdir()
            observation = job.observe_fence("claim.json")
            assert observation.state == (jobs.FENCE_VERIFIED if verified else jobs.FENCE_UNCERTAIN)
            captured.append(job)
            candidate.unlink() if verified else candidate.rmdir()
            folder.rmdir()
        return original(job, *args, **kwargs)

    with patch.object(jobs.PlannedJob, "claim", claim):
        assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
        report = json.loads(capsys.readouterr().out)
    action = job_fixtures.JOBS2_2M_FENCED_UNKNOWN_ACTION if verified else job_fixtures.JOBS2_UNVERIFIED_ACTION
    assert report == job_fixtures.jobs2_2m_unknown_report("job-1", action)
    assert len(captured) == 1 and captured[0].recorded_execution_fence() is None
    assert not captured[0].execution_owned and not folder.exists() and not shop.sentinel.exists()
    assert shop.receipts("job-1") == [] and shop.head() == head
    assert (shop.checkout / ".git/index").read_bytes() == index


@pytest.mark.usefixtures("jobs2_fresh_cache")
def test_attempt_standalone_result_probe_retains_lost_admission_directory(kind_shop, capsys):
    shop = kind_shop
    folder = job_fixtures.jobs2_2j_stopped_derived_admission(shop)
    before = {name: (folder / name).read_bytes()
              for name in ("claim.json", "admitted.json", "packet.md", "derivation.json")}
    saved = shop.tmp / "lost-admission-directory"
    original = jobs.PlannedJob.observe_existing_fence
    captured = []
    head, index = shop.head(), (shop.checkout / ".git/index").read_bytes()

    def existing(job):
        answer = original(job)
        if job.id == "pilot/job-1" and not captured:
            assert answer["admitted"] == "regular" and answer["result"] == "absent"
            captured.append(job)
            folder.rename(saved)
        return answer

    try:
        with patch.object(jobs.PlannedJob, "observe_existing_fence", existing):
            assert jobs.main(shop.argv("run-open", census=[], lock_wait=0)[3:]) == 3
            report = json.loads(capsys.readouterr().out)
        assert report == job_fixtures.jobs2_2m_unknown_report("job-1", job_fixtures.JOBS2_UNVERIFIED_ACTION)
        assert len(captured) == 1 and captured[0].recorded_execution_fence() is None
        assert captured[0].metadata_uncertain and not captured[0].execution_owned
        assert not captured[0].settlement_attempted and not folder.exists()
    finally:
        if saved.exists():
            saved.rename(folder)
    assert {name: (folder / name).read_bytes() for name in before} == before
    assert not (folder / "execution.json").exists() and shop.receipts("job-1") == []
    assert shop.head() == head and (shop.checkout / ".git/index").read_bytes() == index
