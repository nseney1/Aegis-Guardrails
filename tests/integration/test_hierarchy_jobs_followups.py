"""JOBS-2b: observations never authorize a second execution or invent custody."""
import errno
import json
import os
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
    original = jobs.Job.observe_existing_fence
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
            active.enter_context(patch.object(jobs.Job, "observe_existing_fence", existing))
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
    original_run, original_claim = jobs.run_job, jobs.Job.claim
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
        with patch.object(jobs, "run_job", run), patch.object(jobs.Job, "claim", claim):
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
    original_stat, original_existing = os.stat, jobs.Job.observe_existing_fence
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
        with patch.object(jobs.Job, "observe_existing_fence", existing):
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
            original_fence = jobs.Job.observe_fence
            removed = []

            def fence(current, name=None, directory=None):
                selected = current.execution_claim_name if name is None else name
                if current is job and selected == "execution.json" and directory is not None and not removed:
                    execution.rmdir()
                    removed.append(True)
                return original_fence(current, name, directory)

            with patch.object(jobs.Job, "observe_fence", fence):
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
    original_existing, original_stat, original_run = jobs.Job.observe_existing_fence, os.stat, jobs.run_job
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
    with patch.object(jobs.Job, "observe_existing_fence", existing), patch.object(jobs, "run_job", run):
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
    original_route, original_claim, original_stat = getattr(jobs, route), jobs.Job.claim, os.stat
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
        active.enter_context(patch.object(jobs.Job, "claim", claim))
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
    original_publish, original_observe = jobs.Job.publish_execution_claim, jobs.Job.observe_result
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

    with patch.object(jobs.Job, "publish_execution_claim", publish), patch.object(jobs.Job, "observe_result", observe):
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
    original_existing, original_stat = jobs.Job.observe_existing_fence, os.stat
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

    with patch.object(jobs.Job, "observe_existing_fence", existing):
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
    original_fence, original_existing = jobs.Job.observe_fence, jobs.Job.observe_existing_fence
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
            active.enter_context(patch.object(jobs.Job, "observe_fence", fence))
            active.enter_context(patch.object(jobs.Job, "observe_existing_fence", existing))
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
    original_grant, original_existing, original_stat = jobs.grant_next, jobs.Job.observe_existing_fence, os.stat
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

    with patch.object(jobs, "grant_next", grant), patch.object(jobs.Job, "observe_existing_fence", existing):
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
    original_route, original_claim, original_stat = getattr(jobs, route), jobs.Job.claim, os.stat
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
    original_kind, original_admit = jobs.Job.metadata_kind, jobs.admit
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

    with patch.object(jobs.Job, "metadata_kind", kind), patch.object(jobs, "admit", admit):
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
    original_stat, original_existing = os.stat, jobs.Job.observe_existing_fence
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

    with patch.object(jobs.Job, "observe_existing_fence", existing):
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
    original_kind, original_stat = jobs.Job.metadata_kind, os.stat
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

    with patch.object(jobs.Job, "metadata_kind", kind):
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
    original, original_stat = jobs.Job.observe_existing_fence, os.stat
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

    with patch.object(jobs.Job, "observe_existing_fence", existing):
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
    original_observe, original_existing = jobs.Job.observe_result, jobs.Job.observe_existing_fence
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

    with patch.object(jobs.Job, "observe_result", observe), patch.object(jobs.Job, "observe_existing_fence", existing):
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
    original_existing, original_publish = jobs.Job.observe_existing_fence, jobs.Job.publish_execution_claim
    original_observe, original_close = jobs.Job.observe_result, os.close
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
        active.enter_context(patch.object(jobs.Job, "observe_existing_fence", existing))
        active.enter_context(patch.object(jobs.Job, "publish_execution_claim", publish))
        active.enter_context(patch.object(jobs.Job, "observe_result", observe))
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
    original = jobs.Job.claim
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

    with patch.object(jobs.Job, "claim", claim):
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
    original = jobs.Job.observe_existing_fence
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
        with patch.object(jobs.Job, "observe_existing_fence", existing):
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
