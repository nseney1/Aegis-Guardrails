"""Shell-less commit packets bind the runner's admit-time source to the exact commit."""
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

import pytest

from tests.integration.test_hierarchy_jobs import (JOBS, commit_request, first_job, load_jobs_module, needs_bubblewrap,  # noqa: F401
                                                   shop, recorded, source_digest, verified_evidence)
from tests.integration.test_hierarchy_jobs import pytestmark as pytestmark
from tests.integration.test_hierarchy_mailbox import git
from tests.integration.test_hierarchy_workspace import Workspace, write_lease


PATHS = ["src/app.py", "tests/test_app.py"]


def host_plan(shop, **changes):
    plan = {"schema": "aegis.hierarchy-host-plan/v1", "hierarchy": "pilot", "root": "codex-cli",
            "team": "claude-code", "stand_ins": {}, "config_sha256": "a" * 64, **changes}
    path = shop.base / "host-plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return path


def edit_source(shop):
    (shop.checkout / "src" / "app.py").write_text("value = 2\n")
    (shop.checkout / "tests" / "test_app.py").write_text("def test_app():\n    assert True\n")
    (shop.checkout / "src" / "other.py").write_text("outside the requested paths\n")


def staged_tree(shop):
    with tempfile.TemporaryDirectory(dir=shop.tmp) as folder:
        env = {**os.environ, "GIT_INDEX_FILE": folder + "/index", "GIT_LITERAL_PATHSPECS": "1",
               "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        for args in (("read-tree", "HEAD"), ("add", "--", *PATHS), ("write-tree",)):
            result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args],
                                    cwd=shop.checkout, env=env, capture_output=True, text=True, check=True, timeout=10)
        return result.stdout.strip()


def request_derive(shop, **changes):
    return shop.request_job("job-1", "commit-exact", derive="runner", paths=PATHS,
                            message="fix: shell-less source", **changes)


@pytest.fixture
def claude_shop(shop):
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    return shop


@pytest.mark.parametrize("sandbox", ["none", pytest.param("bwrap", marks=needs_bubblewrap)])
def test_derive_commits_exact_paths_and_records_the_runner_values(claude_shop, sandbox):
    shop = claude_shop
    shop.recipes["recipes"]["commit-exact"]["sandbox"] = sandbox
    shop.save_recipes()
    edit_source(shop)
    before = shop.head()
    digest, tree = source_digest(shop)["dirty_content_sha256"], staged_tree(shop)
    plan = shop.base / "host-plan.json"
    request_derive(shop)
    assert shop.run_open()["rows"][0]["state"] == "completed"
    result = recorded(shop)
    evidence = verified_evidence(shop.receipts("job-1")[-1])
    assert json.loads(evidence["result.json"].read_text()) == result
    assert result["derived_by"] == "runner"
    assert result["dirty_content_sha256"] == result["before"]["dirty_content_sha256"] == digest
    assert result["expected_tree"] == result["after"]["source_tree"] == tree
    assert result["host_plan"] == {"path": str(plan), "sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
                                    "team": "claude-code"}
    derivation = json.loads(evidence["derivation.json"].read_text())
    assert all(derivation[key] == result[key]
               for key in ("derived_by", "dirty_content_sha256", "expected_tree", "host_plan"))
    assert derivation["changed_paths"] == PATHS
    assert git(shop.checkout, "rev-parse", "HEAD^") == before["commit"]
    assert git(shop.checkout, "rev-parse", "HEAD^{tree}") == tree
    assert sorted(git(shop.checkout, "show", "--format=", "--name-only", "HEAD").splitlines()) == PATHS
    assert git(shop.checkout, "status", "--porcelain=v1") == "?? src/other.py"


def test_an_edit_between_admit_and_run_refuses_without_moving_head_or_index(claude_shop):
    shop = claude_shop
    edit_source(shop)
    git(shop.checkout, "add", "--", "tests/test_app.py")
    head, index = shop.head()["commit"], (shop.checkout / ".git" / "index").read_bytes()
    digest, tree = source_digest(shop)["dirty_content_sha256"], staged_tree(shop)
    first_job(shop, "import pathlib, sys; pathlib.Path(sys.argv[1], 'src/app.py').write_text('value = 3\\n')",
              dirty_content_sha256=digest)
    request_derive(shop)
    row = next(row for row in shop.run_open()["rows"] if row["job"] == "pilot/job-1")
    assert row["state"] == "refused" and "it changed while the job waited" in row["reason"], row
    result = recorded(shop)
    assert result["steps"] == [] and result["derived_by"] == "runner"
    assert result["dirty_content_sha256"] == digest and result["expected_tree"] == tree
    receipt_evidence = verified_evidence(shop.receipts("job-1")[-1])
    assert set(receipt_evidence) >= {"derivation.json", "result.json"}
    assert json.loads(receipt_evidence["result.json"].read_text()) == result
    evidence = json.loads(receipt_evidence["derivation.json"].read_text())
    assert evidence["dirty_content_sha256"] == digest and evidence["expected_tree"] == tree
    assert git(shop.checkout, "rev-parse", "HEAD") == head
    assert (shop.checkout / ".git" / "index").read_bytes() == index


@pytest.mark.parametrize("edit", [False, True])
def test_first_admission_survives_a_job_limit_and_later_polls(claude_shop, edit):
    shop = claude_shop
    edit_source(shop)
    digest, tree = source_digest(shop)["dirty_content_sha256"], staged_tree(shop)
    shop.request_job("job-0", "ok", dirty_content_sha256=digest)
    request_derive(shop)
    head, index = shop.head()["commit"], (shop.checkout / ".git" / "index").read_bytes()
    answer = shop.run_open("--max-jobs", "1", expect=3)
    assert [(r["job"], r["state"]) for r in answer["rows"]] == [("pilot/job-0", "completed"), ("pilot/job-1", "waiting")]
    folder = shop.workspace.store / "jobs" / "pilot" / "job-1"
    admitted_bytes = (folder / "derivation.json").read_bytes()
    admitted = json.loads(admitted_bytes)
    assert admitted["dirty_content_sha256"] == digest and admitted["expected_tree"] == tree
    recovery = shop.jobs("recovery-status", expect=3)["jobs"]
    source = next(row["source"] for row in recovery if row["job"] == "pilot/job-1")
    assert source["state"] == "match" and source["expected"]["dirty_content_sha256"] == digest
    if edit:
        (shop.checkout / "src" / "app.py").write_text("value = 99\n")
    row = shop.run_open()["rows"][0]
    assert row["state"] == ("refused" if edit else "completed"), row
    assert (folder / "derivation.json").read_bytes() == admitted_bytes
    result = recorded(shop)
    assert result["dirty_content_sha256"] == digest and result["expected_tree"] == tree
    evidence = verified_evidence(shop.receipts("job-1")[-1])
    assert {"derivation.json", "result.json"} <= set(evidence)
    if edit:
        assert "source does not match the packet" in row["reason"]
        assert git(shop.checkout, "rev-parse", "HEAD") == head
        assert (shop.checkout / ".git" / "index").read_bytes() == index
    else:
        assert git(shop.checkout, "rev-parse", "HEAD^{tree}") == tree
        assert shop.run_open()["rows"] == []


def waiting_admission(shop):
    """A completed first invocation leaves a saved admission and a dead original runner."""
    edit_source(shop)
    shop.request_job("job-0", "ok", dirty_content_sha256=source_digest(shop)["dirty_content_sha256"])
    request_derive(shop)
    assert shop.run_open("--max-jobs", "1", expect=3)["rows"][-1]["state"] == "waiting"
    return (shop.workspace.store / "jobs" / "pilot" / "job-1", shop.head()["commit"],
            (shop.checkout / ".git" / "index").read_bytes())


def test_resolve_after_readmission_prevents_the_resumed_commit(claude_shop, monkeypatch):
    shop = claude_shop
    folder, head, index = waiting_admission(shop)
    jobs = load_jobs_module()
    original_run = jobs.run_job
    original_write = jobs.write_result
    resolved = []
    ready = []
    blocked = []

    def execute_between_result_and_receipt(job, state, exit_code, **extra):
        original_write(job, state, exit_code, **extra)
        if extra.get("resolved_by_root"):
            # Root has written failed but has not receipted it yet. Dispatch the already-admitted execution here:
            # before the fix it could publish started, commit, and then collide with this durable failed result.
            try:
                original_run(*ready[0])
            except jobs.ERRORS as exc:
                blocked.append(str(exc))

    def resolve_before_dispatch(store, job, packet, raw, recipes, wait):
        # The second invocation has already re-admitted the request, but has not taken execution custody.
        assert job.id == "pilot/job-1" and not job.execution_path.exists()
        ready.append((store, job, packet, raw, recipes, wait))
        _code, row = jobs.resolve(str(shop.workspace.store), job.id, "root resolved while waiting", 0)
        resolved.append(row)
        # Once root releases the disposition lock, the post-claim terminal check must still prevent execution.
        return original_run(store, job, packet, raw, recipes, wait)

    monkeypatch.setattr(jobs, "write_result", execute_between_result_and_receipt)
    monkeypatch.setattr(jobs, "run_job", resolve_before_dispatch)
    code, answer = jobs.run_open(str(shop.workspace.store), str(shop.recipes_path), [], 20, [], 0)
    assert resolved[0]["state"] == "failed"
    assert git(shop.checkout, "rev-parse", "HEAD") == head, "a terminal resolution must exclude a later commit"
    assert (shop.checkout / ".git" / "index").read_bytes() == index
    assert len(blocked) == 1 and "job disposition is busy" in blocked[0]
    assert code == 0 and answer["rows"][0]["state"] == "failed", answer
    result = recorded(shop)
    assert result["resolved_by_root"] is True and result["commit"] is None
    assert shop.states("job-1") == ["failed"]
    evidence = verified_evidence(shop.receipts("job-1")[-1])
    assert json.loads(evidence["result.json"].read_text()) == result
    assert not (folder / "step-5.log").exists(), "execution must not launch after the resolution"


def test_resolver_excludes_execution_and_other_resolvers_until_its_result_is_durable(claude_shop, monkeypatch):
    shop = claude_shop
    folder, head, index = waiting_admission(shop)
    jobs = load_jobs_module()
    original_write = jobs.write_result
    contenders = []

    def contend_before_terminal_write(job, state, exit_code, **extra):
        # The resolver has checked the dead original runner, but has not yet published result.json.
        assert extra.get("resolved_by_root") is True and not job.result_path.exists()
        contenders.append(shop.run_open(expect=3)["rows"][0])
        assert contenders[-1]["state"] == "settle_pending"
        assert "job disposition is busy" in contenders[-1]["error"]
        refused = shop.jobs("resolve", "--job", job.id, "--reason", "second resolver", expect=2)
        assert "job disposition is busy" in refused["error"]
        assert not job.execution_path.exists()
        return original_write(job, state, exit_code, **extra)

    monkeypatch.setattr(jobs, "write_result", contend_before_terminal_write)
    code, row = jobs.resolve(str(shop.workspace.store), "pilot/job-1", "root closing waiting job", 0)
    assert code == 0 and row["state"] == "failed"
    assert len(contenders) == 1
    assert git(shop.checkout, "rev-parse", "HEAD") == head
    assert (shop.checkout / ".git" / "index").read_bytes() == index
    assert json.loads((folder / "result.json").read_text())["resolved_by_root"] is True
    assert shop.states("job-1") == ["failed"]


def test_live_execution_claim_excludes_resolve_between_stopped_steps(claude_shop, monkeypatch):
    shop = claude_shop
    folder, head, _index = waiting_admission(shop)
    jobs = load_jobs_module()
    original_execute = jobs.execute
    refused = []

    def resolve_before_steps(job, *args, **kwargs):
        assert job.execution_path.exists() and job.runner_alive() is True
        assert not jobs.group_members(job.process_group()), "the staging steps already stopped"
        refused.append(shop.jobs("resolve", "--job", job.id, "--reason", "must not resolve live execution", expect=2))
        assert "its runner is still running" in refused[-1]["error"]
        assert not job.result_path.exists()
        return original_execute(job, *args, **kwargs)

    monkeypatch.setattr(jobs, "execute", resolve_before_steps)
    code, answer = jobs.run_open(str(shop.workspace.store), str(shop.recipes_path), [], 20, [], 0)
    assert code == 0 and answer["rows"][0]["state"] == "completed", answer
    assert len(refused) == 1
    assert git(shop.checkout, "rev-parse", "HEAD^") == head
    assert json.loads((folder / "result.json").read_text())["state"] == "completed"
    assert shop.states("job-1") == ["started", "completed"]


@pytest.mark.parametrize("alive, raise_error", [(False, True), (True, True), (True, False)])
def test_uncertain_derivation_stays_in_job_custody_until_resolved(claude_shop, alive, raise_error):
    shop = claude_shop
    edit_source(shop)
    request_derive(shop)
    if alive:
        shop.recipes["prefix"] = [sys.executable, "-c", "import time; time.sleep(30)"]
        shop.recipes["recipes"]["commit-exact"]["timeout_seconds"] = 1
        shop.save_recipes()
    pid_file = shop.tmp / "uncertain-pid"
    program = ("import importlib.util,json,sys\nfrom pathlib import Path\n"
               "spec=importlib.util.spec_from_file_location('jobs_fault',sys.argv[1])\n"
               "jobs=importlib.util.module_from_spec(spec); spec.loader.exec_module(jobs)\n"
               "real_stop=jobs.stop_for_certain\n"
               "def uncertain(process):\n"
               "    Path(sys.argv[4]).write_text(str(process.pid))\n"
               "    if sys.argv[5] == 'False': real_stop(process)\n"
               "    if sys.argv[6] == 'True': raise jobs.StillRunning(process.pid,'injected uncertain OS stop')\n"
               "jobs.stop_for_certain=uncertain\n"
               "code,result=jobs.run_open(sys.argv[2],sys.argv[3],[],20,[],0)\n"
               "print(json.dumps(result)); sys.exit(code)\n")
    head, index = shop.head()["commit"], (shop.checkout / ".git" / "index").read_bytes()
    pid = None
    try:
        answer = subprocess.run([sys.executable, "-I", "-c", program, str(JOBS), str(shop.workspace.store),
                                 str(shop.recipes_path), str(pid_file), str(alive), str(raise_error)],
                                capture_output=True, text=True, timeout=15, env=shop.env())
        if pid_file.exists():
            pid = int(pid_file.read_text())
        assert answer.returncode == 3, answer.stdout + answer.stderr
        row = json.loads(answer.stdout)["rows"][0]
        assert row["state"] in ("abandoned", "waiting"), row
        folder = shop.workspace.store / "jobs" / "pilot" / "job-1"
        assert (folder / "claim.json").is_file() and (folder / "process.json").is_file()
        assert json.loads((folder / "process.json").read_text())["group"] == pid
        assert not (folder / "result.json").exists()
        assert "job-1" in shop.open_jobs()
        assert shop.run_open(expect=3)["rows"][0]["state"] == "abandoned"
        assert "refused" not in shop.states("job-1")
        if alive:
            refused = shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "test reconciliation", expect=2)
            assert "still running" in refused["error"]
        assert git(shop.checkout, "rev-parse", "HEAD") == head
        assert (shop.checkout / ".git" / "index").read_bytes() == index
    finally:
        if pid is not None:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            jobs = load_jobs_module()
            deadline = time.monotonic() + 5
            while jobs.group_members(pid):
                assert time.monotonic() < deadline, "test staging process survived cleanup"
                time.sleep(0.01)
    assert shop.jobs("resolve", "--job", "pilot/job-1", "--reason", "test confirmed process stopped")["state"] == "failed"


def test_an_alternate_mailbox_cannot_borrow_the_canonical_plan(claude_shop):
    shop = claude_shop
    edit_source(shop)
    request_derive(shop)
    alternate = shop.base / "alternate-mailbox"
    shutil.copytree(shop.root, alternate)
    other_store = shop.tmp / "alternate-registration"
    other_store.mkdir()
    shop.workspace = Workspace(other_store)
    shop.workspace.run("init", {"writer_limit": 3, "heavy_limit": 1})
    shop.workspace.register("pilot", mailbox_root=str(alternate), checkouts=[str(shop.checkout)])
    head = shop.head()["commit"]
    row = shop.run_open()["rows"][0]
    assert row["state"] == "refused" and "derive is for shell-less teams" in row["reason"], row
    assert git(shop.checkout, "rev-parse", "HEAD") == head


def test_an_incomplete_plan_does_not_authorize_derive(claude_shop):
    shop = claude_shop
    (shop.base / "host-plan.json").write_text(json.dumps({"schema": "aegis.hierarchy-host-plan/v1",
                                                       "hierarchy": "pilot", "team": "claude-code"}))
    edit_source(shop)
    request_derive(shop)
    row = shop.run_open()["rows"][0]
    assert row["state"] == "refused" and "host plan is missing" in row["reason"], row


def test_a_folder_path_cannot_stage_unlisted_files(claude_shop):
    shop = claude_shop
    edit_source(shop)
    head, index = shop.head()["commit"], (shop.checkout / ".git" / "index").read_bytes()
    shop.request_job("job-1", "commit-exact", derive="runner", paths=["src"], message="fix: folder request")
    row = shop.run_open()["rows"][0]
    assert row["state"] == "refused" and row["reason"] == (
        "derive staged files outside paths: src/app.py, src/other.py"), row
    evidence = verified_evidence(shop.receipts("job-1")[-1])
    derivation = json.loads(evidence["derivation.json"].read_text())
    assert derivation["changed_paths"] == ["src/app.py", "src/other.py"]
    assert git(shop.checkout, "rev-parse", "HEAD") == head
    assert (shop.checkout / ".git" / "index").read_bytes() == index


def test_source_must_match_the_witness_after_staging(claude_shop):
    shop = claude_shop
    edit_source(shop)
    wrapper = shop.tmp / "git-boundary.py"
    wrapper.write_text("import pathlib, subprocess, sys\n"
                       "result = subprocess.run(sys.argv[1:])\n"
                       "if 'add' in sys.argv[1:] and result.returncode == 0:\n"
                       "    pathlib.Path('src/app.py').write_text('value = 33\\n')\n"
                       "sys.exit(result.returncode)\n")
    shop.recipes["prefix"] = [sys.executable, str(wrapper)]
    shop.save_recipes()
    head = shop.head()["commit"]
    request_derive(shop)
    row = shop.run_open()["rows"][0]
    assert row["state"] == "refused" and row["reason"] == "source changed during derivation", row
    assert git(shop.checkout, "rev-parse", "HEAD") == head


def test_a_derived_no_op_is_refused(claude_shop):
    shop = claude_shop
    head, index = shop.head()["commit"], (shop.checkout / ".git" / "index").read_bytes()
    request_derive(shop)
    row = shop.run_open()["rows"][0]
    assert (row["state"], row["reason"]) == ("refused", "this commit would make no change")
    assert git(shop.checkout, "rev-parse", "HEAD") == head
    assert (shop.checkout / ".git" / "index").read_bytes() == index


@pytest.mark.parametrize("kind", ["command", "merge"])
def test_derive_is_refused_on_other_recipe_kinds(claude_shop, kind):
    shop = claude_shop
    shop.recipes["recipes"]["other"] = (shop.command(["$python", "-c", "print('must not run')"]) if kind == "command"
                                         else {"kind": "merge", "sandbox": "none", "timeout_seconds": 30})
    shop.save_recipes()
    shop.request_job("job-1", "other", derive="runner")
    row = shop.run_open()["rows"][0]
    assert (row["state"], row["reason"]) == ("refused", "only a commit recipe takes derive")


@pytest.mark.parametrize("value", ["lane", "", None, True, {}, ["runner"]])
def test_bad_derive_values_are_refused(claude_shop, value):
    shop = claude_shop
    packet = {"schema": "aegis.hierarchy-job-packet/v1", "recipe": "commit-exact", **shop.head(), "paths": PATHS,
              "message": "fix: bad derive", "derive": value}
    shop.request_job("job-1", "commit-exact", raw=json.dumps(packet))
    row = shop.run_open()["rows"][0]
    assert (row["state"], row["reason"]) == ("refused", "derive must be runner")


def test_a_packet_with_explicit_fields_keeps_the_existing_contract(shop):
    tree = commit_request(shop)
    digest = source_digest(shop)["dirty_content_sha256"]
    assert shop.run_open()["rows"][0]["state"] == "completed"
    result = recorded(shop)
    assert result["before"]["dirty_content_sha256"] == digest
    assert result["after"]["source_tree"] == tree
    assert "derived_by" not in result and "host_plan" not in result


def test_missing_expected_tree_without_derive_keeps_the_existing_refusal(shop):
    commit_request(shop, expected_tree=None)
    row = shop.run_open()["rows"][0]
    assert row["state"] == "refused" and "commit recipe needs expected_tree and message" in row["reason"]
    assert "evidence" not in shop.receipts("job-1")[-1]["receipt"]


def test_staging_failure_receipts_bind_the_available_derivation_evidence(claude_shop):
    shop = claude_shop
    edit_source(shop)
    head, index = shop.head()["commit"], (shop.checkout / ".git" / "index").read_bytes()
    digest = source_digest(shop)["dirty_content_sha256"]
    shop.request_job("job-1", "commit-exact", derive="runner", paths=["src/missing.py"], message="fix: missing")
    row = shop.run_open()["rows"][0]
    assert (row["state"], row["reason"]) == ("refused", "could not derive expected_tree: step 2 exited 128")
    evidence = verified_evidence(shop.receipts("job-1")[-1])
    derived = json.loads(evidence["derivation.json"].read_text())
    assert derived["dirty_content_sha256"] == digest
    assert derived["expected_tree"] is None and derived["changed_paths"] is None
    assert "pathspec" in evidence["step-2.log"].read_text()
    assert git(shop.checkout, "rev-parse", "HEAD") == head
    assert (shop.checkout / ".git" / "index").read_bytes() == index


def test_a_canonical_mailbox_must_agree_with_its_provision_record(claude_shop):
    shop = claude_shop
    setup_path = shop.base / "provision.json"
    setup = json.loads(setup_path.read_text())
    setup["mailbox_root"] = str(shop.base / "other-mailbox")
    setup_path.write_text(json.dumps(setup))
    edit_source(shop)
    request_derive(shop)
    row = shop.run_open()["rows"][0]
    assert row["state"] == "refused" and "registered mailbox does not match provision.json" in row["reason"], row


def test_a_symlink_plan_is_refused(claude_shop):
    shop = claude_shop
    plan = shop.base / "host-plan.json"
    target = shop.tmp / "plan.json"
    plan.rename(target)
    plan.symlink_to(target)
    edit_source(shop)
    request_derive(shop)
    row = shop.run_open()["rows"][0]
    assert row["state"] == "refused" and "host plan must not be a symlink" in row["reason"], row


@pytest.mark.parametrize("changes", [{"team": "codex-cli"}, {"team": "codex"}, {"hierarchy": "other"},
                                    {"schema": "other"}, None, "malformed"])
def test_derive_requires_the_initiatives_claude_team_plan(claude_shop, changes):
    shop = claude_shop
    if changes is None:
        (shop.base / "host-plan.json").unlink()
    elif changes == "malformed":
        (shop.base / "host-plan.json").write_text("{")
    else:
        host_plan(shop, **changes)
    edit_source(shop)
    head, index = shop.head()["commit"], (shop.checkout / ".git" / "index").read_bytes()
    request_derive(shop)
    row = shop.run_open()["rows"][0]
    assert row["state"] == "refused" and "derive is for shell-less teams" in row["reason"], row
    assert git(shop.checkout, "rev-parse", "HEAD") == head
    assert (shop.checkout / ".git" / "index").read_bytes() == index


def test_derive_still_refuses_paths_owned_by_another_lease(claude_shop):
    shop = claude_shop
    edit_source(shop)
    write_lease(shop.checkout, "someone-else", ["tests/test_app.py"])
    head, index = shop.head()["commit"], (shop.checkout / ".git" / "index").read_bytes()
    request_derive(shop)
    row = shop.run_open()["rows"][0]
    assert row["state"] == "refused" and "paths overlap another lease" in row["reason"], row
    assert "someone-else" in row["reason"]
    assert git(shop.checkout, "rev-parse", "HEAD") == head
    assert (shop.checkout / ".git" / "index").read_bytes() == index


@pytest.mark.parametrize("field, value, reason", [("dirty_content_sha256", "0" * 64, "source does not match the packet"),
                                                ("expected_tree", "0" * 40, "tree")])
def test_derive_does_not_discard_explicit_bindings(claude_shop, field, value, reason):
    shop = claude_shop
    edit_source(shop)
    head, index = shop.head()["commit"], (shop.checkout / ".git" / "index").read_bytes()
    request_derive(shop, **{field: value})
    row = shop.run_open()["rows"][0]
    assert row["state"] in ("refused", "failed") and reason in row["reason"], row
    assert git(shop.checkout, "rev-parse", "HEAD") == head
    assert (shop.checkout / ".git" / "index").read_bytes() == index
