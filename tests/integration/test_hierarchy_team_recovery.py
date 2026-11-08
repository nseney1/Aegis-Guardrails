"""Team teardown retains custody when job completion or configuration is uncertain."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_team import REVIEWER, Run, git, in_process


pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the team runner reads /proc")


@pytest.fixture
def run(tmp_path, monkeypatch):
    return Run(tmp_path, monkeypatch)


def test_down_keeps_resources_for_a_job_interrupted_before_its_result(run):
    run.team("init")
    # A crash after creating the job folder and before writing the claim/result
    # leaves exactly this durable state. The public jobs clean command reports it
    # as not_finished, even when no runner can be observed.
    job = run.run / "store" / "jobs" / "pilot" / "interrupted"
    job.mkdir(parents=True)
    before = run.leases()
    answer = run.team("down", expect=3)
    assert answer["error"] == "unfinished jobs retain this run's leases, slots and worktrees"
    assert run.leases() == before
    assert (run.run / "worktrees" / "f2").is_dir()
    assert run.workspace("status")["capacity"]["writer"]["holders"]


def test_down_refuses_changed_config_before_removing_another_worktree(run):
    run.team("init")
    unrelated = run.tmp / "unrelated"
    git(run.project, "worktree", "add", "-q", "-b", "feature/unrelated", str(unrelated), run.base)
    run.config["lanes"][0]["worktree"] = str(unrelated)
    run.save()
    before = run.leases()
    answer = run.team("down", expect=2)
    assert answer["error"] == "run custody changed since init; restore the recorded configuration"
    assert unrelated.is_dir() and (run.run / "worktrees" / "f2").is_dir()
    assert run.leases() == before


def test_a_finished_run_cannot_restart_roles_against_archived_evidence(run):
    run.team("init")
    run.team("root", "--session", "root-session")
    run.team("down")
    answer = run.team("up", "--no-loop", expect=2)
    assert answer["error"] == "teardown has started; a new run needs a new run folder"
    assert run.calls("start") == []


def test_partial_init_cannot_continue_after_teardown_has_started(run):
    run.config["preflight"]["expect"]["targeted-tests"]["min_passed"] = 5
    run.save()
    assert run.team("init", expect=3)["step"] == "preflight"
    run.team("down")
    run.config["preflight"]["expect"]["targeted-tests"]["min_passed"] = 1
    run.save()
    answer = run.team("init", "--continue", expect=2)
    assert answer["error"] == "teardown has started; a new run needs a new run folder"


def test_init_continue_does_not_repeat_a_slot_request_after_its_reply_is_lost(run, monkeypatch, capsys):
    executed = []
    original = subprocess.run

    def lose_reply(argv, *args, **kwargs):
        result = original(argv, *args, **kwargs)
        if any(str(word).endswith("hierarchy_workspace.py") for word in argv) and "request" in argv:
            executed.append(list(argv))
            if len(executed) == 1:
                assert result.returncode == 0
                raise OSError("fixture: slot request reply lost")
        return result

    monkeypatch.setattr(subprocess, "run", lose_reply)
    code, failure = in_process(run, "init", capsys=capsys)
    assert code == 3 and failure["error"] == "fixture: slot request reply lost"
    assert len(executed) == 1
    code, held = in_process(run, "init", "--continue", capsys=capsys)
    assert code == 3, held
    assert held["error"] == ("init step slot-request:f2 has an unresolved outcome; "
                             "inspect durable records before continuing")
    assert len(executed) == 1
    code, cleanup = in_process(run, "down", capsys=capsys)
    assert code == 3
    assert cleanup["error"] == "init has an unresolved outcome; resources were kept for inspection"
    assert len(executed) == 1


@pytest.mark.parametrize("missing", ["recipes.json", "store"])
def test_down_keeps_resources_when_job_cleanup_inputs_are_missing(run, missing):
    run.team("init")
    job = run.run / "store" / "jobs" / "pilot" / "interrupted"
    job.mkdir(parents=True)
    before = run.leases()
    source = run.run / missing
    source.rename(run.run / (missing + "-retained"))
    answer = run.team("down", expect=3)
    assert answer["error"] == "job cleanup inputs are unavailable; resources were kept for inspection"
    assert run.leases() == before
    assert (run.run / "worktrees" / "f2").is_dir()


@pytest.mark.parametrize("payload", [{}, {"not_finished": None}, {"not_finished": ""}])
def test_down_keeps_resources_when_job_cleanup_reporting_is_malformed(run, monkeypatch, capsys, payload):
    run.team("init")
    job = run.run / "store" / "jobs" / "pilot" / "interrupted"
    job.mkdir(parents=True)
    before = run.leases()
    original = subprocess.run
    seen = []

    def bad_report(argv, *args, **kwargs):
        result = original(argv, *args, **kwargs)
        if any(str(word).endswith("hierarchy_jobs.py") for word in argv) and "clean" in argv:
            seen.append(list(argv))
            assert result.returncode == 0
            return subprocess.CompletedProcess(result.args, 0, json.dumps(payload), result.stderr)
        return result

    monkeypatch.setattr(subprocess, "run", bad_report)
    code, answer = in_process(run, "down", capsys=capsys)
    assert code == 3, answer
    assert answer["error"] == "jobs clean returned invalid completion evidence; resources were kept for inspection"
    assert len(seen) == 1
    assert run.leases() == before
    assert (run.run / "worktrees" / "f2").is_dir()


def test_owner_turn_retains_its_marker_after_a_lost_reply(run, monkeypatch, capsys):
    run.ready("--no-loop")
    original = subprocess.Popen
    executed = []
    marker = run.mailbox().wake_marker(REVIEWER)

    def lose_reply(argv, *args, **kwargs):
        result = original(argv, *args, **kwargs)
        if argv[0] == "codex":
            executed.append(list(argv))
            wait = result.wait

            def lost_reply(*args, **kwargs):
                wait(*args, **kwargs)
                assert result.returncode == 0
                raise OSError("fixture: owner turn reply lost")

            result.wait = lost_reply
        return result

    monkeypatch.setattr(subprocess, "Popen", lose_reply)
    for key, value in run.env().items():
        monkeypatch.setenv(key, value)
    code, answer = in_process(run, "turn", REVIEWER, "Check in.", capsys=capsys)
    assert code == 3
    operation = answer["operation"]
    assert isinstance(operation["id"], str) and operation["id"]
    state_path = run.run / "team-state.json"
    retained_state = state_path.read_bytes()
    assert json.loads(retained_state)["operations"][REVIEWER] == operation
    assert answer["error"] == (
        "operation %s is unresolved: fixture: owner turn reply lost; "
        "team-state and output retained; inspect before reconciliation" % operation["id"])
    assert len(executed) == 1
    assert marker.exists(), "a lost reply cannot establish that the turn never ran"
    retained_marker = marker.read_bytes()
    paths = [Path(operation["stdout"]), Path(operation["stderr"]), run.evidence / operation["turn_log"]]
    assert all(path.parent == run.evidence for path in paths)
    retained_output = {path: path.read_bytes() for path in paths}
    code, answer = in_process(run, "turn", REVIEWER, "Check in again.", capsys=capsys)
    assert code == 2
    assert answer["error"] == (
        "%s has unresolved operation %s; inspect status, then use approve/turn --reconcile; "
        "never replay an unknown turn" % (REVIEWER, operation["id"]))
    assert answer["operation"] == operation
    assert len(executed) == 1
    assert marker.exists() and marker.read_bytes() == retained_marker
    assert state_path.read_bytes() == retained_state
    assert {path: path.read_bytes() for path in paths} == retained_output
