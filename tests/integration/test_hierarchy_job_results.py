"""A later launch failure must not erase completed job effects and their evidence."""
import json
import sys

import pytest

from tests.integration.test_hierarchy_jobs import shop, verified_evidence
from tests.integration.test_hierarchy_recovery import stage_interrupted_job

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the job runner reads /proc")


def test_later_launch_failure_keeps_completed_steps_and_does_not_replay_them(shop):
    missing = str(shop.tmp / "missing-executable")
    first = ["$python", "-c", "print('first step completed'); open(%r, 'a').write('once\\n')" % str(shop.sentinel)]
    shop.recipes["recipes"]["later-launch"] = {
        **shop.command(first), "steps": [first, [missing], ["$python", "-c", "raise AssertionError('must not run')"]],
    }
    shop.save_recipes()
    shop.request_job("job-1", "later-launch")

    [row] = shop.run_open()["rows"]

    assert row["state"] == "failed"
    result = json.loads((shop.workspace.store / "jobs" / "pilot" / "job-1" / "result.json").read_text())
    assert len(result["steps"]) == 1, "the completed first step must survive a second launch failure"
    assert result["steps"][0]["exit_code"] == 0
    assert result["steps"][0]["timed_out"] is False
    assert result["steps"][0]["argv"] == [sys.executable, *first[1:]]
    assert result["failed_launch"]["step"] == 2
    assert result["failed_launch"]["argv"] == [missing]
    assert "No such file or directory" in result["failed_launch"]["error"]
    assert result["process_stopped_confirmed"] is True
    evidence = verified_evidence(shop.receipts("job-1")[-1])
    assert evidence["step-1.log"].read_text() == "first step completed\n"
    assert "step-2.log" in evidence
    assert "step-3.log" not in evidence
    assert shop.run_open()["rows"] == []
    assert shop.sentinel.read_text() == "once\n"
    assert shop.states("job-1") == ["started", "failed"]


def test_successful_steps_keep_the_existing_result_shape(shop):
    first, second = ["$python", "-c", "print('first')"], ["$python", "-c", "print('second')"]
    shop.recipes["recipes"]["success"] = {**shop.command(first), "steps": [first, second]}
    shop.save_recipes()
    shop.request_job("job-1", "success")

    [row] = shop.run_open()["rows"]

    assert row["state"] == "completed"
    result = json.loads((shop.workspace.store / "jobs" / "pilot" / "job-1" / "result.json").read_text())
    assert [step["exit_code"] for step in result["steps"]] == [0, 0]
    assert "failed_launch" not in result


@pytest.mark.parametrize("changes,field", [
    ({"steps": [None]}, "steps[0]"),
    ({"steps": [[]]}, "steps[0]"),
    ({"steps": [{}]}, "steps[0].argv"),
    ({"steps": [{"argv": "pytest", "exit_code": 0}]}, "steps[0].argv"),
    ({"steps": [{"argv": [False], "exit_code": 0}]}, "steps[0].argv"),
    ({"steps": [{"argv": ["pytest"], "exit_code": False}]}, "steps[0].exit_code"),
    ({"steps": [{"argv": ["pytest"], "exit_code": 0, "stopped_leftovers": "yes"}]},
     "steps[0].stopped_leftovers"),
    ({"reason": []}, "reason"),
    ({"commit": {}}, "commit"),
    ({"tests": []}, "tests"),
    ({"tests": {"total": True}}, "tests.total"),
    ({"tests": {"total": 1}}, "tests.passed"),
    ({"kept": "output"}, "kept"),
    ({"kept": [None]}, "kept[0]"),
    ({"kept": [{"error": "missing"}]}, "kept[0].path"),
    ({"kept": [{"path": "output", "error": []}]}, "kept[0].error"),
    ({"process_stopped_confirmed": "true"}, "process_stopped_confirmed"),
], ids=["null-step", "array-step", "missing-argv", "string-argv", "boolean-arg", "boolean-exit",
        "string-leftovers", "array-reason", "object-commit", "array-tests", "boolean-count", "missing-count",
        "string-kept", "null-kept", "missing-kept-path", "array-kept-error", "string-stop-confirmation"])
def test_malformed_durable_result_holds_capacity_without_receipt_or_replay(shop, changes, field):
    folder, _ = stage_interrupted_job(shop, result={"process_stopped_confirmed": True, **changes})
    before, events = (folder / "result.json").read_bytes(), shop.events()

    for _ in range(2):
        [row] = shop.run_open(expect=3)["rows"]
        assert row["state"] == "settle_pending"
        assert row["error"] == "invalid job result " + field
        assert shop.heavy()["used"] == 1
        assert shop.receipts("engine-partial") == []
        assert shop.events() == events
        assert (folder / "result.json").read_bytes() == before
        assert not list(folder.glob("step-*.log")), "a malformed result must never replay a completed job"


def test_legacy_minimal_step_result_can_settle_without_replaying(shop):
    folder, _ = stage_interrupted_job(shop, result={
        "steps": [{"argv": ["pytest"], "exit_code": 0}], "process_stopped_confirmed": True,
        "future_field": {"diagnostic": "kept"},
    })

    [row] = shop.run_open()["rows"]

    assert row["state"] == "completed"
    assert shop.heavy()["used"] == 0
    assert shop.states("engine-partial") == ["completed"]
    assert not list(folder.glob("step-*.log"))
    assert shop.run_open()["rows"] == []
