"""A later launch failure must not erase completed job effects and their evidence."""
import json
import sys

import pytest

from tests.integration.test_hierarchy_jobs import shop, verified_evidence

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

