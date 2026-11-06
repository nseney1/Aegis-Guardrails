"""Malformed process reports hold their step without hiding durable effects or stopping other work."""
import json
import sys

import pytest

pytest.importorskip("fcntl", reason="the loop owns POSIX journal locks")
from tests.integration.test_hierarchy_loop import (  # noqa: E402
    EMPTY_SWEEP, ROOT, answering, holds, request, step_states, world,
)

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the loop runs jobs through /proc")


@pytest.mark.parametrize("tool,command,code,payload,field", [
    ("router", "status", 0, {}, "router"),
    ("router", "status", 0, {"router": False, "requests": []}, "router"),
    ("router", "status", 0, {"router": "router-1", "requests": None}, "requests"),
    ("router", "status", 0, {"router": "router-1", "requests": [None]}, "requests[0]"),
    ("router", "status", 0, {"router": "router-1", "requests": [{"request_id": "r"}]}, "requests[0].state"),
    ("router", "status", 0, {"router": "router-1", "requests": [], "escalations": [{}]}, "escalations[0].request_id"),
    ("router", "status", 2, {"error": []}, "error"),
    ("router", "route", 0, {}, "routed"),
    ("router", "route", 0, {"routed": [{}], "requests": []}, "routed[0].request_id"),
    ("router", "route", 0, {"routed": [], "requests": [3]}, "requests[0]"),
    ("router", "route", 0, {"routed": [], "requests": None}, "report_error"),
    ("router", "route", 2, {}, "error"),
    ("sweep", "--durable", 0, {}, "rows"),
    ("sweep", "--durable", 0, {**EMPTY_SWEEP, "rows": [None]}, "rows[0]"),
    ("sweep", "--durable", 3, {**EMPTY_SWEEP, "rows": [{"state": []}]}, "rows[0].state"),
    pytest.param("sweep", "--durable", 0, {**EMPTY_SWEEP, "rows": [
        {"state": "mailbox_error", "initiative": "pilot", "wake_exit": 0}]}, "rows[0].endpoint", id="wake-without-endpoint"),
    pytest.param("sweep", "--durable", 0, {**EMPTY_SWEEP, "rows": [
        {"state": "unknown", "initiative": "pilot", "endpoint": "pilot/lane/f2", "wake_exit": 0}]},
        "rows[0].state", id="unknown-wake-state"),
    ("sweep", "--durable", 0, {**EMPTY_SWEEP, "still_unread": [{}]}, "still_unread[0].initiative"),
    ("sweep", "--durable", 0, {**EMPTY_SWEEP, "root_queue": [
        {"initiative": "pilot", "endpoint": "pilot/root", "unread_count": True, "open_jobs": 0}]},
     "root_queue[0].unread_count"),
    ("sweep", "--durable", 3, {**EMPTY_SWEEP, "silent_roles": [{}]}, "silent_roles[0].initiative"),
    ("sweep", "--durable", 3, {**EMPTY_SWEEP, "stalled_dispatches": [False]}, "stalled_dispatches[0]"),
    ("sweep", "--durable", 3, {**EMPTY_SWEEP, "root_time": [{}]}, "root_time[0].state"),
    pytest.param("sweep", "--durable", 3, {**EMPTY_SWEEP, "root_time": [{"state": "unknown"}]},
        "root_time[0].state", id="unknown-root-time-state"),
    ("sweep", "--durable", 2, {"error": None}, "error"),
    ("jobs", "run-open", 0, {}, "rows"),
    ("jobs", "run-open", 3, {"rows": [None]}, "rows[0]"),
    ("jobs", "run-open", 0, {"rows": [{"state": "completed", "job": 3}]}, "rows[0].job"),
    ("jobs", "run-open", 2, {}, "error"),
])
def test_malformed_child_contract_holds_and_independent_steps_continue(world, tool, command, code, payload, field):
    outputs = {command: (code, payload)}
    if command == "route":
        outputs["status"] = (0, {"router": "router-1", "requests": [{"request_id": "r", "state": "ready"}]})
    child = answering(world, "malformed-child.py", outputs)

    result = world.once(expect=3, swap=(tool, child))

    step = {"status": "router_status", "route": "route", "--durable": "sweep", "run-open": "run_open"}[command]
    held = holds(result)[(step, "child_failed", None)]
    assert held["act"] == "owner"
    assert "malformed child result: " + field in held["detail"]
    assert step_states(result)[step] == "failed"
    assert step_states(result)["run_open"] == ("failed" if tool == "jobs" else "ok")
    if tool == "router":
        assert step_states(result)["sweep"] == "ok"
    assert json.loads(world.status_path.read_text()) == result


def test_compatible_extra_child_fields_are_accepted(world):
    child = answering(world, "extended-child.py", {"--durable": (0, {
        **EMPTY_SWEEP, "future_report": {"anything": [1, 2, 3]},
        "root_time": [{"state": "ok", "future_field": True}],
    })})

    result = world.once(swap=("sweep", child))

    assert holds(result) == {}
    assert step_states(result)["sweep"] == "ok"


def test_completed_route_is_retained_and_not_replayed_after_a_malformed_report(world):
    world.approved(request("feature-1", team="pilot"))
    child = world.script("route-with-malformed-report.py", (
        "import json, subprocess, sys\n"
        "p = subprocess.run([sys.executable, '-I', '-B', %r, *sys.argv[1:]], capture_output=True, text=True)\n"
        "value = json.loads(p.stdout)\n"
        "if 'route' in sys.argv[1:]: value['requests'] = [{}]\n"
        "print(json.dumps(value))\n"
        "sys.exit(p.returncode)\n") % str(ROOT / "tools" / "hierarchy_router.py"))

    result = world.once(expect=3, swap=("router", child))

    assert ("route", "child_failed", None) in holds(result)
    route = next(step for step in result["steps"] if step["step"] == "route")
    assert route["diagnostics"]["routed"] == [{"request_id": "feature-1"}]
    assert world.ledger.status()["requests"]["feature-1"]["routed"] is not None
    before = world.inbox("pilot/orchestrator")
    again = world.once(expect=3)
    assert step_states(again)["route"] == "skipped"
    assert world.inbox("pilot/orchestrator") == before


def test_valid_completed_rows_survive_a_malformed_job_row(world):
    child = answering(world, "malformed-jobs.py", {"run-open": (0, {
        "rows": [{"job": "pilot/job-1", "state": "completed"}, {},
                 {"job": "pilot/job-2", "state": "running"}],
    })})

    result = world.once(expect=3, swap=("jobs", child))

    assert ("run_open", "child_failed", None) in holds(result)
    step = next(step for step in result["steps"] if step["step"] == "run_open")
    assert step["diagnostics"]["rows"] == [
        {"job": "pilot/job-1", "state": "completed"}, {"job": "pilot/job-2", "state": "running"},
    ]
