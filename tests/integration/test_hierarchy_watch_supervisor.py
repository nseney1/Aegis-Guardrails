"""Durable watch behavior with the real lifecycle store and a fake host boundary.

These checks establish local process/storage behavior, never native qualification.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hierarchy_watch_supervisor.py"
pytestmark = pytest.mark.skipif(os.name != "posix", reason="watch worker locking requires POSIX")


class Host:
    """The external host port; effects are visible in an actual temporary file."""

    def __init__(self, directory):
        self.log = directory / "host-effects.jsonl"
        self.capacity = True
        self.lose_reply = False
        self.crash = False
        self.refuse = False
        self.calls = []

    def observe(self, request_id, request_sha256):
        return {"state": "eligible" if self.capacity else "hold", "reason": "capacity" if not self.capacity else "",
                "native_qualified": False}

    def continue_request(self, request_id, request_sha256, operation_id):
        self.calls.append(operation_id)
        if self.refuse:
            return {"state": "refused", "effect": "none", "reason": "host refused before start",
                    "native_qualified": False}
        with self.log.open("a") as stream:
            stream.write(json.dumps({"request": request_id, "operation": operation_id}) + "\n")
        if self.crash:
            raise SystemExit("simulated host process loss")
        if self.lose_reply:
            raise TimeoutError("host reply lost after effect")
        return {"state": "completed", "effect": "confirmed", "reason": "fixture effect only",
                "native_qualified": False}

    def effects(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []


@pytest.fixture
def watch(tmp_path):
    assert TOOL.is_file(), "persistent watch supervisor public entry point is missing"
    from tools.hierarchy_watch_supervisor import Supervisor, initialize
    from tests.integration.test_hierarchy_lifecycle import Ledger, request

    ledger = Ledger(tmp_path)
    root = tmp_path / "watch"
    initialize(root, ledger.path, "watch-one", evidence_only=True)
    return Supervisor(root), ledger, Host(tmp_path), request


def approved(ledger, request, identifier="work-one"):
    value = request(identifier)
    ledger.publish(value)
    ledger.approve(value)
    return value


def test_dispatch_survives_lost_reply_without_duplicate_effect(watch):
    supervisor, ledger, host, request = watch
    approved(ledger, request)
    host.lose_reply = True
    result = supervisor.step(1, host)
    assert result["attempts"][0]["state"] == "unknown"
    assert "host reply lost after effect" in result["attempts"][0]["result"]["reason"]
    host.lose_reply = False
    from tools.hierarchy_watch_supervisor import Supervisor
    result = Supervisor(supervisor.root).step(1, host)
    assert len(host.effects()) == 1
    assert result["work_complete"] is False


def test_process_crash_leaves_a_durable_unresolved_dispatch(watch):
    supervisor, ledger, host, request = watch
    approved(ledger, request)
    host.crash = True
    with pytest.raises(SystemExit, match="^simulated host process loss$"):
        supervisor.step(1, host)
    from tools.hierarchy_watch_supervisor import Supervisor
    restarted = Supervisor(supervisor.root)
    assert restarted.status()["attempts"][0]["state"] == "dispatching"
    host.crash = False
    restarted.step(1, host)
    assert len(host.effects()) == 1


def test_new_watch_generation_fences_predecessor_and_retains_unknown(watch):
    supervisor, ledger, host, request = watch
    approved(ledger, request)
    host.lose_reply = True
    supervisor.step(1, host)
    supervisor.advance(1, 2)
    with pytest.raises(ValueError, match="^watch generation is fenced$"):
        supervisor.step(1, host)
    supervisor.step(2, host)
    assert len(host.effects()) == 1
    assert supervisor.status()["generation"] == 2


def test_competing_worker_cannot_dispatch_or_replace_generation(watch):
    supervisor, ledger, host, request = watch
    approved(ledger, request)
    import fcntl
    with (supervisor.root / "worker.lock").open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ValueError, match="^watch worker is already active$"):
            supervisor.step(1, host)
        with pytest.raises(ValueError, match="^watch worker is already active$"):
            supervisor.advance(1, 2)
    assert host.effects() == []


def test_capacity_wait_and_late_arrival_are_reconsidered(watch):
    supervisor, ledger, host, request = watch
    assert supervisor.step(1, host)["attempts"] == []
    approved(ledger, request)
    host.capacity = False
    result = supervisor.step(1, host)
    assert result["holds"]["work-one"] == "capacity"
    assert result["attempts"] == []
    host.capacity = True
    supervisor.step(1, host)
    approved(ledger, request, "late-work")
    supervisor.step(1, host)
    assert [row["request"] for row in host.effects()] == ["work-one", "late-work"]


def test_capped_operator_is_not_restarted(watch):
    supervisor, ledger, host, request = watch
    approved(ledger, request)
    ledger.event("meter", actor=ledger.operator, subject=ledger.operator, active_seconds=3600, open_since=None)
    result = supervisor.step(1, host)
    assert host.effects() == []
    assert result["holds"]["work-one"] == "actor cumulative active cap reached"


def test_explicit_no_effect_refusal_can_retry_with_same_operation_id(watch):
    supervisor, ledger, host, request = watch
    approved(ledger, request)
    host.refuse = True
    result = supervisor.step(1, host)
    assert result["attempts"][0]["state"] == "refused"
    host.refuse = False
    supervisor.step(1, host)
    supervisor.step(1, host)
    assert len(host.effects()) == 1
    assert len(host.calls) == 2 and host.calls[0] == host.calls[1]


def test_canonical_unknown_intent_prevents_any_host_dispatch(watch):
    supervisor, ledger, host, request = watch
    value = approved(ledger, request)
    ledger.admit(value)
    ledger.intent(value)
    result = supervisor.step(1, host)
    assert host.effects() == []
    assert result["obligations"][0]["state"] == "unknown_effect"
    assert result["work_complete"] is False


def test_canonical_settlement_resolves_unknown_watch_without_erasing_failure(watch):
    supervisor, ledger, host, request = watch
    value = approved(ledger, request)
    host.lose_reply = True
    supervisor.step(1, host)
    ledger.admit(value)
    ledger.intent(value)
    ledger.terminal(value)
    ledger.accepted_delivery(value)
    ledger.event("disposition", status="FINAL", resolution={"kind": "complete", "evidence": ledger.evidence},
                 **ledger.target(value))
    result = supervisor.step(1, host)
    assert result["work_complete"] is True
    assert result["attempts"][0]["state"] == "unknown"
    assert result["attempts"][0]["canonical_settlement"]["intent_id"] == "attempt-1"
    assert any(row["state"] == "unknown" for row in result["history"])
    assert len(host.effects()) == 1


def test_final_with_next_request_preserves_continuation(watch):
    supervisor, ledger, host, request = watch
    first = approved(ledger, request)
    following = request("next-work")
    from tests.integration.test_hierarchy_lifecycle import raw_request
    ledger.event("disposition", status="FINAL", resolution={"kind": "next", "request": raw_request(following),
                                                           "evidence": ledger.evidence},
                 **ledger.target(first))
    ledger.approve(following)
    supervisor.step(1, host)
    assert [row["request"] for row in host.effects()] == ["next-work"]


def test_malformed_host_result_is_unknown_not_retryable(watch):
    supervisor, ledger, host, request = watch
    approved(ledger, request)

    class BadHost(Host):
        def continue_request(self, *args):
            super().continue_request(*args)
            return {"state": "completed", "effect": "none"}

    broken = BadHost(ledger.tmp)
    result = supervisor.step(1, broken)
    assert result["attempts"][0]["state"] == "unknown"
    supervisor.step(1, host)
    assert len(host.effects()) == 1


def test_missing_lifecycle_is_a_hold_and_never_work_complete(watch):
    supervisor, ledger, host, request = watch
    ledger.path.rename(ledger.tmp / "missing-ledger")
    with pytest.raises(ValueError, match="^lifecycle unavailable:"):
        supervisor.step(1, host)
    assert host.effects() == []


def test_run_retains_failed_observations_without_dispatching(watch):
    supervisor, ledger, host, request = watch
    approved(ledger, request)
    ledger.path.rename(ledger.tmp / "unavailable-ledger")
    result = supervisor.run(1, seconds=0.05, interval=0.01, bridge=host)
    assert result["state"] == "hold"
    assert result["work_complete"] is False
    assert result["observation_error"].startswith("lifecycle unavailable:")
    assert result["history"] and all(row["state"] == "observation_hold" for row in result["history"])
    assert host.effects() == []


def test_host_reconnect_reobserves_without_retrying_an_uncertain_effect(watch):
    supervisor, ledger, host, request = watch
    approved(ledger, request)
    stop = threading.Event()

    class ReconnectingHost(Host):
        observations = 0

        def observe(self, *args):
            self.observations += 1
            if self.observations == 1:
                raise TimeoutError("host observation disconnected")
            return super().observe(*args)

        def continue_request(self, *args):
            result = super().continue_request(*args)
            stop.set()
            return result

    recovered = ReconnectingHost(ledger.tmp)
    result = supervisor.run(1, seconds=2, interval=0.01, bridge=recovered, stop_event=stop)
    assert len(recovered.effects()) == 1
    assert any(row["state"] == "observation_hold" and "host observation disconnected" in row["record"]["error"]
               for row in result["history"])


@pytest.mark.parametrize("boundary", ["deadline", "stop"])
def test_stop_or_deadline_during_observation_prevents_dispatch(watch, monkeypatch, boundary):
    supervisor, ledger, host, request = watch
    approved(ledger, request)
    from tools import hierarchy_watch_supervisor
    now = [0.0]
    monkeypatch.setattr(hierarchy_watch_supervisor.time, "monotonic", lambda: now[0])
    stop = threading.Event()

    class StoppingHost(Host):
        def observe(self, *args):
            if boundary == "deadline":
                now[0] = 2.0
            else:
                stop.set()
            return super().observe(*args)

    result = supervisor.run(1, seconds=1, interval=0.01, bridge=StoppingHost(ledger.tmp), stop_event=stop)
    assert result["attempts"] == []
    assert host.effects() == []


def test_stop_during_effect_prevents_further_observations_or_dispatches(watch):
    supervisor, ledger, host, request = watch
    approved(ledger, request, "first-work")
    approved(ledger, request, "second-work")
    stop = threading.Event()
    observations = []

    class StopAfterEffect(Host):
        def observe(self, request_id, request_sha256):
            observations.append(request_id)
            return super().observe(request_id, request_sha256)

        def continue_request(self, *args):
            result = super().continue_request(*args)
            stop.set()
            return result

    supervisor.run(1, seconds=1, interval=0.01, bridge=StopAfterEffect(ledger.tmp), stop_event=stop)
    assert observations == ["first-work"]
    assert [row["request"] for row in host.effects()] == ["first-work"]


def test_revocation_between_observation_and_dispatch_refuses(watch):
    supervisor, ledger, host, request = watch
    value = approved(ledger, request)

    class RevokingHost(Host):
        def observe(self, *args):
            ledger.event("decision", actor=ledger.root_actor, decision="deny", reason="withdrawn", **ledger.target(value))
            return super().observe(*args)

    result = supervisor.step(1, RevokingHost(ledger.tmp))
    assert result["attempts"] == []
    assert host.effects() == []


def test_watch_configuration_change_is_not_silently_adopted(watch):
    supervisor, ledger, host, request = watch
    path = supervisor.root / "config.json"
    config = json.loads(path.read_text())
    config["watch_id"] = "different-watch"
    path.write_text(json.dumps(config))
    from tools.hierarchy_watch_supervisor import Supervisor
    with pytest.raises(ValueError, match="^watch config digest mismatch$"):
        Supervisor(supervisor.root).step(1, host)
    assert host.effects() == []


def test_corrupt_watch_store_is_an_explicit_cli_hold(watch):
    supervisor, ledger, host, request = watch
    (supervisor.root / "watch.sqlite").write_bytes(b"broken sqlite database")
    proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "--root", str(supervisor.root),
                           "step", "--generation", "1", "--evidence-only"],
                          capture_output=True, text=True, timeout=10)
    assert proc.returncode == 2
    result = json.loads(proc.stdout)
    assert result["error"] == "file is not a database"
    assert result["work_complete"] is False


@pytest.mark.parametrize("seconds,interval,error", [(0, 1, "invalid run seconds"),
                                                  (3601, 1, "invalid run seconds"),
                                                  (1, 0, "invalid poll interval"),
                                                  (1, 61, "invalid poll interval")])
def test_polling_is_bounded(watch, seconds, interval, error):
    supervisor, ledger, host, request = watch
    with pytest.raises(ValueError, match="^" + error + "$"):
        supervisor.run(1, seconds=seconds, interval=interval, bridge=host)
    assert host.effects() == []


def test_native_cli_refuses_mutation_without_evidence_only(watch):
    supervisor, ledger, host, request = watch
    proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "--root", str(supervisor.root),
                           "step", "--generation", "1"], capture_output=True, text=True, timeout=10)
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["error"] == "mutation requires --evidence-only; native service is unqualified"


def test_model_free_loop_survives_its_launcher_and_keeps_watching(watch):
    supervisor, ledger, host, request = watch
    output = ledger.tmp / "service-output.json"
    errors = ledger.tmp / "service-errors.txt"
    command = [sys.executable, "-I", "-B", str(TOOL), "--root", str(supervisor.root), "run", "--generation", "1",
               "--seconds", "1", "--interval", "0.02", "--evidence-only"]
    launcher = "import subprocess,sys; p=subprocess.Popen(sys.argv[3:],stdout=open(sys.argv[1],'w'),stderr=open(sys.argv[2],'w'),start_new_session=True); print(p.pid)"
    launched = subprocess.run([sys.executable, "-c", launcher, str(output), str(errors), *command],
                              capture_output=True, text=True, timeout=10)
    assert launched.returncode == 0, launched.stderr
    approved(ledger, request, "after-launcher-exit")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if output.exists() and output.stat().st_size:
            break
        time.sleep(0.02)
    else:
        os.kill(int(launched.stdout), 15)
        pytest.fail("bounded supervisor did not finish")
    assert errors.read_text() == ""
    result = json.loads(output.read_text())
    assert result["iterations"] > 1
    assert result["obligations"][0]["request_id"] == "after-launcher-exit"
    assert result["native_qualified"] is False
    assert result["work_complete"] is False
