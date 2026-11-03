"""The supported bridge keeps unsupported native execution explicitly held."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hierarchy_watch_bridge.py"
PROCESS_CAPABILITIES = ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")
PROCESS_SUPPORTED = os.name == "posix" and all(hasattr(os, name) for name in PROCESS_CAPABILITIES)
PROCESS_UNSUPPORTED = "disposable process port requires POSIX waitid with WNOWAIT"


@pytest.mark.parametrize("host", ["codex", "codex-cli", "claude-code", "unknown-host"])
def test_unqualified_host_cannot_execute_or_claim_native_acceptance(host):
    assert TOOL.is_file(), "supported host bridge public entry point is missing"
    from tools.hierarchy_watch_bridge import NativeBridge
    bridge = NativeBridge(host)
    observed = bridge.observe("work-one", "a" * 64)
    assert observed["state"] == "hold"
    assert observed["native_qualified"] is False
    result = bridge.continue_request("work-one", "a" * 64, "watch-op")
    assert result["state"] == "refused" and result["effect"] == "none"
    assert result["native_qualified"] is False
    assert "unqualified" in result["reason"]


def test_bridge_capabilities_entry_point_distinguishes_metadata_from_execution():
    assert TOOL.is_file(), "supported host bridge public entry point is missing"
    proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "capabilities", "--host", "codex"],
                          capture_output=True, text=True, timeout=10)
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["native_qualified"] is False
    assert result["persistent_executor"] == "unqualified"
    assert result["execution_enabled"] is False


def test_malformed_request_hash_refuses_before_native_execution():
    assert TOOL.is_file(), "supported host bridge public entry point is missing"
    from tools.hierarchy_watch_bridge import NativeBridge
    with pytest.raises(ValueError, match="^invalid request sha256$"):
        NativeBridge("codex").continue_request("work-one", "invalid", "watch-op")


class Provider:
    """Fake host only; ledger, Operator and bridge remain real."""

    def __init__(self, ledger):
        self.ledger = ledger
        self.available = True
        self.lose_reply = False
        self.effects = 0

    def inspect(self, request, actor, generation):
        return {"qualified": self.available, "mode": "fixture", "source": request["source"],
                "gates": {key: self.ledger.evidence for key in
                          ("source", "capability", "lease", "capacity", "observer", "job")},
                "reason": "fixture capacity available" if self.available else "fixture capacity wait"}

    def execute(self, request, intent_id):
        self.effects += 1
        (self.ledger.tmp / "bridge-effect.json").write_text(json.dumps({"request": request["id"], "intent": intent_id}))
        if self.lose_reply:
            raise TimeoutError("fixture reply lost")
        return {"outcome": "passed", "exit_code": 0, "evidence": self.ledger.evidence}


@pytest.fixture
def joined(tmp_path):
    if os.name != "posix":
        pytest.skip("disposable canonical operator requires POSIX durability")
    from tests.integration.test_hierarchy_lifecycle import Ledger, request
    from tools.hierarchy_watch_bridge import OperatorBridge
    from tools.hierarchy_watch_supervisor import Supervisor, initialize
    ledger = Ledger(tmp_path)
    value = request("bridge-work")
    ledger.publish(value)
    ledger.approve(value)
    provider = Provider(ledger)
    bridge = OperatorBridge(ledger.path, provider, ledger.operator, 1, evidence_only=True)
    root = tmp_path / "watch"
    initialize(root, ledger.path, "bridge-watch", evidence_only=True)
    return Supervisor(root), ledger, provider, bridge, value


def test_real_operator_bridge_records_one_canonical_effect(joined):
    supervisor, ledger, provider, bridge, value = joined
    result = supervisor.step(1, bridge)
    supervisor.step(1, bridge)
    assert provider.effects == 1
    row = ledger.status()["requests"][value["id"]]
    assert row["intent"]["id"] == result["attempts"][0]["result"]["intent_id"]
    assert row["terminal"]["value"]["outcome"] == "passed"
    assert result["work_complete"] is False and result["native_qualified"] is False


def test_real_operator_unknown_reply_survives_watch_restart(joined):
    supervisor, ledger, provider, bridge, value = joined
    provider.lose_reply = True
    result = supervisor.step(1, bridge)
    assert result["attempts"][0]["state"] == "unknown"
    from tools.hierarchy_watch_supervisor import Supervisor
    Supervisor(supervisor.root).step(1, bridge)
    assert provider.effects == 1
    assert ledger.status()["obligations"][0]["state"] == "unknown_effect"


def test_bridge_capacity_wait_does_not_consume_canonical_intent(joined):
    supervisor, ledger, provider, bridge, value = joined
    provider.available = False
    result = supervisor.step(1, bridge)
    assert result["holds"][value["id"]] == "fixture capacity wait"
    assert ledger.status()["requests"][value["id"]]["intent"] is None
    provider.available = True
    supervisor.step(1, bridge)
    assert provider.effects == 1


def test_operator_capacity_contention_before_intent_is_reconsidered(joined):
    supervisor, ledger, provider, bridge, value = joined
    import fcntl
    import os
    descriptor = os.open(ledger.path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        supervisor.step(1, bridge)
    finally:
        os.close(descriptor)
    assert ledger.status()["requests"][value["id"]]["intent"] is None
    supervisor.step(1, bridge)
    assert provider.effects == 1


def test_bridge_requires_exact_request_hash(joined):
    supervisor, ledger, provider, bridge, value = joined
    with pytest.raises(ValueError, match="^request sha256 mismatch$"):
        bridge.continue_request(value["id"], "f" * 64, "watch-op")
    assert provider.effects == 0


@pytest.mark.parametrize("actor,generation,reason", [("root-1", 1, "role root cannot record admit"),
                                                  ("router-1", 1, "role router cannot record admit"),
                                                  ("operator-1", 2, "stale actor generation")])
def test_operator_bridge_fences_role_and_generation(joined, actor, generation, reason):
    supervisor, ledger, provider, bridge, value = joined
    from tools.hierarchy_watch_bridge import OperatorBridge
    stale = OperatorBridge(ledger.path, provider, actor, generation, evidence_only=True)
    result = stale.continue_request(value["id"], ledger.target(value)["request_sha256"], "watch-op")
    assert result["state"] == "refused" and result["reason"] == reason
    assert provider.effects == 0


def test_operator_successor_can_continue_without_resuming_capped_predecessor(joined):
    supervisor, ledger, provider, bridge, value = joined
    ledger.event("meter", actor=ledger.operator, subject=ledger.operator, active_seconds=3600, open_since=None)
    supervisor.step(1, bridge)
    assert provider.effects == 0
    checkpoint = ledger.cli("checkpoint")
    ledger.event("succeed", actor="operator-2", predecessor="operator-1", checkpoint_sha256=checkpoint["sha256"])
    from tools.hierarchy_watch_bridge import OperatorBridge
    successor = OperatorBridge(ledger.path, provider, "operator-2", 2, evidence_only=True)
    supervisor.step(1, successor)
    assert provider.effects == 1
    assert ledger.status()["requests"][value["id"]]["intent"]["actor"] == "operator-2"


def test_operator_bridge_default_never_promotes_fixture_provider(joined):
    supervisor, ledger, provider, bridge, value = joined
    from tools.hierarchy_watch_bridge import OperatorBridge
    default = OperatorBridge(ledger.path, provider, ledger.operator, 1)
    result = supervisor.step(1, default)
    assert result["attempts"] == []
    assert provider.effects == 0
    assert ledger.status()["requests"][value["id"]]["intent"] is None


PROCESS_HOST = '''
import hashlib,json,os,signal,sys,time
from pathlib import Path
sys.path.insert(0, sys.argv[1] + "/tools")
from hierarchy_watch_bridge import OperatorBridge
root, mode, marker = Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4])
request = json.load(sys.stdin)
evidence = root.parent / "retained-failure.json"
refs = [{"path":str(evidence),"sha256":hashlib.sha256(evidence.read_bytes()).hexdigest()}]
class Provider:
    def inspect(self, value, actor, generation):
        return {"qualified":True,"mode":"fixture","source":value["source"],
                "gates":{k:refs for k in ("source","capability","lease","capacity","observer","job")},"reason":"fixture"}
    def execute(self, value, intent):
        marker.write_text(json.dumps({"pid":os.getpid(),"intent":intent}))
        if mode == "hang":
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            while True: time.sleep(0.01)
        return {"outcome":"passed","exit_code":0,"evidence":refs}
bridge = OperatorBridge(root, Provider(), "operator-1", 1, evidence_only=True)
if request["method"] == "observe":
    if mode == "hang-observe":
        marker.write_text(json.dumps({"pid":os.getpid()}))
        while True: time.sleep(0.01)
    result = bridge.observe(request["request_id"], request["request_sha256"])
else:
    result = bridge.continue_request(request["request_id"], request["request_sha256"], request["operation_id"])
    if mode == "descendant" and os.fork() == 0:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        marker.with_suffix(".child").write_text(str(os.getpid()))
        while True: time.sleep(0.01)
    if mode == "descendant":
        limit=time.monotonic()+2
        while not marker.with_suffix(".child").exists() and time.monotonic()<limit: time.sleep(0.01)
if mode == "bad-json" or (mode == "bad-continuation" and request["method"] == "continue_request"): print("{broken")
elif mode == "flood": print("x" * 1100000)
else:
    if mode == "wrong-hash": request["request_sha256"]="f"*64
    print(json.dumps({**request,"result":result}))
'''


@pytest.fixture
def process_host(joined, tmp_path):
    if not PROCESS_SUPPORTED:
        pytest.skip(PROCESS_UNSUPPORTED)
    from tools.hierarchy_watch_bridge import ProcessBridge
    supervisor, ledger, provider, bridge, value = joined
    script = tmp_path / "disposable_host.py"
    script.write_text(PROCESS_HOST)
    marker = tmp_path / "effect.json"

    def build(mode="normal", timeout=2):
        return ProcessBridge([sys.executable, "-I", "-B", str(script), str(ROOT), str(ledger.path), mode, str(marker)],
                             cwd=tmp_path, evidence_dir=tmp_path / "process-evidence",
                             timeout_seconds=timeout, stop_grace=0.05, evidence_only=True)
    return supervisor, ledger, value, marker, build


def test_process_bridge_default_refuses_construction_before_launch(tmp_path):
    from tools.hierarchy_watch_bridge import ProcessBridge
    with pytest.raises(ValueError, match="^process bridge requires explicit evidence-only operation$"):
        ProcessBridge([sys.executable], cwd=tmp_path, evidence_dir=tmp_path / "evidence")
    assert not (tmp_path / "evidence").exists()


@pytest.mark.parametrize("missing", PROCESS_CAPABILITIES)
def test_process_bridge_missing_host_capability_refuses_before_launch(tmp_path, monkeypatch, missing):
    from tools.hierarchy_watch_bridge import ProcessBridge
    monkeypatch.delattr(os, missing, raising=False)
    with pytest.raises(ValueError, match="^process bridge requires POSIX waitid WNOWAIT$"):
        ProcessBridge([sys.executable], cwd=tmp_path, evidence_dir=tmp_path / "evidence", evidence_only=True)
    assert not (tmp_path / "evidence").exists()


def test_process_bridge_joins_real_operator_and_retains_output(process_host):
    supervisor, ledger, value, marker, build = process_host
    result = supervisor.step(1, build())
    assert result["attempts"][0]["state"] == "completed"
    assert ledger.status()["requests"][value["id"]]["terminal"]["value"]["outcome"] == "passed"
    assert marker.exists() and result["native_qualified"] is False
    assert len(list((marker.parent / "process-evidence").glob("*/stdout"))) == 2


def test_process_timeout_reaps_child_and_restart_never_reexecutes(process_host):
    supervisor, ledger, value, marker, build = process_host
    result = supervisor.step(1, build("hang", timeout=0.3))
    attempt = result["attempts"][0]
    assert attempt["state"] == "unknown" and attempt["result"]["reason"] == "process bridge deadline reached"
    assert attempt["result"]["process"]["reaped"] is True
    with pytest.raises(ProcessLookupError):
        os.kill(json.loads(marker.read_text())["pid"], 0)
    before = marker.read_bytes()
    from tools.hierarchy_watch_supervisor import Supervisor
    Supervisor(supervisor.root).step(1, build())
    assert marker.read_bytes() == before
    assert ledger.status()["obligations"][0]["state"] == "unknown_effect"


def test_process_bridge_inflight_stop_is_forwarded_by_supervisor(process_host):
    supervisor, ledger, value, marker, build = process_host
    stop = threading.Event()
    def stop_after_effect():
        deadline = time.monotonic() + 3
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        stop.set()
    thread = threading.Thread(target=stop_after_effect)
    thread.start()
    try:
        result = supervisor.run(1, seconds=4, interval=0.01, bridge=build("hang", timeout=5), stop_event=stop)
    finally:
        thread.join(timeout=4)
    assert not thread.is_alive()
    assert result["attempts"][0]["result"]["reason"] == "process bridge stop requested"
    assert result["attempts"][0]["result"]["process"]["reaped"] is True


def test_process_bridge_pre_cancel_does_not_launch(process_host):
    supervisor, ledger, value, marker, build = process_host
    stop = threading.Event()
    stop.set()
    bridge = build().with_control(deadline=time.monotonic() + 1, stop_event=stop)
    result = bridge.continue_request(value["id"], ledger.target(value)["request_sha256"], "watch-op")
    assert result["state"] == "refused" and result["effect"] == "none"
    assert not marker.exists()


def test_process_observation_timeout_holds_without_intent(process_host):
    supervisor, ledger, value, marker, build = process_host
    result = supervisor.step(1, build("hang-observe", timeout=0.2))
    assert result["attempts"] == []
    assert result["holds"][value["id"]] == "process bridge deadline reached"
    assert ledger.status()["requests"][value["id"]]["intent"] is None


@pytest.mark.parametrize("mode,reason", [("bad-json", "invalid process bridge response"),
                                       ("wrong-hash", "process bridge response correlation mismatch"),
                                       ("flood", "process bridge output limit exceeded")])
def test_process_bridge_invalid_observation_is_explicit_hold(process_host, mode, reason):
    supervisor, ledger, value, marker, build = process_host
    result = supervisor.step(1, build(mode))
    assert result["holds"][value["id"]] == reason
    assert result["attempts"] == []


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="independent stopped-child witness uses Linux proc")
def test_process_bridge_stops_same_group_descendant_after_leader_exit(process_host):
    supervisor, ledger, value, marker, build = process_host
    result = supervisor.step(1, build("descendant"))
    assert result["attempts"][0]["result"]["process"]["reaped"] is True
    pid = int(marker.with_suffix(".child").read_text())
    stat = Path("/proc") / str(pid) / "stat"
    deadline = time.monotonic() + 2
    while stat.exists() and time.monotonic() < deadline:
        if stat.read_text().split(") ", 1)[1].split()[0] == "Z":
            break
        time.sleep(0.01)
    assert not stat.exists() or stat.read_text().split(") ", 1)[1].split()[0] == "Z"


def test_supervisor_run_deadline_bounds_inflight_process(process_host):
    supervisor, ledger, value, marker, build = process_host
    result = supervisor.run(1, seconds=0.4, interval=0.01, bridge=build("hang", timeout=5))
    assert marker.exists()
    assert result["attempts"][0]["result"]["reason"] == "process bridge deadline reached"
    assert result["attempts"][0]["result"]["process"]["reaped"] is True


def test_process_lost_terminal_reply_preserves_canonical_settlement(process_host):
    supervisor, ledger, value, marker, build = process_host
    result = supervisor.step(1, build("bad-continuation"))
    assert result["attempts"][0]["state"] == "unknown"
    assert result["attempts"][0]["canonical_settlement"] is not None
    before = marker.read_bytes()
    supervisor.advance(1, 2)
    supervisor.step(2, build())
    assert marker.read_bytes() == before
    assert supervisor.status()["work_complete"] is False


def test_missing_process_executable_is_known_no_effect(process_host):
    supervisor, ledger, value, marker, build = process_host
    from tools.hierarchy_watch_bridge import ProcessBridge
    bridge = ProcessBridge([str(marker.parent / "missing")], cwd=marker.parent,
                           evidence_dir=marker.parent / "missing-evidence", evidence_only=True)
    result = bridge.continue_request(value["id"], ledger.target(value)["request_sha256"], "watch-op")
    assert result["state"] == "refused" and result["effect"] == "none"
    assert result["reason"].startswith("process bridge launch failed: ")
    assert result["process"] is None and not marker.exists()


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"), True, 3601])
def test_process_bridge_rejects_unbounded_timeouts(tmp_path, value):
    from tools.hierarchy_watch_bridge import ProcessBridge
    with pytest.raises(ValueError, match="^invalid process bridge timeout$"):
        ProcessBridge([sys.executable], cwd=tmp_path, evidence_dir=tmp_path / "evidence",
                      timeout_seconds=value, evidence_only=True)


@pytest.mark.skipif(not PROCESS_SUPPORTED, reason=PROCESS_UNSUPPORTED)
def test_stderr_overflow_at_exit_cannot_hide_between_observations(tmp_path, monkeypatch):
    from tools.hierarchy_watch_bridge import ProcessBridge
    gate = tmp_path / "release"
    script = tmp_path / "stderr_host.py"
    script.write_text("import json,sys,time\nfrom pathlib import Path\nr=json.load(sys.stdin)\n"
                      "while not Path(sys.argv[1]).exists(): time.sleep(0.01)\n"
                      "sys.stderr.write('x'*1100000)\n"
                      "print(json.dumps({**r,'result':{'state':'completed','effect':'confirmed','native_qualified':False}}))\n")
    original = os.waitid
    def observe_exit(*args):
        gate.touch()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            result = original(*args)
            if result is not None:
                return result
            time.sleep(0.01)
        pytest.fail("disposable child did not exit")
    monkeypatch.setattr(os, "waitid", observe_exit)
    bridge = ProcessBridge([sys.executable, "-I", str(script), str(gate)], cwd=tmp_path,
                           evidence_dir=tmp_path / "logs", evidence_only=True)
    result = bridge.continue_request("work", "a" * 64, "watch-op")
    assert result["state"] == "unknown"
    assert result["reason"] == "process bridge output limit exceeded"


@pytest.mark.skipif(not PROCESS_SUPPORTED, reason=PROCESS_UNSUPPORTED)
@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX descendant cleanup boundary")
def test_stderr_written_by_descendant_during_cleanup_is_bounded(tmp_path):
    from tools.hierarchy_watch_bridge import ProcessBridge
    script = tmp_path / "cleanup_host.py"
    script.write_text("import json,os,signal,sys,time\nfrom pathlib import Path\nr=json.load(sys.stdin)\n"
                      "ready=Path(sys.argv[1])\n"
                      "if os.fork()==0:\n"
                      " def stopped(*args):\n  os.write(2,b'x'*1100000)\n  os._exit(0)\n"
                      " signal.signal(signal.SIGTERM,stopped)\n ready.touch()\n"
                      " while True: time.sleep(0.01)\n"
                      "end=time.monotonic()+2\n"
                      "while not ready.exists() and time.monotonic()<end: time.sleep(0.01)\n"
                      "print(json.dumps({**r,'result':{'state':'eligible','native_qualified':False}}),flush=True)\n")
    bridge = ProcessBridge([sys.executable, "-I", str(script), str(tmp_path / "ready")], cwd=tmp_path,
                           evidence_dir=tmp_path / "logs", stop_grace=0.05, evidence_only=True)
    result = bridge.observe("work", "a" * 64)
    assert result["state"] == "hold"
    assert result["reason"] == "process bridge output limit exceeded"
    assert result["process"]["reaped"] is True
