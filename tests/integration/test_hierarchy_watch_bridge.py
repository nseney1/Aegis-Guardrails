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


ASYNC_PROCESS_HOST = r'''
import hashlib,json,os,subprocess,sys,time
from pathlib import Path
mode, marker, evidence = sys.argv[1:4]
raw = sys.stdin.buffer.read()
call = json.loads(raw)
with Path(marker).open("a") as stream:
    stream.write(json.dumps({"method":call["method"],"pid":os.getpid()})+"\n")
if mode == "require-lf" and not raw.endswith(b"\n"): sys.exit(8)
if mode == "hang":
    while True: time.sleep(0.01)
if mode == "nonzero": sys.exit(7)
if mode == "flood":
    print("x" * 1100000)
    sys.exit(0)
if mode == "malformed":
    print("{broken")
    sys.exit(0)
refs=[{"path":evidence,"sha256":hashlib.sha256(Path(evidence).read_bytes()).hexdigest()}]
if call["method"] == "inspect":
    result={"qualified":True,"mode":"fixture","source":call["request"]["source"],
            "gates":{k:refs for k in ("source","capability","lease","capacity","observer","job")},"reason":"fixture"}
    if mode == "deep-result":
        nested="leaf"
        for _ in range(30): nested={"x":nested}
        result["gates"]["source"]=nested
else:
    result={"association_sha256":call["association_sha256"],"provider_state":"running",
            "provider_handle":{"thread_id":call["association"]["thread_id"],"turn_id":"turn-fixture"},
            "exit_code":None,"evidence":refs,"quiescent":False}
    if call["method"] == "cancel": result["provider_state"]="cancel_requested"
    if mode == "wrong-handle": result["provider_handle"]["thread_id"]="other-thread"
    if mode == "invalid-result": result["quiescent"]="yes"
    if mode == "state-container": result["provider_state"]=[]
    if mode == "long-ids": result["provider_handle"]["turn_id"]="t"*129
if mode == "wrong-frame": call["request_sha256"]="f"*64
if mode == "bool-generation": call["generation"]=True
if mode == "descendant":
    child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(20)"])
    Path(marker+".child").write_text(str(child.pid))
print(json.dumps({**call,"result":result}),flush=True)
'''


@pytest.fixture
def async_process(tmp_path):
    script = tmp_path / "async_provider.py"
    script.write_text(ASYNC_PROCESS_HOST, encoding="utf-8")
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(b'{"fixture":true}\n')
    marker = tmp_path / "calls.jsonl"
    spec = {"schema": "aegis.fixture-process-provider/v1", "mode": "fixture",
            "provider": "fixture", "endpoint_id": "fixture-endpoint",
            "argv": [sys.executable, "-I", "-B", str(script), "running", str(marker), str(evidence)],
            "cwd": str(tmp_path), "evidence_dir": str(tmp_path / "calls"), "stop_grace": 0.02}
    request = {"id": "async-work", "source": {"commit": "a" * 40, "tree": "b" * 40, "dirty_sha256": "c" * 64}}
    association = {"schema": "aegis.provider-association/v1", "request_id": request["id"],
                   "request_sha256": "d" * 64, "intent_id": "intent-one", "source": request["source"],
                   "provider": spec["provider"], "endpoint_id": spec["endpoint_id"], "thread_id": "thread-fixture"}
    return spec, request, association, marker


def provider_call(values, method="submit", *, deadline=None, **changes):
    from tools.hierarchy_watch_bridge import process_provider_call
    spec, request, association, _ = values
    return process_provider_call(spec, method, request, "d" * 64, actor="operator-one", generation=1,
                                 association=None if method == "inspect" else association,
                                 deadline=deadline if deadline is not None else time.monotonic() + 2,
                                 evidence_only=True, **changes)


def test_process_provider_descriptor_is_plain_copied_data_without_effects(async_process):
    from tools.hierarchy_watch_bridge import validate_process_provider
    spec, _, _, marker = async_process
    result = validate_process_provider(spec)
    result["argv"].append("changed")
    assert spec["argv"][-1] != "changed"
    assert not marker.exists() and not Path(spec["evidence_dir"]).exists()


@pytest.mark.parametrize("key,value", [("mode", "native"), ("stop_grace", True),
                                     ("stop_grace", 0.3), ("stop_grace", float("nan")),
                                     ("argv", ["relative-command"]), ("unknown", None)])
def test_process_provider_descriptor_rejects_invalid_data_before_effects(async_process, key, value):
    from tools.hierarchy_watch_bridge import validate_process_provider
    spec, _, _, marker = async_process
    spec[key] = value
    with pytest.raises(ValueError):
        validate_process_provider(spec)
    assert not marker.exists() and not Path(spec["evidence_dir"]).exists()


def test_process_provider_requires_explicit_evidence_only(async_process):
    from tools.hierarchy_watch_bridge import process_provider_call
    spec, request, association, marker = async_process
    with pytest.raises(ValueError, match="^process provider requires explicit evidence-only operation$"):
        process_provider_call(spec, "submit", request, "d" * 64, actor="operator-one", generation=1,
                              association=association, deadline=time.monotonic() + 1)
    assert not marker.exists() and not Path(spec["evidence_dir"]).exists()


@pytest.mark.parametrize("method", [None, [], True])
def test_process_provider_malformed_method_refuses_before_effects(async_process, method):
    spec, _, _, marker = async_process
    with pytest.raises(ValueError, match="^invalid process provider method$"):
        provider_call(async_process, method)
    assert not marker.exists() and not Path(spec["evidence_dir"]).exists()


def test_process_provider_missing_platform_support_refuses_before_effects(async_process, monkeypatch):
    from tools import hierarchy_watch_bridge
    spec, _, _, marker = async_process
    monkeypatch.delattr(hierarchy_watch_bridge.os, "waitid", raising=False)
    result = provider_call(async_process)
    assert result["transport"] == "not_sent"
    assert result["reason"] == "process provider requires POSIX waitid WNOWAIT"
    assert not marker.exists() and not Path(spec["evidence_dir"]).exists()


@pytest.mark.skipif(not PROCESS_SUPPORTED, reason=PROCESS_UNSUPPORTED)
def test_process_provider_inspection_and_running_do_not_prove_job_completion(async_process):
    from tools.hierarchy_mailbox import digest
    spec, _, association, marker = async_process
    deadline = time.monotonic() + 2
    inspected = provider_call(async_process, "inspect", deadline=deadline)
    result = provider_call(async_process, deadline=deadline)
    assert inspected["transport"] == "received" and inspected["result"]["qualified"] is True
    assert result["transport"] == "received" and result["native_qualified"] is False
    assert result["result"]["association_sha256"] == digest(association)
    assert result["result"]["provider_state"] == "running" and result["result"]["quiescent"] is False
    assert result["process"]["reaped"] is True
    assert [json.loads(line)["method"] for line in marker.read_text().splitlines()] == ["inspect", "submit"]
    folder = Path(result["evidence_dir"])
    assert {p.name for p in folder.iterdir()} == {"request.json", "stdout", "stderr", "result.json"}
    assert json.loads((folder / "result.json").read_text()) == result


@pytest.mark.skipif(not PROCESS_SUPPORTED, reason=PROCESS_UNSUPPORTED)
def test_process_provider_expired_shared_deadline_never_starts_another_child(async_process):
    spec, _, _, marker = async_process
    result = provider_call(async_process, deadline=time.monotonic() - 1)
    assert result["transport"] == "not_sent" and result["result"] is None
    assert result["reason"] == "process provider cleanup reserve exceeds remaining budget"
    assert not marker.exists() and not Path(spec["evidence_dir"]).exists()


@pytest.mark.skipif(not PROCESS_SUPPORTED, reason=PROCESS_UNSUPPORTED)
def test_process_provider_stdin_is_one_complete_lf_frame(async_process):
    spec, _, _, _ = async_process
    spec["argv"][4] = "require-lf"
    result = provider_call(async_process)
    assert result["transport"] == "received", result
    raw = Path(result["evidence_dir"], "request.json").read_bytes()
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    assert json.loads(raw)["method"] == "submit"


def test_process_provider_depth_limit_includes_complete_request_envelope(async_process):
    spec, request, _, marker = async_process
    nested = "leaf"
    for _ in range(31):
        nested = {"x": nested}
    request["extra"] = nested
    with pytest.raises(ValueError, match="^process provider data exceeds nesting limit$"):
        provider_call(async_process, "inspect")
    assert not marker.exists() and not Path(spec["evidence_dir"]).exists()


@pytest.mark.skipif(not PROCESS_SUPPORTED, reason=PROCESS_UNSUPPORTED)
def test_process_provider_depth_limit_includes_complete_response_envelope(async_process):
    spec, _, _, _ = async_process
    spec["argv"][4] = "deep-result"
    result = provider_call(async_process, "inspect")
    assert result["transport"] == "uncertain", result
    assert result["reason"] == "process provider data exceeds nesting limit"


@pytest.mark.parametrize("value", [10 ** 1000, -(10 ** 1000)])
def test_process_provider_huge_numeric_budgets_refuse_without_effects(async_process, value):
    from tools.hierarchy_watch_bridge import validate_process_provider
    spec, _, _, marker = async_process
    with pytest.raises(ValueError, match="^invalid process provider deadline$"):
        provider_call(async_process, deadline=value)
    spec["stop_grace"] = value
    with pytest.raises(ValueError, match="^invalid process provider stop grace$"):
        validate_process_provider(spec)
    assert not marker.exists() and not Path(spec["evidence_dir"]).exists()


@pytest.mark.skipif(not PROCESS_SUPPORTED, reason=PROCESS_UNSUPPORTED)
def test_process_provider_preserves_129_character_canonical_handles(async_process):
    spec, _, association, _ = async_process
    association["thread_id"] = "h" * 129
    spec["argv"][4] = "long-ids"
    handle = {"thread_id": association["thread_id"], "turn_id": "t" * 129}
    result = provider_call(async_process, "observe", provider_handle=handle)
    assert result["transport"] == "received", result
    assert result["result"]["provider_handle"] == handle


def test_process_provider_refuses_257_character_thread_before_effects(async_process):
    spec, _, association, marker = async_process
    association["thread_id"] = "h" * 257
    with pytest.raises(ValueError, match="^process provider association correlation mismatch$"):
        provider_call(async_process)
    assert not marker.exists() and not Path(spec["evidence_dir"]).exists()


@pytest.mark.skipif(not PROCESS_SUPPORTED, reason=PROCESS_UNSUPPORTED)
@pytest.mark.parametrize("mode,reason", [("malformed", "invalid process bridge response"),
                                        ("wrong-frame", "process bridge response correlation mismatch"),
                                        ("bool-generation", "process bridge response correlation mismatch"),
                                        ("wrong-handle", "process provider handle correlation mismatch"),
                                        ("invalid-result", "invalid process provider observation"),
                                        ("state-container", "invalid process provider observation"),
                                        ("nonzero", "process bridge exited unsuccessfully"),
                                        ("flood", "process bridge output limit exceeded")])
def test_process_provider_uncertain_responses_are_retained_without_retry(async_process, mode, reason):
    spec, _, _, marker = async_process
    spec["argv"][4] = mode
    result = provider_call(async_process)
    assert result["transport"] == "uncertain" and result["result"] is None
    assert result["reason"] == reason
    assert result["process"]["reaped"] is True
    assert len(marker.read_text().splitlines()) == 1
    assert Path(result["evidence_dir"], "stdout").exists()


@pytest.mark.skipif(not PROCESS_SUPPORTED, reason=PROCESS_UNSUPPORTED)
def test_process_provider_timeout_keeps_possible_effect_and_evidence(async_process):
    spec, _, _, marker = async_process
    spec["argv"][4] = "hang"
    result = provider_call(async_process, deadline=time.monotonic() + 0.3)
    assert result["transport"] == "uncertain" and result["result"] is None
    assert result["reason"] == "process bridge deadline reached"
    assert result["process"]["reaped"] is True
    assert len(marker.read_text().splitlines()) == 1
    assert Path(result["evidence_dir"], "request.json").exists()


@pytest.mark.skipif(not PROCESS_SUPPORTED, reason=PROCESS_UNSUPPORTED)
def test_process_provider_cancel_ack_does_not_mean_quiescence(async_process):
    _, _, association, _ = async_process
    handle = {"thread_id": association["thread_id"], "turn_id": "turn-fixture"}
    result = provider_call(async_process, "cancel", provider_handle=handle, reason="stop owned fixture")
    assert result["transport"] == "received"
    assert result["result"]["provider_state"] == "cancel_requested"
    assert result["result"]["quiescent"] is False and result["result"]["exit_code"] is None


@pytest.mark.skipif(not PROCESS_SUPPORTED, reason=PROCESS_UNSUPPORTED)
def test_process_provider_exit_with_descendant_has_no_pipe_eof_wait(async_process):
    spec, _, _, _ = async_process
    spec["argv"][4] = "descendant"
    result = provider_call(async_process)
    assert result["transport"] == "received"
    assert result["process"]["reaped"] is True and result["process"]["group_signalled"] is True
    assert result["result"]["quiescent"] is False


@pytest.fixture
def async_joined(tmp_path):
    if not PROCESS_SUPPORTED:
        pytest.skip("asynchronous process execution requires POSIX waitid WNOWAIT")
    from tests.integration.test_hierarchy_operator import async_job
    from tests.integration.test_hierarchy_lifecycle import Ledger
    from tools.hierarchy_watch_bridge import OperatorBridge
    from tools.hierarchy_watch_supervisor import Supervisor, initialize
    journal = Ledger(tmp_path)
    job = async_job.__wrapped__(journal)
    journal, value, candidate, spec, target, state_path = job
    bridge = OperatorBridge(journal.path, spec, journal.operator, 1,
                            evidence_only=True, async_target=target)
    root = tmp_path / "async-watch"
    initialize(root, journal.path, "async-watch", evidence_only=True)
    return Supervisor(root), journal, bridge, value, state_path, spec, target


def async_phase(path, **changes):
    state = json.loads(path.read_text())
    path.write_text(json.dumps({**state, **changes}))


def test_async_consumer_public_bridge_observes_one_intent(async_joined):
    supervisor, journal, bridge, value, state, _, _ = async_joined
    raw = journal.target(value)["request_sha256"]
    first = bridge.continue_request(value["id"], raw, "delivery-one")
    assert (first["state"], first["effect"]) == ("running", "possible")
    replay = bridge.continue_request(value["id"], raw, "different-delivery")
    assert replay["intent_id"] == first["intent_id"]
    async_phase(state, phase="passed")
    final = bridge.poll_request(value["id"], raw, "poll-delivery")
    assert (final["state"], final["effect"], final["outcome"]) == ("completed", "confirmed", "passed")
    assert final["association"] == first["association"]
    assert json.loads(state.read_text())["starts"] == 1
    assert supervisor.status()["work_complete"] is False


def test_async_consumer_restart_observes_terminal_without_resubmit(async_joined):
    supervisor, journal, bridge, value, state, _, _ = async_joined
    first = supervisor.step(1, bridge)
    assert first["attempts"][0]["state"] == "running"
    from tools.hierarchy_watch_supervisor import Supervisor
    async_phase(state, phase="passed")
    final = Supervisor(supervisor.root).step(1, bridge)
    assert final["attempts"][0]["state"] == "completed"
    assert final["attempts"][0]["canonical_settlement"] is not None
    assert final["work_complete"] is False
    assert json.loads(state.read_text())["starts"] == 1


def test_async_consumer_lost_reply_reconnect_retains_failure_history(async_joined):
    supervisor, journal, bridge, value, state, _, _ = async_joined
    async_phase(state, error="lost_reply")
    first = supervisor.step(1, bridge)
    assert first["attempts"][0]["state"] == "unknown"
    from tools.hierarchy_watch_supervisor import Supervisor
    async_phase(state, error=None, phase="passed")
    final = Supervisor(supervisor.root).step(1, bridge)
    assert final["attempts"][0]["state"] == "completed"
    assert any(row["state"] == "unknown" for row in final["history"])
    assert json.loads(state.read_text())["starts"] == 1


def test_async_consumer_recovers_missing_watch_reference_without_start(async_joined):
    supervisor, journal, bridge, value, state, spec, target = async_joined
    from hierarchy_operator import Operator
    first = Operator(journal.path, spec, evidence_only=True).submit(
        value["id"], journal.target(value)["request_sha256"], journal.operator, 1, target)
    assert first["state"] == "running"
    assert supervisor.status()["attempts"] == []
    result = supervisor.step(1, bridge)
    assert result["attempts"][0]["state"] == "running"
    assert result["attempts"][0]["result"]["intent_id"] == first["intent_id"]
    assert json.loads(state.read_text())["starts"] == 1


@pytest.mark.parametrize("fence", ["capped", "succeeded"])
def test_async_consumer_followup_refusal_retains_possible_effect(async_joined, fence):
    supervisor, journal, bridge, value, state, _, _ = async_joined
    first = supervisor.step(1, bridge)
    original = first["attempts"][0]["result"]
    if fence == "capped":
        journal.event("meter", actor=journal.operator, subject=journal.operator,
                      active_seconds=3600, open_since=None)
        reason = "actor cumulative active cap reached"
    else:
        checkpoint = journal.cli("checkpoint")
        journal.event("succeed", actor="operator-2", predecessor=journal.operator,
                      checkpoint_sha256=checkpoint["sha256"])
        reason = "actor generation is fenced"
    result = supervisor.step(1, bridge)
    assert result["attempts"][0]["state"] == "running"
    assert result["attempts"][0]["result"] == original
    assert result["holds"][value["id"]] == reason
    assert any(row["state"] == "observation_refused" for row in result["history"])
    assert json.loads(state.read_text())["starts"] == 1


def test_async_consumer_denied_successor_observes_original_association(async_joined):
    supervisor, journal, bridge, value, state, spec, target = async_joined
    first = supervisor.step(1, bridge)["attempts"][0]["result"]
    journal.event("decision", actor=journal.root_actor, decision="deny", reason="stop new starts",
                  **journal.target(value))
    checkpoint = journal.cli("checkpoint")
    journal.event("succeed", actor="operator-2", predecessor=journal.operator,
                  checkpoint_sha256=checkpoint["sha256"])
    supervisor.advance(1, 2)
    from tools.hierarchy_watch_bridge import OperatorBridge
    successor = OperatorBridge(journal.path, spec, "operator-2", 2, evidence_only=True, async_target=target)
    result = supervisor.step(2, successor)
    assert result["attempts"][0]["result"]["association"] == first["association"]
    assert result["attempts"][0]["state"] == "running"
    assert json.loads(state.read_text())["starts"] == 1


def test_async_consumer_cancel_ack_is_not_quiescence(async_joined):
    supervisor, journal, bridge, value, state, _, _ = async_joined
    supervisor.step(1, bridge)
    raw = journal.target(value)["request_sha256"]
    ack = bridge.cancel_request(value["id"], raw, "cancel-delivery", "stop existing owned job")
    assert (ack["state"], ack["effect"], ack["provider_state"]) == ("unknown", "possible", "cancel_requested")
    bridge.cancel_request(value["id"], raw, "another-delivery", "do not repeat stop")
    waiting = supervisor.step(1, bridge)
    assert waiting["attempts"][0]["state"] == "unknown"
    assert waiting["attempts"][0]["canonical_settlement"] is None
    async_phase(state, phase="cancelled")
    final = supervisor.step(1, bridge)
    assert final["attempts"][0]["result"]["outcome"] == "failed"
    assert final["attempts"][0]["result"]["exit_code"] == 130
    assert final["work_complete"] is False
    assert json.loads(state.read_text())["cancels"] == 1


@pytest.mark.parametrize("method", ["poll_request", "cancel_request"])
def test_async_consumer_followup_hash_mismatch_has_no_effect(async_joined, method):
    supervisor, journal, bridge, value, state, _, _ = async_joined
    supervisor.step(1, bridge)
    before = journal.files()
    args = [value["id"], "f" * 64, "delivery"]
    if method == "cancel_request":
        args.append("stop existing job")
    with pytest.raises(ValueError, match="^request sha256 mismatch$"):
        getattr(bridge, method)(*args)
    assert journal.files() == before
    assert json.loads(state.read_text())["cancels"] == 0


def test_async_consumer_short_watch_budget_never_submits(async_joined):
    supervisor, journal, bridge, value, state, _, _ = async_joined
    controlled = bridge.with_control(deadline=time.monotonic() + 1, stop_event=None)
    result = controlled.continue_request(value["id"], journal.target(value)["request_sha256"], "delivery")
    assert (result["state"], result["effect"]) == ("refused", "none")
    assert result["reason"] == "watch budget cannot fit the bounded operator transaction"
    assert journal.status()["requests"][value["id"]]["intent"] is None
    assert json.loads(state.read_text())["starts"] == 0


@pytest.mark.parametrize("missing", PROCESS_CAPABILITIES)
def test_async_consumer_unsupported_process_boundary_is_explicit(tmp_path, monkeypatch, missing):
    if os.name != "posix":
        pytest.skip("canonical fixture durability requires POSIX")
    from datetime import datetime, timedelta, timezone
    from tests.integration.test_hierarchy_lifecycle import Ledger, request
    from tools.hierarchy_watch_bridge import OperatorBridge
    journal = Ledger(tmp_path)
    value = request()
    journal.publish(value)
    journal.approve(value)
    spec = {"schema": "aegis.fixture-process-provider/v1", "mode": "fixture", "provider": "fixture",
            "endpoint_id": "one", "argv": [sys.executable, "-c", "raise SystemExit(99)"],
            "cwd": str(tmp_path), "evidence_dir": str(tmp_path / "calls"), "stop_grace": 0.02}
    target = {"provider": "fixture", "endpoint_id": "one", "thread_id": "thread",
              "deadline": (datetime.now(timezone.utc) + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")}
    bridge = OperatorBridge(journal.path, spec, journal.operator, 1, evidence_only=True, async_target=target)
    before = journal.files()
    monkeypatch.delattr(os, missing, raising=False)
    result = bridge.continue_request(value["id"], journal.target(value)["request_sha256"], "delivery")
    assert (result["state"], result["effect"]) == ("refused", "none")
    assert result["reason"] == "process provider requires POSIX waitid WNOWAIT"
    assert journal.files() == before and not (tmp_path / "calls").exists()
