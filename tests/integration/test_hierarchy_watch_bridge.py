"""The supported bridge keeps unsupported native execution explicitly held."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hierarchy_watch_bridge.py"


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
