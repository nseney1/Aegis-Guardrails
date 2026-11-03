"""Canonical operator behavior with an explicitly disposable provider boundary."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hierarchy_operator.py"
pytestmark = pytest.mark.skipif(os.name != "posix", reason="canonical journal requires POSIX durability")


def module():
    spec = importlib.util.spec_from_file_location("operator_candidate", TOOL)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


@pytest.fixture
def ledger(tmp_path):
    from tests.integration.test_hierarchy_lifecycle import Ledger
    return Ledger(tmp_path)


class DisposableProvider:
    """External effect boundary; never a production native adapter."""
    def __init__(self, ledger, *, outcome="passed", fail_after_effect=False):
        self.ledger = ledger
        self.outcome = outcome
        self.fail_after_effect = fail_after_effect
        self.calls = 0
        self.inspections = 0
        self.change_on_second_inspect = False

    def inspect(self, request, actor, generation):
        self.inspections += 1
        source = copy.deepcopy(request["source"])
        if self.change_on_second_inspect and self.inspections > 1:
            source["commit"] = "d" * 40
        return {"qualified": True, "mode": "fixture", "source": source,
                "gates": {name: self.ledger.evidence for name in
                          ("source", "capability", "lease", "capacity", "observer", "job")},
                "reason": "disposable provider"}

    def execute(self, request, intent_id):
        self.calls += 1
        marker = self.ledger.tmp / "effect.json"
        marker.write_text(json.dumps({"request": request["id"], "intent": intent_id, "calls": self.calls}))
        if self.fail_after_effect:
            raise TimeoutError("provider reply lost after effect")
        return {"outcome": self.outcome, "exit_code": 0 if self.outcome == "passed" else 1,
                "evidence": self.ledger.evidence}


def approved(ledger):
    from tests.integration.test_hierarchy_lifecycle import request
    value = request()
    ledger.publish(value)
    ledger.approve(value)
    return value


def test_native_cli_refuses_before_mutating_any_canonical_state(tmp_path):
    root = tmp_path / "missing-ledger"
    proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "--lifecycle", str(root),
                           "--actor", "operator-1", "--generation", "1", "execute", "--request-id", "request-1"],
                          capture_output=True, text=True, timeout=10)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert not proc.stderr, proc.stderr
    result = json.loads(proc.stdout)
    assert result["state"] == "refused" and result["effect"] == "none"
    assert result["reason"] == "authenticated native operator execution is unavailable"
    assert not root.exists()


def test_explicit_fixture_effect_records_canonical_intent_and_result_once(ledger):
    value = approved(ledger)
    provider = DisposableProvider(ledger)
    operator = module().Operator(ledger.path, provider, evidence_only=True)
    first = operator.execute(value["id"], "operator-1", 1)
    assert first["state"] == "completed" and first["effect"] == "confirmed"
    assert first["native_qualified"] is False
    second = operator.execute(value["id"], "operator-1", 1)
    assert second["intent_id"] == first["intent_id"]
    assert provider.calls == 1
    row = ledger.status()["requests"][value["id"]]
    assert row["intent"]["id"] == first["intent_id"]
    assert row["terminal"]["value"]["outcome"] == "passed"
    assert row["review"] is None and row["delivery"] is None


@pytest.mark.parametrize("actor,generation,error", [
    ("root-1", 1, "role root cannot record admit"),
    ("router-1", 1, "role router cannot record admit"),
    ("operator-1", 2, "stale actor generation"),
])
def test_role_and_generation_refuse_before_effect(ledger, actor, generation, error):
    value = approved(ledger)
    provider = DisposableProvider(ledger)
    before = ledger.files()
    result = module().Operator(ledger.path, provider, evidence_only=True).execute(value["id"], actor, generation)
    assert result["state"] == "refused" and result["reason"] == error
    assert provider.calls == 0 and ledger.files() == before


def test_local_fixture_claim_cannot_enable_production_execution(ledger):
    value = approved(ledger)
    provider = DisposableProvider(ledger)
    before = ledger.files()
    result = module().Operator(ledger.path, provider).execute(value["id"], "operator-1", 1)
    assert result["reason"] == "authenticated native operator execution is unavailable"
    assert provider.calls == 0 and ledger.files() == before


def test_unapproved_request_is_refused_before_effect(ledger):
    from tests.integration.test_hierarchy_lifecycle import request
    value = request()
    ledger.publish(value)
    provider = DisposableProvider(ledger)
    result = module().Operator(ledger.path, provider, evidence_only=True).execute(value["id"], "operator-1", 1)
    assert result["state"] == "refused"
    assert result["reason"] == "no approved bounded authority"
    assert provider.calls == 0


def test_source_revalidation_after_intent_refuses_effect_and_retains_unknown(ledger):
    value = approved(ledger)
    provider = DisposableProvider(ledger)
    provider.change_on_second_inspect = True
    result = module().Operator(ledger.path, provider, evidence_only=True).execute(value["id"], "operator-1", 1)
    assert result["state"] == "unknown" and result["effect"] == "possible"
    assert result["reason"] == "provider source mismatch"
    assert provider.calls == 0
    assert ledger.status()["obligations"][0]["state"] == "unknown_effect"


def test_lost_reply_retains_intent_and_restart_never_reexecutes(ledger):
    value = approved(ledger)
    provider = DisposableProvider(ledger, fail_after_effect=True)
    first = module().Operator(ledger.path, provider, evidence_only=True).execute(value["id"], "operator-1", 1)
    assert first["state"] == "unknown" and first["effect"] == "possible"
    assert "provider reply lost after effect" in first["reason"]
    resumed = module().Operator(ledger.path, provider, evidence_only=True).execute(value["id"], "operator-1", 1)
    assert resumed["state"] == "unknown" and resumed["intent_id"] == first["intent_id"]
    assert provider.calls == 1


def test_tampered_gate_evidence_refuses_before_intent(ledger):
    value = approved(ledger)
    ledger.evidence_path.write_text("changed evidence")
    provider = DisposableProvider(ledger)
    result = module().Operator(ledger.path, provider, evidence_only=True).execute(value["id"], "operator-1", 1)
    assert result["state"] == "refused"
    assert result["reason"] == "gate evidence sha256 mismatch"
    assert provider.calls == 0
    assert ledger.status()["requests"][value["id"]]["intent"] is None


def test_failure_is_terminal_but_does_not_establish_acceptance(ledger):
    value = approved(ledger)
    provider = DisposableProvider(ledger, outcome="failed")
    result = module().Operator(ledger.path, provider, evidence_only=True).execute(value["id"], "operator-1", 1)
    assert result["state"] == "completed"
    row = ledger.status()["requests"][value["id"]]
    assert row["terminal"]["value"]["outcome"] == "failed"
    assert row["review"] is None and row["resolution"] is None


def test_lost_intent_publication_reply_cannot_claim_no_effect_or_redispatch(ledger, monkeypatch):
    value = approved(ledger)
    provider = DisposableProvider(ledger)
    original = os.link

    def link(source, target, *args, **kwargs):
        original(source, target, *args, **kwargs)
        path = Path(target)
        if path.parent == ledger.path / "events" and json.loads(path.read_text())["envelope"]["event"]["type"] == "intent":
            raise OSError("lost intent publication reply")

    monkeypatch.setattr(os, "link", link)
    result = module().Operator(ledger.path, provider, evidence_only=True).execute(value["id"], "operator-1", 1)
    assert result["state"] == "unknown" and result["effect"] == "possible"
    assert result["intent_id"] == ledger.status()["requests"][value["id"]]["intent"]["id"]
    assert provider.calls == 0
    resumed = module().Operator(ledger.path, provider, evidence_only=True).execute(value["id"], "operator-1", 1)
    assert resumed["state"] == "unknown"
    assert provider.calls == 0


def test_contending_attempt_cannot_execute_from_stale_eligibility(ledger):
    value = approved(ledger)
    candidate = module()
    contender = DisposableProvider(ledger, fail_after_effect=True)
    competing_results = []

    class ScheduledProvider(DisposableProvider):
        def inspect(self, request, actor, generation):
            if self.inspections == 0:
                competing_results.append(candidate.Operator(ledger.path, contender, evidence_only=True)
                                         .execute(value["id"], actor, generation))
            return super().inspect(request, actor, generation)

    provider = ScheduledProvider(ledger)
    result = candidate.Operator(ledger.path, provider, evidence_only=True).execute(value["id"], "operator-1", 1)
    assert provider.calls + contender.calls == 1
    assert result["state"] == "completed"
    assert competing_results[0]["state"] == "refused"
    assert competing_results[0]["effect"] == "none"
    assert competing_results[0]["reason"] == "canonical operator execution is already in progress"
