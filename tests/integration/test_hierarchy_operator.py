"""Canonical operator behavior with an explicitly disposable provider boundary."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timedelta, timezone

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


@pytest.fixture
def async_job(ledger):
    """A real bounded call process models the external provider only."""
    if not all(hasattr(os, name) for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")):
        pytest.skip("asynchronous process execution requires POSIX waitid WNOWAIT")
    value = approved(ledger)
    state_path = ledger.tmp / "external-state.json"
    state_path.write_text(json.dumps({"starts": 0, "cancels": 0, "phase": "running", "error": None}))
    config_path = ledger.tmp / "external-config.json"
    config_path.write_text(json.dumps({"state": str(state_path), "evidence": ledger.evidence}))
    script = ledger.tmp / "external_provider.py"
    script.write_text('''import json, sys, time
from pathlib import Path
config = json.loads(Path(sys.argv[1]).read_text())
state_path = Path(config["state"])
state = json.loads(state_path.read_text())
call = json.load(sys.stdin)
method = call["method"]
if method == "inspect":
    result = {"qualified": True, "mode": "fixture", "source": call["request"]["source"],
              "gates": {name: config["evidence"] for name in
                        ("source", "capability", "lease", "capacity", "observer", "job")},
              "reason": "disposable process provider"}
else:
    if method == "submit":
        state["starts"] += 1
    elif method == "cancel":
        state["cancels"] += 1
        state["phase"] = "cancel_requested"
    state_path.write_text(json.dumps(state))
    if method == "submit" and state["error"] == "timeout":
        time.sleep(20)
    phase = state["phase"]
    result = {"association_sha256": call["association_sha256"], "provider_state": phase,
              "provider_handle": {"thread_id": call["association"]["thread_id"],
                                  "turn_id": "other" if state["error"] == "wrong_handle" else state.get("turn_id", "turn-one")},
              "exit_code": 0 if phase == "passed" else 1 if phase == "failed" else 130 if phase == "cancelled" else None,
              "evidence": config["evidence"], "quiescent": phase in ("passed", "failed", "cancelled")}
if method == "submit" and state["error"] == "lost_reply":
    print("malformed reply")
else:
    print(json.dumps({**call, "result": result}))
''')
    spec = {"schema": "aegis.fixture-process-provider/v1", "mode": "fixture", "provider": "fixture",
            "endpoint_id": "external-one", "argv": [sys.executable, str(script), str(config_path)],
            "cwd": str(ledger.tmp), "evidence_dir": str(ledger.tmp / "calls"), "stop_grace": 0.02}
    deadline = (datetime.now(timezone.utc) + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    target = {"provider": "fixture", "endpoint_id": "external-one", "thread_id": "thread-one", "deadline": deadline}
    return ledger, value, module(), spec, target, state_path


def async_start(job):
    ledger, value, candidate, spec, target, _ = job
    operator = candidate.Operator(ledger.path, spec, evidence_only=True)
    result = operator.submit(value["id"], ledger.target(value)["request_sha256"], ledger.operator, 1, target)
    return operator, result


@pytest.mark.parametrize("missing", ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT"))
def test_async_missing_process_capability_refuses_without_intent_or_effect(ledger, monkeypatch, missing):
    value = approved(ledger)
    marker = ledger.tmp / "unexpected-process-effect"
    spec = {"schema": "aegis.fixture-process-provider/v1", "mode": "fixture", "provider": "fixture",
            "endpoint_id": "external-one",
            "argv": [sys.executable, "-c",
                     "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('unexpected effect')",
                     str(marker)],
            "cwd": str(ledger.tmp), "evidence_dir": str(ledger.tmp / "calls"), "stop_grace": 0.02}
    deadline = (datetime.now(timezone.utc) + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    target = {"provider": "fixture", "endpoint_id": "external-one", "thread_id": "thread-one", "deadline": deadline}
    before = ledger.files()
    with monkeypatch.context() as unavailable:
        unavailable.delattr(os, missing, raising=False)
        result = module().Operator(ledger.path, spec, evidence_only=True).submit(
            value["id"], ledger.target(value)["request_sha256"], ledger.operator, 1, target)
    assert (result["state"], result["effect"]) == ("refused", "none"), result
    assert result["reason"] == "process provider requires POSIX waitid WNOWAIT"
    assert result["intent_id"] is None and result["association"] is None
    assert ledger.files() == before
    retained = ledger.status()["requests"][value["id"]]
    assert retained["intent"] is None and retained.get("association") is None
    assert not (ledger.tmp / "calls").exists()
    assert not marker.exists()


def test_async_running_replay_and_terminal_use_one_canonical_intent(async_job):
    ledger, value, _, _, target, state_path = async_job
    operator, first = async_start(async_job)
    assert (first["state"], first["effect"]) == ("running", "possible"), first
    assert first["request_sha256"] == ledger.target(value)["request_sha256"]
    assert first["original_actor"] == ledger.operator and first["original_generation"] == 1
    assert first["association"]["intent_id"] == first["intent_id"]
    from hierarchy_mailbox import digest
    association_event = next(json.loads(p.read_text())["envelope"] for p in (ledger.path / "events").iterdir()
                             if json.loads(p.read_text())["envelope"]["event"]["type"] == "associate")
    assert association_event["id"] == "async-associate-" + digest(first["association"])[:48]
    again = operator.submit(value["id"], first["request_sha256"], ledger.operator, 1, target)
    assert again["intent_id"] == first["intent_id"]
    assert json.loads(state_path.read_text())["starts"] == 1
    state = json.loads(state_path.read_text())
    state["phase"] = "passed"
    state_path.write_text(json.dumps(state))
    final = operator.observe(value["id"], first["request_sha256"], ledger.operator, 1)
    assert (final["state"], final["effect"], final["outcome"]) == ("completed", "confirmed", "passed"), final
    row = ledger.status()["requests"][value["id"]]
    assert row["terminal"]["value"]["intent_id"] == first["intent_id"]
    assert row["review"] is None and row["delivery"] is None and row["resolution"] is None
    assert final["native_qualified"] is False


@pytest.mark.parametrize("error", ["lost_reply", "timeout"])
def test_async_lost_submit_reply_is_never_a_second_start(async_job, error):
    ledger, value, candidate, spec, target, state_path = async_job
    state = json.loads(state_path.read_text())
    state["error"] = error
    state_path.write_text(json.dumps(state))
    _, first = async_start(async_job)
    assert (first["state"], first["effect"]) == ("unknown", "possible"), first
    retained = ledger.status()["requests"][value["id"]]["observations"][-1]["value"]["evidence"]
    assert any(json.loads(Path(ref["path"]).read_text()).get("transport") == "uncertain" for ref in retained)
    restored = candidate.Operator(ledger.path, spec, evidence_only=True)
    again = restored.submit(value["id"], ledger.target(value)["request_sha256"], ledger.operator, 1, target)
    assert again["intent_id"] == first["intent_id"] and again["state"] == "unknown"
    assert json.loads(state_path.read_text())["starts"] == 1
    state = json.loads(state_path.read_text())
    state["error"] = None
    state_path.write_text(json.dumps(state))
    observed = restored.observe(value["id"], first["request_sha256"], ledger.operator, 1)
    assert observed["state"] == "running" and observed["intent_id"] == first["intent_id"], observed


def test_async_running_releases_writer_for_denial_and_current_successor(async_job):
    ledger, value, _, _, _, state_path = async_job
    operator, first = async_start(async_job)
    assert first["state"] == "running", first
    ledger.event("decision", actor="root-1", decision="deny", reason="stop further starts", **ledger.target(value))
    checkpoint = ledger.cli("checkpoint")
    ledger.event("succeed", actor="operator-2", predecessor="operator-1", checkpoint_sha256=checkpoint["sha256"])
    stale = operator.observe(value["id"], first["request_sha256"], "operator-1", 1)
    assert stale["state"] == "refused" and stale["reason"] == "actor generation is fenced"
    assert stale["intent_id"] == first["intent_id"] and stale["association"] == first["association"]
    current = operator.observe(value["id"], first["request_sha256"], "operator-2", 2)
    assert current["state"] == "running", current
    assert current["original_actor"] == "operator-1" and current["original_generation"] == 1
    assert current["association"] == first["association"]
    assert json.loads(state_path.read_text())["starts"] == 1


def test_async_cancel_ack_stays_unknown_until_observed_owned_quiescence(async_job):
    ledger, value, _, _, _, state_path = async_job
    operator, first = async_start(async_job)
    assert first["state"] == "running", first
    ledger.event("decision", actor="root-1", decision="deny", reason="revoke new starts", **ledger.target(value))
    ack = operator.cancel(value["id"], first["request_sha256"], ledger.operator, 1, "stop owned work")
    assert (ack["state"], ack["effect"]) == ("unknown", "possible"), ack
    operator.cancel(value["id"], first["request_sha256"], ledger.operator, 1, "stop owned work")
    assert json.loads(state_path.read_text())["cancels"] == 1
    assert ledger.status()["requests"][value["id"]]["terminal"] is None
    state = json.loads(state_path.read_text())
    state["phase"] = "cancelled"
    state_path.write_text(json.dumps(state))
    settled = operator.observe(value["id"], first["request_sha256"], ledger.operator, 1)
    assert (settled["state"], settled["outcome"], settled["provider_state"]) == ("completed", "failed", "cancelled"), settled
    assert settled["exit_code"] == 130 and settled["native_qualified"] is False
    assert ledger.status()["requests"][value["id"]]["resolution"] is None


def test_async_wrong_handle_cannot_regress_or_settle_running_work(async_job):
    ledger, value, _, _, _, state_path = async_job
    operator, first = async_start(async_job)
    assert first["state"] == "running", first
    state = json.loads(state_path.read_text())
    state.update(error="wrong_handle", phase="passed")
    state_path.write_text(json.dumps(state))
    observed = operator.observe(value["id"], first["request_sha256"], ledger.operator, 1)
    assert (observed["state"], observed["effect"]) == ("unknown", "possible"), observed
    assert observed["reason"] == "process provider handle correlation mismatch"
    assert ledger.status()["requests"][value["id"]]["terminal"] is None


def test_async_wrong_request_hash_refuses_before_any_new_intent(async_job):
    ledger, value, candidate, spec, target, state_path = async_job
    result = candidate.Operator(ledger.path, spec, evidence_only=True).submit(value["id"], "0" * 64,
                                                                           ledger.operator, 1, target)
    assert result["state"] == "refused" and result["reason"] == "request sha256 mismatch"
    assert ledger.status()["requests"][value["id"]]["intent"] is None
    assert json.loads(state_path.read_text())["starts"] == 0


@pytest.mark.parametrize("change,error", [
    ({"intent_id": "caller-minted"}, "unexpected fields: intent_id"),
    ({"deadline": "2100-01-01T00:00:00Z"}, "execution deadline expired or exceeds authority"),
    ({"deadline": "2098-01-01T00:00:00Z"}, "execution deadline exceeds original actor cap"),
    ({"thread_id": "x" * 257}, "invalid provider thread_id"),
])
def test_async_target_cannot_mint_intent_or_expand_scope_before_publication(async_job, change, error):
    ledger, value, candidate, spec, target, state_path = async_job
    target.update(change)
    before = ledger.files()
    refused = candidate.Operator(ledger.path, spec, evidence_only=True).submit(
        value["id"], ledger.target(value)["request_sha256"], ledger.operator, 1, target)
    assert refused["state"] == "refused" and refused["reason"] == error, refused
    assert ledger.files() == before and json.loads(state_path.read_text())["starts"] == 0


def test_async_256_character_thread_and_turn_identifiers_use_the_same_binding(async_job):
    ledger, value, _, _, target, state_path = async_job
    target["thread_id"] = "t" * 256
    state = json.loads(state_path.read_text())
    state["turn_id"] = "u" * 256
    state_path.write_text(json.dumps(state))
    operator, first = async_start(async_job)
    assert first["state"] == "running", first
    assert first["provider_handle"] == {"thread_id": "t" * 256, "turn_id": "u" * 256}
    state = json.loads(state_path.read_text())
    state["phase"] = "passed"
    state_path.write_text(json.dumps(state))
    observed = operator.observe(value["id"], first["request_sha256"], ledger.operator, 1)
    assert observed["state"] == "completed" and observed["outcome"] == "passed", observed


@pytest.mark.parametrize("method", ["submit", "observe", "cancel"])
def test_async_native_defaults_refuse_before_opening_a_ledger(tmp_path, method):
    candidate = module()
    root = tmp_path / "missing"
    operator = candidate.Operator(root, {})
    args = ["work", "a" * 64, "operator-1", 1]
    if method == "submit":
        args.append({})
    elif method == "cancel":
        args.append("stop")
    result = getattr(operator, method)(*args)
    assert result["state"] == "refused" and result["reason"] == candidate.NATIVE_HOLD
    assert result["native_qualified"] is False and not root.exists()


@pytest.mark.parametrize("actor,generation,error", [("root-1", 1, "role root cannot record admit"),
                                                   ("router-1", 1, "role router cannot record admit"),
                                                   ("operator-1", 2, "stale actor generation")])
def test_async_role_and_generation_refuse_before_an_attempt(async_job, actor, generation, error):
    ledger, value, candidate, spec, target, state_path = async_job
    before = ledger.files()
    result = candidate.Operator(ledger.path, spec, evidence_only=True).submit(
        value["id"], ledger.target(value)["request_sha256"], actor, generation, target)
    assert result["state"] == "refused" and result["reason"] == error
    assert ledger.files() == before and json.loads(state_path.read_text())["starts"] == 0


def test_async_denial_before_submit_refuses_without_consuming_intent(async_job):
    ledger, value, _, _, _, state_path = async_job
    ledger.event("decision", actor="root-1", decision="deny", reason="deny before start", **ledger.target(value))
    _, refused = async_start(async_job)
    assert refused["state"] == "refused" and refused["reason"] == "no approved bounded authority"
    assert ledger.status()["requests"][value["id"]]["intent"] is None
    assert json.loads(state_path.read_text())["starts"] == 0


def test_async_running_reconciliation_retains_old_unknown_history_without_terminal_claim(async_job):
    ledger, value, _, _, _, _ = async_job
    operator, first = async_start(async_job)
    assert first["state"] == "running", first
    from tests.integration.test_hierarchy_lifecycle import raw_request
    result = {"request_sha256": first["request_sha256"], "intent_id": first["intent_id"],
              "source": value["source"], "outcome": "unknown", "exit_code": None, "evidence": ledger.evidence}
    ledger.event("terminal", actor=ledger.operator, result=raw_request(result), **ledger.target(value))
    observed = operator.observe(value["id"], first["request_sha256"], ledger.operator, 1)
    assert observed["state"] == "running" and observed["outcome"] is None and observed["exit_code"] is None
    row = ledger.status()["requests"][value["id"]]
    assert row["results"][0]["value"]["outcome"] == "unknown"
    assert row["review"] is None and row["resolution"] is None


@pytest.mark.parametrize("method", ["submit", "observe"])
def test_async_failed_terminal_publication_cannot_return_speculative_terminal_proof(async_job, monkeypatch, method):
    ledger, value, candidate, spec, target, state_path = async_job
    if method == "observe":
        operator, first = async_start(async_job)
        assert first["state"] == "running", first
    else:
        operator = candidate.Operator(ledger.path, spec, evidence_only=True)
        first = ledger.target(value)
    state = json.loads(state_path.read_text())
    state["phase"] = "passed"
    state_path.write_text(json.dumps(state))
    original = os.link

    def link(source, target, *args, **kwargs):
        path = Path(target)
        if path.parent == ledger.path / "events" and json.loads(Path(source).read_text())["envelope"]["event"]["type"] == "terminal":
            raise OSError("terminal publication failed before write")
        return original(source, target, *args, **kwargs)

    monkeypatch.setattr(os, "link", link)
    if method == "observe":
        result = operator.observe(value["id"], first["request_sha256"], ledger.operator, 1)
    else:
        result = operator.submit(value["id"], first["request_sha256"], ledger.operator, 1, target)
    assert (result["state"], result["effect"]) == ("unknown", "possible"), result
    assert result["reason"] == "terminal publication failed before write"
    assert ledger.status()["requests"][value["id"]]["terminal"] is None
    assert result["outcome"] is None and result["exit_code"] is None and result["terminal_sha256"] is None
    assert json.loads(state_path.read_text())["starts"] == 1


def test_async_lost_terminal_publication_reply_recovers_without_another_start(async_job, monkeypatch):
    ledger, value, candidate, spec, target, state_path = async_job
    state = json.loads(state_path.read_text())
    state["phase"] = "passed"
    state_path.write_text(json.dumps(state))
    original = os.link

    def link(source, target, *args, **kwargs):
        original(source, target, *args, **kwargs)
        path = Path(target)
        if path.parent == ledger.path / "events" and json.loads(path.read_text())["envelope"]["event"]["type"] == "terminal":
            raise OSError("terminal publication reply lost after write")

    monkeypatch.setattr(os, "link", link)
    operator = candidate.Operator(ledger.path, spec, evidence_only=True)
    first = operator.submit(value["id"], ledger.target(value)["request_sha256"], ledger.operator, 1, target)
    assert first["state"] == "unknown" and first["effect"] == "possible"
    assert ledger.status()["requests"][value["id"]]["terminal"]["value"]["outcome"] == "passed"
    recovered = operator.submit(value["id"], first["request_sha256"], ledger.operator, 1, target)
    assert recovered["state"] == "completed" and recovered["outcome"] == "passed"
    assert recovered["intent_id"] == first["intent_id"]
    assert json.loads(state_path.read_text())["starts"] == 1


def test_async_lost_association_publication_reply_never_dispatches_again(async_job, monkeypatch):
    ledger, value, candidate, spec, target, state_path = async_job
    original = os.link

    def link(source, target, *args, **kwargs):
        original(source, target, *args, **kwargs)
        path = Path(target)
        if path.parent == ledger.path / "events" and json.loads(path.read_text())["envelope"]["event"]["type"] == "associate":
            raise OSError("association reply lost")

    monkeypatch.setattr(os, "link", link)
    _, first = async_start(async_job)
    assert first["state"] == "unknown" and first["reason"] == "association reply lost"
    row = ledger.status()["requests"][value["id"]]
    assert row["association"]["value"]["intent_id"] == first["intent_id"]
    again = candidate.Operator(ledger.path, spec, evidence_only=True).submit(
        value["id"], first["request_sha256"], ledger.operator, 1, target)
    assert again["state"] == "unknown" and again["intent_id"] == first["intent_id"]
    assert json.loads(state_path.read_text())["starts"] == 0


def test_async_stop_after_start_expiry_preserves_original_authority_and_cap(async_job, monkeypatch):
    ledger, value, candidate, _, target, state_path = async_job
    import hierarchy_lifecycle
    clock = ["2098-12-31T23:50:00Z"]
    monkeypatch.setattr(candidate, "timestamp", lambda: clock[0])
    monkeypatch.setattr(hierarchy_lifecycle, "timestamp", lambda: clock[0])
    target["deadline"] = "2099-01-01T00:00:00Z"
    operator, first = async_start(async_job)
    assert first["state"] == "running", first
    clock[0] = "2099-01-01T00:00:01Z"
    observed = operator.observe(value["id"], first["request_sha256"], ledger.operator, 1)
    assert observed["state"] == "running", observed
    ack = operator.cancel(value["id"], first["request_sha256"], ledger.operator, 1, "stop expired owned job")
    assert ack["state"] == "unknown", ack
    assert ack["association"] == first["association"]
    assert ack["association"]["original_cap_seconds"] == 3600
    assert ack["association"]["authority_expires_at"] == "2099-01-01T00:00:00Z"
    assert json.loads(state_path.read_text())["starts"] == 1
    assert json.loads(state_path.read_text())["cancels"] == 1


def test_async_legacy_unassociated_intent_and_historical_checkpoint_are_unchanged(async_job):
    ledger, value, candidate, spec, target, state_path = async_job
    from hierarchy_lifecycle import Lifecycle, checkpoint
    from hierarchy_mailbox import digest, encoded, timestamp
    ledger.admit(value)
    ledger.intent(value)
    lifecycle = Lifecycle(ledger.path)
    policy, state = lifecycle.load()
    historical = copy.deepcopy(state)
    old_keys = ("request", "raw", "publisher", "read", "routed", "admission", "wait", "intent", "start",
                "terminal", "results", "review", "delivery", "resolution", "dispositions")
    historical["requests"][value["id"]] = {key: state["requests"][value["id"]][key] for key in old_keys}
    # Archive a genuine v1-shaped succession checkpoint; eager new projection
    # keys would make load reject its stored checkpoint hash.
    envelope = {"id": "legacy-succession", "actor": "operator-2", "generation": 2,
                "custody": {"cid": "root-1", "generation": 1},
                "event": {"type": "succeed", "predecessor": "operator-1",
                          "checkpoint_sha256": checkpoint(policy, historical)["sha256"]}}
    record = {"schema": "aegis.lifecycle-event/v1", "sequence": state["sequence"] + 1,
              "previous": state["head"], "policy_sha256": digest(policy), "at": timestamp(),
              "envelope": envelope, "event_sha256": digest(envelope)}
    (ledger.path / "events" / ("%06d.json" % record["sequence"])).write_bytes(encoded(record) + b"\n")
    before = ledger.files()
    checkpoint_before = ledger.cli("checkpoint")
    retained = candidate.Operator(ledger.path, spec, evidence_only=True).submit(
        value["id"], ledger.target(value)["request_sha256"], "operator-2", 2, target)
    assert retained["state"] == "unknown" and retained["intent_id"] == "attempt-1"
    assert ledger.cli("checkpoint") == checkpoint_before and ledger.files() == before
    assert "association" not in ledger.status()["requests"][value["id"]]
    assert json.loads(state_path.read_text())["starts"] == 0
