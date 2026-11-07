"""Public read-only views; fixture records provide no native authority."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

from tests.integration.test_hierarchy_lifecycle import Ledger, request
from tests.integration.test_hierarchy_workspace import Workspace


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hierarchy_provider_recovery.py"


def module():
    spec = importlib.util.spec_from_file_location("provider_recovery_candidate", TOOL)
    candidate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)
    return candidate


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.fixture
def ledger(tmp_path):
    if os.name != "posix":
        pytest.skip("fixture journal creation requires POSIX directory fsync")
    return Ledger(tmp_path)


@pytest.fixture
def workspace(tmp_path):
    space = Workspace(tmp_path)
    space.run("init", {"writer_limit": 3, "heavy_limit": 3})
    space.register("pilot")
    space.ask("pilot", "heavy", "job:pilot/original")
    space.grant("heavy")
    return space


def associated(ledger):
    from tools.hierarchy_lifecycle import Lifecycle
    from tools.hierarchy_mailbox import digest

    value = ledger.ready()
    ledger.intent(value)
    ledger.event("start", actor=ledger.operator, intent_id="attempt-1", **ledger.target(value))
    policy, state = Lifecycle(ledger.path).load()
    row = state["requests"][value["id"]]
    association = {
        "schema": "aegis.provider-association/v1", **ledger.target(value), "intent_id": "attempt-1",
        "source": value["source"], "authority": value["authority"],
        "authority_sha256": row["raw"]["sha256"],
        "decision_sha256": digest(state["decisions"][-1]), "admission_sha256": digest(row["admission"]),
        "original_actor": ledger.operator, "original_generation": 1,
        "original_cap_seconds": policy["actors"][ledger.operator]["cap_seconds"],
        "authority_expires_at": value["continuation"]["expires_at"], "provider": "fixture",
        "endpoint_id": "retained-endpoint", "thread_id": "not-a-workspace-job",
        "client_id": "client-attempt-1",
        "deadline": (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
    }
    ledger.event("associate", actor=ledger.operator, association=association, **ledger.target(value))
    return value, association, digest(association)


def observe(ledger, value, association_hash, phase="running"):
    terminal = phase in {"passed", "failed", "cancelled"}
    record = {"association_sha256": association_hash, "provider_state": phase,
              "provider_handle": {"thread_id": "not-a-workspace-job", "turn_id": "retained-turn"},
              "exit_code": 0 if phase == "passed" else 1 if terminal else None,
              "quiescent": terminal, "evidence": ledger.evidence}
    ledger.event("observe", actor=ledger.operator, intent_id="attempt-1", association_sha256=association_hash,
                 observation=record, **ledger.target(value))
    return record


def test_public_module_exists():
    assert TOOL.is_file(), "public provider recovery module is missing"


def test_legacy_unassociated_intent_is_read_only_and_has_no_invented_job(ledger):
    value = ledger.ready()
    ledger.intent(value)
    before = ledger.files()
    status = module().provider_status(ledger.path, value["id"], ledger.target(value)["request_sha256"])
    assert status["schema"] == "aegis.provider-recovery/v1"
    assert status["read_only"] is True and status["native_qualified"] is False
    assert status["intent"]["id"] == "attempt-1"
    assert status["association"] is None and status["provider_handle"] is None
    assert status["original"] is None
    assert status["mapping"] == {"state": "unavailable",
                                 "reason": "original provider-to-job admission binding is not available"}
    assert ledger.files() == before


def test_provider_preserves_original_association_and_cancel_uncertainty(ledger):
    value, association, association_hash = associated(ledger)
    observe(ledger, value, association_hash)
    ledger.event("cancel_attempt", actor=ledger.operator, intent_id="attempt-1",
                 association_sha256=association_hash, reason="bounded stop request", **ledger.target(value))
    observe(ledger, value, association_hash, "cancel_requested")
    before = ledger.files()
    candidate = module()
    status = candidate.provider_status(ledger.path, value["id"], ledger.target(value)["request_sha256"])
    assert status["association"] == {"value": association, "sha256": association_hash}
    assert status["original"] == {key: association[key] for key in
                                  ("original_actor", "original_generation", "original_cap_seconds",
                                   "authority_expires_at", "deadline")}
    assert status["observation"]["value"]["provider_state"] == "cancel_requested"
    assert status["observation"]["value"]["quiescent"] is False
    assert status["cancellation"]["reason"] == "bounded stop request"
    assert candidate.provider_status(ledger.path, value["id"], ledger.target(value)["request_sha256"]) == status
    assert ledger.files() == before


def test_late_terminal_observation_preserves_historical_unknown(ledger):
    value, _, association_hash = associated(ledger)
    observe(ledger, value, association_hash, "unknown")
    ledger.terminal(value, "unknown")
    observe(ledger, value, association_hash, "passed")
    before = ledger.files()
    status = module().provider_status(ledger.path, value["id"], ledger.target(value)["request_sha256"])
    assert status["observation"]["value"]["provider_state"] == "passed"
    assert status["terminal"]["value"]["outcome"] == "unknown"
    assert status["mapping"]["state"] == "unavailable"
    assert ledger.files() == before


def test_denial_does_not_erase_original_recovery_evidence(ledger):
    value, association, _ = associated(ledger)
    ledger.event("decision", actor=ledger.root_actor, decision="deny", reason="revoked", **ledger.target(value))
    status = module().provider_status(ledger.path, value["id"], ledger.target(value)["request_sha256"])
    assert status["association"]["value"] == association
    assert status["mapping"]["state"] == "unavailable"


@pytest.mark.parametrize("identifier,hash_value,error", [
    ("../bad", "0" * 64, "invalid request id"),
    ("missing", "0" * 64, "unknown canonical request: missing"),
    ("engine-partial", "bad", "invalid request sha256"),
    ("engine-partial", "0" * 64, "canonical request sha256 mismatch"),
])
def test_provider_invalid_or_conflicting_reference_refuses_without_writes(ledger, identifier, hash_value, error):
    ledger.publish(request())
    before = ledger.files()
    with pytest.raises(ValueError, match="^" + error + "$"):
        module().provider_status(ledger.path, identifier, hash_value)
    assert ledger.files() == before


def test_missing_provider_store_fails_loudly_and_creates_nothing(tmp_path):
    path = tmp_path / "missing"
    with pytest.raises(FileNotFoundError):
        module().provider_status(path, "original", "0" * 64)
    assert not path.exists()


def test_registered_reservation_without_claim_is_orphan_and_retains_capacity(workspace):
    before = snapshot(workspace.store)
    status = module().job_status(workspace.store, "pilot/original")
    assert status["projection"]["state"] == "reserved_not_started"
    assert status["payload_effect"] == "unknown"
    assert status["projection_scope"] == "existing_workspace_job_inventory"
    assert status["correlation"] == {"state": "orphan", "reason": "original mailbox job_request is unavailable"}
    assert status["capacity_scope"] == "ledger_only" and status["capacity"]["heavy"]["used"] == 1
    assert status["projection"]["reservations"][0]["holder"] == "job:pilot/original"
    assert "expires_at" not in status["projection"]["reservations"][0]
    assert snapshot(workspace.store) == before


def test_partial_claim_folder_never_becomes_safe_no_effect(workspace):
    folder = workspace.store / "jobs" / "pilot" / "original"
    folder.mkdir(parents=True)
    before = snapshot(workspace.store)
    status = module().job_status(workspace.store, "pilot/original")
    assert status["projection"]["state"] == "unknown_effect"
    assert status["projection"]["claim"] is None
    assert status["payload_effect"] == "unknown" and status["capacity"]["heavy"]["used"] == 1
    assert snapshot(workspace.store) == before


def test_orphan_folder_does_not_manufacture_mailbox_request(workspace):
    (workspace.store / "jobs" / "pilot" / "orphan").mkdir(parents=True)
    before = snapshot(workspace.store)
    status = module().job_status(workspace.store, "pilot/orphan")
    assert status["correlation"]["state"] == "orphan"
    assert status["payload_effect"] == "unknown"
    assert status["projection"]["source"]["state"] == "unavailable"
    assert snapshot(workspace.store) == before


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="original process scope uses Linux /proc")
def test_old_owner_scope_and_terminal_result_cannot_release_capacity(workspace):
    folder = workspace.store / "jobs" / "pilot" / "original"
    folder.mkdir(parents=True)
    (folder / "claim.json").write_text(json.dumps({"job": "pilot/original", "pid": 999999,
                                                   "start": "1", "process_scope": {"boot_id": "old"}}))
    (folder / "result.json").write_text(json.dumps({"schema": "aegis.hierarchy-job-result/v1",
                                                    "job": "pilot/original", "state": "completed",
                                                    "exit_code": 0, "steps": []}))
    before = snapshot(workspace.store)
    status = module().job_status(workspace.store, "pilot/original")
    assert status["projection"]["state"] == "evidence_error"
    assert status["projection"]["error"] == "job process scope is unknown: pilot/original"
    assert status["projection"]["result"]["state"] == "completed"
    assert status["payload_effect"] == "unknown" and status["capacity"]["heavy"]["used"] == 1
    assert snapshot(workspace.store) == before


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="original PID start witness uses Linux /proc")
def test_reused_pid_with_different_start_retains_unknown_and_original_grant(workspace):
    from tools.hierarchy_jobs import process_scope

    folder = workspace.store / "jobs" / "pilot" / "original"
    folder.mkdir(parents=True)
    (folder / "claim.json").write_text(json.dumps({"job": "pilot/original", "pid": os.getpid(),
                                                   "start": "0", "process_scope": process_scope()}))
    before = snapshot(workspace.store)
    status = module().job_status(workspace.store, "pilot/original")
    assert status["projection"]["runner_alive"] is False
    assert status["projection"]["state"] == "unknown_effect"
    assert status["payload_effect"] == "unknown" and status["capacity"]["heavy"]["used"] == 1
    assert snapshot(workspace.store) == before


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="process read-denial boundary uses Linux /proc")
def test_unreadable_original_process_is_reported_without_capacity_release(workspace, monkeypatch):
    from tools.hierarchy_jobs import process_scope

    folder = workspace.store / "jobs" / "pilot" / "original"
    folder.mkdir(parents=True)
    (folder / "claim.json").write_text(json.dumps({"job": "pilot/original", "pid": 81001,
                                                   "start": "1", "process_scope": process_scope()}))
    original = Path.read_text

    def read(path, *args, **kwargs):
        if str(path) == "/proc/81001/stat":
            raise PermissionError("visibility denied")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    before = snapshot(workspace.store)
    status = module().job_status(workspace.store, "pilot/original")
    assert status["projection"]["state"] == "evidence_error"
    assert status["projection"]["error"] == "cannot observe process 81001: visibility denied"
    assert status["payload_effect"] == "unknown" and status["capacity"]["heavy"]["used"] == 1
    assert snapshot(workspace.store) == before


@pytest.mark.skipif(os.name == "nt", reason="generated profiles and wakes are POSIX only")
def test_real_original_mailbox_job_remains_unbound_to_provider_identity(tmp_path):
    from tests.integration.test_hierarchy_mailbox import git, invoke
    from tests.integration.test_hierarchy_provision import Setup

    built = Setup(tmp_path)
    built.init()
    built.add_role("pilot/orchestrator", cwd=str(tmp_path))
    built.add_role("pilot/root", "codex-cli", session="fixture-root")
    built.workspace.run("update", {"initiative": "pilot", "source": "owner", "checkouts": [str(built.source)]})
    packet = {"schema": "aegis.hierarchy-job-packet/v1", "recipe": "original-recipe",
              "checkout": str(built.source), "commit": git(built.source, "rev-parse", "HEAD"),
              "tree": git(built.source, "rev-parse", "HEAD^{tree}")}
    brief = built.root.parent / "original-packet.md"
    brief.write_text(json.dumps(packet))
    binding = invoke(built.root, "status")["bindings"]["pilot/orchestrator"]
    invoke(built.root, "publish", {"message_id": "original", "from": "pilot/orchestrator", "to": "pilot/root",
                                  "host": binding["host"], "session": binding["session"],
                                  "binding_generation": binding["generation"], "type": "job_request",
                                  "body": "Original fixture job packet.",
                                  "brief": {"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}})
    built.workspace.ask("pilot", "heavy", "job:pilot/original")
    built.workspace.grant("heavy")
    before = snapshot(built.workspace.store), snapshot(built.root)
    status = module().job_status(built.workspace.store, "pilot/original")
    assert status["correlation"]["state"] == "unbound"
    assert status["projection"]["source"]["state"] == "match"
    assert status["payload_effect"] == "unknown" and status["capacity"]["heavy"]["used"] == 1
    assert (snapshot(built.workspace.store), snapshot(built.root)) == before


@pytest.mark.parametrize("identifier,error", [
    ("pilot/missing", "unknown workspace job: pilot/missing"),
    ("../original", "invalid job: ../original"),
])
def test_unknown_or_malformed_job_is_not_invented(workspace, identifier, error):
    before = snapshot(workspace.store)
    with pytest.raises(ValueError, match="^" + error.replace(".", r"\.") + "$"):
        module().job_status(workspace.store, identifier)
    assert snapshot(workspace.store) == before


def test_cli_provider_reference_error_is_exact_json_and_no_effect(ledger):
    value = ledger.ready()
    before = ledger.files()
    proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "--lifecycle", str(ledger.path),
                           "provider", "--request-id", value["id"], "--request-sha256", "0" * 64],
                          capture_output=True, text=True, timeout=10)
    assert proc.returncode == 2 and proc.stderr == ""
    assert json.loads(proc.stdout) == {"error": "canonical request sha256 mismatch"}
    assert ledger.files() == before
