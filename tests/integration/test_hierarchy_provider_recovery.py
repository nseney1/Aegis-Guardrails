"""Public read-only views; fixture records provide no native authority."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

from tests.integration.test_hierarchy_lifecycle import Ledger, request
from tests.integration.test_hierarchy_jobs import kind_shop as kind_shop
from tests.integration.test_hierarchy_workspace import Workspace
from tests.integration import provider_recovery_admissions as admissions
import hierarchy_jobs as process_jobs
from tests.conftest import symlink_or_skip


pytest_plugins = ("tests.integration.provider_recovery_admissions",)
__all__ = ("kind_shop",)


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
    class UnreadableStat:
        def read_text(self, *args, **kwargs):
            raise PermissionError("visibility denied")

    def process_path(value):
        return UnreadableStat() if str(value) == "/proc/81001/stat" else Path(value)

    monkeypatch.setattr(process_jobs, "Path", process_path)
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


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="planned job evidence uses Linux /proc")
@pytest.mark.parametrize("terminal", ["completed", "failed", None], ids=["finished", "failed", "unsettled"])
@pytest.mark.parametrize("recipes", ["match", "mismatch", "absent"])
@pytest.mark.parametrize("surface", ["api", "cli-before", "cli-after"])
def test_planned_job_recipe_matrix(planned_admission, capsys, terminal, recipes, surface):
    from tests.integration.test_hierarchy_jobs_followups import ADMISSION_UNVERIFIED_ACTION

    shop = planned_admission
    trusted = None if recipes == "absent" else shop.recipes_path
    candidate = module()
    before = admissions.typed_snapshot(shop.root)
    try:
        if surface == "api":
            status = (candidate.job_status(shop.store, "pilot/job-1") if trusted is None else
                      candidate.job_status(shop.store, "pilot/job-1", recipes_path=trusted))
        else:
            recipe_args = [] if trusted is None else ["--recipes", str(trusted)]
            argv = ["--store", str(shop.store)]
            argv += (recipe_args + ["job", "--job", "pilot/job-1"] if surface == "cli-before" else
                     ["job", "--job", "pilot/job-1"] + recipe_args)
            assert candidate.main(argv) == 0
            status = json.loads(capsys.readouterr().out)
        row = status["projection"]
        expected = "finished" if terminal else {"match": "admitted", "mismatch": "evidence_error",
                                                "absent": "admission_unverified"}[recipes]
        assert row["state"] == expected, row
        assert status["read_only"] is True and status["payload_effect"] == "unknown"
        if terminal:
            assert row["result"]["state"] == terminal and row["receipt"] == "match"
            assert "error" not in row
        elif recipes == "absent":
            assert row["source"] == {"state": "unavailable", "reason": "planned recipe path absent",
                                     "recipe_bytes_unavailable": True}
            assert row["next_action"] == ADMISSION_UNVERIFIED_ACTION
            assert "error" not in row and "detail" not in row
        elif recipes == "mismatch":
            assert row["error"] == row["detail"] == "recipes changed after admission"
    finally:
        admissions.assert_copy_unchanged(shop.root, before, surface)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="planned job evidence uses Linux /proc")
@pytest.mark.parametrize("custody", ["reservation", "live-runner"])
@pytest.mark.parametrize("recipes", ["absent", "match", "mismatch"])
@pytest.mark.parametrize("surface", ["api", "cli"])
def test_unsettled_provider_projection_agrees_with_blocking_inventory(kind_shop, capsys, custody, recipes, surface):
    from tests.integration.test_hierarchy_jobs_followups import (ADMISSION_UNVERIFIED_ACTION,
                                                                unsettled_recovery_obligation)

    shop = kind_shop
    unsettled_recovery_obligation(shop, custody)
    if recipes == "mismatch":
        shop.recipes["recipes"]["ok"]["timeout_seconds"] += 1
        shop.save_recipes()
    trusted = None if recipes == "absent" else shop.recipes_path
    candidate = module()
    code, inventory = candidate.recovery_status(shop.workspace.store, recipes_path=trusted)
    assert code == 3
    if surface == "api":
        status = candidate.job_status(shop.workspace.store, "pilot/job-1", recipes_path=trusted)
    else:
        args = [] if trusted is None else ["--recipes", str(trusted)]
        assert candidate.main(["--store", str(shop.workspace.store), "job", "--job", "pilot/job-1", *args]) == 0
        status = json.loads(capsys.readouterr().out)
    row = next(row for row in inventory["jobs"] if row["job"] == "pilot/job-1")
    assert status["projection"] == row
    expected = {"absent": "admission_unverified", "match": "admitted", "mismatch": "evidence_error"}[recipes]
    assert row["state"] == expected
    blocker = next(blocker for blocker in inventory["blockers"] if blocker.get("job") == row["job"])
    assert blocker["reason"] == expected
    if recipes == "absent":
        assert blocker["next_action"] == row["next_action"] == ADMISSION_UNVERIFIED_ACTION
        assert row["source"]["recipe_bytes_unavailable"] is True
    assert row["runner_alive"] is (custody == "live-runner")
    if custody == "reservation":
        assert row["reservations"][0]["state"] == "granted"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="planned job evidence uses Linux /proc")
def test_provider_missing_request_is_not_a_recipe_unavailable_projection(kind_shop):
    from tests.integration.test_hierarchy_jobs_followups import recovery_admission_case

    shop = kind_shop
    recovery_admission_case(shop, None)
    candidate = module()
    record = candidate.Mailbox(shop.root).messages()["job-1"]
    Path(record["path"]).rename(shop.tmp / "retained-original-request.md")
    code, inventory = candidate.recovery_status(shop.workspace.store, recipes_path=shop.recipes_path)
    assert code == 3
    status = candidate.job_status(shop.workspace.store, "pilot/job-1", recipes_path=shop.recipes_path)
    row = next(row for row in inventory["jobs"] if row["job"] == "pilot/job-1")
    assert status["projection"] == row and row["state"] == "admitted"
    assert row["source"] == {"state": "unavailable", "reason": "original mailbox request is unavailable"}


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="planned job evidence uses Linux /proc")
@pytest.mark.parametrize("surface", ["api", "cli"])
def test_provider_reports_resolved_unbound_provenance_as_unavailable(kind_shop, capsys, surface):
    from tests.integration.test_hierarchy_jobs_followups import jobs, orphaned_staging_case

    shop = kind_shop
    orphaned_staging_case(shop, "after-stage")
    assert jobs.main(shop.argv("resolve", "--job", "pilot/job-1", "--reason", "owner reconciliation",
                               "--process-stopped", census=[], lock_wait=0)[3:]) == 0
    capsys.readouterr()
    candidate = module()
    code, inventory = candidate.recovery_status(shop.workspace.store)
    assert code == 3
    if surface == "api":
        status = candidate.job_status(shop.workspace.store, "pilot/job-1")
    else:
        assert candidate.main(["--store", str(shop.workspace.store), "job", "--job", "pilot/job-1"]) == 0
        status = json.loads(capsys.readouterr().out)
    row = next(row for row in inventory["jobs"] if row["job"] == "pilot/job-1")
    assert status["projection"] == row and row["state"] == "finished"
    assert row["source"] == {"state": "unavailable", "reason": "derivation provenance unverified",
                             "terminal_source_unverified": True}
    assert row["reservations"][0]["state"] == "released"
    blocker = next(blocker for blocker in inventory["blockers"] if blocker.get("job") == row["job"])
    assert blocker["reason"] == "source_unavailable" and blocker["next_action"] == row["next_action"]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="planned job evidence uses Linux /proc")
@pytest.mark.parametrize("route", ["kill", "refusal"])
def test_provider_missing_derivation_publication_stays_unavailable(kind_shop, capsys, route):
    from tests.integration.test_hierarchy_jobs_followups import jobs, missing_derivation_publication_case

    shop = kind_shop
    missing_derivation_publication_case(shop, route)
    if route == "kill":
        assert jobs.main(shop.argv("resolve", "--job", "pilot/job-1", "--reason", "owner reconciliation",
                                   "--process-stopped", census=[], lock_wait=0)[3:]) == 0
        capsys.readouterr()
    candidate = module()
    code, inventory = candidate.recovery_status(shop.workspace.store)
    assert code == 3
    status = candidate.job_status(shop.workspace.store, "pilot/job-1")
    row = next(row for row in inventory["jobs"] if row["job"] == "pilot/job-1")
    assert status["projection"] == row and row["state"] == "finished" and row["receipt"] == "match"
    assert row["source"]["terminal_source_unverified"] is True
    assert next(blocker for blocker in inventory["blockers"] if blocker.get("job") == row["job"])["reason"] == "source_unavailable"


def _admissions_node_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, (ast.arg, ast.keyword)):
        return node.arg
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler)):
        return node.name
    if isinstance(node, ast.alias):
        return node.asname or node.name.rsplit(".", 1)[-1]
    return None


def _admissions_name_violations(source, private_names=()):
    return _admissions_tree_violations(ast.parse(source), private_names)


def _admissions_tree_violations(tree, private_names=()):
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.alias):
            continue  # Import statements own alias positions on every supported Python.
        name = _admissions_node_name(node)
        if name is not None and (name.startswith("_pra_") or name in private_names):
            found.append(node.lineno)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = _admissions_node_name(alias)
                if name is not None and (name.startswith("_pra_") or name in private_names):
                    found.append(node.lineno)
        if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("provider_recovery_admissions"):
            if any(alias.name.startswith("_") for alias in node.names):
                found.append(node.lineno)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if any(part.startswith("_pra_") and len(part) > len("_pra_")
                   for part in re.split(r"[/\\]", node.value)):
                found.append(node.lineno)
    return sorted(set(found))


def _assert_admissions_api(source):
    tree = ast.parse(source)
    table = next(node.value for node in tree.body if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == "PUBLIC_SIGNATURES" for target in node.targets))
    rows = ast.literal_eval(table)
    actual = {}
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name.startswith("_"):
            continue
        args = node.args
        positional = args.posonlyargs + args.args
        defaults = [None] * (len(positional) - len(args.defaults)) + args.defaults
        fields = tuple((arg.arg, "posonly" if i < len(args.posonlyargs) else "pos",
                        ast.unparse(arg.annotation) if arg.annotation else None,
                        ast.unparse(default) if default else None)
                       for i, (arg, default) in enumerate(zip(positional, defaults)))
        assert args.vararg is None and args.kwarg is None and not args.kwonlyargs
        actual[node.name] = (fields, ast.unparse(node.returns) if node.returns else None)
    assert len(rows) == len({row[0] for row in rows})
    assert actual == {name: (parameters, returns) for name, parameters, returns, writes in rows}
    assert all(writes in {"none", "fresh copy only"} for name, parameters, returns, writes in rows)


@pytest.mark.skipif(not admissions.supported(), reason="source inspection requires descriptor support")
def test_admissions_public_signature_table_is_exact():
    _assert_admissions_api(admissions.read_source(ROOT / "tests", ("integration", "provider_recovery_admissions.py")))


@pytest.mark.skipif(not admissions.supported(), reason="source inspection requires descriptor support")
def test_admissions_signature_table_refuses_an_extra_function():
    source = admissions.read_source(ROOT / "tests", ("integration", "provider_recovery_admissions.py"))
    with pytest.raises(AssertionError):
        _assert_admissions_api(source + "\ndef surplus():\n    pass\n")


def test_admissions_private_reference_and_master_path_are_refused():
    assert _admissions_name_violations("from tests.integration.provider_recovery_admissions import _pra_session\n")
    assert _admissions_name_violations("import tests.integration.provider_recovery_admissions as owned\nowned._pra_session\n")
    assert _admissions_name_violations("root / '_pra_master'\n")
    assert not _admissions_name_violations("from tests.integration.provider_recovery_admissions import typed_snapshot\ntyped_snapshot(root)\n")


@pytest.mark.skipif(not admissions.supported(), reason="source inspection requires descriptor support")
def test_admissions_names_are_confined_to_the_helper_module():
    base = Path(__file__).resolve().parents[1]
    admitted = ("integration", "provider_recovery_admissions.py")
    sources = admissions.source_files(base)
    private_names = set()
    for node in ast.walk(ast.parse(sources[admitted])):
        name = _admissions_node_name(node)
        if name is not None and name.startswith("_") and not name.startswith("__"):
            private_names.add(name)
    violations = []
    for parts, source in sources.items():
        if parts != admitted:
            for line in _admissions_name_violations(source, private_names):
                violations.append((admissions.source_name(parts), line))
    assert violations == []


@pytest.mark.parametrize("source", [
    "def test_actor(_pra_session):\n    pass\n",
    "def _pra_session():\n    pass\n",
    "async def _pra_session():\n    pass\n",
    "class _pra_Cache:\n    pass\n",
    "import os as _pra_os\n",
    "try:\n    pass\nexcept Exception as _pra_session:\n    pass\n",
    "invoke(_pra_session=cache)\n",
])
def test_admissions_name_ban_covers_identifier_forms(source):
    assert _admissions_name_violations(source)


def test_admissions_name_ban_uses_all_declared_private_names():
    assert _admissions_name_violations("alias._hidden\n", {"_hidden"})


@pytest.mark.parametrize("source,expected", [
    ("import os as _pra_os\n", [1]),
    ("from os import (\n    path as _pra_path,\n)\n", [1]),
    ("\n\nfrom sys import (\n    path as _pra_path,\n)\n", [3]),
    ("from tests.integration.provider_recovery_admissions import (\n    _pra_session,\n)\n", [1]),
    ("from tests.integration.provider_recovery_admissions import typed_snapshot\n", []),
])
def test_admissions_import_violations_use_statement_positions(source, expected):
    assert _admissions_name_violations(source) == expected


@pytest.mark.parametrize("kind", ["import", "from"])
def test_admissions_import_aliases_without_positions(kind):
    alias = ast.alias(name="os", asname="_hidden")
    if kind == "import":
        statement = ast.Import(names=[alias], lineno=7, col_offset=0)
    else:
        statement = ast.ImportFrom(module="package", names=[alias], level=0, lineno=7, col_offset=0)
    tree = ast.Module(body=[statement], type_ignores=[])
    assert not hasattr(alias, "lineno")
    assert _admissions_tree_violations(tree, {"_hidden"}) == [7]


def test_admissions_unsupported_probe_refuses_before_open(tmp_path, monkeypatch):
    monkeypatch.setattr(admissions, "supported", lambda: False)
    with pytest.raises(AssertionError, match="^admission descriptors unavailable$"):
        admissions.typed_snapshot(tmp_path / "missing")
    with pytest.raises(AssertionError, match="^admission descriptors unavailable$"):
        admissions.read_source(tmp_path / "missing", ("support.py",))
    with pytest.raises(AssertionError, match="^admission descriptors unavailable$"):
        admissions.source_files(tmp_path / "missing")


@pytest.mark.skipif(not admissions.supported(), reason="source refusal requires descriptor support")
@pytest.mark.parametrize("kind", ["fifo", "stream-link", "oversized"])
def test_admissions_source_contract_refuses_unsafe_sources(tmp_path, kind):
    base = tmp_path / "tests"
    integration = base / "integration"
    integration.mkdir(parents=True)
    (integration / "provider_recovery_admissions.py").write_text("pass\n", encoding="utf-8")
    target = base / "support.py"
    if kind == "fifo":
        os.mkfifo(target)
    elif kind == "stream-link":
        symlink_or_skip("/dev/zero", target)
    else:
        with target.open("wb") as output:
            output.truncate(4 * 1024 * 1024 + 1)
    source = '''import resource
import sys
from tests.integration import test_hierarchy_provider_recovery as candidate
resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
candidate.__file__ = sys.argv[1]
try:
    candidate.test_admissions_names_are_confined_to_the_helper_module()
except AssertionError as error:
    assert "tests/support.py" in str(error)
else:
    raise AssertionError("unsafe source was admitted")
'''
    proc = subprocess.run([sys.executable, "-c", source,
                           str(integration / "test_hierarchy_provider_recovery.py")], cwd=ROOT,
                          env=dict(os.environ, PYTHONPATH=str(ROOT)), capture_output=True,
                          text=True, timeout=5)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.skipif(not admissions.supported(), reason="copy cleanup requires Linux descriptors")
@pytest.mark.parametrize("kind", ["over-ceiling", "deep"])
def test_admissions_refused_copy_does_not_block_the_next_surface(tmp_path, kind):
    source = '''import os
import resource
import pytest
from tests.integration import provider_recovery_admissions as layer
pytest_plugins = ("tests.integration.provider_recovery_admissions",)
original_remove = layer._pra_remove
def limited_remove(parent, name):
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, hard))
    try:
        return original_remove(parent, name)
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
@pytest.mark.parametrize("terminal,recipes,surface", [(None, "match", "copy-only")])
def test_leave_refused_copy(planned_admission, terminal, recipes, surface):
    root = planned_admission.root
'''
    if kind == "over-ceiling":
        source += '''\
    layer._pra_NODES = len(layer.typed_snapshot(root)) + 16
    spill = root / "spill"
    spill.mkdir()
    for index in range(layer._pra_NODES + 1):
        (spill / str(index)).touch()
'''
    else:
        source += '''\
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index in range(96):
            os.mkdir("deep", dir_fd=fd)
            child = os.open("deep", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
    finally:
        os.close(fd)
    layer._pra_remove = limited_remove
'''
    source += '''\
    with pytest.raises(AssertionError, match="^admission fixture unreadable$"):
        layer.typed_snapshot(root)
@pytest.mark.parametrize("terminal,recipes,surface", [(None, "match", "copy-only")])
def test_next_surface(planned_admission, terminal, recipes, surface):
    assert not (planned_admission.root / "spill").exists()
    assert not (planned_admission.root / "deep").exists()
'''
    proc = _admissions_actor(tmp_path, source)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "2 passed" in proc.stdout


@pytest.mark.parametrize("terminal,recipes,surface", [(None, "match", "copy-only")])
def test_admissions_surface_can_write_its_copy(planned_admission, terminal, recipes, surface):
    target = planned_admission.root / "copy-only.txt"
    target.write_bytes(b"copy-only change")
    assert target.read_bytes() == b"copy-only change"


@pytest.mark.skipif(not admissions.supported() or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="read-only permission enforcement needs a non-root Linux user")
def test_admissions_master_write_fails_the_surface_by_name(tmp_path):
    # The static contract rejects this actor. Replay it separately to exercise the
    # independent read-only and snapshot boundaries, including a mode bypass.
    source = '''import os
import pytest
pytest_plugins = ("tests.integration.provider_recovery_admissions",)
@pytest.mark.parametrize("terminal,recipes,surface", [(None, "match", "master-write")])
def test_master_attack(planned_admission, terminal, recipes, surface):
    master = planned_admission.root.parent / "_pra_master"
    target = master / "recipes.json"
    with pytest.raises(PermissionError):
        target.write_bytes(b"blocked")
    os.chmod(target, 0o600)
    target.write_bytes(b"tampered")
    os.chmod(target, 0o400)
'''
    assert _admissions_name_violations(source)
    test_file = tmp_path / "test_master_attack.py"
    test_file.write_text(source, encoding="utf-8")
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-n", "0", "--basetemp",
                           str(tmp_path / "child-data"), str(test_file)], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=180)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "test_master_attack" in proc.stdout
    assert "probe master-write mutated cached master" in proc.stdout


def _admissions_actor(tmp_path, source):
    assert _admissions_name_violations(source)
    test_file = tmp_path / "test_cache_actor.py"
    test_file.write_text(source, encoding="utf-8")
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-n", "0", "--basetemp",
                           str(tmp_path / "child-data"), str(test_file)], cwd=ROOT,
                          env=dict(os.environ, PYTHONPATH=str(ROOT)), capture_output=True,
                          text=True, timeout=180)


@pytest.mark.skipif(not admissions.supported(), reason="cache actor requires Linux descriptors")
def test_admissions_builds_only_the_requested_scenario(tmp_path):
    source = '''import pytest
pytest_plugins = ("tests.integration.provider_recovery_admissions",)
@pytest.mark.parametrize("terminal,recipes,surface", [("completed", "match", "api")])
def test_first_use(planned_admission, terminal, recipes, surface):
    cache = planned_admission.root.parent.parent
    masters = sorted(path.name for path in cache.iterdir()
                     if path.is_dir() and (path / "_pra_master").is_dir())
    assert masters == ["finished-match"]
'''
    proc = _admissions_actor(tmp_path, source)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "1 passed" in proc.stdout


@pytest.mark.skipif(not admissions.supported() or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="cross-master actor needs a non-root Linux user")
@pytest.mark.parametrize("attack", ["rewrite", "remove"])
def test_admissions_session_teardown_names_a_changed_other_master(tmp_path, attack):
    source = '''import os
import shutil
import pytest
pytest_plugins = ("tests.integration.provider_recovery_admissions",)
@pytest.mark.parametrize("terminal,recipes,surface", [("completed", "match", "api")])
def test_original(planned_admission, terminal, recipes, surface):
    pass
@pytest.mark.parametrize("terminal,recipes,surface", [("failed", "match", "master-write")])
def test_other(planned_admission, terminal, recipes, surface):
    target = planned_admission.root.parent.parent / "finished-match" / "_pra_master" / "recipes.json"
'''
    if attack == "rewrite":
        source += '''\
    with pytest.raises(PermissionError):
        target.write_bytes(b"blocked")
    os.chmod(target, 0o600)
    target.write_bytes(b"tampered")
    os.chmod(target, 0o400)
'''
    else:
        source += '''\
    victim = target.parent.parent
    for path in victim.rglob("*"):
        if not path.is_symlink():
            os.chmod(path, 0o700 if path.is_dir() else 0o600)
    shutil.rmtree(victim)
'''
    proc = _admissions_actor(tmp_path, source)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "cached master finished-match changed at session teardown" in proc.stdout
