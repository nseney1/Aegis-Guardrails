"""Manager audit behavior never establishes repository credit or native execution."""
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from aegis_core.manager import ManagerService
from aegis_core.manager_policy import ManagerError
from tests.helpers_manager import active, approve, git, manager_root, prepare


@pytest.fixture
def env(manager_root):
    return prepare(manager_root)


@pytest.mark.parametrize("operation", ["report", "status"])
@pytest.mark.parametrize("observation", ["clean", "dirty", "unavailable", "git_error", "missing", "mismatched"])
def test_repeated_evidence_observes_worktree_once_per_request(env, monkeypatch, operation, observation):
    import subprocess
    from types import SimpleNamespace
    from aegis_core import manager

    service = active(env)
    scan = service.scan("handoff", env["context"])
    rule = scan["rules"][0]
    tree = git(env["member"], "rev-parse", "HEAD^{tree}")
    evidence = [{"member_id": "aegis", "worktree_id": "main", "source_tree": tree if index % 2 else "0" * 40,
                 "check": "pytest", "rule_id": rule["id"],
                 "rule_revision": rule["revision"] if index % 3 else "0" * 64,
                 "reference": "log:" + str(index)} for index in range(20)]
    if operation == "status":
        service.report(scan["decision_ref"], [rule["id"]], "success", evidence, "seed")
    if observation == "dirty":
        (env["member"] / "source.txt").write_text("changed\n")
    elif observation == "missing":
        env["member"].rename(env["member"].with_name("missing-member"))
    elif observation == "mismatched":
        (env["member"] / ".git").rename(env["member"] / ".git-saved")
        git(env["member"], "init", "-q")

    calls = []
    real_run = manager.gitsafe.run
    def observed_run(args, cwd, **kwargs):
        if str(cwd) == str(env["member"]):
            calls.append(tuple(args))
            if observation == "unavailable" and args == ["rev-parse", "HEAD^{tree}"]:
                return subprocess.CompletedProcess(args, 128, b"", b"unavailable")
            if observation == "git_error" and args == ["rev-parse", "HEAD^{tree}"]:
                raise manager.gitsafe.GitError("test Git timeout")
        return real_run(args, cwd, **kwargs)
    # Replace this module's reference, leaving shared Git/OS helpers untouched.
    monkeypatch.setattr(manager, "gitsafe", SimpleNamespace(**{**vars(manager.gitsafe), "run": observed_run}))

    for request in range(2):
        calls.clear()
        result = (service.status() if operation == "status" else
                  service.report(scan["decision_ref"], [rule["id"]], "success", evidence, "once-" + str(request)))
        expected = (["stale", "source_match"] * 10 if observation == "clean" else
                    ["unavailable" if observation == "git_error" else observation] * 20)
        assert [entry["source_status"] for entry in result["evidence"]] == expected
        assert [entry["reference"] for entry in result["evidence"]] == [entry["reference"] for entry in evidence]
        assert [entry["rule_status"] for entry in result["evidence"]] == [
            "match" if index % 3 else "unavailable" for index in range(20)]
        assert all(entry["check_execution"] == "unverified"
                   and entry["reference_status"] == "not_retrieved" for entry in result["evidence"])
        assert calls.count(("rev-parse", "--absolute-git-dir")) == (0 if observation == "missing" else 1)
        assert calls.count(("rev-parse", "HEAD^{tree}")) == (1 if observation in {"clean", "dirty", "unavailable", "git_error"} else 0)
        assert sum("diff-index" in args for args in calls) == (1 if observation in {"clean", "dirty", "unavailable"} else 0)
        if operation == "status":
            expected_identity = "available" if observation in {"clean", "dirty", "unavailable", "git_error"} else observation
            assert result["membership"][0]["state"] == expected_identity


def test_published_request_vocabulary_matches_manager_wire_contract():
    from aegis_core import manager_policy as policy
    from aegis_mcp.manager import TOOL_DEFINITIONS

    schemas = {tool["name"]: tool["inputSchema"]["properties"] for tool in TOOL_DEFINITIONS}
    scan, report = schemas["aegis_scan"], schemas["aegis_report_outcome"]
    assert set(scan["action"]["enum"]) == set(policy.ACTIONS)
    assert set(report["outcome"]["enum"]) == set(policy.OUTCOMES)
    assert {key: value["maxLength"] for key, value in scan["context"]["properties"].items()} == policy.CONTEXT_LIMITS
    assert set(scan["context"]["required"]) == policy.REQUIRED_CONTEXT_FIELDS
    evidence = report["evidence"]
    assert {key: value["maxLength"] for key, value in evidence["items"]["properties"].items()} == policy.EVIDENCE_LIMITS
    assert set(evidence["items"]["required"]) == set(policy.EVIDENCE_LIMITS)
    assert evidence["maxItems"] == policy.MAX_EVIDENCE
    assert report["rules_used"]["maxItems"] == policy.MAX_RULES
    assert report["rules_used"]["items"]["maxLength"] == policy.MAX_RULE_ID_LENGTH
    assert report["idempotency_key"]["maxLength"] == policy.MAX_IDEMPOTENCY_KEY_LENGTH
    assert report["decision_ref"]["minLength"] == report["decision_ref"]["maxLength"] == policy.DECISION_REF_LENGTH


def test_status_observations_keep_different_approved_bindings_separate(env):
    service = active(env)
    scan = service.scan("handoff", env["context"])
    rule = scan["rules"][0]
    evidence = {"member_id": "aegis", "worktree_id": "main",
                "source_tree": git(env["member"], "rev-parse", "HEAD^{tree}"),
                "check": "pytest", "rule_id": rule["id"], "rule_revision": rule["revision"],
                "reference": "log:previous-binding"}
    service.report(scan["decision_ref"], [rule["id"]], "success", [evidence], "previous")
    (env["member"] / ".git").rename(env["member"].parent / "previous-git")
    git(env["member"], "init", "-q")
    git(env["member"], "add", "source.txt")
    git(env["member"], "commit", "-qm", "replacement")
    previous = service.status()["active_revision"]
    candidate = service.candidate(env["revision"])
    service.activate(env["revision"], previous, approve(env, candidate))
    scan = service.scan("handoff", env["context"])
    service.report(scan["decision_ref"], [rule["id"]], "success",
                   [{**evidence, "reference": "log:current-binding"}], "current")
    status = service.status()
    assert [entry["source_status"] for entry in status["evidence"]] == ["mismatched", "source_match"]
    assert status["membership"][0]["state"] == "available"


def test_unapproved_policy_stays_draft_and_scan_refuses(env):
    service = ManagerService(env["config"])
    assert service.status()["policy_approval"] == "draft"
    assert service.status()["native_enforcement_ready"] is False
    with pytest.raises(ManagerError, match="^policy_not_active$"):
        service.scan("handoff", env["context"])
    assert service.candidate(env["revision"])["status"] == "awaiting_owner_approval"
    assert service.status()["policy_approval"] == "draft"


def test_signature_bound_activation_and_claim_only_outcome(env):
    service = active(env)
    scan = service.scan("handoff", env["context"])
    assert scan["rules"][0]["id"] == "manager-handoff"
    receipt = service.report(scan["decision_ref"], ["manager-handoff"], "success", [], "once", True)
    assert receipt["fitness_credit"] == 0
    assert receipt["acknowledgement"] == "recorded"
    assert receipt["execution"] == "unverified"
    assert receipt["human_approval"] == "not_established"
    assert receipt["verified_completion"] is False
    assert receipt["claimed_tests_passed"] is True
    assert not (env["member"] / ".aegis").exists()
    assert not (env["control"] / ".aegis").exists()


def test_reconnect_replays_once_and_conflicting_key_refuses(env):
    service = active(env)
    scan = service.scan("handoff", env["context"])
    args = (scan["decision_ref"], ["manager-handoff"], "success", [], "once")
    receipt = service.report(*args)
    restarted = ManagerService(env["config"], provenance={"transport": "mcp", "session_id": "new"})
    assert restarted.report(*args) == receipt
    with pytest.raises(ManagerError, match="^idempotency_conflict$"):
        restarted.report(scan["decision_ref"], ["manager-handoff"], "failure", [], "once")
    assert restarted.status()["outcomes"] == 1


def test_signed_statement_cannot_be_replayed_against_stale_activation(env):
    service = ManagerService(env["config"])
    candidate = service.candidate(env["revision"])
    approval = approve(env, candidate)
    service.activate(env["revision"], None, approval)
    with pytest.raises(ManagerError, match="^stale_activation$"):
        service.activate(env["revision"], None, approval)


def test_pending_decision_blocks_revision_until_outcome_recorded(env):
    service = active(env)
    scan = service.scan("handoff", env["context"])
    previous = service.status()["active_revision"]
    candidate = service.candidate(env["revision"])
    with pytest.raises(ManagerError, match="^pending_decisions$"):
        service.activate(env["revision"], previous, approve(env, candidate))
    service.report(scan["decision_ref"], ["manager-handoff"], "partial", [], "record-unverified")
    candidate = service.candidate(env["revision"])
    assert service.activate(env["revision"], previous, approve(env, candidate))["policy_approval"] == "approved"


@pytest.mark.parametrize("context", [
    {"member_id": "stormheir", "worktree_id": "main"},
    {"member_id": "aegis", "worktree_id": "other"},
])
def test_unapproved_membership_refuses(env, context):
    service = active(env)
    with pytest.raises(ManagerError, match="^unauthorized_membership$"):
        service.scan("handoff", context)


@pytest.mark.parametrize("field", ["scope", "session", "approval", "files", "workspace", "identity"])
def test_context_cannot_inject_scope_or_commands(env, field):
    service = active(env)
    with pytest.raises(ManagerError, match="^invalid_context$"):
        service.scan("handoff", {**env["context"], field: "forged"})


def test_decision_substitution_and_unserved_rule_refuse(env):
    service = active(env)
    scan = service.scan("handoff", env["context"])
    with pytest.raises(ManagerError, match="^unknown_decision$"):
        service.report("d" * 64, ["manager-handoff"], "success", [], "forged")
    with pytest.raises(ManagerError, match="^unserved_rules$"):
        service.report(scan["decision_ref"], ["repository-rule"], "success", [], "forged")
    assert service.status()["outcomes"] == 0


def test_signature_or_signer_substitution_cannot_activate(env):
    service = ManagerService(env["config"])
    approval = approve(env, service.candidate(env["revision"]))
    approval["statement"]["membership_digest"] = "0" * 64
    with pytest.raises(ManagerError, match="^approval_mismatch$"):
        service.activate(env["revision"], None, approval)
    approval = approve(env, service.candidate(env["revision"]))
    approval["commit"] = "0" * 40
    with pytest.raises(ManagerError, match="^invalid_owner_signature$"):
        service.activate(env["revision"], None, approval)
    env["signers"].write_text("replacement")
    with pytest.raises(ManagerError, match="^trust_root_changed$"):
        ManagerService(env["config"])


def test_evidence_revalidated_and_copied_log_does_not_prove_check(env):
    service = active(env)
    scan = service.scan("handoff", env["context"])
    rule = scan["rules"][0]
    evidence = {"member_id": "aegis", "worktree_id": "main",
                "source_tree": git(env["member"], "rev-parse", "HEAD^{tree}"),
                "check": "pytest", "rule_id": rule["id"], "rule_revision": rule["revision"],
                "reference": "file:///not-read/copied-log"}
    receipt = service.report(scan["decision_ref"], [rule["id"]], "success", [evidence], "copied", True)
    assert receipt["evidence"][0]["source_status"] == "source_match"
    assert receipt["evidence"][0]["check_execution"] == "unverified"
    (env["member"] / "source.txt").write_text("changed\n")
    git(env["member"], "add", "source.txt")
    git(env["member"], "commit", "-qm", "change")
    assert service.status()["evidence"][0]["source_status"] == "stale"
    assert service.status()["native_enforcement_ready"] is False


def test_concurrent_reports_are_exactly_once(env):
    service = active(env)
    scan = service.scan("handoff", env["context"])
    def report(_):
        return ManagerService(env["config"]).report(scan["decision_ref"], ["manager-handoff"],
                                                   "success", [], "concurrent")
    with ThreadPoolExecutor(max_workers=4) as pool:
        receipts = list(pool.map(report, range(8)))
    assert all(row == receipts[0] for row in receipts)
    assert service.status()["outcomes"] == 1


def test_config_substitution_or_store_in_member_refuses(env):
    config = json.loads(env["config"].read_text())
    config["workspace_id"] = "another"
    env["config"].write_text(json.dumps(config))
    with pytest.raises(ManagerError, match="^config_mismatch$"):
        ManagerService(env["config"]).status()


def test_restart_reverifies_cached_policy_and_owner_signature(env):
    import copy
    from aegis_core.manager_policy import digest
    from aegis_core.manager_store import ManagerStore
    service = active(env)
    forged = copy.deepcopy(ManagerStore(env["store"]).read()[-1])
    for key in ("seq", "prev", "hash"):
        forged.pop(key)
    rule = forged["candidate"]["policy"]["rules"][0]
    rule["text"] = "Forged unapproved manager instruction."
    rule["revision"] = digest({key: value for key, value in rule.items() if key != "revision"})
    forged["activation_ref"] = digest({"forged": True})
    ManagerStore(env["store"]).append(forged)
    with pytest.raises(ManagerError, match="^activation_integrity$"):
        ManagerService(env["config"]).list_rules()
    with pytest.raises(ManagerError, match="^activation_integrity$"):
        service.status()


def test_runtime_git_directory_substitution_refuses_management_scan(env):
    service = active(env)
    foreign = env["member"].parent / "foreign"
    foreign.mkdir()
    git(foreign, "init", "-q")
    (foreign / "source.txt").write_text("foreign\n")
    git(foreign, "add", "source.txt")
    git(foreign, "commit", "-qm", "foreign")
    original = env["member"] / ".git"
    original.rename(env["member"] / ".git-saved")
    original.symlink_to(foreign / ".git", target_is_directory=True)
    with pytest.raises(ManagerError, match="^membership_unavailable$"):
        service.scan("handoff", env["context"])
    assert service.status()["membership"][0]["state"] == "mismatched"


def test_identical_draft_initialization_recovers_missing_audit_event(env):
    from aegis_core.manager import initialize
    audit = env["store"] / "audit.jsonl"
    audit.write_bytes(b"")
    result = initialize(env["config"], workspace_id="test-manager", control_root=env["control"],
                        store_root=env["store"], trusted_signers=env["signers"])
    assert result["policy_approval"] == "draft"
    assert ManagerService(env["config"]).status()["policy_approval"] == "draft"


def test_missing_member_preserves_approval_history_and_explicit_evidence_state(env):
    service = active(env)
    env["member"].rename(env["member"].with_name("unavailable-member"))
    status = service.status()
    assert status["policy_approval"] == "approved"
    assert status["membership"][0]["state"] == "missing"
    with pytest.raises(ManagerError, match="^membership_unavailable$"):
        service.scan("handoff", env["context"])


def test_outcome_retry_cannot_promote_forged_audit_acknowledgement(env):
    from aegis_core.manager_store import ManagerStore
    service = active(env)
    scan = service.scan("handoff", env["context"])
    service.report(scan["decision_ref"], ["manager-handoff"], "success", [], "honest")
    forged = ManagerStore(env["store"]).read()[-1]
    for key in ("seq", "prev", "hash"):
        forged.pop(key)
    forged["request"]["idempotency_key"] = "forged"
    forged["result"].update(fitness_credit=99, execution="verified", human_approval="approved", verified_completion=True)
    ManagerStore(env["store"]).append(forged)
    with pytest.raises(ManagerError, match="^audit_corrupt$"):
        service.report(scan["decision_ref"], ["manager-handoff"], "success", [], "forged")


def test_forged_served_rules_cannot_bypass_manager_selection(env):
    from aegis_core.manager_store import ManagerStore
    service = active(env)
    scan = service.scan("handoff", env["context"])
    forged = ManagerStore(env["store"]).read()[-1]
    for key in ("seq", "prev", "hash"):
        forged.pop(key)
    forged["decision_ref"] = "f" * 64
    forged["result"]["decision_ref"] = "f" * 64
    forged["result"]["rules"][0]["id"] = "repository-rule"
    ManagerStore(env["store"]).append(forged)
    with pytest.raises(ManagerError, match="^audit_corrupt$"):
        service.report("f" * 64, ["repository-rule"], "success", [], "forged-rule")


def test_missing_config_with_matching_draft_genesis_is_restored(env):
    from aegis_core.manager import initialize
    original = env["config"].read_bytes()
    env["config"].unlink()
    result = initialize(env["config"], workspace_id="test-manager", control_root=env["control"],
                        store_root=env["store"], trusted_signers=env["signers"])
    assert result["status"] == "prepared"
    assert env["config"].read_bytes() == original
    assert ManagerService(env["config"]).status()["policy_approval"] == "draft"


def test_config_cannot_be_created_beneath_nonexistent_repository_subdirectory(env):
    from aegis_core.manager import initialize
    path = env["control"] / "new" / "manager.json"
    with pytest.raises(ManagerError, match="^config_in_repository$"):
        initialize(path, workspace_id="test-manager", control_root=env["control"],
                   store_root=env["store"], trusted_signers=env["signers"])
    assert not path.exists()


def test_runtime_physical_git_directory_replacement_requires_new_approval(env):
    service = active(env)
    original = env["member"] / ".git"
    original.rename(env["member"] / ".git-saved")
    git(env["member"], "init", "-q")
    with pytest.raises(ManagerError, match="^membership_unavailable$"):
        service.scan("handoff", env["context"])
    assert service.status()["membership"][0]["state"] == "mismatched"


def test_evidence_git_failure_is_unavailable_and_never_proves_check(env, monkeypatch):
    from aegis_core import gitsafe
    import subprocess
    service = active(env)
    scan = service.scan("handoff", env["context"])
    rule = scan["rules"][0]
    evidence = {"member_id": "aegis", "worktree_id": "main",
                "source_tree": git(env["member"], "rev-parse", "HEAD^{tree}"),
                "check": "pytest", "rule_id": rule["id"], "rule_revision": rule["revision"],
                "reference": "log:unavailable"}
    real = gitsafe.run
    def unavailable(args, cwd, *positional, **keywords):
        if "diff-index" in args:
            return subprocess.CompletedProcess(args, 128, b"", b"unavailable")
        return real(args, cwd, *positional, **keywords)
    monkeypatch.setattr(gitsafe, "run", unavailable)
    receipt = service.report(scan["decision_ref"], [rule["id"]], "success", [evidence], "unavailable")
    assert receipt["evidence"][0]["source_status"] == "unavailable"
    assert receipt["evidence"][0]["check_execution"] == "unverified"


@pytest.mark.parametrize("mutation", ["kind", "rules", "key", "candidate"])
def test_malformed_audit_json_fails_with_explicit_corruption(env, mutation):
    from aegis_core.manager_store import ManagerStore
    service = active(env)
    scan = service.scan("handoff", env["context"])
    service.report(scan["decision_ref"], ["manager-handoff"], "success", [], "honest")
    rows = ManagerStore(env["store"]).read()
    forged = rows[-1] if mutation != "candidate" else rows[1]
    for key in ("seq", "prev", "hash"):
        forged.pop(key)
    if mutation == "kind":
        forged["kind"] = []
    elif mutation == "rules":
        forged["request"]["rules_used"] = [{}]
    elif mutation == "key":
        forged["request"]["idempotency_key"] = {}
    else:
        forged["candidate"]["policy"] = []
    ManagerStore(env["store"]).append(forged)
    with pytest.raises(ManagerError, match="^audit_corrupt$"):
        service.status()


def test_prepared_registration_rejects_planted_working_directory_package(env, tmp_path):
    import os
    import subprocess
    from aegis_core.manager import initialize
    prepared = initialize(env["config"], workspace_id="test-manager", control_root=env["control"],
                          store_root=env["store"], trusted_signers=env["signers"])
    registration = prepared["registration"]["aegis-manager"]
    hostile = tmp_path / "hostile"
    package = hostile / "aegis_mcp"
    package.mkdir(parents=True)
    marker = hostile / "planted-ran"
    (package / "__init__.py").write_text("")
    (package / "__main__.py").write_text("from pathlib import Path\nPath('planted-ran').write_text('unsafe')\n")
    process = subprocess.run([registration["command"], *registration["args"]],
                             cwd=hostile, env={**os.environ, **registration["env"]},
                             input='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n',
                             capture_output=True, text=True, timeout=10)
    assert not marker.exists(), "manager registration executed a cwd-planted package"
    if process.returncode:
        # A source-only test venv may have no installed artifact; isolated startup must refuse.
        assert "No module named aegis_mcp" in process.stderr
    else:
        assert json.loads(process.stdout)["result"]["serverInfo"]["name"] == "aegis-manager-mcp"


def test_evidence_review_never_executes_repository_filter_commands(env):
    service = active(env)
    scan = service.scan("handoff", env["context"])
    rule = scan["rules"][0]
    evidence = {"member_id": "aegis", "worktree_id": "main",
                "source_tree": git(env["member"], "rev-parse", "HEAD^{tree}"),
                "check": "pytest", "rule_id": rule["id"], "rule_revision": rule["revision"],
                "reference": "log:hostile-filter"}
    marker = env["member"].parent / "filter-ran"
    git(env["member"], "config", "filter.evil.clean", "touch '" + str(marker) + "'; cat")
    (env["member"] / ".gitattributes").write_text("source.txt filter=evil\n")
    (env["member"] / "source.txt").write_text("changed source\n")
    receipt = service.report(scan["decision_ref"], [rule["id"]], "success", [evidence], "filter")
    assert not marker.exists(), "evidence review executed repository-selected filter"
    assert receipt["evidence"][0]["source_status"] == "dirty"


def test_deleted_source_remains_dirty_evidence(env):
    service = active(env)
    scan = service.scan("handoff", env["context"])
    rule = scan["rules"][0]
    evidence = {"member_id": "aegis", "worktree_id": "main",
                "source_tree": git(env["member"], "rev-parse", "HEAD^{tree}"),
                "check": "pytest", "rule_id": rule["id"], "rule_revision": rule["revision"],
                "reference": "log:deleted-source"}
    (env["member"] / "source.txt").unlink()
    receipt = service.report(scan["decision_ref"], [rule["id"]], "partial", [evidence], "deleted")
    assert receipt["evidence"][0]["source_status"] == "dirty"
