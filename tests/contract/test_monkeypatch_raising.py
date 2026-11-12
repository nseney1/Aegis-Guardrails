"""Census direct, statically resolvable patch calls and ratchet syntactic bans.

The static contract checks literal direct patch syntax, reviewed registrations,
missing-target flags and exact shared-module counts. It separately bans nested
patch-framework imports, global/nonlocal declarations, non-annotation MonkeyPatch references
and namespace capabilities. Namespace access admits only the read-only seam-copy
shape or a registration of the complete operation; generated templates at the
declared existing code boundaries are pinned by their complete outer construction.

Patch objects or modules acquired dynamically at runtime are OUT of static scope:
importlib.import_module, __import__, eval/exec, factories, and patchers passed
through containers or return values. RF-11c (runtime guard) owns that coverage;
this census does not assert completeness for those forms.
"""
import ast
from functools import lru_cache
import hashlib
from pathlib import Path

import pytest

from tests.contract.test_process_ratchets import ScopedNames


REPO = Path(__file__).resolve().parents[2]
PROCESS_MODULES = {"os", "os.path", "subprocess", "sys", "time", "builtins", "shutil"}
PLATFORM_ABSENT = {
    "ctypes.WinDLL": "ctypes exposes WinDLL only on Windows.",
    "subprocess.CREATE_NEW_PROCESS_GROUP": "Windows process creation flag is absent on POSIX.",
    "os.geteuid": "Effective user identity is absent on Windows.",
}
# Builtin read through module globals: create a consumer-local name, leaving builtins alone.
BUILTIN_GLOBALS = {
    ("tests/unit/cli/test_prepare_commit_msg.py", "aegis_cli.hooks.commitmsg.open"):
        "commitmsg reads builtin open through module globals, without a local open binding.",
    ("tests/unit/cli/test_approve_cli.py", "aegis_cli.approve.input"):
        "approve calls builtin input without binding it in its module globals.",
    ("tests/integration/test_hierarchy_root.py", "tool.open"):
        "The dynamically loaded hierarchy_root module reads builtin open through its globals.",
}
# Temporary exceptions pin the file, lexical scope, call syntax and occurrence.
LEASED_SITES = {}

# Exact computed calls: (file, scope, kind, syntax, occurrence) -> (shared, reason).
# A newly permissive flag changes the key and requires its own explicit review.
UNRESOLVED_TARGETS = {
    ('tests/contract/test_mailbox_index_rollout.py', 'test_tip_prefilters_once_with_clean_git_environment', 'patch', "monkeypatch.setitem(globals(), '_tracked_names', observed_tracked_names)", 0):
        (False, 'The contract replaces its own _tracked_names helper to count Git prefilter queries while the observed subprocess and AST boundaries check clean Git environment and single-pass parsing.'),
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_limits_refuse_before_parsing', 'patch', 'monkeypatch.setattr(module, limit, 1)', 0):
        (False, 'doctor() imports tools.hierarchy_mailbox_doctor; limit selects MAX_FILES, MAX_TOTAL_BYTES or MAX_FILE_BYTES, while its hm reference gets a local strict_json failure seam to prove refusal before parsing.'),
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_cap_uses_all_message_files', 'patch', "monkeypatch.setattr(doctor(), 'MESSAGE_CAP', 1)", 0):
        (False, 'doctor() imports tools.hierarchy_mailbox_doctor; lowering its MESSAGE_CAP verifies that the diagnostic counts all message files.'),
    ('tests/unit/cli/test_cli_msg.py', 'test_mc2b_overflow_and_invalid_earlier_family_match_mcp', 'patch', 'monkeypatch.setattr(server, name, value)', 0):
        (False, 'server is aegis_mcp.server; name/value iterate its fresh_state() fields before _canonical_workspace is set to the temporary Workspace, enabling CLI/MCP refusal-parity checks.'),
    ('tests/contract/test_mailbox_index_rollout.py', 'test_admitted_importer_routes_through_ast', 'patch', "monkeypatch.setitem(globals(), 'ADMITTED_IMPORTERS', frozenset({'tools/probe.py'}))", 0):
        (False, "Exact computed consumer-boundary call: globals() is this contract module's owned dictionary; changes the importer fixture only."),
    ('tests/contract/test_mailbox_index_rollout.py', 'test_non_python_mentions_cannot_be_admitted', 'patch', "monkeypatch.setitem(globals(), 'ADMITTED_IMPORTERS', admitted)", 0):
        (False, "Exact computed consumer-boundary call: globals() is this contract module's owned dictionary; changes the importer fixture only."),
    ('tests/contract/test_mailbox_mcp_contract.py', 'test_changed_tool_still_fails_with_its_name', 'patch', "monkeypatch.setitem(globals(), 'SNAPSHOT', path)", 0):
        (False, "Exact computed consumer-boundary call: globals() is this contract module's owned dictionary; changes the snapshot fixture only."),
    ('tests/integration/test_hierarchy_container.py', 'test_matrix_surfaces_do_not_spawn', 'patch', "monkeypatch.setattr(sys.modules[__name__], 'subprocess', SimpleNamespace(**{**vars(subprocess), 'run': unexpected_child}))", 0):
        (False, 'present at tip 4959830f before RF-11b landed; added by 5ae2b29044cf; sys.modules[__name__] is this test module; replaces its subprocess reference only.'),
    ('tests/integration/test_hierarchy_fixture_broker.py', 'missing_host_capability', 'patch', 'monkeypatch.setattr(candidate, name, SimpleNamespace(**values))', 0):
        (False, "Replaces the consumer candidate's os/socket module reference with a capability namespace."),
    ('tests/integration/test_hierarchy_host_authority.py', 'count_external_readback', 'patch', 'patch.setattr(owner, name, observed)', 0):
        (True, 'Loop includes shared os alongside Path and socket.socket; count the possible shared-module patch.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_operations_never_write_root_or_parent', 'patch', 'operation.setattr(owner, name, guarded)', 0):
        (True, 'Loop includes shared os alongside Path; count the shared-module operation.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_platform_guard_uses_capability_probe', 'patch', "monkeypatch.setattr(index_module(), '_checked_reads_supported', lambda: False)", 0):
        (False, 'index_module() returns the product mailbox-index module, not a shared standard-library module.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r19_rejected_new_paths_do_not_enter_hash_history', 'patch', "monkeypatch.setattr(index_module(), '_checked_reads_supported', lambda: False)", 0):
        (False, 'index_module() returns the product mailbox-index module for its portable capability control.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_coord2_clock_driver_does_not_write_importable_cache', 'patch', "monkeypatch.setattr(sys.modules[__name__], 'HELPER', source / 'hierarchy_mailbox.py')", 0):
        (False, "sys.modules[__name__] selects this test module's helper path, not a shared module."),
    ('tests/unit/cli/test_approve_cli.py', 'test_review_identifies_resolved_base_and_sanitizes_subject', 'patch', "monkeypatch.setattr(human_gate, 'verify_test_exemption' if exempt else 'verify_approval', verify)", 0):
        (False, "Conditional field selects the product's existing approval or exemption verifier."),
    ('tests/unit/cli/test_approve_cli.py', 'test_signing_review_precedes_confirmation', 'patch', "monkeypatch.setattr(human_gate, 'verify_test_exemption' if exempt else 'verify_approval', verify)", 0):
        (False, "Conditional field selects the product's existing approval or exemption verifier."),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_a_pin_that_disagrees_with_the_target_holds_before_the_command_runs', 'patch', "monkeypatch.setattr(type(get_default_registry().get(command)), 'execute', lambda self, args: ran.append(args) or 0)", 0):
        (False, 'type(registry.get(...)) selects a CLI command class for pin refusal.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_a_pin_that_is_not_a_workspace_is_an_error', 'patch', "monkeypatch.setattr(type(get_default_registry().get('status')), 'execute', lambda self, args: ran.append(args) or 0)", 0):
        (False, 'type(registry.get(...)) selects the status command class.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_a_pin_to_another_repository_holds_instead_of_acting_on_it', 'patch', "monkeypatch.setattr(type(get_default_registry().get(argv[0])), 'execute', lambda self, args: ran.append(args) or 0)", 0):
        (False, 'type(registry.get(...)) selects a CLI command class, not a shared module.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_migrate_and_uninstall_refuse_home', 'patch', "monkeypatch.setattr(type(get_default_registry().get(argv[0])), 'execute', lambda self, args: ran.append(args) or 0)", 0):
        (False, 'type(registry.get(...)) selects a CLI command class for workspace refusal.'),
    ('tests/unit/cli/test_cli_msg.py', 'test_invalid_read_options_have_identical_frontend_refusals_before_io', 'patch', 'monkeypatch.setattr(server, name, value)', 0):
        (False, 'Iterates fresh_state fields on the product server module; strict field existence is preserved.'),
    ('tests/unit/cli/test_doctor_ast_drivers.py', 'test_windows_doctor_uses_the_runners_driver_decoding', 'patch', "monkeypatch.setattr(module, 'os', SimpleNamespace(**{**vars(os), 'name': 'nt'}))", 0):
        (False, 'Exact computed consumer-boundary call: Owner module has lexical candidates aegis_cli.doctor, aegis_core.argv, aegis_core.ast.runner; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_modules.py', 'test_each_patched_seam_has_one_owner_and_is_never_imported_by_value', 'patch', 'monkeypatch.setattr(doctor, OLD_NAMES.get(seam, seam), None)', 0):
        (False, 'Selects a doctor product seam and intentionally asserts that its obsolete name raises AttributeError.'),
    ('tests/unit/core/test_ast_batch_m1.py', 'test_windows_close_retains_tree_ownership_after_driver_root_exits', 'patch', 'monkeypatch.setitem(sys.modules, module.__name__, module)', 0):
        (True, 'Installs the modeled kernel dependency in sys.modules for the Windows process-tree cleanup control; counts the shared module-map mutation.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_native_startup_failure_never_executes_driver_code', 'patch', "monkeypatch.setattr(kernel, failure, lambda *args: 4294967295 if failure == 'ResumeThread' else 0)", 0):
        (False, 'Selects a failure method on the owned modeled kernel DLL fixture.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_native_startup_failure_never_executes_driver_code', 'patch', 'monkeypatch.setattr(kernel, name, tracked_open)', 0):
        (False, 'Wraps handle methods on the owned modeled kernel DLL fixture.'),
    ('tests/unit/core/test_credit.py', '_settle_keyed_index', 'patch', "monkeypatch.setattr(module, 'os', SimpleNamespace(**dict(vars(module.os), stat=lambda *a, **kw: stamps(os.stat(*a, **kw)), lstat=lambda *a, **kw: stamps(os.lstat(*a, **kw)), fstat=lambda fd: stamps(os.fstat(fd)))))", 0):
        (False, 'Exact computed consumer-boundary call: Owner module has lexical candidates aegis_core.credit_memo, aegis_core.storage, aegis_core.telemetry_engine.ledger; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_credit.py', 'test_credit_memo_process_clock_cannot_certify_erased_exposure', 'patch', "monkeypatch.setattr(module, 'os', io)", 0):
        (False, 'Exact computed consumer-boundary call: Owner module has lexical candidates aegis_core.credit_memo, aegis_core.storage, aegis_core.telemetry_engine.ledger; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_credit.py', 'test_multirow_reset_during_fill_cannot_certify_removed_rule', 'patch', "patch.setattr(credit if phase != 'append' else ledger, 'read_rows_with_report' if phase != 'append' else 'append_rows', read if phase != 'append' else append)", 0):
        (False, 'Conditional owner is the credit or ledger product module; selected read/append hook stays strict.'),
    ('tests/unit/core/test_go_build_cache.py', 'test_child_cleanup_handles_only_a_process_that_already_exited', 'patch', "monkeypatch.setattr(sys.modules[__name__], '_process_running', lambda pid: True)", 0):
        (False, "sys.modules[__name__] selects this test module's process-probe helper."),
    ('tests/unit/core/test_language_tests.py', 'test_deadline_expiring_during_dependency_setup_never_starts_the_command', 'patch', 'monkeypatch.setattr(Path, operation, slow_link)', 0):
        (False, 'Selects a Path class method at the filesystem boundary; classes are outside this module census.'),
    ('tests/unit/core/test_rule_integrity.py', '_ledger_spies', 'patch', 'monkeypatch.setattr(module, name, spy)', 0):
        (False, 'Loop owners are storage, credit and ledger product modules; fields are strict ledger spies.'),
    ('tests/unit/core/test_scan_ledger_reads.py', 'test_an_mcp_scan_reads_the_ledger_at_most_twice_and_once_when_its_exposures_are_kept', 'patch', "monkeypatch.setattr(module, 'os', SimpleNamespace(**dict(vars(module.os), stat=lambda *a, **kw: settled_generation(os.stat(*a, **kw)), lstat=lambda *a, **kw: settled_generation(os.lstat(*a, **kw)), fstat=lambda fd: settled_generation(os.fstat(fd)))))", 0):
        (False, 'Exact computed consumer-boundary call: Owner module has lexical candidates aegis_core.credit_memo, aegis_core.storage, aegis_core.telemetry_engine.ledger; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_scan_spawn_budget.py', 'test_an_mcp_scan_counts_index_reads_and_memo_validation', 'patch', "monkeypatch.setattr(module, 'os', io)", 0):
        (False, 'Exact computed consumer-boundary call: Owner credit has lexical candidates aegis_core.credit; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_storage_shared.py', 'test_error_closures_look_up_patched_factories_at_call_time', 'patch', 'monkeypatch.setattr(storage, name, lambda path, base: refusal)', 0):
        (False, 'Selects existing product storage refusal factories.'),
    ('tests/unit/core/test_storage_shared.py', 'test_private_confinement_hooks_remain_live', 'patch', 'monkeypatch.setattr(storage, name, refuse)', 0):
        (False, 'Selects existing product storage confinement hooks, not shared standard-library attributes.'),
    ('tests/unit/mcp/conftest.py', 'fresh_server', 'patch', 'monkeypatch.setattr(server, name, value)', 0):
        (False, 'Resets existing fresh_state fields on the product server module.'),
    ('tests/unit/verification/test_native_ast_limits.py', 'test_card_reports_the_extractor_cap_when_the_runner_allows_more', 'patch', "monkeypatch.setattr(producer, 'MAX_SOURCE_BYTES', 128)", 0):
        (False, 'Exact computed consumer-boundary call: Merged-tip owner ast_runner has static candidates aegis_core.ast.runner; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/verification/test_native_ast_limits.py', 'test_card_retains_the_limit_from_the_refusal_even_if_configuration_changes', 'patch', "monkeypatch.setattr(parser, 'parse', refuse_then_reconfigure)", 0):
        (False, 'Exact computed consumer-boundary call: Merged-tip owner ast_runner has static candidates aegis_core.ast.runner; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/verification/test_native_ast_limits.py', 'test_card_retains_the_limit_from_the_refusal_even_if_configuration_changes', 'patch', "monkeypatch.setattr(producer, 'MAX_SOURCE_BYTES', 128)", 0):
        (False, 'Exact computed consumer-boundary call: Merged-tip owner ast_runner has static candidates aegis_core.ast.runner; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/verification/test_native_ast_limits.py', 'test_card_retains_the_limit_from_the_refusal_even_if_configuration_changes.refuse_then_reconfigure', 'patch', "monkeypatch.setattr(producer, 'MAX_SOURCE_BYTES', 256)", 0):
        (False, 'Exact computed consumer-boundary call: Merged-tip owner producer has static candidates aegis_core.ast.drivers.js.tokenizer, aegis_core.ast.drivers.rust.extractor; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/verification/test_native_ast_limits.py', 'test_extractors_refuse_oversized_text_before_encoding', 'patch', "monkeypatch.setattr(producer, 'MAX_SOURCE_BYTES', 128)", 0):
        (False, 'Exact computed consumer-boundary call: Merged-tip owner producer has static candidates aegis_core.ast.drivers.js.tokenizer, aegis_core.ast.drivers.rust.extractor; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/verification/test_native_ast_limits.py', 'test_security_pack_keeps_its_json_fields_while_carrying_the_refusing_limit', 'patch', "monkeypatch.setattr(extractor if extension == 'rs' else tokenizer, 'MAX_SOURCE_BYTES', 128)", 0):
        (False, 'Exact computed consumer-boundary call: Merged-tip owner ast_runner has static candidates aegis_core.ast.runner; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/verification/test_scanners.py', 'descriptor_count', 'patch', "monkeypatch.setattr(module, 'os', SimpleNamespace(**dict(vars(os), open=tracked_open, dup=tracked_dup, supports_dir_fd=capabilities)))", 0):
        (False, 'Exact computed consumer-boundary call: Owner module has lexical candidates aegis_core.atomicio, aegis_core.verification.scanners; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
}


FIXTURE = "<monkeypatch>"
UNKNOWN = "<dynamic>"
MOCK_PATCH = {"unittest.mock.patch", "mock.patch", "mocker.patch"}
PATCH_METHODS = {"setattr", "delattr", "setitem", "delitem"}
MOCK_CALLABLES = MOCK_PATCH | {factory + "." + method for factory in MOCK_PATCH
                              for method in ("object", "dict", "multiple")}

# (file, lexical scope, source owner) -> (may be shared, reviewed reason).
# These are identities the static import/binding resolver cannot prove.
OWNER_REGISTRATIONS = {
    ('tests/integration/test_hierarchy_handoff_stop_evidence.py', 'modelled_processes', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] is this test module; replaces its owned fixture reference only.'),
    ('tests/integration/test_hierarchy_hosts.py', 'test_r13_unknown_grammar_family_refuses', 'grammar'):
        (False, "grammar is hierarchy_hosts._HOSTS['claude-code']['session_selectors']['grammar']; setitem changes the product registry's family control, not a shared process module."),
    ('tests/integration/test_hierarchy_launcher.py', 'test_stop_records_a_failed_process_census', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher.py', 'test_endpoint_namespace_unsupported_probe_refuses_before_opening', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher.py', 'test_r31_unavailable_pid_namespace_probe_refuses_without_opening', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r33_terminal_claim_changed_during_recovery_keeps_prior_attempts', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r33_terminal_claim_changed_during_recovery_keeps_prior_attempts', 'module.os'):
        (True, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r32_no_namespace_preserves_no_launch_resume_results', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r32_transient_pidfd_failure_keeps_custody_without_numeric_delivery', 'module.os'):
        (True, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r32_pidfd_delivery_errors_keep_fixed_refusal_and_custody', 'module.signal'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r32_no_namespace_refuses_every_stop_state', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'r31_namespace_switch', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r31_late_namespace_loss_refuses_before_signal', 'module.StopCustody'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r31_namespace_refusal_preserves_live_custody_and_consumers', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r30_resume_uses_the_real_spawns_cwd_and_path', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r29_log_close_after_creation_keeps_the_admitted_child', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r29_popen_failure_still_retires_only_the_no_child_admission', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r27_identity_limit_refusal_is_recorded_before_any_signal', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r27_real_producer_wrapper_exec_keeps_its_admitted_instance', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r27_no_plan_failure_keeps_legacy_output_and_record_bytes', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r27_no_plan_failure_keeps_legacy_output_and_record_bytes', 'module.Launches'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r26_captured_resume_requires_no_installed_host_cli', 'r2_case'):
        (False, 'r2_case is the R2Case fixture; its projection and custody are fixture-owned objects, not shared process modules.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r25_fork_gap_pipe_allocation_failure_closes_prior_descriptors', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] is this test module; replaces its owned fixture reference only.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r25_no_plan_resume_keeps_historical_bytes', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r25_spawn_failure_is_retryable', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r25_every_resolved_refusal_has_one_record', 'module.Launches'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r25_recovered_group_budget_is_checked_before_admission', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r25_admission_metadata_refuses_unsupported_descriptors', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r25_failed_spawn_retirement_names_failure_and_exact_recovery', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r23_cleanup_holds_pending_mailbox_admission', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r22_restricted_procfs_has_an_explicit_manual_refusal', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r23_resume_persists_admission_before_creating_the_host', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r23_failed_publication_and_abandonment_keep_the_unknown_group', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r23_full_history_refuses_resume_before_spawning', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r23_parent_outcome_failure_keeps_admission_until_a_later_stop', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r23_parent_outcome_failure_keeps_admission_until_a_later_stop', 'module.Launches'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r23_private_worker_checks_history_room_before_spawning', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r23_refused_resume_requires_a_later_stop', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'r22_wake_processes', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r22_failed_group_cleanup_retains_the_running_wake', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r21_resume_can_be_stopped_mid_turn', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r22_expected_stop_input_is_bounded_and_redacted', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_linux_matcher_reads_proc_without_a_ps_census', 'module.subprocess'):
        (True, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_ps_fallback_ignores_unrelated_quotes', 'module.subprocess'):
        (True, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_ps_fallback_does_not_reconstruct_paths_with_spaces', 'module.subprocess'):
        (True, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_observed_claude_argv_shapes', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_stop_opens_a_pidfd_then_verifies_then_signals', 'module.os'):
        (True, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_stop_opens_a_pidfd_then_verifies_then_signals', 'module.signal'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_fallback_records_unproven_argument_boundaries', 'module.subprocess'):
        (True, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_ps_fallback_checks_uid_and_positional_selectors', 'module.subprocess'):
        (True, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_stop_spares_an_unowned_member_of_an_owned_group', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_stop_records_a_signal_permission_failure', 'module.signal'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_stop_records_a_signal_permission_failure', 'module.os'):
        (True, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_stop_records_a_signal_permission_failure', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'fallback_process', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'fallback_process', 'module.subprocess'):
        (True, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_stop_falls_back_only_when_pidfd_is_unsupported', 'module.os'):
        (True, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_stop_uses_real_and_effective_status_uids', 'module.os'):
        (True, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_stop_retains_stubborn_descendants_after_the_middle_exits', 'module.os'):
        (True, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_stop_retains_stubborn_descendants_after_the_middle_exits', 'module.signal'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_stop_retains_stubborn_descendants_after_the_middle_exits', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; OS/subprocess owners remain counted as shared candidates, including R2Facade views.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_stubborn_descendant_completion_waits_for_deferred_native_reap.spawn', 'process'):
        (False, 'process is the physical child returned by children(...); poll is its fixture-owned observation boundary.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r11_crash_cuts_observe_exit_before_asserting_dead', 'r2_case'):
        (False, 'r2_case is the R2Case fixture; its projection and custody are fixture-owned objects, not shared process modules.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r2_fixture_closure_failed_ready_keeps_physical_custody', 'r2_case.projection'):
        (False, 'r2_case is the R2Case fixture; its projection and custody are fixture-owned objects, not shared process modules.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r2_sibling_fixture_closes_both_children_when_ready_staging_fails', 'r2_case.projection'):
        (False, 'r2_case is the R2Case fixture; its projection and custody are fixture-owned objects, not shared process modules.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r2_exec_fixture_closes_an_actual_exec_on_ready_failure', 'r2_case.projection'):
        (False, 'r2_case is the R2Case fixture; its projection and custody are fixture-owned objects, not shared process modules.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r2_captured_exec_closes_a_child_still_behind_its_gate', 'r2_case.custody'):
        (False, 'r2_case is the R2Case fixture; its projection and custody are fixture-owned objects, not shared process modules.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r2_fixture_closure_partial_tree_survives_receipt_stage_failure', 'r2_case.projection'):
        (False, 'r2_case is the R2Case fixture; its projection and custody are fixture-owned objects, not shared process modules.'),
    ('tests/integration/test_hierarchy_native_probe.py', 'test_r24_hold_constructor_delivers_its_entry_or_exit_event_before_return', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] is this test module; replaces its owned fixture reference only.'),
    ('tests/contract/test_mailbox_index_rollout.py', 'test_tip_prefilters_once_with_clean_git_environment', 'globals()'):
        (False, 'The contract replaces its own _tracked_names helper to count Git prefilter queries while the observed subprocess and AST boundaries check clean Git environment and single-pass parsing.'),
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_lock_and_pending_are_reported_without_takeover', 'module'):
        (False, 'doctor() imports tools.hierarchy_mailbox_doctor; its os reference is replaced with OSProxy to simulate alive/dead lock owners without taking over the mailbox lock.'),
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_limits_refuse_before_parsing', 'module'):
        (False, 'doctor() imports tools.hierarchy_mailbox_doctor; limit selects MAX_FILES, MAX_TOTAL_BYTES or MAX_FILE_BYTES, while its hm reference gets a local strict_json failure seam to prove refusal before parsing.'),
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_cap_uses_all_message_files', 'doctor()'):
        (False, 'doctor() imports tools.hierarchy_mailbox_doctor; lowering its MESSAGE_CAP verifies that the diagnostic counts all message files.'),
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_unsupported_platform_has_fixed_refusal', 'module'):
        (False, 'doctor() imports tools.hierarchy_mailbox_doctor; replacing its descriptor_reads_supported probe verifies the portable MD_PLATFORM refusal.'),
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_rename_swap_cannot_read_outside_bytes', 'module'):
        (False, 'doctor() imports tools.hierarchy_mailbox_doctor; its local os proxy interleaves a folder rename/symlink swap with descriptor-relative opens to check MD_PATH.'),
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_descriptors_close_on_read_failure', 'module'):
        (False, 'doctor() imports tools.hierarchy_mailbox_doctor; its local os proxy injects read failure and records every open/close to verify MD_IO and descriptor cleanup.'),
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_growth_between_preflight_and_read_refuses_before_parser', 'module'):
        (False, 'doctor() imports tools.hierarchy_mailbox_doctor; its local os proxy grows manifest.json between preflight and open to verify MD_LIMIT before parsing.'),
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_root_rename_keeps_reads_on_the_pinned_identity', 'module'):
        (False, 'doctor() imports tools.hierarchy_mailbox_doctor; its local os proxy renames the mailbox root and inserts an outside symlink to verify reads retain the pinned directory identity.'),
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_permission_denied_lock_probe_reports_unknown', 'module'):
        (False, 'doctor() imports tools.hierarchy_mailbox_doctor; its local os proxy injects EPERM from kill(pid, 0), verifying an unknown lock status.'),
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_index_divergence_is_reported_without_repair', 'module'):
        (False, 'doctor() imports tools.hierarchy_mailbox_doctor; its local os proxy changes message bytes between diagnostic and index reads to verify divergence is reported without repair.'),
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_index_fdopen_failure_closes_descriptors_and_is_not_hidden', 'module'):
        (False, 'doctor() imports tools.hierarchy_mailbox_doctor; its local os proxy records descriptor ownership and injects index fdopen failure, verifying MD_IO and complete closure.'),
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_multifolder_diagnostic_work_has_linear_counts', 'module'):
        (False, 'doctor() imports tools.hierarchy_mailbox_doctor; its os, hm and index_module references get local wrappers to count folder checks, listings and parses before the independent shadow comparison.'),
    ('tests/integration/test_hierarchy_workspace.py', 'test_five_initiatives_across_two_projects_keep_the_caps_and_the_priority_order', 'workspace'):
        (False, 'workspace is the test-local Workspace fixture instance; replacing its run method routes the multi-initiative capacity and priority scenario through controller.main and capsys.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_a_pin_to_another_repository_holds_instead_of_acting_on_it', 'type(get_default_registry().get(argv[0]))'):
        (False, 'type(get_default_registry().get(argv[0])) is a CLI command class; its execute sentinel proves a conflicting repository pin holds before dispatch.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_a_pin_that_is_not_a_workspace_is_an_error', "type(get_default_registry().get('status'))"):
        (False, "type(get_default_registry().get('status')) is the status command class; its execute sentinel proves an invalid workspace pin refuses before dispatch."),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_a_pin_that_disagrees_with_the_target_holds_before_the_command_runs', 'type(get_default_registry().get(command))'):
        (False, 'type(get_default_registry().get(command)) is an init/migrate/uninstall command class; its execute sentinel proves a conflicting target pin holds before dispatch.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_migrate_and_uninstall_refuse_home', 'type(get_default_registry().get(argv[0]))'):
        (False, 'type(get_default_registry().get(argv[0])) is a migrate/uninstall command class; its execute sentinel proves the home-directory refusal precedes dispatch.'),
    ('tests/unit/core/test_go_build_cache.py', 'test_child_cleanup_handles_only_a_process_that_already_exited', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] is this test module; its defined _process_running helper is replaced to exercise already-exited child cleanup and PermissionError propagation.'),
    ('tests/unit/core/test_insights.py', 'test_every_name_in_insights_all_is_used_outside_the_module', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] is this test module; its ast reference is replaced with a counted local copy to measure the bounded source scan for public insights exports.'),
    ('tests/unit/core/test_model_select.py', 'test_mr3c_260_bindings_have_mr1_parity', 'provision.hierarchy_hosts'):
        (False, "The MR3c parity control adds the repository tools directory to sys.path and imports hierarchy_provision; it replaces that product module's read_pinned_bindings and hierarchy_hosts.TEAM_HOSTS to compare 260 bindings across parsed, file and transaction surfaces."),
    ('tests/unit/core/test_model_select.py', 'test_mr3c_260_bindings_have_mr1_parity', 'provision'):
        (False, "The MR3c parity control adds the repository tools directory to sys.path and imports hierarchy_provision; it replaces that product module's read_pinned_bindings and hierarchy_hosts.TEAM_HOSTS to compare 260 bindings across parsed, file and transaction surfaces."),
    ('tests/unit/core/test_redaction.py', 'test_no_module_imports_a_private_name_of_redaction', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] is this test module; its ast reference is replaced with a counted local copy to bound the scan for private redaction imports.'),
    ('tests/unit/core/test_storage_confined.py', 'test_concurrent_creator_entries_are_flushed', 'proxy'):
        (False, 'proxy is a test-local DurabilityOS instance, then installed as aegis_core.storage_confined.os; its mkdir hook interleaves another creator to verify containing directories are flushed even after EEXIST.'),
    ('tests/contract/test_mailbox_index_rollout.py', 'test_admitted_importer_routes_through_ast', 'globals()'):
        (False, "globals() is this contract module's owned dictionary; changes the importer fixture only."),
    ('tests/contract/test_mailbox_index_rollout.py', 'test_non_python_mentions_cannot_be_admitted', 'globals()'):
        (False, "globals() is this contract module's owned dictionary; changes the importer fixture only."),
    ('tests/contract/test_mailbox_mcp_contract.py', 'test_changed_tool_still_fails_with_its_name', 'globals()'):
        (False, "globals() is this contract module's owned dictionary; changes the snapshot fixture only."),
    ('tests/contract/test_model_bindings_parity.py', 'test_core_and_mr1_binding_validation_agree', 'provision'):
        (False, 'provision is dynamically imported hierarchy_provision; its host registry is a product module.'),
    ('tests/contract/test_model_bindings_parity.py', 'test_large_valid_registry_has_mr1_parity', 'provision'):
        (False, 'provision is dynamically imported hierarchy_provision; its host registry is a product module.'),
    ('tests/contract/test_model_bindings_parity.py', 'test_large_valid_registry_has_mr1_parity', 'provision.hierarchy_hosts'):
        (False, 'provision is dynamically imported hierarchy_provision; its host registry is a product module.'),
    ('tests/integration/test_ci_green.py', '_gh', 'module.subprocess'):
        (True, 'The ci_green fixture loads the CI script; its subprocess reference is the shared subprocess module.'),
    ('tests/integration/test_hierarchy_board.py', 'test_board_custom_renderers_keep_legacy_budget_selection', 'module'):
        (False, 'page_board returns the dynamically loaded hierarchy_board module and owned board fixtures.'),
    ('tests/integration/test_hierarchy_board.py', 'test_board_metadata_budget_and_empty_pages_match_legacy', 'module'):
        (False, 'page_board returns the dynamically loaded hierarchy_board module and owned board fixtures.'),
    ('tests/integration/test_hierarchy_board.py', 'test_board_only_loads_content_through_the_first_overflow', 'module'):
        (False, 'page_board returns the dynamically loaded hierarchy_board module and owned board fixtures.'),
    ('tests/integration/test_hierarchy_board.py', 'test_board_pages_match_legacy_bytes_at_every_selected_boundary', 'module'):
        (False, 'page_board returns the dynamically loaded hierarchy_board module and owned board fixtures.'),
    ('tests/integration/test_hierarchy_board.py', 'test_board_undeclared_serializers_match_legacy_bytes', 'module'):
        (False, 'page_board returns the dynamically loaded hierarchy_board module and owned board fixtures.'),
    ('tests/integration/test_hierarchy_container.py', 'cli', 'adapter'):
        (False, 'adapter/verifier dynamically load the container product modules; OS/sys attributes are shared modules.'),
    ('tests/integration/test_hierarchy_container.py', 'container_registry', 'verifier'):
        (False, 'adapter/verifier dynamically load the container product modules; OS/sys attributes are shared modules.'),
    ('tests/integration/test_hierarchy_container.py', 'test_inode_alias_checks_every_ancestor', 'adapter.os'):
        (True, 'adapter/verifier dynamically load the container product modules; OS/sys attributes are shared modules.'),
    ('tests/integration/test_hierarchy_container.py', 'test_inode_alias_with_missing_tails_on_both_sides', 'adapter.os'):
        (True, 'adapter/verifier dynamically load the container product modules; OS/sys attributes are shared modules.'),
    ('tests/integration/test_hierarchy_container.py', 'test_matrix_surfaces_do_not_spawn', 'adapter'):
        (False, 'adapter/verifier dynamically load the container product modules; OS/sys attributes are shared modules.'),
    ('tests/integration/test_hierarchy_container.py', 'test_matrix_surfaces_do_not_spawn', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] is this test module; changes its consumer-local fixture reference.'),
    ('tests/integration/test_hierarchy_container.py', 'test_matrix_surfaces_do_not_spawn', 'verifier'):
        (False, 'adapter/verifier dynamically load the container product modules; OS/sys attributes are shared modules.'),
    ('tests/integration/test_hierarchy_container.py', 'test_mount_inode_alias_contains_relocated_secret', 'adapter.os'):
        (True, 'adapter/verifier dynamically load the container product modules; OS/sys attributes are shared modules.'),
    ('tests/integration/test_hierarchy_container.py', 'test_platform_and_unknown_cpu', 'adapter.os'):
        (True, 'adapter/verifier dynamically load the container product modules; OS/sys attributes are shared modules.'),
    ('tests/integration/test_hierarchy_container.py', 'test_platform_and_unknown_cpu', 'adapter.sys'):
        (True, 'adapter/verifier dynamically load the container product modules; OS/sys attributes are shared modules.'),
    ('tests/integration/test_hierarchy_container.py', 'test_rw_ro_overlap', 'adapter.os'):
        (True, 'adapter/verifier dynamically load the container product modules; OS/sys attributes are shared modules.'),
    ('tests/integration/test_hierarchy_container.py', 'test_team_absolute_delegates_to_absolute_leaf', 'verifier'):
        (False, 'present at tip 4959830f before RF-11b landed; added by e39aba4786d7 (RF-10b), scope renamed by ea51b66d (RF-85); verifier is the dynamically loaded hierarchy_absolute consumer module.'),
    ('tests/integration/test_hierarchy_container.py', 'test_valid_limits', 'adapter.os'):
        (True, 'adapter/verifier dynamically load the container product modules; OS/sys attributes are shared modules.'),
    ('tests/integration/test_hierarchy_fixture_broker.py', 'missing_host_capability', 'candidate'):
        (False, 'candidate is the fixture-broker product module; replaces its consumer-owned module reference.'),
    ('tests/integration/test_hierarchy_handoff_stop_evidence.py', 'test_a_census_timeout_preserves_the_error_and_changes_nothing', 'module.hierarchy_launcher.subprocess'):
        (True, 'handoff_module loads hierarchy_handoff; nested launcher subprocess remains shared.'),
    ('tests/integration/test_hierarchy_handoff_stop_evidence.py', 'test_a_wake_after_preflight_refuses_only_its_entry_and_a_rerun_finishes', 'module'):
        (False, 'handoff_module loads hierarchy_handoff; nested launcher subprocess remains shared.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'test_close_during_post_reply_readback_refuses_with_a_typed_error', 'api'):
        (False, 'api dynamically imports tools.hierarchy_host_authority; select is outside the seven-module census.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'test_close_interrupts_a_live_session_waiting_for_its_next_call', 'api.select'):
        (False, 'api dynamically imports tools.hierarchy_host_authority; select is outside the seven-module census.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'waiting_on', 'api.select'):
        (False, 'api dynamically imports tools.hierarchy_host_authority; select is outside the seven-module census.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_durable_grant_fault_retains_rows_audit_and_recovers', 'jobs.Store'):
        (False, 'load_jobs_module returns hierarchy_jobs; Store is its product class, not a shared module.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_grant_to_a_waiting_jobs_stale_kind_is_reported_with_its_reason', 'jobs'):
        (False, 'load_jobs_module returns hierarchy_jobs; Store is its product class, not a shared module.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_matching_grant_released_without_an_execution_claim_never_starts_the_job', 'jobs'):
        (False, 'load_jobs_module returns hierarchy_jobs; Store is its product class, not a shared module.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_stale_grant_appearing_during_current_kind_admission_runs_on_the_current_grant', 'jobs'):
        (False, 'load_jobs_module returns hierarchy_jobs; Store is its product class, not a shared module.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_version_probe_past_its_timeout_takes_what_it_started_with_it', 'jobs'):
        (False, 'load_jobs_module returns hierarchy_jobs; Store is its product class, not a shared module.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_version_probe_whose_escaped_child_holds_the_pipe_still_returns', 'jobs'):
        (False, 'load_jobs_module returns hierarchy_jobs; Store is its product class, not a shared module.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_an_export_whose_link_checks_outlast_its_deadline_is_refused_within_it', 'jobs'):
        (False, 'load_jobs_module returns hierarchy_jobs; Store is its product class, not a shared module.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_another_initiatives_row_under_a_predecessors_holder_never_ends_a_capacity_admitted_dependent', 'jobs'):
        (False, 'load_jobs_module returns hierarchy_jobs; Store is its product class, not a shared module.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_exhausted_budget_preserves_enqueue_but_skips_kind_grant_admission', 'jobs.Store'):
        (False, 'load_jobs_module returns hierarchy_jobs; Store is its product class, not a shared module.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_job_execution_reuses_its_locked_ledger_snapshot', 'jobs.Store'):
        (False, 'load_jobs_module returns hierarchy_jobs; Store is its product class, not a shared module.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_sibling_admission_rederives_grants_without_stranding_a_slot', 'jobs'):
        (False, 'load_jobs_module returns hierarchy_jobs; Store is its product class, not a shared module.'),
    ('tests/integration/test_hierarchy_jobs_derive.py', 'test_live_execution_claim_excludes_resolve_between_stopped_steps', 'jobs'):
        (False, 'load_jobs_module returns hierarchy_jobs; this patch targets its product seam.'),
    ('tests/integration/test_hierarchy_jobs_derive.py', 'test_resolve_after_readmission_prevents_the_resumed_commit', 'jobs'):
        (False, 'load_jobs_module returns hierarchy_jobs; this patch targets its product seam.'),
    ('tests/integration/test_hierarchy_jobs_derive.py', 'test_resolver_excludes_execution_and_other_resolvers_until_its_result_is_durable', 'jobs'):
        (False, 'load_jobs_module returns hierarchy_jobs; this patch targets its product seam.'),
    ('tests/integration/test_hierarchy_launcher.py', 'test_a_census_that_fails_after_signals_were_sent_is_recorded_as_stop_failed', 'module'):
        (False, 'launcher_module loads hierarchy_launcher; its OS/subprocess attributes remain shared.'),
    ('tests/integration/test_hierarchy_launcher.py', 'test_a_record_write_that_fails_part_way_leaves_no_torn_record', 'module.os'):
        (True, 'launcher_module loads hierarchy_launcher; its OS/subprocess attributes remain shared.'),
    ('tests/integration/test_hierarchy_launcher.py', 'test_resume_records_a_wake_tool_that_cannot_run', 'module.subprocess'):
        (True, 'launcher_module loads hierarchy_launcher; its OS/subprocess attributes remain shared.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'canonical_live_decision', 'clock'):
        (False, 'Runtime fixtures return hierarchy_lifecycle; timestamp is defined by hierarchy_mailbox.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_initial_creation_publication_unknown_retains_original_for_explicit_recovery', 'lifecycle'):
        (False, 'Runtime fixtures return hierarchy_lifecycle; timestamp is defined by hierarchy_mailbox.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_reserved_genesis_ambiguity_retains_claim_without_retry', 'lifecycle'):
        (False, 'Runtime fixtures return hierarchy_lifecycle; timestamp is defined by hierarchy_mailbox.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'MemoTrace.__init__', 'mailbox'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'MemoTrace.__init__', 'module.MailboxIndex'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'MemoTrace.__init__', 'module._Observations'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'change_confirmation_inode', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'preserve_source_stat', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'r23_source_reads', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'reply_policy', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'spy_parses', 'module.MailboxIndex'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_inode_reuse_with_different_ctime_reparses', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_mb7_hashes_current_record_before_observing_dependencies', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_mb7_obsolete_brief_permission_recovers_incremental_reads', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_mb7_reconciliation_preserves_changed_live_sha_baseline', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_oracle_detects_order_only_difference', 'index'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_platform_coarse_timestamps_still_force_fallback', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_platform_fallback_retains_observed_sha', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_platform_guard_uses_capability_probe', 'index_module()'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_platform_without_checked_reads_hashes_and_validates', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r12_hash_policy_reuses_parsing_only_after_hash_match', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r12_hash_policy_reuses_parsing_only_after_hash_match', 'module.MailboxIndex'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r12_unreliable_metadata_rehashes_before_reuse', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r14_process_identity_is_live', 'mailbox'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r14_reference_mode_change_rechecks_its_record', 'mailbox'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r14_warm_validation_is_reused_by_observation_key', 'mailbox'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r15_cached_access_opens_and_reads_only_returned_records', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r16_shadow_component_order_does_not_repeat_reads', 'index'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r16_shadow_component_order_does_not_repeat_reads', 'prefix_mailbox'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r18_in_scope_directory_change_revalidates_its_records', 'mailbox'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r19_global_overflow_has_bounded_paths_hashes_and_counters', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r19_rejected_new_paths_do_not_enter_hash_history', 'index_module()'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r19_summary_path_is_byte_bounded_and_identifiable', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r19_thousand_malformed_alternations_are_bounded', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r20_pinned_write_keeps_existing_validation', 'mailbox'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r20_unavailable_verify_keeps_overflow_and_pending', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r21_argon_deleted_full_history_then_unsampled_fallback', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r21_canonical_full_scan_reclaims_deleted_history', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r21_deleted_history_reclaims_live_capacity', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r21_gap_diagnostics_remain_bounded_and_global', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r21_retiring_path_preserves_unreported_hash_change', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r21_unsampled_live_overflow_cannot_claim_coverage', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r22_live_sample_retires_only_after_successful_scan', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r22_retired_sample_fact_is_acknowledged_without_retaining_dead_baseline', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r22_verify_retains_live_sample_baseline', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r23_overflow_promotion_waits_for_verify', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r23_pinned_fallback_return_coverage', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r24_failed_reconciliation_cannot_reuse_contradicted_header', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r24_unsampled_coverage_survives_clear_and_failed_fallback', 'module'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_shadow_and_oracle_keep_differences_in_memory', 'index'):
        (False, 'index_module returns tools.hierarchy_mailbox_index; mailbox/index values are owned product instances.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_coord2_clock_driver_does_not_write_importable_cache', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] is this test module; changes its consumer-local fixture reference.'),
    ('tests/integration/test_hierarchy_operator.py', 'test_async_stop_after_start_expiry_preserves_original_authority_and_cap', 'candidate'):
        (False, 'async_job returns the product hierarchy_operator module as candidate.'),
    ('tests/integration/test_hierarchy_provision.py', 'test_init_needs_no_system_python_path', 'module'):
        (False, 'mr1_cli returns hierarchy_provision plus its CLI wrapper; only the product seam is replaced.'),
    ('tests/integration/test_hierarchy_provision.py', 'test_init_refuses_an_unavailable_bound_interpreter_without_publication', 'module'):
        (False, 'mr1_cli returns hierarchy_provision plus its CLI wrapper; only the product seam is replaced.'),
    ('tests/integration/test_hierarchy_provision.py', 'test_mr1_planless_does_not_open_bindings_and_preserves_answers', 'module'):
        (False, 'mr1_cli returns hierarchy_provision plus its CLI wrapper; only the product seam is replaced.'),
    ('tests/integration/test_hierarchy_provision.py', 'test_mr1_r2_exempt_roles_keep_exact_answers_even_with_broken_bindings', 'module'):
        (False, 'mr1_cli returns hierarchy_provision plus its CLI wrapper; only the product seam is replaced.'),
    ('tests/integration/test_hierarchy_provision.py', 'test_mr1_r3_host_defaults_keep_exact_answers_without_policy_provenance', 'module'):
        (False, 'mr1_cli returns hierarchy_provision plus its CLI wrapper; only the product seam is replaced.'),
    ('tests/integration/test_hierarchy_provision.py', 'test_mr1_r7_explicit_no_plan_preserves_planless_resolution', 'module'):
        (False, 'mr1_cli returns hierarchy_provision plus its CLI wrapper; only the product seam is replaced.'),
    ('tests/integration/test_hierarchy_provision.py', 'test_rb2_interpreter_probe_failure_has_a_fixed_refusal_and_hint', 'module'):
        (False, 'mr1_cli returns hierarchy_provision plus its CLI wrapper; only the product seam is replaced.'),
    ('tests/integration/test_hierarchy_provision.py', 'test_rb2c_add_role_interpreter_probe_failure_is_a_fixed_refusal', 'module'):
        (False, 'mr1_cli returns hierarchy_provision plus its CLI wrapper; only the product seam is replaced.'),
    ('tests/integration/test_hierarchy_provision.py', 'test_rf42_seed_copy_does_not_hide_unexpected_link_errors', 'module'):
        (False, 'sys.modules[Setup.__module__] selects this provisioning test module; replaces only its local os reference for seed-copy failures.'),
    ('tests/integration/test_hierarchy_provision.py', 'test_rf42_seed_copy_falls_back_when_hard_links_are_unavailable', 'module'):
        (False, 'sys.modules[Setup.__module__] selects this provisioning test module; replaces only its local os reference for seed-copy failures.'),
    ('tests/integration/test_hierarchy_root.py', 'observe_transcript', 'tool'):
        (False, 'tool loads hierarchy_root_under_test from tracked source; replaces its consumer agents_rows boundary.'),
    ('tests/integration/test_hierarchy_root.py', 'test_exit_2_from_the_transfer_cas_leaves_spec_and_transfer_written', 'tool'):
        (False, 'tool loads hierarchy_root_under_test from the tracked tool source.'),
    ('tests/integration/test_hierarchy_root.py', 'test_read_jsonl_drains_after_reducer_failures_and_closes_stream', 'tool'):
        (False, 'tool loads hierarchy_root_under_test from tracked source; the existing builtin allowance creates its consumer-local open seam.'),
    ('tests/integration/test_hierarchy_root.py', 'test_transcript_callers_tolerate_a_live_unterminated_tail', 'tool'):
        (False, 'tool loads hierarchy_root_under_test from the tracked tool source.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_child_processes_and_the_loop_get_the_runs_claude_home', 'team'):
        (False, 'team_module loads the hierarchy_team tool; changes its consumer module reference.'),
    ('tests/integration/test_release_workflow.py', 'launcher_commands', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/integration/test_release_workflow.py', 'smoke_failure.invoke', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_checks_mcp_names', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_cli_json_refusals', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_facts_empty_timeout', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_facts_exact_exception', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_facts_exact_identifier', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_facts_preserve_child_raw_bytes', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_governance_real_landscape', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_invalid_rule_names', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_launcher_refusals', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_limits_output_before_json_parsing', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_limits_structured_facts_before_serializing', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_mcp_response_refusals', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_names_mismatched_identifier_fields', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_refuses_ambiguous_rule_names', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_rules_response_refusals', 'wheel_smoke'):
        (False, 'wheel_smoke loads .github/scripts/wheel_smoke.py via spec_from_file_location; replaces consumer-local smoke boundaries.'),
    ('tests/unit/cli/test_cli_workspace.py', '_capture_execute', 'command_cls'):
        (False, 'command_cls is the CLI command class passed by the test to this boundary helper.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'TestHostRowPins.test_outside_a_governed_workspace_an_unreadable_registry_is_unknown_but_no_reason', 'env'):
        (False, 'env is the owned Env fixture; replaces its test host-registry reader.'),
    ('tests/unit/core/test_argv_consumers.py', 'platform', 'module'):
        (False, 'modules contains product command consumers and optional aegis_core.argv; replaces their OS references.'),
    ('tests/unit/core/test_ast_batch_m1.py', 'test_group_termination_failure_still_reaps_and_cleans_scratch', 'kernel'):
        (False, 'kernel is the modeled Windows kernel boundary on the test driver.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_job_close_error_retains_the_original_startup_diagnostic', 'kernel'):
        (False, 'kernel is the modeled kernel/DLL fixture returned by the Windows job boundary helpers.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_lifetime_accounting_is_checked_again_after_member_waits', 'kernel'):
        (False, 'kernel is the modeled kernel/DLL fixture returned by the Windows job boundary helpers.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_native_startup_failure_never_executes_driver_code', 'kernel'):
        (False, 'kernel is the modeled kernel/DLL fixture returned by the Windows job boundary helpers.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_partial_member_list_growth_obeys_the_shared_shutdown_deadline', 'kernel'):
        (False, 'kernel is the modeled kernel/DLL fixture returned by the Windows job boundary helpers.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_shutdown_deadline_also_bounds_already_signaled_members', 'kernel'):
        (False, 'kernel is the modeled kernel/DLL fixture returned by the Windows job boundary helpers.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_shutdown_waits_share_one_deadline', 'kernel'):
        (False, 'kernel is the modeled kernel/DLL fixture returned by the Windows job boundary helpers.'),
    ('tests/unit/core/test_discovery_never_home.py', 'real_home', 'pwd'):
        (False, 'pytest.importorskip loads pwd, which is outside the seven shared modules in this census.'),
    ('tests/unit/core/test_message_codec.py', 'test_class_a_descriptors_are_lazy_and_expansion_never_reads_grandchildren', 'store'):
        (False, "make_store returns an owned codec.Store instance; replaces that instance's IO boundary."),
    ('tests/unit/core/test_message_codec.py', 'test_r3_class_d_named_ref_selection_reads_only_named_child', 'store'):
        (False, "make_store returns an owned codec.Store instance; replaces that instance's IO boundary."),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_b_all_ref_failures_abort_view', 'store'):
        (False, "make_store returns an owned codec.Store instance; replaces that instance's IO boundary."),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_b_expand_only_reads_requested_children', 'store'):
        (False, "make_store returns an owned codec.Store instance; replaces that instance's IO boundary."),
    ('tests/unit/core/test_message_codec.py', 'test_r5_class_a_expand_is_rejected_before_store_io', 'store'):
        (False, "make_store returns an owned codec.Store instance; replaces that instance's IO boundary."),
    ('tests/unit/core/test_message_codec.py', 'test_r7_class_f_spans_refuse_before_ref_io', 'store'):
        (False, "make_store returns an owned codec.Store instance; replaces that instance's IO boundary."),
    ('tests/unit/core/test_message_codec.py', 'test_r8_class_f_disappearance_and_operational_errors_are_distinct', 'store'):
        (False, "make_store returns an owned codec.Store instance; replaces that instance's IO boundary."),
    ('tests/unit/core/test_storage_ratchets.py', 'test_aliases_and_noncall_os_references_are_refused', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_bare_os_loads_are_allowlisted', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_callback_exception_preserves_the_operation_ceiling', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_callback_exceptions_refuse_other_sites_callees_and_counts', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_declared_opener_noncall_loads_are_refused', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_descriptor_cannot_mask_a_stale_string_mode_exemption', 'module'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_expanded_flags_require_the_undeclared_forwarder_diagnostic', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_flags_through_declared_openers_discover_new_forwarders', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_forwarding_reexports_and_callbacks_cannot_hide_calls', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_missing_and_unregistered_capability_probes_are_refused', 'module'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_nested_argon_operation_loads_are_refused_inside_reviewed_scope', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_new_forwarding_opener_call_is_refused', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_new_store_method_calling_forwarding_opener_is_refused', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_only_direct_comparison_operands_are_exempt', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_removed_declared_forwarding_opener_is_refused', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_reviewed_unread_opener_cannot_hide_expanded_flags', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_stale_capability_registration_is_refused', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_storage_ratchet_refuses_descriptor_growth_even_in_allowlisted_scope', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/core/test_storage_ratchets.py', 'test_undeclared_forwarding_opener_is_refused', 'sys.modules[__name__]'):
        (False, 'sys.modules[__name__] selects this storage-ratchet test module; replaces only its source fixtures or reviewed-operation tables.'),
    ('tests/unit/mcp/test_mcp_report_outcome.py', 'test_the_process_maps_stay_bounded', 'telemetry'):
        (False, 'reporting returns the product telemetry module; replaces its bounded test maps.'),
    ('tests/unit/test_p6_noadmin.py', 'run_worker', 'probe'):
        (False, 'probe loads the no-admin test worker module from its tracked source.'),
    ('tests/unit/test_p6_noadmin.py', 'run_worker.run', 'probe'):
        (False, 'probe loads the no-admin test worker module from its tracked source.'),
    ('tests/unit/verification/test_layer1.py', 'TestLayer1FailsClosed.test_tool_exception_becomes_a_failing_result', 'module'):
        (False, "module is the imported verification tool module selected by this test's tool name."),
    ('tests/unit/verification/test_pipeline.py', 'TestPipelineFailClosed.test_pipeline_partial_test_evidence_triggers_discovery_for_missing', 'pipeline.adversarial_verifier'):
        (False, 'pipeline is an owned VerificationPipeline instance; replaces its verifier boundary.'),
}


def _scope_labels(tree):
    """Lexical names only; no import, binding or owner proof is consulted."""
    labels = {}

    def label(node, scope="<module>"):
        labels[id(node)] = scope
        for child in ast.iter_child_nodes(node):
            nested = scope
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                if child in (node.body if isinstance(node.body, list) else [node.body]):
                    part = getattr(node, "name", "<lambda>")
                    nested = part if scope == "<module>" else scope + "." + part
            label(child, nested)

    label(tree)
    return labels


def _ast_identity(node):
    """Semantic AST fields; locations and load/store context are not site keys."""
    def fields(value):
        if isinstance(value, ast.AST):
            return type(value).__name__, tuple((name, fields(child)) for name, child in ast.iter_fields(value)
                                                if name != "ctx"
                                                and not (name == "type_params" and child == []))
        if isinstance(value, list):
            return tuple(fields(child) for child in value)
        return value
    return repr(fields(node))


class ASTSyntax(str):
    """Readable syntax carrying identity from the original AST, even for fragments."""
    def __new__(cls, node):
        value = str.__new__(cls, ast.unparse(node))
        value.identity = _ast_identity(node)
        return value


class SiteKeys:
    """File, lexical qualname, kind, syntax and zero-based occurrence; never lines."""
    def __init__(self, tree, filename):
        self.filename = filename
        self.labels = _scope_labels(tree)
        self.counts = {}
        self.memo = {}

    def key(self, node, kind, expression):
        scope = self.labels[id(node)]
        syntax = _ban_identity((self.filename, scope, kind, expression, 0))[3]
        identity = id(node), kind, syntax
        if identity not in self.memo:
            base = scope, kind, syntax
            occurrence = self.counts.get(base, 0)
            self.counts[base] = occurrence + 1
            self.memo[identity] = self.filename, scope, kind, expression, occurrence
        return self.memo[identity]


class PatchNames(ScopedNames):
    """Conservative lexical bindings; an unknown alternative never becomes unshared."""
    def __init__(self, tree, filename):
        super().__init__(tree, filename)
        self.bindings = {}
        self.labels = {}
        self.cache = {}
        self.proven = {}
        bindings = {}
        forbidden = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    local = alias.asname or (alias.name.split(".")[0] if isinstance(node, ast.Import) else alias.name)
                    bindings.setdefault(local, []).append(node)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                bindings.setdefault(node.id, []).append(node)
            elif isinstance(node, ast.arg):
                bindings.setdefault(node.arg, []).append(node)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bindings.setdefault(node.name, []).append(node)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                bindings.setdefault(node.name, []).append(node)
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                forbidden.update(node.names)
        self.declared_owners = forbidden
        self.shadowed_module_name = "__name__" in bindings
        # Proof deliberately ignores control flow: even an unreachable rebinding,
        # a sibling nested import or an unused declaration invalidates the name.
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                scope = self.at[id(node)]
                for local, imports in scope.imports.items():
                    if bindings.get(local) == [node] and local not in forbidden and len(imports) == 1:
                        self.proven[local] = next(iter(imports))
            elif (isinstance(node, ast.Assign) and len(node.targets) == 1
                  and isinstance(node.targets[0], ast.Name)):
                local = node.targets[0].id
                value = self.proof(node.value)
                if bindings.get(local) == [node.targets[0]] and local not in forbidden and value is not None:
                    self.proven[local] = value
        self.helpers = {node.name: node for node in tree.body
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and bindings.get(node.name) == [node] and node.name not in forbidden}
        self.module_fields = set()

        def field_names(target):
            if isinstance(target, ast.Name):
                yield target.id
            elif isinstance(target, (ast.Tuple, ast.List)):
                for part in target.elts:
                    yield from field_names(part)
            elif isinstance(target, ast.Starred):
                yield from field_names(target.value)

        for node in tree.body:
            if isinstance(node, ast.Import):
                self.module_fields.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
                self.module_fields.update(alias.asname or alias.name for alias in node.names if alias.name != "*")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.module_fields.add(node.name)
            elif (isinstance(node, ast.Assign)
                  or isinstance(node, ast.AnnAssign) and node.value is not None):
                for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                    self.module_fields.update(field_names(target))
        self.module_fields = {field for field in self.module_fields if len(bindings.get(field, [])) == 1}
        # A conditional deletion or exception-alias cleanup can remove a global.
        # Neither is proof that the attribute will exist when the test runs.
        module_scope = self.at[id(tree)]
        for node in ast.walk(tree):
            if self.at.get(id(node)) is module_scope:
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Del):
                    self.module_fields.discard(node.id)
                elif isinstance(node, ast.ExceptHandler) and node.name:
                    self.module_fields.discard(node.name)

        self.labels = _scope_labels(tree)

        def bind(target, value):
            if isinstance(target, ast.Name):
                scope = self.at[id(target)]
                self.bindings.setdefault((id(scope), target.id), []).append(value)
            elif isinstance(target, (ast.Tuple, ast.List)):
                values = value.elts if isinstance(value, (ast.Tuple, ast.List)) else []
                for index, part in enumerate(target.elts):
                    bind(part, values[index] if len(values) == len(target.elts) else None)

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    bind(target, node.value)
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
                bind(node.target, node.value)
            elif isinstance(node, ast.AugAssign):
                bind(node.target, None)
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                for value in node.iter.elts if isinstance(node.iter, (ast.Tuple, ast.List)) else [None]:
                    bind(node.target, value)
            elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                bind(node.optional_vars, node.context_expr)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                positional = [*node.args.posonlyargs, *node.args.args]
                defaults = [None] * (len(positional) - len(node.args.defaults)) + list(node.args.defaults)
                for argument, default in zip(positional + node.args.kwonlyargs, defaults + node.args.kw_defaults):
                    if default is not None:
                        self.bindings.setdefault((id(self.at[id(argument)]), argument.arg), []).append(default)
                    elif argument.arg == "monkeypatch" or self.resolve(argument.annotation) == {"pytest.MonkeyPatch"}:
                        self.bindings.setdefault((id(self.at[id(argument)]), argument.arg), []).append(FIXTURE)
                    elif argument.arg in {"mock", "mocker"}:
                        self.bindings.setdefault((id(self.at[id(argument)]), argument.arg), []).append(argument.arg)

    def proof(self, node):
        """A unique unconditional import, or one simple alias of such an import."""
        if isinstance(node, ast.Name):
            return self.proven.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self.proof(node.value)
            return base + "." + node.attr if base is not None else None
        if (isinstance(node, ast.Subscript) and self.proof(node.value) == "sys.modules"
                and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str)):
            return node.slice.value
        return None

    def is_current_module(self, node):
        """Only an imported sys.modules and the unshadowed implicit __name__."""
        if (self.shadowed_module_name or not isinstance(node, ast.Subscript) or self.proof(node.value) != "sys.modules"
                or not isinstance(node.slice, ast.Name) or node.slice.id != "__name__"):
            return False
        scope = self.at[id(node.slice)]
        while scope is not None:
            if "__name__" in scope.bound:
                return False
            scope = scope.parent
        return True

    def possible(self, node, seen=frozenset()):
        if seen:
            return self._possible(node, seen)
        key = id(node)
        if key not in self.cache:
            self.cache[key] = self._possible(node, seen)
        return self.cache[key]

    def _possible(self, node, seen):
        if isinstance(node, ast.Name):
            scope = self.at[id(node)]
            while scope is not None:
                if node.id in scope.globals and scope.parent is not None:
                    while scope.parent is not None:
                        scope = scope.parent
                elif node.id in scope.nonlocals and scope.parent is not None:
                    scope = scope.parent
                    continue
                key = (id(scope), node.id)
                if key in seen:
                    return {FIXTURE} if FIXTURE in self.bindings.get(key, []) else {UNKNOWN}
                values = self.bindings.get(key, [])
                result = set(scope.imports.get(node.id, set()))
                for value in values:
                    result |= {value} if isinstance(value, str) else self.possible(value, seen | {key})
                if result or node.id in scope.bound:
                    return result or {UNKNOWN}
                scope = scope.parent
            # Bare monkeypatch is also used by self-contained source controls.
            if node.id == "monkeypatch":
                return {FIXTURE}
            # A builtin candidate identifies reflective calls without claiming
            # an import proves its identity as a patch target owner.
            return ({"builtins." + node.id, UNKNOWN}
                    if node.id in {"getattr", "setattr", "delattr", "vars", "globals", "locals"}
                    else {UNKNOWN})
        if isinstance(node, ast.Attribute):
            return {base + "." + node.attr if base != UNKNOWN else UNKNOWN
                    for base in self.possible(node.value, seen)}
        if isinstance(node, ast.IfExp):
            return self.possible(node.body, seen) | self.possible(node.orelse, seen)
        if isinstance(node, ast.NamedExpr):
            return self.possible(node.value, seen)
        if isinstance(node, ast.Subscript) and self.possible(node.value, seen) == {"sys.modules"}:
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                return {node.slice.value}
        if isinstance(node, ast.Call):
            functions = self.possible(node.func, seen)
            if functions <= {"pytest.MonkeyPatch", "pytest.MonkeyPatch.context", FIXTURE + ".context"}:
                return {FIXTURE}
        return {UNKNOWN}


class NamespaceNames(PatchNames):
    """Normalize literal reflection for namespace checks, without changing patch-owner proof."""
    def _possible(self, node, seen):
        if isinstance(node, ast.Call) and len(node.args) >= 2:
            functions = self.possible(node.func, seen)
            attribute = node.args[1]
            if (("builtins.getattr" in functions
                 or isinstance(node.func, ast.Name) and node.func.id == "getattr")
                    and isinstance(attribute, ast.Constant) and isinstance(attribute.value, str)):
                values = {owner + "." + attribute.value if owner != UNKNOWN else UNKNOWN
                          for owner in self.possible(node.args[0], seen)}
                if functions != {"builtins.getattr"}:
                    values.add(UNKNOWN)
                return values
        return super()._possible(node, seen)


class PatchSites(list):
    def __init__(self):
        super().__init__()
        self.errors = []
        self.owners = set()
        self.owner_shared = {}
        self.resolved_owners = set()
        self.proof_uses = {}
        self.proof_lines = {}
        self.patch_keys = {}
        self.call_shared = {}
        self.proven_owners = set()
        self.bans = set()
        self.ban_lines = {}


UNPROVABLE = "unprovable patch use; rewrite or register with a reason"
NAMESPACE_UNPROVABLE = "unprovable namespace write; rewrite or register with a reason"
AST_DIGEST_PREFIX = "ast-sha256:"
# Exact file, lexical scope, ban kind, AST identity and occurrence -> reason.
# Namespace rows store canonical AST fingerprints, not copies of another file's
# source syntax. Other ban rows retain the existing source-syntax representation.
BAN_REGISTRATIONS = {
    ('tests/conftest.py', '_TestCodeIndex._namespace', 'namespace___dict__', 'ast-sha256:f2f0c1b1deb846ea8cb0b7056a662e5094525ee8e43c2b4a757ab569846e240e', 0):
        'Reads the builtin ModuleType dictionary descriptor to inspect test-module provenance without invoking module hooks; no namespace mutation.',
    ('tests/conftest.py', '_TestCodeIndex._class_namespace', 'namespace___dict__', 'ast-sha256:e220644f06bd09bd9b4c3a2bf42ded744b2b23d01d09bc4ad9ae76e882d56b7e', 0):
        'Reads the builtin type dictionary descriptor to inspect loader-class members without invoking metaclass hooks; no class namespace mutation.',
    ('tests/conftest.py', '_TestCodeIndex._class_member', 'namespace___dict__', 'ast-sha256:1743e72effc34da1db86f0500add37bbc441ed0bb849c9ed9f11fdecb4c95edc', 0):
        'Reads the raw class MRO to locate a loader member for test-code authentication without overridable class attribute access; no namespace mutation.',
    ('tests/conftest.py', '_TestCodeIndex._instance_namespace', 'namespace___dict__', 'ast-sha256:c86c6d7f8205922f432dcd541517c12f0174792e8f16148ea096abcef159202c', 0):
        'Reads the raw MRO to locate a builtin instance-dictionary slot for inert test-loader metadata inspection; no instance or class namespace mutation.',
    ('tests/conftest.py', '_TestCodeIndex.preload', 'namespace_sys_modules', 'ast-sha256:7a142aac29df9f293dc9b9448460441d9e2b8cfb86a03ae8087158b9f8e6c3d4', 0):
        'Snapshots the loaded-module cache to authenticate existing test code trees; never inserts, removes or replaces a sys.modules entry.',
    ('tests/conftest.py', '_TestCodeIndex.preload', 'namespace_sys_modules', 'ast-sha256:bf9eb5eebdbbb810a650259f15d8f3f8cf75da2a103c904db2956dd5674a79d7', 0):
        'Reads cached module identity before trusting a test module during preload, rejecting mismatched names without changing sys.modules.',
    ('tests/conftest.py', '_TestCodeIndex._import_module', 'namespace_sys_modules', 'ast-sha256:0a12bdbc9c8ffcf9b82af88d19ba31566a81b1c0b00823b3bde1143ddc19ff58', 0):
        'Reads sys.modules to bind observed import code to its actual test module and reject forged globals; no module-cache mutation.',
    ('tests/conftest.py', '_TestCodeIndex.owns', 'namespace_sys_modules', 'ast-sha256:92f440f2526fcb2291b122c25580244de1f1b556f1d1e3674e0cc8203b76f74b', 0):
        'Reads sys.modules to verify that a frame namespace belongs to the cached test module; no module-map mutation.',
    ('tests/integration/test_hierarchy_native_probe.py', 'custody_probe', 'namespace___dict__', 'ast-sha256:20b91c2010b2c5cdff757959acea3b15d31ef42bf6b72ceeb1fbb5f883b214c0', 0):
        'Executes the tracked probe source in a fresh fixture-owned ModuleType dictionary; the fixture independently owns and reaps every child.',
    ('tests/integration/test_hierarchy_native_probe.py', 'test_custody_log_close_failure_settles_started_child_and_preserves_error', 'namespace_builtin_import', 'ast-sha256:d002c54b6d6b883775198058c993778d98a248c17682e08aeb910cbe9e59ce1b', 0):
        "Acquires builtins for the probe's local log-open failure wrapper; only the fixture-owned probe module receives the replacement, leaving shared builtins unchanged.",
    ('tests/integration/test_hierarchy_native_probe.py', 'test_custody_turn_failure_and_completion_paths', 'namespace_builtin_import', 'ast-sha256:d002c54b6d6b883775198058c993778d98a248c17682e08aeb910cbe9e59ce1b', 0):
        "Acquires builtins for the probe's local log-open failure wrapper; only the fixture-owned probe module receives the replacement, leaving shared builtins unchanged.",
    ('tests/integration/test_hierarchy_native_probe.py', 'test_custody_turn_failure_and_completion_paths.turns', 'declaration', 'nonlocal read_count', 0):
        "nonlocal read_count updates only this closure's hold-turn counter to inject interruption after the first read; no imported owner is rebound.",
    ('tests/unit/cli/test_cli_team.py', 'test_abbreviated_workspace_operation_failure_is_fixed_json', 'namespace_getattr', 'ast-sha256:88bb5a1e3013ee8dc7f21c0d646ec771eff0aa587d652a6f4cb1e3257aa20ad6', 0):
        "Copies os attributes into a local SimpleNamespace whose open raises for the model-selection consumer; pytest's real process-wide os and cleanup remain intact.",
    ('tests/unit/mcp/test_mcp_team_model.py', 'test_io_errors_are_fixed_refusals', 'namespace_getattr', 'ast-sha256:88bb5a1e3013ee8dc7f21c0d646ec771eff0aa587d652a6f4cb1e3257aa20ad6', 0):
        'Copies os attributes into a local SimpleNamespace whose write injects the model I/O refusal; only model_select.os is replaced and real os remains intact.',
    ('tests/unit/mcp/test_mcp_team_model.py', 'test_component_swap_after_confinement_keeps_no_follow_refusal', 'namespace_getattr', 'ast-sha256:88bb5a1e3013ee8dc7f21c0d646ec771eff0aa587d652a6f4cb1e3257aa20ad6', 0):
        'Copies os attributes into a local SimpleNamespace whose open interleaves a directory/symlink swap, verifying confined no-follow refusal without changing real os.',
    ('tests/integration/test_hierarchy_handoff_stop_evidence.py', 'modelled_processes', 'namespace_sys_modules', 'ast-sha256:8d2da3da34ba4b80a8a17082294363e1aca4687ef28102028190ee6f981c6bdb', 0):
        "Temporarily replaces this test module's handoff_module, handoff and Launch fixture references; pytest restores the dictionary entries.",
    ('tests/integration/test_hierarchy_handoff_stop_evidence.py', 'modelled_processes', 'module_write', "monkeypatch.setattr(sys.modules[__name__], 'handoff_module', scoped_module)", 0):
        "Temporarily replaces this test module's handoff_module, handoff and Launch fixture references; pytest restores the dictionary entries.",
    ('tests/integration/test_hierarchy_handoff_stop_evidence.py', 'modelled_processes', 'module_write', "monkeypatch.setattr(sys.modules[__name__], 'handoff', scoped_handoff)", 0):
        "Temporarily replaces this test module's handoff_module, handoff and Launch fixture references; pytest restores the dictionary entries.",
    ('tests/integration/test_hierarchy_handoff_stop_evidence.py', 'modelled_processes', 'namespace_sys_modules', 'ast-sha256:d4657d7288774ecc833c34c86ee05d2224543bfd8b2be4f6d4cff56dc33a0fc1', 0):
        "Temporarily replaces this test module's handoff_module, handoff and Launch fixture references; pytest restores the dictionary entries.",
    ('tests/integration/test_hierarchy_handoff_stop_evidence.py', 'modelled_processes', 'namespace_sys_modules', 'ast-sha256:3eb98cffac5febfeb46f1a1c05fe6bd50c039dc8e9005bf6d7aa31aa517fd35d', 0):
        "Temporarily replaces this test module's handoff_module, handoff and Launch fixture references; pytest restores the dictionary entries.",
    ('tests/integration/test_hierarchy_handoff_stop_evidence.py', 'modelled_processes', 'module_write', "monkeypatch.setattr(sys.modules[__name__], 'Launch', scoped_launch)", 0):
        "Temporarily replaces this test module's handoff_module, handoff and Launch fixture references; pytest restores the dictionary entries.",
    ('tests/integration/test_hierarchy_launcher.py', 'launcher_module', 'module_write', 'sys.modules[name] = module', 0):
        'Registers the importlib-created hierarchy_launcher test module under its unique name before executing its definitions.',
    ('tests/integration/test_hierarchy_launcher.py', 'launcher_module', 'namespace_sys_modules', 'ast-sha256:e99af6430ef2b4454169d817fdf13327686baebae2e529d45cd821688c4be96d', 0):
        'Registers the importlib-created hierarchy_launcher test module under its unique name before executing its definitions.',
    ('tests/integration/test_hierarchy_launcher.py', 'R2Facade.__init__', 'namespace___dict__', 'ast-sha256:1e6d5cf70e0a734a12074564175232893a079b9a3e4839dddc1ff3eb84a8f7ff', 0):
        'R2Facade initializes only its owned instance dictionary with explicit OS/process overrides, preserving the delegated base module.',
    ('tests/integration/test_hierarchy_launcher.py', 'R2Facade.__getattr__', 'namespace_getattr', 'ast-sha256:8423ce6e998a2a3fd7d6e5ef6285d31602564866bbba972189faa698eb83dbf3', 0):
        "R2Facade delegates missing test overrides to the original module using getattr; its instances replace only the loaded consumer's module reference.",
    ('tests/integration/test_hierarchy_launcher.py', 'r2_captured_entry', 'namespace_builtin_import', 'ast-sha256:d002c54b6d6b883775198058c993778d98a248c17682e08aeb910cbe9e59ce1b', 0):
        'Acquires builtins for the fixture-owned execution namespace and its scoped import boundary.',
    ('tests/integration/test_hierarchy_launcher.py', 'r2_captured_entry.Child.__getattr__', 'namespace_getattr', 'ast-sha256:27da59c888af961e8a3f6e609658659f19a150874b61bb873c037b398c1057f2', 0):
        'The process wrapper delegates missing attributes to its registered physical child; the exact getattr reads instance state.',
    ('tests/integration/test_hierarchy_launcher.py', 'r2_captured_entry', 'namespace_vars', 'ast-sha256:01eeb02195b1ffc3f0cbc0b9df43cb1f31f197a017ae72343bdb279b05a81896', 0):
        "Copies builtins into the captured actor's owned execution namespace and replaces only its import boundary for registered physical children.",
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r29_log_close_after_creation_keeps_the_admitted_child.Stream.__getattr__', 'namespace_getattr', 'ast-sha256:7e5240a49aa711f8b7dd9c3cdaf8b011f4d0708bd36adf1336a1cbcd77e5c325', 0):
        'Stream delegates missing attributes to its owned raw stream while injecting publication failures; no module namespace is acquired.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r27_partial_zombie_with_replacement_uid_cannot_commit_original_exit.replacement.<lambda>', 'namespace_getattr', 'ast-sha256:9c39c6fb87815dc91724a800a7837ec882b9658595ef90f5fc60c9446dfc5e23', 0):
        'Reads only the parameterized birth/UID field on the process snapshot to model identity replacement at the consumer boundary.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r27_replacement_identity_latches_birth_and_each_uid.replacement', 'namespace_getattr', 'ast-sha256:4dff364e618754b036163a0f0db38be129d67ef0522d62be570c4391dc3e89d1', 0):
        'Reads only the parameterized birth/UID field on the process snapshot to model identity replacement at the consumer boundary.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r25_fork_gap_pipe_allocation_failure_closes_prior_descriptors', 'module_write', "monkeypatch.setattr(sys.modules[__name__], 'os', R2Facade(real_os, pipe=failed))", 0):
        "Temporarily replaces this test module's os reference with an R2Facade pipe-failure boundary; pytest restores the dictionary entry.",
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r25_fork_gap_pipe_allocation_failure_closes_prior_descriptors', 'namespace_sys_modules', 'ast-sha256:f1854eb1e8a3f4eda5a988a1f723eedcea645309fc3a61e08745adc36ca625ca', 0):
        "Temporarily replaces this test module's os reference with an R2Facade pipe-failure boundary; pytest restores the dictionary entry.",
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r23_failed_publication_and_abandonment_keep_the_unknown_group.Stream.__getattr__', 'namespace_getattr', 'ast-sha256:7e5240a49aa711f8b7dd9c3cdaf8b011f4d0708bd36adf1336a1cbcd77e5c325', 0):
        'Stream delegates missing attributes to its owned raw stream while injecting publication failures; no module namespace is acquired.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r22_running_wake_enospc_cleans_publication_and_marker.Stream.__getattr__', 'namespace_getattr', 'ast-sha256:7e5240a49aa711f8b7dd9c3cdaf8b011f4d0708bd36adf1336a1cbcd77e5c325', 0):
        'Stream delegates missing attributes to its owned raw stream while injecting publication failures; no module namespace is acquired.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r21_cleanup_fences_an_unbound_start', 'namespace_sys_modules', 'ast-sha256:2a7d9c890202093d47c4774ad079e42b1e90073ba51a916b6b284585b750af75', 0):
        'Temporarily installs the fixture-owned launcher under the import spelling used by the handoff control; pytest restores the module-table entry.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r21_cleanup_fences_an_unbound_start', 'module_write', "monkeypatch.setitem(sys.modules, 'hierarchy_launcher', module)", 0):
        'Temporarily installs the fixture-owned launcher under the import spelling used by the handoff control; pytest restores the module-table entry.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r15_probe_cleanup_preserves_custody_but_removes_auth_and_finishes_roles', 'namespace_builtin_import', 'ast-sha256:d002c54b6d6b883775198058c993778d98a248c17682e08aeb910cbe9e59ce1b', 0):
        'Acquires builtins for the fixture-owned execution namespace and its scoped import boundary.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r15_probe_cleanup_preserves_custody_but_removes_auth_and_finishes_roles', 'namespace___dict__', 'ast-sha256:b86b7373185bc4fd14ab3e43da329c37134975444e62f89d727c8a47c357cc42', 0):
        'Initializes or executes the fixture-owned trusted probe module namespace with copied builtins and a scoped import boundary; the real builtins module is unchanged.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r15_probe_cleanup_preserves_custody_but_removes_auth_and_finishes_roles', 'namespace_vars', 'ast-sha256:b86b7373185bc4fd14ab3e43da329c37134975444e62f89d727c8a47c357cc42', 0):
        'Initializes or executes the fixture-owned trusted probe module namespace with copied builtins and a scoped import boundary; the real builtins module is unchanged.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r15_probe_cleanup_preserves_custody_but_removes_auth_and_finishes_roles', 'namespace___dict__', 'ast-sha256:067dc81654d7647457bb5ce1723fc3d69288ad588904e2e3ec86b8c441cbd9f1', 0):
        'Initializes or executes the fixture-owned trusted probe module namespace with copied builtins and a scoped import boundary; the real builtins module is unchanged.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'r16_cleanup_control', 'namespace_builtin_import', 'ast-sha256:d002c54b6d6b883775198058c993778d98a248c17682e08aeb910cbe9e59ce1b', 0):
        'Acquires builtins for the fixture-owned execution namespace and its scoped import boundary.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'r16_cleanup_control', 'namespace___dict__', 'ast-sha256:b86b7373185bc4fd14ab3e43da329c37134975444e62f89d727c8a47c357cc42', 0):
        'Initializes or executes the fixture-owned trusted probe module namespace with copied builtins and a scoped import boundary; the real builtins module is unchanged.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'r16_cleanup_control', 'namespace_vars', 'ast-sha256:b86b7373185bc4fd14ab3e43da329c37134975444e62f89d727c8a47c357cc42', 0):
        'Initializes or executes the fixture-owned trusted probe module namespace with copied builtins and a scoped import boundary; the real builtins module is unchanged.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'r16_cleanup_control', 'namespace___dict__', 'ast-sha256:067dc81654d7647457bb5ce1723fc3d69288ad588904e2e3ec86b8c441cbd9f1', 0):
        'Initializes or executes the fixture-owned trusted probe module namespace with copied builtins and a scoped import boundary; the real builtins module is unchanged.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_public_probe_cleanup_holds_unresolved_census', 'namespace_builtin_import', 'ast-sha256:d002c54b6d6b883775198058c993778d98a248c17682e08aeb910cbe9e59ce1b', 0):
        'Acquires builtins for the fixture-owned execution namespace and its scoped import boundary.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_public_probe_cleanup_holds_unresolved_census', 'namespace___dict__', 'ast-sha256:b86b7373185bc4fd14ab3e43da329c37134975444e62f89d727c8a47c357cc42', 0):
        'Initializes or executes the fixture-owned trusted probe module namespace with copied builtins and a scoped import boundary; the real builtins module is unchanged.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_public_probe_cleanup_holds_unresolved_census', 'namespace_vars', 'ast-sha256:b86b7373185bc4fd14ab3e43da329c37134975444e62f89d727c8a47c357cc42', 0):
        'Initializes or executes the fixture-owned trusted probe module namespace with copied builtins and a scoped import boundary; the real builtins module is unchanged.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_public_probe_cleanup_holds_unresolved_census', 'namespace___dict__', 'ast-sha256:067dc81654d7647457bb5ce1723fc3d69288ad588904e2e3ec86b8c441cbd9f1', 0):
        'Initializes or executes the fixture-owned trusted probe module namespace with copied builtins and a scoped import boundary; the real builtins module is unchanged.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_custody_uses_original_pidfd_when_metadata_read_races_actual_exit', 'namespace_sys_modules', 'ast-sha256:276b6b4971643730994affeaada4ed5111fa169eee01f0a2222016d65ccd8023', 0):
        'Registers an importlib-created fixture-owned custody helper under its unique spec name before executing its definitions.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_custody_uses_original_pidfd_when_metadata_read_races_actual_exit', 'module_write', 'sys.modules[spec.name] = isolated', 0):
        'Registers an importlib-created fixture-owned custody helper under its unique spec name before executing its definitions.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_modelled_custody_lost_birth_cannot_be_resolved_by_numeric_absence', 'namespace_sys_modules', 'ast-sha256:276b6b4971643730994affeaada4ed5111fa169eee01f0a2222016d65ccd8023', 0):
        'Registers an importlib-created fixture-owned custody helper under its unique spec name before executing its definitions.',
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_modelled_custody_lost_birth_cannot_be_resolved_by_numeric_absence', 'module_write', 'sys.modules[spec.name] = isolated', 0):
        'Registers an importlib-created fixture-owned custody helper under its unique spec name before executing its definitions.',
    ('tests/integration/test_hierarchy_native_probe.py', 'ModelledProbeChild.__getattr__', 'namespace_getattr', 'ast-sha256:27da59c888af961e8a3f6e609658659f19a150874b61bb873c037b398c1057f2', 0):
        'The process wrapper delegates missing attributes to its registered physical child; the exact getattr reads instance state.',
    ('tests/integration/test_hierarchy_native_probe.py', 'run_reviewed_constructor', 'namespace_builtin_import', 'ast-sha256:d002c54b6d6b883775198058c993778d98a248c17682e08aeb910cbe9e59ce1b', 0):
        'Acquires builtins for the fixture-owned execution namespace and its scoped import boundary.',
    ('tests/integration/test_hierarchy_native_probe.py', 'run_reviewed_constructor', 'namespace___dict__', 'ast-sha256:b17d4cb652625f7d83fe9650944512a60416e4afc076309eed6c7ad5ac4a04a2', 0):
        'Initializes or executes the fixture-owned trusted probe module namespace with copied builtins and a scoped import boundary; the real builtins module is unchanged.',
    ('tests/integration/test_hierarchy_native_probe.py', 'run_reviewed_constructor', 'namespace_vars', 'ast-sha256:b17d4cb652625f7d83fe9650944512a60416e4afc076309eed6c7ad5ac4a04a2', 0):
        'Initializes or executes the fixture-owned trusted probe module namespace with copied builtins and a scoped import boundary; the real builtins module is unchanged.',
    ('tests/integration/test_hierarchy_native_probe.py', 'run_reviewed_constructor', 'namespace___dict__', 'ast-sha256:0c02d24f1e66e8edf9519a145a937fd9572b7d116272082f3ee8423496994ed0', 0):
        'Initializes or executes the fixture-owned trusted probe module namespace with copied builtins and a scoped import boundary; the real builtins module is unchanged.',
    ('tests/integration/test_hierarchy_native_probe.py', 'modelled_probe_entry', 'namespace_builtin_import', 'ast-sha256:d002c54b6d6b883775198058c993778d98a248c17682e08aeb910cbe9e59ce1b', 0):
        'Acquires builtins for the fixture-owned execution namespace and its scoped import boundary.',
    ('tests/integration/test_hierarchy_native_probe.py', 'modelled_probe_entry', 'namespace___dict__', 'ast-sha256:8ad84dbe88c1addc465df01134bbcb3e04b9195db5e91a21245f77b0c48310e7', 0):
        'Initializes or executes the fixture-owned trusted probe module namespace with copied builtins and a scoped import boundary; the real builtins module is unchanged.',
    ('tests/integration/test_hierarchy_native_probe.py', 'modelled_probe_entry', 'namespace_vars', 'ast-sha256:8ad84dbe88c1addc465df01134bbcb3e04b9195db5e91a21245f77b0c48310e7', 0):
        'Initializes or executes the fixture-owned trusted probe module namespace with copied builtins and a scoped import boundary; the real builtins module is unchanged.',
    ('tests/integration/test_hierarchy_native_probe.py', 'modelled_probe_entry', 'namespace___dict__', 'ast-sha256:2c990c17c2e5e6454ddc018035f35d4f2e0188d21ccca85e2a986e7ff002f56d', 0):
        'Initializes or executes the fixture-owned trusted probe module namespace with copied builtins and a scoped import boundary; the real builtins module is unchanged.',
    ('tests/integration/test_hierarchy_native_probe.py', 'test_r24_hold_constructor_delivers_its_entry_or_exit_event_before_return', 'module_write', "monkeypatch.setattr(sys.modules[__name__], 'MODELLED_PROBE_BOOTSTRAP', MODELLED_PROBE_BOOTSTRAP.replace(entry, observe + '\\n' + entry))", 0):
        "Temporarily replaces this test module's MODELLED_PROBE_BOOTSTRAP fixture to observe the constructor's entry/exit event; pytest restores the dictionary entry.",
    ('tests/integration/test_hierarchy_native_probe.py', 'test_r24_hold_constructor_delivers_its_entry_or_exit_event_before_return', 'namespace_sys_modules', 'ast-sha256:3166c1baf5ac44f7202d6bf65888639dbb15a1d11516a1e9109c999b169ecee1', 0):
        "Temporarily replaces this test module's MODELLED_PROBE_BOOTSTRAP fixture to observe the constructor's entry/exit event; pytest restores the dictionary entry.",
    ('tests/contract/test_mailbox_index_rollout.py', 'test_tip_prefilters_once_with_clean_git_environment', 'namespace_globals', 'ast-sha256:bd90f66af016c1979ec356dabd779a5830559f74fb2e18e0121ca75860836800', 0):
        'The contract replaces its own _tracked_names helper to count Git prefilter queries while the observed subprocess and AST boundaries check clean Git environment and single-pass parsing.',
    ('tests/contract/test_mailbox_index_rollout.py', 'test_tip_prefilters_once_with_clean_git_environment', 'module_write', "monkeypatch.setitem(globals(), '_tracked_names', observed_tracked_names)", 0):
        'The contract replaces its own _tracked_names helper to count Git prefilter queries while the observed subprocess and AST boundaries check clean Git environment and single-pass parsing.',
    ('tests/integration/test_hierarchy_mailbox.py', 'test_fdopen_failure_closes_descriptor', 'namespace_vars', 'ast-sha256:bce2d3b7b4e7f0dbfe6a1c50261fb1665030a659c0cc543e86f6944c20e7eae7', 0):
        'The mailbox fdopen-failure control copies os into a test-local namespace, then replaces only tools.hierarchy_mailbox.os to track descriptor closure before and after raw-stream cleanup.',
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'OSProxy.__getattr__', 'namespace_getattr', 'ast-sha256:890201b1015c1d199801a1d3d04a0a7c4a9b788d2ca97fd5fda954b28824361f', 0):
        "OSProxy delegates missing test overrides to the real os module using getattr; its instances replace only the doctor's os reference.",
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_rename_swap_cannot_read_outside_bytes.opened', 'declaration', 'nonlocal swapped', 0):
        'The nested open boundary records one folder rename/symlink swap through nonlocal swapped, so the doctor must refuse outside bytes with MD_PATH.',
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_root_rename_keeps_reads_on_the_pinned_identity.opened', 'declaration', 'nonlocal swapped', 0):
        'The nested open boundary records one trusted-root rename through nonlocal swapped, proving subsequent doctor reads retain the pinned directory identity.',
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_index_divergence_is_reported_without_repair.opened', 'declaration', 'nonlocal opens', 0):
        'The nested open boundary increments nonlocal opens and rewrites a message on its second open to expose divergence between pinned diagnostic reads and fresh index reads.',
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_index_fdopen_failure_closes_descriptors_and_is_not_hidden.open_fd', 'declaration', 'nonlocal reads', 0):
        "The nested open boundary counts message reads through nonlocal reads and changes the second read's source bytes to exercise the doctor's index-divergence path.",
    ('tests/integration/test_hierarchy_mailbox_doctor.py', 'test_index_fdopen_failure_closes_descriptors_and_is_not_hidden.fdopen', 'declaration', 'nonlocal transfers', 0):
        'The local fdopen boundary counts transfers through nonlocal transfers before raising EIO, proving index stream-construction failures are reported and descriptors close.',
    ('tests/integration/test_hierarchy_workspace.py', 'test_store_load_completes_short_reads_and_retries_eintr', 'namespace_vars', 'ast-sha256:685c04c6997c58e73c14aa1437f49f57afe2ab9e4aa80bd848d322f609ebe971', 0):
        'The short-read/EINTR control compares vars() dictionaries of the real loaded ledger and its expected ledger, checking complete reconstruction without a namespace write.',
    ('tests/integration/test_hierarchy_workspace.py', 'test_store_load_completes_short_reads_and_retries_eintr', 'namespace_vars', 'ast-sha256:685c04c6997c58e73c14aa1437f49f57afe2ab9e4aa80bd848d322f609ebe971', 1):
        'The short-read/EINTR control compares vars() dictionaries of the real loaded ledger and its expected ledger, checking complete reconstruction without a namespace write.',
    ('tests/unit/cli/test_cli_msg.py', 'test_mc2b_namespace_retains_only_cap_plus_one', 'namespace_getattr', 'ast-sha256:5185f82cbdfafa02b9af1728c9057c10a364020de72840665272429201fe6e7c', 0):
        'The MC-2b parser control reads the fields/spans/expand attribute selected by the parameterized flag from its argparse Namespace, verifying storage stops at cap plus one.',
    ('tests/unit/cli/test_cli_msg.py', 'test_mc2b_invalid_entry_after_cap_keeps_family_refusal', 'namespace_getattr', 'ast-sha256:32f3fbe2b92a1a43cc9f562b2c808b1faa45823adfccc16c42cf654c87ab2a55', 0):
        'The MC-2b parser control reads the parameterized argparse Namespace attribute to verify an invalid token after the cap preserves the original family refusal.',
    ('tests/unit/core/test_model_select.py', 'test_mr3c_publication_refuses_changed_log', 'namespace_vars', 'ast-sha256:8e245957def90426eb07b86d8cd6be95eb8938ff13773d64140b92d6f807a0d4', 0):
        'The model-selection consumer receives a copied os namespace whose fsync hook changes, replaces or removes the decision log, verifying stale publication refusal preserves external bytes.',
    ('tests/unit/core/test_model_select.py', 'test_mr3c_generation_failure_closes_source', 'namespace_vars', 'ast-sha256:4d8f8b92c2f5164cfbdb958445f9f820b1f21779d666565ec423a08f6d019dc0', 0):
        'The model-selection consumer receives a copied os namespace whose fstat hook raises on the opened log descriptor, verifying generation failure closes the source.',
    ('tests/unit/core/test_model_select.py', 'test_mr3c_stale_probe_fdopen_failure_closes_descriptor', 'namespace_vars', 'ast-sha256:38aed18e86b290845f16cd8c61021c50c04b36aead048df324da7dbc5004ddc2', 0):
        'The model-selection consumer receives a copied os namespace with fsync tracking and a failing stale-probe fdopen hook, verifying descriptor cleanup and unchanged log bytes.',
    ('tests/unit/core/test_storage_confined.py', 'ModuleOS.__getattr__', 'namespace_getattr', 'ast-sha256:b6f61ddce5d27645ea61615d3aefd4cf77ff281875e65d8354351220e3a10d0d', 0):
        'ModuleOS is a test-local SimpleNamespace subclass whose getattr fallback delegates to real os; instances replace storage_confined.os without modifying the shared os module.',
    ('tests/conftest.py', 'hermetic_environment_and_mcp_isolation', 'namespace_getattr', 'ast-sha256:27d885af9136e10619c219668b6008408635ee7064654f1b345620ba9e74da6c', 0):
        'Reads or invokes the selected field of the owned test/product boundary for hermetic environment and mcp isolation.',
    ('tests/conftest.py', 'hermetic_environment_and_mcp_isolation', 'namespace_sys_modules', 'ast-sha256:54a07f79a15dbcb41a9a8d0f4aad96e4e1cd4abb94ab66a7fe36456251317011', 0):
        'Reads already-loaded credit, memo and MCP modules to reset their owned caches/fixture fields.',
    ('tests/conftest.py', 'hermetic_environment_and_mcp_isolation', 'namespace_sys_modules', 'ast-sha256:b0c264b397815881a59f561474c0f3d14679b74398b2bdd8cd207f1a10b5f614', 0):
        'Reads already-loaded credit, memo and MCP modules to reset their owned caches/fixture fields.',
    ('tests/conftest.py', 'hermetic_environment_and_mcp_isolation', 'namespace_sys_modules', 'ast-sha256:b6eb096432765cd34f45c9a524769cc1ca52844509b94d97d76296dc3626d224', 0):
        'Reads already-loaded credit, memo and MCP modules to reset their owned caches/fixture fields.',
    ('tests/conftest.py', 'hermetic_environment_and_mcp_isolation', 'namespace_sys_modules', 'ast-sha256:f38d1bf1aa89615e23dd02dcc8ddbd800117c01798ed93883767ed1309d0d59d', 0):
        'Reads already-loaded credit, memo and MCP modules to reset their owned caches/fixture fields.',
    ('tests/conftest.py', 'hermetic_environment_and_mcp_isolation', 'namespace_sys_modules', 'ast-sha256:f98e392df39f49c2b6ff79e1010c7f5e580296532d52f0ff31d5fbda7a276bff', 0):
        'Reads already-loaded credit, memo and MCP modules to reset their owned caches/fixture fields.',
    ('tests/contract/test_cli_contract.py', 'test_top_level_help_lists_every_registered_command', 'import', 'import pytest', 0):
        'Local pytest import supplies raises for the existing top-level CLI help contract.',
    ('tests/contract/test_legacy_ratchet.py', 'test_evidence_exemptions_record_paths_and_reasons', 'namespace_globals', 'ast-sha256:7750e55cb95cdd47f12cec041e2b19d044ab5d607647f91debde4d396edfa190', 0):
        'Read-only assertion verifies the evidence exemption contract has no historical HISTORY_DIGESTS global.',
    ('tests/contract/test_mailbox_index_rollout.py', 'test_admitted_importer_routes_through_ast', 'module_write', "monkeypatch.setitem(globals(), 'ADMITTED_IMPORTERS', frozenset({'tools/probe.py'}))", 0):
        "Temporarily replaces this contract module's importer-admission fixture; pytest restores the dictionary entry.",
    ('tests/contract/test_mailbox_index_rollout.py', 'test_admitted_importer_routes_through_ast', 'namespace_globals', 'ast-sha256:9476879ab4431e8436e9611a29d4e0e5bce026439da4e755b00dfb5eae54a758', 0):
        "Temporarily replaces this contract module's importer-admission fixture; pytest restores the dictionary entry.",
    ('tests/contract/test_mailbox_index_rollout.py', 'test_non_python_mentions_cannot_be_admitted', 'module_write', "monkeypatch.setitem(globals(), 'ADMITTED_IMPORTERS', admitted)", 0):
        "Temporarily replaces this contract module's importer-admission fixture; pytest restores the dictionary entry.",
    ('tests/contract/test_mailbox_index_rollout.py', 'test_non_python_mentions_cannot_be_admitted', 'namespace_globals', 'ast-sha256:7d649d60e96e50e937d01e20d524ffcc8d0f1f2f13e1c6f4a3022be38db134d6', 0):
        "Temporarily replaces this contract module's importer-admission fixture; pytest restores the dictionary entry.",
    ('tests/contract/test_mailbox_mcp_contract.py', 'run_python', 'declaration', 'global PYTHON_RUNS', 0):
        "The owned subprocess-run counter or snapshot fixture is changed by this contract's harness.",
    ('tests/contract/test_mailbox_mcp_contract.py', 'test_changed_tool_still_fails_with_its_name', 'module_write', "monkeypatch.setitem(globals(), 'SNAPSHOT', path)", 0):
        "The owned subprocess-run counter or snapshot fixture is changed by this contract's harness.",
    ('tests/contract/test_mailbox_mcp_contract.py', 'test_changed_tool_still_fails_with_its_name', 'namespace_globals', 'ast-sha256:a5746d20c9ced5757256753dfb08ad7523651819462bdff6c493565f26cbab55', 0):
        "The owned subprocess-run counter or snapshot fixture is changed by this contract's harness.",
    ('tests/contract/test_pinned_sources.py', '_collect_pins', 'declaration', 'global REPO, SOURCE, CONSTANTS, MAX_FILE, MANIFEST_SHA256, MANIFEST_RAW', 0):
        'The pin contract initializes its own repository/AST/constant snapshot globals; no patch receiver is rebound.',
    ('tests/integration/test_hierarchy_container.py', 'cli', 'constructor_reference', 'pytest.MonkeyPatch', 0):
        'The owned CLI fixture opens a pytest context to replace only hierarchy_container.subprocess with a copied process API; context exit restores the consumer reference.',
    ('tests/integration/test_hierarchy_container.py', 'local_via_intermediate_link', 'namespace_getattr', 'ast-sha256:a81493a4fff96a349eac1ec61b12902eaef37e299255b5c127ebe230cbd50311', 0):
        'Selects the parameterized owned layout path for home/mount boundary assertions.',
    ('tests/integration/test_hierarchy_container.py', 'recorded_local_root', 'namespace_getattr', 'ast-sha256:e59eb23b8b8df3afef422a9bf96737748f0e6be34e16bb77e1101d659480332d', 0):
        'Selects the parameterized owned layout path for home/mount boundary assertions.',
    ('tests/integration/test_hierarchy_container.py', 'relocated_local_parent', 'namespace_getattr', 'ast-sha256:d83e485beca8971d4874478d80bb03d68fa0eb32d32e48619751fcb7c75ea0fe', 0):
        'Selects the parameterized owned layout path for home/mount boundary assertions.',
    ('tests/integration/test_hierarchy_container.py', 'test_alias_into_protected_tree_builders_refuse', 'namespace_getattr', 'ast-sha256:8da7ced477d2bba7d0880111743811924ed69c8a465a2eb949b7a28d92e002ae', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_bind_policy_public_builders_refuse', 'namespace_getattr', 'ast-sha256:1e98436142fab8ca5abf3ea573807d8acd3e4088e38ca1ab8758b14aea431cdf', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_builder_recursive_mount_refuses', 'namespace_getattr', 'ast-sha256:eb8b0df686394d06790aa416f726f6cf07b594ddc8ca87207792a9801d6f35a7', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_builders_refuse_every_owner_home_local', 'namespace_getattr', 'ast-sha256:2fb5253606350356c3d880267e0b8a0d48df6cfd5fa37bbffd5d3850444bee32', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_builders_refuse_every_owner_home_local', 'namespace_getattr', 'ast-sha256:479161875fd03b16d077543ac1dff1bbc4dd7f8ef962b467f4e2b534307966f2', 0):
        'Selects the parameterized owned layout path for home/mount boundary assertions.',
    ('tests/integration/test_hierarchy_container.py', 'test_builders_refuse_owner_homes_and_secrets', 'namespace_getattr', 'ast-sha256:70f283fbb627614e1188bf44b17fd8710bfbe6cd4ed71e5cbcfb03f197ef8cfb', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_builders_refuse_unequal_path_spellings', 'namespace_getattr', 'ast-sha256:c395d8990289e7656653ee1aee8d64ef57ec6fd8202808c9b39d333b6eda1c4c', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_builders_refuse_unreadable_mount', 'namespace_getattr', 'ast-sha256:9cabb2a62dd2fb64cf5ea65e6a5065d599d00d53ca55076636e6226c5a8e2f7a', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_builders_revalidate_stored_plan', 'namespace_getattr', 'ast-sha256:bd9af6bed8c2354c0856f1264ff22f9e8709d32ec32c94e8ebedf61452fccb2b', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_cli_verify_refuses_owner_secret_mount', 'namespace_getattr', 'ast-sha256:efd8771a4d9a23d476dae0966b08a8e1120983fda6079e9215275a5a2443ca61', 0):
        'Selects the parameterized owned layout path for home/mount boundary assertions.',
    ('tests/integration/test_hierarchy_container.py', 'test_documents_containing_relocated_secret_refused_cli', 'namespace_getattr', 'ast-sha256:be704ac4d33ae916decfc2c34570dd5e0c8062a39ae9fb4336785d20eb7565bf', 0):
        'Selects the parameterized owned layout path for home/mount boundary assertions.',
    ('tests/integration/test_hierarchy_container.py', 'test_documents_project_and_venv_allowed_cli', 'namespace_getattr', 'ast-sha256:6e33b7e3039e7e48b27f7051320f3ea653457749d7c287bce38288b0feedf614', 0):
        'Selects the parameterized owned layout path for home/mount boundary assertions.',
    ('tests/integration/test_hierarchy_container.py', 'test_existing_local_leaf_identity_alias_boundary', 'namespace_getattr', 'ast-sha256:2320d63b908c36094b5b8bfa182dc1b1737d9fdcbbd7fd5597c8b9e38ffb5e07', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_expected_record_cannot_bind_owner_home_local', 'namespace_getattr', 'ast-sha256:479161875fd03b16d077543ac1dff1bbc4dd7f8ef962b467f4e2b534307966f2', 0):
        'Selects the parameterized owned layout path for home/mount boundary assertions.',
    ('tests/integration/test_hierarchy_container.py', 'test_expected_record_keeps_missing_non_secret_home_path', 'namespace_getattr', 'ast-sha256:53e77c4c694ec4e517b61108535640304752e2875f48c8240ac96addf3a807ff', 0):
        'Selects the parameterized owned layout path for home/mount boundary assertions.',
    ('tests/integration/test_hierarchy_container.py', 'test_home_lookup_keeps_environment_and_password_fallback', 'namespace_getattr', 'ast-sha256:0050d4570bfe2060c11e59fa8e47f06bea3b0a8793cf9866bf6e31a25176116c', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_home_lookup_keeps_environment_and_password_fallback', 'namespace_getattr', 'ast-sha256:27da445cb6e85d57edfe80b5a037181d689918843b12cb8ea0ab0700bf8e7ab8', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_home_lookup_keeps_environment_and_password_fallback', 'namespace_getattr', 'ast-sha256:4bc1e1ab129bc182636b44d3b08a06f9bf47bd6925c8d292ca464df4a704c404', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_home_lookup_keeps_environment_and_password_fallback', 'namespace_getattr', 'ast-sha256:a5dc9092eb5ac6257f183f7966217098048616583a854811804d620ab6be1721', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_home_nss_oserror_is_validation_refusal', 'namespace_getattr', 'ast-sha256:812077172fad21f7387dfe55661f895137feb57d474cd3d0b2f89b34c6f74669', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_home_set_does_not_require_nss_for_empty_builder', 'namespace_getattr', 'ast-sha256:4bc1e1ab129bc182636b44d3b08a06f9bf47bd6925c8d292ca464df4a704c404', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_home_set_does_not_require_nss_for_empty_builder', 'namespace_getattr', 'ast-sha256:a5dc9092eb5ac6257f183f7966217098048616583a854811804d620ab6be1721', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_image_userland_descendant_builders_refuse', 'namespace_getattr', 'ast-sha256:1e98436142fab8ca5abf3ea573807d8acd3e4088e38ca1ab8758b14aea431cdf', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_intermediate_local_enoent_target_protected_descendants_allowed', 'namespace_getattr', 'ast-sha256:54e2e2e7aa5b54c90241c7ec0eef9b529f2fe411bb4450c2fdf67e546af89535', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_intermediate_local_metadata_refuses', 'namespace_getattr', 'ast-sha256:44e1e3c880282ea8d05309c44fc1b3034b6c4ca28d060e7b9e7f889b3562dd2b', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_local_root_metadata_cannot_be_absence', 'namespace_getattr', 'ast-sha256:44e1e3c880282ea8d05309c44fc1b3034b6c4ca28d060e7b9e7f889b3562dd2b', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_local_root_metadata_cannot_be_absence', 'namespace_getattr', 'ast-sha256:5707839e64af2e2356270fdfb2dee22464f43ec12bc32e4fc4f6abc2e4282f82', 0):
        'Reads or invokes the selected field of the owned test/product boundary for test local root metadata cannot be absence.',
    ('tests/integration/test_hierarchy_container.py', 'test_local_root_metadata_cannot_be_absence', 'namespace_getattr', 'ast-sha256:a81493a4fff96a349eac1ec61b12902eaef37e299255b5c127ebe230cbd50311', 0):
        'Selects the parameterized owned layout path for home/mount boundary assertions.',
    ('tests/integration/test_hierarchy_container.py', 'test_local_symlink_expansion_budget_refuses', 'namespace_getattr', 'ast-sha256:67e247e26d4ef66eda74ec7483d187646b70f4352b32f6d05b3fe55460a64230', 0):
        'Selects the parameterized owned layout path for home/mount boundary assertions.',
    ('tests/integration/test_hierarchy_container.py', 'test_matrix_surfaces_do_not_spawn', 'module_write', "monkeypatch.setattr(sys.modules[__name__], 'subprocess', SimpleNamespace(**{**vars(subprocess), 'run': unexpected_child}))", 0):
        "present at tip 4959830f before RF-11b landed; added by 5ae2b29044cf; Replaces this test module's subprocess reference with its no-child-spawn capability fixture.",
    ('tests/integration/test_hierarchy_container.py', 'test_matrix_surfaces_do_not_spawn', 'namespace_sys_modules', 'ast-sha256:0477ef5a0fb82be6729bc1357f78326afd8b9bf28cec37b4efee90e0fb02a9b0', 0):
        "present at tip 4959830f before RF-11b landed; added by 5ae2b29044cf; Replaces this test module's subprocess reference with its no-child-spawn capability fixture.",
    ('tests/integration/test_hierarchy_container.py', 'test_mixed_access_nested_destinations_refuse', 'namespace_getattr', 'ast-sha256:812077172fad21f7387dfe55661f895137feb57d474cd3d0b2f89b34c6f74669', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_mount_canonicalization_oserror_refuses', 'namespace_getattr', 'ast-sha256:d0d5c2aff94243ad74a88c7cfe7c32b477c39ecbbb04e1daa0c93d90b17dcc78', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_mount_metadata_recursion_is_refused', 'namespace_getattr', 'ast-sha256:44e1e3c880282ea8d05309c44fc1b3034b6c4ca28d060e7b9e7f889b3562dd2b', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_mount_metadata_recursion_is_refused', 'namespace_getattr', 'ast-sha256:5707839e64af2e2356270fdfb2dee22464f43ec12bc32e4fc4f6abc2e4282f82', 0):
        'Reads or invokes the selected field of the owned test/product boundary for test mount metadata recursion is refused.',
    ('tests/integration/test_hierarchy_container.py', 'test_protected_home', 'namespace_getattr', 'ast-sha256:9d21a40805a858826a7683db90afb2c6e193108daadd7ea0c3ac70734f94867e', 0):
        'Selects the parameterized owned layout path for home/mount boundary assertions.',
    ('tests/integration/test_hierarchy_container.py', 'test_recorded_local_root_refuses', 'namespace_getattr', 'ast-sha256:f7649433db8a17c809a7349d992dd3ee6abba2c7ef388d092e1d02b1f4da5cf3', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_relocated_local_parent_refuses', 'namespace_getattr', 'ast-sha256:54e2e2e7aa5b54c90241c7ec0eef9b529f2fe411bb4450c2fdf67e546af89535', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_request_never_replaces_one_actual_bind', 'namespace_getattr', 'ast-sha256:507936139e29933e07caa4f670b83a33506eba830b8527fd1b6e65debe98d454', 0):
        'Selects the parameterized owned layout path for home/mount boundary assertions.',
    ('tests/integration/test_hierarchy_container.py', 'test_resolved_local_alias_refuses', 'namespace_getattr', 'ast-sha256:f7649433db8a17c809a7349d992dd3ee6abba2c7ef388d092e1d02b1f4da5cf3', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_secret_discovery_errors_cannot_be_absence', 'namespace_getattr', 'ast-sha256:44e1e3c880282ea8d05309c44fc1b3034b6c4ca28d060e7b9e7f889b3562dd2b', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_stored_mixed_access_overlap_refuses', 'namespace_getattr', 'ast-sha256:812077172fad21f7387dfe55661f895137feb57d474cd3d0b2f89b34c6f74669', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_symlink_expansion_budget_refuses', 'namespace_getattr', 'ast-sha256:812077172fad21f7387dfe55661f895137feb57d474cd3d0b2f89b34c6f74669', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_symlink_memo_hit_still_checks_link_metadata', 'namespace_getattr', 'ast-sha256:812077172fad21f7387dfe55661f895137feb57d474cd3d0b2f89b34c6f74669', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_unavailable_home_lookup_refuses', 'namespace_getattr', 'ast-sha256:44e1e3c880282ea8d05309c44fc1b3034b6c4ca28d060e7b9e7f889b3562dd2b', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_unreadable_owner_identity_fails_closed', 'namespace_getattr', 'ast-sha256:322b3e7c4ccbf9be7cbe7c2b6945313fd37e0d1d4dcd9d3e77259ef2166b61ca', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_user_numeric_type_diagnostic_stays_stable', 'namespace_getattr', 'ast-sha256:ea70d310f8d40b5a0352d150f52a458d1370dbcb0663fb8f31f3814d6e4025d5', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_container.py', 'test_user_upper_bounds_refuse_before_effect', 'namespace_getattr', 'ast-sha256:f70bcfb6543f481b5f81778e479e77a9980cf9307228a2db8a6f669ff38f817f', 0):
        'Invokes the parameterized container plan/record builder to assert the mount and identity boundary.',
    ('tests/integration/test_hierarchy_decider.py', 'test_the_router_never_routes_a_delegation', 'namespace___class__', 'ast-sha256:77e0f9a36354f03f7484fe5244269de9d10cc6b74079cd004e68df8e79158d67', 0):
        "Selects the Decider behavior on this test's owned Loop ledger instance; imported module/patcher bindings are not changed.",
    ('tests/integration/test_hierarchy_decider.py', 'test_the_router_status_lists_each_escalation_for_root', 'namespace___class__', 'ast-sha256:77e0f9a36354f03f7484fe5244269de9d10cc6b74079cd004e68df8e79158d67', 0):
        "Selects the Decider behavior on this test's owned Loop ledger instance; imported module/patcher bindings are not changed.",
    ('tests/integration/test_hierarchy_fixture_broker.py', 'missing_host_capability', 'namespace_getattr', 'ast-sha256:d5c8e72d5a6f5344c9b89e0ae99126013283ab172cb52d36a0cfbaf4882b5f50', 0):
        'Reads or invokes the selected field of the owned test/product boundary for missing host capability.',
    ('tests/integration/test_hierarchy_fixture_broker.py', 'missing_host_capability', 'namespace_vars', 'ast-sha256:d5c8e72d5a6f5344c9b89e0ae99126013283ab172cb52d36a0cfbaf4882b5f50', 0):
        'Copies the candidate os/socket capability dictionary before removing a capability from an owned SimpleNamespace; the real module is left intact.',
    ('tests/integration/test_hierarchy_host_authority.py', 'count_external_readback', 'namespace_getattr', 'ast-sha256:3e3dab9f1c8f73c62e64686802d669dafa2a353ab2a1aa4bab209927e18d4535', 0):
        'Reads or invokes the selected field of the owned test/product boundary for count external readback.',
    ('tests/integration/test_hierarchy_host_authority.py', 'test_real_initial_live_wire_creates_owned_invocation_and_both_fence_guard', 'namespace_setattr', 'ast-sha256:77db8090efb05f2322b940c36a9b1a645cbdf774ca3c52d3d1cc7125c2e9ebe3', 0):
        'Changes an owned modeled fixture field for test real initial live wire creates owned invocation and both fence guard.',
    ('tests/integration/test_hierarchy_lifecycle.py', 'canonical_live_decision', 'namespace_sys_modules', 'ast-sha256:38e86aa0e50e03f5c9bf0851d7e5345be19281589b32e45c52492974321cd145', 0):
        'Selects the already-loaded test/product module for canonical live decision.',
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_initial_creation_late_canonical_exit_budget_recovers_original.expire_after_canonical_release', 'declaration', 'nonlocal offset_ns', 0):
        'The closure changes only its controlled clock offset for publication-deadline tests.',
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_protected_decision_publication_and_scope_exit_keep_original_unknown.scope_exit', 'declaration', 'nonlocal offset', 0):
        'The closure changes only its controlled clock offset for publication-deadline tests.',
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_reserved_genesis_guard_exit_deadline_keeps_publication_unknown.expire_after_canonical_release', 'declaration', 'nonlocal offset_ns', 0):
        'The closure changes only its controlled clock offset for publication-deadline tests.',
    ('tests/integration/test_hierarchy_lifecycle_connections.py', 'team', 'namespace___class__', 'ast-sha256:77e0f9a36354f03f7484fe5244269de9d10cc6b74079cd004e68df8e79158d67', 0):
        "Selects the Decider behavior on this test's owned Loop ledger instance; imported module/patcher bindings are not changed.",
    ('tests/integration/test_hierarchy_mailbox_index.py', 'PlatformOS.__getattr__', 'namespace_getattr', 'ast-sha256:afe98e2622fe6e175d1900c4c6988ab4f4cb375c4c1acca2005e451fe1373592', 0):
        'Reads or invokes the selected field of the owned test/product boundary for PlatformOS.  getattr  .',
    ('tests/integration/test_hierarchy_mailbox_index.py', 'PlatformOS.__init__', 'namespace___dict__', 'ast-sha256:1e6d5cf70e0a734a12074564175232893a079b9a3e4839dddc1ff3eb84a8f7ff', 0):
        'PlatformOS initializes only its owned instance dictionary with explicit OS overrides, preserving the delegated base module.',
    ('tests/integration/test_hierarchy_mailbox_index.py', 'invoke', 'namespace_getattr', 'ast-sha256:565ca9d75abb7473c54f3e0b19e63ca328d3f640807cb9a6bca0a6fc677be37b', 0):
        'Reads or invokes the selected field of the owned test/product boundary for invoke.',
    ('tests/integration/test_hierarchy_mailbox_index.py', 'r23_source_reads.Stream.__getattr__', 'namespace_getattr', 'ast-sha256:f3ebdee2dd55682a3e544c1da05c5283e52206c1aa13b40a5f2dff59a5a4488e', 0):
        'Reads or invokes the selected field of the owned test/product boundary for r23 source reads.Stream.  getattr  .',
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_operations_never_write_root_or_parent', 'namespace_getattr', 'ast-sha256:de807532629bfbfaa5d7bbd3a1a8769507743d7cc323bd0b054f768eb559adc6', 0):
        'Reads or invokes the selected field of the owned test/product boundary for test operations never write root or parent.',
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r15_cached_access_opens_and_reads_only_returned_records.Stream.__getattr__', 'namespace_getattr', 'ast-sha256:f3ebdee2dd55682a3e544c1da05c5283e52206c1aa13b40a5f2dff59a5a4488e', 0):
        'Reads or invokes the selected field of the owned test/product boundary for test r15 cached access opens and reads only returned records.Stream.  getattr  .',
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_coord2_clock_driver_does_not_write_importable_cache', 'module_write', "monkeypatch.setattr(sys.modules[__name__], 'HELPER', source / 'hierarchy_mailbox.py')", 0):
        "Selects this test module's copied mailbox helper path; the module field patch stays strict.",
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_coord2_clock_driver_does_not_write_importable_cache', 'namespace_sys_modules', 'ast-sha256:c8371b168567272be32badeaa4993c0cba3f7b2dd84bcf5d5e1fa8ae314e88f7', 0):
        "Selects this test module's copied mailbox helper path; the module field patch stays strict.",
    ('tests/integration/test_hierarchy_native_probe.py', 'test_a_signal_mid_run_stops_the_turn_cleans_up_and_writes_an_interrupted_report', 'namespace_getattr', 'ast-sha256:437e3ab3ab47205603479acc407562e7cd6921d13878771355098229d58fc033', 0):
        'Reads or invokes the selected field of the owned test/product boundary for test a signal mid run stops the turn cleans up and writes an interrupted report.',
    ('tests/integration/test_hierarchy_native_probe.py', 'test_run_1_observations_replay_without_filesystem_or_process_access', 'namespace_builtin_import', 'ast-sha256:d002c54b6d6b883775198058c993778d98a248c17682e08aeb910cbe9e59ce1b', 0):
        'Acquires builtins to make offline replay fail on any filesystem/process access after host facts are captured.',
    ('tests/integration/test_hierarchy_operator.py', 'test_async_native_defaults_refuse_before_opening_a_ledger', 'namespace_getattr', 'ast-sha256:8447ccd69d02a155c5560c5ae043357d150fd9b0b1c0bbcee70be68bb7400e69', 0):
        'Reads or invokes the selected field of the owned test/product boundary for test async native defaults refuse before opening a ledger.',
    ('tests/integration/test_hierarchy_portability.py', '<module>', 'namespace_generated_builtin_import', 'ast-sha256:16e4cfaa43b8b47e846413246cc0d042c17e0f878b54c7664133984b762fda20', 0):
        'Child collection models unavailable pwd/fcntl and SIGHUP while collecting POSIX hierarchy modules. The complete generated-program construction is pinned.',
    ('tests/integration/test_hierarchy_provision.py', 'test_rf42_seed_copy_does_not_hide_unexpected_link_errors', 'namespace_sys_modules', 'ast-sha256:73b0e84c48599e258731d48224ad8ecddfc59e955e6adaf46fe577ca92934e1f', 0):
        'Selects the already-loaded test/product module for test rf42 seed copy does not hide unexpected link errors.',
    ('tests/integration/test_hierarchy_provision.py', 'test_rf42_seed_copy_falls_back_when_hard_links_are_unavailable', 'namespace_sys_modules', 'ast-sha256:73b0e84c48599e258731d48224ad8ecddfc59e955e6adaf46fe577ca92934e1f', 0):
        'Selects the already-loaded test/product module for test rf42 seed copy falls back when hard links are unavailable.',
    ('tests/integration/test_hierarchy_review.py', 'test_each_side_holds_the_exact_committed_bytes', 'namespace_getattr', 'ast-sha256:e85f7a5efefd7c7564538e531a9cf10d79334c4233f867d06281d74d86954a45', 0):
        'Reads or invokes the selected field of the owned test/product boundary for test each side holds the exact committed bytes.',
    ('tests/integration/test_hierarchy_small_change_dispatch.py', 'formal_dispatch', 'namespace_generated_builtin_import', 'ast-sha256:33f0a93d9e232e9ae186dad9e6eaaf4741f9683ee0b1ffbb8f5dab8f2076f76b', 0):
        'Child router wraps filesystem APIs to model watched paths, telemetry growth and protected-home refusal. The complete generated-program construction is pinned.',
    ('tests/integration/test_hierarchy_small_change_dispatch.py', 'r10_source_io', 'namespace_generated_builtin_import', 'ast-sha256:d15ce195c455b82215c5dc9081cb060a6214b70cd2456af9f7e2b90152ef7d88', 0):
        'Child router wraps source I/O and counts content opens across builtins/io/os APIs. The complete generated-program construction is pinned.',
    ('tests/integration/test_hierarchy_small_change_dispatch.py', 'snapshot_v1_probe', 'namespace_generated_builtin_import', 'ast-sha256:e47b05a6cfdcd74601f9d03443f84c5e05b2f3ef51e8b86a8d8a58170e841cb0', 0):
        'Child router wraps filesystem APIs to model watched paths, telemetry growth and protected-home refusal. The complete generated-program construction is pinned.',
    ('tests/integration/test_hierarchy_team.py', 'test_missing_pin_recovery_before_recipes_exist_resumes_in_place', 'namespace_vars', 'ast-sha256:e551b0dbc69f0f217fdcb0b6506543d8849afe5c5cdd45b33d4c515ae1fb1ea7', 0):
        'Reads vars(os) to copy os into an owned capability/AST namespace for test_missing_pin_recovery_before_recipes_exist_resumes_in_place; overrides are installed on the copy rather than the original namespace.',
    ('tests/integration/test_hierarchy_team.py', 'test_orchestration_interpreter_startup_cwd_failure_is_a_fixed_refusal', 'namespace_vars', 'ast-sha256:e551b0dbc69f0f217fdcb0b6506543d8849afe5c5cdd45b33d4c515ae1fb1ea7', 0):
        'Reads vars(os) to copy os into an owned capability/AST namespace for test_orchestration_interpreter_startup_cwd_failure_is_a_fixed_refusal; overrides are installed on the copy rather than the original namespace.',
    ('tests/integration/test_hierarchy_team_homes.py', 'home_alias', 'namespace_setattr', 'ast-sha256:ddec85c146b4746b09844c96bb0b2d2e3fbeb4ec895c08fc6dc6fda10a467ba8', 0):
        'Changes an owned modeled fixture field for home alias.',
    ('tests/integration/test_hierarchy_watch_bridge.py', 'test_async_consumer_followup_hash_mismatch_has_no_effect', 'namespace_getattr', 'ast-sha256:ad3890385c7584565d2e346c733d46932c8393d7ba9412aebcfb4280eba1f4af', 0):
        'Reads or invokes the selected field of the owned test/product boundary for test async consumer followup hash mismatch has no effect.',
    ('tests/integration/test_hierarchy_watch_bridge.py', 'test_supervisor_run_deadline_bounds_inflight_process.controlled_clock', 'declaration', 'nonlocal safety_expired', 0):
        'The closure records that its existing safety deadline expired.',
    ('tests/integration/test_release_workflow.py', 'smoke_failure.invoke', 'namespace_vars', 'ast-sha256:933c794a668aec33c1257967a3837b4e6e7e84ac44c179a27a316ae4d8b31af3', 0):
        'Reads vars(original_os) to copy original_os into an owned capability/AST namespace for smoke_failure.invoke; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/cli/test_doctor_fix.py', 'Env.run', 'namespace_setattr', 'ast-sha256:d346cf7083474506a60bda7db2c4e0837fe75ba7fbaa2da166186835bcc451b1', 0):
        'Populates the owned CLI argument namespace from keyword arguments.',
    ('tests/unit/cli/test_doctor_host_hooks.py', 'Env.run', 'namespace_setattr', 'ast-sha256:d346cf7083474506a60bda7db2c4e0837fe75ba7fbaa2da166186835bcc451b1', 0):
        'Populates the owned CLI argument namespace from keyword arguments.',
    ('tests/unit/cli/test_doctor_hosts.py', 'Env.run', 'namespace_setattr', 'ast-sha256:d346cf7083474506a60bda7db2c4e0837fe75ba7fbaa2da166186835bcc451b1', 0):
        'Populates the owned CLI argument namespace from keyword arguments.',
    ('tests/unit/cli/test_hook_run.py', 'test_the_cli_loads_command_parsing_only_for_shell_routes', 'namespace_generated_builtin_import', 'ast-sha256:51c6993b031ac15c1d53993a7406d4fee3def118fa764730757360438142ec12', 0):
        'Child import observer verifies command_safety loads only for shell routes. The complete generated-program construction is pinned.',
    ('tests/unit/cli/test_init.py', 'TestRuleSourceLocator.test_a_top_level_rules_package_on_sys_path_is_never_imported_or_read', 'module_write', "del sys.modules['rules']", 0):
        'Removes an adversarial rules import for the packaged-rule locator test and cleanup; no new operation is added.',
    ('tests/unit/cli/test_init.py', 'TestRuleSourceLocator.test_a_top_level_rules_package_on_sys_path_is_never_imported_or_read', 'module_write', "monkeypatch.delitem(sys.modules, 'rules', raising=False)", 0):
        'Removes an adversarial rules import for the packaged-rule locator test and cleanup; no new operation is added.',
    ('tests/unit/cli/test_init.py', 'TestRuleSourceLocator.test_a_top_level_rules_package_on_sys_path_is_never_imported_or_read', 'namespace_sys_modules', 'ast-sha256:956923e6e2af1d2a10421ea0cd1791d57e870068acf0a4585e6d84f9ebcaeb69', 0):
        'Removes an adversarial rules import for the packaged-rule locator test and cleanup; no new operation is added.',
    ('tests/unit/cli/test_init.py', 'TestRuleSourceLocator.test_a_top_level_rules_package_on_sys_path_is_never_imported_or_read', 'namespace_sys_modules', 'ast-sha256:ae5cdd232dddd03e1cfc910f8044f37d09fb90a97d4c21486b7b4a043da001b8', 0):
        'Selects the already-loaded test/product module for TestRuleSourceLocator.test a top level rules package on sys path is never imported or read.',
    ('tests/unit/cli/test_init.py', 'TestRuleSourceLocator.test_a_top_level_rules_package_on_sys_path_is_never_imported_or_read', 'namespace_sys_modules', 'ast-sha256:be92c1e9155d14486f59c55250049ccb1ddf5eb1781ca1a97a44a84973acd263', 0):
        'Removes an adversarial rules import for the packaged-rule locator test and cleanup; no new operation is added.',
    ('tests/unit/cli/test_status.py', 'TestStatus.test_status_command_contract', 'import', 'from unittest.mock import patch', 0):
        'present at tip 4959830f before RF-11b landed; added by afa773d0e3d7; Local unittest.mock.patch wraps the product status handler in its existing command contract.',
    ('tests/unit/core/test_argv_consumers.py', 'platform', 'namespace_sys_modules', 'ast-sha256:06a52c3a59ea41d716a4e2a621421c1f21bf764257a657c43f6e76aeb603ad81', 0):
        'Selects the already-loaded test/product module for platform.',
    ('tests/unit/core/test_ast_batch_m1.py', 'test_group_termination_failure_still_reaps_and_cleans_scratch.failed_close', 'declaration', 'nonlocal closed', 0):
        'The modeled kernel close fixture records closure state; module installation uses an owned dependency fixture.',
    ('tests/unit/core/test_ast_batch_m1.py', 'test_windows_close_retains_tree_ownership_after_driver_root_exits', 'module_write', 'monkeypatch.setitem(sys.modules, module.__name__, module)', 0):
        'The modeled kernel close fixture records closure state; module installation uses an owned dependency fixture.',
    ('tests/unit/core/test_ast_batch_m1.py', 'test_windows_close_retains_tree_ownership_after_driver_root_exits', 'namespace_sys_modules', 'ast-sha256:a2bca2b46ae3e4550bcbc2f7ba0324ab8b5e47ce1e726ef2b58af5dedd9cbf68', 0):
        'The modeled kernel close fixture records closure state; module installation uses an owned dependency fixture.',
    ('tests/unit/core/test_ast_windows_job.py', 'test_native_startup_failure_never_executes_driver_code', 'namespace_getattr', 'ast-sha256:70313a37e4b9d9b70f0116f6b1704045d2e5c922a7f11ca4661c58bd352ca190', 0):
        'Reads or invokes the selected field of the owned test/product boundary for test native startup failure never executes driver code.',
    ('tests/unit/core/test_benchmark_ast.py', 'test_invalid_native_js_with_valid_corpus_digest_is_a_benchmark_error', 'namespace_importlib', 'ast-sha256:b1a4d5496246e4a330a8da9d2fba1fc69888a17d8b390e223d52c24522fc38ef', 0):
        'Replaces importlib.resources.files with the owned temporary corpus to verify malformed benchmark input produces its documented error.',
    ('tests/unit/core/test_benchmark_ast.py', 'test_invalid_python_with_a_valid_digest_is_a_clear_benchmark_error', 'namespace_importlib', 'ast-sha256:b1a4d5496246e4a330a8da9d2fba1fc69888a17d8b390e223d52c24522fc38ef', 0):
        'Replaces importlib.resources.files with the owned temporary corpus to verify malformed benchmark input produces its documented error.',
    ('tests/unit/core/test_credit.py', '_ledger_reads', 'namespace_vars', 'ast-sha256:10d90a0753cc80d38265bc0e443708e2c2d32752b23a708868229bd44465893b', 0):
        'Reads vars(ledger.os) to copy ledger.os into an owned capability/AST namespace for _ledger_reads; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', '_settle_keyed_index', 'namespace_vars', 'ast-sha256:fa84b2027eb6e5fc9cbc236e584782b28fec79287280c0a73cad961f544c4cf2', 0):
        'Reads vars(module.os) to copy module.os into an owned capability/AST namespace for _settle_keyed_index; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', '_settle_keyed_index.stamps', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 0):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_credit.py', 'test_credit_memo_process_clock_cannot_certify_erased_exposure', 'namespace_vars', 'ast-sha256:367786ef78c089af9ac2096b5fba0a7d80e94438b5478f4b54ccd70f3593e2dd', 0):
        'Reads vars(os) to copy os into an owned capability/AST namespace for test_credit_memo_process_clock_cannot_certify_erased_exposure; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_credit_memo_process_clock_cannot_certify_erased_exposure.stamps', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 0):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_credit.py', 'test_delayed_fill_with_coarse_unchanged_stamps_stays_ineligible', 'namespace_vars', 'ast-sha256:0b6eb608f9bc0ede9885dacd37e06330f48c86e6f2c48f1c1e8959a6266ade73', 0):
        'Reads vars(credit_memo.os) to copy credit_memo.os into an owned capability/AST namespace for test_delayed_fill_with_coarse_unchanged_stamps_stays_ineligible; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_delayed_fill_with_coarse_unchanged_stamps_stays_ineligible.coarse', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 0):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_credit.py', 'test_delayed_fill_with_coarse_unchanged_stamps_stays_ineligible.coarse', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 1):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_credit.py', 'test_either_generation_stamp_alone_invalidates_memo', 'namespace_vars', 'ast-sha256:144edfbce1595b44fda0453bbd887f92ad8d5a4ac810e491625ca5b3df31ffcd', 0):
        'Reads vars(base) to copy base into an owned capability/AST namespace for test_either_generation_stamp_alone_invalidates_memo; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_either_generation_stamp_alone_invalidates_memo.changed', 'namespace_getattr', 'ast-sha256:fce1bef52e176555f122322e49b7a926c37c1d300175a9ea46efb127c5a3d203', 0):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_credit.py', 'test_fast_path_stat_error_falls_back_to_the_locked_read', 'namespace_vars', 'ast-sha256:1f6c0547f16a02ff28a8d9400cedd9a4b844ba4dbe8a345390b349abd1d104ad', 0):
        'Reads vars(base) to copy base into an owned capability/AST namespace for test_fast_path_stat_error_falls_back_to_the_locked_read; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_filesystem_clock_failure_reads_and_closes_all_descriptors', 'namespace_vars', 'ast-sha256:1b150754fb7f9d130d8b091b2ff80d6c5c17bb750e157c3e392fec86e1b28f32', 0):
        'Reads vars(base) to copy base into an owned capability/AST namespace for test_filesystem_clock_failure_reads_and_closes_all_descriptors; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_filesystem_clock_failure_reads_and_closes_all_descriptors.fstat', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 0):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_credit.py', 'test_filesystem_clock_never_touches_a_swapped_symlink_target', 'namespace_vars', 'ast-sha256:798199b2ae79908d86d9df3ae5491dd3effb1de2812d55ca5247fa2a94743bcc', 0):
        'Reads vars(base) to copy base into an owned capability/AST namespace for test_filesystem_clock_never_touches_a_swapped_symlink_target; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_keyed_index_reuses_only_unchanged_settled_reads', 'namespace_vars', 'ast-sha256:d4cbf377d2d395fc132ffa156ae6f5cec64da38e476fe89244161c295e6dad23', 0):
        'Reads vars(os) to copy os into an owned capability/AST namespace for test_keyed_index_reuses_only_unchanged_settled_reads; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_keyed_index_reuses_only_unchanged_settled_reads.stamps', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 0):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_credit.py', 'test_keyed_index_reuses_only_unchanged_settled_reads.stamps', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 1):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_credit.py', 'test_ledger_index_closes_opened_descriptor_on_failure', 'namespace_vars', 'ast-sha256:d63c151761f052112e64e090689e2d26de69a6970bd143d14c506e552ac1b131', 0):
        'Reads vars(atomicio) to copy atomicio into an owned capability/AST namespace for test_ledger_index_closes_opened_descriptor_on_failure; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_no_post_commit_index_read_can_turn_append_into_failure', 'namespace_vars', 'ast-sha256:304c5ec292200316c90bd4e734be75d8ffde5a7e6d29672d9613f8063cd6af55', 0):
        'Reads vars(os) to copy os into an owned capability/AST namespace for test_no_post_commit_index_read_can_turn_append_into_failure; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_parent_swap_during_cache_open_cannot_validate_the_old_ledger', 'namespace_vars', 'ast-sha256:f84654f67a5b4b85c5b192f6a371f5fe3c8b981301fcd2749219d061267c2f04', 0):
        'Reads vars(credit_memo.os) to copy credit_memo.os into an owned capability/AST namespace for test_parent_swap_during_cache_open_cannot_validate_the_old_ledger; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_portable_ancestor_substitution_misses_and_reaches_typed_refusal', 'namespace_vars', 'ast-sha256:4f3c7bdc42d6e1b444e456688c4f4ba80b9d90d8e35970a7c99bdb3d1eb7e3af', 0):
        'Reads vars(credit_memo.os) to copy credit_memo.os into an owned capability/AST namespace for test_portable_ancestor_substitution_misses_and_reaches_typed_refusal; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_portable_ancestor_substitution_misses_and_reaches_typed_refusal', 'namespace_vars', 'ast-sha256:d206ee941076b7857222bb60a8d5607be5cd47d0595b9d88a5475e997926b402', 0):
        'Reads vars(credit_memo.os) to copy credit_memo.os into an owned capability/AST namespace for test_portable_ancestor_substitution_misses_and_reaches_typed_refusal; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_post_append_stat_error_does_not_hide_a_successful_write', 'namespace_vars', 'ast-sha256:3ac170df8b77cee3670553d337c0a42956ee14e5b1184d7a4464a90274575d45', 0):
        'Reads vars(credit_memo.os) to copy credit_memo.os into an owned capability/AST namespace for test_post_append_stat_error_does_not_hide_a_successful_write; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_process_clock_ahead_of_coarse_filesystem_cannot_certify_erased_key', 'namespace_vars', 'ast-sha256:d4cbf377d2d395fc132ffa156ae6f5cec64da38e476fe89244161c295e6dad23', 0):
        'Reads vars(os) to copy os into an owned capability/AST namespace for test_process_clock_ahead_of_coarse_filesystem_cannot_certify_erased_key; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_process_clock_ahead_of_coarse_filesystem_cannot_certify_erased_key.stamps', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 0):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_credit.py', 'test_racy_timestamp_refuses_memo_until_settled', 'namespace_vars', 'ast-sha256:06207bbeb396f8818541691e209866ed9780ae1dc223a8bae7278fe193472a6d', 0):
        'Reads vars(credit_memo.os) to copy credit_memo.os into an owned capability/AST namespace for test_racy_timestamp_refuses_memo_until_settled; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_racy_timestamp_refuses_memo_until_settled.stamps', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 0):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_credit.py', 'test_rescan_checks_generation_without_reads_and_any_append_misses', 'namespace_vars', 'ast-sha256:7d0ead742e19497684e1c6baddcd413ad3f6a0a12171e6215748e491a4bf3a06', 0):
        'Reads vars(credit_memo.os) to copy credit_memo.os into an owned capability/AST namespace for test_rescan_checks_generation_without_reads_and_any_append_misses; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_rescan_checks_generation_without_reads_and_any_append_misses', 'namespace_vars', 'ast-sha256:ea3dafc05fcded2321cb376e650e0a39449fc4fad31b22efc20f74f887f9fc2c', 0):
        'Reads vars(credit_memo.os) to copy credit_memo.os into an owned capability/AST namespace for test_rescan_checks_generation_without_reads_and_any_append_misses; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_reset_before_append_report_under_clock_skew_never_fills', 'namespace_vars', 'ast-sha256:53249646b6cd9fb35ddf4f8c0caef5cdd8f525afd0423c1b0b7eeb6e5326d913', 0):
        'Reads vars(credit_memo.os) to copy credit_memo.os into an owned capability/AST namespace for test_reset_before_append_report_under_clock_skew_never_fills; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_settled_index_checks_opened_descriptor_metadata', 'namespace_vars', 'ast-sha256:6b56ca357eaf5bd015f3bc3ee16dc7e376458c36a9fa78c0acdfedb341fe5a95', 0):
        'Reads vars(base) to copy base into an owned capability/AST namespace for test_settled_index_checks_opened_descriptor_metadata; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_settled_index_checks_opened_descriptor_metadata.changed', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 0):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_credit.py', 'test_snapshot_open_error_falls_back_without_duplicating_rows', 'namespace_vars', 'ast-sha256:ea3dafc05fcded2321cb376e650e0a39449fc4fad31b22efc20f74f887f9fc2c', 0):
        'Reads vars(credit_memo.os) to copy credit_memo.os into an owned capability/AST namespace for test_snapshot_open_error_falls_back_without_duplicating_rows; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_snapshot_open_error_falls_back_without_duplicating_rows', 'namespace_vars', 'ast-sha256:f84654f67a5b4b85c5b192f6a371f5fe3c8b981301fcd2749219d061267c2f04', 0):
        'Reads vars(credit_memo.os) to copy credit_memo.os into an owned capability/AST namespace for test_snapshot_open_error_falls_back_without_duplicating_rows; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_windows_creation_time_and_descriptor_change_time_share_generation', 'namespace_vars', 'ast-sha256:6c73beb9a6e11826164ef74b53fde513dfb77de80882ae95110bac2ebd3b54e5', 0):
        'Reads vars(base) to copy base into an owned capability/AST namespace for test_windows_creation_time_and_descriptor_change_time_share_generation; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_credit.py', 'test_windows_creation_time_and_descriptor_change_time_share_generation.changed', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 0):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_f_a1_human_gate_acceptance.py', '_approve', 'namespace_setattr', 'ast-sha256:d346cf7083474506a60bda7db2c4e0837fe75ba7fbaa2da166186835bcc451b1', 0):
        'Populates the owned CLI argument namespace from keyword arguments.',
    ('tests/unit/core/test_f_a1_human_gate_acceptance.py', '_doctor_github', 'namespace_setattr', 'ast-sha256:d346cf7083474506a60bda7db2c4e0837fe75ba7fbaa2da166186835bcc451b1', 0):
        'Populates the owned CLI argument namespace from keyword arguments.',
    ('tests/unit/core/test_f_b2_credit_model_acceptance.py', 'test_every_decision_over_the_grid_is_the_one_recorded_before_the_interval_went', 'namespace_getattr', 'ast-sha256:f31e00b049e54ee53a3e21ff27d5be9e3fe9de580b73087aa77d30c62dde4ab6', 0):
        'Reads or invokes the selected field of the owned test/product boundary for test every decision over the grid is the one recorded before the interval went.',
    ('tests/unit/core/test_go_build_cache.py', 'test_child_cleanup_handles_only_a_process_that_already_exited', 'module_write', "monkeypatch.setattr(sys.modules[__name__], '_process_running', lambda pid: True)", 0):
        "Strictly replaces this test module's process-probe helper for its owned compiler-cache scenario.",
    ('tests/unit/core/test_go_build_cache.py', 'test_child_cleanup_handles_only_a_process_that_already_exited', 'namespace_sys_modules', 'ast-sha256:b1852cb3e84bb54268a2c44122cbbb974175301792d675cf215f41faaab112ab', 0):
        "Strictly replaces this test module's process-probe helper for its owned compiler-cache scenario.",
    ('tests/unit/core/test_go_build_cache.py', 'test_inspection_and_preparation_share_every_cache_key_input', 'namespace_setattr', 'ast-sha256:e61b559f4c80e8a5f3cf62e91a113bbda4f3d569effe44c60b4a0c65d6c00d83', 0):
        'Changes an owned modeled fixture field for test inspection and preparation share every cache key input.',
    ('tests/unit/core/test_go_build_cache.py', 'test_toolchain_identity_changes_the_cache_key', 'namespace_setattr', 'ast-sha256:a1efd9e87377303d786971906ca9d626068b15ca29ed563b85a8329696c56362', 0):
        'Changes an owned modeled fixture field for test toolchain identity changes the cache key.',
    ('tests/unit/core/test_insights.py', 'test_every_name_in_insights_all_is_used_outside_the_module', 'module_write', "monkeypatch.setattr(sys.modules[__name__], 'ast', counted_ast)", 0):
        "present at tip 4959830f before RF-11b landed; added by a52137cd480a; The closure counts AST parses; the strict namespace patch replaces this test module's imported ast reference only.",
    ('tests/unit/core/test_insights.py', 'test_every_name_in_insights_all_is_used_outside_the_module', 'namespace_sys_modules', 'ast-sha256:55f57bec54c9e6ba8c443baa1fbb744cc2a988330e4e361ba8aa7412af8a8352', 0):
        "present at tip 4959830f before RF-11b landed; added by a52137cd480a; The closure counts AST parses; the strict namespace patch replaces this test module's imported ast reference only.",
    ('tests/unit/core/test_insights.py', 'test_every_name_in_insights_all_is_used_outside_the_module.counted_parse', 'declaration', 'nonlocal parse_count', 0):
        "present at tip 4959830f before RF-11b landed; added by a52137cd480a; The closure counts AST parses; the strict namespace patch replaces this test module's imported ast reference only.",
    ('tests/unit/core/test_insights.py', 'test_read_link_key_closes_descriptor_when_fdopen_fails', 'namespace_vars', 'ast-sha256:bce2d3b7b4e7f0dbfe6a1c50261fb1665030a659c0cc543e86f6944c20e7eae7', 0):
        'Reads vars(os) to copy os into an owned capability/AST namespace for test_read_link_key_closes_descriptor_when_fdopen_fails; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_js_ast_driver.py', 'test_decorated_parse_token_work_is_bounded_by_source_size.CountedTokens.__getitem__', 'declaration', 'nonlocal work', 0):
        'The closure counts token work at the modeled parser boundary.',
    ('tests/unit/core/test_lane_ast.py', 'TestPytestConfigView.test_it_parses_without_tomllib', 'module_write', "monkeypatch.setitem(sys.modules, 'tomllib', None)", 0):
        'Models absent tomllib through the existing sys.modules capability fixture; pytest restores the entry.',
    ('tests/unit/core/test_lane_ast.py', 'TestPytestConfigView.test_it_parses_without_tomllib', 'namespace_sys_modules', 'ast-sha256:288dcb1fc0cf312e93f75980a8f7da2f22064ffca9b30fc94522f412fe6c6530', 0):
        'Models absent tomllib through the existing sys.modules capability fixture; pytest restores the entry.',
    ('tests/unit/core/test_language_tests.py', 'test_execution_keeps_failure_skip_no_tests_and_complete_output_errors', 'namespace_getattr', 'ast-sha256:b947f29bc900e41f31cef5ab0e92a87dd4890be9b87fd357964aa8159d440f03', 0):
        'Reads or invokes the selected field of the owned test/product boundary for test execution keeps failure skip no tests and complete output errors.',
    ('tests/unit/core/test_language_tests.py', 'test_windows_junction_lifecycle_preserves_targets_and_detects_retargeting', 'namespace_vars', 'ast-sha256:44a406157caea68b70bd39adc207f5fe28be746c53d5386034ba8d5d2e7c22ef', 0):
        'Reads vars(os) to copy os into an owned capability/AST namespace for test_windows_junction_lifecycle_preserves_targets_and_detects_retargeting; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_language_tests.py', 'test_windows_snapshot_dependencies_use_junction_when_symlink_privilege_is_absent', 'namespace_vars', 'ast-sha256:44a406157caea68b70bd39adc207f5fe28be746c53d5386034ba8d5d2e7c22ef', 0):
        'Reads vars(os) to copy os into an owned capability/AST namespace for test_windows_snapshot_dependencies_use_junction_when_symlink_privilege_is_absent; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_layout.py', 'test_this_repository_never_tracks_machine_local_state', 'import', 'import pytest', 0):
        'Local pytest import supplies the existing optional-checkout skip gate; it does not supply a patch object.',
    ('tests/unit/core/test_lifecycle_write_safety.py', '<module>', 'namespace_builtin_import', 'ast-sha256:d002c54b6d6b883775198058c993778d98a248c17682e08aeb910cbe9e59ce1b', 0):
        'Acquires builtins for lifecycle write interception and refusal controls.',
    ('tests/unit/core/test_message_codec.py', 'test_class_b_entry_operations_use_anchored_directory', 'namespace_getattr', 'ast-sha256:87e508d97d2c8fc85046dffccae5940311e5d7f32027dbbd86134215351595e9', 0):
        'Invokes the parameterized store public operation to check fixed refusals, anchoring or closure behavior.',
    ('tests/unit/core/test_message_codec.py', 'test_coord1_argon1_unchanged_stamp_never_bypasses_verification.<lambda>', 'namespace_getattr', 'ast-sha256:bd0042ae4525cf78d46c07933d76c5fef9b1451c3b60aef79bebe9f1c1a2924c', 0):
        'Invokes the parameterized store public operation to check fixed refusals, anchoring or closure behavior.',
    ('tests/unit/core/test_message_codec.py', 'test_coord3_store_replaced_during_successful_operation_refuses.<lambda>', 'namespace_getattr', 'ast-sha256:17a7bcea0c4fcabd60fdb12c1a640faa42ee47cbeb4c7f309f3221172b62f61c', 0):
        'Invokes the parameterized store public operation to check fixed refusals, anchoring or closure behavior.',
    ('tests/unit/core/test_message_codec.py', 'test_coord5_malformed_handles_have_fixed_grammar_hint.<lambda>', 'namespace_getattr', 'ast-sha256:913302d49071dd24706295d854101ae60ec33a7c44900133c0068655d7534bfc', 0):
        'Invokes the parameterized store public operation to check fixed refusals, anchoring or closure behavior.',
    ('tests/unit/core/test_message_codec.py', 'test_r10_close_release_error_invalidates_before_fd_reuse', 'namespace_getattr', 'ast-sha256:9c879ccc54a542cbc53844b45f63594e4b4b6d6518db2383d43460d0b55f9536', 0):
        'Reads the existing OS capability to delegate or wrap it in the owned boundary fixture.',
    ('tests/unit/core/test_message_codec.py', 'test_r10_close_release_error_invalidates_before_fd_reuse.<lambda>', 'namespace_getattr', 'ast-sha256:e16dc346147774eeb356b82e88a72cd86435384f64d9ce38bc7c5fb64794a1a2', 0):
        'Invokes the parameterized store public operation to check fixed refusals, anchoring or closure behavior.',
    ('tests/unit/core/test_message_codec.py', 'test_r3_class_a_public_entry_points_are_total', 'namespace_getattr', 'ast-sha256:d69b158c8e0469feb608d3b69fa42cb62bcfb11e025023a2414bc0988fd72a06', 0):
        'Invokes the parameterized store public operation to check fixed refusals, anchoring or closure behavior.',
    ('tests/unit/core/test_message_codec.py', 'test_r7_class_d_verified_bytes_must_equal_stat_size.scheduled', 'namespace_getattr', 'ast-sha256:9d6940f87f1cb333a44f4f0f48ab3efe156748ec05ab0d584ad6d587e36cbd8f', 0):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_message_codec.py', 'test_r8_class_f_disappearance_and_operational_errors_are_distinct.<lambda>', 'namespace_getattr', 'ast-sha256:0dbe49b137e1806ef65336985fe9e3a5ee1e943739e54c652c35734786f67d17', 0):
        'Invokes the parameterized store public operation to check fixed refusals, anchoring or closure behavior.',
    ('tests/unit/core/test_message_codec.py', 'test_r9_class_a_close_waits_for_operation_and_closed_store_refuses', 'namespace_getattr', 'ast-sha256:9c879ccc54a542cbc53844b45f63594e4b4b6d6518db2383d43460d0b55f9536', 0):
        'Reads the existing OS capability to delegate or wrap it in the owned boundary fixture.',
    ('tests/unit/core/test_message_codec.py', 'test_r9_class_a_close_waits_for_operation_and_closed_store_refuses.<lambda>', 'namespace_getattr', 'ast-sha256:e16dc346147774eeb356b82e88a72cd86435384f64d9ce38bc7c5fb64794a1a2', 0):
        'Invokes the parameterized store public operation to check fixed refusals, anchoring or closure behavior.',
    ('tests/unit/core/test_message_codec.py', 'test_store_requires_anchored_leaf_stat_capabilities', 'namespace_getattr', 'ast-sha256:904f60ec69746332ee0e87be4de38a2b1ac18f37f7e94ce237cb065f797610f5', 0):
        'Reads the existing OS capability to delegate or wrap it in the owned boundary fixture.',
    ('tests/unit/core/test_packs.py', 'test_the_import_result_carries_no_text_a_pack_chose_beyond_ids_and_paths', 'namespace_vars', 'ast-sha256:f0fd3c54e18c490d5813a6cf8b0fa66c1acab3393a94ad0bf72a35818d1d848b', 0):
        'Read-only enumeration verifies the imported pack result carries exactly the permitted metadata fields, without attacker-chosen text.',
    ('tests/unit/core/test_polyglot_recipes.py', 'TestMutationPointApplication.test_apply_mutation_point_byte_offset', 'namespace___setattr__', 'ast-sha256:454e0562430769459e3a2a5bed86b631fd6449d34226ff9c258ebab6c6ed4a6a', 0):
        "Sets a compatibility field on an owned frozen MutationPoint test instance (object.__setattr__(point, 'byte_offset', idx)); exercises byte offsets, operator aliases or scope filtering.",
    ('tests/unit/core/test_polyglot_recipes.py', 'TestMutationPointApplication.test_collect_mutations_from_ast_filtering', 'namespace___setattr__', 'ast-sha256:306fd321af3f39c2f565c37b2996dbc8b00528e2a1f52af7cc3fc88a3b0235c7', 0):
        "Sets a compatibility field on an owned frozen MutationPoint test instance (object.__setattr__(p2, 'function_scope', 'fnB')); exercises byte offsets, operator aliases or scope filtering.",
    ('tests/unit/core/test_polyglot_recipes.py', 'TestMutationPointApplication.test_collect_mutations_from_ast_filtering', 'namespace___setattr__', 'ast-sha256:f3d2a01bb2912af74292c71e4ab98a108b5dcb9316058a83c461ab5cc128dba5', 0):
        "Sets a compatibility field on an owned frozen MutationPoint test instance (object.__setattr__(p2, 'function_scope', 'fnB')); exercises byte offsets, operator aliases or scope filtering.",
    ('tests/unit/core/test_redaction.py', 'test_no_module_imports_a_private_name_of_redaction', 'module_write', "monkeypatch.setattr(sys.modules[__name__], 'ast', counted_ast)", 0):
        "The closure counts AST parses; the strict namespace patch replaces this test module's imported ast reference only.",
    ('tests/unit/core/test_redaction.py', 'test_no_module_imports_a_private_name_of_redaction', 'namespace_sys_modules', 'ast-sha256:55f57bec54c9e6ba8c443baa1fbb744cc2a988330e4e361ba8aa7412af8a8352', 0):
        "The closure counts AST parses; the strict namespace patch replaces this test module's imported ast reference only.",
    ('tests/unit/core/test_redaction.py', 'test_no_module_imports_a_private_name_of_redaction.counted_parse', 'declaration', 'nonlocal parse_count', 0):
        "The closure counts AST parses; the strict namespace patch replaces this test module's imported ast reference only.",
    ('tests/unit/core/test_rules.py', 'test_an_io_failure_after_a_warm_cache_raises_instead_of_serving_stale_rules', 'namespace_getattr', 'ast-sha256:c26a1a44de78ea3ef25565887493cfcdd8dd5439d18b025f4bac3483183a42b5', 0):
        'Reads the existing OS capability to delegate or wrap it in the owned boundary fixture.',
    ('tests/unit/core/test_rust_native_driver.py', 'test_distinct_attribute_membership_work_is_linear.CountedDecorators.__contains__', 'declaration', 'nonlocal work', 0):
        'The closure counts token work at the modeled parser boundary.',
    ('tests/unit/core/test_scaffolding.py', 'TestInitWorkflowRecognition.test_an_unreadable_workflow_is_not_reported_as_running_check', 'namespace_builtin_import', 'ast-sha256:d002c54b6d6b883775198058c993778d98a248c17682e08aeb910cbe9e59ce1b', 0):
        'Acquires builtins to model unreadable workflow files during init recognition.',
    ('tests/unit/core/test_scan_ledger_reads.py', 'test_an_mcp_scan_reads_the_ledger_at_most_twice_and_once_when_its_exposures_are_kept', 'namespace_vars', 'ast-sha256:5f718571bbf269f09c667f05a10b30fe7185fb7a7334bbf2cf9ab3838ad909a1', 0):
        'Reads vars(module.os) to copy module.os into an owned capability/AST namespace for test_an_mcp_scan_reads_the_ledger_at_most_twice_and_once_when_its_exposures_are_kept; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_scan_ledger_reads.py', 'test_an_mcp_scan_reads_the_ledger_at_most_twice_and_once_when_its_exposures_are_kept.settled_generation', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 0):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_scan_spawn_budget.py', 'test_an_mcp_scan_counts_index_reads_and_memo_validation', 'namespace_vars', 'ast-sha256:8ab45cd5e7b88cb70f8b7cab9e5d99feaeb3c934cd46b8a7c46bdaaf81360435', 0):
        'Reads vars(io) to copy io into an owned capability/AST namespace for test_an_mcp_scan_counts_index_reads_and_memo_validation; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_scan_spawn_budget.py', 'test_an_mcp_scan_counts_index_reads_and_memo_validation', 'namespace_vars', 'ast-sha256:d62d0f4e63fdb238bd3d911621ee2dec27c20dbee9ad866121e4ae5f43238c8a', 0):
        'Reads vars(io) to copy io into an owned capability/AST namespace for test_an_mcp_scan_counts_index_reads_and_memo_validation; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_scan_spawn_budget.py', 'test_an_mcp_scan_counts_index_reads_and_memo_validation.reported', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 0):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_storage.py', 'test_append_jsonl_missing_optional_evidence_still_succeeds', 'namespace_vars', 'ast-sha256:18e885cc94f5b9c093a4b1d52e75d29d0c5f3ab56e12db57e4304730f3237c70', 0):
        'Reads vars(os) to copy os into an owned capability/AST namespace for test_append_jsonl_missing_optional_evidence_still_succeeds; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_storage.py', 'test_atomic_write_gives_up_after_eight_attempts.always_locked', 'declaration', 'nonlocal attempts', 0):
        'The closure counts the existing modeled sharing-violation retries.',
    ('tests/unit/core/test_storage.py', 'test_atomic_write_retries_windows_sharing_violation.flaky_replace', 'declaration', 'nonlocal attempts', 0):
        'The closure counts the existing modeled sharing-violation retries.',
    ('tests/unit/core/test_storage.py', 'test_jsonl_reports_generation_without_process_clock_or_extra_append_reads', 'namespace_vars', 'ast-sha256:fd33beaf768243df1e5d5068c03578caaeb76404626c2db0150130aff9de566b', 0):
        'Reads vars(os) to copy os into an owned capability/AST namespace for test_jsonl_reports_generation_without_process_clock_or_extra_append_reads; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_storage.py', 'test_jsonl_reports_the_descriptor_identity_and_end_offset', 'namespace_vars', 'ast-sha256:0b9f43b955af60bd055947ddde98ab18305cfdd6ae2b81bd6d51a9217ac7015c', 0):
        'Reads vars(os) to copy os into an owned capability/AST namespace for test_jsonl_reports_the_descriptor_identity_and_end_offset; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_storage.py', 'test_read_jsonl_closes_descriptor_when_fdopen_fails', 'namespace_vars', 'ast-sha256:0ec74774719dcec6ca69ab3256d2158e86a47379cbb259ca63eca35d42fe8bab', 0):
        'Reads vars(os) to copy os into an owned capability/AST namespace for test_read_jsonl_closes_descriptor_when_fdopen_fails; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/core/test_storage_ratchets.py', 'test_aliases_and_noncall_os_references_are_refused', 'module_write', "monkeypatch.setattr(sys.modules[__name__], '_sources', lambda: [('aegis_core/probe.py', tree)])", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_aliases_and_noncall_os_references_are_refused', 'namespace_sys_modules', 'ast-sha256:ae11351e0f70fe9e47e03fe91a5280362d400df088e25b8af979110e4829dae6', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_bare_os_loads_are_allowlisted', 'module_write', "monkeypatch.setattr(sys.modules[__name__], '_sources', lambda: [('aegis_core/probe.py', ast.parse(source))])", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_bare_os_loads_are_allowlisted', 'namespace_sys_modules', 'ast-sha256:03081a8c4e3ecf983007b257eb640387349e87f886f61e72608addf787b0d87b', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_callback_exception_preserves_the_operation_ceiling', 'module_write', "monkeypatch.setattr(sys.modules[__name__], 'REVIEWED_DESCRIPTOR_OPERATIONS', reviewed)", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_callback_exception_preserves_the_operation_ceiling', 'namespace_sys_modules', 'ast-sha256:a4573b8e2d83ea4ed3566783ff78271253f4b4d47b9930ba11440c3861f42b8a', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_callback_exceptions_refuse_other_sites_callees_and_counts', 'module_write', "monkeypatch.setattr(sys.modules[__name__], '_sources', lambda: [(rel, ast.parse(source))])", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_callback_exceptions_refuse_other_sites_callees_and_counts', 'namespace_sys_modules', 'ast-sha256:3c7446af0b090cc614e46ad391a21f605cdd5d1be736b502c4e674bbe2f34dae', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_declared_opener_noncall_loads_are_refused', 'module_write', "monkeypatch.setattr(sys.modules[__name__], '_sources', lambda: [('aegis_core/probe.py', ast.parse(source))])", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_declared_opener_noncall_loads_are_refused', 'namespace_sys_modules', 'ast-sha256:03081a8c4e3ecf983007b257eb640387349e87f886f61e72608addf787b0d87b', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_descriptor_cannot_mask_a_stale_string_mode_exemption', 'namespace_sys_modules', 'ast-sha256:6543e6f57888b40538f7ee779630af6aba4ce37b6530e280beb1fc47e393f587', 0):
        'Selects the already-loaded test/product module for test descriptor cannot mask a stale string mode exemption.',
    ('tests/unit/core/test_storage_ratchets.py', 'test_expanded_flags_require_the_undeclared_forwarder_diagnostic', 'module_write', "monkeypatch.setattr(sys.modules[__name__], '_sources', lambda: iter(sources))", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_expanded_flags_require_the_undeclared_forwarder_diagnostic', 'namespace_sys_modules', 'ast-sha256:5de4912f686ebec31dce88e19012059fb547347bfe6f86e80f950ccc52c76de5', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_flags_through_declared_openers_discover_new_forwarders', 'module_write', "monkeypatch.setattr(sys.modules[__name__], '_sources', lambda: iter(sources))", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_flags_through_declared_openers_discover_new_forwarders', 'namespace_sys_modules', 'ast-sha256:5de4912f686ebec31dce88e19012059fb547347bfe6f86e80f950ccc52c76de5', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_forwarding_reexports_and_callbacks_cannot_hide_calls', 'module_write', "monkeypatch.setattr(sys.modules[__name__], '_sources', lambda: iter(sources))", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_forwarding_reexports_and_callbacks_cannot_hide_calls', 'namespace_sys_modules', 'ast-sha256:5de4912f686ebec31dce88e19012059fb547347bfe6f86e80f950ccc52c76de5', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_missing_and_unregistered_capability_probes_are_refused', 'namespace_sys_modules', 'ast-sha256:6543e6f57888b40538f7ee779630af6aba4ce37b6530e280beb1fc47e393f587', 0):
        'Selects the already-loaded test/product module for test missing and unregistered capability probes are refused.',
    ('tests/unit/core/test_storage_ratchets.py', 'test_nested_argon_operation_loads_are_refused_inside_reviewed_scope', 'module_write', "monkeypatch.setattr(sys.modules[__name__], '_sources', lambda: [('aegis_core/model_select.py', ast.parse(source))])", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_nested_argon_operation_loads_are_refused_inside_reviewed_scope', 'namespace_sys_modules', 'ast-sha256:0ba37c628a11231210c42f0c3ee7f98bed0c52f3ae82d091c16ac7d2d5d379ba', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_new_forwarding_opener_call_is_refused', 'module_write', "monkeypatch.setattr(sys.modules[__name__], '_sources', lambda: [('aegis_core/probe.py', ast.parse(source))])", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_new_forwarding_opener_call_is_refused', 'namespace_sys_modules', 'ast-sha256:03081a8c4e3ecf983007b257eb640387349e87f886f61e72608addf787b0d87b', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_new_store_method_calling_forwarding_opener_is_refused', 'module_write', "monkeypatch.setattr(sys.modules[__name__], '_sources', lambda: [('aegis_core/message_codec_store.py', ast.parse(source))])", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_new_store_method_calling_forwarding_opener_is_refused', 'namespace_sys_modules', 'ast-sha256:a4356d52f71a5865c4fc249b87f1ab2a8d5b977572c55fc0cfa39c93235359f6', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_only_direct_comparison_operands_are_exempt', 'module_write', "monkeypatch.setattr(sys.modules[__name__], '_sources', lambda: [('aegis_core/probe.py', ast.parse(source))])", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_only_direct_comparison_operands_are_exempt', 'namespace_sys_modules', 'ast-sha256:03081a8c4e3ecf983007b257eb640387349e87f886f61e72608addf787b0d87b', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_removed_declared_forwarding_opener_is_refused', 'module_write', "monkeypatch.setattr(sys.modules[__name__], '_sources', lambda: iter(sources))", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_removed_declared_forwarding_opener_is_refused', 'namespace_sys_modules', 'ast-sha256:5de4912f686ebec31dce88e19012059fb547347bfe6f86e80f950ccc52c76de5', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_reviewed_unread_opener_cannot_hide_expanded_flags', 'module_write', "monkeypatch.setattr(sys.modules[__name__], '_sources', lambda: iter(sources))", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_reviewed_unread_opener_cannot_hide_expanded_flags', 'namespace_sys_modules', 'ast-sha256:5de4912f686ebec31dce88e19012059fb547347bfe6f86e80f950ccc52c76de5', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_stale_capability_registration_is_refused', 'module_write', "monkeypatch.setattr(sys.modules[__name__], 'CAPABILITY_REFERENCES', registered)", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_stale_capability_registration_is_refused', 'namespace_sys_modules', 'ast-sha256:0a79ebdcbd75b0b9744ecc6c13d79b7acda72807b5cbc6bc19927d3d66ac7f25', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_storage_ratchet_refuses_descriptor_growth_even_in_allowlisted_scope', 'module_write', "monkeypatch.setattr(sys.modules[__name__], '_sources', lambda: [(rel, tree)])", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_storage_ratchet_refuses_descriptor_growth_even_in_allowlisted_scope', 'namespace_sys_modules', 'ast-sha256:eb869fe32c1993d6c29f0a4c92db4c0eb5e9ad680e923941f6972eb367a9c043', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_undeclared_forwarding_opener_is_refused', 'module_write', "monkeypatch.setattr(sys.modules[__name__], '_sources', lambda: [('aegis_core/probe.py', ast.parse(source))])", 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_storage_ratchets.py', 'test_undeclared_forwarding_opener_is_refused', 'namespace_sys_modules', 'ast-sha256:03081a8c4e3ecf983007b257eb640387349e87f886f61e72608addf787b0d87b', 0):
        "Strictly replaces this test module's source/capability fixture for its existing storage-ratchet controls.",
    ('tests/unit/core/test_team.py', 'test_parse_lease_accepts_its_boundaries', 'namespace_getattr', 'ast-sha256:d3835e18dfbf5b13da3536e44e7e8c5866b51eb061aa966e35b4ef61582e3eae', 0):
        'Reads or invokes the selected field of the owned test/product boundary for test parse lease accepts its boundaries.',
    ('tests/unit/core/test_team_profile.py', 'test_descriptor_cleanup_on_failures.ModuleOS.__getattr__', 'namespace_getattr', 'ast-sha256:b6f61ddce5d27645ea61615d3aefd4cf77ff281875e65d8354351220e3a10d0d', 0):
        'Reads the existing OS capability to delegate or wrap it in the owned boundary fixture.',
    ('tests/unit/core/test_team_profile.py', 'test_rename_symlink_race_stays_anchored.ModuleOS.__getattr__', 'namespace_getattr', 'ast-sha256:b6f61ddce5d27645ea61615d3aefd4cf77ff281875e65d8354351220e3a10d0d', 0):
        'Reads the existing OS capability to delegate or wrap it in the owned boundary fixture.',
    ('tests/unit/core/test_team_profile.py', 'test_stow_directory_requires_owner_and_private_write_access.ModuleOS.__getattr__', 'namespace_getattr', 'ast-sha256:b6f61ddce5d27645ea61615d3aefd4cf77ff281875e65d8354351220e3a10d0d', 0):
        'Reads the existing OS capability to delegate or wrap it in the owned boundary fixture.',
    ('tests/unit/core/test_team_profile.py', 'test_user_alias_read_remains_anchored_during_rename.ModuleOS.__getattr__', 'namespace_getattr', 'ast-sha256:b6f61ddce5d27645ea61615d3aefd4cf77ff281875e65d8354351220e3a10d0d', 0):
        'Reads the existing OS capability to delegate or wrap it in the owned boundary fixture.',
    ('tests/unit/core/test_test_outcomes.py', 'test_junit_bad_reports_and_collection_errors_never_supply_evidence', 'namespace_getattr', 'ast-sha256:70356be2703cf30697de176ab630147c808ce0a74a7094179c8f13de61ab37c3', 0):
        'Reads or invokes the selected field of the owned test/product boundary for test junit bad reports and collection errors never supply evidence.',
    ('tests/unit/core/test_verified_checks_units.py', 'test_approve_reads_the_key_from_the_user_config_and_signs_in_the_repository_asked_about', 'namespace_builtin_import', 'ast-sha256:d002c54b6d6b883775198058c993778d98a248c17682e08aeb910cbe9e59ce1b', 0):
        'Acquires builtins to observe reading the user signing key for repository-scoped approval.',
    ('tests/unit/core/test_windows_junction.py', 'junction_kernel.lstat', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 0):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_windows_junction.py', 'junction_kernel.lstat', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 1):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/core/test_windows_junction.py', 'test_identity_fixture_models_python_widths_when_host_identifiers_are_wide.wide_host_lstat', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 0):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/mcp/test_mcp_msg.py', 'test_message_write_fsyncs_state_only_when_preparing_ignore', 'namespace_vars', 'ast-sha256:1d2c7941b7641d49f7b9833e2f25b717a39e1d38d2c2e967b9be1af4ed333069', 0):
        'Reads vars(real_os) to copy real_os into an owned capability/AST namespace for test_message_write_fsyncs_state_only_when_preparing_ignore; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/mcp/test_mcp_msg.py', 'test_operational_refusals_match_cli', 'namespace_vars', 'ast-sha256:732a960b4b89b9216838a64a2104519faf7cef4750764443d30f0cc49c520d61', 0):
        'Reads vars(storage.os) to copy storage.os into an owned capability/AST namespace for test_operational_refusals_match_cli; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/mcp/test_mcp_msg.py', 'test_write_uses_the_mutation_rate_limit', 'namespace_vars', 'ast-sha256:e69244c81ef1878d023a2b807e7c1e3a20076cbbf5ce74934e4d05a8e4f3dc65', 0):
        'Reads vars(server.time) to copy server.time into an owned capability/AST namespace for test_write_uses_the_mutation_rate_limit; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/test_p6_noadmin.py', 'python39_junction.install.junction_lstat', 'namespace_getattr', 'ast-sha256:394ecc47e02e444b4cad3d067d920f6f5d41eb204ae46a01bdf22fb32f0c7b8c', 0):
        'Copies stat-result fields into an owned metadata fixture for timestamp/descriptor failure controls.',
    ('tests/unit/test_p6_noadmin.py', 'run_worker', 'namespace_vars', 'ast-sha256:200920d371e97dd00845751fbbcd461018bcae0d6e94e413f62eaa008ef28049', 0):
        'Reads vars(sys) to copy sys into an owned capability/AST namespace for run_worker; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/verification/test_import_guard.py', 'TestImportExtraction.test_membership_work_is_linear.CountedImportInfo.__getattribute__', 'declaration', 'nonlocal inspections', 0):
        'The closure counts ImportInfo inspections for the existing linear-work assertion.',
    ('tests/unit/verification/test_import_guard.py', 'TestImportExtraction.test_membership_work_is_linear.CountedImportInfo.__getattribute__', 'namespace___getattribute__', 'ast-sha256:bb7544e7c9f49d2d135dd7a049a8b06b82249639a9631ae95d908da185547f65', 0):
        'CountedImportInfo delegates an instance attribute read to super while counting module-field inspections for the linear-work assertion.',
    ('tests/unit/verification/test_import_guard.py', 'discovery_fs', 'namespace_getattr', 'ast-sha256:c6d6118bdac04134ae2a5ef925f3e134f59b1cb2a87139b56b972f4b784ce6f0', 0):
        'Reads the existing OS capability to delegate or wrap it in the owned boundary fixture.',
    ('tests/unit/verification/test_import_guard.py', 'discovery_fs.probe.counted', 'namespace_getattr', 'ast-sha256:b7246a7b70c206032e7181c30f54bcfde8fb5adc90e903b15b055a6debc05043', 0):
        'Reads the existing OS capability to delegate or wrap it in the owned boundary fixture.',
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_each_selection_keeps_its_ceiling_before_aggregation', 'namespace_vars', 'ast-sha256:7133505cc0fb61c87f224c4394f6d148a42fd340b711fb98e5d3311a2edb236c', 0):
        'present at tip b11638bf before RF-11b landed; RF-89 e328b74a; Reads vars(mutation_tester.subprocess) to copy the consumer subprocess/Git API into an owned refusal fixture; the original namespace is preserved.',
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_invalid_test_paths_are_refused_before_spawn', 'namespace_vars', 'ast-sha256:7133505cc0fb61c87f224c4394f6d148a42fd340b711fb98e5d3311a2edb236c', 0):
        'present at tip b11638bf before RF-11b landed; RF-89 e328b74a; Reads vars(mutation_tester.subprocess) to copy the consumer subprocess/Git API into an owned refusal fixture; the original namespace is preserved.',
    ('tests/unit/verification/test_mutation_tester.py', 'TestPolyglotMutationTesterCoverage.test_apply_mutation_point_coverage', 'namespace___setattr__', 'ast-sha256:1e50fd70ca75310e111459f1becfc5723e51687f063fbb32135054dafd86fa12', 0):
        "Sets a compatibility field on an owned frozen MutationPoint test instance (object.__setattr__(pt_col, 'column', 2)); exercises byte offsets, operator aliases or scope filtering.",
    ('tests/unit/verification/test_mutation_tester.py', 'TestPolyglotMutationTesterCoverage.test_apply_mutation_point_coverage', 'namespace___setattr__', 'ast-sha256:3c7f3c942defaaf424fafc12c418ec3138a38ab4c058846e8123b8d4fbde3b2d', 0):
        "Sets a compatibility field on an owned frozen MutationPoint test instance (object.__setattr__(pt_col, 'column', 2)); exercises byte offsets, operator aliases or scope filtering.",
    ('tests/unit/verification/test_mutation_tester.py', 'TestPolyglotMutationTesterCoverage.test_apply_mutation_point_coverage', 'namespace___setattr__', 'ast-sha256:60b7cd3034f6263e1116795359f35a31c47567d6243d165f12e0f12d3f089923', 0):
        "Sets a compatibility field on an owned frozen MutationPoint test instance (object.__setattr__(pt_col, 'column', 2)); exercises byte offsets, operator aliases or scope filtering.",
    ('tests/unit/verification/test_mutation_tester.py', 'TestPolyglotMutationTesterCoverage.test_apply_mutation_point_coverage', 'namespace___setattr__', 'ast-sha256:89871e81d9f863df3fb153da1dbe56dc25948835d67762e2d892417b2cf37377', 0):
        "Sets a compatibility field on an owned frozen MutationPoint test instance (object.__setattr__(pt_col, 'column', 2)); exercises byte offsets, operator aliases or scope filtering.",
    ('tests/unit/verification/test_mutation_tester.py', 'TestPolyglotMutationTesterCoverage.test_apply_mutation_point_coverage', 'namespace___setattr__', 'ast-sha256:8c50aaeeb3a28294c5eb98bccba443ed777bc565c2b9d0fe3eaabfe502a0bd38', 0):
        "Sets a compatibility field on an owned frozen MutationPoint test instance (object.__setattr__(pt_col, 'column', 2)); exercises byte offsets, operator aliases or scope filtering.",
    ('tests/unit/verification/test_mutation_tester.py', 'TestPolyglotMutationTesterCoverage.test_apply_mutation_point_coverage', 'namespace___setattr__', 'ast-sha256:eae8ebfb69ba75a858f86ec915947d6b92b0a554c1814deb805b5a9b8e1b4c4f', 0):
        "Sets a compatibility field on an owned frozen MutationPoint test instance (object.__setattr__(pt_col, 'column', 2)); exercises byte offsets, operator aliases or scope filtering.",
    ('tests/unit/verification/test_mutation_tester.py', 'TestPolyglotMutationTesterCoverage.test_collect_mutations_from_ast_coverage', 'namespace___setattr__', 'ast-sha256:39436ea66a0265c3ff658cb4fb86e1e1272b6c7fb3f15e69be377d1202bc3e4a', 0):
        "Sets a compatibility field on an owned frozen MutationPoint test instance (object.__setattr__(p1, 'function_scope', 'foo')); exercises byte offsets, operator aliases or scope filtering.",
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_falls_back_to_sys_executable', 'namespace_importlib', 'ast-sha256:c4eea2657be21c300315044bd0d7a2a10faaa9d6cac623b2156fb41733214a06', 0):
        'Models presence/absence of the installed pytest module spec to verify executable fallback, optional no-runner and required no-runner outcomes.',
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_raises_when_no_runner_and_required', 'namespace_importlib', 'ast-sha256:f669282885f49c8e0de801a6ef65fd697173db32d8aaa0ea595c13470f956b40', 0):
        'Models presence/absence of the installed pytest module spec to verify executable fallback, optional no-runner and required no-runner outcomes.',
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_returns_empty_when_no_runner_and_not_required', 'namespace_importlib', 'ast-sha256:8647cbd236f343d575d3a04a96d63b7a945503d59344c1cab9e03b91b3ded259', 0):
        'Models presence/absence of the installed pytest module spec to verify executable fallback, optional no-runner and required no-runner outcomes.',
    ('tests/unit/verification/test_scanners.py', 'artifact_reads', 'namespace_vars', 'ast-sha256:93cb4b2cf140ffd0e8651879a368f9d227e33f55b7e2b24b5c580f5fb714c448', 0):
        'Reads vars(os) to copy os into an owned capability/AST namespace for artifact_reads; overrides are installed on the copy rather than the original namespace.',
    ('tests/unit/verification/test_scanners.py', 'descriptor_count', 'namespace_vars', 'ast-sha256:7753147a4a668b8a91f3b2cdb69544cb32cd1138f1fee1be01a8d8d866faf689', 0):
        'Reads vars(os) to copy os into an owned capability/AST namespace for descriptor_count; overrides are installed on the copy rather than the original namespace.',
}
BAN_LIMITS = {'constructor': 0, 'constructor_reference': 1, 'declaration': 20, 'import': 3, 'module_write': 39, 'namespace___class__': 3, 'namespace___delattr__': 0, 'namespace___dict__': 17, 'namespace___getattribute__': 1, 'namespace___setattr__': 10, 'namespace_builtin_import': 12, 'namespace_delattr': 0, 'namespace_generated_builtin_import': 5, 'namespace_getattr': 118, 'namespace_globals': 5, 'namespace_importlib': 5, 'namespace_locals': 0, 'namespace_setattr': 9, 'namespace_sys_modules': 51, 'namespace_vars': 59}

# Formal 0715 example disposition (dynamic examples intentionally unasserted):
# security 1 / correctness 2: global/nonlocal import/from-import rebindings,
# direct patch/.object/.dict/.multiple and reflective extraction -> bans 1a/1b.
# security 2: sys.modules[...].__name__ assignment, __dict__/globals()/vars()
# item writes and module attribute deletion -> ban 1d, before patch recognition.
# correctness 1: helper(pytest.MonkeyPatch(), selector), literal constructors
# returned from factories or placed in containers, computed/conditional selectors,
# getattr aliases and setter/deletion/item methods -> ban 1c at the constructor.
# Round 12 / ARG-1021 widens 1c to non-annotation class references, and 1d
# to namespace builtin references and sensitive attributes on any receiver.
# Intentionally unasserted here, delegated to RF-11c: a factory's dynamically
# acquired patcher returned or put in a container, a patcher/module acquired via
# importlib.import_module/__import__/eval/exec, and reflective computed/conditional
# selectors or getattr aliases on arbitrary helper parameters whose runtime
# patcher identity comes from those sources. No data-flow completeness is claimed.
# Examples intentionally unasserted: helper(factory(), method), [factory()],
# return factory(), getattr(patcher, "set" + "attr")(...), and
# lookup(patcher, "setattr" if condition else "delattr")(...).


def _inert_type(node):
    """An allowlist of inert annotation syntax; every other AST shape refuses."""
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Attribute):
        return isinstance(node.value, (ast.Name, ast.Attribute)) and _inert_type(node.value)
    if isinstance(node, ast.Subscript):
        return (isinstance(node.value, (ast.Name, ast.Attribute, ast.Subscript))
                and _inert_type(node.value) and _inert_type(node.slice))
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str) or node.value is None or node.value is Ellipsis
    if isinstance(node, ast.BinOp):
        return isinstance(node.op, ast.BitOr) and _inert_type(node.left) and _inert_type(node.right)
    if isinstance(node, (ast.Tuple, ast.List)):
        return all(_inert_type(child) for child in node.elts)
    return False


def _complete_operation(node, parents):
    """Pin the outer expression, including a simple statement's write/value."""
    while id(node) in parents and not isinstance(parents[id(node)], ast.stmt):
        parent = parents[id(node)]
        if isinstance(parent, (ast.Module, ast.arguments)):
            break
        node = parent
    parent = parents.get(id(node))
    if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete,
                           ast.Return, ast.Raise, ast.Assert, ast.For, ast.AsyncFor, ast.With, ast.AsyncWith)):
        node = parent
    return node.value if isinstance(node, ast.Expr) else node


def _seam_copy(reference, parents, names):
    if not isinstance(reference, (ast.Name, ast.Attribute)):
        return False
    call = parents.get(id(reference))
    if not (isinstance(call, ast.Call) and call.func is reference
            and len(call.args) == 1 and not call.keywords):
        return False
    if names.possible(reference) != {"builtins.vars"}:
        if not isinstance(reference, ast.Name) or reference.id != "vars":
            return False
        scope = names.at[id(reference)]
        while scope is not None:
            if "vars" in scope.bound:
                return False
            scope = scope.parent
    display = parents.get(id(call))
    if not (isinstance(display, ast.Dict) and display.keys.count(None) == 1
            and any(key is None and value is call for key, value in zip(display.keys, display.values))
            and all(key is None or isinstance(key, ast.Constant) and isinstance(key.value, str)
                    for key in display.keys)):
        return False
    keyword = parents.get(id(display))
    constructor = parents.get(id(keyword))
    if not (isinstance(keyword, ast.keyword) and keyword.arg is None
            and isinstance(constructor, ast.Call) and constructor.keywords == [keyword]
            and not constructor.args and isinstance(constructor.func, (ast.Name, ast.Attribute))):
        return False
    return names.possible(constructor.func) == {"types.SimpleNamespace"}


# Existing generated-code boundaries; ordinary literals elsewhere remain data.
GENERATED_NAMESPACE_SCOPES = {'tests/integration/test_hierarchy_background.py': ('<module>',),
 'tests/integration/test_hierarchy_portability.py': ('<module>',),
 'tests/integration/test_hierarchy_root.py': ('capability_host',
                                              'test_process_verification_refuses_an_unsupported_host_before_any_probe',
                                              'test_render_flushes_the_file_and_preserves_posix_directory_errors'),
 'tests/integration/test_hierarchy_small_change_dispatch.py': ('formal_dispatch',
                                                               'r10_source_io',
                                                               'snapshot_v1_probe'),
 'tests/unit/cli/test_hook_run.py': ('test_the_cli_loads_command_parsing_only_for_shell_routes',)}


def _namespace_uses(tree, names, *, generated=True):
    """Every namespace capability needs the seam shape or an exact whole operation."""
    names = NamespaceNames(tree, names.rel)
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

    def exposed(target):
        if target is None:
            return True
        possible = names.possible(target)
        return UNKNOWN in possible or any(
            candidate == module or candidate.endswith("." + module)
            for candidate in possible for module in PROCESS_MODULES)

    for node in ast.walk(tree):
        kind = None
        if isinstance(node, ast.Import) and any(alias.name == "builtins" for alias in node.names):
            kind = "namespace_builtin_import"
        elif isinstance(node, ast.ImportFrom) and node.module == "builtins":
            kind = "namespace_builtin_import"
        elif (isinstance(node, ast.ImportFrom) and node.module == "sys"
              and any(alias.name == "modules" for alias in node.names)):
            kind = "namespace_sys_modules"
        elif isinstance(node, (ast.Name, ast.Attribute, ast.Call)):
            if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
                continue
            possible = names.possible(node)
            if any(value == "sys.modules" or value.endswith(".sys.modules") for value in possible):
                kind = "namespace_sys_modules"
            elif any(value in {"builtins.__dict__", "builtins.__getattribute__",
                               "builtins.__setattr__", "builtins.__delattr__"}
                     for value in possible):
                kind = "namespace_" + next(value.rsplit(".", 1)[1] for value in sorted(possible)
                                            if value.startswith("builtins.__"))
            else:
                namespace = next((name for name in ("vars", "globals", "locals")
                                  if "builtins." + name in possible
                                  or isinstance(node, ast.Name) and node.id == name
                                  and isinstance(parents.get(id(node)), ast.Call)
                                  and parents[id(node)].func is node
                                  or isinstance(node, ast.Attribute) and node.attr == name
                                  and isinstance(node.value, ast.Name) and node.value.id == "builtins"), None)
                parent = parents.get(id(node))
                if namespace is not None:
                    target = (parent.args[0] if isinstance(parent, ast.Call) and parent.func is node
                              and parent.args and namespace == "vars" else None)
                    if exposed(target) and not (namespace == "vars" and _seam_copy(node, parents, names)):
                        kind = "namespace_" + namespace
                else:
                    attribute = node.attr if isinstance(node, ast.Attribute) else None
                    if (isinstance(node, ast.Call) and len(node.args) >= 2
                            and ("builtins.getattr" in names.possible(node.func)
                                 or isinstance(node.func, ast.Name) and node.func.id == "getattr")
                            and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)):
                        attribute = node.args[1].value
                    if attribute in {"__dict__", "__getattribute__", "__class__", "__setattr__", "__delattr__"}:
                        kind = "namespace_" + attribute
        if kind is None and isinstance(node, ast.Call):
            possible = names.possible(node.func)
            method = next((name for name in ("getattr", "setattr", "delattr")
                           if "builtins." + name in possible
                           or isinstance(node.func, ast.Name) and node.func.id == name), None)
            if method is not None:
                attribute = node.args[1] if len(node.args) > 1 else None
                if (not isinstance(attribute, ast.Constant) or not isinstance(attribute.value, str)):
                    if exposed(node.args[0] if node.args else None):
                        kind = "namespace_" + method
        if kind is None:
            targets = []
            if (isinstance(node, (ast.Attribute, ast.Subscript))
                    and isinstance(node.ctx, (ast.Store, ast.Del))):
                targets = [node]
            elif isinstance(node, ast.Call):
                functions = names.possible(node.func)
                method = node.func.attr if isinstance(node.func, ast.Attribute) else None
                if (method in PATCH_METHODS or functions & (MOCK_CALLABLES | {"builtins.setattr", "builtins.delattr"})
                        or isinstance(node.func, ast.Name) and node.func.id in {"setattr", "delattr"}):
                    target = node.args[0] if node.args else next(
                        (kw.value for kw in node.keywords if kw.arg in {"target", "dic", "in_dict"}), None)
                    if target is not None:
                        targets = [target]
            for target in targets:
                while isinstance(target, ast.Subscript):
                    target = target.value
                candidates = ({target.value} if isinstance(target, ast.Constant) and isinstance(target.value, str)
                              else names.possible(target))
                if any(value == "importlib" or value.startswith("importlib.") for value in candidates):
                    kind = "namespace_importlib"
                    break
        if kind is not None:
            yield node, kind, _complete_operation(node, parents)


    if generated:
        scopes = GENERATED_NAMESPACE_SCOPES.get(names.rel, ())
        for node in ast.walk(tree):
            if (not isinstance(node, ast.Constant) or not isinstance(node.value, str)
                    or names.labels[id(node)] not in scopes):
                continue
            # These existing templates use printf slots. Normalization is for
            # shape classification only; the registry pins the untouched outer AST.
            text = node.value.replace("%%", "%").replace("%r", "None").replace("%s", "None")
            try:
                inner = ast.parse("import types\nfrom types import SimpleNamespace\n" + text)
            except SyntaxError:
                # Ordinary prose/fragments in these scopes are not executable
                # source. Changing a registered template leaves its old key stale.
                continue
            inner_names = PatchNames(inner, names.rel + ":generated")
            for _, kind, _ in _namespace_uses(inner, inner_names, generated=False):
                yield node, "namespace_generated_" + kind.removeprefix("namespace_"), _complete_operation(node, parents)


def _syntactic_bans(tree):
    """Recognize source spellings and AST writes; do not follow runtime values."""
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    annotations = set()
    for node in ast.walk(tree):
        annotation = (node.annotation if isinstance(node, (ast.arg, ast.AnnAssign))
                      else node.returns if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else None)
        if annotation is not None:
            if _inert_type(annotation):
                annotations.update(id(part) for part in ast.walk(annotation))
            else:
                yield annotation, "annotation"
    sys_names, module_maps = {"sys"}, set()
    constructors, patch_names = {"MonkeyPatch"}, {"patch"}
    builtins_names = {"builtins"}
    namespace_names = {name: name for name in ("globals", "locals", "vars")}
    attribute_writes = {"setattr", "delattr", "setitem", "delitem"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "sys":
                    sys_names.add(alias.asname or "sys")
                elif alias.name == "builtins":
                    builtins_names.add(alias.asname or "builtins")
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                local = alias.asname or alias.name
                if node.module == "sys" and alias.name == "modules":
                    module_maps.add(local)
                elif alias.name == "MonkeyPatch":
                    constructors.add(local)
                elif node.module in {"unittest.mock", "mock"} and alias.name == "patch":
                    patch_names.add(local)
                elif node.module == "builtins" and alias.name in {"globals", "locals", "vars"}:
                    namespace_names[local] = alias.name
                elif node.module == "builtins" and alias.name in {"setattr", "delattr"}:
                    attribute_writes.add(local)

    def module_map(node):
        return (isinstance(node, ast.Name) and node.id in module_maps
                or isinstance(node, ast.Attribute) and node.attr == "modules"
                and isinstance(node.value, ast.Name) and node.value.id in sys_names)

    def namespace(node):
        # A write target may contain the module map inside a call or index,
        # rather than along an attribute/subscript spine. No identity proof.
        if any(module_map(part) for part in ast.walk(node)):
            return True
        if isinstance(node, ast.Call):
            function = node.func
            return (isinstance(function, ast.Name) and function.id in namespace_names
                    or isinstance(function, ast.Attribute) and function.attr in {"globals", "locals", "vars"}
                    and isinstance(function.value, ast.Name) and function.value.id in builtins_names)
        return isinstance(node, (ast.Attribute, ast.Subscript)) and namespace(node.value)

    def write_target(node):
        if isinstance(node, ast.Name):
            return node.id == "__name__"
        if isinstance(node, (ast.Tuple, ast.List)):
            return any(write_target(part) for part in node.elts)
        if isinstance(node, ast.Starred):
            return write_target(node.value)
        return isinstance(node, (ast.Attribute, ast.Subscript)) and namespace(node)

    def patch_family(name):
        return any(name == family or name.startswith(family + ".")
                   for family in ("unittest.mock", "mock", "pytest"))

    mutators = {"update", "setdefault", "clear", "pop", "popitem", "__setitem__", "__delitem__", "__ior__"}
    for node in ast.walk(tree):
        if (id(node) not in annotations
                and (isinstance(node, ast.Name) and node.id in constructors
                     or isinstance(node, ast.Attribute) and node.attr == "MonkeyPatch")):
            yield node, "constructor_reference"
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            sensitive = (any(patch_family(alias.name) for alias in node.names) if isinstance(node, ast.Import)
                         else patch_family(node.module or "")
                         or node.module == "unittest" and any(alias.name == "mock" for alias in node.names))
            if sensitive and parents.get(id(node)) is not tree:
                yield node, "import"
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            yield node, "declaration"
        elif isinstance(node, ast.Call):
            function = node.func
            if (id(node) not in annotations
                    and (isinstance(function, ast.Name) and function.id in constructors
                         or isinstance(function, ast.Attribute) and function.attr == "MonkeyPatch")):
                yield node, "constructor"
            method = function.attr if isinstance(function, ast.Attribute) else function.id if isinstance(function, ast.Name) else None
            patch_spine = (isinstance(function, ast.Attribute)
                           and (isinstance(function.value, ast.Attribute) and function.value.attr == "patch"
                                or isinstance(function.value, ast.Name) and function.value.id in patch_names))
            if method in attribute_writes or patch_spine and method in {"object", "dict"}:
                target = node.args[0] if node.args else next((kw.value for kw in node.keywords
                                                             if kw.arg in {"target", "dic", "in_dict"}), None)
                if target is not None and namespace(target):
                    yield node, "module_write"
            elif isinstance(function, ast.Attribute) and method in mutators and namespace(function.value):
                yield node, "module_write"
        else:
            targets = (node.targets if isinstance(node, (ast.Assign, ast.Delete))
                       else [node.target] if isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr, ast.For, ast.AsyncFor, ast.comprehension))
                       else [node.optional_vars] if isinstance(node, ast.withitem) and node.optional_vars is not None
                       else [])
            if any(write_target(target) for target in targets):
                # Comprehension/withitem nodes have no own location; their target does.
                location = node if hasattr(node, "lineno") else targets[0]
                yield location, "module_write"


@lru_cache(maxsize=8192)
def _registered_syntax(expression):
    """Only trusted registration text is parsed; observed keys carry their AST."""
    tree = ast.parse(expression)
    if len(tree.body) == 1:
        node = tree.body[0]
        return _ast_identity(node.value if isinstance(node, ast.Expr) else node)
    return _ast_identity(tree)


def _ban_identity(key):
    """Compare AST identities without reparsing observed source fragments."""
    filename, scope, kind, expression, occurrence = key
    if (kind.startswith("namespace_") and not isinstance(expression, ASTSyntax)
            and expression.startswith(AST_DIGEST_PREFIX)):
        syntax = expression
    else:
        syntax = expression.identity if isinstance(expression, ASTSyntax) else _registered_syntax(expression)
        if kind.startswith("namespace_"):
            syntax = AST_DIGEST_PREFIX + hashlib.sha256(syntax.encode("ascii", "backslashreplace")).hexdigest()
    return filename, scope, kind, syntax, occurrence

# Each group lists zero-based occurrences of identical syntax within its lexical scope.
# Registrations certify today's otherwise unprovable uses, never a wildcard.
PROOF_REGISTRATION_GROUPS = {
    ('tests/unit/core/test_write_census.py', 'test_filesystem_unix_bind_is_a_write', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Uses pytest-owned temporary cwd for a short relative AF_UNIX availability probe; pytest restores cwd and no module attribute is patched.'),
    ('tests/unit/cli/test_cli_team.py', 'test_model_workspace_failure_is_json_exit_two', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census. The control enters its temporary directory and pins a missing workspace to verify the fixed model_workspace_unavailable JSON refusal.'),
    ('tests/unit/cli/test_cli_team.py', 'test_model_workspace_failure_is_json_exit_two', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census. The control enters its temporary directory and pins a missing workspace to verify the fixed model_workspace_unavailable JSON refusal.'),
    ('tests/unit/cli/test_cli_team.py', 'test_model_workspace_spellings_keep_fixed_json_errors', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census. The control enters its temporary workspace and isolates AEGIS_WORKSPACE while checking abbreviated/root/team workspace spellings preserve the fixed usage or workspace JSON error.'),
    ('tests/unit/cli/test_cli_team.py', 'test_model_workspace_spellings_keep_fixed_json_errors', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census. The control enters its temporary workspace and isolates AEGIS_WORKSPACE while checking abbreviated/root/team workspace spellings preserve the fixed usage or workspace JSON error.'),
    ('tests/unit/cli/test_cli_team.py', 'test_model_workspace_spellings_keep_fixed_json_errors', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census. The control enters its temporary workspace and isolates AEGIS_WORKSPACE while checking abbreviated/root/team workspace spellings preserve the fixed usage or workspace JSON error.'),
    ('tests/unit/cli/test_cli_team.py', 'test_abbreviated_workspace_operation_failure_is_fixed_json', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census. The control enters its temporary workspace and clears inherited AEGIS_WORKSPACE before checking that an anchored model I/O failure yields only fixed JSON.'),
    ('tests/unit/cli/test_cli_team.py', 'test_abbreviated_workspace_operation_failure_is_fixed_json', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census. The control enters its temporary workspace and clears inherited AEGIS_WORKSPACE before checking that an anchored model I/O failure yields only fixed JSON.'),
    ('tests/unit/cli/test_cli_team.py', 'test_abbreviated_workspace_operation_failure_is_fixed_json', 'owner', 'model_select', False):
        ((0,), 'model_select is aegis_core.model_select; this call replaces only its os reference with the local failing-open namespace for fixed JSON refusal, not process-wide os.'),
    ('tests/unit/cli/test_cli_team.py', 'test_removed_command_workspace_values_keep_model_json', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census. The control enters its temporary directory and clears inherited AEGIS_WORKSPACE to verify command-like workspace values retain the model JSON refusal.'),
    ('tests/unit/cli/test_cli_team.py', 'test_removed_command_workspace_values_keep_model_json', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census. The control enters its temporary directory and clears inherited AEGIS_WORKSPACE to verify command-like workspace values retain the model JSON refusal.'),
    ('tests/unit/cli/test_cli_team.py', 'test_removed_command_scan_uses_the_built_root_option_table', 'owner', 'cli_module', False):
        ((0,), 'cli_module is aegis_cli.cli; this call wraps its _build_parser to add the test-only --round-workspace option and verify model routing through the built option table.'),
    ('tests/unit/cli/test_cli_team.py', 'test_raw_model_invocation_has_only_model_json_outcomes', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census. The control enters its temporary workspace and sets or removes AEGIS_WORKSPACE for the pinned/unpinned model-invocation refusal matrix.'),
    ('tests/unit/cli/test_cli_team.py', 'test_raw_model_invocation_has_only_model_json_outcomes', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census. The control enters its temporary workspace and sets or removes AEGIS_WORKSPACE for the pinned/unpinned model-invocation refusal matrix.'),
    ('tests/unit/cli/test_cli_team.py', 'test_raw_model_invocation_has_only_model_json_outcomes', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census. The control enters its temporary workspace and sets or removes AEGIS_WORKSPACE for the pinned/unpinned model-invocation refusal matrix.'),
    ('tests/unit/cli/test_cli_team.py', 'test_outer_model_policy_covers_stdout_setup_failure', 'owner', 'cli_module', True):
        ((0,), "cli_module is aegis_cli.cli; this call replaces only its sys reference with a local stdout.reconfigure failure namespace, preserving pytest's real streams. The exact stdout-setup operation is conservatively counted as shared per the round20 brief."),
    ('tests/unit/mcp/test_mcp_team_model.py', 'workspace', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census. The MCP fixture enters its temporary governed workspace and clears inherited AEGIS_WORKSPACE before initializing the real server against that root.'),
    ('tests/unit/mcp/test_mcp_team_model.py', 'workspace', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census. The MCP fixture enters its temporary governed workspace and clears inherited AEGIS_WORKSPACE before initializing the real server against that root.'),
    ('tests/unit/mcp/test_mcp_team_model.py', 'test_cli_subdirectory_resolves_to_the_mcp_workspace', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census. The parity control enters a temporary workspace subdirectory to verify CLI resolution still matches the initialized MCP workspace.'),
    ('tests/unit/mcp/test_mcp_team_model.py', 'test_direct_subdirectory_adapter_matches_both_frontends', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census. The parity control enters the temporary docs directory for its cwd variant, checking both direct adapters and MCP dispatch resolve the same workspace.'),
    ('tests/unit/mcp/test_mcp_team_model.py', 'test_direct_adapter_denied_roots_refuse_before_paths', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census. The control points HOME and USERPROFILE at its test-owned home directory so all model adapters reject home/root workspaces before path handling.'),
    ('tests/unit/mcp/test_mcp_team_model.py', 'test_argument_refusal_precedes_held_workspace', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census. The control pins a deliberately missing workspace while a held binding is installed, verifying argument refusal precedes workspace refusal.'),
    ('tests/integration/test_hierarchy_launcher.py', 'test_stop_records_a_failed_process_census', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r30_resume_uses_the_real_spawns_cwd_and_path', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_launcher_stop_ownership.py', 'test_r26_captured_resume_requires_no_installed_host_cli', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_mailbox.py', 'test_fdopen_failure_closes_descriptor', 'owner', 'mailbox', False):
        ((0,), 'The mailbox fdopen-failure control copies os into a test-local namespace, then replaces only tools.hierarchy_mailbox.os to track descriptor closure before and after raw-stream cleanup.'),
    ('tests/unit/cli/test_cli_msg.py', 'test_mc2b_overflow_and_invalid_earlier_family_match_mcp', 'owner', 'server', False):
        ((1,), 'server is aegis_mcp.server; name/value iterate its fresh_state() fields before _canonical_workspace is set to the temporary Workspace, enabling CLI/MCP refusal-parity checks.'),
    ('tests/unit/cli/test_cli_msg.py', 'test_round6_missing_anchored_capabilities_refuse_fixed_json', 'owner', 'msg', False):
        ((0,), 'msg is aegis_cli.msg; replacing its _anchored_operations_supported probe verifies fixed JSON refusal before unsupported writes read stdin.'),
    ('tests/unit/core/test_argv_consumers.py', 'malformed_project', 'fixture', 'monkeypatch.setenv', False):
        ((0,), "The malformed_project fixture applies its temporary project's home environment and removes inherited Git/GitHub variables before checking malformed tests.command refusal."),
    ('tests/unit/core/test_argv_consumers.py', 'malformed_project', 'fixture', 'monkeypatch.delenv', False):
        ((0,), "The malformed_project fixture applies its temporary project's home environment and removes inherited Git/GitHub variables before checking malformed tests.command refusal."),
    ('tests/unit/core/test_argv_consumers.py', 'test_malformed_global_command_refuses_record_and_replay', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'The CLI record/replay control changes into its generated repository, proving a malformed tests.command records incomplete evidence without running tests.'),
    ('tests/unit/core/test_argv_consumers.py', 'test_malformed_global_command_refuses_regression', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'The CLI regression control changes into its generated repository, proving malformed tests.command refuses without echoing its private value or invoking the runner.'),
    ('tests/unit/core/test_model_select.py', 'test_mr3c_260_bindings_have_mr1_parity', 'fixture', 'monkeypatch.syspath_prepend', False):
        ((0,), "The MR3c parity control adds the repository tools directory to sys.path and imports hierarchy_provision; it replaces that product module's read_pinned_bindings and hierarchy_hosts.TEAM_HOSTS to compare 260 bindings across parsed, file and transaction surfaces."),
    ('tests/unit/core/test_storage_confined.py', 'test_unsupported_platform_refuses_without_io', 'owner', 'storage_confined', False):
        ((0, 1), 'storage_confined is aegis_core.storage_confined; its descriptor_supported probe and os reference are replaced to prove unsupported platforms refuse before opening a path.'),
    ('tests/unit/core/test_storage_confined.py', 'test_invalid_read_bound_refuses_before_open', 'owner', 'storage_confined', False):
        ((0,), 'storage_confined is aegis_core.storage_confined; its local os proxy fails on open to prove invalid read bounds refuse before I/O.'),
    ('tests/unit/core/test_storage_confined.py', 'test_size_checked_before_read_and_growth_bounded', 'owner', 'storage_confined', False):
        ((0, 1), 'storage_confined is aegis_core.storage_confined; its local os proxies fail premature reads and then simulate growth, verifying size checks precede reading and bounded growth refuses.'),
    ('tests/unit/core/test_storage_confined.py', 'test_failures_close_every_descriptor_and_remove_temporary', 'owner', 'storage_confined', False):
        ((0,), 'storage_confined is aegis_core.storage_confined; its local os proxy injects individual descriptor and publication failures while tracking opens/closes and temporary-file cleanup.'),
    ('tests/unit/core/test_storage_confined.py', 'test_invalid_root_spellings_refuse_before_open', 'owner', 'storage_confined', False):
        ((0,), 'storage_confined is aegis_core.storage_confined; its local os proxy fails on open to prove oversize, invalid-Unicode and bytes root spellings refuse before path I/O.'),
    ('tests/unit/core/test_storage_confined.py', 'test_invalid_publication_refuses_before_mutation', 'owner', 'storage_confined', False):
        ((0,), 'storage_confined is aegis_core.storage_confined; its local os proxy fails on open to prove invalid publication data or modes refuse before mutation.'),
    ('tests/unit/core/test_storage_confined.py', 'test_zero_progress_write_refuses_and_cleans_temporary', 'owner', 'storage_confined', False):
        ((0,), 'storage_confined is aegis_core.storage_confined; its local os proxy returns zero from write to verify fixed I/O refusal and temporary-file cleanup.'),
    ('tests/unit/core/test_storage_confined.py', 'test_temporary_collision_preserves_the_unowned_file', 'owner', 'storage_confined', False):
        ((0,), 'storage_confined is aegis_core.storage_confined; its uuid reference gets a deterministic local generator to collide with an unowned temporary file and prove it is preserved.'),
    ('tests/unit/core/test_storage_confined.py', 'test_concurrent_exclusive_publish_has_one_winner', 'owner', 'storage_confined', False):
        ((0,), 'storage_confined is aegis_core.storage_confined; its local os proxy synchronizes link calls from two publishers, proving exclusive creation has exactly one winner.'),
    ('tests/unit/core/test_storage_confined.py', 'test_leaf_swap_during_publication_cannot_write_outside', 'owner', 'storage_confined', False):
        ((0,), 'storage_confined is aegis_core.storage_confined; its local os proxy swaps the leaf to an outside symlink during replace, proving publication never writes outside.'),
    ('tests/unit/core/test_storage_confined.py', 'test_publication_flushes_every_created_entry_in_order', 'owner', 'storage_confined', False):
        ((0,), 'storage_confined is aegis_core.storage_confined; its os reference gets a DurabilityOS recorder to check ordered flushes of every created directory and published file.'),
    ('tests/unit/core/test_storage_confined.py', 'test_each_durability_failure_refuses_and_cleans', 'owner', 'storage_confined', False):
        ((0,), 'storage_confined is aegis_core.storage_confined; its os reference gets a failing DurabilityOS recorder to verify fixed durability refusal, descriptor closure and temporary cleanup at each flush stage.'),
    ('tests/unit/core/test_storage_confined.py', 'test_retry_flushes_reused_ancestor_containers', 'owner', 'storage_confined', False):
        ((0,), 'storage_confined is aegis_core.storage_confined; its os reference gets a DurabilityOS recorder to fail and retry ancestor flushes, verifying reused containers are flushed before publication.'),
    ('tests/unit/core/test_storage_confined.py', 'test_concurrent_creator_entries_are_flushed', 'owner', 'storage_confined', False):
        ((0,), 'proxy is a test-local DurabilityOS instance, then installed as aegis_core.storage_confined.os; its mkdir hook interleaves another creator to verify containing directories are flushed even after EEXIST.'),
    ('tests/unit/core/test_storage_confined.py', 'test_profile_retry_flushes_reused_ancestor_containers', 'owner', 'storage_confined', False):
        ((0,), 'storage_confined is aegis_core.storage_confined; its os reference gets a DurabilityOS recorder to verify team_profile initialization flushes reused ancestors when retrying after durability failure.'),
    ('tests/unit/mcp/test_mcp_stdio_input_budget.py', 'mode', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1, 2), 'The stdio mode fixture removes inherited workspace/manager settings, changes into its temporary directory and configures manager-only environment values to exercise both public transport modes.'),
    ('tests/unit/mcp/test_mcp_stdio_input_budget.py', 'mode', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'The stdio mode fixture removes inherited workspace/manager settings, changes into its temporary directory and configures manager-only environment values to exercise both public transport modes.'),
    ('tests/unit/mcp/test_mcp_stdio_input_budget.py', 'mode', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'The stdio mode fixture removes inherited workspace/manager settings, changes into its temporary directory and configures manager-only environment values to exercise both public transport modes.'),
    ('tests/unit/mcp/test_mcp_stdio_input_budget.py', 'message_workspace', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1), 'The stdio message_workspace fixture removes inherited manager settings and pins its temporary repository with AEGIS_WORKSPACE for repository message-tool requests.'),
    ('tests/unit/mcp/test_mcp_stdio_input_budget.py', 'message_workspace', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'The stdio message_workspace fixture removes inherited manager settings and pins its temporary repository with AEGIS_WORKSPACE for repository message-tool requests.'),
    ('tests/unit/verification/test_coverage_check.py', 'test_mixed_coverage_cli_explains_omissions_without_changing_json_or_exit', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'The mixed-coverage CLI control changes into its generated repository to verify omission explanations preserve the JSON result and exit status.'),
    ('tests/unit/verification/test_coverage_check.py', 'test_absent_omission_inventory_never_becomes_a_zero_count', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'The coverage omission control removes GITHUB_STEP_SUMMARY so absent inventory is reported as unknown through the public formatters without writing an inherited summary path.'),
    ('tests/unit/verification/test_coverage_check.py', 'test_coverage_reason_publications_use_closed_categories', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'The coverage reason control removes GITHUB_STEP_SUMMARY to verify closed publication categories without echoing private or oversized reason text.'),
    ('tests/unit/verification/test_coverage_check.py', 'test_mixed_producer_quoted_password_stays_only_in_json', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'The mixed-producer coverage control isolates Go caches, changes into its generated repository and sets a temporary GitHub summary path to verify a quoted password remains only in JSON.'),
    ('tests/unit/verification/test_coverage_check.py', 'test_mixed_producer_quoted_password_stays_only_in_json', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'The mixed-producer coverage control isolates Go caches, changes into its generated repository and sets a temporary GitHub summary path to verify a quoted password remains only in JSON.'),
    ('tests/unit/cli/test_team_hosts_cli.py', 'test_public_entrypoint', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'TP6 changes to its configured temporary repository before exercising the public team hosts usage CLI entrypoint; pytest restores the working directory.'),
    ('tests/conftest.py', '_no_developer_aegis_env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 031d12068dd4; Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/conftest.py', '_no_real_gh', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/conftest.py', '_no_real_gh', 'owner', 'ghcli', False):
        ((0,), 'Owner ghcli has lexical candidates aegis_core.ghcli; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/conftest.py', '_no_real_gh_on_path', 'owner', 'pathlookup', False):
        ((0,), 'Owner pathlookup has lexical candidates aegis_core.pathlookup; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/conftest.py', 'real_gh_runner', 'owner', 'ghcli', False):
        ((0,), 'Owner ghcli has lexical candidates aegis_core.ghcli; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/contract/test_mailbox_index_rollout.py', 'test_tip_prefilters_once_with_clean_git_environment', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/contract/test_mailbox_index_rollout.py', 'test_unsupported_symlinks_skip', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/contract/test_mailbox_index_rollout.py', 'test_unsupported_symlinks_skip', 'callable', 'patch.setattr', True):
        ((1,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/contract/test_mailbox_index_rollout.py', 'test_unsupported_symlinks_skip', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/contract/test_mailbox_mcp_contract.py', 'test_setup_preserves_the_callers_git_index', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/contract/test_mailbox_mcp_contract.py', 'test_setup_preserves_the_callers_git_index', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/contract/test_mcp_descriptions_truth.py', 'test_insight_ids_are_random_and_never_called_content_addressed', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/contract/test_model_bindings_parity.py', 'test_core_and_mr1_binding_validation_agree', 'fixture', 'monkeypatch.syspath_prepend', False):
        ((0,), 'Fixture syspath_prepend operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/contract/test_model_bindings_parity.py', 'test_large_valid_registry_has_mr1_parity', 'fixture', 'monkeypatch.syspath_prepend', False):
        ((0,), 'Fixture syspath_prepend operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/contract/test_tree_identity_vectors.py', '_env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/contract/test_tree_identity_vectors.py', '_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/contract/test_version.py', 'test_mcp_initialize_reports_it', 'owner', 'server', False):
        ((0,), 'Owner server has lexical candidates aegis_mcp.server; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_debrief_invariants.py', 'test_symbol_authority_includes_package_exports', 'owner', 'command_safety', False):
        ((0,), 'Owner command_safety has lexical candidates aegis_core.command_safety; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_decay_integration.py', '_no_workspace_pin', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_board.py', 'page_board', 'owner', 'board_module', False):
        ((0,), 'Owner board_module has lexical candidates tools.hierarchy_board; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_capability_check.py', 'rendered_profile', 'owner', 'provision', False):
        ((0,), 'Owner provision has lexical candidates hierarchy_provision; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_container.py', 'acl_ancestor', 'owner', 'grp', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by c029dece1226; Owner grp has lexical candidates grp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_container.py', 'acl_ancestor', 'owner', 'pwd', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by c029dece1226; Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_container.py', 'bound_readlink_probe', 'callable', 'm.setattr', True):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing m.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_container.py', 'cli', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_container.py', 'layout', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2, 3, 4), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_container.py', 'layout', 'owner', 'pwd', False):
        ((0,), 'Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_container.py', 'model_stored_inode_alias', 'callable', 'm.setattr', True):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing m.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_container.py', 'test_existing_local_leaf_identity_alias_boundary', 'fixture', 'model_stored_inode_alias(m, (alias, leaf.stat()))', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_existing_local_leaf_identity_alias_boundary', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_expected_record_keeps_missing_non_secret_home_path', 'callable', 'm.setattr', True):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by e28e4fce24f4; Existing m.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_container.py', 'test_expected_record_keeps_missing_non_secret_home_path', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by e28e4fce24f4; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_fake_engine_round_trip', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2, 3, 4), 'present at tip 4959830f before RF-11b landed; added by c029dece1226; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_container.py', 'test_fake_image_environment_and_manifest_list', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by c029dece1226; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_container.py', 'test_home_lookup_keeps_environment_and_password_fallback', 'callable', 'm.setattr', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing m.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_container.py', 'test_home_lookup_keeps_environment_and_password_fallback', 'fixture', 'm.delenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_container.py', 'test_home_lookup_keeps_environment_and_password_fallback', 'fixture', 'monkeypatch.context', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_home_lookup_keeps_environment_and_password_fallback', 'owner', 'pwd', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_container.py', 'test_home_nss_oserror_is_validation_refusal', 'callable', 'm.setattr', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing m.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_container.py', 'test_home_nss_oserror_is_validation_refusal', 'fixture', 'm.delenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_container.py', 'test_home_nss_oserror_is_validation_refusal', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_home_nss_oserror_is_validation_refusal', 'owner', 'pwd', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_container.py', 'test_home_set_does_not_require_nss_for_empty_builder', 'callable', 'm.setattr', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing m.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_container.py', 'test_home_set_does_not_require_nss_for_empty_builder', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_home_set_does_not_require_nss_for_empty_builder', 'owner', 'pwd', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_container.py', 'test_image_config_requires_known_object', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 8328f3d0dd1b; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_container.py', 'test_intermediate_local_metadata_refuses', 'callable', 'm.setattr', True):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing m.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_container.py', 'test_intermediate_local_metadata_refuses', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_local_root_metadata_cannot_be_absence', 'callable', 'm.setattr', True):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing m.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_container.py', 'test_local_root_metadata_cannot_be_absence', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_local_root_metadata_cannot_be_absence', 'owner', 'module', True):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Owner module has lexical candidates os; not a unique module-level import. Includes a shared process module.'),
    ('tests/integration/test_hierarchy_container.py', 'test_local_symlink_expansion_budget_refuses', 'fixture', 'bound_readlink_probe(m)', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_local_symlink_expansion_budget_refuses', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_missing_secrets_are_not_created_or_enumerated', 'callable', 'm.setattr', True):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by e28e4fce24f4; Existing m.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_container.py', 'test_missing_secrets_are_not_created_or_enumerated', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by e28e4fce24f4; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_modelled_acl_effective_grants', 'owner', 'grp', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by c029dece1226; Owner grp has lexical candidates grp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_container.py', 'test_modelled_shared_group_name_cannot_claim_private_nss', 'owner', 'grp', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by c029dece1226; Owner grp has lexical candidates grp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_container.py', 'test_mount_canonicalization_oserror_refuses', 'callable', 'm.setattr', True):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing m.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_container.py', 'test_mount_canonicalization_oserror_refuses', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_mount_metadata_recursion_is_refused', 'callable', 'm.setattr', True):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing m.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_container.py', 'test_mount_metadata_recursion_is_refused', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_mount_metadata_recursion_is_refused', 'owner', 'module', True):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Owner module has lexical candidates os; not a unique module-level import. Includes a shared process module.'),
    ('tests/integration/test_hierarchy_container.py', 'test_owner_capture_missing_file_has_documented_diagnostic', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 5ae2b29044cf; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_container.py', 'test_password_home_unavailable', 'owner', 'pwd', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by c029dece1226; Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_container.py', 'test_pinned_image_credential_cannot_be_overridden', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by c029dece1226; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_container.py', 'test_planner_recorded_local_root_refuses', 'fixture', 'model_stored_inode_alias(m, identity)', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_planner_recorded_local_root_refuses', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_planner_relocated_local_parent_refuses', 'fixture', 'model_stored_inode_alias(m, identity)', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_planner_relocated_local_parent_refuses', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_private_group_writable_ancestors', 'owner', 'grp', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by c029dece1226; Owner grp has lexical candidates grp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_container.py', 'test_private_group_writable_ancestors', 'owner', 'pwd', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by c029dece1226; Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_container.py', 'test_recorded_local_root_descendants_stay_valid', 'fixture', 'model_stored_inode_alias(m, identity)', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_recorded_local_root_descendants_stay_valid', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_recorded_local_root_refuses', 'fixture', 'model_stored_inode_alias(m, identity)', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_recorded_local_root_refuses', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_relocated_local_parent_refuses', 'fixture', 'model_stored_inode_alias(m, identity)', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_relocated_local_parent_refuses', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_resolved_local_alias_refuses', 'callable', 'm.setattr', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing m.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_container.py', 'test_resolved_local_alias_refuses', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_resolved_local_alias_refuses', 'owner', 'pwd', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_container.py', 'test_stored_mixed_access_overlap_refuses', 'fixture', 'model_stored_inode_alias(m, identity)', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_stored_mixed_access_overlap_refuses', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_stored_same_access_overlap_stays_valid', 'fixture', 'model_stored_inode_alias(m, identity)', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_stored_same_access_overlap_stays_valid', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_symlink_completed_resolution_memoizes_each_link', 'callable', 'm.setattr', True):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing m.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_container.py', 'test_symlink_completed_resolution_memoizes_each_link', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_symlink_expansion_budget_refuses', 'fixture', 'bound_readlink_probe(m)', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_symlink_expansion_budget_refuses', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_symlink_memo_hit_still_checks_link_metadata', 'callable', 'm.setattr', True):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing m.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_container.py', 'test_symlink_memo_hit_still_checks_link_metadata', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_unavailable_home_lookup_refuses', 'fixture', 'monkeypatch.context', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'test_unavailable_home_lookup_refuses', 'fixture', 'unavailable_home_lookup(m, shape)', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_container.py', 'unavailable_home_lookup', 'callable', 'm.setattr', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Existing m.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_container.py', 'unavailable_home_lookup', 'owner', 'pwd', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 1fe6c42f119c; Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_decision_service.py', 'test_service_prior_guard_history_cannot_project_no_effect_refusal', 'fixture', 'canonical_live_decision(tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_decision_service.py', 'test_service_public_all_five_inputs_match_actual_received_frame', 'fixture', 'canonical_live_decision(tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_decision_service.py', 'test_service_public_constructors_reject_actual_reservation_types', 'fixture', 'canonical_live_decision(tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_decision_service.py', 'test_service_public_invalid_data_precedes_real_reserved_context', 'fixture', 'canonical_live_decision(tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_decision_service.py', 'test_service_public_journal_conflict_differs_from_changed_direct_input', 'fixture', 'canonical_live_decision(tmp_path, monkeypatch, seed=True, changes=changes)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_decision_service.py', 'test_service_public_possible_publication_stays_unknown', 'callable', 'boundary.setattr', True):
        ((0,), 'Existing boundary.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_decision_service.py', 'test_service_public_possible_publication_stays_unknown', 'fixture', 'canonical_live_decision(tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_decision_service.py', 'test_service_public_possible_publication_stays_unknown', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_decision_service.py', 'test_service_public_possible_publication_stays_unknown', 'owner', 'os', True):
        ((0,), 'Owner os has lexical candidates os; not a unique module-level import. Includes a shared process module.'),
    ('tests/integration/test_hierarchy_decision_service.py', 'test_service_public_real_root_records_once_through_fixed_dispatch', 'fixture', "canonical_live_decision(tmp_path, monkeypatch, changes={'decision': decision})", False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_decision_service.py', 'test_service_public_recovers_original_receipt_without_new_budget', 'fixture', 'canonical_live_decision(tmp_path, monkeypatch, seed=True, capped=capped, future=future)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_decision_service.py', 'test_service_public_second_handle_cannot_append_again', 'fixture', 'canonical_live_decision(tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_decision_service.py', 'test_service_public_valid_data_cannot_promote_actual_reservation', 'fixture', 'canonical_live_decision(tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_fake_claude.py', 'test_a_folder_beside_the_real_users_claude_folder_is_allowed', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_fake_claude.py', 'test_a_folder_beside_the_real_users_claude_folder_is_allowed', 'owner', 'pwd', False):
        ((0,), 'Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_fake_claude.py', 'test_the_fake_drives_the_real_mailbox_adapter_through_the_fake_host', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_fake_claude.py', 'test_the_meter_counts_one_turn_per_invocation_from_the_fake_transcript', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_fake_claude.py', 'test_the_real_users_claude_folder_is_refused_even_under_a_test_home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_fake_claude.py', 'test_the_real_users_claude_folder_is_refused_even_under_a_test_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_fake_claude.py', 'test_the_real_users_claude_folder_is_refused_even_under_a_test_home', 'owner', 'pwd', False):
        ((0,), 'Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_foundation_acceptance.py', 'test_cli_replay_owns_canonical_scratch_under_aliased_temp_directory', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_fresh_brief.py', 'test_consumed_reference_rechecks_do_not_enumerate_shared_cache', 'owner', 'fresh._Operation', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by fccd7f57fc23; Owner fresh._Operation resolves to tools.hierarchy_fresh_brief._Operation; reviewed consumer/class seam, not a shared module patch.'),
    ('tests/integration/test_hierarchy_git_reads.py', 'test_ambient_config_cannot_enable_a_review_fetch', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2, 3, 4, 5), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_git_reads.py', 'test_job_export_never_fetches_if_config_changes_after_object_preflight', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_git_reads.py', 'test_review_ignores_an_ambient_custom_replacement_namespace', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_git_reads.py', 'test_running_mcp_reader_never_fetches_after_promisor_config_changes', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_git_reads.py', 'test_source_digest_preserves_the_owners_global_excludes', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_handoff_stop_evidence.py', 'test_a_background_session_still_requires_a_successful_census', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_handoff_stop_evidence.py', 'test_a_census_timeout_preserves_the_error_and_changes_nothing', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_handoff_stop_evidence.py', 'test_a_census_timeout_preserves_the_error_and_changes_nothing', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_handoff_stop_evidence.py', 'test_a_failed_census_explains_that_stop_cannot_fix_it', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_handoff_stop_evidence.py', 'test_a_missing_ps_explains_the_census_error_and_recovery', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_handoff_stop_evidence.py', 'test_a_wake_after_preflight_refuses_only_its_entry_and_a_rerun_finishes', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_handoff_stop_evidence.py', 'test_a_wake_after_preflight_refuses_only_its_entry_and_a_rerun_finishes', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'count_external_readback', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'count_external_readback', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'owned_runtime_boundary', 'callable', 'boundary.setattr', False):
        ((4, 5, 6), 'Existing boundary.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'owned_runtime_boundary', 'callable', 'boundary.setattr', True):
        ((0, 1, 2, 3), 'Existing boundary.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'owned_runtime_boundary', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'test_error_fields_are_readonly_closed_and_transport_is_explicitly_posix', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'test_error_fields_are_readonly_closed_and_transport_is_explicitly_posix', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'test_initial_start_cannot_renew_original_bound_deadline', 'callable', 'clock.setattr', True):
        ((0, 1), 'Existing clock.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'test_initial_start_cannot_renew_original_bound_deadline', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'test_owned_constructor_failure_closes_all_channels', 'callable', 'boundary.setattr', True):
        ((0,), 'Existing boundary.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'test_owned_constructor_failure_closes_all_channels', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'test_owned_constructor_postreply_readback_keeps_original_deadline', 'callable', 'boundary.setattr', False):
        ((1,), 'Existing boundary.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'test_owned_constructor_postreply_readback_keeps_original_deadline', 'callable', 'boundary.setattr', True):
        ((0, 2, 3), 'Existing boundary.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'test_owned_constructor_postreply_readback_keeps_original_deadline', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'test_owned_constructor_unsupported_host_closes_transferred_channels', 'callable', 'platform.setattr', True):
        ((0,), 'Existing platform.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_host_authority.py', 'test_owned_constructor_unsupported_host_closes_transferred_channels', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_host_plan.py', 'team', 'fixture', 'TeamRun(tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_hosts.py', 'test_claude_auth_check_refuses_a_relative_config_directory', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_derived_publication_loser_reports_pending_settlement', 'callable', 'patch.setattr', False):
        ((1,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_derived_publication_loser_reports_pending_settlement', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_derived_publication_loser_reports_pending_settlement', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_derived_publication_loser_reports_pending_settlement', 'owner', 'fcntl', False):
        ((0,), 'Owner fcntl has lexical candidates fcntl; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_durable_grant_fault_retains_rows_audit_and_recovers', 'callable', 'patch.setattr', False):
        ((0, 1, 3), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_durable_grant_fault_retains_rows_audit_and_recovers', 'callable', 'patch.setattr', True):
        ((2,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_durable_grant_fault_retains_rows_audit_and_recovers', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_failed_derived_admission_preserves_its_partial_claim_custody', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_failed_derived_admission_preserves_its_partial_claim_custody', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_handled_grant_keeps_later_contention_legacy_bytes', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_handled_grant_keeps_later_contention_legacy_bytes', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_postcompletion_fault_appends_its_own_hold_without_changing_an_unknown_job', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_postcompletion_fault_appends_its_own_hold_without_changing_an_unknown_job', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_postcompletion_store_failure_becomes_a_root_hold', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_postcompletion_store_failure_becomes_a_root_hold', 'callable', 'patch.setattr', True):
        ((1,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_postcompletion_store_failure_becomes_a_root_hold', 'fixture', 'monkeypatch.context', False):
        ((0, 1), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_preclaim_mailbox_error_does_not_adopt_another_runners_fence', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_preclaim_mailbox_error_does_not_adopt_another_runners_fence', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_released_grant_is_not_resurrected_by_later_recovery', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_released_grant_is_not_resurrected_by_later_recovery', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_retained_heavy_claim_cannot_exempt_the_runners_next_heavy_tests_job', 'callable', 'patch.setattr', False):
        ((1,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_retained_heavy_claim_cannot_exempt_the_runners_next_heavy_tests_job', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_a_retained_heavy_claim_cannot_exempt_the_runners_next_heavy_tests_job', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_an_admitted_derivation_with_a_busy_execution_lock_stays_retryable', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_an_admitted_derivation_with_a_busy_execution_lock_stays_retryable', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_an_admitted_derivation_with_a_busy_execution_lock_stays_retryable', 'owner', 'fcntl', False):
        ((0,), 'Owner fcntl has lexical candidates fcntl; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_an_unhandled_grant_still_makes_contention_a_postgrant_fault', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_an_unhandled_grant_still_makes_contention_a_postgrant_fault', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_exhausted_budget_preserves_enqueue_but_skips_kind_grant_admission', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_exhausted_budget_preserves_enqueue_but_skips_kind_grant_admission', 'callable', 'patch.setattr', True):
        ((1,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_exhausted_budget_preserves_enqueue_but_skips_kind_grant_admission', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_job_claim_boundary_keeps_other_jobs_running_and_preserves_unknown_custody', 'callable', 'patch.setattr', False):
        ((1,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_job_claim_boundary_keeps_other_jobs_running_and_preserves_unknown_custody', 'callable', 'patch.setattr', True):
        ((0, 2), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_job_claim_boundary_keeps_other_jobs_running_and_preserves_unknown_custody', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_reserved_dependency_refusal_respects_the_claim_boundary', 'callable', 'patch.setattr', False):
        ((1,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_reserved_dependency_refusal_respects_the_claim_boundary', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_jobs.py', 'test_reserved_dependency_refusal_respects_the_claim_boundary', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_launcher.py', 'test_a_census_that_fails_after_signals_were_sent_is_recorded_as_stop_failed', 'fixture', 'monkeypatch.undo', False):
        ((0,), 'Fixture undo operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_launcher.py', 'test_a_record_write_that_fails_part_way_leaves_no_torn_record', 'fixture', 'monkeypatch.undo', False):
        ((0,), 'Fixture undo operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_launcher.py', 'test_resume_records_a_wake_tool_that_cannot_run', 'fixture', 'monkeypatch.undo', False):
        ((0,), 'Fixture undo operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_launcher_hosts.py', 'start_as_owner', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_launcher_hosts.py', 'start_as_owner', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_launcher_hosts.py', 'start_as_owner', 'fixture', 'monkeypatch.undo', False):
        ((0,), 'Fixture undo operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_launcher_hosts.py', 'start_as_owner', 'owner', 'pwd', False):
        ((0,), 'Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_launcher_hosts.py', 'test_a_native_host_is_refused_at_start', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_launcher_hosts.py', 'test_a_native_host_is_refused_at_start', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_launcher_hosts.py', 'test_a_native_host_is_refused_at_start', 'fixture', 'monkeypatch.undo', False):
        ((0,), 'Fixture undo operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'canonical_live_decision', 'callable', 'wire.setattr', False):
        ((1,), 'Existing wire.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'canonical_live_decision', 'callable', 'wire.setattr', True):
        ((0,), 'Existing wire.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'canonical_live_decision', 'fixture', 'live_control_runtime(host, tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'canonical_live_decision', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'initial_runtime_boundary', 'callable', 'boundary.setattr', False):
        ((4, 5, 6), 'Existing boundary.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'initial_runtime_boundary', 'callable', 'boundary.setattr', True):
        ((0, 1, 2, 3), 'Existing boundary.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'initial_runtime_boundary', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_approval_receipt_survives_expiry_and_root_succession_without_new_authority', 'owner', 'hierarchy_lifecycle', False):
        ((0, 1), 'Owner hierarchy_lifecycle has lexical candidates tools.hierarchy_lifecycle; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_bounded_authority_stops_at_denial_expiry_budget_or_exact_scope', 'owner', 'hierarchy_lifecycle', False):
        ((0,), 'Owner hierarchy_lifecycle has lexical candidates tools.hierarchy_lifecycle; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_expired_initial_receipt_recovery_does_not_renew_new_creation_or_current_budget', 'callable', 'clock.setattr', True):
        ((0, 1), 'Existing clock.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_expired_initial_receipt_recovery_does_not_renew_new_creation_or_current_budget', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_initial_creation_canonical_fence_exit_unknown_recovers_original_only', 'callable', 'persistence.setattr', True):
        ((0,), 'Existing persistence.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_initial_creation_canonical_fence_exit_unknown_recovers_original_only', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_initial_creation_late_canonical_exit_budget_recovers_original', 'callable', 'clock.setattr', True):
        ((0, 1), 'Existing clock.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_initial_creation_late_canonical_exit_budget_recovers_original', 'callable', 'persistence.setattr', True):
        ((0,), 'Existing persistence.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_initial_creation_late_canonical_exit_budget_recovers_original', 'fixture', 'monkeypatch.context', False):
        ((0, 1), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_initial_creation_publication_unknown_retains_original_for_explicit_recovery', 'callable', 'persistence.setattr', False):
        ((0,), 'Existing persistence.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_initial_creation_publication_unknown_retains_original_for_explicit_recovery', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_new_approval_at_or_after_expiry_is_refused_atomically', 'owner', 'hierarchy_lifecycle', False):
        ((0,), 'Owner hierarchy_lifecycle has lexical candidates tools.hierarchy_lifecycle; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_protected_decision_publication_and_scope_exit_keep_original_unknown', 'callable', 'boundary.setattr', True):
        ((0, 1, 2, 3), 'Existing boundary.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_protected_decision_publication_and_scope_exit_keep_original_unknown', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_reserved_genesis_ambiguity_retains_claim_without_retry', 'callable', 'persistence.setattr', False):
        ((0, 1, 2), 'Existing persistence.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_reserved_genesis_ambiguity_retains_claim_without_retry', 'callable', 'persistence.setattr', True):
        ((3,), 'Existing persistence.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_reserved_genesis_ambiguity_retains_claim_without_retry', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_reserved_genesis_guard_exit_deadline_keeps_publication_unknown', 'callable', 'clock.setattr', True):
        ((0, 1, 2), 'Existing clock.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_lifecycle.py', 'test_reserved_genesis_guard_exit_deadline_keeps_publication_unknown', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_lifecycle_connections.py', 'test_a_moment_of_journal_contention_at_the_record_is_waited_out', 'owner', 'hierarchy_lifecycle.Lifecycle', False):
        ((0,), 'Owner hierarchy_lifecycle.Lifecycle has lexical candidates hierarchy_lifecycle.Lifecycle; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_m1_loop.py', 'sealed_spawns', 'fixture', 'seal_spawns(monkeypatch, folder)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_m1_loop.py', 'test_failure_lost_deliveries_are_repaired_republished_and_rewoken_without_duplicates', 'fixture', 'monkeypatch.syspath_prepend', False):
        ((0,), 'Fixture syspath_prepend operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_mailbox.py', 'test_git_readiness_timeout_is_an_explicit_failure', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_mailbox_fence.py', 'fake_git', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'measure_ac1', 'fixture', 'MemoTrace(monkeypatch, mailbox)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'measure_ac1', 'fixture', 'ReadCounts(monkeypatch, trace)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'r21_force_fallback', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_mb7_deleted_reply_target_is_not_probed_after_reconciliation', 'callable', 'failure.setattr', True):
        ((0,), 'Existing failure.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_mb7_deleted_reply_target_is_not_probed_after_reconciliation', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_mb7_obsolete_brief_permission_recovers_incremental_reads', 'callable', 'failure.setattr', True):
        ((0,), 'Existing failure.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_mb7_obsolete_brief_permission_recovers_incremental_reads', 'fixture', 'MemoTrace(monkeypatch, mailbox)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_mb7_obsolete_brief_permission_recovers_incremental_reads', 'fixture', 'ReadCounts(monkeypatch, trace)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_mb7_obsolete_brief_permission_recovers_incremental_reads', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_mb7_reconciliation_preserves_changed_live_sha_baseline', 'callable', 'failure.setattr', True):
        ((0,), 'Existing failure.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_mb7_reconciliation_preserves_changed_live_sha_baseline', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_operations_never_write_root_or_parent', 'callable', 'operation.setattr', False):
        ((0,), 'Existing operation.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_operations_never_write_root_or_parent', 'callable', 'operation.setattr', True):
        ((1,), 'Existing operation.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_operations_never_write_root_or_parent', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r12_publication_races_return_pinned_result', 'callable', 'publication.setattr', False):
        ((0,), 'Existing publication.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r12_publication_races_return_pinned_result', 'callable', 'race_patch.setattr', False):
        ((0, 2), 'Existing race_patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r12_publication_races_return_pinned_result', 'callable', 'race_patch.setattr', True):
        ((1, 3), 'Existing race_patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r12_publication_races_return_pinned_result', 'fixture', 'monkeypatch.context', False):
        ((0, 1), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r13_ac1_existing_10k_fixture', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r17_oracle_preparation_finishes_before_warmup', 'fixture', 'MemoTrace(monkeypatch, mailbox)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r17_oracle_preparation_finishes_before_warmup', 'fixture', 'ReadCounts(monkeypatch, trace)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r17_unchanged_warm_counts', 'fixture', 'MemoTrace(monkeypatch, prefix_mailbox)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r17_unchanged_warm_counts', 'fixture', 'ReadCounts(monkeypatch, trace)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r18_above_root_timestamps_do_not_invalidate', 'fixture', 'MemoTrace(monkeypatch, mailbox)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r18_above_root_timestamps_do_not_invalidate', 'fixture', 'ReadCounts(monkeypatch, trace)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r18_in_scope_directory_change_revalidates_its_records', 'fixture', 'MemoTrace(monkeypatch, mailbox)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r18_pending_sibling_keeps_full_internal_directory_observation', 'fixture', 'MemoTrace(monkeypatch, mailbox)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r20_caller_error_preserves_warm_memo', 'fixture', 'MemoTrace(monkeypatch, mailbox)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r20_get_unhashable_caller_key_preserves_memo', 'fixture', 'MemoTrace(monkeypatch, mailbox)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r20_unavailable_verify_keeps_overflow_and_pending', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r24_each_fresh_record_validated_once', 'fixture', 'MemoTrace(monkeypatch, mailbox)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r24_fallback_evicts_observed_byte_contradictions', 'fixture', 'MemoTrace(monkeypatch, mailbox)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r24_fallback_retains_rekeyed_memo', 'fixture', 'MemoTrace(monkeypatch, mailbox)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r24_pending_unlink_check_race_retries_without_clear', 'callable', 'publication.setattr', False):
        ((0,), 'Existing publication.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r24_pending_unlink_check_race_retries_without_clear', 'fixture', 'MemoTrace(monkeypatch, mailbox)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r24_pending_unlink_check_race_retries_without_clear', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_index.py', 'test_r24_unencodable_brief_stays_warm_without_fallback', 'fixture', 'MemoTrace(monkeypatch, mailbox)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'mb3_fixed_clock', 'owner', 'mcp', False):
        ((0,), 'Owner mcp has lexical candidates hierarchy_mailbox_mcp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'mb3_handler_page', 'owner', 'mcp', False):
        ((0,), 'Owner mcp has lexical candidates hierarchy_mailbox_mcp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_2_class_a_one_snapshot', 'owner', 'Mailbox', False):
        ((0,), 'Owner Mailbox has lexical candidates hierarchy_mailbox.Mailbox; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_2_class_b_failures_leave_state_unchanged', 'callable', 'patch.setattr', False):
        ((0, 5), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_2_class_b_failures_leave_state_unchanged', 'callable', 'patch.setattr', True):
        ((1, 2, 3, 4), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_2_class_b_failures_leave_state_unchanged', 'fixture', 'monkeypatch.context', False):
        ((0, 1), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_2_class_b_failures_leave_state_unchanged', 'owner', 'mcp', False):
        ((0, 1), 'Owner mcp has lexical candidates hierarchy_mailbox_mcp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_2_class_d_future_skew_boundary', 'owner', 'mcp', False):
        ((0,), 'Owner mcp has lexical candidates hierarchy_mailbox_mcp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_2_class_f_changed_brief_uses_hash_not_error_text', 'owner', 'Mailbox', False):
        ((0,), 'Owner Mailbox has lexical candidates hierarchy_mailbox.Mailbox; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_2_class_f_pager_negative_control', 'owner', 'mcp', False):
        ((0,), 'Owner mcp has lexical candidates hierarchy_mailbox_mcp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_3_class2_drain_frees_only_finished_context', 'owner', 'mcp', False):
        ((0,), 'Owner mcp has lexical candidates hierarchy_mailbox_mcp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_3_class2_growth_stops_at_cap', 'owner', 'mcp', False):
        ((0,), 'Owner mcp has lexical candidates hierarchy_mailbox_mcp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_3_class4_clock_seam', 'owner', 'mcp', False):
        ((0,), 'Owner mcp has lexical candidates hierarchy_mailbox_mcp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_3b_colliding_default_commits_only_after_successful_flush', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_3b_colliding_default_commits_only_after_successful_flush', 'callable', 'patch.setattr', True):
        ((1, 2, 3, 4), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_3b_colliding_default_commits_only_after_successful_flush', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_3b_colliding_default_commits_only_after_successful_flush', 'owner', 'mcp', False):
        ((0,), 'Owner mcp has lexical candidates hierarchy_mailbox_mcp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_3b_collision_at_cap_refuses_before_staging', 'owner', 'mcp', False):
        ((0,), 'Owner mcp has lexical candidates hierarchy_mailbox_mcp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_3b_collision_pair_reissue_at_exact_cap', 'owner', 'mcp', False):
        ((0,), 'Owner mcp has lexical candidates hierarchy_mailbox_mcp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_coord3_one_plan_decision_per_inbox_call', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_coord3_one_plan_decision_per_inbox_call', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_coord5_no_plan_byte_boundary_and_linear_renders', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_coord5_no_plan_byte_boundary_and_linear_renders', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_coord5_no_plan_byte_boundary_and_linear_renders', 'owner', 'mcp', False):
        ((0,), 'Owner mcp has lexical candidates hierarchy_mailbox_mcp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_coord5_no_plan_preserves_binding_reread', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb3_coord5_no_plan_preserves_binding_reread', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb6_publish_failure_remains_an_error_without_reading_receipt_metadata', 'owner', 'mcp', False):
        ((0,), 'Owner mcp has lexical candidates hierarchy_mailbox_mcp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb6_publish_refuses_invalid_plan_before_writing', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb6_publish_refuses_invalid_plan_before_writing', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb6_publish_refuses_invalid_plan_before_writing', 'owner', 'hierarchy_hosts', False):
        ((0,), 'Owner hierarchy_hosts has lexical candidates hierarchy_hosts; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_mcp.py', 'test_mb6_publish_stat_failure_returns_success_with_size_unavailable', 'owner', 'mcp', False):
        ((0,), 'Owner mcp has lexical candidates hierarchy_mailbox_mcp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_mailbox_pager.py', 'test_retained_pairs_commit_retry_collision_and_drain', 'owner', 'mcp', False):
        ((0,), 'Owner mcp has lexical candidates hierarchy_mailbox_mcp; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_meter_hosts.py', 'test_claude_transcript_found_under_project_slug', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_meter_hosts.py', 'test_codex_rollout_found_only_in_archived_sessions', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_meter_hosts.py', 'test_home_lookup_uses_the_registry_declaration', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_meter_hosts.py', 'test_home_lookup_uses_the_registry_declaration', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_meter_hosts.py', 'test_invalid_sessions_do_not_match_existing_transcripts', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_meter_hosts.py', 'test_missing_home_returns_none', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_meter_hosts.py', 'test_newest_mtime_wins_across_live_and_archived_rollouts', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_meter_hosts.py', 'test_non_string_sessions_return_none', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_meter_hosts.py', 'test_unknown_hosts_do_not_match_existing_transcripts', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_meter_hosts.py', 'test_unset_or_empty_home_uses_the_existing_default', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_meter_hosts.py', 'test_unset_or_empty_home_uses_the_existing_default', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_native_probe.py', 'test_run_1_observations_replay_without_filesystem_or_process_access', 'callable', 'sealed.setattr', True):
        ((0, 1, 2), 'Existing sealed.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_native_probe.py', 'test_run_1_observations_replay_without_filesystem_or_process_access', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_native_probe.py', 'test_run_1_observations_replay_without_filesystem_or_process_access', 'owner', 'builtins', True):
        ((0,), 'Owner builtins has lexical candidates builtins; not a unique module-level import. Includes a shared process module.'),
    ('tests/integration/test_hierarchy_native_probe.py', 'test_the_plan_refuses_a_helper_inside_a_roles_writable_roots', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_native_probe.py', 'test_the_runs_own_cleanup_never_follows_a_codex_home_symlink_to_the_owners_login', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_native_probe.py', 'test_the_stand_in_passwd_home_is_honoured_only_for_the_fake', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_native_probe.py', 'test_under_the_fake_with_a_stand_in_the_real_passwd_home_is_never_resolved', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_operator.py', 'test_async_missing_process_capability_refuses_without_intent_or_effect', 'callable', 'unavailable.delattr', True):
        ((0,), 'Existing unavailable.delattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_operator.py', 'test_async_missing_process_capability_refuses_without_intent_or_effect', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_operator.py', 'test_async_stop_after_start_expiry_preserves_original_authority_and_cap', 'owner', 'hierarchy_lifecycle', False):
        ((0,), 'Owner hierarchy_lifecycle has lexical candidates hierarchy_lifecycle; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_provision.py', 'rb2_pending', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_provision.py', 'rb2_pending', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_provision.py', 'rb2_pending', 'owner', 'hierarchy_workspace', False):
        ((0,), 'Owner hierarchy_workspace has lexical candidates hierarchy_workspace; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_provision.py', 'test_mr1_r14a_governing_check_errors_never_escape_or_echo_details', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_provision.py', 'test_mr1_r14a_governing_check_errors_never_escape_or_echo_details', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_provision.py', 'test_mr1_r7_team_up_preflights_all_profiles_before_starting_router', 'fixture', 'Run(tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_router.py', 'test_status_names_a_refusal_constructing_the_store_as_the_source', 'owner', 'hierarchy_router', False):
        ((0,), 'Owner hierarchy_router has lexical candidates hierarchy_router; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_small_change_admission.py', 'test_admission_at_expiry_refuses_but_retains_approval_receipt', 'owner', 'hierarchy_lifecycle', False):
        ((0,), 'Owner hierarchy_lifecycle has lexical candidates tools.hierarchy_lifecycle; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_small_change_dispatch.py', 'isolated_home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_small_change_dispatch.py', 'isolated_home', 'owner', 'pwd', False):
        ((0,), 'Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_small_change_dispatch.py', 'test_loop_children_strip_parent_nested_claude_environment', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_small_change_dispatch.py', 'test_r15_private_message_does_not_block_other_endpoint_composition', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_small_change_dispatch.py', 'test_r16_modelled_windows_profile_lookup_has_a_positive_control_and_fails_closed', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_small_change_dispatch.py', 'test_r16_windows_defaults_refuse_private_references_before_metadata', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_source.py', 'test_blob_timeout_is_a_documented_refusal_and_can_be_read_later', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_source.py', 'test_blob_timeout_is_a_documented_refusal_and_can_be_read_later', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/integration/test_hierarchy_sweep.py', 'clock.<lambda>', 'owner', 'hierarchy_mailbox', False):
        ((0,), 'Owner hierarchy_mailbox has lexical candidates hierarchy_mailbox; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_sweep.py', 'durable_in_process', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_sweep.py', 'durable_in_process', 'owner', 'hierarchy_sweep', False):
        ((0,), 'Owner hierarchy_sweep has lexical candidates hierarchy_sweep; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_sweep.py', 'test_durable_rereads_receipts_so_a_turn_given_after_the_snapshot_is_not_repeated', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_sweep.py', 'test_durable_rereads_receipts_so_a_turn_given_after_the_snapshot_is_not_repeated', 'owner', 'hierarchy_sweep', False):
        ((0,), 'Owner hierarchy_sweep has lexical candidates hierarchy_sweep; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team.py', 'Run.__init__', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_team.py', 'Run.__init__', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_team.py', 'Run.__init__', 'fixture', 'self.monkeypatch = monkeypatch', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_team.py', 'run', 'fixture', 'Run(tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_team.py', 'seal_spawns', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_team.py', 'test_absolute_default_interpreter_keeps_its_final_symlink', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team.py', 'test_absolute_default_interpreter_keeps_its_final_symlink', 'owner', 'hierarchy_team', False):
        ((0,), 'Owner hierarchy_team has lexical candidates hierarchy_team; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team.py', 'test_completed_init_allows_status_and_down_under_a_different_interpreter', 'callable', 'run.monkeypatch.setattr', False):
        ((0, 1), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team.py', 'test_completed_init_allows_status_and_down_under_a_different_interpreter', 'owner', 'hierarchy_team', False):
        ((0, 1), 'Owner hierarchy_team has lexical candidates hierarchy_team; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team.py', 'test_default_interpreter_custody_survives_interrupted_init', 'callable', 'run.monkeypatch.setattr', False):
        ((0, 1, 2), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team.py', 'test_default_interpreter_custody_survives_interrupted_init', 'owner', 'hierarchy_team', False):
        ((0, 1, 2), 'Owner hierarchy_team has lexical candidates hierarchy_team; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team.py', 'test_default_interpreter_keeps_a_symlinked_bin_directory_and_its_virtual_environment', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team.py', 'test_default_interpreter_keeps_a_symlinked_bin_directory_and_its_virtual_environment', 'owner', 'hierarchy_team', False):
        ((0,), 'Owner hierarchy_team has lexical candidates hierarchy_team; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team.py', 'test_every_interpreter_consumer_refuses_a_relative_default_before_writing', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team.py', 'test_every_interpreter_consumer_refuses_a_relative_default_before_writing', 'owner', 'hierarchy_team', False):
        ((0,), 'Owner hierarchy_team has lexical candidates hierarchy_team; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team.py', 'test_init_continuation_pin_check_refuses_and_audits_an_invalid_default_spelling', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team.py', 'test_init_continuation_pin_check_refuses_and_audits_an_invalid_default_spelling', 'owner', 'hierarchy_team', False):
        ((0,), 'Owner hierarchy_team has lexical candidates hierarchy_team; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team.py', 'test_interpreter_mismatch_canonicalizes_and_redacts_both_paths_before_truncating', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team.py', 'test_interpreter_mismatch_canonicalizes_and_redacts_both_paths_before_truncating', 'owner', 'hierarchy_team', False):
        ((0,), 'Owner hierarchy_team has lexical candidates hierarchy_team; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team.py', 'test_invalid_default_interpreter_has_its_own_fixed_refusal', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team.py', 'test_invalid_default_interpreter_has_its_own_fixed_refusal', 'owner', 'hierarchy_team', False):
        ((0,), 'Owner hierarchy_team has lexical candidates hierarchy_team; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team.py', 'test_lossy_interpreter_recovery_points_to_the_stored_pin', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team.py', 'test_lossy_interpreter_recovery_points_to_the_stored_pin', 'owner', 'hierarchy_team', False):
        ((0,), 'Owner hierarchy_team has lexical candidates hierarchy_team; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team.py', 'test_low_disk_is_refused', 'callable', 'run.monkeypatch.setattr', True):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_team.py', 'test_missing_pin_recovery_before_recipes_exist_resumes_in_place', 'callable', 'run.monkeypatch.setattr', False):
        ((0, 1), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team.py', 'test_missing_pin_recovery_before_recipes_exist_resumes_in_place', 'owner', 'hierarchy_team', False):
        ((0, 1), 'Owner hierarchy_team has lexical candidates hierarchy_team; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team.py', 'test_missing_pin_recovery_stat_failure_is_a_fixed_refusal', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team.py', 'test_missing_pin_recovery_stat_failure_is_a_fixed_refusal', 'owner', 'hierarchy_team', False):
        ((0,), 'Owner hierarchy_team has lexical candidates hierarchy_team; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team.py', 'test_orchestration_interpreter_is_captured_before_the_parent_directory_changes', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team.py', 'test_orchestration_interpreter_is_captured_before_the_parent_directory_changes', 'owner', 'hierarchy_team', False):
        ((0,), 'Owner hierarchy_team has lexical candidates hierarchy_team; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team.py', 'test_orchestration_interpreter_refuses_bad_text_when_consumed', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team.py', 'test_orchestration_interpreter_refuses_bad_text_when_consumed', 'owner', 'hierarchy_team', False):
        ((0,), 'Owner hierarchy_team has lexical candidates hierarchy_team; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team.py', 'test_orchestration_interpreter_startup_cwd_failure_is_a_fixed_refusal', 'callable', 'run.monkeypatch.setattr', False):
        ((0, 1), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team.py', 'test_orchestration_interpreter_startup_cwd_failure_is_a_fixed_refusal', 'owner', 'hierarchy_team', False):
        ((0, 1), 'Owner hierarchy_team has lexical candidates hierarchy_team; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team.py', 'test_owner_turn_holds_the_wake_marker_until_its_process_finishes', 'callable', 'run.monkeypatch.setattr', True):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_team.py', 'test_status_and_down_allow_a_relative_default_interpreter_without_consuming_it', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team.py', 'test_status_and_down_allow_a_relative_default_interpreter_without_consuming_it', 'owner', 'hierarchy_team', False):
        ((0,), 'Owner hierarchy_team has lexical candidates hierarchy_team; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team.py', 'test_up_uses_the_invoking_orchestration_interpreter_when_the_loop_changes_cwd', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team.py', 'test_up_uses_the_invoking_orchestration_interpreter_when_the_loop_changes_cwd', 'owner', 'hierarchy_team', False):
        ((0,), 'Owner hierarchy_team has lexical candidates hierarchy_team; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'HomesRun.__init__', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'HomesRun.__init__', 'fixture', 'super().__init__(tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'make.factory', 'fixture', 'HomesRun(tmp_path, monkeypatch, root, team)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'make.factory', 'fixture', 'Run(tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_a_user_missing_from_the_password_database_is_refused', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_a_user_missing_from_the_password_database_is_refused', 'owner', 'pwd', False):
        ((0,), 'Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_both_homes_exclude_both_owner_trees_on_claude_plans', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_both_homes_exclude_both_owner_trees_on_claude_plans', 'owner', 'pwd', False):
        ((0,), 'Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_child_processes_and_the_loop_get_the_runs_claude_home', 'callable', 'run.monkeypatch.setattr', False):
        ((0, 1), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_claude_home_in_the_owners_claude_folder_is_refused_by_every_subcommand', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_claude_home_in_the_owners_claude_folder_is_refused_by_every_subcommand', 'owner', 'pwd', False):
        ((0,), 'Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_existing_credentials_owned_by_another_user_are_refused_before_auth', 'callable', 'run.monkeypatch.setattr', True):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_round2_a_claude_home_swap_is_caught_before_status_or_state_save', 'callable', 'run.monkeypatch.setattr', True):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_round2_a_home_swap_after_codex_login_is_caught_before_evidence_or_claude_spawn', 'callable', 'run.monkeypatch.setattr', True):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_round2_a_home_swap_after_the_initial_check_refuses_before_any_host_spawn', 'callable', 'run.monkeypatch.setattr', True):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_round2_codex_only_owner_checks_do_not_gain_inode_alias_handling', 'callable', 'run.monkeypatch.setattr', True):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_round2_errors_saving_login_evidence_or_state_also_clean_up', 'callable', 'run.monkeypatch.setattr', True):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_round2_init_rechecks_the_run_destination_immediately_before_its_first_write', 'callable', 'run.monkeypatch.setattr', True):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_round2_owner_inode_aliases_are_refused_for_every_existing_ancestor', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_round2_owner_inode_aliases_are_refused_for_every_existing_ancestor', 'callable', 'run.monkeypatch.setattr', True):
        ((1,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_round3_a_login_finishing_after_a_completed_down_refuses_and_keeps_teardown_state', 'callable', 'run.monkeypatch.setattr', True):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_round4_root_competing_after_logins_final_reload_keeps_both_bindings', 'callable', 'run.monkeypatch.setattr', True):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_run_destination_checks_the_password_database_home', 'callable', 'run.monkeypatch.setattr', False):
        ((0,), 'Existing run.monkeypatch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/integration/test_hierarchy_team_homes.py', 'test_run_destination_checks_the_password_database_home', 'owner', 'pwd', False):
        ((0,), 'Owner pwd has lexical candidates pwd; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_team_recovery.py', 'run', 'fixture', 'Run(tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/integration/test_hierarchy_team_recovery.py', 'test_owner_turn_retains_its_marker_after_a_lost_reply', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_hierarchy_watch_bridge.py', 'test_async_consumer_unsupported_process_boundary_is_explicit', 'owner', 'os', True):
        ((0,), 'Owner os has lexical candidates os; not a unique module-level import. Includes a shared process module.'),
    ('tests/integration/test_hierarchy_watch_bridge.py', 'test_process_bridge_missing_host_capability_refuses_before_launch', 'owner', 'os', True):
        ((0,), 'Owner os has lexical candidates os; not a unique module-level import. Includes a shared process module.'),
    ('tests/integration/test_hierarchy_watch_bridge.py', 'test_process_provider_missing_platform_support_refuses_before_effects', 'owner', 'hierarchy_watch_bridge.os', True):
        ((0,), 'Owner hierarchy_watch_bridge.os has lexical candidates tools.hierarchy_watch_bridge.os; not a unique module-level import. Includes a shared process module.'),
    ('tests/integration/test_hierarchy_watch_bridge.py', 'test_process_provider_validates_complete_request_before_environment_refusal', 'owner', 'hierarchy_watch_bridge.os', True):
        ((0,), 'Owner hierarchy_watch_bridge.os has lexical candidates tools.hierarchy_watch_bridge.os; not a unique module-level import. Includes a shared process module.'),
    ('tests/integration/test_hierarchy_watch_bridge.py', 'test_stderr_overflow_at_exit_cannot_hide_between_observations', 'owner', 'os', True):
        ((0,), 'Owner os has lexical candidates os; not a unique module-level import. Includes a shared process module.'),
    ('tests/integration/test_hierarchy_watch_bridge.py', 'test_supervisor_expired_run_deadline_never_dispatches', 'owner', 'hierarchy_watch_supervisor', False):
        ((0,), 'Owner hierarchy_watch_supervisor has lexical candidates tools.hierarchy_watch_supervisor; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_watch_bridge.py', 'test_supervisor_run_deadline_bounds_inflight_process', 'owner', 'hierarchy_watch_bridge', False):
        ((0,), 'Owner hierarchy_watch_bridge has lexical candidates tools.hierarchy_watch_bridge; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_watch_bridge.py', 'test_supervisor_run_deadline_bounds_inflight_process', 'owner', 'hierarchy_watch_supervisor', False):
        ((0,), 'Owner hierarchy_watch_supervisor has lexical candidates tools.hierarchy_watch_supervisor; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_hierarchy_watch_bridge.py', 'test_supervisor_run_deadline_bounds_inflight_process', 'owner', 'os', True):
        ((0,), 'Owner os has lexical candidates os; not a unique module-level import. Includes a shared process module.'),
    ('tests/integration/test_hierarchy_watch_supervisor.py', 'test_stop_or_deadline_during_observation_prevents_dispatch', 'owner', 'hierarchy_watch_supervisor.time', True):
        ((0,), 'Owner hierarchy_watch_supervisor.time has lexical candidates tools.hierarchy_watch_supervisor.time; not a unique module-level import. Includes a shared process module.'),
    ('tests/integration/test_no_rule_writes.py', 'repo', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_no_rule_writes.py', 'repo', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/integration/test_no_rule_writes.py', 'test_status_and_doctor_never_rewrite_rules', 'owner', 'doctor', False):
        ((0,), 'Owner doctor has lexical candidates aegis_cli.doctor; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_release_workflow.py', 'launcher_commands', 'owner', 'install_hosts', False):
        ((0, 1), 'Owner install_hosts has lexical candidates aegis_cli.install_hosts; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_governance_inventory_refusal', 'owner', 'governance', False):
        ((0,), 'Owner governance has lexical candidates aegis_sdk.governance; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_governance_validates_landscape', 'owner', 'governance', False):
        ((0,), 'Owner governance has lexical candidates aegis_sdk.governance; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/integration/test_release_workflow.py', 'test_wheel_smoke_packaged_registry_refusal', 'owner', 'registry', False):
        ((0,), 'Owner registry has lexical candidates aegis_mcp.registry; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/conftest.py', '_isolated_user_plane', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/conftest.py', '_no_real_desktop_apps', 'owner', 'hosts', False):
        ((0,), 'Owner hosts has lexical candidates aegis_core.hosts; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/conftest.py', '_no_real_host_cli', 'owner', 'install_hosts', False):
        ((0,), 'Owner install_hosts has lexical candidates aegis_cli.install_hosts; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/conftest.py', '_nothing_above_the_test_tree', 'owner', 'doctor_base', False):
        ((0,), 'Owner doctor_base has lexical candidates aegis_cli.doctor_base; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_approve_cli.py', '_run', 'owner', 'approve', False):
        ((0,), 'Owner approve has lexical candidates aegis_cli.approve; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_approve_cli.py', 'review_repo', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_approve_cli.py', 'review_repo', 'owner', 'approve', False):
        ((0,), 'Owner approve has lexical candidates aegis_cli.approve; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_approve_cli.py', 'signer_repo', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_approve_cli.py', 'signer_repo', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_approve_cli.py', 'test_approve_without_a_terminal_refuses_through_main', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_approve_cli.py', 'test_base_limit_precedes_scanning_or_git', 'owner', 'approve', False):
        ((0,), 'Owner approve has lexical candidates aegis_cli.approve; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_approve_cli.py', 'test_base_subject_failures_are_fixed_refusals', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/cli/test_approve_cli.py', 'test_base_subject_failures_are_fixed_refusals', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/cli/test_approve_cli.py', 'test_base_subject_failures_are_fixed_refusals', 'owner', 'approve', False):
        ((0,), 'Owner approve has lexical candidates aegis_cli.approve; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_approve_cli.py', 'test_dynamic_approve_diagnostics_are_safe_to_display', 'callable', 'patch.setattr', False):
        ((0, 1, 2, 3, 4, 5, 6), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/cli/test_approve_cli.py', 'test_dynamic_approve_diagnostics_are_safe_to_display', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/cli/test_approve_cli.py', 'test_exemption_path_read_failure_is_a_fixed_refusal', 'owner', 'approve', False):
        ((0,), 'Owner approve has lexical candidates aegis_cli.approve; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_approve_cli.py', 'test_exemption_refuses_injected_current_governance_approval', 'owner', 'approve', False):
        ((0,), 'Owner approve has lexical candidates aegis_cli.approve; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_approve_cli.py', 'test_exemption_refuses_nonprintable_reasons_before_any_review', 'owner', 'approve', False):
        ((0, 1), 'Owner approve has lexical candidates aegis_cli.approve; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_approve_cli.py', 'test_exemption_review_cannot_be_rewritten_by_caller_text', 'owner', 'approve', False):
        ((0,), 'Owner approve has lexical candidates aegis_cli.approve; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_approve_cli.py', 'test_nonprintable_base_is_refused_before_git', 'owner', 'approve', False):
        ((0, 1), 'Owner approve has lexical candidates aegis_cli.approve; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_approve_cli.py', 'test_review_escapes_format_controls_from_git_and_environment', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_approve_cli.py', 'test_review_preserves_signing_refusals', 'owner', 'approve', False):
        ((0,), 'Owner approve has lexical candidates aegis_cli.approve; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_check_baseline.py', '_no_ci_base', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_baseline.py', 'repo', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_baseline.py', 'test_base_outside_git_is_a_usage_error', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_baseline.py', 'test_write_baseline_works_outside_git', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_calibration.py', '_dated', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_calibration.py', '_dated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_calibration.py', 'repo', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_calibration.py', 'repo', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_calibration.py', 'repo', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_calibration.py', 'test_outside_an_aegis_workspace_no_aegis_directory_is_created', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_calibration.py', 'test_outside_an_aegis_workspace_no_aegis_directory_is_created', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_card_partition.py', '_no_ci_base', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_card_partition.py', 'repo', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_card_partition.py', 'test_the_card_does_not_need_git', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_card_partition.py', 'test_the_card_follows_the_workspace_flag', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_flags.py', '_env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_flags.py', '_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_flags.py', 'repo', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_flags.py', 'test_perf_on_a_checkout_that_is_not_the_head_is_unverified_and_runs_nothing', 'owner', 'perf_check', False):
        ((0,), 'Owner perf_check has lexical candidates aegis_core.verification.perf_check; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_check_ci_flags.py', 'test_the_default_base_is_the_repository_asked_about_with_git_dir_exported_for_another', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_perf_verdict.py', '_env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_perf_verdict.py', '_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_perf_verdict.py', 'repo', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_perf_verdict.py', 'test_a_trailer_only_failure_is_in_the_step_summary', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_perf_verdict.py', 'test_a_trailer_only_failure_is_in_the_step_summary', 'owner', 'checkrun', False):
        ((0,), 'Owner checkrun has lexical candidates aegis_core.checkrun; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_check_ci_perf_verdict.py', 'test_a_workspace_subdirectory_resolves_as_the_other_modes_do', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_perf_verdict.py', 'test_an_unwritable_step_summary_is_one_note_and_the_same_exit', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_perf_verdict.py', 'test_the_step_summary_is_appended_to', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_perf_verdict.py', 'test_the_step_summary_shows_the_perf_result', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_perf_verdict.py', 'test_the_verdict_line_the_json_status_and_the_exit_code_agree', 'callable', 'm.setattr', False):
        ((0, 1), 'Existing m.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/cli/test_check_ci_perf_verdict.py', 'test_the_verdict_line_the_json_status_and_the_exit_code_agree', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/cli/test_check_ci_push.py', '_env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_push.py', '_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_push.py', 'event_file', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_push.py', 'push_event', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_push.py', 'test_a_pull_request_run_still_compares_and_fails_an_unapproved_weakening', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_push.py', 'test_no_exec_on_pull_request_target_hands_the_pull_request_to_the_weakening_check', 'owner', 'rule_integrity', False):
        ((0,), 'Owner rule_integrity has lexical candidates aegis_core.rule_integrity; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_check_ci_regression.py', '_env', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1, 2, 3), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_regression.py', '_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_ci_regression.py', '_fake_pytest_and_rerun', 'owner', 'checkrun', False):
        ((0,), 'Owner checkrun has lexical candidates aegis_core.checkrun; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_check_ci_regression.py', '_fake_pytest_and_rerun', 'owner', 'testexec', False):
        ((0,), 'Owner testexec has lexical candidates aegis_core.testexec; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_check_ci_regression.py', 'test_a_git_failure_of_the_t5_reads_exits_1_with_the_git_error', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_check_ci_regression.py', 'test_a_rejected_exemption_shows_its_code_and_approve_agrees_with_ci', 'owner', 'approve', False):
        ((0,), 'Owner approve has lexical candidates aegis_cli.approve; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_check_ci_regression.py', 'test_ci_strict_is_a_usage_error_and_runs_nothing', 'owner', 'subprocess', True):
        ((0,), 'Owner subprocess has lexical candidates subprocess; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/cli/test_check_explain.py', 'test_oversized_fields_never_reach_the_sanitizer', 'owner', 'aegis_cli', False):
        ((0,), 'Owner aegis_cli has lexical candidates aegis_cli; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_check_hook_gate.py', '_non_numeric_content_size', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_check_hook_gate.py', 'blob_reads', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_check_hook_gate.py', 'repo', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_hook_gate.py', 'test_a_workspace_below_the_git_toplevel_checks_its_own_files', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_hook_gate.py', 'test_a_workspace_the_enclosing_repository_does_not_track_enforces_its_own_rules', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_hook_gate.py', 'test_hook_outside_a_git_work_tree_fails_closed', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_lane.py', '_no_ci_base', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_lane.py', 'repo', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_layer1_report_formats.py', '_env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_layer1_report_formats.py', '_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_layer1_report_formats.py', 'test_a_blocking_checkpoint_issue_fails_the_summary', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_layer1_report_formats.py', 'test_the_step_summary_says_failed_and_names_the_location', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_modes.py', 'repo', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_modes.py', 'repo', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_record_ci_modes.py', '_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_record_cli.py', '_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_scanners.py', '_ci', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_scanners.py', 'env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_scanners.py', 'env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_scanners.py', 'test_a_missing_scanner_is_unverified_reported_and_never_blocks', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_scanners.py', 'test_a_scanner_the_repository_planted_never_runs', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_t7_wiring.py', '_home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_t7_wiring.py', '_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_check_t7_wiring.py', 'test_a_failure_to_run_the_scan_fails_the_check_closed', 'owner', 'pack', False):
        ((0,), 'Owner pack has lexical candidates aegis_core.verification.security_pack; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_check_t7_wiring.py', 'test_a_trailer_recorded_before_the_wiring_diverges_as_documented', 'owner', 'testexec', False):
        ((0,), 'Owner testexec has lexical candidates aegis_core.testexec; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_check_t7_wiring.py', 'test_the_hook_and_the_record_take_a_binary_file_and_note_one_over_the_size_cap', 'owner', 'runner', False):
        ((0,), 'Owner runner has lexical candidates aegis_core.verification.runner; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_check_t7_wiring.py', 'test_the_hook_names_the_index_cap_when_uncovered_native_content_was_not_checked', 'owner', 'runner', False):
        ((0,), 'Owner runner has lexical candidates aegis_core.verification.runner; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli.py', 'TestCLIDispatch.test_subcommand_runs_without_crash', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli.py', 'TestCLIDispatch.test_subcommand_runs_without_crash', 'owner', 'doctor', False):
        ((0,), 'Owner doctor has lexical candidates aegis_cli.doctor; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli.py', 'test_command_exception_is_reported_and_exits_1', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli.py', 'test_hook_run_decides_from_the_payload_where_no_workspace_attaches', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli.py', 'test_hook_run_decides_from_the_payload_where_no_workspace_attaches', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli.py', 'test_hook_run_help_goes_through_the_parser', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli.py', 'test_hook_run_never_reaches_a_usage_error', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_check.py', 'TestHook.test_hook_fails_when_a_layer1_tool_raises', 'owner', 'call_graph', False):
        ((0,), 'Owner call_graph has lexical candidates aegis_core.verification.call_graph; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli_check.py', 'TestHook.test_hook_fails_when_layer1_cannot_run', 'owner', 'runner', False):
        ((0,), 'Owner runner has lexical candidates aegis_core.verification.runner; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli_check.py', 'TestLayer1.test_mutation_testing_runs_only_behind_layer2', 'owner', 'runner', False):
        ((0,), 'Owner runner has lexical candidates aegis_core.verification.runner; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli_check.py', 'TestLayer2.test_env_backend_ship_passes', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_check.py', 'TestLayer2.test_flag_beats_env', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_check.py', 'TestVendorAdvisory._run', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_check.py', 'TestVendorAdvisory._run', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_check.py', 'TestVendorAdvisory.test_a_malformed_user_config_never_fails_layer2', 'fixture', "self._run(ws, llm, monkeypatch, capsys, '{not json', 'claude-code')", False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/cli/test_cli_check.py', 'TestVendorAdvisory.test_text_prints_the_vendor_line_only_when_there_is_one', 'fixture', 'self._run(ws, llm, monkeypatch, capsys, \'{"arbiter_vendor": "claude"}\', \'claude-code\', \'text\')', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/cli/test_cli_check.py', 'TestVendorAdvisory.test_text_prints_the_vendor_line_only_when_there_is_one', 'fixture', 'self._run(ws, llm, monkeypatch, capsys, \'{"arbiter_vendor": "gemini"}\', \'claude-code\', \'text\')', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/cli/test_cli_check.py', 'TestVendorAdvisory.test_the_advisory_compares_the_declared_vendor_with_the_host', 'fixture', 'self._run(ws, llm, monkeypatch, capsys, config, client)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/cli/test_cli_check.py', '_no_ambient_backend', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_a_pin_hold_without_json_is_one_line_on_stderr', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_a_pin_that_disagrees_with_the_target_holds_before_the_command_runs', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_a_pin_that_disagrees_with_the_target_is_a_machine_readable_hold', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_a_pin_that_is_not_a_workspace_is_an_error', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_a_pin_that_is_not_a_workspace_is_an_error', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_a_pin_to_another_repository_holds_instead_of_acting_on_it', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_a_pin_to_another_repository_holds_instead_of_acting_on_it', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_cwd_inside_a_nested_repo_never_syncs_the_outer_workspace', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_doctor_still_runs_from_home', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_home_is_never_the_workspace', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_migrate_and_uninstall_refuse_home', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_migrate_below_home_never_plans_the_user_plane', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_migrate_never_walks_above_the_git_toplevel', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_scan_from_home_never_scans_the_user_layer_as_a_project', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_scan_hold_without_json_is_one_line_on_stderr', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_scan_with_a_pin_that_agrees_with_the_target_scans_the_pin', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_scan_with_a_pin_that_agrees_with_the_target_scans_the_pin', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_scan_with_a_pin_that_disagrees_with_the_target_holds_and_scans_nothing', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_scan_with_a_pin_that_disagrees_with_the_target_holds_and_scans_nothing', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_global_workspace.py', 'test_uninstall_below_home_targets_the_project_not_the_user_plane', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_helpers.py', 'isolated', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_helpers.py', 'isolated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_migrate.py', 'loose_ledger', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_migrate.py', 'loose_ledger', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_migrate.py', 'test_a_chmod_that_fails_is_reported_as_not_tightened', 'owner', 'storage', False):
        ((0,), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli_migrate.py', 'test_a_refusal_found_only_when_applying_is_a_json_report_and_exit_1', 'owner', 'migrate', False):
        ((0,), 'Owner migrate has lexical candidates aegis_core.migrate; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli_migrate.py', 'test_config_that_grows_before_apply_refuses_with_exit_1', 'owner', 'migrate', False):
        ((0,), 'Owner migrate has lexical candidates aegis_core.migrate; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli_msg.py', 'test_argon_uninitialized_repository_is_unchanged', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_msg.py', 'test_invalid_read_options_have_identical_frontend_refusals_before_io', 'owner', 'server', False):
        ((1,), 'Owner server has lexical candidates aegis_mcp.server; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli_msg.py', 'test_invalid_read_options_have_identical_frontend_refusals_before_io', 'owner', 'storage', False):
        ((0,), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli_msg.py', 'test_msg_denied_workspace_has_distinct_fixed_error', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_msg.py', 'test_msg_invalid_explicit_path_keeps_refusal_with_uninitialized_pin', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Merged-tip fixture monkeypatch.setenv operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/cli/test_cli_msg.py', 'test_msg_pin_diagnostic_failure_preserves_fixed_refusal', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Merged-tip fixture monkeypatch.setenv operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/cli/test_cli_msg.py', 'test_msg_pin_diagnostic_failure_preserves_fixed_refusal', 'owner', 'binding', False):
        ((0,), 'Merged-tip owner binding has static candidates aegis_core.workspace.binding; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/cli/test_cli_msg.py', 'test_msg_pin_refusals_have_fixed_guidance', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Merged-tip fixture monkeypatch.setenv operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/cli/test_cli_msg.py', 'test_workspace_pin_conflict_is_fixed_json', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_msg.py', 'workspace', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_msg.py', 'workspace', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_package.py', 'fake_aegis', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_package.py', 'test_without_an_installed_script_the_isolated_runner_is_used', 'owner', 'install_hosts', False):
        ((0,), 'Owner install_hosts has lexical candidates aegis_cli.install_hosts; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli_removed_commands.py', 'test_json_flag_is_honoured_before_or_after_the_command', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_removed_commands.py', 'test_surviving_global_flags_still_parse', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule.py', 'test_rule_archive', 'callable', 'patch', False):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/cli/test_cli_rule.py', 'test_rule_archive_reports_the_rules_it_moved_before_an_archive_fails', 'owner', 'selection', False):
        ((0, 1), 'Owner selection has lexical candidates aegis_core.lifecycle.selection; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli_rule.py', 'test_rule_archive_says_why_a_candidate_was_not_archived', 'owner', 'selection', False):
        ((0,), 'Owner selection has lexical candidates aegis_core.lifecycle.selection; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli_rule.py', 'test_rule_create_binds_type_body_file_and_workspace', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule.py', 'test_rule_create_without_type_makes_a_trap', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule.py', 'test_rule_demote_and_force_demote', 'callable', 'patch', False):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/cli/test_cli_rule.py', 'test_rule_list_marks_only_expired_rules', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule.py', 'test_rule_list_takes_workspace_after_the_action', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule.py', 'test_rule_list_type_filters_and_rejects_an_unknown_type', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule.py', 'test_rule_promote_and_force_promote', 'callable', 'patch', False):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/cli/test_cli_rule_create.py', 'elsewhere', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_create.py', 'enclosed_home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_create.py', 'enclosed_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_create.py', 'home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_create.py', 'home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_create.py', 'repo', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_create.py', 'test_create_from_subdirectory_of_initialized_repo', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_create.py', 'test_explicit_home_workspace_is_rejected', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_create.py', 'test_explicit_initialized_workspace_creates_rule', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_create.py', 'test_explicit_workspace_without_aegis_fails_and_writes_nothing', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_create.py', 'test_implicit_workspace_never_walks_up_into_home', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_create.py', 'test_json_mode_reports_workspace_error_on_stdout', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_create.py', 'test_resolution_never_crosses_the_git_toplevel', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_create.py', 'test_rule_list_does_not_resolve_to_home', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_create.py', 'test_the_user_rule_layer_never_makes_home_the_rule_workspace', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_duplicate_id.py', 'repo', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_duplicate_id.py', 'repo', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_rule_duplicate_id.py', 'repo', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_sanitize_c1.py', 'test_verify_out_of_tree_warning_sanitized', 'callable', 'patch', True):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/cli/test_cli_scan.py', 'slot_ws', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_scan.py', 'slot_ws', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_scan.py', 'slot_ws', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_scan.py', 'test_a_workspace_error_prints_no_terminal_control_sequences_from_the_directory_name', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_scan.py', 'test_outside_an_aegis_workspace_exits_2', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_scan.py', 'test_paths_are_taken_relative_to_the_working_directory', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_scan.py', 'ws', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_sync.py', 'labelled', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_sync.py', 'labelled', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_sync.py', 'test_apply_moves_only_the_rule_with_min_n_verdicts', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_sync.py', 'test_outside_an_aegis_workspace_sync_exits_2', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_sync.py', 'test_public_sync_warning_badges_respect_output_context', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_sync.py', 'test_public_sync_warning_badges_respect_output_context', 'owner', 'sys.stdout', False):
        ((0,), 'Owner sys.stdout has lexical candidates sys.stdout; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli_sync.py', 'test_sync_error_and_advisory_paths_keep_plain_badges', 'owner', 'sys.stdout', False):
        ((0,), 'Owner sys.stdout has lexical candidates sys.stdout; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli_sync.py', 'test_sync_keeps_long_next_actions_and_redacts_diagnostics', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_sync.py', 'test_sync_keeps_long_next_actions_and_redacts_diagnostics', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_sync.py', 'test_sync_keeps_long_next_actions_and_redacts_diagnostics', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli_sync.py', 'ws', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_team.py', 'test_metrics_text_before_git_2_38_says_unavailable', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_cli_team.py', 'test_outside_a_git_repository_team_is_a_usage_error', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_team.py', 'test_release_json_names_the_caller', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_team.py', 'ws', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_team_status.py', 'test_status_from_linked_worktree_observes_the_repository', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_team_status.py', 'test_status_handles_git_timeout_as_unavailable_evidence', 'owner', 'subprocess', True):
        ((0,), 'Owner subprocess has lexical candidates subprocess; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/cli/test_cli_verify.py', 'TestResolveTargetFilesFallbacks.test_a_clean_tree_whose_base_diffs_are_empty_is_a_clean_repository', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_verify.py', 'TestResolveTargetFilesFallbacks.test_hook_without_git_fails_closed', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_verify.py', 'TestResolveTargetFilesFallbacks.test_resolve_target_files_clean_tree_branch_diff_fallback', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_verify.py', 'TestResolveTargetFilesFallbacks.test_resolve_target_files_custom_github_base_ref_prefers_origin', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_verify.py', 'TestResolveTargetFilesFallbacks.test_resolve_target_files_github_base_ref', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_verify.py', 'TestResolveTargetFilesFallbacks.test_resolve_target_files_head_parent_fallback', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_verify.py', 'TestResolveTargetFilesFallbacks.test_resolve_target_files_preserves_existing_files_when_github_base_ref_set', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_verify.py', 'TestResolveTargetFilesFallbacks.test_resolve_target_files_single_commit_clean_tree_has_no_diff_base', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_verify.py', 'TestResolveTargetFilesFallbacks.test_resolve_target_files_without_git', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_verify.py', 'TestRunVerifyNamespaces.test_namespace_without_full_runs_layer1_only', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_cli_verify.py', 'TestVerifyLayer2Execution.test_failed_test_discovery_fails_without_fp_rows', 'owner', 'verify', False):
        ((0,), 'Owner verify has lexical candidates aegis_cli.verify; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor.py', '_rust_project_with_python3_driver', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'isolated_hosts', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'isolated_hosts', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_an_aegis_on_an_absolute_path_entry_inside_the_workspace_counts_and_says_where', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_an_aegis_reached_through_a_relative_path_entry_is_not_the_cli', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_an_aegis_reached_through_a_relative_path_entry_is_not_the_cli', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_check_ast_drivers_missing_extension_slot_warns_and_fixes', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_check_ast_drivers_with_valid_and_invalid_slots', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_check_ast_drivers_with_valid_and_invalid_slots', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2, 3, 4), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_cli_check_never_says_aegis_is_where_only_an_unrelated_script_is', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_cli_check_prints_zsh_remedy_when_unresolvable', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_cli_check_prints_zsh_remedy_when_unresolvable', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_cli_check_silent_remedy_when_resolvable', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_doctor_fails_closed_on_a_rule_that_cannot_be_served', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_doctor_fails_when_no_rule_is_served', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_doctor_json_mode_and_warning_counts', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_doctor_returns_one_on_failure', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_doctor_returns_zero_in_valid_env', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_doctor_warns_when_ast_drivers_unresolvable', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_doctor_warns_when_ast_drivers_unresolvable', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_drivers_fix_provisions_after_a_backup', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_public_doctor_badges_respect_output_context', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_public_doctor_path_hints_respect_output_context', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_public_doctor_path_hints_respect_output_context', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_public_doctor_path_hints_respect_output_context', 'owner', 'pathcheck', False):
        ((0, 1, 2, 3), 'Owner pathcheck has lexical candidates aegis_cli.pathcheck; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor.py', 'test_public_doctor_renderer_paths', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_public_driver_repair_result_respects_output_context', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_public_driver_repair_result_respects_output_context', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_public_github_ci_warning_respects_output_context', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_run_doctor_drivers_flag', 'callable', 'patch', False):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/cli/test_doctor.py', 'test_run_doctor_with_fix_flag', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor.py', 'test_run_doctor_without_fix_flag_does_not_provision', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_ast_drivers.py', 'project', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_ast_drivers.py', 'project', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2, 3, 4), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_ast_drivers.py', 'test_repair_hint_keeps_inspection_scope', 'owner', 'doctor', False):
        ((0,), 'Owner doctor has lexical candidates aegis_cli.doctor; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_ast_drivers.py', 'test_repair_hint_keeps_inspection_scope', 'owner', 'doctor._repair', False):
        ((0,), 'Owner doctor._repair has lexical candidates aegis_cli.doctor._repair; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_ast_drivers.py', 'test_repair_hint_keeps_inspection_scope', 'owner', 'gobuild', False):
        ((0,), 'Owner gobuild has lexical candidates aegis_core.ast.gobuild; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_fix.py', 'Env.__init__', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_fix.py', 'Env.__init__', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_fix.py', 'env', 'fixture', 'Env(tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/cli/test_doctor_fix.py', 'test_a_private_config_swapped_for_a_symlink_after_the_check_stays_owner_only', 'owner', 'storage', False):
        ((0,), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_fix.py', 'test_fix_replaces_a_file_swapped_for_a_symlink_after_the_check_and_spares_the_link_target', 'owner', 'storage', False):
        ((0,), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_host_hooks.py', 'Env.__init__', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_host_hooks.py', 'Env.__init__', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_host_hooks.py', 'Env.__init__', 'owner', 'doctor', False):
        ((0,), 'Owner doctor has lexical candidates aegis_cli.doctor; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_host_hooks.py', '_hook_repo', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_host_hooks.py', 'env', 'fixture', 'Env(tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'Env.__init__', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'Env.__init__', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'Env.__init__', 'owner', 'doctor', False):
        ((0,), 'Owner doctor has lexical candidates aegis_cli.doctor; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'TestHostRowPins.test_a_binary_only_inside_the_workspace_is_unknown_and_never_run', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', '_rows_and_direct_rows', 'owner', 'doctor_findings', False):
        ((0, 1), 'Owner doctor_findings has lexical candidates aegis_cli.doctor_findings; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_hosts.py', '_unreachable', 'owner', 'management', False):
        ((0,), 'Owner management has lexical candidates aegis_cli.hooks.management; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'env', 'fixture', 'Env(tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_a_bare_registered_command_found_only_where_doctor_does_not_look_is_unknown', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_a_bare_registered_command_found_only_where_doctor_does_not_look_is_unknown', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_a_codex_in_the_workspace_is_never_found_or_run', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_a_codex_in_the_workspace_is_never_found_or_run', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_a_dot_claude_md_in_home_counts_when_claude_keeps_its_config_elsewhere', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_a_hook_status_that_raises_leaves_the_floor_unknown_and_the_check_raises_it', 'owner', 'doctor_findings', False):
        ((0,), 'Owner doctor_findings has lexical candidates aegis_cli.doctor_findings; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_a_hook_status_that_raises_leaves_the_floor_unknown_and_the_check_raises_it', 'owner', 'management', False):
        ((0,), 'Owner management has lexical candidates aegis_cli.hooks.management; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_a_host_binary_found_only_inside_the_workspace_is_reported_never_run', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_a_host_binary_reachable_only_through_a_relative_entry_is_unknown_never_run', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_a_host_binary_reachable_only_through_a_relative_entry_is_unknown_never_run', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_a_relative_entry_holding_no_host_binary_is_plainly_missing', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_a_relative_path_entry_never_names_a_codex_even_outside_the_workspace', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_a_relative_path_entry_never_names_a_codex_even_outside_the_workspace', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_a_relative_registry_root_never_matches_the_workspace', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_an_app_that_doctor_cannot_ask_is_auth_unknown_never_ok', 'owner', 'table', False):
        ((0,), 'Owner table has lexical candidates aegis_core.hosts; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_an_installed_app_counts_as_installed_without_a_cli', 'owner', 'table', False):
        ((0,), 'Owner table has lexical candidates aegis_core.hosts; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_no_unmigrated_state_means_no_upgrade_warning', 'owner', 'discovery', False):
        ((0,), 'Owner discovery has lexical candidates aegis_core.workspace.discovery; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_on_windows_host_cli_children_do_not_search_the_current_directory', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_on_windows_host_cli_children_do_not_search_the_current_directory', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_on_windows_host_cli_children_do_not_search_the_current_directory', 'owner', 'doctor.subprocess', True):
        ((0,), 'Owner doctor.subprocess has lexical candidates aegis_cli.doctor.subprocess; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_on_windows_host_cli_children_do_not_search_the_current_directory', 'owner', 'doctor.sys', True):
        ((0, 1), 'Owner doctor.sys has lexical candidates aegis_cli.doctor.sys; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_one_run_reads_the_hook_status_once_for_the_floor_and_the_check', 'owner', 'management', False):
        ((0,), 'Owner management has lexical candidates aegis_cli.hooks.management; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_pending_worktree_ledger_rows_are_a_warning_that_names_aegis_migrate', 'owner', 'migrate', False):
        ((0, 1), 'Owner migrate has lexical candidates aegis_core.migrate; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_the_codex_probe_runs_the_absolute_codex_outside_the_workspace', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_the_codex_probe_runs_the_absolute_codex_outside_the_workspace', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_the_home_directory_is_never_a_governed_workspace', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_the_home_directory_is_never_checked_for_unmigrated_state', 'owner', 'discovery', False):
        ((0,), 'Owner discovery has lexical candidates aegis_core.workspace.discovery; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_the_mcp_launcher_check_runs_no_python3_and_no_aegis_mcp', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_the_mcp_launcher_check_runs_no_python3_and_no_aegis_mcp', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_the_users_own_claude_md_never_shadows_agents_md', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_under_a_symlinked_home_the_users_claude_md_leaves_the_reach_unknown', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_hosts.py', 'test_unmigrated_v3_state_names_the_files_and_manual_archive_action', 'owner', 'discovery', False):
        ((0,), 'Owner discovery has lexical candidates aegis_core.workspace.discovery; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_doctor_mcp_launcher.py', 'test_with_path_unset_doctor_reports_the_launcher_init_registers', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_polyglot.py', 'go_project', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_polyglot.py', 'isolated_hosts', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_doctor_polyglot.py', 'test_doctor_cli_fix_flag', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_env_hermeticity.py', 'test_a_test_can_still_set_one_explicitly', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_hook_ergonomics.py', 'TestHybridDispatcher.test_dispatch_safety_gate', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_hook_install_hosts.py', 'cli_env', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_hook_install_hosts.py', 'cli_env', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_hook_install_hosts.py', 'env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_hook_install_hosts.py', 'env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_hook_install_hosts.py', 'test_a_write_that_fails_after_the_checks_names_the_removals_already_made', 'owner', 'install_hosts', False):
        ((0,), 'Owner install_hosts has lexical candidates aegis_cli.install_hosts; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_hook_install_hosts.py', 'test_cli_without_any_aegis_found_refuses', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_hook_install_hosts.py', 'test_cli_without_host_still_manages_the_git_hook', 'owner', 'runtime', False):
        ((0,), 'Owner runtime has lexical candidates aegis_cli.hooks.runtime; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_hook_pinned_interpreter.py', '_init', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_hook_pinned_interpreter.py', '_init', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_hook_placement.py', 'test_aegis_hook_install_exits_1_for_a_python_hook', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_hook_placement.py', 'test_hook_status_text_names_an_unreachable_block', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_hook_run.py', '_counted', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/cli/test_hook_run.py', '_counted', 'callable', 'patch.setattr', True):
        ((1, 2), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/cli/test_hook_run.py', '_counted', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/cli/test_hook_run.py', 'test_any_internal_error_exits_0_silently', 'owner', 'command_safety', False):
        ((0,), 'Owner command_safety has lexical candidates aegis_core.command_safety; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_init.py', 'TestInitSkills.test_a_packaged_skill_that_cannot_be_projected_stops_init', 'owner', 'skills_sync', False):
        ((0,), 'Owner skills_sync has lexical candidates aegis_cli.skills_sync; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_init.py', 'TestRepositoryPlaneChecks.test_a_write_error_after_the_check_names_what_was_already_written', 'owner', 'init_mod', False):
        ((0,), 'Owner init_mod has lexical candidates aegis_cli.init; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_init.py', 'TestRuleSourceLocator.test_a_broken_install_without_the_data_is_reported_not_guessed', 'owner', 'scaffolding', False):
        ((0,), 'Owner scaffolding has lexical candidates aegis_core.scaffolding; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_init.py', 'TestRuleSourceLocator.test_a_top_level_rules_package_on_sys_path_is_never_imported_or_read', 'fixture', 'monkeypatch.syspath_prepend', False):
        ((0,), 'Fixture syspath_prepend operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_init.py', 'TestRuleSourceLocator.test_a_top_level_rules_package_on_sys_path_is_never_imported_or_read', 'owner', 'sys.modules', True):
        ((0,), 'Nested sys import; deleting rules from the shared sys.modules dictionary must remain in the census.'),
    ('tests/unit/cli/test_init.py', 'TestRunInitPins.test_a_failed_registration_prints_its_error_then_the_outcome', 'owner', 'init_module', False):
        ((0,), 'Owner init_module has lexical candidates aegis_cli.init; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_init.py', 'TestRunInitPins.test_a_failed_registration_prints_its_error_then_the_outcome', 'owner', 'pathcheck', False):
        ((0,), 'Owner pathcheck has lexical candidates aegis_cli.pathcheck; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_init.py', 'TestRunInitPins.test_a_real_run_prints_the_outcome_the_card_and_then_the_path_hint', 'owner', 'init_module', False):
        ((0,), 'Owner init_module has lexical candidates aegis_cli.init; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_init.py', 'TestRunInitPins.test_a_real_run_prints_the_outcome_the_card_and_then_the_path_hint', 'owner', 'pathcheck', False):
        ((0,), 'Owner pathcheck has lexical candidates aegis_cli.pathcheck; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_init.py', 'TestRunInitPins.test_every_other_path_finishes_once_with_its_status', 'owner', 'init_module', False):
        ((0,), 'Owner init_module has lexical candidates aegis_cli.init; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_init.py', 'TestSharedHooksDirectory.git_on_path', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_init.py', 'failing_codex', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_init.py', 'failing_codex', 'owner', 'install_hosts', False):
        ((0,), 'Owner install_hosts has lexical candidates aegis_cli.install_hosts; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_init.py', 'finish_calls', 'owner', 'Report', False):
        ((0,), 'Owner Report has lexical candidates aegis_cli.init_views.Report; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_init.py', 'project', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_init.py', 'test_a_hooks_directory_linked_out_of_the_repository_is_named_as_a_link', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_init_card.py', 'project', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_init_card.py', 'test_a_card_that_cannot_be_built_is_a_warning_not_a_failure', 'owner', 'card', False):
        ((0,), 'Owner card has lexical candidates aegis_core.card; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_init_hosts.py', 'TestExperimentalHosts.test_an_event_that_cannot_be_recorded_never_fails_init', 'owner', 'events', False):
        ((0,), 'Owner events has lexical candidates aegis_core.events; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_init_hosts.py', 'env', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_insight_capture_config.py', '_with_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_insight_capture_config.py', 'env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_insight_capture_config.py', 'env', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_insight_capture_config.py', 'test_a_user_config_inside_the_workspace_is_ignored', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_insight_capture_config.py', 'test_a_user_config_inside_the_workspace_is_ignored', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_insight_capture_config.py', 'test_off_holds_when_the_session_directory_is_home_or_above_it', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_insight_hook_cost.py', 'fingerprints', 'owner', 'rule_inventory', False):
        ((0,), 'Owner rule_inventory has lexical candidates aegis_core.rule_inventory; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_insight_hook_cost.py', 'home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_insight_hook_cost.py', 'home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_insight_hook_launcher.py', 'env', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_insight_hook_launcher.py', 'env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_insight_hook_launcher.py', 'env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_insight_hook_launcher.py', 'test_relative_config_dir_is_ignored', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_install_hosts.py', 'TestHostCliRunner.test_runs_without_shell_stdin_or_the_callers_cwd', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_install_hosts.py', 'TestRepositoryExecutablesAreNeverRun.repo', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_install_hosts.py', 'TestRepositoryExecutablesAreNeverRun.test_relative_and_empty_path_entries_are_skipped', 'fixture', 'self._assert_nothing_from(repo, path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/cli/test_install_hosts.py', 'TestRepositoryExecutablesAreNeverRun.test_the_current_directory_is_not_searched_on_windows', 'fixture', 'self._assert_nothing_from(repo, repo.empty, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/cli/test_install_hosts.py', 'TestWindowsLookup.windows', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_install_hosts.py', 'TestWorkspaceRegistry.test_a_stored_root_the_server_skips_never_matches_and_is_kept', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_language_capabilities.py', 'project', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_language_capabilities.py', 'test_runner_data_refuses_paths_that_cannot_be_safely_displayed', 'owner', 'language_capabilities', False):
        ((0,), 'Owner language_capabilities has lexical candidates aegis_cli.language_capabilities; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_local_promotion_decay.py', 'TestPromotionZeroTriggerGuard.test_normalize_fitness_high_triggers_preserves_data', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_native_driver_diagnostics.py', 'test_doctor_and_card_report_native_js_ready_without_node', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_no_home.py', 'root', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_no_home.py', 'root', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_pathcheck.py', 'mac', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_pathcheck.py', 'mac', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_pathcheck.py', 'mac', 'owner', 'pathcheck.sys', True):
        ((0,), 'Owner pathcheck.sys has lexical candidates aegis_cli.pathcheck.sys; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/cli/test_pathcheck.py', 'mac', 'owner', 'pathcheck.sysconfig', False):
        ((0,), 'Owner pathcheck.sysconfig has lexical candidates aegis_cli.pathcheck.sysconfig; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_pathcheck.py', 'test_build_hint_by_default_never_counts_an_aegis_behind_a_relative_entry', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_pathcheck.py', 'test_off_macos_the_library_dir_is_never_a_candidate', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', '_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_accepts_only_hash_values_from_one_combined_query', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_accepts_only_hash_values_from_one_combined_query', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_authority_above_the_cut_is_byte_identical_and_silent', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_bounds_the_authority_scan_after_the_cut', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Merged-tip fixture monkeypatch.chdir operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_checks_the_row_then_preserves_each_authority', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_closes_a_failed_bounded_read_without_echoing_input', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_comment_config_error_has_one_fixed_notice', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_comment_config_error_has_one_fixed_notice', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_does_not_mistake_a_line_fragment_for_column_zero_authority', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Merged-tip fixture monkeypatch.chdir operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_judges_only_the_candidate_message', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_missing_or_oversized_message_stays_unchanged', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_notices_each_authority_name_below_the_cut', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Merged-tip fixture monkeypatch.chdir operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_publish_failure_has_one_fixed_notice', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_publish_failure_has_one_fixed_notice', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_refuses_an_unproved_cut_marker', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_refuses_malformed_or_oversized_comment_query_output', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_refuses_malformed_or_oversized_comment_query_output', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_refuses_unproved_hash_cut_lines_without_changing_bytes', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Merged-tip fixture monkeypatch.chdir operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_requires_every_comment_key_to_be_hash', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_scan_cap_stops_reads_and_closes_the_stream', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_scans_only_for_authority_after_the_cut_line', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Merged-tip fixture monkeypatch.chdir operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_scans_only_for_authority_after_the_cut_line', 'owner', 'gitsafe', False):
        ((0,), 'Merged-tip owner gitsafe has static candidates aegis_core.gitsafe; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_unsupported_comment_character_has_one_fixed_notice', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_uses_the_portable_helper_and_preserves_authority_bytes', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_uses_the_portable_helper_and_preserves_authority_bytes', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_without_a_passing_row_never_reads_comment_config', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_without_a_passing_row_never_reads_comment_config', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_prepare_commit_msg.py', 'test_hook_without_a_passing_row_or_for_skipped_sources_is_silent', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_python_history_encoding.py', 'repo', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_python_history_encoding.py', 'repo', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'review_ws', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'status_ws', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'status_ws', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_a_corrupt_insights_log_still_exits_zero_silently', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_a_signed_trailer_over_the_typed_text_gives_h_even_when_redaction_changes_it', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_a_signed_trailer_over_the_typed_text_gives_h_even_when_redaction_changes_it', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_hook_entrypoint_exits_zero_with_empty_output_and_a_heartbeat_per_prompt', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_hook_entrypoint_exits_zero_with_empty_output_and_a_heartbeat_per_prompt', 'owner', 'core_rules', False):
        ((0,), 'Owner core_rules has lexical candidates aegis_core.rules; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_insight_add_keeps_a_comma_path_whole_and_stores_absolute_paths_relative', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_insight_add_prints_the_approval_trailer_for_the_typed_text', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_insight_add_refuses_a_path_outside_the_workspace', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_insight_add_refuses_a_typed_session_or_host', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_mcp_capture_insight_confines_like_the_cli', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_rule_insight_add_review_and_propose_cli', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_rule_insight_add_with_signed_commit_flag', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_rule_insight_add_with_signed_commit_flag', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_rule_insight_enable_and_doctor_host_reporting', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_rule_insight_enable_and_doctor_host_reporting', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_the_documented_h_recipe_counts_one_correction_once', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_the_documented_h_recipe_counts_one_correction_once', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_rule_insights.py', 'test_three_cli_adds_carry_no_session_and_are_one_unattributed_episode', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_scan_cli_row.py', 'test_a_directory_that_is_not_a_workspace_records_nothing', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_scan_cli_row.py', 'test_paths_are_workspace_relative_from_a_subdirectory_or_absolute', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_scan_cli_row.py', 'ws', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_skills_sync.py', 'test_a_junction_like_directory_resolving_elsewhere_is_refused', 'owner', 'skills_sync', False):
        ((0,), 'Owner skills_sync has lexical candidates aegis_cli.skills_sync; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_skills_sync.py', 'test_host_auto_uses_the_detected_hosts', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_skills_sync.py', 'test_host_auto_with_nothing_detected_is_a_usage_error', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_skills_sync.py', 'test_text_output_reports_a_packaged_skill_that_cannot_be_projected', 'owner', 'skills_sync', False):
        ((0,), 'Owner skills_sync has lexical candidates aegis_cli.skills_sync; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_status.py', 'TestStatus.test_status_command_contract', 'callable', 'patch', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 4cb82a180956; Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/cli/test_status.py', 'TestStatusComplianceCLI.test_outside_a_workspace_fails_cleanly', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 95270df4d2d5; Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_status.py', 'TestStatusComplianceCLI.test_the_text_view_says_when_commits_were_not_read', 'owner', 'gitsafe', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 95270df4d2d5; Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_status.py', 'TestStatusPins.test_an_empty_rules_directory_says_no_rules_found_and_exits_0', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 13fdb602af65; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_status.py', 'TestStatusPins.test_an_incomplete_ledger_is_named_before_the_rule_table', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 13fdb602af65; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_status.py', '_compliance_workspace', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 95270df4d2d5; Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_status.py', '_pinned_workspace', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 13fdb602af65; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_status.py', '_pinned_workspace', 'owner', 'init_module', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by 13fdb602af65; Owner init_module has lexical candidates aegis_cli.init; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_status.py', 'mixed_service_states', 'owner', 'init_module', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by 0aa1245bdae9; Owner init_module resolves to aegis_cli.init; reviewed consumer/class seam, not a shared module patch.'),
    ('tests/unit/cli/test_status.py', 'status_policy_repo', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 0aa1245bdae9; Existing fixture environment/path setup at these exact source lines.'),
    ('tests/unit/cli/test_status.py', 'status_policy_repo', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 0aa1245bdae9; Existing fixture environment/path setup at these exact source lines.'),
    ('tests/unit/cli/test_status.py', 'test_status_cli_packaged_guidance_is_not_loaded', 'owner', 'init_module', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by 37716d3bb75f; Owner init_module has lexical candidates aegis_cli.init; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_status.py', 'test_status_cli_project_summary_explains_omitted_core_rules', 'owner', 'init_module', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by 37716d3bb75f; Owner init_module has lexical candidates aegis_cli.init; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_status.py', 'test_status_cli_redacts_policy_diagnostics_before_truncation', 'owner', 'rule_integrity', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 0aa1245bdae9; Owner rule_integrity resolves to aegis_core.rule_integrity; reviewed consumer/class seam, not a shared module patch.'),
    ('tests/unit/cli/test_status.py', 'test_status_cli_refuses_unreadable_reviewed_policy', 'owner', 'rule_integrity', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 0aa1245bdae9; Owner rule_integrity resolves to aegis_core.rule_integrity; reviewed consumer/class seam, not a shared module patch.'),
    ('tests/unit/cli/test_status_compliance.py', 'test_without_git_the_window_heuristic_is_unavailable_not_zero', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_status_compliance.py', 'ws', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_status_compliance.py', 'ws', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_sync_pr_branch.py', '_isolated', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_sync_pr_branch.py', '_isolated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_sync_pr_branch.py', 'test_a_branch_name_already_taken_gets_the_next_one', 'owner', 'core_sync', False):
        ((0,), 'Owner core_sync has lexical candidates aegis_core.sync; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_sync_pr_branch.py', 'test_a_push_that_times_out_after_the_remote_took_it_names_the_branch_the_remote_may_hold', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_sync_pr_branch.py', 'test_a_push_url_scheme_that_picks_a_remote_helper_is_refused_and_the_helper_never_runs', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_team_config.py', 'isolated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Merged-tip fixture monkeypatch.setenv operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/cli/test_team_config.py', 'test_config_commands_accept_user_root_aliases', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Merged-tip fixture monkeypatch.setenv operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/cli/test_team_config.py', 'test_doctor_fake_path', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Merged-tip fixture monkeypatch.setenv operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/cli/test_team_config.py', 'test_home_lookup_keyerror_is_a_layered_refusal', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1), 'Merged-tip fixture monkeypatch.delenv operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/cli/test_team_config.py', 'test_home_lookup_keyerror_is_a_layered_refusal', 'owner', 'layout', False):
        ((0,), 'Merged-tip owner layout has static candidates aegis_core.workspace.layout; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/cli/test_team_config.py', 'test_init_binds_claude_host_and_doctor_uses_resolved_profile', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Merged-tip fixture monkeypatch.setenv operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/cli/test_team_config.py', 'test_public_entrypoint', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Merged-tip fixture monkeypatch.chdir operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/cli/test_uninstall.py', 'TestRefusalsTheCheckPassMustSee.test_a_write_error_after_the_check_names_what_was_already_changed', 'owner', 'uninstall_mod', False):
        ((0,), 'Owner uninstall_mod has lexical candidates aegis_cli.uninstall; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/cli/test_uninstall.py', 'TestSharedHooksDirectory.shared', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_uninstall.py', 'env', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_uninstall.py', 'test_uninstall_says_host_hooks_stay_until_hook_uninstall', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_uninstall.py', 'test_uninstall_says_host_hooks_stay_until_hook_uninstall', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_uninstall.py', 'test_uninstall_says_host_hooks_stay_until_hook_uninstall', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_upgrade_cli.py', 'test_retired_state_only_warns_in_check', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_upgrade_cli.py', 'test_retired_state_refuses_commands_before_execution', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/cli/test_v4_multiplatform_init_and_slots.py', 'TestCrossModelSlotRegistry.test_user_config_sets_slots_but_the_repo_config_cannot', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_adjudication.py', '_adjudicate', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_adjudication.py', '_isolated', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_adjudication.py', '_isolated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ambient_telemetry_is_not_evidence.py', '_isolated', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ambient_telemetry_is_not_evidence.py', '_isolated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_argv_consumers.py', 'commands', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_argv_consumers.py', 'test_driver_never_rejoins_a_repository_relative_program_path', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_argv_consumers.py', 'test_driver_never_rejoins_a_repository_relative_program_path', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_batch_m1.py', 'test_group_termination_failure_still_reaps_and_cleans_scratch', 'owner', 'batch.os', True):
        ((0,), 'Owner batch.os has lexical candidates aegis_core.ast.batch.os; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/core/test_ast_batch_m1.py', 'test_windows_close_retains_tree_ownership_after_driver_root_exits', 'owner', 'batch', False):
        ((0,), 'Owner batch has lexical candidates aegis_core.ast.batch; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_ast_batch_m1.py', 'test_windows_close_retains_tree_ownership_after_driver_root_exits', 'owner', 'batch.subprocess', True):
        ((0, 1), 'Owner batch.subprocess has lexical candidates aegis_core.ast.batch.subprocess; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'isolated_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_driver_executable_behind_a_relative_entry_does_not_resolve', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_driver_executable_behind_a_relative_entry_does_not_resolve', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_driver_executable_inside_the_workspace_does_not_resolve', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_driver_path_resolves_against_the_workspace_root_never_the_cwd', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_driver_registered_in_code_runs_the_program_an_absolute_entry_names', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_driver_registered_in_code_runs_the_program_an_absolute_entry_names', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_driver_registered_in_code_that_is_on_no_absolute_entry_is_unavailable', 'fixture', 'monkeypatch.chdir', False):
        ((0, 1), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_driver_registered_in_code_that_is_on_no_absolute_entry_is_unavailable', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_legacy_packaged_ts_opt_in_never_runs_a_node_on_path', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_legacy_packaged_ts_opt_in_never_runs_a_node_on_path', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_relative_driver_path_in_user_config_resolves_against_the_workspace_root', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_toolchain_planted_in_the_repository_is_not_detected', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_toolchain_planted_in_the_repository_is_not_detected', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_user_scope_driver_found_only_inside_the_workspace_says_where', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_user_scope_driver_named_bare_runs_the_real_program_never_a_planted_one', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_user_scope_driver_named_bare_runs_the_real_program_never_a_planted_one', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_a_user_scope_driver_on_path_that_links_into_the_workspace_is_not_run', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_an_interpreter_outside_the_workspace_that_links_into_it_is_not_run', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_windows_splitting_joins_an_unquoted_absolute_path_with_spaces', 'callable', 'm.setattr', True):
        ((0,), 'Existing m.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_windows_splitting_joins_an_unquoted_absolute_path_with_spaces', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_windows_splitting_never_joins_words_by_a_file_in_the_current_directory', 'callable', 'm.setattr', True):
        ((0,), 'Existing m.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_windows_splitting_never_joins_words_by_a_file_in_the_current_directory', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_lookup.py', 'test_windows_splitting_never_joins_words_by_a_file_in_the_current_directory', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_ast_driver_runner.py', '_isolated_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_runner.py', 'test_python_driver_runs_when_interpreter_name_is_not_on_path', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_runner.py', 'test_resolve_driver_executable_deterministic_tokens', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_runner.py', 'test_resolve_driver_executable_deterministic_tokens', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_driver_runner.py', 'test_split_command_windows', 'callable', 'm.setattr', True):
        ((0,), 'Existing m.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_ast_driver_runner.py', 'test_split_command_windows', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_ast_session_m1.py', 'test_user_driver_plan_is_frozen_for_one_pass_not_the_next', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ast_windows_job.py', '_kernel', 'owner', 'windows_job', False):
        ((0,), 'Owner windows_job has lexical candidates aegis_core.ast.windows_job; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_ast_windows_job.py', '_shutdown_job', 'owner', 'windows_job', False):
        ((0,), 'Owner windows_job has lexical candidates aegis_core.ast.windows_job; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_failed_creation_never_leaves_an_unowned_process_or_job', 'owner', 'batch', False):
        ((0,), 'Owner batch has lexical candidates aegis_core.ast.batch; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_failed_creation_never_leaves_an_unowned_process_or_job', 'owner', 'batch.subprocess', True):
        ((0, 1), 'Owner batch.subprocess has lexical candidates aegis_core.ast.batch.subprocess; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_job_close_error_retains_the_original_startup_diagnostic', 'owner', 'batch', False):
        ((0,), 'Owner batch has lexical candidates aegis_core.ast.batch; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_job_close_error_retains_the_original_startup_diagnostic', 'owner', 'batch.subprocess', True):
        ((0, 1), 'Owner batch.subprocess has lexical candidates aegis_core.ast.batch.subprocess; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_native_startup_failure_never_executes_driver_code', 'owner', 'batch.subprocess', True):
        ((0,), 'Owner batch.subprocess has lexical candidates aegis_core.ast.batch.subprocess; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_native_startup_failure_never_executes_driver_code', 'owner', 'windows_job', False):
        ((0,), 'Owner windows_job has lexical candidates aegis_core.ast.windows_job; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_partial_member_list_growth_obeys_the_shared_shutdown_deadline', 'owner', 'windows_job', False):
        ((0,), 'Owner windows_job has lexical candidates aegis_core.ast.windows_job; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_shutdown_deadline_also_bounds_already_signaled_members', 'owner', 'windows_job', False):
        ((0,), 'Owner windows_job has lexical candidates aegis_core.ast.windows_job; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_shutdown_waits_share_one_deadline', 'owner', 'windows_job', False):
        ((0,), 'Owner windows_job has lexical candidates aegis_core.ast.windows_job; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_startup_failures_reap_suspended_root_and_close_every_handle', 'owner', 'batch', False):
        ((0,), 'Owner batch has lexical candidates aegis_core.ast.batch; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_ast_windows_job.py', 'test_startup_failures_reap_suspended_root_and_close_every_handle', 'owner', 'batch.subprocess', True):
        ((0, 1), 'Owner batch.subprocess has lexical candidates aegis_core.ast.batch.subprocess; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/core/test_atomicio.py', 'test_a_link_swapped_in_between_the_check_and_the_open_is_refused', 'fixture', 'monkeypatch.undo', False):
        ((0,), 'Fixture undo operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_baseline.py', 'repo', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_baseline.py', 'test_a_workspace_below_the_repository_top_reads_its_own_baseline_at_base', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_baseline_findings.py', 'repo', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_benchmark.py', 'test_the_hook_runs_with_an_empty_home_and_none_of_the_callers_aegis_or_host_variables', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_card.py', '_own_home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_card.py', '_own_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_checkrun_group_kill.py', 'test_a_live_run_is_killed_with_the_absolute_taskkill', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_checkrun_group_kill.py', 'test_a_relative_or_empty_systemroot_falls_back_to_c_windows', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_checkrun_group_kill.py', 'test_an_exited_run_is_never_signalled', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_checkrun_polyglot.py', 'project', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_checkrun_polyglot.py', 'project', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_checkrun_polyglot.py', 'test_rust_inline_tests_remain_explicitly_unverifiable', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ci_governance_gate.py', '_aegis_approve', 'owner', 'approve_cli', False):
        ((0,), 'Owner approve_cli has lexical candidates aegis_cli.approve; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_ci_governance_gate.py', '_env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ci_governance_gate.py', '_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ci_workflow_identity.py', '_doctor_github', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ci_workflow_identity.py', '_home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ci_workflow_identity.py', '_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ci_workflow_identity.py', 'test_a_user_config_inside_the_workspace_is_ignored', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ci_workflow_identity.py', 'test_init_ci_says_how_to_let_credit_read_the_workflow', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_config.py', 'test_jit_budget_precedence', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_config.py', 'test_jit_budget_precedence', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_config.py', 'test_manager_registration_environment_reads_process_only_without_explicit_mapping', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_core_lifecycle.py', 'TestPromoteAndDemote.test_promotion_without_force_needs_ledger_evidence', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_credit.py', 'test_argon_0735_reset_traces_restore_exposure', 'callable', 'patch.setattr', False):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_credit.py', 'test_argon_0735_reset_traces_restore_exposure', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_credit.py', 'test_argon_two_root_spellings_share_the_memo_and_its_invalidation', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_credit.py', 'test_argon_two_root_spellings_share_the_memo_and_its_invalidation', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_credit.py', 'test_blank_regrowth_after_append_does_not_certify_missing_exposure', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_credit.py', 'test_blank_regrowth_after_append_does_not_certify_missing_exposure', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_credit.py', 'test_blank_regrowth_after_no_append_read_does_not_certify_missing_exposure', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_credit.py', 'test_blank_regrowth_after_no_append_read_does_not_certify_missing_exposure', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_credit.py', 'test_delayed_fill_with_coarse_unchanged_stamps_stays_ineligible', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_credit.py', 'test_delayed_fill_with_coarse_unchanged_stamps_stays_ineligible', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_credit.py', 'test_fill_preserves_the_head_used_by_its_locked_read_when_it_also_appends', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_credit.py', 'test_fill_preserves_the_head_used_by_its_locked_read_when_it_also_appends', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_credit.py', 'test_linked_worktrees_share_one_persistence_memo', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_credit.py', 'test_linked_worktrees_share_one_persistence_memo', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_credit.py', 'test_multirow_reset_during_fill_cannot_certify_removed_rule', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_credit.py', 'test_multirow_reset_during_fill_cannot_certify_removed_rule', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_credit.py', 'test_portable_ancestor_substitution_misses_and_reaches_typed_refusal', 'callable', 'patch.setattr', False):
        ((0, 1, 2), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_credit.py', 'test_portable_ancestor_substitution_misses_and_reaches_typed_refusal', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_credit.py', 'test_replacement_of_initially_missing_ledger_cannot_certify_its_matching_tail', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_credit.py', 'test_replacement_of_initially_missing_ledger_cannot_certify_its_matching_tail', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_credit.py', 'test_replacement_while_waiting_for_lock_drops_old_rules', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_credit.py', 'test_replacement_while_waiting_for_lock_drops_old_rules', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_credit.py', 'test_reset_before_append_report_under_clock_skew_never_fills', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_credit.py', 'test_reset_before_append_report_under_clock_skew_never_fills', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_credit.py', 'test_reset_between_append_and_memo_fill_restores_exposure', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_credit.py', 'test_reset_between_append_and_memo_fill_restores_exposure', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_credit.py', 'test_reset_between_locked_read_and_fill_without_append_restores_exposure', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_credit.py', 'test_reset_between_locked_read_and_fill_without_append_restores_exposure', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_credit.py', 'test_shared_workspace_and_session_record_scan_rows_in_each_test', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_credit.py', 'test_shared_workspace_and_session_record_scan_rows_in_each_test', 'owner', 'scan_compliance', False):
        ((0,), 'Owner scan_compliance has lexical candidates aegis_core.scan_compliance; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_credit_model_v43.py', 'git_spawns', 'owner', 'subprocess', True):
        ((0,), 'Owner subprocess has lexical candidates subprocess; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/core/test_credit_model_v43.py', 'test_25_findings_are_persisted_under_one_lock_with_one_append', 'owner', 'ledger', False):
        ((0,), 'Owner ledger has lexical candidates aegis_core.telemetry_engine.ledger; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_credit_projection_cost.py', '_isolated', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_credit_projection_cost.py', '_isolated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_discovery_never_home.py', 'home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_discovery_never_home.py', 'home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_discovery_never_home.py', 'real_home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_discovery_never_home.py', 'real_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_discovery_never_home.py', 'test_a_folder_under_the_real_home_never_resolves_to_it_when_home_is_overridden', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_discovery_never_home.py', 'test_a_pin_naming_a_real_workspace_still_binds', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_discovery_never_home.py', 'test_a_pin_naming_a_real_workspace_still_binds', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_discovery_never_home.py', 'test_a_pin_naming_home_is_refused_not_bound', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_discovery_never_home.py', 'test_a_pin_naming_home_is_refused_not_bound', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_discovery_never_home.py', 'test_an_uninitialized_repository_under_home_never_resolves_to_home', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_envelope_heads.py', '_documents', 'owner', 'doctor', False):
        ((0,), 'Owner doctor has lexical candidates aegis_cli.doctor; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_envelope_heads.py', '_documents', 'owner', 'doctor.human_gate', False):
        ((0,), 'Owner doctor.human_gate has lexical candidates aegis_cli.doctor.human_gate; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_envelope_heads.py', 'isolated', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_envelope_heads.py', 'isolated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_envelope_heads.py', 'test_mcp_report_head', 'owner', 'telemetry', False):
        ((0,), 'Owner telemetry has lexical candidates aegis_mcp.handlers.telemetry; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_events_try_append.py', 'isolated', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_events_try_append.py', 'isolated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_events_try_append.py', 'test_process_control_is_not_a_metric_warning', 'owner', 'pretool', False):
        ((0,), 'Owner pretool has lexical candidates aegis_cli.hooks.pretool; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_evidence_transactions.py', 'test_report_outcome_batch_failure_then_same_key_retries_once', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_evidence_transactions.py', 'test_report_outcome_batch_failure_then_same_key_retries_once', 'owner', 'ledger_mod', False):
        ((0, 1), 'Owner ledger_mod has lexical candidates aegis_core.telemetry_engine.ledger; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_f_a1_human_gate_acceptance.py', '_approve', 'owner', 'approve', False):
        ((0,), 'Owner approve has lexical candidates aegis_cli.approve; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_f_a1_human_gate_acceptance.py', '_doctor_github', 'owner', 'doctor_base', False):
        ((0,), 'Owner doctor_base has lexical candidates aegis_cli.doctor_base; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_f_a1_human_gate_acceptance.py', '_home', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_a1_human_gate_acceptance.py', '_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_a1_human_gate_acceptance.py', 'test_a_genuine_ssh_approval_verifies_in_a_sha256_repository', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_a1_human_gate_acceptance.py', 'test_ssh_keygen_inside_the_repository_is_never_the_signature_program', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_a1_human_gate_acceptance.py', 'test_the_signature_programs_are_not_looked_up_on_a_path_the_repository_can_plant_on', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_a1_human_gate_acceptance.py', 'test_with_ssh_keygen_only_inside_the_repository_approvals_are_refused', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_a2_verified_checks_acceptance.py', '_home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_a2_verified_checks_acceptance.py', '_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_a2_verified_checks_acceptance.py', 'test_status_and_sync_show_claims_apart_from_every_rule', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_a3_rule_integrity_acceptance.py', '_home', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1, 2, 3), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_a3_rule_integrity_acceptance.py', '_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_a3_rule_integrity_acceptance.py', 'run_release', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b1_insights_acceptance.py', 'review_repo', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b1_insights_acceptance.py', 'review_repo', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b1_insights_acceptance.py', 'test_a_4_3_upgraded_w2_capture_never_counts_as_a_recurrence', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b1_insights_acceptance.py', 'test_agent_suggestions_do_not_count_and_never_enter_scan_or_proposals', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b1_insights_acceptance.py', 'test_closed_template_proposals_and_recurrence_alarm', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b1_insights_acceptance.py', 'test_correction_cue_detector_precision_and_recall_and_hook_storage', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b1_insights_acceptance.py', 'test_human_level_h_insight_requires_content_bound_signed_commit', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b1_insights_acceptance.py', 'test_human_level_h_insight_requires_content_bound_signed_commit', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b1_insights_acceptance.py', 'test_insights_file_created_with_0600_mode_before_first_write', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b1_insights_acceptance.py', 'test_keyed_hs_pseudonymization_and_link_key_creation', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b1_insights_acceptance.py', 'test_ordinary_mcp_aegis_scan_records_exposure_for_review_insights_without_outcome_row', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b1_insights_acceptance.py', 'test_recurrence_reports_insufficient_session_identity_when_hs_is_missing_and_never_inflates_sessions', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b1_insights_acceptance.py', 'test_same_rule_dissimilar_insights_stay_separate_through_rejection_and_resurfacing', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b1_insights_acceptance.py', 'test_tfidf_neighbours_rule_matching_and_rejected_group_cooldown', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b2_credit_model_acceptance.py', '_trailer_repo', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b2_credit_model_acceptance.py', 'test_check_ci_trailer_independently_reruns_snapshot_without_local_ledger', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b2_credit_model_acceptance.py', 'test_check_ci_trailer_independently_reruns_snapshot_without_local_ledger', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b2_credit_model_acceptance.py', 'test_check_ci_trailer_independently_reruns_snapshot_without_local_ledger', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b2_credit_model_acceptance.py', 'test_end_to_end_claimed_to_recorded_to_landed_to_confirmed_to_scored_and_approved_protected_change', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b2_credit_model_acceptance.py', 'test_end_to_end_claimed_to_recorded_to_landed_to_confirmed_to_scored_and_approved_protected_change', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b2_credit_model_acceptance.py', 'test_end_to_end_claimed_to_recorded_to_landed_to_confirmed_to_scored_and_approved_protected_change', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b2_credit_model_acceptance.py', 'test_repeated_sync_refreshes_reruns_and_new_landed_checks_and_fresh_status_stays_offline', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b2_credit_model_acceptance.py', 'test_repeated_sync_refreshes_reruns_and_new_landed_checks_and_fresh_status_stays_offline', 'owner', 'ghcli', False):
        ((0,), 'Owner ghcli has lexical candidates aegis_core.ghcli; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_f_b2_credit_model_acceptance.py', 'test_sync_stores_where_replay_stopped_and_a_second_sync_appends_nothing', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b3_regression_acceptance.py', '_isolated_env', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1, 2, 3), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b3_regression_acceptance.py', '_isolated_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_f_b3_regression_acceptance.py', 'test_editable_install_pth_and_pep660_finder_cannot_shadow_snapshot_source', 'fixture', 'monkeypatch.syspath_prepend', False):
        ((0, 1), 'Fixture syspath_prepend operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_file_lock.py', 'home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_file_lock.py', 'home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2, 3), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_finding_identity.py', '_home', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_finding_identity.py', '_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_fitness.py', 'test_for_rules_folds_every_t4_event_arm_in_ledger_order', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_fitness.py', 'test_for_rules_keeps_detection_and_exposure_buckets_independent', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_fitness_feasibility.py', '_isolated', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_fitness_feasibility.py', '_isolated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_fitness_transitions.py', 'scenario_ws', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_fitness_transitions.py', 'test_an_unreadable_ledger_line_gives_no_suggestion_and_moves_nothing', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_fitness_transitions.py', 'test_one_labelled_promotion_is_one_move_never_also_a_tier_move', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_fitness_transitions.py', 'test_protected_and_unserved_rules_get_no_suggestion_anywhere', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ghcli.py', '_home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ghcli.py', '_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ghcli.py', 'gh_stub', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ghcli.py', 'gh_stub', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ghcli.py', 'test_a_call_without_placeholders_runs_without_a_repository', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ghcli.py', 'test_a_temporary_directory_inside_a_repository_still_finds_no_repository', 'owner', 'tempfile', False):
        ((0,), 'Owner tempfile has lexical candidates tempfile; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_ghcli.py', 'test_missing_gh_does_not_start_a_process', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ghcli.py', 'test_transport_decodes_output_and_preserves_the_exit_code', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ghcli.py', 'test_transport_failures_keep_their_exact_result_and_remove_scratch', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitevidence.py', '_isolated', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitevidence.py', '_isolated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitevidence.py', 'test_without_git_there_is_no_fetch_age', 'fixture', 'monkeypatch.undo', False):
        ((0,), 'Fixture undo operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', '_counting_which', 'owner', 'pathlookup', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 7822b6c88f5f; Owner pathlookup has lexical candidates aegis_core.pathlookup; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_gitsafe.py', 'fake_home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 841f477085a4; Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'fake_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by 841f477085a4; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'git_config.configure', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'git_config.configure', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_a_cached_git_never_outlives_a_path_that_only_holds_a_relative_entry', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 7822b6c88f5f; Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_a_cached_git_never_outlives_a_path_that_only_holds_a_relative_entry', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 7822b6c88f5f; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_a_git_planted_behind_an_empty_or_relative_path_entry_is_never_run', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_a_git_planted_behind_an_empty_or_relative_path_entry_is_never_run', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_a_hook_index_is_still_read_outside_scrubbed', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by eb6111a5de57; Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_a_hook_index_is_still_read_outside_scrubbed', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by eb6111a5de57; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_a_master_only_repository_without_a_remote_measures_against_master', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 841f477085a4; Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_a_memoized_answer_under_an_ambient_git_dir_is_not_served_to_a_scrubbed_call', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by eb6111a5de57; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_a_new_path_finds_its_own_git_and_a_deleted_git_fails_loudly', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 7822b6c88f5f; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_add_trailer_resolves_a_relative_message_file_against_the_callers_directory', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by df710dee7854; Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_add_trailer_runs_no_trailer_command_of_the_repository', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by df710dee7854; Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_add_trailer_runs_no_trailer_command_of_the_repository', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'present at tip 4959830f before RF-11b landed; added by df710dee7854; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_aegis_commands_never_run_a_repo_fsmonitor', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_aegis_commands_never_run_a_repo_fsmonitor', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_an_explicit_index_still_wins_inside_scrubbed', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by eb6111a5de57; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_every_call_is_hardened', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_on_windows_the_current_directory_is_not_searched_for_git', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_on_windows_the_current_directory_is_not_searched_for_git', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_scrubbed_decorates_a_function', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by eb6111a5de57; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_scrubbed_drops_exactly_the_local_variables_git_lists', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'present at tip 4959830f before RF-11b landed; added by eb6111a5de57; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_the_scrub_ends_with_its_block_even_on_an_exception_and_nests', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by eb6111a5de57; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_timeout_and_missing_git_raise_git_error', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_gitsafe.py', 'test_with_windows_rules_a_rule_id_with_a_drive_or_stream_is_refused', 'owner', 'parsers', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by deabb0526c3d; Owner parsers has lexical candidates aegis_core.lifecycle.parsers; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_gitsafe_refs.py', 'test_a_ref_made_symbolic_after_the_check_is_replaced_never_written_through', 'fixture', 'monkeypatch.undo', False):
        ((0,), 'Fixture undo operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_glob_agreement.py', 'isolated', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_glob_agreement.py', 'isolated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_go_build_cache.py', 'compiler', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2, 3), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_go_build_cache.py', 'test_build_is_private_offline_and_retains_only_safe_environment', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_go_build_cache.py', 'test_cache_inside_workspace_is_refused_before_build', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_go_build_cache.py', 'test_inspection_failures_preserve_reasons_and_create_no_cache_state', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_go_build_cache.py', 'test_inspection_ignores_parent_module_repository_and_user_toolchain_pins', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_go_build_cache.py', 'test_lock_failure_is_reasoned_without_publishing', 'owner', 'gobuild', False):
        ((0,), 'Owner gobuild has lexical candidates aegis_core.ast.gobuild; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_go_build_cache.py', 'test_missing_go_is_a_reasoned_unavailable_result', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_go_build_cache.py', 'test_native_windows_real_go_success_accepts_waited_compiler_children', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_go_build_cache.py', 'test_packaged_sources_inside_workspace_are_refused_before_probing_or_writing', 'owner', 'gobuild', False):
        ((0,), 'Owner gobuild has lexical candidates aegis_core.ast.gobuild; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_go_build_cache.py', 'test_public_build_terminates_ordinary_compiler_descendants_before_return', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_go_integration.py', 'go_workspace', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_governance_set.py', 'test_profile_changes_move_the_existing_human_gate_hash', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Merged-tip fixture monkeypatch.setenv operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/core/test_governance_set.py', 'test_the_approval_hash_of_a_fixed_tree_is_the_one_develop_computed', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_governance_set.py', 'test_the_label_pattern_leaves_an_approval_hash_without_label_files_unchanged', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_human_gate.py', '_approve_on_a_pty', 'owner', 'approve', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 59f62d69bb54; Owner approve has lexical candidates aegis_cli.approve; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_human_gate.py', '_counted_find', 'owner', 'gitsafe', False):
        ((0, 1), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_human_gate.py', '_home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_human_gate.py', '_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_human_gate.py', '_tty_recording_signer', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 59f62d69bb54; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_human_gate.py', 'test_batched_exemption_preflight_failure_has_no_candidates_or_diagnostics', 'owner', 'gitsafe', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by bcb7061d06f6; Owner gitsafe resolves to aegis_core.gitsafe; reviewed consumer/class seam, not a shared module patch.'),
    ('tests/unit/core/test_human_gate.py', 'test_exemption_byte_limit_refuses_oversize_and_accepts_exact_bound', 'owner', 'gitsafe', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 3a4879781b6c; Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_human_gate.py', 'test_exemption_discovery_does_not_verify_unrelated_commits', 'owner', 'gitsafe', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 3a4879781b6c; Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_human_gate.py', 'test_failed_exemption_object_read_returns_no_candidate', 'owner', 'gitsafe', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by bcb7061d06f6; Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_human_gate.py', 'test_failed_object_read_discards_partial_exemption_candidates', 'owner', 'gitsafe', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by bcb7061d06f6; Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_human_gate.py', 'test_large_commit_headers_are_read_one_at_a_time_and_released', 'owner', 'gitsafe', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 3a4879781b6c; Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_human_gate.py', 'test_reading_the_base_workflows_costs_one_batched_git_read', 'owner', 'gitsafe', False):
        ((0, 1), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_inference_provider.py', 'TestCommandBackend.test_the_command_runs_in_a_fresh_empty_directory', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_inference_provider.py', 'TestProgramLookup.test_a_bare_command_on_no_absolute_entry_is_not_found', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_inference_provider.py', 'TestProgramLookup.test_a_bare_command_on_no_absolute_entry_is_not_found', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_inference_provider.py', 'TestProgramLookup.test_a_bare_command_runs_the_program_an_absolute_path_entry_names', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_inference_provider.py', 'TestProgramLookup.test_a_bare_command_runs_the_program_an_absolute_path_entry_names', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_inference_provider.py', 'TestProgramLookup.test_the_real_program_runs_and_a_planted_one_never_does', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_inference_provider.py', 'TestProgramLookup.test_the_real_program_runs_and_a_planted_one_never_does', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_inference_provider.py', 'TestResolveBackend.test_workspace_files_are_never_read', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_inference_provider.py', 'TestWindowsBatchShims.test_a_cmd_shim_runs_under_cmd_exe_with_every_argument_quoted', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_inference_provider.py', 'TestWindowsBatchShims.test_a_cmd_shim_runs_under_cmd_exe_with_every_argument_quoted', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_inference_provider.py', 'TestWindowsBatchShims.test_an_exe_runs_directly_by_its_on_disk_name', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_inference_provider.py', 'TestWindowsBatchShims.test_without_comspec_cmd_exe_is_taken_from_the_system_directory', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_inference_provider.py', 'TestWindowsBatchShims.test_without_comspec_cmd_exe_is_taken_from_the_system_directory', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_inference_provider.py', 'TestWindowsBatchShims.windows', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insight_capture_reason.py', 'approved_repo', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insight_capture_reason.py', 'approved_repo', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insight_capture_reason.py', 'test_capture_does_not_persist_or_echo_verification_exceptions', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_insight_capture_reason.py', 'test_cli_gives_one_fixed_next_action_for_every_refusal', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_insight_redaction_bounds.py', 'test_hook_prompt_of_one_huge_token_writes_no_excerpt_row', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights.py', 'hb_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by f3df0bcc73fe; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights.py', 'hook_home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 745bc6b5cacb; Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights.py', 'hook_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'present at tip 4959830f before RF-11b landed; added by 745bc6b5cacb; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights.py', 'lint_repo', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 51efacf365e0; Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights.py', 'lint_repo', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'present at tip 4959830f before RF-11b landed; added by 51efacf365e0; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights.py', 'test_a_hook_whose_recorder_raises_exits_zero_with_the_error_on_stderr', 'owner', 'hook', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 6c8584a9faf5; Owner hook has lexical candidates aegis_cli.hooks.insights; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_insights.py', 'test_a_relative_claude_project_dir_is_ignored', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 745bc6b5cacb; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights.py', 'test_add_insight_level_h_requires_explicit_commit_and_matching_insight_hash', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 4006567dc182; Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights.py', 'test_add_insight_level_h_requires_explicit_commit_and_matching_insight_hash', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'present at tip 4959830f before RF-11b landed; added by 4006567dc182; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights.py', 'test_claude_project_dir_wins_over_the_payload_cwd', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 745bc6b5cacb; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights.py', 'test_hook_counters_only_mode_records_heartbeat_without_excerpt', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by 3a62400efeeb; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights.py', 'test_hook_stdin_that_is_not_a_json_object_records_no_insight', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 6c8584a9faf5; Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights.py', 'test_hook_stdin_that_is_not_a_json_object_records_no_insight', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 6c8584a9faf5; Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights.py', 'test_host_capture_status_ignores_a_relative_config_dir', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by f8e4cf95f649; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights.py', 'test_insight_workspace_id_at_ceiling_ignores_enclosing_repository', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/core/test_insights.py', 'test_insight_workspace_id_at_ceiling_ignores_enclosing_repository', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/core/test_insights.py', 'test_insight_workspace_id_honours_explicit_git_layout', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/core/test_insights.py', 'test_matches_proposal_and_noise_decision_filtering', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by 3a62400efeeb; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights.py', 'test_read_link_key_closes_descriptor_when_fdopen_fails', 'owner', 'keys', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 7549dae65e43; Owner keys resolves to aegis_core.insights.keys; reviewed consumer/class seam, not a shared module patch.'),
    ('tests/unit/core/test_insights.py', 'test_single_explicit_git_layout_above_ceiling_keeps_boundary_and_identity', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/core/test_insights.py', 'test_single_explicit_git_layout_above_ceiling_keeps_boundary_and_identity', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/core/test_insights.py', 'test_tfidf_neighbours_and_dirty_paths', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by 6c8584a9faf5; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights.py', 'test_unusable_explicit_git_layout_does_not_supply_insights_identity', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/core/test_insights.py', 'test_unusable_explicit_git_layout_does_not_supply_insights_identity', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/core/test_insights.py', 'test_unusable_explicit_git_layout_does_not_supply_insights_identity', 'owner', 'keys', False):
        ((0,), "present at tip b11638bf before RF-11b landed; added by e328b74a; Replaces the insights keys consumer's Git API with an owned toplevel refusal fixture."),
    ('tests/unit/core/test_insights_log_scaling.py', 'home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_insights_log_scaling.py', 'home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_js_ast_driver.py', 'test_decorated_parse_token_work_is_bounded_by_source_size', 'owner', 'extractor', False):
        ((0,), 'Owner extractor has lexical candidates aegis_core.ast.drivers.js.extractor; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_js_native_integration.py', 'test_native_js_runs_without_config_or_an_external_program', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_js_tokenizer.py', 'test_compact_group_scans_each_parenthesis_run_a_bounded_number_of_times', 'owner', 'tokenizer', False):
        ((0,), 'Owner tokenizer has lexical candidates aegis_core.ast.drivers.js.tokenizer; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_landed_lookup_cost.py', '_isolated', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_landed_lookup_cost.py', '_isolated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_lane_ast.py', 'TestPytestConfigView.test_it_parses_without_tomllib', 'owner', 'sys.modules', True):
        ((0,), 'Owner sys.modules has lexical candidates sys.modules; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/core/test_lane_gate.py', '_lane_cli', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_lane_gate.py', '_lane_cli', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_lane_gate.py', '_no_ci_base', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_language_tests.py', 'project', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_language_tests.py', 'test_deadline_expiring_during_dependency_setup_never_starts_the_command', 'owner', 'language_tests', False):
        ((0,), 'Owner language_tests has lexical candidates aegis_core.verification.language_tests; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_language_tests.py', 'test_rust_installed_default_is_probed_in_empty_cwd_then_pinned', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_language_tests.py', 'test_ts_link_and_report_failures_are_explicit_and_preserve_snapshot_entries', 'owner', 'ctypes', False):
        ((0,), 'Owner ctypes has lexical candidates ctypes; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_language_tests.py', 'test_windows_junction_lifecycle_preserves_targets_and_detects_retargeting', 'owner', 'language_tests', False):
        ((0,), 'Owner language_tests has lexical candidates aegis_core.verification.language_tests; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_language_tests.py', 'test_windows_snapshot_dependencies_use_junction_when_symlink_privilege_is_absent', 'owner', 'language_tests', False):
        ((0,), 'Owner language_tests has lexical candidates aegis_core.verification.language_tests; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_layout.py', 'test_user_plane_of_the_running_user', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ledger_mixed_versions.py', '_env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_ledger_mixed_versions.py', '_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_lifecycle.py', 'TestPromotion._home', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_lifecycle_write_safety.py', '_rival_on_first_lock', 'owner', 'module', False):
        ((0,), 'The helper defaults to promotion; its six local callers use promotion or explicit selection, both product lifecycle modules. The parameter still requires this exact registration.'),
    ('tests/unit/core/test_lifecycle_write_safety.py', 'test_failed_final_write_leaves_rules_untouched', 'fixture', 'monkeypatch.undo', False):
        ((0,), 'Fixture undo operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_lifecycle_write_safety.py', 'test_rule_files_are_never_rewritten_in_place', 'fixture', 'monkeypatch.undo', False):
        ((0,), 'Fixture undo operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_literal_workspace.py', 'test_no_path_falls_back_to_discovery', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_literal_workspace.py', 'test_no_path_falls_back_to_discovery', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_literal_workspace.py', 'test_the_environment_pin_does_not_redirect_an_explicit_path', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_locking.py', 'test_a_waiter_backs_off_from_10_ms_by_half_again_each_try_up_to_50_ms', 'fixture', 'monkeypatch.undo', False):
        ((0,), 'Fixture undo operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_locking.py', 'test_a_waiter_backs_off_from_10_ms_by_half_again_each_try_up_to_50_ms', 'owner', 'storage.time', True):
        ((0, 1), 'Owner storage.time has lexical candidates aegis_core.storage.time; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/core/test_manager.py', 'test_evidence_git_failure_is_unavailable_and_never_proves_check', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_manager.py', 'test_repeated_evidence_observes_worktree_once_per_request', 'owner', 'manager', False):
        ((0,), 'Owner manager has lexical candidates aegis_core.manager; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_manager_config.py', '_ceiling_workspace', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Merged-tip fixture monkeypatch.setenv operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/core/test_manager_config.py', 'owner', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_manager_config.py', 'test_initialize_metadata_errors_are_unsafe_config', 'owner', 'manager_store', False):
        ((0,), 'Merged-tip owner manager_store has static candidates aegis_core.manager_store; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/core/test_manager_policy.py', 'test_git_timeout_is_explicit_and_does_not_load_checkout', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_manager_store.py', 'test_ancestor_swap_before_directory_open_cannot_write_outside', 'callable', 'patch.setattr', True):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_manager_store.py', 'test_ancestor_swap_before_directory_open_cannot_write_outside', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_manager_store.py', 'test_ancestor_swap_before_lock_open_cannot_write_outside', 'callable', 'patch.setattr', True):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_manager_store.py', 'test_ancestor_swap_before_lock_open_cannot_write_outside', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_manager_store.py', 'test_ancestor_swap_before_mkdir_cannot_create_outside', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_manager_store.py', 'test_ancestor_swap_before_mkdir_cannot_create_outside', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_manager_store.py', 'test_in_git_worktree_resolves_proc_cwd_alias', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Merged-tip fixture monkeypatch.chdir operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/core/test_manager_store.py', 'test_partial_os_write_preserves_raw_uncertainty', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_manager_store.py', 'test_partial_os_write_preserves_raw_uncertainty', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_manager_store.py', 'test_placement_metadata_errors_are_unsafe_store', 'owner', 'manager_store', False):
        ((0,), 'Merged-tip owner manager_store has static candidates aegis_core.manager_store; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/core/test_manager_store.py', 'test_placement_refuses_dot_before_metadata', 'owner', 'manager_store', False):
        ((0,), 'Merged-tip owner manager_store has static candidates aegis_core.manager_store; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/core/test_message_codec.py', 'test_class_a_descriptors_are_lazy_and_expansion_never_reads_grandchildren', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_class_a_limits_precede_decoder_allocation', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_class_a_materialization_is_bounded', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_class_b_entry_operations_use_anchored_directory', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_class_b_publication_verifies_destination', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_coord1_argon1_unchanged_stamp_never_bypasses_verification', 'callable', 'patch.setattr', True):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_coord1_argon1_unchanged_stamp_never_bypasses_verification', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_coord1_argon2_live_root_privacy_is_required', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_coord1_argon2_live_root_privacy_is_required', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_coord3_store_enoent_maps_by_operation', 'callable', 'patch.setattr', True):
        ((0, 1, 2), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_coord3_store_enoent_maps_by_operation', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_coord3_store_replaced_during_successful_operation_refuses', 'callable', 'patch.setattr', True):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_coord3_store_replaced_during_successful_operation_refuses', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_full_id_resolution_does_not_enumerate_store', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r10_close_release_error_invalidates_before_fd_reuse', 'callable', 'patch.setattr', True):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_r10_close_release_error_invalidates_before_fd_reuse', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r10_constructor_close_error_preserves_ownership_without_leak', 'callable', 'patch.setattr', True):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_r10_constructor_close_error_preserves_ownership_without_leak', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r10_constructor_close_observer_rejects_foreign_cleanup_close', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_message_codec.py', 'test_r10_constructor_close_observer_rejects_foreign_cleanup_close', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r10_finalizer_release_error_never_raises_or_retries', 'callable', 'patch.setattr', True):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_r10_finalizer_release_error_never_raises_or_retries', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r3_class_c_cleanup_preserves_original_error', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r3_class_c_link_count_change_is_not_tampering', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r3_class_c_platform_refuses_unanchored_operations', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r3_class_c_prefix_lookup_ignores_foreign_entries', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r3_class_d_fixed_budget_bounds_ref_io', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r3_class_d_named_ref_selection_reads_only_named_child', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r3_class_d_output_budget_is_independent_of_ref_io', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r3_class_e_validation_work_is_cumulatively_bounded', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_a_cumulative_staging_work_is_bounded', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_a_selection_refuses_before_materializing', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_b_all_ref_failures_abort_view', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_b_expand_only_reads_requested_children', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_c_operational_errors_have_fixed_next_action', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_c_root_component_swap_is_refused', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_c_root_component_swap_is_refused', 'fixture', 'use_readlink_only_pathlib(monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_c_root_swap_after_open_is_refused', 'callable', 'patch.setattr', True):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_c_root_swap_after_open_is_refused', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_c_root_swap_after_open_is_refused', 'fixture', 'use_readlink_only_pathlib(patch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_c_temporary_walk_swap_is_refused', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_c_temporary_walk_swap_is_refused', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_c_temporary_walk_swap_is_refused', 'fixture', 'use_readlink_only_pathlib(patch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_e_tmp_path_without_store_on_unsupported_platform', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r4_class_f_existing_write_avoids_temporary_creation', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r5_class_a_expand_is_rejected_before_store_io', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r5_class_a_malformed_options_fail_before_hash', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r5_class_b_intermediate_ancestor_swap_is_refused', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r5_class_b_intermediate_ancestor_swap_is_refused', 'fixture', 'use_readlink_only_pathlib(monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r5_class_b_prefix_scan_uses_fresh_descriptor', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r7_class_d_verified_bytes_must_equal_stat_size', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_r7_class_d_verified_bytes_must_equal_stat_size', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r7_class_f_missing_effective_uid_refuses_before_open', 'callable', 'patch.delattr', True):
        ((0,), 'Existing patch.delattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_r7_class_f_missing_effective_uid_refuses_before_open', 'callable', 'patch.setattr', True):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_r7_class_f_missing_effective_uid_refuses_before_open', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r7_class_f_spans_refuse_before_ref_io', 'callable', 'patch.setattr', False):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_message_codec.py', 'test_r7_class_f_spans_refuse_before_ref_io', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r7_class_f_store_owner_is_effective_uid', 'callable', 'patch.delattr', True):
        ((0,), 'Existing patch.delattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_r7_class_f_store_owner_is_effective_uid', 'callable', 'patch.setattr', True):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_r7_class_f_store_owner_is_effective_uid', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r8_class_d_distinct_children_charge_work_before_decode', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_message_codec.py', 'test_r8_class_d_distinct_children_charge_work_before_decode', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r8_class_d_expansion_caches_and_refuses_before_unbounded_allocation', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_message_codec.py', 'test_r8_class_d_expansion_caches_and_refuses_before_unbounded_allocation', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r8_class_d_unicode_expansion_uses_display_length_and_cached_siblings', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_message_codec.py', 'test_r8_class_d_unicode_expansion_uses_display_length_and_cached_siblings', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r8_class_f_disappearance_and_operational_errors_are_distinct', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_message_codec.py', 'test_r8_class_f_disappearance_and_operational_errors_are_distinct', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r9_class_a_close_waits_for_operation_and_closed_store_refuses', 'callable', 'patch.setattr', True):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_r9_class_a_close_waits_for_operation_and_closed_store_refuses', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r9_class_d_all_valid_descriptor_records_fit_io_domain', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_message_codec.py', 'test_r9_class_d_all_valid_descriptor_records_fit_io_domain', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r9_class_d_descriptions_verify_each_call_and_detect_tampering', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_message_codec.py', 'test_r9_class_d_descriptions_verify_each_call_and_detect_tampering', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r9_class_d_span_coverage_examines_linear_text_and_merges_overlap', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_message_codec.py', 'test_r9_class_d_span_coverage_examines_linear_text_and_merges_overlap', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_r9_class_e_eight_user_parts_are_checked_before_alias_prefix', 'callable', 'patch.setattr', False):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_message_codec.py', 'test_r9_class_e_eight_user_parts_are_checked_before_alias_prefix', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_readlink_only_pathlib_bypasses_stat_observers', 'callable', 'patch.setattr', True):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_readlink_only_pathlib_bypasses_stat_observers', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_readlink_only_pathlib_bypasses_stat_observers', 'fixture', 'use_readlink_only_pathlib(patch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_real_leaf_replacement_before_open_binds_current_entry', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_real_leaf_replacement_before_open_binds_current_entry', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_real_leaf_replacement_before_open_binds_current_entry', 'fixture', 'use_readlink_only_pathlib(patch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_rf16_paging_hashes_each_prefix_row_once.hashing_chunks', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_message_codec.py', 'test_rf16_paging_hashes_each_prefix_row_once.hashing_chunks', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_same_basename_resolution_swap_never_binds_stale_path', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_message_codec.py', 'test_same_basename_resolution_swap_never_binds_stale_path', 'callable', 'patch.setattr', True):
        ((1,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_same_basename_resolution_swap_never_binds_stale_path', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_same_basename_resolution_swap_never_binds_stale_path', 'fixture', 'use_readlink_only_pathlib(patch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_store_leaf_observations_are_parent_anchored', 'callable', 'patch.setattr', False):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_message_codec.py', 'test_store_leaf_observations_are_parent_anchored', 'callable', 'patch.setattr', True):
        ((2,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_store_leaf_observations_are_parent_anchored', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_store_leaf_refusal_releases_parent_and_leaf', 'callable', 'patch.setattr', True):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_store_leaf_refusal_releases_parent_and_leaf', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'test_store_requires_anchored_leaf_stat_capabilities', 'callable', 'patch.setattr', True):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'test_store_requires_anchored_leaf_stat_capabilities', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'tracked_directory_fds', 'callable', 'patch.setattr', True):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_message_codec.py', 'tracked_directory_fds', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_message_codec.py', 'use_readlink_only_pathlib', 'callable', 'patch.setattr', False):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_model_select.py', 'test_ancestor_symlink_substitution_during_acquisition_refuses', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_model_select.py', 'test_ancestor_symlink_substitution_during_acquisition_refuses', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_model_select.py', 'test_log_disappearing_before_locked_open_has_stable_code', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_model_select.py', 'test_log_disappearing_before_locked_open_has_stable_code', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_model_select.py', 'test_os_log_path_rejections_keep_stable_codes', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_model_select.py', 'test_os_log_path_rejections_keep_stable_codes', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_model_select.py', 'test_partial_write_then_enospc_does_not_change_history', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_model_select.py', 'test_partial_write_then_enospc_does_not_change_history', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_model_select.py', 'test_round6_argon_cleanup_does_not_mask_descriptor_failure', 'callable', 'patch.setattr', True):
        ((0, 1), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_model_select.py', 'test_round6_argon_cleanup_does_not_mask_descriptor_failure', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_model_select.py', 'test_round6_configuration_ancestor_swap_refuses', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_model_select.py', 'test_round6_configuration_ancestor_swap_refuses', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_model_select.py', 'test_round6_opened_log_permissions_are_rechecked', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_model_select.py', 'test_round6_opened_log_permissions_are_rechecked', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_model_select.py', 'test_round7_config_paths_require_anchored_io', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_model_select.py', 'test_round7_config_paths_require_anchored_io', 'callable', 'patch.setattr', True):
        ((1,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_model_select.py', 'test_round7_config_paths_require_anchored_io', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_model_select.py', 'test_round7b_final_parent_component_refuses_before_io', 'callable', 'patch.setattr', True):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_model_select.py', 'test_round7b_final_parent_component_refuses_before_io', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_model_select.py', 'test_temp_symlink_substitution_cannot_change_victim_or_history', 'callable', 'patch.setattr', True):
        ((0, 1, 2), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_model_select.py', 'test_temp_symlink_substitution_cannot_change_victim_or_history', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_no_network_on_reads.py', '_env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_no_network_on_reads.py', '_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_no_network_on_reads.py', '_landed', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_no_network_on_reads.py', 'test_read_surfaces_exec_no_gh_found_on_path', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_pathlookup.py', 'TestWindowsLookup.test_relative_entries_are_skipped_on_windows_too', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_pathlookup.py', 'TestWindowsLookup.windows', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_pathlookup.py', 'test_a_relative_entry_resolves_against_the_cwd_by_default', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_pathlookup.py', 'test_empty_and_relative_entries_are_never_searched', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_pathlookup.py', 'test_the_default_path_is_the_environment_path', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_pathlookup_is_bare.py', 'isolated', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_pathlookup_is_bare.py', 'isolated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_polyglot_detect.py', 'test_provision_merges_into_a_config_written_after_it_was_read', 'owner', 'config_mod.RepoConfig', False):
        ((0,), 'Owner config_mod.RepoConfig has lexical candidates aegis_core.config.RepoConfig; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_primitives.py', '_fake_home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_primitives.py', '_fake_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_primitives.py', 'test_real_key_answers_none_when_resolving_raises', 'owner', 'primitives.os.path', True):
        ((0,), 'Owner primitives.os.path has lexical candidates aegis_core.primitives.os.path; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/core/test_primitives.py', 'test_real_key_folds_case_where_the_platform_does', 'owner', 'primitives.os.path', True):
        ((0, 1, 2), 'Owner primitives.os.path has lexical candidates aegis_core.primitives.os.path; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/core/test_primitives.py', 'test_real_path_drops_the_windows_extended_length_prefix', 'owner', 'primitives.os.path', True):
        ((0, 1), 'Owner primitives.os.path has lexical candidates aegis_core.primitives.os.path; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/core/test_primitives.py', 'test_verify_keeps_a_named_file_of_a_repository_at_the_filesystem_root', 'owner', 'verify', False):
        ((0,), 'Owner verify has lexical candidates aegis_cli.verify; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_primitives.py', 'test_verify_still_skips_a_named_file_outside_the_repository', 'owner', 'verify', False):
        ((0,), 'Owner verify has lexical candidates aegis_cli.verify; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_registry_readers.py', 'registry_paths', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_regression.py', '_commit_batch_reads', 'owner', 'gitsafe', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by bcb7061d06f6; Owner gitsafe resolves to aegis_core.gitsafe; reviewed consumer/class seam, not a shared module patch.'),
    ('tests/unit/core/test_regression.py', '_count_runs', 'owner', 'testexec', False):
        ((0,), 'Owner testexec has lexical candidates aegis_core.testexec; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression.py', '_env', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1, 2, 3), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_regression.py', '_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_regression.py', '_fake_outcomes', 'owner', 'testexec', False):
        ((0,), 'Owner testexec has lexical candidates aegis_core.testexec; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression.py', '_metadata_calls', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression.py', '_refuse_exemption_at_git_boundary', 'owner', 'gitsafe', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 72c729cfae93; Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression.py', 'test_a_git_failure_reaches_the_caller_as_a_git_error', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression.py', 'test_a_scratch_path_that_resolves_elsewhere_still_attributes_the_fix', 'owner', 'tempfile', False):
        ((0,), 'Owner tempfile has lexical candidates tempfile; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression.py', 'test_a_scratch_path_that_resolves_elsewhere_still_attributes_the_fix', 'owner', 'testexec', False):
        ((0,), 'Owner testexec has lexical candidates aegis_core.testexec; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression.py', 'test_diagnostic_failure_preserves_independent_primary_exemptions', 'owner', 'gitsafe', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 72c729cfae93; Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression.py', 'test_discovery_failure_does_not_start_a_diagnostic_reread', 'owner', 'gitsafe', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by bcb7061d06f6; Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression.py', 'test_exemption_discovery_timeout_is_not_retried_for_each_fix', 'owner', 'gitsafe', False):
        ((0, 1, 2), 'present at tip 4959830f before RF-11b landed; added by bcb7061d06f6; Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression.py', 'test_hermetic_runner_scrubs_environment', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'present at tip 4959830f before RF-11b landed; added by fdc953d106bc; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_regression.py', 'test_primary_verification_time_does_not_expire_in_memory_diagnostics', 'owner', 'gitsafe', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 72c729cfae93; Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression.py', 'test_refusal_index_checks_total_object_size_before_reading_content', 'owner', 'gitsafe', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 72c729cfae93; Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression.py', 'test_refusal_scan_failure_is_terminal_for_the_report', 'owner', 'gitsafe', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 72c729cfae93; Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression.py', 'test_refusal_scan_has_one_shared_deadline', 'owner', 'gitsafe', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 72c729cfae93; Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression_polyglot.py', 'go_metadata_selection.select', 'owner', 'regression_identity', False):
        ((0,), 'Owner regression_identity has lexical candidates aegis_core.verification.regression_identity; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression_polyglot.py', 'project', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_regression_polyglot.py', 'project', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_regression_polyglot.py', 'rust_metadata', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_regression_polyglot.py', 'rust_metadata', 'owner', 'testexec', False):
        ((0,), 'Owner testexec has lexical candidates aegis_core.testexec; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression_polyglot.py', 'test_configured_python_snapshot_identity_survives_a_temporary_directory_alias', 'owner', 'tempfile', False):
        ((0,), 'Owner tempfile has lexical candidates tempfile; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression_polyglot.py', 'test_go_without_native_driver_is_explicit_and_starts_no_process', 'owner', 'testexec', False):
        ((0,), 'Owner testexec has lexical candidates aegis_core.testexec; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression_polyglot.py', 'test_native_pair_runs_only_twice_across_fix_commits', 'owner', 'testexec', False):
        ((0,), 'Owner testexec has lexical candidates aegis_core.testexec; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression_polyglot.py', 'test_rust_fail_to_pass_overlays_only_owned_test_files', 'owner', 'testexec', False):
        ((0,), 'Owner testexec has lexical candidates aegis_core.testexec; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_regression_polyglot.py', 'test_unreadable_metadata_is_unmapped_without_uncategorized_codes', 'owner', 'testexec', False):
        ((0,), 'Owner testexec has lexical candidates aegis_core.testexec; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_release_verify.py', '_env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_release_verify.py', '_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_release_verify.py', '_git_tree_lookup', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_release_verify.py', 'cli', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_release_verify.py', 'test_a_missing_gh_is_none_through_the_closure', 'owner', 'ghcli', False):
        ((0,), 'Owner ghcli has lexical candidates aegis_core.ghcli; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_release_verify.py', 'test_a_type_error_inside_the_runner_propagates_and_gh_runs_once', 'owner', 'ghcli', False):
        ((0,), 'Owner ghcli has lexical candidates aegis_core.ghcli; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_release_verify.py', 'test_doctor_drivers_says_it_did_not_read_the_tier_and_asks_gh_nothing', 'owner', 'ghcli', False):
        ((0,), 'Owner ghcli has lexical candidates aegis_core.ghcli; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_release_verify.py', 'test_the_cli_prints_the_json_envelope_for_a_git_failure', 'owner', 'ghcli', False):
        ((0,), 'Owner ghcli has lexical candidates aegis_core.ghcli; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_release_verify.py', 'test_the_cli_prints_the_json_report_for_a_malformed_reviews_answer', 'owner', 'ghcli', False):
        ((0,), 'Owner ghcli has lexical candidates aegis_core.ghcli; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_release_verify.py', 'test_the_cli_says_verified_at_tier_a_only', 'owner', 'ghcli', False):
        ((0,), 'Owner ghcli has lexical candidates aegis_core.ghcli; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_release_verify.py', 'test_the_closure_maps_the_runner_result_and_defaults_to_the_release_timeout', 'owner', 'ghcli', False):
        ((0,), 'Owner ghcli has lexical candidates aegis_core.ghcli; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_repo_slots_untrusted.py', 'isolated_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2, 3), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_repo_slots_untrusted.py', 'test_interpreter_found_inside_workspace_is_not_executed', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_repo_slots_untrusted.py', 'test_packaged_go_driver_is_built_from_the_package_template', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_repo_slots_untrusted.py', 'test_run_layer1_fails_closed_when_external_interpreter_is_missing', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_repo_slots_untrusted.py', 'test_run_layer1_fails_closed_when_only_interpreter_is_inside_workspace', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_repo_slots_untrusted.py', 'test_run_layer1_fails_closed_when_packaged_interpreter_is_missing', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_repo_slots_untrusted.py', 'test_user_scope_driver_executable_inside_workspace_is_not_executed', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_repo_slots_untrusted.py', 'test_user_scope_driver_is_not_found_through_relative_path_entries', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_repo_slots_untrusted.py', 'test_user_scope_driver_is_not_found_through_relative_path_entries', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_repo_slots_untrusted.py', 'test_user_scope_driver_via_relative_path_entry_is_refused_even_outside_the_workspace', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_repo_slots_untrusted.py', 'test_user_scope_driver_via_relative_path_entry_is_refused_even_outside_the_workspace', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_repo_slots_untrusted.py', 'test_user_scope_file_inside_workspace_is_treated_as_repo', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_repo_slots_untrusted.py', 'test_user_scope_provisioned_selector_runs_packaged_driver_not_repo_copy', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_rule_integrity.py', '_env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_rule_integrity.py', '_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_rule_integrity.py', 'parse_count', 'owner', 'rules_mod', False):
        ((0,), 'Owner rules_mod has lexical candidates aegis_core.rules; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_rule_integrity.py', 'pull_event', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_rule_integrity.py', 'reviewed_weakening', 'owner', 'ghcli', False):
        ((0,), 'Owner ghcli has lexical candidates aegis_core.ghcli; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_rule_integrity.py', 'test_a_base_codeowners_that_does_not_own_the_change_reads_no_review', 'owner', 'ghcli', False):
        ((0,), 'Owner ghcli has lexical candidates aegis_core.ghcli; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_rule_integrity.py', 'test_a_doubtful_event_is_no_pull_request_and_calls_no_gh', 'owner', 'ghcli', False):
        ((0,), 'Owner ghcli has lexical candidates aegis_core.ghcli; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_rule_integrity.py', 'test_a_governance_change_at_a_signed_base_accepts_the_same_review', 'owner', 'ghcli', False):
        ((0,), 'Owner ghcli has lexical candidates aegis_core.ghcli; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_rule_integrity.py', 'test_a_signed_approval_still_passes_with_no_gh_call', 'owner', 'ghcli', False):
        ((0,), 'Owner ghcli has lexical candidates aegis_core.ghcli; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_rule_integrity.py', 'test_a_user_config_that_lies_inside_the_workspace_is_repository_content', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_rule_integrity.py', 'test_the_pull_request_event_names_the_range_when_no_flags_do', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_rule_inventory_integration.py', 'test_create_prompt_uses_inventory_bytes_without_reopen', 'owner', 'rules', False):
        ((0,), 'Owner rules has lexical candidates aegis_core.rules; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_rule_inventory_integration.py', 'test_invalid_utf8_is_exposed_as_diagnostic_by_sdk_and_mcp', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_rule_inventory_integration.py', 'test_mcp_list_parses_inventory_with_the_stdlib_parser', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_rule_inventory_integration.py', 'test_mcp_transport_marks_inventory_failure_as_error', 'owner', 'server', False):
        ((0, 1), 'Owner server has lexical candidates aegis_mcp.server; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_rule_inventory_integration.py', 'test_same_size_restored_mtime_edit_is_visible_to_sdk_and_mcp', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_rule_inventory_integration.py', 'test_sdk_and_mcp_direct_list_reject_symlinked_directory', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_rules.py', 'test_an_io_failure_after_a_warm_cache_raises_instead_of_serving_stale_rules', 'owner', 'inventory.os', True):
        ((0,), 'Owner inventory.os has lexical candidates aegis_core.rule_inventory.os; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/core/test_rust_native_driver.py', 'test_distinct_attribute_membership_work_is_linear', 'owner', 'extractor', False):
        ((0,), 'Owner extractor has lexical candidates aegis_core.ast.drivers.rust.extractor; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_rust_native_integration.py', 'test_native_rust_ignores_commands_and_malformed_repository_config', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_rust_native_integration.py', 'test_rust_doctor_and_card_are_ready_without_a_toolchain', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_scaffolding.py', 'TestInitWorkflowRecognition.project', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_scaffolding.py', 'TestInitWorkflowRecognition.project', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2, 3), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_scaffolding.py', 'TestInitWorkflowRecognition.project', 'owner', 'hosts', False):
        ((0,), 'Owner hosts has lexical candidates aegis_core.hosts; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_scaffolding.py', 'TestInitWorkflowRecognition.test_an_unreadable_workflow_is_not_reported_as_running_check', 'owner', 'builtins', True):
        ((0,), 'Owner builtins has lexical candidates builtins; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/core/test_scan_ledger_reads.py', '_reads', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_scan_ledger_reads.py', '_reads', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_scan_ledger_reads.py', 'test_an_mcp_scan_without_filesystem_clock_keeps_locked_reads', 'owner', 'credit_memo', False):
        ((0,), 'Owner credit_memo has lexical candidates aegis_core.credit_memo; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_scan_ledger_reads.py', 'ws', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_scan_ledger_reads.py', 'ws', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_scan_reads_no_github.py', '_env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_scan_reads_no_github.py', '_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_scan_spawn_budget.py', '_count', 'callable', 'patch.setattr', False):
        ((0,), 'Existing patch.setattr spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/core/test_scan_spawn_budget.py', '_count', 'callable', 'patch.setattr', True):
        ((1,), 'Existing patch.setattr spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_scan_spawn_budget.py', '_count', 'fixture', 'monkeypatch.context', False):
        ((0,), 'Fixture context operation; context body is independently censused.'),
    ('tests/unit/core/test_scan_spawn_budget.py', '_projections', 'owner', 'credit', False):
        ((0,), 'Owner credit has lexical candidates aegis_core.credit; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_scan_spawn_budget.py', 'isolated', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_scan_spawn_budget.py', 'isolated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2, 3), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_scan_spawn_budget.py', 'test_a_matching_scan_is_what_fitness_over_every_rule_gives', 'owner', 'scan_mod', False):
        ((0,), 'Owner scan_mod has lexical candidates aegis_core.scan; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_scan_spawn_budget.py', 'test_an_mcp_scan_counts_index_reads_and_memo_validation', 'owner', 'credit', False):
        ((0,), 'Owner credit has lexical candidates aegis_core.credit; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_scan_spawn_budget.py', 'test_an_mcp_scan_counts_index_reads_and_memo_validation', 'owner', 'credit_memo', False):
        ((0, 1, 2, 3), 'Owner credit_memo has lexical candidates aegis_core.credit_memo; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_scan_spawn_budget.py', 'test_an_mcp_scan_counts_index_reads_and_memo_validation', 'owner', 'server', False):
        ((0,), 'Owner server has lexical candidates aegis_mcp.server; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_security_ssrf_config.py', 'test_repo_config_cannot_supply_the_layer2_command', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_shared_ledger.py', 'test_when_git_cannot_run_the_ledger_stays_local', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_shared_state.py', 'test_without_git_it_is_the_workspace_state_dir', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_slots.py', 'test_slot_registry_load_user_reads_drivers_and_slots', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_slots_hosts.py', 'isolated_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_slots_shipped_text.py', 'test_shipped_text_renders_completely_for_every_host', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_storage.py', 'test_anchored_file_lock_refuses_an_unsupported_platform', 'owner', 'storage', False):
        ((0,), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_storage.py', 'test_append_jsonl_evidence_is_opt_in', 'owner', 'storage', False):
        ((0,), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_storage.py', 'test_append_jsonl_fsyncs_once_per_call', 'callable', 'patch', True):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_storage.py', 'test_append_jsonl_missing_optional_evidence_still_succeeds', 'owner', 'storage', False):
        ((0,), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_storage.py', 'test_atomic_write_failure_leaves_target_and_no_temp', 'callable', 'patch', True):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_storage.py', 'test_atomic_write_gives_up_after_eight_attempts', 'callable', 'patch', True):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_storage.py', 'test_atomic_write_retries_windows_sharing_violation', 'callable', 'patch', True):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/core/test_storage.py', 'test_byte_range_file_lock_does_not_reenter_a_distinct_stream', 'owner', 'storage', False):
        ((0, 1, 2), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_storage.py', 'test_create_private_file_removes_a_partial_file_when_the_write_fails', 'owner', 'atomicio', False):
        ((0,), 'Owner atomicio has lexical candidates aegis_core.atomicio; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_storage.py', 'test_jsonl_reports_generation_without_process_clock_or_extra_append_reads', 'owner', 'storage', False):
        ((0, 1), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_storage.py', 'test_jsonl_reports_the_descriptor_identity_and_end_offset', 'owner', 'storage', False):
        ((0,), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_storage.py', 'test_read_jsonl_closes_descriptor_when_fdopen_fails', 'owner', 'storage', False):
        ((0, 1), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_storage.py', 'test_the_mode_is_set_on_the_temporary_file_never_on_a_link_swapped_in_at_its_name', 'owner', 'atomicio', False):
        ((0,), 'Owner atomicio has lexical candidates aegis_core.atomicio; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_storage_parse_jsonl.py', 'isolated', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_storage_parse_jsonl.py', 'isolated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_storage_shared.py', 'test_public_scan_covers_storage_confinement', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_storage_shared.py', 'test_public_scan_covers_storage_confinement', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_sync.py', 'labelled_ws', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_sync.py', 'recorded_gh', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_sync.py', 'recorded_gh', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2, 3), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_sync.py', 'test_a_git_failure_during_replay_is_said_and_the_sync_still_writes', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_sync.py', 'test_sync_and_doctor_state_when_base_was_last_fetched', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_sync.py', 'user_home', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_team.py', 'test_defaults_are_the_implementer_role_an_hour_no_branch_and_user_at_host', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_team.py', 'test_release_defaults_the_caller_to_user_at_host', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_team_metrics.py', 'test_with_no_base_branch_the_whole_first_parent_history_counts', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_team_metrics.py', 'test_without_a_base_the_branch_base_is_resolved_as_check_lane_does', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_team_profile.py', 'test_user_root_aliases_resolve_before_anchored_read', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Merged-tip fixture monkeypatch.setenv operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/core/test_testexec.py', '_home', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_testexec.py', '_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_testexec.py', 'test_a_user_command_whose_config_file_is_inside_the_workspace_is_refused', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_testplans.py', 'project', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_testplans.py', 'test_executable_lookup_refuses_repository_and_relative_candidates', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_testplans.py', 'test_missing_executable_is_unavailable', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_tmp_path_git_isolation.py', 'test_ceiling_blocks_enclosing_repository', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_tmp_path_git_isolation.py', 'test_ceiling_blocks_enclosing_repository', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_tmp_path_git_isolation.py', 'test_ceiling_entry_semantics_match_git', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by aa4aece3e9a1; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_tmp_path_git_isolation.py', 'test_empty_ceiling_marker_avoids_resolving_later_entries', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by aa4aece3e9a1; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_tmp_path_git_isolation.py', 'test_empty_ceiling_marker_avoids_resolving_later_entries', 'owner', 'binding', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by aa4aece3e9a1; Owner binding has lexical candidates aegis_core.workspace.binding; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_tmp_path_git_isolation.py', 'test_git_boundary_matches_git_oracle', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by aa4aece3e9a1; Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_tmp_path_git_isolation.py', 'test_git_boundary_matches_git_oracle', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'present at tip 4959830f before RF-11b landed; added by aa4aece3e9a1; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_tmp_path_git_isolation.py', 'test_insight_workspace_id_respects_ceiling', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_tmp_path_git_isolation.py', 'test_insight_workspace_id_respects_ceiling', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_tmp_path_git_isolation.py', 'test_operator_ceiling_cannot_admit_manager_store_in_enclosing_checkout', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by aa4aece3e9a1; Merged-tip fixture monkeypatch.delenv operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/core/test_tmp_path_git_isolation.py', 'test_operator_ceiling_cannot_admit_manager_store_in_enclosing_checkout', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by aa4aece3e9a1; Merged-tip fixture monkeypatch.setenv operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/core/test_tmp_path_git_isolation.py', 'test_workspace_discovery_respects_ceiling_but_store_placement_does_not', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by aa4aece3e9a1; Merged-tip fixture monkeypatch.delenv operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/core/test_tmp_path_git_isolation.py', 'test_workspace_discovery_respects_ceiling_but_store_placement_does_not', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by aa4aece3e9a1; Merged-tip fixture monkeypatch.setenv operation; environment/path setup at this exact scope and line.'),
    ('tests/unit/core/test_tmp_path_git_isolation.py', 'test_workspace_is_git_respects_ceiling', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_tmp_path_git_isolation.py', 'test_workspace_is_git_respects_ceiling', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_treeid_filters.py', 'system_config', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_treeid_filters.py', 'system_config', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_treeid_filters.py', 'test_with_the_system_config_switched_off_its_filter_does_not_run_either', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_treeid_submodules.py', '_home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_treeid_submodules.py', '_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_treeid_submodules.py', 'test_the_work_tree_s_git_variables_never_reach_a_submodule', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_treeid_submodules.py', 'test_without_git_the_binding_is_unbindable_and_nothing_raises', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_user_config_reader.py', '_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_user_config_reader.py', 'repo', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_user_config_reader.py', 'repo', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_v3_zero_legacy_invariants.py', 'TestV3CLIOutputContextAndANSIHygiene.test_cli_commands_emit_zero_ansi_when_plain_or_no_color', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_v3_zero_legacy_invariants.py', 'TestV3CLIOutputContextAndANSIHygiene.test_cli_commands_emit_zero_ansi_when_plain_or_no_color', 'owner', 'doctor', False):
        ((0,), 'Owner doctor has lexical candidates aegis_cli.doctor; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_v3_zero_legacy_invariants.py', 'TestV3CLIOutputContextAndANSIHygiene.test_every_registered_command_supports_output_context', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_v3_zero_legacy_invariants.py', 'TestV3CLIOutputContextAndANSIHygiene.test_every_registered_command_supports_output_context', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_verified_checks_units.py', '_ambient', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_verified_checks_units.py', '_home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_verified_checks_units.py', '_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_verified_checks_units.py', '_record_with_stand_in', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_verified_checks_units.py', 'test_a_recorded_snapshot_enforces_its_gate_rules_wherever_the_temp_dir_is', 'owner', 'tempfile', False):
        ((0,), 'Owner tempfile has lexical candidates tempfile; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_verified_checks_units.py', 'test_a_rerun_that_times_out_is_unbound_and_check_ci_passes', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_verified_checks_units.py', 'test_a_signer_history_git_cannot_read_fails_closed', 'owner', 'gitsafe', False):
        ((0, 1), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_verified_checks_units.py', 'test_approve_reads_the_key_from_the_user_config_and_signs_in_the_repository_asked_about', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_verified_checks_units.py', 'test_approve_reads_the_key_from_the_user_config_and_signs_in_the_repository_asked_about', 'owner', 'approve', False):
        ((0,), 'Owner approve has lexical candidates aegis_cli.approve; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_verified_checks_units.py', 'test_approve_reads_the_key_from_the_user_config_and_signs_in_the_repository_asked_about', 'owner', 'builtins', True):
        ((0,), 'Owner builtins has lexical candidates builtins; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/core/test_verified_checks_units.py', 'test_approve_reads_the_key_from_the_user_config_and_signs_in_the_repository_asked_about', 'owner', 'human_gate', False):
        ((0, 1), 'Owner human_gate has lexical candidates aegis_core.human_gate; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_verified_checks_units.py', 'test_git_trouble_fails_closed_and_a_programming_error_propagates', 'owner', 'human_gate', False):
        ((0, 1), 'Owner human_gate has lexical candidates aegis_core.human_gate; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_verified_checks_units.py', 'test_the_run_sees_a_fixed_environment', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_windows_junction.py', 'test_handle_identity_failure_preserves_entry_without_writing', 'owner', 'windows_junction', False):
        ((0,), 'Owner windows_junction has lexical candidates aegis_core.verification.windows_junction; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_windows_junction.py', 'test_identity_fixture_models_python_widths_when_host_identifiers_are_wide', 'owner', 'windows_junction', False):
        ((0,), 'Owner windows_junction has lexical candidates aegis_core.verification.windows_junction; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_windows_junction.py', 'test_legacy_ambiguous_filesystem_never_authorizes_write_or_rollback', 'owner', 'windows_junction', False):
        ((0,), 'Owner windows_junction has lexical candidates aegis_core.verification.windows_junction; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_windows_junction.py', 'test_matching_native_identity_is_verified_before_the_write', 'owner', 'windows_junction', False):
        ((0,), 'Owner windows_junction has lexical candidates aegis_core.verification.windows_junction; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/core/test_workspace.py', 'TestWorkspaceCore.test_resolve_workspace_walkup', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_workspace.py', 'TestWorkspaceCore.test_resolve_workspace_with_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_workspace_binding.py', 'home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_workspace_binding.py', 'test_workspace_resolve_never_selects_home', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_workspace_binding.py', 'test_workspace_resolve_never_walks_out_of_a_nested_repository', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_workspace_binding.py', 'test_workspace_resolve_still_walks_up_inside_one_repository', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_workspace_discovery.py', 'home', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_workspace_discovery.py', 'home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_workspace_discovery.py', 'home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_workspace_hooks.py', 'no_user_git_config', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_workspace_model.py', 'TestWorkspaceModel.test_workspace_resolve_env', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_workspace_model.py', 'TestWorkspaceModel.test_workspace_resolve_strict_env_error', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/core/test_workspace_model.py', 'TestWorkspaceModel.test_workspace_resolve_walkup', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/conftest.py', 'fresh_server', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_binding_guards.py', 'cwd_with_a_governed_child', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_binding_guards.py', 'home', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_binding_guards.py', 'home', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_binding_guards.py', 'home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_binding_guards.py', 'test_a_relative_claude_project_dir_is_ignored', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_insight_session_binding.py', 'home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_insight_session_binding.py', 'home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_insight_session_binding.py', 'test_an_unreadable_ledger_site_still_records_the_exposure_in_memory_with_one_call', 'owner', 'storage', False):
        ((0,), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/mcp/test_jit_context_budget.py', 'TestJITContextBudgetClamping.test_config_file_sets_token_budget', 'callable', 'patch', True):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/mcp/test_jit_context_budget.py', 'TestJITContextBudgetClamping.test_config_file_sets_token_budget', 'callable', 'patch.dict', True):
        ((0,), 'Existing patch.dict spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/mcp/test_jit_context_budget.py', 'TestJITContextBudgetClamping.test_default_token_budget_is_2000', 'callable', 'patch', True):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/mcp/test_jit_context_budget.py', 'TestJITContextBudgetClamping.test_default_token_budget_is_2000', 'callable', 'patch.dict', True):
        ((0,), 'Existing patch.dict spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/mcp/test_jit_context_budget.py', 'TestJITContextBudgetClamping.test_env_var_overrides_token_budget', 'callable', 'patch', True):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/mcp/test_jit_context_budget.py', 'TestJITContextBudgetClamping.test_env_var_overrides_token_budget', 'callable', 'patch.dict', True):
        ((0,), 'Existing patch.dict spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/mcp/test_jit_context_budget.py', 'TestJITContextBudgetClamping.test_legacy_aegis_conf_is_not_read', 'callable', 'patch', True):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/mcp/test_jit_context_budget.py', 'TestJITContextBudgetClamping.test_legacy_aegis_conf_is_not_read', 'callable', 'patch.dict', True):
        ((0,), 'Existing patch.dict spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/mcp/test_jit_payload.py', 'many_gates', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_jit_payload.py', 'test_budget_bounds_gate_rules_written_without_spaces', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_jit_payload.py', 'test_mandatory_rules_take_two_slots_through_the_mcp_tool_too', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_annotations.py', 'governed', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_attribution.py', 'test_a_scan_of_the_git_diff_records_the_diffed_files', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/mcp/test_mcp_attribution.py', 'test_an_empty_files_list_scans_the_git_diff_and_records_the_scan', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_attribution.py', 'test_an_empty_files_list_scans_the_git_diff_and_records_the_scan', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_attribution.py', 'ws', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_capture_insight.py', 'bounded', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_capture_insight.py', 'test_aegis_capture_insight_records_suggestion_and_is_corroborated_never_upgraded', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_capture_insight.py', 'test_aegis_capture_insight_rejects_invalid_arguments_and_path_traversal', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_compact_json.py', 'repository', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_compact_json.py', 'test_repository_never_reads_developer_registry', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_handlers.py', 'test_a_sessionless_read_is_the_hosts_own_exposures_never_another_hosts_session', 'owner', 'credit', False):
        ((0,), 'Owner credit has lexical candidates aegis_mcp.handlers.telemetry.credit; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/mcp/test_mcp_handlers.py', 'test_the_witnessed_set_holds_only_what_this_process_exposed', 'owner', 'credit', False):
        ((0,), 'Owner credit has lexical candidates aegis_mcp.handlers.telemetry.credit; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/mcp/test_mcp_msg.py', 'test_ambiguous_host_roots_dispatch_gives_launch_pin_guidance', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_msg.py', 'test_message_write_fsyncs_state_only_when_preparing_ignore', 'owner', 'storage', False):
        ((0,), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/mcp/test_mcp_msg.py', 'test_operational_refusals_match_cli', 'owner', 'storage', False):
        ((0,), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/mcp/test_mcp_msg.py', 'test_read_preflight_precedes_all_store_io', 'owner', 'storage', False):
        ((0,), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/mcp/test_mcp_msg.py', 'test_real_pin_error_dispatch_selects_reason_specific_remedy', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_msg.py', 'test_real_unbound_host_roots_dispatch_gives_init_guidance', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_msg.py', 'test_rendering_seam_bounds_even_pre_rendered_text', 'owner', 'msg', False):
        ((0,), 'Owner msg has lexical candidates aegis_mcp.handlers.msg; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/mcp/test_mcp_msg.py', 'test_selector_bounds_refuse_before_store_access', 'owner', 'storage', False):
        ((0,), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/mcp/test_mcp_msg.py', 'test_state_preparation_cannot_follow_a_swapped_ancestor', 'owner', 'storage', False):
        ((0,), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/mcp/test_mcp_msg.py', 'test_unsupported_platform_refuses_without_creating_state', 'owner', 'storage', False):
        ((0,), 'Owner storage has lexical candidates aegis_core.storage; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/mcp/test_mcp_msg.py', 'workspace', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_msg.py', 'workspace', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_projection.py', 'isolated_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_projection.py', 'test_public_scan_ids_reports_more_omitted_mandatory_rules_than_names', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 071720276e5b; Existing fixture environment/path setup at these exact source lines.'),
    ('tests/unit/mcp/test_mcp_projection.py', 'test_public_scan_summary_keeps_exact_totals_within_the_scan_budget', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip 4959830f before RF-11b landed; added by 4d7d220da843; Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_protocol_hygiene.py', 'home', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_protocol_hygiene.py', 'home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_protocol_hygiene.py', 'test_an_unknown_registration_env_is_ignored', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_protocol_hygiene.py', 'test_the_registration_env_wins_over_client_info', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_report_outcome.py', '_project', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_report_outcome.py', '_project', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_report_outcome.py', 'reporting', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_report_outcome.py', 'reporting', 'owner', 'telemetry', False):
        ((0, 1), 'Owner telemetry has lexical candidates aegis_mcp.handlers.telemetry; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/mcp/test_mcp_rule_integrity.py', '_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_runtime_binding.py', 'home', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_runtime_binding.py', 'home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_runtime_binding.py', 'home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_runtime_binding.py', 'test_a_pin_error_answers_every_tool_call_before_its_params_are_read', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_runtime_binding.py', 'test_a_pin_that_disagrees_with_the_host_holds_and_writes_nothing', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_runtime_binding.py', 'test_a_pin_through_a_symlink_loop_keeps_the_server_up_in_an_error_state', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_runtime_binding.py', 'test_a_relative_codex_meta_workspace_is_ignored', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_runtime_binding.py', 'test_an_inherited_claude_project_dir_under_another_client_is_ignored', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_runtime_binding.py', 'test_an_unusable_pin_puts_the_server_in_an_error_state', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_runtime_binding.py', 'test_an_unusable_pin_puts_the_server_in_an_error_state', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_runtime_binding.py', 'test_claude_project_dir_binds_and_a_model_workspace_argument_is_ignored', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_runtime_binding.py', 'test_one_workspace_object_serves_every_call_bound_to_the_same_root_and_source', 'owner', 'governance', False):
        ((0,), 'Owner governance has lexical candidates aegis_mcp.handlers.governance; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/mcp/test_mcp_runtime_binding.py', 'test_relative_files_in_two_registered_workspaces_follow_the_server_cwd', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_runtime_binding.py', 'test_the_server_cwd_walks_up_to_its_workspace', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_session_close_side_effects.py', 'governed_repo', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_session_stdio_contract.py', '_cwd_is_home', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_session_stdio_contract.py', '_cwd_is_home_with_v33_user_rules', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_session_stdio_contract.py', '_cwd_without_aegis', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_session_stdio_contract.py', '_pin_missing_dir', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_session_stdio_contract.py', '_pin_missing_dir', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_session_stdio_contract.py', '_pin_without_aegis', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_session_stdio_contract.py', '_pin_without_aegis', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_session_stdio_contract.py', 'home', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_session_stdio_contract.py', 'home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_session_stdio_contract.py', 'test_governed_workspace_still_dispatches_tools', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_session_stdio_contract.py', 'test_non_object_frame_gets_invalid_request_and_server_keeps_serving', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_session_stdio_contract.py', 'test_ungoverned_server_stays_up_creates_nothing_and_answers_not_governed', 'fixture', 'setup(home, tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/mcp/test_mcp_session_stdio_contract.py', 'test_unusable_pin_keeps_the_server_up_and_errors_every_tool_call', 'fixture', 'setup(home, tmp_path, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/mcp/test_mcp_session_stdio_contract.py', 'test_wrong_jsonrpc_version_request_gets_invalid_request', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_surface.py', 'test_execution_env_flag_no_longer_widens_the_surface', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_surface.py', 'test_write_tool_runs_without_a_receipt_or_token', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_team_config.py', 'test_default_root_uses_cli_resolution_without_rules', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by c52b9d05; Sets the isolated home/workspace environment or cwd for MCP/CLI team-configuration parity; pytest restores it.'),
    ('tests/unit/mcp/test_mcp_team_config.py', 'test_default_root_uses_cli_resolution_without_rules', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by c52b9d05; Sets the isolated home/workspace environment or cwd for MCP/CLI team-configuration parity; pytest restores it.'),
    ('tests/unit/mcp/test_mcp_team_config.py', 'test_default_root_uses_cli_resolution_without_rules', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by c52b9d05; Sets the isolated home/workspace environment or cwd for MCP/CLI team-configuration parity; pytest restores it.'),
    ('tests/unit/mcp/test_mcp_team_config.py', 'test_missing_workspace_matches_cli_without_raw_token', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by c52b9d05; Sets the isolated home/workspace environment or cwd for MCP/CLI team-configuration parity; pytest restores it.'),
    ('tests/unit/mcp/test_mcp_team_config.py', 'test_missing_workspace_matches_cli_without_raw_token', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by c52b9d05; Sets the isolated home/workspace environment or cwd for MCP/CLI team-configuration parity; pytest restores it.'),
    ('tests/unit/mcp/test_mcp_team_config.py', 'test_supplied_workspace_spellings_match_public_cli', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by c52b9d05; Sets the isolated home/workspace environment or cwd for MCP/CLI team-configuration parity; pytest restores it.'),
    ('tests/unit/mcp/test_mcp_team_config.py', 'test_supplied_workspace_spellings_match_public_cli', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by c52b9d05; Sets the isolated home/workspace environment or cwd for MCP/CLI team-configuration parity; pytest restores it.'),
    ('tests/unit/mcp/test_mcp_team_config.py', 'test_workspace_input_table_matches_public_cli', 'fixture', 'monkeypatch.chdir', False):
        ((0, 1), 'present at tip b11638bf before RF-11b landed; added by c52b9d05; Sets the isolated home/workspace environment or cwd for MCP/CLI team-configuration parity; pytest restores it.'),
    ('tests/unit/mcp/test_mcp_team_config.py', 'test_workspace_input_table_matches_public_cli', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by c52b9d05; Sets the isolated home/workspace environment or cwd for MCP/CLI team-configuration parity; pytest restores it.'),
    ('tests/unit/mcp/test_mcp_team_config.py', 'workspace', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'present at tip b11638bf before RF-11b landed; added by c52b9d05; Sets the isolated home/workspace environment or cwd for MCP/CLI team-configuration parity; pytest restores it.'),
    ('tests/unit/mcp/test_mcp_tools_contract.py', 'TestAegisCreateRule.test_create_rule_returns_prompt', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_tools_contract.py', 'TestAegisListRules.test_list_returns_rules_stale_rules_and_ignored', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_tools_contract.py', 'TestAegisReportOutcome.test_invalid_outcome_returns_error', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_tools_contract.py', 'TestAegisReportOutcome.test_report_outcome_rejects_non_list_rules', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_tools_contract.py', 'TestAegisReportOutcome.test_valid_outcome_returns_recorded', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_tools_contract.py', 'TestAegisScan.test_scan_blocks_path_traversal', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_tools_contract.py', 'TestAegisScan.test_scan_rejects_non_list_files', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_tools_contract.py', 'TestAegisScan.test_scan_returns_required_keys', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_tools_contract.py', 'TestAegisScan.test_scan_with_files_arg', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_mcp_tools_contract.py', 'TestToolOutputSerializability.test_output_is_json_serializable', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_scan_rows_window.py', 'small_map', 'owner', 'core', False):
        ((0, 1), 'Owner core has lexical candidates aegis_mcp.handlers.core; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/mcp/test_scan_rows_window.py', 'ws', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_skills.py', 'TestSlotRegistry.test_slot_loading_from_user_config', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_v4_telemetry_tier_and_client_slots.py', 'test_initialize_detects_client_platform_and_interpolates_slots_in_scan', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/mcp/test_v4_telemetry_tier_and_client_slots.py', 'test_repo_root_aegis_scan_loads_cleanly_without_integrity_warnings', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_changelog.py', 'test_each_removed_flag_in_the_entry_exits_2', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_docs_claims.py', 'test_docs_name_real_rule_directories_and_shared_ledger_paths', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_no_real_gh.py', 'test_a_path_built_from_gits_directory_finds_no_real_gh', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_pypi_state.py', 'dist', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_pypi_state.py', 'dist', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_pypi_state.py', 'dist', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_pypi_state.py', 'test_nothing_on_pypi_uploads_every_file', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_readme.py', 'quick_start', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_readme.py', 'quick_start', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_readme.py', 'quick_start', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_readme.py', 'quick_start', 'owner', 'install_hosts', False):
        ((0,), 'Owner install_hosts has lexical candidates aegis_cli.install_hosts; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/test_readme.py', 'test_language_guide_config_examples_expand_as_documented', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_readme.py', 'test_the_docs_say_plain_check_enforces_the_reviewed_rules', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_readme.py', 'test_the_docs_state_the_gemini_cli_retirement_as_aegis_refuses_it', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_readme.py', 'test_the_readme_states_the_enforcement_tiers_as_doctor_reports_them', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_readme.py', 'test_the_readme_states_the_enforcement_tiers_as_doctor_reports_them', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_readme.py', 'test_the_readme_states_the_enforcement_tiers_as_doctor_reports_them', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_readme.py', 'test_the_readme_states_the_enforcement_tiers_as_doctor_reports_them', 'owner', 'doctor', False):
        ((0,), 'Owner doctor has lexical candidates aegis_cli.doctor; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/test_release_guard.py', 'env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_release_guard.py', 'env', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/test_release_guard.py', 'env', 'fixture', 'return monkeypatch', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/verification/test_call_graph_ast.py', 'TestCallGraphAST.test_call_graph_fast_mode_skips_external_walk', 'owner', 'os', True):
        ((0,), 'Owner os has lexical candidates os; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/verification/test_canonical_evidence_readers.py', 'test_lifecycle_uses_weighted_ledger_rows', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_checkpoint_fail_closed.py', 'test_rule_stat_failure_is_an_issue', 'owner', 'inventory.os', True):
        ((0,), 'Owner inventory.os has lexical candidates aegis_core.rule_inventory.os; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/verification/test_coverage_check.py', 'TestCheckCliIntegration.test_ci_coverage_is_reported_and_never_changes_the_exit_code', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_coverage_check.py', 'TestCheckCliIntegration.test_ci_coverage_is_reported_and_never_changes_the_exit_code', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_coverage_check.py', 'TestCheckCliIntegration.test_ci_coverage_on_a_checkout_that_is_not_the_head_says_unverified_and_exits_0', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_coverage_check.py', 'TestCheckCliIntegration.test_ci_format_sarif_and_github_step_summary', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_coverage_check.py', 'TestReportOnlyCoverage.test_a_configured_python_process_controls_coverage', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_coverage_check.py', 'TestReportOnlyCoverage.test_both_coverage_commands_keep_the_interpreter_contract', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_coverage_check.py', 'TestSarifIsSchemaValidAndHonest.test_a_weakening_without_a_line_is_no_result_and_an_approved_one_is_no_failure', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_coverage_check.py', 'TestSarifIsSchemaValidAndHonest.test_an_error_path_still_prints_a_valid_empty_log', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_coverage_check.py', 'cov_env', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_coverage_check.py', 'cov_env', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_coverage_quoted_paths.py', 'test_a_real_diff_of_a_non_ascii_file_attributes_its_lines', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_coverage_quoted_paths.py', 'test_coverage_of_a_non_ascii_file_counts_its_lines', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_coverage_quoted_paths.py', 'test_coverage_of_a_non_ascii_file_counts_its_lines', 'owner', 'coverage_check', False):
        ((0,), 'Owner coverage_check has lexical candidates aegis_core.verification.coverage_check; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/verification/test_forbid_ast_hardening.py', 'TestSourceIdentity.test_one_line_source_naming_an_existing_file_is_not_swapped_for_it', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_forbid_ast_hardening.py', 'TestTheScalingCheck.test_a_quadratic_evaluator_fails_the_ratio', 'owner', 'policy', False):
        ((0,), 'Owner policy has lexical candidates aegis_core.ast.policy; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/verification/test_forbid_ast_rules.py', 'TestAdvisoryNotes.test_a_note_that_cannot_be_made_fails_closed', 'owner', 'runner', False):
        ((0,), 'Owner runner has lexical candidates aegis_core.verification.runner; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/verification/test_forbid_ast_rules.py', 'TestMalformedWhereFailsClosedInLayer1.test_the_staged_snapshot_path_refuses_the_rule', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_import_guard.py', 'TestImportExtraction.test_membership_work_is_linear', 'owner', 'ig', False):
        ((0,), 'Owner ig has lexical candidates aegis_core.verification.import_guard; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/verification/test_import_guard.py', 'TestStdlibClassification.test_python39_fallback_simulation', 'owner', 'ig', False):
        ((0,), 'Owner ig has lexical candidates aegis_core.verification.import_guard; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/verification/test_import_guard.py', 'TestStdlibClassification.test_python39_fallback_simulation', 'owner', 'sys', True):
        ((0,), 'Owner sys has lexical candidates sys; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/verification/test_import_guard.py', 'discovery_fs', 'owner', 'import_guard', False):
        ((0,), 'Merged-tip owner import_guard has static candidates aegis_core.verification.import_guard; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/verification/test_import_guard.py', 'test_importorskip_line_scanning_is_linear', 'owner', 'import_guard', False):
        ((0,), 'Merged-tip owner import_guard has static candidates aegis_core.verification.import_guard; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/verification/test_layer1.py', 'TestGetModifiedLines.test_get_modified_lines_uses_the_pull_request_base', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_layer1.py', 'TestLayer1FailsClosed.test_forbid_ast_exception_becomes_a_failing_result', 'owner', 'policy', False):
        ((0,), 'Owner policy has lexical candidates aegis_core.ast.policy; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/verification/test_layer1.py', 'TestLayer1FailsClosed.test_forbid_ast_rule_discovery_failure_fails_closed', 'owner', 'runner', False):
        ((0,), 'Owner runner has lexical candidates aegis_core.verification.runner; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/verification/test_layer1.py', 'TestOneForbidAstEvaluation.test_each_file_and_rule_is_evaluated_once_however_many_sites', 'owner', 'policy', False):
        ((0,), 'Owner policy has lexical candidates aegis_core.ast.policy; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/verification/test_layer1.py', 'TestOneForbidAstEvaluation.test_each_file_and_rule_is_evaluated_once_however_many_sites', 'owner', 'security_pack', False):
        ((0,), 'Owner security_pack has lexical candidates aegis_core.verification.security_pack; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/verification/test_layer1.py', 'TestRunnerCoverageEnhancements.test_run_layer1_polyglot_call_graph', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_mutation_scope.py', 'TestMutantReachesEveryImporter.test_check_leaves_the_tree_as_it_found_it', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_mutation_scope.py', 'TestMutantReachesEveryImporter.test_no_test_files_fails_closed_without_running_pytest', 'fixture', 'install_fake_popen(monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/verification/test_mutation_scope.py', 'TestRunTimeouts.test_baseline_timeout_is_reported_with_its_limit', 'callable', 'patch', False):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/verification/test_mutation_scope.py', 'TestRunTimeouts.test_baseline_timeout_is_reported_with_its_limit', 'fixture', 'install_fake_popen(monkeypatch, hang=True)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestCheckTestsSpawn.test_a_spawn_is_killed_as_a_group_after_it_ends', 'callable', 'patch', False):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestCheckTestsSpawn.test_a_spawn_is_killed_as_a_group_after_it_ends', 'fixture', 'install_fake_popen(monkeypatch, returncode=0)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestCheckTestsSpawn.test_pytest_runs_through_popen_in_its_own_group_even_when_run_is_replaced', 'owner', 'subprocess', True):
        ((0, 1), 'Owner subprocess has lexical candidates subprocess; not a unique module-level import. Includes a shared process module.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestModuleSwapStaging.test_check_tests_kills_process_group_on_timeout', 'callable', 'patch', False):
        ((0, 2), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestModuleSwapStaging.test_check_tests_kills_process_group_on_timeout', 'callable', 'patch', True):
        ((1,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestModuleSwapStaging.test_mutant_startup_timeout_retries_once_and_does_not_survive', 'callable', 'patch', False):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestModuleSwapStaging.test_the_plugin_dir_comes_first_and_an_inherited_pythonpath_is_kept', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestModuleSwapStaging.test_the_plugin_dir_comes_first_and_an_inherited_pythonpath_is_kept', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_argon_alias_ceiling_and_test_path_share_physical_boundary', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_basetemp_inside_checkout_respects_git_ceiling', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_common_test_directory_equal_to_ceiling_stops_discovery', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_discovery_walk_at_ceiling_keeps_start_only', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_each_selection_keeps_its_ceiling_before_aggregation', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_each_selection_keeps_its_ceiling_before_aggregation', 'owner', 'mutation_tester', False):
        ((0,), "present at tip b11638bf before RF-11b landed; added by e328b74a; Replaces the mutation tester consumer's subprocess reference with an owned no-spawn/process-observation API."),
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_equal_ceiling_native_git_cannot_conflict_with_pin', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_equal_ceiling_native_git_cannot_conflict_with_pin', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_invalid_test_paths_are_refused_before_spawn', 'owner', 'mutation_tester', False):
        ((0,), "present at tip b11638bf before RF-11b landed; added by e328b74a; Replaces the mutation tester consumer's subprocess reference with an owned no-spawn/process-observation API."),
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_symlinked_test_paths_keep_conftest_boundary', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_unusable_explicit_git_layout_keeps_inner_marker', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_unusable_explicit_git_layout_keeps_inner_marker', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_unusable_explicit_git_layout_keeps_inner_marker', 'owner', 'aegis_core', False):
        ((0,), "present at tip b11638bf before RF-11b landed; added by e328b74a; Replaces only the aegis_core package's Git API reference with an owned unusable-layout fixture."),
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_unusable_explicit_git_layout_without_marker_stops_at_start', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_unusable_explicit_git_layout_without_marker_stops_at_start', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'present at tip b11638bf before RF-11b landed; added by e328b74a; Sets or clears explicit Git-layout/ceiling environment variables for the existing repository-boundary refusal controls; pytest restores them.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestMutationTesterContract.test_unusable_explicit_git_layout_without_marker_stops_at_start', 'owner', 'aegis_core', False):
        ((0,), "present at tip b11638bf before RF-11b landed; added by e328b74a; Replaces only the aegis_core package's Git API reference with an owned unusable-layout fixture."),
    ('tests/unit/verification/test_mutation_tester.py', 'TestPolyglotMutationTesterCoverage.test_check_non_python_baseline_fail_and_survived_and_killed', 'callable', 'patch', False):
        ((0, 1, 2), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestPolyglotMutationTesterCoverage.test_mutation_tester_reports_diagnostic_baseline_reasons', 'callable', 'patch', False):
        ((0, 1, 2, 3), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestPolyglotMutationTesterCoverage.test_mutation_tester_reports_diagnostic_baseline_reasons', 'fixture', 'install_fake_popen(monkeypatch, hang=True)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestPolyglotMutationTesterCoverage.test_mutation_tester_reports_diagnostic_baseline_reasons', 'fixture', "install_fake_popen(monkeypatch, returncode=1, stderr='AssertionError: expected 2 got 3')", False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/verification/test_mutation_tester.py', 'TestPolyglotMutationTesterCoverage.test_mutation_tester_reports_diagnostic_baseline_reasons', 'fixture', "install_fake_popen(monkeypatch, spawn_error=OSError('disk read failure'))", False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/verification/test_mutation_tester_paths.py', 'test_the_pytest_command_is_bounded_only_when_a_root_is_found', 'callable', 'patch', False):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/verification/test_mutation_tester_paths.py', 'test_the_pytest_command_is_bounded_only_when_a_root_is_found', 'fixture', 'install_fake_popen(monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/verification/test_native_ast_limits.py', 'test_card_reports_the_extractor_cap_when_the_runner_allows_more', 'owner', 'ast_runner', False):
        ((0,), 'Merged-tip owner ast_runner has static candidates aegis_core.ast.runner; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/verification/test_native_ast_limits.py', 'test_card_retains_the_limit_from_the_refusal_even_if_configuration_changes', 'owner', 'ast_runner', False):
        ((0,), 'Merged-tip owner ast_runner has static candidates aegis_core.ast.runner; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/verification/test_native_ast_limits.py', 'test_card_size_reason_tracks_the_native_source_limit', 'owner', 'ast_runner', False):
        ((0,), 'Owner ast_runner has lexical candidates aegis_core.ast.runner; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/verification/test_native_ast_limits.py', 'test_go_at_exact_limit_is_not_classified_as_too_large', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_native_ast_limits.py', 'test_go_over_limit_is_advisory_before_any_compiler_or_driver_process', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_native_ast_limits.py', 'test_limit_words_in_the_filename_cannot_supply_the_reported_limit', 'owner', 'ast_runner', False):
        ((0,), 'Merged-tip owner ast_runner has static candidates aegis_core.ast.runner; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/verification/test_native_ast_limits.py', 'test_limit_words_in_the_filename_cannot_supply_the_reported_limit', 'owner', 'tokenizer', False):
        ((0,), 'Merged-tip owner tokenizer has static candidates aegis_core.ast.drivers.js.tokenizer; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/verification/test_native_ast_limits.py', 'test_runner_size_error_message_tracks_the_applied_limit', 'owner', 'ast_runner', False):
        ((0,), 'Merged-tip owner ast_runner has static candidates aegis_core.ast.runner; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/verification/test_native_ast_limits.py', 'test_rust_size_error_message_tracks_the_extractor_limit', 'owner', 'extractor', False):
        ((0,), 'Merged-tip owner extractor has static candidates aegis_core.ast.drivers.rust.extractor; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/verification/test_native_ast_limits.py', 'test_security_pack_keeps_its_json_fields_while_carrying_the_refusing_limit', 'owner', 'ast_runner', False):
        ((0,), 'Merged-tip owner ast_runner has static candidates aegis_core.ast.runner; product module/class boundary, not a unique module-level import.'),
    ('tests/unit/verification/test_perf_check.py', 'TestCheckCiPerf._run', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_perf_check.py', 'TestCheckCiPerf._run', 'fixture', 'monkeypatch.delenv', False):
        ((0, 1), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_perf_check.py', 'TestCheckCiPerf.test_a_malformed_perf_command_is_unverified_not_a_traceback', 'fixture', 'self._run(two_commits, capsys, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/verification/test_perf_check.py', 'TestCheckCiPerf.test_a_perf_check_that_raises_is_unverified_naming_only_the_type', 'fixture', 'self._run(two_commits, capsys, monkeypatch)', False):
        ((0,), 'Existing fixture plumbing at this exact expression; downstream patch methods are independently censused.'),
    ('tests/unit/verification/test_perf_check.py', 'TestPerfCommandReading.test_a_failed_export_is_unverified_whatever_the_runner', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/verification/test_perf_check.py', 'TestPerfCommandReading.test_a_home_inside_the_workspace_is_repository_content', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_perf_check.py', 'TestPerfCommandReading.test_no_command_with_the_benchmark_plugin_runs_the_pytest_benchmark_argv', 'fixture', 'monkeypatch.syspath_prepend', False):
        ((0,), 'Fixture syspath_prepend operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_perf_check.py', 'TestPerfMergeBase.test_a_base_that_does_not_resolve_never_reaches_git_argv', 'owner', 'gitsafe', False):
        ((0,), 'Owner gitsafe has lexical candidates aegis_core.gitsafe; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/verification/test_perf_check.py', 'TestPerfProgramLookup.test_a_program_the_repository_planted_never_runs', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_perf_check.py', 'TestRunPerfCheck.test_interleaved_paired_execution_with_user_config_and_no_baseline_file', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_perf_check.py', 'bench_repo', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_perf_check.py', 'bench_repo', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_perf_check.py', 'forked', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_perf_check.py', 'two_commits', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_pipeline.py', 'TestChangedFilesFromGit.test_a_clean_git_tree_is_a_clean_pass', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_pipeline.py', 'TestChangedFilesFromGit.test_an_explicit_empty_list_is_a_clean_pass_outside_git', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_pipeline.py', 'TestChangedFilesFromGit.test_the_layer1_verifier_outside_a_git_work_tree_raises', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_pipeline.py', 'TestChangedFilesFromGit.test_the_pipeline_outside_a_git_work_tree_raises', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_polyglot_coverage.py', 'project', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_polyglot_coverage.py', 'project', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2, 3, 4), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestDiscoverTestEvidence.test_direct_test_file_discovered_and_run', 'callable', 'patch', False):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestDiscoverTestEvidence.test_direct_test_file_discovered_and_run', 'callable', 'patch', True):
        ((1,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestDiscoverTestEvidence.test_discover_test_evidence_handles_listdir_and_ast_errors', 'callable', 'patch', False):
        ((1,), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestDiscoverTestEvidence.test_discover_test_evidence_handles_listdir_and_ast_errors', 'callable', 'patch', True):
        ((0, 2), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestDiscoverTestEvidence.test_no_runner_found_raises_error', 'callable', 'patch', False):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestDiscoverTestEvidence.test_source_file_finds_candidate_and_handles_error', 'callable', 'patch', False):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestDiscoverTestEvidence.test_source_file_finds_candidate_and_handles_error', 'callable', 'patch', True):
        ((1,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_a_pytest_behind_a_relative_path_entry_is_never_chosen', 'callable', 'patch', True):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_a_pytest_behind_a_relative_path_entry_is_never_chosen', 'callable', 'patch.dict', True):
        ((0,), 'Existing patch.dict spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_a_pytest_behind_a_relative_path_entry_is_never_chosen', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_falls_back_to_local_workspace_venv', 'callable', 'patch', True):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_falls_back_to_local_workspace_venv', 'callable', 'patch.dict', True):
        ((0,), 'Existing patch.dict spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_falls_back_to_sys_executable', 'callable', 'patch', False):
        ((1,), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_falls_back_to_sys_executable', 'callable', 'patch', True):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_falls_back_to_sys_executable', 'callable', 'patch.dict', True):
        ((0,), 'Existing patch.dict spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_falls_back_to_system_which', 'callable', 'patch', True):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_falls_back_to_system_which', 'callable', 'patch.dict', True):
        ((0,), 'Existing patch.dict spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_prefers_active_virtual_env', 'callable', 'patch', True):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_prefers_active_virtual_env', 'callable', 'patch.dict', True):
        ((0,), 'Existing patch.dict spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_raises_when_no_runner_and_required', 'callable', 'patch', False):
        ((1,), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_raises_when_no_runner_and_required', 'callable', 'patch', True):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_raises_when_no_runner_and_required', 'callable', 'patch.dict', True):
        ((0,), 'Existing patch.dict spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_returns_empty_when_no_runner_and_not_required', 'callable', 'patch', False):
        ((1,), 'Existing patch spelling; the direct operation is independently counted. Consumer-owned target or fixture boundary.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_returns_empty_when_no_runner_and_not_required', 'callable', 'patch', True):
        ((0,), 'Existing patch spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_pytest_resolution.py', 'TestPytestResolution.test_returns_empty_when_no_runner_and_not_required', 'callable', 'patch.dict', True):
        ((0,), 'Existing patch.dict spelling; the direct operation is independently counted. Shared process-module site.'),
    ('tests/unit/verification/test_records.py', 'repo', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_records.py', 'test_calibration_counts_only_what_git_resolved', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_records.py', 'test_rows_past_the_bound_are_left_unresolved_whatever_they_claim', 'owner', 'records', False):
        ((0,), 'Owner records has lexical candidates aegis_core.verification.records; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/verification/test_runner_contract.py', '_isolated_home', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_scanners.py', 'TestExternalScannerPresets.home', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_scanners.py', 'TestExternalScannerPresets.test_a_user_config_dir_inside_the_repository_does_not_count', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_scanners.py', 'TestPresetScannerProgramLookup.repo', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_scanners.py', 'TestPresetScannerProgramLookup.repo', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_scanners.py', 'TestSarifIngestStaysInsideWorkspace.test_paths_resolve_against_the_workspace_and_keep_dot_directories', 'fixture', 'monkeypatch.chdir', False):
        ((0,), 'Fixture chdir operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_scanners.py', 'TestScannerSurfaceAndInventory.isolated', 'fixture', 'monkeypatch.delenv', False):
        ((0,), 'Fixture delenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_scanners.py', 'TestScannerSurfaceAndInventory.isolated', 'fixture', 'monkeypatch.setenv', False):
        ((0, 1, 2), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_scanners.py', 'TestScannerSurfaceAndInventory.test_unavailable_git_leaves_the_suppression_delta_unknown', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_scanners.py', '_set_path', 'fixture', 'monkeypatch.setenv', False):
        ((0,), 'Fixture setenv operation; environment, path or restoration API outside the module-attribute census.'),
    ('tests/unit/verification/test_verifier_architecture.py', 'TestDeterministicVerifier.test_verify_auto_discovers_staged_only_changes', 'owner', 'runner', False):
        ((0,), 'Owner runner has lexical candidates aegis_core.verification.runner; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/verification/test_verifier_architecture.py', 'TestDeterministicVerifier.test_verify_auto_discovers_unstaged_changes', 'owner', 'runner', False):
        ((0,), 'Owner runner has lexical candidates aegis_core.verification.runner; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
    ('tests/unit/verification/test_verifier_architecture.py', 'TestVerificationPipeline.test_pipeline_rejects_a_missing_backend_before_running_layer1', 'owner', 'runner', False):
        ((0,), 'Owner runner has lexical candidates aegis_core.verification.runner; not a unique module-level import. Consumer module or class boundary; no shared process module candidate.'),
}
PROOF_REGISTRATIONS = {
    (path, scope, kind, expression, occurrence): (shared, reason)
    for (path, scope, kind, expression, shared), (occurrences, reason) in PROOF_REGISTRATION_GROUPS.items()
    for occurrence in occurrences
}


def _proof_uses(tree, names):
    """Accept a small syntax, rather than trying to interpret dynamic dispatch."""
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

    def context(node):
        # Pin the complete expression/statement, including the context of
        # keywords, arguments, withitems, comprehensions and expression fragments.
        while (not isinstance(node, (ast.expr, ast.stmt))
               or isinstance(node, (ast.Starred, ast.FormattedValue, ast.Slice))):
            node = parents[id(node)]
        return ASTSyntax(node)

    for node in ast.walk(tree):
        parent = parents.get(id(node))
        if isinstance(node, ast.Call) and node.args:
            functions = names.possible(node.func)
            receiver = node.args[0]
            if (("builtins.getattr" in functions or isinstance(node.func, ast.Name) and node.func.id == "getattr")
                    and (FIXTURE in names.possible(receiver)
                         or isinstance(receiver, ast.Name) and receiver.id in {"monkeypatch", "mp"}
                         or names.possible(receiver) & (MOCK_CALLABLES | {"unittest.mock", "mock"}))):
                yield node, "callable", ASTSyntax(node)
        if not isinstance(node, (ast.Name, ast.Attribute)) or not isinstance(node.ctx, ast.Load):
            continue
        functions = names.possible(node)
        if isinstance(node, ast.Attribute) and node.attr in PATCH_METHODS:
            if not (isinstance(parent, ast.Call) and parent.func is node
                    and isinstance(node.value, ast.Name) and node.value.id == "monkeypatch"):
                yield node, "callable", ASTSyntax(node)
        elif functions & MOCK_CALLABLES:
            if (isinstance(parent, ast.Attribute) and parent.value is node
                    and parent.attr in {"object", "multiple"} and functions & MOCK_PATCH):
                continue
            direct = isinstance(parent, ast.Call) and parent.func is node
            object_call = (isinstance(node, ast.Attribute) and node.attr == "object"
                           and names.proof(node.value) in MOCK_PATCH)
            multiple = bool(functions & {factory + ".multiple" for factory in MOCK_PATCH})
            if not (direct and (object_call or multiple)):
                yield node, "callable", ASTSyntax(node)
        elif FIXTURE in functions or isinstance(node, ast.Name) and node.id == "monkeypatch":
            if isinstance(parent, ast.Attribute) and parent.value is node:
                grandparent = parents.get(id(parent))
                if (parent.attr in PATCH_METHODS and isinstance(grandparent, ast.Call)
                        and grandparent.func is parent):
                    continue
            # Local helpers are admitted only at a direct call and only when the
            # receiving parameter keeps the fixture name. Their bodies are walked.
            if isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name):
                helper = names.helpers.get(parent.func.id)
                if helper is not None:
                    positional = [*helper.args.posonlyargs, *helper.args.args]
                    arguments = dict(zip((arg.arg for arg in positional), parent.args))
                    arguments.update((kw.arg, kw.value) for kw in parent.keywords if kw.arg is not None)
                    if arguments.get("monkeypatch") is node:
                        continue
            yield node, "fixture", context(parent)
        elif functions & {"unittest.mock", "mock", "mocker"}:
            if not (isinstance(parent, ast.Attribute) and parent.value is node):
                yield node, "fixture", context(parent)


def _name(node, names):
    possible = names.possible(node)
    if len(possible) == 1 and UNKNOWN not in possible:
        return next(iter(possible))
    if isinstance(node, ast.Name):
        return node.id if possible == {UNKNOWN} else UNKNOWN
    if isinstance(node, ast.Attribute):
        base = _name(node.value, names)
        return base + "." + node.attr if base != "<dynamic>" else base
    if isinstance(node, ast.Subscript) and _name(node.value, names) == "sys.modules":
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            return node.slice.value
    return "<dynamic>"


def _possible_names(node, names):
    """Keep all possible import bindings when choosing one would be unsound."""
    return names.possible(node)


def _arguments(node, positional):
    """Do not discard starred arguments, duplicate bindings or opaque keyword maps."""
    values = {}
    opaque = len(node.args) > len(positional)
    for key, value in zip(positional, node.args):
        opaque |= isinstance(value, ast.Starred)
        values[key] = value
    for keyword in node.keywords:
        if keyword.arg is None or keyword.arg in values:
            opaque = True
        else:
            values[keyword.arg] = keyword.value
    return values, opaque


def _literal(node, value):
    return isinstance(node, ast.Constant) and node.value is value


def _canonical(target):
    owner, _, attribute = target.rpartition(".")
    for module in sorted(PROCESS_MODULES | {"ctypes"}, key=len, reverse=True):
        if owner == module or owner.endswith("." + module):
            return module + "." + attribute, module in PROCESS_MODULES
    return target, False


def patch_sites(source, filename="<fixture>", *, dynamic=None, owners=None, proofs=None, bans=None):
    """Accept provable patch syntax and require exact registrations for the rest.

    Legacy forms remain censused even when refused. Unprovable owners default to
    possibly shared; reviewed classifications cannot suppress a known shared
    candidate or a global/nonlocal declaration. Target modules are never imported.
    """
    tree = ast.parse(source, filename=filename)
    sites = PatchSites()
    keys = SiteKeys(tree, filename)
    ban_registry = {_ban_identity(key): reason
                    for key, reason in (BAN_REGISTRATIONS if bans is None else bans).items()}
    names = PatchNames(tree, filename)
    uses = [(node, kind, node) for node, kind in _syntactic_bans(tree)]
    uses.extend(_namespace_uses(tree, names))
    for node, kind, operation in sorted(uses, key=lambda use: (use[0].lineno, use[0].col_offset, use[1])):
        key = keys.key(node, kind, ASTSyntax(operation))
        sites.bans.add(key)
        sites.ban_lines[key] = node.lineno
        if kind == "annotation" or not ban_registry.get(_ban_identity(key), "").strip():
            refusal = NAMESPACE_UNPROVABLE if kind == "module_write" or kind.startswith("namespace_") else UNPROVABLE
            sites.errors.append(f"{filename}:{node.lineno}: {refusal}")
    proof_registry = {_ban_identity(key): value for key, value in
                      (PROOF_REGISTRATIONS if proofs is None else proofs).items()}
    registry = {_ban_identity(key): value for key, value in
                (UNRESOLVED_TARGETS if dynamic is None else dynamic).items()}
    uses = sorted(_proof_uses(tree, names), key=lambda use: (use[0].lineno, use[0].col_offset, use[1]))
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and node.args
                and (names.possible(node.func) & {"builtins.getattr"}
                     or isinstance(node.func, ast.Name) and node.func.id == "getattr")):
            attribute = node.args[1] if len(node.args) > 1 else None
            literal = isinstance(attribute, ast.Constant) and isinstance(attribute.value, str)
            method = attribute.value if literal else None
            if ((literal and method in PATCH_METHODS)
                    or (names.possible(node.args[0]) & {"unittest.mock", "mock"}
                        and (not literal or method == "patch"))):
                sites.errors.append(f"{filename}:{node.lineno}: patch callable must be used in a recognised direct call")
        if not isinstance(node, (ast.Name, ast.Attribute)) or not isinstance(node.ctx, ast.Load):
            continue
        functions = names.possible(node)
        method = isinstance(node, ast.Attribute) and node.attr in PATCH_METHODS
        sensitive = method or bool(functions & MOCK_CALLABLES)
        parent = parents.get(id(node))
        # patch.object/dict/multiple have a supported attribute spine. No other
        # attribute access may turn a patch callable into an unchecked alias.
        if (isinstance(parent, ast.Attribute) and parent.value is node
                and parent.attr in {"object", "dict", "multiple"} and functions & MOCK_PATCH):
            continue
        direct = isinstance(parent, ast.Call) and parent.func is node
        recognised = method or functions <= MOCK_CALLABLES
        if sensitive and not (direct and recognised):
            sites.errors.append(f"{filename}:{node.lineno}: patch callable must be used in a recognised direct call")
    for node in sorted(ast.walk(tree), key=lambda part: (getattr(part, "lineno", 0), getattr(part, "col_offset", 0))):
        if not isinstance(node, ast.Call):
            continue
        resolved = False
        functions = _possible_names(node.func, names)
        setter = isinstance(node.func, ast.Attribute) and node.func.attr == "setattr"
        deleter = isinstance(node.func, ast.Attribute) and node.func.attr == "delattr"
        item = isinstance(node.func, ast.Attribute) and node.func.attr in {"setitem", "delitem"}
        delitem = item and node.func.attr == "delitem"
        mock = bool(functions & {"unittest.mock.patch", "mock.patch", "mocker.patch", "patch"})
        mock_object = bool(functions & {"unittest.mock.patch.object", "mock.patch.object",
                                      "mocker.patch.object", "patch.object"})
        mock_dict = bool(functions & {factory + ".dict" for factory in MOCK_PATCH})
        if functions & {factory + ".multiple" for factory in MOCK_PATCH}:
            sites.errors.append(f"{filename}:{node.lineno}: patch.multiple is forbidden; use individual direct patch calls")
            continue
        if not (setter or deleter or item or mock or mock_object or mock_dict):
            continue
        if setter or deleter or item:
            positional = (("target", "name", "raising") if deleter or delitem else ("target", "name", "value", "raising"))
            values, opaque = _arguments(node, positional)
            if item:
                # pytest names this argument dic, unlike setattr's target.
                if "dic" in values:
                    values["target"] = values.pop("dic")
            # A nonraising deletion removes a platform capability; it cannot create a seam.
            nonraising = not (deleter or delitem) and "raising" in values and not _literal(values["raising"], True)
            opaque |= bool(values.keys() - {"target", "name", "value", "raising"})
        elif mock_dict:
            values, opaque = _arguments(node, ("target", "values", "clear"))
            if "in_dict" in values:
                values["target"] = values.pop("in_dict")
            nonraising = False
        else:
            positional = (("target", "attribute", "new", "spec", "create", "spec_set", "autospec", "new_callable")
                          if mock_object else
                          ("target", "new", "spec", "create", "spec_set", "autospec", "new_callable"))
            values, opaque = _arguments(node, positional)
            nonraising = "create" in values and not _literal(values["create"], False)
            opaque |= len(functions) != 1
        target = values.get("target")
        # Inspect permissive flags before resolving the target; no form is dropped.
        if opaque or target is None:
            name, shared, nonraising = "<unresolved-call>", False, True
        elif mock or ((mock_dict or setter or deleter) and isinstance(target, ast.Constant) and isinstance(target.value, str)):
            if isinstance(target, ast.Constant) and isinstance(target.value, str) and "." in target.value:
                name, shared = _canonical(target.value)
                if setter and ("name" not in values or "value" in values):
                    name, shared, nonraising = "<unresolved-call>", False, True
            else:
                name, shared = "<dynamic>", False
        else:
            attribute = values.get("name" if setter or deleter or item else "attribute")
            if mock_dict:
                attribute = ast.Constant(value="<item>")
            if attribute is None or ((setter or item and not delitem) and "value" not in values):
                name, shared, nonraising = "<unresolved-call>", False, True
            else:
                field = (attribute.value if isinstance(attribute, ast.Constant)
                         and isinstance(attribute.value, str) else "<dynamic>")
                name, shared = _canonical(_name(target, names) + "." + field)
        # An ambiguous import cannot make a possible shared-module patch disappear,
        # including when a reviewed computed-target entry declares it unshared.
        if isinstance(target, ast.Constant) and isinstance(target.value, str) and not mock_object and not item:
            possible_shared = _canonical(target.value)[1]
        else:
            field = values.get("name" if setter or deleter or item else "attribute")
            field = field.value if isinstance(field, ast.Constant) and isinstance(field.value, str) else "<dynamic>"
            possible_shared = any(_canonical(owner + "." + field)[1]
                                  for owner in _possible_names(target, names)) if target is not None else False
        shared |= possible_shared
        if target is not None and any(isinstance(part, ast.Name) and part.id in names.declared_owners
                                      for part in ast.walk(target)):
            # Declarations invalidate every earlier identity registration too.
            # Do not interpret which branch performs the effective namespace write.
            shared = True
        if (item or mock_dict) and target is not None:
            shared |= any(_canonical(owner)[1] for owner in names.possible(target))
        patch_key = keys.key(node, "patch", ASTSyntax(node))
        registration = registry.get(_ban_identity(patch_key))
        if registration is not None:
            shared |= registration[0]
        attribute = values.get("name" if setter or deleter else "attribute")
        current_module = (not opaque and (setter or deleter or mock_object)
                          and isinstance(attribute, ast.Constant) and isinstance(attribute.value, str)
                          and names.is_current_module(target))
        if (isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Name)
                and target.slice.id == "__name__" and "sys.modules" in names.possible(target.value)
                and not names.is_current_module(target)):
            sites.errors.append(f"{filename}:{node.lineno}: {UNPROVABLE}")
        if current_module:
            if attribute.value not in names.module_fields:
                sites.errors.append(f"{filename}:{node.lineno}: current-module patch attribute is not defined")
            if nonraising or (deleter and "raising" in values and not _literal(values["raising"], True)):
                sites.errors.append(f"{filename}:{node.lineno}: current-module patches must be strict")
            else:
                resolved = True
        proof_key = keys.key(node, "owner", ASTSyntax(target)) if target is not None else None
        reviewed = proof_registry.get(_ban_identity(proof_key)) if proof_key is not None else None
        reviewed_owner = reviewed is not None and bool(reviewed[1].strip())
        if (target is not None and not isinstance(target, ast.Constant)
                and names.proof(target) is None and not current_module):
            owner_key = (filename, names.labels[id(node)], ast.unparse(target))
            owner_registry = OWNER_REGISTRATIONS if owners is None else owners
            # Earlier exact registrations remain explicit evidence, not proof.
            if owner_key not in owner_registry and registration is None and (filename, name) not in BUILTIN_GLOBALS:
                uses.append((node, "owner", ASTSyntax(target)))
                shared |= reviewed[0] if reviewed_owner else True
                if reviewed_owner and not nonraising:
                    resolved = True
        if target is not None and not isinstance(target, ast.Constant):
            possible = names.possible(target)
            if UNKNOWN not in possible and len(possible) > 1:
                field = values.get("name" if setter or deleter or item else "attribute")
                if isinstance(field, ast.Constant) and isinstance(field.value, str):
                    resolved = True
            if UNKNOWN in possible or any(owner == FIXTURE or owner.startswith(FIXTURE + ".")
                                          for owner in possible):
                owner_key = (filename, names.labels[id(node)], ast.unparse(target))
                sites.owners.add(owner_key)
                owner_registry = OWNER_REGISTRATIONS if owners is None else owners
                owner_registration = owner_registry.get(owner_key)
                if owner_registration is not None and owner_registration[1].strip():
                    shared |= owner_registration[0]
                    if not nonraising:
                        resolved = True
                elif (registration is None and (filename, name) not in BUILTIN_GLOBALS
                      and not current_module and not reviewed_owner):
                    sites.errors.append(f"{filename}:{node.lineno}: unresolved patch owner; register file, scope and reason")
                sites.owner_shared[owner_key] = sites.owner_shared.get(owner_key, False) or shared
            elif (item or mock_dict) and not opaque:
                resolved = True
        row = (node.lineno, name, shared, nonraising)
        sites.append(row)
        sites.patch_keys[id(row)] = patch_key
        sites.call_shared[id(node)] = shared
        if current_module and not nonraising:
            sites.proven_owners.add(id(row))
        if resolved:
            sites.resolved_owners.add(id(row))
    sites.sort()
    for node, kind, expression in sorted(uses, key=lambda use: (use[0].lineno, use[0].col_offset, use[1])):
        key = keys.key(node, kind, expression)
        operation = node
        while id(operation) not in sites.call_shared and id(operation) in parents:
            operation = parents[id(operation)]
        shared = sites.call_shared.get(id(operation), False)
        sites.proof_uses[key] = shared
        sites.proof_lines[key] = node.lineno
        registration = proof_registry.get(_ban_identity(key))
        if registration is None or not registration[1].strip():
            sites.errors.append(f"{filename}:{node.lineno}: {UNPROVABLE}")
        elif registration[0] != shared:
            sites.errors.append(f"{filename}:{node.lineno}: proof registration misclassifies shared status")
    sites.errors = sorted(set(sites.errors))
    return sites


def raising_errors(sites, filename="<fixture>", *, dynamic=None):
    registry = {_ban_identity(key): value for key, value in
                (UNRESOLVED_TARGETS if dynamic is None else dynamic).items()}
    leased = {_ban_identity(key) for key in LEASED_SITES}
    errors = list(getattr(sites, "errors", []))
    for row in sites:
        line, name, shared, nonraising = row
        computed = "<dynamic>" in name or name == "<unresolved-call>"
        key = getattr(sites, "patch_keys", {}).get(id(row))
        identity = _ban_identity(key) if key is not None and key[0] == filename else None
        if (computed and id(row) not in getattr(sites, "proven_owners", set())
                and (nonraising or name.rpartition(".")[0] not in PROCESS_MODULES)):
            if identity not in registry:
                errors.append(f"{line}: {name} cannot classify patch target or call; register with a reason")
        elif (nonraising and name not in PLATFORM_ABSENT
              and (filename, name) not in BUILTIN_GLOBALS and identity not in leased):
            errors.append(f"{line}: {name} permits a missing target")
    return errors


def count_errors(current, limits, *, sites=None):
    errors = []
    for path in sorted(current.keys() | limits.keys()):
        count, limit = current.get(path, 0), limits.get(path, 0)
        if count > limit:
            lines = [line for line, _, shared, _ in sites.get(path, []) if shared] if sites is not None else []
            location = f"{path}:{lines[-1]}" if lines else path
            errors.append(f"{location}: shared module patch count {count} exceeds {limit}")
        elif count < limit:
            errors.append(f"{path}: shared module patch count fell from {limit}; lower to {count}")
    return errors


def owner_allowance_errors(repository, registrations):
    live = set().union(*(getattr(rows, "owners", set()) for rows in repository.values()))
    errors = []
    for key, (shared, reason) in registrations.items():
        if not reason.strip() or key not in live:
            errors.append(f"stale owner registration: {key}")
        elif any(getattr(rows, "owner_shared", {}).get(key, False) for rows in repository.values()) != shared:
            errors.append(f"owner registration misclassifies shared status: {key}")
    return errors


def proof_allowance_errors(repository, registrations):
    live = {_ban_identity(key): shared for rows in repository.values() for key, shared in rows.proof_uses.items()}
    locations = {_ban_identity(key): rows.proof_lines[key] for rows in repository.values() for key in rows.proof_uses}
    errors, registered = [], set()
    for key, (shared, reason) in registrations.items():
        identity = _ban_identity(key)
        if identity in registered:
            errors.append(f"{key[0]}:{locations.get(identity, 0)}: duplicate proof registration")
        registered.add(identity)
        if not reason.strip() or live.get(identity) is not shared:
            errors.append(f"stale or invalid proof registration: {key}")
    return errors


def ban_allowance_errors(repository, registrations, limits):
    locations = {_ban_identity(key): rows.ban_lines[key] for rows in repository.values() for key in rows.bans}
    live = set(locations)
    errors, registered = [], set()
    for key, reason in registrations.items():
        identity = _ban_identity(key)
        if identity in registered:
            errors.append(f"{key[0]}:{locations.get(identity, 0)}: duplicate ban registration")
        registered.add(identity)
        if not reason.strip() or identity not in live:
            errors.append(f"stale or empty ban registration: {key}")
    for kind, limit in limits.items():
        count = sum(key[2] == kind for key in live)
        if count > limit:
            key = max((key for key in live if key[2] == kind),
                      key=lambda candidate: (candidate[0], locations[candidate]))
            path, line = key[0], locations[key]
            refusal = NAMESPACE_UNPROVABLE if kind == "module_write" or kind.startswith("namespace_") else UNPROVABLE
            errors.append(f"{path}:{line}: {refusal}; {kind} ban count {count} exceeds {limit}")
        elif count < limit:
            errors.append(f"{kind}: syntactic ban count fell from {limit}; lower to {count}")
    return errors


def allowance_errors(repository, *, platform, builtin, leased, dynamic):
    live = {(path, line, name, nonraising)
            for path, rows in repository.items() for line, name, _, nonraising in rows}
    live_shared, patch_lines, live_nonraising = {}, {}, set()
    for rows in repository.values():
        for row in rows:
            key = getattr(rows, "patch_keys", {}).get(id(row))
            if key is not None:
                identity = _ban_identity(key)
                live_shared[identity] = live_shared.get(identity, False) or row[2]
                patch_lines[identity] = row[0]
                if row[3]:
                    live_nonraising.add(identity)
    errors = []
    for kind, entries in (("leased", leased), ("computed-target", dynamic)):
        registered = set()
        for key in entries:
            identity = _ban_identity(key)
            if identity in registered:
                errors.append(f"{key[0]}:{patch_lines.get(identity, 0)}: duplicate {kind} allowance")
            registered.add(identity)
    for target, reason in platform.items():
        if not reason.strip() or not any(name == target and nr for _, _, name, nr in live):
            errors.append(f"stale platform allowance: {target}")
    for key, reason in builtin.items():
        if not reason.strip() or not any((path, name) == key and nr for path, _, name, nr in live):
            errors.append(f"stale builtin allowance: {key}")
    for key, reason in leased.items():
        if not reason.strip() or _ban_identity(key) not in live_nonraising:
            errors.append(f"stale leased allowance: {key}")
    for key, (shared, reason) in dynamic.items():
        if not reason.strip() or _ban_identity(key) not in live_shared:
            errors.append(f"stale computed-target allowance: {key}")
        elif live_shared[_ban_identity(key)] != shared:
            errors.append(f"computed-target allowance misclassifies shared status: {key}")
    return errors


@pytest.fixture(scope="module")
def repository_sites():
    return {path.relative_to(REPO).as_posix(): patch_sites(path.read_text(encoding="utf-8"),
                                                        path.relative_to(REPO).as_posix())
            for path in sorted((REPO / "tests").rglob("*.py"))}


def test_setattr_requires_an_existing_target(repository_sites):
    errors = [error if error.startswith(path + ":") else f"{path}:{error}"
              for path, sites in repository_sites.items()
              for error in raising_errors(sites, path)]
    assert not errors, "\n".join(errors)
    assert allowance_errors(repository_sites, platform=PLATFORM_ABSENT, builtin=BUILTIN_GLOBALS,
                            leased=LEASED_SITES, dynamic=UNRESOLVED_TARGETS) == []
    assert owner_allowance_errors(repository_sites, OWNER_REGISTRATIONS) == []
    assert proof_allowance_errors(repository_sites, PROOF_REGISTRATIONS) == []
    assert ban_allowance_errors(repository_sites, BAN_REGISTRATIONS, BAN_LIMITS) == []


def test_process_module_patch_counts_never_rise(repository_sites):
    current = {path: sum(shared for _, _, shared, _ in sites) for path, sites in repository_sites.items()}
    errors = count_errors(current, PROCESS_PATCH_LIMITS, sites=repository_sites)
    assert not errors, "\n".join(errors)


def test_guard_refuses_missing_target_flags_but_allows_platform_names():
    source = '''
import ctypes as C, module, os
import subprocess as sp
monkeypatch.setattr(module, "renamed", None, raising=False)
monkeypatch.setattr("package.module.renamed", None, raising=False)
monkeypatch.setattr(module, "positional", None, False)
monkeypatch.setattr(C, "WinDLL", fake, raising=False)
monkeypatch.setattr(sp, "CREATE_NEW_PROCESS_GROUP", 512, raising=False)
monkeypatch.setattr("package.os.geteuid", fake, raising=False)
# Environment APIs require their own exact registrations.
monkeypatch.delattr(os, "waitid", raising=False)
'''
    assert raising_errors(patch_sites(source)) == [
        "4: module.renamed permits a missing target",
        "5: package.module.renamed permits a missing target",
        "6: module.positional permits a missing target",
    ]


def test_builtin_allowances_are_exact_module_names_in_the_consumer_file():
    sites = patch_sites('from aegis_cli import approve\nmonkeypatch.setattr(approve, "input", fake, raising=False)')
    assert raising_errors(sites, "tests/unit/cli/test_approve_cli.py") == []
    assert raising_errors(sites, "tests/other.py") == [
        "2: aegis_cli.approve.input permits a missing target"]
    sites = patch_sites('import tool; monkeypatch.setattr(tool, "open", fake, raising=False)')
    assert raising_errors(sites, "tests/integration/test_hierarchy_root.py") == []
    assert raising_errors(sites, "tests/other.py") == ["1: tool.open permits a missing target"]
    assert raising_errors(patch_sites('import other; monkeypatch.setattr(other, "input", fake, raising=False)'),
                          "tests/unit/cli/test_approve_cli.py") == [
        "1: other.input permits a missing target"]


def test_retired_lease_refuses_file_scope_call_flags_and_occurrence():
    path = "tests/integration/test_hierarchy_provision.py"
    source = ("def test_mr1_planless_does_not_open_bindings_and_preserves_answers(monkeypatch, module):\n"
              "    monkeypatch.setattr(module, 'MODEL_BINDINGS', garbage, raising=False)")
    assert raising_errors(patch_sites(source, path), path) == [
        "2: module.MODEL_BINDINGS permits a missing target"]
    assert raising_errors(patch_sites("# marker\n" + source, path), path) == [
        "3: module.MODEL_BINDINGS permits a missing target"]
    assert raising_errors(patch_sites(source, "tests/other.py"), "tests/other.py")
    assert raising_errors(patch_sites(source.replace("MODEL_BINDINGS", "RENAMED"), path), path)
    assert raising_errors(patch_sites(source + "\n    monkeypatch.setattr(module, 'MODEL_BINDINGS', garbage, raising=False)", path), path)


def test_counts_cover_object_aliases_and_dotted_strings_without_patching_a_global():
    source = '''
import os as operating
from package import subprocess as processes
monkeypatch.setattr(operating, "name", "nt")
monkeypatch.setattr(processes, "run", fake)
monkeypatch.setattr(tool.sys, "platform", "win32")
monkeypatch.setattr("package.os.name", "nt")
monkeypatch.setattr("package.subprocess.run", fake)
monkeypatch.setattr("time.monotonic", fake)
monkeypatch.setattr("builtins.open", fake)
monkeypatch.setattr(operating, attribute, fake)
monkeypatch.setattr(tool, "os", fake)
monkeypatch.setattr("tool.subprocess", fake)
# monkeypatch.setattr(os, "open", fake)
text = 'monkeypatch.setattr(os, "open", fake)'
'''
    sites = patch_sites(source)
    assert [name for _, name, shared, _ in sites if shared] == [
        "os.name", "subprocess.run", "sys.platform", "os.name", "subprocess.run",
        "time.monotonic", "builtins.open", "os.<dynamic>", "tool.os",
    ]
    assert count_errors({"tests/one.py": 7}, {"tests/one.py": 7}) == []
    assert "lower to 6" in count_errors({"tests/one.py": 6}, {"tests/one.py": 7})[0]
    assert count_errors({"tests/one.py": 8}, {"tests/one.py": 7}) == [
        "tests/one.py: shared module patch count 8 exceeds 7"]
    assert count_errors({"tests/new.py": 1}, {}) == [
        "tests/new.py: shared module patch count 1 exceeds 0"]


@pytest.mark.parametrize("declaration,field", [
    ("import ast", "ast"),
    ("import ast as syntax", "syntax"),
    ("from ast import parse as parser", "parser"),
    ("VALUE = 1", "VALUE"),
    ("LEFT, RIGHT = 1, 2", "LEFT"),
    ("VALUE: int = 1", "VALUE"),
    ("def helper():\n    pass", "helper"),
    ("class Model:\n    pass", "Model"),
])
def test_current_module_patches_resolve_defined_attributes_with_namespace_registration(declaration, field):
    source = ('import sys\n' + declaration + '\ndef t(monkeypatch):\n'
              f'    monkeypatch.setattr(sys.modules[__name__], "{field}", fake)')
    path = "tests/current_module.py"
    rows = patch_sites(source, path, owners={}, dynamic={}, bans=_registered_namespace_call(source, path))
    assert len(rows) == 1 and rows[0][2] is False
    assert raising_errors(rows, path, dynamic={}) == []


@pytest.mark.parametrize("prefix,target,call", [
    ('import ast\nimport sys as runtime', 'runtime.modules[__name__]', 'monkeypatch.setattr({target}, "ast", fake)'),
    ('import ast\nfrom sys import modules as loaded', 'loaded[__name__]', 'monkeypatch.setattr({target}, "ast", fake)'),
    ('import ast, sys\nfrom unittest import mock', 'sys.modules[__name__]', 'mock.patch.object({target}, "ast", fake)'),
    ('import ast, sys', 'sys.modules[__name__]', 'monkeypatch.setattr(target={target}, name="ast", value=fake, raising=True)'),
    ('import ast, sys', 'sys.modules[__name__]', 'monkeypatch.delattr({target}, "ast")'),
])
def test_current_module_import_aliases_and_keyword_calls_stay_exact(prefix, target, call):
    source = prefix + '\ndef t(monkeypatch):\n    ' + call.format(target=target)
    path = "tests/current_alias.py"
    assert raising_errors(patch_sites(source, path, owners={}, dynamic={},
                                     bans=_registered_namespace_call(source, path)), path, dynamic={}) == []


@pytest.mark.parametrize("declaration,field", [
    ("", "MISSING"),
    ("import ast", "MISSING"),
    ("import ast as syntax", "ast"),
    ("ast: object", "ast"),
    ("if condition:\n    import ast", "ast"),
    ("import ast\ndel ast", "ast"),
    ("import ast\nif condition:\n    del ast", "ast"),
    ("import ast\ntry:\n    pass\nexcept Exception as ast:\n    pass", "ast"),
])
def test_current_module_missing_attributes_are_refused(declaration, field):
    source = ('import sys\n' + declaration + '\ndef t(monkeypatch):\n'
              f'    monkeypatch.setattr(sys.modules[__name__], "{field}", fake)')
    path = "tests/missing_current.py"
    line = source.count('\n') + 1
    errors = raising_errors(patch_sites(source, path, owners={}, dynamic={}), path, dynamic={})
    assert f"{path}:{line}: current-module patch attribute is not defined" in errors


@pytest.mark.parametrize("call", [
    'monkeypatch.setattr(sys.modules[__name__], "ast", fake, raising=False)',
    'monkeypatch.setattr(sys.modules[__name__], "ast", fake, raising=0)',
    'monkeypatch.setattr(sys.modules[__name__], "ast", fake, raising=flag)',
    'mock.patch.object(sys.modules[__name__], "ast", fake, create=True)',
    'monkeypatch.delattr(sys.modules[__name__], "ast", raising=False)',
])
def test_current_module_proof_never_permits_nonraising_attribute_creation(call):
    source = 'import ast, sys\nfrom unittest import mock\ndef t(monkeypatch):\n    ' + call
    path = "tests/nonraising_current.py"
    errors = raising_errors(patch_sites(source, path, owners={}, dynamic={}), path, dynamic={})
    assert f"{path}:4: current-module patches must be strict" in errors


def test_current_module_missing_attribute_cannot_be_authorized_by_a_registration():
    source = ('import ast, sys\ndef t(monkeypatch):\n'
              '    monkeypatch.setattr(sys.modules[__name__], "MISSING", fake)')
    path = "tests/registered_current.py"
    owners = {(path, "t", "sys.modules[__name__]"): (False, "Owned test module")}
    dynamic = {_fixture_patch_key(path, source, 3): (False, "Old computed target")}
    rows = patch_sites(source, path, owners=owners, dynamic=dynamic)
    assert f"{path}:3: current-module patch attribute is not defined" in raising_errors(rows, path, dynamic=dynamic)


@pytest.mark.parametrize("source", [
    'import ast, sys\n__name__ = "os"\ndef t(monkeypatch):\n    monkeypatch.setattr(sys.modules[__name__], "ast", fake)',
    'import ast, sys\ndef t(monkeypatch, __name__="os"):\n    monkeypatch.setattr(sys.modules[__name__], "ast", fake)',
    'import ast, sys\ndef t(monkeypatch):\n    __name__ = "os"\n    monkeypatch.setattr(sys.modules[__name__], "ast", fake)',
])
def test_shadowed_module_names_do_not_receive_current_module_proof(source):
    path = "tests/shadowed_current.py"
    assert raising_errors(patch_sites(source, path, owners={}, dynamic={}), path, dynamic={})


def test_literal_foreign_sys_module_still_counts_as_shared():
    source = 'import sys\nmonkeypatch.setattr(sys.modules["os"], "name", "nt")'
    rows = patch_sites(source, bans=_registered_namespace_call(source, "<fixture>"))
    assert rows == [(2, "os.name", True, False)]
    assert raising_errors(rows) == []


@pytest.mark.parametrize("selector", ['method', '"set" + "attr"', '"setattr" if flag else "delattr"'])
@pytest.mark.parametrize("lookup", ["getattr", "lookup"])
@pytest.mark.parametrize("receiver", ["monkeypatch", "mp"])
def test_r8_reflection_is_unprovable_for_every_selector(selector, lookup, receiver):
    source = (f'from builtins import getattr as lookup\nimport os\n'
              f'def helper({receiver}, method):\n'
              f'    {lookup}({receiver}, {selector})(os, "name", "nt")')
    path = "tests/reflective.py"
    assert f"{path}:4: unprovable patch use; rewrite or register with a reason" in raising_errors(
        patch_sites(source, path), path)


@pytest.mark.parametrize("body,line", [
    ('mp = monkeypatch', 3),
    ('f = monkeypatch.setattr', 3),
    ('external(monkeypatch)', 3),
    ('return monkeypatch', 3),
    ('mp.setattr(os, "name", "nt")', 3),
    ('lookup = getattr\n    lookup(monkeypatch, method)(os, "name", "nt")', 4),
])
def test_r8_fixture_escapes_require_exact_registration(body, line):
    source = 'import os\ndef helper(monkeypatch, mp):\n    ' + body
    path = "tests/escape.py"
    assert f"{path}:{line}: unprovable patch use; rewrite or register with a reason" in raising_errors(
        patch_sites(source, path), path)


@pytest.mark.parametrize("declaration", ["global", "nonlocal"])
@pytest.mark.parametrize("write", [
    'owner = os',
    'owner, other = os, 1',
    'if (owner := os):\n    pass',
    'for owner in (os,):\n    pass',
    'import os as owner',
])
@pytest.mark.parametrize("api", ["monkeypatch.setattr", "mock.patch.object"])
def test_r8_declared_owner_writes_never_receive_import_proof(declaration, write, api):
    prefix = 'import json as owner\nimport os\nfrom unittest import mock\n'
    if declaration == "nonlocal":
        prefix += 'def outer():\n    owner = json\n'
    indent = '    ' if declaration == "nonlocal" else ''
    source = (prefix + indent + 'def select(monkeypatch):\n'
              + indent + f'    {declaration} owner\n'
              + ''.join(indent + '    ' + line + '\n' for line in write.split('\n'))
              + indent + f'    {api}(owner, "name", "nt")')
    path = "tests/rebound.py"
    line = source.count('\n') + 1
    rows = patch_sites(source, path, owners={}, dynamic={})
    assert f"{path}:{line}: unprovable patch use; rewrite or register with a reason" in raising_errors(rows, path)
    assert rows[-1][2] is True


@pytest.mark.parametrize("binding", [
    'owner, other = os, 1',
    'if (owner := os):\n    pass',
    'for owner in (os,):\n    pass',
    'owner = os\nowner = json',
    'def nested():\n    import os as owner',
])
def test_r8_only_unique_module_import_bindings_prove_owners(binding):
    source = 'import os, json\n' + binding + '\nmonkeypatch.setattr(owner, "name", "nt")'
    path = "tests/owner.py"
    line = source.count('\n') + 1
    assert f"{path}:{line}: unprovable patch use; rewrite or register with a reason" in raising_errors(
        patch_sites(source, path, owners={}, dynamic={}), path)


@pytest.mark.parametrize("source", [
    'import os\nmonkeypatch.setattr(os, "name", "nt")',
    'import os\nowner = os\nmonkeypatch.delattr(owner, "name")',
    'import sys\nmonkeypatch.setitem(sys.modules, "example", fake)',
    'import sys\nmonkeypatch.delitem(sys.modules, "example")',
    'import os\nfrom unittest import mock\nmock.patch.object(os, "name", "nt")',
    'import os\nfrom unittest.mock import patch\npatch.object(os, "name", "nt")',
    'import os\ndef helper(monkeypatch):\n    monkeypatch.setattr(os, "name", "nt")\n'
    'def test_case(monkeypatch):\n    helper(monkeypatch)',
])
def test_r8_provable_calls_and_analysed_local_helpers_pass(source):
    bans = _registered_namespace_call(source, "<fixture>") if "sys.modules" in source else {}
    rows = patch_sites(source, owners={}, dynamic={}, bans=bans)
    assert len(rows) == 1
    assert rows[0][2] is True
    assert raising_errors(rows) == []


@pytest.mark.parametrize("kind,source,expression,shared", [
    ("callable", 'import os\ndef t(mp):\n    mp.setattr(os, "name", "nt")', "mp.setattr", True),
    ("fixture", 'import os\ndef t(monkeypatch):\n    external(monkeypatch)', "external(monkeypatch)", False),
    ("owner", 'import os\ndef t(monkeypatch, owner):\n    monkeypatch.setattr(owner, "field", fake)', "owner", False),
])
def test_r8_registrations_pin_every_use_and_require_a_live_reason(kind, source, expression, shared):
    path = "tests/proof.py"
    key = (path, 't', kind, expression, 0)
    proofs = {key: (shared, "Reviewed exact boundary; fixture or owner identity is explicit here.")}
    rows = patch_sites(source, path, proofs=proofs, owners={}, dynamic={})
    assert raising_errors(rows, path) == []
    assert proof_allowance_errors({path: rows}, proofs) == []
    assert raising_errors(patch_sites(source, "tests/other.py", proofs=proofs), "tests/other.py")
    assert raising_errors(patch_sites('\n' + source, path, proofs=proofs), path) == []
    assert raising_errors(patch_sites(source.replace('def t(', 'def other('), path, proofs=proofs), path)
    assert raising_errors(patch_sites(source, path, proofs={key: (shared, " ")}), path)
    assert proof_allowance_errors({}, proofs)


def test_r8_a_registration_cannot_hide_a_known_shared_owner():
    source = 'import os\ndef t(monkeypatch, owner=os):\n    monkeypatch.setattr(owner, "name", "nt")'
    path = "tests/wrong_proof.py"
    proofs = {(path, 't', 'owner', 'owner', 0): (False, "Incorrectly declares a shared default unshared")}
    rows = patch_sites(source, path, proofs=proofs)
    assert rows == [(3, "os.name", True, False)]
    assert f"{path}:3: proof registration misclassifies shared status" in raising_errors(rows, path)
    assert proof_allowance_errors({path: rows}, proofs)


def test_r8_a_rebound_local_helper_cannot_admit_fixture_escape():
    source = ('def helper(monkeypatch):\n    pass\nhelper = external\n'
              'def t(monkeypatch):\n    helper(monkeypatch)')
    path = "tests/rebound_helper.py"
    assert f"{path}:5: {UNPROVABLE}" in raising_errors(patch_sites(source, path), path)


@pytest.mark.parametrize("source,line", [
    ('def t(mocker):\n    mocker.patch("os.RENAMED", 1, create=True)', 2),
    ('def t(mocker):\n    mocker.patch.object(owner, "RENAMED", 1, create=True)', 2),
    ('def helper(mock):\n    mock.patch.object(owner, "RENAMED", 1, create=True)\n'
     'from unittest import mock\nhelper(mock)', 2),
    ('import json, os\ndef helper(monkeypatch, owner=json):\n'
     '    monkeypatch.setattr(owner, "name", "nt")\n'
     'def t(monkeypatch):\n    helper(monkeypatch, os)', 3),
    ('import json, os\nfirst, owner, *discard = *(1, os), json, 2\n'
     'monkeypatch.setattr(owner, "name", "nt")', 3),
])
def test_arg0559_unprovable_receivers_and_owners_refuse(source, line):
    path = "tests/argon.py"
    assert f"{path}:{line}: {UNPROVABLE}" in raising_errors(
        patch_sites(source, path, owners={}, dynamic={}, proofs={}), path)


def test_arg0559_mocker_multiple_is_refused():
    source = 'def t(mocker):\n    mocker.patch.multiple(owner, RENAMED=1, create=True)'
    path = "tests/argon_multiple.py"
    assert f"{path}:2: patch.multiple is forbidden; use individual direct patch calls" in raising_errors(
        patch_sites(source, path), path)


@pytest.mark.parametrize("declarations,field", [
    ('items = [0]\nitems[[missing for missing in [0]][0]] = 1', 'missing'),
    ('import ast\ndef remove():\n    global ast\n    del ast', 'ast'),
    ('import ast\ndef replace():\n    global ast\n    ast = replacement', 'ast'),
    ('import ast\ndef local(ast):\n    pass', 'ast'),
    ('from os import name\ndef select():\n    global __name__\n    __name__ = "os"', 'name'),
])
def test_arg0559_current_module_proof_excludes_other_bindings(declarations, field):
    source = 'import sys\n' + declarations + f'\ndef t(monkeypatch):\n    monkeypatch.setattr(sys.modules[__name__], "{field}", fake)'
    path = "tests/argon_current.py"
    line = source.count('\n') + 1
    errors = raising_errors(patch_sites(source, path, owners={}, dynamic={}, proofs={}), path)
    assert any(error.startswith(f"{path}:{line}:") for error in errors)


def test_arg0559_a_registration_cannot_mask_a_shadowed_module_selector():
    source = ('import ast, sys\ndef select():\n    global __name__\n    __name__ = "os"\n'
              'def t(monkeypatch):\n    monkeypatch.setattr(sys.modules[__name__], "ast", fake)')
    path = "tests/registered_selector.py"
    owners = {(path, "t", "sys.modules[__name__]"): (False, "Previously reviewed current module")}
    dynamic = {_fixture_patch_key(path, source, 6): (False, "Previously reviewed current module")}
    rows = patch_sites(source, path, owners=owners, dynamic=dynamic)
    assert f"{path}:6: {UNPROVABLE}" in raising_errors(rows, path, dynamic=dynamic)


def test_arg0559_a_registration_cannot_mask_a_declared_owner_write():
    source = ('import json as owner\nimport os\ndef t(monkeypatch):\n'
              '    global owner\n    owner = os\n    monkeypatch.setattr(owner, "name", "nt")')
    path = "tests/registered_write.py"
    owners = {(path, "t", "owner"): (False, "Previously reviewed product import")}
    rows = patch_sites(source, path, owners=owners)
    assert rows[-1][2] is True
    assert owner_allowance_errors({path: rows}, owners)


@pytest.mark.parametrize("statement", [
    'import unittest.mock as receiver',
    'from unittest import mock as receiver',
    'from unittest.mock import patch as receiver',
    'import mock as receiver',
    'from mock import patch as receiver',
    'import pytest as receiver',
    'from pytest import MonkeyPatch as receiver',
])
@pytest.mark.parametrize("wrapper", [
    'def select():\n    {statement}',
    'if condition:\n    {statement}',
    'try:\n    {statement}\nexcept ImportError:\n    pass',
])
def test_r9_nested_patch_imports_are_syntactically_banned(statement, wrapper):
    path = "tests/nested_import.py"
    source = wrapper.format(statement=statement)
    assert f"{path}:2: {UNPROVABLE}" in raising_errors(patch_sites(source, path), path)


@pytest.mark.parametrize("declaration", ["global receiver", "nonlocal receiver"])
@pytest.mark.parametrize("operation", [
    'import unittest.mock as receiver\nwith receiver.patch("os.RENAMED", 1, create=True):\n    pass',
    'from unittest import mock as receiver\nreceiver.patch.object(owner, "RENAMED", 1, create=True)',
    'from unittest.mock import patch as receiver\nreceiver("os.RENAMED", 1, create=True)',
    'from unittest.mock import patch as receiver\nreceiver.dict("sys.modules", values)',
    'import mock as receiver\nreceiver.patch.multiple(owner, RENAMED=1, create=True)',
    'from unittest import mock as receiver\ngetattr(receiver, selector)(owner, "RENAMED", 1)',
])
def test_r9_review_namespace_import_examples_refuse_before_patch_recognition(declaration, operation):
    source = ('import json as receiver\ndef outer():\n    receiver = json\n'
              '    def select():\n        ' + declaration + '\n'
              + ''.join('        ' + line + '\n' for line in operation.split('\n')))
    path = "tests/namespace_import.py"
    assert f"{path}:5: {UNPROVABLE}" in raising_errors(patch_sites(source, path), path)


@pytest.mark.parametrize("declaration", ["global unused", "nonlocal unused"])
def test_r9_declarations_refuse_even_without_a_recognised_patch_call(declaration):
    source = 'def outer():\n    unused = 1\n    def select():\n        ' + declaration
    path = "tests/declaration.py"
    assert f"{path}:4: {UNPROVABLE}" in raising_errors(patch_sites(source, path), path)


@pytest.mark.parametrize("constructor", ["pytest.MonkeyPatch()", "MonkeyPatch()", "p.MonkeyPatch()", "Maker()"])
@pytest.mark.parametrize("expression", [
    'helper({constructor}, "setattr")',
    'return {constructor}',
    'patchers = [{constructor}]',
])
def test_r9_constructor_results_are_banned_before_escaping(constructor, expression):
    source = ('import pytest as p\nfrom pytest import MonkeyPatch as Maker\n'
              'def factory():\n    ' + expression.format(constructor=constructor))
    path = "tests/constructor.py"
    assert f"{path}:4: {UNPROVABLE}" in raising_errors(patch_sites(source, path), path)


@pytest.mark.parametrize("statement", [
    'sys.modules[__name__].__name__ = "os"',
    'sys.modules[__name__].__dict__["__name__"] = "os"',
    'globals()["__name__"] = "os"',
    'vars(sys.modules[__name__])["__name__"] = "os"',
    'globals().update({"__name__": "os"})',
    'vars(sys.modules[__name__]).pop("ast")',
    'sys.modules[__name__].__dict__.clear()',
    'del sys.modules[__name__].ast',
    'del globals()["ast"]',
    'setattr(sys.modules[__name__], "__name__", "os")',
    'delattr(sys.modules[__name__], "ast")',
    'monkeypatch.setattr(sys.modules[__name__], "ast", fake)',
    'monkeypatch.delattr(target=sys.modules[__name__], name="ast")',
    '__name__ = "os"',
    '__name__ += ".changed"',
    'if (__name__ := "os"):\n    pass',
])
def test_r9_review_module_namespace_writes_are_syntactically_banned(statement):
    source = 'import ast, sys\ndef select(monkeypatch):\n' + ''.join('    ' + line + '\n' for line in statement.split('\n'))
    path = "tests/module_write.py"
    assert f"{path}:3: {NAMESPACE_UNPROVABLE}" in raising_errors(patch_sites(source, path), path)


@pytest.mark.parametrize("source", [
    'import pytest\nfrom unittest import mock\nfrom unittest.mock import patch',
    'def helper():\n    import json\n    return json',
    'import os\ndef t(monkeypatch):\n    monkeypatch.setattr(os, "name", "nt")',
    'values = {}\nvalues["field"] = 1\ndel values["field"]',
])
def test_r9_simple_bans_leave_direct_imports_fixtures_and_owned_data_alone(source):
    assert raising_errors(patch_sites(source)) == []


@pytest.mark.parametrize("kind,source,expression", [
    ("import", 'def helper():\n    import pytest as runtime', 'import pytest as runtime'),
    ("declaration", 'def helper():\n    global value', 'global value'),
    ("constructor", 'def helper():\n    return MonkeyPatch()', 'MonkeyPatch()'),
    ("module_write", 'import sys\nsys.modules["owned"].flag = True', "sys.modules['owned'].flag = True"),
])
def test_r9_ban_exceptions_are_exact_live_and_reasoned(kind, source, expression):
    path = "tests/registered_ban.py"
    key = _fixture_key(path, source, 2, kind, expression)
    registrations = {key: "Reviewed existing fixture or namespace operation at this exact site."}
    registrations.update({key: reason for key, reason in _registered_namespace_call(source, path).items()
                          if key[2].startswith("namespace_")})
    limits = _fixture_ban_limits(registrations)
    if kind == "constructor":
        registrations[_fixture_key(path, source, 2, 'constructor_reference', 'MonkeyPatch')] = "Owned positive class reference"
        limits["constructor_reference"] = 1
    rows = patch_sites(source, path, bans=registrations)
    assert raising_errors(rows, path) == []
    assert ban_allowance_errors({path: rows}, registrations, limits) == []
    refusal = NAMESPACE_UNPROVABLE if kind == "module_write" else UNPROVABLE
    assert f"{path}:2: {refusal}" in raising_errors(patch_sites(source, path, bans={key: " "}), path)
    other = "tests/other_ban.py"
    assert f"{other}:2: {refusal}" in raising_errors(patch_sites(source, other, bans=registrations), other)
    assert raising_errors(patch_sites('\n' + source, path, bans=registrations), path) == []
    assert ban_allowance_errors({}, registrations, {kind: 1})


def test_r9_registering_an_extra_ban_cannot_raise_its_count():
    path = "tests/ban_ceiling.py"
    source = 'def helper():\n    global value\nglobal other'
    registrations = {_fixture_key(path, source, 2, 'declaration', 'global value'): "Existing declaration",
                     _fixture_key(path, source, 3, 'declaration', 'global other'): "New declaration"}
    rows = patch_sites(source, path, bans=registrations)
    assert f"{path}:3: {UNPROVABLE}" in '\n'.join(ban_allowance_errors({path: rows}, registrations, {"declaration": 1}))


@pytest.mark.parametrize("source,line", [
    ('import os, pytest\ndef helper(p, method="setattr"):\n'
     '    getattr(p, method)(os, "RENAMED", 1, raising=False)\n'
     'helper(pytest.MonkeyPatch())', 4),
    ('import json as owner, os\nglobals()["owner"] = os\n'
     'monkeypatch.setattr(owner, "name", "nt")', 2),
    ('from os import name\nimport sys\nglobals()["__name__"] = "os"\n'
     'monkeypatch.setattr(sys.modules[__name__], "name", "nt")', 3),
    ('from os import name\nimport sys\nsys.modules[__name__].__name__ = "os"\n'
     'monkeypatch.setattr(sys.modules[__name__], "name", "nt")', 3),
])
def test_arg0715_exact_examples_refuse_at_the_syntactic_ban(source, line):
    path = "tests/argon0715.py"
    refusal = UNPROVABLE if "MonkeyPatch" in source else NAMESPACE_UNPROVABLE
    assert f"{path}:{line}: {refusal}" in raising_errors(patch_sites(source, path), path)


def _fixture_key(filename, source, line, kind, expression, occurrence=0):
    tree = ast.parse(source)
    node = next(part for part in ast.walk(tree) if getattr(part, "lineno", 0) == line)
    return filename, _scope_labels(tree)[id(node)], kind, expression, occurrence


def _fixture_patch_key(filename, source, line):
    tree = ast.parse(source)
    node = next(part for part in ast.walk(tree) if isinstance(part, ast.Call) and part.lineno == line)
    return SiteKeys(tree, filename).key(node, "patch", ast.unparse(node))


def _registered_namespace_call(source, filename):
    """Exact complete-operation registrations for an owned positive source fixture."""
    rows = patch_sites(source, filename, bans={})
    return {key: "Owned positive control; only this complete namespace operation is admitted."
            for key in rows.bans if key[2] == "module_write" or key[2].startswith("namespace_")}


def _fixture_ban_limits(registrations):
    return {kind: sum(key[2] == kind for key in registrations)
            for kind in {key[2] for key in registrations}}


@pytest.mark.parametrize("api", ["monkeypatch.setattr", "mock.patch.object"])
@pytest.mark.parametrize("callback", [
    "lambda: [('aegis_core/probe.py', tree)]",
    "lambda: [(rel, tree)]",
    "lambda: [(rel, ast.parse(source))]",
    "lambda: iter(sources)",
])
@pytest.mark.parametrize("lambda_token", ["lambda:", "lambda :"])
def test_r10_lambda_allowances_match_both_python_renderings(api, callback, lambda_token):
    expression = f"{api}(sys.modules[__name__], '_sources', {callback})"
    source = 'import ast, sys\nfrom unittest import mock\n_sources = None\ndef t(monkeypatch):\n    ' + expression
    path = "tests/py39_lambda.py"
    # 3.9's writer includes a space before the colon for an empty argument list.
    registered = expression.replace("lambda:", lambda_token, 1)
    bans = {_fixture_key(path, source, 5, 'module_write', registered): "Owned strict current-module source fixture"}
    bans.update({key: reason for key, reason in _registered_namespace_call(source, path).items()
                 if key[2].startswith("namespace_")})
    rows = patch_sites(source, path, bans=bans)
    assert rows == [(5, "<dynamic>._sources", False, False)]
    assert raising_errors(rows, path) == []
    assert ban_allowance_errors({path: rows}, bans, _fixture_ban_limits(bans)) == []


@pytest.mark.parametrize("kind,source,line,registered", [
    ("import", 'def t():\n    import pytest', 2, 'import  pytest'),
    ("declaration", 'def outer():\n    value = 0\n    def t():\n        nonlocal value', 4, 'nonlocal  value'),
    ("constructor", 'import pytest\ndef t():\n    return pytest.MonkeyPatch()', 3, 'pytest.MonkeyPatch( )'),
    ("module_write", 'import sys\nsys.modules[__name__].flag = True', 2, 'sys.modules[ __name__ ].flag=True'),
    ("module_write", 'globals()["flag"] = True', 1, 'globals()[ "flag" ]=True'),
])
def test_r10_sibling_ban_forms_match_equivalent_syntax(kind, source, line, registered):
    path = "tests/py39_sibling.py"
    bans = {_fixture_key(path, source, line, kind, registered): "Reviewed equivalent source spelling"}
    limits = {kind: 1}
    bans.update({key: reason for key, reason in _registered_namespace_call(source, path).items()
                 if key[2].startswith("namespace_")})
    limits.update(_fixture_ban_limits(bans))
    if kind == "constructor":
        bans[_fixture_key(path, source, line, 'constructor_reference', 'pytest.MonkeyPatch')] = "Owned positive class reference"
        limits["constructor_reference"] = 1
    rows = patch_sites(source, path, bans=bans)
    assert raising_errors(rows, path) == []
    assert ban_allowance_errors({path: rows}, bans, limits) == []


@pytest.mark.parametrize("lambda_token", ["lambda:", "lambda :"])
def test_r10_tracked_storage_ratchet_lambda_sites_remain_registered(lambda_token):
    path = "tests/unit/core/test_storage_ratchets.py"
    source = (REPO / path).read_text(encoding="utf-8")
    bans = {(file, scope, kind, expression.replace('lambda:', lambda_token), occurrence):
            reason for (file, scope, kind, expression, occurrence), reason in BAN_REGISTRATIONS.items() if file == path}
    rows = patch_sites(source, path, bans=bans)
    assert raising_errors(rows, path) == []
    assert len(rows.bans) == len(bans)
    assert ban_allowance_errors({path: rows}, bans, _fixture_ban_limits(bans)) == []


@pytest.mark.parametrize("registered", [
    "globals()['token'] = 'lambda :'",
    "globals()['renamed'] = 'lambda:'",
    "globals()['token'] = factory()",
])
def test_r10_normalization_never_changes_literals_targets_or_calls(registered):
    source = "globals()['token'] = 'lambda:'"
    path = "tests/exact_syntax.py"
    bans = {_fixture_key(path, source, 1, 'module_write', registered): "Different syntax cannot authorize this site"}
    bans.update({key: reason for key, reason in _registered_namespace_call(source, path).items()
                 if key[2].startswith("namespace_")})
    assert f"{path}:1: {NAMESPACE_UNPROVABLE}" in raising_errors(patch_sites(source, path, bans=bans), path)


def test_r10_equivalent_duplicate_ban_registrations_are_refused():
    source = "globals()['token'] = True"
    path = "tests/duplicate_syntax.py"
    bans = {_fixture_key(path, source, 1, 'module_write', "globals()['token'] = True"): "First spelling",
            _fixture_key(path, source, 1, 'module_write', 'globals()[ "token" ]=True'): "Equivalent duplicate"}
    bans.update({key: reason for key, reason in _registered_namespace_call(source, path).items()
                 if key[2].startswith("namespace_")})
    rows = patch_sites(source, path, bans=bans)
    assert any("duplicate ban registration" in error for error in ban_allowance_errors({path: rows}, bans, {"module_write": 1}))


@pytest.mark.parametrize("operation", [
    'sys.modules[__name__].__setattr__("owner", os)',
    'sys.modules[__name__].__delattr__("owner")',
    'type(sys.modules[__name__]).__setattr__(sys.modules[__name__], "owner", os)',
    'type(sys.modules[__name__]).__delattr__(sys.modules[__name__], "owner")',
    'object.__setattr__(owner, "name", "nt")',
    'object.__delattr__(owner, "name")',
    'type.__setattr__(kind, "owner", os)',
    'saved = owner.__setattr__',
    'saved = owner.__delattr__',
    'saved = owner.__dict__',
    'saved = owner.__getattribute__',
    'saved = owner.__class__',
    'owner.__dict__["owner"] = os',
    'del owner.__dict__["owner"]',
    'owner.__class__ = kind',
    'del owner.__class__',
    'locals()["owner"] = os',
    'del locals()["owner"]',
    'locals().update(owner=os)',
    'dict.update(globals(), owner=os)',
    'saved = globals',
    'saved = locals',
    'saved = vars',
    'saved = builtins.globals',
    'saved = builtins.locals',
    'saved = builtins.vars',
    'saved = b.locals',
    'builtins.locals()["owner"] = os',
    'from builtins import locals as capture',
    'capture()["owner"] = os',
    'saved = capture',
    '(sys.modules.get(__name__)).owner = os',
    'holder[sys.modules] = os',
    'del holder[sys.modules]',
    'holder[sys.modules].update(owner=os)',
    'del holder[sys.modules]["owner"]',
])
def test_r12_namespace_family_refuses_before_stale_owner_proof(operation):
    prefix = 'import json as owner, os, sys, builtins\nimport builtins as b\n'
    if operation in {'capture()["owner"] = os', 'saved = capture'}:
        prefix += 'from builtins import locals as capture\n'
    line = prefix.count('\n') + 1
    source = (prefix + operation + '\n'
              'def test_case(monkeypatch):\n    monkeypatch.setattr(owner, "name", "nt")')
    path = "tests/namespace_family.py"
    rows = patch_sites(source, path, bans={})
    refusal = "unprovable namespace write; rewrite or register with a reason"
    assert f"{path}:{line}: {refusal}" in raising_errors(rows, path)
    assert rows.errors[0].endswith(refusal)


@pytest.mark.parametrize("kind,source,line,expression", [
    ("namespace_globals", 'saved = globals', 1, 'globals'),
    ("namespace_locals", 'saved = builtins.locals', 1, 'builtins.locals'),
    ("namespace_vars", 'from builtins import vars as inspect\nsaved = inspect', 2, 'inspect'),
    ("namespace___setattr__", 'saved = owner.__setattr__', 1, 'owner.__setattr__'),
    ("namespace___delattr__", 'object.__delattr__(owner, "field")', 1, 'object.__delattr__'),
    ("namespace___dict__", 'saved = owner.__dict__', 1, 'owner.__dict__'),
    ("namespace___getattribute__", 'saved = owner.__getattribute__', 1, 'owner.__getattribute__'),
    ("namespace___class__", 'owner.__class__ = Kind', 1, 'owner.__class__'),
])
def test_r12_namespace_family_registrations_are_exact_and_counted(kind, source, line, expression):
    path = "tests/namespace_registration.py"
    # The imported builtin is a separate acquisition site from its later reference.
    registrations = ({_fixture_key(path, source, 1, 'namespace_builtin_import', 'from builtins import vars as inspect'):
                      "Owned positive fixture acquisition"} if line == 2 else {})
    expression = source.split("\n")[line - 1]
    key = _fixture_key(path, source, line, kind, expression)
    registrations[key] = "Owned positive fixture reference at this exact site"
    rows = patch_sites(source, path, bans=registrations)
    assert raising_errors(rows, path) == []
    assert ban_allowance_errors({path: rows}, registrations, _fixture_ban_limits(registrations)) == []
    refusal = f"{path}:{line}: unprovable namespace write; rewrite or register with a reason"
    assert refusal in raising_errors(patch_sites(source, path, bans={}), path)
    blank = dict(registrations)
    blank[key] = " "
    assert refusal in raising_errors(patch_sites(source, path, bans=blank), path)
    changed = dict(registrations)
    del changed[key]
    changed[_fixture_key(path, source, line, kind, 'unrelated')] = "A different reference at the same location"
    assert refusal in raising_errors(patch_sites(source, path, bans=changed), path)
    assert ban_allowance_errors({}, registrations, _fixture_ban_limits(registrations))
    assert any("exceeds" in error for error in ban_allowance_errors(
        {path: rows}, registrations, {kind: _fixture_ban_limits(registrations)[kind] - 1}))
    other = "tests/other_namespace.py"
    assert f"{other}:{line}: unprovable namespace write; rewrite or register with a reason" in raising_errors(
        patch_sites(source, other, bans=registrations), other)
    assert raising_errors(patch_sites('\n' + source, path, bans=registrations), path) == []


def test_r12_namespace_words_in_literals_and_owned_dictionary_fields_are_plain_data():
    source = ('fields = {"locals": "__class__", "vars": "__dict__"}\n'
              'fields["globals"] = "__setattr__"\n'
              'scope.globals = fields\ndel fields["vars"]')
    assert raising_errors(patch_sites(source, bans={})) == []


@pytest.mark.parametrize("source,line", [
    ('import os, pytest\nMaker = pytest.MonkeyPatch\n'
     'def helper(patcher, method="setattr"):\n'
     '    getattr(patcher, method)(os, "RENAMED", 1, raising=False)\n'
     'def test_case():\n    helper(Maker(), "setattr")', 2),
    ('import os, pytest\ndef helper(patcher, method="setattr"):\n'
     '    getattr(patcher, method)(os, "RENAMED", 1, raising=False)\n'
     'def test_case():\n    helper(pytest.MonkeyPatch.__call__(), "setattr")', 5),
    ('import pytest as p\nsaved = p.MonkeyPatch', 2),
    ('from pytest import MonkeyPatch as Maker\nsaved = Maker', 2),
    ('saved = MonkeyPatch', 1),
    ('saved = MonkeyPatch.__call__', 1),
    ('saved = [pytest.MonkeyPatch]', 1),
    ('consume(pytest.MonkeyPatch)', 1),
    ('def factory():\n    return pytest.MonkeyPatch', 2),
    ('def helper(patcher=pytest.MonkeyPatch):\n    pass', 1),
    ('patcher: object = pytest.MonkeyPatch', 1),
    ('def helper(patcher: object = pytest.MonkeyPatch):\n    pass', 1),
])
def test_r12_argon1021_monkeypatch_class_acquisition_is_refused(source, line):
    path = "tests/argon1021_constructor.py"
    assert f"{path}:{line}: {UNPROVABLE}" in raising_errors(patch_sites(source, path, bans={}), path)


@pytest.mark.parametrize("source", [
    'import pytest\ndef helper(patcher: pytest.MonkeyPatch):\n    pass',
    'from pytest import MonkeyPatch as Maker\ndef helper(patcher: Maker) -> Maker:\n    pass',
    'import pytest\npatcher: pytest.MonkeyPatch',
    'import pytest\npatcher: list[pytest.MonkeyPatch] = []',
    'def helper(patcher: "pytest.MonkeyPatch") -> "MonkeyPatch":\n    pass',
])
def test_r12_argon1021_monkeypatch_type_annotations_remain_allowed(source):
    assert raising_errors(patch_sites(source, bans={})) == []


def test_r12_argon1021_class_reference_registration_is_exact_and_counted():
    path = "tests/registered_constructor_reference.py"
    source = 'import pytest\nsaved = pytest.MonkeyPatch'
    key = _fixture_key(path, source, 2, 'constructor_reference', 'pytest.MonkeyPatch')
    bans = {key: "Owned synthetic class-reference positive control"}
    rows = patch_sites(source, path, bans=bans)
    assert raising_errors(rows, path) == []
    assert ban_allowance_errors({path: rows}, bans, {"constructor_reference": 1}) == []
    assert f"{path}:2: {UNPROVABLE}" in raising_errors(patch_sites(source, path, bans={key: " "}), path)
    assert raising_errors(patch_sites('\n' + source, path, bans=bans), path) == []
    assert any("exceeds" in error for error in ban_allowance_errors({path: rows}, bans, {"constructor_reference": 0}))
    assert ban_allowance_errors({}, bans, {"constructor_reference": 1})


@pytest.mark.parametrize("kind,expression,statement,shared", [
    ("owner", "owner", 'monkeypatch.setattr(owner, "field", fake)', False),
    ("callable", "mp.setattr", 'mp.setattr(os, "name", "nt")', True),
    ("fixture", "external(monkeypatch)", 'external(monkeypatch)', False),
])
def test_r12c_proof_keys_survive_markers_but_pin_scope_syntax_and_occurrence(kind, expression, statement, shared):
    path = "tests/stable_proof.py"
    source = 'import os\ndef t(monkeypatch, mp, owner):\n    ' + statement
    key = (path, "t", kind, expression, 0)
    proofs = {key: (shared, "Owned exact synthetic boundary")}
    # The callable control also needs its existing lexical owner classification.
    owners = {(path, "t", "os"): (True, "Imported shared module")}
    for variant in (source, '# marker\n\n' + source, source.replace('    ' + statement, '    marker = True\n    ' + statement)):
        rows = patch_sites(variant, path, proofs=proofs, owners=owners, dynamic={})
        assert raising_errors(rows, path) == []
        assert proof_allowance_errors({path: rows}, proofs) == []
    assert raising_errors(patch_sites(source.replace('def t(', 'def other('), path, proofs=proofs), path)
    doubled = source + '\n    ' + statement
    assert raising_errors(patch_sites(doubled, path, proofs=proofs, owners=owners), path)


def test_r12c_ban_keys_survive_markers_and_reject_an_extra_identical_reference():
    path = "tests/stable_ban.py"
    source = 'def t():\n    return globals'
    key = (path, "t", "namespace_globals", "return globals", 0)
    bans = {key: "Owned exact synthetic namespace reference"}
    for variant in (source, '# marker\n\n' + source, source.replace('    return', '    marker = True\n    return')):
        rows = patch_sites(variant, path, bans=bans)
        assert raising_errors(rows, path) == []
        assert ban_allowance_errors({path: rows}, bans, {"namespace_globals": 1}) == []
    doubled = source + '\n    saved = globals'
    assert f"{path}:3: {NAMESPACE_UNPROVABLE}" in raising_errors(patch_sites(doubled, path, bans=bans), path)
    assert raising_errors(patch_sites(source.replace('def t(', 'def other('), path, bans=bans), path)


def test_r12c_computed_keys_survive_markers_and_pin_call_flags_and_occurrence():
    path = "tests/stable_computed.py"
    call = 'monkeypatch.setattr(factory(), "open", fake)'
    source = 'def t(monkeypatch):\n    ' + call
    key = (path, "t", "patch", call, 0)
    dynamic = {key: (True, "Owned fixture factory returns shared OS API")}
    for variant in (source, '# marker\n\n' + source, source.replace('    ' + call, '    marker = True\n    ' + call)):
        rows = patch_sites(variant, path, dynamic=dynamic)
        assert raising_errors(rows, path, dynamic=dynamic) == []
        assert allowance_errors({path: rows}, platform={}, builtin={}, leased={}, dynamic=dynamic) == []
    assert raising_errors(patch_sites(source + '\n    ' + call, path, dynamic=dynamic), path, dynamic=dynamic)
    assert raising_errors(patch_sites(source[:-1] + ', raising=False)', path, dynamic=dynamic), path, dynamic=dynamic)


def test_r12c_strict_site_survives_marker_only_edits():
    path = "tests/integration/test_hierarchy_provision.py"
    source = (REPO / path).read_text(encoding="utf-8")
    assert raising_errors(patch_sites(source, path), path) == []
    assert raising_errors(patch_sites('# capability marker\n\n' + source, path), path) == []


def test_r12c_identical_banned_references_on_one_line_need_separate_registrations():
    path = "tests/same_line_ban.py"
    source = 'def t():\n    return globals, globals'
    key = (path, "t", "namespace_globals", "return globals, globals", 0)
    bans = {key: "First owned reference"}
    assert f"{path}:2: {NAMESPACE_UNPROVABLE}" in raising_errors(patch_sites(source, path, bans=bans), path)
    bans[(*key[:4], 1)] = "Second owned reference"
    rows = patch_sites(source, path, bans=bans)
    assert raising_errors(rows, path) == []
    assert ban_allowance_errors({path: rows}, bans, {"namespace_globals": 1})
    assert ban_allowance_errors({path: rows}, bans, {"namespace_globals": 2}) == []


def test_r12c_identical_computed_calls_on_one_line_need_separate_registrations():
    path = "tests/same_line_computed.py"
    call = 'monkeypatch.setattr(factory(), "open", fake)'
    source = 'def t(monkeypatch):\n    ' + call + '; ' + call
    key = (path, "t", "patch", call, 0)
    dynamic = {key: (True, "First owned factory result")}
    assert raising_errors(patch_sites(source, path, dynamic=dynamic), path, dynamic=dynamic)
    dynamic[(*key[:4], 1)] = (True, "Second owned factory result")
    rows = patch_sites(source, path, dynamic=dynamic)
    assert raising_errors(rows, path, dynamic=dynamic) == []
    assert allowance_errors({path: rows}, platform={}, builtin={}, leased={}, dynamic=dynamic) == []


def test_r12c_equivalent_proof_keys_cannot_register_the_same_occurrence_twice():
    path = "tests/duplicate_proof.py"
    source = 'def t(monkeypatch, owner):\n    monkeypatch.setattr(owner, "field", fake)'
    proofs = {(path, "t", "owner", "owner", 0): (False, "First spelling"),
              (path, "t", "owner", "(owner)", 0): (False, "Equivalent spelling")}
    rows = patch_sites(source, path, proofs=proofs)
    assert raising_errors(rows, path) == []
    assert any("duplicate" in error for error in proof_allowance_errors({path: rows}, proofs))


def test_r12c_equivalent_computed_keys_cannot_register_the_same_occurrence_twice():
    path = "tests/duplicate_computed.py"
    call = 'monkeypatch.setattr(factory(), "open", fake)'
    source = 'def t(monkeypatch):\n    ' + call
    dynamic = {(path, "t", "patch", call, 0): (True, "First spelling"),
               (path, "t", "patch", call.replace('"open"', "'open'"), 0): (True, "Equivalent spelling")}
    rows = patch_sites(source, path, dynamic=dynamic)
    assert raising_errors(rows, path, dynamic=dynamic) == []
    assert any("duplicate" in error for error in allowance_errors(
        {path: rows}, platform={}, builtin={}, leased={}, dynamic=dynamic))


def test_r12c_a_strict_call_cannot_keep_a_stale_nonraising_lease():
    path = "tests/stale_lease.py"
    call = 'monkeypatch.setattr(module, "field", fake)'
    source = 'import json as module\n' + call
    leased = {(path, "<module>", "patch", call, 0): "No permissive flag remains"}
    rows = patch_sites(source, path)
    assert allowance_errors({path: rows}, platform={}, builtin={}, leased=leased, dynamic={})


@pytest.mark.parametrize("statement", [
    'external(**monkeypatch)',
    'values = [x for x in monkeypatch]',
    'with monkeypatch as p:\n    pass',
    'def helper(first=1, second=monkeypatch):\n    pass',
])
def test_r12c_fixture_fragments_refuse_without_a_parser_exception(statement):
    source = 'def t(monkeypatch):\n' + ''.join('    ' + line + '\n' for line in statement.split('\n'))
    path = "tests/fixture_fragment.py"
    errors = raising_errors(patch_sites(source, path), path)
    assert f"{path}:2: {UNPROVABLE}" in errors


@pytest.mark.parametrize("statement,expression,changed", [
    ('external(*monkeypatch)', 'external(*monkeypatch)', 'saved = [*monkeypatch]'),
    ("saved = f'{monkeypatch}'", "f'{monkeypatch}'", 'saved = {monkeypatch}'),
    ('saved = values[monkeypatch:]', 'values[monkeypatch:]', 'saved = values[:monkeypatch]'),
])
def test_r12c_fragment_keys_pin_the_complete_expression(statement, expression, changed):
    path = "tests/fragment_identity.py"
    source = 'def t(monkeypatch):\n    ' + statement
    proofs = {(path, "t", "fixture", expression, 0): (False, "Owned complete expression")}
    rows = patch_sites(source, path, proofs=proofs)
    assert raising_errors(rows, path) == []
    assert proof_allowance_errors({path: rows}, proofs) == []
    assert raising_errors(patch_sites('def t(monkeypatch):\n    ' + changed, path, proofs=proofs), path)


@pytest.mark.parametrize("acquisition,mutation", [
    ('from builtins import __dict__ as ns', 'ns["globals"]().update(owner=os)'),
    ('from builtins import __getattribute__ as lookup', 'lookup("globals")().update(owner=os)'),
])
def test_r13_builtin_namespace_acquisition_requires_a_complete_admitted_operation(acquisition, mutation):
    source = ('import json as owner, os\n' + acquisition + '\n' + mutation + '\n'
              'def test_case(monkeypatch):\n    monkeypatch.setattr(owner, "name", "nt")')
    path = "tests/r13_namespace_import.py"
    assert f"{path}:2: {NAMESPACE_UNPROVABLE}" in raising_errors(patch_sites(source, path), path)


@pytest.mark.parametrize("path,scope,target,replacement", [
    ('tests/integration/test_hierarchy_source.py', 'source', 'subprocess',
     'dict.update(vars(subprocess), run=run) or subprocess'),
    ('tests/integration/test_hierarchy_source.py', 'test_blob_timeout_is_a_documented_refusal_and_can_be_read_later', 'subprocess',
     'dict.update(vars(subprocess), run=timeout) or subprocess'),
    ('tests/integration/test_hierarchy_container.py', 'cli', 'adapter.subprocess',
     'dict.update(vars(adapter.subprocess), run=lambda command, **kwargs: fake_engine_call(command)) or adapter.subprocess'),
])
def test_r13_existing_seam_registration_does_not_authorize_a_namespace_write(path, scope, target, replacement):
    source = (REPO / path).read_text(encoding="utf-8")
    assert raising_errors(patch_sites(source, path), path) == []
    tree = ast.parse(source)
    labels = _scope_labels(tree)
    constructor = next(node for node in ast.walk(tree)
                       if isinstance(node, ast.Call) and ast.unparse(node.func) == 'SimpleNamespace'
                       and labels[id(node)] == scope
                       and any(isinstance(child, ast.Call) and ast.unparse(child.func) == 'vars'
                               and child.args and ast.unparse(child.args[0]) == target for child in ast.walk(node)))

    class ReplaceSeam(ast.NodeTransformer):
        def visit_Call(self, node):
            if node is constructor:
                return ast.copy_location(ast.parse(replacement, mode='eval').body, node)
            return self.generic_visit(node)

    changed = ast.unparse(ast.fix_missing_locations(ReplaceSeam().visit(tree)))
    mutated = ast.parse(changed)
    mutation = next(node for node in ast.walk(mutated) if isinstance(node, ast.Call)
                    and ast.unparse(node.func) == 'dict.update' and node.args
                    and ast.unparse(node.args[0]) == 'vars(' + target + ')')
    assert f"{path}:{mutation.lineno}: {NAMESPACE_UNPROVABLE}" in raising_errors(patch_sites(changed, path), path)


@pytest.mark.parametrize("placement", [
    'def probe(value: helper(pytest.MonkeyPatch(), "setattr")):\n    pass',
    'def probe() -> helper(pytest.MonkeyPatch(), "setattr"):\n    pass',
    'async def probe() -> helper(pytest.MonkeyPatch(), "setattr"):\n    pass',
    'sentinel: helper(pytest.MonkeyPatch(), "setattr")',
    'class Probe:\n    sentinel: helper(pytest.MonkeyPatch(), "setattr")',
    'def probe(value: (Maker := pytest.MonkeyPatch)):\n    pass',
])
def test_r13_executable_annotations_are_refused_at_every_placement(placement):
    source = ('import os, pytest\ndef helper(patcher, method):\n'
              '    getattr(patcher, method)(os, "RENAMED", 1, raising=False)\n' + placement)
    path = "tests/r13_annotation.py"
    tree = ast.parse(source)
    annotation = next(node.annotation for node in ast.walk(tree) if isinstance(node, (ast.arg, ast.AnnAssign))
                      and node.annotation is not None) if '->' not in placement else next(
                          node.returns for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                          and node.returns is not None)
    assert f"{path}:{annotation.lineno}: {UNPROVABLE}" in raising_errors(patch_sites(source, path), path)


@pytest.mark.parametrize("imports,modules", [('import os, sys', 'sys.modules'),
                                           ('import os, importlib', 'importlib.sys.modules')])
def test_r13_argon_sys_modules_substitution_is_refused(imports, modules):
    source = (imports + '\ndict.update(' + modules + ', json=os)\nimport json as owner\n'
              'def test_case(monkeypatch):\n    monkeypatch.setattr(owner, "name", "nt")')
    path = "tests/r13_module_substitution.py"
    assert f"{path}:2: {NAMESPACE_UNPROVABLE}" in raising_errors(patch_sites(source, path), path)


@pytest.mark.parametrize("expression", ['values[monkeypatch:, 0]', 'values[0, monkeypatch:]'])
def test_r13_argon_multidimensional_slice_refuses_without_reparsing_a_fragment(expression):
    source = 'def test_case(monkeypatch):\n    ' + expression
    path = "tests/r13_slices.py"
    assert f"{path}:2: {UNPROVABLE}" in raising_errors(patch_sites(source, path), path)


def test_r13_argon_registered_dynamic_owner_still_needs_a_computed_call_registration():
    path = "tests/r13_dynamic_owner.py"
    call = 'monkeypatch.setattr(factory(), "field", fake)'
    source = 'def test_case(monkeypatch):\n    ' + call
    owners = {(path, "test_case", "factory()"): (False, "Owned product-module factory")}
    rows = patch_sites(source, path, owners=owners, dynamic={})
    assert raising_errors(rows, path, dynamic={}) == [
        '2: <dynamic>.field cannot classify patch target or call; register with a reason']
    computed = {(path, "test_case", "patch", call, 0): (False, "Exact owned factory invocation")}
    assert raising_errors(patch_sites(source, path, owners=owners, dynamic=computed), path, dynamic=computed) == []


def test_r13_argon_multiline_callable_inherits_its_own_call_shared_status():
    path = "tests/r13_multiline_callable.py"
    source = 'from unittest.mock import patch\n(\n    patch\n)(\n    "os.name", "nt"\n)'
    key = (path, "<module>", "callable", "patch", 0)
    correct = {key: (True, "This callable patches shared os.name")}
    rows = patch_sites(source, path, proofs=correct)
    assert rows == [(2, 'os.name', True, False)]
    assert raising_errors(rows, path) == []
    wrong = {key: (False, "Incorrectly hides the shared operation")}
    assert f"{path}:3: proof registration misclassifies shared status" in raising_errors(
        patch_sites(source, path, proofs=wrong), path)


@pytest.mark.parametrize("annotation", [
    'factory()', '(alias := object)', '(lambda: object)', '[value for value in types]',
    '{"field": str}', '{str}', 'str + int', '0', 'True',
])
def test_r13_annotation_grammar_defaults_to_refusal(annotation):
    path = "tests/r13_type_grammar.py"
    source = 'def probe(value: ' + annotation + '):\n    pass'
    assert f"{path}:1: {UNPROVABLE}" in raising_errors(patch_sites(source, path), path)


@pytest.mark.parametrize("annotation", [
    'Name', 'typing.Type', 'list[str]', 'typing.Callable[[str, bytes], None]',
    'str | None', 'tuple[str, int | None]', '"ForwardRef"', 'None',
])
def test_r13_annotation_grammar_admits_only_inert_type_shapes(annotation):
    source = 'def probe(value: ' + annotation + ') -> ' + annotation + ':\n    local: ' + annotation
    assert raising_errors(patch_sites(source)) == []


def test_r13_same_line_callables_do_not_share_an_unrelated_calls_classification():
    path = "tests/r13_same_line_classification.py"
    source = 'from unittest.mock import patch\npatch("consumer.field"); patch("os.name")'
    proofs = {(path, "<module>", "callable", "patch", 0): (False, "Owned consumer target"),
              (path, "<module>", "callable", "patch", 1): (True, "Shared os target")}
    rows = patch_sites(source, path, proofs=proofs)
    assert [row[2] for row in rows] == [False, True]
    assert raising_errors(rows, path) == []
    assert proof_allowance_errors({path: rows}, proofs) == []


def test_r13_executable_annotation_cannot_be_admitted_by_a_registration():
    source = 'def probe(value: factory()):\n    pass'
    path = "tests/r13_hard_annotation_refusal.py"
    bans = {(path, "<module>", "annotation", "factory()", 0): "Cannot override the inert grammar"}
    assert f"{path}:1: {UNPROVABLE}" in raising_errors(patch_sites(source, path, bans=bans), path)


@pytest.mark.parametrize("constructor", ["SimpleNamespace", "types.SimpleNamespace"])
def test_r14_seam_shape_is_allowed_without_a_site_registration(constructor):
    source = ('import os, types\nfrom types import SimpleNamespace\n'
              'snapshot = ' + constructor + '(**{**vars(os), "name": "nt"})')
    assert raising_errors(patch_sites(source, bans={})) == []


@pytest.mark.parametrize("annotation", ['tuple[str, ...]', 'typing.Callable[..., None]', '...'])
def test_r14_ellipsis_is_inert_at_every_annotation_placement(annotation):
    source = ('def probe(value: ' + annotation + ') -> ' + annotation
              + ':\n    local: ' + annotation)
    assert raising_errors(patch_sites(source)) == []


@pytest.mark.parametrize("kind,imports,operation,changed", [
    ('namespace_vars', 'import os', 'snapshot = SimpleNamespace(**vars(os))',
     'snapshot = dict.update(vars(os), name="nt")'),
    ('namespace_sys_modules', 'import sys', 'owner = sys.modules["os"]',
     'owner = dict.update(sys.modules, json=os)'),
    ('namespace_builtin_import', '', 'import builtins as runtime',
     'from builtins import __dict__ as runtime'),
    ('namespace_getattr', 'import os', 'field = getattr(os, selected, None)',
     'field = getattr(os, selected)("value")'),
])
def test_r14_registrations_pin_complete_operations_and_survive_line_changes(kind, imports, operation, changed):
    path = 'tests/r14_registered_operation.py'
    source = imports + '\ndef test_case():\n    ' + operation
    key = (path, 'test_case', kind, operation, 0)
    registrations = {key: 'Owned synthetic operation; its complete syntax is reviewed.'}
    rows = patch_sites(source, path, bans=registrations)
    assert raising_errors(rows, path) == []
    assert ban_allowance_errors({path: rows}, registrations, {kind: 1}) == []
    assert raising_errors(patch_sites('# marker\n\n' + source, path, bans=registrations), path) == []
    mutated = source.replace(operation, changed)
    assert f'{path}:3: {NAMESPACE_UNPROVABLE}' in raising_errors(
        patch_sites(mutated, path, bans=registrations), path)
    assert raising_errors(patch_sites(source + '\n    ' + operation, path, bans=registrations), path)
    assert raising_errors(patch_sites(source.replace('test_case', 'other'), path, bans=registrations), path)


def test_r14_two_references_in_one_operation_each_need_their_occurrence():
    path = 'tests/r14_namespace_occurrences.py'
    operation = 'snapshot = (vars(os), vars(os))'
    source = 'import os\n' + operation
    key = (path, '<module>', 'namespace_vars', operation, 0)
    registrations = {key: 'First owned module namespace read.'}
    assert f'{path}:2: {NAMESPACE_UNPROVABLE}' in raising_errors(
        patch_sites(source, path, bans=registrations), path)
    registrations[(*key[:4], 1)] = 'Second owned module namespace read.'
    assert raising_errors(patch_sites(source, path, bans=registrations), path) == []


def test_r14_a_registered_builtin_import_does_not_register_its_aliased_capability():
    path = 'tests/r14_alias_capability.py'
    source = 'from builtins import __dict__ as ns\nns["globals"]().update(owner=os)'
    bans = {(path, '<module>', 'namespace_builtin_import', 'from builtins import __dict__ as ns', 0):
            'Owned import positive; use still requires its own exact operation.'}
    assert f'{path}:2: {NAMESPACE_UNPROVABLE}' in raising_errors(patch_sites(source, path, bans=bans), path)


def test_r14_a_seam_constructor_must_resolve_to_types_simple_namespace():
    source = 'import os\nfrom evil import SimpleNamespace\nsnapshot = SimpleNamespace(**{**vars(os), "name": "nt"})'
    assert f'<fixture>:3: {NAMESPACE_UNPROVABLE}' in raising_errors(patch_sites(source, bans={}))


def test_r14_an_ambiguous_vars_alias_cannot_use_the_read_only_seam_shape():
    path = 'tests/r14_ambiguous_namespace.py'
    binding = 'inspect = vars if flag else evil'
    source = ('import os\nfrom types import SimpleNamespace\n' + binding
              + '\nsnapshot = SimpleNamespace(**{**inspect(os), "name": "nt"})')
    bans = {(path, '<module>', 'namespace_vars', binding, 0): 'Owned binding; invocation is independently reviewed.'}
    assert f'{path}:4: {NAMESPACE_UNPROVABLE}' in raising_errors(patch_sites(source, path, bans=bans), path)


@pytest.mark.parametrize('operation', [
    'importlib.import_module = lambda name: os',
    'monkeypatch.setattr(importlib, "import_module", lambda name: os)',
    'importlib.import_module, marker = (lambda name: os), None',
    'for importlib.import_module in [lambda name: os]:\n    pass',
])
def test_r14_importlib_module_substitution_needs_a_complete_registration(operation):
    source = 'import importlib, os\n' + operation
    path = 'tests/r14_importlib_substitution.py'
    assert f'{path}:2: {NAMESPACE_UNPROVABLE}' in raising_errors(patch_sites(source, path), path)


@pytest.mark.parametrize('operation', [
    'getattr(builtins, "__dict__")["globals"]().update(owner=os)',
    'getattr(builtins, "globals")().update(owner=os)',
    'getattr(builtins, "__getattribute__")("globals")().update(owner=os)',
    'dict.update(getattr(sys, "modules"), json=os)',
])
def test_r14_literal_reflection_is_the_same_namespace_capability(operation):
    path = 'tests/r14_literal_namespace.py'
    source = 'import builtins, os, sys\n' + operation
    bans = {(path, '<module>', 'namespace_builtin_import', 'import builtins, os, sys', 0):
            'Owned import positive; it does not authorize another namespace operation.'}
    assert f'{path}:2: {NAMESPACE_UNPROVABLE}' in raising_errors(patch_sites(source, path, bans=bans), path)


@pytest.mark.parametrize('kind,source', [
    ('constructor', 'import pytest\npytest.MonkeyPatch()'),
    ('namespace___delattr__', 'object.__delattr__(owned, "field")'),
    ('namespace_locals', 'captured = locals'),
    ('namespace_delattr', 'delattr(owned, selected)'),
])
def test_r14_registration_cannot_raise_an_unused_class_ceiling(kind, source):
    path = 'tests/r14_zero_ceiling.py'
    observed = patch_sites(source, path, bans={})
    registrations = {key: 'Owned positive source operation; the count ceiling is independent.' for key in observed.bans}
    rows = patch_sites(source, path, bans=registrations)
    assert raising_errors(rows, path) == []
    limits = {name: limit for name, limit in BAN_LIMITS.items() if name == kind}
    assert any(kind + ' ban count 1 exceeds 0' in error
               for error in ban_allowance_errors({path: rows}, registrations, limits))


def test_r14_namespace_ast_fingerprints_match_only_the_complete_operation():
    path = 'tests/r14_namespace_fingerprint.py'
    operation = 'owner = sys.modules["os"]'
    source = 'import sys\n' + operation
    key = (path, '<module>', 'namespace_sys_modules',
           'ast-sha256:1efe9c560116f7a83f483b4717c99da58910ca633b14d3711777bcea7de34b00', 0)
    registrations = {key: 'Owned loaded-module selection; fingerprint pins the complete assignment.'}
    rows = patch_sites(source, path, bans=registrations)
    assert raising_errors(rows, path) == []
    assert raising_errors(patch_sites('# marker\n' + source, path, bans=registrations), path) == []
    assert raising_errors(patch_sites(source.replace('["os"]', '[ "os" ]'), path, bans=registrations), path) == []
    assert f'{path}:2: {NAMESPACE_UNPROVABLE}' in raising_errors(
        patch_sites(source.replace('"os"', '"json"'), path, bans=registrations), path)
    registrations[(path, '<module>', 'namespace_sys_modules', operation, 0)] = 'Equivalent duplicate spelling.'
    assert any('duplicate ban registration' in error for error in ban_allowance_errors(
        {path: rows}, registrations, {'namespace_sys_modules': 1}))


@pytest.mark.parametrize('source,kind,fingerprint', [
    ('import importlib\nfor importlib.import_module in [None]:\n    def helper():\n        pass',
     'namespace_importlib', 'c3027eb9435a69c70a83415684776786425e10fc86d5c705466d8c5592850698'),
    ('import sys\nowner = sys.modules["\U0001fae8"]',
     'namespace_sys_modules', 'fa5cf19466191d876c2361494616593a6597b316a23e0457f3f4cef8fe8c065c'),
])
def test_r14_namespace_fingerprints_are_portable_across_supported_parsers(source, kind, fingerprint):
    path = 'tests/r14_portable_fingerprint.py'
    # Expected identities omit empty definition fields absent on 3.9 and use
    # ASCII escapes independently of the interpreter's Unicode database.
    bans = {(path, '<module>', kind, 'ast-sha256:' + fingerprint, 0): 'Owned portable source operation.'}
    assert raising_errors(patch_sites(source, path, bans=bans), path) == []


@pytest.mark.parametrize('filename', ['tests/unit/cli/test_team_hosts_cli.py', 'tests/unit/core/test_team_hosts.py'])
def test_r15_merged_sites_have_exact_reviewed_registrations(filename):
    source = (REPO / filename).read_text(encoding='utf-8')
    assert raising_errors(patch_sites(source, filename), filename) == []


@pytest.mark.parametrize('filename,target', [
    ('tests/integration/test_hierarchy_provision.py', 'MODEL_BINDINGS'),
    ('tests/unit/core/test_team_hosts.py', 'deque'),
])
def test_rf11d_always_present_targets_require_strict_patches(filename, target):
    rows = patch_sites((REPO / filename).read_text(encoding='utf-8'), filename)
    selected = [row for row in rows if row[1].endswith('.' + target)]
    assert selected, 'the behavior probe must still patch its intended target'
    assert all(not nonraising for _, _, _, nonraising in selected)


@pytest.mark.parametrize('filename,function', [
    ('tests/unit/cli/test_team_hosts_cli.py', 'test_public_entrypoint'),
])
def test_r15_registrations_do_not_authorize_a_sibling_scope(filename, function):
    source = (REPO / filename).read_text(encoding='utf-8')
    changed = source.replace('def ' + function + '(', 'def unregistered_' + function + '(', 1)
    assert changed != source
    assert raising_errors(patch_sites(changed, filename), filename)


def test_r15_queue_patch_cannot_permit_a_missing_target():
    filename = 'tests/unit/core/test_team_hosts.py'
    source = (REPO / filename).read_text(encoding='utf-8')
    changed = source.replace('"deque", CountedDeque)', '"unregistered_queue", CountedDeque, raising=False)', 1)
    assert changed != source
    assert any('aegis_core.team_profile.unregistered_queue permits a missing target' in error
               for error in raising_errors(patch_sites(changed, filename), filename))


def test_malformed_python_is_not_silently_ignored():
    with pytest.raises(SyntaxError) as error:
        patch_sites("def broken(\n", "tests/broken.py")
    assert error.value.filename == "tests/broken.py"


@pytest.mark.parametrize("source", [
    'mp.setattr(target=module, name="RENAMED", value=1, raising=False)',
    'mp.setattr(module, name="missing", value=1, raising=False)',
    'import sys\nmp.setattr(sys.modules["os"], "name", "nt", raising=False)',
    'mp.setattr(module, "RENAMED", 1, raising=flag)',
    'mp.setattr(module, "RENAMED", 1, raising=0)',
    'mp.setattr(index_module(), "RENAMED", 1, raising=False)',
    'mp.setattr(objects[0], "RENAMED", 1, raising=False)',
    'mp.setattr(first if condition else second, "RENAMED", 1, raising=False)',
])
def test_unseen_nonraising_forms_fail_closed(source):
    assert raising_errors(patch_sites(source)), source


@pytest.mark.parametrize("source,target", [
    ('import sys\nmp.setattr(sys.modules["os"], "open", fake)', "os.open"),
    ('import os\nmp.setattr(target=os, name="open", value=fake)', "os.open"),
    ('import os\nmp.setattr(os.path, "realpath", fake)', "os.path.realpath"),
    ('from os import path\nmp.setattr(path, "realpath", fake)', "os.path.realpath"),
    ('def a(patch):\n    import os as mod\n    patch.setattr(mod, "name", "nt")\n'
     'def b():\n    from pathlib import Path as mod\n', "os.name"),
    ('from unittest import mock\nmock.patch("os.replace")', "os.replace"),
    ('from unittest.mock import patch\npatch("os.replace")', "os.replace"),
    ('import unittest.mock\nunittest.mock.patch("os.replace")', "os.replace"),
    ('from unittest.mock import patch\nimport os\npatch.object(os.path, "realpath", fake)', "os.path.realpath"),
    ('from unittest import mock\nimport shutil\nmock.patch.object(target=shutil, attribute="which", new=fake)', "shutil.which"),
])
def test_shared_patch_forms_cannot_escape_the_ceiling(source, target):
    sites = patch_sites(source)
    assert [name for _, name, shared, _ in sites if shared] == [target]
    assert count_errors({"tests/new.py": sum(shared for _, _, shared, _ in sites)}, {})


@pytest.mark.parametrize("call", [
    'mp.setattr(os.path, "realpath", fake)',
    'mock.patch("os.replace")',
])
def test_an_added_shared_patch_in_a_file_at_its_limit_fails(call):
    source = 'import os\nfrom unittest import mock\n' + call + '\n' + call
    count = sum(shared for _, _, shared, _ in patch_sites(source))
    assert count == 2
    assert count_errors({"tests/at_limit.py": count}, {"tests/at_limit.py": 1}) == [
        "tests/at_limit.py: shared module patch count 2 exceeds 1"]


@pytest.mark.parametrize("source", [
    'mp.setattr(*arguments, raising=False)',
    'mp.setattr(target=os, name="open", value=fake, **options)',
    'from unittest import mock\nmock.patch("os.replace", create=True)',
    'from unittest import mock\nmock.patch.object(os, "replace", create=flag)',
])
def test_opaque_or_permissive_patch_calls_are_refused(source):
    assert raising_errors(patch_sites(source))


def test_removing_a_patch_requires_lowering_the_ceiling():
    assert "lower to 0" in "\n".join(count_errors({}, {"tests/old.py": 1}))


@pytest.mark.parametrize("entries", [
    {"platform": {"os.geteuid": "absent on Windows"}, "builtin": {}, "leased": {}, "dynamic": {}},
    {"platform": {}, "builtin": {("tests/a.py", "module.open"): "builtin lookup"}, "leased": {}, "dynamic": {}},
    {"platform": {}, "builtin": {}, "leased": {("tests/a.py", "<module>", "patch", "call()", 0): "owner follow-up"}, "dynamic": {}},
    {"platform": {}, "builtin": {}, "leased": {},
     "dynamic": {("tests/a.py", "<module>", "patch", "call()", 0): (True, "OS module factory")}},
])
def test_stale_allowlist_entries_fail(entries):
    assert allowance_errors({}, **entries)


def test_computed_target_registration_pins_file_line_flag_and_shared_status():
    path = "tests/a.py"
    source = 'monkeypatch.setattr(factory(), "open", fake)'
    key = _fixture_patch_key(path, source, 1)
    registry = {key: (True, "Reviewed factory returns the shared OS module")}
    rows = patch_sites(source, path, dynamic=registry)
    assert rows == [(1, "<dynamic>.open", True, False)]
    assert raising_errors(rows, path, dynamic=registry) == []
    assert raising_errors(rows, "tests/other.py", dynamic=registry)
    assert raising_errors([(2, *rows[0][1:])], path, dynamic=registry)
    unsafe = patch_sites(source[:-1] + ', raising=False)', path, dynamic=registry)
    assert raising_errors(unsafe, path, dynamic=registry)
    assert allowance_errors({path: rows}, platform={}, builtin={}, leased={}, dynamic=registry) == []


@pytest.mark.parametrize("imports,shared", [
    ('if condition:\n    import os as mod\nelse:\n    import json as mod', True),
    ('import os as mod\nimport json as mod', True),
    ('if condition:\n    from os import path as mod\nelse:\n    import json as mod', True),
    ('if condition:\n    import json as mod\nelse:\n    import math as mod', True),
])
def test_ambiguous_imports_fail_closed_and_count_any_shared_candidate(imports, shared):
    rows = patch_sites(imports + '\nmp.setattr(mod, "name", fake, raising=False)')
    assert len(rows) == 1
    assert rows[0][1] == "<dynamic>.name"
    assert rows[0][2] is shared
    assert raising_errors(rows)


def test_an_allowance_cannot_hide_a_shared_import_candidate():
    source = 'if condition:\n    import os as mod\nelse:\n    import json as mod\nmp.setattr(mod, "name", fake)'
    path = "tests/ambiguous.py"
    registry = {_fixture_patch_key(path, source, 5): (False, "incorrectly marked unshared")}
    rows = patch_sites(source, path, dynamic=registry)
    assert rows == [(5, "<dynamic>.name", True, False)]
    assert allowance_errors({path: rows}, platform={}, builtin={}, leased={}, dynamic=registry)


def test_an_ambiguous_mock_factory_cannot_hide_a_shared_target():
    source = ('if condition:\n    from unittest.mock import patch as operation\n'
              'else:\n    from builtins import print as operation\noperation("os.replace")')
    rows = patch_sites(source)
    assert rows == [(5, "<unresolved-call>", True, True)]
    assert raising_errors(rows)


@pytest.mark.parametrize("source,line", [
    ('def t(monkeypatch):\n    put = monkeypatch.setattr\n    put(module, "RENAMED", 1, raising=False)', 2),
    ('def t(monkeypatch):\n    getattr(monkeypatch, "setattr")(module, "RENAMED", 1, raising=False)', 2),
    ('from unittest import mock\nput = mock.patch\nput("os.name", "nt")', 2),
    ('from unittest import mock\nput = mock.patch.object\nput(module, "RENAMED", 1, create=True)', 2),
    ('from unittest.mock import patch as p\nput = p\nput("os.name", "nt")', 2),
    ('import unittest.mock as m\nput = m.patch.dict\nput(mapping, {})', 2),
    ('def t(monkeypatch):\n    operations = [monkeypatch.setattr]', 2),
    ('def t(monkeypatch):\n    helper(monkeypatch.setitem)', 2),
    ('def t(monkeypatch):\n    put = monkeypatch.delattr', 2),
    ('from unittest import mock\ngetattr(mock, "patch")("os.name", "nt")', 2),
    ('from unittest.mock import patch\ngetattr(patch, "object")(module, "RENAMED", 1, create=True)', 2),
    ('def helper(mp):\n    put = mp.setattr\n    put(module, "RENAMED", 1, raising=False)', 2),
    ('def helper(mp):\n    operations = [mp.delattr, mp.setitem]', 2),
    ('def helper(mp):\n    getattr(mp, "setattr")(module, "RENAMED", 1, raising=False)', 2),
    ('def helper(mp):\n    getattr(mp, "delattr")(module, "field")', 2),
    ('def helper(mp):\n    getattr(mp, "setitem")(mapping, "field", fake)', 2),
    ('from builtins import getattr as lookup\ndef helper(mp):\n    lookup(mp, "setattr")(module, "field", fake)', 3),
    ('lookup = getattr\ndef helper(mp):\n    lookup(mp, "setattr")(module, "field", fake)', 3),
    ('def helper(mp):\n    invoke = mp.setattr.__call__', 2),
    ('from unittest import mock\ninvoke = mock.patch.__call__', 2),
    ('if condition:\n    from builtins import getattr as lookup\n'
     'else:\n    from builtins import print as lookup\n'
     'lookup(mp, "setattr")(module, "field", fake)', 5),
])
def test_ruling_callable_loads_require_a_recognised_direct_call(source, line):
    path = "tests/callable.py"
    assert f"{path}:{line}: patch callable must be used in a recognised direct call" in raising_errors(
        patch_sites(source, path), path)


@pytest.mark.parametrize("source,shared", [
    ('def t(monkeypatch):\n    helper(monkeypatch)', 0),
    ('def t(monkeypatch):\n    alias = monkeypatch', 0),
    ('class Harness:\n    def __init__(self, monkeypatch):\n        self.monkeypatch = monkeypatch', 0),
    ('def helper(monkeypatch):\n    return monkeypatch', 0),
    ('import os\ndef helper(mp):\n    mp.setattr(os, "name", "nt")\n'
     'def t(monkeypatch):\n    helper(monkeypatch)', 1),
    ('import os\nclass Harness:\n    def __init__(self, monkeypatch):\n        self.monkeypatch = monkeypatch\n'
     '    def run(self):\n        self.monkeypatch.setattr(os, "name", "nt")', 1),
    ('import os\ndef helper(monkeypatch):\n    return monkeypatch\n'
     'def t(monkeypatch):\n    returned = helper(monkeypatch)\n    returned.setattr(os, "name", "nt")', 1),
])
def test_ruling_fixture_plumbing_requires_explicit_registration(source, shared):
    path = "tests/plumbing.py"
    rows = patch_sites(source, path)
    assert any(UNPROVABLE in error for error in raising_errors(rows, path))
    assert sum(row[2] for row in rows) == shared
    assert not rows.owners


@pytest.mark.parametrize("receiver", ["mp", "self.monkeypatch", "ordinary_object"])
@pytest.mark.parametrize("method,arguments,target", [
    ("setattr", 'os, "name", "nt"', "os.name"),
    ("delattr", 'os, "name"', "os.name"),
    ("setitem", 'os.environ, "NAME", "value"', "os.environ.NAME"),
])
def test_ruling_direct_methods_are_counted_for_any_receiver(receiver, method, arguments, target):
    path = "tests/receiver.py"
    rows = patch_sites('import os\n' + receiver + '.' + method + '(' + arguments + ')', path)
    assert rows == [(2, target, True, False)]
    assert f"{path}:2: {UNPROVABLE}" in raising_errors(rows, path)


@pytest.mark.parametrize("spelling", [
    'from unittest import mock\nmock.patch.multiple',
    'from unittest.mock import patch as p\np.multiple',
    'import unittest.mock as m\nm.patch.multiple',
    'import mock as m\nm.patch.multiple',
])
@pytest.mark.parametrize("arguments", ['"os", replace=fake', 'module, RENAMED=1, create=True'])
def test_ruling_patch_multiple_is_always_refused(spelling, arguments):
    path = "tests/multiple.py"
    assert raising_errors(patch_sites(spelling + '(' + arguments + ')', path), path) == [
        f"{path}:2: patch.multiple is forbidden; use individual direct patch calls"]


@pytest.mark.parametrize("binding", [
    'owner = os',
    'owner = sys.modules["os"]',
    'owner, operation = os, "lstat"',
    '(owner, (operation, other)) = (os, ("lstat", 1))',
    'for owner in (os, shutil):\n    pass',
    'for owner, operation in [(os, "lstat"), (shutil, "which")]:\n    pass',
    'if (owner := os):\n    pass',
])
@pytest.mark.parametrize("call", ['monkeypatch.setattr(owner, "name", "nt")',
                                  'mock.patch.object(owner, "name", "nt")'])
def test_ruling_provable_shared_bindings_cannot_escape_counts(binding, call):
    source = 'import os, sys, shutil\nfrom unittest import mock\n' + binding + '\n' + call
    path = "tests/binding.py"
    rows = patch_sites(source, path)
    assert sum(shared for _, _, shared, _ in rows) == 1
    line = source.count('\n') + 1
    assert count_errors({path: 1}, {}, sites={path: rows}) == [
        f"{path}:{line}: shared module patch count 1 exceeds 0"]


@pytest.mark.parametrize("call", ['monkeypatch.setattr(owner, "name", "nt")',
                                  'mock.patch.object(owner, "name", "nt")'])
def test_ruling_parameter_defaults_are_counted(call):
    source = 'import os\nfrom unittest import mock\ndef t(monkeypatch, owner=os):\n    ' + call
    rows = patch_sites(source)
    assert sum(shared for _, _, shared, _ in rows) == 1
    assert f"<fixture>:4: {UNPROVABLE}" in raising_errors(rows)


@pytest.mark.parametrize("binding,owner,line", [
    ('import importlib\nowner = importlib.import_module("subprocess")', 'owner', 3),
    ('def factory():\n    pass\nowner = factory()', 'owner', 4),
    ('', 'unknown', 1),
    ('', 'getattr', 1),
    ('', 'monkeypatch', 1),
    ('', 'monkeypatch.owner', 1),
    ('import os\nowner = os\nowner = factory()', 'owner', 4),
])
def test_ruling_unresolved_owners_are_refused_even_for_strict_calls(binding, owner, line):
    path = "tests/unresolved.py"
    source = (binding + '\n' if binding else '') + f'monkeypatch.setattr({owner}, "name", "nt")'
    assert f"{path}:{line}: unresolved patch owner; register file, scope and reason" in raising_errors(
        patch_sites(source, path), path)


@pytest.mark.parametrize("source,provable", [
    ('import os\nowner = os\nmonkeypatch.setattr(owner, "name", "nt")', True),
    ('import sys\nowner = sys.modules["os"]\nmonkeypatch.setattr(owner, "name", "nt")', True),
    ('import os\nowner, operation = os, "name"\nmonkeypatch.setattr(owner, "name", "nt")', False),
    ('import os\nfor owner in [os]:\n    monkeypatch.setattr(owner, "name", "nt")', False),
    ('import os\nif (owner := os):\n    monkeypatch.setattr(owner, "name", "nt")', False),
    ('import os\ndef t(monkeypatch, owner=os):\n    monkeypatch.setattr(owner, "name", "nt")', False),
    ('from unittest.mock import patch as p\np.dict("os.environ", {"A": "B"})', False),
    ('import os\ndef t(monkeypatch):\n    monkeypatch.delattr(os, "name")', True),
    ('import sys\ndef t(monkeypatch):\n    monkeypatch.setitem(sys.modules, "example", fake)', True),
])
def test_ruling_direct_shapes_preserve_counts_and_enforce_proof(source, provable):
    bans = _registered_namespace_call(source, "<fixture>") if "sys.modules" in source else {}
    rows = patch_sites(source, bans=bans)
    assert len(rows) == 1
    assert rows[0][2] is True
    errors = raising_errors(rows)
    if not provable:
        assert any(UNPROVABLE in error for error in errors)
    else:
        assert errors == []


def test_ruling_owner_registration_is_explicit_live_and_cannot_hide_shared_candidates():
    path = "tests/registered.py"
    source = 'def t(monkeypatch, owner):\n    monkeypatch.setattr(owner, "field", fake)'
    key = (path, "t", "owner")
    owners = {key: (False, "Owned fixture object at the OS boundary")}
    assert raising_errors(patch_sites(source, path, owners={key: (False, " ")}), path) == [
        f"{path}:2: unresolved patch owner; register file, scope and reason"]
    rows = patch_sites(source, path, owners=owners)
    assert raising_errors(rows, path) == []
    assert owner_allowance_errors({path: rows}, owners) == []
    assert raising_errors(patch_sites(source, "tests/other.py", owners=owners), "tests/other.py")
    assert raising_errors(patch_sites(source.replace('def t(', 'def other('), path, owners=owners), path)
    assert owner_allowance_errors({}, owners) == [f"stale owner registration: {key}"]
    assert owner_allowance_errors({path: rows}, {key: (False, " ")}) == [
        f"stale owner registration: {key}"]
    mixed = 'import os\ndef t(monkeypatch, owner):\n    owner = os if flag else factory()\n    monkeypatch.setattr(owner, "name", "nt")'
    rows = patch_sites(mixed, path, owners=owners)
    assert rows[0][2] is True
    assert owner_allowance_errors({path: rows}, owners) == [f"owner registration misclassifies shared status: {key}"]


def test_ruling_lexical_bindings_do_not_leak_or_hide_rebindings():
    source = ('import os\nowner = os\n'
              'def shared(monkeypatch):\n    monkeypatch.setattr(owner, "name", "nt")\n'
              'def local(monkeypatch, owner):\n    monkeypatch.setattr(owner, "field", fake)\n'
              'def different(monkeypatch):\n    import json as owner\n    monkeypatch.setattr(owner, "loads", fake)')
    rows = patch_sites(source, "tests/scopes.py")
    assert [shared for _, _, shared, _ in rows] == [True, True, True]
    errors = raising_errors(rows, "tests/scopes.py")
    assert "tests/scopes.py:6: unresolved patch owner; register file, scope and reason" in errors
    assert all(f"tests/scopes.py:{line}: {UNPROVABLE}" in errors for line in (4, 9))


@pytest.mark.parametrize("source", [
    'from unittest.mock import patch\nimport os\npatch.dict(os.environ, {"A": "B"})',
    'import pytest, os\ndef t(mp: pytest.MonkeyPatch):\n    mp.setattr(os, "name", "nt")',
    'import os\ndef t(monkeypatch):\n    with monkeypatch.context() as monkeypatch:\n        monkeypatch.setattr(os, "name", "nt")',
])
def test_ruling_additional_allowed_fixture_and_dictionary_shapes(source):
    rows = patch_sites(source)
    assert len(rows) == 1
    assert rows[0][2] is True
    assert any(UNPROVABLE in error for error in raising_errors(rows))


# Initial shared-module baseline re-measured at tip b11638bf, before RF-11b lands.
# After landing, reductions require lowering the recorded value.
PROCESS_PATCH_LIMITS = {
    'tests/unit/cli/test_cli_team.py': 1,
    'tests/integration/test_hierarchy_launcher_stop_ownership.py': 18,
    'tests/contract/test_mailbox_index_rollout.py': 5,
    'tests/helpers_popen.py': 1,
    'tests/integration/test_ci_green.py': 1,
    'tests/integration/test_hierarchy_container.py': 34,
    'tests/integration/test_hierarchy_decision_service.py': 1,
    'tests/integration/test_hierarchy_fake_claude.py': 1,
    'tests/integration/test_hierarchy_fixture_broker.py': 1,
    'tests/integration/test_hierarchy_handoff_stop_evidence.py': 1,
    'tests/integration/test_hierarchy_host_authority.py': 16,
    'tests/integration/test_hierarchy_jobs.py': 12,
    'tests/integration/test_hierarchy_jobs_census_policy.py': 11,
    'tests/integration/test_hierarchy_launcher.py': 2,
    'tests/integration/test_hierarchy_lifecycle.py': 23,
    'tests/integration/test_hierarchy_mailbox.py': 1,
    'tests/integration/test_hierarchy_mailbox_index.py': 20,
    'tests/integration/test_hierarchy_mailbox_mcp.py': 8,
    'tests/integration/test_hierarchy_native_probe.py': 14,
    'tests/integration/test_hierarchy_operator.py': 5,
    'tests/integration/test_hierarchy_recovery.py': 5,
    'tests/integration/test_hierarchy_team.py': 2,
    'tests/integration/test_hierarchy_team_homes.py': 10,
    'tests/integration/test_hierarchy_team_recovery.py': 3,
    'tests/integration/test_hierarchy_watch_bridge.py': 9,
    'tests/integration/test_hierarchy_watch_supervisor.py': 1,
    'tests/unit/cli/test_approve_cli.py': 2,
    'tests/unit/cli/test_check_ci_regression.py': 2,
    'tests/unit/cli/test_cli.py': 2,
    'tests/unit/cli/test_cli_helpers.py': 1,
    'tests/unit/cli/test_cli_migrate.py': 1,
    # baseline correction: test_cli_msg.py:854 monkeypatch.setattr(sys, 'stdin', ...)
    # was merged by another lane before this guard reached the integration tip;
    # no new shared operation from RF-11b.
    'tests/unit/cli/test_cli_msg.py': 21,
    'tests/unit/cli/test_cli_rule_create.py': 2,
    'tests/unit/cli/test_cli_sanitize_c1.py': 1,
    'tests/unit/cli/test_cli_team_status.py': 1,
    'tests/unit/cli/test_doctor.py': 4,
    'tests/unit/cli/test_doctor_fix.py': 2,
    'tests/unit/cli/test_doctor_host_hooks.py': 1,
    'tests/unit/cli/test_doctor_hosts.py': 4,
    'tests/unit/cli/test_doctor_mcp_launcher.py': 1,
    'tests/unit/cli/test_formatters_text.py': 1,
    'tests/unit/cli/test_go_doctor_card.py': 2,
    'tests/unit/cli/test_hook_install_hosts.py': 1,
    'tests/unit/cli/test_hook_run.py': 2,
    # baseline correction: the existing test_init.py:80 monkeypatch.delitem(sys.modules, ...)
    # predates RF-11b and was first censused when round 8 recognised delitem;
    # no new shared operation was added.
    'tests/unit/cli/test_init.py': 9,
    'tests/unit/cli/test_init_polyglot.py': 2,
    'tests/unit/cli/test_insight_hook_launcher.py': 2,
    'tests/unit/cli/test_install_hosts.py': 2,
    'tests/unit/cli/test_pathcheck.py': 2,
    'tests/unit/cli/test_skills_sync.py': 1,
    'tests/unit/core/test_ast_batch_m1.py': 4,
    'tests/unit/core/test_ast_driver_lookup.py': 2,
    'tests/unit/core/test_ast_driver_runner.py': 2,
    'tests/unit/core/test_ast_windows_job.py': 7,
    'tests/unit/core/test_atomicio.py': 2,
    'tests/unit/core/test_checkrun_group_kill.py': 2,
    'tests/unit/core/test_checkrun_polyglot.py': 1,
    'tests/unit/core/test_ci_governance_gate.py': 1,
    'tests/unit/core/test_coverage_formats.py': 1,
    'tests/unit/core/test_credit_model_v43.py': 1,
    'tests/unit/core/test_f_a1_human_gate_acceptance.py': 2,
    'tests/unit/core/test_f_b1_insights_acceptance.py': 2,
    'tests/unit/core/test_ghcli.py': 3,
    'tests/unit/core/test_gitsafe.py': 8,
    'tests/unit/core/test_go_build_cache.py': 12,
    'tests/unit/core/test_go_integration.py': 2,
    'tests/unit/core/test_human_gate.py': 1,
    'tests/unit/core/test_inference_provider.py': 2,
    'tests/unit/core/test_insights.py': 2,
    'tests/unit/core/test_language_tests.py': 2,
    'tests/unit/core/test_lane_ast.py': 1,
    'tests/unit/core/test_lifecycle_write_safety.py': 2,
    'tests/unit/core/test_locking.py': 2,
    'tests/unit/core/test_manager_store.py': 6,
    'tests/unit/core/test_message_codec.py': 55,
    'tests/unit/core/test_model_select.py': 17,
    'tests/unit/core/test_pathlookup.py': 1,
    'tests/unit/core/test_primitives.py': 6,
    'tests/unit/core/test_rules.py': 2,
    'tests/unit/core/test_scaffolding.py': 1,
    'tests/unit/core/test_scan_spawn_budget.py': 1,
    'tests/unit/core/test_security.py': 1,
    'tests/unit/core/test_shared_ledger.py': 1,
    'tests/unit/core/test_shared_state.py': 1,
    'tests/unit/core/test_storage.py': 6,
    'tests/unit/core/test_treeid_submodules.py': 3,
    'tests/unit/core/test_verified_checks_units.py': 3,
    'tests/unit/core/test_windows_junction.py': 2,
    'tests/unit/mcp/test_binding_guards.py': 1,
    'tests/unit/mcp/test_insight_session_binding.py': 1,
    'tests/unit/mcp/test_jit_context_budget.py': 4,
    'tests/unit/mcp/test_mcp_protocol_hygiene.py': 1,
    'tests/unit/mcp/test_mcp_report_outcome.py': 1,
    'tests/unit/mcp/test_mcp_runtime_binding.py': 2,
    'tests/unit/mcp/test_mcp_session_close_side_effects.py': 1,
    'tests/unit/mcp/test_mcp_session_stdio_contract.py': 1,
    'tests/unit/mcp/test_server_hardening.py': 2,
    'tests/unit/test_p6_noadmin.py': 1,
    'tests/unit/verification/test_call_graph_ast.py': 1,
    'tests/unit/verification/test_checkpoint_fail_closed.py': 1,
    'tests/unit/verification/test_import_guard.py': 1,
    'tests/unit/verification/test_mutation_tester.py': 3,
    'tests/unit/verification/test_native_ast_limits.py': 2,
    'tests/unit/verification/test_polyglot_coverage.py': 1,
    'tests/unit/verification/test_pytest_resolution.py': 11,
    'tests/unit/verification/test_scanners.py': 10,
}
