"""Audited live-clock assertion callers in the RF-3b admitted files retain timing markers.

This inventory includes helper-level bounds (including hang ceilings and scaled real
clocks). Polling/cleanup ceilings, synthetic clocks and UTC stamp observations are
not elapsed-time assertions. Read only tracked source; no git history or POSIX APIs.
"""
import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

# Test names are stable across line shifts. Helper callers were traced in the audit.
TIMING_TESTS = {
    "tests/integration/test_hierarchy_host_authority.py": (
        "test_all_five_dispatch_fields_must_match_actual_owned_frame_before_canonical_access",
        "test_bind_start_use_real_initial_and_one_owned_context",
        "test_close_during_post_reply_readback_refuses_with_a_typed_error",
        "test_close_interrupts_a_blocked_read_long_before_its_deadline",
        "test_close_interrupts_a_live_session_waiting_for_its_next_call",
        "test_close_revokes_an_in_flight_control_exchange_without_awaiting_its_reply",
        "test_initial_context_without_start_cannot_open_live_session",
        "test_initial_start_cannot_renew_original_bound_deadline",
        "test_live_runtime_projection_cannot_replace_owned_profile_or_rpc_variant",
        "test_possible_initial_control_retains_unknown_without_retry",
        "test_public_prior_guard_history_with_present_producer_stays_unknown",
        "test_real_initial_live_wire_creates_owned_invocation_and_both_fence_guard",
        "test_started_initial_with_legacy_role_ceiling_cannot_open_live_session",
    ),
    "tests/unit/cli/test_hook_run.py": (
        "test_hook_run_overhead_is_under_250_ms",
        "test_the_deadline_fails_open",
        "test_the_deadline_leaves_the_callers_timer_and_handler_as_they_were",
        "test_the_hooks_cost_does_not_grow_with_the_log",
    ),
    "tests/unit/verification/test_forbid_ast_hardening.py": (
        "test_a_quadratic_evaluator_fails_the_ratio",
        "test_generated_file_cost_scales_linearly",
    ),
    "tests/unit/core/test_benchmark.py": (
        "test_a_real_run_measures_all_three_and_leaves_no_temporary_directory",
    ),
    "tests/unit/verification/test_redaction_parity.py": (
        "test_redaction_time_is_linear",
    ),
    "tests/unit/core/test_locking.py": (
        "test_lock_held_by_another_process_times_out_with_exact_error",
        "test_nested_acquire_in_one_thread_does_not_deadlock",
    ),
    "tests/unit/core/test_command_guard.py": (
        "test_a_shell_alias_script_that_reruns_its_alias_is_scanned_in_linear_time",
        "test_an_alias_chain_is_expanded_in_linear_time",
    ),
    "tests/unit/core/test_shared_state.py": (
        "test_a_shared_lock_held_from_another_worktree_times_out_with_exact_error",
    ),
    "tests/unit/core/test_shared_ledger.py": (
        "test_every_ledger_writer_waits_for_the_one_common_lock",
    ),
    "tests/unit/core/test_scan_spawn_budget.py": (
        "test_a_core_scan_opens_the_ledger_once",
        "test_a_rule_that_cannot_load_fails_the_scan_before_any_fitness_work",
        "test_a_scan_outside_git_starts_one_git_process",
        "test_a_scan_that_matches_no_rule_opens_no_ledger_and_projects_no_credit",
        "test_a_warm_scan_asks_no_object_question_it_already_answered",
        "test_a_warm_scan_in_git_starts_at_most_four_and_no_tree_reads",
        "test_an_mcp_scan_with_a_session_outside_git_starts_one_git_process",
        "test_slowed_spawns_change_no_count",
        "test_the_pre_tool_hook_spawns_at_most_two_gits_on_edit_and_none_on_bash",
    ),
    "tests/unit/core/test_scan_gate_rows.py": (
        "test_a_full_tail_is_judged_fast",
    ),
    "tests/unit/core/test_match.py": (
        "test_wildcard_heavy_patterns_match_in_linear_time",
    ),
    "tests/unit/core/test_insights.py": (
        "test_a_prompt_waits_out_a_lock_held_past_5s_and_keeps_its_row",
    ),
    "tests/unit/core/test_command_safety.py": (
        "test_latency_budget",
    ),
    "tests/unit/cli/test_layer2_summary.py": (
        "test_unterminated_escape_introducers_cost_the_same_at_any_length",
    ),
    "tests/integration/test_hierarchy_fake_codex_rollouts.py": (
        "test_turn_keys_delay_the_context_change_the_recorded_sandbox_and_drop_the_completion",
    ),
    "tests/integration/test_hierarchy_background.py": (
        "test_a_failed_launch_whose_leftover_cannot_be_stopped_keeps_the_lock",
        "test_an_unconfirmed_stop_keeps_the_wake_lock",
        "test_one_missing_look_after_stop_does_not_confirm_the_stop",
    ),
}


@pytest.mark.parametrize("relative,names", TIMING_TESTS.items(), ids=TIMING_TESTS)
def test_live_clock_assertion_callers_carry_the_timing_marker(relative, names):
    tree = ast.parse((REPO / relative).read_text(encoding="utf-8"))
    tests = {node.name: node for node in ast.walk(tree)
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
             and node.name.startswith("test_")}
    assert set(names) <= tests.keys(), f"{relative}: audited clock test disappeared"
    missing = [f"{relative}:{tests[name].lineno}:{name}" for name in names
               if not any(ast.unparse(mark) == "pytest.mark.timing"
                          for mark in tests[name].decorator_list)]
    assert not missing, "wall-clock assertions lack @pytest.mark.timing:\n" + "\n".join(missing)
